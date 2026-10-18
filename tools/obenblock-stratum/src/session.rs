//! The downstream side: one Stratum V1 connection.
//!
//! [`Session`] is a pure state machine over incoming lines and published
//! jobs (no I/O, unit tested); [`serve`] is the thin async loop around it.
//!
//! Protocol, as SHA-256d ASIC firmware expects it:
//!
//! * `mining.configure` (BIP 310): `version-rolling` is granted with the
//!   template's BIP 320 mask (`1fffe000`) intersected with the miner's;
//!   `minimum-difficulty` is honored; other extensions are declined.
//! * `mining.subscribe`: a unique 4-byte `extranonce1`, `extranonce2` of 4.
//! * `mining.authorize [user, password]`: `user` is an ObenBlock address of
//!   this network, optionally `<address>.<worker>`; `d=<difficulty>` in the
//!   password sets the starting difficulty.
//! * `mining.notify`, `mining.set_difficulty` with per-connection vardiff.
//! * `mining.submit [user, job_id, extranonce2, ntime, nonce, version_bits?]`.
//!
//! ObenBlock's header root is Bitcoin's SHA-256d transaction tree
//! (docs/OBENBLOCK-MINING.md §3.3, §4.1), so every job is a plain Stratum V1
//! job built from the node's `stratum` object, and stock ASIC firmware (or a
//! rental service such as MiningRigRentals) mines it unmodified. Every share
//! is judged as the node judges the block: the coinbase rebuilt from
//! `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2`, the branch walked with
//! SHA-256d, the header's id against the share and block targets, and its
//! `ntime` against the job's window (`mintime` / `maxtime`, one stall-relief
//! step).

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{watch, Notify};

use crate::codec::{error_line, notification_line, parse_request, parse_submit, result_line, LineReader, Request};
use crate::job::ObbJob;
use crate::jobstore::JobStore;
use crate::pplns::PplnsLedger;
use crate::rpc::RpcClient;
use crate::template::{unix_now, Published};
use crate::types::{
    error_codes, methods, Line, Metrics, PoolError, ShareOutcome, StratumConfig, WorkerId, EXTRANONCE2_LEN,
};
use crate::validator::{difficulty_to_target, id_difficulty, meets_target};
use crate::vardiff::Vardiff;

/// A share's time may be at most this far past the server's clock (the node
/// allows 600 s past its own; 30 s margin).
pub const MAX_FUTURE_SECS: u64 = 570;

/// Jobs kept per connection.
const JOB_CACHE: usize = 16;
/// Submitted shares remembered for duplicate detection.
const SEEN_CAP: usize = 65_536;

/// A share that met the block target: the block to submit.
#[derive(Clone, Debug)]
pub struct BlockFound {
    pub job: Arc<ObbJob>,
    pub block: Vec<u8>,
    pub version: u32,
    pub time: u32,
    pub nonce: u32,
    /// `extranonce1 ‖ extranonce2` of the share (`submitblock`'s `extranonce`).
    pub extranonce: [u8; crate::job::EXTRANONCE_LEN],
    pub id: [u8; 32],
    pub account: String,
}

#[derive(Debug, Default)]
pub struct Reaction {
    pub send: Vec<String>,
    pub block: Option<BlockFound>,
    /// Close the connection after sending (protocol abuse).
    pub close: bool,
}

type SeenKey = (String, [u8; EXTRANONCE2_LEN], u32, u32, u32);

pub struct Session {
    pub id: WorkerId,
    en1: [u8; 4],
    cfg: Arc<StratumConfig>,
    metrics: Arc<Metrics>,
    ledger: Arc<PplnsLedger>,
    subscribed: bool,
    account: Option<String>,
    worker_name: String,
    /// Version bits this miner may roll (negotiated, or the template's mask).
    version_mask: Option<u32>,
    vardiff: Vardiff,
    jobs: JobStore,
    seen: HashSet<SeenKey>,
    seen_order: VecDeque<SeenKey>,
    work_sent: bool,
}

impl Session {
    pub fn new(id: WorkerId, en1: [u8; 4], cfg: Arc<StratumConfig>, metrics: Arc<Metrics>, ledger: Arc<PplnsLedger>)
        -> Self
    {
        let vardiff = Vardiff::from_cfg(&cfg);
        Self {
            id, en1, cfg, metrics, ledger, subscribed: false, account: None, worker_name: String::new(),
            version_mask: None, vardiff, jobs: JobStore::new(JOB_CACHE),
            seen: HashSet::new(), seen_order: VecDeque::new(), work_sent: false,
        }
    }

    pub fn is_subscribed(&self) -> bool {
        self.subscribed
    }

    pub fn is_authorized(&self) -> bool {
        self.account.is_some()
    }

    pub fn difficulty(&self) -> f64 {
        self.vardiff.current()
    }

    pub fn extranonce1(&self) -> [u8; 4] {
        self.en1
    }

    fn ready(&self) -> bool {
        self.subscribed && self.account.is_some()
    }

    fn set_difficulty_line(&mut self) -> String {
        self.vardiff.mark_announced();
        notification_line(methods::SET_DIFFICULTY, json!([self.vardiff.current()]))
    }

    fn notify_line(&self, job: &ObbJob, clean: bool) -> String {
        notification_line(methods::NOTIFY, job.notify_params(clean))
    }

    /// Lines for a newly published job.
    pub fn on_job(&mut self, p: &Published) -> Vec<String> {
        if p.clean_jobs {
            self.seen.clear();
            self.seen_order.clear();
        }
        self.jobs.insert(p.job.clone(), p.clean_jobs);
        if !self.ready() {
            return Vec::new();
        }
        let mut out = Vec::new();
        if self.vardiff.needs_announce() {
            out.push(self.set_difficulty_line());
        }
        out.push(self.notify_line(&p.job, p.clean_jobs || !self.work_sent));
        self.work_sent = true;
        out
    }

    /// Periodic housekeeping: the vardiff idle escape (a new difficulty
    /// applies with the next notify, so the latest job is re-sent).
    pub fn on_tick(&mut self, now: Instant) -> Vec<String> {
        if !self.ready() || self.vardiff.on_idle(now).is_none() {
            return Vec::new();
        }
        let mut out = vec![self.set_difficulty_line()];
        if let Some(job) = self.jobs.latest().cloned() {
            out.push(self.notify_line(&job, false));
        }
        out
    }

    /// Start work once both subscribed and authorized.
    fn start_work(&mut self, current: Option<&Published>) -> Vec<String> {
        let mut out = vec![self.set_difficulty_line()];
        if let Some(p) = current {
            self.jobs.insert(p.job.clone(), true);
            out.push(self.notify_line(&p.job, true));
            self.work_sent = true;
        }
        out
    }

    /// Handle one line from the miner. `current` is the latest published job
    /// (sent right after authorization).
    pub fn handle_line(&mut self, line: &str, current: Option<&Published>, now_unix: u64) -> Reaction {
        let req = match parse_request(line) {
            Ok(Some(r)) => r,
            Ok(None) => return Reaction::default(),
            Err(_) => {
                return Reaction { send: vec![error_line(&Value::Null, error_codes::OTHER, "malformed JSON")], close: true,
                                  ..Reaction::default() };
            }
        };
        match req.method.as_str() {
            methods::CONFIGURE => self.configure(&req),
            methods::SUBSCRIBE => {
                let was_ready = self.ready();
                self.subscribed = true;
                let en1 = hex::encode(self.en1);
                let mut send = vec![result_line(&req.id, json!([
                    [[methods::SET_DIFFICULTY, en1], [methods::NOTIFY, en1]], en1, EXTRANONCE2_LEN,
                ]))];
                if !was_ready && self.ready() {
                    send.extend(self.start_work(current));
                }
                Reaction { send, ..Reaction::default() }
            }
            methods::AUTHORIZE => self.authorize(&req, current),
            methods::SUBMIT => self.submit(&req, now_unix),
            methods::EXTRANONCE_SUBSCRIBE => Reaction { send: vec![result_line(&req.id, json!(true))], ..Default::default() },
            methods::SUGGEST_DIFFICULTY => {
                let d = req.params.first().and_then(Value::as_f64).unwrap_or(0.0);
                let mut send = vec![result_line(&req.id, json!(true))];
                if self.vardiff.suggest(d) && self.ready() {
                    send.push(self.set_difficulty_line());
                    if let Some(job) = self.jobs.latest().cloned() {
                        send.push(self.notify_line(&job, false));
                    }
                }
                Reaction { send, ..Default::default() }
            }
            methods::SUGGEST_TARGET => Reaction { send: vec![result_line(&req.id, json!(true))], ..Default::default() },
            _ => Reaction {
                send: vec![error_line(&req.id, error_codes::OTHER, &format!("unsupported method {}", req.method))],
                ..Default::default()
            },
        }
    }

    fn configure(&mut self, req: &Request) -> Reaction {
        let exts: Vec<String> = req.params.first().and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        let opts = req.params.get(1).cloned().unwrap_or(Value::Null);
        let mut result = serde_json::Map::new();
        for ext in exts {
            match ext.as_str() {
                "version-rolling" => {
                    let theirs = opts.get("version-rolling.mask").and_then(Value::as_str)
                        .and_then(crate::codec::parse_hex_u32).unwrap_or(u32::MAX);
                    let granted = theirs & gnb_smh::sha256d::BIP320_VERSION_MASK;
                    self.version_mask = Some(granted);
                    result.insert("version-rolling".into(), json!(true));
                    result.insert("version-rolling.mask".into(), json!(format!("{granted:08x}")));
                }
                "minimum-difficulty" => {
                    let v = opts.get("minimum-difficulty.value").and_then(Value::as_f64).unwrap_or(0.0);
                    let _ = self.vardiff.suggest(v);
                    result.insert("minimum-difficulty".into(), json!(true));
                }
                other => {
                    result.insert(other.to_string(), json!(false));
                }
            }
        }
        Reaction { send: vec![result_line(&req.id, Value::Object(result))], ..Default::default() }
    }

    fn authorize(&mut self, req: &Request, current: Option<&Published>) -> Reaction {
        let user = req.params.first().and_then(Value::as_str).unwrap_or("").trim().to_string();
        let account = crate::addr::username_address(&user).to_string();
        if !self.cfg.any_user {
            if let Err(e) = crate::addr::script_for(&account, self.cfg.network) {
                let msg = format!("username must be an ObenBlock address ({e}): <address> or <address>.<worker>");
                return Reaction { send: vec![error_line(&req.id, error_codes::UNAUTHORIZED, &msg)], ..Default::default() };
            }
        }
        if user.is_empty() || user.len() > 256 {
            return Reaction { send: vec![error_line(&req.id, error_codes::UNAUTHORIZED, "empty or oversized username")],
                              ..Default::default() };
        }
        if let Some(pass) = req.params.get(1).and_then(Value::as_str) {
            for part in pass.split([',', ';', ' ']) {
                if let Some(d) = part.trim().strip_prefix("d=").and_then(|v| v.parse::<f64>().ok()) {
                    let _ = self.vardiff.suggest(d);
                }
            }
        }
        let was_ready = self.ready();
        if self.account.is_none() {
            self.metrics.workers_authorized.fetch_add(1, Ordering::Relaxed);
        }
        self.account = Some(account);
        self.worker_name = user;
        log::info!("{}: authorized {} (difficulty {})", self.id, self.worker_name, self.vardiff.current());
        let mut send = vec![result_line(&req.id, json!(true))];
        if !was_ready && self.ready() {
            send.extend(self.start_work(current));
        }
        Reaction { send, ..Default::default() }
    }

    fn reject(&self, id: &Value, outcome: ShareOutcome, message: &str) -> Reaction {
        let code = match &outcome {
            ShareOutcome::Stale => error_codes::JOB_NOT_FOUND_OR_STALE,
            ShareOutcome::Duplicate => error_codes::DUPLICATE_SHARE,
            ShareOutcome::LowDifficulty => error_codes::LOW_DIFFICULTY,
            ShareOutcome::Rejected { code, .. } => *code,
            _ => error_codes::OTHER,
        };
        self.metrics.record_outcome(&outcome, 0.0);
        if let Some(a) = &self.account {
            self.ledger.record(a.clone(), "", None, &outcome);
        }
        Reaction { send: vec![error_line(id, code, message)], ..Default::default() }
    }

    fn submit(&mut self, req: &Request, now_unix: u64) -> Reaction {
        if !self.subscribed {
            return Reaction { send: vec![error_line(&req.id, error_codes::NOT_SUBSCRIBED, "not subscribed")], ..Default::default() };
        }
        let Some(account) = self.account.clone() else {
            return Reaction { send: vec![error_line(&req.id, error_codes::UNAUTHORIZED, "unauthorized worker")], ..Default::default() };
        };
        let s = match parse_submit(&req.params) {
            Ok(s) => s,
            Err(e) => {
                return self.reject(&req.id, ShareOutcome::Rejected { code: error_codes::OTHER, message: e.clone() }, &e);
            }
        };
        let Some(job) = self.jobs.get(&s.job_id).cloned() else {
            return self.reject(&req.id, ShareOutcome::Stale, "job not found (stale)");
        };
        let en2: [u8; EXTRANONCE2_LEN] = match s.extranonce2.as_slice().try_into() {
            Ok(e) => e,
            Err(_) => {
                let m = format!("extranonce2 must be {EXTRANONCE2_LEN} bytes");
                return self.reject(&req.id, ShareOutcome::Rejected { code: error_codes::OTHER, message: m.clone() }, &m);
            }
        };
        if let Err(why) = job.check_time(s.ntime, now_unix, MAX_FUTURE_SECS) {
            return self.reject(&req.id, ShareOutcome::Stale, why);
        }
        let mask = self.version_mask.unwrap_or(job.version_mask) & job.version_mask;
        let rolled = s.version_bits.map(|v| v & mask);
        let share = match job.share_header(&self.en1, &en2, s.ntime, s.nonce, rolled) {
            Ok(h) => h,
            Err(e) => return self.reject(&req.id, ShareOutcome::Rejected { code: error_codes::OTHER, message: e.clone() }, &e),
        };
        let key: SeenKey = (job.job_id.clone(), en2, s.ntime, s.nonce, share.version);
        if self.seen.contains(&key) {
            return self.reject(&req.id, ShareOutcome::Duplicate, "duplicate share");
        }
        self.seen.insert(key.clone());
        self.seen_order.push_back(key);
        while self.seen_order.len() > SEEN_CAP {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }

        let now = Instant::now();
        let announced = match self.vardiff.grace(now) {
            Some(g) => g.min(self.vardiff.current()),
            None => self.vardiff.current(),
        };
        let meets_block = meets_target(&share.id, &job.target);
        let meets_share = meets_target(&share.id, &difficulty_to_target(announced));

        if !meets_block && !meets_share {
            let mut r = self.reject(&req.id, ShareOutcome::LowDifficulty, "low difficulty share");
            if self.vardiff.note_low_share(id_difficulty(&share.id)).is_some() {
                r.send.push(self.set_difficulty_line());
            }
            return r;
        }

        let mut send = vec![result_line(&req.id, json!(true))];
        let mut block = None;
        let outcome = if meets_block {
            match job.block_for(&self.en1, &en2, &share, s.ntime, s.nonce) {
                Ok(b) => {
                    block = Some(BlockFound {
                        job: job.clone(), block: b, version: share.version, time: s.ntime, nonce: s.nonce,
                        extranonce: ObbJob::extranonce(&self.en1, &en2), id: share.id, account: account.clone(),
                    });
                    ShareOutcome::Block
                }
                Err(e) => {
                    log::error!("{}: block candidate could not be assembled: {e}", self.id);
                    ShareOutcome::Accepted
                }
            }
        } else {
            ShareOutcome::Accepted
        };
        let credited = if meets_share { announced } else { id_difficulty(&share.id).min(announced) };
        self.metrics.record_outcome(&outcome, credited);
        self.ledger.record(account, &job.job_id, Some(credited), &outcome);
        if meets_share && self.vardiff.on_accepted(now, announced).is_some() {
            send.push(self.set_difficulty_line());
        }
        Reaction { send, block, close: false }
    }
}

/// Everything a connection task needs.
#[derive(Clone)]
pub struct Shared {
    pub cfg: Arc<StratumConfig>,
    pub metrics: Arc<Metrics>,
    pub ledger: Arc<PplnsLedger>,
    pub rpc: RpcClient,
    pub jobs: watch::Receiver<Option<Published>>,
    pub wake: Arc<Notify>,
}

/// Submit a found block and record the node's verdict.
pub async fn submit_found_block(rpc: &RpcClient, metrics: &Metrics, wake: &Notify, found: &BlockFound) {
    log::info!("BLOCK candidate at height {} id {} (worker {}): submitting", found.job.height, hex::encode(found.id),
               found.account);
    match rpc.submit_block(&found.block, found.version, found.time, found.nonce, Some(&found.extranonce)).await {
        Ok(hash) => {
            metrics.blocks_accepted.fetch_add(1, Ordering::Relaxed);
            log::info!("BLOCK accepted by the node: {hash} (height {})", found.job.height);
        }
        Err(e) => {
            metrics.blocks_rejected.fetch_add(1, Ordering::Relaxed);
            if !matches!(e, PoolError::Node(_)) {
                metrics.rpc_failures.fetch_add(1, Ordering::Relaxed);
            }
            log::error!("BLOCK refused at height {}: {e}", found.job.height);
        }
    }
    wake.notify_one();
}

async fn read_line_until<R: AsyncBufRead + Unpin>(reader: &mut LineReader<R>, deadline: tokio::time::Instant, what: &str)
    -> Result<Option<Line>, PoolError>
{
    match tokio::time::timeout_at(deadline, reader.next_line()).await {
        Ok(r) => r,
        Err(_) => Err(PoolError::Timeout(what.to_string())),
    }
}

/// Serve one connection until it closes.
pub async fn serve(stream: TcpStream, id: WorkerId, en1: [u8; 4], mut shared: Shared) -> Result<(), PoolError> {
    let _ = stream.set_nodelay(true);
    let (rd, mut wr) = stream.into_split();
    let mut reader = LineReader::new(BufReader::new(rd));
    let mut session = Session::new(id, en1, shared.cfg.clone(), shared.metrics.clone(), shared.ledger.clone());
    let started = tokio::time::Instant::now();
    let mut idle_deadline = started + shared.cfg.idle_timeout;
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Jobs already published before this connection count as seen; the
    // current one is sent on authorization.
    let _ = shared.jobs.borrow_and_update();
    loop {
        let deadline = if session.is_subscribed() && session.is_authorized() {
            idle_deadline
        } else {
            idle_deadline.min(started + shared.cfg.handshake_timeout)
        };
        let out: Vec<String>;
        tokio::select! {
            r = read_line_until(&mut reader, deadline, "connection idle or handshake not completed") => {
                let Some(line) = r? else { break };
                shared.metrics.bytes_in.fetch_add(line.len() as u64, Ordering::Relaxed);
                idle_deadline = tokio::time::Instant::now() + shared.cfg.idle_timeout;
                let current = shared.jobs.borrow().clone();
                let reaction = session.handle_line(&line, current.as_ref(), unix_now());
                if let Some(found) = reaction.block {
                    let (rpc, metrics, wake) = (shared.rpc.clone(), shared.metrics.clone(), shared.wake.clone());
                    tokio::spawn(async move { submit_found_block(&rpc, &metrics, &wake, &found).await });
                }
                if reaction.close {
                    write_all(&mut wr, &reaction.send, &shared.metrics).await?;
                    break;
                }
                out = reaction.send;
            }
            changed = shared.jobs.changed() => {
                if changed.is_err() {
                    break; // the template source stopped
                }
                let p = shared.jobs.borrow_and_update().clone();
                out = match p { Some(p) => session.on_job(&p), None => Vec::new() };
            }
            _ = tick.tick() => {
                out = session.on_tick(Instant::now());
            }
        }
        write_all(&mut wr, &out, &shared.metrics).await?;
    }
    if session.is_authorized() {
        shared.metrics.workers_authorized.fetch_sub(1, Ordering::Relaxed);
    }
    Ok(())
}

async fn write_all(wr: &mut (impl AsyncWriteExt + Unpin), lines: &[String], metrics: &Metrics) -> Result<(), PoolError> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut buf = String::new();
    for l in lines {
        buf.push_str(l);
        buf.push('\n');
    }
    metrics.bytes_out.fetch_add(buf.len() as u64, Ordering::Relaxed);
    tokio::time::timeout(Duration::from_secs(30), async {
        wr.write_all(buf.as_bytes()).await?;
        wr.flush().await
    })
    .await
    .map_err(|_| PoolError::Timeout("write to miner".into()))?
    .map_err(PoolError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::tests::{template_from_vector, vector_extranonce};
    use crate::types::Network;
    use crate::validator::{bitcoin_merkle_root, block_id, header80, sha256d, stratum_word_swap};

    const MAIN_ADDR: &str = "obb1q0000000000000000000000000000000000000000335d2ee7";

    fn cfg() -> Arc<StratumConfig> {
        Arc::new(StratumConfig {
            network: Network::Mainnet,
            vardiff_initial: 1e-9,
            vardiff_min: 1e-12,
            pplns_window_shares: 100,
            ..StratumConfig::default()
        })
    }

    fn published(clean: bool) -> Published {
        let job = ObbJob::from_template(&template_from_vector(0), vector_extranonce(0), "j1".into()).unwrap();
        Published { job: Arc::new(job), clean_jobs: clean }
    }

    fn session_with(cfg: Arc<StratumConfig>) -> (Session, Arc<Metrics>, Arc<PplnsLedger>) {
        let m = Arc::new(Metrics::new());
        let l = Arc::new(PplnsLedger::new(&cfg));
        (Session::new(WorkerId(1), [0xde, 0xad, 0xbe, 0xef], cfg, m.clone(), l.clone()), m, l)
    }

    fn ready_session(rolling: bool) -> (Session, Arc<Metrics>, Arc<PplnsLedger>, Published) {
        let (mut s, m, l) = session_with(cfg());
        let p = published(true);
        if rolling {
            s.handle_line(r#"{"id":0,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"ffffffff"}]}"#, None, 0);
        }
        s.handle_line(r#"{"id":1,"method":"mining.subscribe","params":["test"]}"#, Some(&p), 0);
        let r = s.handle_line(&format!(r#"{{"id":2,"method":"mining.authorize","params":["{MAIN_ADDR}.rig1","x"]}}"#), Some(&p), 0);
        assert!(r.send.iter().any(|l| l.contains("mining.notify")), "work starts on authorize");
        (s, m, l, p)
    }

    fn v(line: &str) -> Value {
        serde_json::from_str(line).unwrap()
    }

    #[test]
    fn subscribe_advertises_the_extranonce() {
        let (mut s, _, _) = session_with(cfg());
        let r = s.handle_line(r#"{"id":1,"method":"mining.subscribe","params":["bmminer/2.0.0"]}"#, None, 0);
        let res = v(&r.send[0]);
        assert_eq!(res["result"][1], json!("deadbeef"));
        assert_eq!(res["result"][2], json!(4));
        assert_eq!(res["result"][0][1][0], json!("mining.notify"));
    }

    #[test]
    fn configure_grants_bip320_rolling_and_declines_the_rest() {
        let (mut s, _, _) = session_with(cfg());
        let r = s.handle_line(r#"{"id":0,"method":"mining.configure","params":[["version-rolling","minimum-difficulty","subscribe-extranonce","obenblock-root"],{"version-rolling.mask":"ffffffff","version-rolling.min-bit-count":2,"minimum-difficulty.value":2048}]}"#, None, 0);
        let res = &v(&r.send[0])["result"];
        assert_eq!(res["version-rolling"], json!(true));
        assert_eq!(res["version-rolling.mask"], json!("1fffe000"));
        assert_eq!(res["minimum-difficulty"], json!(true));
        assert_eq!(res["subscribe-extranonce"], json!(false));
        assert_eq!(res["obenblock-root"], json!(false), "the retired root extension is declined");
        assert_eq!(s.difficulty(), 2048.0);
        // A narrower miner mask is intersected.
        let (mut s2, _, _) = session_with(cfg());
        let r = s2.handle_line(r#"{"id":0,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"00ffe000"}]}"#, None, 0);
        assert_eq!(v(&r.send[0])["result"]["version-rolling.mask"], json!("00ffe000"));
    }

    #[test]
    fn authorize_requires_an_obenblock_address_of_the_network() {
        for bad in ["x", "", "bc1qjpnqq4f6hjh2n39tzwy8ttrj4h78yx22retkyk", "obb1t0000000000000000000000000000000000000000335d2ee7"] {
            let (mut s, _, _) = session_with(cfg());
            let r = s.handle_line(&format!(r#"{{"id":2,"method":"mining.authorize","params":["{bad}","x"]}}"#), None, 0);
            assert_eq!(v(&r.send[0])["error"][0], json!(24), "{bad:?}");
            assert!(!s.is_authorized());
        }
        let any = Arc::new(StratumConfig { any_user: true, ..(*cfg()).clone() });
        let (mut s, _, _) = session_with(any);
        let r = s.handle_line(r#"{"id":2,"method":"mining.authorize","params":["rental-user.1","x"]}"#, None, 0);
        assert_eq!(v(&r.send[0])["result"], json!(true));
    }

    #[test]
    fn password_difficulty_hint_is_applied() {
        let (mut s, _, _) = session_with(Arc::new(StratumConfig { vardiff_min: 1.0, ..(*cfg()).clone() }));
        s.handle_line(&format!(r#"{{"id":2,"method":"mining.authorize","params":["{MAIN_ADDR}","x,d=500000"]}}"#), None, 0);
        assert_eq!(s.difficulty(), 500_000.0);
    }

    #[test]
    fn work_starts_with_set_difficulty_then_a_clean_notify() {
        let (mut s, _, _) = session_with(cfg());
        let p = published(false);
        s.handle_line(&format!(r#"{{"id":2,"method":"mining.authorize","params":["{MAIN_ADDR}"]}}"#), Some(&p), 0);
        let r = s.handle_line(r#"{"id":1,"method":"mining.subscribe","params":[]}"#, Some(&p), 0);
        assert_eq!(v(&r.send[1])["method"], json!("mining.set_difficulty"));
        let n = v(&r.send[2]);
        assert_eq!(n["method"], json!("mining.notify"));
        assert_eq!(n["params"][8], json!(true));
        assert_eq!(n["params"].as_array().unwrap().len(), 9, "plain Stratum V1 notify");
    }

    /// Mine a share against a session's current job (Bitcoin's root), for a
    /// target.
    fn mine(s: &Session, job: &ObbJob, en2: [u8; 4], target: &crate::validator::Target) -> (u32, [u8; 32]) {
        let root = job.merkle_root_for(&s.en1, &en2);
        for nonce in 0u32.. {
            let id = block_id(&header80(job.version, &job.parents_commitment, &root, job.time, job.bits, nonce));
            if meets_target(&id, target) {
                return (nonce, id);
            }
        }
        unreachable!()
    }

    fn submit_line(id: u64, job: &str, en2: [u8; 4], ntime: u32, nonce: u32) -> String {
        format!(r#"{{"id":{id},"method":"mining.submit","params":["{MAIN_ADDR}","{job}","{}","{ntime:08x}","{nonce:08x}"]}}"#,
                hex::encode(en2))
    }

    #[test]
    fn a_block_share_becomes_a_block_and_counts() {
        let (mut s, m, l, p) = ready_session(true);
        let job = p.job.clone();
        let (nonce, id) = mine(&s, &job, [0, 0, 0, 1], &job.target);
        let r = s.handle_line(&submit_line(9, &job.job_id, [0, 0, 0, 1], job.time, nonce), None, job.time as u64);
        assert_eq!(v(&r.send[0])["result"], json!(true), "{:?}", r.send);
        let found = r.block.expect("meets the block target");
        assert_eq!(found.id, id);
        assert_eq!(found.nonce, nonce);
        assert_eq!(found.extranonce, [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1]);
        assert_eq!(m.snapshot().blocks_found, 1);
        assert_eq!(l.totals().blocks, 1);
        // The same share again is a duplicate.
        let r = s.handle_line(&submit_line(10, &job.job_id, [0, 0, 0, 1], job.time, nonce), None, job.time as u64);
        assert_eq!(v(&r.send[0])["error"][0], json!(22));
        assert!(r.block.is_none());
    }

    #[test]
    fn shares_are_judged_on_the_header() {
        let (mut s, m, _, p) = ready_session(true);
        let job = p.job.clone();
        let hard = Arc::new(StratumConfig { vardiff_initial: 1e6, vardiff_min: 1e6, ..(*cfg()).clone() });
        s.vardiff = Vardiff::from_cfg(&hard);
        // A nonce that misses both targets is low difficulty.
        let root = job.merkle_root_for(&s.en1, &[0, 0, 0, 2]);
        let miss = (0u32..).find(|&n| !meets_target(&block_id(&header80(job.version, &job.parents_commitment, &root,
            job.time, job.bits, n)), &job.target)).unwrap();
        let r = s.handle_line(&submit_line(3, &job.job_id, [0, 0, 0, 2], job.time, miss), None, job.time as u64);
        assert_eq!(v(&r.send[0])["error"][0], json!(23));
        assert_eq!(m.snapshot().shares_low_difficulty, 1);
        // Unknown job: stale. Bad extranonce2 length: rejected.
        let r = s.handle_line(&submit_line(4, "nope", [0, 0, 0, 2], job.time, miss), None, job.time as u64);
        assert_eq!(v(&r.send[0])["error"][0], json!(21));
        let r = s.handle_line(&format!(r#"{{"id":5,"method":"mining.submit","params":["a","{}","00","{:08x}","00000000"]}}"#,
                                       job.job_id, job.time), None, job.time as u64);
        assert_eq!(v(&r.send[0])["error"][0], json!(20));
        // Time outside the job's window (before it, or in the next relief
        // step): stale.
        let r = s.handle_line(&submit_line(6, &job.job_id, [0, 0, 0, 2], job.mintime as u32 - 1, miss), None, job.time as u64);
        assert_eq!(v(&r.send[0])["error"][0], json!(21));
        let late = job.maxtime as u32 + 1;
        let r = s.handle_line(&submit_line(7, &job.job_id, [0, 0, 0, 2], late, miss), None, late as u64);
        assert_eq!(v(&r.send[0])["error"][0], json!(21));
        assert!(r.send[0].contains("window"), "{:?}", r.send);
    }

    #[test]
    fn rolled_version_bits_enter_the_header() {
        let (mut s, _, _, p) = ready_session(true);
        let job = p.job.clone();
        let en2 = [0, 0, 0, 3];
        let rolled = 0x0000_6000u32;
        let root = job.merkle_root_for(&s.en1, &en2);
        let version = job.version | rolled;
        let nonce = (0u32..).find(|&n| meets_target(&block_id(&header80(version, &job.parents_commitment, &root, job.time,
            job.bits, n)), &job.target)).unwrap();
        let line = format!(r#"{{"id":7,"method":"mining.submit","params":["w","{}","{}","{:08x}","{nonce:08x}","{rolled:08x}"]}}"#,
                           job.job_id, hex::encode(en2), job.time);
        let r = s.handle_line(&line, None, job.time as u64);
        let found = r.block.expect("the rolled header meets the block target");
        assert_eq!(found.version, version);
        assert_eq!(&found.block[0..4], &version.to_le_bytes());
    }

    /// A stock Stratum V1 device: it reads only the `mining.notify` params and
    /// the subscribe result, builds the coinbase, walks the branch, swaps the
    /// prevhash words back and rolls ntime and version bits, exactly as
    /// Bitcoin firmware does. Its block share is a block.
    #[test]
    fn stock_firmware_work_from_notify_alone_is_a_block() {
        let (mut s, _, _, p) = ready_session(true);
        let job = p.job.clone();
        let n = job.notify_params(false);
        let n = n.as_array().unwrap();
        let hx = |i: usize| hex::decode(n[i].as_str().unwrap()).unwrap();
        let be = |i: usize| u32::from_str_radix(n[i].as_str().unwrap(), 16).unwrap();
        let en1 = s.extranonce1();
        let en2 = [0xa0, 0, 0, 5];
        let mut cb = hx(2);
        cb.extend_from_slice(&en1);
        cb.extend_from_slice(&en2);
        cb.extend(hx(3));
        let mut root = sha256d(&cb);
        for b in n[4].as_array().unwrap() {
            let mut pair = root.to_vec();
            pair.extend(hex::decode(b.as_str().unwrap()).unwrap());
            root = sha256d(&pair);
        }
        assert_eq!(root, bitcoin_merkle_root(&job.coinbase_txid(&en1, &en2), &job.branch));
        let prev: [u8; 32] = hx(1).try_into().unwrap();
        let rolled = 0x0001_e000u32;
        let (version, bits, ntime) = (be(5) | rolled, be(6), be(7) + 3);
        let nonce = (0u32..).find(|&k| meets_target(&block_id(&header80(version, &stratum_word_swap(&prev), &root, ntime,
            bits, k)), &job.target)).unwrap();
        let line = format!(r#"{{"id":8,"method":"mining.submit","params":["w","{}","{}","{ntime:08x}","{nonce:08x}","{rolled:08x}"]}}"#,
                           n[0].as_str().unwrap(), hex::encode(en2));
        let r = s.handle_line(&line, None, ntime as u64);
        assert_eq!(v(&r.send[0])["result"], json!(true), "{:?}", r.send);
        let found = r.block.expect("a stock-firmware block share is a block");
        assert_eq!((found.version, found.time, found.nonce), (version, ntime, nonce));
        assert_eq!(&found.block[job.merkle_offset..job.merkle_offset + 32], &root);
    }

    #[test]
    fn submit_before_subscribe_or_authorize_is_refused() {
        let (mut s, _, _) = session_with(cfg());
        let r = s.handle_line(&submit_line(1, "j1", [0; 4], 0, 0), None, 0);
        assert_eq!(v(&r.send[0])["error"][0], json!(25));
        s.handle_line(r#"{"id":1,"method":"mining.subscribe","params":[]}"#, None, 0);
        let r = s.handle_line(&submit_line(2, "j1", [0; 4], 0, 0), None, 0);
        assert_eq!(v(&r.send[0])["error"][0], json!(24));
    }

    #[test]
    fn clean_jobs_make_old_jobs_stale() {
        let (mut s, _, _, p) = ready_session(true);
        let mut other = (*p.job).clone();
        other.job_id = "j2".into();
        other.parents_commitment = [0x55; 32];
        let lines = s.on_job(&Published { job: Arc::new(other), clean_jobs: true });
        assert!(lines.iter().any(|l| l.contains("\"j2\"")));
        let r = s.handle_line(&submit_line(1, "j1", [0; 4], p.job.time, 0), None, p.job.time as u64);
        assert_eq!(v(&r.send[0])["error"][0], json!(21));
    }

    #[test]
    fn malformed_json_closes_and_unknown_methods_error() {
        let (mut s, _, _) = session_with(cfg());
        assert!(s.handle_line("{nope", None, 0).close);
        let r = s.handle_line(r#"{"id":3,"method":"mining.hello","params":[]}"#, None, 0);
        assert_eq!(v(&r.send[0])["error"][0], json!(20));
        let r = s.handle_line(r#"{"id":4,"method":"mining.extranonce.subscribe","params":[]}"#, None, 0);
        assert_eq!(v(&r.send[0])["result"], json!(true));
    }

    // ── Framing: the socket loop's read is bounded and deadlined ─────────

    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    struct Endless;
    impl AsyncRead for Endless {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            let n = buf.remaining().min(4096);
            buf.put_slice(&vec![b'x'; n]);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn never_terminated_line_is_refused() {
        let mut reader = LineReader::new(BufReader::new(Endless));
        let far = tokio::time::Instant::now() + Duration::from_secs(600);
        let err = tokio::time::timeout(Duration::from_secs(5), read_line_until(&mut reader, far, "x"))
            .await.expect("bounded").expect_err("over-long line");
        assert!(matches!(err, PoolError::Protocol(_)));
    }

    #[tokio::test]
    async fn silent_peer_hits_the_deadline() {
        struct Silent;
        impl AsyncRead for Silent {
            fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }
        let mut reader = LineReader::new(BufReader::new(Silent));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        assert!(matches!(read_line_until(&mut reader, deadline, "x").await, Err(PoolError::Timeout(_))));
    }
}
