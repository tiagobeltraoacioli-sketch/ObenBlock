//! Per-connection V1 session: state machine, jobs, vardiff and I/O loop.
//!
//! Ported from the legacy Bloch server (genesis3-node `src/stratum/session.rs`):
//! the state machine, the bounded writer, the read bounds, the timeouts, the
//! vardiff and the duplicate cache are unchanged. What changed for ObenBlock:
//!
//! * jobs are `getblocktemplate` header jobs ([`super::jobs::Job`]) on the
//!   shared work feed, rebuilt by the session itself on every publication
//!   (tip change, refresh, stall-relief step);
//! * `mining.configure` accepts BIP 310 version rolling with the BIP 320 mask
//!   `1fffe000` (the legacy server declined it), and offers the
//!   `obb-merkle-root` extension that tells an ObenBlock-aware client how to
//!   compute the header root (sent as a tenth `mining.notify` parameter);
//! * the worker name is an `obb1…` address ([`super::payout`]).
//!
//! ```text
//!   Fresh       -- mining.subscribe --> Subscribed
//!   Subscribed  -- mining.authorize --> Authorized
//!   Authorized  (submit / configure / suggest_difficulty)
//! ```
//!
//! Timeouts: 30 s from connection to Authorized, else closed; an authorized
//! miner is never dropped for silence (a solo miner may say nothing for
//! hours while it still needs `mining.notify`), only on EOF, a read error
//! or a failed write.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use parking_lot::Mutex;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::jobs::{Job, EXTRANONCE1_BYTES, EXTRANONCE2_BYTES, EXTRANONCE_BYTES};
use super::payout::{self, Payout};
use super::protocol::{
    methods, ErrorCode, StratumError, StratumNotification, StratumRequest, StratumResponse, MAX_LINE_BYTES,
};
use super::work::{Work, WorkReceiver};
use super::{difficulty, StratumConfig};
use crate::core::pow_scheme::Sha256dParams;
use gnb_smh::sha256d::BIP320_VERSION_MASK;

/// Session-level state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// TCP accept complete, no subscribe yet.
    Fresh,
    /// Received mining.subscribe, awaiting mining.authorize.
    Subscribed,
    /// Authorized; receives jobs and submits shares.
    Authorized,
    /// Marked for removal; the I/O loop exits shortly.
    Dead,
}

/// Time a peer has to reach Authorized.
pub const AUTH_TIMEOUT_SECS: u64 = 30;

/// Read-poll interval of an authorized session (liveness re-check only).
pub const IDLE_TIMEOUT_SECS: u64 = 600;

/// Max submissions per minute per session (anti-flood).
pub const SUBMIT_RATE_PER_MIN: u32 = 30;

/// Jobs retained per session; older job ids get error 21.
pub const MAX_TEMPLATES_PER_SESSION: usize = 16;

/// Soft cap of the duplicate-share cache.
pub const MAX_SUBMITTED_ENTRIES: usize = 4096;

/// Longest accepted `job_id` (ours are `{sid:x}-{seq:x}-{ctr:x}`).
pub const MAX_JOB_ID_LEN: usize = 64;

// ── Vardiff (per-connection share difficulty) ───────────────────────────────
//
// Adapts each miner's share difficulty to about one share every
// TARGET_SHARE_INTERVAL_SEC, never harder than a block. Consensus is
// untouched: the block's bits stay the job's.

/// Starting share difficulty (env `OBB_STRATUM_START_DIFF` overrides).
pub const START_SHARE_DIFF: f64 = 0.01;
/// Floor of the share difficulty (env `OBB_STRATUM_MIN_DIFF`); the network
/// difficulty wins when it is lower.
pub const MIN_SHARE_DIFF: f64 = 0.001;
/// Desired seconds between accepted shares.
pub const TARGET_SHARE_INTERVAL_SEC: f64 = 10.0;
/// Minimum shares in a window before a retarget.
pub const RETARGET_MIN_SHARES: u32 = 4;
/// Retarget early once this many shares land.
pub const RETARGET_TRIGGER_SHARES: u32 = 8;
/// Or after this many seconds with at least RETARGET_MIN_SHARES shares.
pub const RETARGET_INTERVAL_SEC: f64 = 90.0;
/// Per-retarget change-factor bounds.
pub const STEP_CLAMP_MIN: f64 = 0.25;
pub const STEP_CLAMP_MAX: f64 = 4.0;
/// Re-send mining.set_difficulty only on a change above this fraction.
pub const SEND_THRESHOLD: f64 = 0.10;

/// Bounded outbound queue; a full queue means the peer stopped reading.
pub const OUTBOUND_CHANNEL_BOUND: usize = 256;
/// Per-write timeout of the writer task.
pub const WRITE_TIMEOUT_SECS: u64 = 10;
/// Teardown wait for the writer task before it is aborted.
pub const WRITER_JOIN_TIMEOUT_SECS: u64 = 2;

/// Name of the vendor extension of `mining.configure` that carries the
/// ObenBlock header-root rule.
pub const OBB_MERKLE_EXTENSION: &str = "obb-merkle-root";

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key).ok().and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0).unwrap_or(default)
}

/// Effective starting share difficulty.
pub fn start_share_diff() -> f64 { env_f64("OBB_STRATUM_START_DIFF", START_SHARE_DIFF) }
/// Effective minimum share difficulty.
pub fn min_share_diff() -> f64 { env_f64("OBB_STRATUM_MIN_DIFF", MIN_SHARE_DIFF) }

/// Duplicate-cache key: (job_id, extranonce2, ntime, nonce, version bits).
type ShareKey = (String, String, String, String, String);

/// A job as the session stores it.
#[derive(Clone, Debug)]
pub struct SessionJob {
    pub job_id: String,
    pub job: Arc<Job>,
}

/// One V1 client session (shared between the server registry and its task).
pub struct Session {
    pub id: u64,
    pub peer_addr: SocketAddr,
    pub created_at: Instant,
    /// Random 4-byte extranonce1 (CSPRNG, legacy L-7).
    pub extranonce1: [u8; EXTRANONCE1_BYTES],
    tx_out: Mutex<Option<mpsc::Sender<String>>>,
    state: Mutex<SessionState>,
    /// The worker name as authorized, its payout and label.
    authorized_name: Mutex<Option<String>>,
    payout: Mutex<Option<Payout>>,
    submit_counter: AtomicU32,
    submit_window_start: AtomicU64,
    jobs: Mutex<VecDeque<SessionJob>>,
    submitted: Mutex<HashSet<ShareKey>>,
    job_counter: AtomicU64,
    /// Negotiated BIP 310 version-rolling mask (0 = none).
    version_mask: AtomicU32,
    /// The client negotiated the `obb-merkle-root` extension.
    obb_merkle: AtomicBool,
    /// A share met its target only under Bitcoin's Merkle tree (logged once).
    warned_bitcoin_tree: AtomicBool,
    share_difficulty: Mutex<f64>,
    last_sent_difficulty: Mutex<f64>,
    share_window_start: Mutex<Instant>,
    shares_in_window: AtomicU32,
}

impl Session {
    pub fn new(id: u64, peer_addr: SocketAddr) -> Self {
        let mut extranonce1 = [0u8; EXTRANONCE1_BYTES];
        // Legacy L-7: CSPRNG, never derived from the id or the time.
        rand::rng().fill_bytes(&mut extranonce1);
        Self {
            id,
            peer_addr,
            created_at: Instant::now(),
            extranonce1,
            tx_out: Mutex::new(None),
            state: Mutex::new(SessionState::Fresh),
            authorized_name: Mutex::new(None),
            payout: Mutex::new(None),
            submit_counter: AtomicU32::new(0),
            submit_window_start: AtomicU64::new(0),
            jobs: Mutex::new(VecDeque::with_capacity(MAX_TEMPLATES_PER_SESSION)),
            submitted: Mutex::new(HashSet::new()),
            job_counter: AtomicU64::new(0),
            version_mask: AtomicU32::new(0),
            obb_merkle: AtomicBool::new(false),
            warned_bitcoin_tree: AtomicBool::new(false),
            share_difficulty: Mutex::new(start_share_diff()),
            last_sent_difficulty: Mutex::new(0.0),
            share_window_start: Mutex::new(Instant::now()),
            shares_in_window: AtomicU32::new(0),
        }
    }

    pub fn state(&self) -> SessionState { *self.state.lock() }
    pub fn is_authorized(&self) -> bool { self.state() == SessionState::Authorized }
    pub fn is_dead(&self) -> bool { self.state() == SessionState::Dead }
    pub fn set_state(&self, s: SessionState) { *self.state.lock() = s; }

    /// The worker name as authorized.
    pub fn authorized_name(&self) -> Option<String> { self.authorized_name.lock().clone() }
    /// The payout of this session's blocks.
    pub fn payout(&self) -> Option<Payout> { self.payout.lock().clone() }

    /// Authorize as `name` paying `payout` (the authorize handler; tests).
    pub fn set_authorized(&self, name: String, payout: Payout) {
        *self.authorized_name.lock() = Some(name);
        *self.payout.lock() = Some(payout);
        self.set_state(SessionState::Authorized);
    }

    pub fn version_mask(&self) -> u32 { self.version_mask.load(Ordering::Relaxed) }
    pub fn set_version_mask(&self, m: u32) { self.version_mask.store(m, Ordering::Relaxed) }
    pub fn obb_merkle(&self) -> bool { self.obb_merkle.load(Ordering::Relaxed) }
    pub fn set_obb_merkle(&self, on: bool) { self.obb_merkle.store(on, Ordering::Relaxed) }

    /// The full 8-byte extranonce of a share with `en2`.
    pub fn extranonce(&self, en2: &[u8; EXTRANONCE2_BYTES]) -> [u8; EXTRANONCE_BYTES] {
        let mut e = [0u8; EXTRANONCE_BYTES];
        e[..EXTRANONCE1_BYTES].copy_from_slice(&self.extranonce1);
        e[EXTRANONCE1_BYTES..].copy_from_slice(en2);
        e
    }

    /// A fresh job id.
    pub fn next_job_id(&self, work_seq: u64) -> String {
        let c = self.job_counter.fetch_add(1, Ordering::Relaxed);
        format!("{:x}-{:x}-{:x}", self.id, work_seq, c)
    }

    /// Append a job (oldest evicted, with its duplicate-cache entries).
    pub fn push_job(&self, j: SessionJob) {
        let mut jobs = self.jobs.lock();
        if jobs.len() >= MAX_TEMPLATES_PER_SESSION {
            if let Some(evicted) = jobs.pop_front() {
                self.submitted.lock().retain(|k| k.0 != evicted.job_id);
            }
        }
        jobs.push_back(j);
    }

    /// Replace every job (clean jobs); the duplicate cache is cleared.
    pub fn replace_jobs(&self, j: SessionJob) {
        let mut jobs = self.jobs.lock();
        jobs.clear();
        jobs.push_back(j);
        self.submitted.lock().clear();
    }

    pub fn find_job(&self, job_id: &str) -> Option<SessionJob> {
        self.jobs.lock().iter().rev().find(|t| t.job_id == job_id).cloned()
    }

    /// Record a share; false if it was already submitted. The key includes
    /// the time and the version bits: rolled shares are distinct solutions.
    pub fn record_submission(&self, job_id: &str, en2: &str, ntime: &str, nonce: &str, version: &str) -> bool {
        let key = (job_id.to_string(), en2.to_string(), ntime.to_string(), nonce.to_string(), version.to_string());
        let mut s = self.submitted.lock();
        if s.contains(&key) {
            return false;
        }
        if s.len() >= MAX_SUBMITTED_ENTRIES {
            if let Some(evict) = s.iter().next().cloned() {
                s.remove(&evict);
            }
        }
        s.insert(key)
    }

    /// Note a share that only Bitcoin's Merkle tree explains; true the
    /// first time (log once per session).
    pub fn note_bitcoin_tree_share(&self) -> bool {
        !self.warned_bitcoin_tree.swap(true, Ordering::Relaxed)
    }

    fn install_writer(&self, tx: mpsc::Sender<String>) { *self.tx_out.lock() = Some(tx); }
    fn clear_writer(&self) { *self.tx_out.lock() = None; }

    // ── Vardiff ────────────────────────────────────────────────────────────

    pub fn share_difficulty(&self) -> f64 { *self.share_difficulty.lock() }
    pub fn set_share_difficulty(&self, d: f64) { *self.share_difficulty.lock() = d; }
    pub fn last_sent_difficulty(&self) -> f64 { *self.last_sent_difficulty.lock() }

    /// Push `mining.set_difficulty([d])` (before the notify it applies to;
    /// the queue is FIFO).
    pub fn send_set_difficulty(&self, d: f64) -> Result<(), &'static str> {
        let r = self.send_line(StratumNotification::new(methods::SET_DIFFICULTY, json!([d])).to_line());
        if r.is_ok() {
            *self.last_sent_difficulty.lock() = d;
        }
        r
    }

    /// Count one accepted share and maybe retarget toward one share per
    /// TARGET_SHARE_INTERVAL_SEC, capped at `net_diff` (a share is never
    /// harder than a block). `Some(d)` when a new set_difficulty is due.
    pub fn record_share_and_maybe_retarget(&self, net_diff: f64) -> Option<f64> {
        let count = self.shares_in_window.fetch_add(1, Ordering::Relaxed) + 1;
        if count < RETARGET_MIN_SHARES {
            return None;
        }
        let elapsed = self.share_window_start.lock().elapsed().as_secs_f64();
        if count < RETARGET_TRIGGER_SHARES && elapsed < RETARGET_INTERVAL_SEC {
            return None;
        }
        let observed = (elapsed / count as f64).max(f64::MIN_POSITIVE);
        let ratio = (TARGET_SHARE_INTERVAL_SEC / observed).clamp(STEP_CLAMP_MIN, STEP_CLAMP_MAX);
        let cap = net_diff.max(f64::MIN_POSITIVE);
        let lo = min_share_diff().min(cap);
        let cur = *self.share_difficulty.lock();
        let new_diff = (cur * ratio).clamp(lo, cap);
        *self.share_window_start.lock() = Instant::now();
        self.shares_in_window.store(0, Ordering::Relaxed);
        *self.share_difficulty.lock() = new_diff;
        let last_sent = *self.last_sent_difficulty.lock();
        let at_boundary = new_diff <= lo || new_diff >= cap;
        let changed = last_sent <= 0.0
            || (new_diff / last_sent - 1.0).abs() > SEND_THRESHOLD
            || (at_boundary && (new_diff - last_sent).abs() > f64::EPSILON);
        changed.then_some(new_diff)
    }

    /// Clamp the share difficulty into `[min, net_diff]` (a new job's
    /// network difficulty).
    pub fn clamp_share_difficulty(&self, net_diff: f64) {
        let cur = self.share_difficulty();
        let cap = net_diff.max(f64::MIN_POSITIVE);
        let capped = cur.clamp(min_share_diff().min(cap), cap);
        if (capped - cur).abs() > f64::EPSILON {
            self.set_share_difficulty(capped);
        }
    }

    /// Queue a line for the writer. A full queue (peer not reading) or a
    /// closed one marks the session Dead.
    pub fn send_line(&self, line: String) -> Result<(), &'static str> {
        let g = self.tx_out.lock();
        let (res, peer_failed) = match g.as_ref() {
            Some(tx) => match tx.try_send(line) {
                Ok(()) => (Ok(()), false),
                Err(mpsc::error::TrySendError::Full(_)) => (Err("writer backpressure: peer not draining"), true),
                Err(mpsc::error::TrySendError::Closed(_)) => (Err("writer closed"), true),
            },
            None => (Err("writer not installed"), false),
        };
        drop(g);
        if peer_failed {
            self.set_state(SessionState::Dead);
        }
        res
    }

    pub fn notify(&self, method: &str, params: Value) -> Result<(), &'static str> {
        self.send_line(StratumNotification::new(method, params).to_line())
    }

    /// Check-and-increment the per-minute submit limiter.
    pub fn check_submit_rate(&self) -> Result<(), StratumError> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let start = self.submit_window_start.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= 60 {
            self.submit_window_start.store(now, Ordering::Relaxed);
            self.submit_counter.store(1, Ordering::Relaxed);
            return Ok(());
        }
        let count = self.submit_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if count > SUBMIT_RATE_PER_MIN {
            return Err(StratumError::new(ErrorCode::Other, format!("submit rate exceeded ({SUBMIT_RATE_PER_MIN}/min cap)")));
        }
        Ok(())
    }
}

/// Stratum V1 sends the previous-block field with each 32-bit word
/// byte-reversed; Bitcoin miners `le32dec` each word, which restores the
/// header bytes (here `parents_commitment`, header bytes 4..36).
pub fn stratum_prevhash(prev: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        for k in 0..4 {
            out[i * 4 + k] = prev[i * 4 + 3 - k];
        }
    }
    out
}

/// `mining.notify` params of `job` under id `job_id`:
/// `[job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]`
/// (integers as big-endian hex, as in Bitcoin stratum), plus, for a client
/// that negotiated `obb-merkle-root`, a tenth object with the header-root
/// rule and its two section roots.
pub fn notify_params(job: &Job, job_id: &str, clean_jobs: bool, obb_merkle: bool) -> Value {
    let branch: Vec<String> = job.merkle_branch.iter().map(hex::encode).collect();
    let mut p = vec![
        json!(job_id),
        json!(hex::encode(stratum_prevhash(&job.parents_commitment))),
        json!(hex::encode(&job.coinb1)),
        json!(hex::encode(&job.coinb2)),
        json!(branch),
        json!(format!("{:08x}", job.version)),
        json!(format!("{:08x}", job.bits)),
        json!(format!("{:08x}", job.time)),
        json!(clean_jobs),
    ];
    if obb_merkle {
        p.push(json!({
            "merkle_root_rule": "gnb-body-v2",
            "shielded_root": hex::encode(job.shielded_root),
            "powit_root": hex::encode(job.powit_root),
        }));
    }
    Value::Array(p)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Build this session's job on `work` and send `mining.set_difficulty` (when
/// it changed) and `mining.notify`.
pub async fn install_job(session: &Arc<Session>, work: &Arc<Work>, params: Sha256dParams, clean: bool)
    -> Result<(), String>
{
    let payout = session.payout().ok_or("install_job on an unauthorized session")?;
    let template = work.template.clone();
    let extranonce = session.extranonce(&[0u8; EXTRANONCE2_BYTES]);
    let job = tokio::task::spawn_blocking(move || Job::build(template, &params, &payout.script_pubkey, extranonce, now_secs()))
        .await
        .map_err(|e| format!("job task failed: {e}"))??;
    let job = Arc::new(job);
    let job_id = session.next_job_id(work.seq);
    session.clamp_share_difficulty(difficulty::difficulty_from_bits(job.bits));
    let entry = SessionJob { job_id: job_id.clone(), job: job.clone() };
    if clean {
        session.replace_jobs(entry);
    } else {
        session.push_job(entry);
    }
    let cur = session.share_difficulty();
    let last = session.last_sent_difficulty();
    if last <= 0.0 || (cur - last).abs() > f64::EPSILON {
        let _ = session.send_set_difficulty(cur);
    }
    let _ = session.notify(methods::NOTIFY, notify_params(&job, &job_id, clean, session.obb_merkle()));
    info!("stratum: session {} job {job_id} h={} bits={:08x} clean={clean} {} txs",
          session.id, job.template.height, job.bits, job.template.transactions.len());
    Ok(())
}

/// Per-session I/O task.
pub async fn run(
    session: Arc<Session>,
    socket: TcpStream,
    config: Arc<StratumConfig>,
    params: Sha256dParams,
    mut work: WorkReceiver,
) -> std::io::Result<()> {
    let _ = socket.set_nodelay(true);
    let (rd, wr) = socket.into_split();
    let (out_tx, out_rx) = mpsc::channel::<String>(OUTBOUND_CHANNEL_BOUND);
    session.install_writer(out_tx);
    let s_writer = session.clone();
    let mut writer = tokio::spawn(async move { writer_loop(wr, out_rx, s_writer).await });

    let mut reader = BufReader::with_capacity(MAX_LINE_BYTES + 256, rd);
    let mut line_buf: Vec<u8> = Vec::with_capacity(512);
    let auth_deadline = Instant::now() + Duration::from_secs(AUTH_TIMEOUT_SECS);

    loop {
        if session.is_dead() {
            debug!("stratum: session {} writer reported a dead peer", session.id);
            break;
        }
        if !session.is_authorized() && Instant::now() > auth_deadline {
            warn!("stratum: session {} auth timeout ({AUTH_TIMEOUT_SECS}s)", session.id);
            let _ = session.send_line(StratumResponse::error(None,
                StratumError::new(ErrorCode::Unauthorized, "authorization timeout")).to_line());
            break;
        }
        let authorized = session.is_authorized();
        let read_timeout = if authorized {
            Duration::from_secs(IDLE_TIMEOUT_SECS)
        } else {
            auth_deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(IDLE_TIMEOUT_SECS))
        };
        tokio::select! {
            read = tokio::time::timeout(read_timeout, read_bounded_line(&mut reader, &mut line_buf)) => match read {
                Ok(Ok(0)) => {
                    debug!("stratum: session {} peer closed", session.id);
                    break;
                }
                Ok(Ok(_)) => {
                    let dispatched = match std::str::from_utf8(&line_buf) {
                        Ok(line) => dispatch(&session, line, &config, params, &mut work).await,
                        Err(_) => Err("non-utf8 line".to_string()),
                    };
                    match dispatched {
                        Ok(Some(resp)) => {
                            if session.send_line(resp.to_line()).is_err() {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("stratum: session {} dispatch error: {e}", session.id);
                            let _ = session.send_line(StratumResponse::error(None,
                                StratumError::new(ErrorCode::Other, "malformed request")).to_line());
                        }
                    }
                    line_buf.clear();
                    if line_buf.capacity() > MAX_LINE_BYTES {
                        line_buf.shrink_to(512);
                    }
                }
                Ok(Err(e)) => {
                    debug!("stratum: session {} read error: {e}", session.id);
                    break;
                }
                Err(_) => {
                    if session.is_authorized() {
                        // A quiet solo miner is normal; keep it.
                        continue;
                    }
                    warn!("stratum: session {} auth timeout ({AUTH_TIMEOUT_SECS}s)", session.id);
                    let _ = session.send_line(StratumResponse::error(None,
                        StratumError::new(ErrorCode::Unauthorized, "authorization timeout")).to_line());
                    break;
                }
            },
            changed = work.changed(), if authorized => {
                if changed.is_err() {
                    warn!("stratum: session {}: the work feed stopped", session.id);
                    break;
                }
                let w = work.borrow_and_update().clone();
                if let Some(w) = w {
                    if let Err(e) = install_job(&session, &w, params, w.clean).await {
                        warn!("stratum: session {} job on work #{} failed: {e}", session.id, w.seq);
                    }
                }
            }
        }
    }

    session.set_state(SessionState::Dead);
    session.clear_writer();
    if tokio::time::timeout(Duration::from_secs(WRITER_JOIN_TIMEOUT_SECS), &mut writer).await.is_err() {
        writer.abort();
    }
    Ok(())
}

/// Read one '\n'-terminated line into `buf`, bounded by MAX_LINE_BYTES while
/// it accumulates. Cancellation-safe (`fill_buf` consumes nothing itself).
async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(0);
        }
        if let Some(i) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=i]);
            reader.consume(i + 1);
            return Ok(buf.len());
        }
        let n = available.len();
        buf.extend_from_slice(available);
        reader.consume(n);
        if buf.len() > MAX_LINE_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "stratum line exceeds MAX_LINE_BYTES"));
        }
    }
}

/// Drain the outbound queue into the socket; mark Dead on a failed or
/// stalled write.
async fn writer_loop(mut wr: OwnedWriteHalf, mut rx: mpsc::Receiver<String>, session: Arc<Session>) {
    while let Some(line) = rx.recv().await {
        let write = tokio::time::timeout(Duration::from_secs(WRITE_TIMEOUT_SECS), async {
            wr.write_all(line.as_bytes()).await?;
            wr.flush().await
        }).await;
        if !matches!(write, Ok(Ok(()))) {
            session.set_state(SessionState::Dead);
            break;
        }
    }
    let _ = wr.shutdown().await;
}

async fn dispatch(
    session: &Arc<Session>,
    line: &str,
    config: &Arc<StratumConfig>,
    params: Sha256dParams,
    work: &mut WorkReceiver,
) -> Result<Option<StratumResponse>, String> {
    let req = StratumRequest::parse(line)?;
    match req.method.as_str() {
        methods::SUBSCRIBE => Ok(Some(handle_subscribe(session, &req))),
        methods::AUTHORIZE => {
            // Sends its own lines in the order authorize result,
            // set_difficulty, notify.
            let resp = handle_authorize(session, &req, config.payout.as_ref());
            if resp.error.is_none() {
                let w = work.borrow_and_update().clone();
                match w {
                    Some(w) => {
                        if let Err(e) = install_job(session, &w, params, true).await {
                            warn!("stratum: session {} authorized but its first job failed: {e}", session.id);
                        }
                    }
                    None => info!("stratum: session {} authorized; waiting for the first block template", session.id),
                }
            }
            Ok(None)
        }
        methods::SUBMIT => {
            let (s, cb) = (session.clone(), config.accept_block.clone());
            tokio::task::spawn_blocking(move || super::submit::handle_submit(&s, &req, &*cb))
                .await
                .map(Some)
                .map_err(|e| format!("submit task failed: {e}"))
        }
        methods::CONFIGURE => Ok(Some(handle_configure(session, &req))),
        methods::EXTRANONCE_SUBSCRIBE => Ok(Some(StratumResponse::ok(req.id, Value::from(true)))),
        methods::SUGGEST_DIFFICULTY | methods::SUGGEST_TARGET => Ok(Some(handle_suggest_difficulty(session, &req, work))),
        methods::PING => Ok(Some(StratumResponse::ok(req.id, json!("pong")))),
        other => {
            warn!("stratum: session {} unknown method: {other}", session.id);
            Ok(Some(StratumResponse::error(req.id, StratumError::new(ErrorCode::Other, format!("unknown method: {other}")))))
        }
    }
}

/// `mining.subscribe` → `[[["mining.set_difficulty", id], ["mining.notify", id]], extranonce1, 4]`.
pub fn handle_subscribe(session: &Arc<Session>, req: &StratumRequest) -> StratumResponse {
    if session.state() != SessionState::Fresh {
        return StratumResponse::error(req.id.clone(), StratumError::new(ErrorCode::Other, "already subscribed"));
    }
    session.set_state(SessionState::Subscribed);
    let en1 = hex::encode(session.extranonce1);
    info!("stratum: session {} subscribed (extranonce1={en1})", session.id);
    StratumResponse::ok(req.id.clone(), json!([
        [[methods::SET_DIFFICULTY, en1.clone()], [methods::NOTIFY, en1.clone()]],
        en1,
        EXTRANONCE2_BYTES as u32,
    ]))
}

/// `mining.authorize [worker, password]`: the worker must name an `obb1…`
/// address of this network (or be a plain label with an operator payout
/// configured, [`payout::resolve_worker`]). Sends the result itself (the
/// first job follows it on the wire) and returns it.
pub fn handle_authorize(session: &Arc<Session>, req: &StratumRequest, fallback: Option<&Payout>) -> StratumResponse {
    let send_err = |code, msg: &str| -> StratumResponse {
        let e = StratumResponse::error(req.id.clone(), StratumError::new(code, msg.to_string()));
        let _ = session.send_line(e.to_line());
        e
    };
    if session.state() == SessionState::Fresh {
        return send_err(ErrorCode::NotSubscribed, "must subscribe before authorizing");
    }
    let Some(username) = req.params.as_array().and_then(|a| a.first()).and_then(Value::as_str) else {
        return send_err(ErrorCode::Unauthorized, "authorize requires [username, password]");
    };
    match payout::resolve_worker(username, fallback) {
        Ok((p, label)) => {
            info!("stratum: session {} authorized {username} -> pays {}{}", session.id, p.address,
                  label.map(|l| format!(" (worker {l})")).unwrap_or_default());
            session.set_authorized(username.to_string(), p);
            session.set_share_difficulty(start_share_diff());
            let ok = StratumResponse::ok(req.id.clone(), Value::from(true));
            let _ = session.send_line(ok.to_line());
            ok
        }
        Err(e) => {
            warn!("stratum: session {} refused worker {username:?}: {e}", session.id);
            send_err(ErrorCode::Unauthorized, &e)
        }
    }
}

/// `mining.configure [extensions, params]` (BIP 310): version rolling with
/// the BIP 320 mask (`1fffe000`, intersected with the miner's mask), and the
/// `obb-merkle-root` vendor extension. Other extensions are declined.
pub fn handle_configure(session: &Arc<Session>, req: &StratumRequest) -> StratumResponse {
    let arr = req.params.as_array();
    let exts: Vec<&str> = arr.and_then(|a| a.first()).and_then(Value::as_array)
        .map(|v| v.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let opts = arr.and_then(|a| a.get(1)).and_then(Value::as_object);
    let mut result = serde_json::Map::new();
    for ext in exts {
        match ext {
            "version-rolling" => {
                let requested = opts.and_then(|o| o.get("version-rolling.mask")).and_then(Value::as_str)
                    .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(BIP320_VERSION_MASK);
                let mask = requested & BIP320_VERSION_MASK;
                session.set_version_mask(mask);
                result.insert("version-rolling".into(), json!(mask != 0));
                result.insert("version-rolling.mask".into(), json!(format!("{mask:08x}")));
                info!("stratum: session {} version rolling mask {mask:08x}", session.id);
            }
            OBB_MERKLE_EXTENSION => {
                session.set_obb_merkle(true);
                result.insert(OBB_MERKLE_EXTENSION.into(), json!(true));
                result.insert(format!("{OBB_MERKLE_EXTENSION}.rule"), json!("gnb-body-v2"));
            }
            other => {
                result.insert(other.to_string(), json!(false));
            }
        }
    }
    StratumResponse::ok(req.id.clone(), Value::Object(result))
}

/// `mining.suggest_difficulty [d]`: seed the share difficulty, capped at
/// the current network difficulty, and confirm it with set_difficulty.
fn handle_suggest_difficulty(session: &Arc<Session>, req: &StratumRequest, work: &WorkReceiver) -> StratumResponse {
    if let Some(d) = req.params.as_array().and_then(|a| a.first()).and_then(Value::as_f64) {
        if d.is_finite() && d > 0.0 {
            let cap = work.borrow().as_ref().map(|w| difficulty::difficulty_from_bits(w.bits).max(f64::MIN_POSITIVE)).unwrap_or(d);
            let clamped = d.clamp(min_share_diff().min(cap), cap);
            session.set_share_difficulty(clamped);
            let _ = session.send_set_difficulty(clamped);
        }
    }
    StratumResponse::ok(req.id.clone(), Value::from(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn mk_session() -> Arc<Session> {
        Arc::new(Session::new(1, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
    }

    /// This chain's form of an address (the lib tests run GnB mainnet).
    fn valid_addr() -> String {
        crate::address::Address::from_hash([0x4f; 20], crate::address::Network::Mainnet).to_string()
    }

    fn req(id: i64, method: &str, params: Value) -> StratumRequest {
        StratumRequest { id: Some(Value::from(id)), method: method.to_string(), params }
    }

    #[test]
    fn session_starts_fresh() {
        let s = mk_session();
        assert_eq!(s.state(), SessionState::Fresh);
        assert!(!s.is_authorized());
        assert_eq!(s.extranonce1.len(), 4);
    }

    #[test]
    fn extranonce1_is_not_derived_from_id_or_time() {
        // Legacy L-7: 16 sessions with the same id draw distinct values.
        let mut values = HashSet::new();
        for _ in 0..16 {
            values.insert(Session::new(7, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).extranonce1);
        }
        assert_eq!(values.len(), 16);
    }

    #[test]
    fn extranonce_is_en1_then_en2() {
        let s = mk_session();
        let e = s.extranonce(&[9, 8, 7, 6]);
        assert_eq!(&e[..4], &s.extranonce1);
        assert_eq!(&e[4..], &[9, 8, 7, 6]);
    }

    #[test]
    fn subscribe_advances_state_and_returns_extranonce() {
        let s = mk_session();
        let resp = handle_subscribe(&s, &req(1, methods::SUBSCRIBE, json!(["cpuminer/2.5"])));
        assert_eq!(s.state(), SessionState::Subscribed);
        let arr = resp.result.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[1].as_str().unwrap(), hex::encode(s.extranonce1));
        assert_eq!(arr[2].as_u64(), Some(4));
        assert!(handle_subscribe(&s, &req(2, methods::SUBSCRIBE, json!([]))).error.is_some(), "second subscribe");
    }

    #[test]
    fn authorize_rejects_invalid_address() {
        let s = mk_session();
        s.set_state(SessionState::Subscribed);
        let resp = handle_authorize(&s, &req(2, methods::AUTHORIZE, json!(["not-a-valid-address!", "x"])), None);
        assert!(resp.error.is_some());
        assert_eq!(s.state(), SessionState::Subscribed);
        // A Bitcoin address is refused even with an operator payout set.
        let op = payout::parse_payout_address(&valid_addr()).unwrap();
        let resp = handle_authorize(&s, &req(3, methods::AUTHORIZE,
            json!(["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "x"])), Some(&op));
        assert_eq!(resp.error.as_ref().unwrap()[0], json!(24));
    }

    #[test]
    fn authorize_accepts_this_chains_address() {
        let s = mk_session();
        s.set_state(SessionState::Subscribed);
        let resp = handle_authorize(&s, &req(2, methods::AUTHORIZE, json!([format!("{}.rig7", valid_addr()), "x"])), None);
        assert!(resp.error.is_none(), "{:?}", resp.error);
        assert!(s.is_authorized());
        assert_eq!(s.payout().unwrap().script_pubkey, vec![0x4f; 20]);
    }

    #[test]
    fn authorize_before_subscribe_errors() {
        let s = mk_session();
        let resp = handle_authorize(&s, &req(1, methods::AUTHORIZE, json!([valid_addr(), "x"])), None);
        assert_eq!(resp.error.as_ref().unwrap()[0], json!(25));
    }

    #[test]
    fn configure_negotiates_bip320_version_rolling() {
        let s = mk_session();
        let resp = handle_configure(&s, &req(9, methods::CONFIGURE,
            json!([["version-rolling", "minimum-difficulty"], {"version-rolling.mask": "ffffffff"}])));
        assert_eq!(resp.result["version-rolling"], json!(true));
        assert_eq!(resp.result["version-rolling.mask"], json!("1fffe000"));
        assert_eq!(resp.result["minimum-difficulty"], json!(false));
        assert_eq!(s.version_mask(), 0x1fff_e000);
        // A narrower miner mask is intersected.
        let resp = handle_configure(&s, &req(10, methods::CONFIGURE,
            json!([["version-rolling"], {"version-rolling.mask": "00ffe000"}])));
        assert_eq!(resp.result["version-rolling.mask"], json!("00ffe000"));
        assert!(!s.obb_merkle());
        let resp = handle_configure(&s, &req(11, methods::CONFIGURE, json!([[OBB_MERKLE_EXTENSION], {}])));
        assert_eq!(resp.result[OBB_MERKLE_EXTENSION], json!(true));
        assert!(s.obb_merkle());
    }

    #[test]
    fn prevhash_word_swap_round_trips() {
        let mut p = [0u8; 32];
        for (i, b) in p.iter_mut().enumerate() {
            *b = i as u8;
        }
        let s = stratum_prevhash(&p);
        assert_eq!(&s[..4], &[3, 2, 1, 0]);
        assert_eq!(stratum_prevhash(&s), p);
    }

    #[test]
    fn submit_rate_limiter_cuts_off_after_cap() {
        let s = mk_session();
        for _ in 0..SUBMIT_RATE_PER_MIN {
            assert!(s.check_submit_rate().is_ok());
        }
        assert!(s.check_submit_rate().is_err());
    }

    #[test]
    fn retarget_needs_minimum_shares() {
        let s = mk_session();
        for _ in 0..(RETARGET_MIN_SHARES - 1) {
            assert!(s.record_share_and_maybe_retarget(1.0).is_none());
        }
    }

    #[test]
    fn fast_shares_raise_difficulty_within_the_cap() {
        let s = mk_session();
        s.set_share_difficulty(0.1);
        let mut raised = None;
        for _ in 0..RETARGET_TRIGGER_SHARES {
            if let Some(d) = s.record_share_and_maybe_retarget(1.0) {
                raised = Some(d);
            }
        }
        let d = raised.expect("a retarget at the trigger count");
        assert!(d > 0.1 && d <= 1.0, "{d}");
    }

    #[test]
    fn retarget_respects_net_difficulty_cap() {
        let s = mk_session();
        s.set_share_difficulty(10.0);
        let mut last = None;
        for _ in 0..RETARGET_TRIGGER_SHARES {
            if let Some(d) = s.record_share_and_maybe_retarget(2.0) {
                last = Some(d);
            }
        }
        assert!(last.is_none_or(|d| d <= 2.0));
        s.clamp_share_difficulty(1.0);
        assert!(s.share_difficulty() <= 1.0);
    }

    // ── Session lifetime over a real socket (legacy regressions) ───────────

    fn test_config() -> Arc<StratumConfig> {
        Arc::new(StratumConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            max_sessions: 4,
            payout: None,
            accept_block: Arc::new(|_b| Err("test: no node".to_string())),
        })
    }

    fn test_params() -> Sha256dParams {
        Sha256dParams::obenblock_regtest(1_800_000_000)
    }

    async fn spawn_session_pair() -> (TcpStream, Arc<Session>, tokio::sync::watch::Sender<Option<Arc<Work>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server_sock, peer) = listener.accept().await.unwrap();
        let session = Arc::new(Session::new(1, peer));
        let (wtx, wrx) = tokio::sync::watch::channel(None);
        let s2 = session.clone();
        tokio::spawn(async move {
            let _ = run(s2, server_sock, test_config(), test_params(), wrx).await;
        });
        (client, session, wtx)
    }

    async fn send_json<W: AsyncWriteExt + Unpin>(client: &mut W, line: &str) {
        client.write_all(line.as_bytes()).await.unwrap();
        client.write_all(b"\n").await.unwrap();
        client.flush().await.unwrap();
    }

    async fn read_json_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await.unwrap();
        assert!(n > 0, "peer closed unexpectedly");
        buf
    }

    #[tokio::test]
    async fn authorized_quiet_session_survives_idle_windows() {
        let (client, session, _wtx) = spawn_session_pair().await;
        let (rd, mut wr) = client.into_split();
        let mut rdr = BufReader::new(rd);
        send_json(&mut wr, r#"{"id":1,"method":"mining.subscribe","params":["cpuminer/2.5"]}"#).await;
        let _ = read_json_line(&mut rdr).await;
        send_json(&mut wr, &format!(r#"{{"id":2,"method":"mining.authorize","params":["{}","x"]}}"#, valid_addr())).await;
        let auth = read_json_line(&mut rdr).await;
        assert!(auth.contains("true"), "{auth}");
        assert_eq!(session.state(), SessionState::Authorized);

        tokio::time::pause();
        tokio::time::sleep(Duration::from_secs(IDLE_TIMEOUT_SECS * 3 + 5)).await;
        tokio::time::resume();

        assert_eq!(session.state(), SessionState::Authorized, "a quiet authorized session is kept");
        session.notify(methods::SET_DIFFICULTY, json!([1])).expect("writer still installed");
        assert!(read_json_line(&mut rdr).await.contains(methods::SET_DIFFICULTY));
        send_json(&mut wr, r#"{"id":3,"method":"mining.ping","params":[]}"#).await;
        assert!(read_json_line(&mut rdr).await.contains("pong"));
    }

    #[tokio::test(start_paused = true)]
    async fn unauthorized_session_closed_at_auth_deadline() {
        let (client, session, _wtx) = spawn_session_pair().await;
        let (rd, _wr) = client.into_split();
        let mut rdr = BufReader::new(rd);
        let mut all = String::new();
        let read_all = tokio::time::timeout(Duration::from_secs(AUTH_TIMEOUT_SECS + 30), async {
            loop {
                let mut line = String::new();
                match rdr.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => all.push_str(&line),
                }
            }
        }).await;
        assert!(read_all.is_ok(), "the socket closes at the auth deadline");
        assert!(all.contains("authorization timeout"), "{all}");
        assert!(session.is_dead());
    }
}
