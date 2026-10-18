//! Per-connection SV2 session (after the Noise NX handshake).
//!
//! ```text
//!   AwaitingSetupConnection ── SetupConnection (Mining, v2) ──► Live ──► Closed
//!   Live: OpenStandardMiningChannel → Success, then NewMiningJob (future) + SetNewPrevHash
//!         each work update (tip, refresh, stall-relief step) → a new job per channel
//!         SubmitSharesStandard → Job::solve → channel target → block target → accept
//! ```
//!
//! A reader task decrypts frames (its own copy of the Noise codec, decrypt
//! only) and hands them to the session loop, which owns the write half and
//! the encrypting copy. The legacy Bloch session read one TCP `read()` as one
//! frame and dropped a miner after 10 s of silence; here frames are read
//! exactly (framing.rs) and a quiet miner is kept (a solo miner on a hard
//! target may submit rarely), until EOF, a protocol error or a failed write.
//!
//! Ported from the legacy Bloch server (genesis3-node `src/stratum_v2/session.rs`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use noise_sv2::NoiseCodec;
use rand::RngCore;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::block_reconstruct::{reconstruct_block_for_sv2_submit, BlockReconstructError};
use super::channel::{ChannelRegistry, ChannelState, Sv2CachedJob, MAX_CHANNELS_PER_SESSION};
use super::framing::{self, Frame, FramingError};
use super::messages::{self as msg, Encoded};
use super::setup_connection;
use super::template_adapter::build_channel_job;
use super::Sv2Config;
use crate::core::pow_scheme::Sha256dParams;
use crate::stratum::difficulty;
use crate::stratum::jobs::SolveError;
use crate::stratum::payout;
use crate::stratum::work::{Work, WorkReceiver};
use gnb_smh::difficulty::{bits_to_target, Target};
use gnb_smh::sha256d;

/// Time for the first message (SetupConnection) after the handshake.
pub const SETUP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-frame write timeout.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Seconds between shares a channel's initial target aims at.
pub const TARGET_SHARE_INTERVAL_SEC: f64 = 10.0;
/// Shares per minute per session (anti-flood).
pub const SUBMIT_RATE_PER_MIN: u32 = 120;
/// Decrypted frames queued from the reader task.
pub const INBOUND_QUEUE: usize = 64;

/// State of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Handshaking,
    AwaitingSetupConnection,
    Live,
    Closed,
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The share target of a channel: the target a miner of the channel's
/// nominal hash rate meets about every TARGET_SHARE_INTERVAL_SEC, never
/// harder than a block, and within the client's `max_target`.
pub fn channel_target(nominal_hash_rate: f32, max_target: &[u8; 32], block_target: &Target) -> [u8; 32] {
    let rate = difficulty::target_for_rate(nominal_hash_rate as f64, TARGET_SHARE_INTERVAL_SEC);
    let t = difficulty::easier(&rate, block_target);
    difficulty::harder(&t, &Target(*max_target)).0
}

struct Session {
    id: u64,
    peer: SocketAddr,
    config: Arc<Sv2Config>,
    params: Sha256dParams,
    wr: OwnedWriteHalf,
    codec: NoiseCodec,
    channels: ChannelRegistry,
    next_job_id: u32,
    submit_window: Instant,
    submits_in_window: u32,
}

impl Session {
    async fn send(&mut self, e: Encoded) -> std::io::Result<()> {
        let bytes = framing::encrypt_frame(&mut self.codec, 0, e.channel_msg, e.msg_type, &e.payload).map_err(io_err)?;
        tokio::time::timeout(WRITE_TIMEOUT, async {
            use tokio::io::AsyncWriteExt;
            self.wr.write_all(&bytes).await?;
            self.wr.flush().await
        }).await.map_err(|_| io_err("write timeout"))?
    }

    async fn send_result(&mut self, e: Result<Encoded, String>) -> std::io::Result<()> {
        self.send(e.map_err(io_err)?).await
    }

    /// Build and send the job of `work` to `channel_id`.
    async fn push_job(&mut self, channel_id: u32, work: &Arc<Work>, clean: bool) -> std::io::Result<()> {
        let Some(ch) = self.channels.get(channel_id) else { return Ok(()) };
        let (spk, extranonce) = (ch.payout.script_pubkey.clone(), ch.extranonce_prefix);
        let (template, params) = (work.template.clone(), self.params);
        let built = tokio::task::spawn_blocking(move || build_channel_job(template, &params, &spk, extranonce, now_secs()))
            .await
            .map_err(io_err)?;
        let (job, root) = match built {
            Ok(x) => x,
            Err(e) => {
                warn!("stratum_v2: session {} channel {channel_id} job on work #{} failed: {e}", self.id, work.seq);
                return Ok(());
            }
        };
        let job_id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1).max(1);
        let job = Arc::new(job);
        // A share is never harder than a block: a channel opened before the
        // first template (or on a harder one) gets the block target.
        let block_target = job.block_target();
        let raise = self.channels.get(channel_id).is_some_and(|c| c.target < block_target.0);
        if raise {
            if let Some(c) = self.channels.get_mut(channel_id) {
                c.target = block_target.0;
            }
            self.send_result(msg::set_target(channel_id, &block_target.0)).await?;
        }
        self.send_result(msg::new_mining_job(channel_id, job_id, None, job.version, &root)).await?;
        self.send_result(msg::set_new_prev_hash(channel_id, job_id, &job.parents_commitment, job.time, job.bits)).await?;
        debug!("stratum_v2: session {} channel {channel_id} job {job_id} h={} bits={:08x}",
               self.id, job.template.height, job.bits);
        if let Some(ch) = self.channels.get_mut(channel_id) {
            ch.push_job(Sv2CachedJob { job_id, job, merkle_root: root }, clean);
        }
        Ok(())
    }

    async fn push_work(&mut self, work: &Arc<Work>) -> std::io::Result<()> {
        for id in self.channels.ids() {
            self.push_job(id, work, work.clean).await?;
        }
        if !self.channels.is_empty() {
            info!("stratum_v2: session {} work #{} h={} to {} channel(s) ({:?})",
                  self.id, work.seq, work.template.height, self.channels.len(), work.reason);
        }
        Ok(())
    }

    async fn open_standard_channel(&mut self, payload: &mut [u8], work: &WorkReceiver) -> std::io::Result<()> {
        let req = match msg::decode_open_standard_channel(payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("stratum_v2: session {} OpenStandardMiningChannel decode failed: {e}", self.id);
                return Ok(());
            }
        };
        if self.channels.len() >= MAX_CHANNELS_PER_SESSION {
            return self.send_result(msg::open_mining_channel_error(req.request_id, msg::ERR_TOO_MANY_CHANNELS)).await;
        }
        let (payout, label) = match payout::resolve_worker(&req.user_identity, self.config.payout.as_ref()) {
            Ok(x) => x,
            Err(e) => {
                warn!("stratum_v2: session {} refused user {:?}: {e}", self.id, req.user_identity);
                return self.send_result(msg::open_mining_channel_error(req.request_id, msg::ERR_UNKNOWN_USER)).await;
            }
        };
        let current = work.borrow().clone();
        let block_target = current.as_ref().map(|w| bits_to_target(w.bits)).unwrap_or(Target::ZERO);
        let target = channel_target(req.nominal_hash_rate, &req.max_target, &block_target);
        if target == [0u8; 32] {
            return self.send_result(msg::open_mining_channel_error(req.request_id, msg::ERR_MAX_TARGET_OUT_OF_RANGE)).await;
        }
        let channel_id = self.channels.allocate_id();
        let extranonce = self.channels.extranonce_for(channel_id);
        let state = ChannelState::new(channel_id, req.user_identity.clone(), payout.clone(),
                                      req.nominal_hash_rate, target, extranonce);
        if let Err(e) = self.channels.insert(state) {
            warn!("stratum_v2: session {} channel insert failed: {e}", self.id);
            return self.send_result(msg::open_mining_channel_error(req.request_id, msg::ERR_TOO_MANY_CHANNELS)).await;
        }
        self.send_result(msg::open_standard_channel_success(req.request_id, channel_id, &target, &extranonce)).await?;
        info!("stratum_v2: session {} channel {channel_id} opened for {} -> pays {}{} (nominal {:.3e} H/s)",
              self.id, req.user_identity, payout.address,
              label.map(|l| format!(" (worker {l})")).unwrap_or_default(), req.nominal_hash_rate);
        match current {
            Some(w) => self.push_job(channel_id, &w, true).await,
            None => {
                info!("stratum_v2: session {} channel {channel_id}: waiting for the first block template", self.id);
                Ok(())
            }
        }
    }

    fn rate_ok(&mut self) -> bool {
        if self.submit_window.elapsed() >= Duration::from_secs(60) {
            self.submit_window = Instant::now();
            self.submits_in_window = 0;
        }
        self.submits_in_window += 1;
        self.submits_in_window <= SUBMIT_RATE_PER_MIN
    }

    async fn submit_error(&mut self, channel_id: u32, seq: u32, code: &str, result: &str) -> std::io::Result<()> {
        crate::metrics::stratum_share("v2", result);
        self.send_result(msg::submit_shares_error(channel_id, seq, code)).await
    }

    async fn submit_shares_standard(&mut self, payload: &mut [u8]) -> std::io::Result<()> {
        let s = match msg::decode_submit_shares_standard(payload) {
            Ok(s) => s,
            Err(e) => {
                warn!("stratum_v2: session {} SubmitSharesStandard decode failed: {e}", self.id);
                return Ok(());
            }
        };
        let (cid, seq) = (s.channel_id, s.sequence_number);
        if !self.rate_ok() {
            return self.submit_error(cid, seq, msg::ERR_RATE_LIMITED, "rejected").await;
        }
        let Some(ch) = self.channels.get_mut(cid) else {
            return self.submit_error(cid, seq, msg::ERR_INVALID_CHANNEL_ID, "stale").await;
        };
        let Some(cached) = ch.find_job(s.job_id).cloned() else {
            return self.submit_error(cid, seq, msg::ERR_INVALID_JOB_ID, "stale").await;
        };
        if !ch.record_share(s.job_id, s.nonce, s.ntime, s.version) {
            return self.submit_error(cid, seq, msg::ERR_DUPLICATE_SHARE, "dup").await;
        }
        let (extranonce, target) = (ch.extranonce_prefix, Target(ch.target));
        let solved = match reconstruct_block_for_sv2_submit(&cached, &extranonce, s.version, s.ntime, s.nonce) {
            Ok(x) => x,
            Err(BlockReconstructError::Solve(SolveError::BadVersion(_))) =>
                return self.submit_error(cid, seq, msg::ERR_INVALID_VERSION, "rejected").await,
            Err(BlockReconstructError::Solve(SolveError::TimeTooOld { .. } | SolveError::TimeTooNew { .. })) =>
                return self.submit_error(cid, seq, msg::ERR_INVALID_TIME, "rejected").await,
            Err(BlockReconstructError::Solve(SolveError::BitsChanged { .. })) =>
                return self.submit_error(cid, seq, msg::ERR_STALE_SHARE, "stale").await,
            Err(e) => {
                warn!("stratum_v2: session {} channel {cid} job {}: {e}", self.id, s.job_id);
                return self.submit_error(cid, seq, msg::ERR_OTHER, "rejected").await;
            }
        };
        let is_block = sha256d::meets_target(&solved.id, &cached.job.block_target());
        if !is_block && !sha256d::meets_target(&solved.id, &target) {
            return self.submit_error(cid, seq, msg::ERR_DIFFICULTY_TOO_LOW, "low_diff").await;
        }
        if is_block {
            let height = solved.block.height;
            let cb = self.config.accept_block.clone();
            let verdict = tokio::task::spawn_blocking(move || cb(solved.block)).await.map_err(io_err)?;
            match verdict {
                Ok(hash) => {
                    crate::metrics::stratum_block_found("v2");
                    info!("stratum_v2: session {} channel {cid} BLOCK FOUND h={height} id={hash} (job {}, version {:08x})",
                          self.id, s.job_id, s.version);
                }
                Err(reason) => {
                    warn!("stratum_v2: session {} channel {cid} block rejected by the node: {reason}", self.id);
                    return self.submit_error(cid, seq, msg::ERR_BLOCK_REJECTED, "rejected").await;
                }
            }
        }
        crate::metrics::stratum_share("v2", "ok");
        let accepted = self.channels.get_mut(cid).map(|c| { c.accepted = c.accepted.wrapping_add(1); c.accepted }).unwrap_or(0);
        debug!("stratum_v2: session {} channel {cid} share {seq} ok ({accepted} accepted)", self.id);
        self.send_result(msg::submit_shares_success(cid, seq, 1, 1)).await
    }

    async fn dispatch(&mut self, mut f: Frame, work: &WorkReceiver) -> std::io::Result<()> {
        if f.extension() != 0 {
            debug!("stratum_v2: session {} ignores extension {:#06x} message {:#04x}", self.id, f.extension(), f.msg_type);
            return Ok(());
        }
        match f.msg_type {
            msg::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => self.open_standard_channel(&mut f.payload, work).await,
            msg::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD => self.submit_shares_standard(&mut f.payload).await,
            msg::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
                let request_id = f.payload.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
                self.send_result(msg::open_mining_channel_error(request_id, msg::ERR_EXTENDED_UNSUPPORTED)).await
            }
            msg::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED => {
                let cid = f.payload.get(..4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
                let seq = f.payload.get(4..8).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
                self.submit_error(cid, seq, msg::ERR_INVALID_CHANNEL_ID, "rejected").await
            }
            other => {
                debug!("stratum_v2: session {} unhandled message {other:#04x} ({} bytes)", self.id, f.payload.len());
                Ok(())
            }
        }
    }
}

/// Read frames until EOF or an error; each goes to the session loop.
async fn reader_loop(mut rd: tokio::net::tcp::OwnedReadHalf, mut codec: NoiseCodec,
                     tx: mpsc::Sender<Result<Frame, FramingError>>) {
    loop {
        let r = framing::read_frame(&mut rd, &mut codec).await;
        let stop = r.is_err();
        if tx.send(r).await.is_err() || stop {
            return;
        }
    }
}

/// Serve one session after its handshake.
pub async fn run(
    id: u64,
    peer: SocketAddr,
    stream: TcpStream,
    codec: NoiseCodec,
    config: Arc<Sv2Config>,
    params: Sha256dParams,
    mut work: WorkReceiver,
) -> std::io::Result<SessionState> {
    let _ = stream.set_nodelay(true);
    let (rd, wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel(INBOUND_QUEUE);
    let reader = tokio::spawn(reader_loop(rd, codec.clone(), tx));
    let mut prefix = [0u8; 4];
    rand::rng().fill_bytes(&mut prefix);
    let mut s = Session {
        id, peer, config, params, wr, codec,
        channels: ChannelRegistry::new(prefix),
        next_job_id: 1,
        submit_window: Instant::now(),
        submits_in_window: 0,
    };
    let result = drive(&mut s, &mut rx, &mut work).await;
    reader.abort();
    result
}

async fn drive(
    s: &mut Session,
    rx: &mut mpsc::Receiver<Result<Frame, FramingError>>,
    work: &mut WorkReceiver,
) -> std::io::Result<SessionState> {
    // ── Phase 1: SetupConnection ─────────────────────────────────────────
    let first = match tokio::time::timeout(SETUP_CONNECTION_TIMEOUT, rx.recv()).await {
        Err(_) => {
            warn!("stratum_v2: session {} timed out awaiting SetupConnection", s.id);
            return Ok(SessionState::Closed);
        }
        Ok(None) => return Ok(SessionState::Closed),
        Ok(Some(Err(e))) => {
            debug!("stratum_v2: session {} closed before SetupConnection: {e}", s.id);
            return Ok(SessionState::Closed);
        }
        Ok(Some(Ok(f))) => f,
    };
    let mut payload = first.payload;
    let setup = match setup_connection::decode_setup_connection(first.msg_type, &mut payload) {
        Ok(x) => x,
        Err(e) => {
            warn!("stratum_v2: session {} SetupConnection decode failed: {e}; closing", s.id);
            return Ok(SessionState::Closed);
        }
    };
    let outcome = setup_connection::evaluate(&setup);
    info!("stratum_v2: session {} from {} SetupConnection protocol={} versions={}..={} flags={:#010x} \
           vendor={:?} hardware={:?} firmware={:?} device={:?}: {}",
          s.id, s.peer, setup.protocol, setup.min_version, setup.max_version, setup.flags,
          setup.vendor, setup.hardware_version, setup.firmware, setup.device_id,
          match &outcome { Ok(_) => "accepted".to_string(), Err(e) => format!("refused ({e})") });
    let (t, p) = setup_connection::encode_response(&outcome).map_err(io_err)?;
    s.send(Encoded { msg_type: t, channel_msg: false, payload: p }).await?;
    if outcome.is_err() {
        return Ok(SessionState::Closed);
    }
    work.borrow_and_update();

    // ── Phase 2: live ────────────────────────────────────────────────────
    loop {
        tokio::select! {
            f = rx.recv() => match f {
                None => return Ok(SessionState::Live),
                Some(Err(FramingError::Io(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("stratum_v2: session {} peer disconnected", s.id);
                    return Ok(SessionState::Closed);
                }
                Some(Err(e)) => return Err(io_err(e)),
                Some(Ok(frame)) => s.dispatch(frame, work).await?,
            },
            changed = work.changed() => {
                if changed.is_err() {
                    warn!("stratum_v2: session {}: the work feed stopped", s.id);
                    return Ok(SessionState::Closed);
                }
                let w = work.borrow_and_update().clone();
                if let Some(w) = w {
                    s.push_work(&w).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_target_is_never_harder_than_a_block_and_respects_max_target() {
        let block = bits_to_target(0x1d00_ffff);
        // A tiny miner: its rate target is easier than the block's...
        let t = channel_target(1.0e3, &[0xff; 32], &block);
        assert!(t >= block.0);
        // ...but never easier than the client's max_target.
        let mut max = [0u8; 32];
        max[8] = 1;
        assert_eq!(channel_target(1.0e3, &max, &block), max);
        // A huge miner is capped at the block target (no harder).
        let t = channel_target(1.0e30, &[0xff; 32], &block);
        assert_eq!(t, block.0);
        // Unknown hash rate: the easiest the client allows.
        assert_eq!(channel_target(0.0, &[0xff; 32], &block), [0xff; 32]);
    }

    #[test]
    fn session_states_are_distinct() {
        let all = [SessionState::Handshaking, SessionState::AwaitingSetupConnection, SessionState::Live, SessionState::Closed];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
        }
        assert_eq!(format!("{:?}", SessionState::Live), "Live");
    }
}
