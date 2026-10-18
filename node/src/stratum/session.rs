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
//!   `1fffe000` (the legacy server declined it);
//! * `mining.notify` is the header job's `stratum` object (Bitcoin's Merkle
//!   tree: stock firmware mines it unmodified);
//! * the worker name is an `obb1…` address ([`super::payout`]).
//!
//! ```text
//!   Fresh       -- mining.subscribe --> Subscribed
//!   Subscribed  -- mining.authorize --> Authorized
//!   Authorized  (submit / configure / suggest_difficulty)
//! ```
//!
//! Limits (pre-launch review): a session is a slot a stranger can hold, so
//!
//! * 30 s from connection to Authorized, else closed;
//! * an authorized session with no accepted share for
//!   [`SHARE_IDLE_TIMEOUT_SECS`] is closed (vardiff lowers the share
//!   difficulty every [`VARDIFF_IDLE_SECS`] without a share, so a slow miner
//!   reaches shares long before that), and the listener may evict a session
//!   idle for `guard::EVICT_IDLE_SECS` when its cap is reached;
//! * control requests (subscribe, authorize, configure, suggest, ping,
//!   unknown methods) draw on a per-session budget ([`CONTROL_BURST`], one
//!   more every [`CONTROL_REFILL_SECS`]); `mining.authorize` may change the
//!   worker at most [`MAX_AUTHORIZE_PER_SESSION`] times, and a repeat of the
//!   same worker builds no job;
//! * [`MAX_PROTOCOL_ERRORS`] malformed requests close the session, and its
//!   warnings are rate-limited with peer strings truncated and escaped;
//! * shares are hashed before the submit limiter: a share that meets the
//!   block target is always submitted; above [`SUBMIT_RATE_PER_MIN`] other
//!   shares are refused and vardiff jumps to the observed rate, and above
//!   [`SUBMIT_FLOOD_PER_MIN`] the session is closed.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

use log::{debug, info, warn};
use parking_lot::Mutex;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::guard::{peer_str, ConnActivity, LogLimiter, TokenBucket};
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

/// Read-poll interval of an authorized session (the idle checks run at
/// least this often).
pub const IDLE_TIMEOUT_SECS: u64 = 30;

/// An authorized session with no accepted share for this long is closed
/// (env `OBB_STRATUM_SHARE_IDLE_SECS` overrides).
pub const SHARE_IDLE_TIMEOUT_SECS: u64 = 1_800;

/// Without an accepted share for this long, the share difficulty drops by
/// [`STEP_CLAMP_MIN`] (down to the floor) and the job is re-sent.
pub const VARDIFF_IDLE_SECS: u64 = 180;

/// Shares per minute per session the server judges below the block target
/// (a share that meets the block target is never refused for rate).
pub const SUBMIT_RATE_PER_MIN: u32 = 60;

/// Submits per minute that close the session (a flood, not a miner).
pub const SUBMIT_FLOOD_PER_MIN: u32 = 600;

/// After a vardiff raise, shares at the previous difficulty still count for
/// this long (they were mined before the miner saw the raise).
pub const RAISE_GRACE_SECS: u64 = 10;

/// Control-request budget: a burst, then one request per refill period.
pub const CONTROL_BURST: u32 = 16;
pub const CONTROL_REFILL_SECS: u64 = 30;

/// `mining.authorize` with a new worker, per session lifetime.
pub const MAX_AUTHORIZE_PER_SESSION: u32 = 4;

/// Malformed or refused requests that close the session.
pub const MAX_PROTOCOL_ERRORS: u32 = 16;

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

/// Starting share difficulty (env `OBB_STRATUM_START_DIFF` overrides; a
/// miner's `mining.suggest_difficulty` or `d=<diff>` password before its
/// first share wins). About 4.3e9 hashes per share: a CPU miner sees one
/// within minutes (vardiff lowers it when idle), and an ASIC that floods
/// shares at it is raised to its rate within seconds.
pub const START_SHARE_DIFF: f64 = 1.0;
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

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key).ok().and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0).unwrap_or(default)
}

/// Effective starting share difficulty.
pub fn start_share_diff() -> f64 { env_f64("OBB_STRATUM_START_DIFF", START_SHARE_DIFF) }
/// Effective minimum share difficulty.
pub fn min_share_diff() -> f64 { env_f64("OBB_STRATUM_MIN_DIFF", MIN_SHARE_DIFF) }
/// Effective share idle timeout.
pub fn share_idle_timeout() -> Duration {
    Duration::from_secs(env_f64("OBB_STRATUM_SHARE_IDLE_SECS", SHARE_IDLE_TIMEOUT_SECS as f64) as u64)
}

/// Duplicate-cache key: the share's header id. Two submits are the same
/// work exactly when they hash the same 80 bytes, however their fields were
/// spelled (hex case, `0x`, leading zeros) or whichever job id carried them.
type ShareKey = [u8; 32];

/// What the submit limiter says about one more submit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitRate {
    Ok,
    /// Over [`SUBMIT_RATE_PER_MIN`]: judge only a block, raise vardiff.
    Excess,
    /// Over [`SUBMIT_FLOOD_PER_MIN`]: close.
    Flood,
}

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
    /// Submits in the current minute and when it started.
    submit_window: Mutex<(Instant, u32)>,
    /// Whether vardiff was already raised for rate in this window.
    raised_in_window: AtomicBool,
    jobs: Mutex<VecDeque<SessionJob>>,
    submitted: Mutex<(HashSet<ShareKey>, VecDeque<ShareKey>)>,
    job_counter: AtomicU64,
    /// Negotiated BIP 310 version-rolling mask (0 = none).
    version_mask: AtomicU32,
    share_difficulty: Mutex<f64>,
    last_sent_difficulty: Mutex<f64>,
    share_window_start: Mutex<Instant>,
    shares_in_window: AtomicU32,
    /// The difficulty before the last raise, valid until the instant.
    grace: Mutex<Option<(f64, Instant)>>,
    /// Last vardiff idle step.
    last_idle_step: Mutex<Instant>,
    /// The listener's view of this session (idle eviction, kill signal).
    pub activity: Arc<ConnActivity>,
    /// A difficulty hint (`suggest_difficulty`, `d=`) arrived; ignored once
    /// a share was accepted.
    hinted: AtomicBool,
    hints_locked: AtomicBool,
    authorizations: AtomicU32,
    /// The worker changed: the dispatcher builds a job for the new payout.
    needs_job: AtomicBool,
    protocol_errors: AtomicU32,
    control: Mutex<TokenBucket>,
    log: Mutex<LogLimiter>,
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
            submit_window: Mutex::new((Instant::now(), 0)),
            raised_in_window: AtomicBool::new(false),
            jobs: Mutex::new(VecDeque::with_capacity(MAX_TEMPLATES_PER_SESSION)),
            submitted: Mutex::new((HashSet::new(), VecDeque::new())),
            job_counter: AtomicU64::new(0),
            version_mask: AtomicU32::new(0),
            share_difficulty: Mutex::new(start_share_diff()),
            last_sent_difficulty: Mutex::new(0.0),
            share_window_start: Mutex::new(Instant::now()),
            shares_in_window: AtomicU32::new(0),
            grace: Mutex::new(None),
            last_idle_step: Mutex::new(Instant::now()),
            activity: Arc::new(ConnActivity::new()),
            hinted: AtomicBool::new(false),
            hints_locked: AtomicBool::new(false),
            authorizations: AtomicU32::new(0),
            needs_job: AtomicBool::new(false),
            protocol_errors: AtomicU32::new(0),
            control: Mutex::new(TokenBucket::new(CONTROL_BURST, Duration::from_secs(CONTROL_REFILL_SECS))),
            log: Mutex::new(LogLimiter::per_session()),
        }
    }

    /// `Some(suppressed)` when this session may write one more warning.
    pub fn log_allow(&self) -> Option<u64> { self.log.lock().allow() }

    /// Count a malformed or refused request; true once the session has
    /// used up [`MAX_PROTOCOL_ERRORS`] (it is then marked Dead).
    pub fn protocol_error(&self) -> bool {
        let n = self.protocol_errors.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= MAX_PROTOCOL_ERRORS {
            self.set_state(SessionState::Dead);
            return true;
        }
        false
    }

    /// Take one control request from the budget; false (and Dead) when
    /// it is used up.
    pub fn control_ok(&self) -> bool {
        if self.control.lock().take() {
            return true;
        }
        self.set_state(SessionState::Dead);
        false
    }

    /// Take the "build a job for the new worker" flag.
    pub fn take_needs_job(&self) -> bool { self.needs_job.swap(false, Ordering::Relaxed) }

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

    /// Append a job (oldest evicted).
    pub fn push_job(&self, j: SessionJob) {
        let mut jobs = self.jobs.lock();
        if jobs.len() >= MAX_TEMPLATES_PER_SESSION {
            jobs.pop_front();
        }
        jobs.push_back(j);
    }

    /// Replace every job (clean jobs). The duplicate cache is keyed on
    /// header ids and bounded, so it is kept: a header credited on an older
    /// job is not credited again under a new job id.
    pub fn replace_jobs(&self, j: SessionJob) {
        let mut jobs = self.jobs.lock();
        jobs.clear();
        jobs.push_back(j);
    }

    /// The newest job.
    pub fn latest_job(&self) -> Option<SessionJob> {
        self.jobs.lock().back().cloned()
    }

    pub fn find_job(&self, job_id: &str) -> Option<SessionJob> {
        self.jobs.lock().iter().rev().find(|t| t.job_id == job_id).cloned()
    }

    /// Whether the share with header id `id` was already credited.
    pub fn is_duplicate(&self, id: &ShareKey) -> bool {
        self.submitted.lock().0.contains(id)
    }

    /// Remember a credited share (only shares that met a target are
    /// remembered: a share without proof of work costs no memory). FIFO,
    /// at most [`MAX_SUBMITTED_ENTRIES`].
    pub fn remember_share(&self, id: ShareKey) {
        let mut g = self.submitted.lock();
        let (set, order) = &mut *g;
        if set.insert(id) {
            order.push_back(id);
            while order.len() > MAX_SUBMITTED_ENTRIES {
                if let Some(old) = order.pop_front() {
                    set.remove(&old);
                }
            }
        }
    }

    /// Entries in the duplicate cache.
    pub fn remembered_shares(&self) -> usize {
        self.submitted.lock().0.len()
    }

    /// A share was accepted: the session is productive, and client
    /// difficulty hints no longer apply.
    pub fn note_accepted_share(&self) {
        self.activity.mark_share();
        self.hints_locked.store(true, Ordering::Relaxed);
    }

    /// Apply a client difficulty hint (`suggest_difficulty`, `d=`), only
    /// before the first accepted share. `Some(d)` when applied.
    pub fn apply_hint(&self, d: f64, net_cap: Option<f64>) -> Option<f64> {
        if !(d.is_finite() && d > 0.0) || self.hints_locked.load(Ordering::Relaxed) {
            return None;
        }
        let cap = net_cap.unwrap_or(f64::MAX).max(f64::MIN_POSITIVE);
        let clamped = d.clamp(min_share_diff().min(cap), cap);
        self.set_share_difficulty(clamped);
        self.hinted.store(true, Ordering::Relaxed);
        Some(clamped)
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

    /// The difficulty a share is judged at: the current one, or the one
    /// before the last raise during its grace period.
    pub fn judged_difficulty(&self) -> f64 {
        let cur = self.share_difficulty();
        match *self.grace.lock() {
            Some((prev, until)) if Instant::now() < until => cur.min(prev),
            _ => cur,
        }
    }

    fn raise_to(&self, new_diff: f64) {
        let cur = self.share_difficulty();
        if new_diff > cur {
            *self.grace.lock() = Some((cur, Instant::now() + Duration::from_secs(RAISE_GRACE_SECS)));
        }
        self.set_share_difficulty(new_diff);
        *self.share_window_start.lock() = Instant::now();
        self.shares_in_window.store(0, Ordering::Relaxed);
    }

    /// Count one submit against the per-minute limits.
    pub fn note_submit(&self) -> SubmitRate {
        let mut w = self.submit_window.lock();
        if w.0.elapsed() >= Duration::from_secs(60) {
            *w = (Instant::now(), 0);
            self.raised_in_window.store(false, Ordering::Relaxed);
        }
        w.1 = w.1.saturating_add(1);
        if w.1 > SUBMIT_FLOOD_PER_MIN {
            SubmitRate::Flood
        } else if w.1 > SUBMIT_RATE_PER_MIN {
            SubmitRate::Excess
        } else {
            SubmitRate::Ok
        }
    }

    /// The miner submits faster than the limiter allows: jump the share
    /// difficulty to the observed rate (one share per
    /// TARGET_SHARE_INTERVAL_SEC), once per window, capped at `net_diff`.
    /// `Some(d)` when a new difficulty is due (send it and the job again).
    pub fn raise_for_rate(&self, net_diff: f64) -> Option<f64> {
        if self.raised_in_window.swap(true, Ordering::Relaxed) {
            return None;
        }
        let (since, count) = *self.submit_window.lock();
        let per_sec = count as f64 / since.elapsed().as_secs_f64().max(1.0);
        let factor = (per_sec * TARGET_SHARE_INTERVAL_SEC).clamp(STEP_CLAMP_MAX, 1e9);
        let cap = net_diff.max(f64::MIN_POSITIVE);
        let cur = self.share_difficulty();
        let new_diff = (cur * factor).min(cap);
        if new_diff <= cur {
            return None;
        }
        self.raise_to(new_diff);
        Some(new_diff)
    }

    /// Vardiff's idle step: no accepted share for VARDIFF_IDLE_SECS (since
    /// the last share or the last step) lowers the difficulty by
    /// STEP_CLAMP_MIN, down to the floor. `Some(d)` when lowered.
    pub fn vardiff_idle_step(&self, now: Instant) -> Option<f64> {
        let mut last = self.last_idle_step.lock();
        let since = self.activity.last_productive().max(*last);
        if now.saturating_duration_since(since) < Duration::from_secs(VARDIFF_IDLE_SECS) {
            return None;
        }
        *last = now;
        let cur = self.share_difficulty();
        let next = (cur * STEP_CLAMP_MIN).max(min_share_diff());
        if next >= cur {
            return None;
        }
        self.set_share_difficulty(next);
        *self.share_window_start.lock() = Instant::now();
        self.shares_in_window.store(0, Ordering::Relaxed);
        Some(next)
    }

    /// Send `mining.set_difficulty(d)` and the newest job again (most
    /// firmware applies a difficulty to the next notify).
    pub fn announce_difficulty(&self, d: f64) {
        let _ = self.send_set_difficulty(d);
        if let Some(j) = self.latest_job() {
            let _ = self.notify(methods::NOTIFY, notify_params(&j.job, &j.job_id, false));
        }
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

/// `mining.notify` params of `job` under id `job_id`, straight from the
/// header job's `stratum` object:
/// `[job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]`
/// (`prevhash` word-swapped, integers as big-endian hex, as Bitcoin pools
/// send them: stock firmware builds the header from these alone).
pub fn notify_params(job: &Job, job_id: &str, clean_jobs: bool) -> Value {
    let s = &job.stratum;
    json!([job_id, s["prevhash"], s["coinb1"], s["coinb2"], s["merkle_branch"], s["version"], s["nbits"], s["ntime"],
           clean_jobs])
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
    let (template, prep) = (work.template.clone(), work.prep.clone());
    let extranonce = session.extranonce(&[0u8; EXTRANONCE2_BYTES]);
    let job = tokio::task::spawn_blocking(move || {
        Job::build_with(template, prep, &params, &payout.script_pubkey, extranonce, now_secs())
    })
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
    let _ = session.notify(methods::NOTIFY, notify_params(&job, &job_id, clean));
    debug!("stratum: session {} job {job_id} h={} bits={:08x} clean={clean} {} txs",
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

    let share_idle = share_idle_timeout();
    loop {
        if session.is_dead() || session.activity.is_killed() {
            debug!("stratum: session {} closing (dead peer, limit or eviction)", session.id);
            break;
        }
        if session.is_authorized() {
            let now = Instant::now();
            if session.activity.idle_for(now) >= share_idle {
                info!("stratum: session {} closed: no accepted share for {}s", session.id, share_idle.as_secs());
                let _ = session.send_line(StratumResponse::error(None, StratumError::new(ErrorCode::Other,
                    format!("no accepted share for {}s", share_idle.as_secs()))).to_line());
                break;
            }
            if let Some(d) = session.vardiff_idle_step(now) {
                debug!("stratum: session {} idle: share difficulty lowered to {d}", session.id);
                session.announce_difficulty(d);
            }
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
                            if let Some(n) = session.log_allow() {
                                warn!("stratum: session {} dispatch error: {}{}", session.id, peer_str(&e),
                                      super::suppressed_note(n));
                            }
                            let _ = session.send_line(StratumResponse::error(None,
                                StratumError::new(ErrorCode::Other, "malformed request")).to_line());
                            if session.protocol_error() {
                                info!("stratum: session {} closed after {MAX_PROTOCOL_ERRORS} protocol errors", session.id);
                            }
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
            _ = session.activity.killed() => {
                info!("stratum: session {} evicted (idle at the session cap)", session.id);
                break;
            }
            changed = work.changed(), if authorized => {
                if changed.is_err() {
                    warn!("stratum: session {}: the work feed stopped", session.id);
                    break;
                }
                let w = work.borrow_and_update().clone();
                if let Some(w) = w {
                    if let Err(e) = install_job(&session, &w, params, w.clean).await {
                        if let Some(n) = session.log_allow() {
                            warn!("stratum: session {} job on work #{} failed: {e}{}", session.id, w.seq,
                                  super::suppressed_note(n));
                        }
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
    if req.method != methods::SUBMIT && !session.control_ok() {
        info!("stratum: session {} closed: control-request budget used up", session.id);
        return Ok(Some(StratumResponse::error(req.id, StratumError::new(ErrorCode::Other, "too many requests"))));
    }
    match req.method.as_str() {
        methods::SUBSCRIBE => {
            let r = handle_subscribe(session, &req);
            if r.error.is_some() {
                session.protocol_error();
            }
            Ok(Some(r))
        }
        methods::AUTHORIZE => {
            // Sends its own lines in the order authorize result,
            // set_difficulty, notify.
            let resp = handle_authorize(session, &req, config.payout.as_ref());
            if resp.error.is_some() {
                session.protocol_error();
            }
            if session.take_needs_job() {
                let w = work.borrow_and_update().clone();
                match w {
                    Some(w) => {
                        if let Err(e) = install_job(session, &w, params, true).await {
                            if let Some(n) = session.log_allow() {
                                warn!("stratum: session {} authorized but its first job failed: {e}{}", session.id,
                                      super::suppressed_note(n));
                            }
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
            if let Some(n) = session.log_allow() {
                warn!("stratum: session {} unknown method {}{}", session.id, peer_str(other), super::suppressed_note(n));
            }
            session.protocol_error();
            // Never echo the peer's method name.
            Ok(Some(StratumResponse::error(req.id, StratumError::new(ErrorCode::Other, "unknown method"))))
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
/// first job follows it on the wire) and returns it. A repeat of the
/// current worker is answered without a new job; a new worker counts
/// against [`MAX_AUTHORIZE_PER_SESSION`]. `d=<difficulty>` in the password
/// is a difficulty hint (honoured before the first accepted share).
pub fn handle_authorize(session: &Arc<Session>, req: &StratumRequest, fallback: Option<&Payout>) -> StratumResponse {
    let send_err = |code, msg: &str| -> StratumResponse {
        let e = StratumResponse::error(req.id.clone(), StratumError::new(code, msg.to_string()));
        let _ = session.send_line(e.to_line());
        e
    };
    if session.state() == SessionState::Fresh {
        return send_err(ErrorCode::NotSubscribed, "must subscribe before authorizing");
    }
    let params = req.params.as_array();
    let Some(username) = params.and_then(|a| a.first()).and_then(Value::as_str) else {
        return send_err(ErrorCode::Unauthorized, "authorize requires [username, password]");
    };
    if session.is_authorized() && session.authorized_name().as_deref() == Some(username) {
        let ok = StratumResponse::ok(req.id.clone(), Value::from(true));
        let _ = session.send_line(ok.to_line());
        return ok;
    }
    if session.authorizations.load(Ordering::Relaxed) >= MAX_AUTHORIZE_PER_SESSION {
        return send_err(ErrorCode::Unauthorized, "too many workers on this connection");
    }
    match payout::resolve_worker(username, fallback) {
        Ok((p, label)) => {
            session.authorizations.fetch_add(1, Ordering::Relaxed);
            info!("stratum: session {} authorized {} -> pays {}{}", session.id, peer_str(username), p.address,
                  label.map(|l| format!(" (worker {})", peer_str(&l))).unwrap_or_default());
            let first = !session.is_authorized();
            session.set_authorized(username.to_string(), p);
            let pass = params.and_then(|a| a.get(1)).and_then(Value::as_str).unwrap_or("");
            for part in pass.split([',', ';', ' ']) {
                if let Some(d) = part.trim().strip_prefix("d=").and_then(|v| v.parse::<f64>().ok()) {
                    session.apply_hint(d, None);
                }
            }
            if first && !session.hinted.load(Ordering::Relaxed) {
                session.set_share_difficulty(start_share_diff());
            }
            session.needs_job.store(true, Ordering::Relaxed);
            let ok = StratumResponse::ok(req.id.clone(), Value::from(true));
            let _ = session.send_line(ok.to_line());
            ok
        }
        Err(e) => {
            if let Some(n) = session.log_allow() {
                warn!("stratum: session {} refused worker {}: {e}{}", session.id, peer_str(username),
                      super::suppressed_note(n));
            }
            send_err(ErrorCode::Unauthorized, &e)
        }
    }
}

/// `mining.configure [extensions, params]` (BIP 310): version rolling with
/// the BIP 320 mask (`1fffe000`, intersected with the miner's mask). Other
/// extensions are declined.
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
            other => {
                result.insert(other.to_string(), json!(false));
            }
        }
    }
    StratumResponse::ok(req.id.clone(), Value::Object(result))
}

/// `mining.suggest_difficulty [d]`: seed the share difficulty, capped at
/// the current network difficulty, and confirm it with set_difficulty.
/// Only before the first accepted share: afterwards vardiff owns the
/// difficulty and the hint is acknowledged and ignored.
fn handle_suggest_difficulty(session: &Arc<Session>, req: &StratumRequest, work: &WorkReceiver) -> StratumResponse {
    if let Some(d) = req.params.as_array().and_then(|a| a.first()).and_then(Value::as_f64) {
        let cap = work.borrow().as_ref().map(|w| difficulty::difficulty_from_bits(w.bits));
        if let Some(applied) = session.apply_hint(d, cap) {
            if session.is_authorized() {
                session.announce_difficulty(applied);
            } else {
                let _ = session.send_set_difficulty(applied);
            }
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
    fn submit_limiter_has_an_excess_band_then_a_flood_cap() {
        let s = mk_session();
        for _ in 0..SUBMIT_RATE_PER_MIN {
            assert_eq!(s.note_submit(), SubmitRate::Ok);
        }
        for _ in SUBMIT_RATE_PER_MIN..SUBMIT_FLOOD_PER_MIN {
            assert_eq!(s.note_submit(), SubmitRate::Excess);
        }
        assert_eq!(s.note_submit(), SubmitRate::Flood);
    }

    #[test]
    fn excess_rate_jumps_vardiff_once_per_window_with_a_grace() {
        let s = mk_session();
        s.set_share_difficulty(1.0);
        for _ in 0..=SUBMIT_RATE_PER_MIN {
            s.note_submit();
        }
        // 61 submits in well under a second: about 610 shares per target
        // interval at difficulty 1.
        let d = s.raise_for_rate(1e12).expect("raised");
        assert!(d >= 600.0 && d <= 1e9, "{d}");
        assert_eq!(s.share_difficulty(), d);
        assert_eq!(s.judged_difficulty(), 1.0, "shares at the old difficulty count during the grace");
        assert!(s.raise_for_rate(1e12).is_none(), "once per window");
        // Never above the network difficulty.
        let t = mk_session();
        t.set_share_difficulty(1.0);
        for _ in 0..=SUBMIT_RATE_PER_MIN {
            t.note_submit();
        }
        assert_eq!(t.raise_for_rate(5.0), Some(5.0));
    }

    #[tokio::test(start_paused = true)]
    async fn the_raise_grace_expires() {
        let s = mk_session();
        s.set_share_difficulty(1.0);
        for _ in 0..=SUBMIT_RATE_PER_MIN {
            s.note_submit();
        }
        let d = s.raise_for_rate(1e12).unwrap();
        tokio::time::advance(Duration::from_secs(RAISE_GRACE_SECS + 1)).await;
        assert_eq!(s.judged_difficulty(), d);
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_miner_gets_an_easier_difficulty_down_to_the_floor() {
        let s = mk_session();
        s.set_share_difficulty(1.0);
        assert!(s.vardiff_idle_step(Instant::now()).is_none(), "not idle yet");
        tokio::time::advance(Duration::from_secs(VARDIFF_IDLE_SECS)).await;
        assert_eq!(s.vardiff_idle_step(Instant::now()), Some(0.25));
        assert!(s.vardiff_idle_step(Instant::now()).is_none(), "one step per idle period");
        for _ in 0..20 {
            tokio::time::advance(Duration::from_secs(VARDIFF_IDLE_SECS)).await;
            s.vardiff_idle_step(Instant::now());
        }
        assert_eq!(s.share_difficulty(), min_share_diff());
        // A share resets the idle clock.
        s.set_share_difficulty(1.0);
        tokio::time::advance(Duration::from_secs(VARDIFF_IDLE_SECS - 1)).await;
        s.note_accepted_share();
        tokio::time::advance(Duration::from_secs(VARDIFF_IDLE_SECS - 1)).await;
        assert!(s.vardiff_idle_step(Instant::now()).is_none());
    }

    #[test]
    fn duplicate_cache_is_keyed_on_header_ids_and_bounded() {
        let s = mk_session();
        let id = |n: u32| { let mut k = [0u8; 32]; k[..4].copy_from_slice(&n.to_le_bytes()); k };
        assert!(!s.is_duplicate(&id(1)));
        s.remember_share(id(1));
        assert!(s.is_duplicate(&id(1)));
        for n in 2..(MAX_SUBMITTED_ENTRIES as u32 + 10) {
            s.remember_share(id(n));
        }
        assert_eq!(s.remembered_shares(), MAX_SUBMITTED_ENTRIES);
        assert!(!s.is_duplicate(&id(1)), "oldest evicted first");
        assert!(s.is_duplicate(&id(MAX_SUBMITTED_ENTRIES as u32 + 9)));
        // Clean jobs keep the cache (a header is credited once).
        s.replace_jobs(SessionJob { job_id: "x".into(), job: test_job() });
        assert!(s.is_duplicate(&id(MAX_SUBMITTED_ENTRIES as u32 + 9)));
    }

    #[test]
    fn difficulty_hints_apply_only_before_the_first_accepted_share() {
        let s = mk_session();
        s.set_state(SessionState::Subscribed);
        assert_eq!(s.apply_hint(65_536.0, Some(1e9)), Some(65_536.0));
        assert_eq!(s.apply_hint(1e12, Some(1e9)), Some(1e9), "capped at the network difficulty");
        assert!(s.apply_hint(f64::NAN, None).is_none());
        // The hint survives authorization (no reset to the start difficulty).
        let r = handle_authorize(&s, &req(2, methods::AUTHORIZE, json!([valid_addr(), "x"])), None);
        assert!(r.error.is_none());
        assert_eq!(s.share_difficulty(), 1e9);
        s.note_accepted_share();
        assert!(s.apply_hint(0.001, None).is_none(), "vardiff owns the difficulty now");
        assert_eq!(s.share_difficulty(), 1e9);
    }

    #[test]
    fn password_difficulty_is_a_hint() {
        let s = mk_session();
        s.set_state(SessionState::Subscribed);
        handle_authorize(&s, &req(2, methods::AUTHORIZE, json!([valid_addr(), "x,d=4096"])), None);
        assert_eq!(s.share_difficulty(), 4096.0);
        let t = mk_session();
        t.set_state(SessionState::Subscribed);
        handle_authorize(&t, &req(2, methods::AUTHORIZE, json!([valid_addr(), "x"])), None);
        assert_eq!(t.share_difficulty(), start_share_diff());
    }

    #[test]
    fn re_authorize_builds_no_job_and_new_workers_are_capped() {
        let s = mk_session();
        s.set_state(SessionState::Subscribed);
        assert!(handle_authorize(&s, &req(1, methods::AUTHORIZE, json!([valid_addr(), "x"])), None).error.is_none());
        assert!(s.take_needs_job(), "the first authorize builds a job");
        for i in 0..100 {
            let r = handle_authorize(&s, &req(2 + i, methods::AUTHORIZE, json!([valid_addr(), "x"])), None);
            assert!(r.error.is_none());
            assert!(!s.take_needs_job(), "a repeat of the same worker builds nothing");
        }
        for i in 1..MAX_AUTHORIZE_PER_SESSION {
            let w = format!("{}.rig{i}", valid_addr());
            assert!(handle_authorize(&s, &req(500 + i as i64, methods::AUTHORIZE, json!([w, "x"])), None).error.is_none());
            assert!(s.take_needs_job(), "a new worker gets its job");
        }
        let r = handle_authorize(&s, &req(900, methods::AUTHORIZE, json!([format!("{}.extra", valid_addr()), "x"])), None);
        assert_eq!(r.error.as_ref().unwrap()[0], json!(24), "worker changes are capped");
        assert!(!s.take_needs_job());
    }

    #[test]
    fn protocol_errors_and_the_control_budget_close_the_session() {
        let s = mk_session();
        for _ in 0..(MAX_PROTOCOL_ERRORS - 1) {
            assert!(!s.protocol_error());
        }
        assert!(s.protocol_error());
        assert!(s.is_dead());
        let t = mk_session();
        for _ in 0..CONTROL_BURST {
            assert!(t.control_ok());
        }
        assert!(!t.control_ok());
        assert!(t.is_dead());
    }

    /// A job stub (the session caches only look at ids).
    fn test_job() -> Arc<Job> {
        let template = Arc::new(crate::template::BlockTemplate {
            parents: vec![], height: 1, blue_score: 1, bits: 0x1d00_ffff, parent_timestamp: 0,
            transactions: vec![], total_fees: 0, subsidy: 0, evicted: 0, tx_byte_budget: 0,
            activation_height: 0, hardened: true, powit: Default::default(),
        });
        let prep = Arc::new(super::super::jobs::JobPrep::new(&template, None, 0));
        Arc::new(Job {
            template, prep, params: test_params(), script_pubkey: vec![0; 20], built_at: 0,
            header: [0; 80], coinb1: vec![], coinb2: vec![], extranonce: [0; 8],
            version: 0x2000_0000, time: 0, bits: 0x1d00_ffff, parents_commitment: [0; 32], merkle_branch: vec![],
            window: crate::mining::sha256d::TimeWindow { curtime: 0, mintime: 0, maxtime: 0, bits: 0x1d00_ffff,
                                                         relief_step: 0, next_bits_time: None },
            stratum: serde_json::Value::Null,
        })
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
            max_sessions_per_ip: 4,
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

    async fn read_until(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>, needle: &str) -> String {
        loop {
            let l = read_json_line(reader).await;
            if l.contains(needle) {
                return l;
            }
        }
    }

    #[tokio::test]
    async fn authorized_session_without_shares_is_closed_at_the_share_idle_timeout() {
        let (client, session, _wtx) = spawn_session_pair().await;
        let (rd, mut wr) = client.into_split();
        let mut rdr = BufReader::new(rd);
        send_json(&mut wr, r#"{"id":1,"method":"mining.subscribe","params":["cpuminer/2.5"]}"#).await;
        let _ = read_json_line(&mut rdr).await;
        send_json(&mut wr, &format!(r#"{{"id":2,"method":"mining.authorize","params":["{}","x"]}}"#, valid_addr())).await;
        let auth = read_json_line(&mut rdr).await;
        assert!(auth.contains("true"), "{auth}");
        assert_eq!(session.state(), SessionState::Authorized);

        // Quiet for a while (vardiff steps the difficulty down): kept.
        tokio::time::pause();
        tokio::time::sleep(Duration::from_secs(SHARE_IDLE_TIMEOUT_SECS - 120)).await;
        tokio::time::resume();
        assert_eq!(session.state(), SessionState::Authorized, "a quiet authorized session is kept for a while");
        assert!(read_until(&mut rdr, methods::SET_DIFFICULTY).await.contains("0.25"), "the idle step lowered it");
        send_json(&mut wr, r#"{"id":3,"method":"mining.ping","params":[]}"#).await;
        read_until(&mut rdr, "pong").await;

        // No share at all for the share idle timeout: closed.
        tokio::time::pause();
        tokio::time::sleep(Duration::from_secs(240)).await;
        tokio::time::resume();
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut all = String::new();
            loop {
                let mut line = String::new();
                match rdr.read_line(&mut line).await {
                    Ok(0) | Err(_) => break all,
                    Ok(_) => all.push_str(&line),
                }
            }
        }).await.expect("the server closes the socket");
        assert!(closed.contains("no accepted share"), "{closed}");
        assert!(session.is_dead());
    }

    #[tokio::test]
    async fn an_evicted_session_closes() {
        let (client, session, _wtx) = spawn_session_pair().await;
        let (rd, _wr) = client.into_split();
        let mut rdr = BufReader::new(rd);
        session.activity.kill();
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(10), rdr.read_line(&mut line)).await.expect("closed").unwrap_or(0);
        assert_eq!(n, 0, "{line}");
    }

    #[tokio::test]
    async fn protocol_error_flood_closes_the_socket() {
        let (client, session, _wtx) = spawn_session_pair().await;
        let (rd, mut wr) = client.into_split();
        let mut rdr = BufReader::new(rd);
        let forged = format!(r#"{{"id":1,"method":"{}"}}"#, "x\\n[INFO] BLOCK FOUND ".repeat(300));
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..(MAX_PROTOCOL_ERRORS + 4) {
                if wr.write_all(format!("{forged}\n").as_bytes()).await.is_err() {
                    break;
                }
            }
            let mut answers = 0;
            loop {
                let mut line = String::new();
                match rdr.read_line(&mut line).await {
                    Ok(0) | Err(_) => break answers,
                    Ok(_) => {
                        assert!(!line.contains("BLOCK FOUND"), "the method name is not echoed: {line}");
                        answers += 1;
                    }
                }
            }
        }).await.expect("the server closes the socket");
        assert!(closed <= MAX_PROTOCOL_ERRORS + 1, "{closed} answers before the close");
        assert!(session.is_dead());
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
