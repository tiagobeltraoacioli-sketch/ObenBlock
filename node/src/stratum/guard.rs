//! Abuse limits shared by the V1 and V2 servers.
//!
//! * [`ConnTracker`]: the session cap of a listener, a per-IP cap, and
//!   eviction of the most idle session when the cap is reached (a session
//!   that has not had a share accepted for [`EVICT_IDLE_SECS`]), so a host
//!   that opens every slot and goes silent cannot lock real miners out.
//! * [`ConnActivity`]: the per-session record the tracker reads (opened,
//!   last accepted share) and the kill signal it sends.
//! * [`TokenBucket`]: a per-session budget for control requests
//!   (authorize, configure, suggest_difficulty, ...).
//! * [`LogLimiter`] and [`peer_str`]: per-session log volume and
//!   attacker-controlled strings (truncated, escaped) in log lines.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;

/// Default concurrent sessions per source IP (each listener). Operators
/// whose miners share an address (a rental proxy, a farm behind NAT) raise
/// it with `--stratum-max-sessions-per-ip` / `--stratum-v2-max-sessions-per-ip`.
pub const DEFAULT_MAX_SESSIONS_PER_IP: usize = 16;

/// A session with no accepted share for this long may be evicted when a
/// new connection finds the cap reached.
pub const EVICT_IDLE_SECS: u64 = 120;

/// Longest peer string written to a log line (bytes of the original).
pub const MAX_LOGGED_PEER_STR: usize = 64;

/// A peer-supplied string fit for a log line: at most
/// [`MAX_LOGGED_PEER_STR`] bytes of it (on a char boundary), with control
/// characters, quotes and backslashes escaped (`{:?}` style), so a peer can
/// neither forge log lines nor flood the log with one field.
pub fn peer_str(s: &str) -> String {
    let mut cut = s.len().min(MAX_LOGGED_PEER_STR);
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = format!("{:?}", &s[..cut]);
    if cut < s.len() {
        out.push_str(&format!("…(+{}B)", s.len() - cut));
    }
    out
}

/// Per-session log budget: the first `burst` lines pass, then one line per
/// `every`, which reports how many were suppressed in between.
#[derive(Debug)]
pub struct LogLimiter {
    burst: u32,
    every: Duration,
    used: u32,
    suppressed: u64,
    last: Option<Instant>,
}

impl LogLimiter {
    pub fn new(burst: u32, every: Duration) -> Self {
        Self { burst, every, used: 0, suppressed: 0, last: None }
    }

    /// Defaults of a session: 8 lines, then one a minute.
    pub fn per_session() -> Self {
        Self::new(8, Duration::from_secs(60))
    }

    /// `Some(suppressed_before)` when this line may be logged.
    pub fn allow(&mut self) -> Option<u64> {
        let now = Instant::now();
        if self.used < self.burst {
            self.used += 1;
            self.last = Some(now);
            return Some(0);
        }
        if self.last.is_none_or(|t| now.duration_since(t) >= self.every) {
            self.last = Some(now);
            return Some(std::mem::take(&mut self.suppressed));
        }
        self.suppressed += 1;
        None
    }
}

/// A token bucket: `burst` tokens, one more every `refill`.
#[derive(Debug)]
pub struct TokenBucket {
    burst: f64,
    per_sec: f64,
    tokens: f64,
    at: Instant,
}

impl TokenBucket {
    pub fn new(burst: u32, refill: Duration) -> Self {
        Self { burst: burst as f64, per_sec: 1.0 / refill.as_secs_f64().max(1e-9), tokens: burst as f64, at: Instant::now() }
    }

    /// Take one token; false when the bucket is empty.
    pub fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * self.per_sec).min(self.burst);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// What a tracker knows of one session, shared with the session itself.
#[derive(Debug)]
pub struct ConnActivity {
    opened: Instant,
    /// Milliseconds after `opened` of the last accepted share (0: none).
    last_share_ms: AtomicU64,
    killed: AtomicBool,
    kill: Notify,
}

impl Default for ConnActivity {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnActivity {
    pub fn new() -> Self {
        Self { opened: Instant::now(), last_share_ms: AtomicU64::new(0), killed: AtomicBool::new(false), kill: Notify::new() }
    }

    /// Record an accepted share.
    pub fn mark_share(&self) {
        let ms = Instant::now().duration_since(self.opened).as_millis().max(1);
        self.last_share_ms.store(u64::try_from(ms).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Whether a share was ever accepted.
    pub fn has_share(&self) -> bool {
        self.last_share_ms.load(Ordering::Relaxed) != 0
    }

    /// The last accepted share, else the opening.
    pub fn last_productive(&self) -> Instant {
        self.opened + Duration::from_millis(self.last_share_ms.load(Ordering::Relaxed))
    }

    /// Time since the last accepted share (or the opening).
    pub fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_productive())
    }

    /// Ask the session to close (it waits on [`Self::killed`]).
    pub fn kill(&self) {
        self.killed.store(true, Ordering::Relaxed);
        // notify_one keeps a permit for a session not waiting right now.
        self.kill.notify_one();
    }

    pub fn is_killed(&self) -> bool {
        self.killed.load(Ordering::Relaxed)
    }

    /// Resolves once [`Self::kill`] was called.
    pub async fn killed(&self) {
        if self.is_killed() {
            return;
        }
        self.kill.notified().await;
    }
}

/// Why a connection was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Every slot is taken by a session that is not idle.
    Full,
    /// This IP holds its maximum of sessions, none idle.
    PerIp,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Full => write!(f, "session cap reached"),
            Refused::PerIp => write!(f, "per-IP session cap reached"),
        }
    }
}

struct Entry {
    ip: IpAddr,
    activity: Arc<ConnActivity>,
}

/// The sessions of one listener: a global cap, a per-IP cap, and idle
/// eviction.
pub struct ConnTracker {
    max: usize,
    max_per_ip: usize,
    evict_idle: Duration,
    entries: Mutex<HashMap<u64, Entry>>,
}

/// A slot in a [`ConnTracker`]; released on drop.
pub struct ConnGuard {
    tracker: Arc<ConnTracker>,
    id: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.entries.lock().remove(&self.id);
    }
}

impl ConnTracker {
    pub fn new(max: usize, max_per_ip: usize) -> Self {
        Self::with_evict_idle(max, max_per_ip, Duration::from_secs(EVICT_IDLE_SECS))
    }

    pub fn with_evict_idle(max: usize, max_per_ip: usize, evict_idle: Duration) -> Self {
        Self { max: max.max(1), max_per_ip: max_per_ip.max(1), evict_idle, entries: Mutex::new(HashMap::new()) }
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sessions from `ip`.
    pub fn count_ip(&self, ip: IpAddr) -> usize {
        self.entries.lock().values().filter(|e| e.ip == ip).count()
    }

    /// Admit session `id` from `ip`. At a cap, the most idle session in
    /// scope (the same IP for the per-IP cap, any for the global cap) is
    /// killed and its slot taken, if it has been idle for the eviction
    /// threshold; otherwise the connection is refused.
    pub fn admit(self: &Arc<Self>, id: u64, ip: IpAddr, activity: Arc<ConnActivity>) -> Result<ConnGuard, Refused> {
        let now = Instant::now();
        let mut g = self.entries.lock();
        let most_idle = |g: &HashMap<u64, Entry>, same_ip: bool| -> Option<u64> {
            g.iter()
                .filter(|(_, e)| !same_ip || e.ip == ip)
                .filter(|(_, e)| e.activity.idle_for(now) >= self.evict_idle)
                .min_by_key(|(_, e)| e.activity.last_productive())
                .map(|(k, _)| *k)
        };
        if g.values().filter(|e| e.ip == ip).count() >= self.max_per_ip {
            let victim = most_idle(&g, true).ok_or(Refused::PerIp)?;
            if let Some(e) = g.remove(&victim) {
                e.activity.kill();
            }
        }
        if g.len() >= self.max {
            let victim = most_idle(&g, false).ok_or(Refused::Full)?;
            if let Some(e) = g.remove(&victim) {
                e.activity.kill();
            }
        }
        g.insert(id, Entry { ip, activity });
        Ok(ConnGuard { tracker: self.clone(), id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn peer_strings_are_truncated_and_escaped() {
        assert_eq!(peer_str("rig1"), "\"rig1\"");
        let forged = "x\n[INFO] BLOCK FOUND\r\u{1b}[31m";
        let s = peer_str(forged);
        assert!(!s.contains('\n') && !s.contains('\r') && !s.contains('\u{1b}'), "{s}");
        let long = "é".repeat(8_000);
        let s = peer_str(&long);
        assert!(s.len() < MAX_LOGGED_PEER_STR + 32, "{}", s.len());
        assert!(s.contains("(+"), "{s}");
    }

    #[tokio::test(start_paused = true)]
    async fn log_limiter_passes_a_burst_then_one_per_period() {
        let mut l = LogLimiter::new(3, Duration::from_secs(60));
        assert!((0..3).all(|_| l.allow() == Some(0)));
        for _ in 0..1_000 {
            assert_eq!(l.allow(), None);
        }
        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(l.allow(), Some(1_000), "reports what it suppressed");
        assert_eq!(l.allow(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn token_bucket_refills() {
        let mut b = TokenBucket::new(2, Duration::from_secs(10));
        assert!(b.take() && b.take());
        assert!(!b.take());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(b.take());
        assert!(!b.take());
    }

    #[tokio::test(start_paused = true)]
    async fn per_ip_cap_and_global_cap() {
        let t = Arc::new(ConnTracker::new(4, 2));
        let a = t.admit(1, ip(1), Arc::new(ConnActivity::new())).unwrap();
        let _b = t.admit(2, ip(1), Arc::new(ConnActivity::new())).unwrap();
        assert_eq!(t.admit(3, ip(1), Arc::new(ConnActivity::new())).err(), Some(Refused::PerIp));
        let _c = t.admit(4, ip(2), Arc::new(ConnActivity::new())).unwrap();
        let _d = t.admit(5, ip(3), Arc::new(ConnActivity::new())).unwrap();
        assert_eq!(t.admit(6, ip(4), Arc::new(ConnActivity::new())).err(), Some(Refused::Full));
        drop(a);
        assert_eq!(t.len(), 3);
        assert_eq!(t.count_ip(ip(1)), 1);
        assert!(t.admit(7, ip(1), Arc::new(ConnActivity::new())).is_ok(), "a released slot is free again");
    }

    #[tokio::test(start_paused = true)]
    async fn the_most_idle_session_is_evicted_at_the_cap() {
        let t = Arc::new(ConnTracker::new(2, 2));
        let busy = Arc::new(ConnActivity::new());
        let idle = Arc::new(ConnActivity::new());
        let _g1 = t.admit(1, ip(1), busy.clone()).unwrap();
        let _g2 = t.admit(2, ip(2), idle.clone()).unwrap();
        // Nobody idle long enough yet: refused.
        assert_eq!(t.admit(3, ip(3), Arc::new(ConnActivity::new())).err(), Some(Refused::Full));
        tokio::time::advance(Duration::from_secs(EVICT_IDLE_SECS + 1)).await;
        busy.mark_share();
        let _g3 = t.admit(3, ip(3), Arc::new(ConnActivity::new())).expect("the idle session makes room");
        assert!(idle.is_killed(), "the idle one is told to close");
        assert!(!busy.is_killed(), "the session with a recent share stays");
        tokio::time::timeout(Duration::from_secs(1), idle.killed()).await.expect("the kill signal resolves");
        assert_eq!(t.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn per_ip_eviction_stays_within_the_ip() {
        let t = Arc::new(ConnTracker::new(10, 1));
        let other = Arc::new(ConnActivity::new());
        let mine = Arc::new(ConnActivity::new());
        let _g1 = t.admit(1, ip(9), other.clone()).unwrap();
        let _g2 = t.admit(2, ip(1), mine.clone()).unwrap();
        tokio::time::advance(Duration::from_secs(EVICT_IDLE_SECS + 1)).await;
        let _g3 = t.admit(3, ip(1), Arc::new(ConnActivity::new())).unwrap();
        assert!(mine.is_killed() && !other.is_killed());
    }
}
