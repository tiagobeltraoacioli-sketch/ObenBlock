//! Shared types of the ObenBlock stratum server: identity, configuration,
//! errors, share outcomes and the process-wide counters.
//!
//! ```text
//!   ASIC / obenblock-cpu-miner ── TCP :3333 ──▶ [session]  one per connection
//!                                                   │  jobs (watch channel)
//!                                                   ▼
//!                                              [template] ── JSON-RPC ──▶ ObenBlock node
//!                                                   getdaginfo (tip poll)
//!                                                   getblocktemplate {header_job}
//!                                                   submitblock [block, {version,time,nonce}]
//! ```
//!
//! Unlike the Bloch proxy it is ported from, there is no node-side stratum:
//! the server builds every job itself from the node's header job
//! (docs/OBENBLOCK-MINING.md §3.2), assigns each connection a unique
//! `extranonce1`, validates every share with the node's own SHA-256d
//! functions (`gnb-smh`) and submits a full block when a share meets the
//! block target.

use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Monotonic per-process connection id, assigned by the accept loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkerId(pub u64);

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "w{}", self.0)
    }
}

/// One newline-terminated stratum line.
pub type Line = String;

/// Hard cap on a single stratum line. A longer line is a protocol violation
/// and closes the session.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Bytes of `extranonce1` the server assigns to a connection.
pub const EXTRANONCE1_LEN: usize = 4;
/// Bytes of `extranonce2` a miner rolls. `EXTRANONCE1_LEN + EXTRANONCE2_LEN`
/// is the node's header-job extranonce length (8, `extranonce_bytes`).
pub const EXTRANONCE2_LEN: usize = 4;

/// Network the server mines on; selects the address prefixes it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// ObenBlock mainnet: `obb1q…`, `obb1m…`, `obb1z…` (and the GnB/Bloch
    /// mainnet aliases).
    Mainnet,
    /// ObenBlock regtest, which uses the testnet address slot: `obb1t…`,
    /// `obb1n…`, `tobb1z…`.
    Regtest,
}

/// Where the coinbase of every job pays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payout {
    /// The configured address, as given.
    pub address: String,
    /// Its output script (a 20-byte key hash or `0x02 ‖` a 32-byte policy hash).
    pub script_pubkey: Vec<u8>,
}

/// Runtime configuration, loaded by [`crate::server::config_from_env`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StratumConfig {
    /// Where miners connect. Default `0.0.0.0:3333`.
    pub listen_addr: String,
    /// Prometheus text (and `/pplns`) endpoint. Default `127.0.0.1:9333`.
    pub metrics_addr: String,
    /// Node JSON-RPC `host:port`. Default `127.0.0.1:18210` (ObenBlock mainnet).
    pub rpc_addr: String,
    /// API key the node requires for `getblocktemplate` / `submitblock`
    /// (sent as `X-API-Key`).
    pub rpc_api_key: Option<String>,
    pub network: Network,
    /// The address every coinbase pays (solo pool).
    pub payout: Payout,
    /// Accept any username in `mining.authorize`. Off: the username must be
    /// an ObenBlock address of this network, optionally followed by
    /// `.<worker>` (the payout never depends on it: solo pool).
    pub any_user: bool,
    /// How long a new connection may take to subscribe.
    pub handshake_timeout: Duration,
    /// A connection silent for this long is closed.
    pub idle_timeout: Duration,
    /// Tip poll interval (`getdaginfo`).
    pub poll_interval: Duration,
    /// A new job (same parents, fresh time and mempool) at least this often.
    pub refresh_interval: Duration,
    pub vardiff_target_secs: f64,
    pub vardiff_initial: f64,
    pub vardiff_min: f64,
    pub vardiff_max: f64,
    pub vardiff_retarget_shares: usize,
    pub vardiff_grace_secs: u64,
    /// PPLNS window, in shares. 0 (default) turns share accounting off; the
    /// server is a solo pool and never pays anyone but `payout`.
    pub pplns_window_shares: usize,
    /// PPLNS window, in seconds (0: no time bound).
    pub pplns_window_secs: u64,
    pub max_workers: usize,
    pub max_connections_per_ip: usize,
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:3333".to_string(),
            metrics_addr: "127.0.0.1:9333".to_string(),
            rpc_addr: "127.0.0.1:18210".to_string(),
            rpc_api_key: None,
            network: Network::Mainnet,
            payout: Payout { address: String::new(), script_pubkey: Vec::new() },
            any_user: false,
            handshake_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(600),
            poll_interval: Duration::from_millis(500),
            refresh_interval: Duration::from_secs(30),
            vardiff_target_secs: 10.0,
            vardiff_initial: 65_536.0,
            vardiff_min: 1.0,
            vardiff_max: 4_294_967_296.0 * 1024.0,
            vardiff_retarget_shares: 8,
            vardiff_grace_secs: 120,
            pplns_window_shares: 0,
            pplns_window_secs: 0,
            max_workers: 4096,
            max_connections_per_ip: 64,
        }
    }
}

/// Unified error type.
#[derive(Debug)]
pub enum PoolError {
    Io(std::io::Error),
    /// Malformed or unexpected content (stratum or RPC).
    Protocol(String),
    /// The node answered with an error, or refused.
    Node(String),
    /// A bounded wait elapsed.
    Timeout(String),
    /// Bad configuration at startup.
    Config(String),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::Io(e) => write!(f, "io: {e}"),
            PoolError::Protocol(m) => write!(f, "protocol: {m}"),
            PoolError::Node(m) => write!(f, "node: {m}"),
            PoolError::Timeout(m) => write!(f, "timeout: {m}"),
            PoolError::Config(m) => write!(f, "config: {m}"),
        }
    }
}

impl std::error::Error for PoolError {}

impl From<std::io::Error> for PoolError {
    fn from(e: std::io::Error) -> Self {
        PoolError::Io(e)
    }
}

/// Outcome of one submitted share.
#[derive(Clone, Debug, PartialEq)]
pub enum ShareOutcome {
    /// Met the connection's share target.
    Accepted,
    /// Met the block target too; the block went to the node.
    Block,
    /// Unknown job, or a job of a replaced tip (error 21).
    Stale,
    /// Submitted before (error 22).
    Duplicate,
    /// Below the share target (error 23).
    LowDifficulty,
    /// Any other rejection.
    Rejected { code: i64, message: String },
}

impl ShareOutcome {
    pub fn is_accepted(&self) -> bool {
        matches!(self, ShareOutcome::Accepted | ShareOutcome::Block)
    }
}

/// Stratum error codes (Bitcoin pool convention).
pub mod error_codes {
    pub const OTHER: i64 = 20;
    pub const JOB_NOT_FOUND_OR_STALE: i64 = 21;
    pub const DUPLICATE_SHARE: i64 = 22;
    pub const LOW_DIFFICULTY: i64 = 23;
    pub const UNAUTHORIZED: i64 = 24;
    pub const NOT_SUBSCRIBED: i64 = 25;
}

/// Stratum method names.
pub mod methods {
    pub const SUBSCRIBE: &str = "mining.subscribe";
    pub const AUTHORIZE: &str = "mining.authorize";
    pub const SUBMIT: &str = "mining.submit";
    pub const CONFIGURE: &str = "mining.configure";
    pub const EXTRANONCE_SUBSCRIBE: &str = "mining.extranonce.subscribe";
    pub const SUGGEST_DIFFICULTY: &str = "mining.suggest_difficulty";
    pub const SUGGEST_TARGET: &str = "mining.suggest_target";
    pub const NOTIFY: &str = "mining.notify";
    pub const SET_DIFFICULTY: &str = "mining.set_difficulty";
}

/// Process-wide counters, shared as `Arc<Metrics>` and rendered by
/// [`crate::metrics`].
#[derive(Debug, Default)]
pub struct Metrics {
    pub workers_active: AtomicI64,
    pub workers_total: AtomicU64,
    pub workers_authorized: AtomicI64,
    pub shares_accepted: AtomicU64,
    pub shares_rejected: AtomicU64,
    pub shares_stale: AtomicU64,
    pub shares_duplicate: AtomicU64,
    pub shares_low_difficulty: AtomicU64,
    /// Accepted shares weighted by their difficulty (hashrate estimate).
    pub share_work_total: AtomicU64,
    pub blocks_found: AtomicU64,
    pub blocks_accepted: AtomicU64,
    pub blocks_rejected: AtomicU64,
    pub rpc_failures: AtomicU64,
    pub templates_total: AtomicU64,
    pub template_height: AtomicI64,
    pub template_bits: AtomicI64,
    pub template_parent_count: AtomicI64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn worker_connected(&self) {
        self.workers_active.fetch_add(1, Ordering::Relaxed);
        self.workers_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_disconnected(&self) {
        self.workers_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Fold one share outcome into the counters.
    pub fn record_outcome(&self, outcome: &ShareOutcome, difficulty: f64) {
        match outcome {
            ShareOutcome::Accepted | ShareOutcome::Block => {
                self.shares_accepted.fetch_add(1, Ordering::Relaxed);
                let w = if difficulty.is_finite() && difficulty > 0.0 { difficulty.min(u64::MAX as f64) } else { 0.0 };
                self.share_work_total.fetch_add(w as u64, Ordering::Relaxed);
                if matches!(outcome, ShareOutcome::Block) {
                    self.blocks_found.fetch_add(1, Ordering::Relaxed);
                }
            }
            ShareOutcome::Stale => {
                self.shares_rejected.fetch_add(1, Ordering::Relaxed);
                self.shares_stale.fetch_add(1, Ordering::Relaxed);
            }
            ShareOutcome::Duplicate => {
                self.shares_rejected.fetch_add(1, Ordering::Relaxed);
                self.shares_duplicate.fetch_add(1, Ordering::Relaxed);
            }
            ShareOutcome::LowDifficulty => {
                self.shares_rejected.fetch_add(1, Ordering::Relaxed);
                self.shares_low_difficulty.fetch_add(1, Ordering::Relaxed);
            }
            ShareOutcome::Rejected { .. } => {
                self.shares_rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let li = |a: &AtomicI64| a.load(Ordering::Relaxed);
        MetricsSnapshot {
            workers_active: li(&self.workers_active),
            workers_total: l(&self.workers_total),
            workers_authorized: li(&self.workers_authorized),
            shares_accepted: l(&self.shares_accepted),
            shares_rejected: l(&self.shares_rejected),
            shares_stale: l(&self.shares_stale),
            shares_duplicate: l(&self.shares_duplicate),
            shares_low_difficulty: l(&self.shares_low_difficulty),
            share_work_total: l(&self.share_work_total),
            blocks_found: l(&self.blocks_found),
            blocks_accepted: l(&self.blocks_accepted),
            blocks_rejected: l(&self.blocks_rejected),
            rpc_failures: l(&self.rpc_failures),
            templates_total: l(&self.templates_total),
            template_height: li(&self.template_height),
            template_bits: li(&self.template_bits),
            template_parent_count: li(&self.template_parent_count),
            bytes_in: l(&self.bytes_in),
            bytes_out: l(&self.bytes_out),
        }
    }
}

/// Flat copy of the counters for the Prometheus renderer.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct MetricsSnapshot {
    pub workers_active: i64,
    pub workers_total: u64,
    pub workers_authorized: i64,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    pub shares_stale: u64,
    pub shares_duplicate: u64,
    pub shares_low_difficulty: u64,
    pub share_work_total: u64,
    pub blocks_found: u64,
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub rpc_failures: u64,
    pub templates_total: u64,
    pub template_height: i64,
    pub template_bits: i64,
    pub template_parent_count: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
