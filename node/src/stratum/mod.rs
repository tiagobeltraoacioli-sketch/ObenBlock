//! Built-in Stratum V1 server (solo mode), ported from the legacy Bloch PoW
//! node (genesis3-node `src/stratum`) to ObenBlock's SHA-256d header.
//!
//! Enabled with `--stratum` (default bind `0.0.0.0:3333`); off by default.
//! Operator guide: docs/STRATUM.md.
//!
//! ```text
//!   tip broadcast (TipChanged) ──► work feed (work.rs) ── watch ──┬─► V1 sessions (this module)
//!   60 s refresh, stall-relief steps ─┘   template::build_block_template  └─► V2 sessions (stratum_v2)
//!
//!   session: subscribe → configure → authorize(worker = obb1 address)
//!            each work update → Job (= getblocktemplate header job) → mining.notify
//!            mining.submit → Job::solve → share/block target → accept (same path as submitblock)
//! ```
//!
//! Solo semantics, as in the legacy server: every block found pays its whole
//! coinbase to the worker's address ([`payout`]); no share accounting, no
//! payout logic. Shares below the block target are acknowledged against a
//! per-session vardiff target so miners see their hashrate.
//!
//! Only for SHA-256d chains (ObenBlock): [`require_sha256d_chain`] refuses a
//! GnB-SMH chain, whose blocks a SHA-256d share can never prove.

pub mod difficulty;
pub mod guard;
pub mod jobs;
pub mod payout;
pub mod protocol;
pub mod session;
pub mod submit;
pub mod work;

#[allow(unused_imports)] // re-exports for the library API; the binary uses a subset
pub use jobs::Job;
pub use payout::Payout;
#[allow(unused_imports)]
pub use protocol::{ErrorCode, StratumError, StratumRequest, StratumResponse};
#[allow(unused_imports)]
pub use session::{Session, SessionState};
#[allow(unused_imports)]
pub use guard::DEFAULT_MAX_SESSIONS_PER_IP;
#[allow(unused_imports)]
pub use work::{Work, WorkReceiver};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use parking_lot::RwLock;
use tokio::net::TcpListener;

use crate::consensus::GhostDAG;
use crate::core::pow_scheme::{self, Sha256dParams};
use crate::mempool::Mempool;
use crate::storage::Storage;

/// Default V1 port (every ASIC firmware's default).
pub const DEFAULT_STRATUM_PORT: u16 = 3333;

/// Default V1 bind address.
pub const DEFAULT_STRATUM_ADDR: &str = "0.0.0.0:3333";

/// Default maximum of concurrent V1 sessions.
pub const DEFAULT_MAX_SESSIONS: usize = 256;

/// Upper bound accepted for `--stratum-max-sessions`.
pub const MAX_SESSIONS_CAP: usize = 10_000;

/// Callback into the node's acceptance path: the same hook as RPC
/// `submitblock` (`main.rs::make_rpc_submit_block_cb`: block-id dedup,
/// minimum chain work, `validate_structure_without_pow`, `accept_block`,
/// gossip). Returns the block id hex, or the rejection reason.
pub type AcceptBlockFn = crate::rpc::SubmitBlockFn;

/// The node handles template building needs.
pub struct NodeContext {
    pub dag: Arc<RwLock<GhostDAG>>,
    pub store: Arc<Storage>,
    pub mempool: Arc<Mempool>,
    /// The node's minimum chain work (no template below it, as
    /// `getblocktemplate`).
    pub min_chain_work: u128,
}

/// The SHA-256d parameters of the node's chain, or why stratum must not
/// start: the stratum servers produce SHA-256d work (an 80-byte header and
/// a 32-bit nonce), which proves nothing on a GnB-SMH chain.
pub fn require_sha256d_chain() -> Result<Sha256dParams, String> {
    pow_scheme::node_sha256d_params().ok_or_else(|| format!(
        "stratum is only for SHA-256d chains (ObenBlock): this node runs {} with GnB-SMH proof of work, \
         whose blocks a stratum share cannot prove. Start the node with --chain obenblock (or --regtest on \
         ObenBlock), or mine GnB with --mine",
        crate::core::node_chain_id().params().network_name))
}

/// Configuration of the V1 server, from the CLI flags.
#[derive(Clone)]
pub struct StratumConfig {
    pub bind_addr: SocketAddr,
    pub max_sessions: usize,
    /// Concurrent sessions per source IP (`--stratum-max-sessions-per-ip`).
    pub max_sessions_per_ip: usize,
    /// Payout of workers that authorize with a plain label instead of an
    /// address (`--stratum-payout`, else `--miner-address`).
    pub payout: Option<Payout>,
    pub accept_block: Arc<AcceptBlockFn>,
}

impl std::fmt::Debug for StratumConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StratumConfig")
            .field("bind_addr", &self.bind_addr)
            .field("max_sessions", &self.max_sessions)
            .field("max_sessions_per_ip", &self.max_sessions_per_ip)
            .field("payout", &self.payout.as_ref().map(|p| p.address.as_str()))
            .finish()
    }
}

/// Validate `--stratum-max-sessions` / `--stratum-v2-max-sessions`.
pub fn check_max_sessions(n: usize) -> Result<usize, String> {
    if n == 0 || n > MAX_SESSIONS_CAP {
        return Err(format!("max sessions must be in 1..={MAX_SESSIONS_CAP}, got {n}"));
    }
    Ok(n)
}

/// The tail of a rate-limited log line that follows suppressed ones.
pub fn suppressed_note(n: u64) -> String {
    if n == 0 { String::new() } else { format!(" ({n} similar lines suppressed)") }
}

/// Bind the V1 listener (separate from [`serve`] so a caller learns the
/// bound address, e.g. port 0 in tests).
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let l = TcpListener::bind(addr).await?;
    info!("stratum: V1 listening on {}", l.local_addr()?);
    Ok(l)
}

/// Accept V1 connections on `listener` and serve each in its own task.
pub async fn serve(
    listener: TcpListener,
    config: StratumConfig,
    params: Sha256dParams,
    work: WorkReceiver,
) -> std::io::Result<()> {
    let tracker = Arc::new(guard::ConnTracker::new(config.max_sessions, config.max_sessions_per_ip));
    let config = Arc::new(config);
    let mut next_session_id: u64 = 1;
    let mut refusal_log = guard::LogLimiter::per_session();
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!("stratum: accept error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let id = next_session_id;
        next_session_id += 1;
        let session = Arc::new(Session::new(id, peer));
        let slot = match tracker.admit(id, peer.ip(), session.activity.clone()) {
            Ok(g) => g,
            Err(why) => {
                if let Some(n) = refusal_log.allow() {
                    warn!("stratum: rejecting {peer}: {why} ({} total, {} per IP){}", config.max_sessions,
                          config.max_sessions_per_ip, suppressed_note(n));
                }
                continue;
            }
        };
        crate::metrics::stratum_session_opened("v1");
        info!("stratum: session {id} accepted from {peer} (total: {})", tracker.len());
        let (config, work) = (config.clone(), work.clone());
        tokio::spawn(async move {
            match session::run(session, socket, config, params, work).await {
                Ok(()) => info!("stratum: session {id} closed"),
                Err(e) => warn!("stratum: session {id} ended with error: {e}"),
            }
            drop(slot);
            crate::metrics::stratum_session_closed("v1");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_sessions_bounds() {
        assert!(check_max_sessions(0).is_err());
        assert_eq!(check_max_sessions(1), Ok(1));
        assert_eq!(check_max_sessions(MAX_SESSIONS_CAP), Ok(MAX_SESSIONS_CAP));
        assert!(check_max_sessions(MAX_SESSIONS_CAP + 1).is_err());
    }

    /// The lib test binary runs GnB (GnB-SMH): stratum refuses to start.
    #[test]
    fn refuses_a_gnb_smh_chain() {
        let e = require_sha256d_chain().unwrap_err();
        assert!(e.contains("only for SHA-256d chains") && e.contains("GnB-SMH"), "{e}");
    }
}
