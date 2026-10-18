//! Built-in Stratum V2 server (Mining Protocol, standard channels), ported
//! from the legacy Bloch PoW node (genesis3-node `src/stratum_v2`, GIP-0003)
//! to ObenBlock's SHA-256d header.
//!
//! Enabled with `--stratum-v2` (default bind `0.0.0.0:3334`, next to V1 on
//! 3333); off by default. Operator guide: docs/STRATUM.md.
//!
//! * **Transport**: Noise NX (secp256k1 ElligatorSwift, ChaCha20-Poly1305),
//!   the responder of SRI's `noise_sv2`; the server proves its identity with
//!   a certificate signed by its authority key ([`keypair`], pinned by
//!   miners). Everything after the 64-byte act 1 is encrypted.
//! * **Messages**: SRI's `common_messages_sv2` / `mining_sv2` types
//!   ([`setup_connection`], [`messages`]), framed per the spec ([`framing`]).
//! * **Work**: the same work feed and the same jobs as V1
//!   (`stratum::work`, `stratum::jobs`: `getblocktemplate` header jobs), one
//!   job per channel with the channel's extranonce; `NewMiningJob.merkle_root`
//!   is ObenBlock's body root and `SetNewPrevHash.prev_hash` is
//!   `parents_commitment`, so a standard SV2 device mines ObenBlock
//!   unmodified (docs/OBENBLOCK-MINING.md §4).
//! * **Blocks**: a share that meets the job's block target goes through the
//!   same hook as RPC `submitblock`.
//!
//! The SRI crates are the constituents of the `stratum-core` 0.2.1 umbrella
//! the legacy node used, pinned to the versions of its lock (node/Cargo.toml).

pub mod block_reconstruct;
pub mod channel;
pub mod framing;
pub mod handshake;
pub mod keypair;
pub mod messages;
pub mod session;
pub mod setup_connection;
pub mod template_adapter;

pub use keypair::AuthorityKeypair;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use tokio::net::TcpListener;

use crate::core::pow_scheme::Sha256dParams;
use crate::stratum::work::WorkReceiver;
use crate::stratum::{AcceptBlockFn, Payout};

/// Default V2 port.
pub const DEFAULT_SV2_PORT: u16 = 3334;
/// Default V2 bind address.
pub const DEFAULT_SV2_ADDR: &str = "0.0.0.0:3334";
/// Default maximum of concurrent V2 sessions.
pub const DEFAULT_MAX_SESSIONS: usize = 500;
/// Default authority key file name (in the data directory).
pub const DEFAULT_KEY_FILE: &str = "stratum-v2-authority.json";

/// V2 errors.
#[derive(Debug, thiserror::Error)]
pub enum Sv2Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("keypair: {0}")]
    Keypair(String),
}

/// Configuration of the V2 server.
pub struct Sv2Config {
    pub bind_addr: SocketAddr,
    pub max_sessions: usize,
    /// Authority key file (`--stratum-v2-key`).
    pub key_path: PathBuf,
    /// Payout of workers that open a channel with a plain label.
    pub payout: Option<Payout>,
    pub accept_block: Arc<AcceptBlockFn>,
}

impl std::fmt::Debug for Sv2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sv2Config")
            .field("bind_addr", &self.bind_addr)
            .field("max_sessions", &self.max_sessions)
            .field("key_path", &self.key_path)
            .field("payout", &self.payout.as_ref().map(|p| p.address.as_str()))
            .finish()
    }
}

impl Sv2Config {
    pub fn new(bind_addr: SocketAddr, max_sessions: usize, key_path: PathBuf, payout: Option<Payout>,
               accept_block: Arc<AcceptBlockFn>) -> Result<Self, Sv2Error> {
        crate::stratum::check_max_sessions(max_sessions).map_err(Sv2Error::Config)?;
        Ok(Self { bind_addr, max_sessions, key_path, payout, accept_block })
    }
}

/// The pool URL a miner configures: `stratum2+tcp://<host>:<port>/<authority key>`.
pub fn pool_url(host: &str, port: u16, key: &AuthorityKeypair) -> String {
    format!("stratum2+tcp://{host}:{port}/{}", key.public_base58())
}

/// Bind the V2 listener.
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let l = TcpListener::bind(addr).await?;
    info!("stratum_v2: listening on {}", l.local_addr()?);
    Ok(l)
}

/// Accept V2 connections: cap, handshake, session.
pub async fn serve(
    listener: TcpListener,
    config: Sv2Config,
    authority: AuthorityKeypair,
    params: Sha256dParams,
    work: WorkReceiver,
) -> std::io::Result<()> {
    let config = Arc::new(config);
    let authority = Arc::new(authority);
    let live = Arc::new(AtomicUsize::new(0));
    let mut next_id: u64 = 1;
    info!("stratum_v2: authority key {} (fingerprint {}), max {} sessions",
          authority.public_base58(), authority.fingerprint_hex(), config.max_sessions);
    loop {
        let (mut socket, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!("stratum_v2: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if live.load(Ordering::Relaxed) >= config.max_sessions {
            warn!("stratum_v2: rejecting {peer}: session cap {} reached", config.max_sessions);
            continue;
        }
        live.fetch_add(1, Ordering::Relaxed);
        crate::metrics::stratum_session_opened("v2");
        let id = next_id;
        next_id += 1;
        let (config, authority, live, work) = (config.clone(), authority.clone(), live.clone(), work.clone());
        tokio::spawn(async move {
            match handshake::perform_handshake(&mut socket, &authority, handshake::DEFAULT_CERT_VALIDITY_SECS,
                                               handshake::DEFAULT_HANDSHAKE_TIMEOUT).await {
                Ok(codec) => {
                    info!("stratum_v2: session {id} from {peer}: handshake OK");
                    match session::run(id, peer, socket, codec, config, params, work).await {
                        Ok(state) => info!("stratum_v2: session {id} closed ({state:?})"),
                        Err(e) => warn!("stratum_v2: session {id} ended with error: {e}"),
                    }
                }
                Err(e) => warn!("stratum_v2: session {id} from {peer}: handshake failed: {e}"),
            }
            live.fetch_sub(1, Ordering::Relaxed);
            crate::metrics::stratum_session_closed("v2");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cb() -> Arc<AcceptBlockFn> {
        Arc::new(|_b| Err("test".to_string()))
    }

    #[test]
    fn config_bounds() {
        let a: SocketAddr = DEFAULT_SV2_ADDR.parse().unwrap();
        let c = Sv2Config::new(a, 500, "/tmp/k.json".into(), None, cb()).unwrap();
        assert_eq!((c.max_sessions, c.bind_addr.port()), (500, DEFAULT_SV2_PORT));
        assert!(matches!(Sv2Config::new(a, 0, "/tmp/k.json".into(), None, cb()), Err(Sv2Error::Config(_))));
        assert!(matches!(Sv2Config::new(a, 20_000, "/tmp/k.json".into(), None, cb()), Err(Sv2Error::Config(_))));
    }

    #[test]
    fn pool_url_carries_the_base58_authority_key() {
        let k = AuthorityKeypair::generate();
        let url = pool_url("pool.example", 3334, &k);
        assert_eq!(url, format!("stratum2+tcp://pool.example:3334/{}", k.public_base58()));
    }

    #[tokio::test]
    async fn listener_binds_an_ephemeral_port() {
        let l = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        assert_ne!(l.local_addr().unwrap().port(), 0);
    }
}
