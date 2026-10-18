//! Process wiring: configuration from the environment, the template source,
//! the metrics endpoint and the accept loop (per-IP and global connection
//! caps, a unique extranonce1 per connection, one task per connection).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;

use crate::extranonce::ExtranonceRegistry;
use crate::metrics;
use crate::pplns::PplnsLedger;
use crate::rpc::RpcClient;
use crate::session::{self, Shared};
use crate::template::TemplateSource;
use crate::types::{Metrics, Network, Payout, PoolError, StratumConfig, WorkerId};

pub struct StratumServer {
    cfg: Arc<StratumConfig>,
    metrics: Arc<Metrics>,
    ledger: Arc<PplnsLedger>,
    registry: Arc<ExtranonceRegistry>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

/// Releases a per-IP slot on every exit path of a connection task.
struct PerIpGuard {
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    addr: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut m = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.addr) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.addr);
            }
        }
    }
}

/// Keeps `workers_active` balanced on every exit path.
struct WorkerGuard(Arc<Metrics>);

impl WorkerGuard {
    fn new(m: Arc<Metrics>) -> Self {
        m.worker_connected();
        WorkerGuard(m)
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.worker_disconnected();
    }
}

impl StratumServer {
    pub fn new(cfg: StratumConfig) -> Self {
        let ledger = Arc::new(PplnsLedger::new(&cfg));
        Self {
            cfg: Arc::new(cfg),
            metrics: Arc::new(Metrics::new()),
            ledger,
            registry: Arc::new(ExtranonceRegistry::new()),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    /// Bind and serve until SIGINT/SIGTERM.
    pub async fn run(self) -> Result<(), PoolError> {
        let listener = TcpListener::bind(&self.cfg.listen_addr).await
            .map_err(|e| PoolError::Config(format!("cannot bind {}: {e}", self.cfg.listen_addr)))?;
        self.run_on(listener, shutdown_signal()).await
    }

    /// [`Self::run`] on a bound listener, until `shutdown` resolves (tests).
    pub async fn run_on(self, listener: TcpListener, shutdown: impl std::future::Future<Output = ()>)
        -> Result<(), PoolError>
    {
        let local = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
        log::info!("obenblock-stratum listening on {local}, node {}, paying {} ({:?})", self.cfg.rpc_addr,
                   self.cfg.payout.address, self.cfg.network);
        if self.cfg.pplns_window_shares > 0 {
            log::info!("PPLNS accounting on (window {} shares); accounting only, no payouts",
                       self.cfg.pplns_window_shares);
        }

        {
            let (m, l, addr) = (self.metrics.clone(), self.ledger.clone(), self.cfg.metrics_addr.clone());
            if !addr.is_empty() {
                tokio::spawn(async move {
                    if let Err(e) = metrics::serve_metrics(&addr, m, l).await {
                        log::error!("metrics endpoint failed: {e}");
                    }
                });
            }
        }

        let rpc = RpcClient::new(self.cfg.rpc_addr.clone(), self.cfg.rpc_api_key.clone());
        let (source, jobs) = TemplateSource::new(rpc.clone(), self.cfg.payout.script_pubkey.clone(),
                                                 self.cfg.poll_interval, self.cfg.refresh_interval, self.metrics.clone());
        let wake = source.wake.clone();
        let source_task = tokio::spawn(source.run());

        let shared = Shared { cfg: self.cfg.clone(), metrics: self.metrics.clone(), ledger: self.ledger.clone(), rpc,
                              jobs, wake };
        tokio::pin!(shutdown);
        let mut next_id: u64 = 1;
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    log::info!("shutdown signal received");
                    break;
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(p) => p,
                        Err(e) => {
                            log::warn!("accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let active = self.metrics.workers_active.load(Ordering::Relaxed);
                    if active >= 0 && active as usize >= self.cfg.max_workers {
                        log::warn!("at capacity ({} connections); refusing {peer}", self.cfg.max_workers);
                        continue;
                    }
                    let ip_guard = {
                        let mut m = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
                        let n = m.entry(peer.ip()).or_insert(0);
                        if *n >= self.cfg.max_connections_per_ip {
                            log::warn!("refusing {peer}: {} connections open from this IP", *n);
                            continue;
                        }
                        *n += 1;
                        PerIpGuard { per_ip: self.per_ip.clone(), addr: peer.ip() }
                    };
                    let Some(lease) = self.registry.lease() else {
                        log::error!("extranonce space exhausted; refusing {peer}");
                        continue;
                    };
                    let id = WorkerId(next_id);
                    next_id = next_id.wrapping_add(1);
                    log::info!("{id} connected from {peer} (extranonce1 {})", hex::encode(lease.bytes()));
                    let shared = shared.clone();
                    let metrics = self.metrics.clone();
                    tokio::spawn(async move {
                        let _g = WorkerGuard::new(metrics);
                        let _ip = ip_guard;
                        let en1 = lease.bytes();
                        let _lease = lease;
                        match session::serve(stream, id, en1, shared).await {
                            Ok(()) => log::info!("{id} closed"),
                            Err(e) => log::info!("{id} closed: {e}"),
                        }
                    });
                }
            }
        }
        source_task.abort();
        Ok(())
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Build the configuration from `OBB_STRATUM_*` environment variables
/// (README, "Configuration"). An unset variable keeps the default; a set but
/// unparseable one is an error, so a typo fails at startup.
pub fn config_from_env() -> Result<StratumConfig, PoolError> {
    config_from_getter(|k| std::env::var(k).ok())
}

pub fn config_from_getter<F: Fn(&str) -> Option<String>>(get: F) -> Result<StratumConfig, PoolError> {
    let mut cfg = StratumConfig::default();
    let set = |k: &str| get(k).filter(|v| !v.trim().is_empty());
    if let Some(v) = set("OBB_STRATUM_NETWORK") {
        cfg.network = match v.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "main" => Network::Mainnet,
            "regtest" => Network::Regtest,
            other => return Err(PoolError::Config(format!("OBB_STRATUM_NETWORK: mainnet or regtest, got {other:?}"))),
        };
        if cfg.network == Network::Regtest {
            cfg.rpc_addr = "127.0.0.1:18211".into();
        }
    }
    if let Some(v) = set("OBB_STRATUM_LISTEN") {
        cfg.listen_addr = v;
    }
    if let Some(v) = get("OBB_STRATUM_METRICS") {
        cfg.metrics_addr = v.trim().to_string(); // empty: no metrics endpoint
    }
    if let Some(v) = set("OBB_STRATUM_RPC") {
        cfg.rpc_addr = v.trim().trim_start_matches("http://").trim_end_matches('/').to_string();
    }
    if let Some(path) = set("OBB_STRATUM_RPC_API_KEY_FILE") {
        let s = std::fs::read_to_string(path.trim())
            .map_err(|e| PoolError::Config(format!("OBB_STRATUM_RPC_API_KEY_FILE: {e}")))?;
        cfg.rpc_api_key = s.lines().next().map(|l| l.trim().to_string()).filter(|k| !k.is_empty());
    }
    if let Some(v) = set("OBB_STRATUM_RPC_API_KEY") {
        cfg.rpc_api_key = Some(v.trim().to_string());
    }
    let address = set("OBB_STRATUM_PAYOUT_ADDRESS")
        .ok_or_else(|| PoolError::Config("OBB_STRATUM_PAYOUT_ADDRESS is required (the obb1 address every block pays)".into()))?;
    let script = crate::addr::script_for(address.trim(), cfg.network)
        .map_err(|e| PoolError::Config(format!("OBB_STRATUM_PAYOUT_ADDRESS: {e}")))?;
    cfg.payout = Payout { address: address.trim().to_string(), script_pubkey: script };
    if let Some(v) = set("OBB_STRATUM_ANY_USER") {
        cfg.any_user = parse_bool("OBB_STRATUM_ANY_USER", &v)?;
    }
    let secs = |k: &str, min: u64| -> Result<Option<Duration>, PoolError> {
        match set(k) {
            None => Ok(None),
            Some(v) => {
                let n = parse_field::<u64>(k, &v)?;
                if n < min {
                    return Err(PoolError::Config(format!("{k} must be >= {min}")));
                }
                Ok(Some(Duration::from_secs(n)))
            }
        }
    };
    if let Some(d) = secs("OBB_STRATUM_HANDSHAKE_SECS", 1)? {
        cfg.handshake_timeout = d;
    }
    if let Some(d) = secs("OBB_STRATUM_IDLE_SECS", 10)? {
        cfg.idle_timeout = d;
    }
    if let Some(d) = secs("OBB_STRATUM_REFRESH_SECS", 1)? {
        cfg.refresh_interval = d;
    }
    if let Some(v) = set("OBB_STRATUM_POLL_MS") {
        let ms = parse_field::<u64>("OBB_STRATUM_POLL_MS", &v)?;
        if ms < 50 {
            return Err(PoolError::Config("OBB_STRATUM_POLL_MS must be >= 50".into()));
        }
        cfg.poll_interval = Duration::from_millis(ms);
    }
    let f = |k: &str| -> Result<Option<f64>, PoolError> {
        match set(k) {
            None => Ok(None),
            Some(v) => {
                let x = parse_field::<f64>(k, &v)?;
                if !(x.is_finite() && x > 0.0) {
                    return Err(PoolError::Config(format!("{k} must be a positive number")));
                }
                Ok(Some(x))
            }
        }
    };
    if let Some(x) = f("OBB_STRATUM_DIFFICULTY")? {
        cfg.vardiff_initial = x;
    }
    if let Some(x) = f("OBB_STRATUM_DIFFICULTY_MIN")? {
        cfg.vardiff_min = x;
    }
    if let Some(x) = f("OBB_STRATUM_DIFFICULTY_MAX")? {
        cfg.vardiff_max = x;
    }
    if let Some(x) = f("OBB_STRATUM_SHARE_SECS")? {
        cfg.vardiff_target_secs = x;
    }
    if cfg.vardiff_min > cfg.vardiff_max {
        return Err(PoolError::Config("OBB_STRATUM_DIFFICULTY_MIN above OBB_STRATUM_DIFFICULTY_MAX".into()));
    }
    if let Some(v) = set("OBB_STRATUM_PPLNS_WINDOW") {
        cfg.pplns_window_shares = parse_field("OBB_STRATUM_PPLNS_WINDOW", &v)?;
    }
    if let Some(v) = set("OBB_STRATUM_PPLNS_WINDOW_SECS") {
        cfg.pplns_window_secs = parse_field("OBB_STRATUM_PPLNS_WINDOW_SECS", &v)?;
    }
    if let Some(v) = set("OBB_STRATUM_MAX_WORKERS") {
        cfg.max_workers = parse_field::<usize>("OBB_STRATUM_MAX_WORKERS", &v)?.max(1);
    }
    if let Some(v) = set("OBB_STRATUM_MAX_PER_IP") {
        cfg.max_connections_per_ip = parse_field::<usize>("OBB_STRATUM_MAX_PER_IP", &v)?.max(1);
    }
    Ok(cfg)
}

fn parse_field<T>(name: &str, raw: &str) -> Result<T, PoolError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    raw.trim().parse::<T>().map_err(|e| PoolError::Config(format!("{name}: invalid value {raw:?}: {e}")))
}

fn parse_bool(name: &str, raw: &str) -> Result<bool, PoolError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(PoolError::Config(format!("{name}: expected on/off, got {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = "obb1q0000000000000000000000000000000000000000335d2ee7";

    fn cfg_of(pairs: &[(&'static str, &'static str)]) -> Result<StratumConfig, PoolError> {
        let m: HashMap<&str, &str> = pairs.iter().copied().collect();
        config_from_getter(|k| m.get(k).map(|s| s.to_string()))
    }

    #[test]
    fn payout_address_is_required_and_checked() {
        assert!(matches!(cfg_of(&[]), Err(PoolError::Config(m)) if m.contains("PAYOUT_ADDRESS")));
        assert!(cfg_of(&[("OBB_STRATUM_PAYOUT_ADDRESS", "bc1qnotours")]).is_err());
        assert!(cfg_of(&[("OBB_STRATUM_PAYOUT_ADDRESS", MAIN), ("OBB_STRATUM_NETWORK", "regtest")]).is_err(),
                "a mainnet address on regtest");
        let c = cfg_of(&[("OBB_STRATUM_PAYOUT_ADDRESS", MAIN)]).unwrap();
        assert_eq!(c.payout.script_pubkey, vec![0u8; 20]);
        assert_eq!(c.rpc_addr, "127.0.0.1:18210");
        assert_eq!(c.listen_addr, "0.0.0.0:3333");
        assert_eq!(c.pplns_window_shares, 0, "PPLNS off by default");
        assert!(!c.any_user);
    }

    #[test]
    fn overrides_apply_and_typos_fail() {
        let c = cfg_of(&[
            ("OBB_STRATUM_PAYOUT_ADDRESS", MAIN),
            ("OBB_STRATUM_LISTEN", "0.0.0.0:4444"),
            ("OBB_STRATUM_RPC", "http://127.0.0.1:18210/"),
            ("OBB_STRATUM_RPC_API_KEY", "k"),
            ("OBB_STRATUM_DIFFICULTY", "131072"),
            ("OBB_STRATUM_DIFFICULTY_MIN", "0.5"),
            ("OBB_STRATUM_SHARE_SECS", "15"),
            ("OBB_STRATUM_POLL_MS", "250"),
            ("OBB_STRATUM_REFRESH_SECS", "20"),
            ("OBB_STRATUM_ANY_USER", "on"),
            ("OBB_STRATUM_PPLNS_WINDOW", "50000"),
            ("OBB_STRATUM_MAX_PER_IP", "8"),
            ("OBB_STRATUM_METRICS", ""),
        ]).unwrap();
        assert_eq!(c.listen_addr, "0.0.0.0:4444");
        assert_eq!(c.rpc_addr, "127.0.0.1:18210");
        assert_eq!(c.rpc_api_key.as_deref(), Some("k"));
        assert_eq!(c.vardiff_initial, 131_072.0);
        assert_eq!(c.vardiff_min, 0.5);
        assert_eq!(c.vardiff_target_secs, 15.0);
        assert_eq!(c.poll_interval, Duration::from_millis(250));
        assert_eq!(c.refresh_interval, Duration::from_secs(20));
        assert!(c.any_user);
        assert_eq!(c.pplns_window_shares, 50_000);
        assert_eq!(c.max_connections_per_ip, 8);
        assert_eq!(c.metrics_addr, "");
        for bad in [
            ("OBB_STRATUM_DIFFICULTY", "lots"),
            ("OBB_STRATUM_DIFFICULTY", "-1"),
            ("OBB_STRATUM_POLL_MS", "1"),
            ("OBB_STRATUM_ANY_USER", "maybe"),
            ("OBB_STRATUM_NETWORK", "testnet"),
            ("OBB_STRATUM_IDLE_SECS", "1"),
        ] {
            assert!(cfg_of(&[("OBB_STRATUM_PAYOUT_ADDRESS", MAIN), bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn regtest_defaults_to_the_regtest_rpc_port() {
        let c = cfg_of(&[
            ("OBB_STRATUM_NETWORK", "regtest"),
            ("OBB_STRATUM_PAYOUT_ADDRESS", "obb1t0000000000000000000000000000000000000000335d2ee7"),
        ]).unwrap();
        assert_eq!(c.rpc_addr, "127.0.0.1:18211");
        assert_eq!(c.network, Network::Regtest);
    }

    #[test]
    fn guards_balance() {
        let m = Arc::new(Metrics::new());
        {
            let _g = WorkerGuard::new(m.clone());
            assert_eq!(m.snapshot().workers_active, 1);
        }
        assert_eq!(m.snapshot().workers_active, 0);
        let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        per_ip.lock().unwrap().insert(ip, 2);
        drop(PerIpGuard { per_ip: per_ip.clone(), addr: ip });
        assert_eq!(per_ip.lock().unwrap()[&ip], 1);
        drop(PerIpGuard { per_ip: per_ip.clone(), addr: ip });
        assert!(per_ip.lock().unwrap().is_empty());
    }
}
