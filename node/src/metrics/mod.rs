//! Bloch-SIS Protocol — Sprint D: Prometheus metrics endpoint (Phase 2)
//!
//! Phase 1 exposed a minimal server + 5 base gauges. Phase 2 adds:
//!   - Counters: block_accepted_total, block_rejected_total,
//!     block_backfill_dropped_total,
//!               tx_accepted_total, tx_rejected_total{reason},
//!               kyber_handshake_failures_total,
//!               rpc_requests_total{method,status}
//!   - Histograms: block_validation_seconds, rpc_latency_seconds{method}
//!   - Free-function API (set_peer_count, inc_block_accepted, etc.)
//!     so modules can instrument without plumbing a state handle.
//!
//! The registry is stored in a process-wide OnceLock. If metrics are
//! disabled (--metrics not passed), the registry is never initialized
//! and the free functions become no-ops. This keeps instrumentation
//! calls cheap when metrics are off.
//!
//! ## Security
//! See Phase 1 header — no changes to the threat model.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use axum::{
    routing::get as axum_get,
    Router,
    http::StatusCode,
    response::IntoResponse,
    extract::State,
};
use log::{info, error, warn};
use prometheus::{
    Encoder, IntGauge, IntCounter, IntCounterVec, HistogramVec, Histogram,
    Registry, TextEncoder,
    register_int_gauge_with_registry,
    register_int_counter_with_registry,
    register_int_counter_vec_with_registry,
    register_histogram_with_registry,
    register_histogram_vec_with_registry,
    opts, histogram_opts,
};

/// Process-wide metrics handle. Initialized by main.rs if --metrics is on.
/// If None, all free functions below are no-ops.
static METRICS: OnceLock<Arc<MetricsState>> = OnceLock::new();

pub struct MetricsState {
    pub registry:                        Arc<Registry>,
    pub started_at:                      Instant,

    // ── Gauges (Phase 1) ─────────────────────────────────────────
    pub uptime_seconds:                  IntGauge,
    pub info:                            IntGauge,
    pub block_count:                     IntGauge,
    pub peer_count:                      IntGauge,
    pub mempool_size:                    IntGauge,

    // ── Counters (Phase 2) ──────────────────────────────────────
    pub block_accepted_total:            IntCounter,
    pub block_rejected_total:            IntCounter,
    pub block_backfill_dropped_total:    IntCounter,
    pub tx_accepted_total:               IntCounter,
    pub tx_rejected_total:               IntCounterVec,
    pub kyber_handshake_failures_total:  IntCounter,
    pub rpc_requests_total:              IntCounterVec,
    /// P0 (roadmap §2.5): incremented whenever a supervised long-lived task
    /// (e.g. the message-processor) panics and is restarted. A rising value
    /// means the node caught a would-be silent desync.
    pub task_panics_total:               IntCounterVec,

    // ── Reorg observability (Sprint FF) ─────────────────────────
    pub reorg_attempts_total:            IntCounter,
    pub reorg_failures_total:            IntCounter,
    pub fork_depth:                      IntGauge,
    /// S5: explicit success counter — success-rate becomes a direct series
    /// instead of being derived as attempts - failures.
    pub reorg_success_total:             IntCounter,
    /// S5: per-attempt depth distribution. `fork_depth` is last-value-only
    /// (racy under scrape); the histogram records every attempt.
    pub reorg_depth:                     Histogram,
    /// Audit DAG-6: committed chain moves deeper than
    /// `reorg::DEEP_REORG_ALERT_DEPTH`. Alert series only: there is no
    /// reorg-depth limit, so every such reorg was followed.
    pub deep_reorgs_total:               IntCounter,
    /// PoWit finality conflict alert (review HIGH 1): counted finalized
    /// checkpoints that conflict with the node's pin; 0 when none.
    pub finality_conflicts:              IntGauge,
    /// The configured weak-subjectivity anchor is unknown while the applied
    /// tip is above its height (review round 2, M3): 1, else 0.
    pub finality_anchor_unknown:         IntGauge,
    /// PoWit signer protection (DESIGN-obenblock-poci.md §8): witness
    /// signers of this process halted by the rollback guard or the
    /// one-signer check; 0 when none.
    pub powit_signer_halted:             IntGauge,

    // ── Histograms (Phase 2) ────────────────────────────────────
    pub block_validation_seconds:        Histogram,
    pub rpc_latency_seconds:             HistogramVec,
}

impl MetricsState {
    pub fn new(version: &str, network: &str) -> Self {
        let registry = Arc::new(Registry::new());

        let uptime_seconds = register_int_gauge_with_registry!(
            opts!("gnb_uptime_seconds", "Seconds since node startup"),
            registry
        ).expect("register uptime_seconds");

        let info = register_int_gauge_with_registry!(
            opts!("gnb_info", "Node metadata; value always 1")
                .const_label("version", version)
                .const_label("network", network),
            registry
        ).expect("register info");
        info.set(1);

        let block_count = register_int_gauge_with_registry!(
            opts!("gnb_block_count", "Current selected-chain block count (1-based, includes genesis; equals tip_height + 1)"),
            registry
        ).expect("register block_count");

        let peer_count = register_int_gauge_with_registry!(
            opts!("gnb_peer_count", "Connected P2P peers"),
            registry
        ).expect("register peer_count");

        let mempool_size = register_int_gauge_with_registry!(
            opts!("gnb_mempool_size", "Transactions currently in mempool"),
            registry
        ).expect("register mempool_size");

        // ── Counters ─────────────────────────────────────────────
        let block_accepted_total = register_int_counter_with_registry!(
            opts!("gnb_block_accepted_total",
                  "Blocks accepted into the DAG"),
            registry
        ).expect("register block_accepted_total");

        let block_rejected_total = register_int_counter_with_registry!(
            opts!("gnb_block_rejected_total",
                  "Blocks rejected during validation"),
            registry
        ).expect("register block_rejected_total");

        // Deliberately NOT block_rejected_total: dropping unsolicited deep
        // backfill is healthy defensive behaviour, not an invalid block. The
        // rejection counter is the signal used to spot consensus divergence
        // (an `invalid difficulty` storm is what exposed the order-dependent
        // difficulty bug), so it must stay clean.
        let block_backfill_dropped_total = register_int_counter_with_registry!(
            opts!("gnb_block_backfill_dropped_total",
                  "Unsolicited deep backfill blocks dropped by the flood guard"),
            registry
        ).expect("register block_backfill_dropped_total");

        let tx_accepted_total = register_int_counter_with_registry!(
            opts!("gnb_tx_accepted_total",
                  "Transactions accepted into the mempool"),
            registry
        ).expect("register tx_accepted_total");

        let tx_rejected_total = register_int_counter_vec_with_registry!(
            opts!("gnb_tx_rejected_total",
                  "Transactions rejected from the mempool, by reason"),
            &["reason"],
            registry
        ).expect("register tx_rejected_total");

        let kyber_handshake_failures_total = register_int_counter_with_registry!(
            opts!("gnb_kyber_handshake_failures_total",
                  "ML-KEM-768 hybrid handshake failures"),
            registry
        ).expect("register kyber_handshake_failures_total");

        let rpc_requests_total = register_int_counter_vec_with_registry!(
            opts!("gnb_rpc_requests_total",
                  "RPC requests served, by method and outcome"),
            &["method", "status"],
            registry
        ).expect("register rpc_requests_total");

        let task_panics_total = register_int_counter_vec_with_registry!(
            opts!("gnb_task_panics_total",
                  "Panics caught by a supervised long-lived task (by task name); each was restarted rather than silently killing the node"),
            &["task"],
            registry
        ).expect("register task_panics_total");

        // ── Reorg observability (Sprint FF) ──────────────────────
        let reorg_attempts_total = register_int_counter_with_registry!(
            opts!("gnb_reorg_attempts_total",
                  "Chain reorganizations attempted (execute_reorg invocations)"),
            registry
        ).expect("register reorg_attempts_total");

        let reorg_failures_total = register_int_counter_with_registry!(
            opts!("gnb_reorg_failures_total",
                  "Chain reorganizations that failed mid-execution (storage may be in partial state)"),
            registry
        ).expect("register reorg_failures_total");

        let fork_depth = register_int_gauge_with_registry!(
            opts!("gnb_fork_depth",
                  "Depth (blocks rolled back) of the most recent reorg attempt"),
            registry
        ).expect("register fork_depth");

        let reorg_success_total = register_int_counter_with_registry!(
            opts!("gnb_reorg_success_total",
                  "Chain reorganizations completed successfully (atomic chain-switch batch committed)"),
            registry
        ).expect("register reorg_success_total");

        // Depth buckets up to the deep-reorg alert depth
        // (`reorg::DEEP_REORG_ALERT_DEPTH` = core::CHECKPOINT_DEPTH = 1_000);
        // +Inf counts deeper reorgs, which are executed (no depth limit, audit
        // DAG-6) and also counted by `gnb_deep_reorgs_total`.
        let reorg_depth = register_histogram_with_registry!(
            histogram_opts!(
                "gnb_reorg_depth",
                "Blocks rolled back per reorg attempt (observed before execution; includes failed attempts)",
                vec![1.0, 2.0, 3.0, 5.0, 8.0, 13.0, 21.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
            ),
            registry
        ).expect("register reorg_depth");

        let deep_reorgs_total = register_int_counter_with_registry!(
            opts!("gnb_deep_reorgs_total",
                  "Committed chain moves that rolled back more than the deep-reorg alert depth (1,000 blocks); followed, never refused"),
            registry
        ).expect("register deep_reorgs_total");

        let finality_conflicts = register_int_gauge_with_registry!(
            opts!("gnb_finality_conflicts",
                  "Finalized PoWit checkpoints that conflict with this node's finality pin (alert while > 0; \
                   the node keeps its finality, an operator decides: getfinalityinfo)"),
            registry
        ).expect("register finality_conflicts");

        let finality_anchor_unknown = register_int_gauge_with_registry!(
            opts!("gnb_finality_anchor_unknown",
                  "1 while the PoWit finality anchor (release, --finalitycheckpoint or setfinalitycheckpoint) is \
                   unknown and this node's chain is above its height (the pin is held: getfinalityinfo)"),
            registry
        ).expect("register finality_anchor_unknown");

        let powit_signer_halted = register_int_gauge_with_registry!(
            opts!("gnb_powit_signer_halted",
                  "PoWit witness signers of this node halted by signer protection (a vote of the key the record \
                   does not hold, or a second instance): alert while > 0; getpowitinfo.signers has the reason"),
            registry
        ).expect("register powit_signer_halted");

        // ── Histograms ───────────────────────────────────────────
        // Block validation buckets tuned for expected range: 1ms..10s
        let block_validation_seconds = register_histogram_with_registry!(
            histogram_opts!(
                "gnb_block_validation_seconds",
                "Time spent validating a block before accept/reject",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
            ),
            registry
        ).expect("register block_validation_seconds");

        // RPC latency buckets tuned for expected range: 100us..5s
        let rpc_latency_seconds = register_histogram_vec_with_registry!(
            histogram_opts!(
                "gnb_rpc_latency_seconds",
                "RPC request duration"
            ).buckets(vec![0.0001, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["method"],
            registry
        ).expect("register rpc_latency_seconds");

        Self {
            registry,
            started_at: Instant::now(),
            uptime_seconds,
            info,
            block_count,
            peer_count,
            mempool_size,
            block_accepted_total,
            block_rejected_total,
            block_backfill_dropped_total,
            tx_accepted_total,
            tx_rejected_total,
            kyber_handshake_failures_total,
            rpc_requests_total,
            task_panics_total,
            reorg_attempts_total,
            reorg_failures_total,
            fork_depth,
            reorg_success_total,
            reorg_depth,
            deep_reorgs_total,
            finality_conflicts,
            finality_anchor_unknown,
            powit_signer_halted,
            block_validation_seconds,
            rpc_latency_seconds,
        }
    }
}

/// Install the process-wide metrics handle. Main.rs calls this once
/// if --metrics is enabled.
pub fn install(state: Arc<MetricsState>) {
    let _ = METRICS.set(state);
}

/// Returns the installed metrics handle, or None if metrics are disabled.
pub fn get() -> Option<&'static Arc<MetricsState>> {
    METRICS.get()
}

// ── Free-function API for instrumentation ─────────────────────────
//
// All of these are no-ops if metrics are disabled (METRICS not set).
// This lets callers instrument code without branching on a config flag.

#[inline]
pub fn set_block_count(v: i64) {
    if let Some(m) = METRICS.get() { m.block_count.set(v); }
}

#[inline]
pub fn set_peer_count(v: i64) {
    if let Some(m) = METRICS.get() { m.peer_count.set(v); }
}

#[inline]
pub fn set_mempool_size(v: i64) {
    if let Some(m) = METRICS.get() { m.mempool_size.set(v); }
}

#[inline]
pub fn inc_block_accepted() {
    if let Some(m) = METRICS.get() { m.block_accepted_total.inc(); }
}

#[inline]
pub fn inc_block_rejected() {
    if let Some(m) = METRICS.get() { m.block_rejected_total.inc(); }
}

#[inline]
pub fn inc_block_backfill_dropped() {
    if let Some(m) = METRICS.get() { m.block_backfill_dropped_total.inc(); }
}

#[inline]
pub fn inc_tx_accepted() {
    if let Some(m) = METRICS.get() { m.tx_accepted_total.inc(); }
}

/// Reason label should be a short stable string: "duplicate", "conflict",
/// "oversized", "full", "invalid", "overflow".
#[inline]
pub fn inc_tx_rejected(reason: &str) {
    if let Some(m) = METRICS.get() {
        m.tx_rejected_total.with_label_values(&[reason]).inc();
    }
}

#[inline]
pub fn inc_kyber_handshake_failure() {
    if let Some(m) = METRICS.get() { m.kyber_handshake_failures_total.inc(); }
}

/// P0 (roadmap §2.5): record a caught-and-restarted panic in a supervised
/// task. `task` is a short stable label, e.g. "message_processor".
#[inline]
pub fn inc_task_panic(task: &str) {
    if let Some(m) = METRICS.get() {
        m.task_panics_total.with_label_values(&[task]).inc();
    }
}

/// NET-13 (defence in depth): the RPC layer already maps caller-supplied
/// method names to a fixed set (`rpc::method_label`); any label that is not
/// a short lowercase identifier still becomes `"unknown"` here, so a new
/// call site can never mint unbounded Prometheus series.
fn bounded_label(label: &str) -> &str {
    let ok = !label.is_empty()
        && label.len() <= 40
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok { label } else { "unknown" }
}

/// Status label is "ok", "unauthorized", or "rate_limited".
#[inline]
pub fn inc_rpc_request(method: &str, status: &str) {
    if let Some(m) = METRICS.get() {
        m.rpc_requests_total.with_label_values(&[bounded_label(method), bounded_label(status)]).inc();
    }
}

/// Record the start of a reorg execution. Pair with `inc_reorg_failure`
/// on the error path so `failures/attempts` gives the reorg failure rate.
#[inline]
pub fn inc_reorg_attempt() {
    if let Some(m) = METRICS.get() { m.reorg_attempts_total.inc(); }
}

#[inline]
pub fn inc_reorg_failure() {
    if let Some(m) = METRICS.get() { m.reorg_failures_total.inc(); }
}

/// Depth of the most recent reorg (number of blocks rolled back). Set at
/// the start of each `execute_reorg` so a spiking gauge flags deep forks.
#[inline]
pub fn set_fork_depth(depth: i64) {
    if let Some(m) = METRICS.get() { m.fork_depth.set(depth); }
}

/// S5: record a successfully committed reorg (the Ok path of `execute_reorg`).
#[inline]
pub fn inc_reorg_success() {
    if let Some(m) = METRICS.get() { m.reorg_success_total.inc(); }
}

/// S5: observe the depth (blocks rolled back) of a reorg attempt. Called at
/// the start of `execute_reorg` alongside `set_fork_depth`, so the histogram
/// counts every attempt, including ones that later fail.
#[inline]
pub fn observe_reorg_depth(depth: f64) {
    if let Some(m) = METRICS.get() { m.reorg_depth.observe(depth); }
}

/// Audit DAG-6: a committed reorg rolled back more than
/// `reorg::DEEP_REORG_ALERT_DEPTH` blocks (alert only; it was followed).
#[inline]
pub fn inc_deep_reorg() {
    if let Some(m) = METRICS.get() { m.deep_reorgs_total.inc(); }
}

/// Review HIGH 1: the number of counted finalized checkpoints that conflict
/// with the finality pin (`powit::refresh_finality_pin`).
#[inline]
pub fn set_finality_conflicts(n: i64) {
    if let Some(m) = METRICS.get() { m.finality_conflicts.set(n); }
}

/// Review round 2, M3: the anchor is unknown above its height.
#[inline]
pub fn set_finality_anchor_unknown(overdue: bool) {
    if let Some(m) = METRICS.get() { m.finality_anchor_unknown.set(i64::from(overdue)); }
}

/// PoWit signer protection: halted witness signers (`powit_signer`).
#[inline]
pub fn set_powit_signer_halted(n: i64) {
    if let Some(m) = METRICS.get() { m.powit_signer_halted.set(n); }
}

#[inline]
pub fn observe_block_validation(seconds: f64) {
    if let Some(m) = METRICS.get() { m.block_validation_seconds.observe(seconds); }
}

#[inline]
pub fn observe_rpc_latency(method: &str, seconds: f64) {
    if let Some(m) = METRICS.get() {
        m.rpc_latency_seconds.with_label_values(&[bounded_label(method)]).observe(seconds);
    }
}

// ── HTTP server ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MetricsConfig {
    pub enabled:       bool,
    pub bind_address:  String,
    pub port:          u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled:       false,
            bind_address:  "127.0.0.1".into(),
            port:          17310,
        }
    }
}

pub async fn start_metrics_server(
    config:  MetricsConfig,
    state:   Arc<MetricsState>,
) {
    if !config.enabled {
        info!("metrics: disabled (pass --metrics to enable)");
        // Do NOT return: this future lives inside the node's top-level
        // tokio::select!, so returning here would complete that arm and shut
        // the whole node down. Park forever instead (B7 fix).
        std::future::pending::<()>().await;
        return;
    }

    // NET-14: `format!("{host}:{port}").parse()` rejected IPv6 hosts such as
    // `::1`. Resolve explicitly; on failure only the metrics task stops (it
    // runs as its own task, so the node keeps running).
    let addr: SocketAddr = match crate::rpc::resolve_bind_address(&config.bind_address, config.port) {
        Ok(a)  => a,
        Err(e) => {
            error!("metrics: {}; metrics are disabled (the node keeps running)", e);
            return;
        }
    };

    if config.bind_address == "0.0.0.0" {
        warn!("metrics: bound to 0.0.0.0 — endpoint is publicly reachable.");
        warn!("metrics: this reveals version, peer count, hashrate, and timing data.");
    }

    let app = Router::new()
        .route("/debug/metrics/prometheus", axum_get(handle_metrics))
        .route("/metrics", axum_get(handle_metrics))
        .with_state(state);

    info!("metrics: serving on http://{}/debug/metrics/prometheus", addr);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("metrics: bind {} failed: {}; metrics are disabled (the node keeps running)", addr, e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("metrics: server error: {}", e);
    }
}

async fn handle_metrics(
    State(state): State<Arc<MetricsState>>,
) -> impl IntoResponse {
    let uptime = state.started_at.elapsed().as_secs() as i64;
    state.uptime_seconds.set(uptime);

    let encoder = TextEncoder::new();
    let metric_families = state.registry.gather();
    let mut buf = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        error!("metrics: encode failed: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Content-Type", "text/plain")],
            format!("encode error: {}\n", e),
        );
    }

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
        String::from_utf8_lossy(&buf).into_owned(),
    )
}

// ── Tests ─────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_state_registers_all_metrics() {
        let s = MetricsState::new("0.5.12", "mainnet");
        let families = s.registry.gather();
        let names: Vec<&str> = families.iter().map(|f| f.name()).collect();

        // Phase 1
        assert!(names.contains(&"gnb_uptime_seconds"));
        assert!(names.contains(&"gnb_info"));
        assert!(names.contains(&"gnb_block_count"));
        assert!(names.contains(&"gnb_peer_count"));
        assert!(names.contains(&"gnb_mempool_size"));

        // Phase 2 counters
        assert!(names.contains(&"gnb_block_accepted_total"));
        assert!(names.contains(&"gnb_block_rejected_total"));
        assert!(names.contains(&"gnb_tx_accepted_total"));
        // Note: IntCounterVec with zero observations doesn't appear in gather()
        // until at least one label combination is incremented.
        assert!(names.contains(&"gnb_kyber_handshake_failures_total"));

        // Reorg observability (Sprint FF)
        assert!(names.contains(&"gnb_reorg_attempts_total"));
        assert!(names.contains(&"gnb_reorg_failures_total"));
        assert!(names.contains(&"gnb_fork_depth"));
        assert!(names.contains(&"gnb_reorg_success_total"));
        // bloch_reorg_depth is a Histogram — presence after observation is
        // asserted in reorg_metrics_track_attempts_failures_and_depth.

        // Phase 2 histograms (same rule — only shown after first observation)
        // We skip assert on those; gauges verify registry is alive.
    }

    #[test]
    fn info_gauge_has_version_and_network_labels() {
        let s = MetricsState::new("0.5.12", "testnet");
        let families = s.registry.gather();
        let info = families.iter().find(|f| f.name() == "gnb_info").unwrap();
        let metric = &info.get_metric()[0];
        let labels: Vec<(&str, &str)> = metric.get_label()
            .iter()
            .map(|l| (l.name(), l.value()))
            .collect();
        assert!(labels.contains(&("version", "0.5.12")));
        assert!(labels.contains(&("network", "testnet")));
    }

    #[test]
    fn default_config_is_disabled_and_localhost() {
        let c = MetricsConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.bind_address, "127.0.0.1");
        assert_eq!(c.port, 17310);
    }

    #[test]
    fn gauges_are_updatable() {
        let s = MetricsState::new("0.5.12", "mainnet");
        s.block_count.set(42);
        s.peer_count.set(7);
        s.mempool_size.set(3);

        let families = s.registry.gather();
        let find = |n: &str| {
            families.iter().find(|f| f.name() == n).unwrap()
                .get_metric()[0].get_gauge().value() as i64
        };
        assert_eq!(find("gnb_block_count"), 42);
        assert_eq!(find("gnb_peer_count"), 7);
        assert_eq!(find("gnb_mempool_size"), 3);
    }

    #[test]
    fn counters_can_be_incremented() {
        let s = MetricsState::new("0.5.12", "mainnet");
        s.block_accepted_total.inc();
        s.block_accepted_total.inc();
        s.block_rejected_total.inc();
        s.tx_accepted_total.inc();
        s.tx_rejected_total.with_label_values(&["duplicate"]).inc();
        s.tx_rejected_total.with_label_values(&["oversized"]).inc();
        s.tx_rejected_total.with_label_values(&["duplicate"]).inc();
        s.kyber_handshake_failures_total.inc();
        s.rpc_requests_total.with_label_values(&["getblockcount", "ok"]).inc();

        assert_eq!(s.block_accepted_total.get(), 2);
        assert_eq!(s.block_rejected_total.get(), 1);
        assert_eq!(s.tx_accepted_total.get(), 1);
        assert_eq!(s.tx_rejected_total.with_label_values(&["duplicate"]).get(), 2);
        assert_eq!(s.tx_rejected_total.with_label_values(&["oversized"]).get(), 1);
        assert_eq!(s.kyber_handshake_failures_total.get(), 1);
        assert_eq!(
            s.rpc_requests_total.with_label_values(&["getblockcount", "ok"]).get(),
            1
        );
    }

    #[test]
    fn reorg_metrics_track_attempts_failures_and_depth() {
        let s = MetricsState::new("0.5.12", "mainnet");
        s.reorg_attempts_total.inc();
        s.reorg_attempts_total.inc();
        s.reorg_failures_total.inc();
        s.fork_depth.set(7);
        s.reorg_success_total.inc();
        s.reorg_depth.observe(7.0);
        s.reorg_depth.observe(2.0);

        assert_eq!(s.reorg_attempts_total.get(), 2);
        assert_eq!(s.reorg_failures_total.get(), 1);
        assert_eq!(s.reorg_success_total.get(), 1);

        let families = s.registry.gather();
        let depth = families.iter()
            .find(|f| f.name() == "gnb_fork_depth").unwrap()
            .get_metric()[0].get_gauge().value() as i64;
        assert_eq!(depth, 7);

        // Histogram: registered under the bloch_ prefix, both observations
        // recorded, sum matches (7 + 2).
        let hist = families.iter()
            .find(|f| f.name() == "gnb_reorg_depth").unwrap()
            .get_metric()[0].get_histogram();
        assert_eq!(hist.get_sample_count(), 2);
        assert!((hist.get_sample_sum() - 9.0).abs() < 1e-9);
    }

    #[test]
    fn histograms_can_observe() {
        let s = MetricsState::new("0.5.12", "mainnet");
        s.block_validation_seconds.observe(0.003);
        s.block_validation_seconds.observe(0.042);
        s.rpc_latency_seconds.with_label_values(&["getblockcount"]).observe(0.0002);

        let families = s.registry.gather();
        let find_count = |name: &str| -> u64 {
            families.iter().find(|f| f.name() == name)
                .map(|f| f.get_metric()[0].get_histogram().get_sample_count())
                .unwrap_or(0)
        };
        assert_eq!(find_count("gnb_block_validation_seconds"), 2);
        assert_eq!(find_count("gnb_rpc_latency_seconds"), 1);
    }

    #[test]
    fn free_functions_are_noop_when_not_installed() {
        // These should not panic or block when METRICS is not set.
        // Note: OnceLock state is process-wide; this test assumes
        // no prior test has called install().
        set_block_count(999);
        inc_block_accepted();
        inc_reorg_success();
        observe_reorg_depth(3.0);
        observe_rpc_latency("foo", 0.1);
        // If we got here without panic, test passes.
    }
}

#[cfg(test)]
mod net13_net14_tests {
    use super::*;

    /// NET-13: a caller-controlled label can never become a new series.
    #[test]
    fn labels_are_bounded() {
        assert_eq!(bounded_label("getblockcount"), "getblockcount");
        assert_eq!(bounded_label("rate_limited"), "rate_limited");
        assert_eq!(bounded_label(&"x".repeat(41)), "unknown");
        assert_eq!(bounded_label("Get<script>"), "unknown");
        assert_eq!(bounded_label(""), "unknown");
    }

    /// NET-14: a server that cannot bind returns (its task ends) instead
    /// of panicking; IPv6 literals such as `::1` are now valid addresses.
    #[tokio::test]
    async fn metrics_server_with_unusable_address_returns() {
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = busy.local_addr().unwrap().port();
        let config = MetricsConfig { enabled: true, bind_address: "127.0.0.1".into(), port };
        let state = Arc::new(MetricsState::new("test", "testnet"));
        tokio::time::timeout(std::time::Duration::from_secs(5), start_metrics_server(config, state.clone()))
            .await
            .expect("bind failure must end the metrics task, not hang or panic");
        let config = MetricsConfig { enabled: true, bind_address: "not an address".into(), port: 1 };
        tokio::time::timeout(std::time::Duration::from_secs(5), start_metrics_server(config, state))
            .await
            .expect("invalid address must end the metrics task");
        assert!(crate::rpc::resolve_bind_address("::1", 17310).unwrap().is_ipv6());
        assert!(crate::rpc::resolve_bind_address("[::1]", 17310).unwrap().is_ipv6());
    }
}
