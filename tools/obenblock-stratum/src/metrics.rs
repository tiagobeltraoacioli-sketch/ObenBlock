//! Prometheus text rendering and a tiny hand-rolled HTTP/1.1 endpoint
//! (ported from the Bloch pool proxy; series renamed `obb_stratum_*`).
//!
//! * Any path returns the Prometheus text of the shared `Arc<Metrics>`.
//! * A path starting with `/pplns` returns `serde_json(ledger.credit())`
//!   (empty while PPLNS accounting is off, the default).
//!
//! The request head is read into a bounded buffer under a timeout, so a
//! stalled or hostile scraper can neither pin a task nor grow memory.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::pplns::{PplnsLedger, PplnsSnapshot};
use crate::types::{Metrics, MetricsSnapshot, PoolError};

/// Largest request head read before responding.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// How long a peer may take to send its request head.
const READ_HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Content type Prometheus expects.
const PROM_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Render a metrics snapshot plus the PPLNS window shape as Prometheus text.
/// Deterministic field order.
pub fn render_prometheus(snap: &MetricsSnapshot, pplns: &PplnsSnapshot) -> String {
    let mut out = String::with_capacity(4096);
    gauge(&mut out, "obb_stratum_workers_active", "Miner connections currently open.", snap.workers_active);
    counter(&mut out, "obb_stratum_workers_total", "Miner connections accepted since start.", snap.workers_total);
    gauge(&mut out, "obb_stratum_workers_authorized", "Open connections that completed mining.authorize.",
          snap.workers_authorized);
    counter(&mut out, "obb_stratum_shares_accepted_total", "Shares that met their connection's share target.",
            snap.shares_accepted);
    counter(&mut out, "obb_stratum_shares_rejected_total", "Shares rejected for any reason.", snap.shares_rejected);
    counter(&mut out, "obb_stratum_shares_stale_total", "Shares for an unknown or replaced job, or out of its time window (error 21).",
            snap.shares_stale);
    counter(&mut out, "obb_stratum_shares_duplicate_total", "Shares submitted twice (error 22).", snap.shares_duplicate);
    counter(&mut out, "obb_stratum_shares_low_difficulty_total", "Shares below their share target (error 23).",
            snap.shares_low_difficulty);
    counter(&mut out, "obb_stratum_share_work_total",
            "Sum of the difficulties of accepted shares (rate x 2^32 = hashes per second).", snap.share_work_total);
    counter(&mut out, "obb_stratum_blocks_found_total", "Shares that met the block target and were submitted.",
            snap.blocks_found);
    counter(&mut out, "obb_stratum_blocks_accepted_total", "Submitted blocks the node accepted.", snap.blocks_accepted);
    counter(&mut out, "obb_stratum_blocks_rejected_total", "Submitted blocks the node refused (see the log).",
            snap.blocks_rejected);
    counter(&mut out, "obb_stratum_rpc_failures_total", "Failed node RPC calls (getdaginfo, getblocktemplate, submitblock).",
            snap.rpc_failures);
    counter(&mut out, "obb_stratum_templates_total", "Jobs built from node templates.", snap.templates_total);
    gauge(&mut out, "obb_stratum_template_height", "Height of the current job.", snap.template_height);
    gauge(&mut out, "obb_stratum_template_bits", "Compact bits of the current job (decimal).", snap.template_bits);
    gauge(&mut out, "obb_stratum_template_parent_count", "Parents of the current job.", snap.template_parent_count);
    gauge(&mut out, "obb_stratum_pplns_window_shares", "Accepted shares in the PPLNS window (0 while accounting is off).",
          pplns.window_len as i64);
    gauge_f64(&mut out, "obb_stratum_pplns_window_weight", "Total difficulty weight of the PPLNS window.",
              pplns.total_weight);
    gauge(&mut out, "obb_stratum_pplns_distinct_workers", "Accounts with at least one share in the PPLNS window.",
          pplns.distinct_workers as i64);
    counter(&mut out, "obb_stratum_bytes_in_total", "Bytes received from miners.", snap.bytes_in);
    counter(&mut out, "obb_stratum_bytes_out_total", "Bytes sent to miners.", snap.bytes_out);
    out
}

fn gauge(out: &mut String, name: &str, help: &str, value: i64) {
    header(out, name, help, "gauge");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn gauge_f64(out: &mut String, name: &str, help: &str, value: f64) {
    header(out, name, help, "gauge");
    out.push_str(name);
    out.push(' ');
    // Rust's Display for f64 never uses scientific notation and always emits a
    // finite decimal for finite inputs; a non-finite weight (should never
    // occur — weights are clamped to unit on non-positive difficulty upstream)
    // renders as `NaN`/`inf`, which Prometheus tolerates. Never panics.
    out.push_str(&value.to_string());
    out.push('\n');
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    header(out, name, help, "counter");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Emit the shared `# HELP` / `# TYPE` preamble for one series.
fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

/// Bind `addr` and serve the metrics endpoint forever. Returns only on a
/// fatal bind error; per-connection errors are logged and swallowed so one
/// bad scraper never takes the endpoint down.
pub async fn serve_metrics(
    addr: &str,
    metrics: Arc<Metrics>,
    ledger: Arc<PplnsLedger>,
) -> Result<(), PoolError> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        PoolError::Config(format!("cannot bind metrics endpoint {}: {}", addr, e))
    })?;
    log::info!("metrics endpoint listening on {}", addr);
    serve_metrics_on(listener, metrics, ledger).await
}

/// Accept-loop half of [`serve_metrics`], split out so tests can drive it on
/// an OS-assigned ephemeral port.
pub(crate) async fn serve_metrics_on(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    ledger: Arc<PplnsLedger>,
) -> Result<(), PoolError> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Transient accept errors (fd exhaustion, reset) must not kill
                // the endpoint; log and keep going.
                log::warn!("metrics accept error: {}", e);
                continue;
            }
        };
        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, &m, &l).await {
                log::debug!("metrics conn {} ended: {}", peer, e);
            }
        });
    }
}

/// Read the request head (bounded in both bytes AND time), then write the
/// appropriate response: PPLNS JSON for a `/pplns*` target, Prometheus text
/// for anything else. Thin wrapper around [`handle_conn_inner`] pinning the
/// production [`READ_HEAD_TIMEOUT`].
async fn handle_conn(
    stream: TcpStream,
    metrics: &Metrics,
    ledger: &PplnsLedger,
) -> std::io::Result<()> {
    handle_conn_inner(stream, metrics, ledger, READ_HEAD_TIMEOUT).await
}

/// [`handle_conn`] with an explicit head-read deadline, so tests can exercise
/// the timeout path deterministically with a short real-time bound instead of
/// a flaky paused clock over live sockets.
async fn handle_conn_inner(
    mut stream: TcpStream,
    metrics: &Metrics,
    ledger: &PplnsLedger,
    head_timeout: Duration,
) -> std::io::Result<()> {
    // Drain the request head up to the blank line (or the byte cap), bounded
    // by `head_timeout` so a stalled peer cannot pin this task. We keep the
    // accumulated head so we can route on the request target.
    let mut head: Vec<u8> = Vec::with_capacity(1024);
    match timeout(head_timeout, read_request_head(&mut stream, &mut head)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            // Timed out waiting for the head: answer 408 and drop the peer.
            let resp = http_response("408 Request Timeout", "text/plain", "request timeout\n");
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    }

    let response = if wants_pplns(&head) {
        // G1 query surface: the exact credit vector a payout job consumes.
        // Serialization of a `Vec<PplnsCredit>` cannot fail, but degrade to an
        // empty array rather than ever unwrapping on untrusted-adjacent state.
        let body = serde_json::to_string(&ledger.credit()).unwrap_or_else(|_| "[]".to_string());
        http_response("200 OK", "application/json", &body)
    } else {
        let body = render_prometheus(&metrics.snapshot(), &ledger.snapshot());
        http_response("200 OK", PROM_CONTENT_TYPE, &body)
    };

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    // Best-effort clean close; ignore errors from an already-gone peer.
    let _ = stream.shutdown().await;
    Ok(())
}

/// Read bytes into `head` until the end-of-head marker is seen anywhere in the
/// ACCUMULATED buffer, the byte cap is reached, or the peer closes. Never
/// interprets the bytes here — routing happens after — but bounds memory.
async fn read_request_head(stream: &mut TcpStream, head: &mut Vec<u8>) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break; // client closed before finishing; caller replies anyway.
        }
        head.extend_from_slice(&buf[..n]);
        // Scan the accumulated buffer (fix vs. only-latest-chunk) so the
        // `\r\n\r\n` marker is found even when split across reads. Cap the
        // scanned/kept head so a flood cannot grow memory.
        if head.len() >= MAX_REQUEST_BYTES {
            head.truncate(MAX_REQUEST_BYTES);
            break;
        }
        if contains_head_end(head) {
            break;
        }
    }
    Ok(())
}

/// Cheap check for the end-of-headers marker anywhere within `head`.
fn contains_head_end(head: &[u8]) -> bool {
    head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n")
}

/// Does the request target begin with `/pplns`? Parses only the request line
/// (`METHOD SP TARGET SP VERSION`); any malformed / missing head routes to the
/// Prometheus default. Never panics on hostile bytes.
fn wants_pplns(head: &[u8]) -> bool {
    request_target(head)
        .map(|t| t.starts_with("/pplns"))
        .unwrap_or(false)
}

/// Extract the request target (second whitespace token of the first line).
fn request_target(head: &[u8]) -> Option<String> {
    let end = head.iter().position(|&b| b == b'\n')?;
    let mut line = &head[..end];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let s = std::str::from_utf8(line).ok()?;
    let mut it = s.split(' ');
    let _method = it.next()?;
    let target = it.next()?;
    if target.is_empty() {
        return None;
    }
    Some(target.to_string())
}

/// Build a complete HTTP/1.1 response carrying `body` with the given status
/// line (e.g. `"200 OK"`) and content type.
fn http_response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {ct}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        status = status,
        ct = content_type,
        len = body.len(),
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ShareOutcome, StratumConfig};
    use std::sync::atomic::Ordering;

    fn snap_with(f: impl FnOnce(&Metrics)) -> MetricsSnapshot {
        let m = Metrics::new();
        f(&m);
        m.snapshot()
    }

    /// A zeroed PPLNS-window snapshot for render tests that only assert on the
    /// metric SHAPE (HELP/TYPE lines are emitted regardless of value).
    fn empty_pplns() -> PplnsSnapshot {
        PplnsSnapshot::default()
    }

    fn test_ledger() -> Arc<PplnsLedger> {
        Arc::new(PplnsLedger::new(&StratumConfig { pplns_window_shares: 100, ..StratumConfig::default() }))
    }

    #[test]
    fn render_has_help_type_and_values() {
        let snap = snap_with(|m| {
            m.worker_connected();
            m.worker_connected();
            m.shares_accepted.fetch_add(7, Ordering::Relaxed);
            m.blocks_found.fetch_add(1, Ordering::Relaxed);
            m.bytes_out.fetch_add(4096, Ordering::Relaxed);
        });
        let text = render_prometheus(&snap, &empty_pplns());
        assert!(text.contains("# HELP obb_stratum_workers_active"));
        assert!(text.contains("# TYPE obb_stratum_workers_active gauge"));
        assert!(text.contains("\nobb_stratum_workers_active 2\n"));
        assert!(text.contains("# TYPE obb_stratum_shares_accepted_total counter"));
        assert!(text.contains("\nobb_stratum_shares_accepted_total 7\n"));
        assert!(text.contains("\nobb_stratum_workers_total 2\n"));
        assert!(text.contains("\nobb_stratum_blocks_found_total 1\n"));
        assert!(text.contains("\nobb_stratum_bytes_out_total 4096\n"));
    }

    #[test]
    fn render_default_is_all_zero_and_well_formed() {
        let text = render_prometheus(&MetricsSnapshot::default(), &empty_pplns());
        for name in [
            "obb_stratum_workers_active",
            "obb_stratum_workers_total",
            "obb_stratum_workers_authorized",
            "obb_stratum_shares_accepted_total",
            "obb_stratum_shares_rejected_total",
            "obb_stratum_shares_stale_total",
            "obb_stratum_shares_duplicate_total",
            "obb_stratum_shares_low_difficulty_total",
            "obb_stratum_share_work_total",
            "obb_stratum_blocks_found_total",
            "obb_stratum_blocks_accepted_total",
            "obb_stratum_blocks_rejected_total",
            "obb_stratum_rpc_failures_total",
            "obb_stratum_templates_total",
            "obb_stratum_template_height",
            "obb_stratum_template_bits",
            "obb_stratum_template_parent_count",
            "obb_stratum_pplns_window_shares",
            "obb_stratum_pplns_window_weight",
            "obb_stratum_pplns_distinct_workers",
            "obb_stratum_bytes_in_total",
            "obb_stratum_bytes_out_total",
        ] {
            let help = format!("# HELP {name} ");
            assert_eq!(text.matches(&help).count(), 1, "missing/dup HELP for {name}");
            assert!(text.contains(&format!("\n{name} 0\n")), "zero value for {name}");
        }
        assert!(text.ends_with('\n'));
        assert!(!text.contains("bloch_"), "no Bloch series names left");
    }

    #[test]
    fn render_includes_the_pplns_window_shape() {
        let ledger = PplnsLedger::new(&StratumConfig { pplns_window_shares: 100, ..StratumConfig::default() });
        ledger.record("a".into(), "j", Some(8.0), &ShareOutcome::Accepted);
        ledger.record("b".into(), "j", Some(4.0), &ShareOutcome::Accepted);
        let text = render_prometheus(&MetricsSnapshot::default(), &ledger.snapshot());
        assert!(text.contains("\nobb_stratum_pplns_window_shares 2\n"));
        assert!(text.contains("\nobb_stratum_pplns_distinct_workers 2\n"));
        assert!(text.contains("\nobb_stratum_pplns_window_weight 12\n"));
    }

    #[test]
    fn pplns_is_off_by_default() {
        let ledger = PplnsLedger::new(&StratumConfig::default());
        ledger.record("a".into(), "j", Some(8.0), &ShareOutcome::Accepted);
        assert!(ledger.credit().is_empty());
        assert_eq!(ledger.totals().accepted, 1, "totals still count");
    }

    #[test]
    fn http_response_sets_content_length_to_body_len() {
        let body = "hello metrics\n";
        let resp = http_response("200 OK", PROM_CONTENT_TYPE, body);
        assert!(resp.contains(&format!("Content-Length: {}", body.len())));
        assert!(resp.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(resp.ends_with(body));
    }

    #[test]
    fn head_end_detection_scans_whole_buffer() {
        assert!(contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(contains_head_end(b"GET / HTTP/1.1\n\n"));
        assert!(!contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"));
        // The marker split across what would have been two chunks is still
        // found because we scan the accumulated buffer.
        assert!(contains_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"));
    }

    #[test]
    fn request_target_parses_or_defaults() {
        assert_eq!(
            request_target(b"GET /pplns HTTP/1.1\r\n\r\n").as_deref(),
            Some("/pplns")
        );
        assert_eq!(
            request_target(b"GET /metrics?foo=1 HTTP/1.1\r\n").as_deref(),
            Some("/metrics?foo=1")
        );
        // Garbage / empty must not panic — just yield None (→ Prometheus).
        assert_eq!(request_target(b""), None);
        assert_eq!(request_target(b"garbage-no-newline"), None);
        assert!(!wants_pplns(b"GET /metrics HTTP/1.1\r\n\r\n"));
        assert!(wants_pplns(b"GET /pplns HTTP/1.1\r\n\r\n"));
    }

    #[tokio::test]
    async fn end_to_end_scrape_returns_prometheus() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::new());
        metrics.shares_accepted.fetch_add(5, Ordering::Relaxed);
        metrics.worker_connected();
        let ledger = test_ledger();

        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            let _ = serve_metrics_on(listener, m, l).await;
        });

        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(text.contains("\nobb_stratum_shares_accepted_total 5\n"));
        assert!(text.contains("\nobb_stratum_workers_active 1\n"));
        assert!(text.contains("obb_stratum_pplns_window_shares"));
    }

    #[tokio::test]
    async fn pplns_endpoint_returns_json_credit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::new());
        let ledger = test_ledger();
        // Record an accepted share so the credit vector is non-empty.
        ledger.record("w1".into(), "job", Some(8.0), &ShareOutcome::Accepted);

        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            let _ = serve_metrics_on(listener, m, l).await;
        });

        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /pplns HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Type: application/json"));
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(
            body.trim_start().starts_with('['),
            "pplns body is not a JSON array: {body}"
        );
        // The serialized PplnsCredit exposes the worker + payout fraction.
        assert!(body.contains("\"worker\""), "body: {body}");
        assert!(body.contains("\"fraction\""), "body: {body}");
    }

    #[tokio::test]
    async fn empty_pplns_endpoint_is_empty_json_array() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(Metrics::new());
        let ledger = test_ledger();

        let m = metrics.clone();
        let l = ledger.clone();
        tokio::spawn(async move {
            let _ = serve_metrics_on(listener, m, l).await;
        });

        let mut conn = TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /pplns HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        assert_eq!(body, "[]");
    }

    /// A peer that opens a socket and sends a partial request head (no
    /// end-of-head marker) must be timed out and answered `408`, not pin the
    /// task. Driven through `handle_conn_inner` with a short real-time deadline
    /// so it is deterministic and fast.
    #[tokio::test]
    async fn slow_client_hits_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let metrics = Arc::new(Metrics::new());
        let ledger = test_ledger();
        let srv = tokio::spawn(async move {
            let _ =
                handle_conn_inner(server, &metrics, &ledger, Duration::from_millis(50)).await;
        });

        // Partial head: a request line but never the blank-line terminator.
        client.write_all(b"GET /metrics HTTP/1.1\r\n").await.unwrap();
        client.flush().await.unwrap();

        // The server must time out, answer 408, and close.
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with("HTTP/1.1 408"),
            "expected a 408 after the head-read timeout, got: {text}"
        );
        let _ = srv.await;
    }
}
