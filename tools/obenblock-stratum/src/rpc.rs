//! JSON-RPC client for the ObenBlock node (ported from the Bloch pool
//! proxy's dependency-free client: tokio + serde_json, one `POST /` per call
//! with `Connection: close`, bounded response, per-call deadline).
//!
//! Calls used by the server:
//!
//! * `getdaginfo`: the tip set, polled to notice a new block at once;
//! * `getblocktemplate [{"header_job": {"coinbase_script_pubkey", "extranonce"}}]`:
//!   the job (docs/OBENBLOCK-MINING.md §3.2);
//! * `submitblock [block_hex, {"version", "time", "nonce"}]` (§3.4).
//!
//! `getblocktemplate` and `submitblock` are privileged on the node (write
//! methods): the server sends the node's API key as `X-API-Key`. The node
//! reports method-level failures inside `result` as `{"error": "…"}`; those
//! become [`PoolError::Node`]. Nothing here panics on node output.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::PoolError;

/// Per-call deadline (connect + write + read).
const RPC_TIMEOUT: Duration = Duration::from_secs(20);

/// Largest response buffered (a template with a full block of transactions
/// is a few MB of JSON).
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RpcClient {
    addr: String,
    api_key: Option<String>,
}

impl RpcClient {
    /// `addr` is `host:port` (e.g. `127.0.0.1:18210`).
    pub fn new(addr: String, api_key: Option<String>) -> Self {
        Self { addr, api_key }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Invoke `method` with `params`; the JSON-RPC `result`.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, PoolError> {
        match tokio::time::timeout(RPC_TIMEOUT, self.call_inner(method, params)).await {
            Ok(res) => res,
            Err(_) => Err(PoolError::Timeout(format!("rpc {method} to {} timed out after {RPC_TIMEOUT:?}", self.addr))),
        }
    }

    async fn call_inner(&self, method: &str, params: Value) -> Result<Value, PoolError> {
        // Build the JSON-RPC 2.0 request body.
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let body = serde_json::to_string(&req)
            .map_err(|e| PoolError::Protocol(format!("rpc: encode request: {}", e)))?;

        // Assemble the HTTP/1.1 request head. Host is informational for the
        // node; `Connection: close` lets us read to EOF for the body.
        let mut head = format!(
            "POST / HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n",
            host = self.addr,
            len = body.len(),
        );
        // Optional API key. Guard against header injection from a stray
        // control char in the configured key (config is trusted, but cheap
        // to be safe).
        if let Some(key) = self.api_key.as_deref() {
            if !key.is_empty() && !key.contains(['\r', '\n']) {
                head.push_str("X-API-Key: ");
                head.push_str(key);
                head.push_str("\r\n");
            }
        }
        head.push_str("\r\n");

        // Serialise head+body into ONE buffer and write it in a single call.
        // A peer that reads the head, replies, and closes before we send a
        // separately-written body would reset our second write; one write
        // avoids that race entirely.
        let mut wire = Vec::with_capacity(head.len() + body.len());
        wire.extend_from_slice(head.as_bytes());
        wire.extend_from_slice(body.as_bytes());

        // Connect, send, read.
        let mut stream = TcpStream::connect(&self.addr).await?;
        stream.write_all(&wire).await?;
        stream.flush().await?;

        let raw = read_response_bounded(&mut stream).await?;
        let _ = stream.shutdown().await; // best-effort clean close

        // Split head/body, check status, parse JSON, extract `result`.
        let (status, json_body) = split_http_response(&raw)?;
        if status != 200 {
            return Err(PoolError::Protocol(format!(
                "rpc {} to {} returned HTTP {}",
                method, self.addr, status
            )));
        }
        let value: Value = serde_json::from_slice(json_body)
            .map_err(|e| PoolError::Protocol(format!("rpc: response not JSON: {}", e)))?;

        if let Some(result) = value.get("result") {
            Ok(result.clone())
        } else if let Some(err) = value.get("error") {
            Err(PoolError::Protocol(format!("rpc {} error: {}", method, err)))
        } else {
            Err(PoolError::Protocol(format!(
                "rpc {}: response missing both result and error",
                method
            )))
        }
    }

    /// The node's current DAG tips (hex), from `getdaginfo`.
    pub async fn dag_tips(&self) -> Result<Vec<String>, PoolError> {
        let v = self.call("getdaginfo", Value::Array(vec![])).await?;
        node_error(&v, "getdaginfo")?;
        let tips = v.get("tips").and_then(Value::as_array)
            .ok_or_else(|| PoolError::Protocol("getdaginfo: no tips array".into()))?;
        let mut t: Vec<String> = tips.iter().filter_map(Value::as_str).map(str::to_string).collect();
        t.sort_unstable();
        Ok(t)
    }

    /// `getblocktemplate` with a header job paying `script_pubkey`, with the
    /// given 8-byte extranonce.
    pub async fn header_job_template(&self, script_pubkey: &[u8], extranonce: &[u8; 8]) -> Result<Value, PoolError> {
        let v = self.call("getblocktemplate", json!([{"header_job": {
            "coinbase_script_pubkey": hex::encode(script_pubkey),
            "extranonce": hex::encode(extranonce),
        }}])).await?;
        node_error(&v, "getblocktemplate")?;
        Ok(v)
    }

    /// `submitblock [block_hex, {version, time, nonce}]`: the accepted block
    /// id (hex), or why the node refused it.
    pub async fn submit_block(&self, block: &[u8], version: u32, time: u32, nonce: u32) -> Result<String, PoolError> {
        let v = self.call("submitblock", json!([hex::encode(block), {"version": version, "time": time, "nonce": nonce}])).await?;
        node_error(&v, "submitblock")?;
        if v.get("accepted").and_then(Value::as_bool) != Some(true) {
            return Err(PoolError::Node(format!("submitblock: unexpected answer {v}")));
        }
        Ok(v.get("hash").and_then(Value::as_str).unwrap_or("").to_string())
    }
}

/// A `result` of the form `{"error": "…"}` is the node refusing the call.
fn node_error(v: &Value, method: &str) -> Result<(), PoolError> {
    match v.get("error") {
        Some(Value::String(e)) => Err(PoolError::Node(format!("{method}: {e}"))),
        Some(Value::Null) | None => Ok(()),
        Some(other) => Err(PoolError::Node(format!("{method}: {other}"))),
    }
}

// ── Minimal HTTP/1.1 response parsing ────────────────────────────────────

/// Read the full response into a bounded buffer (peer sends
/// `Connection: close`, so EOF terminates). Errors if it exceeds
/// [`MAX_RESPONSE_BYTES`] rather than growing memory unbounded.
async fn read_response_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, PoolError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_RESPONSE_BYTES {
            return Err(PoolError::Protocol("rpc: response exceeds size cap".to_string()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Split an HTTP response into `(status_code, body_bytes)`.
///
/// Parses only the status line and the header terminator — enough to locate
/// the body — and tolerates a missing/garbled status line by erroring rather
/// than panicking. Assumes the node's `Content-Length` framing (axum `Json`
/// responses set it); a chunked body would simply fail the later JSON parse,
/// still an `Err`, never a panic.
fn split_http_response(raw: &[u8]) -> Result<(u16, &[u8]), PoolError> {
    let sep = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| PoolError::Protocol("rpc: no HTTP header terminator".to_string()))?;
    let head = &raw[..sep];
    let body = &raw[sep + 4..];

    // First line: "HTTP/1.1 200 OK" — code is the second whitespace token.
    let first_line_end = find_subslice(head, b"\r\n").unwrap_or(head.len());
    let status_line = String::from_utf8_lossy(&head[..first_line_end]);
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| PoolError::Protocol("rpc: unparseable HTTP status line".to_string()))?;

    Ok((code, body))
}

/// First index of `needle` within `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn mock_node_raw(raw: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut scratch = [0u8; 4096];
                let _ = stream.read(&mut scratch).await;
                let _ = stream.write_all(raw.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        addr
    }

    async fn mock_node_ok(body: &str) -> String {
        mock_node_raw(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body)).await
    }

    #[tokio::test]
    async fn dag_tips_are_sorted() {
        let addr = mock_node_ok(r#"{"jsonrpc":"2.0","id":1,"result":{"tips":["bb","aa"],"tip_count":2}}"#).await;
        assert_eq!(RpcClient::new(addr, None).dag_tips().await.unwrap(), vec!["aa", "bb"]);
    }

    #[tokio::test]
    async fn node_errors_inside_result_are_errors() {
        let addr = mock_node_ok(r#"{"result":{"error":"rejected: bad pow"}}"#).await;
        let e = RpcClient::new(addr, None).submit_block(&[1, 2], 1, 2, 3).await.unwrap_err();
        assert!(matches!(e, PoolError::Node(ref m) if m.contains("bad pow")), "{e}");
        let addr = mock_node_ok(r#"{"result":{"accepted":true,"hash":"00ff"}}"#).await;
        assert_eq!(RpcClient::new(addr, None).submit_block(&[1], 1, 2, 3).await.unwrap(), "00ff");
    }

    #[tokio::test]
    async fn api_key_is_sent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 8192];
            let n = stream.read(&mut scratch).await.unwrap();
            let head = String::from_utf8_lossy(&scratch[..n]).to_string();
            let body = r#"{"result":{"tips":[]}}"#;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
            head
        });
        let _ = RpcClient::new(addr, Some("s3cr3t".into())).dag_tips().await.unwrap();
        let head = handle.await.unwrap();
        assert!(head.contains("X-API-Key: s3cr3t"), "{head}");
        assert!(head.contains("\"method\":\"getdaginfo\""), "{head}");
    }

    #[tokio::test]
    async fn bad_answers_are_errors_not_panics() {
        for raw in [
            "not even http\r\n\r\n{}".to_string(),
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}".to_string(),
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n<<<<<".to_string(),
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"jsonrpc\":1}".to_string(),
        ] {
            let addr = mock_node_raw(raw).await;
            assert!(RpcClient::new(addr, None).dag_tips().await.is_err());
        }
    }

    #[tokio::test]
    async fn refused_connection_is_an_error() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        drop(l);
        assert!(RpcClient::new(addr, None).dag_tips().await.is_err());
    }

    #[test]
    fn split_http_response_extracts_status_and_body() {
        let (code, body) = split_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((code, body), (200, &b"{}"[..]));
        assert!(split_http_response(b"HTTP/1.1 200 OK\r\nno end").is_err());
    }
}
