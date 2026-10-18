//! Stratum V1 line protocol: bounded framing and request parsing.
//!
//! * **Framing** ([`LineReader`] / [`write_line`]): newline-delimited JSON
//!   over any tokio stream half. `MAX_LINE_BYTES` is enforced DURING
//!   accumulation, so a peer that never sends `\n` cannot grow a buffer
//!   without bound, and [`LineReader::next_line`] is cancel-safe (a partial
//!   line survives losing a `select!` arm).
//! * **Parsing** ([`parse_request`], [`parse_submit`]): pure mapping of one
//!   untrusted line to typed values. Nothing here unwraps network input.
//!
//! ```text
//!   subscribe result : [[["mining.set_difficulty",sid],["mining.notify",sid]], en1_hex, en2_size]
//!   notify           : [job_id, prevhash, coinb1, coinb2, merkle[], version, bits, ntime, clean_jobs]
//!   set_difficulty   : [difficulty]
//!   submit           : [worker_name, job_id, extranonce2, ntime, nonce, version_bits?]
//!   error payload    : [code, "message", null]
//! ```

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::types::{Line, PoolError, MAX_LINE_BYTES};

/// Bounded, cancellation-friendly line reader.
pub struct LineReader<R: AsyncBufRead + Unpin> {
    inner: R,
    /// Partial-line accumulator, kept across calls.
    buf: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, buf: Vec::with_capacity(512) }
    }

    /// Read one line, INCLUDING its trailing `\n` (a final unterminated line
    /// at EOF is delivered once without it).
    ///
    /// * `Ok(None)`: clean EOF with nothing buffered.
    /// * `Err(PoolError::Protocol)`: over `MAX_LINE_BYTES`, or not UTF-8.
    pub async fn next_line(&mut self) -> Result<Option<Line>, PoolError> {
        loop {
            let available = self.inner.fill_buf().await.map_err(PoolError::Io)?;
            if available.is_empty() {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let bytes = std::mem::take(&mut self.buf);
                return String::from_utf8(bytes)
                    .map(Some)
                    .map_err(|_| PoolError::Protocol("non-utf8 stratum line".into()));
            }
            if let Some(i) = available.iter().position(|&b| b == b'\n') {
                self.buf.extend_from_slice(&available[..=i]);
                self.inner.consume(i + 1);
                if self.buf.len() > MAX_LINE_BYTES {
                    return Err(PoolError::Protocol(format!("stratum line exceeds {MAX_LINE_BYTES} bytes")));
                }
                let bytes = std::mem::take(&mut self.buf);
                return String::from_utf8(bytes)
                    .map(Some)
                    .map_err(|_| PoolError::Protocol("non-utf8 stratum line".into()));
            }
            let n = available.len();
            self.buf.extend_from_slice(available);
            self.inner.consume(n);
            if self.buf.len() > MAX_LINE_BYTES {
                return Err(PoolError::Protocol(format!("stratum line exceeds {MAX_LINE_BYTES} bytes")));
            }
        }
    }
}

/// Write one line, appending `\n` if missing, and flush.
pub async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, line: &str) -> Result<(), PoolError> {
    w.write_all(line.as_bytes()).await.map_err(PoolError::Io)?;
    if !line.ends_with('\n') {
        w.write_all(b"\n").await.map_err(PoolError::Io)?;
    }
    w.flush().await.map_err(PoolError::Io)?;
    Ok(())
}

/// A parsed client request.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: Value,
    pub method: String,
    pub params: Vec<Value>,
}

/// Parse one client line. `Ok(None)` for a blank line or a line without a
/// `method` (a stray response); `Err` for malformed JSON.
pub fn parse_request(line: &str) -> Result<Option<Request>, PoolError> {
    let t = line.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let v: Value = serde_json::from_str(t).map_err(|e| PoolError::Protocol(format!("client parse: {e}")))?;
    let Some(method) = v.get("method").and_then(Value::as_str) else { return Ok(None) };
    let params = match v.get("params") {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other.clone()],
    };
    Ok(Some(Request { id: v.get("id").cloned().unwrap_or(Value::Null), method: method.to_string(), params }))
}

/// A parsed `mining.submit`:
/// `[worker_name, job_id, extranonce2, ntime, nonce, version_bits?]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Submit {
    pub worker_name: String,
    pub job_id: String,
    pub extranonce2: Vec<u8>,
    pub ntime: u32,
    pub nonce: u32,
    /// BIP 310 rolled version bits (6th param), when the miner rolls.
    pub version_bits: Option<u32>,
}

/// Parse the params of a `mining.submit`. Every field is hex; ntime, nonce
/// and version bits are big-endian hex u32 (stratum convention). Any
/// malformed field is an error (the share is rejected, not guessed at).
pub fn parse_submit(params: &[Value]) -> Result<Submit, String> {
    if params.len() < 5 {
        return Err("submit needs [worker, job_id, extranonce2, ntime, nonce]".into());
    }
    let s = |i: usize, name: &str| params[i].as_str().map(str::to_string).ok_or_else(|| format!("submit: {name} must be a string"));
    let extranonce2 = hex_to_bytes(&s(2, "extranonce2")?).ok_or("submit: extranonce2 is not hex")?;
    let ntime = parse_hex_u32(&s(3, "ntime")?).ok_or("submit: ntime is not a hex u32")?;
    let nonce = parse_hex_u32(&s(4, "nonce")?).ok_or("submit: nonce is not a hex u32")?;
    let version_bits = match params.get(5) {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_str().and_then(parse_hex_u32).ok_or("submit: version bits are not a hex u32")?),
    };
    Ok(Submit { worker_name: s(0, "worker")?, job_id: s(1, "job_id")?, extranonce2, ntime, nonce, version_bits })
}

/// Decode an even-length hex string; `None` on any malformed input.
pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.trim()).ok()
}

/// Parse a big-endian hex `u32` (optional `0x`, at most 8 digits).
pub fn parse_hex_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() || t.len() > 8 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(t, 16).ok()
}

/// `{"id":…,"result":…,"error":null}`.
pub fn result_line(id: &Value, result: Value) -> String {
    serde_json::json!({"id": id, "result": result, "error": Value::Null}).to_string()
}

/// `{"id":…,"result":null,"error":[code,"message",null]}`; `message` is JSON
/// escaped (it may echo client input).
pub fn error_line(id: &Value, code: i64, message: &str) -> String {
    serde_json::json!({"id": id, "result": Value::Null, "error": [code, message, Value::Null]}).to_string()
}

/// A server notification `{"id":null,"method":…,"params":…}`.
pub fn notification_line(method: &str, params: Value) -> String {
    serde_json::json!({"id": Value::Null, "method": method, "params": params}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::BufReader;

    fn reader(bytes: &'static [u8]) -> LineReader<BufReader<&'static [u8]>> {
        LineReader::new(BufReader::new(bytes))
    }

    #[tokio::test]
    async fn reads_multiple_lines_then_eof() {
        let mut r = reader(b"{\"a\":1}\n{\"b\":2}\n");
        assert_eq!(r.next_line().await.unwrap().unwrap(), "{\"a\":1}\n");
        assert_eq!(r.next_line().await.unwrap().unwrap(), "{\"b\":2}\n");
        assert!(r.next_line().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delivers_final_unterminated_line_then_eof() {
        let mut r = reader(b"no-newline-here");
        assert_eq!(r.next_line().await.unwrap().unwrap(), "no-newline-here");
        assert!(r.next_line().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversize_line_is_a_protocol_error() {
        let giant: &'static [u8] = Box::leak(vec![b'x'; MAX_LINE_BYTES + 10].into_boxed_slice());
        let mut r = LineReader::new(BufReader::new(giant));
        assert!(matches!(r.next_line().await, Err(PoolError::Protocol(_))));
    }

    #[tokio::test]
    async fn write_line_appends_newline_once() {
        let mut out: Vec<u8> = Vec::new();
        write_line(&mut out, "{\"x\":1}").await.unwrap();
        write_line(&mut out, "{\"y\":1}\n").await.unwrap();
        assert_eq!(out, b"{\"x\":1}\n{\"y\":1}\n");
    }

    #[test]
    fn parses_requests() {
        let r = parse_request(r#"{"id":1,"method":"mining.subscribe","params":["bmminer/2.0"]}"#).unwrap().unwrap();
        assert_eq!(r.id, json!(1));
        assert_eq!(r.method, "mining.subscribe");
        assert_eq!(r.params, vec![json!("bmminer/2.0")]);
        assert!(parse_request("   \n").unwrap().is_none());
        assert!(parse_request(r#"{"id":5,"result":true,"error":null}"#).unwrap().is_none());
        assert!(parse_request("{not json").is_err());
        // A missing params field is an empty list.
        assert!(parse_request(r#"{"id":2,"method":"mining.extranonce.subscribe"}"#).unwrap().unwrap().params.is_empty());
    }

    #[test]
    fn parses_submit_with_and_without_version_bits() {
        let p = vec![json!("obb1qxyz.rig1"), json!("1a-2"), json!("deadbeef"), json!("5f5e1000"), json!("00c0ffee")];
        let s = parse_submit(&p).unwrap();
        assert_eq!(s.job_id, "1a-2");
        assert_eq!(s.extranonce2, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(s.ntime, 0x5f5e_1000);
        assert_eq!(s.nonce, 0x00c0_ffee);
        assert_eq!(s.version_bits, None);
        let mut p6 = p.clone();
        p6.push(json!("00004000"));
        assert_eq!(parse_submit(&p6).unwrap().version_bits, Some(0x4000));
    }

    #[test]
    fn malformed_submit_fields_are_errors() {
        let base = || vec![json!("w"), json!("j"), json!("00000000"), json!("5f5e1000"), json!("00000000")];
        assert!(parse_submit(&base()[..4]).is_err());
        let mut p = base();
        p[1] = json!(5);
        assert!(parse_submit(&p).is_err());
        let mut p = base();
        p[2] = json!("xyz");
        assert!(parse_submit(&p).is_err());
        let mut p = base();
        p[4] = json!("100000000");
        assert!(parse_submit(&p).is_err());
        let mut p = base();
        p.push(json!("not-hex"));
        assert!(parse_submit(&p).is_err());
    }

    #[test]
    fn hex_u32_parsing_fails_closed() {
        assert_eq!(parse_hex_u32("60000000"), Some(0x6000_0000));
        assert_eq!(parse_hex_u32("0x01"), Some(1));
        assert!(parse_hex_u32("100000000").is_none());
        assert!(parse_hex_u32("+1").is_none());
        assert!(parse_hex_u32("").is_none());
    }

    #[test]
    fn error_lines_escape_client_text() {
        let l = error_line(&json!(3), 20, "bad \"quote\"\nnewline");
        let v: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(v["error"][1], json!("bad \"quote\"\nnewline"));
        assert!(!l.contains('\n'));
    }
}
