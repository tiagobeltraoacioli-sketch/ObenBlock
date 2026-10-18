//! V1 `mining.submit`: from a share to a block through the node's
//! acceptance path.
//!
//! ```text
//! params: [worker, job_id, extranonce2_hex, ntime_hex, nonce_hex, (version_bits_hex)]
//! ```
//!
//! The sixth parameter is BIP 310's rolled version bits; the header version
//! is `(job_version & !mask) | (version_bits & mask)` with the session's
//! negotiated mask. The share is turned into its block by
//! [`Job::solve`](super::jobs::Job::solve) (the extranonce gives the
//! coinbase and ObenBlock's header root; the header must be the block's own
//! 80 bytes), then:
//!
//! * the id is checked against the session's share target (never harder than
//!   the block target): below it, error 23;
//! * a share that also meets the job's block target is a block: it goes to
//!   the same hook as `submitblock` (`AcceptBlockFn`), and the node's verdict
//!   is the answer.
//!
//! Error codes (Bitcoin stratum convention): 20 other / rejected block,
//! 21 unknown or stale job, 22 duplicate, 23 low difficulty, 24 unauthorized.
//!
//! Ported from the legacy Bloch server (genesis3-node `src/stratum/submit.rs`).

use std::sync::Arc;

use log::{info, warn};
use serde_json::Value;

use super::difficulty::{self, difficulty_from_bits, target_from_difficulty};
use super::jobs::{SolveError, EXTRANONCE2_BYTES};
use super::protocol::{ErrorCode, StratumError, StratumRequest, StratumResponse};
use super::session::{Session, MAX_JOB_ID_LEN};
use super::AcceptBlockFn;
use gnb_smh::sha256d;

fn err(id: Option<Value>, code: ErrorCode, msg: impl Into<String>) -> StratumResponse {
    StratumResponse::error(id, StratumError::new(code, msg))
}

/// Parse a big-endian hex u32 (with or without `0x`).
pub fn parse_hex_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() || t.len() > 8 {
        return None;
    }
    u32::from_str_radix(t, 16).ok()
}

/// Handle one `mining.submit`.
pub fn handle_submit(session: &Arc<Session>, req: &StratumRequest, accept_block: &AcceptBlockFn) -> StratumResponse {
    let r = submit_inner(session, req, accept_block);
    let result = match &r.error {
        None => "ok",
        Some(e) => match e.get(0).and_then(Value::as_u64) {
            Some(21) => "stale",
            Some(22) => "dup",
            Some(23) => "low_diff",
            Some(24) => "unauthorized",
            _ => "rejected",
        },
    };
    crate::metrics::stratum_share("v1", result);
    r
}

fn submit_inner(session: &Arc<Session>, req: &StratumRequest, accept_block: &AcceptBlockFn) -> StratumResponse {
    let id = req.id.clone();
    if let Err(e) = session.check_submit_rate() {
        return StratumResponse::error(id, e);
    }
    if !session.is_authorized() {
        return err(id, ErrorCode::Unauthorized, "unauthorized worker");
    }
    let params = match req.params.as_array() {
        Some(a) if a.len() >= 5 => a,
        _ => return err(id, ErrorCode::Other, "submit requires [worker, job_id, extranonce2, ntime, nonce]"),
    };
    let str_at = |i: usize| params.get(i).and_then(Value::as_str);
    let Some(job_id) = str_at(1) else { return err(id, ErrorCode::Other, "job_id must be a string") };
    if job_id.len() > MAX_JOB_ID_LEN {
        return err(id, ErrorCode::JobNotFoundOrStale, "job_id too long");
    }
    let (Some(en2_hex), Some(ntime_hex), Some(nonce_hex)) = (str_at(2), str_at(3), str_at(4)) else {
        return err(id, ErrorCode::Other, "extranonce2, ntime and nonce must be hex strings");
    };
    let en2: [u8; EXTRANONCE2_BYTES] = match hex::decode(en2_hex) {
        Ok(v) => match v.try_into() {
            Ok(a) => a,
            Err(_) => return err(id, ErrorCode::Other, format!("extranonce2 must be {EXTRANONCE2_BYTES} bytes")),
        },
        Err(_) => return err(id, ErrorCode::Other, "extranonce2 not valid hex"),
    };
    let Some(ntime) = parse_hex_u32(ntime_hex) else { return err(id, ErrorCode::Other, "ntime not valid hex u32") };
    let Some(nonce) = parse_hex_u32(nonce_hex) else { return err(id, ErrorCode::Other, "nonce not valid hex u32") };
    let version_bits = match str_at(5) {
        None => None,
        Some(s) => match parse_hex_u32(s) {
            Some(v) => Some(v),
            None => return err(id, ErrorCode::Other, "version bits not valid hex u32"),
        },
    };

    // Duplicate before lookup: a repeat against an evicted job is still 22.
    if !session.record_submission(job_id, en2_hex, ntime_hex, nonce_hex, str_at(5).unwrap_or("")) {
        return err(id, ErrorCode::DuplicateShare, "duplicate share");
    }
    let Some(entry) = session.find_job(job_id) else {
        return err(id, ErrorCode::JobNotFoundOrStale, format!("job {job_id:?} is not current"));
    };
    let job = &entry.job;

    let version = match version_bits {
        None => job.version,
        Some(bits) => {
            let mask = session.version_mask();
            if bits & !mask != 0 {
                return err(id, ErrorCode::Other, format!(
                    "version bits {bits:08x} outside the negotiated mask {mask:08x} (mining.configure version-rolling)"));
            }
            (job.version & !mask) | (bits & mask)
        }
    };

    let extranonce = session.extranonce(&en2);
    let solved = match job.solve(&extranonce, version, ntime, nonce) {
        Ok(s) => s,
        Err(e @ SolveError::BitsChanged { .. }) => return err(id, ErrorCode::JobNotFoundOrStale, e.to_string()),
        Err(e @ SolveError::Internal(_)) => {
            warn!("stratum: session {} share on job {job_id} not reconstructible: {e}", session.id);
            return err(id, ErrorCode::Other, e.to_string());
        }
        Err(e) => return err(id, ErrorCode::Other, e.to_string()),
    };

    // Share target: the session's difficulty, capped at the block's (a
    // share is never harder than a block, also after rounding).
    let block_target = job.block_target();
    let net_diff = difficulty_from_bits(job.bits);
    let share_target = difficulty::easier(&target_from_difficulty(session.share_difficulty().min(net_diff)), &block_target);
    if !sha256d::meets_target(&solved.id, &share_target) {
        if !session.obb_merkle() {
            let btc_root = job.bitcoin_tree_root_for(&extranonce);
            let btc_header = super::jobs::header_bytes(version, &job.parents_commitment, &btc_root, ntime, job.bits, nonce);
            if sha256d::meets_target(&sha256d::block_id(&btc_header), &share_target) {
                if session.note_bitcoin_tree_share() {
                    warn!("stratum: session {} ({}) hashes headers with Bitcoin's Merkle tree: its shares can \
                           never be ObenBlock blocks (docs/STRATUM.md, \"V1 and the header root\")",
                          session.id, session.authorized_name().unwrap_or_default());
                }
                return err(id, ErrorCode::LowDifficulty,
                    "share uses Bitcoin's Merkle root; ObenBlock's header root is the body root \
                     (mining.configure obb-merkle-root, or use Stratum V2)");
            }
        }
        return err(id, ErrorCode::LowDifficulty, "share above target");
    }
    if let Some(d) = session.record_share_and_maybe_retarget(net_diff) {
        let _ = session.send_set_difficulty(d);
    }
    if !sha256d::meets_target(&solved.id, &block_target) {
        return StratumResponse::ok(id, Value::from(true));
    }

    let height = solved.block.height;
    match accept_block(solved.block) {
        Ok(hash) => {
            crate::metrics::stratum_block_found("v1");
            info!("stratum: session {} BLOCK FOUND h={height} id={hash} (by {}, version {version:08x} ntime {ntime})",
                  session.id, session.authorized_name().unwrap_or_default());
            StratumResponse::ok(id, Value::from(true))
        }
        Err(reason) => {
            warn!("stratum: session {} block rejected by the node: {reason}", session.id);
            err(id, ErrorCode::Other, format!("rejected: {reason}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn mk_session() -> Arc<Session> {
        let s = Arc::new(Session::new(1, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)));
        let p = super::super::payout::Payout { address: "test".into(), script_pubkey: vec![0x11; 20] };
        s.set_authorized("test".into(), p);
        s
    }

    fn cb() -> Box<AcceptBlockFn> {
        Box::new(|_b| Ok("ok".to_string()))
    }

    fn submit_req(job: &str, en2: &str, ntime: &str, nonce: &str) -> StratumRequest {
        StratumRequest { id: Some(json!(1)), method: "mining.submit".into(), params: json!(["w", job, en2, ntime, nonce]) }
    }

    fn code(r: &StratumResponse) -> u64 {
        r.error.as_ref().and_then(|e| e[0].as_u64()).expect("an error response")
    }

    #[test]
    fn unauthorized_returns_24() {
        let s = Arc::new(Session::new(1, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)));
        assert_eq!(code(&handle_submit(&s, &submit_req("j", "00000000", "00000000", "00000000"), &*cb())), 24);
    }

    #[test]
    fn malformed_params_return_20() {
        let s = mk_session();
        let four = StratumRequest { id: Some(json!(1)), method: "mining.submit".into(), params: json!(["w", "j", "00", "00"]) };
        assert_eq!(code(&handle_submit(&s, &four, &*cb())), 20);
        assert_eq!(code(&handle_submit(&s, &submit_req("j", "ZZZZZZZZ", "0", "0"), &*cb())), 20);
        assert_eq!(code(&handle_submit(&s, &submit_req("j", "00", "0", "0"), &*cb())), 20, "extranonce2 is 4 bytes");
        assert_eq!(code(&handle_submit(&s, &submit_req("j", "00000000", "nothex", "0"), &*cb())), 20);
    }

    #[test]
    fn unknown_and_overlong_job_ids_return_21() {
        let s = mk_session();
        assert_eq!(code(&handle_submit(&s, &submit_req("nope", "00000000", "0", "0"), &*cb())), 21);
        let long = "j".repeat(MAX_JOB_ID_LEN + 1);
        assert_eq!(code(&handle_submit(&s, &submit_req(&long, "00000000", "0", "0"), &*cb())), 21);
    }

    #[test]
    fn duplicates_return_22_and_rolled_fields_are_distinct() {
        let s = mk_session();
        let _ = handle_submit(&s, &submit_req("j", "cafebabe", "00000001", "00000000"), &*cb());
        assert_eq!(code(&handle_submit(&s, &submit_req("j", "cafebabe", "00000001", "00000000"), &*cb())), 22);
        // Another ntime is another solution (not 22; 21 for the unknown job).
        assert_eq!(code(&handle_submit(&s, &submit_req("j", "cafebabe", "00000002", "00000000"), &*cb())), 21);
    }

    #[test]
    fn parse_hex_u32_accepts_various_forms() {
        assert_eq!(parse_hex_u32("0"), Some(0));
        assert_eq!(parse_hex_u32("ffffffff"), Some(0xffff_ffff));
        assert_eq!(parse_hex_u32("0x1234abcd"), Some(0x1234_abcd));
        assert_eq!(parse_hex_u32("0X1234ABCD"), Some(0x1234_abcd));
        assert!(parse_hex_u32("not-hex").is_none());
        assert!(parse_hex_u32("100000000").is_none());
        assert!(parse_hex_u32("").is_none());
    }
}
