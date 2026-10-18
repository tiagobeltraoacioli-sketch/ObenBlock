//! V1 `mining.submit`: from a share to a block through the node's
//! acceptance path.
//!
//! ```text
//! params: [worker, job_id, extranonce2_hex, ntime_hex, nonce_hex, (version_bits_hex)]
//! ```
//!
//! The sixth parameter is BIP 310's rolled version bits; the header version
//! is `(job_version & !mask) | (version_bits & mask)` with the session's
//! negotiated mask (the extranonce gives the coinbase and ObenBlock's
//! header root; a block's header must be its own 80 bytes):
//!
//! * the header and id come first, cheaply ([`Job::share`](super::jobs::Job::share):
//!   coinbase txid and branch, no block);
//! * a share that meets the job's block target is a block, whatever the
//!   submit rate: only then is the block assembled
//!   ([`Job::block_for`](super::jobs::Job::block_for)) and sent to the same
//!   hook as `submitblock` (`AcceptBlockFn`); the node's verdict is the
//!   answer;
//! * any other share over the session's submit rate is refused and raises
//!   vardiff to the observed rate; otherwise the id is checked against the
//!   session's share target (never harder than the block target): below
//!   it, error 23;
//! * duplicates are keyed on the header id and remembered only once
//!   credited.
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
use super::guard::peer_str;
use super::session::{Session, SessionState, SubmitRate, MAX_JOB_ID_LEN, SUBMIT_FLOOD_PER_MIN, SUBMIT_RATE_PER_MIN};
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
    if !session.is_authorized() {
        return err(id, ErrorCode::Unauthorized, "unauthorized worker");
    }
    let rate = session.note_submit();
    if rate == SubmitRate::Flood {
        session.set_state(SessionState::Dead);
        return err(id, ErrorCode::Other, format!("submit flood (over {SUBMIT_FLOOD_PER_MIN}/min): closing"));
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

    let Some(entry) = session.find_job(job_id) else {
        return err(id, ErrorCode::JobNotFoundOrStale, "job is not current");
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

    // The header first (cheap: coinbase txid and branch, no block): the
    // limiter below must never cost a block.
    let extranonce = session.extranonce(&en2);
    let share = match job.share(&extranonce, version, ntime, nonce) {
        Ok(s) => s,
        Err(e @ SolveError::BitsChanged { .. }) => return err(id, ErrorCode::JobNotFoundOrStale, e.to_string()),
        Err(e @ SolveError::Internal(_)) => {
            if let Some(n) = session.log_allow() {
                warn!("stratum: session {} share on job {} not reconstructible: {e}{}", session.id,
                      peer_str(job_id), super::suppressed_note(n));
            }
            return err(id, ErrorCode::Other, e.to_string());
        }
        Err(e) => return err(id, ErrorCode::Other, e.to_string()),
    };
    // Duplicates are keyed on the header id (canonical whatever the hex
    // spelling or job id), checked here and remembered only once credited.
    if session.is_duplicate(&share.id) {
        return err(id, ErrorCode::DuplicateShare, "duplicate share");
    }

    let block_target = job.block_target();
    let net_diff = difficulty_from_bits(job.bits);
    let is_block = sha256d::meets_target(&share.id, &block_target);
    if !is_block {
        if rate == SubmitRate::Excess {
            if let Some(d) = session.raise_for_rate(net_diff) {
                session.announce_difficulty(d);
            }
            return err(id, ErrorCode::Other, format!("submit rate exceeded ({SUBMIT_RATE_PER_MIN}/min): difficulty raised"));
        }
        // Share target: the session's difficulty (or the one before a raise,
        // in its grace), capped at the block's (a share is never harder than
        // a block, also after rounding).
        let share_target = difficulty::easier(&target_from_difficulty(session.judged_difficulty().min(net_diff)),
                                              &block_target);
        if !sha256d::meets_target(&share.id, &share_target) {
            return err(id, ErrorCode::LowDifficulty, "share above target");
        }
    }
    session.remember_share(share.id);
    session.note_accepted_share();
    if let Some(d) = session.record_share_and_maybe_retarget(net_diff) {
        let _ = session.send_set_difficulty(d);
    }
    if !is_block {
        return StratumResponse::ok(id, Value::from(true));
    }

    // A block: only now is the block assembled (whatever the submit rate).
    let block = match job.block_for(&extranonce, &share) {
        Ok(b) => b,
        Err(e) => {
            warn!("stratum: session {} block share on job {} could not be assembled: {e}", session.id, peer_str(job_id));
            return err(id, ErrorCode::Other, e.to_string());
        }
    };
    let height = block.height;
    match accept_block(block) {
        Ok(hash) => {
            crate::metrics::stratum_block_found("v1");
            info!("stratum: session {} BLOCK FOUND h={height} id={hash} (by {}, version {version:08x} ntime {ntime})",
                  session.id, peer_str(&session.authorized_name().unwrap_or_default()));
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
    fn the_rate_limiter_never_refuses_before_the_share_is_hashed() {
        // Over the per-minute rate, a submit is still parsed and looked up
        // (the job lookup answers 21 here, not a blanket rate refusal); a
        // block share would be judged and submitted.
        let s = mk_session();
        for _ in 0..(SUBMIT_RATE_PER_MIN + 5) {
            assert_eq!(code(&handle_submit(&s, &submit_req("j", "cafebabe", "00000001", "00000000"), &*cb())), 21);
        }
        assert!(!s.is_dead());
    }

    #[test]
    fn a_submit_flood_closes_the_session() {
        let s = mk_session();
        for _ in 0..SUBMIT_FLOOD_PER_MIN {
            let _ = handle_submit(&s, &submit_req("j", "cafebabe", "00000001", "00000000"), &*cb());
        }
        assert!(!s.is_dead());
        assert_eq!(code(&handle_submit(&s, &submit_req("j", "cafebabe", "00000001", "00000000"), &*cb())), 20);
        assert!(s.is_dead(), "closed at the flood cap");
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
