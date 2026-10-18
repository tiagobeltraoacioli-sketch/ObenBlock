//! The SHA-256d pool interface of `getblocktemplate` and `submitblock`
//! (ObenBlock, docs/DESIGN-obenblock.md §4.1, docs/OBENBLOCK-MINING.md).
//!
//! A Bitcoin ASIC hashes the 80-byte header
//! `version ‖ parents_commitment ‖ merkle_root ‖ time ‖ bits ‖ nonce` and
//! rolls the nonce, the BIP 320 version bits and the time. Stock Stratum V1
//! firmware also rolls extranonce2 and rebuilds `merkle_root` itself as
//! Bitcoin does: `SHA-256d(coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2)`
//! folded up the job's merkle branch with `SHA-256d(cur ‖ sibling)`. That is
//! ObenBlock's consensus header root (`core::pow_scheme::bitcoin_merkle_root`
//! over the txids; the rest of the body is committed by the coinbase
//! commitment), so a standard `mining.notify` mines ObenBlock unmodified.
//! This module gives a pool what it needs:
//!
//! * [`template_fields`]: the `sha256d` object of `getblocktemplate`: the
//!   header fields in their 80-byte order, the `bits` of the job's time and
//!   the time window in which a rolled `ntime` keeps those bits
//!   ([`TimeWindow`], stall relief), and a header job on request;
//! * [`header_job`]: on request (`getblocktemplate [{"header_job": {...}}]`),
//!   a complete candidate block paying a pool's script, its 80-byte header,
//!   the coinbase split around an [`EXTRANONCE_LEN`]-byte extranonce
//!   (`coinb1 ‖ extranonce ‖ coinb2`), the Bitcoin merkle branch and the
//!   fields of a Stratum V1 `mining.notify` ([`HeaderJob::stratum_json`];
//!   reference: `reference/obb_job.py`);
//! * [`apply_submit_solution`]: `submitblock [block_hex, {"version", "time",
//!   "nonce"[, "extranonce"]}]` writes a share's rolled header fields (and
//!   its extranonce) into the block of its job before the usual submission
//!   path.
//!
//! Nothing here is consensus: a block is judged by the same acceptance path
//! whatever produced it. Under GnB-SMH (no SHA-256d scheme set)
//! [`template_fields`] is `null` and [`apply_submit_solution`] ignores its
//! argument, exactly as before.

use serde_json::{json, Value};

use crate::core::pow_scheme::{self, Sha256dParams};
use crate::core::{self, Block, MerkleRoot, Transaction, TxInput};
use crate::template::{self, BlockTemplate};
use gnb_smh::sha256d;

/// Bytes of the extranonce a header job's coinbase carries: stratum's
/// `extranonce1 ‖ extranonce2` (a pool picks the split, e.g. 4 + 4).
pub const EXTRANONCE_LEN: usize = 8;

/// Miner bytes of a header job's coinbase before the extranonce, after the
/// 80-byte coinbase commitment.
pub const COINBASE_TAG: &[u8] = b"/obb/";

/// The `merkle_rule` of an ObenBlock template: Bitcoin's SHA-256d tree.
pub const MERKLE_RULE: &str = "bitcoin-sha256d";

/// The rule a pool applies to compute the header Merkle root from the
/// coinbase txid, or why this template has none a pool can use.
fn merkle_rule(tmpl: &BlockTemplate) -> Result<&'static str, String> {
    if !core::block_rules::rules_apply(tmpl.height, tmpl.activation_height) || !tmpl.hardened {
        return Err("header jobs need the hardening block rules at the template height \
                    (ObenBlock applies them from genesis)".into());
    }
    if pow_scheme::node_sha256d_params().is_none() {
        return Err("header jobs need the SHA-256d proof-of-work scheme".into());
    }
    Ok(MERKLE_RULE)
}

/// The Bitcoin merkle branch of a block built from `tmpl`: the siblings of
/// the coinbase (position 0) bottom-up, in the byte order they are hashed
/// in (stratum's `merkle_branch`).
pub fn merkle_branch(tmpl: &BlockTemplate) -> Vec<[u8; 32]> {
    tmpl.coinbase_merkle_branch()
}

/// The header Merkle root of a block built from `tmpl` whose coinbase has
/// txid `coinbase_txid`: `cur = coinbase_txid; cur = SHA-256d(cur ‖ s)` for
/// each `s` of [`merkle_branch`] (exactly what stratum firmware computes).
pub fn header_merkle_root(tmpl: &BlockTemplate, coinbase_txid: &[u8; 32]) -> Result<MerkleRoot, String> {
    merkle_rule(tmpl)?;
    Ok(core::block_rules::merkle_root_from_coinbase_branch(coinbase_txid, &merkle_branch(tmpl), false))
}

/// The time window of a job (DESIGN-obenblock.md §5.1): a block's `bits`
/// depend on its own time once it is 180 s late, in 60-second steps. A job
/// carries the `bits` of its `curtime`; any `time` in `[mintime, maxtime]`
/// has exactly those bits (same relief step, at or after the parents, at
/// most `MAX_FUTURE_SECS` ahead of the answering node's clock). A pool must
/// fetch a new job when its clock passes `maxtime` (the next step makes the
/// target easier) and must never roll `ntime` outside the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeWindow {
    pub curtime: u64,
    pub mintime: u64,
    pub maxtime: u64,
    /// `bits` for every time in the window (stall relief applied).
    pub bits: u32,
    /// The relief step of the window (0: not late).
    pub relief_step: u64,
    /// First time with the next step's (easier) bits, `None` without stall
    /// relief at this height.
    pub next_bits_time: Option<u64>,
}

/// [`TimeWindow`] of a job from `tmpl` cut on a node whose clock reads `now`.
pub fn time_window(tmpl: &BlockTemplate, now: u64) -> TimeWindow {
    let parent = tmpl.parent_timestamp;
    let curtime = now.max(parent).min(u32::MAX as u64);
    let liveness_height = core::liveness::liveness_activation_height();
    let bits = core::liveness::relieve_at(tmpl.bits, parent, tmpl.height, curtime, tmpl.activation_height,
                                          liveness_height);
    let future = now.saturating_add(core::MAX_FUTURE_SECS).min(u32::MAX as u64);
    if !core::activation::is_active_at(tmpl.height, liveness_height) {
        return TimeWindow { curtime, mintime: parent, maxtime: future.max(curtime), bits, relief_step: 0,
                            next_bits_time: None };
    }
    let p = core::liveness::OBENBLOCK_STALL_RELIEF;
    let as_i64 = |t: u64| i64::try_from(t).unwrap_or(i64::MAX);
    let k = gnb_smh::stall_relief::relief_steps(&p, as_i64(parent), as_i64(curtime));
    let (grace, step) = (p.grace_secs as u64, p.step_secs as u64);
    let lo = if k == 0 { parent } else { parent.saturating_add(grace).saturating_add(k.saturating_mul(step)) };
    let next = parent.saturating_add(grace).saturating_add(k.saturating_add(1).saturating_mul(step));
    TimeWindow {
        curtime,
        mintime: lo.max(parent),
        // `curtime <= now <= future` and `curtime < next`, so the window
        // always holds `curtime`.
        maxtime: next.saturating_sub(1).min(future).max(curtime),
        bits,
        relief_step: k,
        next_bits_time: Some(next),
    }
}

/// The `sha256d` object of `getblocktemplate` (`Value::Null` under GnB-SMH):
/// the 80-byte header fields of `tmpl`, the time window, and a header job
/// when `request` (the call's params) asks for one ([`header_job_request`]).
/// `bits` and `target` are those of `curtime` (stall relief applied, the
/// same as the top-level `bits` and the header job's); `asert_bits` is the
/// template's ASERT value before relief.
pub fn template_fields(tmpl: &BlockTemplate, request: Option<&Value>, now: u64) -> Result<Value, String> {
    let Some(params) = pow_scheme::node_sha256d_params() else { return Ok(Value::Null) };
    let job = match header_job_request(request)? {
        None => Value::Null,
        Some((spk, extranonce)) => {
            let extranonce = extranonce.unwrap_or_else(rand::random);
            header_job(tmpl, &params, &spk, extranonce, now)?.to_json()
        }
    };
    let commitment = sha256d::parents_commitment(&tmpl.parents);
    let mut display = commitment;
    display.reverse();
    let rule = merkle_rule(tmpl).unwrap_or("unsupported");
    let w = time_window(tmpl, now);
    Ok(json!({
        "header_layout": "u32le version | parents_commitment[32] | merkle_root[32] | u32le time | u32le bits | u32le nonce",
        "version": params.block_version,
        "version_rolling_mask": format!("{:08x}", sha256d::BIP320_VERSION_MASK),
        // In header byte order; `previousblockhash` is the same 32 bytes
        // reversed, the order Bitcoin's getblocktemplate displays.
        "parents_commitment": hex::encode(commitment),
        "previousblockhash": hex::encode(display),
        "bits": format!("{:08x}", w.bits),
        "target": hex::encode(core::bits_to_target(w.bits)),
        "asert_bits": format!("{:08x}", tmpl.bits),
        "curtime": w.curtime,
        "mintime": w.mintime,
        "maxtime": w.maxtime,
        "relief_step": w.relief_step,
        "next_bits_time": w.next_bits_time,
        "noncerange": "00000000ffffffff",
        "merkle_root_rule": rule,
        "merkle_branch": merkle_branch(tmpl).iter().map(hex::encode).collect::<Vec<_>>(),
        "extranonce_bytes": EXTRANONCE_LEN,
        "header_job": job,
    }))
}

/// A header-job request: the coinbase `script_pubkey` and, optionally, the
/// extranonce.
pub type HeaderJobRequest = (Vec<u8>, Option<[u8; EXTRANONCE_LEN]>);

/// The header-job request of a `getblocktemplate` call, if any:
/// `params[0].header_job = {"coinbase_script_pubkey": hex, "extranonce": hex}`
/// (`extranonce` optional, exactly [`EXTRANONCE_LEN`] bytes; the node picks a
/// random one without it). Any other shape of `header_job` is an error.
pub fn header_job_request(params: Option<&Value>) -> Result<Option<HeaderJobRequest>, String> {
    let Some(req) = params.and_then(|p| p.get(0)).and_then(|o| o.get("header_job")) else { return Ok(None) };
    let obj = req.as_object().ok_or("header_job must be an object")?;
    if let Some(k) = obj.keys().find(|k| *k != "coinbase_script_pubkey" && *k != "extranonce") {
        return Err(format!("header_job: unknown field {k:?}"));
    }
    let spk = obj.get("coinbase_script_pubkey").and_then(Value::as_str)
        .ok_or("header_job.coinbase_script_pubkey (hex) is required")?;
    let spk = hex::decode(spk).map_err(|_| "header_job.coinbase_script_pubkey: invalid hex")?;
    let extranonce = match obj.get("extranonce") {
        None => None,
        Some(v) => Some(parse_extranonce(v).map_err(|e| format!("header_job.{e}"))?),
    };
    Ok(Some((spk, extranonce)))
}

fn parse_extranonce(v: &Value) -> Result<[u8; EXTRANONCE_LEN], String> {
    let b = v.as_str().and_then(|s| hex::decode(s).ok()).ok_or("extranonce: invalid hex")?;
    <[u8; EXTRANONCE_LEN]>::try_from(b.as_slice()).map_err(|_| format!("extranonce must be {EXTRANONCE_LEN} bytes"))
}

/// A complete candidate block for a pool: nonce 0, the scheme's block
/// version, and a coinbase that pays `tmpl.coinbase_outputs` to the pool's
/// script with `commitment ‖ COINBASE_TAG ‖ extranonce` as its `script_sig`.
#[derive(Clone, Debug)]
pub struct HeaderJob {
    pub block: Block,
    pub header: [u8; sha256d::POW_HEADER_LEN],
    /// Coinbase wire bytes (`Transaction::to_wire_bytes(true)`, which the
    /// txid hashes) before the extranonce.
    pub coinb1: Vec<u8>,
    /// Coinbase wire bytes after the extranonce.
    pub coinb2: Vec<u8>,
    pub extranonce: [u8; EXTRANONCE_LEN],
    /// Siblings of the coinbase in Bitcoin's tree, bottom-up.
    pub merkle_branch: Vec<[u8; 32]>,
    /// The `ntime` window that keeps `block.header.bits`.
    pub window: TimeWindow,
}

/// Stratum's `prevhash` encoding of 32 header bytes: each 4-byte word
/// byte-reversed (the order stock firmware swaps back into the header).
pub fn stratum_prevhash(header_bytes: &[u8; 32]) -> String {
    let mut out = [0u8; 32];
    for (dst, src) in out.chunks_exact_mut(4).zip(header_bytes.chunks_exact(4)) {
        dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
    }
    hex::encode(out)
}

impl HeaderJob {
    pub fn to_json(&self) -> Value {
        json!({
            "header": hex::encode(self.header),
            "block": hex::encode(self.block.to_wire_bytes()),
            "merkle_root": hex::encode(self.block.header.merkle_root.0),
            "time": self.block.header.timestamp,
            "bits": format!("{:08x}", self.block.header.bits),
            "mintime": self.window.mintime,
            "maxtime": self.window.maxtime,
            "coinb1": hex::encode(&self.coinb1),
            "coinb2": hex::encode(&self.coinb2),
            "extranonce": hex::encode(self.extranonce),
            "merkle_branch": self.merkle_branch.iter().map(hex::encode).collect::<Vec<_>>(),
            "coinbase_txid": hex::encode(self.block.transactions[0].txid()),
            "stratum": self.stratum_json(),
        })
    }

    /// The parameters of a Stratum V1 `mining.notify` for this job, in
    /// stratum's encodings (docs/OBENBLOCK-MINING.md §4.1): `prevhash`
    /// word-swapped, `version` / `nbits` / `ntime` as big-endian hex of the
    /// u32, `merkle_branch` in hashing byte order, and the extranonce size
    /// the pool splits into `extranonce1` (`mining.subscribe`) and
    /// `extranonce2_size`.
    pub fn stratum_json(&self) -> Value {
        let mut prev = [0u8; 32];
        prev.copy_from_slice(&self.header[4..36]);
        json!({
            "prevhash": stratum_prevhash(&prev),
            "coinb1": hex::encode(&self.coinb1),
            "coinb2": hex::encode(&self.coinb2),
            "merkle_branch": self.merkle_branch.iter().map(hex::encode).collect::<Vec<_>>(),
            "version": format!("{:08x}", self.block.header.version),
            "nbits": format!("{:08x}", self.block.header.bits),
            "ntime": format!("{:08x}", self.block.header.timestamp),
            "extranonce_size": EXTRANONCE_LEN,
            "ntime_min": self.window.mintime,
            "ntime_max": self.window.maxtime,
            "version_rolling_mask": format!("{:08x}", sha256d::BIP320_VERSION_MASK),
        })
    }
}

/// Build the [`HeaderJob`] of `tmpl` paying `script_pubkey` (an output kind
/// the chain accepts, `core::policy::output_kind`) with `extranonce`, for a
/// node whose clock reads `now` (the job's time is the window's `curtime`).
/// Runs the template self-check (`template::assemble_block`) and checks that
/// the coinbase split and [`header_merkle_root`] reproduce the block's own
/// txid and root.
pub fn header_job(
    tmpl: &BlockTemplate,
    params: &Sha256dParams,
    script_pubkey: &[u8],
    extranonce: [u8; EXTRANONCE_LEN],
    now: u64,
) -> Result<HeaderJob, String> {
    merkle_rule(tmpl)?;
    if script_pubkey.len() > template::EXTERNAL_COINBASE_MAX_SPK || core::policy::output_kind(script_pubkey).is_none() {
        return Err(format!(
            "coinbase script_pubkey ({} bytes) is not a supported output (a 20-byte key hash or a 33-byte spend policy)",
            script_pubkey.len()));
    }
    sha256d::check_parents(&tmpl.parents, core::MAX_PARENTS)
        .map_err(|e| format!("template parents are not in SHA-256d header order: {e}"))?;
    let window = time_window(tmpl, now);
    let mut script_sig = COINBASE_TAG.to_vec();
    script_sig.extend_from_slice(&extranonce);
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
        outputs: tmpl.coinbase_outputs(script_pubkey.to_vec()),
        locktime: 0,
    };
    let mut block = template::assemble_block(tmpl, coinbase, window.curtime)?;
    block.header.version = params.block_version;
    if block.header.bits != window.bits {
        return Err("internal: job bits differ from the time window's".into());
    }
    let header = block.header.sha256d_pow_bytes().map_err(|e| format!("header does not fit 80 bytes: {e}"))?;
    let (coinb1, coinb2) = split_coinbase(&block.transactions[0])?;
    let txid = block.transactions[0].txid();
    let mut joined = coinb1.clone();
    joined.extend_from_slice(&extranonce);
    joined.extend_from_slice(&coinb2);
    if sha256d::sha256d(&joined) != txid {
        return Err("internal: coinbase split does not reproduce the coinbase txid".into());
    }
    if header_merkle_root(tmpl, &txid)? != block.header.merkle_root {
        return Err("internal: header_merkle_root differs from the block's header root".into());
    }
    Ok(HeaderJob { block, header, coinb1, coinb2, extranonce, merkle_branch: merkle_branch(tmpl), window })
}

/// Split the wire bytes of a header-job coinbase (its `script_sig` ending in
/// the extranonce) around the extranonce: the bytes that change when only
/// the extranonce changes must be one run of exactly [`EXTRANONCE_LEN`]
/// bytes.
fn split_coinbase(cb: &Transaction) -> Result<(Vec<u8>, Vec<u8>), String> {
    let a = cb.to_wire_bytes(true);
    let mut alt = cb.clone();
    let ss = &mut alt.inputs.first_mut().ok_or("coinbase has no input")?.script_sig;
    if ss.len() < EXTRANONCE_LEN {
        return Err("coinbase script_sig shorter than the extranonce".into());
    }
    let n = ss.len();
    for b in &mut ss[n - EXTRANONCE_LEN..] {
        *b ^= 0xFF;
    }
    let b = alt.to_wire_bytes(true);
    let diff: Vec<usize> = (0..a.len().min(b.len())).filter(|&i| a[i] != b[i]).collect();
    let (Some(&first), Some(&last)) = (diff.first(), diff.last()) else {
        return Err("internal: extranonce not found in the coinbase".into());
    };
    if a.len() != b.len() || diff.len() != EXTRANONCE_LEN || last - first + 1 != EXTRANONCE_LEN {
        return Err("internal: extranonce is not one contiguous run of the coinbase".into());
    }
    Ok((a[..first].to_vec(), a[first + EXTRANONCE_LEN..].to_vec()))
}

/// The header fields a share rolls, and the extranonce of a stratum share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderSolution {
    pub version: u32,
    pub time: u32,
    pub nonce: u32,
    /// `extranonce1 ‖ extranonce2` of the share (`None`: the job's own).
    pub extranonce: Option<[u8; EXTRANONCE_LEN]>,
}

/// Parse `{"version": u32, "time": u32, "nonce": u32[, "extranonce": hex]}`
/// (the first three required, no other field).
pub fn parse_solution(v: &Value) -> Result<HeaderSolution, String> {
    let obj = v.as_object().ok_or("solution must be an object {version, time, nonce[, extranonce]}")?;
    if let Some(k) = obj.keys().find(|k| !matches!(k.as_str(), "version" | "time" | "nonce" | "extranonce")) {
        return Err(format!("solution: unknown field {k:?}"));
    }
    let field = |name: &str| -> Result<u32, String> {
        obj.get(name).and_then(Value::as_u64).and_then(|x| u32::try_from(x).ok())
            .ok_or_else(|| format!("solution.{name} must be an integer in 0..=4294967295"))
    };
    let extranonce = match obj.get("extranonce") {
        None => None,
        Some(v) => Some(parse_extranonce(v).map_err(|e| format!("solution.{e}"))?),
    };
    Ok(HeaderSolution { version: field("version")?, time: field("time")?, nonce: field("nonce")?, extranonce })
}

/// `submitblock`'s optional second parameter under the SHA-256d scheme:
/// write the share's rolled `version`, `time` and `nonce` into `block` (the
/// block of its header job) and, with `extranonce`, replace the last
/// [`EXTRANONCE_LEN`] bytes of the coinbase `script_sig` (which must follow
/// [`COINBASE_TAG`], as in every header job) and recompute the header root.
/// The block is then judged as any other. Under GnB-SMH, or with no second
/// parameter (or `null`), the block is unchanged.
pub fn apply_submit_solution(block: &mut Block, solution: Option<&Value>) -> Result<(), String> {
    if pow_scheme::node_sha256d_params().is_none() {
        return Ok(());
    }
    let Some(v) = solution.filter(|v| !v.is_null()) else { return Ok(()) };
    let s = parse_solution(v)?;
    if let Some(en) = s.extranonce {
        let ss = &mut block.transactions.first_mut().and_then(|cb| cb.inputs.first_mut())
            .ok_or("solution.extranonce: the block has no coinbase input")?.script_sig;
        let n = ss.len();
        if n < COINBASE_TAG.len() + EXTRANONCE_LEN || &ss[n - EXTRANONCE_LEN - COINBASE_TAG.len()..n - EXTRANONCE_LEN] != COINBASE_TAG {
            return Err("solution.extranonce: the coinbase is not a header job's (no /obb/ extranonce)".into());
        }
        ss[n - EXTRANONCE_LEN..].copy_from_slice(&en);
        block.header.merkle_root = block.body_merkle_root();
    }
    block.header.version = s.version;
    block.header.timestamp = s.time as u64;
    block.header.nonce = s.nonce as u64;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solution_parsing_is_strict() {
        let ok = json!({"version": 0x2000_2000u32, "time": 1_800_000_000u32, "nonce": 7});
        assert_eq!(parse_solution(&ok), Ok(HeaderSolution { version: 0x2000_2000, time: 1_800_000_000, nonce: 7, extranonce: None }));
        let en = json!({"version": 1, "time": 2, "nonce": 3, "extranonce": "0001020304050607"});
        assert_eq!(parse_solution(&en).unwrap().extranonce, Some([0, 1, 2, 3, 4, 5, 6, 7]));
        for bad in [
            json!({"version": 1, "time": 2}),
            json!({"version": 1, "time": 2, "nonce": 4_294_967_296u64}),
            json!({"version": -1, "time": 2, "nonce": 3}),
            json!({"version": "1", "time": 2, "nonce": 3}),
            json!({"version": 1, "time": 2, "nonce": 3, "extra": 0}),
            json!({"version": 1, "time": 2, "nonce": 3, "extranonce": "00"}),
            json!([1, 2, 3]),
        ] {
            assert!(parse_solution(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn stratum_prevhash_swaps_each_word() {
        // slush's stratum example: display hash
        // 00000000440b921e1b77c6c0487ae5616de67f788f44ae2a5af6e2194d16b6f8.
        let mut header_order: [u8; 32] =
            hex::decode("00000000440b921e1b77c6c0487ae5616de67f788f44ae2a5af6e2194d16b6f8").unwrap().try_into().unwrap();
        header_order.reverse();
        assert_eq!(stratum_prevhash(&header_order), "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000");
    }

    #[test]
    fn header_job_requests_are_strict() {
        assert_eq!(header_job_request(None), Ok(None));
        assert_eq!(header_job_request(Some(&json!([]))), Ok(None));
        assert_eq!(header_job_request(Some(&json!([{"rules": ["segwit"]}]))), Ok(None));
        let spk = "00".repeat(20);
        assert_eq!(header_job_request(Some(&json!([{"header_job": {"coinbase_script_pubkey": spk}}]))),
            Ok(Some((vec![0; 20], None))));
        assert_eq!(header_job_request(Some(&json!([{"header_job": {"coinbase_script_pubkey": spk, "extranonce": "0102030405060708"}}]))),
            Ok(Some((vec![0; 20], Some([1, 2, 3, 4, 5, 6, 7, 8])))));
        for bad in [
            json!([{"header_job": "x"}]),
            json!([{"header_job": {}}]),
            json!([{"header_job": {"coinbase_script_pubkey": "zz"}}]),
            json!([{"header_job": {"coinbase_script_pubkey": spk, "extranonce": "01"}}]),
            json!([{"header_job": {"coinbase_script_pubkey": spk, "other": 1}}]),
        ] {
            assert!(header_job_request(Some(&bad)).is_err(), "{bad}");
        }
    }

    /// The lib test binary runs GnB-SMH: the SHA-256d interface is inert.
    #[test]
    fn inert_under_gnb_smh() {
        let mut b = core::genesis_block();
        let before = b.clone();
        apply_submit_solution(&mut b, Some(&json!({"version": 9, "time": 9, "nonce": 9}))).unwrap();
        apply_submit_solution(&mut b, Some(&json!("garbage"))).unwrap();
        assert_eq!(b.block_hash(), before.block_hash());
    }
}
