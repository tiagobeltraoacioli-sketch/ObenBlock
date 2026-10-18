//! The SHA-256d pool interface of `getblocktemplate` and `submitblock`
//! (ObenBlock, docs/DESIGN-obenblock.md §4.1, docs/OBENBLOCK-MINING.md).
//!
//! A Bitcoin ASIC hashes the 80-byte header
//! `version ‖ parents_commitment ‖ merkle_root ‖ time ‖ bits ‖ nonce` and
//! rolls the nonce, the BIP 320 version bits and the time. The header's
//! `merkle_root` is this chain's body root, not Bitcoin's transaction tree,
//! so the job server (pool), not the ASIC, computes it from the coinbase
//! extranonce. This module gives a pool what it needs:
//!
//! * [`template_fields`]: the `sha256d` object of `getblocktemplate`, the
//!   header fields in their 80-byte order plus the inputs of the Merkle
//!   root (`shielded_root`, `powit_root`; `coinbase_merkle_branch` is a
//!   top-level field);
//! * [`header_job`]: on request (`getblocktemplate [{"header_job": {...}}]`),
//!   a complete candidate block paying a pool's script, its 80-byte header,
//!   and the coinbase split around an [`EXTRANONCE_LEN`]-byte extranonce
//!   (`coinb1 ‖ extranonce ‖ coinb2`, as in stratum), so a pool rolls the
//!   extranonce itself and recomputes the root with
//!   [`header_merkle_root`] (reference: `reference/obb_job.py`);
//! * [`apply_submit_solution`]: `submitblock [block_hex, {"version", "time",
//!   "nonce"}]` writes the three rolled header fields of a share into the
//!   block of its job before the usual submission path.
//!
//! Nothing here is consensus: a block is judged by the same acceptance path
//! whatever produced it. Under GnB-SMH (no SHA-256d scheme set)
//! [`template_fields`] is `null` and [`apply_submit_solution`] ignores its
//! argument, exactly as before.

use serde_json::{json, Value};
use sha3::{Digest as _, Sha3_256};

use crate::core::pow_scheme::{self, Sha256dParams};
use crate::core::{self, Block, MerkleRoot, Transaction, TxInput};
use crate::template::{self, BlockTemplate};
use gnb_smh::sha256d;

/// Bytes of the extranonce a header job's coinbase carries (stratum's
/// `extranonce1 ‖ extranonce2`, e.g. 4 + 4).
pub const EXTRANONCE_LEN: usize = 8;

/// Miner bytes of a header job's coinbase before the extranonce, after the
/// 80-byte coinbase commitment.
pub const COINBASE_TAG: &[u8] = b"/obb/";

/// Tag of the body root (`Block::body_merkle_root_at`, PoWit active).
const BODY_V2_TAG: &[u8] = b"gnb:block:body:v2";
/// Tag of the shielded section root (`Block::shielded_root`).
const SHIELDED_TAG: &[u8] = b"gnb:block:shielded:v1";

/// Root of an empty shielded section: templates carry no shielded
/// transactions.
pub fn empty_shielded_root() -> [u8; 32] {
    Sha3_256::digest(SHIELDED_TAG).into()
}

/// The rule a pool applies to compute the header Merkle root from the
/// coinbase txid, or why this template has none a pool can use.
fn merkle_rule(tmpl: &BlockTemplate) -> Result<&'static str, String> {
    if !tmpl.hardened {
        return Err("header jobs need the hardening block rules at the template height \
                    (ObenBlock applies them from genesis)".into());
    }
    if core::suffix_witness_commitment_required(tmpl.height) {
        return Err("header jobs are not offered where the coinbase carries the witness suffix".into());
    }
    Ok(if core::powit_active(tmpl.height) { "gnb-body-v2" } else { "gnb-tagged-v1" })
}

/// The header Merkle root of a block built from `tmpl` whose coinbase has
/// txid `coinbase_txid`: fold the txid through `coinbase_merkle_branch`
/// (tagged tree), then, where PoWit is active,
/// `SHA3-256("gnb:block:body:v2" ‖ tx_root ‖ shielded_root ‖ powit_root)`.
pub fn header_merkle_root(tmpl: &BlockTemplate, coinbase_txid: &[u8; 32]) -> Result<MerkleRoot, String> {
    let rule = merkle_rule(tmpl)?;
    let tx_root = core::block_rules::merkle_root_from_coinbase_branch(coinbase_txid, &tmpl.coinbase_merkle_branch(), true);
    if rule == "gnb-tagged-v1" {
        return Ok(tx_root);
    }
    let mut h = Sha3_256::new();
    h.update(BODY_V2_TAG);
    h.update(tx_root.0);
    h.update(empty_shielded_root());
    h.update(tmpl.powit.root());
    Ok(MerkleRoot(h.finalize().into()))
}

/// The `sha256d` object of `getblocktemplate` (`Value::Null` under GnB-SMH):
/// the 80-byte header fields of `tmpl`, the time window, the Merkle-root
/// inputs, and a header job when `request` (the call's params) asks for one
/// ([`header_job_request`]).
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
    let (rule, shielded_root, powit_root) = match merkle_rule(tmpl) {
        Ok(r) => (r, hex::encode(empty_shielded_root()), hex::encode(tmpl.powit.root())),
        Err(_) => ("unsupported", String::new(), String::new()),
    };
    let max_time = now.saturating_add(core::MAX_FUTURE_SECS).min(u32::MAX as u64);
    Ok(json!({
        "header_layout": "u32le version | parents_commitment[32] | merkle_root[32] | u32le time | u32le bits | u32le nonce",
        "version": params.block_version,
        "version_rolling_mask": format!("{:08x}", sha256d::BIP320_VERSION_MASK),
        // In header byte order; `previousblockhash` is the same 32 bytes
        // reversed, the order Bitcoin's getblocktemplate displays.
        "parents_commitment": hex::encode(commitment),
        "previousblockhash": hex::encode(display),
        "bits": format!("{:08x}", tmpl.bits),
        "target": hex::encode(core::bits_to_target(tmpl.bits)),
        "curtime": now.max(tmpl.parent_timestamp),
        "mintime": tmpl.parent_timestamp,
        "maxtime": max_time,
        "noncerange": "00000000ffffffff",
        "merkle_root_rule": rule,
        "shielded_root": shielded_root,
        "powit_root": powit_root,
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
        Some(v) => {
            let b = v.as_str().and_then(|s| hex::decode(s).ok())
                .ok_or("header_job.extranonce: invalid hex")?;
            Some(<[u8; EXTRANONCE_LEN]>::try_from(b.as_slice())
                .map_err(|_| format!("header_job.extranonce must be {EXTRANONCE_LEN} bytes"))?)
        }
    };
    Ok(Some((spk, extranonce)))
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
}

impl HeaderJob {
    pub fn to_json(&self) -> Value {
        json!({
            "header": hex::encode(self.header),
            "block": hex::encode(self.block.to_wire_bytes()),
            "merkle_root": hex::encode(self.block.header.merkle_root.0),
            "time": self.block.header.timestamp,
            "coinb1": hex::encode(&self.coinb1),
            "coinb2": hex::encode(&self.coinb2),
            "extranonce": hex::encode(self.extranonce),
            "coinbase_txid": hex::encode(self.block.transactions[0].txid()),
        })
    }
}

/// Build the [`HeaderJob`] of `tmpl` paying `script_pubkey` (an output kind
/// the chain accepts, `core::policy::output_kind`) with `extranonce`, stamped
/// `timestamp` (at least the template's parent time; must fit u32). Runs the
/// template self-check (`template::assemble_block`) and checks that the
/// coinbase split and [`header_merkle_root`] reproduce the block's own
/// txid and root.
pub fn header_job(
    tmpl: &BlockTemplate,
    params: &Sha256dParams,
    script_pubkey: &[u8],
    extranonce: [u8; EXTRANONCE_LEN],
    timestamp: u64,
) -> Result<HeaderJob, String> {
    merkle_rule(tmpl)?;
    if script_pubkey.len() > template::EXTERNAL_COINBASE_MAX_SPK || core::policy::output_kind(script_pubkey).is_none() {
        return Err(format!(
            "coinbase script_pubkey ({} bytes) is not a supported output (a 20-byte key hash or a 33-byte spend policy)",
            script_pubkey.len()));
    }
    sha256d::check_parents(&tmpl.parents, core::MAX_PARENTS)
        .map_err(|e| format!("template parents are not in SHA-256d header order: {e}"))?;
    let mut script_sig = COINBASE_TAG.to_vec();
    script_sig.extend_from_slice(&extranonce);
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
        outputs: tmpl.coinbase_outputs(script_pubkey.to_vec()),
        locktime: 0,
    };
    let mut block = template::assemble_block(tmpl, coinbase, timestamp)?;
    block.header.version = params.block_version;
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
        return Err("internal: header_merkle_root differs from the block's body root".into());
    }
    Ok(HeaderJob { block, header, coinb1, coinb2, extranonce })
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

/// The three header fields a share rolls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderSolution {
    pub version: u32,
    pub time: u32,
    pub nonce: u32,
}

/// Parse `{"version": u32, "time": u32, "nonce": u32}` (all three required,
/// no other field).
pub fn parse_solution(v: &Value) -> Result<HeaderSolution, String> {
    let obj = v.as_object().ok_or("solution must be an object {version, time, nonce}")?;
    if let Some(k) = obj.keys().find(|k| !matches!(k.as_str(), "version" | "time" | "nonce")) {
        return Err(format!("solution: unknown field {k:?}"));
    }
    let field = |name: &str| -> Result<u32, String> {
        obj.get(name).and_then(Value::as_u64).and_then(|x| u32::try_from(x).ok())
            .ok_or_else(|| format!("solution.{name} must be an integer in 0..=4294967295"))
    };
    Ok(HeaderSolution { version: field("version")?, time: field("time")?, nonce: field("nonce")? })
}

/// `submitblock`'s optional second parameter under the SHA-256d scheme:
/// write the share's rolled `version`, `time` and `nonce` into `block` (the
/// block of its header job). The block is then judged as any other. Under
/// GnB-SMH, or with no second parameter (or `null`), the block is unchanged.
pub fn apply_submit_solution(block: &mut Block, solution: Option<&Value>) -> Result<(), String> {
    if pow_scheme::node_sha256d_params().is_none() {
        return Ok(());
    }
    let Some(v) = solution.filter(|v| !v.is_null()) else { return Ok(()) };
    let s = parse_solution(v)?;
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
        assert_eq!(parse_solution(&ok), Ok(HeaderSolution { version: 0x2000_2000, time: 1_800_000_000, nonce: 7 }));
        for bad in [
            json!({"version": 1, "time": 2}),
            json!({"version": 1, "time": 2, "nonce": 4_294_967_296u64}),
            json!({"version": -1, "time": 2, "nonce": 3}),
            json!({"version": "1", "time": 2, "nonce": 3}),
            json!({"version": 1, "time": 2, "nonce": 3, "extra": 0}),
            json!([1, 2, 3]),
        ] {
            assert!(parse_solution(&bad).is_err(), "{bad}");
        }
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
