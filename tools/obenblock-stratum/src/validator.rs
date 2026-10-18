//! Share validation: the 80-byte ObenBlock header of a share, its id and the
//! targets it meets, computed exactly as the node computes them.
//!
//! ```text
//! coinbase      = coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2      (8 extranonce bytes)
//! coinbase_txid = SHA-256d(coinbase)
//! tx_root       = cur = leaf(coinbase_txid); cur = node(cur, s) for s in branch
//!                 leaf(x) = tagged("GnB/merkle/leaf", x), node(l, r) = tagged("GnB/merkle/node", l ‖ r)
//!                 tagged(t, m) = SHA-256(SHA-256(t) ‖ SHA-256(t) ‖ m)
//! merkle_root   = SHA3-256("gnb:block:body:v2" ‖ tx_root ‖ shielded_root ‖ powit_root)   (gnb-body-v2)
//!               = tx_root                                                              (gnb-tagged-v1)
//! header        = u32le(version) ‖ parents_commitment ‖ merkle_root ‖ u32le(time) ‖ u32le(bits) ‖ u32le(nonce)
//! block_id      = SHA-256d(header);  valid  <=>  le256(block_id) <= target(bits)
//! ```
//!
//! (docs/OBENBLOCK-MINING.md §1 and §3.3; `reference/obb_job.py` is the
//! executable reference, and the tests below recompute its vectors,
//! `reference/obb_job_vectors.json`.)
//!
//! The header, id, target decoding and the comparison are the node's own
//! functions (`gnb_smh::sha256d`, `gnb_smh::difficulty`), linked, not
//! copied. Only the Merkle root rule, which lives in the node crate, is
//! restated here, and the vector test pins it.
//!
//! The root is NOT Bitcoin's SHA-256d transaction tree. Unmodified Stratum V1
//! firmware builds Bitcoin's tree from `coinb1 ‖ extranonce ‖ coinb2` and the
//! branch, so its headers are never ObenBlock blocks;
//! [`bitcoin_merkle_root`] exists only to recognize (and count) such work.

use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

pub use gnb_smh::difficulty::{bits_to_target, Target};
pub use gnb_smh::sha256d::{block_id, meets_target, sha256d, BIP320_VERSION_MASK, POW_HEADER_LEN};

const LEAF_TAG: &[u8] = b"GnB/merkle/leaf";
const NODE_TAG: &[u8] = b"GnB/merkle/node";
const BODY_V2_TAG: &[u8] = b"gnb:block:body:v2";

/// How the header root is derived from the coinbase txid
/// (`getblocktemplate` `sha256d.merkle_root_rule`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootRule {
    /// `gnb-body-v2` (ObenBlock: PoWit active from genesis).
    BodyV2,
    /// `gnb-tagged-v1`.
    TaggedV1,
}

impl RootRule {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "gnb-body-v2" => Some(RootRule::BodyV2),
            "gnb-tagged-v1" => Some(RootRule::TaggedV1),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            RootRule::BodyV2 => "gnb-body-v2",
            RootRule::TaggedV1 => "gnb-tagged-v1",
        }
    }
}

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The header Merkle root of a block whose coinbase txid is `coinbase_txid`.
pub fn merkle_root(
    rule: RootRule,
    coinbase_txid: &[u8; 32],
    branch: &[[u8; 32]],
    shielded_root: &[u8; 32],
    powit_root: &[u8; 32],
) -> [u8; 32] {
    let mut cur = tagged(LEAF_TAG, &[coinbase_txid]);
    for s in branch {
        cur = tagged(NODE_TAG, &[&cur, s]);
    }
    match rule {
        RootRule::TaggedV1 => cur,
        RootRule::BodyV2 => {
            let mut h = Sha3_256::new();
            h.update(BODY_V2_TAG);
            h.update(cur);
            h.update(shielded_root);
            h.update(powit_root);
            h.finalize().into()
        }
    }
}

/// Bitcoin's root (coinbase at position 0, SHA-256d nodes): what unmodified
/// Stratum V1 firmware puts in the header. Diagnostics only.
pub fn bitcoin_merkle_root(coinbase_txid: &[u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
    let mut h = *coinbase_txid;
    for s in branch {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&h);
        buf[32..].copy_from_slice(s);
        h = sha256d(&buf);
    }
    h
}

/// The 80-byte proof-of-work header.
pub fn header80(version: u32, parents_commitment: &[u8; 32], merkle_root: &[u8; 32], time: u32, bits: u32, nonce: u32)
    -> [u8; POW_HEADER_LEN]
{
    let mut h = [0u8; POW_HEADER_LEN];
    h[0..4].copy_from_slice(&version.to_le_bytes());
    h[4..36].copy_from_slice(parents_commitment);
    h[36..68].copy_from_slice(merkle_root);
    h[68..72].copy_from_slice(&time.to_le_bytes());
    h[72..76].copy_from_slice(&bits.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

/// The version a share's header carries: the job's version outside `mask`,
/// the miner's rolled bits inside it (BIP 310 / BIP 320). Without rolled bits
/// the job's version.
pub fn effective_version(job_version: u32, mask: u32, rolled: Option<u32>) -> u32 {
    match rolled {
        Some(v) => (job_version & !mask) | (v & mask),
        None => job_version,
    }
}

/// Stratum's `prevhash` encoding: the 32 header bytes with each 4-byte word
/// reversed (word order kept). Its own inverse.
pub fn stratum_word_swap(b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        for k in 0..4 {
            out[i * 4 + k] = b[i * 4 + 3 - k];
        }
    }
    out
}

/// Pool difficulty to target: `diff1 / difficulty` with diff1 the target of
/// `0x1d00ffff` (Bitcoin's difficulty 1), in fixed-point millionths, as the
/// Bloch pool did. Big-endian, the order of [`Target`].
pub fn difficulty_to_target(diff: f64) -> Target {
    use primitive_types::U256;
    let scaled = (diff.max(f64::MIN_POSITIVE) * 1_000_000.0).round();
    let d: u128 = if scaled.is_finite() && scaled >= 1.0 { scaled.min(u128::MAX as f64) as u128 } else { 1 };
    let diff1 = U256::from_big_endian(&bits_to_target(0x1d00_ffff).0);
    let t = diff1.saturating_mul(U256::from(1_000_000u64)) / U256::from(d.max(1));
    Target(t.to_big_endian())
}

/// The difficulty a block id achieved: `diff1 / le256(id)`.
pub fn id_difficulty(id: &[u8; 32]) -> f64 {
    let mut be = *id;
    be.reverse();
    let hv = be_to_f64(&be);
    if hv <= 0.0 {
        return f64::INFINITY;
    }
    be_to_f64(&bits_to_target(0x1d00_ffff).0) / hv
}

/// The difficulty of a target: `diff1 / target`.
pub fn target_difficulty(t: &Target) -> f64 {
    let v = be_to_f64(&t.0);
    if v <= 0.0 {
        return f64::INFINITY;
    }
    be_to_f64(&bits_to_target(0x1d00_ffff).0) / v
}

fn be_to_f64(be: &[u8; 32]) -> f64 {
    be.iter().fold(0.0f64, |f, &b| f * 256.0 + b as f64)
}

// ── SHA-256 midstate (the CPU miner's inner loop) ─────────────────────────

const H0: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

/// SHA-256 state after the first 64 header bytes.
pub fn midstate(header: &[u8; POW_HEADER_LEN]) -> [u32; 8] {
    let mut state = H0;
    sha2::compress256(&mut state, &[*GenericArray::from_slice(&header[..64])]);
    state
}

/// Second-block template for the last 16 header bytes: the bytes, the
/// padding and the 640-bit length. Bytes 12..16 are the nonce.
pub fn tail_block(header: &[u8; POW_HEADER_LEN]) -> [u8; 64] {
    let mut b = [0u8; 64];
    b[..16].copy_from_slice(&header[64..80]);
    b[16] = 0x80;
    b[56..64].copy_from_slice(&(640u64).to_be_bytes());
    b
}

/// `SHA-256d(header)` from its midstate and tail block (nonce already set).
/// Equal to [`block_id`] of the header.
pub fn id_from_midstate(mid: &[u32; 8], tail: &[u8; 64]) -> [u8; 32] {
    let mut s1 = *mid;
    sha2::compress256(&mut s1, &[*GenericArray::from_slice(tail)]);
    let mut b2 = [0u8; 64];
    for (i, w) in s1.iter().enumerate() {
        b2[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    b2[32] = 0x80;
    b2[56..64].copy_from_slice(&(256u64).to_be_bytes());
    let mut s2 = H0;
    sha2::compress256(&mut s2, &[*GenericArray::from_slice(&b2)]);
    let mut out = [0u8; 32];
    for (i, w) in s2.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../../reference/obb_job_vectors.json");

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// Every case and share of `reference/obb_job_vectors.json` (produced by
    /// the node's test `obb_sha256d_mining`, recomputed by
    /// `reference/obb_job_test.py`): coinbase txid, Merkle root, header,
    /// block id and the target verdict.
    #[test]
    fn reproduces_the_node_job_vectors() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(v["extranonce_bytes"].as_u64(), Some(8));
        assert_eq!(v["bip320_mask"].as_u64(), Some(BIP320_VERSION_MASK as u64));
        let cases = v["cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        let mut shares = 0;
        for case in cases {
            let job = &case["job"];
            let parents: Vec<[u8; 32]> = case["parents"].as_array().unwrap().iter().map(|p| h32(p.as_str().unwrap())).collect();
            let commitment = gnb_smh::sha256d::parents_commitment(&parents);
            let mut cb = hex::decode(job["coinb1"].as_str().unwrap()).unwrap();
            cb.extend(hex::decode(job["extranonce"].as_str().unwrap()).unwrap());
            cb.extend(hex::decode(job["coinb2"].as_str().unwrap()).unwrap());
            let txid = sha256d(&cb);
            assert_eq!(hex::encode(txid), case["expect"]["coinbase_txid"].as_str().unwrap(), "{}", case["name"]);
            let branch: Vec<[u8; 32]> =
                job["coinbase_merkle_branch"].as_array().unwrap().iter().map(|b| h32(b.as_str().unwrap())).collect();
            let rule = RootRule::parse(job["merkle_root_rule"].as_str().unwrap()).unwrap();
            let root = merkle_root(rule, &txid, &branch, &h32(job["shielded_root"].as_str().unwrap()),
                                   &h32(job["powit_root"].as_str().unwrap()));
            assert_eq!(hex::encode(root), case["expect"]["merkle_root"].as_str().unwrap(), "{}", case["name"]);
            let bits = job["bits"].as_u64().unwrap() as u32;
            let header = header80(job["version"].as_u64().unwrap() as u32, &commitment, &root,
                                  job["time"].as_u64().unwrap() as u32, bits, 0);
            assert_eq!(hex::encode(header), case["expect"]["header"].as_str().unwrap(), "{}", case["name"]);
            for s in case["shares"].as_array().unwrap() {
                let h = header80(s["version"].as_u64().unwrap() as u32, &commitment, &root,
                                 s["time"].as_u64().unwrap() as u32, bits, s["nonce"].as_u64().unwrap() as u32);
                assert_eq!(hex::encode(h), s["header"].as_str().unwrap());
                let id = block_id(&h);
                assert_eq!(hex::encode(id), s["block_id"].as_str().unwrap());
                assert_eq!(meets_target(&id, &bits_to_target(bits)), s["meets_target"].as_bool().unwrap());
                // The midstate path computes the same id.
                let mut tail = tail_block(&h);
                tail[12..16].copy_from_slice(&h[76..80]);
                assert_eq!(id_from_midstate(&midstate(&h), &tail), id);
                shares += 1;
            }
        }
        assert!(shares > 0);
    }

    #[test]
    fn bitcoin_root_differs_from_the_obenblock_root() {
        let txid = [7u8; 32];
        let branch = [[9u8; 32]];
        let btc = bitcoin_merkle_root(&txid, &branch);
        assert_ne!(btc, merkle_root(RootRule::BodyV2, &txid, &branch, &[0; 32], &[0; 32]));
        assert_ne!(btc, merkle_root(RootRule::TaggedV1, &txid, &branch, &[0; 32], &[0; 32]));
        assert_eq!(bitcoin_merkle_root(&txid, &[]), txid, "empty branch: the root is the txid");
    }

    #[test]
    fn difficulty_one_is_the_diff1_target() {
        assert_eq!(difficulty_to_target(1.0), bits_to_target(0x1d00_ffff));
        assert!(difficulty_to_target(1024.0) < difficulty_to_target(1.0));
        assert!((target_difficulty(&difficulty_to_target(4096.0)) - 4096.0).abs() < 1e-6);
        // Absurd inputs saturate instead of panicking.
        let _ = difficulty_to_target(f64::INFINITY);
        let _ = difficulty_to_target(f64::NAN);
        let _ = difficulty_to_target(0.0);
    }

    #[test]
    fn id_difficulty_agrees_with_meets_target() {
        let t = difficulty_to_target(1e-6);
        let td = target_difficulty(&t);
        let mut found = 0;
        for nonce in 0u32..20_000 {
            let id = block_id(&header80(0x2000_0000, &[1; 32], &[2; 32], 1_800_000_000, 0x207f_ffff, nonce));
            if meets_target(&id, &t) {
                assert!(id_difficulty(&id) + 1e-12 >= td);
                found += 1;
            } else {
                assert!(id_difficulty(&id) <= td * (1.0 + 1e-9));
            }
        }
        assert!(found > 0);
    }

    #[test]
    fn version_rolling_stays_inside_the_mask() {
        assert_eq!(effective_version(0x2000_0000, BIP320_VERSION_MASK, None), 0x2000_0000);
        assert_eq!(effective_version(0x2000_0000, BIP320_VERSION_MASK, Some(0x0000_6000)), 0x2000_6000);
        // Bits outside the mask never reach the header.
        assert_eq!(effective_version(0x2000_0000, BIP320_VERSION_MASK, Some(0xffff_ffff)), 0x3fff_e000);
        assert!(gnb_smh::sha256d::version_ok(effective_version(0x2000_0000, BIP320_VERSION_MASK, Some(u32::MAX)), 0x2000_0000));
        // A narrower negotiated mask.
        assert_eq!(effective_version(0x2000_0000, 0x0000_e000, Some(0x1fff_e000)), 0x2000_e000);
    }

    #[test]
    fn word_swap_is_an_involution() {
        let raw: [u8; 32] = core::array::from_fn(|i| i as u8);
        let once = stratum_word_swap(&raw);
        assert_eq!(&once[..4], &[3, 2, 1, 0]);
        assert_eq!(stratum_word_swap(&once), raw);
    }

    #[test]
    fn midstate_matches_plain_sha256d() {
        for nonce in [0u32, 1, 0xdead_beef, u32::MAX] {
            let h = header80(0x2000_4000, &[0xab; 32], &[0xcd; 32], 1_900_000_000, 0x1d00_ffff, nonce);
            let mut tail = tail_block(&h);
            tail[12..16].copy_from_slice(&nonce.to_le_bytes());
            assert_eq!(id_from_midstate(&midstate(&h), &tail), block_id(&h));
        }
    }
}
