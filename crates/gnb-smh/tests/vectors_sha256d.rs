//! Cross-implementation check of `gnb_smh::sha256d` against the normative
//! Python reference `reference/obb_pow.py`, through the vectors it generates
//! (`reference/obb_pow_vectors.json`): Bitcoin's own headers, the parent
//! commitment, chain work and the launch target.

use gnb_smh::difficulty::Target;
use gnb_smh::sha256d::{self, ParentsError, PowHeader, POW_HEADER_LEN};
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_pow_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn parents_of(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().unwrap().iter().map(h32).collect()
}

#[test]
fn bitcoin_headers() {
    let d = doc();
    let cases = d["bitcoin_headers"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for v in cases {
        let bytes: [u8; POW_HEADER_LEN] = hex::decode(v["header_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let header = PowHeader::from_bytes(&bytes);
        assert_eq!(header.to_bytes(), bytes);
        let mut id = sha256d::block_id(&bytes);
        assert_eq!(id, header.id());
        id.reverse();
        assert_eq!(hex::encode(id), v["id_display_hex"].as_str().unwrap(), "{}", v["name"]);
        assert_eq!(sha256d::verify_header(&bytes), v["valid"].as_bool().unwrap(), "{}", v["name"]);
    }
}

#[test]
fn parent_commitments_and_rules() {
    let d = doc();
    let max = d["constants"]["max_parents"].as_u64().unwrap() as usize;
    for v in d["parents"].as_array().unwrap() {
        let ps = parents_of(&v["parents"]);
        assert_eq!(sha256d::parents_commitment(&ps), h32(&v["commitment_hex"]));
        let want = match v["check"].as_str() {
            None => Ok(()),
            Some("TooMany") => Err(ParentsError::TooMany),
            Some("Duplicate") => Err(ParentsError::Duplicate),
            Some("NotSorted") => Err(ParentsError::NotSorted),
            Some(other) => panic!("unknown verdict {other}"),
        };
        assert_eq!(sha256d::check_parents(&ps, max), want);
    }
}

#[test]
fn chain_work() {
    let d = doc();
    let cases = d["work"].as_array().unwrap();
    assert!(cases.len() >= 50);
    for v in cases {
        let t = Target(h32(&v["target_hex"]));
        let want: u128 = v["work"].as_str().unwrap().parse().unwrap();
        assert_eq!(sha256d::work(&t), want, "target {}", v["target_hex"]);
    }
}

#[test]
fn launch_targets() {
    let d = doc();
    for v in d["target_for_hashes"].as_array().unwrap() {
        let rate: u128 = v["hashrate"].as_str().unwrap().parse().unwrap();
        let spacing = v["spacing"].as_u64().unwrap();
        assert_eq!(sha256d::target_for_hashes(rate, spacing), Target(h32(&v["target_hex"])), "{rate} x {spacing}");
    }
}

#[test]
fn dag_header_ids() {
    let d = doc();
    for v in d["headers"].as_array().unwrap() {
        let h = &v["header"];
        let (Ok(time), Ok(nonce)) = (u32::try_from(h["timestamp"].as_u64().unwrap()), u32::try_from(h["nonce"].as_u64().unwrap())) else {
            continue; // out-of-range ids are gnb-crypto's (`sha256d_block_id`)
        };
        let header = PowHeader {
            version: h["version"].as_u64().unwrap() as u32,
            parents_commitment: sha256d::parents_commitment(&parents_of(&h["parents"])),
            merkle_root: h32(&h["merkle_root_hex"]),
            time,
            bits: h["bits"].as_u64().unwrap() as u32,
            nonce,
        };
        assert_eq!(header.id(), h32(&v["block_id_hex"]), "{}", v["name"]);
    }
}
