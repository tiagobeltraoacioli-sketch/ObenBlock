//! The ObenBlock anchor record against the Python reference
//! (`reference/obb_anchor.py` -> `reference/obb_anchor_vectors.json`):
//! witness-set digests, record encodings and ids, and the records decoding
//! refuses (docs/OBB-ANCHOR.md).

use gnb_crypto::obb_anchor::{self, AnchorRecord, KeyId, RECORD_LEN, W_DIGEST_TAG};
use serde_json::Value;

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_anchor_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

#[test]
fn constants_match_the_reference() {
    let d = doc();
    assert_eq!(d["format"], "obb-anchor-v1");
    assert_eq!(d["record_len"].as_u64().unwrap() as usize, RECORD_LEN);
    assert_eq!(d["w_digest_tag"].as_str().unwrap().as_bytes(), W_DIGEST_TAG);
}

#[test]
fn witness_set_digests_match_the_reference() {
    let d = doc();
    let cases = d["w_digest"].as_array().unwrap();
    assert!(cases.len() >= 4);
    for c in cases {
        let set: Vec<(KeyId, u128)> = c["set"].as_array().unwrap().iter().map(|e| {
            let k: KeyId = bytes(&e["key"]).try_into().unwrap();
            (k, e["weight"].as_str().unwrap().parse::<u128>().unwrap())
        }).collect();
        assert_eq!(obb_anchor::w_digest(&set).unwrap(), h32(&c["digest"]), "{}", c["name"]);
    }
}

#[test]
fn records_match_the_reference() {
    let d = doc();
    for c in d["records"].as_array().unwrap() {
        let r = AnchorRecord {
            chain_id: c["chain_id"].as_u64().unwrap() as u32,
            slot: c["slot"].as_u64().unwrap(),
            block_id: h32(&c["block_id"]),
            finalized_at: c["finalized_at"].as_u64().unwrap(),
            w_digest: h32(&c["w_digest"]),
        };
        let raw = bytes(&c["record"]);
        assert_eq!(r.encode().as_slice(), raw.as_slice(), "{}", c["name"]);
        assert_eq!(AnchorRecord::decode(&raw).unwrap(), r, "{}", c["name"]);
        assert_eq!(r.record_id(), h32(&c["record_id"]), "{}", c["name"]);
    }
}

#[test]
fn invalid_records_are_refused() {
    let d = doc();
    let cases = d["invalid_records"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        assert!(AnchorRecord::decode(&bytes(&c["record"])).is_err(), "{}", c["name"]);
    }
}
