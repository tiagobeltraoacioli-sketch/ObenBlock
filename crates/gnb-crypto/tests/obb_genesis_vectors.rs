//! The ObenBlock genesis blocks (`core::genesis`) against
//! `reference/obb_genesis.py` through `reference/obb_genesis_vectors.json`:
//! the coinbase, its txid, the body root and the 80-byte header of both
//! networks, the regtest proof of work, and the mainnet rehearsal solution
//! (the launch search, end to end). No chain is selected in this process, so
//! the blocks are built from the constants alone, as the mining tool does.

use gnb_crypto::core::genesis::{self, chain_genesis, pow_scheme_for};
use gnb_crypto::core::pow_scheme::{check_sha256d_pow, PowScheme, OBB_BLOCK_VERSION};
use gnb_crypto::core::{self, ChainId};
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_genesis_vectors.json"));

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn params(id: ChainId) -> core::pow_scheme::Sha256dParams {
    match pow_scheme_for(id) {
        PowScheme::Sha256d(p) => p,
        PowScheme::GnbSmh => panic!("ObenBlock runs SHA-256d"),
    }
}

/// The template fields both networks share with the reference.
fn check_template(id: ChainId, v: &Value) -> core::Block {
    let g = chain_genesis(id);
    assert_eq!(v["text"].as_str().unwrap(), g.text);
    assert_eq!(v["bits"].as_u64().unwrap() as u32, g.bits);
    let b = g.block_with(OBB_BLOCK_VERSION, 1, 0);
    let cb = &b.transactions[0];
    assert_eq!(hex::encode(cb.to_wire_bytes(true)), v["coinbase_wire_hex"].as_str().unwrap());
    assert_eq!(cb.txid(), hex32(&v["coinbase_txid_hex"]));
    assert_eq!(b.header.merkle_root.0, hex32(&v["merkle_root_hex"]));
    assert_eq!(gnb_smh::sha256d::parents_commitment(&[]), hex32(&v["parents_commitment_hex"]));
    b
}

#[test]
fn genesis_blocks_match_the_reference() {
    let d: Value = serde_json::from_str(VECTORS).unwrap();

    // Regtest: the whole block, mined.
    let r = &d["regtest"];
    check_template(ChainId::ObenBlockRegtest, r);
    let g = chain_genesis(ChainId::ObenBlockRegtest);
    assert_eq!((g.timestamp, u64::from(g.version), g.nonce),
               (r["timestamp"].as_u64().unwrap(), r["version"].as_u64().unwrap(), r["nonce"].as_u64().unwrap()));
    let b = g.block();
    assert_eq!(hex::encode(b.header.sha256d_pow_bytes().unwrap()), r["header_hex"].as_str().unwrap());
    assert_eq!(b.header.sha256d_block_id(), hex32(&r["block_id_hex"]));
    assert_eq!(g.expected_hash, hex32(&r["block_id_hex"]));
    assert_eq!(check_sha256d_pow(&b.header, &params(ChainId::ObenBlockRegtest)), Ok(()));

    // Mainnet: the template, and the rehearsal solution under the mainnet
    // rules (the launch run produces exactly such a header at its own time).
    let m = &d["mainnet"];
    check_template(ChainId::ObenBlockMainnet, m);
    let g = chain_genesis(ChainId::ObenBlockMainnet);
    assert_eq!(m["launched"].as_bool().unwrap(), !g.is_placeholder(),
               "set \"launched\" in reference/obb_genesis.py together with the mainnet constants");
    let rh = &m["rehearsal"];
    let b = g.block_with(rh["version"].as_u64().unwrap() as u32, rh["timestamp"].as_u64().unwrap(), rh["nonce"].as_u64().unwrap());
    assert_eq!(hex::encode(b.header.sha256d_pow_bytes().unwrap()), rh["header_hex"].as_str().unwrap());
    assert_eq!(b.header.sha256d_block_id(), hex32(&rh["block_id_hex"]));
    assert_eq!(check_sha256d_pow(&b.header, &params(ChainId::ObenBlockMainnet)), Ok(()));
    let mut wrong = b.header.clone();
    wrong.nonce += 1;
    assert!(check_sha256d_pow(&wrong, &params(ChainId::ObenBlockMainnet)).is_err(), "difficulty 1: the next nonce fails");
    if g.is_placeholder() {
        assert!(genesis::launch_refusal(ChainId::ObenBlockMainnet).is_some());
        assert_ne!(b.header.sha256d_block_id(), g.expected_hash);
    } else {
        // Launched: the mined genesis itself, as for regtest.
        assert_eq!((g.timestamp, u64::from(g.version), g.nonce),
                   (m["timestamp"].as_u64().unwrap(), m["version"].as_u64().unwrap(), m["nonce"].as_u64().unwrap()));
        let b = g.block();
        assert_eq!(hex::encode(b.header.sha256d_pow_bytes().unwrap()), m["header_hex"].as_str().unwrap());
        assert_eq!(g.expected_hash, hex32(&m["block_id_hex"]));
        assert_eq!(check_sha256d_pow(&b.header, &params(ChainId::ObenBlockMainnet)), Ok(()));
        assert!(genesis::launch_refusal(ChainId::ObenBlockMainnet).is_none());
    }

    // GnB is untouched: the process selected no chain.
    assert_eq!(core::genesis_block().block_hash(), core::GENESIS_EXPECTED_HASH);
    assert_eq!(core::pow_scheme::node_pow_scheme(), PowScheme::GnbSmh);
}
