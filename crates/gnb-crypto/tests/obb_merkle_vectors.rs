//! ObenBlock's header Merkle root (Bitcoin's tree with Bitcoin Core's
//! mutation check) and body commitment against `reference/obb_merkle.py`
//! through `reference/obb_merkle_vectors.json`, then the `core` dispatch
//! under a process-wide SHA-256d scheme: a block's header root is Bitcoin's
//! root of its txids, a mutated tree (CVE-2012-2459) is refused, and the
//! coinbase commitment carries the body commitment. Setting the scheme is
//! irreversible, so this runs in its own test process (one test function).

use gnb_crypto::core::pow_scheme::{self, PowScheme, Sha256dParams, OBB_BLOCK_VERSION};
use gnb_crypto::core::{self, block_rules, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_merkle_vectors.json"));

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn ids(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().unwrap().iter().map(h32).collect()
}

fn check_reference_vectors(v: &Value) {
    // Our wire encoding of a coinbase is Bitcoin's: the Bitcoin genesis and
    // block-1 coinbases decode and hash to their Bitcoin txids.
    let g = &v["bitcoin_genesis_coinbase"];
    let tx = Transaction::from_wire_bytes(&hex::decode(g["wire_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert!(tx.is_coinbase());
    assert_eq!(tx.txid(), h32(&g["txid"]));
    assert_eq!(tx.to_wire_bytes(true), hex::decode(g["wire_hex"].as_str().unwrap()).unwrap());

    for b in v["bitcoin_blocks"].as_array().unwrap() {
        let t = ids(&b["txids"]);
        let (root, mutated) = pow_scheme::bitcoin_merkle_root(&t);
        assert!(!mutated, "{}", b["name"]);
        assert_eq!(root.0, h32(&b["merkle_root"]), "{}", b["name"]);
        let mut display = root.0;
        display.reverse();
        assert_eq!(hex::encode(display), b["merkle_root_display"].as_str().unwrap());
        let branch = block_rules::coinbase_merkle_branch(&t, false);
        assert_eq!(branch, ids(&b["branch"]));
        assert_eq!(block_rules::merkle_root_from_coinbase_branch(&t[0], &branch, false), root);
        if let Some(cb) = b["coinbase_wire_hex"].as_str() {
            let tx = Transaction::from_wire_bytes(&hex::decode(cb).unwrap()).unwrap();
            assert_eq!(tx.txid(), t[0], "{}", b["name"]);
            assert_eq!(pow_scheme::obb_tx_merkle_root(std::slice::from_ref(&tx)), (root, false));
        }
    }
    for c in v["trees"].as_array().unwrap() {
        let t = ids(&c["ids"]);
        assert_eq!(pow_scheme::bitcoin_merkle_root(&t), (MerkleRoot(h32(&c["root"])), false), "n={}", t.len());
        // GnB's legacy root is the same tree (without the mutation flag).
        assert_eq!(block_rules::legacy_merkle_root(&t).0, h32(&c["root"]));
        if !t.is_empty() {
            assert_eq!(block_rules::coinbase_merkle_branch(&t, false), ids(&c["branch"]));
        }
    }
    for c in v["mutations"].as_array().unwrap() {
        let t = ids(&c["ids"]);
        let (root, mutated) = pow_scheme::bitcoin_merkle_root(&t);
        assert!(mutated, "{}", c["name"]);
        assert_eq!(root.0, h32(&c["root"]), "{}", c["name"]);
        if let Some(h) = c.get("honest_ids") {
            assert_eq!(pow_scheme::bitcoin_merkle_root(&ids(h)), (root, false), "{}", c["name"]);
        }
    }
    assert_eq!(v["body_commitment_tag"].as_str().unwrap().as_bytes(), pow_scheme::OBB_BODY_COMMITMENT_TAG);
    for c in v["body_commitments"].as_array().unwrap() {
        let got = pow_scheme::obb_body_commitment_parts(
            &MerkleRoot(h32(&c["witness_root"])), &h32(&c["shielded_root"]), &h32(&c["powit_root"]));
        assert_eq!(got.0, h32(&c["body_commitment"]));
    }
}

fn tx(tag: u8) -> Transaction {
    Transaction {
        version: 3,
        inputs: vec![TxInput { prev_txid: [tag; 32], prev_index: 0, script_sig: vec![tag; 70], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 10_000, script_pubkey: vec![tag; 20] }],
        locktime: 0,
    }
}

/// A block at height 1 with the coinbase commitment and header root of the
/// process's rules.
fn block(txs: Vec<Transaction>) -> Block {
    let cb = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: vec![], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 0, script_pubkey: vec![0x55; 20] }],
        locktime: 0,
    };
    let mut b = Block {
        header: BlockHeader { version: OBB_BLOCK_VERSION, parents: vec![[1; 32]], merkle_root: MerkleRoot::ZERO,
                              timestamp: 1_800_000_000, bits: 0x207f_ffff, nonce: 0 },
        transactions: std::iter::once(cb).chain(txs).collect(),
        blue_score: 1,
        height: 1,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    };
    let c = block_rules::expected_coinbase_commitment(&b);
    b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&c, b"/test/");
    b.header.merkle_root = b.body_merkle_root();
    b
}

#[test]
fn obenblock_header_root_is_bitcoins_tree() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    // Pure functions first (the scheme does not matter to them).
    check_reference_vectors(&v);

    // Under GnB-SMH (the default before the scheme is set) the dispatch is
    // GnB's: tagged tree, bare witness root.
    let gnb = block(vec![tx(1), tx(2)]);
    assert_eq!(block_rules::body_commitment_root(&gnb), block_rules::witness_root(&gnb.transactions));
    assert_eq!(gnb.body_merkle_root_at(0), block_rules::tx_merkle_root(&gnb.transactions, true));
    assert!(!block_rules::rules_apply(1, core::activation::NEVER));

    pow_scheme::set_node_pow_scheme(PowScheme::Sha256d(Sha256dParams::obenblock_regtest(1_800_000_000))).unwrap();

    // The header root is Bitcoin's root of the txids at every activation
    // height, and the coinbase commitment carries the body commitment.
    for n in [0u8, 1, 2, 3, 6] {
        let b = block((1..=n).map(tx).collect());
        let txids: Vec<[u8; 32]> = b.transactions.iter().map(Transaction::txid).collect();
        assert_eq!(b.header.merkle_root, block_rules::legacy_merkle_root(&txids), "n={n}");
        assert_eq!(b.body_merkle_root_at(core::activation::NEVER), b.header.merkle_root);
        assert!(b.validate_merkle() && b.validate_merkle_at(0) && b.validate_merkle_at(core::activation::NEVER));
        assert_eq!(block_rules::body_commitment_root(&b), pow_scheme::obb_body_commitment(&b));
        assert_ne!(block_rules::body_commitment_root(&b), block_rules::witness_root(&b.transactions));
        assert_eq!(block_rules::check_block_hardened_at(&b, 0), Ok(()), "n={n}");
        // Mandatory from height 1 whatever the activation height says.
        assert!(block_rules::rules_apply(1, core::activation::NEVER) && !block_rules::rules_apply(0, 0));
        assert_eq!(block_rules::check_block_hardened_at(&b, core::activation::NEVER), Ok(()));
        let mut bare = b.clone();
        bare.transactions[0].inputs[0].script_sig = b"/no-commitment/".to_vec();
        bare.header.merkle_root = bare.body_merkle_root();
        assert!(block_rules::check_block_hardened_at(&bare, core::activation::NEVER).is_err());
        assert!(bare.validate_structure_without_pow_at(core::activation::NEVER).is_err());

        // Every body byte outside the txids is committed: another witness
        // keeps the header root but fails the coinbase commitment (the
        // PoWit section: `node/tests/obb_sha256d_mining.rs`).
        if n > 0 {
            let mut w = b.clone();
            w.transactions[1].inputs[0].script_sig[0] ^= 1;
            assert_eq!(w.body_merkle_root(), b.header.merkle_root, "witnesses are not in the txid");
            assert!(block_rules::check_coinbase_commitment(&w).unwrap_err().starts_with("bad witness commitment"));
        }
    }

    // CVE-2012-2459: duplicating the odd tail keeps Bitcoin's root, so the
    // mutated list is refused by the mutation flag, before anything else.
    let honest = block(vec![tx(1), tx(2)]); // three transactions: odd
    let mut mutated = honest.clone();
    mutated.transactions.push(tx(2));
    assert_eq!(mutated.body_merkle_root(), honest.header.merkle_root, "same root");
    assert!(pow_scheme::obb_tx_merkle_root(&mutated.transactions).1);
    assert!(!mutated.validate_merkle() && !mutated.validate_merkle_at(0));
    assert_eq!(block_rules::check_block_hardened_at(&mutated, 0),
               Err("bad-txns-duplicate: mutated merkle tree (CVE-2012-2459)"));
    assert!(mutated.validate_structure_without_pow().is_err());
    assert_eq!(block_rules::check_block_hardened_at(&honest, 0), Ok(()));
    // Any other root mismatch keeps the generic error.
    let mut other = honest.clone();
    other.header.merkle_root = MerkleRoot([9; 32]);
    assert_eq!(block_rules::check_block_hardened_at(&other, 0), Err("invalid merkle root"));
}
