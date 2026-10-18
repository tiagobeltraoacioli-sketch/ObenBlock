//! ObenBlock regtest from a fresh data directory (docs/DESIGN-obenblock.md
//! §3, package O6c): the node's own first-boot path (`genesis_init`, which
//! main.rs runs) writes the real genesis ledger (the shipped Bloch Genesis-3
//! snapshot, converted exactly as on GnB, plus the locked team and founder
//! tranches) and the mined regtest genesis; then blocks are mined on it
//! through the real template builder, a SHA-256d nonce search and
//! `accept::accept_block`, with every rule of the chain from height 0 (PoWit
//! on the genesis, slow-start subsidy); then the node restarts on the same
//! data directory.
//!
//! The chain id is process-wide and fixed once, so this runs in its own test
//! process (one test function). The node binary itself cannot be spawned
//! from `cargo test --release` (the dev-dependency feature `test-pow-limit`
//! makes an optimised test build refuse to start), so the test drives the
//! library functions `main` calls.

mod fix_common;
use fix_common::*;

use std::sync::Arc;

use gnb::coherence::ShieldedPool;
use gnb::consensus::GhostDAG;
use gnb::core::genesis::{OBB_MIN_CHAIN_WORK, OBB_REGTEST_GENESIS_HASH};
use gnb::core::pow_scheme::{self, OBB_BLOCK_VERSION, OBB_REGTEST_POW_LIMIT_BITS};
use gnb::core::{self, carryover, powit::Checkpoint, tokenomics, vesting, ChainId};
use gnb::mempool::Mempool;
use gnb::rpc::NodeState;
use gnb::storage::Storage;
use gnb::{genesis_init, ingress, template, tip};
use parking_lot::RwLock;
use tokio::sync::broadcast;

fn snapshot() -> Vec<u8> {
    let gz = concat!(env!("CARGO_MANIFEST_DIR"), "/../genesis/bloch-g3-carryover.tsv.gz");
    let out = std::process::Command::new("gzip").args(["-dc", gz]).output().expect("gzip");
    assert!(out.status.success(), "gunzip the shipped snapshot");
    out.stdout
}

fn node_on(tmp: tempfile::TempDir, store: Arc<Storage>, dag: Arc<RwLock<GhostDAG>>) -> Node {
    let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(64);
    Node {
        path: tmp.path().join("db"),
        _tmp: tmp,
        dag,
        store,
        mempool: Arc::new(Mempool::new()),
        node_state: Arc::new(RwLock::new(NodeState::default())),
        shielded: Arc::new(RwLock::new(ShieldedPool::new())),
        tip_tx,
    }
}

/// One block on the node's tip, as the built-in miner builds it: template,
/// coinbase, `assemble_block`, then a SHA-256d nonce search at the regtest
/// pow limit (about two hashes).
fn mine_one(n: &Node, spk: &[u8], ts: u64) -> core::Block {
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::miner_coinbase_reserve(spk))
        .expect("template");
    assert!(tmpl.hardened && core::powit_active(tmpl.height), "every rule from height 1");
    assert_eq!(tmpl.bits, OBB_REGTEST_POW_LIMIT_BITS);
    let cb = tmpl.miner_coinbase(spk.to_vec());
    let mut b = template::assemble_block(&tmpl, cb, ts).expect("template self-check");
    b.header.version = OBB_BLOCK_VERSION;
    while !b.validate_pow() {
        b.header.nonce += 1;
    }
    b
}

#[test]
fn regtest_boots_from_its_genesis_and_mines() {
    core::set_node_chain_id(ChainId::ObenBlockRegtest).expect("fresh process");
    assert!(pow_scheme::node_sha256d_params().is_some(), "SHA-256d bound to the chain id");
    // §3: no minimum chain work and no assumed-valid block at launch.
    assert_eq!(ingress::minimum_chain_work(), OBB_MIN_CHAIN_WORK);
    assert_eq!(ingress::OBENBLOCK_MINIMUM_CHAIN_WORK, OBB_MIN_CHAIN_WORK);
    assert!(gnb::assumevalid::default_assume_valid(core::activation::ActivationNetwork::ObenBlockMainnet).is_none());
    let bytes = snapshot();

    // A snapshot that does not verify writes nothing.
    {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Storage::open(&tmp.path().join("db")).unwrap();
        let dag = RwLock::new(GhostDAG::with_default_k());
        let errs = genesis_init::initialise(&store, &dag, &bytes[..bytes.len() - 1]).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("not this chain's carryover")), "{errs:?}");
        assert_eq!(store.get_meta("genesis_hash").unwrap(), None);
        assert_eq!(store.get_meta("carryover_sha3").unwrap(), None);
    }

    // First boot.
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Arc::new(Storage::open(&tmp.path().join("db")).unwrap());
    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    assert_eq!(genesis_init::initialise(&store, &dag, &bytes), Ok(OBB_REGTEST_GENESIS_HASH));
    assert_eq!(genesis_init::check_data_dir(&store), Ok(()));
    assert_eq!(dag.read().selected_tip(), Some(OBB_REGTEST_GENESIS_HASH));
    let g = store.get_block(&OBB_REGTEST_GENESIS_HASH).unwrap().expect("genesis stored");
    assert_eq!(g.block_hash(), OBB_REGTEST_GENESIS_HASH);
    assert_eq!(store.get_meta("current_bits").unwrap().unwrap(), OBB_REGTEST_POW_LIMIT_BITS.to_le_bytes().to_vec());

    // The genesis ledger is GnB's: the same outputs to the same key hashes,
    // the same conversion, the same locked tranches.
    let snap = carryover::verify_and_convert(&bytes).unwrap();
    assert_eq!(snap.utxos.len() as u64, carryover::CARRYOVER_CONVERTED_UTXOS);
    assert_eq!(snap.converted_total_sat, carryover::CARRYOVER_CONVERTED_TOTAL_SAT);
    for u in snap.utxos.iter().step_by(45_000) {
        let o = store.get_utxo(&u.txid, u.vout).unwrap().expect("carry-over output");
        assert_eq!((o.value, &o.script_pubkey), (u.output.value, &u.output.script_pubkey));
    }
    let locked = vesting::genesis_tranches().unwrap();
    assert_eq!(locked.len(), 72);
    for t in &locked {
        let o = store.get_utxo(&t.txid, t.vout).unwrap().expect("locked tranche");
        assert_eq!(o.value, t.output.value);
    }
    assert_eq!(locked.iter().map(|t| t.output.value).sum::<u64>(),
               tokenomics::TEAM_ALLOCATION_SAT + tokenomics::FOUNDER_ALLOCATION_SAT);
    // The genesis coinbase pays nothing and creates no output.
    assert_eq!(store.get_utxo(&g.transactions[0].txid(), 0).unwrap().map(|o| o.value), None);

    // Mine three blocks through the real pipeline.
    let mut n = node_on(tmp, store, dag);
    let k = key();
    let t0 = unix_now();
    let mut tips = vec![OBB_REGTEST_GENESIS_HASH];
    for i in 1..=3u64 {
        let b = mine_one(&n, &k.spk, t0 + i);
        assert_eq!(b.height, i);
        assert_eq!(b.header.parents, vec![*tips.last().unwrap()]);
        // Slow start: block i pays floor(full * i / 5,760), split with the
        // (empty) witness pool.
        let split = core::witness_share::split_subsidy(i, 0);
        assert_eq!(b.transactions[0].outputs.len(), 1);
        assert_eq!(b.transactions[0].outputs[0].value, split.miner);
        assert_eq!(split.miner + split.unissued, tokenomics::INITIAL_SUBSIDY_SAT * i / pow_scheme::SLOW_START_BLOCKS);
        assert_eq!(accept(&n, &b), Ok(b.block_hash()), "block {i}");
        tips.push(b.block_hash());
        assert_eq!(sel_tip(&n), Some(b.block_hash()));
        assert_eq!(applied_tip(&n), Some(b.block_hash()));
    }
    // PoWit from height 0: block 1 builds on the genesis as checkpoint slot
    // 0, justified and final; the witness set is still empty.
    let st = gnb::powit::load_state(&n.store, &tips[1]).expect("PoWit state of block 1");
    let slot0 = Checkpoint { height: 0, hash: OBB_REGTEST_GENESIS_HASH };
    assert_eq!((st.activation, st.justified, st.finalized), (0, slot0, slot0));
    assert!(gnb::powit::load_state(&n.store, &tips[3]).is_some());

    // A header outside the SHA-256d layout (GnB's version 1) is refused.
    let mut bad = mine_one(&n, &k.spk, t0 + 10);
    bad.header.version = 1;
    assert!(accept(&n, &bad).is_err());

    // Restart on the same data directory: the genesis check passes, the
    // chain is reloaded and reconciled.
    restart(&mut n);
    assert_eq!(genesis_init::check_data_dir(&n.store), Ok(()));
    assert_eq!(sel_tip(&n), Some(tips[3]));
    let b4 = mine_one(&n, &k.spk, t0 + 20);
    assert_eq!(accept(&n, &b4), Ok(b4.block_hash()));
    assert_eq!(n.dag.read().get_block_data(&b4.block_hash()).unwrap().height, 4);

    // A data directory of another genesis (GnB's) is refused.
    n.store.put_meta("genesis_hash", &core::GENESIS_EXPECTED_HASH).unwrap();
    let why = genesis_init::check_data_dir(&n.store).unwrap_err();
    assert!(why.contains(&hex::encode(OBB_REGTEST_GENESIS_HASH)), "{why}");
}
