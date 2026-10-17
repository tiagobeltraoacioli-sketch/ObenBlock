//! PoWit state replay across the second hardening activation through the
//! REAL pipeline (PoWit audit findings 1 and 4, item "restart/reorg"): every
//! node computes the same PoWit state for every block whatever the order it
//! receives them in, across a reorg in both directions and a restart.
//!
//! The miner's path builds the chain (`template::build_block_template` ->
//! `BlockTemplate::miner_coinbase` -> `template::assemble_block` ->
//! `accept::accept_block`), with three witness nodes' duties
//! (`powit::WitnessDuty::maybe_attest`, the node's pool) and their shares
//! (`powit::mine_share`), and a fourth witness that double-votes once. The
//! second hardening activation is at height 96: votes for slots up to 93 are
//! signed v1 and slot 98 v2, the double vote is proven in a block from the
//! activation (where only a witness may be proven), and the witness set,
//! threshold and decay switch there. A competing branch forks below the
//! activation and crosses it.
//!
//! Testnet PoWit clock (epochs of 20, checkpoints every 5) with PoWit from
//! height 3; proofs of work marked verified (`test-pow-limit`).

mod fix_common;
use fix_common::*;

use std::collections::HashMap;

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::kes::{KesKeyFile, KesSigner};
use gnb::core::powit::{Attestation, Checkpoint, PowitState, TESTNET_PARAMS};
use gnb::core::{self, activation, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput};
use gnb::pow;
use gnb::powit;
use gnb::template;
use tempfile::TempDir;

const POWIT: u64 = 3;
const H2: u64 = 96;
const PASSWORD: &str = "correct horse battery staple 42";

struct Witness {
    _dir: TempDir,
    duty: powit::WitnessDuty,
}

fn witness(seed: u8) -> Witness {
    let dir = TempDir::new().unwrap();
    // Depth 3: epochs 0..=7 (heights 3..=162).
    let signer = KesSigner::generate(3, [seed; 32], |_| {}).unwrap();
    KesKeyFile::seal(&signer, PASSWORD).unwrap().save(&dir.path().join("witness.key")).unwrap();
    std::fs::write(dir.path().join("pw"), format!("{PASSWORD}\n")).unwrap();
    std::fs::create_dir_all(dir.path().join("data")).unwrap();
    let d = dir.path();
    let duty = powit::WitnessDuty::load(&d.join("witness.key"), &d.join("pw"), vec![0xAB; 20], &d.join("data")).unwrap();
    Witness { _dir: dir, duty }
}

fn states_of(n: &Node, blocks: &[Block]) -> HashMap<BlockHash, PowitState> {
    blocks.iter()
        .filter(|b| b.height >= POWIT)
        .map(|b| (b.block_hash(), powit::load_state(&n.store, &b.block_hash()).unwrap_or_else(|| panic!("h={} has no state", b.height))))
        .collect()
}

/// Every stored state equals a fresh replay of its block on the node's DAG.
fn replay_matches(n: &Node, blocks: &[Block]) {
    let d = n.dag.read();
    for b in blocks.iter().filter(|b| b.height >= POWIT) {
        let replayed = powit::block_state(b, &b.block_hash(), &d, &n.store)
            .unwrap_or_else(|e| panic!("replay of h={}: {e}", b.height))
            .expect("PoWit active");
        assert_eq!(Some(replayed), powit::load_state(&n.store, &b.block_hash()), "h={}", b.height);
    }
}

fn deliver(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

/// Empty-section blocks on `from` (a branch with no witness activity).
fn branch(blocks_so_far: &[Block], genesis: &Block, from: BlockHash, n: usize) -> Vec<Block> {
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
    for b in blocks_so_far {
        dag.add_block(b.block_hash(), b.header.parents.clone(), b.header.timestamp, pow::block_work(b.header.bits, b.height))
            .unwrap();
    }
    let mut out = Vec::with_capacity(n);
    let mut p = from;
    for i in 0..n {
        let pd = dag.get_block_data(&p).unwrap().clone();
        let height = pd.height + 1;
        let bits = pow::expected_bits(pd.timestamp, height).unwrap();
        let cb = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX,
                                   script_sig: format!("branch{i}").into_bytes(), sequence: u32::MAX }],
            outputs: Block::coinbase_outputs(height, vec![0xC1; 20], 0, &[]),
            locktime: 0,
        };
        let mut b = Block {
            header: BlockHeader { version: 1, parents: vec![p], merkle_root: MerkleRoot::ZERO,
                                  timestamp: pd.timestamp + 1, bits, nonce: 0 },
            transactions: vec![cb],
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        commit_block(&mut b);
        b.test_only_assume_pow_valid();
        dag.add_block(b.block_hash(), vec![p], b.header.timestamp, pow::block_work(bits, height)).unwrap();
        p = b.block_hash();
        out.push(b);
    }
    out
}

#[test]
fn powit_states_replay_identically_across_the_activation_restart_and_reorg() {
    let _ = core::set_node_chain_id(ChainId::Testnet);
    let _ = core::set_powit_height_override(POWIT);
    assert_eq!(core::node_chain_id(), ChainId::Testnet);
    assert_eq!(core::powit_height(), POWIT);
    let _g = activation::scoped_override_v2(H2);
    let p = TESTNET_PARAMS;

    let genesis = mk_genesis(unix_now() - 100_000);
    let mut n1 = node_with(&genesis, &[]);
    let witnesses: Vec<Witness> = (1..=3).map(witness).collect();
    // The fourth witness signs by hand (a double vote at slot 98).
    let mut d_signer = KesSigner::generate(3, [9; 32], |_| {}).unwrap();
    let d_id = d_signer.public().witness_id();
    let ids: Vec<[u8; 20]> = witnesses.iter().map(|w| w.duty.key_id).chain([d_id]).collect();
    let miner = vec![0xCB; 20];
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut main: Vec<Block> = Vec::new();
    let mut evidence_at = None;

    for height in 1..=125u64 {
        let (tip, tip_h) = {
            let d = n1.dag.read();
            let t = d.selected_tip().unwrap();
            (t, d.get_block_data(&t).unwrap().height)
        };
        assert_eq!(tip_h + 1, height);
        // Shares: every witness, attesting the tip, in blocks 4..=8 (epoch 0).
        if (4..=8).contains(&height) {
            let attested = n1.store.get_block(&tip).unwrap().unwrap();
            for id in &ids {
                let s = powit::mine_share(&attested, tip, *id, &[0xAB; 20], u64::from(id[0]) << 32, 64, &stop)
                    .expect("a share at the pow limit");
                powit::pool().admit_share(s, &n1.dag.read(), &n1.store).unwrap();
            }
        }
        // The duties, while the witnesses are online (up to block 100).
        if height <= 100 {
            for w in &witnesses {
                let d = n1.dag.read();
                if let Some(a) = w.duty.maybe_attest(&d, &n1.store).unwrap() {
                    assert_eq!(a.verify_signature_at(ChainId::Testnet, &p, POWIT, activation::NEVER),
                               a.target.height < H2, "slot {}: v1 below the activation, v2 from it", a.target.height);
                    powit::pool().admit_attestation(a, &d, &n1.store).unwrap();
                }
            }
        }
        // The fourth witness double-votes for slot 98 (two blocks at height 97).
        if height == 98 {
            let d = n1.dag.read();
            let st = powit::load_state(&n1.store, &tip).unwrap();
            d_signer.evolve_to(p.epoch(POWIT, 98)).unwrap();
            let real = Checkpoint { height: 98, hash: tip };
            let fake = Checkpoint { height: 98, hash: [0xEE; 32] };
            for t in [fake, real] {
                let a = Attestation::sign(ChainId::Testnet, st.justified, t, &d_signer).unwrap();
                let _ = powit::pool().admit_attestation(a, &d, &n1.store);
            }
            assert!(powit::pool().snapshot().2.iter().any(|e| e.a.key_id() == d_id), "the pool built the proof");
        }
        let tmpl = template::build_block_template(&n1.dag, &n1.store, &n1.mempool,
            template::miner_coinbase_reserve(&miner)).expect("template");
        if !tmpl.powit.evidence.is_empty() {
            evidence_at.get_or_insert(height);
        }
        let block = template::assemble_block(&tmpl, tmpl.miner_coinbase(miner.clone()), unix_now())
            .unwrap_or_else(|e| panic!("assemble h={height}: {e}"));
        block.test_only_assume_pow_valid();
        accept(&n1, &block).unwrap_or_else(|e| panic!("h={height}: {e}"));
        main.push(block);
    }

    // What the chain did.
    let st = |h: u64| powit::load_state(&n1.store, &main[h as usize - 1].block_hash()).unwrap();
    assert_eq!(evidence_at, Some(98), "the double vote is proven in the first block after it");
    assert!(st(98).is_banned(&d_id, p.epoch(POWIT, 98)), "and bars the fourth witness");
    let fin = st(100).finalized;
    assert!(fin.height >= 88 && fin.height < 96, "finality from the duties: {fin:?}");
    assert!(st(100).justified.height >= 98, "slot 98 (v2 votes) justified: {:?}", st(100).justified);
    let finalized_block = n1.dag.read().get_block_data(&fin.hash).unwrap().height;
    assert!(finalized_block < 95, "the competing branch below forks above the finalized block");

    // Restart: every state as stored, and as a fresh replay.
    let before = states_of(&n1, &main);
    let pin = n1.dag.read().finalized();
    restart(&mut n1);
    assert_eq!(states_of(&n1, &main), before);
    assert_eq!(n1.dag.read().finalized(), pin, "the pin is restored");
    replay_matches(&n1, &main);

    // A branch from height 95 (below the activation) that crosses it.
    let b = branch(&main[..95], &genesis, main[94].block_hash(), 20);
    assert_eq!((b[0].height, b[19].height), (96, 115));

    // Node 2: main to 110, then the heavier branch (reorg across the
    // activation), then the rest of main (reorg back).
    let mut n2 = node_with(&genesis, &[]);
    deliver(&n2, &main[..110]);
    deliver(&n2, &b);
    assert_eq!(applied_tip(&n2), Some(b[19].block_hash()), "reorg onto the branch");
    deliver(&n2, &main[110..]);
    assert_eq!(applied_tip(&n2), Some(main[124].block_hash()), "reorg back onto main");
    // Node 1 receives the branch as fork-losers.
    deliver(&n1, &b);
    assert_eq!(applied_tip(&n1), Some(main[124].block_hash()));

    let all: Vec<Block> = main.iter().chain(&b).cloned().collect();
    let s1 = states_of(&n1, &all);
    let s2 = states_of(&n2, &all);
    assert_eq!(s1, s2, "both nodes hold the same state for every block");
    assert_eq!(states_of(&n2, &main), before, "main's states do not depend on the order or the reorgs");
    replay_matches(&n2, &all);
    restart(&mut n2);
    assert_eq!(states_of(&n2, &all), s1);
    assert_eq!(n2.dag.read().finalized(), n1.dag.read().finalized());

    // The branch's states switched rules at the activation like main's: its
    // first block (96) is checked under the second hardening rules.
    let parent = powit::load_state(&n2.store, &main[94].block_hash()).unwrap();
    let first = &s1[&b[0].block_hash()];
    assert_eq!(first.epoch, p.epoch(POWIT, 96));
    assert_eq!(first.justified, parent.justified);
}
