//! P5-G: the assumed-valid block (Bitcoin Core's `-assumevalid`,
//! `node/src/assumevalid.rs`). Blocks go through the REAL pipeline
//! (`fix_common::accept` -> `accept::accept_block` -> `resolve_best_chain`
//! -> `commit_chunk` -> `reorg::connect_plan`), and through the chain-state
//! rebuild (`accept::rebuild_chain_state`, Core's `-reindex-chainstate`).
//!
//! Core skips the script checks of a block B when (validation.cpp,
//! `ConnectBlock`): the assumed-valid block AV's header is known, B is an
//! ancestor of AV and of the best header, the best header has the minimum
//! chain work, and the best header is more than two weeks of
//! proof-equivalent time above B. GnB's header tree is the DAG, "ancestor"
//! is the selected chain (only selected-chain blocks are connected) and only
//! the signature step is skipped (every other rule still runs); a block whose
//! id does not commit to its witnesses is never skipped.
//!
//! The test chains are a few blocks long, so the two-week burial is scaled
//! to two blocks (`TEST_BURIAL_SECS`, pow-limit work 1 per 30 s block); one
//! test keeps Core's two weeks and shows nothing is skipped. Every test runs
//! the hardening rules from genesis on its own thread
//! (`activation::scoped_override(0)`: version-3 transactions, witness
//! commitments), except the one about uncommitted witnesses.

mod fix_common;
use fix_common::*;

use gnb::accept;
use gnb::assumevalid::{self, Policy, MIN_BURIAL_SECS};
use gnb::consensus::BlockHash;
use gnb::core::{self, activation, Block, Transaction, TxOutput};
use gnb::crypto;
use gnb::mempool::admission;
use gnb::pow;

const FEE: u64 = 100_000;
/// Two test blocks of proof-equivalent time (work 1 per block at the test
/// pow limit, 30 s per block): Core's two weeks scaled to the test chains.
const TEST_BURIAL_SECS: u64 = 60;

type Fund = ([u8; 32], u32, TxOutput);

/// The assumed-valid policy of a test: `block`, the test burial, and no
/// minimum chain work (the test chains carry a few units of work).
fn policy(block: Option<BlockHash>) -> Policy {
    Policy { block, min_burial_secs: TEST_BURIAL_SECS, min_chain_work: Some(0) }
}

/// Insert `b` into the builder's DAG only: no connect, so no signature is
/// verified (or cached) while the fixture is built.
fn insert_header(builder: &Node, b: &Block) {
    let work = pow::block_work(b.header.bits, b.height);
    builder.dag.write().add_block(b.block_hash(), b.header.parents.clone(), b.header.timestamp, work)
        .expect("builder DAG insertion");
}

/// A child of `parent` carrying `txs` after a coinbase claiming the subsidy
/// plus `fees`; `pred` constrains its hash (tie-break control).
fn child(builder: &Node, parent: BlockHash, tag: &str, txs: Vec<Transaction>, fees: u64,
         pred: impl Fn(&BlockHash) -> bool) -> Block {
    let h = builder.dag.read().get_block_data(&parent).unwrap().height + 1;
    let mut all = vec![coinbase(tag, core::tokenomics::block_subsidy_sat(h) + fees, vec![0xC0; 20])];
    all.extend(txs);
    let b = mk_block_where(builder, vec![parent], all, pred);
    insert_header(builder, &b);
    b
}

/// A spend of `fund` by `k` at header height `height` whose witness is
/// well-formed (canonical framing, canonical signature encoding, the right
/// public key) but whose signature signs another digest: only the signature
/// math rejects it.
fn bad_signature_spend(k: &Key, fund: &Fund, height: u64) -> Transaction {
    let mut tx = signed_spend_at(k, &[(fund.0, fund.1)], std::slice::from_ref(&fund.2),
        vec![out(fund.2.value - FEE, &[0xD1; 20])], height);
    let wrong = if core::block_rules::rules_active(height) {
        crypto::sign_bound(&k.sk, &[0x55; 32]).expect("sign")
    } else {
        crypto::sign(&k.sk, &[0x55; 32]).expect("sign")
    };
    tx.inputs[0].script_sig = Transaction::build_script_sig(&wrong, &k.pk);
    tx
}

/// The release chain `r1..r8` (the bad-signature spend of the fund in
/// `r[bad]`, 1-based) and a minority chain `m1..m6` from the same genesis.
/// `r6` is the assumed-valid block of most tests. `r6` loses the tie with
/// `m6` (equal work and blue score: the larger hash wins), so the node moves
/// to the release chain when `r7` arrives, with `r6` already in its DAG.
struct Fixture {
    genesis: Block,
    fund: Fund,
    bad_tx: Transaction,
    release: Vec<Block>,
    minority: Vec<Block>,
}

impl Fixture {
    fn new(bad: usize) -> Self {
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let fund: Fund = ([0x7A; 32], 0, out(5_000_000, &k.spk));
        let builder = node_with(&genesis, std::slice::from_ref(&fund));
        let mut minority = Vec::new();
        let mut tip = gh;
        for i in 1..=6 {
            let b = child(&builder, tip, &format!("m{i}"), vec![], 0, |h| i < 6 || h[0] >= 0x80);
            tip = b.block_hash();
            minority.push(b);
        }
        let mut release = Vec::new();
        let mut bad_tx = None;
        let mut tip = gh;
        for i in 1..=8 {
            let (txs, fees) = if i == bad {
                let tx = bad_signature_spend(&k, &fund, i as u64);
                bad_tx = Some(tx.clone());
                (vec![tx], FEE)
            } else {
                (vec![], 0)
            };
            let b = child(&builder, tip, &format!("r{i}"), txs, fees, |h| i != 6 || h[0] < 0x80);
            tip = b.block_hash();
            release.push(b);
        }
        Fixture { genesis, fund, bad_tx: bad_tx.expect("a bad spend"), release, minority }
    }

    fn r(&self, i: usize) -> BlockHash {
        self.release[i - 1].block_hash()
    }

    fn m(&self, i: usize) -> BlockHash {
        self.minority[i - 1].block_hash()
    }

    /// A node that sits on the minority chain, then receives the release
    /// chain block by block.
    fn sync(&self) -> Node {
        let n = node_with(&self.genesis, std::slice::from_ref(&self.fund));
        for b in &self.minority {
            accept(&n, b).expect("minority block");
        }
        assert_eq!(applied_tip(&n), Some(self.m(6)));
        for b in &self.release {
            let _ = accept(&n, b);
        }
        n
    }

    fn on_release_chain(&self, n: &Node) -> bool {
        applied_tip(n) == Some(self.r(8))
    }

    fn bad_spend_applied(&self, n: &Node) -> bool {
        n.store.get_utxo(&self.fund.0, self.fund.1).unwrap().is_none()
            && n.store.get_utxo(&self.bad_tx.txid(), 0).unwrap().is_some()
    }
}

/// Core's `-assumevalid`: the release chain carries a spend whose signature
/// is invalid in r1, five blocks below the assumed-valid block r6. The node
/// moves to it once it is the heaviest chain (r6 is then in its DAG), skips
/// the signature checks of r1..r4 (buried more than the burial below the
/// best block r7, and on its selected chain) and ends on r8, with the
/// spend's UTXO effects applied. Pre-fix (no assumed-valid block) r1 is
/// disqualified and the node stays on the minority chain.
#[test]
fn a_bad_signature_below_the_assumed_valid_block_syncs() {
    let _act = activation::scoped_override(0);
    let f = Fixture::new(1);
    let _av = assumevalid::scoped_override(policy(Some(f.r(6))));
    let before = admission::signature_inputs_on_this_thread();
    let n = f.sync();
    let after = admission::signature_inputs_on_this_thread();
    assert!(f.on_release_chain(&n), "the release chain connects (tip {:?})", applied_tip(&n).map(hex::encode));
    assert!(f.bad_spend_applied(&n), "the spend's UTXO effects are applied");
    assert!(!n.dag.read().is_invalid(&f.r(1)));
    assert_eq!(after.assumed - before.assumed, 1, "r1's one input was assumed valid");
    assert_eq!(after.verified - before.verified, 0, "no signature of the release chain was verified");
}

/// The same chain with assumevalid off (`--assumevalid=0`, and the default
/// of a network without a release value): r1 fails its signature check, is
/// disqualified with every descendant, and the node stays on the minority
/// chain.
#[test]
fn the_same_chain_without_an_assumed_valid_block_is_rejected() {
    let _act = activation::scoped_override(0);
    let f = Fixture::new(1);
    let _av = assumevalid::scoped_override(policy(None));
    let n = f.sync();
    assert_eq!(applied_tip(&n), Some(f.m(6)));
    assert!(!f.bad_spend_applied(&n));
    assert!(n.dag.read().is_invalid(&f.r(1)) && n.dag.read().is_invalid(&f.r(8)));
    let reason = n.store.invalid_block_reason(&f.r(1)).unwrap().expect("a persisted verdict");
    assert!(reason.contains("invalid signature"), "{reason}");
}

/// The assumed-valid block is not a descendant of the bad block: it names a
/// block of the minority chain (the release chain does not contain it), or a
/// block this node never saw. Core requires the block to be an ancestor of
/// the assumed-valid block whose header is known: the signatures are checked
/// and r1 is rejected.
#[test]
fn a_block_that_is_not_an_ancestor_of_the_assumed_valid_block_is_verified() {
    let _act = activation::scoped_override(0);
    let f = Fixture::new(1);
    for av in [f.m(6), f.m(3), [0xEE; 32]] {
        let _av = assumevalid::scoped_override(policy(Some(av)));
        let n = f.sync();
        assert_eq!(applied_tip(&n), Some(f.m(6)), "assumed-valid block {}", hex::encode(&av[..4]));
        assert!(n.dag.read().is_invalid(&f.r(1)));
        assert!(!f.bad_spend_applied(&n));
    }
}

/// The bad block lies ABOVE the assumed-valid block (r7, assumed-valid
/// block r6): it is not an ancestor, so it is verified and rejected; the
/// chain below it (r1..r6) is valid and stays a candidate.
#[test]
fn a_block_above_the_assumed_valid_block_is_verified() {
    let _act = activation::scoped_override(0);
    let f = Fixture::new(7);
    let _av = assumevalid::scoped_override(policy(Some(f.r(6))));
    let n = f.sync();
    assert!(n.dag.read().is_invalid(&f.r(7)));
    let reason = n.store.invalid_block_reason(&f.r(7)).unwrap().expect("a persisted verdict");
    assert!(reason.contains("invalid signature"), "{reason}");
    assert!(!f.on_release_chain(&n));
    assert!(!f.bad_spend_applied(&n));
}

/// Core's burial: the best header must be more than two weeks of
/// proof-equivalent time above the block. With Core's two weeks
/// (`MIN_BURIAL_SECS`) a few-block chain is never buried enough: r1 is
/// verified and rejected. With the minimum chain work above the best block
/// (Core: `m_best_header->nChainWork >= MinimumChainWork()`), likewise.
#[test]
fn a_block_not_buried_two_weeks_or_below_the_minimum_chain_work_is_verified() {
    let _act = activation::scoped_override(0);
    let f = Fixture::new(1);
    let unburied = Policy { block: Some(f.r(6)), min_burial_secs: MIN_BURIAL_SECS, min_chain_work: Some(0) };
    let low_work = Policy { block: Some(f.r(6)), min_burial_secs: TEST_BURIAL_SECS, min_chain_work: Some(1_000_000) };
    for p in [unburied, low_work] {
        let _av = assumevalid::scoped_override(p);
        let n = f.sync();
        assert_eq!(applied_tip(&n), Some(f.m(6)), "{p:?}");
        assert!(n.dag.read().is_invalid(&f.r(1)), "{p:?}");
    }
}

/// A block whose id does not commit to its witnesses (below both
/// `core::WITNESS_COMMITMENT_HEIGHT` and the hardening activation) is never
/// skipped: a relay can replace its `script_sig` bytes without changing its
/// id, so the body this node holds need not be the body the assumed-valid
/// chain was validated with (Core's justification, "block merkle hashes are
/// still computed and checked", needs the commitment). r1's bad signature is
/// found; its body is dropped and the block waits for another one.
#[test]
fn a_block_whose_id_does_not_commit_to_its_witnesses_is_verified() {
    let _act = activation::scoped_override(activation::NEVER);
    let f = Fixture::new(1);
    assert!(!accept::witnesses_fixed_at(1, activation::NEVER));
    let _av = assumevalid::scoped_override(policy(Some(f.r(6))));
    let n = f.sync();
    assert_eq!(applied_tip(&n), Some(f.m(6)));
    assert!(!f.bad_spend_applied(&n));
    assert!(n.dag.read().is_body_pending(&f.r(1)), "the body was rejected, the block waits for another");
}

/// Core's `-reindex-chainstate` path: a node that rejected the release chain
/// (no assumed-valid block) rebuilds its chain state from the stored bodies
/// with the release's assumed-valid block: the consensus marks are
/// re-derived, every header is in the DAG, and the release chain connects
/// with r1..r5 skipped (buried below the best block r8).
#[test]
fn a_chain_state_rebuild_skips_signatures_below_the_assumed_valid_block() {
    let _act = activation::scoped_override(0);
    let f = Fixture::new(1);
    let n = {
        let _av = assumevalid::scoped_override(policy(None));
        f.sync()
    };
    assert_eq!(applied_tip(&n), Some(f.m(6)));
    let fund = f.fund.clone();
    let seed = move |st: &gnb::storage::Storage, batch: &mut rocksdb::WriteBatch| {
        st.stage_utxo(batch, &fund.0, fund.1, &fund.2).map_err(|e| e.to_string())
    };
    let _av = assumevalid::scoped_override(policy(Some(f.r(6))));
    let before = admission::signature_inputs_on_this_thread();
    accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &seed).expect("rebuild");
    let after = admission::signature_inputs_on_this_thread();
    assert!(f.on_release_chain(&n), "tip {:?}", applied_tip(&n).map(hex::encode));
    assert!(f.bad_spend_applied(&n));
    assert_eq!(after.assumed - before.assumed, 1);
}

/// Measurement: the signature verifications the assumed-valid block saves.
/// The release chain r1..r8 carries one valid signed spend per block (a
/// chain of spends of the fund); the assumed-valid block is r6. Node A
/// (assumed-valid block set) and node B (none) each sit on a minority chain
/// and then receive the release chain; it becomes the heaviest at r7, when
/// r1..r7 connect in one move with r6 in the DAG. A skips r1..r4 (buried
/// more than two test blocks below r7; r5 and r6 are not, r7 and r8 are
/// above the assumed-valid block) and verifies the other four; B verifies
/// every input A skipped (the four A verified are in the verified-signature
/// cache by then). Pre-fix nothing is ever assumed.
#[test]
fn the_assumed_valid_block_saves_the_signature_verifications_below_it() {
    let _act = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund: Fund = ([0x7B; 32], 0, out(50_000_000, &k.spk));
    let builder = node_with(&genesis, std::slice::from_ref(&fund));
    let mut minority = Vec::new();
    let mut tip = gh;
    for i in 1..=6 {
        let b = child(&builder, tip, &format!("mm{i}"), vec![], 0, |h| i < 6 || h[0] >= 0x80);
        tip = b.block_hash();
        minority.push(b);
    }
    let mut release = Vec::new();
    let (mut prev, mut tip) = (fund.clone(), gh);
    for i in 1..=8u64 {
        let tx = signed_spend_at(&k, &[(prev.0, prev.1)], std::slice::from_ref(&prev.2),
            vec![out(prev.2.value - FEE, &k.spk)], i);
        prev = (tx.txid(), 0, tx.outputs[0].clone());
        let b = child(&builder, tip, &format!("rr{i}"), vec![tx], FEE, |h| i != 6 || h[0] < 0x80);
        tip = b.block_hash();
        release.push(b);
    }
    let av = release[5].block_hash();
    let run = |p: Policy| {
        let _g = assumevalid::scoped_override(p);
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        for b in &minority {
            accept(&n, b).unwrap();
        }
        let before = admission::signature_inputs_on_this_thread();
        for b in &release {
            accept(&n, b).unwrap();
        }
        let after = admission::signature_inputs_on_this_thread();
        assert_eq!(applied_tip(&n), Some(release[7].block_hash()));
        (after.verified - before.verified, after.cached - before.cached, after.assumed - before.assumed)
    };
    let (a_verified, a_cached, a_assumed) = run(policy(Some(av)));
    let (b_verified, b_cached, b_assumed) = run(policy(None));
    assert_eq!((a_verified, a_cached, a_assumed), (4, 0, 4), "A: r5..r8 verified, r1..r4 assumed");
    assert_eq!((b_verified, b_cached, b_assumed), (4, 4, 0), "B: r1..r4 verified, r5..r8 cached");
}
