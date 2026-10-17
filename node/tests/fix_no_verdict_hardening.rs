//! Follow-up to the audit-F1 hotfix (572b63c): the four Low findings of its
//! adversarial review, all node-local (no block verdict changes).
//!
//! 1. The stop (Bitcoin Core's `AbortNode`) counted every failure without a
//!    verdict, logical index misses included: a block that ever made one
//!    reachable from block data, sent 3 times, would stop every node that
//!    receives it. Now only storage-engine failures (`ViewErrorKind::Io`)
//!    count; an inconsistent index parks the block (kept, not marked, not
//!    deleted), logs loudly and shows in `getdaginfo`.
//! 2. After a no-verdict the unvalidated branch stayed the selected tip, so
//!    templates were refused ("chain move in progress") and every acceptance
//!    re-ran the failing move. Now the block is parked, the node mines on the
//!    tip it can judge, and the block is retried on a bounded schedule.
//! 3. On a pruned node a reorg committed its rollback of blocks whose bodies
//!    were gone, then could not judge the new branch and could not re-apply
//!    the old one: it stayed on the LCA. Now that rollback is committed in
//!    the batch of the first apply chunk.
//! 4. The stop message recommended `--carryover-snapshot`, which rebuilds
//!    nothing here; it now names a resync into a fresh `--data-dir`.
//!
//! Each `#[test]` below was seen failing on 1a0ba40 (the reproduction kept in
//! its first part) before the fix.

mod fix_common;
use fix_common::*;

use std::sync::Arc;
use std::time::{Duration, Instant};

use gnb::accept;
use gnb::address::Network;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::policy::SpendPolicy;
use gnb::core::sighash::SighashVersion;
use gnb::core::{self, activation, Block, Transaction, TxOutput};
use gnb::crypto;
use gnb::reorg::ReorgPlan;
use gnb::storage::Storage;
use gnb::wallet::policy_spend::PolicySpend;
use parking_lot::RwLock;

fn policy_spend(k: &Key, policy: &SpendPolicy, prev: ([u8; 32], u32, u64), height: u64) -> Transaction {
    let mut spend = PolicySpend::new(Network::Mainnet, policy.clone(), &[prev], vec![0x33; 20],
                                     prev.2 - 100_000_000, 0, 0).unwrap();
    spend.tx.version = core::sighash::tx_version_for_height(height, activation::hardening_activation_height());
    spend.sign_digest(&k.pk, |d, v| match v {
        SighashVersion::V2 => crypto::sign(&k.sk, d),
        SighashVersion::V3 => crypto::sign_bound(&k.sk, d),
    }.map_err(|e| format!("{e:?}"))).unwrap();
    spend.finalize().unwrap()
}

fn child_where(n: &Node, parent: BlockHash, txs: Vec<Transaction>, tag: &str, pred: impl Fn(&BlockHash) -> bool) -> Block {
    let h = n.dag.read().get_block_data(&parent).unwrap().height + 1;
    let mut all = vec![coinbase(tag, core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20])];
    all.extend(txs);
    mk_block_where(n, vec![parent], all, pred)
}

fn build(n: &Node) -> Result<gnb::template::BlockTemplate, String> {
    gnb::template::build_block_template(&n.dag, &n.store, &n.mempool, gnb::template::EXTERNAL_COINBASE_RESERVE)
}

/// Make every parked block's retry due (the schedule is 1 minute doubling to
/// 1 hour); the next acceptance validates it again.
fn retry_due(n: &Node) -> Vec<BlockHash> {
    accept::unpark_due_no_verdicts(&n.dag, &n.store, Instant::now() + Duration::from_secs(10 * 3600))
}

/// A restart (store closed and reopened, DAG and shielded state reloaded as
/// main() does); `before` runs on the new store before the start-up
/// reconciliation, whose result is returned (`Err` = refuses to start).
fn reopen_with(n: Node, before: impl Fn(&Storage)) -> (Node, Result<(), String>) {
    let Node { _tmp, path, dag, store, mempool, node_state, shielded, tip_tx } = n;
    drop((dag, shielded));
    drop(store);
    let store = Arc::new(Storage::open(&path).unwrap());
    before(&store);
    let mut d = GhostDAG::with_default_k();
    d.load_persisted_validated(store.load_all_dag_data().unwrap(), store.load_all_integrity_hashes().unwrap())
        .expect("integrity chain verifies");
    d.rebuild_reachability_from_store().unwrap();
    let dag = Arc::new(RwLock::new(d));
    let shielded = Arc::new(RwLock::new(gnb::coherence::ShieldedPool::load(&store).unwrap()));
    let r = accept::reconcile_on_startup(&dag, &store, &shielded);
    (Node { _tmp, path, dag, store, mempool, node_state, shielded, tip_tx }, r)
}

/// A logical index miss under a fork-loser: a policy output (`older = 1`)
/// in the UTXO set with neither a tx-index row nor a genesis-ledger row, and
/// `B_nv` (on `P`, losing the tie-break against `T`) spending it with its
/// real, correctly signed policy: its validation reads the confirmation the
/// invariants promise and finds none (no verdict, inconsistent index).
struct Fixture {
    n: Node,
    t: BlockHash,
    b_nv: Block,
    a2: Block,
    prev: [u8; 32],
}

fn fixture() -> Fixture {
    let genesis = mk_genesis(unix_now() - 100_000);
    let k = key();
    let policy = SpendPolicy::new(1, vec![k.pk.clone()], 0, 1).unwrap();
    let prev = [0x9Du8; 32];
    let value = 1_000_000_000;
    let n = node_with(&genesis, &[(prev, 0, TxOutput { value, script_pubkey: policy.script_pubkey() })]);
    let p = empty_child(&n, genesis.block_hash(), "p");
    accept(&n, &p).unwrap();
    let t = empty_child(&n, p.block_hash(), "t");
    accept(&n, &t).unwrap();
    let th = t.block_hash();
    let b_nv = child_where(&n, p.block_hash(), vec![policy_spend(&k, &policy, (prev, 0, value), 2)], "nv",
        |h| *h < th);
    accept(&n, &b_nv).expect("fork-loser stored");
    let a2 = empty_child(&n, b_nv.block_hash(), "a2");
    Fixture { n, t: th, b_nv, a2, prev }
}

/// The same fixture with the index made consistent (the coin's tx-index
/// row) and its UTXO row failing to read in the storage engine.
fn io_fixture() -> Fixture {
    let f = fixture();
    let genesis_hash: [u8; 32] = f.n.store.get_meta("genesis_hash").unwrap().unwrap().try_into().unwrap();
    f.n.store.put_tx_index(&f.prev, &genesis_hash, 0).unwrap();
    f.n.store.inject_utxo_read_failure(f.prev);
    f
}

/// Extend the tip of the parked branch by one block (the branch stays the
/// heaviest, so a due retry validates `B_nv` again).
fn extend(n: &Node, tip: &mut BlockHash, tag: &str) -> Result<BlockHash, String> {
    let b = empty_child(n, *tip, tag);
    *tip = b.block_hash();
    accept(n, &b)
}

fn assert_kept_without_verdict(n: &Node, b: &BlockHash) {
    assert!(n.dag.read().has_block(b), "kept in the DAG");
    assert!(n.store.has_block_body(b).unwrap(), "body kept (not deleted and re-downloaded in a loop)");
    assert_eq!(n.store.invalid_block_reason(b).unwrap(), None, "B1-T12: not marked invalid");
    assert!(!n.dag.read().is_invalid_persistently(b));
    assert!(accept::is_known_block(&n.dag, &n.store, b), "known: a copy is not processed again");
}

// ── Finding 1: only storage-engine failures stop the node ───────────────────

/// Reproduction (1a0ba40): the logical miss was retried by every acceptance
/// and the third stopped the node. Now: parked, retried on schedule, never a
/// stop, visible as a no-verdict record; a restart starts.
#[test]
fn a_logical_index_miss_never_stops_the_node() {
    let _g = activation::scoped_override(0);
    let Fixture { n, t, b_nv, a2, .. } = fixture();
    accept(&n, &a2).unwrap_or_else(|e| panic!("A2 is stored, waiting for B_nv: {e}"));
    assert_eq!(applied_tip(&n), Some(t));
    assert!(n.dag.read().is_no_verdict_parked(&b_nv.block_hash()), "parked");
    let rec = n.store.no_verdict_record(&b_nv.block_hash()).expect("recorded");
    assert!(!rec.last_io && rec.io_failures == 0, "an inconsistent index, not an engine failure: {rec:?}");
    assert!(rec.reason.contains("confirmation height of input 0 unknown"), "{rec:?}");

    let mut tip = a2.block_hash();
    for i in 0..2 * accept::NO_VERDICT_ABORT_AFTER {
        // A block on the parked branch before its retry is due: no retry.
        let _ = extend(&n, &mut tip, &format!("w{i}"));
        assert_eq!(n.store.no_verdict_record(&b_nv.block_hash()).unwrap().attempts, 1 + i, "not yet due");
        assert_eq!(retry_due(&n), vec![b_nv.block_hash()]);
        let _ = extend(&n, &mut tip, &format!("c{i}"));
        assert_eq!(n.store.no_verdict_record(&b_nv.block_hash()).unwrap().attempts, 2 + i, "retried");
        assert!(n.store.abort_reason().is_none(), "attempt {i}: a logical miss never stops the node");
        assert_eq!(applied_tip(&n), Some(t));
    }
    assert_kept_without_verdict(&n, &b_nv.block_hash());
    build(&n).expect("templates");

    // A restart starts (B_nv is parked again by the start-up resolution).
    let (n, r) = reopen_with(n, |_| {});
    r.expect("an inconsistent index does not refuse the start");
    assert_eq!(applied_tip(&n), Some(t));
    assert!(n.dag.read().is_no_verdict_parked(&b_nv.block_hash()));
    assert!(n.store.abort_reason().is_none());
}

/// A real storage-engine failure still stops the node after
/// `NO_VERDICT_ABORT_AFTER` attempts in a row (each a scheduled retry), with
/// a message naming a recovery that works (finding 4), and a restart that
/// meets it refuses to start.
#[test]
fn repeated_storage_engine_failures_stop_the_node() {
    let _g = activation::scoped_override(0);
    let Fixture { n, t, b_nv, a2, prev } = io_fixture();
    let _ = accept(&n, &a2);
    assert_eq!(applied_tip(&n), Some(t));
    let rec = n.store.no_verdict_record(&b_nv.block_hash()).expect("recorded");
    assert!(rec.last_io && rec.io_failures == 1, "{rec:?}");
    assert!(n.store.abort_reason().is_none(), "one failure may be transient");
    build(&n).expect("templates on T meanwhile");

    let mut tip = a2.block_hash();
    for i in 1..accept::NO_VERDICT_ABORT_AFTER {
        retry_due(&n);
        let _ = extend(&n, &mut tip, &format!("c{i}"));
    }
    let reason = n.store.abort_reason().expect("the node stopped");
    assert!(reason.contains(&hex::encode(b_nv.block_hash())), "{reason}");
    assert!(reason.contains("not a verdict"), "{reason}");
    assert_eq!(reason, accept::no_verdict_abort_message(&b_nv.block_hash(), accept::NO_VERDICT_ABORT_AFTER,
        &n.store.no_verdict_record(&b_nv.block_hash()).unwrap().reason));
    assert_kept_without_verdict(&n, &b_nv.block_hash());
    // On the applied tip: the move of the stopping acceptance committed
    // nothing (its rollback of T shares the apply batch, review of PR #15,
    // finding 5), so its trigger was rolled back with it.
    let mut on_t = t;
    let e = extend(&n, &mut on_t, "after").unwrap_err();
    assert!(e.starts_with("node stopped:"), "{e}");
    assert!(build(&n).unwrap_err().starts_with("node stopped:"));

    let (n, r) = reopen_with(n, |s| s.inject_utxo_read_failure(prev));
    let e = r.expect_err("a restart that meets the engine failure refuses to start");
    assert!(e.contains("storage engine failed"), "{e}");
    assert_eq!(applied_tip(&n), Some(t));
    assert_eq!(n.store.invalid_block_reason(&b_nv.block_hash()).unwrap(), None);
}

// ── Finding 2: mining resumes on the restored tip ───────────────────────────

/// Reproduction (1a0ba40): applied tip T, selected tip A2, templates refused
/// "chain move in progress". Now the node mines on T, and once the index is
/// repaired the retry connects the heavier branch.
#[test]
fn after_a_no_verdict_templates_are_built_on_the_restored_tip() {
    let _g = activation::scoped_override(0);
    let Fixture { n, t, b_nv, a2, prev } = fixture();
    let _ = accept(&n, &a2);
    assert_eq!(applied_tip(&n), Some(t), "back on the applied tip the move started from");
    assert_eq!(sel_tip(&n), Some(t), "the unjudged branch is parked, not selected");
    let tpl = build(&n).expect("templates on the restored tip");
    assert_eq!(tpl.parents.first(), Some(&t));

    // Mining continues on T: a block there connects.
    let m1 = empty_child(&n, t, "m1");
    accept(&n, &m1).expect("a block on the restored tip connects");
    assert_eq!(applied_tip(&n), Some(m1.block_hash()));
    assert_eq!(n.store.no_verdict_record(&b_nv.block_hash()).unwrap().attempts, 1, "retry not due: not re-run");

    // The index is repaired; the parked branch grows heavier; its retry
    // comes due and connects it.
    let genesis_hash: [u8; 32] = n.store.get_meta("genesis_hash").unwrap().unwrap().try_into().unwrap();
    n.store.put_tx_index(&prev, &genesis_hash, 0).unwrap();
    let a3 = empty_child(&n, a2.block_hash(), "a3");
    let _ = accept(&n, &a3);
    assert_eq!(applied_tip(&n), Some(m1.block_hash()), "not yet due");
    retry_due(&n);
    let a4 = empty_child(&n, a3.block_hash(), "a4");
    accept(&n, &a4).expect("the best chain connects once B_nv can be judged");
    assert_eq!(applied_tip(&n), Some(a4.block_hash()));
    assert!(n.store.no_verdict_record(&b_nv.block_hash()).is_none(), "validated: the record goes");
    assert!(!n.dag.read().is_no_verdict_parked(&b_nv.block_hash()));
    build(&n).expect("templates");
}

// ── Finding 3: a pruned node never commits a rollback it cannot undo ────────

/// Reproduction (1a0ba40): the rollback of T3, T2, T (bodies of T2 and T
/// pruned) committed, B_nv had no verdict, and re-applying the old branch
/// failed for the missing bodies: applied tip P (the LCA). Now the rollback
/// of the bodiless blocks goes into the batch of the first apply chunk.
#[test]
fn a_pruned_node_keeps_its_tip_when_the_new_branch_has_no_verdict() {
    let _g = activation::scoped_override(0);
    let Fixture { n, t, b_nv, a2, prev } = fixture();
    // Old branch P - T - T2 - T3 (applied); new branch P - B_nv - A2 - A3 - A4.
    let t2 = empty_child(&n, t, "t2");
    accept(&n, &t2).unwrap();
    let t3 = empty_child(&n, t2.block_hash(), "t3");
    accept(&n, &t3).unwrap();
    accept(&n, &a2).expect("lighter branch stored");
    let t3h = t3.block_hash();
    let a3 = child_where(&n, a2.block_hash(), vec![], "a3", |h| *h < t3h);
    accept(&n, &a3).expect("tie lost: stored");
    assert_eq!(applied_tip(&n), Some(t3h));
    // Prune: the new branch's bodies are kept (re-stored higher, as a body
    // fetched back is), the old branch below T3 loses its bodies.
    for b in [&b_nv, &a2, &a3] {
        n.store.put_block_body_at(b, 1_000).unwrap();
    }
    n.store.prune_blocks_below(4).unwrap();
    assert!(!n.store.has_block_body(&t).unwrap() && !n.store.has_block_body(&t2.block_hash()).unwrap());
    let a4 = empty_child(&n, a3.block_hash(), "a4");
    let _ = accept(&n, &a4);
    assert_eq!(applied_tip(&n), Some(t3h), "the rollback it could not undo was not committed");
    let tpl = build(&n).expect("templates on the old tip");
    assert_eq!(tpl.parents.first(), Some(&t3h));
    assert_kept_without_verdict(&n, &b_nv.block_hash());

    // Once B_nv can be judged, the same deep move commits (the bodiless
    // rollback with the first apply chunk) and lands on A5.
    let genesis_hash: [u8; 32] = n.store.get_meta("genesis_hash").unwrap().unwrap().try_into().unwrap();
    n.store.put_tx_index(&prev, &genesis_hash, 0).unwrap();
    retry_due(&n);
    let a5 = empty_child(&n, a4.block_hash(), "a5");
    accept(&n, &a5).expect("connects");
    assert_eq!(applied_tip(&n), Some(a5.block_hash()));
}

/// `ReorgPlan::chunks_with_rollback_tail`: the last `tail` (at most `max`)
/// rollbacks share a sub-plan with the first apply chunk; the sub-plans chain
/// (each starts where the previous ends) and cover the plan exactly once.
#[test]
fn rollback_tail_shares_the_first_apply_chunk() {
    let h = |i: u8| [i; 32];
    let plan = ReorgPlan { lca: h(0), to_rollback: (1..=5).rev().map(h).collect(), to_apply: (10..=14).map(h).collect() };
    // No tail (or nothing to apply): the plain chunks.
    assert_eq!(plan.chunks_with_rollback_tail(2, 0), plan.chunks(2));
    let pure = ReorgPlan { lca: h(0), to_rollback: plan.to_rollback.clone(), to_apply: vec![] };
    assert_eq!(pure.chunks_with_rollback_tail(2, 3), pure.chunks(2));
    // Tail 2 of rollback [5,4,3,2,1], max 2.
    let c = plan.chunks_with_rollback_tail(2, 2);
    assert_eq!(c, vec![
        ReorgPlan { lca: h(3), to_rollback: vec![h(5), h(4)], to_apply: vec![] },
        ReorgPlan { lca: h(2), to_rollback: vec![h(3)], to_apply: vec![] },
        ReorgPlan { lca: h(0), to_rollback: vec![h(2), h(1)], to_apply: vec![h(10), h(11)] },
        ReorgPlan { lca: h(11), to_rollback: vec![], to_apply: vec![h(12), h(13)] },
        ReorgPlan { lca: h(13), to_rollback: vec![], to_apply: vec![h(14)] },
    ]);
    // A tail longer than one commit is capped at `max`.
    let c = plan.chunks_with_rollback_tail(2, 5);
    assert_eq!(c[2], ReorgPlan { lca: h(0), to_rollback: vec![h(2), h(1)], to_apply: vec![h(10), h(11)] });
}

// ── Finding 4: the operator message names a recovery that works ────────────

/// Reproduction (1a0ba40): the stop said "rebuild the chain state (restart
/// with --carryover-snapshot)", which only rebuilds when the start-up check
/// finds an interrupted commit. Now: a resync into a fresh `--data-dir`.
#[test]
fn the_stop_message_names_a_recovery_that_works() {
    let _g = activation::scoped_override(0);
    let Fixture { n, a2, .. } = io_fixture();
    let _ = accept(&n, &a2);
    let mut tip = a2.block_hash();
    for i in 1..accept::NO_VERDICT_ABORT_AFTER {
        retry_due(&n);
        let _ = extend(&n, &mut tip, &format!("c{i}"));
    }
    let reason = n.store.abort_reason().expect("stopped");
    assert!(!reason.contains("--carryover-snapshot"), "a restart with --carryover-snapshot rebuilds nothing: {reason}");
    assert!(reason.contains("fresh, empty --data-dir"), "{reason}");
}
