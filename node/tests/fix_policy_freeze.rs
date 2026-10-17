//! Audit F1 (HIGH): a free invalid transaction made a block impossible to
//! judge, and a short private fork then froze every node.
//!
//! The policy a `script_sig` reveals was used for its timelocks BEFORE
//! anything checked that it hashes to the spent output. A made-up policy with
//! `older = 1` spending a genesis-ledger output (a vesting tranche: a
//! synthetic txid with no tx-index row) made the confirmation lookup answer
//! "unknown", a read failure: no verdict (re-audit B1-T12). A fork-loser
//! `B_bad` carrying it, then a heavier child `A2`, made the chunked chain
//! move commit its rollback of the honest tip `T` and stop on `T`'s parent
//! `P`; every later block re-ran the same failing move and was rolled back,
//! templates were refused, and a restart refused to start. Observed at HEAD
//! 4293747 (this file's scenario, `fake_policy_tranche_spend_*`):
//!
//! * hardened rules: `accept(A2)` = Ok, applied tip = P, selected tip = A2,
//!   template "chain move in progress", `accept(C on A2)` and
//!   `accept(T2 on T)` = Err "could not be validated (storage read failed,
//!   no verdict): storage: confirmation height of input 0 unknown" (both
//!   rolled back out of the DAG), no invalid mark, restart reconciliation
//!   Err with the same message (the node refuses to start);
//! * pre-activation rules: the same stall (T2 escaped it only by winning
//!   the hash tie-break against A2).
//!
//! Fixed: the revealed policy is checked against the output first (a
//! witness failure, classified like every other one), genesis-ledger
//! outputs are confirmed at the genesis, a move that cannot apply the new
//! branch returns to the applied tip it started from, and a block without a
//! verdict is parked and retried on a bounded schedule instead of looping;
//! only repeated storage-engine failures stop the node (Bitcoin Core's
//! `AbortNode`; the review's follow-up, `fix_no_verdict_hardening.rs`).
//! Audit F5 (the relay's signature budget
//! counts policy signatures) is in `fix_ingress_dos.rs`.

mod fix_common;
use fix_common::*;

use std::sync::Arc;

use gnb::accept::{self, confirmations_in_view, MaturityRule};
use gnb::address::Network;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::policy::{PolicyWitness, SpendPolicy};
use gnb::core::sighash::SighashVersion;
use gnb::core::vesting::{Role, Tranche};
use gnb::core::{self, activation, Block, Transaction, TxInput, TxOutput};
use gnb::crypto;
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::storage::Storage;
use gnb::wallet::policy_spend::PolicySpend;
use parking_lot::RwLock;

// ── Fixtures ─────────────────────────────────────────────────────────────────

const CARRYOVER_TXID: [u8; 32] = [0xCA; 32];

fn carryover(utxos: Vec<core::carryover::CarryoverUtxo>) -> core::carryover::VerifiedCarryover {
    let total: u64 = utxos.iter().map(|u| u.output.value).sum();
    core::carryover::VerifiedCarryover {
        utxos,
        sha3: core::carryover::CARRYOVER_SNAPSHOT_SHA3,
        source_rows: 1,
        source_total_sat: total as u128,
        converted_total_sat: total,
        dropped_zero: 0,
        fixed_vouts: 0,
    }
}

/// A node whose genesis ledger (ingested exactly as first boot does,
/// `Storage::ingest_carryover`) holds one carryover output and `locked`.
fn ledger_node_with(genesis: &Block, locked: &[Tranche]) -> Node {
    let n = node_with(genesis, &[]);
    let snap = carryover(vec![core::carryover::CarryoverUtxo {
        txid: CARRYOVER_TXID, vout: 0, output: out(5_000_000, &[0x22; 20]),
    }]);
    n.store.ingest_carryover(&snap, locked).expect("genesis ledger ingested");
    n
}

/// The shipped vesting tranches (`genesis/vesting.json`): founder tranche 1.
fn ledger_node(genesis: &Block) -> (Node, Tranche) {
    let locked = core::vesting::genesis_tranches().expect("shipped vesting spec");
    (ledger_node_with(genesis, &locked), locked[0].clone())
}

/// The attack: tranche `t` spent with a made-up 1-of-1 policy (`older = 1`)
/// and a junk signature. No key of the tranche is needed.
fn fake_spend(t: &Tranche, height: u64) -> Transaction {
    let k = key();
    let policy = SpendPolicy::new(1, vec![k.pk.clone()], 0, 1).unwrap();
    let witness = PolicyWitness { policy, signatures: vec![(0, vec![0xAB; 64])] }.encode();
    Transaction {
        version: core::sighash::tx_version_for_height(height, activation::hardening_activation_height()),
        inputs: vec![TxInput { prev_txid: t.txid, prev_index: t.vout, script_sig: witness, sequence: u32::MAX }],
        outputs: vec![out(t.output.value - 100_000_000, &[0x11; 20])],
        locktime: 0,
    }
}

/// A correctly signed spend of `prev` (locked by `policy`, keyed by `k`) for
/// a block at `height`, under the rules of that height.
fn policy_spend(k: &Key, policy: &SpendPolicy, prev: ([u8; 32], u32, u64), locktime: u32, height: u64) -> Transaction {
    let mut spend = PolicySpend::new(Network::Mainnet, policy.clone(), &[prev], vec![0x33; 20],
                                     prev.2 - 100_000_000, 0, locktime).unwrap();
    spend.tx.version = core::sighash::tx_version_for_height(height, activation::hardening_activation_height());
    spend.sign_digest(&k.pk, |d, v| match v {
        SighashVersion::V2 => crypto::sign(&k.sk, d),
        SighashVersion::V3 => crypto::sign_bound(&k.sk, d),
    }.map_err(|e| format!("{e:?}"))).unwrap();
    spend.finalize().unwrap()
}

fn child_with(n: &Node, parent: BlockHash, txs: Vec<Transaction>, tag: &str, pred: impl Fn(&BlockHash) -> bool) -> Block {
    let h = n.dag.read().get_block_data(&parent).unwrap().height + 1;
    let mut all = vec![coinbase(tag, core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20])];
    all.extend(txs);
    mk_block_where(n, vec![parent], all, pred)
}

fn build(n: &Node) -> Result<gnb::template::BlockTemplate, String> {
    gnb::template::build_block_template(&n.dag, &n.store, &n.mempool, gnb::template::EXTERNAL_COINBASE_RESERVE)
}

fn relay_policy(n: &Node) -> AdmissionPolicy {
    AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()))
}

/// A node restart: the store is closed and reopened, the DAG and the
/// shielded state reloaded from it as main() does, then the start-up
/// reconciliation runs (its result is returned: `Err` = refuses to start).
fn reopen(n: Node) -> (Node, Result<(), String>) {
    let Node { _tmp, path, dag, store, mempool, node_state, shielded, tip_tx } = n;
    drop((dag, shielded));
    drop(store);
    let store = Arc::new(Storage::open(&path).unwrap());
    let mut d = GhostDAG::with_default_k();
    d.load_persisted_validated(store.load_all_dag_data().unwrap(), store.load_all_integrity_hashes().unwrap())
        .expect("integrity chain verifies");
    d.rebuild_reachability_from_store().unwrap();
    let dag = Arc::new(RwLock::new(d));
    let shielded = Arc::new(RwLock::new(gnb::coherence::ShieldedPool::load(&store).unwrap()));
    let r = accept::reconcile_on_startup(&dag, &store, &shielded);
    (Node { _tmp, path, dag, store, mempool, node_state, shielded, tip_tx }, r)
}

fn regimes() -> [(u64, &'static str); 2] {
    [(0, "hardened"), (activation::NEVER, "pre-activation")]
}

// ═════════════════════════════════════════════════════════════════════════════
// The reported scenario
// ═════════════════════════════════════════════════════════════════════════════

/// The auditor's scenario, in both regimes. `B_bad` (fork-loser on `P`,
/// never validated on arrival) spends a shipped vesting tranche with a
/// made-up `older = 1` policy; `A2` on it is the heaviest block. Now `B_bad`
/// fails the policy hash (a witness failure: permanent where the block id
/// commits to its witnesses, a body failure below that), the node stays on
/// `T`, keeps building templates and extending the honest chain, and a
/// restart starts.
#[test]
fn fake_policy_tranche_spend_in_a_fork_loser_cannot_freeze_the_node() {
    for (act, regime) in regimes() {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 100_000);
        let (n, tranche) = ledger_node(&genesis);

        // The mempool refuses the attack transaction as invalid (it was a
        // "storage" no-verdict before the fix).
        let err = admission::admit(&n.store, &n.mempool, fake_spend(&tranche, 1), &relay_policy(&n)).unwrap_err();
        assert!(matches!(&err, AdmissionError::Rejected(m) if m.contains("policy does not match the output")),
            "{regime}: {err:?}");

        let p = empty_child(&n, genesis.block_hash(), "p");
        accept(&n, &p).unwrap();
        let t = empty_child(&n, p.block_hash(), "t");
        accept(&n, &t).unwrap();
        let th = t.block_hash();

        let b_bad = child_with(&n, p.block_hash(), vec![fake_spend(&tranche, 2)], "bad", |h| *h < th);
        accept(&n, &b_bad).expect("a fork-loser is stored without being validated");
        assert_eq!(applied_tip(&n), Some(th));
        let a2 = empty_child(&n, b_bad.block_hash(), "a2");
        let r = accept(&n, &a2);
        if act == 0 {
            assert!(r.is_err(), "{regime}: A2 builds on a disqualified block: {r:?}");
        }

        // HEAD: applied = P, selected = A2. Now the node stays on T.
        assert_eq!(applied_tip(&n), Some(th), "{regime}: the node stays on the best valid chain");
        assert_eq!(sel_tip(&n), Some(th), "{regime}");
        let mark = n.store.invalid_block_reason(&b_bad.block_hash()).unwrap();
        if act == 0 {
            // The block id commits to every witness: no other body exists.
            let reason = mark.expect("B_bad is disqualified");
            assert!(reason.contains("policy does not match the output at input 0"), "{reason}");
        } else {
            // Below WITNESS_COMMITMENT_HEIGHT: a property of this body only.
            assert_eq!(mark, None, "{regime}: a body failure persists no mark");
            assert!(n.dag.read().is_body_pending(&b_bad.block_hash()));
        }
        assert!(n.store.abort_reason().is_none());

        // Templates, and the honest chain grows.
        assert_eq!(build(&n).expect("a template on T").height, 3, "{regime}");
        let t2 = empty_child(&n, th, "t2");
        accept(&n, &t2).expect("T2 connects");
        assert_eq!(applied_tip(&n), Some(t2.block_hash()));
        // A heavier block on A2 does not move the node.
        let c = empty_child(&n, a2.block_hash(), "c");
        let _ = accept(&n, &c);
        assert_eq!(applied_tip(&n), Some(t2.block_hash()), "{regime}");
        assert_eq!(build(&n).expect("a template on T2").height, 4, "{regime}");

        // Restart: it starts, on T2, and still builds templates.
        let (n, r) = reopen(n);
        r.unwrap_or_else(|e| panic!("{regime}: the node starts: {e}"));
        assert_eq!(applied_tip(&n), Some(t2.block_hash()), "{regime}");
        assert_eq!(sel_tip(&n), Some(t2.block_hash()), "{regime}");
        assert_eq!(build(&n).expect("a template after the restart").height, 4, "{regime}");
        if act == 0 {
            assert!(n.store.invalid_block_reason(&b_bad.block_hash()).unwrap().is_some(), "the mark persists");
        }
    }
}

/// The same blocks during initial sync (attacker's chain first) and replayed:
/// `B_bad` is now an extension, validated at once, and judged; a replay of it
/// is a known block (or a body already rejected), never another attempt.
#[test]
fn fake_policy_tranche_spend_during_sync_and_replayed_is_judged() {
    for (act, regime) in regimes() {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 100_000);
        let (src, tranche) = ledger_node(&genesis);
        // Build the blocks on a scratch node (it only lends its DAG).
        let p = empty_child(&src, genesis.block_hash(), "p");
        accept(&src, &p).unwrap();
        let b_bad = child_with(&src, p.block_hash(), vec![fake_spend(&tranche, 2)], "bad", |_| true);
        let t = empty_child(&src, p.block_hash(), "t");

        let (n, _) = ledger_node(&genesis);
        accept(&n, &p).unwrap();
        let e = accept(&n, &b_bad).expect_err("an invalid extension is refused");
        assert!(e.contains("policy does not match the output"), "{regime}: {e}");
        for _ in 0..3 {
            let e = accept(&n, &b_bad).expect_err("a replay is refused");
            assert!(!e.contains("no verdict"), "{regime}: a replay is not validated again: {e}");
        }
        assert!(n.store.abort_reason().is_none());
        accept(&n, &t).expect("the honest block connects");
        assert_eq!(applied_tip(&n), Some(t.block_hash()), "{regime}");
        build(&n).expect("templates");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Genesis-ledger outputs: confirmed at the genesis
// ═════════════════════════════════════════════════════════════════════════════

/// The confirmation lookup of the connect, reorg, mempool and template paths
/// answers the genesis for every genesis-ledger output (carryover and
/// vesting tranches), in both measures; an output with neither a tx-index
/// row nor a genesis-ledger row stays unknown (an inconsistent index: no
/// verdict). Every shipped tranche has `older = 0`, so no block of this chain
/// ever read that point: the definition changes no verdict.
#[test]
fn genesis_ledger_outputs_are_confirmed_at_the_genesis() {
    let genesis = mk_genesis(unix_now() - 100_000);
    let (n, tranche) = ledger_node(&genesis);
    let store: &Storage = &n.store;
    let depth = || -> Result<u64, gnb::reorg::ViewError> { Ok(7) };
    for txid in [tranche.txid, CARRYOVER_TXID] {
        assert!(store.is_genesis_ledger_txid(&txid).unwrap());
        assert_eq!(confirmations_in_view(store, MaturityRule::HeaderHeights(10), &txid).unwrap(), Some(10));
        assert_eq!(confirmations_in_view(store, MaturityRule::SelectedChainDepth(&depth), &txid).unwrap(), Some(7));
    }
    for t in core::vesting::genesis_tranches().unwrap() {
        assert!(store.is_genesis_ledger_txid(&t.txid).unwrap());
        assert_eq!(t.policy.older, 0, "a shipped tranche has no relative timelock");
    }
    let stray = [0x5Au8; 32];
    assert!(!store.is_genesis_ledger_txid(&stray).unwrap());
    assert_eq!(confirmations_in_view(store, MaturityRule::HeaderHeights(10), &stray).unwrap(), None);
    // Mempool and templates: the next block (height 1, DAG height 1).
    for act in [0, activation::NEVER] {
        let _g = activation::scoped_override(act);
        assert_eq!(admission::confirmations_for_next_block(store, &tranche.txid, 1).unwrap(), Some(1));
        assert_eq!(admission::confirmations_for_next_block(store, &stray, 1).unwrap(), None);
    }
    assert_eq!(store.get_meta(gnb::storage::GENESIS_LEDGER_INDEX_META).unwrap(), Some(vec![1]));
    assert_eq!(store.migrate_genesis_ledger_index().unwrap(), None, "a fresh ledger needs no migration");
}

/// A data dir whose genesis ledger was ingested by an earlier release (no
/// genesis-ledger rows) gets them at start-up: the shipped tranches exactly,
/// the carryover outputs unspent or spent by an applied block (key-hash
/// outputs without a tx-index row), and nothing a transaction created.
#[test]
fn an_existing_data_dir_gets_the_genesis_ledger_index_at_startup() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 100_000);
    let k = key();
    let spent_c = [0xC1u8; 32];
    let kept_c = [0xC2u8; 32];
    let tranches = core::vesting::genesis_tranches().unwrap();
    let mut utxos = vec![(spent_c, 0, out(900_000_000, &k.spk)), (kept_c, 3, out(5_000_000, &[0x44; 20]))];
    utxos.extend(tranches.iter().map(|t| (t.txid, t.vout, t.output.clone())));
    // The ledger as the earlier release wrote it: UTXO rows and markers.
    let n = node_with(&genesis, &utxos);
    n.store.put_meta("carryover_sha3", &core::carryover::CARRYOVER_SNAPSHOT_SHA3).unwrap();
    n.store.put_meta("vesting_sha3", &core::vesting::VESTING_SPEC_SHA3).unwrap();
    // A block spends one carryover output.
    let spend = signed_spend_at(&k, &[(spent_c, 0)], &[out(900_000_000, &k.spk)], vec![out(800_000_000, &k.spk)], 1);
    let b1 = child_with(&n, genesis.block_hash(), vec![spend.clone()], "b1", |_| true);
    accept(&n, &b1).expect("b1 connects");
    assert!(!n.store.is_genesis_ledger_txid(&tranches[0].txid).unwrap());

    let (n, r) = reopen(n);
    r.expect("the node starts");
    assert_eq!(n.store.get_meta(gnb::storage::GENESIS_LEDGER_INDEX_META).unwrap(), Some(vec![1]));
    for t in &tranches {
        assert!(n.store.is_genesis_ledger_txid(&t.txid).unwrap());
    }
    assert!(n.store.is_genesis_ledger_txid(&kept_c).unwrap(), "unspent carryover");
    assert!(n.store.is_genesis_ledger_txid(&spent_c).unwrap(), "carryover spent by an applied block");
    assert!(!n.store.is_genesis_ledger_txid(&spend.txid()).unwrap(), "created by a transaction");
    assert!(!n.store.is_genesis_ledger_txid(&b1.transactions[0].txid()).unwrap(), "a coinbase");
    assert_eq!(n.store.migrate_genesis_ledger_index().unwrap(), None, "once");
}

/// A genesis-ledger policy output is judged by the policy it commits to,
/// with its relative timelock counted from the genesis, in both regimes, on
/// the connect, mempool and template paths. (The shipped tranches' keys are
/// not test-derivable, so a test ledger holds a tranche whose policy has
/// both timelocks: `after = 2`, `older = 4`.)
#[test]
fn a_genesis_ledger_policy_output_is_judged_by_its_real_policy() {
    for (act, regime) in regimes() {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 100_000);
        let k = key();
        let policy = SpendPolicy::new(1, vec![k.pk.clone()], 2, 4).unwrap();
        let tranche = Tranche {
            role: Role::Founder, k: 1, unlock_height: 2, policy: policy.clone(), txid: [0x7E; 32], vout: 0,
            output: TxOutput { value: 1_000_000_000, script_pubkey: policy.script_pubkey() },
        };
        let n = ledger_node_with(&genesis, std::slice::from_ref(&tranche));
        let prev = (tranche.txid, tranche.vout, tranche.output.value);
        let mut tip = genesis.block_hash();
        for i in 0..2 {
            let b = empty_child(&n, tip, &format!("b{i}"));
            accept(&n, &b).unwrap();
            tip = b.block_hash();
        }
        // Next block: height 3, 3 confirmations of the genesis < older 4.
        let early = policy_spend(&k, &policy, prev, 2, 3);
        let err = admission::admit(&n.store, &n.mempool, early.clone(), &relay_policy(&n)).unwrap_err();
        assert!(format!("{err:?}").contains("relative timelock: 3 confirmations < 4"), "{regime}: {err:?}");
        let x = child_with(&n, tip, vec![early], "x", |_| true);
        let e = accept(&n, &x).expect_err("older not satisfied");
        assert!(e.contains("relative timelock: 3 confirmations < 4"), "{regime}: {e}");
        assert_eq!(n.store.invalid_block_reason(&x.block_hash()).unwrap().is_some(), act == 0, "{regime}");
        let b3 = empty_child(&n, tip, "b3");
        accept(&n, &b3).expect("the chain goes on");
        assert_eq!(applied_tip(&n), Some(b3.block_hash()));

        // Height 4: 4 confirmations, satisfied.
        let spend = policy_spend(&k, &policy, prev, 2, 4);
        admission::admit(&n.store, &n.mempool, spend.clone(), &relay_policy(&n))
            .unwrap_or_else(|e| panic!("{regime}: admitted at its height: {e:?}"));
        let tpl = build(&n).expect("template");
        assert!(tpl.transactions.iter().any(|(t, _)| t.txid() == spend.txid()), "{regime}: in the template");
        let y = child_with(&n, b3.block_hash(), vec![spend], "y", |_| true);
        accept(&n, &y).expect("older satisfied: connects");
        assert_eq!(applied_tip(&n), Some(y.block_hash()));
        assert!(n.store.get_utxo(&tranche.txid, 0).unwrap().is_none(), "{regime}: the tranche is spent");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// A true "no verdict" is never a silent permanent stall
// ═════════════════════════════════════════════════════════════════════════════

/// An inconsistent index (a policy output in the UTXO set with neither a
/// tx-index row nor a genesis-ledger row) under a fork-loser `B_nv` that
/// spends it with its real, correctly signed policy (`older = 1`): its
/// validation ends without a verdict.
struct NoVerdict {
    n: Node,
    t: BlockHash,
    b_nv: Block,
    a2: Block,
    prev: [u8; 32],
}

fn no_verdict_fixture() -> NoVerdict {
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
    let b_nv = child_with(&n, p.block_hash(), vec![policy_spend(&k, &policy, (prev, 0, value), 0, 2)], "nv",
        |h| *h < th);
    accept(&n, &b_nv).expect("fork-loser stored");
    let a2 = empty_child(&n, b_nv.block_hash(), "a2");
    NoVerdict { n, t: th, b_nv, a2, prev }
}

/// The move commits its rollback of `T`, then cannot judge `B_nv`: it
/// returns to `T` (HEAD stopped on `P`, an ancestor of both branches), marks
/// nothing (re-audit B1-T12), and parks `B_nv` with its descendants (review
/// of the hotfix, findings 1 and 2; `fix_no_verdict_hardening.rs`): `T` is
/// the selected tip again and templates are built on it. The failure is an
/// inconsistent index, not a storage-engine failure, so however often the
/// block is retried the node never stops (only repeated engine failures do,
/// `fix_no_verdict_hardening::repeated_storage_engine_failures_stop_the_node`),
/// and a restart starts, still on `T`.
#[test]
fn a_repeated_no_verdict_keeps_the_applied_tip_and_parks_the_block() {
    let _g = activation::scoped_override(0);
    let NoVerdict { n, t, b_nv, a2, .. } = no_verdict_fixture();

    let _ = accept(&n, &a2);
    assert_eq!(applied_tip(&n), Some(t), "back on the applied tip the move started from");
    assert_eq!(sel_tip(&n), Some(t), "no verdict: B_nv and A2 are parked");
    assert!(n.dag.read().is_no_verdict_parked(&b_nv.block_hash()));
    assert_eq!(build(&n).expect("templates on T").parents.first(), Some(&t));
    assert_eq!(n.store.invalid_block_reason(&b_nv.block_hash()).unwrap(), None, "B1-T12: no mark");
    assert!(n.store.abort_reason().is_none());

    let mut tip = a2.block_hash();
    for i in 1..=2 * accept::NO_VERDICT_ABORT_AFTER {
        accept::unpark_due_no_verdicts(&n.dag, &n.store,
            std::time::Instant::now() + std::time::Duration::from_secs(10 * 3600));
        let b = empty_child(&n, tip, &format!("c{i}"));
        let _ = accept(&n, &b);
        tip = b.block_hash();
        assert_eq!(applied_tip(&n), Some(t));
        assert_eq!(n.store.no_verdict_record(&b_nv.block_hash()).unwrap().attempts, 1 + i);
    }
    assert!(n.store.abort_reason().is_none(), "an inconsistent index never stops the node");
    assert_eq!(n.store.invalid_block_reason(&b_nv.block_hash()).unwrap(), None, "B1-T12: no mark");
    assert!(n.store.has_block_body(&b_nv.block_hash()).unwrap(), "body kept");

    // Restart: the start-up resolution parks B_nv again and the node starts
    // on T.
    let (n, r) = reopen(n);
    r.expect("an inconsistent index does not refuse the start");
    assert_eq!(applied_tip(&n), Some(t));
    assert!(n.dag.read().is_no_verdict_parked(&b_nv.block_hash()));
    assert_eq!(n.store.invalid_block_reason(&b_nv.block_hash()).unwrap(), None);
}

/// A no-verdict that clears (the index is repaired) leaves nothing behind:
/// the acceptance after the block's retry comes due connects the best chain
/// and the failure record goes.
#[test]
fn a_no_verdict_that_clears_leaves_no_trace() {
    let _g = activation::scoped_override(0);
    let NoVerdict { n, t, b_nv, a2, prev } = no_verdict_fixture();
    let _ = accept(&n, &a2);
    assert_eq!(applied_tip(&n), Some(t));
    // Repair: the output's confirmation point is known again.
    let genesis_hash: [u8; 32] = n.store.get_meta("genesis_hash").unwrap().unwrap().try_into().unwrap();
    n.store.put_tx_index(&prev, &genesis_hash, 0).unwrap();
    // B_nv is retried on a bounded schedule (1 minute first), not by every
    // acceptance: make the retry due.
    accept::unpark_due_no_verdicts(&n.dag, &n.store,
        std::time::Instant::now() + std::time::Duration::from_secs(3600));
    let c = empty_child(&n, a2.block_hash(), "c");
    accept(&n, &c).expect("the best chain connects");
    assert_eq!(applied_tip(&n), Some(c.block_hash()));
    for _ in 0..accept::NO_VERDICT_ABORT_AFTER {
        let d = empty_child(&n, applied_tip(&n).unwrap(), "d");
        accept(&n, &d).unwrap();
    }
    assert!(n.store.abort_reason().is_none());
    assert!(n.store.no_verdict_record(&b_nv.block_hash()).is_none(), "validated: the record goes");
    build(&n).expect("templates");
}
