//! Re-audit package R1a (phase 4): value and connect-time block rules.
//!
//! * B1-T1: the VAL-11 remediation added a block-wide output-total
//!   MoneyRange rule. Chained in-block spends move the same coins once per
//!   hop, so a valid block (and a valid template of a valid mempool chain)
//!   could exceed it; it applied at every height (changing pre-activation
//!   verdicts) and templates ignored it. Removed: Bitcoin Core bounds each
//!   transaction's output total and the accumulated fees, never the sum of
//!   all outputs of a block.
//!
//! Every block goes through the real acceptance pipeline
//! (`gnb::accept::accept_block`, after `validate_structure`); proofs of work
//! are recorded as verified (`Block::test_only_assume_pow_valid`, dev-only
//! `test-pow-limit`).

mod fix_common;
use fix_common::*;

use gnb::core::{self, activation, Transaction, TxOutput};
use gnb::mempool::admission::{self, AdmissionPolicy};
use gnb::template;

/// 4,500,000 GNB: three hops of it sum above `MAX_SUPPLY_SAT` (12,500,000 GNB).
const BIG: u64 = 4_500_000 * core::tokenomics::SAT_PER_GNB;
const HOP_FEE: u64 = 100_000;

/// A chain of `keys.len() - 1` signed spends: hop i moves the previous
/// output (locked to `keys[i]`) to `keys[i + 1]`, paying `HOP_FEE`. Signed
/// for a block at `height` under the calling thread's activation height.
fn hop_chain(keys: &[Key], fund: &([u8; 32], u32, TxOutput), height: u64) -> Vec<Transaction> {
    let mut prev = (fund.0, fund.1, fund.2.clone());
    let mut out_txs = Vec::new();
    for i in 0..keys.len() - 1 {
        let next = out(prev.2.value - HOP_FEE, &keys[i + 1].spk);
        let tx = signed_spend_at(&keys[i], &[(prev.0, prev.1)], std::slice::from_ref(&prev.2), vec![next.clone()], height);
        prev = (tx.txid(), 0, next);
        out_txs.push(tx);
    }
    out_txs
}

/// B1-T1: on both sides of the activation, a mempool chain of three hops of
/// 4,500,000 GNB (each transaction in range, outputs summing to about
/// 13,500,000 GNB) is admitted, templated, assembled (the template
/// self-check) and accepted and connected by the real pipeline. Before the
/// fix `assemble_block` refused it ("block output total ... exceeds
/// MAX_SUPPLY_SAT") and so did `accept_block`: the miner retried the same
/// poisoned template every second while the chain stayed pooled.
#[test]
fn chained_spends_whose_outputs_sum_above_the_supply_are_valid_and_templated() {
    for act in [activation::NEVER, 0] {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 10_000);
        let keys: Vec<Key> = (0..4).map(|_| key()).collect();
        let fund = ([0xB1u8; 32], 0u32, out(BIG, &keys[0].spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let height = admission::next_block_height(&n.dag.read());
        let chain = hop_chain(&keys, &fund, height);
        let total: u128 = chain.iter().flat_map(|t| &t.outputs).map(|o| u128::from(o.value)).sum();
        assert!(total > u128::from(core::tokenomics::MAX_SUPPLY_SAT), "outputs sum above the supply: {total}");
        for t in &chain {
            assert!(core::limits::check_tx_money_range(t).is_ok(), "each transaction is in range");
            admission::admit(&n.store, &n.mempool, t.clone(), &AdmissionPolicy::relay(height))
                .unwrap_or_else(|e| panic!("act {act}: hop admitted: {e}"));
        }

        let miner = vec![0xCB; 20];
        let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::miner_coinbase_reserve(&miner)).unwrap();
        assert_eq!(tmpl.transactions.len(), 3, "act {act}: the whole chain, parents first");
        assert_eq!(tmpl.total_fees, 3 * HOP_FEE);
        let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, miner.clone());
        let block = template::assemble_block(&tmpl, cb, unix_now())
            .unwrap_or_else(|e| panic!("act {act}: the template self-check refused a valid block: {e}"));
        assert_eq!(core::limits::check_block_context_free(&block), Ok(()));
        block.test_only_assume_pow_valid();
        accept(&n, &block).unwrap_or_else(|e| panic!("act {act}: accept_block: {e}"));
        assert_eq!(applied_tip(&n), Some(block.block_hash()), "act {act}: connected");
        assert!(n.store.get_utxo(&chain[2].txid(), 0).unwrap().is_some());
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
        assert_eq!(n.mempool.size(), 0);
    }
}

// ── B1-T12: storage read failures are never consensus verdicts ─────────────

/// Overwrite one row of a column family with bytes that do not decode
/// (a corrupted record, as after a checksum or decode failure).
fn corrupt_row(n: &Node, cf: &str, key: &[u8], bytes: &[u8]) {
    let db = n.store.db();
    db.put_cf(db.cf_handle(cf).expect("column family"), key, bytes).unwrap();
}

fn utxo_row_key(txid: &[u8; 32], index: u32) -> Vec<u8> {
    let mut k = txid.to_vec();
    k.extend_from_slice(&index.to_le_bytes());
    k
}

/// Make every block parked without a verdict due for its retry (the
/// schedule is 1 minute doubling to 1 hour), so the next acceptance
/// validates it again.
fn retry_due(n: &Node) {
    gnb::accept::unpark_due_no_verdicts(&n.dag, &n.store,
        std::time::Instant::now() + std::time::Duration::from_secs(10 * 3600));
}

/// Nothing about `id` was persisted or remembered as a verdict.
fn assert_no_verdict(n: &Node, id: &gnb::consensus::BlockHash, what: &str) {
    assert!(n.store.invalid_block_reason(id).unwrap().is_none(), "{what}: no persisted invalid mark");
    assert!(n.store.load_invalid_blocks().unwrap().is_empty(), "{what}");
    assert!(!n.dag.read().is_invalid_persistently(id), "{what}: not disqualified");
}

/// B1-T12: a UTXO row that cannot be read while a block is connected (I/O
/// error, corruption) must not become a consensus verdict. Before the fix the
/// read error went through `From<String> for TxFailure` as an id-committed
/// failure: the honest block was disqualified and `invalid_block/<id>` was
/// persisted (it survived restarts). Now nothing is committed, nothing is
/// remembered, and the block connects once the row reads again. The same for
/// the BIP30 read of the block's own outpoints (at/after the activation).
#[test]
fn utxo_read_failure_while_connecting_is_not_a_verdict() {
    // Below the activation: the input lookup.
    {
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let fund = ([0xC1u8; 32], 0u32, out(5_000_000, &k.spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let tx = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
        let b = mk_block(&n, vec![gh], vec![coinbase("t12", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0x9B; 20]), tx]);
        let id = b.block_hash();
        corrupt_row(&n, "utxo", &utxo_row_key(&fund.0, 0), &[0xFF, 0xFF, 0xFF]);
        let err = accept(&n, &b).expect_err("cannot be validated while the row is unreadable");
        assert!(!err.contains("invalid in its own chain context"), "not a verdict: {err}");
        assert_no_verdict(&n, &id, "input lookup");
        assert_eq!(applied_tip(&n), Some(gh));
        // Review of the F1 hotfix: kept (with its body) and parked, retried
        // on a bounded schedule rather than deleted and re-downloaded.
        assert!(n.dag.read().is_no_verdict_parked(&id) && n.store.has_block_body(&id).unwrap());
        let db = n.store.db();
        db.delete_cf(db.cf_handle("utxo").unwrap(), utxo_row_key(&fund.0, 0)).unwrap();
        n.store.put_utxo(&fund.0, 0, &fund.2).unwrap();
        retry_due(&n);
        let c = empty_child(&n, id, "t12-next");
        accept(&n, &c).expect("the next block, once the row reads again and the retry is due");
        assert_eq!(applied_tip(&n), Some(c.block_hash()), "B connected with it");
    }
    // At/after the activation: BIP30 reads every outpoint the block creates.
    {
        let _g = activation::scoped_override(0);
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        let b = mk_block(&n, vec![gh], vec![coinbase("t12-bip30", core::tokenomics::block_subsidy_sat(1), vec![0x9C; 20])]);
        let id = b.block_hash();
        let cb = b.transactions[0].txid();
        corrupt_row(&n, "utxo", &utxo_row_key(&cb, 0), &[0xFF, 0xFF, 0xFF]);
        let err = accept(&n, &b).expect_err("BIP30 cannot be evaluated");
        assert!(!err.contains("invalid in its own chain context"), "not a verdict: {err}");
        assert_no_verdict(&n, &id, "BIP30 lookup");
        assert!(n.dag.read().is_no_verdict_parked(&id) && n.store.has_block_body(&id).unwrap());
        let db = n.store.db();
        db.delete_cf(db.cf_handle("utxo").unwrap(), utxo_row_key(&cb, 0)).unwrap();
        retry_due(&n);
        let c = empty_child(&n, id, "t12-bip30-next");
        accept(&n, &c).expect("the next block, once the row is gone and the retry is due");
        assert_eq!(applied_tip(&n), Some(c.block_hash()), "B connected with it");
    }
}

/// B1-T12 (reorg.rs:819): the connect batch captures each spent coin for the
/// undo record before deleting it, with a validator that reads nothing. The
/// capture used to skip a failed read (`if let Ok(Some(..))`); the deletion
/// right after it re-reads the same row and already failed closed, so that
/// skip was not reachable on its own (a mutation restoring it passes this
/// test). The capture now propagates the error itself. Guarded property: an
/// unreadable spent coin fails the connect as a storage failure and no undo
/// record is written.
#[test]
fn undo_capture_read_failure_fails_the_connect() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xC2u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let tx = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
    let b = mk_block(&n, vec![gh], vec![coinbase("t12-undo", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0x9B; 20]), tx]);
    n.store.put_block_body(&b).unwrap();
    corrupt_row(&n, "utxo", &utxo_row_key(&fund.0, 0), &[0xFF, 0xFF, 0xFF]);
    let plan = gnb::reorg::ReorgPlan { lca: gh, to_rollback: vec![], to_apply: vec![b.block_hash()] };
    // A validator that does not read the view (the batch's own reads remain).
    let validate = |_: &dyn gnb::reorg::UtxoView, _: &core::Block| -> Result<(), gnb::reorg::ValidationFailure> { Ok(()) };
    let none = |_: &gnb::storage::Storage, _: &mut rocksdb::WriteBatch| -> Result<(), String> { Ok(()) };
    let r = gnb::reorg::connect_plan(&n.store, &plan, &gnb::reorg::ConnectHooks { validate: &validate, stage_extra: &none });
    match r {
        Err(gnb::reorg::ConnectError::Failed(m)) => assert!(m.contains("get_utxo"), "{m}"),
        other => panic!("the apply must fail on the unreadable coin: {:?}", other.map(|o| o.connected.len())),
    }
    assert!(n.store.get_undo_data(&b.block_hash()).unwrap().is_none(), "no undo record written");
}

/// B1-T12 (review): the legacy direct apply
/// (`reorg::apply_block_utxo_mutations`) captures each spent coin before
/// `Storage::delete_utxo`, which deletes a row it cannot decode WITHOUT
/// failing. With the capture skipping a failed read (`if let Ok(Some(..))`,
/// the code before B1-T12) the apply wrote an undo record without the coin
/// (a rollback could never restore it) and returned Ok. It must fail and
/// write no undo record. (The connect batch's capture, guarded by
/// `undo_capture_read_failure_fails_the_connect`, is followed by a deletion
/// that re-reads the row through the same overlay read and fails with the
/// same error, so a skip there is not observable without fault injection.)
#[test]
fn direct_apply_undo_capture_read_failure_fails_the_apply() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xC4u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let tx = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
    let b = mk_block(&n, vec![gh], vec![coinbase("t12-direct", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0x9B; 20]), tx]);
    corrupt_row(&n, "utxo", &utxo_row_key(&fund.0, 0), &[0xFF, 0xFF, 0xFF]);
    let err = gnb::reorg::apply_block_utxo_mutations(&n.store, &b).expect_err("the spent coin cannot be captured");
    assert!(err.contains("get_utxo failed"), "{err}");
    assert!(n.store.get_undo_data(&b.block_hash()).unwrap().is_none(), "no undo record written");
}

/// B1-T12: a coinbase-height row that cannot be read must never look like
/// "not a coinbase". Before the fix (`.ok().flatten()`, and a row of the
/// wrong length read as absent) the maturity check was skipped and a block
/// spending a 1-block-old coinbase was accepted and applied, a block every
/// other node rejects. Now nothing is committed; once the row reads again
/// the block is rejected for its immature spend, as everywhere else.
#[test]
fn coinbase_height_read_failure_never_skips_maturity() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let n = node_with(&genesis, &[]);
    let b1 = mk_block(&n, vec![gh], vec![coinbase("t12-cb", core::tokenomics::block_subsidy_sat(1), k.spk.clone())]);
    accept(&n, &b1).unwrap();
    let cb = b1.transactions[0].txid();
    assert_eq!(n.store.get_coinbase_height(&cb).unwrap(), Some(1));
    let spend = signed_spend(&k, &[(cb, 0)], vec![out(core::tokenomics::block_subsidy_sat(1) - 100_000, &[0x9D; 20])]);
    let b2 = mk_block(&n, vec![b1.block_hash()],
        vec![coinbase("t12-spend", core::tokenomics::block_subsidy_sat(2) + 100_000, vec![0x9E; 20]), spend]);
    let id = b2.block_hash();
    corrupt_row(&n, "coinbase", &cb, &[0x01, 0x02, 0x03]);
    let err = accept(&n, &b2).expect_err("an immature spend is never accepted");
    assert!(!err.contains("invalid in its own chain context"), "not a verdict while unreadable: {err}");
    assert_no_verdict(&n, &id, "coinbase height lookup");
    assert_eq!(applied_tip(&n), Some(b1.block_hash()), "not applied");
    n.store.put_coinbase_info(&cb, 1).unwrap();
    // Review of the F1 hotfix: B2 is kept and parked without a verdict, and
    // judged at its (bounded) retry, not by a re-sent copy.
    assert!(n.dag.read().is_no_verdict_parked(&id));
    retry_due(&n);
    let c = empty_child(&n, id, "t12-cb-next");
    let _ = accept(&n, &c);
    let reason = n.store.invalid_block_reason(&id).unwrap().expect("now a genuine verdict, persisted");
    assert!(reason.contains("coinbase maturity"), "immature: {reason}");
    assert_eq!(applied_tip(&n), Some(b1.block_hash()));
}

// ── B1-T13: classify witness-dependent failures by curability ──────────────

fn subsidy(h: u64) -> u64 {
    core::tokenomics::block_subsidy_sat(h)
}

/// A block on genesis carrying `txs`, its coinbase claiming the subsidy plus
/// `fees`.
fn block_with_txs(n: &Node, gh: gnb::consensus::BlockHash, tag: &str, fees: u64, txs: Vec<Transaction>) -> core::Block {
    let mut all = vec![coinbase(tag, subsidy(1) + fees, vec![0xC3; 20])];
    all.extend(txs);
    mk_block(n, vec![gh], all)
}

/// The connect-time verdict of `b` on `n`'s state (below the activation).
fn classify_below(n: &Node, b: &core::Block) -> gnb::accept::BlockInvalidity {
    let view: &gnb::storage::Storage = &n.store;
    match gnb::accept::validate_block_in_view_classified_at(view, b, activation::NEVER) {
        Err(gnb::accept::ConnectFailure::Invalid(e)) => e,
        other => panic!("expected a verdict, got {other:?}"),
    }
}

/// B1-T13: below the activation a failure that NO body with the same block
/// id can cure is id-committed: the block is disqualified and the mark
/// persisted, like any other consensus failure. Before the fix every script
/// and minimum-fee failure was "witness-dependent", so such a block (and its
/// descendants) waited for another body forever and every re-malleated copy
/// was re-validated. Incurable here: a fee below the size-independent floor
/// (MIN_TX_FEE_SAT), a transaction without inputs (its fee is 0), a spend of
/// a coin whose script is not 20 bytes (no public key hashes to it), and a
/// block whose first failure is a bad signature but which also spends more
/// than it has in a later transaction (id-committed checks of the whole
/// block run before any witness check).
#[test]
fn incurable_failures_below_the_activation_are_id_committed() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xD1u8; 32], 0u32, out(5_000_000, &k.spk));
    let fund2 = ([0xD2u8; 32], 0u32, out(5_000_000, &k.spk));
    let odd = ([0xD3u8; 32], 0u32, out(5_000_000, &[0x55; 5]));
    let funds = [fund.clone(), fund2.clone(), odd.clone()];
    let pay = |v: u64| vec![out(v, &[0x9A; 20])];

    let mut bad_sig = signed_spend(&k, &[(fund.0, 0)], pay(4_900_000));
    bad_sig.inputs[0].script_sig[100] ^= 0x01;
    let overspend = signed_spend(&k, &[(fund2.0, 0)], pay(5_000_001));
    let cases: Vec<(&str, Vec<Transaction>, u64, &str)> = vec![
        ("fee of 1 below the 10,000 floor", vec![signed_spend(&k, &[(fund.0, 0)], pay(4_999_999))], 1, "below consensus minimum"),
        ("transaction without inputs", vec![Transaction { version: 1, inputs: vec![], outputs: vec![], locktime: 0 }], 0, "below consensus minimum"),
        ("coin locked to a 5-byte script", vec![signed_spend(&k, &[(odd.0, 0)], pay(4_900_000))], 100_000, "pubkey mismatch"),
        ("bad signature, then an overspend", vec![bad_sig, overspend], 100_000, "inputs"),
    ];
    for (what, txs, fees, fragment) in cases {
        let n = node_with(&genesis, &funds);
        let b = block_with_txs(&n, gh, what, fees, txs);
        let e = classify_below(&n, &b);
        assert!(e.reason.contains(fragment), "{what}: {e:?}");
        assert!(!e.witness_dependent, "{what}: no body with this id can be valid: {e:?}");
        let err = accept(&n, &b).expect_err(what);
        assert!(err.contains("invalid in its own chain context"), "{what}: {err}");
        assert!(n.dag.read().is_invalid_persistently(&b.block_hash()), "{what}: disqualified");
        assert!(!n.dag.read().is_body_pending(&b.block_hash()), "{what}: not waiting for a body");
        assert!(n.store.invalid_block_reason(&b.block_hash()).unwrap().is_some(), "{what}: persisted");
    }
}

/// The curable failures stay witness-dependent below the activation (another
/// body with the same id can be valid): a bad signature alone, and a fee at
/// or above the floor but below the size-based minimum of this body (a body
/// with shorter witnesses can meet it).
#[test]
fn curable_failures_below_the_activation_stay_witness_dependent() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xD4u8; 32], 0u32, out(5_000_000, &k.spk));
    let pay = |v: u64| vec![out(v, &[0x9A; 20])];
    let mut bad_sig = signed_spend(&k, &[(fund.0, 0)], pay(4_900_000));
    bad_sig.inputs[0].script_sig[100] ^= 0x01;
    let low_fee = signed_spend(&k, &[(fund.0, 0)], pay(5_000_000 - 12_000));
    assert!(core::tokenomics::min_tx_fee_sat(low_fee.to_wire_bytes(true).len()) > 12_000);
    for (what, tx, fees, fragment) in [
        ("bad signature", bad_sig, 100_000, "invalid signature"),
        ("fee above the floor, below this body's minimum", low_fee, 12_000, "below consensus minimum"),
    ] {
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let b = block_with_txs(&n, gh, what, fees, vec![tx]);
        let e = classify_below(&n, &b);
        assert!(e.reason.contains(fragment) && e.witness_dependent, "{what}: {e:?}");
        accept(&n, &b).expect_err(what);
        assert!(n.dag.read().is_body_pending(&b.block_hash()), "{what}: waits for another body");
        assert!(n.store.invalid_block_reason(&b.block_hash()).unwrap().is_none(), "{what}: nothing persisted");
    }
}

/// B1-T13: a block whose body was rejected for a witness-dependent reason
/// waits for another body, but its body is WANTED (requested and chased from
/// peers) only while the chain through it can become the best one: a tip on
/// it is heavier than the selected tip (Bitcoin Core downloads blocks of the
/// best header chain only). Before the fix it was chased forever, so each
/// such block (one block of proof of work) held a body-pull slot and every
/// re-malleated answer re-validated it, however far the honest chain moved
/// on. Once the honest chain is heavier the pulls stop; if the waiting branch
/// grows heavier again they resume.
#[test]
fn wanted_bodies_are_bounded_by_the_best_chain() {
    use gnb::ingress::{awaited_bodies_to_chase, awaited_bodies_to_request};
    use gnb::sync::parent_fetch::ParentFetchTracker;
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xD5u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let m1 = empty_child(&n, gh, "main-1");
    accept(&n, &m1).unwrap();
    let mut bad = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
    bad.inputs[0].script_sig[100] ^= 0x01;
    let f = block_with_txs(&n, gh, "fork", 100_000, vec![bad]);
    // Equal weight to m1: stored unevaluated as a fork-loser, or (when it
    // wins the hash tie-break) evaluated and its body rejected right away.
    let _ = accept(&n, &f);
    let g = empty_child(&n, f.block_hash(), "fork-child");
    let _ = accept(&n, &g); // stored; the branch is evaluated and waits for F's body
    assert!(n.dag.read().is_body_pending(&f.block_hash()));
    let tracker = ParentFetchTracker::new();
    let wanted = |n: &Node| awaited_bodies_to_request(&n.dag.read(), &tracker, 64);
    let chased = |n: &Node| awaited_bodies_to_chase(&n.dag.read(), &tracker, 64);
    assert_eq!(wanted(&n), vec![f.block_hash()], "the waiting branch is the heaviest");
    assert_eq!(chased(&n), vec![f.block_hash()]);

    // The honest chain moves on: three blocks against the branch's two.
    let m2 = empty_child(&n, m1.block_hash(), "main-2");
    accept(&n, &m2).unwrap();
    let m3 = empty_child(&n, m2.block_hash(), "main-3");
    accept(&n, &m3).unwrap();
    assert!(n.dag.read().is_body_pending(&f.block_hash()), "still waiting (in memory, never persisted)");
    assert!(wanted(&n).is_empty(), "no longer requested: the honest chain is heavier");
    assert!(chased(&n).is_empty(), "no longer chased");
    // ... and a copy that arrives anyway is known (an unrequested low-work
    // block in Bitcoin Core): it is not validated again.
    assert!(!gnb::accept::awaits_body(&n.dag, &n.store, &f.block_hash()));
    let err = accept(&n, &f).expect_err("known");
    assert!(err.contains("already in DAG"), "{err}");

    // The waiting branch grows heavier again: its body is wanted again.
    let g2 = empty_child(&n, g.block_hash(), "fork-2");
    accept(&n, &g2).unwrap();
    let g3 = empty_child(&n, g2.block_hash(), "fork-3");
    accept(&n, &g3).unwrap();
    assert_eq!(wanted(&n), vec![f.block_hash()]);
    assert!(gnb::accept::awaits_body(&n.dag, &n.store, &f.block_hash()));
}

// ── B1-T14: coinbase maturity counts selected-chain blocks from the activation

/// A store holding one coin (output 0, 5,000,000) of the coinbase of block
/// C (header height `cb_header`, DAG height `cb_dag`: its coinbase-height
/// row, its tx-index row and its DAG record, as a node applies it), and the
/// DAG records of two blocks a spending block S lists as parents: `sel`
/// (DAG height `sel_dag`, the heavier: S's selected parent, the applied tip)
/// and `side` (DAG height `side_dag`, lighter). S's header height is
/// `max(sel_dag, side_dag) + 1`, its DAG height `sel_dag + 1`.
struct MaturityFixture {
    _tmp: tempfile::TempDir,
    store: gnb::storage::Storage,
    coin: ([u8; 32], u32, TxOutput),
    parents: Vec<gnb::consensus::BlockHash>,
    header_height: u64,
}

fn maturity_fixture(k: &Key, cb_header: u64, cb_dag: u64, sel_dag: u64, side_dag: u64) -> MaturityFixture {
    use gnb::consensus::GhostdagData;
    let tmp = tempfile::TempDir::new().unwrap();
    let store = gnb::storage::Storage::open(&tmp.path().join("db")).unwrap();
    let record = |height: u64, blue_work: u128| {
        let mut d = GhostdagData::genesis();
        d.height = height;
        d.blue_score = height;
        d.blue_work = blue_work;
        d
    };
    let (c, sel, side) = ([0xC1u8; 32], [0xC2u8; 32], [0xC3u8; 32]);
    let cb_txid = [0xCBu8; 32];
    let coin = (cb_txid, 0u32, out(5_000_000, &k.spk));
    store.put_dag_data(&c, &record(cb_dag, 10)).unwrap();
    store.put_dag_data(&sel, &record(sel_dag, 1_000_000)).unwrap();
    store.put_dag_data(&side, &record(side_dag, 1)).unwrap();
    store.put_tx_index(&cb_txid, &c, cb_header).unwrap();
    store.put_utxo(&coin.0, coin.1, &coin.2).unwrap();
    store.put_coinbase_info(&cb_txid, cb_header).unwrap();
    store.put_meta("tip_hash", &sel).unwrap();
    MaturityFixture { _tmp: tmp, store, coin, parents: vec![sel, side], header_height: sel_dag.max(side_dag) + 1 }
}

/// A block S on `f`'s two parents spending `f`'s coin, signed under the
/// calling thread's activation height.
fn maturity_spend(k: &Key, f: &MaturityFixture) -> (core::Block, Transaction) {
    let h = f.header_height;
    let spend = signed_spend_at(k, &[(f.coin.0, f.coin.1)], std::slice::from_ref(&f.coin.2),
        vec![out(4_900_000, &[0x9A; 20])], h);
    let block = core::Block {
        header: core::BlockHeader {
            version: 1, parents: f.parents.clone(), merkle_root: core::MerkleRoot::ZERO,
            timestamp: 0, bits: 0, nonce: 0,
        },
        transactions: vec![coinbase("t14", subsidy(h) + 100_000, vec![0xC4; 20]), spend.clone()],
        blue_score: h,
        height: h,
        shielded_transactions: vec![],
        powit: Default::default(),
    };
    (block, spend)
}

/// B1-T14: the header height is `max(parent DAG heights) + 1`, so a block
/// that merges a long, light side tip has a header height far above its
/// position on its selected chain, and its selected-chain descendants repeat
/// lower header heights. Maturity compared header heights, so such a block
/// could spend a coinbase with a handful of confirmations (case "merge").
/// From the activation the rule counts selected-chain blocks: the spending
/// block's DAG height minus the DAG height of the coinbase's block (Bitcoin
/// Core compares chain positions). Below the activation the header-height
/// rule is kept exactly, in both directions (case "inflated coinbase
/// header": a coinbase whose own block merged a high tip is immature longer
/// under it). Mempool admission (and so the templates, which re-check
/// through it) follows the same rule for the next block on the applied tip.
#[test]
fn coinbase_maturity_counts_selected_chain_blocks_from_the_activation() {
    let k = key();
    // (case, C header, C DAG, sel DAG, side DAG, valid below, valid from the activation)
    let cases = [
        ("merge: header depth 100, 10 selected-chain blocks", 1, 1, 10, 100, true, false),
        ("100 selected-chain blocks", 1, 1, 100, 5, true, true),
        ("99 selected-chain blocks", 1, 1, 99, 5, false, false),
        ("inflated coinbase header: header depth 51, 100 selected-chain blocks", 50, 1, 100, 5, false, true),
    ];
    for (what, cb_header, cb_dag, sel_dag, side_dag, below, from) in cases {
        let f = maturity_fixture(&k, cb_header, cb_dag, sel_dag, side_dag);
        let view: &gnb::storage::Storage = &f.store;
        for (act, valid) in [(activation::NEVER, below), (1, from)] {
            let _g = activation::scoped_override(act);
            let (b, spend) = maturity_spend(&k, &f);
            let connect = gnb::accept::validate_block_in_view_classified_at(view, &b, act);
            match (&connect, valid) {
                (Ok(()), true) => {}
                (Err(gnb::accept::ConnectFailure::Invalid(e)), false) => {
                    assert!(e.reason.contains("coinbase maturity"), "{what} (act {act}): {e:?}");
                    assert!(!e.witness_dependent, "{what}");
                }
                _ => panic!("{what} (activation {act}): expected valid={valid}, got {connect:?}"),
            }
            let adm = admission::check_transaction(&f.store, None, &spend, &AdmissionPolicy::relay(f.header_height));
            match (&adm, valid) {
                (Ok(_), true) => {}
                (Err(admission::AdmissionError::Immature(_)), false) => {}
                _ => panic!("{what} (activation {act}): admission expected valid={valid}, got {adm:?}"),
            }
        }
    }
}

/// B1-T14, producers: the template self-check
/// (`admission::coinbase_maturity_for_next_block`, also mempool admission and
/// the post-connect revalidation) and the `getutxos` value the wallets compare
/// (`admission::coinbase_height_for_wallets`: spendable in the next block iff
/// `next_block_height - coinbase_height >= COINBASE_MATURITY`) follow the
/// rule in force for the next block's header height: header heights for a
/// next block at H-1 (H the activation), selected-chain depth at H.
#[test]
fn producers_follow_the_maturity_rule_of_the_next_block_height() {
    let k = key();
    // Applied tip at DAG height 10 (the next block's selected parent), a
    // side tip at DAG height 100: a next block merging both has header
    // height 101 and DAG height 11; the coinbase is at height 1.
    let (cb_header, cb_dag, sel_dag, side_dag) = (1, 1, 10, 100);
    let f = maturity_fixture(&k, cb_header, cb_dag, sel_dag, side_dag);
    let next = f.header_height;
    for (activation_h, mature) in [(next + 1, true), (next, false)] {
        let _g = activation::scoped_override(activation_h);
        let (_, spend) = maturity_spend(&k, &f);
        let verdict = admission::coinbase_maturity_for_next_block(&f.store, &spend, next).unwrap();
        assert_eq!(verdict.is_ok(), mature, "activation {activation_h}: template self-check {verdict:?}");
        let reported = admission::coinbase_height_for_wallets(&f.store, &f.coin.0, next).unwrap().expect("a coinbase");
        assert_eq!(next.saturating_sub(reported) >= core::COINBASE_MATURITY, mature,
            "activation {activation_h}: the wallets' comparison with coinbase_height {reported}");
        let expected = if mature { cb_header } else { next - (sel_dag + 1 - cb_dag) };
        assert_eq!(reported, expected, "activation {activation_h}");
    }
    // A transaction spending no coinbase reports no coinbase height.
    let _g = activation::scoped_override(next);
    assert_eq!(admission::coinbase_height_for_wallets(&f.store, &[0x77; 32], next).unwrap(), None);
}

/// B1-T14 (review), the template self-check call site
/// (`template::build_block_template` -> `self_check`): from the activation, a
/// pooled spend of a coinbase that is 100 selected-chain blocks deep but only
/// 51 header heights deep (case "inflated coinbase header") is mature for
/// the next block. Admission accepts it, and the template must include it:
/// a template still comparing header heights would evict it from the
/// mempool at every template, so this node would never mine it.
#[test]
fn template_includes_a_spend_mature_by_selected_chain_depth_from_the_activation() {
    let k = key();
    let f = maturity_fixture(&k, 50, 1, 100, 5);
    let next = f.header_height;
    assert_eq!(next, 101);
    let _g = activation::scoped_override(1);
    // The template's DAG: a chain whose tip, at DAG height 100 (so the next
    // header height is 101), has a body stored that passes the hardening
    // block rules (an eligible template parent).
    let mut d = gnb::consensus::GhostDAG::with_default_k();
    let id = |i: u32| {
        let mut x = [0x7Du8; 32];
        x[..4].copy_from_slice(&i.to_le_bytes());
        x
    };
    d.add_genesis(id(0), 1_000);
    for i in 1..100u32 {
        d.add_block(id(i), vec![id(i - 1)], 1_000 + i as u64, 1).unwrap();
    }
    let mut tip = core::Block {
        header: core::BlockHeader {
            version: 1, parents: vec![id(99)], merkle_root: core::MerkleRoot::ZERO,
            timestamp: 1_100, bits: core::GENESIS_BITS, nonce: 0,
        },
        transactions: vec![coinbase("t14-template-tip", subsidy(100), vec![0xC9; 20])],
        blue_score: 100,
        height: 100,
        shielded_transactions: vec![],
        powit: Default::default(),
    };
    commit_block(&mut tip);
    f.store.put_block_body(&tip).unwrap();
    d.add_block(tip.block_hash(), vec![id(99)], 1_100, 1).unwrap();
    let dag = std::sync::Arc::new(parking_lot::RwLock::new(d));

    let (_, spend) = maturity_spend(&k, &f);
    let mempool = gnb::mempool::Mempool::new();
    let txid = admission::admit(&f.store, &mempool, spend.clone(), &AdmissionPolicy::relay(next))
        .expect("mature by selected-chain depth: admitted");
    let tmpl = template::build_block_template(&dag, &f.store, &mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.height, next);
    assert!(tmpl.transactions.iter().any(|(t, _)| t.txid() == txid), "the template includes the spend");
    assert_eq!(tmpl.evicted, 0);
    assert!(mempool.get_tx(&txid).is_some(), "not evicted");
}

// ── This chain's rules (main's `blockval`) under B1-T12 / B1-T13 / B1-T14 ────

/// A 1-of-1 spend policy of `k` with relative timelock `older`.
fn older_policy(k: &Key, older: u32) -> core::policy::SpendPolicy {
    core::policy::SpendPolicy::new(1, vec![k.pk.clone()], 0, older).unwrap()
}

/// A signed spend of the policy coin `coin` (locked by `policy`) paying
/// 4,000,000 to a key hash (change back to the policy), for a block at
/// header height `height` under the calling thread's activation height
/// (version 1 / sighash v2 below it, version 3 / sighash v3 from it).
fn policy_spend_of(
    k: &Key,
    policy: &core::policy::SpendPolicy,
    coin: &([u8; 32], u32, TxOutput),
    height: u64,
) -> Transaction {
    use gnb::core::sighash::SighashVersion;
    let mut s = gnb::wallet::policy_spend::PolicySpend::new(
        gnb::address::Network::Mainnet, policy.clone(), &[(coin.0, coin.1, coin.2.value)],
        vec![0x9A; 20], 4_000_000, 0, 0,
    ).unwrap();
    s.target_height(height).unwrap();
    s.sign_digest(&k.pk, |d, v| match v {
        SighashVersion::V2 => gnb::crypto::sign(&k.sk, d),
        SighashVersion::V3 => gnb::crypto::sign_bound(&k.sk, d),
    }.map_err(|e| format!("{e:?}"))).unwrap();
    s.finalize().unwrap()
}

/// B1-T13 with this chain's rules (main's `blockval`, enforced at every
/// height): their failures are classified by curability like every other
/// connect failure. Locktime finality and the output kinds read only data
/// the txid commits to: id-committed (disqualified and persisted). The
/// policy-spend rules (timelocks, branch, framing) read the policy the
/// `script_sig` reveals, so below `WITNESS_COMMITMENT_HEIGHT` (and the
/// activation) another witness may cure them: witness-dependent (the block
/// waits for another body, nothing persisted). Main classified every one of
/// them id-committed (`From<String>`), so a relay that altered a policy
/// witness of an honest block below 5,000 disqualified its id for good. From
/// `WITNESS_COMMITMENT_HEIGHT` the `|wc:` suffix commits every witness and
/// all of them are id-committed.
#[test]
fn chain_rule_failures_are_classified_by_curability() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xE1u8; 32], 0u32, out(5_000_000, &k.spk));
    let policy = older_policy(&k, 60_000);
    let pcoin = ([0xE2u8; 32], 0u32, out(5_000_000, &policy.script_pubkey()));
    let funds = [fund.clone(), pcoin.clone()];
    let mut non_final = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
    non_final.locktime = 1_000_000;
    let bad_kind = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x55; 5])]);
    let timelocked = policy_spend_of(&k, &policy, &pcoin, 1);
    let mut malformed = timelocked.clone();
    malformed.inputs[0].script_sig = vec![0x02, 0xFF];
    let cases = [
        ("locktime above the block height", non_final, "non-final", false),
        ("an output of neither kind", bad_kind, "unsupported script_pubkey", false),
        ("a relative timelock the revealed policy does not meet", timelocked, "relative timelock", true),
        ("a malformed policy witness", malformed, "malformed policy witness", true),
    ];
    for (what, tx, fragment, curable) in cases {
        let n = node_with(&genesis, &funds);
        n.store.put_tx_index(&pcoin.0, &gh, 0).unwrap(); // the policy coin, confirmed at height 0
        let b = block_with_txs(&n, gh, what, 0, vec![tx]);
        let e = classify_below(&n, &b);
        assert!(e.reason.contains(fragment), "{what}: {e:?}");
        assert_eq!(e.witness_dependent, curable, "{what}: {e:?}");
        accept(&n, &b).expect_err(what);
        let id = b.block_hash();
        if curable {
            assert!(n.dag.read().is_body_pending(&id), "{what}: waits for another body");
            assert!(n.store.invalid_block_reason(&id).unwrap().is_none(), "{what}: nothing persisted");
        } else {
            assert!(n.dag.read().is_invalid_persistently(&id), "{what}: disqualified");
            assert!(n.store.invalid_block_reason(&id).unwrap().is_some(), "{what}: persisted");
        }
        // The same transaction in a block at WITNESS_COMMITMENT_HEIGHT (below
        // the activation): the block id commits to the witnesses.
        let h = core::WITNESS_COMMITMENT_HEIGHT;
        let mut hb = b.clone();
        hb.height = h;
        hb.blue_score = h;
        hb.transactions[0] = coinbase(what, subsidy(h), vec![0xC3; 20]);
        let view: &gnb::storage::Storage = &n.store;
        match gnb::accept::validate_block_in_view_classified_at(view, &hb, activation::NEVER) {
            Err(gnb::accept::ConnectFailure::Invalid(e)) => {
                assert!(e.reason.contains(fragment) && !e.witness_dependent, "{what} at {h}: {e:?}");
            }
            other => panic!("{what} at {h}: expected a verdict, got {other:?}"),
        }
    }
}

/// B1-T12 with main's relative timelocks: the confirmation height of a
/// spent policy output is read from the tx index while the block is
/// connected. A row that cannot be read (or a confirmed coin without one,
/// an inconsistent index) is a storage failure: no verdict, nothing
/// persisted, and the block is judged once the row reads (main mapped the
/// `storage:` error through `From<String>` into an id-committed verdict).
#[test]
fn relative_timelock_confirmation_read_failure_is_not_a_verdict() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let policy = older_policy(&k, 60_000);
    let pcoin = ([0xE3u8; 32], 0u32, out(5_000_000, &policy.script_pubkey()));
    let n = node_with(&genesis, std::slice::from_ref(&pcoin));
    let b = block_with_txs(&n, gh, "t12-older", 0, vec![policy_spend_of(&k, &policy, &pcoin, 1)]);
    let id = b.block_hash();
    let view: &gnb::storage::Storage = &n.store;
    for (what, row) in [("no tx-index row", None), ("a tx-index row that does not decode", Some(vec![1u8, 2, 3]))] {
        if let Some(bytes) = &row {
            corrupt_row(&n, "tx_index", &pcoin.0, bytes);
        }
        match gnb::accept::validate_block_in_view_classified_at(view, &b, activation::NEVER) {
            Err(gnb::accept::ConnectFailure::Storage(m)) => {
                let m = m.to_string();
                assert!(m.contains("storage") || m.contains("tx-index"), "{what}: {m}")
            }
            other => panic!("{what}: expected a storage failure, got {other:?}"),
        }
        // The first case parks B (kept, not marked); the second meets it
        // in the DAG and is retried there once due.
        retry_due(&n);
        let err = if n.dag.read().has_block(&id) {
            let c = empty_child(&n, id, &format!("t12-older-{what}"));
            let _ = accept(&n, &c);
            assert_eq!(applied_tip(&n), Some(gh), "{what}");
            n.store.no_verdict_record(&id).expect("no verdict recorded").reason
        } else {
            accept(&n, &b).expect_err(what)
        };
        assert!(!err.contains("invalid in its own chain context"), "{what}: not a verdict: {err}");
        assert_no_verdict(&n, &id, what);
        assert!(!n.dag.read().is_body_pending(&id), "{what}: not waiting for another body either");
        assert!(n.dag.read().is_no_verdict_parked(&id), "{what}: parked without a verdict");
    }
    n.store.put_tx_index(&pcoin.0, &gh, 0).unwrap();
    let e = classify_below(&n, &b);
    assert!(e.reason.contains("relative timelock") && e.witness_dependent, "once readable, judged: {e:?}");
}

/// B1-T14 with main's relative timelocks (`older` of a spend policy): a
/// relative timelock counts confirmations of the spent output, exactly what
/// coinbase maturity counts, and had the same defect (header heights, which
/// a block merging a long light side tip inflates). One measure decides
/// both (`accept::MaturityRule`, `confirmations_in_view`): below the
/// activation header heights (main's rule, kept exactly), from it the
/// selected-chain depth: the spending block's DAG height minus the DAG
/// height of the block that confirmed the output. Connect and mempool
/// admission (the template self-check reads the same
/// `admission::confirmations_for_next_block`) agree in both regimes.
#[test]
fn relative_timelocks_count_selected_chain_blocks_from_the_activation() {
    use gnb::consensus::GhostdagData;
    let k = key();
    let policy = older_policy(&k, core::COINBASE_MATURITY as u32);
    // (case, C header, C DAG, sel DAG, side DAG, valid below, valid from the activation)
    let cases = [
        ("merge: header age 100, 10 selected-chain blocks", 1, 1, 10, 100, true, false),
        ("inflated confirming header: header age 51, 100 selected-chain blocks", 50, 1, 100, 5, false, true),
        ("99 selected-chain blocks", 1, 1, 99, 5, false, false),
    ];
    for (what, c_header, c_dag, sel_dag, side_dag, below, from) in cases {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = gnb::storage::Storage::open(&tmp.path().join("db")).unwrap();
        let record = |height: u64, blue_work: u128| {
            let mut d = GhostdagData::genesis();
            d.height = height;
            d.blue_score = height;
            d.blue_work = blue_work;
            d
        };
        let (c, sel, side) = ([0xE4u8; 32], [0xE5u8; 32], [0xE6u8; 32]);
        let coin = ([0xE7u8; 32], 0u32, out(5_000_000, &policy.script_pubkey()));
        store.put_dag_data(&c, &record(c_dag, 10)).unwrap();
        store.put_dag_data(&sel, &record(sel_dag, 1_000_000)).unwrap();
        store.put_dag_data(&side, &record(side_dag, 1)).unwrap();
        store.put_tx_index(&coin.0, &c, c_header).unwrap();
        store.put_utxo(&coin.0, coin.1, &coin.2).unwrap();
        store.put_meta("tip_hash", &sel).unwrap();
        let h = sel_dag.max(side_dag) + 1;
        let view: &gnb::storage::Storage = &store;
        for (act, valid) in [(activation::NEVER, below), (1, from)] {
            let _g = activation::scoped_override(act);
            let spend = policy_spend_of(&k, &policy, &coin, h);
            let b = core::Block {
                header: core::BlockHeader {
                    version: 1, parents: vec![sel, side], merkle_root: core::MerkleRoot::ZERO,
                    timestamp: 0, bits: 0, nonce: 0,
                },
                transactions: vec![coinbase("older", subsidy(h), vec![0xC4; 20]), spend.clone()],
                blue_score: h,
                height: h,
                shielded_transactions: vec![],
                powit: Default::default(),
            };
            let want = if act == 1 { sel_dag + 1 - c_dag } else { h - c_header };
            assert_eq!(admission::confirmations_for_next_block(&store, &coin.0, h).unwrap(), Some(want), "{what} (act {act})");
            let connect = gnb::accept::validate_block_in_view_classified_at(view, &b, act);
            match (&connect, valid) {
                (Ok(()), true) => {}
                (Err(gnb::accept::ConnectFailure::Invalid(e)), false) => {
                    assert!(e.reason.contains("relative timelock"), "{what} (act {act}): {e:?}");
                    // Curable below the witness commitment and the activation
                    // (the policy is revealed by the witness); fixed from it.
                    assert_eq!(e.witness_dependent, act == activation::NEVER, "{what} (act {act})");
                }
                _ => panic!("{what} (activation {act}): expected valid={valid}, got {connect:?}"),
            }
            let adm = admission::check_transaction(&store, None, &spend, &AdmissionPolicy::relay(h));
            match (&adm, valid) {
                (Ok(_), true) => {}
                (Err(admission::AdmissionError::Rejected(m)), false) if m.contains("relative timelock") => {}
                _ => panic!("{what} (activation {act}): admission expected valid={valid}, got {adm:?}"),
            }
        }
    }
}
