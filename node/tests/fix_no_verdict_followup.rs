//! Review of PR #15 (09ade07, "no-verdict blocks are parked"): six Low
//! findings, all node-local (no block verdict changes). Each needs a local
//! storage fault first; the faults are injected (`Storage::
//! inject_utxo_read_failure`, `Storage::inject_body_read_failure`, raw bytes
//! written over a stored body, `reorg::fault_injection`).
//!
//! 1. The due retries were unparked before the `old_tip` snapshot and before
//!    every early return: a retry that moved the node onto the parked branch
//!    sent no `TipChanged`, a refused frame (wrong bits) or a failed
//!    resolution left the DAG selecting an unvalidated branch (templates
//!    refused), and every unparked block re-derived the disqualified set.
//! 2. (IBD latch: `src/main.rs` bin tests; the RPC warning: `src/rpc` tests.)
//! 3. A chain-state rebuild that parked a block cleared its pending flag and
//!    the start-up refusal on an engine failure was skipped when the applied
//!    tip was the selected one.
//! 4. A body presence-check error after committed chunks returned a bare
//!    `Err`, so the acceptance rolled back a trigger whose DAG record had
//!    already been committed.
//! 5. A failed first apply chunk (not a no-verdict) after the committed
//!    rollback chunks left the applied tip at the fork point.
//! 6. A body that cannot be read (engine error) or decoded, of a block being
//!    applied, was neither parked nor counted toward the stop: a silent stall.
//!
//! Each `#[test]` below was seen failing on 61c78e7 (with only the
//! behaviour-neutral fault-injection hooks added) before the fix.

mod fix_common;
use fix_common::*;

use std::sync::Arc;
use std::time::{Duration, Instant};

use gnb::accept;
use gnb::address::Network;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::policy::SpendPolicy;
use gnb::core::sighash::SighashVersion;
use gnb::core::{self, activation, Block, BlockHeader, MerkleRoot, Transaction, TxOutput};
use gnb::crypto;
use gnb::pow;
use gnb::reorg;
use gnb::storage::Storage;
use gnb::wallet::policy_spend::PolicySpend;
use parking_lot::RwLock;

// ── Fixtures ─────────────────────────────────────────────────────────────────

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

fn genesis_hash(n: &Node) -> BlockHash {
    n.store.get_meta("genesis_hash").unwrap().unwrap().try_into().unwrap()
}

/// Clears this thread's `reorg::fault_injection` and the store's injected
/// read failures when dropped (also on panic).
struct NoFaults;
impl Drop for NoFaults {
    fn drop(&mut self) {
        reorg::fault_injection::set_max_blocks_per_commit(None);
        reorg::fault_injection::fail_after_commits(None);
    }
}

/// The fixture of `fix_no_verdict_hardening`: a policy output (`older = 1`)
/// in the UTXO set without its tx-index row, and `B_nv` (on `P`, losing the
/// tie-break against `T`) spending it: its validation finds no confirmation
/// (no verdict, inconsistent index). `A2` extends `B_nv` (not accepted).
struct Fixture {
    n: Node,
    t: BlockHash,
    b_nv: Block,
    a2: Block,
    prev: [u8; 32],
}

const POLICY_VALUE: u64 = 1_000_000_000;

fn fixture() -> Fixture {
    let genesis = mk_genesis(unix_now() - 100_000);
    let k = key();
    let policy = SpendPolicy::new(1, vec![k.pk.clone()], 0, 1).unwrap();
    let prev = [0x9Du8; 32];
    let n = node_with(&genesis, &[(prev, 0, TxOutput { value: POLICY_VALUE, script_pubkey: policy.script_pubkey() })]);
    let p = empty_child(&n, genesis.block_hash(), "p");
    accept(&n, &p).unwrap();
    let t = empty_child(&n, p.block_hash(), "t");
    accept(&n, &t).unwrap();
    let th = t.block_hash();
    let b_nv = child_where(&n, p.block_hash(), vec![policy_spend(&k, &policy, (prev, 0, POLICY_VALUE), 2)], "nv",
        |h| *h < th);
    accept(&n, &b_nv).expect("fork-loser stored");
    let a2 = empty_child(&n, b_nv.block_hash(), "a2");
    Fixture { n, t: th, b_nv, a2, prev }
}

/// `fixture()` after `A2` arrived: `B_nv` parked, applied tip `T`.
fn parked_fixture() -> Fixture {
    let f = fixture();
    let _ = accept(&f.n, &f.a2);
    assert!(f.n.dag.read().is_no_verdict_parked(&f.b_nv.block_hash()), "B_nv parked");
    assert_eq!(applied_tip(&f.n), Some(f.t));
    assert_eq!(sel_tip(&f.n), Some(f.t));
    f
}

fn repair_index(f: &Fixture) {
    f.n.store.put_tx_index(&f.prev, &genesis_hash(&f.n), 0).unwrap();
}

/// A small fork: `G - P - T` applied, `B` (on `P`, losing the tie against
/// `T`) stored, `A` on `B` (not accepted): `A`'s arrival moves the node to
/// `P - B - A` (rollback of `T`, apply `B`, `A`).
struct Fork {
    n: Node,
    p: BlockHash,
    t: BlockHash,
    b: Block,
    a: Block,
}

fn fork() -> Fork {
    let genesis = mk_genesis(unix_now() - 100_000);
    let n = node_with(&genesis, &[]);
    let p = empty_child(&n, genesis.block_hash(), "p");
    accept(&n, &p).unwrap();
    let t = empty_child(&n, p.block_hash(), "t");
    accept(&n, &t).unwrap();
    let th = t.block_hash();
    let b = child_where(&n, p.block_hash(), vec![], "b", |h| *h < th);
    accept(&n, &b).expect("fork-loser stored");
    assert_eq!(applied_tip(&n), Some(th));
    let a = empty_child(&n, b.block_hash(), "a");
    Fork { n, p: p.block_hash(), t: th, b, a }
}

/// Overwrite the stored body of `h` with bytes that do not decode (a row
/// RocksDB returns without an engine error, written that way by a bug or
/// corrupted in memory before it was written).
fn corrupt_body(n: &Node, h: &BlockHash) {
    let db = n.store.db();
    let cf = db.cf_handle("blocks").expect("blocks column family");
    db.put_cf(&cf, h, b"\x01not a block").unwrap();
    assert!(n.store.get_block(h).is_err(), "the body no longer decodes");
}

/// Extend `tip` by one block and accept it.
fn extend(n: &Node, tip: &mut BlockHash, tag: &str) -> Result<BlockHash, String> {
    let b = empty_child(n, *tip, tag);
    *tip = b.block_hash();
    accept(n, &b)
}

/// Blocks built on a separate DAG, proof of work marked verified
/// (`Block::test_only_assume_pow_valid`, dev-only `test-pow-limit`), as in
/// `fix_chain_move_bounds`: long branches cheaply, delivered in any order.
struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    fn block_where(&mut self, parent: BlockHash, mut txs: Vec<Transaction>, tag: &str,
                   pred: impl Fn(&BlockHash) -> bool) -> Block {
        let pd = self.dag.get_block_data(&parent).expect("parent built").clone();
        let height = pd.height + 1;
        let bits = pow::expected_bits(pd.timestamp, height).unwrap();
        txs.insert(0, coinbase(tag, core::tokenomics::block_subsidy_sat(height), vec![0xC0; 20]));
        let mut b = Block {
            header: BlockHeader {
                version: 1, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
                timestamp: pd.timestamp + 1, bits, nonce: 0,
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        commit_block(&mut b);
        while !pred(&b.block_hash()) {
            b.header.nonce += 1;
        }
        b.test_only_assume_pow_valid();
        self.dag.add_block(b.block_hash(), vec![parent], b.header.timestamp, pow::work_from_bits(bits))
            .expect("builder DAG accepts the block");
        b
    }

    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let b = self.block_where(p, vec![], &format!("{tag}{i}"), |_| true);
            p = b.block_hash();
            out.push(b);
        }
        out
    }
}

fn deliver_all(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

/// Reopen the store and reload the DAG and the shielded state as main()
/// does, WITHOUT the start-up reconciliation.
fn reopen(n: Node) -> Node {
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
    Node { _tmp, path, dag, store, mempool, node_state, shielded, tip_tx }
}

// ── Finding 1: the due retries are unparked right before the resolution ────

/// Reproduction (61c78e7): a due retry that succeeds, triggered by a block
/// that does not extend the parked branch (here a fork-loser on the
/// genesis), moved the node onto the parked branch without a `TipChanged`
/// (the "old" tip was snapshotted after the unpark), so miners kept working
/// on the lighter chain.
#[test]
fn a_retry_that_moves_the_tip_signals_tip_changed() {
    let _g = activation::scoped_override(0);
    let f = parked_fixture();
    repair_index(&f);
    f.n.store.make_no_verdict_retries_due(Instant::now());
    let mut rx = f.n.tip_tx.subscribe();
    let x = empty_child(&f.n, genesis_hash(&f.n), "x");
    let _ = accept(&f.n, &x);
    assert_eq!(applied_tip(&f.n), Some(f.a2.block_hash()), "the due retry connected the parked branch");
    let ev = rx.try_recv().expect("the tip moved: TipChanged is sent");
    assert_eq!(ev.hash, f.a2.block_hash());
}

/// Reproduction (61c78e7): a frame refused before the proof of work (wrong
/// bits) still unparked the due blocks: the DAG then selected the
/// unvalidated branch while the applied tip stayed on `T`, and templates
/// were refused ("chain move in progress") until the next full acceptance.
#[test]
fn a_refused_frame_does_not_unpark_anything() {
    let _g = activation::scoped_override(0);
    let f = parked_fixture();
    f.n.store.make_no_verdict_retries_due(Instant::now());
    let mut junk = empty_child(&f.n, f.t, "junk");
    junk.header.bits ^= 1;
    let e = accept::accept_block(&junk, junk.block_hash(), junk.height, &f.n.dag, &f.n.store, &f.n.mempool,
        &f.n.node_state, Some(&f.n.tip_tx), &f.n.shielded).unwrap_err();
    assert!(e.contains("invalid difficulty"), "{e}");
    assert!(f.n.dag.read().is_no_verdict_parked(&f.b_nv.block_hash()), "still parked: nothing was resolved");
    assert_eq!(sel_tip(&f.n), Some(f.t));
    build(&f.n).expect("templates on T");
}

/// Reproduction (61c78e7): a resolution that fails (here the chain move's
/// commit) left the unparked blocks unparked: selected tip `A2`, applied tip
/// `T`, templates refused. Now they are parked again (the retry stays due)
/// and the next acceptance retries them.
#[test]
fn a_failed_resolution_parks_the_due_blocks_again() {
    let _g = activation::scoped_override(0);
    let _f = NoFaults;
    let f = parked_fixture();
    repair_index(&f);
    f.n.store.make_no_verdict_retries_due(Instant::now());
    reorg::fault_injection::fail_after_commits(Some(0));
    let x = empty_child(&f.n, genesis_hash(&f.n), "x");
    accept(&f.n, &x).expect_err("the commit fails");
    reorg::fault_injection::fail_after_commits(None);
    assert!(f.n.dag.read().is_no_verdict_parked(&f.b_nv.block_hash()), "parked again");
    assert_eq!(sel_tip(&f.n), Some(f.t));
    assert_eq!(applied_tip(&f.n), Some(f.t));
    build(&f.n).expect("templates on T");
    // The retry is still due: the next acceptance connects the branch.
    let y = empty_child(&f.n, genesis_hash(&f.n), "y");
    let _ = accept(&f.n, &y);
    assert_eq!(applied_tip(&f.n), Some(f.a2.block_hash()));
}

/// Reproduction (61c78e7): every unparked block re-derived the whole
/// disqualified set (`recompute_invalid`); now all due blocks are unparked
/// with one.
#[test]
fn due_blocks_are_unparked_with_one_recompute() {
    let genesis = mk_genesis(unix_now() - 100_000);
    let n = node_with(&genesis, &[]);
    let gh = genesis.block_hash();
    let now = Instant::now();
    let mut parked = Vec::new();
    for i in 0..3 {
        let b = empty_child(&n, gh, &format!("k{i}"));
        accept(&n, &b).unwrap();
        n.store.note_no_verdict(&b.block_hash(), false, "test", now);
        n.dag.write().park_no_verdict(b.block_hash());
        parked.push(b.block_hash());
    }
    let before = n.dag.read().invalid_recomputes();
    let mut due = accept::unpark_due_no_verdicts(&n.dag, &n.store, now + Duration::from_secs(10 * 3600));
    due.sort_unstable();
    parked.sort_unstable();
    assert_eq!(due, parked);
    assert_eq!(n.dag.read().invalid_recomputes() - before, 1, "one recompute for all due blocks");
    assert!(n.dag.read().no_verdict_parked().is_empty());
}

// ── Finding 3: a rebuild that parks a block is not complete ─────────────────

fn seed_with(genesis: BlockHash, coinbase_txid: [u8; 32], prev: [u8; 32], spk: Vec<u8>)
    -> impl Fn(&Storage, &mut rocksdb::WriteBatch) -> Result<(), String>
{
    move |st: &Storage, batch: &mut rocksdb::WriteBatch| {
        st.stage_tx_index(batch, &coinbase_txid, &genesis, 0).map_err(|e| e.to_string())?;
        st.stage_utxo(batch, &prev, 0, &TxOutput { value: POLICY_VALUE, script_pubkey: spk.clone() })
            .map_err(|e| e.to_string())?;
        // The coin's confirmation (consistent index).
        st.stage_tx_index(batch, &prev, &genesis, 0).map_err(|e| e.to_string())
    }
}

/// Reproduction (61c78e7): a chain-state rebuild during which a block could
/// not be judged (the storage engine failed reading its input) parked it,
/// connected the shorter chain, cleared `REBUILD_PENDING` and reported
/// success; the reconciliation that follows saw applied tip = selected tip
/// and skipped the engine-failure refusal, so the node started on the
/// shortened chain. Now the flag stays set (the rebuild resumes at the next
/// start) and the rebuild reports the failure.
#[test]
fn a_rebuild_that_parks_a_block_stays_pending() {
    let _g = activation::scoped_override(0);
    let Fixture { n, t, b_nv, a2, prev } = fixture();
    let _ = accept(&n, &a2);
    let gh = genesis_hash(&n);
    let cb_txid = n.store.get_block(&gh).unwrap().unwrap().transactions[0].txid();
    let spk = n.store.get_utxo(&prev, 0).unwrap().unwrap().script_pubkey;
    let n = reopen(n);
    n.store.inject_utxo_read_failure(prev);
    let seed = seed_with(gh, cb_txid, prev, spk);
    let r = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &seed);
    assert_eq!(applied_tip(&n), Some(t), "the rebuild connected the chain it could judge");
    assert!(n.dag.read().is_no_verdict_parked(&b_nv.block_hash()));
    assert_eq!(n.store.get_meta(accept::REBUILD_PENDING_META).unwrap().as_deref(), Some(&[1u8][..]),
        "the rebuild did not reach the best chain: it stays pending");
    let e = r.expect_err("the rebuild reports that it is incomplete");
    assert!(e.contains(&hex::encode(&b_nv.block_hash()[..8])), "{e}");
    assert!(accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).is_err(), "the start is refused");

    // Once the engine reads again, the next start resumes and completes it.
    n.store.clear_injected_read_failures();
    let n = reopen(n);
    let report = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &seed).expect("resumes");
    assert!(report.resumed);
    assert_eq!(applied_tip(&n), Some(a2.block_hash()));
    assert_eq!(n.store.get_meta(accept::REBUILD_PENDING_META).unwrap().as_deref(), Some(&[0u8][..]));
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("starts");
}

/// Reproduction (61c78e7): the start-up refusal on a block that could not be
/// judged because the storage engine failed ran only when the applied tip
/// differed from the selected tip; a parked block makes them equal.
#[test]
fn an_engine_failure_refuses_the_start_when_the_applied_tip_is_selected() {
    let _g = activation::scoped_override(0);
    let f = fixture();
    repair_index(&f);
    f.n.store.inject_utxo_read_failure(f.prev);
    let _ = accept(&f.n, &f.a2);
    let rec = f.n.store.no_verdict_record(&f.b_nv.block_hash()).expect("recorded");
    assert!(rec.last_io);
    assert_eq!(applied_tip(&f.n), sel_tip(&f.n), "parked: the applied tip is the selected one");
    let e = accept::reconcile_on_startup(&f.n.dag, &f.n.store, &f.n.shielded)
        .expect_err("an engine failure refuses the start");
    assert!(e.contains("storage engine failed"), "{e}");
}

// ── Finding 4: never a bare Err after committed chunks ─────────────────────

/// Reproduction (61c78e7): a move that committed chunks (rollback of the 17
/// blocks of `L`, apply of `N1..N16`), parked `B_nv` and then met a body
/// read error (engine) checking the bodies of the next candidate (`L` again)
/// returned a bare `Err`: the acceptance took it for "nothing committed",
/// deleted the trigger's body and removed it from the DAG although its DAG
/// record had been committed. Now the error is attributed (the block is
/// parked, counted toward the stop) and the committed move stands.
#[test]
fn a_body_read_error_after_committed_chunks_keeps_the_committed_move() {
    let _g = activation::scoped_override(0);
    let _f = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let k = key();
    let policy = SpendPolicy::new(1, vec![k.pk.clone()], 0, 1).unwrap();
    let prev = [0x9Du8; 32];
    let n = node_with(&genesis, &[(prev, 0, TxOutput { value: POLICY_VALUE, script_pubkey: policy.script_pubkey() })]);
    let mut b = Builder::new(&genesis);
    let p = b.chain(gh, 1, "p");
    let ph = p[0].block_hash();
    let l = b.chain(ph, 17, "t");
    let nb = b.chain(ph, 16, "n");
    let t17 = l.last().unwrap().block_hash();
    let n16 = nb.last().unwrap().block_hash();
    let spend = policy_spend(&k, &policy, (prev, 0, POLICY_VALUE), nb.last().unwrap().height + 1);
    let b_nv = b.block_where(n16, vec![spend], "nv", |h| *h < t17);
    let a = b.block_where(b_nv.block_hash(), vec![], "a", |_| true);
    deliver_all(&n, &p);
    deliver_all(&n, &l);
    deliver_all(&n, &nb);
    accept(&n, &b_nv).expect("tie lost: stored");
    assert_eq!(applied_tip(&n), Some(t17));

    n.store.inject_body_read_failure(l[0].block_hash(), true);
    let _ = accept(&n, &a);
    let ah = a.block_hash();
    assert!(n.dag.read().has_block(&ah), "the trigger stays in the DAG");
    assert!(n.store.has_block_body(&ah).unwrap(), "its body is kept");
    assert!(n.store.get_dag_data(&ah).unwrap().is_some(), "its committed DAG record stands");
    assert_eq!(applied_tip(&n), Some(n16), "the committed chunks stand");
    assert_eq!(sel_tip(&n), Some(n16), "the block that could not be read is parked");
    let rec = n.store.no_verdict_record(&l[0].block_hash()).expect("attributed to T1");
    assert!(rec.last_io && rec.io_failures == 1, "{rec:?}");
    build(&n).expect("templates on the applied tip");

    // The engine reads again: the retry moves the node back to L.
    n.store.clear_injected_read_failures();
    n.store.make_no_verdict_retries_due(Instant::now());
    let x = b.block_where(gh, vec![], "x", |_| true);
    let _ = accept(&n, &x);
    assert_eq!(applied_tip(&n), Some(t17));
}

// ── Finding 5: the first apply chunk commits with the deepest rollbacks ────

/// Reproduction (61c78e7): the rollback of `T` committed alone, then the
/// first apply chunk failed for a reason that is not a no-verdict (here its
/// commit): the applied tip stayed at the fork point `P`. Now the rollback
/// commits in the batch of the first apply chunk: one commit, which either
/// fails (the tip stays `T`) or lands on `A`.
#[test]
fn a_failed_first_apply_chunk_never_leaves_the_tip_at_the_fork_point() {
    let _g = activation::scoped_override(0);
    let _f = NoFaults;
    let Fork { n, p, t, a, .. } = fork();
    reorg::fault_injection::fail_after_commits(Some(0));
    let _ = accept(&n, &a);
    assert_eq!(applied_tip(&n), Some(t), "nothing committed");
    reorg::fault_injection::fail_after_commits(Some(1));
    let _ = accept(&n, &a);
    reorg::fault_injection::fail_after_commits(None);
    assert_ne!(applied_tip(&n), Some(p), "never the fork point");
    assert_eq!(applied_tip(&n), Some(a.block_hash()), "the move is one commit");
}

/// Reproduction (61c78e7): the stored body of `B` does not decode: the
/// rollback of `T` had committed, the apply chunk failed, and the applied
/// tip stayed at the fork point `P` with nothing to retry it. Now nothing is
/// committed, the body is dropped and fetched again (`awaits_body`), and the
/// copy that arrives connects the branch.
#[test]
fn an_undecodable_body_is_dropped_and_fetched_again() {
    let _g = activation::scoped_override(0);
    let Fork { n, t, b, a, .. } = fork();
    let bh = b.block_hash();
    corrupt_body(&n, &bh);
    let _ = accept(&n, &a);
    assert_eq!(applied_tip(&n), Some(t), "nothing committed: the tip stays T");
    assert_eq!(sel_tip(&n), Some(t));
    assert!(!n.store.has_block_body(&bh).unwrap(), "the undecodable body is dropped");
    assert!(accept::awaits_body(&n.dag, &n.store, &bh), "and wanted again");
    assert_eq!(n.store.invalid_block_reason(&bh).unwrap(), None, "not a verdict");
    build(&n).expect("templates on T");
    // The copy fetched from a peer replaces it and the branch connects.
    accept(&n, &b).expect("the fetched body is stored");
    assert_eq!(applied_tip(&n), Some(a.block_hash()));
}

// ── Finding 6: an unreadable body of a block being applied is attributed ──

/// Reproduction (61c78e7): the body of `B` cannot be read (engine error) on
/// every attempt. Pre-fix the failure was neither parked nor counted: each
/// acceptance re-ran the move (applied tip at the fork point after the
/// first), templates were refused, and the node never stopped: the silent
/// permanent stall the module doc says cannot happen. Now `B` is parked as
/// a storage-engine failure (the node mines on `T`), retried on schedule,
/// and `NO_VERDICT_ABORT_AFTER` in a row stop the node.
#[test]
fn a_persistently_unreadable_body_stops_the_node() {
    let _g = activation::scoped_override(0);
    let Fork { n, t, b, a, .. } = fork();
    let bh = b.block_hash();
    n.store.inject_body_read_failure(bh, false);
    let _ = accept(&n, &a);
    assert_eq!(applied_tip(&n), Some(t));
    let rec = n.store.no_verdict_record(&bh).expect("attributed to B");
    assert!(rec.last_io && rec.io_failures == 1, "{rec:?}");
    assert!(n.dag.read().is_no_verdict_parked(&bh));
    assert_eq!(sel_tip(&n), Some(t));
    build(&n).expect("templates on T meanwhile");
    assert!(n.store.abort_reason().is_none());

    let mut tip = a.block_hash();
    for i in 1..accept::NO_VERDICT_ABORT_AFTER {
        n.store.make_no_verdict_retries_due(Instant::now());
        let _ = extend(&n, &mut tip, &format!("c{i}"));
    }
    let reason = n.store.abort_reason().expect("the node stopped");
    assert!(reason.contains(&hex::encode(bh)), "{reason}");
    assert!(n.store.has_block_body(&bh).unwrap(), "the body is kept (it may read again after a restart)");
    assert_eq!(n.store.invalid_block_reason(&bh).unwrap(), None, "not a verdict");
}
