//! Phase-4 package R4 regressions: bounded chain moves.
//!
//! * B1-T16 — planning a chain move walks O(move) selected-parent steps,
//!   never the whole chain to genesis.
//! * B2-T0 — chain moves (acceptance, start-up reconciliation, chain-state
//!   rebuild) commit in bounded chunks, each one a consistent applied tip that
//!   start-up resumes from; a move larger than the memory available to one
//!   commit still completes.
//! * B2-T0 × PoWit — a chunked move goes to the best chain under the
//!   finality pin, which the node learns from any stored block's PoWit state
//!   (PoWit audit finding 2: a fork-loser's finalization moves the node at
//!   once), and start-up rebuilds the pin from the persisted finality rows
//!   before it resumes a move.
//! * B1-T20 — reorg re-injection is capped by Bitcoin Core's 20 MB
//!   `DisconnectedBlockTransactions` budget; into a full pool, a candidate
//!   that would only be trimmed again is skipped (`Mempool::would_only_trim`)
//!   and the pool is trimmed once at the end (Core's `bypass_limits`, then
//!   `LimitMempoolSize`).
//!
//! Every block goes through the REAL acceptance pipeline
//! (`gnb::accept::accept_block`, after `validate_structure`), with the proof
//! of work marked verified (`Block::test_only_assume_pow_valid`, dev-only
//! `test-pow-limit`).

mod fix_common;
use fix_common::*;

use std::sync::Arc;

use gnb::accept;
use gnb::consensus::{self, BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput, GHOSTDAG_K};
use gnb::core::activation::NEVER;
use gnb::mempool::Mempool;
use gnb::pow;
use gnb::reorg;
use gnb::storage::Storage;
use parking_lot::RwLock;

// ── Fixtures ─────────────────────────────────────────────────────────────────

struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    fn block(&mut self, parents: Vec<BlockHash>, txs: Vec<Transaction>) -> Block {
        let height = parents.iter()
            .map(|p| self.dag.get_block_data(p).expect("parent built").height).max().unwrap() + 1;
        let pts = parents.iter().map(|p| self.dag.get_block_data(p).unwrap().timestamp).max().unwrap();
        let bits = pow::expected_bits(pts, height).unwrap();
        let mut b = Block {
            header: BlockHeader {
                version: 1, parents: parents.clone(), merkle_root: MerkleRoot::ZERO,
                timestamp: pts + 1, bits, nonce: 0,
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        commit_block(&mut b);
        b.test_only_assume_pow_valid();
        self.dag.add_block(b.block_hash(), parents, b.header.timestamp, pow::work_from_bits(bits))
            .expect("builder DAG accepts the block");
        b
    }

    fn height(&self, h: &BlockHash) -> u64 {
        self.dag.get_block_data(h).unwrap().height
    }

    /// A chain of `n` coinbase-only blocks on `from`.
    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let h = self.height(&p) + 1;
            let cb = coinbase(&format!("{tag}{i}"), core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20]);
            let b = self.block(vec![p], vec![cb]);
            p = b.block_hash();
            out.push(b);
        }
        out
    }
}

fn digest(n: &Node) -> [u8; 32] {
    n.store.utxo_set_digest().unwrap()
}

/// Reload the DAG and the shielded state from disk exactly as main() does
/// after a restart (an in-memory state that was lost in a crash), WITHOUT the
/// reconciliation.
fn reload(n: &mut Node) {
    let mut d = GhostDAG::with_default_k();
    let entries = n.store.load_all_dag_data().unwrap();
    let im = n.store.load_all_integrity_hashes().unwrap();
    d.load_persisted_validated(entries, im).expect("integrity chain verifies");
    let records = n.store.load_all_reachability().unwrap();
    let root = n.store.get_reachability_root().unwrap();
    if records.len() == d.block_count() {
        d.reach_load_records(&records, root).unwrap();
    } else {
        d.rebuild_reachability_from_store().unwrap();
    }
    n.dag = Arc::new(RwLock::new(d));
    n.shielded = Arc::new(RwLock::new(gnb::coherence::ShieldedPool::load(&n.store).expect("shielded state loads")));
}

fn deliver_all(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

/// Clears the fault injection of this thread when dropped (also on panic).
struct NoFaults;
impl Drop for NoFaults {
    fn drop(&mut self) {
        reorg::fault_injection::set_max_blocks_per_commit(None);
        reorg::fault_injection::fail_after_commits(None);
    }
}

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T16: the LCA walk costs the move, not the chain
// ═════════════════════════════════════════════════════════════════════════════

/// Pre-fix `find_lca` inserted the applied tip's whole selected chain, back to
/// genesis, into a set on EVERY tip-moving acceptance, so a one-block
/// extension of an N-block chain cost N steps and initial sync cost Θ(N²).
/// The plan is now found by walking both selected chains down by DAG height
/// (it strictly decreases along selected-parent edges, Bitcoin Core's
/// `LastCommonAncestor` on heights): O(reorg depth + extension length).
#[test]
fn b1_t16_connect_plan_walks_the_move_not_the_chain() {
    const N: u64 = 20_000;
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    dag.add_genesis(g, 0);
    let mut prev = g;
    for i in 1..=N {
        dag.add_block(hx(1, i), vec![prev], i, 1).unwrap();
        prev = hx(1, i);
    }
    // A 7-block fork from block N - 5 (a 5-block reorg).
    let mut fp = hx(1, N - 5);
    for j in 1..=7 {
        dag.add_block(hx(2, j), vec![fp], N + j, 1).unwrap();
        fp = hx(2, j);
    }

    // Cost is measured as GhostDAG record lookups (`DagStore::get`, behind
    // `get_block_data`): any planner, whatever its code, reads the records
    // it walks through it (the pre-fix `find_lca` read all N of them). The
    // planner's own step counter is checked too.
    let lookups = consensus::block_data_lookups;

    // One-block extension: the fast path every honest block takes.
    let (before, before_l) = (reorg::chain_walk_steps(), lookups());
    let plan = reorg::compute_connect_plan(&dag, &hx(1, N - 1), &hx(1, N)).expect("extension plan");
    let (steps, reads) = (reorg::chain_walk_steps() - before, lookups() - before_l);
    assert_eq!(plan.to_apply, vec![hx(1, N)]);
    assert!(plan.to_rollback.is_empty());
    assert!(steps <= 4, "a one-block extension walked {steps} selected-parent steps (chain of {N})");
    assert!(reads <= 16, "a one-block extension read {reads} DAG records (chain of {N})");

    // A 5-block reorg onto the 7-block fork.
    let (before, before_l) = (reorg::chain_walk_steps(), lookups());
    let plan = reorg::compute_connect_plan(&dag, &hx(1, N), &hx(2, 7)).expect("reorg plan");
    let (steps, reads) = (reorg::chain_walk_steps() - before, lookups() - before_l);
    assert_eq!(plan.lca, hx(1, N - 5));
    assert_eq!(plan.to_rollback.len(), 5);
    assert_eq!(plan.to_apply.len(), 7);
    assert!(steps <= 2 * (5 + 7) + 8, "a 5-block reorg walked {steps} steps (chain of {N})");
    assert!(reads <= 4 * (5 + 7) + 16, "a 5-block reorg read {reads} DAG records (chain of {N})");
    let (before, before_l) = (reorg::chain_walk_steps(), lookups());
    assert_eq!(reorg::find_lca(&dag, &hx(2, 7), &hx(1, N)), Some(hx(1, N - 5)));
    assert!(reorg::chain_walk_steps() - before <= 2 * (5 + 7) + 4);
    assert!(lookups() - before_l <= 4 * (5 + 7) + 8);

    // A backward move (operator invalidateblock) and the degenerate cases.
    let plan = reorg::compute_connect_plan(&dag, &hx(1, N), &hx(1, N - 3)).expect("backward plan");
    assert_eq!(plan.to_rollback, vec![hx(1, N), hx(1, N - 1), hx(1, N - 2)]);
    assert!(plan.to_apply.is_empty());
    assert!(reorg::compute_connect_plan(&dag, &hx(1, N), &hx(1, N)).is_none());
    assert_eq!(reorg::find_lca(&dag, &g, &hx(2, 7)), Some(g));
    assert_eq!(reorg::find_lca(&dag, &hx(9, 9), &hx(2, 7)), None, "unknown block: no common ancestor");
}

// ═════════════════════════════════════════════════════════════════════════════
// B2-T0: chain moves commit in bounded chunks
// ═════════════════════════════════════════════════════════════════════════════

/// The audit's out-of-memory scenario, with the memory limit simulated: a
/// commit that stages more than 40 blocks "runs out of memory" before it is
/// written. Pre-fix the 60-block reorg (rolling back 60 blocks and applying
/// 61) was staged as ONE plan, failed, and failed again for every later block
/// and at every start-up: the node never reached the best chain. The move now
/// commits in chunks of `reorg::MAX_BLOCKS_PER_COMMIT` and completes; a
/// restart under the same limit is clean.
#[test]
fn b2_t0_a_reorg_larger_than_one_commit_can_hold_still_completes() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 60, "a");
    let fork = b.chain(gh, 62, "b");

    let reference = node_with(&genesis, &[]);
    deliver_all(&reference, &a);
    deliver_all(&reference, &fork);
    let best = fork.last().unwrap().block_hash();
    assert_eq!(applied_tip(&reference), Some(best));

    let mut n = node_with(&genesis, &[]);
    deliver_all(&n, &a);
    reorg::fault_injection::set_max_blocks_per_commit(Some(40));
    for blk in &fork {
        let _ = accept(&n, blk);
    }
    assert_eq!(applied_tip(&n), Some(best), "the node follows the best chain whatever the move's size");
    assert_eq!(digest(&n), digest(&reference));
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());

    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(best));
    assert_eq!(digest(&n), digest(&reference));
}

/// A crash between two chunks of a deep reorg (simulated: the fourth commit
/// fails before it is written, and the in-memory state is then discarded).
/// Every committed chunk is a consistent applied tip — tip pointer, UTXO set,
/// undo records, shielded tip and the arriving block's DAG record moved
/// together — so the start-up check finds nothing to repair and start-up
/// reconciliation resumes the move from where it stopped, ending with the
/// UTXO set of a node that never crashed. Pre-fix the move was one batch: no
/// progress survived a crash, and the same move was retried from scratch.
#[test]
fn b2_t0_a_crash_between_chunks_resumes_at_restart() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 60, "a");
    let fork = b.chain(gh, 64, "b");

    let reference = node_with(&genesis, &[]);
    deliver_all(&reference, &a);
    deliver_all(&reference, &fork);

    let mut n = node_with(&genesis, &[]);
    deliver_all(&n, &a);
    let a_tip = a.last().unwrap().block_hash();
    // B's first 59 blocks are lighter than A: stored as fork-losers.
    deliver_all(&n, &fork[..59]);
    assert_eq!(applied_tip(&n), Some(a_tip));

    // The reorg starts with B's 60th or 61st block; the fourth commit "crashes".
    reorg::fault_injection::fail_after_commits(Some(3));
    let mut switched_at = None;
    for (i, blk) in fork.iter().enumerate().skip(59).take(2) {
        let _ = accept(&n, blk);
        if applied_tip(&n) != Some(a_tip) && switched_at.is_none() {
            switched_at = Some(i);
        }
    }
    let switched_at = switched_at.expect("the reorg started and committed progress before the crash");
    let mid = applied_tip(&n).unwrap();
    assert_ne!(mid, a_tip);
    assert!(!fork.iter().any(|x| x.block_hash() == mid),
        "the crash interrupted the move: the applied tip is an intermediate block of the old chain");
    assert!(n.dag.read().is_on_selected_chain_of(&mid, &a_tip), "rolled back part of the old chain");
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty(),
        "every intermediate state is a consistent applied tip");
    let shielded = gnb::coherence::ShieldedPool::load(&n.store).expect("shielded state loads");
    assert_eq!(shielded.tip(), Some(mid), "the shielded tip moved with the UTXO tip");

    // Crash: the in-memory state is lost; restart from disk.
    reorg::fault_injection::fail_after_commits(None);
    reload(&mut n);
    assert!(n.dag.read().has_block(&fork[switched_at].block_hash()),
        "the arriving block's DAG record was committed with the first chunk");
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("reconcile resumes the move");
    assert_eq!(applied_tip(&n), Some(fork[switched_at].block_hash()));
    for blk in &fork[switched_at + 1..] {
        if !n.dag.read().has_block(&blk.block_hash()) {
            accept(&n, blk).expect("later blocks connect normally");
        }
    }
    assert_eq!(applied_tip(&n), Some(fork.last().unwrap().block_hash()));
    assert_eq!(digest(&n), digest(&reference), "same UTXO set as a node that never crashed");
    restart(&mut n);
    assert_eq!(digest(&n), digest(&reference));
}

/// Review finding on B2-T0: a move that stops after committed chunks (a
/// storage failure, here injected) leaves the UTXO set on an intermediate
/// block while the DAG's selected tip is the new branch's tip. A template
/// then took its parents and height from the DAG tip but checked its
/// transactions against the intermediate UTXO set, so the node's own miner
/// could mine blocks its connect path rejects. The template builder now
/// refuses while the applied tip is not the selected tip, and builds again
/// once the move has resumed (next acceptance) and completed.
#[test]
fn b2_t0_no_template_while_a_stopped_move_is_incomplete() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 60, "a");
    let fork = b.chain(gh, 64, "b");
    let build = |n: &Node| gnb::template::build_block_template(
        &n.dag, &n.store, &n.mempool, gnb::template::EXTERNAL_COINBASE_RESERVE);

    let n = node_with(&genesis, &[]);
    deliver_all(&n, &a);
    let a_tip = a.last().unwrap().block_hash();
    deliver_all(&n, &fork[..59]);
    assert_eq!(applied_tip(&n), Some(a_tip));
    build(&n).expect("a template on a node whose applied tip is the selected tip");

    // The fourth commit of the reorg fails (storage failure): the move stops
    // on an intermediate block; the acceptance itself returns Ok.
    reorg::fault_injection::fail_after_commits(Some(3));
    let mut next = 59;
    while applied_tip(&n) == Some(a_tip) && next < 61 {
        let _ = accept(&n, &fork[next]);
        next += 1;
    }
    let mid = applied_tip(&n).unwrap();
    assert_ne!(mid, a_tip, "the move committed chunks before it stopped");
    assert_ne!(sel_tip(&n), Some(mid), "the DAG's selected tip is ahead of the applied tip");
    assert_eq!(gnb::template::chain_move_incomplete(&n.dag.read(), &n.store), Some((mid, sel_tip(&n).unwrap())));
    let err = build(&n).expect_err("no template on the DAG tip over an intermediate UTXO set");
    assert!(err.contains("chain move in progress"), "{err}");

    // The next acceptance resumes the move; templates are built again.
    reorg::fault_injection::fail_after_commits(None);
    for blk in &fork[next..] {
        accept(&n, blk).expect("later blocks connect and resume the move");
    }
    assert_eq!(applied_tip(&n), Some(fork.last().unwrap().block_hash()));
    assert_eq!(gnb::template::chain_move_incomplete(&n.dag.read(), &n.store), None);
    let t = build(&n).expect("a template once the move completed");
    assert_eq!(t.height, fork.len() as u64 + 1);
}

fn genesis_seed(genesis: &Block)
    -> impl Fn(&Storage, &mut rocksdb::WriteBatch) -> Result<(), String>
{
    let gh = genesis.block_hash();
    let txids: Vec<[u8; 32]> = genesis.transactions.iter().map(|t| t.txid()).collect();
    move |st: &Storage, batch: &mut rocksdb::WriteBatch| {
        for t in &txids {
            st.stage_tx_index(batch, t, &gh, 0).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// The chain-state rebuild (audit DAG-11) re-applies the chain from genesis
/// in bounded chunks: it completes under a memory limit no single commit of
/// the whole chain fits in, and an interrupted rebuild resumes from the last
/// committed chunk instead of starting over (pre-fix: one plan from genesis,
/// O(chain bytes) of memory, retried from scratch at every start).
#[test]
fn b2_t0_chain_state_rebuild_is_chunked_and_resumes() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let chain = b.chain(gh, 70, "r");
    let mut n = node_with(&genesis, &[]);
    n.store.put_tx_index(&genesis.transactions[0].txid(), &gh, 0).unwrap();
    deliver_all(&n, &chain);
    let clean = digest(&n);
    let tip = chain.last().unwrap().block_hash();

    // Under a 40-block commit limit the whole rebuild still completes.
    reorg::fault_injection::set_max_blocks_per_commit(Some(40));
    let report = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis))
        .expect("a chunked rebuild fits the memory limit");
    assert_eq!(report.connected_blocks, chain.len());
    assert_eq!(digest(&n), clean);
    reorg::fault_injection::set_max_blocks_per_commit(None);

    // A rebuild interrupted after two chunks keeps its progress...
    reorg::fault_injection::fail_after_commits(Some(2));
    let err = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis));
    reorg::fault_injection::fail_after_commits(None);
    assert!(err.is_err(), "the interrupted rebuild reports the failure");
    let mid = applied_tip(&n).unwrap();
    assert_ne!(mid, gh, "progress was committed");
    assert_ne!(mid, tip);
    reload(&mut n);
    assert_eq!(accept::check_chain_state(&n.dag, &n.store).unwrap(),
        vec![accept::ChainStateFault::RebuildInterrupted]);
    // ...and the next run resumes from the last committed chunk.
    let mid_height = n.dag.read().get_block_data(&mid).unwrap().height as usize;
    let report = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis))
        .expect("the rebuild resumes");
    assert_eq!(report.connected_blocks, chain.len() - mid_height, "resumed, not restarted from genesis");
    assert_eq!(applied_tip(&n), Some(tip));
    assert_eq!(digest(&n), clean);
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());
    restart(&mut n);
    assert_eq!(digest(&n), clean);
}

// ═════════════════════════════════════════════════════════════════════════════
// B2-T0 × PoWit finality: every chunk respects (and advances) the pin
// ═════════════════════════════════════════════════════════════════════════════

/// A PoWit state whose witness set has finalized `cp` (slot 6, beyond the
/// activation checkpoint at slot 1, so it pins fork choice).
fn state_finalizing(cp: BlockHash) -> core::powit::PowitState {
    let mut st = core::powit::PowitState::genesis(1, cp);
    st.finalized = core::powit::Checkpoint { height: 6, hash: cp };
    st.justified = st.finalized;
    st
}

/// The finality fixture: genesis; A = 45 blocks; B = 46 blocks (heavier),
/// whose 36th block pays its miner one satoshi too much (invalid in its own
/// context only: it is stored as a fork-loser like any other block) and
/// whose blocks from the 21st on carry a PoWit state finalizing B's 6th
/// block (synthetic states, saved in every node's store: below the PoWit
/// activation acceptance computes none). The reference node followed B
/// block by block: it pinned B's 6th block as soon as B's 21st was its tip,
/// so it never leaves B, and ends on B's last valid block, B[34].
struct FinalityFixture {
    genesis: Block,
    a: Vec<Block>,
    fork: Vec<Block>,
    finalized: BlockHash,
    reference: Node,
}

fn finality_fixture() -> FinalityFixture {
    // The pin is taken only at or above the node's minimum chain work
    // (`consensus::finality`); these few-block chains test the chunked
    // move, not that gate (fix_powit_finality_min_work.rs), so this binary
    // runs with 0 whatever the mainnet `core::MIN_CHAIN_WORK` becomes.
    let _ = gnb::ingress::set_minimum_chain_work(0);
    assert_eq!(gnb::ingress::minimum_chain_work(), 0);
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 45, "a");
    let mut fork = b.chain(gh, 35, "b");
    let h = b.height(&fork[34].block_hash()) + 1;
    let bad = b.block(vec![fork[34].block_hash()],
        vec![coinbase("b-overpays", core::tokenomics::block_subsidy_sat(h) + 1, vec![0xC0; 20])]);
    fork.push(bad.clone());
    fork.extend(b.chain(bad.block_hash(), 10, "bx"));
    assert_eq!(fork.len(), 46);
    let finalized = fork[5].block_hash();

    let reference = node_with(&genesis, &[]);
    save_finality_states(&reference, &fork, finalized);
    deliver_all(&reference, &fork[..35]);
    assert_eq!(reference.dag.read().finalized(), Some((finalized, 6)));
    for blk in fork[35..].iter().chain(&a) {
        let _ = accept(&reference, blk);
    }
    assert_eq!(applied_tip(&reference), Some(fork[34].block_hash()));
    FinalityFixture { genesis, a, fork, finalized, reference }
}

fn save_finality_states(n: &Node, fork: &[Block], finalized: BlockHash) {
    for blk in &fork[20..] {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(finalized)).unwrap();
    }
}

/// PoWit finality pins fork choice to the highest finalized checkpoint any
/// stored block's PoWit state carries (`consensus::finality`; PoWit audit
/// finding 2, which replaced "the applied tip's state, pinned per committed
/// chunk"). Here B[20], arriving as a fork-loser of the heavier A, carries
/// B[5]'s finalization: the pin is taken before the chain move, so the move
/// from A onto B goes at once, in chunks (3 rollback chunks, then B[0..16]
/// and B[16..21]), although B is lighter (the node used to stay on A until B
/// was heavier, then could fall back to A when a later chunk failed). The
/// rest of B then connects up to B[34], B[35] being invalid: the node ends
/// where the node that followed B block by block ends, and a restart keeps
/// it there (start-up rebuilds the pin from the finality rows).
#[test]
fn b2_t0_finality_learned_from_a_fork_loser_binds_the_chunked_move() {
    let _guard = NoFaults;
    let fx = finality_fixture();
    let mut n = node_with(&fx.genesis, &[]);
    save_finality_states(&n, &fx.fork, fx.finalized);
    deliver_all(&n, &fx.a);
    deliver_all(&n, &fx.fork[..20]);
    assert_eq!(applied_tip(&n), Some(fx.a.last().unwrap().block_hash()), "B is lighter than A");
    assert_eq!(n.dag.read().finalized(), None, "no block of B carries a finalization yet");

    deliver_all(&n, &fx.fork[20..21]);
    assert_eq!(n.dag.read().finalized(), Some((fx.finalized, 6)), "pinned from B[20]'s state");
    assert_eq!(applied_tip(&n), Some(fx.fork[20].block_hash()),
        "the move goes to the finalized branch (A forks below B[5]), lighter or not");
    for blk in &fx.fork[21..] {
        let _ = accept(&n, blk);
    }
    assert_eq!(n.dag.read().finalized(), Some((fx.finalized, 6)));
    assert_eq!(applied_tip(&n), Some(fx.fork[34].block_hash()), "B's last valid block");
    let reason = n.store.invalid_block_reason(&fx.fork[35].block_hash()).unwrap().expect("B[35] disqualified");
    assert_eq!(accept::mark_kind(&reason), accept::MarkKind::Consensus, "{reason}");
    assert_eq!(digest(&n), digest(&fx.reference), "same UTXO set as the node that followed B");
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());

    restart(&mut n);
    assert_eq!(n.dag.read().finalized(), Some((fx.finalized, 6)), "rebuilt from the finality rows");
    assert_eq!(applied_tip(&n), Some(fx.fork[34].block_hash()), "a restart does not leave finality");
    assert_eq!(digest(&n), digest(&fx.reference));
}

/// A crash between two chunks of that move (B[20]'s record, its PoWit state
/// and its finality row were committed with the first one): the pin lives in
/// memory, so start-up rebuilds it from the persisted finality rows BEFORE it
/// picks the block to resume to. Unpinned, the resumed move went back to A
/// (heavier than B); it completes on B[20], and the rest of B on B[34], with
/// the reference UTXO set.
#[test]
fn b2_t0_crash_resume_restores_the_finality_pin() {
    let _guard = NoFaults;
    let fx = finality_fixture();
    let mut n = node_with(&fx.genesis, &[]);
    save_finality_states(&n, &fx.fork, fx.finalized);
    deliver_all(&n, &fx.a);
    deliver_all(&n, &fx.fork[..20]);

    // Commits 1-3 roll A back, 4 applies B[0..16]; the next one "crashes".
    reorg::fault_injection::fail_after_commits(Some(4));
    let _ = accept(&n, &fx.fork[20]);
    reorg::fault_injection::fail_after_commits(None);
    assert_eq!(applied_tip(&n), Some(fx.fork[15].block_hash()), "stopped between two chunks");
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());

    // Crash: the in-memory pin is lost with the rest of the DAG state.
    reload(&mut n);
    assert_eq!(n.dag.read().finalized(), None);
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("reconcile resumes the move");
    assert_eq!(n.dag.read().finalized(), Some((fx.finalized, 6)));
    assert_eq!(applied_tip(&n), Some(fx.fork[20].block_hash()), "resumed on the finalized branch");
    for blk in &fx.fork[21..] {
        let _ = accept(&n, blk);
    }
    assert_eq!(applied_tip(&n), Some(fx.fork[34].block_hash()));
    assert_eq!(digest(&n), digest(&fx.reference));
    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(fx.fork[34].block_hash()));
    assert_eq!(digest(&n), digest(&fx.reference));
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T20: bounded re-injection
// ═════════════════════════════════════════════════════════════════════════════

/// A large, standard-looking transaction spending `fund` (synthetic witness:
/// re-injection does not re-check witnesses below the activation).
fn fat_tx(fund: ([u8; 32], u32), tag: u32) -> Transaction {
    let mut script_sig = vec![0x5Au8; 9_000];
    script_sig[..4].copy_from_slice(&tag.to_le_bytes());
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: fund.0, prev_index: fund.1, script_sig, sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 10_000, script_pubkey: vec![0xB7; 20] }],
        locktime: 0,
    }
}

fn synthetic_block(height: u64, nonce: u64, txs: Vec<Transaction>) -> Block {
    let mut all = vec![coinbase(&format!("syn{height}:{nonce}"), 0, vec![0u8; 20])];
    all.extend(txs);
    Block {
        header: BlockHeader {
            version: 1, parents: vec![], merkle_root: MerkleRoot::ZERO,
            timestamp: 1_700_000_000 + height, bits: 0x1d00ffff, nonce,
        },
        transactions: all,
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    }
}

/// Bitcoin Core keeps at most `MAX_DISCONNECTED_TX_POOL_BYTES` (20 MB) of
/// disconnected transactions for re-admission and trims the MOST RECENTLY
/// confirmed ones first, so what it keeps (the transactions of the oldest
/// disconnected blocks, in block order) never misses a parent. Pre-fix every
/// non-coinbase transaction of every disconnected block was cloned and
/// re-admitted, under the acceptance lock: here 25 MB of them.
#[test]
fn b1_t20_reinjection_candidates_are_capped_at_the_core_budget() {
    let mut blocks = Vec::new();
    let mut tag = 0u32;
    for h in 0..25u64 {
        let txs: Vec<Transaction> = (0..110)
            .map(|i| {
                tag += 1;
                let mut fund = [0u8; 32];
                fund[..8].copy_from_slice(&(h * 1_000 + i).to_le_bytes());
                fat_tx((fund, 0), tag)
            })
            .collect();
        blocks.push(synthetic_block(h + 1, h, txs));
    }
    let total: usize = blocks.iter()
        .flat_map(|b| b.transactions.iter().skip(1))
        .map(|t| t.actual_size())
        .sum();
    assert!(total > 24_000_000, "the disconnected blocks carry {total} bytes of transactions");

    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();
    for b in &blocks {
        store.put_block_body(b).unwrap();
    }
    // Tip-first, as a move disconnects them; hashes only (B2-T0).
    let outcome = reorg::ConnectOutcome {
        disconnected: blocks.iter().rev().map(|b| b.block_hash()).collect(),
        ..Default::default()
    };
    let selected = outcome.reinjection_candidates(&store, reorg::MAX_DISCONNECTED_TX_POOL_BYTES);
    assert!(selected.truncated);
    let candidates = selected.txs;
    let bytes: usize = candidates.iter().map(|t| t.actual_size()).sum();
    assert_eq!(bytes, selected.bytes);
    assert_eq!(reorg::MAX_DISCONNECTED_TX_POOL_BYTES, 20_000_000, "Bitcoin Core's budget");
    assert!(bytes <= 20_000_000, "{bytes} bytes of re-admission candidates (budget 20 MB)");
    assert!(bytes > 20_000_000 - 10_000, "the budget is used up to its last transaction");
    let expect: Vec<[u8; 32]> = blocks.iter()
        .flat_map(|b| b.transactions.iter().skip(1).map(|t| t.txid()))
        .take(candidates.len())
        .collect();
    assert_eq!(candidates.iter().map(|t| t.txid()).collect::<Vec<_>>(), expect,
        "the oldest disconnected blocks' transactions, in block order, are kept");
}

/// Re-admission into a full pool, modeled on Core's `MaybeUpdateMempoolForReorg`
/// (re-add with `bypass_limits`, then ONE `LimitMempoolSize`): a candidate
/// that the final trim would remove at once is not inserted (no per-candidate
/// insert-and-trim under the acceptance lock), better-paying candidates
/// displace the cheapest pooled packages, the pool ends within its caps, and
/// the rolling minimum fee (relay policy) does not refuse a transaction that
/// was already mined.
#[test]
fn b1_t20_readmission_into_a_full_pool_trims_once_and_keeps_the_best() {
    const POOL_CAP: usize = gnb::mempool::MAX_MEMPOOL_SIZE;
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();
    let mempool = Mempool::new();
    // A full pool of small transactions paying 50 sat/byte.
    for i in 0..POOL_CAP as u64 {
        let mut prev = [0xA0u8; 32];
        prev[..8].copy_from_slice(&i.to_le_bytes());
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![1, 2, 3], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 5_000, script_pubkey: vec![0xA1; 20] }],
            locktime: 0,
        };
        let fee = 50 * tx.actual_size() as u64;
        mempool.add(tx, fee).expect("pool fills");
    }
    assert_eq!(mempool.size(), POOL_CAP);

    // Candidates from disconnected blocks: 10 paying ~110 sat/byte, 10 paying
    // ~3 sat/byte (above the consensus minimum, below the pool's eviction rate).
    let mut cands = Vec::new();
    for (i, value) in [(0u32, 1_000_000u64), (1, 37_000)].iter().flat_map(|&(k, v)| (0..10).map(move |j| (k * 10 + j, v))) {
        let mut fund = [0xC5u8; 32];
        fund[..4].copy_from_slice(&i.to_le_bytes());
        store.put_utxo(&fund, 0, &TxOutput { value, script_pubkey: vec![0xC6; 20] }).unwrap();
        cands.push(fat_tx((fund, 0), i));
    }
    let high: Vec<[u8; 32]> = cands[..10].iter().map(|t| t.txid()).collect();
    let low: Vec<[u8; 32]> = cands[10..].iter().map(|t| t.txid()).collect();
    let (re, dropped) = reorg::reinject_disconnected(&store, &mempool, cands, 2);
    assert_eq!((re, dropped), (10, 10), "the 10 well-paying candidates are re-admitted, the 10 cheap ones skipped");
    assert!(high.iter().all(|t| mempool.contains(t)));
    assert!(low.iter().all(|t| !mempool.contains(t)));
    assert!(mempool.size() <= POOL_CAP, "the pool is trimmed back within its cap");

    // Not full any more, but the trim raised the rolling minimum (50 sat/byte
    // and up): relay refuses 3 sat/byte, re-admission of a mined transaction
    // does not (Core bypasses the mempool minimum fee for reorged transactions).
    for t in mempool.txids().into_iter().filter(|t| !high.contains(t)).take(100) {
        mempool.remove(&t);
    }
    assert!(mempool.rolling_min_fee_rate() >= 50);
    let mut fund = [0xC7u8; 32];
    fund[0] = 1;
    store.put_utxo(&fund, 0, &TxOutput { value: 37_000, script_pubkey: vec![0xC6; 20] }).unwrap();
    let cheap = fat_tx((fund, 0), 999);
    let id = cheap.txid();
    let (re, _) = reorg::reinject_disconnected(&store, &mempool, vec![cheap], 2);
    assert_eq!(re, 1);
    assert!(mempool.contains(&id));
}

// ═════════════════════════════════════════════════════════════════════════════
// B2-T0 with DAG-8 and DAG-11: what each chunk's batch carries
// ═════════════════════════════════════════════════════════════════════════════

/// Every row of the selected-chain index column families (position -> hash,
/// position -> timestamp, address history).
fn chain_index_rows(n: &Node) -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    let db = n.store.db();
    let mut out = Vec::new();
    for cf in ["height", "timestamps", "addr_tx_history"] {
        let h = db.cf_handle(cf).unwrap();
        for r in db.iterator_cf(&h, rocksdb::IteratorMode::Start) {
            let (k, v) = r.unwrap();
            out.push((cf, k.to_vec(), v.to_vec()));
        }
    }
    out
}

/// The position index is exactly the selected chain of the APPLIED tip, each
/// block at its DAG height, and every chain coinbase's history row is at the
/// block's position (audit DAG-8): nothing of a rolled-back block and nothing
/// of a block the move has not reached yet.
fn assert_indexes_follow_the_applied_tip(n: &Node, coinbases: &std::collections::HashMap<[u8; 32], BlockHash>,
                                         what: &str) {
    let tip = applied_tip(n).unwrap();
    let mut chain = Vec::new();
    let mut cur = Some(tip);
    while let Some(h) = cur {
        chain.push(h);
        cur = n.dag.read().get_block_data(&h).and_then(|d| d.selected_parent);
    }
    chain.reverse();
    for (pos, h) in chain.iter().enumerate() {
        assert_eq!(n.store.get_block_hash_at_height(pos as u64).unwrap(), Some(*h), "{what}: position {pos}");
    }
    assert_eq!(n.store.get_block_hash_at_height(chain.len() as u64).unwrap(), None, "{what}: nothing above the tip");
    let rows = n.store.query_address_history(&[0xC0; 20], 0, u64::MAX, 100_000, 0).unwrap();
    let mut expected: Vec<(u64, [u8; 32])> = Vec::new();
    for (pos, h) in chain.iter().enumerate().skip(1) {
        let (txid, _) = coinbases.iter().find(|(_, b)| *b == h).expect("a builder block");
        expected.push((pos as u64, *txid));
    }
    let mut got: Vec<(u64, [u8; 32])> = rows.iter().map(|e| (e.height, e.txid)).collect();
    got.sort();
    expected.sort();
    assert_eq!(got, expected, "{what}: the address history is the applied chain's, at its positions");
}

/// Audit B2-T0 (R4) with DAG-8 and DAG-11 (R1b): a chunked chain move whose
/// SECOND commit fails (simulated crash between chunks). The first chunk's
/// one batch carries everything of its blocks and of the arriving block: the
/// UTXO effects, the chain-index rows keyed by chain position (rollback
/// chunks un-index at `lca + len - j` of their own sub-plan, apply chunks
/// index from the block the previous chunk ended at), the tip pointer, the
/// arriving block's DAG record with the pending reachability delta, which
/// leaves the in-memory pending set once that batch committed (not at the
/// end of the whole move, which never comes here). After the restart the
/// move resumes and every index row equals that of a node fed in order.
#[test]
fn b2_t0_each_chunk_commits_its_position_index_rows_and_the_reachability_delta() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 60, "a");
    let fork = b.chain(gh, 64, "b");
    let coinbases: std::collections::HashMap<[u8; 32], BlockHash> = a.iter().chain(fork.iter())
        .map(|x| (x.transactions[0].txid(), x.block_hash())).collect();

    let reference = node_with(&genesis, &[]);
    deliver_all(&reference, &a);
    deliver_all(&reference, &fork);
    assert_indexes_follow_the_applied_tip(&reference, &coinbases, "reference");

    let mut n = node_with(&genesis, &[]);
    deliver_all(&n, &a);
    let a_tip = a.last().unwrap().block_hash();
    deliver_all(&n, &fork[..59]);
    assert_eq!(applied_tip(&n), Some(a_tip));
    assert_indexes_follow_the_applied_tip(&n, &coinbases, "before the move");

    // The first chunk commits; the second "crashes" before its commit.
    reorg::fault_injection::fail_after_commits(Some(1));
    let mut trigger = None;
    for blk in fork.iter().skip(59).take(2) {
        let _ = accept(&n, blk);
        if applied_tip(&n) != Some(a_tip) {
            trigger = Some(blk.block_hash());
            break;
        }
    }
    let trigger = trigger.expect("the reorg started and committed its first chunk");
    reorg::fault_injection::fail_after_commits(None);
    let mid = applied_tip(&n).unwrap();
    assert!(n.dag.read().is_on_selected_chain_of(&mid, &a_tip), "one rollback chunk committed: {}",
        hex::encode(&mid[..4]));
    assert_eq!(n.dag.read().get_block_data(&mid).unwrap().height, 60 - reorg::MAX_BLOCKS_PER_COMMIT as u64);
    assert_indexes_follow_the_applied_tip(&n, &coinbases, "after the first chunk");

    // DAG-11: the trigger's DAG record and its reachability records went to
    // disk with the first chunk, and the pending delta was cleared then.
    assert!(n.store.get_dag_data(&trigger).unwrap().is_some(), "the DAG record committed with the first chunk");
    let pending = n.dag.read().reach_peek_delta();
    assert!(pending.0.is_empty() && pending.1.is_empty(),
        "the delta the committed chunk wrote is no longer pending ({} upserts)", pending.0.len());
    let disk: std::collections::HashMap<BlockHash, Vec<u8>> = n.store.load_all_reachability().unwrap().into_iter().collect();
    let mem: std::collections::HashMap<BlockHash, Vec<u8>> = n.dag.read().reach_export_all().into_iter().collect();
    assert_eq!(disk, mem, "the reachability index on disk is the one in memory");

    // Crash and restart: the move resumes from the committed chunk.
    reload(&mut n);
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("reconcile resumes the move");
    for blk in &fork {
        if !n.dag.read().has_block(&blk.block_hash()) {
            accept(&n, blk).expect("later blocks connect normally");
        }
    }
    assert_eq!(applied_tip(&n), Some(fork.last().unwrap().block_hash()));
    assert_indexes_follow_the_applied_tip(&n, &coinbases, "after the resumed move");
    assert_eq!(chain_index_rows(&n), chain_index_rows(&reference),
        "every position, timestamp and history row equals that of a node fed in order");
    assert_eq!(digest(&n), digest(&reference));
}
