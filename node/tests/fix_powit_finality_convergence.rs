//! PoWit audit (PR head 4293747), findings 2 and 3, node-local fork choice:
//! the finality pin converges.
//!
//! Finding 2: the pin came only from the PoWit state of the node's own
//! applied tip, so after a healed partition the side that had more hashrate
//! but no finality never pinned the other side's finalized checkpoint (it
//! never applied those blocks) and both sides grew forever; the same for a
//! node that first saw a heavier private chain; and a restart restored the
//! pin from the applied tip only, so it could drop. Now (Gasper's fork
//! choice starts from the highest justified checkpoint learned from ANY
//! block) the pin is the highest finalized checkpoint carried by the PoWit
//! state of any stored block that is not disqualified; conflicting
//! finalized checkpoints are handled deterministically (the pin falls back
//! to their latest common block and the most work decides above it, with an
//! alert); restart rebuilds the same pin from storage.
//!
//! Finding 3 (node side): an eclipsed node pinned a cheap fork's checkpoint
//! and then ignored the heavier honest chain forever.
//!
//! Every block goes through the REAL acceptance pipeline; PoWit states are
//! synthetic (below the PoWit activation acceptance computes none), as in
//! `fix_powit_finality_min_work.rs`. The minimum chain work is 0 for this
//! binary (that gate has its own test).

mod fix_common;
use fix_common::*;

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction};
use gnb::pow;
use gnb::powit::FinalityOp;

fn setup() {
    let _ = gnb::ingress::set_minimum_chain_work(0);
    assert_eq!(gnb::ingress::minimum_chain_work(), 0, "one minimum chain work per test binary");
}

struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    fn block(&mut self, parent: BlockHash, txs: Vec<Transaction>) -> Block {
        let pd = self.dag.get_block_data(&parent).expect("parent built").clone();
        let height = pd.height + 1;
        let bits = pow::expected_bits(pd.timestamp, height).unwrap();
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
        b.test_only_assume_pow_valid();
        self.dag.add_block(b.block_hash(), vec![parent], b.header.timestamp, pow::work_from_bits(bits))
            .expect("builder DAG accepts the block");
        b
    }

    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out: Vec<Block> = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let h = self.dag.get_block_data(&p).unwrap().height + 1;
            let cb = coinbase(&format!("{tag}{i}"), core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20]);
            let b = self.block(p, vec![cb]);
            p = b.block_hash();
            out.push(b);
        }
        out
    }

    fn work(&self, h: &BlockHash) -> u128 {
        self.dag.get_block_data(h).unwrap().blue_work
    }

    fn height(&self, h: &BlockHash) -> u64 {
        self.dag.get_block_data(h).unwrap().height
    }
}

/// A PoWit state whose witness set has finalized `cp` (slot `slot`, beyond
/// the activation checkpoint at slot 1, so it pins fork choice).
fn state_finalizing(cp: BlockHash, slot: u64) -> core::powit::PowitState {
    let mut st = core::powit::PowitState::genesis(1, cp);
    st.finalized = core::powit::Checkpoint { height: slot, hash: cp };
    st.justified = st.finalized;
    st
}

/// Save, in `n`'s store, a state finalizing `blocks[cp]` for every block of
/// `blocks` from index `from` on (the block that included the finalizing
/// attestations and its descendants on that chain).
fn finalize(n: &Node, b: &Builder, blocks: &[Block], cp: usize, from: usize) {
    let cph = blocks[cp].block_hash();
    let slot = b.height(&cph) + 1;
    for blk in &blocks[from..] {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(cph, slot)).unwrap();
    }
}

fn deliver(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

fn pin_of(n: &Node) -> Option<BlockHash> {
    n.dag.read().finalized().map(|(h, _)| h)
}

fn tip(blocks: &[Block]) -> BlockHash {
    blocks.last().unwrap().block_hash()
}

/// The partition of finding 2. Shared history C; side A (at least 2/3 of
/// the witness weight, less hashrate) finalizes A[3] from A[10] on; side B
/// (more hashrate, too little witness weight to finalize) mines a longer
/// chain. Before the heal each side's node is on its own chain, A's pinned.
struct Partition {
    genesis: Block,
    common: Vec<Block>,
    a: Vec<Block>,
    b: Vec<Block>,
    builder: Builder,
}

fn partition() -> Partition {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut builder = Builder::new(&genesis);
    let common = builder.chain(gh, 5, "c");
    let a = builder.chain(tip(&common), 20, "a");
    let b = builder.chain(tip(&common), 30, "b");
    assert!(builder.work(&tip(&b)) > builder.work(&tip(&a)), "side B has more work");
    Partition { genesis, common, a, b, builder }
}

impl Partition {
    /// A node that stores the side-A finality states (every node computes
    /// the same state for the same block; synthetic states are saved per node).
    fn node(&self) -> Node {
        let n = node_with(&self.genesis, &[]);
        finalize(&n, &self.builder, &self.a, 3, 10);
        n
    }
}

/// Finding 2: after the heal every node ends on side A, the side whose
/// witness set finalized a checkpoint, whichever side it was on. The side-B
/// node learns A[3]'s finalization from A's blocks (stored as fork-losers,
/// never applied) and leaves the heavier chain; the side-A node stays.
#[test]
fn a_healed_partition_converges_on_the_finalized_side() {
    let p = partition();
    let na = p.node();
    let nb = p.node();
    deliver(&na, &p.common);
    deliver(&na, &p.a);
    deliver(&nb, &p.common);
    deliver(&nb, &p.b);
    assert_eq!(pin_of(&na), Some(p.a[3].block_hash()), "side A finalized A[3]");
    assert_eq!(applied_tip(&na), Some(tip(&p.a)));
    assert_eq!(pin_of(&nb), None, "side B finalized nothing");
    assert_eq!(applied_tip(&nb), Some(tip(&p.b)));

    // Heal: each side receives the other's blocks.
    deliver(&na, &p.b);
    deliver(&nb, &p.a);
    for (name, n) in [("A", &na), ("B", &nb)] {
        assert_eq!(pin_of(n), Some(p.a[3].block_hash()), "node {name}: pinned to the finalized checkpoint");
        assert_eq!(applied_tip(n), Some(tip(&p.a)), "node {name}: on the finalized side");
    }

    // Both keep agreeing as the chain grows (side B's miners now build on A).
    let mut builder = p.builder;
    let more = builder.chain(tip(&p.a), 3, "m");
    deliver(&na, &more);
    deliver(&nb, &more);
    assert_eq!(applied_tip(&na), Some(tip(&more)));
    assert_eq!(applied_tip(&nb), Some(tip(&more)));
}

/// Every arrival order of the same blocks ends on the same chain with the
/// same pin (docs/CONSENSUS.md: "whatever their arrival order").
#[test]
fn every_arrival_order_of_a_partition_ends_on_the_same_chain() {
    let p = partition();
    let all: Vec<&Block> = p.common.iter().chain(&p.a).chain(&p.b).collect();
    let n_common = p.common.len();
    let side_a: Vec<&Block> = all[n_common..n_common + p.a.len()].to_vec();
    let side_b: Vec<&Block> = all[n_common + p.a.len()..].to_vec();
    let mut orders: Vec<Vec<&Block>> = Vec::new();
    // A then B, B then A, interleaved both ways.
    orders.push(side_a.iter().chain(&side_b).copied().collect());
    orders.push(side_b.iter().chain(&side_a).copied().collect());
    let mut zip_ab = Vec::new();
    let mut zip_ba = Vec::new();
    for i in 0..side_a.len().max(side_b.len()) {
        if let Some(x) = side_a.get(i) { zip_ab.push(*x); }
        if let Some(x) = side_b.get(i) { zip_ab.push(*x); zip_ba.push(*x); }
        if let Some(x) = side_a.get(i) { zip_ba.push(*x); }
    }
    orders.push(zip_ab);
    orders.push(zip_ba);
    for (i, order) in orders.iter().enumerate() {
        let n = p.node();
        deliver(&n, &p.common);
        for b in order {
            accept(&n, b).unwrap_or_else(|e| panic!("order {i}: h={} refused: {e}", b.height));
        }
        assert_eq!(pin_of(&n), Some(p.a[3].block_hash()), "order {i}");
        assert_eq!(applied_tip(&n), Some(tip(&p.a)), "order {i}");
    }
}

/// Finding 2, majority-hashrate variant: a private chain Y with more work
/// and no finality, branching below X's finalized checkpoint, is published.
/// A node that was online on X stays; a node that was offline and receives
/// Y first then X must end on X too (it used to stay on Y forever, never
/// having applied the blocks that finalized X[3]). A restart keeps it there.
#[test]
fn a_heavier_private_chain_never_captures_a_node_that_learns_the_finalized_chain() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let x = b.chain(gh, 20, "x");
    let y = b.chain(x[1].block_hash(), 40, "y");
    assert!(b.work(&tip(&y)) > b.work(&tip(&x)));
    let mk = || {
        let n = node_with(&genesis, &[]);
        finalize(&n, &b, &x, 3, 10);
        n
    };
    let online = mk();
    deliver(&online, &x);
    deliver(&online, &y);
    assert_eq!(applied_tip(&online), Some(tip(&x)), "the online node stays on the finalized chain");

    let mut offline = mk();
    deliver(&offline, &x[..2]);
    deliver(&offline, &y);
    assert_eq!(applied_tip(&offline), Some(tip(&y)), "Y is all it knows above X[1]");
    deliver(&offline, &x[2..]);
    assert_eq!(pin_of(&offline), Some(x[3].block_hash()), "learned X's finality from X's blocks");
    assert_eq!(applied_tip(&offline), Some(tip(&x)), "and left the heavier chain that misses it");
    restart(&mut offline);
    assert_eq!(pin_of(&offline), Some(x[3].block_hash()));
    assert_eq!(applied_tip(&offline), Some(tip(&x)));
}

/// Finding 2, restart variant: the node pinned X[3] while on X, then moved
/// to a heavier chain Y THROUGH X[3] whose states have not recorded that
/// finalization yet (they finalized nothing beyond the activation). The pin
/// was restored from the applied tip's state only, so it dropped at the
/// restart, and a heavier chain Z that forks below X[3] then won. The pin
/// is now rebuilt from every stored block's state: same pin, same chain.
#[test]
fn a_restart_restores_exactly_the_pin_it_had() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let x = b.chain(gh, 20, "x");
    let y = b.chain(x[5].block_hash(), 30, "y");
    let z = b.chain(gh, 60, "z");
    assert!(b.work(&tip(&z)) > b.work(&tip(&y)) && b.work(&tip(&y)) > b.work(&tip(&x)));
    let mut n = node_with(&genesis, &[]);
    finalize(&n, &b, &x, 3, 10);
    deliver(&n, &x);
    assert_eq!(pin_of(&n), Some(x[3].block_hash()));
    deliver(&n, &y);
    assert_eq!(applied_tip(&n), Some(tip(&y)), "Y passes through the pinned checkpoint");
    let before = n.dag.read().finalized();

    restart(&mut n);
    assert_eq!(n.dag.read().finalized(), before, "the same pin after a restart");
    deliver(&n, &z);
    assert_eq!(applied_tip(&n), Some(tip(&y)), "a heavier chain forking below the pin never wins");
}

/// Finding 3, the eclipse: a node syncing while eclipsed sees only a fork F
/// whose own witness set finalized F[3], and pins it. When the honest chain
/// H arrives it carries its own finalized checkpoint H[5]: the two conflict
/// (finality cannot be trusted any more: at least a third of the witness
/// weight signed both, or the witness sets differ), so the pin falls back to
/// their latest common block (genesis here) and the most work decides: H.
/// The node used to stay on F forever.
#[test]
fn an_eclipsed_node_pinned_to_a_fork_follows_the_honest_chain_once_it_sees_it() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let fork = b.chain(gh, 12, "f");
    let honest = b.chain(gh, 40, "h");
    let mut n = node_with(&genesis, &[]);
    finalize(&n, &b, &fork, 3, 6);
    finalize(&n, &b, &honest, 5, 20);
    deliver(&n, &fork);
    assert_eq!(pin_of(&n), Some(fork[3].block_hash()), "eclipsed: the fork's finality is all it knows");
    deliver(&n, &honest);
    assert_eq!(applied_tip(&n), Some(tip(&honest)), "the honest chain, the most work");
    assert_ne!(pin_of(&n), Some(fork[3].block_hash()));
    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(tip(&honest)));
}

/// An operator `invalidateblock` of the pinned checkpoint: the block and
/// every block through it are disqualified, so the finalizations they carry
/// stop counting and the node moves to the best remaining chain. The
/// monotone pin stayed on the disqualified block, and no block above it was
/// selectable any more.
#[test]
fn invalidating_the_pinned_checkpoint_moves_the_node_to_the_best_remaining_chain() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let x = b.chain(gh, 20, "x");
    let z = b.chain(gh, 15, "z");
    let n = node_with(&genesis, &[]);
    finalize(&n, &b, &x, 3, 10);
    deliver(&n, &x);
    deliver(&n, &z);
    assert_eq!(pin_of(&n), Some(x[3].block_hash()));
    assert_eq!(applied_tip(&n), Some(tip(&x)));
    gnb::accept::invalidate_block(x[3].block_hash(), &n.dag, &n.store, &n.mempool, &n.node_state,
        Some(&n.tip_tx), &n.shielded).expect("invalidateblock");
    assert_eq!(pin_of(&n), None, "the finality its disqualified blocks carried is gone");
    assert_eq!(applied_tip(&n), Some(tip(&z)), "the best remaining chain");
    assert_eq!(sel_tip(&n), Some(tip(&z)));
}

fn finality_op(n: &Node, op: FinalityOp) -> gnb::accept::ChainOverride {
    gnb::accept::override_finality(op, &n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
        .unwrap_or_else(|e| panic!("{op:?}: {e}"))
}

/// The operator escape hatch (RPC `ignorefinalized` / `reconsiderfinalized`,
/// the finality analogue of Bitcoin Core's `invalidateblock` /
/// `reconsiderblock`): setting the pinned checkpoint aside leaves the blocks
/// valid and lets the most work decide (here a heavier chain that forks
/// below it); taking it back pins it again and returns to its chain. The
/// setting is persisted: a restart keeps it.
#[test]
fn the_operator_can_set_the_pin_aside_and_take_it_back() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let x = b.chain(gh, 20, "x");
    let z = b.chain(gh, 30, "z");
    let mut n = node_with(&genesis, &[]);
    finalize(&n, &b, &x, 3, 10);
    deliver(&n, &x);
    deliver(&n, &z);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));

    let r = finality_op(&n, FinalityOp::Ignore(x[3].block_hash()));
    assert_eq!(r.affected, 1, "the pin moved");
    assert_eq!(pin_of(&n), None);
    assert_eq!(applied_tip(&n), Some(tip(&z)), "the most work decides");
    assert!(n.store.invalid_block_reason(&x[3].block_hash()).unwrap().is_none(), "no block was marked");
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (None, Some(tip(&z))), "the setting survives a restart");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!(info["ignored"], serde_json::json!([hex::encode(x[3].block_hash())]), "{info}");
    assert_eq!(info["ignored_finalized"], serde_json::json!(1));

    finality_op(&n, FinalityOp::Reconsider(x[3].block_hash()));
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
}

/// An operator weak-subjectivity checkpoint (`setfinalitycheckpoint`): the
/// node trusts that block as final, so a chain through it wins whatever its
/// work, and no finalized checkpoint that conflicts with it counts; `none`
/// removes every anchor, `default` returns to the release checkpoint (none
/// on this network). Persisted across restarts.
#[test]
fn an_operator_checkpoint_anchors_the_pin() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let x = b.chain(gh, 20, "x");
    let y = b.chain(gh, 12, "y");
    let mut n = node_with(&genesis, &[]);
    finalize(&n, &b, &x, 3, 10);
    deliver(&n, &x);
    deliver(&n, &y);
    assert_eq!(pin_of(&n), Some(x[3].block_hash()));

    finality_op(&n, FinalityOp::SetAnchor(y[5].block_hash()));
    assert_eq!(pin_of(&n), Some(y[5].block_hash()), "the anchor; X's finality conflicts with it");
    assert_eq!(applied_tip(&n), Some(tip(&y)), "the lighter chain through the anchor");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!((info["origin"].as_str(), info["anchor_source"].as_str(), info["against_anchor"].as_u64()),
        (Some("anchor"), Some("operator"), Some(1)), "{info}");
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(y[5].block_hash()), Some(tip(&y))));

    finality_op(&n, FinalityOp::DisableAnchor);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
    finality_op(&n, FinalityOp::SetAnchor(y[5].block_hash()));
    finality_op(&n, FinalityOp::DefaultAnchor);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
}

/// Conflicting finalized checkpoints are reported (`getfinalityinfo`
/// `conflict`, `getpowitinfo` `finality_conflict`) and the pin is their
/// latest common block; an operator then picks a side with
/// `setfinalitycheckpoint`.
#[test]
fn a_finality_conflict_is_reported_and_the_operator_can_resolve_it() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let common = b.chain(gh, 4, "c");
    let x = b.chain(tip(&common), 20, "x");
    let y = b.chain(tip(&common), 25, "y");
    let n = node_with(&genesis, &[]);
    finalize(&n, &b, &x, 3, 10);
    finalize(&n, &b, &y, 6, 12);
    deliver(&n, &common);
    deliver(&n, &x);
    deliver(&n, &y);
    assert_eq!(pin_of(&n), Some(tip(&common)), "their latest common block");
    assert_eq!(applied_tip(&n), Some(tip(&y)), "the most work above it");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!(info["origin"], serde_json::json!("conflict"), "{info}");
    let pair: Vec<String> = info["conflict"].as_array().unwrap().iter()
        .map(|c| c["hash"].as_str().unwrap().to_string()).collect();
    assert_eq!(pair, vec![hex::encode(y[6].block_hash()), hex::encode(x[3].block_hash())]);
    assert_eq!(gnb::powit::info_json(&n.dag.read(), &n.store)["finality_conflict"], serde_json::json!(true));

    finality_op(&n, FinalityOp::SetAnchor(x[3].block_hash()));
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
    assert!(gnb::powit::finality_info_json(&n.dag.read(), 8)["conflict"].is_null());
}
