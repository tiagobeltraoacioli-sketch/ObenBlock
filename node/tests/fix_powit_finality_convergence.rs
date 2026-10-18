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
//! state of any stored block that is not disqualified; restart rebuilds the
//! same pin from storage.
//!
//! Review of that fix, HIGH 1 and MEDIUM 3: conflicting finalized
//! checkpoints used to make the pin fall back to their latest common block,
//! so the most work decided above it: a majority-hashrate fork that
//! finalized its own rolled every synced node's finalized history back, and
//! a cheap fork froze a syncing node's pin at the fork point. Finality the
//! node reached on its own chain is now sticky (a conflicting one raises a
//! persistent alert, the operator decides), a finality learned from another
//! chain only advances it, and a node with no finality of its own resolves
//! conflicting learned ones by the work of their best sources.
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

/// Finding 3, the eclipse, without an anchor: a node syncing while eclipsed
/// sees only a fork F whose own witness set finalized F[3], and pins it: that
/// is finality reached on its own applied chain. When the honest chain H
/// arrives with its own finalized checkpoint H[5], the two conflict, and the
/// node cannot tell an eclipse from a majority-hashrate attack on finality
/// (review HIGH 1, `a_synced_node_keeps_its_finality_against_a_heavier_
/// conflicting_fork`): it keeps F[3] and raises the conflict alert, as every
/// Ethereum client keeps its finalized checkpoint. The defences against the
/// eclipse come first (the release finality checkpoint, the minimum chain
/// work, `fix_powit_finality_e2e.rs`); the remedy is the operator's: a
/// weak-subjectivity checkpoint on H moves the node, for good.
#[test]
fn an_eclipsed_node_keeps_the_forks_finality_and_alerts_until_the_operator_moves_it() {
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
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(fork[3].block_hash()), Some(tip(&fork))),
        "it keeps the finality it reached, whatever the work of the other chain");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!((info["conflict_resolution"].as_str(), info["conflicting_finalized"].as_u64()),
        (Some("own_finality"), Some(1)), "{info}");
    assert_eq!(info["own_finality"]["hash"], serde_json::json!(hex::encode(fork[3].block_hash())));

    finality_op(&n, FinalityOp::SetAnchor(honest[2].block_hash()));
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(honest[5].block_hash()), Some(tip(&honest))));
    assert!(gnb::powit::finality_info_json(&n.dag.read(), 8)["conflict"].is_null(), "F[3] is against the anchor");
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(honest[5].block_hash()), Some(tip(&honest))));
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
/// `conflict`, `getpowitinfo` `finality_conflict`, persistently): the node
/// keeps the finality it reached (X[3]), never the heavier chain Y that
/// finalized Y[6]; an operator then picks a side with `setfinalitycheckpoint`.
#[test]
fn a_finality_conflict_is_reported_and_the_operator_can_resolve_it() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let common = b.chain(gh, 4, "c");
    let x = b.chain(tip(&common), 20, "x");
    let y = b.chain(tip(&common), 25, "y");
    let mut n = node_with(&genesis, &[]);
    finalize(&n, &b, &x, 3, 10);
    finalize(&n, &b, &y, 6, 12);
    deliver(&n, &common);
    deliver(&n, &x);
    deliver(&n, &y);
    assert_eq!(pin_of(&n), Some(x[3].block_hash()), "its own finality");
    assert_eq!(applied_tip(&n), Some(tip(&x)), "not the most work");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!(info["origin"], serde_json::json!("finalized"), "{info}");
    let pair: Vec<String> = info["conflict"].as_array().unwrap().iter()
        .map(|c| c["hash"].as_str().unwrap().to_string()).collect();
    assert_eq!(pair, vec![hex::encode(x[3].block_hash()), hex::encode(y[6].block_hash())]);
    assert_eq!(gnb::powit::info_json(&n.dag.read(), &n.store)["finality_conflict"], serde_json::json!(true));
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
    assert!(!gnb::powit::finality_info_json(&n.dag.read(), 8)["conflict"].is_null(), "the alert persists");

    finality_op(&n, FinalityOp::SetAnchor(y[6].block_hash()));
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(y[6].block_hash()), Some(tip(&y))));
    assert!(gnb::powit::finality_info_json(&n.dag.read(), 8)["conflict"].is_null());
}

// ── Review of the PoWit finality pin: findings HIGH 1 and MEDIUM 3 ──────────

/// Review HIGH 1 (regression against main): a majority-hashrate attacker
/// forks right after the honest finalized checkpoint H[3], finalizes its own
/// checkpoint A[5] (under the first witness-set rule its own shares become
/// its witness set) and publishes the heavier fork once the honest chain has
/// finalized H[12] above the fork point. The pin used to fall back to the
/// latest common block of the two finalities, so the most work decided above
/// it and every synced node rolled finalized history back. Finality the
/// node reached on its own chain is now sticky: it keeps H[12], stays on H,
/// raises a persistent conflict alert, and only the operator moves it.
#[test]
fn a_synced_node_keeps_its_finality_against_a_heavier_conflicting_fork() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let h = b.chain(gh, 20, "h");
    let a = b.chain(h[4].block_hash(), 30, "a");
    assert!(b.work(&tip(&a)) > b.work(&tip(&h)), "the attacker's fork carries more work");
    let mut n = node_with(&genesis, &[]);
    finalize(&n, &b, &h, 3, 8);
    finalize(&n, &b, &h, 12, 18);
    finalize(&n, &b, &a, 5, 20);
    deliver(&n, &h);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h[12].block_hash()), Some(tip(&h))));

    deliver(&n, &a);
    assert_eq!(pin_of(&n), Some(h[12].block_hash()), "the node keeps the finality it reached");
    assert_eq!(applied_tip(&n), Some(tip(&h)), "finalized history is never rolled back by work");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    let pair: Vec<String> = info["conflict"].as_array().expect("a conflict is reported").iter()
        .map(|c| c["hash"].as_str().unwrap().to_string()).collect();
    assert_eq!(pair, vec![hex::encode(h[12].block_hash()), hex::encode(a[5].block_hash())], "{info}");
    assert_eq!(gnb::powit::info_json(&n.dag.read(), &n.store)["finality_conflict"], serde_json::json!(true));

    // Persistent: a restart, and more attacker blocks, change nothing.
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h[12].block_hash()), Some(tip(&h))));
    assert!(!gnb::powit::finality_info_json(&n.dag.read(), 8)["conflict"].is_null(), "still alerting");
    let more = b.chain(tip(&a), 5, "m");
    for blk in &more {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(a[5].block_hash(),
            b.height(&a[5].block_hash()) + 1)).unwrap();
    }
    deliver(&n, &more);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h[12].block_hash()), Some(tip(&h))));

    // The operator's escape hatch: set the node's own checkpoint aside and
    // the other finality, which descends from H[3], advances the pin.
    finality_op(&n, FinalityOp::Ignore(h[12].block_hash()));
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(a[5].block_hash()), Some(tip(&more))));
}

/// Review MEDIUM 3: a cheap fork X with its own finalization, sent to a
/// node syncing the honest chain H, used to pin the node at the fork point
/// forever: X's checkpoint stayed counted, so the latest common block of the
/// two (genesis here) stayed the pin however far H's own finality went, and
/// the node followed X while X was heavier. The node now keeps the finality
/// it reached on H, reports X, and its pin keeps advancing on H.
#[test]
fn a_cheap_conflicting_fork_never_freezes_the_pin_of_a_syncing_node() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let h = b.chain(gh, 40, "h");
    let x = b.chain(gh, 12, "x");
    let n = node_with(&genesis, &[]);
    for (cp, from) in [(3, 8), (13, 18), (23, 28), (33, 38)] {
        let till = if from + 10 < h.len() { from + 10 } else { h.len() };
        let cph = h[cp].block_hash();
        for blk in &h[from..till] {
            gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(cph, b.height(&cph) + 1)).unwrap();
        }
    }
    finalize(&n, &b, &x, 3, 6);
    deliver(&n, &h[..10]);
    assert_eq!(pin_of(&n), Some(h[3].block_hash()));
    deliver(&n, &x);
    assert_eq!(pin_of(&n), Some(h[3].block_hash()), "the cheap fork does not move the pin back");
    assert_eq!(applied_tip(&n), Some(h[9].block_hash()), "nor capture the node, although it is heavier");
    assert!(!gnb::powit::finality_info_json(&n.dag.read(), 8)["conflict"].is_null());
    for (upto, cp) in [(20, 13), (30, 23), (40, 33)] {
        deliver(&n, &h[upto - 10..upto]);
        assert_eq!(pin_of(&n), Some(h[cp].block_hash()), "the pin keeps advancing on H");
    }
    assert_eq!(applied_tip(&n), Some(tip(&h)));
}

/// Review MEDIUM 3, a node with no finality of its own: conflicting
/// finalized checkpoints it only learned from chains it has not applied
/// resolve deterministically, to the one whose best source carries the most
/// work, never to their latest common block forever. Here the operator set
/// the node's own checkpoint X[3] aside (`ignorefinalized`), leaving H[5]
/// and Y[4], which conflict: H's sources are heavier, so the node pins H[5],
/// moves to H, and its pin then advances with H's next finalization.
#[test]
fn with_no_finality_of_its_own_conflicting_checkpoints_resolve_by_work() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let x = b.chain(gh, 12, "x");
    let y = b.chain(gh, 14, "y");
    let h = b.chain(gh, 30, "h");
    let n = node_with(&genesis, &[]);
    finalize(&n, &b, &x, 3, 6);
    finalize(&n, &b, &y, 4, 8);
    let cph = h[5].block_hash();
    for blk in &h[10..20] {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(cph, b.height(&cph) + 1)).unwrap();
    }
    deliver(&n, &x);
    deliver(&n, &y);
    deliver(&n, &h[..20]);
    assert_eq!(pin_of(&n), Some(x[3].block_hash()), "the finality the node reached first");
    finality_op(&n, FinalityOp::Ignore(x[3].block_hash()));
    assert_eq!(pin_of(&n), Some(h[5].block_hash()), "H's checkpoint: its best source carries the most work");
    assert_eq!(applied_tip(&n), Some(h[19].block_hash()));
    let cph = h[15].block_hash();
    for blk in &h[20..] {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(cph, b.height(&cph) + 1)).unwrap();
    }
    deliver(&n, &h[20..]);
    assert_eq!(pin_of(&n), Some(h[15].block_hash()), "and the pin advances with H, not stuck at genesis");
    assert_eq!(applied_tip(&n), Some(tip(&h)));
}

// ── Review MEDIUM 6: a weak-subjectivity checkpoint set before syncing ──────

/// Review MEDIUM 6: `setfinalitycheckpoint` required the block to be stored
/// (and there was no start-up option), so an operator could not set a
/// weak-subjectivity checkpoint before syncing, which is when it protects:
/// a node eclipsed on a fork F during sync reaches F's finality and keeps
/// it (review HIGH 1). Set before sync, by hash and DAG height, the anchor
/// is unknown until it arrives: nothing above its height counts, nothing at
/// or below it is decided, so F's finality never pins the node, and the
/// honest chain's finality through the anchor does once it arrives.
#[test]
fn an_operator_checkpoint_set_before_sync_keeps_an_eclipsed_node_off_the_fork() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let fork = b.chain(gh, 12, "f");
    let honest = b.chain(gh, 40, "h");
    let mut n = node_with(&genesis, &[]);
    finalize(&n, &b, &fork, 3, 6);
    finalize(&n, &b, &honest, 15, 25);
    let anchor = honest[9].block_hash();
    let r = gnb::accept::override_finality(FinalityOp::SetAnchorAt(anchor, 10), &n.dag, &n.store, &n.mempool,
        &n.node_state, Some(&n.tip_tx), &n.shielded);
    assert!(r.is_ok(), "an unknown block is accepted with its height: {:?}", r.err());
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!((info["anchor_source"].as_str(), info["anchor_status"].as_str()), (Some("operator"), Some("unknown")));
    restart(&mut n);
    assert_eq!(gnb::powit::finality_info_json(&n.dag.read(), 8)["anchor_status"], serde_json::json!("unknown"));

    deliver(&n, &fork);
    assert_eq!(pin_of(&n), None, "F's finality is undecided while the anchor is unknown");
    assert_eq!(applied_tip(&n), Some(tip(&fork)), "the only chain the eclipsed node knows");
    deliver(&n, &honest);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(honest[15].block_hash()), Some(tip(&honest))));
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!((info["anchor_status"].as_str(), info["against_anchor"].as_u64()), (Some("known"), Some(1)), "{info}");
    assert!(info["conflict"].is_null(), "F's finality is against the anchor, not a conflict: {info}");

    // A known block at another height is refused; an unknown one is not
    // checked until it arrives (then `height_mismatch` is reported).
    let e = gnb::accept::override_finality(FinalityOp::SetAnchorAt(anchor, 11), &n.dag, &n.store, &n.mempool,
        &n.node_state, Some(&n.tip_tx), &n.shielded).expect_err("wrong height");
    assert!(e.to_string().contains("DAG height 10"), "{e}");
}

// ── Review round 2: M3 (unknown anchor) and L4 / L2 (the persisted pin) ─────

/// Review round 2, M3: an anchor the node never receives (`setfinalitycheckpoint
/// <hash> <height>` or `--finalitycheckpoint` naming a block it does not get)
/// made nothing count: the pin dropped to none, the persisted pin was
/// deleted and fork choice fell back to the most work, silently. While the
/// anchor is unknown the node now holds the checkpoint it had pinned
/// (`origin: held`), keeps it persisted, and alerts once its applied tip is
/// above the anchor's height (`anchor_overdue`).
#[test]
fn an_unknown_anchor_holds_the_pinned_checkpoint_and_alerts() {
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
    let persisted = |n: &Node| n.store.get_meta(gnb::powit::FINALITY_PIN_META).unwrap();
    assert_eq!(persisted(&n), Some(x[3].block_hash().to_vec()));

    finality_op(&n, FinalityOp::SetAnchorAt([0xEE; 32], 5));
    assert_eq!(pin_of(&n), Some(x[3].block_hash()), "the pin is held while the anchor is unknown");
    assert_eq!(applied_tip(&n), Some(tip(&x)), "not the most work (Z)");
    assert_eq!(persisted(&n), Some(x[3].block_hash().to_vec()), "and stays persisted");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!((info["anchor_status"].as_str(), info["origin"].as_str(), info["anchor_overdue"].as_bool()),
        (Some("unknown"), Some("held"), Some(true)), "{info}");
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(x[3].block_hash()), Some(tip(&x))));
    assert_eq!(persisted(&n), Some(x[3].block_hash().to_vec()));

    finality_op(&n, FinalityOp::DefaultAnchor);
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!((info["origin"].as_str(), info["anchor_overdue"].as_bool()), (Some("finalized"), Some(false)));
}

fn genesis_seed(genesis: &Block) -> impl Fn(&gnb::storage::Storage, &mut rocksdb::WriteBatch) -> Result<(), String> {
    let gh = genesis.block_hash();
    let txids: Vec<[u8; 32]> = genesis.transactions.iter().map(|t| t.txid()).collect();
    move |st: &gnb::storage::Storage, batch: &mut rocksdb::WriteBatch| {
        for t in &txids {
            st.stage_tx_index(batch, t, &gh, 0).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// The DAG reloaded from storage, nothing reconciled (a process that
/// crashed in the middle of a chain-state rebuild, before it resumes it).
fn reload(n: &mut Node) {
    let mut d = GhostDAG::with_default_k();
    let entries = n.store.load_all_dag_data().unwrap();
    let im = n.store.load_all_integrity_hashes().unwrap();
    d.load_persisted_validated(entries, im).expect("integrity chain verifies");
    d.rebuild_reachability_from_store().unwrap();
    n.dag = std::sync::Arc::new(parking_lot::RwLock::new(d));
    n.shielded = std::sync::Arc::new(parking_lot::RwLock::new(
        gnb::coherence::ShieldedPool::load(&n.store).expect("shielded state loads")));
}

/// Review round 2, L4 (and L2): a chain-state rebuild reconnects from
/// genesis, so while it runs, and after a crash in its middle, the applied
/// chain's own finality is far below the pin. In a conflict, the pin the
/// node persisted keeps it on its side: here the node keeps H[30] against
/// the heavier A's A[5], the rebuild is interrupted at H[15] (where the
/// applied chain's own finality is H[3], which both H[30] and A[5] advance:
/// without the persisted pin the most work, A, would win), the process
/// restarts from storage, and the resumed rebuild ends on H with the same
/// pin. (A lost write of the pin plus such a rebuild can switch sides: the
/// write follows every change of pin, docs/CONSENSUS.md.)
#[test]
fn an_interrupted_rebuild_resumes_on_the_persisted_pin_during_a_conflict() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let h = b.chain(gh, 40, "h");
    let a = b.chain(h[4].block_hash(), 50, "a");
    assert!(b.work(&tip(&a)) > b.work(&tip(&h)));
    let mut n = node_with(&genesis, &[]);
    n.store.put_tx_index(&genesis.transactions[0].txid(), &gh, 0).unwrap();
    finalize(&n, &b, &h, 3, 8);
    finalize(&n, &b, &h, 30, 35);
    finalize(&n, &b, &a, 5, 20);
    deliver(&n, &h);
    deliver(&n, &a);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h[30].block_hash()), Some(tip(&h))));

    gnb::reorg::fault_injection::fail_after_commits(Some(1));
    let r = gnb::accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis));
    gnb::reorg::fault_injection::fail_after_commits(None);
    assert!(r.is_err(), "the rebuild was interrupted");
    let mid = applied_tip(&n).unwrap();
    let mid_height = n.dag.read().get_block_data(&mid).unwrap().height;
    assert!(mid_height < b.height(&h[30].block_hash()), "interrupted below the pin (at {mid_height})");
    reload(&mut n);
    gnb::accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis)).expect("resumes");
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h[30].block_hash()), Some(tip(&h))),
        "the persisted pin, not the most work");
    restart(&mut n);
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h[30].block_hash()), Some(tip(&h))));
}
