//! Package A2 (docs/DESIGN-obenblock.md §7, §9 O2): the PoWit finality pin is
//! sticky, a conflicting finalization raises an alert and waits for the
//! operator (`setfinalitycheckpoint`, `ignorefinalized`), a partitioned side
//! that did not finalize rejoins the side that did, and the ingress lets
//! such a branch in although its work is below the anti-DoS threshold
//! (rationed).
//!
//! Every block goes through the REAL acceptance pipeline (and the real
//! ingress core for the heal admission); PoWit states are synthetic (below
//! the PoWit activation acceptance computes none), as in
//! `fix_powit_finality_min_work.rs`. The minimum chain work is 0 in this
//! binary.

mod fix_common;
use fix_common::*;

use std::time::Instant;

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction};
use gnb::finality::{self, PinSource};
use gnb::ingress::{self, BlockIngress, BlockOutcome, DropReason, FinalityHealBudget, WorkAdmission};
use gnb::{accept, pow};
use libp2p::PeerId;

fn zero_minimum_chain_work() {
    let _ = ingress::set_minimum_chain_work(0);
    assert_eq!(ingress::minimum_chain_work(), 0);
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
        self.dag.add_block(b.block_hash(), vec![parent], b.header.timestamp, pow::block_work(bits, height))
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
}

/// A PoWit state whose witness set has finalized `cp` (slot 6, beyond the
/// activation checkpoint at slot 1, so it pins fork choice).
fn state_finalizing(cp: BlockHash) -> core::powit::PowitState {
    let mut st = core::powit::PowitState::genesis(1, cp);
    st.finalized = core::powit::Checkpoint { height: 6, hash: cp };
    st.justified = st.finalized;
    st
}

/// A PoWit state that finalized nothing beyond activation.
fn state_unfinalized(cp: BlockHash) -> core::powit::PowitState {
    core::powit::PowitState::genesis(1, cp)
}

fn finalize_from(n: &Node, blocks: &[Block], cp: &Block) {
    for blk in blocks {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(cp.block_hash())).unwrap();
    }
}

fn deliver_all(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

fn pin_of(n: &Node) -> Option<BlockHash> {
    n.dag.read().finalized().map(|(h, _)| h)
}

fn set_checkpoint(n: &Node, h: BlockHash) -> Result<accept::ChainOverride, accept::OverrideError> {
    accept::set_finality_checkpoint(h, &n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
}

fn ignore(n: &Node) -> Result<accept::ChainOverride, accept::OverrideError> {
    accept::ignore_finalized(&n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
}

/// A: 20 blocks whose witness set finalized A[5] from A[10] on; B: a
/// heavier 30-block chain from genesis. The pin is persisted and survives
/// a restart even when the applied tip's own state no longer carries it
/// (before A2 the pin was re-derived from that state only, and the node
/// then moved to the heavier B, below its finality).
#[test]
fn the_pin_is_sticky_across_restarts_and_a_heavier_chain_never_takes_the_node_below_it() {
    zero_minimum_chain_work();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 20, "a");
    let heavy = b.chain(gh, 30, "b");
    let mut n = node_with(&genesis, &[]);
    finalize_from(&n, &a[10..], &a[5]);

    deliver_all(&n, &a);
    assert_eq!(pin_of(&n), Some(a[5].block_hash()));
    let rec = finality::load_pin(&n.store).expect("persisted when it moved");
    assert_eq!((rec.hash, rec.source), (a[5].block_hash(), PinSource::WitnessSet));

    // The applied tip's state loses its finality (as if the state were
    // re-derived without it): the persisted pin still holds after a restart.
    gnb::powit::save_state(&n.store, &a[19].block_hash(), &state_unfinalized(a[0].block_hash())).unwrap();
    restart(&mut n);
    assert_eq!(pin_of(&n), Some(a[5].block_hash()), "restored from disk");

    deliver_all(&n, &heavy);
    assert_eq!(applied_tip(&n), Some(a[19].block_hash()), "the heavier chain misses the pin");
    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(a[19].block_hash()), "and still after a restart");
    assert_eq!(pin_of(&n), Some(a[5].block_hash()));
    // The legacy pre-DAG-6 meta key is never read as the pin.
    n.store.put_meta("finalized_height", &3u64.to_le_bytes()).unwrap();
    restart(&mut n);
    assert_eq!(pin_of(&n), Some(a[5].block_hash()));
}

/// A finalized A[5]; B, forking at genesis, finalized B[5]: a conflicting
/// finalization. The node stays on A and raises the alert (once per
/// checkpoint); the operator then pins B[5] (`setfinalitycheckpoint`) and
/// the node moves to B, and `ignorefinalized` drops the pin.
#[test]
fn a_conflicting_finalization_raises_the_alert_and_waits_for_the_operator() {
    zero_minimum_chain_work();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 20, "a");
    let other = b.chain(gh, 30, "b");
    let mut n = node_with(&genesis, &[]);
    finalize_from(&n, &a[10..], &a[5]);
    finalize_from(&n, &other[10..], &other[5]);

    deliver_all(&n, &a);
    assert_eq!(pin_of(&n), Some(a[5].block_hash()));
    assert!(finality::load_conflicts(&n.store).conflicts.is_empty());
    deliver_all(&n, &other);
    assert_eq!(applied_tip(&n), Some(a[19].block_hash()), "the pin holds whatever the work");
    assert_eq!(pin_of(&n), Some(a[5].block_hash()), "a conflicting checkpoint never replaces the pin");
    let log = finality::load_conflicts(&n.store);
    assert_eq!(log.conflicts.len(), 1, "one conflicting checkpoint, recorded once: {log:?}");
    assert_eq!(log.conflicts[0].checkpoint, hex::encode(other[5].block_hash()));
    assert_eq!(log.conflicts[0].block, hex::encode(other[10].block_hash()), "the first block that carried it");
    assert_eq!(log.conflicts[0].pin, hex::encode(a[5].block_hash()));
    let info = finality::info_json(&n.dag.read(), &n.store);
    assert_eq!(info["conflict"], true);
    assert_eq!(info["applied_tip_on_finalized_chain"], true);
    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(a[19].block_hash()), "the alert does not resolve itself");
    assert_eq!(finality::load_conflicts(&n.store).conflicts.len(), 1, "the alert is persisted");

    // The operator decides for B.
    assert!(set_checkpoint(&n, [0xEE; 32]).is_err(), "an unknown block");
    let r = set_checkpoint(&n, other[5].block_hash()).expect("moves to B");
    assert_eq!(r.tip, other[29].block_hash());
    assert_eq!(applied_tip(&n), Some(other[29].block_hash()));
    assert_eq!(pin_of(&n), Some(other[5].block_hash()));
    assert!(finality::load_conflicts(&n.store).conflicts.is_empty(), "the alert is cleared");
    let rec = finality::load_pin(&n.store).unwrap();
    assert_eq!((rec.hash, rec.source), (other[5].block_hash(), PinSource::Operator));
    restart(&mut n);
    assert_eq!(pin_of(&n), Some(other[5].block_hash()));
    assert_eq!(applied_tip(&n), Some(other[29].block_hash()));

    // An older checkpoint on the same chain: the operator may move the pin
    // back too.
    set_checkpoint(&n, other[2].block_hash()).expect("pin back");
    assert_eq!(pin_of(&n), Some(other[2].block_hash()));

    // ignorefinalized: no pin, the most work (B) wins, and B's own witness
    // set pins B[5] again on the next block.
    ignore(&n).expect("drops the pin");
    assert!(finality::load_pin(&n.store).is_none());
    let next = b.chain(other[29].block_hash(), 1, "c");
    finalize_from(&n, &next, &other[5]);
    deliver_all(&n, &next);
    assert_eq!(pin_of(&n), Some(other[5].block_hash()));
    assert_eq!(applied_tip(&n), Some(next[0].block_hash()));
}

/// Partition heal (docs/DESIGN-pow-powit.md §7.6): a common prefix C
/// finalized C[4]; side A (more work) finalized nothing more, side B (less
/// work) finalized B[3]. A node on A adopts B[3] when B's blocks arrive (it
/// extends the pin) and moves to B, the heaviest chain through the latest
/// final checkpoint.
#[test]
fn the_side_that_did_not_finalize_rejoins_the_side_that_did() {
    zero_minimum_chain_work();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let c = b.chain(gh, 10, "c");
    let side_a = b.chain(c[9].block_hash(), 30, "a");
    let side_b = b.chain(c[9].block_hash(), 12, "b");
    let mut n = node_with(&genesis, &[]);
    finalize_from(&n, &c[8..], &c[4]);
    finalize_from(&n, &side_a, &c[4]);
    finalize_from(&n, &side_b[..6], &c[4]);
    finalize_from(&n, &side_b[6..], &side_b[3]);

    deliver_all(&n, &c);
    deliver_all(&n, &side_a);
    assert_eq!(pin_of(&n), Some(c[4].block_hash()));
    assert_eq!(applied_tip(&n), Some(side_a[29].block_hash()));
    for (i, blk) in side_b.iter().enumerate() {
        accept(&n, blk).unwrap();
        if i < 6 {
            assert_eq!(applied_tip(&n), Some(side_a[29].block_hash()), "B[{i}]: the most work through C[4]");
        }
    }
    assert_eq!(pin_of(&n), Some(side_b[3].block_hash()), "B's finality extends the pin");
    assert_eq!(applied_tip(&n), Some(side_b[11].block_hash()), "the node rejoined the finalized side");
    assert!(finality::load_conflicts(&n.store).conflicts.is_empty(), "no conflict: A never finalized");
    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(side_b[11].block_hash()));
    assert_eq!(pin_of(&n), Some(side_b[3].block_hash()));
}

fn pulled(core: &mut BlockIngress, n: &Node, b: &Block) -> BlockOutcome {
    let ctx = ingress::AcceptCtx {
        dag: &n.dag, store: &n.store, mempool: &n.mempool, node_state: &n.node_state,
        tip_tx: Some(&n.tip_tx), shielded: &n.shielded,
    };
    core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), Some(PeerId::random()), true,
        Instant::now(), unix_now(), &ctx)
}

/// Partition heal through ingress: a low-work branch above the pin is let
/// in (`WorkAdmission::FinalityHeal`, rationed); one forking below the pin,
/// or any low-work branch without a pin, stays refused (`LowWork`).
#[test]
fn ingress_lets_a_low_work_branch_above_the_pin_in_rationed() {
    zero_minimum_chain_work();
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 800, "h");
    let n = node_with(&genesis, &[]);
    deliver_all(&n, &honest);
    let above = b.chain(honest[399].block_hash(), 2, "above");
    let below = b.chain(honest[199].block_hash(), 1, "below");

    // No pin: the work rule alone.
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    assert!(matches!(pulled(&mut core, &n, &above[0]), BlockOutcome::Dropped(DropReason::LowWork)));

    // Pin honest[299] (as the witness set would).
    n.dag.write().set_finalized(honest[299].block_hash(), honest[299].height);
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    core.heal_budget = FinalityHealBudget::with_rate(1, 0.0);
    assert!(matches!(pulled(&mut core, &n, &below[0]), BlockOutcome::Dropped(DropReason::LowWork)),
        "a branch below the pin is never selectable: refused");
    match pulled(&mut core, &n, &above[0]) {
        BlockOutcome::Processed { admission: WorkAdmission::FinalityHeal, result: Ok(_), .. } => {}
        o => panic!("expected a finality-heal admission, got {o:?}"),
    }
    assert!(n.dag.read().has_block(&above[0].block_hash()));
    assert!(matches!(pulled(&mut core, &n, &above[1]), BlockOutcome::Dropped(DropReason::LowWork)),
        "the ration is spent: the work rule alone again");
    assert!(!n.dag.read().has_block(&above[1].block_hash()));
}
