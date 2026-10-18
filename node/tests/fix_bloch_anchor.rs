//! The Bloch weak-subjectivity anchor (`--bloch-rpc`, docs/OBB-ANCHOR.md)
//! through the REAL acceptance pipeline: `accept::set_finality_checkpoint`
//! moves the applied chain onto the anchored one, and `anchoring::enforce`
//! refuses a chain that passed the anchored slot with another block, then
//! pins the anchored block once it arrives.

mod fix_common;
use fix_common::*;

use gnb::accept;
use gnb::anchoring::{self, ChainOps, Verdict};
use gnb::consensus::BlockHash;
use gnb::core::Block;
use gnb::obb_anchor::AnchorRecord;

fn chain_of(n: &Node, from: BlockHash, len: usize, tag: &str) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    let mut prev = from;
    for i in 0..len {
        let b = empty_child(n, prev, &format!("{tag}{i}"));
        prev = b.block_hash();
        accept(n, &b).expect("accepted");
        out.push(b);
    }
    out
}

fn pin(n: &Node, h: BlockHash) -> Result<accept::ChainOverride, accept::OverrideError> {
    accept::set_finality_checkpoint(h, &n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
}

struct Ops<'a>(&'a Node);

impl ChainOps for Ops<'_> {
    fn pin(&self, h: [u8; 32]) -> Result<(), String> {
        pin(self.0, h).map(|_| ()).map_err(|e| e.to_string())
    }
    fn refuse(&self, h: [u8; 32]) -> Result<(), String> {
        let n = self.0;
        accept::invalidate_block(h, &n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
            .map(|_| ()).map_err(|e| e.to_string())
    }
}

fn record(slot: u64, block: BlockHash) -> AnchorRecord {
    AnchorRecord {
        chain_id: gnb::core::node_chain_id().to_u32(),
        slot,
        block_id: block,
        finalized_at: slot + 125,
        w_digest: [3; 32],
    }
}

/// A pin to a block of the lighter chain moves the applied chain onto it at
/// once; a later pin that leaves it is refused.
#[test]
fn set_finality_checkpoint_moves_the_applied_chain() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let a = chain_of(&n, gh, 6, "pa");
    let b = chain_of(&n, gh, 4, "pb");
    let a_tip = a.last().unwrap().block_hash();
    let b_tip = b.last().unwrap().block_hash();
    assert_eq!(applied_tip(&n), Some(a_tip), "A is heavier");

    assert!(pin(&n, [0x99; 32]).unwrap_err().to_string().contains("not found"));
    let r = pin(&n, b[1].block_hash()).expect("pin");
    assert_eq!(r.tip, b_tip);
    assert_eq!(applied_tip(&n), Some(b_tip));
    assert_eq!(sel_tip(&n), Some(b_tip));
    assert_eq!(n.dag.read().finalized().map(|f| f.0), Some(b[1].block_hash()));

    // A block of A that is higher than the pin does not descend from it.
    let e = pin(&n, a[3].block_hash()).unwrap_err().to_string();
    assert!(e.contains("does not descend"), "{e}");
    assert_eq!(applied_tip(&n), Some(b_tip));
    // A new block on A is never selected.
    let a7 = empty_child(&n, a_tip, "pa7");
    let _ = accept(&n, &a7);
    assert_eq!(applied_tip(&n), Some(b_tip));
}

/// The anchor's block is unknown and the node's chain passed its slot with
/// another block: that chain is refused, and the anchored chain is pinned
/// once it arrives.
#[test]
fn an_unknown_anchor_refuses_the_chain_then_pins_the_anchored_one() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let a = chain_of(&n, gh, 6, "ua");
    // Build B on a scratch node (so the node under test does not know it).
    let scratch = node_with(&genesis, &[]);
    let b = chain_of(&scratch, gh, 4, "ub");
    // Slot 3 names the chain block below height 3: b[1] (height 2).
    let anchor = record(3, b[1].block_hash());
    let ops = Ops(&n);

    assert_eq!(anchoring::enforce(&n.dag, &ops, &anchor), Verdict::Pending);
    assert_eq!(applied_tip(&n), Some(a[1].block_hash()), "rolled back below the slot");
    assert!(n.dag.read().is_invalid(&a[2].block_hash()));

    for blk in &b {
        accept(&n, blk).expect("B accepted");
    }
    assert_eq!(anchoring::enforce(&n.dag, &ops, &anchor), Verdict::Pinned);
    assert_eq!(applied_tip(&n), Some(b.last().unwrap().block_hash()));
    assert_eq!(anchoring::enforce(&n.dag, &ops, &anchor), Verdict::Pinned, "idempotent");
}
