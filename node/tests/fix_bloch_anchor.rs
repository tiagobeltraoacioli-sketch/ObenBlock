//! The Bloch anchor (`--bloch-rpc`, docs/OBB-ANCHOR.md) is ADVISORY ONLY
//! (docs/DESIGN-obenblock.md §8: "an anchor never sets a checkpoint by
//! itself"). Through the REAL acceptance pipeline: a hostile registry answer
//! (an anchor naming the lighter chain, or a block the node does not have)
//! raises the conflict alert and changes nothing in fork choice: same applied
//! and selected tip, same pin, same finality anchor setting, no block marked
//! invalid, nothing persisted. An agreeing anchor is reported, not applied.
//! One test function: the anchor status is process-wide.

mod fix_common;
use fix_common::*;

use gnb::anchoring::{self, Verdict};
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

fn record(slot: u64, block: BlockHash) -> AnchorRecord {
    AnchorRecord {
        chain_id: gnb::core::node_chain_id().to_u32(),
        slot,
        block_id: block,
        finalized_at: slot + 125,
        w_digest: [3; 32],
    }
}

/// Everything fork choice reads, as one comparable value.
fn fork_choice(n: &Node, blocks: &[&[Block]]) -> String {
    let dag = n.dag.read();
    let invalid: Vec<bool> = blocks.iter().flat_map(|c| c.iter()).map(|b| dag.is_invalid(&b.block_hash())).collect();
    let fin = gnb::powit::finality_info_json(&dag, 8);
    format!("{:?} {:?} {:?} {} {} {:?}", applied_tip(n), dag.selected_tip(), dag.finalized(), fin["anchor"],
            fin["anchor_source"], invalid)
}

#[test]
fn a_hostile_bloch_anchor_changes_nothing_in_fork_choice() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let a = chain_of(&n, gh, 6, "ha");
    let b = chain_of(&n, gh, 4, "hb");
    // A block only a scratch node knows.
    let scratch = node_with(&genesis, &[]);
    let c = chain_of(&scratch, gh, 4, "hc");
    let a_tip = a.last().unwrap().block_hash();
    assert_eq!(applied_tip(&n), Some(a_tip), "A is heavier");
    let before = fork_choice(&n, &[&a, &b]);
    anchoring::restore("hostile-mock".into());

    // Slot 3 names the selected-chain block below height 3 (height 2).
    // 1. The lighter chain's block: a contradiction of the selected chain.
    let hostile = record(3, b[1].block_hash());
    assert!(matches!(anchoring::check(&n.dag.read(), &hostile), Verdict::Conflict(_)));
    anchoring::take_answer(Ok(Some(hostile)), "hostile-mock", &n.dag);
    assert_eq!(fork_choice(&n, &[&a, &b]), before, "a conflicting anchor moved fork choice");
    let s = anchoring::status_json();
    assert_eq!((s["status"].as_str(), s["alert"].as_bool(), s["advisory"].as_bool()),
               (Some("conflict"), Some(true), Some(true)), "{s}");
    let info = gnb::powit::finality_info_json(&n.dag.read(), 8);
    assert_eq!(info["bloch_anchor"]["alert"], true, "getfinalityinfo carries the alert");
    // A new block on A is still selected.
    let a7 = empty_child(&n, a_tip, "ha7");
    accept(&n, &a7).expect("A extends");
    assert_eq!(applied_tip(&n), Some(a7.block_hash()));
    let before = fork_choice(&n, &[&a, &b]);

    // 2. A newer anchor naming a block the node does not have: the alert,
    //    no refusal of the chain that passed the slot.
    let unknown = record(4, c[2].block_hash());
    assert!(matches!(anchoring::check(&n.dag.read(), &unknown), Verdict::Unknown(_)));
    anchoring::take_answer(Ok(Some(unknown)), "hostile-mock", &n.dag);
    assert_eq!(fork_choice(&n, &[&a, &b]), before, "an unknown anchor moved fork choice");
    let s = anchoring::status_json();
    assert_eq!((s["status"].as_str(), s["alert"].as_bool()), (Some("unknown"), Some(true)), "{s}");

    // 3. Nothing about an anchor is persisted (no stored key fork choice or a
    //    restart could read).
    assert_eq!(n.store.get_meta("bloch_anchor/latest").unwrap(), None);

    // 4. An agreeing anchor: reported, never applied.
    let agrees = record(5, a[3].block_hash());
    assert_eq!(anchoring::check(&n.dag.read(), &agrees), Verdict::Ahead);
    anchoring::take_answer(Ok(Some(agrees)), "mock", &n.dag);
    assert_eq!(fork_choice(&n, &[&a, &b]), before);
    let s = anchoring::status_json();
    assert_eq!((s["status"].as_str(), s["alert"].as_bool()), (Some("ahead"), Some(false)), "{s}");
}
