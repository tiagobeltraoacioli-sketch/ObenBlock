//! P5-G item 2: the proof-of-work cost of sync. Verifying a block costs one
//! GnB-SMH evaluation (v1: 64 MiB, about half a second; v3: 4 MiB, about a
//! sixth of that), the same as mining one attempt. Bitcoin Core never skips
//! a proof (one SHA-256d); this node never skips one either, but it must
//! never pay for the same proof twice. Blocks go through the REAL ingress
//! core (`gnb::ingress::BlockIngress`, what main.rs's processor calls) and
//! the real pipeline (`accept::accept_block`).

mod fix_common;
use fix_common::*;

use gnb::consensus::BlockHash;
use gnb::core::Block;
use gnb::ingress::{self, BlockIngress, BlockOutcome, PowCheck, PowGate};
use gnb::pow;

fn ctx(n: &Node) -> ingress::AcceptCtx<'_> {
    ingress::AcceptCtx {
        dag: &n.dag, store: &n.store, mempool: &n.mempool, node_state: &n.node_state,
        tip_tx: Some(&n.tip_tx), shielded: &n.shielded,
    }
}

/// The node's proof-of-work gate as the processor uses it (every proof it is
/// asked for goes to the PoW workers), evaluated inline and counted.
struct CountingPow(usize);

impl PowGate for CountingPow {
    fn check(&mut self, block: &Block, _hash: &[u8; 32]) -> PowCheck {
        self.0 += 1;
        if block.validate_pow() { PowCheck::Valid } else { PowCheck::Invalid }
    }
}

/// Deliver `b` as the answer to one of the node's directed pulls (how a
/// wanted body arrives), proofs through `gate`.
fn feed(core: &mut BlockIngress, n: &Node, b: &Block, gate: &mut CountingPow) -> BlockOutcome {
    match core.handle_block_gated(b.clone(), b.block_hash(), b.to_wire_bytes().len(), None, true,
                                  std::time::Instant::now(), unix_now(), &ctx(n), gate) {
        ingress::Gated::Done(o) => o,
        ingress::Gated::PowPending(_) => panic!("an inline gate never defers"),
    }
}

/// `n` coinbase-only blocks on `from`, built on `builder`'s DAG only (no
/// connect).
fn chain(builder: &Node, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
    let mut out = Vec::new();
    let mut tip = from;
    for i in 0..n {
        let b = empty_child(builder, tip, &format!("{tag}{i}"));
        let work = pow::block_work(b.header.bits, b.height);
        builder.dag.write().add_block(b.block_hash(), b.header.parents.clone(), b.header.timestamp, work).unwrap();
        tip = b.block_hash();
        out.push(b);
    }
    out
}

/// A pruned node re-syncs bodies it needs again (audit DAG-6: a reorg back
/// onto a branch whose bodies it pruned; the same path serves a body that
/// waits after a witness-dependent rejection). Every such block is already
/// in the DAG: its header entered it only after its proof was verified at
/// this same header height (the id commits to the proof's preimage and
/// nonce, and the restored copy's height is bound to the parents again), so
/// the DAG record IS the verified result, and it survives restarts. Here the
/// node restarted in between (its in-memory proof cache no longer holds
/// the honest blocks): restoring seven bodies must evaluate no proof.
/// Pre-fix each restored body was handed to the PoW workers (64 MiB GnB-SMH
/// v1 each) because the process cache had lost it.
#[test]
fn restoring_bodies_of_dag_blocks_evaluates_no_proof_of_work() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let builder = node_with(&genesis, &[]);
    let honest = chain(&builder, gh, 10, "h");
    let fork = chain(&builder, gh, 12, "f");
    let more = chain(&builder, honest[9].block_hash(), 3, "hm");

    let x = node_with(&genesis, &[]);
    for b in &honest {
        accept(&x, b).unwrap();
    }
    assert_eq!(x.store.prune_blocks_below(8).unwrap(), 8, "genesis and h0..h6 pruned");
    for b in &fork {
        accept(&x, b).unwrap();
    }
    assert_eq!(applied_tip(&x), Some(fork[11].block_hash()), "the heavier fork is applied");
    // A restart: the process forgets every proof it verified; the DAG keeps
    // the headers.
    for b in &honest {
        b.test_only_forget_pow();
        assert!(!b.pow_is_cached());
    }

    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let mut restore_gate = CountingPow(0);
    let mut new_gate = CountingPow(0);
    let mut restored = Vec::new();
    for b in &more {
        match feed(&mut core, &x, b, &mut new_gate) {
            BlockOutcome::Processed { result: Ok(_), missing_bodies, .. } => {
                for h in missing_bodies {
                    let body = honest.iter().find(|x| x.block_hash() == h).expect("a pruned honest block");
                    let outcome = feed(&mut core, &x, body, &mut restore_gate);
                    assert!(matches!(outcome, BlockOutcome::BodyRestored), "{outcome:?}");
                    restored.push(h);
                }
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(restored.len(), 7, "the seven pruned honest bodies (genesis is never re-applied)");
    assert_eq!(applied_tip(&x), Some(more[2].block_hash()), "back on the honest chain");
    assert_eq!(restore_gate.0, 0, "a restored body's proof was handed to the PoW workers");
    let evaluated = honest.iter().filter(|b| b.pow_is_cached()).count();
    assert_eq!(evaluated, 0, "restored bodies had their proof of work evaluated again");
    // The three new blocks' proofs were checked, once each.
    assert_eq!(new_gate.0, 3);
}

/// Why a proof verified once may answer for its block id (`validate_pow`'s
/// process cache, the DAG record above): the id commits to the proof's
/// preimage and nonce but not to the header height, and the height selects
/// the algorithm (GnB-SMH v1 below `core::powit_height()`, v3 from it). A
/// copy re-framed across that switch would be judged with the other
/// algorithm. It never gets that far: the body root the header commits to
/// changes version at the same height (`Block::body_merkle_root_at`: v2,
/// with the shielded and PoWit sections, from `powit_height()`), and every
/// ingress path checks the root at the claimed height before any proof
/// (`validate_structure_without_pow`). So every framing that reaches a
/// proof evaluation uses one algorithm. (Checked while looking for a PoW
/// result-cache defect, P5-G item 2: not reproducible.)
#[test]
fn a_reframing_across_the_pow_algorithm_switch_never_reaches_the_proof() {
    use gnb::core::{self, BlockHeader};
    let v3 = core::powit_height();
    assert!(v3 > 1 && v3 != u64::MAX, "mainnet switches to v3 at {v3}");
    let genesis = mk_genesis(unix_now() - 10_000);
    let builder = node_with(&genesis, &[]);
    // A v1-height block, re-framed at the v3 height.
    let mut b = empty_child(&builder, genesis.block_hash(), "v1");
    b.validate_structure_without_pow().expect("valid at its own height");
    let id = b.block_hash();
    b.height = v3;
    assert_eq!(b.block_hash(), id);
    assert_eq!(b.validate_structure_without_pow(), Err("invalid merkle root"));
    // A v3-height block (built directly: its root is the v2 body root),
    // re-framed one height lower.
    let mut c = Block {
        header: BlockHeader { version: 1, parents: vec![[7; 32]], merkle_root: core::MerkleRoot::ZERO,
                              timestamp: unix_now(), bits: core::POW_LIMIT_BITS, nonce: 0 },
        transactions: vec![coinbase("v3", core::tokenomics::block_subsidy_sat(v3), vec![0xC0; 20])],
        blue_score: v3, height: v3, shielded_transactions: Vec::new(), powit: Default::default(),
    };
    // From WITNESS_COMMITMENT_HEIGHT the coinbase commits to the witnesses.
    let wc = c.witness_commitment();
    c.transactions[0].inputs[0].script_sig.extend_from_slice(&wc);
    commit_block(&mut c);
    c.validate_structure_without_pow().expect("valid at its own height");
    c.height = v3 - 1;
    assert_eq!(c.validate_structure_without_pow(), Err("invalid merkle root"));
}

/// The DAG record answers only for the header it was made for. A copy that
/// claims a DAG block's id under another header height (the id does not
/// commit the height below the hardening activation) is judged as before:
/// refused before any proof work (its height is checked against its parents
/// first), and the wanted body is still restored afterwards.
#[test]
fn a_reframed_copy_of_a_dag_block_is_refused() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let builder = node_with(&genesis, &[]);
    let honest = chain(&builder, gh, 10, "rh");
    let fork = chain(&builder, gh, 12, "rf");
    let more = chain(&builder, honest[9].block_hash(), 3, "rm");
    let x = node_with(&genesis, &[]);
    for b in &honest {
        accept(&x, b).unwrap();
    }
    x.store.prune_blocks_below(8).unwrap();
    for b in &fork {
        accept(&x, b).unwrap();
    }
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let mut gate = CountingPow(0);
    let mut wanted = Vec::new();
    for b in &more {
        if let BlockOutcome::Processed { missing_bodies, .. } = feed(&mut core, &x, b, &mut gate) {
            wanted.extend(missing_bodies);
        }
    }
    let h = wanted.first().copied().expect("a wanted body");
    let body = honest.iter().find(|b| b.block_hash() == h).unwrap();
    let mut reframed = body.clone();
    reframed.height += 1;
    reframed.blue_score += 1;
    assert_eq!(reframed.block_hash(), h, "same id");
    let before = gate.0;
    let outcome = feed(&mut core, &x, &reframed, &mut gate);
    assert!(matches!(outcome, BlockOutcome::BodyRefused(_)), "{outcome:?}");
    assert!(x.dag.read().is_body_pending(&h), "still waiting for a body");
    assert_eq!(gate.0, before, "no proof work for a reframed copy");
    assert!(matches!(feed(&mut core, &x, body, &mut gate), BlockOutcome::BodyRestored));
}
