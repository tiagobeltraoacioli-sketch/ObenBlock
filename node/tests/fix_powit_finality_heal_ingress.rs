//! Review HIGH 2 of the PoWit finality pin, end to end THROUGH INGRESS
//! (`BlockIngress::handle_block`, as the network processor feeds it), with
//! real witness shares, KES keys and hybrid-signed attestations: every PoWit
//! state is computed by acceptance.
//!
//! The POW-3 work rule (`ingress::work_rule`) drops every block of a chain
//! that cannot come within `ANTI_DOS_WINDOW_BLOCKS` (360) selected-chain
//! blocks of work of the tip. After a partition longer than that, the
//! heavier side B, which finalized nothing, dropped every block of side A,
//! which did, so it never stored them, never learned A's finality (the pin
//! learns it from any STORED block, PoWit finding 2) and the network stayed
//! split. Side A's blocks claim a finality newer than B's (their attestations
//! link from a checkpoint A justified), so the ancestors the node pulls for
//! them are admitted below the work threshold, within budgets
//! (`ingress::FinalityPulls`).
//!
//! Node test builds use gnb-crypto's `test-pow-limit` (every expected target
//! is the pow limit), under which a GnB-SMH v3 block (from the PoWit
//! activation) carries no work at all. The work gap is therefore built below
//! the activation (here 160): side B mines four blocks per DAG layer there
//! (each merging the other three), side A one, and both continue above it.

mod fix_common;
use fix_common::*;

use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use gnb::consensus::BlockHash;
use gnb::core::kes::KesSigner;
use gnb::core::powit::{Attestation, ChainView, Checkpoint, KeyId, PowitBody, PowitState, TESTNET_PARAMS};
use gnb::core::witness_share::WitnessShare;
use gnb::core::{self, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput};
use gnb::ingress::{self, BlockIngress, BlockOutcome, DropReason, WorkAdmission};
use gnb::pow;
use gnb::powit::{self, DagChainView};
use libp2p::PeerId;

const ACT: u64 = 160;
const P: core::powit::PowitParams = TESTNET_PARAMS;
/// Blocks per DAG layer of side B below the activation.
const WIDTH: usize = 4;

fn setup() {
    let _ = core::set_node_chain_id(ChainId::Testnet);
    let _ = core::set_powit_height_override(ACT);
    assert_eq!(core::node_chain_id(), ChainId::Testnet, "one chain id per test binary");
    assert_eq!(core::powit_height(), ACT, "one PoWit activation per test binary");
    assert_eq!(ingress::minimum_chain_work(), 0, "testnet: no minimum chain work");
}

/// A genuine KES witness key (depth 3: PoWit epochs 0..=7, heights 160..=319).
struct Key {
    signer: std::cell::RefCell<KesSigner>,
}

impl Key {
    fn new(seed: u8) -> Key {
        Key { signer: std::cell::RefCell::new(KesSigner::generate(3, [seed; 32], |_| {}).unwrap()) }
    }
    fn id(&self) -> KeyId {
        self.signer.borrow().public().witness_id()
    }
    fn can_sign(&self, epoch: u64) -> bool {
        epoch >= self.signer.borrow().epoch()
    }
    fn attest(&self, source: Checkpoint, target: Checkpoint) -> Attestation {
        let e = P.epoch(ACT, target.height);
        let mut s = self.signer.borrow_mut();
        if e > s.epoch() {
            s.evolve_to(e).unwrap();
        }
        Attestation::sign(ChainId::Testnet, source, target, &s).unwrap()
    }
}

/// A block on `parents` (known to `n`) with this PoWit section; the coinbase
/// pays the shares as consensus requires.
fn build(n: &Node, mut parents: Vec<BlockHash>, tag: &str, shares: Vec<WitnessShare>, atts: Vec<Attestation>) -> Block {
    parents.sort_unstable();
    let (height, pts) = {
        let d = n.dag.read();
        let h = parents.iter().map(|p| d.get_block_data(p).expect("parent known").height).max().unwrap() + 1;
        let ts = parents.iter().map(|p| d.get_block_data(p).unwrap().timestamp).max().unwrap();
        (h, ts)
    };
    let bits = pow::expected_bits(pts, height).unwrap();
    let cb = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: tag.as_bytes().to_vec(),
                               sequence: u32::MAX }],
        outputs: Block::coinbase_outputs(height, vec![0xC0; 20], 0, &shares),
        locktime: 0,
    };
    let mut b = Block {
        header: BlockHeader { version: 1, parents, merkle_root: MerkleRoot::ZERO, timestamp: pts + 1, bits, nonce: 0 },
        transactions: vec![cb],
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
        powit: PowitBody { shares, attestations: atts, evidence: Vec::new() },
    };
    commit_block(&mut b);
    b.test_only_assume_pow_valid();
    b
}

/// A miner and its witnesses building one side through a real node.
struct Producer {
    node: Node,
}

impl Producer {
    fn new(genesis: &Block) -> Self {
        Producer { node: node_with(genesis, &[]) }
    }

    fn tip(&self) -> BlockHash {
        applied_tip(&self.node).unwrap()
    }

    fn adopt(&self, blocks: &[Block]) {
        for b in blocks {
            accept(&self.node, b).unwrap_or_else(|e| panic!("adopt h={}: {e}", b.height));
        }
    }

    /// The open checkpoint slot of a block at `height` on `parent`, if the
    /// parent's state has one above its justified checkpoint.
    fn open_target(&self, parent: BlockHash, height: u64) -> Option<(PowitState, Checkpoint)> {
        let st = powit::load_state(&self.node.store, &parent)?;
        let slot = ACT + (height - ACT) / P.checkpoint_interval * P.checkpoint_interval;
        if slot <= st.justified.height {
            return None;
        }
        let d = self.node.dag.read();
        let hash = DagChainView { dag: &d, start: Some(parent) }.selected_at(slot)?;
        drop(d);
        Some((st, Checkpoint { height: slot, hash }))
    }

    /// Extend the tip by `n` blocks, each with one share per key of `share_keys`
    /// (from the activation) and the attestation of each signer the next
    /// block's witness set holds for the open slot.
    fn extend(&self, n: usize, tag: &str, share_keys: &[&Key], signers: &[&Key]) -> Vec<Block> {
        let stop = AtomicBool::new(false);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let parent = self.tip();
            let height = self.node.dag.read().get_block_data(&parent).unwrap().height + 1;
            let mut shares = Vec::new();
            if core::powit_active(height) {
                let pb = self.node.store.get_block(&parent).unwrap().unwrap();
                for k in share_keys {
                    shares.push(powit::mine_share(&pb, parent, k.id(), &[0x51; 20], height << 16, 100_000, &stop)
                        .expect("a share"));
                }
            }
            let mut atts = Vec::new();
            if let Some((st, target)) = self.open_target(parent, height) {
                let te = P.epoch(ACT, target.height);
                let members = st.witness_set_for_block(&P, te, height);
                for k in signers {
                    let voted = st.votes.get(&target).is_some_and(|v| v.contains_key(&k.id()));
                    if members.iter().any(|(m, _)| *m == k.id()) && !voted && k.can_sign(te) {
                        atts.push(k.attest(st.justified, target));
                    }
                }
            }
            let b = build(&self.node, vec![parent], &format!("{tag}{i}"), shares, atts);
            accept(&self.node, &b).unwrap_or_else(|e| panic!("{tag} h={height}: {e}"));
            out.push(b);
        }
        out
    }

    /// `layers` DAG layers of `WIDTH` blocks above the tip, each block
    /// merging the whole layer below; then one block merging the last layer.
    fn wide(&self, layers: usize, tag: &str) -> Vec<Block> {
        let mut out = Vec::new();
        let mut below = vec![self.tip()];
        for l in 0..layers {
            let layer: Vec<Block> = (0..WIDTH)
                .map(|j| build(&self.node, below.clone(), &format!("{tag}{l}.{j}"), Vec::new(), Vec::new()))
                .collect();
            for b in &layer {
                accept(&self.node, b).unwrap_or_else(|e| panic!("{tag} layer {l}: {e}"));
            }
            below = layer.iter().map(|b| b.block_hash()).collect();
            out.extend(layer);
        }
        let join = build(&self.node, below, &format!("{tag}join"), Vec::new(), Vec::new());
        accept(&self.node, &join).unwrap();
        out.push(join);
        out
    }

    fn tip_state(&self) -> PowitState {
        powit::load_state(&self.node.store, &self.tip()).expect("PoWit state")
    }
}

fn pin_of(n: &Node) -> Option<BlockHash> {
    n.dag.read().finalized().map(|(h, _)| h)
}

fn ctx(n: &Node) -> ingress::AcceptCtx<'_> {
    ingress::AcceptCtx {
        dag: &n.dag, store: &n.store, mempool: &n.mempool, node_state: &n.node_state,
        tip_tx: Some(&n.tip_tx), shielded: &n.shielded,
    }
}

/// The partition: a common chain C (9 blocks), then side A (150 blocks below
/// the activation, then 60 above it: the witnesses' shares, then their votes:
/// it finalizes) and side B (150 layers of four blocks below the activation,
/// then 380 blocks above it, no witness: it finalizes nothing). B's tip is
/// about 450 blocks of work above A's, more than the 360-block window.
struct Heal {
    genesis: Block,
    common: Vec<Block>,
    a: Vec<Block>,
    b: Vec<Block>,
    a_fin: Checkpoint,
}

fn heal() -> Heal {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let (k1, k2) = (Key::new(61), Key::new(62));
    let side_a = Producer::new(&genesis);
    let common = side_a.extend(9, "c", &[], &[]);
    let mut a = side_a.extend(150, "a", &[], &[]);
    a.extend(side_a.extend(40, "s", &[&k1, &k2], &[&k1, &k2]));
    a.extend(side_a.extend(20, "v", &[], &[&k1, &k2]));
    let a_fin = side_a.tip_state().finalized;
    assert!(a.iter().any(|b| b.block_hash() == a_fin.hash), "side A finalized: {a_fin:?}");
    let side_b = Producer::new(&genesis);
    side_b.adopt(&common);
    let mut b = side_b.wide(150, "w");
    b.extend(side_b.extend(380, "b", &[], &[]));
    assert_eq!(side_b.tip_state().finalized.height, ACT, "side B finalized nothing");
    Heal { genesis, common, a, b, a_fin }
}

/// A synced node of side B.
fn side_b_node(h: &Heal) -> Node {
    let n = node_with(&h.genesis, &[]);
    for blk in h.common.iter().chain(&h.b) {
        accept(&n, blk).unwrap_or_else(|e| panic!("side B h={}: {e}", blk.height));
    }
    assert_eq!((pin_of(&n), applied_tip(&n)), (None, Some(h.b.last().unwrap().block_hash())));
    n
}

/// Side A reaches the side-B node as the network delivers it: A's tip
/// gossiped by `peer`, then each missing parent as the answer to the node's
/// directed pull, down to the first block above C. `answer` names the peer
/// that answers each pull (`None`: a new one each time).
fn pull(core: &mut BlockIngress, n: &Node, chain: &[Block], peer: PeerId, answer: Option<PeerId>, now: Instant)
    -> Vec<BlockOutcome>
{
    let mut out = Vec::new();
    let tip = chain.last().unwrap();
    out.push(core.handle_block(tip.clone(), tip.block_hash(), tip.to_wire_bytes().len(), Some(peer), false, now,
        unix_now(), &ctx(n)));
    for blk in chain[..chain.len() - 1].iter().rev() {
        out.push(core.handle_block(blk.clone(), blk.block_hash(), blk.to_wire_bytes().len(),
            Some(answer.unwrap_or_else(PeerId::random)), true, now, unix_now(), &ctx(n)));
    }
    out
}

fn stored(n: &Node, blocks: &[Block]) -> usize {
    let d = n.dag.read();
    blocks.iter().filter(|b| d.has_block(&b.block_hash())).count()
}

/// Review HIGH 2: a chain below the window that claims no finality is still
/// refused, and the heal converges through ingress across the work window.
#[test]
fn a_healed_partition_converges_through_ingress_across_the_work_window() {
    let h = heal();
    let n = side_b_node(&h);
    let a_tip = h.a.last().unwrap().block_hash();
    {
        let d = n.dag.read();
        let threshold = ingress::anti_dos_work_threshold(&d);
        let a_work = d.get_block_data(&h.common.last().unwrap().block_hash()).unwrap().blue_work
            + h.a.iter().map(|b| core::block_work(b.header.bits, b.height)).sum::<u128>();
        let per_block = core::block_work(h.a[0].header.bits, h.a[0].height);
        assert!(a_work + ingress::ANTI_DOS_WINDOW_BLOCKS as u128 * per_block
            < ingress::tip_blue_work(&d), "a work gap over 360 blocks: {a_work} vs {}", ingress::tip_blue_work(&d));
        assert!(a_work < threshold, "side A is entirely below the anti-DoS threshold ({a_work} < {threshold})");
    }
    // A chain below the window that claims no finality is still refused.
    let plain = Producer::new(&h.genesis);
    plain.adopt(&h.common);
    let fork = plain.extend(5, "p", &[], &[]);
    let mut core = BlockIngress::new();
    let out = pull(&mut core, &n, &fork, PeerId::random(), None, Instant::now());
    assert!(matches!(out.last().unwrap(), BlockOutcome::Dropped(DropReason::LowWork)), "{:?}", out.last());
    assert_eq!(stored(&n, &fork), 0);

    // Side A claims a newer finality: the heal.
    let out = pull(&mut core, &n, &h.a, PeerId::random(), None, Instant::now());
    let bottom = out.last().unwrap();
    assert!(matches!(bottom, BlockOutcome::Processed { admission: WorkAdmission::FinalityBacked, result: Ok(_), .. }),
        "the first block above C is admitted as finality-backed: {bottom:?}");
    assert_eq!(pin_of(&n), Some(h.a_fin.hash), "the side-B node learned A's finality");
    assert_eq!(applied_tip(&n), Some(a_tip), "and the partition healed onto A");
    assert!(powit::finality_info_json(&n.dag.read(), 8)["conflict"].is_null());

}

/// Review HIGH 2, the bounds: admissions below the work threshold are
/// charged to the peer that delivered each block and to the node; a spent
/// budget refuses the block (`FinalityBudgetExhausted`, nothing stored) and
/// the heal resumes as the budget refills.
#[test]
fn finality_backed_pulls_are_bounded_per_peer_and_per_node() {
    let h = heal();
    let a_tip = h.a.last().unwrap().block_hash();

    // Per delivering peer: one peer delivers everything, 30 admissions.
    let n = side_b_node(&h);
    let mut core = BlockIngress::new().with_finality_pull_budgets(30, 10_000);
    let p = PeerId::random();
    let t0 = Instant::now();
    pull(&mut core, &n, &h.a, p, Some(p), t0);
    let refused = core.take_orphan_events().refused;
    assert!(refused.iter().any(|(_, r)| *r == DropReason::FinalityBudgetExhausted), "{refused:?}");
    assert_eq!(stored(&n, &h.a), 30, "the delivering peer's budget");
    assert_eq!(pin_of(&n), None, "not enough of A to learn its finality yet");
    // Its budget refills (one block a minute, at most 30 at a time): the
    // next pulls of the refused block resume the heal.
    let mut now = t0;
    while applied_tip(&n) != Some(a_tip) {
        now += Duration::from_secs(31 * 60);
        assert!(now < t0 + Duration::from_secs(12 * 3_600), "the heal stalled at {} blocks", stored(&n, &h.a));
        let next = h.a.iter().find(|b| !n.dag.read().has_block(&b.block_hash())).unwrap();
        let _ = core.handle_block(next.clone(), next.block_hash(), next.to_wire_bytes().len(), Some(p), true, now,
            unix_now(), &ctx(&n));
    }
    assert_eq!(pin_of(&n), Some(h.a_fin.hash));

    // Per node: every block from another peer, 20 admissions in all.
    let m = side_b_node(&h);
    let mut core = BlockIngress::new().with_finality_pull_budgets(10_000, 20);
    pull(&mut core, &m, &h.a, PeerId::random(), None, t0);
    assert!(core.take_orphan_events().refused.iter().any(|(_, r)| *r == DropReason::FinalityBudgetExhausted));
    assert_eq!(stored(&m, &h.a), 20, "the node's budget, whoever delivers");
    assert_eq!(pin_of(&m), None);
}

/// The claim test itself: a block claims a finality newer than the node's
/// when one of its attestations links from a checkpoint more than one
/// interval above the node's pin (with no pin, above the activation).
#[test]
fn a_block_claims_finality_when_its_votes_link_from_beyond_the_pin() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let n = node_with(&genesis, &[]);
    let floor = ingress::finality_claim_floor(&n.dag.read());
    assert_eq!(floor, ACT + P.checkpoint_interval);
    let k = Key::new(63);
    let vote = |source: u64| {
        let mut b = mk_genesis(1);
        b.powit.attestations = vec![k.attest(Checkpoint { height: source, hash: [1; 32] },
            Checkpoint { height: source + P.checkpoint_interval, hash: [2; 32] })];
        b
    };
    assert!(!ingress::claims_finality(&vote(ACT), floor), "a link from the activation checkpoint");
    assert!(!ingress::claims_finality(&vote(ACT + P.checkpoint_interval), floor), "justified one slot on");
    assert!(ingress::claims_finality(&vote(ACT + 2 * P.checkpoint_interval), floor), "finalized one slot on");
    assert!(!ingress::claims_finality(&mk_genesis(1), floor), "no vote, no claim");
}
