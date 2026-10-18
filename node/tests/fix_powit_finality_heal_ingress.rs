//! Review HIGH 2 of the PoWit finality pin, and round 2 of that review (H1,
//! M2, L4), end to end THROUGH INGRESS (`BlockIngress::handle_block`, as the
//! network processor feeds it), with real witness shares, KES keys and
//! hybrid-signed attestations: every PoWit state is computed by acceptance.
//!
//! The POW-3 work rule (`ingress::work_rule`) drops every block of a chain
//! that cannot come within `ANTI_DOS_WINDOW_BLOCKS` (360) selected-chain
//! blocks of work of the tip. After a partition longer than that, the
//! heavier side B, which finalized nothing, dropped every block of side A,
//! which did, so it never stored them, never learned A's finality (the pin
//! learns it from any STORED block, PoWit finding 2) and the network stayed
//! split. A block of side A carries a finality claim: a vote linking from a
//! checkpoint A justified beyond B's finality, signed by a key with weight in
//! the witness set B's own state derives, whose target lies in the chain the
//! node pulls for it; the blocks of that chain are admitted below the work
//! threshold, within budgets (`ingress::FinalityPulls`).
//!
//! Node test builds use gnb-crypto's `test-pow-limit` (every expected target
//! is the pow limit), under which a GnB-SMH v3 block (from the PoWit
//! activation) carries no work at all. The work gap is therefore built below
//! the activation (here 400): side B mines four blocks per DAG layer there
//! (each merging the other three), side A one. Both sides then mine witness
//! shares for the same two keys (as a common history longer than a partition
//! would give them), and only side A's witnesses vote.

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

const ACT: u64 = 400;
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

/// A genuine KES witness key (depth 3: PoWit epochs 0..=7, heights 400..=559).
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
        powit: PowitBody { shares, attestations: atts, evidence: Vec::new(), exits: Vec::new(), poci_evidence: Vec::new() },
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

/// The partition: a common chain C (9 blocks), then side A (390 blocks below
/// the activation, then 90 above it: two epochs with shares for keys K1 and
/// K2, then their votes: it finalizes) and side B (390 layers of four blocks
/// below the activation, then 80 blocks above it with shares for the same
/// keys in the same epochs, no vote: it finalizes nothing). B's tip carries
/// about 1,170 blocks of work more than A's, and the block 360 below it more
/// than all of A.
struct Heal {
    genesis: Block,
    common: Vec<Block>,
    a: Vec<Block>,
    b: Vec<Block>,
    a_fin: Checkpoint,
    /// An authentic vote of side A that claims its finality.
    claim: Attestation,
}

const K1: u8 = 61;
const K2: u8 = 62;

fn heal() -> Heal {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    let (k1, k2) = (Key::new(K1), Key::new(K2));
    let side_a = Producer::new(&genesis);
    let common = side_a.extend(9, "c", &[], &[]);
    let mut a = side_a.extend(390, "a", &[], &[]);
    a.extend(side_a.extend(20, "a0", &[], &[]));
    a.extend(side_a.extend(4, "s1", &[&k1, &k2], &[]));
    a.extend(side_a.extend(16, "a1", &[], &[]));
    a.extend(side_a.extend(4, "s2", &[&k1, &k2], &[]));
    a.extend(side_a.extend(16, "a2", &[], &[]));
    a.extend(side_a.extend(30, "v", &[], &[&k1, &k2]));
    let a_fin = side_a.tip_state().finalized;
    assert!(a.iter().any(|b| b.block_hash() == a_fin.hash), "side A finalized: {a_fin:?}");
    let claim = a.iter().flat_map(|b| b.powit.attestations.iter())
        .find(|x| x.source.height > ACT + P.checkpoint_interval).cloned().expect("a vote claiming A's finality");
    let side_b = Producer::new(&genesis);
    side_b.adopt(&common);
    let mut b = side_b.wide(390, "w");
    b.extend(side_b.extend(19, "b0", &[], &[]));
    b.extend(side_b.extend(4, "t1", &[&k1, &k2], &[]));
    b.extend(side_b.extend(16, "b1", &[], &[]));
    b.extend(side_b.extend(4, "t2", &[&k1, &k2], &[]));
    b.extend(side_b.extend(37, "b2", &[], &[]));
    assert_eq!(side_b.tip_state().finalized.height, ACT, "side B finalized nothing");
    Heal { genesis, common, a, b, a_fin, claim }
}

/// A fork from `from` (on C) to the activation, whose last block (above it)
/// carries `votes`: the chain an attacker pulls a node along.
fn fork_with(h: &Heal, from: usize, to_height: u64, tag: &str, votes: impl Fn(&Producer) -> Vec<Attestation>)
    -> Vec<Block>
{
    let f = Producer::new(&h.genesis);
    f.adopt(&h.common[..=from]);
    let n = to_height - 1 - (from as u64 + 1);
    let mut out = f.extend(n as usize, tag, &[], &[]);
    let top = build(&f.node, vec![f.tip()], &format!("{tag}top"), Vec::new(), votes(&f));
    out.push(top);
    out
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

/// The claim pre-filter: a block claims finality only with a vote that links
/// from a checkpoint more than one interval above the node's pin (with no
/// pin, above the activation).
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
    // With a pin, the floor is the pin's slot (here its DAG height + 1) plus
    // one interval (review round 2, L4).
    n.dag.write().set_finalized(genesis.block_hash(), 430);
    assert_eq!(ingress::finality_claim_floor(&n.dag.read()), 431 + P.checkpoint_interval);
    assert!(!ingress::claims_finality(&vote(431 + P.checkpoint_interval), 431 + P.checkpoint_interval));
}

// ── Review round 2, H1: claims are authenticated and bound to their chain ───

/// A claim backs nothing unless one of its votes is signed by a key with
/// weight in the witness set the node's own state derives (H1.1), and its
/// target lies in the chain the claim reaches the node along: a fake vote
/// (a key with no weight), a vote by a witness with a forged signature, and
/// an authentic vote copied from side A onto another chain all leave that
/// chain below the work threshold. Each used to mark the chain as backed.
#[test]
fn unauthenticated_or_copied_finality_claims_back_nothing() {
    let h = heal();
    let n = side_b_node(&h);
    let stranger = Key::new(99);
    let forged = {
        let mut v = h.claim.clone();
        for x in v.sig.sig.iter_mut().take(8) {
            *x ^= 0x5A;
        }
        v
    };
    let cases: Vec<(&str, Vec<Attestation>)> = vec![
        ("fake", vec![stranger.attest(h.claim.source, h.claim.target)]),
        ("forged", vec![forged]),
        ("copied", vec![h.claim.clone()]),
    ];
    for (tag, votes) in cases {
        let fork = fork_with(&h, 8, ACT + 1, tag, |_| votes.clone());
        let mut core = BlockIngress::new();
        let out = pull(&mut core, &n, &fork, PeerId::random(), None, Instant::now());
        assert!(matches!(out.last().unwrap(), BlockOutcome::Dropped(DropReason::LowWork)), "{tag}: {:?}",
            out.last().unwrap());
        assert_eq!(stored(&n, &fork), 0, "{tag}: nothing stored");
    }
    // Side A still heals the node.
    let mut core = BlockIngress::new();
    pull(&mut core, &n, &h.a, PeerId::random(), None, Instant::now());
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h.a_fin.hash), Some(h.a.last().unwrap().block_hash())));
}

/// A flood of orphans with claims (fake ones and authentic copies) and 256
/// random parents each, between the pulls of side A: the claims used to mark
/// all 257 hashes each in a global first-in-first-out set of 8,192, evicting
/// side A's marks, and the heal never completed. Backing now lives in the
/// orphan pool (the claim orphan and the chain under it), so nothing
/// evicts it but the pool's own bounds.
#[test]
fn a_flood_of_claims_does_not_stop_the_heal() {
    let h = heal();
    let n = side_b_node(&h);
    let mut core = BlockIngress::new();
    let now = Instant::now();
    let top = h.a.len() - 100;
    pull(&mut core, &n, &h.a[top..], PeerId::random(), None, now);
    let stranger = Key::new(98);
    let bits = h.a.last().unwrap().header.bits;
    for i in 0..40u32 {
        let vote = if i % 2 == 0 { stranger.attest(h.claim.source, h.claim.target) } else { h.claim.clone() };
        let b = stray_orphan(i, bits, core::MAX_PARENTS, Some(vote));
        let o = core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), Some(PeerId::random()), false,
            now, unix_now(), &ctx(&n));
        assert!(matches!(o, BlockOutcome::Buffered { .. }), "flood orphan {i}: {o:?}");
    }
    pull(&mut core, &n, &h.a[..top], PeerId::random(), None, now);
    assert_eq!(pin_of(&n), Some(h.a_fin.hash), "the heal completed despite the flood");
    assert_eq!(applied_tip(&n), Some(h.a.last().unwrap().block_hash()));
}

/// An orphan at height 470 on `parents` random parents, carrying `vote`.
fn stray_orphan(i: u32, bits: u32, parents: usize, vote: Option<Attestation>) -> Block {
    let parents: Vec<BlockHash> = (0..parents).map(|j| {
        let mut x = [0u8; 32];
        x[..4].copy_from_slice(&i.to_le_bytes());
        x[4..8].copy_from_slice(&(j as u32).to_le_bytes());
        x[31] = 0xF1;
        x
    }).collect();
    let height = 470;
    let mut b = Block {
        header: BlockHeader { version: 1, parents, merkle_root: MerkleRoot::ZERO, timestamp: unix_now(), bits,
                              nonce: u64::from(i) },
        transactions: vec![Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX,
                                   script_sig: format!("stray{i}").into_bytes(), sequence: u32::MAX }],
            outputs: Block::coinbase_outputs(height, vec![0xC0; 20], 0, &[]),
            locktime: 0,
        }],
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
        powit: PowitBody { shares: Vec::new(), attestations: vote.into_iter().collect(), evidence: Vec::new(), exits: Vec::new(), poci_evidence: Vec::new() },
    };
    commit_block(&mut b);
    b.test_only_assume_pow_valid();
    b
}

/// Review round 2, M2: a finality-backed block must itself carry at least
/// the orphan floor's work (1/16 of a block at the tip): a claim cannot carry
/// a cheap chain. Under a reference target that puts side A's blocks below
/// the floor, its first block is refused although a claim backs it; under
/// the real one it is admitted.
#[test]
fn a_finality_backed_block_must_meet_the_orphan_floor() {
    let h = heal();
    let n = side_b_node(&h);
    let mut core = BlockIngress::new();
    let now = Instant::now();
    pull(&mut core, &n, &h.a[1..], PeerId::random(), None, now);
    let bottom = &h.a[0];
    let mut hard = [0u8; 32];
    hard[31] = 1;
    core.set_reference_target(Some(hard));
    let o = core.handle_block(bottom.clone(), bottom.block_hash(), bottom.to_wire_bytes().len(),
        Some(PeerId::random()), true, now, unix_now(), &ctx(&n));
    assert!(matches!(o, BlockOutcome::Dropped(DropReason::LowWork)), "{o:?}");
    assert_eq!(stored(&n, &h.a), 0);
    core.set_reference_target(None);
    // (Any new orphan clears the cached LowWork verdict.)
    let stray = stray_orphan(1_000, bottom.header.bits, 1, None);
    core.handle_block(stray.clone(), stray.block_hash(), stray.to_wire_bytes().len(), Some(PeerId::random()), false,
        now, unix_now(), &ctx(&n));
    let o = core.handle_block(bottom.clone(), bottom.block_hash(), bottom.to_wire_bytes().len(),
        Some(PeerId::random()), true, now, unix_now(), &ctx(&n));
    assert!(matches!(o, BlockOutcome::Processed { admission: WorkAdmission::FinalityBacked, .. }), "{o:?}");
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h.a_fin.hash), Some(h.a.last().unwrap().block_hash())));
}

/// The node-wide budget belongs to the heal: chains a third party pulls the
/// node along with fake or copied claims spend none of it (they used to be
/// admitted and spend it, leaving too little for side A).
#[test]
fn a_third_party_cannot_spend_the_heals_budget() {
    let h = heal();
    let n = side_b_node(&h);
    let mut core = BlockIngress::new().with_finality_pull_budgets(10_000, h.a.len() as u32 + 10);
    let stranger = Key::new(97);
    for (tag, vote) in [("copied", h.claim.clone()), ("fake", stranger.attest(h.claim.source, h.claim.target))] {
        let fork = fork_with(&h, 8, ACT + 1, tag, |_| vec![vote.clone()]);
        pull(&mut core, &n, &fork, PeerId::random(), None, Instant::now());
        assert_eq!(stored(&n, &fork), 0, "{tag}");
    }
    pull(&mut core, &n, &h.a, PeerId::random(), None, Instant::now());
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h.a_fin.hash), Some(h.a.last().unwrap().block_hash())));
}

/// Review round 2, L4: with a pin (an operator checkpoint on C), a chain that
/// forks below it gains nothing from a claim, even an authentic one bound to
/// its own chain (a witness signing a link to it): it cannot move the pin
/// (`ingress::extends_pin`). Side A, which extends the pin, still heals.
#[test]
fn a_claim_on_a_chain_that_forks_below_the_pin_buys_nothing() {
    let h = heal();
    let n = side_b_node(&h);
    let anchor = h.common.last().unwrap().block_hash();
    gnb::accept::override_finality(gnb::powit::FinalityOp::SetAnchor(anchor), &n.dag, &n.store, &n.mempool,
        &n.node_state, Some(&n.tip_tx), &n.shielded).unwrap();
    assert_eq!(pin_of(&n), Some(anchor));
    let k1 = Key::new(K1);
    let fork = fork_with(&h, 5, 470, "below", |f| {
        let t = Checkpoint { height: 470, hash: f.tip() };
        vec![k1.attest(Checkpoint { height: 465, hash: [7; 32] }, t)]
    });
    let mut core = BlockIngress::new();
    let out = pull(&mut core, &n, &fork, PeerId::random(), None, Instant::now());
    assert!(matches!(out.last().unwrap(), BlockOutcome::Dropped(DropReason::LowWork)), "{:?}", out.last());
    assert_eq!(stored(&n, &fork), 0);
    pull(&mut core, &n, &h.a, PeerId::random(), None, Instant::now());
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h.a_fin.hash), Some(h.a.last().unwrap().block_hash())));
}

// ── Review round 3, M-A: the claim search cannot be crowded out ─────────────

/// An orphan on `parent` from a crowd. It claims a header height above the
/// activation, where (under `test-pow-limit`) it announces no work: as a
/// crowd at the floor's work, 1/16 of a block each, announces too little to
/// back its parent by work (POW-3's `ChainBacked`).
fn crowd_orphan(i: u32, parent: BlockHash, bits: u32) -> Block {
    let height = 470;
    let mut b = Block {
        header: BlockHeader { version: 1, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
                              timestamp: unix_now(), bits, nonce: u64::from(i) },
        transactions: vec![Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX,
                                   script_sig: format!("crowd{i}").into_bytes(), sequence: u32::MAX }],
            outputs: Block::coinbase_outputs(height, vec![0xC0; 20], 0, &[]),
            locktime: 0,
        }],
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
        powit: PowitBody::default(),
    };
    commit_block(&mut b);
    b.test_only_assume_pow_valid();
    b
}

/// Review round 3, M-A: the block hashes of the lighter side are public, so
/// anyone can buffer orphans that list the heal's next block as a parent.
/// 4,200 such orphans (two Sybil peers, at the floor's work) used to fill
/// the bounded upward search from that block before it reached side A's
/// orphan above it: the block was refused as low-work and the heal stalled.
/// Backing now follows the ancestry of the claimed targets downward, which
/// no other orphan can enter.
#[test]
fn a_crowd_of_orphans_on_the_heals_next_block_cannot_stop_it() {
    let h = heal();
    let n = side_b_node(&h);
    let mut core = BlockIngress::new();
    let now = Instant::now();
    pull(&mut core, &n, &h.a[1..], PeerId::random(), None, now);
    let x = &h.a[0];
    let sybils = [PeerId::random(), PeerId::random()];
    for i in 0..4_200u32 {
        let b = crowd_orphan(i, x.block_hash(), x.header.bits);
        let o = core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), Some(sybils[(i % 2) as usize]),
            false, now, unix_now(), &ctx(&n));
        assert!(matches!(o, BlockOutcome::Buffered { .. }), "crowd orphan {i}: {o:?}");
    }
    let o = core.handle_block(x.clone(), x.block_hash(), x.to_wire_bytes().len(), Some(PeerId::random()), true, now,
        unix_now(), &ctx(&n));
    assert!(matches!(o, BlockOutcome::Processed { admission: WorkAdmission::FinalityBacked, .. }), "{o:?}");
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h.a_fin.hash), Some(h.a.last().unwrap().block_hash())));
}

/// Review round 3, LOW 3: below the second hardening activation a claim is
/// authenticated against the first rule's witness set the node's own state
/// derives (built for at most two target epochs per orphan); the heal
/// converges the same way.
#[test]
fn a_healed_partition_converges_under_the_first_witness_set_rule() {
    let _g = gnb::core::activation::scoped_override_v2(gnb::core::activation::NEVER);
    let h = heal();
    let n = side_b_node(&h);
    let mut core = BlockIngress::new();
    let out = pull(&mut core, &n, &h.a, PeerId::random(), None, Instant::now());
    assert!(matches!(out.last().unwrap(), BlockOutcome::Processed { admission: WorkAdmission::FinalityBacked, .. }),
        "{:?}", out.last().unwrap());
    assert_eq!((pin_of(&n), applied_tip(&n)), (Some(h.a_fin.hash), Some(h.a.last().unwrap().block_hash())));
}
