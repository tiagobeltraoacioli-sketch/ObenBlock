//! PoCI under network partitions, node level (docs/DESIGN-obenblock-poci.md
//! §10; the scenarios of reference/sim/partition_sim.py on ObenBlock
//! regtest). Every block goes through the REAL acceptance pipeline
//! (`accept::accept_block`, so `powit::block_state` and `apply_poci`) of
//! real nodes, with real SHA-256d witness shares, real KES keys and v3
//! votes; nothing is synthetic.
//!
//! Two nodes share a chain until epoch 7 (PoW only for epochs 0..=3, `C_4`
//! from the first block at `launch_height`, the slot opening epoch 4 buried
//! by one epoch, then a handoff per finalized epoch).
//! Then each side builds its own branch with its own witnesses (honest
//! signers: a monotone record, §8), and finally every block is delivered to
//! both nodes (the heal) and all witnesses vote on the chain the nodes
//! select. Required, for 50/50, 60/40, 70/30 and exactly 2/3, over a few
//! epochs and over longer than the 112-epoch window:
//!
//! - never two conflicting finalized checkpoints, and no conflict alert;
//! - only a side with more than 2/3 of the configuration in force at the
//!   split advances; a side without it keeps that configuration, its total
//!   and its finalized checkpoint for every block (no leak, no local
//!   timeout);
//! - after the heal both nodes select the same chain (a side that finalized
//!   is followed even when the other carries more work: the finality pin)
//!   and finality resumes, the first new certificate naming the
//!   configuration in force at the split when nothing was finalized
//!   meanwhile; both nodes keep and serve the same certificate, which
//!   verifies against the trusted `config_id` with its registry proof.
//!
//! Plus a fork at the epoch-4 boundary (§9, buried launch): no finality on
//! either branch until `launch_height`, so the nodes converge on the branch
//! with the most work and launch on it together.
//!
//! Plus exits and bans during a stall (40 % offline): the same configuration
//! and denominators on every node through the stall, the exit and the
//! evidence take effect at the one handoff that ends it (stepped through
//! every epoch boundary: `ban_start` = the first step above the evidence,
//! 100 epochs), and the certificate kept before the stall still verifies.
//!
//! The chain id is process-wide: this binary runs ObenBlock regtest only.

mod fix_common;
use fix_common::*;

use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, OnceLock};

use gnb::consensus::BlockHash;
use gnb::core::kes::{KesPublic, KesSigner};
use gnb::core::pow_scheme::OBB_BLOCK_VERSION;
use gnb::core::powit::poci::{self, Configuration, Kes, PociEvidence, OBB_REGTEST_POCI as PP};
use gnb::core::powit::{Attestation, ChainView, Checkpoint, KeyId, PowitBody, PowitState, WitnessExit};
use gnb::core::{self, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput};
use gnb::pow;
use gnb::powit::{self, certificate, DagChainView};

const EL: u64 = PP.epoch_len;
const IV: u64 = PP.checkpoint_interval;
/// The epoch the sides split at.
const SPLIT_EPOCH: u64 = 7;
/// KES depths: 32 epochs (short scenarios), 256 (beyond the window).
const DEPTH_SHORT: u8 = 5;
const DEPTH_LONG: u8 = 8;
const MAX_KEYS: usize = 10;

fn setup() {
    let _ = core::set_node_chain_id(ChainId::ObenBlockRegtest);
    assert_eq!(core::node_chain_id(), ChainId::ObenBlockRegtest, "one chain id per test binary");
    assert_eq!(core::powit_height(), 0, "ObenBlock runs PoWit from genesis");
}

// ── Witnesses ────────────────────────────────────────────────────────────────

struct KeyMaterial {
    secret: Vec<u8>,
    leaves: Vec<[u8; 32]>,
    public: KesPublic,
}

/// The test keys of `depth`, generated once per process (in parallel).
fn material(depth: u8) -> &'static [KeyMaterial] {
    static SHORT: OnceLock<Vec<KeyMaterial>> = OnceLock::new();
    static LONG: OnceLock<Vec<KeyMaterial>> = OnceLock::new();
    let cell = if depth == DEPTH_SHORT { &SHORT } else { &LONG };
    cell.get_or_init(|| std::thread::scope(|s| {
        let hs: Vec<_> = (0..MAX_KEYS).map(|i| s.spawn(move || {
            let k = KesSigner::generate(depth, [0x40 + i as u8; 32], |_| {}).unwrap();
            KeyMaterial { secret: k.secret_bytes().to_vec(), leaves: k.leaves().to_vec(), public: k.public() }
        })).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    }))
}

/// A witness: its KES signer and its signer record (the highest target it
/// signed; an honest signer never signs at or below it again, §8).
struct Witness {
    signer: Mutex<KesSigner>,
    id: KeyId,
    last_target: Mutex<u64>,
}

fn witnesses(depth: u8, n: usize) -> Vec<Witness> {
    material(depth)[..n].iter().map(|m| {
        let s = KesSigner::from_parts(&m.secret, m.leaves.clone(), &m.public).unwrap();
        Witness { id: m.public.witness_id(), signer: Mutex::new(s), last_target: Mutex::new(0) }
    }).collect()
}

impl Witness {
    fn evolved(&self, epoch: u64) -> std::sync::MutexGuard<'_, KesSigner> {
        let mut s = self.signer.lock().unwrap();
        if epoch > s.epoch() {
            s.evolve_to(epoch).unwrap();
        }
        s
    }

    /// An honest v3 vote, if the record allows it.
    fn vote(&self, config_id: &[u8; 32], source: Checkpoint, target: Checkpoint) -> Option<Attestation> {
        let mut last = self.last_target.lock().unwrap();
        if target.height <= *last {
            return None;
        }
        let s = self.evolved(PP.epoch_of(target.height));
        if s.epoch() != PP.epoch_of(target.height) {
            return None;
        }
        let a = Attestation::sign_v3(PP.chain_id, config_id, source, target, &s).unwrap();
        *last = target.height;
        Some(a)
    }

    /// A vote outside the record (equivocation: the faulty key of §10).
    fn vote_unguarded(&self, config_id: &[u8; 32], source: Checkpoint, target: Checkpoint) -> Attestation {
        let s = self.evolved(PP.epoch_of(target.height));
        Attestation::sign_v3(PP.chain_id, config_id, source, target, &s).unwrap()
    }

    fn exit(&self, epoch: u64) -> WitnessExit {
        let s = self.evolved(epoch);
        assert_eq!(s.epoch(), epoch);
        WitnessExit::sign(PP.chain_id, &s).unwrap()
    }
}

// ── Blocks ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Votes {
    /// Every slot (the witness duty's cadence).
    EverySlot,
    /// The first two slots of each epoch only: enough to justify and
    /// finalize the epoch's opening checkpoint (each target needs its own
    /// quorum either way), at a fraction of the signatures, for the
    /// scenarios that run beyond the window.
    TwoPerEpoch,
}

#[derive(Default)]
struct Extra {
    exits: Vec<WitnessExit>,
    evidence: Vec<PociEvidence>,
}

fn state(n: &Node, h: &BlockHash) -> PowitState {
    powit::load_state(&n.store, h).expect("PoWit state")
}

fn height_of(n: &Node, h: &BlockHash) -> u64 {
    n.dag.read().get_block_data(h).expect("known block").height
}

/// One block on `parent` (known to `n`): a share by every miner whose turn
/// it is (key `i` at offset `2 + i` of each epoch: one share per key per
/// epoch, equal weights), the v3 vote of every voter of the configuration
/// in force for the open slot, and `extra`.
fn build(n: &Node, parent: BlockHash, ws: &[Witness], voters: &[usize], miners: &[usize], votes: Votes, tag: &str,
         extra: Extra) -> Block {
    let (height, pts) = {
        let d = n.dag.read();
        let pd = d.get_block_data(&parent).expect("parent known");
        (pd.height + 1, pd.timestamp)
    };
    let mut shares = Vec::new();
    if let Some(&i) = miners.iter().find(|&&i| height % EL == 2 + i as u64) {
        let pb = n.store.get_block(&parent).unwrap().expect("parent body");
        let stop = AtomicBool::new(false);
        shares.push(powit::mine_share(&pb, parent, ws[i].id, &[0x51; 20], height << 16, 1 << 20, &stop)
            .expect("a share at the regtest target"));
    }
    let mut atts = Vec::new();
    if height > 1 {
        let st = state(n, &parent);
        if let Some(cfg) = st.poci_config() {
            let slot = height / IV * IV;
            let wanted = votes == Votes::EverySlot || slot % EL < 2 * IV;
            if wanted && slot > st.justified.height {
                let hash = {
                    let d = n.dag.read();
                    DagChainView { dag: &d, start: Some(parent) }.selected_at(slot).expect("slot on chain")
                };
                let target = Checkpoint { height: slot, hash };
                let cid = cfg.id();
                let voted = |k: &KeyId| st.votes.get(&target).is_some_and(|v| v.contains_key(k));
                let todo: Vec<usize> = voters.iter().copied()
                    .filter(|&i| cfg.weight(&ws[i].id).is_some() && !voted(&ws[i].id)).collect();
                atts = std::thread::scope(|s| {
                    let hs: Vec<_> = todo.iter().map(|&i| {
                        let w = &ws[i];
                        let source = st.justified;
                        s.spawn(move || w.vote(&cid, source, target))
                    }).collect();
                    hs.into_iter().filter_map(|h| h.join().unwrap()).collect()
                });
            }
        }
    }
    let cb = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX,
                               script_sig: format!("{tag}{height}").into_bytes(), sequence: u32::MAX }],
        outputs: Block::coinbase_outputs(height, vec![0xC0; 20], 0, &shares),
        locktime: 0,
    };
    let bits = pow::expected_block_bits(pts, height, pts + 1).unwrap();
    let mut b = Block {
        header: BlockHeader { version: OBB_BLOCK_VERSION, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
                              timestamp: pts + 1, bits, nonce: 0 },
        transactions: vec![cb],
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
        powit: PowitBody { shares, attestations: atts, evidence: Vec::new(), exits: extra.exits,
                           poci_evidence: extra.evidence, rejoins: Vec::new() },
    };
    commit_block(&mut b);
    while !b.validate_pow() {
        b.header.nonce += 1;
    }
    b
}

fn deliver(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

/// Extend `n`'s chain from `tip` by `count` blocks (also accepted by
/// `mirror`), calling `check` with every new block's state.
#[allow(clippy::too_many_arguments)]
fn extend(n: &Node, mirror: Option<&Node>, mut tip: BlockHash, ws: &[Witness], voters: &[usize], miners: &[usize],
          votes: Votes, count: u64, tag: &str, mut check: impl FnMut(&Block, &PowitState)) -> Vec<Block> {
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let b = build(n, tip, ws, voters, miners, votes, tag, Extra::default());
        tip = accept(n, &b).unwrap_or_else(|e| panic!("{tag} h={}: {e}", b.height));
        if let Some(m) = mirror {
            deliver(m, std::slice::from_ref(&b));
        }
        check(&b, &state(n, &tip));
        out.push(b);
    }
    out
}

/// The shared history: epochs `0..SPLIT_EPOCH` with every witness, on both
/// nodes. Returns the tip.
fn common_history(a: &Node, b: &Node, genesis: &Block, ws: &[Witness]) -> BlockHash {
    let all: Vec<usize> = (0..ws.len()).collect();
    let blocks = extend(a, Some(b), genesis.block_hash(), ws, &all, &all, Votes::EverySlot, SPLIT_EPOCH * EL - 1, "c",
                        |_, _| {});
    let tip = blocks.last().unwrap().block_hash();
    let st = state(a, &tip);
    let launch = PP.opening(PP.bootstrap_epochs);
    assert!(st.finalized.height > launch + EL, "finality runs before the split: {:?}", st.finalized);
    assert!(st.poci_config().unwrap().epoch() > PP.bootstrap_epochs, "handoffs before the split");
    tip
}

/// The kept certificate of `f` on `n` (by RPC: `getfinalitycertificate`),
/// verified against the trusted `config_id` with its registry proof and
/// against the configuration's entries.
fn served_certificate(n: &Node, slot: Option<u64>) -> (Vec<u8>, [u8; 32]) {
    let arg = slot.map(serde_json::Value::from);
    let j = certificate::rpc_json(&n.dag.read(), &n.store, arg.as_ref());
    assert!(j.get("error").is_none(), "getfinalitycertificate: {j}");
    let cert = hex::decode(j["certificate"].as_str().unwrap()).unwrap();
    let proof = hex::decode(j["registry_proof"].as_str().unwrap()).unwrap();
    let cid: [u8; 32] = hex::decode(j["config_id"].as_str().unwrap()).unwrap().try_into().unwrap();
    poci::verify_certificate_with_proof::<Kes>(&cert, &proof, &PP, &cid).expect("verifies with its registry proof");
    let cfg = certificate::load_config(&n.store, &cid).expect("configuration row");
    poci::verify_certificate::<Kes>(&cert, &PP, &cfg).expect("verifies against the entries");
    // A forged weight, another configuration: refused.
    let mut other = (*cfg).entries().to_vec();
    other[0].1 += 1;
    let forged = Configuration::new(&PP, cfg.epoch(), other).unwrap();
    assert_eq!(poci::verify_certificate::<Kes>(&cert, &PP, &forged).unwrap_err(), poci::CertReject::ConfigId);
    (cert, cid)
}

/// `a` and `b` are not conflicting: one is on the other's chain.
fn compatible(n: &Node, tip_a: &BlockHash, fa: &Checkpoint, tip_b: &BlockHash, fb: &Checkpoint) -> bool {
    let d = n.dag.read();
    let on = |tip: &BlockHash, c: &Checkpoint| DagChainView { dag: &d, start: Some(*tip) }.selected_at(c.height) == Some(c.hash);
    on(tip_a, fb) || on(tip_b, fa)
}

// ── Partitions ───────────────────────────────────────────────────────────────

struct Split {
    n: usize,
    a: usize,
    epochs: u64,
    votes: Votes,
    depth: u8,
}

fn partition(sc: Split) {
    setup();
    let ws = witnesses(sc.depth, sc.n);
    let genesis = mk_genesis(unix_now() - 40_000);
    let (na, nb) = (node_with(&genesis, &[]), node_with(&genesis, &[]));
    let split = common_history(&na, &nb, &genesis, &ws);
    let st0 = state(&na, &split);
    let c0 = st0.poci_config().unwrap().clone();
    let f0 = st0.finalized;
    let (side_a, side_b): (Vec<usize>, Vec<usize>) = ((0..sc.a).collect(), (sc.a..sc.n).collect());
    let weight = |keys: &[usize]| keys.iter().map(|&i| c0.weight(&ws[i].id).expect("a member")).sum::<u128>();
    assert!(c0.entries().iter().all(|(_, w)| *w == c0.entries()[0].1), "equal weights");
    assert_eq!(c0.len(), sc.n);
    let (qa, qb) = (poci::quorum(weight(&side_a), c0.total()), poci::quorum(weight(&side_b), c0.total()));
    assert!(!(qa && qb), "two quorums of one configuration intersect");

    // The split: each side on its own node and branch. A side with a quorum
    // is given LESS work than the other, so only the finality pin can make
    // the heavier side follow it after the heal; otherwise A is one block
    // longer (the heal is decided by work).
    let len = sc.epochs * EL;
    let (len_a, len_b) = if qa { (len, len + 3) } else { (len + 1, len) };
    let watch = |quorum: bool| {
        let c0 = c0.clone();
        move |b: &Block, st: &PowitState| {
            if !quorum {
                // No quorum: nothing about finality changes, block after block.
                assert_eq!(st.finalized, f0, "h={}: a side without 2/3 finalized", b.height);
                let c = st.poci_config().unwrap();
                assert_eq!((c.id(), c.total()), (c0.id(), c0.total()), "h={}: configuration changed", b.height);
                assert!(st.decay.is_empty() && st.banned.is_empty(), "no inactivity leak on ObenBlock");
            }
        }
    };
    let (blocks_a, blocks_b) = std::thread::scope(|s| {
        let ha = s.spawn(|| extend(&na, None, split, &ws, &side_a, &side_a, sc.votes, len_a, "a", watch(qa)));
        let hb = s.spawn(|| extend(&nb, None, split, &ws, &side_b, &side_b, sc.votes, len_b, "b", watch(qb)));
        (ha.join().unwrap(), hb.join().unwrap())
    });
    let (tip_a, tip_b) = (blocks_a.last().unwrap().block_hash(), blocks_b.last().unwrap().block_hash());
    let (fa, fb) = (state(&na, &tip_a).finalized, state(&nb, &tip_b).finalized);
    assert_eq!(fa != f0, qa, "side A advances iff it holds more than 2/3 of the configuration at the split");
    assert_eq!(fb != f0, qb, "side B advances iff it holds more than 2/3 of the configuration at the split");
    if qa {
        assert!(fa.height + 2 * EL >= height_of(&na, &tip_a), "the quorum side keeps finalizing: {fa:?}");
        let (_, cid) = served_certificate(&na, None);
        assert_ne!(cid, c0.id(), "the quorum side handed off");
    }

    // The heal: every block reaches both nodes.
    deliver(&na, &blocks_b);
    deliver(&nb, &blocks_a);
    for n in [&na, &nb] {
        assert_eq!(sel_tip(n), Some(tip_a), "both nodes follow side A");
        assert_eq!(applied_tip(n), Some(tip_a));
        assert!(n.dag.read().finality_outcome().conflict.is_none(), "no conflicting finality");
        assert!(compatible(n, &tip_a, &fa, &tip_b, &fb), "never two conflicting finalized checkpoints");
    }

    // After the heal every witness votes on the selected chain: finality
    // resumes on both nodes, with the same certificates.
    let all: Vec<usize> = (0..sc.n).collect();
    let resumed: std::cell::RefCell<Option<Checkpoint>> = Default::default();
    let healed = extend(&na, Some(&nb), tip_a, &ws, &all, &all, Votes::EverySlot, 3 * EL, "h", |_, st| {
        if st.finalized != fa && resumed.borrow().is_none() {
            *resumed.borrow_mut() = Some(st.finalized);
        }
    });
    let first = resumed.into_inner().expect("finality resumes after the heal");
    let end = healed.last().unwrap().block_hash();
    let st_end = state(&na, &end);
    assert_eq!(st_end.finalized, state(&nb, &end).finalized, "both nodes finalize the same checkpoint");
    assert!(st_end.finalized.height > fa.height.max(fb.height));
    let (cert_first_a, cid_first) = served_certificate(&na, Some(first.height));
    let (cert_first_b, _) = served_certificate(&nb, Some(first.height));
    assert_eq!(cert_first_a, cert_first_b, "both nodes keep the same certificate");
    if !qa {
        assert_eq!(cid_first, c0.id(), "finality resumes under the configuration in force at the split");
    }
    let (latest_a, _) = served_certificate(&na, None);
    let (latest_b, _) = served_certificate(&nb, None);
    assert_eq!(latest_a, latest_b);
    for n in [&na, &nb] {
        assert!(n.dag.read().finality_outcome().conflict.is_none());
    }
}

#[test]
fn split_50_50_short() {
    partition(Split { n: 10, a: 5, epochs: 2, votes: Votes::EverySlot, depth: DEPTH_SHORT });
}

#[test]
fn split_60_40() {
    partition(Split { n: 10, a: 6, epochs: 6, votes: Votes::EverySlot, depth: DEPTH_SHORT });
}

#[test]
fn split_70_30() {
    partition(Split { n: 10, a: 7, epochs: 6, votes: Votes::EverySlot, depth: DEPTH_SHORT });
}

#[test]
fn split_exactly_two_thirds() {
    partition(Split { n: 9, a: 6, epochs: 4, votes: Votes::EverySlot, depth: DEPTH_SHORT });
}

/// Longer than the 112-epoch window: the configuration in force does not
/// age on either side (it changes only at a handoff).
#[test]
fn split_50_50_beyond_the_window() {
    partition(Split { n: 10, a: 5, epochs: PP.window_epochs + 8, votes: Votes::TwoPerEpoch, depth: DEPTH_LONG });
}

#[test]
fn split_60_40_beyond_the_window() {
    partition(Split { n: 10, a: 6, epochs: PP.window_epochs + 8, votes: Votes::TwoPerEpoch, depth: DEPTH_LONG });
}

#[test]
fn split_70_30_beyond_the_window() {
    partition(Split { n: 10, a: 7, epochs: PP.window_epochs + 8, votes: Votes::TwoPerEpoch, depth: DEPTH_LONG });
}

// ── Exit and ban during a stall ──────────────────────────────────────────────

/// §10 "exit, ban and expiry during a stall": 40 % of the weight goes
/// offline for 6 epochs. During the stall key 0 exits and key 1's
/// equivocation is included; nothing in force changes on either node. When
/// the weight returns, one handoff ends the stall, stepping through every
/// epoch boundary (§4): key 0 is out, key 1 is banned for 100 epochs from
/// the first step whose opening lies above its evidence, and the
/// certificate kept before the stall still verifies. (Expiry of weight cannot be shown here: the
/// window is 112 epochs on regtest too, part of `params_digest`.)
#[test]
fn exit_and_ban_during_a_stall() {
    setup();
    let ws = witnesses(DEPTH_SHORT, 10);
    let genesis = mk_genesis(unix_now() - 40_000);
    let (na, nb) = (node_with(&genesis, &[]), node_with(&genesis, &[]));
    let mut tip = common_history(&na, &nb, &genesis, &ws);
    let st0 = state(&na, &tip);
    let c0 = st0.poci_config().unwrap().clone();
    let f0 = st0.finalized;
    let (cert_before, cid_before) = served_certificate(&na, None);
    assert_eq!(cid_before, c0.id());
    let configs_before = st0.poci.as_ref().unwrap().history().count();
    forged_poci_evidence_is_a_peer_fault(&na, &tip, &ws[3], &c0);

    let online: Vec<usize> = (0..6).collect();
    let mut miners: Vec<usize> = online.clone();
    let stall_end = (SPLIT_EPOCH + 6) * EL;
    let mut exited_at = None;
    let mut evidence_at = None;
    while height_of(&na, &tip) + 1 < stall_end {
        let h = height_of(&na, &tip) + 1;
        let mut extra = Extra::default();
        if h == (SPLIT_EPOCH + 1) * EL + 1 {
            extra.exits.push(ws[0].exit(PP.epoch_of(h)));
            miners.retain(|&i| i != 0); // an exited key earns no share work
            exited_at = Some(h);
        }
        if h == (SPLIT_EPOCH + 2) * EL + 1 {
            let st = state(&na, &tip);
            let slot = h / IV * IV;
            let va = ws[1].vote_unguarded(&c0.id(), st.justified, Checkpoint { height: slot, hash: [0xE1; 32] });
            let vb = ws[1].vote_unguarded(&c0.id(), st.justified, Checkpoint { height: slot, hash: [0xE2; 32] });
            extra.evidence.push(PociEvidence { config_id: c0.id(), a: va, b: vb });
            miners.retain(|&i| i != 1);
            evidence_at = Some(h);
        }
        let b = build(&na, tip, &ws, &online, &miners, Votes::EverySlot, "s", extra);
        if evidence_at == Some(h) {
            stripped_poci_items_fail_the_body_commitment(&na, &b, &ws[2]);
        }
        tip = accept(&na, &b).unwrap_or_else(|e| panic!("stall h={h}: {e}"));
        deliver(&nb, std::slice::from_ref(&b));
        for n in [&na, &nb] {
            let st = state(n, &tip);
            let c = st.poci_config().unwrap();
            assert_eq!((c.id(), c.total()), (c0.id(), c0.total()), "h={h}: the same configuration on every node");
            assert_eq!(st.finalized, f0, "h={h}: 60 % does not finalize");
            assert!(st.decay.is_empty(), "no inactivity leak");
            if exited_at.is_some() {
                assert!(st.exited.contains_key(&ws[0].id));
            }
            if evidence_at.is_some() {
                let bans = &st.poci.as_ref().unwrap().bans[&ws[1].id];
                assert_eq!(bans.len(), 1);
                assert_eq!(bans[0].start, None, "pending until a handoff");
            }
        }
    }
    // Operators see the absent weight (getpowitinfo: poci.absent_weight).
    let info = powit::info_json(&na.dag.read(), &na.store);
    let absent = info["poci"]["absent_weight"].as_array().expect("absent weight per epoch").last().unwrap().clone();
    let offline_w: u128 = (6..10).map(|i| c0.weight(&ws[i].id).unwrap()).sum();
    assert_eq!(absent["weight"].as_str().unwrap().parse::<u128>().unwrap(), offline_w, "{absent}");
    assert_eq!(absent["keys"], 4);
    assert_eq!(absent["over_a_third"], true);
    let fin_info = powit::poci_finality_json(&na.dag.read(), &na.store);
    assert_eq!(fin_info["config_id"].as_str().unwrap(), hex::encode(c0.id()));

    // The weight returns: one handoff ends the stall.
    let all: Vec<usize> = (0..10).collect();
    let back: Vec<usize> = (2..10).collect();
    let mut handoff: Option<(u64, PowitState)> = None;
    let blocks = extend(&na, Some(&nb), tip, &ws, &all, &back, Votes::EverySlot, 2 * EL, "r", |b, st| {
        if handoff.is_none() && st.poci_config().unwrap().id() != c0.id() {
            handoff = Some((b.height, st.clone()));
        }
    });
    let (hh, st) = handoff.expect("finality resumes and hands off");
    let ps = st.poci.as_ref().unwrap();
    let e = ps.config().epoch();
    assert_eq!(e, PP.epoch_of(st.finalized.height));
    // §4: one handoff, one step per epoch boundary (C_{e0+1} ..= C_e).
    let steps = (e - c0.epoch()) as usize;
    assert!(steps > 1, "the stall spans several epochs");
    assert_eq!(ps.history().count(), configs_before + steps, "one configuration per epoch");
    assert_eq!(ps.history().nth(steps).unwrap().id(), c0.id());
    assert!(ps.history().take(steps).map(|c| c.epoch()).eq((c0.epoch() + 1..=e).rev()));
    assert!(ps.config().weight(&ws[0].id).is_none(), "the exited key left at the handoff");
    assert!(ps.config().weight(&ws[1].id).is_none(), "the banned key left at the handoff");
    // The ban starts at the first step whose opening is at or above the
    // evidence (included at its block's height + 1), inside the stall.
    let ban = &ps.bans[&ws[1].id][0];
    let start = (c0.epoch() + 1..=e).find(|y| PP.opening(*y) > evidence_at.unwrap()).unwrap();
    assert!(start < e);
    assert_eq!((ban.config_id, ban.start, ban.end(PP.ban_epochs)), (c0.id(), Some(start), Some(start + 100)));
    assert!(ps.banned_at(&PP, &ws[1].id, start) && ps.banned_at(&PP, &ws[1].id, start + 99)
            && !ps.banned_at(&PP, &ws[1].id, start + 100));
    assert!(ps.history().take_while(|c| c.epoch() >= start).all(|c| c.weight(&ws[1].id).is_none()));
    // The finalization that ended the stall is certified by C0 (exited and
    // banned keys still count in it: nothing is retroactive).
    let resume = state(&na, &blocks.iter().find(|b| b.height == hh).unwrap().block_hash()).finalized;
    let (_, cid) = served_certificate(&na, Some(resume.height));
    assert_eq!(cid, c0.id());
    assert_eq!(state(&nb, &blocks.last().unwrap().block_hash()).poci, state(&na, &blocks.last().unwrap().block_hash()).poci);
    // The certificate kept before the stall still verifies.
    let (cert_again, _) = served_certificate(&na, Some(f0.height));
    assert_eq!(cert_again, cert_before);
    // Evidence against the banned key again is refused while the ban runs.
    let end = blocks.last().unwrap().block_hash();
    assert!(state(&na, &end).poci.as_ref().unwrap().may_ban(&PP, &ws[1].id, &c0.id()).is_err());
}

/// Review finding (MEDIUM): PoCI evidence against a real member whose
/// signature is forged passes every cheap check and costs the node KES
/// verifications; its refusal is a context-free fault (charge kept, the
/// peer penalised: `ingress::powit_admit_error_fault`), while evidence
/// against a key outside every configuration is refused before any
/// signature and keeps its charge without a penalty.
fn forged_poci_evidence_is_a_peer_fault(n: &Node, tip: &BlockHash, w: &Witness, c0: &Configuration) {
    use gnb::ingress::{powit_admit_error_fault, powit_admit_error_keeps_charge, BlockFault};
    let st = state(n, tip);
    let slot = (height_of(n, tip) + 1) / IV * IV;
    let va = w.vote_unguarded(&c0.id(), st.justified, Checkpoint { height: slot, hash: [0xF1; 32] });
    let mut vb = w.vote_unguarded(&c0.id(), st.justified, Checkpoint { height: slot, hash: [0xF2; 32] });
    vb.sig.sig[0] ^= 1;
    let (_, kind, data) = powit::poci_evidence_item(&PociEvidence { config_id: c0.id(), a: va.clone(), b: vb });
    let err = powit::admit_item(kind, &data, &n.dag.read(), &n.store).expect_err("a forged signature");
    assert_eq!(err, poci::EvidenceReject::Signature.to_string());
    assert_eq!(powit_admit_error_fault(kind, &err), Some(BlockFault::ContextFree), "{err}");
    // Not a member of any configuration: refused before the signatures.
    let mut stranger = va.clone();
    stranger.witness.root = [0xEE; 32];
    let mut stranger_b = stranger.clone();
    stranger_b.target.hash = [0xF3; 32];
    let (_, kind, data) = powit::poci_evidence_item(&PociEvidence { config_id: c0.id(), a: stranger, b: stranger_b });
    let err = powit::admit_item(kind, &data, &n.dag.read(), &n.store).expect_err("not a member");
    assert_eq!(err, powit::EVIDENCE_NOT_A_WITNESS);
    assert_eq!(powit_admit_error_fault(kind, &err), None);
    assert!(powit_admit_error_keeps_charge(kind, &err));
}

/// Decision D1 (review CRITICAL): the body commitment covers the whole PoWit
/// section in the PoCI wire format. Copies of the evidence block `b` (same
/// block id) whose PoCI evidence was deleted or swapped, or that carry a
/// rejoin the miner did not include, are refused for the commitment before
/// they are stored, and do not disqualify the id: the honest body is
/// accepted afterwards (the caller does).
fn stripped_poci_items_fail_the_body_commitment(n: &Node, b: &Block, other: &Witness) {
    assert!(!b.powit.poci_evidence.is_empty());
    let rejoin = {
        let s = other.evolved(PP.epoch_of(b.height));
        gnb::core::powit::WitnessRejoin::sign(PP.chain_id, &s).unwrap()
    };
    let mut copies: Vec<(&str, Block)> = Vec::new();
    let mut c = b.clone();
    c.powit.poci_evidence.clear();
    copies.push(("evidence deleted", c));
    let mut c = b.clone();
    let e = &mut c.powit.poci_evidence[0];
    std::mem::swap(&mut e.a, &mut e.b);
    copies.push(("evidence votes swapped", c));
    let mut c = b.clone();
    c.powit.rejoins.push(rejoin.clone());
    copies.push(("rejoin added", c));
    let mut c = b.clone();
    c.powit.poci_evidence.clear();
    c.powit.rejoins.push(rejoin);
    copies.push(("evidence swapped for a rejoin", c));
    for (what, c) in copies {
        assert_eq!(c.block_hash(), b.block_hash(), "{what}: same block id");
        // The altered copy survives the wire (it is what a relay would send).
        let c = Block::from_wire_bytes(&c.to_wire_bytes()).unwrap();
        assert_ne!(core::block_rules::body_commitment_root(&c), core::block_rules::body_commitment_root(b), "{what}");
        let err = accept(n, &c).expect_err(what);
        assert!(err.contains("bad witness commitment"), "{what}: {err}");
        assert!(n.dag.read().get_block_data(&b.block_hash()).is_none(), "{what}: not stored");
    }
}

/// The certificate RPC refuses what is not a finalized checkpoint.
#[test]
fn certificate_rpc_refuses_what_is_not_finalized() {
    setup();
    let ws = witnesses(DEPTH_SHORT, 4);
    let genesis = mk_genesis(unix_now() - 40_000);
    let (na, nb) = (node_with(&genesis, &[]), node_with(&genesis, &[]));
    let tip = common_history(&na, &nb, &genesis, &ws);
    let st = state(&na, &tip);
    let d = na.dag.read();
    let err = |v: serde_json::Value| certificate::rpc_json(&d, &na.store, Some(&v))["error"].as_str().map(str::to_owned);
    assert!(err(serde_json::json!(st.justified.height + IV)).is_some(), "above the finalized checkpoint");
    assert!(err(serde_json::json!(st.finalized.height + 1)).unwrap().contains("not a checkpoint slot"));
    assert!(err(serde_json::json!(PP.opening(PP.bootstrap_epochs))).unwrap().contains("final by definition"));
    assert!(err(serde_json::json!(0)).unwrap().contains("final by definition"));
    // By hash: the finalized checkpoint's block.
    let by_hash = certificate::rpc_json(&d, &na.store, Some(&serde_json::json!(hex::encode(st.finalized.hash))));
    assert_eq!(by_hash["checkpoint"]["slot"], st.finalized.height, "{by_hash}");
    // Every finalized checkpoint since the launch has a kept certificate.
    let mut f = st.finalized.height;
    let mut kept = 0;
    while f > PP.opening(PP.bootstrap_epochs) {
        let hash = DagChainView { dag: &d, start: Some(tip) }.selected_at(f).unwrap();
        if let Some(k) = certificate::load(&na.store, &hash) {
            k.certificate.verify(&PP, &k.config).unwrap();
            assert_eq!(k.certificate.target.height, f + IV);
            kept += 1;
        }
        f -= IV;
    }
    // Every slot from the first one the launch block can vote for
    // (`launch_height`) on finalizes (all witnesses vote at once).
    assert_eq!(kept, (st.finalized.height - PP.launch_height()) / IV + 1, "a certificate per finalization");
}

// ── Launch (§9) ──────────────────────────────────────────────────────────────

/// Review HIGH (§9, decision D2): a fork at the epoch-4 boundary used to be
/// a permanent split, because each branch made its own slot `opening(4)`
/// final one block deep and the sticky pin never gives a finalized
/// checkpoint up. Now `C_4` enters into force only at `launch_height`
/// (`opening(4)` buried by one epoch): below it neither branch carries a
/// finalized checkpoint, so nothing is pinned, the node on the lighter
/// branch follows the heavier one, and both launch on it together.
#[test]
fn a_fork_at_the_epoch_4_boundary_is_settled_by_work() {
    setup();
    let ws = witnesses(DEPTH_SHORT, 4);
    let all: Vec<usize> = (0..ws.len()).collect();
    let genesis = mk_genesis(unix_now() - 40_000);
    let (na, nb) = (node_with(&genesis, &[]), node_with(&genesis, &[]));
    let boundary = PP.opening(PP.bootstrap_epochs);
    assert_eq!(PP.launch_height(), boundary + EL);
    let common = extend(&na, Some(&nb), genesis.block_hash(), &ws, &all, &all, Votes::EverySlot, boundary - 3, "c",
                        |_, _| {});
    let fork = common.last().unwrap().block_hash();
    let pre_launch = |b: &Block, st: &PowitState| {
        assert!(b.height < PP.launch_height());
        assert!(st.poci.is_none(), "h={}: no configuration before the launch", b.height);
        assert_eq!(st.finalized.height, 0, "h={}: no finalized checkpoint to pin", b.height);
    };
    // A is past the boundary on node a; B, longer, on node b. Both below
    // launch_height.
    let (blocks_a, blocks_b) = std::thread::scope(|s| {
        let ha = s.spawn(|| extend(&na, None, fork, &ws, &all, &all, Votes::EverySlot, 18, "fa", pre_launch));
        let hb = s.spawn(|| extend(&nb, None, fork, &ws, &all, &all, Votes::EverySlot, 21, "fb", pre_launch));
        (ha.join().unwrap(), hb.join().unwrap())
    });
    let (tip_a, tip_b) = (blocks_a.last().unwrap().block_hash(), blocks_b.last().unwrap().block_hash());
    assert!(height_of(&na, &tip_a) > boundary && height_of(&nb, &tip_b) > boundary, "both cross the boundary");
    for n in [&na, &nb] {
        assert!(n.dag.read().finality_outcome().pin.is_none_or(|(_, h)| h == 0), "nothing pinned");
    }
    deliver(&na, &blocks_b);
    deliver(&nb, &blocks_a);
    for n in [&na, &nb] {
        assert_eq!(sel_tip(n), Some(tip_b), "both nodes follow the branch with the most work");
        assert_eq!(applied_tip(n), Some(tip_b));
        assert!(n.dag.read().finality_outcome().conflict.is_none());
    }
    // Both launch on B: the same launch checkpoint, then finality runs.
    let launched: std::cell::RefCell<Option<Checkpoint>> = Default::default();
    let blocks = extend(&nb, Some(&na), tip_b, &ws, &all, &all, Votes::EverySlot, 2 * EL, "l", |b, st| {
        if b.height >= PP.launch_height() && launched.borrow().is_none() {
            *launched.borrow_mut() = Some(st.finalized);
        }
    });
    let lc = launched.into_inner().expect("launched");
    let b_slot = DagChainView { dag: &nb.dag.read(), start: Some(tip_b) }.selected_at(boundary).unwrap();
    assert_eq!(lc, Checkpoint { height: boundary, hash: b_slot }, "the launch checkpoint is B's");
    let end = blocks.last().unwrap().block_hash();
    let (sa, sb) = (state(&na, &end), state(&nb, &end));
    assert_eq!(sa.finalized, sb.finalized);
    assert!(sa.finalized.height > PP.launch_height(), "PoCI finality after the launch: {:?}", sa.finalized);
    assert_eq!(sa.poci_config().unwrap().id(), sb.poci_config().unwrap().id());
    for n in [&na, &nb] {
        assert_eq!(sel_tip(n), Some(end));
        assert!(n.dag.read().finality_outcome().conflict.is_none(), "no conflicting finality");
    }
}
