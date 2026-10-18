//! PoWit audit (PR head 4293747), findings 3 and 2, end to end through the
//! REAL acceptance pipeline with real witness shares (GnB-SMH v3 proofs),
//! real KES keys and hybrid-signed attestations: every PoWit state here is
//! computed by `accept_block` (`powit::block_state`), none is synthetic.
//!
//! - Finding 3, consensus (second hardening upgrade): a private fork that
//!   branches after the honest chain's last finalized checkpoint mines its
//!   own shares; under the first rule its own key ends up holding 2/3 of its
//!   witness set and finalizes it; from hardening 2 the fork's witness set
//!   is the honest one of the finalized window and the fork never finalizes
//!   (an attestation by its key is refused by acceptance).
//! - Finding 3, node side (weak subjectivity): a fork from the PoWit
//!   activation (where no shares exist yet, so its own witness set is
//!   entirely the attacker's: the finding's "fork from 10,000") finalizes
//!   its own checkpoints; an eclipsed syncing node never pins them below the
//!   release finality checkpoint, and follows the honest chain once it sees
//!   it, even when the fork carries more work. Without an anchor (operator
//!   `setfinalitycheckpoint none`) the node keeps the fork's finality it
//!   reached, raises the conflict, and only an operator checkpoint moves it
//!   (why the release checkpoint matters).
//! - Review HIGH 1: a synced node keeps its finality when a heavier fork
//!   that finalized its own (a majority of the hashrate, first rule) is
//!   published, and raises the conflict.
//! - Producers at the activation boundary: the pool and the witness duty
//!   judge membership by the rule of the next block's height (H-1 / H).
//!
//! Testnet clock (`TESTNET_PARAMS`: 20-block epochs, checkpoints every 5),
//! PoWit from height 3, both process-wide for this binary; the second
//! hardening height is set per test thread (`scoped_override_v2`).

mod fix_common;
use fix_common::*;

use std::sync::atomic::AtomicBool;

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::activation;
use gnb::core::kes::{KesKeyFile, KesSigner};
use gnb::core::powit::{Attestation, ChainView, Checkpoint, KeyId, PowitBody, PowitState, TESTNET_PARAMS};
use gnb::core::witness_share::WitnessShare;
use gnb::core::{self, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput};
use gnb::pow;
use gnb::powit::{self, DagChainView, FinalityOp, PowitPool};
use gnb::storage::Storage;
use tempfile::TempDir;

const ACT: u64 = 3;
const P: core::powit::PowitParams = TESTNET_PARAMS;

fn setup() {
    let _ = core::set_node_chain_id(ChainId::Testnet);
    let _ = core::set_powit_height_override(ACT);
    assert_eq!(core::node_chain_id(), ChainId::Testnet, "one chain id per test binary");
    assert_eq!(core::powit_height(), ACT, "one PoWit activation per test binary");
    assert_eq!(gnb::ingress::minimum_chain_work(), 0, "testnet: no minimum chain work");
}

/// A genuine KES witness key (depth 3: epochs 0..=7, heights 3..=162).
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

/// A block on `parent` (known to `n`) with this PoWit section; the coinbase
/// pays the shares as consensus requires (`Block::coinbase_outputs`).
fn build(n: &Node, parent: BlockHash, tag: &str, shares: Vec<WitnessShare>, atts: Vec<Attestation>) -> Block {
    let (height, pts) = {
        let d = n.dag.read();
        let pd = d.get_block_data(&parent).expect("parent known");
        (pd.height + 1, pd.timestamp)
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
        header: BlockHeader { version: 1, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
                              timestamp: pts + 1, bits, nonce: 0 },
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

/// A miner and its witnesses building one chain through a real node.
struct Producer {
    node: Node,
    /// Every block it holds, in delivery order (genesis excluded).
    blocks: Vec<Block>,
}

impl Producer {
    fn new(genesis: &Block) -> Self {
        Producer { node: node_with(genesis, &[]), blocks: Vec::new() }
    }

    fn tip(&self) -> BlockHash {
        applied_tip(&self.node).unwrap()
    }

    fn adopt(&mut self, blocks: &[Block]) {
        for b in blocks {
            accept(&self.node, b).unwrap_or_else(|e| panic!("adopt h={}: {e}", b.height));
            self.blocks.push(b.clone());
        }
    }

    /// The open checkpoint slot of a block at `height` on `parent` and its
    /// target, if the parent's state has one above its justified checkpoint.
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

    /// Extend the tip by `n` blocks: every block carries `count` shares for
    /// each `(key, count)` of `share_keys` (attesting the parent), and the
    /// attestation of each signer that the next block's witness set holds
    /// for the open slot (as the witness duty decides).
    fn extend(&mut self, n: usize, tag: &str, share_keys: &[(&Key, usize)], signers: &[&Key]) -> Vec<Block> {
        let stop = AtomicBool::new(false);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let parent = self.tip();
            let height = self.node.dag.read().get_block_data(&parent).unwrap().height + 1;
            let mut shares = Vec::new();
            if core::powit_active(height) {
                let pb = self.node.store.get_block(&parent).unwrap().unwrap();
                for (k, count) in share_keys {
                    for j in 0..*count {
                        let start = (height << 16) + j as u64 * 1_000;
                        shares.push(powit::mine_share(&pb, parent, k.id(), &[0x51; 20], start, 100_000, &stop)
                            .expect("a share"));
                    }
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
            let b = build(&self.node, parent, &format!("{tag}{i}"), shares, atts);
            accept(&self.node, &b).unwrap_or_else(|e| panic!("{tag} h={height}: {e}"));
            self.blocks.push(b.clone());
            out.push(b);
        }
        out
    }

    fn tip_state(&self) -> PowitState {
        powit::load_state(&self.node.store, &self.tip()).expect("PoWit state")
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

/// Finding 3, consensus side, through acceptance. The honest chain (two
/// equal witnesses, both signing) finalizes continuously; at height 60 an
/// attacker forks it privately with four shares per block for its own key
/// Z (twice the honest share rate) and signs every slot it may.
#[test]
fn a_private_fork_after_finality_cannot_finalize_from_hardening_2() {
    setup();
    let genesis = mk_genesis(unix_now() - 100_000);
    for h2 in [activation::NEVER, 0] {
        let _g = activation::scoped_override_v2(h2);
        let (k1, k2, z) = (Key::new(1), Key::new(2), Key::new(9));
        let mut honest = Producer::new(&genesis);
        honest.extend(60, "h", &[(&k1, 1), (&k2, 1)], &[&k1, &k2]);
        let at_fork = honest.tip_state();
        assert!(at_fork.finalized.height > ACT, "h2 {h2}: the honest chain finalized {:?}", at_fork.finalized);

        let mut attacker = Producer::new(&genesis);
        attacker.adopt(&honest.blocks);
        let fork = attacker.extend(80, "z", &[(&z, 4)], &[&z]);
        let st = attacker.tip_state();
        let fork_hashes: Vec<BlockHash> = fork.iter().map(|b| b.block_hash()).collect();
        if h2 == activation::NEVER {
            assert!(fork_hashes.contains(&st.finalized.hash),
                "first rule: the attacker's own shares give it the witness set: {:?}", st.finalized);
        } else {
            assert_eq!(st.finalized, at_fork.finalized, "hardening 2: the fork finalizes nothing of its own");
            assert!(!st.links.contains_key(&z.id()), "Z never was a member");
            // An attestation by Z is refused by acceptance itself.
            let parent = attacker.tip();
            let h = attacker.node.dag.read().get_block_data(&parent).unwrap().height + 1;
            let target = (ACT..=h).rev().find(|s| P.is_checkpoint(ACT, *s) && *s > st.justified.height)
                .expect("an open slot");
            let hash = DagChainView { dag: &attacker.node.dag.read(), start: Some(parent) }.selected_at(target).unwrap();
            let forced = z.attest(st.justified, Checkpoint { height: target, hash });
            let b = build(&attacker.node, parent, "forced", Vec::new(), vec![forced]);
            let err = accept(&attacker.node, &b).expect_err("not a member of the finalized witness set");
            assert!(err.contains("not in the witness set"), "{err}");
        }
    }
}

/// Finding 3, node side: the eclipse of a syncing node by a fork from the
/// PoWit activation, against the release finality checkpoint X (a block of
/// the honest chain at height 20, set process-wide once in this binary).
#[test]
fn an_eclipsed_node_never_pins_a_fork_below_the_release_checkpoint() {
    setup();
    let _g = activation::scoped_override_v2(0);
    let genesis = mk_genesis(unix_now() - 100_000);
    let (k1, k2, z) = (Key::new(11), Key::new(12), Key::new(19));
    let mut honest = Producer::new(&genesis);
    honest.extend(56, "h", &[(&k1, 1), (&k2, 1)], &[&k1, &k2]);
    let x = &honest.blocks[19];
    assert_eq!(x.height, 20);
    powit::set_release_finality_checkpoint(Some(powit::ReleaseCheckpoint { height: 20, hash: x.block_hash() }))
        .expect("the release checkpoint is set once, by this test");
    let honest_fin = honest.tip_state().finalized;
    assert!(honest_fin.height > 20);

    // The attacker forks right below the activation: no shares exist yet, so
    // its own key is its whole witness set.
    let mut attacker = Producer::new(&genesis);
    attacker.adopt(&honest.blocks[..2]);
    attacker.extend(50, "f", &[(&z, 1)], &[&z]);
    let fork_fin = attacker.tip_state().finalized;
    assert!(fork_fin.height > ACT, "the fork finalized its own checkpoint: {fork_fin:?}");
    let fork: Vec<Block> = attacker.blocks[2..].to_vec();
    let heavier_fork: Vec<Block> = {
        attacker.extend(20, "g", &[(&z, 1)], &[&z]);
        attacker.blocks[2..].to_vec()
    };
    let fin_of = |blocks: &[Block]| {
        powit::load_state(&attacker.node.store, &blocks.last().unwrap().block_hash()).unwrap().finalized.hash
    };
    assert!(heavier_fork.len() > honest.blocks.len() - 2 && fork.len() < honest.blocks.len() - 2);

    // V1: eclipsed on the fork while syncing; the honest (heavier) chain
    // then arrives.
    let mut v1 = node_with(&genesis, &[]);
    deliver(&v1, &honest.blocks[..2]);
    deliver(&v1, &fork);
    assert_eq!(pin_of(&v1), None, "a finality that conflicts with the release checkpoint never pins");
    assert_eq!(applied_tip(&v1), Some(fork.last().unwrap().block_hash()), "the only chain it knows");
    let info = powit::finality_info_json(&v1.dag.read(), 8);
    assert_eq!(info["anchor_status"], serde_json::json!("unknown"), "{info}");
    assert!(info["against_anchor"].as_u64().unwrap() >= 1, "{info}");
    deliver(&v1, &honest.blocks[2..]);
    assert_eq!(pin_of(&v1), Some(honest_fin.hash), "the honest finality, through X");
    assert_eq!(applied_tip(&v1), Some(honest.tip()));
    restart(&mut v1);
    assert_eq!((pin_of(&v1), applied_tip(&v1)), (Some(honest_fin.hash), Some(honest.tip())));

    // V2: the fork carries more work than the honest chain: X still decides.
    let v2 = node_with(&genesis, &[]);
    deliver(&v2, &honest.blocks[..2]);
    deliver(&v2, &heavier_fork);
    deliver(&v2, &honest.blocks[2..]);
    assert_eq!(applied_tip(&v2), Some(honest.tip()), "the release checkpoint outweighs the fork's work");

    // V3 / V4: no anchor at all (`setfinalitycheckpoint none`). The fork's
    // finality is all the eclipsed node knows: it reaches it on its applied
    // chain, and keeps it when the honest chain arrives with its own, whether
    // the honest chain is heavier (V3) or not (V4), raising the conflict:
    // a node cannot tell an eclipse from a majority-hashrate attack on its
    // finality (review HIGH 1, the test below), which is why the release
    // checkpoint (V1, V2) and the minimum chain work exist. The operator's
    // weak-subjectivity checkpoint then moves it to the honest chain.
    for fork in [&fork, &heavier_fork] {
        let v = node_with(&genesis, &[]);
        deliver(&v, &honest.blocks[..2]);
        gnb::accept::override_finality(FinalityOp::DisableAnchor, &v.dag, &v.store, &v.mempool, &v.node_state,
            Some(&v.tip_tx), &v.shielded).unwrap();
        deliver(&v, fork);
        assert_eq!(pin_of(&v), Some(fin_of(fork)), "no anchor: the fork's finality pins the eclipsed node");
        deliver(&v, &honest.blocks[2..]);
        assert_eq!(pin_of(&v), Some(fin_of(fork)), "it keeps the finality it reached");
        assert_eq!(applied_tip(&v), Some(fork.last().unwrap().block_hash()), "whatever the honest chain's work");
        assert!(powit::info_json(&v.dag.read(), &v.store)["finality_conflict"].as_bool().unwrap());
        gnb::accept::override_finality(FinalityOp::SetAnchor(x.block_hash()), &v.dag, &v.store, &v.mempool,
            &v.node_state, Some(&v.tip_tx), &v.shielded).unwrap();
        assert_eq!((pin_of(&v), applied_tip(&v)), (Some(honest_fin.hash), Some(honest.tip())),
            "the operator's checkpoint moves it");
    }
}

/// Review HIGH 1 (regression against main), end to end under the first
/// witness-set rule: a majority-hashrate attacker forks the honest chain
/// privately right after its finalized checkpoint, mines four shares per
/// block for its own key Z, finalizes its own checkpoint, and publishes the
/// heavier fork once the honest chain has finalized above the fork point. A
/// synced node used to pin the latest common block of the two finalities and
/// follow the most work, rolling its finalized history back. It now keeps the
/// finality it reached, stays on the honest chain and raises the conflict.
#[test]
fn a_synced_node_keeps_its_finality_when_a_heavier_fork_finalizes_its_own() {
    setup();
    let _g = activation::scoped_override_v2(activation::NEVER);
    let genesis = mk_genesis(unix_now() - 100_000);
    let (k1, k2, z) = (Key::new(41), Key::new(42), Key::new(49));
    let mut honest = Producer::new(&genesis);
    honest.extend(60, "h", &[(&k1, 1), (&k2, 1)], &[&k1, &k2]);
    let mut attacker = Producer::new(&genesis);
    attacker.adopt(&honest.blocks);
    let fork = attacker.extend(80, "z", &[(&z, 4)], &[&z]);
    let fork_fin = attacker.tip_state().finalized;
    assert!(fork.iter().any(|b| b.block_hash() == fork_fin.hash), "the fork finalized its own: {fork_fin:?}");
    let more = honest.extend(40, "i", &[(&k1, 1), (&k2, 1)], &[&k1, &k2]);
    let honest_fin = honest.tip_state().finalized;
    assert!(more.iter().any(|b| b.block_hash() == honest_fin.hash), "honest finality above the fork point");
    assert!(fork.len() > more.len(), "the attacker's fork carries more work");

    let mut v = node_with(&genesis, &[]);
    // No anchor: the release checkpoint of this binary belongs to another
    // chain (`an_eclipsed_node_never_pins_a_fork_below_the_release_checkpoint`).
    gnb::accept::override_finality(FinalityOp::DisableAnchor, &v.dag, &v.store, &v.mempool, &v.node_state,
        Some(&v.tip_tx), &v.shielded).unwrap();
    deliver(&v, &honest.blocks);
    assert_eq!((pin_of(&v), applied_tip(&v)), (Some(honest_fin.hash), Some(honest.tip())));
    deliver(&v, &fork);
    assert_eq!(pin_of(&v), Some(honest_fin.hash), "the node keeps the finality it reached");
    assert_eq!(applied_tip(&v), Some(honest.tip()), "and never rolls it back for more work");
    let info = powit::finality_info_json(&v.dag.read(), 8);
    let pair: Vec<String> = info["conflict"].as_array().expect("the conflict is reported").iter()
        .map(|c| c["hash"].as_str().unwrap().to_string()).collect();
    assert_eq!(pair, vec![hex::encode(honest_fin.hash), hex::encode(fork_fin.hash)], "{info}");
    restart(&mut v);
    assert_eq!((pin_of(&v), applied_tip(&v)), (Some(honest_fin.hash), Some(honest.tip())));
    assert!(powit::info_json(&v.dag.read(), &v.store)["finality_conflict"].as_bool().unwrap());
}

// ── Producers at the second hardening boundary ───────────────────────────────

/// A synthetic chain whose tip state finalized slot 43 (two whole epochs)
/// and stalled: the honest key M earned shares in epochs 0-1, the newcomer K
/// (heavier) in epochs 2-4. A target in epoch 5 reads the window 1..=3 under
/// the first rule (K is a member) and the frozen finalized window 0..=1
/// from hardening 2 (M only).
struct Stalled {
    _tmp: TempDir,
    store: Storage,
    dag: GhostDAG,
    hashes: Vec<BlockHash>,
}

fn stalled(m: KeyId, k: KeyId) -> Stalled {
    let tmp = TempDir::new().unwrap();
    let store = Storage::open(&tmp.path().join("db")).unwrap();
    let mut dag = GhostDAG::with_default_k();
    let mut hashes = Vec::new();
    for h in 0..=111u64 {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&h.to_le_bytes());
        x[31] = 0x5A;
        if h == 0 {
            dag.add_genesis(x, 1_000);
        } else {
            dag.add_block(x, vec![hashes[h as usize - 1]], 1_000 + h, 1).unwrap();
        }
        hashes.push(x);
    }
    let cp = |slot: u64| Checkpoint { height: slot, hash: hashes[slot as usize - 1] };
    let mut st = PowitState::genesis(ACT, cp(ACT).hash);
    st.finalized = cp(43);
    st.justified = cp(43);
    st.finalized_at = 50;
    st.epoch = P.epoch(ACT, 111);
    for e in 0..=1 {
        st.epoch_work.entry(e).or_default().insert(m, 1_000);
    }
    for e in 2..=4 {
        st.epoch_work.entry(e).or_default().insert(k, 5_000);
    }
    powit::save_state(&store, &hashes[111], &st).unwrap();
    Stalled { _tmp: tmp, store, dag, hashes }
}

const PASSWORD: &str = "correct horse battery staple 77";

/// The pool admits, and the witness duty signs, an attestation by K exactly
/// while the next block is below the second hardening height: at H-1 (the
/// next block at 112 = H - 1) both do, at H (the next block at H = 112)
/// neither does, as `apply` would refuse it there.
#[test]
fn producers_follow_the_witness_set_rule_of_the_next_block() {
    setup();
    let (m, k) = (Key::new(31), Key::new(32));
    let s = stalled(m.id(), k.id());
    let next = 112u64;
    let target = Checkpoint { height: 108, hash: s.hashes[107] };
    for (h2, member) in [(next + 1, true), (next, false)] {
        let _g = activation::scoped_override_v2(h2);
        // Signed under the message rule of this second hardening height
        // (`Attestation::sign` reads it: v2 for a target at or above it).
        let att = k.attest(Checkpoint { height: 43, hash: s.hashes[42] }, target);
        let pool = PowitPool::new();
        let r = pool.admit_attestation(att.clone(), &s.dag, &s.store);
        assert_eq!(r.is_ok(), member, "H = {h2}: pool admission {r:?}");

        let dir = TempDir::new().unwrap();
        let fresh = Key::new(32);
        KesKeyFile::seal(&fresh.signer.borrow(), PASSWORD).unwrap().save(&dir.path().join("w.key")).unwrap();
        std::fs::write(dir.path().join("pw"), format!("{PASSWORD}\n")).unwrap();
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        let duty = powit::WitnessDuty::load(&dir.path().join("w.key"), &dir.path().join("pw"), vec![0x51],
            &dir.path().join("data")).unwrap();
        let signed = duty.maybe_attest(&s.dag, &s.store).unwrap();
        assert_eq!(signed.is_some(), member, "H = {h2}: witness duty");
        if let Some(a) = signed {
            assert_eq!(a.target, target, "the newest slot at or below the next block, 108");
        }
    }
}

/// Review MEDIUM 5: the pool computed the attester's weight for an
/// attacker-chosen target before checking that the target is an open
/// checkpoint slot (and before the signature). From the second hardening
/// activation that weight reads the frozen finalized window, whose
/// emptiness test aggregated the whole window, for any target epoch beyond
/// the finalized one. The target is now checked first: a link to a slot the
/// next block cannot include is refused before any witness-set work, by
/// member and non-member alike.
#[test]
fn the_pool_checks_the_target_slot_before_the_witness_set() {
    setup();
    let (m, k) = (Key::new(35), Key::new(36));
    let s = stalled(m.id(), k.id());
    let _g = activation::scoped_override_v2(0);
    let source = Checkpoint { height: 43, hash: s.hashes[42] };
    // Slot 148 (epoch 7): a checkpoint slot far above the tip (111).
    let far = Checkpoint { height: 148, hash: [7; 32] };
    for key in [&k, &m] {
        let pool = PowitPool::new();
        let err = pool.admit_attestation(key.attest(source, far), &s.dag, &s.store).expect_err("not open");
        assert_eq!(err, "attestation target is not an open checkpoint slot");
    }
}
