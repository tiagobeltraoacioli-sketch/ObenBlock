//! PoCI with real KES keys and the PoWit state machine (ObenBlock regtest
//! clock: 20-block epochs, slots every 5): v3 signatures, the launch
//! bootstrap, strict quorum, handoff, evidence and bans, the PoCI body
//! format, certificates. The byte-level rules are checked against the
//! reference in `tests/poci_vectors.rs`.

use super::poci::*;
use super::*;
use crate::core::kes::KesSigner;
use crate::core::ChainId;

const CHAIN: ChainId = ChainId::ObenBlockRegtest;
const P: PowitParams = OBENBLOCK_REGTEST_PARAMS;
const PP: PociParams = OBB_REGTEST_POCI;
const W: u128 = 1_000;
/// Every block's compact bits: share work 1 at the share target, so the
/// growth cap's `G_min` is `20 × 16 × 1 / 8 = 40` per epoch.
const BITS: u32 = 0x207F_FFFF;

struct Key(std::cell::RefCell<KesSigner>);

impl Key {
    fn rejoin(&self, e: u64) -> WitnessRejoin {
        self.evolve(e);
        WitnessRejoin::sign(PP.chain_id, &self.0.borrow()).unwrap()
    }

    fn new(seed: u8) -> Key {
        Key(std::cell::RefCell::new(KesSigner::generate(6, [seed; 32], |_| {}).unwrap()))
    }
    fn public(&self) -> KesPublic {
        self.0.borrow().public()
    }
    fn id(&self) -> KeyId {
        self.public().witness_id()
    }
    fn evolve(&self, e: u64) {
        let mut s = self.0.borrow_mut();
        if e > s.epoch() {
            s.evolve_to(e).unwrap();
        }
    }
    fn vote(&self, config_id: &[u8; 32], source: Checkpoint, target: Checkpoint) -> Attestation {
        self.evolve(PP.epoch_of(target.height));
        Attestation::sign_v3(PP.chain_id, config_id, source, target, &self.0.borrow()).unwrap()
    }
}

fn hash(h: u64) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&h.to_le_bytes());
    x[31] = 0xB1;
    x
}

/// Slot `c` names the highest selected-chain block strictly below `c`: on
/// this linear chain, block `c - 1`.
fn cp(c: u64) -> Checkpoint {
    Checkpoint { height: c, hash: hash(c - 1) }
}

/// The selected chain of a block at height `.0` (blocks `0 ..= .0 - 1`).
struct Chain(u64);

impl ChainView for Chain {
    fn selected_at(&self, slot: u64) -> Option<[u8; 32]> {
        (slot >= 1 && slot <= self.0).then(|| hash(slot - 1))
    }
}

struct Harness {
    st: PowitState,
    h: u64,
    shares: Vec<KeyId>,
    /// Share work of other keys in every block.
    extra: Vec<(KeyId, u128)>,
}

impl Harness {
    fn new(keys: &[&Key]) -> Harness {
        Harness { st: PowitState::genesis(0, hash(0)), h: 0, shares: keys.iter().map(|k| k.id()).collect(),
                  extra: Vec::new() }
    }

    fn try_block(&self, atts: &[Attestation], ev: &[PociEvidence]) -> Result<PowitState, String> {
        self.try_block_with(atts, ev, &[])
    }

    fn try_block_with(&self, atts: &[Attestation], ev: &[PociEvidence], rejoins: &[WitnessRejoin])
        -> Result<PowitState, String>
    {
        let h = self.h + 1;
        let mut sw: Vec<(KeyId, u128)> = self.shares.iter().map(|k| (*k, W)).collect();
        sw.extend(self.extra.iter().copied());
        let input = BlockInput { height: h, hash: hash(h), share_work: &sw, attestations: atts, evidence: &[], exits: &[] };
        self.st.apply_block(&P, CHAIN, 0, 0, &input, BITS, PociItems { evidence: ev, rejoins }, &Chain(h))
    }

    fn block_with(&mut self, atts: &[Attestation], rejoins: &[WitnessRejoin]) {
        self.st = self.try_block_with(atts, &[], rejoins).unwrap_or_else(|e| panic!("block {}: {e}", self.h + 1));
        self.h += 1;
    }

    /// `keys` vote justified -> `slot` in the block right after it.
    fn slot(&mut self, keys: &[&Key], slot: u64) {
        self.to(slot);
        let v = self.votes(keys, slot);
        self.block(&v, &[]);
    }

    /// Votes at every slot up to the one after the opening of `x`, which
    /// finalizes it: the handoff to `C_x`.
    fn handoff_to(&mut self, keys: &[&Key], x: u64) {
        // Right after the launch (block `launch_height`) the slot at the tip
        // is still open for votes.
        let open = (self.h - self.h % PP.checkpoint_interval).saturating_sub(PP.checkpoint_interval);
        let mut slot = self.st.justified.height.max(open);
        while slot < PP.opening(x) + PP.checkpoint_interval {
            slot += PP.checkpoint_interval;
            self.slot(keys, slot);
            assert_eq!(self.st.justified, cp(slot), "slot {slot}");
        }
        assert_eq!(self.st.finalized, cp(PP.opening(x)));
        assert_eq!(self.config().epoch(), x);
    }

    fn block(&mut self, atts: &[Attestation], ev: &[PociEvidence]) {
        self.st = self.try_block(atts, ev).unwrap_or_else(|e| panic!("block {}: {e}", self.h + 1));
        self.h += 1;
    }

    fn to(&mut self, h: u64) {
        while self.h < h {
            self.block(&[], &[]);
        }
    }

    /// Up to the block that launches PoCI (§9: `launch_height`).
    fn launch(&mut self) {
        self.to(PP.launch_height() - 1);
        assert!(self.st.poci.is_none());
        self.block(&[], &[]);
        assert_eq!(self.config().epoch(), PP.bootstrap_epochs);
    }

    fn config(&self) -> std::sync::Arc<Configuration> {
        self.st.poci_config().unwrap().clone()
    }

    /// Votes of `keys` for justified -> `target` under the configuration in force.
    fn votes(&self, keys: &[&Key], target: u64) -> Vec<Attestation> {
        let id = self.config().id();
        keys.iter().map(|k| k.vote(&id, self.st.justified, cp(target))).collect()
    }
}

#[test]
fn params_match_the_chain() {
    assert_eq!(PociParams::for_chain(ChainId::ObenBlockMainnet), Some(OBB_MAINNET_POCI));
    assert_eq!(PociParams::for_chain(ChainId::ObenBlockRegtest), Some(OBB_REGTEST_POCI));
    assert_eq!(PociParams::for_chain(ChainId::Mainnet), None);
    assert_eq!(PociParams::for_chain(ChainId::Testnet), None);
    for (chain, pp) in [(ChainId::ObenBlockMainnet, OBB_MAINNET_POCI), (ChainId::ObenBlockRegtest, OBB_REGTEST_POCI)] {
        let p = params_for(chain);
        assert_eq!(pp.chain_id, chain.to_u32());
        assert_eq!((pp.epoch_len, pp.checkpoint_interval, pp.vote_ttl), (p.epoch_len, p.checkpoint_interval, p.vote_ttl));
        assert_eq!(pp.max_attestations_per_block, p.max_attestations_per_block as u64);
        assert_eq!(pp.max_evidence_per_block, p.max_evidence_per_block as u64);
    }
    assert_eq!(params_for(ChainId::ObenBlockMainnet).window_epochs, OBB_MAINNET_POCI.window_epochs);
}

#[test]
fn v3_signatures_bind_key_and_configuration() {
    let k = Key::new(1);
    let (s, t) = (cp(80), cp(85));
    let a = k.vote(&[7; 32], s, t);
    assert!(a.verify_signature_v3(&PP, &[7; 32]));
    assert!(!a.verify_signature_v3(&PP, &[8; 32]), "another configuration");
    assert!(!a.verify_signature_v3(&OBB_MAINNET_POCI, &[7; 32]), "another chain");
    // Not a PoWit v1 or v2 signature, and a v2 one is not a v3 one.
    assert!(!a.verify_signature_at(CHAIN, &P, 0, 0));
    assert!(!a.verify_signature_at(CHAIN, &P, 0, activation::NEVER));
    let v2 = Attestation::sign_at(CHAIN, 0, s, t, &k.0.borrow()).unwrap();
    assert!(v2.verify_signature_at(CHAIN, &P, 0, 0));
    assert!(!v2.verify_signature_v3(&PP, &[7; 32]));
    // Re-rooting the leaf signature into another key does not verify.
    let mut other = a.clone();
    other.witness.root[0] ^= 1;
    assert!(!other.verify_signature_v3(&PP, &[7; 32]));
}

#[test]
fn launch_bootstrap_then_strict_quorum_handoff_and_v3_only() {
    let keys: Vec<Key> = (1..=4).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let outsider = Key::new(9);
    let mut c = Harness::new(&k);
    c.to(10);
    // §9: no votes during the PoW-only epochs.
    let early = k[0].vote(&[0; 32], cp(0 + 5), cp(10));
    assert!(c.try_block(&[early], &[]).unwrap_err().contains("bootstrap"));
    assert!(c.st.poci.is_none());
    // Nor during epoch 4: the launch checkpoint (slot 80) is not buried yet,
    // and no state carries a finalized checkpoint above genesis (nothing to pin).
    assert_eq!(PP.launch_height(), 100);
    while c.h < PP.launch_height() - 1 {
        if c.h == 96 {
            let early = k[0].vote(&[0; 32], cp(80), cp(95));
            assert!(c.try_block(&[early], &[]).unwrap_err().contains("bootstrap"));
        }
        c.block(&[], &[]);
        assert!(c.st.poci.is_none(), "block {}", c.h);
        assert_eq!((c.st.finalized.height, c.st.justified.height), (0, 0), "block {}", c.h);
    }
    // The block at launch_height launches C_4 from the history below slot 80,
    // now buried by one epoch.
    c.block(&[], &[]);
    let launch = cp(80);
    assert_eq!((c.st.justified, c.st.finalized), (launch, launch));
    let c4 = c.config();
    assert_eq!(c4.epoch(), 4);
    assert_eq!(c4.len(), 4);
    // The growth cap (DESIGN-obenblock.md §6.3) from W = 0: the cap steps
    // for C_2, C_3, C_4 (epochs 0, 1, 2 entering the window) each admit
    // G_min = 40, pro rata over four equal keys, 10 each.
    assert!(c4.entries().iter().all(|(_, w)| *w == 30));
    assert_eq!(c4.total(), 120);
    assert_eq!(c.st.cap.as_ref().unwrap().ledger.epoch(), 4);
    assert_eq!(c.st.finalized_at, 100);
    c.to(105);

    // Half the weight justifies nothing; a third key (75 %) does.
    let two = c.votes(&k[..2], 105);
    c.block(&two, &[]);
    assert_eq!(c.st.justified, launch);
    // A PoWit v2 vote of a member does not verify on PoCI.
    let v2 = Attestation::sign_at(CHAIN, 0, launch, cp(105), &k[2].0.borrow()).unwrap();
    assert!(c.try_block(&[v2], &[]).unwrap_err().contains("invalid attestation signature"));
    // A key outside the configuration cannot vote.
    let out = outsider.vote(&c4.id(), launch, cp(105));
    assert!(c.try_block(&[out], &[]).unwrap_err().contains("not in the PoCI configuration"));
    // A vote naming another configuration is refused.
    let wrong = k[2].vote(&[0xEE; 32], launch, cp(105));
    assert!(c.try_block(&[wrong], &[]).is_err());
    let third = c.votes(&k[2..3], 105);
    c.block(&third, &[]);
    assert_eq!(c.st.justified, cp(105));
    // Not a direct child of the launch checkpoint: nothing finalized.
    assert_eq!(c.st.finalized, launch);
    assert_eq!(c.config().epoch(), 4);

    // The next slot finalizes 105, in epoch 5: the handoff to C_5.
    let mut slot = 105;
    while slot < 115 {
        slot += 5;
        c.to(slot);
        let v = c.votes(&k[..3], slot);
        c.block(&v, &[]);
        assert_eq!(c.st.justified, cp(slot));
        assert_eq!(c.st.finalized, cp(slot - 5));
        assert_eq!(c.config().epoch(), 5, "slot {slot}");
    }
    let c5 = c.config();
    assert_ne!(c5.id(), c4.id());
    // C_5: one more cap step (epoch 3 entering; G = max(120 / 64, 40) = 40).
    assert!(c5.entries().iter().all(|(_, w)| *w == 40));
    assert_eq!(c.st.poci.as_ref().unwrap().previous().unwrap().id(), c4.id());
    // Votes under the old configuration are refused now.
    c.to(120);
    let old = k[0].vote(&c4.id(), c.st.justified, cp(120));
    assert!(c.try_block(&[old], &[]).unwrap_err().contains("invalid attestation signature"));
    // No inactivity leak: the GnB decay and bans stay empty.
    assert!(c.st.decay.is_empty() && c.st.banned.is_empty());
}

#[test]
fn exactly_two_thirds_never_justifies() {
    let keys: Vec<Key> = (11..=13).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let mut c = Harness::new(&k);
    c.launch();
    c.to(105);
    // Three equal keys: two of them are exactly two thirds.
    let two = c.votes(&k[..2], 105);
    c.block(&two, &[]);
    assert_eq!(c.st.justified, cp(80), "3 got > 2 total is strict");
    let three = c.votes(&k[2..], 105);
    c.block(&three, &[]);
    assert_eq!(c.st.justified, cp(105));
}

#[test]
fn evidence_bans_from_the_next_handoff_and_keeps_the_configuration_in_force() {
    let keys: Vec<Key> = (21..=24).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let mut c = Harness::new(&k);
    c.launch();
    c.to(105);
    let c4 = c.config();
    // Key 3 signs two different targets at the same height under C_4.
    let a = k[3].vote(&c4.id(), cp(80), cp(105));
    let mut fake = cp(105);
    fake.hash[0] ^= 0xFF;
    let b = k[3].vote(&c4.id(), cp(80), fake);
    let ev = PociEvidence { config_id: c4.id(), a: a.clone(), b: b.clone() };
    // Not GnB's equivocation proofs on a PoCI chain.
    let gnb = BlockInput { height: c.h + 1, hash: hash(c.h + 1), share_work: &[], attestations: &[],
                           evidence: &[Equivocation { a: a.clone(), b: b.clone() }], exits: &[] };
    assert!(c.st.apply_block(&P, CHAIN, 0, 0, &gnb, BITS, PociItems::default(), &Chain(c.h + 1)).is_err());
    // Identical votes and unknown configurations are not evidence.
    let same = PociEvidence { config_id: c4.id(), a: a.clone(), b: a.clone() };
    assert!(c.try_block(&[], &[same]).unwrap_err().contains("identical"));
    let unknown = PociEvidence { config_id: [3; 32], a: a.clone(), b: b.clone() };
    assert!(c.try_block(&[], &[unknown]).unwrap_err().contains("unknown_config"));
    let ev_height = c.h + 1;
    c.block(&[], &[ev.clone()]);
    let bans = &c.st.poci.as_ref().unwrap().bans[&k[3].id()];
    assert_eq!(bans.len(), 1);
    assert_eq!((bans[0].included_at, bans[0].start), (ev_height + 1, None));
    // One ban at a time: the same evidence again is refused.
    assert!(c.try_block(&[], &[ev.clone()]).unwrap_err().contains("already_banned_for_config"));
    // The configuration in force is unchanged: key 3 still counts.
    assert_eq!(c.config().id(), c4.id());
    // Keys 0..=2 justify 105 and finalize it: the handoff to C_5. The
    // evidence (included at 107) is above opening(5) = 100, so C_5, which
    // reads the history up to opening(5) only (§4), does not see it: the
    // ban stays pending and key 3 is still an entry of C_5.
    for slot in [105, 110] {
        c.to(slot.max(c.h));
        let v = c.votes(&k[..3], slot);
        c.block(&v, &[]);
    }
    assert_eq!((c.st.finalized, c.config().epoch()), (cp(105), 5));
    assert_eq!(c.st.poci.as_ref().unwrap().bans[&k[3].id()][0].start, None);
    assert!(c.config().weight(&k[3].id()).is_some());
    // The next handoff (opening(6) = 120 >= 107) starts it.
    c.handoff_to(&k[..3], 6);
    let st = c.st.poci.as_ref().unwrap();
    assert_eq!(st.bans[&k[3].id()][0].start, Some(6));
    assert_eq!(st.bans[&k[3].id()][0].end(PP.ban_epochs), Some(106));
    assert!(st.banned_at(&PP, &k[3].id(), 6) && st.banned_at(&PP, &k[3].id(), 105));
    assert!(!st.banned_at(&PP, &k[3].id(), 106) && !st.banned_at(&PP, &k[3].id(), 5));
    // Left out of C_6; its shares are refused while banned.
    assert_eq!(c.config().epoch(), 6);
    assert!(c.config().weight(&k[3].id()).is_none());
    assert_eq!(c.config().len(), 3);
    assert!(c.try_block(&[], &[]).unwrap_err().contains("barred"));
    c.shares.pop();
    c.block(&[], &[]);
}

#[test]
fn poci_body_format() {
    let k = Key::new(31);
    let a = k.vote(&[1; 32], cp(80), cp(85));
    let mut b2 = cp(85);
    b2.hash[1] ^= 1;
    let ev = PociEvidence { config_id: [1; 32], a: a.clone(), b: k.vote(&[1; 32], cp(80), b2) };
    let body = PowitBody { attestations: vec![a], poci_evidence: vec![ev.clone()], ..PowitBody::default() };
    for exits in [false, true] {
        let fmt = BodyFormat { exits, poci: true };
        let mut buf = Vec::new();
        body.write_wire_for(&mut buf, fmt);
        let mut cur = std::io::Cursor::new(buf.as_slice());
        assert_eq!(PowitBody::read_wire_for(&mut cur, fmt).unwrap(), body);
        assert_eq!(cur.position() as usize, buf.len());
        // An empty section is the same bytes in every format (genesis roots).
        for gnb in [BodyFormat::GNB, BodyFormat { exits, poci: false }] {
            if gnb.exits == exits {
                assert_eq!(PowitBody::default().root_for(fmt), PowitBody::default().root_for(gnb));
            }
        }
    }
    assert_eq!(PowitBody::default().root_for(BodyFormat::GNB), PowitBody::default().root());
    let ev_bytes = ev.to_wire_bytes();
    let mut cur_ev = std::io::Cursor::new(&ev_bytes[..]);
    assert_eq!(PociEvidence::read_wire(&mut cur_ev).unwrap(), ev);
    // GnB rejects PoCI evidence.
    let st = PowitState::genesis(0, hash(0));
    let input = BlockInput { height: 1, hash: hash(1), share_work: &[], attestations: &[], evidence: &[], exits: &[] };
    assert!(st.apply_block(&TESTNET_PARAMS, ChainId::Testnet, 0, 0, &input, BITS,
                           PociItems { evidence: &[ev], rejoins: &[] }, &Chain(1)).is_err());
}

#[test]
fn gnb_state_encoding_is_unchanged_by_the_poci_field() {
    let keys: Vec<Key> = (41..=42).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let mut c = Harness::new(&k);
    c.to(PP.launch_height() + 1);
    assert!(c.st.poci.is_some());
    let with = bincode::serde::encode_to_vec(&c.st, bincode::config::standard()).unwrap();
    let mut without = c.st.clone();
    without.poci = None;
    assert_eq!(with, bincode::serde::encode_to_vec(&without, bincode::config::standard()).unwrap());
}

#[test]
fn kes_certificates_and_registry_proofs() {
    let keys: Vec<Key> = (51..=54).map(Key::new).collect();
    let weights: BTreeMap<KeyId, u128> = keys.iter().enumerate().map(|(i, k)| (k.id(), 100 + i as u128)).collect();
    let cfg = Configuration::from_weights(&PP, 4, &weights).unwrap();
    let (s, t) = (cp(80), cp(85));
    let votes: Vec<(KesPublic, KesSignature)> =
        keys[..3].iter().map(|k| (k.public(), k.vote(&cfg.id(), s, t).sig)).collect();
    let cert = Certificate::<Kes>::new(PP.chain_id, cfg.id(), s, t, votes.clone());
    let data = cert.encode();
    let back = Certificate::<Kes>::decode(&data).unwrap();
    assert_eq!(back, cert);
    assert!(verify_certificate::<Kes>(&data, &PP, &cfg).is_ok());
    let voters: Vec<KeyId> = cert.votes.iter().map(|(k, _)| k.witness_id()).collect();
    let proof = cfg.registry_proof(&voters).unwrap().encode();
    assert!(verify_certificate_with_proof::<Kes>(&data, &proof, &PP, &cfg.id()).is_ok());
    // Two keys are below the strict quorum.
    let two = Certificate::<Kes>::new(PP.chain_id, cfg.id(), s, t, votes[..2].to_vec());
    assert_eq!(two.verify(&PP, &cfg), Err(CertReject::Quorum));
    // A tampered signature, last.
    let mut bad = cert.clone();
    bad.votes[1].1.sig[0] ^= 1;
    assert_eq!(bad.verify(&PP, &cfg), Err(CertReject::Signature));
    // Truncation anywhere is a decode failure, never a panic.
    for n in 0..data.len() {
        assert!(Certificate::<Kes>::decode(&data[..n]).is_err());
    }
    // Real-KES evidence verdict.
    let (a, b) = (keys[0].vote(&cfg.id(), s, t), keys[0].vote(&cfg.id(), s, Checkpoint { height: 85, hash: [9; 32] }));
    let ev = PociEvidence { config_id: cfg.id(), a, b };
    let (va, vb) = ev.votes();
    assert_eq!(check_evidence(&PP, &va, &vb, |id| (*id == cfg.id()).then_some(&cfg)), Ok(EvidenceKind::Double));
}

#[test]
fn absent_keys_are_pruned_at_the_handoff_and_rejoin_from_the_next() {
    let keys: Vec<Key> = (61..=65).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let (core, quiet) = (&k[..4], k[4]);
    let mut c = Harness::new(&k);
    c.launch();
    assert_eq!(c.config().len(), 5);
    // Epochs 5..=7: the quiet key is in its grace period.
    for x in 5..=7 {
        c.handoff_to(core, x);
        assert!(c.config().weight(&quiet.id()).is_some(), "grace at {x}");
    }
    // A rejoin by a key that is not pruned is refused.
    let early = quiet.rejoin(7);
    assert!(c.try_block_with(&[], &[], &[early]).unwrap_err().contains("not_pruned"));
    // An entry since epoch 4 with no vote included: pruned at 8.
    c.handoff_to(core, 8);
    let st = c.st.poci.as_ref().unwrap();
    assert!(c.config().weight(&quiet.id()).is_none());
    assert_eq!(st.pruned.get(&quiet.id()).map(|p| p.start), Some(8));
    assert_eq!(c.config().len(), 4);
    // No leak: the keys that stayed keep every credit of the growth cap (the
    // same shares for every key, whether it voted or not): the configuration
    // is the cap ledger's weights without the pruned key. The pruned key
    // keeps its credits but got none at 8 (excluded keys do not compete).
    let ledger_w = c.st.cap.as_ref().unwrap().ledger.weights();
    let w8 = c.config().entries()[0].1;
    assert!(c.config().entries().iter().all(|(id, w)| *w == w8 && ledger_w.get(id) == Some(w)));
    assert!(ledger_w.get(&quiet.id()).is_some_and(|w| 0 < *w && *w < w8), "no credit while pruned");
    // Pruned, not banned: its shares are still valid; it cannot vote.
    let id8 = c.config().id();
    let v = quiet.vote(&id8, c.st.justified, cp(c.h - c.h % 5));
    assert!(c.try_block(&[v], &[]).unwrap_err().contains("not in the PoCI configuration"));
    // Rejoin: refused for an old epoch, with a bad signature, twice.
    assert!(c.try_block_with(&[], &[], &[k[0].rejoin(8)]).unwrap_err().contains("not_pruned"));
    let mut bad = quiet.rejoin(8);
    bad.sig.sig[0] ^= 1;
    assert!(c.try_block_with(&[], &[], &[bad]).unwrap_err().contains("signature"));
    let rj = quiet.rejoin(8);
    assert!(c.try_block_with(&[], &[], &[rj.clone(), rj.clone()]).unwrap_err().contains("pending"));
    c.block_with(&[], &[rj.clone()]);
    let rj_at = c.h + 1;
    assert_eq!(c.st.poci.as_ref().unwrap().rejoins.get(&quiet.id()), Some(&rj_at));
    assert!(c.try_block_with(&[], &[], &[rj]).unwrap_err().contains("pending"));
    // The handoff whose finalization holds the rejoin brings it back, its
    // share work competing again under the growth cap (it lacks only the
    // credit of the epoch it was pruned), and a fresh grace period.
    c.handoff_to(core, 9);
    let st = c.st.poci.as_ref().unwrap();
    assert!(st.pruned.is_empty() && st.rejoins.is_empty());
    let w9 = c.config().weight(&k[0].id()).unwrap();
    let wq = c.config().weight(&quiet.id()).unwrap();
    let missed = w8 - ledger_w[&quiet.id()];
    assert_eq!(wq + missed, w9, "back under the growth cap");
    for x in 10..=12 {
        c.handoff_to(core, x);
        assert!(c.config().weight(&quiet.id()).is_some(), "grace at {x}");
    }
    c.handoff_to(core, 13);
    assert!(c.config().weight(&quiet.id()).is_none(), "silent again: pruned at 13");
    // The ledger stays bounded: included votes of PRUNE_AFTER + 3 epochs at most.
    let st = c.st.poci.as_ref().unwrap();
    assert!(st.seen.values().all(|m| m.len() <= (POCI_PRUNE_AFTER_EPOCHS + 3) as usize));
    assert!(c.st.decay.is_empty() && c.st.banned.is_empty());
}

#[test]
fn a_stall_never_changes_the_configuration_and_nobody_is_pruned() {
    let keys: Vec<Key> = (71..=75).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let mut c = Harness::new(&k);
    c.launch();
    let c4 = c.config();
    // 40 % vanish at once: three keys out of five are not a strict quorum.
    let mut slot = PP.launch_height();
    while slot < PP.opening(14) {
        slot += 5;
        c.slot(&k[..3], slot);
        assert_eq!(c.st.justified, cp(PP.opening(4)), "no quorum at {slot}");
    }
    let st = c.st.poci.as_ref().unwrap();
    assert_eq!(c.config().id(), c4.id(), "the same C, the same denominator");
    assert!(st.pruned.is_empty(), "no local pruning without a handoff");
    assert!(c.st.decay.is_empty(), "no inactivity leak on PoCI");
    // The weight returns: finality resumes under C_4 and hands off at once.
    let back = c.votes(&k[3..], slot);
    c.block(&back, &[]);
    assert_eq!(c.st.justified, cp(slot));
    c.slot(&k, slot + 5);
    assert_eq!(c.st.finalized, cp(slot));
    assert_eq!(c.config().epoch(), 14);
    // Review HIGH (§4.1): the stall lasted more than PRUNE_AFTER epochs and
    // the keys that came back have no vote in the blocks of epochs 10..=13
    // (theirs are above opening(14)). The present keys (60 %) hold no strict
    // quorum of C_4, so the handoff the returning committee authorizes
    // prunes nobody: they stay in C_14.
    let st = c.st.poci.as_ref().unwrap();
    assert!(st.pruned.is_empty());
    assert_eq!(c.config().len(), 5);
    assert_eq!(c.config().total(), c.st.cap.as_ref().unwrap().ledger.weights().values().sum::<u128>());
    // Finality goes on under C_14 with every key.
    c.handoff_to(&k, 15);
    assert_eq!(c.config().len(), 5);
}

/// Review HIGH: nobody votes for more than PRUNE_AFTER epochs (24 h on
/// mainnet), then the whole committee returns. The handoff it authorizes
/// keeps it (no key of C_4 is present in the window, so no quorum is
/// present and nobody is pruned): finality never halts for good.
#[test]
fn a_total_stall_ends_with_the_returning_committee_in_force() {
    let keys: Vec<Key> = (76..=79).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let mut c = Harness::new(&k);
    c.launch();
    c.to(PP.opening(12));
    assert_eq!((c.st.finalized, c.config().epoch()), (cp(80), 4));
    c.handoff_to(&k, 12);
    let st = c.st.poci.as_ref().unwrap();
    assert!(st.pruned.is_empty());
    assert_eq!(c.config().len(), 4);
    c.handoff_to(&k, 13);
    assert_eq!(c.config().len(), 4);
}

/// Review MEDIUM (§4): two chains share the history up to opening(9) and
/// then finalize different checkpoints of epoch 9 first; above opening(9)
/// one of them carries evidence and votes the other does not. Both hold the
/// same C_9 (with the rejoin included in epoch 8 on both), so an
/// equivocation across them names one config_id.
#[test]
fn compatible_chains_finalizing_different_checkpoints_of_an_epoch_hold_the_same_configuration() {
    let keys: Vec<Key> = (91..=95).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let (core, quiet) = (&k[..4], k[4]);
    let mut c = Harness::new(&k);
    c.launch();
    for x in 5..=8 {
        c.handoff_to(core, x);
    }
    assert!(c.st.poci.as_ref().unwrap().pruned.contains_key(&quiet.id()));
    let rj8 = quiet.rejoin(8);
    c.block_with(&[], &[rj8]);
    c.to(PP.opening(9));
    // The two chains share every block up to here (heights < opening(9)).
    let mut b = Harness { st: c.st.clone(), h: c.h, shares: c.shares.clone(), extra: c.extra.clone() };
    // Chain a: finalizes the opening of epoch 9.
    c.handoff_to(core, 9);
    assert_eq!(c.st.finalized, cp(PP.opening(9)));
    // Chain b: no quorum for opening(9); evidence against key 3 and votes
    // above it; finalizes opening(9) + 5 instead.
    let v = b.votes(&core[..2], 180);
    b.block(&v, &[]);
    let cfg8 = b.config();
    let (j, t) = (b.st.justified, cp(185));
    let mut fake = t;
    fake.hash[0] ^= 1;
    let ev = PociEvidence { config_id: cfg8.id(), a: k[3].vote(&cfg8.id(), j, t), b: k[3].vote(&cfg8.id(), j, fake) };
    b.block(&[], &[ev]);
    for slot in [185, 190] {
        b.to(slot);
        let v = b.votes(core, slot);
        b.block(&v, &[]);
    }
    assert_eq!(b.st.finalized, cp(185));
    assert_eq!(b.config().epoch(), 9);
    assert_eq!(b.st.poci.as_ref().unwrap().bans[&k[3].id()][0].start, None, "above opening(9): pending");
    assert_eq!(b.config().id(), c.config().id(), "one C_9");
    assert!(c.config().weight(&quiet.id()).is_some(), "the rejoin at or below opening(9) counts on both");
    assert_eq!(b.st.poci.as_ref().unwrap().pruned, c.st.poci.as_ref().unwrap().pruned);
}

/// §4.1 (review HIGH, the worst case): a handoff never leaves an empty
/// configuration. Every key of C_5 equivocates; the handoff to 6 bans them
/// all, so the candidates leave nothing: C_6 carries C_5's entries forward
/// and finality goes on.
#[test]
fn a_handoff_never_leaves_an_empty_configuration() {
    let keys: Vec<Key> = (101..=103).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let mut c = Harness::new(&k);
    c.launch();
    c.handoff_to(&k, 5);
    let c5 = c.config();
    let (j, t) = (c.st.justified, cp(c.st.justified.height + 10));
    let mut fake = t;
    fake.hash[0] ^= 1;
    let ev: Vec<PociEvidence> = k.iter()
        .map(|key| PociEvidence { config_id: c5.id(), a: key.vote(&c5.id(), j, t), b: key.vote(&c5.id(), j, fake) })
        .collect();
    c.to(t.height);
    c.block(&[], &ev);
    // No share work from here on (banned keys may not be paid).
    c.shares.clear();
    c.handoff_to(&k, 6);
    let st = c.st.poci.as_ref().unwrap();
    assert!(k.iter().all(|key| st.banned_at(&PP, &key.id(), 6)));
    assert_eq!(c.config().epoch(), 6);
    assert_eq!(c.config().entries(), c5.entries());
    assert_ne!(c.config().id(), c5.id());
    c.handoff_to(&k, 7);
    assert_eq!(c.config().entries(), c5.entries());
}

/// Review HIGH (§9): a fork at the epoch-4 boundary. Below launch_height no
/// state carries a finalized checkpoint above genesis on either branch, so
/// the finality pin has no candidate and work settles the fork; the branch
/// that reaches launch_height launches on its own slot 80.
#[test]
fn a_fork_at_the_launch_boundary_carries_no_finality_until_buried() {
    let keys: Vec<Key> = (111..=113).map(Key::new).collect();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    /// Block `h` of branch `br` (the branches share blocks below 78).
    fn bh(br: u8, h: u64) -> [u8; 32] {
        let mut x = hash(h);
        if h >= 78 {
            x[30] = br;
        }
        x
    }
    struct Branch(u8, u64);
    impl ChainView for Branch {
        fn selected_at(&self, slot: u64) -> Option<[u8; 32]> {
            (slot >= 1 && slot <= self.1).then(|| bh(self.0, slot - 1))
        }
    }
    let mut common = PowitState::genesis(0, hash(0));
    let sw: Vec<(KeyId, u128)> = ids.iter().map(|k| (*k, W)).collect();
    let step = |st: &PowitState, br: u8, h: u64| {
        let input = BlockInput { height: h, hash: bh(br, h), share_work: &sw, attestations: &[], evidence: &[], exits: &[] };
        st.apply_block(&P, CHAIN, 0, 0, &input, BITS, PociItems::default(), &Branch(br, h)).unwrap()
    };
    for h in 1..78 {
        common = step(&common, 0, h);
    }
    let mut tips = Vec::new();
    for br in [1u8, 2] {
        let mut st = common.clone();
        for h in 78..PP.launch_height() {
            st = step(&st, br, h);
            assert!(st.poci.is_none(), "branch {br} block {h}");
            assert_eq!(st.finalized.height, 0, "branch {br} block {h}: no pin candidate");
        }
        st = step(&st, br, PP.launch_height());
        tips.push(st);
    }
    for (br, st) in [1u8, 2].into_iter().zip(&tips) {
        assert_eq!(st.finalized, Checkpoint { height: 80, hash: bh(br, 79) }, "branch {br}");
    }
    assert_eq!(tips[0].poci_config().unwrap().id(), tips[1].poci_config().unwrap().id(),
               "same weights: the branches differ only in where slot 80 lies");
}

#[test]
fn rejoins_need_poci_and_the_membership_list() {
    let k = Key::new(81);
    let r = k.rejoin(3);
    // GnB: no rejoin.
    let st = PowitState::genesis(0, hash(0));
    let input = BlockInput { height: 1, hash: hash(1), share_work: &[], attestations: &[], evidence: &[], exits: &[] };
    assert!(st.apply_block(&TESTNET_PARAMS, ChainId::Testnet, 0, 0, &input, BITS,
                           PociItems { evidence: &[], rejoins: std::slice::from_ref(&r) }, &Chain(1))
        .unwrap_err().contains("without PoCI"));
    // ObenBlock before the launch: nothing to rejoin.
    let mut c = Harness::new(&[&k]);
    c.to(10);
    assert!(c.try_block_with(&[], &[], &[r.clone()]).unwrap_err().contains("bootstrap"));
    // Body format: exits then rejoins in one tagged list; an empty one is
    // the GnB bytes.
    let x = WitnessExit::sign(PP.chain_id, &k.0.borrow()).unwrap();
    let body = PowitBody { exits: vec![x.clone()], rejoins: vec![r.clone(), r.clone()], ..PowitBody::default() };
    let fmt = BodyFormat { exits: true, poci: true };
    let mut buf = Vec::new();
    body.write_wire_for(&mut buf, fmt);
    let mut cur = std::io::Cursor::new(buf.as_slice());
    assert_eq!(PowitBody::read_wire_for(&mut cur, fmt).unwrap(), body);
    assert_eq!(cur.position() as usize, buf.len());
    // An exit after a rejoin, an unknown tag, too many rejoins: refused.
    let swapped = {
        let mut out = Vec::new();
        let b = PowitBody { exits: vec![], rejoins: vec![r.clone()], ..PowitBody::default() };
        b.write_wire_for(&mut out, fmt);
        // Patch the count to 2 and append an exit item.
        let n = out.len() - (1 + r.to_wire_bytes().len()) - 1;
        out[n] = 2;
        out.push(0);
        out.extend_from_slice(&x.to_wire_bytes());
        out
    };
    assert!(PowitBody::read_wire_for(&mut std::io::Cursor::new(swapped.as_slice()), fmt).unwrap_err().contains("after"));
    let mut tagged = Vec::new();
    PowitBody { exits: vec![x.clone()], ..PowitBody::default() }.write_wire_for(&mut tagged, fmt);
    let tag_at = tagged.len() - x.to_wire_bytes().len() - 1;
    tagged[tag_at] = 7;
    assert!(PowitBody::read_wire_for(&mut std::io::Cursor::new(tagged.as_slice()), fmt).unwrap_err().contains("tag"));
    let five = PowitBody { rejoins: vec![r.clone(); MAX_REJOINS_PER_BLOCK + 1], ..PowitBody::default() };
    let mut out = Vec::new();
    five.write_wire_for(&mut out, fmt);
    assert!(PowitBody::read_wire_for(&mut std::io::Cursor::new(out.as_slice()), fmt).is_err());
    // The rejoin message is its own domain: not an exit.
    assert!(r.verify_signature(PP.chain_id));
    assert!(!r.verify_signature(OBB_MAINNET_POCI.chain_id));
    let as_exit = WitnessExit { witness: r.witness, epoch: r.epoch, sig: r.sig.clone() };
    assert!(!as_exit.verify_signature(PP.chain_id));
    let mut wb = Vec::new();
    PowitBody::default().write_wire_for(&mut wb, fmt);
    let mut gb = Vec::new();
    PowitBody::default().write_wire_with(&mut gb, true);
    assert_eq!(wb, gb);
}

/// The growth cap at the PoCI handoff (DESIGN-obenblock.md §6.3): a newcomer
/// whose share work dwarfs the members' gets only the budget `G` of each cap
/// step, members that keep mining renew their credits first, and every
/// configuration's weights are the ledger's credits.
#[test]
fn handoffs_run_the_growth_cap() {
    let keys: Vec<Key> = (61..=64).map(Key::new).collect();
    let k: Vec<&Key> = keys.iter().collect();
    let newcomer: KeyId = [0x77; 20];
    let mut c = Harness::new(&k);
    c.to(79);
    // From epoch 4 on, a newcomer brings 1000 times the members' work.
    c.extra.push((newcomer, 1_000 * W));
    c.launch();
    assert_eq!(c.config().epoch(), 4);
    let mut slot = 80;
    let mut seen = BTreeMap::new();
    while slot < 145 {
        slot += 5;
        c.to(slot);
        // All four members: the newcomer's capped weight is in the totals.
        let v = c.votes(&k, slot);
        c.block(&v, &[]);
        let cfg = c.config();
        if seen.insert(cfg.epoch(), cfg.id()).is_none() && cfg.epoch() > 4 {
            let cap = c.st.cap.as_ref().unwrap();
            assert_eq!(cap.ledger.epoch(), cfg.epoch());
            let r = *cap.ledger.report().unwrap();
            assert_eq!(r.epoch, cfg.epoch());
            // The configuration is the ledger's weights.
            let w: Vec<(KeyId, u128)> = cap.ledger.weights().into_iter().collect();
            assert_eq!(cfg.entries(), &w[..]);
            // The newcomer gets at most G per step, whatever its work.
            let prev = c.st.poci.as_ref().unwrap().previous().unwrap().weight(&newcomer).unwrap_or(0);
            let now = cfg.weight(&newcomer).unwrap_or(0);
            assert!(now - prev <= r.g, "epoch {}: {now} - {prev} > {}", cfg.epoch(), r.g);
            assert!(r.dropped > primitive_types::U256::zero() || now == 0);
        }
    }
    // C_5 (epoch 3 entering) has no newcomer work yet; C_6 and C_7 do.
    assert_eq!(c.config().epoch(), 7);
    let c7 = c.config();
    let nw = c7.weight(&newcomer).unwrap();
    assert!(nw > 0 && 3 * nw < c7.total(), "capped: {nw} of {}", c7.total());
    // Members keep every credit they renew.
    for key in &k {
        assert!(c7.weight(&key.id()).unwrap() >= 40);
    }
    // Skipped bits never stop the cap: every epoch's first block recorded its bits
    // (kept only from the ledger's epoch - 1).
    let cap = c.st.cap.as_ref().unwrap();
    assert!(cap.first_bits.keys().all(|e| *e + 1 >= cap.ledger.epoch()));
    assert!(cap.first_bits.values().all(|b| *b == BITS));
    // One window (§2, merge item): apply_poci keeps share work and links for
    // the PoCI window (112 + 2 epochs, part of params_digest), not the short
    // PoWit regtest window (3), so nothing of the first epochs is dropped yet.
    assert_eq!((P.window_epochs, PP.window_epochs), (3, 112));
    assert!(c.st.epoch_work.contains_key(&0));
    assert!(c.st.links.values().all(|v| v.iter().any(|(_, th, _)| *th <= 100)));
}
