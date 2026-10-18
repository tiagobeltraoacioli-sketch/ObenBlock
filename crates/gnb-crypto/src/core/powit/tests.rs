//! PoWit state machine: finality, accountable safety, witness set, decay.
//! Real hybrid keys and signatures; a simulated selected chain.

use super::*;
use crate::core::kes::KesSigner;
use crate::core::ChainId;
use std::collections::HashMap;

const CHAIN: ChainId = ChainId::Testnet;
const P: PowitParams = TESTNET_PARAMS;
const ACT: u64 = 1_000;

struct Key {
    signer: std::cell::RefCell<KesSigner>,
}

impl Key {
    /// Depth 6 = 64 epochs, enough for every test below.
    fn new(seed: u8) -> Key {
        Key { signer: std::cell::RefCell::new(KesSigner::generate(6, [seed; 32], |_| {}).unwrap()) }
    }
    fn id(&self) -> KeyId {
        self.signer.borrow().public().witness_id()
    }
    /// Sign with the leaf of the target's epoch, evolving forward as needed.
    fn attest(&self, source: Checkpoint, target: Checkpoint) -> Attestation {
        let e = P.epoch(ACT, target.height);
        let mut s = self.signer.borrow_mut();
        if e > s.epoch() {
            s.evolve_to(e).unwrap();
        }
        assert_eq!(e, s.epoch(), "tests sign epochs in order");
        Attestation::sign(CHAIN, source, target, &s).unwrap()
    }
}

/// A linear selected chain: hash(h) is deterministic per (fork, height).
struct Chain {
    fork: u8,
    tip: u64,
}

fn hash(fork: u8, h: u64) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&h.to_le_bytes());
    x[8] = fork;
    x
}

impl ChainView for Chain {
    fn selected_at(&self, height: u64) -> Option<[u8; 32]> {
        (height < self.tip).then(|| hash(self.fork, height))
    }
}

fn cp(fork: u8, h: u64) -> Checkpoint {
    Checkpoint { height: h, hash: hash(fork, h) }
}

/// Drive a chain: `shares[h]` credits work, `atts[h]` and `evid[h]` are
/// included at height h. Returns the state after `to` and every state.
struct Run {
    states: HashMap<u64, PowitState>,
}

fn run(fork: u8, to: u64,
       shares: &dyn Fn(u64) -> Vec<(KeyId, u128)>,
       atts: &dyn Fn(u64, &PowitState) -> Vec<Attestation>) -> Run {
    let mut st = PowitState::genesis(ACT, hash(fork, ACT));
    let mut states = HashMap::new();
    states.insert(ACT, st.clone());
    for h in ACT + 1..=to {
        let sw = shares(h);
        let a = atts(h, &st);
        let input = BlockInput { height: h, hash: hash(fork, h), share_work: &sw, attestations: &a, evidence: &[], exits: &[] };
        st = st.apply(&P, CHAIN, &input, &Chain { fork, tip: h }).unwrap_or_else(|e| panic!("h={h}: {e}"));
        states.insert(h, st.clone());
    }
    Run { states }
}

/// Three equal witnesses earn shares every block of the first epochs.
fn three_keys() -> Vec<Key> {
    vec![Key::new(1), Key::new(2), Key::new(3)]
}

/// Every key earns the same share work in every block: equal weights.
fn even_shares(keys: &[KeyId]) -> impl Fn(u64) -> Vec<(KeyId, u128)> + '_ {
    move |_| keys.iter().map(|k| (*k, 1_000)).collect()
}

#[test]
fn witness_set_lags_two_epochs_and_is_heaviest_first() {
    let a = [1u8; 20];
    let b = [2u8; 20];
    let mut s = PowitState::genesis(ACT, [0; 32]);
    s.epoch_work.entry(0).or_default().insert(a, 10);
    s.epoch_work.entry(1).or_default().insert(b, 50);
    assert!(s.witness_set(&P, 1).is_empty(), "nothing before epoch 2");
    assert_eq!(s.witness_set(&P, 2), vec![(a, 10)], "epoch 2 sees epoch 0 only");
    assert_eq!(s.witness_set(&P, 3), vec![(b, 50), (a, 10)], "epoch 3 sees epochs 0..=1");
    // window = 3 epochs: at epoch 5, epochs 1..=3 count, epoch 0 dropped.
    assert_eq!(s.witness_set(&P, 5), vec![(b, 50)]);
    s.banned.insert(b, 9);
    assert_eq!(s.witness_set(&P, 4), vec![(a, 10)], "barred keys never count");
}

#[test]
fn two_thirds_justify_and_a_direct_child_finalizes() {
    let keys = three_keys();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let shares = even_shares(&ids);
    // Witness set exists from epoch 2 (height ACT + 40). Checkpoints every 5.
    let c1 = ACT + 45;
    let c2 = ACT + 50;
    let r = run(0, ACT + 60, &shares, &|h, st| {
        let src = st.justified;
        let target = if h == c1 + 1 { Some(c1) } else if h == c2 + 1 { Some(c2) } else { None };
        // Two of three witnesses vote: exactly 2/3 of equal weights.
        target.map(|t| keys[..2].iter().map(|k| k.attest(src, cp(0, t))).collect()).unwrap_or_default()
    });
    let s1 = &r.states[&(c1 + 1)];
    assert_eq!(s1.justified, cp(0, c1), "2/3 justify the first checkpoint");
    assert_eq!(s1.finalized, cp(0, ACT), "genesis checkpoint still the final one (gap > interval)");
    let s2 = &r.states[&(c2 + 1)];
    assert_eq!(s2.justified, cp(0, c2));
    assert_eq!(s2.finalized, cp(0, c1), "justifying the direct child finalizes its source");
}

#[test]
fn one_third_is_not_enough() {
    let keys = three_keys();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let shares = even_shares(&ids);
    let c1 = ACT + 45;
    let r = run(0, ACT + 50, &shares, &|h, st| {
        if h == c1 + 1 { vec![keys[0].attest(st.justified, cp(0, c1))] } else { vec![] }
    });
    assert_eq!(r.states[&(ACT + 50)].justified, cp(0, ACT));
}

fn apply_one(st: &PowitState, h: u64, atts: &[Attestation], ev: &[Equivocation]) -> Result<PowitState, String> {
    let input = BlockInput { height: h, hash: hash(0, h), share_work: &[], attestations: atts, evidence: ev, exits: &[] };
    st.apply(&P, CHAIN, &input, &Chain { fork: 0, tip: h })
}

fn warmed() -> (Vec<Key>, PowitState) {
    let keys = three_keys();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let shares = even_shares(&ids);
    let r = run(0, ACT + 45, &shares, &|_, _| vec![]);
    let st = r.states[&(ACT + 45)].clone();
    (keys, st)
}

#[test]
fn attestation_rules_reject_bad_links() {
    let (keys, st) = warmed();
    let h = ACT + 46;
    let src = st.justified;
    // Not a checkpoint height.
    assert!(apply_one(&st, h, &[keys[0].attest(src, cp(0, ACT + 44))], &[]).is_err());
    // Target not on this chain.
    assert!(apply_one(&st, h, &[keys[0].attest(src, cp(9, ACT + 45))], &[]).is_err());
    // Wrong source.
    assert!(apply_one(&st, h, &[keys[0].attest(cp(0, ACT + 40), cp(0, ACT + 45))], &[]).is_err());
    // Not a witness.
    let outsider = Key::new(77);
    assert!(apply_one(&st, h, &[outsider.attest(src, cp(0, ACT + 45))], &[]).is_err());
    // Same vote twice in one block.
    let v = keys[0].attest(src, cp(0, ACT + 45));
    assert!(apply_one(&st, h, &[v.clone(), v.clone()], &[]).is_err());
    // Tampered signature.
    let mut bad = keys[0].attest(src, cp(0, ACT + 45));
    bad.target = cp(0, ACT + 40);
    assert!(apply_one(&st, h, &[bad], &[]).is_err());
    // Expired.
    let far = ACT + 45 + P.vote_ttl + 1;
    assert!(apply_one(&st, far, &[keys[0].attest(src, cp(0, ACT + 45))], &[]).is_err());
    // A good one passes.
    assert!(apply_one(&st, h, &[v], &[]).is_ok());
}

#[test]
fn equivocations_are_proven_and_bar_the_key() {
    let (keys, st) = warmed();
    let src = st.justified;
    let k = &keys[0];
    // Double vote: same target height, different hash (different fork).
    let double = Equivocation { a: k.attest(src, cp(0, ACT + 45)), b: k.attest(src, cp(5, ACT + 45)) };
    assert_eq!(double.verify(CHAIN, &P, ACT), Ok(k.id()));
    // Surround vote.
    let surround = Equivocation {
        a: k.attest(cp(0, ACT), cp(0, ACT + 50)),
        b: k.attest(cp(0, ACT + 40), cp(0, ACT + 45)),
    };
    assert_eq!(surround.verify(CHAIN, &P, ACT), Ok(k.id()));
    // Not conflicting: consecutive links.
    let fine = Equivocation {
        a: k.attest(cp(0, ACT), cp(0, ACT + 45)),
        b: k.attest(cp(0, ACT + 45), cp(0, ACT + 50)),
    };
    assert!(fine.verify(CHAIN, &P, ACT).is_err());
    // Different keys are not an equivocation.
    let two = Equivocation { a: k.attest(src, cp(0, ACT + 45)), b: keys[1].attest(src, cp(5, ACT + 45)) };
    assert!(two.verify(CHAIN, &P, ACT).is_err());

    let barred = apply_one(&st, ACT + 46, &[], &[double.clone()]).unwrap();
    let e = P.epoch(ACT, ACT + 46);
    assert!(barred.is_banned(&k.id(), e));
    assert!(barred.witness_set(&P, e).iter().all(|(m, _)| *m != k.id()), "barred key leaves the witness set");
    // It can no longer attest, and the same proof cannot be used twice.
    assert!(apply_one(&barred, ACT + 47, &[k.attest(src, cp(0, ACT + 45))], &[]).is_err());
    assert!(apply_one(&barred, ACT + 47, &[], &[double]).is_err());
    // Shares paying it are invalid while barred.
    let input = BlockInput { height: ACT + 47, hash: hash(0, ACT + 47), share_work: &[(k.id(), 5)],
                             attestations: &[], evidence: &[], exits: &[] };
    assert!(barred.apply(&P, CHAIN, &input, &Chain { fork: 0, tip: ACT + 47 }).is_err());
}

#[test]
fn a_key_cannot_contradict_its_own_on_chain_vote() {
    let (keys, st) = warmed();
    let src = st.justified;
    let s1 = apply_one(&st, ACT + 46, &[keys[0].attest(src, cp(0, ACT + 45))], &[]).unwrap();
    // A surrounding link from the same key later on this chain is refused.
    let s2 = apply_one(&s1, ACT + 47, &[keys[1].attest(src, cp(0, ACT + 45))], &[]).unwrap();
    assert_eq!(s2.justified, cp(0, ACT + 45), "keys 0+1 justify");
    // Key 0 now tries a link that surrounds its earlier (ACT -> ACT+45) vote:
    // source below ACT is impossible, so test the double-vote path instead:
    // a second vote for height ACT+45 is a duplicate and refused.
    assert!(apply_one(&s2, ACT + 48, &[keys[0].attest(s2.justified, cp(0, ACT + 45))], &[]).is_err());
}

#[test]
fn inactivity_decays_absent_witnesses_until_finality_resumes() {
    let keys = three_keys();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    // Shares keep flowing (weights exist) but nobody attests: no finality.
    let shares = even_shares(&ids);
    let stall_end = ACT + (P.leak_after_epochs + 3) * P.epoch_len;
    let r = run(0, stall_end, &shares, &|_, _| vec![]);
    let st = &r.states[&stall_end];
    assert!(ids.iter().all(|k| st.decay.get(k).copied().unwrap_or(0) > 0), "every absent witness decays");
    // Decay only reduces weight.
    let e = st.epoch;
    let w_now: u128 = st.witness_set(&P, e).iter().map(|(_, w)| *w).sum();
    let mut undecayed = st.clone();
    undecayed.decay.clear();
    let w_full: u128 = undecayed.witness_set(&P, e).iter().map(|(_, w)| *w).sum();
    assert!(w_now < w_full);
}

#[test]
fn active_witnesses_regain_two_thirds_after_one_third_goes_silent() {
    // Four keys with equal share work. Two stop attesting (> 1/3 offline),
    // the other two keep voting; decay must eventually let them finalize.
    let keys: Vec<Key> = (1..=4).map(Key::new).collect();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let shares = even_shares(&ids);
    let to = ACT + 40 * P.epoch_len;
    let r = run(0, to, &shares, &|h, st| {
        // Each checkpoint, the two live keys vote for the newest checkpoint
        // above the justified one (one block after it).
        let t = h - 1;
        if h > ACT + 40 && P.is_checkpoint(ACT, t) && t > st.justified.height
            && h <= t + P.vote_ttl
        {
            keys[..2].iter().map(|k| k.attest(st.justified, cp(0, t))).collect()
        } else {
            vec![]
        }
    });
    let st = &r.states[&to];
    assert!(st.finalized.height > ACT, "finality resumed through inactivity decay: {:?}", st.finalized);
}

#[test]
fn wire_roundtrip() {
    let k = Key::new(9);
    let a = k.attest(cp(0, ACT), cp(0, ACT + 5));
    let body = PowitBody {
        shares: vec![WitnessShare { attested: [3; 32], witness: [5; 20], payout: vec![7; 20], bits: 0x1f00_ffff, nonce: 42, sha256d: None }],
        attestations: vec![a.clone()],
        evidence: vec![Equivocation { a: a.clone(), b: k.attest(cp(0, ACT), cp(1, ACT + 5)) }],
        exits: Vec::new(), poci_evidence: Vec::new(),
    };
    let mut buf = Vec::new();
    body.write_wire(&mut buf);
    let mut cur = std::io::Cursor::new(buf.as_slice());
    assert_eq!(PowitBody::read_wire(&mut cur).unwrap(), body);
    assert_eq!(cur.position() as usize, buf.len());
    // Truncation is an error, never a panic.
    for cut in [1, 10, buf.len() / 2, buf.len() - 1] {
        let mut c = std::io::Cursor::new(&buf[..cut]);
        assert!(PowitBody::read_wire(&mut c).is_err());
    }
    // Over-long counts are refused before allocating.
    let mut huge = Vec::new();
    crate::core::write_varint(&mut huge, 1_000_000);
    assert!(PowitBody::read_wire(&mut std::io::Cursor::new(huge.as_slice())).is_err());
}

#[test]
fn a_leaf_from_another_epoch_is_refused() {
    let (keys, st) = warmed();
    let src = st.justified;
    // Key 0 signs slot ACT+45 (epoch 2) with the epoch-3 leaf: forge by
    // evolving first, then sign the epoch-2 message.
    let k = Key::new(1);
    {
        let mut s = k.signer.borrow_mut();
        s.evolve_to(3).unwrap();
    }
    let target = cp(0, ACT + 45);
    let wrong = Attestation::sign(CHAIN, src, target, &k.signer.borrow()).unwrap();
    assert_eq!(wrong.sig.index, 3);
    assert!(!wrong.verify_signature(CHAIN, &P, ACT), "epoch-3 leaf cannot sign an epoch-2 target");
    assert!(apply_one(&st, ACT + 46, &[wrong], &[]).is_err());
    // And once a signer has moved past epoch 2, it cannot produce one at all.
    assert!(k.signer.borrow_mut().evolve_to(2).is_err());
    let _ = keys;
}

/// ObenBlock's long window (docs/DESIGN-obenblock.md §6.2) on the short test
/// clock: work credited in epoch 0 is weight in W(2) ..= W(113), 112 epochs,
/// and leaves at W(114); the state prunes it one epoch later (it keeps
/// `window + 2` epochs).
#[test]
fn obenblock_window_keeps_work_for_112_epochs() {
    let p = obenblock_window(P);
    assert_eq!((p.window_epochs, p.ban_epochs, p.epoch_len), (OBB_WINDOW_EPOCHS, OBB_WINDOW_EPOCHS, P.epoch_len));
    assert_eq!(obenblock_window(MAINNET_PARAMS).window_epochs * MAINNET_PARAMS.epoch_len * 30, 28 * 24 * 3_600,
               "112 six-hour epochs are 28 days");
    let k: KeyId = [0x11; 20];
    let mut st = PowitState::genesis(ACT, hash(0, ACT));
    let last = ACT + (OBB_WINDOW_EPOCHS + 3) * p.epoch_len;
    for h in ACT + 1..=last {
        let sw = if h == ACT + 1 { vec![(k, 1_000u128)] } else { vec![] };
        let input = BlockInput { height: h, hash: hash(0, h), share_work: &sw, attestations: &[], evidence: &[], exits: &[] };
        st = st.apply_at(&p, CHAIN, 0, &input, &Chain { fork: 0, tip: h }).unwrap_or_else(|e| panic!("h={h}: {e}"));
        let e = p.epoch(ACT, h);
        let w = st.member_weight_h2(&p, e, &k);
        let counts = (2..=OBB_WINDOW_EPOCHS + 1).contains(&e);
        // No attestations: finality stalls and the decay starts after
        // `leak_after_epochs`, so only presence is checked here.
        assert_eq!(w.is_some(), counts, "h={h} e={e} w={w:?}");
        assert_eq!(st.epoch_work.contains_key(&0), e <= OBB_WINDOW_EPOCHS + 2, "h={h} e={e}");
        // GnB's window would have dropped it after 3 epochs.
        if e == P.window_epochs + 2 {
            assert!(st.member_weight_h2(&P, e, &k).is_none());
        }
    }
}
