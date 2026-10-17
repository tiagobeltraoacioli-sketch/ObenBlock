//! PoWit at the second hardening activation (Phase-5 audit of the PoWit
//! line, findings 1 and 4): what the state machine did before, pinned, and
//! what it does from the activation.
//!
//! Real hybrid KES keys and signatures throughout; a simulated selected chain.

use super::*;
use crate::core::kes::{KesPublic, KesSigner};
use crate::core::ChainId;
use std::cell::RefCell;

const CHAIN: ChainId = ChainId::Testnet;
const P: PowitParams = TESTNET_PARAMS;
const ACT: u64 = 1_000;

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hash(fork: u8, h: u64) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&h.to_le_bytes());
    x[8] = fork;
    x
}

/// A linear selected chain: `hash(fork, h)` below `tip`.
struct Chain {
    fork: u8,
    tip: u64,
}

impl ChainView for Chain {
    fn selected_at(&self, height: u64) -> Option<[u8; 32]> {
        (height < self.tip).then(|| hash(self.fork, height))
    }
}

fn cp(fork: u8, h: u64) -> Checkpoint {
    Checkpoint { height: h, hash: hash(fork, h) }
}

/// A genuine KES witness key (every leaf derived, as `gnb-cli witnesskeygen`).
struct Key {
    signer: RefCell<KesSigner>,
}

impl Key {
    fn new(seed: u8, depth: u8) -> Key {
        Key { signer: RefCell::new(KesSigner::generate(depth, [seed; 32], |_| {}).unwrap()) }
    }
    fn id(&self) -> KeyId {
        self.signer.borrow().public().witness_id()
    }
    /// Sign with the leaf of the target's epoch (evolving forward).
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

/// Finding 1's forgery: the signed message does not depend on the witness
/// key and `kes::verify` only checks that the leaf plus the supplied path
/// reach the root, so a leaf signature re-rooted under any sibling hash is a
/// signature by another depth-1 key (one SHA3 per key).
fn reroot(a: &Attestation, sibling: [u8; 32]) -> Attestation {
    let mut a = a.clone();
    let leaf = sha3(&[b"GNB-KES-v1/pk", &a.sig.leaf_pk]);
    a.sig.path = vec![sibling];
    let root = if a.sig.index & 1 == 0 {
        sha3(&[b"GNB-KES-v1/node", &leaf, &sibling])
    } else {
        sha3(&[b"GNB-KES-v1/node", &sibling, &leaf])
    };
    a.witness = KesPublic { depth: 1, root };
    a
}

/// One depth-1 leaf's double vote (epoch 1, slot ACT + 35), re-rooted per
/// sibling into as many distinct witnesses as wanted.
struct Forger {
    a: Attestation,
    b: Attestation,
}

impl Forger {
    fn new(seed: u8) -> Forger {
        let mut s = KesSigner::generate(1, [seed; 32], |_| {}).unwrap();
        s.evolve_to(1).unwrap();
        let src = cp(0, ACT);
        let a = Attestation::sign(CHAIN, src, cp(0, ACT + 35), &s).unwrap();
        let b = Attestation::sign(CHAIN, src, cp(9, ACT + 35), &s).unwrap();
        Forger { a, b }
    }
    fn sibling(i: u64) -> [u8; 32] {
        sha3(&[b"sibling", &i.to_le_bytes()])
    }
    fn equivocation(&self, i: u64) -> Equivocation {
        let s = Self::sibling(i);
        Equivocation { a: reroot(&self.a, s), b: reroot(&self.b, s) }
    }
}

/// Digest of a state: SHA3 of its bincode encoding (the node stores states
/// with this encoding, `node/src/powit.rs`); every map is ordered.
fn state_digest(st: &PowitState) -> [u8; 32] {
    let bytes = bincode::serde::encode_to_vec(st, bincode::config::standard()).unwrap();
    sha3(&[&bytes])
}

// ── The pinned scenario ──────────────────────────────────────────────────────

/// Filler share keys: 70 ids of weight 100 per block, so the 64-member cap
/// cuts 9 of them off and the two-thirds rule depends on it.
fn fillers() -> Vec<KeyId> {
    (0..70u8).map(|i| [0x80 ^ i; 20]).collect()
}

/// What a block carries in [`scenario`].
type Step<'a> = (Vec<(KeyId, u128)>, Vec<Attestation>, Vec<Equivocation>);

/// A run through everything the PoWit transition does: shares from three
/// genuine witnesses (4,300 per block each) and 70 fillers (100 each),
/// justification and finality (c1 = ACT+45, c2 = ACT+50, c3 = ACT+55), a
/// genuine double vote that bars key 2, a forged (re-rooted) equivocation, a
/// stall long enough for inactivity decay, and votes resuming. `apply` is
/// the transition under test. Returns every state, `ACT+1..=ACT+180`.
fn scenario(apply: &dyn Fn(&PowitState, &BlockInput<'_>, &Chain) -> Result<PowitState, String>)
    -> Vec<PowitState>
{
    let keys: Vec<Key> = (1..=3).map(|s| Key::new(s, 4)).collect();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let fill = fillers();
    let forger = Forger::new(40);
    let mut st = PowitState::genesis(ACT, hash(0, ACT));
    let mut out = Vec::new();
    let (c1, c2, c3) = (ACT + 45, ACT + 50, ACT + 55);
    for h in ACT + 1..=ACT + 180 {
        let e = P.epoch(ACT, h);
        let mut shares: Vec<(KeyId, u128)> = Vec::new();
        for (i, k) in ids.iter().enumerate() {
            if !(i == 2 && (st.is_banned(k, e) || (ACT + 57..ACT + 60).contains(&h))) {
                shares.push((*k, 4_300));
            }
        }
        shares.extend(fill.iter().map(|k| (*k, 100)));
        let src = st.justified;
        let step: Step = match h {
            _ if h == c1 + 1 || h == c2 + 1 || h == c3 + 1 => {
                let t = h - 1;
                (shares, keys.iter().map(|k| k.attest(src, cp(0, t))).collect(), vec![])
            }
            // Key 2 signs a second target for c3 (a double vote): proven.
            _ if h == c3 + 2 => {
                let other = keys[2].attest(cp(0, c2), cp(7, c3));
                let first = keys[2].attest(cp(0, c2), cp(0, c3));
                (shares, vec![], vec![Equivocation { a: first, b: other }])
            }
            // A forged proof against a key nobody holds work for.
            _ if h == c3 + 3 => (shares, vec![], vec![forger.equivocation(1)]),
            // Votes resume after the stall: every unbarred genuine key.
            _ if h >= ACT + 166 && P.is_checkpoint(ACT, h - 1) && h - 1 > st.justified.height => {
                let t = h - 1;
                let voters = keys.iter().zip(&ids).filter(|(_, id)| !st.is_banned(id, e));
                (shares, voters.map(|(k, _)| k.attest(src, cp(0, t))).collect(), vec![])
            }
            _ => (shares, vec![], vec![]),
        };
        let (sw, atts, ev) = step;
        let input = BlockInput { height: h, hash: hash(0, h), share_work: &sw, attestations: &atts, evidence: &ev };
        st = apply(&st, &input, &Chain { fork: 0, tip: h }).unwrap_or_else(|err| panic!("h={h}: {err}"));
        out.push(st.clone());
    }
    out
}

/// The digest over every state of [`scenario`] under the transition as it was
/// before the second hardening activation existed (computed on 71c2262).
const OLD_REGIME_DIGEST: &str = "32fa7a109f4e418344b0606f7120b827754dbd0348b623f07cb6b6d4845b28aa";

fn chain_digest(states: &[PowitState]) -> String {
    let mut h = Sha3_256::new();
    for s in states {
        h.update(state_digest(s));
    }
    hex::encode(h.finalize())
}

/// Below the second hardening activation the PoWit transition is
/// bit-identical to the one that produced the existing chain: the scenario's
/// states hash to the digest pinned from the code before the change.
#[test]
fn old_regime_transition_is_pinned() {
    let states = scenario(&|s, b, v| s.apply(&P, CHAIN, b, v));
    // The scenario does what it says.
    let at = |h: u64| &states[(h - ACT - 1) as usize];
    assert_eq!(at(ACT + 46).justified, cp(0, ACT + 45));
    assert_eq!(at(ACT + 51).finalized, cp(0, ACT + 45));
    assert_eq!(at(ACT + 56).finalized, cp(0, ACT + 50));
    assert_eq!(at(ACT + 57).banned.len(), 1, "key 2's double vote bars it");
    assert_eq!(at(ACT + 58).banned.len(), 2, "the forged proof bars a key nobody holds");
    assert!(!at(ACT + 160).decay.is_empty(), "the stall decays absent members");
    assert_eq!(chain_digest(&states), OLD_REGIME_DIGEST);
}

// ── Helpers for the hardening-2 tests ────────────────────────────────────────

use crate::core::activation::{scoped_override_v2, NEVER};

fn merkle(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| sha3(&[b"GNB-KES-v1/node", &c[0], &c[1]])).collect();
    }
    level[0]
}

fn kes_secret(depth: u8, epoch: u64, seed: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![depth];
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(seed);
    v
}

/// Many KES keys at one cost: the leaf of epoch `epoch` is genuine and
/// shared (seed `seed`), every other leaf an arbitrary hash, so each key has
/// its own root and witness id. A valid KES key (verification sees only the
/// leaf key, its path and the root): one leaf keygen for any number of keys,
/// one hybrid signature per attestation.
struct Sparse {
    depth: u8,
    epoch: u64,
    seed: [u8; 32],
    leaf: [u8; 32],
}

impl Sparse {
    fn new(seed: [u8; 32], depth: u8, epoch: u64) -> Sparse {
        let dummy: Vec<[u8; 32]> = (0..1u64 << depth).map(|i| sha3(&[b"dummy", &i.to_le_bytes()])).collect();
        let root = merkle(&dummy);
        let probe = KesSigner::from_parts(&kes_secret(depth, epoch, &seed), dummy, &KesPublic { depth, root }).unwrap();
        let pk = probe.sign(b"probe").unwrap().leaf_pk;
        Sparse { depth, epoch, seed, leaf: sha3(&[b"GNB-KES-v1/pk", &pk]) }
    }
    fn signer(&self, i: u64) -> KesSigner {
        let leaves: Vec<[u8; 32]> = (0..1u64 << self.depth)
            .map(|j| if j == self.epoch { self.leaf } else { sha3(&[b"sparse", &i.to_le_bytes(), &j.to_le_bytes()]) })
            .collect();
        let root = merkle(&leaves);
        KesSigner::from_parts(&kes_secret(self.depth, self.epoch, &self.seed), leaves,
                              &KesPublic { depth: self.depth, root }).unwrap()
    }
}

/// Sign `link(i)` with every signer, four threads, each under the calling
/// thread's second-hardening height `h2` (the override is per thread).
fn sign_all(signers: &[KesSigner], h2: u64, link: &(dyn Fn(usize) -> (Checkpoint, Checkpoint) + Sync))
    -> Vec<Attestation>
{
    let chunk = signers.len().div_ceil(4).max(1);
    std::thread::scope(|sc| {
        let hs: Vec<_> = signers.chunks(chunk).enumerate().map(|(c, part)| {
            sc.spawn(move || {
                let _g = scoped_override_v2(h2);
                part.iter().enumerate().map(|(j, s)| {
                    let (src, tgt) = link(c * chunk + j);
                    Attestation::sign(CHAIN, src, tgt, s).unwrap()
                }).collect::<Vec<_>>()
            })
        }).collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    })
}

/// A state at height `h` (its epoch) whose epoch-`e` share work is `work[e]`.
fn state_at(h: u64, work: &[(u64, KeyId, u128)]) -> PowitState {
    let mut st = PowitState::genesis(ACT, hash(0, ACT));
    st.epoch = P.epoch(ACT, h);
    for (e, k, w) in work {
        *st.epoch_work.entry(*e).or_default().entry(*k).or_insert(0) += *w;
    }
    st
}

fn block(st: &PowitState, h: u64, atts: &[Attestation], ev: &[Equivocation]) -> Result<PowitState, String> {
    let input = BlockInput { height: h, hash: hash(0, h), share_work: &[], attestations: atts, evidence: ev };
    st.apply(&P, CHAIN, &input, &Chain { fork: 0, tip: h })
}

// ═════════════════════════════════════════════════════════════════════════════
// Finding 1: one leaf, unlimited keys
// ═════════════════════════════════════════════════════════════════════════════

/// Before hardening 2 a leaf signature re-rooted under any sibling hash is a
/// valid signature by another key (the message does not commit the key).
/// From hardening 2 (target height >= the activation) the message commits the
/// witness key (depth, root): the genuine key's signature verifies, no
/// re-rooted one does.
#[test]
fn a_leaf_signature_is_valid_for_exactly_one_key_from_hardening2() {
    {
        let _g = scoped_override_v2(NEVER);
        let f = Forger::new(41);
        for i in 0..3 {
            assert!(reroot(&f.a, Forger::sibling(i)).verify_signature(CHAIN, &P, ACT), "old regime: forgery {i}");
        }
    }
    let _g = scoped_override_v2(0);
    let f = Forger::new(42);
    assert!(f.a.verify_signature(CHAIN, &P, ACT), "the genuine key's own signature");
    for i in 0..3 {
        assert!(!reroot(&f.a, Forger::sibling(i)).verify_signature(CHAIN, &P, ACT),
            "a re-rooted signature is not a signature by another key ({i})");
    }
    assert!(Equivocation { a: reroot(&f.a, Forger::sibling(7)), b: reroot(&f.b, Forger::sibling(7)) }
        .verify(CHAIN, &P, ACT).is_err());
}

/// Three members with share work in every epoch, at height `h`.
fn members_state(ids: &[KeyId], h: u64) -> PowitState {
    let e = P.epoch(ACT, h);
    let work: Vec<(u64, KeyId, u128)> = (0..=e).flat_map(|x| ids.iter().map(move |k| (x, *k, 1_000))).collect();
    state_at(h, &work)
}

/// Finding 1, consensus side: blocks full of forged proofs (four per block,
/// one SHA3 each) bar a fresh key per proof, so `banned` (stored in every
/// block's PoWit state) grows by four entries per block forever, and the
/// keys barred are keys nobody holds. From hardening 2 a block may carry a
/// proof only against a member of a witness set of the evidence epochs, so
/// every such block is invalid: links signed before the activation (still
/// re-rootable) fail the membership, links from it fail the signature.
#[test]
fn forged_equivocations_cannot_bar_keys_from_hardening2() {
    let ids: Vec<KeyId> = (1..=3u8).map(|s| sha3(&[b"member", &[s]])[..20].try_into().unwrap()).collect();
    let h0 = ACT + 45;
    let run = |forger: &Forger, h2: u64| -> (usize, Vec<Result<(), String>>) {
        let _g = scoped_override_v2(h2);
        let mut st = members_state(&ids, h0);
        let mut verdicts = Vec::new();
        for b in 0..5u64 {
            let ev: Vec<Equivocation> = (0..4).map(|i| forger.equivocation(100 * b + i)).collect();
            match block(&st, h0 + 1 + b, &[], &ev) {
                Ok(next) => {
                    st = next;
                    verdicts.push(Ok(()));
                }
                Err(e) => verdicts.push(Err(e)),
            }
        }
        (st.banned.len(), verdicts)
    };
    let old = {
        let _g = scoped_override_v2(NEVER);
        Forger::new(43)
    };
    let (banned, verdicts) = run(&old, NEVER);
    assert_eq!(banned, 20, "old regime: four keys nobody holds barred per block");
    assert!(verdicts.iter().all(Result::is_ok));

    // Links signed before the activation (v1 message, re-rootable), blocks after it.
    let (banned, verdicts) = run(&old, ACT + 40);
    assert_eq!(banned, 0, "{verdicts:?}");
    assert!(verdicts.iter().all(|v| v.as_ref().is_err_and(|e| e.contains("not a member"))), "{verdicts:?}");

    // Links signed from the activation: the re-rooted signatures are invalid.
    let new = {
        let _g = scoped_override_v2(0);
        Forger::new(44)
    };
    let (banned, verdicts) = run(&new, 0);
    assert_eq!(banned, 0, "{verdicts:?}");
    assert!(verdicts.iter().all(Result::is_err), "{verdicts:?}");
}

/// The evidence epoch rule. A block of PoWit epoch E may carry a proof
/// against key k only if k is a member of W(E-1), W(E) or W(E+1) (the
/// witness sets the block's state can compute): the sets of every vote this
/// chain can still include, and of the next epoch. Members of W(E), W(E-1)
/// and W(E+1) are provable, also for links of an older epoch; a key with no
/// work in those windows, or none at all, is not.
#[test]
fn evidence_is_valid_only_against_a_member_of_the_evidence_epochs() {
    // Testnet: window 3, W(e) counts epochs e-4..=e-2; E = 6 (heights 1120..1139).
    let h = ACT + 126;
    let sp = Sparse::new([0x33; 32], 3, 6);
    let old_sp = Sparse::new([0x34; 32], 3, 2);
    let keys: Vec<KesSigner> = (0..5).map(|i| sp.signer(i)).collect();
    let id = |s: &KesSigner| s.public().witness_id();
    // 0: work in every epoch (W(5), W(6), W(7)); 1: only epoch 1 (W(5) = E-1);
    // 2: only epoch 5 (W(7) = E+1); 3: only epoch 6 (W(8): outside); 4: none.
    let mut work: Vec<(u64, KeyId, u128)> = (0..=6).map(|e| (e, id(&keys[0]), 1_000)).collect();
    work.push((1, id(&keys[1]), 1_000));
    work.push((5, id(&keys[2]), 1_000));
    work.push((6, id(&keys[3]), 1_000));
    // A member whose double vote is for an old epoch (2): still provable.
    let old_key = old_sp.signer(9);
    work.extend((0..=6).map(|e| (e, id(&old_key), 1_000)));
    let st = state_at(h, &work);
    let double = |s: &KesSigner, h2: u64, slot: u64| {
        let _g = scoped_override_v2(h2);
        let src = cp(0, ACT);
        Equivocation {
            a: Attestation::sign(CHAIN, src, cp(0, slot), s).unwrap(),
            b: Attestation::sign(CHAIN, src, cp(5, slot), s).unwrap(),
        }
    };
    for (h2, label) in [(NEVER, "old regime"), (0, "hardening 2")] {
        let _g = scoped_override_v2(h2);
        let verdict = |ev: Equivocation| block(&st, h, &[], &[ev]).map(|s| s.banned.len());
        assert_eq!(verdict(double(&keys[0], h2, ACT + 125)), Ok(1), "{label}: member of W(E)");
        assert_eq!(verdict(double(&keys[1], h2, ACT + 125)), Ok(1), "{label}: member of W(E-1)");
        assert_eq!(verdict(double(&keys[2], h2, ACT + 125)), Ok(1), "{label}: member of W(E+1)");
        assert_eq!(verdict(double(&old_key, h2, ACT + 45)), Ok(1), "{label}: a member's old double vote");
        let outside = [verdict(double(&keys[3], h2, ACT + 125)), verdict(double(&keys[4], h2, ACT + 125))];
        if h2 == NEVER {
            assert_eq!(outside, [Ok(1), Ok(1)], "old regime: any key");
        } else {
            for v in outside {
                assert!(v.as_ref().is_err_and(|e| e.contains("not a member")), "{label}: {v:?}");
            }
        }
    }
}

/// Barring is one `banned` entry per key with its expiry epoch, removed at
/// expiry; from hardening 2 their number is bounded by the keys with share
/// work in the evidence epochs (and by the four proofs a block may carry).
#[test]
fn a_ban_is_one_entry_per_key_until_its_expiry() {
    let _g = scoped_override_v2(0);
    let sp = Sparse::new([0x35; 32], 3, 2);
    let k = sp.signer(1);
    let id = k.public().witness_id();
    let h = ACT + 46;
    let st = state_at(h, &[(0, id, 1_000), (1, id, 1_000), (2, id, 1_000)]);
    let src = cp(0, ACT);
    let ev = Equivocation {
        a: Attestation::sign(CHAIN, src, cp(0, ACT + 45), &k).unwrap(),
        b: Attestation::sign(CHAIN, src, cp(5, ACT + 45), &k).unwrap(),
    };
    let barred = block(&st, h, &[], std::slice::from_ref(&ev)).unwrap();
    assert_eq!(barred.banned.len(), 1);
    assert_eq!(barred.banned.get(&id), Some(&(P.epoch(ACT, h) + P.ban_epochs)));
    assert!(block(&barred, h + 1, &[], &[ev]).is_err(), "the same key cannot be barred twice");
    // At the expiry epoch the entry goes.
    let mut s = barred;
    let expiry_h = ACT + (P.epoch(ACT, h) + P.ban_epochs) * P.epoch_len;
    for hh in h + 1..=expiry_h {
        s = block(&s, hh, &[], &[]).unwrap();
    }
    assert!(s.banned.is_empty(), "{:?}", s.banned);
}

// ═════════════════════════════════════════════════════════════════════════════
// Finding 4: a minority split over many keys
// ═════════════════════════════════════════════════════════════════════════════

/// The finding's numbers: 200 honest keys of 0.35% of the share work each
/// (70%) and an attacker with 30% split over 60 keys of 0.5%. Before
/// hardening 2, W = the 64 heaviest = the attacker's 60 keys and 4 honest
/// ones: the attacker justifies alone, and honest keys outside W cannot vote
/// at all (finality stalls without the attacker). From hardening 2 the
/// threshold is two thirds of the total window weight of every share key
/// and every weighted key may vote: the attacker cannot justify alone, and
/// the honest keys justify and finalize without it. The per-block bound on
/// signature checks is unchanged (at most 32 attestations per block).
#[test]
fn finding4_a_split_minority_neither_justifies_alone_nor_stalls_from_hardening2() {
    let honest_sp = Sparse::new([0x41; 32], 2, 2);
    let attacker_sp = Sparse::new([0x42; 32], 2, 2);
    let honest: Vec<KesSigner> = (0..200).map(|i| honest_sp.signer(i)).collect();
    let attacker: Vec<KesSigner> = (0..60).map(|i| attacker_sp.signer(1_000 + i)).collect();
    // W(2) counts epoch 0 only.
    let mut work: Vec<(u64, KeyId, u128)> = honest.iter().map(|s| (0, s.public().witness_id(), 35)).collect();
    work.extend(attacker.iter().map(|s| (0, s.public().witness_id(), 50)));
    let c1 = cp(0, ACT + 45);
    let c2 = cp(0, ACT + 50);
    let g = cp(0, ACT);
    let start = ACT + 46;

    // Include `atts`, 32 per block from height `from`, until the justified
    // checkpoint moves (the rest no longer link from it): the state after
    // the last block and the next height.
    let include = |st: &PowitState, from: u64, atts: &[Attestation]| -> Result<(PowitState, u64), String> {
        let mut s = st.clone();
        let mut h = from;
        let j0 = s.justified;
        for chunk in atts.chunks(P.max_attestations_per_block) {
            if s.justified != j0 {
                break;
            }
            s = block(&s, h, chunk, &[])?;
            h += 1;
        }
        Ok((s, h))
    };

    // ── Old regime ──
    {
        let _g = scoped_override_v2(NEVER);
        let st = state_at(start, &work);
        let w = st.witness_set(&P, 2);
        assert_eq!(w.len(), 64);
        let attacker_weight: u128 = w.iter().filter(|(_, x)| *x == 50).map(|(_, x)| *x).sum();
        assert_eq!(attacker_weight, 3_000, "the attacker's 60 keys are all in W");
        let atts = sign_all(&attacker, NEVER, &|_| (g, c1));
        let (s, _) = include(&st, start, &atts).unwrap();
        assert_eq!(s.justified, c1, "old regime: 30% of the share work justifies alone");
        let honest_atts = sign_all(&honest[..40], NEVER, &|_| (g, c1));
        let err = include(&st, start, &honest_atts).unwrap_err();
        assert!(err.contains("not in the witness set"), "old regime: honest keys outside W cannot vote: {err}");
    }

    // ── From hardening 2 ──
    let _g = scoped_override_v2(0);
    let st = state_at(start, &work);
    let atts = sign_all(&attacker, 0, &|_| (g, c1));
    let (s, _) = include(&st, start, &atts).unwrap();
    assert_eq!(s.justified, g, "the attacker (30%) cannot justify alone");

    // The honest 70% justify c1, then c2 (finalizing c1), without the attacker.
    let round1 = sign_all(&honest, 0, &|_| (g, c1));
    let (s, h) = include(&st, start, &round1).unwrap();
    assert_eq!(s.justified, c1, "the honest keys justify without the attacker");
    assert!(h <= ACT + 45 + P.vote_ttl, "within the vote lifetime");
    let round2 = sign_all(&honest[..195], 0, &|_| (c1, c2));
    let from = h.max(c2.height + 1);
    let (s, _) = include(&s, from, &round2).unwrap();
    assert_eq!((s.justified, s.finalized), (c2, c1), "and finalize");

    // Signature checks per block stay bounded by the attestation cap.
    let too_many = &round1[..P.max_attestations_per_block + 1];
    assert!(block(&st, start, too_many, &[]).is_err_and(|e| e.contains("too many attestations")));
}

// ═════════════════════════════════════════════════════════════════════════════
// The activation boundary
// ═════════════════════════════════════════════════════════════════════════════

/// Every rule switches exactly at the activation height, on one parent
/// state: at H-1 the old verdicts, at H the new ones.
/// - Threshold: three keys of 43 and 70 fillers of 1. The 64 heaviest weigh
///   190, all 199: the three keys' 129 justify at H-1 (>= 2/3 of 190), not at
///   H (< 2/3 of 199).
/// - Evidence: a forged (re-rooted) proof bars a key nobody holds at H-1,
///   and is refused at H.
/// - Messages: the version follows the TARGET height. A link to a slot
///   below H is signed v1 and valid in blocks on both sides (a v2 signature
///   for it is not); a link to a slot at or above H must be v2 (a v1
///   signature for it is refused). Below H every message is v1, also an
///   equivocation's link to a later slot (the old rule).
#[test]
fn the_rules_switch_at_the_activation_height() {
    let sp = Sparse::new([0x51; 32], 2, 2);
    let keys: Vec<KesSigner> = (0..3).map(|i| sp.signer(i)).collect();
    let mut work: Vec<(u64, KeyId, u128)> = keys.iter().map(|k| (0, k.public().witness_id(), 43)).collect();
    work.extend(fillers().into_iter().map(|k| (0, k, 1)));
    let st = state_at(ACT + 45, &work);
    let g = cp(0, ACT);
    let c1 = cp(0, ACT + 45);
    let sign = |k: &KesSigner, h2: u64, t: Checkpoint| Attestation::sign_at(CHAIN, h2, g, t, k).unwrap();

    // Threshold, H = ACT + 47.
    let votes: Vec<Attestation> = keys.iter().map(|k| sign(k, NEVER, c1)).collect();
    {
        let _g = scoped_override_v2(ACT + 47);
        assert_eq!(block(&st, ACT + 46, &votes, &[]).unwrap().justified, c1, "H-1: two thirds of the 64 heaviest");
        let s = block(&st, ACT + 47, &votes, &[]).unwrap();
        assert_eq!(s.justified, g, "H: two thirds of all the weight");
        assert_eq!(s.votes[&c1].len(), 3, "the v1 votes for a target below H are counted at H");
    }

    // Forged evidence, H = ACT + 47.
    let forger = {
        let _g = scoped_override_v2(NEVER);
        Forger::new(52)
    };
    {
        let _g = scoped_override_v2(ACT + 47);
        assert_eq!(block(&st, ACT + 46, &[], &[forger.equivocation(1)]).unwrap().banned.len(), 1);
        assert!(block(&st, ACT + 47, &[], &[forger.equivocation(1)]).is_err_and(|e| e.contains("not a member")));
    }

    // Message versions, H = ACT + 50 (a slot): blocks ACT+49 (V1) and ACT+51.
    let _g = scoped_override_v2(ACT + 50);
    let c2 = cp(0, ACT + 50);
    let ok = |h: u64, a: &Attestation| block(&st, h, std::slice::from_ref(a), &[]).is_ok();
    assert!(ok(ACT + 49, &sign(&keys[0], NEVER, c1)) && ok(ACT + 51, &sign(&keys[0], NEVER, c1)),
        "target below H: v1 on both sides");
    assert!(!ok(ACT + 51, &sign(&keys[0], 0, c1)), "target below H: a v2 signature is refused");
    assert!(ok(ACT + 51, &sign(&keys[0], 0, c2)), "target at H: v2");
    assert!(!ok(ACT + 51, &sign(&keys[0], NEVER, c2)), "target at H: a v1 signature is refused");
    assert!(sign(&keys[0], ACT + 50, c2).verify_signature(CHAIN, &P, ACT) && !sign(&keys[0], ACT + 50, c2)
        .verify_signature_at(CHAIN, &P, ACT, NEVER), "sign_at follows the target height");
    // An equivocation whose links target a slot at or above H, in a block below H: v1 (the old rule).
    let ev = |h2: u64| Equivocation { a: sign(&keys[1], h2, c2), b: sign(&keys[1], h2, cp(4, ACT + 50)) };
    assert!(block(&st, ACT + 46, &[], &[ev(NEVER)]).is_ok(), "below H: v1 links");
    assert!(block(&st, ACT + 46, &[], &[ev(0)]).is_err(), "below H: a v2 link is not verified");
    assert!(block(&st, ACT + 51, &[], &[ev(0)]).is_ok(), "at H: v2 links");
    assert!(block(&st, ACT + 51, &[], &[ev(NEVER)]).is_err(), "at H: a v1 link to a slot at H is refused");
}

/// Replaying a chain across the activation is a pure function of the
/// blocks: two runs give the same states, every state survives the storage
/// encoding unchanged (a restart reads exactly what was written), the states
/// below the activation are the old regime's, and from the activation the
/// new rules are in force (the decay of a stall reaches every share key, not
/// only the 64 heaviest).
#[test]
fn replay_across_the_activation_is_deterministic() {
    let h2 = ACT + 100;
    let run = || {
        let _g = scoped_override_v2(h2);
        scenario(&|s, b, v| s.apply(&P, CHAIN, b, v))
    };
    let a = run();
    let b = run();
    assert_eq!(chain_digest(&a), chain_digest(&b));
    for s in &a {
        let bytes = bincode::serde::encode_to_vec(s, bincode::config::standard()).unwrap();
        let (back, _): (PowitState, usize) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(&back, s);
    }
    let old = {
        let _g = scoped_override_v2(NEVER);
        scenario(&|s, b, v| s.apply(&P, CHAIN, b, v))
    };
    let below = (h2 - ACT - 1) as usize;
    assert_eq!(a[..below], old[..below], "below the activation: the old states");
    let at = |s: &[PowitState], h: u64| s[(h - ACT - 1) as usize].clone();
    assert!(at(&old, ACT + 160).decay.values().any(|d| *d == 1),
        "old regime: only the 64 heaviest of each stalled epoch decay");
    let new_end = at(&a, ACT + 160);
    assert!(new_end.decay.len() == 73 && new_end.decay.values().all(|d| *d == 2),
        "hardening 2: every one of the 73 share keys decays each stalled epoch: {:?}", new_end.decay);
    assert_ne!(chain_digest(&a), OLD_REGIME_DIGEST);
}

/// From hardening 2 every share key is a member, so a stall decays every
/// one of them; a decay entry is dropped once its key's share work has left
/// the kept epochs (it can be a member of no computable set), so `decay`
/// stays bounded by the keys of `epoch_work`. The old regime keeps it until
/// finality resumes.
#[test]
fn decay_entries_go_with_their_keys_work() {
    let k: KeyId = [7; 20];
    let st = state_at(ACT + 1, &[(0, k, 1_000)]);
    let run = |h2: u64| {
        let _g = scoped_override_v2(h2);
        let mut s = st.clone();
        let mut seen = Vec::new();
        for h in ACT + 1..=ACT + 125 {
            s = block(&s, h, &[], &[]).unwrap();
            seen.push(s.decay.get(&k).copied());
        }
        seen
    };
    let old = run(NEVER);
    let new = run(0);
    let at = |v: &[Option<u32>], h: u64| v[(h - ACT - 1) as usize];
    // Stalled from ACT + 80: the key (work in epoch 0, a member of W(2..=4)) decays at the
    // boundaries into epochs 4 and 5; its work leaves the kept epochs at epoch 6.
    for v in [&old, &new] {
        assert_eq!(at(v, ACT + 79), None);
        assert_eq!(at(v, ACT + 80), Some(1));
        assert_eq!(at(v, ACT + 100), Some(2));
    }
    assert_eq!(at(&old, ACT + 125), Some(2), "old regime: kept");
    assert_eq!(at(&new, ACT + 125), None, "hardening 2: gone with the key's work");
}

