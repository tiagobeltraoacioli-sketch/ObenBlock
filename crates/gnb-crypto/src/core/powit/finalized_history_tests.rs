//! Hardening 2, PoWit audit finding 3 (docs/DESIGN-pow-powit.md §7.4): the
//! witness set a block uses comes from FINALIZED history only.
//!
//! The attack: a private fork that branches after the honest chain's last
//! finalized checkpoint mines its own witness shares; under the first rule
//! the fork's witness set is built from the fork's own `epoch_work`, so once
//! its shares fill the window (two epochs of lag plus the window) the
//! attacker's key alone holds 2/3 of W and finalizes the fork. From hardening
//! 2 the window is anchored at the state's finalized checkpoint: the fork
//! shares the honest finalized checkpoint, so its W is the honest W, which
//! never signs the fork, and the fork never finalizes.
//!
//! Real KES keys and hybrid signatures; a simulated selected chain (fork 0
//! up to [`FORK_AT`], the private fork above it).

use super::*;
use crate::core::activation;
use crate::core::kes::KesSigner;
use crate::core::ChainId;
use std::cell::RefCell;

const CHAIN: ChainId = ChainId::Testnet;
const P: PowitParams = TESTNET_PARAMS;
const ACT: u64 = 1_000;
/// The last block both chains share; the private fork's blocks are above it.
const FORK_AT: u64 = 1_100;
/// How far both chains are driven.
const TO: u64 = 1_200;

struct Key {
    signer: RefCell<KesSigner>,
}

impl Key {
    /// Depth 4 = 16 epochs: heights up to ACT + 320 on the testnet clock.
    fn new(seed: u8) -> Key {
        Key { signer: RefCell::new(KesSigner::generate(4, [seed; 32], |_| {}).unwrap()) }
    }
    fn id(&self) -> KeyId {
        self.signer.borrow().public().witness_id()
    }
    /// The attestation message of `target`'s height under the second
    /// hardening height `h2` (v2 from it, PoWit finding 1).
    fn attest(&self, source: Checkpoint, target: Checkpoint, h2: u64) -> Attestation {
        let e = P.epoch(ACT, target.height);
        let mut s = self.signer.borrow_mut();
        if e > s.epoch() {
            s.evolve_to(e).unwrap();
        }
        assert_eq!(e, s.epoch(), "keys sign epochs in order");
        Attestation::sign_at(CHAIN, h2, source, target, &s).unwrap()
    }
}

/// The checkpoint id of slot `slot` on chain `fork` (shared below the fork).
fn slot_hash(fork: u8, slot: u64) -> [u8; 32] {
    let f = if slot <= FORK_AT { 0 } else { fork };
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&slot.to_le_bytes());
    x[8] = f;
    x
}

fn cp(fork: u8, slot: u64) -> Checkpoint {
    Checkpoint { height: slot, hash: slot_hash(fork, slot) }
}

struct View {
    fork: u8,
    tip: u64,
}

impl ChainView for View {
    fn selected_at(&self, slot: u64) -> Option<[u8; 32]> {
        (slot < self.tip).then(|| slot_hash(self.fork, slot))
    }
}

/// Apply one block at `h` on chain `fork` with the second hardening upgrade
/// active from `h2` (the calling thread's `scoped_override_v2`).
fn step(st: &PowitState, h: u64, fork: u8, shares: &[(KeyId, u128)], atts: &[Attestation], h2: u64)
    -> Result<PowitState, String>
{
    let _g = activation::scoped_override_v2(h2);
    let input = BlockInput { height: h, hash: slot_hash(fork, h + 1), share_work: shares,
                             attestations: atts, evidence: &[], exits: &[] };
    st.apply(&P, CHAIN, &input, &View { fork, tip: h })
}

/// The newest checkpoint slot below `h` above the justified one, if any.
fn open_slot(st: &PowitState, h: u64) -> Option<u64> {
    let t = h - 1;
    (P.is_checkpoint(ACT, t) && t > st.justified.height).then_some(t)
}

/// Drive the honest chain (fork 0) from the activation to `to`: two equal
/// witnesses earn 1,000 of share work each per block and both sign every
/// open slot (each holds half of W, so both are needed for 2/3), the
/// pattern of a healthy network. Returns the state after every height.
fn honest_chain(keys: &[Key], to: u64, h2: u64) -> Vec<PowitState> {
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let mut st = PowitState::genesis(ACT, slot_hash(0, ACT));
    let mut out = vec![st.clone()];
    for h in ACT + 1..=to {
        let shares: Vec<(KeyId, u128)> = ids.iter().map(|k| (*k, 1_000)).collect();
        let atts: Vec<Attestation> = match open_slot(&st, h) {
            Some(t) if P.epoch(ACT, t) >= 2 => keys.iter().map(|k| k.attest(st.justified, cp(0, t), h2)).collect(),
            _ => Vec::new(),
        };
        st = step(&st, h, 0, &shares, &atts, h2).unwrap_or_else(|e| panic!("honest h={h}: {e}"));
        out.push(st.clone());
    }
    out
}

/// The private fork (fork 1) on `base` (the honest state at `FORK_AT`): the
/// attacker's key `z` earns all the share work of the fork's blocks (2,000
/// per block, as much as the honest network) and signs every open slot,
/// including its attestation whenever the block stays valid with it (an
/// attacker includes what it can).
fn private_fork(base: &PowitState, z: &Key, to: u64, h2: u64) -> PowitState {
    let mut st = base.clone();
    for h in FORK_AT + 1..=to {
        let shares = [(z.id(), 2_000u128)];
        let with_vote = open_slot(&st, h).and_then(|t| {
            let a = z.attest(st.justified, cp(1, t), h2);
            step(&st, h, 1, &shares, &[a], h2).ok()
        });
        st = match with_vote {
            Some(s) => s,
            None => step(&st, h, 1, &shares, &[], h2).unwrap_or_else(|e| panic!("fork h={h}: {e}")),
        };
    }
    st
}

fn digest(states: &[&PowitState]) -> String {
    let mut h = Sha3_256::new();
    for s in states {
        h.update(bincode::serde::encode_to_vec(s, bincode::config::standard()).unwrap());
    }
    hex::encode(h.finalize())
}

/// The finding's scenario on both regimes.
///
/// First rule (`h2` = NEVER): the fork's own shares fill the window by epoch
/// 9 and the attacker alone finalizes a fork checkpoint (the defect; this
/// regime is kept bit-for-bit below the activation, pinned by a digest of
/// both chains' final states).
///
/// Hardening 2 (`h2` = 0): the fork's W stays the honest W of the finalized
/// window, the attacker is never a member, nothing on the fork justifies or
/// finalizes; the honest chain, finalizing continuously, reaches exactly the
/// same states as under the first rule.
#[test]
fn a_private_fork_with_its_own_shares_never_finalizes_from_hardening_2() {
    // First rule.
    let honest_keys = [Key::new(1), Key::new(2)];
    let old = honest_chain(&honest_keys, TO, activation::NEVER);
    let at_fork = &old[(FORK_AT - ACT) as usize];
    assert_eq!(at_fork.finalized, cp(0, 1_090), "the honest chain finalizes continuously");
    assert_eq!(at_fork.justified, cp(0, 1_095));
    let z = Key::new(9);
    let fork_old = private_fork(at_fork, &z, TO, activation::NEVER);
    assert_eq!(fork_old.finalized.hash, slot_hash(1, fork_old.finalized.height),
        "first rule: the attacker's own witness set finalizes a fork checkpoint");
    assert!(fork_old.finalized.height > FORK_AT);
    assert_eq!(fork_old.finalized, cp(1, 1_190),
        "from epoch 9 the window holds the fork's shares only: the attacker justifies every slot");
    let honest_old = old.last().unwrap();
    assert_eq!(honest_old.finalized, cp(0, 1_190));
    let old_digest = digest(&[honest_old, &fork_old]);
    eprintln!("first-rule digest: {old_digest}");

    // Hardening 2 from genesis.
    let honest_keys = [Key::new(1), Key::new(2)];
    let new = honest_chain(&honest_keys, TO, 0);
    assert_eq!(new, old, "a chain that finalizes continuously sees the same witness sets");
    let z = Key::new(9);
    let fork_new = private_fork(&new[(FORK_AT - ACT) as usize], &z, TO, 0);
    assert_eq!(fork_new.finalized, cp(0, 1_090), "the fork never finalizes anything of its own");
    assert_eq!(fork_new.justified, cp(0, 1_095), "nor justifies anything");
    assert!(fork_new.votes.is_empty() && !fork_new.links.contains_key(&z.id()),
        "the attacker never voted: it is not in the finalized witness set");
    assert_eq!(old_digest, "ca883d976b7bf5a8be4feb3af7b5f5301358baf4697017d686103def4678914a",
        "the first rule is unchanged below the activation");
}

/// The anchored epoch is a pure function of the finalized slot (golden
/// table, testnet clock: 20-block epochs from ACT).
#[test]
fn finalized_window_epoch_golden_table() {
    let mut st = PowitState::genesis(ACT, slot_hash(0, ACT));
    // (finalized slot, target epoch, epoch whose window is read)
    let rows: &[(u64, u64, u64)] = &[
        (ACT, 0, 0), (ACT, 7, 7), (ACT, 40, 40),                               // bootstrap: the first rule
        (ACT + 40, 2, 2), (ACT + 40, 3, 3), (ACT + 40, 4, 3), (ACT + 40, 9, 3), // nf = 2
        (ACT + 55, 3, 3), (ACT + 55, 4, 3),                                    // slot 1055 is inside epoch 2
        (ACT + 60, 4, 4), (ACT + 60, 5, 4),                                    // nf = 3
        (ACT + 95, 5, 5), (ACT + 95, 6, 5),                                    // nf = 4
    ];
    for &(fin, e, want) in rows {
        st.finalized = cp(0, fin);
        assert_eq!(st.finalized_window_epoch(&P, e), want, "finalized {fin}, epoch {e}");
        assert_eq!(st.finalized_epochs(&P), (fin - ACT) / P.epoch_len);
    }
}

/// While finality keeps up the anchored set IS the first rule's; when it
/// lags it is the last finalized window's; an empty frozen window gives way
/// to the epoch's own (liveness across the upgrade).
#[test]
fn witness_set_at_matches_the_first_rule_unless_finality_lags() {
    let (a, b, c) = ([1u8; 20], [2u8; 20], [3u8; 20]);
    let mut st = PowitState::genesis(ACT, slot_hash(0, ACT));
    for e in 0..=9 {
        st.epoch_work.entry(e).or_default().insert(a, 100);
        st.epoch_work.entry(e).or_default().insert(b, 100);
    }
    for e in 5..=9 {
        st.epoch_work.entry(e).or_default().insert(c, 1_000);
    }
    st.finalized = cp(0, ACT + 8 * P.epoch_len); // nf = 8
    for e in 2..=9 {
        assert_eq!(st.witness_set_at(&P, e, true), st.witness_set(&P, e), "epoch {e}: finality keeps up");
    }
    st.finalized = cp(0, ACT + 4 * P.epoch_len + 5); // nf = 4: c's shares are not final
    assert_eq!(st.witness_set_at(&P, 9, false), st.witness_set(&P, 9));
    assert!(st.witness_set(&P, 9).iter().any(|(k, _)| *k == c), "the first rule counts unfinalized shares");
    assert_eq!(st.witness_set_at(&P, 9, true), st.witness_set(&P, 5), "frozen at the last finalized window");
    assert!(st.witness_set_at(&P, 9, true).iter().all(|(k, _)| *k != c));
    // The frozen window [1, 3] emptied (pruned before the upgrade): its own.
    for e in 1..=3 {
        st.epoch_work.remove(&e);
    }
    assert!(st.witness_set(&P, 5).is_empty());
    assert_eq!(st.witness_set_at(&P, 9, true), st.witness_set(&P, 9));
}

/// A long stall and a new share miner. The honest witnesses stop signing
/// after height 1100 (finalized slot 1090) for ten epochs while a new key N
/// earns as much share work as both of them. Under the first rule N enters
/// the witness set two epochs later and may sign; from hardening 2 it may
/// not (membership changes only through finalized history), the frozen
/// window survives the first rule's pruning (nothing else of the stall is
/// kept), and once the honest witnesses sign again finality resumes and N
/// becomes a member from the window of the new finalized checkpoint (under
/// the first rule the newcomer, holding half the weight without ever
/// having been finalized, keeps the returning witnesses below 2/3).
#[test]
fn a_stall_freezes_the_witness_set_and_resumed_finality_refreshes_it() {
    const RESUME: u64 = 1_300;
    for h2 in [activation::NEVER, 0] {
        let keys = [Key::new(1), Key::new(2)];
        let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
        let n = Key::new(5);
        let mut st = honest_chain(&keys, FORK_AT, h2).pop().unwrap();
        assert_eq!(st.finalized, cp(0, 1_090));
        for h in FORK_AT + 1..=RESUME + 10 {
            let shares = [(ids[0], 1_000u128), (ids[1], 1_000), (n.id(), 2_000)];
            let atts: Vec<Attestation> = match open_slot(&st, h) {
                Some(t) if h > RESUME => keys.iter().map(|k| k.attest(st.justified, cp(0, t), h2)).collect(),
                _ => Vec::new(),
            };
            if h == 1_201 {
                // N signs slot 1200 (epoch 10) during the stall.
                let vote = n.attest(st.justified, cp(0, 1_200), h2);
                let r = step(&st, h, 0, &shares, std::slice::from_ref(&vote), h2);
                assert_eq!(r.is_ok(), h2 == activation::NEVER,
                    "h2 {h2}: a stall lets a new key vote only under the first rule: {r:?}");
            }
            st = step(&st, h, 0, &shares, &atts, h2).unwrap_or_else(|e| panic!("h2 {h2} h={h}: {e}"));
            if h == RESUME && h2 == 0 {
                let kept: Vec<u64> = st.epoch_work.keys().copied().collect();
                assert_eq!(kept, vec![1, 2, 3, 10, 11, 12, 13, 14, 15],
                    "the frozen window (finalized epochs 1..=3) and the first rule's horizon, nothing between");
                assert!(st.witness_set_at(&P, 15, true).iter().all(|(k, _)| *k != n.id()));
            }
        }
        let e = P.epoch(ACT, RESUME + 10);
        if h2 == activation::NEVER {
            // The first rule: N holds half of the witness weight it joined
            // during the stall, so the two returning witnesses cannot reach
            // 2/3 without it (until inactivity decay wears N down).
            assert_eq!(st.finalized, cp(0, 1_090), "first rule: the unfinalized newcomer blocks finality");
        } else {
            assert_eq!(st.finalized, cp(0, 1_300), "hardening 2: finality resumed with the frozen set");
            assert!(st.witness_set_at(&P, e, true).iter().any(|(k, _)| *k == n.id()),
                "the new key is a member once its shares are final");
        }
    }
}

/// Review MEDIUM 5: the emptiness test of the frozen window stops at the
/// first member, and answers exactly what aggregating the whole window did
/// (so `h2_window_epoch`, a consensus function, is unchanged): over windows
/// with keys of zero work, barred keys, decayed keys and empty epochs.
#[test]
fn the_early_exit_window_test_agrees_with_the_full_aggregation() {
    let k = |i: u8| -> KeyId { [i; 20] };
    let mut st = PowitState::genesis(ACT, [1; 32]);
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut checked = 0;
    for _ in 0..400 {
        st.epoch_work.clear();
        st.banned.clear();
        st.decay.clear();
        for e in 0..12u64 {
            if next() % 3 == 0 {
                continue; // an empty epoch
            }
            for _ in 0..(next() % 4) {
                let key = k((next() % 6) as u8);
                let w = match next() % 4 { 0 => 0, 1 => 1, _ => u128::from(next() % 5_000) };
                st.epoch_work.entry(e).or_default().insert(key, w);
            }
        }
        for i in 0..6u8 {
            match next() % 5 {
                0 => { st.banned.insert(k(i), next() % 14); }
                1 => { st.decay.insert(k(i), (next() % 70) as u32); }
                _ => {}
            }
        }
        for window_epoch in 0..14u64 {
            for bar_epoch in [window_epoch, window_epoch + 3, 0] {
                let full = !st.window_weights_at(&P, window_epoch, bar_epoch).is_empty();
                assert_eq!(st.window_has_weight(&P, window_epoch, bar_epoch), full,
                    "window {window_epoch}, bars at {bar_epoch}: {:?} {:?}", st.epoch_work, st.banned);
                checked += 1;
            }
        }
    }
    assert!(checked > 10_000);
}

/// Review LOW 10: the relation the frozen-window retention relies on holds
/// for both networks (also a compile-time assertion) and is not vacuous.
#[test]
fn the_parameters_keep_the_frozen_window() {
    assert!(params_keep_the_frozen_window(&MAINNET_PARAMS));
    assert!(params_keep_the_frozen_window(&TESTNET_PARAMS));
    assert!(!params_keep_the_frozen_window(&PowitParams { vote_ttl: 21, ..TESTNET_PARAMS }));
    assert!(!params_keep_the_frozen_window(&PowitParams { checkpoint_interval: 20, ..TESTNET_PARAMS }));
}
