//! ObenBlock liveness in the PoWit state machine (`docs/DESIGN-obenblock.md`
//! §5.2): the half leak restores finality sooner than GnB's 1/16, and
//! witness exits (real KES keys and signatures; a simulated selected chain).

use super::*;
use crate::core::kes::KesSigner;
use crate::core::liveness::MAX_EXITS_PER_BLOCK;
use crate::core::ChainId;

const CHAIN: ChainId = ChainId::Testnet;
const ACT: u64 = 1_000;
const HALF: PowitParams = OBENBLOCK_REGTEST_PARAMS;
/// The liveness rules from the start (ObenBlock).
const LIVE: u64 = 0;

struct Key(std::cell::RefCell<KesSigner>);

impl Key {
    fn new(seed: u8) -> Key {
        Key(std::cell::RefCell::new(KesSigner::generate(6, [seed; 32], |_| {}).unwrap()))
    }
    fn id(&self) -> KeyId {
        self.0.borrow().public().witness_id()
    }
    fn evolve(&self, e: u64) {
        let mut s = self.0.borrow_mut();
        if e > s.epoch() {
            s.evolve_to(e).unwrap();
        }
    }
    fn attest(&self, p: &PowitParams, source: Checkpoint, target: Checkpoint) -> Attestation {
        self.evolve(p.epoch(ACT, target.height));
        Attestation::sign_at(CHAIN, 0, source, target, &self.0.borrow()).unwrap()
    }
    fn exit(&self, epoch: u64) -> WitnessExit {
        self.evolve(epoch);
        WitnessExit::sign(CHAIN.to_u32(), &self.0.borrow()).unwrap()
    }
}

struct Chain(u64);

fn hash(h: u64) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&h.to_le_bytes());
    x
}

impl ChainView for Chain {
    fn selected_at(&self, height: u64) -> Option<[u8; 32]> {
        (height < self.0).then(|| hash(height))
    }
}

fn cp(h: u64) -> Checkpoint {
    Checkpoint { height: h, hash: hash(h) }
}

fn step(st: &PowitState, p: &PowitParams, liveness: u64, h: u64, sw: &[(KeyId, u128)], atts: &[Attestation],
        exits: &[WitnessExit]) -> Result<PowitState, String> {
    let input = BlockInput { height: h, hash: hash(h), share_work: sw, attestations: atts, evidence: &[], exits };
    st.apply_full(p, CHAIN, 0, liveness, &input, &Chain(h))
}

/// Shares for every key in every block up to `to`, nothing else.
fn warmed(p: &PowitParams, ids: &[KeyId], to: u64) -> PowitState {
    let mut st = PowitState::genesis(ACT, hash(ACT));
    let sw: Vec<(KeyId, u128)> = ids.iter().map(|k| (*k, 1_000)).collect();
    for h in ACT + 1..=to {
        st = step(&st, p, LIVE, h, &sw, &[], &[]).unwrap();
    }
    st
}

/// One of three equal witnesses keeps voting, two are gone: the epoch of the
/// first finality after the stall.
fn first_finality_epoch(p: &PowitParams, keys: &[Key]) -> Option<u64> {
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let sw: Vec<(KeyId, u128)> = ids.iter().map(|k| (*k, 1_000)).collect();
    let mut st = PowitState::genesis(ACT, hash(ACT));
    for h in ACT + 1..=ACT + 60 * p.epoch_len {
        let mut atts = Vec::new();
        // Key 0 votes for the newest checkpoint slot from the justified one.
        if h > ACT + 2 * p.epoch_len && p.is_checkpoint(ACT, h - 1) {
            atts.push(keys[0].attest(p, st.justified, cp(h - 1)));
        }
        st = step(&st, p, LIVE, h, &sw, &atts, &[]).unwrap_or_else(|e| panic!("h={h}: {e}"));
        if st.finalized.height > ACT {
            return Some(p.epoch(ACT, h));
        }
    }
    None
}

/// Two thirds of the weight gone: two halvings (from the boundary into epoch
/// 4, `leak_after_epochs`) restore finality in epoch 5; 1/16 needs 22 steps
/// (15/16^22 < 1/4), the 22nd at the boundary into epoch 25.
#[test]
fn half_leak_restores_finality_sooner() {
    let keys = vec![Key::new(1), Key::new(2), Key::new(3)];
    let half = first_finality_epoch(&HALF, &keys).expect("half leak finalizes");
    assert_eq!(half, 5);
    let keys = vec![Key::new(1), Key::new(2), Key::new(3)];
    let sixteenth = first_finality_epoch(&TESTNET_PARAMS, &keys).expect("1/16 leak finalizes");
    assert_eq!(sixteenth, 25);
}

#[test]
fn an_exit_leaves_w_from_the_next_epoch() {
    let keys = [Key::new(4), Key::new(5)];
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let h = ACT + 45; // epoch 2
    let st = warmed(&HALF, &ids, h);
    let e = HALF.epoch(ACT, h + 1);
    assert_eq!(e, 2);
    let out = step(&st, &HALF, LIVE, h + 1, &[], &[], &[keys[0].exit(e)]).unwrap();
    assert_eq!(out.exited.get(&ids[0]), Some(&(e + 1)));
    assert!(out.member_weight_h2(&HALF, e, &ids[0]).is_some(), "still a member of W(E)");
    assert!(out.member_weight_h2(&HALF, e + 1, &ids[0]).is_none(), "out of W(E+1)");
    assert_eq!(out.total_weight_h2(&HALF, e + 1), out.member_weight_h2(&HALF, e + 1, &ids[1]).unwrap());
    // A vote for a target of epoch E still counts; shares to the key do not.
    let src = out.justified;
    assert!(step(&out, &HALF, LIVE, h + 2, &[], &[keys[0].attest(&HALF, src, cp(h))], &[]).is_ok());
    assert!(step(&out, &HALF, LIVE, h + 2, &[(ids[0], 1)], &[], &[]).unwrap_err().contains("exited"));
    // A second exit by the same key is refused.
    assert!(step(&out, &HALF, LIVE, h + 2, &[], &[], &[keys[0].exit(e)]).unwrap_err().contains("already exited"));
}

#[test]
fn exit_rules_reject_bad_exits() {
    let keys = [Key::new(6), Key::new(7)];
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let h = ACT + 61; // epoch 3
    let st = warmed(&HALF, &ids, h - 1);
    let e = HALF.epoch(ACT, h);
    let ok = keys[0].exit(e);
    // Before the liveness activation (GnB) no block may carry one.
    assert!(step(&st, &HALF, activation::NEVER, h, &[], &[], std::slice::from_ref(&ok)).is_err());
    assert!(step(&st, &HALF, h + 1, h, &[], &[], std::slice::from_ref(&ok)).is_err());
    // Twice in one block.
    assert!(step(&st, &HALF, LIVE, h, &[], &[], &[ok.clone(), ok.clone()]).is_err());
    // Too many (checked before any signature).
    let many = vec![ok.clone(); MAX_EXITS_PER_BLOCK + 1];
    assert!(step(&st, &HALF, LIVE, h, &[], &[], &many).unwrap_err().contains("too many"));
    // A key without share work.
    assert!(step(&st, &HALF, LIVE, h, &[], &[], &[Key::new(8).exit(e)]).unwrap_err().contains("without share work"));
    // Signed for another chain.
    let other = { keys[1].evolve(e); WitnessExit::sign(ChainId::Mainnet.to_u32(), &keys[1].0.borrow()).unwrap() };
    assert!(step(&st, &HALF, LIVE, h, &[], &[], &[other]).unwrap_err().contains("signature"));
    // Tampered epoch (the leaf no longer matches).
    let mut wrong = ok.clone();
    wrong.epoch = e - 1;
    assert!(step(&st, &HALF, LIVE, h, &[], &[], &[wrong]).is_err());
    // Signed two epochs ago: too old (and replays are impossible).
    let st5 = warmed(&HALF, &ids, ACT + 100); // epoch 4 at h=ACT+100 -> next block epoch 5
    assert!(step(&st5, &HALF, LIVE, ACT + 101, &[], &[], std::slice::from_ref(&ok)).unwrap_err().contains("epoch"));
    // The next epoch still accepts it.
    let st4 = warmed(&HALF, &ids, ACT + 80);
    assert!(step(&st4, &HALF, LIVE, ACT + 81, &[], &[], std::slice::from_ref(&ok)).is_ok());
    // The good one, here.
    assert!(step(&st, &HALF, LIVE, h, &[], &[], &[ok]).is_ok());
}

/// The record lives while the key has share work in the kept epochs, then
/// goes (bounded state).
#[test]
fn exit_records_are_pruned_with_the_work() {
    let keys = [Key::new(9), Key::new(10)];
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let h = ACT + 45;
    let st = warmed(&HALF, &ids, h);
    let mut st = step(&st, &HALF, LIVE, h + 1, &[], &[], &[keys[0].exit(2)]).unwrap();
    let only_1 = [(ids[1], 1_000u128)];
    let mut gone_at = None;
    for x in h + 2..h + 2 + 10 * HALF.epoch_len {
        st = step(&st, &HALF, LIVE, x, &only_1, &[], &[]).unwrap();
        if gone_at.is_none() && !st.exited.contains_key(&ids[0]) {
            gone_at = Some(HALF.epoch(ACT, x));
        }
    }
    // Key 0's last work is in epoch 2; at epoch e `epoch_work` keeps epochs
    // e - (window + 2) ..= e, so it drops out at the boundary into epoch 8.
    assert_eq!(gone_at, Some(8));
    assert!(st.member_weight_h2(&HALF, st.epoch, &ids[0]).is_none());
}

#[test]
fn exits_are_on_the_wire_only_when_enabled() {
    let k = Key::new(11);
    let body = PowitBody { exits: vec![k.exit(0)], ..PowitBody::default() };
    let mut gnb = Vec::new();
    body.write_wire_with(&mut gnb, false);
    let mut plain = Vec::new();
    body.write_wire(&mut plain);
    assert_eq!(gnb, plain, "the GnB encoding has no exits list");
    assert_eq!(gnb, { let mut v = Vec::new(); PowitBody::default().write_wire(&mut v); v });
    assert_eq!(body.root_with(false), PowitBody::default().root());
    let mut obb = Vec::new();
    body.write_wire_with(&mut obb, true);
    let back = PowitBody::read_wire_with(&mut std::io::Cursor::new(obb.as_slice()), true).unwrap();
    assert_eq!(back, body);
    assert_ne!(body.root_with(true), body.root_with(false));
    // An empty exits list is one byte (count 0) from the activation.
    let mut empty = Vec::new();
    PowitBody::default().write_wire_with(&mut empty, true);
    assert_eq!(empty.len(), gnb.len() + 1);
    // Count above the cap is refused before anything is read.
    let mut big = gnb.clone();
    big.push((MAX_EXITS_PER_BLOCK + 1) as u8);
    assert!(PowitBody::read_wire_with(&mut std::io::Cursor::new(big.as_slice()), true).is_err());
}

#[test]
fn half_decay_matches_repeated_halving() {
    for w in [0u128, 1, 2, 3, 1_000_003, u128::MAX] {
        let mut x = w;
        for n in 1..=130u32 {
            if n <= 128 {
                x -= x / 2;
            }
            assert_eq!(decayed_half(w, n), x, "w={w} n={n}");
        }
    }
    assert_eq!(decayed_with(InactivityLeak::Sixteenth, 1_000, 3), decayed(1_000, 3));
}
