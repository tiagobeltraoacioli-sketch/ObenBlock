//! PoWit pool and witness duty, node-local hardening (PoWit audit of the PR
//! head 4293747, findings 1 (pool side), 5, 7 and 8). Nothing here changes a
//! block-validity rule: every test drives the node's own pool / signer.
//!
//! - Finding 1: an equivocation proof costs an attacker two signatures once,
//!   then one SHA3 per new KES root (the sibling hash in the path is free), so
//!   the pool admits only proofs against keys that are (or recently were) in
//!   the witness set, checked before any signature; it is capped; templates
//!   take the heaviest keys first (a ground KeyId cannot crowd out a real
//!   equivocator); `seen_links` keeps the oldest-evicted links of witnesses
//!   only, so a flood cannot wipe the honest links double votes are caught
//!   against.
//! - Finding 5: one witness cannot fill every node's attestation pool with
//!   off-slot, far or expired targets, nor hold more than two pending links.
//! - Finding 7: the pool forgets what a new tip made stale on every node.
//! - Finding 8: a corrupt vote record refuses to sign; a reset record cannot
//!   sign below the highest heights this key ever signed.
//!
//! This binary runs on the testnet PoWit clock (short epochs) with PoWit
//! active from height 3 (process-wide overrides, once per binary).
//!
//! The re-rooting forgery of finding 1 exists only below the second
//! hardening activation (from it the signed message commits the witness
//! key and a block may carry a proof only against a witness:
//! `node/tests/fix_powit_hardening2.rs`). The tests that use it run under the
//! old regime (`old_regime()`, `activation::scoped_override_v2(NEVER)`),
//! the rules mainnet runs until that activation is scheduled; testnet runs
//! the second hardening rules from genesis.

use gnb::consensus::GhostDAG;
use gnb::core::kes::{KesKeyFile, KesPublic, KesSigner};
use gnb::core::powit::{Attestation, Checkpoint, Equivocation, KeyId, PowitState, TESTNET_PARAMS};
use gnb::core::{self, activation, Block, BlockHeader, ChainId, MerkleRoot};
use gnb::powit::{self, PowitPool};
use gnb::storage::Storage;
use sha3::{Digest, Sha3_256};
use tempfile::TempDir;

const ACT: u64 = 3;
const CHAIN: ChainId = ChainId::Testnet;

fn setup() {
    let _ = core::set_node_chain_id(CHAIN);
    let _ = core::set_powit_height_override(ACT);
    assert_eq!(core::node_chain_id(), CHAIN, "one chain id per test binary");
    assert_eq!(core::powit_height(), ACT, "one PoWit activation per test binary");
}

// ── A chain in a GhostDAG + store, with synthetic PoWit states ───────────────

struct Fx {
    _tmp: TempDir,
    store: Storage,
}

/// One selected chain: `hashes[h]` is the block at height `h`.
struct Chain {
    dag: GhostDAG,
    hashes: Vec<[u8; 32]>,
}

fn mk_block(parent: [u8; 32], h: u64, fork: u64) -> Block {
    Block {
        header: BlockHeader {
            version: 1, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
            timestamp: 1_000 + h, bits: core::POW_LIMIT_BITS, nonce: fork * 1_000_000 + h,
        },
        transactions: vec![],
        blue_score: h,
        height: h,
        shielded_transactions: vec![],
        powit: Default::default(),
    }
}

impl Fx {
    fn new() -> Self {
        setup();
        let tmp = TempDir::new().unwrap();
        let store = Storage::open(&tmp.path().join("db")).unwrap();
        Fx { _tmp: tmp, store }
    }

    /// A chain from a fixed genesis: heights `1..=shared` are common to
    /// every fork, `shared+1..=tip_h` are fork `fork`'s own.
    fn chain(&self, tip_h: u64, shared: u64, fork: u64) -> Chain {
        let genesis = mk_block([0u8; 32], 0, 0);
        let gh = genesis.block_hash();
        self.store.put_block(&genesis).unwrap();
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(gh, genesis.header.timestamp);
        let mut hashes = vec![gh];
        for h in 1..=tip_h {
            let f = if h <= shared { 0 } else { fork };
            let b = mk_block(hashes[h as usize - 1], h, f);
            let bh = b.block_hash();
            self.store.put_block(&b).unwrap();
            dag.add_block(bh, vec![hashes[h as usize - 1]], b.header.timestamp, 1).unwrap();
            hashes.push(bh);
        }
        assert_eq!(dag.selected_tip(), Some(*hashes.last().unwrap()));
        Chain { dag, hashes }
    }

    /// Grow `c` by `n` blocks of fork `fork`.
    fn extend(&self, c: &mut Chain, n: u64, fork: u64) {
        for _ in 0..n {
            let h = c.hashes.len() as u64;
            let b = mk_block(*c.hashes.last().unwrap(), h, fork);
            let bh = b.block_hash();
            self.store.put_block(&b).unwrap();
            c.dag.add_block(bh, vec![*c.hashes.last().unwrap()], b.header.timestamp, 1).unwrap();
            c.hashes.push(bh);
        }
    }

    /// Save, as `c`'s tip state, a state at the tip's epoch whose witness
    /// sets (from epoch 2 on) hold `members` with their weights, justified
    /// at the activation checkpoint.
    fn tip_state(&self, c: &Chain, members: &[(KeyId, u128)]) -> PowitState {
        let tip_h = c.hashes.len() as u64 - 1;
        let mut st = PowitState::genesis(ACT, c.hashes[ACT as usize - 1]);
        st.epoch = TESTNET_PARAMS.epoch(ACT, tip_h);
        for e in 0..=st.epoch {
            for (k, w) in members {
                st.epoch_work.entry(e).or_default().insert(*k, *w);
            }
        }
        powit::save_state(&self.store, c.hashes.last().unwrap(), &st).unwrap();
        st
    }
}

impl Chain {
    fn tip(&self) -> [u8; 32] {
        *self.hashes.last().unwrap()
    }
    fn tip_h(&self) -> u64 {
        self.hashes.len() as u64 - 1
    }
    /// The checkpoint at `slot` on this chain (the block just below it).
    fn cp(&self, slot: u64) -> Checkpoint {
        Checkpoint { height: slot, hash: self.hashes[slot as usize - 1] }
    }
    /// The justified checkpoint of every state here: the activation slot.
    fn justified(&self) -> Checkpoint {
        self.cp(ACT)
    }
}

// ── Keys ─────────────────────────────────────────────────────────────────────

/// A genuine KES witness key (depth 2: epochs 0..=3, heights 3..=82).
struct Key {
    signer: std::cell::RefCell<KesSigner>,
}

impl Key {
    fn new(seed: u8) -> Key {
        Key { signer: std::cell::RefCell::new(KesSigner::generate(2, [seed; 32], |_| {}).unwrap()) }
    }
    fn id(&self) -> KeyId {
        self.signer.borrow().public().witness_id()
    }
    fn attest(&self, source: Checkpoint, target: Checkpoint) -> Attestation {
        let e = TESTNET_PARAMS.epoch(ACT, target.height);
        let mut s = self.signer.borrow_mut();
        if e > s.epoch() {
            s.evolve_to(e).unwrap();
        }
        assert_eq!(e, s.epoch(), "tests sign epochs in order");
        Attestation::sign(CHAIN, source, target, &s).unwrap()
    }
}

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Finding 1's forgery: `attestation_message` does not bind the witness key
/// and `kes::verify` only checks that the leaf plus the supplied path reach
/// the root, so ONE leaf signature re-rooted under any sibling hash is a
/// valid attestation by a new depth-1 key (one SHA3 per key).
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

/// A double vote by one depth-1 leaf (epoch 1: target 33), re-rooted per
/// sibling into as many distinct witnesses as wanted.
struct Forger {
    a: Attestation,
    b: Attestation,
}

impl Forger {
    fn new(seed: u8) -> Forger {
        let mut s = KesSigner::generate(1, [seed; 32], |_| {}).unwrap();
        s.evolve_to(1).unwrap();
        let src = Checkpoint { height: ACT, hash: [1; 32] };
        let a = Attestation::sign(CHAIN, src, Checkpoint { height: 33, hash: [0xA; 32] }, &s).unwrap();
        let b = Attestation::sign(CHAIN, src, Checkpoint { height: 33, hash: [0xB; 32] }, &s).unwrap();
        Forger { a, b }
    }
    fn sibling(i: u64) -> [u8; 32] {
        sha3(&[b"sibling", &i.to_le_bytes()])
    }
    fn key(&self, i: u64) -> KeyId {
        reroot(&self.a, Self::sibling(i)).key_id()
    }
    fn equivocation(&self, i: u64) -> Equivocation {
        let s = Self::sibling(i);
        Equivocation { a: reroot(&self.a, s), b: reroot(&self.b, s) }
    }
    fn link(&self, i: u64) -> Attestation {
        reroot(&self.a, Self::sibling(i))
    }
}

/// The PoWit rules before the second hardening activation, on this thread.
fn old_regime() -> activation::OverrideGuardV2 {
    activation::scoped_override_v2(activation::NEVER)
}

fn verify_ev(ev: &Equivocation) -> KeyId {
    ev.verify(CHAIN, &TESTNET_PARAMS, ACT).expect("a valid equivocation proof")
}

// ═════════════════════════════════════════════════════════════════════════════
// Finding 1, pool side
// ═════════════════════════════════════════════════════════════════════════════

/// A valid equivocation proof against a key that is not in the witness set
/// (any re-rooted forgery) is refused, before its signatures are checked:
/// a proof with a broken signature is refused for the membership, not for
/// the signature (no verification spent), and that refusal is not a
/// misbehaviour (the witness set is this node's view). A proof against a
/// member is admitted.
#[test]
fn evidence_against_a_key_outside_the_witness_set_is_not_admitted() {
    let _old = old_regime();
    let fx = Fx::new();
    let c = fx.chain(70, 70, 0);
    let f = Forger::new(1);
    let member = f.key(1);
    fx.tip_state(&c, &[(member, 1_000)]);
    let pool = PowitPool::new();

    let outsider = f.equivocation(2);
    assert_ne!(verify_ev(&outsider), member);
    let err = pool.admit_evidence(outsider.clone(), &c.dag, &fx.store).expect_err("a non-member's equivocation is not admitted");
    assert!(!err.starts_with("equivocation: "), "not a context-free fault: {err}");

    let mut broken = f.equivocation(3);
    broken.b.sig.sig[10] ^= 0xFF;
    let err = pool.admit_evidence(broken, &c.dag, &fx.store).expect_err("refused");
    assert!(!err.contains("signature"), "refused for the membership, before any signature check: {err}");

    assert_eq!(pool.admit_evidence(f.equivocation(1), &c.dag, &fx.store).unwrap(), member);
    assert_eq!(pool.counts().2, 1, "only the member's proof is held");
}

/// Finding 1's flood: 300 re-rooted proofs (one SHA3 each) are 300 distinct
/// valid equivocations; the pool held them all, forever, and relayed them.
#[test]
fn a_flood_of_forged_equivocations_is_bounded() {
    let _old = old_regime();
    let fx = Fx::new();
    let c = fx.chain(70, 70, 0);
    let f = Forger::new(2);
    fx.tip_state(&c, &[(f.key(0), 1_000)]);
    let pool = PowitPool::new();
    let mut admitted = 0;
    for i in 1..=300 {
        if pool.admit_evidence(f.equivocation(i), &c.dag, &fx.store).is_ok() {
            admitted += 1;
        }
    }
    assert!(pool.counts().2 <= 256, "evidence pool holds {} proofs", pool.counts().2);
    assert_eq!(admitted, 0, "no proof against a non-member is admitted (or relayed)");
}

/// Templates take evidence by the key's witness weight, heaviest first, not
/// in KeyId order: four light members whose KeyIds sort first cannot crowd
/// the heaviest equivocator out of the four evidence slots.
#[test]
fn template_evidence_goes_to_the_heaviest_witnesses_first() {
    let _old = old_regime();
    let fx = Fx::new();
    let c = fx.chain(70, 70, 0);
    let f = Forger::new(3);
    let mut ids: Vec<(KeyId, u64)> = (0..40).map(|i| (f.key(i), i)).collect();
    ids.sort();
    let heavy = ids[39];
    let light = &ids[..4];
    let mut members: Vec<(KeyId, u128)> = light.iter().map(|(k, _)| (*k, 1)).collect();
    members.push((heavy.0, 1_000_000));
    fx.tip_state(&c, &members);
    let pool = PowitPool::new();
    for (_, i) in light.iter().chain([&heavy]) {
        pool.admit_evidence(f.equivocation(*i), &c.dag, &fx.store).unwrap();
    }
    let body = powit::template_body(&pool, &c.dag, &fx.store, c.tip(), c.tip_h() + 1);
    assert_eq!(body.evidence.len(), TESTNET_PARAMS.max_evidence_per_block);
    assert!(body.evidence.iter().any(|e| e.a.key_id() == heavy.0),
        "the heaviest equivocator is in the template");
}

/// Equivocation detection from gossip survives a flood of links by other
/// keys: the honest witness's link stays recorded (links are recorded for
/// witness-set members only, bounded with oldest-first eviction, never wiped
/// wholesale), so its later double vote still becomes a proof.
#[test]
fn a_link_flood_does_not_wipe_the_links_double_votes_are_caught_against() {
    let _old = old_regime();
    let fx = Fx::new();
    let c = fx.chain(70, 70, 0);
    let k = Key::new(4);
    fx.tip_state(&c, &[(k.id(), 1_000)]);
    let pool = PowitPool::new();
    let first = k.attest(c.justified(), c.cp(68));
    pool.admit_attestation(first, &c.dag, &fx.store).unwrap();

    let f = Forger::new(5);
    for i in 0..4_200 {
        let _ = pool.admit_attestation(f.link(i), &c.dag, &fx.store);
    }
    pool.prune(&c.dag, &fx.store);

    let double = k.attest(c.justified(), Checkpoint { height: 68, hash: [0xEE; 32] });
    let _ = pool.admit_attestation(double, &c.dag, &fx.store);
    let (_, _, evidence) = pool.snapshot();
    assert!(evidence.iter().any(|e| e.a.key_id() == k.id()), "the double vote became a proof");
}

// ═════════════════════════════════════════════════════════════════════════════
// Finding 5: attestation admission
// ═════════════════════════════════════════════════════════════════════════════

/// One member's links to an off-slot height, a slot more than one interval
/// above the tip, or a target no next block may include (expired) are not
/// admitted; an open slot near the tip is.
#[test]
fn attestations_outside_the_open_checkpoint_slots_are_not_admitted() {
    let fx = Fx::new();
    let c = fx.chain(70, 70, 0);
    let k = Key::new(6);
    fx.tip_state(&c, &[(k.id(), 1_000)]);
    let pool = PowitPool::new();
    let j = c.justified();

    // Epoch 2 first (KES evolves forward only).
    let expired = k.attest(j, c.cp(48));
    assert!(pool.admit_attestation(expired, &c.dag, &fx.store).is_err(), "expired target (71 > 48 + 20)");
    let open = k.attest(j, c.cp(68));
    pool.admit_attestation(open, &c.dag, &fx.store).expect("an open slot near the tip");
    let off_slot = k.attest(j, c.cp(64));
    assert!(pool.admit_attestation(off_slot, &c.dag, &fx.store).is_err(), "64 is not a checkpoint slot");
    let far = k.attest(j, Checkpoint { height: 78, hash: [0x78; 32] });
    assert!(pool.admit_attestation(far, &c.dag, &fx.store).is_err(), "78 > tip 70 + one interval");
    assert_eq!(pool.counts().1, 1);
}

/// One member holds at most two pending links; a newer target replaces its
/// oldest (the newest checkpoint is the one that can still justify).
#[test]
fn one_witness_holds_at_most_two_pending_attestations() {
    let fx = Fx::new();
    let c = fx.chain(70, 70, 0);
    let k = Key::new(7);
    fx.tip_state(&c, &[(k.id(), 1_000)]);
    let pool = PowitPool::new();
    let j = c.justified();
    for slot in [58, 63, 68, 73] {
        let t = if slot <= 70 { c.cp(slot) } else { Checkpoint { height: slot, hash: [0x73; 32] } };
        let _ = pool.admit_attestation(k.attest(j, t), &c.dag, &fx.store);
    }
    let (_, atts, _) = pool.snapshot();
    let heights: Vec<u64> = atts.iter().map(|a| a.target.height).collect();
    assert_eq!(heights, vec![68, 73], "the two newest targets");
}

// ═════════════════════════════════════════════════════════════════════════════
// Finding 7: the pool follows the tip on every node
// ═════════════════════════════════════════════════════════════════════════════

/// A non-witness node never called `prune`: an attestation admitted at tip
/// 70 stayed after the tip moved past its expiry. The pool now forgets what
/// the new tip made stale before it admits anything against that tip.
#[test]
fn the_pool_forgets_expired_attestations_when_the_tip_moves() {
    let fx = Fx::new();
    let mut c = fx.chain(70, 70, 0);
    let k = Key::new(8);
    fx.tip_state(&c, &[(k.id(), 1_000)]);
    let pool = PowitPool::new();
    let j = c.justified();
    pool.admit_attestation(k.attest(j, c.cp(53)), &c.dag, &fx.store).expect("open at tip 70");

    fx.extend(&mut c, 10, 0);
    fx.tip_state(&c, &[(k.id(), 1_000)]);
    pool.admit_attestation(k.attest(j, c.cp(78)), &c.dag, &fx.store).expect("open at tip 80");
    let (_, atts, _) = pool.snapshot();
    assert_eq!(atts.iter().map(|a| a.target.height).collect::<Vec<_>>(), vec![78],
        "53 expired at tip 80 (81 > 53 + 20)");
}

// ═════════════════════════════════════════════════════════════════════════════
// Finding 8: the witness's vote record
// ═════════════════════════════════════════════════════════════════════════════

const PASSWORD: &str = "correct horse battery staple 42";

struct Witness {
    dir: TempDir,
}

impl Witness {
    fn new(k: &Key) -> Witness {
        let dir = TempDir::new().unwrap();
        KesKeyFile::seal(&k.signer.borrow(), PASSWORD).unwrap().save(&dir.path().join("witness.key")).unwrap();
        std::fs::write(dir.path().join("pw"), format!("{PASSWORD}\n")).unwrap();
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        Witness { dir }
    }
    fn load(&self) -> Result<powit::WitnessDuty, String> {
        let d = self.dir.path();
        powit::WitnessDuty::load(&d.join("witness.key"), &d.join("pw"), vec![0x51], &d.join("data"))
    }
    fn record(&self, k: &Key) -> std::path::PathBuf {
        self.dir.path().join("data").join(format!("powit-votes-{}.json", hex::encode(k.id())))
    }
}

/// A vote record that exists but does not parse was read as "no votes":
/// the witness could sign anything again. It now refuses to load.
#[test]
fn a_corrupt_vote_record_refuses_to_sign() {
    setup();
    let k = Key::new(9);
    let w = Witness::new(&k);
    std::fs::write(w.record(&k), b"{ not json").unwrap();
    let err = w.load().err().expect("a corrupt vote record is refused");
    assert!(err.contains("vote record"), "{err}");
}

/// A witness signed slot 68 on chain A; its vote record is then lost (a
/// failover onto a fresh data directory). After a reorg onto chain B, whose
/// slot 68 is another block, it signed slot 68 again: a double vote that
/// bars the key. The highest heights it signed are kept with the key and
/// enforced, so it does not.
#[test]
fn a_reset_vote_record_cannot_cause_a_double_vote() {
    let fx = Fx::new();
    let k = Key::new(10);
    let a = fx.chain(70, 60, 1);
    let b = fx.chain(70, 60, 2);
    assert_ne!(a.cp(68), b.cp(68));
    fx.tip_state(&a, &[(k.id(), 1_000)]);
    fx.tip_state(&b, &[(k.id(), 1_000)]);
    let w = Witness::new(&k);

    let duty = w.load().unwrap();
    let first = duty.maybe_attest(&a.dag, &fx.store).unwrap().expect("signs slot 68 on A");
    assert_eq!(first.target, a.cp(68));
    drop(duty);
    std::fs::remove_file(w.record(&k)).unwrap();

    let duty = w.load().unwrap();
    let second = duty.maybe_attest(&b.dag, &fx.store);
    if let Ok(Some(att)) = &second {
        let ev = Equivocation { a: first.clone(), b: att.clone() };
        assert!(ev.verify(CHAIN, &TESTNET_PARAMS, ACT).is_err(), "signed a double vote after the reset");
    }
}
