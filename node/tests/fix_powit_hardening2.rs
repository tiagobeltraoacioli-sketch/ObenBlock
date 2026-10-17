//! PoWit at the second hardening activation, node side (PoWit audit
//! findings 1 and 4): every producer and every admission path judges an item
//! by the rules of the block that may include it.
//!
//! - The witness duty (main.rs) signs the message of its target's height
//!   (v2, committing its key, from the activation) and is a member under the
//!   rules of the next block (every key with weight from the activation, the
//!   64 heaviest before): at the target heights H-1 and H, and with the next
//!   block on either side of H, its attestation is admitted by the pool (the
//!   path of gossip and of the `submitpowititem` RPC, `powit::admit_item`),
//!   taken by the template and accepted by consensus (`powit::block_state`).
//! - `gnb-cli powitattest` signs on its chain's schedule.
//! - The pool holds an equivocation proof only against a member of the next
//!   block's evidence epochs (the consensus rule), refuses forged
//!   (re-rooted) attestations as invalid signatures (penalised in gossip),
//!   and templates' proofs pass consensus.
//!
//! This binary runs on the testnet PoWit clock with PoWit active from
//! height 3 (process-wide, once per binary); each test sets the second
//! hardening height on its own thread (`activation::scoped_override_v2`).

use gnb::consensus::GhostDAG;
use gnb::core::kes::{KesKeyFile, KesPublic, KesSigner};
use gnb::core::powit::{Attestation, Checkpoint, Equivocation, KeyId, PowitBody, PowitState, TESTNET_PARAMS,
                       MAINNET_PARAMS};
use gnb::core::{self, activation, Block, BlockHeader, ChainId, MerkleRoot};
use gnb::powit::{self, PowitPool};
use gnb::storage::Storage;
use sha3::{Digest, Sha3_256};
use tempfile::TempDir;

const ACT: u64 = 3;
const CHAIN: ChainId = ChainId::Testnet;
const P: gnb::core::powit::PowitParams = TESTNET_PARAMS;
const NEVER: u64 = activation::NEVER;

fn setup() {
    let _ = core::set_node_chain_id(CHAIN);
    let _ = core::set_powit_height_override(ACT);
    assert_eq!(core::node_chain_id(), CHAIN, "one chain id per test binary");
    assert_eq!(core::powit_height(), ACT, "one PoWit activation per test binary");
}

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ── A selected chain in a GhostDAG + store, with a synthetic PoWit state ─────

struct Fx {
    _tmp: TempDir,
    store: Storage,
    dag: GhostDAG,
    hashes: Vec<[u8; 32]>,
}

fn mk_block(parent: [u8; 32], h: u64) -> Block {
    Block {
        header: BlockHeader {
            version: 1, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
            timestamp: 1_000 + h, bits: core::POW_LIMIT_BITS, nonce: h,
        },
        transactions: vec![],
        blue_score: h,
        height: h,
        shielded_transactions: vec![],
        powit: Default::default(),
    }
}

impl Fx {
    /// A chain of `tip_h` blocks whose tip state has `work` (epoch, key,
    /// weight) and is justified at the activation checkpoint.
    fn new(tip_h: u64, work: &[(u64, KeyId, u128)]) -> Fx {
        setup();
        let tmp = TempDir::new().unwrap();
        let store = Storage::open(&tmp.path().join("db")).unwrap();
        let genesis = mk_block([0u8; 32], 0);
        let gh = genesis.block_hash();
        store.put_block(&genesis).unwrap();
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(gh, genesis.header.timestamp);
        let mut hashes = vec![gh];
        for h in 1..=tip_h {
            let b = mk_block(hashes[h as usize - 1], h);
            let bh = b.block_hash();
            store.put_block(&b).unwrap();
            dag.add_block(bh, vec![hashes[h as usize - 1]], b.header.timestamp, 1).unwrap();
            hashes.push(bh);
        }
        let mut st = PowitState::genesis(ACT, hashes[ACT as usize - 1]);
        st.epoch = P.epoch(ACT, tip_h);
        for (e, k, w) in work {
            *st.epoch_work.entry(*e).or_default().entry(*k).or_insert(0) += *w;
        }
        powit::save_state(&store, hashes.last().unwrap(), &st).unwrap();
        Fx { _tmp: tmp, store, dag, hashes }
    }
    fn tip(&self) -> [u8; 32] {
        *self.hashes.last().unwrap()
    }
    fn tip_h(&self) -> u64 {
        self.hashes.len() as u64 - 1
    }
    fn cp(&self, slot: u64) -> Checkpoint {
        Checkpoint { height: slot, hash: self.hashes[slot as usize - 1] }
    }
    fn justified(&self) -> Checkpoint {
        self.cp(ACT)
    }
    /// Consensus on a next block carrying `body`: its PoWit state.
    fn next_block_state(&self, body: PowitBody) -> Result<PowitState, String> {
        let mut b = mk_block(self.tip(), self.tip_h() + 1);
        b.powit = body;
        powit::block_state(&b, &b.block_hash(), &self.dag, &self.store).map(|s| s.expect("PoWit active"))
    }
}

/// Work in every epoch up to the tip's for each key.
fn steady(keys: &[(KeyId, u128)], tip_h: u64) -> Vec<(u64, KeyId, u128)> {
    (0..=P.epoch(ACT, tip_h)).flat_map(|e| keys.iter().map(move |(k, w)| (e, *k, *w))).collect()
}

// ── Witness keys ─────────────────────────────────────────────────────────────

const PASSWORD: &str = "correct horse battery staple 42";

/// A genuine KES key (depth 2: epochs 0..=3, heights 3..=82) and a witness
/// node directory holding it sealed, as `gnb-cli witnesskeygen` leaves it.
struct Witness {
    dir: TempDir,
    id: KeyId,
    signer: KesSigner,
}

impl Witness {
    fn new(seed: u8) -> Witness {
        let signer = KesSigner::generate(2, [seed; 32], |_| {}).unwrap();
        let dir = TempDir::new().unwrap();
        KesKeyFile::seal(&signer, PASSWORD).unwrap().save(&dir.path().join("witness.key")).unwrap();
        std::fs::write(dir.path().join("pw"), format!("{PASSWORD}\n")).unwrap();
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        Witness { dir, id: signer.public().witness_id(), signer }
    }
    fn duty(&self) -> powit::WitnessDuty {
        let d = self.dir.path();
        powit::WitnessDuty::load(&d.join("witness.key"), &d.join("pw"), vec![0x51], &d.join("data")).unwrap()
    }
    /// Sign `source -> target` with the leaf of the target's epoch (the
    /// in-memory signer; tests sign epochs in order).
    fn sign(&mut self, h2: u64, source: Checkpoint, target: Checkpoint) -> Attestation {
        let e = P.epoch(ACT, target.height);
        if e > self.signer.epoch() {
            self.signer.evolve_to(e).unwrap();
        }
        Attestation::sign_at(CHAIN, h2, source, target, &self.signer).unwrap()
    }
}

fn v2(a: &Attestation) -> bool {
    a.verify_signature_at(CHAIN, &P, ACT, 0)
}

fn v1(a: &Attestation) -> bool {
    a.verify_signature_at(CHAIN, &P, ACT, NEVER)
}

// ═════════════════════════════════════════════════════════════════════════════
// Producers
// ═════════════════════════════════════════════════════════════════════════════

/// The witness duty at tip 70 signs slot 68 (the newest slot at or below the
/// next height, 71). With the second hardening activation at 68 (target =
/// H), 69 (target = H-1, next block above H) and 72 (target and next block
/// below H) its attestation carries the message of the target's height,
/// passes the pool (`admit_item`, the gossip and RPC path), is taken by the
/// template and is accepted by consensus in the next block.
#[test]
fn the_witness_duty_signs_what_the_including_block_accepts() {
    for (h2, want_v2) in [(68u64, true), (69, false), (72, false)] {
        let _g = activation::scoped_override_v2(h2);
        let w = Witness::new(1 + h2 as u8);
        let fx = Fx::new(70, &steady(&[(w.id, 1_000)], 70));
        let att = w.duty().maybe_attest(&fx.dag, &fx.store).unwrap().expect("a member signs slot 68");
        assert_eq!(att.target, fx.cp(68));
        assert_eq!((v2(&att), v1(&att)), (want_v2, !want_v2), "H={h2}: the message of the target's height");

        let pool = PowitPool::new();
        pool.admit_attestation(att.clone(), &fx.dag, &fx.store).unwrap_or_else(|e| panic!("H={h2}: pool: {e}"));
        let body = powit::template_body(&pool, &fx.dag, &fx.store, fx.tip(), 71);
        assert_eq!(body.attestations, vec![att.clone()], "H={h2}: the template takes it");
        let st = fx.next_block_state(body).unwrap_or_else(|e| panic!("H={h2}: consensus: {e}"));
        assert!(st.votes.values().any(|v| v.contains_key(&w.id)) || st.justified == fx.cp(68), "H={h2}: counted");
    }
}

/// From the activation every key with weight is a witness: the duty of a key
/// outside the 64 heaviest signs (and consensus counts its vote) at H, and
/// does not below H (it is no member under the old rule).
#[test]
fn the_witness_duty_follows_the_membership_rule_of_the_next_block() {
    let w = Witness::new(90);
    let mut keys: Vec<(KeyId, u128)> = (0..70u8).map(|i| ([0xA0 ^ i; 20], 10_000)).collect();
    keys.push((w.id, 1));
    let work = steady(&keys, 70);
    {
        let _g = activation::scoped_override_v2(72);
        let fx = Fx::new(70, &work);
        assert!(w.duty().maybe_attest(&fx.dag, &fx.store).unwrap().is_none(), "below H: not in the 64 heaviest");
    }
    let _g = activation::scoped_override_v2(71);
    let fx = Fx::new(70, &work);
    let att = w.duty().maybe_attest(&fx.dag, &fx.store).unwrap().expect("from H: every key with weight");
    let pool = PowitPool::new();
    pool.admit_attestation(att.clone(), &fx.dag, &fx.store).unwrap();
    let body = powit::template_body(&pool, &fx.dag, &fx.store, fx.tip(), 71);
    let st = fx.next_block_state(body).unwrap();
    // Its weight in W(3): one unit in each of epochs 0 and 1.
    assert_eq!(st.votes[&fx.cp(68)].get(&w.id), Some(&2));
}

/// Liveness of the uncapped witness set: from the activation a slot may take
/// longer than one interval to justify (32 votes per block, any number of
/// share keys), and a justified checkpoint is final only once its direct
/// child is justified, so the duty votes for that child (justified + one
/// interval) while a block can still include the vote, else the newest slot.
/// Before the activation it always votes for the newest slot.
#[test]
fn from_the_activation_the_duty_votes_for_the_justified_checkpoints_child() {
    let cases = [
        // (justified slot, H2, slot the duty signs at tip 70 / next 71)
        (58u64, 72u64, 68u64), // old rule: the newest slot
        (58, 71, 63),          // child 63, includable until 83
        (53, 71, 58),          // child 58, includable until 78
        (43, 71, 68),          // child 48 expired (71 > 68): the newest
    ];
    for (i, (j, h2, want)) in cases.into_iter().enumerate() {
        let _g = activation::scoped_override_v2(h2);
        let w = Witness::new(100 + i as u8);
        let fx = Fx::new(70, &steady(&[(w.id, 1_000)], 70));
        let mut st = powit::load_state(&fx.store, &fx.tip()).unwrap();
        st.justified = fx.cp(j);
        powit::save_state(&fx.store, &fx.tip(), &st).unwrap();
        let att = w.duty().maybe_attest(&fx.dag, &fx.store).unwrap().expect("signs");
        assert_eq!((att.source, att.target), (fx.cp(j), fx.cp(want)), "justified {j}, H={h2}");
        let pool = PowitPool::new();
        pool.admit_attestation(att.clone(), &fx.dag, &fx.store).unwrap();
        let body = powit::template_body(&pool, &fx.dag, &fx.store, fx.tip(), 71);
        assert_eq!(body.attestations, vec![att], "justified {j}, H={h2}: includable");
        let next = fx.next_block_state(body).unwrap();
        if want == j + P.checkpoint_interval {
            assert_eq!((next.justified, next.finalized), (fx.cp(want), fx.cp(j)), "the child's justification finalizes");
        }
    }
}

/// A duty that may no longer sign the child (its record holds a vote for a
/// later slot, e.g. one signed under the old rule just before the activation)
/// votes for the newest slot instead of not voting at all.
#[test]
fn the_duty_falls_back_to_the_newest_slot_when_it_cannot_sign_the_child() {
    let _g = activation::scoped_override_v2(0);
    let w = Witness::new(110);
    let fx = Fx::new(75, &steady(&[(w.id, 1_000)], 75));
    let mut st = powit::load_state(&fx.store, &fx.tip()).unwrap();
    st.justified = fx.cp(58);
    powit::save_state(&fx.store, &fx.tip(), &st).unwrap();
    let record = w.dir.path().join("data").join(format!("powit-votes-{}.json", hex::encode(w.id)));
    std::fs::write(&record, serde_json::to_vec(&vec![(fx.cp(58), fx.cp(68))]).unwrap()).unwrap();
    let att = w.duty().maybe_attest(&fx.dag, &fx.store).unwrap().expect("signs the newest slot");
    assert_eq!((att.source, att.target), (fx.cp(58), fx.cp(73)), "child 63 is below the signed 68");
}

/// `gnb-cli powitattest` signs on the schedule of the chain it names: testnet
/// (second hardening from genesis) the v2 message, mainnet (not scheduled)
/// the v1 message.
#[test]
fn powitattest_signs_on_its_chains_schedule() {
    let run = |net: &str, key: &std::path::Path, src: u64, tgt: u64| -> Attestation {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_gnb-cli"))
            .args(["powitattest", key.to_str().unwrap(), net, &src.to_string(), &hex::encode([1u8; 32]),
                   &tgt.to_string(), &hex::encode([2u8; 32]), &ACT.to_string()])
            .env("GNB_WALLET_PASSWORD", PASSWORD)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let hex_att = String::from_utf8(out.stdout).unwrap();
        let bytes = hex::decode(hex_att.trim()).unwrap();
        Attestation::read_wire(&mut std::io::Cursor::new(bytes.as_slice())).unwrap()
    };
    let testnet = Witness::new(70);
    let a = run("testnet", &testnet.dir.path().join("witness.key"), ACT, 43);
    assert!(v2(&a) && !v1(&a), "testnet: v2");
    let mainnet = Witness::new(71);
    let b = run("mainnet", &mainnet.dir.path().join("witness.key"), ACT, 63);
    assert!(b.verify_signature_at(ChainId::Mainnet, &MAINNET_PARAMS, ACT, NEVER), "mainnet: v1");
    assert!(!b.verify_signature_at(ChainId::Mainnet, &MAINNET_PARAMS, ACT, 0));
}

// ═════════════════════════════════════════════════════════════════════════════
// Pool admission from the activation
// ═════════════════════════════════════════════════════════════════════════════

fn double(w: &mut Witness, fx: &Fx, h2: u64, slot: u64) -> Equivocation {
    let j = fx.justified();
    let a = w.sign(h2, j, fx.cp(slot));
    let b = w.sign(h2, j, Checkpoint { height: slot, hash: [0xEE; 32] });
    Equivocation { a, b }
}

/// The pool holds a proof only against a member of the next block's
/// evidence epochs (E-1..=E+1, the consensus rule) and refuses others
/// before their signatures (`EVIDENCE_NOT_A_WITNESS`, the deliverer's
/// budget charge kept); the proof it holds is taken by the template and
/// bars the key in consensus.
#[test]
fn the_pool_holds_proofs_only_against_witnesses_of_the_evidence_epochs() {
    let _g = activation::scoped_override_v2(0);
    let mut m = Witness::new(20);
    let mut outsider = Witness::new(21);
    let mut later = Witness::new(22);
    let mut next_only = Witness::new(23);
    // Next block 71: epoch 3, evidence epochs 2..=4 (W(2..=4) count epochs
    // 0..=2). `later` has work only in epoch 3: a member of W(5) only.
    // `next_only` has work only in epoch 2: a member of W(4) = W(E+1) only
    // (the old node-local rule looked at W(E-4..=E) and refused it).
    let mut work = steady(&[(m.id, 1_000)], 70);
    work.push((3, later.id, 1_000));
    work.push((2, next_only.id, 1_000));
    let fx = Fx::new(70, &work);
    let pool = PowitPool::new();
    for w in [&mut outsider, &mut later] {
        let ev = double(w, &fx, 0, 68);
        assert_eq!(pool.admit_evidence(ev, &fx.dag, &fx.store).unwrap_err(), powit::EVIDENCE_NOT_A_WITNESS);
    }
    let ev = double(&mut m, &fx, 0, 68);
    assert_eq!(pool.admit_evidence(ev.clone(), &fx.dag, &fx.store).unwrap(), m.id);
    let ev_next = double(&mut next_only, &fx, 0, 68);
    assert_eq!(pool.admit_evidence(ev_next.clone(), &fx.dag, &fx.store).unwrap(), next_only.id,
        "a member of W(E+1) is provable in consensus, so the pool holds its proof");
    let body = powit::template_body(&pool, &fx.dag, &fx.store, fx.tip(), 71);
    assert_eq!(body.evidence.len(), 2);
    assert_eq!(body.evidence[0], ev, "the heavier key's proof first");
    let st = fx.next_block_state(body).unwrap();
    assert!(st.is_banned(&m.id, 3) && st.is_banned(&next_only.id, 3), "the template's proofs bar the keys in consensus");
}

/// Finding 1 in gossip: a member's leaf signature re-rooted into another
/// member's (depth, root) is a valid attestation by that other key before
/// the activation; from it the message commits the key, so the pool refuses
/// it as an invalid signature, a context-free fault that ingress penalises.
#[test]
fn a_rerooted_attestation_is_an_invalid_signature_from_hardening2() {
    let reroot = |a: &Attestation, sibling: [u8; 32]| {
        let mut a = a.clone();
        let leaf = sha3(&[b"GNB-KES-v1/pk", &a.sig.leaf_pk]);
        // depth-2 path: replace the top sibling, keep the leaf's own level.
        a.sig.path[1] = sibling;
        let i = a.sig.index;
        let l1 = if i & 1 == 0 { sha3(&[b"GNB-KES-v1/node", &leaf, &a.sig.path[0]]) }
                 else { sha3(&[b"GNB-KES-v1/node", &a.sig.path[0], &leaf]) };
        let root = if (i >> 1) & 1 == 0 { sha3(&[b"GNB-KES-v1/node", &l1, &sibling]) }
                   else { sha3(&[b"GNB-KES-v1/node", &sibling, &l1]) };
        a.witness = KesPublic { depth: 2, root };
        a
    };
    for (h2, label) in [(NEVER, "old regime"), (0, "hardening 2")] {
        let _g = activation::scoped_override_v2(h2);
        let mut w = Witness::new(30 + (h2 == 0) as u8);
        let probe = reroot(&w.sign(h2, Checkpoint { height: ACT, hash: [0; 32] }, Checkpoint { height: 68, hash: [0; 32] }),
                           [0x77; 32]);
        let fake_id = probe.key_id();
        let fx = Fx::new(70, &steady(&[(w.id, 1_000), (fake_id, 1_000)], 70));
        let forged = reroot(&w.sign(h2, fx.justified(), fx.cp(68)), [0x77; 32]);
        assert_eq!(forged.key_id(), fake_id);
        let pool = PowitPool::new();
        let r = pool.admit_attestation(forged, &fx.dag, &fx.store);
        if h2 == NEVER {
            assert!(r.is_ok(), "{label}: the forgery is a valid vote by the other key: {r:?}");
        } else {
            let e = r.unwrap_err();
            assert_eq!(e, gnb::ingress::POWIT_BAD_ATTESTATION_SIGNATURE, "{label}");
            assert!(gnb::ingress::powit_admit_error_fault(powit::ITEM_ATTESTATION, &e).is_some(),
                "{label}: penalised as a context-free fault");
        }
    }
}

/// The `submitpowititem` RPC and gossip admit through `powit::admit_item`
/// (the node's single pool): a v2 attestation and a member's proof are
/// admitted from the activation, a re-rooted one is not.
#[test]
fn admit_item_follows_the_rules_of_the_target_height() {
    let _g = activation::scoped_override_v2(0);
    let mut w = Witness::new(40);
    let fx = Fx::new(70, &steady(&[(w.id, 1_000)], 70));
    let att = w.sign(0, fx.justified(), fx.cp(68));
    let (_, kind, data) = powit::attestation_item(&att);
    powit::admit_item(kind, &data, &fx.dag, &fx.store).unwrap();
    let ev = double(&mut w, &fx, 0, 68);
    let (_, kind, data) = powit::evidence_item(&ev);
    powit::admit_item(kind, &data, &fx.dag, &fx.store).unwrap();
    let mut bad = att.clone();
    bad.witness.root[0] ^= 1;
    let (_, kind, data) = powit::attestation_item(&bad);
    assert!(powit::admit_item(kind, &data, &fx.dag, &fx.store).is_err());
}
