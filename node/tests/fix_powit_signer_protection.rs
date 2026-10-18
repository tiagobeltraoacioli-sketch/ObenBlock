//! PoWit signer protection (docs/DESIGN-obenblock-poci.md §8, §10 rows
//! "crash before/after persisting, before/after signing" and "restored old
//! record, two signer instances"). Local safety, not consensus: it applies to
//! GnB and ObenBlock alike.
//!
//! - Persist before release: the vote entry is on disk (record, then the
//!   high-water file beside the key) before the signature is returned; a
//!   repeated request returns the stored attestation.
//! - Double and surround votes are refused against the record on every path
//!   (duty, CLI, restart, v1 record migration).
//! - Rollback guard: a vote of the key in the chain the record does not hold
//!   halts the signer with an alert (getpowitinfo, persisted).
//! - One active signer per key: the key's and the record's locks refuse a
//!   second instance; a record claimed by another instance halts the first.
//! - Crash points (in process and by aborting `gnb-cli`): no sequence
//!   releases two conflicting votes; the restart is idempotent.
//!
//! Testnet PoWit clock (epochs of 20 blocks, slots every 5), PoWit from
//! height 3, as `fix_powit_pool_dos.rs`.

use gnb::consensus::GhostDAG;
use gnb::core::kes::{KesKeyFile, KesSigner};
use gnb::core::powit::{Attestation, Checkpoint, KeyId, PowitState, TESTNET_PARAMS};
use gnb::core::{self, Block, BlockHeader, ChainId, MerkleRoot};
use gnb::powit;
use gnb::powit_signer::{self, CrashPoint, ObservedVote, Origin, Signed, VoteGuard};
use gnb::storage::Storage;
use tempfile::TempDir;

const ACT: u64 = 3;
const CHAIN: ChainId = ChainId::Testnet;
const PASSWORD: &str = "correct horse battery staple 42";

fn setup() {
    let _ = core::set_node_chain_id(CHAIN);
    let _ = core::set_powit_height_override(ACT);
    assert_eq!(core::node_chain_id(), CHAIN, "one chain id per test binary");
    assert_eq!(core::powit_height(), ACT, "one PoWit activation per test binary");
}

// ── Chains with synthetic PoWit states ───────────────────────────────────────

struct Fx {
    _tmp: TempDir,
    store: Storage,
}

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
        Chain { dag, hashes }
    }

    /// The tip state of `c`: `members` hold weight in every epoch; `links`
    /// are links of a key the chain has included.
    fn tip_state(&self, c: &Chain, members: &[(KeyId, u128)], links: &[(KeyId, Checkpoint, Checkpoint)]) {
        let tip_h = c.hashes.len() as u64 - 1;
        let mut st = PowitState::genesis(ACT, c.hashes[ACT as usize - 1]);
        st.epoch = TESTNET_PARAMS.epoch(ACT, tip_h);
        for e in 0..=st.epoch {
            for (k, w) in members {
                st.epoch_work.entry(e).or_default().insert(*k, *w);
            }
        }
        for (k, s, t) in links {
            st.links.entry(*k).or_default().push((s.height, t.height, t.hash));
        }
        powit::save_state(&self.store, c.hashes.last().unwrap(), &st).unwrap();
    }
}

impl Chain {
    fn cp(&self, slot: u64) -> Checkpoint {
        Checkpoint { height: slot, hash: self.hashes[slot as usize - 1] }
    }
    fn justified(&self) -> Checkpoint {
        self.cp(ACT)
    }
}

// ── Witness files ────────────────────────────────────────────────────────────

struct Witness {
    dir: TempDir,
    id: KeyId,
}

impl Witness {
    fn new(seed: u8) -> Witness {
        let signer = KesSigner::generate(2, [seed; 32], |_| {}).unwrap();
        let dir = TempDir::new().unwrap();
        KesKeyFile::seal(&signer, PASSWORD).unwrap().save(&dir.path().join("witness.key")).unwrap();
        std::fs::write(dir.path().join("pw"), format!("{PASSWORD}\n")).unwrap();
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        Witness { dir, id: signer.public().witness_id() }
    }
    fn key(&self) -> std::path::PathBuf {
        self.dir.path().join("witness.key")
    }
    fn data(&self) -> std::path::PathBuf {
        self.dir.path().join("data")
    }
    fn load(&self) -> Result<powit::WitnessDuty, String> {
        powit::WitnessDuty::load(&self.key(), &self.dir.path().join("pw"), vec![0x51], &self.data())
    }
    fn record(&self) -> std::path::PathBuf {
        powit_signer::record_path(&self.data(), &self.id)
    }
    fn highwater(&self) -> std::path::PathBuf {
        powit_signer::highwater_path(&self.key()).unwrap()
    }
    fn record_v2(&self) -> powit_signer::RecordV2 {
        powit_signer::read_record(&self.record(), &self.id).unwrap().unwrap()
    }
}

/// Two released attestations a valid equivocation proof could be built from.
fn conflicting(a: &Attestation, b: &Attestation) -> bool {
    a.key_id() == b.key_id() && (a.source, a.target) != (b.source, b.target)
        && powit_signer::links_conflict(&a.source, &a.target, &b.source, &b.target)
}

fn assert_no_conflict(released: &[Attestation], what: &str) {
    for (i, a) in released.iter().enumerate() {
        for b in &released[i + 1..] {
            assert!(!conflicting(a, b), "{what}: released {}->{} and {}->{}", a.source.height, a.target.height,
                    b.source.height, b.target.height);
        }
    }
}

// ── 1. Persist before release; idempotent repeats ────────────────────────────

/// The vote is on disk with its signature, and the high-water mark with the
/// link beside the key, when `maybe_attest` returns; a restart releases the
/// same stored attestation once, then nothing.
#[test]
fn a_vote_is_persisted_before_release_and_a_repeat_returns_it() {
    let fx = Fx::new();
    let w = Witness::new(1);
    let a = fx.chain(70, 60, 1);
    fx.tip_state(&a, &[(w.id, 1_000)], &[]);

    let duty = w.load().unwrap();
    let att = duty.maybe_attest(&a.dag, &fx.store).unwrap().expect("signs slot 68");
    assert_eq!((att.source, att.target), (a.justified(), a.cp(68)));
    let rec = w.record_v2();
    assert_eq!(rec.format, powit_signer::RECORD_FORMAT);
    assert_eq!(rec.instance, hex::encode(duty.guard().instance()));
    assert_eq!(rec.votes.len(), 1);
    assert_eq!(rec.votes[0].origin, Origin::Signed);
    assert_eq!(rec.votes[0].attestation.as_deref(), Some(hex::encode(att.to_wire_bytes()).as_str()));
    let hw: powit_signer::HighWater = serde_json::from_slice(&std::fs::read(w.highwater()).unwrap()).unwrap();
    assert_eq!((hw.source, hw.target, hw.last), (ACT, 68, Some((att.source, att.target))));
    assert!(duty.maybe_attest(&a.dag, &fx.store).unwrap().is_none(), "signed once: waits for inclusion");
    drop(duty);

    let duty = w.load().unwrap();
    let again = duty.maybe_attest(&a.dag, &fx.store).unwrap().expect("a restart releases the stored vote once");
    assert_eq!(again, att, "the stored attestation, not a new signature");
    assert!(duty.maybe_attest(&a.dag, &fx.store).unwrap().is_none());
    assert_eq!(w.record_v2().votes.len(), 1, "nothing new recorded");
}

// ── 2. Double and surround votes refused on every path ──────────────────────

fn signer_of(seed: u8) -> std::cell::RefCell<KesSigner> {
    std::cell::RefCell::new(KesSigner::generate(2, [seed; 32], |_| {}).unwrap())
}

fn sign_with(s: &std::cell::RefCell<KesSigner>, src: Checkpoint, tgt: Checkpoint) -> Result<Attestation, String> {
    let e = TESTNET_PARAMS.epoch(ACT, tgt.height);
    let mut s = s.borrow_mut();
    if e > s.epoch() {
        s.evolve_to(e)?;
    }
    Attestation::sign(CHAIN, src, tgt, &s)
}

fn cp(h: u64, tag: u8) -> Checkpoint {
    Checkpoint { height: h, hash: [tag; 32] }
}

/// The guard refuses a double vote, a surround vote (either way) and any
/// link at or below its high-water mark; the same request returns the stored
/// attestation without calling the signer.
#[test]
fn the_guard_refuses_double_and_surround_votes() {
    setup();
    let w = Witness::new(2);
    let s = signer_of(2);
    let g = VoteGuard::open(w.id, &w.key(), &w.record()).unwrap();
    let first = match g.sign_link(cp(23, 1), cp(48, 1), None, || sign_with(&s, cp(23, 1), cp(48, 1))).unwrap() {
        Signed::Fresh(a) => a,
        other => panic!("{other:?}"),
    };
    let repeat = g.sign_link(cp(23, 1), cp(48, 1), None, || panic!("must not sign again")).unwrap();
    assert!(matches!(repeat, Signed::Stored { ref att, .. } if *att == first), "{repeat:?}");
    for (src, tgt, what) in [
        (cp(23, 1), cp(48, 2), "double vote"),
        (cp(3, 1), cp(68, 1), "surrounds the recorded link"),
        (cp(28, 1), cp(43, 1), "surrounded by the recorded link"),
        (cp(18, 1), cp(53, 1), "source below the high-water source"),
    ] {
        let r = g.sign_link(src, tgt, None, || panic!("{what}: must not reach the signer"));
        assert!(r.is_err(), "{what}: {r:?}");
    }
    // A later, compatible link is signed.
    assert!(matches!(g.sign_link(cp(48, 1), cp(53, 1), None, || sign_with(&s, cp(48, 1), cp(53, 1))).unwrap(),
                     Signed::Fresh(_)));
}

/// A v1 record (a bare array of links) is read, migrated to v2 at start,
/// and its links keep refusing conflicts; a repeat of a v1 link releases
/// nothing (no signature was kept).
#[test]
fn a_v1_record_is_migrated_and_still_enforced() {
    setup();
    let w = Witness::new(3);
    std::fs::write(w.record(), serde_json::to_vec(&vec![(cp(3, 9), cp(28, 9))]).unwrap()).unwrap();
    let g = VoteGuard::open(w.id, &w.key(), &w.record()).unwrap();
    let rec = w.record_v2();
    assert_eq!(rec.votes.len(), 1);
    assert_eq!(rec.votes[0].origin, Origin::Legacy);
    assert_eq!((rec.highwater.source, rec.highwater.target), (3, 28));
    assert_eq!(g.sign_link(cp(3, 9), cp(28, 9), None, || panic!("no re-sign")).unwrap(),
               Signed::RecordedWithoutSignature);
    assert!(g.sign_link(cp(3, 9), cp(28, 1), None, || panic!("double vote")).is_err());
}

// ── 3. Rollback guard ────────────────────────────────────────────────────────

/// An old record is restored (backup from before a vote, together with the
/// old high-water file) and the vote it lost is in the chain: the duty stops
/// signing at start, reports the alert (getpowitinfo, persisted), and after
/// the operator clears it the adopted vote is still refused against.
#[test]
fn a_restored_old_record_halts_signing_with_an_alert() {
    let fx = Fx::new();
    let w = Witness::new(4);
    let a = fx.chain(70, 60, 1);
    let b = fx.chain(70, 60, 2);
    fx.tip_state(&a, &[(w.id, 1_000)], &[]);

    drop(w.load().unwrap());
    let backup_rec = std::fs::read(w.record()).unwrap();
    let backup_hw = std::fs::read(w.highwater()).unwrap();
    let duty = w.load().unwrap();
    let att = duty.maybe_attest(&a.dag, &fx.store).unwrap().expect("signs slot 68 on A");
    drop(duty);
    // Restore the backup; the vote was included on A, and B's view also
    // knows it (it was gossiped and included there too).
    std::fs::write(w.record(), &backup_rec).unwrap();
    std::fs::write(w.highwater(), &backup_hw).unwrap();
    fx.tip_state(&b, &[(w.id, 1_000)], &[(w.id, att.source, att.target)]);

    let duty = w.load().unwrap();
    let alert = duty.scan_for_rollback(&b.dag, &fx.store).expect("the start scan halts the signer");
    assert!(alert.contains("does not hold"), "{alert}");
    assert!(duty.maybe_attest(&b.dag, &fx.store).unwrap().is_none(), "halted: nothing is signed");
    let info = powit::info_json(&b.dag, &fx.store);
    assert_eq!(info["signer_halted"], true);
    let me = info["signers"].as_array().unwrap().iter()
        .find(|s| s["key"] == hex::encode(w.id)).expect("listed").clone();
    assert_eq!(me["halted"], true);
    let rec = w.record_v2();
    assert!(rec.alert.is_some(), "the alert is persisted");
    assert!(rec.votes.iter().any(|v| v.origin == Origin::Foreign && v.target == att.target), "adopted");
    drop(duty);

    // A restart stays halted, even without the chain.
    let duty = w.load().unwrap();
    assert!(duty.guard().alert().is_some());
    assert!(duty.maybe_attest(&b.dag, &fx.store).unwrap().is_none());
    // The operator clears it: B's slot 68 (a double vote) is still refused.
    duty.guard().clear_alert().unwrap();
    assert!(duty.maybe_attest(&b.dag, &fx.store).unwrap().is_none(), "the adopted vote bars B's slot 68");
    assert!(duty.guard().alert().is_none());
}

/// A pool vote of this key (with its source hash) the record lacks, and an
/// equivocation proof against the key, each halt the guard; a vote the
/// record holds, or one below the high-water mark, does not.
#[test]
fn pool_votes_and_evidence_halt_the_guard() {
    setup();
    let w = Witness::new(5);
    let s = signer_of(5);
    let g = VoteGuard::open(w.id, &w.key(), &w.record()).unwrap();
    g.sign_link(cp(23, 1), cp(48, 1), None, || sign_with(&s, cp(23, 1), cp(48, 1))).unwrap();
    let ov = |sh: u64, th: u64, tag: u8| ObservedVote { source_height: sh, source_hash: Some([1; 32]),
                                                         target: cp(th, tag) };
    assert_eq!(g.observe(&[ov(23, 48, 1)], false, "pool"), None, "its own vote");
    assert_eq!(g.observe(&[ov(3, 28, 7)], false, "pool"), None, "below the high-water mark");
    assert!(g.observe(&[ov(23, 53, 7)], false, "pool").is_some(), "a newer vote it never signed");
    drop(g);
    let w2 = Witness::new(6);
    let g2 = VoteGuard::open(w2.id, &w2.key(), &w2.record()).unwrap();
    assert!(g2.observe(&[], true, "pool").unwrap().contains("equivocation proof"));
}

// ── 4. One active signer per key ─────────────────────────────────────────────

/// A second duty for the same key file, or for the same record through a
/// copy of the key file, refuses to start while the first runs.
#[test]
fn a_second_signer_instance_refuses_to_start() {
    setup();
    let w = Witness::new(7);
    let first = w.load().unwrap();
    let err = w.load().err().expect("same key file: refused");
    assert!(err.contains("another signer instance"), "{err}");
    // A copy of the key file in another directory, the same data directory.
    let other = TempDir::new().unwrap();
    std::fs::copy(w.key(), other.path().join("witness.key")).unwrap();
    let err = powit::WitnessDuty::load(&other.path().join("witness.key"), &w.dir.path().join("pw"), vec![0x51],
                                       &w.data()).err().expect("same record: refused");
    assert!(err.contains("another signer instance"), "{err}");
    drop(first);
    assert!(w.load().is_ok(), "free again once the first stops");
}

/// Where the lock does not hold (two hosts sharing storage), the record
/// claimed by another instance halts the first signer before its next vote.
#[test]
fn a_record_claimed_by_another_instance_halts_the_signer() {
    setup();
    let w = Witness::new(8);
    let s = signer_of(8);
    let g = VoteGuard::open(w.id, &w.key(), &w.record()).unwrap();
    let mut rec = w.record_v2();
    rec.instance = hex::encode([0xEE; 16]);
    rec.votes.push(powit_signer::VoteEntry { source: cp(3, 1), target: cp(28, 1), config_id: None,
        attestation: None, origin: Origin::Signed, instance: Some(rec.instance.clone()) });
    std::fs::write(w.record(), serde_json::to_vec(&rec).unwrap()).unwrap();
    let r = g.sign_link(cp(28, 1), cp(48, 1), None, || sign_with(&s, cp(28, 1), cp(48, 1)));
    assert!(r.unwrap_err().contains("another signer instance"));
    assert!(g.alert().is_some());
    assert!(g.votes().iter().any(|v| v.target == cp(28, 1)), "the other instance's vote is adopted");
}

// ── 5. Crash points ──────────────────────────────────────────────────────────

/// For every crash point of the duty's signing path: crash while signing A's
/// slot 68, restart, then try A's slot 68 again and B's slot 68 (a double
/// vote). The released attestations never conflict; once the vote reached
/// the record, the restart releases exactly the stored attestation.
#[test]
fn no_crash_point_releases_two_conflicting_votes() {
    let fx = Fx::new();
    let a = fx.chain(70, 60, 1);
    let b = fx.chain(70, 60, 2);
    for (i, p) in [CrashPoint::BeforeSign, CrashPoint::AfterSign, CrashPoint::AfterRecord, CrashPoint::AfterPersist]
        .into_iter().enumerate()
    {
        let w = Witness::new(20 + i as u8);
        fx.tip_state(&a, &[(w.id, 1_000)], &[]);
        fx.tip_state(&b, &[(w.id, 1_000)], &[]);
        let mut released = Vec::new();
        let duty = w.load().unwrap();
        duty.set_crash_point(Some(p));
        assert!(duty.maybe_attest(&a.dag, &fx.store).is_err(), "{p:?}: crashed");
        drop(duty); // the process dies: only the files remain

        let persisted = std::fs::read(w.record()).ok()
            .and_then(|_| powit_signer::read_record(&w.record(), &w.id).unwrap())
            .and_then(|r| r.votes.first().and_then(|v| v.attestation.clone()));
        let duty = w.load().unwrap();
        // B first: if A's vote is persisted, B's slot 68 must be refused.
        if let Some(att) = duty.maybe_attest(&b.dag, &fx.store).unwrap() {
            released.push(att);
        }
        if let Some(att) = duty.maybe_attest(&a.dag, &fx.store).unwrap() {
            released.push(att);
        }
        drop(duty);
        let duty = w.load().unwrap();
        for c in [&a, &b] {
            if let Some(att) = duty.maybe_attest(&c.dag, &fx.store).unwrap() {
                released.push(att);
            }
        }
        assert_no_conflict(&released, &format!("{p:?}"));
        match p {
            CrashPoint::BeforeSign | CrashPoint::AfterSign => assert!(persisted.is_none(), "{p:?}: nothing recorded"),
            CrashPoint::AfterRecord | CrashPoint::AfterPersist => {
                let stored = persisted.expect("recorded");
                assert!(released.iter().all(|r| hex::encode(r.to_wire_bytes()) == stored),
                        "{p:?}: only the stored attestation is ever released");
                assert!(!released.is_empty(), "{p:?}: the restart releases it");
            }
        }
    }
}

// ── gnb-cli powitattest ──────────────────────────────────────────────────────

fn cli(key: &std::path::Path, src: Checkpoint, tgt: Checkpoint, extra: &[&str], crash: Option<&str>)
    -> std::process::Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_gnb-cli"));
    cmd.args(["--rpc-port", "1", "powitattest", key.to_str().unwrap(), "testnet", &src.height.to_string(),
              &hex::encode(src.hash), &tgt.height.to_string(), &hex::encode(tgt.hash), &ACT.to_string()])
        .args(extra)
        .env("GNB_WALLET_PASSWORD", PASSWORD)
        .env_remove(powit_signer::CRASH_ENV);
    if let Some(c) = crash {
        cmd.env(powit_signer::CRASH_ENV, c);
    }
    cmd.output().unwrap()
}

fn released(out: &std::process::Output) -> Option<Attestation> {
    if !out.status.success() {
        return None;
    }
    let bytes = hex::decode(String::from_utf8_lossy(&out.stdout).trim()).ok()?;
    Attestation::read_wire(&mut std::io::Cursor::new(bytes.as_slice())).ok()
}

/// The CLI records its vote, prints the stored attestation for a repeat,
/// refuses a double vote, refuses without a node unless `--offline`, and
/// refuses while another signer holds the key.
#[test]
fn powitattest_is_protected() {
    setup();
    let w = Witness::new(30);
    let key = w.key();
    let out = cli(&key, cp(3, 1), cp(48, 1), &[], None);
    assert!(!out.status.success(), "no node, no --offline: refused");
    assert!(String::from_utf8_lossy(&out.stderr).contains("rollback guard"));

    let first = released(&cli(&key, cp(3, 1), cp(48, 1), &["--offline"], None)).expect("signs");
    let repeat = released(&cli(&key, cp(3, 1), cp(48, 1), &["--offline"], None)).expect("repeat");
    assert_eq!(first, repeat, "a repeat prints the stored attestation");
    let double = cli(&key, cp(3, 1), cp(48, 2), &["--offline"], None);
    assert!(!double.status.success(), "double vote refused");
    // Record in the key's directory by default.
    let rec = powit_signer::read_record(&powit_signer::record_path(w.dir.path(), &w.id), &w.id).unwrap().unwrap();
    assert_eq!(rec.votes.len(), 1);

    // A running signer (the node's duty) holds the key: the CLI refuses.
    let duty = w.load().unwrap();
    let busy = cli(&key, cp(48, 1), cp(53, 1), &["--offline"], None);
    assert!(String::from_utf8_lossy(&busy.stderr).contains("another signer instance"), "{busy:?}");
    drop(duty);
    // The high-water file beside the key carries the CLI's vote to the duty's
    // record directory: a double vote there is refused too.
    let data = w.data();
    let d = cli(&key, cp(3, 1), cp(48, 3), &["--offline", data.to_str().unwrap()], None);
    assert!(!d.status.success(), "the duty's record directory: refused by the high-water mark");
}

/// `gnb-cli powitattest` aborted (SIGABRT, a real crash) at every crash
/// point, then run again with the same request and with a conflicting one:
/// the outputs never hold two conflicting votes, and once the vote reached
/// the record the repeat prints exactly the stored attestation.
#[test]
fn powitattest_crash_points_never_release_conflicting_votes() {
    setup();
    for (i, point) in ["before_sign", "after_sign", "after_record", "after_persist"].into_iter().enumerate() {
        let w = Witness::new(40 + i as u8);
        let key = w.key();
        let mut out = Vec::new();
        let crashed = cli(&key, cp(3, 1), cp(48, 1), &["--offline"], Some(point));
        assert!(!crashed.status.success() && crashed.stdout.is_empty(), "{point}: aborted before printing");
        let record = powit_signer::record_path(w.dir.path(), &w.id);
        let stored = powit_signer::read_record(&record, &w.id).unwrap()
            .and_then(|r| r.votes.first().and_then(|v| v.attestation.clone()));
        out.extend(released(&cli(&key, cp(3, 1), cp(48, 2), &["--offline"], None)));
        out.extend(released(&cli(&key, cp(3, 1), cp(48, 1), &["--offline"], None)));
        assert_no_conflict(&out, point);
        match point {
            "after_record" | "after_persist" => {
                let s = stored.unwrap_or_else(|| panic!("{point}: recorded"));
                assert_eq!(out.len(), 1, "{point}: only the repeat succeeds");
                assert_eq!(hex::encode(out[0].to_wire_bytes()), s, "{point}: the stored attestation");
            }
            _ => {
                assert!(stored.is_none(), "{point}: nothing recorded");
                assert_eq!(out.len(), 1, "{point}: the first request after the crash is signed, the other refused");
            }
        }
    }
}
