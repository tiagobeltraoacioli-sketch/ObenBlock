//! PoCI ledger storage beside the PoWit state (ObenBlock): the configuration
//! in force, the ones before it, the bans and the absence-pruning ledger
//! (pruned keys, pending rejoins, included votes) survive a store round trip
//! (`powit/poci/<block>`, `powit/pocihist/<node id>`), each history node is
//! stored once, two branches that put the same configuration in force after
//! different ones each reload their own history, and a state without PoCI
//! (GnB) stores no PoCI row.

use std::collections::BTreeMap;

use gnb::core::powit::poci::{Ban, PociState, OBB_REGTEST_POCI};
use gnb::core::powit::{Checkpoint, KeyId, PowitState};
use gnb::storage::Storage;

fn weights(n: u8, w: u128) -> BTreeMap<KeyId, u128> {
    (1..=n).map(|i| ([i; 20], w * u128::from(i))).collect()
}

fn cp(h: u64) -> Checkpoint {
    Checkpoint { height: h, hash: [h as u8; 32] }
}

#[test]
fn poci_ledger_round_trips_through_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(&dir.path().join("db")).unwrap();
    let pp = OBB_REGTEST_POCI;

    let mut st = PowitState::genesis(0, [0; 32]);
    gnb::powit::save_state(&store, &[1; 32], &st).unwrap();
    let back = gnb::powit::load_state(&store, &[1; 32]).unwrap();
    assert!(back.poci.is_none(), "no PoCI row for a state without PoCI");
    assert!(store.get_meta(&format!("powit/poci/{}", hex::encode([1u8; 32]))).unwrap().is_none());

    let mut ledger = PociState::launch(&pp, &weights(4, 100)).unwrap();
    st.poci = Some(ledger.clone());
    gnb::powit::save_state(&store, &[2; 32], &st).unwrap();
    assert_eq!(gnb::powit::load_state(&store, &[2; 32]).unwrap(), st);

    // A handoff and a pending ban: the new head is stored, the old one shared.
    let f = cp(pp.opening(5));
    ledger.bans.insert([3; 20], vec![Ban { config_id: ledger.config().id(), included_at: 90, start: None }]);
    assert!(ledger.finalized(&pp, &f, |_, _| weights(3, 7)).unwrap());
    assert_eq!(ledger.bans[&[3u8; 20]][0].start, Some(5));
    st.poci = Some(ledger.clone());
    gnb::powit::save_state(&store, &[3; 32], &st).unwrap();
    let back = gnb::powit::load_state(&store, &[3; 32]).unwrap();
    assert_eq!(back, st);
    let bl = back.poci.as_ref().unwrap();
    assert_eq!(bl.history().count(), 2);
    assert_eq!(bl.config().epoch(), 5);
    assert!(bl.config().weight(&[3; 20]).is_none(), "banned at the handoff");
    // The earlier block still loads its own ledger.
    assert_eq!(gnb::powit::load_state(&store, &[2; 32]).unwrap().poci.unwrap().config().epoch(), 4);
}

#[test]
fn absence_pruning_ledger_round_trips_through_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(&dir.path().join("db")).unwrap();
    let pp = OBB_REGTEST_POCI;
    let mut st = PowitState::genesis(0, [0; 32]);
    let mut ledger = PociState::launch(&pp, &weights(4, 100)).unwrap();
    // Keys 1..=3 vote in every epoch; key 4 never does.
    for e in 4..=8u64 {
        for k in 1..=3u8 {
            ledger.record_vote(&pp, &[k; 20], pp.opening(e) + 2);
        }
        assert!(ledger.finalized(&pp, &cp(pp.opening(e + 1)), |_, _| weights(4, 100)).unwrap());
    }
    assert_eq!(ledger.config().epoch(), 9);
    assert_eq!(ledger.pruned.get(&[4; 20]).map(|p| p.start), Some(8), "an entry since 4, nothing included");
    assert!(ledger.config().weight(&[4; 20]).is_none());
    // A pending rejoin and some included votes above the finalized checkpoint.
    let at = pp.opening(9) + 3;
    ledger.admit_rejoin(at, pp.opening(9), 9, &[4; 20], 9, || true).unwrap();
    ledger.record_vote(&pp, &[1; 20], at);
    assert!(!ledger.seen.is_empty());
    st.poci = Some(ledger.clone());
    gnb::powit::save_state(&store, &[7; 32], &st).unwrap();
    let back = gnb::powit::load_state(&store, &[7; 32]).unwrap();
    assert_eq!(back, st, "pruned keys, rejoins and included votes reload");
    let bl = back.poci.unwrap();
    assert_eq!(bl.rejoins.get(&[4; 20]), Some(&at));
    assert_eq!(bl.seen, ledger.seen);
    // The reloaded ledger goes on exactly as the one in memory.
    let (mut a, mut b) = (ledger, bl);
    for l in [&mut a, &mut b] {
        assert!(l.finalized(&pp, &cp(pp.opening(10)), |_, _| weights(4, 100)).unwrap());
    }
    assert_eq!(a, b);
    assert_eq!(a.config().weight(&[4; 20]), Some(400), "back after the rejoin is final");
}

/// Two branches reach the same configuration through different handoffs:
/// each block reads back its own chain's history, whatever was stored first
/// (evidence naming a past configuration is valid only where it was in
/// force). Found by both B2 and B4.
#[test]
fn branches_with_the_same_configuration_keep_their_own_history() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(&dir.path().join("db")).unwrap();
    let pp = OBB_REGTEST_POCI;
    let launch = PociState::launch(&pp, &weights(4, 100)).unwrap();
    // Branch A hands off 4 -> 5 -> 6; branch B skips: 4 -> 6. Both compute the
    // same C_6 (same weights), after different configurations.
    let mut a = launch.clone();
    assert!(a.finalized(&pp, &cp(pp.opening(5)), |_, _| weights(4, 50)).unwrap());
    assert!(a.finalized(&pp, &cp(pp.opening(6)), |_, _| weights(4, 60)).unwrap());
    let mut b = launch;
    assert!(b.finalized(&pp, &cp(pp.opening(6) + 5), |_, _| weights(4, 60)).unwrap());
    assert_eq!(a.config().id(), b.config().id());
    assert_ne!(a.history().count(), b.history().count());
    let mut st = PowitState::genesis(0, [0; 32]);
    st.poci = Some(a.clone());
    gnb::powit::save_state(&store, &[0xA; 32], &st).unwrap();
    st.poci = Some(b.clone());
    gnb::powit::save_state(&store, &[0xB; 32], &st).unwrap();
    let la = gnb::powit::load_state(&store, &[0xA; 32]).unwrap().poci.unwrap();
    let lb = gnb::powit::load_state(&store, &[0xB; 32]).unwrap().poci.unwrap();
    assert_eq!(la, a);
    assert_eq!(lb, b);
    assert_eq!(la.history().map(|c| c.epoch()).collect::<Vec<_>>(), vec![6, 5, 4]);
    assert_eq!(lb.history().map(|c| c.epoch()).collect::<Vec<_>>(), vec![6, 4]);
    let c5 = a.history().nth(1).unwrap().id();
    assert!(la.find_config(&c5).is_some() && lb.find_config(&c5).is_none());
}

/// Review finding (LOW): the acceptance pipeline stored a full copy of the
/// PoCI ledger per block (`powit/poci/<block>`). Staged with its selected
/// parent (`powit::stage_state`), a block now stores a small diff of the
/// ledger (`powit/pocir/<block>`) and no whole-ledger row; every block's
/// state reloads exactly after the store is reopened, on both branches of
/// a fork.
#[test]
fn poci_ledger_is_stored_as_diffs_and_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pp = OBB_REGTEST_POCI;
    let hash = |n: u64| {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h[31] = 0xC3;
        h
    };
    let mut expected = Vec::new();
    {
        let store = Storage::open(&dir.path().join("db")).unwrap();
        let mut st = PowitState::genesis(0, [0; 32]);
        let mut ledger = PociState::launch(&pp, &weights(8, 100)).unwrap();
        let first = pp.opening(4) + 1;
        let mut parent: Option<[u8; 32]> = None;
        for (i, height) in (first..first + 3 * pp.epoch_len).enumerate() {
            ledger.record_vote(&pp, &[(i % 8) as u8 + 1; 20], height);
            ledger.trim_seen(pp.epoch_of(height));
            st.poci = Some(ledger.clone());
            let h = hash(i as u64);
            let mut batch = rocksdb::WriteBatch::default();
            gnb::powit::stage_state(&store, &mut batch, &h, parent.as_ref(), &st).unwrap();
            store.write_batch(batch).unwrap();
            assert!(store.get_meta(&format!("powit/poci/{}", hex::encode(h))).unwrap().is_none(),
                "no whole-ledger row per block");
            assert!(store.get_meta(&format!("powit/pocir/{}", hex::encode(h))).unwrap().is_some());
            expected.push((h, st.clone()));
            parent = Some(h);
        }
        // A fork from the middle: its own diff chain.
        let (fork_parent, fork_state) = expected[10].clone();
        let mut fl = fork_state.poci.clone().unwrap();
        fl.record_vote(&pp, &[3; 20], first + 11);
        fl.record_vote(&pp, &[4; 20], first + 11);
        let mut fs = fork_state.clone();
        fs.poci = Some(fl);
        let fh = [0xF0; 32];
        let mut batch = rocksdb::WriteBatch::default();
        gnb::powit::stage_state(&store, &mut batch, &fh, Some(&fork_parent), &fs).unwrap();
        store.write_batch(batch).unwrap();
        expected.push((fh, fs));
    }
    let store = Storage::open(&dir.path().join("db")).unwrap();
    for (h, st) in &expected {
        assert_eq!(gnb::powit::load_state(&store, h).as_ref(), Some(st), "{}", hex::encode(&h[..8]));
    }
}
