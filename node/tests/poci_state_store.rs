//! PoCI ledger storage beside the PoWit state (ObenBlock): the configuration
//! in force, the ones before it and the bans survive a store round trip
//! (`powit/poci/<block>`, `powit/pocicfg/<config id>`), each configuration is
//! stored once, and a state without PoCI (GnB) stores no PoCI row.

use std::collections::BTreeMap;

use gnb::core::powit::poci::{Ban, PociState, OBB_REGTEST_POCI};
use gnb::core::powit::{Checkpoint, KeyId, PowitState};
use gnb::storage::Storage;

fn weights(n: u8, w: u128) -> BTreeMap<KeyId, u128> {
    (1..=n).map(|i| ([i; 20], w * u128::from(i))).collect()
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
    let f = Checkpoint { height: pp.opening(5), hash: [5; 32] };
    ledger.bans.insert([3; 20], vec![Ban { config_id: ledger.config().id(), included_at: 90, start: None }]);
    assert!(ledger.finalized(&pp, &f, |_| weights(3, 7)).unwrap());
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

/// Two forks reach the same configuration through different handoffs (one
/// hands off at epochs 5 and 6, the other skips 5): each block reads back
/// its own chain's history, whatever was stored first (evidence naming a
/// past configuration is valid only where it was in force).
#[test]
fn forks_with_the_same_configuration_keep_their_own_histories() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(&dir.path().join("db")).unwrap();
    let pp = OBB_REGTEST_POCI;
    let launch = PociState::launch(&pp, &weights(4, 100)).unwrap();
    let cp = |e: u64| Checkpoint { height: pp.opening(e), hash: [e as u8; 32] };

    let mut a = launch.clone();
    assert!(a.finalized(&pp, &cp(5), |_| weights(4, 50)).unwrap());
    assert!(a.finalized(&pp, &cp(6), |_| weights(3, 9)).unwrap());
    let mut b = launch.clone();
    assert!(b.finalized(&pp, &cp(6), |_| weights(3, 9)).unwrap());
    assert_eq!(a.config().id(), b.config().id(), "the same configuration in force");
    assert_ne!(a.history().count(), b.history().count());

    let mut st = PowitState::genesis(0, [0; 32]);
    st.poci = Some(a.clone());
    gnb::powit::save_state(&store, &[0xA; 32], &st).unwrap();
    st.poci = Some(b.clone());
    gnb::powit::save_state(&store, &[0xB; 32], &st).unwrap();
    let ids = |s: &PociState| s.history().map(|c| c.id()).collect::<Vec<_>>();
    let back_a = gnb::powit::load_state(&store, &[0xA; 32]).unwrap().poci.unwrap();
    let back_b = gnb::powit::load_state(&store, &[0xB; 32]).unwrap().poci.unwrap();
    assert_eq!(ids(&back_a), ids(&a));
    assert_eq!(ids(&back_b), ids(&b));
    let c5 = a.history().nth(1).unwrap().id();
    assert!(back_a.find_config(&c5).is_some() && back_b.find_config(&c5).is_none());
}
