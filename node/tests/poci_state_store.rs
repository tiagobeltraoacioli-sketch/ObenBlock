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
