//! Growth cap storage beside the PoWit state (ObenBlock,
//! docs/DESIGN-obenblock.md §6.3): the admitted credit per key per window
//! epoch survives a store round trip as content-addressed segments in the
//! per-epoch store (`powit/epoch/<digest>`), each ledger is stored once
//! (`powit/capl/<id>`) however many blocks share it, each block stores only
//! its ledger id and first-block bits (`powit/cap/<block>`), a corrupt
//! ledger row loads nothing, and a GnB state stores no growth cap row.

use std::collections::BTreeMap;

use gnb::core::powit::growth_cap::{CapLedger, CapState, EpochMap, GROWTH_DIV, G_MIN_DIV};
use gnb::core::powit::{KeyId, PowitState};
use gnb::storage::Storage;

const EASY_BITS: u32 = 0x207F_FFFF;

fn work(n: u64) -> EpochMap {
    (1..=5u8).map(|i| ([i; 20], 10 * u128::from(i) + u128::from(n))).collect::<BTreeMap<KeyId, u128>>()
}

fn ledger_at(to: u64) -> CapLedger {
    let hist: BTreeMap<u64, EpochMap> = (0..to).map(|n| (n, work(n))).collect();
    CapLedger::empty()
        .advance(to, 20, 3, GROWTH_DIV, G_MIN_DIV, &|n| hist.get(&n), &|_| Some(EASY_BITS), &|_, _| false)
        .unwrap()
}

fn rows(store: &Storage, prefix: &str) -> usize {
    store.scan_meta_prefix(prefix).unwrap().len()
}

#[test]
fn growth_cap_ledger_round_trips_through_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::open(&dir.path().join("db")).unwrap();

    // GnB: no growth cap row.
    let gnb_state = PowitState::genesis(0, [0; 32]);
    gnb::powit::save_state(&store, &[1; 32], &gnb_state).unwrap();
    assert!(gnb::powit::load_state(&store, &[1; 32]).unwrap().cap.is_none());
    assert!(store.get_meta(&format!("powit/cap/{}", hex::encode([1u8; 32]))).unwrap().is_none());

    // Two blocks under one ledger, a third after a handoff.
    let led6 = ledger_at(6);
    assert!(led6.credits().len() >= 3 && led6.report().is_some());
    let mut st = PowitState::genesis(0, [0; 32]);
    st.cap = Some(CapState { ledger: led6.clone(), first_bits: [(5, EASY_BITS), (6, EASY_BITS)].into() });
    gnb::powit::save_state(&store, &[2; 32], &st).unwrap();
    st.cap.as_mut().unwrap().first_bits.insert(7, 0x1D00_FFFF);
    gnb::powit::save_state(&store, &[3; 32], &st).unwrap();
    let ledger_key = format!("powit/capl/{}", hex::encode(led6.id()));
    assert!(store.get_meta(&ledger_key).unwrap().is_some());

    let back2 = gnb::powit::load_state(&store, &[2; 32]).unwrap();
    assert_eq!(back2.cap.as_ref().unwrap().ledger, led6);
    assert_eq!(back2.cap.as_ref().unwrap().first_bits.len(), 2);
    let back3 = gnb::powit::load_state(&store, &[3; 32]).unwrap();
    assert_eq!(back3, st);

    let led7 = ledger_at(7);
    assert_ne!(led7.id(), led6.id());
    st.cap.as_mut().unwrap().ledger = led7.clone();
    gnb::powit::save_state(&store, &[4; 32], &st).unwrap();
    assert_eq!(gnb::powit::load_state(&store, &[4; 32]).unwrap(), st);
    // The earlier blocks still load their own ledger.
    assert_eq!(gnb::powit::load_state(&store, &[2; 32]).unwrap().cap.unwrap().ledger.epoch(), 6);
    assert_eq!(rows(&store, "powit/capl/"), 2, "one row per ledger, not per block");
    assert_eq!(rows(&store, "powit/cap/"), 3);

    // A ledger row that does not match its id loads nothing (a ledger never
    // loaded before, so no in-memory cache answers for it).
    let led9 = ledger_at(9);
    st.cap.as_mut().unwrap().ledger = led9.clone();
    gnb::powit::save_state(&store, &[5; 32], &st).unwrap();
    let k9 = format!("powit/capl/{}", hex::encode(led9.id()));
    let mut b9 = store.get_meta(&k9).unwrap().unwrap();
    let l9 = b9.len() - 1;
    b9[l9] ^= 1;
    let mut b = rocksdb::WriteBatch::default();
    store.stage_meta(&mut b, &k9, &b9).unwrap();
    store.write_batch(b).unwrap();
    assert!(gnb::powit::load_state(&store, &[5; 32]).is_none(), "corrupt ledger row");
}
