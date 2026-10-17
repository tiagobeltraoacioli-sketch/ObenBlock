//! CRY-4: the node's long-lived secrets live in secret memory.
//!
//! A node's own code keeps two secrets for its whole run besides wallet
//! keys: its P2P post-quantum identity key (`transport::identity::
//! PqIdentity`) and, on a witness, the password that re-opens the KES key
//! file at every epoch (`powit::WitnessDuty`). (Two more live as long as
//! the node or a connection but are not in secret memory, documented in
//! docs/RUNNING.md "Secret key memory": the libp2p Ed25519 identity key,
//! which libp2p holds itself, and each connection's ChaCha20-Poly1305
//! stream keys, `Zeroizing` as Bitcoin Core's BIP324 session keys are
//! ordinary memory.) Both were plain heap buffers (`Zeroizing`):
//! wiped on drop, but swappable to disk and in core dumps. Like Bitcoin
//! Core's `secure_allocator` (`LockedPoolManager`: `mlock`, `MADV_DONTDUMP`,
//! `memory_cleanse` before release) they now live in `gnb_secret::
//! SecretBytes` regions, counted by `gnb_secret::locked_memory()`.
//!
//! One test only: the region counters are process-wide, so nothing else in
//! this binary may allocate secrets concurrently.

use gnb::core::kes::{KesKeyFile, KesSigner};
use gnb::powit::WitnessDuty;
use gnb::transport::identity::PqIdentity;
use gnb_secret::test_support::Quarantine;

const PASSWORD: &str = "correct horse battery staple 42";

/// Live secret regions (locked or not).
fn live_regions() -> usize {
    let m = gnb_secret::locked_memory();
    m.locked_regions + m.unlocked_regions
}

#[test]
fn long_lived_node_secrets_live_in_secret_memory() {
    // (A test quarantine keeps released regions counted until it ends, so
    // the counters are read outside one.)
    // P2P identity: its secret key is one secret region while it lives.
    let base = live_regions();
    let id = PqIdentity::generate().unwrap();
    assert_eq!(live_regions(), base + 1, "the identity's secret key is a SecretBytes region");
    let sig = id.sign(b"m").unwrap();
    assert!(gnb::crypto::verify_enveloped_canonical(id.public_key(), b"m", &sig));
    drop(id);
    assert_eq!(live_regions(), base, "released with the identity");
    let q = Quarantine::start();
    drop(PqIdentity::generate().unwrap());
    assert!(!q.released().is_empty() && q.all_released_zeroed(), "a dropped identity left secret bytes behind");
    drop(q);

    // The identity file round trip keeps the key in secret memory too.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("p2p_pq_identity.bin");
    let a = PqIdentity::load_or_create(&path).unwrap();
    let b = PqIdentity::load_or_create(&path).unwrap();
    assert_eq!(a.public_key(), b.public_key());
    assert_eq!(live_regions(), base + 2);
    drop((a, b));
    assert_eq!(live_regions(), base);

    // Witness duty: the KES seed and the key-file password, two regions.
    let signer = KesSigner::generate(1, [0x33; 32], |_| {}).unwrap();
    KesKeyFile::seal(&signer, PASSWORD).unwrap().save(&dir.path().join("witness.key")).unwrap();
    drop(signer);
    std::fs::write(dir.path().join("pw"), format!("{PASSWORD}\n")).unwrap();
    std::fs::create_dir_all(dir.path().join("data")).unwrap();
    let load = || WitnessDuty::load(&dir.path().join("witness.key"), &dir.path().join("pw"), vec![0x51],
        &dir.path().join("data")).unwrap();
    assert_eq!(live_regions(), base);
    let duty = load();
    assert_eq!(live_regions(), base + 2, "the witness's KES seed and its key-file password are SecretBytes");
    drop(duty);
    assert_eq!(live_regions(), base);
    let q = Quarantine::start();
    drop(load());
    assert!(!q.released().is_empty() && q.all_released_zeroed(), "a dropped witness duty left secret bytes behind");
}
