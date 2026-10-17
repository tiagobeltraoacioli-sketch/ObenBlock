//! P5-S: measured cost of the conservative suite 0x0003 (SLH-DSA-SHAKE-128s
//! AND Falcon-1024) against the hybrid suite 0x0001 (ML-DSA-65 AND
//! Falcon-1024), the numbers `docs/CONSENSUS.md` ("Conservative suite
//! 0x0003", "Cost") and the relay token price (`node/src/mempool/relay.rs`,
//! `CONSERVATIVE_VERIFY_TOKENS`) are derived from.
//!
//! `measure_suite_costs` prints the timings (run it with `--ignored
//! --nocapture`; for production numbers in a release build, `cargo test
//! --release -p gnb-crypto --test conservative_suite_cost -- --ignored
//! --nocapture`: a dev build with only some crypto packages optimized
//! overstates the hybrid verification about threefold). The non-ignored test bounds the conservative
//! verification time so a regression (an unoptimized or pathological build of
//! the verifier) fails CI instead of slowing block validation unnoticed.

use std::time::{Duration, Instant};

use gnb_crypto::crypto::{self, SuiteRules};

fn time<T>(n: u32, mut f: impl FnMut() -> T) -> Duration {
    let start = Instant::now();
    for _ in 0..n {
        std::hint::black_box(f());
    }
    start.elapsed() / n
}

#[test]
#[ignore = "timing probe: prints the per-suite costs (cargo test --test conservative_suite_cost -- --ignored --nocapture)"]
fn measure_suite_costs() {
    let digest = [0x5Au8; 32];
    let (hpk, hsk) = crypto::generate_keypair_from_seed_secret(&[0x11; 32]).unwrap();
    let (cpk, csk) = crypto::generate_conservative_keypair_from_seed_secret(&[0x11; 32]).unwrap();
    let keygen_h = time(3, || crypto::generate_keypair_secret());
    let keygen_c = time(3, || crypto::generate_conservative_keypair_secret().unwrap());
    let hsig = crypto::sign_bound(&hsk, &digest).unwrap();
    let csig = crypto::sign_bound(&csk, &digest).unwrap();
    let sign_h = time(5, || crypto::sign_bound(&hsk, &digest).unwrap());
    let sign_c = time(3, || crypto::sign_bound(&csk, &digest).unwrap());
    let verify_h = time(200, || assert!(crypto::verify_bound_under(&hpk, &digest, &hsig, SuiteRules::HARDENING2)));
    let verify_c = time(50, || assert!(crypto::verify_bound_under(&cpk, &digest, &csig, SuiteRules::HARDENING2)));
    println!("hybrid 0x0001:       pk {} B, sig {} B, keygen {:?}, sign {:?}, verify {:?}",
        hpk.len(), hsig.len(), keygen_h, sign_h, verify_h);
    println!("conservative 0x0003: pk {} B, sig {} B, keygen {:?}, sign {:?}, verify {:?}",
        cpk.len(), csig.len(), keygen_c, sign_c, verify_c);
    println!("verify ratio conservative / hybrid: {:.2}", verify_c.as_secs_f64() / verify_h.as_secs_f64());
}
