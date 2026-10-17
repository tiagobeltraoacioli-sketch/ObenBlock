#![no_main]
//! Single-key witnesses: parsing is exact (no trailing bytes) and canonical,
//! and the consensus verifier never panics on arbitrary key/signature bytes.
//!
//! P5-S: the same under the rules of the second hardening height (the
//! conservative suite 0x0003), which only add a suite: every witness that is
//! canonical under the earlier rules is canonical under them, and every
//! signature they accept the earlier rules' verifier accepted or never knew.
use libfuzzer_sys::fuzz_target;
use gnb::core::Transaction;
use gnb::crypto::SuiteRules;

const DIGEST: &[u8; 32] = b"fuzz-sighash-32-bytes-0000000000";

fuzz_target!(|data: &[u8]| {
    if let Some((sig, pk)) = Transaction::parse_script_sig(data) {
        assert_eq!(Transaction::build_script_sig(&sig, &pk), data, "parse must be exact");
        let _ = gnb::crypto::verify_canonical(&pk, DIGEST, &sig);
    }
    let legacy = gnb::core::sighash::canonical_witness_under(data, SuiteRules::LEGACY);
    let hardening2 = gnb::core::sighash::canonical_witness_under(data, SuiteRules::HARDENING2);
    if let Ok((sig, pk)) = legacy {
        assert_eq!(hardening2, Ok((sig, pk)), "the second hardening rules only add a suite");
    }
    if let Ok((sig, pk)) = hardening2 {
        let new = gnb::crypto::verify_bound_under(pk, DIGEST, sig, SuiteRules::HARDENING2);
        let old = gnb::crypto::verify_bound_under(pk, DIGEST, sig, SuiteRules::LEGACY);
        assert!(!old || new, "a signature valid under the earlier rules stays valid");
        if new && !old {
            assert!(gnb::crypto::is_conservative_public_key(pk), "only the conservative suite is new");
        }
    }
});
