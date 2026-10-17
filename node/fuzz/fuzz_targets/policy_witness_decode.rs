#![no_main]
//! Policy witnesses are canonical: anything the strict decoder accepts must
//! re-encode to exactly the same bytes (one witness byte string per signature
//! set), and decoding must never panic.
//!
//! P5-S: the same under the rules of the second hardening height
//! (conservative suite-0x0003 keys, 10 KiB signatures), which only widen
//! what decodes: whatever decodes under the earlier rules decodes to the same
//! value under them.
use libfuzzer_sys::fuzz_target;
use gnb::core::policy::{PolicyWitness, SpendPolicy};
use gnb::crypto::SuiteRules;

fuzz_target!(|data: &[u8]| {
    let legacy = PolicyWitness::decode(data);
    let hardening2 = PolicyWitness::decode_under(data, SuiteRules::HARDENING2);
    if let Ok(w) = &legacy {
        assert_eq!(w.encode(), data, "accepted witness must be canonical");
        assert!(w.encode().len() <= gnb::core::MAX_SCRIPT_SIG_LEN, "the decoder cap covers every witness");
        assert_eq!(hardening2.as_ref().ok(), Some(w), "the second hardening rules only widen decoding");
    }
    if let Ok(w) = &hardening2 {
        assert_eq!(w.encode(), data, "accepted witness must be canonical");
        assert!(w.encode().len() <= gnb::core::MAX_SCRIPT_SIG_LEN, "the decoder cap covers every witness");
    }
    let legacy = SpendPolicy::decode(data);
    let hardening2 = SpendPolicy::decode_under(data, SuiteRules::HARDENING2);
    if let Ok(p) = &legacy {
        assert_eq!(p.encode(), data, "accepted policy must be canonical");
        assert_eq!(hardening2.as_ref().ok(), Some(p), "the second hardening rules only widen decoding");
    }
    if let Ok(p) = &hardening2 {
        assert_eq!(p.encode(), data, "accepted policy must be canonical");
    }
});
