//! P5-S: differential test of the conservative suite's SLH-DSA-SHAKE-128s
//! (`crypto::slhdsa`, backed by the pinned `fips205` crate) against a second,
//! independent FIPS 205 implementation: RustCrypto's `slh-dsa` (a
//! dev-dependency only, never linked into a build artifact).
//!
//! The two crates share no code (different authors, different hash crate
//! generations: sha3 0.10 vs 0.11). The verifier is the consensus-critical
//! half, so it gets the most cases: on pseudo-random keys, messages and
//! contexts both must accept the production signatures and give the SAME
//! verdict on single-byte and truncation mutations of them, other messages,
//! contexts and keys, and random garbage; a verifier bug in either shows as a
//! disagreement, and the consensus verdict does not depend on which correct
//! implementation a node would link. Key generation must agree byte for byte.
//!
//! RustCrypto's API is generic over the parameter set, so its code is
//! instantiated in this (unoptimized) test crate: a key generation takes
//! about 17 s and a signature about 130 s in the dev profile. Signing
//! agreement is therefore established through the NIST ACVP sigGen vectors,
//! which `tests/acvp_slhdsa.rs` reproduces with `fips205` and RustCrypto's
//! own test suite with `slh-dsa`, and signatures are compared here only
//! through verification.

use gnb_crypto::crypto::{self, slhdsa, SuiteRules};
use slh_dsa::{Shake128s, Signature, SigningKey, VerifyingKey};

/// Deterministic test stream (SplitMix64).
struct Stream(u64);
impl Stream {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// RustCrypto's verdict (pure, with context). A signature of the wrong
/// length is invalid for both (FIPS 205 Algorithm 20, step 1).
fn other_verify(pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::<Shake128s>::try_from(pk) else { return false };
    let Ok(sig) = Signature::<Shake128s>::try_from(sig) else { return false };
    vk.try_verify_with_context(msg, ctx, &sig).is_ok()
}

#[test]
fn key_generation_agrees_on_a_pseudo_random_seed_triple() {
    let mut s = Stream(0x0003_5EED);
    let (sk_seed, sk_prf, pk_seed) = (s.bytes(16), s.bytes(16), s.bytes(16));
    let mut pk = [0u8; slhdsa::PUBLIC_KEY_LEN];
    let mut sk = [0u8; slhdsa::SECRET_KEY_LEN];
    slhdsa::keypair_from_seeds_into(&sk_seed, &sk_prf, &pk_seed, &mut pk, &mut sk).unwrap();
    let other = SigningKey::<Shake128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    assert_eq!(&sk[..], other.to_bytes().as_slice(), "secret keys differ");
    assert_eq!(&pk[..], other.as_ref().to_bytes().as_slice(), "public keys differ");
}

#[test]
fn verifiers_agree_on_valid_signatures_and_every_mutation() {
    let mut s = Stream(0x0003_D1FF);
    for round in 0..2 {
        let (sk_seed, sk_prf, pk_seed) = (s.bytes(16), s.bytes(16), s.bytes(16));
        let mut pk = [0u8; slhdsa::PUBLIC_KEY_LEN];
        let mut sk = [0u8; slhdsa::SECRET_KEY_LEN];
        slhdsa::keypair_from_seeds_into(&sk_seed, &sk_prf, &pk_seed, &mut pk, &mut sk).unwrap();
        let msg_len = (s.next() % 300) as usize;
        let msg = s.bytes(msg_len);
        // Round 0: the consensus form (empty context); round 1: a context.
        let ctx_len = (s.next() % 256) as usize;
        let ctx = if round == 0 { vec![] } else { s.bytes(ctx_len) };
        let opt_rand = s.bytes(16);
        let ours = slhdsa::sign_with_context_and_randomness(&sk, &msg, &ctx, &opt_rand).unwrap();
        assert!(slhdsa::verify_with_context(&pk, &msg, &ours, &ctx));
        assert!(other_verify(&pk, &msg, &ours, &ctx), "round {round}: RustCrypto rejects a fips205 signature");
        if ctx.is_empty() {
            assert!(slhdsa::verify(&pk, &msg, &ours));
        }
        // Same verdict on mutations: R, the FORS part and every hypertree
        // layer (a flip every 197 bytes), truncations and extensions,
        // another message, another context, a flipped key byte.
        let mut checked = 0;
        for i in (0..ours.len()).step_by(197) {
            let mut m = ours.clone();
            m[i] ^= 1 << (i % 8);
            let verdict = slhdsa::verify_with_context(&pk, &msg, &m, &ctx);
            assert_eq!(verdict, other_verify(&pk, &msg, &m, &ctx), "round {round}, byte {i}");
            assert!(!verdict, "round {round}: a mutated signature verified (byte {i})");
            checked += 1;
        }
        assert!(checked >= 40);
        for len in [0, 1, 16, slhdsa::SIGNATURE_LEN - 1, slhdsa::SIGNATURE_LEN + 1] {
            let mut m = ours.clone();
            m.resize(len, 0);
            assert!(!slhdsa::verify_with_context(&pk, &msg, &m, &ctx));
            assert!(!other_verify(&pk, &msg, &m, &ctx));
        }
        let mut other_msg = msg.clone();
        other_msg.push(1);
        assert!(!slhdsa::verify_with_context(&pk, &other_msg, &ours, &ctx));
        assert!(!other_verify(&pk, &other_msg, &ours, &ctx));
        let mut other_ctx = ctx.clone();
        other_ctx.push(1);
        assert!(!slhdsa::verify_with_context(&pk, &msg, &ours, &other_ctx));
        assert!(!other_verify(&pk, &msg, &ours, &other_ctx));
        for i in [0usize, 15, 16, 31] {
            let mut k = pk;
            k[i] ^= 0x80;
            assert!(!slhdsa::verify_with_context(&k, &msg, &ours, &ctx));
            assert!(!other_verify(&k, &msg, &ours, &ctx));
        }
        // Random garbage of the right length.
        let garbage = s.bytes(slhdsa::SIGNATURE_LEN);
        assert!(!slhdsa::verify_with_context(&pk, &msg, &garbage, &ctx));
        assert!(!other_verify(&pk, &msg, &garbage, &ctx));
    }
}

/// The SLH-DSA component of a production conservative transaction signature
/// (suite 0x0003, component 0x03 over its bound message) verifies under the
/// independent implementation too, and only over that message.
#[test]
fn the_slh_dsa_half_of_a_conservative_signature_verifies_independently() {
    let digest = [0x7Du8; 32];
    let (pk, sk) = crypto::generate_conservative_keypair_from_seed_secret(&[0x7E; 32]).unwrap();
    let sig = crypto::sign_bound(&sk, &digest).unwrap();
    assert!(crypto::verify_bound_under(&pk, &digest, &sig, SuiteRules::HARDENING2));
    let h = crypto::SUITE_HEADER_LEN;
    let slh_pk = &pk[h..h + slhdsa::PUBLIC_KEY_LEN];
    let slh_sig = &sig[h..h + slhdsa::SIGNATURE_LEN];
    let msg = crypto::bound_component_message(crypto::SUITE_CONSERVATIVE, crypto::COMPONENT_SLHDSA_SHAKE128S, &digest);
    assert!(other_verify(slh_pk, &msg, slh_sig, &[]));
    let wrong = crypto::bound_component_message(crypto::SUITE_CONSERVATIVE, crypto::COMPONENT_FALCON1024, &digest);
    assert!(!other_verify(slh_pk, &wrong, slh_sig, &[]));
}
