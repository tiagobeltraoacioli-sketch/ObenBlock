//! P5-S: the official NIST ACVP SLH-DSA-SHAKE-128s vectors (FIPS 205) against
//! the conservative suite's SLH-DSA component (`crypto::slhdsa`, the pinned
//! `fips205` crate). See vectors/ACVP-SLHDSA-PROVENANCE.md for the exact
//! source and scope.
//!
//! * keyGen (10 cases): `slhdsa::keypair_from_seeds_into` (FIPS 205
//!   Algorithm 18) reproduces every official key pair, byte for byte.
//! * sigGen, pure external interface (14 cases, deterministic and hedged,
//!   with contexts): `slhdsa::sign_with_context_and_randomness` (Algorithm 22)
//!   reproduces every official signature (compared by SHA-256), and
//!   `slhdsa::verify_with_context` accepts it.
//! * sigGen, internal interface (14 cases): the dependency's
//!   `slh_sign_internal` (Algorithm 19) reproduces every official signature.
//! * sigVer, pure external interface (14 cases, 2 valid): the production
//!   verifier gives every official verdict, wrong lengths included.
//! * sigVer, internal interface (14 cases): the dependency's
//!   `slh_verify_internal` gives every official verdict.
//!
//! The consensus verifier is `slhdsa::verify` (empty context); the official
//! valid empty-context cases (sigVer tcId 343, sigGen tcId 215 and 530) are
//! checked through it, and every positive with a non-empty context must be
//! REJECTED by it (the context is bound).

use gnb_crypto::crypto::slhdsa;
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("vectors/acvp-slhdsa-shake128s.json");
const FIXTURE_SHA256: &str = "fe1ee7daa6f985255e41735fb23afadfddd9cee473c4e3ab6df79ceb689dfd00";

fn fixture() -> Value {
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)), FIXTURE_SHA256, "the vendored ACVP fixture was edited");
    let v: Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(v["parameterSet"], "SLH-DSA-SHAKE-128s");
    assert_eq!(v["source"], "usnistgov/ACVP-Server@975de31eb83d87039ec88934fdc47d8c312b892d");
    v
}

fn cases(mode: &str) -> Vec<Value> {
    fixture()[mode].as_array().unwrap().clone()
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap_or("")).unwrap()
}

#[test]
fn keygen_reproduces_every_official_key_pair() {
    let cases = cases("keyGen");
    assert_eq!(cases.len(), 10);
    for case in cases {
        let mut pk = [0u8; slhdsa::PUBLIC_KEY_LEN];
        let mut sk = [0u8; slhdsa::SECRET_KEY_LEN];
        slhdsa::keypair_from_seeds_into(
            &bytes(&case, "skSeed"), &bytes(&case, "skPrf"), &bytes(&case, "pkSeed"), &mut pk, &mut sk,
        ).unwrap();
        assert_eq!(pk.to_vec(), bytes(&case, "pk"), "ACVP keyGen tcId {} (pk)", case["tcId"]);
        assert_eq!(sk.to_vec(), bytes(&case, "sk"), "ACVP keyGen tcId {} (sk)", case["tcId"]);
    }
}

#[test]
fn pure_signing_reproduces_every_official_signature() {
    let pure: Vec<Value> = cases("sigGen").into_iter()
        .filter(|c| c["signatureInterface"] == "external" && c["preHash"] == "pure").collect();
    assert_eq!(pure.len(), 14);
    let mut empty_context = 0;
    for case in pure {
        let (sk, pk) = (bytes(&case, "sk"), bytes(&case, "pk"));
        let (msg, ctx) = (bytes(&case, "message"), bytes(&case, "context"));
        let opt_rand = if case["deterministic"] == true {
            pk[..slhdsa::N].to_vec() // FIPS 205: the deterministic variant signs with PK.seed
        } else {
            bytes(&case, "additionalRandomness")
        };
        let sig = slhdsa::sign_with_context_and_randomness(&sk, &msg, &ctx, &opt_rand).unwrap();
        assert_eq!(sig.len(), case["signatureLen"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(Sha256::digest(&sig)), case["signatureSha256"].as_str().unwrap(),
            "ACVP sigGen tcId {}", case["tcId"]);
        assert!(slhdsa::verify_with_context(&pk, &msg, &sig, &ctx), "tcId {}", case["tcId"]);
        if ctx.is_empty() {
            empty_context += 1;
            assert!(slhdsa::verify(&pk, &msg, &sig), "consensus verifier, tcId {}", case["tcId"]);
        } else {
            assert!(!slhdsa::verify(&pk, &msg, &sig), "the empty-context verifier must reject tcId {}", case["tcId"]);
        }
    }
    assert_eq!(empty_context, 2, "tcId 215 (deterministic) and 530 (hedged)");
}

/// A rand_core 0.6 RNG that yields one fixed buffer (the vector's
/// `additionalRandomness`).
struct Fixed(Vec<u8>);
impl rand_core_06::RngCore for Fixed {
    fn next_u32(&mut self) -> u32 { unimplemented!() }
    fn next_u64(&mut self) -> u64 { unimplemented!() }
    fn fill_bytes(&mut self, dest: &mut [u8]) { self.try_fill_bytes(dest).unwrap() }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        dest.copy_from_slice(&self.0[..dest.len()]);
        Ok(())
    }
}
impl rand_core_06::CryptoRng for Fixed {}

#[test]
#[allow(deprecated)] // fips205 exposes the internal interface only for these NIST vectors
fn internal_signing_reproduces_every_official_signature() {
    use fips205::slh_dsa_shake_128s::PrivateKey;
    use fips205::traits::{SerDes, Signer};
    let internal: Vec<Value> = cases("sigGen").into_iter()
        .filter(|c| c["signatureInterface"] == "internal").collect();
    assert_eq!(internal.len(), 14);
    for case in internal {
        let sk = PrivateKey::try_from_bytes(&bytes(&case, "sk").try_into().unwrap()).unwrap();
        let hedged = case["deterministic"] == false;
        let mut rng = Fixed(if hedged { bytes(&case, "additionalRandomness") } else { vec![0; 16] });
        let sig = sk._test_only_raw_sign(&mut rng, &bytes(&case, "message"), hedged).unwrap();
        assert_eq!(hex::encode(Sha256::digest(sig)), case["signatureSha256"].as_str().unwrap(),
            "ACVP internal sigGen tcId {}", case["tcId"]);
    }
}

#[test]
fn pure_verification_gives_every_official_verdict() {
    let pure: Vec<Value> = cases("sigVer").into_iter()
        .filter(|c| c["signatureInterface"] == "external" && c["preHash"] == "pure").collect();
    assert_eq!(pure.len(), 14);
    assert_eq!(pure.iter().filter(|c| c["testPassed"] == true).count(), 2);
    let mut wrong_length = 0;
    for case in pure {
        let (pk, msg, sig, ctx) = (bytes(&case, "pk"), bytes(&case, "message"), bytes(&case, "signature"), bytes(&case, "context"));
        let expected = case["testPassed"].as_bool().unwrap();
        if sig.len() != slhdsa::SIGNATURE_LEN {
            wrong_length += 1;
            assert!(!expected);
        }
        assert_eq!(slhdsa::verify_with_context(&pk, &msg, &sig, &ctx), expected, "ACVP sigVer tcId {}", case["tcId"]);
        if ctx.is_empty() {
            assert_eq!(slhdsa::verify(&pk, &msg, &sig), expected, "consensus verifier, tcId {}", case["tcId"]);
        } else {
            assert!(!slhdsa::verify(&pk, &msg, &sig), "the empty-context verifier must reject tcId {}", case["tcId"]);
        }
    }
    assert_eq!(wrong_length, 4, "two 7,857-byte and two 7,855-byte signatures");
}

#[test]
#[allow(deprecated)]
fn internal_verification_gives_every_official_verdict() {
    use fips205::slh_dsa_shake_128s::{PublicKey, SIG_LEN};
    use fips205::traits::{SerDes, Verifier};
    let internal: Vec<Value> = cases("sigVer").into_iter()
        .filter(|c| c["signatureInterface"] == "internal").collect();
    assert_eq!(internal.len(), 14);
    for case in internal {
        let pk = PublicKey::try_from_bytes(&bytes(&case, "pk").try_into().unwrap()).unwrap();
        let sig = bytes(&case, "signature");
        let verdict = match <[u8; SIG_LEN]>::try_from(sig.as_slice()) {
            Ok(sig) => pk._test_only_raw_verify(&bytes(&case, "message"), &sig).unwrap(),
            Err(_) => false, // FIPS 205 Algorithm 20, step 1: a wrong length is invalid
        };
        assert_eq!(verdict, case["testPassed"].as_bool().unwrap(), "ACVP internal sigVer tcId {}", case["tcId"]);
    }
}
