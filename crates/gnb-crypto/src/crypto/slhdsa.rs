//! SLH-DSA-SHAKE-128s (NIST FIPS 205, stateless hash-based signatures): the
//! hash-based component of the conservative suite 0x0003 (P5-S,
//! `docs/CONSENSUS.md`, "Conservative suite 0x0003").
//!
//! Security rests only on SHAKE256 (second-preimage and PRF properties), not
//! on any lattice problem, so a suite-0x0003 signature (this AND Falcon-1024)
//! is forged only by breaking both a lattice and a hash function.
//!
//! * Parameter set SLH-DSA-SHAKE-128s (FIPS 205, Table 2: n = 16, h = 63,
//!   d = 7, h' = 9, a = 12, k = 14, lg w = 4, m = 30; security category 1).
//!   Public key 32 bytes (`PK.seed ‖ PK.root`), secret key 64 bytes
//!   (`SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`), signature 7,856 bytes.
//! * Pure signing (FIPS 205 Algorithm 22 `slh_sign`, Algorithm 24
//!   `slh_verify`): the signed message is `M' = 0x00 ‖ |ctx| ‖ ctx ‖ M`.
//!   Every consensus use has the EMPTY context ([`verify`], [`sign`]); the
//!   `*_with_context` entry points exist for the NIST ACVP vectors
//!   (`tests/acvp_slhdsa.rs`).
//! * Hedged signing: `opt_rand` is 16 fresh bytes from
//!   `pqcrypto_internals::randombytes_fill`, the source Falcon-1024 and
//!   ML-DSA-65 sign with (OS entropy, or the thread's seeded scope:
//!   `pqcrypto_internals::with_seeded_rng_scope`, which makes the consensus
//!   vectors and the seeded wallet tests reproducible). The signature is
//!   valid whatever `opt_rand` is; it only hardens signing against fault and
//!   side-channel attacks (FIPS 205, section 9.2).
//! * Implementation: the `fips205` crate (pure Rust, no `unsafe`, FIPS 205
//!   final), pinned exactly in `Cargo.toml`. Validated against the NIST ACVP
//!   SLH-DSA-SHAKE-128s keyGen / sigGen / sigVer vectors
//!   (`tests/acvp_slhdsa.rs`) and differentially against RustCrypto's
//!   independent `slh-dsa` crate (`tests/slhdsa_differential.rs`).
//!   Integer-only code (no floating point), so verification gives the same
//!   verdict on every platform.
//!
//! CRY-4. This module is the ONLY place that builds `fips205` secret-key
//! values (`PrivateKey`, enforced by `tests/secret_hygiene.rs`). Seeds and
//! secret keys live in [`SecretBytes`]; the `fips205` `PrivateKey` is
//! zeroized on drop, and the stack its signer and key generator used is
//! scrubbed ([`gnb_secret::scrub_stack`]) before this module returns.

use fips205::slh_dsa_shake_128s as params;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};

use super::{CryptoError, SecretBytes};

/// FIPS 205 security parameter `n` of SHAKE-128s: the length of `SK.seed`,
/// `SK.prf`, `PK.seed`, `PK.root` and `opt_rand`.
pub const N: usize = params::N;
/// SLH-DSA-SHAKE-128s public key length: `PK.seed ‖ PK.root` (32 bytes).
pub const PUBLIC_KEY_LEN: usize = params::PK_LEN;
/// SLH-DSA-SHAKE-128s secret key length: `SK.seed ‖ SK.prf ‖ PK.seed ‖
/// PK.root` (64 bytes).
pub const SECRET_KEY_LEN: usize = params::SK_LEN;
/// SLH-DSA-SHAKE-128s signature length (7,856 bytes).
pub const SIGNATURE_LEN: usize = params::SIG_LEN;
/// Longest FIPS 205 context string.
pub const MAX_CONTEXT_LEN: usize = 255;

// Compile-time pins of the FIPS 205 sizes this module and the consensus
// encoding (docs/CONSENSUS.md) are written for.
const _: () = assert!(N == 16 && PUBLIC_KEY_LEN == 32 && SECRET_KEY_LEN == 64 && SIGNATURE_LEN == 7_856);

/// Generate a key pair in place from the three FIPS 205 seeds (Algorithm 18,
/// `slh_keygen_internal`): `pk` receives `PK.seed ‖ PK.root`, `sk` receives
/// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`. This is the ACVP keyGen
/// interface; production key generation draws the seeds itself
/// ([`keypair_into`]).
pub fn keypair_from_seeds_into(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk: &mut [u8],
    sk: &mut [u8],
) -> Result<(), CryptoError> {
    let (Ok(sk_seed), Ok(sk_prf), Ok(pk_seed)) = (
        <&[u8; N]>::try_from(sk_seed),
        <&[u8; N]>::try_from(sk_prf),
        <&[u8; N]>::try_from(pk_seed),
    ) else {
        return Err(CryptoError::InvalidKey(format!("SLH-DSA seeds must be {N} bytes each")));
    };
    if pk.len() != PUBLIC_KEY_LEN || sk.len() != SECRET_KEY_LEN {
        return Err(CryptoError::InvalidKey("SLH-DSA key buffers have the wrong length".into()));
    }
    let (public, private) = params::KG::keygen_with_seeds(sk_seed, sk_prf, pk_seed);
    // The secret key is the three seeds and the public root (FIPS 205,
    // Figure 15); it is assembled from the caller's seeds, so the
    // `PrivateKey` value never has to be serialized (its `into_bytes`
    // returns the secret by value). It is zeroized when it drops here.
    drop(private);
    let public = public.into_bytes();
    pk.copy_from_slice(&public);
    sk[..N].copy_from_slice(sk_seed);
    sk[N..2 * N].copy_from_slice(sk_prf);
    sk[2 * N..].copy_from_slice(&public);
    gnb_secret::scrub_stack();
    Ok(())
}

/// Generate a key pair in place (FIPS 205 Algorithm 21, `slh_keygen`):
/// `SK.seed`, `SK.prf` and `PK.seed` are 48 bytes drawn from
/// `pqcrypto_internals::randombytes_fill` straight into secret memory (OS
/// entropy, or the thread's seeded scope for seeded wallets and vectors).
pub fn keypair_into(pk: &mut [u8], sk: &mut [u8]) -> Result<(), CryptoError> {
    let mut seeds = SecretBytes::zeroed(3 * N);
    pqcrypto_internals::randombytes_fill(&mut seeds[..])
        .map_err(|e| CryptoError::SignFailed(format!("SLH-DSA key generation: no randomness ({e})")))?;
    keypair_from_seeds_into(&seeds[..N], &seeds[N..2 * N], &seeds[2 * N..], pk, sk)
}

/// A fresh key pair whose secret key lives only in a [`SecretBytes`].
pub fn keypair_secret() -> Result<(Vec<u8>, SecretBytes), CryptoError> {
    let mut pk = vec![0u8; PUBLIC_KEY_LEN];
    let mut sk = SecretBytes::zeroed(SECRET_KEY_LEN);
    keypair_into(&mut pk, &mut sk)?;
    Ok((pk, sk))
}

/// The `fips205` signing key of `secret_key_bytes`, built from the borrowed
/// bytes (no copy is made here; the value is zeroized when it drops).
/// `fips205` recomputes `PK.root` from the seeds and refuses a key whose
/// stored root differs (a corrupted key).
fn private_key(secret_key_bytes: &[u8]) -> Result<params::PrivateKey, CryptoError> {
    let bytes = <&[u8; SECRET_KEY_LEN]>::try_from(secret_key_bytes)
        .map_err(|_| CryptoError::InvalidKey(format!("SLH-DSA secret key must be {SECRET_KEY_LEN} bytes")))?;
    params::PrivateKey::try_from_bytes(bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("SLH-DSA secret key: {e}")))
}

/// `opt_rand` handed to `fips205`'s signer: a rand_core 0.6 RNG that yields
/// exactly the 16 bytes drawn before the call (and fails on any further
/// request, which `fips205` never makes).
struct OptRand {
    bytes: [u8; N],
    used: bool,
}

impl Drop for OptRand {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}

impl rand_core_06::RngCore for OptRand {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Unreachable through `try_sign_with_rng` (it calls try_fill_bytes);
        // a misuse yields zero bytes, never a panic in consensus-adjacent code.
        if self.try_fill_bytes(dest).is_err() {
            dest.fill(0);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        if self.used || dest.len() != N {
            return Err(rand_core_06::Error::from(core::num::NonZeroU32::new(rand_core_06::Error::CUSTOM_START).unwrap()));
        }
        dest.copy_from_slice(&self.bytes);
        self.used = true;
        Ok(())
    }
}

impl rand_core_06::CryptoRng for OptRand {}

/// FIPS 205 Algorithm 22 (`slh_sign`, pure, hedged) with an explicit context
/// and an explicit `opt_rand` (16 bytes; `PK.seed` gives the deterministic
/// variant). The ACVP sigGen interface; production signs with [`sign`].
pub fn sign_with_context_and_randomness(
    secret_key_bytes: &[u8],
    message: &[u8],
    context: &[u8],
    opt_rand: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(CryptoError::SignFailed("SLH-DSA context longer than 255 bytes".into()));
    }
    let bytes = <[u8; N]>::try_from(opt_rand)
        .map_err(|_| CryptoError::SignFailed(format!("SLH-DSA opt_rand must be {N} bytes")))?;
    let mut rng = OptRand { bytes, used: false };
    // `private_key` already runs the key generator over the seeds (to check
    // PK.root), so the stack is scrubbed on its failure too.
    let result = private_key(secret_key_bytes).and_then(|sk| {
        sk.try_sign_with_rng(&mut rng, message, context, true)
            .map(|sig| sig.to_vec())
            .map_err(|e| CryptoError::SignFailed(format!("SLH-DSA signer: {e}")))
    });
    drop(rng);
    gnb_secret::scrub_stack();
    let sig = result?;
    if sig.len() != SIGNATURE_LEN {
        return Err(CryptoError::SignFailed(format!(
            "SLH-DSA signer returned {} bytes, expected {SIGNATURE_LEN}", sig.len())));
    }
    Ok(sig)
}

/// Hedged pure SLH-DSA-SHAKE-128s signature of `message` with the EMPTY
/// context (the consensus form). `opt_rand` is 16 fresh bytes from
/// `pqcrypto_internals::randombytes_fill`.
pub fn sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut opt_rand = zeroize::Zeroizing::new([0u8; N]);
    pqcrypto_internals::randombytes_fill(&mut opt_rand[..])
        .map_err(|e| CryptoError::SignFailed(format!("SLH-DSA signing: no randomness ({e})")))?;
    sign_with_context_and_randomness(secret_key_bytes, message, &[], &opt_rand[..])
}

/// FIPS 205 Algorithm 24 (`slh_verify`, pure) with an explicit context.
/// Exact lengths are required (a 32-byte key, a 7,856-byte signature, a
/// context of at most 255 bytes); anything else is `false`. Never panics.
pub fn verify_with_context(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8], context: &[u8]) -> bool {
    if context.len() > MAX_CONTEXT_LEN {
        return false;
    }
    let (Ok(pk), Ok(sig)) = (
        <&[u8; PUBLIC_KEY_LEN]>::try_from(public_key_bytes),
        <&[u8; SIGNATURE_LEN]>::try_from(signature_bytes),
    ) else {
        return false;
    };
    match params::PublicKey::try_from_bytes(pk) {
        Ok(pk) => pk.verify(message, sig, context),
        Err(_) => false,
    }
}

/// Pure SLH-DSA-SHAKE-128s verification with the EMPTY context: the
/// consensus verifier of the hash-based component of suite 0x0003.
/// Deterministic; malformed input is `false`, never a panic.
pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    verify_with_context(public_key_bytes, message, signature_bytes, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_the_fips205_shake_128s_sizes() {
        assert_eq!((N, PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LEN), (16, 32, 64, 7_856));
    }

    #[test]
    fn seeded_roundtrip_and_tamper_rejection() {
        let (pk, sk) = pqcrypto_internals::with_seeded_rng_scope(&[0x53; 32], keypair_secret).unwrap();
        // The secret key ends with the public key (FIPS 205 Figure 15).
        assert_eq!(&sk[2 * N..], &pk[..]);
        let sig = sign(&sk, b"slh-dsa roundtrip").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&pk, b"slh-dsa roundtrip", &sig));
        assert!(!verify(&pk, b"slh-dsa roundtrip!", &sig));
        assert!(!verify_with_context(&pk, b"slh-dsa roundtrip", &sig, b"ctx"), "context is bound");
        let mut bad = sig.clone();
        bad[SIGNATURE_LEN - 1] ^= 1;
        assert!(!verify(&pk, b"slh-dsa roundtrip", &bad));
        // Exact lengths.
        assert!(!verify(&pk, b"slh-dsa roundtrip", &sig[..SIGNATURE_LEN - 1]));
        let mut long = sig.clone();
        long.push(0);
        assert!(!verify(&pk, b"slh-dsa roundtrip", &long));
        assert!(!verify(&pk[..31], b"slh-dsa roundtrip", &sig));
        assert!(!verify(&[], b"", &[]));
        assert!(!verify_with_context(&pk, b"m", &sig, &[0u8; 256]));
    }

    #[test]
    fn seeded_keygen_is_deterministic_and_seeds_separate_keys() {
        let a = pqcrypto_internals::with_seeded_rng_scope(&[1; 32], keypair_secret).unwrap();
        let b = pqcrypto_internals::with_seeded_rng_scope(&[1; 32], keypair_secret).unwrap();
        let c = pqcrypto_internals::with_seeded_rng_scope(&[2; 32], keypair_secret).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(&a.1[..], &b.1[..]);
        assert_ne!(a.0, c.0);
    }

    #[test]
    fn deterministic_variant_and_hedged_variant() {
        let (pk, sk) = pqcrypto_internals::with_seeded_rng_scope(&[0x54; 32], keypair_secret).unwrap();
        let pk_seed = &pk[..N];
        let d1 = sign_with_context_and_randomness(&sk, b"m", &[], pk_seed).unwrap();
        let d2 = sign_with_context_and_randomness(&sk, b"m", &[], pk_seed).unwrap();
        assert_eq!(d1, d2, "opt_rand = PK.seed is the deterministic variant");
        let h = sign(&sk, b"m").unwrap();
        assert_ne!(h, d1, "production signing is hedged");
        assert!(verify(&pk, b"m", &d1) && verify(&pk, b"m", &h));
    }

    #[test]
    fn corrupted_and_misshapen_secret_keys_are_errors() {
        let (_, sk) = pqcrypto_internals::with_seeded_rng_scope(&[0x55; 32], keypair_secret).unwrap();
        let mut bad = sk.to_vec();
        bad[SECRET_KEY_LEN - 1] ^= 1; // PK.root no longer matches the seeds
        assert!(matches!(sign(&bad, b"m"), Err(CryptoError::InvalidKey(_))));
        assert!(matches!(sign(&sk[..SECRET_KEY_LEN - 1], b"m"), Err(CryptoError::InvalidKey(_))));
        assert!(sign_with_context_and_randomness(&sk, b"m", &[0u8; 256], &[0u8; N]).is_err());
        assert!(sign_with_context_and_randomness(&sk, b"m", &[], &[0u8; N - 1]).is_err());
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        let mut out = [0u8; SECRET_KEY_LEN];
        assert!(keypair_from_seeds_into(&[0; 15], &[0; 16], &[0; 16], &mut pk, &mut out).is_err());
        assert!(keypair_from_seeds_into(&[0; 16], &[0; 16], &[0; 16], &mut pk[..31], &mut out).is_err());
    }

    /// The secret key lives in secret memory and a dropped key is wiped.
    #[test]
    fn secret_key_is_secret_memory_and_wiped_on_drop() {
        let q = gnb_secret::test_support::Quarantine::start();
        let (pk, sk) = keypair_secret().unwrap();
        assert!(verify(&pk, b"q", &sign(&sk, b"q").unwrap()));
        drop(sk);
        assert!(!q.released().is_empty());
        assert!(q.all_released_zeroed(), "a dropped SLH-DSA secret key left bytes behind");
    }
}
