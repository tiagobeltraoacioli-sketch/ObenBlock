//! ML-DSA-65 and Falcon-1024 key generation and signing on caller-owned
//! secret buffers (audit CRY-4).
//!
//! The `pqcrypto-mldsa` / `pqcrypto-falcon` wrappers hold secret keys in
//! `SecretKey` types that are `Copy` byte arrays: `keypair()` returns one by
//! value, `SecretKey::from_bytes` builds one on the stack for every
//! signature, and none of the copies can be wiped by ownership. These
//! functions call the same PQClean `clean` C functions those wrappers call
//! (the only variants this workspace links), writing the secret key straight
//! into the caller's buffer (a [`crate::SecretBytes`]) and signing from a
//! borrowed slice of it, so no secret-key value is ever created on the Rust
//! side. Output is byte-identical to the wrappers' (tested below, under a
//! seeded RNG). Unlike `pqcrypto-falcon`, the C return code is checked.

use pqcrypto_falcon::ffi as falcon_ffi;
use pqcrypto_mldsa::ffi as mldsa_ffi;

/// ML-DSA-65 public-key length.
pub const MLDSA65_PUBLIC_KEY_BYTES: usize = mldsa_ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES;
/// ML-DSA-65 secret-key length.
pub const MLDSA65_SECRET_KEY_BYTES: usize = mldsa_ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES;
/// ML-DSA-65 signature length.
pub const MLDSA65_SIGNATURE_BYTES: usize = mldsa_ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
/// Falcon-1024 public-key length.
pub const FALCON1024_PUBLIC_KEY_BYTES: usize = falcon_ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
/// Falcon-1024 secret-key length.
pub const FALCON1024_SECRET_KEY_BYTES: usize = falcon_ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES;
/// Largest Falcon-1024 (compact) signature.
pub const FALCON1024_SIGNATURE_BYTES: usize = falcon_ffi::PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES;

/// Why a key generation or signature failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqError {
    /// A buffer has the wrong length.
    BadLength {
        /// Which buffer.
        what: &'static str,
        /// Its length.
        got: usize,
        /// The length the algorithm needs.
        expected: usize,
    },
    /// The C function returned a non-zero code (for a signer: the secret key
    /// does not decode).
    Failed {
        /// Which function.
        what: &'static str,
        /// Its return code.
        code: i32,
    },
}

impl std::fmt::Display for PqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqError::BadLength { what, got, expected } => write!(f, "{what}: {got} bytes, expected {expected}"),
            PqError::Failed { what, code } => write!(f, "{what} failed (code {code})"),
        }
    }
}

impl std::error::Error for PqError {}

fn check_len(what: &'static str, got: usize, expected: usize) -> Result<(), PqError> {
    if got == expected { Ok(()) } else { Err(PqError::BadLength { what, got, expected }) }
}

/// ML-DSA-65 key generation (`PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair`,
/// what `pqcrypto_mldsa::mldsa65::keypair` calls) into `pk` and `sk`.
/// Randomness comes from `PQCRYPTO_RUST_randombytes` (the OS, or the seeded
/// stream of `pqcrypto_internals::with_seeded_rng_scope`).
pub fn mldsa65_keypair(pk: &mut [u8], sk: &mut [u8]) -> Result<(), PqError> {
    check_len("ML-DSA-65 public key", pk.len(), MLDSA65_PUBLIC_KEY_BYTES)?;
    check_len("ML-DSA-65 secret key", sk.len(), MLDSA65_SECRET_KEY_BYTES)?;
    // SAFETY: PQClean writes exactly PUBLICKEYBYTES to `pk` and
    // SECRETKEYBYTES to `sk`; both are valid, exclusively borrowed buffers of
    // those lengths.
    let rc = unsafe { mldsa_ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err(PqError::Failed { what: "ML-DSA-65 key generation", code: rc });
    }
    Ok(())
}

/// ML-DSA-65 detached signature of `msg` with secret key `sk` and an empty
/// context (`..._crypto_sign_signature_ctx(.., NULL, 0, sk)`, exactly what
/// `pqcrypto_mldsa::mldsa65::detached_sign` calls).
pub fn mldsa65_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, PqError> {
    check_len("ML-DSA-65 secret key", sk.len(), MLDSA65_SECRET_KEY_BYTES)?;
    let mut sig = vec![0u8; MLDSA65_SIGNATURE_BYTES];
    let mut siglen: usize = 0;
    // SAFETY: `sig` has room for CRYPTO_BYTES (the most PQClean writes),
    // `siglen` is a valid out-pointer, `msg` is readable for `msg.len()`
    // bytes, the context is empty (NULL, 0) and `sk` is readable for
    // SECRETKEYBYTES.
    let rc = unsafe {
        mldsa_ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
            sig.as_mut_ptr(),
            &mut siglen,
            msg.as_ptr(),
            msg.len(),
            std::ptr::null(),
            0,
            sk.as_ptr(),
        )
    };
    if rc != 0 || siglen > sig.len() {
        return Err(PqError::Failed { what: "ML-DSA-65 signing", code: rc });
    }
    sig.truncate(siglen);
    Ok(sig)
}

/// Falcon-1024 key generation (`PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair`,
/// what `pqcrypto_falcon::falcon1024::keypair` calls) into `pk` and `sk`.
pub fn falcon1024_keypair(pk: &mut [u8], sk: &mut [u8]) -> Result<(), PqError> {
    check_len("Falcon-1024 public key", pk.len(), FALCON1024_PUBLIC_KEY_BYTES)?;
    check_len("Falcon-1024 secret key", sk.len(), FALCON1024_SECRET_KEY_BYTES)?;
    // SAFETY: PQClean writes exactly PUBLICKEYBYTES to `pk` and
    // SECRETKEYBYTES to `sk`; both are valid, exclusively borrowed buffers of
    // those lengths.
    let rc = unsafe { falcon_ffi::PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err(PqError::Failed { what: "Falcon-1024 key generation", code: rc });
    }
    Ok(())
}

/// Falcon-1024 detached (compact) signature of `msg` with secret key `sk`
/// (`PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature`, what
/// `pqcrypto_falcon::falcon1024::detached_sign` calls). A secret key the C
/// code cannot decode is an error (the wrapper ignored the return code and
/// returned an empty signature, audit CRY-5).
pub fn falcon1024_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, PqError> {
    check_len("Falcon-1024 secret key", sk.len(), FALCON1024_SECRET_KEY_BYTES)?;
    let mut sig = vec![0u8; FALCON1024_SIGNATURE_BYTES];
    let mut siglen: usize = 0;
    // SAFETY: `sig` has room for CRYPTO_BYTES (the most PQClean writes),
    // `siglen` is a valid out-pointer, `msg` is readable for `msg.len()`
    // bytes and `sk` for SECRETKEYBYTES.
    let rc = unsafe {
        falcon_ffi::PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
            sig.as_mut_ptr(),
            &mut siglen,
            msg.as_ptr(),
            msg.len(),
            sk.as_ptr(),
        )
    };
    if rc != 0 || siglen == 0 || siglen > sig.len() {
        return Err(PqError::Failed { what: "Falcon-1024 signing", code: rc });
    }
    sig.truncate(siglen);
    Ok(sig)
}

// ── ML-KEM-768 (feature `mlkem`: the node's P2P handshake) ─────────────────

/// ML-KEM-768 public-key length.
#[cfg(feature = "mlkem")]
pub const MLKEM768_PUBLIC_KEY_BYTES: usize = mlkem_ffi::PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES;
/// ML-KEM-768 secret (decapsulation) key length.
#[cfg(feature = "mlkem")]
pub const MLKEM768_SECRET_KEY_BYTES: usize = mlkem_ffi::PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES;
/// ML-KEM-768 ciphertext length.
#[cfg(feature = "mlkem")]
pub const MLKEM768_CIPHERTEXT_BYTES: usize = mlkem_ffi::PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
/// ML-KEM-768 shared-secret length.
#[cfg(feature = "mlkem")]
pub const MLKEM768_SHARED_SECRET_BYTES: usize = mlkem_ffi::PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES;

#[cfg(feature = "mlkem")]
use pqcrypto_mlkem::ffi as mlkem_ffi;

/// ML-KEM-768 key generation (`PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair`)
/// into `pk` and `sk`. The `pqcrypto_mlkem` wrapper returns the
/// decapsulation key as a `Copy` array that is never wiped; here it is
/// written straight into the caller's buffer. The `clean` code is the
/// portable reference the wrapper falls back to and is byte-compatible with
/// its AVX2 / NEON variants (one FIPS 203 algorithm; tested below).
#[cfg(feature = "mlkem")]
pub fn mlkem768_keypair(pk: &mut [u8], sk: &mut [u8]) -> Result<(), PqError> {
    check_len("ML-KEM-768 public key", pk.len(), MLKEM768_PUBLIC_KEY_BYTES)?;
    check_len("ML-KEM-768 secret key", sk.len(), MLKEM768_SECRET_KEY_BYTES)?;
    // SAFETY: PQClean writes exactly PUBLICKEYBYTES to `pk` and
    // SECRETKEYBYTES to `sk`, both valid exclusively borrowed buffers of
    // those lengths.
    let rc = unsafe { mlkem_ffi::PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err(PqError::Failed { what: "ML-KEM-768 key generation", code: rc });
    }
    Ok(())
}

/// ML-KEM-768 encapsulation to `pk`: writes the ciphertext to `ct` and the
/// shared secret to `ss` (`PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc`).
#[cfg(feature = "mlkem")]
pub fn mlkem768_encapsulate(pk: &[u8], ct: &mut [u8], ss: &mut [u8]) -> Result<(), PqError> {
    check_len("ML-KEM-768 public key", pk.len(), MLKEM768_PUBLIC_KEY_BYTES)?;
    check_len("ML-KEM-768 ciphertext", ct.len(), MLKEM768_CIPHERTEXT_BYTES)?;
    check_len("ML-KEM-768 shared secret", ss.len(), MLKEM768_SHARED_SECRET_BYTES)?;
    // SAFETY: `ct` and `ss` are exclusively borrowed buffers of exactly the
    // lengths PQClean writes; `pk` is readable for PUBLICKEYBYTES.
    let rc = unsafe { mlkem_ffi::PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
    if rc != 0 {
        return Err(PqError::Failed { what: "ML-KEM-768 encapsulation", code: rc });
    }
    Ok(())
}

/// ML-KEM-768 decapsulation of `ct` with secret key `sk` into `ss`
/// (`PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec`; implicit rejection, so any
/// well-sized ciphertext yields a shared secret).
#[cfg(feature = "mlkem")]
pub fn mlkem768_decapsulate(sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), PqError> {
    check_len("ML-KEM-768 secret key", sk.len(), MLKEM768_SECRET_KEY_BYTES)?;
    check_len("ML-KEM-768 ciphertext", ct.len(), MLKEM768_CIPHERTEXT_BYTES)?;
    check_len("ML-KEM-768 shared secret", ss.len(), MLKEM768_SHARED_SECRET_BYTES)?;
    // SAFETY: `ss` is an exclusively borrowed buffer of exactly BYTES;
    // `ct` and `sk` are readable for CIPHERTEXTBYTES and SECRETKEYBYTES.
    let rc = unsafe { mlkem_ffi::PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    if rc != 0 {
        return Err(PqError::Failed { what: "ML-KEM-768 decapsulation", code: rc });
    }
    Ok(())
}

#[cfg(all(test, feature = "mlkem"))]
mod mlkem_tests {
    use super::*;
    use pqcrypto_mlkem::mlkem768;
    use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

    /// Interoperable with the wrapper in both directions (whichever variant,
    /// clean or AVX2, it dispatches to), and byte-identical key generation
    /// under the same seeded randomness.
    #[test]
    fn mlkem768_matches_the_pqcrypto_wrapper() {
        let mut pk = vec![0u8; MLKEM768_PUBLIC_KEY_BYTES];
        let mut sk = crate::SecretBytes::zeroed(MLKEM768_SECRET_KEY_BYTES);
        mlkem768_keypair(&mut pk, &mut sk).unwrap();
        // Wrapper encapsulates to our key; we decapsulate.
        let (wss, wct) = mlkem768::encapsulate(&mlkem768::PublicKey::from_bytes(&pk).unwrap());
        let mut ss = crate::SecretBytes::zeroed(MLKEM768_SHARED_SECRET_BYTES);
        mlkem768_decapsulate(&sk, wct.as_bytes(), &mut ss).unwrap();
        assert_eq!(ss.as_slice(), wss.as_bytes());
        // We encapsulate to a wrapper key; the wrapper decapsulates.
        let (wpk, wsk) = mlkem768::keypair();
        let mut ct = vec![0u8; MLKEM768_CIPHERTEXT_BYTES];
        let mut ss2 = crate::SecretBytes::zeroed(MLKEM768_SHARED_SECRET_BYTES);
        mlkem768_encapsulate(wpk.as_bytes(), &mut ct, &mut ss2).unwrap();
        let back = mlkem768::decapsulate(&mlkem768::Ciphertext::from_bytes(&ct).unwrap(), &wsk);
        assert_eq!(ss2.as_slice(), back.as_bytes());
        // Seeded key generation: the same bytes as the wrapper.
        let seed = [0x6Bu8; 32];
        let (wpk, wsk) = pqcrypto_internals::with_seeded_rng_scope(&seed, mlkem768::keypair);
        let (pk, sk) = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
            let mut pk = vec![0u8; MLKEM768_PUBLIC_KEY_BYTES];
            let mut sk = crate::SecretBytes::zeroed(MLKEM768_SECRET_KEY_BYTES);
            mlkem768_keypair(&mut pk, &mut sk).unwrap();
            (pk, sk)
        });
        assert_eq!((pk.as_slice(), sk.as_slice()), (wpk.as_bytes(), wsk.as_bytes()));
        assert!(matches!(mlkem768_decapsulate(&sk, &[0u8; 10], &mut [0u8; 32]), Err(PqError::BadLength { .. })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

    /// Byte-identical to the wrappers under the same seeded randomness: the
    /// key pair, and the signatures (both signers draw randomness).
    #[test]
    fn matches_the_pqcrypto_wrappers_byte_for_byte() {
        use pqcrypto_falcon::falcon1024;
        use pqcrypto_mldsa::mldsa65;
        let seed = [0x5Cu8; 32];
        let msg = b"gnb-secret pq equivalence";
        let (wpk, wsk, wsig) = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
            let (pk, sk) = mldsa65::keypair();
            let sig = mldsa65::detached_sign(msg, &sk);
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec(), sig.as_bytes().to_vec())
        });
        let (pk, sk, sig) = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
            let mut pk = vec![0u8; MLDSA65_PUBLIC_KEY_BYTES];
            let mut sk = crate::SecretBytes::zeroed(MLDSA65_SECRET_KEY_BYTES);
            mldsa65_keypair(&mut pk, &mut sk).unwrap();
            let sig = mldsa65_sign(&sk, msg).unwrap();
            (pk, sk, sig)
        });
        assert_eq!((pk.as_slice(), sk.as_slice(), sig.as_slice()), (wpk.as_slice(), wsk.as_slice(), wsig.as_slice()));
        assert_eq!(sig.len(), MLDSA65_SIGNATURE_BYTES);
        let ds = mldsa65::DetachedSignature::from_bytes(&sig).unwrap();
        assert!(mldsa65::verify_detached_signature(&ds, msg, &mldsa65::PublicKey::from_bytes(&pk).unwrap()).is_ok());

        let (wpk, wsk, wsig) = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
            let (pk, sk) = falcon1024::keypair();
            let sig = falcon1024::detached_sign(msg, &sk);
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec(), sig.as_bytes().to_vec())
        });
        let (pk, sk, sig) = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
            let mut pk = vec![0u8; FALCON1024_PUBLIC_KEY_BYTES];
            let mut sk = crate::SecretBytes::zeroed(FALCON1024_SECRET_KEY_BYTES);
            falcon1024_keypair(&mut pk, &mut sk).unwrap();
            let sig = falcon1024_sign(&sk, msg).unwrap();
            (pk, sk, sig)
        });
        assert_eq!((pk.as_slice(), sk.as_slice(), sig.as_slice()), (wpk.as_slice(), wsk.as_slice(), wsig.as_slice()));
        let ds = falcon1024::DetachedSignature::from_bytes(&sig).unwrap();
        assert!(falcon1024::verify_detached_signature(&ds, msg, &falcon1024::PublicKey::from_bytes(&pk).unwrap()).is_ok());
    }

    #[test]
    fn wrong_lengths_and_undecodable_keys_are_errors() {
        let mut pk = vec![0u8; MLDSA65_PUBLIC_KEY_BYTES];
        assert!(matches!(mldsa65_keypair(&mut pk, &mut [0u8; 10]), Err(PqError::BadLength { .. })));
        assert!(matches!(mldsa65_sign(&[0u8; 10], b"m"), Err(PqError::BadLength { .. })));
        assert!(matches!(falcon1024_sign(&[0u8; 10], b"m"), Err(PqError::BadLength { .. })));
        // An all-zero Falcon key has a bad header byte: the C signer refuses.
        assert!(matches!(falcon1024_sign(&[0u8; FALCON1024_SECRET_KEY_BYTES], b"m"), Err(PqError::Failed { .. })));
    }
}
