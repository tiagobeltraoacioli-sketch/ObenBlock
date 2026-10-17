//! Bloch-SIS Protocol — Cryptography
//!
//! ML-DSA-65 signatures via pqcrypto-mldsa (NIST FIPS 204, official name).
//! Replaces deprecated pqcrypto-dilithium.
//!
//! Key sizes (ML-DSA-65):
//!   Public key:  1952 bytes
//!   Secret key:  4032 bytes
//!   Signature:   3309 bytes

use pqcrypto_mldsa::mldsa65;
// CRY-4: no `SecretKey` here. The pqcrypto `SecretKey` types are `Copy`
// arrays that cannot be wiped; secret keys are generated and used through
// `gnb_secret::pq` on `SecretBytes` buffers instead (see `hybrid_keypair_into`).
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use sha3::{Sha3_256, Digest};
use log::debug;

pub use gnb_secret::SecretBytes;

// Hybrid signature layout (Sprint B6b-1): ML-DSA-65 ‖ Falcon-1024.
// Public key = mldsa_pk(1952) ‖ falcon_pk. Secret = mldsa_sk(4032) ‖ falcon_sk.
// Signature  = mldsa_sig(3309) ‖ falcon_sig(variable). Splits use the fixed
// ML-DSA lengths; the Falcon part is the remainder. Both must verify.
pub const MLDSA_PUBKEY_LEN: usize = 1952;
pub const MLDSA_SECRET_LEN: usize = 4032;
pub const MLDSA_SIG_LEN:    usize = 3309;
/// Falcon-1024 public-key length.
pub const FALCON_PUBKEY_LEN: usize = gnb_secret::pq::FALCON1024_PUBLIC_KEY_BYTES;
/// Falcon-1024 secret-key length.
pub const FALCON_SECRET_LEN: usize = gnb_secret::pq::FALCON1024_SECRET_KEY_BYTES;
/// Enveloped hybrid public key: 4 + 1,952 + 1,793 = 3,749 bytes.
pub const HYBRID_PUBLIC_KEY_LEN: usize = SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN + FALCON_PUBKEY_LEN;
/// Enveloped hybrid secret key: 4 + 4,032 + 2,305 = 6,341 bytes.
pub const HYBRID_SECRET_KEY_LEN: usize = SUITE_HEADER_LEN + MLDSA_SECRET_LEN + FALCON_SECRET_LEN;

// ── Crypto-agility suite-ID envelope (Roadmap #1) ────────────────────────────
//
// Every public key AND signature (and, for symmetry, the secret key) now carries
// a 4-byte header so the verifier dispatches on an IN-BAND algorithm identifier
// instead of assuming fixed offsets. This makes suites swappable (e.g. drop
// Falcon → SUITE_MLDSA65_ONLY) without a further format break.
//
//   byte 0     : 0xB1  ┐ 2-byte magic "B1 0C" — an enveloped object vs. a legacy
//   byte 1     : 0x0C  ┘ raw ML-DSA blob; a mismatch ⇒ verify returns false.
//   bytes 2..4 : suite_id : u16 LE
//
// Parse failure (len<4 / bad magic / unknown suite) ⇒ verify returns false and
// NEVER panics (consensus rule). NOT a security claim: this is unaudited.
pub const SUITE_HEADER_LEN: usize = 4;
const SUITE_MAGIC: [u8; 2] = [0xB1, 0x0C];
/// Today's hybrid: ML-DSA-65 ‖ Falcon-1024.
pub const SUITE_MLDSA65_FALCON1024: u16 = 0x0001;
/// ML-DSA-65 only — the "Falcon removed" suite (proof that Falcon is removable).
pub const SUITE_MLDSA65_ONLY: u16 = 0x0002;

/// Maximum encoded signature length emitted by the currently supported signers.
/// Producers may reserve this before signing; this does not change wire rules.
pub fn max_signature_len() -> usize {
    SUITE_HEADER_LEN.saturating_add(MLDSA_SIG_LEN)
        .saturating_add(pqcrypto_falcon::falcon1024::signature_bytes())
}

// 0x0000 and 0xFFFF are reserved and never valid ⇒ verify returns false.

/// Parse the 4-byte suite envelope header. `None` on any malformation
/// (len < 4 or bad magic) — the caller MUST treat `None` as invalid (`false`),
/// never a panic. The returned body is everything after the header.
pub(crate) fn parse_envelope(b: &[u8]) -> Option<(u16, &[u8])> {
    if b.len() < SUITE_HEADER_LEN { return None; }
    if b[0] != SUITE_MAGIC[0] || b[1] != SUITE_MAGIC[1] { return None; }
    let suite = u16::from_le_bytes([b[2], b[3]]);
    Some((suite, &b[SUITE_HEADER_LEN..]))
}

/// Prepend the 4-byte suite header (`magic ‖ suite_id LE`) to a body.
pub(crate) fn wrap_envelope(suite: u16, body: &[u8]) -> Vec<u8> {
    // Capacity hint only: saturating is exact for every real body and merely
    // a smaller-than-ideal hint in the impossible overflow case.
    let mut out = Vec::with_capacity(SUITE_HEADER_LEN.saturating_add(body.len()));
    out.extend_from_slice(&SUITE_MAGIC);
    out.extend_from_slice(&suite.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// [`wrap_envelope`] of a secret body into a [`SecretBytes`] (CRY-4: the
/// enveloped copy of a legacy raw secret key is the whole secret).
pub(crate) fn wrap_envelope_secret(suite: u16, body: &[u8]) -> SecretBytes {
    let mut out = SecretBytes::zeroed(SUITE_HEADER_LEN.saturating_add(body.len()));
    out[..2].copy_from_slice(&SUITE_MAGIC);
    out[2..SUITE_HEADER_LEN].copy_from_slice(&suite.to_le_bytes());
    out[SUITE_HEADER_LEN..].copy_from_slice(body);
    out
}

/// Generate the enveloped hybrid key pair in place (CRY-4).
///
/// The C key generators write each half of the secret key straight into
/// `sk` (`gnb_secret::pq`): no `pqcrypto` `SecretKey` value (a `Copy` array
/// that can never be wiped) and no other copy of the secret exists. ML-DSA-65
/// first, then Falcon-1024, the order (and so the randomness consumption)
/// of the historical `mldsa65::keypair()` / `falcon1024::keypair()` calls,
/// so seeded key generation is byte-identical. Layout: `pk = B1 0C ‖ 01 00
/// ‖ mldsa_pk ‖ falcon_pk`, `sk = B1 0C ‖ 01 00 ‖ mldsa_sk ‖ falcon_sk`.
fn hybrid_keypair_into(pk: &mut [u8], sk: &mut [u8]) {
    let mut header = [0u8; SUITE_HEADER_LEN];
    header[..2].copy_from_slice(&SUITE_MAGIC);
    header[2..].copy_from_slice(&SUITE_MLDSA65_FALCON1024.to_le_bytes());
    pk[..SUITE_HEADER_LEN].copy_from_slice(&header);
    sk[..SUITE_HEADER_LEN].copy_from_slice(&header);
    let (mpk, fpk) = pk[SUITE_HEADER_LEN..].split_at_mut(MLDSA_PUBKEY_LEN);
    let (msk, fsk) = sk[SUITE_HEADER_LEN..].split_at_mut(MLDSA_SECRET_LEN);
    // PQClean's key generators cannot fail on these lengths (they return
    // 0 unconditionally); the wrappers asserted the same.
    gnb_secret::pq::mldsa65_keypair(mpk, msk).expect("ML-DSA-65 key generation");
    gnb_secret::pq::falcon1024_keypair(fpk, fsk).expect("Falcon-1024 key generation");
}

/// A fresh hybrid key pair (OS randomness) whose secret key lives only in
/// a [`SecretBytes`]: locked in RAM where the platform allows, wiped on
/// drop, never `Copy` or `Clone` (CRY-4). The entry point for new code.
pub fn generate_keypair_secret() -> (Vec<u8>, SecretBytes) {
    let mut pk = vec![0u8; HYBRID_PUBLIC_KEY_LEN];
    let mut sk = SecretBytes::zeroed(HYBRID_SECRET_KEY_LEN);
    hybrid_keypair_into(&mut pk, &mut sk);
    // The C code's expanded keys and temporaries are dead stack now.
    gnb_secret::scrub_stack();
    (pk, sk)
}

/// Compatibility entry point: [`generate_keypair_secret`] with the secret
/// copied into a plain `Vec` that the CALLER must wipe. Kept for existing
/// callers and tests; wallet, KES and node code use the `SecretBytes`
/// variants.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = generate_keypair_secret();
    (pk, sk.to_vec())
}

/// [`generate_keypair`] returning the secret key under wiping ownership
/// (CRY-4, compatibility; prefer [`generate_keypair_secret`]).
pub fn generate_keypair_zeroizing() -> (Vec<u8>, zeroize::Zeroizing<Vec<u8>>) {
    let (pk, sk) = generate_keypair_secret();
    (pk, zeroize::Zeroizing::new(sk.to_vec()))
}

/// Deterministic keypair generation from a 32-byte seed.
///
/// Uses FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal) — keygen is inherently
/// deterministic from the seed bytes consumed by `randombytes()`. We activate
/// a thread-local ChaCha20-seeded RNG via the Bloch-SIS Protocol pqcrypto-internals fork (see Cargo.toml [patch.crates-io]) of
/// `pqcrypto-internals` (see Cargo.toml `[patch.crates-io]`), which overrides
/// `PQCRYPTO_RUST_randombytes` for the duration of the keypair() call.
///
/// # Guarantees
///
/// - Same `seed` bytes → byte-identical `(public_key, secret_key)` every time,
///   on every platform supported by pqcrypto-mldsa.
/// - Different seeds → independent keypairs (ChaCha20 gives cryptographic
///   separation).
/// - The RNG state does not leak across calls: a thread-local RAII guard
///   owns cleanup and clears the override on return or unwind (and wipes
///   the ChaCha20 state, CRY-4).
///
/// Both halves are reproducible across platforms: ML-DSA-65 keygen is integer
/// arithmetic, and Falcon-1024 is pinned to PQClean's `clean` variant, whose
/// keygen and signing emulate IEEE-754 in integer code and are bit-exact on
/// every target (pinned by `falcon_clean_seeded_kat_is_byte_stable_and_verifies`).
///
/// # Compatibility warning
///
/// This produces keypairs compatible with `pqcrypto-mldsa 0.1.x`. A future
/// upstream crate upgrade that changes internal keygen order would produce
/// different keypairs from the same seed. Wallet files should therefore
/// record the `pqcrypto-mldsa` version at generation time, and migration
/// should re-derive via the old version's algorithm before upgrading.
///
/// # Seed input
///
/// Accepts any `&[u8]` of length >= 32. Only the first 32 bytes are used as
/// the ChaCha20 key. Callers deriving seeds from BIP39 24-word phrases should
/// pass the 64-byte PBKDF2 output truncated to or hashed to 32 bytes.
///
/// Compatibility entry point: the secret is a plain `Vec` copy the caller
/// must wipe; prefer [`generate_keypair_from_seed_secret`].
pub fn generate_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (pk, sk) = generate_keypair_from_seed_secret(seed)?;
    Ok((pk, sk.to_vec()))
}

/// [`generate_keypair_from_seed`] returning the secret key under wiping
/// ownership (CRY-4, compatibility). Byte-identical output.
pub fn generate_keypair_from_seed_zeroizing(
    seed: &[u8],
) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), CryptoError> {
    let (pk, sk) = generate_keypair_from_seed_secret(seed)?;
    Ok((pk, zeroize::Zeroizing::new(sk.to_vec())))
}

/// [`generate_keypair_from_seed`] with the secret key generated in place in
/// a [`SecretBytes`] (CRY-4): the seed copy, the key and the seeded RNG
/// state are wiped, the stack the C key generators used is scrubbed.
/// Byte-identical output.
pub fn generate_keypair_from_seed_secret(seed: &[u8]) -> Result<(Vec<u8>, SecretBytes), CryptoError> {
    if seed.len() < 32 {
        return Err(CryptoError::InvalidKey(
            format!("seed too short: {} bytes (need 32+)", seed.len())
        ));
    }
    // Use first 32 bytes as ChaCha20 key. For longer seeds (e.g. 64-byte
    // BIP39 PBKDF2), the caller is responsible for hashing down to 32 bytes
    // if they want the full entropy preserved — here we take the first 32
    // for simplicity.
    let mut seed32 = zeroize::Zeroizing::new([0u8; 32]);
    seed32.copy_from_slice(&seed[..32]);
    let mut pk = vec![0u8; HYBRID_PUBLIC_KEY_LEN];
    let mut sk = SecretBytes::zeroed(HYBRID_SECRET_KEY_LEN);
    // Both keygens consume the unchanged stream within a non-escaping scope.
    // Cleanup also removes any accidentally forgotten nested legacy guards.
    pqcrypto_internals::with_seeded_rng_scope(&seed32, || hybrid_keypair_into(&mut pk, &mut sk));
    gnb_secret::scrub_stack();
    Ok((pk, sk))
}

// ── Signed-message domain (A4-M-4) ──────────────────────────────────────────
//
// `crypto::sign` signs its `message` argument verbatim. Every OTHER caller in
// the codebase signs a 32-byte digest whose PREIMAGE is domain-tagged (tx
// sighash, disclosure digest, PoS signing root, transport handshake). A
// "sign arbitrary user-supplied text" CLI/API flow that fed raw text straight
// into `crypto::sign` had no such tag: a 64-hex-character "message" is a raw
// 32-byte digest, indistinguishable at the signature layer from an attacker-
// chosen tx sighash preimage — a "prove you own this address by signing this
// challenge" flow could silently produce a valid transaction/disclosure
// signature. `signed_message_digest` closes that: length-prefixed AND
// domain-tagged, so no choice of `message` bytes (hex-looking or otherwise)
// can ever collide with another domain's preimage.

/// Domain tag for the "sign an arbitrary message" flow. Distinct from every
/// other signing domain in the codebase; not a prefix of any of them and none
/// of them are a prefix of this one.
pub const SIGNED_MESSAGE_DOMAIN: &[u8] = b"BLOCH-SIGNED-MESSAGE-v1";

/// The digest a "sign this message" flow actually signs: SHA3-256(
/// `SIGNED_MESSAGE_DOMAIN` ‖ `message.len() as u64 LE` ‖ `message`).
///
/// Callers MUST pass the message's raw bytes as the user typed/supplied them
/// — NEVER hex-decode user-supplied text first. Hex-decoding a 64-character
/// message before this point is exactly the bug this function exists to
/// close: it would turn a "sign this challenge" phishing prompt back into
/// "sign this raw 32-byte digest", regardless of what digest gets computed
/// afterwards.
pub fn signed_message_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SIGNED_MESSAGE_DOMAIN);
    h.update((message.len() as u64).to_le_bytes());
    h.update(message);
    h.finalize().into()
}

/// Domain tag of the chain-bound signed-message format (CRY-8).
///
/// The v1 tag above carries no chain identifier, so a v1 message signature
/// verifies identically on Bloch, GnB mainnet and GnB testnet, which share
/// keys. New signatures use this v2 domain, which appends the 4-byte chain id
/// ([`crate::core::ChainId`]) before the length-prefixed message. No default
/// GnB verifier accepts v1 (re-audit CRY-8: a Bloch v1 signature verified as
/// a GnB mainnet and testnet proof); only the explicit legacy mode
/// `wallet::Keypair::verify_message_allowing_legacy_v1` (`gnb-wallet
/// verify-message --legacy-v1`) does, and never a canonical verifier. Like
/// v1, the tag is not a prefix of any other signing domain in the codebase
/// and none of them is a prefix of it.
pub const SIGNED_MESSAGE_DOMAIN_V2: &[u8] = b"GNB-SIGNED-MESSAGE-v2";

/// The digest a v2 "sign this message" flow signs:
/// SHA3-256(`SIGNED_MESSAGE_DOMAIN_V2` ‖ chain_id u32 LE ‖
/// `message.len() as u64 LE` ‖ `message`). Same caller contract as
/// [`signed_message_digest`]: pass the raw message bytes, never hex-decoded text.
pub fn signed_message_digest_v2(chain_id: crate::core::ChainId, message: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SIGNED_MESSAGE_DOMAIN_V2);
    h.update(chain_id.to_le_bytes());
    h.update((message.len() as u64).to_le_bytes());
    h.update(message);
    h.finalize().into()
}

/// Sign `message` with an enveloped secret key.
///
/// CRY-5: the output is checked before it is returned. The ML-DSA half must
/// have its fixed length and the Falcon half must be a well-formed compact
/// Falcon-1024 encoding: `pqcrypto-falcon` discards the C signer's return
/// code, so a secret key the signer rejects (corrupt header, bad encoding)
/// used to yield `Ok` with an EMPTY Falcon half. That case is now an error.
///
/// This function has no public key, so it cannot verify the signature
/// itself; wallet code signs through [`sign_checked`], which also verifies
/// both halves under the wallet's public key before returning.
pub fn sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Parse the suite envelope on the secret key, then produce a signature
    // enveloped under the SAME suite. Parse failure ⇒ Err (never a panic).
    let (suite, sk_body) = parse_envelope(secret_key_bytes)
        .ok_or_else(|| CryptoError::InvalidKey("secret-key envelope: too short or bad magic".into()))?;
    match suite {
        SUITE_MLDSA65_FALCON1024 => {
            // Hybrid body: mldsa_sk(4032) ‖ falcon_sk. Produce mldsa_sig(3309) ‖ falcon_sig.
            if sk_body.len() <= MLDSA_SECRET_LEN {
                return Err(CryptoError::InvalidKey("hybrid secret key too short".into()));
            }
            let (msk, fsk) = sk_body.split_at(MLDSA_SECRET_LEN);
            let signed = mldsa_sign_checked(msk, message)
                .and_then(|mut out| { out.extend_from_slice(&falcon::sign(fsk, message)?); Ok(out) });
            gnb_secret::scrub_stack();
            Ok(wrap_envelope(suite, &signed?))
        }
        SUITE_MLDSA65_ONLY => {
            if sk_body.len() != MLDSA_SECRET_LEN {
                return Err(CryptoError::InvalidKey("ML-DSA-only secret key wrong length".into()));
            }
            let out = mldsa_sign_checked(sk_body, message);
            gnb_secret::scrub_stack();
            Ok(wrap_envelope(suite, &out?))
        }
        _ => Err(CryptoError::InvalidKey(format!("unknown/reserved suite {:#06x}", suite))),
    }
}

/// ML-DSA-65 detached signature with an output-length check (CRY-5),
/// signed straight from the borrowed secret bytes (CRY-4: no `Copy`
/// `SecretKey` value is built).
fn mldsa_sign_checked(secret: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sig = gnb_secret::pq::mldsa65_sign(secret, message).map_err(|e| match e {
        gnb_secret::pq::PqError::BadLength { .. } => CryptoError::InvalidKey("bad ML-DSA secret key".into()),
        e => CryptoError::SignFailed(e.to_string()),
    })?;
    if sig.len() != MLDSA_SIG_LEN {
        return Err(CryptoError::SignFailed(format!(
            "ML-DSA-65 signer returned {} bytes, expected {}", sig.len(), MLDSA_SIG_LEN
        )));
    }
    Ok(sig)
}

/// Sign and verify before returning (CRY-5). This is the entry point for
/// every wallet signer.
///
/// The produced signature must verify under `public_key_bytes` through BOTH
/// the consensus verifier ([`verify`]) and the canonical policy (mandatory
/// suite envelope on the signature, compact Falcon encoding: the wallet side
/// of CRY-1/CRY-2, so a future canonical-witness rule cannot invalidate what
/// wallets emit). Each hybrid half is therefore checked. A secret key that
/// does not belong to `public_key_bytes`, a corrupted key, or a signer fault
/// returns `Err` instead of a signature the network would reject.
///
/// `public_key_bytes` may be enveloped (every current key) or the exact raw
/// legacy hybrid encoding of a pre-envelope carry-over wallet, whose address
/// commits to the raw key; the signature itself is always enveloped.
pub fn sign_checked(
    secret_key_bytes: &[u8],
    public_key_bytes: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let sig = sign(secret_key_bytes, message)?;
    if !verify_wallet_signature(public_key_bytes, message, &sig) {
        return Err(CryptoError::SignFailed(
            "produced signature does not verify under the wallet public key \
             (corrupted or mismatched secret key)".into(),
        ));
    }
    Ok(sig)
}

/// True when `sig` is a canonical wallet signature over `message` that the
/// consensus verifier accepts for `public_key_bytes`.
pub fn verify_wallet_signature(public_key_bytes: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let canonical = if public_key_bytes.len() == legacy_hybrid_pubkey_len() {
        // Pre-envelope key: the address commits to the raw key bytes, the
        // signature still carries the suite-0x0001 envelope.
        match parse_envelope(sig) {
            Some((SUITE_MLDSA65_FALCON1024, body)) => {
                verify_legacy_hybrid_raw_canonical(public_key_bytes, message, body)
            }
            _ => false,
        }
    } else {
        verify_enveloped_canonical(public_key_bytes, message, sig)
    };
    canonical && verify(public_key_bytes, message, sig)
}

/// Parse a suite envelope, or fall back to the LEGACY pre-envelope encoding:
/// carry-over wallets created before the 4-byte header (their address is
/// `SHA3-256(raw hybrid pubkey)`) present a bare `mldsa ‖ falcon` body with no
/// magic. Treat a no-magic object as suite 0x0001 (hybrid), the only suite the
/// old chain produced. A mismatch still ⇒ verify false via the body checks.
/// This restores spendability of pre-envelope carry-over funds without
/// weakening enveloped verification. CONSENSUS-CRITICAL.
fn parse_envelope_or_legacy(b: &[u8]) -> (u16, &[u8]) {
    match parse_envelope(b) {
        Some((suite, body)) => (suite, body),
        None => (SUITE_MLDSA65_FALCON1024, b),
    }
}

/// Exact byte length of a raw (non-enveloped) legacy hybrid ML-DSA-65 ‖
/// Falcon-1024 PUBLIC key — `MLDSA_PUBKEY_LEN` plus the Falcon-1024 public-key
/// length, both fixed. An ENVELOPED pubkey of the same suite is always
/// exactly `SUITE_HEADER_LEN` bytes LONGER, so length alone disambiguates
/// legacy-vs-enveloped with no ambiguity — see [`parse_pubkey_envelope_or_legacy`].
pub(crate) fn legacy_hybrid_pubkey_len() -> usize {
    MLDSA_PUBKEY_LEN.saturating_add(falcon::pubkey_len())
}

/// Exact byte length of a raw (non-enveloped) SECRET key of `suite`:
/// `mldsa_sk(4,032) ‖ falcon_sk(2,305)` = 6,337 for suite 0x0001 (the
/// pre-envelope founder / Bloch v2 keystores store this), the bare ML-DSA-65
/// secret (4,032) for suite 0x0002. An enveloped secret of the same suite is
/// exactly `SUITE_HEADER_LEN` bytes longer, so the two never collide on
/// length (B2-T2: the wallet signer classifies secrets by these lengths, as
/// consensus classifies public keys, never by their leading bytes). `None`
/// for any other suite.
pub(crate) fn raw_secret_key_len(suite: u16) -> Option<usize> {
    match suite {
        SUITE_MLDSA65_FALCON1024 => Some(MLDSA_SECRET_LEN.saturating_add(
            pqcrypto_falcon::falcon1024::secret_key_bytes())),
        SUITE_MLDSA65_ONLY => Some(MLDSA_SECRET_LEN),
        _ => None,
    }
}

/// Public-key-specific version of [`parse_envelope_or_legacy`] (audit A4
/// lows / legacy pubkey fallback).
///
/// A raw legacy pubkey has a `1/65536` chance of happening to start with the
/// two-byte magic `[0xB1, 0x0C]` — plain hybrid key material, not a crafted
/// attack. `parse_envelope_or_legacy` would then misclassify it as enveloped
/// (treating its bytes 2..4 as a bogus suite id), corrupting the suite
/// dispatch in `verify` and permanently locking those funds even though the
/// key and signature are both genuine.
///
/// Length resolves this with no heuristics: an ENVELOPED hybrid pubkey is
/// *exactly* `SUITE_HEADER_LEN` (4) bytes longer than the raw legacy
/// encoding, so the two encodings can never collide on length. Checking the
/// exact legacy length FIRST — before the magic-byte heuristic — means a
/// legacy pubkey is classified correctly regardless of its leading bytes.
fn parse_pubkey_envelope_or_legacy(b: &[u8]) -> (u16, &[u8]) {
    if b.len() == legacy_hybrid_pubkey_len() {
        return (SUITE_MLDSA65_FALCON1024, b);
    }
    parse_envelope_or_legacy(b)
}

/// Whether a public-key encoding names the live hybrid suite.
///
/// This is a format/policy predicate, not a cryptographic verification: it
/// accepts the exact legacy raw `ML-DSA-65 || Falcon-1024` key shape and the
/// exact suite-0x0001 envelope shape.  In particular it refuses suite 0x0002
/// even though [`verify`] deliberately retains support for that crypto-agility
/// suite.  CRY-2: mempool admission (`node/src/mempool/admission.rs`,
/// standardness) refuses every input whose key fails this predicate, and the
/// wallet builders refuse to sign with such a key, so new ML-DSA-only spends
/// stay out of the live network while outputs that may already be locked to a
/// 0x0002 key stay consensus-spendable.
pub fn is_hybrid_public_key(public_key_bytes: &[u8]) -> bool {
    let (suite, body) = parse_pubkey_envelope_or_legacy(public_key_bytes);
    suite == SUITE_MLDSA65_FALCON1024 && body.len() == legacy_hybrid_pubkey_len()
}

pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    // Suite-ID dispatch (design §2.3). Accepts enveloped objects AND legacy
    // pre-envelope (raw hybrid) objects from the carry-over. A pk of one suite
    // must not verify a sig of another. Any body parse failure ⇒ false, never a
    // panic (consensus rule). NO security is claimed.
    let (pk_suite, pk_body) = parse_pubkey_envelope_or_legacy(public_key_bytes);
    let (sig_suite, sig_body) = parse_envelope_or_legacy(signature_bytes);
    verify_parsed(pk_suite, pk_body, message, sig_suite, sig_body)
}

/// Verify objects whose trusted format contract requires an explicit suite envelope.
///
/// Unlike [`verify`], this entry point never falls back to the legacy raw hybrid
/// encoding and therefore never guesses whether signature bytes beginning with
/// the envelope magic are raw material or a header. Use it only for versioned
/// formats that already require both their key and signature to be enveloped.
/// Historical consensus and carry-over wallet verification must keep using
/// [`verify`] or [`verify_legacy_hybrid_raw`] according to their trusted format
/// metadata.
pub fn verify_enveloped(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let Some((pk_suite, pk_body)) = parse_envelope(public_key_bytes) else {
        return false;
    };
    let Some((sig_suite, sig_body)) = parse_envelope(signature_bytes) else {
        return false;
    };
    verify_parsed(pk_suite, pk_body, message, sig_suite, sig_body)
}

/// Verify explicitly enveloped objects and require canonical primitive encodings.
///
/// This opt-in entry point has the same strict envelope and suite dispatch as
/// [`verify_enveloped`]. For hybrid suite `0x0001`, it additionally rejects
/// Falcon's alternate 1,280-byte zero-padded representation. Existing
/// consensus and compatibility callers are intentionally not migrated here.
pub fn verify_enveloped_canonical(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    #[cfg(test)]
    POLICY_VERIFICATION_CALLS.with(|n| n.set(n.get() + 1));
    let Some((pk_suite, pk_body)) = parse_envelope(public_key_bytes) else {
        return false;
    };
    let Some((sig_suite, sig_body)) = parse_envelope(signature_bytes) else {
        return false;
    };
    verify_parsed_with_falcon(
        pk_suite,
        pk_body,
        message,
        sig_suite,
        sig_body,
        falcon::verify_canonical,
    )
}

/// [`verify`] (enveloped or legacy raw keys and signatures, as carried over
/// from Bloch) that also requires Falcon-1024's compact canonical encoding,
/// so one signature has exactly one byte string: PQClean's alternate
/// zero-padded 1280-byte form of the same signature is refused. This is the
/// consensus rule for single-key (20-byte hash) spends.
pub fn verify_canonical(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let (pk_suite, pk_body) = parse_pubkey_envelope_or_legacy(public_key_bytes);
    let (sig_suite, sig_body) = parse_envelope_or_legacy(signature_bytes);
    verify_parsed_with_falcon(pk_suite, pk_body, message, sig_suite, sig_body, falcon::verify_canonical)
}

fn verify_parsed(
    pk_suite: u16,
    pk_body: &[u8],
    message: &[u8],
    sig_suite: u16,
    sig_body: &[u8],
) -> bool {
    verify_parsed_with_falcon(
        pk_suite,
        pk_body,
        message,
        sig_suite,
        sig_body,
        falcon::verify,
    )
}

fn verify_parsed_with_falcon(
    pk_suite: u16,
    pk_body: &[u8],
    message: &[u8],
    sig_suite: u16,
    sig_body: &[u8],
    verify_falcon: fn(&[u8], &[u8], &[u8]) -> bool,
) -> bool {
    if pk_suite != sig_suite {
        debug!("crypto::verify: suite mismatch (pk={:#06x}, sig={:#06x})", pk_suite, sig_suite);
        return false;
    }
    match pk_suite {
        SUITE_MLDSA65_FALCON1024 => {
            verify_hybrid_mldsa_falcon_with(pk_body, message, sig_body, verify_falcon)
        }
        SUITE_MLDSA65_ONLY       => verify_mldsa65_only(pk_body, message, sig_body),
        other => { debug!("crypto::verify: unknown/reserved suite {:#06x}", other); false }
    }
}

/// Explicit verification of legacy raw ML-DSA-65 || Falcon-1024 objects.
///
/// Use only when trusted format metadata says BOTH the key and signature are
/// raw legacy hybrid bytes. No magic-byte classification is performed, so a
/// raw signature beginning with `B1 0C` is not mistaken for an envelope.
/// Enveloped keys are rejected by their different length; do not strip an
/// untrusted envelope and retry here after another verification policy fails.
/// This opt-in API does not change [`verify`] or any historical consensus
/// caller. The legacy heuristic's ambiguous signatures remain a separate
/// consensus compatibility/activation issue.
pub fn verify_legacy_hybrid_raw(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    public_key_bytes.len() == legacy_hybrid_pubkey_len()
        && verify_hybrid_mldsa_falcon(public_key_bytes, message, signature_bytes)
}

/// Verify explicitly raw legacy hybrid objects with canonical Falcon encoding.
///
/// This is the canonical-policy counterpart of [`verify_legacy_hybrid_raw`].
/// It is only appropriate when trusted format metadata already requires BOTH
/// objects to use the raw legacy hybrid layout. It performs no envelope
/// detection or fallback and rejects Falcon's alternate zero-padded encoding.
/// Existing consensus and compatibility callers are intentionally unchanged.
pub fn verify_legacy_hybrid_raw_canonical(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    public_key_bytes.len() == legacy_hybrid_pubkey_len()
        && verify_hybrid_mldsa_falcon_with(
            public_key_bytes,
            message,
            signature_bytes,
            falcon::verify_canonical,
        )
}

/// Suite 0x0001 verifier — the pre-envelope `verify` body verbatim, now
/// operating on the post-header BODY slices. The `<=` length guards, the
/// `from_bytes` parse-fail⇒false, and the ML-DSA-AND-Falcon combiner are all
/// preserved: BOTH halves must verify (defence in depth across two lattice
/// families). Behaviour on 0x0001 objects is byte-for-byte identical to the
/// legacy path except for the 4-byte header strip.
fn verify_hybrid_mldsa_falcon(pk_body: &[u8], message: &[u8], sig_body: &[u8]) -> bool {
    verify_hybrid_mldsa_falcon_with(pk_body, message, sig_body, falcon::verify)
}

/// FIPS 204 bound on an ML-DSA-65 signature's response vector `z`: every
/// coefficient must satisfy |z| < γ1 − β (γ1 = 2^19, β = τ·η = 49·4 = 196).
///
/// Checked here, before the library, as a rule of its own: PQClean's AVX2
/// ML-DSA-65 (pqcrypto-mldsa's default features) skips it and accepts 41
/// Wycheproof vectors that violate it (tests/wycheproof_mldsa65.rs), the exact
/// boundary −(γ1 − β) included. The clean implementation that every build
/// links now (`mldsa_one_verdict` below) checks it too; this check keeps the
/// verdict independent of the implementation a build links.
///
/// Layout (FIPS 204, ML-DSA-65): c̃ (48 bytes) ‖ z (5 polynomials × 256
/// coefficients × 20 bits, packed little-endian as γ1 − z) ‖ h (61 bytes).
fn mldsa65_z_within_bound(sig: &[u8]) -> bool {
    const CTILDE_LEN: usize = 48;
    const Z_COEFFS: usize = 5 * 256;
    const GAMMA1: i32 = 1 << 19;
    const BETA: i32 = 49 * 4;
    if sig.len() != MLDSA_SIG_LEN {
        return false;
    }
    let z = &sig[CTILDE_LEN..CTILDE_LEN + Z_COEFFS * 20 / 8];
    (0..Z_COEFFS).all(|j| {
        let bit = j * 20;
        let (byte, shift) = (bit / 8, bit % 8); // shift is 0 or 4: 3 bytes suffice
        let word = u32::from(z[byte]) | u32::from(z[byte + 1]) << 8 | u32::from(z[byte + 2]) << 16;
        let packed = ((word >> shift) & 0xF_FFFF) as i32;
        (GAMMA1 - packed).abs() < GAMMA1 - BETA
    })
}

fn verify_hybrid_mldsa_falcon_with(
    pk_body: &[u8],
    message: &[u8],
    sig_body: &[u8],
    verify_falcon: fn(&[u8], &[u8], &[u8]) -> bool,
) -> bool {
    if pk_body.len() <= MLDSA_PUBKEY_LEN || sig_body.len() <= MLDSA_SIG_LEN {
        debug!("crypto::verify: hybrid pubkey/sig body too short (pk={}, sig={})",
               pk_body.len(), sig_body.len());
        return false;
    }
    let (mpk, fpk) = pk_body.split_at(MLDSA_PUBKEY_LEN);
    let (msig, fsig) = sig_body.split_at(MLDSA_SIG_LEN);
    if !mldsa65_z_within_bound(msig) {
        debug!("crypto::verify: ML-DSA z outside the FIPS 204 norm bound");
        return false;
    }

    let pk = match mldsa65::PublicKey::from_bytes(mpk) {
        Ok(k) => k,
        Err(e) => { debug!("crypto::verify: ML-DSA pubkey parse failed: {:?}", e); return false; }
    };
    let sig = match mldsa65::DetachedSignature::from_bytes(msig) {
        Ok(s) => s,
        Err(e) => { debug!("crypto::verify: ML-DSA sig parse failed: {:?}", e); return false; }
    };
    if mldsa65::verify_detached_signature(&sig, message, &pk).is_err() {
        return false;
    }
    // Falcon half.
    verify_falcon(fpk, message, fsig)
}

/// Suite 0x0002 verifier — ML-DSA-65 only (Falcon removed). Exact-length bodies
/// required. Consensus-valid at every height so that outputs already locked to
/// a 0x0002 key are never frozen; relay policy refuses new 0x0002 spends and
/// wallets never produce them (CRY-2, see [`is_hybrid_public_key`]).
fn verify_mldsa65_only(pk_body: &[u8], message: &[u8], sig_body: &[u8]) -> bool {
    if pk_body.len() != MLDSA_PUBKEY_LEN || sig_body.len() != MLDSA_SIG_LEN {
        debug!("crypto::verify: mldsa-only pk/sig body wrong length (pk={}, sig={})",
               pk_body.len(), sig_body.len());
        return false;
    }
    if !mldsa65_z_within_bound(sig_body) {
        return false;
    }
    let pk = match mldsa65::PublicKey::from_bytes(pk_body) {
        Ok(k) => k, Err(_) => return false,
    };
    let sig = match mldsa65::DetachedSignature::from_bytes(sig_body) {
        Ok(s) => s, Err(_) => return false,
    };
    mldsa65::verify_detached_signature(&sig, message, &pk).is_ok()
}

/// Verify a raw (non-enveloped) ML-DSA-65 detached signature — the public
/// counterpart of [`falcon::verify`] for the other half of the hybrid.
///
/// The Genesis-4 weak-subjectivity envelope verifier
/// (`bloch-pos-committee::ws` via the node's `HybridKeyVerifier`
/// implementation) receives the two hybrid halves already split at the fixed
/// points and must verify each under its own primitive. Exported so that
/// caller does not have to counterfeit a suite envelope to reach the ML-DSA
/// body verifier — one primitive, one entry point per half. Exact-length
/// bodies required; malformed input ⇒ `false`, never a panic (consensus
/// rule).
pub fn verify_mldsa65_raw(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    verify_mldsa65_only(public_key_bytes, message, signature_bytes)
}

/// Split a suite-enveloped object (public key, secret key, or signature) into
/// `(suite_id, body)`, or `None` if the bytes carry no valid envelope header.
///
/// Public for Genesis-4 node tooling that must re-frame enveloped objects
/// into the raw halves the PoS committee crate consumes (weak-subjectivity
/// checkpoint envelopes carry raw `mldsa ‖ falcon` bodies, not suite
/// envelopes). Read-only view; exposing it here keeps the 4-byte header
/// format defined in exactly one place.
pub fn split_envelope(bytes: &[u8]) -> Option<(u16, &[u8])> {
    parse_envelope(bytes)
}

// ── Canonical signature encoding and suite helpers (CRY-1, CRY-2) ────────────

/// Suite named by a PUBLIC key: the exact raw legacy hybrid length is suite
/// 0x0001 (genesis carry-over addresses commit to raw keys), otherwise the
/// envelope's suite. `None` for anything else (no envelope, unknown or
/// reserved suite). A format predicate; it does not check the key material.
pub fn public_key_suite(public_key_bytes: &[u8]) -> Option<u16> {
    if public_key_bytes.len() == legacy_hybrid_pubkey_len() {
        return Some(SUITE_MLDSA65_FALCON1024);
    }
    match parse_envelope(public_key_bytes) {
        Some((suite @ (SUITE_MLDSA65_FALCON1024 | SUITE_MLDSA65_ONLY), _)) => Some(suite),
        _ => None,
    }
}

/// `true` iff `signature_bytes` is the single canonical encoding of a
/// signature: the 4-byte suite envelope is present and names a live suite,
/// and the body has its exact form —
///
/// * suite 0x0001: `mldsa_sig(3,309) ‖ falcon_sig` where `falcon_sig` is
///   Falcon-1024's COMPACT encoding (header byte 0x3A, 40-byte nonce,
///   exactly framed coefficients, zero padding bits, nothing after it, at
///   most `falcon1024::signature_bytes()` bytes). The 1,280-byte zero-padded
///   form the historical verifier also accepts is NOT canonical;
/// * suite 0x0002: exactly the 3,309-byte ML-DSA-65 signature.
///
/// Format only (no signature math): cheap enough for relay policy. Together
/// with a successful [`verify`] it is equivalent to
/// [`verify_enveloped_canonical`] / [`verify_legacy_hybrid_raw_canonical`].
pub fn is_canonical_signature_encoding(signature_bytes: &[u8]) -> bool {
    match parse_envelope(signature_bytes) {
        Some((SUITE_MLDSA65_FALCON1024, body)) => {
            body.len() > MLDSA_SIG_LEN && falcon::is_canonical_encoding(&body[MLDSA_SIG_LEN..])
        }
        Some((SUITE_MLDSA65_ONLY, body)) => body.len() == MLDSA_SIG_LEN,
        _ => false,
    }
}

// ── Component-bound transaction signatures (sighash v3, CRY-2) ───────────────
//
// Under the legacy binding every component of a hybrid signature signs the
// same 32-byte digest, so the ML-DSA half of a suite-0x0001 signature is, by
// itself, a valid suite-0x0002 signature over that digest ("split and
// relabel"). Under sighash v3 each component signs a message that names the
// suite AND the component (composite-signature practice):
//
//   message(suite, component, digest) =
//       TX_SIG_COMPONENT_DOMAIN (12 bytes, "GNB-TXSIG-v3")
//     ‖ suite      u16 LE
//     ‖ component  u8      (0x01 = ML-DSA-65, 0x02 = Falcon-1024)
//     ‖ digest     32 bytes (the sighash v3 digest)
//
// A suite-0x0001 ML-DSA component is a signature over a message containing
// `01 00 01`; the suite-0x0002 verifier checks a message containing
// `02 00 01`, so a stripped and relabelled half never verifies, even over
// the same digest. The suite is also committed in the digest itself (sighash
// v3 commits the signature's suite id), which is a second, independent bar.

/// Domain tag of a v3 component message. Not a prefix of any other signing
/// domain in the codebase, and none of them is a prefix of it.
pub const TX_SIG_COMPONENT_DOMAIN: [u8; 12] = *b"GNB-TXSIG-v3";
/// Component id of the ML-DSA-65 signature in a v3 component message.
pub const COMPONENT_MLDSA65: u8 = 0x01;
/// Component id of the Falcon-1024 signature in a v3 component message.
pub const COMPONENT_FALCON1024: u8 = 0x02;
/// Length of a v3 component message: 12 + 2 + 1 + 32.
pub const BOUND_COMPONENT_MESSAGE_LEN: usize = 47;

/// The message component `component` of suite `suite` signs under sighash v3.
pub fn bound_component_message(suite: u16, component: u8, digest: &[u8; 32]) -> [u8; BOUND_COMPONENT_MESSAGE_LEN] {
    let mut m = [0u8; BOUND_COMPONENT_MESSAGE_LEN];
    m[..12].copy_from_slice(&TX_SIG_COMPONENT_DOMAIN);
    m[12..14].copy_from_slice(&suite.to_le_bytes());
    m[14] = component;
    m[15..].copy_from_slice(digest);
    m
}

/// Sign a sighash-v3 digest with an enveloped secret key: every component
/// signs its own [`bound_component_message`]. The output is the canonical
/// enveloped encoding of the key's suite.
pub fn sign_bound(secret_key_bytes: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let (suite, sk_body) = parse_envelope(secret_key_bytes)
        .ok_or_else(|| CryptoError::InvalidKey("secret-key envelope: too short or bad magic".into()))?;
    match suite {
        SUITE_MLDSA65_FALCON1024 => {
            if sk_body.len() <= MLDSA_SECRET_LEN {
                return Err(CryptoError::InvalidKey("hybrid secret key too short".into()));
            }
            let (msk, fsk) = sk_body.split_at(MLDSA_SECRET_LEN);
            let signed = mldsa_sign_checked(msk, &bound_component_message(suite, COMPONENT_MLDSA65, digest))
                .and_then(|mut out| {
                    out.extend_from_slice(&falcon::sign(fsk, &bound_component_message(suite, COMPONENT_FALCON1024, digest))?);
                    Ok(out)
                });
            gnb_secret::scrub_stack();
            Ok(wrap_envelope(suite, &signed?))
        }
        SUITE_MLDSA65_ONLY => {
            if sk_body.len() != MLDSA_SECRET_LEN {
                return Err(CryptoError::InvalidKey("ML-DSA-only secret key wrong length".into()));
            }
            let out = mldsa_sign_checked(sk_body, &bound_component_message(suite, COMPONENT_MLDSA65, digest));
            gnb_secret::scrub_stack();
            Ok(wrap_envelope(suite, &out?))
        }
        _ => Err(CryptoError::InvalidKey(format!("unknown/reserved suite {:#06x}", suite))),
    }
}

/// [`sign_bound`] followed by [`verify_bound`] under `public_key_bytes`
/// (enveloped, or the exact raw legacy hybrid key of a carry-over wallet).
/// The wallet entry point for version-3 transactions.
pub fn sign_bound_checked(
    secret_key_bytes: &[u8],
    public_key_bytes: &[u8],
    digest: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let sig = sign_bound(secret_key_bytes, digest)?;
    if !verify_bound(public_key_bytes, digest, &sig) {
        return Err(CryptoError::SignFailed(
            "produced signature does not verify under the wallet public key \
             (corrupted or mismatched secret key)".into(),
        ));
    }
    Ok(sig)
}

/// Consensus verifier of a sighash-v3 signature. Requires the canonical
/// signature encoding ([`is_canonical_signature_encoding`]); the public key
/// may be enveloped or the exact raw legacy hybrid encoding (genesis
/// carry-over addresses commit to raw keys and must stay spendable). The
/// key's suite must equal the signature's, and every component must verify
/// over its [`bound_component_message`]. Never panics.
pub fn verify_bound(public_key_bytes: &[u8], digest: &[u8; 32], signature_bytes: &[u8]) -> bool {
    #[cfg(test)]
    POLICY_VERIFICATION_CALLS.with(|n| n.set(n.get() + 1));
    if !is_canonical_signature_encoding(signature_bytes) {
        return false;
    }
    let Some((sig_suite, sig_body)) = parse_envelope(signature_bytes) else { return false };
    let Some(pk_suite) = public_key_suite(public_key_bytes) else { return false };
    if pk_suite != sig_suite {
        return false;
    }
    let pk_body = if public_key_bytes.len() == legacy_hybrid_pubkey_len() {
        public_key_bytes
    } else {
        &public_key_bytes[SUITE_HEADER_LEN..]
    };
    match sig_suite {
        SUITE_MLDSA65_FALCON1024 => {
            if pk_body.len() <= MLDSA_PUBKEY_LEN {
                return false;
            }
            let (mpk, fpk) = pk_body.split_at(MLDSA_PUBKEY_LEN);
            let (msig, fsig) = sig_body.split_at(MLDSA_SIG_LEN);
            verify_mldsa65_only(mpk, &bound_component_message(sig_suite, COMPONENT_MLDSA65, digest), msig)
                && falcon::verify_canonical(fpk, &bound_component_message(sig_suite, COMPONENT_FALCON1024, digest), fsig)
        }
        SUITE_MLDSA65_ONLY => {
            verify_mldsa65_only(pk_body, &bound_component_message(sig_suite, COMPONENT_MLDSA65, digest), sig_body)
        }
        _ => false,
    }
}

pub fn address_from_pubkey(public_key: &[u8], testnet: bool) -> String {
    let hash = Sha3_256::digest(public_key);
    let mut payload = [0u8; 20];
    payload.copy_from_slice(&hash[..20]);
    address_from_hash(&payload, testnet)
}

// ── Diversified (unlinkable) addresses — privacy P4 ───────────────────────────
//
// Address reuse links a user's activity on-chain. Diversified addresses derive an
// INDEPENDENT keypair per index from the master seed: each yields an
// on-chain-unlinkable address (an observer can't tell two belong to the same
// wallet), all deterministically recoverable from the seed. Rotate one per
// receive; never reuse.

/// Per-index sub-seed for a diversified address (HD-style, domain-separated).
pub fn diversified_seed(master_seed: &[u8], index: u32) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"bloch:diversifier:v1");
    h.update(master_seed);
    h.update(index.to_le_bytes());
    h.finalize().into()
}

/// Repository-owned per-index seed used for key generation. The public
/// `diversified_seed` return remains caller-owned for API compatibility; this
/// wrapper keeps the internal copy under wiping ownership for its full use.
fn zeroizing_diversified_seed(master_seed: &[u8], index: u32) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(diversified_seed(master_seed, index))
}

/// Diversified keypair for `index` — independent, unlinkable, deterministic.
/// Compatibility entry point (plain `Vec` secret the caller must wipe);
/// prefer [`diversified_keypair_secret`].
pub fn diversified_keypair(master_seed: &[u8], index: u32)
    -> Result<(Vec<u8>, Vec<u8>), CryptoError>
{
    let (pk, sk) = diversified_keypair_secret(master_seed, index)?;
    Ok((pk, sk.to_vec()))
}

/// [`diversified_keypair`] with the secret key in a [`SecretBytes`] (CRY-4).
pub fn diversified_keypair_secret(master_seed: &[u8], index: u32)
    -> Result<(Vec<u8>, SecretBytes), CryptoError>
{
    let seed = zeroizing_diversified_seed(master_seed, index);
    generate_keypair_from_seed_secret(&seed[..])
}

/// Diversified address string for `index`.
pub fn diversified_address(master_seed: &[u8], index: u32, testnet: bool)
    -> Result<String, CryptoError>
{
    let (pk, _secret) = diversified_keypair_secret(master_seed, index)?;
    Ok(address_from_pubkey(&pk, testnet))
}

/// Format a 20-byte pubkey hash into a gnb1q/gnb1t address with 4-byte checksum.
/// Use this when you already have the hash (e.g. treasury address, multisig hash)
/// and need the user-facing string form.
pub fn address_from_hash(hash: &[u8; 20], testnet: bool) -> String {
    use crate::core::{MAINNET_PREFIX, TESTNET_PREFIX};
    let inner   = Sha3_256::digest(hash);
    let outer   = Sha3_256::digest(inner);
    let checksum = &outer[..4];
    let mut addr = hash.to_vec();
    addr.extend_from_slice(checksum);
    format!("{}{}", if testnet { TESTNET_PREFIX } else { MAINNET_PREFIX }, hex::encode(&addr))
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key: {0}")]   InvalidKey(String),
    #[error("sign failed: {0}")]   SignFailed(String),
    #[error("verify failed")]      VerifyFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    /// CRY-4: the hybrid secret key is generated in place in a
    /// `SecretBytes` (the old pre-envelope body copy, `hybrid_secret_body`,
    /// and the `Copy` pqcrypto `SecretKey` values are gone), and the memory
    /// a dropped key leaves behind is all zeros (read after the drop through
    /// the test quarantine).
    #[test]
    fn hybrid_secret_key_lives_in_secret_memory_and_is_wiped_on_drop() {
        let q = gnb_secret::test_support::Quarantine::start();
        let (pk, sk) = generate_keypair_secret();
        assert_eq!((pk.len(), sk.len()), (HYBRID_PUBLIC_KEY_LEN, HYBRID_SECRET_KEY_LEN));
        assert!(verify(&pk, b"m", &sign(&sk, b"m").unwrap()));
        let (spk, ssk) = generate_keypair_from_seed_secret(&[0x31; 32]).unwrap();
        assert!(verify(&spk, b"m", &sign(&ssk, b"m").unwrap()));
        drop((sk, ssk));
        let released = q.released();
        assert!(released.len() >= 2, "both secret keys were secret regions");
        assert!(q.all_released_zeroed(), "a dropped hybrid secret key left bytes behind");
    }
    #[test] fn sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, b"test").unwrap();
        assert!(verify(&pk, b"test", &sig));
    }
    #[test] fn wrong_message_fails() {
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, b"correct").unwrap();
        assert!(!verify(&pk, b"tampered", &sig));
    }

    // ── CRY-5 regressions ────────────────────────────────────────────────
    /// A Falcon secret key the C signer rejects (corrupted header byte, same
    /// length) used to produce `Ok` with an empty Falcon half.
    #[test]
    fn sign_fails_on_corrupted_falcon_secret_key() {
        let (pk, mut sk) = generate_keypair();
        sk[SUITE_HEADER_LEN + MLDSA_SECRET_LEN] ^= 0xFF;
        let err = sign(&sk, b"m").unwrap_err();
        assert!(matches!(err, CryptoError::SignFailed(_)), "{err}");
        assert!(sign_checked(&sk, &pk, b"m").is_err());
        let falcon_sk = &sk[SUITE_HEADER_LEN + MLDSA_SECRET_LEN..];
        assert!(falcon::sign(falcon_sk, b"m").is_err());
    }

    /// A structurally valid secret key that belongs to another public key
    /// signs, but the checked signer refuses to return the signature.
    #[test]
    fn sign_checked_refuses_a_secret_key_of_another_public_key() {
        let (pk, _) = generate_keypair();
        let (_, other_sk) = generate_keypair();
        assert!(sign(&other_sk, b"m").is_ok());
        assert!(matches!(sign_checked(&other_sk, &pk, b"m"), Err(CryptoError::SignFailed(_))));
    }

    /// Wallet side of CRY-1/CRY-2: what the checked signer returns is the
    /// canonical witness form (enveloped, compact Falcon) and passes the
    /// consensus verifier, for enveloped and raw legacy public keys alike.
    #[test]
    fn sign_checked_emits_canonical_signatures_for_both_key_encodings() {
        let (pk, sk) = generate_keypair();
        let sig = sign_checked(&sk, &pk, b"wallet-witness").unwrap();
        assert!(verify_enveloped_canonical(&pk, b"wallet-witness", &sig));
        assert!(verify(&pk, b"wallet-witness", &sig));
        assert!(verify_wallet_signature(&pk, b"wallet-witness", &sig));

        let raw_pk = &pk[SUITE_HEADER_LEN..];
        let sig = sign_checked(&sk, raw_pk, b"wallet-witness").unwrap();
        assert!(parse_envelope(&sig).is_some(), "signature keeps its suite envelope");
        assert!(verify(raw_pk, b"wallet-witness", &sig));
        assert!(!verify_wallet_signature(raw_pk, b"other", &sig));

        // A zero-padded Falcon half is not what a wallet emits.
        let mut padded = sig.clone();
        padded.resize(SUITE_HEADER_LEN + MLDSA_SIG_LEN + falcon::padded_signature_len(), 0);
        if padded != sig {
            assert!(!verify_wallet_signature(raw_pk, b"wallet-witness", &padded));
        }
    }

    // ── CRY-8: chain-bound signed-message domain ─────────────────────────
    #[test]
    fn signed_message_v2_digest_binds_the_chain_and_differs_from_v1() {
        use crate::core::ChainId;
        let m = b"prove you own this address";
        let main = signed_message_digest_v2(ChainId::Mainnet, m);
        let test = signed_message_digest_v2(ChainId::Testnet, m);
        assert_ne!(main, test);
        assert_ne!(main, signed_message_digest(m));
        assert_eq!(main, signed_message_digest_v2(ChainId::Mainnet, m));
        assert!(!SIGNED_MESSAGE_DOMAIN_V2.starts_with(SIGNED_MESSAGE_DOMAIN));
    }

    // ── CRY-4: zeroizing keygen entry points are byte-identical ──────────
    #[test]
    fn zeroizing_keygen_matches_compatibility_keygen() {
        assert!(std::mem::needs_drop::<zeroize::Zeroizing<Vec<u8>>>());
        let (pk_a, sk_a) = generate_keypair_from_seed(&[0x31; 32]).unwrap();
        let (pk_b, sk_b) = generate_keypair_from_seed_zeroizing(&[0x31; 32]).unwrap();
        assert_eq!(pk_a, pk_b);
        assert_eq!(sk_a.as_slice(), sk_b.as_slice());
        let (pk, sk) = generate_keypair_zeroizing();
        assert!(verify(&pk, b"z", &sign(&sk, b"z").unwrap()));
    }
    #[test] fn diversified_addresses_are_distinct_deterministic_and_valid() {
        let seed = [7u8; 64];
        let a0 = diversified_address(&seed, 0, true).unwrap();
        let a1 = diversified_address(&seed, 1, true).unwrap();
        let a2 = diversified_address(&seed, 2, true).unwrap();
        // Unlinkable: different indices → different addresses.
        assert_ne!(a0, a1);
        assert_ne!(a1, a2);
        assert_ne!(a0, a2);
        // Recoverable: same (seed, index) → same address.
        assert_eq!(a0, diversified_address(&seed, 0, true).unwrap());
        // Valid testnet address form.
        assert!(a0.starts_with("gnb1t"));
        // A different master seed gives a different address at the same index.
        assert_ne!(a0, diversified_address(&[8u8; 64], 0, true).unwrap());
    }
    #[test]
    fn diversified_address_matches_public_half_and_owns_discarded_secret() {
        let seed = [0x39u8; 64];
        assert!(std::mem::needs_drop::<zeroize::Zeroizing<Vec<u8>>>());

        for (index, testnet) in [
            (0, false),
            (0, true),
            (0x1020_3040, false),
            (u32::MAX, true),
        ] {
            let (pk, secret) = diversified_keypair(&seed, index).unwrap();
            let secret = zeroize::Zeroizing::new(secret);
            let expected = address_from_pubkey(&pk, testnet);

            assert_eq!(
                diversified_address(&seed, index, testnet).unwrap(),
                expected,
            );
            drop(secret);
        }
    }
    #[test]
    fn diversified_keypair_owns_exact_subseed_under_zeroizing_drop() {
        use zeroize::Zeroize;

        let master_seed = [0x5au8; 64];
        let index = 0x1020_3040;
        let public_seed = diversified_seed(&master_seed, index);
        let mut owned_seed = zeroizing_diversified_seed(&master_seed, index);

        assert!(std::mem::needs_drop::<zeroize::Zeroizing<[u8; 32]>>());
        assert_eq!(&owned_seed[..], &public_seed);

        let expected = generate_keypair_from_seed(&public_seed).unwrap();
        let actual = diversified_keypair(&master_seed, index).unwrap();
        assert_eq!(actual, expected, "zeroizing ownership must not change key bytes");

        // Structural evidence for the live owner; no post-Drop memory claim.
        owned_seed.zeroize();
        assert!(owned_seed.iter().all(|byte| *byte == 0));
    }
    #[test] fn address_format() {
        let (pk, _) = generate_keypair();
        assert!(address_from_pubkey(&pk, false).starts_with("gnb1q"));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Sprint T.1 — Audit finding C-2 fix verification
    // ═══════════════════════════════════════════════════════════════════

    /// Core guarantee: same seed → byte-identical keypair.
    /// This is the test that distinguishes real seed derivation from the
    /// admitted stub that Sprint T.1 replaces.
    #[test]
    fn seed_keypair_is_deterministic() {
        let seed = [0x42u8; 32];
        let (pk1, sk1) = generate_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = generate_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2, "same seed must produce same public key");
        assert_eq!(sk1, sk2, "same seed must produce same secret key");
    }

    /// Different seeds must produce independent keypairs.
    #[test]
    fn different_seeds_yield_different_keypairs() {
        let (pk_a, _) = generate_keypair_from_seed(&[0xAAu8; 32]).unwrap();
        let (pk_b, _) = generate_keypair_from_seed(&[0xBBu8; 32]).unwrap();
        assert_ne!(pk_a, pk_b, "different seeds must produce different keys");
    }

    /// Seeded keypair and random keypair must not collide. This confirms
    /// that the thread-local override does not leak into subsequent
    /// `generate_keypair()` calls (guard is correctly dropped).
    #[test]
    fn random_keypair_unaffected_by_prior_seeded_call() {
        let _seeded = generate_keypair_from_seed(&[0xFFu8; 32]).unwrap();
        let (pk_rand_1, _) = generate_keypair();
        let (pk_rand_2, _) = generate_keypair();
        assert_ne!(
            pk_rand_1, pk_rand_2,
            "random keypairs after seeded call must still be independent"
        );
    }

    /// Sign/verify works end-to-end with a seeded keypair.
    #[test]
    fn seeded_keypair_can_sign_and_verify() {
        let seed = [0x77u8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
        let msg = b"bloch-test-message";
        let sig = sign(&sk, msg).unwrap();
        assert!(verify(&pk, msg, &sig));
    }

    /// Short seeds must be rejected with a clear error.
    #[test]
    fn short_seed_rejected() {
        let result = generate_keypair_from_seed(&[0u8; 16]);
        assert!(result.is_err());
    }
}

// ── Falcon-1024 (Sprint B6b) ────────────────────────────────────────────────
//
// The second signature of the hybrid ML-DSA-65 ‖ Falcon-1024 scheme: two
// distinct lattice families (NTRU vs Module-LWE/SIS) for defence in depth — a
// break of one assumption does not forge a signature. Falcon verification is
// deterministic (integer), so it is consensus-safe. Falcon *signing* is pinned
// to PQClean's `clean` variant (PoS finding F1, BLOCH-FALCON-ONLINE-SIGNING.md
// §3.2): integer-only emulated IEEE-754 Gaussian sampling, constant-time by
// construction and bit-exact across platforms — the native floating-point
// variants (avx2/aarch64) are excluded via `default-features = false` and
// guarded by the tripwire test + KAT below and scripts/falcon-clean-guard.sh.
pub mod falcon {
    use pqcrypto_falcon::falcon1024;
    use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
    use super::{CryptoError, SecretBytes};

    /// Falcon-1024 public-key length (bytes).
    pub fn pubkey_len() -> usize { falcon1024::public_key_bytes() }

    /// Length of Falcon-1024's alternate fixed-width padded signature.
    ///
    /// The compatibility verifier accepts this representation; canonical
    /// policies use the value to construct or identify migration fixtures.
    pub fn padded_signature_len() -> usize {
        pqcrypto_falcon::falconpadded1024::signature_bytes()
    }

    /// Compatibility entry point: [`keypair_secret`] with the secret copied
    /// into a plain `Vec` the caller must wipe.
    pub fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = keypair_secret();
        (pk, sk.to_vec())
    }

    /// [`keypair`] with the secret key under wiping ownership (CRY-4,
    /// compatibility).
    pub fn keypair_zeroizing() -> (Vec<u8>, zeroize::Zeroizing<Vec<u8>>) {
        let (pk, sk) = keypair_secret();
        (pk, zeroize::Zeroizing::new(sk.to_vec()))
    }

    /// A Falcon-1024 key pair generated in place in a [`SecretBytes`]
    /// (CRY-4: no `Copy` `SecretKey` value).
    pub fn keypair_secret() -> (Vec<u8>, SecretBytes) {
        let mut pk = vec![0u8; super::FALCON_PUBKEY_LEN];
        let mut sk = SecretBytes::zeroed(super::FALCON_SECRET_LEN);
        gnb_secret::pq::falcon1024_keypair(&mut pk, &mut sk).expect("Falcon-1024 key generation");
        gnb_secret::scrub_stack();
        (pk, sk)
    }

    /// Falcon-1024 detached signature (compact encoding).
    ///
    /// CRY-5: `pqcrypto-falcon` ignores the C signer's return code; on
    /// failure the output stays EMPTY. The output is therefore required to
    /// be a well-formed compact encoding (header byte, nonce, exactly framed
    /// coefficients) before it is returned; anything else is an error.
    pub fn sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // CRY-4: signed straight from the borrowed bytes; no `Copy`
        // `SecretKey` value. The C signer's return code is checked too.
        let sig = match gnb_secret::pq::falcon1024_sign(secret_key_bytes, message) {
            Ok(sig) => sig,
            Err(gnb_secret::pq::PqError::BadLength { .. }) => {
                return Err(CryptoError::InvalidKey("bad falcon secret key".into()));
            }
            Err(e) => {
                return Err(CryptoError::SignFailed(format!(
                    "Falcon-1024 signer failed ({e}; corrupted secret key?)")));
            }
        };
        if sig.len() > falcon1024::signature_bytes() || !is_compact_signature_encoding(&sig) {
            return Err(CryptoError::SignFailed(format!(
                "Falcon-1024 signer failed (returned {} bytes; corrupted secret key?)",
                sig.len()
            )));
        }
        Ok(sig)
    }

    /// Deterministic verification (consensus rule): malformed inputs → false.
    pub fn verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
        let pk = match falcon1024::PublicKey::from_bytes(public_key_bytes) {
            Ok(p) => p, Err(_) => return false,
        };
        let sig = match falcon1024::DetachedSignature::from_bytes(signature_bytes) {
            Ok(s) => s, Err(_) => return false,
        };
        falcon1024::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    /// Verify only Falcon-1024's compact, non-padded detached encoding.
    ///
    /// The historical verifier deliberately accepts PQClean's alternate
    /// 1280-byte zero-padded representation. That is consensus compatibility,
    /// but it also gives one mathematical signature two byte encodings. New
    /// non-consensus formats can opt into this entry point to require the exact
    /// compact encoding emitted by [`sign`].
    pub fn verify_canonical(
        public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> bool {
        is_compact_signature_encoding(signature_bytes)
            && verify(public_key_bytes, message, signature_bytes)
    }

    /// `true` iff `signature` is a well-formed COMPACT Falcon-1024 encoding
    /// (the only one [`sign`] emits) no longer than the compact maximum.
    /// Format only; no signature math.
    pub fn is_canonical_encoding(signature: &[u8]) -> bool {
        signature.len() <= falcon1024::signature_bytes() && is_compact_signature_encoding(signature)
    }

    const FALCON1024_HEADER: u8 = 0x30 + 10;
    const FALCON_NONCE_LEN: usize = 40;
    const FALCON1024_COEFFICIENTS: usize = 1024;

    fn is_compact_signature_encoding(signature: &[u8]) -> bool {
        if signature.len() <= 1 + FALCON_NONCE_LEN || signature[0] != FALCON1024_HEADER {
            return false;
        }
        let encoded = &signature[1 + FALCON_NONCE_LEN..];
        compact_encoding_len(encoded) == Some(encoded.len())
    }

    /// Length-only mirror of PQClean's `comp_decode` framing. It validates the
    /// unique sign/magnitude+unary encoding without performing signature math.
    fn compact_encoding_len(encoded: &[u8]) -> Option<usize> {
        let mut accumulator = 0u32;
        let mut remaining_bits = 0u32;
        let mut consumed = 0usize;

        for _ in 0..FALCON1024_COEFFICIENTS {
            let next = *encoded.get(consumed)?;
            consumed += 1;
            accumulator = (accumulator << 8) | u32::from(next);
            let first = accumulator >> remaining_bits;
            let sign = first & 128;
            let mut magnitude = first & 127;

            loop {
                if remaining_bits == 0 {
                    let next = *encoded.get(consumed)?;
                    consumed += 1;
                    accumulator = (accumulator << 8) | u32::from(next);
                    remaining_bits = 8;
                }
                remaining_bits -= 1;
                if ((accumulator >> remaining_bits) & 1) != 0 {
                    break;
                }
                magnitude += 128;
                if magnitude > 2047 {
                    return None;
                }
            }
            if sign != 0 && magnitude == 0 {
                return None;
            }
        }

        let unused_mask = (1u32 << remaining_bits).wrapping_sub(1);
        if accumulator & unused_mask != 0 {
            return None;
        }
        Some(consumed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn falcon_roundtrip() {
            let (pk, sk) = keypair();
            let msg = b"bloch-falcon-b6b";
            let sig = sign(&sk, msg).expect("sign");
            assert!(verify(&pk, msg, &sig), "valid falcon sig must verify");
            assert!(!verify(&pk, b"other message", &sig), "wrong message must fail");
            let mut bad = sig.clone(); bad[0] ^= 0x01;
            assert!(!verify(&pk, msg, &bad), "tampered sig must fail");
        }

        #[test]
        fn canonical_verifier_rejects_the_legacy_zero_padded_variant() {
            // Use the same deterministic RNG fixture as the clean-variant KAT
            // below. A random compact Falcon signature can legitimately fill
            // all 1280 bytes, in which case `resize` adds no padding and this
            // test would fail before exercising either verifier.
            let msg = b"bloch-pos-falcon-clean-kat-v1";
            let (pk, sig) = pqcrypto_internals::with_seeded_rng_scope(&[0xB1; 32], || {
                let (pk, sk) = keypair();
                let sig = sign(&sk, msg).expect("seeded falcon sign");
                (pk, sig)
            });
            assert!(verify_canonical(&pk, msg, &sig));

            let mut padded = sig.clone();
            padded.resize(
                pqcrypto_falcon::falconpadded1024::signature_bytes(),
                0,
            );
            assert_ne!(
                padded, sig,
                "fresh compact signature must leave padding room"
            );
            assert!(
                verify(&pk, msg, &padded),
                "legacy verifier accepts PQClean padding"
            );
            assert!(!verify_canonical(&pk, msg, &padded));

            assert!(!verify_canonical(&pk, msg, &sig[..sig.len() - 1]));
            let mut tampered = sig;
            tampered[1] ^= 1;
            assert!(!verify_canonical(&pk, msg, &tampered));
        }

        // ── F1 guard: the constant-time `clean` path must be the ONLY Falcon ──
        // implementation in the binary (BLOCH-FALCON-ONLINE-SIGNING.md §3.2).
        //
        // `pqcrypto-falcon`'s DEFAULT features ("avx2", "neon") compile PQClean's
        // native floating-point variants and runtime-dispatch signing to them
        // (AVX2 doubles on x86_64, `typedef double fpr` on aarch64). A PoS
        // validator signs on a publicly known schedule, so Falcon signing must
        // run PQClean's `clean` variant: integer-emulated IEEE-754, constant-time
        // by construction. The workspace therefore declares the crate with
        // `default-features = false`.
        //
        // A Cargo.toml declaration alone is not proof — features are ADDITIVE,
        // so any workspace member (or a future dependency) re-enabling the
        // defaults silently restores native-FP dispatch for every build. This
        // test inspects the test executable itself: when the avx2/neon features
        // are off, the FP variants' C files are never compiled and their symbols
        // (`PQCLEAN_FALCON1024_AVX2_*`, `PQCLEAN_FALCON1024_AARCH64_*`) cannot
        // exist in the binary; when a feature is re-enabled, the dispatch code
        // references them and the linker must keep them. Symbol ABSENCE is
        // therefore a faithful tripwire, on every target, for "the constant-time
        // path is the only path".
        //
        // The needles are assembled at runtime from fragments so the test's own
        // string literals cannot produce a false positive in the scan.

        /// Plain forward byte-substring scan (no regex/memmem dependency).
        fn binary_contains(haystack: &[u8], needle: &[u8]) -> bool {
            if needle.is_empty() || haystack.len() < needle.len() {
                return false;
            }
            let first = needle[0];
            let mut i = 0;
            while i + needle.len() <= haystack.len() {
                if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
                    return true;
                }
                i += 1;
            }
            false
        }

        #[test]
        fn falcon_native_fp_variants_are_not_linked() {
            let exe = std::env::current_exe().expect("current_exe");
            let bytes = std::fs::read(&exe).expect("read test executable");

            // Assembled at runtime — the concatenated needle never appears as a
            // contiguous literal in this test's own rodata.
            let sym = |variant: &str| format!("PQCLEAN_{}{}_{}_crypto_sign", "FALCON", "1024", variant);
            let clean = sym("CLEAN");
            let avx2 = sym("AVX2");
            let aarch64 = sym("AARCH64");

            // Control: the `clean` symbols MUST be visible. If this fails, the
            // binary's symbol names are not observable (e.g. stripped test
            // binary) and the absence checks below would be vacuous — fail
            // loudly instead of false-passing.
            assert!(
                binary_contains(&bytes, clean.as_bytes()),
                "control failed: `{clean}` not found in {} — symbol names are not \
                 observable in this binary, so this guard cannot run (is the test \
                 binary stripped?)",
                exe.display()
            );

            // Tripwire: no native floating-point Falcon variant may be linked.
            for fp in [&avx2, &aarch64] {
                assert!(
                    !binary_contains(&bytes, fp.as_bytes()),
                    "NATIVE FLOATING-POINT Falcon implementation `{fp}` is linked \
                     into the binary. Someone re-enabled pqcrypto-falcon's default \
                     features (avx2/neon) somewhere in the workspace. Under PoS the \
                     validator signs on a public schedule and must use PQClean's \
                     integer-only constant-time `clean` variant exclusively — see \
                     BLOCH-FALCON-ONLINE-SIGNING.md §3.2 and the pqcrypto-falcon \
                     entries in Cargo.toml (`default-features = false`)."
                );
            }
        }

        // ── F1 KAT: seeded Falcon-1024 keygen + sign pinned byte-for-byte ────
        //
        // Purpose: prove the switch to the `clean` variant did NOT change the
        // wire format or the produced bytes. PQClean requires all variants of a
        // scheme to be KAT-compatible (same randombytes stream → same key/sig
        // bytes), so these pins hold across `clean`/avx2/aarch64 AND across
        // platforms — `clean` is bit-exact integer emulation. A dependency bump
        // that changed the produced bytes (format break, sampler change, e.g. a
        // silent move to FN-DSA semantics) fails here before it can hit
        // consensus. NOTE: precisely because the variants are KAT-compatible,
        // this test does NOT prove which variant runs — that is
        // `falcon_native_fp_variants_are_not_linked`'s job. The two tests
        // together are the guard.
        //
        // Seeded signing is REGRESSION PINNING ONLY: production Falcon signing
        // must stay randomized (fresh salt per signature — the property that
        // neutralizes the "Sleeping Falcon" FP-divergence attack, eprint
        // 2024/1709). Never seed the RNG around a production signer.
        #[test]
        fn falcon_clean_seeded_kat_is_byte_stable_and_verifies() {
            use sha3::{Digest, Sha3_256};

            const KAT_SEED: [u8; 32] = [0xB1; 32];
            const KAT_MSG: &[u8] = b"bloch-pos-falcon-clean-kat-v1";

            // Pinned on pqcrypto-falcon 0.4.1, `clean` variant (aarch64 host;
            // bit-exact on every platform by construction).
            const KAT_PK_HASH: &str =
                "afc79ea102992a5081b8172b55fb7c14e01ff2a74501a8577d1fe4df094c2375";
            const KAT_SIG_HASH: &str =
                "645bf4db96650515c016aa1f615b78ad4dac5985363abdfbb8a3e0fc4a5d2e24";
            const KAT_SIG_LEN: usize = 1271;

            let (pk, sk, sig) = pqcrypto_internals::with_seeded_rng_scope(&KAT_SEED, || {
                let (pk, sk) = keypair();
                let sig = sign(&sk, KAT_MSG).expect("seeded falcon sign");
                (pk, sk, sig)
            });
            // Falcon signatures are variable-length in general; under a fixed
            // randomness stream the length is fixed too, so pin it as well.
            assert_eq!(sig.len(), KAT_SIG_LEN, "seeded Falcon signature length drifted");
            assert_eq!(
                hex::encode(Sha3_256::digest(&pk)),
                KAT_PK_HASH,
                "seeded Falcon-1024 public key drifted from the pinned KAT"
            );
            assert_eq!(
                hex::encode(Sha3_256::digest(&sig)),
                KAT_SIG_HASH,
                "seeded Falcon-1024 signature drifted from the pinned KAT"
            );

            // Compatibility both ways: the pinned signature verifies, and a
            // fresh (OS-randomness) signature under the same key verifies too —
            // the format change surface is zero.
            assert!(verify(&pk, KAT_MSG, &sig), "pinned KAT signature must verify");
            let fresh = sign(&sk, KAT_MSG).expect("randomized falcon sign");
            assert!(verify(&pk, KAT_MSG, &fresh), "randomized signature must verify");
            assert_ne!(fresh, sig, "production signing must remain randomized (fresh salt)");
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Roadmap #5 — KATs + reference-equivalence + no-panic fuzz (audit-prep).
//
// Scope (see docs/../roadmap-crypto-core §3.1 items 2–3, §4 items 1–3):
//   (A) Reference-equivalence for the borrowed primitives — prove the hybrid
//       wrapper preserves the upstream ML-DSA-65 / Falcon-1024 byte layout
//       (catches offset/endianness/split bugs). The upstream `pqcrypto-*`
//       crates are used as the reference ORACLE; no vectors are fabricated.
//   (B) Golden regression vector for deterministic keygen-from-seed.
//   (C) No-panic fuzz of the signature parse+verify path.
//
// KAT SOURCE / HONESTY: the official NIST FIPS-204 ML-DSA-65 `.rsp` KAT files
// and the Falcon-1024 NIST KATs are NOT vendored in-tree — only PQClean's
// `nistkat.c` C harness ships in the `pqcrypto-*` crates, which is not callable
// from Rust and, crucially, reproduces its keypair from a NIST AES-256-CTR DRBG
// while Bloch's `generate_keypair_from_seed` uses a ChaCha20 stream. A signed
// NIST `.rsp` vector therefore does NOT reproduce a Bloch seeded keypair. What
// IS provable here without fabrication is that Bloch's wrapper does not corrupt
// the underlying scheme: a signature produced with the upstream primitive at
// the documented offsets verifies through Bloch's hybrid `verify`, and vice
// versa. Full NIST-KAT wiring still needs: (1) the official `.rsp` files
// vendored, and (2) an AES-256-CTR NIST DRBG to drive keygen — see the
// `#[ignore]`d `full_nist_kat_wiring_todo` below.
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod kat {
    use super::*;
    use pqcrypto_falcon::falcon1024;
    use pqcrypto_mldsa::mldsa65;
    // Test fixtures build legacy keys with the wrappers directly (CRY-4
    // keeps their `Copy` `SecretKey` out of production code only).
    use pqcrypto_traits::sign::SecretKey;
    // NOTE: the `pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey}`
    // trait imports were removed here: the suite-envelope refactor replaced the
    // kat module's direct trait-method slicing with `parse_envelope(..)` body
    // access, so those traits are no longer referenced in this module.

    // Falcon-1024 public-key length (used for the reverse-split oracle test).
    const FALCON_PUBKEY_LEN: usize = 1793;

    #[test]
    fn valid_magic_prefixed_raw_signature_requires_explicit_legacy_policy() {
        const MESSAGE: &[u8] = b"BLOCH-CR10-MAGIC-PREFIX-FIXTURE-v1";
        const SEARCH_COUNTER: u64 = 23_156;
        const SIGNING_SEED_HEX: &str =
            "5d051b8c445a2f169a9a0104877500c39332cb493ec6de2723cb37dfbb233042";

        let (enveloped_pk, enveloped_sk) =
            generate_keypair_from_seed(&[0x64; 32]).unwrap();
        let mut h = Sha3_256::new();
        h.update(b"bloch/cr10/signing-rng/v1");
        h.update(SEARCH_COUNTER.to_le_bytes());
        let signing_seed: [u8; 32] = h.finalize().into();
        assert_eq!(hex::encode(signing_seed), SIGNING_SEED_HEX);

        let enveloped_sig = pqcrypto_internals::with_seeded_rng_scope(
            &signing_seed,
            || sign(&enveloped_sk, MESSAGE).unwrap(),
        );
        let raw_pk = &enveloped_pk[SUITE_HEADER_LEN..];
        let raw_sig = &enveloped_sig[SUITE_HEADER_LEN..];

        assert_eq!(&raw_sig[..2], &SUITE_MAGIC, "fixture must hit the ambiguity");
        assert!(
            verify_legacy_hybrid_raw(raw_pk, MESSAGE, raw_sig),
            "the magic-prefixed raw signature is cryptographically genuine"
        );
        assert!(verify_legacy_hybrid_raw_canonical(raw_pk, MESSAGE, raw_sig));
        assert!(
            !verify(raw_pk, MESSAGE, raw_sig),
            "generic autodetection must misclassify the raw magic prefix"
        );

        let (misclassified_suite, _) = parse_envelope(raw_sig).unwrap();
        assert_ne!(
            misclassified_suite,
            SUITE_MLDSA65_FALCON1024,
            "bytes after the coincidental magic are not trusted format metadata"
        );
    }

    // ─── (A) Reference-equivalence: primitive length KATs ─────────────────────
    // The hybrid wrapper hard-codes the ML-DSA split offsets. If the upstream
    // crate ever changed a length, the fixed 1952/4032/3309 splits would slice
    // the wrong bytes — assert they still match the primitive.
    #[test]
    fn primitive_lengths_match_hybrid_split_offsets() {
        assert_eq!(mldsa65::public_key_bytes(), MLDSA_PUBKEY_LEN, "ML-DSA-65 pk len");
        assert_eq!(mldsa65::secret_key_bytes(), MLDSA_SECRET_LEN, "ML-DSA-65 sk len");
        assert_eq!(mldsa65::signature_bytes(), MLDSA_SIG_LEN, "ML-DSA-65 sig len");
        assert_eq!(falcon1024::public_key_bytes(), FALCON_PUBKEY_LEN, "Falcon-1024 pk len");

        // Enveloped objects = 4-byte suite header + the raw primitive lengths.
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, b"envelope-len-check").unwrap();
        assert_eq!(pk.len(), SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN + FALCON_PUBKEY_LEN,
                   "enveloped hybrid pk = header + mldsa_pk + falcon_pk");
        assert_eq!(sk.len(), SUITE_HEADER_LEN + MLDSA_SECRET_LEN + falcon1024::secret_key_bytes(),
                   "enveloped hybrid sk = header + mldsa_sk + falcon_sk");
        // Falcon signature is variable-length, so the enveloped sig is bounded
        // above by header + mldsa_sig + Falcon MAX, and strictly larger than the
        // header + mldsa_sig (a non-empty Falcon tail is present).
        assert!(sig.len() > SUITE_HEADER_LEN + MLDSA_SIG_LEN,
                   "enveloped hybrid sig must carry a Falcon tail");
        assert!(sig.len() <= SUITE_HEADER_LEN + MLDSA_SIG_LEN + falcon1024::signature_bytes(),
                   "enveloped hybrid sig <= header + mldsa_sig + falcon_sig(max)");
        // The header carries the magic + suite 0x0001.
        assert_eq!(&pk[..2], &SUITE_MAGIC, "pk magic");
        assert_eq!(u16::from_le_bytes([pk[2], pk[3]]), SUITE_MLDSA65_FALCON1024, "pk suite id");
    }

    // ─── (A) Reference-equivalence: upstream-built artifact verifies via Bloch ─
    // Build a hybrid keypair + signature by hand from the UPSTREAM primitives in
    // the documented ML-DSA-first order, then feed it to Bloch's `verify`.
    // Acceptance proves Bloch splits `pk`/`sig` at exactly the upstream byte
    // boundaries (offset/endianness bug catcher).
    #[test]
    fn upstream_built_hybrid_verifies_through_bloch() {
        let msg = b"reference-equivalence-forward";
        let (mpk, msk) = mldsa65::keypair();
        let (fpk, fsk) = falcon1024::keypair();

        // pk = mldsa_pk(1952) ‖ falcon_pk ; sig = mldsa_sig(3309) ‖ falcon_sig,
        // each wrapped in the suite-0x0001 envelope Bloch's verify now expects.
        let mut pk_body = mpk.as_bytes().to_vec();
        pk_body.extend_from_slice(fpk.as_bytes());
        let mut sig_body = mldsa65::detached_sign(msg, &msk).as_bytes().to_vec();
        sig_body.extend_from_slice(falcon1024::detached_sign(msg, &fsk).as_bytes());
        let pk = wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk_body);
        let sig = wrap_envelope(SUITE_MLDSA65_FALCON1024, &sig_body);

        assert!(
            verify(&pk, msg, &sig),
            "hybrid assembled from upstream primitives at documented offsets must verify"
        );
        // Sanity: a different message must fail (the wrapper really checks it).
        assert!(!verify(&pk, b"other", &sig));
    }

    #[test]
    fn strict_enveloped_verifier_rejects_raw_and_mixed_encodings() {
        let msg = b"strict-enveloped-format";
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, msg).unwrap();
        let raw_pk = &pk[SUITE_HEADER_LEN..];
        let raw_sig = &sig[SUITE_HEADER_LEN..];

        assert!(verify_enveloped(&pk, msg, &sig));
        assert!(!verify_enveloped(raw_pk, msg, &sig));
        assert!(!verify_enveloped(&pk, msg, raw_sig));
        assert!(!verify_enveloped(raw_pk, msg, raw_sig));
        assert!(!verify_enveloped(&pk, b"other", &sig));
    }

    #[test]
    fn canonical_enveloped_verifier_rejects_padded_falcon_half() {
        let msg = b"canonical-enveloped-format";
        let (pk, sk) = generate_keypair_from_seed(&[0x58; 32]).unwrap();
        let sig = pqcrypto_internals::with_seeded_rng_scope(&[0xA5; 32], || {
            sign(&sk, msg).unwrap()
        });

        assert!(verify_enveloped(&pk, msg, &sig));
        assert!(verify_enveloped_canonical(&pk, msg, &sig));

        let falcon_offset = SUITE_HEADER_LEN + MLDSA_SIG_LEN;
        let padded_len = falcon_offset + pqcrypto_falcon::falconpadded1024::signature_bytes();
        assert!(
            sig.len() < padded_len,
            "pinned compact signature must fit padded form"
        );
        let mut padded = sig.clone();
        padded.resize(padded_len, 0);

        assert!(
            verify_enveloped(&pk, msg, &padded),
            "compatibility verifier must retain the accepted padded form"
        );
        assert!(!verify_enveloped_canonical(&pk, msg, &padded));
        assert!(!verify_enveloped_canonical(
            &pk[SUITE_HEADER_LEN..],
            msg,
            &sig
        ));

        let (mpk, msk) = mldsa65::keypair();
        let mldsa_pk = wrap_envelope(SUITE_MLDSA65_ONLY, mpk.as_bytes());
        let mldsa_sk = wrap_envelope(SUITE_MLDSA65_ONLY, msk.as_bytes());
        let mldsa_sig = sign(&mldsa_sk, msg).unwrap();
        assert!(verify_enveloped_canonical(&mldsa_pk, msg, &mldsa_sig));
    }

    /// Honest signatures always satisfy the FIPS 204 z bound; a coefficient
    /// at exactly ±(γ1 − β) does not.
    #[test]
    fn mldsa_z_norm_bound() {
        for i in 0..20u8 {
            let (pk, sk) = generate_keypair_from_seed(&[i; 32]).unwrap();
            let msg = [i; 32];
            let sig = sign(&sk, &msg).unwrap();
            let body = &sig[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SIG_LEN];
            assert!(mldsa65_z_within_bound(body), "honest signature {i}");
            assert!(verify(&pk, &msg, &sig));
        }
        let (_, sk) = generate_keypair_from_seed(&[0x77; 32]).unwrap();
        let sig = sign(&sk, b"bound").unwrap();
        let body = sig[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SIG_LEN].to_vec();
        let gamma1: u32 = 1 << 19;
        let beta: u32 = 196;
        // Coefficient 0 (bits 0..20 of z, which starts after the 48-byte c̃).
        let set = |b: &mut Vec<u8>, packed: u32| {
            let w = u32::from(b[48]) | u32::from(b[49]) << 8 | u32::from(b[50]) << 16;
            let w = (w & !0xF_FFFF) | (packed & 0xF_FFFF);
            b[48] = w as u8; b[49] = (w >> 8) as u8; b[50] = (w >> 16) as u8;
        };
        for (z, ok) in [(gamma1 - beta - 1, true), (gamma1 - beta, false)] {
            for (packed, sign) in [(gamma1 - z, "+"), (gamma1 + z, "-")] {
                let mut b = body.clone();
                set(&mut b, packed);
                assert_eq!(mldsa65_z_within_bound(&b), ok, "z = {sign}{z}");
            }
        }
    }

    /// The single-key consensus verifier: enveloped AND legacy raw keys and
    /// signatures (the carryover) still verify, but only with the compact
    /// Falcon encoding.
    #[test]
    fn consensus_canonical_verifier_keeps_legacy_but_refuses_padded_falcon() {
        let msg = b"single-key-consensus";
        let (pk, sk) = generate_keypair_from_seed(&[0x58; 32]).unwrap();
        let sig = pqcrypto_internals::with_seeded_rng_scope(&[0xA5; 32], || sign(&sk, msg).unwrap());
        assert!(verify_canonical(&pk, msg, &sig), "enveloped compact");
        assert!(verify_canonical(&pk[SUITE_HEADER_LEN..], msg, &sig[SUITE_HEADER_LEN..]), "legacy raw compact");

        let falcon_offset = SUITE_HEADER_LEN + MLDSA_SIG_LEN;
        let mut padded = sig.clone();
        padded.resize(falcon_offset + pqcrypto_falcon::falconpadded1024::signature_bytes(), 0);
        assert!(verify(&pk, msg, &padded), "the historical verifier accepts the padded form");
        assert!(!verify_canonical(&pk, msg, &padded), "consensus refuses it");
        assert!(!verify_canonical(&pk[SUITE_HEADER_LEN..], msg, &padded[SUITE_HEADER_LEN..]));
    }

    #[test]
    fn canonical_raw_verifier_rejects_padded_falcon_half_without_sniffing() {
        // Reuse the exact deterministic compact fixture from the enveloped
        // test above, then strip only its suite headers. Random Falcon
        // signatures vary in encoded length and can already fill the padded
        // form, making this fixture precondition flaky before either verifier
        // is exercised.
        let msg = b"canonical-enveloped-format";
        let (enveloped_pk, enveloped_sk) =
            generate_keypair_from_seed(&[0x58; 32]).unwrap();
        let enveloped_sig = pqcrypto_internals::with_seeded_rng_scope(&[0xA5; 32], || {
            sign(&enveloped_sk, msg).unwrap()
        });
        let (pk_suite, pk) = split_envelope(&enveloped_pk).unwrap();
        let (sig_suite, sig) = split_envelope(&enveloped_sig).unwrap();
        assert_eq!(pk_suite, SUITE_MLDSA65_FALCON1024);
        assert_eq!(sig_suite, SUITE_MLDSA65_FALCON1024);
        let pk = pk.to_vec();
        let sig = sig.to_vec();

        assert!(verify_legacy_hybrid_raw(&pk, msg, &sig));
        assert!(verify_legacy_hybrid_raw_canonical(&pk, msg, &sig));

        let padded_len = MLDSA_SIG_LEN
            + pqcrypto_falcon::falconpadded1024::signature_bytes();
        assert!(sig.len() < padded_len, "compact fixture must leave padding room");
        let mut padded = sig.clone();
        padded.resize(padded_len, 0);

        assert!(
            verify_legacy_hybrid_raw(&pk, msg, &padded),
            "compatibility raw verifier must retain padded acceptance"
        );
        assert!(!verify_legacy_hybrid_raw_canonical(&pk, msg, &padded));
        assert!(!verify_legacy_hybrid_raw_canonical(
            &wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk),
            msg,
            &sig,
        ));
        assert!(!verify_legacy_hybrid_raw_canonical(
            &pk,
            msg,
            &wrap_envelope(SUITE_MLDSA65_FALCON1024, &sig),
        ));
        assert!(!verify_legacy_hybrid_raw_canonical(&pk, b"other", &sig));
    }

    /// A genuine LEGACY (non-enveloped) hybrid object — no magic, no header,
    /// exactly the carry-over encoding — must still verify through the public
    /// `verify()` entry point via the length-based classification.
    #[test]
    fn genuine_legacy_raw_hybrid_verifies_through_bloch() {
        let msg = b"legacy-carry-over-raw-hybrid";
        let (mpk, msk) = mldsa65::keypair();
        let (fpk, fsk) = falcon1024::keypair();

        let mut pk_raw = mpk.as_bytes().to_vec();
        pk_raw.extend_from_slice(fpk.as_bytes());
        let mut sig_raw = mldsa65::detached_sign(msg, &msk).as_bytes().to_vec();
        sig_raw.extend_from_slice(falcon1024::detached_sign(msg, &fsk).as_bytes());

        assert_eq!(pk_raw.len(), legacy_hybrid_pubkey_len());
        assert!(verify_legacy_hybrid_raw(&pk_raw, msg, &sig_raw));
        assert!(!verify_legacy_hybrid_raw(&pk_raw, b"other", &sig_raw));
        assert!(!verify_legacy_hybrid_raw(&wrap_envelope(SUITE_MLDSA65_FALCON1024, &pk_raw), msg, &sig_raw));
        assert!(!verify_legacy_hybrid_raw(&pk_raw, msg, &wrap_envelope(SUITE_MLDSA65_FALCON1024, &sig_raw)));
        // Historical auto-detection remains unchanged. Its rare raw-signature
        // collision is deliberately not promoted into an unversioned fallback.
        if !sig_raw.starts_with(&[0xb1, 0x0c]) {
            assert!(verify(&pk_raw, msg, &sig_raw), "unambiguous raw legacy hybrid must verify");
        }
        assert!(!verify(&pk_raw, b"other", &sig_raw));
    }

    /// A4 lows (legacy pubkey fallback): a raw legacy pubkey that happens to
    /// start with the 4-byte suite header's magic `[0xB1, 0x0C]` must NOT be
    /// misclassified as an enveloped object. A genuine collision is a
    /// 1-in-65536 event over real key material — far too rare to brute-force
    /// a real ML-DSA-65 keypair for in a test — so this constructs the
    /// SHAPE directly: a buffer of exactly `legacy_hybrid_pubkey_len()` bytes
    /// leading with the magic. Length alone must win the classification.
    #[test]
    fn legacy_pubkey_starting_with_envelope_magic_is_not_misclassified() {
        let len = legacy_hybrid_pubkey_len();
        let mut raw_pk = vec![0xABu8; len];
        raw_pk[0] = 0xB1;
        raw_pk[1] = 0x0C;

        let (suite, body) = parse_pubkey_envelope_or_legacy(&raw_pk);
        assert_eq!(suite, SUITE_MLDSA65_FALCON1024, "exact legacy length must win over the magic heuristic");
        assert_eq!(body.len(), len, "the WHOLE buffer is the body — no header may be stripped");

        // Contrast: the magic-only heuristic (`parse_envelope_or_legacy`, still
        // used for signatures, whose length is not fixed) DOES misread this
        // buffer as enveloped and strips 4 bytes — demonstrating the bug this
        // pubkey-specific fix closes.
        let (old_suite, old_body) = parse_envelope_or_legacy(&raw_pk);
        assert_eq!(old_body.len(), len - SUITE_HEADER_LEN, "sanity: the naive heuristic strips a header here");
        assert_ne!(old_suite, suite, "sanity: the naive heuristic derives a bogus suite id from key bytes");
    }

    #[test]
    fn hybrid_public_key_policy_distinguishes_live_and_crypto_agility_suites() {
        let raw_hybrid = vec![0xabu8; legacy_hybrid_pubkey_len()];
        let enveloped_hybrid = wrap_envelope(SUITE_MLDSA65_FALCON1024, &raw_hybrid);
        let mldsa_only = wrap_envelope(SUITE_MLDSA65_ONLY, &vec![0xcdu8; MLDSA_PUBKEY_LEN]);

        assert!(is_hybrid_public_key(&raw_hybrid));
        assert!(is_hybrid_public_key(&enveloped_hybrid));
        assert!(!is_hybrid_public_key(&mldsa_only));
        assert!(!is_hybrid_public_key(&enveloped_hybrid[..enveloped_hybrid.len() - 1]));

        // The exact legacy length wins over coincidental magic, just as it
        // does in verification; old funds are not stranded by this policy.
        let mut magic_collision = raw_hybrid;
        magic_collision[..2].copy_from_slice(&SUITE_MAGIC);
        magic_collision[2..4].copy_from_slice(&SUITE_MLDSA65_ONLY.to_le_bytes());
        assert!(is_hybrid_public_key(&magic_collision));
    }

    // ─── (A) Reference-equivalence: Bloch-built halves parse as upstream prims ─
    // The reverse direction: take a Bloch hybrid keypair/signature, split at the
    // documented offsets, and verify each half DIRECTLY with the upstream crate.
    // Proves Bloch's concatenation emits valid, correctly-ordered upstream bytes.
    #[test]
    fn bloch_built_halves_verify_as_upstream_primitives() {
        let msg = b"reference-equivalence-reverse";
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, msg).unwrap();

        // Strip the 4-byte suite header before splitting at the primitive offsets.
        let (_pk_suite, pk_body)  = parse_envelope(&pk).expect("pk envelope");
        let (_sig_suite, sig_body) = parse_envelope(&sig).expect("sig envelope");
        let (mpk_b, fpk_b) = pk_body.split_at(MLDSA_PUBKEY_LEN);
        let (msig_b, fsig_b) = sig_body.split_at(MLDSA_SIG_LEN);

        // ML-DSA half through the upstream primitive directly.
        let mpk = mldsa65::PublicKey::from_bytes(mpk_b).expect("ML-DSA pk half must parse upstream");
        let msig = mldsa65::DetachedSignature::from_bytes(msig_b)
            .expect("ML-DSA sig half must parse upstream");
        assert!(
            mldsa65::verify_detached_signature(&msig, msg, &mpk).is_ok(),
            "Bloch ML-DSA half must verify under the upstream primitive"
        );

        // Falcon half through the upstream primitive directly.
        let fpk = falcon1024::PublicKey::from_bytes(fpk_b).expect("Falcon pk half must parse upstream");
        let fsig = falcon1024::DetachedSignature::from_bytes(fsig_b)
            .expect("Falcon sig half must parse upstream");
        assert!(
            falcon1024::verify_detached_signature(&fsig, msg, &fpk).is_ok(),
            "Bloch Falcon half must verify under the upstream primitive"
        );
    }

    // ─── (B) Golden regression vector: deterministic keygen-from-seed ─────────
    // Fixed seed → byte-stable keypair. This vector pins the ML-DSA-65 halves:
    // FIPS 204 keygen (Alg. 6) is deterministic AND platform-stable given the
    // byte stream, so these hashes are portable regression anchors. The
    // Falcon-1024 half is just as reproducible (PQClean's `clean` variant is
    // integer-only, emulating IEEE-754 bit-exactly on every platform); it is
    // pinned separately by `falcon::tests::falcon_clean_seeded_kat_is_byte_stable_and_verifies`.
    // If pqcrypto-mldsa's internal keygen order ever changes, these hashes
    // change and wallet recovery breaks — that is exactly what this vector
    // guards (cf. the crate's own compatibility warning).
    const GOLDEN_SEED: [u8; 32] = [0x11u8; 32];
    const GOLDEN_MLDSA_PK_HASH: &str =
        "bb34618ab597cc394fcfa9c9c5791d4767baacce3648285e8069742a55e2de37";
    const GOLDEN_MLDSA_SK_HASH: &str =
        "4ea56265a543928d9c4cf073fe8a6a85b9f7444b2012f2603b26b6a24f1255aa";
    // Deterministic ML-DSA signature over GOLDEN_MSG produced under the seeded
    // RNG (regression-only path; production signing is HEDGED — see below).
    const GOLDEN_MSG: &[u8] = b"BLOCH-HYBRID-GOLDEN-VECTOR-V1";
    const GOLDEN_MLDSA_SIG_HASH: &str =
        "196127fe6b978be23ad4828405f60a7d49839abf4cbba77ead02394e291a59fb";

    #[test]
    fn golden_seed_to_keypair_is_byte_stable() {
        let (pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        // Full ENVELOPED hybrid lengths (4-byte suite header + hybrid body).
        assert_eq!(pk.len(), SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN + FALCON_PUBKEY_LEN, "hybrid pk len");
        assert_eq!(sk.len(), SUITE_HEADER_LEN + MLDSA_SECRET_LEN + falcon1024::secret_key_bytes(), "hybrid sk len");
        // Pinned ML-DSA halves — the hash VALUES are unchanged from the pre-envelope
        // goldens: the ML-DSA body bytes are identical, only shifted by the 4-byte
        // header, so we slice pk[4..4+1952] / sk[4..4+4032] instead of pk[..1952].
        assert_eq!(
            hex::encode(Sha3_256::digest(&pk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN])),
            GOLDEN_MLDSA_PK_HASH,
            "ML-DSA-65 public-key half drifted from the golden vector"
        );
        assert_eq!(
            hex::encode(Sha3_256::digest(&sk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SECRET_LEN])),
            GOLDEN_MLDSA_SK_HASH,
            "ML-DSA-65 secret-key half drifted from the golden vector"
        );
    }

    #[test]
    fn golden_deterministic_mldsa_signature_half_is_byte_stable() {
        // Drive PQClean's randombytes from the same seed so the (normally
        // hedged) ML-DSA signature becomes deterministic for a byte-stable
        // golden vector. This exercises the deterministic-signing path used
        // ONLY for regression pinning — NOT the production signer.
        let (_pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        let sig = pqcrypto_internals::with_seeded_rng_scope(&GOLDEN_SEED, || {
            sign(&sk, GOLDEN_MSG).unwrap()
        });
        // Hash VALUE unchanged; slice shifts by the 4-byte header: sig[4..4+3309].
        assert_eq!(
            hex::encode(Sha3_256::digest(&sig[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SIG_LEN])),
            GOLDEN_MLDSA_SIG_HASH,
            "deterministic ML-DSA-65 signature half drifted from the golden vector"
        );
    }

    #[test]
    fn golden_vector_verifies_and_rejects_tampering() {
        let (pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        let sig = sign(&sk, GOLDEN_MSG).unwrap();
        assert!(verify(&pk, GOLDEN_MSG, &sig), "fresh hybrid signature must verify");

        // Flip the FIRST ML-DSA-body byte (offset shifted past the 4-byte header,
        // sig[0]→sig[4]) → must fail (AND-combiner).
        let mut t1 = sig.clone();
        t1[SUITE_HEADER_LEN] ^= 0x01;
        assert!(!verify(&pk, GOLDEN_MSG, &t1), "tampered ML-DSA half must fail");

        // Flip a byte in the Falcon half (MLDSA_SIG_LEN+1 → 4+MLDSA_SIG_LEN+1) →
        // must fail (AND-combiner).
        let mut t2 = sig.clone();
        let flip = SUITE_HEADER_LEN + MLDSA_SIG_LEN + 1;
        t2[flip] ^= 0x01;
        assert!(!verify(&pk, GOLDEN_MSG, &t2), "tampered Falcon half must fail");

        // Truncated signature → parse failure ⇒ false.
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..sig.len() - 1]), "truncated sig must fail");
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..MLDSA_SIG_LEN]), "falcon-less sig must fail");

        // Oversized signature (trailing garbage) → false. The garbage byte is
        // non-zero: signing is randomized, and a 1,279-byte compact Falcon half
        // plus one 0x00 is the 1,280-byte zero-padded encoding, which this
        // lenient verifier accepts by design (see
        // `canonical_verifier_rejects_the_legacy_zero_padded_variant`).
        let mut over = sig.clone();
        over.push(0x01);
        assert!(!verify(&pk, GOLDEN_MSG, &over), "oversized sig must fail");

        // Tampered public key: ML-DSA body byte (pk[4]) and Falcon body byte
        // (pk[4+1952+1]) → false.
        let mut pk_m = pk.clone();
        pk_m[SUITE_HEADER_LEN] ^= 0x01;
        assert!(!verify(&pk_m, GOLDEN_MSG, &sig), "tampered ML-DSA pubkey must fail");
        let mut pk_f = pk.clone();
        pk_f[SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN + 1] ^= 0x01;
        assert!(!verify(&pk_f, GOLDEN_MSG, &sig), "tampered Falcon pubkey must fail");

        // ── NEW envelope negative cases (design §4.2) ─────────────────────────
        // Bad magic on the signature → parse fail ⇒ false.
        let mut bad_magic = sig.clone();
        bad_magic[0] ^= 0x01;
        assert!(!verify(&pk, GOLDEN_MSG, &bad_magic), "bad-magic sig must fail");
        // Bad magic on the pubkey → false.
        let mut bad_magic_pk = pk.clone();
        bad_magic_pk[1] ^= 0x01;
        assert!(!verify(&bad_magic_pk, GOLDEN_MSG, &sig), "bad-magic pk must fail");
        // Unknown suite (0xFFFF) on BOTH pk and sig so the suites match but the
        // dispatch arm is `_ => false`.
        let mut us_pk = pk.clone();  us_pk[2] = 0xFF;  us_pk[3] = 0xFF;
        let mut us_sig = sig.clone(); us_sig[2] = 0xFF; us_sig[3] = 0xFF;
        assert!(!verify(&us_pk, GOLDEN_MSG, &us_sig), "unknown-suite must fail");
        // Reserved suite 0x0000 on both → false.
        let mut z_pk = pk.clone();  z_pk[2] = 0x00;  z_pk[3] = 0x00;
        let mut z_sig = sig.clone(); z_sig[2] = 0x00; z_sig[3] = 0x00;
        assert!(!verify(&z_pk, GOLDEN_MSG, &z_sig), "reserved suite 0x0000 must fail");
        // Suite mismatch: valid 0x0001 pk vs a sig relabelled 0x0002 → false.
        let mut mism_sig = sig.clone(); mism_sig[2] = 0x02; mism_sig[3] = 0x00;
        assert!(!verify(&pk, GOLDEN_MSG, &mism_sig), "pk/sig suite mismatch must fail");
        // Header-only (len == 4, empty body) on sig and on pk → false.
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..SUITE_HEADER_LEN]), "header-only sig must fail");
        assert!(!verify(&pk[..SUITE_HEADER_LEN], GOLDEN_MSG, &sig), "header-only pk must fail");
        // Shorter-than-header (len < 4) on both → false (parse_envelope None).
        assert!(!verify(&pk[..2], GOLDEN_MSG, &sig), "len-2 pk must fail");
        assert!(!verify(&pk, GOLDEN_MSG, &sig[..3]), "len-3 sig must fail");
    }

    // ─── (B') Hedged-signing regression (roadmap §2.2) ────────────────────────
    // Production signing must stay HEDGED (randomized): two signatures over the
    // same message under the same key must differ. A regression to deterministic
    // signing would be a silent fault-attack exposure.
    #[test]
    fn production_signing_is_hedged_nondeterministic() {
        let (pk, sk) = generate_keypair_from_seed(&GOLDEN_SEED).unwrap();
        let s1 = sign(&sk, GOLDEN_MSG).unwrap();
        assert!(s1.len() <= max_signature_len());
        let s2 = sign(&sk, GOLDEN_MSG).unwrap();
        assert_ne!(s1, s2, "hybrid signing must be hedged (randomized), not deterministic");
        assert!(verify(&pk, GOLDEN_MSG, &s1));
        assert!(verify(&pk, GOLDEN_MSG, &s2));
    }

    // ─── Suite 0x0002 (ML-DSA-65 only) round-trip + suite isolation ───────────
    // Concrete proof that Falcon is removable in principle (design §2.5): build a
    // SUITE_MLDSA65_ONLY keypair from the upstream ML-DSA primitive, sign+verify
    // through the enveloped path, and confirm suite isolation.
    #[test]
    fn suite_mldsa65_only_roundtrips_and_is_suite_isolated() {
        let (mpk, msk) = mldsa65::keypair();
        let pk_env = wrap_envelope(SUITE_MLDSA65_ONLY, mpk.as_bytes());
        let sk_env = wrap_envelope(SUITE_MLDSA65_ONLY, msk.as_bytes());
        assert_eq!(pk_env.len(), SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN, "0x0002 pk len");

        let msg = b"mldsa-only-suite";
        let sig = sign(&sk_env, msg).expect("mldsa-only sign");
        assert!(sig.len() <= max_signature_len());
        assert_eq!(sig.len(), SUITE_HEADER_LEN + MLDSA_SIG_LEN, "0x0002 sig len");
        assert!(verify(&pk_env, msg, &sig), "mldsa-only sig must verify");
        assert!(!verify(&pk_env, b"other", &sig), "wrong message must fail");

        // A 0x0001 (hybrid) pk cannot verify a 0x0002 sig — suite mismatch ⇒ false.
        let (hpk, _hsk) = generate_keypair();
        assert!(!verify(&hpk, msg, &sig), "hybrid pk must reject mldsa-only sig (suite mismatch)");
    }

    // ─── Addresses commit to the suite (design §2.4) ──────────────────────────
    // The address hashes the ENVELOPED pk, so a 0x0001 key and a 0x0002 key over
    // the SAME ML-DSA body hash to different addresses.
    #[test]
    fn addresses_commit_to_suite() {
        let (mpk, _msk) = mldsa65::keypair();
        let (fpk, _fsk) = falcon1024::keypair();
        let mut hybrid_body = mpk.as_bytes().to_vec();
        hybrid_body.extend_from_slice(fpk.as_bytes());
        let pk_0001 = wrap_envelope(SUITE_MLDSA65_FALCON1024, &hybrid_body);
        let pk_0002 = wrap_envelope(SUITE_MLDSA65_ONLY, mpk.as_bytes());
        let a1 = address_from_pubkey(&pk_0001, false);
        let a2 = address_from_pubkey(&pk_0002, false);
        assert_ne!(a1, a2, "different suites over the same ML-DSA key must hash to different addresses");
    }

    // ─── (C) No-panic fuzz: signature parse+verify path ───────────────────────
    // Adversarial/random bytes into `verify` must ALWAYS return a bool (the
    // consensus "parse-failure ⇒ false" rule), never panic. Uses a deterministic
    // SplitMix64 stream so failures are reproducible; cargo-fuzz `pow_verify`
    // provides coverage-guided fuzzing on nightly (see fuzz/).
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| (self.next() & 0xFF) as u8).collect()
        }
    }

    #[test]
    fn fuzz_verify_never_panics() {
        // A real keypair/sig so some structured inputs land near the valid path.
        let (good_pk, sk) = generate_keypair();
        let good_sig = sign(&sk, b"m").unwrap();

        // Structured seed cases (boundary lengths around the split offsets AND
        // the 4-byte envelope header — design §4.3 invariant 2).
        let hdr = |suite: u16, body_len: usize| {
            let mut v = vec![0xB1u8, 0x0C];
            v.extend_from_slice(&suite.to_le_bytes());
            v.extend(std::iter::repeat(0u8).take(body_len));
            v
        };
        let structured: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (vec![], vec![]),
            // Envelope-length boundaries: len 0,1,2,3,4.
            (vec![], vec![0xB1]),
            (vec![0xB1], vec![0xB1, 0x0C]),
            (vec![0xB1, 0x0C], vec![0xB1, 0x0C, 0x01]),
            (vec![0xB1, 0x0C, 0x01], vec![0xB1, 0x0C, 0x01, 0x00]), // len 4 header-only
            // Good header + garbage body, various suites incl. reserved 0x0000/0xFFFF.
            (hdr(SUITE_MLDSA65_FALCON1024, MLDSA_PUBKEY_LEN), hdr(SUITE_MLDSA65_FALCON1024, MLDSA_SIG_LEN)),
            (hdr(SUITE_MLDSA65_ONLY, MLDSA_PUBKEY_LEN), hdr(SUITE_MLDSA65_ONLY, MLDSA_SIG_LEN)),
            (hdr(0x0000, MLDSA_PUBKEY_LEN), hdr(0x0000, MLDSA_SIG_LEN)),
            (hdr(0xFFFF, MLDSA_PUBKEY_LEN), hdr(0xFFFF, MLDSA_SIG_LEN)),
            // Legacy raw (no header) blobs — must now parse-fail ⇒ false, not panic.
            (vec![0u8; MLDSA_PUBKEY_LEN], vec![0u8; MLDSA_SIG_LEN]),
            (vec![0u8; MLDSA_PUBKEY_LEN + 1], vec![0u8; MLDSA_SIG_LEN + 1]),
            (good_pk.clone(), good_sig.clone()),
            (good_pk.clone(), vec![0xFFu8; good_sig.len()]),
            (vec![0u8; good_pk.len()], good_sig.clone()),
        ];
        for (pk, sig) in &structured {
            let r = std::panic::catch_unwind(|| verify(pk, b"m", sig));
            assert!(r.is_ok(), "verify panicked on a structured case");
        }

        // Random fuzz: pk/sig of varied lengths, random messages.
        let mut rng = SplitMix64(0xB10C_C0DE_1234_5678);
        for _ in 0..4000 {
            let pk_len = (rng.next() % 4000) as usize;
            let sig_len = (rng.next() % 4700) as usize;
            let msg_len = (rng.next() % 64) as usize;
            let pk = rng.bytes(pk_len);
            let sig = rng.bytes(sig_len);
            let msg = rng.bytes(msg_len);
            let r = std::panic::catch_unwind(|| verify(&pk, &msg, &sig));
            assert!(r.is_ok(), "verify panicked on random input (pk={pk_len}, sig={sig_len})");
        }

        // Mutate a valid sig one byte at a time — never panics, always false.
        for i in 0..good_sig.len().min(512) {
            let mut s = good_sig.clone();
            s[i] ^= 0xFF;
            let r = std::panic::catch_unwind(|| verify(&good_pk, b"m", &s));
            assert!(r.is_ok(), "verify panicked on single-byte mutation at {i}");
        }
    }

    #[test]
    fn fuzz_sign_never_panics_on_bad_secret_key() {
        // `sign` must return Ok/Err on any secret-key bytes, never panic.
        let mut rng = SplitMix64(0xDEAD_BEEF_F00D_0001);
        for _ in 0..2000 {
            let len = (rng.next() % 6500) as usize;
            let sk = rng.bytes(len);
            let r = std::panic::catch_unwind(|| {
                let _ = sign(&sk, b"fuzz-message");
            });
            assert!(r.is_ok(), "sign panicked on bad secret key (len={len})");
        }
    }

    // ─── CRY-2: component-bound (sighash v3) signatures ──────────────────────

    /// A compact-Falcon fixture whose signature leaves room for padding.
    fn bound_fixture(digest: &[u8; 32]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let (pk, sk) = generate_keypair_from_seed(&[0x5B; 32]).unwrap();
        for seed in 0u8..=255 {
            let sig = pqcrypto_internals::with_seeded_rng_scope(&[seed; 32], || sign_bound(&sk, digest).unwrap());
            if sig.len() < SUITE_HEADER_LEN + MLDSA_SIG_LEN + falcon::padded_signature_len() {
                return (pk, sk, sig);
            }
        }
        unreachable!("no compact Falcon signature shorter than the padded form");
    }

    #[test]
    fn bound_signature_roundtrip_and_canonical_form() {
        let d = [0x42u8; 32];
        let (pk, sk, sig) = bound_fixture(&d);
        assert!(is_canonical_signature_encoding(&sig));
        assert!(verify_bound(&pk, &d, &sig));
        assert!(!verify_bound(&pk, &[0x43; 32], &sig), "other digest");
        // The bound signature is NOT a legacy signature over the digest, and
        // a legacy signature is not a bound one: the bindings never collide.
        assert!(!verify(&pk, &d, &sig));
        let legacy = sign(&sk, &d).unwrap();
        assert!(verify(&pk, &d, &legacy));
        assert!(!verify_bound(&pk, &d, &legacy));
        // The checked signer verifies under the raw legacy key encoding too
        // (genesis carry-over addresses commit to raw keys).
        let raw_pk = &pk[SUITE_HEADER_LEN..];
        let s2 = sign_bound_checked(&sk, raw_pk, &d).unwrap();
        assert!(verify_bound(raw_pk, &d, &s2));
        assert!(verify_bound(&pk, &d, &s2));
        let (other_pk, _) = generate_keypair();
        assert!(sign_bound_checked(&sk, &other_pk, &d).is_err());
    }

    /// CRY-1: every non-canonical encoding of a valid bound signature fails:
    /// envelope stripped, Falcon half zero-padded to 1,280 bytes, a trailing
    /// byte, a truncated Falcon half, an unknown suite.
    #[test]
    fn bound_verifier_requires_the_canonical_encoding() {
        let d = [0x24u8; 32];
        let (pk, _sk, sig) = bound_fixture(&d);
        let stripped = sig[SUITE_HEADER_LEN..].to_vec();
        assert!(!is_canonical_signature_encoding(&stripped));
        assert!(!verify_bound(&pk, &d, &stripped));
        let mut padded = sig.clone();
        padded.resize(SUITE_HEADER_LEN + MLDSA_SIG_LEN + falcon::padded_signature_len(), 0);
        assert_ne!(padded, sig);
        assert!(!is_canonical_signature_encoding(&padded));
        assert!(!verify_bound(&pk, &d, &padded));
        let mut trailing = sig.clone();
        trailing.push(0);
        assert!(!is_canonical_signature_encoding(&trailing));
        assert!(!verify_bound(&pk, &d, &trailing));
        assert!(!verify_bound(&pk, &d, &sig[..sig.len() - 1]));
        let mut unknown = sig.clone();
        unknown[2] = 0x09;
        assert!(!is_canonical_signature_encoding(&unknown));
        assert!(!verify_bound(&pk, &d, &unknown));
        // Format predicate on suite 0x0002: exactly the ML-DSA length.
        let only = wrap_envelope(SUITE_MLDSA65_ONLY, &[0u8; MLDSA_SIG_LEN]);
        assert!(is_canonical_signature_encoding(&only));
        assert!(!is_canonical_signature_encoding(&wrap_envelope(SUITE_MLDSA65_ONLY, &[0u8; MLDSA_SIG_LEN + 1])));
    }

    /// CRY-2, the finding's exact attack: strip the Falcon half of a hybrid
    /// signature and relabel it suite 0x0002, for the 0x0002 key over the
    /// same ML-DSA body. Under the legacy binding it verifies; under the v3
    /// binding it does not, even over the very same digest.
    #[test]
    fn split_hybrid_relabelled_as_mldsa_only_fails_under_the_bound_scheme() {
        let d = [0x77u8; 32];
        let (pk, sk) = generate_keypair_from_seed(&[0x31; 32]).unwrap();
        let mldsa_pk = wrap_envelope(SUITE_MLDSA65_ONLY, &pk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_PUBKEY_LEN]);
        let relabel = |hybrid: &[u8]| wrap_envelope(SUITE_MLDSA65_ONLY, &hybrid[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SIG_LEN]);

        // Legacy (sighash v2) binding: the split works (the finding).
        let legacy = sign(&sk, &d).unwrap();
        assert!(verify(&mldsa_pk, &d, &relabel(&legacy)), "pre-fix weakness reproduced");

        // Bound (sighash v3) binding: the stripped half signed a message that
        // names suite 0x0001, so the 0x0002 verifier rejects it.
        let bound = sign_bound(&sk, &d).unwrap();
        assert!(verify_bound(&pk, &d, &bound));
        let split = relabel(&bound);
        assert!(is_canonical_signature_encoding(&split), "the forgery is well-formed");
        assert!(!verify_bound(&mldsa_pk, &d, &split), "split + relabel must fail under v3");
        // A genuine 0x0002 signature still verifies (the suite stays valid).
        let mldsa_sk = wrap_envelope(SUITE_MLDSA65_ONLY, &sk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SECRET_LEN]);
        let only = sign_bound(&mldsa_sk, &d).unwrap();
        assert!(verify_bound(&mldsa_pk, &d, &only));
        assert!(!verify_bound(&pk, &d, &only), "suite mismatch");
        assert_eq!(public_key_suite(&mldsa_pk), Some(SUITE_MLDSA65_ONLY));
        assert_eq!(public_key_suite(&pk), Some(SUITE_MLDSA65_FALCON1024));
        assert_eq!(public_key_suite(&pk[SUITE_HEADER_LEN..]), Some(SUITE_MLDSA65_FALCON1024));
        assert_eq!(public_key_suite(&[1, 2, 3]), None);
    }

    #[test]
    fn bound_component_messages_are_distinct_per_suite_and_component() {
        let d = [9u8; 32];
        let a = bound_component_message(SUITE_MLDSA65_FALCON1024, COMPONENT_MLDSA65, &d);
        let b = bound_component_message(SUITE_MLDSA65_FALCON1024, COMPONENT_FALCON1024, &d);
        let c = bound_component_message(SUITE_MLDSA65_ONLY, COMPONENT_MLDSA65, &d);
        assert!(a != b && a != c && b != c);
        assert_eq!(&a[..12], b"GNB-TXSIG-v3");
        assert_eq!(&a[12..15], &[0x01, 0x00, 0x01]);
        assert_eq!(&c[12..15], &[0x02, 0x00, 0x01]);
        assert_eq!(&a[15..], &d);
    }

    #[test]
    fn fuzz_verify_bound_never_panics() {
        let mut rng = SplitMix64(0xB0B0_0003_0000_0001);
        let (pk, _) = generate_keypair();
        for _ in 0..2000 {
            let sig_len = (rng.next() % 4900) as usize;
            let mut sig = rng.bytes(sig_len);
            if rng.next().is_multiple_of(2) && sig.len() >= 4 {
                sig[..2].copy_from_slice(&SUITE_MAGIC);
                sig[2] = (rng.next() % 3) as u8;
                sig[3] = 0;
            }
            let pk_choice = rng.next() % 3;
            let random_len = (rng.next() % 4000) as usize;
            let p: Vec<u8> = match pk_choice { 0 => pk.clone(), 1 => pk[SUITE_HEADER_LEN..].to_vec(), _ => rng.bytes(random_len) };
            let r = std::panic::catch_unwind(|| verify_bound(&p, &[0u8; 32], &sig));
            assert!(r.is_ok());
            assert!(!r.unwrap());
        }
    }

    // ─── Honest gap marker: full NIST-KAT wiring ──────────────────────────────
    #[test]
    #[ignore = "needs vendored NIST FIPS-204/Falcon .rsp KAT files + an AES-256-CTR \
                NIST DRBG to reproduce keygen; not sourceable in-tree today (only \
                PQClean nistkat.c ships, which is C-only and DRBG-seeded). The tests \
                above prove wrapper equivalence against the upstream crate oracle."]
    fn full_nist_kat_wiring_todo() {
        // TODO(audit P0.3): vendor the official ML-DSA-65 and Falcon-1024 NIST
        // KAT response files, implement the AES-256-CTR DRBG the KATs seed from,
        // reproduce (pk, sk, sig) for each seed, and assert byte-equality through
        // the pqcrypto primitives. This gives standards-traceable KATs on top of
        // the crate-oracle equivalence already proven here.
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ML-DSA-65: one implementation, so one verdict, on every platform.
//
// With its default features, pqcrypto-mldsa also compiles PQClean's AVX2
// (x86_64 except Windows) and AArch64 ML-DSA-65 and dispatches to them: on
// x86_64 at RUN TIME (`is_x86_feature_detected!("avx2")`), so one node binary
// verifies with AVX2 code on one CPU and with the clean code on another; i686,
// wasm32, Windows and x86_64 CPUs without AVX2 run the clean code. The AVX2
// verifier is not FIPS 204 (tests/wycheproof_mldsa65.rs): it never checks
// ‖z‖∞ < γ1 − β (41 Wycheproof cases accepted), and its UseHint
// (`use_hint_avx`, a blend on the sign bit of r0) treats r0 = 0 as positive,
// so h = 1 moves r1 UP where FIPS 204 Algorithm 40 (r0 ≤ 0) moves it DOWN
// (Wycheproof tcId 161 refused). The second needs no secret key: coins locked
// to a key whose ML-DSA t1 is 0 can be spent with a signature that AVX2 nodes
// refuse and every other node accepts, or the other way round. Every build of
// the workspace therefore links the clean implementation only
// (`default-features = false`, as for Falcon); these tests pin the FIPS 204
// verdicts on whatever CPU runs them and the absence of the other
// implementations from the binary.
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod mldsa_one_verdict {
    use super::*;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;

    // FIPS 204 ML-DSA-65 parameters.
    const K: usize = 6;
    const L: usize = 5;
    const N: usize = 256;
    const OMEGA: usize = 55;
    const CTILDE_LEN: usize = 48;
    const GAMMA1: u64 = 1 << 19;

    /// Hinted coefficients (polynomial, coefficient), in HintBitPack order.
    const HINTS: [(usize, usize); 3] = [(0, 0), (2, 77), (5, 255)];
    /// UseHint(1, r) for r1 = 0, r0 = 0: FIPS 204 Algorithm 40 takes the
    /// r0 ≤ 0 branch, (r1 − 1) mod 16.
    const FIPS_204: u8 = 15;
    /// What PQClean's AVX2 `use_hint_avx` returns there: (r1 + 1) mod 16.
    const AVX2_RULE: u8 = 1;

    fn shake256(parts: &[&[u8]], out: &mut [u8]) {
        let mut h = Shake256::default();
        for p in parts {
            h.update(p);
        }
        h.finalize_xof().read(out);
    }

    /// An ML-DSA-65 public key ρ ‖ t1 with t1 = 0. Nobody holds its secret
    /// key and nobody needs it: for z = 0, w'_approx = A·z − c·t1·2^d is 0
    /// whatever ρ (A) and c are, so every coefficient decomposes into r1 = 0
    /// and r0 = 0, the UseHint input the AVX2 code gets wrong.
    fn t1_zero_public_key(rho: [u8; 32]) -> Vec<u8> {
        let mut pk = rho.to_vec();
        pk.resize(MLDSA_PUBKEY_LEN, 0);
        pk
    }

    /// w1 (K·N coefficients) that is 0 except `value` at `at`.
    fn w1_with(at: &[(usize, usize)], value: u8) -> Vec<u8> {
        let mut w1 = vec![0u8; K * N];
        for &(i, j) in at {
            w1[i * N + j] = value;
        }
        w1
    }

    /// The ML-DSA-65 signature (c̃, z = 0, h) of `msg` (empty context) whose
    /// challenge commits to `w1` and whose hint bits are `hints`. It is valid
    /// under a key from [`t1_zero_public_key`] iff UseHint(h, 0) = w1.
    fn signature(pk: &[u8], msg: &[u8], w1: &[u8], hints: &[(usize, usize)]) -> Vec<u8> {
        // tr = H(pk, 64), μ = H(tr ‖ 0x00 ‖ |ctx| = 0 ‖ M, 64) (FIPS 204
        // Algorithms 3 and 8), c̃ = H(μ ‖ w1Encode(w1), 48) with 4-bit
        // coefficients, low nibble first (γ2 = (q − 1)/32).
        let mut tr = [0u8; 64];
        shake256(&[pk], &mut tr);
        let mut mu = [0u8; 64];
        shake256(&[&tr, &[0, 0], msg], &mut mu);
        let w1_packed: Vec<u8> = w1.chunks(2).map(|p| p[0] | p[1] << 4).collect();
        let mut sig = vec![0u8; CTILDE_LEN];
        shake256(&[&mu, &w1_packed], &mut sig);
        // z = 0: every coefficient packs as γ1 − 0, 20 bits little-endian.
        let pair = (GAMMA1 | GAMMA1 << 20).to_le_bytes();
        for _ in 0..L * N / 2 {
            sig.extend_from_slice(&pair[..5]);
        }
        // HintBitPack: the hinted coefficients, then K running counts.
        let mut h = [0u8; OMEGA + K];
        let mut k = 0;
        for i in 0..K {
            for &(_, j) in hints.iter().filter(|&&(p, _)| p == i) {
                h[k] = u8::try_from(j).unwrap();
                k += 1;
            }
            h[OMEGA + i] = u8::try_from(k).unwrap();
        }
        sig.extend_from_slice(&h);
        assert_eq!(sig.len(), MLDSA_SIG_LEN);
        sig
    }

    /// The verdict of every consensus path on an ML-DSA-65 component: the
    /// library, suite 0x0002 (legacy-tolerant and canonical), suite 0x0001
    /// with a genuine Falcon-1024 half (a standard key shape), and sighash v3
    /// component-bound signatures of both suites. All must agree.
    fn consensus_verdict(
        mpk: &[u8],
        (fpk, fsk): &(Vec<u8>, Vec<u8>),
        msg: &[u8],
        w1: &[u8],
        hints: &[(usize, usize)],
    ) -> bool {
        let msig = signature(mpk, msg, w1, hints);
        let library = mldsa65::verify_detached_signature(
            &mldsa65::DetachedSignature::from_bytes(&msig).unwrap(),
            msg,
            &mldsa65::PublicKey::from_bytes(mpk).unwrap(),
        )
        .is_ok();
        let mut verdicts = vec![library, verify_mldsa65_raw(mpk, msg, &msig)];

        let pk2 = wrap_envelope(SUITE_MLDSA65_ONLY, mpk);
        let sig2 = wrap_envelope(SUITE_MLDSA65_ONLY, &msig);
        verdicts.push(verify(&pk2, msg, &sig2));
        verdicts.push(verify_canonical(&pk2, msg, &sig2));
        verdicts.push(verify_enveloped_canonical(&pk2, msg, &sig2));

        let pk1 = wrap_envelope(SUITE_MLDSA65_FALCON1024, &[mpk, &fpk[..]].concat());
        assert!(is_hybrid_public_key(&pk1), "a standard (relayable) key shape");
        let fsig = falcon::sign(fsk, msg).unwrap();
        let sig1 = wrap_envelope(SUITE_MLDSA65_FALCON1024, &[&msig[..], &fsig[..]].concat());
        verdicts.push(verify(&pk1, msg, &sig1));
        verdicts.push(verify_canonical(&pk1, msg, &sig1));
        verdicts.push(verify_wallet_signature(&pk1, msg, &sig1));

        let digest = [0x3C; 32];
        let m1 = bound_component_message(SUITE_MLDSA65_FALCON1024, COMPONENT_MLDSA65, &digest);
        let f1 = bound_component_message(SUITE_MLDSA65_FALCON1024, COMPONENT_FALCON1024, &digest);
        let bound1 = [signature(mpk, &m1, w1, hints), falcon::sign(fsk, &f1).unwrap()].concat();
        verdicts.push(verify_bound(&pk1, &digest, &wrap_envelope(SUITE_MLDSA65_FALCON1024, &bound1)));
        let m2 = bound_component_message(SUITE_MLDSA65_ONLY, COMPONENT_MLDSA65, &digest);
        let bound2 = signature(mpk, &m2, w1, hints);
        verdicts.push(verify_bound(&pk2, &digest, &wrap_envelope(SUITE_MLDSA65_ONLY, &bound2)));

        assert!(
            verdicts.iter().all(|&v| v == library),
            "consensus paths disagree with each other: {verdicts:?}"
        );
        library
    }

    /// FIPS 204 UseHint at r0 = 0, through every consensus path, on whatever
    /// CPU runs the test. With the AVX2 implementation linked, an AVX2 CPU
    /// fails the FIPS 204 and AVX2-rule cases; CI runs this test on an AVX2
    /// runner, on i686 and on qemu's Nehalem (no AVX2), so a verdict that
    /// depends on the platform fails somewhere.
    #[test]
    fn use_hint_at_r0_zero_follows_fips_204() {
        let msg = b"GnB: one ML-DSA-65 verdict on every platform";
        // The attacker's own Falcon-1024 key for the hybrid suite.
        let falcon_key = pqcrypto_internals::with_seeded_rng_scope(&[0x61; 32], falcon::keypair);
        for rho in [[0u8; 32], [0x5A; 32]] {
            let pk = t1_zero_public_key(rho);
            let verdict = |w1: &[u8], hints: &[(usize, usize)]| consensus_verdict(&pk, &falcon_key, msg, w1, hints);
            // Controls, where both UseHint rules agree: no hint keeps r1 = 0.
            assert!(verdict(&w1_with(&[], 0), &[]), "w1 = 0, no hint");
            assert!(!verdict(&w1_with(&HINTS, FIPS_204), &[]), "w1 = 15 needs hints");
            assert!(!verdict(&w1_with(&[], 0), &HINTS), "a hint moves r1");
            // The case the implementations disagreed on.
            assert!(verdict(&w1_with(&HINTS, FIPS_204), &HINTS), "FIPS 204: (0 - 1) mod 16");
            assert!(!verdict(&w1_with(&HINTS, AVX2_RULE), &HINTS), "AVX2 rule: (0 + 1) mod 16");
            // One hinted coefficient is enough.
            assert!(verdict(&w1_with(&HINTS[1..2], FIPS_204), &HINTS[1..2]));
            assert!(!verdict(&w1_with(&HINTS[1..2], AVX2_RULE), &HINTS[1..2]));
        }
    }

    /// Plain forward byte-substring scan.
    fn binary_contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The clean ML-DSA-65 is the only one in the binary: with pqcrypto-mldsa's
    /// `avx2` or `neon` feature on (Cargo features are additive across the
    /// workspace), the dispatch code references the AVX2 / AArch64 symbols
    /// and the linker keeps them. Needles are assembled at run time so this
    /// test's own strings cannot match.
    #[test]
    fn mldsa_avx2_and_aarch64_variants_are_not_linked() {
        let exe = std::env::current_exe().expect("current_exe");
        let bytes = std::fs::read(&exe).expect("read test executable");
        let sym = |variant: &str| format!("PQCLEAN_{}{}_{}_crypto_sign_verify", "MLDSA", "65", variant);
        let clean = sym("CLEAN");
        assert!(
            binary_contains(&bytes, clean.as_bytes()),
            "control failed: `{clean}` not found in {}: symbol names are not observable \
             (stripped test binary?), so this guard cannot run",
            exe.display()
        );
        for other in [sym("AVX2"), sym("AARCH64")] {
            assert!(
                !binary_contains(&bytes, other.as_bytes()),
                "`{other}` is linked: pqcrypto-mldsa's default features (avx2/neon) are \
                 enabled somewhere in the workspace. Its AVX2 verifier is not FIPS 204 \
                 and splits consensus between CPUs; keep `default-features = false`."
            );
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Actual strict policy verifier calls, including the consensus witness
    /// check. Thread-local so parallel tests cannot contaminate cost evidence.
    pub(crate) static POLICY_VERIFICATION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
