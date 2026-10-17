//! Audit CRY-4 tripwire: no production code builds a `pqcrypto` secret key
//! (signing keys, and the ML-KEM-768 keys and shared secrets of the node's
//! P2P handshake), and no secret is left in dead stack frames.
//!
//! The `pqcrypto-mldsa` / `pqcrypto-falcon` `SecretKey` types are `Copy`
//! fixed-size arrays: `keypair()` returns one by value, `from_bytes` builds
//! one for every signature, `detached_sign` takes one, and no copy can be
//! wiped. Production code generates and uses secret keys through
//! `gnb_secret::pq` on `SecretBytes` buffers instead (`crypto::
//! generate_keypair_secret`, `crypto::sign`). This test scans the production
//! sources of every crate that handles GnB secret keys (comments, string
//! literals and `#[cfg(test)]` items removed) and fails if any of those
//! wrapper entry points comes back. Test fixtures may still use them to
//! build legacy keys.

use std::path::{Path, PathBuf};

/// Wrapper entry points that create or consume a `Copy` secret-key value.
const FORBIDDEN: &[&str] = &[
    "SecretKey::from_bytes",
    "mldsa65::keypair(",
    "falcon1024::keypair(",
    "detached_sign(",
    "detached_sign_ctx(",
    "falcon1024::sign(",
    "mldsa65::sign(",
    // ML-KEM-768 (the node's P2P handshake): the wrapper's decapsulation key
    // and shared secrets are `Copy` arrays too (`gnb_secret::pq::mlkem768_*`).
    "mlkem768::keypair(",
    "mlkem768::encapsulate(",
    "mlkem768::decapsulate(",
];

/// Compatibility key-generation entry points that hand the secret key out as
/// a plain `Vec` (the caller must wipe it). Production code outside their
/// own module uses the `SecretBytes` variants (`generate_keypair_secret`,
/// `generate_keypair_from_seed_secret`, `diversified_keypair_secret`,
/// `falcon::keypair_secret`, `wallet::generate_keypair`).
const COMPAT_VEC_SECRETS: &[&str] = &[
    "crypto::generate_keypair()",
    "generate_keypair_zeroizing(",
    "generate_keypair_from_seed(",
    "generate_keypair_from_seed_zeroizing(",
    "diversified_keypair(",
    "falcon::keypair(",
    "falcon::keypair_zeroizing(",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `src` with comments and string/char literal contents blanked out, so
/// braces and patterns inside them are not seen.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if c == b'r' && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
        {
            // raw string r"..." / r#"..."#
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                out.push(c);
                i += 1;
                continue;
            }
            j += 1;
            loop {
                if j >= b.len() {
                    break;
                }
                if b[j] == b'"' && b[j + 1..].iter().take(hashes).filter(|&&h| h == b'#').count() == hashes {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            out.extend_from_slice(b"\"\"");
            i = j;
        } else if c == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            out.extend_from_slice(b"\"\"");
            i = j + 1;
        } else if c == b'\'' {
            // char literal or lifetime
            if b.get(i + 1) == Some(&b'\\') {
                let mut j = i + 2;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                out.extend_from_slice(b"' '");
                i = j + 1;
            } else if b.get(i + 2) == Some(&b'\'') {
                out.extend_from_slice(b"' '");
                i += 3;
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `code` without its `#[cfg(test)]` items (attribute through the end of the
/// item: its `;` or its matching closing brace).
fn without_test_items(code: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let mut out = String::new();
    let mut i = 0;
    while let Some(pos) = code[i..].find(ATTR) {
        let start = i + pos;
        out.push_str(&code[i..start]);
        let b = code.as_bytes();
        let mut j = start + ATTR.len();
        let mut depth = 0usize;
        while j < b.len() {
            match b[j] {
                b';' if depth == 0 => {
                    j += 1;
                    break;
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        j += 1;
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        i = j;
    }
    out.push_str(&code[i..]);
    out
}

fn production_sources() -> Vec<(PathBuf, String)> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().unwrap().parent().unwrap();
    let mut files = Vec::new();
    for dir in ["crates/gnb-crypto/src", "crates/gnb-wallet-wasm/src", "node/src"] {
        rust_files(&root.join(dir), &mut files);
    }
    files.sort();
    files
        .into_iter()
        // Whole files that are test modules (`#[cfg(test)] mod tests;`).
        .filter(|p| !p.file_name().unwrap().to_string_lossy().ends_with("tests.rs"))
        .map(|p| {
            let src = std::fs::read_to_string(&p).unwrap();
            (p, without_test_items(&code_only(&src)))
        })
        .collect()
}

#[test]
fn no_production_code_creates_a_pqcrypto_secret_key() {
    let sources = production_sources();
    assert!(sources.len() > 50, "scanned too few files: {}", sources.len());
    let mut hits = Vec::new();
    for (path, code) in &sources {
        for pattern in FORBIDDEN {
            if code.contains(pattern) {
                hits.push(format!("{}: {}", path.display(), pattern));
            }
        }
        if !path.ends_with("crates/gnb-crypto/src/crypto/mod.rs") {
            for pattern in COMPAT_VEC_SECRETS {
                if code.contains(pattern) {
                    hits.push(format!("{}: {} (plain-Vec secret; use the SecretBytes variant)", path.display(), pattern));
                }
            }
        }
        // Importing the trait is how the wrappers' secret values are used.
        for (module, secret_traits) in [("pqcrypto_traits::sign::", &["SecretKey"][..]),
                                        ("pqcrypto_traits::kem::", &["SecretKey", "SharedSecret"][..])] {
            for t in secret_traits {
                if code.lines().any(|l| l.contains(module) && l.contains(t)) {
                    hits.push(format!("{}: imports {module}{t}", path.display()));
                }
            }
        }
    }
    assert!(hits.is_empty(), "CRY-4: production code uses Copy pqcrypto secret keys:\n{}", hits.join("\n"));
}

/// The scanner itself: test items, comments and strings are ignored, a
/// production call is found.
#[test]
fn the_scanner_sees_production_code_only() {
    let src = r#"
        // mldsa65::keypair() in a comment
        /* falcon1024::keypair() in a block comment */
        const S: &str = "detached_sign(";
        fn f<'a>(x: &'a [u8]) -> char { let _ = x; '{' }
        #[cfg(test)]
        mod tests {
            fn t() { let _ = mldsa65::keypair(); if true { } }
        }
        #[cfg(test)]
        use pqcrypto_traits::sign::SecretKey;
        fn prod() { let k = SecretKey::from_bytes(&[]); }
    "#;
    let code = without_test_items(&code_only(src));
    assert!(!code.contains("mldsa65::keypair("));
    assert!(!code.contains("falcon1024::keypair("));
    assert!(!code.contains("detached_sign("));
    assert!(code.contains("SecretKey::from_bytes"), "{code}");
    assert!(code.contains("fn prod()"));
}

// ── No copy of a secret in dead stack frames (CRY-4) ────────────────────────
//
// Each test runs the operation under test and then copies the dead stack its
// frames left below the test's own frame (`gnb_secret::test_support::
// dead_stack_below_caller`), and looks there for any 16-byte window of the
// secret. Before CRY-4 they found copies: the `Copy` pqcrypto `SecretKey`
// values built per signature and returned by key generation, the BIP39 seed
// returned by value as a `[u8; 64]`, the KES seed taken by value, and the
// expanded keys and hash states of the C signers and the SHA-3 / PBKDF2 code
// (now overwritten by `gnb_secret::scrub_stack`). For KES this was checked
// by running the KES test against the pre-CRY-4 `core/kes.rs` (with the
// CRY-4 crypto layer): its `generate` and `evolve_to` checks fail there (35
// and 170 windows of the seed); its `sign` check passes there too (the
// crypto layer's own scrub covers what KES signing leaves) and guards
// against a regression of either layer.

use gnb_crypto::crypto::{self, SecretBytes};
use gnb_secret::test_support::{dead_stack_below_caller, residue, RESIDUE_WINDOW};

/// The secret parts of an enveloped hybrid secret key: the ML-DSA-65 key
/// seed `K` and `s1 ‖ s2 ‖ t0`, and the Falcon-1024 `f ‖ g ‖ F`. (`rho`, `tr`
/// and the headers are public or derived from the public key, which is on
/// the stack legitimately.)
fn secret_parts(sk: &[u8]) -> Vec<&[u8]> {
    assert_eq!(sk.len(), crypto::HYBRID_SECRET_KEY_LEN);
    let m = crypto::SUITE_HEADER_LEN;
    let f = m + crypto::MLDSA_SECRET_LEN;
    vec![&sk[m + 32..m + 64], &sk[m + 128..f], &sk[f + 1..]]
}

fn assert_no_residue(stack: &[u8], what: &str, parts: &[&[u8]]) {
    // `residue` skips windows of one repeated byte, so a secret made only of
    // such windows (a `[0x77; 32]` fixture) could never be found and the
    // check would pass whatever the stack holds (review finding).
    for (p, part) in parts.iter().enumerate() {
        assert!(part.windows(RESIDUE_WINDOW).any(|w| w.iter().any(|&b| b != w[0])),
            "{what}: secret part {p} has no window `residue` can look for (degenerate fixture)");
    }
    let hits: Vec<_> = parts.iter().enumerate()
        .flat_map(|(p, s)| residue(stack, s).into_iter().map(move |h| (p, h)))
        .collect();
    assert!(hits.is_empty(),
        "{what}: {} windows of the secret are in dead stack frames, first (part, (offset, depth)): {:?}",
        hits.len(), &hits[..hits.len().min(8)]);
}

#[test]
fn signing_leaves_no_secret_key_in_dead_stack() {
    let (pk, sk) = crypto::generate_keypair_from_seed_secret(&[0x4D; 32]).unwrap();
    gnb_secret::scrub_stack(); // only what signing leaves is measured
    let sig = crypto::sign(&sk, b"CRY-4 stack residue").unwrap();
    let stack = dead_stack_below_caller();
    assert!(crypto::verify(&pk, b"CRY-4 stack residue", &sig));
    assert_no_residue(&stack, "crypto::sign", &secret_parts(&sk));

    gnb_secret::scrub_stack();
    let sig = crypto::sign_bound(&sk, &[0x5E; 32]).unwrap();
    let stack = dead_stack_below_caller();
    assert!(!sig.is_empty());
    assert_no_residue(&stack, "crypto::sign_bound", &secret_parts(&sk));

    // A legacy raw secret key (no envelope) is enveloped for signing.
    let kp = gnb_crypto::wallet::Keypair {
        private_key: SecretBytes::from_slice(&sk[crypto::SUITE_HEADER_LEN..]),
        public_key: pk.clone(),
        address: crypto::address_from_pubkey(&pk, true),
    };
    gnb_secret::scrub_stack();
    let sig = kp.sign(b"legacy").unwrap();
    let stack = dead_stack_below_caller();
    assert!(crypto::verify(&pk, b"legacy", &sig));
    assert_no_residue(&stack, "Keypair::sign (raw legacy key)", &secret_parts(&sk));
}

#[test]
fn key_generation_leaves_no_secret_key_in_dead_stack() {
    gnb_secret::scrub_stack();
    let (_, sk) = crypto::generate_keypair_secret();
    let stack = dead_stack_below_caller();
    assert_no_residue(&stack, "crypto::generate_keypair_secret", &secret_parts(&sk));

    let seed = SecretBytes::from_slice(&[0x2A; 32]);
    gnb_secret::scrub_stack();
    let (_, sk) = crypto::generate_keypair_from_seed_secret(&seed).unwrap();
    let stack = dead_stack_below_caller();
    assert_no_residue(&stack, "crypto::generate_keypair_from_seed_secret", &secret_parts(&sk));

    let master: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(29).wrapping_add(3)).collect();
    gnb_secret::scrub_stack();
    let (_, sk) = crypto::diversified_keypair_secret(&master, 7).unwrap();
    let stack = dead_stack_below_caller();
    let mut parts = secret_parts(&sk);
    parts.push(&master);
    assert_no_residue(&stack, "crypto::diversified_keypair_secret", &parts);

    gnb_secret::scrub_stack();
    let kp = gnb_crypto::wallet::generate_keypair(true);
    let stack = dead_stack_below_caller();
    assert_no_residue(&stack, "wallet::generate_keypair", &secret_parts(&kp.private_key));
}

#[test]
fn seed_derivation_leaves_no_seed_in_dead_stack() {
    use gnb_crypto::wallet::seed::{SeedPhrase, SeedVersion};
    let phrase = SeedPhrase::parse(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ).unwrap();
    gnb_secret::scrub_stack();
    let seed = phrase.to_seed_bytes();
    let stack = dead_stack_below_caller();
    assert_eq!(seed.len(), 64);
    assert_no_residue(&stack, "SeedPhrase::to_seed_bytes", &[&seed[..]]);

    gnb_secret::scrub_stack();
    let seed = phrase.to_seed_bytes_versioned(SeedVersion::V2Bip39Sha512, "TREZOR").unwrap();
    let stack = dead_stack_below_caller();
    assert_no_residue(&stack, "SeedPhrase::to_seed_bytes_versioned", &[&seed[..]]);

    gnb_secret::scrub_stack();
    let wallet = gnb_crypto::wallet::Wallet::from_seed_versioned(
        &phrase, "TREZOR", SeedVersion::V2Bip39Sha512, gnb_crypto::address::Network::Testnet).unwrap();
    let stack = dead_stack_below_caller();
    assert_no_residue(&stack, "Wallet::from_seed_versioned (seed)", &[&seed[..]]);
    let kp = wallet.into_keypair();
    assert_no_residue(&stack, "Wallet::from_seed_versioned (key)", &secret_parts(&kp.private_key));
}

#[test]
fn kes_signing_and_evolution_leave_no_seed_in_dead_stack() {
    use gnb_crypto::core::kes::KesSigner;
    // A root seed with no repeated-byte window (a `[0x77; 32]` root left the
    // generate, sign and seed_0 evolve checks unable to fail).
    let bytes: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
    let root = SecretBytes::from_slice(&bytes);
    let root_arr: &[u8; 32] = root.as_slice().try_into().unwrap();
    gnb_secret::scrub_stack();
    let mut signer = KesSigner::generate(2, root_arr, |_| {}).unwrap();
    let stack = dead_stack_below_caller();
    let seed0 = signer.secret_bytes()[9..41].to_vec();
    assert_eq!(seed0, root.as_slice());
    assert_no_residue(&stack, "KesSigner::generate", &[&seed0]);

    gnb_secret::scrub_stack();
    let sig = signer.sign(b"epoch 0").unwrap();
    let stack = dead_stack_below_caller();
    assert!(!sig.sig.is_empty());
    // The epoch-0 leaf secret key signing derived (`leaf_seed = SHA3-256(
    // "GNB-KES-v1/leaf" ‖ seed_0)`, docs/DESIGN-powit-kes.md) must not be
    // left behind either.
    let leaf_seed: [u8; 32] = {
        use sha3::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(b"GNB-KES-v1/leaf");
        h.update(&seed0);
        h.finalize().into()
    };
    let (leaf_pk, leaf_sk) = crypto::generate_keypair_from_seed_secret(&leaf_seed).unwrap();
    assert_eq!(sig.leaf_pk, leaf_pk, "the derived leaf key is the one that signed");
    let mut parts = secret_parts(&leaf_sk);
    parts.push(&seed0);
    parts.push(&leaf_seed);
    assert_no_residue(&stack, "KesSigner::sign", &parts);

    gnb_secret::scrub_stack();
    signer.evolve_to(1).unwrap();
    let stack = dead_stack_below_caller();
    let seed1 = signer.secret_bytes()[9..41].to_vec();
    assert_ne!(seed0, seed1);
    // Forward security: the erased seed is nowhere, nor is the new one.
    assert_no_residue(&stack, "KesSigner::evolve_to", &[&seed0, &seed1]);
}

// ── Conservative suite 0x0003 (P5-S): SLH-DSA secrets ───────────────────────
//
// `fips205`'s secret-key value (`PrivateKey`) is not `Copy` and is zeroized on
// drop, but every way of building one (`PrivateKey::try_from_bytes`,
// `KG::keygen_with_seeds`, `try_keygen*`) and of extracting its bytes by value
// (`into_bytes`) copies the secret around; it is confined to the one wrapper
// module that scrubs the stack after it, `crypto/slhdsa.rs`.

/// `fips205` entry points that create or expose a secret-key value.
const SLHDSA_SECRET_APIS: &[&str] = &[
    "PrivateKey::try_from_bytes",
    "keygen_with_seeds",
    "try_keygen",
    "_test_only_raw_sign",
    "slh_dsa_shake_128s::KG",
];

#[test]
fn fips205_secret_keys_are_built_only_by_the_slhdsa_wrapper() {
    let sources = production_sources();
    let mut wrapper_uses = 0;
    let mut hits = Vec::new();
    for (path, code) in &sources {
        let in_wrapper = path.ends_with("crates/gnb-crypto/src/crypto/slhdsa.rs");
        for pattern in SLHDSA_SECRET_APIS {
            if code.contains(pattern) {
                if in_wrapper {
                    wrapper_uses += 1;
                } else {
                    hits.push(format!("{}: {}", path.display(), pattern));
                }
            }
        }
        if !in_wrapper && code.contains("fips205") {
            hits.push(format!("{}: names the fips205 crate (only crypto/slhdsa.rs may)", path.display()));
        }
    }
    assert!(wrapper_uses >= 2, "control: the wrapper's own uses were not found ({wrapper_uses})");
    assert!(hits.is_empty(), "CRY-4: SLH-DSA secret keys handled outside crypto/slhdsa.rs:\n{}", hits.join("\n"));
}

/// The secret parts of an enveloped conservative secret key: SLH-DSA's
/// `SK.seed ‖ SK.prf` and Falcon-1024's `f ‖ g ‖ F` (`PK.seed`, `PK.root`
/// and the headers are public).
fn conservative_secret_parts(sk: &[u8]) -> Vec<&[u8]> {
    assert_eq!(sk.len(), crypto::CONSERVATIVE_SECRET_KEY_LEN);
    let h = crypto::SUITE_HEADER_LEN;
    let f = h + crypto::slhdsa::SECRET_KEY_LEN;
    vec![&sk[h..h + 2 * crypto::slhdsa::N], &sk[f + 1..]]
}

#[test]
fn conservative_signing_and_key_generation_leave_no_secret_in_dead_stack() {
    gnb_secret::scrub_stack();
    let (pk, sk) = crypto::generate_conservative_keypair_secret().unwrap();
    let stack = dead_stack_below_caller();
    assert_no_residue(&stack, "crypto::generate_conservative_keypair_secret", &conservative_secret_parts(&sk));

    let seed: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(53).wrapping_add(7)).collect();
    gnb_secret::scrub_stack();
    let (spk, ssk) = crypto::generate_conservative_keypair_from_seed_secret(&seed).unwrap();
    let stack = dead_stack_below_caller();
    let mut parts = conservative_secret_parts(&ssk);
    parts.push(&seed);
    assert_no_residue(&stack, "crypto::generate_conservative_keypair_from_seed_secret", &parts);

    gnb_secret::scrub_stack();
    let sig = crypto::sign_bound(&sk, &[0x3C; 32]).unwrap();
    let stack = dead_stack_below_caller();
    assert!(crypto::verify_bound_under(&pk, &[0x3C; 32], &sig, crypto::SuiteRules::HARDENING2));
    assert_no_residue(&stack, "crypto::sign_bound (conservative)", &conservative_secret_parts(&sk));
    let _ = spk;
}
