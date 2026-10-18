//! The SV2 authority keypair (secp256k1, BIP 340 x-only public key).
//!
//! The authority key is the server's long-lived identity: miners pin its
//! public key (in the pool URL, `stratum2+tcp://host:3334/<key>`). In every
//! Noise NX handshake noise_sv2 generates a fresh static key and signs a
//! certificate for it with this authority key, so a client that pinned the
//! key knows it talks to this node. Keep the file (`--stratum-v2-key`,
//! default `<data-dir>/stratum-v2-authority.json`, mode 0600) across
//! restarts and upgrades: losing it changes the key every miner pinned.
//!
//! File format (JSON, version 1): `secret_hex`, `public_hex` (x-only, 32
//! bytes), `public_b58` (the SRI key-utils form), `fingerprint_hex`,
//! `created_unix`. On load the public key is re-derived from the secret and
//! must match the stored one.

use std::fs;
use std::path::Path;

use rand::RngCore;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Sv2Error;

/// Version of the key file format.
pub const KEY_FILE_VERSION: u32 = 1;

/// The authority keypair.
pub struct AuthorityKeypair {
    secret: [u8; 32],
    /// x-only public key (BIP 340), the form noise_sv2 and SRI clients use.
    pub public: [u8; 32],
}

impl std::fmt::Debug for AuthorityKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityKeypair").field("public", &hex::encode(self.public)).finish_non_exhaustive()
    }
}

impl Drop for AuthorityKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    version: u32,
    secret_hex: String,
    public_hex: String,
    public_b58: String,
    fingerprint_hex: String,
    created_unix: u64,
}

impl AuthorityKeypair {
    /// The keypair of a 32-byte secret (a valid secp256k1 scalar).
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, Sv2Error> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&secret).map_err(|e| Sv2Error::Keypair(format!("secret key: {e}")))?;
        let public = Keypair::from_secret_key(&secp, &sk).x_only_public_key().0.serialize();
        Ok(Self { secret, public })
    }

    /// A fresh random keypair.
    pub fn generate() -> Self {
        loop {
            let mut s = [0u8; 32];
            rand::rng().fill_bytes(&mut s);
            if let Ok(k) = Self::from_secret(s) {
                return k;
            }
        }
    }

    /// The secret, for the Noise responder only.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Load the key at `path`, or create one there (mode 0600) when the file
    /// does not exist. A file that exists but does not parse is an error,
    /// never replaced.
    pub fn load_or_generate(path: &Path) -> Result<Self, Sv2Error> {
        if path.exists() {
            return Self::load(path);
        }
        let k = Self::generate();
        k.save(path)?;
        Ok(k)
    }

    fn load(path: &Path) -> Result<Self, Sv2Error> {
        let bytes = fs::read(path).map_err(|e| Sv2Error::Keypair(format!("read {path:?}: {e}")))?;
        let stored: StoredKey = serde_json::from_slice(&bytes).map_err(|e| Sv2Error::Keypair(format!("parse {path:?}: {e}")))?;
        if stored.version != KEY_FILE_VERSION {
            return Err(Sv2Error::Keypair(format!("{path:?}: key file version {} (expected {KEY_FILE_VERSION})", stored.version)));
        }
        let secret: [u8; 32] = hex::decode(&stored.secret_hex).ok().and_then(|v| v.try_into().ok())
            .ok_or_else(|| Sv2Error::Keypair(format!("{path:?}: secret_hex is not 32 bytes of hex")))?;
        let k = Self::from_secret(secret)?;
        if hex::encode(k.public) != stored.public_hex.to_ascii_lowercase() {
            return Err(Sv2Error::Keypair(format!("{path:?}: public_hex does not match the secret")));
        }
        Ok(k)
    }

    fn save(&self, path: &Path) -> Result<(), Sv2Error> {
        let stored = StoredKey {
            version: KEY_FILE_VERSION,
            secret_hex: hex::encode(self.secret),
            public_hex: hex::encode(self.public),
            public_b58: self.public_base58(),
            fingerprint_hex: self.fingerprint_hex(),
            created_unix: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        };
        let json = serde_json::to_vec_pretty(&stored).map_err(|e| Sv2Error::Keypair(format!("serialize: {e}")))?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| Sv2Error::Keypair(format!("mkdir {parent:?}: {e}")))?;
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
                .map_err(|e| Sv2Error::Keypair(format!("create {path:?}: {e}")))?;
            f.write_all(&json).map_err(|e| Sv2Error::Keypair(format!("write {path:?}: {e}")))?;
        }
        #[cfg(not(unix))]
        fs::write(path, json).map_err(|e| Sv2Error::Keypair(format!("write {path:?}: {e}")))?;
        Ok(())
    }

    /// First 8 bytes of SHA-256(public key), hex: a short name for logs.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(&Sha256::digest(self.public)[..8])
    }

    /// The public key in SRI's key-utils form: Base58Check of
    /// `u16le(1) ‖ x-only key` (what SRI miners and proxies take as
    /// `authority_public_key`).
    pub fn public_base58(&self) -> String {
        public_key_base58(&self.public)
    }
}

/// SRI key-utils Base58Check form of an x-only public key.
pub fn public_key_base58(public: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(38);
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(public);
    let check = Sha256::digest(Sha256::digest(&data));
    data.extend_from_slice(&check[..4]);
    bs58::encode(data).into_string()
}

/// Parse the key-utils form back (version 1, valid checksum).
pub fn parse_public_key_base58(s: &str) -> Result<[u8; 32], Sv2Error> {
    let raw = bs58::decode(s).into_vec().map_err(|e| Sv2Error::Keypair(format!("base58: {e}")))?;
    if raw.len() != 38 {
        return Err(Sv2Error::Keypair(format!("key is {} bytes, expected 38", raw.len())));
    }
    let (data, check) = raw.split_at(34);
    if Sha256::digest(Sha256::digest(data))[..4] != *check {
        return Err(Sv2Error::Keypair("bad checksum".into()));
    }
    if data[..2] != 1u16.to_le_bytes() {
        return Err(Sv2Error::Keypair("unknown key version".into()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&data[2..]);
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn keypair_round_trip_through_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sv2_key.json");
        let k1 = AuthorityKeypair::load_or_generate(&path).unwrap();
        assert!(path.exists());
        let k2 = AuthorityKeypair::load_or_generate(&path).unwrap();
        assert_eq!(k1.public, k2.public);
        assert_eq!(k1.fingerprint_hex(), k2.fingerprint_hex());
        assert_eq!(k1.fingerprint_hex().len(), 16);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn keypair_rejects_corrupt_or_tampered_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("k.json");
        fs::write(&path, b"not valid json").unwrap();
        assert!(AuthorityKeypair::load_or_generate(&path).is_err(), "a corrupt file is never replaced");
        let k = AuthorityKeypair::generate();
        let path2 = dir.path().join("k2.json");
        k.save(&path2).unwrap();
        let text = fs::read_to_string(&path2).unwrap().replace(&hex::encode(k.public), &"00".repeat(32));
        fs::write(&path2, text).unwrap();
        assert!(AuthorityKeypair::load_or_generate(&path2).is_err(), "public key must match the secret");
    }

    #[test]
    fn x_only_key_matches_a_known_vector() {
        // BIP 340 test vector 1: secret 3 -> x-only key F9308A01...
        let mut s = [0u8; 32];
        s[31] = 3;
        let k = AuthorityKeypair::from_secret(s).unwrap();
        assert_eq!(hex::encode(k.public), "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        assert!(AuthorityKeypair::from_secret([0u8; 32]).is_err(), "zero is not a valid secret");
    }

    #[test]
    fn base58_form_round_trips() {
        let k = AuthorityKeypair::generate();
        let b = k.public_base58();
        assert_eq!(parse_public_key_base58(&b).unwrap(), k.public);
        let mut bad = b.clone();
        let c = bad.pop().unwrap();
        bad.push(if c == '2' { '3' } else { '2' });
        assert!(parse_public_key_base58(&bad).is_err());
    }
}
