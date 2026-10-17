//! Post-quantum node identity and peer-key pinning for the P2P transport.
//!
//! libp2p derives a node's `PeerId` from a classical (Ed25519) key, which a
//! large quantum computer could forge. Every GnB node therefore also holds a
//! hybrid ML-DSA-65 ‖ Falcon-1024 identity (the same scheme the consensus
//! layer uses) and signs every handshake transcript with BOTH keys.
//!
//! The first time a node completes a handshake with a peer it records the
//! peer's PQ key fingerprint under its `PeerId` (trust on first use) and from
//! then on refuses any handshake for that `PeerId` presenting a different PQ
//! key. Forging the Ed25519 signature is then not enough to impersonate a
//! known peer: the attacker would also have to forge the pinned PQ key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use libp2p::PeerId;
use log::{error, info, warn};
use parking_lot::Mutex;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::crypto::SecretBytes;

/// On-disk identity file magic (format version 1).
const IDENTITY_MAGIC: &[u8; 8] = b"GNBPQID1";

/// Domain separator for PQ key fingerprints.
const FINGERPRINT_DOMAIN: &[u8] = b"GNB-P2P-PQ-identity-v1";

/// Fixed self-test message signed and verified when an identity is loaded.
const SELF_TEST_MSG: &[u8] = b"GNB-P2P-PQ-identity self-test";

/// SHA3-256 fingerprint of a PQ identity public key.
pub fn fingerprint(public_key: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(FINGERPRINT_DOMAIN);
    h.update((public_key.len() as u32).to_le_bytes());
    h.update(public_key);
    h.finalize().into()
}

/// The node's hybrid ML-DSA-65 ‖ Falcon-1024 transport identity.
///
/// CRY-4: the secret key is held for the node's whole run, so it lives in a
/// [`SecretBytes`] region: locked in RAM where the platform allows (never
/// swapped, excluded from core dumps) and wiped before release, like
/// Bitcoin Core's keys in `secure_allocator` memory. It is generated in
/// place there and never exists as a plain `Vec`.
pub struct PqIdentity {
    public_key: Vec<u8>,
    secret_key: SecretBytes,
}

gnb_secret::assert_not_copy_or_clone!(PqIdentity);

impl PqIdentity {
    /// Fresh random identity.
    pub fn generate() -> Result<Self, String> {
        let (pk, sk) = crypto::generate_keypair_secret();
        Self::from_parts(pk, sk)
    }

    fn from_parts(public_key: Vec<u8>, secret_key: SecretBytes) -> Result<Self, String> {
        if !crypto::is_hybrid_public_key(&public_key) {
            return Err("PQ identity key is not a hybrid ML-DSA-65 ‖ Falcon-1024 key".into());
        }
        let id = Self { public_key, secret_key };
        // Corrupt or mismatched key material must never reach the network.
        let sig = id.sign(SELF_TEST_MSG)?;
        if !crypto::verify_enveloped_canonical(&id.public_key, SELF_TEST_MSG, &sig) {
            return Err("PQ identity self-test failed: key pair does not verify".into());
        }
        Ok(id)
    }

    /// Load the identity at `path`, or create and store a new one (mode
    /// 0600 on Unix, written atomically through a temporary file).
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        if path.exists() {
            let bytes = Zeroizing::new(std::fs::read(path)
                .map_err(|e| format!("read PQ identity {}: {}", path.display(), e))?);
            let (pk, sk) = decode_identity(&bytes)
                .ok_or_else(|| format!("PQ identity {} is malformed", path.display()))?;
            return Self::from_parts(pk, sk);
        }
        let id = Self::generate()?;
        write_private(path, &encode_identity(&id.public_key, &id.secret_key))?;
        info!("created P2P post-quantum identity: {}", path.display());
        Ok(id)
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.public_key)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        crypto::sign(&self.secret_key, message).map_err(|e| format!("PQ sign: {:?}", e))
    }
}

fn encode_identity(pk: &[u8], sk: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(16 + pk.len() + sk.len()));
    out.extend_from_slice(IDENTITY_MAGIC);
    out.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    out.extend_from_slice(pk);
    out.extend_from_slice(&(sk.len() as u32).to_le_bytes());
    out.extend_from_slice(sk);
    out
}

fn decode_identity(bytes: &[u8]) -> Option<(Vec<u8>, SecretBytes)> {
    let rest = bytes.strip_prefix(IDENTITY_MAGIC.as_slice())?;
    let (pk, rest) = take_field(rest)?;
    let (sk, rest) = take_field(rest)?;
    if !rest.is_empty() {
        return None;
    }
    // CRY-4: straight from the (wiping) file buffer into secret memory.
    Some((pk.to_vec(), SecretBytes::from_slice(sk)))
}

fn take_field(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let body = buf.get(4..4usize.checked_add(len)?)?;
    Some((body, &buf[4 + len..]))
}

/// Write secret material: temp file with owner-only permissions, fsync,
/// then rename over `path`.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| format!("create {}: {}", tmp.display(), e))?;
    f.write_all(bytes).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    f.sync_all().map_err(|e| format!("sync {}: {}", tmp.display(), e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {}", path.display(), e))
}

/// Why a peer's PQ key was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The `PeerId` is pinned to a different PQ key.
    Mismatch { peer: PeerId, pinned: [u8; 32], presented: [u8; 32] },
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::Mismatch { peer, pinned, presented } => write!(
                f,
                "peer {} presented PQ key {} but is pinned to {}",
                peer, hex::encode(&presented[..8]), hex::encode(&pinned[..8])
            ),
        }
    }
}

/// `PeerId` → PQ key fingerprint, trust on first use, optionally persisted.
pub struct PeerPins {
    path: Option<PathBuf>,
    pins: Mutex<HashMap<PeerId, [u8; 32]>>,
}

impl PeerPins {
    /// Pins kept in memory only (tests, ephemeral nodes).
    pub fn in_memory() -> Self {
        Self { path: None, pins: Mutex::new(HashMap::new()) }
    }

    /// Pins loaded from, and saved to, `path` (JSON `{peer_id: hex}`).
    /// A malformed file is an error, never silently replaced: dropping pins
    /// would re-open every known peer to first-use impersonation.
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut pins = HashMap::new();
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("read {}: {}", path.display(), e))?;
            let raw: HashMap<String, String> = serde_json::from_str(&text)
                .map_err(|e| format!("parse {}: {}", path.display(), e))?;
            for (peer, fp) in raw {
                let peer: PeerId = peer.parse()
                    .map_err(|e| format!("{}: bad peer id {}: {}", path.display(), peer, e))?;
                let fp: [u8; 32] = hex::decode(&fp).ok().and_then(|v| v.try_into().ok())
                    .ok_or_else(|| format!("{}: bad fingerprint for {}", path.display(), peer))?;
                pins.insert(peer, fp);
            }
        }
        Ok(Self { path: Some(path.to_path_buf()), pins: Mutex::new(pins) })
    }

    /// Pin `peer` to `presented` on first contact; refuse a different key
    /// afterwards.
    pub fn check_and_pin(&self, peer: &PeerId, presented: [u8; 32]) -> Result<(), PinError> {
        let mut pins = self.pins.lock();
        match pins.get(peer) {
            Some(pinned) if *pinned == presented => Ok(()),
            Some(pinned) => {
                warn!("P2P: refusing {}: PQ key changed (possible impersonation)", peer);
                Err(PinError::Mismatch { peer: *peer, pinned: *pinned, presented })
            }
            None => {
                pins.insert(*peer, presented);
                if let Some(path) = &self.path {
                    let raw: HashMap<String, String> = pins.iter()
                        .map(|(p, f)| (p.to_string(), hex::encode(f)))
                        .collect();
                    match serde_json::to_vec_pretty(&raw) {
                        Ok(json) => {
                            if let Err(e) = write_private(path, &json) {
                                error!("P2P: could not persist PQ pin for {}: {}", peer, e);
                            }
                        }
                        Err(e) => error!("P2P: could not encode PQ pins: {}", e),
                    }
                }
                Ok(())
            }
        }
    }

    pub fn pinned(&self, peer: &PeerId) -> Option<[u8; 32]> {
        self.pins.lock().get(peer).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrips_through_disk_with_private_permissions() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("p2p_pq_identity.bin");
        let a = PqIdentity::load_or_create(&path).unwrap();
        let b = PqIdentity::load_or_create(&path).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert!(crypto::is_hybrid_public_key(a.public_key()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "identity file must be owner-only");
        }
    }

    #[test]
    fn corrupt_identity_file_is_refused() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("id.bin");
        PqIdentity::load_or_create(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let n = bytes.len();
        bytes[n - 10] ^= 0xFF; // flip secret-key bits
        std::fs::write(&path, &bytes).unwrap();
        assert!(PqIdentity::load_or_create(&path).is_err());
        std::fs::write(&path, b"GNBPQID1\x05\x00\x00\x00ab").unwrap();
        assert!(PqIdentity::load_or_create(&path).is_err());
    }

    #[test]
    fn pins_are_trust_on_first_use_and_persist() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("pins.json");
        let peer = PeerId::random();
        let pins = PeerPins::load(&path).unwrap();
        assert_eq!(pins.check_and_pin(&peer, [1; 32]), Ok(()));
        assert_eq!(pins.check_and_pin(&peer, [1; 32]), Ok(()));
        assert!(matches!(pins.check_and_pin(&peer, [2; 32]), Err(PinError::Mismatch { .. })));
        let reloaded = PeerPins::load(&path).unwrap();
        assert_eq!(reloaded.pinned(&peer), Some([1; 32]));
        assert!(reloaded.check_and_pin(&peer, [2; 32]).is_err());
    }

    #[test]
    fn malformed_pin_file_is_an_error_not_an_empty_set() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("pins.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(PeerPins::load(&path).is_err());
    }
}
