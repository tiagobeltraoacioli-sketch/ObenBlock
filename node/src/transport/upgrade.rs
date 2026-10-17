//! Post-quantum libp2p security upgrade, protocol `/gnb/pq/2.0.0`.
//!
//! # Construction
//!
//! - **Key exchange: hybrid ML-KEM-768 (FIPS 203) + X25519.** Both shared
//!   secrets feed the key schedule, so a session stays confidential unless
//!   BOTH are broken — the same combination TLS 1.3 deploys as
//!   `X25519MLKEM768`. Ephemeral keys on both sides: forward secrecy.
//! - **Authentication: hybrid Ed25519 + ML-DSA-65 ‖ Falcon-1024.** Each side
//!   signs the transcript with its libp2p identity key (Ed25519; libp2p
//!   derives the `PeerId` from it) AND with its PQ identity key (the same
//!   hybrid scheme as consensus, verified in the strict enveloped, canonical
//!   form). The PQ key is pinned per `PeerId` on first contact
//!   ([`PeerPins`]), so a forged Ed25519 signature alone cannot impersonate a
//!   known peer.
//! - **Mutual transcript authentication (SIGMA-style).** The responder signs
//!   the transcript of both opening messages; the initiator then signs the
//!   complete transcript in a third message. Neither side accepts the
//!   connection before verifying the other's signatures over everything both
//!   sent.
//! - **Session cipher:** ChaCha20-Poly1305 with monotonic counters
//!   ([`KyberStream`], unchanged), keys from HKDF-SHA256 over
//!   `ss_mlkem ‖ ss_x25519` salted with the transcript hash.
//!
//! ```text
//!   INITIATOR                                          RESPONDER
//!   Init { v, mlkem_pk, x25519_i, ed_pk_i, pq_pk_i, nonce_i } ──>
//!                                       (ss_m, ct) = ML-KEM.Encaps(mlkem_pk)
//!                                       ss_x = X25519(x_r, x25519_i)
//!                                       th_r = H(th_i, ct, x25519_r, ed_pk_r, pq_pk_r, nonce_r)
//!   <── Resp { ct, x25519_r, ed_pk_r, pq_pk_r, nonce_r,
//!              Ed25519(th_r), PQ(th_r) }
//!   verify both sigs, pin pq_pk_r
//!   ss_m = Decaps(ct); ss_x = X25519(x_i, x25519_r)
//!   th_f = H(th_r)
//!   Finish { Ed25519(th_f), PQ(th_f) } ──>
//!                                       verify both sigs, pin pq_pk_i
//!   keys = HKDF(salt = th_r, ss_m ‖ ss_x)         keys = HKDF(…)
//! ```
//!
//! Not claimed: identity hiding (identities travel in clear), traffic-analysis
//! resistance, post-compromise security within a session, a formal proof, or
//! a third-party audit.

use std::future::Future;
use std::iter;
use std::pin::Pin;
use std::sync::Arc;

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use hkdf::Hkdf;
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use libp2p::identity;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::crypto::SecretBytes;
use crate::transport::identity::{fingerprint, PeerPins, PinError, PqIdentity};
use crate::transport::{stream::KyberStream, RxStream, TxStream, STREAM_KEY_SIZE};

// ── Protocol constants ──────────────────────────────────────────────────────

/// multistream-select protocol id.
pub const PQ_PROTOCOL_ID: &str = "/gnb/pq/2.0.0";

/// Handshake version carried in `Init`.
pub const PQ_HANDSHAKE_VERSION: u8 = 2;

const DOMAIN: &[u8] = b"GNB-P2P-PQ-v2";
const LABEL_I2R: &[u8] = b"GNB-P2P-PQ-v2 i->r";
const LABEL_R2I: &[u8] = b"GNB-P2P-PQ-v2 r->i";

/// ML-KEM-768 (FIPS 203) sizes.
pub const MLKEM768_PK_SIZE: usize = 1184;
pub const MLKEM768_CT_SIZE: usize = 1088;
const _: () = assert!(MLKEM768_PK_SIZE == gnb_secret::pq::MLKEM768_PUBLIC_KEY_BYTES
    && MLKEM768_CT_SIZE == gnb_secret::pq::MLKEM768_CIPHERTEXT_BYTES);
const NONCE_SIZE: usize = 32;

/// Defensive bound on one handshake message. The largest (`Resp`) carries an
/// ML-KEM ciphertext, a PQ public key and a PQ signature: about 9.7 KB.
/// Public so the `handshake_decode` fuzz target applies the same bound.
pub const MAX_HANDSHAKE_MSG_SIZE: u32 = 32 * 1024;

// ── Wire messages ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct Init {
    pub version: u8,
    pub mlkem_pk: Vec<u8>,
    pub x25519_pk: [u8; 32],
    /// libp2p `PublicKey::encode_protobuf()`.
    pub ed_pk: Vec<u8>,
    /// Hybrid ML-DSA-65 ‖ Falcon-1024 public key (enveloped).
    pub pq_pk: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
}

#[derive(Serialize, Deserialize)]
pub struct Resp {
    pub mlkem_ct: Vec<u8>,
    pub x25519_pk: [u8; 32],
    pub ed_pk: Vec<u8>,
    pub pq_pk: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
    pub ed_sig: Vec<u8>,
    pub pq_sig: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Finish {
    pub ed_sig: Vec<u8>,
    pub pq_sig: Vec<u8>,
}

// ── Config ──────────────────────────────────────────────────────────────────

/// Security upgrade: the node's two identities and its peer pins.
#[derive(Clone)]
pub struct PqConfig {
    keypair: identity::Keypair,
    pq: Arc<PqIdentity>,
    pins: Arc<PeerPins>,
}

impl PqConfig {
    pub fn new(keypair: &identity::Keypair, pq: Arc<PqIdentity>, pins: Arc<PeerPins>) -> Self {
        Self { keypair: keypair.clone(), pq, pins }
    }
}

impl UpgradeInfo for PqConfig {
    type Info = &'static str;
    type InfoIter = iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(PQ_PROTOCOL_ID)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PqUpgradeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("message too large ({got} bytes, max {max})")]
    MessageTooLarge { got: u32, max: u32 },
    #[error("serialization: {0}")]
    Serialize(String),
    #[error("deserialization: {0}")]
    Deserialize(String),
    #[error("unsupported handshake version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid ML-KEM public key")]
    BadKemPk,
    #[error("invalid ML-KEM ciphertext")]
    BadKemCt,
    #[error("X25519 exchange is not contributory (low-order point)")]
    WeakX25519,
    #[error("invalid libp2p identity public key: {0}")]
    BadIdentityPk(String),
    #[error("PQ identity key is not a hybrid ML-DSA-65 ‖ Falcon-1024 key")]
    BadPqPk,
    #[error("bad responder signature")]
    BadResponderSignature,
    #[error("bad initiator signature")]
    BadInitiatorSignature,
    #[error("peer connected to itself")]
    SelfConnection,
    #[error("{0}")]
    Pin(PinError),
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

// ── Transcript and keys ─────────────────────────────────────────────────────

/// Length-prefixed transcript hashing (no field can shift into another).
struct Transcript(Sha3_256);

impl Transcript {
    fn new(label: &[u8]) -> Self {
        let mut t = Transcript(Sha3_256::new());
        t.put(DOMAIN);
        t.put(label);
        t
    }
    fn put(&mut self, field: &[u8]) {
        self.0.update((field.len() as u64).to_le_bytes());
        self.0.update(field);
    }
    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn th_init(m: &Init) -> [u8; 32] {
    let mut t = Transcript::new(b"init");
    t.put(&[m.version]);
    t.put(&m.mlkem_pk);
    t.put(&m.x25519_pk);
    t.put(&m.ed_pk);
    t.put(&m.pq_pk);
    t.put(&m.nonce);
    t.finish()
}

fn th_resp(th_i: &[u8; 32], m: &Resp) -> [u8; 32] {
    let mut t = Transcript::new(b"resp");
    t.put(th_i);
    t.put(&m.mlkem_ct);
    t.put(&m.x25519_pk);
    t.put(&m.ed_pk);
    t.put(&m.pq_pk);
    t.put(&m.nonce);
    t.finish()
}

fn th_finish(th_r: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new(b"finish");
    t.put(th_r);
    t.finish()
}

/// Session keys from both shared secrets, salted with the transcript.
/// CRY-4: retain non-Copy cleaning owners from HKDF expansion through stream
/// drop. This follows the cleanup-before-free principle in Bitcoin Core v29.0
/// `secure_allocator::deallocate`:
/// https://github.com/bitcoin/bitcoin/blob/v29.0/src/support/allocators/secure.h#L34-L39
/// `Zeroizing` does not lock pages or erase every compiler-created copy.
fn derive_keys(ss_mlkem: &[u8], ss_x25519: &[u8; 32], th_r: &[u8; 32])
    -> (Zeroizing<[u8; STREAM_KEY_SIZE]>, Zeroizing<[u8; STREAM_KEY_SIZE]>)
{
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss_mlkem.len() + 32));
    ikm.extend_from_slice(ss_mlkem);
    ikm.extend_from_slice(ss_x25519);
    let hk = Hkdf::<Sha256>::new(Some(th_r), &ikm);
    let mut k_i2r = Zeroizing::new([0u8; STREAM_KEY_SIZE]);
    let mut k_r2i = Zeroizing::new([0u8; STREAM_KEY_SIZE]);
    hk.expand(LABEL_I2R, k_i2r.as_mut()).expect("HKDF output length is valid");
    hk.expand(LABEL_R2I, k_r2i.as_mut()).expect("HKDF output length is valid");
    (k_i2r, k_r2i)
}

// ── ML-KEM-768 on secret memory (CRY-4) ─────────────────────────────────────
//
// The `pqcrypto_mlkem` wrapper hands out the ephemeral decapsulation key and
// both shared secrets as `Copy` arrays that live in the handshake future (on
// the heap) until it is freed, never wiped: the transport's forward secrecy
// rests on erasing them. Here they are generated and used in `SecretBytes`
// regions through PQClean's C functions (`gnb_secret::pq`), and the stack the
// C code used is scrubbed after each call.

/// Ephemeral ML-KEM-768 key pair; the decapsulation key in secret memory.
fn kem_keypair() -> (Vec<u8>, SecretBytes) {
    let mut pk = vec![0u8; MLKEM768_PK_SIZE];
    let mut sk = SecretBytes::zeroed(gnb_secret::pq::MLKEM768_SECRET_KEY_BYTES);
    // PQClean's key generator cannot fail on these lengths (the wrapper
    // asserted the same).
    gnb_secret::pq::mlkem768_keypair(&mut pk, &mut sk).expect("ML-KEM-768 key generation");
    gnb_secret::scrub_stack();
    (pk, sk)
}

/// Encapsulate to the initiator's key: `(shared secret, ciphertext)`, or
/// `None` for a key of the wrong size (`PqUpgradeError::BadKemPk`).
fn kem_encapsulate(pk: &[u8]) -> Option<(SecretBytes, Vec<u8>)> {
    let mut ct = vec![0u8; MLKEM768_CT_SIZE];
    let mut ss = SecretBytes::zeroed(gnb_secret::pq::MLKEM768_SHARED_SECRET_BYTES);
    let r = gnb_secret::pq::mlkem768_encapsulate(pk, &mut ct, &mut ss);
    gnb_secret::scrub_stack();
    r.ok().map(|()| (ss, ct))
}

/// Decapsulate the responder's ciphertext with the ephemeral key, or `None`
/// for a ciphertext of the wrong size (`PqUpgradeError::BadKemCt`).
fn kem_decapsulate(sk: &[u8], ct: &[u8]) -> Option<SecretBytes> {
    let mut ss = SecretBytes::zeroed(gnb_secret::pq::MLKEM768_SHARED_SECRET_BYTES);
    let r = gnb_secret::pq::mlkem768_decapsulate(sk, ct, &mut ss);
    gnb_secret::scrub_stack();
    r.ok().map(|()| ss)
}

fn x25519_ephemeral() -> (x25519_dalek::StaticSecret, [u8; 32]) {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(seed.as_mut());
    let sk = x25519_dalek::StaticSecret::from(*seed);
    let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
    (sk, pk)
}

fn x25519_shared(sk: &x25519_dalek::StaticSecret, peer: &[u8; 32]) -> Result<[u8; 32], PqUpgradeError> {
    let ss = sk.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
    if !ss.was_contributory() {
        return Err(PqUpgradeError::WeakX25519);
    }
    Ok(ss.to_bytes())
}

/// Decode and check a peer's two identity keys.
fn peer_identity(ed_pk: &[u8], pq_pk: &[u8]) -> Result<identity::PublicKey, PqUpgradeError> {
    let ed = identity::PublicKey::try_decode_protobuf(ed_pk)
        .map_err(|e| PqUpgradeError::BadIdentityPk(e.to_string()))?;
    if !crypto::is_hybrid_public_key(pq_pk) {
        return Err(PqUpgradeError::BadPqPk);
    }
    Ok(ed)
}

fn verify_both(ed: &identity::PublicKey, pq_pk: &[u8], msg: &[u8; 32], ed_sig: &[u8], pq_sig: &[u8]) -> bool {
    // Both are always evaluated; the result is the AND.
    let ed_ok = ed.verify(msg, ed_sig);
    let pq_ok = crypto::verify_enveloped_canonical(pq_pk, msg, pq_sig);
    ed_ok & pq_ok
}

fn sign_both(cfg: &PqConfig, msg: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PqUpgradeError> {
    let ed = cfg.keypair.sign(msg).map_err(|e| PqUpgradeError::SigningFailed(e.to_string()))?;
    let pq = cfg.pq.sign(msg).map_err(PqUpgradeError::SigningFailed)?;
    Ok((ed, pq))
}

// ── Wire I/O ────────────────────────────────────────────────────────────────

async fn write_msg<S: AsyncWrite + Unpin, T: Serialize>(s: &mut S, msg: &T) -> Result<(), PqUpgradeError> {
    let bytes = bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .map_err(|e| PqUpgradeError::Serialize(e.to_string()))?;
    if bytes.len() > MAX_HANDSHAKE_MSG_SIZE as usize {
        return Err(PqUpgradeError::MessageTooLarge { got: bytes.len() as u32, max: MAX_HANDSHAKE_MSG_SIZE });
    }
    s.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    s.write_all(&bytes).await?;
    s.flush().await?;
    Ok(())
}

async fn read_msg<S: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(s: &mut S) -> Result<T, PqUpgradeError> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    if len > MAX_HANDSHAKE_MSG_SIZE {
        return Err(PqUpgradeError::MessageTooLarge { got: len, max: MAX_HANDSHAKE_MSG_SIZE });
    }
    let mut body = vec![0u8; len as usize];
    s.read_exact(&mut body).await?;
    let (msg, used) = bincode::serde::decode_from_slice(&body, bincode::config::standard())
        .map_err(|e| PqUpgradeError::Deserialize(e.to_string()))?;
    if used != body.len() {
        return Err(PqUpgradeError::Deserialize("trailing bytes".into()));
    }
    Ok(msg)
}

// ── Initiator (dialer) ──────────────────────────────────────────────────────

impl<T> OutboundConnectionUpgrade<T> for PqConfig
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = (PeerId, KyberStream<T>);
    type Error = PqUpgradeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, mut socket: T, _info: Self::Info) -> Self::Future {
        Box::pin(async move {
            let (kem_pk, kem_sk) = kem_keypair();
            let (x_sk, x_pk) = x25519_ephemeral();
            let mut nonce = [0u8; NONCE_SIZE];
            rand::rng().fill_bytes(&mut nonce);
            let init = Init {
                version: PQ_HANDSHAKE_VERSION,
                mlkem_pk: kem_pk,
                x25519_pk: x_pk,
                ed_pk: self.keypair.public().encode_protobuf(),
                pq_pk: self.pq.public_key().to_vec(),
                nonce,
            };
            let th_i = th_init(&init);
            write_msg(&mut socket, &init).await?;

            let resp: Resp = read_msg(&mut socket).await?;
            if resp.mlkem_ct.len() != MLKEM768_CT_SIZE {
                return Err(PqUpgradeError::BadKemCt);
            }
            let peer_ed = peer_identity(&resp.ed_pk, &resp.pq_pk)?;
            let peer_id = peer_ed.to_peer_id();
            if peer_id == self.keypair.public().to_peer_id() {
                return Err(PqUpgradeError::SelfConnection);
            }
            let th_r = th_resp(&th_i, &resp);
            if !verify_both(&peer_ed, &resp.pq_pk, &th_r, &resp.ed_sig, &resp.pq_sig) {
                return Err(PqUpgradeError::BadResponderSignature);
            }
            self.pins.check_and_pin(&peer_id, fingerprint(&resp.pq_pk)).map_err(PqUpgradeError::Pin)?;

            let ss_m = kem_decapsulate(&kem_sk, &resp.mlkem_ct).ok_or(PqUpgradeError::BadKemCt)?;
            drop(kem_sk); // CRY-4: the ephemeral key is wiped as soon as it is used
            let ss_x = Zeroizing::new(x25519_shared(&x_sk, &resp.x25519_pk)?);

            let (ed_sig, pq_sig) = sign_both(&self, &th_finish(&th_r))?;
            write_msg(&mut socket, &Finish { ed_sig, pq_sig }).await?;

            let (k_i2r, k_r2i) = derive_keys(&ss_m, &ss_x, &th_r);
            Ok((peer_id, KyberStream::new(socket, TxStream::from_owned_key(k_i2r), RxStream::from_owned_key(k_r2i))))
        })
    }
}

// ── Responder (listener) ────────────────────────────────────────────────────

impl<T> InboundConnectionUpgrade<T> for PqConfig
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = (PeerId, KyberStream<T>);
    type Error = PqUpgradeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, mut socket: T, _info: Self::Info) -> Self::Future {
        Box::pin(async move {
            let init: Init = read_msg(&mut socket).await?;
            if init.version != PQ_HANDSHAKE_VERSION {
                return Err(PqUpgradeError::UnsupportedVersion(init.version));
            }
            if init.mlkem_pk.len() != MLKEM768_PK_SIZE {
                return Err(PqUpgradeError::BadKemPk);
            }
            let peer_ed = peer_identity(&init.ed_pk, &init.pq_pk)?;
            let peer_id = peer_ed.to_peer_id();
            if peer_id == self.keypair.public().to_peer_id() {
                return Err(PqUpgradeError::SelfConnection);
            }
            let th_i = th_init(&init);

            let (ss_m, ct) = kem_encapsulate(&init.mlkem_pk).ok_or(PqUpgradeError::BadKemPk)?;
            let (x_sk, x_pk) = x25519_ephemeral();
            let ss_x = Zeroizing::new(x25519_shared(&x_sk, &init.x25519_pk)?);
            let mut nonce = [0u8; NONCE_SIZE];
            rand::rng().fill_bytes(&mut nonce);

            let mut resp = Resp {
                mlkem_ct: ct,
                x25519_pk: x_pk,
                ed_pk: self.keypair.public().encode_protobuf(),
                pq_pk: self.pq.public_key().to_vec(),
                nonce,
                ed_sig: Vec::new(),
                pq_sig: Vec::new(),
            };
            let th_r = th_resp(&th_i, &resp);
            let (ed_sig, pq_sig) = sign_both(&self, &th_r)?;
            resp.ed_sig = ed_sig;
            resp.pq_sig = pq_sig;
            write_msg(&mut socket, &resp).await?;

            // The initiator is accepted only after it signs the FULL transcript.
            let fin: Finish = read_msg(&mut socket).await?;
            if !verify_both(&peer_ed, &init.pq_pk, &th_finish(&th_r), &fin.ed_sig, &fin.pq_sig) {
                return Err(PqUpgradeError::BadInitiatorSignature);
            }
            self.pins.check_and_pin(&peer_id, fingerprint(&init.pq_pk)).map_err(PqUpgradeError::Pin)?;

            let (k_i2r, k_r2i) = derive_keys(&ss_m, &ss_x, &th_r);
            Ok((peer_id, KyberStream::new(socket, TxStream::from_owned_key(k_r2i), RxStream::from_owned_key(k_i2r))))
        })
    }
}

#[cfg(test)]
mod key_ownership_tests {
    use super::*;
    use zeroize::Zeroize;

    /// CRY-4: the ephemeral ML-KEM-768 decapsulation key and both shared
    /// secrets are `SecretBytes` (the wrapper's were `Copy` arrays kept,
    /// unwiped, in the handshake future), the two sides agree, and no copy
    /// of a secret is left in the dead stack frames of the C code (read back
    /// with the test-only probe right after each call).
    #[test]
    fn kem_secrets_live_in_secret_memory_and_leave_no_stack_residue() {
        use gnb_secret::test_support::{dead_stack_below_caller, residue};
        // Secret parts of a decapsulation key: dk_pke (1,152 bytes) and the
        // implicit-rejection seed z (last 32); ek and H(ek) are public.
        fn secret_parts(sk: &[u8]) -> [&[u8]; 2] {
            [&sk[..1152], &sk[sk.len() - 32..]]
        }
        gnb_secret::scrub_stack();
        let (pk, sk) = kem_keypair();
        let stack = dead_stack_below_caller();
        assert_eq!((pk.len(), sk.len()), (MLKEM768_PK_SIZE, 2400));
        for part in secret_parts(&sk) {
            assert!(residue(&stack, part).is_empty(), "kem_keypair left its key on the stack");
        }
        gnb_secret::scrub_stack();
        let (ss_r, ct) = kem_encapsulate(&pk).unwrap();
        let stack = dead_stack_below_caller();
        assert!(residue(&stack, &ss_r).is_empty(), "kem_encapsulate left the shared secret on the stack");
        gnb_secret::scrub_stack();
        let ss_i = kem_decapsulate(&sk, &ct).unwrap();
        let stack = dead_stack_below_caller();
        assert_eq!(ss_i, ss_r, "both sides derive one shared secret");
        assert!(residue(&stack, &ss_i).is_empty(), "kem_decapsulate left the shared secret on the stack");
        for part in secret_parts(&sk) {
            assert!(residue(&stack, part).is_empty(), "kem_decapsulate left the key on the stack");
        }
        assert!(kem_encapsulate(&pk[1..]).is_none(), "wrong-size key");
        assert!(kem_decapsulate(&sk, &ct[1..]).is_none(), "wrong-size ciphertext");
    }

    // Independent one-block HKDF-SHA256 fixture: Python stdlib hmac/hashlib,
    // extract(salt=[0x33;32], ikm=[0x11;32] || [0x22;32]), then expand each
    // literal direction label with counter byte 0x01. No production helper
    // generated these expected bytes.
    const I2R: [u8; STREAM_KEY_SIZE] = [
        0x4c, 0xa4, 0xd1, 0x00, 0x6a, 0xe9, 0xb1, 0x25,
        0x87, 0x74, 0x21, 0xbc, 0x76, 0x32, 0x27, 0x4e,
        0xa4, 0x69, 0xc9, 0x7c, 0xeb, 0x75, 0xf4, 0x1c,
        0x18, 0xc0, 0xe6, 0xed, 0x39, 0x29, 0xa2, 0xb1,
    ];
    const R2I: [u8; STREAM_KEY_SIZE] = [
        0xef, 0xd7, 0xe8, 0x91, 0x04, 0x9e, 0xae, 0x42,
        0xa4, 0xf3, 0x74, 0xf1, 0x2c, 0x1e, 0xc0, 0x0e,
        0xad, 0xe6, 0x34, 0x4b, 0xbd, 0x2a, 0xe0, 0x78,
        0x05, 0xe7, 0x63, 0xab, 0x59, 0x49, 0xec, 0xc9,
    ];

    #[test]
    fn derived_keys_preserve_fixed_hkdf_vector_and_direction() {
        let (i2r, r2i) = derive_keys(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
        assert_eq!(i2r.as_slice(), I2R);
        assert_eq!(r2i.as_slice(), R2I);
        assert_ne!(i2r.as_slice(), r2i.as_slice());
    }

    #[test]
    fn derived_keys_require_drop_cleanup() {
        fn needs_drop<T>(_: &T) -> bool { std::mem::needs_drop::<T>() }
        let (i2r, r2i) = derive_keys(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
        let cleanup = (needs_drop(&i2r), needs_drop(&r2i));
        assert_eq!(cleanup, (true, true), "both derived keys need cleaning owners");
    }

    #[test]
    fn derived_keys_can_be_wiped_while_alive() {
        let (mut i2r, mut r2i) = derive_keys(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
        i2r.zeroize();
        assert_eq!(i2r.as_slice(), [0; STREAM_KEY_SIZE]);
        assert_eq!(r2i.as_slice(), R2I, "the other owner remains independent");
        r2i.zeroize();
        assert_eq!(r2i.as_slice(), [0; STREAM_KEY_SIZE]);
    }

    #[test]
    fn session_key_owners_are_not_copy() {
        // A Copy type would have both candidates, making `_` ambiguous at
        // compile time. Guard the exact protected key type and stream owners;
        // derived_keys_require_drop_cleanup separately checks actual results.
        trait AmbiguousIfCopy<A> { fn check() {} }
        impl<T> AmbiguousIfCopy<()> for T {}
        impl<T: Copy> AmbiguousIfCopy<u8> for T {}
        let _ = <Zeroizing<[u8; STREAM_KEY_SIZE]> as AmbiguousIfCopy<_>>::check;
        let _ = <TxStream as AmbiguousIfCopy<_>>::check;
        let _ = <RxStream as AmbiguousIfCopy<_>>::check;
    }

    #[test]
    fn stream_owners_wipe_keys_and_counters_while_alive() {
        // Keep exercising the public array-taking compatibility constructors.
        let mut tx = TxStream::new(I2R);
        let mut rx = RxStream::new(I2R);
        let ciphertext = tx.seal(b"synthetic payload", b"fixed aad").unwrap();
        assert_eq!(rx.open(&ciphertext, b"fixed aad").unwrap(), b"synthetic payload");
        assert_eq!((tx.counter(), rx.counter()), (1, 1));
        tx.zeroize();
        assert_eq!(tx.key.as_slice(), [0; STREAM_KEY_SIZE]);
        assert_eq!(tx.counter(), 0);
        assert_eq!(rx.key.as_slice(), I2R);
        rx.zeroize();
        assert_eq!(rx.key.as_slice(), [0; STREAM_KEY_SIZE]);
        assert_eq!(rx.counter(), 0);
    }
}
