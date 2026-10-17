//! GnB-KES: forward-secure (key-evolving) hybrid signatures for PoWit witnesses.
//!
//! See `docs/DESIGN-powit-kes.md`. A witness key is the Merkle root over
//! `2^depth` hybrid ML-DSA-65 ‖ Falcon-1024 leaf keys, one per PoWit epoch.
//! Leaf `i`'s keypair is derived from `seed_i`, and `seed_{i+1} = H(seed_i)`,
//! so a signer that has evolved to epoch `e` holds only `seed_e`: it can sign
//! epoch `e` and later, and nothing earlier. A stolen current state cannot
//! sign the past, which closes long-range attacks on witness finality.
//!
//! ```text
//! seed_{i+1} = SHA3("GNB-KES-v1/step" ‖ seed_i)
//! leaf_i     = hybrid keypair from SHA3("GNB-KES-v1/leaf" ‖ seed_i)
//! L_i        = SHA3("GNB-KES-v1/pk" ‖ pk_i)
//! node       = SHA3("GNB-KES-v1/node" ‖ left ‖ right)
//! witness id = SHA3("GNB-KES-v1/id" ‖ u8(depth) ‖ root)[0..20]
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::crypto::SecretBytes;

use super::write_varint;

const DS_STEP: &[u8] = b"GNB-KES-v1/step";
const DS_LEAF: &[u8] = b"GNB-KES-v1/leaf";
const DS_PK: &[u8] = b"GNB-KES-v1/pk";
const DS_NODE: &[u8] = b"GNB-KES-v1/node";
const DS_ID: &[u8] = b"GNB-KES-v1/id";

/// Deepest tree accepted (65,536 epochs).
pub const MAX_DEPTH: u8 = 16;
/// Default depth for new witness keys: 4,096 epochs (~2.8 years of 6 h epochs).
pub const DEFAULT_DEPTH: u8 = 12;
pub const MAX_LEAF_PK_LEN: usize = 8 * 1024;
pub const MAX_LEAF_SIG_LEN: usize = 8 * 1024;

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Sha3_256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

/// `seed <- SHA3("GNB-KES-v1/step" ‖ seed)` in place (CRY-4): the next seed
/// is written over the current one, through a wiped temporary, so no copy
/// of an earlier seed outlives the step (forward security). The hasher's
/// stack state is dead after the call; callers scrub the stack once their
/// loop is done (`gnb_secret::scrub_stack`).
fn step_in_place(seed: &mut [u8]) {
    let mut hasher = Sha3_256::new();
    hasher.update(DS_STEP);
    hasher.update(&*seed);
    let mut next = Zeroizing::new([0u8; 32]);
    hasher.finalize_into(sha3::digest::generic_array::GenericArray::from_mut_slice(&mut next[..]));
    seed.copy_from_slice(&next[..]);
}

/// Leaf `i`'s key pair from `seed_i`, the secret key in secret memory.
fn leaf_keypair(seed: &[u8]) -> Result<(Vec<u8>, SecretBytes), String> {
    let leaf_seed = Zeroizing::new(h(&[DS_LEAF, seed]));
    crate::crypto::generate_keypair_from_seed_secret(&leaf_seed[..])
        .map_err(|e| format!("kes leaf keygen: {e:?}"))
}

fn leaf_hash(pk: &[u8]) -> [u8; 32] {
    h(&[DS_PK, pk])
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    h(&[DS_NODE, l, r])
}

/// Public KES key: tree depth and Merkle root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KesPublic {
    pub depth: u8,
    pub root: [u8; 32],
}

impl KesPublic {
    /// 20-byte witness id.
    pub fn witness_id(&self) -> [u8; 20] {
        let d = h(&[DS_ID, &[self.depth], &self.root]);
        let mut id = [0u8; 20];
        id.copy_from_slice(&d[..20]);
        id
    }

    pub fn epochs(&self) -> u64 {
        1u64 << self.depth
    }
}

/// A signature by the leaf of epoch `index`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KesSignature {
    pub index: u32,
    pub leaf_pk: Vec<u8>,
    pub sig: Vec<u8>,
    /// Sibling hashes from the leaf up to the root.
    pub path: Vec<[u8; 32]>,
}

impl KesSignature {
    pub fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.index.to_le_bytes());
        write_varint(out, self.leaf_pk.len() as u64);
        out.extend_from_slice(&self.leaf_pk);
        write_varint(out, self.sig.len() as u64);
        out.extend_from_slice(&self.sig);
        out.push(self.path.len() as u8);
        for n in &self.path {
            out.extend_from_slice(n);
        }
    }

    pub fn read_wire(cur: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        use super::powit::{read_array32, read_bytes, read_u32};
        let index = read_u32(cur)?;
        let leaf_pk = read_bytes(cur, MAX_LEAF_PK_LEN, "kes leaf pk")?;
        let sig = read_bytes(cur, MAX_LEAF_SIG_LEN, "kes sig")?;
        let n = read_varint_u8(cur)?;
        if n > MAX_DEPTH {
            return Err("kes path too long".into());
        }
        let mut path = Vec::with_capacity(n as usize);
        for _ in 0..n {
            path.push(read_array32(cur)?);
        }
        Ok(KesSignature { index, leaf_pk, sig, path })
    }
}

fn read_varint_u8(cur: &mut std::io::Cursor<&[u8]>) -> Result<u8, String> {
    let pos = cur.position() as usize;
    let b = cur.get_ref().get(pos).copied().ok_or("truncated")?;
    cur.set_position(pos as u64 + 1);
    Ok(b)
}

/// Verify `s` as `public`'s signature on `msg` for epoch `index`.
pub fn verify(public: &KesPublic, index: u64, msg: &[u8], s: &KesSignature) -> bool {
    if public.depth == 0 || public.depth > MAX_DEPTH || index >= public.epochs() {
        return false;
    }
    if u64::from(s.index) != index || s.path.len() != public.depth as usize {
        return false;
    }
    if s.leaf_pk.len() > MAX_LEAF_PK_LEN || s.sig.len() > MAX_LEAF_SIG_LEN {
        return false;
    }
    let mut node = leaf_hash(&s.leaf_pk);
    let mut i = index;
    for sib in &s.path {
        node = if i & 1 == 0 { node_hash(&node, sib) } else { node_hash(sib, &node) };
        i >>= 1;
    }
    node == public.root && crate::crypto::verify_canonical(&s.leaf_pk, msg, &s.sig)
}

/// The secret side: current epoch, current seed, and the (public) leaf hashes
/// needed for authentication paths. Never holds an earlier seed.
///
/// CRY-4: the seed lives in a [`SecretBytes`] (locked in RAM where the
/// platform allows: a witness key stays in a node's memory for its whole
/// run), evolves in place and is wiped on drop; the signer is neither
/// `Copy` nor `Clone`.
pub struct KesSigner {
    depth: u8,
    epoch: u64,
    seed: SecretBytes,
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

gnb_secret::assert_not_copy_or_clone!(KesSigner);

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
    }
    level[0]
}

impl KesSigner {
    /// Derive all leaf public keys from `seed0` and keep only their hashes.
    /// `progress(i)` is called after each leaf (keygen is slow at depth 12+).
    ///
    /// CRY-4: production callers pass `seed0` by reference (`&seed`, from
    /// wiping storage): taking it by value, as this function used to, left
    /// an unwiped copy of the key's root secret in the callee's frame. A
    /// by-value array is still accepted for test fixtures (public seeds).
    /// The running seed and every leaf's secret key live in wiped secret
    /// memory.
    pub fn generate(
        depth: u8,
        seed0: impl std::borrow::Borrow<[u8; 32]>,
        mut progress: impl FnMut(u64),
    ) -> Result<Self, String> {
        let seed0: &[u8; 32] = seed0.borrow();
        if depth == 0 || depth > MAX_DEPTH {
            return Err(format!("kes depth must be 1..={MAX_DEPTH}"));
        }
        let n = 1u64 << depth;
        let mut leaves = Vec::with_capacity(n as usize);
        let mut s = SecretBytes::from_slice(seed0);
        for i in 0..n {
            let (pk, _sk) = leaf_keypair(&s)?;
            leaves.push(leaf_hash(&pk));
            step_in_place(&mut s);
            progress(i + 1);
        }
        drop(s);
        gnb_secret::scrub_stack();
        let root = merkle_root(&leaves);
        Ok(KesSigner { depth, epoch: 0, seed: SecretBytes::from_slice(seed0), leaves, root })
    }

    pub fn public(&self) -> KesPublic {
        KesPublic { depth: self.depth, root: self.root }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Advance to `epoch`, erasing every earlier seed. Refuses to go back.
    pub fn evolve_to(&mut self, epoch: u64) -> Result<(), String> {
        if epoch < self.epoch {
            return Err(format!("kes: cannot go back from epoch {} to {}", self.epoch, epoch));
        }
        if epoch >= self.public().epochs() {
            return Err("kes: key exhausted; generate a new witness key".into());
        }
        for _ in self.epoch..epoch {
            step_in_place(&mut self.seed);
        }
        // The hash states of the steps held the earlier seeds.
        gnb_secret::scrub_stack();
        self.epoch = epoch;
        Ok(())
    }

    /// Sign with the current epoch's leaf.
    pub fn sign(&self, msg: &[u8]) -> Result<KesSignature, String> {
        let (pk, sk) = leaf_keypair(&self.seed)?;
        let sig = crate::crypto::sign(&sk, msg).map_err(|e| format!("kes sign: {e:?}"))?;
        let mut path = Vec::with_capacity(self.depth as usize);
        let mut level = self.leaves.clone();
        let mut i = self.epoch as usize;
        while level.len() > 1 {
            path.push(level[i ^ 1]);
            level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
            i >>= 1;
        }
        Ok(KesSignature { index: self.epoch as u32, leaf_pk: pk, sig, path })
    }

    /// Secret state for encrypted storage: depth ‖ epoch ‖ seed (the leaves
    /// are public and stored alongside in clear), in secret memory.
    pub fn secret_bytes(&self) -> SecretBytes {
        let mut v = SecretBytes::zeroed(41);
        v[0] = self.depth;
        v[1..9].copy_from_slice(&self.epoch.to_le_bytes());
        v[9..41].copy_from_slice(&self.seed);
        v
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Rebuild from stored secret state and public leaves; the root must match.
    pub fn from_parts(secret: &[u8], leaves: Vec<[u8; 32]>, expected: &KesPublic) -> Result<Self, String> {
        if secret.len() != 41 {
            return Err("kes: bad secret state".into());
        }
        let depth = secret[0];
        if depth != expected.depth || leaves.len() as u64 != (1u64 << depth) {
            return Err("kes: state does not match the public key".into());
        }
        let epoch = u64::from_le_bytes(secret[1..9].try_into().unwrap());
        let seed = SecretBytes::from_slice(&secret[9..41]);
        let root = merkle_root(&leaves);
        if root != expected.root {
            return Err("kes: leaves do not match the root".into());
        }
        Ok(KesSigner { depth, epoch, seed, leaves, root })
    }
}

/// Encrypted on-disk witness key: public part in clear, secret state under
/// the wallet's Argon2id + AES-256-GCM keyfile.
#[derive(Serialize, Deserialize)]
pub struct KesKeyFile {
    pub version: u32,
    pub public: KesPublic,
    /// Informational; the authoritative epoch is inside the encrypted state.
    pub epoch_hint: u64,
    pub leaves_hex: String,
    pub secret: crate::wallet::encryption::EncryptedKeyfile,
}

impl KesKeyFile {
    pub fn seal(signer: &KesSigner, password: &str) -> Result<Self, String> {
        let public = signer.public();
        let secret = crate::wallet::encryption::EncryptedKeyfile::encrypt(
            &signer.secret_bytes(), &public.root, crate::address::Network::Mainnet, password)
            .map_err(|e| format!("kes seal: {e:?}"))?;
        let mut leaves = Vec::with_capacity(signer.leaves.len() * 32);
        for l in &signer.leaves {
            leaves.extend_from_slice(l);
        }
        Ok(KesKeyFile { version: 1, public, epoch_hint: signer.epoch, leaves_hex: hex::encode(leaves), secret })
    }

    pub fn open(&self, password: &str) -> Result<KesSigner, String> {
        let (secret, _public, _net) = self.secret.decrypt(password).map_err(|e| format!("kes open: {e:?}"))?;
        // CRY-4: into secret memory; the decrypted `Vec` is wiped.
        let secret = SecretBytes::from_vec(secret);
        let raw = hex::decode(&self.leaves_hex).map_err(|e| format!("kes leaves: {e}"))?;
        if raw.len() % 32 != 0 {
            return Err("kes leaves: bad length".into());
        }
        let leaves = raw.chunks(32).map(|c| c.try_into().unwrap()).collect();
        KesSigner::from_parts(&secret, leaves, &self.public)
    }

    /// Write atomically (temp file + rename).
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json).map_err(|e| format!("kes save: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("kes save: {e}"))
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let b = std::fs::read(path).map_err(|e| format!("kes load: {e}"))?;
        serde_json::from_slice(&b).map_err(|e| format!("kes load: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(depth: u8) -> KesSigner {
        KesSigner::generate(depth, [7u8; 32], |_| {}).unwrap()
    }

    /// CRY-4: evolving keeps no earlier seed in the signer (the seed is
    /// overwritten in place), and a dropped signer, its stored state and
    /// every transient leaf key leave only zeros behind (read after the drop
    /// through the test quarantine).
    #[test]
    fn evolution_and_drop_leave_no_seed_behind() {
        let q = gnb_secret::test_support::Quarantine::start();
        let mut s = signer(2);
        let seed0 = s.secret_bytes()[9..41].to_vec();
        s.evolve_to(2).unwrap();
        let mut seed2 = seed0.clone();
        step_in_place(&mut seed2);
        step_in_place(&mut seed2);
        assert_eq!(&s.secret_bytes()[9..41], seed2.as_slice(), "seed_2 = step(step(seed_0))");
        let _sig = s.sign(b"m").unwrap();
        drop(s);
        let released = q.released();
        assert!(!released.is_empty());
        assert!(q.all_released_zeroed(), "a dropped KES seed or leaf key left bytes behind");
        assert!(!released.iter().any(|r| r.windows(32).any(|w| w == seed0.as_slice())));
    }

    #[test]
    fn every_leaf_signs_and_verifies_only_for_its_epoch() {
        let mut s = signer(3);
        let pubk = s.public();
        for e in 0..8u64 {
            s.evolve_to(e).unwrap();
            let sig = s.sign(b"msg").unwrap();
            assert!(verify(&pubk, e, b"msg", &sig), "epoch {e}");
            assert!(!verify(&pubk, (e + 1) % 8, b"msg", &sig), "wrong index");
            assert!(!verify(&pubk, e, b"other", &sig), "wrong message");
        }
    }

    #[test]
    fn evolving_erases_the_past() {
        let mut s = signer(3);
        s.evolve_to(5).unwrap();
        assert!(s.evolve_to(4).is_err(), "cannot go back");
        // The only secret left is seed_5; the signature it makes is for epoch 5.
        let sig = s.sign(b"m").unwrap();
        assert_eq!(sig.index, 5);
        assert!(!verify(&s.public(), 2, b"m", &sig));
        assert!(s.evolve_to(8).is_err(), "exhausted key refused");
    }

    #[test]
    fn tampering_fails() {
        let s = signer(3);
        let pubk = s.public();
        let good = s.sign(b"m").unwrap();
        let mut bad = good.clone();
        bad.path[1][0] ^= 1;
        assert!(!verify(&pubk, 0, b"m", &bad), "tampered path");
        let other = KesSigner::generate(3, [8u8; 32], |_| {}).unwrap();
        assert!(!verify(&other.public(), 0, b"m", &good), "another root");
        let mut short = good.clone();
        short.path.pop();
        assert!(!verify(&pubk, 0, b"m", &short), "short path");
        // Swap in a leaf key from another tree: the path no longer leads to the root.
        let mut swapped = good.clone();
        swapped.leaf_pk = other.sign(b"m").unwrap().leaf_pk;
        assert!(!verify(&pubk, 0, b"m", &swapped));
    }

    #[test]
    fn wire_and_sealed_file_roundtrip() {
        let mut s = signer(2);
        s.evolve_to(1).unwrap();
        let sig = s.sign(b"x").unwrap();
        let mut buf = Vec::new();
        sig.write_wire(&mut buf);
        let back = KesSignature::read_wire(&mut std::io::Cursor::new(buf.as_slice())).unwrap();
        assert_eq!(back, sig);

        let pw = "Witness-Test-2026!xQ";
        let file = KesKeyFile::seal(&s, pw).unwrap();
        let opened = file.open(pw).unwrap();
        assert_eq!(opened.epoch(), 1);
        assert_eq!(opened.public(), s.public());
        assert!(file.open("Wrong-Password-2026!x").is_err());
    }

    #[test]
    fn witness_id_depends_on_depth_and_root() {
        let a = signer(2).public();
        let b = KesPublic { depth: 3, root: a.root };
        assert_ne!(a.witness_id(), b.witness_id());
    }
}
