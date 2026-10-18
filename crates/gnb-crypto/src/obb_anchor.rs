//! ObenBlock finalized checkpoints anchored in Bloch: the anchor record.
//!
//! See `docs/OBB-ANCHOR.md` and `docs/DESIGN-obenblock.md` §8. For every
//! PoWit-finalized checkpoint that starts a new epoch, an operator publishes
//! one record in the Bloch anchor registry. The record is the interface
//! between the two chains, 84 bytes, every integer little-endian:
//!
//! ```text
//!   record   = u32le(chain_id) ‖ u64le(slot) ‖ block_id ‖ u64le(finalized_at) ‖ w_digest
//!                    4               8           32            8                 32   = 84
//!   w_digest = SHA-256d("OBB-ANCHOR-v1/W" ‖ u32le(n) ‖ key_0 ‖ u128le(weight_0) ‖ …)
//!                 keys ascending, no duplicates (20-byte key ids)
//!   record_id = SHA-256d(record)
//! ```
//!
//! * `chain_id`: the chain the checkpoint belongs to (`core::ChainId`).
//! * `slot`: the checkpoint slot (`powit::Checkpoint::height`); `block_id`
//!   is the block that slot names on the finalized chain
//!   (`powit::Checkpoint::hash`, the 32 bytes as the node stores them).
//! * `finalized_at`: the DAG height of the selected-chain block whose PoWit
//!   state first holds this checkpoint as finalized
//!   (`PowitState::finalized_at`), always above `slot`.
//! * `w_digest`: the witness set (key, weight) of the epoch of the
//!   checkpoint that justified the next one and so finalized this one, as
//!   that block's state holds it.
//!
//! The record carries no version byte: a later format is a new registry
//! method (`docs/OBB-ANCHOR.md`). Decoding is exact: length, a non-zero
//! block id and `finalized_at > slot` are checked. Nothing here is a
//! consensus rule.

use sha2::{Digest, Sha256};

/// Length of an encoded record.
pub const RECORD_LEN: usize = 84;

/// Domain tag of the witness-set digest.
pub const W_DIGEST_TAG: &[u8] = b"OBB-ANCHOR-v1/W";

/// A 20-byte PoWit key id (`core::powit::KeyId`).
pub type KeyId = [u8; 20];

/// SHA-256d, Bitcoin's double SHA-256.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let once = Sha256::digest(data);
    Sha256::digest(once).into()
}

/// One anchor record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AnchorRecord {
    pub chain_id: u32,
    pub slot: u64,
    pub block_id: [u8; 32],
    pub finalized_at: u64,
    pub w_digest: [u8; 32],
}

impl AnchorRecord {
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[0..4].copy_from_slice(&self.chain_id.to_le_bytes());
        out[4..12].copy_from_slice(&self.slot.to_le_bytes());
        out[12..44].copy_from_slice(&self.block_id);
        out[44..52].copy_from_slice(&self.finalized_at.to_le_bytes());
        out[52..84].copy_from_slice(&self.w_digest);
        out
    }

    /// Parse exactly [`RECORD_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<AnchorRecord, String> {
        if bytes.len() != RECORD_LEN {
            return Err(format!("anchor record: {} bytes, expected {RECORD_LEN}", bytes.len()));
        }
        let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().expect("8 bytes"));
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(&bytes[12..44]);
        let mut w_digest = [0u8; 32];
        w_digest.copy_from_slice(&bytes[52..84]);
        let r = AnchorRecord {
            chain_id: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
            slot: u64_at(4),
            block_id,
            finalized_at: u64_at(44),
            w_digest,
        };
        r.check()?;
        Ok(r)
    }

    /// The field rules [`decode`](Self::decode) applies.
    pub fn check(&self) -> Result<(), String> {
        if self.block_id == [0u8; 32] {
            return Err("anchor record: zero block id".into());
        }
        if self.finalized_at <= self.slot {
            return Err("anchor record: finalized_at must be above slot".into());
        }
        Ok(())
    }

    /// `SHA-256d(record)`: how a record is referred to.
    pub fn record_id(&self) -> [u8; 32] {
        sha256d(&self.encode())
    }

    /// Two records for the same (chain, slot) that differ: on Bloch the first
    /// one stands and the other is evidence of a conflicting finalization.
    pub fn conflicts_with(&self, other: &AnchorRecord) -> bool {
        self.chain_id == other.chain_id && self.slot == other.slot && self != other
    }
}

/// The witness-set digest: keys sorted ascending (the input may be in any
/// order, e.g. heaviest first as `PowitState::witness_set_in` returns it).
/// A duplicate key is an error.
pub fn w_digest(set: &[(KeyId, u128)]) -> Result<[u8; 32], String> {
    let mut v: Vec<(KeyId, u128)> = set.to_vec();
    v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    if v.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("witness set: duplicate key".into());
    }
    let n = u32::try_from(v.len()).map_err(|_| "witness set: too many keys".to_string())?;
    let mut buf = Vec::with_capacity(W_DIGEST_TAG.len() + 4 + v.len() * 36);
    buf.extend_from_slice(W_DIGEST_TAG);
    buf.extend_from_slice(&n.to_le_bytes());
    for (k, w) in &v {
        buf.extend_from_slice(k);
        buf.extend_from_slice(&w.to_le_bytes());
    }
    Ok(sha256d(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> AnchorRecord {
        AnchorRecord { chain_id: 0x4F42_0001, slot: 720, block_id: [7; 32], finalized_at: 845, w_digest: [9; 32] }
    }

    #[test]
    fn encode_decode_round_trip_and_layout() {
        let r = rec();
        let b = r.encode();
        assert_eq!(&b[0..4], &[0x01, 0x00, 0x42, 0x4F]);
        assert_eq!(&b[4..12], &720u64.to_le_bytes());
        assert_eq!(&b[44..52], &845u64.to_le_bytes());
        assert_eq!(AnchorRecord::decode(&b).unwrap(), r);
    }

    #[test]
    fn decode_is_exact() {
        let b = rec().encode();
        assert!(AnchorRecord::decode(&b[..83]).is_err());
        let mut long = b.to_vec();
        long.push(0);
        assert!(AnchorRecord::decode(&long).is_err());
        let mut z = rec();
        z.block_id = [0; 32];
        assert!(AnchorRecord::decode(&z.encode()).is_err());
        let mut early = rec();
        early.finalized_at = early.slot;
        assert!(AnchorRecord::decode(&early.encode()).is_err());
    }

    #[test]
    fn w_digest_ignores_input_order_and_refuses_duplicates() {
        let a = ([1u8; 20], 5u128);
        let b = ([2u8; 20], 50u128);
        assert_eq!(w_digest(&[a, b]).unwrap(), w_digest(&[b, a]).unwrap());
        assert_ne!(w_digest(&[a, b]).unwrap(), w_digest(&[a]).unwrap());
        assert!(w_digest(&[a, a]).is_err());
        assert!(w_digest(&[a, ([1u8; 20], 6)]).is_err());
    }

    #[test]
    fn conflict_is_same_slot_different_bytes() {
        let r = rec();
        let mut other = r;
        assert!(!r.conflicts_with(&other));
        other.block_id = [8; 32];
        assert!(r.conflicts_with(&other));
        other.slot += 60;
        assert!(!r.conflicts_with(&other));
    }
}
