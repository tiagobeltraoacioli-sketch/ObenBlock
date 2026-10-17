//! Bloch finalized-checkpoint anchors on GnB-SMH.
//!
//! See `docs/BLOCH-ANCHOR.md`. An anchor is an ordinary payment from the
//! anchoring wallet whose first two outputs are data markers worth exactly
//! `MARKER_VALUE`, the shape the bridge already uses for its markers:
//!
//! ```text
//!   output 0  33 B  0x02 ‖ root          Bloch finalized checkpoint root
//!   output 1  20 B  "BLA1" ‖ epoch ‖ height   (u64 big-endian each)
//!   output 2+       change to the anchoring wallet
//! ```
//!
//! Both markers are valid output kinds (a policy hash and a key hash) that
//! nobody can spend: spending output 0 needs a policy tree hashing to the
//! Bloch root, output 1 a key hashing to the marker. They stay in the UTXO
//! set, so an anchor remains findable after its block body is pruned.
//!
//! Nothing here is a consensus rule. An anchor proves that its signer saw
//! this checkpoint as finalized no later than the GnB block that holds it;
//! who is trusted is a choice of the verifier (`anchor_signers`).

use crate::bridge::MARKER_VALUE;
use crate::core::policy::{PKH_SPK_LEN, POLICY_SPK_LEN, POLICY_TAG};
use crate::core::{Transaction, TxOutput};
use sha3::{Digest, Sha3_256};

/// First 4 bytes of the epoch marker (format version 1).
pub const ANCHOR_MAGIC: [u8; 4] = *b"BLA1";

/// A Bloch FFG-finalized checkpoint as reported by `getchaininfo`
/// (`finalized.epoch`, `finalized.root`, `finalized_height`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: u64,
    pub height: u64,
    pub root: [u8; 32],
}

/// Output 0: the root behind the policy tag.
pub fn root_marker(root: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(POLICY_SPK_LEN);
    s.push(POLICY_TAG);
    s.extend_from_slice(root);
    s
}

/// Output 1: magic, epoch and height.
pub fn epoch_marker(epoch: u64, height: u64) -> [u8; 20] {
    let mut m = [0u8; 20];
    m[..4].copy_from_slice(&ANCHOR_MAGIC);
    m[4..12].copy_from_slice(&epoch.to_be_bytes());
    m[12..].copy_from_slice(&height.to_be_bytes());
    m
}

/// The fixed outputs of an anchor (change is appended by the wallet).
pub fn anchor_outputs(cp: &Checkpoint) -> Result<Vec<TxOutput>, String> {
    if cp.root == [0u8; 32] {
        return Err("checkpoint root is all zero".into());
    }
    Ok(vec![
        TxOutput { value: MARKER_VALUE, script_pubkey: root_marker(&cp.root) },
        TxOutput { value: MARKER_VALUE, script_pubkey: epoch_marker(cp.epoch, cp.height).to_vec() },
    ])
}

/// Parse an anchor from a transaction's outputs, exact shape only.
pub fn parse_anchor(outputs: &[TxOutput]) -> Result<Checkpoint, String> {
    let o0 = outputs.first().ok_or("no outputs")?;
    let o1 = outputs.get(1).ok_or("no epoch marker (output 1)")?;
    if o0.value != MARKER_VALUE || o0.script_pubkey.len() != POLICY_SPK_LEN || o0.script_pubkey[0] != POLICY_TAG {
        return Err(format!("output 0 is not a root marker (33 bytes 0x02 ‖ root, exactly {MARKER_VALUE})"));
    }
    if o1.value != MARKER_VALUE || o1.script_pubkey.len() != PKH_SPK_LEN || o1.script_pubkey[..4] != ANCHOR_MAGIC {
        return Err(format!("output 1 is not an epoch marker (20 bytes \"BLA1\" ‖ epoch ‖ height, exactly {MARKER_VALUE})"));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&o0.script_pubkey[1..]);
    if root == [0u8; 32] {
        return Err("checkpoint root is all zero".into());
    }
    let epoch = u64::from_be_bytes(o1.script_pubkey[4..12].try_into().expect("8 bytes"));
    let height = u64::from_be_bytes(o1.script_pubkey[12..20].try_into().expect("8 bytes"));
    Ok(Checkpoint { epoch, height, root })
}

/// Key hashes (the 20 bytes of a `gnb1q` address) of the single-key inputs
/// that signed `tx`, deduplicated, in input order. Policy inputs are skipped.
/// The signatures themselves were checked by consensus when the transaction
/// was mined; this only names who made the anchor.
pub fn anchor_signers(tx: &Transaction) -> Vec<[u8; 20]> {
    let mut out: Vec<[u8; 20]> = Vec::new();
    for input in &tx.inputs {
        let Some((_sig, pk)) = Transaction::parse_script_sig_borrowed(&input.script_sig) else { continue };
        let mut h = [0u8; 20];
        h.copy_from_slice(&Sha3_256::digest(pk)[..20]);
        if !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp() -> Checkpoint {
        Checkpoint { epoch: 5819, height: 151_098, root: [0x34; 32] }
    }

    #[test]
    fn roundtrip() {
        let outs = anchor_outputs(&cp()).unwrap();
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].script_pubkey.len(), 33);
        assert_eq!(outs[1].script_pubkey.len(), 20);
        assert!(outs.iter().all(|o| o.value == MARKER_VALUE));
        assert!(outs.iter().all(|o| crate::core::policy::output_kind(&o.script_pubkey).is_some()));
        assert_eq!(parse_anchor(&outs).unwrap(), cp());
    }

    #[test]
    fn change_after_markers_is_ignored() {
        let mut outs = anchor_outputs(&cp()).unwrap();
        outs.push(TxOutput { value: 1_000_000, script_pubkey: vec![7; 20] });
        assert_eq!(parse_anchor(&outs).unwrap(), cp());
    }

    #[test]
    fn epoch_marker_layout() {
        let m = epoch_marker(0x0102, 0x0a0b);
        assert_eq!(&m[..4], b"BLA1");
        assert_eq!(&m[4..12], &[0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(&m[12..], &[0, 0, 0, 0, 0, 0, 0x0a, 0x0b]);
    }

    #[test]
    fn signers_are_the_input_key_hashes() {
        use crate::core::TxInput;
        let witness = |sig: &[u8], pk: &[u8]| {
            let mut w = (sig.len() as u32).to_le_bytes().to_vec();
            w.extend_from_slice(sig);
            w.extend_from_slice(&(pk.len() as u32).to_le_bytes());
            w.extend_from_slice(pk);
            w
        };
        let input = |pk: &[u8]| TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: witness(&[9; 4], pk), sequence: 0 };
        let tx = Transaction {
            version: 2,
            inputs: vec![input(b"key-a"), input(b"key-b"), input(b"key-a"),
                         TxInput { prev_txid: [2; 32], prev_index: 1, script_sig: vec![0x02, 1, 2], sequence: 0 }],
            outputs: anchor_outputs(&cp()).unwrap(),
            locktime: 0,
        };
        let h = |pk: &[u8]| -> [u8; 20] { Sha3_256::digest(pk)[..20].try_into().unwrap() };
        assert_eq!(anchor_signers(&tx), vec![h(b"key-a"), h(b"key-b")]);
        assert_eq!(&h(b"key-a"), crate::address::Address::from_pubkey(b"key-a", crate::address::Network::Mainnet).hash());
    }

    #[test]
    fn rejects_wrong_shapes() {
        let good = anchor_outputs(&cp()).unwrap();
        assert!(anchor_outputs(&Checkpoint { root: [0; 32], ..cp() }).is_err());
        assert!(parse_anchor(&good[..1]).is_err());

        let mut v = good.clone();
        v[0].value += 1;
        assert!(parse_anchor(&v).is_err(), "marker value must be exact");

        let mut v = good.clone();
        v[0].script_pubkey[0] = 0x03;
        assert!(parse_anchor(&v).is_err(), "root marker needs the policy tag");

        let mut v = good.clone();
        v[1].script_pubkey[0] = b'X';
        assert!(parse_anchor(&v).is_err(), "epoch marker needs the magic");

        let mut v = good.clone();
        v.swap(0, 1);
        assert!(parse_anchor(&v).is_err(), "order is fixed");

        let mut v = good;
        v[0].script_pubkey = root_marker(&[0; 32]);
        assert!(parse_anchor(&v).is_err(), "zero root");
    }
}
