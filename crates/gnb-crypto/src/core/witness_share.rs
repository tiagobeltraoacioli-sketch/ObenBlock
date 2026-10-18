//! Witness shares: extra reward for proven witness custody.
//!
//! Consensus from `core::powit_height()`: blocks carry up to
//! `MAX_SHARES_PER_BLOCK` shares in their PoWit section and pay them from the
//! coinbase (`Block::validate_coinbase_value`). The share proof is GnB-SMH v3.
//! Rationale and parameters: `docs/DESIGN-witness-shares.md`.
//!
//! A witness share is a small GnB-SMH proof (`SHARE_TARGET_FACTOR` times
//! easier than a block) that attests to a recent block `B` and can only be
//! computed by someone holding B's full transaction data, witnesses
//! included: every nonce selects `SAMPLE_CHUNKS` pseudo-random 64-byte
//! chunks of B's transaction stream, and those bytes are part of the PoW
//! input. A miner that never downloaded B (SPV / blind mining) cannot try a
//! single nonce.
//!
//! ```text
//! stream(B)  = wire(tx_0, with witness) ‖ wire(tx_1) ‖ …          (64-byte chunks, last zero-padded)
//! idx_k      = u64le(SHA3-256(DS_IDX ‖ attested ‖ SHA3(payout) ‖ u64le(nonce) ‖ u8(k))[0..8]) mod n_chunks
//! preimage   = enc(DS_POW) ‖ attested ‖ witness_root(B) ‖ SHA3(payout) ‖ u32le(bits)
//!              ‖ chunk[idx_0] ‖ … ‖ chunk[idx_7]
//! valid     <=> GnB-SMH(preimage, nonce) < target(bits) × SHARE_TARGET_FACTOR
//! ```
//!
//! Rewards: `WITNESS_POOL_BPS` of each block subsidy is reserved for shares
//! in that block, `MAX_SHARES_PER_BLOCK` equal slots. Each included share
//! pays its slot to the attester's `payout` script, minus an inclusion bonus
//! (`INCLUSION_BONUS_BPS` of the slot) paid to the block miner. Empty slots
//! are not issued, so the miner never gains by dropping other people's shares.
//!
//! Under the SHA-256d proof-of-work scheme (ObenBlock,
//! `core::pow_scheme::PowScheme::Sha256d`) the share proof is an 80-byte
//! SHA-256d header a Bitcoin ASIC mines, and the custody sampling is per job
//! instead of per nonce: [`sha256d`]. Rewards, slots and the share window are
//! the same.

pub mod sha256d;

use super::{pow_scheme, tokenomics, Block};
use gnb_smh::difficulty::{bits_to_target, meets_target, work, Target};
use sha3::{Digest, Sha3_256};

const DS_POW: &[u8] = b"GNB-WSHARE-v1/pow";
const DS_IDX: &[u8] = b"GNB-WSHARE-v1/idx";
const DS_ID: &[u8] = b"GNB-WSHARE-v1/id";

/// A share is this many times easier than a block at the same `bits` (2^4).
pub const SHARE_TARGET_SHIFT: u32 = 4;
pub const SHARE_TARGET_FACTOR: u32 = 1 << SHARE_TARGET_SHIFT;
/// Chunks of the attested block's transaction stream bound into each attempt.
pub const SAMPLE_CHUNKS: usize = 8;
pub const CHUNK_BYTES: usize = 64;
/// Shares a block may carry (each one costs a GnB-SMH verification).
pub const MAX_SHARES_PER_BLOCK: usize = 16;
/// A share in a block at height h must attest a block at height h-WINDOW..h-1.
pub const SHARE_WINDOW: u64 = 16;
/// Part of the block subsidy reserved for witness shares, in basis points.
pub const WITNESS_POOL_BPS: u64 = 2_000;
/// Part of each share slot paid to the block miner for including it.
pub const INCLUSION_BONUS_BPS: u64 = 1_000;
/// Largest payout script accepted.
pub const MAX_PAYOUT_SCRIPT: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WitnessShare {
    /// Block id (`Block::block_hash`) of the attested block.
    pub attested: [u8; 32],
    /// Witness id credited with this share's work (`KesPublic::witness_id`).
    pub witness: [u8; 20],
    /// script_pubkey that receives the reward: any valid output, so the
    /// witness identity and its money are separate (e.g. a cold wallet).
    pub payout: Vec<u8>,
    /// Compact bits of the attested block (the share target derives from it).
    pub bits: u32,
    /// GnB-SMH: the proof's nonce. SHA-256d: the job nonce (`job_nonce`),
    /// which selects the sampled chunks of the job.
    pub nonce: u64,
    /// SHA-256d only: the share header's fields an ASIC sets or rolls
    /// ([`sha256d`]). `None` on GnB, whose wire encoding is unchanged; on the
    /// wire it is present exactly when the process runs the SHA-256d scheme.
    /// Not part of the serde encoding, so GnB's serde shape is unchanged in
    /// both directions; the wire is the only encoding of a share that
    /// travels or is stored, and a share that lost the field fails closed
    /// (`ShareError::WrongScheme`).
    #[serde(skip)]
    pub sha256d: Option<Sha256dShareFields>,
}

/// The fields of a SHA-256d share header besides the attested block, the
/// job commitment and `bits` (`sha256d::share_header`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Sha256dShareFields {
    /// BIP 320: the chain's block version with bits 13 to 28 rolled freely.
    pub version: u32,
    /// Must equal the attested block's timestamp (no ntime rolling).
    pub time: u32,
    /// The header nonce an ASIC rolls.
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    PayoutTooLong,
    WrongAttestedBlock,
    WrongBits,
    BadTarget,
    InsufficientWork,
    OutsideWindow { attested_height: u64, block_height: u64 },
    TooMany(usize),
    Duplicate([u8; 32]),
    /// The share's form does not match the chain's proof-of-work scheme
    /// (SHA-256d header fields on a GnB-SMH chain, or missing on a SHA-256d one).
    WrongScheme,
    /// SHA-256d: the share header's version breaks BIP 320.
    Version,
    /// SHA-256d: the share header's time differs from the attested block's.
    WrongTime,
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayoutTooLong => write!(f, "payout script longer than {MAX_PAYOUT_SCRIPT} bytes"),
            Self::WrongAttestedBlock => f.write_str("share attests a different block than supplied"),
            Self::WrongBits => f.write_str("share bits differ from the attested block's bits"),
            Self::BadTarget => f.write_str("share target is zero"),
            Self::InsufficientWork => f.write_str("share proof does not meet the share target"),
            Self::OutsideWindow { attested_height, block_height } => write!(
                f, "share attests height {attested_height}, outside the window of block {block_height}"),
            Self::TooMany(n) => write!(f, "{n} shares in one block (max {MAX_SHARES_PER_BLOCK})"),
            Self::Duplicate(id) => write!(f, "duplicate share {}", hex::encode(id)),
            Self::WrongScheme => f.write_str("share form does not match the chain's proof-of-work scheme"),
            Self::Version => f.write_str("share header version outside the BIP 320 rolling mask"),
            Self::WrongTime => f.write_str("share header time differs from the attested block's timestamp"),
        }
    }
}

impl std::error::Error for ShareError {}

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The attested block's transaction stream: every transaction's wire bytes,
/// witnesses included, in block order.
pub fn tx_stream(block: &Block) -> Vec<u8> {
    block.transactions.iter().flat_map(|t| t.to_wire_bytes(true)).collect()
}

fn n_chunks(stream: &[u8]) -> u64 {
    (stream.len().div_ceil(CHUNK_BYTES)).max(1) as u64
}

fn chunk(stream: &[u8], i: u64) -> [u8; CHUNK_BYTES] {
    let mut c = [0u8; CHUNK_BYTES];
    let start = (i as usize) * CHUNK_BYTES;
    if start < stream.len() {
        let end = (start + CHUNK_BYTES).min(stream.len());
        c[..end - start].copy_from_slice(&stream[start..end]);
    }
    c
}

/// Chunk indices a nonce selects.
pub fn sample_indices(attested: &[u8; 32], payout: &[u8], nonce: u64, n: u64) -> [u64; SAMPLE_CHUNKS] {
    let ph = sha3(&[payout]);
    let mut out = [0u64; SAMPLE_CHUNKS];
    for (k, slot) in out.iter_mut().enumerate() {
        let d = sha3(&[DS_IDX, attested, &ph, &nonce.to_le_bytes(), &[k as u8]]);
        *slot = u64::from_le_bytes(d[..8].try_into().unwrap()) % n;
    }
    out
}

/// GnB-SMH input for one attempt. `stream` and `witness_root` belong to the
/// attested block; a miner precomputes them once per attested block.
/// What a share's work is bound to besides the attested block: the witness
/// credited and the payout (neither can be swapped after mining).
fn binding(share: &WitnessShare) -> Vec<u8> {
    [&share.witness[..], &sha3(&[&share.payout])[..]].concat()
}

pub fn pow_preimage(share: &WitnessShare, witness_root: &[u8; 32], stream: &[u8]) -> Vec<u8> {
    let idx = sample_indices(&share.attested, &binding(share), share.nonce, n_chunks(stream));
    let mut b = Vec::with_capacity(4 + DS_POW.len() + 32 * 3 + 4 + SAMPLE_CHUNKS * CHUNK_BYTES);
    b.extend_from_slice(&(DS_POW.len() as u32).to_le_bytes());
    b.extend_from_slice(DS_POW);
    b.extend_from_slice(&share.attested);
    b.extend_from_slice(witness_root);
    b.extend_from_slice(&share.witness);
    b.extend_from_slice(&sha3(&[&share.payout]));
    b.extend_from_slice(&share.bits.to_le_bytes());
    for i in idx {
        b.extend_from_slice(&chunk(stream, i));
    }
    b
}

/// target × SHARE_TARGET_FACTOR, saturating at the maximum target.
pub fn share_target(block_target: &Target) -> Target {
    let t = &block_target.0;
    if t[..1].iter().any(|&b| b >> (8 - SHARE_TARGET_SHIFT) != 0) {
        return Target::MAX;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let next = if i + 1 < 32 { t[i + 1] } else { 0 };
        out[i] = (t[i] << SHARE_TARGET_SHIFT) | (next >> (8 - SHARE_TARGET_SHIFT));
    }
    Target(out)
}

impl WitnessShare {
    /// Wire: attested 32 ‖ witness 20 ‖ varint len ‖ payout ‖ bits u32le ‖ nonce u64le,
    /// then under SHA-256d ‖ version u32le ‖ time u32le ‖ header nonce u32le.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(52 + 9 + self.payout.len() + 24);
        out.extend_from_slice(&self.attested);
        out.extend_from_slice(&self.witness);
        super::write_varint(&mut out, self.payout.len() as u64);
        out.extend_from_slice(&self.payout);
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        if let Some(f) = &self.sha256d {
            out.extend_from_slice(&f.version.to_le_bytes());
            out.extend_from_slice(&f.time.to_le_bytes());
            out.extend_from_slice(&f.nonce.to_le_bytes());
        }
        out
    }

    /// Decode under the process's proof-of-work scheme ([`Self::read_wire_in`]).
    pub fn read_wire(cur: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        Self::read_wire_in(cur, pow_scheme::node_sha256d_params().is_some())
    }

    /// Decode a share of a GnB-SMH chain (`sha256d == false`, GnB's encoding)
    /// or of a SHA-256d chain (the three header fields follow).
    pub fn read_wire_in(cur: &mut std::io::Cursor<&[u8]>, sha256d: bool) -> Result<Self, String> {
        let attested = super::powit::read_array32(cur)?;
        let witness = super::powit::read_fixed::<20>(cur)?;
        let payout = super::powit::read_bytes(cur, MAX_PAYOUT_SCRIPT, "share payout")?;
        let bits = super::powit::read_u32(cur)?;
        let nonce = super::powit::read_u64(cur)?;
        let sha256d = if sha256d {
            Some(Sha256dShareFields {
                version: super::powit::read_u32(cur)?,
                time: super::powit::read_u32(cur)?,
                nonce: super::powit::read_u32(cur)?,
            })
        } else {
            None
        };
        Ok(WitnessShare { attested, witness, payout, bits, nonce, sha256d })
    }

    /// The witness this share credits.
    pub fn key_id(&self) -> super::powit::KeyId {
        self.witness
    }

    /// The payout must be a valid output script.
    pub fn payout_is_valid(&self) -> bool {
        super::policy::output_kind(&self.payout).is_some()
    }
}

/// Production share proof: GnB-SMH v3.
pub fn smh_v3(pre: &[u8], nonce: u64) -> [u8; 32] {
    gnb_smh::hash_algo(gnb_smh::Algo::V3, pre, nonce)
}

/// Unique id of a share (duplicates are refused across a block). It covers
/// every field, so it also keys the node's cache of verified shares.
pub fn share_id(share: &WitnessShare) -> [u8; 32] {
    if let Some(f) = &share.sha256d {
        return sha256d::share_id(share, f);
    }
    sha3(&[DS_ID, &share.attested, &share.witness, &sha3(&[&share.payout]), &share.bits.to_le_bytes(),
           &share.nonce.to_le_bytes()])
}

/// Verify one share against the block it attests. `pow` is the GnB-SMH
/// evaluation (`gnb_smh::hash_thread_local` in production; a stub in tests).
/// Returns the share's work. Under the SHA-256d scheme the share is checked
/// by [`sha256d::verify_share`] instead and `pow` is not used.
pub fn verify_share<F>(share: &WitnessShare, attested: &Block, pow: F) -> Result<u128, ShareError>
where
    F: Fn(&[u8], u64) -> [u8; 32],
{
    if let Some(p) = pow_scheme::node_sha256d_params() {
        return sha256d::verify_share(share, attested, &p);
    }
    if share.payout.len() > MAX_PAYOUT_SCRIPT {
        return Err(ShareError::PayoutTooLong);
    }
    if share.sha256d.is_some() {
        return Err(ShareError::WrongScheme);
    }
    if share.attested != attested.block_hash() {
        return Err(ShareError::WrongAttestedBlock);
    }
    if share.bits != attested.header.bits {
        return Err(ShareError::WrongBits);
    }
    let block_target = bits_to_target(share.bits);
    if block_target.is_zero() {
        return Err(ShareError::BadTarget);
    }
    let target = share_target(&block_target);
    let pre = pow_preimage(share, &attested.witness_root(), &tx_stream(attested));
    if !meets_target(&pow(&pre, share.nonce), &target) {
        return Err(ShareError::InsufficientWork);
    }
    Ok(work(&target))
}

/// Block-level checks: count, uniqueness, window, and every proof.
/// `shares` pairs each share with the block it attests.
pub fn verify_block_shares<F>(block_height: u64, shares: &[(&WitnessShare, &Block)], pow: F)
    -> Result<u128, ShareError>
where
    F: Fn(&[u8], u64) -> [u8; 32],
{
    if shares.len() > MAX_SHARES_PER_BLOCK {
        return Err(ShareError::TooMany(shares.len()));
    }
    let mut seen = std::collections::HashSet::with_capacity(shares.len());
    let mut total: u128 = 0;
    for (share, attested) in shares {
        let id = share_id(share);
        if !seen.insert(id) {
            return Err(ShareError::Duplicate(id));
        }
        let h = attested.height;
        if h >= block_height || block_height - h > SHARE_WINDOW {
            return Err(ShareError::OutsideWindow { attested_height: h, block_height });
        }
        total = total.saturating_add(verify_share(share, attested, &pow)?);
    }
    Ok(total)
}

/// How the subsidy of a block with `n_shares` shares is split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Split {
    /// Subsidy part of the miner's coinbase output (fees come on top).
    pub miner: u64,
    /// Paid to each included share's payout script.
    pub per_attester: u64,
    /// Never issued (empty slots and rounding).
    pub unissued: u64,
}

pub fn split_subsidy(height: u64, n_shares: usize) -> Split {
    let subsidy = tokenomics::block_subsidy_sat(height);
    let pool = subsidy * WITNESS_POOL_BPS / 10_000;
    let slot = pool / MAX_SHARES_PER_BLOCK as u64;
    let bonus = slot * INCLUSION_BONUS_BPS / 10_000;
    let per_attester = slot - bonus;
    let n = n_shares.min(MAX_SHARES_PER_BLOCK) as u64;
    let miner = subsidy - pool + n * bonus;
    let unissued = subsidy - miner - n * per_attester;
    Split { miner, per_attester, unissued }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};

    fn block(height: u64, payload: &[u8]) -> Block {
        let cb = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: payload.to_vec(), sequence: 0 }],
            outputs: vec![TxOutput { value: 1, script_pubkey: vec![0xAB; 22] }],
            locktime: 0,
        };
        let header = BlockHeader {
            version: 1, parents: vec![[7; 32]], merkle_root: MerkleRoot([0; 32]),
            timestamp: 1, bits: 0x2000_FFFF, nonce: height,
        };
        Block { header, transactions: vec![cb], height, blue_score: height, shielded_transactions: vec![], powit: Default::default() }
    }

    /// Stub PoW: SHA3 of the input; deterministic and cheap.
    fn stub(pre: &[u8], nonce: u64) -> [u8; 32] {
        sha3(&[pre, &nonce.to_le_bytes()])
    }

    fn mine(b: &Block, payout: &[u8]) -> WitnessShare {
        let mut s = WitnessShare { attested: b.block_hash(), witness: [9; 20], payout: payout.to_vec(), bits: b.header.bits, nonce: 0,
                                   sha256d: None };
        while verify_share(&s, b, stub).is_err() {
            s.nonce += 1;
        }
        s
    }

    /// The serde (bincode) shape of a GnB share is the five fields it had
    /// before the SHA-256d fields existed.
    #[test]
    fn gnb_serde_shape_is_unchanged() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Before { attested: [u8; 32], witness: [u8; 20], payout: Vec<u8>, bits: u32, nonce: u64 }
        let s = WitnessShare { attested: [1; 32], witness: [2; 20], payout: vec![3; 25], bits: 0x1f00_ffff, nonce: 1 << 40,
                               sha256d: None };
        let old = Before { attested: s.attested, witness: s.witness, payout: s.payout.clone(), bits: s.bits, nonce: s.nonce };
        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&s, cfg).unwrap();
        assert_eq!(bytes, bincode::serde::encode_to_vec(&old, cfg).unwrap());
        let (back, n): (WitnessShare, usize) = bincode::serde::decode_from_slice(&bytes, cfg).unwrap();
        assert_eq!((back, n), (s, bytes.len()));
    }

    #[test]
    fn share_target_is_sixteen_times_easier() {
        let t = Target([0, 0, 0x01, 0x23, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let s = share_target(&t);
        assert_eq!(&s.0[..5], &[0, 0, 0x12, 0x34, 0x50]);
        assert_eq!(share_target(&Target([0xF0; 32])), Target::MAX);
    }

    #[test]
    fn mined_share_verifies_and_binds_the_data() {
        let b = block(100, &[1u8; 300]);
        let s = mine(&b, b"payout-a");
        assert!(verify_share(&s, &b, stub).unwrap() > 0);

        // Same header fields, different transaction bytes: the share must fail
        // (the attested hash still matches only if the header matches, so test
        // the data binding through the preimage directly).
        let other = block(100, &[2u8; 300]);
        assert_ne!(pow_preimage(&s, &b.witness_root(), &tx_stream(&b)),
                   pow_preimage(&s, &other.witness_root(), &tx_stream(&other)));

        // Stealing the share for another payout fails.
        let stolen = WitnessShare { payout: b"thief".to_vec(), ..s.clone() };
        assert_eq!(verify_share(&stolen, &b, stub), Err(ShareError::InsufficientWork));
    }

    #[test]
    fn each_nonce_samples_different_chunks() {
        let a = [9u8; 32];
        let distinct: std::collections::HashSet<_> =
            (0..64).map(|n| sample_indices(&a, b"p", n, 1_000)).collect();
        assert_eq!(distinct.len(), 64);
        assert!(sample_indices(&a, b"p", 5, 1).iter().all(|&i| i == 0));
    }

    #[test]
    fn wrong_block_bits_and_payout_are_refused() {
        let b = block(100, &[1u8; 300]);
        let s = mine(&b, b"payout-a");
        assert_eq!(verify_share(&s, &block(101, &[1u8; 300]), stub), Err(ShareError::WrongAttestedBlock));
        assert_eq!(verify_share(&WitnessShare { bits: 0x1f00_ffff, ..s.clone() }, &b, stub), Err(ShareError::WrongBits));
        let long = WitnessShare { payout: vec![0; MAX_PAYOUT_SCRIPT + 1], ..s };
        assert_eq!(verify_share(&long, &b, stub), Err(ShareError::PayoutTooLong));
    }

    #[test]
    fn block_level_rules() {
        let b = block(100, &[1u8; 300]);
        let s1 = mine(&b, b"a");
        let s2 = mine(&b, b"b");
        assert!(verify_block_shares(101, &[(&s1, &b), (&s2, &b)], stub).is_ok());
        assert!(matches!(verify_block_shares(101, &[(&s1, &b), (&s1, &b)], stub), Err(ShareError::Duplicate(_))));
        assert!(matches!(verify_block_shares(100, &[(&s1, &b)], stub), Err(ShareError::OutsideWindow { .. })));
        assert!(matches!(verify_block_shares(100 + SHARE_WINDOW + 1, &[(&s1, &b)], stub),
                         Err(ShareError::OutsideWindow { .. })));
        assert!(verify_block_shares(100 + SHARE_WINDOW, &[(&s1, &b)], stub).is_ok());
        let many: Vec<_> = (0..=MAX_SHARES_PER_BLOCK).map(|_| (&s1, &b)).collect();
        assert_eq!(verify_block_shares(101, &many, stub), Err(ShareError::TooMany(MAX_SHARES_PER_BLOCK + 1)));
    }

    #[test]
    fn split_never_exceeds_subsidy_and_rewards_inclusion() {
        for h in [1, 5_000, tokenomics::HALVING_INTERVAL, tokenomics::LAST_SUBSIDY_HEIGHT_EXCLUSIVE - 1] {
            let subsidy = tokenomics::block_subsidy_sat(h);
            let mut last_miner = 0;
            for n in 0..=MAX_SHARES_PER_BLOCK {
                let s = split_subsidy(h, n);
                assert_eq!(s.miner + n as u64 * s.per_attester + s.unissued, subsidy, "h={h} n={n}");
                assert!(s.miner >= last_miner, "including a share never lowers the miner's pay");
                last_miner = s.miner;
            }
        }
        let full = split_subsidy(1, MAX_SHARES_PER_BLOCK);
        let none = split_subsidy(1, 0);
        // Initial subsidy 1.07020547 GNB: 20% pool, 16 slots.
        assert_eq!(none.miner, tokenomics::INITIAL_SUBSIDY_SAT - tokenomics::INITIAL_SUBSIDY_SAT * 2 / 10);
        assert!(full.per_attester > 0 && full.miner > none.miner);
        assert!(full.unissued < 100, "rounding only");
    }
}
