//! Witness shares on SHA-256d (ObenBlock, docs/DESIGN-obenblock.md §6.1).
//!
//! The share proof is an 80-byte header in Bitcoin's layout, so an unmodified
//! SHA-256d ASIC mines it. The custody sampling moves from every nonce to
//! every *job*: a job fixes eight pseudo-random 64-byte chunks of the attested
//! block's transaction stream (`super::tx_stream`), and the header commits to
//! them. Within a job an ASIC rolls the 32-bit nonce and the BIP 320 version
//! bits (2^48 attempts); every further job needs eight fresh chunks, so the
//! job server must hold the block.
//!
//! ```text
//! idx_k          = u64le(SHA-256d("OBB-WSHARE-v1/idx" ‖ attested ‖ SHA-256d(payout)
//!                                 ‖ u64le(job_nonce) ‖ u8(k))[0..8]) mod n_chunks
//! job_commitment = SHA-256d("OBB-WSHARE-v1/job" ‖ attested ‖ witness ‖ SHA-256d(payout)
//!                           ‖ u64le(job_nonce) ‖ chunk[idx_0] ‖ … ‖ chunk[idx_7])
//! share_header   = u32le(version) ‖ attested ‖ job_commitment ‖ u32le(time)
//!                  ‖ u32le(bits) ‖ u32le(nonce)                                    80 bytes
//! valid         <=> le256(SHA-256d(share_header)) <= target(bits) × SHARE_TARGET_FACTOR
//! work           = floor(2^256 / (share_target + 1))                (Bitcoin's work)
//! ```
//!
//! `job_nonce` is the share's `nonce` field; `version`, `time` and the header
//! nonce are [`Sha256dShareFields`]. The executable reference is
//! `reference/obb_shares.py`; `reference/obb_shares_vectors.json` pins it and
//! `crates/gnb-crypto/tests/obb_share_vectors.rs` checks this module and the
//! dispatch in `core` against it.
//!
//! Rules this module adds where the design is silent (conservative):
//! * the share header's `time` must equal the attested block's timestamp.
//!   A free `time` would add 2^32 attempts to every job, so one job (one set
//!   of eight chunks) could feed an ASIC for its whole life and the
//!   per-job custody of §6.1 would be void;
//! * the share header's `version` follows BIP 320 against the chain's block
//!   version (the rolling ASIC firmware performs), as block headers do;
//! * the share id is a tagged SHA-256d over every field
//!   (`"OBB-WSHARE-v1/id"`), computable before the proof is checked, as on GnB.

use gnb_smh::difficulty::{bits_to_target, Target};
use gnb_smh::sha256d::{self as pow, PowHeader, POW_HEADER_LEN};

use super::{chunk, n_chunks, share_target, tx_stream, Sha256dShareFields, ShareError, WitnessShare,
            MAX_PAYOUT_SCRIPT, SAMPLE_CHUNKS};
use crate::core::pow_scheme::Sha256dParams;
use crate::core::Block;

/// Tag of the per-job chunk selection.
pub const DS_IDX: &[u8] = b"OBB-WSHARE-v1/idx";
/// Tag of the job commitment.
pub const DS_JOB: &[u8] = b"OBB-WSHARE-v1/job";
/// Tag of the share id.
pub const DS_ID: &[u8] = b"OBB-WSHARE-v1/id";

/// `SHA-256d(payout)`, the payout's binding in every share hash.
pub fn payout_hash(payout: &[u8]) -> [u8; 32] {
    pow::sha256d(payout)
}

/// Chunk indices a job selects, out of `n` chunks (`n >= 1`).
pub fn sample_indices(attested: &[u8; 32], payout: &[u8], job_nonce: u64, n: u64) -> [u64; SAMPLE_CHUNKS] {
    let ph = payout_hash(payout);
    let mut out = [0u64; SAMPLE_CHUNKS];
    let mut pre = Vec::with_capacity(DS_IDX.len() + 32 + 32 + 8 + 1);
    for (k, slot) in out.iter_mut().enumerate() {
        pre.clear();
        pre.extend_from_slice(DS_IDX);
        pre.extend_from_slice(attested);
        pre.extend_from_slice(&ph);
        pre.extend_from_slice(&job_nonce.to_le_bytes());
        pre.push(k as u8);
        let d = pow::sha256d(&pre);
        *slot = u64::from_le_bytes(d[..8].try_into().expect("8 bytes")) % n;
    }
    out
}

/// The job commitment over the attested block's transaction `stream`.
pub fn job_commitment(attested: &[u8; 32], witness: &[u8; 20], payout: &[u8], job_nonce: u64, stream: &[u8])
    -> [u8; 32]
{
    let idx = sample_indices(attested, payout, job_nonce, n_chunks(stream));
    let mut b = Vec::with_capacity(DS_JOB.len() + 32 + 20 + 32 + 8 + SAMPLE_CHUNKS * super::CHUNK_BYTES);
    b.extend_from_slice(DS_JOB);
    b.extend_from_slice(attested);
    b.extend_from_slice(witness);
    b.extend_from_slice(&payout_hash(payout));
    b.extend_from_slice(&job_nonce.to_le_bytes());
    for i in idx {
        b.extend_from_slice(&chunk(stream, i));
    }
    pow::sha256d(&b)
}

/// The 80-byte share header: Bitcoin's layout with the attested block id in
/// place of `hashPrevBlock` and the job commitment in place of the Merkle root.
pub fn share_header(version: u32, attested: &[u8; 32], job_commitment: &[u8; 32], time: u32, bits: u32, nonce: u32)
    -> [u8; POW_HEADER_LEN]
{
    PowHeader { version, parents_commitment: *attested, merkle_root: *job_commitment, time, bits, nonce }.to_bytes()
}

/// Unique id of a SHA-256d share: `SHA-256d("OBB-WSHARE-v1/id" ‖ attested ‖
/// witness ‖ SHA-256d(payout) ‖ u32le(bits) ‖ u64le(job_nonce) ‖ u32le(version)
/// ‖ u32le(time) ‖ u32le(nonce))`.
pub fn share_id(share: &WitnessShare, f: &Sha256dShareFields) -> [u8; 32] {
    let mut b = Vec::with_capacity(DS_ID.len() + 32 + 20 + 32 + 4 + 8 + 12);
    b.extend_from_slice(DS_ID);
    b.extend_from_slice(&share.attested);
    b.extend_from_slice(&share.witness);
    b.extend_from_slice(&payout_hash(&share.payout));
    b.extend_from_slice(&share.bits.to_le_bytes());
    b.extend_from_slice(&share.nonce.to_le_bytes());
    b.extend_from_slice(&f.version.to_le_bytes());
    b.extend_from_slice(&f.time.to_le_bytes());
    b.extend_from_slice(&f.nonce.to_le_bytes());
    pow::sha256d(&b)
}

/// What a share is checked against: the attested block's id, `bits`,
/// timestamp and transaction stream.
#[derive(Clone, Copy, Debug)]
pub struct AttestedParts<'a> {
    pub id: [u8; 32],
    pub bits: u32,
    pub timestamp: u64,
    pub stream: &'a [u8],
}

/// Verify a SHA-256d share against the parts of the block it attests, cheap
/// checks first (one SHA-256d of the job and one of the header at the end).
/// Returns the share's work: Bitcoin's work of the share target.
pub fn verify_share_parts(share: &WitnessShare, attested: &AttestedParts<'_>, params: &Sha256dParams)
    -> Result<u128, ShareError>
{
    if share.payout.len() > MAX_PAYOUT_SCRIPT {
        return Err(ShareError::PayoutTooLong);
    }
    let f = share.sha256d.ok_or(ShareError::WrongScheme)?;
    if share.attested != attested.id {
        return Err(ShareError::WrongAttestedBlock);
    }
    if share.bits != attested.bits {
        return Err(ShareError::WrongBits);
    }
    if !pow::version_ok(f.version, params.block_version) {
        return Err(ShareError::Version);
    }
    if u64::from(f.time) != attested.timestamp {
        return Err(ShareError::WrongTime);
    }
    let block_target = bits_to_target(share.bits);
    if block_target.is_zero() {
        return Err(ShareError::BadTarget);
    }
    let target = share_target(&block_target);
    let job = job_commitment(&share.attested, &share.witness, &share.payout, share.nonce, attested.stream);
    let id = pow::sha256d(&share_header(f.version, &share.attested, &job, f.time, share.bits, f.nonce));
    if !pow::meets_target(&id, &target) {
        return Err(ShareError::InsufficientWork);
    }
    Ok(pow::work(&target))
}

/// Verify a SHA-256d share against the block it attests (its SHA-256d id,
/// whatever the process scheme). Returns the share's work.
pub fn verify_share(share: &WitnessShare, attested: &Block, params: &Sha256dParams) -> Result<u128, ShareError> {
    // Cheap refusals before the block's stream is assembled.
    if share.payout.len() > MAX_PAYOUT_SCRIPT {
        return Err(ShareError::PayoutTooLong);
    }
    if share.sha256d.is_none() {
        return Err(ShareError::WrongScheme);
    }
    let id = attested.header.sha256d_block_id();
    if share.attested != id {
        return Err(ShareError::WrongAttestedBlock);
    }
    let stream = tx_stream(attested);
    verify_share_parts(share, &AttestedParts { id, bits: attested.header.bits, timestamp: attested.header.timestamp,
                                               stream: &stream }, params)
}

/// One mining job: everything an ASIC needs (the header template) and what
/// the job server keeps to turn a found nonce into a share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareJob {
    pub attested: [u8; 32],
    pub witness: [u8; 20],
    pub payout: Vec<u8>,
    pub job_nonce: u64,
    pub job_commitment: [u8; 32],
    /// The chain's block version (BIP 320 bits roll on top of it).
    pub version: u32,
    /// The attested block's timestamp (fixed for the job).
    pub time: u32,
    pub bits: u32,
    /// The share target: `target(bits) × SHARE_TARGET_FACTOR`.
    pub target: Target,
}

impl ShareJob {
    /// A job for a share attesting `attested` (`None` if its timestamp does
    /// not fit u32, so no share for it can be valid).
    pub fn new(attested: &Block, witness: [u8; 20], payout: &[u8], job_nonce: u64, params: &Sha256dParams)
        -> Option<ShareJob>
    {
        Self::from_stream(attested, &tx_stream(attested), witness, payout, job_nonce, params)
    }

    /// [`Self::new`] with the attested block's stream precomputed (one per
    /// attested block, reused across jobs).
    pub fn from_stream(attested: &Block, stream: &[u8], witness: [u8; 20], payout: &[u8], job_nonce: u64,
                       params: &Sha256dParams) -> Option<ShareJob>
    {
        let time = u32::try_from(attested.header.timestamp).ok()?;
        let id = attested.header.sha256d_block_id();
        let bits = attested.header.bits;
        Some(ShareJob {
            attested: id,
            witness,
            payout: payout.to_vec(),
            job_nonce,
            job_commitment: job_commitment(&id, &witness, payout, job_nonce, stream),
            version: params.block_version,
            time,
            bits,
            target: share_target(&bits_to_target(bits)),
        })
    }

    /// The 80-byte header for one attempt (`version` with BIP 320 bits rolled).
    pub fn header(&self, version: u32, nonce: u32) -> [u8; POW_HEADER_LEN] {
        share_header(version, &self.attested, &self.job_commitment, self.time, self.bits, nonce)
    }

    /// Whether one attempt meets the share target.
    pub fn meets(&self, version: u32, nonce: u32) -> bool {
        pow::meets_target(&pow::sha256d(&self.header(version, nonce)), &self.target)
    }

    /// The share an attempt that [`Self::meets`] the target makes.
    pub fn share(&self, version: u32, nonce: u32) -> WitnessShare {
        WitnessShare {
            attested: self.attested,
            witness: self.witness,
            payout: self.payout.clone(),
            bits: self.bits,
            nonce: self.job_nonce,
            sha256d: Some(Sha256dShareFields { version, time: self.time, nonce }),
        }
    }

    /// CPU search over header nonces `start ..= start + attempts - 1`
    /// (wrapping in u32) at the job's base version; `stop` is polled every
    /// 2^16 attempts. For regtest and tests: mainnet shares need an ASIC.
    pub fn mine_cpu(&self, start: u32, attempts: u64, stop: &std::sync::atomic::AtomicBool) -> Option<WitnessShare> {
        let mut hdr = self.header(self.version, start);
        for i in 0..attempts.min(1 << 32) {
            if i & 0xFFFF == 0 && stop.load(std::sync::atomic::Ordering::Relaxed) {
                return None;
            }
            let nonce = start.wrapping_add(i as u32);
            hdr[76..80].copy_from_slice(&nonce.to_le_bytes());
            if pow::meets_target(&pow::sha256d(&hdr), &self.target) {
                return Some(self.share(self.version, nonce));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pow_scheme::{OBB_BLOCK_VERSION, OBB_POW_LIMIT_BITS};
    use crate::core::{BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
    use std::sync::atomic::AtomicBool;

    /// Block target 2^248: a share (target 2^252) succeeds once in 16 hashes.
    const EASY_BITS: u32 = 0x2001_0000;

    fn params() -> Sha256dParams {
        Sha256dParams::obenblock_regtest(1_800_000_000)
    }

    fn block(payload: &[u8], bits: u32) -> Block {
        let cb = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: payload.to_vec(), sequence: 0 }],
            outputs: vec![TxOutput { value: 1, script_pubkey: vec![0xAB; 22] }],
            locktime: 0,
        };
        let header = BlockHeader {
            version: OBB_BLOCK_VERSION, parents: vec![[7; 32]], merkle_root: MerkleRoot([3; 32]),
            timestamp: 1_800_000_123, bits, nonce: 5,
        };
        Block { header, transactions: vec![cb], height: 100, blue_score: 100, shielded_transactions: vec![],
                powit: Default::default() }
    }

    fn mine(b: &Block, payout: &[u8], job_nonce: u64) -> WitnessShare {
        let job = ShareJob::new(b, [9; 20], payout, job_nonce, &params()).unwrap();
        job.mine_cpu(0, 1 << 16, &AtomicBool::new(false)).expect("1/16 per attempt")
    }

    #[test]
    fn mined_share_verifies_with_bitcoin_work() {
        let b = block(&[1u8; 300], EASY_BITS);
        let s = mine(&b, b"payout-a", 7);
        let w = verify_share(&s, &b, &params()).unwrap();
        assert_eq!(w, pow::work(&share_target(&bits_to_target(EASY_BITS))));
        assert_eq!(w, 15, "floor(2^256 / (2^252 + 1))");
        assert_eq!(s.nonce, 7, "the share's nonce field is the job nonce");
        // The wire round trip carries the header fields under SHA-256d only.
        let wire = s.to_wire_bytes();
        let back = WitnessShare::read_wire_in(&mut std::io::Cursor::new(&wire[..]), true).unwrap();
        assert_eq!(back, s);
        let mut gnb = std::io::Cursor::new(&wire[..]);
        assert_eq!(WitnessShare::read_wire_in(&mut gnb, false).unwrap().sha256d, None);
        assert_eq!(gnb.position() as usize, wire.len() - 12, "GnB's decoder leaves the 12 header bytes");
    }

    #[test]
    fn the_job_binds_the_data_the_witness_and_the_payout() {
        let b = block(&[1u8; 300], EASY_BITS);
        let id = b.header.sha256d_block_id();
        let st = tx_stream(&b);
        let other = tx_stream(&block(&[2u8; 300], EASY_BITS));
        let j = job_commitment(&id, &[9; 20], b"p", 1, &st);
        assert_ne!(j, job_commitment(&id, &[9; 20], b"p", 1, &other), "chunk bytes are committed");
        assert_ne!(j, job_commitment(&id, &[8; 20], b"p", 1, &st), "witness is committed");
        assert_ne!(j, job_commitment(&id, &[9; 20], b"q", 1, &st), "payout is committed");
        assert_ne!(j, job_commitment(&id, &[9; 20], b"p", 2, &st), "job nonce is committed");

        // A mined share cannot be re-pointed or have its job swapped. (The
        // re-pointed share fails unless the new header also happens to meet
        // the 1/16 target, so grind a payout on which it does not.)
        let s = mine(&b, b"payout-a", 7);
        let stolen = (0u8..).map(|i| WitnessShare { payout: vec![b't', i], ..s.clone() })
            .find(|t| verify_share(t, &b, &params()).is_err()).unwrap();
        assert_eq!(verify_share(&stolen, &b, &params()), Err(ShareError::InsufficientWork));
    }

    #[test]
    fn each_job_samples_different_chunks() {
        let a = [9u8; 32];
        let distinct: std::collections::HashSet<_> = (0..64).map(|n| sample_indices(&a, b"p", n, 1_000)).collect();
        assert_eq!(distinct.len(), 64);
        assert!(sample_indices(&a, b"p", 5, 1).iter().all(|&i| i == 0));
        // A different payout selects different chunks for the same job nonce.
        assert_ne!(sample_indices(&a, b"p", 5, 1_000), sample_indices(&a, b"q", 5, 1_000));
    }

    #[test]
    fn refusals_in_order() {
        let b = block(&[1u8; 300], EASY_BITS);
        let p = params();
        let s = mine(&b, b"payout-a", 7);
        let f = s.sha256d.unwrap();
        let with = |g: Sha256dShareFields| WitnessShare { sha256d: Some(g), ..s.clone() };

        assert_eq!(verify_share(&WitnessShare { sha256d: None, ..s.clone() }, &b, &p), Err(ShareError::WrongScheme));
        assert_eq!(verify_share(&WitnessShare { payout: vec![0; MAX_PAYOUT_SCRIPT + 1], ..s.clone() }, &b, &p),
                   Err(ShareError::PayoutTooLong));
        let mut moved = b.clone();
        moved.header.nonce += 1;
        assert_eq!(verify_share(&s, &moved, &p), Err(ShareError::WrongAttestedBlock));
        assert_eq!(verify_share(&WitnessShare { bits: OBB_POW_LIMIT_BITS, ..s.clone() }, &b, &p),
                   Err(ShareError::WrongBits));
        assert_eq!(verify_share(&with(Sha256dShareFields { version: f.version | 0x1000, ..f }), &b, &p),
                   Err(ShareError::Version));
        assert_eq!(verify_share(&with(Sha256dShareFields { time: f.time + 1, ..f }), &b, &p),
                   Err(ShareError::WrongTime));
        // BIP 320 rolling is allowed: a rolled version is judged on its work.
        let rolled = (0u32..).map(|v| with(Sha256dShareFields { version: f.version | (v << 13), ..f }))
            .skip(1).find(|t| verify_share(t, &b, &p).is_ok());
        assert!(rolled.is_some());
        // A u64 timestamp that does not fit u32 has no job.
        let mut late = b.clone();
        late.header.timestamp = u64::from(u32::MAX) + 1;
        assert!(ShareJob::new(&late, [9; 20], b"p", 0, &p).is_none());
    }

    #[test]
    fn ids_cover_every_field() {
        let b = block(&[1u8; 64], EASY_BITS);
        let s = mine(&b, b"payout-a", 7);
        let f = s.sha256d.unwrap();
        let id = super::super::share_id(&s);
        assert_eq!(id, share_id(&s, &f));
        let variants = [
            WitnessShare { attested: [1; 32], ..s.clone() },
            WitnessShare { witness: [1; 20], ..s.clone() },
            WitnessShare { payout: b"x".to_vec(), ..s.clone() },
            WitnessShare { bits: 1, ..s.clone() },
            WitnessShare { nonce: 8, ..s.clone() },
            WitnessShare { sha256d: Some(Sha256dShareFields { version: f.version ^ 0x2000, ..f }), ..s.clone() },
            WitnessShare { sha256d: Some(Sha256dShareFields { time: f.time ^ 1, ..f }), ..s.clone() },
            WitnessShare { sha256d: Some(Sha256dShareFields { nonce: f.nonce ^ 1, ..f }), ..s.clone() },
            WitnessShare { sha256d: None, ..s.clone() },
        ];
        let ids: std::collections::HashSet<_> = variants.iter().map(super::super::share_id).chain([id]).collect();
        assert_eq!(ids.len(), variants.len() + 1);
    }

    #[test]
    fn gnb_path_refuses_a_sha256d_share() {
        // The lib test process never sets the scheme: verify_share is GnB's.
        let b = block(&[1u8; 64], EASY_BITS);
        let s = mine(&b, b"payout-a", 7);
        let s = WitnessShare { attested: b.block_hash(), ..s };
        assert_eq!(super::super::verify_share(&s, &b, |_, _| [0; 32]), Err(ShareError::WrongScheme));
    }

    #[test]
    fn empty_stream_samples_one_zero_chunk() {
        let a = [5u8; 32];
        let j = job_commitment(&a, &[1; 20], b"p", 3, &[]);
        let mut pre = DS_JOB.to_vec();
        pre.extend_from_slice(&a);
        pre.extend_from_slice(&[1; 20]);
        pre.extend_from_slice(&payout_hash(b"p"));
        pre.extend_from_slice(&3u64.to_le_bytes());
        pre.extend_from_slice(&[0u8; SAMPLE_CHUNKS * super::super::CHUNK_BYTES]);
        assert_eq!(j, pow::sha256d(&pre));
    }
}
