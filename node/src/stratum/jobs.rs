//! Stratum jobs: the header jobs of `getblocktemplate`, shared by the V1
//! and V2 servers.
//!
//! A [`Job`] is exactly `mining::sha256d::header_job` (the RPC's
//! `getblocktemplate [{"header_job": …}]`) on a template of the shared work
//! feed ([`super::work`]), for one payout script and one extranonce. So a
//! V1 notify, a V2 `NewMiningJob` and an RPC header job built from the same
//! template, script, extranonce and time carry byte-identical 80-byte
//! headers:
//!
//! ```text
//! u32le version ‖ parents_commitment ‖ merkle_root ‖ u32le time ‖ u32le bits ‖ u32le nonce
//! ```
//!
//! (docs/DESIGN-obenblock.md §4.1). The Merkle root is ObenBlock's body root
//! (docs/OBENBLOCK-MINING.md §3.3), not Bitcoin's transaction tree:
//!
//! * V2 standard channels receive it ready-made (`NewMiningJob.merkle_root`):
//!   the server computes it for the channel's extranonce;
//! * V1 sends `coinb1`, `coinb2` and the tagged-tree branch; a V1 client
//!   computes the root with ObenBlock's rule (the `obb-merkle-root`
//!   extension of `mining.configure` tells it the rule and the two section
//!   roots). Firmware that folds the branch with Bitcoin's SHA-256d tree
//!   computes a header no ObenBlock node accepts (docs/STRATUM.md).
//!
//! [`Job::solve`] rebuilds the block of a share and checks, before anything
//! is submitted, that the root it derived from the extranonce is the block's
//! own body root and that the header it hashed is the header the block
//! serializes (`BlockHeader::sha256d_pow_bytes`, the bytes the node's proof
//! check hashes). A share that passes both is judged by the same acceptance
//! path as `submitblock`.

use std::sync::Arc;

use crate::core::{self, pow_scheme::Sha256dParams, Block, MerkleRoot};
use crate::mining::sha256d::{self as job_rpc, EXTRANONCE_LEN};
use crate::template::BlockTemplate;
use gnb_smh::difficulty::{bits_to_target, Target};
use gnb_smh::sha256d;

/// Bytes of the extranonce (`extranonce1 ‖ extranonce2` in V1, the channel's
/// extranonce prefix in V2).
pub const EXTRANONCE_BYTES: usize = EXTRANONCE_LEN;

/// V1 `extranonce1` (per session) and `extranonce2` (rolled by the miner).
pub const EXTRANONCE1_BYTES: usize = 4;
pub const EXTRANONCE2_BYTES: usize = EXTRANONCE_BYTES - EXTRANONCE1_BYTES;

/// One job: a candidate block paying one script, with its coinbase split
/// around the extranonce.
#[derive(Clone, Debug)]
pub struct Job {
    /// The shared template the job was built from.
    pub template: Arc<BlockTemplate>,
    /// The candidate block (nonce 0) for [`Self::extranonce`].
    pub block: Block,
    /// Its 80-byte header (nonce 0).
    pub header: [u8; sha256d::POW_HEADER_LEN],
    /// Coinbase wire bytes before / after the extranonce.
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    /// The extranonce the candidate block carries.
    pub extranonce: [u8; EXTRANONCE_BYTES],
    /// Header fields of the job (the miner rolls nonce, the BIP 320 bits of
    /// `version`, and `time` inside the job's stall-relief step).
    pub version: u32,
    pub time: u32,
    pub bits: u32,
    /// Header bytes 4..36: `parents_commitment`.
    pub parents_commitment: [u8; 32],
    /// Siblings from the coinbase leaf to the transaction root (tagged tree).
    pub merkle_branch: Vec<[u8; 32]>,
    /// The two other inputs of the body root.
    pub shielded_root: [u8; 32],
    pub powit_root: [u8; 32],
}

/// Why a share could not be turned into a block of its job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolveError {
    /// The version changes bits outside the BIP 320 mask.
    BadVersion(u32),
    /// The time is before the template's latest parent time.
    TimeTooOld { time: u32, min: u64 },
    /// The time is more than `MAX_FUTURE_SECS` ahead of this node's clock.
    TimeTooNew { time: u32, max: u64 },
    /// At this time the block needs other bits than the job's (the share
    /// rolled `time` into another stall-relief step): take the newer job.
    BitsChanged { job_bits: u32, bits_at_time: u32 },
    /// Internal: the root or the header the server derived disagrees with
    /// the block it would submit (never expected; refused, not submitted).
    Internal(String),
}

impl std::fmt::Display for SolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadVersion(v) => write!(f, "version {v:#010x} changes bits outside the BIP 320 mask 0x1fffe000"),
            Self::TimeTooOld { time, min } => write!(f, "time {time} is before the parents' time {min}"),
            Self::TimeTooNew { time, max } => write!(f, "time {time} is more than 600 s ahead (max {max})"),
            Self::BitsChanged { job_bits, bits_at_time } => write!(
                f, "at this time the block needs bits {bits_at_time:08x}, the job has {job_bits:08x} \
                    (stall-relief step changed): take the new job"),
            Self::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

/// A share turned into its block.
#[derive(Clone, Debug)]
pub struct Solved {
    pub block: Block,
    /// The 80-byte header the miner hashed (= `block.header.sha256d_pow_bytes()`).
    pub header: [u8; sha256d::POW_HEADER_LEN],
    /// `SHA-256d(header)`, the block id.
    pub id: [u8; 32],
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The 80-byte header of the given fields.
pub fn header_bytes(version: u32, parents_commitment: &[u8; 32], merkle_root: &[u8; 32], time: u32, bits: u32, nonce: u32)
    -> [u8; sha256d::POW_HEADER_LEN]
{
    let mut h = [0u8; sha256d::POW_HEADER_LEN];
    h[0..4].copy_from_slice(&version.to_le_bytes());
    h[4..36].copy_from_slice(parents_commitment);
    h[36..68].copy_from_slice(merkle_root);
    h[68..72].copy_from_slice(&time.to_le_bytes());
    h[72..76].copy_from_slice(&bits.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

/// The bits a block of `template` stamped `time` must carry: the template's
/// ASERT bits relaxed by the stall relief (`core::liveness::relieve_at`, as
/// `template::assemble_block` and the validator compute them).
pub fn bits_at(template: &BlockTemplate, time: u64) -> u32 {
    core::liveness::relieve_at(template.bits, template.parent_timestamp, template.height,
                               time.max(template.parent_timestamp), template.activation_height,
                               core::liveness::liveness_activation_height())
}

impl Job {
    /// The header job of `template` paying `script_pubkey` with `extranonce`,
    /// stamped `now` (at least the parents' time): exactly
    /// `mining::sha256d::header_job`.
    pub fn build(
        template: Arc<BlockTemplate>,
        params: &Sha256dParams,
        script_pubkey: &[u8],
        extranonce: [u8; EXTRANONCE_BYTES],
        now: u64,
    ) -> Result<Job, String> {
        let hj = job_rpc::header_job(&template, params, script_pubkey, extranonce, now)?;
        let h = &hj.block.header;
        let time = u32::try_from(h.timestamp).map_err(|_| "job time does not fit u32".to_string())?;
        let mut parents_commitment = [0u8; 32];
        parents_commitment.copy_from_slice(&hj.header[4..36]);
        Ok(Job {
            version: h.version,
            time,
            bits: h.bits,
            parents_commitment,
            merkle_branch: template.coinbase_merkle_branch(),
            shielded_root: job_rpc::empty_shielded_root(),
            powit_root: job_rpc::powit_root(&template),
            header: hj.header,
            coinb1: hj.coinb1,
            coinb2: hj.coinb2,
            extranonce: hj.extranonce,
            block: hj.block,
            template,
        })
    }

    /// The consensus target of the job's bits.
    pub fn block_target(&self) -> Target {
        bits_to_target(self.bits)
    }

    /// Coinbase wire bytes for `extranonce` (its txid is their SHA-256d).
    pub fn coinbase_bytes(&self, extranonce: &[u8; EXTRANONCE_BYTES]) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.coinb1.len() + EXTRANONCE_BYTES + self.coinb2.len());
        b.extend_from_slice(&self.coinb1);
        b.extend_from_slice(extranonce);
        b.extend_from_slice(&self.coinb2);
        b
    }

    /// The header Merkle root (ObenBlock's body root) for `extranonce`.
    pub fn merkle_root_for(&self, extranonce: &[u8; EXTRANONCE_BYTES]) -> Result<[u8; 32], String> {
        let txid = sha256d::sha256d(&self.coinbase_bytes(extranonce));
        job_rpc::header_merkle_root(&self.template, &txid).map(|r| r.0)
    }

    /// The Merkle root a miner computes when it folds the branch with
    /// Bitcoin's SHA-256d tree instead (diagnostics only: a share that meets
    /// its target only with this root comes from Bitcoin-only firmware).
    pub fn bitcoin_tree_root_for(&self, extranonce: &[u8; EXTRANONCE_BYTES]) -> [u8; 32] {
        let mut h = sha256d::sha256d(&self.coinbase_bytes(extranonce));
        for s in &self.merkle_branch {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&h);
            buf[32..].copy_from_slice(s);
            h = sha256d::sha256d(&buf);
        }
        h
    }

    /// The 80-byte header of a share of this job.
    pub fn share_header(&self, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, time: u32, nonce: u32)
        -> Result<[u8; sha256d::POW_HEADER_LEN], String>
    {
        let root = self.merkle_root_for(extranonce)?;
        Ok(header_bytes(version, &self.parents_commitment, &root, time, self.bits, nonce))
    }

    /// Turn a share (`extranonce`, rolled `version`, `time`, `nonce`) into the
    /// block it mined, checking the header rules a share can break
    /// (BIP 320 version, time window, stall-relief step) and the
    /// byte-identity of the root and the header with the block. The proof
    /// itself is the caller's: compare [`Solved::id`] with a target.
    pub fn solve(&self, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, time: u32, nonce: u32)
        -> Result<Solved, SolveError>
    {
        if !sha256d::version_ok(version, self.version & !sha256d::BIP320_VERSION_MASK) {
            return Err(SolveError::BadVersion(version));
        }
        let min = self.template.parent_timestamp;
        if (time as u64) < min {
            return Err(SolveError::TimeTooOld { time, min });
        }
        let max = now_secs().saturating_add(core::MAX_FUTURE_SECS);
        if time as u64 > max {
            return Err(SolveError::TimeTooNew { time, max });
        }
        let bits_at_time = bits_at(&self.template, time as u64);
        if bits_at_time != self.bits {
            return Err(SolveError::BitsChanged { job_bits: self.bits, bits_at_time });
        }
        let root = self.merkle_root_for(extranonce).map_err(SolveError::Internal)?;
        let header = header_bytes(version, &self.parents_commitment, &root, time, self.bits, nonce);

        let mut block = self.block.clone();
        {
            let ss = &mut block.transactions[0].inputs[0].script_sig;
            let n = ss.len();
            if n < EXTRANONCE_BYTES || ss[n - EXTRANONCE_BYTES..] != self.extranonce {
                return Err(SolveError::Internal("job coinbase does not end in its extranonce".into()));
            }
            ss[n - EXTRANONCE_BYTES..].copy_from_slice(extranonce);
        }
        block.header.version = version;
        block.header.timestamp = time as u64;
        block.header.nonce = nonce as u64;
        block.header.merkle_root = MerkleRoot(root);
        // Byte identity: the root from the extranonce is the block's own body
        // root, and the header hashed is the one the block serializes.
        let body_root = block.body_merkle_root_at(self.template.activation_height);
        if body_root.0 != root {
            return Err(SolveError::Internal("derived Merkle root differs from the block's body root".into()));
        }
        let own = block.header.sha256d_pow_bytes()
            .map_err(|e| SolveError::Internal(format!("header does not fit 80 bytes: {e}")))?;
        if own != header {
            return Err(SolveError::Internal("share header differs from the block's header bytes".into()));
        }
        let id = sha256d::block_id(&header);
        Ok(Solved { block, header, id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bytes_follow_the_design_layout() {
        let h = header_bytes(0x2000_6000, &[0xAA; 32], &[0xBB; 32], 1_800_000_000, 0x1D00_FFFF, 7);
        assert_eq!(&h[0..4], &0x2000_6000u32.to_le_bytes());
        assert_eq!(&h[4..36], &[0xAA; 32]);
        assert_eq!(&h[36..68], &[0xBB; 32]);
        assert_eq!(&h[68..72], &1_800_000_000u32.to_le_bytes());
        assert_eq!(&h[72..76], &0x1D00_FFFFu32.to_le_bytes());
        assert_eq!(&h[76..80], &7u32.to_le_bytes());
        let p = sha256d::PowHeader::from_bytes(&h);
        assert_eq!(p.to_bytes(), h, "the reference PowHeader reads the same fields");
    }

    #[test]
    fn extranonce_split_is_four_plus_four() {
        assert_eq!(EXTRANONCE1_BYTES + EXTRANONCE2_BYTES, EXTRANONCE_BYTES);
        assert_eq!(EXTRANONCE_BYTES, 8);
    }
}
