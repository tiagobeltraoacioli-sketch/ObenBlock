//! From an SV2 share to its block.
//!
//! `SubmitSharesStandard` carries `(job_id, nonce, ntime, version)`; the
//! extranonce is the channel's. The block is rebuilt from the cached job by
//! [`Job::solve`] (the same code as V1), after checking that the root it
//! derives is the root this channel was sent: if the cache and the miner's
//! view of the job ever drifted, the share is refused, never submitted.
//! Ported from the legacy Bloch server (genesis3-node
//! `src/stratum_v2/block_reconstruct.rs`), which ignored the rolled version;
//! here BIP 320 rolling is honoured for both the proof and the block.

use crate::stratum::jobs::{SolveError, Solved, EXTRANONCE_BYTES};

use super::channel::Sv2CachedJob;

/// Why a share has no block.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockReconstructError {
    #[error("the root for this extranonce differs from the root sent in NewMiningJob (cache drift)")]
    MerkleRootMismatch { cached: [u8; 32], reconstructed: [u8; 32] },
    #[error("{0}")]
    Solve(SolveError),
}

/// Rebuild the block of a share of `cached` with `extranonce`.
pub fn reconstruct_block_for_sv2_submit(
    cached: &Sv2CachedJob, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, ntime: u32, nonce: u32,
) -> Result<Solved, BlockReconstructError> {
    let reconstructed = cached.job.merkle_root_for(extranonce)
        .map_err(|e| BlockReconstructError::Solve(SolveError::Internal(e)))?;
    if reconstructed != cached.merkle_root {
        return Err(BlockReconstructError::MerkleRootMismatch { cached: cached.merkle_root, reconstructed });
    }
    let solved = cached.job.solve(extranonce, version, ntime, nonce).map_err(BlockReconstructError::Solve)?;
    if solved.block.header.merkle_root.0 != cached.merkle_root {
        return Err(BlockReconstructError::MerkleRootMismatch { cached: cached.merkle_root, reconstructed: solved.block.header.merkle_root.0 });
    }
    Ok(solved)
}
