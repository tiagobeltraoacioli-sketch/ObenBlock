//! From an SV2 share to its block.
//!
//! `SubmitSharesStandard` carries `(job_id, nonce, ntime, version)`; the
//! extranonce is the channel's. The block is rebuilt from the cached job by
//! `Job::share` / `Job::block_for` (the same code as V1; the block
//! only for a share that meets the block target), after checking that the root it
//! derives is the root this channel was sent: if the cache and the miner's
//! view of the job ever drifted, the share is refused, never submitted.
//! Ported from the legacy Bloch server (genesis3-node
//! `src/stratum_v2/block_reconstruct.rs`), which ignored the rolled version;
//! here BIP 320 rolling is honoured for both the proof and the block.

use crate::core::Block;
use crate::stratum::jobs::{Share, SolveError, Solved, EXTRANONCE_BYTES};

use super::channel::Sv2CachedJob;

/// Why a share has no block.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockReconstructError {
    #[error("the root for this extranonce differs from the root sent in NewMiningJob (cache drift)")]
    MerkleRootMismatch { cached: [u8; 32], reconstructed: [u8; 32] },
    #[error("{0}")]
    Solve(SolveError),
}

/// The header and id of a share of `cached` with `extranonce` (cheap: no
/// block), after checking that the root it derives is the root this channel
/// was sent.
pub fn sv2_share(
    cached: &Sv2CachedJob, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, ntime: u32, nonce: u32,
) -> Result<Share, BlockReconstructError> {
    let share = cached.job.share(extranonce, version, ntime, nonce).map_err(BlockReconstructError::Solve)?;
    if share.merkle_root != cached.merkle_root {
        return Err(BlockReconstructError::MerkleRootMismatch { cached: cached.merkle_root, reconstructed: share.merkle_root });
    }
    Ok(share)
}

/// The block of a share from [`sv2_share`] (only for a share that meets the
/// block target).
pub fn sv2_block(cached: &Sv2CachedJob, extranonce: &[u8; EXTRANONCE_BYTES], share: &Share)
    -> Result<Block, BlockReconstructError>
{
    let block = cached.job.block_for(extranonce, share).map_err(BlockReconstructError::Solve)?;
    if block.header.merkle_root.0 != cached.merkle_root {
        return Err(BlockReconstructError::MerkleRootMismatch { cached: cached.merkle_root, reconstructed: block.header.merkle_root.0 });
    }
    Ok(block)
}

/// Rebuild the block of a share of `cached` with `extranonce`.
pub fn reconstruct_block_for_sv2_submit(
    cached: &Sv2CachedJob, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, ntime: u32, nonce: u32,
) -> Result<Solved, BlockReconstructError> {
    let share = sv2_share(cached, extranonce, version, ntime, nonce)?;
    let block = sv2_block(cached, extranonce, &share)?;
    Ok(Solved { block, header: share.header, id: share.id })
}
