//! From a work-feed template to a channel's job (Stratum V2).
//!
//! V1 ships `coinb1`, `coinb2` and the branch and lets the miner compute the
//! root; a standard SV2 channel receives the root itself in `NewMiningJob`,
//! so the server computes it for the channel's extranonce. Both go through
//! the same [`Job`] (the `getblocktemplate` header job), which keeps the
//! byte-identical-header invariant between V1, V2, RPC and the node's own
//! proof check: for one template, payout script, extranonce and time, every
//! path yields the same 80 bytes (tested in node/tests/stratum_e2e.rs).

use std::sync::Arc;

use crate::core::pow_scheme::Sha256dParams;
use crate::stratum::jobs::{Job, EXTRANONCE_BYTES};
use crate::template::BlockTemplate;

/// The header Merkle root for a channel's extranonce: exactly what a V1
/// miner computes from `coinb1 ‖ extranonce ‖ coinb2` and the branch under
/// ObenBlock's rule.
pub fn compute_merkle_root_for_channel(job: &Job, extranonce: &[u8; EXTRANONCE_BYTES]) -> Result<[u8; 32], String> {
    job.merkle_root_for(extranonce)
}

/// The job of a channel: the header job of `template` paying the channel's
/// script with the channel's extranonce, stamped `now`. Its candidate block
/// already carries the channel's extranonce, so `job.header` is the header
/// the channel mines (nonce 0).
pub fn build_channel_job(
    template: Arc<BlockTemplate>, params: &Sha256dParams, script_pubkey: &[u8],
    extranonce: [u8; EXTRANONCE_BYTES], now: u64,
) -> Result<(Job, [u8; 32]), String> {
    let job = Job::build(template, params, script_pubkey, extranonce, now)?;
    let root = compute_merkle_root_for_channel(&job, &extranonce)?;
    if root != job.block.header.merkle_root.0 {
        return Err("internal: channel root differs from the header job's root".into());
    }
    Ok((job, root))
}
