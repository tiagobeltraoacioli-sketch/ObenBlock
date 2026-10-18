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
use crate::stratum::jobs::{Job, JobPrep, EXTRANONCE_BYTES};
use crate::template::BlockTemplate;

/// The header Merkle root for a channel's extranonce: exactly what a V1
/// miner computes from `coinb1 ‖ extranonce ‖ coinb2` and the branch under
/// ObenBlock's rule.
pub fn compute_merkle_root_for_channel(job: &Job, extranonce: &[u8; EXTRANONCE_BYTES]) -> Result<[u8; 32], String> {
    job.merkle_root_for(extranonce)
}

/// The job of a channel: the header job of `template` paying the channel's
/// script with the channel's extranonce, stamped `now`. `job.header` is the
/// header the channel mines (nonce 0). Computes the template's shared parts;
/// the server uses [`build_channel_job_with`] and the work feed's.
pub fn build_channel_job(
    template: Arc<BlockTemplate>, params: &Sha256dParams, script_pubkey: &[u8],
    extranonce: [u8; EXTRANONCE_BYTES], now: u64,
) -> Result<(Job, [u8; 32]), String> {
    let prep = Arc::new(JobPrep::new(&template, Some(params), now));
    build_channel_job_with(template, prep, params, script_pubkey, extranonce, now)
}

/// [`build_channel_job`] with the template's shared parts ([`JobPrep`]):
/// a light job, no block.
pub fn build_channel_job_with(
    template: Arc<BlockTemplate>, prep: Arc<JobPrep>, params: &Sha256dParams, script_pubkey: &[u8],
    extranonce: [u8; EXTRANONCE_BYTES], now: u64,
) -> Result<(Job, [u8; 32]), String> {
    let job = Job::build_with(template, prep, params, script_pubkey, extranonce, now)?;
    let root = compute_merkle_root_for_channel(&job, &extranonce)?;
    if root[..] != job.header[36..68] {
        return Err("internal: channel root differs from the header job's root".into());
    }
    Ok((job, root))
}
