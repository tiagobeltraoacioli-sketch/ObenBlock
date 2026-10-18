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
//! (docs/DESIGN-obenblock.md §4.1). The Merkle root is Bitcoin's SHA-256d
//! transaction tree over the wire txids (docs/OBENBLOCK-MINING.md §3.3; the
//! rest of the body is committed in the coinbase commitment), so:
//!
//! * V1 sends the header job's `stratum` object as it is (`coinb1`, `coinb2`,
//!   the Bitcoin branch, word-swapped `prevhash`, big-endian hex fields):
//!   stock Bitcoin firmware computes the root itself;
//! * V2 standard channels receive the root ready-made
//!   (`NewMiningJob.merkle_root`), computed for the channel's extranonce.
//!
//! A job is light: it shares the template (`Arc<BlockTemplate>`) and the
//! per-template [`JobPrep`] (coinbase commitment, Merkle branch, parents
//! commitment, computed once per work publication) and holds only its own
//! coinbase split, header fields and notify object. No job holds a block.
//!
//! [`Job::share`] turns a share into its 80-byte header and id (the coinbase
//! txid from `coinb1 ‖ extranonce ‖ coinb2`, the branch, the header rules a
//! share can break): O(coinbase + branch), whatever the template size.
//! Only a share that meets the block target pays for the full block:
//! [`Job::block_for`] assembles it as `getblocktemplate`'s header job does
//! and checks, before anything is submitted, that the root the share derived
//! is the block's own body root and that the header it hashed is the header
//! the block serializes (`BlockHeader::sha256d_pow_bytes`, the bytes the
//! node's proof check hashes). A block that passes both is judged by the same
//! acceptance path as `submitblock`.

use std::sync::Arc;

use crate::core::{self, pow_scheme::Sha256dParams, Block, MerkleRoot, Transaction, TxInput};
use crate::mining::sha256d::{self as job_rpc, TimeWindow, EXTRANONCE_LEN};
use crate::template::{self, BlockTemplate};
use gnb_smh::difficulty::{bits_to_target, Target};
use gnb_smh::sha256d;

/// Bytes of the extranonce (`extranonce1 ‖ extranonce2` in V1, the channel's
/// extranonce prefix in V2).
pub const EXTRANONCE_BYTES: usize = EXTRANONCE_LEN;

/// V1 `extranonce1` (per session) and `extranonce2` (rolled by the miner).
pub const EXTRANONCE1_BYTES: usize = 4;
pub const EXTRANONCE2_BYTES: usize = EXTRANONCE_BYTES - EXTRANONCE1_BYTES;

/// What every job of one template shares, computed once per template (the
/// work feed does it off the async runtime): the coinbase commitment and the
/// Merkle branch each cost a pass over every template transaction.
#[derive(Clone, Debug)]
pub struct JobPrep {
    /// The coinbase commitment (`None` below the hardening rules).
    pub commitment: Option<[u8; core::block_rules::COINBASE_COMMITMENT_LEN]>,
    /// Siblings of the coinbase in Bitcoin's tree, bottom-up.
    pub branch: Vec<[u8; 32]>,
    /// Header bytes 4..36.
    pub parents_commitment: [u8; 32],
    /// Light jobs reproduce `mining::sha256d::header_job` byte for byte on
    /// this template (checked once, against a full reference build). When
    /// false every job is built the full way (slower, never wrong).
    pub light: bool,
}

/// The reference payout of the [`JobPrep`] self-check (a 20-byte key hash).
const PREP_CHECK_SCRIPT: [u8; 20] = [0x5a; 20];
const PREP_CHECK_EXTRANONCE: [u8; EXTRANONCE_BYTES] = [0xa5, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

impl JobPrep {
    /// The shared parts of `template`'s jobs. `params` is the chain's
    /// SHA-256d scheme (`None` off a SHA-256d chain: no light jobs).
    pub fn new(template: &BlockTemplate, params: Option<&Sha256dParams>, now: u64) -> JobPrep {
        let mut prep = JobPrep {
            commitment: template.coinbase_commitment(),
            branch: job_rpc::merkle_branch(template),
            parents_commitment: sha256d::parents_commitment(&template.parents),
            light: false,
        };
        let Some(params) = params else { return prep };
        let full = job_rpc::header_job(template, params, &PREP_CHECK_SCRIPT, PREP_CHECK_EXTRANONCE, now);
        let light = build_parts(template, &prep, params, &PREP_CHECK_SCRIPT, PREP_CHECK_EXTRANONCE, now);
        prep.light = match (full, light) {
            (Ok(f), Ok(l)) => {
                let same = f.coinb1 == l.coinb1 && f.coinb2 == l.coinb2 && f.header == l.header
                    && f.merkle_branch == prep.branch && f.window == l.window;
                if !same {
                    log::error!("stratum: light jobs differ from the header job at h={}; building full jobs",
                                template.height);
                }
                same
            }
            _ => false,
        };
        prep
    }
}

/// The parts of a job, without its block.
struct Parts {
    header: [u8; sha256d::POW_HEADER_LEN],
    coinb1: Vec<u8>,
    coinb2: Vec<u8>,
    window: TimeWindow,
}

/// A job's parts the light way: the coinbase `assemble_block` would put in
/// the block (the commitment ‖ `COINBASE_TAG` ‖ extranonce `script_sig`, the
/// template's outputs for the script), split around the extranonce, and the
/// header over the shared branch.
fn build_parts(template: &BlockTemplate, prep: &JobPrep, params: &Sha256dParams, script_pubkey: &[u8],
               extranonce: [u8; EXTRANONCE_BYTES], now: u64) -> Result<Parts, String> {
    job_rpc::merkle_rule(template)?;
    if script_pubkey.len() > template::EXTERNAL_COINBASE_MAX_SPK || core::policy::output_kind(script_pubkey).is_none() {
        return Err(format!(
            "coinbase script_pubkey ({} bytes) is not a supported output (a 20-byte key hash or a 33-byte spend policy)",
            script_pubkey.len()));
    }
    sha256d::check_parents(&template.parents, core::MAX_PARENTS)
        .map_err(|e| format!("template parents are not in SHA-256d header order: {e}"))?;
    let window = job_rpc::time_window(template, now);
    let mut extra = job_rpc::COINBASE_TAG.to_vec();
    extra.extend_from_slice(&extranonce);
    let script_sig = match &prep.commitment {
        Some(c) => core::block_rules::coinbase_script_sig(c, &extra),
        None => extra,
    };
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
        outputs: template.coinbase_outputs(script_pubkey.to_vec()),
        locktime: 0,
    };
    let (coinb1, coinb2) = job_rpc::split_coinbase(&coinbase)?;
    let txid = coinbase.txid();
    let time = u32::try_from(window.curtime).map_err(|_| "job time does not fit u32".to_string())?;
    let root = core::block_rules::merkle_root_from_coinbase_branch(&txid, &prep.branch, false).0;
    let header = header_bytes(params.block_version, &prep.parents_commitment, &root, time, window.bits, 0);
    Ok(Parts { header, coinb1, coinb2, window })
}

/// One job: a candidate block paying one script, with its coinbase split
/// around the extranonce (the block itself is assembled only for a share
/// that meets the block target).
#[derive(Clone, Debug)]
pub struct Job {
    /// The shared template the job was built from.
    pub template: Arc<BlockTemplate>,
    /// The template's shared parts.
    pub prep: Arc<JobPrep>,
    pub params: Sha256dParams,
    /// The payout script of the coinbase.
    pub script_pubkey: Vec<u8>,
    /// The clock reading the job was built at (its window's `now`).
    pub built_at: u64,
    /// Its 80-byte header for [`Self::extranonce`] (nonce 0).
    pub header: [u8; sha256d::POW_HEADER_LEN],
    /// Coinbase wire bytes before / after the extranonce.
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    /// The extranonce [`Self::header`] is computed for.
    pub extranonce: [u8; EXTRANONCE_BYTES],
    /// Header fields of the job (the miner rolls nonce, the BIP 320 bits of
    /// `version`, and `time` inside [`Self::window`]).
    pub version: u32,
    pub time: u32,
    pub bits: u32,
    /// Header bytes 4..36: `parents_commitment`.
    pub parents_commitment: [u8; 32],
    /// Siblings of the coinbase in Bitcoin's tree, bottom-up.
    pub merkle_branch: Vec<[u8; 32]>,
    /// The `ntime` window that keeps `bits` (one stall-relief step).
    pub window: TimeWindow,
    /// The header job's `stratum` object (the V1 notify fields).
    pub stratum: serde_json::Value,
}

/// Why a share could not be turned into a block of its job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolveError {
    /// The version changes bits outside the BIP 320 mask.
    BadVersion(u32),
    /// The time is before the job's window (`mintime`).
    TimeTooOld { time: u32, min: u64 },
    /// The time is after the job's window (`maxtime`) in the same step, or
    /// more than `MAX_FUTURE_SECS` ahead of this node's clock.
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
            Self::TimeTooOld { time, min } => write!(f, "time {time} is before the job's mintime {min}"),
            Self::TimeTooNew { time, max } => write!(f, "time {time} is after the job's maxtime {max}"),
            Self::BitsChanged { job_bits, bits_at_time } => write!(
                f, "at this time the block needs bits {bits_at_time:08x}, the job has {job_bits:08x} \
                    (stall-relief step changed): take the new job"),
            Self::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

/// A share's header: what the proof is judged on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Share {
    /// The 80-byte header the miner hashed.
    pub header: [u8; sha256d::POW_HEADER_LEN],
    /// `SHA-256d(header)`, the block id.
    pub id: [u8; 32],
    /// Its Merkle root (Bitcoin's tree for the share's extranonce).
    pub merkle_root: [u8; 32],
    pub version: u32,
    pub time: u32,
    pub nonce: u32,
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
    /// `mining::sha256d::header_job`. Computes the template's [`JobPrep`];
    /// the servers use [`Self::build_with`] and the work feed's.
    pub fn build(
        template: Arc<BlockTemplate>,
        params: &Sha256dParams,
        script_pubkey: &[u8],
        extranonce: [u8; EXTRANONCE_BYTES],
        now: u64,
    ) -> Result<Job, String> {
        let prep = Arc::new(JobPrep::new(&template, Some(params), now));
        Self::build_with(template, prep, params, script_pubkey, extranonce, now)
    }

    /// [`Self::build`] with the template's shared parts: O(coinbase) when
    /// `prep` is light, never a pass over the template's transactions.
    pub fn build_with(
        template: Arc<BlockTemplate>,
        prep: Arc<JobPrep>,
        params: &Sha256dParams,
        script_pubkey: &[u8],
        extranonce: [u8; EXTRANONCE_BYTES],
        now: u64,
    ) -> Result<Job, String> {
        let parts = if prep.light {
            build_parts(&template, &prep, params, script_pubkey, extranonce, now)?
        } else {
            let hj = job_rpc::header_job(&template, params, script_pubkey, extranonce, now)?;
            Parts { header: hj.header, coinb1: hj.coinb1, coinb2: hj.coinb2, window: hj.window }
        };
        let word = |at: usize| u32::from_le_bytes([parts.header[at], parts.header[at + 1], parts.header[at + 2],
                                                   parts.header[at + 3]]);
        let mut parents_commitment = [0u8; 32];
        parents_commitment.copy_from_slice(&parts.header[4..36]);
        let stratum = job_rpc::stratum_object(&parts.header, &parts.coinb1, &parts.coinb2, &prep.branch, &parts.window);
        Ok(Job {
            version: word(0),
            time: word(68),
            bits: word(72),
            parents_commitment,
            merkle_branch: prep.branch.clone(),
            window: parts.window,
            stratum,
            header: parts.header,
            coinb1: parts.coinb1,
            coinb2: parts.coinb2,
            extranonce,
            script_pubkey: script_pubkey.to_vec(),
            built_at: now,
            params: *params,
            prep,
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

    /// The header Merkle root (Bitcoin's tree) for `extranonce`: the coinbase
    /// txid folded with the shared branch.
    pub fn merkle_root_for(&self, extranonce: &[u8; EXTRANONCE_BYTES]) -> Result<[u8; 32], String> {
        job_rpc::merkle_rule(&self.template)?;
        let txid = sha256d::sha256d(&self.coinbase_bytes(extranonce));
        Ok(core::block_rules::merkle_root_from_coinbase_branch(&txid, &self.merkle_branch, false).0)
    }

    /// The 80-byte header of a share of this job.
    pub fn share_header(&self, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, time: u32, nonce: u32)
        -> Result<[u8; sha256d::POW_HEADER_LEN], String>
    {
        let root = self.merkle_root_for(extranonce)?;
        Ok(header_bytes(version, &self.parents_commitment, &root, time, self.bits, nonce))
    }

    /// The header and id of a share (`extranonce`, rolled `version`, `time`,
    /// `nonce`), after the header rules a share can break (BIP 320 version,
    /// time window, stall-relief step). Cheap: no block is built. The proof
    /// is the caller's: compare [`Share::id`] with a target.
    pub fn share(&self, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, time: u32, nonce: u32)
        -> Result<Share, SolveError>
    {
        if !sha256d::version_ok(version, self.version & !sha256d::BIP320_VERSION_MASK) {
            return Err(SolveError::BadVersion(version));
        }
        // The job's window: one stall-relief step, at or after the parents,
        // at most MAX_FUTURE_SECS ahead (of the clock at the job, and now).
        let (min, max) = (self.window.mintime, self.window.maxtime);
        if (time as u64) < min {
            return Err(SolveError::TimeTooOld { time, min });
        }
        let bits_at_time = bits_at(&self.template, time as u64);
        if bits_at_time != self.bits {
            return Err(SolveError::BitsChanged { job_bits: self.bits, bits_at_time });
        }
        let max = max.min(now_secs().saturating_add(core::MAX_FUTURE_SECS));
        if time as u64 > max {
            return Err(SolveError::TimeTooNew { time, max });
        }
        let merkle_root = self.merkle_root_for(extranonce).map_err(SolveError::Internal)?;
        let header = header_bytes(version, &self.parents_commitment, &merkle_root, time, self.bits, nonce);
        Ok(Share { header, id: sha256d::block_id(&header), merkle_root, version, time, nonce })
    }

    /// The block of `share` (a share of this job with `extranonce`, from
    /// [`Self::share`]): assembled as `getblocktemplate`'s header job for
    /// the share's extranonce, then checked byte for byte: the coinbase is
    /// the job's (the split the miner was sent), the body root is the root
    /// the share hashed, and the header the block serializes is the share's.
    /// Only worth it for a share that meets the block target.
    pub fn block_for(&self, extranonce: &[u8; EXTRANONCE_BYTES], share: &Share) -> Result<Block, SolveError> {
        let hj = job_rpc::header_job(&self.template, &self.params, &self.script_pubkey, *extranonce, self.built_at)
            .map_err(SolveError::Internal)?;
        if hj.coinb1 != self.coinb1 || hj.coinb2 != self.coinb2 {
            return Err(SolveError::Internal("the block's coinbase differs from the job's coinbase split".into()));
        }
        let mut block = hj.block;
        block.header.version = share.version;
        block.header.timestamp = share.time as u64;
        block.header.nonce = share.nonce as u64;
        block.header.merkle_root = MerkleRoot(share.merkle_root);
        // Byte identity: the root from the extranonce is the block's own body
        // root, and the header hashed is the one the block serializes.
        let body_root = block.body_merkle_root();
        if body_root.0 != share.merkle_root {
            return Err(SolveError::Internal("derived Merkle root differs from the block's body root".into()));
        }
        let own = block.header.sha256d_pow_bytes()
            .map_err(|e| SolveError::Internal(format!("header does not fit 80 bytes: {e}")))?;
        if own != share.header {
            return Err(SolveError::Internal("share header differs from the block's header bytes".into()));
        }
        Ok(block)
    }

    /// [`Self::share`] then [`Self::block_for`]: the block a share mined,
    /// whatever its proof.
    pub fn solve(&self, extranonce: &[u8; EXTRANONCE_BYTES], version: u32, time: u32, nonce: u32)
        -> Result<Solved, SolveError>
    {
        let share = self.share(extranonce, version, time, nonce)?;
        let block = self.block_for(extranonce, &share)?;
        Ok(Solved { block, header: share.header, id: share.id })
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
