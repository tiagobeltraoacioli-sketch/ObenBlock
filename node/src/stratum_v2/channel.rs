//! Standard mining channels of one SV2 session.
//!
//! A channel is opened by `OpenStandardMiningChannel`; it has its own id,
//! payout, share target and 8-byte extranonce (`extranonce_prefix`, all of
//! the coinbase extranonce: a standard channel mines header-only), and the
//! ring of its recent jobs. A job is cached with the exact `Job` and Merkle
//! root sent in `NewMiningJob`, so a share is reconstructed byte for byte
//! from what the miner received. Ported from the legacy Bloch server
//! (genesis3-node `src/stratum_v2/channel.rs`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use crate::stratum::jobs::{Job, EXTRANONCE_BYTES};
use crate::stratum::Payout;

/// Jobs kept per channel (older job ids get `invalid-job-id`).
pub const MAX_JOBS_PER_CHANNEL: usize = 16;

/// Channels per session (a standard-channel device opens one; a small
/// proxy a few).
pub const MAX_CHANNELS_PER_SESSION: usize = 8;

/// Channels across every session of the server (each costs a job per work
/// update).
pub const MAX_CHANNELS_GLOBAL: usize = 2_048;

/// Duplicate cache per channel.
pub const MAX_SEEN_SHARES: usize = 4096;

/// Shares per minute per channel judged below the block target (a share
/// that meets the block target is never refused for rate).
pub const SUBMIT_RATE_PER_MIN_PER_CHANNEL: u32 = 120;

/// After a target raise, shares at the previous target still count for
/// this long.
pub const RAISE_GRACE_SECS: u64 = 10;

/// A job as sent to a channel.
#[derive(Clone)]
pub struct Sv2CachedJob {
    pub job_id: u32,
    pub job: Arc<Job>,
    /// The root sent in `NewMiningJob` (the body root for the channel's
    /// extranonce).
    pub merkle_root: [u8; 32],
}

impl std::fmt::Debug for Sv2CachedJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sv2CachedJob")
            .field("job_id", &self.job_id)
            .field("height", &self.job.template.height)
            .field("bits", &format_args!("{:08x}", self.job.bits))
            .field("merkle_root", &hex::encode(&self.merkle_root[..4]))
            .finish()
    }
}

/// One standard channel.
#[derive(Debug)]
pub struct ChannelState {
    pub channel_id: u32,
    pub user_identity: String,
    pub payout: Payout,
    pub nominal_hash_rate: f32,
    /// Share target, big-endian.
    pub target: [u8; 32],
    pub extranonce_prefix: [u8; EXTRANONCE_BYTES],
    pub last_job_id: Option<u32>,
    pub recent_jobs: VecDeque<Sv2CachedJob>,
    seen: HashSet<(u32, u32, u32, u32)>,
    seen_order: VecDeque<(u32, u32, u32, u32)>,
    pub accepted: u32,
    /// Submits in the current minute and when it started.
    submit_window: (std::time::Instant, u32),
    raised_in_window: bool,
    /// The target before the last raise, honoured until the instant (shares
    /// mined before the miner saw the new target).
    grace: Option<([u8; 32], std::time::Instant)>,
}

impl ChannelState {
    pub fn new(channel_id: u32, user_identity: String, payout: Payout, nominal_hash_rate: f32,
               target: [u8; 32], extranonce_prefix: [u8; EXTRANONCE_BYTES]) -> Self {
        Self {
            channel_id, user_identity, payout, nominal_hash_rate, target, extranonce_prefix,
            last_job_id: None,
            recent_jobs: VecDeque::with_capacity(MAX_JOBS_PER_CHANNEL),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            accepted: 0,
            submit_window: (std::time::Instant::now(), 0),
            raised_in_window: false,
            grace: None,
        }
    }

    /// The target a share is judged at: the channel's, or the easier one
    /// before the last raise during its grace.
    pub fn judged_target(&self) -> [u8; 32] {
        match self.grace {
            Some((prev, until)) if std::time::Instant::now() < until => prev.max(self.target),
            _ => self.target,
        }
    }

    /// Count a submit; false once the channel is over
    /// [`SUBMIT_RATE_PER_MIN_PER_CHANNEL`] in the current minute.
    pub fn note_submit(&mut self) -> bool {
        if self.submit_window.0.elapsed() >= std::time::Duration::from_secs(60) {
            self.submit_window = (std::time::Instant::now(), 0);
            self.raised_in_window = false;
        }
        self.submit_window.1 = self.submit_window.1.saturating_add(1);
        self.submit_window.1 <= SUBMIT_RATE_PER_MIN_PER_CHANNEL
    }

    /// Over the rate: a harder share target matching the observed rate (one
    /// share per `interval_secs`), never harder than `block_target`, once
    /// per window. `Some(target)` when the channel's target changed.
    pub fn raise_for_rate(&mut self, block_target: &[u8; 32], interval_secs: f64) -> Option<[u8; 32]> {
        if self.raised_in_window {
            return None;
        }
        self.raised_in_window = true;
        let (since, count) = self.submit_window;
        let per_sec = count as f64 / since.elapsed().as_secs_f64().max(1.0);
        let factor = (per_sec * interval_secs).clamp(4.0, 1e9);
        let cur = crate::stratum::difficulty::difficulty_from_target(&gnb_smh::difficulty::Target(self.target));
        let want = crate::stratum::difficulty::target_from_difficulty(cur * factor);
        let next = crate::stratum::difficulty::easier(&want, &gnb_smh::difficulty::Target(*block_target)).0;
        if next >= self.target {
            return None;
        }
        self.grace = Some((self.target, std::time::Instant::now() + std::time::Duration::from_secs(RAISE_GRACE_SECS)));
        self.target = next;
        Some(next)
    }

    /// Record a pushed job (oldest evicted). `clean` drops every older job
    /// (a new tip or a new stall-relief step: their blocks can no longer be
    /// the best).
    pub fn push_job(&mut self, job: Sv2CachedJob, clean: bool) {
        self.last_job_id = Some(job.job_id);
        if clean {
            self.recent_jobs.clear();
            self.seen.clear();
            self.seen_order.clear();
        }
        if self.recent_jobs.len() >= MAX_JOBS_PER_CHANNEL {
            if let Some(old) = self.recent_jobs.pop_front() {
                self.seen.retain(|k| k.0 != old.job_id);
                self.seen_order.retain(|k| k.0 != old.job_id);
            }
        }
        self.recent_jobs.push_back(job);
    }

    pub fn find_job(&self, job_id: u32) -> Option<&Sv2CachedJob> {
        self.recent_jobs.iter().find(|j| j.job_id == job_id)
    }

    /// Whether this share was already credited.
    pub fn is_duplicate(&self, job_id: u32, nonce: u32, ntime: u32, version: u32) -> bool {
        self.seen.contains(&(job_id, nonce, ntime, version))
    }

    /// Record a credited share (call only once it met a target: a share
    /// without proof of work costs no memory); false if it was already
    /// recorded. FIFO, at most [`MAX_SEEN_SHARES`].
    pub fn record_share(&mut self, job_id: u32, nonce: u32, ntime: u32, version: u32) -> bool {
        let k = (job_id, nonce, ntime, version);
        if !self.seen.insert(k) {
            return false;
        }
        self.seen_order.push_back(k);
        while self.seen_order.len() > MAX_SEEN_SHARES {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    /// Entries in the duplicate cache.
    pub fn seen_len(&self) -> usize {
        self.seen.len()
    }
}

/// Channel registry errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("channel id {0} already exists")]
    DuplicateId(u32),
    #[error("session reached the channel limit ({0})")]
    TooManyChannels(usize),
}

/// The channels of one session.
#[derive(Debug)]
pub struct ChannelRegistry {
    next_id: u32,
    /// Random per session: extranonces of different sessions differ.
    session_prefix: [u8; 4],
    channels: HashMap<u32, ChannelState>,
}

impl ChannelRegistry {
    pub fn new(session_prefix: [u8; 4]) -> Self {
        Self { next_id: 1, session_prefix, channels: HashMap::new() }
    }

    pub fn allocate_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    /// The channel's extranonce: `session_prefix ‖ u32be(channel_id)`.
    pub fn extranonce_for(&self, channel_id: u32) -> [u8; EXTRANONCE_BYTES] {
        let mut e = [0u8; EXTRANONCE_BYTES];
        e[..4].copy_from_slice(&self.session_prefix);
        e[4..].copy_from_slice(&channel_id.to_be_bytes());
        e
    }

    pub fn insert(&mut self, channel: ChannelState) -> Result<(), ChannelError> {
        if self.channels.contains_key(&channel.channel_id) {
            return Err(ChannelError::DuplicateId(channel.channel_id));
        }
        if self.channels.len() >= MAX_CHANNELS_PER_SESSION {
            return Err(ChannelError::TooManyChannels(MAX_CHANNELS_PER_SESSION));
        }
        self.channels.insert(channel.channel_id, channel);
        Ok(())
    }

    pub fn get(&self, id: u32) -> Option<&ChannelState> { self.channels.get(&id) }
    pub fn get_mut(&mut self, id: u32) -> Option<&mut ChannelState> { self.channels.get_mut(&id) }
    pub fn len(&self) -> usize { self.channels.len() }
    pub fn is_empty(&self) -> bool { self.channels.is_empty() }
    pub fn ids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.channels.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payout() -> Payout {
        Payout { address: "x".into(), script_pubkey: vec![1; 20] }
    }

    fn ch(id: u32) -> ChannelState {
        ChannelState::new(id, "u".into(), payout(), 1.0, [0xff; 32], [0; 8])
    }

    #[test]
    fn registry_allocates_unique_ids_and_extranonces() {
        let mut reg = ChannelRegistry::new([9, 9, 9, 9]);
        let (a, b) = (reg.allocate_id(), reg.allocate_id());
        assert_ne!(a, b);
        assert_ne!(reg.extranonce_for(a), reg.extranonce_for(b));
        assert_eq!(&reg.extranonce_for(1)[..], &[9, 9, 9, 9, 0, 0, 0, 1]);
    }

    #[test]
    fn registry_rejects_duplicates_and_caps_channels() {
        let mut reg = ChannelRegistry::new([0; 4]);
        reg.insert(ch(42)).unwrap();
        assert_eq!(reg.insert(ch(42)), Err(ChannelError::DuplicateId(42)));
        for i in 0..(MAX_CHANNELS_PER_SESSION as u32 - 1) {
            reg.insert(ch(100 + i)).unwrap();
        }
        assert_eq!(reg.insert(ch(9_999)), Err(ChannelError::TooManyChannels(MAX_CHANNELS_PER_SESSION)));
        assert_eq!(reg.len(), MAX_CHANNELS_PER_SESSION);
    }

    /// A job stub (the ring only looks at ids).
    fn cached(job_id: u32) -> Sv2CachedJob {
        let template = Arc::new(crate::template::BlockTemplate {
            parents: vec![], height: 1, blue_score: 1, bits: 0x1d00_ffff, parent_timestamp: 0,
            transactions: vec![], total_fees: 0, subsidy: 0, evicted: 0, tx_byte_budget: 0,
            activation_height: 0, hardened: true, powit: Default::default(),
        });
        let prep = Arc::new(crate::stratum::jobs::JobPrep::new(&template, None, 0));
        let job = Arc::new(Job {
            template, prep, params: crate::core::pow_scheme::Sha256dParams::obenblock_regtest(1_800_000_000),
            script_pubkey: vec![0; 20], built_at: 0,
            header: [0; 80], coinb1: vec![], coinb2: vec![], extranonce: [0; 8],
            version: 0x2000_0000, time: 0, bits: 0x1d00_ffff, parents_commitment: [0; 32],
            merkle_branch: vec![],
            window: crate::mining::sha256d::TimeWindow { curtime: 0, mintime: 0, maxtime: 0, bits: 0x1d00_ffff,
                                                         relief_step: 0, next_bits_time: None },
            stratum: serde_json::Value::Null,
        });
        Sv2CachedJob { job_id, job, merkle_root: [0; 32] }
    }

    #[test]
    fn job_ring_evicts_oldest_and_clean_drops_all() {
        let mut c = ch(1);
        assert_eq!(c.last_job_id, None);
        for i in 0..(MAX_JOBS_PER_CHANNEL as u32 + 2) {
            c.push_job(cached(i), false);
        }
        assert_eq!(c.recent_jobs.len(), MAX_JOBS_PER_CHANNEL);
        assert!(c.find_job(0).is_none() && c.find_job(1).is_none());
        assert!(c.find_job(2).is_some());
        assert_eq!(c.last_job_id, Some(MAX_JOBS_PER_CHANNEL as u32 + 1));
        assert!(c.record_share(5, 0, 0, 0));
        c.push_job(cached(100), true);
        assert_eq!(c.recent_jobs.len(), 1);
        assert!(c.find_job(5).is_none() && c.find_job(100).is_some());
        assert!(c.record_share(5, 0, 0, 0), "the duplicate cache was cleared with the jobs");
    }

    #[test]
    fn duplicate_shares_are_detected_per_job() {
        let mut c = ch(1);
        assert!(!c.is_duplicate(1, 2, 3, 4));
        assert!(c.record_share(1, 2, 3, 4));
        assert!(c.is_duplicate(1, 2, 3, 4));
        assert!(!c.record_share(1, 2, 3, 4));
        assert!(c.record_share(1, 2, 4, 4), "another time is another share");
    }

    #[test]
    fn duplicate_cache_is_fifo_bounded() {
        let mut c = ch(1);
        for n in 0..(MAX_SEEN_SHARES as u32 + 5) {
            c.record_share(1, n, 0, 0);
        }
        assert_eq!(c.seen_len(), MAX_SEEN_SHARES);
        assert!(!c.is_duplicate(1, 0, 0, 0) && c.is_duplicate(1, MAX_SEEN_SHARES as u32 + 4, 0, 0));
    }

    #[test]
    fn channel_rate_limit_raises_the_target_never_past_the_block() {
        let mut c = ch(1);
        for _ in 0..SUBMIT_RATE_PER_MIN_PER_CHANNEL {
            assert!(c.note_submit());
        }
        assert!(!c.note_submit());
        let block = gnb_smh::difficulty::bits_to_target(0x1d00_ffff).0;
        let t = c.raise_for_rate(&block, 10.0).expect("harder target");
        assert!(t < [0xff; 32] && t >= block, "harder than before, not harder than a block");
        assert_eq!(c.judged_target(), [0xff; 32], "the old target holds during the grace");
        assert!(c.raise_for_rate(&block, 10.0).is_none(), "once per window");
        // At the block target already: nothing to raise.
        let mut d = ch(2);
        d.target = block;
        for _ in 0..=SUBMIT_RATE_PER_MIN_PER_CHANNEL {
            d.note_submit();
        }
        assert!(d.raise_for_rate(&block, 10.0).is_none());
    }
}
