//! The upstream side: one task that follows the node and publishes jobs.
//!
//! * Every `poll_interval` it reads the node's tip set (`getdaginfo`).
//! * It fetches a new header job (`getblocktemplate`) when the tips change
//!   (a clean job: miners drop work on the old parents), when
//!   `refresh_interval` has passed (fresh time and mempool, not clean), when
//!   the job's `ntime` window ends: its `maxtime` has passed or the node's
//!   `next_bits_time` (the next stall-relief step, easier bits) has come
//!   (not clean: the old job's shares inside its window are still blocks),
//!   and right after this server found a block. A job whose window is
//!   already over when it arrives (the node caches templates for 5 s) is
//!   not published; the next poll asks again.
//! * Jobs are published on a `watch` channel; every connection sees the
//!   latest one. A failing node keeps the last good job published (miners
//!   keep working on it) and is retried at the next poll.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Notify};

use crate::job::{ObbJob, EXTRANONCE_LEN};
use crate::rpc::RpcClient;
use crate::types::{Metrics, PoolError};

/// A published job and whether miners must drop older work.
#[derive(Clone, Debug)]
pub struct Published {
    pub job: Arc<ObbJob>,
    pub clean_jobs: bool,
}

/// The extranonce the server asks the node to build its header job with.
/// Connections replace it; any fixed value works.
pub const JOB_EXTRANONCE: [u8; EXTRANONCE_LEN] = [0; EXTRANONCE_LEN];

pub struct TemplateSource {
    rpc: RpcClient,
    script_pubkey: Vec<u8>,
    poll_interval: Duration,
    refresh_interval: Duration,
    metrics: Arc<Metrics>,
    tx: watch::Sender<Option<Published>>,
    /// Signalled when a block was found: refresh at once.
    pub wake: Arc<Notify>,
    counter: u64,
}

impl TemplateSource {
    pub fn new(rpc: RpcClient, script_pubkey: Vec<u8>, poll_interval: Duration, refresh_interval: Duration,
               metrics: Arc<Metrics>) -> (Self, watch::Receiver<Option<Published>>) {
        let (tx, rx) = watch::channel(None);
        (Self { rpc, script_pubkey, poll_interval, refresh_interval, metrics, tx, wake: Arc::new(Notify::new()),
                counter: 0 }, rx)
    }

    /// Fetch one header job and build it.
    pub async fn fetch_job(&mut self) -> Result<ObbJob, PoolError> {
        let gbt = self.rpc.header_job_template(&self.script_pubkey, &JOB_EXTRANONCE).await?;
        self.counter += 1;
        let height = gbt.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
        let id = format!("{:x}{:04x}", height, self.counter & 0xffff);
        ObbJob::from_template(&gbt, JOB_EXTRANONCE, id).map_err(PoolError::Protocol)
    }

    fn publish(&self, job: ObbJob, clean_jobs: bool) {
        let m = &self.metrics;
        m.templates_total.fetch_add(1, Ordering::Relaxed);
        m.template_height.store(job.height as i64, Ordering::Relaxed);
        m.template_bits.store(job.bits as i64, Ordering::Relaxed);
        m.template_parent_count.store(job.parents.len() as i64, Ordering::Relaxed);
        log::info!("job {} height {} bits {:08x} step {} ntime {}..={} parents {} clean {}", job.job_id, job.height,
                   job.bits, job.relief_step, job.mintime, job.maxtime, job.parents.len(), clean_jobs);
        let _ = self.tx.send(Some(Published { job: Arc::new(job), clean_jobs }));
    }

    /// Follow the node forever.
    pub async fn run(mut self) {
        let mut last_tips: Option<Vec<String>> = None;
        let mut last: Option<(Arc<ObbJob>, Instant)> = None;
        let mut force = true;
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = self.wake.notified() => { force = true; }
            }
            let tips = match self.rpc.dag_tips().await {
                Ok(t) => t,
                Err(e) => {
                    self.metrics.rpc_failures.fetch_add(1, Ordering::Relaxed);
                    log::warn!("getdaginfo failed: {e}");
                    continue;
                }
            };
            let tips_changed = last_tips.as_ref() != Some(&tips);
            let now_unix = unix_now();
            let due = match &last {
                None => true,
                Some((job, at)) => {
                    at.elapsed() >= self.refresh_interval || job.window_over(now_unix)
                }
            };
            if !(force || tips_changed || due) {
                continue;
            }
            match self.fetch_job().await {
                Ok(job) if job.window_over(unix_now()) => {
                    log::debug!("job {} arrived with its window over (maxtime {}); asking again", job.job_id,
                                job.maxtime);
                }
                Ok(job) => {
                    let clean = match &last {
                        None => true,
                        Some((prev, _)) => prev.parents_commitment != job.parents_commitment,
                    };
                    last_tips = Some(tips);
                    force = false;
                    self.publish(job, clean);
                    last = self.tx.borrow().as_ref().map(|p| (p.job.clone(), Instant::now()));
                }
                Err(e) => {
                    self.metrics.rpc_failures.fetch_add(1, Ordering::Relaxed);
                    log::warn!("getblocktemplate failed (keeping the previous job): {e}");
                }
            }
        }
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
