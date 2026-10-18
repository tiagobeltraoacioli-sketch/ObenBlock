//! The work feed shared by the V1 and V2 servers.
//!
//! One task builds block templates with the same builder as
//! `getblocktemplate` (`template::build_block_template`,
//! `EXTERNAL_COINBASE_RESERVE`, the same IBD refusal) and publishes them on a
//! `watch` channel. Every session turns the newest template into its own
//! job ([`super::jobs::Job`]) for its payout script and extranonce.
//!
//! A new template is published:
//!
//! * on a tip change (`TipChanged`, the node's tip broadcast): clean, the old
//!   jobs can no longer make a block on the best tip;
//! * every [`REFRESH_SECS`] (mempool churn): not clean when the parents are
//!   unchanged;
//! * at each stall-relief step (docs/DESIGN-obenblock.md §5.1): once a block
//!   is late its expected bits change every 60 s, and a job keeps the bits it
//!   was built with. The feed re-publishes the template (clean) as soon as
//!   the bits for the current time differ from the bits of the last
//!   publication, so every miner gets a job with the easier target within
//!   [`STEP_POLL_MS`] of the step.

use std::sync::Arc;
use std::time::Duration;

use log::{debug, info, warn};
use tokio::sync::{broadcast, watch};

use super::jobs::JobPrep;
use super::NodeContext;
use crate::template::{self, BlockTemplate};
use crate::tip::TipChanged;

/// Mempool refresh interval without a tip change.
pub const REFRESH_SECS: u64 = 60;

/// Retry interval while no template can be built (initial block download).
pub const RETRY_SECS: u64 = 5;

/// How often the feed checks whether the stall-relief step changed.
pub const STEP_POLL_MS: u64 = 1_000;

/// Why a template was published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkReason {
    /// The feed's first template.
    Start,
    /// The selected tip moved.
    TipChanged,
    /// Periodic mempool refresh.
    Refresh,
    /// The expected bits changed with the time (stall relief).
    StallStep,
}

/// One publication of the feed.
#[derive(Clone, Debug)]
pub struct Work {
    /// Increases with every publication.
    pub seq: u64,
    pub template: Arc<BlockTemplate>,
    /// Miners should drop older jobs (V1 `clean_jobs`; V2 always sends a new
    /// `SetNewPrevHash`).
    pub clean: bool,
    pub reason: WorkReason,
    /// The bits a block stamped at publication time needs.
    pub bits: u32,
    /// The parts every job of `template` shares (built once here, so a
    /// session's job costs O(coinbase), not a pass over the template).
    pub prep: Arc<JobPrep>,
}

impl Work {
    /// A publication of `template` (its [`JobPrep`] computed here).
    pub fn new(seq: u64, template: Arc<BlockTemplate>, clean: bool, reason: WorkReason, bits: u32) -> Work {
        let prep = Arc::new(JobPrep::new(&template, crate::core::pow_scheme::node_sha256d_params().as_ref(), now_secs()));
        Work { seq, template, clean, reason, bits, prep }
    }
}

/// Receiver of the feed: `None` until the first template is built.
pub type WorkReceiver = watch::Receiver<Option<Arc<Work>>>;

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The bits of a new stall-relief step, when the bits a block of `work`'s
/// template stamped `now` needs differ from the bits it was published with.
pub fn stall_step_due(work: &Work, now: u64) -> Option<u32> {
    let bits = super::jobs::bits_at(&work.template, now);
    (bits != work.bits).then_some(bits)
}

/// Build a template on the node's state, as `getblocktemplate` does
/// (refused during initial block download and while a chain move is
/// incomplete).
pub fn build_template(ctx: &NodeContext) -> Result<BlockTemplate, String> {
    if let Some(e) = crate::ingress::ibd_template_refusal(&ctx.dag.read(), ctx.min_chain_work) {
        return Err(e);
    }
    template::build_block_template(&ctx.dag, &ctx.store, &ctx.mempool, template::EXTERNAL_COINBASE_RESERVE)
}

async fn build_async(ctx: &Arc<NodeContext>) -> Result<(Arc<BlockTemplate>, Arc<JobPrep>), String> {
    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        let t = build_template(&ctx)?;
        let prep = JobPrep::new(&t, crate::core::pow_scheme::node_sha256d_params().as_ref(), now_secs());
        Ok((Arc::new(t), Arc::new(prep)))
    })
    .await
    .map_err(|e| format!("template task failed: {e}"))?
}

/// Start the feed. The returned receiver (and its clones) see every
/// publication; the task ends when the tip broadcast closes.
pub fn spawn(ctx: Arc<NodeContext>, mut tip_rx: broadcast::Receiver<TipChanged>) -> WorkReceiver {
    let (tx, rx) = watch::channel::<Option<Arc<Work>>>(None);
    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut refresh = tokio::time::interval(Duration::from_secs(REFRESH_SECS));
        refresh.tick().await;
        let mut step = tokio::time::interval(Duration::from_millis(STEP_POLL_MS));
        let mut reason = Some(WorkReason::Start);
        let mut last_try = std::time::Instant::now();
        let mut last_error = String::new();
        loop {
            if let Some(why) = reason.take() {
                last_try = std::time::Instant::now();
                match build_async(&ctx).await {
                    Ok((t, prep)) => {
                        last_error.clear();
                        let prev = tx.borrow().clone();
                        let clean = match (&prev, why) {
                            (_, WorkReason::Refresh) => prev.as_ref().is_none_or(|p| p.template.parents != t.parents),
                            _ => true,
                        };
                        seq += 1;
                        let bits = super::jobs::bits_at(&t, now_secs());
                        info!("stratum: work #{seq} h={} bits={bits:08x} txs={} ({why:?}, clean={clean}, light jobs {})",
                              t.height, t.transactions.len(), prep.light);
                        let _ = tx.send(Some(Arc::new(Work { seq, template: t, clean, reason: why, bits, prep })));
                    }
                    Err(e) => {
                        // Logged once per distinct reason (IBD can last hours).
                        if e != last_error {
                            warn!("stratum: no block template ({why:?}): {e}");
                            last_error = e;
                        }
                    }
                }
            }
            tokio::select! {
                evt = tip_rx.recv() => match evt {
                    Ok(tip) => {
                        debug!("stratum: tip changed to h={}", tip.height);
                        reason = Some(WorkReason::TipChanged);
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("stratum: tip broadcast lagged, dropped {n} events");
                        reason = Some(WorkReason::TipChanged);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("stratum: tip broadcast closed; the work feed stops");
                        return;
                    }
                },
                _ = refresh.tick() => reason = Some(WorkReason::Refresh),
                _ = step.tick() => {
                    let cur = tx.borrow().clone();
                    match cur {
                        None if last_try.elapsed() >= Duration::from_secs(RETRY_SECS) => {
                            reason = Some(WorkReason::Start)
                        }
                        None => {}
                        Some(w) => {
                            if let Some(bits) = stall_step_due(&w, now_secs()) {
                                seq += 1;
                                info!("stratum: work #{seq} h={} stall-relief step: bits {:08x} -> {bits:08x}",
                                      w.template.height, w.bits);
                                let _ = tx.send(Some(Arc::new(Work {
                                    seq, template: w.template.clone(), clean: true,
                                    reason: WorkReason::StallStep, bits, prep: w.prep.clone(),
                                })));
                            }
                        }
                    }
                }
            }
        }
    });
    rx
}
