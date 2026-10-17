//! Validated gossip relay of transactions (audit MEM-5 residual, NET-2 and
//! NET-4 on the transaction side; MEM-6 orphan handling).
//!
//! Blocks were already validated before gossipsub forwarded them
//! (`NetworkNode::run_validated` + a verdict channel), but `NewTransaction`
//! frames were still relayed on decode: an invalid transaction reached every
//! node at zero cost to its author, every honest relay forwarded it, and a
//! neighbour that judged it invalid could only blame the honest relay
//! (NET-4). The network loop now DEFERS the verdict on every gossiped
//! transaction to the message processor, which calls [`TxRelay::on_gossip_tx`]:
//!
//! * the frame's `tx_data` is decoded strictly (exact canonical bytes) and its
//!   claimed txid must match;
//! * the transaction goes through the SHARED admission function
//!   (`admission::admit_gated`, the same rules as RPC and reorg
//!   re-injection), cheapest checks first;
//! * the signature step — the only expensive one — runs LAST and is charged
//!   to the DELIVERING CONNECTION's token bucket ([`SIG_BUDGET_BURST`]
//!   tokens, refilled at [`SIG_BUDGET_REFILL_PER_SEC`]) AND to one node-wide
//!   bucket shared by every connection ([`NODE_SIG_BUDGET_BURST`],
//!   [`NODE_SIG_BUDGET_REFILL_PER_SEC`]). Never to the signed gossip author:
//!   one connection can sign every frame with a fresh keypair, and a fresh
//!   key was a fresh full bucket (review finding). B1-T19 (Phase 4): a token
//!   pays for one input signature OR [`SIG_BUDGET_BYTES_PER_TOKEN`] bytes
//!   hashed, and the gate is priced in both ([`signature_gate_cost`]: under
//!   sighash v2 every input hashes the whole transaction); the frame's
//!   decoding, canonical check and single wtxid hash are charged before
//!   decoding ([`frame_cost`]). The tokens are refunded when the transaction
//!   enters the pool, so a connection pays only for verification that did
//!   not lead to admission (an invalid signature, a full pool, a failed
//!   orphan re-try), and an honest relay forwarding valid traffic is never
//!   throttled. A connection out of budget is answered `Ignore` without any
//!   signature work; its bucket and its orphans are dropped when it
//!   disconnects;
//! * the verdict is `Accept` (relayed by gossipsub) only for a transaction
//!   that entered the pool; `Ignore` (not relayed, not penalised) for policy
//!   refusals, duplicates, recently rejected ids, missing inputs and rate
//!   limiting; for a malformed frame or a consensus-invalid transaction it is
//!   `Reject` (not relayed, the delivering peer takes gossipsub's
//!   invalid-message penalty) ONLY once no older release can be an honest
//!   peer on the node's chain ([`TxRelay::penalties_in_force`]): every
//!   release before this one forwards every `NewTransaction` frame on the
//!   same topic without validating it, so until the chain contains the
//!   hardening activation block (which those releases reject, see
//!   docs/CONSENSUS.md, "Relay policy") an invalid frame can come from an
//!   honest relay, and `Reject` would let an attacker get it graylisted by
//!   every upgraded peer (review finding). Such a frame is answered `Ignore`
//!   there (still not relayed, still cached in the recent-rejects filter);
//!   from the block after the activation every peer that follows the chain
//!   validates before forwarding, so an invalid frame comes from its author
//!   and `Reject` lands on it;
//! * a transaction with missing inputs is kept in the bounded orphanage
//!   ([`super::orphanage`], keyed by wtxid) and re-tried when a parent
//!   enters the pool or a block confirms one (only the children of those
//!   txids — Bitcoin Core's work set — never a scan of the whole orphanage
//!   per block). The caller withholds the verdict of the orphan's frame
//!   ([`DeferredVerdicts`], keyed by the frame's WTXID, timed from the
//!   frame's arrival) and settles it from the [`OrphanEvents`] the relay
//!   returns: `Accept` when exactly those bytes are admitted, `Reject` when
//!   their re-try proves them consensus-invalid while penalties are in force
//!   (or, once the frame left gossipsub's cache, an application-score
//!   penalty on the connection that delivered them), `Ignore` when the
//!   orphan is evicted, expires, is erased, or proves invalid before
//!   penalties are in force. Orphans are erased and re-tried after a block
//!   only for the transactions the APPLIED chain gained or lost
//!   ([`TxRelay::on_chain_moved`]; a fork-loser applies none, as for the
//!   mempool). Every admitted orphan is also re-announced by the node after
//!   [`REANNOUNCE_DELAY`], so one admitted after its frame left gossipsub's
//!   cache still propagates.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use crate::core::Transaction;
use crate::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use crate::mempool::orphanage::{OrphanAdd, OrphanLimits, TxOrphanage};
use crate::mempool::{Mempool, MAX_TX_SIZE};
use crate::network::ratelimit::TokenBuckets;
use crate::network::{GossipVerdict, GOSSIP_HISTORY_LENGTH};
use crate::storage::Storage;

/// Per-connection burst of verification tokens. A token pays for one input
/// signature check (a hybrid ML-DSA-65 + Falcon-1024 verification) or for
/// [`SIG_BUDGET_BYTES_PER_TOKEN`] bytes decoded or hashed (B1-T19:
/// [`signature_gate_cost`], [`frame_cost`]).
pub const SIG_BUDGET_BURST: u32 = 400;
/// Per-connection sustained tokens per second.
pub const SIG_BUDGET_REFILL_PER_SEC: f64 = 20.0;
/// B1-T19: bytes of digest preimage (or of frame decoded and hashed) one
/// token pays for: about the cost of one hybrid signature verification
/// (SHA3-256 runs at roughly 0.4 GB/s here: 64 KiB in about 0.15 ms).
pub const SIG_BUDGET_BYTES_PER_TOKEN: usize = 64 * 1024;
/// B1-T19: node-wide budget of verification tokens, shared by every
/// connection (the per-connection budget alone let 50 inbound connections
/// spend 50 bursts at once): burst and sustained rate.
pub const NODE_SIG_BUDGET_BURST: u32 = 4_000;
pub const NODE_SIG_BUDGET_REFILL_PER_SEC: f64 = 400.0;
/// P5-S: tokens one conservative suite-0x0003 signature check costs
/// (SLH-DSA-SHAKE-128s AND Falcon-1024), against one token for a hybrid
/// ML-DSA-65 + Falcon-1024 check. Measured on the reference machine in a
/// release build (`crates/gnb-crypto/tests/conservative_suite_cost.rs`,
/// docs/CONSENSUS.md "Conservative suite 0x0003"): about 1.8 to 2.0 ms
/// against about 0.25 ms, a ratio of 6.6 to 7.5, rounded up. Without it a
/// peer could make the node verify conservative signatures at one hybrid
/// token each, about seven times
/// the verification time the budget allows (Bitcoin Core prices by
/// verification cost the same way: BIP342's validation weight charges each
/// signature check against the witness bytes, and sigops cost weights a
/// legacy CHECKSIG four times a witness one).
pub const CONSERVATIVE_VERIFY_TOKENS: usize = 8;
/// Bytes hashed per input by the sighash v3 digest besides the shared
/// precomputed midstates (outpoint, amount and script commitments, index,
/// suite: a fixed-size preimage), rounded up.
pub const V3_PER_INPUT_PREIMAGE_BYTES: usize = 256;

/// Tokens for `bytes` decoded or hashed (rounded up).
pub fn bytes_tokens(bytes: usize) -> usize {
    bytes.div_ceil(SIG_BUDGET_BYTES_PER_TOKEN)
}

/// B1-T19: tokens charged BEFORE a gossip transaction frame is decoded —
/// its decoding, the canonical-encoding check and the one wtxid hash are
/// proportional to its size, and used to run for free, also for frames then
/// refused for an exhausted budget.
pub fn frame_cost(frame_len: usize) -> usize {
    bytes_tokens(frame_len)
}

/// B1-T19: tokens charged at the signature gate for verifying `tx` (canonical
/// wire size `wire_len`) for a block at `next_block_height` under the
/// hardening activation `act`: one per input signature, plus the bytes its
/// digests hash. Under sighash v2 (below the activation; mainnet's regime
/// until 17,500) EVERY input clones the whole transaction and re-encodes
/// and hashes it (outputs included), so the bytes are inputs × size — a
/// 1-input transaction carrying 390 kB of outputs used to cost one token and
/// hash 390 kB; under v3 the transaction is hashed once into precomputed
/// midstates plus a fixed preimage per input.
///
/// Audit F5: an input spending a policy output carries up to
/// `core::policy::MAX_POLICY_KEYS` (7) hybrid signatures, each verified
/// (`core::sighash::verify_input_signatures`), so the signature part counts
/// signatures, not inputs; P5-S: each priced by its suite's verification
/// cost ([`input_verification_tokens`]).
pub fn signature_gate_cost(tx: &Transaction, wire_len: usize, next_block_height: u64, act: u64) -> usize {
    let inputs = tx.inputs.len().max(1);
    let signatures = tx.inputs.iter()
        .map(|i| input_verification_tokens(&i.script_sig))
        .fold(0usize, usize::saturating_add)
        .max(1);
    let hashed = if crate::core::activation::is_active_at(next_block_height, act) {
        wire_len.saturating_add(inputs.saturating_mul(V3_PER_INPUT_PREIMAGE_BYTES))
    } else {
        inputs.saturating_mul(wire_len)
    };
    signatures.saturating_add(bytes_tokens(hashed))
}

/// Audit F5: the signatures verifying an input with `script_sig` can cost:
/// a policy witness's (`core::policy::AnyPolicyWitness::signatures`, exactly
/// the policy's threshold, at most `MAX_POLICY_KEYS`; decoded, not verified:
/// whether the input spends a policy output is not known before its prevout
/// is read), otherwise one. A key-hash `script_sig` that also decodes as a
/// policy witness is charged as one: it pays for at most what it could cost.
pub fn input_signature_count(script_sig: &[u8]) -> usize {
    match crate::core::policy::AnyPolicyWitness::decode(script_sig) {
        Ok(w) => w.signatures().len().max(1),
        Err(_) => 1,
    }
}
/// P5-S: the verification tokens the signatures of an input with
/// `script_sig` can cost: one per signature ([`input_signature_count`]),
/// [`CONSERVATIVE_VERIFY_TOKENS`] for each conservative suite-0x0003
/// signature (told by its envelope; decoded, not verified, like
/// [`input_signature_count`]: the input pays for at most what it could
/// cost). A policy witness is read in its widest form (every suite), a
/// key-hash witness by its exact framing.
pub fn input_verification_tokens(script_sig: &[u8]) -> usize {
    let tokens = |sig: &[u8]| match crate::crypto::split_envelope(sig) {
        Some((crate::crypto::SUITE_CONSERVATIVE, _)) => CONSERVATIVE_VERIFY_TOKENS,
        _ => 1,
    };
    match crate::core::policy::AnyPolicyWitness::decode_under(script_sig, crate::crypto::SuiteRules::HARDENING2) {
        Ok(w) => w.signatures().iter().map(|(_, s)| tokens(s)).fold(0usize, usize::saturating_add).max(1),
        Err(_) => Transaction::parse_script_sig_exact(script_sig).map_or(1, |(sig, _)| tokens(sig)),
    }
}

/// Bound on the number of connections whose budget is tracked (far above
/// the connection limit: a live connection is never evicted).
pub const SIG_BUDGET_TRACK_CAP: usize = 4096;
/// At most this many orphans are re-tried per triggering event; the rest
/// wait for the next event or the periodic sweep.
pub const MAX_ORPHANS_PER_EVENT: usize = 25;
/// At most this many orphan INPUTS (each one storage lookups and, at the
/// end, one hybrid signature check) are re-tried per triggering event —
/// at least one orphan is always tried.
pub const MAX_ORPHAN_RETRY_INPUTS_PER_EVENT: usize = 400;
/// Storage / mempool lookups the periodic sweep spends on finding ready
/// orphans (one per recorded missing parent, stopping at the first one
/// still missing); the next sweep resumes where this one stopped.
pub const MAX_SWEEP_LOOKUPS: usize = 1_000;

/// How long a deferred orphan verdict stays useful, measured from the
/// frame's ARRIVAL: gossipsub keeps an unvalidated frame for
/// [`GOSSIP_HISTORY_LENGTH`] heartbeats of 1 s (it can be gone 11 s after
/// receipt, depending on the heartbeat phase); two heartbeats of margin
/// also cover the trip through the verdict channel.
pub const DEFERRED_VERDICT_TTL: Duration = Duration::from_secs((GOSSIP_HISTORY_LENGTH as u64).saturating_sub(2));
/// Delay before the node re-announces an orphan it admitted: longer than
/// gossipsub's 30 s duplicate cache (an earlier publish of the same bytes is
/// refused as a duplicate).
pub const REANNOUNCE_DELAY: Duration = Duration::from_secs(35);
/// Bound on deferred verdicts and scheduled re-announcements.
pub const MAX_DEFERRED: usize = 1024;

/// Gossip verdict for an admission error once penalties are in force
/// ([`TxRelay::penalties_in_force`]): `Reject` only for consensus-invalid
/// transactions (no upgraded node relays them, so the penalty lands on the
/// author), `Ignore` for everything that is local policy or state
/// (duplicates, recent rejects, missing inputs, fees, replacement and chain
/// limits, rate limits, a full pool). Before that,
/// [`verdict_for_admission_error_at`] answers `Ignore` for every error.
pub fn verdict_for_admission_error(e: &AdmissionError) -> GossipVerdict {
    verdict_for_admission_error_at(e, true)
}

/// [`verdict_for_admission_error`] with the penalty gate: `penalise =
/// false` (an older, non-validating release may still be an honest peer on
/// the chain) turns `Reject` into `Ignore`.
pub fn verdict_for_admission_error_at(e: &AdmissionError, penalise: bool) -> GossipVerdict {
    if e.is_consensus_invalid() && penalise {
        GossipVerdict::Reject
    } else {
        GossipVerdict::Ignore
    }
}

/// An orphan whose re-try proved it consensus-invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedOrphan {
    pub txid:   [u8; 32],
    pub wtxid:  [u8; 32],
    /// The connection that delivered it.
    pub peer:   Option<PeerId>,
    pub reason: String,
}

/// What happened to buffered orphans during one relay call. The caller
/// settles the withheld gossip verdicts from it
/// ([`DeferredVerdicts::settle`]).
#[derive(Debug, Clone, Default)]
pub struct OrphanEvents {
    /// Orphans that entered the pool, parents first (announce them).
    pub admitted: Vec<Transaction>,
    /// Orphans whose re-try proved them consensus-invalid while penalties
    /// are in force ([`TxRelay::penalties_in_force`]; before that such an
    /// orphan is reported in `dropped`).
    pub rejected: Vec<RejectedOrphan>,
    /// Wtxids of orphans that left the orphanage without a verdict
    /// (evicted, expired, erased by a block or a disconnect, another
    /// encoding admitted, refused by policy on re-try).
    pub dropped: Vec<[u8; 32]>,
}

impl OrphanEvents {
    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty() && self.rejected.is_empty() && self.dropped.is_empty()
    }

    fn absorb(&mut self, other: OrphanEvents) {
        self.admitted.extend(other.admitted);
        self.rejected.extend(other.rejected);
        self.dropped.extend(other.dropped);
    }
}

/// What the processor must do after one gossiped transaction.
#[derive(Debug, Clone)]
pub struct GossipTxOutcome {
    /// The verdict to report for the gossip frame.
    pub verdict: GossipVerdict,
    /// The frame was malformed or its transaction consensus-invalid,
    /// whatever the verdict (`Reject` once penalties are in force, `Ignore`
    /// before).
    pub invalid: bool,
    /// Human-readable reason (logs).
    pub detail: String,
    /// The frame's transaction was buffered as an orphan: the caller should
    /// DEFER the verdict ([`DeferredVerdicts::defer`] with [`Self::wtxid`])
    /// instead of reporting `verdict` (`Ignore`), so the frame can still be
    /// relayed when the orphan is admitted.
    pub orphaned: bool,
    /// Wtxid of the frame's transaction (all zero when it did not decode).
    pub wtxid: [u8; 32],
    /// What happened to OTHER buffered orphans as a consequence (admitted
    /// because this transaction was their parent, evicted to make room, ...).
    pub orphans: OrphanEvents,
}

impl GossipTxOutcome {
    fn verdict(verdict: GossipVerdict, detail: impl Into<String>) -> Self {
        Self { verdict, invalid: false, detail: detail.into(), orphaned: false, wtxid: [0u8; 32], orphans: OrphanEvents::default() }
    }

    /// A malformed frame or a consensus-invalid transaction: `Reject` when
    /// `penalise`, else `Ignore` (see [`TxRelay::penalties_in_force`]).
    fn invalid(penalise: bool, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let (verdict, detail) = if penalise {
            (GossipVerdict::Reject, detail)
        } else {
            (GossipVerdict::Ignore, format!(
                "{detail} (not penalised: an older release that forwards transaction frames unvalidated \
                 can still be an honest peer on this chain)"))
        };
        Self { invalid: true, ..Self::verdict(verdict, detail) }
    }
}

/// Verdicts to report and connections to penalise after settling
/// [`OrphanEvents`].
#[derive(Debug)]
pub struct Settlement<O> {
    pub verdicts: Vec<(O, GossipVerdict)>,
    /// Connections that delivered a consensus-invalid orphan whose frame can
    /// no longer be answered `Reject` (send `NetworkControl::PenalizePeer`).
    pub penalize: Vec<PeerId>,
}

/// MEM-6: verdicts withheld for gossiped orphans, so the ORIGINAL frame can
/// be relayed (`Accept`) once the orphan enters the pool — gossipsub would
/// refuse a re-publish of the same bytes as a duplicate.
///
/// Keyed by the frame's WTXID, never by the txid: two frames can share a
/// txid and differ in their script_sigs. Keyed by txid, the withheld verdict
/// of a junk-signature frame was released as `Accept` when the valid
/// encoding was admitted, so an honest node forwarded an invalid transaction
/// and its neighbours penalised it (review finding). Timed from the frame's
/// arrival at the network loop (`InboundOrigin::received_at`), not from
/// when the processor got to it. Bounded by [`MAX_DEFERRED`]; `O` is the
/// frame's origin (the network's `InboundOrigin` in the node).
#[derive(Debug)]
pub struct DeferredVerdicts<O> {
    pending: HashMap<[u8; 32], (O, Instant)>,
    reannounce: VecDeque<(Instant, [u8; 32])>,
}

impl<O> Default for DeferredVerdicts<O> {
    fn default() -> Self {
        Self { pending: HashMap::new(), reannounce: VecDeque::new() }
    }
}

impl<O> DeferredVerdicts<O> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Withhold the verdict of the frame (received at `received_at`) that
    /// carried the orphan `wtxid`. Returns the origin back when it was NOT
    /// stored (frame already too old, the same bytes already pending, or the
    /// table full): the caller reports `Ignore` for it.
    pub fn defer(&mut self, wtxid: [u8; 32], origin: O, received_at: Instant, now: Instant) -> Option<O> {
        if now.saturating_duration_since(received_at) >= DEFERRED_VERDICT_TTL {
            return Some(origin);
        }
        if self.pending.len() >= MAX_DEFERRED {
            self.pending.retain(|_, (_, at)| now.saturating_duration_since(*at) < DEFERRED_VERDICT_TTL);
        }
        if self.pending.len() >= MAX_DEFERRED || self.pending.contains_key(&wtxid) {
            return Some(origin);
        }
        self.pending.insert(wtxid, (origin, received_at));
        None
    }

    /// `admitted` = `(txid, wtxid)` of transactions that entered the pool:
    /// returns the origins of the frames carrying EXACTLY those bytes that
    /// must now be reported `Accept` (still within gossipsub's cache
    /// window), and schedules a re-announcement of every admitted txid (a
    /// frame released too late is not forwarded by gossipsub).
    pub fn on_admitted(&mut self, admitted: &[([u8; 32], [u8; 32])], now: Instant) -> Vec<O> {
        let mut release = Vec::new();
        for (txid, wtxid) in admitted {
            if let Some((o, at)) = self.pending.remove(wtxid) {
                if now.saturating_duration_since(at) < DEFERRED_VERDICT_TTL {
                    release.push(o);
                }
            }
            if self.reannounce.len() < MAX_DEFERRED {
                self.reannounce.push_back((now + REANNOUNCE_DELAY, *txid));
            }
        }
        release
    }

    /// The orphan `wtxid` proved consensus-invalid: the origin of its frame
    /// if it can still be answered `Reject` (within the cache window). The
    /// entry is removed either way.
    pub fn on_rejected(&mut self, wtxid: &[u8; 32], now: Instant) -> Option<O> {
        self.pending.remove(wtxid)
            .filter(|(_, at)| now.saturating_duration_since(*at) < DEFERRED_VERDICT_TTL)
            .map(|(o, _)| o)
    }

    /// The orphan `wtxid` left the orphanage without a verdict: the origin
    /// of its frame (answer `Ignore`).
    pub fn on_dropped(&mut self, wtxid: &[u8; 32]) -> Option<O> {
        self.pending.remove(wtxid).map(|(o, _)| o)
    }

    /// Settle everything one relay call reported: `Accept` for the frames of
    /// admitted orphans, `Reject` for consensus-invalid ones still in the
    /// cache window (else a penalty on the delivering connection), `Ignore`
    /// for dropped ones.
    pub fn settle(&mut self, ev: &OrphanEvents, now: Instant) -> Settlement<O> {
        let mut out = Settlement { verdicts: Vec::new(), penalize: Vec::new() };
        for w in &ev.dropped {
            if let Some(o) = self.on_dropped(w) {
                out.verdicts.push((o, GossipVerdict::Ignore));
            }
        }
        for r in &ev.rejected {
            match self.on_rejected(&r.wtxid, now) {
                Some(o) => out.verdicts.push((o, GossipVerdict::Reject)),
                None => {
                    if let Some(p) = r.peer {
                        out.penalize.push(p);
                    }
                }
            }
        }
        let ids: Vec<([u8; 32], [u8; 32])> = ev.admitted.iter().map(|t| (t.txid(), admission::wtxid(t))).collect();
        for o in self.on_admitted(&ids, now) {
            out.verdicts.push((o, GossipVerdict::Accept));
        }
        out
    }

    /// Transactions whose re-announcement is due.
    pub fn due_reannouncements(&mut self, now: Instant) -> Vec<[u8; 32]> {
        let mut due = Vec::new();
        while let Some((at, _)) = self.reannounce.front() {
            if *at > now {
                break;
            }
            if let Some((_, t)) = self.reannounce.pop_front() {
                due.push(t);
            }
        }
        due
    }

    /// Forget deferred verdicts whose frame expired or whose orphan (by
    /// wtxid) left the orphanage. Returns their origins (answer `Ignore`).
    pub fn prune(&mut self, still_orphan: impl Fn(&[u8; 32]) -> bool, now: Instant) -> Vec<O> {
        let doomed: Vec<[u8; 32]> = self.pending.iter()
            .filter(|(w, (_, at))| now.saturating_duration_since(*at) >= DEFERRED_VERDICT_TTL || !still_orphan(w))
            .map(|(w, _)| *w)
            .collect();
        doomed.iter().filter_map(|w| self.pending.remove(w).map(|(o, _)| o)).collect()
    }

    /// Number of withheld verdicts.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// The default [`TxRelay::penalty_height`] for a hardening activation at
/// `activation_height`: the block AFTER the activation block, the first next
/// block whose parent chain no older release accepts. Saturating, so
/// `activation::NEVER` never penalises.
pub fn default_penalty_height(activation_height: u64) -> u64 {
    activation_height.saturating_add(1)
}

/// Per-node transaction-relay state: per-connection signature budgets and
/// the orphanage. Owned by the message processor.
pub struct TxRelay {
    budget: TokenBuckets<Option<PeerId>>,
    /// B1-T19: the node-wide verification budget (one key).
    node_budget: TokenBuckets<()>,
    orphans: TxOrphanage<PeerId>,
    /// Round-robin position of the periodic sweep (an orphan sequence
    /// number).
    sweep_cursor: u64,
    /// The smallest next-block height at which invalid transaction frames
    /// are penalised ([`Self::penalties_in_force`]).
    penalty_height: u64,
}

impl Default for TxRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl TxRelay {
    pub fn new() -> Self {
        Self::with_limits(SIG_BUDGET_BURST, SIG_BUDGET_REFILL_PER_SEC, OrphanLimits::default())
    }

    /// Explicit budget / orphanage bounds (tests).
    pub fn with_limits(burst: u32, refill_per_sec: f64, orphan_limits: OrphanLimits) -> Self {
        Self {
            budget: TokenBuckets::new(burst, refill_per_sec, SIG_BUDGET_TRACK_CAP),
            node_budget: TokenBuckets::new(NODE_SIG_BUDGET_BURST, NODE_SIG_BUDGET_REFILL_PER_SEC, 1),
            orphans: TxOrphanage::new(orphan_limits),
            sweep_cursor: 0,
            penalty_height: default_penalty_height(crate::core::activation::hardening_activation_height()),
        }
    }

    /// Replace the node-wide verification budget (tests).
    pub fn with_node_budget(mut self, burst: u32, refill_per_sec: f64) -> Self {
        self.node_budget = TokenBuckets::new(burst, refill_per_sec, 1);
        self
    }

    /// Take `n` tokens from the connection's budget AND the node-wide one,
    /// all or nothing.
    fn take_tokens(&mut self, peer: Option<PeerId>, n: usize, now: Instant) -> bool {
        if !self.budget.try_take_n_at(peer, n, now) {
            return false;
        }
        if !self.node_budget.try_take_n_at((), n, now) {
            self.budget.refund_n(peer, n);
            return false;
        }
        true
    }

    fn refund_tokens(&mut self, peer: Option<PeerId>, n: usize) {
        self.budget.refund_n(peer, n);
        self.node_budget.refund_n((), n);
    }

    /// Penalise invalid frames from next-block height `height` on instead of
    /// the default ([`default_penalty_height`] of the process-wide hardening
    /// activation, read at construction). `0` penalises at every height:
    /// tests of the post-rollout verdicts on chains below the activation.
    pub fn with_penalty_height(mut self, height: u64) -> Self {
        self.penalty_height = height;
        self
    }

    /// The smallest next-block height at which invalid frames are penalised.
    pub fn penalty_height(&self) -> u64 {
        self.penalty_height
    }

    /// True iff a malformed frame or a consensus-invalid transaction judged
    /// for the block at `next_block_height` is answered `Reject` (and an
    /// invalid orphan penalised): iff the node's chain already contains the
    /// hardening activation block, i.e. `next_block_height > activation`.
    ///
    /// Why (review finding): every release before this one forwards every
    /// `NewTransaction` frame without validating it, on the same topic
    /// (`gnb/txs/1`). `Reject` charges gossipsub's invalid-message penalty to
    /// the delivering peer and to every peer that delivered a duplicate;
    /// with the transaction topic's weights about six invalid frames within
    /// a minute or two push a peer below the graylist threshold, after which
    /// all its gossip, blocks included, is ignored. While such a release can
    /// be an honest peer on the chain, an attacker could have every upgraded
    /// node graylist every non-upgraded one by sending it a few garbage
    /// frames, splitting the network during the rollout. Those releases
    /// cannot accept the activation block (tagged Merkle root, sighash v3,
    /// docs/CONSENSUS.md), so from the block after it every peer on the
    /// chain validates transaction frames before forwarding them and an
    /// invalid frame is delivered only by its author. Before that the frame
    /// is answered `Ignore`: still never forwarded, still remembered in the
    /// recent-rejects filter, and still charged to the delivering
    /// connection's signature budget.
    pub fn penalties_in_force(&self, next_block_height: u64) -> bool {
        next_block_height >= self.penalty_height
    }

    /// The orphanage (read-only).
    pub fn orphans(&self) -> &TxOrphanage<PeerId> {
        &self.orphans
    }

    /// Number of connections whose signature budget is tracked.
    pub fn budgets_tracked(&self) -> usize {
        self.budget.tracked()
    }

    /// Judge one gossiped `NewTransaction { txid: claimed_txid, tx_data }`
    /// delivered by the connection `peer` (the gossip `propagation_source`;
    /// never the self-chosen gossip author). `next_block_height` is the
    /// height of the next block (`admission::pool_next_height`: the node's
    /// next template height, the one height every admission uses).
    #[allow(clippy::too_many_arguments)]
    pub fn on_gossip_tx(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        next_block_height: u64,
        claimed_txid: &[u8; 32],
        tx_data: &[u8],
        peer: Option<PeerId>,
        now: Instant,
        now_unix: u64,
    ) -> GossipTxOutcome {
        let mut events = OrphanEvents { dropped: self.orphans.expire(now_unix), ..Default::default() };
        let done = |mut o: GossipTxOutcome, events: OrphanEvents| {
            o.orphans = events;
            o
        };
        // Policy, not invalidity: a > MAX_TX_SIZE transaction can be valid
        // in a block. Refused before decoding it.
        if tx_data.len() > MAX_TX_SIZE {
            return done(GossipTxOutcome::verdict(GossipVerdict::Ignore,
                format!("transaction of {} bytes exceeds the relay limit {}", tx_data.len(), MAX_TX_SIZE)), events);
        }
        let penalise = self.penalties_in_force(next_block_height);
        // B1-T19: decoding, the canonical check and the wtxid hash cost time
        // in proportion to the frame; they are charged first (refunded with
        // the rest if the transaction is admitted), so a connection out of
        // budget costs nothing but this check.
        let pre = frame_cost(tx_data.len());
        if !self.take_tokens(peer, pre, now) {
            return done(GossipTxOutcome::verdict(GossipVerdict::Ignore, format!(
                "verification budget of {} exhausted (frame of {} bytes)",
                peer.map(|p| p.to_string()).unwrap_or_else(|| "an unknown connection".into()), tx_data.len())), events);
        }
        let tx = match admission::decode_tx_canonical(tx_data) {
            Ok(t) => t,
            Err(e) => return done(GossipTxOutcome::invalid(penalise, format!("malformed transaction: {}", e)), events),
        };
        let txid = tx.txid();
        if txid != *claimed_txid {
            return done(GossipTxOutcome::invalid(penalise,
                format!("frame claims txid {} but the transaction hashes to {}",
                    hex::encode(&claimed_txid[..8]), hex::encode(&txid[..8]))), events);
        }
        // B1-T19: the wtxid once per frame, from the canonical bytes received.
        let wtxid = admission::wtxid_of_canonical_bytes(tx_data);
        if self.orphans.contains(&wtxid) {
            let mut o = GossipTxOutcome::verdict(GossipVerdict::Ignore, "already buffered as an orphan");
            o.wtxid = wtxid;
            return done(o, events);
        }
        let policy = AdmissionPolicy::relay(next_block_height);
        let mut out = match self.admit_charged(store, mempool, tx.clone(), &wtxid, tx_data.len(), &policy, peer, now) {
            Ok(()) => {
                self.refund_tokens(peer, pre);
                // Other encodings of this txid can never be admitted now.
                events.dropped.extend(self.orphans.erase_txid(&txid));
                let mut budget = MAX_ORPHAN_RETRY_INPUTS_PER_EVENT;
                let resolved = self.resolve_orphans(store, mempool, &policy, vec![txid], now, &mut budget);
                events.absorb(resolved);
                GossipTxOutcome::verdict(GossipVerdict::Accept, "admitted")
            }
            Err(AdmissionError::MissingInputs(m)) => {
                // Inputs are counted first: `missing_parents` reads two
                // indexes per input.
                let (orphaned, detail) = if tx.inputs.len() > crate::mempool::orphanage::MAX_ORPHAN_INPUTS {
                    (false, format!("orphan with {} inputs not buffered (max {})",
                        tx.inputs.len(), crate::mempool::orphanage::MAX_ORPHAN_INPUTS))
                } else {
                    let missing = admission::missing_parents(store, mempool, &tx);
                    match self.orphans.add(tx, tx_data.len(), peer, missing, now_unix) {
                        OrphanAdd::Inserted { evicted } => {
                            events.dropped.extend(evicted);
                            (true, format!("orphan: {}", m))
                        }
                        other => (false, format!("orphan not buffered ({:?}): {}", other, m)),
                    }
                };
                let mut o = GossipTxOutcome::verdict(GossipVerdict::Ignore, detail);
                o.orphaned = orphaned;
                o
            }
            Err(e) if e.is_consensus_invalid() => GossipTxOutcome::invalid(penalise, e.to_string()),
            Err(e) => GossipTxOutcome::verdict(verdict_for_admission_error_at(&e, penalise), e.to_string()),
        };
        out.wtxid = wtxid;
        done(out, events)
    }

    /// After ONE block was connected to the applied chain (no reorg):
    /// [`Self::on_chain_moved`] with `block_txs` connected and nothing
    /// disconnected.
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_connected(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        next_block_height: u64,
        block_txs: &[Transaction],
        now: Instant,
        now_unix: u64,
    ) -> OrphanEvents {
        self.on_chain_moved(store, mempool, next_block_height, block_txs, &[], now, now_unix)
    }

    /// After the APPLIED chain moved (`accept::ChainMove`): `connected_txs`
    /// are the transactions of the blocks it gained, `disconnected_txs` the
    /// non-coinbase transactions of the blocks it lost (re-injected into the
    /// pool by the acceptance pipeline). Drops orphans the connected blocks
    /// confirmed (in any encoding) or conflict with, expires stale ones, then
    /// re-tries ONLY the orphans waiting on one of those transactions
    /// (Bitcoin Core's work set; the review found the previous full scan of
    /// the orphanage — one storage read per orphan input — on every block's
    /// relay path): a confirmed parent, or a disconnected one now back in
    /// the pool. Orphans whose parent arrived through another path are found
    /// by the periodic [`Self::retry_orphans`] sweep.
    ///
    /// Review finding: the caller passed the ARRIVING block's transactions
    /// for every accepted block, fork-losers and merge candidates included,
    /// and ignored the other blocks of a reorg. Under the selected-chain-only
    /// ledger such a block applies nothing, so a valid orphan whose input a
    /// side block spent (or that a side block contained) was erased while
    /// its input was still unspent; only the applied chain's movement counts
    /// now, exactly as for the mempool (`accept::update_mempool_after_connect`).
    #[allow(clippy::too_many_arguments)]
    pub fn on_chain_moved(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        next_block_height: u64,
        connected_txs: &[Transaction],
        disconnected_txs: &[Transaction],
        now: Instant,
        now_unix: u64,
    ) -> OrphanEvents {
        let confirmed: Vec<[u8; 32]> = connected_txs.iter().map(|t| t.txid()).collect();
        let spent: Vec<([u8; 32], u32)> = connected_txs.iter()
            .filter(|t| !t.is_coinbase())
            .flat_map(|t| t.inputs.iter().map(|i| (i.prev_txid, i.prev_index)))
            .collect();
        let mut events = OrphanEvents { dropped: self.orphans.erase_for_block(&spent, &confirmed), ..Default::default() };
        events.dropped.extend(self.orphans.expire(now_unix));
        let policy = AdmissionPolicy::relay(next_block_height);
        let mut budget = MAX_ORPHAN_RETRY_INPUTS_PER_EVENT;
        let mut roots = confirmed;
        roots.extend(disconnected_txs.iter().map(|t| t.txid()));
        let resolved = self.resolve_orphans(store, mempool, &policy, roots, now, &mut budget);
        events.absorb(resolved);
        events
    }

    /// Periodic sweep: expire stale orphans and re-try those whose parents
    /// became available through any path (miner, RPC, a block connected by
    /// a reorg). Cheap: one lookup per recorded missing parent, stopping at
    /// the first still missing, at most [`MAX_SWEEP_LOOKUPS`] lookups and
    /// [`MAX_ORPHANS_PER_EVENT`] ready orphans per sweep, round-robin from
    /// where the previous sweep stopped.
    pub fn retry_orphans(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        next_block_height: u64,
        now: Instant,
        now_unix: u64,
    ) -> OrphanEvents {
        let mut events = OrphanEvents { dropped: self.orphans.expire(now_unix), ..Default::default() };
        let policy = AdmissionPolicy::relay(next_block_height);
        let mut lookups = 0usize;
        let mut ready: Vec<(u64, [u8; 32])> = Vec::new();
        let mut resume_at = None;
        for (seq, w) in self.orphans.round_robin_from(self.sweep_cursor) {
            if ready.len() >= MAX_ORPHANS_PER_EVENT || lookups >= MAX_SWEEP_LOOKUPS {
                resume_at = Some(seq);
                break;
            }
            let Some(o) = self.orphans.get(&w) else { continue };
            let mut all_there = true;
            for p in &o.missing_parents {
                lookups += 1;
                if !admission::parent_available(store, mempool, p) {
                    all_there = false;
                    break;
                }
            }
            if all_there {
                ready.push((seq, w));
            }
        }
        if let Some(s) = resume_at {
            self.sweep_cursor = s;
        }
        let mut budget = MAX_ORPHAN_RETRY_INPUTS_PER_EVENT;
        let mut admitted_ids = Vec::new();
        for (i, (seq, w)) in ready.iter().enumerate() {
            let inputs = self.orphans.get(w).map(|o| o.tx.inputs.len()).unwrap_or(0);
            if i > 0 && inputs > budget {
                // Out of budget: the next sweep resumes at this ready orphan.
                self.sweep_cursor = *seq;
                break;
            }
            budget = budget.saturating_sub(inputs);
            if let Some(tx) = self.try_orphan(store, mempool, &policy, w, now, &mut events) {
                admitted_ids.push(tx.txid());
                events.admitted.push(tx);
            }
        }
        let resolved = self.resolve_orphans(store, mempool, &policy, admitted_ids, now, &mut budget);
        events.absorb(resolved);
        events
    }

    /// The connection to `peer` closed: forget its signature budget and drop
    /// the orphans it delivered (Bitcoin Core's `EraseForPeer`).
    pub fn on_peer_disconnected(&mut self, peer: PeerId) -> OrphanEvents {
        self.budget.remove(&Some(peer));
        OrphanEvents { dropped: self.orphans.erase_peer(Some(peer)), ..Default::default() }
    }

    /// Admission with the delivering connection's and the node-wide
    /// verification budgets as the gate (B1-T19: priced by
    /// [`signature_gate_cost`], in signatures AND bytes hashed); the tokens
    /// are refunded when the transaction enters the pool. `tx_wtxid` is the
    /// transaction's wtxid, `wire_len` its canonical size.
    #[allow(clippy::too_many_arguments)]
    fn admit_charged(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        tx: Transaction,
        tx_wtxid: &[u8; 32],
        wire_len: usize,
        policy: &AdmissionPolicy,
        peer: Option<PeerId>,
        now: Instant,
    ) -> Result<(), AdmissionError> {
        let mut charged = 0usize;
        let act = crate::core::activation::hardening_activation_height();
        let result = {
            let budget = &mut self.budget;
            let node_budget = &mut self.node_budget;
            let charged = &mut charged;
            let mut gate = |t: &Transaction| -> Result<(), AdmissionError> {
                let cost = signature_gate_cost(t, wire_len, policy.next_block_height, act);
                if !budget.try_take_n_at(peer, cost, now) {
                    return Err(AdmissionError::RateLimited(format!(
                        "signature budget of {} exhausted ({} token(s) asked: {} input signature(s), {} bytes)",
                        peer.map(|p| p.to_string()).unwrap_or_else(|| "an unknown connection".into()),
                        cost, t.inputs.len(), wire_len)));
                }
                if !node_budget.try_take_n_at((), cost, now) {
                    budget.refund_n(peer, cost);
                    return Err(AdmissionError::RateLimited(format!(
                        "node-wide signature budget exhausted ({cost} token(s) asked)")));
                }
                *charged = cost;
                Ok(())
            };
            admission::admit_gated_with_wtxid(store, mempool, tx, tx_wtxid, policy, &mut gate).map(|_| ())
        };
        if result.is_ok() && charged > 0 {
            self.refund_tokens(peer, charged);
        }
        result
    }

    /// Re-try the orphan `wtxid` if all its inputs are now available.
    /// Returns the transaction when it entered the pool; records rejections
    /// and drops in `events`. An orphan still missing an input, or whose
    /// delivering connection is out of budget, is kept (same deadline).
    fn try_orphan(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        policy: &AdmissionPolicy,
        wtxid: &[u8; 32],
        now: Instant,
        events: &mut OrphanEvents,
    ) -> Option<Transaction> {
        let o = self.orphans.get(wtxid)?;
        if admission::has_missing_input(store, mempool, &o.tx) {
            return None;
        }
        let o = self.orphans.remove(wtxid)?;
        match self.admit_charged(store, mempool, o.tx.clone(), &o.wtxid, o.bytes, policy, o.peer, now) {
            Ok(()) => {
                events.dropped.extend(self.orphans.erase_txid(&o.txid));
                Some(o.tx)
            }
            Err(AdmissionError::MissingInputs(_)) | Err(AdmissionError::RateLimited(_)) => {
                let missing = admission::missing_parents(store, mempool, &o.tx);
                let missing = if missing.is_empty() { o.missing_parents.clone() } else { missing };
                match self.orphans.add_with_expiry(o.tx, o.bytes, o.peer, missing, o.expires_at) {
                    OrphanAdd::Inserted { evicted } => events.dropped.extend(evicted),
                    OrphanAdd::Duplicate | OrphanAdd::TooLarge => events.dropped.push(*wtxid),
                }
                None
            }
            Err(e) if e.is_consensus_invalid() => {
                if self.penalties_in_force(policy.next_block_height) {
                    log::debug!("orphan {} invalid on re-try: {}", hex::encode(&wtxid[..8]), e);
                    events.rejected.push(RejectedOrphan { txid: o.txid, wtxid: *wtxid, peer: o.peer, reason: e.to_string() });
                } else {
                    // Its frame is answered Ignore and its connection is not
                    // penalised: see `penalties_in_force`.
                    log::debug!("orphan {} invalid on re-try (not penalised before the activation block): {}",
                        hex::encode(&wtxid[..8]), e);
                    events.dropped.push(*wtxid);
                }
                None
            }
            Err(e) => {
                log::debug!("orphan {} dropped on re-try: {}", hex::encode(&wtxid[..8]), e);
                events.dropped.push(*wtxid);
                None
            }
        }
    }

    /// Breadth-first: for every txid that just entered the pool (or a
    /// block), re-try the orphans waiting on it — at most
    /// [`MAX_ORPHANS_PER_EVENT`] orphans and `inputs_budget` inputs in total
    /// (at least one orphan when the budget is untouched). What is left
    /// waits for the next event or the sweep.
    fn resolve_orphans(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        policy: &AdmissionPolicy,
        roots: Vec<[u8; 32]>,
        now: Instant,
        inputs_budget: &mut usize,
    ) -> OrphanEvents {
        let mut events = OrphanEvents::default();
        let untouched = *inputs_budget == MAX_ORPHAN_RETRY_INPUTS_PER_EVENT;
        let mut queue: VecDeque<[u8; 32]> = roots.into();
        let mut tried: BTreeSet<[u8; 32]> = BTreeSet::new();
        while let Some(parent) = queue.pop_front() {
            for child in self.orphans.waiting_on(&parent) {
                if tried.contains(&child) {
                    continue;
                }
                if tried.len() >= MAX_ORPHANS_PER_EVENT {
                    return events;
                }
                let inputs = self.orphans.get(&child).map(|o| o.tx.inputs.len()).unwrap_or(0);
                if inputs > *inputs_budget && !(untouched && tried.is_empty()) {
                    return events;
                }
                tried.insert(child);
                *inputs_budget = inputs_budget.saturating_sub(inputs);
                if let Some(tx) = self.try_orphan(store, mempool, policy, &child, now, &mut events) {
                    queue.push_back(tx.txid());
                    events.admitted.push(tx);
                }
            }
        }
        events
    }
}
