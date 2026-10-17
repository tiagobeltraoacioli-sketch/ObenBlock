//! Block-ingress policy for the message processor (audit fixes POW-2, NET-2,
//! POW-3, POW-4, POW-8, NET-6, DAG-7).
//!
//! `main.rs` is a binary that integration tests cannot link, so every decision
//! the processor makes about an inbound block — before any expensive work —
//! lives here as a small pure function or a self-contained data structure,
//! unit- and integration-tested in isolation.
//!
//! NONE of this changes consensus validity. A block valid on the chain stays
//! valid (it still goes through `accept_block`); these are relay, buffering,
//! ordering and anti-DoS policies of one node:
//!
//! * peer-supplied integers are compared with saturating arithmetic only
//!   (a `NewBlock { height: u64::MAX }` used to panic the processor — POW-2);
//! * cheap checks run before the 64 MiB proof of work, and an orphan (parents
//!   unknown, so its expected bits cannot be derived) must carry bits no
//!   easier than an anti-DoS floor derived from OUR selected tip and the wall
//!   clock before its PoW is even evaluated (NET-2 / POW-3 / POW-4);
//! * the orphan pool is bounded by bytes and per peer and evicts by ARRIVAL
//!   order, never by a self-declared height; the first copy of an id wins
//!   (POW-4 / POW-8);
//! * the IBD latch is set only by work-backed evidence (a full-difficulty
//!   orphan claiming to be well ahead of us), never by a tip claim (NET-6);
//! * POW-3 (node-local anti-DoS half): a block whose parents we hold is only
//!   stored and processed if its chain can come within
//!   [`ANTI_DOS_WINDOW_BLOCKS`] selected-chain blocks of work of our tip, or
//!   if the proof-of-work-verified orphans announced on top of it (summed,
//!   each once, buffered or evicted) bring it there (see [`work_admission`]).
//!   A chain that carries the work is accepted, so the final outcome for
//!   honest data is unchanged;
//! * a copy of a block already in the DAG is processed only if a body of it
//!   is wanted (`accept::awaits_body`: its body was rejected for a
//!   witness-dependent reason, or a connect — or an operator override —
//!   needs a body that is missing, pruned ones included, audit DAG-6) and it
//!   is the answer to one of this node's directed pulls; it then goes through
//!   `accept_block`'s body-replacement path (bound to the header height the
//!   DAG parents imply, the expected bits, the witness-root rules and the
//!   proof). Any other copy is known before any work.
//!
//! [`BlockIngress`] is the processor's per-block core (orphan pool,
//! missing-parent tracker, deep-insertion budget, the decisions above, the
//! call into `accept_block` and the iterative orphan drain). `main.rs` feeds
//! it decoded gossip / sync blocks and acts on the outcome (network requests,
//! frontier, IBD latch, gossip verdict); the integration tests drive the
//! same core.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use log::{debug, info, warn};
use parking_lot::RwLock;
use tokio::sync::broadcast;

use crate::coherence::ShieldedPool;
use crate::consensus::{BlockHash, GhostDAG};
use crate::core;
use crate::mempool::Mempool;
use crate::network::GossipVerdict;
use crate::pow::verifier::{PowJob, PowLimits, PowScheduler, PowSource, StartNext};
use crate::rpc::NodeState;
use crate::storage::Storage;
use crate::sync::parent_fetch::ParentFetchTracker;
use crate::tip::TipChanged;

// ── POW-2: peer-supplied heights ─────────────────────────────────────────────

/// An UNSOLICITED (gossip) `NewBlock` claiming a height more than this far
/// above our selected tip is dropped before any decoding or arithmetic. A node
/// that far behind syncs by directed pulls; a gossiped block from the network
/// tip would only be an orphan waiting on a thousand-block parent chain.
pub const MAX_UNSOLICITED_HEIGHT_LOOKAHEAD: u64 = core::CHECKPOINT_DEPTH;

/// POW-2: `height > tip_h + lookahead`, overflow-free.
pub fn unsolicited_height_too_far_ahead(height: u64, tip_h: u64) -> bool {
    height > tip_h.saturating_add(MAX_UNSOLICITED_HEIGHT_LOOKAHEAD)
}

/// Outcome of the backfill-flood guard (see `main.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackfillDecision {
    /// Not deep below the tip: continue.
    Pass,
    /// Deep below the tip and nobody asked for it: drop cheaply.
    DropUnsolicitedDeep,
    /// Deep below the tip but awaited as the parent of a buffered orphan:
    /// may continue, subject to the deep-backfill budget.
    AwaitedDeep,
}

/// The backfill-flood guard, overflow-free (POW-2: this expression used to be
/// `height + CHECKPOINT_DEPTH < tip_h`, which panicked on `height = u64::MAX`
/// under `overflow-checks = true`).
pub fn backfill_decision(height: u64, tip_h: u64, awaited: bool) -> BackfillDecision {
    let deep = tip_h > core::CHECKPOINT_DEPTH
        && height.saturating_add(core::CHECKPOINT_DEPTH) < tip_h;
    match (deep, awaited) {
        (false, _) => BackfillDecision::Pass,
        (true, false) => BackfillDecision::DropUnsolicitedDeep,
        (true, true) => BackfillDecision::AwaitedDeep,
    }
}

/// DAG-7 / POW-3: global budget of deep (more than `CHECKPOINT_DEPTH` below
/// the tip) MERGE-BACKED block insertions (see [`WorkAdmission::MergeBacked`]).
/// Inserting one deep block costs a reachability reindex under the DAG write
/// lock, and a single crafted orphan merging a deep block makes it needed, so
/// these insertions are rationed. A deep block backed by the work of its own
/// announced chain (`ChainBacked`, an honest deep fork) does not use it. An
/// honest node needs it almost never; a denied block is simply re-requested
/// by the orphan sweep.
pub struct DeepBackfillBudget {
    bucket: crate::network::ratelimit::TokenBuckets<()>,
}

/// Burst / refill (one per 30 s) of [`DeepBackfillBudget`].
pub const DEEP_BACKFILL_BURST: u32 = 4;
pub const DEEP_BACKFILL_REFILL_PER_SEC: f64 = 1.0 / 30.0;

impl Default for DeepBackfillBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl DeepBackfillBudget {
    pub fn new() -> Self {
        Self {
            bucket: crate::network::ratelimit::TokenBuckets::new(
                DEEP_BACKFILL_BURST,
                DEEP_BACKFILL_REFILL_PER_SEC,
                1,
            ),
        }
    }

    pub fn allow_at(&mut self, now: Instant) -> bool {
        self.bucket.allow_at((), now)
    }
}

// ── NET-2 / POW-3 / POW-4: the orphan anti-DoS work floor ────────────────────

/// An orphan may claim a target at most `2^ORPHAN_WORK_FLOOR_SHIFT` times
/// easier than the reference target (≈ 4 ASERT half-lives ≈ 8 h, or ~960
/// blocks of depth on a chain running on schedule).
pub const ORPHAN_WORK_FLOOR_SHIFT: u32 = 4;

/// Reference target for "now": the target a child of our selected tip (height
/// `tip_h + 1`) would have if its parent were stamped `now_unix` — the EASIEST
/// target any honest block extending our chain can carry right now (honest
/// blocks further ahead, or with earlier parents, are harder). Never easier
/// than the pow limit of height `tip_h + 1` (`core::block_rules::
/// pow_limit_bits_at`: the genesis target at/after the hardening activation,
/// audit POW-3), which it falls back to (fail open: this is anti-DoS, never
/// consensus).
pub fn reference_target(tip_h: u64, now_unix: u64) -> [u8; 32] {
    let height = tip_h.saturating_add(1);
    let limit = core::Block::pow_limit_target_for_height(height);
    match core::expected_bits(now_unix, height) {
        Ok(bits) => {
            let t = core::bits_to_target(bits);
            if t == [0u8; 32] || t > limit { limit } else { t }
        }
        Err(_) => limit,
    }
}

/// `target × 2^shift`, saturating at the pow limit of a block at `height`
/// (`core::Block::pow_limit_target_for_height`, i.e. `core::block_rules::
/// pow_limit_bits_at` under the process-wide activation height).
pub fn ease_target(target: &[u8; 32], shift: u32, height: u64) -> [u8; 32] {
    ease_target_to(target, shift, &core::Block::pow_limit_target_for_height(height))
}

/// `target × 2^shift`, saturating at the target `limit`.
pub fn ease_target_to(target: &[u8; 32], shift: u32, limit: &[u8; 32]) -> [u8; 32] {
    use primitive_types::U256;
    let limit = U256::from_big_endian(limit);
    let t = U256::from_big_endian(target);
    if t.is_zero() {
        return limit.to_big_endian();
    }
    let eased = if t.leading_zeros() < shift { limit } else { (t << shift as usize).min(limit) };
    eased.to_big_endian()
}

/// The admission floor for an orphan that claims header height
/// `orphan_height`: [`reference_target`] eased by [`ORPHAN_WORK_FLOOR_SHIFT`],
/// capped at the pow limit of `orphan_height` — the limit `validate_pow`
/// checks the orphan's own proof against. The cap is evaluated at the
/// orphan's OWN claimed height, never at the tip's next height: after the
/// tip passed the hardening activation, a heavier fork that branched below it
/// delivers orphans at pre-activation heights whose legal bits can be easier
/// than the genesis target (the legacy pow limit applies there); capping
/// their floor at the genesis target would drop them, break the fork's orphan
/// chain and keep the node on the lighter chain (review of the P3 merge).
/// The 16-fold easing of the reference still bounds how cheap any orphan can
/// be.
#[allow(dead_code)] // tests only (the ingress core uses `orphan_floor_from`); the node binary compiles this module too
pub fn orphan_admission_floor(tip_h: u64, now_unix: u64, orphan_height: u64) -> [u8; 32] {
    orphan_floor_from(&reference_target(tip_h, now_unix), orphan_height)
}

/// [`orphan_admission_floor`] from a given reference target (the ingress
/// core's: [`reference_target`], or the POW-4 test seam
/// `BlockIngress::with_reference_target`).
pub fn orphan_floor_from(reference: &[u8; 32], orphan_height: u64) -> [u8; 32] {
    ease_target(reference, ORPHAN_WORK_FLOOR_SHIFT, orphan_height)
}

/// The reference target ([`reference_target`], computed for the tip's next
/// height `ref_height`) re-expressed for a block at `height`: across the
/// GnB-SMH v1 -> v3 switch (`core::powit_height()`) honest v3 targets are
/// `2^POW_V3_DIFFICULTY_SHIFT` times harder than v1 targets of the same work
/// (`core::adjust_bits_for_algo`; `core::block_work` divides their work by
/// the same factor). Without this a v1-height orphan judged against a v3
/// reference (a fork that branches below the switch) would meet a floor four
/// times stricter in work, and a v3 orphan against a v1 reference one four
/// times more lenient. Equal algorithms: unchanged.
pub fn reference_for_height(reference: &[u8; 32], ref_height: u64, height: u64) -> [u8; 32] {
    reference_for_height_with(reference, ref_height, height, core::powit_height())
}

/// [`reference_for_height`] for an explicit v3 activation height (testable).
pub fn reference_for_height_with(reference: &[u8; 32], ref_height: u64, height: u64, v3_activation: u64) -> [u8; 32] {
    use primitive_types::U256;
    let shift = core::POW_V3_DIFFICULTY_SHIFT as usize;
    match (core::pow_algo_with(ref_height, v3_activation), core::pow_algo_with(height, v3_activation)) {
        (gnb_smh::Algo::V3, gnb_smh::Algo::V1) => {
            let t = U256::from_big_endian(reference);
            if t.leading_zeros() < shift as u32 { [0xFF; 32] } else { (t << shift).to_big_endian() }
        }
        (gnb_smh::Algo::V1, gnb_smh::Algo::V3) => {
            (U256::from_big_endian(reference) >> shift).max(U256::one()).to_big_endian()
        }
        _ => *reference,
    }
}

/// `target(bits) <= floor`. Malformed bits never meet any floor. Cheap: no
/// proof-of-work evaluation.
pub fn bits_meet_floor(bits: u32, floor: &[u8; 32]) -> bool {
    match gnb_smh::difficulty::try_bits_to_target(bits) {
        Ok(t) => t.0 <= *floor,
        Err(_) => false,
    }
}

// ── POW-3 (Phase 4): minimum chain work and unrequested blocks ───────────────
//
// Bitcoin Core's defences for a node that is behind (initial block download,
// or a node that was offline): `nMinimumChainWork` — the chain work of a
// recent block of the real chain, raised at every release — and the
// `AcceptBlock` rule for UNREQUESTED blocks (validation.cpp): a block nobody
// asked for is processed only if it has at least the work of the tip, is not
// too far ahead of it, and, while the node is below the minimum chain work,
// only if its own chain work reaches it. GnB's anti-DoS work rule
// (`work_admission`) is relative to the node's own tip, so on its own it does
// not protect a node whose tip is far behind the network: an attacker mines
// one block A on that tip stamped "now", and every child of A then has
// near-minimum ASERT difficulty (absolute schedule) and the work rule's
// threshold is the victim's own (low) tip work.

/// Minimum chain work (blue work, `u128`) of mainnet: the blue work of a
/// block of the real chain somewhat below its tip at release time, below
/// which a node considers itself in initial block download (Bitcoin Core's
/// `nMinimumChainWork`).
///
/// It IS `core::MIN_CHAIN_WORK` (7,000,000 = 0x6acfc0: derived from the
/// mainnet reading of docs/MAINNET-READINESS.md §1, tip height 8,302 and
/// blue work 7,782,451 on 2026-10-14, see its documentation), the one
/// constant a release raises. It gates this node's initial-block-download
/// state, its unrequested-block rule, `submitblock`, and whether its
/// selected tip is its chain of record ([`below_minimum_chain_work`]: block
/// templates, mining, the frontier it advertises), nothing else: no
/// verdict on a block, no GhostDAG data and no fork choice (the PoWit
/// finalized checkpoint included) reads it, so a node with another value
/// (`--minimumchainwork`, an older release, main's 0) reaches the same
/// verdicts on the same blocks. The release process raises it
/// (docs/RUNNING.md, "Initial sync and minimum chain work";
/// `tools/release/min_chain_work.py` reads the blue work of the
/// selected-chain block 2,880 blocks, about a day, below the tip from two or
/// more independent nodes and prints the value to set). A value the real
/// chain does not reach would keep every new node in initial block download
/// (the node warns, [`MinimumWorkWatch`]); operators can lower it at run
/// time with `--minimumchainwork`.
pub const MAINNET_MINIMUM_CHAIN_WORK: u128 = core::MIN_CHAIN_WORK;
/// Testnet: 0 (a public test network is reset at will; no requirement).
pub const TESTNET_MINIMUM_CHAIN_WORK: u128 = 0;
/// Regtest: 0 (Bitcoin Core's regtest value).
pub const REGTEST_MINIMUM_CHAIN_WORK: u128 = 0;

/// The default minimum chain work of a network.
pub const fn default_minimum_chain_work(net: core::activation::ActivationNetwork) -> u128 {
    match net {
        core::activation::ActivationNetwork::Mainnet => MAINNET_MINIMUM_CHAIN_WORK,
        core::activation::ActivationNetwork::Testnet => TESTNET_MINIMUM_CHAIN_WORK,
        core::activation::ActivationNetwork::Regtest => REGTEST_MINIMUM_CHAIN_WORK,
    }
}

/// Parse a `--minimumchainwork` value: hexadecimal, as Bitcoin Core's
/// `-minimumchainwork=<hex>` (an optional `0x` prefix, at most 32 hex digits
/// once leading zeros are dropped: blue work is a `u128`).
pub fn parse_minimum_chain_work(s: &str) -> Result<u128, String> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid minimum chain work {s:?}: expected a hexadecimal number"));
    }
    let digits = t.trim_start_matches('0');
    if digits.len() > 32 {
        return Err(format!("minimum chain work {s:?} exceeds the 128-bit blue work range"));
    }
    if digits.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(digits, 16).map_err(|e| format!("invalid minimum chain work {s:?}: {e}"))
}

/// The minimum chain work a node runs with, as chosen at start-up:
/// `--minimumchainwork` when given, else the network's default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimumChainWorkSetting {
    /// The value in force.
    pub value: u128,
    /// The network's default ([`default_minimum_chain_work`]).
    pub default: u128,
    /// Set by `--minimumchainwork`.
    pub overridden: bool,
}

impl MinimumChainWorkSetting {
    /// Resolve `--minimumchainwork` (`arg`, hexadecimal) against the
    /// default of `net`.
    pub fn resolve(arg: Option<&str>, net: core::activation::ActivationNetwork) -> Result<Self, String> {
        let default = default_minimum_chain_work(net);
        Ok(match arg {
            Some(s) => MinimumChainWorkSetting { value: parse_minimum_chain_work(s)?, default, overridden: true },
            None => MinimumChainWorkSetting { value: default, default, overridden: false },
        })
    }

    /// The start-up warning of Bitcoin Core (`init.cpp`: "nMinimumChainWork
    /// set below default value of ..."), when the override lowers the
    /// release value: the node then leaves initial block download, and
    /// processes unrequested blocks, on a chain the release would not trust.
    pub fn below_default_warning(&self) -> Option<String> {
        (self.value < self.default).then(|| format!(
            "--minimumchainwork {:#x} is below this network's default {:#x}: initial block download ends, \
             and unrequested blocks are processed, on chains with less work than the release value",
            self.value, self.default))
    }
}

/// How long the selected tip may stay below the minimum chain work before
/// the node warns ([`MinimumWorkWatch`]), and the interval between
/// warnings. Reaching the mainnet value from genesis verifies some 7,400
/// GnB-SMH v1 proofs (64 MiB, about half a second each on one core, on up to
/// four threads); a node still below it after this long is slow, stuck, or
/// on a chain (or network) whose work is below the value. Each warning says
/// how much work the tip gained since the previous one.
pub const MIN_WORK_WARNING_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Watches how long the selected tip stays below the minimum chain work.
/// Bitcoin Core reports such a node as in initial block download (it stays
/// there until a chain with that much work arrives); the node logs
/// [`MinimumWorkWarning`] every [`MIN_WORK_WARNING_INTERVAL`] while it lasts.
#[derive(Clone, Debug, Default)]
pub struct MinimumWorkWatch {
    below_since: Option<Instant>,
    /// When the last warning was issued, and the tip work it reported.
    last_warning: Option<(Instant, u128)>,
}

/// A warning of [`MinimumWorkWatch::observe`]; its `Display` is the log line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinimumWorkWarning {
    /// How long the tip has been below the minimum.
    pub below_for: Duration,
    pub tip_work: u128,
    pub min_chain_work: u128,
    /// Tip work gained since the previous warning (`None` for the first).
    pub gained: Option<u128>,
}

impl MinimumWorkWatch {
    /// Record the selected tip's work at `now`; `Some` when a warning is due:
    /// the tip has been below `min_chain_work` for at least
    /// [`MIN_WORK_WARNING_INTERVAL`], and as long since the previous warning.
    /// Reaching the minimum resets the watch.
    pub fn observe(&mut self, tip_work: u128, min_chain_work: u128, now: Instant) -> Option<MinimumWorkWarning> {
        if tip_work >= min_chain_work {
            *self = MinimumWorkWatch::default();
            return None;
        }
        let since = *self.below_since.get_or_insert(now);
        let below_for = now.saturating_duration_since(since);
        let last = self.last_warning.map_or(since, |(at, _)| at);
        if now.saturating_duration_since(last) < MIN_WORK_WARNING_INTERVAL {
            return None;
        }
        let gained = self.last_warning.map(|(_, w)| tip_work.saturating_sub(w));
        self.last_warning = Some((now, tip_work));
        Some(MinimumWorkWarning { below_for, tip_work, min_chain_work, gained })
    }
}

impl std::fmt::Display for MinimumWorkWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pct = self.tip_work.saturating_mul(100) / self.min_chain_work.max(1);
        write!(f, "the selected tip's chain work {:#x} ({pct}% of the minimum chain work {:#x}) has been below \
            the minimum for {} min", self.tip_work, self.min_chain_work, self.below_for.as_secs() / 60)?;
        match self.gained {
            Some(0) => write!(f, ", with no progress since the last warning")?,
            Some(g) => write!(f, " ({g:#x} gained since the last warning)")?,
            None => {}
        }
        write!(f, ": this node stays in initial block download (the miner paused, unrequested blocks refused) \
            until it syncs a chain with at least that much work. If its peers serve the real chain, keep it \
            running; if this network's chain carries less work than this value, restart it with a lower \
            --minimumchainwork <hex> (0 turns the minimum off)")
    }
}

static MINIMUM_CHAIN_WORK: std::sync::OnceLock<u128> = std::sync::OnceLock::new();

/// Set the process-wide minimum chain work once, at start-up (the node's
/// `--minimumchainwork`, else the network default). Later calls are
/// refused. Tests set it per ingress core instead
/// ([`BlockIngress::with_minimum_chain_work`]).
pub fn set_minimum_chain_work(w: u128) -> Result<(), u128> {
    MINIMUM_CHAIN_WORK.set(w)
}

/// The process-wide minimum chain work: the value set at start-up, else the
/// default of the node's network (mainnet when no chain id is set, as for
/// the activation height).
pub fn minimum_chain_work() -> u128 {
    *MINIMUM_CHAIN_WORK.get().unwrap_or(&default_minimum_chain_work(core::node_chain_id().into()))
}

/// Blue work of the selected tip (0 for an empty DAG).
pub fn tip_blue_work(dag: &GhostDAG) -> u128 {
    dag.selected_tip().and_then(|t| dag.get_block_data(&t)).map(|d| d.blue_work).unwrap_or(0)
}

/// Bitcoin Core's first initial-block-download criterion: the selected tip
/// has less blue work than the minimum chain work.
///
/// Blocks this node requested are processed below it (as in Core, which
/// downloads them during initial block download), so its selected tip may
/// be a chain below the minimum, the real chain part-synced or an eclipsing
/// peer's cheap chain. Such a tip is not the node's chain of record: while
/// this holds the node mines nothing and serves no block template
/// ([`ibd_template_refusal`]), advertises no frontier or headers to peers
/// (`network::serve::serve_sync_request`), a witness node neither attests
/// checkpoints nor mines shares, and the IBD latch holds.
pub fn below_minimum_chain_work(dag: &GhostDAG, min_chain_work: u128) -> bool {
    tip_blue_work(dag) < min_chain_work
}

/// Why no block template is built on `dag`'s selected tip: it is below the
/// minimum chain work (initial block download). Bitcoin Core's
/// `getblocktemplate` refuses the same way ("is in initial sync and waiting
/// for blocks", `RPC_CLIENT_IN_INITIAL_DOWNLOAD`), and its miners only ever
/// build on a chain that left initial block download. `None`: a template
/// may be built.
pub fn ibd_template_refusal(dag: &GhostDAG, min_chain_work: u128) -> Option<String> {
    let tip_work = tip_blue_work(dag);
    (tip_work < min_chain_work).then(|| format!(
        "in initial block download: the selected tip's chain work {tip_work:#x} is below the minimum chain work \
         {min_chain_work:#x}; no block template until the node has synced a chain with at least that much work \
         (--minimumchainwork lowers it)"))
}

/// How far below the selected tip an UNREQUESTED block may branch, in
/// selected-chain blocks: GhostDAG's k + 1. Bitcoin Core processes an
/// unrequested block only if its chain work is at least the tip's; in a DAG,
/// honest blocks mined concurrently (at most k of them in any honest block's
/// anticone) carry slightly less, and [`block_work_lower_bound`] is a lower
/// bound (after the hardening activation it omits the merged blues), so the
/// comparison is with the selected-chain block k + 1 below the tip. A block
/// branching deeper is processed only when this node asked for it (a parent
/// of a buffered orphan, a frontier tip, an IBD pull).
pub const UNREQUESTED_WINDOW_BLOCKS: u64 = core::GHOSTDAG_K as u64 + 1;

/// The blue work of the selected-chain block `depth` blocks below the
/// selected tip (0 while the chain is shorter). O(depth).
pub fn selected_chain_work_below(dag: &GhostDAG, depth: u64) -> u128 {
    let mut cur = dag.selected_tip();
    for _ in 0..depth {
        match cur.and_then(|h| dag.get_block_data(&h)).and_then(|d| d.selected_parent) {
            Some(p) => cur = Some(p),
            None => return 0,
        }
    }
    cur.and_then(|h| dag.get_block_data(&h)).map(|d| d.blue_work).unwrap_or(0)
}

/// Verdict of the unrequested-block rule (Bitcoin Core's `AcceptBlock`
/// `!fRequested` branch) on a block that arrived without being asked for.
/// `lb` is the block's [`block_work_lower_bound`] (`None` when a parent is
/// unknown: an orphan). Cheap: no proof of work, no storage.
pub fn unrequested_block_admission(
    lb: Option<u128>,
    min_chain_work: u128,
    tip_work: u128,
    near_tip_work: u128,
) -> Result<(), DropReason> {
    match lb {
        // While below the minimum chain work an unrequested orphan proves
        // nothing (Core never stores a block whose header does not connect,
        // and none at all on a low-work chain): the node syncs by pulls.
        None if tip_work < min_chain_work => Err(DropReason::BelowMinimumChainWork),
        None => Ok(()),
        Some(lb) if lb < min_chain_work => Err(DropReason::BelowMinimumChainWork),
        Some(lb) if lb < near_tip_work => Err(DropReason::UnrequestedLowWork),
        Some(_) => Ok(()),
    }
}

/// POW-3 (Phase 4): the work requirement of a block submitted over RPC
/// (`submitblock`), checked before its proof of work: its chain work bound
/// must reach the minimum chain work (a node in initial block download has
/// no use for a block on a chain below it). The tip-relative anti-DoS work
/// rule is NOT applied (review finding): like Bitcoin Core's `submitblock`
/// (`ProcessNewBlock` with `force_processing`), the RPC is how an operator
/// feeds a node the heavier chain after a long partition or an eclipse, and
/// that chain's first blocks above the fork point are, judged one at a
/// time, below the window. A public RPC should require authentication for
/// writes (`--rpc-require-auth-for-writes`): a deep-fork block submitted
/// anonymously is cheap below the hardening activation. A block with an
/// unknown parent passes here and is refused by `accept_block`.
pub fn submitted_block_admission(dag: &GhostDAG, block: &core::Block, min_chain_work: u128) -> Result<(), String> {
    let Some(lb) = block_work_lower_bound(dag, &block.header.parents, block.header.bits, block.height) else {
        return Ok(());
    };
    if lb < min_chain_work {
        return Err(format!(
            "block rejected: its chain work (at least {lb:#x}) is below the minimum chain work {min_chain_work:#x} \
             (this node is in initial block download)"));
    }
    Ok(())
}

// ── NET-6: work-backed IBD evidence ──────────────────────────────────────────

/// A PoW-verified orphan counts as evidence that we are BEHIND (and may latch
/// the IBD latch) iff its bits are at least as hard as the un-eased
/// [`reference_target`] — i.e. it cost as much work as a real next block —
/// and it claims a height more than `IBD_EXIT_LAG` above our tip. Its height
/// is a claim, but a claim that cost a full block of work to make, and
/// `accept_block` verifies it the moment its parents arrive.
#[allow(dead_code)] // tests only (the ingress core uses `orphan_is_sync_evidence_from`); the node binary compiles this module too
pub fn orphan_is_sync_evidence(bits: u32, claimed_height: u64, tip_h: u64, now_unix: u64) -> bool {
    orphan_is_sync_evidence_from(bits, claimed_height, tip_h, &reference_target(tip_h, now_unix))
}

/// [`orphan_is_sync_evidence`] against a given reference target (see
/// [`orphan_floor_from`]).
pub fn orphan_is_sync_evidence_from(bits: u32, claimed_height: u64, tip_h: u64, reference: &[u8; 32]) -> bool {
    claimed_height > tip_h.saturating_add(crate::sync::IBD_EXIT_LAG) && bits_meet_floor(bits, reference)
}

/// NET-6: what the processor does with one (clamped) tip claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimAction {
    /// The claim clamped against our own verified score.
    pub clamped: u64,
    /// Send a directed GetHeaders / GetTips (rate-limited). Never latches IBD.
    pub pull: bool,
    /// Answer a BEHIND peer with a reciprocal Version (rate-limited).
    pub reciprocal: bool,
}

/// Minimum spacing between claim-triggered pulls.
pub const CLAIM_PULL_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Minimum spacing between reciprocal tip announcements.
pub const RECIPROCAL_MIN_INTERVAL: Duration = Duration::from_secs(15);

/// NET-6: tip claims (`PeerTip` / `Version`) are hints. A claim ahead of us
/// only triggers a rate-limited directed pull; it never sets `is_syncing`
/// (that requires work-backed evidence — see [`orphan_is_sync_evidence`]).
#[derive(Debug, Default)]
pub struct ClaimPolicy {
    last_pull: Option<Instant>,
    last_reciprocal: Option<Instant>,
}

impl ClaimPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate(&mut self, raw_claim: u64, our_score: u64, now: Instant) -> ClaimAction {
        let clamped = crate::network::clamp_announced_blue_score(raw_claim, our_score);
        let mut act = ClaimAction { clamped, pull: false, reciprocal: false };
        if clamped > our_score {
            if self.last_pull.is_none_or(|t| now.saturating_duration_since(t) >= CLAIM_PULL_MIN_INTERVAL) {
                self.last_pull = Some(now);
                act.pull = true;
            }
        } else if clamped < our_score
            && self.last_reciprocal.is_none_or(|t| now.saturating_duration_since(t) >= RECIPROCAL_MIN_INTERVAL)
        {
            self.last_reciprocal = Some(now);
            act.reciprocal = true;
        }
        act
    }
}

// ── POW-8: never trust wire metadata ─────────────────────────────────────────

/// POW-8: the `blue_score` carried on the wire is not committed by the block
/// id and was persisted and re-served verbatim. Before a block is stored it
/// is replaced by a value derived from VERIFIED parents — exactly what this
/// codebase's miner writes (`max(parent blue_score) + 1`). The authoritative
/// GhostDAG blue score lives in the DAG, not in the block body.
pub fn derived_blue_score<I: IntoIterator<Item = u64>>(parent_scores: I) -> u64 {
    parent_scores.into_iter().max().unwrap_or(0).saturating_add(1)
}

// ── NET-2: verdicts ──────────────────────────────────────────────────────────

/// Map an `accept_block` rejection to a gossip verdict. Only rejections that
/// are a pure function of the block and its (known) parents — wrong height,
/// wrong difficulty bits, invalid proof of work, timestamp before a parent,
/// coinbase over-claim — are `Reject` (penalized, never relayed: no honest
/// node can produce them). Anything that depends on local state or time
/// (duplicates, finality, reorg policy, storage, UTXO view, future
/// timestamps, shielded verifier) is `Ignore`.
pub fn verdict_for_accept_error(err: &str) -> GossipVerdict {
    const REJECT_PREFIXES: &[&str] = &[
        "invalid height",
        "invalid difficulty",
        "consensus rejection: invalid GnB-SMH proof of work",
        "consensus rejection: non-genesis block without parents",
        "timestamp rejected: timestamp before parent",
        "coinbase rejected",
    ];
    if REJECT_PREFIXES.iter().any(|p| err.starts_with(p)) {
        GossipVerdict::Reject
    } else {
        GossipVerdict::Ignore
    }
}

/// Map a `NewBlock` frame whose `block_data` does not decode
/// (`core::Block::from_wire_bytes`) to a gossip verdict.
///
/// `Ignore` (not relayed, not penalized, nothing recorded about the id) when
/// the decoder refused a non-minimal CompactSize varint
/// (`core::is_non_minimal_varint_error`); `Reject` (the delivering peer takes
/// gossipsub's P4 penalty) for every other malformed body. Releases before
/// the minimal-varint rule (H-fuzz; origin/main) accept a widened copy of a
/// valid block, return `Accept`, and gossipsub forwards the bytes they
/// received, so such a copy can arrive from an honest older relay: `Reject`
/// would let anyone who widens a varint of a fresh block get every upgraded
/// node to graylist its older peers (three such frames within a couple of
/// minutes pass the block topic's graylist threshold). Every byte string an
/// older node accepts and this node refuses fails on a non-minimal varint
/// (`core::wire_canonical_tests::pre_fix_acceptances_fail_on_a_non_minimal_varint`),
/// so no such relay is penalized. The block itself is taken from its
/// canonical encoding (another relay, or directed sync). docs/CONSENSUS.md,
/// "Wire encoding".
pub fn verdict_for_block_decode_error(err: &str) -> GossipVerdict {
    if core::is_non_minimal_varint_error(err) {
        GossipVerdict::Ignore
    } else {
        GossipVerdict::Reject
    }
}

// ── B1-T7 / NET-4 residual: who a refused block frame is charged to ──────────
//
// Gossipsub's `Reject` charges its invalid-message penalty (P4) to the peer
// that delivered the frame AND to every peer that delivered a duplicate.
// Releases older than the validated relay (NET-2) forward every frame before
// validating it, and they follow the chain until the hardening activation
// block (they reject it); releases older than this one (Phase 4) forward an
// orphan once its bits meet THEIR floor and its proof is valid, before its
// parents are known — at every height, since they accept the activation
// block. Either can be an honest peer that delivers a frame this node
// refuses, and penalizing it would let anyone get every upgraded node to cut
// it off (B1-T7; the transaction relay has the same gate,
// `mempool::relay::TxRelay::penalties_in_force`). Bitcoin Core never
// punishes a peer for data that may be invalid only because of a recent rule
// change (`BLOCK_RECENT_CONSENSUS_CHANGE`) and punishes the peer that SENT
// the invalid data. So:
//
// * a frame the delivering peer AUTHORED (gossipsub's signed source is the
//   propagation source: nobody relayed it) is always charged to it — as a
//   misbehaviour (disconnect and address discouragement), with `Ignore` to
//   gossipsub so that no relay that forwarded a duplicate is charged;
// * a RELAYED frame is charged (`Reject`) only for a context-free fault —
//   one every release on the chain checks before forwarding anything
//   (decode, id / height binding, structure, proof of work) — and only once
//   the chain contains the hardening activation block (no release that
//   forwards unvalidated frames follows it);
// * a relayed frame with a contextual fault (height, bits, timestamp,
//   coinbase: what an older release's relayed orphan can carry), or one
//   below the orphan floor (a function of the node's own tip and clock), is
//   never charged to the relay.

/// The class of fault of a refused block frame (see above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockFault {
    /// Decode, id / height binding, structure, proof of work.
    ContextFree,
    /// Needs the parents (height, bits, timestamp, coinbase), or the orphan
    /// floor.
    Context,
}

/// The fault class of an `accept_block` error (the proof of work is
/// context-free; every other error [`verdict_for_accept_error`] rejects
/// depends on the parents).
pub fn accept_error_fault(err: &str) -> BlockFault {
    if err.starts_with("consensus rejection: invalid GnB-SMH proof of work") {
        BlockFault::ContextFree
    } else {
        BlockFault::Context
    }
}

/// What to do about a refused gossip block frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPenalty {
    /// The verdict reported to gossipsub (`Reject` = P4 on the deliverer and
    /// on every peer that delivered a duplicate).
    pub gossip: GossipVerdict,
    /// Treat the delivering peer as misbehaving (disconnect it and
    /// discourage its address, `network::discourage`).
    pub misbehaving: bool,
}

/// Penalty for a block frame whose verdict would be `base` (see the section
/// comment above). `self_authored`: the frame's signed gossip author is the
/// peer that delivered it. `penalties_in_force`:
/// [`block_penalties_in_force`].
pub fn block_penalty(base: GossipVerdict, fault: BlockFault, self_authored: bool, penalties_in_force: bool) -> BlockPenalty {
    match base {
        GossipVerdict::Reject if penalties_in_force && fault == BlockFault::ContextFree => {
            BlockPenalty { gossip: GossipVerdict::Reject, misbehaving: true }
        }
        GossipVerdict::Reject if self_authored => BlockPenalty { gossip: GossipVerdict::Ignore, misbehaving: true },
        GossipVerdict::Reject => BlockPenalty { gossip: GossipVerdict::Ignore, misbehaving: false },
        v => BlockPenalty { gossip: v, misbehaving: false },
    }
}

/// NET-2 residual: what to do about an orphan whose bits fail the anti-DoS
/// floor ([`DropReason::OrphanBelowFloor`]). Returns the penalty and whether
/// its decoding and hashing are charged to the deliverer's proof-of-work
/// budget. Gossip: charged, and its author, if it delivered the frame
/// itself, is treated as misbehaving (a relay never is: an older release
/// forwards orphans that meet ITS floor). An answer to this node's own pull
/// is dropped with no charge and no penalty (review finding): the floor is a
/// function of this node's tip and clock, and the node asked for the block
/// (an old block of an era whose difficulty was far easier can fail it
/// honestly).
pub fn orphan_floor_penalty(solicited: bool, self_authored: bool, penalties_in_force: bool) -> (BlockPenalty, bool) {
    if solicited {
        (BlockPenalty { gossip: GossipVerdict::Ignore, misbehaving: false }, false)
    } else {
        (block_penalty(GossipVerdict::Reject, BlockFault::Context, self_authored, penalties_in_force), true)
    }
}

/// True iff the node's selected chain contains the hardening activation
/// block (`tip_height >= activation`): from then on no release that forwards
/// unvalidated frames follows the chain (the same gate as
/// `mempool::relay::TxRelay::penalties_in_force`, whose next-block height is
/// `tip_height + 1`).
pub fn block_penalties_in_force(tip_height: u64, activation: u64) -> bool {
    activation != core::activation::NEVER
        && tip_height.saturating_add(1) >= crate::mempool::relay::default_penalty_height(activation)
}

// ── B1-T5: no relay of orphans before they connect ───────────────────────────

/// How long a withheld orphan verdict stays useful, from the frame's arrival
/// (gossipsub keeps an unvalidated frame for `GOSSIP_HISTORY_LENGTH`
/// heartbeats; the same margin as the transaction relay's deferred verdicts).
pub const DEFERRED_BLOCK_VERDICT_TTL: Duration = crate::mempool::relay::DEFERRED_VERDICT_TTL;

/// Bound on withheld orphan verdicts.
pub const MAX_DEFERRED_BLOCK_VERDICTS: usize = 1_024;

/// What became of a buffered orphan whose gossip verdict was withheld.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrphanFate {
    /// Connected (`accept_block` accepted it): relay its frame.
    Accepted,
    /// `accept_block` refused it with this error.
    Rejected(String),
    /// The work rule refused it once its parents were known, or it left the
    /// pool, or its frame expired: not relayed, not penalized.
    Dropped,
}

/// B1-T5 / POW-4: the gossip verdicts of buffered orphans are WITHHELD
/// until the orphan connects (as the transaction relay does for orphan
/// transactions, MEM-6): an orphan has passed only the floor and its proof
/// of work, and relaying it at once (`Accept` on buffering) let an attacker's
/// floor-meeting orphans travel the whole network, charged at every hop to
/// the honest relay that forwarded them. Keyed by block id, timed from the
/// frame's arrival, bounded.
#[derive(Debug)]
pub struct DeferredBlockVerdicts<O> {
    pending: HashMap<[u8; 32], (O, Instant)>,
}

impl<O> Default for DeferredBlockVerdicts<O> {
    fn default() -> Self {
        Self { pending: HashMap::new() }
    }
}

impl<O> DeferredBlockVerdicts<O> {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Withhold the verdict of the frame (received at `received_at`) that
    /// carried the buffered orphan `hash`. Returns the origin back when it is
    /// not stored (frame already too old, the same id already pending, or the
    /// table full): the caller answers `Ignore`.
    pub fn defer(&mut self, hash: [u8; 32], origin: O, received_at: Instant, now: Instant) -> Option<O> {
        if now.saturating_duration_since(received_at) >= DEFERRED_BLOCK_VERDICT_TTL {
            return Some(origin);
        }
        if self.pending.len() >= MAX_DEFERRED_BLOCK_VERDICTS {
            self.pending.retain(|_, (_, at)| now.saturating_duration_since(*at) < DEFERRED_BLOCK_VERDICT_TTL);
        }
        if self.pending.len() >= MAX_DEFERRED_BLOCK_VERDICTS || self.pending.contains_key(&hash) {
            return Some(origin);
        }
        self.pending.insert(hash, (origin, received_at));
        None
    }

    /// Settle the withheld verdicts of the drained orphans in `ev`.
    pub fn settle(&mut self, ev: &OrphanBlockEvents) -> Vec<(O, OrphanFate)> {
        let mut out = Vec::new();
        for h in &ev.accepted {
            if let Some((o, _)) = self.pending.remove(h) {
                out.push((o, OrphanFate::Accepted));
            }
        }
        for (h, e) in &ev.rejected {
            if let Some((o, _)) = self.pending.remove(h) {
                out.push((o, OrphanFate::Rejected(e.clone())));
            }
        }
        for (h, _) in &ev.refused {
            if let Some((o, _)) = self.pending.remove(h) {
                out.push((o, OrphanFate::Dropped));
            }
        }
        out
    }

    /// Forget the verdicts whose frame expired or whose orphan is no longer
    /// buffered (`still_buffered` false: evicted, given up): their origins,
    /// to be answered `Ignore`.
    pub fn prune(&mut self, still_buffered: impl Fn(&[u8; 32]) -> bool, now: Instant) -> Vec<O> {
        let doomed: Vec<[u8; 32]> = self.pending.iter()
            .filter(|(h, (_, at))| now.saturating_duration_since(*at) >= DEFERRED_BLOCK_VERDICT_TTL || !still_buffered(h))
            .map(|(h, _)| *h)
            .collect();
        doomed.iter().filter_map(|h| self.pending.remove(h).map(|(o, _)| o)).collect()
    }
}

// ── POW-2: supervisor back-off ───────────────────────────────────────────────

/// A processor run that lasted at least this long counts as healthy: the next
/// panic restarts after the BASE back-off, not after the accumulated one.
pub const SUPERVISOR_HEALTHY_RESET: Duration = Duration::from_secs(60);

/// Exponential restart back-off for the supervised message processor, reset
/// after a healthy period (POW-2: it used to only ever grow, to its 30 s cap,
/// so one panic per 30 s kept block processing stopped).
#[derive(Debug, Clone)]
pub struct SupervisorBackoff {
    base: Duration,
    max: Duration,
    next: Duration,
}

impl SupervisorBackoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self { base, max, next: base }
    }

    /// The processor panicked after running for `ran_for`: how long to wait
    /// before restarting it.
    pub fn on_panic(&mut self, ran_for: Duration) -> Duration {
        if ran_for >= SUPERVISOR_HEALTHY_RESET {
            self.next = self.base;
        }
        let wait = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        wait
    }
}

// ── POW-4 / POW-8: the bounded orphan pool ───────────────────────────────────

/// Bounds of an [`OrphanPool`]. `bytes` are wire bytes of the block (the
/// parsed copy in memory is proportional; the raw bytes are not retained).
#[derive(Clone, Copy, Debug)]
pub struct OrphanLimits {
    pub max_entries:          usize,
    pub max_bytes:            usize,
    pub max_entries_per_peer: usize,
    pub max_bytes_per_peer:   usize,
}

impl Default for OrphanLimits {
    fn default() -> Self {
        Self {
            max_entries:          10_000,
            max_bytes:            64 * 1024 * 1024,
            max_entries_per_peer: 2_500,
            max_bytes_per_peer:   16 * 1024 * 1024,
        }
    }
}

/// One buffered orphan.
#[derive(Clone, Debug)]
pub struct OrphanEntry {
    pub block:  core::Block,
    /// Claimed (wire) height; verified by `accept_block` when parents arrive.
    pub height: u64,
    pub bytes:  usize,
    /// The peer that delivered it (`None` = local / unknown).
    pub peer:   Option<PeerId>,
    /// Counted as IBD evidence (see [`orphan_is_sync_evidence`]).
    pub evidence: bool,
    /// The parents that were missing (not in the DAG) when it was buffered:
    /// the only keys its eviction remembers work under (POW-3). A parent
    /// already in the DAG is never looked up by the work rule.
    pub missing: Vec<[u8; 32]>,
    seq:        u64,
}

/// POW-3: an evicted orphan kept WITHOUT its body: its work and the missing
/// parents it waited on. The work rule sums the work of the distinct blocks
/// buffered or kept as skeletons above a block (see
/// [`OrphanPool::announced_work_above`]). Being keyed by the block id, a
/// re-sent orphan never adds its work twice.
#[derive(Clone, Debug)]
struct Skeleton {
    work:    u128,
    /// At most [`REMEMBERED_KEYS_PER_ORPHAN`] of its missing parents.
    parents: Vec<[u8; 32]>,
    owner:   Option<PeerId>,
    seq:     u64,
}

/// POW-3: the greatest work of a single path of evicted orphans announced on
/// top of a missing parent (cumulative along the path, so it chains through
/// any number of evictions: it lets a linear fork longer than every bounded
/// store prove its work).
#[derive(Clone, Copy, Debug)]
struct RememberedPath {
    work:  u128,
    owner: Option<PeerId>,
    seq:   u64,
}

/// Result of [`OrphanPool::insert`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrphanInsert {
    /// Buffered; `evicted` lists orphans dropped to make room (arrival order).
    Inserted { evicted: Vec<[u8; 32]> },
    /// Already buffered: the FIRST copy wins (POW-8 — a later copy with
    /// different wire metadata never overwrites a pending orphan).
    Duplicate,
    /// Larger than any quota could ever hold.
    TooLarge,
}

#[derive(Default, Debug)]
struct PeerUsage {
    bytes: usize,
    seqs:  BTreeSet<u64>,
}

/// POW-4 (audit): the orphan pool, bounded by entries AND bytes, globally and
/// per delivering peer. Eviction is by ARRIVAL order — first the delivering
/// peer's own oldest entries when it exceeds its quota, then the globally
/// oldest — never by the self-declared height (which used to let attacker
/// orphans claiming huge heights evict every honest orphan). Holds the
/// reverse index `parent -> waiting orphans`.
#[derive(Debug)]
pub struct OrphanPool {
    limits:      OrphanLimits,
    entries:     HashMap<[u8; 32], OrphanEntry>,
    order:       BTreeMap<u64, [u8; 32]>,
    waiting_for: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    per_peer:    HashMap<Option<PeerId>, PeerUsage>,
    evidence:    BTreeMap<u64, usize>,
    total_bytes: usize,
    next_seq:    u64,
    // ── POW-3: work announced by evicted orphans ──────────────────────────
    //
    // Two bounded stores, both filled when an orphan is evicted, both keyed
    // only by the orphan's MISSING parents (at most
    // REMEMBERED_KEYS_PER_ORPHAN of them) and both charged to the peer that
    // delivered it: a peer owns at most 1/REMEMBERED_PEER_SHARE of each. A
    // full store gives way to an entry of greater work (the lowest-work entry
    // goes; skeletons: else the delivering peer's own oldest), so orphans at
    // the anti-DoS floor can neither flush a remembered honest chain nor
    // re-add work by being re-sent.
    remembered_cap: usize,
    /// Evicted orphans by id (exact set semantics: summed once each).
    skeletons:      HashMap<[u8; 32], Skeleton>,
    /// Reverse index: missing parent -> skeletons that waited on it.
    skel_children:  HashMap<[u8; 32], HashSet<[u8; 32]>>,
    skel_by_work:   BTreeSet<WorkKey>,
    skel_by_owner:  HashMap<Option<PeerId>, BTreeSet<(u64, [u8; 32])>>,
    /// Missing parent -> greatest single-path work remembered above it.
    paths:          HashMap<[u8; 32], RememberedPath>,
    path_by_work:   BTreeSet<WorkKey>,
    path_by_owner:  HashMap<Option<PeerId>, BTreeSet<WorkKey>>,
    rem_seq:        u64,
    /// Bumped whenever the backing of some block can have grown (an orphan
    /// was buffered, or a remembered path grew). Lets the ingress core cache
    /// a LowWork verdict until then.
    generation:     u64,
}

/// `(work, insertion sequence, id)`: orders remembered entries lowest work
/// first, oldest first among equals.
type WorkKey = (u128, u64, [u8; 32]);

/// Bound of each POW-3 remembered-work store: evicted-orphan skeletons
/// (about 200 bytes each with one parent) and remembered paths (about 100).
/// Tests may lower it ([`OrphanPool::set_remembered_capacity`]).
pub const REMEMBERED_WORK_MAX: usize = 50_000;

/// At most this many missing parents of one evicted orphan are remembered.
/// Honest fork blocks miss a handful; a crafted orphan's 256 random parents
/// no longer turn one eviction into 256 entries.
pub const REMEMBERED_KEYS_PER_ORPHAN: usize = 8;

/// One delivering peer owns at most `1 / REMEMBERED_PEER_SHARE` of each
/// remembered store (it then pays with its own entries).
pub const REMEMBERED_PEER_SHARE: usize = 4;

/// Proof-of-work work a block's header claims (its bits at its claimed
/// height, normalised across the GnB-SMH v1 -> v3 switch as `accept_block`
/// counts it, `core::block_work`; checked against the proof before an orphan
/// is buffered — the proof's algorithm follows the same height).
fn header_work(block: &core::Block) -> u128 {
    core::block_work(block.header.bits, block.height)
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new(OrphanLimits::default())
    }
}

impl OrphanPool {
    pub fn new(limits: OrphanLimits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            waiting_for: HashMap::new(),
            per_peer: HashMap::new(),
            evidence: BTreeMap::new(),
            total_bytes: 0,
            next_seq: 0,
            remembered_cap: REMEMBERED_WORK_MAX,
            skeletons: HashMap::new(),
            skel_children: HashMap::new(),
            skel_by_work: BTreeSet::new(),
            skel_by_owner: HashMap::new(),
            paths: HashMap::new(),
            path_by_work: BTreeSet::new(),
            path_by_owner: HashMap::new(),
            rem_seq: 0,
            generation: 0,
        }
    }

    /// Change the bound of each remembered-work store (tests use small ones
    /// to exercise eviction). Existing entries above the bound are kept
    /// until they are replaced.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn set_remembered_capacity(&mut self, cap: usize) {
        self.remembered_cap = cap;
    }

    /// See the `generation` field.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of evicted orphans kept as skeletons / remembered paths.
    pub fn remembered_len(&self) -> (usize, usize) {
        (self.skeletons.len(), self.paths.len())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn contains(&self, h: &[u8; 32]) -> bool {
        self.entries.contains_key(h)
    }

    pub fn get(&self, h: &[u8; 32]) -> Option<&OrphanEntry> {
        self.entries.get(h)
    }

    /// `(entries, bytes)` buffered on behalf of `peer`.
    pub fn peer_usage(&self, peer: Option<PeerId>) -> (usize, usize) {
        self.per_peer.get(&peer).map(|u| (u.seqs.len(), u.bytes)).unwrap_or((0, 0))
    }

    /// True iff some buffered orphan waits for `h` as a parent.
    pub fn is_waited_on(&self, h: &[u8; 32]) -> bool {
        self.waiting_for.contains_key(h)
    }

    /// Every parent some orphan is waiting for.
    pub fn waiting_parents(&self) -> Vec<[u8; 32]> {
        self.waiting_for.keys().copied().collect()
    }

    /// NET-6: highest claimed height among orphans counted as IBD evidence.
    pub fn max_evidence_height(&self) -> Option<u64> {
        self.evidence.keys().next_back().copied()
    }

    /// Buffer an orphan waiting on `missing_parents`. See [`OrphanInsert`].
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        hash: [u8; 32],
        block: core::Block,
        height: u64,
        bytes: usize,
        peer: Option<PeerId>,
        evidence: bool,
        missing_parents: &[[u8; 32]],
    ) -> OrphanInsert {
        if self.entries.contains_key(&hash) {
            return OrphanInsert::Duplicate;
        }
        if bytes > self.limits.max_bytes_per_peer || bytes > self.limits.max_bytes {
            return OrphanInsert::TooLarge;
        }
        let mut evicted = Vec::new();
        // Per-peer quota: the delivering peer pays with its OWN oldest orphans.
        loop {
            let (count, used) = self.peer_usage(peer);
            if count < self.limits.max_entries_per_peer
                && used.saturating_add(bytes) <= self.limits.max_bytes_per_peer
            {
                break;
            }
            let oldest = self.per_peer.get(&peer).and_then(|u| u.seqs.iter().next().copied());
            match oldest.and_then(|s| self.order.get(&s).copied()) {
                Some(h) => {
                    self.evict(&h);
                    evicted.push(h);
                }
                None => break,
            }
        }
        // Global bounds: oldest arrival first.
        while self.entries.len() >= self.limits.max_entries
            || self.total_bytes.saturating_add(bytes) > self.limits.max_bytes
        {
            match self.order.values().next().copied() {
                Some(h) => {
                    self.evict(&h);
                    evicted.push(h);
                }
                None => break,
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        for mp in missing_parents {
            self.waiting_for.entry(*mp).or_default().insert(hash);
        }
        if evidence {
            *self.evidence.entry(height).or_insert(0) += 1;
        }
        let usage = self.per_peer.entry(peer).or_default();
        usage.bytes = usage.bytes.saturating_add(bytes);
        usage.seqs.insert(seq);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.order.insert(seq, hash);
        // A re-buffered evicted orphan replaces its skeleton (its work is
        // counted once). Any insertion can raise a block's backing (a new id,
        // or a buffered orphan that may merge-back its parents again).
        self.drop_skeleton(&hash);
        self.generation = self.generation.wrapping_add(1);
        self.entries.insert(hash, OrphanEntry {
            block, height, bytes, peer, evidence, missing: missing_parents.to_vec(), seq,
        });
        OrphanInsert::Inserted { evicted }
    }

    /// Evict one orphan to make room. Its work is remembered first (POW-3):
    /// as a skeleton (the orphan without its body), and, under each of its
    /// missing parents, as the work of the heaviest single path of orphans it
    /// tops. Then it is removed.
    fn evict(&mut self, h: &[u8; 32]) {
        if let Some(e) = self.entries.get(h) {
            let work = header_work(&e.block);
            let keys: Vec<[u8; 32]> = e.missing.iter().take(REMEMBERED_KEYS_PER_ORPHAN).copied().collect();
            let owner = e.peer;
            let path = work.saturating_add(self.path_work_above(h));
            for p in &keys {
                self.remember_path(*p, path, owner);
            }
            self.add_skeleton(*h, work, keys, owner);
        }
        self.remove(h);
    }

    /// Keep an evicted orphan as a skeleton, within the store's bounds.
    fn add_skeleton(&mut self, hash: [u8; 32], work: u128, parents: Vec<[u8; 32]>, owner: Option<PeerId>) {
        if self.remembered_cap == 0 || self.skeletons.contains_key(&hash) {
            return;
        }
        let per_owner = (self.remembered_cap / REMEMBERED_PEER_SHARE).max(1);
        let own_oldest = |pool: &Self| pool.skel_by_owner.get(&owner).and_then(|s| s.iter().next().map(|(_, h)| *h));
        if self.skel_by_owner.get(&owner).map_or(0, |s| s.len()) >= per_owner {
            // The delivering peer pays with its own oldest skeleton.
            if let Some(o) = own_oldest(self) {
                self.drop_skeleton(&o);
            }
        } else if self.skeletons.len() >= self.remembered_cap {
            // Full: an entry of greater work replaces the lowest-work one;
            // otherwise the delivering peer pays with its own oldest.
            match self.skel_by_work.iter().next().copied() {
                Some((lowest, _, l)) if work > lowest => {
                    self.drop_skeleton(&l);
                }
                _ => match own_oldest(self) {
                    Some(o) => {
                        self.drop_skeleton(&o);
                    }
                    None => return,
                },
            }
        }
        let seq = self.rem_seq;
        self.rem_seq = self.rem_seq.wrapping_add(1);
        for p in &parents {
            self.skel_children.entry(*p).or_default().insert(hash);
        }
        self.skel_by_work.insert((work, seq, hash));
        self.skel_by_owner.entry(owner).or_default().insert((seq, hash));
        self.skeletons.insert(hash, Skeleton { work, parents, owner, seq });
    }

    fn drop_skeleton(&mut self, h: &[u8; 32]) -> Option<Skeleton> {
        let s = self.skeletons.remove(h)?;
        self.skel_by_work.remove(&(s.work, s.seq, *h));
        if let Some(set) = self.skel_by_owner.get_mut(&s.owner) {
            set.remove(&(s.seq, *h));
            if set.is_empty() {
                self.skel_by_owner.remove(&s.owner);
            }
        }
        for p in &s.parents {
            if let Some(c) = self.skel_children.get_mut(p) {
                c.remove(h);
                if c.is_empty() {
                    self.skel_children.remove(p);
                }
            }
        }
        Some(s)
    }

    /// Remember `work` (a single path of evicted orphans) above `parent`,
    /// combined with what is remembered there by `max` (idempotent: a re-sent
    /// orphan never adds its work twice). Bounded: a peer at its share
    /// replaces its own lowest entry, a full store its globally lowest one,
    /// and only by an entry of greater work. Along an honest chain fetched
    /// tip first, the newest link carries the greatest cumulative work, so
    /// what gives way is the obsolete links above it.
    fn remember_path(&mut self, parent: [u8; 32], work: u128, owner: Option<PeerId>) {
        if self.remembered_cap == 0 || work == 0 {
            return;
        }
        let old = self.paths.get(&parent).copied();
        if old.is_some_and(|o| o.work >= work) {
            return;
        }
        // Upgrading a key frees its own slot first.
        if old.is_some() {
            self.forget_path(&parent);
        }
        let per_owner = (self.remembered_cap / REMEMBERED_PEER_SHARE).max(1);
        let owner_full = self.path_by_owner.get(&owner).map_or(0, |s| s.len()) >= per_owner;
        let store_full = self.paths.len() >= self.remembered_cap;
        if owner_full || store_full {
            let victim = if owner_full {
                self.path_by_owner.get(&owner).and_then(|s| s.iter().next().copied())
            } else {
                self.path_by_work.iter().next().copied()
            };
            match victim {
                Some((lowest, _, v)) if work > lowest => self.forget_path(&v),
                _ => {
                    // Refused: what was remembered here stays.
                    if let Some(o) = old {
                        self.insert_path(parent, o);
                    }
                    return;
                }
            }
        }
        let seq = self.rem_seq;
        self.rem_seq = self.rem_seq.wrapping_add(1);
        self.insert_path(parent, RememberedPath { work, owner, seq });
        self.generation = self.generation.wrapping_add(1);
    }

    fn insert_path(&mut self, parent: [u8; 32], r: RememberedPath) {
        self.path_by_work.insert((r.work, r.seq, parent));
        self.path_by_owner.entry(r.owner).or_default().insert((r.work, r.seq, parent));
        self.paths.insert(parent, r);
    }

    fn forget_path(&mut self, h: &[u8; 32]) {
        if let Some(r) = self.paths.remove(h) {
            self.path_by_work.remove(&(r.work, r.seq, *h));
            if let Some(set) = self.path_by_owner.get_mut(&r.owner) {
                set.remove(&(r.work, r.seq, *h));
                if set.is_empty() {
                    self.path_by_owner.remove(&r.owner);
                }
            }
        }
    }

    /// True iff evicted orphans announced work above `h` (it was a missing
    /// parent of an orphan we had buffered).
    pub fn remembers(&self, h: &[u8; 32]) -> bool {
        self.paths.contains_key(h) || self.skel_children.contains_key(h)
    }

    /// `h` is in the DAG now: drop what is remembered under it and its own
    /// skeleton. Skeletons that waited on it stay (they may wait on other
    /// parents, and they still announce work above blocks below `h`).
    pub fn forget(&mut self, h: &[u8; 32]) {
        self.forget_path(h);
        self.drop_skeleton(h);
    }

    /// POW-3: the work announced ABOVE `root` (excluding `root` itself) by
    /// proof-of-work-verified orphans: the summed header work of the DISTINCT
    /// orphans, buffered or kept as skeletons, that wait on `root` directly
    /// or through one another, each counted once whatever the shape (a
    /// diamond or a DAG-shaped fork is summed, never counted per path); or,
    /// if greater, the work of the heaviest single path of buffered orphans
    /// plus a remembered path (which lets a linear fork deeper than the
    /// stores still prove its work). Never more than the work the announcers
    /// really spent. O(orphans above `root`).
    #[allow(dead_code)] // the work rule uses the capped form; tests use this one
    pub fn announced_work_above(&self, root: &[u8; 32]) -> u128 {
        self.announced_work_capped(root, u128::MAX)
    }

    /// [`Self::announced_work_above`], cut short once it reaches `need` (the
    /// result is `>= need` iff the full value is).
    pub fn announced_work_capped(&self, root: &[u8; 32], need: u128) -> u128 {
        let sum = self.closure_work_above(root, need);
        if sum >= need || self.paths.is_empty() {
            return sum;
        }
        sum.max(self.path_work_above(root))
    }

    /// The summed work of the distinct buffered or skeleton orphans
    /// transitively waiting on `root`; stops once it reaches `need`.
    fn closure_work_above(&self, root: &[u8; 32], need: u128) -> u128 {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        seen.insert(*root);
        let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
        queue.push_back(*root);
        let mut sum = 0u128;
        while let Some(h) = queue.pop_front() {
            let buffered = self.waiting_for.get(&h).into_iter().flatten();
            let evicted = self.skel_children.get(&h).into_iter().flatten();
            for c in buffered.chain(evicted) {
                if !seen.insert(*c) {
                    continue;
                }
                let w = match self.entries.get(c) {
                    Some(e) => header_work(&e.block),
                    None => match self.skeletons.get(c) {
                        Some(sk) => sk.work,
                        None => continue,
                    },
                };
                sum = sum.saturating_add(w);
                if sum >= need {
                    return sum;
                }
                queue.push_back(*c);
            }
        }
        sum
    }

    /// The greatest work of a single path of buffered orphans above `root`,
    /// extended by the remembered path work at its end. O(buffered orphans
    /// above `root`).
    fn path_work_above(&self, root: &[u8; 32]) -> u128 {
        // Depth-first, a node is computed once all its buffered waiters are;
        // `in_progress` guards against (impossible) cycles.
        let mut memo: HashMap<[u8; 32], u128> = HashMap::new();
        let mut in_progress: HashSet<[u8; 32]> = HashSet::new();
        let mut stack: Vec<[u8; 32]> = vec![*root];
        while let Some(&h) = stack.last() {
            if memo.contains_key(&h) {
                stack.pop();
                continue;
            }
            let waiters = self.waiting_for.get(&h);
            let pending: Vec<[u8; 32]> = waiters
                .map(|ws| ws.iter()
                    .filter(|w| self.entries.contains_key(*w) && !memo.contains_key(*w) && !in_progress.contains(*w))
                    .copied()
                    .collect())
                .unwrap_or_default();
            if pending.is_empty() || !in_progress.insert(h) {
                let mut best = self.paths.get(&h).map_or(0, |r| r.work);
                if let Some(ws) = waiters {
                    for w in ws {
                        if let Some(e) = self.entries.get(w) {
                            let above = memo.get(w).copied().unwrap_or(0);
                            best = best.max(header_work(&e.block).saturating_add(above));
                        }
                    }
                }
                memo.insert(h, best);
                in_progress.remove(&h);
                stack.pop();
            } else {
                stack.extend(pending);
            }
        }
        memo.get(root).copied().unwrap_or(0)
    }

    /// POW-3 / B1-T5: the greatest lower bound on the blue work of a buffered
    /// orphan that VOUCHES for `root` — a block whose parents are all in the
    /// DAG, `root_block`, being judged by the work rule with its own bound
    /// `root_lb` — or 0 if none does.
    ///
    /// The audit (B1-T5) found that the bound used to be built from the
    /// self-declared parents and bits of ANY orphan transitively above
    /// `root`, none of them checked in context: one orphan listing our tip
    /// and a low-work block as parents (even one that could never be valid,
    /// stamped before its parents) got that block and, through the drain,
    /// every orphan above it stored. A voucher now has to be checkable, and
    /// checked, before it can make anything acceptable (as Bitcoin Core never
    /// lets a header that fails `ContextualCheckBlockHeader` make another
    /// block acceptable):
    ///
    /// * it waits on `root` DIRECTLY and every other parent is in the DAG
    ///   (an orphan above other orphans cannot be checked yet);
    /// * its header height is `max(parent DAG heights) + 1`, `root` counting
    ///   with the height `accept_block` will require of it;
    /// * its bits are the expected ASERT bits of its parent set and its
    ///   timestamp is within the bounds `accept_block` enforces;
    /// * it is below the hardening activation (`activation`): from the
    ///   activation a block that merges a red below its merge-depth root is
    ///   invalid, and a block whose own chain cannot come within the
    ///   anti-DoS window (360 selected-chain blocks of work, `MERGE_DEPTH`) of
    ///   the tip is below the merge-depth root of every block an honest miner
    ///   builds on the tip — merging it is a `MergeDepthViolation`, so no
    ///   valid block can vouch for it.
    ///
    /// Its proof of work was verified when it was buffered. The bound is the
    /// largest parent blue work (`root_lb` for `root`) plus its header work.
    /// O(direct waiters × parents).
    #[allow(clippy::too_many_arguments)]
    pub fn best_voucher_lb(
        &self,
        root: &[u8; 32],
        root_block: &core::Block,
        root_lb: u128,
        dag: &crate::consensus::GhostDAG,
        now_unix: u64,
        activation: u64,
    ) -> u128 {
        let Some(waiters) = self.waiting_for.get(root) else { return 0 };
        // The header height `accept_block` will require of `root`.
        let root_height = root_block.header.parents.iter()
            .filter_map(|p| dag.get_block_data(p).map(|d| d.height))
            .max()
            .map(|h| h.saturating_add(1));
        let Some(root_height) = root_height.filter(|h| *h == root_block.height) else { return 0 };
        let mut best = 0u128;
        'voucher: for w in waiters {
            let Some(e) = self.entries.get(w) else { continue };
            let b = &e.block;
            if core::activation::is_active_at(b.height, activation) {
                continue;
            }
            let (mut max_h, mut max_ts, mut max_bw) = (0u64, 0u64, 0u128);
            for p in &b.header.parents {
                let (h, ts, bw) = if p == root {
                    (root_height, root_block.header.timestamp, root_lb)
                } else {
                    match dag.get_block_data(p) {
                        Some(d) => (d.height, d.timestamp, d.blue_work),
                        None => continue 'voucher,
                    }
                };
                max_h = max_h.max(h);
                max_ts = max_ts.max(ts);
                max_bw = max_bw.max(bw);
            }
            if b.height != max_h.saturating_add(1) {
                continue;
            }
            match crate::pow::expected_bits(max_ts, b.height) {
                Ok(bits) if bits == b.header.bits => {}
                _ => continue,
            }
            if b.header.timestamp < max_ts || b.header.timestamp > now_unix.saturating_add(core::MAX_FUTURE_SECS) {
                continue;
            }
            best = best.max(max_bw.saturating_add(header_work(b)));
        }
        best
    }

    /// Remove one orphan, detaching it from every parent it waited on.
    /// Orphans waiting on IT keep waiting (their parent is just not buffered).
    pub fn remove(&mut self, h: &[u8; 32]) -> Option<OrphanEntry> {
        let e = self.entries.remove(h)?;
        self.order.remove(&e.seq);
        if let Some(u) = self.per_peer.get_mut(&e.peer) {
            u.seqs.remove(&e.seq);
            u.bytes = u.bytes.saturating_sub(e.bytes);
            if u.seqs.is_empty() {
                self.per_peer.remove(&e.peer);
            }
        }
        if e.evidence {
            if let Some(n) = self.evidence.get_mut(&e.height) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.evidence.remove(&e.height);
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(e.bytes);
        for p in &e.block.header.parents {
            if let Some(set) = self.waiting_for.get_mut(p) {
                set.remove(h);
                if set.is_empty() {
                    self.waiting_for.remove(p);
                }
            }
        }
        Some(e)
    }

    /// Detach and return the orphans waiting on `parent`, in arrival order.
    pub fn take_waiters(&mut self, parent: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self.waiting_for.remove(parent).unwrap_or_default().into_iter().collect();
        v.sort_by_key(|h| self.entries.get(h).map(|e| e.seq).unwrap_or(u64::MAX));
        v
    }

    /// Remove every orphan transitively waiting on `root_parent`
    /// (iteratively — no recursion). Returns how many were dropped.
    pub fn drop_subtree(&mut self, root_parent: &[u8; 32]) -> usize {
        let mut dropped = 0usize;
        let mut stack: VecDeque<[u8; 32]> = self.take_waiters(root_parent).into();
        while let Some(h) = stack.pop_front() {
            if self.remove(&h).is_some() {
                dropped += 1;
                stack.extend(self.take_waiters(&h));
            }
        }
        dropped
    }
}

// ── POW-3: anti-DoS work rule for blocks whose parents are known ─────────────

/// The anti-DoS window, in selected-chain blocks (Bitcoin uses 144 blocks
/// of work below the tip for `GetAntiDoSWorkThreshold`). 360 = `MERGE_DEPTH`:
/// 3 hours at 30 s, the depth below which, after the hardening activation, a
/// red block can no longer be merged; and with a 2-hour ASERT half-life a
/// fork that branches this far back still pays at least 2^-1.5 ≈ 35% of the
/// tip's work per block.
pub const ANTI_DOS_WINDOW_BLOCKS: u64 = crate::consensus::MERGE_DEPTH;

/// The anti-DoS work threshold: the blue work of the selected-chain block
/// [`ANTI_DOS_WINDOW_BLOCKS`] below our selected tip (0 while the chain is
/// shorter), i.e. our tip's work minus the work of the last
/// `ANTI_DOS_WINDOW_BLOCKS` selected-chain blocks. O(window).
pub fn anti_dos_work_threshold(dag: &GhostDAG) -> u128 {
    let mut cur = dag.selected_tip();
    for _ in 0..ANTI_DOS_WINDOW_BLOCKS {
        match cur.and_then(|h| dag.get_block_data(&h)).and_then(|d| d.selected_parent) {
            Some(p) => cur = Some(p),
            None => return 0,
        }
    }
    cur.and_then(|h| dag.get_block_data(&h)).map(|d| d.blue_work).unwrap_or(0)
}

/// A lower bound on the blue work a block at header height `height` with
/// these parents and `bits` gets: the largest parent blue work plus its own
/// work. Exact before the hardening activation (the selected parent IS the
/// parent of largest blue work); after it the merged blues only add. `None`
/// if a parent is unknown. The block's own work is `core::block_work` (what
/// `accept_block` adds to the DAG): GnB-SMH v3 blocks, from
/// `core::powit_height()`, are normalised by `POW_V3_DIFFICULTY_SHIFT`, so
/// `bits_to_work` would overstate a v3 block's work fourfold and the bound
/// would not be one.
pub fn block_work_lower_bound(dag: &GhostDAG, parents: &[BlockHash], bits: u32, height: u64) -> Option<u128> {
    let mut best = 0u128;
    for p in parents {
        best = best.max(dag.get_block_data(p)?.blue_work);
    }
    Some(best.saturating_add(core::block_work(bits, height)))
}

/// Verdict of the POW-3 anti-DoS work rule on a block whose parents are all
/// known, evaluated BEFORE its proof of work, storage or DAG insertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkAdmission {
    /// Its own work bound reaches the threshold (every honest block near the
    /// tip, fork-losers within the window).
    NearTip,
    /// The proof-of-work-verified orphans announced on top of it (buffered,
    /// or remembered after eviction; their work summed, each counted once —
    /// see [`OrphanPool::announced_work_above`]) bring the chain through it
    /// to the threshold: a chain that carries the work, however deep it
    /// branches and whatever its shape (Bitcoin: headers with enough work
    /// make the blocks requested).
    ChainBacked,
    /// A buffered orphan whose own bound reaches the threshold needs it as a
    /// parent (it merges a lower-work block); deep ones consume the
    /// [`DeepBackfillBudget`].
    MergeBacked,
    /// Nothing backs it: its chain cannot come within the window of our tip.
    /// Not stored, not processed, not penalized; if a heavier chain ever
    /// builds on it, that chain's orphans make it `ChainBacked` /
    /// `MergeBacked` and it is fetched again.
    LowWork,
}

/// The POW-3 decision from its inputs: `lb` = [`block_work_lower_bound`],
/// `threshold` = [`anti_dos_work_threshold`], `chain_above` =
/// [`OrphanPool::announced_work_above`], `merge_lb` =
/// [`OrphanPool::best_voucher_lb`].
pub fn work_admission(lb: u128, threshold: u128, chain_above: u128, merge_lb: u128) -> WorkAdmission {
    if lb >= threshold {
        WorkAdmission::NearTip
    } else if lb.saturating_add(chain_above) >= threshold {
        WorkAdmission::ChainBacked
    } else if merge_lb >= threshold {
        WorkAdmission::MergeBacked
    } else {
        WorkAdmission::LowWork
    }
}

// ── The processor's block-ingress core ───────────────────────────────────────

/// POW-8 (audit): the wire `blue_score` is not committed by the block id and
/// used to be persisted and re-served verbatim. Replace it with the value
/// derived from the block's VERIFIED parents before the block is stored.
/// (`height` needs no rewrite: `accept_block` rejects any block whose height
/// differs from max(parent height) + 1.) `accept_block` itself makes the same
/// replacement for every caller (re-audit B1-T0: `submitblock` skipped this
/// helper), so the calls on the ingress paths are defence in depth; RPC
/// `submitblock` uses it to relay the bytes it stores.
pub fn normalize_wire_metadata(block: &mut core::Block, dag: &Arc<RwLock<GhostDAG>>) {
    let d = dag.read();
    block.blue_score = derived_blue_score(
        block.header.parents.iter().filter_map(|p| d.get_block_data(p).map(|x| x.blue_score)),
    );
}

/// What happened to buffered orphans in the ingress core (for the gossip
/// verdicts withheld while they were orphans, [`DeferredBlockVerdicts`]).
#[derive(Debug, Default, Clone)]
pub struct OrphanBlockEvents {
    /// Drained orphans `accept_block` accepted.
    pub accepted: Vec<[u8; 32]>,
    /// Drained orphans `accept_block` rejected, with its error.
    pub rejected: Vec<([u8; 32], String)>,
    /// Drained orphans the work rule refused (B1-T5) — not stored.
    pub refused: Vec<([u8; 32], DropReason)>,
}

impl OrphanBlockEvents {
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty() && self.rejected.is_empty() && self.refused.is_empty()
    }
}

/// The work-rule gate the orphan drain calls for each orphan whose parents
/// are all known, before `accept_block` (see [`process_orphans_gated`]).
pub type DrainGate<'a> =
    dyn FnMut(&OrphanPool, &core::Block, &[u8; 32], &GhostDAG) -> Result<WorkAdmission, DropReason> + 'a;

/// After accepting a block, accept every buffered orphan that can now be
/// connected, transitively. Returns the hashes accepted, in order; `chain`
/// accumulates what they did to the applied chain (`accept::ChainMove`, for
/// the orphan-transaction bookkeeping, audit MEM-6).
///
/// POW-3 / POW-4 (audit): ITERATIVE (a work queue), not recursive — an
/// attacker-built chain of thousands of orphans used to recurse once per
/// accepted orphan on a 2 MiB worker stack
/// (`fix_ingress_dos::drain_of_a_deep_orphan_chain_runs_on_a_small_stack`).
///
/// B1-T5: each orphan is judged by the work rule again once its parents are
/// known: buffering only checked its bits against the orphan floor and its
/// proof of work, and the block it waited on may have been admitted only
/// because another orphan vouched for it — a low-work fork above such a block
/// used to be stored whole. This function applies the rule without the
/// ingress core's state (the orphan's own bound, or the orphans announced
/// above it; never a voucher, which needs the merge-backed budget); the node
/// uses [`BlockIngress::drain_orphans`], which applies the full rule.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // tests only; the node binary compiles this module too
pub fn process_orphans(
    accepted_hash: [u8; 32],
    orphans:       &mut OrphanPool,
    dag:           &Arc<RwLock<GhostDAG>>,
    store:         &Arc<Storage>,
    mempool:       &Arc<Mempool>,
    node_state:    &Arc<RwLock<NodeState>>,
    tip_tx:        Option<&broadcast::Sender<TipChanged>>,
    shielded:      &Arc<RwLock<ShieldedPool>>,
    chain:         &mut crate::accept::ChainMove,
) -> Vec<[u8; 32]> {
    let mut gate = |pool: &OrphanPool, block: &core::Block, hash: &[u8; 32], d: &GhostDAG| {
        let threshold = anti_dos_work_threshold(d);
        let lb = block_work_lower_bound(d, &block.header.parents, block.header.bits, block.height).unwrap_or(0);
        let above = if lb >= threshold { 0 } else { pool.announced_work_capped(hash, threshold - lb) };
        match work_admission(lb, threshold, above, 0) {
            WorkAdmission::LowWork => Err(DropReason::LowWork),
            a => Ok(a),
        }
    };
    let ctx = AcceptCtx { dag, store, mempool, node_state, tip_tx, shielded };
    let mut events = OrphanBlockEvents::default();
    process_orphans_gated(accepted_hash, orphans, &ctx, chain, &mut gate, &mut events);
    events.accepted
}

/// [`process_orphans`] with the work-rule `gate`; records every drained
/// orphan's outcome in `events`.
pub fn process_orphans_gated(
    accepted_hash: [u8; 32],
    orphans:       &mut OrphanPool,
    ctx:           &AcceptCtx,
    chain:         &mut crate::accept::ChainMove,
    gate:          &mut DrainGate<'_>,
    events:        &mut OrphanBlockEvents,
) {
    let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
    queue.push_back(accepted_hash);
    while let Some(parent) = queue.pop_front() {
        for orphan_hash in orphans.take_waiters(&parent) {
            let verdict = {
                let Some(e) = orphans.get(&orphan_hash) else { continue };
                let d = ctx.dag.read();
                // Still waiting on another parent: it stays registered under
                // that parent and is retried when it arrives.
                if !e.block.header.parents.iter().all(|p| d.has_block(p)) {
                    continue;
                }
                gate(orphans, &e.block, &orphan_hash, &d)
            };
            let Some(entry) = orphans.remove(&orphan_hash) else { continue };
            let height = entry.height;
            if let Err(reason) = verdict {
                // Not stored. The orphans above it stay buffered (they still
                // wait on it): if more work is announced above it, the orphan
                // sweep requests it again and it is judged again.
                debug!("orphan h={} refused by the work rule on drain: {:?}", height, reason);
                events.refused.push((orphan_hash, reason));
                continue;
            }
            let mut block = entry.block;
            normalize_wire_metadata(&mut block, ctx.dag);
            match crate::accept::accept_block_tracking(&block, orphan_hash, height, ctx.dag, ctx.store, ctx.mempool,
                                                       ctx.node_state, ctx.tip_tx, ctx.shielded, chain) {
                Ok(hash) => {
                    info!("✓ orphan h={} accepted (pool={})", height, orphans.len());
                    orphans.forget(&hash);
                    events.accepted.push(hash);
                    queue.push_back(hash);
                }
                Err(e) => {
                    warn!("orphan h={} rejected: {}", height, e);
                    events.rejected.push((orphan_hash, e));
                }
            }
        }
    }
}

/// What the acceptance pipeline needs (the arguments `accept_block` takes
/// besides the block).
pub struct AcceptCtx<'a> {
    pub dag:        &'a Arc<RwLock<GhostDAG>>,
    pub store:      &'a Arc<Storage>,
    pub mempool:    &'a Arc<Mempool>,
    pub node_state: &'a Arc<RwLock<NodeState>>,
    pub tip_tx:     Option<&'a broadcast::Sender<TipChanged>>,
    pub shielded:   &'a Arc<RwLock<ShieldedPool>>,
}

/// Why [`BlockIngress::handle_block`] dropped a block before evaluating its
/// proof of work. None of these is a protocol violation (gossip verdict
/// `Ignore`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// An orphan far below our tip that nobody asked for (backfill-flood
    /// guard: backfill is pulled, never pushed).
    UnsolicitedDeepOrphan,
    /// An orphan whose bits are easier than the anti-DoS floor.
    OrphanBelowFloor,
    /// POW-3: a block whose chain cannot reach the anti-DoS work threshold.
    LowWork,
    /// POW-3 / DAG-7 / B1-T5: a merge-backed block while the merge-backed
    /// insertion budget is exhausted (the orphan sweep re-requests it).
    DeepBudgetExhausted,
    /// POW-3 (Phase 4): an unrequested block while this node is below the
    /// minimum chain work, or one whose own chain work does not reach it
    /// (Bitcoin Core's `nMinimumChainWork` rule in `AcceptBlock`).
    BelowMinimumChainWork,
    /// POW-3 (Phase 4): an unrequested block whose chain work cannot come
    /// within [`UNREQUESTED_WINDOW_BLOCKS`] of the selected tip (Core:
    /// "don't process less-work chains" unless requested).
    UnrequestedLowWork,
    /// NET-2 residual (Phase 4): its proof of work would have to be
    /// evaluated but the delivering peer's or its network group's
    /// proof-of-work budget is spent, or the PoW queue is full
    /// (`pow::verifier`). Not evaluated, not relayed, not penalized.
    /// Returned by [`BlockIngress::handle_block`] only; the node answers a
    /// refused proof-of-work job directly.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    PowBusy,
}

/// At most this many pruned bodies are named by an operator override that
/// needs them (`accept::missing_bodies_below`); a retry names the next ones.
pub const MAX_BODY_REFETCH: usize = 4_096;

/// At most this many blocks that wait for a body are being fetched at once
/// (tracked in `parent_fetch`: requested through [`awaited_bodies_to_request`]
/// or re-requested by the orphan sweep through [`awaited_bodies_to_chase`]).
/// A quarter of the network's directed-pull queue
/// (`network::MAX_PENDING_PULLS`): a pruned node that waits for thousands of
/// bodies at once (a fork deeper than the pruning depth, audit DAG-6) must
/// not fill that queue with body pulls, which would make it drop the
/// orphan-parent and IBD pulls issued meanwhile (review of the P3 merge).
/// The other bodies are requested as these arrive or are given up on.
pub const MAX_BODY_PULLS_IN_FLIGHT: usize = crate::network::MAX_PENDING_PULLS / 4;

/// The blocks in the DAG whose body is wanted (`GhostDAG::wanted_body_blocks`:
/// they wait for a body and a chain through them can still become the best
/// one, or an operator override asked for it, re-audit B1-T13; see
/// `accept::awaits_body`) and are not already being fetched through
/// `parent_fetch`, as many as keep the bodies
/// being fetched at once within `limit` (those already tracked count). The
/// ONE request path for wanted bodies, whatever made them wanted (a
/// witness-dependent rejection, a connect or an operator override that needs
/// a missing or pruned body): the processor sends a directed GetBlock for
/// each and records it in `parent_fetch`, so the periodic sweep retries it
/// with backoff. Sorted; when the room is smaller than the candidates, a
/// random window of them ([`take_rotated`]). Pure selection: nothing is
/// recorded here.
pub fn awaited_bodies_to_request(
    dag: &GhostDAG,
    parent_fetch: &ParentFetchTracker,
    limit: usize,
) -> Vec<BlockHash> {
    let (in_flight, fresh): (Vec<BlockHash>, Vec<BlockHash>) = dag.wanted_body_blocks().into_iter()
        .partition(|h| parent_fetch.is_awaited(h));
    take_rotated(fresh, limit.saturating_sub(in_flight.len()))
}

/// The blocks whose body is wanted (`GhostDAG::wanted_body_blocks`) that the
/// periodic orphan sweep chases
/// (`ParentFetchTracker::sweep` retries each with backoff and forgets every
/// tracked hash NOT in its chased list): those already being fetched — at
/// most `limit`, so they keep their retry schedule — then not-yet-tracked
/// ones up to `limit` in total, which the sweep requests now. The bound keeps
/// the sweep's GetBlock bursts within [`MAX_BODY_PULLS_IN_FLIGHT`] however
/// many blocks wait (it used to chase every one, every period).
pub fn awaited_bodies_to_chase(
    dag: &GhostDAG,
    parent_fetch: &ParentFetchTracker,
    limit: usize,
) -> Vec<BlockHash> {
    let (mut in_flight, fresh): (Vec<BlockHash>, Vec<BlockHash>) = dag.wanted_body_blocks().into_iter()
        .partition(|h| parent_fetch.is_awaited(h));
    in_flight.truncate(limit);
    let room = limit - in_flight.len();
    in_flight.extend(take_rotated(fresh, room));
    in_flight
}

/// Up to `n` of the sorted `candidates`: all of them if they fit, otherwise
/// a window of `n` starting at a random offset (wrapping), sorted. A fixed
/// window would starve the blocks after it whenever the first ones cannot be
/// fetched (no peer serves them: the sweep gives up and chases them again).
fn take_rotated(candidates: Vec<BlockHash>, n: usize) -> Vec<BlockHash> {
    if candidates.len() <= n {
        return candidates;
    }
    if n == 0 {
        return Vec::new();
    }
    let start = rand::random_range(0..candidates.len());
    let mut out: Vec<BlockHash> = candidates.iter().cycle().skip(start).take(n).copied().collect();
    out.sort_unstable();
    out
}

/// What [`BlockIngress::handle_block`] did with one block.
#[derive(Debug)]
pub enum BlockOutcome {
    /// Already in the DAG or buffered (a copy of a DAG block is known unless
    /// a body of it is wanted, `accept::awaits_body`, and it is the answer to
    /// a directed pull).
    Known,
    /// The block was in the DAG and waited for a body (its body was rejected
    /// for a witness-dependent reason, or is missing — pruned and then
    /// reorganized away from, audit DAG-6); this copy passed `accept_block`'s
    /// body-replacement checks (header height implied by the DAG parents,
    /// expected bits, timestamp, hardening rules, proof of work, a witness
    /// root not rejected before) and is stored, so the chain through it can
    /// be connected again (it is, once nothing else is missing).
    BodyRestored,
    /// A wanted body (the answer to a directed pull of a block that waits
    /// for one) was not stored: `accept_block`'s error, or "body not stored".
    /// Judged like a first arrival's rejection (`verdict_for_accept_error`):
    /// a body rejected for a witness-dependent reason, already rejected, or
    /// lost to a node-local storage error says nothing about the peer that
    /// served it (below the activation the block id does not commit to
    /// non-coinbase `script_sig` bytes, so an honest peer may hold a
    /// malleated copy). Only a failure the block id commits to (proof of
    /// work, bits, height, timestamp, coinbase) is a `Reject`.
    BodyRefused(String),
    /// Dropped before any proof-of-work evaluation.
    Dropped(DropReason),
    /// Context-free invalid (structure, or an orphan's proof of work).
    Invalid(String),
    /// Buffered as an orphan; `request` = missing parents to fetch now.
    Buffered { request: Vec<[u8; 32]>, evidence: bool, evicted: usize },
    /// The orphan pool refused it (an earlier copy is buffered, or too large).
    PoolRefused,
    /// Its parents are known and it passed the POW-3 work rule (`admission`):
    /// `accept_block` ran (`result`) and, on success, the orphans waiting on
    /// it were drained (`drained`). `missing_bodies`: the blocks that now
    /// wait for a body and are not being fetched yet
    /// ([`awaited_bodies_to_request`]) — e.g. the pruned bodies the chain
    /// through this block needs (the block itself is accepted and connects
    /// once they are back) — for the caller to request.
    Processed {
        admission:      WorkAdmission,
        result:         Result<[u8; 32], String>,
        drained:        Vec<[u8; 32]>,
        missing_bodies: Vec<[u8; 32]>,
    },
}

/// How [`BlockIngress::handle_block_gated`] gets a block's proof of work
/// checked (NET-2 residual, Phase 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowCheck {
    /// The proof is valid (evaluated now, or known from an earlier
    /// evaluation; a valid proof is also in the PoW cache of `validate_pow`).
    Valid,
    /// The proof is invalid.
    Invalid,
    /// Not evaluated yet: the caller evaluates it OFF the message processor
    /// (`pow::verifier`) and submits the block again once the result is
    /// known.
    Deferred,
}

/// Where the ingress core's proof-of-work evaluations happen. The core asks
/// only after every cheap check passed (structure, the unrequested-block and
/// minimum-chain-work rules, the orphan floor or the work rule, and for a
/// block whose parents are known the header height, expected bits,
/// timestamp and hardened block rules `accept_block` checks first).
pub trait PowGate {
    fn check(&mut self, block: &core::Block, hash: &[u8; 32]) -> PowCheck;
}

/// Evaluate inline (64 MiB GnB-SMH on the calling thread): tests and
/// [`BlockIngress::handle_block`].
#[allow(dead_code)] // tests only; the node binary compiles this module too
pub struct InlinePow;

impl PowGate for InlinePow {
    fn check(&mut self, block: &core::Block, _hash: &[u8; 32]) -> PowCheck {
        if block.validate_pow() { PowCheck::Valid } else { PowCheck::Invalid }
    }
}

/// Outcome of [`BlockIngress::handle_block_gated`].
#[derive(Debug)]
pub enum Gated {
    /// Fully handled.
    Done(BlockOutcome),
    /// Every cheap check passed and the gate deferred the proof of work: the
    /// block is handed back, to be submitted again once its proof is known
    /// (the node keeps the frame's bytes instead and decodes them again).
    PowPending(#[allow(dead_code)] Box<core::Block>),
}

/// `accept_block`'s checks that come BEFORE its proof of work, for a block
/// whose parents are all in the DAG (header height = max parent DAG height +
/// 1, bits = expected ASERT bits of the parent set, timestamp bounds, the
/// hardened block rules at the activation height): true iff they all pass.
/// The node evaluates the 64 MiB proof only for such blocks; a block that
/// fails one goes to `accept_block` directly, which refuses it with its own
/// error before evaluating anything (one source of truth for the verdict).
pub fn passes_pre_pow_checks(block: &core::Block, dag: &GhostDAG, activation: u64) -> bool {
    if block.header.parents.is_empty() {
        return false;
    }
    let (mut max_h, mut max_ts) = (0u64, 0u64);
    for p in &block.header.parents {
        match dag.get_block_data(p) {
            Some(d) => {
                max_h = max_h.max(d.height);
                max_ts = max_ts.max(d.timestamp);
            }
            None => return false,
        }
    }
    if block.height != max_h.saturating_add(1) {
        return false;
    }
    match crate::pow::expected_bits(max_ts, block.height) {
        Ok(bits) if bits == block.header.bits => {}
        _ => return false,
    }
    block.validate_timestamp(max_ts).is_ok()
        && core::block_rules::check_block_hardened_at(block, activation).is_ok()
}

/// Bounded FIFO cache of LowWork verdicts (see [`BlockIngress`]).
#[derive(Default)]
struct LowWorkCache {
    seen:  HashMap<[u8; 32], LowWorkState>,
    order: VecDeque<[u8; 32]>,
}

impl LowWorkCache {
    fn hit(&self, hash: &[u8; 32], state: &LowWorkState) -> bool {
        self.seen.get(hash) == Some(state)
    }

    fn note(&mut self, hash: [u8; 32], state: LowWorkState) {
        if self.seen.insert(hash, state).is_none() {
            self.order.push_back(hash);
            while self.order.len() > LOW_WORK_CACHE_MAX {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }
}

/// The message processor's per-block core: everything it decides about an
/// inbound block (decoded and bound to its id and height by the caller)
/// before and around `accept_block`.
pub struct BlockIngress {
    pub orphans:      OrphanPool,
    pub parent_fetch: ParentFetchTracker,
    /// The merge-backed insertion budget (B1-T5: every merge-backed
    /// admission is charged, not only those more than `CHECKPOINT_DEPTH`
    /// below the tip).
    pub deep_budget:  DeepBackfillBudget,
    /// `(selected tip, anti_dos_work_threshold)` of the last work check: the
    /// threshold only changes when the selected tip does.
    threshold_cache:  Option<(BlockHash, u128)>,
    /// POW-3: blocks refused as `LowWork`, with the state they were refused
    /// in (orphan-pool generation, DAG size, selected tip). The verdict can
    /// only change with that state, so a re-sent refused block costs a map
    /// lookup, not another walk over the orphans above it. Bounded, FIFO.
    low_work:         LowWorkCache,
    /// POW-3 (Phase 4): the minimum chain work (see
    /// [`MAINNET_MINIMUM_CHAIN_WORK`]).
    min_chain_work:   u128,
    /// POW-4 test seam: the reference target the orphan floor and the IBD
    /// evidence derive from, instead of [`reference_target`] (node tests
    /// build with `test-pow-limit`, under which the clock-derived reference is
    /// the pow limit and the floor admits every decodable bits value).
    reference_override: Option<[u8; 32]>,
    /// What the `accept_block` calls of this core did to the applied chain
    /// since the last [`BlockIngress::take_chain_move`] (audit MEM-6: the
    /// orphan-transaction bookkeeping runs after the gossip verdict).
    chain:            crate::accept::ChainMove,
    /// What happened to drained orphans since the last
    /// [`BlockIngress::take_orphan_events`] (their withheld gossip verdicts).
    orphan_events:    OrphanBlockEvents,
}

type LowWorkState = (u64, usize, Option<BlockHash>);

/// Bound of the LowWork verdict cache of [`BlockIngress`].
pub const LOW_WORK_CACHE_MAX: usize = 4_096;

impl Default for BlockIngress {
    fn default() -> Self {
        Self::new()
    }
}

/// The POW-3 work rule (see [`BlockIngress::work_check`]) on the core's
/// parts, so the orphan drain can apply it while it holds the pool. With
/// `budget` `None` a merge-backed admission is classified but not charged:
/// the caller charges it once the block's proof is known valid.
#[allow(clippy::too_many_arguments)]
fn work_rule(
    orphans:         &OrphanPool,
    budget:          Option<&mut DeepBackfillBudget>,
    threshold_cache: &mut Option<(BlockHash, u128)>,
    low_work:        &mut LowWorkCache,
    block:           &core::Block,
    hash:            &[u8; 32],
    now:             Instant,
    now_unix:        u64,
    dag:             &GhostDAG,
) -> Result<WorkAdmission, DropReason> {
    let state: LowWorkState = (orphans.generation(), dag.block_count(), dag.selected_tip());
    if low_work.hit(hash, &state) {
        return Err(DropReason::LowWork);
    }
    let threshold = match (dag.selected_tip(), *threshold_cache) {
        (Some(tip), Some((cached_tip, t))) if tip == cached_tip => t,
        (tip, _) => {
            let t = anti_dos_work_threshold(dag);
            *threshold_cache = tip.map(|h| (h, t));
            t
        }
    };
    let lb = block_work_lower_bound(dag, &block.header.parents, block.header.bits, block.height).unwrap_or(0);
    let (chain_above, merge_lb) = if lb >= threshold {
        (0, 0)
    } else {
        let chain_above = orphans.announced_work_capped(hash, threshold - lb);
        if lb.saturating_add(chain_above) >= threshold {
            (chain_above, 0) // ChainBacked: the merge bound is not needed
        } else {
            let act = core::activation::hardening_activation_height();
            (chain_above, orphans.best_voucher_lb(hash, block, lb, dag, now_unix, act))
        }
    };
    match work_admission(lb, threshold, chain_above, merge_lb) {
        WorkAdmission::LowWork => {
            low_work.note(*hash, state);
            Err(DropReason::LowWork)
        }
        // B1-T5: every merge-backed admission is rationed (one voucher costs
        // one full block of work at the tip; the budget bounds how many
        // low-work blocks such vouchers can get stored).
        WorkAdmission::MergeBacked if budget.is_some_and(|b| !b.allow_at(now)) => Err(DropReason::DeepBudgetExhausted),
        ok => Ok(ok),
    }
}

impl BlockIngress {
    pub fn new() -> Self {
        Self::with_limits(OrphanLimits::default())
    }

    pub fn with_limits(limits: OrphanLimits) -> Self {
        Self {
            orphans: OrphanPool::new(limits),
            parent_fetch: ParentFetchTracker::new(),
            deep_budget: DeepBackfillBudget::new(),
            threshold_cache: None,
            low_work: LowWorkCache::default(),
            min_chain_work: minimum_chain_work(),
            reference_override: None,
            chain: crate::accept::ChainMove::default(),
            orphan_events: OrphanBlockEvents::default(),
        }
    }

    /// Use `w` as the minimum chain work (default: the process-wide
    /// [`minimum_chain_work`]).
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn with_minimum_chain_work(mut self, w: u128) -> Self {
        self.min_chain_work = w;
        self
    }

    /// The minimum chain work this core applies.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn minimum_chain_work(&self) -> u128 {
        self.min_chain_work
    }

    /// POW-4 test seam: derive the orphan floor and the IBD evidence from the
    /// reference target `t` instead of the clock and the selected tip
    /// ([`reference_target`]).
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn with_reference_target(mut self, t: [u8; 32]) -> Self {
        self.reference_override = Some(t);
        self
    }

    /// True while the selected tip has less blue work than the minimum chain
    /// work (Bitcoin Core's initial block download; the node reads
    /// [`minimum_chain_work`] in its IBD latch).
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn in_initial_download(&self, dag: &GhostDAG) -> bool {
        below_minimum_chain_work(dag, self.min_chain_work)
    }

    /// What this core's `accept_block` calls did to the applied chain since
    /// the last call (audit MEM-6: `TxRelay::on_chain_moved` consumes it).
    pub fn take_chain_move(&mut self) -> crate::accept::ChainMove {
        std::mem::take(&mut self.chain)
    }

    /// What happened to drained orphans since the last call (accepted,
    /// rejected by `accept_block`, refused by the work rule).
    pub fn take_orphan_events(&mut self) -> OrphanBlockEvents {
        std::mem::take(&mut self.orphan_events)
    }

    /// True iff some buffered orphan, an outstanding parent request or a
    /// remembered evicted orphan chain waits for `hash`.
    pub fn is_awaited(&self, hash: &[u8; 32]) -> bool {
        self.orphans.is_waited_on(hash) || self.parent_fetch.is_awaited(hash) || self.orphans.remembers(hash)
    }

    /// True iff this node asked for `hash`: the block is the answer to one
    /// of its directed pulls (`solicited`), or a request for it is
    /// outstanding (whoever delivers it — Bitcoin Core's `IsBlockRequested`).
    pub fn is_requested(&self, hash: &[u8; 32], solicited: bool) -> bool {
        solicited || self.parent_fetch.is_awaited(hash)
    }

    /// The POW-3 work rule for a block whose parents are all known (cheap:
    /// DAG lookups and the orphan pool, no proof of work), at the wall-clock
    /// time. `_tip_h` is no longer used: B1-T5 charges every merge-backed
    /// admission to the budget, not only those more than `CHECKPOINT_DEPTH`
    /// below the tip.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn work_check(
        &mut self,
        block: &core::Block,
        hash: &[u8; 32],
        _tip_h: u64,
        now: Instant,
        dag: &GhostDAG,
    ) -> Result<WorkAdmission, DropReason> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.work_check_at(block, hash, now, now_unix, dag)
    }

    /// [`Self::work_check`] at `now_unix`. B1-T5: a merge-backed admission
    /// needs a voucher that passes its contextual checks
    /// ([`OrphanPool::best_voucher_lb`]) and is charged to the merge-backed
    /// budget.
    pub fn work_check_at(
        &mut self,
        block: &core::Block,
        hash: &[u8; 32],
        now: Instant,
        now_unix: u64,
        dag: &GhostDAG,
    ) -> Result<WorkAdmission, DropReason> {
        work_rule(&self.orphans, Some(&mut self.deep_budget), &mut self.threshold_cache, &mut self.low_work,
            block, hash, now, now_unix, dag)
    }

    /// The reference target of the orphan floor and the IBD evidence.
    fn reference(&self, tip_h: u64, now_unix: u64) -> [u8; 32] {
        self.reference_override.unwrap_or_else(|| reference_target(tip_h, now_unix))
    }

    /// Handle one inbound block, evaluating its proof of work inline (see
    /// [`Self::handle_block_gated`]). The node itself defers the proof to its
    /// PoW workers (`handle_block_gated`); tests and the fuzz target use this.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn handle_block(
        &mut self,
        block: core::Block,
        hash: [u8; 32],
        wire_bytes: usize,
        peer: Option<PeerId>,
        solicited: bool,
        now: Instant,
        now_unix: u64,
        ctx: &AcceptCtx,
    ) -> BlockOutcome {
        match self.handle_block_gated(block, hash, wire_bytes, peer, solicited, now, now_unix, ctx, &mut InlinePow) {
            Gated::Done(o) => o,
            // `InlinePow` never defers.
            Gated::PowPending(_) => BlockOutcome::Dropped(DropReason::PowBusy),
        }
    }

    /// Handle one inbound block. Cheapest checks first:
    ///
    /// 1. already in the DAG (a wanted body, see [`Self::restore_body`]) or
    ///    buffered: known;
    /// 2. POW-3 (Phase 4), an UNREQUESTED block (gossip, not the answer to
    ///    one of this node's pulls nor a block it has an outstanding request
    ///    for): refused while the selected tip is below the minimum chain
    ///    work (unless its own chain reaches it), and refused if its chain
    ///    cannot come within [`UNREQUESTED_WINDOW_BLOCKS`] of the tip
    ///    ([`unrequested_block_admission`], Bitcoin Core's `AcceptBlock`);
    /// 3. structure without the proof of work;
    /// 4. an orphan: the backfill-flood guard and the orphan floor; a block
    ///    whose parents are known: the POW-3 work rule and the checks
    ///    `accept_block` runs before its proof ([`passes_pre_pow_checks`]);
    /// 5. the proof of work, through `pow` ([`PowGate`]: inline, or deferred
    ///    to the bounded PoW worker pool of the node, which then submits the
    ///    block again);
    /// 6. the orphan pool, or `accept_block` and the orphan drain (which
    ///    applies the work rule to each drained orphan, B1-T5).
    ///
    /// `solicited`: the block is the answer to one of this node's directed
    /// pulls (`InboundOrigin::is_solicited`), not gossip.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_block_gated(
        &mut self,
        mut block: core::Block,
        hash: [u8; 32],
        wire_bytes: usize,
        peer: Option<PeerId>,
        solicited: bool,
        now: Instant,
        now_unix: u64,
        ctx: &AcceptCtx,
        pow: &mut dyn PowGate,
    ) -> Gated {
        if ctx.dag.read().has_block(&hash) {
            return self.restore_body(block, hash, solicited, ctx);
        }
        if self.orphans.contains(&hash) {
            return Gated::Done(BlockOutcome::Known);
        }
        let (tip_h, missing, lb) = {
            let d = ctx.dag.read();
            let tip_h = d.selected_tip().and_then(|t| d.get_block_data(&t).map(|x| x.height)).unwrap_or(0);
            let missing: Vec<[u8; 32]> = block.header.parents.iter().filter(|p| !d.has_block(p)).copied().collect();
            let lb = block_work_lower_bound(&d, &block.header.parents, block.header.bits, block.height);
            // POW-3 (Phase 4): the unrequested-block rule, before anything
            // that costs more than a few DAG lookups.
            if !self.is_requested(&hash, solicited) {
                let near_tip = selected_chain_work_below(&d, UNREQUESTED_WINDOW_BLOCKS);
                if let Err(r) = unrequested_block_admission(lb, self.min_chain_work, tip_blue_work(&d), near_tip) {
                    return Gated::Done(BlockOutcome::Dropped(r));
                }
            }
            (tip_h, missing, lb)
        };
        // Cheap structural validation (merkle, coinbase format, duplicates,
        // dust, size, parent count) — NO PoW yet.
        if let Err(reason) = block.validate_structure_without_pow() {
            return Gated::Done(BlockOutcome::Invalid(reason.to_string()));
        }

        if !missing.is_empty() {
            // Orphan. Backfill-flood guard: a far-below-tip orphan nobody
            // asked for is dropped (backfill is pulled). An awaited one is
            // buffered — the expensive step, inserting it, happens only when
            // its chain connects and passes the POW-3 work rule there.
            if backfill_decision(block.height, tip_h, self.is_awaited(&hash))
                == BackfillDecision::DropUnsolicitedDeep
            {
                return Gated::Done(BlockOutcome::Dropped(DropReason::UnsolicitedDeepOrphan));
            }
            // NET-2 / POW-4: bits no easier than the anti-DoS floor BEFORE
            // the proof is evaluated.
            // The cap is the pow limit of the height the orphan claims (the
            // one its proof is checked against), not the tip's next height.
            // Across the GnB-SMH v1 -> v3 switch the reference is first
            // re-expressed in the orphan's own algorithm (equal work).
            let reference = reference_for_height(&self.reference(tip_h, now_unix), tip_h.saturating_add(1), block.height);
            let floor = orphan_floor_from(&reference, block.height);
            if !bits_meet_floor(block.header.bits, &floor) {
                return Gated::Done(BlockOutcome::Dropped(DropReason::OrphanBelowFloor));
            }
            match pow.check(&block, &hash) {
                PowCheck::Valid => {}
                PowCheck::Invalid => return Gated::Done(BlockOutcome::Invalid("invalid PoW".into())),
                PowCheck::Deferred => return Gated::PowPending(Box::new(block)),
            }
            let evidence = orphan_is_sync_evidence_from(block.header.bits, block.height, tip_h, &reference);
            // Request each missing parent that nobody is waiting for and that
            // is not itself buffered (a deep gap fans out one level at a time).
            let fresh: Vec<[u8; 32]> = missing.iter()
                .filter(|mp| !self.orphans.is_waited_on(mp) && !self.orphans.contains(mp))
                .copied()
                .collect();
            let height = block.height;
            match self.orphans.insert(hash, block, height, wire_bytes, peer, evidence, &missing) {
                OrphanInsert::Inserted { evicted } => {
                    for mp in &fresh {
                        self.parent_fetch.note_requested(*mp, now);
                    }
                    debug!("orphan block h={} (missing {} parents), buffered (pool={} / {} bytes)",
                        height, missing.len(), self.orphans.len(), self.orphans.total_bytes());
                    Gated::Done(BlockOutcome::Buffered { request: fresh, evidence, evicted: evicted.len() })
                }
                OrphanInsert::Duplicate | OrphanInsert::TooLarge => Gated::Done(BlockOutcome::PoolRefused),
            }
        } else {
            let _ = lb;
            // All parents known: POW-3 work rule before any expensive step.
            let (admission, pre_pow_ok) = {
                let d = ctx.dag.read();
                // The work rule on the read guard's DAG; a merge-backed
                // admission is charged below, once its proof is known valid.
                let a = match work_rule(&self.orphans, None, &mut self.threshold_cache, &mut self.low_work,
                    &block, &hash, now, now_unix, &d)
                {
                    Ok(a) => a,
                    Err(r) => return Gated::Done(BlockOutcome::Dropped(r)),
                };
                (a, passes_pre_pow_checks(&block, &d, core::activation::hardening_activation_height()))
            };
            // NET-2 residual: the proof is evaluated (inline, or on the PoW
            // worker pool) only for a block that passes every check
            // `accept_block` runs before it; one that does not is refused by
            // `accept_block` below, before any evaluation.
            if pre_pow_ok {
                match pow.check(&block, &hash) {
                    PowCheck::Valid => {}
                    PowCheck::Invalid => {
                        return Gated::Done(BlockOutcome::Processed {
                            admission,
                            result: Err("consensus rejection: invalid GnB-SMH proof of work".into()),
                            drained: Vec::new(),
                            missing_bodies: Vec::new(),
                        });
                    }
                    PowCheck::Deferred => return Gated::PowPending(Box::new(block)),
                }
                // B1-T5 (review finding): the merge-backed ration is spent
                // once, when the block is about to be stored with a valid
                // proof. Spent before the proof it was charged twice (the
                // first pass, then the resubmission once the PoW worker is
                // done) and junk-nonce candidates drained it for free.
                if admission == WorkAdmission::MergeBacked && !self.deep_budget.allow_at(now) {
                    return Gated::Done(BlockOutcome::Dropped(DropReason::DeepBudgetExhausted));
                }
            }
            normalize_wire_metadata(&mut block, ctx.dag);
            let height = block.height;
            let result = crate::accept::accept_block_tracking(
                &block, hash, height, ctx.dag, ctx.store, ctx.mempool, ctx.node_state,
                ctx.tip_tx, ctx.shielded, &mut self.chain,
            );
            let drained = match &result {
                Ok(h) => {
                    self.orphans.forget(h);
                    self.drain_orphans_at(*h, now, now_unix, ctx)
                }
                Err(_) => Vec::new(),
            };
            // Bodies the connect (of this block or a drained orphan) found
            // missing — pruned ones included (audit DAG-6) — or rejected for a
            // witness-dependent reason now wait for one; the caller requests
            // them (`awaited_bodies_to_request`, the one request path).
            let missing_bodies = awaited_bodies_to_request(&ctx.dag.read(), &self.parent_fetch, MAX_BODY_PULLS_IN_FLIGHT);
            Gated::Done(BlockOutcome::Processed { admission, result, drained, missing_bodies })
        }
    }

    /// A block that is already in the DAG. Its copy is processed only if a
    /// body of it is wanted (`accept::awaits_body`, the one predicate: a
    /// witness-dependent rejection of its body, or a connect / operator
    /// override that needs its missing — e.g. pruned, audit DAG-6 — body) and
    /// it arrived as the answer to a directed pull, which is how the processor
    /// requests wanted bodies. Anything else is `Known` before any decoding
    /// work, proof of work or storage — the bodies of applied blocks are never
    /// needed (a rollback works from undo data), and an unrequested old body
    /// used to cost a 64 MiB proof evaluation and a disk write, for free.
    ///
    /// A wanted copy goes through `accept_block`'s body-replacement path:
    /// header height = max(parent DAG heights) + 1 (what the block was
    /// accepted at; `height` and `blue_score` are not committed by the block
    /// id), expected bits, timestamp, the hardening block rules (witness
    /// commitment at/after the activation), the proof of work's cheap checks
    /// and the rejected-witness-root memo; it is stored with the metadata
    /// acceptance derives, and the chain through it is re-evaluated. Its
    /// proof is NOT evaluated again, here or on the PoW workers: the block's
    /// DAG record is the verified result of that proof at that height, and
    /// survives restarts (`pow::proof_recorded_in_dag`, P5-G). A restored
    /// body used to cost a GnB-SMH evaluation whenever the process had
    /// forgotten the proof (after any restart): one per body of a reorg back
    /// onto a pruned branch.
    fn restore_body(
        &mut self,
        mut block: core::Block,
        hash: [u8; 32],
        solicited: bool,
        ctx: &AcceptCtx,
    ) -> Gated {
        if !solicited || !crate::accept::awaits_body(ctx.dag, ctx.store, &hash) {
            return Gated::Done(BlockOutcome::Known);
        }
        // Never for an applied block (it has an undo record).
        if ctx.store.has_undo_data(&hash).unwrap_or(true) {
            return Gated::Done(BlockOutcome::Known);
        }
        // Cheapest check first (no proof of work).
        if let Err(reason) = block.validate_structure_without_pow() {
            return Gated::Done(BlockOutcome::Invalid(reason.to_string()));
        }
        // POW-8: the wire blue_score is replaced exactly as on acceptance.
        normalize_wire_metadata(&mut block, ctx.dag);
        let height = block.height;
        let result = crate::accept::accept_block_tracking(
            &block, hash, height, ctx.dag, ctx.store, ctx.mempool, ctx.node_state,
            ctx.tip_tx, ctx.shielded, &mut self.chain,
        );
        // Stored and no longer waiting: restored (the block itself may still
        // be disqualified for another reason, e.g. an operator mark, which
        // `accept_block` reports as its error).
        let restored = ctx.store.has_block_body(&hash).unwrap_or(false)
            && !ctx.dag.read().is_body_pending(&hash);
        Gated::Done(match result {
            _ if restored => BlockOutcome::BodyRestored,
            Err(e) => BlockOutcome::BodyRefused(e),
            Ok(_) => BlockOutcome::BodyRefused("body not stored".into()),
        })
    }

    /// [`process_orphans_gated`] on this core's pool, with the full POW-3
    /// work rule applied to each drained orphan (B1-T5). Returns the
    /// accepted hashes; every drained orphan's outcome is also recorded for
    /// [`Self::take_orphan_events`].
    pub fn drain_orphans(&mut self, accepted: [u8; 32], ctx: &AcceptCtx) -> Vec<[u8; 32]> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.drain_orphans_at(accepted, Instant::now(), now_unix, ctx)
    }

    fn drain_orphans_at(&mut self, accepted: [u8; 32], now: Instant, now_unix: u64, ctx: &AcceptCtx) -> Vec<[u8; 32]> {
        let Self { orphans, deep_budget, threshold_cache, low_work, chain, .. } = self;
        let mut gate = |pool: &OrphanPool, block: &core::Block, hash: &[u8; 32], d: &GhostDAG| {
            work_rule(pool, Some(&mut *deep_budget), threshold_cache, low_work, block, hash, now, now_unix, d)
        };
        let mut events = OrphanBlockEvents::default();
        process_orphans_gated(accepted, orphans, ctx, chain, &mut gate, &mut events);
        let out = events.accepted.clone();
        self.orphan_events.accepted.extend(events.accepted);
        self.orphan_events.rejected.extend(events.rejected);
        self.orphan_events.refused.extend(events.refused);
        out
    }
}

// ── PoWit gossip (`NewPowitItem`): bounds and rollout-gated penalties ────────
//
// The PoWit relay merged from the mainnet line judged every gossiped witness
// share, attestation and equivocation proof with `powit::admit_item` awaited
// INLINE on the block processor, unbudgeted: a share's proof is a GnB-SMH v3
// evaluation (4 MiB, ~90 ms), an attestation a KES signature check, both free
// to fake, so a flood of junk items stalled block processing (the NET-2
// residual on the new topic), and an item whose claimed id did not match was
// `Reject`ed whoever delivered it (the B1-T7 question). Now:
//
// * PoWit items travel on the transaction topic and are delivered to the
//   transaction relay task (`NetworkNode::attach_tx_ingest`, B1-T19), never
//   to the block processor;
// * cheap, context-free checks first ([`powit_item_precheck`]: the claimed id
//   is the item's id, the data is exactly one well-formed item of its kind);
// * verification runs on the blocking pool through a proof-of-work scheduler
//   of its own (`pow::verifier`, [`PowLimits::powit_items`]): bounded
//   concurrency in its own worker slots, a queue bounded globally, per
//   delivering peer and per network group, failed verifications charged to
//   the peer's and its group's budgets (refunded when the item is admitted
//   or fails only for context); an item still queued when its frame left
//   gossipsub's cache is answered `Ignore` unevaluated;
// * a context-free fault (id mismatch, malformed item, invalid share proof,
//   invalid witness signature, invalid equivocation proof — what no release
//   that knows `NewPowitItem` relays: they all admit an item before relaying
//   it) is penalised through the block gate, [`block_penalty`]: its author
//   when it delivered the frame itself (misbehaving: disconnect and address
//   discouragement, `Ignore` to gossipsub), a relay only once penalties are
//   in force ([`block_penalties_in_force`]); a fault that depends on this
//   node's chain (a share for a block not on its selected chain or outside
//   the window, an attestation from another justified checkpoint or by a key
//   outside the witness set, a full pool) is `Ignore`, never penalised;
//   an equivocation proof against a key outside the recent witness sets is
//   refused before its signatures are checked and keeps its budget charge
//   ([`powit_admit_error_keeps_charge`]).

/// The context-free checks of a gossiped PoWit item, before any
/// verification is queued: the claimed id is `powit::item_id(kind, data)` and
/// `data` decodes as exactly one item of `kind` (no trailing bytes). Cheap:
/// one SHA3 over at most `MAX_WIRE_POWIT_ITEM` bytes and a bounded decode.
pub fn powit_item_precheck(claimed: &[u8; 32], kind: u8, data: &[u8]) -> Result<(), String> {
    if crate::powit::item_id(kind, data) != *claimed {
        return Err("PoWit item id does not match its content".into());
    }
    let mut cur = std::io::Cursor::new(data);
    match kind {
        crate::powit::ITEM_SHARE => core::witness_share::WitnessShare::read_wire(&mut cur).map(|_| ()),
        crate::powit::ITEM_ATTESTATION => core::powit::Attestation::read_wire(&mut cur).map(|_| ()),
        crate::powit::ITEM_EVIDENCE => core::powit::Equivocation::read_wire(&mut cur).map(|_| ()),
        k => Err(format!("unknown PoWit item kind {k}")),
    }
    .map_err(|e| format!("malformed PoWit item: {e}"))?;
    if cur.position() as usize != data.len() {
        return Err("malformed PoWit item: trailing bytes".into());
    }
    Ok(())
}

/// `powit::check_share`'s refusal of a share that pays an invalid script.
pub const POWIT_SHARE_BAD_PAYOUT: &str = "witness share pays an invalid script";
/// `powit::PowitPool::admit_attestation`'s refusal of a bad signature.
pub const POWIT_BAD_ATTESTATION_SIGNATURE: &str = "invalid attestation signature";

/// The fault class of a `powit::admit_item` refusal of an item of `kind`
/// that passed [`powit_item_precheck`]: `Some(ContextFree)` when no honest
/// node produces or relays it — an invalid share proof (or bits, target or
/// payout that the share's own attested block contradicts), an invalid
/// attestation signature, an equivocation proof that does not verify (its
/// check uses only the network's constants); `None` when it depends on this
/// node's chain or state (stale, another branch, witness set, pool full,
/// storage) — never penalised. Unknown wording is `None` (fail safe).
pub fn powit_admit_error_fault(kind: u8, err: &str) -> Option<BlockFault> {
    use core::witness_share::ShareError;
    let context_free = match kind {
        crate::powit::ITEM_SHARE => {
            err == POWIT_SHARE_BAD_PAYOUT
                || [ShareError::InsufficientWork, ShareError::WrongBits, ShareError::BadTarget, ShareError::PayoutTooLong]
                    .iter()
                    .any(|e| err == e.to_string())
        }
        crate::powit::ITEM_ATTESTATION => err == POWIT_BAD_ATTESTATION_SIGNATURE,
        crate::powit::ITEM_EVIDENCE => err.starts_with("equivocation: "),
        _ => false,
    };
    context_free.then_some(BlockFault::ContextFree)
}

/// Whether a `powit::admit_item` refusal keeps the delivering peer's
/// verification-budget charge although it is no misbehaviour (`Ignore`): an
/// equivocation proof against a key outside this node's recent witness sets
/// (`powit::EVIDENCE_NOT_A_WITNESS`, PoWit audit finding 1). Such a proof is
/// valid wherever its key is a witness, so it is never penalised; but it is
/// free to forge in bulk (one SHA3 per re-rooted KES key), so relaying them
/// costs the relay its budget as an invalid item would, as Bitcoin Core
/// counts what a peer makes it do before the expensive checks.
pub fn powit_admit_error_keeps_charge(kind: u8, err: &str) -> bool {
    kind == crate::powit::ITEM_EVIDENCE && err == crate::powit::EVIDENCE_NOT_A_WITNESS
}

/// A gossiped PoWit item waiting for (or under) verification.
#[derive(Debug)]
pub struct PowitItem {
    pub kind:          u8,
    pub data:          Vec<u8>,
    pub origin:        crate::network::InboundOrigin,
    /// The delivering peer authored the frame (B1-T7).
    pub self_authored: bool,
}

/// A PoWit verification job (see [`PowitIngress`]).
pub type PowitJob = PowJob<PowitItem>;

/// What to report for a PoWit frame now.
#[derive(Debug)]
pub struct PowitVerdict {
    pub origin:  crate::network::InboundOrigin,
    pub penalty: BlockPenalty,
}

/// The transaction relay task's PoWit gossip core (see the section comment):
/// cheap checks, then a bounded, budgeted verification queue.
pub struct PowitIngress {
    sched: PowScheduler<PowitItem>,
}

impl Default for PowitIngress {
    fn default() -> Self {
        Self::new(PowLimits::powit_items())
    }
}

impl PowitIngress {
    pub fn new(limits: PowLimits) -> Self {
        Self { sched: PowScheduler::new(limits) }
    }

    /// The scheduler (counters, tests).
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn scheduler(&self) -> &PowScheduler<PowitItem> {
        &self.sched
    }

    /// A gossiped `NewPowitItem { id: claimed, kind, data }` delivered with
    /// `origin` by `source`. `Some`: report this now (a context-free fault,
    /// charged to the deliverer's budget and penalised through
    /// [`block_penalty`]; or `Ignore` for a frame the queue refused). `None`:
    /// queued; its verdict comes from [`Self::complete`] or
    /// [`Self::start_next`] (expired).
    #[allow(clippy::too_many_arguments)]
    pub fn on_item(
        &mut self,
        claimed: [u8; 32],
        kind: u8,
        data: Vec<u8>,
        origin: crate::network::InboundOrigin,
        source: PowSource,
        penalties_in_force: bool,
        now: Instant,
    ) -> Option<PowitVerdict> {
        let self_authored = origin.delivered_by_author();
        if let Err(e) = powit_item_precheck(&claimed, kind, &data) {
            debug!("PoWit item {} refused before verification: {}", hex::encode(&claimed[..8]), e);
            let _ = self.sched.charge(&source, now);
            let penalty = block_penalty(GossipVerdict::Reject, BlockFault::ContextFree, self_authored, penalties_in_force);
            return Some(PowitVerdict { origin, penalty });
        }
        let job = PowJob {
            id: claimed,
            height: 0,
            source,
            solicited: false,
            received_at: origin.received_at().unwrap_or(now),
            payload: PowitItem { kind, data, origin, self_authored },
        };
        match self.sched.submit(job, now) {
            Ok(()) => None,
            Err((refusal, job)) => {
                debug!("PoWit item {} not verified: queue refused it ({:?})", hex::encode(&claimed[..8]), refusal);
                Some(PowitVerdict { origin: job.payload.origin, penalty: plain_penalty(GossipVerdict::Ignore) })
            }
        }
    }

    /// The next job a worker slot is free for (see
    /// [`PowScheduler::start_next`]): `Start` — verify it (`powit::admit_item`)
    /// on the blocking pool and pass the result to [`Self::complete`];
    /// `Expired` — answer its frame `Ignore` unverified.
    pub fn start_next(&mut self, now: Instant) -> StartNext<PowitItem> {
        self.sched.start_next(now)
    }

    /// The result of a started job (`powit::admit_item`): frees its worker
    /// slot, refunds the budget charge unless the item failed for a
    /// context-free fault or is a charged refusal
    /// ([`powit_admit_error_keeps_charge`]), and returns what to report for its frame
    /// (`Accept` for an admitted item: relayed).
    pub fn complete(&mut self, job: PowitJob, result: &Result<(), String>, penalties_in_force: bool, now: Instant) -> PowitVerdict {
        let fault = match result {
            Ok(()) => None,
            Err(e) => powit_admit_error_fault(job.payload.kind, e),
        };
        let keeps_charge = matches!(result, Err(e) if powit_admit_error_keeps_charge(job.payload.kind, e));
        // `valid` = no context-free failure and no charged refusal: the
        // charge is refunded.
        self.sched.complete(job.outcome(fault.is_none() && !keeps_charge), now);
        let penalty = match (result, fault) {
            (Ok(()), _) => plain_penalty(GossipVerdict::Accept),
            (Err(_), Some(f)) => block_penalty(GossipVerdict::Reject, f, job.payload.self_authored, penalties_in_force),
            (Err(_), None) => plain_penalty(GossipVerdict::Ignore),
        };
        PowitVerdict { origin: job.payload.origin, penalty }
    }

    /// Housekeeping of the budget maps.
    pub fn gc_at(&mut self, now: Instant) {
        self.sched.gc_at(now);
    }
}

fn plain_penalty(gossip: GossipVerdict) -> BlockPenalty {
    BlockPenalty { gossip, misbehaving: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(parents: Vec<[u8; 32]>, tag: u64) -> core::Block {
        core::Block {
            header: core::BlockHeader {
                version: 1,
                parents,
                merkle_root: core::MerkleRoot::ZERO,
                timestamp: tag,
                bits: core::POW_LIMIT_BITS,
                nonce: tag,
            },
            transactions: vec![],
            blue_score: 0,
            height: 0,
            shielded_transactions: vec![],
            powit: Default::default(),
        }
    }

    fn h(i: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_le_bytes());
        b
    }

    #[test]
    fn height_checks_never_overflow() {
        assert!(unsolicited_height_too_far_ahead(u64::MAX, 40_000));
        assert!(!unsolicited_height_too_far_ahead(40_500, 40_000));
        assert!(!unsolicited_height_too_far_ahead(u64::MAX, u64::MAX));
        assert_eq!(backfill_decision(u64::MAX, 40_000, false), BackfillDecision::Pass);
        assert_eq!(backfill_decision(1, 40_000, false), BackfillDecision::DropUnsolicitedDeep);
        assert_eq!(backfill_decision(1, 40_000, true), BackfillDecision::AwaitedDeep);
        assert_eq!(backfill_decision(1, 500, false), BackfillDecision::Pass);
    }

    #[test]
    fn supervisor_backoff_resets_after_healthy_run() {
        let mut b = SupervisorBackoff::new(Duration::from_millis(100), Duration::from_secs(30));
        assert_eq!(b.on_panic(Duration::ZERO), Duration::from_millis(100));
        assert_eq!(b.on_panic(Duration::ZERO), Duration::from_millis(200));
        for _ in 0..20 { b.on_panic(Duration::ZERO); }
        assert_eq!(b.on_panic(Duration::ZERO), Duration::from_secs(30), "capped");
        assert_eq!(b.on_panic(SUPERVISOR_HEALTHY_RESET), Duration::from_millis(100), "reset after a healthy run");
    }

    #[test]
    fn verdict_mapping() {
        assert_eq!(verdict_for_accept_error("consensus rejection: invalid GnB-SMH proof of work"), GossipVerdict::Reject);
        assert_eq!(verdict_for_accept_error("invalid difficulty: block bits 0x1 != expected 0x2"), GossipVerdict::Reject);
        assert_eq!(verdict_for_accept_error("invalid height: block claims h=9 but expected h=2"), GossipVerdict::Reject);
        assert_eq!(verdict_for_accept_error("consensus rejection: block already in DAG: ab"), GossipVerdict::Ignore);
        assert_eq!(verdict_for_accept_error("timestamp rejected: timestamp too far in the future"), GossipVerdict::Ignore);
        assert_eq!(verdict_for_accept_error("finality: block h=3 may not become the selected tip"), GossipVerdict::Ignore);
        assert_eq!(verdict_for_block_decode_error("tx[0] parse: non-canonical varint: 12 encoded with the 0xFD form"),
            GossipVerdict::Ignore);
        assert_eq!(verdict_for_block_decode_error("trailing bytes in block body: parsed 5 of 7"), GossipVerdict::Reject);
    }

    /// PoW v3: the orphan floor's reference is re-expressed in the orphan's
    /// algorithm across the GnB-SMH v1 -> v3 switch (equal work,
    /// `core::adjust_bits_for_algo` / `core::block_work`); same algorithm on
    /// both sides: unchanged.
    #[test]
    fn floor_reference_follows_the_pow_algorithm_switch() {
        use primitive_types::U256;
        const V3: u64 = 10_000;
        let reference = core::bits_to_target(0x1d00_ffff);
        let r = U256::from_big_endian(&reference);
        let s = core::POW_V3_DIFFICULTY_SHIFT as usize;
        assert_eq!(reference_for_height_with(&reference, V3 + 5, V3 + 1, V3), reference, "v3 / v3");
        assert_eq!(reference_for_height_with(&reference, 7, 6, V3), reference, "v1 / v1");
        // v3 reference (tip past the switch), v1 orphan (a fork below it):
        // the v1 target of equal work is 2^shift times easier.
        assert_eq!(U256::from_big_endian(&reference_for_height_with(&reference, V3 + 5, V3 - 1, V3)), r << s);
        // v1 reference, v3 orphan: 2^shift times harder.
        assert_eq!(U256::from_big_endian(&reference_for_height_with(&reference, V3 - 1, V3, V3)), r >> s);
        // A v1 orphan whose bits are 4x easier than the v3 reference passes
        // the floor derived from the re-expressed reference, as a v3 orphan
        // of the same work passes the v3 floor.
        let v1_equal_work = core::target_to_bits(&(r << s).to_big_endian());
        let floor = ease_target_to(&reference_for_height_with(&reference, V3 + 5, V3 - 1, V3),
            ORPHAN_WORK_FLOOR_SHIFT, &[0xFF; 32]);
        assert!(bits_meet_floor(v1_equal_work, &floor));
        let floor_unadjusted = ease_target_to(&reference, ORPHAN_WORK_FLOOR_SHIFT, &[0xFF; 32]);
        let v1_16x = core::target_to_bits(&(r << (s + ORPHAN_WORK_FLOOR_SHIFT as usize)).to_big_endian());
        assert!(bits_meet_floor(v1_16x, &floor) && !bits_meet_floor(v1_16x, &floor_unadjusted),
            "16x below the reference in work: passes only with the re-expressed reference");
    }

    #[test]
    fn ease_target_saturates_at_pow_limit() {
        // The cap is the pow limit of the height (POW-3: the genesis target
        // at/after the hardening activation). Explicit schedules: the
        // test-only pow limit the node's tests build with pins every
        // height's limit to `POW_LIMIT_BITS`.
        let legacy = core::bits_to_target(core::POW_LIMIT_BITS);
        let genesis = core::bits_to_target(core::GENESIS_BITS);
        assert!(genesis < legacy);
        for limit in [legacy, genesis] {
            assert_eq!(ease_target_to(&legacy, 4, &limit), limit);
            assert_eq!(ease_target_to(&[0u8; 32], 4, &limit), limit, "a zero target falls back to the limit");
        }
        assert_eq!(ease_target(&legacy, 4, 1), core::Block::pow_limit_target_for_height(1));
        for h in [1u64, core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT, u64::MAX] {
            assert!(reference_target(h.saturating_sub(1), 0) <= core::Block::pow_limit_target_for_height(h));
        }
        let limit = core::bits_to_target(core::POW_LIMIT_BITS);
        let g = core::bits_to_target(core::GENESIS_BITS);
        let eased = ease_target(&g, 4, 1);
        assert!(eased > g && eased <= limit);
        assert!(bits_meet_floor(core::GENESIS_BITS, &eased));
        assert!(!bits_meet_floor(core::POW_LIMIT_BITS, &eased), "pow-limit bits are easier than the floor");
        assert!(!bits_meet_floor(0x0480_0001, &limit), "malformed bits never meet a floor");
    }

    /// Review of the P3 merge: the orphan floor is capped at the pow limit of
    /// the height the orphan CLAIMS (what `validate_pow` checks its proof
    /// against), not of the tip's next height. Mainnet schedule (activation
    /// `MAINNET_HARDENING_ACTIVATION_HEIGHT`), tip past the activation with
    /// the network at the genesis target: an orphan of a heavier fork at a
    /// pre-activation height whose legal bits are 4x easier than the genesis
    /// target is admitted (it was dropped as `OrphanBelowFloor` when the cap
    /// was the genesis target of height tip+1), while the same bits at a
    /// post-activation height still fail (they fail `validate_pow` there
    /// anyway).
    #[test]
    fn orphan_floor_cap_follows_the_orphans_own_height() {
        const ACT: u64 = core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
        let pow_limit_at = |h: u64| core::bits_to_target(core::block_rules::pow_limit_bits_at(h, ACT));
        let genesis = core::bits_to_target(core::GENESIS_BITS);
        // Network target near the genesis target after the activation: the
        // reference a child of the tip at ACT + 500 would carry.
        let reference = genesis;
        let easier_4x = {
            use primitive_types::U256;
            (U256::from_big_endian(&genesis) << 2usize).to_big_endian()
        };
        let bits_4x = core::target_to_bits(&easier_4x);
        assert!(core::bits_to_target(bits_4x) > genesis, "easier than the genesis target");
        assert!(core::bits_to_target(bits_4x) <= pow_limit_at(ACT - 1), "legal below the activation");

        // `orphan_admission_floor` under this schedule: the reference eased
        // 16-fold, capped at the pow limit of the orphan's claimed height.
        let floor = |claimed: u64| ease_target_to(&reference, ORPHAN_WORK_FLOOR_SHIFT, &pow_limit_at(claimed));
        let pre = floor(ACT - 1);
        assert!(bits_meet_floor(bits_4x, &pre), "a pre-activation orphan with legal bits is admitted");
        assert_eq!(pre, ease_target_to(&reference, ORPHAN_WORK_FLOOR_SHIFT, &pow_limit_at(0)),
            "below the activation: the legacy cap, i.e. 16x the reference");
        // The pre-merge cap (pow limit of tip_h + 1) dropped it.
        let at_tip_next = floor(ACT + 501);
        assert_eq!(at_tip_next, genesis);
        assert!(!bits_meet_floor(bits_4x, &at_tip_next));
        // Never easier than 16x the reference, whatever height is claimed.
        let eased_16x = ease_target_to(&reference, ORPHAN_WORK_FLOOR_SHIFT, &core::bits_to_target(core::POW_LIMIT_BITS));
        assert!(pre <= eased_16x);
        let too_easy = {
            use primitive_types::U256;
            core::target_to_bits(&(U256::from_big_endian(&genesis) << 5usize).to_big_endian())
        };
        assert!(!bits_meet_floor(too_easy, &pre), "32x easier than the reference: below the floor");
    }

    #[test]
    fn derived_blue_score_ignores_wire_value() {
        assert_eq!(derived_blue_score([5u64, 9, 7]), 10);
        assert_eq!(derived_blue_score(std::iter::empty()), 1);
        assert_eq!(derived_blue_score([u64::MAX]), u64::MAX);
    }

    #[test]
    fn claims_never_latch_and_are_rate_limited() {
        let mut p = ClaimPolicy::new();
        let t0 = Instant::now();
        let a = p.evaluate(u64::MAX, 100, t0);
        assert_eq!(a.clamped, 100 + crate::network::MAX_ANNOUNCED_LOOKAHEAD);
        assert!(a.pull);
        assert!(!p.evaluate(u64::MAX, 100, t0 + Duration::from_secs(1)).pull, "rate-limited");
        assert!(p.evaluate(u64::MAX, 100, t0 + CLAIM_PULL_MIN_INTERVAL).pull);
        let b = p.evaluate(5, 100, t0);
        assert!(b.reciprocal && !b.pull);
    }

    #[test]
    fn orphan_pool_first_copy_wins_and_fifo_eviction() {
        let limits = OrphanLimits { max_entries: 3, max_bytes: 1_000, max_entries_per_peer: 3, max_bytes_per_peer: 1_000 };
        let mut pool = OrphanPool::new(limits);
        for i in 0..3 {
            assert!(matches!(pool.insert(h(i), blk(vec![h(100 + i)], i), 10, 10, None, false, &[h(100 + i)]), OrphanInsert::Inserted { .. }));
        }
        assert_eq!(pool.insert(h(0), blk(vec![h(100)], 0), u64::MAX, 10, None, false, &[h(100)]), OrphanInsert::Duplicate);
        assert_eq!(pool.get(&h(0)).unwrap().height, 10, "the first copy is kept");
        // A 4th entry evicts the OLDEST arrival (h0), regardless of heights.
        match pool.insert(h(3), blk(vec![h(103)], 3), 0, 10, None, false, &[h(103)]) {
            OrphanInsert::Inserted { evicted } => assert_eq!(evicted, vec![h(0)]),
            other => panic!("{other:?}"),
        }
        assert!(!pool.is_waited_on(&h(100)), "evicted orphan detached from its parent");
    }

    #[test]
    fn orphan_pool_drop_subtree_is_iterative() {
        let mut pool = OrphanPool::new(OrphanLimits {
            max_entries: 10_000, max_bytes: 1 << 20, max_entries_per_peer: 10_000, max_bytes_per_peer: 1 << 20,
        });
        // chain: h1 waits on h0 (missing), h2 waits on h1, ... 5_000 deep
        for i in 1..=5_000u64 {
            pool.insert(h(i), blk(vec![h(i - 1)], i), i, 1, None, false, &[h(i - 1)]);
        }
        assert_eq!(pool.drop_subtree(&h(0)), 5_000);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn evidence_height_tracks_pool() {
        let mut pool = OrphanPool::default();
        pool.insert(h(1), blk(vec![h(9)], 1), 500, 1, None, true, &[h(9)]);
        pool.insert(h(2), blk(vec![h(9)], 2), 900, 1, None, true, &[h(9)]);
        pool.insert(h(3), blk(vec![h(9)], 3), 5_000, 1, None, false, &[h(9)]);
        assert_eq!(pool.max_evidence_height(), Some(900));
        pool.remove(&h(2));
        assert_eq!(pool.max_evidence_height(), Some(500));
        pool.drop_subtree(&h(9));
        assert_eq!(pool.max_evidence_height(), None);
    }

    // ── POW-3 work rule ────────────────────────────────────────────────────

    #[test]
    fn work_admission_decision_table() {
        use WorkAdmission::*;
        assert_eq!(work_admission(100, 100, 0, 0), NearTip);
        assert_eq!(work_admission(99, 100, 1, 0), ChainBacked);
        assert_eq!(work_admission(99, 100, 0, 100), MergeBacked);
        assert_eq!(work_admission(10, 100, 89, 99), LowWork);
        assert_eq!(work_admission(u128::MAX, 0, u128::MAX, u128::MAX), NearTip, "no overflow");
        assert_eq!(work_admission(1, u128::MAX, u128::MAX, 0), ChainBacked, "saturating");
    }

    fn chain_dag(n: u64, work: u128) -> (crate::consensus::GhostDAG, Vec<[u8; 32]>) {
        let mut dag = crate::consensus::GhostDAG::with_default_k();
        dag.add_genesis(h(0), 0);
        let mut chain = vec![h(0)];
        for i in 1..=n {
            dag.add_block(h(i), vec![h(i - 1)], i, work).unwrap();
            chain.push(h(i));
        }
        (dag, chain)
    }

    #[test]
    fn threshold_is_the_work_of_the_selected_chain_block_a_window_below_the_tip() {
        let (dag, _) = chain_dag(ANTI_DOS_WINDOW_BLOCKS - 1, 10);
        assert_eq!(anti_dos_work_threshold(&dag), 0, "chain shorter than the window");
        let (dag, chain) = chain_dag(ANTI_DOS_WINDOW_BLOCKS + 40, 10);
        assert_eq!(anti_dos_work_threshold(&dag), 400, "block 40 carries 40 x 10");
        assert_eq!(block_work_lower_bound(&dag, &[chain[40], chain[7]], core::POW_LIMIT_BITS, 41),
            Some(400 + core::bits_to_work(core::POW_LIMIT_BITS)));
        assert_eq!(block_work_lower_bound(&dag, &[[0xEE; 32]], core::POW_LIMIT_BITS, 41), None);
        // From the GnB-SMH v3 switch a block's own work is normalised exactly
        // as `accept_block` adds it to the DAG (`core::block_work`): the
        // bound must not count a v3 block's bits fourfold.
        let v3 = core::powit_height();
        if v3 != u64::MAX {
            let bits = core::POW_LIMIT_BITS;
            assert_eq!(block_work_lower_bound(&dag, &[chain[40]], bits, v3),
                Some(400 + core::block_work(bits, v3)));
            assert_eq!(core::block_work(bits, v3), core::bits_to_work(bits) >> core::POW_V3_DIFFICULTY_SHIFT);
            assert_eq!(block_work_lower_bound(&dag, &[chain[40]], bits, v3 - 1),
                Some(400 + core::bits_to_work(bits)), "below the switch: v1 work");
        }
    }

    #[test]
    fn announced_work_survives_eviction() {
        // A chain o1 <- o2 <- ... <- o6 announced on top of the missing x,
        // fetched tip-first (o6 arrives first) into a pool of 3 entries.
        let limits = OrphanLimits { max_entries: 3, max_bytes: 1 << 20, max_entries_per_peer: 3, max_bytes_per_peer: 1 << 20 };
        let mut pool = OrphanPool::new(limits);
        let x = h(1000);
        let o = |i: u64| h(2000 + i);
        let w = core::bits_to_work(core::POW_LIMIT_BITS);
        for i in (1..=6u64).rev() {
            let parent = if i == 1 { x } else { o(i - 1) };
            pool.insert(o(i), blk(vec![parent], i), i, 1, None, false, &[parent]);
        }
        assert_eq!(pool.len(), 3, "o6, o5, o4 were evicted");
        assert!(pool.remembers(&o(3)), "o4's eviction remembered the work above o3");
        assert_eq!(pool.remembered_len(), (3, 3), "three skeletons, three remembered path links");
        assert_eq!(pool.announced_work_above(&x), 6 * w, "the whole announced chain, buffered + remembered");
        assert_eq!(pool.announced_work_above(&o(2)), 4 * w);
        // o1..o3 connect (removed from the pool, forgotten): the evicted part
        // above o3 is still announced, by its skeletons.
        for i in 1..=3 {
            pool.remove(&o(i));
            pool.forget(&o(i));
        }
        assert_eq!(pool.announced_work_above(&o(3)), 3 * w);
        // Re-sending the evicted orphans (they are re-buffered, evicting one
        // another) never adds their work twice.
        for _round in 0..3 {
            for i in (4..=6u64).rev() {
                pool.insert(o(i), blk(vec![o(i - 1)], i), i, 1, None, false, &[o(i - 1)]);
                assert_eq!(pool.announced_work_above(&o(3)), 3 * w);
            }
        }
    }

    #[test]
    fn announced_work_sums_a_dag_shaped_chain_once() {
        // Width-2 lattice of 40 levels above the missing root x: each level's
        // two blocks have both blocks of the level below as parents. Its
        // summed work is 80 blocks; any single path carries 40.
        let w = core::bits_to_work(core::POW_LIMIT_BITS);
        let x = h(9_000);
        let node = |level: u64, side: u64| if level == 0 { x } else { h(10_000 + 2 * level + side) };
        let build = |pool: &mut OrphanPool| {
            for level in (1..=40u64).rev() {
                for side in 0..2u64 {
                    let parents = if level == 1 { vec![x] } else { vec![node(level - 1, 0), node(level - 1, 1)] };
                    pool.insert(node(level, side), blk(parents.clone(), 2 * level + side), level, 1, None, false, &parents);
                }
            }
        };
        let mut big = OrphanPool::default();
        build(&mut big);
        assert_eq!(big.announced_work_above(&x), 80 * w, "every block once");
        assert_eq!(big.path_work_above(&x), 40 * w, "the heaviest single path (the pre-fix measure)");
        // Fetched tip first through a pool of 10: 70 of them evicted, still
        // counted once each.
        let mut small = OrphanPool::new(OrphanLimits {
            max_entries: 10, max_bytes: 1 << 20, max_entries_per_peer: 10, max_bytes_per_peer: 1 << 20,
        });
        build(&mut small);
        assert_eq!(small.len(), 10);
        assert_eq!(small.announced_work_above(&x), 80 * w);
        assert_eq!(small.announced_work_capped(&x, 5 * w), 5 * w, "stops once the need is met");
        // A width-k diamond flood: k orphans on x and one merging them all.
        let mut d = OrphanPool::default();
        let k = 50u64;
        let fan: Vec<[u8; 32]> = (0..k).map(|i| h(20_000 + i)).collect();
        for (i, f) in fan.iter().enumerate() {
            d.insert(*f, blk(vec![x], 30_000 + i as u64), 1, 1, None, false, &[x]);
        }
        d.insert(h(21_000), blk(fan.clone(), 31_000), 2, 1, None, false, &fan);
        assert_eq!(d.announced_work_above(&x), (k + 1) as u128 * w, "no more than its summed proof of work");
    }

    #[test]
    fn remembered_work_resists_a_parent_key_flood() {
        // An honest chain of 30 orphans above x, fetched tip first from peer
        // None through a pool of 10 (default remembered-store bounds).
        let w = core::bits_to_work(core::POW_LIMIT_BITS);
        let x = h(40_000);
        let o = |i: u64| h(41_000 + i);
        let mut pool = OrphanPool::new(OrphanLimits {
            max_entries: 1_000, max_bytes: 1 << 30, max_entries_per_peer: 10, max_bytes_per_peer: 1 << 30,
        });
        let attacker = Some(PeerId::random());
        // The audit's flood: 212 distinct attacker orphans, each with 256
        // random missing parents (212 x 256 > REMEMBERED_WORK_MAX keys per
        // cycle), cycled between every honest delivery.
        let flood: Vec<core::Block> = (0..212u64)
            .map(|j| blk((0..256u64).map(|p| h(1_000_000 + j * 1_000 + p)).collect(), 50_000 + j))
            .collect();
        let send_flood = |pool: &mut OrphanPool| {
            for b in &flood {
                let parents = b.header.parents.clone();
                pool.insert(b.block_hash(), b.clone(), 1, 1, attacker, false, &parents);
            }
        };
        for i in (1..=30u64).rev() {
            let parent = if i == 1 { x } else { o(i - 1) };
            pool.insert(o(i), blk(vec![parent], 60_000 + i), i, 1, None, false, &[parent]);
            // Between every honest delivery the attacker cycles its flood
            // (re-sent orphans are re-buffered and evicted again).
            send_flood(&mut pool);
        }
        // Pre-fix: each attacker eviction pushed 256 keys into a 50,000-entry
        // FIFO, flushing every honest link. Now an eviction remembers at most
        // 8 keys, re-sends never create entries, a peer owns at most a
        // quarter of each store and only greater work displaces another
        // peer's entries.
        assert_eq!(pool.announced_work_above(&x), 30 * w, "the honest chain's work is still announced above x");
        let (skel, paths) = pool.remembered_len();
        assert!(skel <= 20 + 212, "one skeleton per distinct evicted orphan: {skel}");
        assert!(paths <= 20 + 212 * REMEMBERED_KEYS_PER_ORPHAN, "at most 8 keys per evicted orphan: {paths}");
    }

    #[test]
    fn awaited_bodies_are_requested_once_and_bounded() {
        let (mut dag, chain) = chain_dag(6, 10);
        let mut pf = ParentFetchTracker::new();
        assert!(awaited_bodies_to_request(&dag, &pf, MAX_BODY_REFETCH).is_empty(), "nothing waits");
        dag.mark_body_pending(chain[2], None);
        dag.mark_body_pending(chain[4], Some([7; 32]));
        let mut want = vec![chain[2], chain[4]];
        want.sort_unstable();
        assert_eq!(awaited_bodies_to_request(&dag, &pf, MAX_BODY_REFETCH), want);
        assert_eq!(awaited_bodies_to_request(&dag, &pf, 1).len(), 1, "bounded");
        pf.note_requested(chain[2], Instant::now());
        assert_eq!(awaited_bodies_to_request(&dag, &pf, MAX_BODY_REFETCH), vec![chain[4]],
            "a body already being fetched is not requested twice");
        assert!(awaited_bodies_to_request(&dag, &pf, 1).is_empty(),
            "the bound counts the bodies already being fetched");
        dag.clear_body_pending(&chain[4]);
        assert!(awaited_bodies_to_request(&dag, &pf, MAX_BODY_REFETCH).is_empty());
    }

    /// Review of the P3 merge: the orphan sweep chased EVERY block waiting
    /// for a body each period (thousands on a pruned node following a fork
    /// deeper than the pruning depth), filling the shared directed-pull
    /// queue. Now the bodies being fetched at once stay within the bound —
    /// requested or re-chased — the tracked ones keep their place, and a
    /// capped selection does not always pick the same window.
    #[test]
    fn awaited_bodies_in_flight_stay_bounded() {
        let (mut dag, chain) = chain_dag(40, 10);
        for h in &chain[1..] {
            dag.mark_body_pending(*h, None);
        }
        let waiting = dag.body_pending_blocks();
        assert_eq!(waiting.len(), 40);
        let mut pf = ParentFetchTracker::new();
        let now = Instant::now();
        // Requests: at most the bound in flight.
        let first = awaited_bodies_to_request(&dag, &pf, 10);
        assert_eq!(first.len(), 10);
        assert!(first.windows(2).all(|w| w[0] < w[1]), "sorted, distinct");
        for h in &first {
            pf.note_requested(*h, now);
        }
        assert!(awaited_bodies_to_request(&dag, &pf, 10).is_empty(), "the bound is reached");
        assert_eq!(awaited_bodies_to_request(&dag, &pf, 15).len(), 5);
        // The sweep keeps the tracked ones and adds none while full ...
        let chased = awaited_bodies_to_chase(&dag, &pf, 10);
        assert_eq!(chased, first);
        let (retry, give_up) = pf.sweep(&chased, now);
        assert!(retry.is_empty() && give_up.is_empty(), "within their backoff");
        assert_eq!(pf.len(), 10, "nothing tracked was forgotten");
        // ... and fills the room once some arrived.
        for h in &first[..4] {
            dag.clear_body_pending(h);
        }
        let chased = awaited_bodies_to_chase(&dag, &pf, 10);
        assert_eq!(chased.len(), 10);
        assert!(first[4..].iter().all(|h| chased.contains(h)), "tracked first");
        let (retry, _) = pf.sweep(&chased, now);
        assert_eq!(retry.len(), 4, "only the new ones are requested now");
        // A capped selection is not a fixed window: over a few draws more
        // than `n` distinct blocks come up.
        let fresh = ParentFetchTracker::new();
        let mut seen: HashSet<BlockHash> = HashSet::new();
        for _ in 0..64 {
            seen.extend(awaited_bodies_to_request(&dag, &fresh, 5));
        }
        assert!(seen.len() > 5, "rotating window: {} distinct", seen.len());
        assert!(awaited_bodies_to_chase(&dag, &fresh, 0).is_empty());
    }

    #[test]
    fn announced_work_counts_a_diamond_once() {
        let (_dag, chain) = chain_dag(50, 10);
        let w = core::bits_to_work(core::POW_LIMIT_BITS);
        let x = h(1000);
        let mut pool = OrphanPool::default();
        // a waits on x; b waits on x; c merges a, b and the known chain[50].
        pool.insert(h(1001), blk(vec![x], 1), 1, 1, None, false, &[x]);
        pool.insert(h(1002), blk(vec![x], 2), 1, 1, None, false, &[x]);
        pool.insert(h(1003), blk(vec![h(1001), h(1002), chain[50]], 3), 2, 1, None, false, &[h(1001), h(1002)]);
        assert_eq!(pool.announced_work_above(&x), 3 * w, "a, b and c, each once (not the longest path)");
    }

    /// B1-T5: only a DIRECT waiter whose every other parent is in the DAG
    /// and whose header passes its contextual checks (height, expected bits,
    /// timestamp; below the activation) vouches for a block. The transitive,
    /// unchecked bound that replaced it let one orphan get a low-work fork
    /// stored (`fix_ingress_dos`).
    #[test]
    fn only_checkable_direct_waiters_vouch() {
        let (dag, chain) = chain_dag(50, 10);
        let w = core::bits_to_work(core::POW_LIMIT_BITS);
        let tip = chain[50];
        let tip_ts = dag.get_block_data(&tip).unwrap().timestamp;
        // The block under judgement: a child of chain[10] (DAG height 11).
        let mut root = blk(vec![chain[10]], 77);
        root.height = 11;
        root.header.timestamp = 11;
        let x = h(9_999);
        let now = 1_000_000;
        let voucher = |parents: Vec<[u8; 32]>, height: u64, ts: u64, tag: u64| {
            let mut b = blk(parents, tag);
            b.height = height;
            b.header.timestamp = ts;
            b
        };
        let act = core::activation::NEVER;
        // A valid voucher: parents [tip, root], height 51, ts >= both.
        let mut pool = OrphanPool::default();
        pool.insert(h(1), voucher(vec![tip, x], 51, tip_ts, 1), 51, 1, None, false, &[x]);
        assert_eq!(pool.best_voucher_lb(&x, &root, 3, &dag, now, act), 500 + w);
        // ... not at/after the hardening activation (merge depth).
        assert_eq!(pool.best_voucher_lb(&x, &root, 3, &dag, now, 0), 0);
        // Wrong height, timestamp before a parent, or from the future: none.
        for (height, ts) in [(52, tip_ts), (51, tip_ts - 1), (51, now + core::MAX_FUTURE_SECS + 1)] {
            let mut p = OrphanPool::default();
            p.insert(h(2), voucher(vec![tip, x], height, ts, 2), height, 1, None, false, &[x]);
            assert_eq!(p.best_voucher_lb(&x, &root, 3, &dag, now, act), 0, "height {height} ts {ts}");
        }
        // Another parent still missing (an orphan above an orphan): none.
        let mut p = OrphanPool::default();
        p.insert(h(3), voucher(vec![tip, x, h(4_242)], 51, tip_ts, 3), 51, 1, None, false, &[x, h(4_242)]);
        assert_eq!(p.best_voucher_lb(&x, &root, 3, &dag, now, act), 0);
        // The block under judgement claiming a height its parents do not
        // imply: nothing vouches for it.
        let mut bad_root = root.clone();
        bad_root.height = 12;
        assert_eq!(pool.best_voucher_lb(&x, &bad_root, 3, &dag, now, act), 0);
        assert_eq!(pool.best_voucher_lb(&h(4242), &root, 1, &dag, now, act), 0, "nobody waits on it");
    }

    #[test]
    fn minimum_chain_work_parses_like_bitcoin_core() {
        assert_eq!(parse_minimum_chain_work("0"), Ok(0));
        assert_eq!(parse_minimum_chain_work("0x1f"), Ok(31));
        assert_eq!(parse_minimum_chain_work("00000000000000000000000000000000000000000000000000000000000000ff"), Ok(255));
        assert_eq!(parse_minimum_chain_work(&"f".repeat(32)), Ok(u128::MAX));
        assert!(parse_minimum_chain_work(&format!("1{}", "0".repeat(32))).is_err(), "above 128 bits");
        assert!(parse_minimum_chain_work("").is_err());
        assert!(parse_minimum_chain_work("12g").is_err());
        assert_eq!(MAINNET_MINIMUM_CHAIN_WORK, core::MIN_CHAIN_WORK,
            "one release constant (docs/RUNNING.md)");
    }

    /// The network defaults (mainnet: the release constant derived from the
    /// 2026-10-14 reading; testnet and regtest: 0) and `--minimumchainwork`,
    /// which replaces the default either way, with Bitcoin Core's warning
    /// when it lowers it.
    #[test]
    fn minimum_chain_work_defaults_and_the_override() {
        use crate::core::activation::ActivationNetwork as Net;
        assert_eq!(MAINNET_MINIMUM_CHAIN_WORK, 7_000_000);
        assert_eq!(parse_minimum_chain_work("6acfc0"), Ok(MAINNET_MINIMUM_CHAIN_WORK), "RUNNING.md's hex form");
        assert_eq!(default_minimum_chain_work(Net::Mainnet), 7_000_000);
        assert_eq!(default_minimum_chain_work(Net::Testnet), 0);
        assert_eq!(default_minimum_chain_work(Net::Regtest), 0);
        assert_eq!(default_minimum_chain_work(core::ChainId::Mainnet.into()), 7_000_000);
        assert_eq!(default_minimum_chain_work(core::ChainId::Testnet.into()), 0);

        let d = MinimumChainWorkSetting::resolve(None, Net::Mainnet).unwrap();
        assert_eq!(d, MinimumChainWorkSetting { value: 7_000_000, default: 7_000_000, overridden: false });
        assert_eq!(d.below_default_warning(), None);
        let off = MinimumChainWorkSetting::resolve(Some("0"), Net::Mainnet).unwrap();
        assert_eq!((off.value, off.overridden), (0, true));
        let w = off.below_default_warning().expect("lowering the release value warns");
        assert!(w.contains("0x6acfc0") && w.contains("below this network's default"), "{w}");
        let up = MinimumChainWorkSetting::resolve(Some("0x7000000"), Net::Mainnet).unwrap();
        assert_eq!(up.value, 0x700_0000);
        assert_eq!(up.below_default_warning(), None, "raising it is the operator's choice");
        let t = MinimumChainWorkSetting::resolve(Some("ff"), Net::Testnet).unwrap();
        assert_eq!((t.value, t.default, t.below_default_warning()), (255, 0, None));
        assert!(MinimumChainWorkSetting::resolve(Some("7,000,000"), Net::Mainnet).is_err(), "hex only");
    }

    /// The long-IBD warning: none while the tip is above the minimum or has
    /// been below it for less than the interval; then one per interval, each
    /// with the work gained since the previous one; reaching the minimum
    /// resets the watch.
    #[test]
    fn minimum_work_watch_warns_when_the_tip_stays_below() {
        let min = MAINNET_MINIMUM_CHAIN_WORK;
        let iv = MIN_WORK_WARNING_INTERVAL;
        let t0 = Instant::now();
        let mut w = MinimumWorkWatch::default();
        assert_eq!(w.observe(min, min, t0), None, "at the minimum: not in IBD");
        assert_eq!(w.observe(1_000, min, t0), None, "just fell below");
        assert_eq!(w.observe(2_000, min, t0 + iv - Duration::from_secs(1)), None);
        let first = w.observe(3_500_000, min, t0 + iv).expect("below for the whole interval");
        assert_eq!(first, MinimumWorkWarning { below_for: iv, tip_work: 3_500_000, min_chain_work: min, gained: None });
        let line = first.to_string();
        assert!(line.contains("50% of the minimum chain work 0x6acfc0") && line.contains("for 30 min"), "{line}");
        assert!(line.contains("initial block download") && line.contains("--minimumchainwork"), "{line}");
        assert_eq!(w.observe(3_600_000, min, t0 + iv + iv / 2), None, "one warning per interval");
        let second = w.observe(3_600_000, min, t0 + 2 * iv).expect("next interval");
        assert_eq!((second.below_for, second.gained), (2 * iv, Some(100_000)));
        let third = w.observe(3_600_000, min, t0 + 3 * iv).expect("still below");
        assert_eq!(third.gained, Some(0));
        assert!(third.to_string().contains("no progress"), "{third}");
        // Reaching the minimum resets the watch: a later dip starts over.
        assert_eq!(w.observe(min + 1, min, t0 + 4 * iv), None);
        assert_eq!(w.observe(5, min, t0 + 5 * iv), None);
        assert_eq!(w.observe(5, min, t0 + 6 * iv - Duration::from_secs(1)), None);
        assert!(w.observe(5, min, t0 + 6 * iv).is_some());
        // A node whose minimum is 0 (testnet, or --minimumchainwork 0) never warns.
        let mut z = MinimumWorkWatch::default();
        assert_eq!(z.observe(0, 0, t0), None);
        assert_eq!(z.observe(0, 0, t0 + 10 * iv), None);
    }

    /// POW-3 (Phase 4): Bitcoin Core's unrequested-block rule.
    #[test]
    fn unrequested_block_rule() {
        use DropReason::*;
        // Not in IBD: an orphan may be buffered; a connectable block needs
        // the near-tip work.
        assert_eq!(unrequested_block_admission(None, 0, 100, 90), Ok(()));
        assert_eq!(unrequested_block_admission(Some(90), 0, 100, 90), Ok(()));
        assert_eq!(unrequested_block_admission(Some(89), 0, 100, 90), Err(UnrequestedLowWork));
        // Below the minimum chain work: nothing, unless its own chain
        // reaches it.
        assert_eq!(unrequested_block_admission(None, 1_000, 100, 90), Err(BelowMinimumChainWork));
        assert_eq!(unrequested_block_admission(Some(101), 1_000, 100, 90), Err(BelowMinimumChainWork));
        assert_eq!(unrequested_block_admission(Some(1_000), 1_000, 999, 990), Ok(()));
    }

    // ── PoWit gossip ─────────────────────────────────────────────────────

    fn gossip_from(delivering: PeerId, author: Option<PeerId>, at: Instant) -> crate::network::InboundOrigin {
        crate::network::InboundOrigin::Gossip { propagation_source: delivering, author, pending: None, received_at: at }
    }

    fn share_frame(nonce: u64) -> ([u8; 32], u8, Vec<u8>) {
        let s = core::witness_share::WitnessShare {
            attested: [7; 32], witness: [9; 20], payout: vec![0x51], bits: core::POW_LIMIT_BITS, nonce,
        };
        crate::powit::share_item(&s)
    }

    /// PoWit gossip: the context-free checks before any verification bind
    /// the claimed id to the content and the content to exactly one item of
    /// its kind.
    #[test]
    fn powit_item_precheck_binds_the_id_and_the_encoding() {
        use crate::powit::{item_id, ITEM_ATTESTATION, ITEM_SHARE};
        let (id, kind, data) = share_frame(1);
        assert_eq!(kind, ITEM_SHARE);
        assert_eq!(powit_item_precheck(&id, kind, &data), Ok(()));
        assert!(powit_item_precheck(&[0; 32], kind, &data).unwrap_err().contains("id does not match"));
        let mut long = data.clone();
        long.push(0);
        assert!(powit_item_precheck(&item_id(kind, &long), kind, &long).unwrap_err().contains("trailing bytes"));
        let short = &data[..data.len() - 1];
        assert!(powit_item_precheck(&item_id(kind, short), kind, short).unwrap_err().contains("malformed"));
        assert!(powit_item_precheck(&item_id(ITEM_ATTESTATION, &data), ITEM_ATTESTATION, &data).is_err(),
            "a share's bytes are no attestation");
        assert!(powit_item_precheck(&item_id(9, &data), 9, &data).is_err());
    }

    /// PoWit gossip: only refusals no honest node produces or relays are
    /// context-free (penalised through the block gate); anything that
    /// depends on this node's chain or state is not.
    #[test]
    fn powit_refusals_are_classified() {
        use crate::powit::{ITEM_ATTESTATION, ITEM_EVIDENCE, ITEM_SHARE};
        use crate::core::witness_share::ShareError;
        let cf = Some(BlockFault::ContextFree);
        for e in [ShareError::InsufficientWork, ShareError::WrongBits, ShareError::BadTarget, ShareError::PayoutTooLong] {
            assert_eq!(powit_admit_error_fault(ITEM_SHARE, &e.to_string()), cf, "{e}");
        }
        assert_eq!(powit_admit_error_fault(ITEM_SHARE, POWIT_SHARE_BAD_PAYOUT), cf);
        for e in ["witness share attests a block that is not on this selected chain",
                  "witness share attests a block outside the share window",
                  "witness share already included on this chain",
                  "share pool full", "no tip", "PoWit not active",
                  "storage: attested block body missing"] {
            assert_eq!(powit_admit_error_fault(ITEM_SHARE, e), None, "{e}");
        }
        assert_eq!(powit_admit_error_fault(ITEM_SHARE, &ShareError::WrongAttestedBlock.to_string()), None,
            "the attested body is read by its id: a mismatch is local");
        assert_eq!(powit_admit_error_fault(ITEM_ATTESTATION, POWIT_BAD_ATTESTATION_SIGNATURE), cf);
        for e in ["attestation source is not the tip's justified checkpoint", "attester is not in the witness set",
                  "attestation pool full", "PoWit not active at the tip"] {
            assert_eq!(powit_admit_error_fault(ITEM_ATTESTATION, e), None, "{e}");
        }
        assert_eq!(powit_admit_error_fault(ITEM_EVIDENCE, "equivocation: invalid signature"), cf);
        assert_eq!(powit_admit_error_fault(ITEM_EVIDENCE, "equivocation: links do not conflict"), cf);
        assert_eq!(powit_admit_error_fault(ITEM_SHARE, POWIT_BAD_ATTESTATION_SIGNATURE), None, "per kind");
        // The literals are the ones `powit` returns: a reworded refusal would
        // silently stop being penalised.
        let src = include_str!("powit.rs");
        assert!(src.contains(&format!("\"{POWIT_SHARE_BAD_PAYOUT}\"")));
        assert!(src.contains(&format!("\"{POWIT_BAD_ATTESTATION_SIGNATURE}\"")));
    }

    /// PoWit gossip core: a context-free fault is charged to the deliverer
    /// and penalised through the block gate (B1-T7: a relay only once
    /// penalties are in force; an author that delivered it itself is
    /// misbehaving); a well-formed item is queued and verified off the
    /// caller, its charge refunded when it is admitted or refused for
    /// context; failed proofs consume the deliverer's budget until its items
    /// are refused unverified; a stale queued item is expired unverified.
    #[test]
    fn powit_ingress_budgets_and_gated_penalties() {
        use crate::network::GossipVerdict::{Accept, Ignore, Reject};
        use crate::pow::verifier::StartNext;
        let t0 = Instant::now();
        let limits = PowLimits {
            workers: 1, max_queued: 8, max_queued_per_peer: 4, max_queued_per_group: 8, max_queued_solicited: 0,
            peer_burst: 3, peer_refill_per_sec: 0.0, group_burst: 100, group_refill_per_sec: 0.0,
            verdict_ttl: Duration::from_secs(10), results_cap: 1,
        };
        let mut p = PowitIngress::new(limits);
        let (relay, author) = (PeerId::random(), PeerId::random());
        let src = |peer: PeerId| PowSource { peer: Some(peer), group: None };
        let plain = |gossip| BlockPenalty { gossip, misbehaving: false };
        let (_, kind, data) = share_frame(1);

        // A wrong id: relayed before the activation — Ignore, nobody
        // misbehaves; delivered by its author — misbehaving (Ignore to
        // gossipsub); relayed once penalties are in force — Reject.
        let v = p.on_item([0; 32], kind, data.clone(), gossip_from(relay, Some(author), t0), src(relay), false, t0).unwrap();
        assert_eq!(v.penalty, plain(Ignore));
        let v = p.on_item([0; 32], kind, data.clone(), gossip_from(author, Some(author), t0), src(author), false, t0).unwrap();
        assert_eq!(v.penalty, BlockPenalty { gossip: Ignore, misbehaving: true });
        let v = p.on_item([0; 32], kind, data, gossip_from(relay, Some(author), t0), src(relay), true, t0).unwrap();
        assert_eq!(v.penalty, BlockPenalty { gossip: Reject, misbehaving: true });
        // `relay` has spent 2 of its 3 tokens.

        let verify = |p: &mut PowitIngress, n: u64, result: Result<(), String>| {
            let (id, kind, data) = share_frame(n);
            assert!(p.on_item(id, kind, data, gossip_from(relay, Some(author), t0), src(relay), false, t0).is_none(), "queued");
            let StartNext::Start(job) = p.start_next(t0) else { panic!("a free worker") };
            assert_eq!(job.id, id);
            p.complete(job, &result, false, t0).penalty
        };
        // Admitted: Accept (relayed), refunded.
        assert_eq!(verify(&mut p, 2, Ok(())), plain(Accept));
        // Refused for context: Ignore, refunded.
        assert_eq!(verify(&mut p, 3, Err("witness share attests a block outside the share window".into())), plain(Ignore));
        // A failed proof, relayed before the activation: Ignore, not
        // misbehaving — but it spends the last token.
        assert_eq!(verify(&mut p, 4, Err(core::witness_share::ShareError::InsufficientWork.to_string())), plain(Ignore));
        let (id, kind, data) = share_frame(5);
        let v = p.on_item(id, kind, data, gossip_from(relay, Some(author), t0), src(relay), false, t0)
            .expect("budget spent: refused unverified");
        assert_eq!(v.penalty, plain(Ignore));
        assert_eq!(p.scheduler().queued(), 0);
        assert_eq!(p.scheduler().stats().invalid, 1);

        // Another peer is unaffected; with the one worker busy its next
        // item waits, and is expired unverified once its frame is stale.
        let other = PeerId::random();
        let (a, ka, da) = share_frame(6);
        let (b, kb, db) = share_frame(7);
        assert!(p.on_item(a, ka, da, gossip_from(other, Some(other), t0), src(other), false, t0).is_none());
        assert!(p.on_item(b, kb, db, gossip_from(other, Some(other), t0), src(other), false, t0).is_none());
        let StartNext::Start(job) = p.start_next(t0) else { panic!() };
        assert!(matches!(p.start_next(t0), StartNext::Idle), "one worker");
        let late = t0 + Duration::from_secs(11);
        assert_eq!(p.complete(job, &Ok(()), false, late).penalty, plain(Accept));
        let StartNext::Expired(stale) = p.start_next(late) else { panic!("stale: expired, not verified") };
        assert_eq!(stale.id, b);
    }

    fn evidence_frame(n: u64) -> ([u8; 32], u8, Vec<u8>) {
        use gnb_crypto::core::kes::{KesPublic, KesSignature};
        use gnb_crypto::core::powit::{Attestation, Checkpoint, Equivocation};
        let link = |m: u64| Attestation {
            source: Checkpoint { height: 1, hash: [0; 32] },
            target: Checkpoint { height: 10, hash: [m as u8; 32] },
            witness: KesPublic { depth: 1, root: [n as u8; 32] },
            sig: KesSignature { index: 0, leaf_pk: vec![1], sig: n.to_le_bytes().to_vec(), path: vec![[2; 32]] },
        };
        crate::powit::evidence_item(&Equivocation { a: link(1), b: link(2) })
    }

    /// PoWit audit finding 1: an equivocation proof against a key outside
    /// this node's recent witness sets is refused before its signatures are
    /// checked, is no misbehaviour (`Ignore`: the witness set is this node's
    /// view), but keeps its verification-budget charge: re-rooted proofs are
    /// free to forge in bulk, so a peer relaying them runs out of budget and
    /// its next items are refused unverified.
    #[test]
    fn powit_evidence_against_a_non_witness_keeps_its_charge() {
        use crate::network::GossipVerdict::Ignore;
        use crate::pow::verifier::StartNext;
        let t0 = Instant::now();
        let limits = PowLimits {
            workers: 1, max_queued: 8, max_queued_per_peer: 4, max_queued_per_group: 8, max_queued_solicited: 0,
            peer_burst: 2, peer_refill_per_sec: 0.0, group_burst: 100, group_refill_per_sec: 0.0,
            verdict_ttl: Duration::from_secs(10), results_cap: 1,
        };
        let mut p = PowitIngress::new(limits);
        let relay = PeerId::random();
        let src = PowSource { peer: Some(relay), group: None };
        let not_witness = crate::powit::EVIDENCE_NOT_A_WITNESS;
        assert_eq!(powit_admit_error_fault(crate::powit::ITEM_EVIDENCE, not_witness), None, "not penalised");
        assert!(powit_admit_error_keeps_charge(crate::powit::ITEM_EVIDENCE, not_witness));
        assert!(!powit_admit_error_keeps_charge(crate::powit::ITEM_ATTESTATION, not_witness), "per kind");
        for n in 0..2 {
            let (id, kind, data) = evidence_frame(n);
            assert!(p.on_item(id, kind, data, gossip_from(relay, None, t0), src, false, t0).is_none(), "queued");
            let StartNext::Start(job) = p.start_next(t0) else { panic!("a free worker") };
            let v = p.complete(job, &Err(not_witness.into()), false, t0);
            assert_eq!(v.penalty, BlockPenalty { gossip: Ignore, misbehaving: false });
        }
        let (id, kind, data) = evidence_frame(2);
        let v = p.on_item(id, kind, data, gossip_from(relay, None, t0), src, false, t0)
            .expect("budget spent on refused proofs: refused unverified");
        assert_eq!(v.penalty, BlockPenalty { gossip: Ignore, misbehaving: false });
        assert_eq!(p.scheduler().stats().invalid, 2);
        assert_eq!(p.scheduler().stats().valid, 0);
    }
}
