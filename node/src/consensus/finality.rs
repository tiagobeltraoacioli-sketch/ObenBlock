//! The PoWit finality pin: node-local fork choice (PoWit audit findings 2
//! and 3; docs/CONSENSUS.md "Selected parent and fork choice",
//! docs/DESIGN-pow-powit.md §7.6).
//!
//! The pin ([`GhostDAG::finalized`]) restricts which blocks are selectable:
//! a block whose selected-parent chain misses it is never selected nor
//! offered as a template parent. As in Gasper, whose fork choice starts from
//! the highest checkpoint learned from ANY block, the node learns finality
//! from every block it stores, applied or not (finding 2: a healed partition
//! used to stay split), and, as every Ethereum client does, finality the node
//! has reached is never given up because a conflicting finality appeared:
//!
//! * a **candidate** is a finalized checkpoint (beyond the activation one)
//!   carried by the PoWit state of a stored block, its **source**;
//!   [`FinalityIndex`] records every (source, checkpoint) pair;
//! * it **counts** when some source is not disqualified for a reason its id
//!   commits to ([`GhostDAG::is_invalid_persistently`]: a block waiting for
//!   a body or a verdict still counts) and has at least the node's minimum
//!   chain work (a cheap chain pulled during initial sync proves nothing,
//!   `ingress::minimum_chain_work`), the operator did not set it aside, and
//!   it agrees with the weak-subjectivity **anchor** (the release finality
//!   checkpoint, or the operator's): a candidate at or below the anchor's
//!   height never counts (the anchor dominates it), one above it counts only
//!   if the anchor is on its selected chain;
//! * the node's **own finality** is the highest counted candidate on its
//!   applied chain, or the counted candidate it pinned last (persisted,
//!   `powit::FINALITY_PIN_META`) when that one descends from it: a learned
//!   finality the node pinned before its chain move to it was done (a move
//!   stopped between chunks, a rebuild that restarts from genesis);
//! * a candidate that descends from the own finality **advances** it. The
//!   pin is the highest advancing candidate when they all lie on one chain
//!   (the healed partition: a node with no finality of its own, or an older
//!   one on the same chain, learns a newer one from a stored fork-loser).
//!   Two advancing candidates that conflict (neither on the other's selected
//!   chain) were only learned from chains the node has not applied: the
//!   node takes the one whose best source carries the most blue work (then
//!   the higher, then the larger hash), never their latest common block;
//! * a candidate that **conflicts** with the pin (it is neither on the pin's
//!   selected chain nor descends from it) never moves it: at least a third
//!   of the witness weight signed both, or the two chains derived different
//!   witness sets (a fork that branched before any common finality, a long
//!   partition finalized through inactivity decay, or a majority-hashrate
//!   fork building its own witness set under the first rule). The node keeps
//!   its finality and raises a persistent conflict alert (`getfinalityinfo`
//!   `conflict`, the log, the `gnb_finality_conflicts` metric) for as long as
//!   the conflicting candidate counts; only the operator moves it
//!   (`ignorefinalized`, `setfinalitycheckpoint`), as Ethereum clients
//!   require a manual intervention to leave a finalized checkpoint.
//!
//! Without a conflict, two nodes holding the same blocks (and the same
//! disqualifications, minimum chain work, anchor and operator settings)
//! compute the same pin whatever the arrival order. With one, a node keeps
//! whichever finality it reached first: the weak-subjectivity assumption of
//! every finality protocol, which the release anchor and the minimum chain
//! work make hold for a node that syncs while eclipsed.
//!
//! Cost: the pin is recomputed after every accepted block and at each step
//! of a chain move, and almost every block after a finalization is a source
//! of it, so one computation examines O(1) sources per candidate (sources
//! are kept heaviest first, and the first that qualifies decides; review
//! round 2, M1; a candidate below the minimum chain work costs O(1), round
//! 3, M-B), walks each disqualified block at
//! most once (shared walks), reads every source only of conflicting
//! candidates resolved by work, and asks O(1) reachability queries per
//! candidate (no selected-chain walk).
//! `tests::a_pin_computation_examines_a_bounded_number_of_sources` bounds
//! it; `tests::measure_pin_computation_cost` times it. A candidate is one
//! finalized checkpoint, at most one per checkpoint interval of a chain (60
//! blocks on mainnet, about 17,500 a year), and candidates at or below the
//! anchor never count.
//!
//! Package O2 (DoS bounds): a computation that visits every candidate cost
//! 5 to 9 ms at 10,000 of them, after every accepted block, so initial sync
//! grew quadratically with the chain's age. [`PinCache`] keeps the class of
//! every candidate and the counted ones that conflict with the pin between
//! computations, under a key of everything else they depend on (the
//! disqualified set's generation, the minimum chain work, the ignored blocks,
//! the anchor); a computation after a new block re-classifies the candidates
//! whose sources changed and tests the new counted ones against the pin
//! (about 0.15 ms at 10,000). Its outcome is that of the full computation,
//! kept as `compute_finality_pin_reference`
//! (`tests::the_cached_pin_equals_the_full_computation`).
//!
//! While a configured anchor is unknown (review round 2, M3) nothing above
//! its height counts; the node holds the block it pinned last, a finalized
//! checkpoint or a previous anchor ([`PinOrigin::Held`], round 3, LOW 4),
//! keeps it persisted, and alerts once its applied tip is above the
//! anchor's height ([`PinOutcome::anchor_overdue`]; the node adds a
//! time-based alert, `powit::UNKNOWN_ANCHOR_ALERT_AFTER`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use super::{BlockHash, GhostDAG};

/// One finalized checkpoint and the blocks whose PoWit state carries it.
#[derive(Clone, Debug, Default)]
struct Candidate {
    /// Its PoWit slot (`Checkpoint::height`).
    slot: u64,
    /// (blue work, source), heaviest first (ties by hash): a block's blue
    /// work never changes, so the first entry is the heaviest source and a
    /// candidate whose heaviest source is below the minimum chain work is
    /// skipped in O(1) (review round 3, M-B).
    sources: Vec<(u128, BlockHash)>,
}

/// A weak-subjectivity anchor: a block the node trusts as final (release
/// finality checkpoint, or the operator's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub hash: BlockHash,
    /// Its DAG height.
    pub height: u64,
}

/// The operator's anchor setting (`setfinalitycheckpoint`), persisted by the
/// node (`powit::FINALITY_ANCHOR_META`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnchorSetting {
    /// The release finality checkpoint of the node's network, if any.
    #[default]
    Release,
    /// No anchor at all, not even the release one.
    Disabled,
    /// This block.
    Operator(Anchor),
}

/// Inputs of the pin that do not come from the DAG.
#[derive(Clone, Copy, Debug)]
pub struct PinPolicy<'a> {
    pub min_chain_work: u128,
    pub anchor: Option<Anchor>,
    /// Blocks the operator set aside (`ignorefinalized`): no candidate at or
    /// above one of them on its selected chain counts.
    pub ignored: &'a HashSet<BlockHash>,
    /// The node's applied tip (the block its UTXO set sits on): the counted
    /// candidates on its selected chain are the node's own finality.
    pub applied: Option<BlockHash>,
    /// The block the node pinned last ([`FinalityIndex`], persisted by the
    /// node): its own finality while it is a counted finalized checkpoint,
    /// and the pin held while a configured anchor is unknown.
    pub sticky: Option<BlockHash>,
}

/// Where the pin comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PinOrigin {
    #[default]
    None,
    /// The anchor (no counted candidate above it).
    Anchor,
    /// A counted finalized checkpoint: the node's own finality, or one that
    /// advances it.
    Finalized,
    /// The checkpoint the node pinned last, held while the configured anchor
    /// is unknown (review round 2, M3).
    Held,
}

impl PinOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            PinOrigin::None => "none",
            PinOrigin::Anchor => "anchor",
            PinOrigin::Finalized => "finalized",
            PinOrigin::Held => "held",
        }
    }
}

/// How a conflict between counted finalized checkpoints was handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConflictResolution {
    /// No conflict.
    #[default]
    None,
    /// The node kept the finality it had reached: the conflicting
    /// checkpoints are reported, the operator decides.
    OwnFinality,
    /// The node had no finality of its own above them: of the conflicting
    /// checkpoints it learned from chains it has not applied, it took the one
    /// whose best source carries the most blue work.
    MostWork,
}

impl ConflictResolution {
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            ConflictResolution::None => None,
            ConflictResolution::OwnFinality => Some("own_finality"),
            ConflictResolution::MostWork => Some("most_work"),
        }
    }
}

/// What the anchor of a [`PinPolicy`] amounts to on this DAG.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnchorStatus {
    /// No anchor configured.
    #[default]
    None,
    /// The block is in the DAG, valid, at the configured height.
    Known,
    /// Not in the DAG yet: nothing above its height counts until it arrives.
    Unknown,
    /// In the DAG but disqualified: nothing through it counts (alert).
    Invalid,
    /// In the DAG at another DAG height than configured (the DAG's height is
    /// used; a release or operator typo, alert).
    HeightMismatch,
}

/// Result of [`GhostDAG::compute_finality_pin`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinOutcome {
    /// (block, DAG height).
    pub pin: Option<(BlockHash, u64)>,
    pub origin: PinOrigin,
    pub anchor: AnchorStatus,
    /// Counted candidates: (checkpoint, DAG height, slot), highest first
    /// (shared with the [`PinCache`] while they do not change).
    pub counted: Arc<Vec<(BlockHash, u64, u64)>>,
    /// The node's own finality (module docs), if any counted candidate is.
    pub own: Option<(BlockHash, u64)>,
    /// (the pinned checkpoint, the highest counted checkpoint that conflicts
    /// with it), when any does: the persistent conflict alert.
    pub conflict: Option<((BlockHash, u64), (BlockHash, u64))>,
    /// Counted checkpoints that conflict with the pin.
    pub conflicting: usize,
    pub resolution: ConflictResolution,
    /// Supported candidates refused because they conflict with the anchor.
    pub against_anchor: usize,
    /// Supported candidates the operator set aside.
    pub ignored: usize,
    /// The configured anchor is unknown while the applied tip is above its
    /// height (review round 2, M3: the alert; the node also raises it when
    /// the anchor stays unknown for `powit::UNKNOWN_ANCHOR_ALERT_AFTER` out of
    /// initial block download, whatever height it names: round 3, LOW 4).
    pub anchor_overdue: bool,
}

/// A counted candidate: checkpoint, DAG height.
#[derive(Clone, Copy, Debug)]
struct Counted {
    hash: BlockHash,
    height: u64,
}

/// The anchor of a [`PinPolicy`] on this DAG (`GhostDAG::resolve_anchor`).
#[derive(Clone, Copy, Debug)]
struct AnchorView {
    /// The block, if known and not disqualified (at its DAG height).
    block: Option<Anchor>,
    /// The height that separates what the anchor dominates from what must
    /// descend from it (the DAG's height of a held block, else the
    /// configured one).
    height: Option<u64>,
    status: AnchorStatus,
}

/// What one candidate amounts to under a [`PinCache`] key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// No source qualifies.
    Unsupported,
    /// The operator set it aside.
    Ignored,
    /// It conflicts with the anchor.
    AgainstAnchor,
    /// At or below the anchor, on its chain (the anchor dominates it).
    Dominated,
    /// It counts.
    Counted { height: u64, slot: u64 },
}

/// The inputs a candidate's [`Class`] depends on besides its own sources.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheKey {
    /// `GhostDAG::invalid_gen`: the disqualified set.
    invalid_gen: u64,
    min_chain_work: u128,
    anchor: Option<Anchor>,
    anchor_block: Option<Anchor>,
    anchor_status: AnchorStatus,
    /// The operator's ignored blocks, sorted.
    ignored: Vec<BlockHash>,
}

/// Package O2 (DoS bounds of the A2 pin): the pin is recomputed after every
/// accepted block and at each step of a chain move, and a full computation
/// visits every candidate (one per checkpoint interval of every chain, about
/// 17,500 a year on mainnet: 5.5 ms per computation at 10,000, so initial
/// sync grew quadratically with the chain's age). The cache keeps, under a
/// [`CacheKey`], the class of every candidate and the counted ones that
/// conflict with the last pin; a computation re-classifies only the
/// candidates whose sources changed (`dirty`, set by
/// `note_finality_source` / `forget_finality_source`) and re-tests
/// conflicts only for new counted candidates and, when the pin advanced
/// along its chain, for those above the previous pin. Every input the class
/// reads is either in the key or fixed once a block is in the DAG (its
/// height, blue work, selected parent and so every chain relation).
#[derive(Debug, Default)]
pub(crate) struct PinCache {
    key: Option<CacheKey>,
    /// Checkpoints whose sources changed since the last computation.
    dirty: HashSet<BlockHash>,
    class: HashMap<BlockHash, Class>,
    /// Counted candidates: (DAG height, checkpoint) -> slot.
    counted: BTreeMap<(u64, BlockHash), u64>,
    /// Candidates of class `Ignored` / `AgainstAnchor`.
    ignored: usize,
    against_anchor: usize,
    /// `counted` highest first, as `PinOutcome::counted` (rebuilt when it
    /// changes).
    list: Option<Arc<Vec<(BlockHash, u64, u64)>>>,
    /// The pin `conflicting` was computed against.
    conflict_pin: Option<(BlockHash, u64)>,
    /// Counted candidates that conflict with `conflict_pin`, except those in
    /// `added`, which are not tested yet.
    conflicting: BTreeSet<(u64, BlockHash)>,
    added: Vec<(u64, BlockHash)>,
}

impl PinCache {
    /// Forget everything derived (the dirty set too: every candidate is
    /// classified again under the next key).
    fn reset(&mut self) {
        *self = PinCache::default();
    }

    fn unclassify(&mut self, cp: &BlockHash) {
        match self.class.remove(cp) {
            Some(Class::Ignored) => self.ignored -= 1,
            Some(Class::AgainstAnchor) => self.against_anchor -= 1,
            Some(Class::Counted { height, .. }) => {
                self.counted.remove(&(height, *cp));
                self.conflicting.remove(&(height, *cp));
                self.list = None;
            }
            Some(Class::Unsupported | Class::Dominated) | None => {}
        }
    }

    fn classify_as(&mut self, cp: BlockHash, c: Class) {
        match c {
            Class::Ignored => self.ignored += 1,
            Class::AgainstAnchor => self.against_anchor += 1,
            Class::Counted { height, slot } => {
                self.counted.insert((height, cp), slot);
                self.added.push((height, cp));
                self.list = None;
            }
            Class::Unsupported | Class::Dominated => {}
        }
        self.class.insert(cp, c);
    }

    /// Make `conflicting` the counted candidates that conflict with `p` (one
    /// reachability query each: only a lower block can be on the pin's
    /// selected chain, only a higher one can descend from it). Against the
    /// same pin only the new candidates are tested. When the pin advanced
    /// along its chain (the previous pin is on `p`'s selected chain), a
    /// candidate that conflicted with the previous pin still conflicts, and
    /// one that did not and is at or below the previous pin is on `p`'s
    /// chain, so only those above the previous pin are tested again (a
    /// defence: a counted candidate above a chosen pin that descends from it
    /// would have been chosen instead, so none of them passes the filter).
    fn sync_conflicts(&mut self, dag: &GhostDAG, p: (BlockHash, u64)) {
        let anc = |a: &BlockHash, b: &BlockHash| dag.is_chain_ancestor_or_self(a, b);
        let conflicts = |c: &(u64, BlockHash)| if c.0 > p.1 { !anc(&p.0, &c.1) } else { !anc(&c.1, &p.0) };
        let retest_above = match self.conflict_pin {
            Some(old) if old == p => Some(None),
            Some(old) if p.1 > old.1 && anc(&old.0, &p.0) => Some(Some(old.1)),
            _ => None,
        };
        match retest_above {
            None => {
                self.conflicting = self.counted.keys().filter(|c| conflicts(c)).copied().collect();
            }
            Some(above) => {
                if let Some(h) = above {
                    let again: Vec<(u64, BlockHash)> = self.counted.range((h.saturating_add(1), [0u8; 32])..)
                        .map(|(k, _)| *k)
                        .filter(|k| !self.conflicting.contains(k))
                        .collect();
                    for k in again {
                        if conflicts(&k) {
                            self.conflicting.insert(k);
                        }
                    }
                }
                for k in std::mem::take(&mut self.added) {
                    if self.counted.contains_key(&k) && conflicts(&k) {
                        self.conflicting.insert(k);
                    }
                }
            }
        }
        self.added.clear();
        self.conflict_pin = Some(p);
    }

    fn counted_list(&mut self) -> Arc<Vec<(BlockHash, u64, u64)>> {
        if self.list.is_none() {
            let v = self.counted.iter().rev().map(|(&(height, hash), &slot)| (hash, height, slot)).collect();
            self.list = Some(Arc::new(v));
        }
        self.list.clone().expect("just set")
    }
}

/// Every (source, finalized checkpoint) pair the node knows (memory: about
/// 70 bytes per post-activation block whose state finalized something).
#[derive(Debug, Default)]
pub struct FinalityIndex {
    by_checkpoint: HashMap<BlockHash, Candidate>,
    by_source: HashMap<BlockHash, BlockHash>,
    /// Operator settings (loaded from storage at start-up, changed by RPC).
    pub(crate) anchor_setting: AnchorSetting,
    pub(crate) ignored: HashSet<BlockHash>,
    /// The block pinned last, a finalized checkpoint or the anchor
    /// ([`PinPolicy::sticky`]): set by [`GhostDAG::set_finality_pin`],
    /// persisted and reloaded by the node.
    pub(crate) sticky: Option<BlockHash>,
    /// Since when (the node's clock, out of initial block download) the
    /// configured anchor has been unknown (review round 3, LOW 4).
    pub(crate) anchor_unknown_since: Option<std::time::Instant>,
    /// The last outcome applied ([`GhostDAG::set_finality_pin`]), for RPC and
    /// for logging changes once.
    pub(crate) last: PinOutcome,
    /// Instrumentation, never consensus state: sources (and disqualified
    /// blocks walked for them) examined by [`GhostDAG::compute_finality_pin`]
    /// (review round 2, M1: a regression test bounds it per computation).
    source_visits: std::sync::atomic::AtomicU64,
    /// Package O2: what the pin computation derives from the candidates,
    /// kept between computations ([`PinCache`]).
    cache: std::sync::Mutex<PinCache>,
}

impl FinalityIndex {
    pub fn candidates(&self) -> usize {
        self.by_checkpoint.len()
    }

    pub fn sources(&self) -> usize {
        self.by_source.len()
    }

    /// Sources examined by the pin computations so far (instrumentation).
    pub fn source_visits(&self) -> u64 {
        self.source_visits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The finalized checkpoint pinned last (see [`PinPolicy::sticky`]).
    pub fn sticky(&self) -> Option<BlockHash> {
        self.sticky
    }

    /// Restore the finalized checkpoint pinned last (start-up reload).
    pub fn set_sticky(&mut self, h: Option<BlockHash>) {
        self.sticky = h;
    }

    fn cache_mut(&mut self) -> &mut PinCache {
        self.cache.get_mut().unwrap_or_else(|e| e.into_inner())
    }

    /// The checkpoint `source`'s state finalized, if recorded.
    #[allow(dead_code)] // tests and tools; the node binary compiles this module too
    pub fn checkpoint_of(&self, source: &BlockHash) -> Option<BlockHash> {
        self.by_source.get(source).copied()
    }
}

impl GhostDAG {
    /// The finality index (read).
    pub fn finality_index(&self) -> &FinalityIndex {
        &self.finality
    }

    /// The finality index (operator settings, start-up reload).
    pub fn finality_index_mut(&mut self) -> &mut FinalityIndex {
        &mut self.finality
    }

    /// Record that `source`'s PoWit state finalized `checkpoint` (slot
    /// `slot`). Both must be in the DAG; idempotent.
    pub fn note_finality_source(&mut self, source: BlockHash, checkpoint: BlockHash, slot: u64) -> bool {
        if !self.store.has(&source) || !self.store.has(&checkpoint) || self.finality.by_source.contains_key(&source) {
            return false;
        }
        let work = self.store.get(&source).map(|d| d.blue_work).unwrap_or(0);
        self.finality.by_source.insert(source, checkpoint);
        let c = self.finality.by_checkpoint.entry(checkpoint).or_default();
        c.slot = slot;
        let at = c.sources.partition_point(|(w, h)| (*w, *h) > (work, source));
        c.sources.insert(at, (work, source));
        self.finality.cache_mut().dirty.insert(checkpoint);
        true
    }

    /// Forget `source` (its block left the DAG: a rolled-back acceptance).
    pub(super) fn forget_finality_source(&mut self, source: &BlockHash) {
        // The block may itself be a checkpoint: it no longer counts.
        self.finality.cache_mut().dirty.insert(*source);
        let Some(cp) = self.finality.by_source.remove(source) else { return };
        self.finality.cache_mut().dirty.insert(cp);
        if let Some(c) = self.finality.by_checkpoint.get_mut(&cp) {
            c.sources.retain(|(_, s)| s != source);
            if c.sources.is_empty() {
                self.finality.by_checkpoint.remove(&cp);
            }
        }
    }

    /// Drop every recorded pair (start-up reload), keeping operator settings.
    pub fn clear_finality_sources(&mut self) {
        self.finality.by_checkpoint.clear();
        self.finality.by_source.clear();
        self.finality.cache_mut().reset();
    }

    /// `a == b` or `a` is on `b`'s selected-parent chain. O(1) through the
    /// reachability index; a selected-chain walk where it is not maintained.
    pub fn is_chain_ancestor_or_self(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b {
            return true;
        }
        if self.maintains_reachability_index() && self.reach.has(a) && self.reach.has(b) {
            return self.reach.is_chain_ancestor(a, b);
        }
        self.is_on_selected_chain_of(a, b)
    }

    /// The pin these blocks and `policy` give (see the module docs). It
    /// reads the DAG, the disqualified set and the index, and changes nothing
    /// but the [`PinCache`]: package O2 keeps what a computation derives from
    /// the candidates alone (which count, which conflict with the pin)
    /// between computations, and updates it for the candidates whose sources
    /// changed, so one computation costs O(changed candidates + candidates
    /// above the node's own finality) instead of O(candidates), every chain
    /// relation an O(1) reachability query (no selected-chain walk, review
    /// MEDIUM 4). The outcome is that of the former full computation
    /// (`compute_finality_pin_reference`, which the tests compare it with).
    pub fn compute_finality_pin(&self, policy: &PinPolicy<'_>) -> PinOutcome {
        let mut cache = match self.finality.cache.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // A panic in the middle of an update: start from scratch.
                let mut g = poisoned.into_inner();
                g.reset();
                self.finality.cache.clear_poison();
                g
            }
        };
        // Review round 2, M1: sources examined, and the shared walks of the
        // persistent-invalidity test (`invalid_persistently_memo`).
        let mut visits = 0u64;
        let mut memo: HashMap<BlockHash, bool> = HashMap::new();
        let mut out = PinOutcome::default();
        let anchor = self.resolve_anchor(policy, &mut memo, &mut visits);
        out.anchor = anchor.status;
        let anc = |a: &BlockHash, b: &BlockHash| self.is_chain_ancestor_or_self(a, b);
        self.update_pin_cache(&mut cache, policy, &anchor, &mut memo, &mut visits);
        out.ignored = cache.ignored;
        out.against_anchor = cache.against_anchor;

        let (own, chosen) = {
            // Counted candidates highest first; ties (two blocks at one DAG
            // height) by hash, so every choice below is independent of
            // insertion order.
            let desc = || cache.counted.keys().rev().map(|&(height, hash)| Counted { hash, height });
            // The node's own finality: the highest counted checkpoint on its
            // applied chain, or the one it pinned last (still counted) when
            // that one descends from it (learned and pinned, the chain move to
            // it not done yet: a move stopped between chunks, a rebuild from
            // genesis).
            let on_applied = policy.applied.and_then(|t| desc().find(|c| anc(&c.hash, &t)));
            let sticky = policy.sticky.and_then(|s| match cache.class.get(&s) {
                Some(&Class::Counted { height, .. }) => Some(Counted { hash: s, height }),
                _ => None,
            });
            let own = match (on_applied, sticky) {
                (Some(a), Some(s)) if anc(&a.hash, &s.hash) => Some(s),
                (Some(a), _) => Some(a),
                (None, s) => s,
            };
            // What advances it: counted checkpoints strictly above it on its
            // chain (all of them when it has none). The maximal ones (none on
            // the selected chain of another; heights strictly increase along
            // a selected chain, so a candidate can only be an ancestor of one
            // already taken).
            let mut maximal: Vec<Counted> = Vec::new();
            for c in desc() {
                // Only a higher block can descend from `own` (and the order is
                // highest first, so the rest is not advancing either).
                if own.is_some_and(|o| c.height <= o.height) {
                    break;
                }
                let advances = own.is_none_or(|o| anc(&o.hash, &c.hash));
                if advances && !maximal.iter().any(|m| anc(&c.hash, &m.hash)) {
                    maximal.push(c);
                }
            }
            let chosen = match maximal.as_slice() {
                [] => own,
                [only] => Some(*only),
                // Learned only from chains the node has not applied (an
                // applied one would be its own finality): the most work,
                // deterministic. The work of every source is read for these
                // few only.
                several => {
                    out.resolution = ConflictResolution::MostWork;
                    let mut best: Option<(u128, Counted)> = None;
                    for m in several {
                        let w = self.best_source_work(&m.hash, policy.min_chain_work, &mut memo, &mut visits);
                        let better = best.is_none_or(|(bw, b)| (w, m.height, m.hash) > (bw, b.height, b.hash));
                        if better {
                            best = Some((w, *m));
                        }
                    }
                    best.map(|(_, m)| m)
                }
            };
            (own, chosen)
        };
        if let Some(p) = chosen {
            out.origin = PinOrigin::Finalized;
            // Every counted checkpoint off the pin's chain conflicts with it
            // (kept by the cache, `PinCache::sync_conflicts`).
            cache.sync_conflicts(self, (p.hash, p.height));
            if let Some(&(height, hash)) = cache.conflicting.last() {
                out.conflict = Some(((p.hash, p.height), (hash, height)));
                out.conflicting = cache.conflicting.len();
                if out.resolution == ConflictResolution::None {
                    out.resolution = ConflictResolution::OwnFinality;
                }
            } else {
                out.resolution = ConflictResolution::None;
            }
        }
        out.own = own.map(|o| (o.hash, o.height));
        out.counted = cache.counted_list();
        drop(cache);
        out.pin = match (anchor.block, chosen) {
            (Some(a), None) => {
                out.origin = PinOrigin::Anchor;
                Some((a.hash, a.height))
            }
            // Every counted candidate descends from the anchor: the higher
            // of the two is the pin.
            (Some(a), Some(p)) if p.height < a.height => {
                out.origin = PinOrigin::Anchor;
                Some((a.hash, a.height))
            }
            (_, p) => p.map(|p| (p.hash, p.height)),
        };
        // Review round 2, M3: while a configured anchor is unknown nothing
        // above it counts. The node holds the checkpoint it pinned last
        // instead of falling back to the most work: an anchor it never
        // receives (a typo, a block of another network) must not take its
        // finality away, silently.
        if out.anchor == AnchorStatus::Unknown {
            if out.pin.is_none() {
                let held = policy.sticky
                    .filter(|s| !self.invalid_persistently_memo(s, &mut memo, &mut visits))
                    .filter(|s| !policy.ignored.iter().any(|i| anc(i, s)))
                    .and_then(|s| self.store.get(&s).map(|d| (s, d.height)));
                if let Some(h) = held {
                    out.pin = Some(h);
                    out.origin = PinOrigin::Held;
                }
            }
            let applied_height = policy.applied.and_then(|t| self.store.get(&t)).map(|d| d.height);
            out.anchor_overdue = matches!((policy.anchor, applied_height), (Some(a), Some(h)) if h > a.height);
        }
        self.finality.source_visits.fetch_add(visits, std::sync::atomic::Ordering::Relaxed);
        out
    }

    /// What the anchor of `policy` amounts to on this DAG: the block if known
    /// and valid, and the height that separates what it dominates from what
    /// must descend from it.
    fn resolve_anchor(&self, policy: &PinPolicy<'_>, memo: &mut HashMap<BlockHash, bool>, visits: &mut u64)
        -> AnchorView
    {
        match policy.anchor {
            None => AnchorView { block: None, height: None, status: AnchorStatus::None },
            Some(a) => match self.store.get(&a.hash) {
                None => AnchorView { block: None, height: Some(a.height), status: AnchorStatus::Unknown },
                Some(d) => {
                    let status = if self.invalid_persistently_memo(&a.hash, memo, visits) {
                        AnchorStatus::Invalid
                    } else if d.height != a.height {
                        AnchorStatus::HeightMismatch
                    } else {
                        AnchorStatus::Known
                    };
                    let usable = status != AnchorStatus::Invalid;
                    AnchorView {
                        block: usable.then_some(Anchor { hash: a.hash, height: d.height }),
                        height: Some(d.height),
                        status,
                    }
                }
            },
        }
    }

    /// Whether candidate `cp` counts, and if not why (`None`: its block is not
    /// in the DAG). Depends on its sources, the disqualified set and the
    /// policy's minimum chain work, ignored blocks and anchor only: the
    /// [`PinCache`] key.
    fn classify_candidate(&self, cp: &BlockHash, cand: &Candidate, policy: &PinPolicy<'_>, anchor: &AnchorView,
                          memo: &mut HashMap<BlockHash, bool>, visits: &mut u64) -> Option<Class>
    {
        let d = self.store.get(cp)?;
        let anc = |a: &BlockHash, b: &BlockHash| self.is_chain_ancestor_or_self(a, b);
        // Review LOW 7: a source counts unless it is disqualified for a
        // reason its id commits to; one waiting for a body or a verdict
        // (in-memory marks) keeps its finality. Round 2, M1: the first
        // qualifying source decides (almost every block after a finalization
        // is a source of it). Round 3, M-B: heaviest first, so a candidate
        // below the minimum chain work (initial sync with a real minimum)
        // costs O(1).
        if cand.sources.first().is_none_or(|(w, _)| *w < policy.min_chain_work) {
            return Some(Class::Unsupported);
        }
        let mut supported = false;
        for (w, s) in &cand.sources {
            if *w < policy.min_chain_work {
                break;
            }
            if self.source_qualifies(s, policy.min_chain_work, memo, visits) {
                supported = true;
                break;
            }
        }
        if !supported {
            return Some(Class::Unsupported);
        }
        if policy.ignored.iter().any(|i| anc(i, cp)) {
            return Some(Class::Ignored);
        }
        if let Some(ah) = anchor.height {
            let descends = anchor.block.is_some_and(|a| d.height > ah && anc(&a.hash, cp));
            if !descends {
                // Above the anchor's height without it on its chain: against
                // it (were the anchor on that chain, it would be in the DAG).
                // At or below: dominated if it is on the anchor's chain,
                // against it if not, undecided while the anchor is unknown.
                let against = d.height > ah || anchor.block.is_some_and(|a| !anc(cp, &a.hash));
                return Some(if against { Class::AgainstAnchor } else { Class::Dominated });
            }
        }
        Some(Class::Counted { height: d.height, slot: cand.slot })
    }

    /// Bring `cache` up to date for `policy`: every candidate again when its
    /// key changed (the disqualified set, the minimum chain work, the ignored
    /// blocks or the anchor), else the candidates whose sources changed.
    fn update_pin_cache(&self, cache: &mut PinCache, policy: &PinPolicy<'_>, anchor: &AnchorView,
                        memo: &mut HashMap<BlockHash, bool>, visits: &mut u64)
    {
        let mut ignored: Vec<BlockHash> = policy.ignored.iter().copied().collect();
        ignored.sort_unstable();
        let key = CacheKey {
            invalid_gen: self.invalid_gen,
            min_chain_work: policy.min_chain_work,
            anchor: policy.anchor,
            anchor_block: anchor.block,
            anchor_status: anchor.status,
            ignored,
        };
        let todo: Vec<BlockHash> = if cache.key.as_ref() != Some(&key) {
            cache.reset();
            cache.key = Some(key);
            self.finality.by_checkpoint.keys().copied().collect()
        } else {
            cache.dirty.drain().collect()
        };
        for cp in todo {
            cache.unclassify(&cp);
            let class = self.finality.by_checkpoint.get(&cp)
                .and_then(|cand| self.classify_candidate(&cp, cand, policy, anchor, memo, visits));
            if let Some(c) = class {
                cache.classify_as(cp, c);
            }
        }
    }

    /// Whether `s` is a source that counts: not disqualified for a reason its
    /// id commits to, with at least `min_work` blue work.
    fn source_qualifies(&self, s: &BlockHash, min_work: u128, memo: &mut HashMap<BlockHash, bool>, visits: &mut u64)
        -> bool
    {
        *visits += 1;
        !self.invalid_persistently_memo(s, memo, visits) && self.store.get(s).is_some_and(|d| d.blue_work >= min_work)
    }

    /// The blue work of the heaviest qualifying source of checkpoint `cp`
    /// (the first that qualifies: sources are kept heaviest first).
    fn best_source_work(&self, cp: &BlockHash, min_work: u128, memo: &mut HashMap<BlockHash, bool>, visits: &mut u64)
        -> u128
    {
        for (w, s) in self.finality.by_checkpoint.get(cp).map(|c| c.sources.as_slice()).unwrap_or(&[]) {
            if *w < min_work {
                break;
            }
            if self.source_qualifies(s, min_work, memo, visits) {
                return *w;
            }
        }
        0
    }

    /// [`GhostDAG::is_invalid_persistently`] with its selected-chain walks
    /// shared through `memo` (every block on a walk has the walk's answer),
    /// so one pin computation walks each disqualified block at most once.
    fn invalid_persistently_memo(&self, h: &BlockHash, memo: &mut HashMap<BlockHash, bool>, visits: &mut u64) -> bool {
        if !self.invalid.contains(h) {
            return false;
        }
        let mut path = Vec::new();
        let mut cur = *h;
        let result = loop {
            *visits += 1;
            if !self.invalid.contains(&cur) {
                break false;
            }
            if let Some(&r) = memo.get(&cur) {
                break r;
            }
            if self.invalid_roots.contains(&cur) || self.invalid_all_edges.contains(&cur) {
                break true;
            }
            path.push(cur);
            match self.store.get(&cur).and_then(|d| d.selected_parent) {
                Some(sp) => cur = sp,
                None => break false,
            }
        };
        for p in path {
            memo.insert(p, result);
        }
        result
    }

    /// Replace the pin (it may move back: a disqualification or an operator
    /// setting changes what counts; a conflicting finalized checkpoint never
    /// does). [`GhostDAG::set_finalized`] only ever advances it. The pinned
    /// finalized checkpoint becomes the sticky one ([`PinPolicy::sticky`]).
    pub fn set_finality_pin(&mut self, outcome: PinOutcome) {
        self.finalized = outcome.pin;
        self.finality.sticky = match (outcome.anchor, outcome.origin) {
            // Never cleared nor replaced while the anchor is unknown (M3).
            (AnchorStatus::Unknown, _) => self.finality.sticky,
            // The block pinned last, whatever its origin (round 3, LOW 4): an
            // anchor pin is held as well. Only a counted finalized checkpoint
            // is ever the node's own finality.
            (_, PinOrigin::Finalized | PinOrigin::Anchor) => outcome.pin.map(|(h, _)| h),
            _ => None,
        };
        self.finality.last = outcome;
    }

    /// The last outcome applied by [`set_finality_pin`](Self::set_finality_pin).
    pub fn finality_outcome(&self) -> &PinOutcome {
        &self.finality.last
    }

    /// Every recorded candidate: (checkpoint, slot, sources).
    #[allow(dead_code)] // tests and tools; the node binary compiles this module too
    pub fn finality_candidates(&self) -> Vec<(BlockHash, u64, usize)> {
        let mut v: Vec<(BlockHash, u64, usize)> = self.finality.by_checkpoint.iter()
            .map(|(h, c)| (*h, c.slot, c.sources.len()))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
        v
    }
}

#[cfg(test)]
impl GhostDAG {
    /// The former full computation of [`GhostDAG::compute_finality_pin`]
    /// (main before package O2), kept verbatim as the reference the tests
    /// compare the cached computation with. The pin these blocks and
    /// `policy` give (see the module docs). Pure:
    /// it reads the DAG, the disqualified set and the index, and changes
    /// nothing. O(candidates + sources), every chain relation an O(1)
    /// reachability query (no selected-chain walk, review MEDIUM 4).
    pub(crate) fn compute_finality_pin_reference(&self, policy: &PinPolicy<'_>) -> PinOutcome {
        /// A counted candidate: checkpoint, DAG height, slot.
        #[derive(Clone, Copy)]
        struct Counted {
            hash: BlockHash,
            height: u64,
            slot: u64,
        }
        // Review round 2, M1: sources examined, and the shared walks of the
        // persistent-invalidity test (`invalid_persistently_memo`).
        let mut visits = 0u64;
        let mut memo: HashMap<BlockHash, bool> = HashMap::new();
        let mut out = PinOutcome::default();
        // The anchor: the block if known and valid, and the height that
        // separates what it dominates from what must descend from it.
        let (anchor_block, anchor_height) = match policy.anchor {
            None => (None, None),
            Some(a) => match self.store.get(&a.hash) {
                None => {
                    out.anchor = AnchorStatus::Unknown;
                    (None, Some(a.height))
                }
                Some(d) => {
                    out.anchor = if self.invalid_persistently_memo(&a.hash, &mut memo, &mut visits) {
                        AnchorStatus::Invalid
                    } else if d.height != a.height {
                        AnchorStatus::HeightMismatch
                    } else {
                        AnchorStatus::Known
                    };
                    let usable = out.anchor != AnchorStatus::Invalid;
                    (usable.then_some(Anchor { hash: a.hash, height: d.height }), Some(d.height))
                }
            },
        };
        let anc = |a: &BlockHash, b: &BlockHash| self.is_chain_ancestor_or_self(a, b);

        let mut counted: Vec<Counted> = Vec::new();
        for (cp, cand) in &self.finality.by_checkpoint {
            let Some(d) = self.store.get(cp) else { continue };
            // Review LOW 7: a source counts unless it is disqualified for a
            // reason its id commits to; one waiting for a body or a verdict
            // (in-memory marks) keeps its finality. Round 2, M1: the first
            // qualifying source decides (almost every block after a
            // finalization is a source of it). Round 3, M-B: heaviest first,
            // so a candidate below the minimum chain work (initial sync with a
            // real minimum) costs O(1).
            if cand.sources.first().is_none_or(|(w, _)| *w < policy.min_chain_work) {
                continue;
            }
            let mut supported = false;
            for (w, s) in &cand.sources {
                if *w < policy.min_chain_work {
                    break;
                }
                if self.source_qualifies(s, policy.min_chain_work, &mut memo, &mut visits) {
                    supported = true;
                    break;
                }
            }
            if !supported {
                continue;
            }
            if policy.ignored.iter().any(|i| anc(i, cp)) {
                out.ignored += 1;
                continue;
            }
            if let Some(ah) = anchor_height {
                let descends = anchor_block.is_some_and(|a| d.height > ah && anc(&a.hash, cp));
                if !descends {
                    // Above the anchor's height without it on its chain:
                    // against it (were the anchor on that chain, it would be
                    // in the DAG). At or below: dominated if it is on the
                    // anchor's chain, against it if not, undecided while
                    // the anchor is unknown.
                    let against = d.height > ah || anchor_block.is_some_and(|a| !anc(cp, &a.hash));
                    if against {
                        out.against_anchor += 1;
                    }
                    continue;
                }
            }
            counted.push(Counted { hash: *cp, height: d.height, slot: cand.slot });
        }
        // Highest first; ties (two blocks at one DAG height) by hash, so the
        // order, and every choice below, is independent of insertion order.
        counted.sort_by(|a, b| b.height.cmp(&a.height).then(b.hash.cmp(&a.hash)));

        // The node's own finality: the highest counted checkpoint on its
        // applied chain, or the one it pinned last (still counted) when that
        // one descends from it (learned and pinned, the chain move to it not
        // done yet: a move stopped between chunks, a rebuild from genesis).
        let on_applied = policy.applied.and_then(|t| counted.iter().find(|c| anc(&c.hash, &t)).copied());
        let sticky = policy.sticky.and_then(|s| counted.iter().find(|c| c.hash == s).copied());
        let own = match (on_applied, sticky) {
            (Some(a), Some(s)) if anc(&a.hash, &s.hash) => Some(s),
            (Some(a), _) => Some(a),
            (None, s) => s,
        };
        // What advances it: counted checkpoints strictly above it on its
        // chain (all of them when it has none). The maximal ones (none on
        // the selected chain of another; heights strictly increase along a
        // selected chain, so a candidate can only be an ancestor of one
        // already taken).
        let mut maximal: Vec<Counted> = Vec::new();
        for c in &counted {
            // Only a higher block can descend from `own` (and `counted` is
            // highest first, so the rest is not advancing either).
            if own.is_some_and(|o| c.height <= o.height) {
                break;
            }
            let advances = own.is_none_or(|o| anc(&o.hash, &c.hash));
            if advances && !maximal.iter().any(|m| anc(&c.hash, &m.hash)) {
                maximal.push(*c);
            }
        }
        let chosen = match maximal.as_slice() {
            [] => own,
            [only] => Some(*only),
            // Learned only from chains the node has not applied (an applied
            // one would be its own finality): the most work, deterministic.
            // The work of every source is read for these few only.
            several => {
                out.resolution = ConflictResolution::MostWork;
                let mut best: Option<(u128, Counted)> = None;
                for m in several {
                    let w = self.best_source_work(&m.hash, policy.min_chain_work, &mut memo, &mut visits);
                    let better = best.is_none_or(|(bw, b)| (w, m.height, m.hash) > (bw, b.height, b.hash));
                    if better {
                        best = Some((w, *m));
                    }
                }
                best.map(|(_, m)| m)
            }
        };
        if let Some(p) = chosen {
            out.origin = PinOrigin::Finalized;
            // Every counted checkpoint off the pin's chain conflicts with it
            // (one reachability query each: only a lower block can be on the
            // pin's selected chain, only a higher one can descend from it).
            let mut conflicting = counted.iter().filter(|c| match c.height.cmp(&p.height) {
                std::cmp::Ordering::Greater => !anc(&p.hash, &c.hash),
                _ => !anc(&c.hash, &p.hash),
            });
            if let Some(first) = conflicting.next() {
                out.conflict = Some(((p.hash, p.height), (first.hash, first.height)));
                out.conflicting = 1 + conflicting.count();
                if out.resolution == ConflictResolution::None {
                    out.resolution = ConflictResolution::OwnFinality;
                }
            } else {
                out.resolution = ConflictResolution::None;
            }
        }
        out.own = own.map(|o| (o.hash, o.height));
        out.counted = Arc::new(counted.iter().map(|c| (c.hash, c.height, c.slot)).collect());
        out.pin = match (anchor_block, chosen) {
            (Some(a), None) => {
                out.origin = PinOrigin::Anchor;
                Some((a.hash, a.height))
            }
            // Every counted candidate descends from the anchor: the higher
            // of the two is the pin.
            (Some(a), Some(p)) if p.height < a.height => {
                out.origin = PinOrigin::Anchor;
                Some((a.hash, a.height))
            }
            (_, p) => p.map(|p| (p.hash, p.height)),
        };
        // Review round 2, M3: while a configured anchor is unknown nothing
        // above it counts. The node holds the checkpoint it pinned last
        // instead of falling back to the most work: an anchor it never
        // receives (a typo, a block of another network) must not take its
        // finality away, silently.
        if out.anchor == AnchorStatus::Unknown {
            if out.pin.is_none() {
                let held = policy.sticky
                    .filter(|s| !self.invalid_persistently_memo(s, &mut memo, &mut visits))
                    .filter(|s| !policy.ignored.iter().any(|i| anc(i, s)))
                    .and_then(|s| self.store.get(&s).map(|d| (s, d.height)));
                if let Some(h) = held {
                    out.pin = Some(h);
                    out.origin = PinOrigin::Held;
                }
            }
            let applied_height = policy.applied.and_then(|t| self.store.get(&t)).map(|d| d.height);
            out.anchor_overdue = matches!((policy.anchor, applied_height), (Some(a), Some(h)) if h > a.height);
        }
        self.finality.source_visits.fetch_add(visits, std::sync::atomic::Ordering::Relaxed);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(tag: u8, n: u64) -> BlockHash {
        let mut x = [0u8; 32];
        x[0] = tag;
        x[1..9].copy_from_slice(&n.to_le_bytes());
        x
    }

    /// genesis g; chain a = g -> a1..a10; chain b = a3 -> b4..b12 (heavier).
    fn dag() -> GhostDAG {
        let mut d = GhostDAG::with_default_k();
        d.add_genesis(h(0, 0), 0);
        let mut p = h(0, 0);
        for i in 1..=10 {
            d.add_block(h(1, i), vec![p], i, 10).unwrap();
            p = h(1, i);
        }
        let mut p = h(1, 3);
        for i in 4..=12 {
            d.add_block(h(2, i), vec![p], i, 10).unwrap();
            p = h(2, i);
        }
        d
    }

    fn policy(ignored: &HashSet<BlockHash>) -> PinPolicy<'_> {
        PinPolicy { min_chain_work: 0, anchor: None, ignored, applied: None, sticky: None }
    }

    /// A node whose applied tip is `applied` and which pinned `sticky` last.
    fn on(applied: BlockHash, sticky: Option<BlockHash>, ignored: &HashSet<BlockHash>) -> PinPolicy<'_> {
        PinPolicy { applied: Some(applied), sticky, ..policy(ignored) }
    }

    /// The pin is the highest candidate of one chain; a finality learned from
    /// a chain the node has not applied advances it when it descends from it
    /// (finding 2, the healed partition).
    #[test]
    fn the_pin_is_the_highest_candidate_and_a_learned_one_advances_it() {
        let none = HashSet::new();
        let mut d = dag();
        assert_eq!(d.compute_finality_pin(&on(h(1, 10), None, &none)).pin, None);
        d.note_finality_source(h(1, 8), h(1, 2), 3);
        let o = d.compute_finality_pin(&on(h(1, 10), None, &none));
        assert_eq!((o.pin, o.own, o.origin, o.conflict), (Some((h(1, 2), 2)), Some((h(1, 2), 2)),
            PinOrigin::Finalized, None));
        // b finalizes b6, which descends from a2: the node on a learns it.
        d.note_finality_source(h(2, 11), h(2, 6), 7);
        let o = d.compute_finality_pin(&on(h(1, 10), Some(h(1, 2)), &none));
        assert_eq!((o.pin, o.own, o.conflict, o.resolution), (Some((h(2, 6), 6)), Some((h(1, 2), 2)), None,
            ConflictResolution::None));
    }

    /// Review HIGH 1: finality the node reached on its own chain is sticky.
    /// a finalizes a5, b (heavier) finalizes b6: they conflict. The node on
    /// a keeps a5 and the node on b keeps b6, each reporting the other; a
    /// node with no finality of its own takes the one whose best source has
    /// the most work (review MEDIUM 3), never their latest common block a3.
    #[test]
    fn own_finality_is_kept_against_a_conflict_and_learned_conflicts_go_to_the_most_work() {
        let none = HashSet::new();
        let mut d = dag();
        d.note_finality_source(h(1, 8), h(1, 2), 3);
        d.note_finality_source(h(1, 9), h(1, 5), 6);
        d.note_finality_source(h(2, 11), h(2, 6), 7);
        let o = d.compute_finality_pin(&on(h(1, 10), Some(h(1, 5)), &none));
        assert_eq!((o.pin, o.own, o.origin), (Some((h(1, 5), 5)), Some((h(1, 5), 5)), PinOrigin::Finalized));
        assert_eq!((o.conflict, o.conflicting, o.resolution),
            (Some(((h(1, 5), 5), (h(2, 6), 6))), 1, ConflictResolution::OwnFinality));
        // The same without the sticky pin (a restart before it was persisted):
        // the applied chain's finality is the node's own.
        assert_eq!(d.compute_finality_pin(&on(h(1, 10), None, &none)), o);
        let o = d.compute_finality_pin(&on(h(2, 12), None, &none));
        assert_eq!((o.pin, o.conflict), (Some((h(2, 6), 6)), Some(((h(2, 6), 6), (h(1, 5), 5)))));
        // The applied chain wins over a sticky pin that conflicts with it.
        assert_eq!(d.compute_finality_pin(&on(h(1, 10), Some(h(2, 6)), &none)).pin, Some((h(1, 5), 5)));
        // A sticky pin above the applied chain's finality stays (a move
        // stopped below it, a rebuild that restarts from the fork point).
        assert_eq!(d.compute_finality_pin(&on(h(1, 3), Some(h(1, 5)), &none)).pin, Some((h(1, 5), 5)));
        assert_eq!(d.compute_finality_pin(&on(h(1, 3), Some(h(2, 6)), &none)).pin, Some((h(2, 6), 6)));
        // No finality of its own: b6's source (11 blocks of work) beats a5's (9).
        let o = d.compute_finality_pin(&policy(&none));
        assert_eq!((o.pin, o.own, o.resolution), (Some((h(2, 6), 6)), None, ConflictResolution::MostWork));
        assert_eq!(o.conflict, Some(((h(2, 6), 6), (h(1, 5), 5))));
        let o2 = d.compute_finality_pin(&on(h(1, 3), None, &none));
        assert_eq!((o2.pin, o2.own, o2.resolution), (Some((h(2, 6), 6)), Some((h(1, 2), 2)),
            ConflictResolution::MostWork), "both advance a2: still the most work");
        // The same set in another insertion order gives the same outcome.
        let mut e = dag();
        e.note_finality_source(h(2, 11), h(2, 6), 7);
        e.note_finality_source(h(1, 9), h(1, 5), 6);
        e.note_finality_source(h(1, 8), h(1, 2), 3);
        assert_eq!(e.compute_finality_pin(&policy(&none)), o);
        // A later, heavier source of a5 turns the choice.
        d.add_block(h(1, 11), vec![h(1, 10)], 11, 10).unwrap();
        d.add_block(h(1, 12), vec![h(1, 11)], 12, 10).unwrap();
        d.note_finality_source(h(1, 12), h(1, 5), 6);
        assert_eq!(d.compute_finality_pin(&policy(&none)).pin, Some((h(1, 5), 5)));
        // Disqualifying b's source drops b6: no conflict any more.
        d.mark_invalid(h(2, 10));
        let o = d.compute_finality_pin(&on(h(1, 10), None, &none));
        assert_eq!((o.pin, o.conflict, o.resolution), (Some((h(1, 5), 5)), None, ConflictResolution::None));
        // The operator sets a5 aside: a2 remains.
        let ignored: HashSet<BlockHash> = [h(1, 4)].into_iter().collect();
        let o = d.compute_finality_pin(&on(h(1, 10), Some(h(1, 5)), &ignored));
        assert_eq!((o.pin, o.ignored), (Some((h(1, 2), 2)), 1));
    }

    /// Review LOW 7: a source counts unless it is disqualified for a reason
    /// its id commits to; a block waiting for a body or a verdict keeps it.
    #[test]
    fn only_a_persistent_disqualification_drops_a_source() {
        let none = HashSet::new();
        let mut d = dag();
        d.note_finality_source(h(1, 9), h(1, 5), 6);
        d.mark_body_pending(h(1, 8), None);
        assert!(d.is_invalid(&h(1, 9)));
        assert_eq!(d.compute_finality_pin(&policy(&none)).pin, Some((h(1, 5), 5)));
        d.park_no_verdict(h(1, 7));
        assert_eq!(d.compute_finality_pin(&policy(&none)).pin, Some((h(1, 5), 5)));
        d.mark_invalid(h(1, 9));
        assert_eq!(d.compute_finality_pin(&policy(&none)).pin, None);
    }

    #[test]
    fn the_anchor_dominates_below_and_must_be_an_ancestor_above() {
        let none = HashSet::new();
        let mut d = dag();
        d.note_finality_source(h(1, 9), h(1, 5), 6);
        d.note_finality_source(h(2, 11), h(2, 6), 7);
        // Anchor b4: a5 conflicts with it, b6 descends from it.
        let anchor = Some(Anchor { hash: h(2, 4), height: 4 });
        let o = d.compute_finality_pin(&PinPolicy { anchor, ..policy(&none) });
        assert_eq!((o.pin, o.origin, o.against_anchor, o.anchor), (Some((h(2, 6), 6)), PinOrigin::Finalized, 1,
            AnchorStatus::Known));
        // Anchor b8, above b6: b6 is below it (dominated), a5 conflicts.
        let anchor = Some(Anchor { hash: h(2, 8), height: 8 });
        let o = d.compute_finality_pin(&PinPolicy { anchor, ..policy(&none) });
        assert_eq!((o.pin, o.origin, o.against_anchor), (Some((h(2, 8), 8)), PinOrigin::Anchor, 1));
        // An anchor not in the DAG yet: nothing above its height counts, and
        // nothing pins (a fork the node is eclipsed on cannot pin it).
        let anchor = Some(Anchor { hash: h(9, 4), height: 4 });
        let o = d.compute_finality_pin(&PinPolicy { anchor, ..policy(&none) });
        assert_eq!((o.pin, o.anchor, o.counted.len()), (None, AnchorStatus::Unknown, 0));
        // A disqualified anchor pins nothing (and nothing through it counts).
        d.mark_invalid(h(2, 4));
        let anchor = Some(Anchor { hash: h(2, 4), height: 4 });
        let o = d.compute_finality_pin(&PinPolicy { anchor, ..policy(&none) });
        assert_eq!((o.pin, o.anchor), (None, AnchorStatus::Invalid));
    }

    /// Cost probe for the pin computation (run with `--ignored
    /// --nocapture`): 10,000 finalized checkpoints on one chain, each with
    /// two sources, then the same with a conflicting chain of 2,000 more
    /// (review MEDIUM 4: the former latest-common-block walk made a
    /// conflict cost a selected-chain walk per maximal candidate, at least
    /// three times per accepted block).
    #[test]
    #[ignore = "timing probe: prints the cost of one pin computation"]
    fn measure_pin_computation_cost() {
        let none = HashSet::new();
        let mut d = GhostDAG::with_default_k();
        d.add_genesis(h(0, 0), 0);
        let mut p = h(0, 0);
        let n = 20_000u64;
        for i in 1..=n {
            d.add_block(h(1, i), vec![p], i, 10).unwrap();
            p = h(1, i);
        }
        for i in (2..=n).step_by(2) {
            d.note_finality_source(h(1, i), h(1, i - 1), i);
            d.note_finality_source(h(1, i - 1), h(1, i.saturating_sub(3).max(1)), i);
        }
        // The first computation classifies every candidate (the former cost
        // of every computation); the next ones follow new blocks, as the node
        // does after each acceptance (package O2).
        let measure = |d: &mut GhostDAG, what: &str, tag: u8| {
            let t = std::time::Instant::now();
            let tip = d.selected_tip().unwrap();
            let o = d.compute_finality_pin(&on(tip, d.finality_index().sticky(), &none));
            let full = t.elapsed();
            d.set_finality_pin(o);
            let mut tip = tip;
            let t = std::time::Instant::now();
            for i in 0..10u64 {
                let b = h(tag, 1_000_000 + i);
                d.add_block(b, vec![tip], 1_000_000 + i, 10).unwrap();
                d.note_finality_source(b, tip, 1_000_000 + i);
                tip = b;
                let o = d.compute_finality_pin(&on(tip, d.finality_index().sticky(), &none));
                d.set_finality_pin(o);
            }
            let o = d.finality_outcome();
            eprintln!("{what}: candidates {} -> first {:?}, then {:?} per new block; pin {:?}, conflicting {}",
                d.finality_index().candidates(), full, t.elapsed() / 10, o.pin.map(|x| x.1), o.conflicting);
        };
        measure(&mut d, "one chain", 7);
        let mut p = h(1, 10);
        for i in 11..=4_010u64 {
            d.add_block(h(2, i), vec![p], i, 10).unwrap();
            p = h(2, i);
        }
        for i in (12..=4_010u64).step_by(2) {
            d.note_finality_source(h(2, i), h(2, i - 1), i);
        }
        measure(&mut d, "with a conflicting chain", 8);
    }

    /// Review round 2, M1: the pin is refreshed after every accepted block and
    /// at each step of a chain move, and almost every block after a
    /// finalization is a source of it, so a computation that examines every
    /// source made initial sync quadratic. One computation examines O(1)
    /// sources per candidate (the first that qualifies), also when a chain
    /// of sources is disqualified (its walks are shared), and the most-work
    /// choice reads every source only of the few conflicting candidates.
    #[test]
    fn a_pin_computation_examines_a_bounded_number_of_sources() {
        let none = HashSet::new();
        let mut d = GhostDAG::with_default_k();
        d.add_genesis(h(0, 0), 0);
        let (candidates, per) = (400u64, 25u64);
        let n = candidates * per + 1;
        let mut p = h(0, 0);
        for i in 1..=n {
            d.add_block(h(1, i), vec![p], i, 10).unwrap();
            p = h(1, i);
        }
        // Checkpoint c * per, sourced by the `per` blocks above it.
        for c in 1..candidates {
            for s in 1..=per {
                d.note_finality_source(h(1, c * per + s), h(1, c * per), c * per + 1);
            }
        }
        let sources = d.finality_index().sources() as u64;
        assert_eq!(sources, (candidates - 1) * per);
        let visits = |d: &GhostDAG, policy: &PinPolicy<'_>| {
            let before = d.finality_index().source_visits();
            let o = d.compute_finality_pin(policy);
            (d.finality_index().source_visits() - before, o)
        };
        let (v, o) = visits(&d, &on(h(1, n), None, &none));
        assert_eq!(o.pin.map(|x| x.1), Some((candidates - 1) * per));
        assert!(v <= 2 * candidates, "{v} source visits for {candidates} candidates ({sources} sources)");
        // A disqualified stretch (every source of the top 100 candidates):
        // shared walks, linear in the disqualified blocks.
        d.mark_invalid(h(1, (candidates - 100) * per + 1));
        let (v, o) = visits(&d, &on(h(1, (candidates - 100) * per), None, &none));
        assert_eq!(o.pin.map(|x| x.1), Some((candidates - 101) * per));
        assert!(v <= 2 * candidates + 3 * 100 * per, "{v} visits with 100 candidates disqualified");
        // Review round 3, M-B: below the minimum chain work (initial sync with
        // a real minimum) no source qualifies: a candidate is skipped in O(1).
        let heavy = PinPolicy { min_chain_work: u128::MAX, ..on(h(1, n), None, &none) };
        let (v, o) = visits(&d, &heavy);
        assert_eq!(o.pin, None);
        assert!(v <= candidates, "{v} source visits below the minimum chain work for {candidates} candidates");
    }

    /// A small deterministic generator for the equivalence test.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Package O2: the cached computation gives exactly the outcome of the
    /// former full one (`compute_finality_pin_reference`) through random
    /// sequences of everything that changes its inputs: blocks on competing
    /// branches (some merging), finality sources (new checkpoints and new
    /// sources of old ones), persistent and in-memory disqualifications and
    /// their removal, removed leaves, the node's applied tip and sticky pin
    /// (applied as the node does, `set_finality_pin`), the minimum chain
    /// work, the operator's ignored blocks and the anchor (none, held,
    /// unknown, at the wrong height).
    #[test]
    fn the_cached_pin_equals_the_full_computation() {
        // What the sequences reached: pins, conflicts, most-work choices,
        // advances along the chain, anchored and held pins, ignored and
        // against-anchor candidates.
        let mut seen = [0u32; 8];
        for seed in 1..=24u64 {
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D));
            let mut d = GhostDAG::with_default_k();
            d.add_genesis(h(0, 0), 0);
            let mut blocks: Vec<BlockHash> = vec![h(0, 0)];
            let mut ignored: HashSet<BlockHash> = HashSet::new();
            let mut anchor: Option<Anchor> = None;
            let mut min_work = 0u128;
            let mut pending: Vec<BlockHash> = Vec::new();
            let mut applied = h(0, 0);
            for step in 1..=400u64 {
                match rng.below(100) {
                    // A block on a random recent block (branches), sometimes
                    // merging a second one.
                    0..=44 => {
                        let n = blocks.len();
                        let p = blocks[n - 1 - rng.below(n.min(12))];
                        let mut parents = vec![p];
                        if rng.below(5) == 0 {
                            let q = blocks[n - 1 - rng.below(n.min(12))];
                            if q != p {
                                parents.push(q);
                            }
                        }
                        let b = h(1, step);
                        if d.add_block(b, parents, step, u128::from(1 + rng.next() % 20)).is_ok() {
                            blocks.push(b);
                        }
                    }
                    // A source: a block finalizing one of its selected-chain
                    // ancestors (or, rarely, any block below it).
                    45..=74 => {
                        let s = blocks[rng.below(blocks.len())];
                        let mut cp = s;
                        for _ in 0..(1 + rng.below(6)) {
                            match d.get_block_data(&cp).and_then(|x| x.selected_parent) {
                                Some(sp) => cp = sp,
                                None => break,
                            }
                        }
                        if rng.below(10) == 0 {
                            cp = blocks[rng.below(blocks.len())];
                        }
                        if cp != s {
                            let slot = d.get_block_data(&cp).map(|x| x.height).unwrap_or(0) + 1;
                            d.note_finality_source(s, cp, slot);
                        }
                    }
                    75..=77 => {
                        d.mark_invalid(blocks[rng.below(blocks.len())]);
                    }
                    78..=79 => {
                        let b = blocks[rng.below(blocks.len())];
                        d.mark_body_pending(b, None);
                        pending.push(b);
                    }
                    80 => {
                        if let Some(b) = pending.pop() {
                            d.clear_body_pending(&b);
                        }
                    }
                    81 => {
                        let roots: Vec<BlockHash> = Vec::new();
                        d.reset_invalid_sets(roots.clone(), roots);
                    }
                    82 => {
                        let tips = d.tips();
                        let t = tips[rng.below(tips.len())];
                        if t != h(0, 0) && d.remove_block(&t) {
                            blocks.retain(|x| *x != t);
                            if applied == t {
                                applied = h(0, 0);
                            }
                        }
                    }
                    83..=84 => {
                        let b = blocks[rng.below(blocks.len())];
                        if !ignored.remove(&b) {
                            ignored.insert(b);
                        }
                    }
                    85..=86 => {
                        anchor = match rng.below(4) {
                            0 => None,
                            1 => Some(Anchor { hash: h(9, step), height: 1 + rng.next() % 30 }),
                            _ => {
                                let b = blocks[rng.below(blocks.len())];
                                let ht = d.get_block_data(&b).unwrap().height;
                                Some(Anchor { hash: b, height: if rng.below(6) == 0 { ht + 1 } else { ht } })
                            }
                        };
                    }
                    87 => {
                        min_work = if rng.below(2) == 0 { 0 } else { u128::from(rng.next() % 200) };
                    }
                    88..=93 => {
                        applied = d.selected_tip().unwrap_or(h(0, 0));
                    }
                    _ => {
                        applied = blocks[rng.below(blocks.len())];
                    }
                }
                let sticky = if rng.below(8) == 0 { Some(blocks[rng.below(blocks.len())]) } else { d.finality_index().sticky() };
                let policy = PinPolicy { min_chain_work: min_work, anchor, ignored: &ignored,
                    applied: Some(applied), sticky };
                let fast = d.compute_finality_pin(&policy);
                let full = d.compute_finality_pin_reference(&policy);
                assert_eq!(fast, full, "seed {seed}, step {step}");
                let prev = d.finalized();
                for (i, hit) in [
                    fast.pin.is_some(),
                    fast.conflict.is_some(),
                    fast.resolution == ConflictResolution::MostWork,
                    fast.pin.is_some_and(|p| prev.is_some_and(|q| p.1 > q.1 && d.is_chain_ancestor_or_self(&q.0, &p.0))),
                    fast.origin == PinOrigin::Anchor,
                    fast.origin == PinOrigin::Held,
                    fast.ignored > 0,
                    fast.against_anchor > 0,
                ].into_iter().enumerate() {
                    seen[i] += u32::from(hit);
                }
                d.set_finality_pin(fast);
            }
        }
        assert!(seen.iter().all(|&n| n >= 5), "every case reached: {seen:?}");
    }

    /// Package O2: with an unchanged disqualified set and policy, a
    /// computation after a new block re-examines only what changed: one
    /// chain of 4,000 counted checkpoints (and a conflicting branch of 400)
    /// costs a bounded number of source visits per new block, not one per
    /// candidate, and the counted list is shared while it does not change.
    #[test]
    fn a_pin_computation_after_a_new_block_is_incremental() {
        let none = HashSet::new();
        let mut d = GhostDAG::with_default_k();
        d.add_genesis(h(0, 0), 0);
        let n = 8_000u64;
        let mut p = h(0, 0);
        for i in 1..=n {
            d.add_block(h(1, i), vec![p], i, 10).unwrap();
            p = h(1, i);
        }
        for i in (2..=n).step_by(2) {
            d.note_finality_source(h(1, i), h(1, i - 1), i);
        }
        let mut p = h(1, 10);
        for i in 11..=810u64 {
            d.add_block(h(2, i), vec![p], i, 10).unwrap();
            p = h(2, i);
        }
        for i in (12..=810u64).step_by(2) {
            d.note_finality_source(h(2, i), h(2, i - 1), i);
        }
        let visits = |d: &GhostDAG, tip: BlockHash, sticky: Option<BlockHash>| {
            let before = d.finality_index().source_visits();
            let o = d.compute_finality_pin(&on(tip, sticky, &none));
            (d.finality_index().source_visits() - before, o)
        };
        let (_, o) = visits(&d, h(1, n), None);
        assert_eq!((o.pin, o.conflicting), (Some((h(1, n - 1), n - 1)), 400));
        d.set_finality_pin(o.clone());
        let mut tip = h(1, n);
        for i in n + 1..=n + 40 {
            d.add_block(h(1, i), vec![tip], i, 10).unwrap();
            tip = h(1, i);
            if i % 2 == 0 {
                d.note_finality_source(tip, h(1, i - 1), i);
            }
            let (v, o) = visits(&d, tip, d.finality_index().sticky());
            assert_eq!(o, d.compute_finality_pin_reference(&on(tip, d.finality_index().sticky(), &none)));
            assert!(v <= 4, "{v} source visits for one new block among {} candidates",
                d.finality_index().candidates());
            d.set_finality_pin(o);
        }
        // Unchanged inputs: the same counted list, not a copy.
        let a = d.compute_finality_pin(&on(tip, d.finality_index().sticky(), &none));
        let b = d.compute_finality_pin(&on(tip, d.finality_index().sticky(), &none));
        assert!(Arc::ptr_eq(&a.counted, &b.counted));
        assert_eq!(a.conflicting, 400);
    }

    #[test]
    fn a_source_below_the_minimum_chain_work_does_not_count() {
        let none = HashSet::new();
        let mut d = dag();
        d.note_finality_source(h(1, 6), h(1, 2), 3);
        let w6 = d.get_block_data(&h(1, 6)).unwrap().blue_work;
        let p = |min| PinPolicy { min_chain_work: min, ..policy(&none) };
        assert_eq!(d.compute_finality_pin(&p(w6)).pin, Some((h(1, 2), 2)));
        assert_eq!(d.compute_finality_pin(&p(w6 + 1)).pin, None);
        // A later source of the same checkpoint reaching the minimum counts.
        d.note_finality_source(h(1, 7), h(1, 2), 3);
        assert_eq!(d.compute_finality_pin(&p(w6 + 1)).pin, Some((h(1, 2), 2)));
        // Removing the block forgets its source.
        assert!(d.remove_block(&h(2, 12)));
        d.note_finality_source(h(2, 11), h(2, 5), 6);
        assert!(d.remove_block(&h(2, 11)));
        assert_eq!(d.finality_index().checkpoint_of(&h(2, 11)), None);
        assert_eq!(d.finality_candidates().len(), 1);
    }
}
