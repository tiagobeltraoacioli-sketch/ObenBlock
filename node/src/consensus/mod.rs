//! Bloch-SIS Protocol — GhostDAG Consensus (PHANTOM Protocol)
//!
//! Implementation based on:
//!   Sompolinsky, Wyborski, Zohar — "PHANTOM GHOSTDAG: A Scalable
//!   Generalization of Nakamoto Consensus" (2021)
//!
//! Reference: kaspanet/rusty-kaspa consensus/src/processes/ghostdag/
//!
//! Key invariants:
//!   - selected_parent = argmax(blue_work) over parents
//!   - blue_score(B) = blue_score(selected_parent) + |mergeset_blues(B)| + 1
//!   - Block C is blue in B's context iff |anticone(C) ∩ blue_set(B)| ≤ K
//!   - Both candidate and existing blue blocks satisfy the K constraint
//!
//! Performance:
//!   - ancestry: the interval reachability index (`reachability`), live for
//!     every block (`CORRECTED_COLORING_ACTIVATION_HEIGHT = 0`), O(log) per
//!     query; the bounded legacy `is_ancestor` (blue_work shortcut, DAG-8)
//!     and the k*100-bounded `past_blue_set` serve only the Legacy coloring,
//!     which the activation gate never selects on GnB
//!   - blue_work: cumulative work; see the hardening activation note below
//!
//! Hardening activation (audit 2026-10-14, DAG-3 / DAG-4 / DAG-7):
//!   Blocks whose `GhostdagData::height` is at or above
//!   [`GhostDAG::hardening_activation_height`] (mainnet 17,500; testnet and
//!   regtest 0, see `crate::core::activation`) are processed under corrected
//!   rules. Blocks below it are processed exactly as before.
//!   - blue_work = sp.blue_work + work of the mergeset blues + own work, i.e.
//!     the work of blue(B) ∪ {B} (DAG-3). Below activation: sp.blue_work + own.
//!   - coloring: exact GHOSTDAG k-cluster rule over the full blue anticone,
//!     selected chain included (DAG-4). Below activation: the old coloring.
//!   - mergeset at most [`MAX_MERGESET_SIZE`] blocks (selected parent
//!     included) and no red merged from below the merge-depth root
//!     ([`MERGE_DEPTH`]) unless a merged blue covers it (DAG-7).
//!
//!   The ledger stays selected-chain-only at every height: transactions of
//!   merged blocks are never applied (docs/CONSENSUS.md).

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use serde::{Serialize, Deserialize};
use log::warn;
use crate::core::GHOSTDAG_K;
use crate::core::activation;

/// Maximum mergeset size of a block at or above the hardening activation,
/// counting the selected parent (Kaspa's convention: `mergeset_blues` there
/// includes the selected parent; GnB stores it separately, so the check is
/// `1 + |mergeset_blues| + |mergeset_reds| <= MAX_MERGESET_SIZE`).
///
/// Why 180: it is Kaspa's mainnet `mergeset_size_limit`, in production since
/// 2021. With k = 10 at most k + 1 = 11 entries are blue, so the limit leaves
/// 169 slots for reds: at the 30 s target an honest block merges a few blocks,
/// and a partition that produced up to ~170 blocks on the losing side can still
/// be merged in one block (larger ones are merged over several blocks, or not
/// at all once they fall below the merge-depth root). The limit bounds the
/// coloring cost of one block to 179 candidates, each checked with the k + 1
/// early-exit walk below (measured in `node/tests/fix_ghostdag_dag7_perf.rs`).
/// It is below `MAX_PARENTS` (256), so templates must pick their parents with
/// [`GhostDAG::select_parents_for_template`].
pub const MAX_MERGESET_SIZE: usize = 180;

/// Merge depth, in blue score, for blocks at or above the hardening
/// activation. The merge-depth root of a block B is the highest block of B's
/// selected chain whose blue_score is at most `B.blue_score - MERGE_DEPTH`. A
/// red block in B's mergeset must be in the future of that root, or in the past
/// of a mergeset blue that is (Kaspa's "kosherizing" rule). Blues need no check:
/// a blue that deep would have more than k blues in its anticone.
///
/// Why 360: 3 hours at the 30 s target, comparable to Kaspa's one hour and far
/// above any propagation delay. It bounds MERGING objectively (a pure
/// function of each block's past); it does not bound reorgs: GnB has no
/// reorg-depth limit and no finality checkpoint (audit DAG-6), so the
/// heaviest valid chain is followed at any depth.
pub const MERGE_DEPTH: u64 = 360;

pub mod reachability;
use reachability::ReachabilityStore;
pub mod finality;

thread_local! {
    static COMPUTE_BLOCK_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static BLOCK_DATA_LOOKUPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Number of per-block GhostDAG record lookups (`DagStore::get`, behind
/// `GhostDAG::get_block_data`) on the calling thread since it started.
/// Every walk over the DAG's records goes through it, whatever the walking
/// code, so cost tests bound it (audit B1-T16: planning a chain move reads
/// O(move) records, not the chain back to genesis). No effect on behaviour.
#[allow(dead_code)] // tests only; the node binary compiles this module too
pub fn block_data_lookups() -> u64 {
    BLOCK_DATA_LOOKUPS.with(|c| c.get())
}

/// Number of full GhostDAG block computations (`compute_block`: mergeset,
/// coloring, merge-depth check) run on the calling thread since it started.
/// Instrumentation for cost tests (audit B1-T15); no effect on behaviour.
#[allow(dead_code)] // tests only; the node binary compiles this module too
pub fn compute_block_calls() -> u64 {
    COMPUTE_BLOCK_CALLS.with(|c| c.get())
}

// ── Types ────────────────────────────────────────────────────────────────────

pub type BlockHash = [u8; 32];

/// All GhostDAG consensus data for a single block.
/// Mirrors kaspa-rs `GhostdagData`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GhostdagData {
    /// Number of blue blocks in this block's past (including itself if blue)
    pub blue_score: u64,
    /// Accumulated PoW work of blue blocks (for tie-breaking)
    pub blue_work: u128,
    /// Selected parent — parent with highest blue_score (ties broken by hash)
    pub selected_parent: Option<BlockHash>,
    /// Blue blocks from the mergeset (topologically ordered)
    pub mergeset_blues: Vec<BlockHash>,
    /// Red blocks from the mergeset
    pub mergeset_reds: Vec<BlockHash>,
    /// For each blue block in mergeset: its anticone size w.r.t. this block's blue set
    pub blues_anticone_sizes: HashMap<BlockHash, usize>,
    /// This block's parents
    pub parents: Vec<BlockHash>,
    /// DAG height: `selected_parent.height + 1` (genesis = 0). NOT the
    /// longest path from genesis and NOT the header height.
    ///
    /// Audit DAG-8 — the node uses two heights:
    ///   * this DAG height, a function of the selected-parent chain only;
    ///   * the HEADER height (`Block::height`), which `accept_block` requires
    ///     to equal `max(parent DAG heights) + 1`.
    /// They diverge whenever the selected (highest blue-work) parent is not
    /// the parent with the greatest DAG height. Consequently the DAG height
    /// is monotone along selected-parent edges but NOT along merge edges: a
    /// non-selected parent can have a GREATER DAG height than its child.
    /// Nothing may treat "a.height >= b.height" as proof that `a` is not an
    /// ancestor of `b` (the legacy `is_ancestor` did; fixed). Unifying the two
    /// definitions would change which headers are valid and is out of scope.
    pub height: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl GhostdagData {
    pub fn genesis() -> Self {
        Self {
            blue_score: 0,
            blue_work: 0,
            selected_parent: None,
            mergeset_blues: vec![],
            mergeset_reds: vec![],
            blues_anticone_sizes: HashMap::new(),
            parents: vec![],
            height: 0,
            timestamp: 0,
        }
    }
}

// ── Sprint Y (M-2): GhostdagData integrity chain ─────────────────────────────
//
// A hash-chain over per-block GhostdagData, persisted alongside CF_DAG in a
// separate column family (`CF_DAG_INTEGRITY`). Each block's integrity hash
// covers its own canonical bytes plus its selected-parent's integrity hash,
// so tampering with any ancestor's data (or swapping an ancestor for a
// competing-chain block) breaks the chain at that point and every
// descendant validates as mismatched.
//
// See `load_persisted_validated` and `docs/audit/AUDIT-2026-04-20.md` (M-2)
// for the full threat model and the scope of what this does/doesn't protect
// against.

/// Serialize a `GhostdagData` deterministically, regardless of the
/// `HashMap` iteration order for `blues_anticone_sizes`. The output is
/// the canonical pre-image for `compute_integrity_hash`.
///
/// Contract: any two `GhostdagData` values that are structurally equal
/// (same field values, same map contents) MUST produce byte-identical
/// output. Breaking this contract breaks the integrity chain for every
/// node in existence.
pub fn canonical_encode(d: &GhostdagData) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&d.blue_score.to_le_bytes());
    out.extend_from_slice(&d.blue_work.to_le_bytes());
    out.extend_from_slice(&d.height.to_le_bytes());
    out.extend_from_slice(&d.timestamp.to_le_bytes());

    // selected_parent: 1 byte tag + 32 bytes of hash (or 32 zeros for None)
    match &d.selected_parent {
        Some(sp) => {
            out.push(1);
            out.extend_from_slice(sp);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; 32]);
        }
    }

    // parents: length-prefixed, SORTED lexicographically for determinism.
    // Block validation order doesn't depend on parent vector order and
    // the DAG doesn't ascribe meaning to it, so canonical ordering here
    // is safe and necessary.
    let mut parents_sorted = d.parents.clone();
    parents_sorted.sort();
    out.extend_from_slice(&(parents_sorted.len() as u32).to_le_bytes());
    for p in &parents_sorted {
        out.extend_from_slice(p);
    }

    // mergeset_blues: insertion order IS meaningful (topologically sorted,
    // ancestors-first per Kaspa convention). Preserve order verbatim —
    // changing it would change GhostDAG semantics.
    out.extend_from_slice(&(d.mergeset_blues.len() as u32).to_le_bytes());
    for m in &d.mergeset_blues {
        out.extend_from_slice(m);
    }

    // mergeset_reds: same — order-preserving.
    out.extend_from_slice(&(d.mergeset_reds.len() as u32).to_le_bytes());
    for m in &d.mergeset_reds {
        out.extend_from_slice(m);
    }

    // blues_anticone_sizes is the single HashMap in the struct. Its
    // iteration order is non-deterministic across hasher seeds. Sort
    // by key (lexicographic on BlockHash) so the canonical form is
    // stable across machines and across process restarts.
    let mut anticone: Vec<(&BlockHash, &usize)> = d.blues_anticone_sizes.iter().collect();
    anticone.sort_by_key(|(k, _)| *k);
    out.extend_from_slice(&(anticone.len() as u32).to_le_bytes());
    for (k, v) in anticone {
        out.extend_from_slice(k);
        out.extend_from_slice(&(*v as u64).to_le_bytes());
    }

    out
}

/// Hash-chain link: SHA-256 of (block_hash || canonical_encode(data) ||
/// parent_integrity_hash). For genesis, parent_integrity_hash is all zeros.
///
/// Chaining guarantees that altering any ancestor's GhostdagData
/// invalidates every descendant's integrity hash, because the chain
/// carries forward via selected_parent.
pub fn compute_integrity_hash(
    block_hash: &BlockHash,
    data: &GhostdagData,
    parent_integrity: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(block_hash);
    h.update(&canonical_encode(data));
    h.update(parent_integrity);
    h.finalize().into()
}

/// Outcome of `GhostDAG::load_persisted_validated`.
#[derive(Debug)]
pub struct LoadedIntegrity {
    pub blocks_loaded: usize,
    /// True if CF_DAG_INTEGRITY was empty on load and the caller should
    /// persist `fresh_map`. Indicates first boot after Sprint Y upgrade.
    pub self_healed:   bool,
    /// Newly-computed integrity map the caller must persist if self_healed.
    pub fresh_map:     Option<std::collections::HashMap<BlockHash, [u8; 32]>>,
}

/// The header fields a block's GhostDAG data are computed from (what
/// `accept_block` passes to `add_block`): its parents, its timestamp and the
/// work of its bits.
#[derive(Debug, Clone)]
pub struct StoredHeader {
    pub parents: Vec<BlockHash>,
    pub timestamp: u64,
    pub work: u128,
}

/// Outcome of [`GhostDAG::load_persisted_repairing`] (audit DAG-11).
#[derive(Debug, Default)]
pub struct DagRepair {
    /// Blocks loaded into the DAG.
    pub blocks_loaded: usize,
    /// Records kept as stored whose integrity link was re-derived.
    pub relinked: Vec<BlockHash>,
    /// Blocks whose GhostDAG data were recomputed from their stored header
    /// (no record, or a record matching no integrity link), with the data.
    pub recomputed: Vec<(BlockHash, GhostdagData)>,
    /// Blocks not loaded (no header to recompute from, or an unloadable
    /// parent), every descendant of one included.
    pub dropped: Vec<BlockHash>,
    /// The re-derived integrity hash of every loaded block.
    pub integrity: HashMap<BlockHash, [u8; 32]>,
}

/// Errors that can be returned by `load_persisted_validated`. In the
/// original threat model every variant was fatal; the start-up path now
/// repairs the footprints a pre-fix binary left
/// ([`GhostDAG::load_persisted_repairing`], audit DAG-11) instead of exiting.
#[derive(Debug)]
pub enum IntegrityError {
    /// Some blocks have integrity records and some don't. Ambiguous —
    /// could be crash mid-write or could be targeted tampering.
    PartialCoverage { present: usize, total: usize },
    /// A block referenced a selected_parent that didn't appear in the
    /// loaded set. Should never happen on a clean DB.
    ParentNotLoaded { block: BlockHash, parent: BlockHash },
    /// CF_DAG_INTEGRITY had records but this specific block's is missing.
    MissingEntry { block: BlockHash },
    /// The stored integrity hash does not match what we recompute from
    /// the stored GhostdagData + parent integrity. Strongest signal
    /// of tampering or corruption.
    ChainMismatch {
        block:    BlockHash,
        expected: [u8; 32],
        stored:   [u8; 32],
    },
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityError::PartialCoverage { present, total } => write!(f,
                "CF_DAG_INTEGRITY has partial coverage: {}/{} blocks have \
                 integrity records. This is ambiguous — either a crash \
                 mid-write or targeted deletion. Investigate manually.",
                present, total),
            IntegrityError::ParentNotLoaded { block, parent } => write!(f,
                "block {} references selected_parent {} which was not \
                 persisted. The DAG store is incomplete — possible \
                 partial-write corruption.",
                hex::encode(&block[..8]), hex::encode(&parent[..8])),
            IntegrityError::MissingEntry { block } => write!(f,
                "block {} is in CF_DAG but has no integrity record in \
                 CF_DAG_INTEGRITY. A targeted deletion, or partial \
                 recovery from backup.",
                hex::encode(&block[..8])),
            IntegrityError::ChainMismatch { block, expected, stored } => write!(f,
                "integrity mismatch on block {}: expected {} but stored \
                 {}. The GhostdagData for this block, or for one of its \
                 ancestors, has been altered since it was written.",
                hex::encode(&block[..8]),
                hex::encode(&expected[..8]),
                hex::encode(&stored[..8])),
        }
    }
}

impl std::error::Error for IntegrityError {}

// ── DAG Store ────────────────────────────────────────────────────────────────

/// GhostDAG's tip order key: (blue_work, blue_score, hash), larger wins — the
/// order of `select_parent` and `selected_tip`.
type TipKey = (u128, u64, BlockHash);

/// The GhostDAG data of every stored block (`DagStore::data`).
///
/// Audit B1-T3 / B2-T5 (review): every whole-store iteration (`iter`,
/// `keys`, `values`, a `for` loop over `&map`) adds the number of stored
/// blocks to [`BlockDataMap::scanned`], which `GhostDAG::query_visits`
/// includes. So the served-request work test notices any remotely
/// triggerable path that scans the DAG — e.g. the old `ordered_hashes_from`,
/// which walked every entry and counted only what it returned — whatever
/// that path counts itself. Point reads (`get`, `contains_key`, `[h]`) are
/// not counted. Not consensus state.
#[derive(Default)]
pub struct BlockDataMap {
    map: HashMap<BlockHash, GhostdagData>,
    scanned: std::sync::atomic::AtomicU64,
}

impl BlockDataMap {
    fn note_scan(&self) {
        self.scanned.fetch_add(self.map.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Entries walked by whole-store iterations so far (monotonic).
    pub fn scanned(&self) -> u64 {
        self.scanned.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get(&self, hash: &BlockHash) -> Option<&GhostdagData> {
        self.map.get(hash)
    }

    pub fn contains_key(&self, hash: &BlockHash) -> bool {
        self.map.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Every entry (counted in [`Self::scanned`]).
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, BlockHash, GhostdagData> {
        self.note_scan();
        self.map.iter()
    }

    /// Every stored hash (counted in [`Self::scanned`]).
    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, BlockHash, GhostdagData> {
        self.note_scan();
        self.map.keys()
    }

    /// Every entry's data (counted in [`Self::scanned`]).
    pub fn values(&self) -> std::collections::hash_map::Values<'_, BlockHash, GhostdagData> {
        self.note_scan();
        self.map.values()
    }

    fn insert(&mut self, hash: BlockHash, data: GhostdagData) -> Option<GhostdagData> {
        self.map.insert(hash, data)
    }

    fn remove(&mut self, hash: &BlockHash) -> Option<GhostdagData> {
        self.map.remove(hash)
    }
}

impl std::ops::Index<&BlockHash> for BlockDataMap {
    type Output = GhostdagData;

    fn index(&self, hash: &BlockHash) -> &GhostdagData {
        &self.map[hash]
    }
}

impl<'a> IntoIterator for &'a BlockDataMap {
    type Item = (&'a BlockHash, &'a GhostdagData);
    type IntoIter = std::collections::hash_map::Iter<'a, BlockHash, GhostdagData>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// In-memory DAG — production would use RocksDB for this
///
/// `data`, `children` and `tips` are read by tests and tools; they are only
/// ever MUTATED through [`DagStore::insert`], [`DagStore::remove_leaf`] and
/// [`DagStore::set_tips`], which keep the two ordered indexes below in step.
pub struct DagStore {
    /// GhostDAG data per block (whole-store iterations are counted,
    /// [`BlockDataMap`])
    pub data: BlockDataMap,
    /// Children index: block → set of blocks that reference it as parent
    pub children: HashMap<BlockHash, HashSet<BlockHash>>,
    /// Current tips (leaf blocks with no children)
    pub tips: HashSet<BlockHash>,
    /// Genesis hash
    pub genesis: Option<BlockHash>,
    /// Audit B1-T3 / B2-T5: every stored block keyed by (blue_score, hash),
    /// so `GhostDAG::ordered_hashes_from` (the `/gnb/sync/1` GetHeaders
    /// answer) is a range read, O(log n + limit), instead of a scan of the
    /// whole store per request. Not consensus state (derived from `data`).
    by_score: BTreeSet<(u64, BlockHash)>,
    /// The tips ordered by GhostDAG's tip order ([`TipKey`]), so the
    /// selected tip and the best tips for peers (`GhostDAG::tips_for_peers`)
    /// are read from the top instead of scanning every leaf. Not consensus
    /// state (derived from `tips` and `data`).
    tips_by_work: BTreeSet<TipKey>,
}

impl Default for DagStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DagStore {
    pub fn new() -> Self {
        Self {
            data: BlockDataMap::default(),
            children: HashMap::new(),
            tips: HashSet::new(),
            genesis: None,
            by_score: BTreeSet::new(),
            tips_by_work: BTreeSet::new(),
        }
    }

    pub fn get(&self, hash: &BlockHash) -> Option<&GhostdagData> {
        BLOCK_DATA_LOOKUPS.with(|c| c.set(c.get().wrapping_add(1)));
        self.data.get(hash)
    }

    pub fn has(&self, hash: &BlockHash) -> bool {
        self.data.contains_key(hash)
    }

    fn tip_key(&self, hash: &BlockHash) -> Option<TipKey> {
        self.data.get(hash).map(|d| (d.blue_work, d.blue_score, *hash))
    }

    /// Mark a stored block as a tip (no-op for an unknown block).
    fn add_tip(&mut self, hash: BlockHash) {
        if let Some(k) = self.tip_key(&hash) {
            self.tips.insert(hash);
            self.tips_by_work.insert(k);
        }
    }

    /// Unmark a tip (its data must still be stored).
    fn remove_tip(&mut self, hash: &BlockHash) {
        if self.tips.remove(hash) {
            if let Some(k) = self.tip_key(hash) {
                self.tips_by_work.remove(&k);
            }
        }
    }

    pub fn insert(&mut self, hash: BlockHash, data: GhostdagData) {
        // A re-insert replaces the entry: drop its old index keys first.
        if self.data.contains_key(&hash) {
            self.remove_tip(&hash);
            if let Some(old) = self.data.get(&hash) {
                self.by_score.remove(&(old.blue_score, hash));
            }
        }
        // Remove parents from tips (they now have a child)
        for p in &data.parents {
            self.remove_tip(p);
            self.children.entry(*p).or_default().insert(hash);
        }
        self.by_score.insert((data.blue_score, hash));
        self.data.insert(hash, data);
        // This block is a new tip
        self.add_tip(hash);
    }

    /// Exact inverse of [`insert`](Self::insert) for a block without
    /// children: drops it, its index keys and its child edges; a parent
    /// becomes a tip again iff it is stored and has no child left. Returns
    /// the removed data (`None` when the block is unknown).
    fn remove_leaf(&mut self, hash: &BlockHash) -> Option<GhostdagData> {
        if !self.data.contains_key(hash) {
            return None;
        }
        self.remove_tip(hash);
        let data = self.data.remove(hash)?;
        self.by_score.remove(&(data.blue_score, *hash));
        self.children.remove(hash);
        for p in &data.parents {
            if let Some(ch) = self.children.get_mut(p) {
                ch.remove(hash);
                if ch.is_empty() {
                    self.children.remove(p);
                }
            }
            if self.data.contains_key(p) && self.children.get(p).is_none_or(|c| c.is_empty()) {
                self.add_tip(*p);
            }
        }
        Some(data)
    }

    /// Replace the tip set (start-up recomputation).
    fn set_tips(&mut self, tips: HashSet<BlockHash>) {
        self.tips_by_work = tips.iter().filter_map(|h| self.tip_key(h)).collect();
        self.tips = tips;
    }
}

// ── Reachability ─────────────────────────────────────────────────────────────

/// Check if `ancestor` is in the past of `descendant` (legacy, bounded).
///
/// Only the `Legacy` coloring path uses this; GnB colors every block with the
/// interval index (`CORRECTED_COLORING_ACTIVATION_HEIGHT = 0`), so it is not on
/// the live consensus path.
///
/// Audit DAG-8 fix: the old version short-circuited on
/// `ancestor.height >= descendant.height` and on blue_score, and pruned the
/// BFS below the ancestor's height. Neither the DAG height (selected-parent
/// based, see [`GhostdagData::height`]) nor blue_score is monotone along MERGE
/// edges, so both shortcuts returned false negatives for a merged ancestor
/// with a larger height / score than its descendant. The only quantity that is
/// monotone along EVERY parent edge is `blue_work`
/// (`child = selected_parent.blue_work + work`, and the selected parent has
/// the maximum blue_work among the parents), so `blue_work` is now the sole
/// shortcut and pruning bound. The visited-node safety cap stays (bounded
/// legacy semantics) and still warns when it truncates the search.
///
/// Production improvement: interval-based reachability tree (O(1)).
const MAX_REACHABILITY_DEPTH: u64 = 1024;

pub fn is_ancestor(
    store: &DagStore,
    ancestor: &BlockHash,
    descendant: &BlockHash,
) -> bool {
    if ancestor == descendant { return false; }

    let (a_work, d_work) = match (store.get(ancestor), store.get(descendant)) {
        (Some(a), Some(d)) => (a.blue_work, d.blue_work),
        _ => return false,
    };
    // Sound shortcut: blue_work never decreases along a parent edge, so an
    // ancestor can never carry MORE blue_work than its descendant.
    if a_work > d_work { return false; }

    // Bounded BFS from descendant backwards, pruning every block whose
    // blue_work is below the ancestor's (it cannot have the ancestor in its
    // past).
    let visit_cap = MAX_REACHABILITY_DEPTH * 10;
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(*descendant);
    let mut visits = 0u64;

    while let Some(h) = queue.pop_front() {
        if &h == ancestor { return true; }
        if visited.insert(h) {
            if let Some(d) = store.get(&h) {
                for p in &d.parents {
                    if visited.contains(p) { continue; }
                    let p_work = store.get(p).map(|pd| pd.blue_work).unwrap_or(0);
                    if p == ancestor || p_work >= a_work {
                        queue.push_back(*p);
                    }
                }
            }
        }
        visits += 1;
        if visits > visit_cap {
            warn!(
                "is_ancestor: visited-node cap {} hit when checking ancestor {} → \
                 descendant {}; ancestry check may return a false negative (legacy \
                 bounded path — the interval index is exact).",
                visit_cap, hex::encode(ancestor), hex::encode(descendant),
            );
            break;
        }
    }
    false
}

/// Compute past(B) — all ancestors of B (exclusive of B itself)
fn compute_past(store: &DagStore, b: &BlockHash) -> HashSet<BlockHash> {
    let mut past = HashSet::new();
    let mut queue = VecDeque::new();
    if let Some(data) = store.get(b) {
        for p in &data.parents {
            queue.push_back(*p);
        }
    }
    while let Some(h) = queue.pop_front() {
        if past.insert(h) {
            if let Some(data) = store.get(&h) {
                for p in &data.parents {
                    if !past.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
    }
    past
}

// ── Mergeset computation ──────────────────────────────────────────────────────

/// Compute mergeset(B, selected_parent):
/// All blocks in past(B) that are NOT in past(selected_parent) and not selected_parent itself.
/// These are blocks B "merges" by referencing parents other than selected_parent.
///
/// O(|past(selected_parent)|): kept as the fallback for a DAG whose
/// reachability index is not populated. `GhostDAG::compute_mergeset_bounded`
/// returns the identical list in O(|mergeset|) when the index is ready.
fn compute_mergeset(
    store: &DagStore,
    b_parents: &[BlockHash],
    selected_parent: &BlockHash,
) -> Vec<BlockHash> {
    let sp_past = compute_past(store, selected_parent);
    let mut mergeset_set: HashSet<BlockHash> = HashSet::new();

    // Collect all ancestors of non-selected parents that are not in sp_past
    for parent in b_parents {
        if parent == selected_parent { continue; }
        let mut queue = VecDeque::new();
        queue.push_back(*parent);
        while let Some(h) = queue.pop_front() {
            if !sp_past.contains(&h) && h != *selected_parent && mergeset_set.insert(h) {
                if let Some(data) = store.get(&h) {
                    for p in &data.parents {
                        if !sp_past.contains(p) && p != selected_parent {
                            queue.push_back(*p);
                        }
                    }
                }
            }
        }
    }

    // Topological sort of mergeset (ancestors before descendants)
    topological_sort(store, mergeset_set.into_iter().collect())
}

/// The coloring order of a mergeset (consensus, audit B2-T9; specified in
/// docs/CONSENSUS.md, "Coloring", executable in reference/gnb_ghostdag.py):
/// Kahn's algorithm with a FIFO queue. The in-degree of a block counts its
/// parents inside `blocks`; the queue starts with the blocks of in-degree 0
/// in ascending byte order of their ids; each block taken from the FRONT
/// appends the blocks it makes ready at the BACK, in ascending id order. It
/// is NOT "the lowest id among the blocks ready now": a block that becomes
/// ready later comes after every block already queued, whatever its id
/// (`node/tests/ghostdag_vectors.rs`, case `order/fifo-not-lowest-id`).
fn topological_sort(store: &DagStore, blocks: Vec<BlockHash>) -> Vec<BlockHash> {
    // Build in-degree map within this set
    let set: HashSet<BlockHash> = blocks.iter().cloned().collect();
    let mut in_degree: HashMap<BlockHash, usize> = HashMap::new();
    let mut reverse_deps: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();

    for &b in &blocks {
        in_degree.entry(b).or_insert(0);
        if let Some(data) = store.get(&b) {
            for p in &data.parents {
                if set.contains(p) {
                    *in_degree.entry(b).or_insert(0) += 1;
                    reverse_deps.entry(*p).or_default().push(b);
                }
            }
        }
    }

    let mut result = Vec::with_capacity(blocks.len());
    let mut queue: VecDeque<BlockHash> = in_degree.iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&h, _)| h)
        .collect();
    // Sort for determinism (break ties by hash)
    let mut sorted_start: Vec<BlockHash> = queue.drain(..).collect();
    sorted_start.sort_unstable();
    queue.extend(sorted_start);

    while let Some(b) = queue.pop_front() {
        result.push(b);
        if let Some(children) = reverse_deps.get(&b) {
            let mut next: Vec<BlockHash> = children.iter()
                .filter_map(|c| {
                    let deg = in_degree.get_mut(c)?;
                    *deg -= 1;
                    if *deg == 0 { Some(*c) } else { None }
                })
                .collect();
            next.sort_unstable();
            queue.extend(next);
        }
    }
    result
}

/// Deterministic topological order over persisted entries (DAG-5): every
/// entry comes after all of its parents that are present in `entries`; ties
/// are broken by (blue_score, hash). Parents absent from `entries` impose no
/// constraint. Cycles cannot occur in a hash-linked DAG; if the input were
/// cyclic anyway, the remaining entries are appended in (blue_score, hash)
/// order so nothing is silently dropped.
fn topological_entries(entries: Vec<(BlockHash, GhostdagData)>) -> Vec<(BlockHash, GhostdagData)> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let mut by_hash: HashMap<BlockHash, GhostdagData> = HashMap::with_capacity(entries.len());
    for (h, d) in entries {
        by_hash.insert(h, d);
    }
    let mut indegree: HashMap<BlockHash, usize> = HashMap::with_capacity(by_hash.len());
    let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
    for (h, d) in &by_hash {
        let mut deg = 0usize;
        let mut seen: HashSet<BlockHash> = HashSet::new();
        for p in &d.parents {
            if by_hash.contains_key(p) && seen.insert(*p) {
                deg += 1;
                children.entry(*p).or_default().push(*h);
            }
        }
        indegree.insert(*h, deg);
    }
    let mut ready: BinaryHeap<Reverse<(u64, BlockHash)>> = indegree.iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(h, _)| Reverse((by_hash[h].blue_score, *h)))
        .collect();
    let mut order: Vec<BlockHash> = Vec::with_capacity(by_hash.len());
    while let Some(Reverse((_, h))) = ready.pop() {
        order.push(h);
        if let Some(ch) = children.get(&h) {
            for c in ch {
                if let Some(deg) = indegree.get_mut(c) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        ready.push(Reverse((by_hash[c].blue_score, *c)));
                    }
                }
            }
        }
    }
    if order.len() < by_hash.len() {
        let placed: HashSet<BlockHash> = order.iter().copied().collect();
        let mut rest: Vec<(u64, BlockHash)> = by_hash.iter()
            .filter(|(h, _)| !placed.contains(*h))
            .map(|(h, d)| (d.blue_score, *h))
            .collect();
        rest.sort();
        order.extend(rest.into_iter().map(|(_, h)| h));
    }
    order.into_iter()
        .filter_map(|h| by_hash.remove(&h).map(|d| (h, d)))
        .collect()
}

// ── GhostDAG protocol ────────────────────────────────────────────────────────

/// Selects how `classify_mergeset` computes the blue/red partition.
///
/// # SAFETY / consensus status
///
/// `Legacy` is the byte-for-byte, currently-deployed mainnet-beta behavior:
/// bounded `is_ancestor` BFS + `k*100`-bounded `past_blue_set`. It is the
/// default for every live constructor and MUST stay the default until a
/// differential replay over the real ≥397k history proves `Fast` is
/// byte-identical.
///
/// `Fast` routes all ancestry queries through the interval reachability index
/// (`reachability::ReachabilityStore`), removing the bounded BFS. It is
/// **result-identical to `Legacy` on every DAG where the legacy bound never
/// bit**, and is exercised by `tests/ghostdag_differential.rs`. Where the two
/// diverge, the legacy (bug-compatible) answer is the consensus-correct one to
/// keep; adopting `Fast`'s answer there would be a FORK and requires an
/// activation-height gate.
///
/// (The two paragraphs above describe Bloch. On GnB the activation gate
/// [`CORRECTED_COLORING_ACTIVATION_HEIGHT`] is `0`, so a DAG built with the
/// `Legacy` constructor mode colors every block with `Fast`; the `Legacy`
/// coloring is never applied on the live path and stays in the code for the
/// replay/differential tests inherited from Bloch.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColoringMode {
    /// Bounded-BFS coloring (Bloch's deployed behavior). As a constructor
    /// mode it defers to the activation gate, which selects `Fast` for every
    /// height on GnB.
    Legacy,
    /// Interval-index-backed unbounded coloring: what GnB applies to every
    /// block. As a constructor mode, it bypasses the gate.
    Fast,
}

/// Activation height for the corrected (`Fast`) GhostDAG coloring.
///
/// # Current value on GnB: `0` — `Fast` from genesis
///
/// GnB is a new chain with no Legacy-colored history, so the gate is `0`: every
/// block, genesis included, is colored with the exact index-based `Fast`
/// coloring, and the reachability index is maintained from genesis. With the
/// value at `0` the gate comparison is always true; it is kept (written with
/// `Ord::cmp`, not `>=`, so that it is not an always-true comparison) so that
/// a future re-arming is a one-constant change. The passages below that
/// describe a `u64::MAX` ("disabled") gate or the `21_430` flag day are
/// history inherited from Bloch, not GnB's current state.
///
/// # TOKEN / HISTORY PRESERVATION — READ BEFORE CHANGING
///
/// This is a soft-fork-style activation gate. On the live path (`self.coloring
/// == Legacy`), a block at `height` is colored with:
///
/// ```text
/// if height >= CORRECTED_COLORING_ACTIVATION_HEIGHT { Fast } else { Legacy }
/// ```
///
/// **CORRECTED (was stale as of the original writing of this paragraph):**
/// this comment used to say the constant "defaults to `u64::MAX` = DISABLED"
/// and "changes ZERO live behavior". That was true only until WS-A
/// (2026-08-05) armed it — see the "Coordinated-release sentinel" and
/// "FLAG-DAY LOWERED" notes below, which were added at that time but never
/// reconciled against this paragraph. On Bloch the constant was `21_430`, not
/// `u64::MAX`, from the flag day, and roughly 46% of the Genesis-3 chain's
/// eventual terminal height (39,918, reached 2026-08-24) was mined AT OR
/// ABOVE this gate, i.e. under `Fast` coloring, not `Legacy`. Historical
/// blocks are never *recolored* after the fact regardless of where the gate
/// sits: they are loaded from CF_DAG verbatim (`load_persisted` /
/// `load_persisted_validated` insert stored data without recomputation), so
/// each block's coloring — decided once, at the height it was mined, by
/// comparing that height against whatever this constant was AT THE TIME — is
/// preserved unconditionally. "Preserved" here means "frozen as originally
/// computed", not "computed under `Legacy`".
///
/// ## Setting a real activation height (founder action only)
///
/// The value MUST be a **future** height, strictly greater than the current
/// chain tip at the moment of the coordinated upgrade, and MUST be adopted by
/// ALL nodes simultaneously (a soft-fork upgrade). Only blocks mined at or
/// above that future height are colored with `Fast`; every block below it keeps
/// its `Legacy` coloring, so no historical block is ever recomputed and no
/// reorg of history occurs.
///
/// Setting this to a height at or below the current tip is **FORBIDDEN**: it
/// would retroactively recolor already-mined blocks, which is a history reorg
/// that can change balances. Do not do it. The replay harness
/// (`tests/ghostdag_replay_snapshot.rs`) is the tool that first proves whether
/// `Fast` even differs from `Legacy` on real history; if it is byte-identical
/// everywhere, `Fast` is a transparent speedup and no activation is needed at
/// all.
///
/// ## Coordinated-release sentinel (Phase 3) — SUPERSEDED, see WS-A below
///
/// This paragraph originally left the value at `u64::MAX` =
/// `TBD_COORDINATED_RELEASE` and said "every live node stays byte-for-byte on
/// the `Legacy` coloring until this constant changes". That description is
/// **no longer current**: WS-A armed the gate at a real height (`21_430`,
/// later documented below) as exactly the coordinated soft-fork this
/// paragraph called for — all fleet nodes adopted the same future height
/// simultaneously, per this constant's own rule. The general principle still
/// holds for any FUTURE re-arming (a real height is a coordinated soft-fork
/// decision, never a code-review default, and the dev/test env override
/// `GNB_GHOSTDAG_COLORING=fast` remains node-local and not a substitute for
/// it); only the "still disabled" conclusion is stale.
///
/// WS-A (2026-08-05): armed to a FUTURE flag-day height. The replay-snapshot
/// proof (h18532) showed `Fast` is NOT byte-identical to `Legacy` — it diverges
/// only in the `blues_anticone_sizes` metadata field (Legacy's bounded seed
/// under-counts), with **zero** blue_score / mergeset / selected-chain / balance
/// changes. Adopting the exact `Fast` coloring is therefore a consensus change
/// and MUST be gated at a height ABOVE every already-mined block: history below
/// the gate keeps its Legacy `GhostdagData` (no reorg, no balance recompute) and
/// only blocks at/above the gate use the exact index-based coloring.
///
/// GnB: a new chain has no Legacy-colored history to preserve, so the exact
/// index-based (`Fast`) coloring applies from genesis. The Legacy path stays
/// in the code only for the replay/differential tests inherited from Bloch.
pub const CORRECTED_COLORING_ACTIVATION_HEIGHT: u64 = 0;

pub struct GhostDAG {
    pub k: usize,
    pub store: DagStore,
    /// Constructor coloring mode. Defaults to `Legacy`, which defers to the
    /// activation gate (`Fast` for every block on GnB, gate = 0).
    pub coloring: ColoringMode,
    /// Interval reachability index. Maintained whenever
    /// `maintains_reachability_index()` is true (always on GnB, gate = 0).
    /// Never consensus state.
    reach: ReachabilityStore,
    /// Hardening activation height (DAG-3/4/7): blocks with
    /// `GhostdagData::height >= hardening_activation` use the corrected rules.
    /// Fixed for the lifetime of the DAG (stored data is interpreted with it).
    hardening_activation: u64,
    /// Cache, never consensus state: PoW work of blocks at or above the
    /// activation (their own work is not recoverable from `GhostdagData` in
    /// O(1)). Missing entries are derived from the stored data; see `work_of`.
    block_work: HashMap<BlockHash, u128>,
    /// Cache, never consensus state, for blocks below the activation: the
    /// nearest block at or below the key on its selected chain whose
    /// `mergeset_blues` is non-empty (`None` = none down to genesis). Lets the
    /// pre-activation chain walk skip blocks that contribute nothing; a missing
    /// entry falls back to a plain one-step walk.
    merge_skip: HashMap<BlockHash, Option<BlockHash>>,
    /// Audit DAG-1: chain-disqualified blocks. A block is in this set iff it,
    /// or a block on its selected-parent chain, failed connect-time (UTXO /
    /// in-context) validation. The set is closed under "selected-parent
    /// child": `add_block` and `mark_invalid` keep that invariant. Such blocks
    /// stay in the DAG (they can still be merged as non-selected parents, which
    /// is what makes the outcome arrival-order independent) but are never
    /// returned by `selected_tip()` or offered as template parents. Persisted
    /// by the acceptance pipeline (`Storage::load_invalid_blocks`).
    invalid: HashSet<BlockHash>,
    /// PoWit finality pin (`finality`, node-local fork choice): the block,
    /// as (hash, DAG height), every selectable block's selected-parent chain
    /// passes through. A block whose selected-parent chain does not pass
    /// through it is never selected or offered as a template parent:
    /// finalized history is never rolled back. Computed from every stored
    /// block's PoWit state and the node's own finality
    /// ([`GhostDAG::compute_finality_pin`]).
    finalized: Option<(BlockHash, u64)>,
    /// Every finalized checkpoint the PoWit states of stored blocks carry,
    /// and the operator's finality settings (`finality`).
    finality: finality::FinalityIndex,
    /// Whether the persisted invalid set has been loaded into `invalid`
    /// (set by `load_invalid`). The acceptance pipeline loads it lazily on
    /// first use if start-up did not.
    invalid_loaded: bool,
    /// The roots of the PERSISTENT part of `invalid`: blocks passed to
    /// `mark_invalid` / `load_invalid` (a failure the block id commits to).
    invalid_roots: HashSet<BlockHash>,
    /// Roots whose disqualification spreads through EVERY parent edge, not
    /// only selected-parent edges: blocks stored by a pre-upgrade binary that
    /// fail the hardening block rules (no upgraded node ever stores them, so
    /// no block referencing them can be accepted anywhere else).
    invalid_all_edges_roots: HashSet<BlockHash>,
    /// Closure of `invalid_all_edges_roots` under "child" (any parent edge).
    /// A subset of `invalid`; `add_block` keeps it closed for later arrivals.
    invalid_all_edges: HashSet<BlockHash>,
    /// Bumped whenever the disqualification of blocks already in the DAG
    /// may change (`propagate_invalid`, `propagate_all_edges`,
    /// `recompute_invalid`; `add_block` and `remove_block` only change the
    /// block they add or remove, a leaf): the finality pin's cache keys on it
    /// (package O2, `finality::PinCache`).
    invalid_gen: u64,
    /// Blocks waiting for a (different) body, in memory only: their stored
    /// body failed a rule that depends on bytes the block id does not commit
    /// to (non-coinbase `script_sig`s below the hardening activation), or the
    /// body is missing. They are roots of `invalid` (with their selected-chain
    /// descendants) until a body that passes arrives, but the block id is not
    /// disqualified: nothing is persisted. The value lists the witness roots
    /// of the bodies already rejected for this id (most recent last, at most
    /// [`MAX_REJECTED_BODIES`]), so the same bad body is refused cheaply.
    /// Waiting is not wanting: a body is requested from peers, and a copy
    /// processed, only while [`is_body_wanted`](Self::is_body_wanted).
    body_pending: HashMap<BlockHash, Vec<[u8; 32]>>,
    /// Cache, never consensus state (audit DAG-7): the heaviest block seen by
    /// `(blue_work, blue_score, hash)`, validity ignored — the selected-tip
    /// hint that moves the reachability index's reindex root
    /// (`ReachabilityStore::hint_virtual_selected_parent`).
    reach_hint: Option<BlockHash>,
    /// Instrumentation, never consensus state: DAG entries touched by the
    /// read queries that peers can trigger remotely (`/gnb/sync/1` serving:
    /// `selected_chain`, `ordered_hashes_from`, `tips_for_peers`) and by
    /// `selected_tip`; `query_visits()` adds every whole-store iteration
    /// (`BlockDataMap::scanned`). Regression tests (audit B1-T3 / B2-T5)
    /// assert that the per-request count does not grow with the DAG size.
    query_visits: std::sync::atomic::AtomicU64,
    /// The body-pending blocks an operator override needs
    /// ([`request_body`](Self::request_body)): wanted whatever the weight of
    /// their chain, until a body arrives. A subset of `body_pending`'s keys.
    body_requested: HashSet<BlockHash>,
    /// Blocks parked without a verdict (review of audit F1, finding 2): their
    /// validation could not be completed (a read failure of the chain state,
    /// `accept`'s no-verdict guard). Like `body_pending`, roots of `invalid`
    /// (with their selected-chain descendants) in memory only, so the best
    /// chain the node CAN judge is selected and mined on meanwhile; nothing
    /// is persisted and the block keeps its body. The acceptance pipeline
    /// unparks a block when its retry is due.
    no_verdict: HashSet<BlockHash>,
    /// Instrumentation, never consensus state: how many times the
    /// disqualified set was re-derived from its roots (`recompute_invalid`,
    /// O(disqualified blocks) each). Regression tests bound it.
    invalid_recomputes: u64,
}

/// Rejected-body witness roots remembered per body-pending block.
pub const MAX_REJECTED_BODIES: usize = 8;

/// Result of [`GhostDAG::compute_block`]: everything `add_block` needs,
/// computed without mutating the DAG.
struct ComputedBlock {
    data: GhostdagData,
    selected_parent: BlockHash,
    /// Blues ∪ reds, i.e. the mergeset, for the reachability index.
    mergeset: Vec<BlockHash>,
    /// Work values derived while computing blue_work, worth caching.
    derived_work: HashMap<BlockHash, u128>,
}

impl GhostDAG {
    fn new_with(k: usize, coloring: ColoringMode, hardening_activation: u64) -> Self {
        Self {
            k,
            store: DagStore::new(),
            coloring,
            reach: ReachabilityStore::new(),
            hardening_activation,
            block_work: HashMap::new(),
            merge_skip: HashMap::new(),
            invalid: HashSet::new(),
            finalized: None,
            finality: finality::FinalityIndex::default(),
            invalid_loaded: false,
            invalid_roots: HashSet::new(),
            invalid_all_edges_roots: HashSet::new(),
            invalid_all_edges: HashSet::new(),
            invalid_gen: 0,
            body_pending: HashMap::new(),
            reach_hint: None,
            query_visits: std::sync::atomic::AtomicU64::new(0),
            body_requested: HashSet::new(),
            no_verdict: HashSet::new(),
            invalid_recomputes: 0,
        }
    }

    /// DAG entries touched so far by the remotely triggerable read queries
    /// (see the `query_visits` field). Monotonic; tests take differences.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn query_visits(&self) -> u64 {
        self.query_visits.load(std::sync::atomic::Ordering::Relaxed) + self.store.data.scanned()
    }

    fn note_visits(&self, n: u64) {
        self.query_visits.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn with_default_k() -> Self {
        Self::new_with(GHOSTDAG_K, ColoringMode::Legacy, activation::hardening_activation_height())
    }

    pub fn with_k(k: usize) -> Self {
        Self::new_with(k, ColoringMode::Legacy, activation::hardening_activation_height())
    }

    /// Test/benchmark constructor: same as `with_k` but selects the `Fast`
    /// (interval-index) coloring mode. NOT for live use — see [`ColoringMode`].
    pub fn with_k_fast(k: usize) -> Self {
        Self::new_with(k, ColoringMode::Fast, activation::hardening_activation_height())
    }

    /// Same as [`with_k`](Self::with_k) with an explicit hardening activation
    /// height: `0` applies the corrected rules from genesis,
    /// `activation::NEVER` (`u64::MAX`) keeps the old rules forever. The other
    /// constructors take the height from the node's chain id
    /// (`activation::hardening_activation_height`).
    pub fn with_k_and_activation(k: usize, activation_height: u64) -> Self {
        Self::new_with(k, ColoringMode::Legacy, activation_height)
    }

    /// Builder form: replace the hardening activation height. Must be called
    /// before any block is added, because stored data is interpreted with it.
    pub fn with_hardening_activation(mut self, activation_height: u64) -> Self {
        assert!(
            self.store.data.is_empty(),
            "the hardening activation height must be set before blocks are added"
        );
        self.hardening_activation = activation_height;
        self
    }

    /// The hardening activation height this DAG applies.
    pub fn hardening_activation_height(&self) -> u64 {
        self.hardening_activation
    }

    /// Whether a block at `height` (its `GhostdagData::height`) is processed
    /// under the corrected rules.
    pub fn is_hardened_at(&self, height: u64) -> bool {
        activation::is_active_at(height, self.hardening_activation)
    }

    /// Construct with the default K, honoring the **dev/test** coloring override.
    ///
    /// # Activation shape
    ///
    /// With no override set this is exactly [`with_default_k`]: the constructor
    /// mode is `Legacy`, and the live gate
    /// [`CORRECTED_COLORING_ACTIVATION_HEIGHT`] (`0` on GnB) then colors every
    /// block with `Fast` from genesis. The override below does not change
    /// which coloring a live node applies to any block; it only selects the
    /// `Fast` constructor mode directly.
    ///
    /// For local testing / replay ONLY, setting the env var
    /// `GNB_GHOSTDAG_COLORING=fast` selects the `Fast` interval-index coloring
    /// from genesis so an operator can exercise the durable index + rebuild on a
    /// throwaway datadir. This is a node-local switch — it colors THIS node's
    /// view and is NOT a network activation. Flipping the whole network to Fast
    /// is a coordinated soft-fork that sets a real future
    /// `CORRECTED_COLORING_ACTIVATION_HEIGHT`; the env override deliberately does
    /// not and cannot do that.
    pub fn with_default_k_env() -> Self {
        match Self::coloring_from_env() {
            ColoringMode::Fast => {
                log::warn!(
                    "GNB_GHOSTDAG_COLORING=fast — running the interval-index (Fast) \
                     coloring from genesis. DEV/TEST ONLY: this is a node-local view, \
                     NOT a network activation. Do not use on a shared/live datadir."
                );
                Self::with_k_fast(GHOSTDAG_K)
            }
            ColoringMode::Legacy => Self::with_default_k(),
        }
    }

    /// Read the dev/test coloring override. Defaults to `Legacy` for any unset /
    /// unrecognized value — the safe, live-preserving default.
    pub fn coloring_from_env() -> ColoringMode {
        match std::env::var("GNB_GHOSTDAG_COLORING") {
            Ok(v) if v.eq_ignore_ascii_case("fast") => ColoringMode::Fast,
            _ => ColoringMode::Legacy,
        }
    }

    /// Read-only handle to the reachability index (for tests/diagnostics).
    pub fn reachability(&self) -> &ReachabilityStore {
        &self.reach
    }

    /// The coloring mode that applies to a block at the given `height`.
    ///
    /// - `self.coloring == Fast` (test/replay constructor): always `Fast`.
    /// - `self.coloring == Legacy` (every live constructor): the
    ///   [`CORRECTED_COLORING_ACTIVATION_HEIGHT`] soft-fork gate decides — `Fast`
    ///   at/above the activation height, `Legacy` below it. On GnB the
    ///   activation height is `0`, so this is `Fast` for every height, genesis
    ///   included.
    fn effective_coloring(&self, height: u64) -> ColoringMode {
        match self.coloring {
            ColoringMode::Fast => ColoringMode::Fast,
            // `height >= CORRECTED_COLORING_ACTIVATION_HEIGHT`, spelled with
            // `cmp` because the constant is 0 and `>= 0` on a u64 is the
            // deny-level `clippy::absurd_extreme_comparisons`. Same result for
            // every height: only `Less` (impossible while the gate is 0)
            // selects Legacy.
            ColoringMode::Legacy => match height.cmp(&CORRECTED_COLORING_ACTIVATION_HEIGHT) {
                std::cmp::Ordering::Less => ColoringMode::Legacy,
                std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => ColoringMode::Fast,
            },
        }
    }

    /// Whether the reachability index must be maintained for this DAG.
    ///
    /// True when the DAG is a `Fast` constructor OR when the corrected-coloring
    /// activation gate is armed (any value other than `u64::MAX`) — in the
    /// armed case the index must be built from genesis so `Fast` classification
    /// is ready by the time the activation height is reached. On GnB the gate
    /// is `0`, so this is always `true`. Only a gate set to `u64::MAX`
    /// ("disabled", Bloch's pre-flag-day value, never used on GnB) with a
    /// `Legacy` DAG would leave the index untouched.
    pub fn maintains_reachability_index(&self) -> bool {
        self.coloring == ColoringMode::Fast
            || CORRECTED_COLORING_ACTIVATION_HEIGHT != u64::MAX
    }

    // ── Durable reachability index plumbing (Phase 1 / 2) ────────────────────

    /// Drain the pending reachability durability delta so the caller can fold it
    /// into the same atomic write as the block's CF_DAG entry. Empty unless the
    /// index is being maintained.
    pub fn reach_take_delta(&mut self) -> (Vec<(BlockHash, Vec<u8>)>, Vec<BlockHash>) {
        self.reach.take_persist_delta()
    }

    /// The pending reachability delta, NOT drained (audit DAG-11): stage it
    /// with the block's CF_DAG record and call
    /// [`reach_mark_persisted`](Self::reach_mark_persisted) once the batch has
    /// committed; a batch that fails leaves it pending.
    pub fn reach_peek_delta(&self) -> (Vec<(BlockHash, Vec<u8>)>, Vec<BlockHash>) {
        self.reach.peek_persist_delta()
    }

    /// Clear what a committed batch wrote from the pending reachability delta
    /// (see [`ReachabilityStore::mark_persisted`]).
    pub fn reach_mark_persisted(&mut self, upserts: &[(BlockHash, Vec<u8>)], deletes: &[BlockHash]) {
        self.reach.mark_persisted(upserts, deletes)
    }

    /// The current reachability root (genesis), for persisting the meta tag.
    pub fn reach_root(&self) -> Option<BlockHash> {
        self.reach.root()
    }

    /// Full snapshot of the reachability index for a one-batch rebuild write.
    pub fn reach_export_all(&self) -> Vec<(BlockHash, Vec<u8>)> {
        self.reach.export_all()
    }

    /// Load a persisted reachability index into memory (boot fast-path). The
    /// caller is responsible for having validated version + coverage first.
    pub fn reach_load_records(
        &mut self,
        records: &[(BlockHash, Vec<u8>)],
        root: Option<BlockHash>,
    ) -> Result<(), String> {
        self.reach.load_from_records(records, root)
    }

    /// Rebuild the reachability index from scratch by replaying the SAME
    /// `reach.add_block` code path over the in-memory DAG in topological order
    /// (parents strictly before children). Used by the boot migration when the
    /// persisted index is missing / version-mismatched / fails its self-check.
    /// Returns the number of blocks indexed. Leaves the delta pre-populated
    /// (every block dirty) so the caller can flush a full snapshot.
    pub fn rebuild_reachability_from_store(&mut self) -> Result<usize, String> {
        self.reach = ReachabilityStore::new();
        self.reach_hint = None;
        let order = self.topological_order()?;
        for h in &order {
            let d = self.store.get(h).ok_or_else(|| {
                format!("rebuild: block {} vanished from store", hex::encode(&h[..4]))
            })?;
            if d.parents.is_empty() {
                self.reach.add_genesis(*h);
            } else {
                let sp = d.selected_parent.ok_or_else(|| {
                    format!("rebuild: non-genesis {} has no selected parent", hex::encode(&h[..4]))
                })?;
                let mut mergeset = d.mergeset_blues.clone();
                mergeset.extend_from_slice(&d.mergeset_reds);
                self.reach.add_block(*h, &sp, &mergeset);
                // The replay moves the reindex root along, as live insertion
                // does (DAG-7).
                self.advance_reach_hint(*h);
            }
        }
        Ok(order.len())
    }

    /// Audit DAG-7: after `new` was added to the index, move the reindex root
    /// if `new` is the heaviest block seen (the selected-tip hint). Pure
    /// performance: no answer of the index depends on it.
    fn advance_reach_hint(&mut self, new: BlockHash) {
        if !self.maintains_reachability_index() || !self.reach.has(&new) {
            return;
        }
        let current = match self.reach_hint.filter(|h| self.store.has(h) && self.reach.has(h)) {
            Some(h) => h,
            // After a restart: the heaviest tip so far.
            None => match self.store.tips.iter().copied()
                .filter(|t| self.reach.has(t))
                .max_by_key(|t| self.order_key(t))
            {
                Some(t) => t,
                None => new,
            },
        };
        let hint = if self.order_key(&new) > self.order_key(&current) { new } else { current };
        let moved = self.reach_hint != Some(hint);
        self.reach_hint = Some(hint);
        if moved {
            self.reach.hint_virtual_selected_parent(&hint);
        }
    }

    /// Kahn topological sort of the in-memory DAG: every parent strictly
    /// precedes its children, so a downstream `reach.add_block` always finds its
    /// selected parent and all mergeset members already indexed. Ties broken by
    /// (blue_score, height, hash) for determinism. `Err` if the store is not a
    /// DAG or references an absent parent.
    fn topological_order(&self) -> Result<Vec<BlockHash>, String> {
        let mut indegree: HashMap<BlockHash, usize> = HashMap::new();
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        for h in self.store.data.keys() {
            indegree.entry(*h).or_insert(0);
        }
        for (h, d) in &self.store.data {
            for p in &d.parents {
                if !self.store.data.contains_key(p) {
                    return Err(format!(
                        "block {} references parent {} absent from store",
                        hex::encode(&h[..4]), hex::encode(&p[..4])
                    ));
                }
                // `h` is a key of `self.store.data`, and every such key was
                // seeded into `indegree` above, so this lookup is infallible.
                // Return an error instead of panicking to keep this consensus
                // path fail-closed rather than aborting the node (DoS).
                *indegree
                    .get_mut(h)
                    .ok_or_else(|| format!("indegree missing {}", hex::encode(&h[..4])))? += 1;
                children.entry(*p).or_default().push(*h);
            }
        }
        let key = |h: &BlockHash| {
            let d = &self.store.data[h];
            (d.blue_score, d.height, *h)
        };
        let mut ready: Vec<BlockHash> = indegree.iter()
            .filter(|(_, &deg)| deg == 0).map(|(h, _)| *h).collect();
        ready.sort_by_key(key);
        let mut queue: VecDeque<BlockHash> = ready.into_iter().collect();
        let mut out = Vec::with_capacity(self.store.data.len());
        while let Some(h) = queue.pop_front() {
            out.push(h);
            if let Some(ch) = children.get(&h) {
                let mut newly = Vec::new();
                for c in ch {
                    // `c` is a child recorded from a parent edge whose endpoint
                    // is a store key, so it is always present in `indegree`.
                    // Fail-closed (error) rather than panic on the impossible
                    // branch.
                    let deg = indegree
                        .get_mut(c)
                        .ok_or_else(|| format!("indegree missing child {}", hex::encode(&c[..4])))?;
                    *deg -= 1;
                    if *deg == 0 { newly.push(*c); }
                }
                if !newly.is_empty() {
                    let mut rest: Vec<BlockHash> = queue.drain(..).collect();
                    rest.extend(newly);
                    rest.sort_by_key(key);
                    queue = rest.into_iter().collect();
                }
            }
        }
        if out.len() != self.store.data.len() {
            return Err(format!(
                "topological sort visited {}/{} blocks — parent graph has a cycle",
                out.len(), self.store.data.len()
            ));
        }
        Ok(out)
    }

    /// Random-sample self-check of the reachability index against the unbounded
    /// brute-force oracle over the raw parent graph. Draws `samples` random
    /// ordered block pairs with the given `seed` and returns `Err` on the first
    /// disagreement. A cheap boot-time guard that a loaded/rebuilt index is not
    /// silently mis-labeled before it is trusted for classification.
    pub fn reach_self_check_sample(&self, samples: usize, seed: u64) -> Result<usize, String> {
        let blocks: Vec<BlockHash> = self.store.data.keys().copied().collect();
        if blocks.len() < 2 {
            return Ok(0);
        }
        let mut state = seed | 1;
        let mut next = || {
            state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        let n = blocks.len();
        let mut checked = 0usize;
        for _ in 0..samples {
            let a = blocks[(next() as usize) % n];
            let b = blocks[(next() as usize) % n];
            if a == b { continue; }
            let idx = self.reach.is_dag_ancestor(&a, &b);
            let oracle = reachability::brute_force_is_ancestor(&self.store, &a, &b);
            if idx != oracle {
                return Err(format!(
                    "reachability self-check MISMATCH: is_ancestor({},{}) index={} oracle={}",
                    hex::encode(&a[..4]), hex::encode(&b[..4]), idx, oracle
                ));
            }
            checked += 1;
        }
        Ok(checked)
    }

    /// Add genesis block
    pub fn add_genesis(&mut self, hash: BlockHash, timestamp: u64) {
        let data = GhostdagData {
            blue_score: 0,
            blue_work: 0,
            selected_parent: None,
            mergeset_blues: vec![],
            mergeset_reds: vec![],
            blues_anticone_sizes: HashMap::new(),
            parents: vec![],
            height: 0,
            timestamp,
        };
        self.store.genesis = Some(hash);
        if self.maintains_reachability_index() {
            self.reach.add_genesis(hash);
        }
        self.store.insert(hash, data);
    }

    /// Reconstruct DAG from persisted GhostdagData entries.
    ///
    /// Audit DAG-5 fix: entries used to be inserted in blue_score order, which
    /// is NOT topological for non-selected parents (a merged parent can carry
    /// a larger blue_score than its child). `DagStore::insert` marks every new
    /// block as a tip, so a parent inserted after its child came back as a tip
    /// after every restart (redundant template parents, tip sets that differ
    /// between nodes). Entries are now inserted in a deterministic topological
    /// order and the tip set is recomputed from the children index afterwards.
    /// The stored GhostDAG data is inserted verbatim (no recomputation).
    pub fn load_persisted(&mut self, entries: Vec<(BlockHash, GhostdagData)>) {
        for (hash, data) in topological_entries(entries) {
            if data.parents.is_empty() {
                // Genesis
                self.store.genesis = Some(hash);
            }
            self.store.insert(hash, data);
        }
        self.recompute_tips();
    }

    /// Recompute `tips` as exactly the stored blocks without children.
    fn recompute_tips(&mut self) {
        let tips: HashSet<BlockHash> = self.store.data.keys()
            .filter(|h| self.store.children.get(*h).map_or(true, |c| c.is_empty()))
            .copied()
            .collect();
        self.store.set_tips(tips);
    }

    /// Sprint Y (M-2): verified variant of `load_persisted`.
    ///
    /// Same behavior as `load_persisted` on the happy path, but validates
    /// an integrity hash-chain over GhostdagData before inserting anything
    /// into the in-memory DAG. Detects three concrete tampering patterns:
    ///
    ///   * Silent RocksDB corruption (bit flip, bad hardware): any field
    ///     mutation changes the recomputed hash.
    ///   * Adversary with disk access altering `blue_score`,
    ///     `mergeset_blues`, or other consensus-critical fields.
    ///   * Downgrade attack: swapping CF_DAG contents with a competing
    ///     chain's data. The parent chain link breaks unless the attacker
    ///     also forges every ancestor back to genesis.
    ///
    /// Returns `Ok(n)` where n is the number of blocks loaded. `Err` on
    /// any mismatch — the caller is expected to treat this as fatal.
    ///
    /// `integrity_map` is `Option<[u8; 32]>` per block: `None` means
    /// the integrity record was missing from CF_DAG_INTEGRITY. If ALL
    /// records are missing, the function self-heals by computing and
    /// returning the fresh integrity map to the caller (to be persisted).
    /// Mixed presence (some present, some missing) is treated as an
    /// error — the attacker may have deleted specific records.
    pub fn load_persisted_validated(
        &mut self,
        entries: Vec<(BlockHash, GhostdagData)>,
        integrity_map: std::collections::HashMap<BlockHash, [u8; 32]>,
    ) -> Result<LoadedIntegrity, IntegrityError> {
        let total = entries.len();
        let integrity_count = integrity_map.len();

        // All-or-nothing for the migration path. Mixed state is suspicious.
        let self_heal = if integrity_count == 0 {
            true
        } else if integrity_count == total {
            false
        } else {
            return Err(IntegrityError::PartialCoverage {
                present: integrity_count,
                total,
            });
        };

        // Topological order (parents before children, DAG-5) — load-bearing
        // for the chain check: the selected parent's integrity hash must be
        // computed before the child is validated.
        let sorted = topological_entries(entries);

        let mut computed: std::collections::HashMap<BlockHash, [u8; 32]> =
            std::collections::HashMap::with_capacity(sorted.len());

        for (hash, data) in &sorted {
            let parent_integrity = match &data.selected_parent {
                Some(sp) => *computed.get(sp).ok_or_else(|| {
                    // This should never trip if blue_score ordering holds
                    // and the DAG is well-formed. If it does, the stored
                    // GhostdagData references a parent that was not
                    // persisted — corruption or a partial write mid-crash.
                    IntegrityError::ParentNotLoaded {
                        block: *hash,
                        parent: *sp,
                    }
                })?,
                None => [0u8; 32], // Genesis: no parent link.
            };

            let expected = compute_integrity_hash(hash, data, &parent_integrity);

            if !self_heal {
                let stored = integrity_map.get(hash).ok_or_else(|| {
                    IntegrityError::MissingEntry { block: *hash }
                })?;
                if stored != &expected {
                    return Err(IntegrityError::ChainMismatch {
                        block: *hash,
                        expected,
                        stored: *stored,
                    });
                }
            }

            computed.insert(*hash, expected);
        }

        // All checks passed (or self-heal, which is also OK). Now the
        // in-memory insertion, identical to load_persisted's loop.
        for (hash, data) in sorted {
            if data.parents.is_empty() {
                self.store.genesis = Some(hash);
            }
            self.store.insert(hash, data);
        }
        self.recompute_tips();

        Ok(LoadedIntegrity {
            blocks_loaded: total,
            self_healed:   self_heal,
            fresh_map:     if self_heal { Some(computed) } else { None },
        })
    }

    /// Load persisted entries whose integrity chain does NOT verify, repairing
    /// what the pre-fix binary left behind (audit DAG-11), instead of refusing
    /// to start. The pre-fix commit wrote a block's CF_DAG record and
    /// integrity link with `.ok()`-ignored errors and zero-filled a missing
    /// parent link, so a node that lost one DAG write kept running and stored
    /// descendants chaining to a missing record or a zero link;
    /// [`load_persisted_validated`](Self::load_persisted_validated) then fails
    /// (`ParentNotLoaded`, `ChainMismatch`, `PartialCoverage`, `MissingEntry`).
    ///
    /// Blocks are processed in a topological order (parents first), and each
    /// one's data is decided as follows:
    ///
    /// * the stored integrity matches the chain link re-derived from its
    ///   selected parent: kept as is;
    /// * otherwise, if the stored record is consistent with its OWN integrity
    ///   hash (linked to the selected parent's STORED integrity, or to the
    ///   pre-fix zero link), or has no integrity record at all: the stored
    ///   data are kept and only the link is re-derived (`relinked`). The data
    ///   were computed by the node when the block arrived; recomputing them
    ///   could only disagree with the history the network holds;
    /// * otherwise (no record: a lost write; or a record that matches no link:
    ///   corrupted), the data are recomputed with the consensus code from the
    ///   block's stored header (`header_of`), whose parents, timestamp and
    ///   bits the proof of work commits to (`recomputed`);
    /// * with no header to recompute from, or a parent that could not be
    ///   loaded, the block and every block that descends from it are dropped
    ///   (`dropped`): the node fetches them again from its peers.
    ///
    /// The DAG must be empty. The reachability index is rebuilt alongside;
    /// the caller persists the repair (`Storage::stage_dag_repair`), which
    /// also makes the next start rebuild the persisted index.
    pub fn load_persisted_repairing<F>(
        &mut self,
        entries: Vec<(BlockHash, GhostdagData)>,
        integrity_map: HashMap<BlockHash, [u8; 32]>,
        header_of: F,
    ) -> Result<DagRepair, String>
    where
        F: Fn(&BlockHash) -> Option<StoredHeader>,
    {
        if !self.store.data.is_empty() {
            return Err("load_persisted_repairing needs an empty DAG".into());
        }
        let records: HashMap<BlockHash, GhostdagData> = entries.into_iter().collect();
        // Blocks referenced as parents without a record (lost writes), and
        // their own record-less ancestors, recoverable from their headers.
        let mut headers: HashMap<BlockHash, StoredHeader> = HashMap::new();
        let mut stack: Vec<BlockHash> = records.values()
            .flat_map(|d| d.parents.iter().copied())
            .filter(|p| !records.contains_key(p))
            .collect();
        while let Some(p) = stack.pop() {
            if records.contains_key(&p) || headers.contains_key(&p) {
                continue;
            }
            if let Some(h) = header_of(&p) {
                stack.extend(h.parents.iter().copied().filter(|q| !records.contains_key(q)));
                headers.insert(p, h);
            }
        }
        // Kahn order over records ∪ recoverable headers (ties by id).
        let parents_of = |h: &BlockHash| -> Vec<BlockHash> {
            let ps = match records.get(h) {
                Some(d) => d.parents.clone(),
                None => headers.get(h).map(|x| x.parents.clone()).unwrap_or_default(),
            };
            let mut seen = HashSet::new();
            ps.into_iter().filter(|p| seen.insert(*p)).collect()
        };
        let universe: Vec<BlockHash> = records.keys().chain(headers.keys()).copied().collect();
        let known: HashSet<BlockHash> = universe.iter().copied().collect();
        let mut indegree: HashMap<BlockHash, usize> = HashMap::new();
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        for h in &universe {
            let ps: Vec<BlockHash> = parents_of(h).into_iter().filter(|p| known.contains(p)).collect();
            indegree.insert(*h, ps.len());
            for p in ps {
                children.entry(p).or_default().push(*h);
            }
        }
        let mut ready: std::collections::BTreeSet<BlockHash> =
            indegree.iter().filter(|(_, d)| **d == 0).map(|(h, _)| *h).collect();
        let mut order = Vec::with_capacity(universe.len());
        while let Some(h) = ready.pop_first() {
            order.push(h);
            for c in children.get(&h).cloned().unwrap_or_default() {
                if let Some(d) = indegree.get_mut(&c) {
                    *d -= 1;
                    if *d == 0 {
                        ready.insert(c);
                    }
                }
            }
        }

        let mut rep = DagRepair::default();
        self.reach = ReachabilityStore::new();
        let index = self.maintains_reachability_index();
        for h in order {
            let parents = parents_of(&h);
            if parents.iter().any(|p| !self.store.has(p)) {
                rep.dropped.push(h);
                continue;
            }
            let link = |sp: &Option<BlockHash>, integ: &HashMap<BlockHash, [u8; 32]>| -> Option<[u8; 32]> {
                match sp {
                    None => Some([0u8; 32]),
                    Some(s) => integ.get(s).copied(),
                }
            };
            let stored = records.get(&h);
            let stored_int = integrity_map.get(&h);
            let mut decided: Option<GhostdagData> = None;
            if let Some(d) = stored {
                let chained = link(&d.selected_parent, &rep.integrity)
                    .map(|l| compute_integrity_hash(&h, d, &l));
                if chained.is_some() && stored_int == chained.as_ref() {
                    decided = Some(d.clone());
                } else {
                    let self_consistent = match stored_int {
                        None => true,
                        Some(si) => {
                            *si == compute_integrity_hash(&h, d, &[0u8; 32])
                                || link(&d.selected_parent, &integrity_map)
                                    .is_some_and(|l| *si == compute_integrity_hash(&h, d, &l))
                        }
                    };
                    let sp_loaded = d.selected_parent.is_none_or(|s| self.store.has(&s));
                    if self_consistent && sp_loaded {
                        rep.relinked.push(h);
                        decided = Some(d.clone());
                    }
                }
            }
            let data = match decided {
                Some(d) => d,
                None => match header_of(&h) {
                    Some(hdr) if hdr.parents.is_empty() => {
                        let d = GhostdagData { timestamp: hdr.timestamp, ..GhostdagData::genesis() };
                        rep.recomputed.push((h, d.clone()));
                        d
                    }
                    Some(hdr) if hdr.parents.iter().all(|p| self.store.has(p)) => {
                        match self.compute_block(&hdr.parents, hdr.timestamp, hdr.work) {
                            Ok(c) => {
                                rep.recomputed.push((h, c.data.clone()));
                                c.data
                            }
                            Err(_) => {
                                rep.dropped.push(h);
                                continue;
                            }
                        }
                    }
                    _ => {
                        rep.dropped.push(h);
                        continue;
                    }
                },
            };
            let parent_link = link(&data.selected_parent, &rep.integrity).unwrap_or([0u8; 32]);
            rep.integrity.insert(h, compute_integrity_hash(&h, &data, &parent_link));
            if index {
                match data.selected_parent {
                    None => self.reach.add_genesis(h),
                    Some(sp) => {
                        let mut mergeset = data.mergeset_blues.clone();
                        mergeset.extend_from_slice(&data.mergeset_reds);
                        self.reach.add_block(h, &sp, &mergeset);
                    }
                }
            }
            if data.parents.is_empty() {
                self.store.genesis = Some(h);
            }
            self.store.insert(h, data);
            rep.blocks_loaded += 1;
        }
        self.recompute_tips();
        // The caller makes the next start rebuild the persisted index.
        let _ = self.reach.take_persist_delta();
        Ok(rep)
    }

    /// Add a new block and compute its full GhostDAG data.
    /// Returns the computed GhostdagData on success.
    ///
    /// Audit M-9 fix: previously used `assert!` for the two preconditions,
    /// which panicked the whole node if an invalid block slipped past
    /// upstream validation (gossipsub, accept_block, etc). Now returns
    /// a `ConsensusError` variant so callers can reject the block
    /// cleanly without tearing down the process.
    ///
    /// Hardening (DAG-3/4/7): a block whose height (`selected_parent.height +
    /// 1`) is at or above [`hardening_activation_height`](Self::hardening_activation_height)
    /// is colored with the exact GHOSTDAG rule, gets Kaspa blue work, and is
    /// rejected with [`ConsensusError::MergesetTooLarge`] or
    /// [`ConsensusError::MergeDepthViolation`] when it breaks the new limits.
    /// Below that height the result is bit-identical to the old code. Nothing
    /// is mutated when an error is returned.
    pub fn add_block(
        &mut self,
        hash: BlockHash,
        parents: Vec<BlockHash>,
        timestamp: u64,
        work: u128,  // PoW work of this block (difficulty)
    ) -> Result<GhostdagData, ConsensusError> {
        if parents.is_empty() {
            return Err(ConsensusError::NoParents);
        }
        if self.store.has(&hash) {
            return Err(ConsensusError::DuplicateBlock(hash));
        }

        // Warm the pre-activation skip cache for the selected chain (pure
        // performance; `compute_block` gives the same answer without it).
        let selected_parent = self.select_parent(&parents);
        let sp_height = self.store.get(&selected_parent).map(|d| d.height);
        let hardened = matches!(sp_height, Some(h) if self.is_hardened_at(h + 1));
        if sp_height.is_some() && !hardened {
            self.ensure_merge_skip(&selected_parent);
        }

        let ComputedBlock { data, selected_parent, mergeset, derived_work } =
            self.compute_block(&parents, timestamp, work)?;

        // Maintain the reachability index (Fast mode only). Register `hash`
        // now, after classification, before it is inserted into the store — so
        // subsequent blocks can query its ancestry.
        if self.maintains_reachability_index() {
            self.reach.add_block(hash, &selected_parent, &mergeset);
        }

        // Non-consensus caches.
        self.block_work.extend(derived_work);
        if hardened {
            self.block_work.insert(hash, work);
        } else if !data.mergeset_blues.is_empty() {
            self.merge_skip.insert(hash, Some(hash));
        } else if let Some(below) = self.merge_skip.get(&selected_parent).copied() {
            self.merge_skip.insert(hash, below);
        }

        let result = data.clone();
        self.store.insert(hash, data);
        // DAG-7: keep the reachability index's reindex root behind the tip.
        self.advance_reach_hint(hash);
        // DAG-1: a block whose selected parent is chain-disqualified is
        // itself disqualified (its UTXO context does not exist). It still
        // enters the DAG so other blocks can merge it deterministically.
        if self.invalid.contains(&selected_parent) {
            self.invalid.insert(hash);
        }
        // A block referencing (through any parent edge) a block that fails
        // the hardening block rules can never be accepted by an upgraded node
        // that never stored that parent: same treatment.
        if result.parents.iter().any(|p| self.invalid_all_edges.contains(p)) {
            self.invalid_all_edges.insert(hash);
            self.invalid.insert(hash);
        }
        Ok(result)
    }

    /// Compute a block's `GhostdagData` from its parents without touching the
    /// DAG. Shared by [`add_block`](Self::add_block) and
    /// [`select_parents_for_template`](Self::select_parents_for_template), so a
    /// template is checked with exactly the consensus code.
    fn compute_block(
        &self,
        parents: &[BlockHash],
        timestamp: u64,
        work: u128,
    ) -> Result<ComputedBlock, ConsensusError> {
        COMPUTE_BLOCK_CALLS.with(|c| c.set(c.get().wrapping_add(1)));
        if parents.is_empty() {
            return Err(ConsensusError::NoParents);
        }

        // 1. Select parent: argmax blue_score, tie-break by hash (lexicographic)
        let selected_parent = self.select_parent(parents);

        // The selected parent must be present in the store. A block whose
        // selected parent is absent is an orphan the sync layer should have
        // buffered; reaching here means it slipped past upstream validation.
        // Reject cleanly rather than panic (completes Audit M-9 — previously a
        // `.expect()` here, inconsistent with the tolerant lookups elsewhere).
        let sp_data = self.store.get(&selected_parent)
            .ok_or(ConsensusError::MissingSelectedParent(selected_parent))?;

        // 2. Compute height from the (now validated) selected parent. This is
        //    the DAG height (selected parent + 1). The difficulty and
        //    `block.height` rule uses max(parent heights) + 1 over these stored
        //    heights instead (docs/CONSENSUS.md, "Difficulty input").
        let height = sp_data.height + 1;
        let hardened = self.is_hardened_at(height);
        let use_index = self.ancestry_index_ready(parents, &selected_parent);

        // 3. Compute mergeset (topologically sorted, ancestors first). The
        //    index-based walk returns the same list as the O(past) one.
        //    MERGESET_SIZE_LIMIT (64, this chain's rule at every height) is
        //    tighter than the audit's hardened MAX_MERGESET_SIZE - 1, so it
        //    is the limit on both sides of the activation.
        let limit = Some(MERGESET_SIZE_LIMIT.min(MAX_MERGESET_SIZE - 1));
        let mergeset = if use_index {
            self.compute_mergeset_bounded(parents, &selected_parent, limit)?
        } else {
            let m = compute_mergeset(&self.store, parents, &selected_parent);
            if let Some(limit) = limit {
                if m.len() > limit {
                    return Err(ConsensusError::MergesetTooLarge { limit: MERGESET_SIZE_LIMIT });
                }
            }
            m
        };

        // 4. Classify mergeset blocks as blue or red using PHANTOM constraint.
        //    In Fast mode the reachability index must contain every existing
        //    block before classification queries it; the index is maintained
        //    incrementally, so it already does. `hash` itself is not queried
        //    during its own classification, so we register it afterwards.
        //    Below the hardening activation the coloring is chosen by the
        //    height-gated `effective_coloring`, exactly as before (Legacy below
        //    CORRECTED_COLORING_ACTIVATION_HEIGHT, Fast at/above it). At or
        //    above the hardening activation the exact GHOSTDAG coloring applies.
        let (mergeset_blues, mergeset_reds, blues_anticone_sizes) = if hardened {
            self.classify_mergeset_exact(&mergeset, &selected_parent, use_index)
        } else {
            match self.effective_coloring(height) {
                ColoringMode::Legacy => self.classify_mergeset(&mergeset, &selected_parent),
                ColoringMode::Fast => self.classify_mergeset_fast(&mergeset, &selected_parent),
            }
        };

        // 5. Compute blue_score and blue_work
        let blue_score = sp_data.blue_score + mergeset_blues.len() as u64 + 1;
        let mut derived_work = HashMap::new();
        let blue_work = if hardened {
            // DAG-3: Kaspa blue work. sp.blue_work already counts the selected
            // parent's own work, so adding every mergeset blue and this block's
            // work makes blue_work(B) the total work of blue(B) ∪ {B}.
            let merged: u128 = mergeset_blues
                .iter()
                .map(|m| self.work_of(m, &mut derived_work))
                .sum();
            sp_data.blue_work + merged + work
        } else {
            // Pre-activation rule: cumulative PoW along the selected chain plus
            // this block's work; merged blues add nothing.
            sp_data.blue_work + work
        };

        // 6. Merge depth (DAG-7), at or above the activation only.
        if hardened && !mergeset_reds.is_empty() {
            self.check_merge_depth(&selected_parent, blue_score, &mergeset_blues, &mergeset_reds, use_index)?;
        }

        let data = GhostdagData {
            blue_score,
            blue_work,
            selected_parent: Some(selected_parent),
            mergeset_blues,
            mergeset_reds,
            blues_anticone_sizes,
            parents: parents.to_vec(),
            height,
            timestamp,
        };
        Ok(ComputedBlock { data, selected_parent, mergeset, derived_work })
    }

    /// Remove a just-added LEAF block, exactly inverting `DagStore::insert`.
    ///
    /// CONSENSUS-HALT FIX (DAG-vs-UTXO ordering): `accept_block` inserts a
    /// block into the DAG *before* it knows whether the reorg the block
    /// triggers will be accepted. When `reorg::execute_reorg` REFUSES the
    /// plan (depth cap) the UTXO store is untouched — but without an undo,
    /// `selected_tip()` has already permanently adopted the fork tip, so
    /// every later legitimate extension of the real chain is misclassified
    /// as a fork-loser: a durable consensus halt. This method lets the
    /// accept path roll the in-memory insertion back on a refused/failed
    /// disposition (the CF_DAG persist is deferred until after success, see
    /// `accept_block` in main.rs).
    ///
    /// Guards — all return `false` with NO mutation:
    ///   * `hash` is not in the store,
    ///   * `hash` is genesis,
    ///   * `hash` has children (only leaf/tip blocks are safely removable;
    ///     removing an interior block would corrupt descendants' GhostDAG
    ///     data — the accept path only ever removes the block it just added).
    ///
    /// Returns `true` when the block was removed and each parent regained
    /// tip status iff it no longer has any remaining children.
    pub fn remove_block(&mut self, hash: &BlockHash) -> bool {
        if self.store.genesis == Some(*hash) {
            return false;
        }
        if self.store.children.get(hash).map_or(false, |c| !c.is_empty()) {
            return false;
        }
        // Exact inverse of `DagStore::insert` (its indexes included): drop
        // the child edge from each parent; a parent becomes a tip again iff
        // it is still stored and now has no children at all.
        let data = match self.store.remove_leaf(hash) {
            Some(d) => d,
            None => return false,
        };
        // Keep the reachability index consistent (Fast mode only). The mergeset
        // used at insert time is recoverable as blues ∪ reds.
        if self.maintains_reachability_index() {
            let mut mergeset = data.mergeset_blues.clone();
            mergeset.extend_from_slice(&data.mergeset_reds);
            self.reach.remove_leaf(hash, &mergeset);
        }
        // Drop the non-consensus caches for this block. A leaf is nobody's
        // selected parent and nobody's merged blue, so no other entry refers
        // to it.
        self.block_work.remove(hash);
        self.merge_skip.remove(hash);
        self.invalid.remove(hash);
        self.invalid_roots.remove(hash);
        self.invalid_all_edges_roots.remove(hash);
        self.invalid_all_edges.remove(hash);
        self.body_pending.remove(hash);
        self.body_requested.remove(hash);
        self.forget_finality_source(hash);
        self.no_verdict.remove(hash);
        if self.reach_hint == Some(*hash) {
            self.reach_hint = None;
        }
        true
    }

    /// The selected parent a block with `parents` WILL get when inserted —
    /// the same rule `add_block` applies. Used to validate a block's
    /// transactions against the right state before it is inserted.
    /// `None` when `parents` is empty.
    pub fn preview_selected_parent(&self, parents: &[BlockHash]) -> Option<BlockHash> {
        if parents.is_empty() { return None; }
        Some(self.select_parent(parents))
    }

    /// Select parent with highest blue_work (heaviest chain).
    /// Tie-break: blue_score, then hash (lexicographic, deterministic).
    fn select_parent(&self, parents: &[BlockHash]) -> BlockHash {
        *parents.iter().max_by(|a, b| {
            let da = self.store.get(*a);
            let db = self.store.get(*b);
            let work_a = da.map(|d| d.blue_work).unwrap_or(0);
            let work_b = db.map(|d| d.blue_work).unwrap_or(0);
            let score_a = da.map(|d| d.blue_score).unwrap_or(0);
            let score_b = db.map(|d| d.blue_score).unwrap_or(0);
            work_a.cmp(&work_b)
                .then(score_a.cmp(&score_b))
                .then(a.cmp(b))
        }).expect("parents non-empty")
    }

    /// The block GhostDAG ranks heaviest among `blocks`, in the order of
    /// parent selection (highest blue_work, then blue_score, then hash),
    /// considering only the blocks this DAG holds; `None` when it holds none
    /// of them. Validity plays no part: a chain-disqualified block ranks like
    /// any other. A block ranks strictly above each of its parents (its
    /// blue_work is at least its selected parent's, its blue_score larger),
    /// so among blocks that are all ancestors of one block B (B included),
    /// this is B. Start-up reconciliation uses it to find the block the UTXO
    /// set sits on (audit DAG-11).
    pub fn heaviest_among(&self, blocks: &[BlockHash]) -> Option<BlockHash> {
        let known: Vec<BlockHash> = blocks.iter().copied().filter(|p| self.store.has(p)).collect();
        (!known.is_empty()).then(|| self.select_parent(&known))
    }

    /// Classify mergeset blocks as blue or red.
    ///
    /// A block C from the mergeset is blue if BOTH:
    ///   (a) |anticone(C) ∩ current_blue_set| ≤ K   (candidate constraint)
    ///   (b) For every already-blue block B: |(anticone(B) ∩ new_blue_set) ∪ {C}| ≤ K
    ///
    /// The "current blue set" grows as we iterate topologically over the mergeset.
    fn classify_mergeset(
        &self,
        mergeset: &[BlockHash],
        selected_parent: &BlockHash,
    ) -> (Vec<BlockHash>, Vec<BlockHash>, HashMap<BlockHash, usize>) {
        // Start blue set from selected parent's full blue lineage
        let mut blue_set: HashSet<BlockHash> = self.past_blue_set(selected_parent);
        blue_set.insert(*selected_parent);

        // Track anticone sizes for each blue block w.r.t. current blue set
        // Key: blue block hash, Value: |anticone(blue_block) ∩ blue_set|
        let mut blues_anticone_sizes: HashMap<BlockHash, usize> = HashMap::new();

        let mut mergeset_blues = Vec::new();
        let mut mergeset_reds = Vec::new();

        // Initialize anticone sizes for existing blue set
        // (simplified: we track the sizes incrementally)
        for b in &blue_set {
            blues_anticone_sizes.insert(*b, 0);
        }

        // Iterate mergeset topologically (ancestors first)
        for &candidate in mergeset {
            let candidate_anticone_in_blue = self.anticone_size_in_set(
                &candidate, &blue_set
            );

            if candidate_anticone_in_blue > self.k {
                // Constraint (a) violated — candidate is red
                mergeset_reds.push(candidate);
                continue;
            }

            // Check constraint (b): for each blue block, would adding candidate
            // push its anticone size over K?
            let mut constraint_b_ok = true;
            for (&blue_block, &current_anticone_size) in &blues_anticone_sizes {
                // Is candidate in anticone of blue_block?
                // anticone(B) = blocks neither in past(B) nor in future(B)
                let in_anticone = self.is_in_anticone(&candidate, &blue_block);
                if in_anticone && current_anticone_size + 1 > self.k {
                    constraint_b_ok = false;
                    break;
                }
            }

            if !constraint_b_ok {
                mergeset_reds.push(candidate);
                continue;
            }

            // Candidate is blue — add to blue set and update anticone sizes
            mergeset_blues.push(candidate);
            blue_set.insert(candidate);
            blues_anticone_sizes.insert(candidate, candidate_anticone_in_blue);

            // Update anticone sizes of existing blue blocks
            for (&blue_block, anticone_size) in blues_anticone_sizes.iter_mut() {
                if blue_block != candidate && self.is_in_anticone(&candidate, &blue_block) {
                    *anticone_size += 1;
                }
            }
        }

        (mergeset_blues, mergeset_reds, blues_anticone_sizes)
    }

    /// WS-B: compact, `O(k · mergeset)` GHOSTDAG coloring (Kaspa protocol).
    ///
    /// Replaces the old whole-blue-set seed + per-candidate full-set scan — which
    /// walked the ENTIRE selected chain (`past_blue_set_unbounded`, O(depth)) and
    /// materialized every historical blue — with a BOUNDED selected-chain walk:
    /// for each mergeset candidate we scan only each chain block's
    /// `mergeset_blues`, stopping the instant a chain block is an ancestor of the
    /// candidate (everything deeper is in the candidate's past, never its
    /// anticone). The per-block `blues_anticone_sizes` map is now COMPACT — only
    /// the blues this block adds and the sizes it bumps — and is read back for
    /// later blocks via [`blue_anticone_size`](Self::blue_anticone_size).
    ///
    /// Byte-identity note: the blue/red DECISIONS — hence `mergeset_blues`,
    /// `blue_score`, and the selected chain — are identical to the exact
    /// whole-set algorithm (validated against Legacy by `ghostdag_differential`).
    /// The `blues_anticone_sizes` map SHAPE differs (compact vs whole-history);
    /// that difference is exactly the gated-consensus metadata change activated
    /// with the reachability index at [`CORRECTED_COLORING_ACTIVATION_HEIGHT`].
    ///
    /// Audit DAG-4: this coloring is NOT exact GHOSTDAG. The selected parent is
    /// not part of GnB's `mergeset_blues`, so the chain walk never counts the
    /// selected-chain blocks below the immediate selected parent, and the
    /// anticone sizes of historical blues restart at 0 per block. It is kept
    /// bit-for-bit as the rule for blocks below the hardening activation;
    /// [`classify_mergeset_exact`](Self::classify_mergeset_exact) applies at or
    /// above it.
    fn classify_mergeset_fast(
        &self,
        mergeset: &[BlockHash],
        selected_parent: &BlockHash,
    ) -> (Vec<BlockHash>, Vec<BlockHash>, HashMap<BlockHash, usize>) {
        // Re-seeded semantics matching `classify_mergeset` (the consensus
        // reference), but with its O(depth) whole-blue-set seed + per-candidate
        // full scan replaced by the BOUNDED chain walk in
        // `candidate_anticone_blues`. `cur_blues_anticone_sizes` is COMPACT: an
        // entry exists only once a blue's (re-seeded) anticone count is set —
        // `selected_parent`, this block's own mergeset blues, and any historical
        // blue this block bumps. An absent blue counts as 0. This is exactly the
        // whole-history map with its zero entries dropped, so it carries the SAME
        // value on every key it keeps (validated by `ghostdag_differential`).
        // The selected parent is seeded blue (size 0) and stripped from the
        // returned `mergeset_blues` (blue_score = sp.blue_score + |blues| + 1).
        let mut cur_mergeset_blues: Vec<BlockHash> = Vec::with_capacity(mergeset.len() + 1);
        let mut cur_blues_anticone_sizes: HashMap<BlockHash, usize> = HashMap::new();
        cur_mergeset_blues.push(*selected_parent);
        cur_blues_anticone_sizes.insert(*selected_parent, 0);

        let mut mergeset_reds: Vec<BlockHash> = Vec::new();

        for &candidate in mergeset {
            // Every blue in the candidate's anticone (bounded selected-chain walk).
            let anticone_blues =
                self.candidate_anticone_blues(selected_parent, &cur_mergeset_blues, &candidate);

            // Constraint (a): |anticone(candidate) ∩ blue_set| ≤ k.
            if anticone_blues.len() > self.k {
                mergeset_reds.push(candidate);
                continue;
            }
            // Constraint (b): colouring the candidate blue must not push any blue
            // it lands in the anticone of over k (re-seeded count, absent = 0).
            let violates_b = anticone_blues
                .iter()
                .any(|b| *cur_blues_anticone_sizes.get(b).unwrap_or(&0) + 1 > self.k);
            if violates_b {
                mergeset_reds.push(candidate);
                continue;
            }

            // Blue: record its own count and bump every blue in its anticone.
            cur_mergeset_blues.push(candidate);
            cur_blues_anticone_sizes.insert(candidate, anticone_blues.len());
            for b in &anticone_blues {
                *cur_blues_anticone_sizes.entry(*b).or_insert(0) += 1;
            }
        }

        let mergeset_blues: Vec<BlockHash> =
            cur_mergeset_blues.into_iter().filter(|b| b != selected_parent).collect();
        (mergeset_blues, mergeset_reds, cur_blues_anticone_sizes)
    }

    /// Collect every blue in the candidate's anticone via a BOUNDED selected-chain
    /// walk. Phase 0 scans the block-under-construction's own blues
    /// (`selected_parent` + mergeset candidates already coloured blue). Phase 1
    /// walks `selected_parent` and up, stopping the instant a chain block is an
    /// ancestor of the candidate — everything deeper is in the candidate's past,
    /// never its anticone. Each block belongs to exactly one mergeset, so there
    /// are no duplicates. This replaces the old O(depth) `past_blue_set_unbounded`
    /// seed + full-set scan while producing the identical anticone set.
    ///
    /// Audit DAG-7, two output-preserving shortcuts (pre-activation rule):
    /// - k + 1 early exit: the caller colours the candidate red as soon as the
    ///   list holds more than k blues, so the walk stops there. The returned list
    ///   is then a (k + 1)-prefix of the full one, which leads to the same red
    ///   decision and to no anticone-size update (only blues update sizes).
    /// - skip pointers (`merge_skip`): chain blocks with an empty
    ///   `mergeset_blues` add nothing to the list, so the walk jumps from one
    ///   merging chain block to the next. The stop condition is unaffected: if
    ///   a skipped block is an ancestor of the candidate, the next merging block
    ///   below it is one too (ancestry is transitive), so the walk still stops
    ///   before processing anything the original walk would not have processed.
    ///
    /// Residual cost (package P3): beyond k + 1 steps, each step is a distinct
    /// block of the candidate's past that the selected chain merged as blue.
    /// Every block reaches this walk only through `accept::accept_block`
    /// after the node's anti-DoS work rule (`ingress::BlockIngress`), so a
    /// long walk costs the attacker one work-rule admission per step; see
    /// docs/CONSENSUS.md, "Per-block cost".
    fn candidate_anticone_blues(
        &self,
        selected_parent: &BlockHash,
        cur_mergeset_blues: &[BlockHash],
        candidate: &BlockHash,
    ) -> Vec<BlockHash> {
        let mut out: Vec<BlockHash> = Vec::new();

        // Phase 0 — the under-construction block's own accumulated blues.
        for &blue in cur_mergeset_blues {
            if !self.reach.is_dag_ancestor(&blue, candidate)
                && !self.reach.is_dag_ancestor(candidate, &blue)
            {
                out.push(blue);
                if out.len() > self.k {
                    return out;
                }
            }
        }

        // Phase 1 — selected_parent and up, until an ancestor of the candidate.
        let mut chain = self.next_merging_chain_block(selected_parent);
        while let Some(h) = chain {
            if self.reach.is_dag_ancestor(&h, candidate) {
                break;
            }
            let d = match self.store.get(&h) {
                Some(d) => d,
                None => break, // missing ancestor (shouldn't happen) — stop
            };
            for &blue in &d.mergeset_blues {
                if !self.reach.is_dag_ancestor(&blue, candidate)
                    && !self.reach.is_dag_ancestor(candidate, &blue)
                {
                    out.push(blue);
                    if out.len() > self.k {
                        return out;
                    }
                }
            }
            chain = d.selected_parent.and_then(|p| self.next_merging_chain_block(&p));
        }

        out
    }

    /// First block at or below `from` on its selected chain whose
    /// `mergeset_blues` is non-empty, from the `merge_skip` cache. Without a
    /// cache entry this is `Some(from)`: the walk then visits `from` itself,
    /// exactly like the original one-step walk.
    fn next_merging_chain_block(&self, from: &BlockHash) -> Option<BlockHash> {
        match self.merge_skip.get(from) {
            Some(v) => *v,
            None => Some(*from),
        }
    }

    /// Fill the `merge_skip` cache for `from` and every block below it on its
    /// selected chain (amortised O(1) per block; a DAG loaded from disk pays
    /// one walk the first time). If the store lacks a chain block the cache
    /// ends above it, which the original walk would also stop at.
    fn ensure_merge_skip(&mut self, from: &BlockHash) {
        let mut path: Vec<(BlockHash, bool)> = Vec::new();
        let mut below: Option<BlockHash> = None;
        let mut cur = Some(*from);
        while let Some(h) = cur {
            if let Some(v) = self.merge_skip.get(&h) {
                below = *v;
                break;
            }
            let d = match self.store.get(&h) {
                Some(d) => d,
                None => break,
            };
            path.push((h, !d.mergeset_blues.is_empty()));
            cur = d.selected_parent;
        }
        let mut acc = below;
        for (h, merging) in path.into_iter().rev() {
            if merging {
                acc = Some(h);
            }
            self.merge_skip.insert(h, acc);
        }
    }

    // ── Hardening (audit DAG-3 / DAG-4 / DAG-7) ─────────────────────────────

    /// Whether ancestry queries for a block with these parents can use the
    /// reachability index. The index is filled in topological order (or loaded
    /// whole and self-checked at boot), so indexed parents imply an indexed
    /// past. Otherwise the callers fall back to unbounded graph walks, which
    /// give the same answers more slowly.
    fn ancestry_index_ready(&self, parents: &[BlockHash], selected_parent: &BlockHash) -> bool {
        self.maintains_reachability_index()
            && self.reach.has(selected_parent)
            && parents.iter().all(|p| self.reach.has(p))
    }

    /// Exact, unbounded `a ∈ past(b)` (strict). Never the bounded legacy
    /// `is_ancestor`.
    fn dag_ancestor(&self, a: &BlockHash, b: &BlockHash, use_index: bool) -> bool {
        if use_index {
            self.reach.is_dag_ancestor(a, b)
        } else {
            reachability::brute_force_is_ancestor(&self.store, a, b)
        }
    }

    /// The mergeset of a block with these parents, from the reachability index
    /// in O(|mergeset| · parents · log): a backward walk from the non-selected
    /// parents that stops at `past(selected_parent) ∪ {selected_parent}`.
    ///
    /// Same output as [`compute_mergeset`]: both collect exactly the blocks
    /// reachable from a non-selected parent without passing through
    /// `past(selected_parent) ∪ {selected_parent}` (any path to a mergeset
    /// block avoids that set, since it is closed under taking ancestors), and
    /// both order the set with the same deterministic `topological_sort`. The
    /// index answers `h ∈ past(selected_parent)` exactly where the old code
    /// looked `h` up in the materialised `compute_past(selected_parent)`.
    ///
    /// `limit` (blocks, selected parent excluded) aborts the walk with
    /// [`ConsensusError::MergesetTooLarge`] as soon as it is exceeded, so an
    /// oversized mergeset costs O(limit), not O(|mergeset|).
    fn compute_mergeset_bounded(
        &self,
        parents: &[BlockHash],
        selected_parent: &BlockHash,
        limit: Option<usize>,
    ) -> Result<Vec<BlockHash>, ConsensusError> {
        let mut set: HashSet<BlockHash> = HashSet::new();
        let mut queue: VecDeque<BlockHash> = parents
            .iter()
            .filter(|p| *p != selected_parent)
            .copied()
            .collect();
        while let Some(h) = queue.pop_front() {
            if h == *selected_parent || set.contains(&h) || self.reach.is_dag_ancestor(&h, selected_parent) {
                continue;
            }
            set.insert(h);
            if let Some(limit) = limit {
                if set.len() > limit {
                    return Err(ConsensusError::MergesetTooLarge { limit: MERGESET_SIZE_LIMIT });
                }
            }
            if let Some(d) = self.store.get(&h) {
                for p in &d.parents {
                    if !set.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
        Ok(topological_sort(&self.store, set.into_iter().collect()))
    }

    /// Exact GHOSTDAG coloring (PHANTOM paper, Kaspa's algorithm) for blocks at
    /// or above the hardening activation (audit DAG-4).
    ///
    /// Candidates are taken in the mergeset order of [`topological_sort`]
    /// (FIFO Kahn, ids ascending among the blocks each step makes ready).
    /// With `blue` = blue(selected_parent) ∪ {selected_parent} ∪ the
    /// candidates already coloured blue, a candidate
    /// `c` is blue iff
    ///   (a) |anticone(c) ∩ blue| ≤ k, and
    ///   (b) every `x ∈ anticone(c) ∩ blue` has |anticone(x) ∩ blue| + 1 ≤ k.
    /// Both counts run over the FULL blue anticone, selected-chain blocks
    /// included: every chain block's selected parent is walked as a blue, which
    /// is what Kaspa gets from storing the selected parent as
    /// `mergeset_blues[0]` and what the pre-activation walk misses.
    ///
    /// Anticone sizes are computed from the DAG, never read from stored
    /// `blues_anticone_sizes` (those of pre-activation blocks are not exact),
    /// then kept current as blues are added. Every walk exits after k + 1
    /// blues, so a candidate costs O(k) chain blocks: each chain block visited
    /// that is not in the past of the walked block is itself in its blue
    /// anticone. Returns (blues without the selected parent, reds, the sizes of
    /// the selected parent, the new blues and every older blue whose size grew,
    /// each exact with respect to blue(B)).
    fn classify_mergeset_exact(
        &self,
        mergeset: &[BlockHash],
        selected_parent: &BlockHash,
        use_index: bool,
    ) -> (Vec<BlockHash>, Vec<BlockHash>, HashMap<BlockHash, usize>) {
        let k = self.k;
        let mut blues: Vec<BlockHash> = Vec::new();
        let mut reds: Vec<BlockHash> = Vec::new();
        // |anticone(x) ∩ blue| for every blue looked at so far, exact while < k
        // and stored as k once it reaches k (such an x turns every candidate in
        // its anticone red, so it never grows further).
        let mut sizes: HashMap<BlockHash, usize> = HashMap::new();
        let mut changed: HashSet<BlockHash> = HashSet::new();
        // blue(sp) ⊂ past(sp): the selected parent starts with an empty blue anticone.
        sizes.insert(*selected_parent, 0);
        changed.insert(*selected_parent);

        for &candidate in mergeset {
            let anticone = match self.exact_candidate_blue_anticone(selected_parent, &blues, &candidate, use_index) {
                Some(a) => a,
                None => {
                    reds.push(candidate); // (a): more than k blues in its anticone
                    continue;
                }
            };
            let mut fits = true;
            for x in &anticone {
                let s = match sizes.get(x) {
                    Some(s) => *s,
                    None => {
                        let s = self.exact_blue_anticone_size(x, selected_parent, &blues, use_index);
                        sizes.insert(*x, s);
                        s
                    }
                };
                if s + 1 > k {
                    fits = false; // (b): x would exceed k
                    break;
                }
            }
            if !fits {
                reds.push(candidate);
                continue;
            }
            for x in &anticone {
                if let Some(s) = sizes.get_mut(x) {
                    *s += 1;
                }
                changed.insert(*x);
            }
            sizes.insert(candidate, anticone.len());
            changed.insert(candidate);
            blues.push(candidate);
        }

        let anticone_sizes = changed
            .into_iter()
            .map(|h| {
                let s = sizes.get(&h).copied().unwrap_or(0);
                (h, s)
            })
            .collect();
        (blues, reds, anticone_sizes)
    }

    /// The blues in `candidate`'s anticone, or `None` as soon as there are more
    /// than k. The blue set is blue(sp) ∪ {sp} ∪ `blues`; it is enumerated as
    /// sp and `blues` (the block under construction), then, for each chain
    /// block d from sp down, sp(d) and d's mergeset blues. The walk stops after
    /// d once sp(d) is in the candidate's past: all remaining blues are below.
    ///
    /// A candidate is never in the past of a listed blue: candidates come in
    /// topological order and are not in past(sp), so only `y ∈ past(c)` needs a
    /// test.
    fn exact_candidate_blue_anticone(
        &self,
        selected_parent: &BlockHash,
        blues: &[BlockHash],
        candidate: &BlockHash,
        use_index: bool,
    ) -> Option<Vec<BlockHash>> {
        let k = self.k;
        let mut out: Vec<BlockHash> = Vec::with_capacity(k + 1);
        for y in std::iter::once(selected_parent).chain(blues.iter()) {
            if !self.dag_ancestor(y, candidate, use_index) {
                out.push(*y);
                if out.len() > k {
                    return None;
                }
            }
        }
        let mut d = *selected_parent;
        while let Some(dd) = self.store.get(&d) {
            let dsp = match dd.selected_parent {
                Some(p) => p,
                None => break, // genesis: blue(genesis) is empty
            };
            let dsp_in_past = self.dag_ancestor(&dsp, candidate, use_index);
            if !dsp_in_past {
                out.push(dsp);
                if out.len() > k {
                    return None;
                }
            }
            for y in &dd.mergeset_blues {
                if !self.dag_ancestor(y, candidate, use_index) {
                    out.push(*y);
                    if out.len() > k {
                        return None;
                    }
                }
            }
            if dsp_in_past {
                break;
            }
            d = dsp;
        }
        Some(out)
    }

    /// |anticone(x) ∩ blue| for a blue `x`, where blue = blue(sp) ∪ {sp} ∪
    /// `blues`, capped at k (the caller only needs to know whether it reached
    /// k). Same enumeration as [`exact_candidate_blue_anticone`], testing both
    /// directions of ancestry, and stopping once the chain reaches `x` or its
    /// past.
    fn exact_blue_anticone_size(
        &self,
        x: &BlockHash,
        selected_parent: &BlockHash,
        blues: &[BlockHash],
        use_index: bool,
    ) -> usize {
        let cap = self.k;
        let in_anticone = |y: &BlockHash| {
            y != x && !self.dag_ancestor(y, x, use_index) && !self.dag_ancestor(x, y, use_index)
        };
        let mut n = 0usize;
        for y in std::iter::once(selected_parent).chain(blues.iter()) {
            if in_anticone(y) {
                n += 1;
                if n >= cap {
                    return cap;
                }
            }
        }
        let mut d = *selected_parent;
        loop {
            if d == *x {
                break; // blue(x) ⊂ past(x)
            }
            let dd = match self.store.get(&d) {
                Some(dd) => dd,
                None => break,
            };
            let dsp = match dd.selected_parent {
                Some(p) => p,
                None => break,
            };
            for y in std::iter::once(&dsp).chain(dd.mergeset_blues.iter()) {
                if in_anticone(y) {
                    n += 1;
                    if n >= cap {
                        return cap;
                    }
                }
            }
            if dsp == *x || self.dag_ancestor(&dsp, x, use_index) {
                break;
            }
            d = dsp;
        }
        n
    }

    /// PoW work of a block (the `work` it was added with), for Kaspa blue work.
    ///
    /// Taken from the cache, or derived from stored `GhostdagData`: below the
    /// activation `blue_work = sp.blue_work + work`, at or above it
    /// `blue_work = sp.blue_work + Σ work(mergeset blues) + work`. Both invert
    /// exactly; the recursion only descends into mergeset blues (ancestors), so
    /// it terminates. Iterative, with results recorded in `memo`.
    fn work_of(&self, block: &BlockHash, memo: &mut HashMap<BlockHash, u128>) -> u128 {
        let known = |h: &BlockHash, memo: &HashMap<BlockHash, u128>| {
            self.block_work.get(h).or_else(|| memo.get(h)).copied()
        };
        if let Some(w) = known(block, memo) {
            return w;
        }
        let mut stack = vec![*block];
        while let Some(&h) = stack.last() {
            if known(&h, memo).is_some() {
                stack.pop();
                continue;
            }
            let d = match self.store.get(&h) {
                Some(d) => d,
                None => {
                    memo.insert(h, 0);
                    stack.pop();
                    continue;
                }
            };
            let sp_work = d
                .selected_parent
                .and_then(|p| self.store.get(&p))
                .map(|p| p.blue_work)
                .unwrap_or(0);
            let own_and_merged = d.blue_work.saturating_sub(sp_work);
            if d.selected_parent.is_none() || !self.is_hardened_at(d.height) {
                memo.insert(h, own_and_merged);
                stack.pop();
                continue;
            }
            let missing: Vec<BlockHash> = d
                .mergeset_blues
                .iter()
                .filter(|m| known(m, memo).is_none())
                .copied()
                .collect();
            if missing.is_empty() {
                let merged: u128 = d.mergeset_blues.iter().filter_map(|m| known(m, memo)).sum();
                memo.insert(h, own_and_merged.saturating_sub(merged));
                stack.pop();
            } else {
                stack.extend(missing);
            }
        }
        known(block, memo).unwrap_or(0)
    }

    /// The merge-depth root of a block with this selected parent and blue
    /// score: the highest block of the selected chain (from the selected parent
    /// down) whose blue_score is at most `blue_score - MERGE_DEPTH`; `None` while
    /// the chain is shallower than `MERGE_DEPTH`. At most `MERGE_DEPTH` steps,
    /// since blue_score strictly decreases down the chain.
    fn merge_depth_root(&self, selected_parent: &BlockHash, blue_score: u64) -> Option<BlockHash> {
        let required = blue_score.checked_sub(MERGE_DEPTH)?;
        let mut d = *selected_parent;
        loop {
            let dd = self.store.get(&d)?;
            if dd.blue_score <= required {
                return Some(d);
            }
            d = dd.selected_parent?;
        }
    }

    /// Bounded merge depth (audit DAG-7), as in Kaspa: every red of the
    /// mergeset must be in the future of the merge-depth root, or in the past
    /// of a mergeset blue that is ("kosherized").
    fn check_merge_depth(
        &self,
        selected_parent: &BlockHash,
        blue_score: u64,
        blues: &[BlockHash],
        reds: &[BlockHash],
        use_index: bool,
    ) -> Result<(), ConsensusError> {
        let root = match self.merge_depth_root(selected_parent, blue_score) {
            Some(r) => r,
            None => return Ok(()),
        };
        let above_root = |h: &BlockHash| *h == root || self.dag_ancestor(&root, h, use_index);
        let kosherizing: Vec<&BlockHash> = blues.iter().filter(|b| above_root(b)).collect();
        for red in reds {
            if above_root(red) {
                continue;
            }
            if kosherizing.iter().any(|b| self.dag_ancestor(red, b, use_index)) {
                continue;
            }
            return Err(ConsensusError::MergeDepthViolation { red: *red });
        }
        Ok(())
    }

    /// Audit B1-T15: a predicate telling whether a candidate template parent
    /// can be merged at all by a block whose selected parent is `sp` (at or
    /// above the hardening activation): it must be the LOWEST possible
    /// merge-depth root of such a block, or in its future. The lowest root is
    /// the one of a block with no mergeset blue
    /// (`blue_score = sp.blue_score + 1`); any actual block's root is at or
    /// above it on `sp`'s chain, so a
    /// candidate below it is below the actual root too. Such a candidate is
    /// red (it is in the anticone of every chain block from the root to `sp`,
    /// far more than k blues) and, when it is a tip, nothing kosherizes it (a
    /// tip is in no block's past): every parent set containing it fails
    /// [`check_merge_depth`](Self::check_merge_depth). Its whole branch is
    /// below the root (an ancestor above the root would put it in the root's
    /// future), so no block can merge it again after the activation; it stays
    /// in the DAG and in the valid tips (chain selection is unaffected) but
    /// is never offered as a template parent again (Kaspa filters virtual
    /// parent candidates the same way). Always true below the activation or
    /// while `sp`'s chain is shallower than `MERGE_DEPTH`. O(MERGE_DEPTH) once,
    /// then one reachability query per candidate.
    fn mergeable_below(&self, sp: &BlockHash, use_index: bool) -> impl Fn(&BlockHash) -> bool + '_ {
        let sp_data = self.store.get(sp);
        let hardened = sp_data.is_some_and(|d| self.is_hardened_at(d.height + 1));
        let root = match (hardened, sp_data) {
            (true, Some(d)) => self.merge_depth_root(sp, d.blue_score + 1),
            _ => None,
        };
        move |c: &BlockHash| match root {
            None => true,
            Some(r) => *c == r || self.dag_ancestor(&r, c, use_index && self.reach.has(c)),
        }
    }

    /// Parents for a block template (audit DAG-2 / DAG-7).
    ///
    /// Returns at most `max_parents` of `candidates` (normally the bodied tips)
    /// such that a block with exactly these parents, in this order, is accepted
    /// by [`add_block`](Self::add_block): the first entry is the block's
    /// selected parent (the heaviest candidate by blue work, blue score, hash —
    /// the same rule `add_block` applies), and the others follow by decreasing
    /// blue work.
    ///
    /// Below the hardening activation (judged at the template's height,
    /// `selected_parent.height + 1`) this is the heaviest `max_parents`
    /// candidates. At or above it, a candidate is added only while the
    /// mergeset stays within [`MAX_MERGESET_SIZE`], and parents that would make
    /// the block merge a red below the merge-depth root are then dropped, as
    /// Kaspa's virtual-parent selection does.
    ///
    /// Template code should call it as
    /// `dag.select_parents_for_template(&dag.bodied_tips(has_body), core::MAX_PARENTS)`
    /// and use the result as `header.parents` unchanged. Unknown candidates
    /// are ignored. With a single candidate the result is that candidate.
    pub fn select_parents_for_template(&self, candidates: &[BlockHash], max_parents: usize) -> Vec<BlockHash> {
        let key = |h: &BlockHash| {
            let d = self.store.get(h);
            (d.map(|d| d.blue_work).unwrap_or(0), d.map(|d| d.blue_score).unwrap_or(0), *h)
        };
        let mut cands: Vec<BlockHash> = candidates.iter().copied().filter(|h| self.store.has(h)).collect();
        cands.sort_by_key(|h| std::cmp::Reverse(key(h)));
        cands.dedup();
        if cands.is_empty() || max_parents == 0 {
            return Vec::new();
        }
        let sp = cands[0];

        // MERGESET_SIZE_LIMIT is this chain's rule at every height (and is
        // tighter than the hardened MAX_MERGESET_SIZE - 1), so the budgeted
        // selection runs on both sides of the activation: a plain capped
        // list made the node reject its own templates on a fast network.
        let use_index = self.ancestry_index_ready(&cands, &sp);
        let budget = MERGESET_SIZE_LIMIT.min(MAX_MERGESET_SIZE - 1);
        let mut chosen = vec![sp];
        let mut merged: HashSet<BlockHash> = HashSet::new();
        let mergeable = self.mergeable_below(&sp, use_index);
        for c in cands.iter().skip(1) {
            if chosen.len() >= max_parents {
                break;
            }
            if merged.contains(c) || self.dag_ancestor(c, &sp, use_index) {
                continue; // adds nothing to the mergeset
            }
            // B1-T15: a candidate below the merge-depth root can only be a
            // red nothing kosherizes; skip it before any mergeset work.
            if !mergeable(c) {
                continue;
            }
            // The blocks `c` would add to the mergeset, bounded by the budget.
            let mut added: Vec<BlockHash> = Vec::new();
            let mut seen: HashSet<BlockHash> = HashSet::new();
            let mut queue: VecDeque<BlockHash> = VecDeque::from([*c]);
            let mut over = false;
            while let Some(h) = queue.pop_front() {
                if h == sp || merged.contains(&h) || !seen.insert(h) || self.dag_ancestor(&h, &sp, use_index) {
                    continue;
                }
                added.push(h);
                if merged.len() + added.len() > budget {
                    over = true;
                    break;
                }
                if let Some(d) = self.store.get(&h) {
                    queue.extend(d.parents.iter().copied());
                }
            }
            if over {
                continue;
            }
            merged.extend(added);
            chosen.push(*c);
        }

        // Check the result with the consensus code (one `compute_block`
        // normally: the candidates that can never be merged were skipped
        // above). A violation can remain only through the coloring (a red
        // above the lowest root that ends below the actual root, or below
        // it and not kosherized): drop the parents responsible and check
        // again. Each round removes at least one parent; the selected parent
        // alone always is valid.
        loop {
            match self.compute_block(&chosen, 0, 0) {
                Ok(_) => break,
                Err(ConsensusError::MergeDepthViolation { red }) => {
                    let before = chosen.len();
                    chosen.retain(|p| *p == sp || !(*p == red || self.dag_ancestor(&red, p, use_index)));
                    if chosen.len() == before {
                        chosen.truncate(1);
                    }
                }
                Err(_) => {
                    chosen.truncate(1);
                    break;
                }
            }
        }
        chosen
    }

    /// Compute |anticone(candidate) ∩ blue_set|
    fn anticone_size_in_set(&self, candidate: &BlockHash, blue_set: &HashSet<BlockHash>) -> usize {
        blue_set.iter()
            .filter(|&b| self.is_in_anticone(candidate, b))
            .count()
    }

    /// Check if `a` and `b` are in each other's anticone
    /// (neither is ancestor of the other)
    fn is_in_anticone(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b { return false; }
        !is_ancestor(&self.store, a, b) && !is_ancestor(&self.store, b, a)
    }

    /// Collect blue blocks in the past of `block` by walking the selected chain.
    ///
    /// Audit H-5 fix: previously bounded at `2*K = 20` selected-chain hops
    /// (with K=10), which under-counted the anticone when the DAG had
    /// branches extending beyond that window. A red block could then be
    /// classified blue, causing `blue_score` to diverge between nodes — a
    /// silent consensus split.
    ///
    /// The short-term mitigation here is to raise the bound to `K*100`
    /// (1000 hops with K=10) and log a warning whenever the bound is hit,
    /// so misclassifications become observable in production even before
    /// the long-term fix (Kaspa-style reachability tree) lands.
    ///
    /// A node that sees these warnings regularly should open a bug — it
    /// means the DAG has drift exceeding the bound and a reachability tree
    /// is now a critical upgrade for that deployment.
    fn past_blue_set(&self, block: &BlockHash) -> HashSet<BlockHash> {
        let mut blue = HashSet::new();
        let mut cur = Some(*block);
        let max_depth = self.k * 100;
        let mut depth = 0usize;
        while let Some(h) = cur {
            if depth >= max_depth {
                warn!(
                    "past_blue_set hit depth bound of {} (K*100) walking from block {} — \
                     classification may under-count anticone. If this repeats, a reachability \
                     tree upgrade is now required for correctness.",
                    max_depth,
                    hex::encode(block),
                );
                break;
            }
            if let Some(data) = self.store.get(&h) {
                for mb in &data.mergeset_blues {
                    blue.insert(*mb);
                }
                cur = data.selected_parent;
                depth += 1;
            } else {
                break;
            }
        }
        blue
    }

    // ── Chain-disqualified (invalid) blocks — audit DAG-1 ─────────────────

    /// Mark `hash` chain-disqualified, together with every block whose
    /// selected-parent chain passes through it (the invariant `add_block`
    /// maintains for later arrivals). Returns the blocks newly marked, in
    /// discovery order. Unknown hashes are ignored.
    pub fn mark_invalid(&mut self, hash: BlockHash) -> Vec<BlockHash> {
        if self.store.has(&hash) {
            self.invalid_roots.insert(hash);
        }
        self.propagate_invalid(hash)
    }

    /// Mark `hash` and its selected-chain descendants in `invalid` (no root
    /// bookkeeping). Returns the blocks newly marked.
    fn propagate_invalid(&mut self, hash: BlockHash) -> Vec<BlockHash> {
        self.invalid_gen = self.invalid_gen.wrapping_add(1);
        let mut newly = Vec::new();
        let mut stack = vec![hash];
        while let Some(h) = stack.pop() {
            if !self.store.has(&h) || !self.invalid.insert(h) {
                continue;
            }
            newly.push(h);
            if let Some(children) = self.store.children.get(&h) {
                let mut ch: Vec<BlockHash> = children.iter()
                    .filter(|c| self.store.get(c).and_then(|d| d.selected_parent) == Some(h))
                    .copied()
                    .collect();
                ch.sort_unstable();
                stack.extend(ch);
            }
        }
        newly
    }

    /// Re-apply a persisted invalid set after a reload (propagates to
    /// selected-chain descendants loaded since). Returns how many blocks are
    /// now marked.
    pub fn load_invalid<I: IntoIterator<Item = BlockHash>>(&mut self, hashes: I) -> usize {
        let mut roots: Vec<BlockHash> = hashes.into_iter().collect();
        roots.sort_unstable();
        for h in roots {
            self.mark_invalid(h);
        }
        self.invalid_loaded = true;
        self.invalid.len()
    }

    /// Whether `load_invalid` has run on this instance.
    pub fn invalid_set_loaded(&self) -> bool {
        self.invalid_loaded
    }

    /// Disqualify `hash` and EVERY block that descends from it through any
    /// parent edge (selected or merged), and keep later arrivals that
    /// reference one of them disqualified too (`add_block`). For blocks that
    /// fail a context-free rule no upgraded node would ever have stored (the
    /// start-up hardening recheck): a block merging one of them can never be
    /// accepted by such a node, so it must not stay a template parent.
    /// Returns the blocks newly added to the all-edges closure. Unknown
    /// hashes are ignored.
    pub fn mark_invalid_all_edges(&mut self, hash: BlockHash) -> Vec<BlockHash> {
        if !self.store.has(&hash) {
            return Vec::new();
        }
        self.invalid_all_edges_roots.insert(hash);
        self.propagate_all_edges(hash)
    }

    fn propagate_all_edges(&mut self, hash: BlockHash) -> Vec<BlockHash> {
        self.invalid_gen = self.invalid_gen.wrapping_add(1);
        let mut newly = Vec::new();
        let mut stack = vec![hash];
        while let Some(h) = stack.pop() {
            if !self.store.has(&h) || !self.invalid_all_edges.insert(h) {
                continue;
            }
            self.invalid.insert(h);
            newly.push(h);
            if let Some(children) = self.store.children.get(&h) {
                let mut ch: Vec<BlockHash> = children.iter().copied().collect();
                ch.sort_unstable();
                stack.extend(ch);
            }
        }
        newly
    }

    /// [`load_invalid`](Self::load_invalid) for persisted roots of both
    /// kinds: `selected` spread along selected-parent chains, `all_edges`
    /// through every parent edge.
    pub fn load_invalid_sets<I, J>(&mut self, selected: I, all_edges: J) -> usize
    where
        I: IntoIterator<Item = BlockHash>,
        J: IntoIterator<Item = BlockHash>,
    {
        let mut roots: Vec<BlockHash> = all_edges.into_iter().collect();
        roots.sort_unstable();
        for h in roots {
            self.mark_invalid_all_edges(h);
        }
        self.load_invalid(selected)
    }

    /// True iff `hash` is in the all-edges closure (see
    /// [`mark_invalid_all_edges`](Self::mark_invalid_all_edges)).
    pub fn is_invalid_all_edges(&self, hash: &BlockHash) -> bool {
        self.invalid_all_edges.contains(hash)
    }

    /// Wait for a different body of `hash` (see the `body_pending` field):
    /// `hash` and its selected-chain descendants are disqualified IN MEMORY
    /// ONLY. `rejected_witness_root` is the witness root of the body just
    /// rejected (`None` when the body is merely missing). Returns the blocks
    /// newly marked invalid. Unknown hashes are ignored.
    pub fn mark_body_pending(&mut self, hash: BlockHash, rejected_witness_root: Option<[u8; 32]>) -> Vec<BlockHash> {
        if !self.store.has(&hash) {
            return Vec::new();
        }
        let rejected = self.body_pending.entry(hash).or_default();
        if let Some(wr) = rejected_witness_root {
            if !rejected.contains(&wr) {
                rejected.push(wr);
                if rejected.len() > MAX_REJECTED_BODIES {
                    rejected.remove(0);
                }
            }
        }
        self.propagate_invalid(hash)
    }

    /// [`mark_body_pending`](Self::mark_body_pending) for a body an operator
    /// override needs (`accept::request_bodies`): the block also stays
    /// wanted ([`is_body_wanted`](Self::is_body_wanted)) whatever the weight
    /// of its chain, until a body arrives
    /// ([`clear_body_pending`](Self::clear_body_pending)). Unknown hashes are
    /// ignored.
    pub fn request_body(&mut self, hash: BlockHash) -> Vec<BlockHash> {
        if !self.store.has(&hash) {
            return Vec::new();
        }
        self.body_requested.insert(hash);
        self.mark_body_pending(hash, None)
    }

    /// Park `hash` without a verdict (see the `no_verdict` field): it and its
    /// selected-chain descendants are disqualified IN MEMORY ONLY until
    /// [`unpark_no_verdicts`](Self::unpark_no_verdicts). Returns the blocks
    /// newly marked invalid. Unknown hashes are ignored.
    pub fn park_no_verdict(&mut self, hash: BlockHash) -> Vec<BlockHash> {
        if !self.store.has(&hash) {
            return Vec::new();
        }
        self.no_verdict.insert(hash);
        self.propagate_invalid(hash)
    }

    /// Unpark every block of `hashes` (their retries are due) and re-derive
    /// the disqualified set ONCE for all of them, so they and the blocks
    /// parked only through them are candidates again (review of PR #15, finding
    /// 1: one `recompute_invalid` per block was O(parked x disqualified)).
    /// Returns how many of them were parked.
    pub fn unpark_no_verdicts(&mut self, hashes: &[BlockHash]) -> usize {
        let n = hashes.iter().filter(|h| self.no_verdict.remove(*h)).count();
        if n > 0 {
            self.recompute_invalid();
        }
        n
    }

    /// True iff `hash` is disqualified ONLY because a block parked without
    /// a verdict lies on its selected chain (itself included), with no
    /// persistent root, all-edges block or body-pending block on the way
    /// (review of PR #15, finding 2). Such a block was not judged: once the
    /// parked block is, its chain may be the best one (a peer serving it is
    /// ahead of this node, not on an invalid chain). O(selected-chain steps
    /// to the root).
    pub fn is_no_verdict_branch(&self, hash: &BlockHash) -> bool {
        let mut cur = *hash;
        let mut parked = false;
        loop {
            if !self.invalid.contains(&cur) {
                return parked;
            }
            if self.invalid_roots.contains(&cur) || self.invalid_all_edges.contains(&cur)
                || self.body_pending.contains_key(&cur)
            {
                return false;
            }
            parked |= self.no_verdict.contains(&cur);
            match self.store.get(&cur).and_then(|d| d.selected_parent) {
                Some(sp) => cur = sp,
                None => return parked,
            }
        }
    }

    /// The heaviest block (GhostDAG's tip order, `(blue_work, blue_score,
    /// hash)`) of the branches parked without a verdict
    /// ([`is_no_verdict_branch`](Self::is_no_verdict_branch)), with the
    /// parked block on its selected chain; `None` when nothing is parked
    /// (review of PR #15, finding 2). Walks the parked blocks' selected-chain
    /// descendants only (what `park_no_verdict` marked).
    pub fn best_no_verdict_branch(&self) -> Option<(BlockHash, BlockHash)> {
        if self.no_verdict.is_empty() {
            return None;
        }
        let mut roots: Vec<BlockHash> = self.no_verdict.iter().copied().collect();
        roots.sort_unstable();
        let mut best: Option<((u128, u64, BlockHash), BlockHash)> = None;
        let mut seen: HashSet<BlockHash> = HashSet::new();
        for root in roots {
            if !self.is_no_verdict_branch(&root) {
                continue;
            }
            let mut stack = vec![root];
            while let Some(h) = stack.pop() {
                if !seen.insert(h) {
                    continue;
                }
                // A disqualification below the parked block ends the branch.
                if h != root && (self.invalid_roots.contains(&h) || self.invalid_all_edges.contains(&h)
                    || self.body_pending.contains_key(&h))
                {
                    continue;
                }
                let key = self.order_key(&h);
                if best.as_ref().is_none_or(|(k, _)| key > *k) {
                    best = Some((key, root));
                }
                if let Some(children) = self.store.children.get(&h) {
                    stack.extend(children.iter()
                        .filter(|c| self.store.get(c).and_then(|d| d.selected_parent) == Some(h))
                        .copied());
                }
            }
        }
        best.map(|((_, _, h), root)| (h, root))
    }

    /// How many times the disqualified set was re-derived from its roots
    /// (instrumentation for tests; see the `invalid_recomputes` field).
    #[allow(dead_code)] // library API (tests)
    pub fn invalid_recomputes(&self) -> u64 {
        self.invalid_recomputes
    }

    /// True iff `hash` itself is parked without a verdict.
    pub fn is_no_verdict_parked(&self, hash: &BlockHash) -> bool {
        self.no_verdict.contains(hash)
    }

    /// The blocks parked without a verdict, sorted.
    pub fn no_verdict_parked(&self) -> Vec<BlockHash> {
        let mut v: Vec<BlockHash> = self.no_verdict.iter().copied().collect();
        v.sort_unstable();
        v
    }

    /// True iff `hash` waits for a body (see `mark_body_pending`).
    pub fn is_body_pending(&self, hash: &BlockHash) -> bool {
        self.body_pending.contains_key(hash)
    }

    /// True iff `hash` waits for a body AND that body is wanted now (re-audit
    /// B1-T13): an operator override asked for it
    /// ([`request_body`](Self::request_body)), or a body could make a chain
    /// through `hash` the best one — some block on whose selected chain
    /// `hash` lies, with no persistent disqualification root between them
    /// (`hash` included), orders above the selected tip under GhostDAG's tip
    /// order (`order_key`) and could be selected at all (its selected chain
    /// passes through the PoWit-finalized checkpoint,
    /// [`conflicts_with_finality`](Self::conflicts_with_finality): a chain
    /// that would roll finalized history back never wins, whatever its
    /// work). Bitcoin Core downloads only the blocks of chains
    /// with more work than its tip and ignores an unrequested block with
    /// less work (`AcceptBlock`); here a body-pending block on a lighter
    /// branch is neither requested from peers nor processed when a copy
    /// arrives (`accept::awaits_body`), so a block whose body no witness can
    /// fix stops costing pulls and validations as soon as the honest chain is
    /// heavier, and is wanted again if its branch grows heavier. NOT
    /// consensus (which bodies are fetched, not which are valid).
    pub fn is_body_wanted(&self, hash: &BlockHash) -> bool {
        if !self.body_pending.contains_key(hash) {
            return false;
        }
        if self.body_requested.contains(hash) {
            return true;
        }
        let Some(height) = self.store.get(hash).map(|d| d.height) else {
            return false;
        };
        self.wanted_pending(height).0.contains(hash)
    }

    /// Every block whose body is wanted now
    /// ([`is_body_wanted`](Self::is_body_wanted)), sorted: the set the
    /// message processor requests (`ingress::awaited_bodies_to_request`) and
    /// the orphan sweep chases (`ingress::awaited_bodies_to_chase`).
    pub fn wanted_body_blocks(&self) -> Vec<BlockHash> {
        if self.body_pending.is_empty() {
            return Vec::new();
        }
        let min_height = self.body_pending.keys()
            .filter_map(|h| self.store.get(h).map(|d| d.height))
            .min()
            .unwrap_or(0);
        let (wanted, _) = self.wanted_pending(min_height);
        let mut v: Vec<BlockHash> = self.body_pending.keys()
            .filter(|h| self.body_requested.contains(*h) || wanted.contains(*h))
            .copied()
            .collect();
        v.sort_unstable();
        v
    }

    /// The body-pending blocks at DAG height >= `min_dag_height` on whose
    /// selected chain lies a block ordering above the selected tip, with no
    /// disqualification root (or all-edges block) strictly between them and
    /// no persistent disqualification of their own (the relation
    /// [`is_body_wanted`](Self::is_body_wanted) describes), and the number of
    /// blocks visited to find them.
    ///
    /// One memoised pass (review of re-audit B1-T13: a selected-subtree DFS
    /// per pending block cost O(pending x depth) under the DAG read lock,
    /// twice per processed block, while a pruned node follows a deep reorg).
    /// blue_work strictly increases along every parent -> child edge (the
    /// selected parent has the greatest blue_work of the parents and a block
    /// adds its own non-zero work), so every block ordering above the
    /// selected tip is reached from a tip that does through blocks that also
    /// do: those are the seeds. Each seed's selected-parent chain is then
    /// walked toward genesis, stopping after a disqualification root (a
    /// chain through it is invalid whatever body the blocks below get), at a
    /// block already reached, or below `min_dag_height` (DAG heights strictly
    /// decrease along it), so every block is visited at most once. A seed
    /// whose selected chain misses the PoWit-finalized checkpoint is dropped
    /// (it can never be selected); that check is memoised along the shared
    /// chains too.
    fn wanted_pending(&self, min_dag_height: u64) -> (HashSet<BlockHash>, usize) {
        let mut visits = 0usize;
        let mut reached: HashSet<BlockHash> = HashSet::new();
        // `conflicts_with_finality`, memoised: true = the block's selected
        // chain misses the finalized checkpoint.
        let mut finality_memo: HashMap<BlockHash, bool> = HashMap::new();
        let mut conflicts = |h: BlockHash, visits: &mut usize| -> bool {
            let Some((fh, fheight)) = self.finalized else { return false };
            let mut path = Vec::new();
            let mut cur = h;
            let verdict = loop {
                if let Some(&v) = finality_memo.get(&cur) {
                    break v;
                }
                if cur == fh {
                    break false;
                }
                *visits += 1;
                let Some(d) = self.store.get(&cur) else { break true };
                if d.height <= fheight {
                    break true;
                }
                path.push(cur);
                match d.selected_parent {
                    Some(sp) => cur = sp,
                    None => break true,
                }
            };
            for p in path {
                finality_memo.insert(p, verdict);
            }
            verdict
        };
        match self.selected_tip().map(|t| self.order_key(&t)) {
            // No selected tip: any chain can win.
            None => reached.extend(self.body_pending.keys().copied()),
            Some(best) => {
                let mut seeds = Vec::new();
                let mut seen: HashSet<BlockHash> = HashSet::new();
                let mut stack: Vec<BlockHash> = self.store.tips.iter()
                    .filter(|t| self.order_key(t) > best)
                    .copied()
                    .collect();
                while let Some(h) = stack.pop() {
                    if !seen.insert(h) {
                        continue;
                    }
                    visits += 1;
                    seeds.push(h);
                    if let Some(d) = self.store.get(&h) {
                        stack.extend(d.parents.iter().filter(|p| !seen.contains(*p) && self.order_key(p) > best));
                    }
                }
                for seed in seeds {
                    if conflicts(seed, &mut visits) {
                        continue;
                    }
                    let mut x = seed;
                    while let Some(d) = self.store.get(&x) {
                        if d.height < min_dag_height || !reached.insert(x) {
                            break;
                        }
                        visits += 1;
                        if self.invalid_roots.contains(&x) || self.invalid_all_edges.contains(&x) {
                            break;
                        }
                        match d.selected_parent {
                            Some(p) => x = p,
                            None => break,
                        }
                    }
                }
            }
        }
        // `is_invalid_persistently`, memoised along the shared chains.
        let mut persistent: HashMap<BlockHash, bool> = HashMap::new();
        let mut wanted = HashSet::new();
        for h in self.body_pending.keys().filter(|h| reached.contains(*h)) {
            let mut path = Vec::new();
            let mut cur = *h;
            let verdict = loop {
                if let Some(&v) = persistent.get(&cur) {
                    break v;
                }
                visits += 1;
                if !self.invalid.contains(&cur) {
                    break false;
                }
                path.push(cur);
                if self.invalid_roots.contains(&cur) || self.invalid_all_edges.contains(&cur) {
                    break true;
                }
                match self.store.get(&cur).and_then(|d| d.selected_parent) {
                    Some(sp) => cur = sp,
                    None => break false,
                }
            };
            for p in path {
                persistent.insert(p, verdict);
            }
            if !verdict {
                wanted.insert(*h);
            }
        }
        (wanted, visits)
    }

    /// Every block waiting for a body, sorted.
    pub fn body_pending_blocks(&self) -> Vec<BlockHash> {
        let mut v: Vec<BlockHash> = self.body_pending.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// True iff a body of `hash` with this witness root was already rejected.
    pub fn body_rejected_before(&self, hash: &BlockHash, witness_root: &[u8; 32]) -> bool {
        self.body_pending.get(hash).is_some_and(|v| v.contains(witness_root))
    }

    /// A body of `hash` is available again: stop waiting and re-derive the
    /// disqualified set from the remaining roots, so the blocks that were
    /// disqualified only through `hash` become candidates again. Returns
    /// `false` (no change) if `hash` was not waiting for a body.
    pub fn clear_body_pending(&mut self, hash: &BlockHash) -> bool {
        self.body_requested.remove(hash);
        if self.body_pending.remove(hash).is_none() {
            return false;
        }
        self.recompute_invalid();
        true
    }

    /// Rebuild `invalid` (and the all-edges closure) from the roots. Every
    /// disqualified block is reachable from a root: `mark_invalid`,
    /// `mark_body_pending` and `add_block` only ever extend a root's
    /// selected-chain (or, for all-edges roots, any-edge) descendants.
    fn recompute_invalid(&mut self) {
        self.invalid_recomputes += 1;
        self.invalid_gen = self.invalid_gen.wrapping_add(1);
        self.invalid.clear();
        self.invalid_all_edges.clear();
        let mut all_edges: Vec<BlockHash> = self.invalid_all_edges_roots.iter().copied().collect();
        all_edges.sort_unstable();
        for r in all_edges {
            self.propagate_all_edges(r);
        }
        let mut roots: Vec<BlockHash> = self.invalid_roots.iter()
            .chain(self.body_pending.keys())
            .chain(self.no_verdict.iter())
            .copied()
            .collect();
        roots.sort_unstable();
        roots.dedup();
        for r in roots {
            self.propagate_invalid(r);
        }
    }

    /// True iff `hash` is disqualified for a reason the block id commits to:
    /// a persistent root (or an all-edges block) lies on its selected-parent
    /// chain. `false` for a valid block and for one disqualified only because
    /// it waits for a body or descends from such a block, whose mark must
    /// never be persisted.
    pub fn is_invalid_persistently(&self, hash: &BlockHash) -> bool {
        let mut cur = *hash;
        loop {
            if !self.invalid.contains(&cur) {
                return false;
            }
            if self.invalid_roots.contains(&cur) || self.invalid_all_edges.contains(&cur) {
                return true;
            }
            match self.store.get(&cur).and_then(|d| d.selected_parent) {
                Some(sp) => cur = sp,
                None => return false,
            }
        }
    }

    /// Every non-genesis block whose HEADER height (`max(parent DAG heights)
    /// + 1`, the height `accept_block` validated it at) is at least
    /// `min_height`, sorted. Computed from the DAG alone (no body is read).
    pub fn blocks_with_header_height_at_least(&self, min_height: u64) -> Vec<BlockHash> {
        let mut out: Vec<BlockHash> = self.store.data.iter()
            .filter(|(_, d)| !d.parents.is_empty())
            .filter(|(_, d)| {
                let hh = d.parents.iter()
                    .filter_map(|p| self.store.get(p))
                    .map(|p| p.height)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                hh >= min_height
            })
            .map(|(h, _)| *h)
            .collect();
        out.sort_unstable();
        out
    }

    /// Replace the PERSISTENT disqualification roots by `selected` (spread
    /// along selected-parent chains, `mark_invalid`) and `all_edges` (spread
    /// through every parent edge, `mark_invalid_all_edges`), and re-derive the
    /// disqualified set from them and from the in-memory body-pending roots,
    /// which are kept. Used when persisted marks are removed (operator
    /// `reconsiderblock`), put back after an override that committed nothing,
    /// or kept by a chain-state rebuild (audit DAG-6 / DAG-11). Returns how
    /// many blocks are marked afterwards.
    pub fn reset_invalid_sets<I, J>(&mut self, selected: I, all_edges: J) -> usize
    where
        I: IntoIterator<Item = BlockHash>,
        J: IntoIterator<Item = BlockHash>,
    {
        self.invalid_roots = selected.into_iter().filter(|h| self.store.has(h)).collect();
        self.invalid_all_edges_roots = all_edges.into_iter().filter(|h| self.store.has(h)).collect();
        self.recompute_invalid();
        self.invalid_loaded = true;
        self.invalid.len()
    }

    /// True iff `ancestor` is `block` itself or lies on `block`'s
    /// selected-parent chain. Walks selected parents from `block` while the
    /// DAG height is above `ancestor`'s (the DAG height strictly decreases
    /// along selected-parent edges), so it costs O(height difference).
    pub fn is_on_selected_chain_of(&self, ancestor: &BlockHash, block: &BlockHash) -> bool {
        let target_h = match self.store.get(ancestor) {
            Some(d) => d.height,
            None => return false,
        };
        let mut cur = Some(*block);
        while let Some(h) = cur {
            if h == *ancestor {
                return true;
            }
            let d = match self.store.get(&h) {
                Some(d) => d,
                None => return false,
            };
            if d.height <= target_h {
                return false;
            }
            cur = d.selected_parent;
        }
        false
    }

    /// True iff `hash` is chain-disqualified.
    pub fn is_invalid(&self, hash: &BlockHash) -> bool {
        self.invalid.contains(hash)
    }

    /// Number of chain-disqualified blocks.
    pub fn invalid_count(&self) -> usize {
        self.invalid.len()
    }

    /// GhostDAG tip ordering key: (blue_work, blue_score, hash), larger wins —
    /// the same order `select_parent` uses.
    fn order_key(&self, h: &BlockHash) -> (u128, u64, BlockHash) {
        let d = self.store.get(h);
        (
            d.map(|d| d.blue_work).unwrap_or(0),
            d.map(|d| d.blue_score).unwrap_or(0),
            *h,
        )
    }

    /// Non-disqualified blocks none of whose children is non-disqualified:
    /// the tips of the valid sub-DAG. Equal to `tips()` when nothing is
    /// marked invalid. Unordered.
    pub fn valid_tips(&self) -> Vec<BlockHash> {
        if self.invalid.is_empty() && self.finalized.is_none() {
            return self.tips();
        }
        let mut out = Vec::new();
        let mut visited: HashSet<BlockHash> = HashSet::new();
        let mut stack: Vec<BlockHash> = self.store.tips.iter().copied().collect();
        while let Some(h) = stack.pop() {
            if !visited.insert(h) {
                continue;
            }
            if !self.selectable(&h) {
                if let Some(d) = self.store.get(&h) {
                    // Nothing at or below the finalized height is selectable
                    // except the checkpoint's own chain, which is reached
                    // through its descendants: stop there instead of walking
                    // a stale branch down to genesis.
                    let below_finality = self.finalized.is_some_and(|(_, fh)| d.height <= fh);
                    if !below_finality {
                        stack.extend(d.parents.iter().copied());
                    }
                }
                continue;
            }
            if !self.store.has(&h) {
                continue;
            }
            let all_children_invalid = self.store.children.get(&h)
                .map_or(true, |c| c.iter().all(|x| !self.selectable(x)));
            if all_children_invalid {
                out.push(h);
            }
        }
        out
    }

    // ── PoWit finality ──────────────────────────────────────────────────────

    /// Record the PoWit-finalized checkpoint (hash, DAG height). Only ever
    /// moves forward in height; see [`GhostDAG::finalized`]. The node sets
    /// the pin with [`GhostDAG::set_finality_pin`] (`finality`), which may
    /// move it back; this stays for tests and tools that pin directly.
    pub fn set_finalized(&mut self, hash: BlockHash, height: u64) {
        if self.finalized.is_none_or(|(_, h)| height > h) {
            self.finalized = Some((hash, height));
        }
    }

    /// The PoWit-finalized checkpoint, if any.
    pub fn finalized(&self) -> Option<(BlockHash, u64)> {
        self.finalized
    }

    /// Whether `h`'s selected-parent chain misses the finalized checkpoint
    /// (it forks below it, or `h` is below it): such a block would roll
    /// finalized history back.
    pub fn conflicts_with_finality(&self, h: &BlockHash) -> bool {
        let Some((fh, fheight)) = self.finalized else { return false };
        let mut cur = *h;
        loop {
            if cur == fh {
                return false;
            }
            let Some(d) = self.store.get(&cur) else { return true };
            if d.height <= fheight {
                return true;
            }
            match d.selected_parent {
                Some(sp) => cur = sp,
                None => return true,
            }
        }
    }

    /// Selectable: not disqualified and on the finalized chain.
    fn selectable(&self, h: &BlockHash) -> bool {
        !self.invalid.contains(h) && !self.conflicts_with_finality(h)
    }

    /// [`selectable`](Self::selectable) for the remotely triggerable reads
    /// (`selected_tip`, `tips_for_peers`): the same answer, with the
    /// finality walk memoized across the calls of one query and its DAG
    /// reads counted in `visits` (audit B1-T3 / B2-T5). Every block on the
    /// walk from `h` down to where it ends shares `h`'s answer (its own walk
    /// is a suffix of `h`'s), so tips whose selected chains meet are walked
    /// once below the meeting point instead of once per tip.
    fn selectable_memo(&self, h: &BlockHash, memo: &mut HashMap<BlockHash, bool>, visits: &mut u64) -> bool {
        if self.invalid.contains(h) {
            return false;
        }
        let Some((fh, fheight)) = self.finalized else { return true };
        let mut path: Vec<BlockHash> = Vec::new();
        let mut cur = *h;
        let conflicts = loop {
            if let Some(&c) = memo.get(&cur) {
                break c;
            }
            if cur == fh {
                break false;
            }
            *visits += 1;
            let Some(d) = self.store.get(&cur) else { break true };
            if d.height <= fheight {
                break true;
            }
            path.push(cur);
            match d.selected_parent {
                Some(sp) => cur = sp,
                None => break true,
            }
        };
        for b in path {
            memo.insert(b, conflicts);
        }
        !conflicts
    }

    // ── Public query API ────────────────────────────────────────────────────

    /// Best tip: highest blue_work, then blue_score, then hash, among the
    /// selectable blocks: NOT chain-disqualified (DAG-1) and on the PoWit
    /// finalized chain. With no invalid block and no finalized checkpoint
    /// this is exactly the maximum over `tips()`. Otherwise a best-first
    /// search from the tips through unselectable blocks finds the best
    /// selectable block: every descendant of it is unselectable (a
    /// selectable descendant would carry more blue_work), so it is reached
    /// through them.
    ///
    /// Audit B1-T3 / B2-T5 (cost only, same result): the tips are read in
    /// descending order from the store's ordered tip index, merged with the
    /// heap of parents pushed below unselectable blocks, so the search
    /// touches only the unselectable blocks ranked above the answer (and
    /// their parents) instead of every leaf of the DAG. The candidate
    /// sequence is exactly the one the full heap of all tips produced: at
    /// every step the largest remaining candidate is max(next tip from the
    /// index, top of the parent heap), and a parent is never a tip (it has a
    /// child), so the two sources never overlap. The finality walk is
    /// memoized within the call. `sync_index_tests` cross-check it against
    /// the full-heap search (`selected_tip_reference`).
    pub fn selected_tip(&self) -> Option<BlockHash> {
        let mut memo = HashMap::new();
        let mut visits = 0u64;
        let found = self.selected_tip_memo(&mut memo, &mut visits);
        self.note_visits(visits);
        found
    }

    /// [`selected_tip`](Self::selected_tip), sharing the finality memo and
    /// the visit count with its caller.
    fn selected_tip_memo(&self, memo: &mut HashMap<BlockHash, bool>, visits: &mut u64) -> Option<BlockHash> {
        let mut tips = self.store.tips_by_work.iter().rev().peekable();
        if self.invalid.is_empty() && self.finalized.is_none() {
            *visits += 1;
            return tips.next().map(|k| k.2);
        }
        use std::collections::BinaryHeap;
        let mut heap: BinaryHeap<TipKey> = BinaryHeap::new();
        let mut pushed: HashSet<BlockHash> = HashSet::new();
        loop {
            let from_tips = match (tips.peek(), heap.peek()) {
                (Some(t), Some(p)) => *t > p,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return None,
            };
            let (_, _, h) = if from_tips {
                *tips.next().expect("peeked")
            } else {
                heap.pop().expect("peeked")
            };
            *visits += 1;
            if self.selectable_memo(&h, memo, visits) {
                return Some(h);
            }
            if let Some(d) = self.store.get(&h) {
                for p in &d.parents {
                    if self.store.has(p) && pushed.insert(*p) {
                        heap.push(self.order_key(p));
                    }
                }
            }
        }
    }

    /// The selected tip by the original search: a heap of EVERY tip, then
    /// the parents of unselectable blocks (test reference for
    /// [`selected_tip`](Self::selected_tip)).
    #[cfg(test)]
    fn selected_tip_reference(&self) -> Option<BlockHash> {
        if self.invalid.is_empty() && self.finalized.is_none() {
            return self.store.tips.iter()
                .max_by(|a, b| self.order_key(a).cmp(&self.order_key(b)))
                .cloned();
        }
        use std::collections::BinaryHeap;
        let mut heap: BinaryHeap<(u128, u64, BlockHash)> = BinaryHeap::new();
        let mut pushed: HashSet<BlockHash> = HashSet::new();
        for t in &self.store.tips {
            if pushed.insert(*t) {
                heap.push(self.order_key(t));
            }
        }
        while let Some((_, _, h)) = heap.pop() {
            if self.selectable(&h) {
                return Some(h);
            }
            if let Some(d) = self.store.get(&h) {
                for p in &d.parents {
                    if self.store.has(p) && pushed.insert(*p) {
                        heap.push(self.order_key(p));
                    }
                }
            }
        }
        None
    }

    /// Audit B2-T7: the frontier this node advertises to peers (the
    /// `/gnb/sync/1` GetTips answer): the selected tip first, then the other
    /// selectable tips (not chain-disqualified, on the PoWit finalized
    /// chain) by GhostDAG's tip order (blue work, blue score, hash), at most
    /// `max` in all. An unselectable block is never advertised (it is never
    /// selected or merged as a template parent, `valid_tips`, so it stays a
    /// leaf for good, and advertising it made every requester fetch it).
    /// Reads at most `4 × max` leaves from the ordered tip index, the
    /// finality walk memoized across them (B1-T3: the cost does not grow
    /// with the DAG); when more unselectable leaves than that outrank the
    /// selectable ones, fewer tips are returned, the selected tip always
    /// among them.
    pub fn tips_for_peers(&self, max: usize) -> Vec<BlockHash> {
        let mut out = Vec::with_capacity(max.min(self.store.tips.len() + 1));
        if max == 0 {
            return out;
        }
        let mut memo = HashMap::new();
        let mut visits = 0u64;
        let selected = self.selected_tip_memo(&mut memo, &mut visits);
        if let Some(s) = selected {
            out.push(s);
        }
        let mut read = 0u64;
        for (_, _, h) in self.store.tips_by_work.iter().rev() {
            if out.len() >= max || read >= 4 * max as u64 {
                break;
            }
            read += 1;
            if Some(*h) != selected && self.selectable_memo(h, &mut memo, &mut visits) {
                out.push(*h);
            }
        }
        self.note_visits(visits + read);
        out
    }

    /// Template parents (audit DAG-2): the bodied valid tips, highest
    /// (blue_work, blue_score, hash) first, capped at `max`. The first entry
    /// is therefore the template's selected parent. Header-only tips are
    /// skipped; when no valid tip has a body, falls back to the best bodied
    /// valid ancestor (see `best_bodied_tip`). Shared by the internal miner
    /// and `getblocktemplate` so both stay under `core::MAX_PARENTS`.
    ///
    /// The candidates go through
    /// [`select_parents_for_template`](Self::select_parents_for_template), so
    /// the template respects `MERGESET_SIZE_LIMIT` at every height and, at or
    /// above the hardening activation, the merge-depth rule.
    ///
    /// Audit B1-T15: the selected parent is found first (the heaviest valid
    /// tip with a body); then a tip that can never be merged by a block on it
    /// (its whole branch below the merge-depth root, `mergeable_below`) is
    /// dropped BEFORE its body is looked up (`has_body` reads storage) and
    /// before any mergeset work, so such tips cost one reachability query
    /// each per template instead of a stored-body lookup and a full
    /// `compute_block`. Pre-activation the candidate list is unchanged.
    pub fn template_parents<F: Fn(&BlockHash) -> bool>(&self, max: usize, has_body: F) -> Vec<BlockHash> {
        let mut tips = self.valid_tips();
        tips.sort_by_key(|h| std::cmp::Reverse(self.order_key(h)));
        let Some(pos) = tips.iter().position(&has_body) else {
            return self.best_bodied_tip(has_body).into_iter().collect();
        };
        let sp = tips[pos];
        let use_index = self.maintains_reachability_index() && self.reach.has(&sp);
        let mergeable = self.mergeable_below(&sp, use_index);
        let cands: Vec<BlockHash> = std::iter::once(sp)
            .chain(tips[pos + 1..].iter().copied().filter(|h| mergeable(h) && has_body(h)))
            .collect();
        self.select_parents_for_template(&cands, max.max(1))
    }

    pub fn tip_blue_score(&self) -> u64 {
        self.selected_tip()
            .and_then(|h| self.store.get(&h))
            .map(|d| d.blue_score)
            .unwrap_or(0)
    }

    pub fn tips(&self) -> Vec<BlockHash> {
        self.store.tips.iter().cloned().collect()
    }

    /// Best tip whose BODY is available, walking the selected-parent chain
    /// down from the highest-blue-work tip until a bodied block is found.
    ///
    /// A header-only tip — accepted via headers-first sync but whose body
    /// never arrived (e.g. an unreachable chain advertised by peers) — is
    /// UNMINEABLE: a block built on it cannot be validated by accept_block,
    /// so the internal miner and stratum silently stall on a phantom parent.
    /// This is exactly what wedged the founder at H=3737 behind a bodyless
    /// H=3738 header. `has_body(&hash)` must return true iff the full block
    /// body is present in block storage.
    pub fn best_bodied_tip<F: Fn(&BlockHash) -> bool>(&self, has_body: F) -> Option<BlockHash> {
        // Resolve EVERY tip to a bodied candidate — the tip itself when its
        // body is present, else its nearest bodied ancestor along the
        // selected-parent chain — then return the heaviest candidate under
        // GhostDAG's own tip ordering (blue_work, then blue_score, then hash).
        //
        // This deliberately EXCLUDES a header-only tip from selection. A
        // dominant-blue_work but BODILESS tip — e.g. a persisted N-way merge
        // header whose body never arrived — can never be extended, so the miner
        // must build on the heaviest tip we actually hold a body for. The prior
        // implementation walked selected_parent down from the single
        // highest-blue_work tip and so returned that phantom's bodied ANCESTOR,
        // leaving the miner producing sibling blocks that always lost the
        // blue_work race to the phantom → a persisted deadlock no restart could
        // clear (h3757/b3ee487b). Scanning all tips instead lets a freshly-mined
        // bodied tip win selection and the chain advance. Recomputed from the
        // store on every call — no persisted latch, so this is restart-safe.
        let mut best: Option<BlockHash> = None;
        for tip in self.valid_tips().iter() {
            // Nearest bodied block at or below this tip. (Selected-parent
            // ancestors of a valid tip are valid: the invalid set is closed
            // under selected-parent children.)
            let mut cur = Some(*tip);
            let candidate = loop {
                match cur {
                    Some(h) if has_body(&h)  => break Some(h),
                    Some(h)                  => cur = self.store.get(&h).and_then(|d| d.selected_parent),
                    None                     => break None,
                }
            };
            if let Some(c) = candidate {
                best = Some(match best {
                    None => c,
                    Some(b) => {
                        let dc = self.store.get(&c);
                        let db = self.store.get(&b);
                        let wc = dc.map(|d| d.blue_work).unwrap_or(0);
                        let wb = db.map(|d| d.blue_work).unwrap_or(0);
                        let sc = dc.map(|d| d.blue_score).unwrap_or(0);
                        let sb = db.map(|d| d.blue_score).unwrap_or(0);
                        if wc.cmp(&wb).then(sc.cmp(&sb)).then(c.cmp(&b)).is_gt() { c } else { b }
                    }
                });
            }
        }
        best
    }

    /// Tips that are safe to mine on: those whose body is available. When
    /// every tip is header-only, falls back to the nearest bodied ancestor
    /// via [`best_bodied_tip`] so mining never stalls on a phantom parent.
    pub fn bodied_tips<F: Fn(&BlockHash) -> bool>(&self, has_body: F) -> Vec<BlockHash> {
        let bodied: Vec<BlockHash> = self.valid_tips().into_iter()
            .filter(|h| has_body(h))
            .collect();
        if !bodied.is_empty() {
            return bodied;
        }
        self.best_bodied_tip(has_body).into_iter().collect()
    }

    pub fn block_count(&self) -> usize {
        self.store.data.len()
    }

    pub fn has_block(&self, hash: &BlockHash) -> bool {
        self.store.has(hash)
    }

    pub fn get_block_data(&self, hash: &BlockHash) -> Option<&GhostdagData> {
        self.store.get(hash)
    }

    /// Selected parent chain from best tip (the "virtual selected chain")
    pub fn selected_chain(&self) -> Vec<BlockHash> {
        let mut chain = Vec::new();
        let mut cur = self.selected_tip();
        while let Some(h) = cur {
            chain.push(h);
            cur = self.store.get(&h).and_then(|d| d.selected_parent);
        }
        self.note_visits(chain.len() as u64);
        chain
    }

    /// Is `hash` in the blue set of the selected tip, i.e. in
    /// `blue(tip) ∪ {tip}`: the selected chain from the tip down to genesis
    /// and every mergeset blue of a block on it? Exact at any depth (audit
    /// DAG-12: it used the legacy `past_blue_set` walk, bounded to k * 100
    /// chain blocks, and missed the selected chain itself).
    ///
    /// The walk down the selected chain stops at the first chain block whose
    /// `blue_work` is below `hash`'s: `blue_work` never decreases along a
    /// parent edge (a block's is at least its selected parent's, the
    /// heaviest of its parents), so neither that block nor anything below it
    /// has `hash` in its past or mergeset. Diagnostics and tests only; no
    /// consensus or relay decision calls it.
    pub fn is_blue(&self, hash: &BlockHash) -> bool {
        let (Some(tip), Some(target)) = (self.selected_tip(), self.store.get(hash)) else {
            return false;
        };
        let mut cur = Some(tip);
        while let Some(h) = cur {
            if h == *hash {
                return true;
            }
            let Some(d) = self.store.get(&h) else { return false };
            if d.mergeset_blues.contains(hash) {
                return true;
            }
            if d.blue_work < target.blue_work {
                return false;
            }
            cur = d.selected_parent;
        }
        false
    }

    // (Audit DAG-12: `is_final`, a diagnostic that compared a blue-score gap
    // with the header-height constant `CHECKPOINT_DEPTH` and that nothing
    // called, was removed. There is no finality: docs/CONSENSUS.md, "Selected
    // parent and fork choice".)

    /// Ordered block hashes from blue_score `from` for IBD sync: the first
    /// `limit` blocks in (blue_score, hash) order with `blue_score >= from`
    /// (the `/gnb/sync/1` GetHeaders answer).
    ///
    /// H-R3-1 made this O(limit) memory but left it O(n) time: it scanned
    /// every stored block per request. Audit B1-T3 / B2-T5: it is now a range
    /// read of the store's (blue_score, hash) index, O(log n + limit) time,
    /// with the same result (ascending (blue_score, hash), ties by hash).
    pub fn ordered_hashes_from(&self, from_blue_score: u64, limit: usize) -> Vec<BlockHash> {
        let out: Vec<BlockHash> = self.store.by_score
            .range((from_blue_score, [0u8; 32])..)
            .take(limit)
            .map(|(_, h)| *h)
            .collect();
        self.note_visits(out.len() as u64);
        out
    }

    pub fn get_node(&self, hash: &BlockHash) -> Option<&GhostdagData> {
        self.store.get(hash)
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors returned by consensus operations.
///
/// Introduced by audit finding M-9 — previously `add_block` used `assert!`
/// for its preconditions and panicked the whole process when an invalid
/// block somehow reached the consensus layer. This enum lets callers
/// reject bad input cleanly.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// A block was submitted with an empty parents vector. Only the genesis
    /// block is allowed to have no parents, and genesis goes through
    /// `add_genesis`, not `add_block`.
    #[error("block has no parents — only genesis can have zero parents, and genesis uses add_genesis()")]
    NoParents,

    /// A block with this hash is already present in the DAG. The caller
    /// should treat this as a duplicate-announcement case rather than an
    /// error on the consensus layer.
    #[error("block already in DAG: {}", hex::encode(.0))]
    DuplicateBlock(BlockHash),

    /// The block's selected parent is not present in the DAG store. In the
    /// normal path this cannot happen — the sync/gossip layer buffers blocks
    /// with missing parents in the orphan pool and only calls `add_block`
    /// once every parent is known. This variant completes the Audit M-9
    /// hardening: if a block ever reaches `add_block` with an absent selected
    /// parent, reject it cleanly instead of panicking the node.
    #[error("selected parent not in DAG: {}", hex::encode(.0))]
    MissingSelectedParent(BlockHash),

    /// Audit DAG-7 (at or above the hardening activation): the block's
    /// mergeset, selected parent included, has more than `limit` blocks.
    #[error("mergeset exceeds the limit of {limit} blocks")]
    MergesetTooLarge { limit: usize },

    /// Audit DAG-7 (at or above the hardening activation): the block merges a
    /// red block that is neither in the future of its merge-depth root nor in
    /// the past of a merged blue block that is.
    #[error("merges red block {} below the merge-depth root", hex::encode(.red))]
    MergeDepthViolation { red: BlockHash },
}

/// Largest mergeset a block may have (blocks merged besides its selected
/// chain). With k = 10 and 30-second blocks an honest mergeset stays near k;
/// the live chain's has never exceeded 2. Bounds coloring and validation work
/// per block (Kaspa enforces the same kind of limit).
/// Parents a template references at most (Kaspa uses 10).

pub const MERGESET_SIZE_LIMIT: usize = 64;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(n: u8) -> BlockHash {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    /// A block may not merge more than MERGESET_SIZE_LIMIT blocks; refusing
    /// it leaves the DAG unchanged.
    #[test]
    fn oversized_mergeset_is_refused_without_mutation() {
        for coloring in [ColoringMode::Legacy, ColoringMode::Fast] {
            let mut dag = GhostDAG::with_default_k();
            dag.coloring = coloring;
            let g = [0xEEu8; 32];
            dag.add_genesis(g, 1_000);
            // The mergeset excludes the selected parent: LIMIT + 2 parents
            // merge LIMIT + 1 blocks.
            let side: Vec<BlockHash> = (0..MERGESET_SIZE_LIMIT as u16 + 2)
                .map(|i| { let mut h = [0u8; 32]; h[..2].copy_from_slice(&i.to_le_bytes()); h[2] = 0x5A; h })
                .collect();
            for h in &side {
                dag.add_block(*h, vec![g], 1_030, 1).unwrap();
            }
            let count = dag.block_count();
            let big = [0xB1u8; 32];
            let res = dag.add_block(big, side.clone(), 1_060, 1);
            assert!(matches!(res, Err(ConsensusError::MergesetTooLarge { .. })), "{:?}", res.map(|d| d.height));
            assert_eq!(dag.block_count(), count, "nothing inserted");
            assert!(dag.get_block_data(&big).is_none());
            let ok = [0xB2u8; 32];
            assert!(dag.add_block(ok, side[..MERGESET_SIZE_LIMIT + 1].to_vec(), 1_060, 1).is_ok(),
                    "a mergeset at the limit is accepted");
        }
    }

    /// WS-A: the corrected-coloring gate is armed to a FUTURE height. A Legacy
    /// (production) DAG stays Legacy below the gate — so all already-mined
    /// history keeps its coloring, no reorg / no balance recompute — and flips
    /// to the exact index-based `Fast` coloring at/above it. Arming the gate also
    /// turns on reachability-index maintenance from genesis so `Fast` is ready by
    /// the activation height.
    #[test]
    fn corrected_coloring_gate_is_armed_at_future_height() {
        assert_ne!(
            CORRECTED_COLORING_ACTIVATION_HEIGHT, u64::MAX,
            "WS-A: gate must be armed to a real future height, not disabled",
        );
        let dag = GhostDAG::with_default_k(); // Legacy constructor = production path
        assert!(
            dag.maintains_reachability_index(),
            "an armed gate must maintain the reachability index from genesis",
        );
        // GnB: exact coloring from genesis.
        assert_eq!(CORRECTED_COLORING_ACTIVATION_HEIGHT, 0);
        assert!(matches!(dag.effective_coloring(0), ColoringMode::Fast));
        assert!(matches!(dag.effective_coloring(1), ColoringMode::Fast));
    }

    /// The pre-review wanted-body relation (re-audit B1-T13): a DFS over the
    /// selected-chain subtree of each pending block. Kept as the oracle of
    /// `wanted_pending`; returns the wanted set and the blocks it visited.
    fn wanted_by_subtree_dfs(dag: &GhostDAG) -> (Vec<BlockHash>, usize) {
        let best = dag.selected_tip().map(|t| dag.order_key(&t));
        let mut visits = 0usize;
        let mut out = Vec::new();
        for root in dag.body_pending.keys() {
            if dag.is_invalid_persistently(root) {
                continue;
            }
            let Some(best) = best else { out.push(*root); continue };
            let mut stack = vec![*root];
            let mut seen: HashSet<BlockHash> = HashSet::new();
            let mut wins = false;
            while let Some(h) = stack.pop() {
                if !seen.insert(h) {
                    continue;
                }
                visits += 1;
                if dag.order_key(&h) > best {
                    wins = true;
                    break;
                }
                for c in dag.store.children.get(&h).into_iter().flatten() {
                    let on_chain = dag.store.get(c).is_some_and(|d| d.selected_parent == Some(h));
                    let dead = dag.invalid_roots.contains(c) || dag.invalid_all_edges.contains(c);
                    if on_chain && !dead {
                        stack.push(*c);
                    }
                }
            }
            if wins {
                out.push(*root);
            }
        }
        out.sort_unstable();
        (out, visits)
    }

    /// Review of re-audit B1-T13 (cost): a pruned node following a deep
    /// reorg waits for many bodies of the heavier branch at once. The wanted
    /// set is computed in one memoised pass (each block visited at most a
    /// small constant number of times), not one selected-subtree DFS per
    /// pending block (O(pending x depth), under the DAG read lock, twice per
    /// processed block); it equals the DFS relation, also with persistent
    /// disqualification roots on and below the heavy branch.
    #[test]
    fn wanted_body_set_is_one_memoised_pass_over_the_pending_branch() {
        let id = |tag: u8, i: u32| {
            let mut x = [0u8; 32];
            x[0] = tag;
            x[1..5].copy_from_slice(&i.to_le_bytes());
            x
        };
        // genesis - 20 common blocks - B (600) | A (700); the node waits for
        // the bodies of A's first 500 blocks (pruned): A is disqualified in
        // memory, the selected tip is B's, and only A's last 100 blocks order
        // above it.
        // With `side`, a 700-block branch S leaves A at a[100].
        let fixture = |side: bool| {
            let mut dag = GhostDAG::with_k(3);
            let g = id(0, 0);
            dag.add_genesis(g, 1_000);
            let mut ts = 1_000u64;
            let mut chain = |dag: &mut GhostDAG, tag: u8, from: BlockHash, len: u32| -> Vec<BlockHash> {
                let mut v = Vec::new();
                let mut parent = from;
                for i in 1..=len {
                    ts += 1;
                    let h = id(tag, i);
                    dag.add_block(h, vec![parent], ts, 1_000).unwrap();
                    v.push(h);
                    parent = h;
                }
                v
            };
            let common = chain(&mut dag, 1, g, 20);
            let fork = *common.last().unwrap();
            let b = chain(&mut dag, 2, fork, 600);
            let a = chain(&mut dag, 3, fork, 700);
            if side {
                chain(&mut dag, 4, a[100], 700);
            }
            for h in &a[..500] {
                dag.mark_body_pending(*h, None);
            }
            (dag, a, b)
        };
        let (dag, a, b) = fixture(false);
        assert_eq!(dag.selected_tip(), Some(*b.last().unwrap()));
        let min = dag.store.get(&a[0]).unwrap().height;
        let (wanted, visits) = dag.wanted_pending(min);
        let mut wanted: Vec<BlockHash> = wanted.into_iter().collect();
        wanted.sort_unstable();
        let (oracle, oracle_visits) = wanted_by_subtree_dfs(&dag);
        let mut all: Vec<BlockHash> = a[..500].to_vec();
        all.sort_unstable();
        assert_eq!(wanted, all, "every pending block of the heavier branch is wanted");
        assert_eq!(wanted, oracle);
        assert_eq!(dag.wanted_body_blocks(), oracle);
        assert!(a[..500].iter().all(|h| dag.is_body_wanted(h)));
        // 700 blocks on the branch: seeds (100) + walk (600) + memoised
        // persistence checks (500 + 1). The per-block DFS visits ~175,000.
        assert!(visits <= 3 * 700, "visits {visits}");
        assert!(oracle_visits > 100_000, "oracle visits {oracle_visits}");

        // A persistent root between the pending blocks and the blocks above
        // the tip makes none of them wanted. With a heavy side branch S
        // leaving A at a[100], a persistent root at a[300] leaves wanted
        // exactly a[0..=100] (through S); a[101..300] have no winning chain
        // and a[300..500] are disqualified for good.
        let (mut cut, _, _) = fixture(false);
        cut.mark_invalid(a[550]);
        assert_eq!(cut.wanted_body_blocks(), wanted_by_subtree_dfs(&cut).0);
        assert!(cut.wanted_body_blocks().is_empty());
        let (mut cut, _, _) = fixture(true);
        cut.mark_invalid(a[300]);
        let w = cut.wanted_body_blocks();
        assert_eq!(w, wanted_by_subtree_dfs(&cut).0);
        let mut expect: Vec<BlockHash> = a[..=100].to_vec();
        expect.sort_unstable();
        assert_eq!(w, expect);
        assert!(cut.is_body_wanted(&a[10]) && cut.is_body_wanted(&a[100]));
        assert!(!cut.is_body_wanted(&a[101]) && !cut.is_body_wanted(&a[300]) && !cut.is_body_wanted(&a[301]));
    }

    /// Re-audit B1-T13 with main's PoWit finality (`set_finalized`): a body
    /// is wanted only while a chain through it can be SELECTED, and a chain
    /// whose selected-parent chain misses the finalized checkpoint never is
    /// (`selectable`), however heavy. A heavier branch forking below the
    /// checkpoint therefore stops wanting its pending bodies once the
    /// checkpoint is finalized on the other branch; a checkpoint below the
    /// fork changes nothing.
    #[test]
    fn wanted_bodies_never_include_a_branch_that_misses_the_finalized_checkpoint() {
        let id = |tag: u8, i: u32| {
            let mut x = [0u8; 32];
            x[0] = tag;
            x[1..5].copy_from_slice(&i.to_le_bytes());
            x
        };
        // genesis - 5 common blocks - B (10) | A (15); A's first 5 blocks
        // wait for bodies.
        let fixture = || {
            let mut dag = GhostDAG::with_k(3);
            let g = id(0, 0);
            dag.add_genesis(g, 1_000);
            let mut ts = 1_000u64;
            let mut chain = |dag: &mut GhostDAG, tag: u8, from: BlockHash, len: u32| -> Vec<BlockHash> {
                let mut v = Vec::new();
                let mut parent = from;
                for i in 1..=len {
                    ts += 1;
                    let h = id(tag, i);
                    dag.add_block(h, vec![parent], ts, 1_000).unwrap();
                    v.push(h);
                    parent = h;
                }
                v
            };
            let common = chain(&mut dag, 1, g, 5);
            let fork = *common.last().unwrap();
            let b = chain(&mut dag, 2, fork, 10);
            let a = chain(&mut dag, 3, fork, 15);
            for h in &a[..5] {
                dag.mark_body_pending(*h, None);
            }
            (dag, common, a, b)
        };
        let (dag, _, a, b) = fixture();
        assert_eq!(dag.selected_tip(), Some(*b.last().unwrap()));
        let mut pending: Vec<BlockHash> = a[..5].to_vec();
        pending.sort_unstable();
        assert_eq!(dag.wanted_body_blocks(), pending, "the heavier branch can win: its bodies are wanted");

        // Finalized on B, above the fork: A can never be selected.
        let (mut dag, _, a, b) = fixture();
        let fh = dag.store.get(&b[2]).unwrap().height;
        dag.set_finalized(b[2], fh);
        assert!(dag.conflicts_with_finality(a.last().unwrap()));
        assert_eq!(dag.selected_tip(), Some(*b.last().unwrap()));
        assert!(dag.wanted_body_blocks().is_empty(), "a branch that misses the checkpoint is never wanted");
        assert!(a[..5].iter().all(|h| dag.is_body_pending(h) && !dag.is_body_wanted(h)));

        // Finalized below the fork: both branches pass through it.
        let (mut dag, common, a, _) = fixture();
        let fh = dag.store.get(&common[2]).unwrap().height;
        dag.set_finalized(common[2], fh);
        assert!(!dag.conflicts_with_finality(a.last().unwrap()));
        assert_eq!(dag.wanted_body_blocks(), pending);
    }

    #[test]
    fn genesis_blue_score_zero() {
        let mut dag = GhostDAG::with_k(3);
        dag.add_genesis(make_hash(0), 1000);
        assert_eq!(dag.tip_blue_score(), 0);
        assert_eq!(dag.block_count(), 1);
    }

    #[test]
    fn linear_chain_blue_scores() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let b1 = make_hash(1);
        dag.add_block(b1, vec![g], 1, 1000).unwrap();
        assert_eq!(dag.store.get(&b1).unwrap().blue_score, 1);

        let b2 = make_hash(2);
        dag.add_block(b2, vec![b1], 2, 1000).unwrap();
        assert_eq!(dag.store.get(&b2).unwrap().blue_score, 2);

        let b3 = make_hash(3);
        dag.add_block(b3, vec![b2], 3, 1000).unwrap();
        assert_eq!(dag.store.get(&b3).unwrap().blue_score, 3);
    }

    /// H-R3-1 regression: `ordered_hashes_from` must return exactly the
    /// `limit` smallest qualifying blue_scores, in ascending order — the same
    /// observable result the old "collect everything, sort, take(limit)"
    /// implementation produced (now via the (blue_score, hash) index range
    /// read, B1-T3 / B2-T5; `sync_index_tests` cross-checks it at random).
    /// Reverting to a naive `.filter().collect()` without the `limit`
    /// respected before materialising would still pass this on correctness,
    /// but the point of the invariant is memory/CPU, not just the return
    /// value — see `ordered_hashes_from_never_returns_more_than_limit` below
    /// for the bound this test's sibling pins.
    #[test]
    fn ordered_hashes_from_ascending_and_correct() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        for i in 1..=10u8 {
            let b = make_hash(i);
            dag.add_block(b, vec![prev], i as u64, 1000u128 + i as u128).unwrap();
            prev = b;
        }
        // blue_scores present: 0..=10. Ask from 3, limit 4 -> expect the four
        // smallest qualifying scores: 3,4,5,6 (hashes 3,4,5,6), ascending.
        let got = dag.ordered_hashes_from(3, 4);
        assert_eq!(
            got,
            vec![make_hash(3), make_hash(4), make_hash(5), make_hash(6)],
            "must return the smallest `limit` qualifying blue_scores, ascending"
        );
    }

    /// H-R3-1 regression: `limit` bounds the OUTPUT (and, by construction of
    /// the fix, the heap's peak memory) regardless of how many blocks in the
    /// DAG satisfy `blue_score >= from_blue_score`. This is the property a
    /// naive revert-to-full-sort would still satisfy for correctness of the
    /// truncation itself, but pairs with the doc-invariant above: the fix is
    /// that the heap here never holds more than `limit` entries at any point
    /// during the scan, not merely that the final `Vec` is short.
    #[test]
    fn ordered_hashes_from_never_returns_more_than_limit() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        for i in 1..=50u8 {
            let b = make_hash(i);
            dag.add_block(b, vec![prev], i as u64, 1000u128 + i as u128).unwrap();
            prev = b;
        }
        let got = dag.ordered_hashes_from(0, 5);
        assert_eq!(got.len(), 5, "limit must bound the result even with 51 qualifying blocks");
        assert_eq!(got, vec![make_hash(0), make_hash(1), make_hash(2), make_hash(3), make_hash(4)]);

        // limit larger than the qualifying set returns everything, still ascending.
        let all = dag.ordered_hashes_from(48, 100);
        assert_eq!(all, vec![make_hash(48), make_hash(49), make_hash(50)]);

        // limit == 0 returns empty without touching the store.
        assert_eq!(dag.ordered_hashes_from(0, 0), Vec::<BlockHash>::new());
    }

    #[test]
    fn missing_selected_parent_is_rejected_not_panic() {
        // Audit M-9 completion: a block whose parent is unknown to the DAG
        // must return ConsensusError::MissingSelectedParent, never panic.
        let mut dag = GhostDAG::with_k(3);
        dag.add_genesis(make_hash(0), 0);

        let unknown_parent = make_hash(200);
        let child = make_hash(201);
        let err = dag.add_block(child, vec![unknown_parent], 1, 1000).unwrap_err();
        assert!(matches!(err, ConsensusError::MissingSelectedParent(p) if p == unknown_parent));
        // DAG must be unchanged — only genesis present.
        assert_eq!(dag.block_count(), 1);
        assert!(!dag.store.has(&child));
    }

    #[test]
    fn parallel_blocks_merged() {
        //  G ─ A
        //  └── B
        //      └── C (merges A and B)
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        let a = make_hash(1);
        let b = make_hash(2);
        let c = make_hash(3);

        dag.add_genesis(g, 0);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        dag.add_block(b, vec![g], 2, 1000).unwrap();
        // C references both A and B
        let data_c = dag.add_block(c, vec![a, b], 3, 1000).unwrap();

        // C should merge both A and B — both should be blue (k=3)
        assert!(!data_c.mergeset_blues.is_empty() || !data_c.mergeset_reds.is_empty());
        assert!(dag.block_count() == 4);
    }

    #[test]
    fn selected_parent_is_highest_blue_work() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        // Chain 1: g -> a -> b (blue_score 2)
        let a = make_hash(1);
        let b = make_hash(2);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        dag.add_block(b, vec![a], 2, 1000).unwrap();

        // Chain 2: g -> c (blue_score 1)
        let c = make_hash(3);
        dag.add_block(c, vec![g], 3, 1000).unwrap();

        // Block d merges b and c — selected parent should be b (higher blue_score)
        let d = make_hash(4);
        let data_d = dag.add_block(d, vec![b, c], 4, 1000).unwrap();
        assert_eq!(data_d.selected_parent, Some(b));
    }

    #[test]
    fn tips_updated_correctly() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        assert_eq!(dag.tips().len(), 1);

        let a = make_hash(1);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        // g is no longer a tip
        assert!(!dag.store.tips.contains(&g));
        assert!(dag.store.tips.contains(&a));

        // Two parallel blocks
        let b = make_hash(2);
        let cc = make_hash(3);
        dag.add_block(b, vec![a], 2, 1000).unwrap();
        dag.add_block(cc, vec![a], 3, 1000).unwrap();
        assert_eq!(dag.tips().len(), 2);

        // Merge them
        let d = make_hash(4);
        dag.add_block(d, vec![b, cc], 4, 1000).unwrap();
        assert_eq!(dag.tips().len(), 1);
    }

    #[test]
    fn selected_chain_is_consistent() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        for i in 1u8..=10 {
            let h = make_hash(i);
            dag.add_block(h, vec![make_hash(i-1)], i as u64, 1000).unwrap();
        }
        let chain = dag.selected_chain();
        assert_eq!(chain.len(), 11); // genesis + 10 blocks
        assert_eq!(chain[0], make_hash(10)); // tip first
        assert_eq!(*chain.last().unwrap(), g);
    }

    // ── M-9 regression tests ────────────────────────────────────────────────

    #[test]
    fn add_block_rejects_no_parents() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        // A block with no parents must not be accepted — only genesis is
        // allowed to have zero parents, and genesis uses add_genesis().
        let orphan = make_hash(99);
        let err = dag.add_block(orphan, vec![], 1, 1000).unwrap_err();
        assert_eq!(err, ConsensusError::NoParents);
        // Store must be untouched
        assert!(dag.store.get(&orphan).is_none());
        assert_eq!(dag.block_count(), 1);
    }

    #[test]
    fn add_block_rejects_duplicate_hash() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let a = make_hash(1);
        dag.add_block(a, vec![g], 1, 1000).unwrap();

        // Second attempt with the same hash must fail without panicking.
        let err = dag.add_block(a, vec![g], 2, 1000).unwrap_err();
        assert_eq!(err, ConsensusError::DuplicateBlock(a));
        assert_eq!(dag.block_count(), 2); // g + a, not 3
    }

    #[test]
    fn add_block_errors_are_not_fatal_to_subsequent_blocks() {
        // Key property of the M-9 fix: a bad call no longer aborts the
        // process, so the DAG can keep accepting valid blocks after it.
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let _ = dag.add_block(make_hash(50), vec![], 1, 1000); // bad: no parents
        let _ = dag.add_block(g, vec![g], 1, 1000);            // bad: duplicate

        // The DAG is still usable.
        let a = make_hash(1);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        assert_eq!(dag.store.get(&a).unwrap().blue_score, 1);
    }

    // ── H-5 regression tests ────────────────────────────────────────────────

    #[test]
    fn past_blue_set_walks_beyond_old_2k_bound() {
        // H-5 regression test.
        //
        // The previous bound was `self.k * 2` selected-chain hops (20 hops
        // when K=10). Any blue block deeper than 20 hops was silently
        // dropped from past_blue_set, under-counting the anticone — the
        // core symptom of audit H-5.
        //
        // We cannot exercise the bound with a linear chain because
        // `mergeset_blues` is empty at every linear position (no
        // sibling blocks merging in). So we build 30 iterations of
        //
        //     Left_i  = [prev]
        //     Right_i = [prev]          (sibling of Left_i)
        //     Merge_i = [Left_i, Right_i]
        //     prev = Merge_i
        //
        // Each Merge_i contributes exactly one block to its
        // `mergeset_blues` (the non-selected one of Left_i / Right_i),
        // so past_blue_set picks up 1 blue per Merge encountered on the
        // selected chain. K=100 is chosen large enough that every
        // mergeset block stays blue — the test is about the bound, not
        // PHANTOM classification logic.
        //
        // The selected chain from the tip is
        //     Merge_30 → SelectedSibling_30 → Merge_29 → SelectedSibling_29
        //              → ... → SelectedSibling_1 → G
        // — 61 hops total. With the old K*2=200 bound (K=100 here) we'd
        // walk all 61 hops anyway, so we pick K=10 to exercise the OLD
        // failure mode. But K=10 means PHANTOM's K-constraint kicks in
        // and some mergeset blocks go red. To sidestep that, we build
        // with K=100 and construct a chain ≥ 200 hops so the old bound
        // (2*K=200) would still truncate it.
        //
        // 80 iterations × (3 blocks per iteration) = 240 blocks.
        // Selected chain from tip: 2 hops per iteration × 80 + genesis = 161
        // hops. That's below the old 2*K=200 bound, so let's push further.
        // 110 iterations → 221 hops on the selected chain, and 110 blues in
        // mergeset_blues. Old bound (200) truncates at Merge_~10, giving
        // ~100 blues. New bound (K*100 = 10_000) walks everything.

        fn h(kind: u8, i: u16) -> BlockHash {
            let mut out = [0u8; 32];
            out[0] = kind;
            out[1] = (i >> 8) as u8;
            out[2] = (i & 0xff) as u8;
            out
        }

        let mut dag = GhostDAG::with_k(100);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let iterations: u16 = 110;
        let mut prev = g;
        for i in 1..=iterations {
            let l = h(b'L', i);
            let r = h(b'R', i);
            let m = h(b'M', i);
            dag.add_block(l, vec![prev], (3 * i) as u64, 1000).unwrap();
            dag.add_block(r, vec![prev], (3 * i + 1) as u64, 1000).unwrap();
            dag.add_block(m, vec![l, r], (3 * i + 2) as u64, 1000).unwrap();
            prev = m;
        }

        let blues = dag.past_blue_set(&prev);

        // With K=100, old bound = 2*K = 200 selected-chain hops. We have 221
        // hops on the selected chain and 110 Merges contributing one blue
        // each. Old bound truncates at hop 200 (after ~100 Merges walked) →
        // ~100 blues. New bound (K*100 = 10_000) walks all 221 hops → 110
        // blues. Assert strictly > old maximum to prove we're past it.
        assert!(
            blues.len() > 100,
            "past_blue_set returned only {} blues from a {}-iteration \
             merging DAG (chain length ~{} hops). Old 2*K=200 bound would \
             give about 100; new K*100=10000 bound should give {}. \
             H-5 fix has regressed.",
            blues.len(),
            iterations,
            2 * iterations + 1,
            iterations,
        );
    }

    /// Property-only check: the `past_blue_set` code path must not panic or
    /// loop on a long linear chain. This is a weaker regression guard than
    /// the merging-DAG test above — linear chains have empty mergesets at
    /// every position, so this call returns {} by construction — but it
    /// pins the invariant that the bound-increase doesn't break the
    /// traversal shape.
    #[test]
    fn past_blue_set_long_linear_chain_does_not_panic() {
        let mut dag = GhostDAG::with_k(10);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        for i in 1u16..=200 {
            let mut hx = [0u8; 32];
            hx[0] = (i >> 8) as u8;
            hx[1] = (i & 0xff) as u8;
            hx[2] = 0xaa;
            dag.add_block(hx, vec![prev], i as u64, 1000).unwrap();
            prev = hx;
        }
        // Linear chain → empty mergesets at every position → {} result.
        // The assertion is merely that we completed without panicking.
        let blues = dag.past_blue_set(&prev);
        assert_eq!(
            blues.len(), 0,
            "linear chain has no merges, so past_blue_set must be empty; \
             got {} entries — this indicates a new code path was added \
             that the bound test must account for",
            blues.len(),
        );
    }
}

// ── Property-based GhostDAG invariants (security scanner lane) ───────────────
//
// GhostDAG ordering is consensus-critical: if two honest nodes colour the same
// DAG differently — because block/parent ingestion order leaked into the result,
// or because a `HashMap` iteration order made colouring nondeterministic — they
// disagree on `blue_score`, hence on the selected chain, hence they fork. These
// `proptest` cases build randomly-shaped DAGs and assert the ordering is a pure
// deterministic function of the DAG structure alone. Run with:
//   `cargo test -p bloch ghostdag_proptest`
#[cfg(test)]
mod ghostdag_proptest {
    use super::*;
    use proptest::prelude::*;

    fn idx_hash(i: usize) -> BlockHash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&(i as u64).to_le_bytes());
        h
    }

    /// Build a DAG from a structural description. `shape[i]` is the parent-index
    /// set of block `i` (block 0 is genesis, always empty). `reverse` flips each
    /// parent vector to probe parent-order independence; `k` is the GhostDAG
    /// anticone bound.
    fn build(shape: &[Vec<usize>], k: usize, reverse: bool) -> GhostDAG {
        let mut dag = GhostDAG::with_k(k);
        dag.add_genesis(idx_hash(0), 0);
        for (i, parents) in shape.iter().enumerate().skip(1) {
            let mut ph: Vec<BlockHash> = parents.iter().map(|&j| idx_hash(j)).collect();
            if reverse {
                ph.reverse();
            }
            dag.add_block(idx_hash(i), ph, i as u64, 1000)
                .expect("well-formed block must be accepted");
        }
        dag
    }

    /// Same as `build` with an explicit hardening activation height (0 = the
    /// corrected rules from genesis; a mid-DAG height mixes both regimes).
    fn build_at(shape: &[Vec<usize>], k: usize, reverse: bool, activation: u64) -> GhostDAG {
        let mut dag = GhostDAG::with_k_and_activation(k, activation);
        dag.add_genesis(idx_hash(0), 0);
        for (i, parents) in shape.iter().enumerate().skip(1) {
            let mut ph: Vec<BlockHash> = parents.iter().map(|&j| idx_hash(j)).collect();
            if reverse {
                ph.reverse();
            }
            // Vary the work so blue work (DAG-3) is exercised, deterministically.
            let work = 1 + (i as u128 * 7919) % 1000;
            dag.add_block(idx_hash(i), ph, i as u64, work)
                .expect("well-formed block must be accepted");
        }
        dag
    }

    /// Activation heights for the hardened proptests: from genesis, or inside
    /// the DAG so both regimes and the boundary are exercised.
    fn activation_height() -> impl Strategy<Value = u64> {
        prop_oneof![Just(0u64), 1u64..12]
    }

    /// A structurally valid DAG shape: block `i` (>0) has a non-empty parent set
    /// drawn from `{0..i}`, so parents always exist when added in index order.
    fn dag_shape() -> impl Strategy<Value = (Vec<Vec<usize>>, usize)> {
        (proptest::collection::vec(any::<u64>(), 1..18usize), 1usize..6)
            .prop_map(|(seeds, k)| {
                let n = seeds.len();
                let mut shape: Vec<Vec<usize>> = Vec::with_capacity(n);
                for (i, seed) in seeds.iter().enumerate() {
                    if i == 0 {
                        shape.push(vec![]);
                        continue;
                    }
                    let mut parents: Vec<usize> =
                        (0..i).filter(|j| (seed >> (j % 64)) & 1 == 1).collect();
                    if parents.is_empty() {
                        parents.push(i - 1);
                    }
                    shape.push(parents);
                }
                (shape, k)
            })
    }

    proptest! {
        // Determinism: colouring the identical DAG twice yields byte-identical
        // per-block data. Catches any nondeterminism (e.g. HashMap iteration
        // order) leaking into blue_score / blue_work / selected_parent.
        #[test]
        fn colouring_is_deterministic((shape, k) in dag_shape()) {
            let a = build(&shape, k, false);
            let b = build(&shape, k, false);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                let da = a.get_block_data(&h).unwrap();
                let db = b.get_block_data(&h).unwrap();
                prop_assert_eq!(da.blue_score, db.blue_score);
                prop_assert_eq!(da.blue_work, db.blue_work);
                prop_assert_eq!(da.selected_parent, db.selected_parent);
                prop_assert_eq!(da.height, db.height);
            }
        }

        // Parent-order independence: reversing every parent vector (as gossip
        // reordering would) must not change any block's colouring. A failure
        // here is a consensus-split vulnerability.
        #[test]
        fn colouring_ignores_parent_order((shape, k) in dag_shape()) {
            let fwd = build(&shape, k, false);
            let rev = build(&shape, k, true);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                let df = fwd.get_block_data(&h).unwrap();
                let dr = rev.get_block_data(&h).unwrap();
                prop_assert_eq!(df.blue_score, dr.blue_score, "blue_score depends on parent order at block {}", i);
                prop_assert_eq!(df.blue_work, dr.blue_work);
                prop_assert_eq!(df.selected_parent, dr.selected_parent);
                prop_assert_eq!(df.height, dr.height);
            }
        }

        // Monotonicity: every non-genesis block dominates its selected parent in
        // blue_score and blue_work, and strictly increases height. Genesis is 0.
        #[test]
        fn blue_score_monotone_over_selected_parent((shape, k) in dag_shape()) {
            let dag = build(&shape, k, false);
            prop_assert_eq!(dag.get_block_data(&idx_hash(0)).unwrap().blue_score, 0);
            for i in 1..shape.len() {
                let d = dag.get_block_data(&idx_hash(i)).unwrap();
                let sp = d.selected_parent.expect("non-genesis has a selected parent");
                let sd = dag.get_block_data(&sp).unwrap();
                prop_assert!(d.blue_score >= sd.blue_score, "blue_score regressed vs selected parent at block {}", i);
                prop_assert!(d.blue_work >= sd.blue_work, "blue_work regressed vs selected parent at block {}", i);
                prop_assert!(d.height >= sd.height + 1, "height did not increase over selected parent at block {}", i);
            }
        }

        // The selected chain (tip → genesis) has non-increasing blue_score.
        #[test]
        fn selected_chain_blue_score_non_increasing((shape, k) in dag_shape()) {
            let dag = build(&shape, k, false);
            let chain = dag.selected_chain();
            for w in chain.windows(2) {
                let child = dag.get_block_data(&w[0]).unwrap();
                let parent = dag.get_block_data(&w[1]).unwrap();
                prop_assert!(child.blue_score >= parent.blue_score);
            }
        }

        // topological_order is a valid, complete, deterministic linearisation:
        // it lists every block exactly once and always places a block after all
        // of its parents.
        #[test]
        fn topological_order_is_valid_and_deterministic((shape, k) in dag_shape()) {
            let dag = build(&shape, k, false);
            let ord = dag.topological_order().expect("topological order must exist for a DAG");
            prop_assert_eq!(ord.len(), dag.block_count());
            let pos: std::collections::HashMap<BlockHash, usize> =
                ord.iter().enumerate().map(|(p, h)| (*h, p)).collect();
            for i in 0..shape.len() {
                let h = idx_hash(i);
                let d = dag.get_block_data(&h).unwrap();
                for p in &d.parents {
                    prop_assert!(pos[p] < pos[&h], "parent ordered after child at block {}", i);
                }
            }
            // Determinism: recomputing on an independently-built DAG matches.
            let dag2 = build(&shape, k, false);
            prop_assert_eq!(ord, dag2.topological_order().unwrap());
        }

        // ── Hardened (post-activation and mixed) regimes ──────────────────

        // Determinism of the full canonical data, every field included.
        #[test]
        fn hardened_colouring_is_deterministic((shape, k) in dag_shape(), act in activation_height()) {
            let a = build_at(&shape, k, false, act);
            let b = build_at(&shape, k, false, act);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                prop_assert_eq!(
                    canonical_encode(a.get_block_data(&h).unwrap()),
                    canonical_encode(b.get_block_data(&h).unwrap())
                );
            }
        }

        // Parent-order independence of the full canonical data (canonical
        // encoding sorts the parent list, everything else must match).
        #[test]
        fn hardened_colouring_ignores_parent_order((shape, k) in dag_shape(), act in activation_height()) {
            let fwd = build_at(&shape, k, false, act);
            let rev = build_at(&shape, k, true, act);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                prop_assert_eq!(
                    canonical_encode(fwd.get_block_data(&h).unwrap()),
                    canonical_encode(rev.get_block_data(&h).unwrap()),
                    "block {} depends on parent order", i
                );
            }
            prop_assert_eq!(fwd.selected_tip(), rev.selected_tip());
        }

        // Monotonicity and DAG-3 blue work: a hardened block's blue work is its
        // selected parent's plus the work of its merged blues plus its own, so
        // it strictly exceeds the selected parent's; blue_score counts blues.
        #[test]
        fn hardened_blue_work_and_score((shape, k) in dag_shape(), act in activation_height()) {
            let dag = build_at(&shape, k, false, act);
            for i in 1..shape.len() {
                let d = dag.get_block_data(&idx_hash(i)).unwrap();
                let sp = d.selected_parent.expect("non-genesis has a selected parent");
                let sd = dag.get_block_data(&sp).unwrap();
                let own = 1 + (i as u128 * 7919) % 1000;
                let merged: u128 = d.mergeset_blues.iter()
                    .map(|m| {
                        let j = u64::from_le_bytes(m[..8].try_into().unwrap()) as u128;
                        1 + (j * 7919) % 1000
                    })
                    .sum();
                if dag.is_hardened_at(d.height) {
                    prop_assert_eq!(d.blue_work, sd.blue_work + merged + own);
                    // Exact coloring: at most k blues besides the selected parent.
                    prop_assert!(d.mergeset_blues.len() <= k);
                } else {
                    prop_assert_eq!(d.blue_work, sd.blue_work + own);
                }
                prop_assert_eq!(d.blue_score, sd.blue_score + d.mergeset_blues.len() as u64 + 1);
                prop_assert!(d.height == sd.height + 1);
            }
        }

        // Below the activation, the hardened DAG and a never-activating DAG
        // agree on every block whose whole past is below the activation.
        #[test]
        fn hardened_keeps_old_data_below_activation((shape, k) in dag_shape(), act in 1u64..12) {
            let mixed = build_at(&shape, k, false, act);
            let never = build_at(&shape, k, false, u64::MAX);
            let mut below = vec![false; shape.len()];
            below[0] = true;
            for i in 1..shape.len() {
                let d = never.get_block_data(&idx_hash(i)).unwrap();
                below[i] = d.height < act && shape[i].iter().all(|&j| below[j]);
                if below[i] {
                    prop_assert_eq!(
                        canonical_encode(mixed.get_block_data(&idx_hash(i)).unwrap()),
                        canonical_encode(d)
                    );
                }
            }
        }
    }
}

// ── Hardening unit tests (audit DAG-3 / DAG-4 / DAG-7) ───────────────────────

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn h(tag: u8, i: u64) -> BlockHash {
        let mut out = [0u8; 32];
        out[0] = tag;
        out[1..9].copy_from_slice(&i.to_be_bytes());
        out
    }

    #[test]
    fn default_constructors_follow_the_process_activation_height() {
        // Unit tests never set the chain id: mainnet schedule.
        assert_eq!(
            GhostDAG::with_default_k().hardening_activation_height(),
            activation::hardening_activation_height()
        );
        {
            let _g = activation::scoped_override(0);
            assert_eq!(GhostDAG::with_k(3).hardening_activation_height(), 0);
            assert_eq!(GhostDAG::with_k_fast(3).hardening_activation_height(), 0);
        }
        let dag = GhostDAG::with_k(3).with_hardening_activation(7);
        assert!(!dag.is_hardened_at(6));
        assert!(dag.is_hardened_at(7));
    }

    #[test]
    #[should_panic(expected = "before blocks are added")]
    fn activation_height_cannot_change_after_blocks_exist() {
        let mut dag = GhostDAG::with_k_and_activation(3, 0);
        dag.add_genesis(h(0, 0), 0);
        let _ = dag.with_hardening_activation(5);
    }

    /// `work_of` recovers the exact work of every block from stored data
    /// alone (as after a restart), in both regimes and across the boundary.
    #[test]
    fn work_is_recovered_from_stored_data() {
        let mut dag = GhostDAG::with_k_and_activation(3, 4);
        let g = h(0, 0);
        dag.add_genesis(g, 0);
        let mut works = HashMap::new();
        let mut tips = vec![g];
        for i in 1..=40u64 {
            let w = 1 + (i as u128 * 37) % 50;
            let mut parents = vec![tips[tips.len() - 1]];
            if i % 3 == 0 && tips.len() > 2 {
                parents.push(tips[tips.len() - 3]);
            }
            let b = h(1, i);
            dag.add_block(b, parents, i, w).unwrap();
            works.insert(b, w);
            tips.push(b);
        }
        let mut fresh = GhostDAG::with_k_and_activation(3, 4);
        fresh.load_persisted(dag.store.data.iter().map(|(k, v)| (*k, v.clone())).collect());
        let mut memo = HashMap::new();
        for (b, w) in &works {
            assert_eq!(fresh.work_of(b, &mut memo), *w, "work of {}", hex::encode(&b[..9]));
        }
        assert_eq!(fresh.work_of(&g, &mut memo), 0);
    }

    /// Removing a just-added block clears its cache entries; re-adding it
    /// gives the same data.
    #[test]
    fn remove_and_re_add_is_identical() {
        for act in [0u64, u64::MAX] {
            let mut dag = GhostDAG::with_k_and_activation(3, act);
            let g = h(0, 0);
            dag.add_genesis(g, 0);
            let a = h(1, 1);
            let b = h(1, 2);
            dag.add_block(a, vec![g], 1, 10).unwrap();
            dag.add_block(b, vec![g], 1, 20).unwrap();
            let m = h(1, 3);
            let first = dag.add_block(m, vec![a, b], 2, 30).unwrap();
            assert!(dag.remove_block(&m));
            assert!(!dag.block_work.contains_key(&m) && !dag.merge_skip.contains_key(&m));
            let again = dag.add_block(m, vec![a, b], 2, 30).unwrap();
            assert_eq!(canonical_encode(&first), canonical_encode(&again));
        }
    }

    /// The pre-activation skip pointers name the nearest merging block on the
    /// selected chain, and a DAG without them (fallback walk) agrees.
    #[test]
    fn merge_skip_pointers_are_correct() {
        let mut dag = GhostDAG::with_k_and_activation(5, u64::MAX);
        let g = h(0, 0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        let mut merging = None;
        for i in 1..=30u64 {
            let b = h(1, i);
            let mut parents = vec![prev];
            if i % 7 == 0 {
                let s = h(2, i);
                dag.add_block(s, vec![prev], i, 1).unwrap();
                parents.push(s);
            }
            dag.add_block(b, parents, i, 1000).unwrap();
            if !dag.get_block_data(&b).unwrap().mergeset_blues.is_empty() {
                merging = Some(b);
            }
            assert_eq!(dag.merge_skip.get(&b).copied(), Some(merging), "block {i}");
            prev = b;
        }
        // Rebuilding the cache from scratch gives the same pointers.
        let cached = dag.merge_skip.clone();
        dag.merge_skip.clear();
        dag.ensure_merge_skip(&prev);
        for (k, v) in &dag.merge_skip {
            assert_eq!(cached.get(k), Some(v));
        }
    }

    /// The index-based mergeset equals the O(past) one, in content and order.
    #[test]
    fn bounded_mergeset_equals_compute_past_mergeset() {
        let mut dag = GhostDAG::with_k_and_activation(4, u64::MAX);
        let g = h(0, 0);
        dag.add_genesis(g, 0);
        let mut all = vec![g];
        let mut state = 0x1234_5678_9ABC_DEF1u64;
        for i in 1..=150u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let n = all.len();
            let mut parents = vec![all[n - 1 - (state as usize % n.min(5))]];
            for j in 0..(state % 4) as usize {
                let p = all[(state as usize >> (8 + j * 8)) % n];
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
            let sp = dag.select_parent(&parents);
            let a = compute_mergeset(&dag.store, &parents, &sp);
            let b = dag.compute_mergeset_bounded(&parents, &sp, None).unwrap();
            assert_eq!(a, b, "block {i}");
            let blk = h(1, i);
            dag.add_block(blk, parents, i, 1 + state as u128 % 100).unwrap();
            all.push(blk);
        }
    }
}

/// Audit B1-T3 / B2-T5 / B2-T7: the ordered indexes of `DagStore` (sync
/// serving) are derived state; these tests check them against the store
/// itself, and the index-driven `selected_tip` against the full-heap search,
/// over random DAGs with random disqualified sets, removals and reloads.
#[cfg(test)]
mod sync_index_tests {
    use super::*;

    fn h(i: u64) -> BlockHash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_be_bytes());
        b[31] = 0x1D;
        b
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// The two ordered indexes equal what they index.
    fn assert_indexes_consistent(dag: &GhostDAG) {
        let by_score: BTreeSet<(u64, BlockHash)> = dag.store.data.iter().map(|(h, d)| (d.blue_score, *h)).collect();
        assert_eq!(dag.store.by_score, by_score, "(blue_score, hash) index");
        let tips: BTreeSet<TipKey> = dag.store.tips.iter()
            .map(|h| {
                let d = &dag.store.data[h];
                (d.blue_work, d.blue_score, *h)
            })
            .collect();
        assert_eq!(dag.store.tips_by_work, tips, "tip index");
        for t in &dag.store.tips {
            assert!(dag.store.children.get(t).is_none_or(|c| c.is_empty()), "a tip with children");
        }
    }

    /// `tips_for_peers` by brute force: every tip sorted by GhostDAG's tip
    /// order, the unmemoized `selectable`, the same `4 × max` read cap.
    fn tips_for_peers_reference(dag: &GhostDAG, max: usize) -> Vec<BlockHash> {
        if max == 0 {
            return Vec::new();
        }
        let selected = dag.selected_tip_reference();
        let mut out: Vec<BlockHash> = selected.into_iter().collect();
        let mut tips: Vec<TipKey> = dag.store.tips.iter().map(|t| dag.order_key(t)).collect();
        tips.sort_unstable_by(|a, b| b.cmp(a));
        for (_, _, t) in tips.into_iter().take(4 * max) {
            if out.len() >= max {
                break;
            }
            if Some(t) != selected && dag.selectable(&t) {
                out.push(t);
            }
        }
        for t in &out {
            assert!(dag.selectable(t), "an unselectable tip in the reference");
        }
        out
    }

    /// `ordered_hashes_from` by brute force (the pre-index algorithm).
    fn ordered_reference(dag: &GhostDAG, from: u64, limit: usize) -> Vec<BlockHash> {
        let mut v: Vec<(u64, BlockHash)> = dag.store.data.iter()
            .filter(|(_, d)| d.blue_score >= from)
            .map(|(h, d)| (d.blue_score, *h))
            .collect();
        v.sort_unstable();
        v.into_iter().take(limit).map(|(_, h)| h).collect()
    }

    fn random_dag(seed: u64, n: u64, rng: &mut Rng) -> (GhostDAG, Vec<BlockHash>) {
        let mut dag = GhostDAG::with_k_and_activation(4, u64::MAX);
        let g = h(seed << 32);
        dag.add_genesis(g, 0);
        let mut all = vec![g];
        for i in 1..=n {
            let len = all.len();
            let mut parents = vec![all[len - 1 - (rng.next() as usize % len.min(6))]];
            for _ in 0..(rng.next() % 3) {
                let p = all[rng.next() as usize % len];
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
            let b = h((seed << 32) + i);
            if dag.add_block(b, parents, i, 1 + u128::from(rng.next() % 50)).is_ok() {
                all.push(b);
            }
        }
        (dag, all)
    }

    #[test]
    fn indexes_and_selected_tip_match_the_reference() {
        let mut rng = Rng(0x5EED_0F51_DE7E_5701);
        for seed in 1..=12u64 {
            let (mut dag, all) = random_dag(seed, 120, &mut rng);
            assert_indexes_consistent(&dag);
            assert_eq!(dag.selected_tip(), dag.selected_tip_reference(), "seed {seed}: no invalid block");
            // Disqualify random blocks (with their selected-chain closure).
            for _ in 0..(1 + rng.next() % 12) {
                let x = all[1 + rng.next() as usize % (all.len() - 1)];
                dag.mark_invalid(x);
                assert_eq!(dag.selected_tip(), dag.selected_tip_reference(), "seed {seed}: after invalidating");
            }
            // A PoWit finalized checkpoint (main's `set_finalized`): on the
            // selected chain for even seeds, anywhere for odd ones. The
            // memoized finality walk gives the reference's answers.
            let fin = if seed % 2 == 0 {
                let chain = dag.selected_chain();
                chain[chain.len() / 2]
            } else {
                all[rng.next() as usize % all.len()]
            };
            let fin_height = dag.get_block_data(&fin).unwrap().height;
            dag.set_finalized(fin, fin_height);
            assert_eq!(dag.selected_tip(), dag.selected_tip_reference(), "seed {seed}: with a finalized checkpoint");
            for max in [0usize, 1, 3, 8, 64] {
                assert_eq!(dag.tips_for_peers(max), tips_for_peers_reference(&dag, max), "seed {seed}: max {max}");
            }
            // Range reads equal the brute-force scan.
            for _ in 0..20 {
                let from = rng.next() % 140;
                let limit = (rng.next() % 60) as usize;
                assert_eq!(dag.ordered_hashes_from(from, limit), ordered_reference(&dag, from, limit), "seed {seed}");
            }
            // Remove leaves: the indexes follow.
            for _ in 0..10 {
                let mut tips: Vec<BlockHash> =
                    dag.store.tips.iter().copied().filter(|t| Some(*t) != dag.store.genesis).collect();
                if tips.is_empty() {
                    break;
                }
                tips.sort_unstable();
                assert!(dag.remove_block(&tips[rng.next() as usize % tips.len()]));
                assert_indexes_consistent(&dag);
                assert_eq!(dag.selected_tip(), dag.selected_tip_reference(), "seed {seed}: after a removal");
            }
            // A reload rebuilds the same indexes.
            let entries: Vec<(BlockHash, GhostdagData)> = dag.store.data.iter().map(|(h, d)| (*h, d.clone())).collect();
            let mut reloaded = GhostDAG::with_k_and_activation(4, u64::MAX);
            reloaded.load_persisted(entries);
            assert_indexes_consistent(&reloaded);
            assert_eq!(reloaded.store.tips_by_work, dag.store.tips_by_work, "seed {seed}: reload");
            assert_eq!(reloaded.store.by_score, dag.store.by_score);
        }
    }

    /// The advertised frontier: selected tip first, then valid tips by
    /// blue work, never a disqualified one, at most `max`.
    #[test]
    fn tips_for_peers_is_the_best_valid_frontier() {
        let mut dag = GhostDAG::with_k_and_activation(10, u64::MAX);
        let g = h(0);
        dag.add_genesis(g, 0);
        for i in 1..=40u64 {
            dag.add_block(h(i), vec![g], i, 100 + u128::from(i)).unwrap();
        }
        for i in 36..=40u64 {
            dag.mark_invalid(h(i));
        }
        let t = dag.tips_for_peers(10);
        assert_eq!(t, (26..=35u64).rev().map(h).collect::<Vec<_>>());
        assert_eq!(dag.tips_for_peers(0), Vec::<BlockHash>::new());
        assert_eq!(dag.tips_for_peers(1000).len(), 35);
        // The selected tip leads even when it is not a leaf (its only child
        // is disqualified).
        dag.add_block(h(100), vec![h(35)], 100, 1).unwrap();
        dag.mark_invalid(h(100));
        assert_eq!(dag.tips_for_peers(3), vec![h(35), h(34), h(33)]);
    }

    /// PoWit finality (main's `set_finalized`): a tip whose selected chain
    /// misses the finalized checkpoint is never selected nor merged by a
    /// template (`valid_tips`), so it is not advertised either; tips that
    /// fork above the checkpoint are. The finality walk is shared by the
    /// tips whose chains meet: its reads do not grow with the number of
    /// such tips times the distance to the checkpoint.
    #[test]
    fn tips_for_peers_skips_tips_that_conflict_with_finality() {
        let mut dag = GhostDAG::with_k_and_activation(10, u64::MAX);
        let g = h(0);
        dag.add_genesis(g, 0);
        // The chain c1..c60, heavy.
        for i in 1..=60u64 {
            dag.add_block(h(i), vec![h(i - 1)], i, 1_000).unwrap();
        }
        // Stale siblings of c1 (they fork below the checkpoint).
        for i in 0..10u64 {
            dag.add_block(h(200 + i), vec![g], 200 + i, 1 + u128::from(i)).unwrap();
        }
        // Side tips off c50 (above the checkpoint), all lighter than c60.
        for i in 0..10u64 {
            dag.add_block(h(300 + i), vec![h(50)], 300 + i, 1 + u128::from(i)).unwrap();
        }
        dag.set_finalized(h(5), 5);
        assert_eq!(dag.selected_tip(), Some(h(60)));
        assert_eq!(dag.selected_tip(), dag.selected_tip_reference());
        let before = dag.query_visits();
        let t = dag.tips_for_peers(64);
        let work = dag.query_visits() - before;
        let mut want = vec![h(60)];
        want.extend((0..10u64).rev().map(|i| h(300 + i)));
        assert_eq!(t, want, "no tip that forks below the checkpoint");
        assert_eq!(t, tips_for_peers_reference(&dag, 64));
        let mut valid = dag.valid_tips();
        valid.sort_unstable();
        let mut advertised = t.clone();
        advertised.sort_unstable();
        assert_eq!(advertised, valid, "advertised = what templates may merge");
        // 21 tips read; c60 walks down to c5 once (56 reads); each side tip
        // reads itself and meets the memo at c50; each stale tip reads
        // itself (below the checkpoint height). Unshared, every side tip
        // would walk 46 blocks again: over 500 reads.
        assert!(work <= 21 + 56 + 10 + 10, "finality walk not shared: {work} reads");
    }
}
