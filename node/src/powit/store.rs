//! PoWit state storage (package A3): per-epoch work segments plus per-block
//! diffs.
//!
//! A block's PoWit state (`PowitState`) holds `window + 2` epochs of share
//! work per key (`epoch_work`). Stored whole per block, as before this
//! layout, every block repeated every closed epoch: with 16 shares a block
//! and a 28- or 112-epoch window that is megabytes per block, decoded again
//! for each child. The state is now split by how it changes:
//!
//! - **Frozen epochs.** `epoch_work[e]` for `e != state.epoch` never changes
//!   again on a chain: `apply_at` credits shares only to the block's own
//!   epoch, which is `state.epoch` after the epoch step, and the step only
//!   drops old epochs (`split_off`). Each frozen epoch is written once, as a
//!   content-addressed segment `powit/epoch/<digest>` that every block (and
//!   every branch) with the same contents shares.
//! - **The current epoch** (`epoch_work[state.epoch]`) grows within an epoch.
//!   A block whose selected parent is in the same epoch stores only the
//!   entries its shares changed (a diff against the parent's record); every
//!   `ANCHOR_EVERY` blocks, at an epoch change, and whenever the parent's
//!   record is not in this layout, the block stores an anchor instead (the
//!   whole current epoch and the digests of the frozen ones), so a load walks
//!   at most `ANCHOR_EVERY - 1` diffs.
//! - **The rest** (checkpoints, votes, links, bans, decay, active keys) is
//!   small and stored whole per block (`powit/sc/<hash>`).
//!
//! Records are node-local (not consensus, not on the wire): the decoded
//! state is exactly the `PowitState` that was staged (tests:
//! `round_trip_*`). All rows of one block, and the segments they reference,
//! are staged in the caller's batch, so a crash leaves either the whole
//! state or none of it; a record only ever references rows already
//! committed or staged in the same batch. Records are never rewritten by the
//! node (a block's state is staged once, `accept::TriggerRecord`); nothing
//! deletes them, so a diff never loses its parent.
//!
//! - **The growth cap** (ObenBlock, `PowitState::cap`, DESIGN-obenblock.md
//!   §6.3): the admitted credit per key per window epoch is stored like the
//!   frozen epochs, as content-addressed segments (`powit/epoch/<digest>`,
//!   the same digest of `(epoch, map)`: a credit map is a key -> u128 map
//!   too). A ledger changes only at a PoCI handoff, so it is stored once per
//!   ledger (`powit/capl/<ledger id>`: its epoch, the segments of its
//!   credits, its last report), and each block stores only the ledger's id
//!   and the first-block bits it keeps (`powit/cap/<hash>`). GnB states
//!   have no ledger and store none of these rows.
//!
//! Compatibility: data dirs written before this layout hold
//! `powit/state/<hash>` (the whole state, bincode). They are read as before
//! when a block has no record in this layout, and a child of such a block
//! is stored as an anchor, so an upgraded node needs no migration step. The
//! layout is one-way: a release before it does not read the new rows.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::storage::Storage;
use gnb_crypto::core::powit::growth_cap::{CapLedger, CapReport, CapState};
use gnb_crypto::core::powit::{KeyId, PowitState};
use primitive_types::U256;

type Hash = [u8; 32];
type EpochWork = BTreeMap<KeyId, u128>;

/// The whole state per block, as written before this layout (read only).
const LEGACY_PREFIX: &str = "powit/state/";
/// Everything but `epoch_work`, per block.
const CORE_PREFIX: &str = "powit/sc/";
/// The block's [`WorkRecord`].
const WORK_PREFIX: &str = "powit/sw/";
/// A frozen epoch's work map, by [`epoch_digest`].
const EPOCH_PREFIX: &str = "powit/epoch/";
/// A block's [`CapRecord`] (ObenBlock).
const CAP_PREFIX: &str = "powit/cap/";
/// A growth cap ledger's [`LedgerRow`], by [`CapLedger::id`].
const CAP_LEDGER_PREFIX: &str = "powit/capl/";
/// Domain tag of a segment digest.
const EPOCH_TAG: &[u8] = b"GNB-POWIT-STORE-v1/epoch";
/// First byte of a core or work row: the layout version.
const RECORD_VERSION: u8 = 1;

/// A block stores an anchor when its parent's record is this many diffs
/// from its own anchor: a load reads at most `ANCHOR_EVERY` work rows.
pub const ANCHOR_EVERY: u32 = 32;
/// Decoded, verified segments kept in memory (by digest; content-addressed,
/// so one cache serves every branch).
const EPOCH_CACHE_CAP: usize = 256;

/// A frozen epoch referenced by an anchor: its segment's digest, number of
/// keys and wrapping sum of work (both checked on decode, and compared
/// before a record inherits the reference from its parent's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FrozenRef {
    epoch: u64,
    digest: Hash,
    keys: u64,
    sum: u128,
}

/// (number of keys, wrapping sum of work) of an epoch's map.
fn fingerprint(m: &EpochWork) -> (u64, u128) {
    (m.len() as u64, m.values().fold(0u128, |a, w| a.wrapping_add(*w)))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum WorkKind {
    /// The frozen epochs by digest and the current epoch's map in full.
    Anchor { frozen: Vec<FrozenRef>, current: Option<EpochWork> },
    /// The current epoch's entries that changed (new values) since the
    /// record of `parent` (same epoch, `depth - 1` diffs from its anchor);
    /// the frozen epochs are the parent's.
    Diff { parent: Hash, depth: u32, changed: Vec<(KeyId, u128)> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WorkRecord {
    /// `state.epoch` of the block.
    epoch: u64,
    kind: WorkKind,
}

/// A block's work record resolved through its diffs.
struct Resolved {
    epoch: u64,
    /// Diffs from the anchor (0 for an anchor).
    depth: u32,
    frozen: Vec<FrozenRef>,
    current: Option<EpochWork>,
}

fn key(prefix: &str, hash: &Hash) -> String {
    format!("{prefix}{}", hex::encode(hash))
}

fn encode<T: Serialize>(v: &T, what: &str) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(v, bincode::config::standard()).map_err(|e| format!("powit {what} encode: {e}"))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    match bincode::serde::decode_from_slice(bytes, bincode::config::standard()) {
        Ok((v, used)) if used == bytes.len() => Some(v),
        _ => None,
    }
}

fn versioned<T: Serialize>(v: &T, what: &str) -> Result<Vec<u8>, String> {
    let mut out = vec![RECORD_VERSION];
    out.extend(encode(v, what)?);
    Ok(out)
}

fn unversioned<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    match bytes.split_first() {
        Some((&RECORD_VERSION, rest)) => decode(rest),
        _ => None,
    }
}

/// Digest of a frozen epoch's encoded map: SHA3-256(tag ‖ u64le(epoch) ‖ bytes).
fn epoch_digest(epoch: u64, bytes: &[u8]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(EPOCH_TAG);
    h.update(epoch.to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

/// The state without `epoch_work` (stored whole per block).
fn core_of(s: &PowitState) -> PowitState {
    PowitState {
        activation: s.activation,
        justified: s.justified,
        finalized: s.finalized,
        finalized_at: s.finalized_at,
        epoch_work: BTreeMap::new(),
        votes: s.votes.clone(),
        links: s.links.clone(),
        banned: s.banned.clone(),
        decay: s.decay.clone(),
        active_this_epoch: s.active_this_epoch.clone(),
        epoch: s.epoch,
        // Not in the serde encoding: node/src/powit.rs stores them in their own rows.
        exited: BTreeMap::new(),
        poci: None,
        cap: None,
    }
}

// ── Growth cap rows (ObenBlock) ──────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CapRecord {
    ledger: Hash,
    first_bits: Vec<(u64, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ReportRow {
    epoch: u64,
    w: u128,
    g: u128,
    /// sum_x, admitted, admitted_new, dropped: 256-bit, little-endian.
    wide: [[u8; 32]; 4],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerRow {
    epoch: u64,
    credits: Vec<FrozenRef>,
    report: Option<ReportRow>,
}

/// Decoded ledgers by id (a handful are live at once: one per configuration
/// in force on the branches the node follows).
static LEDGER_CACHE: Mutex<Option<HashMap<Hash, CapLedger>>> = parking_lot::const_mutex(None);
const LEDGER_CACHE_CAP: usize = 16;

fn report_row(r: &CapReport) -> ReportRow {
    ReportRow { epoch: r.epoch, w: r.w, g: r.g,
                wide: [r.sum_x, r.admitted, r.admitted_new, r.dropped].map(|v| v.to_little_endian()) }
}

fn report_of(r: &ReportRow) -> CapReport {
    let [sum_x, admitted, admitted_new, dropped] = r.wide.map(|b| U256::from_little_endian(&b));
    CapReport { epoch: r.epoch, w: r.w, g: r.g, sum_x, admitted, admitted_new, dropped }
}

fn load_ledger(store: &Storage, id: &Hash) -> Option<CapLedger> {
    if let Some(l) = LEDGER_CACHE.lock().as_ref().and_then(|m| m.get(id).cloned()) {
        return Some(l);
    }
    let row: LedgerRow = unversioned(&store.get_meta(&key(CAP_LEDGER_PREFIX, id)).ok().flatten()?)?;
    let mut credits = BTreeMap::new();
    for f in &row.credits {
        if credits.insert(f.epoch, load_epoch(store, f)?).is_some() {
            return None;
        }
    }
    let ledger = CapLedger::from_parts(row.epoch, credits, row.report.as_ref().map(report_of));
    if ledger.id() != *id {
        return None;
    }
    let mut g = LEDGER_CACHE.lock();
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= LEDGER_CACHE_CAP {
        m.clear();
    }
    m.insert(*id, ledger.clone());
    Some(ledger)
}

/// `hash`'s growth cap state: `Some(None)` when it has none (GnB, or a
/// state stored before the cap), `None` when a row it needs is missing or
/// corrupt.
pub fn load_cap(store: &Storage, hash: &Hash) -> Option<Option<CapState>> {
    let Some(bytes) = store.get_meta(&key(CAP_PREFIX, hash)).ok()? else { return Some(None) };
    let rec: CapRecord = unversioned(&bytes)?;
    let ledger = load_ledger(store, &rec.ledger)?;
    let first_bits: BTreeMap<u64, u32> = rec.first_bits.iter().copied().collect();
    if first_bits.len() != rec.first_bits.len() {
        return None;
    }
    Some(Some(CapState { ledger, first_bits }))
}

/// Stage `state`'s growth cap rows: the block's record, and the ledger with
/// its credit segments unless already stored (by the block whose handoff
/// built it).
pub fn stage_cap(store: &Storage, batch: &mut rocksdb::WriteBatch, hash: &Hash, state: &PowitState)
    -> Result<(), String>
{
    let Some(cap) = &state.cap else { return Ok(()) };
    let err = |e: String| format!("storage: powit growth cap: {e}");
    let id = cap.ledger.id();
    let lkey = key(CAP_LEDGER_PREFIX, &id);
    if store.get_meta(&lkey).map_err(|e| err(e.to_string()))?.is_none() {
        let mut credits = Vec::with_capacity(cap.ledger.credits().len());
        for (n, m) in cap.ledger.credits() {
            let bytes = encode(&**m, "credit")?;
            let digest = epoch_digest(*n, &bytes);
            let k = key(EPOCH_PREFIX, &digest);
            if store.get_meta(&k).map_err(|e| err(e.to_string()))?.is_none() {
                store.stage_meta(batch, &k, &bytes).map_err(|e| err(e.to_string()))?;
            }
            let (keys, sum) = fingerprint(m);
            credits.push(FrozenRef { epoch: *n, digest, keys, sum });
        }
        let row = LedgerRow { epoch: cap.ledger.epoch(), credits, report: cap.ledger.report().map(report_row) };
        store.stage_meta(batch, &lkey, &versioned(&row, "growth cap ledger")?).map_err(|e| err(e.to_string()))?;
    }
    let rec = CapRecord { ledger: id, first_bits: cap.first_bits.iter().map(|(e, b)| (*e, *b)).collect() };
    store.stage_meta(batch, &key(CAP_PREFIX, hash), &versioned(&rec, "growth cap")?).map_err(|e| err(e.to_string()))
}

// ── Segment cache ────────────────────────────────────────────────────────────

struct EpochCache {
    map: HashMap<Hash, Arc<EpochWork>>,
    order: VecDeque<Hash>,
}

static EPOCH_CACHE: Mutex<Option<EpochCache>> = parking_lot::const_mutex(None);

fn cached(digest: &Hash) -> Option<Arc<EpochWork>> {
    EPOCH_CACHE.lock().as_ref().and_then(|c| c.map.get(digest).cloned())
}

fn remember(digest: Hash, m: Arc<EpochWork>) {
    let mut g = EPOCH_CACHE.lock();
    let c = g.get_or_insert_with(|| EpochCache { map: HashMap::new(), order: VecDeque::new() });
    if c.map.insert(digest, m).is_none() {
        c.order.push_back(digest);
        if c.order.len() > EPOCH_CACHE_CAP {
            if let Some(old) = c.order.pop_front() {
                c.map.remove(&old);
            }
        }
    }
}

/// Drop `digest` from the cache (tests: a corrupt row on disk is read again).
#[cfg(test)]
fn forget(digest: &Hash) {
    if let Some(c) = EPOCH_CACHE.lock().as_mut() {
        c.map.remove(digest);
        c.order.retain(|d| d != digest);
    }
}

/// A frozen epoch's map, checked against its digest and key count.
fn load_epoch(store: &Storage, r: &FrozenRef) -> Option<Arc<EpochWork>> {
    if let Some(m) = cached(&r.digest) {
        return Some(m);
    }
    let bytes = store.get_meta(&key(EPOCH_PREFIX, &r.digest)).ok().flatten()?;
    if epoch_digest(r.epoch, &bytes) != r.digest {
        return None;
    }
    let m: EpochWork = decode(&bytes)?;
    if fingerprint(&m) != (r.keys, r.sum) {
        return None;
    }
    let m = Arc::new(m);
    remember(r.digest, m.clone());
    Some(m)
}

// ── Loading ──────────────────────────────────────────────────────────────────

fn read_work(store: &Storage, hash: &Hash) -> Option<WorkRecord> {
    let bytes = store.get_meta(&key(WORK_PREFIX, hash)).ok().flatten()?;
    unversioned(&bytes)
}

/// `hash`'s work record resolved through its diffs, `None` if it has none
/// in this layout or the chain of diffs is broken or malformed.
fn resolve(store: &Storage, hash: &Hash) -> Option<Resolved> {
    let first = read_work(store, hash)?;
    let mut diffs: Vec<Vec<(KeyId, u128)>> = Vec::new();
    let (epoch, depth) = (first.epoch, match &first.kind {
        WorkKind::Anchor { .. } => 0,
        WorkKind::Diff { depth, .. } => *depth,
    });
    if depth >= ANCHOR_EVERY {
        return None;
    }
    let mut rec = first;
    loop {
        match rec.kind {
            WorkKind::Anchor { frozen, current } => {
                if diffs.len() as u32 != depth {
                    return None;
                }
                let mut current = current;
                for changed in diffs.into_iter().rev() {
                    // An empty diff leaves an absent current epoch absent
                    // (a block without shares at the start of an epoch).
                    if changed.is_empty() {
                        continue;
                    }
                    let cur = current.get_or_insert_with(BTreeMap::new);
                    for (k, w) in changed {
                        cur.insert(k, w);
                    }
                }
                return Some(Resolved { epoch, depth, frozen, current });
            }
            WorkKind::Diff { parent, depth: d, changed } => {
                // Each step goes one diff closer to the anchor, in the same epoch.
                if d as usize != depth as usize - diffs.len() || d == 0 {
                    return None;
                }
                diffs.push(changed);
                let next = read_work(store, &parent)?;
                if next.epoch != epoch {
                    return None;
                }
                rec = next;
            }
        }
    }
}

fn load_legacy(store: &Storage, hash: &Hash) -> Option<PowitState> {
    let bytes = store.get_meta(&key(LEGACY_PREFIX, hash)).ok().flatten()?;
    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).ok().map(|(s, _)| s)
}

/// `hash`'s PoWit state: from this layout, else from the layout before it;
/// `None` when it has none or a row it needs is missing or corrupt.
pub fn load(store: &Storage, hash: &Hash) -> Option<PowitState> {
    if store.get_meta(&key(WORK_PREFIX, hash)).ok().flatten().is_none() {
        return load_legacy(store, hash);
    }
    let core_bytes = store.get_meta(&key(CORE_PREFIX, hash)).ok().flatten()?;
    let mut s: PowitState = unversioned(&core_bytes)?;
    if !s.epoch_work.is_empty() {
        return None;
    }
    let r = resolve(store, hash)?;
    if r.epoch != s.epoch {
        return None;
    }
    for f in &r.frozen {
        if f.epoch == s.epoch {
            return None;
        }
        s.epoch_work.insert(f.epoch, (*load_epoch(store, f)?).clone());
    }
    if let Some(cur) = r.current {
        s.epoch_work.insert(s.epoch, cur);
    }
    Some(s)
}

// ── Staging ──────────────────────────────────────────────────────────────────

/// Entries of `child` that are new or changed against `parent`, or `None`
/// when `child` is not `parent` plus entries (an entry dropped, or an empty
/// map a diff cannot express): then the block stores an anchor.
fn changed_entries(parent: Option<&EpochWork>, child: Option<&EpochWork>) -> Option<Vec<(KeyId, u128)>> {
    match (parent, child) {
        (None, None) => Some(Vec::new()),
        (Some(_), None) => None,
        (None, Some(c)) => (!c.is_empty()).then(|| c.iter().map(|(k, w)| (*k, *w)).collect()),
        (Some(p), Some(c)) => {
            if p.keys().any(|k| !c.contains_key(k)) {
                return None;
            }
            Some(c.iter().filter(|(k, w)| p.get(*k) != Some(*w)).map(|(k, w)| (*k, *w)).collect())
        }
    }
}

/// Whether `state`'s frozen epochs are exactly the parent record's (same
/// epochs, same maps; segments are cached, so this is a map comparison).
/// They are by construction (`apply_at` never changes a frozen epoch, and
/// `parent` is the selected parent the state was computed on); the check
/// keeps a diff from inheriting a wrong set if either ever fails.
fn same_frozen(store: &Storage, parent: &Resolved, state: &PowitState) -> bool {
    let mut mine = state.epoch_work.iter().filter(|(e, _)| **e != state.epoch);
    let mut theirs = parent.frozen.iter();
    loop {
        match (mine.next(), theirs.next()) {
            (None, None) => return true,
            (Some((e, m)), Some(f)) if *e == f.epoch && (f.keys, f.sum) == fingerprint(m) => {
                if load_epoch(store, f).is_none_or(|seg| *seg != *m) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// Stage `hash`'s state into `batch`: its core row, its work record (a diff
/// against `parent`'s record when it can be one) and the segments of frozen
/// epochs not yet stored. `parent` is the block's selected parent, `None`
/// to always store an anchor (tools and tests).
pub fn stage(store: &Storage, batch: &mut rocksdb::WriteBatch, hash: &Hash, parent: Option<&Hash>,
             state: &PowitState) -> Result<(), String>
{
    let stage = |batch: &mut rocksdb::WriteBatch, k: String, v: &[u8]| {
        store.stage_meta(batch, &k, v).map_err(|e| format!("storage: powit state: {e}"))
    };
    let current = state.epoch_work.get(&state.epoch);
    let parent_rec = parent.and_then(|p| resolve(store, p).map(|r| (*p, r)));
    let diff = parent_rec.as_ref().and_then(|(p, r)| {
        if r.epoch != state.epoch || r.depth + 1 >= ANCHOR_EVERY || !same_frozen(store, r, state) {
            return None;
        }
        let changed = changed_entries(r.current.as_ref(), current)?;
        Some(WorkKind::Diff { parent: *p, depth: r.depth + 1, changed })
    });
    let kind = match diff {
        Some(d) => d,
        None => {
            // Frozen epochs the parent's record already references keep
            // their digest (same contents by construction, compared with
            // the stored segment); the others are encoded once and stored
            // if new.
            let known: BTreeMap<u64, FrozenRef> = parent_rec.iter()
                .flat_map(|(_, r)| r.frozen.iter().map(|f| (f.epoch, *f)))
                .collect();
            let mut frozen = Vec::new();
            for (e, m) in state.epoch_work.iter().filter(|(e, _)| **e != state.epoch) {
                let (keys, sum) = fingerprint(m);
                let same = |f: &&FrozenRef| (f.keys, f.sum) == (keys, sum)
                    && load_epoch(store, f).is_some_and(|seg| *seg == *m);
                if let Some(f) = known.get(e).filter(same) {
                    frozen.push(*f);
                    continue;
                }
                let bytes = encode(m, "epoch")?;
                let digest = epoch_digest(*e, &bytes);
                let k = key(EPOCH_PREFIX, &digest);
                if store.get_meta(&k).map_err(|e| format!("storage: powit epoch: {e}"))?.is_none() {
                    stage(batch, k, &bytes)?;
                }
                frozen.push(FrozenRef { epoch: *e, digest, keys, sum });
            }
            WorkKind::Anchor { frozen, current: current.cloned() }
        }
    };
    let work = WorkRecord { epoch: state.epoch, kind };
    stage(batch, key(CORE_PREFIX, hash), &versioned(&core_of(state), "core")?)?;
    stage(batch, key(WORK_PREFIX, hash), &versioned(&work, "work")?)?;
    Ok(())
}

/// Whether `hash`'s record in this layout is an anchor (`Some(true)`), a
/// diff (`Some(false)`), or absent (`None`). For tests and diagnostics.
#[allow(dead_code)] // tests; the node binary compiles this module too
pub fn record_kind(store: &Storage, hash: &Hash) -> Option<bool> {
    read_work(store, hash).map(|r| matches!(r.kind, WorkKind::Anchor { .. }))
}

// ── PoCI ledger rows (ObenBlock) ─────────────────────────────────────────────
//
// The PoCI ledger beside a block's state (`PociState`: the history head, the
// bans, the pruned keys, the pending rejoins and the included votes `seen`)
// used to be stored whole per block (`powit/poci/<hash>`), never deleted:
// with `seen` holding up to `PRUNE_AFTER + 3` block epochs of every key of
// the configuration, that repeated the whole absence-pruning ledger at every
// block (review finding LOW: tens of MB a day). It is now laid out like the
// work records above:
//
// - **Slow part** (bans, pruned keys, pending rejoins): it changes only when
//   a block includes evidence or a rejoin, or at a handoff; stored once per
//   content as a segment `powit/pocis/<digest>`.
// - **`seen` by block epoch**: an anchor references one content-addressed
//   segment per block epoch (`key -> lowest included_at`), so the epochs
//   that no longer change are shared by every later anchor and branch.
// - **Per block** (`powit/pocir/<hash>`): the history head, the slow part's
//   digest, and either an anchor (the epoch segments) or a diff against the
//   selected parent's record: the `seen` entries the block added or lowered.
//   A block stores an anchor every `ANCHOR_EVERY` records, when an entry
//   was dropped (`trim_seen`, a handoff), and when its parent has no record
//   in this layout; a load walks at most `ANCHOR_EVERY - 1` diffs.
//
// Data dirs written before this layout keep their `powit/poci/<hash>` rows
// (read when a block has no record here; `node/src/powit.rs`).

/// A block's PoCI record.
const POCI_REC_PREFIX: &str = "powit/pocir/";
/// A content-addressed PoCI segment (slow part or one block epoch of `seen`).
const POCI_SEG_PREFIX: &str = "powit/pocis/";
/// Domain tag of a PoCI segment digest.
const POCI_SEG_TAG: &[u8] = b"GNB-POWIT-STORE-v1/poci";

/// The PoCI ledger of a block as stored (the history itself is stored by
/// `node/src/powit.rs` as history nodes and named here by its head).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PociLedgerRows {
    pub head: Hash,
    pub bans: BTreeMap<KeyId, Vec<gnb_crypto::core::powit::poci::Ban>>,
    /// key -> the epoch its pruning started.
    pub pruned: BTreeMap<KeyId, u64>,
    pub rejoins: BTreeMap<KeyId, u64>,
    /// key -> (block epoch -> lowest `included_at`).
    pub seen: BTreeMap<KeyId, BTreeMap<u64, u64>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PociSlow {
    bans: BTreeMap<KeyId, Vec<gnb_crypto::core::powit::poci::Ban>>,
    pruned: BTreeMap<KeyId, u64>,
    rejoins: BTreeMap<KeyId, u64>,
}

/// One block epoch of `seen` referenced by an anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SeenRef {
    epoch: u64,
    digest: Hash,
    keys: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum PociKind {
    Anchor { seen: Vec<SeenRef> },
    /// `(key, block epoch, lowest included_at)` added or lowered since the
    /// record of `parent` (`depth - 1` diffs from its anchor).
    Diff { parent: Hash, depth: u32, changed: Vec<(KeyId, u64, u64)> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PociRec {
    head: Hash,
    slow: Hash,
    kind: PociKind,
}

type SeenEpoch = BTreeMap<KeyId, u64>;

/// Decoded, verified PoCI segments by digest.
#[derive(Clone)]
enum PociSeg {
    Slow(Arc<PociSlow>),
    Seen(Arc<SeenEpoch>),
}

static POCI_SEG_CACHE: Mutex<Option<(HashMap<Hash, PociSeg>, VecDeque<Hash>)>> = parking_lot::const_mutex(None);
const POCI_SEG_CACHE_CAP: usize = 512;

/// SHA3-256(tag ‖ kind ‖ u64le(epoch) ‖ bytes): kind 0 the slow part
/// (epoch 0), kind 1 one block epoch of `seen`.
fn poci_digest(kind: u8, epoch: u64, bytes: &[u8]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(POCI_SEG_TAG);
    h.update([kind]);
    h.update(epoch.to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

fn poci_seg_cached(digest: &Hash) -> Option<PociSeg> {
    POCI_SEG_CACHE.lock().as_ref().and_then(|(m, _)| m.get(digest).cloned())
}

fn poci_seg_remember(digest: Hash, seg: PociSeg) {
    let mut g = POCI_SEG_CACHE.lock();
    let (m, order) = g.get_or_insert_with(Default::default);
    if m.insert(digest, seg).is_none() {
        order.push_back(digest);
        if order.len() > POCI_SEG_CACHE_CAP {
            if let Some(old) = order.pop_front() {
                m.remove(&old);
            }
        }
    }
}

fn load_slow(store: &Storage, digest: &Hash) -> Option<Arc<PociSlow>> {
    if let Some(PociSeg::Slow(s)) = poci_seg_cached(digest) {
        return Some(s);
    }
    let bytes = store.get_meta(&key(POCI_SEG_PREFIX, digest)).ok().flatten()?;
    if poci_digest(0, 0, &bytes) != *digest {
        return None;
    }
    let s = Arc::new(decode::<PociSlow>(&bytes)?);
    poci_seg_remember(*digest, PociSeg::Slow(s.clone()));
    Some(s)
}

fn load_seen_epoch(store: &Storage, r: &SeenRef) -> Option<Arc<SeenEpoch>> {
    if let Some(PociSeg::Seen(s)) = poci_seg_cached(&r.digest) {
        return Some(s);
    }
    let bytes = store.get_meta(&key(POCI_SEG_PREFIX, &r.digest)).ok().flatten()?;
    if poci_digest(1, r.epoch, &bytes) != r.digest {
        return None;
    }
    let m: SeenEpoch = decode(&bytes)?;
    if m.len() as u64 != r.keys || m.is_empty() {
        return None;
    }
    let m = Arc::new(m);
    poci_seg_remember(r.digest, PociSeg::Seen(m.clone()));
    Some(m)
}

fn read_poci_rec(store: &Storage, hash: &Hash) -> Option<PociRec> {
    unversioned(&store.get_meta(&key(POCI_REC_PREFIX, hash)).ok().flatten()?)
}

/// A PoCI record resolved through its diffs: its depth and `seen` by
/// block epoch.
struct PociResolved {
    rec: PociRec,
    depth: u32,
    seen: BTreeMap<u64, SeenEpoch>,
}

fn resolve_poci(store: &Storage, hash: &Hash) -> Option<PociResolved> {
    let first = read_poci_rec(store, hash)?;
    let depth = match &first.kind {
        PociKind::Anchor { .. } => 0,
        PociKind::Diff { depth, .. } => *depth,
    };
    if depth >= ANCHOR_EVERY {
        return None;
    }
    let mut diffs: Vec<Vec<(KeyId, u64, u64)>> = Vec::new();
    let mut rec = first.clone();
    loop {
        match rec.kind {
            PociKind::Anchor { seen: refs } => {
                if diffs.len() as u32 != depth {
                    return None;
                }
                let mut seen: BTreeMap<u64, SeenEpoch> = BTreeMap::new();
                for r in &refs {
                    if seen.insert(r.epoch, (*load_seen_epoch(store, r)?).clone()).is_some() {
                        return None;
                    }
                }
                for changed in diffs.into_iter().rev() {
                    for (k, y, at) in changed {
                        seen.entry(y).or_default().insert(k, at);
                    }
                }
                return Some(PociResolved { rec: first, depth, seen });
            }
            PociKind::Diff { parent, depth: d, changed } => {
                if d as usize != depth as usize - diffs.len() || d == 0 {
                    return None;
                }
                diffs.push(changed);
                rec = read_poci_rec(store, &parent)?;
            }
        }
    }
}

fn seen_by_epoch(seen: &BTreeMap<KeyId, BTreeMap<u64, u64>>) -> BTreeMap<u64, SeenEpoch> {
    let mut out: BTreeMap<u64, SeenEpoch> = BTreeMap::new();
    for (k, m) in seen {
        for (y, at) in m {
            out.entry(*y).or_default().insert(*k, *at);
        }
    }
    out
}

/// `hash`'s PoCI ledger rows in this layout: `Some(None)` when it has no
/// record here, `None` when a row it needs is missing or corrupt.
pub fn load_poci_ledger(store: &Storage, hash: &Hash) -> Option<Option<PociLedgerRows>> {
    if store.get_meta(&key(POCI_REC_PREFIX, hash)).ok()?.is_none() {
        return Some(None);
    }
    let r = resolve_poci(store, hash)?;
    let slow = load_slow(store, &r.rec.slow)?;
    let mut seen: BTreeMap<KeyId, BTreeMap<u64, u64>> = BTreeMap::new();
    for (y, m) in r.seen {
        for (k, at) in m {
            seen.entry(k).or_default().insert(y, at);
        }
    }
    Some(Some(PociLedgerRows { head: r.rec.head, bans: slow.bans.clone(), pruned: slow.pruned.clone(),
                               rejoins: slow.rejoins.clone(), seen }))
}

/// The `seen` entries of `child` that are new or changed against `parent`,
/// or `None` when one of `parent`'s is gone (then the block stores an anchor).
fn seen_changes(parent: &BTreeMap<u64, SeenEpoch>, child: &BTreeMap<u64, SeenEpoch>) -> Option<Vec<(KeyId, u64, u64)>> {
    for (y, pm) in parent {
        let cm = child.get(y)?;
        if pm.keys().any(|k| !cm.contains_key(k)) {
            return None;
        }
    }
    let mut out = Vec::new();
    for (y, cm) in child {
        let pm = parent.get(y);
        for (k, at) in cm {
            if pm.and_then(|m| m.get(k)) != Some(at) {
                out.push((*k, *y, *at));
            }
        }
    }
    Some(out)
}

/// Stage `hash`'s PoCI ledger rows: its record (a diff against `parent`'s
/// when it can be one), the slow part's segment and the anchor's `seen`
/// segments that are not stored yet.
pub fn stage_poci_ledger(store: &Storage, batch: &mut rocksdb::WriteBatch, hash: &Hash, parent: Option<&Hash>,
                         rows: &PociLedgerRows) -> Result<(), String>
{
    let err = |e: String| format!("storage: powit poci: {e}");
    let put_seg = |batch: &mut rocksdb::WriteBatch, digest: &Hash, bytes: &[u8]| -> Result<(), String> {
        let k = key(POCI_SEG_PREFIX, digest);
        if store.get_meta(&k).map_err(|e| err(e.to_string()))?.is_none() {
            store.stage_meta(batch, &k, bytes).map_err(|e| err(e.to_string()))?;
        }
        Ok(())
    };
    let slow = PociSlow { bans: rows.bans.clone(), pruned: rows.pruned.clone(), rejoins: rows.rejoins.clone() };
    let slow_bytes = encode(&slow, "poci ledger")?;
    let slow_digest = poci_digest(0, 0, &slow_bytes);
    put_seg(batch, &slow_digest, &slow_bytes)?;
    let seen = seen_by_epoch(&rows.seen);
    let diff = parent.and_then(|p| resolve_poci(store, p).map(|r| (*p, r))).and_then(|(p, r)| {
        if r.depth + 1 >= ANCHOR_EVERY {
            return None;
        }
        let changed = seen_changes(&r.seen, &seen)?;
        Some(PociKind::Diff { parent: p, depth: r.depth + 1, changed })
    });
    let kind = match diff {
        Some(d) => d,
        None => {
            let mut refs = Vec::with_capacity(seen.len());
            for (y, m) in &seen {
                let bytes = encode(m, "poci seen")?;
                let digest = poci_digest(1, *y, &bytes);
                put_seg(batch, &digest, &bytes)?;
                refs.push(SeenRef { epoch: *y, digest, keys: m.len() as u64 });
            }
            PociKind::Anchor { seen: refs }
        }
    };
    let rec = PociRec { head: rows.head, slow: slow_digest, kind };
    store.stage_meta(batch, &key(POCI_REC_PREFIX, hash), &versioned(&rec, "poci record")?).map_err(|e| err(e.to_string()))
}

/// Whether `hash`'s PoCI record is an anchor (`Some(true)`), a diff
/// (`Some(false)`), or absent (`None`), and its encoded size. Tests.
#[allow(dead_code)] // tests; the node binary compiles this module too
pub fn poci_record_kind(store: &Storage, hash: &Hash) -> Option<(bool, usize)> {
    let bytes = store.get_meta(&key(POCI_REC_PREFIX, hash)).ok().flatten()?;
    let rec: PociRec = unversioned(&bytes)?;
    Some((matches!(rec.kind, PociKind::Anchor { .. }), bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnb_crypto::core::powit::Checkpoint;
    use tempfile::TempDir;

    fn store() -> (TempDir, Storage) {
        let dir = TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        (dir, s)
    }

    fn h(n: u64) -> Hash {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&n.to_le_bytes());
        x[31] = 0x5A;
        x
    }

    fn k(n: u32) -> KeyId {
        let mut x = [0u8; 20];
        x[..4].copy_from_slice(&n.to_le_bytes());
        x
    }

    fn put(st: &Storage, hash: &Hash, parent: Option<&Hash>, s: &PowitState) {
        let mut b = rocksdb::WriteBatch::default();
        stage(st, &mut b, hash, parent, s).unwrap();
        st.write_batch(b).unwrap();
    }

    fn base() -> PowitState {
        let mut s = PowitState::genesis(10, [7; 32]);
        s.justified = Checkpoint { height: 70, hash: [1; 32] };
        s.votes.entry(Checkpoint { height: 130, hash: [2; 32] }).or_default().insert(k(1), 5);
        s.links.insert(k(1), vec![(70, 130, [2; 32])]);
        s.banned.insert(k(9), 40);
        s.decay.insert(k(2), 3);
        s.active_this_epoch.insert(k(1));
        s
    }

    /// A deterministic pseudo-random walk of states shaped like `apply_at`'s:
    /// shares credited to the current epoch, epoch steps that freeze it and
    /// drop the oldest, a window of `window + 2` epochs.
    fn walk(n: u64, per_epoch: u64, window: u64, seed: u64) -> Vec<PowitState> {
        let mut x = seed | 1;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut s = base();
        let mut out = Vec::new();
        for i in 0..n {
            let epoch = i / per_epoch;
            if epoch > s.epoch {
                s.epoch = epoch;
                s.epoch_work = s.epoch_work.split_off(&epoch.saturating_sub(window + 2));
                s.active_this_epoch.clear();
            }
            for _ in 0..(rnd() % 4) {
                let e = s.epoch_work.entry(epoch).or_default().entry(k((rnd() % 40) as u32)).or_insert(0);
                *e = e.saturating_add(u128::from(rnd() % 1_000) + 1);
            }
            if rnd() % 5 == 0 {
                s.active_this_epoch.insert(k((rnd() % 40) as u32));
            }
            s.finalized_at = i;
            out.push(s.clone());
        }
        out
    }

    #[test]
    fn round_trip_a_chain_of_states() {
        let (_d, st) = store();
        let states = walk(400, 37, 3, 0x9E37);
        for (i, s) in states.iter().enumerate() {
            let parent = (i > 0).then(|| h(i as u64 - 1));
            put(&st, &h(i as u64), parent.as_ref(), s);
        }
        let mut anchors = 0;
        for (i, s) in states.iter().enumerate() {
            assert_eq!(load(&st, &h(i as u64)).as_ref(), Some(s), "block {i}");
            anchors += usize::from(record_kind(&st, &h(i as u64)) == Some(true));
        }
        // Anchors: the first block, each epoch change, every ANCHOR_EVERY.
        assert!(anchors < states.len() / 8, "{anchors} anchors of {}", states.len());
        // Frozen epochs are stored once each, not per block: every anchor
        // that references an epoch references the same segment.
        let mut by_epoch: BTreeMap<u64, std::collections::BTreeSet<Hash>> = BTreeMap::new();
        for i in 0..states.len() as u64 {
            if let Some(WorkRecord { kind: WorkKind::Anchor { frozen, .. }, .. }) = read_work(&st, &h(i)) {
                for f in frozen {
                    assert!(st.get_meta(&key(EPOCH_PREFIX, &f.digest)).unwrap().is_some());
                    by_epoch.entry(f.epoch).or_default().insert(f.digest);
                }
            }
        }
        assert!(by_epoch.len() >= 5);
        assert!(by_epoch.values().all(|d| d.len() == 1), "one segment per frozen epoch");
    }

    #[test]
    fn round_trip_branches_sharing_segments() {
        let (_d, st) = store();
        let a = walk(120, 20, 2, 11);
        let b = walk(120, 20, 2, 12);
        // b's blocks 0..60 are a's; from 60 b is a fork on a[59].
        for (i, s) in a.iter().enumerate() {
            put(&st, &h(i as u64), (i > 0).then(|| h(i as u64 - 1)).as_ref(), s);
        }
        for (i, s) in b.iter().enumerate().skip(60) {
            let parent = if i == 60 { h(59) } else { h(1_000 + i as u64 - 1) };
            put(&st, &h(1_000 + i as u64), Some(&parent), s);
        }
        for (i, s) in a.iter().enumerate() {
            assert_eq!(load(&st, &h(i as u64)).as_ref(), Some(s));
        }
        for (i, s) in b.iter().enumerate().skip(60) {
            assert_eq!(load(&st, &h(1_000 + i as u64)).as_ref(), Some(s), "fork block {i}");
        }
    }

    #[test]
    fn a_legacy_parent_is_read_and_its_child_is_an_anchor() {
        let (_d, st) = store();
        let states = walk(10, 100, 3, 5);
        let legacy = bincode::serde::encode_to_vec(&states[0], bincode::config::standard()).unwrap();
        st.put_meta(&key(LEGACY_PREFIX, &h(0)), &legacy).unwrap();
        assert_eq!(load(&st, &h(0)).as_ref(), Some(&states[0]));
        put(&st, &h(1), Some(&h(0)), &states[1]);
        assert_eq!(record_kind(&st, &h(1)), Some(true));
        put(&st, &h(2), Some(&h(1)), &states[2]);
        assert_eq!(record_kind(&st, &h(2)), Some(false));
        for i in 0..3 {
            assert_eq!(load(&st, &h(i)).as_ref(), Some(&states[i as usize]));
        }
    }

    #[test]
    fn a_diff_is_never_written_across_an_epoch_change_or_a_shrinking_epoch() {
        let (_d, st) = store();
        let mut s0 = base();
        s0.epoch_work.entry(0).or_default().insert(k(1), 10);
        put(&st, &h(0), None, &s0);
        // Same epoch, an entry gone: anchor.
        let mut s1 = s0.clone();
        s1.epoch_work.get_mut(&0).unwrap().remove(&k(1));
        s1.epoch_work.get_mut(&0).unwrap().insert(k(2), 1);
        put(&st, &h(1), Some(&h(0)), &s1);
        assert_eq!(record_kind(&st, &h(1)), Some(true));
        assert_eq!(load(&st, &h(1)), Some(s1.clone()));
        // Epoch change: anchor, and epoch 0 becomes a segment.
        let mut s2 = s1.clone();
        s2.epoch = 1;
        s2.epoch_work.entry(1).or_default().insert(k(3), 4);
        put(&st, &h(2), Some(&h(1)), &s2);
        assert_eq!(record_kind(&st, &h(2)), Some(true));
        assert_eq!(load(&st, &h(2)), Some(s2.clone()));
        // An empty current map (no diff can say so): anchor, kept exactly.
        let mut s3 = base();
        s3.epoch_work.insert(0, BTreeMap::new());
        put(&st, &h(3), Some(&h(9)), &s3);
        assert_eq!(load(&st, &h(3)), Some(s3));
    }

    #[test]
    fn an_absent_current_epoch_stays_absent_through_empty_diffs() {
        let (_d, st) = store();
        let mut s0 = base();
        s0.epoch_work.entry(0).or_default().insert(k(1), 10);
        put(&st, &h(0), None, &s0);
        // Epoch 1 starts without shares: no current map at all.
        let mut s1 = s0.clone();
        s1.epoch = 1;
        put(&st, &h(1), Some(&h(0)), &s1);
        let s2 = s1.clone();
        put(&st, &h(2), Some(&h(1)), &s2);
        assert_eq!(record_kind(&st, &h(2)), Some(false));
        assert_eq!(load(&st, &h(2)), Some(s2.clone()));
        let mut s3 = s2.clone();
        s3.epoch_work.entry(1).or_default().insert(k(2), 3);
        put(&st, &h(3), Some(&h(2)), &s3);
        let s4 = s3.clone();
        put(&st, &h(4), Some(&h(3)), &s4);
        assert_eq!(record_kind(&st, &h(4)), Some(false));
        for (i, s) in [&s0, &s1, &s2, &s3, &s4].into_iter().enumerate() {
            assert_eq!(load(&st, &h(i as u64)).as_ref(), Some(s), "block {i}");
        }
    }

    /// A state whose frozen epochs differ from its parent record's (same
    /// fingerprint, other contents) is stored as an anchor with its own
    /// segment, never as a diff inheriting the parent's.
    #[test]
    fn a_frozen_epoch_unlike_the_parents_is_never_inherited() {
        let (_d, st) = store();
        let mut s0 = base();
        s0.epoch = 1;
        s0.epoch_work.entry(0).or_default().insert(k(1), 10);
        s0.epoch_work.entry(0).or_default().insert(k(2), 20);
        s0.epoch_work.entry(1).or_default().insert(k(3), 1);
        put(&st, &h(0), None, &s0);
        let mut s1 = s0.clone();
        let e0 = s1.epoch_work.get_mut(&0).unwrap();
        e0.insert(k(1), 20);
        e0.insert(k(2), 10);
        put(&st, &h(1), Some(&h(0)), &s1);
        assert_eq!(record_kind(&st, &h(1)), Some(true));
        assert_eq!(load(&st, &h(1)), Some(s1));
        assert_eq!(load(&st, &h(0)), Some(s0));
    }

    #[test]
    fn the_diff_depth_is_bounded() {
        let (_d, st) = store();
        let states = walk(3 * ANCHOR_EVERY as u64, 10_000, 3, 77);
        for (i, s) in states.iter().enumerate() {
            put(&st, &h(i as u64), (i > 0).then(|| h(i as u64 - 1)).as_ref(), s);
        }
        for i in 0..states.len() as u64 {
            let r = resolve(&st, &h(i)).unwrap();
            assert!(r.depth < ANCHOR_EVERY);
            assert_eq!(r.depth as u64, i % ANCHOR_EVERY as u64, "block {i}");
        }
    }

    #[test]
    fn a_missing_or_corrupt_row_loads_nothing() {
        let (_d, st) = store();
        let mut s0 = base();
        s0.epoch = 1;
        s0.epoch_work.entry(0).or_default().insert(k(77), 123_456);
        s0.epoch_work.entry(1).or_default().insert(k(78), 1);
        let mut s1 = s0.clone();
        s1.epoch_work.get_mut(&1).unwrap().insert(k(79), 2);
        put(&st, &h(0), None, &s0);
        put(&st, &h(1), Some(&h(0)), &s1);
        assert_eq!(record_kind(&st, &h(1)), Some(false));
        // A corrupt segment (once out of the cache) loads nothing.
        let Some(WorkRecord { kind: WorkKind::Anchor { frozen, .. }, .. }) = read_work(&st, &h(0)) else { panic!() };
        st.put_meta(&key(EPOCH_PREFIX, &frozen[0].digest), b"garbage").unwrap();
        forget(&frozen[0].digest);
        assert_eq!(load(&st, &h(0)), None);
        assert_eq!(load(&st, &h(1)), None);
        // A diff whose parent's record is gone loads nothing.
        let (_d2, st2) = store();
        put(&st2, &h(0), None, &s0);
        put(&st2, &h(1), Some(&h(0)), &s1);
        st2.put_meta(&key(WORK_PREFIX, &h(0)), b"").unwrap();
        assert_eq!(load(&st2, &h(1)), None);
        // An unknown layout version loads nothing.
        put(&st2, &h(5), None, &s0);
        assert_eq!(load(&st2, &h(5)), Some(s0.clone()));
        let mut bad = vec![RECORD_VERSION + 1];
        bad.extend(encode(&core_of(&s0), "core").unwrap());
        st2.put_meta(&key(CORE_PREFIX, &h(5)), &bad).unwrap();
        assert_eq!(load(&st2, &h(5)), None);
    }

    #[test]
    fn a_refused_batch_leaves_no_rows() {
        let (_d, st) = store();
        let states = walk(3, 100, 3, 3);
        let mut b = rocksdb::WriteBatch::default();
        stage(&st, &mut b, &h(0), None, &states[0]).unwrap();
        drop(b);
        assert_eq!(load(&st, &h(0)), None);
        assert_eq!(record_kind(&st, &h(0)), None);
    }

    // ── PoCI ledger rows ─────────────────────────────────────────────────────

    fn poci_put(st: &Storage, hash: &Hash, parent: Option<&Hash>, r: &PociLedgerRows) {
        let mut b = rocksdb::WriteBatch::default();
        stage_poci_ledger(st, &mut b, hash, parent, r).unwrap();
        st.write_batch(b).unwrap();
    }

    fn poci_forget_all() {
        *POCI_SEG_CACHE.lock() = None;
    }

    /// A ledger walk shaped like `apply_poci`'s: each block includes votes
    /// of some keys (first inclusion per key per block epoch kept), an
    /// epoch step trims the oldest block epochs, evidence and rejoins now
    /// and then.
    fn poci_walk(n: u64, per_epoch: u64, keys: u32, seed: u64) -> Vec<PociLedgerRows> {
        let mut x = seed | 1;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut r = PociLedgerRows { head: [0x11; 32], ..Default::default() };
        let mut out = Vec::new();
        let mut epoch = 0;
        for i in 1..=n {
            let y = i / per_epoch;
            if y > epoch {
                epoch = y;
                for m in r.seen.values_mut() {
                    m.retain(|e, _| *e + 10 >= y);
                }
                r.seen.retain(|_, m| !m.is_empty());
                r.head = [y as u8; 32];
            }
            for _ in 0..(1 + rnd() % 3) {
                let key = k((rnd() % keys as u64) as u32);
                r.seen.entry(key).or_default().entry(y).or_insert(i);
            }
            if rnd() % 50 == 0 {
                r.bans.entry(k(1000 + (i % 7) as u32)).or_default().push(
                    gnb_crypto::core::powit::poci::Ban { config_id: [i as u8; 32], included_at: i, start: None });
            }
            if rnd() % 70 == 0 {
                r.pruned.insert(k(2000 + (i % 5) as u32), y);
                r.rejoins.insert(k(2000 + (i % 5) as u32), i);
            }
            out.push(r.clone());
        }
        out
    }

    /// Review finding (LOW): the PoCI ledger was stored whole per block. It
    /// is now per-epoch segments plus diffs: every block's ledger reloads
    /// exactly (from disk, with no segment cached), most blocks store a
    /// small diff, an anchor at least every `ANCHOR_EVERY` records, and the
    /// rows written per block stay far below the whole ledger's size.
    #[test]
    fn poci_ledger_round_trips_as_segments_and_diffs() {
        let (_d, st) = store();
        let rows = poci_walk(400, 40, 60, 7);
        let mut diff_bytes = 0usize;
        let (mut anchors, mut diffs) = (0, 0);
        for (i, r) in rows.iter().enumerate() {
            let parent = (i > 0).then(|| h(i as u64 - 1));
            poci_put(&st, &h(i as u64), parent.as_ref(), r);
            let (anchor, size) = poci_record_kind(&st, &h(i as u64)).unwrap();
            if anchor {
                anchors += 1;
            } else {
                diffs += 1;
                diff_bytes += size;
            }
        }
        assert!(diffs > 300, "mostly diffs ({anchors} anchors, {diffs} diffs)");
        let whole = encode(&rows.last().unwrap().seen, "x").unwrap().len();
        assert!(diff_bytes / diffs < 256, "a diff is small: {} bytes on average", diff_bytes / diffs);
        assert!(whole > 4 * (diff_bytes / diffs), "the whole ledger ({whole} bytes) was stored per block before");
        poci_forget_all();
        for (i, r) in rows.iter().enumerate() {
            assert_eq!(load_poci_ledger(&st, &h(i as u64)), Some(Some(r.clone())), "block {i}");
        }
        // No anchor is more than ANCHOR_EVERY - 1 diffs away.
        for i in 0..rows.len() as u64 {
            assert!(resolve_poci(&st, &h(i)).unwrap().depth < ANCHOR_EVERY);
        }
        // A block without a record in this layout: Some(None).
        assert_eq!(load_poci_ledger(&st, &h(9_999)), Some(None));
    }

    /// Reorgs: two branches from one parent store diffs against their own
    /// parents and each reloads its own ledger, whatever was stored first;
    /// a block whose entries were trimmed stores an anchor; a corrupt
    /// segment or a missing parent record loads nothing (never a wrong
    /// ledger).
    #[test]
    fn poci_ledger_branches_trims_and_corruption() {
        let (_d, st) = store();
        let rows = poci_walk(20, 1_000, 20, 3);
        for (i, r) in rows.iter().enumerate() {
            poci_put(&st, &h(i as u64), (i > 0).then(|| h(i as u64 - 1)).as_ref(), r);
        }
        let base = rows.last().unwrap().clone();
        let tip = h(rows.len() as u64 - 1);
        let mut a = base.clone();
        a.seen.entry(k(500)).or_default().insert(0, 31);
        let mut b = base.clone();
        b.seen.entry(k(501)).or_default().insert(0, 31);
        b.bans.entry(k(502)).or_default().push(
            gnb_crypto::core::powit::poci::Ban { config_id: [9; 32], included_at: 31, start: None });
        let (ha, hb) = ([0xA1; 32], [0xB1; 32]);
        poci_put(&st, &hb, Some(&tip), &b);
        poci_put(&st, &ha, Some(&tip), &a);
        let mut a2 = a.clone();
        a2.seen.entry(k(503)).or_default().insert(0, 32);
        poci_put(&st, &[0xA2; 32], Some(&ha), &a2);
        poci_forget_all();
        assert_eq!(load_poci_ledger(&st, &ha), Some(Some(a.clone())));
        assert_eq!(load_poci_ledger(&st, &hb), Some(Some(b.clone())));
        assert_eq!(load_poci_ledger(&st, &[0xA2; 32]), Some(Some(a2.clone())));
        assert_eq!(poci_record_kind(&st, &[0xA2; 32]).map(|x| x.0), Some(false), "a diff on its branch");
        // A trimmed entry: the block stores an anchor.
        let mut t = a2.clone();
        t.seen.remove(&k(500));
        poci_put(&st, &[0xA3; 32], Some(&[0xA2; 32]), &t);
        assert_eq!(poci_record_kind(&st, &[0xA3; 32]).map(|x| x.0), Some(true));
        assert_eq!(load_poci_ledger(&st, &[0xA3; 32]), Some(Some(t)));
        // A diff whose parent's record is gone loads nothing.
        st.put_meta(&key(POCI_REC_PREFIX, &ha), b"").unwrap();
        assert_eq!(load_poci_ledger(&st, &[0xA2; 32]), None);
        // A corrupt segment (out of the cache) loads nothing.
        let Some(PociRec { kind: PociKind::Anchor { seen }, .. }) = read_poci_rec(&st, &h(0)) else { panic!() };
        st.put_meta(&key(POCI_SEG_PREFIX, &seen[0].digest), b"garbage").unwrap();
        poci_forget_all();
        assert_eq!(load_poci_ledger(&st, &h(0)), None);
        assert_eq!(load_poci_ledger(&st, &hb), None);
    }
}
