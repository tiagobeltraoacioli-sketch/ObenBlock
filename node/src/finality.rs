//! The PoWit finality pin, sticky (package A2: docs/DESIGN-obenblock.md §5.2,
//! §7 and §9 O2; docs/DESIGN-pow-powit.md §7.6; docs/CONSENSUS.md,
//! "Selected chain"). Node-local fork-choice input: no block verdict and no
//! GhostDAG data read it.
//!
//! The pin is the checkpoint this node holds as finalized
//! (`GhostDAG::finalized`): a block whose selected-parent chain does not pass
//! through it is never selected. This module decides when the pin moves.
//!
//! * **Sticky.** Every move of the pin is persisted ([`PIN_KEY`]) and the
//!   first finality read of a DAG instance restores it
//!   ([`restore_persisted`]), before anything chooses a chain: neither a
//!   restart, nor a crash in the middle of a chain move, nor a heavier chain
//!   takes the node below a checkpoint it finalized. Before A2 the pin lived
//!   in memory only and was re-derived from the applied tip's witness set at
//!   start-up.
//! * **Forward along its own chain only.** A finalized checkpoint moves the
//!   pin only when it extends it ([`Relation::Extends`]: the pin lies on its
//!   selected chain). `GhostDAG::set_finalized` compared heights only, so a
//!   higher checkpoint of another branch replaced the pin.
//! * **Convergence.** The finality the node learns from ANY block it holds
//!   with the minimum chain work, not only from its applied chain, is
//!   adopted when it extends the pin (`accept_block`, [`observe`]): the
//!   side of a partition that did not finalize rejoins the side that did on
//!   heal, also when that side has less work (docs/DESIGN-pow-powit.md §7.6:
//!   the heaviest chain AMONG the branches that contain the latest final
//!   checkpoint). Ingress lets such a branch in although its work is below
//!   the anti-DoS threshold (`ingress::FinalityHealBudget`).
//! * **Conflict: alert, then the operator.** A finalized checkpoint that
//!   neither extends the pin nor lies on its chain (both sides of a
//!   partition longer than the leak finalized, or a third of the weight
//!   equivocated) moves nothing. It is recorded ([`CONFLICTS_KEY`],
//!   `getfinalityinfo`) and logged at error level, and the node stays where
//!   it is until the operator decides: `setfinalitycheckpoint <hash>` pins a
//!   block of their choice (any branch, moving the chain to it) and
//!   `ignorefinalized` drops the pin (the node follows the most work again
//!   and pins the finality of the chain it ends on).
//!
//! DoS bounds: every finalized checkpoint considered comes from a PoWit
//! state that passed the consensus checks (two thirds of `W` signed it), of
//! a block with valid proof of work and at least the minimum chain work;
//! classifying it is one selected-parent walk bounded by the height
//! difference between the two checkpoints (`GhostDAG::is_on_selected_chain_of`);
//! the alert keeps at most [`MAX_CONFLICTS`] distinct checkpoints (later ones
//! are counted, not stored).

use std::sync::atomic::{AtomicBool, Ordering};

use log::{error, info, warn};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::consensus::{BlockHash, GhostDAG};
use crate::storage::Storage;
use gnb_crypto::core::powit::PowitState;

/// CF_META key of the persisted pin. Not `finalized_height`: data dirs of
/// releases before audit DAG-6 still carry that key, which is ignored.
pub const PIN_KEY: &str = "powit_finality_pin";

/// CF_META key of the conflicting-finalization alert ([`ConflictLog`], JSON).
pub const CONFLICTS_KEY: &str = "powit_finality_conflicts";

/// Distinct conflicting checkpoints the alert keeps.
pub const MAX_CONFLICTS: usize = 8;

/// Version byte of the persisted pin record.
const PIN_RECORD_V1: u8 = 1;
/// Length of a persisted pin record: version, hash, DAG height, source,
/// time it was set.
const PIN_RECORD_LEN: usize = 1 + 32 + 8 + 1 + 8;

/// Who set the pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinSource {
    /// The witness set finalized it (automatic).
    WitnessSet,
    /// `setfinalitycheckpoint`.
    Operator,
}

impl PinSource {
    fn byte(self) -> u8 {
        match self {
            PinSource::WitnessSet => 1,
            PinSource::Operator => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(PinSource::WitnessSet),
            2 => Some(PinSource::Operator),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PinSource::WitnessSet => "witness-set",
            PinSource::Operator => "operator",
        }
    }
}

/// The persisted pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    pub hash: BlockHash,
    /// DAG height of `hash`.
    pub height: u64,
    pub source: PinSource,
    /// Unix time it was set.
    pub set_at: u64,
}

impl Pin {
    pub fn encode(&self) -> [u8; PIN_RECORD_LEN] {
        let mut out = [0u8; PIN_RECORD_LEN];
        out[0] = PIN_RECORD_V1;
        out[1..33].copy_from_slice(&self.hash);
        out[33..41].copy_from_slice(&self.height.to_le_bytes());
        out[41] = self.source.byte();
        out[42..50].copy_from_slice(&self.set_at.to_le_bytes());
        out
    }

    /// `None` for anything but a well-formed v1 record (an empty value is
    /// a cleared pin).
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != PIN_RECORD_LEN || b[0] != PIN_RECORD_V1 {
            return None;
        }
        Some(Pin {
            hash: b[1..33].try_into().ok()?,
            height: u64::from_le_bytes(b[33..41].try_into().ok()?),
            source: PinSource::from_byte(b[41])?,
            set_at: u64::from_le_bytes(b[42..50].try_into().ok()?),
        })
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The persisted pin, if any (a read error or a malformed record is
/// reported and counts as none: the in-memory pin is unaffected).
pub fn load_pin(store: &Storage) -> Option<Pin> {
    match store.get_meta(PIN_KEY) {
        Ok(Some(v)) if v.is_empty() => None,
        Ok(Some(v)) => {
            let p = Pin::decode(&v);
            if p.is_none() {
                error!("finality: the persisted pin record ({} bytes) is malformed; ignored", v.len());
            }
            p
        }
        Ok(None) => None,
        Err(e) => {
            error!("finality: reading the persisted pin failed: {e}");
            None
        }
    }
}

fn save_pin(store: &Storage, pin: &Pin) -> Result<(), String> {
    store.put_meta(PIN_KEY, &pin.encode()).map_err(|e| e.to_string())
}

/// Clear the persisted pin (an empty record: CF_META has no delete).
fn clear_pin(store: &Storage) -> Result<(), String> {
    store.put_meta(PIN_KEY, &[]).map_err(|e| e.to_string())
}

/// One conflicting finalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// The finalized checkpoint that conflicts with the pin (hex).
    pub checkpoint: String,
    /// Its DAG height.
    pub checkpoint_height: u64,
    /// The first block seen whose PoWit state finalized it (hex).
    pub block: String,
    /// That block's blue work (decimal).
    pub block_blue_work: String,
    /// The pin it conflicted with (hex) and its DAG height.
    pub pin: String,
    pub pin_height: u64,
    /// Unix time it was first seen.
    pub first_seen: u64,
}

/// The conflicting-finalization alert.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictLog {
    /// The first [`MAX_CONFLICTS`] distinct conflicting checkpoints.
    pub conflicts: Vec<Conflict>,
    /// Further distinct conflicting checkpoints, not stored.
    pub dropped: u64,
}

pub fn load_conflicts(store: &Storage) -> ConflictLog {
    match store.get_meta(CONFLICTS_KEY) {
        Ok(Some(v)) if !v.is_empty() => serde_json::from_slice(&v).unwrap_or_else(|e| {
            error!("finality: the persisted conflict alert is malformed ({e}); starting a new one");
            ConflictLog::default()
        }),
        Ok(_) => ConflictLog::default(),
        Err(e) => {
            error!("finality: reading the conflict alert failed: {e}");
            ConflictLog::default()
        }
    }
}

fn save_conflicts(store: &Storage, log: &ConflictLog) -> Result<(), String> {
    let bytes = serde_json::to_vec(log).map_err(|e| e.to_string())?;
    store.put_meta(CONFLICTS_KEY, &bytes).map_err(|e| e.to_string())
}

/// Clear the alert (the operator decided).
pub fn clear_conflicts(store: &Storage) -> Result<(), String> {
    store.put_meta(CONFLICTS_KEY, &[]).map_err(|e| e.to_string())
}

/// Record `c` unless its checkpoint is already recorded. Returns whether it
/// is new (stored or counted).
fn record_conflict(store: &Storage, c: Conflict) -> bool {
    let mut log = load_conflicts(store);
    if log.conflicts.iter().any(|o| o.checkpoint == c.checkpoint) {
        return false;
    }
    if log.conflicts.len() < MAX_CONFLICTS {
        log.conflicts.push(c);
    } else {
        // Counted, not stored: an unbounded set of distinct checkpoints
        // cannot grow the record. (Repeats of a dropped checkpoint count
        // again; the counter only says the alert is incomplete.)
        log.dropped = log.dropped.saturating_add(1);
    }
    if let Err(e) = save_conflicts(store, &log) {
        error!("finality: persisting the conflict alert failed: {e}");
    }
    true
}

/// How a finalized checkpoint relates to the pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// The pin itself.
    Same,
    /// Above the pin, on a chain through it: the pin may move to it.
    Extends,
    /// At or below the pin, on its chain (older finality).
    Behind,
    /// Neither: finalized history disagrees.
    Conflicts,
}

/// Relation of checkpoint `cp` (hash, DAG height) to `pin`. One
/// selected-parent walk, bounded by the height difference.
pub fn relation(dag: &GhostDAG, pin: (BlockHash, u64), cp: (BlockHash, u64)) -> Relation {
    if cp.0 == pin.0 {
        Relation::Same
    } else if cp.1 > pin.1 {
        if dag.is_on_selected_chain_of(&pin.0, &cp.0) { Relation::Extends } else { Relation::Conflicts }
    } else if dag.is_on_selected_chain_of(&cp.0, &pin.0) {
        Relation::Behind
    } else {
        Relation::Conflicts
    }
}

/// Restore the persisted pin into `dag`, once per DAG instance (the first
/// finality read after a start). A persisted pin whose block the DAG does
/// not hold is reported and not applied (no block could be selected); it
/// stays on disk.
pub fn restore_persisted(dag: &RwLock<GhostDAG>, store: &Storage) {
    if !dag.write().take_finality_restore() {
        return;
    }
    let Some(pin) = load_pin(store) else { return };
    let mut d = dag.write();
    let Some(height) = d.get_block_data(&pin.hash).map(|bd| bd.height) else {
        error!("finality: the persisted pin {} (DAG height {}) is not in the DAG; not applied. \
                Inspect with getfinalityinfo; setfinalitycheckpoint or ignorefinalized replace it",
            hex::encode(pin.hash), pin.height);
        return;
    };
    let apply = match d.finalized() {
        None => true,
        Some(cur) => relation(&d, cur, (pin.hash, height)) == Relation::Extends
            || pin.source == PinSource::Operator,
    };
    if apply {
        d.replace_finalized(Some((pin.hash, height)));
        info!("finality: restored the pin {} (DAG height {}, set by the {})",
            hex::encode(&pin.hash[..8]), height, pin.source.as_str());
    }
}

/// What [`observe`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// Nothing to consider (no finality beyond activation, below the
    /// minimum chain work, unknown checkpoint).
    Nothing,
    /// The pin, or older finality on its chain.
    Unchanged,
    /// The pin moved to the checkpoint.
    Advanced,
    /// A conflicting finalization (recorded when the caller asked).
    Conflict,
}

/// Consider the finality of `holder`'s PoWit state `st`: advance the pin
/// when it extends it (persisted), record a conflict when it disagrees and
/// `record` is set. Takes nothing while `holder`'s chain has less than
/// `min_chain_work` (PoWit audit finding 3: a cheap fork carries its own
/// witness set). Restores the persisted pin first.
pub fn observe(
    dag: &RwLock<GhostDAG>,
    store: &Storage,
    holder: &BlockHash,
    st: &PowitState,
    min_chain_work: u128,
    record: bool,
) -> Observed {
    restore_persisted(dag, store);
    if st.finalized.height <= st.activation {
        // The activation checkpoint is final by definition only and never
        // pins fork choice (two chains may compete right at activation).
        return Observed::Nothing;
    }
    let cp = st.finalized.hash;
    let (rel, cp_height, pin, holder_work) = {
        let d = dag.read();
        let Some(work) = d.get_block_data(holder).map(|bd| bd.blue_work) else { return Observed::Nothing };
        if work < min_chain_work {
            return Observed::Nothing;
        }
        let Some(h) = d.get_block_data(&cp).map(|bd| bd.height) else { return Observed::Nothing };
        let pin = d.finalized();
        let rel = match pin {
            None => Relation::Extends,
            Some(p) => relation(&d, p, (cp, h)),
        };
        (rel, h, pin, work)
    };
    match rel {
        Relation::Same | Relation::Behind => Observed::Unchanged,
        Relation::Extends => {
            {
                let mut d = dag.write();
                // Re-checked under the write lock (the acceptance lock
                // serializes every writer; this keeps the rule local).
                if d.finalized() != pin {
                    return Observed::Unchanged;
                }
                d.set_finalized(cp, cp_height);
            }
            let rec = Pin { hash: cp, height: cp_height, source: PinSource::WitnessSet, set_at: unix_now() };
            if let Err(e) = save_pin(store, &rec) {
                // The in-memory pin holds for this run; the next move or the
                // applied chain's state re-persists it.
                error!("finality: persisting the pin {} failed: {e}", hex::encode(&cp[..8]));
            }
            Observed::Advanced
        }
        Relation::Conflicts => {
            let (ph, pheight) = pin.expect("a conflict needs a pin");
            if record {
                let new = record_conflict(store, Conflict {
                    checkpoint: hex::encode(cp),
                    checkpoint_height: cp_height,
                    block: hex::encode(holder),
                    block_blue_work: holder_work.to_string(),
                    pin: hex::encode(ph),
                    pin_height: pheight,
                    first_seen: unix_now(),
                });
                if new {
                    error!("FINALITY CONFLICT: block {} carries a finalized checkpoint {} (DAG height {}) that \
                            conflicts with this node's finalized checkpoint {} (DAG height {}). The node stays \
                            on its finalized chain and waits for the operator: inspect with getfinalityinfo, \
                            then setfinalitycheckpoint <hash> or ignorefinalized",
                        hex::encode(&holder[..8]), hex::encode(&cp[..8]), cp_height,
                        hex::encode(&ph[..8]), pheight);
                }
            } else {
                static WARNED: AtomicBool = AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    warn!("finality: the applied chain's state finalized {} (DAG height {}), off the pinned \
                           checkpoint {} (DAG height {}); the pin holds",
                        hex::encode(&cp[..8]), cp_height, hex::encode(&ph[..8]), pheight);
                }
            }
            Observed::Conflict
        }
    }
}

/// [`observe`] for a block on arrival (`accept_block`, before the best chain
/// is resolved): its finality binds the resolution that follows, whichever
/// branch it is on; a conflict is recorded.
pub fn observe_block(dag: &RwLock<GhostDAG>, store: &Storage, block: &BlockHash, st: &PowitState) -> Observed {
    observe(dag, store, block, st, crate::ingress::minimum_chain_work(), true)
}

/// Operator escape hatch (`setfinalitycheckpoint`, `ignorefinalized`): set
/// the pin to `pin` whatever its relation to the current one (`None`
/// clears it), persist it, and clear the conflict alert. The caller moves
/// the chain afterwards. Returns the previous in-memory pin.
pub fn operator_replace(
    dag: &RwLock<GhostDAG>,
    store: &Storage,
    pin: Option<(BlockHash, u64)>,
) -> Result<Option<(BlockHash, u64)>, String> {
    // A persisted pin not restored yet must not come back over the
    // operator's choice.
    let _ = dag.write().take_finality_restore();
    let prev = dag.read().finalized();
    match pin {
        Some((hash, height)) => save_pin(store, &Pin { hash, height, source: PinSource::Operator, set_at: unix_now() })?,
        None => clear_pin(store)?,
    }
    dag.write().replace_finalized(pin);
    clear_conflicts(store)?;
    Ok(prev)
}

/// Undo [`operator_replace`] when the move that followed it committed
/// nothing: `prev` in memory and on disk (as set by the witness set).
pub fn operator_restore(dag: &RwLock<GhostDAG>, store: &Storage, prev: Option<(BlockHash, u64)>) {
    dag.write().replace_finalized(prev);
    let res = match prev {
        Some((hash, height)) => save_pin(store, &Pin { hash, height, source: PinSource::WitnessSet, set_at: unix_now() }),
        None => clear_pin(store),
    };
    if let Err(e) = res {
        error!("finality: restoring the previous pin failed: {e}");
    }
}

/// `getfinalityinfo`.
pub fn info_json(dag: &GhostDAG, store: &Storage) -> serde_json::Value {
    let pin = dag.finalized();
    let rec = load_pin(store);
    let log = load_conflicts(store);
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let applied_on_pin = match (pin, applied) {
        (Some((p, _)), Some(a)) => Some(dag.is_on_selected_chain_of(&p, &a)),
        (None, _) => None,
        (Some(_), None) => Some(false),
    };
    serde_json::json!({
        "finalized": pin.map(|(h, height)| serde_json::json!({
            "hash": hex::encode(h),
            "dag_height": height,
            "source": rec.filter(|r| r.hash == h).map(|r| r.source.as_str()),
            "set_at": rec.filter(|r| r.hash == h).map(|r| r.set_at),
        })),
        "persisted": rec.map(|r| serde_json::json!({
            "hash": hex::encode(r.hash),
            "dag_height": r.height,
            "source": r.source.as_str(),
            "set_at": r.set_at,
        })),
        "applied_tip_on_finalized_chain": applied_on_pin,
        "conflict": !log.conflicts.is_empty() || log.dropped > 0,
        "conflicts": log.conflicts,
        "conflicts_dropped": log.dropped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> BlockHash {
        let mut x = [0u8; 32];
        x[0] = n;
        x[31] = 0xA2;
        x
    }

    /// genesis g; a: g-a1-a2-a3-a4; b: a1-b2-b3-b4 (forks at a1).
    fn forked() -> GhostDAG {
        let mut d = GhostDAG::with_default_k();
        d.add_genesis(h(0), 1);
        d.add_block(h(1), vec![h(0)], 2, 10).unwrap();
        d.add_block(h(2), vec![h(1)], 3, 10).unwrap();
        d.add_block(h(3), vec![h(2)], 4, 10).unwrap();
        d.add_block(h(4), vec![h(3)], 5, 10).unwrap();
        d.add_block(h(12), vec![h(1)], 3, 10).unwrap();
        d.add_block(h(13), vec![h(12)], 4, 10).unwrap();
        d.add_block(h(14), vec![h(13)], 5, 10).unwrap();
        d
    }

    #[test]
    fn relation_classifies_extension_older_finality_and_conflicts() {
        let d = forked();
        let ht = |x: u8| d.get_block_data(&h(x)).unwrap().height;
        let p = (h(2), ht(2));
        assert_eq!(relation(&d, p, p), Relation::Same);
        assert_eq!(relation(&d, p, (h(4), ht(4))), Relation::Extends);
        assert_eq!(relation(&d, p, (h(1), ht(1))), Relation::Behind);
        assert_eq!(relation(&d, p, (h(0), ht(0))), Relation::Behind);
        assert_eq!(relation(&d, p, (h(13), ht(13))), Relation::Conflicts, "other branch, above the pin");
        assert_eq!(relation(&d, p, (h(12), ht(12))), Relation::Conflicts, "other branch, same height");
        let low = (h(1), ht(1));
        assert_eq!(relation(&d, low, (h(14), ht(14))), Relation::Extends, "the fork is above the pin");
    }

    #[test]
    fn pin_record_round_trips_and_rejects_other_bytes() {
        let p = Pin { hash: h(7), height: 1234, source: PinSource::Operator, set_at: 99 };
        assert_eq!(Pin::decode(&p.encode()), Some(p));
        assert_eq!(Pin::decode(&[]), None, "a cleared pin");
        let mut bad = p.encode();
        bad[0] = 2;
        assert_eq!(Pin::decode(&bad), None, "unknown version");
        let mut bad = p.encode();
        bad[41] = 0;
        assert_eq!(Pin::decode(&bad), None, "unknown source");
        assert_eq!(Pin::decode(&p.encode()[..49]), None, "short");
        // The legacy `finalized_height` meta key (u64) is never read as a pin.
        assert_eq!(Pin::decode(&3u64.to_le_bytes()), None);
    }
}
