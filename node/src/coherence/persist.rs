//! Shielded-pool persistence (audit COH-2).
//!
//! The pool's consensus state follows the APPLIED selected chain and is
//! written to RocksDB column family `shielded` in the same WriteBatch as the
//! UTXO changes of every connect plan (`accept::resolve_best_chain` folds
//! [`StagedShielded::stage_into`] into the batch `reorg::connect_plan`
//! commits). A crash therefore leaves either the old or the new UTXO set and
//! shielded state together, never one without the other.
//!
//! # Layout of the `shielded` column family (schema version 1)
//!
//! | key                         | value                                      |
//! |-----------------------------|--------------------------------------------|
//! | `"L"` ‖ position (u64 BE)   | note commitment (32 bytes), one per leaf   |
//! | `"N"` ‖ nullifier (32)      | empty: the nullifier is spent              |
//! | `"U"` ‖ block hash (32)     | bincode(standard) of [`BlockUndo`]         |
//! | `"A"`                       | anchor window, 32-byte roots, oldest first |
//! | `"T"`                       | block hash the state corresponds to        |
//! | `"V"`                       | schema version, u32 LE (= 1)               |
//!
//! Only blocks that carry shielded transactions change the leaves, the
//! nullifiers or the anchor window and get an undo record; every committed
//! plan rewrites `"T"`. At start-up [`ShieldedPool::load`] rebuilds the
//! commitment tree (`O(n)` hashes), the nullifier set and the anchor window
//! and checks `"T"` against the UTXO tip (`meta/tip_hash`).

use super::{BlockRedo, BlockUndo, ShieldedEngine, ShieldedPool, ShieldedTx, SpendPublic, ANCHOR_HISTORY};
use crate::reorg::{ConnectError, ReorgPlan};
use crate::storage::Storage;

/// Schema version of the `shielded` column family.
pub const SHIELDED_SCHEMA_VERSION: u32 = 1;

const LEAF_PREFIX: u8 = b'L';
const NULLIFIER_PREFIX: u8 = b'N';
const UNDO_PREFIX: u8 = b'U';
const KEY_ANCHORS: &[u8] = b"A";
const KEY_TIP: &[u8] = b"T";
const KEY_VERSION: &[u8] = b"V";

fn leaf_key(position: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = LEAF_PREFIX;
    k[1..].copy_from_slice(&position.to_be_bytes());
    k
}

fn hash_key(prefix: u8, h: &[u8; 32]) -> [u8; 33] {
    let mut k = [0u8; 33];
    k[0] = prefix;
    k[1..].copy_from_slice(h);
    k
}

fn encode_undo(undo: &BlockUndo) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(undo, bincode::config::standard()).map_err(|e| format!("shielded undo encode: {e}"))
}

fn decode_undo(bytes: &[u8]) -> Result<BlockUndo, String> {
    let (undo, used): (BlockUndo, usize) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map_err(|e| format!("shielded undo decode: {e}"))?;
    if used != bytes.len() {
        return Err("shielded undo record has trailing bytes".into());
    }
    Ok(undo)
}

fn encode_anchors(anchors: &[[u8; 32]]) -> Vec<u8> {
    anchors.iter().flat_map(|a| a.iter().copied()).collect()
}

fn decode_anchors(bytes: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) || bytes.len() / 32 > ANCHOR_HISTORY {
        return Err(format!("persisted anchor window has a malformed length ({} bytes)", bytes.len()));
    }
    Ok(bytes.chunks(32).map(|c| <[u8; 32]>::try_from(c).expect("32-byte chunk")).collect())
}

fn hash32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|_| format!("{what} is not 32 bytes"))
}

/// Whether a shielded undo record is persisted for `block` (it is applied
/// and carried shielded transactions), without decoding it.
pub fn has_undo(store: &Storage, block: &[u8; 32]) -> Result<bool, String> {
    Ok(store.get_shielded(&hash_key(UNDO_PREFIX, block)).map_err(|e| e.to_string())?.is_some())
}

/// The undo record persisted for `block`, if any.
pub fn read_undo(store: &Storage, block: &[u8; 32]) -> Result<Option<BlockUndo>, String> {
    store.get_shielded(&hash_key(UNDO_PREFIX, block))
        .map_err(|e| e.to_string())?
        .map(|b| decode_undo(&b))
        .transpose()
}

/// One write in the `shielded` column family.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Write {
    PutLeaf(u64, [u8; 32]),
    DeleteLeaf(u64),
    PutNullifier([u8; 32]),
    DeleteNullifier([u8; 32]),
    PutUndo([u8; 32], Vec<u8>),
    DeleteUndo([u8; 32]),
    PutAnchors(Vec<u8>),
    PutTip([u8; 32]),
    PutVersion,
}

/// One in-memory step of a staged plan, kept so it can be reverted exactly.
#[derive(Debug)]
enum Step {
    Applied(BlockUndo),
    Disconnected(BlockRedo),
}

/// The shielded side of a connect plan: the pool has ALREADY been moved in
/// memory; the writes are folded into the plan's WriteBatch with
/// [`stage_into`](Self::stage_into). After the batch commits call
/// [`ShieldedPool::commit_staged`]; if it does not, call
/// [`ShieldedPool::revert_staged`] to restore the exact previous state.
#[derive(Debug)]
#[must_use = "a staged shielded plan must be committed or reverted"]
pub struct StagedShielded {
    steps: Vec<Step>,
    writes: Vec<Write>,
    prev_tip: Option<[u8; 32]>,
    included: Vec<ShieldedTx>,
}

impl StagedShielded {
    /// Stage every shielded write, in order, into `batch` (the batch that
    /// carries the plan's UTXO changes).
    pub fn stage_into(&self, store: &Storage, batch: &mut rocksdb::WriteBatch) -> Result<(), String> {
        let e = |err: crate::storage::StorageError| err.to_string();
        for w in &self.writes {
            match w {
                Write::PutLeaf(pos, cm) => store.stage_shielded_put(batch, &leaf_key(*pos), cm).map_err(e)?,
                Write::DeleteLeaf(pos) => store.stage_shielded_delete(batch, &leaf_key(*pos)).map_err(e)?,
                Write::PutNullifier(nf) => store.stage_shielded_put(batch, &hash_key(NULLIFIER_PREFIX, nf), &[]).map_err(e)?,
                Write::DeleteNullifier(nf) => store.stage_shielded_delete(batch, &hash_key(NULLIFIER_PREFIX, nf)).map_err(e)?,
                Write::PutUndo(h, bytes) => store.stage_shielded_put(batch, &hash_key(UNDO_PREFIX, h), bytes).map_err(e)?,
                Write::DeleteUndo(h) => store.stage_shielded_delete(batch, &hash_key(UNDO_PREFIX, h)).map_err(e)?,
                Write::PutAnchors(bytes) => store.stage_shielded_put(batch, KEY_ANCHORS, bytes).map_err(e)?,
                Write::PutTip(h) => store.stage_shielded_put(batch, KEY_TIP, h).map_err(e)?,
                Write::PutVersion => store
                    .stage_shielded_put(batch, KEY_VERSION, &SHIELDED_SCHEMA_VERSION.to_le_bytes())
                    .map_err(e)?,
            }
        }
        Ok(())
    }

    /// How many blocks of the plan changed the shielded state.
    pub fn shielded_blocks(&self) -> usize {
        self.steps.len()
    }
}

impl ShieldedPool {
    /// Load the persisted shielded state (start-up). A data-dir without any
    /// shielded record (fresh, or written before audit COH-2: no shielded
    /// transaction was ever accepted) loads as the empty genesis state at the
    /// UTXO tip. A state whose tip differs from the UTXO tip is refused unless
    /// it is empty (then it is consistent with any chain position).
    ///
    /// No node build reaches that mismatch any more: every write of the UTXO
    /// tip after genesis carries the shielded tip in the same batch, and a
    /// release from before this column family cannot open a data dir that has
    /// it (RocksDB refuses the read-write open, see docs/RUNNING.md,
    /// "Upgrading and downgrading"), so it cannot move the UTXO tip alone
    /// after a downgrade. The adopt branch below only covers a data dir that
    /// was edited outside the node or restored in part.
    pub fn load(store: &Storage) -> Result<ShieldedPool, String> {
        let utxo_tip = store.get_meta("tip_hash").map_err(|e| e.to_string())?
            .map(|v| hash32(&v, "meta tip_hash")).transpose()?;
        let version = store.get_shielded(KEY_VERSION).map_err(|e| e.to_string())?;
        if let Some(v) = &version {
            if v.as_slice() != SHIELDED_SCHEMA_VERSION.to_le_bytes() {
                return Err(format!("unsupported shielded schema version {v:?}"));
            }
        }
        let mut leaves = Vec::new();
        for (k, v) in store.scan_shielded_prefix(&[LEAF_PREFIX]).map_err(|e| e.to_string())? {
            let pos = <[u8; 8]>::try_from(&k[1..]).map(u64::from_be_bytes)
                .map_err(|_| "malformed shielded leaf key".to_string())?;
            if pos != leaves.len() as u64 {
                return Err(format!("shielded commitment tree has a gap at position {}", leaves.len()));
            }
            leaves.push(hash32(&v, "shielded leaf")?);
        }
        let mut nullifiers = Vec::new();
        for (k, v) in store.scan_shielded_prefix(&[NULLIFIER_PREFIX]).map_err(|e| e.to_string())? {
            if !v.is_empty() {
                return Err("malformed shielded nullifier value".into());
            }
            nullifiers.push(hash32(&k[1..], "shielded nullifier key")?);
        }
        let anchors = match store.get_shielded(KEY_ANCHORS).map_err(|e| e.to_string())? {
            Some(b) => decode_anchors(&b)?,
            None => ShieldedEngine::new().anchors(),
        };
        let stored_tip = store.get_shielded(KEY_TIP).map_err(|e| e.to_string())?
            .map(|v| hash32(&v, "shielded tip")).transpose()?;
        let empty = leaves.is_empty() && nullifiers.is_empty();
        if version.is_none() && !(empty && stored_tip.is_none()) {
            return Err("shielded records without a schema version".into());
        }
        let engine = ShieldedEngine::from_parts(leaves, anchors, nullifiers)?;
        let tip = match (stored_tip, utxo_tip) {
            (Some(s), Some(u)) if s != u => {
                if !empty {
                    return Err(format!(
                        "shielded state is at block {} but the UTXO set is at {}; refusing to start \
                         (resynchronise the node)",
                        hex::encode(&s[..8]), hex::encode(&u[..8])));
                }
                log::warn!("shielded tip {} != UTXO tip {}; the shielded state is empty, adopting the UTXO tip",
                    hex::encode(&s[..8]), hex::encode(&u[..8]));
                Some(u)
            }
            (Some(s), _) => Some(s),
            (None, u) => u,
        };
        Ok(ShieldedPool { engine, tip, ..ShieldedPool::new() })
    }

    /// [`stage_plan_with`](Self::stage_plan_with) using the pool's own
    /// verifier (`RejectAll` in every node build).
    pub fn stage_plan(&mut self, store: &Storage, plan: &ReorgPlan) -> Result<StagedShielded, ConnectError> {
        let verifier = self.verifier.clone();
        self.stage_plan_with(store, plan, |p, pf| verifier.verify(p, pf))
    }

    /// Move the pool along `plan` IN MEMORY (disconnect `to_rollback`
    /// tip-first from their persisted undo records, connect `to_apply` in
    /// order) and return the matching writes. The pool must be at the plan's
    /// start (`ConnectError::Failed` otherwise). A block whose shielded
    /// transactions do not validate is `ConnectError::Invalid`; on any error
    /// the pool is restored exactly.
    pub fn stage_plan_with<F>(&mut self, store: &Storage, plan: &ReorgPlan, verify: F)
        -> Result<StagedShielded, ConnectError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        let mut staged = StagedShielded { steps: Vec::new(), writes: Vec::new(), prev_tip: self.tip, included: Vec::new() };
        match self.stage_plan_inner(store, plan, &verify, &mut staged) {
            Ok(()) => Ok(staged),
            Err(e) => {
                self.revert_staged(staged);
                Err(e)
            }
        }
    }

    fn stage_plan_inner<F>(
        &mut self,
        store: &Storage,
        plan: &ReorgPlan,
        verify: &F,
        staged: &mut StagedShielded,
    ) -> Result<(), ConnectError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        let start = plan.to_rollback.first().copied().unwrap_or(plan.lca);
        if let Some(tip) = self.tip {
            if tip != start {
                return Err(ConnectError::Failed(format!(
                    "shielded state is at block {} but the plan starts at {}",
                    hex::encode(&tip[..8]), hex::encode(&start[..8]))));
            }
        }
        // A body that cannot be read is typed (review of PR #15, finding 6):
        // the acceptance pipeline attributes it to the block.
        let body = |h: &[u8; 32]| -> Result<crate::core::Block, ConnectError> {
            store.get_block(h).map_err(|e| ConnectError::body_unreadable(*h, true, &e))?
                .ok_or_else(|| ConnectError::Failed(format!(
                    "{}: block body {} missing for the shielded state",
                    crate::reorg::ERR_MISSING_BODIES, hex::encode(&h[..8]))))
        };
        let mut anchors_changed = false;

        for h in &plan.to_rollback {
            // Whether the block carried shielded transactions: from its body,
            // or — its body pruned (audit DAG-6: a reorg of any depth
            // disconnects pruned blocks) — from the record written when it was
            // pruned; a body pruned by an older release has no record, and
            // then the persisted shielded undo record answers (every applied
            // block that carried shielded transactions has one, and undo
            // records are never pruned).
            let had_shielded = match store.get_block(h).map_err(|e| ConnectError::body_unreadable(*h, false, &e))? {
                Some(block) => !block.shielded_transactions.is_empty(),
                None => match store.get_pruned_body_record(h).map_err(|e| ConnectError::Failed(e.to_string()))? {
                    Some(rec) => rec.had_shielded,
                    None => read_undo(store, h).map_err(ConnectError::Failed)?.is_some(),
                },
            };
            if !had_shielded {
                continue;
            }
            let undo = read_undo(store, h).map_err(ConnectError::Failed)?.ok_or_else(|| ConnectError::Failed(
                format!("no shielded undo record for block {}", hex::encode(&h[..8]))))?;
            let old_len = self.engine.tree_len();
            let redo = self.engine.undo(&undo)
                .map_err(|e| ConnectError::Failed(format!("shielded disconnect of {}: {e:?}", hex::encode(&h[..8]))))?;
            staged.writes.extend((undo.tree_len..old_len).map(Write::DeleteLeaf));
            staged.writes.extend(undo.nullifiers.iter().map(|nf| Write::DeleteNullifier(*nf)));
            staged.writes.push(Write::DeleteUndo(*h));
            staged.steps.push(Step::Disconnected(redo));
            anchors_changed = true;
        }

        for h in &plan.to_apply {
            let block = body(h)?;
            if block.shielded_transactions.is_empty() {
                continue;
            }
            let undo = self.engine.apply_txs(&block.shielded_transactions, verify).map_err(|e| ConnectError::Invalid {
                block: *h,
                height: block.height,
                reason: format!("shielded consensus rejection: {e:?}"),
            })?;
            let leaves = self.engine.snapshot_leaves_from(undo.tree_len);
            let first = undo.tree_len;
            staged.writes.extend(leaves.into_iter().enumerate().map(|(i, cm)| Write::PutLeaf(first + i as u64, cm)));
            staged.writes.extend(undo.nullifiers.iter().map(|nf| Write::PutNullifier(*nf)));
            staged.writes.push(Write::PutUndo(*h, encode_undo(&undo).map_err(ConnectError::Failed)?));
            staged.steps.push(Step::Applied(undo));
            staged.included.extend(block.shielded_transactions.iter().cloned());
            anchors_changed = true;
        }

        let new_tip = plan.to_apply.last().copied().unwrap_or(plan.lca);
        if anchors_changed {
            staged.writes.push(Write::PutAnchors(encode_anchors(&self.engine.anchors())));
        }
        staged.writes.push(Write::PutTip(new_tip));
        staged.writes.push(Write::PutVersion);
        self.tip = Some(new_tip);
        Ok(())
    }

    /// The plan's batch committed: evict the included transactions from the
    /// shielded mempool. (The engine already holds the new state.)
    pub fn commit_staged(&mut self, staged: StagedShielded) {
        self.mempool.remove_included(&staged.included);
    }

    /// The plan's batch was NOT committed: restore the exact previous state.
    pub fn revert_staged(&mut self, staged: StagedShielded) {
        for step in staged.steps.into_iter().rev() {
            match step {
                Step::Applied(undo) => self.engine.revert_apply(&undo),
                Step::Disconnected(redo) => self.engine.redo(redo),
            }
        }
        self.tip = staged.prev_tip;
    }

    /// Chain-state rebuild (audit DAG-11): back to the empty genesis state
    /// with no shielded tip (the next committed plan sets it), keeping the
    /// configured proof verifier. The caller deletes the persisted state in
    /// the same batch as the rest of the chain state
    /// (`Storage::stage_clear_chain_state`).
    pub fn reset_for_rebuild(&mut self) {
        let verifier = self.verifier.clone();
        *self = ShieldedPool { verifier, ..ShieldedPool::new() };
    }

    /// Re-point the shielded tip at `new_tip` after `rolled_back` blocks were
    /// removed from the applied chain by start-up reconciliation (blocks whose
    /// UTXO effects were applied without a DAG record, written before audit
    /// DAG-11). Those blocks predate shielded persistence and must not carry
    /// shielded transactions; the returned writes go into the same batch.
    pub fn stage_retip(&mut self, store: &Storage, rolled_back: &[[u8; 32]], new_tip: [u8; 32])
        -> Result<StagedShielded, String>
    {
        for h in rolled_back {
            if let Some(b) = store.get_block(h).map_err(|e| e.to_string())? {
                if !b.shielded_transactions.is_empty() {
                    return Err(format!(
                        "block {} carries shielded transactions but has no shielded undo history",
                        hex::encode(&h[..8])));
                }
            }
        }
        let staged = StagedShielded {
            steps: Vec::new(),
            writes: vec![Write::PutTip(new_tip), Write::PutVersion],
            prev_tip: self.tip,
            included: Vec::new(),
        };
        self.tip = Some(new_tip);
        Ok(staged)
    }
}
