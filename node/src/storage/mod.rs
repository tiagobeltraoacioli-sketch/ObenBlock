//! Bloch-SIS Protocol — Storage (RocksDB)

pub mod indexer;
/// Audit NET-12: explorer aggregates maintained in the UTXO write batches.
pub mod aggregates;
// Audit VAL-11: the UTXO-set supply audit (`gettxoutsetinfo`).
pub mod utxo_audit;

use rocksdb::{DB, Options, ColumnFamilyDescriptor, IteratorMode};
use std::path::Path;
use crate::core::{Block, TxOutput};
use crate::consensus::{BlockHash, GhostdagData};

const CF_BLOCKS:     &str = "blocks";
const CF_UTXO:       &str = "utxo";
const CF_DAG:        &str = "dag";
const CF_BLUE_SCORE: &str = "blue_score";
const CF_META:       &str = "meta";
const CF_HEIGHT:     &str = "height";
const CF_TIMESTAMPS: &str = "timestamps";
const CF_ADDR_UTXO:  &str = "addr_utxo";  // address index: [20B addr][32B txid][4B idx] → empty
const CF_COINBASE:   &str = "coinbase";    // txid → height (for maturity check)
const CF_TX_INDEX:   &str = "tx_index";    // txid → [32B block_hash][8B height]
const CF_ADDR_TX_HISTORY: &str = "addr_tx_history";  // addr → chronological tx touches
const CF_UNDO:       &str = "undo";        // Sprint U.1: per-block undo data for reorg rollback
const CF_DAG_INTEGRITY: &str = "dag_integrity";  // Sprint Y (M-2): hash-chain over GhostdagData
const CF_REACHABILITY: &str = "reachability";    // Phase 1: durable interval-reachability index (non-consensus cache)
const CF_SHIELDED: &str = "shielded";            // audit COH-2: shielded-pool state + undo (layout: coherence::persist)

// ── PoBRS Column Families (Sprint 1.5) ─────────────────────────────────
// Persistence layer for the Proof-of-Blue-and-Red-Score subsystem.
// All keys use big-endian for u64/u32 to preserve lexicographic ordering
// on RocksDB iterators. Schema version stored in CF_POBRS_META.
pub(crate) const CF_POBRS_META:                &str = "pobrs_meta";                // key: ascii string  | value: bincode
pub(crate) const CF_POBRS_ORACLES:             &str = "pobrs_oracles";             // key: oracle_id 1B  | value: OracleRecord
pub(crate) const CF_POBRS_ORACLES_BY_PK:       &str = "pobrs_oracles_by_pk";       // key: pk 48B        | value: oracle_id 1B
pub(crate) const CF_POBRS_ORACLE_SNAPSHOTS:    &str = "pobrs_oracle_snapshots";    // key: height 8B BE  | value: OracleSetSnapshot (every 100 blocks)
pub(crate) const CF_POBRS_ORACLE_EVENTS:       &str = "pobrs_oracle_events";       // key: height 8B BE + seq 4B BE | value: OracleEvent
pub(crate) const CF_POBRS_ATTESTATIONS:        &str = "pobrs_attestations";        // key: wallet_hash 32B          | value: AttestationCore
pub(crate) const CF_POBRS_ATTESTATIONS_EXTRA:  &str = "pobrs_attestations_extra";  // key: wallet_hash 32B          | value: AttestationExtra
pub(crate) const CF_POBRS_ATTESTATION_HISTORY: &str = "pobrs_attestation_history"; // key: wallet_hash 32B + block 8B BE | value: AttestationCore
pub(crate) const CF_POBRS_MODELS:              &str = "pobrs_models";              // key: model_id 4B BE           | value: ModelRecord
pub(crate) const CF_POBRS_MODEL_PENDING:       &str = "pobrs_model_pending";       // key: update_id 8B BE         | value: PendingModelUpdate
pub(crate) const CF_POBRS_DISPUTES:            &str = "pobrs_disputes";            // key: wallet_hash 32B          | value: DisputeRecord
pub(crate) const CF_POBRS_TEE_PLATFORMS:       &str = "pobrs_tee_platforms";       // key: platform_byte 1B         | value: PlatformInfo

// ── Bonding CFs (Sprint 2.1.D, ADR-007 §4.7) ─────────────────────────────
pub(crate) const CF_BONDING_META:      &str = "bonding_meta";       // ascii string keys → bincode (schema_version, next_bond_id)
pub(crate) const CF_BONDING_REGISTRY:  &str = "bonding_registry";   // BondId 8B BE        → BondRecord (Day β)
pub(crate) const CF_BONDING_BY_UID:    &str = "bonding_by_uid";     // OperatorUid 32B     → BondId 8B BE
pub(crate) const CF_BONDING_BY_PUBKEY: &str = "bonding_by_pk";      // BlsPubkey 48B       → BondId 8B BE
pub(crate) const CF_BONDING_HISTORY:   &str = "bonding_history";    // BondId 8B BE        → Vec<SlashEvent>
pub(crate) const CF_PARTICIPATION:     &str = "participation";      // (epoch 8B BE, bond_id 8B BE) → ParticipationRecord

// ── FFG Column Families (Sprint 2.1) ───────────────────────────────────
// Persistence layer for the Friendly Finality Gadget committee subsystem.
// Schema version stored in CF_FFG_META.
pub(crate) const CF_FFG_META:                 &str = "ffg_meta";                 // key: ascii string  | value: u32 LE / bincode
pub(crate) const CF_FFG_COMMITTEE:            &str = "ffg_committee";            // key: epoch 8B BE   | value: bincode(Committee)
pub(crate) const CF_FFG_PENDING_COMMITTEE:    &str = "ffg_pending_committee";    // key: dkg_epoch 8B BE | value: bincode(PendingCommittee)

/// PoBRS schema version. Bumped when key/value layout changes incompatibly.
/// Stored as `CF_POBRS_META["schema_version"] = u32 LE`.
pub const POBRS_SCHEMA_VERSION: u32 = 1;

/// (key, value) rows read from a column family, in key order.
pub type KeyValueRows = Vec<(Vec<u8>, Vec<u8>)>;

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, StorageError> {
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e| StorageError::SerializeFailed(e.to_string()))
}

pub fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, StorageError> {
    bincode::serde::decode_from_slice(b, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| StorageError::DeserializeFailed(e.to_string()))
}

/// `(txid, block_hash)`: one CF_TX_INDEX row (`Storage::tx_index_entries`).
pub type TxIndexEntry = ([u8; 32], [u8; 32]);

/// CF_META key of the selected-chain index layout version
/// ([`Storage::chain_index_version`]).
pub const CHAIN_INDEX_VERSION_META: &str = "chain_index_version";

/// Layout of CF_HEIGHT, CF_TIMESTAMPS and the address history: 2 = keyed by
/// the selected-chain position (DAG height, audit DAG-8); 1 = keyed by the
/// header height (earlier releases, migrated at start-up by
/// [`Storage::rebuild_chain_indexes`]).
pub const CHAIN_INDEX_VERSION: u32 = 2;

/// What [`Storage::rebuild_chain_indexes`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainIndexRebuild {
    /// Selected-chain blocks indexed (the genesis included).
    pub blocks: usize,
    /// Address-history rows written.
    pub rows: usize,
    /// Rows of pruned blocks that could not be kept (overwritten or lost by
    /// an earlier release, or not attributable to a block).
    pub lost: usize,
    /// Inputs of bodied blocks whose spent output their undo record does not
    /// hold (a block without one): no spend row is written for them.
    pub unresolved: usize,
}

/// Selected-chain index rows, from the top, that
/// [`Storage::stored_chain_network`] reads at most.
pub const CHAIN_SHAPE_SCAN: usize = 64;

/// CF_UNDO key prefix of a [`PrunedBodyRecord`]. Undo records are keyed by
/// the bare 32-byte block hash; these keys are longer, so
/// `Storage::undo_block_hashes` never mistakes one for an undo record.
pub const PRUNED_BODY_PREFIX: &[u8] = b"pruned_body/";

/// CF_UNDO key of `hash`'s pruned-body record.
pub fn pruned_body_key(hash: &BlockHash) -> Vec<u8> {
    let mut k = PRUNED_BODY_PREFIX.to_vec();
    k.extend_from_slice(hash);
    k
}

/// CF_META key prefix of the body height index (audit B1-T17):
/// `body_h/` ‖ height (u64 BE) ‖ block hash → empty, one row per stored
/// body, whatever the block's place in the DAG. `Storage::prune_blocks_below`
/// range-scans it, so EVERY body below the pruning height is pruned — merged,
/// fork-loser and junk bodies included (Bitcoin Core prunes whole block
/// files, stale blocks with the rest) — in O(bodies pruned), never by
/// walking all heights from 0.
pub const BODY_INDEX_PREFIX: &[u8] = b"body_h/";

/// CF_META key: `[1]` once every stored body has a body-index row (set on a
/// fresh database, or by the one-time backfill of an older one).
const BODY_INDEX_READY_KEY: &str = "body_index_v1";

fn body_index_key(height: u64, hash: &BlockHash) -> Vec<u8> {
    let mut k = Vec::with_capacity(BODY_INDEX_PREFIX.len() + 40);
    k.extend_from_slice(BODY_INDEX_PREFIX);
    k.extend_from_slice(&height.to_be_bytes());
    k.extend_from_slice(hash);
    k
}

/// CF_META key prefix of the body index's reverse rows (audit B1-T17):
/// `body_hk/` ‖ block hash → the height (u64 BE) of the hash's one current
/// [`BODY_INDEX_PREFIX`] row. A body write moves the row (the old one is
/// deleted in the same batch), a body deletion removes it, and pruning skips
/// a row the reverse row does not point at, so a stale row left at a lower
/// height can never prune a body that was re-stored to be kept longer.
const BODY_INDEX_HEIGHT_PREFIX: &[u8] = b"body_hk/";

fn body_index_height_key(hash: &BlockHash) -> Vec<u8> {
    let mut k = Vec::with_capacity(BODY_INDEX_HEIGHT_PREFIX.len() + 32);
    k.extend_from_slice(BODY_INDEX_HEIGHT_PREFIX);
    k.extend_from_slice(hash);
    k
}

/// CF_META key prefix of a hardened-body marker: `hardened_body/<hash>` (empty
/// value) is written, in the same batch that prunes the body, when the pruned
/// body passed every context-free hardening block rule as if active
/// (`accept::classify_stored_block` at activation 0). Those rules are gated
/// on the block's own header height only, so the marker answers "would this
/// body pass the start-up hardening recheck" for EVERY activation at or below
/// its height. The recheck reads it for a candidate whose body is gone
/// (re-audit B2-T1 follow-up): a body pruned after it was checked is not
/// disqualified when the recheck runs again under another activation height.
/// It lives in CF_META, which a chain-state rebuild never clears.
pub const HARDENED_BODY_PREFIX: &[u8] = b"hardened_body/";

/// CF_META key of `hash`'s hardened-body marker.
pub fn hardened_body_key(hash: &BlockHash) -> Vec<u8> {
    let mut k = HARDENED_BODY_PREFIX.to_vec();
    k.extend_from_slice(hash);
    k
}

/// CF_META key prefix of the genesis-ledger index (audit F1):
/// `genesis_ledger/` ‖ txid (empty value) for every txid of an output the
/// genesis ledger holds (the Bloch carryover and the locked vesting tranches,
/// `stage_carryover`). Those outputs are created by no transaction, so they
/// have no tx-index row; their confirmation point is the genesis (header
/// height 0, DAG height 0, chain position 0; docs/CONSENSUS.md, "Genesis
/// ledger"), which `accept::confirmations_in_view` answers through
/// `reorg::UtxoView::view_genesis_ledger`. CF_META is never cleared by a
/// chain-state rebuild, which re-stages the rows with the ledger anyway.
pub const GENESIS_LEDGER_PREFIX: &[u8] = b"genesis_ledger/";

/// CF_META key: `[1]` once the genesis-ledger index is complete (written with
/// the ledger, or by [`Storage::migrate_genesis_ledger_index`] for a data dir
/// ingested before the index existed).
pub const GENESIS_LEDGER_INDEX_META: &str = "genesis_ledger_index_v1";

/// CF_META key of `txid`'s genesis-ledger row.
pub fn genesis_ledger_key(txid: &[u8; 32]) -> Vec<u8> {
    let mut k = GENESIS_LEDGER_PREFIX.to_vec();
    k.extend_from_slice(txid);
    k
}

/// What disconnecting a selected-chain block needs from its body, kept when
/// the body is pruned (audit DAG-6): the UTXO effects are reversed from the
/// undo record, which is never pruned; the address-history rows to delete and
/// whether the block carried shielded transactions are kept here.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrunedBodyRecord {
    /// Header height of the pruned block.
    pub height: u64,
    /// The block carried shielded transactions.
    pub had_shielded: bool,
    /// Every CF_ADDR_TX_HISTORY key the block's connect wrote
    /// (`indexer::addr_history_keys`, keyed by the block's chain position).
    pub addr_history_keys: Vec<Vec<u8>>,
}

/// Decode one exported UTXO row without silently omitting corrupt ledger data.
/// Historical exports retain their big-endian vout interpretation; canonical
/// exports are explicit and must never replace the published genesis artifact.
pub fn decode_snapshot_row(key: &[u8], value: &[u8], canonical_vout: bool)
    -> Result<(Vec<u8>, u32, u64, Vec<u8>), StorageError>
{
    if key.len() != 36 {
        return Err(StorageError::DeserializeFailed("UTXO snapshot key must be exactly 36 bytes".into()));
    }
    let suffix = [key[32], key[33], key[34], key[35]];
    let vout = if canonical_vout { u32::from_le_bytes(suffix) } else { u32::from_be_bytes(suffix) };
    let (output, used): (TxOutput, usize) = bincode::serde::decode_from_slice(value, bincode::config::standard())
        .map_err(|e| StorageError::DeserializeFailed(format!("UTXO snapshot value: {e}")))?;
    if used != value.len() {
        return Err(StorageError::DeserializeFailed("UTXO snapshot value has trailing bytes".into()));
    }
    Ok((key[..32].to_vec(), vout, output.value, output.script_pubkey))
}

pub struct Storage {
    db: DB,
    /// Audit DAG-10: the acceptance mutex. Every path that mutates chain
    /// state (block acceptance from gossip, the miner, RPC `submitblock`,
    /// orphan resurrection, start-up reconciliation) holds it for the whole
    /// accept → connect → commit pipeline, so tip snapshot, validation, DAG
    /// insertion and the atomic commit can never interleave. It lives on the
    /// store because the store is the one object every ingress path shares
    /// and every chain-state mutation goes through. Reentrant so a nested
    /// call on the same thread cannot self-deadlock.
    accept_lock: parking_lot::ReentrantMutex<()>,
    /// Memo of pure verdicts on stored block bodies ([`Storage::body_verdict`]).
    body_verdicts: parking_lot::Mutex<BodyVerdicts>,
    /// NET-12: serialises every read-modify-write of the explorer
    /// aggregates (`aggregates.rs`). Never held while taking `accept_lock`.
    agg_lock: parking_lot::Mutex<()>,
    /// NET-12: the aggregates are complete (cached `agg/version`).
    agg_ready: std::sync::atomic::AtomicBool,
    /// NET-12: number of storage reads served (diagnostics; lets tests prove
    /// that an RPC's cost does not grow with the chain).
    reads: std::sync::atomic::AtomicU64,
    /// Fault injection ([`Storage::inject_batch_failures`]): how many of the
    /// next atomic batch commits fail. Always 0 outside tests.
    injected_batch_failures: std::sync::atomic::AtomicU32,
    /// Audit F1: the blocks whose validation ended without a verdict (a
    /// read failure of the chain state, re-audit B1-T12) since their last
    /// one that reached one, with the retry schedule (`accept`'s no-verdict
    /// guard). In memory only: never a mark.
    no_verdicts: parking_lot::Mutex<std::collections::HashMap<[u8; 32], NoVerdictRecord>>,
    /// Rate limit of the no-verdict error log: (last line, lines suppressed
    /// since).
    no_verdict_log: parking_lot::Mutex<(Option<std::time::Instant>, u64)>,
    /// Fault injection ([`Storage::inject_utxo_read_failure`]): UTXO rows
    /// whose reads fail with `StorageError::ReadFailed`. Empty outside
    /// tests; `read_faults_armed` keeps the hot path to one atomic load.
    injected_read_faults: parking_lot::Mutex<std::collections::HashSet<[u8; 32]>>,
    /// Fault injection ([`Storage::inject_body_read_failure`]): block hashes
    /// whose body reads (`get_block`, `get_block_wire_bytes`) fail, and block
    /// hashes whose body presence checks (`has_block_body`) fail, with
    /// `StorageError::ReadFailed`. Empty outside tests.
    injected_body_faults: parking_lot::Mutex<InjectedBodyFaults>,
    read_faults_armed: std::sync::atomic::AtomicBool,
    /// Audit F1: set when the node must stop (Bitcoin Core's `AbortNode`):
    /// the reason, for the operator. Acceptance and templates refuse from
    /// then on and the `gnb` binary exits.
    abort_reason: parking_lot::Mutex<Option<String>>,
}

/// Fault injection ([`Storage::inject_body_read_failure`]): the block hashes
/// whose body reads fail, and those whose body presence checks fail.
#[derive(Default)]
struct InjectedBodyFaults {
    reads: std::collections::HashSet<[u8; 32]>,
    presence: std::collections::HashSet<[u8; 32]>,
}

/// Audit F1 (review finding 2): what the node remembers of a block whose
/// validation ended without a verdict (`Storage::note_no_verdict`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoVerdictRecord {
    /// Validations that ended without a verdict since the last one that
    /// reached one.
    pub attempts: u32,
    /// Of those, the latest consecutive ones on which the storage engine
    /// failed (`reorg::ViewErrorKind::Io`): the count the node's stop reads.
    pub io_failures: u32,
    /// Whether the last failure was a storage-engine failure.
    pub last_io: bool,
    /// The last failure (at most 512 characters).
    pub reason: String,
    /// When the block may be validated again.
    pub retry_at: std::time::Instant,
}

/// First retry delay of a block without a verdict; it doubles with every
/// attempt up to [`NO_VERDICT_RETRY_MAX`].
pub const NO_VERDICT_RETRY_BASE: std::time::Duration = std::time::Duration::from_secs(60);
/// Longest retry delay of a block without a verdict.
pub const NO_VERDICT_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(3600);
/// At most one no-verdict error line per this interval.
pub const NO_VERDICT_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Upper bound on the entries of the body-verdict memo. Reaching it clears
/// the memo (the verdicts are recomputable; only the cost changes).
pub const BODY_VERDICT_MEMO_CAP: usize = 16_384;

/// The body-verdict memo ([`Storage::body_verdict`]).
#[derive(Default)]
struct BodyVerdicts {
    /// Block hash → (caller key, verdict on the body stored under that hash).
    map: std::collections::HashMap<[u8; 32], (u64, bool)>,
    /// Bumped by every body write or delete through this type, so a verdict
    /// computed while a body changed is not recorded.
    epoch: u64,
    /// Verdicts computed (memo misses), for tests and diagnostics.
    computed: u64,
}

impl Storage {
    fn with_db(db: DB) -> Self {
        Self {
            db,
            accept_lock: parking_lot::ReentrantMutex::new(()),
            body_verdicts: Default::default(),
            agg_lock: parking_lot::Mutex::new(()),
            agg_ready: std::sync::atomic::AtomicBool::new(false),
            reads: std::sync::atomic::AtomicU64::new(0),
            injected_batch_failures: std::sync::atomic::AtomicU32::new(0),
            no_verdicts: Default::default(),
            no_verdict_log: parking_lot::Mutex::new((None, 0)),
            injected_read_faults: Default::default(),
            injected_body_faults: Default::default(),
            read_faults_armed: std::sync::atomic::AtomicBool::new(false),
            abort_reason: parking_lot::Mutex::new(None),
        }
    }

    /// Audit F1: record one more validation of `block` that ended without a
    /// verdict at `now` (`io`: the storage engine failed, `reason`: the
    /// failure), and schedule its next attempt (bounded exponential backoff,
    /// [`NO_VERDICT_RETRY_BASE`] doubling up to [`NO_VERDICT_RETRY_MAX`]).
    /// Returns the updated record (counts since the block's last validation
    /// that reached a verdict, [`Storage::clear_no_verdict`]).
    pub fn note_no_verdict(&self, block: &[u8; 32], io: bool, reason: &str, now: std::time::Instant) -> NoVerdictRecord {
        let mut m = self.no_verdicts.lock();
        // Bounded: a guard against a flood of distinct failing blocks (a
        // block without a record is due for a retry, so losing records
        // only retries sooner).
        if m.len() >= 4096 && !m.contains_key(block) {
            m.clear();
        }
        let r = m.entry(*block).or_insert_with(|| NoVerdictRecord {
            attempts: 0, io_failures: 0, last_io: false, reason: String::new(), retry_at: now,
        });
        r.attempts = r.attempts.saturating_add(1);
        // "In a row": a failure of the other class in between restarts it.
        r.io_failures = if io { r.io_failures.saturating_add(1) } else { 0 };
        r.last_io = io;
        r.reason = reason.chars().take(512).collect();
        let shift = r.attempts.saturating_sub(1).min(16);
        let backoff = NO_VERDICT_RETRY_BASE.saturating_mul(1u32 << shift).min(NO_VERDICT_RETRY_MAX);
        r.retry_at = now + backoff;
        r.clone()
    }

    /// The no-verdict record of `block`, if its last validation ended
    /// without a verdict.
    pub fn no_verdict_record(&self, block: &[u8; 32]) -> Option<NoVerdictRecord> {
        self.no_verdicts.lock().get(block).cloned()
    }

    /// Every no-verdict record, by block hash (RPC `getdaginfo`).
    pub fn no_verdict_records(&self) -> Vec<([u8; 32], NoVerdictRecord)> {
        let mut v: Vec<_> = self.no_verdicts.lock().iter().map(|(h, r)| (*h, r.clone())).collect();
        v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Whether `block` may be validated again at `now` (its backoff has
    /// elapsed, or it has no record).
    pub fn no_verdict_due(&self, block: &[u8; 32], now: std::time::Instant) -> bool {
        self.no_verdicts.lock().get(block).is_none_or(|r| r.retry_at <= now)
    }

    /// Whether a no-verdict error line may be logged at `now` (at most one
    /// per [`NO_VERDICT_LOG_INTERVAL`]); `Some(n)`: yes, `n` lines were
    /// suppressed since the last one.
    pub fn no_verdict_log_permit(&self, now: std::time::Instant) -> Option<u64> {
        let mut g = self.no_verdict_log.lock();
        match g.0 {
            Some(last) if now.saturating_duration_since(last) < NO_VERDICT_LOG_INTERVAL => {
                g.1 = g.1.saturating_add(1);
                None
            }
            _ => {
                let suppressed = std::mem::take(&mut g.1);
                g.0 = Some(now);
                Some(suppressed)
            }
        }
    }

    /// Fault injection for tests (review of audit F1): every read of an
    /// output of `txid` through [`Storage::get_utxo`] fails with
    /// `StorageError::ReadFailed` (an engine error) until
    /// [`Storage::clear_injected_read_failures`]. The node never calls it.
    #[allow(dead_code)] // library API (tests)
    pub fn inject_utxo_read_failure(&self, txid: [u8; 32]) {
        self.injected_read_faults.lock().insert(txid);
        self.read_faults_armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Fault injection for tests (review of PR #15, findings 4-6): reads of
    /// the stored body of `hash` fail with `StorageError::ReadFailed` (an
    /// engine error) until [`Storage::clear_injected_read_failures`]: its
    /// presence check ([`Storage::has_block_body`]) when `presence`, else
    /// its reads ([`Storage::get_block`], [`Storage::get_block_wire_bytes`]).
    /// The node never calls it.
    #[allow(dead_code)] // library API (tests)
    pub fn inject_body_read_failure(&self, hash: [u8; 32], presence: bool) {
        let mut g = self.injected_body_faults.lock();
        if presence { g.presence.insert(hash); } else { g.reads.insert(hash); }
        self.read_faults_armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Ends [`Storage::inject_utxo_read_failure`] and
    /// [`Storage::inject_body_read_failure`].
    #[allow(dead_code)] // library API (tests)
    pub fn clear_injected_read_failures(&self) {
        self.injected_read_faults.lock().clear();
        *self.injected_body_faults.lock() = Default::default();
        self.read_faults_armed.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    #[inline]
    fn injected_body_failure(&self, hash: &[u8; 32], presence: bool) -> Result<(), StorageError> {
        if self.read_faults_armed.load(std::sync::atomic::Ordering::Relaxed) {
            let g = self.injected_body_faults.lock();
            if (if presence { &g.presence } else { &g.reads }).contains(hash) {
                return Err(StorageError::ReadFailed("injected body read failure (test fault injection)".into()));
            }
        }
        Ok(())
    }

    /// Make every block parked without a verdict due for its retry at `now`
    /// (its backoff is cut short; the attempt counts are kept). Tests use it
    /// to let the next acceptance retry a parked block.
    #[allow(dead_code)] // library API (tests)
    pub fn make_no_verdict_retries_due(&self, now: std::time::Instant) {
        for r in self.no_verdicts.lock().values_mut() {
            r.retry_at = r.retry_at.min(now);
        }
    }

    #[inline]
    fn injected_read_failure(&self, txid: &[u8]) -> Result<(), StorageError> {
        if self.read_faults_armed.load(std::sync::atomic::Ordering::Relaxed)
            && <[u8; 32]>::try_from(txid).is_ok_and(|t| self.injected_read_faults.lock().contains(&t))
        {
            return Err(StorageError::ReadFailed("injected read failure (test fault injection)".into()));
        }
        Ok(())
    }

    /// Audit F1: `block` was validated (a verdict was reached).
    pub fn clear_no_verdict(&self, block: &[u8; 32]) {
        let mut m = self.no_verdicts.lock();
        if !m.is_empty() {
            m.remove(block);
        }
    }

    /// Audit F1: stop the node (Bitcoin Core's `AbortNode`): from now on
    /// [`Storage::abort_reason`] reports `reason` (the first one is kept).
    pub fn abort_node(&self, reason: String) {
        self.abort_reason.lock().get_or_insert(reason);
    }

    /// Why the node was stopped ([`Storage::abort_node`]), if it was.
    pub fn abort_reason(&self) -> Option<String> {
        self.abort_reason.lock().clone()
    }

    /// Fault injection for tests (audit DAG-11; in the spirit of Bitcoin
    /// Core's `-dbcrashratio`): the next `n` atomic batch commits through
    /// [`Storage::write_batch`] (every chain move, `reorg::connect_plan`, and
    /// every DAG-record write of a block that does not move the chain) fail
    /// with `StorageError::WriteFailed` and write nothing. The node never
    /// calls it.
    #[allow(dead_code)] // library API (tests)
    pub fn inject_batch_failures(&self, n: u32) {
        self.injected_batch_failures.store(n, std::sync::atomic::Ordering::SeqCst);
    }

    #[inline]
    fn note_reads(&self, n: u64) {
        self.reads.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        #[cfg(test)]
        READ_PROBE.with(|p| if let Some(f) = p.borrow().as_ref() { f() });
    }

    /// NET-12: total storage reads served by this handle so far (point
    /// reads plus iterator steps of the instrumented accessors).
    #[allow(dead_code)] // library API (tests, diagnostics)
    pub fn storage_reads(&self) -> u64 {
        self.reads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Build the full column-family descriptor list. Shared by the read-write
    /// [`open`] and the read-only [`open_read_only`] paths so both agree on the
    /// exact schema (CF names + per-CF options) — the read-only replay harness
    /// must decode CF_DAG with the identical layout the node wrote.
    fn cf_descriptors() -> Vec<ColumnFamilyDescriptor> {
        let mut addr_utxo_opts = Options::default();
        addr_utxo_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(20));
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS,     Options::default()),
            ColumnFamilyDescriptor::new(CF_UTXO,       Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG,        Options::default()),
            ColumnFamilyDescriptor::new(CF_BLUE_SCORE, Options::default()),
            ColumnFamilyDescriptor::new(CF_META,       Options::default()),
            ColumnFamilyDescriptor::new(CF_HEIGHT,     Options::default()),
            ColumnFamilyDescriptor::new(CF_TIMESTAMPS, Options::default()),
            ColumnFamilyDescriptor::new(CF_ADDR_UTXO,  addr_utxo_opts),
            ColumnFamilyDescriptor::new(CF_COINBASE,   Options::default()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX,   Options::default()),
            {
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(20));
                ColumnFamilyDescriptor::new(CF_ADDR_TX_HISTORY, opts)
            },
            ColumnFamilyDescriptor::new(CF_UNDO,       Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG_INTEGRITY, Options::default()),
            // Phase 1: durable reachability index. Key = 32B block hash,
            // value = encode_record() bytes. A rebuildable cache, never part of
            // the integrity chain; see docs/adr/ADR-035-durable-reachability-index.md.
            ColumnFamilyDescriptor::new(CF_REACHABILITY, Options::default()),
            // Audit COH-2: shielded-pool consensus state (commitment-tree
            // leaves, spent nullifiers, anchor window, per-block undo, tip),
            // written in the same WriteBatch as the UTXO changes.
            ColumnFamilyDescriptor::new(CF_SHIELDED, Options::default()),
            // ── PoBRS CFs (Sprint 1.5) ─────────────────────────────
            ColumnFamilyDescriptor::new(CF_POBRS_META,                Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLES,             Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLES_BY_PK,       Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLE_SNAPSHOTS,    Options::default()),
            {
                // Event log: prefix by height (8B) for efficient range scans
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
                ColumnFamilyDescriptor::new(CF_POBRS_ORACLE_EVENTS, opts)
            },
            ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATIONS,        Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATIONS_EXTRA,  Options::default()),
            {
                // Attestation history: prefix by wallet_hash (32B)
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATION_HISTORY, opts)
            },
            ColumnFamilyDescriptor::new(CF_POBRS_MODELS,              Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_MODEL_PENDING,       Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_DISPUTES,            Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_TEE_PLATFORMS,       Options::default()),
            // ── Bonding CFs (Sprint 2.1.D, ADR-007 §4.7) ────────────
            ColumnFamilyDescriptor::new(CF_BONDING_META,      Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_REGISTRY,  Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_BY_UID,    Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_BY_PUBKEY, Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_HISTORY,   Options::default()),
            ColumnFamilyDescriptor::new(CF_PARTICIPATION,     Options::default()),
            // ── FFG CFs (Sprint 2.1) ───────────────────────────────
            ColumnFamilyDescriptor::new(CF_FFG_META,                  Options::default()),
            ColumnFamilyDescriptor::new(CF_FFG_COMMITTEE,             Options::default()),
            ColumnFamilyDescriptor::new(CF_FFG_PENDING_COMMITTEE,     Options::default()),
        ];
        cfs
    }

    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        let db = DB::open_cf_descriptors(&opts, path, Self::cf_descriptors())
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
        let store = Self::with_db(db);
        store.init_aggregates_marker()?;
        store.init_body_index_marker()?;
        Ok(store)
    }

    /// B1-T17: a database without any body has a complete (empty) body
    /// index; an older one is backfilled by [`Self::ensure_body_index`].
    fn init_body_index_marker(&self) -> Result<(), StorageError> {
        if self.get_meta(BODY_INDEX_READY_KEY)?.is_some() {
            return Ok(());
        }
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        if self.db.iterator_cf(&cf, IteratorMode::Start).next().is_none() {
            self.put_meta(BODY_INDEX_READY_KEY, &[1u8])?;
        }
        Ok(())
    }

    /// B1-T17: give every stored body a body-index row (one-time migration
    /// of a database written before the index existed): its height is the
    /// DAG height of its CF_DAG record, else its header height (never below
    /// the DAG height, so a body is never pruned above the pruning cursor).
    /// Returns the number of rows written (0 when the index was complete).
    pub fn ensure_body_index(&self) -> Result<usize, StorageError> {
        if self.get_meta(BODY_INDEX_READY_KEY)?.is_some() {
            return Ok(0);
        }
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_m = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut rows = 0usize;
        let mut batch = rocksdb::WriteBatch::default();
        for item in self.db.iterator_cf(&cf_b, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            let Ok(hash) = <BlockHash>::try_from(k.as_ref()) else { continue };
            let height = match self.get_dag_data(&hash)? {
                Some(d) => d.height,
                None => match Block::from_wire_bytes(&v) {
                    Ok(b) => b.height,
                    Err(_) => 0, // undecodable: pruned at the first opportunity
                },
            };
            batch.put_cf(&cf_m, body_index_key(height, &hash), []);
            batch.put_cf(&cf_m, body_index_height_key(&hash), height.to_be_bytes());
            rows += 1;
            if rows.is_multiple_of(4096) {
                self.db.write(std::mem::take(&mut batch)).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
            }
        }
        batch.put_cf(&cf_m, BODY_INDEX_READY_KEY.as_bytes(), [1u8]);
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        if rows > 0 {
            log::info!("body index (B1-T17): {} stored bodies indexed by height for pruning", rows);
        }
        Ok(rows)
    }

    /// Open an existing snapshot **read-only**. RocksDB is opened with
    /// `open_cf_descriptors_read_only`, which acquires no write lock, creates
    /// nothing, and rejects every mutating call — so a live node can keep the
    /// same data-dir open while this handle inspects it. Used by the GhostDAG
    /// differential replay harness (`tests/ghostdag_replay_snapshot.rs`) to read
    /// CF_DAG without any risk of touching mined history.
    ///
    /// `path` is the node data-dir (the same directory passed to [`open`]).
    /// The DB must already exist; this never creates column families.
    pub fn open_read_only(path: &Path) -> Result<Self, StorageError> {
        let opts = Options::default();
        // A read-only open cannot create column families, so open only the
        // ones the snapshot has: a data-dir written before a CF was added
        // (e.g. `shielded`, audit COH-2) stays readable.
        let existing: std::collections::HashSet<String> = DB::list_cf(&opts, path)
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?
            .into_iter()
            .collect();
        let descriptors: Vec<ColumnFamilyDescriptor> = Self::cf_descriptors()
            .into_iter()
            .filter(|d| existing.contains(d.name()))
            .collect();
        // `error_if_log_file_exist = false`: tolerate a live/unclean WAL so we
        // can inspect a running node's dir. Read-only mode never replays into or
        // mutates the primary.
        let db = DB::open_cf_descriptors_read_only(&opts, path, descriptors, false)
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
        let store = Self::with_db(db);
        // Read-only: report the marker, never write it.
        let ready = store.get_meta("agg/version").ok().flatten()
            .is_some_and(|v| v.as_slice() == aggregates::AGG_VERSION.to_le_bytes());
        store.agg_ready.store(ready, std::sync::atomic::Ordering::Release);
        Ok(store)
    }

    /// Take the acceptance mutex (audit DAG-10). See the field documentation.
    pub fn acceptance_lock(&self) -> parking_lot::ReentrantMutexGuard<'_, ()> {
        self.accept_lock.lock()
    }

    /// Returns a reference to the underlying RocksDB instance. Used by
    /// `PobrsStorage` (Sprint 1.5 L2) to share the same DB connection
    /// without owning it. Safe because RocksDB handles internal concurrency.
    pub fn db(&self) -> &DB {
        &self.db
    }

    /// Write a block and all of its derived index rows atomically.
    ///
    /// The height of `hash`'s current body-index row (its reverse row), if any.
    fn body_index_height(&self, hash: &BlockHash) -> Result<Option<u64>, StorageError> {
        let cf_m = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let v = self.db.get_cf(&cf_m, body_index_height_key(hash))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?;
        Ok(v.and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok()).map(u64::from_be_bytes))
    }

    /// Stage `hash`'s body-index row at `height` (and its reverse row),
    /// deleting the row of an earlier write at another height (B1-T17).
    fn stage_body_index(&self, batch: &mut rocksdb::WriteBatch, hash: &BlockHash, height: u64)
        -> Result<(), StorageError>
    {
        let cf_m = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        if let Some(old) = self.body_index_height(hash)? {
            if old != height {
                batch.delete_cf(&cf_m, body_index_key(old, hash));
            }
        }
        batch.put_cf(&cf_m, body_index_key(height, hash), []);
        batch.put_cf(&cf_m, body_index_height_key(hash), height.to_be_bytes());
        Ok(())
    }

    /// P0 crash-consistency (roadmap §3.2): previously this issued 4+ separate
    /// `put_cf` calls (block body, height→hash, timestamp, per-tx address
    /// index). A crash between any two left height→hash pointing at a block
    /// body that wasn't there, or an un-indexed block. All writes now go
    /// through a single RocksDB `WriteBatch` committed with one `db.write`, so
    /// either the whole block lands or none of it does. Keys/values/CFs are
    /// byte-identical to the old path — this is a durability fix only, not a
    /// schema or wire change.
    pub fn put_block(&self, block: &Block) -> Result<(), StorageError> {
        let hash = block.block_hash();
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_h = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let cf_t = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        let cf_ai = self.db.cf_handle(CF_ADDR_TX_HISTORY).ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        let mut batch = rocksdb::WriteBatch::default();

        // Sprint 1.b: Bitcoin-format wire serialization (replaces pre-v0.6.0 bincode).
        // Block bytes on disk are now byte-identical to the canonical network
        // wire format, so a future direct-from-disk broadcast path can skip
        // re-encoding. Consensus-breaking; existing v0.5.x RocksDB data-dirs
        // are unreadable at v0.6.0+ and must be reset.
        batch.put_cf(&cf_b, &hash, &block.to_wire_bytes());
        batch.put_cf(&cf_h, &block.height.to_be_bytes(), &hash);
        batch.put_cf(&cf_t, &block.height.to_be_bytes(), &block.header.timestamp.to_le_bytes());
        // B1-T17: body-index row (header height, never below the DAG height).
        self.stage_body_index(&mut batch, &hash, block.height)?;

        // Sprint F: index address touches for each tx in this block. These were
        // previously best-effort (errors ignored). Folding them into the same
        // batch keeps the same entries but makes them crash-consistent with the
        // block body. An entry-computation error for one tx skips only that tx's
        // rows (matching the old best-effort semantics) rather than aborting.
        // B1-T11: the per-address history counters in the same batch.
        let _agg = self.agg_lock();
        let mut history = aggregates::HistoryDeltas::default();
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            match self.addr_index_entries(tx, block.height, tx_idx as u32) {
                Ok(entries) => {
                    for (key, val) in entries {
                        history.put(&key);
                        batch.put_cf(&cf_ai, &key, &val);
                    }
                }
                Err(e) => log::warn!("addr-index skipped for tx {}: {}", tx_idx, e),
            }
        }
        self.stage_history_deltas(&mut batch, &history)?;

        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        self.forget_body_verdict(&hash);
        Ok(())
    }

    /// Persist ONLY the block body (CF_BLOCKS), keyed by block hash.
    ///
    /// Audit DAG-12: `put_block` also writes the height→hash and
    /// height→timestamp indexes and the address-history rows, which are
    /// SELECTED-CHAIN indexes. The acceptance pipeline stores every DAG block's
    /// body (fork-losers and disqualified blocks included, so they can be
    /// served and connected later) through this body-only write, and writes the
    /// chain indexes in the atomic connect batch (`stage_chain_index`) only for
    /// blocks that join the selected chain — so a fork-loser or a refused block
    /// can no longer overwrite `getblockhash`'s answer or the pruning cursor.
    ///
    /// Audit B1-T17: the body is indexed for pruning at its header height
    /// (never below its DAG height); the acceptance pipeline uses
    /// [`Self::put_block_body_at`] with the height it chose.
    pub fn put_block_body(&self, block: &Block) -> Result<(), StorageError> {
        self.put_block_body_at(block, block.height)
    }

    /// [`Self::put_block_body`] indexed for pruning at `prune_height` (audit
    /// B1-T17): the body is pruned once the pruning cursor
    /// (`pruned_height`) passes `prune_height`. The caller passes the
    /// block's DAG height, or a greater height to keep a body longer (a body
    /// the node fetched back for a reorg, `accept::accept_block`); never a
    /// smaller one (`accept::awaits_body` relies on "a block whose DAG height
    /// is at or above the cursor was never pruned"). Body and index row are
    /// written in one batch.
    pub fn put_block_body_at(&self, block: &Block, prune_height: u64) -> Result<(), StorageError> {
        let hash = block.block_hash();
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf_b, hash, block.to_wire_bytes());
        // One row per body: a re-stored body's earlier row (left by a write
        // at another height) goes in the same batch.
        self.stage_body_index(&mut batch, &hash, prune_height)?;
        let written = self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()));
        self.forget_body_verdict(&hash);
        written
    }

    /// Delete a block body (CF_BLOCKS) and its body-index rows (B1-T17), in
    /// one batch. Used to drop the body of a block whose DAG insertion was
    /// rolled back (refused by policy) or whose body was rejected, so nothing
    /// unreferenced is left behind — in particular no index row that would
    /// later prune a replacement body stored to be kept longer.
    pub fn delete_block_body(&self, hash: &[u8; 32]) -> Result<(), StorageError> {
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_m = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_cf(&cf_b, hash);
        if let Some(h) = self.body_index_height(hash)? {
            batch.delete_cf(&cf_m, body_index_key(h, hash));
            batch.delete_cf(&cf_m, body_index_height_key(hash));
        }
        let deleted = self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()));
        self.forget_body_verdict(hash);
        deleted
    }

    /// A verdict `verdict(body)` on the body stored under `hash`, memoized per
    /// hash and `key`: `Ok(None)` when no body is stored (checked on every
    /// call, so a pruned or deleted body is never reported), otherwise the
    /// memoized verdict for `(hash, key)` or, on a miss, `verdict` applied to
    /// the decoded body and recorded. `verdict` MUST be a pure function of the
    /// body and `key` (one memo slot per hash: another `key` replaces it).
    /// Every body write or delete through this type (`put_block`,
    /// `put_block_body`, `delete_block_body`, `prune_blocks_below`) drops the
    /// hash's memo, and a verdict computed while a body changed is not
    /// recorded; a raw write through [`Storage::db`] bypasses the memo.
    /// A body that cannot be read or decoded is an error and is not memoized.
    ///
    /// Used by the block template's parent predicate
    /// (`template::template_parents_and_height_at`), which runs on every
    /// valid tip at every block acceptance: without the memo every call
    /// decoded and re-hashed (Merkle and witness roots) every tip body.
    pub fn body_verdict<F: FnOnce(&Block) -> bool>(
        &self,
        hash: &[u8; 32],
        key: u64,
        verdict: F,
    ) -> Result<Option<bool>, StorageError> {
        if !self.has_block_body(hash)? {
            return Ok(None);
        }
        let epoch = {
            let memo = self.body_verdicts.lock();
            if let Some(&(k, v)) = memo.map.get(hash) {
                if k == key {
                    return Ok(Some(v));
                }
            }
            memo.epoch
        };
        let Some(block) = self.get_block(hash)? else { return Ok(None) };
        let v = verdict(&block);
        let mut memo = self.body_verdicts.lock();
        memo.computed = memo.computed.wrapping_add(1);
        if memo.epoch == epoch {
            if memo.map.len() >= BODY_VERDICT_MEMO_CAP && !memo.map.contains_key(hash) {
                memo.map.clear();
            }
            memo.map.insert(*hash, (key, v));
        }
        Ok(Some(v))
    }

    /// Number of verdicts [`Storage::body_verdict`] computed (memo misses)
    /// since the store was opened. Diagnostics and tests (the `gnb` binary
    /// does not call it).
    #[allow(dead_code)]
    pub fn body_verdicts_computed(&self) -> u64 {
        self.body_verdicts.lock().computed
    }

    /// Drop the memoized body verdict of `hash` (its body was written or
    /// deleted).
    fn forget_body_verdict(&self, hash: &[u8; 32]) {
        let mut memo = self.body_verdicts.lock();
        memo.map.remove(hash);
        memo.epoch = memo.epoch.wrapping_add(1);
    }

    /// Whether a body is stored for `hash` (no decoding).
    pub fn has_block_body(&self, hash: &[u8; 32]) -> Result<bool, StorageError> {
        self.injected_body_failure(hash, true)?;
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        Ok(self.db.get_pinned_cf(&cf, hash)
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            .is_some())
    }

    pub fn get_block(&self, hash: &[u8; 32]) -> Result<Option<Block>, StorageError> {
        self.note_reads(1);
        self.injected_body_failure(hash, false)?;
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(
                Block::from_wire_bytes(&d)
                    .map_err(StorageError::DeserializeFailed)?
            )),
            None    => Ok(None),
        }
    }

    /// The stored body of `hash` exactly as stored: the canonical
    /// `Block::to_wire_bytes` encoding every write path uses, not decoded.
    /// The `/gnb/sync/1` server sends these bytes as they are (audit B2-T6:
    /// it used to decode the block and encode it again for every request).
    pub fn get_block_wire_bytes(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        self.note_reads(1);
        self.injected_body_failure(hash, false)?;
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    pub fn get_block_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 32 => { let mut h = [0u8;32]; h.copy_from_slice(&d); Ok(Some(h)) }
            _ => Ok(None),
        }
    }

    pub fn get_timestamp_at_height(&self, height: u64) -> Result<Option<u64>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 8 => Ok(Some(u64::from_le_bytes(d[..8].try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    /// Create (or overwrite) one UTXO with its address-index row. NET-12:
    /// the explorer aggregates change in the SAME write batch.
    pub fn put_utxo(&self, txid: &[u8], index: u32, output: &TxOutput) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let key = utxo_key(txid, index);
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        if let Some(prev) = self.get_utxo(txid, index)? {
            deltas.remove(&prev);
        }
        deltas.add(output);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf, &key, &encode(output)?);

        // Address index: key = [20B address][32B txid][4B index], value = empty
        if output.script_pubkey.len() >= 20 {
            let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
            let ai_key = addr_utxo_key(&output.script_pubkey, txid, index);
            batch.put_cf(&cf_ai, &ai_key, []);
        }
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn get_utxo(&self, txid: &[u8], index: u32) -> Result<Option<TxOutput>, StorageError> {
        self.note_reads(1);
        self.injected_read_failure(txid)?;
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        match self.db.get_cf(&cf, &utxo_key(txid, index)).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None    => Ok(None),
        }
    }

    pub fn iter_all_blocks(&self) -> Vec<([u8; 32], crate::core::Block)> {
        let mut results = Vec::new();
        if let Some(cf) = self.db.cf_handle(CF_BLOCKS) {
            let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
            for item in iter {
                self.note_reads(1);
                if let Ok((key, val)) = item {
                    if key.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&key);
                        // Sprint 1.b: Bitcoin-format decode (replaces bincode).
                        if let Ok(block) = crate::core::Block::from_wire_bytes(&val) {
                            results.push((hash, block));
                        }
                    }
                }
            }
        }
        results
    }

    /// Iterate the entire UTXO set in DETERMINISTIC order for snapshotting.
    ///
    /// Returns `(txid, vout, value, script_pubkey)` sorted by the raw CF_UTXO key,
    /// which is `txid ‖ vout_be` — so the order is a pure function of the set's
    /// contents, independent of insertion history, RocksDB compaction state, or
    /// which node produced it. Two honest nodes at the same height MUST produce
    /// byte-identical output; that is what makes a commitment over this meaningful.
    ///
    /// Why this exists: block bodies below `pruned_height` are deleted (see
    /// [`Self::prune_blocks_below`]) but the UTXO set is retained in full. On this
    /// fleet in 2026-07 that left ~95% of history unservable while every balance
    /// stayed intact and queryable — so the SET is recoverable even when the CHAIN
    /// that produced it is not. A snapshot taken here is the carry-over artifact
    /// for any migration, and the input to an assumeutxo-style bootstrap for fresh
    /// nodes that cannot sync from genesis because no archival peer has the bodies.
    ///
    /// Read-only friendly: pair with [`Self::open_read_only`] to snapshot a data-dir
    /// while the node keeps running on it.
    pub fn iter_utxos_sorted(&self) -> Result<Vec<(Vec<u8>, u32, u64, Vec<u8>)>, StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let mut out: Vec<(Vec<u8>, u32, u64, Vec<u8>)> = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            self.note_reads(1);
            let (key, val) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            // Fail the whole export on corruption; a partial ledger cannot
            // be advertised as a complete carryover set. Preserve historical
            // vout decoding for reproducibility (Legacy M-3).
            out.push(decode_snapshot_row(&key, &val, false)?);
        }
        // RocksDB already yields keys in byte order; sort explicitly so the
        // guarantee is in THIS function rather than in an engine detail.
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        Ok(out)
    }

    pub fn clear_utxos(&self) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            if let Ok((key, val)) = item {
                if let Ok(out) = decode::<TxOutput>(&val) {
                    deltas.remove(&out);
                }
                batch.delete_cf(&cf, &key);
            }
        }
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    /// Delete one UTXO with its address-index row. NET-12: the explorer
    /// aggregates change in the SAME write batch.
    pub fn delete_utxo(&self, txid: &[u8], index: u32) -> Result<(), StorageError> {
        // Fetch the UTXO first to get the address for index cleanup
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        let mut batch = rocksdb::WriteBatch::default();
        if let Some(data) = self.db.get_cf(&cf, &utxo_key(txid, index))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
        {
            if let Ok(output) = decode::<TxOutput>(&data) {
                if output.script_pubkey.len() >= 20 {
                    let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
                    batch.delete_cf(&cf_ai, addr_utxo_key(&output.script_pubkey, txid, index));
                }
                deltas.remove(&output);
            }
        }
        batch.delete_cf(&cf, utxo_key(txid, index));
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// O(k) balance query via address index (was O(n) full UTXO scan)
    pub fn get_balance(&self, address_bytes: &[u8]) -> Result<(u64, usize), StorageError> {
        self.get_balance_cancellable(address_bytes, &std::sync::atomic::AtomicBool::new(false))
    }

    /// [`Self::get_balance`] that checks `cancel` on every UTXO (B1-T11: the
    /// RPC uses the O(1) holder aggregate, [`Self::address_balance`]; this
    /// walk is its fallback while the aggregates are rebuilt).
    pub fn get_balance_cancellable(
        &self,
        address_bytes: &[u8],
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(u64, usize), StorageError> {
        if address_bytes.len() < 20 {
            return Ok((0, 0)); // invalid address length
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let prefix = address_bytes.to_vec();

        let (mut total, mut count) = (0u64, 0usize);
        let iter = self.db.prefix_iterator_cf(&cf_ai, &prefix);
        for item in iter {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(aggregates::cancelled());
            }
            self.note_reads(2);
            if let Ok((k, _)) = item {
                // Stop when prefix no longer matches
                if k.len() < address_bytes.len() || &k[..address_bytes.len()] != address_bytes { break; }
                // Extract txid + index from key: [20B addr][32B txid][4B idx]
                let expected_len = address_bytes.len() + 36;
                if k.len() == expected_len {
                    let utxo_k = k[address_bytes.len()..expected_len].to_vec(); // 32B txid + 4B index
                    if let Some(v) = self.db.get_cf(&cf_utxo, &utxo_k)
                        .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                    {
                        if let Ok(out) = decode::<TxOutput>(&v) {
                            total = total.saturating_add(out.value);
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok((total, count))
    }

    /// Count distinct addresses that currently hold at least one UTXO — i.e.
    /// the number of on-chain "wallets" with a non-zero balance. Iterates
    /// CF_ADDR_UTXO whose keys are `[20B addr][32B txid][4B idx]`; the distinct
    /// 20-byte address prefixes are the wallets. Also returns the total UTXO
    /// entry count. O(n) over the UTXO-address index.
    pub fn count_addresses_with_balance(&self) -> Result<(usize, usize), StorageError> {
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO)
            .ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let mut set = std::collections::HashSet::<[u8; 20]>::new();
        let mut utxos = 0usize;
        for item in self.db.iterator_cf(&cf_ai, IteratorMode::Start) {
            self.note_reads(1);
            if let Ok((k, _)) = item {
                if k.len() >= 20 {
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&k[..20]);
                    set.insert(addr);
                    utxos += 1;
                }
            }
        }
        Ok((set.len(), utxos))
    }

    /// O(k) UTXO lookup via address index (was O(n) full UTXO scan)
    /// UTXOs paying exactly `address_bytes`, the FULL script_pubkey (20-byte
    /// key hash or 33-byte policy script): the index key is
    /// `script ‖ txid ‖ index`, so a shorter prefix finds nothing.
    pub fn get_utxos_for_address(&self, address_bytes: &[u8]) -> Result<Vec<(Vec<u8>, u32, TxOutput)>, StorageError> {
        if address_bytes.len() < 20 {
            return Ok(vec![]);
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let prefix = address_bytes.to_vec();

        let mut result = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf_ai, &prefix);
        for item in iter {
            self.note_reads(2);
            if let Ok((k, _)) = item {
                let alen = address_bytes.len();
                if k.len() < alen || &k[..alen] != address_bytes { break; }
                let expected = alen + 36;
                if k.len() == expected {
                    let txid = k[alen..alen+32].to_vec();
                    let idx = u32::from_le_bytes(k[alen+32..expected].try_into().unwrap());
                    let utxo_k = k[alen..expected].to_vec();
                    if let Some(v) = self.db.get_cf(&cf_utxo, &utxo_k)
                        .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                    {
                        if let Ok(out) = decode::<TxOutput>(&v) {
                            result.push((txid, idx, out));
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    /// NET-12: [`Self::get_utxos_for_address`] that stops after `limit`
    /// entries while walking the address index, instead of loading every
    /// UTXO of the address first. Returns the UTXOs and whether more exist.
    pub fn get_utxos_for_address_limited(
        &self,
        address_bytes: &[u8],
        limit: usize,
    ) -> Result<(Vec<(Vec<u8>, u32, TxOutput)>, bool), StorageError> {
        if address_bytes.len() < 20 {
            return Ok((vec![], false));
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let alen = address_bytes.len();
        let expected = alen + 36;
        let mut result = Vec::new();
        for (k, _) in self.db.prefix_iterator_cf(&cf_ai, address_bytes).flatten() {
            self.note_reads(2);
            if k.len() < alen || &k[..alen] != address_bytes { break; }
            if k.len() != expected { continue; }
            let Some(v) = self.db.get_cf(&cf_utxo, &k[alen..expected])
                .map_err(|e| StorageError::ReadFailed(e.to_string()))? else { continue };
            let Ok(out) = decode::<TxOutput>(&v) else { continue };
            if result.len() == limit {
                return Ok((result, true));
            }
            let mut idx = [0u8; 4];
            idx.copy_from_slice(&k[alen + 32..expected]);
            result.push((k[alen..alen + 32].to_vec(), u32::from_le_bytes(idx), out));
        }
        Ok((result, false))
    }

    // ── DAG persistence ─────────────────────────────────────────────────────

    /// Persist GhostDAG data for a single block
    pub fn put_dag_data(&self, hash: &BlockHash, data: &GhostdagData) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        self.db.put_cf(&cf, hash, &encode(data)?)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load GhostDAG data for a single block
    pub fn get_dag_data(&self, hash: &BlockHash) -> Result<Option<GhostdagData>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None    => Ok(None),
        }
    }

    // ── Sprint Y (M-2): GhostdagData integrity chain ──────────────────
    //
    // See `src/consensus/mod.rs::canonical_encode` and
    // `compute_integrity_hash` for the chain definition, and
    // `GhostDAG::load_persisted_validated` for the verifier.
    //
    // `put_dag_with_integrity` is the preferred write path: it looks up
    // the parent's integrity hash, computes this block's integrity, and
    // writes both CF_DAG and CF_DAG_INTEGRITY in a single WriteBatch so
    // they can never drift out of sync.
    //
    // The plain `put_dag_data` above is kept for backwards compatibility
    // and for call sites that have already computed integrity themselves.

    /// Persist GhostDAG data AND its integrity hash atomically.
    /// Returns the computed integrity hash (useful for logging / chaining).
    pub fn put_dag_with_integrity(
        &self,
        hash: &BlockHash,
        data: &GhostdagData,
    ) -> Result<[u8; 32], StorageError> {
        // 1. Parent lookup. Genesis uses all-zero parent integrity —
        //    matches the chain base convention in `load_persisted_validated`.
        let parent_integrity: [u8; 32] = match &data.selected_parent {
            Some(sp) => self.get_integrity_hash(sp)?.unwrap_or([0u8; 32]),
            None     => [0u8; 32],
        };

        // 2. Compute this block's chain link.
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);

        // 3. Atomic write. WriteBatch guarantees either both CFs are
        //    updated or neither, even if the process is killed mid-write.
        let cf_dag = self.db.cf_handle(CF_DAG)
            .ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;

        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        self.db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        Ok(integrity)
    }

    /// Read a single block's integrity hash. `Ok(None)` if absent —
    /// the caller distinguishes between "pre-Sprint-Y database" (all
    /// absent) and "targeted deletion" (some absent) at load time.
    pub fn get_integrity_hash(&self, hash: &BlockHash) -> Result<Option<[u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Ok(Some(out))
            }
            Some(_) => Err(StorageError::DeserializeFailed(
                "CF_DAG_INTEGRITY entry has wrong length (not 32 bytes)".into()
            )),
            None => Ok(None),
        }
    }

    /// Persist an integrity hash directly. Used by `load_persisted_validated`
    /// during the self-heal migration from pre-Sprint-Y databases.
    pub fn put_integrity_hash(
        &self,
        hash: &BlockHash,
        integrity: &[u8; 32],
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        self.db.put_cf(&cf, hash, integrity)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load every (block_hash → integrity_hash) record from CF_DAG_INTEGRITY.
    /// Returns an empty map on a pre-Sprint-Y database; the caller treats
    /// that as "self-heal on first boot".
    pub fn load_all_integrity_hashes(
        &self,
    ) -> Result<std::collections::HashMap<BlockHash, [u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let mut map = std::collections::HashMap::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 && v.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&k);
                    let mut i = [0u8; 32];
                    i.copy_from_slice(&v);
                    map.insert(h, i);
                }
            }
        }
        Ok(map)
    }

    /// Load all persisted DAG data for full reconstruction on startup.
    /// Returns (hash, data) pairs in insertion order is NOT guaranteed —
    /// caller must handle topological insertion.
    pub fn load_all_dag_data(&self) -> Result<Vec<(BlockHash, GhostdagData)>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let mut entries = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&k);
                    if let Ok(data) = decode::<GhostdagData>(&v) {
                        entries.push((hash, data));
                    }
                }
            }
        }
        Ok(entries)
    }

    // ── Durable reachability index (Phase 1) ────────────────────────────
    //
    // The interval-reachability index (`consensus::reachability::ReachabilityStore`)
    // is an O(1)/O(log n) DAG-ancestry cache. It is NOT consensus state — it is
    // never hashed into the integrity chain and can always be rebuilt by
    // replaying CF_DAG. To make it durable (and avoid an O(chain) rebuild every
    // boot) its per-block records live in CF_REACHABILITY, and — crucially —
    // each record delta is written in the SAME WriteBatch as the CF_DAG block it
    // derives from (`put_dag_with_integrity_and_reach`), so a crash can never
    // leave the index describing a block CF_DAG doesn't have, or vice-versa.
    //
    // The layout version + root live in CF_META under `reachability/meta/*`.

    /// Schema version for the CF_REACHABILITY record layout, mirrored from
    /// `consensus::reachability::REACHABILITY_RECORD_VERSION`. On boot a
    /// mismatch (or absent tag) forces a full rebuild from CF_DAG.
    pub const REACHABILITY_SCHEMA_VERSION: u32 =
        crate::consensus::reachability::REACHABILITY_RECORD_VERSION;

    /// Atomic CF_DAG + CF_DAG_INTEGRITY + CF_REACHABILITY write.
    ///
    /// Identical to [`put_dag_with_integrity`] for the DAG/integrity CFs, but
    /// additionally folds the reachability delta (`reach_upserts` /
    /// `reach_removals`, drained from `ReachabilityStore::take_persist_delta`)
    /// into the SAME `WriteBatch`. All-or-nothing: after a crash the block, its
    /// integrity link, and every reachability record touched by inserting it
    /// either all landed or none did.
    ///
    /// Used only when the reachability index is being maintained (Fast /
    /// armed-activation). On the live Legacy path the caller uses the plain
    /// [`put_dag_with_integrity`] and CF_REACHABILITY stays empty.
    pub fn put_dag_with_integrity_and_reach(
        &self,
        hash: &BlockHash,
        data: &GhostdagData,
        reach_upserts: &[(BlockHash, Vec<u8>)],
        reach_removals: &[BlockHash],
    ) -> Result<[u8; 32], StorageError> {
        let mut batch = rocksdb::WriteBatch::default();
        let integrity = self.stage_dag_entry(&mut batch, hash, data, reach_upserts, reach_removals)?;
        self.db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(integrity)
    }

    /// Stage a block's CF_DAG entry, its integrity link and a reachability
    /// delta into `batch`, so a caller can commit them together with the
    /// chain-state change of the same block (one atomic write: a crash can
    /// never leave the UTXO set applied for a block CF_DAG does not know).
    /// The selected parent's integrity hash must already be committed.
    pub fn stage_dag_entry(
        &self,
        batch: &mut rocksdb::WriteBatch,
        hash: &BlockHash,
        data: &GhostdagData,
        reach_upserts: &[(BlockHash, Vec<u8>)],
        reach_removals: &[BlockHash],
    ) -> Result<[u8; 32], StorageError> {
        let parent_integrity: [u8; 32] = match &data.selected_parent {
            Some(sp) => self.get_integrity_hash(sp)?.unwrap_or([0u8; 32]),
            None     => [0u8; 32],
        };
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);

        let cf_dag = self.db.cf_handle(CF_DAG)
            .ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;

        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        for (h, rec) in reach_upserts {
            batch.put_cf(&cf_reach, h, rec);
        }
        for h in reach_removals {
            batch.delete_cf(&cf_reach, h);
        }
        Ok(integrity)
    }

    // ── Batched chain-state staging (audit DAG-11) ─────────────────────
    //
    // The acceptance pipeline commits a block's UTXO effects, undo record,
    // CF_DAG + CF_DAG_INTEGRITY (+ CF_REACHABILITY) record, the selected-chain
    // indexes, the tip pointer and any invalid-block marks in ONE RocksDB
    // WriteBatch (see `reorg::connect_plan`). These helpers stage into a
    // caller-owned batch; nothing is visible until the caller commits it.

    /// Stage a block's CF_DAG + CF_DAG_INTEGRITY record (+ the reachability
    /// delta) into `batch`. Returns the staged integrity hash.
    ///
    /// Unlike `put_dag_with_integrity`, a missing selected-parent integrity
    /// record is an ERROR here (DAG-11): zero-filling it wrote a link that the
    /// boot-time chain check then rejected, turning a lost write into a fatal
    /// start-up error. `parent_integrity_override` lets the caller supply a
    /// parent integrity it staged in the same batch (lazy genesis record).
    pub fn stage_dag_record(
        &self,
        batch: &mut rocksdb::WriteBatch,
        hash: &BlockHash,
        data: &GhostdagData,
        reach_upserts: &[(BlockHash, Vec<u8>)],
        reach_removals: &[BlockHash],
        parent_integrity_override: Option<[u8; 32]>,
    ) -> Result<[u8; 32], StorageError> {
        let parent_integrity: [u8; 32] = match (&data.selected_parent, parent_integrity_override) {
            (_, Some(p)) => p,
            (Some(sp), None) => self.get_integrity_hash(sp)?.ok_or_else(|| {
                StorageError::ReadFailed(format!(
                    "integrity record of selected parent {} is missing; refusing to \
                     write a zero-filled chain link",
                    hex::encode(&sp[..8])
                ))
            })?,
            (None, None) => [0u8; 32],
        };
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);
        let cf_dag = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        for (h, rec) in reach_upserts {
            batch.put_cf(&cf_reach, h, rec);
        }
        for h in reach_removals {
            batch.delete_cf(&cf_reach, h);
        }
        Ok(integrity)
    }

    /// Stage the start-up repair of the DAG records (audit DAG-11,
    /// `GhostDAG::load_persisted_repairing`): the recomputed CF_DAG records,
    /// the re-derived CF_DAG_INTEGRITY link of every loaded block, and the
    /// removal of the dropped blocks' CF_DAG, CF_DAG_INTEGRITY and
    /// CF_REACHABILITY records. The reachability version tag is removed too,
    /// so the start-up path rebuilds the persisted index from CF_DAG.
    pub fn stage_dag_repair(
        &self,
        batch: &mut rocksdb::WriteBatch,
        recomputed: &[(BlockHash, GhostdagData)],
        integrity: &std::collections::HashMap<BlockHash, [u8; 32]>,
        dropped: &[BlockHash],
    ) -> Result<(), StorageError> {
        let cf = |n: &str| self.db.cf_handle(n).ok_or_else(|| StorageError::CfNotFound(n.into()));
        let (cf_dag, cf_int, cf_reach, cf_meta) = (cf(CF_DAG)?, cf(CF_DAG_INTEGRITY)?, cf(CF_REACHABILITY)?, cf(CF_META)?);
        for (h, d) in recomputed {
            batch.put_cf(&cf_dag, h, &encode(d)?);
        }
        for (h, i) in integrity {
            batch.put_cf(&cf_int, h, i);
        }
        for h in dropped {
            batch.delete_cf(&cf_dag, h);
            batch.delete_cf(&cf_int, h);
            batch.delete_cf(&cf_reach, h);
        }
        batch.delete_cf(&cf_meta, b"reachability/meta/version");
        Ok(())
    }

    /// Stage a CF_META write.
    pub fn stage_meta(&self, batch: &mut rocksdb::WriteBatch, key: &str, value: &[u8])
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        batch.put_cf(&cf, key.as_bytes(), value);
        Ok(())
    }

    /// Commit a caller-built batch atomically.
    pub fn write_batch(&self, batch: rocksdb::WriteBatch) -> Result<(), StorageError> {
        use std::sync::atomic::Ordering;
        if self.injected_batch_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(StorageError::WriteFailed("injected batch failure (test fault injection)".into()));
        }
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Stage the SELECTED-CHAIN indexes of a block being connected (DAG-12):
    /// position→hash, position→timestamp and the address-history rows. Input
    /// rows resolve the spent output through `spent` (the block's undo
    /// capture), so they are byte-identical to what a rollback un-indexes.
    ///
    /// `position` is the block's place on the selected chain, its DAG height
    /// (`GhostdagData::height`: 0 for the genesis, + 1 per selected-parent
    /// edge), NOT its header height (audit DAG-8): header heights repeat and
    /// decrease along the selected chain, so rows keyed by them collided, a
    /// later block overwrote an earlier one's and disconnecting it deleted a
    /// row of a block still on the chain. Positions are unique along the
    /// selected chain, like Bitcoin Core's active-chain heights
    /// ([`CHAIN_INDEX_VERSION`]).
    ///
    /// B1-T11: every history row staged is recorded in `history`; the caller
    /// stages the per-address counters ([`Self::stage_history_deltas`]) into
    /// the same batch before writing it.
    pub fn stage_chain_index(
        &self,
        batch: &mut rocksdb::WriteBatch,
        block: &Block,
        position: u64,
        spent: &std::collections::HashMap<([u8; 32], u32), TxOutput>,
        history: &mut aggregates::HistoryDeltas,
    ) -> Result<(), StorageError> {
        let hash = block.block_hash();
        self.stage_chain_position(batch, position, &hash, block.header.timestamp)?;
        let cf_ai = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        let position_key = position;
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid();
            for (vout, out) in tx.outputs.iter().enumerate() {
                if out.script_pubkey.len() >= 20 {
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&out.script_pubkey[..20]);
                    let key = indexer::make_key(&addr, position_key, tx_idx as u32, vout as u32);
                    history.put(&key);
                    batch.put_cf(&cf_ai, key, indexer::make_value(&txid, indexer::DIR_OUT, out.value));
                }
            }
            if !tx.is_coinbase() {
                for (vin, inp) in tx.inputs.iter().enumerate() {
                    if let Some(prev) = spent.get(&(inp.prev_txid, inp.prev_index)) {
                        if prev.script_pubkey.len() >= 20 {
                            let mut addr = [0u8; 20];
                            addr.copy_from_slice(&prev.script_pubkey[..20]);
                            let key = indexer::make_key(&addr, position_key, tx_idx as u32, 0x8000_0000 | vin as u32);
                            history.put(&key);
                            batch.put_cf(&cf_ai, key, indexer::make_value(&txid, indexer::DIR_IN, prev.value));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Stage the position→hash and position→timestamp rows of a
    /// selected-chain block (see [`Storage::stage_chain_index`]).
    pub fn stage_chain_position(&self, batch: &mut rocksdb::WriteBatch, position: u64, hash: &BlockHash, timestamp: u64)
        -> Result<(), StorageError>
    {
        let cf_h = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let cf_t = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        batch.put_cf(&cf_h, position.to_be_bytes(), hash);
        batch.put_cf(&cf_t, position.to_be_bytes(), timestamp.to_le_bytes());
        Ok(())
    }

    /// Stage removal of a disconnected block's position→hash /
    /// position→timestamp rows at its selected-chain `position` (its DAG
    /// height), but only where they point at this block. Positions are
    /// unique along the selected chain (DAG-8), so the row is the block's
    /// own; the check guards against a caller passing another position.
    /// Address-history rows are un-indexed by the rollback staging itself.
    /// Works from the position and hash alone, so a block whose body was
    /// pruned can be disconnected by a reorg of any depth (audit DAG-6).
    pub fn stage_chain_unindex_at(&self, batch: &mut rocksdb::WriteBatch, position: u64, hash: &BlockHash)
        -> Result<(), StorageError>
    {
        if self.get_block_hash_at_height(position)? == Some(*hash) {
            let cf_h = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
            let cf_t = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
            batch.delete_cf(&cf_h, position.to_be_bytes());
            batch.delete_cf(&cf_t, position.to_be_bytes());
        }
        Ok(())
    }

    /// The selected-chain position (DAG height) of `hash` from its CF_DAG
    /// record; a block without one is the genesis iff its stored header has
    /// no parents (fixture stores that never wrote the genesis record).
    pub fn chain_position(&self, hash: &BlockHash) -> Result<Option<u64>, StorageError> {
        if let Some(d) = self.get_dag_data(hash)? {
            return Ok(Some(d.height));
        }
        Ok(self.get_block(hash)?.filter(|b| b.header.parents.is_empty()).map(|_| 0))
    }

    /// Rebuild the selected-chain indexes in the position layout (audit
    /// DAG-8, [`CHAIN_INDEX_VERSION`] 2) in ONE batch, given the applied
    /// selected chain as `(hash, position, timestamp)` from the genesis up.
    /// The one rebuild path: the start-up migration of a data dir of an
    /// earlier release (`accept::migrate_chain_indexes`) and the operator's
    /// `--reindex-addresses` (`accept::reindex_chain_indexes`) both run it.
    /// Releases before DAG-8 keyed CF_HEIGHT, CF_TIMESTAMPS and the address
    /// history by header height, where two chain blocks could share a row
    /// (the later one's replaced the earlier one's), wrote rows for blocks
    /// that never joined the chain (fork siblings, on arrival), and lost the
    /// spend rows of blocks a reorg rolled back and re-applied. Every row of
    /// the three column families is deleted and rewritten from the chain: the
    /// height and timestamp rows for every chain block, the address-history
    /// rows of every block whose body is stored from the body and its undo
    /// record (exactly what a connect writes: the undo record holds every
    /// output the block spent, genesis-ledger outputs included, so no
    /// snapshot is needed to resolve a spend), and those of a pruned block by
    /// moving the rows its pruned-body record names to its position, when the
    /// stored row still belongs to it (a row an earlier release overwrote
    /// with another block's, or lost, cannot be recovered without the body);
    /// the record is rewritten with the new keys so a later rollback deletes
    /// the right rows. A body pruned by a release before audit DAG-6 left its
    /// rows but no record: those rows are attributed to their block through
    /// the transaction index (the row's txid), moved to its position, and a
    /// record naming them is written (its `had_shielded` from the shielded
    /// undo record, the rule `ShieldedPool::stage_plan` applies to a missing
    /// record), so neither the history nor a later rollback loses them. A
    /// row of such a block that cannot be attributed is counted as lost.
    /// Idempotent on a data dir already in the position layout.
    ///
    /// Audit B1-T11: the per-address history counters (`agg/hist/`, the
    /// `total` of `getaddresshistory` and `listtransactions`) must equal the
    /// rows, and the rows are rewritten outside the connect path that keeps
    /// them. So the same batch marks the aggregates incomplete (counters are
    /// then neither read nor updated; a crash before the end leaves the
    /// version marker absent and start-up rebuilds them), and once it has
    /// committed they are rebuilt from the new rows, if they were complete
    /// before (otherwise start-up's `ensure_aggregates` builds them).
    pub fn rebuild_chain_indexes(&self, chain: &[(BlockHash, u64, u64)]) -> Result<ChainIndexRebuild, StorageError> {
        let cf_ai = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        let cf_undo = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        let counters_were_ready = self.aggregates_ready();
        self.stage_aggregates_incomplete(&mut batch)?;
        // Chain blocks whose body was pruned without a record (a release
        // before audit DAG-6): their rows are the only copy of their history.
        let mut unrecorded: std::collections::HashMap<BlockHash, u64> = std::collections::HashMap::new();
        for (hash, position, _) in chain {
            if self.get_block(hash)?.is_none() && self.get_pruned_body_record(hash)?.is_none() {
                unrecorded.insert(*hash, *position);
            }
        }
        // (block, new key, value) of their rows, re-keyed below.
        let mut rekeyed: Vec<(BlockHash, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut lost = 0usize;
        for name in [CF_HEIGHT, CF_TIMESTAMPS, CF_ADDR_TX_HISTORY] {
            let cf = self.db.cf_handle(name).ok_or(StorageError::CfNotFound(name.into()))?;
            for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
                batch.delete_cf(&cf, &k);
                if name != CF_ADDR_TX_HISTORY || unrecorded.is_empty() {
                    continue;
                }
                let block = match indexer::parse_value(&v) {
                    Some((txid, _, _)) => self.get_tx_location(&txid)?.map(|(b, _)| b),
                    None => None,
                };
                match block {
                    Some(b) => {
                        if let Some(position) = unrecorded.get(&b) {
                            rekeyed.push((b, indexer::with_position(&k, *position), v.to_vec()));
                        }
                    }
                    // Not attributable to any block: it may have belonged to
                    // one of the record-less pruned blocks.
                    None => lost += 1,
                }
            }
        }
        let (mut written, mut unresolved) = (0usize, 0usize);
        let mut record_keys: std::collections::HashMap<BlockHash, Vec<Vec<u8>>> = std::collections::HashMap::new();
        for (block, key, value) in rekeyed {
            batch.put_cf(&cf_ai, &key, &value);
            written += 1;
            record_keys.entry(block).or_default().push(key);
        }
        for hash in unrecorded.keys() {
            let Some(undo) = self.get_undo_data(hash)? else { continue };
            let rec = PrunedBodyRecord {
                height: undo.block_height,
                had_shielded: crate::coherence::persist::read_undo(self, hash)
                    .map_err(StorageError::ReadFailed)?
                    .is_some(),
                addr_history_keys: record_keys.remove(hash).unwrap_or_default(),
            };
            batch.put_cf(&cf_undo, pruned_body_key(hash), encode(&rec)?);
        }
        for (hash, position, timestamp) in chain {
            match self.get_block(hash)? {
                Some(body) => {
                    let spent: std::collections::HashMap<([u8; 32], u32), TxOutput> = self
                        .get_undo_data(hash)?
                        .map(|u| u.spent_utxos.into_iter().map(|e| ((e.prev_txid, e.prev_index), e.output)).collect())
                        .unwrap_or_default();
                    // An input its undo record does not hold (a block
                    // without one) has no spend row: a rollback could not
                    // delete it either.
                    unresolved += body.transactions.iter()
                        .filter(|tx| !tx.is_coinbase())
                        .flat_map(|tx| tx.inputs.iter())
                        .filter(|i| !spent.contains_key(&(i.prev_txid, i.prev_index)))
                        .count();
                    written += indexer::addr_history_keys(&body, *position, &spent).len();
                    // The aggregates are incomplete (above): no counter delta.
                    self.stage_chain_index(&mut batch, &body, *position, &spent, &mut Default::default())?;
                }
                None => {
                    self.stage_chain_position(&mut batch, *position, hash, *timestamp)?;
                    if let Some(mut rec) = self.get_pruned_body_record(hash)? {
                        let mut keys = Vec::with_capacity(rec.addr_history_keys.len());
                        for old in &rec.addr_history_keys {
                            let value = self.db.get_cf(&cf_ai, old).map_err(|e| StorageError::ReadFailed(e.to_string()))?;
                            let owned = value.as_deref()
                                .and_then(indexer::parse_value)
                                .map(|(txid, _, _)| self.get_tx_location(&txid).ok().flatten().map(|(b, _)| b) == Some(*hash))
                                .unwrap_or(false);
                            let new = indexer::with_position(old, *position);
                            match (owned, value) {
                                (true, Some(v)) => {
                                    batch.put_cf(&cf_ai, &new, &v);
                                    written += 1;
                                }
                                _ => lost += 1,
                            }
                            keys.push(new);
                        }
                        rec.addr_history_keys = keys;
                        batch.put_cf(&cf_undo, pruned_body_key(hash), encode(&rec)?);
                    }
                }
            }
        }
        let cf_meta = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        batch.put_cf(&cf_meta, CHAIN_INDEX_VERSION_META.as_bytes(), CHAIN_INDEX_VERSION.to_le_bytes());
        self.write_batch(batch)?;
        if counters_were_ready {
            // B1-T11: the counters recounted from the rows just written (with
            // every other aggregate, which this rebuild did not change).
            self.rebuild_aggregates(&std::sync::atomic::AtomicBool::new(false))?;
        }
        Ok(ChainIndexRebuild { blocks: chain.len(), rows: written, lost, unresolved })
    }

    /// The layout version of the selected-chain indexes: 1 (header height,
    /// releases before audit DAG-8) when the key is absent.
    pub fn chain_index_version(&self) -> Result<u32, StorageError> {
        Ok(self.get_meta(CHAIN_INDEX_VERSION_META)?
            .and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok().map(u32::from_le_bytes))
            .unwrap_or(1))
    }

    // ── Shielded-pool state (audit COH-2; key layout in coherence::persist) ──

    /// Stage a CF_SHIELDED put.
    pub fn stage_shielded_put(&self, batch: &mut rocksdb::WriteBatch, key: &[u8], value: &[u8])
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        batch.put_cf(&cf, key, value);
        Ok(())
    }

    /// Stage a CF_SHIELDED delete.
    pub fn stage_shielded_delete(&self, batch: &mut rocksdb::WriteBatch, key: &[u8])
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        batch.delete_cf(&cf, key);
        Ok(())
    }

    /// Read one CF_SHIELDED value.
    pub fn get_shielded(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        self.db.get_cf(&cf, key).map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    /// Every CF_SHIELDED (key, value) whose key starts with `prefix`, in key
    /// order.
    pub fn scan_shielded_prefix(&self, prefix: &[u8]) -> Result<KeyValueRows, StorageError> {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::From(prefix, rocksdb::Direction::Forward)) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    }

    // ── Chain-disqualified blocks (audit DAG-1) ─────────────────────────

    const INVALID_PREFIX: &'static [u8] = b"invalid_block/";

    fn invalid_key(hash: &BlockHash) -> Vec<u8> {
        let mut k = Self::INVALID_PREFIX.to_vec();
        k.extend_from_slice(hash);
        k
    }

    /// Stage a persistent "chain-disqualified" mark for `hash` with a short
    /// reason (diagnostics only — the mark itself is what is consensus-relevant
    /// for this node: the block is never selected or applied again).
    pub fn stage_invalid_block(&self, batch: &mut rocksdb::WriteBatch, hash: &BlockHash, reason: &str)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut r = reason.as_bytes().to_vec();
        r.truncate(256);
        batch.put_cf(&cf, Self::invalid_key(hash), r);
        Ok(())
    }

    /// Every persisted chain-disqualified block hash.
    pub fn load_invalid_blocks(&self) -> Result<Vec<BlockHash>, StorageError> {
        Ok(self.load_invalid_blocks_with_reasons()?.into_iter().map(|(h, _)| h).collect())
    }

    /// Every persisted chain-disqualified block hash with its recorded reason.
    pub fn load_invalid_blocks_with_reasons(&self) -> Result<Vec<(BlockHash, String)>, StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, IteratorMode::From(Self::INVALID_PREFIX, rocksdb::Direction::Forward));
        for item in iter {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(Self::INVALID_PREFIX) {
                break;
            }
            if k.len() == Self::INVALID_PREFIX.len() + 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&k[Self::INVALID_PREFIX.len()..]);
                out.push((h, String::from_utf8_lossy(&v).into_owned()));
            }
        }
        Ok(out)
    }

    /// Stage removal of the persisted chain-disqualified mark of `hash`
    /// (operator `reconsiderblock`, chain-state rebuild).
    pub fn stage_clear_invalid_block(&self, batch: &mut rocksdb::WriteBatch, hash: &BlockHash)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        batch.delete_cf(&cf, Self::invalid_key(hash));
        Ok(())
    }

    /// The recorded reason a block was disqualified, if it was.
    pub fn invalid_block_reason(&self, hash: &BlockHash) -> Result<Option<String>, StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        Ok(self.db.get_cf(&cf, Self::invalid_key(hash))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            .map(|v| String::from_utf8_lossy(&v).into_owned()))
    }

    /// Persist a full reachability snapshot + its version tag + root in one
    /// batch. Used after a boot-time rebuild to write the freshly-materialized
    /// index. Clears any stale records first so the CF exactly mirrors memory.
    pub fn store_reachability_snapshot(
        &self,
        records: &[(BlockHash, Vec<u8>)],
        root: Option<BlockHash>,
    ) -> Result<(), StorageError> {
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        let cf_meta = self.db.cf_handle(CF_META)
            .ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        // Wipe existing records (rebuild replaces the whole index).
        for item in self.db.iterator_cf(&cf_reach, IteratorMode::Start) {
            if let Ok((k, _)) = item { batch.delete_cf(&cf_reach, &k); }
        }
        for (h, rec) in records {
            batch.put_cf(&cf_reach, h, rec);
        }
        batch.put_cf(&cf_meta, b"reachability/meta/version",
                     &Self::REACHABILITY_SCHEMA_VERSION.to_le_bytes());
        match root {
            Some(r) => batch.put_cf(&cf_meta, b"reachability/meta/root", &r),
            None    => batch.delete_cf(&cf_meta, b"reachability/meta/root"),
        }
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load every persisted `(block_hash, record_bytes)` from CF_REACHABILITY.
    pub fn load_all_reachability(&self) -> Result<Vec<(BlockHash, Vec<u8>)>, StorageError> {
        let cf = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&k);
                    out.push((h, v.to_vec()));
                }
            }
        }
        Ok(out)
    }

    /// Read the persisted reachability schema version, if present.
    pub fn get_reachability_version(&self) -> Result<Option<u32>, StorageError> {
        Ok(self.get_meta("reachability/meta/version")?
            .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes)))
    }

    /// Read the persisted reachability root (genesis) hash, if present.
    pub fn get_reachability_root(&self) -> Result<Option<BlockHash>, StorageError> {
        Ok(self.get_meta("reachability/meta/root")?
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()))
    }

    // ── Coinbase maturity tracking (FIX VULN-03) ────────────────────────

    /// Record that a txid is a coinbase transaction created at the given height.
    pub fn put_coinbase_info(&self, txid: &[u8; 32], height: u64) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        self.db.put_cf(&cf, txid, &height.to_le_bytes())
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Get the height at which a coinbase transaction was created.
    /// Returns None if the txid is not a coinbase. A row that is not exactly
    /// 8 bytes is corrupted, an error: reading it as "not a coinbase" skipped
    /// the coinbase-maturity check (re-audit B1-T12).
    pub fn get_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        match self.db.get_cf(&cf, txid).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => <[u8; 8]>::try_from(d.as_slice()).map(|b| Some(u64::from_le_bytes(b))).map_err(|_| {
                StorageError::DeserializeFailed(format!(
                    "coinbase-height row of {} has {} bytes (expected 8)", hex::encode(&txid[..8]), d.len()))
            }),
            None => Ok(None),
        }
    }

    /// Sprint U.2 — Remove a coinbase-info record. Used by rollback_block to
    /// unmark a coinbase whose creating block was reverted out of the chain.
    /// Idempotent: deleting a missing record is not an error.
    pub fn delete_coinbase_info(&self, txid: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        self.db.delete_cf(&cf, txid).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    // ── Transaction index (O(1) tx lookup) ────────────────────────────

    /// Index a transaction: txid → (block_hash, block_height)
    pub fn put_tx_index(&self, txid: &[u8; 32], block_hash: &[u8; 32], height: u64) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        let mut val = Vec::with_capacity(40);
        val.extend_from_slice(block_hash);
        val.extend_from_slice(&height.to_le_bytes());
        self.db.put_cf(&cf, txid, &val).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Stage a CF_TX_INDEX row (same layout as [`put_tx_index`](Self::put_tx_index)).
    pub fn stage_tx_index(&self, batch: &mut rocksdb::WriteBatch, txid: &[u8; 32], block_hash: &[u8; 32], height: u64)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        let mut val = Vec::with_capacity(40);
        val.extend_from_slice(block_hash);
        val.extend_from_slice(&height.to_le_bytes());
        batch.put_cf(&cf, txid, &val);
        Ok(())
    }

    /// Stage a UTXO row and its address-index row (same layout as
    /// [`put_utxo`](Self::put_utxo)).
    pub fn stage_utxo(&self, batch: &mut rocksdb::WriteBatch, txid: &[u8], index: u32, output: &TxOutput)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        batch.put_cf(&cf, utxo_key(txid, index), encode(output)?);
        if output.script_pubkey.len() >= 20 {
            let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
            batch.put_cf(&cf_ai, addr_utxo_key(&output.script_pubkey, txid, index), [0u8; 0]);
        }
        Ok(())
    }

    /// Lookup transaction location: returns (block_hash, block_height). A
    /// row that is not 40 bytes is an error, never "not confirmed" (re-audit
    /// B1-T12: coinbase maturity and relative timelocks read this row while
    /// a block is connected, and an absent confirmation is not a verdict
    /// either way).
    pub fn get_tx_location(&self, txid: &[u8; 32]) -> Result<Option<([u8; 32], u64)>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        match self.db.get_cf(&cf, txid).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 40 => {
                let mut bh = [0u8; 32];
                bh.copy_from_slice(&d[..32]);
                let height = u64::from_le_bytes(d[32..40].try_into().unwrap());
                Ok(Some((bh, height)))
            }
            Some(d) => Err(StorageError::DeserializeFailed(format!(
                "tx-index row of {} has {} bytes (expected 40)", hex::encode(&txid[..8]), d.len()))),
            None => Ok(None),
        }
    }

    /// Sprint U.2 — Remove a tx_index entry. Used by rollback_block to unpoint
    /// a txid away from a block that's being reverted. Idempotent.
    pub fn delete_tx_index(&self, txid: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        self.db.delete_cf(&cf, txid).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.put_cf(&cf, key.as_bytes(), value).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.get_cf(&cf, key.as_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    /// Delete one CF_META key (absent: nothing to do).
    pub fn delete_meta(&self, key: &str) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.delete_cf(&cf, key.as_bytes()).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Every CF_META (key, value) whose key starts with `prefix`, in key
    /// order (the PoWit finality index, `powit::load_finality_index`).
    pub fn scan_meta_prefix(&self, prefix: &str) -> Result<KeyValueRows, StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::From(prefix.as_bytes(), rocksdb::Direction::Forward)) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    }

    /// CF_META key of the network a data dir belongs to (u32 LE chain id).
    pub const CHAIN_ID_META: &'static str = "chain_id";

    /// Audit POW-9: mainnet and testnet share the genesis block, so the
    /// genesis check at start-up cannot tell a data dir of the other network
    /// apart (opening a mainnet data dir on testnet would recheck its blocks
    /// under testnet's activation schedule and disqualify them). The data dir
    /// records the chain id it was created for: `Ok(true)` when the marker
    /// was absent and has been written, `Ok(false)` when it matches, `Err`
    /// when it names another network.
    ///
    /// A data dir without the marker (a new one, or one written before the
    /// marker existed: every data dir of an earlier release) is not marked
    /// for whatever network opens it first: when it holds chain blocks, the
    /// network they belong to is read from the blocks themselves
    /// ([`Storage::stored_chain_network`]) and a node of the other network is
    /// refused, so a mainnet node restarted with `--testnet` by mistake
    /// neither marks the dir as testnet nor disqualifies its blocks.
    pub fn check_chain_marker(&self, chain_id: u32) -> Result<bool, String> {
        match self.get_meta(Self::CHAIN_ID_META).map_err(|e| e.to_string())? {
            None => {
                if let Some((found, block, height)) = self.stored_chain_network().map_err(|e| e.to_string())? {
                    if found.to_u32() != chain_id {
                        return Err(format!(
                            "this data dir has no chain id marker yet, but its block {} (height {}) follows the \
                             {} rules below the mainnet hardening activation, so it belongs to chain id {:#010x}{}; \
                             the node runs chain id {:#010x}",
                            hex::encode(&block[..8]), height,
                            match found {
                                crate::core::ChainId::Mainnet => "pre-activation (legacy)",
                                _ => "hardened",
                            },
                            found.to_u32(),
                            match found {
                                crate::core::ChainId::Mainnet => " (or to a testnet started before testnet's \
                                    hardening, whose blocks the testnet rules reject anyway: start testnet with \
                                    a new --data-dir)",
                                _ => "",
                            },
                            chain_id,
                        ));
                    }
                }
                self.put_meta(Self::CHAIN_ID_META, &chain_id.to_le_bytes()).map_err(|e| e.to_string())?;
                Ok(true)
            }
            Some(v) if v.as_slice() == chain_id.to_le_bytes() => Ok(false),
            Some(v) => Err(format!(
                "this data dir belongs to chain id {} but the node runs chain id {:#010x}",
                <[u8; 4]>::try_from(v.as_slice())
                    .map(|b| format!("{:#010x}", u32::from_le_bytes(b)))
                    .unwrap_or_else(|_| format!("<{} bytes>", v.len())),
                chain_id,
            )),
        }
    }

    /// The network the stored chain of an unmarked data dir belongs to
    /// (POW-9 review), with the block that tells: the first block with a
    /// stored body among the [`CHAIN_SHAPE_SCAN`] highest selected-chain
    /// index rows whose header height is in `1..17,500` (the mainnet
    /// hardening activation). Below it a mainnet block follows the
    /// pre-activation rules (legacy Merkle root, free-form coinbase) and a
    /// testnet block the hardening rules (testnet activates them at 0),
    /// which exclude each other (docs/CONSENSUS.md, "Networks"). The
    /// hardened body rules (`block_rules::check_hardened_body`: the coinbase
    /// commitment, which no mainnet coinbase carries below the activation)
    /// tell them apart; the Merkle root does not: from a network's PoWit
    /// height the body root is the v2 commitment, and which heights that
    /// covers is the RUNNING node's PoWit height (mainnet 10,000, testnet
    /// off or `--powit-height`), not the stored chain's, so a testnet block
    /// above 10,000 checked by a mainnet process failed it and read as
    /// mainnet.
    /// `None`: no such block (a dir holding only the genesis, or whose
    /// recent bodies are all at or above the activation or pruned); the
    /// running network is then adopted. Pruning keeps the bodies of the
    /// most recent 10,000 positions, so the highest rows have bodies.
    pub fn stored_chain_network(&self) -> Result<Option<(crate::core::ChainId, BlockHash, u64)>, StorageError> {
        use crate::core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        for item in self.db.iterator_cf(&cf, IteratorMode::End).take(CHAIN_SHAPE_SCAN) {
            let (_, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            let Ok(hash) = <BlockHash>::try_from(v.as_ref()) else { continue };
            let Ok(Some(block)) = self.get_block(&hash) else { continue };
            if block.height == 0 || block.height >= MAINNET_HARDENING_ACTIVATION_HEIGHT {
                continue;
            }
            let chain = match crate::core::block_rules::check_hardened_body(&block) {
                Ok(()) => crate::core::ChainId::Testnet,
                Err(_) => crate::core::ChainId::Mainnet,
            };
            return Ok(Some((chain, hash, block.height)));
        }
        Ok(None)
    }

    // ── Sprint U.1: Undo data for reorg rollback ─────────────────────────
    //
    // Each connected block writes one UndoData record keyed by block hash,
    // deleted only when the block is rolled back. Undo records are NEVER
    // pruned: there is no reorg-depth limit (audit DAG-6), so a reorg of any
    // depth must be able to disconnect any connected block.

    /// Persist the undo record for a block. Should be called once per block,
    /// immediately after all UTXO/index mutations for that block complete.
    pub fn put_undo_data(&self, block_hash: &[u8; 32], data: &crate::core::UndoData)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        // `UndoData::to_bytes`: the legacy encoding, plus the overwritten-rows
        // extension only when the block replaced something (audit VAL-2).
        let bytes = data.to_bytes().map_err(StorageError::SerializeFailed)?;
        self.db.put_cf(&cf, block_hash, &bytes)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Fetch the undo record for a block. Returns Ok(None) if the block was
    /// accepted before U.1 landed, or if its undo record has been pruned.
    pub fn get_undo_data(&self, block_hash: &[u8; 32])
        -> Result<Option<crate::core::UndoData>, StorageError>
    {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        match self.db.get_cf(&cf, block_hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            // Records written before the VAL-2 extension decode unchanged.
            Some(d) => Ok(Some(crate::core::UndoData::from_bytes(&d).map_err(StorageError::DeserializeFailed)?)),
            None    => Ok(None),
        }
    }

    /// True iff `block_hash` has an undo record (its effects are applied),
    /// without decoding it.
    pub fn has_undo_data(&self, block_hash: &[u8; 32]) -> Result<bool, StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        Ok(self.db.get_pinned_cf(&cf, block_hash)
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            .is_some())
    }

    /// Every block hash that has an undo record (i.e. whose UTXO effects are
    /// currently applied). Used by start-up reconciliation (DAG-11) to find
    /// blocks a pre-fix, non-atomic commit applied but never recorded in
    /// CF_DAG. Keys only; O(applied blocks).
    pub fn undo_block_hashes(&self) -> Result<Vec<[u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if k.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&k);
                out.push(h);
            }
        }
        Ok(out)
    }

    /// Remove an undo record (rollback). Never call it on a block that stays
    /// connected: with no reorg-depth limit (audit DAG-6) every connected
    /// block must remain disconnectable.
    pub fn delete_undo_data(&self, block_hash: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        self.db.delete_cf(&cf, block_hash).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Sprint U.2 — Reverse every mutation recorded in the block's UndoData.
    ///
    /// This is the storage-level primitive the reorg logic (U.3) will call for
    /// each block of the losing chain, in tip-toward-LCA order. It is purely
    /// about rolling back **state** (UTXO set, tx index, coinbase index,
    /// address indices, undo record itself) — it deliberately does NOT touch:
    ///
    ///   - CF_BLOCKS, CF_HEIGHT, CF_TIMESTAMPS: the block still exists as a
    ///     known DAG node; U.3 repoints selected-chain membership, not block
    ///     knowledge.
    ///   - CF_DAG: GhostDAG metadata for the block stays valid.
    ///   - Mempool: caller's job to re-inject invalidated txs if desired.
    ///
    /// # Order of operations (reversed from accept_block, with rationale)
    ///
    ///   1. Un-index addr_tx_history — needs the block body + spent lookup
    ///      from UndoData, both still intact at this point.
    ///   2. Restore spent UTXOs via put_utxo — also repopulates CF_ADDR_UTXO.
    ///   3. Delete created UTXOs via delete_utxo — also cleans CF_ADDR_UTXO.
    ///   4. Delete coinbase_info entries.
    ///   5. Delete tx_index entries.
    ///   6. Delete the UndoData record itself — final step, marks rollback
    ///      as complete and prevents accidental re-rollback.
    ///
    /// # Errors
    ///
    /// Returns Err if the undo record is missing or if the block body is
    /// missing. These are abnormal conditions: an accepted-post-U.1 block
    /// always has an undo record. (The batched reorg path,
    /// `reorg::connect_plan`, also handles a pruned body.)
    ///
    /// Individual inner ops use `let _ =` for idempotent sub-operations: if
    /// a delete target was never present (e.g. intra-block chains that
    /// weren't indexed) the rollback still makes progress rather than
    /// aborting halfway through.
    ///
    /// # Returns
    ///
    /// The `UndoData` that was applied, so callers can, e.g., re-inject
    /// invalidated transactions into the mempool or emit reorg events.
    pub fn rollback_block(&self, block_hash: &[u8; 32])
        -> Result<crate::core::UndoData, StorageError>
    {
        // 1. Load the undo record. Missing record = nothing to roll back;
        //    treat as error so caller can distinguish "already rolled back"
        //    (or "pre-U.1 block we can't roll back") from success.
        let hash_prefix = format!(
            "{:02x}{:02x}{:02x}{:02x}..",
            block_hash[0], block_hash[1], block_hash[2], block_hash[3]
        );
        let undo = self.get_undo_data(block_hash)?
            .ok_or_else(|| StorageError::ReadFailed(format!(
                "rollback_block: no undo data for block {}",
                hash_prefix
            )))?;

        // 2. Load the block body — needed for addr_tx_history unindex, which
        //    walks every transaction. Also serves as a sanity check that the
        //    block we're rolling back actually exists in storage.
        let block = self.get_block(block_hash)?
            .ok_or_else(|| StorageError::ReadFailed(format!(
                "rollback_block: block body missing for {}",
                hash_prefix
            )))?;

        // 3. Build a lookup from (prev_txid, prev_index) → spent TxOutput so
        //    unindex_tx_addresses can resolve input addresses without going
        //    through get_utxo_including_spent (which becomes stale as we
        //    mutate the UTXO set below).
        let mut spent_lookup: std::collections::HashMap<([u8; 32], u32), TxOutput> =
            std::collections::HashMap::with_capacity(undo.spent_utxos.len());
        for entry in &undo.spent_utxos {
            spent_lookup.insert((entry.prev_txid, entry.prev_index), entry.output.clone());
        }

        // 4. Un-index addr_tx_history (must run BEFORE UTXO mutations —
        //    see doc comment on ordering above).
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            // Best-effort: log on failure but keep going. A partial unindex
            // is still better than aborting mid-rollback.
            if let Err(e) = self.unindex_tx_addresses(
                tx, block.height, tx_idx as u32, &spent_lookup
            ) {
                log::warn!(
                    "rollback_block h={}: addr_tx_history unindex failed for tx {}: {}",
                    block.height, tx_idx, e
                );
            }
        }

        // 5. Restore spent UTXOs. put_utxo also rewrites the CF_ADDR_UTXO
        //    entry, so we don't have to handle that column family manually.
        for entry in &undo.spent_utxos {
            let _ = self.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output);
        }

        // 6. Delete created UTXOs. delete_utxo also removes the CF_ADDR_UTXO
        //    entry if present.
        for (txid, idx) in &undo.created_utxo_keys {
            let _ = self.delete_utxo(txid, *idx);
        }
        //    VAL-2: restore the coins those outputs overwrote (same outpoint),
        //    so the UTXO set equals that of a node that never applied the block.
        for entry in &undo.overwritten.utxos {
            let _ = self.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output);
        }

        // 7. Delete coinbase-info entries for any coinbase txs this block
        //    introduced. A reverted coinbase must not be treated as mature
        //    by downstream validation.
        for txid in &undo.coinbase_txids {
            let _ = self.delete_coinbase_info(txid);
        }
        for (txid, height) in &undo.overwritten.coinbase_heights {
            let _ = self.put_coinbase_info(txid, *height);
        }

        // 8. Delete tx_index entries. After rollback the txid is no longer
        //    locatable at this block — either the tx will land in a replacement
        //    block (and get re-indexed there by accept_block) or it reverts
        //    to the mempool.
        for txid in &undo.tx_index_keys {
            let _ = self.delete_tx_index(txid);
        }
        for (txid, block, height) in &undo.overwritten.tx_index {
            let _ = self.put_tx_index(txid, block, *height);
        }

        // 9. Finally, delete the undo record itself. Must be last: if any
        //    earlier step erred after we deleted this first, the caller
        //    would have no way to retry or to introspect the record.
        self.delete_undo_data(block_hash)?;

        // NET-12: the block left the connected chain (holder aggregates
        // already followed the put/delete calls above).
        self.note_block_disconnected(block_hash, undo.tx_index_keys.len() as u64)?;

        Ok(undo)
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    /// Prune the stored block bodies indexed below `below_height`, a DAG
    /// height (for an applied block its selected-chain position, audit
    /// DAG-8; see B1-T17 below).
    /// Keeps: position→hash mapping, DAG data, TX index, UTXO set, undo records.
    /// Removes: full block data from CF_BLOCKS (saves ~90% of storage).
    /// Returns number of blocks pruned.
    ///
    /// Audit B1-T17: EVERY stored body indexed below `below_height` is pruned
    /// — selected-chain, merged, fork-loser and junk bodies alike (Bitcoin
    /// Core prunes whole block files, stale blocks included) — found through
    /// the body height index ([`BODY_INDEX_PREFIX`], O(bodies pruned); the
    /// previous version looked up the selected-chain height index for every
    /// height from 0, O(height) per call, and never found a non-selected
    /// body). A database written before the index existed is backfilled first
    /// ([`Self::ensure_body_index`]).
    ///
    /// Audit DAG-6: a reorg of ANY depth must be able to disconnect a pruned
    /// block (there is no reorg-depth limit). The UTXO effects come back from
    /// the undo record, which is never pruned; what the rollback still needed
    /// from the body — the address-history keys to un-index and whether the
    /// block carried shielded transactions — is recorded here, in the same
    /// batch as the body deletion, as a [`PrunedBodyRecord`] — only for a
    /// block that HAS an undo record, of the UTXO set or of the shielded pool
    /// (it is applied; both are written with the block's connect), and for
    /// the genesis (applied by seeding, without an undo record; its record
    /// keeps its address-history keys for `rebuild_chain_indexes`): a block
    /// that is not applied is never rolled back, and if its chain becomes the
    /// best its body is fetched again (`accept::awaits_body`).
    pub fn prune_blocks_below(&self, below_height: u64) -> Result<usize, StorageError> {
        self.ensure_body_index()?;
        let cf_blocks = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_undo = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        let cf_meta = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let end = body_index_key(below_height, &[0u8; 32]);
        let mut rows: Vec<(Vec<u8>, u64, BlockHash)> = Vec::new();
        let iter = self.db.iterator_cf(&cf_meta,
            IteratorMode::From(BODY_INDEX_PREFIX, rocksdb::Direction::Forward));
        for item in iter {
            let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(BODY_INDEX_PREFIX) || k.as_ref() >= end.as_slice() {
                break;
            }
            let p = BODY_INDEX_PREFIX.len();
            let height = k.get(p..p + 8).and_then(|b| <[u8; 8]>::try_from(b).ok());
            let hash = k.get(p + 8..).and_then(|b| <BlockHash>::try_from(b).ok());
            if let (Some(h), Some(hash)) = (height, hash) {
                rows.push((k.to_vec(), u64::from_be_bytes(h), hash));
            }
        }

        let mut pruned = 0usize;
        for (key, row_height, hash) in rows {
            let mut batch = rocksdb::WriteBatch::default();
            batch.delete_cf(&cf_meta, &key);
            match self.body_index_height(&hash)? {
                // A stale row: the body was re-stored (or deleted and
                // re-stored) under another height since; that row decides.
                Some(current) if current != row_height => {
                    self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
                    continue;
                }
                Some(_) => batch.delete_cf(&cf_meta, body_index_height_key(&hash)),
                None => {}
            }
            let raw = self.db.get_cf(&cf_blocks, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if let Some(raw) = raw {
                batch.delete_cf(&cf_blocks, hash);
                let decoded = Block::from_wire_bytes(&raw);
                // Re-audit B2-T1 follow-up (R1a) with B1-T17 (R4): EVERY body
                // pruned here — merged, fork-loser and junk ones too — leaves
                // the hardened-body marker when it passed the hardening block
                // rules (see [`HARDENED_BODY_PREFIX`]). The start-up recheck
                // considers every DAG block at or above the activation, and a
                // merged block disqualified there for a missing body would
                // take every block that merged it along.
                if let Ok(body) = &decoded {
                    if matches!(crate::accept::classify_stored_block(body, 0),
                                crate::accept::StoredBlockCheck::Valid) {
                        batch.put_cf(&cf_meta, hardened_body_key(&hash), [0u8; 0]);
                    }
                }
                // The genesis is on every selected chain (its ledger is
                // seeded, so it has no undo record): its record keeps its
                // address-history keys, as every other chain block's does
                // (`rebuild_chain_indexes` reads a bodiless chain block
                // without a record as one pruned by a release before
                // DAG-6, audit DAG-8).
                let genesis = matches!(&decoded, Ok(b) if b.header.parents.is_empty());
                let applied = genesis
                    || self.has_undo_data(&hash)?
                    || crate::coherence::persist::has_undo(self, &hash).map_err(StorageError::ReadFailed)?;
                if applied {
                    match decoded {
                        Ok(body) => {
                            let spent: std::collections::HashMap<([u8; 32], u32), TxOutput> = self
                                .get_undo_data(&hash)?
                                .map(|u| u.spent_utxos.into_iter()
                                    .map(|e| ((e.prev_txid, e.prev_index), e.output))
                                    .collect())
                                .unwrap_or_default();
                            // The rows its connect wrote, at its chain
                            // position (audit DAG-8): an applied block is on
                            // the selected chain, at its DAG height (a store
                            // without its DAG record: the header height, as
                            // `reorg::connect_plan` falls back to).
                            let position = self.chain_position(&hash)?.unwrap_or(body.height);
                            let rec = PrunedBodyRecord {
                                height: body.height,
                                had_shielded: !body.shielded_transactions.is_empty(),
                                addr_history_keys: indexer::addr_history_keys(&body, position, &spent),
                            };
                            batch.put_cf(&cf_undo, pruned_body_key(&hash), encode(&rec)?);
                        }
                        Err(e) => log::warn!(
                            "prune: body of {} does not decode ({}); pruned without a rollback record",
                            hex::encode(&hash[..8]), e
                        ),
                    }
                }
                pruned += 1;
            }
            // (A row without a body — deleted or pruned under another
            // height — only loses its row.)
            self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
            self.forget_body_verdict(&hash);
        }

        if pruned > 0 && below_height > self.pruned_height() {
            self.put_meta("pruned_height", &below_height.to_le_bytes())?;
        }
        Ok(pruned)
    }

    /// True iff `hash`'s body was pruned after passing every context-free
    /// hardening block rule (see [`HARDENED_BODY_PREFIX`]).
    pub fn has_hardened_body_marker(&self, hash: &BlockHash) -> Result<bool, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.get_cf(&cf, hardened_body_key(hash))
            .map(|v| v.is_some())
            .map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    /// The rollback record written when `hash`'s body was pruned, if any.
    pub fn get_pruned_body_record(&self, hash: &BlockHash) -> Result<Option<PrunedBodyRecord>, StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        match self.db.get_cf(&cf, pruned_body_key(hash)).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None => Ok(None),
        }
    }

    /// Stage removal of `hash`'s pruned-body record (the block is being
    /// disconnected; a later re-connect needs the body again anyway).
    pub fn stage_delete_pruned_body_record(&self, batch: &mut rocksdb::WriteBatch, hash: &BlockHash)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        batch.delete_cf(&cf, pruned_body_key(hash));
        Ok(())
    }

    // ── Chain-state integrity (audit DAG-6 / DAG-11) ───────────────────

    /// SHA3-256 commitment to the whole UTXO set: every CF_UTXO row in key
    /// order, each fed as `len(key) ‖ key ‖ len(value) ‖ value` (u32 LE
    /// lengths). A pure function of the set's contents, so two nodes (or one
    /// node before and after a rebuild) hold the same UTXO set iff the
    /// digests are equal. O(UTXO set).
    pub fn utxo_set_digest(&self) -> Result<[u8; 32], StorageError> {
        use sha3::{Digest, Sha3_256};
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let mut h = Sha3_256::new();
        h.update(b"gnb/utxo-set/v1");
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            h.update((k.len() as u32).to_le_bytes());
            h.update(&k);
            h.update((v.len() as u32).to_le_bytes());
            h.update(&v);
        }
        Ok(h.finalize().into())
    }

    /// Every `(txid, block_hash)` pair of CF_TX_INDEX (start-up chain-state
    /// check, DAG-11). O(indexed transactions).
    pub fn tx_index_entries(&self) -> Result<Vec<TxIndexEntry>, StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if k.len() == 32 && v.len() >= 32 {
                let mut t = [0u8; 32];
                t.copy_from_slice(&k);
                let mut b = [0u8; 32];
                b.copy_from_slice(&v[..32]);
                out.push((t, b));
            }
        }
        Ok(out)
    }

    /// Stage the deletion of every row of the chain-state column families —
    /// UTXO set and its address index, coinbase heights, transaction index,
    /// undo and pruned-body records, the selected-chain height / timestamp
    /// indexes, the address history and the shielded-pool state with its
    /// per-block undo records (audit COH-2) — for a rebuild from blocks
    /// (DAG-11). Block bodies, GhostDAG data and CF_META are untouched (the
    /// NET-12 aggregates in CF_META are marked incomplete and recomputed by
    /// the rebuild itself). Returns the number of rows staged for deletion.
    pub fn stage_clear_chain_state(&self, batch: &mut rocksdb::WriteBatch) -> Result<usize, StorageError> {
        let mut n = 0usize;
        for name in [CF_UTXO, CF_ADDR_UTXO, CF_COINBASE, CF_TX_INDEX, CF_UNDO, CF_HEIGHT,
                     CF_TIMESTAMPS, CF_ADDR_TX_HISTORY, CF_SHIELDED] {
            let cf = self.db.cf_handle(name).ok_or(StorageError::CfNotFound(name.into()))?;
            for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
                batch.delete_cf(&cf, &k);
                n += 1;
            }
        }
        Ok(n)
    }

    /// Get the height below which blocks have been pruned
    pub fn pruned_height(&self) -> u64 {
        self.get_meta("pruned_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0)
    }

    /// Sprint F: get block timestamp by height (used by listtransactions RPC).
    pub fn get_block_timestamp_at_height(&self, height: u64) -> Result<Option<u64>, StorageError> {
        let cf = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 8 => Ok(Some(u64::from_le_bytes(d.try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    /// Sprint F: get tip height (highest block number).
    pub fn get_tip_height(&self) -> Result<u64, StorageError> {
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::End);
        for item in iter {
            let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if k.len() == 8 {
                return Ok(u64::from_be_bytes(k.as_ref().try_into().unwrap()));
            }
        }
        Ok(0)
    }

}

/// `txid ‖ vout`, vout encoded LITTLE-endian. Every consensus read/write of a
/// UTXO goes through this SAME function on both sides (`get_utxo`,
/// `put_utxo`, `delete_utxo`), so the encoding round-trips correctly for
/// consensus purposes. Code that instead parses the RAW key bytes back into
/// a vout number for display/export (`iter_utxos_sorted`,
/// `bloch-snapshot-utxo`) has historically decoded that suffix BIG-endian —
/// a doc-drift bug documented at `iter_utxos_sorted` (Legacy M-3) — do not
/// "fix" this function's endianness without reading that comment first: the
/// published carry-over snapshot's SHAKE-256 root depends on the mismatch
/// staying exactly as it is today.
fn utxo_key(txid: &[u8], index: u32) -> Vec<u8> {
    let mut k = txid.to_vec(); k.extend_from_slice(&index.to_le_bytes()); k
}

/// Address index key: [20B address][32B txid][4B index] = 56 bytes
fn addr_utxo_key(address: &[u8], txid: &[u8], index: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(56);
    k.extend_from_slice(address);
    k.extend_from_slice(txid);
    k.extend_from_slice(&index.to_le_bytes());
    k
}

#[cfg(test)]
thread_local! {
    /// NET-15 tests: called on every instrumented storage read (the
    /// `storage_reads` counter) made by this thread.
    pub(crate) static READ_PROBE: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("open: {0}")]        OpenFailed(String),
    #[error("cf: {0}")]          CfNotFound(String),
    #[error("serialize: {0}")]   SerializeFailed(String),
    #[error("deserialize: {0}")] DeserializeFailed(String),
    #[error("write: {0}")]       WriteFailed(String),
    #[error("read: {0}")]        ReadFailed(String),
}

impl From<rocksdb::Error> for StorageError {
    fn from(e: rocksdb::Error) -> Self { StorageError::ReadFailed(e.to_string()) }
}

// Sprint F — tests for address history indexer and related RPCs.
// (appended from scaffold; // instead of //! because this is not a module root)

#[cfg(test)]
mod sprint_f_tests {
    use super::*;
    use crate::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
    use crate::storage::indexer::{make_key, make_value, parse_key, parse_value, DIR_IN, DIR_OUT, ENTRY_SIZE};
    use tempfile::TempDir;

    fn mk_storage() -> (TempDir, Storage) {
        let tmp = TempDir::new().unwrap();
        let s = Storage::open(tmp.path()).unwrap();
        (tmp, s)
    }

    fn dummy_addr(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
        TxOutput {
            value,
            script_pubkey: vec![addr_byte; 20],
        }
    }

    fn mk_tx_coinbase(addr_byte: u8, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0xffffffff,
                script_sig: b"height:1".to_vec(),
                sequence: 0xffffffff,
            }],
            outputs: vec![mk_output(addr_byte, value)],
            locktime: 0,
        }
    }

    /// Audit POW-9: a data dir records its network; the other network's node
    /// is refused, the same network passes, an unmarked dir is marked once.
    #[test]
    fn chain_marker_refuses_the_other_network() {
        let (_t, s) = mk_storage();
        let main = crate::core::ChainId::Mainnet.to_u32();
        let test = crate::core::ChainId::Testnet.to_u32();
        assert_eq!(s.check_chain_marker(main), Ok(true), "first open marks the dir");
        assert_eq!(s.get_meta(Storage::CHAIN_ID_META).unwrap(), Some(main.to_le_bytes().to_vec()));
        assert_eq!(s.check_chain_marker(main), Ok(false));
        let err = s.check_chain_marker(test).unwrap_err();
        assert!(err.contains("0x474e0001") && err.contains("0x474e0002"), "{err}");
        assert_eq!(s.get_meta(Storage::CHAIN_ID_META).unwrap(), Some(main.to_le_bytes().to_vec()), "unchanged");
        s.put_meta(Storage::CHAIN_ID_META, &[1, 2]).unwrap();
        assert!(s.check_chain_marker(main).unwrap_err().contains("<2 bytes>"));
    }

    /// Policy outputs (33-byte scripts) are found by their full script, and
    /// a key-hash script that shares their first 20 bytes never mixes in.
    #[test]
    fn utxos_for_address_finds_policy_scripts() {
        let (_tmp, s) = mk_storage();
        let mut policy = vec![0x02u8];
        policy.extend_from_slice(&[0x55u8; 32]);
        let key_hash = policy[..20].to_vec();
        s.put_utxo(&[1u8; 32], 0, &TxOutput { value: 7, script_pubkey: policy.clone() }).unwrap();
        s.put_utxo(&[2u8; 32], 1, &TxOutput { value: 9, script_pubkey: key_hash.clone() }).unwrap();
        let p = s.get_utxos_for_address(&policy).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].1, p[0].2.value), (0, 7));
        let k = s.get_utxos_for_address(&key_hash).unwrap();
        assert_eq!(k.len(), 1);
        assert_eq!((k[0].1, k[0].2.value), (1, 9));
    }

    #[test]
    fn key_value_encoding_roundtrip() {
        let addr = dummy_addr(0x42);
        let txid = [0x99u8; 32];

        let k = make_key(&addr, 100, 5, 2);
        let v = make_value(&txid, DIR_OUT, 1_000_000_000);

        assert_eq!(k.len(), 36);
        assert_eq!(v.len(), ENTRY_SIZE);

        let (pa, ph, pti, pii) = parse_key(&k).unwrap();
        assert_eq!(pa, addr);
        assert_eq!(ph, 100);
        assert_eq!(pti, 5);
        assert_eq!(pii, 2);

        let (ptxid, pdir, pamt) = parse_value(&v).unwrap();
        assert_eq!(ptxid, txid);
        assert_eq!(pdir, DIR_OUT);
        assert_eq!(pamt, 1_000_000_000);
    }

    #[test]
    fn key_ordering_is_chronological() {
        let addr = dummy_addr(0x11);
        let k1 = make_key(&addr, 10, 0, 0);
        let k2 = make_key(&addr, 100, 0, 0);
        let k3 = make_key(&addr, 1000, 0, 0);
        assert!(k1 < k2);
        assert!(k2 < k3);
    }

    #[test]
    fn parse_invalid_sizes_returns_none() {
        assert!(parse_key(&[0u8; 10]).is_none());
        assert!(parse_key(&[0u8; 50]).is_none());
        assert!(parse_value(&[0u8; 20]).is_none());
    }

    #[test]
    fn index_coinbase_adds_out_entry() {
        let (_tmp, store) = mk_storage();
        let tx = mk_tx_coinbase(0x42, 33 * 100_000_000);
        store.index_tx_addresses(&tx, 1, 0).unwrap();
        let entries = store.query_address_history(&dummy_addr(0x42), 0, 100, 10, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_incoming());
        assert_eq!(entries[0].amount, 33 * 100_000_000);
        assert_eq!(entries[0].height, 1);
    }

    #[test]
    fn query_respects_height_range() {
        let (_tmp, store) = mk_storage();
        for h in 1..=10 {
            let tx = mk_tx_coinbase(0x55, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let mid = store.query_address_history(&dummy_addr(0x55), 3, 7, 100, 0).unwrap();
        assert_eq!(mid.len(), 5);
        assert_eq!(mid[0].height, 3);
        assert_eq!(mid[4].height, 7);
    }

    #[test]
    fn query_respects_limit_and_offset() {
        let (_tmp, store) = mk_storage();
        for h in 1..=20 {
            let tx = mk_tx_coinbase(0x77, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let page1 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 0).unwrap();
        let page2 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 5).unwrap();
        let page3 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 10).unwrap();

        assert_eq!(page1.len(), 5);
        assert_eq!(page2.len(), 5);
        assert_eq!(page3.len(), 5);

        // Pages should not overlap
        assert_eq!(page1[0].height, 1);
        assert_eq!(page2[0].height, 6);
        assert_eq!(page3[0].height, 11);
    }

    #[test]
    fn count_is_consistent_with_query() {
        let (_tmp, store) = mk_storage();
        for h in 1..=15 {
            let tx = mk_tx_coinbase(0xAA, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let count = store.count_address_history(&dummy_addr(0xAA), 0, 15).unwrap();
        assert_eq!(count, 15);
        let count_range = store.count_address_history(&dummy_addr(0xAA), 5, 10).unwrap();
        assert_eq!(count_range, 6);
    }

    #[test]
    fn balance_at_height_sums_incoming() {
        let (_tmp, store) = mk_storage();
        for h in 1..=5 {
            let tx = mk_tx_coinbase(0xBB, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        // All incoming, balance at tip = 500
        let bal_tip = store.balance_at_height(&dummy_addr(0xBB), 5).unwrap();
        assert_eq!(bal_tip, 500);
        // At height 3, only 3 entries counted = 300
        let bal_3 = store.balance_at_height(&dummy_addr(0xBB), 3).unwrap();
        assert_eq!(bal_3, 300);
    }

    #[test]
    fn different_addresses_isolated() {
        let (_tmp, store) = mk_storage();
        let tx_a = mk_tx_coinbase(0xAA, 100);
        let tx_b = mk_tx_coinbase(0xBB, 200);
        store.index_tx_addresses(&tx_a, 1, 0).unwrap();
        store.index_tx_addresses(&tx_b, 1, 1).unwrap();

        let a = store.query_address_history(&dummy_addr(0xAA), 0, 100, 10, 0).unwrap();
        let b = store.query_address_history(&dummy_addr(0xBB), 0, 100, 10, 0).unwrap();

        assert_eq!(a.len(), 1);
        assert_eq!(a[0].amount, 100);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].amount, 200);
    }

    #[test]
    fn empty_address_returns_empty() {
        let (_tmp, store) = mk_storage();
        let e = store.query_address_history(&dummy_addr(0x00), 0, 1000, 100, 0).unwrap();
        assert!(e.is_empty());
        let c = store.count_address_history(&dummy_addr(0x00), 0, 1000).unwrap();
        assert_eq!(c, 0);
        let b = store.balance_at_height(&dummy_addr(0x00), 1000).unwrap();
        assert_eq!(b, 0);
    }
}


#[cfg(test)]
mod snapshot_row_tests {
    use super::*;
    #[test]
    fn corrupted_rows_refuse_export_and_valid_rows_preserve_both_vout_modes() {
        let mut key = vec![7; 32];
        key.extend_from_slice(&1u32.to_le_bytes());
        let output = TxOutput { value: 42, script_pubkey: vec![3; 20] };
        let bytes = encode(&output).unwrap();
        assert_eq!(decode_snapshot_row(&key, &bytes, false).unwrap().1, 16_777_216);
        assert_eq!(decode_snapshot_row(&key, &bytes, true).unwrap().1, 1);
        assert!(decode_snapshot_row(&key[..35], &bytes, false).is_err());
        let mut long_key = key.clone(); long_key.push(0);
        assert!(decode_snapshot_row(&long_key, &bytes, false).is_err());
        assert!(decode_snapshot_row(&key, &[], false).is_err());
        let mut trailing = bytes; trailing.push(0);
        assert!(decode_snapshot_row(&key, &trailing, false).is_err());
    }
}

#[cfg(test)]
mod shielded_cf_tests {
    use super::*;

    /// Audit COH-2 added the `shielded` column family. A data-dir written
    /// before it still opens read-only (the replay harness inspects old
    /// snapshots), and a read-write open adds the family.
    #[test]
    fn data_dir_without_the_shielded_family_opens_read_only_and_upgrades() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let old: Vec<ColumnFamilyDescriptor> =
                Storage::cf_descriptors().into_iter().filter(|d| d.name() != CF_SHIELDED).collect();
            let db = DB::open_cf_descriptors(&opts, tmp.path(), old).unwrap();
            db.put_cf(&db.cf_handle(CF_META).unwrap(), b"tip_hash", [7u8; 32]).unwrap();
        }
        let ro = Storage::open_read_only(tmp.path()).expect("a pre-COH-2 data-dir opens read-only");
        assert_eq!(ro.get_meta("tip_hash").unwrap(), Some(vec![7u8; 32]));
        assert!(ro.get_shielded(b"T").is_err(), "the family does not exist read-only");
        drop(ro);
        let rw = Storage::open(tmp.path()).unwrap();
        assert_eq!(rw.get_shielded(b"T").unwrap(), None);
    }

    /// The upgrade is one-way (docs/RUNNING.md, "Upgrading and
    /// downgrading"): once this release has opened a data-dir, the open an
    /// earlier release performs (read-write, a fixed descriptor list without
    /// `shielded`) is refused by RocksDB, so a downgrade needs a pre-upgrade
    /// copy of the data directory or a resync.
    #[test]
    fn upgraded_data_dir_is_refused_by_the_open_of_an_earlier_release() {
        let tmp = tempfile::tempdir().unwrap();
        drop(Storage::open(tmp.path()).unwrap());
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let old: Vec<ColumnFamilyDescriptor> =
            Storage::cf_descriptors().into_iter().filter(|d| d.name() != CF_SHIELDED).collect();
        let err = DB::open_cf_descriptors(&opts, tmp.path(), old).expect_err("an earlier release cannot open it");
        assert!(err.to_string().contains("Column families not opened: shielded"), "{err}");
        drop(Storage::open(tmp.path()).expect("this release still opens it"));
    }

    /// B1-T11: the per-address history counter equals the number of index
    /// rows through indexing, re-indexing the same rows (idempotent: a key
    /// counts once), un-indexing and `put_block`; a data directory written
    /// with aggregate layout 1 (no counters) reports no count until the
    /// start-up rebuild, which restores the exact counts.
    #[test]
    fn b1_t11_history_counter_tracks_the_index_exactly() {
        let tmp = tempfile::tempdir().unwrap();
        let a = [0x31u8; 20];
        let mk_tx_coinbase = |_: u8, value: u64| crate::core::Transaction {
            version: 1,
            inputs: vec![crate::core::TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: b"cb".to_vec(), sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: a.to_vec() }],
            locktime: 0,
        };
        let rows = |s: &Storage| s.count_address_history(&a, 0, u64::MAX).unwrap();
        {
            let store = Storage::open(tmp.path()).unwrap();
            assert!(store.aggregates_ready());
            assert_eq!(store.address_history_count(&a).unwrap(), Some(0));
            for h in 1..=5u64 {
                store.index_tx_addresses(&mk_tx_coinbase(0x31, h), h, 0).unwrap();
            }
            assert_eq!(store.address_history_count(&a).unwrap(), Some(5));
            store.index_tx_addresses(&mk_tx_coinbase(0x31, 3), 3, 0).unwrap();
            assert_eq!((store.address_history_count(&a).unwrap(), rows(&store)), (Some(5), 5), "same key counts once");
            store.unindex_tx_addresses(&mk_tx_coinbase(0x31, 3), 3, 0, &std::collections::HashMap::new()).unwrap();
            store.unindex_tx_addresses(&mk_tx_coinbase(0x31, 3), 3, 0, &std::collections::HashMap::new()).unwrap();
            assert_eq!((store.address_history_count(&a).unwrap(), rows(&store)), (Some(4), 4));
            let mut genesis = crate::core::genesis_block();
            genesis.transactions[0].outputs[0].script_pubkey = a.to_vec();
            store.put_block(&genesis).unwrap();
            assert_eq!((store.address_history_count(&a).unwrap(), rows(&store)), (Some(5), 5), "put_block counts");
            let cancel = std::sync::atomic::AtomicBool::new(false);
            assert_eq!(store.aggregate_snapshot().unwrap(), store.recompute_aggregates(&cancel).unwrap());
            // Simulate a layout-1 data directory: no counters, version 1.
            let cf = store.db.cf_handle(CF_META).unwrap();
            store.db.delete_cf(cf, [&b"agg/hist/"[..], &a[..]].concat()).unwrap();
            store.db.put_cf(cf, b"agg/version", 1u32.to_le_bytes()).unwrap();
        }
        let store = Storage::open(tmp.path()).unwrap();
        assert!(!store.aggregates_ready());
        assert_eq!(store.address_history_count(&a).unwrap(), None, "no count while incomplete");
        assert!(store.ensure_aggregates().unwrap(), "the upgrade rebuilds the aggregates");
        assert_eq!(store.address_history_count(&a).unwrap(), Some(5));
    }

    /// B1-T11 (R5) with `--reindex-addresses` (main d400bd0), which since
    /// DAG-8 (R1b) is `rebuild_chain_indexes`, the one rebuild of the
    /// selected-chain indexes (also the start-up migration): it rewrites the
    /// history rows outside the indexing paths that keep the per-address
    /// counters, so it rebuilds the counters from the new rows: afterwards
    /// every counter equals its address's rows (receipts AND spends, the rows
    /// the rebuild restores from the undo record), the aggregates are
    /// complete again and equal a full recomputation, and the rows are keyed
    /// by chain position.
    #[test]
    fn b1_t11_reindex_addresses_keeps_the_history_counters_exact() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Storage::open(tmp.path()).unwrap();
        let (a, b) = ([0x41u8; 20], [0x42u8; 20]);
        let coinbase = |tag: &str, to: [u8; 20], value: u64| crate::core::Transaction {
            version: 1,
            inputs: vec![crate::core::TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: tag.as_bytes().to_vec(), sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: to.to_vec() }],
            locktime: 0,
        };
        let mut b0 = crate::core::genesis_block();
        b0.transactions = vec![coinbase("b0", a, 50)];
        let pay = crate::core::Transaction {
            version: 1,
            inputs: vec![crate::core::TxInput { prev_txid: b0.transactions[0].txid(), prev_index: 0, script_sig: vec![1], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 30, script_pubkey: b.to_vec() }, TxOutput { value: 19, script_pubkey: a.to_vec() }],
            locktime: 0,
        };
        let mut b1 = b0.clone();
        b1.header.parents = vec![b0.block_hash()];
        b1.height = 1;
        b1.transactions = vec![coinbase("b1", b, 50), pay];
        store.put_block(&b0).unwrap();
        store.put_block(&b1).unwrap();
        // b1's undo record: what its connect spent (the rebuild resolves the
        // spend row from it).
        let mut undo = crate::core::UndoData::new(b1.block_hash(), 1);
        undo.spent_utxos.push(crate::core::UndoEntry {
            prev_txid: b0.transactions[0].txid(), prev_index: 0, output: b0.transactions[0].outputs[0].clone(),
        });
        store.put_undo_data(&b1.block_hash(), &undo).unwrap();
        // A history that lost its spend row (the pre-d400bd0 reorg defect):
        // the counter follows the deletion through the indexing path.
        let spend_row = indexer::make_key(&a, 1, 1, 0x8000_0000);
        store.unindex_tx_addresses(&b1.transactions[1], 1, 1,
            &[((b0.transactions[0].txid(), 0), b0.transactions[0].outputs[0].clone())].into_iter().collect()).unwrap();
        let rows = |s: &Storage, x: &[u8; 20]| s.count_address_history(x, 0, u64::MAX).unwrap();
        assert_eq!((store.address_history_count(&a).unwrap(), rows(&store, &a)), (Some(1), 1));
        let cf = store.db.cf_handle(indexer::CF_ADDR_TX_HISTORY).unwrap();
        assert!(store.db.get_cf(cf, &spend_row).unwrap().is_none());
        assert!(store.aggregates_ready());

        let r = store.rebuild_chain_indexes(&[
            (b0.block_hash(), 0, b0.header.timestamp),
            (b1.block_hash(), 1, b1.header.timestamp),
        ]).unwrap();
        assert_eq!((r.blocks, r.rows, r.lost, r.unresolved), (2, 5, 0, 0));
        assert!(store.db.get_cf(cf, &spend_row).unwrap().is_some(), "the spend row is back, at b1's position");
        assert!(store.aggregates_ready(), "complete again after the rebuild");
        for (x, n) in [(a, 3u64), (b, 2)] {
            assert_eq!((store.address_history_count(&x).unwrap(), rows(&store, &x)), (Some(n), n));
        }
        let cancel = std::sync::atomic::AtomicBool::new(false);
        assert_eq!(store.aggregate_snapshot().unwrap(), store.recompute_aggregates(&cancel).unwrap());
    }
}

// ── Bloch Genesis-3 carryover ingestion ─────────────────────────────────────

impl Storage {
    /// Write a verified, converted carryover into the UTXO set in one atomic
    /// batch, together with the `carryover_sha3` marker. `snap` can only come
    /// from `core::carryover::verify_and_convert`, so every consensus check
    /// has already passed.
    pub fn ingest_carryover(
        &self,
        snap: &crate::core::carryover::VerifiedCarryover,
        locked: &[crate::core::vesting::Tranche],
    ) -> Result<u64, StorageError> {
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        for u in &snap.utxos {
            if let Some(prev) = self.get_utxo(&u.txid, u.vout)? {
                deltas.remove(&prev);
            }
            deltas.add(&u.output);
        }
        for t in locked {
            if let Some(prev) = self.get_utxo(&t.txid, t.vout)? {
                deltas.remove(&prev);
            }
            deltas.add(&t.output);
        }
        let mut batch = rocksdb::WriteBatch::default();
        self.stage_carryover(&mut batch, snap, locked)?;
        // NET-12: holder aggregates in the same batch.
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok((snap.utxos.len() + locked.len()) as u64)
    }

    /// Stage exactly the UTXO rows [`ingest_carryover`](Self::ingest_carryover)
    /// writes (the carryover UTXOs, the locked vesting tranches, their
    /// address-index rows and the `carryover_sha3` / `vesting_sha3` markers) into a caller-owned batch, WITHOUT the NET-12
    /// holder aggregates: `ingest_carryover` stages those itself, and the
    /// chain-state rebuild (audit DAG-11), which uses this to restore the
    /// genesis state, recomputes every aggregate once it has reconnected the
    /// chain (`Storage::rebuild_aggregates`).
    pub fn stage_carryover(
        &self,
        batch: &mut rocksdb::WriteBatch,
        snap: &crate::core::carryover::VerifiedCarryover,
        locked: &[crate::core::vesting::Tranche],
    ) -> Result<(), StorageError> {
        let cf_utxo = self.db.cf_handle(CF_UTXO)
            .ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO)
            .ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_meta = self.db.cf_handle(CF_META)
            .ok_or(StorageError::CfNotFound(CF_META.into()))?;
        // Audit F1: every txid of the ledger gets a genesis-ledger row (its
        // confirmation point, the genesis), in the same batch.
        for u in &snap.utxos {
            batch.put_cf(&cf_utxo, utxo_key(&u.txid, u.vout), encode(&u.output)?);
            batch.put_cf(&cf_ai, addr_utxo_key(&u.output.script_pubkey, &u.txid, u.vout), [0u8; 0]);
            batch.put_cf(&cf_meta, genesis_ledger_key(&u.txid), [0u8; 0]);
        }
        // Locked team and founder tranches (core::vesting), same batch: the
        // genesis ledger lands complete or not at all.
        for t in locked {
            batch.put_cf(&cf_utxo, utxo_key(&t.txid, t.vout), encode(&t.output)?);
            batch.put_cf(&cf_ai, addr_utxo_key(&t.output.script_pubkey, &t.txid, t.vout), [0u8; 0]);
            batch.put_cf(&cf_meta, genesis_ledger_key(&t.txid), [0u8; 0]);
        }
        batch.put_cf(&cf_meta, b"carryover_sha3", snap.sha3);
        batch.put_cf(&cf_meta, b"vesting_sha3", crate::core::vesting::VESTING_SPEC_SHA3);
        batch.put_cf(&cf_meta, GENESIS_LEDGER_INDEX_META.as_bytes(), [1u8]);
        Ok(())
    }

    /// Audit F1: whether `txid` is the txid of a genesis-ledger output (its
    /// [`GENESIS_LEDGER_PREFIX`] row). Such an output has no tx-index row and
    /// is confirmed at the genesis.
    pub fn is_genesis_ledger_txid(&self, txid: &[u8; 32]) -> Result<bool, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        Ok(self.db.get_pinned_cf(&cf, genesis_ledger_key(txid))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            .is_some())
    }

    /// Audit F1, start-up migration: give a data dir whose genesis ledger was
    /// ingested before the genesis-ledger index existed its rows (one batch,
    /// once; [`GENESIS_LEDGER_INDEX_META`]). Without the carryover snapshot
    /// (not needed after first boot) the rows are recovered from the state:
    ///
    /// * the locked vesting tranches from the embedded specification
    ///   (`core::vesting::genesis_tranches`, the one the `vesting_sha3`
    ///   marker names), exactly, spent or not. They are the genesis ledger's
    ///   only policy outputs, so the only ones whose confirmation point a
    ///   rule reads (relative timelocks read policy outputs only, coinbase
    ///   maturity coinbases only);
    /// * the carryover (20-byte key-hash outputs, `core::carryover`): every
    ///   key-hash output, unspent (CF_UTXO) or spent by an applied block (its
    ///   undo record), whose txid has no tx-index row. Every transaction's
    ///   outputs are written with its tx-index row in one batch, so on a
    ///   consistent chain state these are exactly the carryover outputs.
    ///
    /// A store without the genesis-ledger markers (fixtures) is left alone.
    /// Returns the number of txids recorded (`None`: nothing to do).
    pub fn migrate_genesis_ledger_index(&self) -> Result<Option<usize>, StorageError> {
        if self.get_meta(GENESIS_LEDGER_INDEX_META)?.is_some() {
            return Ok(None);
        }
        let vesting = self.get_meta("vesting_sha3")?;
        if vesting.is_none() && self.get_meta("carryover_sha3")?.is_none() {
            return Ok(None);
        }
        let mut txids: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        if vesting.as_deref() == Some(&crate::core::vesting::VESTING_SPEC_SHA3[..]) {
            let tranches = crate::core::vesting::genesis_tranches()
                .map_err(|e| StorageError::DeserializeFailed(format!("vesting specification: {e}")))?;
            txids.extend(tranches.iter().map(|t| t.txid));
        }
        let key_hash = |o: &TxOutput| crate::core::policy::output_kind(&o.script_pubkey)
            == Some(crate::core::policy::OutputKind::PubkeyHash);
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        for item in self.db.iterator_cf(&cf_utxo, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            let Some(txid) = k.get(..32).and_then(|t| <[u8; 32]>::try_from(t).ok()) else { continue };
            if txids.contains(&txid) {
                continue;
            }
            let output: TxOutput = decode(&v)?;
            if key_hash(&output) && self.get_tx_location(&txid)?.is_none() {
                txids.insert(txid);
            }
        }
        for block in self.undo_block_hashes()? {
            let Some(undo) = self.get_undo_data(&block)? else { continue };
            for e in &undo.spent_utxos {
                if !txids.contains(&e.prev_txid) && key_hash(&e.output)
                    && self.get_tx_location(&e.prev_txid)?.is_none()
                {
                    txids.insert(e.prev_txid);
                }
            }
        }
        let cf_meta = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        for t in &txids {
            batch.put_cf(&cf_meta, genesis_ledger_key(t), [0u8; 0]);
        }
        batch.put_cf(&cf_meta, GENESIS_LEDGER_INDEX_META.as_bytes(), [1u8]);
        self.write_batch(batch)?;
        Ok(Some(txids.len()))
    }
}
