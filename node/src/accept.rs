//! Block acceptance pipeline — acceptance separated from connection.
//!
//! Moved out of `main.rs` so integration tests can drive the REAL pipeline
//! (`gnb::accept::accept_block`). `main.rs` declares this module and `use`s the
//! same function names and signatures.
//!
//! # Semantics (audit DAG-1)
//!
//! Like Bitcoin Core's `AcceptBlock` / `ConnectBlock` split, and Kaspa's
//! "disqualified from chain" status:
//!
//! **Acceptance** (every block, any arrival order): parents known, header
//! height = max parent DAG height + 1, expected ASERT bits, timestamp, at/after
//! the hardening activation the context-free block rules of
//! `core::block_rules` (wire size, tagged Merkle root, 64-byte transactions,
//! coinbase height / parents / witness commitment), the block-size limit of
//! the verified height in the measure of the regime, proof of work, and the
//! context-free consensus checks (canonical-encoding limits, MoneyRange; the
//! structural checks run in `validate_structure` before this function). A
//! failure here is context-free, so every node rejects the block and it is
//! never stored. A block that passes is inserted into GhostDAG and
//! its body is stored — fork-losers included — WITHOUT validating its
//! transactions against the current tip's UTXO set. The stored body carries
//! the `blue_score` derived from the block's parents (the max parent blue
//! score plus one), never the uncommitted wire value (POW-8, re-audit B1-T0),
//! so every node stores and serves the same bytes for one block id.
//!
//! **Connection**: the applied UTXO set always corresponds to the selected-
//! parent chain of the best (highest blue_work, blue_score, hash) block that is
//! not chain-disqualified. After an insertion the pipeline computes the plan
//! from the applied tip to that best block (an extension, several blocks, or a
//! reorg) and executes it in ONE atomic RocksDB batch (`reorg::connect_plan`),
//! validating every block of the plan against ITS OWN selected-chain context
//! (inputs, double spends, coinbase maturity, signatures, fees, coinbase
//! value). Merged (non-selected) blocks never affect the UTXO set — as before.
//!
//! **Invalid blocks**: a connect-time failure that depends only on data the
//! block id commits to is a deterministic property of the block and its
//! selected-parent chain, so it is permanent. The failing
//! block and every block whose selected-parent chain passes through it are
//! marked chain-disqualified, in memory (`GhostDAG::mark_invalid`) and on disk
//! (`Storage::stage_invalid_block`), and the next-best block is tried; the
//! old tip is kept when nothing better is valid. A disqualified block is never
//! selected, applied or offered as a template parent, and a new block whose
//! selected parent is disqualified is disqualified on arrival. `accept_block`
//! reports such blocks as rejected (`Err`). A failure to READ the UTXO view
//! (`reorg::ViewError`: I/O error, corrupted row) is no verdict
//! ([`ConnectFailure::Storage`]): nothing is marked or persisted and the
//! connect fails as a storage failure (re-audit B1-T12). It is never a
//! silent permanent stall (audit F1 and its review): the block keeps its
//! body and is parked in memory with its descendants, the node connects and
//! mines on the best chain it can judge (re-applying an old branch whose
//! rollback committed), and the block is retried on a bounded schedule
//! ([`unpark_due_no_verdicts`]). Only storage-engine failures
//! (`reorg::ViewErrorKind::Io`), [`NO_VERDICT_ABORT_AFTER`] in a row, stop
//! the node, like Bitcoin Core's `AbortNode`; an inconsistent index never
//! does ([`note_no_verdict`]), and the RPC warns while such a parked branch
//! is heavier than the applied tip ([`no_verdict_branch_warning`]). A stored
//! body of a block to apply that cannot be read is attributed the same way
//! (review of PR #15, finding 6): an engine error is that block's
//! no-verdict, a body that does not decode is dropped and fetched again
//! (`drop_undecodable_body`). A block whose judgement fails is therefore
//! given a verdict, parked (retried on schedule, counted toward the stop
//! when the engine failed) or made to wait for a body; what remains (a
//! failed write, a rollback-only chunk that cannot read a body) fails that
//! acceptance with an error, and a move stopped after committed chunks
//! resumes with the next one.
//!
//! **Witness-dependent failures below the hardening activation**: there the
//! block id does not commit to non-coinbase `script_sig` bytes, so a relay
//! can alter them (breaking a signature, padding past the minimum fee)
//! without changing the id. Such a failure (`BlockInvalidity::
//! witness_dependent`) is a property of THIS BODY, not of the block: the body
//! is deleted, nothing is persisted, and the block (with its selected-chain
//! descendants) waits in memory for another body
//! (`GhostDAG::mark_body_pending`). Header sync and `submitblock` do not
//! treat it as known (`is_known_block`); the processor re-requests it from
//! peers, and over block relay only the answer to that directed pull is taken
//! (`ingress::BlockIngress::handle_block`: an unsolicited gossip copy is
//! ignored, so nobody can make the node re-validate the chain through the
//! block with an endless supply of re-malleated bodies). A copy with a
//! different witness root replaces the body and is re-evaluated.
//! A block whose body is missing waits the same way — also one whose body was
//! PRUNED while it was on the selected chain and that a reorg left unapplied
//! (audit DAG-6: without a reorg-depth limit the chain through it can become
//! the best again): `resolve_best_chain` makes every bodiless block of the
//! best chain wait at once, and the chain connects when the last body is
//! back. One predicate ([`awaits_body`]) decides whether a body of a DAG block
//! is wanted, one request path fetches it, and one acceptance path
//! (`accept_block`'s body replacement) binds a copy to the header height the
//! DAG parents imply and to the witness-root rules. At/after the activation
//! the witness commitment is checked before the block is stored, so every
//! connect-time failure is permanent.
//!
//! **Blocks stored by a pre-upgrade binary**: at start-up
//! (`reconcile_on_startup`) the stored blocks at header height >= the
//! hardening activation are rechecked once against the context-free
//! hardening rules (`recheck_stored_blocks_under_hardening`); one that fails
//! for a reason its id commits to is disqualified with every DAG descendant
//! through ANY parent edge, since no upgraded peer can accept a block that
//! references it.
//!
//! Disqualified blocks are KEPT in the DAG (their insertion is not rolled
//! back) on purpose: whether a node evaluates a block at all depends on
//! arrival order (a fork-loser is never connected), so a block one node
//! disqualified can be an unevaluated tip on another node, which may merge it
//! as a NON-selected parent. If the first node had deleted the block it could
//! never accept that honest merging block, and the two would split. Since a
//! block's validity depends only on its selected-parent chain, keeping the
//! disqualified block lets both nodes accept the merger and converge.
//!
//! **No reorg-depth limit, no finality checkpoint (audit DAG-6)**: the old
//! `MAX_REORG_DEPTH` cap and `finalized_height` gate compared a fork with THIS
//! node's own history, so two nodes given the same blocks in different orders
//! could end on different chains. Both are gone. Like Bitcoin Core, the node
//! always ends on the best valid chain of the blocks it holds; deep reorgs are
//! logged and counted (`reorg::DEEP_REORG_ALERT_DEPTH`), never refused.
//! Bounded merging is enforced objectively by GhostDAG's merge depth after the
//! hardening activation. Operators override the choice explicitly and
//! persistently with [`invalidate_block`] / [`reconsider_block`] (the RPCs
//! `invalidateblock` / `reconsiderblock`), which reuse the disqualification
//! machinery below. `reconsiderblock` never removes a consensus verdict
//! without re-validating it: a hardening-recheck mark goes only if the stored
//! body now passes those rules, a connect-time mark only with the batch that
//! re-validates and applies the block.
//!
//! **Arrival-order independence**: given the same block set, every node ends
//! with the applied tip = the best block whose selected chain is valid in its
//! own context, and the same UTXO set (the deterministic application of that
//! chain), whatever order the blocks arrived in, at any depth
//! (`node/tests/fix_chain_selection.rs`).
//!
//! **Chain-state check (audit DAG-11)**: [`check_chain_state`] detects, at
//! start-up, the footprint a crash or write error of the pre-fix NON-atomic
//! extension commit leaves (UTXO effects without an undo record), which
//! [`reconcile_on_startup`] cannot repair (it runs after reconciliation's
//! step 2, which repairs the states it can); [`rebuild_chain_state`] rebuilds
//! the chain state — UTXO set and indexes, undo records, shielded state,
//! explorer aggregates — from the block bodies.
//!
//! # Serialization (audit DAG-10)
//!
//! The whole pipeline runs under `Storage::acceptance_lock()`. Lock order:
//! acceptance lock → DAG lock → everything else.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use log::{debug, error, info, warn};
use parking_lot::RwLock;
use tokio::sync::broadcast;

pub use crate::assumevalid::ScriptChecks;
use crate::coherence::ShieldedPool;
use crate::consensus::{self, BlockHash};
use crate::core;
use crate::mempool::{self, admission};
use crate::pow;
use crate::reorg::{self, ConnectError, ConnectHooks, ConnectOutcome, UtxoView, ValidationFailure, ViewError, ViewErrorKind};
use crate::rpc;
use crate::storage;
use crate::tip;

/// Set once from `--archive` at startup: accept_block runs far from the CLI
/// struct and threading a bool through every caller would be noise for a
/// value that is fixed for the process lifetime. (The former `FINALITY_FROZEN`
/// flag is gone with the finality checkpoint it froze, audit DAG-6.)
pub static ARCHIVE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Reason recorded with a disqualification made by the operator
/// (`invalidateblock`). Marks carrying it survive a chain-state rebuild
/// (DAG-11); consensus disqualifications are re-derived instead.
pub const OPERATOR_INVALIDATE_REASON: &str = "invalidateblock (operator)";

// ── Invalid-set persistence ──────────────────────────────────────────────────

/// Reason prefix of the persisted marks written by the start-up hardening
/// recheck ([`recheck_stored_blocks_under_hardening`]). Such marks are
/// reloaded as all-edges roots (`GhostDAG::mark_invalid_all_edges`).
pub const HARDENING_RECHECK_REASON: &str = "fails the hardening block rules";

/// Load the persisted chain-disqualified set into `dag` once (start-up does it
/// via `reconcile_on_startup`; this is the lazy fallback).
pub fn ensure_invalid_set_loaded(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) {
    if dag.read().invalid_set_loaded() {
        return;
    }
    match store.load_invalid_blocks_with_reasons() {
        Ok(marks) => {
            let (selected, all_edges) = split_marks(marks);
            let n = dag.write().load_invalid_sets(selected, all_edges);
            if n > 0 {
                info!("loaded {} chain-disqualified block(s)", n);
            }
        }
        Err(e) => error!("cannot read the persisted invalid-block set: {}", e),
    }
}

/// True iff `hash` is in the DAG but a body for it is still wanted — THE one
/// predicate for "a body of this DAG block is wanted" (see "Blocks in the DAG
/// without a usable body" below): it waits for a body
/// (`GhostDAG::is_body_pending`: its body failed a witness-dependent rule,
/// or a connect of the best chain — or an operator override — needs a body
/// that is missing, pruned ones included, audit DAG-6) and that body is
/// wanted now (`GhostDAG::is_body_wanted`: a chain through it can still
/// become the best one, or an operator override needs it; re-audit B1-T13),
/// or its body is missing although it was never pruned (a body dropped after
/// such a failure, before a restart). A copy of such a block is processed (and
/// requested from peers) instead of being discarded as already known; any
/// other copy of a DAG block — an unrequested old body included — is known.
pub fn awaits_body(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    hash: &BlockHash,
) -> bool {
    awaits_body_in(&dag.read(), store, hash)
}

/// [`awaits_body`] under a DAG guard the caller already holds.
pub fn awaits_body_in(d: &consensus::GhostDAG, store: &storage::Storage, hash: &BlockHash) -> bool {
    if d.is_body_pending(hash) {
        // Waiting, but wanted only while a chain through it can still win
        // (or an operator asked): a copy of a block on a lighter branch is
        // known, like an unrequested low-work block in Bitcoin Core
        // (re-audit B1-T13, `GhostDAG::is_body_wanted`).
        return d.is_body_wanted(hash);
    }
    let dag_height = match d.get_block_data(hash) {
        Some(data) if !data.parents.is_empty() => data.height,
        _ => return false, // unknown, or the genesis
    };
    // Pruning removes a body once the cursor passes the height it was
    // indexed at, which is never below the block's DAG height (B1-T17,
    // `Storage::put_block_body_at`; the cursor is a chain position, a DAG
    // height, audit DAG-8; releases before both pruned selected-chain bodies
    // by header height, which is >= the DAG height): a block whose DAG
    // height is at or above the pruning cursor was never pruned.
    dag_height >= store.pruned_height() && matches!(store.has_block_body(hash), Ok(false))
}

/// True iff `hash` needs no further copy: it is in the DAG and does not
/// [`awaits_body`]. The dedup header sync, directed pulls and `submitblock`
/// apply before `accept_block`. Gossip is stricter: an unsolicited copy of a
/// DAG block is ignored even while a body of it is wanted (only the answer to
/// the node's own directed pull is taken, `ingress::BlockIngress::
/// handle_block`; docs/CONSENSUS.md, "Ledger semantics").
pub fn is_known_block(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    hash: &BlockHash,
) -> bool {
    is_known_block_in(&dag.read(), store, hash)
}

/// [`is_known_block`] under a DAG guard the caller already holds.
pub fn is_known_block_in(d: &consensus::GhostDAG, store: &storage::Storage, hash: &BlockHash) -> bool {
    d.has_block(hash) && !awaits_body_in(d, store, hash)
}

/// The reachability records a batch carries: `(upserts, deletes)`.
type ReachDelta = (Vec<(BlockHash, Vec<u8>)>, Vec<BlockHash>);

/// Stage the CF_DAG (+ integrity, + reachability delta) record of `hash`. If
/// the selected parent is the genesis and its integrity record was never
/// written (fixture stores), the genesis record is staged lazily in the same
/// batch; any other missing parent record is an error (DAG-11).
///
/// The reachability delta is staged but NOT drained (audit DAG-11): the
/// caller passes the returned delta to [`reach_committed`] once the batch has
/// committed. A batch that is dropped or fails leaves the delta pending, so
/// the next committed DAG record writes it (a delta drained here was lost
/// with a failed batch, and the intervals a reindex had moved stayed stale on
/// disk: rolling the insertion back only re-marks the removed leaf's parent).
fn stage_dag_record_for(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    batch: &mut rocksdb::WriteBatch,
    hash: &BlockHash,
) -> Result<ReachDelta, String> {
    let data = dag.read().get_block_data(hash).cloned()
        .ok_or_else(|| format!("block {} vanished from the DAG", hex::encode(&hash[..8])))?;
    let mut parent_override = None;
    if let Some(sp) = data.selected_parent {
        let missing = store.get_integrity_hash(&sp).map_err(|e| e.to_string())?.is_none();
        let genesis = dag.read().store.genesis;
        if missing && genesis == Some(sp) {
            let gd = dag.read().get_block_data(&sp).cloned()
                .ok_or_else(|| "genesis vanished from the DAG".to_string())?;
            let gi = store.stage_dag_record(batch, &sp, &gd, &[], &[], None)
                .map_err(|e| e.to_string())?;
            parent_override = Some(gi);
        } else if missing {
            return Err(format!(
                "DAG record: integrity record of selected parent {} is missing; refusing to \
                 write a zero-filled chain link",
                hex::encode(&sp[..8])
            ));
        }
    }
    let (ups, rems) = if dag.read().maintains_reachability_index() {
        dag.read().reach_peek_delta()
    } else {
        (Vec::new(), Vec::new())
    };
    store.stage_dag_record(batch, hash, &data, &ups, &rems, parent_override)
        .map_err(|e| format!("DAG record: {}", e))?;
    Ok((ups, rems))
}

/// A batch carrying `delta` (from [`stage_dag_record_for`]) has committed:
/// clear what it wrote from the pending reachability delta.
fn reach_committed(dag: &Arc<RwLock<consensus::GhostDAG>>, delta: &ReachDelta) {
    if !delta.0.is_empty() || !delta.1.is_empty() {
        dag.write().reach_mark_persisted(&delta.0, &delta.1);
    }
}

// ── In-context block validation ──────────────────────────────────────────────

/// A connect-time rejection, classified by what it depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInvalidity {
    pub reason: String,
    /// The failure depends on bytes the block id does not commit to, and a
    /// body with other such bytes could cure it: a non-coinbase `script_sig`
    /// (script parse, public key against a 20-byte prevout script, a policy
    /// witness: its framing, its hash against a policy output, its
    /// timelocks and branch, `blockval::check_policy_spends`; signature) or
    /// the size-based minimum fee above the floor a body with minimal
    /// witnesses would still owe, of a block whose id does not commit to its
    /// witnesses ([`witnesses_fixed_at`]: below both
    /// `core::WITNESS_COMMITMENT_HEIGHT` and the hardening activation) and
    /// whose id-committed checks all passed. Another body with the same id
    /// may be valid, so the id must not be disqualified. A failure no body
    /// with this id can cure is id-committed (re-audit B1-T13): a fee below
    /// `min_tx_fee_sat` of the size with every `script_sig` empty (so below
    /// `MIN_TX_FEE_SAT` too), a transaction without inputs, a spend of a
    /// coin whose script is neither output kind, this chain's context-free
    /// rules (locktime finality, output kinds, dust), and any id-committed
    /// failure anywhere in the block (the id-committed checks of every
    /// transaction run before any witness check). Always `false` where the
    /// id commits to the witnesses (the `|wc:` suffix from
    /// `WITNESS_COMMITMENT_HEIGHT`, the coinbase commitment from the
    /// activation; both checked before the block is stored, so they fix
    /// every byte of the body).
    pub witness_dependent: bool,
}

/// Why connect-time validation did not pass: a verdict on the block, or no
/// verdict at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectFailure {
    /// The block is invalid in its own selected-chain context (classified,
    /// see [`BlockInvalidity`]).
    Invalid(BlockInvalidity),
    /// The UTXO view could not be read (`reorg::ViewError`: I/O error,
    /// corrupted row, inconsistent index; its `kind` says which class).
    /// NOT a verdict: nothing is marked or persisted, the connect fails as a
    /// storage failure and the block is validated again later (re-audit
    /// B1-T12; Bitcoin Core aborts on a coins-database read error instead of
    /// caching BLOCK_FAILED_VALID).
    Storage(ViewError),
}

impl ConnectFailure {
    /// The verdict, when this is one.
    pub fn invalidity(&self) -> Option<&BlockInvalidity> {
        match self {
            ConnectFailure::Invalid(b) => Some(b),
            ConnectFailure::Storage(_) => None,
        }
    }

    /// One line for the string-typed library API: the verdict's reason, or
    /// the read failure (never mistaken for a rule: it says so).
    pub fn into_message(self) -> String {
        match self {
            ConnectFailure::Invalid(b) => b.reason,
            ConnectFailure::Storage(e) => match e.kind {
                ViewErrorKind::Io => format!("storage read failed, no verdict: {}", e.msg),
                ViewErrorKind::Inconsistent => {
                    format!("storage read failed, no verdict (inconsistent chain state): {}", e.msg)
                }
            },
        }
    }
}

/// A transaction-level failure: a verdict (`witness` = it depends on the
/// transaction's `script_sig` bytes, see [`BlockInvalidity`]) or a read
/// failure of the view, which is no verdict (re-audit B1-T12: a read error
/// used to convert into an id-committed verdict through `From<String>`).
#[derive(Debug)]
enum TxFailure {
    Invalid { reason: String, witness: bool },
    Storage(ViewError),
}

impl From<String> for TxFailure {
    fn from(reason: String) -> Self {
        TxFailure::Invalid { reason, witness: false }
    }
}

impl From<ViewError> for TxFailure {
    fn from(e: ViewError) -> Self {
        TxFailure::Storage(e)
    }
}

impl TxFailure {
    fn witness(reason: String) -> Self {
        TxFailure::Invalid { reason, witness: true }
    }

    /// Classified at a block whose id commits (`witnesses_fixed`) or not to
    /// every witness: from `core::WITNESS_COMMITMENT_HEIGHT` (the `|wc:`
    /// suffix) and at/after the hardening activation (the audit's coinbase
    /// commitment) the witness commitment, checked before the block is
    /// stored, fixed the body, so no failure is witness-dependent there
    /// ([`witnesses_fixed_at`]).
    fn into_connect(self, witnesses_fixed: bool) -> ConnectFailure {
        match self {
            TxFailure::Invalid { reason, witness } => {
                ConnectFailure::Invalid(BlockInvalidity { reason, witness_dependent: witness && !witnesses_fixed })
            }
            TxFailure::Storage(e) => ConnectFailure::Storage(e),
        }
    }

    fn into_message(self) -> String {
        self.into_connect(true).into_message()
    }
}

/// Whether the id of a block at header height `height` commits to every
/// witness of its body: from `core::WITNESS_COMMITMENT_HEIGHT` (the `|wc:`
/// suffix, `Block::validate_witness_commitment`) and at/after the hardening
/// activation (`block_rules::check_coinbase_commitment`). Both are checked
/// before a block is stored, so a stored body of such a block is the only
/// body its id admits and no connect failure is witness-dependent.
pub fn witnesses_fixed_at(height: u64, activation_height: u64) -> bool {
    core::block_rules::rules_active_at(height, activation_height) || core::witnesses_committed(height)
}

/// Which heights the coinbase-maturity rule compares (re-audit B1-T14;
/// docs/CONSENSUS.md, "Coinbase maturity"). A spend of an output of the
/// coinbase of block C by a transaction of block B needs a depth of at least
/// `core::COINBASE_MATURITY` (100). The same measure counts the
/// confirmations a relative timelock (`older` of a spend policy,
/// `blockval::check_policy_spends_with_confirmations`) requires of the
/// output it spends, C being the block that confirmed that output
/// ([`confirmations_in_view`]); absolute heights (`locktime`, a policy's
/// `after`) are compared with B's header height in both regimes:
#[derive(Clone, Copy)]
pub enum MaturityRule<'a> {
    /// No maturity check (the single-transaction helpers' `0`).
    Skip,
    /// Below the hardening activation (B's header height below it): depth =
    /// B's HEADER height (the value given) minus C's header height (the
    /// coinbase-height row). Header heights are `max(parent DAG heights) +
    /// 1`, so this is not a count of confirmations: a B that merges a long
    /// side tip sits higher than its selected-chain position. Kept exactly.
    HeaderHeights(u64),
    /// From the activation: depth = B's DAG height (its position on its
    /// selected chain, from the closure, called at most once and only when
    /// an input spends a coinbase) minus C's DAG height (through the tx
    /// index and C's DAG record): the number of selected-chain blocks from
    /// C's child to B, B included. C lies on B's selected chain (only
    /// selected-chain blocks are applied), so this counts confirmations,
    /// like Bitcoin Core's `nSpendHeight - coin.nHeight`.
    SelectedChainDepth(&'a dyn Fn() -> Result<u64, ViewError>),
}

/// The DAG height of the block that created the coinbase `txid`, `None`
/// when `txid` is not a coinbase of the applied chain (no coinbase-height
/// row). A coinbase whose tx-index row or block DAG record cannot be found
/// is an inconsistent index: an error (no verdict), never "not a coinbase".
pub fn coinbase_dag_height(view: &dyn UtxoView, txid: &[u8; 32]) -> Result<Option<u64>, ViewError> {
    if view.view_coinbase_height(txid)?.is_none() {
        return Ok(None);
    }
    let block = view.view_tx_block(txid)?.ok_or_else(|| ViewError::inconsistent(format!(
        "coinbase {} has no tx-index row", hex::encode(&txid[..8]))))?;
    let data = view.view_dag_data(&block)?.ok_or_else(|| ViewError::inconsistent(format!(
        "block {} of coinbase {} has no DAG record", hex::encode(&block[..8]), hex::encode(&txid[..8]))))?;
    Ok(Some(data.height))
}

/// The DAG height of `block` (`GhostdagData::height`): its selected
/// parent's plus one. The selected parent is the parent of greatest
/// `(blue_work, blue_score, hash)` (`GhostDAG::select_parent`), read from the
/// parents' persisted DAG records (every parent is persisted before a block
/// on it is connected). A missing record is an error (no verdict).
pub fn block_dag_height(view: &dyn UtxoView, block: &core::Block) -> Result<u64, ViewError> {
    let mut best: Option<((u128, u64, BlockHash), u64)> = None;
    for p in &block.header.parents {
        let d = view.view_dag_data(p)?.ok_or_else(|| ViewError::inconsistent(format!(
            "parent {} of block {} has no DAG record", hex::encode(&p[..8]), hex::encode(&block.block_hash()[..8]))))?;
        let key = (d.blue_work, d.blue_score, *p);
        if best.as_ref().is_none_or(|(k, _)| key > *k) {
            best = Some((key, d.height));
        }
    }
    best.map(|(_, h)| h + 1).ok_or_else(|| ViewError::inconsistent("a block without parents has no selected parent"))
}

/// THE coinbase-maturity rule (re-audit B1-T14), shared by the connect path
/// (extension, reorg, start-up: [`validate_block_in_view`]), mempool
/// admission and revalidation, and the template self-check
/// (`admission::coinbase_maturity_for_next_block`). `Ok(Err(reason))`: an
/// input spends an immature coinbase; `Err`: a read failure of the view,
/// never "not a coinbase" (re-audit B1-T12).
pub fn check_coinbase_maturity_in_view(
    tx: &core::Transaction,
    view: &dyn UtxoView,
    rule: MaturityRule<'_>,
) -> Result<Result<(), String>, ViewError> {
    match rule {
        MaturityRule::Skip => Ok(Ok(())),
        MaturityRule::HeaderHeights(height) => {
            let mut read_error = None;
            let verdict = core::check_coinbase_maturity(tx, height, |txid| {
                view.view_coinbase_height(txid).unwrap_or_else(|e| {
                    read_error.get_or_insert(e);
                    None
                })
            });
            match read_error {
                Some(e) => Err(e),
                None => Ok(verdict),
            }
        }
        MaturityRule::SelectedChainDepth(spend_dag_height) => {
            let mut spend: Option<u64> = None;
            for (i, inp) in tx.inputs.iter().enumerate() {
                let Some(cb) = coinbase_dag_height(view, &inp.prev_txid)? else {
                    continue;
                };
                let s = match spend {
                    Some(s) => s,
                    None => *spend.insert(spend_dag_height()?),
                };
                let depth = s.saturating_sub(cb);
                if depth < core::COINBASE_MATURITY {
                    return Ok(Err(format!(
                        "coinbase maturity: input {} references a coinbase at DAG height {}, only {} \
                         selected-chain confirmations at DAG height {} (need {})",
                        i, cb, depth, s, core::COINBASE_MATURITY
                    )));
                }
            }
            Ok(Ok(()))
        }
    }
}

/// The confirmations the outputs of the CONFIRMED transaction `txid` have at
/// the spending block B under `rule` (the coinbase-maturity measure, re-audit
/// B1-T14), for relative timelocks (`older`): below the activation B's header
/// height minus the header height of the block the tx index names
/// (`blockval::check_policy_spends`, unchanged); from it B's DAG height minus
/// that block's DAG height, the number of selected-chain blocks from its
/// child to B. A genesis-ledger output (the carryover, the locked vesting
/// tranches: created by no transaction, so without a tx-index row,
/// `UtxoView::view_genesis_ledger`) is confirmed at the genesis, header
/// height 0 and DAG height 0 (audit F1; docs/CONSENSUS.md, "Genesis
/// ledger"): B's header height, resp. DAG height, confirmations. `Ok(None)`
/// when `txid` has neither (an output of an unconfirmed transaction); a
/// confirmed transaction whose block has no DAG record is an inconsistent
/// index, an error (no verdict). An output created earlier in B itself has
/// 0 confirmations: the caller answers that without asking the view.
/// [`MaturityRule::Skip`] has no measure and is never passed here (reported
/// as a read failure, so no verdict, if it were).
pub fn confirmations_in_view(
    view: &dyn UtxoView,
    rule: MaturityRule<'_>,
    txid: &[u8; 32],
) -> Result<Option<u64>, ViewError> {
    match rule {
        MaturityRule::Skip => Err(ViewError::inconsistent("no confirmation measure (MaturityRule::Skip)")),
        MaturityRule::HeaderHeights(height) => match view.view_tx_height(txid)? {
            Some(c) => Ok(Some(height.saturating_sub(c))),
            // Confirmed at the genesis: header height 0.
            None if view.view_genesis_ledger(txid)? => Ok(Some(height)),
            None => Ok(None),
        },
        MaturityRule::SelectedChainDepth(spend_dag_height) => {
            let Some(block) = view.view_tx_block(txid)? else {
                // Confirmed at the genesis: DAG height 0.
                if view.view_genesis_ledger(txid)? {
                    return Ok(Some(spend_dag_height()?));
                }
                return Ok(None);
            };
            let data = view.view_dag_data(&block)?.ok_or_else(|| ViewError::inconsistent(format!(
                "block {} of transaction {} has no DAG record", hex::encode(&block[..8]), hex::encode(&txid[..8]))))?;
            Ok(Some(spend_dag_height()?.saturating_sub(data.height)))
        }
    }
}

/// [`check_coinbase_maturity_in_view`] as a transaction-level failure.
fn check_maturity_in_view(tx: &core::Transaction, view: &dyn UtxoView, rule: MaturityRule<'_>) -> Result<(), TxFailure> {
    check_coinbase_maturity_in_view(tx, view, rule)?.map_err(TxFailure::from)
}

/// The id-committed checks of `tx` (a non-coinbase transaction of a block
/// at header height `block_height`) against `view` plus the outputs of the
/// transactions STRICTLY BEFORE it in the block (`earlier`): when
/// `same_block_coinbase` is `Some`, no input spending that coinbase's
/// outputs (this chain's rule at every height, audit VAL-3), coinbase
/// maturity under `maturity` (the block path passes the rule of its regime,
/// [`MaturityRule`]), this chain's context-free transaction rules once every
/// prevout is found (`blockval::check_tx_context_free`: locktime finality,
/// the two output kinds, dust; all over data the txid commits to), then
/// everything [`check_tx_inputs_committed`] checks. Returns what the witness
/// checks ([`check_tx_policy_spends`], [`check_tx_witnesses`]) need.
#[allow(clippy::too_many_arguments)]
fn check_tx_in_view_committed(
    tx: &core::Transaction,
    view: &dyn UtxoView,
    earlier: &HashMap<([u8; 32], u32), core::TxOutput>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    block_height: u64,
    maturity: MaturityRule<'_>,
    same_block_coinbase: Option<&[u8; 32]>,
    activation_height: u64,
) -> Result<CommittedTx, TxFailure> {
    if let Some(cb) = same_block_coinbase {
        if let Some(i) = tx.inputs.iter().position(|inp| &inp.prev_txid == cb) {
            return Err(format!(
                "coinbase maturity: input {} spends the coinbase of its own block (0 confirmations, need {})",
                i, core::COINBASE_MATURITY
            ).into());
        }
    }
    check_maturity_in_view(tx, view, maturity)?;
    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, ViewError> {
        if let Some(out) = earlier.get(&(*txid, idx)) {
            return Ok(Some(out.clone()));
        }
        view.view_utxo(txid, idx)
    };
    // This chain's context-free rules (`blockval`: finality, output kinds,
    // dust), in this chain's order: once every prevout is found, before the
    // input and value checks. Id-committed (locktime and outputs are in the
    // txid). The policy-spend rules (timelocks) read the witness: they are
    // witness checks ([`check_tx_policy_spends`], pass 2).
    let mut found = 0usize;
    for inp in &tx.inputs {
        if lookup(&inp.prev_txid, inp.prev_index)?.is_some() {
            found += 1;
        }
    }
    if found == tx.inputs.len() {
        crate::blockval::check_tx_context_free(tx, block_height)?;
    }
    let mut committed = check_tx_inputs_committed(tx, &lookup, Some(spent_in_block), block_height, activation_height)?;
    // The prevouts created earlier in this block: confirmed in the block
    // itself, so 0 confirmations for a relative timelock. (A txid created
    // earlier in the block has no other unspent outputs: BIP30.)
    committed.in_block = tx.inputs.iter()
        .filter(|inp| earlier.contains_key(&(inp.prev_txid, inp.prev_index)))
        .map(|inp| inp.prev_txid)
        .collect();
    Ok(committed)
}

/// [`check_tx_in_view_committed`], [`check_tx_policy_spends`] (relative
/// timelocks measured under `maturity`'s regime, `timelocks`) then
/// [`check_tx_witnesses`]: one transaction in full (the single-transaction
/// helpers). Returns the fee.
#[allow(clippy::too_many_arguments)]
fn validate_tx_in_view(
    tx: &core::Transaction,
    view: &dyn UtxoView,
    earlier: &HashMap<([u8; 32], u32), core::TxOutput>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    block_height: u64,
    maturity: MaturityRule<'_>,
    timelocks: MaturityRule<'_>,
    same_block_coinbase: Option<&[u8; 32]>,
    activation_height: u64,
) -> Result<u64, TxFailure> {
    let committed = check_tx_in_view_committed(
        tx, view, earlier, spent_in_block, block_height, maturity, same_block_coinbase, activation_height,
    )?;
    check_tx_policy_spends(tx, &committed, block_height, view, timelocks)?;
    check_tx_witnesses(tx, &committed, block_height, activation_height, ScriptChecks::Full)?;
    Ok(committed.fee)
}

/// The policy-spend rules of `tx` (`blockval::check_policy_spends_with_confirmations`:
/// the revealed policy's timelocks, a policy-tree spend only from
/// `core::powit_height()`) in a block at header height `block_height`, a
/// relative timelock counting confirmations under `timelocks` (the
/// coinbase-maturity measure of the block's regime, [`confirmations_in_view`];
/// 0 for an output created earlier in the block). Witness-dependent: the
/// policy and its branch are revealed by the `script_sig`, so another
/// witness may satisfy what this one does not. The revealed policy is
/// checked against the spent output FIRST (audit F1): a made-up policy is
/// this witness failure (classified like every other one: a body failure
/// below `witnesses_fixed_at`, permanent from it), never a confirmation
/// lookup. A confirmation that cannot be read, or an output found in the
/// view with neither a tx-index row nor a genesis-ledger row (an
/// inconsistent index), is a read failure (no verdict, re-audit B1-T12);
/// the policy that asks for it is the one the output commits to.
fn check_tx_policy_spends(
    tx: &core::Transaction,
    committed: &CommittedTx,
    block_height: u64,
    view: &dyn UtxoView,
    timelocks: MaturityRule<'_>,
) -> Result<(), TxFailure> {
    let read_error: std::cell::RefCell<Option<ViewError>> = std::cell::RefCell::new(None);
    let confirmations = |t: &[u8; 32]| -> Result<Option<u64>, String> {
        if committed.in_block.contains(t) {
            return Ok(Some(0));
        }
        confirmations_in_view(view, timelocks, t).map_err(|e| {
            let m = e.msg.clone();
            read_error.borrow_mut().get_or_insert(e);
            m
        })
    };
    let verdict = crate::blockval::check_policy_spends_with_confirmations(
        tx, &committed.prevouts, block_height, &confirmations,
    );
    if let Some(e) = read_error.into_inner() {
        return Err(TxFailure::Storage(e));
    }
    match verdict {
        Ok(()) => Ok(()),
        // An output found in the view without a confirmation: an
        // inconsistent index, not a rule (and not an engine failure).
        Err(e) if e.starts_with(crate::blockval::STORAGE_ERR) => Err(TxFailure::Storage(ViewError::inconsistent(e))),
        Err(e) => Err(TxFailure::witness(e)),
    }
}

/// BIP30 (audit VAL-2) for one transaction of a block subject to the
/// hardening rules: none of `tx`'s outputs may have the outpoint of a coin
/// that is unspent in `view` (the parent's state). The block path checks every
/// transaction of the block, the coinbase included, before validating any;
/// [`validate_tx_in_block_with_maturity`] checks the transaction it validates.
fn check_no_unspent_overwrite(view: &dyn UtxoView, tx: &core::Transaction) -> Result<(), TxFailure> {
    let txid = tx.txid();
    for j in 0..tx.outputs.len() as u32 {
        if view.view_utxo(&txid, j)?.is_some() {
            return Err(format!(
                "BIP30: output {}:{} would overwrite an unspent coin",
                hex::encode(&txid[..8]), j
            ).into());
        }
    }
    Ok(())
}

/// Full in-context validation of a block's transactions against `view` (the
/// UTXO state of its selected parent): every non-coinbase transaction (inputs
/// exist, no double spend, maturity, scripts, value, minimum fee) and the
/// coinbase value against subsidy + fees. The rules are exactly the ones the
/// pre-fix `accept_block` applied to an extension block; the difference is
/// only WHICH state a block is checked against (its own, never the tip's).
///
/// Two passes (re-audit B1-T13, like Bitcoin Core's `ConnectBlock`, which
/// runs `CheckTxInputs` for every transaction and leaves the scripts to the
/// check queue): first the checks that depend only on data the block id
/// commits to, for EVERY transaction and then the coinbase value; then the
/// witness checks (the policy-spend rules, the scripts, the size-based
/// minimum fee) of every transaction. The verdict is the same in any order (every rule must
/// pass); the order decides the reported failure and so its class: an
/// id-committed failure anywhere in the block is reported as such, never
/// hidden behind an earlier witness failure. It also runs no signature
/// check for a block that fails a cheap rule.
///
/// THE shared connect-time rule: the acceptance pipeline calls it for an
/// extension and for every block of a reorg (`reorg::connect_plan`), under
/// the process-wide hardening activation height (see
/// [`validate_block_in_view_at`] for the rules that change there). The
/// pipeline itself calls the classified variant
/// ([`validate_block_in_view_classified`], same verdict); this unclassified
/// form is library API (tests), unused by the `gnb` binary, which compiles
/// this file as its own module.
#[allow(dead_code)]
pub fn validate_block_in_view(view: &dyn UtxoView, block: &core::Block) -> Result<(), String> {
    validate_block_in_view_at(view, block, core::activation::hardening_activation_height())
}

/// [`validate_block_in_view`] for an explicit activation height. At every
/// height (this chain's rules since before the 2026-10-14 reset; the
/// audit's VAL-2 / VAL-3 at the activation):
///
/// * **BIP30**: no output of the block may have the outpoint of a coin that
///   is unspent in `view` (the parent's state), checked for every
///   transaction, the coinbase included, before any transaction is validated;
/// * **no same-block coinbase spend**: the coinbase's outputs are not in the
///   in-block prevout map, and an input spending them is rejected as a
///   coinbase-maturity violation;
/// * this chain's transaction rules (`blockval`): locktime finality, the two
///   output kinds and dust (the coinbase's too), the policy-spend timelocks.
///
/// What changes at the activation: the transaction rules (version 3 /
/// sighash v3 / canonical witnesses, `core::sighash`), evaluated at the same
/// height (`block.height`) under the same `activation_height`
/// (`admission::verify_input_scripts_at`), and the depth measure of coinbase
/// maturity and relative timelocks ([`MaturityRule`]: header heights below,
/// selected-chain depth from it, re-audit B1-T14). Library API like
/// [`validate_block_in_view`] (unused by the `gnb` binary).
#[allow(dead_code)]
pub fn validate_block_in_view_at(
    view: &dyn UtxoView,
    block: &core::Block,
    activation_height: u64,
) -> Result<(), String> {
    validate_block_in_view_classified_at(view, block, activation_height).map_err(ConnectFailure::into_message)
}

/// [`validate_block_in_view`] with the failure classified (see
/// [`BlockInvalidity`]): the acceptance pipeline uses the class to decide
/// whether the block id is disqualified (persisted) or only this body is
/// dropped, and a read failure of the view ([`ConnectFailure::Storage`]) is
/// no verdict at all. The verdict (`Ok` / `Err`) is exactly
/// `validate_block_in_view`'s. The pipeline itself calls
/// [`validate_block_in_view_classified_with`] (the assumed-valid block's
/// script mode, P5-G); this full-check form is library API
/// (`blockval::validate_block_transactions`, tests).
#[allow(dead_code)] // library API; the node binary compiles this module too
pub fn validate_block_in_view_classified(view: &dyn UtxoView, block: &core::Block) -> Result<(), ConnectFailure> {
    validate_block_in_view_classified_at(view, block, core::activation::hardening_activation_height())
}

/// [`validate_block_in_view_classified`] for an explicit activation height.
pub fn validate_block_in_view_classified_at(
    view: &dyn UtxoView,
    block: &core::Block,
    activation_height: u64,
) -> Result<(), ConnectFailure> {
    validate_block_in_view_classified_with(view, block, activation_height, ScriptChecks::Full)
}

/// [`validate_block_in_view_classified_at`] with the input scripts checked
/// as `scripts` says. [`ScriptChecks::SignaturesAssumed`] (the connect path,
/// for a block the assumed-valid block vouches for, `crate::assumevalid`,
/// Bitcoin Core's `-assumevalid`) leaves out the signature verification of
/// every input and nothing else: the version rule, every witness check
/// (framing, public key hash, policy hash), the policy timelocks, the
/// size-based minimum fee and every id-committed rule run as always. It
/// applies only where the block id commits to every witness byte
/// ([`witnesses_fixed_at`]): below that, a relay can swap `script_sig` bytes
/// without changing the id, so the body held need not be the one the
/// assumed-valid chain was validated with, and the block is checked in full.
/// A valid block gets the same verdict either way.
pub fn validate_block_in_view_classified_with(
    view: &dyn UtxoView,
    block: &core::Block,
    activation_height: u64,
    scripts: ScriptChecks,
) -> Result<(), ConnectFailure> {
    let committed = |reason: String| ConnectFailure::Invalid(BlockInvalidity { reason, witness_dependent: false });
    let height = block.height;
    let hardened = core::block_rules::rules_active_at(height, activation_height);
    let witnesses_fixed = witnesses_fixed_at(height, activation_height);
    let scripts = if witnesses_fixed { scripts } else { ScriptChecks::Full };
    // BIP30 and no spend of the block's own coinbase: this chain's rules from
    // genesis (the audit's VAL-2 / VAL-3 at the activation), so at every
    // height here. A read failure of the view is no verdict (B1-T12).
    for tx in &block.transactions {
        check_no_unspent_overwrite(view, tx).map_err(|f| f.into_connect(witnesses_fixed))?;
    }
    if let Some(cb) = block.transactions.first() {
        crate::blockval::check_tx_context_free(cb, height)
            .map_err(|e| committed(format!("coinbase rejected: {}", e)))?;
    }
    let same_block_coinbase = block.transactions.first().map(|cb| cb.txid());
    let mut spent_in_block: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut earlier: HashMap<([u8; 32], u32), core::TxOutput> = HashMap::new();
    let mut total_fees: u64 = 0;
    // Coinbase maturity (re-audit B1-T14): header heights below the
    // activation, selected-chain depth from it (the block's DAG height read
    // once, and only if a transaction spends a coinbase).
    let spend_dag = std::cell::OnceCell::new();
    let spend_dag_height = || -> Result<u64, ViewError> {
        if let Some(h) = spend_dag.get() {
            return Ok(*h);
        }
        let h = block_dag_height(view, block)?;
        Ok(*spend_dag.get_or_init(|| h))
    };
    let maturity = if hardened {
        MaturityRule::SelectedChainDepth(&spend_dag_height)
    } else {
        MaturityRule::HeaderHeights(height)
    };
    // Pass 1: the id-committed checks of every transaction, then the
    // coinbase value (the fees are id-committed: input and output values).
    let mut checked: Vec<(&core::Transaction, CommittedTx)> = Vec::with_capacity(block.transactions.len());
    for (i, tx) in block.transactions.iter().enumerate() {
        if i > 0 {
            let c = check_tx_in_view_committed(
                tx, view, &earlier, &mut spent_in_block, height, maturity, same_block_coinbase.as_ref(),
                activation_height,
            ).map_err(|f| f.into_connect(witnesses_fixed))?;
            total_fees = core::limits::money_add(total_fees, c.fee)
                .map_err(|e| committed(format!("block fee sum: {}", e)))?;
            checked.push((tx, c));
        }
        if i == 0 {
            continue; // VAL-3: the coinbase's outputs are not spendable in its own block
        }
        let txid = tx.txid();
        for (j, o) in tx.outputs.iter().enumerate() {
            earlier.insert((txid, j as u32), o.clone());
        }
    }
    block.validate_coinbase_value(total_fees)
        .map_err(|e| committed(format!("coinbase rejected: {}", e)))?;
    // Pass 2: the witness checks, in block order: the policy spends (their
    // relative timelocks counted under the block's maturity measure), then
    // the scripts and the size-based minimum fee.
    for (tx, c) in &checked {
        check_tx_policy_spends(tx, c, height, view, maturity).map_err(|f| f.into_connect(witnesses_fixed))?;
        check_tx_witnesses(tx, c, height, activation_height, scripts).map_err(|f| f.into_connect(witnesses_fixed))?;
    }
    Ok(())
}

// ── Shielded state (COH-2) ───────────────────────────────────────────────────
//
// The shielded pool moves with the applied chain: `ShieldedPool::stage_plan`
// moves it in memory along the plan (no clone: in-place apply/undo with an
// exact revert journal) and returns its writes, which `stage_extra` folds into
// the plan's WriteBatch; after the commit the staged plan is committed, on
// any failure it is reverted. The shielded lock is taken only for those short
// steps (acceptance is serialized by the acceptance lock, and the pipeline is
// the only user of the pool).
//
// Rolled-back blocks whose body was pruned (audit DAG-6) are disconnected from
// the shielded undo record (never pruned); whether they carried shielded
// transactions comes from the record written when their body was pruned
// (`storage::PrunedBodyRecord::had_shielded`), see `ShieldedPool::stage_plan`.

// ── Mempool maintenance after a connect (MEM-3, MEM-7) ──────────────────────

/// Bring the mempool in line with a committed chain move: drop confirmed txs
/// and every tx conflicting with an outpoint the connected blocks spent;
/// after a reorg re-admit the disconnected txs through the shared admission
/// function (only those of blocks whose body is stored: a block rolled back
/// from its undo record alone, body pruned, has none to re-admit) and
/// re-validate the whole pool against the new UTXO set; clear
/// the recent-rejects filter (the tip changed) and expire stale entries.
///
/// `next_height` is the node's next template height on the DAG AFTER the
/// move (`template::next_template_height`, the value `accept_block` passes):
/// the ONE height admission, eviction, re-injection, templates and wallets
/// use. It is NOT the new tip's header height + 1: a tip that merged a
/// parent with a greater DAG height than its selected parent has a header
/// height above its DAG height (DAG-8), while a child of that tip alone sits
/// at its DAG height + 1, so the header height would evict transactions that
/// are still valid for the next block. It is recorded in
/// `Mempool::next_height` first, so concurrent admissions re-check against it.
/// Call under the acceptance lock.
pub fn update_mempool_after_connect(
    store: &storage::Storage,
    mempool: &mempool::Mempool,
    outcome: &ConnectOutcome,
    next_height: u64,
) {
    let previous = mempool.set_next_height(next_height);
    // B2-T0: the outcome lists hashes; each connected body is read, applied
    // to the pool and dropped (one body in memory at a time).
    let mut swept = 0usize;
    for h in &outcome.connected {
        let block = match store.get_block(h) {
            Ok(Some(b)) => b,
            other => {
                warn!("mempool: body of connected block {} unreadable ({:?}); its confirmed transactions \
                       stay pooled until the next revalidation", hex::encode(&h[..8]), other.err());
                continue;
            }
        };
        let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
        mempool.remove_confirmed(&confirmed);
        let spent: Vec<([u8; 32], u32)> = block.transactions.iter()
            .filter(|t| !t.is_coinbase())
            .flat_map(|t| t.inputs.iter().map(|i| (i.prev_txid, i.prev_index)))
            .collect();
        swept += mempool.remove_conflicts(&spent).len();
    }
    if swept > 0 {
        info!("mempool: removed {} tx(s) conflicting with the connected block(s)", swept);
    }
    // CRY-3 activation: after EVERY connect (extension or reorg) drop pooled
    // transactions whose version is invalid or non-standard for the next
    // block (version 1/2 once the next block is at/after the hardening
    // activation; version >= 3 after a reorg back below it). Cheap: no I/O,
    // no signatures.
    // When the next height went DOWN on an extension (the new tip merged the
    // tip that set the old, higher template height), maturity can also be
    // lost: run the full signature-free revalidation instead (a reorg runs it
    // below anyway).
    if !outcome.connected.is_empty() {
        let lower = previous != 0 && next_height < previous && outcome.rolled_back() == 0;
        let stale = if lower {
            revalidate_mempool(store, mempool, next_height)
        } else {
            evict_version_invalid(mempool, next_height)
        };
        if stale > 0 {
            info!("mempool: evicted {} tx(s) no longer valid for the next block at height {}", stale, next_height);
        }
    }
    // Any rollback — also a pure one (operator `invalidateblock`, DAG-6) and
    // one through pruned bodies, whose transactions cannot be re-admitted —
    // re-validates the pool against the new UTXO set.
    if outcome.rolled_back() > 0 {
        // Oldest disconnected block first: a child confirmed after its parent
        // is re-admitted after it, as an in-pool chain (MEM-6). At most
        // Core's 20 MB of them (B1-T20): the most recently confirmed are the
        // ones left out, so no kept transaction misses a parent.
        let candidates = outcome.reinjection_candidates(store, reorg::MAX_DISCONNECTED_TX_POOL_BYTES);
        if candidates.truncated {
            warn!("reorg: only the first {} bytes of the disconnected blocks' transactions are re-admitted \
                   (Bitcoin Core's DisconnectedBlockTransactions budget); the rest must be rebroadcast",
                candidates.bytes);
        }
        let (re, dropped) = reorg::reinject_disconnected(store, mempool, candidates.txs, next_height);
        let stale = revalidate_mempool(store, mempool, next_height);
        info!("reorg: mempool reinjected={} discarded={} invalidated={}", re, dropped, stale);
        if !outcome.disconnected_pruned.is_empty() {
            // Rolled back from their undo records alone (docs/MEMPOOL.md §6).
            warn!("reorg: {} disconnected block(s) had pruned bodies; their transactions cannot be \
                   re-admitted to the mempool and must be rebroadcast by their senders",
                outcome.disconnected_pruned.len());
        }
    }
    mempool.clear_recent_rejects();
    let expired = mempool.expire_older_than(mempool::MEMPOOL_EXPIRY_SECS);
    if expired > 0 {
        info!("mempool: expired {} tx(s) older than {} s", expired, mempool::MEMPOOL_EXPIRY_SECS);
    }
}

/// Drop every pooled tx whose version the consensus rule or the version policy
/// rejects for a block at `next_height`, or that the 64-byte rule forbids
/// there (`admission::check_tx_for_next_block`). Returns how many were
/// removed.
pub fn evict_version_invalid(mempool: &mempool::Mempool, next_height: u64) -> usize {
    mempool.retain_valid(|e| admission::check_tx_for_next_block(&e.tx, next_height).is_ok())
}

/// MEM-3: drop every pooled tx that is no longer minable on the current
/// UTXO set (an input missing, an immature coinbase input at `next_height`,
/// a fee below the consensus minimum, a version invalid or non-standard at
/// `next_height`, or a 64-byte txid preimage at/after the activation:
/// `admission::check_tx_for_next_block`). An input may also be an output of
/// another pooled tx (MEM-6 chains); a tx that fails is removed together
/// with its in-pool descendants. Signature-free and cheap. Returns how many
/// were removed.
pub fn revalidate_mempool(store: &storage::Storage, mempool: &mempool::Mempool, next_height: u64) -> usize {
    mempool.retain_valid_with(|e, pool_output| {
        if admission::check_tx_for_next_block(&e.tx, next_height).is_err() {
            return false;
        }
        let mut total_in: u64 = 0;
        let mut prevouts = Vec::with_capacity(e.tx.inputs.len());
        for inp in &e.tx.inputs {
            let prev = match store.get_utxo(&inp.prev_txid, inp.prev_index) {
                Ok(Some(o)) => Some(o),
                Ok(None) => pool_output(&inp.prev_txid, inp.prev_index),
                Err(_) => None,
            };
            match prev {
                Some(o) => match core::limits::money_add(total_in, o.value) {
                    Ok(t) => {
                        total_in = t;
                        prevouts.push(o);
                    }
                    Err(_) => return false,
                },
                None => return false,
            }
        }
        // Immature, or a height that cannot be read (never "not a
        // coinbase", re-audit B1-T12): not minable now.
        if !matches!(admission::coinbase_maturity_for_next_block(store, &e.tx, next_height), Ok(Ok(()))) {
            return false;
        }
        match core::limits::check_tx_money_range(&e.tx) {
            Ok(out) if out <= total_in => core::check_min_fee(&e.tx, total_in - out, &prevouts).is_ok(),
            _ => false,
        }
    })
}

/// Keep `Mempool::next_height` equal to the node's next template height after
/// a DAG change that connected nothing (a fork-loser or merge candidate
/// stored, a block disqualified): a new tip with a greater DAG height, or a
/// disqualified one, moves the template height without moving the applied
/// tip. When the height moved, clear the recent-rejects filter (its verdicts
/// were computed for the old height), drop the transactions whose version is
/// invalid or non-standard at the new height and, when it went down, the ones
/// no longer mature (`revalidate_mempool`). Call under the acceptance lock (or
/// at start-up before any concurrent acceptance). Returns the height.
pub fn sync_mempool_next_height(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    mempool: &mempool::Mempool,
) -> u64 {
    let next = crate::template::next_template_height(&dag.read(), store);
    let previous = mempool.set_next_height(next);
    if previous != next {
        // Review finding: the recent-rejects filter holds verdicts computed
        // for the previous next height (the version rule and policy, the
        // 64-byte rule, coinbase maturity). Without a tip change nothing else
        // clears it, so a transaction refused for H-1 stayed "recently
        // rejected" at H (RPC and gossip) until the next tip change.
        mempool.clear_recent_rejects();
    }
    if previous != 0 && previous != next {
        let dropped = if next < previous {
            revalidate_mempool(store, mempool, next)
        } else {
            evict_version_invalid(mempool, next)
        };
        if dropped > 0 {
            info!("mempool: next block height {} -> {}: evicted {} tx(s) no longer valid for it",
                previous, next, dropped);
        }
    }
    next
}

// ── The pipeline ─────────────────────────────────────────────────────────────

/// Outcome of resolving the best valid chain after a DAG change.
enum Resolution {
    /// Nothing was committed: the applied tip did not move (fork-loser,
    /// merged-only, or every better candidate turned out invalid).
    Unchanged,
    /// At least one chunk of a chain move was committed (audit B2-T0: moves
    /// commit in chunks of `reorg::MAX_BLOCKS_PER_COMMIT` blocks). `outcome`
    /// is the NET effect of every committed chunk (it can be empty when the
    /// move went forward and back, e.g. a block of a new branch turned out
    /// invalid). `stopped` is set when a storage / missing-data failure
    /// stopped the move before the best valid block: the applied tip is then
    /// a consistent intermediate block of the move (tip pointer, UTXO set,
    /// undo records, shielded tip and DAG records were committed together),
    /// from which the next acceptance or start-up reconciliation resumes.
    Connected { outcome: ConnectOutcome, stopped: Option<String> },
}

/// Where `resolve_best_chain` records what it found on the way.
#[derive(Default)]
struct ResolveLog {
    /// (root, reason) for every newly disqualified root (persisted).
    invalid: Vec<(BlockHash, String)>,
    /// (block, reason) for every block whose body was dropped after a
    /// witness-dependent failure (never persisted; see `drop_body_and_wait`).
    body_rejected: Vec<(BlockHash, String)>,
}

/// What `resolve_best_chain` does when the plan to the best candidate must
/// APPLY blocks whose body is not stored (dropped after a witness-dependent
/// failure, or pruned and since reorganized away from, audit DAG-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingBodies {
    /// Acceptance and start-up: every such block waits for a body
    /// (`GhostDAG::mark_body_pending`, in memory only: the one record of
    /// "a body of this DAG block is wanted", see [`awaits_body`]), the
    /// processor requests them, and the next-best chain is tried meanwhile.
    Wait,
    /// Operator overrides: stop with [`reorg::ERR_MISSING_BODIES`] before
    /// anything of that plan is committed (the caller names the bodies and
    /// asks for a retry once they are restored).
    Stop,
}

/// Persisted disqualification marks an operator `reconsiderblock` removes
/// (audit DAG-6), committed in the same batch as the chain move.
#[derive(Default)]
struct MarkClears {
    /// Removed in any case (operator marks, marks inherited from a selected
    /// parent, hardening-recheck marks whose stored body now passes).
    always: Vec<BlockHash>,
    /// Marks of genuine connect-time consensus failures: removed only by the
    /// batch that RE-VALIDATES the block (it is in a committed chunk's
    /// `to_apply`, every block of which `connect_plan` validated in its own
    /// context; `resolve_best_chain` lifts the consensus mark of every such
    /// block). A block the move does not apply keeps its mark, also in memory
    /// ([`remark_unvalidated`]).
    if_applied: Vec<BlockHash>,
}

/// The block whose insertion prompted a resolution (a new block, not a body
/// replacement). Its DAG record and, from the PoWit activation, the
/// in-context PoWit state computed before it was stored
/// (`powit::block_state`) go into the FIRST batch that commits: the first
/// chunk of the chain move (`commit_chunk`), or `persist_unchanged` when the
/// applied chain does not move. A block is never recorded without its PoWit
/// state (its children's state builds on it, `powit::base_state`), and a
/// block refused before that commit leaves neither behind.
#[derive(Clone, Copy)]
struct TriggerRecord<'a> {
    hash: BlockHash,
    powit: Option<&'a core::powit::PowitState>,
}

/// Stage `t`'s DAG record, the pending reachability delta and its PoWit
/// state (if it is still in the DAG). Returns the staged reachability delta
/// (`None` when nothing was staged): the caller clears it with
/// [`reach_committed`] only once the batch has committed (audit DAG-11), so
/// a chunk that fails to commit leaves it pending.
fn stage_trigger_record(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    batch: &mut rocksdb::WriteBatch,
    t: &TriggerRecord<'_>,
) -> Result<Option<ReachDelta>, String> {
    if !dag.read().has_block(&t.hash) {
        return Ok(None);
    }
    let delta = stage_dag_record_for(dag, store, batch, &t.hash)?;
    if let Some(st) = t.powit {
        let sp = dag.read().get_block_data(&t.hash).and_then(|d| d.selected_parent);
        crate::powit::stage_state(store, batch, &t.hash, sp.as_ref(), st)?;
    }
    Ok(Some(delta))
}

/// Why one chunk of a chain move did not commit (nothing of it was written).
enum ChunkFailure {
    /// A block of the chunk is invalid in its own context; `witness` = the
    /// failure depends on witness bytes its id does not commit to (the body
    /// is wrong, not the block), with the body's witness root.
    Invalid { block: BlockHash, reason: String, witness: Option<[u8; 32]> },
    /// Storage / missing-data failure. `no_verdict`: the block whose
    /// validation could not be completed (a read failure of the view, no
    /// verdict, re-audit B1-T12; or a body that could not be read, review of
    /// PR #15, finding 6) and the class of that failure, when that is what
    /// failed.
    Failed { reason: String, no_verdict: Option<(BlockHash, ViewErrorKind)> },
    /// The stored body of `block`, a block of the chunk to apply, does not
    /// decode (review of PR #15, finding 6). No verdict: the body is dropped
    /// and fetched again ([`drop_undecodable_body`]).
    Undecodable { block: BlockHash, reason: String },
}

impl ChunkFailure {
    fn failed(reason: String) -> Self {
        ChunkFailure::Failed { reason, no_verdict: None }
    }

    /// Review of PR #15, finding 6: a body read failure of `sub`, attributed
    /// to the block whose judgement it prevents, so it is never a silent
    /// stall. A block to APPLY: an engine error is a no-verdict of the
    /// block (`ViewErrorKind::Io`: parked, counted toward the stop), a body
    /// that does not decode is dropped and fetched again
    /// ([`ChunkFailure::Undecodable`]). A block to ROLL BACK: the first block
    /// the chunk applies cannot be judged without that rollback, so the
    /// failure is that block's no-verdict, of the same class (the deepest
    /// rollbacks share their chunk with the first apply blocks,
    /// `ReorgPlan::chunks_with_rollback_tail`); a chunk that only rolls back
    /// has no block to attribute it to.
    fn body_unreadable(sub: &reorg::ReorgPlan, block: BlockHash, applying: bool, error: ViewError) -> Self {
        let reason = ConnectError::BodyUnreadable { block, applying, error: error.clone() }.to_string();
        match (applying, error.kind) {
            (true, ViewErrorKind::Inconsistent) => ChunkFailure::Undecodable { block, reason },
            (true, kind) => ChunkFailure::Failed { reason, no_verdict: Some((block, kind)) },
            (false, kind) => ChunkFailure::Failed { reason, no_verdict: sub.to_apply.first().map(|b| (*b, kind)) },
        }
    }
}

/// Audit F1: how many validations in a row of one block may end on a
/// storage-engine failure ([`ViewErrorKind::Io`]) before the node stops
/// ([`note_no_verdict`]).
pub const NO_VERDICT_ABORT_AFTER: u32 = 3;

/// The operator message of the stop (review of audit F1, finding 4): it
/// names the recovery that works. The start-up rebuild of the chain state
/// (`rebuild_chain_state`) only runs when `check_chain_state` finds the
/// footprint of an interrupted commit, so a restart with
/// `--carryover-snapshot` repairs nothing here; a node whose storage engine
/// keeps failing is resynchronized (docs/RUNNING.md, "Blocks without a verdict").
pub fn no_verdict_abort_message(block: &BlockHash, failures: u32, reason: &str) -> String {
    format!(
        "block {} could not be validated {} times in a row because the storage engine failed ({}). \
         This is not a verdict on the block (nothing is marked invalid): the node cannot read its own \
         chain state. Stopping the node instead of running on it. Check the disk (free space, \
         permissions, I/O errors in the system log), then restart; if the failure persists, the data \
         directory is damaged: stop the node and resynchronize into a fresh, empty --data-dir (or start \
         from a copy of an archival node's data directory)",
        hex::encode(block), failures, reason)
}

/// Audit F1 (and its review, findings 1 and 2): `block`'s validation ended
/// without a verdict (`kind`, `reason`). A read failure is never a verdict
/// (re-audit B1-T12): nothing is marked or persisted, and the block keeps
/// its body. It is PARKED (`GhostDAG::park_no_verdict`, in memory, with its
/// selected-chain descendants) so the node selects, connects and mines on
/// the best chain it can judge, and it is retried on a bounded schedule
/// (`Storage::note_no_verdict`: 1 minute doubling up to 1 hour;
/// [`unpark_due_no_verdicts`]). Only a storage-engine failure
/// ([`ViewErrorKind::Io`]: a RocksDB read/write error, a missing column
/// family) counts toward the stop: [`NO_VERDICT_ABORT_AFTER`] in a row stop
/// the node, like Bitcoin Core's `AbortNode` / `FatalError`
/// (`Storage::abort_node`: acceptance and templates refuse, the `gnb`
/// binary exits with [`no_verdict_abort_message`]). An inconsistent index
/// ([`ViewErrorKind::Inconsistent`]: a row an invariant requires is absent,
/// or a row does not decode) never does: if such a miss ever became
/// reachable from block data, one block would stop every node that receives
/// it. It is logged loudly (rate-limited) and shown by `getdaginfo`
/// (`no_verdict`). The record is cleared when the block is validated.
fn note_no_verdict(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    block: &BlockHash,
    kind: ViewErrorKind,
    reason: &str,
) {
    let now = std::time::Instant::now();
    let rec = store.note_no_verdict(block, kind == ViewErrorKind::Io, reason, now);
    let parked = dag.write().park_no_verdict(*block);
    let retry = rec.retry_at.saturating_duration_since(now).as_secs();
    match kind {
        ViewErrorKind::Io if rec.io_failures >= NO_VERDICT_ABORT_AFTER => {
            let msg = no_verdict_abort_message(block, rec.io_failures, reason);
            error!("FATAL: {}", msg);
            store.abort_node(msg);
        }
        ViewErrorKind::Io => warn!(
            "block {} could not be validated: the storage engine failed (no verdict, attempt {} of {} \
             before the node stops): {}; parked with {} selected-chain descendant(s), retried in {} s",
            hex::encode(&block[..8]), rec.io_failures, NO_VERDICT_ABORT_AFTER, reason,
            parked.len().saturating_sub(1), retry),
        ViewErrorKind::Inconsistent => match store.no_verdict_log_permit(now) {
            Some(suppressed) => error!(
                "block {} could not be validated: the local chain state is INCONSISTENT ({}). No verdict: \
                 the block is NOT marked invalid and keeps its body; it is parked with {} selected-chain \
                 descendant(s) and retried in {} s (attempt {}), and the node follows the best chain it can \
                 judge meanwhile. A node on a consistent index never gets here: report it, and see \
                 `getdaginfo` (no_verdict){}",
                hex::encode(&block[..8]), reason, parked.len().saturating_sub(1), retry, rec.attempts,
                if suppressed > 0 { format!(" ({suppressed} similar line(s) suppressed)") } else { String::new() }),
            None => debug!("block {} could not be validated (inconsistent chain state, attempt {}): {}",
                hex::encode(&block[..8]), rec.attempts, reason),
        },
    }
}

/// Review of audit F1, finding 2: unpark every block parked without a
/// verdict whose retry is due at `now` (`Storage::no_verdict_due`), so the
/// next resolution validates it again, re-deriving the disqualified set once
/// for all of them (review of PR #15, finding 1). The acceptance pipeline
/// calls it right before its resolution (the node's own blocks included, so
/// a parked block is retried while the node mines on the chain it can
/// judge) and parks them again ([`repark_no_verdicts`]) if that resolution
/// fails before judging them. Returns the blocks unparked.
pub fn unpark_due_no_verdicts(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    now: std::time::Instant,
) -> Vec<BlockHash> {
    let parked = dag.read().no_verdict_parked();
    let due: Vec<BlockHash> = parked.into_iter().filter(|h| store.no_verdict_due(h, now)).collect();
    if !due.is_empty() {
        dag.write().unpark_no_verdicts(&due);
        info!("retrying {} block(s) parked without a verdict (first {})", due.len(), hex::encode(&due[0][..8]));
    }
    due
}

/// Review of PR #15, finding 1: park `due` (unparked by
/// [`unpark_due_no_verdicts`] for a resolution that then failed before
/// judging them) again, so the DAG never selects a branch nobody validated
/// while the applied tip stays where it is (templates would be refused).
/// Their records are kept, still due: the next acceptance retries them. A
/// block whose record is gone (it reached a verdict) stays unparked.
fn repark_no_verdicts(dag: &Arc<RwLock<consensus::GhostDAG>>, store: &storage::Storage, due: &[BlockHash]) {
    let mut d = dag.write();
    for h in due {
        if !d.is_no_verdict_parked(h) && store.no_verdict_record(h).is_some() {
            d.park_no_verdict(*h);
        }
    }
}

/// Review of PR #15, finding 2: the operator warning while a branch parked
/// without a verdict has more chain work than the applied tip. The node then
/// follows, mines and serves templates on a chain it knows is not the
/// heaviest, because it could not judge a block of the heavier one; the IBD
/// latch counts that branch as servable (the node does not claim to be
/// synced), and `getblocktemplate`, `getdaginfo` and `getnetworkinfo` carry
/// this text in `warnings` (Bitcoin Core's `GetWarnings`). The node never
/// stops for it: only repeated storage-engine failures stop it
/// ([`note_no_verdict`]), so no peer can stop a node with a block.
pub fn no_verdict_branch_warning(d: &consensus::GhostDAG, store: &storage::Storage) -> Option<String> {
    let (best, root) = d.best_no_verdict_branch()?;
    let best_work = d.get_block_data(&best)?.blue_work;
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .filter(|t| d.has_block(t))
        .or_else(|| d.selected_tip())?;
    let applied_work = d.get_block_data(&applied).map_or(0, |x| x.blue_work);
    if best_work <= applied_work {
        return None;
    }
    let (class, reason, retry) = match store.no_verdict_record(&root) {
        Some(r) => (
            if r.last_io { "the storage engine failed" } else { "inconsistent chain state" },
            r.reason,
            r.retry_at.saturating_duration_since(std::time::Instant::now()).as_secs(),
        ),
        None => ("no verdict", String::new(), 0),
    };
    Some(format!(
        "a branch with more chain work than the applied tip is parked without a verdict: block {} could not \
         be validated ({}: {}); the node follows and mines on the lighter chain it can judge (applied tip {}, \
         heaviest parked block {}) and retries it in {} s. See getdaginfo no_verdict and docs/RUNNING.md \
         (\"Blocks without a verdict\")",
        hex::encode(&root[..8]), class, reason, hex::encode(&applied[..8]), hex::encode(&best[..8]), retry))
}

/// Commit ONE chunk (`sub`, at most `reorg::MAX_BLOCKS_PER_COMMIT` blocks)
/// of a chain move in one atomic batch: its UTXO effects, undo records and
/// chain indexes keyed by chain position (`reorg::connect_plan`, audit
/// DAG-8), its shielded state (COH-2), the tip pointer at the chunk's end,
/// the persisted marks of `log_invalid`, the removal of the marks of every
/// block it applies, and — when given — the trigger's DAG record with the
/// pending reachability delta and its PoWit state ([`TriggerRecord`]) and
/// the operator's `clears_always`. The reachability delta leaves the
/// in-memory pending set only once this batch has committed (audit DAG-11).
fn commit_chunk(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    shielded: &Arc<RwLock<ShieldedPool>>,
    sub: &reorg::ReorgPlan,
    trigger: Option<TriggerRecord<'_>>,
    clears_always: &[BlockHash],
    log_invalid: &[(BlockHash, String)],
) -> Result<ConnectOutcome, ChunkFailure> {
    let staged_shielded = match shielded.write().stage_plan(store, sub) {
        Ok(s) => s,
        // The shielded bytes are committed by the header root.
        Err(ConnectError::Invalid { block, reason, .. }) => {
            return Err(ChunkFailure::Invalid { block, reason, witness: None });
        }
        Err(ConnectError::BodyUnreadable { block, applying, error }) => {
            return Err(ChunkFailure::body_unreadable(sub, block, applying, error));
        }
        Err(e) => return Err(ChunkFailure::failed(e.to_string())),
    };

    // The assumed-valid block (Bitcoin Core's `-assumevalid`, P5-G): the
    // blocks of this chunk whose signature checks are skipped, decided once
    // with Core's conditions on the DAG as it stands (the assumed-valid
    // block's header in the DAG, each block on its selected chain and on the
    // best block's, the best block at the minimum chain work and two weeks
    // of proof-equivalent time above the block; `crate::assumevalid`). One
    // hash lookup without an assumed-valid block or while its header is
    // unknown.
    let assumed = crate::assumevalid::assumed_valid_blocks(&dag.read(), &sub.to_apply);
    if !assumed.is_empty() {
        info!("connecting {} block(s) with their signatures assumed valid (ancestors of the assumed-valid block)",
            assumed.len());
    }
    // The validator reports, beside the verdict, whether the failure
    // depends on witness bytes (block id, witness root of the body).
    let witness_failure: std::cell::Cell<Option<(BlockHash, [u8; 32])>> = std::cell::Cell::new(None);
    let no_verdict: std::cell::Cell<Option<(BlockHash, ViewErrorKind)>> = std::cell::Cell::new(None);
    let validate = |view: &dyn UtxoView, b: &core::Block| -> Result<(), ValidationFailure> {
        let scripts = if !assumed.is_empty() && assumed.contains(&b.block_hash()) {
            ScriptChecks::SignaturesAssumed
        } else {
            ScriptChecks::Full
        };
        match validate_block_in_view_classified_with(view, b, core::activation::hardening_activation_height(), scripts) {
            Ok(()) => Ok(()),
            Err(ConnectFailure::Invalid(e)) => {
                witness_failure.set(e.witness_dependent.then(|| {
                    (b.block_hash(), core::block_rules::body_commitment_root(&b).0)
                }));
                Err(ValidationFailure::Invalid(e.reason))
            }
            // No verdict (re-audit B1-T12): `connect_plan` fails the chunk
            // as a storage failure (`ChunkFailure::Failed`): nothing of it is
            // written or marked. `resolve_best_chain` parks the block and
            // goes on with the best chain it can judge (audit F1,
            // [`note_no_verdict`]).
            Err(ConnectFailure::Storage(e)) => {
                witness_failure.set(None);
                no_verdict.set(Some((b.block_hash(), e.kind)));
                Err(ValidationFailure::Storage(e.msg))
            }
        }
    };
    let new_tip = sub.target();
    // The reachability delta staged with the trigger's DAG record, cleared
    // only once THIS chunk's batch has committed (audit DAG-11): a chunk
    // that fails leaves it pending for the next committed DAG record.
    let staged_reach: std::cell::RefCell<Option<ReachDelta>> = std::cell::RefCell::new(None);
    let stage_extra = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
        if let Some(t) = &trigger {
            *staged_reach.borrow_mut() = stage_trigger_record(dag, st, batch, t)?;
        }
        // Operator `reconsiderblock`: the marks it removes in any case.
        for h in clears_always {
            st.stage_clear_invalid_block(batch, h).map_err(|e| e.to_string())?;
        }
        // A consensus (or inherited) mark goes with the batch that
        // RE-VALIDATED its block: `connect_plan` validated every block of
        // `to_apply` in its own context before this runs. This covers the
        // `reconsiderblock` marks (`clears.if_applied`) and any stale mark
        // whose block connects through an ordinary acceptance, so an
        // applied block never keeps a mark that would disqualify it again
        // at the next restart.
        for h in &sub.to_apply {
            if let Some(reason) = st.invalid_block_reason(h).map_err(|e| e.to_string())? {
                match mark_kind(&reason) {
                    MarkKind::Consensus | MarkKind::Inherited => {
                        st.stage_clear_invalid_block(batch, h).map_err(|e| e.to_string())?;
                    }
                    // Never lifted by a connect: only `reconsiderblock`
                    // removes these (it re-checks a hardening mark).
                    kind @ (MarkKind::Operator | MarkKind::Hardening) => warn!(
                        "block {} connects although it carries a persisted {:?} mark ({}); \
                         the mark is kept", hex::encode(&h[..8]), kind, reason),
                }
            }
        }
        stage_invalid_marks(dag, st, batch, log_invalid)?;
        // COH-2: the shielded state of the chunk, in the same batch.
        staged_shielded.stage_into(st, batch)?;
        st.stage_meta(batch, "tip_hash", &new_tip).map_err(|e| e.to_string())
    };
    let hooks = ConnectHooks { validate: &validate, stage_extra: &stage_extra };
    let result = reorg::connect_plan(store, sub, &hooks);
    match &result {
        Ok(_) => {
            shielded.write().commit_staged(staged_shielded);
            if let Some(delta) = staged_reach.borrow_mut().take() {
                reach_committed(dag, &delta);
            }
            // Every applied block reached a verdict (audit F1).
            for h in &sub.to_apply {
                store.clear_no_verdict(h);
            }
        }
        Err(_) => shielded.write().revert_staged(staged_shielded),
    }
    match result {
        Ok(outcome) => Ok(outcome),
        Err(ConnectError::Invalid { block, reason, .. }) => {
            let witness = match witness_failure.take() {
                Some((h, root)) if h == block => Some(root),
                _ => None,
            };
            Err(ChunkFailure::Invalid { block, reason, witness })
        }
        Err(ConnectError::Failed(reason)) => Err(ChunkFailure::Failed { reason, no_verdict: no_verdict.take() }),
        Err(ConnectError::BodyUnreadable { block, applying, error }) => {
            Err(ChunkFailure::body_unreadable(sub, block, applying, error))
        }
    }
}

/// Move the applied chain to the best valid block, marking blocks invalid as
/// they fail. `applied_tip` is the block the UTXO set sits on (meta
/// `tip_hash`). `trigger` is the new block whose insertion prompted the call
/// (`None` for a body replacement and for the callers that insert nothing);
/// its DAG record and PoWit state are folded into the first commit batch
/// ([`TriggerRecord`]). `log`
/// accumulates the disqualified roots and the dropped bodies; `clears` lists
/// persisted marks to delete in the first commit (operator
/// `reconsiderblock`). Whatever the caller, a committed chunk also deletes
/// the persisted consensus or inherited mark of every block it applies
/// (validated in its own context just before): an applied block never
/// carries a mark that would disqualify it again at the next start.
///
/// A block of the plan whose body fails a rule that depends on witness bytes
/// its id does not commit to (below the hardening activation) is NOT
/// disqualified: its body is dropped and it waits, in memory only, for
/// another body (`GhostDAG::mark_body_pending`); the next-best chain is tried
/// meanwhile. Blocks of the plan without a stored body are handled as
/// `missing` says ([`MissingBodies`]).
///
/// There is no depth limit and no depth-based finality gate (audit DAG-6; PoWit
/// finality pins the candidate, see below): the plan to the
/// best valid block is executed at any depth — in chunks (audit B2-T0, like
/// Bitcoin Core's `ActivateBestChain`, which steps through at most 32 blocks
/// at a time with a bounded coins cache): each chunk of at most
/// `reorg::MAX_BLOCKS_PER_COMMIT` blocks is validated and committed
/// atomically with the tip pointer at its end ([`commit_chunk`]), so memory
/// is bounded by one chunk and every intermediate state is a consistent
/// applied tip. A block of a later chunk that turns out invalid is
/// disqualified and the best valid chain is resolved again from where the
/// applied chain now is (Core's `InvalidChainFound`, then the next
/// `ActivateBestChainStep`), which can move back to the old branch. `Err`
/// is a storage / missing-data failure before anything was committed (the
/// caller rolls its trigger back); after a commit the failure is reported as
/// `Connected { stopped: Some(..) }`.
///
/// A failure without a verdict (audit F1) is never a silent stall: the block
/// is parked in memory with its selected-chain descendants
/// ([`note_no_verdict`]: nothing marked or persisted, re-audit B1-T12, the
/// body kept) and the best chain the node can judge is resolved again from
/// where the applied chain now is, exactly as after an invalid block: a
/// move that had committed rollback chunks re-applies the old branch, and
/// templates are built on it. The parked block is retried on a bounded
/// schedule ([`unpark_due_no_verdicts`]), and repeated storage-engine
/// failures stop the node (Bitcoin Core's `AbortNode`). A body of a block
/// to apply that cannot be read is attributed too (review of PR #15,
/// finding 6): an engine error is that block's no-verdict, a body that does
/// not decode is dropped and fetched again ([`drop_undecodable_body`]). The
/// deepest rollbacks (at most `reorg::MAX_BLOCKS_PER_COMMIT`) are committed
/// in ONE batch with the first apply chunk
/// (`ReorgPlan::chunks_with_rollback_tail`; review of audit F1, finding 3,
/// and of PR #15, finding 5), so a reorg up to that depth is one commit: a
/// first apply chunk that fails, for any reason, never leaves the applied
/// tip at the fork point, and a pruned node never commits a rollback it
/// could not undo. (A deeper rollback commits its first part in earlier
/// chunks; if their bodies were pruned, only a re-fetch can undo it: the old
/// branch then waits for them like any best chain without bodies,
/// `MissingBodies::Wait`.)
///
/// PoWit finality (`consensus::finality`): the candidate is always the best
/// block whose selected chain passes through the pin, and the pin is
/// recomputed (`powit::refresh_finality_pin`) before each resolution step.
/// It depends on every stored block's PoWit state (PoWit audit finding 2)
/// and on the node's own finality: the checkpoint it pinned last (sticky,
/// persisted), which the applied chain only raises. A chunk moving toward
/// the pin never lowers it (the applied chain stays at or above the fork
/// point, which is at or above the pin's chain below the pin), so a chunk
/// committing or failing changes the pin only through what the step
/// disqualified: a disqualified block's finalization stops counting, and the
/// move goes to the best chain under what remains.
#[allow(clippy::too_many_arguments)]
fn resolve_best_chain(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    shielded: &Arc<RwLock<ShieldedPool>>,
    applied_tip: BlockHash,
    trigger: Option<TriggerRecord<'_>>,
    log: &mut ResolveLog,
    clears: &MarkClears,
    missing: MissingBodies,
) -> Result<Resolution, String> {
    let mut applied = applied_tip;
    let mut delta = reorg::ChainDelta::default();
    let mut committed_any = false;
    let mut trigger_pending = trigger.is_some();
    let mut clears_pending = true;
    let mut first_lca: Option<BlockHash> = None;

    // What was committed; disqualifications found after the last commit are
    // persisted here (the caller persists them only when nothing was
    // committed).
    let finish = |delta: &reorg::ChainDelta, log: &mut ResolveLog, stopped: Option<String>,
                  first_lca: Option<BlockHash>| -> Resolution {
        if !log.invalid.is_empty() {
            match persist_unchanged(dag, store, None, &log.invalid, &[]) {
                Ok(()) => log.invalid.clear(),
                Err(e) => error!("failed to persist invalid-block marks: {}", e),
            }
        }
        let outcome = delta.to_outcome();
        reorg::alert_if_deep(&outcome, first_lca.as_ref());
        Resolution::Connected { outcome, stopped }
    };

    // Each iteration either commits, stops, or disqualifies (or parks) at
    // least one more block; the DAG is finite, so this terminates. The bound
    // is a guard.
    'resolve: for _ in 0..10_000 {
        // The pin first: blocks disqualified by the previous step no longer
        // carry their finality (`consensus::finality`).
        crate::powit::refresh_finality_pin(dag, store);
        let cand = match dag.read().selected_tip() {
            Some(c) => c,
            None => break 'resolve,
        };
        if cand == applied {
            break 'resolve;
        }
        let plan = {
            let d = dag.read();
            // The best valid block can be an ANCESTOR of the applied tip when
            // applied blocks were disqualified (start-up hardening recheck,
            // operator `invalidateblock`): then the plan only disconnects.
            reorg::compute_connect_plan(&d, &applied, &cand)
        };
        let plan = match plan {
            Some(p) => p,
            None => {
                let m = format!(
                    "U.4: unexpected selected-tip transition (applied={}, best={}): no connect plan",
                    hex::encode(&applied[..8]), hex::encode(&cand[..8]));
                if committed_any {
                    return Ok(finish(&delta, log, Some(m), first_lca));
                }
                return Err(m);
            }
        };

        // A block without a stored body cannot be connected.
        let mut bodiless = Vec::new();
        let mut unreadable = None;
        for h in &plan.to_apply {
            match store.has_block_body(h) {
                Ok(true) => {}
                Ok(false) => bodiless.push(*h),
                Err(e) => {
                    unreadable = Some((*h, ViewError::from_storage(&e)));
                    break;
                }
            }
        }
        if let Some((h, e)) = unreadable {
            // Review of PR #15, findings 4 and 6: the storage engine failed
            // reading whether a block to apply has a body. No verdict on it:
            // it is parked and counted toward the stop like any engine
            // failure (`note_no_verdict`), and the best chain the node can
            // judge is resolved again. Never a bare `Err` once chunks have
            // committed: the caller would take the committed move for
            // nothing (and roll its trigger back).
            let m = format!("the stored body of block {} could not be read: {}", hex::encode(&h[..8]), e);
            note_no_verdict(dag, store, &h, e.kind, &m);
            if store.abort_reason().is_none() {
                continue 'resolve;
            }
            if committed_any {
                return Ok(finish(&delta, log, Some(m), first_lca));
            }
            return Err(m);
        }
        if let Some(first) = bodiless.first() {
            match missing {
                MissingBodies::Stop => {
                    let m = format!(
                        "{}: {} block(s) to connect have no body (first {})",
                        reorg::ERR_MISSING_BODIES, bodiless.len(), hex::encode(&first[..8]));
                    if committed_any {
                        return Ok(finish(&delta, log, Some(m), first_lca));
                    }
                    return Err(m);
                }
                MissingBodies::Wait => {
                    // All of them at once, so they are requested together.
                    warn!("{} block(s) of the best chain have no stored body (first {}); waiting for \
                           them before connecting it", bodiless.len(), hex::encode(&first[..8]));
                    let mut d = dag.write();
                    for h in &bodiless {
                        d.mark_body_pending(*h, None);
                    }
                    continue 'resolve;
                }
            }
        }

        let reorg_depth = plan.to_rollback.len();
        if reorg_depth > 0 {
            crate::metrics::inc_reorg_attempt();
            crate::metrics::set_fork_depth(reorg_depth as i64);
            crate::metrics::observe_reorg_depth(reorg_depth as f64);
        }
        first_lca.get_or_insert(plan.lca);

        // Review of audit F1, finding 3, and of PR #15, finding 5: a
        // rollback that commits before the first block of the new branch is
        // judged leaves the applied tip at the fork point if that chunk then
        // fails for any reason (an unreadable body, a failed commit), and
        // undoing it needs the old branch's bodies (gone on a pruned node).
        // The deepest rollbacks (up to `MAX_BLOCKS_PER_COMMIT`) therefore go
        // into the batch of the first apply chunk: a reorg up to that depth
        // is one commit. (Deeper rollbacks commit in earlier chunks, each a
        // consistent applied tip the move resumes from.)
        if plan.to_rollback.len() > reorg::MAX_BLOCKS_PER_COMMIT && !plan.to_apply.is_empty() {
            info!("chain move: the rollback of {} of {} block(s) commits before the new branch is judged",
                plan.to_rollback.len() - reorg::MAX_BLOCKS_PER_COMMIT, plan.to_rollback.len());
        }

        for sub in plan.chunks_with_rollback_tail(reorg::MAX_BLOCKS_PER_COMMIT, plan.to_rollback.len()) {
            let t = if trigger_pending { trigger } else { None };
            let always: &[BlockHash] = if clears_pending { &clears.always } else { &[] };
            let log_snapshot = log.invalid.clone();
            match commit_chunk(dag, store, shielded, &sub, t, always, &log_snapshot) {
                Ok(outcome) => {
                    delta.record(&outcome);
                    applied = sub.target();
                    committed_any = true;
                    trigger_pending = false;
                    clears_pending = false;
                    // Marks were persisted in the batch.
                    log.invalid.clear();
                }
                Err(ChunkFailure::Invalid { block, reason, witness }) => {
                    if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                    match witness {
                        // An operator override (`MissingBodies::Stop`) needs
                        // this block's body whatever the weight of its chain
                        // (re-audit B1-T13).
                        Some(root) => drop_body_and_wait(dag, store, block, root, reason,
                            missing == MissingBodies::Stop, &mut log.body_rejected),
                        None => disqualify(dag, block, reason, &mut log.invalid),
                    }
                    continue 'resolve;
                }
                Err(ChunkFailure::Undecodable { block, reason }) => {
                    if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                    drop_undecodable_body(dag, store, block, reason, missing == MissingBodies::Stop,
                        &mut log.body_rejected);
                    continue 'resolve;
                }
                Err(ChunkFailure::Failed { reason: m, no_verdict }) => {
                    if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                    // Audit F1 (review, finding 2): a block without a verdict
                    // is parked, not a reason to stop the move where it is:
                    // the best chain the node can judge is resolved again from
                    // the applied tip it is on (which re-applies an old branch
                    // whose rollback committed), like after an invalid block.
                    if let Some((b, kind)) = no_verdict {
                        note_no_verdict(dag, store, &b, kind, &m);
                        if store.abort_reason().is_none() {
                            continue 'resolve;
                        }
                    }
                    if committed_any {
                        error!("chain move stopped at {} after committed chunk(s): {}; it resumes with the \
                                next block or at the next start", hex::encode(&applied[..8]), m);
                        return Ok(finish(&delta, log, Some(m), first_lca));
                    }
                    return Err(m);
                }
            }
        }
        if reorg_depth > 0 { crate::metrics::inc_reorg_success(); }
    }
    let unresolved = dag.read().selected_tip().is_some_and(|c| c != applied);
    if !committed_any {
        if unresolved {
            return Err("resolve_best_chain: iteration guard reached".into());
        }
        return Ok(Resolution::Unchanged);
    }
    let stopped = unresolved.then(|| "resolve_best_chain: iteration guard reached".to_string());
    Ok(finish(&delta, log, stopped, first_lca))
}

/// `block`'s stored body failed a rule that depends on witness bytes its id
/// does not commit to (below the hardening activation a relay can change a
/// non-coinbase `script_sig` without changing the block id). Unlike
/// [`disqualify`], nothing is persisted and the block id is not poisoned:
/// the body is deleted (so it is never served to peers again) and the block,
/// with its selected-chain descendants, waits in memory for a different body
/// (`GhostDAG::mark_body_pending`): the message processor re-requests it
/// from peers and takes the answer to that pull (`awaits_body`; header sync
/// and `submitblock` take a copy too, unsolicited gossip copies are
/// ignored) while a chain through it can still become the best one
/// (`GhostDAG::is_body_wanted`, re-audit B1-T13) or, when `operator` (the
/// move of an operator override), until a body arrives
/// (`GhostDAG::request_body`).
fn drop_body_and_wait(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    block: BlockHash,
    witness_root: [u8; 32],
    reason: String,
    operator: bool,
    body_log: &mut Vec<(BlockHash, String)>,
) {
    let marked = {
        let mut d = dag.write();
        let marked = d.mark_body_pending(block, Some(witness_root));
        if operator {
            d.request_body(block);
        }
        marked
    };
    if let Err(e) = store.delete_block_body(&block) {
        error!("could not delete the rejected body of {}: {}", hex::encode(&block[..8]), e);
    }
    warn!(
        "block {} body rejected ({}): the failure depends on witness bytes the block id does not \
         commit to, so the id is NOT disqualified; body dropped, waiting for another copy \
         ({} selected-chain descendant(s) wait with it)",
        hex::encode(&block[..8]), reason, marked.len().saturating_sub(1)
    );
    body_log.push((block, reason));
}

/// Review of PR #15, finding 6: the stored body of `block`, a block to
/// apply, does not decode (the row was written that way, or corrupted
/// before RocksDB checksummed it). That is no verdict on the block (its id
/// commits to its transactions; the node's copy is bad): nothing is marked
/// or persisted, the body is deleted, and the block, with its selected-chain
/// descendants, waits for a copy from peers like a block whose body is
/// missing (`GhostDAG::mark_body_pending`; the processor requests it while a
/// chain through it can still become the best one, [`awaits_body`], and the
/// copy goes through `accept_block`'s body replacement). The node meanwhile
/// follows the best chain it can judge. Bitcoin Core stops on a block it
/// cannot read back (`FatalError`); fetching the block again is the repair
/// a node with peers has, and it keeps the node running.
fn drop_undecodable_body(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    block: BlockHash,
    reason: String,
    operator: bool,
    body_log: &mut Vec<(BlockHash, String)>,
) {
    let marked = {
        let mut d = dag.write();
        let marked = d.mark_body_pending(block, None);
        if operator {
            d.request_body(block);
        }
        marked
    };
    if let Err(e) = store.delete_block_body(&block) {
        error!("could not delete the undecodable body of {}: {}", hex::encode(&block[..8]), e);
    }
    error!(
        "block {} could not be judged: {}. No verdict (it is NOT marked invalid): the stored body is \
         dropped and fetched again from peers ({} selected-chain descendant(s) wait with it)",
        hex::encode(&block[..8]), reason, marked.len().saturating_sub(1)
    );
    body_log.push((block, format!("{UNDECODABLE_BODY_REASON}: {reason}")));
}

/// The reason [`drop_undecodable_body`] logs for a dropped body.
const UNDECODABLE_BODY_REASON: &str = "stored body does not decode";

/// Disqualify `block` (and its selected-chain descendants) in memory and
/// remember the root + reason for persistence.
fn disqualify(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    block: BlockHash,
    reason: String,
    invalid_log: &mut Vec<(BlockHash, String)>,
) {
    let marked = dag.write().mark_invalid(block);
    warn!(
        "block {} is invalid in its own context ({}); disqualified with {} selected-chain descendant(s)",
        hex::encode(&block[..8]), reason, marked.len().saturating_sub(1)
    );
    invalid_log.push((block, reason));
}

/// Stage persistent marks for every logged root and its marked descendants.
fn stage_invalid_marks(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    batch: &mut rocksdb::WriteBatch,
    log: &[(BlockHash, String)],
) -> Result<(), String> {
    for (root, reason) in log {
        if !dag.read().has_block(root) {
            continue;
        }
        store.stage_invalid_block(batch, root, reason).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Persist the trigger's DAG record, the pending reachability delta and its
/// PoWit state (if it is still in the DAG, [`TriggerRecord`]), the removal of
/// every `cleared` mark and every pending invalid mark in one batch — used
/// when the applied chain did not move. The delta is cleared from memory only
/// once the batch has committed (audit DAG-11).
fn persist_unchanged(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    trigger: Option<TriggerRecord<'_>>,
    invalid_log: &[(BlockHash, String)],
    cleared: &[BlockHash],
) -> Result<(), String> {
    let mut batch = rocksdb::WriteBatch::default();
    let mut delta = None;
    if let Some(t) = &trigger {
        delta = stage_trigger_record(dag, store, &mut batch, t)?;
    }
    for h in cleared {
        store.stage_clear_invalid_block(&mut batch, h).map_err(|e| e.to_string())?;
    }
    stage_invalid_marks(dag, store, &mut batch, invalid_log)?;
    store.write_batch(batch).map_err(|e| e.to_string())?;
    if let Some(delta) = delta {
        reach_committed(dag, &delta);
    }
    Ok(())
}

/// What one or more acceptance calls did to the applied (selected) chain:
/// the NET effect of every committed move, accumulated in order (a block
/// connected by one call and disconnected by a later one appears in neither
/// list). Under the selected-chain-only ledger (docs/CONSENSUS.md) these are
/// the only blocks whose transactions were applied or un-applied; a block
/// stored as a fork-loser or merge candidate applies nothing. Consumers: the
/// orphan-transaction bookkeeping (`mempool::relay::TxRelay::on_chain_moved`),
/// which must treat exactly the transactions the mempool treats as confirmed
/// (`update_mempool_after_connect` reads the same `ConnectOutcome`).
///
/// Audit B1-T20 / B2-T0: block HASHES only, with O(1) netting per block
/// (`reorg::ChainDelta`); the transactions are read back from storage, within
/// Bitcoin Core's 20 MB `DisconnectedBlockTransactions` budget, when the
/// bookkeeping runs ([`Self::connected_txs`], [`Self::disconnected_txs`]).
#[derive(Debug, Default, Clone)]
pub struct ChainMove {
    delta: reorg::ChainDelta,
}

impl ChainMove {
    /// Fold one committed move's outcome in. A block rolled back from its
    /// undo record alone (body pruned, audit DAG-6) has no transactions to
    /// report; it only cancels an earlier connect of the same block.
    pub fn record(&mut self, outcome: &ConnectOutcome) {
        self.delta.record(outcome);
    }

    /// True iff no block with transactions to report was connected or
    /// disconnected (net).
    pub fn is_empty(&self) -> bool {
        self.delta.connected().is_empty() && self.delta.disconnected().is_empty()
    }

    /// Blocks added to the applied chain and still on it, in connect order.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn connected(&self) -> Vec<BlockHash> {
        self.delta.connected()
    }

    /// Blocks removed from the applied chain that were on it before the first
    /// recorded move, in disconnect order (tip first).
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn disconnected(&self) -> Vec<BlockHash> {
        self.delta.disconnected()
    }

    /// The transactions (coinbases included) of the connected blocks, in
    /// connect order — those of the most recently connected blocks, at most
    /// `reorg::MAX_DISCONNECTED_TX_POOL_BYTES` of them (orphans they do not
    /// cover expire normally). Bodies are read one at a time.
    pub fn connected_txs(&self, store: &storage::Storage) -> Vec<core::Transaction> {
        let mut blocks: Vec<Vec<core::Transaction>> = Vec::new();
        let mut bytes = 0usize;
        'blocks: for h in self.delta.connected().iter().rev() {
            let Ok(Some(b)) = store.get_block(h) else { continue };
            let mut kept = Vec::with_capacity(b.transactions.len());
            for tx in b.transactions {
                bytes = bytes.saturating_add(tx.actual_size());
                if bytes > reorg::MAX_DISCONNECTED_TX_POOL_BYTES {
                    if !kept.is_empty() {
                        blocks.push(kept);
                    }
                    break 'blocks;
                }
                kept.push(tx);
            }
            blocks.push(kept);
        }
        blocks.into_iter().rev().flatten().collect()
    }

    /// The non-coinbase transactions of the disconnected blocks, oldest
    /// disconnected block first (the order and the 20 MB budget reorg
    /// re-injection uses, `ConnectOutcome::reinjection_candidates`).
    pub fn disconnected_txs(&self, store: &storage::Storage) -> Vec<core::Transaction> {
        let outcome = ConnectOutcome { disconnected: self.delta.disconnected(), ..Default::default() };
        outcome.reinjection_candidates(store, reorg::MAX_DISCONNECTED_TX_POOL_BYTES).txs
    }
}

/// Accept a block: acceptance checks, DAG insertion, then connect the best
/// valid chain atomically (see the module documentation for the semantics).
/// Returns `Ok(block_hash)` when the block was accepted into the DAG and is
/// not disqualified (connected or stored as a fork-loser / merge candidate).
/// Returns `Err` for every rejection, including a block stored but
/// disqualified (invalid in its own context, or descending from an invalid
/// selected parent).
#[allow(clippy::too_many_arguments)]
pub fn accept_block(
    block:      &core::Block,
    block_hash: [u8; 32],
    height:     u64,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    // Sprint 2.c: tip-change broadcast for stratum re-notify.
    // None disables notification (tests, CLI without --stratum).
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    // Coherence C2: the node's shielded-pool engine. Applied only for blocks
    // that join the selected chain (COH-2).
    shielded:   &Arc<RwLock<ShieldedPool>>,
) -> Result<[u8; 32], String> {
    let mut ignored = ChainMove::default();
    accept_block_tracking(block, block_hash, height, dag, store, mempool, node_state, tip_tx, shielded, &mut ignored)
}

/// [`accept_block`] that also records into `chain` what the call did to the
/// applied chain ([`ChainMove`]): nothing for a fork-loser / merge candidate
/// (the block is accepted but applies no transaction), the connected and
/// disconnected blocks of a committed extension or reorg — also when the
/// arriving block itself is reported invalid while another chain was
/// connected.
#[allow(clippy::too_many_arguments)]
pub fn accept_block_tracking(
    block:      &core::Block,
    block_hash: [u8; 32],
    height:     u64,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    shielded:   &Arc<RwLock<ShieldedPool>>,
    chain:      &mut ChainMove,
) -> Result<[u8; 32], String> {
    // DAG-10: one acceptance at a time, across every ingress path.
    let _accept_guard = store.acceptance_lock();
    // Audit F1: a node that was stopped (`note_no_verdict`) accepts nothing.
    if let Some(m) = store.abort_reason() {
        return Err(format!("node stopped: {m}"));
    }
    ensure_invalid_set_loaded(dag, store);

    // Sprint 2.c: snapshot the selected tip BEFORE any DAG mutation so we can
    // detect whether this block changed the chain's head.
    let old_tip = { dag.read().selected_tip() };

    // ── Early dedup ──────────────────────────────────────────────────
    // A block already in the DAG is refused, unless it waits for a body
    // (its previous body failed a witness-dependent rule, or is missing):
    // then this copy REPLACES the body and is re-evaluated, after the same
    // acceptance checks as a new block.
    let in_dag = dag.read().has_block(&block_hash);
    let replacing = if in_dag {
        if !awaits_body(dag, store, &block_hash) {
            return Err(format!(
                "consensus rejection: block already in DAG: {}",
                hex::encode(block_hash)
            ));
        }
        let witness_root = core::block_rules::body_commitment_root(block).0;
        if dag.read().body_rejected_before(&block_hash, &witness_root) {
            return Err(format!(
                "consensus rejection: block already in DAG: {} (this body was already rejected; \
                 waiting for a different one)",
                hex::encode(block_hash)
            ));
        }
        true
    } else {
        false
    };

    // ── Parents must be known (cheap, before anything else) ──────────
    if block.header.parents.is_empty() {
        return Err("consensus rejection: non-genesis block without parents".into());
    }
    let parent_data: Vec<(u64, u64)> = {
        let d = dag.read();
        let mut v = Vec::with_capacity(block.header.parents.len());
        for p in &block.header.parents {
            match d.get_block_data(p) {
                Some(data) => v.push((data.height, data.timestamp)),
                None => return Err(format!(
                    "consensus rejection: unknown parent {}", hex::encode(p))),
            }
        }
        v
    };

    // ── POW-8 / re-audit B1-T0: the wire blue_score is not committed by the
    //    block id. Replace it HERE, with the value derived from the verified
    //    parents, so every caller (gossip, directed sync, orphan drain, body
    //    restore, `submitblock`, the miner) stores and serves the same body
    //    for one id and no peer-chosen value is ever persisted. No consensus
    //    rule reads it (the size measure of both regimes, the wire encoding,
    //    `core::block_rules::legacy_block_size` / `Block::wire_size`, writes
    //    it at a fixed width), so this changes no verdict.
    let derived_blue_score = {
        let d = dag.read();
        crate::ingress::derived_blue_score(
            block.header.parents.iter().filter_map(|p| d.get_block_data(p).map(|x| x.blue_score)),
        )
    };
    let normalized;
    let block: &core::Block = if block.blue_score == derived_blue_score {
        block
    } else {
        normalized = core::Block { blue_score: derived_blue_score, ..block.clone() };
        &normalized
    };

    // ── FIX VULN-02: header height = max parent DAG height + 1 ───────
    let expected_height = parent_data.iter().map(|(h, _)| *h).max().unwrap_or(0) + 1;
    if block.height != expected_height || height != expected_height {
        return Err(format!(
            "invalid height: block claims h={} but expected h={}",
            block.height, expected_height
        ));
    }

    // ── FIX VULN-01: difficulty bits must equal the ASERT schedule ───
    let parent_ts = core::difficulty_parent_timestamp(parent_data.iter().map(|(_, t)| *t));
    // From the liveness activation the block's own timestamp relaxes the
    // ASERT target once it is late (stall relief, DESIGN-obenblock.md 5.1).
    let expected_bits = pow::expected_block_bits(parent_ts, block.height, block.header.timestamp)
        .map_err(|e| format!("invalid difficulty: {}", e))?;
    if block.header.bits != expected_bits {
        return Err(format!(
            "invalid difficulty: block bits 0x{:08x} != expected 0x{:08x}",
            block.header.bits, expected_bits
        ));
    }

    // ── FIX VULN-04: Validate timestamp ──────────────────────────────
    {
        let parent_ts = parent_data.iter().map(|(_, t)| *t).max().unwrap_or(0);
        block.validate_timestamp(parent_ts)
            .map_err(|e| format!("timestamp rejected: {}", e))?;
    }

    // ── Hardening block rules (context-free; the header height is now
    //    verified). At/after the activation: wire-size limit, tagged Merkle
    //    root, no 64-byte transaction, coinbase height / parents / witness
    //    commitment (audit VAL-2, VAL-10, VAL-12, CRY-1). Checked BEFORE the
    //    block is stored and before any signature work, so a block whose
    //    witnesses were altered in transit (same block id) is refused without
    //    a trace, and the honest copy of that id is still accepted later. A
    //    no-op below the activation.
    core::block_rules::check_block_hardened_at(block, core::activation::hardening_activation_height())
        .map_err(|e| format!("consensus rejection: {}", e))?;
    // ── The block-size limit at the VERIFIED header height, in the measure
    //    of the regime (`block_rules::check_block_size_at`: the wire
    //    encoding at every height on this chain, re-audit B1-T0: the
    //    uncommitted blue_score has a fixed width there). Every ingress path
    //    checked it on the claimed height; checking it here too means no
    //    caller can store a block over the limit.
    core::block_rules::check_block_size_at(block, core::activation::hardening_activation_height())
        .map_err(|e| format!("consensus rejection: {}", e))?;
    // This chain's context-free rules that depend on the header height
    // (re-checked now that the height is verified; every ingress path ran
    // them in `validate_structure` on the claimed height): the `|wc:` witness
    // commitment from WITNESS_COMMITMENT_HEIGHT, the PoWit section's shape
    // from `powit_height()`, and dust.
    block.validate_witness_commitment()
        .map_err(|e| format!("consensus rejection: {}", e))?;
    block.validate_powit_structure()
        .map_err(|e| format!("consensus rejection: {}", e))?;
    block.validate_dust()
        .map_err(|e| format!("consensus rejection: {}", e))?;

    // ── Proof of work (expensive: 64 MiB GnB-SMH, cached by block id) ─
    //    A body for a block already in the DAG (`replacing`: same id, so the
    //    same proof preimage and nonce, and the height just bound to the
    //    same parents) carries the proof its DAG record already verified:
    //    only the cheap checks run again (`pow::proof_recorded_in_dag`, P5-G).
    let proof_ok = if replacing { pow::proof_recorded_in_dag(block) } else { block.validate_pow() };
    if !proof_ok {
        // Name the scheme the block was judged under (ObenBlock: SHA-256d).
        return Err(if core::pow_scheme::node_sha256d_params().is_some() {
            "consensus rejection: invalid SHA-256d proof of work".into()
        } else {
            "consensus rejection: invalid GnB-SMH proof of work".into()
        });
    }

    // ── Context-free consensus checks (VAL-11 MoneyRange, VAL-12 canonical
    //    encoding limits). No-ops for every block that went through the wire
    //    parser; they stop an in-process block that could not be read back.
    core::limits::check_block_context_free(block)
        .map_err(|e| format!("consensus rejection: {}", e))?;
    // The connect-time validator treats transaction 0 as the coinbase and
    // keys in-block prevouts by txid. Every ingress path already enforces
    // both rules through `validate_structure`; re-checking them here (cheap)
    // keeps the pipeline sound for any in-process caller that does not.
    if !block.validate_coinbase_format() {
        return Err("consensus rejection: invalid coinbase format".into());
    }
    block.validate_no_duplicate_txs()
        .map_err(|e| format!("consensus rejection: {}", e))?;

    // Shielded transactions cannot validate without an active verifier
    // (RejectAll is the default): context-free rejection, exactly as before.
    if !block.shielded_transactions.is_empty() && !shielded.read().verifier.is_active() {
        return Err("shielded consensus rejection: ProofInvalid (no shielded verifier active)".into());
    }

    // ── PoWit section, in context (from powit_height) ────────────────
    // Share proofs, attested blocks and share uniqueness against this
    // block's own selected chain, then the witness-set state transition
    // (attestations, equivocation proofs, justification, finality). A pure
    // function of the block and its past (never of the UTXO set), so a
    // failure is refused like a bad height or difficulty: the block is not
    // stored. `storage:` errors are local and refuse only this attempt.
    let powit_state = if replacing {
        None // same id, same PoWit section: its state is already stored
    } else {
        let d = dag.read();
        crate::powit::block_state(block, &block_hash, &d, store)
            .map_err(|e| if e.starts_with("storage:") { e } else { format!("consensus rejection: {}", e) })?
    };

    // ── Insert into GhostDAG and store the body ──────────────────────
    if old_tip.is_none() {
        return Err("consensus rejection: DAG has no genesis".into());
    }
    // The APPLIED tip is the block the UTXO set (and the shielded state) sit
    // on: the persisted tip pointer, written in the same batch as every
    // chain-move commit. The DAG's selected tip is only the best candidate;
    // it differs from the applied tip whenever a move to the best block could
    // not be committed: a failed start-up reconnect or a storage error (audit
    // DAG-11), or a chunked move stopped after committed chunks, which leaves
    // the pointer on an intermediate block (audit B2-T0). A plan computed
    // from the selected tip started where the state is not, so every later
    // connect was refused until a restart. Bitcoin Core likewise extends from
    // its active chain tip, never from the best header. A store without a
    // tip pointer the DAG knows (fixtures) falls back to the selected tip.
    let applied_tip = store.get_meta("tip_hash").map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .filter(|t| dag.read().has_block(t))
        .or(old_tip)
        .ok_or("consensus rejection: DAG has no genesis")?;
    if replacing {
        // Same id (header, txids, coinbase), different witness bytes: store
        // this body and let the blocks that waited for it compete again.
        // B1-T17: a body the node wanted back (a reorg needs it) is indexed
        // for pruning at the selected tip's height, not its own, so it is
        // not pruned again before the chain through it connects (Bitcoin
        // Core prunes by block file, and a re-downloaded block lands in a
        // recent file).
        let prune_height = {
            let d = dag.read();
            let own = d.get_block_data(&block_hash).map(|x| x.height).unwrap_or(block.height);
            let tip = d.selected_tip().and_then(|t| d.get_block_data(&t)).map(|x| x.height).unwrap_or(0);
            own.max(tip)
        };
        store.put_block_body_at(block, prune_height).map_err(|e| e.to_string())?;
        dag.write().clear_body_pending(&block_hash);
        info!("block {} h={}: new body stored for a block that waited for one; re-evaluating",
            hex::encode(&block_hash[..8]), block.height);
    } else {
        // Chain work normalised across the GnB-SMH v1 -> v3 switch
        // (`core::block_work`).
        let work = pow::block_work(block.header.bits, block.height);
        let data = dag.write().add_block(block_hash, block.header.parents.clone(), block.header.timestamp, work)
            .map_err(|e| format!("consensus rejection: {}", e))?;
        // B1-T17: every body is indexed for pruning at its DAG height,
        // whatever its place in the DAG (selected chain, merged, fork-loser).
        if let Err(e) = store.put_block_body_at(block, data.height) {
            dag.write().remove_block(&block_hash);
            return Err(e.to_string());
        }
        // The block's PoWit state, keyed by its hash (deterministic; inert
        // if the block never joins the selected chain), is committed with
        // its DAG record below (`TriggerRecord`): in the first chunk of the
        // chain move it triggers, or with its fork-loser record.
        //
        // PoWit audit finding 2: the checkpoint it finalized counts for the
        // finality pin whether or not it ever joins the selected chain
        // (Gasper's fork choice starts from the highest justified
        // checkpoint learned from ANY block), so the pin is refreshed before
        // the chain move: a node that learns a finalization from a lighter
        // branch moves to that branch when it advances the node's own
        // finality; one that conflicts with it only raises the conflict
        // alert (review HIGH 1, `consensus::finality`).
        crate::powit::note_block_finality(dag, store, &block_hash, powit_state.as_ref());
        // PoCI (ObenBlock): keep the finality certificate of a checkpoint
        // this block finalized (docs/DESIGN-obenblock-poci.md §6).
        crate::powit::certificate::keep(dag, store, &block_hash, powit_state.as_ref());
        crate::powit::refresh_finality_pin(dag, store);
    }
    // Informational only (RPC / tip notifications).
    let _ = store.put_meta("current_bits", &block.header.bits.to_le_bytes());

    // Undo this call's storage effects (nothing was committed): a new block
    // leaves the DAG; a replacement body is dropped again and the block keeps
    // waiting for one.
    let roll_back = |why: &str| {
        let _ = store.delete_block_body(&block_hash);
        if replacing {
            dag.write().mark_body_pending(block_hash, None);
        } else if !dag.write().remove_block(&block_hash) {
            warn!("could not roll back DAG insertion of {} ({})", hex::encode(&block_hash[..8]), why);
        }
        // Its finalization, if any, left with it.
        crate::powit::refresh_finality_pin(dag, store);
    };

    let mut log = ResolveLog::default();
    // A new block whose selected parent is disqualified for a reason the
    // block id commits to is disqualified with it (persisted). One that only
    // descends from a block waiting for a body is not: it waits too.
    if !replacing && dag.read().is_invalid_all_edges(&block_hash) {
        // It references (through any parent edge) a block that fails the
        // hardening block rules: no upgraded node can ever accept it.
        log.invalid.push((block_hash, format!(
            "{}: references a block stored by a pre-upgrade binary that fails them",
            HARDENING_RECHECK_REASON
        )));
    } else if !replacing && dag.read().is_invalid(&block_hash) && dag.read().is_invalid_persistently(&block_hash) {
        let sp = dag.read().get_block_data(&block_hash).and_then(|d| d.selected_parent);
        log.invalid.push((block_hash, format!(
            "{}{} is invalid", INHERITED_REASON_PREFIX,
            sp.map(|p| hex::encode(&p[..8])).unwrap_or_default()
        )));
    }

    // ── Connect the best valid chain (any depth, audit DAG-6) ────────
    let trigger = (!replacing).then_some(TriggerRecord { hash: block_hash, powit: powit_state.as_ref() });
    // Review of audit F1, finding 2: blocks parked without a verdict whose
    // retry is due compete again in this resolution. Unparked HERE (review
    // of PR #15, finding 1): after every early refusal of the arriving block
    // (a junk frame unparks nothing) and after `old_tip` was taken (a retry
    // that moves the selected tip is signalled like any move), and parked
    // again if the resolution fails before judging them.
    let due = unpark_due_no_verdicts(dag, store, std::time::Instant::now());
    let resolution = resolve_best_chain(
        dag, store, shielded, applied_tip, trigger,
        &mut log, &MarkClears::default(), MissingBodies::Wait,
    );

    let resolution = match resolution {
        Ok(r) => r,
        Err(m) => {
            repark_no_verdicts(dag, store, &due);
            // Storage failure: roll the in-memory change back (nothing was
            // committed), drop the body, but keep any deterministic invalid
            // marks discovered on the way.
            roll_back("resolution stopped");
            if !log.invalid.is_empty() {
                if let Err(e) = persist_unchanged(dag, store, None, &log.invalid, &[]) {
                    error!("failed to persist invalid-block marks: {}", e);
                }
            }
            // Disqualifications found on the way change the valid tips.
            sync_mempool_next_height(dag, store, mempool);
            return Err(format!("block {} not committed: {}", hex::encode(&block_hash[..8]), m));
        }
    };

    let connected = match resolution {
        Resolution::Unchanged => {
            if let Err(e) = persist_unchanged(dag, store, trigger, &log.invalid, &[]) {
                // The DAG record of a non-applied block failed to persist:
                // undo the in-memory insertion so memory and disk agree.
                error!("failed to persist DAG record of {}: {}", hex::encode(&block_hash[..8]), e);
                roll_back("DAG record not persisted");
                sync_mempool_next_height(dag, store, mempool);
                return Err(format!("block {} not committed: {}", hex::encode(&block_hash[..8]), e));
            }
            // A stored fork-loser / merge candidate (or a disqualification)
            // can move the template height without moving the applied tip.
            sync_mempool_next_height(dag, store, mempool);
            false
        }
        Resolution::Connected { outcome, stopped } => {
            if outcome.rolled_back() == 0 {
                info!("block h={} {} connected ({} block(s))",
                    block.height, hex::encode(&block_hash[..8]), outcome.connected.len());
            } else {
                info!("🔀 Reorg at h={}: rolled back {} block(s), applied {}",
                    block.height, outcome.rolled_back(), outcome.connected.len());
            }
            if let Some(m) = &stopped {
                // B2-T0: the committed chunks stand (each a consistent
                // applied tip); the move resumes with the next block or at
                // the next start (`reconcile_on_startup`).
                error!("block {}: the chain move stopped before the best valid block: {}",
                    hex::encode(&block_hash[..8]), m);
            }
            // The next height on the DAG after the move: the template
            // height (never the new tip's header height + 1, DAG-8).
            let next_height = crate::template::next_template_height(&dag.read(), store);
            update_mempool_after_connect(store, mempool, &outcome, next_height);
            chain.record(&outcome);
            true
        }
    };

    // ── Update node state ────────────────────────────────────────────
    {
        let mut s = node_state.write();
        s.tip_blue_score = dag.read().tip_blue_score();
        s.block_count    = dag.read().block_count() as u64;
        s.mempool_size   = mempool.size();
    }

    // The arriving block itself is disqualified: it is reported as rejected
    // (it is kept in the DAG — see the module docs — but never selected or
    // applied). Computed now, returned after the tip bookkeeping below.
    //
    // Its BODY was rejected for a witness-dependent reason: reported as
    // rejected too, but the id is not disqualified (a different body is
    // re-evaluated). A block that only waits for an ancestor's body is
    // accepted into the DAG (like a fork-loser) and connects when that body
    // arrives.
    let trigger_invalid: Option<String> = if !dag.read().is_invalid(&block_hash) {
        None
    } else if dag.read().is_no_verdict_parked(&block_hash) {
        // Audit F1 (review, findings 1 and 2): kept in the DAG with its body,
        // parked, not marked; reported as not connected (nothing is relayed
        // or penalized for it: `ingress::verdict_for_accept_error` ignores
        // this message).
        let reason = store.no_verdict_record(&block_hash).map(|r| r.reason)
            .unwrap_or_else(|| "storage read failed".to_string());
        Some(format!(
            "block {} could not be validated (no verdict: {}); it is not marked invalid, it is kept \
             and retried later",
            hex::encode(&block_hash[..8]), reason
        ))
    } else if dag.read().is_body_pending(&block_hash) {
        let reason = log.body_rejected.iter().rev()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, r)| r.clone())
            .unwrap_or_else(|| "body missing".to_string());
        if reason.starts_with(UNDECODABLE_BODY_REASON) {
            // A local fault, not the sender's (review of PR #15, finding 6):
            // no "consensus rejection" (nothing is penalized for it).
            Some(format!("block {} could not be judged ({}); it waits for a copy from peers",
                hex::encode(&block_hash[..8]), reason))
        } else {
            Some(format!(
                "consensus rejection: block {} body rejected ({}); the block id commits to no witness \
                 bytes below the hardening activation, so it is not disqualified and a different body \
                 will be re-evaluated",
                hex::encode(&block_hash[..8]), reason
            ))
        }
    } else if dag.read().is_invalid_persistently(&block_hash) {
        let reason = store.invalid_block_reason(&block_hash).ok().flatten()
            .unwrap_or_else(|| "descends from an invalid block".to_string());
        Some(format!(
            "consensus rejection: block {} is invalid in its own chain context: {}",
            hex::encode(&block_hash[..8]), reason
        ))
    } else {
        info!("block {} waits for an ancestor (a body, or a verdict) before it can be connected",
            hex::encode(&block_hash[..8]));
        None
    };

    if !connected {
        if let Some(e) = trigger_invalid {
            return Err(e);
        }
        info!("block h={} {} accepted into the DAG (not on the selected chain)",
            block.height, hex::encode(&block_hash[..8]));
        return Ok(block_hash);
    }
    if trigger_invalid.is_none() {
        info!("✓ block h={} accepted", height);
    }

    // No depth-based finality any more (audit DAG-6). PoWit finality: the
    // pin was refreshed before the move (`consensus::finality`); refreshed
    // again for what the move disqualified. The pruning cursor below uses
    // the selected tip's DAG height, never tip_blue_score(); see the DAG-8
    // note on `GhostdagData::height`.
    crate::powit::refresh_finality_pin(dag, store);
    let tip_height = {
        let d = dag.read();
        d.selected_tip()
            .and_then(|h| d.get_block_data(&h).map(|data| data.height))
            .unwrap_or(0)
    };

    // ── Prune old block bodies ───────────────────────────────────────
    // Bodies only: undo records are kept for every connected block and a
    // rollback record is written for each pruned APPLIED body, so a reorg of
    // any depth still works on a pruned node (DAG-6). Every stored body below
    // the pruning height goes — merged, fork-loser and junk bodies too
    // (B1-T17, `Storage::prune_blocks_below`). The PoWit checks read bodies
    // only within `SHARE_WINDOW` blocks below the block they validate (the
    // selected chain's recent shares and the attested blocks,
    // `powit::block_state`), so a block that can still compete never needs
    // a pruned body; a reorg back onto a pruned block fetches it again
    // (`awaits_body`) and its rollback uses the pruned-body record.
    const _: () = assert!(core::PRUNING_DEPTH > 4 * core::witness_share::SHARE_WINDOW);
    if ARCHIVE_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        if tip_height % 10_000 == 0 {
            info!("archival mode: retaining ALL block bodies (h={}); pruning disabled", tip_height);
        }
    } else if tip_height > core::PRUNING_DEPTH {
        let prune_below = tip_height - core::PRUNING_DEPTH;
        let last_pruned = store.pruned_height();
        if prune_below > last_pruned + 1000 {
            match store.prune_blocks_below(prune_below) {
                Ok(n) if n > 0 => info!("Pruned {} block bodies below h={}", n, prune_below),
                Err(e)         => warn!("Prune failed: {}", e),
                _ => {}
            }
        }
    }

    // ── Sprint 2.c: emit TipChanged if the selected tip moved ────────
    if let Some(tip_tx) = tip_tx {
        // Presence only (no decode): this runs at every acceptance.
        let has_body = |h: &[u8; 32]| store.has_block_body(h).unwrap_or(false);
        let new_tip = { dag.read().best_bodied_tip(has_body) };
        if new_tip != old_tip {
            if let Some(tip_hash) = new_tip {
                let d = dag.read();
                if let Some(data) = d.get_block_data(&tip_hash).cloned() {
                    // The template's own parents (memoized parent predicate,
                    // `template::eligible_parent`), not a second predicate.
                    let tips_parents: Vec<[u8; 32]> = crate::template::template_parents_and_height(&d, store).0;
                    drop(d);
                    let bits = store.get_meta("current_bits").ok().flatten()
                        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                        .unwrap_or(0x1d00ffff_u32);
                    let _ = tip_tx.send(tip::TipChanged {
                        hash:       tip_hash,
                        height:     data.height,
                        blue_score: data.blue_score,
                        parents:    tips_parents,
                        bits,
                    });
                }
            }
        }
    }

    match trigger_invalid {
        Some(e) => Err(e),
        None => Ok(block_hash),
    }
}

// ── Start-up recheck of stored blocks under the hardening rules ─────────────

/// Meta key recording the hardening activation height the stored DAG was
/// last rechecked against ([`recheck_stored_blocks_under_hardening`]).
pub const HARDENING_RECHECK_META: &str = "hardening_block_rules_checked";

/// Verdict of the hardening block rules on a STORED body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredBlockCheck {
    /// The body passes (or the rules do not apply at its height).
    Valid,
    /// It fails for a reason the block id commits to: every body with this
    /// id fails (the header Merkle root, the coinbase — its txid covers its
    /// `script_sig`, hence the commitment's tag, height and parents — or a
    /// transaction's txid preimage). The block must be disqualified.
    IdCommitted(&'static str),
    /// Only this body fails (its witness root differs from the committed
    /// one, or its transaction list does not match the header at all):
    /// another body with the same id may be valid.
    BodyOnly(&'static str),
}

/// Classify a stored body against the context-free hardening rules
/// (`check_block_hardened_at` + `validate_structure_without_pow_at`) at
/// `activation_height`.
pub fn classify_stored_block(b: &core::Block, activation_height: u64) -> StoredBlockCheck {
    use core::block_rules;
    let reason = match block_rules::check_block_hardened_at(b, activation_height)
        .and_then(|()| b.validate_structure_without_pow_at(activation_height))
    {
        Ok(()) => return StoredBlockCheck::Valid,
        Err(e) => e,
    };
    // A repeated parent (B2-T10) is in the header: every body of this id
    // fails.
    if block_rules::rules_active_at(b.height, activation_height)
        && block_rules::check_parents_distinct(&b.header.parents).is_err()
    {
        return StoredBlockCheck::IdCommitted(reason);
    }
    if !b.validate_merkle_at(activation_height) {
        // The header root is not the tagged root of these txids. If it is
        // their LEGACY root, the id commits to a legacy-format block, which
        // no body can turn into a valid one; otherwise this body's
        // transaction list is simply not the id's.
        return if b.validate_merkle_at(core::activation::NEVER) {
            StoredBlockCheck::IdCommitted(reason)
        } else {
            StoredBlockCheck::BodyOnly(reason)
        };
    }
    // The header root matches: the txids (and so the coinbase and every
    // txid preimage) are the id's.
    if !b.validate_coinbase_format()
        || b.transactions.iter().any(|t| block_rules::check_tx_not_64_bytes(t).is_err())
    {
        return StoredBlockCheck::IdCommitted(reason);
    }
    match block_rules::check_coinbase_commitment(b) {
        // Tag, height and parents match but not the witness root: a body
        // with other witness bytes.
        Err(e) if e.starts_with("bad witness commitment") => StoredBlockCheck::BodyOnly(e),
        // Ok: the witness root matches, so this body IS the committed one
        // and any other failure (size, duplicates, dust) is the id's.
        _ => StoredBlockCheck::IdCommitted(reason),
    }
}

/// What [`recheck_stored_blocks_under_hardening`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecheckReport {
    /// `false` when the DAG had already been rechecked at this activation.
    pub ran: bool,
    /// Blocks checked (stored bodies at header height >= the activation).
    pub checked: usize,
    /// Blocks disqualified (with all their DAG descendants).
    pub disqualified: Vec<BlockHash>,
    /// Blocks whose body was dropped to wait for another one.
    pub bodies_dropped: Vec<BlockHash>,
    /// Of `disqualified`, the candidates without a stored body (pruned by
    /// the pre-upgrade binary), disqualified conservatively (re-audit B2-T1).
    pub disqualified_without_body: usize,
    /// Candidates without a stored body whose body passed the hardening
    /// rules when it was pruned (`Storage::has_hardened_body_marker`): left
    /// valid.
    pub pruned_after_check: usize,
}

/// Prefix of the error [`reconcile_on_startup`] returns when the hardening
/// recheck could not complete (a storage error): nothing was recorded, and
/// the node must not start (re-audit B2-T1), so it never stores a block
/// before the recheck has run to completion.
pub const HARDENING_RECHECK_FAILED: &str = "hardening recheck of stored blocks failed";

/// Recheck the blocks a PRE-UPGRADE binary may have stored at a header
/// height at or above the hardening activation against the context-free
/// hardening rules (wire size, tagged Merkle root, 64-byte transactions,
/// coinbase commitment). An upgraded node never stores such a block, so one left in
/// the DAG (a legacy-format fork-loser, or a legacy chain the node applied
/// while it still ran the old binary) would stay a valid template parent and
/// make this node's blocks unacceptable to every upgraded peer.
///
/// A block failing for a reason its id commits to is disqualified together
/// with EVERY block that descends from it through any parent edge
/// (`GhostDAG::mark_invalid_all_edges`; later arrivals referencing one of
/// them are disqualified on insertion), and persisted with a reason starting
/// with [`HARDENING_RECHECK_REASON`] so the next start reloads it with the
/// same reach. A block whose only failure is its witness root (only this
/// body is wrong) is not disqualified: an unapplied one drops its body and
/// waits for another (`GhostDAG::mark_body_pending`).
///
/// A candidate whose body is gone (the pre-upgrade binary pruned it) is
/// disqualified conservatively, like an id-committed failure (re-audit
/// B2-T1), unless its body was pruned after passing these rules (a
/// hardened-body marker, `Storage::has_hardened_body_marker`: the recheck
/// runs again after a switch between builds with different activation
/// heights, and blocks this node accepted under the rules and pruned since
/// must stay valid). The recheck runs at the first start of a binary with these rules,
/// before any block is accepted ([`reconcile_on_startup`] refuses to go on
/// when it fails), so every candidate was stored by a binary without them,
/// which checked the LEGACY header root against the body before storing it:
/// the id commits to a legacy root no body can match under the tagged rule,
/// and no upgraded node ever accepted the block. Counting it as unchecked
/// while recording the recheck as done left such a block valid forever (once
/// its unpruned descendants were disqualified it became the best valid tip).
/// Bitcoin Core likewise never trusts blocks connected without a newly
/// activated deployment's checks (`NeedsRedownload`).
///
/// Runs once per activation height (meta key [`HARDENING_RECHECK_META`]);
/// it reads no body when no stored block is at or above the activation (a
/// mainnet node upgraded before it). Call it BEFORE reconnecting the best
/// chain, so the reconnect rolls the applied tip off a disqualified branch.
pub fn recheck_stored_blocks_under_hardening(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    activation_height: u64,
) -> Result<RecheckReport, String> {
    let done = store.get_meta(HARDENING_RECHECK_META).map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok().map(u64::from_le_bytes));
    if done == Some(activation_height) {
        return Ok(RecheckReport::default());
    }
    let mut report = RecheckReport { ran: true, ..Default::default() };
    let candidates = dag.read().blocks_with_header_height_at_least(activation_height.max(1));
    let mut batch = rocksdb::WriteBatch::default();
    for h in candidates {
        if dag.read().is_invalid_all_edges(&h) {
            continue; // already disqualified through an ancestor checked earlier
        }
        let body = match store.get_block(&h).map_err(|e| e.to_string())? {
            Some(b) => b,
            // Pruned by a binary that checked the body first (the marker is
            // written with the pruning, see `storage::HARDENED_BODY_PREFIX`).
            // The recheck runs again whenever the activation height differs
            // from the recorded one (a switch between builds), and this body
            // may have been accepted and pruned under the hardening rules
            // themselves: disqualifying it would fork the node off a valid
            // chain for good.
            None if store.has_hardened_body_marker(&h).map_err(|e| e.to_string())? => {
                report.pruned_after_check += 1;
                continue;
            }
            None => {
                let marked = dag.write().mark_invalid_all_edges(h);
                error!(
                    "stored block {} at or above the hardening activation has no body (pruned by a \
                     pre-upgrade binary): disqualified with {} descendant(s)",
                    hex::encode(&h[..8]), marked.len().saturating_sub(1)
                );
                store.stage_invalid_block(&mut batch, &h, &format!(
                    "{}: no stored body to check (pruned by a pre-upgrade binary)", HARDENING_RECHECK_REASON
                )).map_err(|e| e.to_string())?;
                report.disqualified.push(h);
                report.disqualified_without_body += 1;
                continue;
            }
        };
        report.checked += 1;
        match classify_stored_block(&body, activation_height) {
            StoredBlockCheck::Valid => {}
            StoredBlockCheck::IdCommitted(reason) => {
                let marked = dag.write().mark_invalid_all_edges(h);
                error!(
                    "stored block {} h={} fails the hardening block rules ({}); it was stored by a \
                     pre-upgrade binary: disqualified with {} descendant(s)",
                    hex::encode(&h[..8]), body.height, reason, marked.len().saturating_sub(1)
                );
                store.stage_invalid_block(&mut batch, &h, &format!(
                    "{}: {} (stored by a pre-upgrade binary)", HARDENING_RECHECK_REASON, reason
                )).map_err(|e| e.to_string())?;
                report.disqualified.push(h);
            }
            StoredBlockCheck::BodyOnly(reason) => {
                if store.get_undo_data(&h).map_err(|e| e.to_string())?.is_some() {
                    // Applied: its body is needed to roll it back. Cannot
                    // happen for a body stored by any binary (the old one
                    // never stores a tagged root, the new one checks the
                    // commitment first); left alone and reported.
                    error!("applied block {} has a body whose witnesses do not match its commitment ({}); \
                            left in place", hex::encode(&h[..8]), reason);
                    continue;
                }
                warn!("stored body of {} fails the hardening rules only by its witnesses ({}); \
                       dropped, waiting for another copy", hex::encode(&h[..8]), reason);
                let wr = core::block_rules::body_commitment_root(&body).0;
                dag.write().mark_body_pending(h, Some(wr));
                store.delete_block_body(&h).map_err(|e| e.to_string())?;
                report.bodies_dropped.push(h);
            }
        }
    }
    store.stage_meta(&mut batch, HARDENING_RECHECK_META, &activation_height.to_le_bytes())
        .map_err(|e| e.to_string())?;
    store.write_batch(batch).map_err(|e| e.to_string())?;
    if !report.disqualified.is_empty() || !report.bodies_dropped.is_empty() {
        warn!(
            "hardening recheck at activation {}: {} checked, {} disqualified ({} without a body), {} bodies dropped",
            activation_height, report.checked, report.disqualified.len(), report.disqualified_without_body,
            report.bodies_dropped.len()
        );
    }
    Ok(report)
}

// ── Start-up reconciliation (DAG-11) ─────────────────────────────────────────

/// Reconcile the chain state on boot, before any block is accepted:
///
/// 1. load the persisted chain-disqualified set into the DAG, then recheck
///    the blocks a pre-upgrade binary may have stored at or above the
///    hardening activation ([`recheck_stored_blocks_under_hardening`]);
/// 2. roll back the UTXO effects of any block that has an undo record but no
///    CF_DAG record — the footprint of the pre-fix, non-atomic extension
///    commit crashing between "apply UTXO effects" and "persist DAG data"
///    (audit VAL-4 / DAG-11). Its inputs would otherwise read as spent and the
///    block would be refused forever on re-receipt. The tip pointer (and the
///    shielded tip) is set, in the same batch, to the block the UTXO set then
///    describes: the heaviest DAG block that holds an undo record, even when
///    step 1 disqualified it (not the DAG's selected tip);
/// 3. refuse (an error naming the faults) if the chain state still carries
///    the footprint of an interrupted pre-fix commit that steps 1-2 cannot
///    repair ([`check_chain_state`], audit DAG-11 residual; run only after
///    step 2, which repairs the states it handles, so it never misfires on
///    them): the caller rebuilds ([`rebuild_chain_state`]) and calls this
///    again;
/// 4. if the applied tip pointer is not the best valid block, connect the
///    best valid chain with the same atomic machinery as `accept_block` (a
///    rollback-only plan when step 1 disqualified applied blocks), at any
///    depth (audit DAG-6); blocks of that chain whose body is missing wait
///    for one, and the best chain the node can connect is connected
///    meanwhile.
///
/// Every step is idempotent and cheap (one scan of CF_UNDO keys). New writes
/// can no longer produce a state that needs step 2: an extension now commits
/// UTXO effects, undo data, DAG record and tip pointer in one batch.
///
/// `shielded` must be the state [`ShieldedPool::load`] returned for `store`
/// (audit COH-2: it sits at the applied tip). Step 1 and the explorer
/// aggregate rebuild (NET-12) leave the applied tip where it is; steps 2 and
/// 4 move the shielded state with the chain, in the same batches.
pub fn reconcile_on_startup(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<(), String> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    // DAG-8: a data dir written before the selected-chain indexes were keyed
    // by chain position is migrated before anything moves the chain.
    migrate_chain_indexes(dag, store)?;
    // Audit F1: the genesis-ledger index (the confirmation point of the
    // carryover and the vesting tranches) of a data dir ingested before it
    // existed, before any block is validated.
    match store.migrate_genesis_ledger_index() {
        Ok(Some(n)) => info!("genesis-ledger index written for an existing data dir: {} txid(s)", n),
        Ok(None) => {}
        Err(e) => return Err(format!("genesis-ledger index migration failed: {e}")),
    }
    // Re-audit B2-T1: a recheck that cannot complete records nothing, and
    // the node must not accept a block before it has (a block the upgraded
    // binary stored and later pruned would otherwise reach a later recheck
    // and be disqualified as a legacy one): refuse to start.
    let recheck = recheck_stored_blocks_under_hardening(
        dag, store, core::activation::hardening_activation_height(),
    ).map_err(|e| format!("{}: {}", HARDENING_RECHECK_FAILED, e))?;

    // NET-12: a database written before the explorer aggregates existed gets
    // them built once, from scratch (later connects keep them current in the
    // same batches as the UTXO changes).
    match store.ensure_aggregates() {
        Ok(true) => info!("NET-12: explorer aggregates rebuilt from the UTXO set and undo records"),
        Ok(false) => {}
        Err(e) => error!("NET-12: explorer aggregates could not be rebuilt: {} (explorer statistics stay unavailable)", e),
    }

    // Step 2: applied-but-unrecorded blocks.
    let UnrecordedApplied { mut orphan_applied, back_to } = unrecorded_applied_blocks(dag, store, true)?;
    if !orphan_applied.is_empty() {
        orphan_applied.sort_by(|a, b| b.cmp(a)); // tip-first
        let to_rollback: Vec<BlockHash> = orphan_applied.iter().map(|(_, h)| *h).collect();
        // Once they are gone, the UTXO set describes the chain of the DAG
        // blocks that still hold an undo record (every connect writes one,
        // every disconnect deletes it), so its tip is the heaviest of those:
        // they are all its ancestors. Neither pointer the node keeps is a
        // witness for it:
        // - the DAG's selected tip: step 1 may have disqualified applied
        //   blocks (they stay applied until step 4 disconnects them), and a
        //   pre-fix reorg that crashed before its DAG write left the UTXO set
        //   on a branch the DAG alone does not select;
        // - meta tip_hash: that crashed reorg had not rewritten it, and the
        //   crashed extension may have written it as the unrecorded block;
        // - the unrecorded blocks' parents: a pre-fix binary that kept
        //   running after the crash connected later blocks on top of them.
        // Pointing the tip (and the shielded tip) at a block the UTXO set does
        // not sit on would leave effects applied under a tip that excludes
        // them, or drop effects of blocks it includes, with nothing to
        // repair it. When no DAG block holds an undo record (genesis has
        // none; a chain connected before undo records existed neither) the
        // unrecorded blocks sit on their selected parent. Step 4 then moves
        // the chain from this real applied tip to the best valid block.
        let Some(back_to) = back_to else {
            return Err(format!(
                "reconcile: {} block(s) have applied UTXO effects but no DAG record, and the DAG holds \
                 neither an applied block nor one of their parents, so the chain position of the UTXO \
                 set is unknown; resynchronize this data directory",
                to_rollback.len()));
        };
        warn!(
            "reconcile: {} block(s) have applied UTXO effects but no DAG record (interrupted \
             pre-fix commit); rolling them back atomically to {}",
            to_rollback.len(), hex::encode(&back_to[..8])
        );
        // COH-2: these blocks predate shielded persistence; the shielded tip
        // follows the UTXO tip in the same batch. B2-T0: in chunks of
        // `reorg::MAX_BLOCKS_PER_COMMIT` blocks (each batch points the tip at
        // `back_to`; blocks a crash leaves unrolled are found again by this
        // same scan at the next start).
        for chunk in to_rollback.chunks(reorg::MAX_BLOCKS_PER_COMMIT) {
            let staged_shielded = shielded.write().stage_retip(store, chunk, back_to)
                .map_err(|e| format!("reconcile rollback: {e}"))?;
            let plan = reorg::ReorgPlan { lca: back_to, to_rollback: chunk.to_vec(), to_apply: vec![] };
            let validate = |_: &dyn UtxoView, _: &core::Block| -> Result<(), ValidationFailure> { Ok(()) };
            let stage_extra = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
                st.stage_meta(batch, "tip_hash", &back_to).map_err(|e| e.to_string())?;
                staged_shielded.stage_into(st, batch)
            };
            let hooks = ConnectHooks { validate: &validate, stage_extra: &stage_extra };
            let result = reorg::connect_plan(store, &plan, &hooks);
            match &result {
                Ok(_) => shielded.write().commit_staged(staged_shielded),
                Err(_) => shielded.write().revert_staged(staged_shielded),
            }
            result.map_err(|e| format!("reconcile rollback: {}", e))?;
        }
    }

    // DAG-11 residual: never connect anything on top of a chain state that
    // carries the footprint of an interrupted pre-fix commit (step 4 would
    // validate blocks against it and could disqualify valid ones). The
    // caller rebuilds (`rebuild_chain_state`) or stops.
    let faults = check_chain_state(dag, store)?;
    if !faults.is_empty() {
        let list: Vec<String> = faults.iter().map(|f| f.to_string()).collect();
        return Err(format!(
            "chain state inconsistent ({}); rebuild it from the block bodies \
             (`rebuild_chain_state`, done by `gnb` at start-up with --carryover-snapshot)",
            list.join("; ")
        ));
    }

    // Step 4: applied tip vs best valid block.
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    // PoWit finality first (B2-T0, PoWit audit finding 2): the pin lives in
    // memory, so it is rebuilt from the persisted finality rows of every
    // stored block (`powit::load_finality_index`) BEFORE the best block is
    // chosen: the node restarts with exactly the pin it had, and a resumed
    // move never leaves finality it had learned.
    crate::powit::load_finality_index(dag, store)?;
    crate::powit::refresh_finality_pin(dag, store);
    let best = dag.read().selected_tip();
    if let (Some(applied), Some(best)) = (applied, best) {
        if applied != best && dag.read().has_block(&applied) {
            warn!("reconcile: applied tip {} != best valid block {}; reconnecting",
                hex::encode(&applied[..8]), hex::encode(&best[..8]));
            let mut log = ResolveLog::default();
            match resolve_best_chain(dag, store, shielded, applied, None, &mut log,
                                     &MarkClears::default(), MissingBodies::Wait) {
                Ok(Resolution::Connected { stopped: Some(m), .. }) => {
                    // B2-T0: the committed chunks stand; the next start (or
                    // the next accepted block) resumes from the applied tip.
                    error!("reconcile: reconnecting the best valid chain stopped: {}", m);
                    return Err(m);
                }
                Ok(_) => {
                    if !log.invalid.is_empty() {
                        persist_unchanged(dag, store, None, &log.invalid, &[])?;
                    }
                }
                Err(m) => {
                    error!("reconcile: cannot reconnect the best valid chain: {}", m);
                    if !recheck.disqualified.is_empty() {
                        // There is no reorg-depth limit (audit DAG-6): the
                        // rollback off them failed on storage or missing data.
                        error!(
                            "reconcile: the applied chain still contains blocks a pre-upgrade binary stored \
                             that fail the hardening block rules, and the rollback off them failed; \
                             resynchronize this data directory if this persists"
                        );
                    }
                    return Err(m);
                }
            }
        }
    }
    // Audit F1 (review, finding 1): a block that could not be judged because
    // the storage engine failed refuses the start, like Bitcoin Core's init
    // when it cannot connect the best block; an inconsistent index does not
    // (the block stays parked and is retried while the node runs). Checked
    // whatever the tips (review of PR #15, finding 3): a block parked by the
    // resolution above, or by a chain-state rebuild that ran before this
    // call, makes the applied tip the selected one.
    if let Some((b, r)) = store.no_verdict_records().into_iter().find(|(_, r)| r.last_io) {
        return Err(format!(
            "block {} could not be validated: the storage engine failed (no verdict): {}",
            hex::encode(&b[..8]), r.reason));
    }
    Ok(())
}

/// Reconciliation step 2's input: the blocks with applied UTXO effects (an
/// undo record and a body) but no DAG record, highest header height first,
/// and the block the UTXO set sits on once they are rolled back (`None` when
/// there are none, or when the DAG holds neither an applied block nor one of
/// their parents). Shared by step 2 and the DAG-8 index migration, which must
/// index the chain step 2 leaves applied.
struct UnrecordedApplied {
    orphan_applied: Vec<(u64, BlockHash)>,
    back_to: Option<BlockHash>,
}

fn unrecorded_applied_blocks(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    log_ignored: bool,
) -> Result<UnrecordedApplied, String> {
    let mut orphan_applied: Vec<(u64, BlockHash)> = Vec::new();
    let mut orphan_parents: Vec<BlockHash> = Vec::new();
    let undo_hashes = store.undo_block_hashes().map_err(|e| e.to_string())?;
    for &h in &undo_hashes {
        if !dag.read().has_block(&h) {
            if let Ok(Some(b)) = store.get_block(&h) {
                orphan_applied.push((b.height, h));
                orphan_parents.extend_from_slice(&b.header.parents);
            } else if log_ignored {
                warn!("reconcile: undo record for unknown block {} without a body; ignoring",
                    hex::encode(&h[..8]));
            }
        }
    }
    if orphan_applied.is_empty() {
        return Ok(UnrecordedApplied { orphan_applied, back_to: None });
    }
    // Once they are gone, the UTXO set describes the chain of the DAG blocks
    // that still hold an undo record (see step 2).
    let back_to = {
        let d = dag.read();
        let recorded: Vec<BlockHash> = undo_hashes.iter().copied().filter(|h| d.has_block(h)).collect();
        d.heaviest_among(&recorded).or_else(|| d.heaviest_among(&orphan_parents))
    };
    Ok(UnrecordedApplied { orphan_applied, back_to })
}

// ── Selected-chain index layout (DAG-8) ──────────────────────────────────────

/// Migrate the selected-chain indexes (CF_HEIGHT, CF_TIMESTAMPS, address
/// history) of a data dir written before audit DAG-8 from header-height keys
/// to selected-chain positions (DAG heights), once: a versioned schema step
/// (`storage::CHAIN_INDEX_VERSION`). Run by [`reconcile_on_startup`] before
/// anything moves the chain, through [`rebuild_chain_indexes`]. Returns
/// whether it migrated.
pub fn migrate_chain_indexes(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) -> Result<bool, String> {
    if store.chain_index_version().map_err(|e| e.to_string())? == storage::CHAIN_INDEX_VERSION {
        return Ok(false);
    }
    let r = rebuild_chain_indexes(dag, store)?;
    warn!("DAG-8: selected-chain indexes migrated to chain positions: {} block(s), {} address-history \
           row(s){}{}", r.blocks, r.rows,
           if r.lost > 0 {
               format!(", {} row(s) of pruned blocks not recoverable (overwritten by an earlier release, \
                        or not attributable to a block)", r.lost)
           } else { String::new() },
           if r.unresolved > 0 {
               format!(", {} input(s) without an undo record to resolve their spend", r.unresolved)
           } else { String::new() });
    Ok(true)
}

/// `--reindex-addresses`: rebuild the selected-chain indexes (the address
/// history `getaddresshistory` serves, the position -> hash and position ->
/// timestamp rows) from the applied chain, under the acceptance lock. The
/// same rebuild as the DAG-8 migration ([`rebuild_chain_indexes`],
/// `Storage::rebuild_chain_indexes`), in the same layout (rows keyed by
/// chain position, exactly what a connect writes), so the flag and the
/// migration can never produce two layouts. Fixes histories that lost their
/// spends to reorgs on releases before the address rows were written at
/// apply time; spends are resolved from each block's undo record, which
/// holds every output the block spent (genesis-ledger outputs included).
pub fn reindex_chain_indexes(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) -> Result<storage::ChainIndexRebuild, String> {
    let _guard = store.acceptance_lock();
    rebuild_chain_indexes(dag, store)
}

/// Rebuild the selected-chain indexes from the applied chain (one batch,
/// `Storage::rebuild_chain_indexes`). The applied chain is the one
/// reconciliation leaves the UTXO set on before it reconnects: when step 2
/// will roll back applied blocks without a DAG record, the chain of the block
/// it re-tips to ([`unrecorded_applied_blocks`], the same decision);
/// otherwise the selected-parent chain of the tip pointer (or, when the DAG
/// does not know it, of the heaviest DAG block holding an undo record).
fn rebuild_chain_indexes(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) -> Result<storage::ChainIndexRebuild, String> {
    // Step 2 moves the tip pointer to `back_to` before step 4 connects
    // anything; the pointer on disk may still name a block of another branch
    // (a pre-fix reorg that crashed before its DAG and tip writes).
    let retip = unrecorded_applied_blocks(dag, store, false)?.back_to;
    let chain: Vec<(BlockHash, u64, u64)> = {
        let d = dag.read();
        let tip = retip
            .or(store.get_meta("tip_hash").map_err(|e| e.to_string())?
                .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                .filter(|t| d.has_block(t)))
            .or_else(|| {
                let undo = store.undo_block_hashes().ok()?;
                let recorded: Vec<BlockHash> = undo.into_iter().filter(|h| d.has_block(h)).collect();
                d.heaviest_among(&recorded)
            })
            .or(d.store.genesis);
        let mut out = Vec::new();
        let mut cur = tip;
        while let Some(h) = cur {
            let Some(data) = d.get_block_data(&h) else { break };
            out.push((h, data.height, data.timestamp));
            cur = data.selected_parent;
        }
        out.reverse();
        out
    };
    store.rebuild_chain_indexes(&chain).map_err(|e| e.to_string())
}

// ── Start-up DAG load and repair (DAG-11 residual) ───────────────────────────

/// What the DAG repair recomputes a block's record from: its stored
/// header, with the work `accept_block` inserted it with (normalised across
/// the GnB-SMH v1 -> v3 switch, `core::block_work`; the raw `work_from_bits`
/// of a v3 block is four times that, and a record recomputed with it carries
/// another blue work than every other node's).
pub fn repair_header(b: &core::Block) -> consensus::StoredHeader {
    consensus::StoredHeader {
        parents: b.header.parents.clone(),
        timestamp: b.header.timestamp,
        work: pow::block_work(b.header.bits, b.height),
    }
}

/// What [`load_dag`] did.
#[derive(Debug, Default)]
pub struct DagLoadReport {
    /// Blocks loaded into the DAG (0: nothing persisted yet).
    pub blocks_loaded: usize,
    /// No integrity record existed (a data dir from before the integrity
    /// chain); they were computed and written.
    pub self_healed: bool,
    /// The integrity chain did not verify and the repair ran.
    pub repair: Option<consensus::DagRepair>,
}

/// Load the persisted DAG into the (empty) `dag` at start-up.
///
/// The integrity chain over every block's GhostDAG data is verified first
/// (`GhostDAG::load_persisted_validated`). If it does not verify, the node
/// used to exit with a tampering message, before reconciliation could run and
/// with no repair but a resync (audit DAG-11), and the footprint a pre-fix
/// binary leaves after losing one DAG write (a missing record, descendants
/// chained to a zero-filled link) triggers exactly that. The DAG is now
/// repaired instead (`GhostDAG::load_persisted_repairing`): records
/// consistent with their own integrity hash are kept and relinked, missing
/// or corrupted ones are recomputed from the stored block headers with the
/// consensus code, and what cannot be recomputed is dropped with its
/// descendants and fetched again from peers, like Bitcoin Core's
/// `-reindex` rebuilding its block index from the block files. The repair is
/// committed in one batch, and the next start verifies strictly.
///
/// The UTXO set must not keep the effects of a block the repaired DAG no
/// longer has and that cannot be rolled back: if a dropped block was applied
/// (it has an undo record) the repair is refused and the data dir must be
/// resynchronized. (Applied blocks are only dropped when their bodies are
/// gone; a pruned node's footprint in its pruned range is the one case.)
pub fn load_dag(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) -> Result<DagLoadReport, String> {
    let entries = store.load_all_dag_data().map_err(|e| format!("CF_DAG read failed: {e}"))?;
    if entries.is_empty() {
        return Ok(DagLoadReport::default());
    }
    let integrity_map = match store.load_all_integrity_hashes() {
        Ok(m) => m,
        Err(e) => {
            warn!("failed to read CF_DAG_INTEGRITY ({e}); assuming a data dir from before the integrity chain");
            HashMap::new()
        }
    };
    let verified = dag.write().load_persisted_validated(entries.clone(), integrity_map.clone());
    match verified {
        Ok(loaded) => {
            if let Some(fresh) = loaded.fresh_map.as_ref().filter(|_| loaded.self_healed) {
                let mut batch = rocksdb::WriteBatch::default();
                store.stage_dag_repair(&mut batch, &[], fresh, &[]).map_err(|e| e.to_string())?;
                store.write_batch(batch).map_err(|e| format!("self-heal: integrity records not written: {e}"))?;
            }
            Ok(DagLoadReport { blocks_loaded: loaded.blocks_loaded, self_healed: loaded.self_healed, repair: None })
        }
        Err(e) => {
            warn!("GhostDAG integrity check failed: {e}. Repairing the DAG records from the stored records \
                   and block headers (audit DAG-11) instead of refusing to start.");
            let header_of = |h: &BlockHash| -> Option<consensus::StoredHeader> {
                store.get_block(h).ok().flatten().map(|b| repair_header(&b))
            };
            let repair = dag.write().load_persisted_repairing(entries, integrity_map, header_of)?;
            for h in &repair.dropped {
                if store.has_undo_data(h).map_err(|e| e.to_string())? {
                    return Err(format!(
                        "DAG repair: block {} is applied (it has an undo record) but its DAG record cannot be \
                         recovered (no stored body to recompute it from); the UTXO set cannot be repaired \
                         in place. Resynchronize this data directory (a fresh --data-dir with \
                         --carryover-snapshot, or an archival node's data dir).",
                        hex::encode(&h[..8])));
                }
            }
            let mut batch = rocksdb::WriteBatch::default();
            store.stage_dag_repair(&mut batch, &repair.recomputed, &repair.integrity, &repair.dropped)
                .map_err(|e| e.to_string())?;
            store.write_batch(batch).map_err(|e| format!("DAG repair not written: {e}"))?;
            warn!("DAG repaired: {} block(s) loaded, {} relinked, {} recomputed from their headers, {} dropped \
                   (fetched again from peers)", repair.blocks_loaded, repair.relinked.len(),
                   repair.recomputed.len(), repair.dropped.len());
            Ok(DagLoadReport { blocks_loaded: repair.blocks_loaded, self_healed: false, repair: Some(repair) })
        }
    }
}

// ── Start-up chain-state check and rebuild (DAG-11 residual) ─────────────────

/// CF_META flag set while [`rebuild_chain_state`] is between its two commits.
pub const REBUILD_PENDING_META: &str = "chainstate_rebuild_pending";

/// A footprint of the PRE-FIX, non-atomic extension commit that
/// `reconcile_on_startup` cannot repair (audit DAG-11 residual).
///
/// The pre-fix extension wrote, one RocksDB write at a time and in this
/// order: per transaction `tx_index` row, created outputs, then the coinbase
/// row or the input deletions; the undo record LAST; then the tip pointer and
/// the CF_DAG record — and a write error was only logged. RocksDB recovers a
/// prefix of the issued writes after a crash, so:
///
/// * a crash (or error) before the undo record leaves `tx_index` rows of the
///   block — the first write for every transaction whose effects started —
///   pointing at a block WITHOUT an undo record: [`UnrecordedEffects`];
/// * a write error followed by the (logged-and-ignored) tip / CF_DAG writes
///   leaves the block on the applied chain without an undo record:
///   [`AppliedWithoutUndo`].
///
/// This release cannot produce either: every chain move commits UTXO effects,
/// undo record, chain indexes, DAG record and tip pointer in ONE batch
/// (`reorg::connect_plan`), so a crash leaves all of them or none. The
/// footprints can only come from a database written by an earlier release.
///
/// [`UnrecordedEffects`]: ChainStateFault::UnrecordedEffects
/// [`AppliedWithoutUndo`]: ChainStateFault::AppliedWithoutUndo
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStateFault {
    /// `rows` CF_TX_INDEX rows point at `block`, which has no undo record.
    UnrecordedEffects { block: BlockHash, rows: usize },
    /// `block` is on the applied chain (tip pointer back to genesis) but has
    /// no undo record.
    AppliedWithoutUndo { block: BlockHash },
    /// A previous [`rebuild_chain_state`] stopped between its two commits.
    RebuildInterrupted,
}

impl std::fmt::Display for ChainStateFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainStateFault::UnrecordedEffects { block, rows } => write!(
                f, "{} transaction-index row(s) point at block {} which has no undo record \
                    (UTXO effects of an interrupted pre-fix commit)", rows, hex::encode(&block[..8])),
            ChainStateFault::AppliedWithoutUndo { block } => write!(
                f, "block {} is on the applied chain but has no undo record", hex::encode(&block[..8])),
            ChainStateFault::RebuildInterrupted => write!(f, "a chain-state rebuild was interrupted"),
        }
    }
}

/// Detect every [`ChainStateFault`]. Cheap enough for every start-up: one
/// scan of the CF_UNDO keys and of CF_TX_INDEX, plus a walk of the applied
/// chain. The genesis block has no undo record by construction and is
/// exempt.
pub fn check_chain_state(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) -> Result<Vec<ChainStateFault>, String> {
    let mut faults = Vec::new();
    if store.get_meta(REBUILD_PENDING_META).map_err(|e| e.to_string())?.as_deref() == Some(&[1u8][..]) {
        faults.push(ChainStateFault::RebuildInterrupted);
    }
    let genesis = dag.read().store.genesis;
    let undo: HashSet<BlockHash> = store.undo_block_hashes().map_err(|e| e.to_string())?
        .into_iter().collect();
    let mut unrecorded: HashMap<BlockHash, usize> = HashMap::new();
    for (_, block) in store.tx_index_entries().map_err(|e| e.to_string())? {
        if Some(block) != genesis && !undo.contains(&block) {
            *unrecorded.entry(block).or_insert(0) += 1;
        }
    }
    let mut unrecorded: Vec<(BlockHash, usize)> = unrecorded.into_iter().collect();
    unrecorded.sort_unstable();
    faults.extend(unrecorded.into_iter()
        .map(|(block, rows)| ChainStateFault::UnrecordedEffects { block, rows }));

    let applied = store.get_meta("tip_hash").map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    if let Some(tip) = applied {
        let d = dag.read();
        // A tip pointer the DAG does not know is reconcile step 2's case.
        let mut cur = if d.has_block(&tip) { Some(tip) } else { None };
        while let Some(h) = cur {
            if Some(h) == genesis {
                break;
            }
            if !undo.contains(&h) {
                faults.push(ChainStateFault::AppliedWithoutUndo { block: h });
            }
            cur = d.get_block_data(&h).and_then(|x| x.selected_parent);
        }
    }
    Ok(faults)
}

/// What [`rebuild_chain_state`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RebuildReport {
    /// Chain-state rows deleted before the rebuild (0 when an interrupted
    /// rebuild was resumed).
    pub cleared_rows: usize,
    /// Consensus disqualification marks dropped (re-derived while connecting).
    pub cleared_marks: usize,
    /// Selected-chain blocks connected by this call (from genesis, or from
    /// where an interrupted rebuild stopped).
    pub connected_blocks: usize,
    /// An interrupted rebuild was resumed from its last committed chunk
    /// instead of starting over (audit B2-T0).
    pub resumed: bool,
}

/// Rebuild the chain state — UTXO set, coinbase heights, transaction index,
/// undo records, selected-chain indexes, address history, the shielded-pool
/// state (audit COH-2) and the explorer aggregates (audit NET-12) — from the
/// block bodies (audit DAG-11 residual).
///
/// 1. Check that every block of the best valid chain whose body was PRUNED
///    still has it (a pruned node cannot rebuild: it must resync from a fresh
///    data dir or an archival copy; a body missing above the pruning cursor
///    is waited for like on acceptance). Operator `invalidateblock` marks and
///    the context-free hardening-recheck marks (they depend on the stored
///    bodies only, and the recheck does not run again) are kept; connect-time
///    consensus marks are dropped, since they may have been made against the
///    inconsistent state, and are re-derived by step 3.
/// 2. One batch: delete every chain-state row (shielded state included), mark
///    the explorer aggregates incomplete, stage the genesis state (`seed`:
///    the carryover UTXOs and the genesis transaction index, exactly what
///    first boot writes), the genesis chain-index rows, the tip pointer =
///    genesis and the `REBUILD_PENDING_META` flag; the in-memory shielded
///    pool is reset to the genesis state.
/// 3. Connect the best valid chain from genesis with the normal atomic
///    machinery (`resolve_best_chain`: every block validated in its own
///    context, the shielded state staged into the same batches), block by
///    block in chunks of `reorg::MAX_BLOCKS_PER_COMMIT` (audit B2-T0: memory
///    bounded by one chunk, not by the chain), recompute the explorer
///    aggregates from scratch, then clear the flag.
///
/// Resumption (audit B2-T0): the flag is set by the batch that clears the
/// old state, and every later write of the rebuild is a chunk commit that
/// leaves a consistent applied tip. So when the flag is found set and the
/// start-up check reports nothing else ([`check_chain_state`] =
/// `[RebuildInterrupted]`), steps 1-2 are skipped and step 3 continues from
/// the applied tip; any other fault starts the rebuild over.
///
/// The result is the state a node that never crashed holds: the UTXO set is
/// the deterministic application of the best valid chain to the genesis
/// state (`node/tests/fix_chain_selection.rs` compares UTXO-set digests).
pub fn rebuild_chain_state(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    shielded: &Arc<RwLock<ShieldedPool>>,
    seed: &dyn Fn(&storage::Storage, &mut rocksdb::WriteBatch) -> Result<(), String>,
) -> Result<RebuildReport, String> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    let genesis = dag.read().store.genesis.ok_or("rebuild: the DAG has no genesis")?;

    let applied = store.get_meta("tip_hash").map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .filter(|t| dag.read().has_block(t));
    // PoWit finality: the pin the node had before the restart pins the
    // chain the rebuild (or its resumption) reconnects (the PoWit states and
    // their finality rows are per block, never part of the chain state
    // cleared below).
    crate::powit::load_finality_index(dag, store)?;
    crate::powit::refresh_finality_pin(dag, store);
    let resume_from = match applied {
        Some(tip) if check_chain_state(dag, store)? == vec![ChainStateFault::RebuildInterrupted] => Some(tip),
        _ => None,
    };

    // 1. Marks, then the bodies of the best valid chain under them.
    let marks = store.load_invalid_blocks_with_reasons().map_err(|e| e.to_string())?;
    let (keep, drop): (Vec<_>, Vec<_>) = marks.into_iter()
        .partition(|(_, r)| resume_from.is_some() || matches!(mark_kind(r), MarkKind::Operator | MarkKind::Hardening));
    {
        let (selected, all_edges) = split_marks(keep.iter().cloned());
        dag.write().reset_invalid_sets(selected, all_edges);
    }
    let pruned_below = store.pruned_height();
    let missing_body = {
        let d = dag.read();
        let mut cur = d.selected_tip();
        let mut missing = None;
        while let Some(h) = cur {
            if h == genesis {
                break;
            }
            let height = d.get_block_data(&h).map(|x| x.height).unwrap_or(0);
            if height < pruned_below && !store.has_block_body(&h).map_err(|e| e.to_string())? {
                missing = Some((h, height));
                break;
            }
            cur = d.get_block_data(&h).and_then(|x| x.selected_parent);
        }
        missing
    };
    if let Some((h, height)) = missing_body {
        // Nothing was written: restore the in-memory disqualified set.
        reload_persisted_marks(dag, store);
        return Err(format!(
            "rebuild impossible: the body of selected-chain block {} (h={}) has been \
             pruned. Resync from a fresh --data-dir (with --carryover-snapshot) or from \
             an archival node's data dir.",
            hex::encode(&h[..8]), height
        ));
    }

    let (start, cleared_rows) = match resume_from {
        Some(tip) => {
            warn!("resuming an interrupted chain-state rebuild from {}", hex::encode(&tip[..8]));
            (tip, 0)
        }
        None => {
            // 2. Clear + genesis state, one batch.
            let mut batch = rocksdb::WriteBatch::default();
            store.stage_aggregates_incomplete(&mut batch).map_err(|e| e.to_string())?;
            let cleared_rows = store.stage_clear_chain_state(&mut batch).map_err(|e| e.to_string())?;
            seed(store, &mut batch)?;
            if let Some(gb) = store.get_block(&genesis).map_err(|e| e.to_string())? {
                // The aggregates were just marked incomplete (rebuilt at the end):
                // no history counter is staged (B1-T11).
                store.stage_chain_index(&mut batch, &gb, 0, &HashMap::new(), &mut Default::default())
                    .map_err(|e| e.to_string())?;
            }
            for (h, _) in &drop {
                store.stage_clear_invalid_block(&mut batch, h).map_err(|e| e.to_string())?;
            }
            store.stage_meta(&mut batch, "tip_hash", &genesis).map_err(|e| e.to_string())?;
            store.stage_meta(&mut batch, REBUILD_PENDING_META, &[1u8]).map_err(|e| e.to_string())?;
            store.write_batch(batch).map_err(|e| e.to_string())?;
            shielded.write().reset_for_rebuild();
            (genesis, cleared_rows)
        }
    };

    // 3. Connect the best valid chain, chunk by chunk.
    let mut log = ResolveLog::default();
    let connected_blocks = match resolve_best_chain(dag, store, shielded, start, None, &mut log,
                                                    &MarkClears::default(), MissingBodies::Wait)? {
        Resolution::Connected { stopped: Some(m), .. } => {
            // The flag stays set: the next run resumes from the last
            // committed chunk.
            return Err(format!("chain-state rebuild interrupted (it resumes at the next start): {m}"));
        }
        Resolution::Connected { outcome, stopped: None } => outcome.connected.len(),
        Resolution::Unchanged => {
            if !log.invalid.is_empty() {
                persist_unchanged(dag, store, None, &log.invalid, &[])?;
            }
            0
        }
    };
    // Review of PR #15, finding 3: a block of the best chain that could not
    // be judged (no verdict, parked) left the rebuild on a shorter chain:
    // the rebuild is not complete. The flag stays set (the next start
    // resumes from the applied tip; `check_chain_state` reports
    // `RebuildInterrupted` meanwhile, so the node never starts on the
    // shortened chain) and the failure is reported, like Bitcoin Core's
    // init when a reindex cannot connect the best block.
    let parked = dag.read().no_verdict_parked();
    if let Some(first) = parked.first() {
        let reason = store.no_verdict_record(first).map(|r| r.reason).unwrap_or_default();
        let at = store.get_meta("tip_hash").ok().flatten()
            .map(|v| hex::encode(&v[..v.len().min(8)])).unwrap_or_default();
        return Err(format!(
            "chain-state rebuild incomplete: {} block(s) could not be validated (no verdict; first {}: {}); \
             the rebuild stays pending and resumes from the applied tip {} at the next start",
            parked.len(), hex::encode(&first[..8]), reason, at));
    }
    store.rebuild_aggregates(&std::sync::atomic::AtomicBool::new(false)).map_err(|e| e.to_string())?;
    store.put_meta(REBUILD_PENDING_META, &[0u8]).map_err(|e| e.to_string())?;
    warn!("chain state rebuilt from block bodies: {} row(s) cleared, {} consensus mark(s) re-derived, \
           {} block(s) connected{}", cleared_rows, drop.len(), connected_blocks,
           if resume_from.is_some() { " (resumed)" } else { "" });
    Ok(RebuildReport { cleared_rows, cleared_marks: drop.len(), connected_blocks, resumed: resume_from.is_some() })
}

// ── Blocks in the DAG without a usable body (audit DAG-6 / VAL-1x) ──────────
//
// Two situations leave a block in the DAG without a body the node can use:
// its body failed a rule that depends on witness bytes the id does not commit
// to (below the hardening activation, `drop_body_and_wait`), or its body was
// pruned while it was on the selected chain and a reorg then left it
// unapplied (DAG-6: no reorg-depth limit, so the chain through it can become
// the best one again). Both are ONE state: the block waits for a body
// (`GhostDAG::mark_body_pending`, in memory) — set by `resolve_best_chain`
// for every block of the best chain it cannot connect, or by
// [`request_bodies`] for the bodies an operator override needs —, and
// [`awaits_body`] is the one predicate every ingress path consults (gossip
// additionally takes only the answer to the node's own directed pull). The
// message processor requests those bodies through its missing-parent tracker
// (`ingress::awaited_bodies_to_request`, at most
// `ingress::MAX_BODY_PULLS_IN_FLIGHT` being fetched at once), and a copy that
// arrives goes through `accept_block`'s body-replacement path: bound to the
// header height the DAG parents imply, the expected bits, the timestamp, the
// hardening block rules (witness commitment), the proof of work and the
// rejected-witness-root memo, then stored with the metadata acceptance
// derives.

/// The blocks a connect of a block with these `parents` would APPLY that
/// have no stored body: its selected-chain ancestors that are not applied
/// (no undo record), walking down from the parent of greatest
/// `(blue_work, blue_score, hash)`, nearest first, at most `limit`.
///
/// Operator overrides name exactly these when the chain they move to needs
/// bodies this pruned node no longer has ([`OverrideError::MissingBodies`]).
pub fn missing_bodies_below(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    parents: &[BlockHash],
    limit: usize,
) -> Vec<BlockHash> {
    let d = dag.read();
    let genesis = d.store.genesis;
    let mut cur = parents.iter()
        .filter_map(|p| d.get_block_data(p).map(|x| (x.blue_work, x.blue_score, *p)))
        .max()
        .map(|(_, _, p)| p);
    let mut out = Vec::new();
    while let Some(h) = cur {
        if out.len() >= limit || Some(h) == genesis || store.has_undo_data(&h).unwrap_or(true) {
            break;
        }
        if !store.has_block_body(&h).unwrap_or(true) {
            out.push(h);
        }
        cur = d.get_block_data(&h).and_then(|x| x.selected_parent);
    }
    out
}

/// Make the blocks of `hashes` whose body is wanted wait for one
/// (`GhostDAG::mark_body_pending`), so [`awaits_body`] admits a copy and the
/// message processor requests it: blocks in the DAG, not the genesis, without
/// a stored body and NOT applied (an applied block never needs its body: a
/// rollback works from its undo record), and not on the selected chain of
/// the selected tip (marking those would move the selected tip without a
/// connect; the acceptance pipeline marks the bodies the best chain needs
/// itself). Returns the hashes marked. Used for the bodies an operator
/// override needs (audit DAG-6).
pub fn request_bodies(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    hashes: &[BlockHash],
) -> Vec<BlockHash> {
    let mut d = dag.write();
    let genesis = d.store.genesis;
    let tip = d.selected_tip();
    let mut marked = Vec::new();
    for h in hashes {
        let wanted = d.has_block(h)
            && Some(*h) != genesis
            && matches!(store.has_block_body(h), Ok(false))
            && matches!(store.has_undo_data(h), Ok(false))
            && !tip.is_some_and(|t| d.is_on_selected_chain_of(h, &t));
        if wanted {
            d.request_body(*h);
            marked.push(*h);
        }
    }
    marked
}

// ── Operator recovery: invalidateblock / reconsiderblock (DAG-6) ─────────────

/// Reason prefix of a mark a block inherits from its disqualified selected
/// parent (`accept_block`, a new block on a disqualified chain).
pub const INHERITED_REASON_PREFIX: &str = "selected parent ";

/// What a persisted disqualification mark records, by its reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkKind {
    /// Operator `invalidateblock` ([`OPERATOR_INVALIDATE_REASON`]).
    Operator,
    /// The context-free hardening block rules (start-up recheck of blocks a
    /// pre-upgrade binary stored, or a block referencing one): reason
    /// starting with [`HARDENING_RECHECK_REASON`], reloaded as an all-edges
    /// root.
    Hardening,
    /// Inherited from a disqualified selected parent
    /// ([`INHERITED_REASON_PREFIX`]): a consequence, not a verdict on the
    /// block itself.
    Inherited,
    /// The block itself failed a connect-time consensus rule in its own
    /// selected-chain context.
    Consensus,
}

/// Classify a persisted mark by its recorded reason.
pub fn mark_kind(reason: &str) -> MarkKind {
    if reason == OPERATOR_INVALIDATE_REASON {
        MarkKind::Operator
    } else if reason.starts_with(HARDENING_RECHECK_REASON) {
        MarkKind::Hardening
    } else if reason.starts_with(INHERITED_REASON_PREFIX) {
        MarkKind::Inherited
    } else {
        MarkKind::Consensus
    }
}

/// Persisted marks as GhostDAG loads them: (roots spread along selected-parent
/// chains, roots spread through every parent edge — hardening marks).
fn split_marks<I: IntoIterator<Item = (BlockHash, String)>>(marks: I) -> (Vec<BlockHash>, Vec<BlockHash>) {
    let mut selected = Vec::new();
    let mut all_edges = Vec::new();
    for (h, reason) in marks {
        if mark_kind(&reason) == MarkKind::Hardening {
            all_edges.push(h);
        } else {
            selected.push(h);
        }
    }
    (selected, all_edges)
}

/// Re-derive the in-memory disqualified set from the persisted marks (the
/// in-memory body-pending roots are kept): after an override that committed
/// nothing.
fn reload_persisted_marks(dag: &Arc<RwLock<consensus::GhostDAG>>, store: &storage::Storage) {
    match store.load_invalid_blocks_with_reasons() {
        Ok(marks) => {
            let (selected, all_edges) = split_marks(marks);
            dag.write().reset_invalid_sets(selected, all_edges);
        }
        Err(e) => error!("cannot re-read the persisted invalid-block set: {}", e),
    }
}

/// Result of an operator chain override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOverride {
    /// The applied tip after the call.
    pub tip: BlockHash,
    /// Its DAG height.
    pub tip_height: u64,
    /// Selected-chain blocks rolled back / connected by the call.
    pub rolled_back: usize,
    pub connected: usize,
    /// Blocks marked (invalidate) or unmarked (reconsider).
    pub affected: usize,
}

/// Why an operator chain override changed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideError {
    /// Refused or failed (unknown block, genesis, storage error, ...).
    Failed(String),
    /// Pruned nodes: the chain to move to must apply blocks whose bodies this
    /// node pruned (`reorg::ERR_MISSING_BODIES`). Nothing was committed and
    /// the marks are as before the call. `missing` are the next bodies to
    /// re-fetch (unapplied selected-chain blocks without a body, nearest the
    /// new tip first, at most `ingress::MAX_BODY_REFETCH`); they now wait for
    /// a body ([`request_bodies`]: the processor requests them), and once they
    /// are restored the same call is retried (and asks for the next ones).
    MissingBodies { missing: Vec<BlockHash>, reason: String },
}

impl std::fmt::Display for OverrideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverrideError::Failed(m) => f.write_str(m),
            OverrideError::MissingBodies { missing, reason } => write!(
                f, "{} block bod(ies) must be re-fetched first ({})", missing.len(), reason),
        }
    }
}

impl std::error::Error for OverrideError {}

impl From<String> for OverrideError {
    fn from(m: String) -> Self {
        OverrideError::Failed(m)
    }
}

impl From<&str> for OverrideError {
    fn from(m: &str) -> Self {
        OverrideError::Failed(m.to_string())
    }
}

/// Shared tail of the two operator calls: move the applied chain to the best
/// valid block, persisting `log` marks and removing the `clears` marks in the
/// same batch (a consensus mark only if the move re-validated its block),
/// then refresh the mempool and the RPC-visible state. The caller's in-memory
/// marks are still in place on return; on `Err` the caller restores them from
/// disk (nothing was committed).
#[allow(clippy::too_many_arguments)]
fn apply_operator_override(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
    log: Vec<(BlockHash, String)>,
    clears: MarkClears,
    affected: usize,
) -> Result<ChainOverride, OverrideError> {
    let applied = store.get_meta("tip_hash").map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or("no applied tip pointer")?;
    let (mut rolled_back, mut connected) = (0usize, 0usize);
    let mut rlog = ResolveLog { invalid: log, body_rejected: Vec::new() };
    let resolution = match resolve_best_chain(dag, store, shielded, applied, None, &mut rlog,
                                              &clears, MissingBodies::Stop) {
        Ok(r) => r,
        Err(m) if m.contains(reorg::ERR_MISSING_BODIES) => {
            // DAG-6, pruned nodes: name the bodies to re-fetch while the
            // operator's marks still select the candidate that needs them.
            let cand = dag.read().selected_tip();
            let missing = match cand {
                Some(c) => missing_bodies_below(dag, store, &[c], crate::ingress::MAX_BODY_REFETCH),
                None => Vec::new(),
            };
            return Err(if missing.is_empty() {
                OverrideError::Failed(m)
            } else {
                OverrideError::MissingBodies { missing, reason: m }
            });
        }
        Err(m) => return Err(OverrideError::Failed(m)),
    };
    // First, before anything reads the valid tips (the next template height
    // below, the TipChanged parents): the consensus marks this move did not
    // re-validate are persisted still, so they hold in memory again.
    remark_unvalidated(dag, store, &clears.if_applied);
    let mut stopped = None;
    match resolution {
        Resolution::Unchanged => {
            persist_unchanged(dag, store, None, &rlog.invalid, &clears.always)?;
            // The marks change the valid tips, hence the template height.
            sync_mempool_next_height(dag, store, mempool);
        }
        Resolution::Connected { outcome, stopped: s } => {
            rolled_back = outcome.rolled_back();
            connected = outcome.connected.len();
            warn!("operator override: rolled back {} block(s), connected {}", rolled_back, connected);
            // The next height on the DAG after the move: the template height
            // (never the new tip's header height + 1, DAG-8).
            let next_height = crate::template::next_template_height(&dag.read(), store);
            update_mempool_after_connect(store, mempool, &outcome, next_height);
            stopped = s;
        }
    }
    if let Some(m) = stopped {
        // B2-T0: chunks were committed (marks included) before the move
        // stopped; the caller re-reads the marks from disk and the next
        // acceptance or start resumes the move.
        return Err(if m.contains(reorg::ERR_MISSING_BODIES) {
            let cand = dag.read().selected_tip();
            let missing = match cand {
                Some(c) => missing_bodies_below(dag, store, &[c], crate::ingress::MAX_BODY_REFETCH),
                None => Vec::new(),
            };
            if missing.is_empty() { OverrideError::Failed(m) } else { OverrideError::MissingBodies { missing, reason: m } }
        } else {
            OverrideError::Failed(m)
        });
    }
    let (tip, tip_height, score) = {
        let d = dag.read();
        let t = d.selected_tip().ok_or("DAG has no tip")?;
        let data = d.get_block_data(&t).cloned().ok_or("tip vanished")?;
        (t, data.height, data.blue_score)
    };
    {
        let mut s = node_state.write();
        s.tip_blue_score = score;
        s.block_count = dag.read().block_count() as u64;
        s.mempool_size = mempool.size();
    }
    if let Some(tx) = tip_tx {
        // Presence only (no decode), as on acceptance.
        let has_body = |h: &[u8; 32]| store.has_block_body(h).unwrap_or(false);
        let d = dag.read();
        if let Some(best) = d.best_bodied_tip(has_body) {
            if let Some(data) = d.get_block_data(&best).cloned() {
                // The template's own parents (memoized parent predicate).
                let parents = crate::template::template_parents_and_height(&d, store).0;
                drop(d);
                let bits = store.get_meta("current_bits").ok().flatten()
                    .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                    .unwrap_or(0x1d00ffff_u32);
                let _ = tx.send(tip::TipChanged {
                    hash: best, height: data.height, blue_score: data.blue_score, parents, bits,
                });
            }
        }
    }
    Ok(ChainOverride { tip, tip_height, rolled_back, connected, affected })
}

/// After a committed `reconsiderblock` move: every consensus mark in
/// `if_applied` whose block the move did not re-validate (not applied now)
/// is still persisted, so it holds in memory again, as a persistent root.
/// Also when the block is already disqualified in memory only through a
/// body-pending mark (its stored body was just rejected for a
/// witness-dependent reason, or it waits for an ancestor's body): that mark
/// is cleared when a body arrives, and without the root the block would
/// then connect while `invalid_block/<id>` stays on disk, to be disqualified
/// again at the next start (review of the P3 merge). The block is not an
/// ancestor of the applied tip (it is not applied), so the selected tip does
/// not move. Call before anything reads the valid tips.
fn remark_unvalidated(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    if_applied: &[BlockHash],
) {
    for r in if_applied {
        // A read error counts as "still persisted" (the stricter memory).
        let persisted = store.invalid_block_reason(r).map(|m| m.is_some()).unwrap_or(true);
        if persisted && !store.has_undo_data(r).unwrap_or(false) {
            dag.write().mark_invalid(*r);
        }
    }
}

/// After an override that committed nothing: restore the in-memory marks from
/// disk and, when the chain to move to needs pruned bodies, make them wait for
/// a body ([`request_bodies`]) so the processor fetches them.
fn after_failed_override(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    err: &OverrideError,
) {
    reload_persisted_marks(dag, store);
    if let OverrideError::MissingBodies { missing, .. } = err {
        let marked = request_bodies(dag, store, missing);
        info!("operator override: {} pruned block bod(ies) requested; retry once they arrived",
            marked.len());
    }
}

/// Operator `invalidateblock` (Bitcoin Core's `InvalidateBlock`): disqualify
/// `hash` and every block whose selected-parent chain passes through it,
/// persist the mark (`invalid_block/<hash>`, reason
/// [`OPERATOR_INVALIDATE_REASON`]) and move the applied chain to the best
/// valid block that remains — rolling back past `hash` if it was applied.
/// The move commits in chunks of at most `reorg::MAX_BLOCKS_PER_COMMIT`
/// blocks (audit B2-T0), the mark with the first one; each chunk is atomic
/// and leaves a consistent applied tip. Survives restarts; undone by
/// [`reconsider_block`]. A block that already carries a persisted mark keeps
/// it (a consensus or hardening verdict never becomes an operator mark the
/// operator could clear without re-validation): no new mark is written. On a
/// pruned node whose new chain needs pruned bodies it returns
/// [`OverrideError::MissingBodies`] (they are requested; retry): nothing is
/// written when the first plan needs them, but when a block of a later chunk
/// fails validation and the chain resolved again needs pruned bodies, the
/// chunks committed until then (the mark included) stand. Likewise
/// [`OverrideError::Failed`] can follow committed chunks (a storage
/// failure). In both cases the move resumes on the retried call, with the
/// next block, or at the next start.
#[allow(clippy::too_many_arguments)]
pub fn invalidate_block(
    hash: BlockHash,
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<ChainOverride, OverrideError> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    if !dag.read().has_block(&hash) {
        return Err(format!("block {} not found", hex::encode(hash)).into());
    }
    if dag.read().store.genesis == Some(hash) {
        return Err("the genesis block cannot be invalidated".into());
    }
    if let Some(reason) = store.invalid_block_reason(&hash).map_err(|e| e.to_string())? {
        info!("invalidateblock {}: already disqualified ({}); nothing to do", hex::encode(&hash[..8]), reason);
        return apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded,
                                       Vec::new(), MarkClears::default(), 0);
    }
    let marked = dag.write().mark_invalid(hash);
    warn!("invalidateblock {}: {} block(s) disqualified by the operator",
        hex::encode(&hash[..8]), marked.len());
    let log = vec![(hash, OPERATOR_INVALIDATE_REASON.to_string())];
    let res = apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded, log,
                                      MarkClears::default(), marked.len());
    if let Err(e) = &res {
        // Nothing was committed.
        after_failed_override(dag, store, e);
    }
    res
}

/// Operator `reconsiderblock` (Bitcoin Core's `ReconsiderBlock`): consider
/// every persisted disqualification whose root is `hash`, a selected-chain
/// ancestor of `hash` or a block whose selected chain passes through `hash`,
/// and move the applied chain to the best valid block, committed in chunks
/// like [`invalidate_block`] (the marks removed with the first one):
///
/// * operator marks and marks inherited from a selected parent are removed;
/// * a hardening-recheck mark (context-free, audit VAL/CRY hardening rules)
///   is removed only if the stored body now passes those rules
///   (`classify_stored_block`); otherwise it stays (a pruned body cannot be
///   re-checked and stays too);
/// * a connect-time consensus mark is removed only by the batch that
///   RE-VALIDATES the block — the move applies it, after validating it in its
///   own context; a block the move does not apply keeps its mark, and one
///   that fails again is disqualified again with its new reason.
///
/// Like [`invalidate_block`], it returns [`OverrideError::MissingBodies`] when
/// the chain to move to needs bodies this pruned node no longer has: nothing
/// is written when the first plan needs them, and the chunks committed
/// before a later failure stand (the move resumes on the retried call).
#[allow(clippy::too_many_arguments)]
pub fn reconsider_block(
    hash: BlockHash,
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<ChainOverride, OverrideError> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    if !dag.read().has_block(&hash) {
        return Err(format!("block {} not found", hex::encode(hash)).into());
    }
    let marks = store.load_invalid_blocks_with_reasons().map_err(|e| e.to_string())?;
    let activation = core::activation::hardening_activation_height();
    let mut clears = MarkClears::default();
    let mut kept: Vec<(BlockHash, String)> = Vec::new();
    let mut still_failing = 0usize;
    {
        let d = dag.read();
        for (r, reason) in marks {
            if !(d.is_on_selected_chain_of(&r, &hash) || d.is_on_selected_chain_of(&hash, &r)) {
                kept.push((r, reason));
                continue;
            }
            match mark_kind(&reason) {
                MarkKind::Operator | MarkKind::Inherited => clears.always.push(r),
                MarkKind::Hardening => {
                    let passes = matches!(store.get_block(&r), Ok(Some(b))
                        if classify_stored_block(&b, activation) == StoredBlockCheck::Valid);
                    if passes {
                        clears.always.push(r);
                    } else {
                        still_failing += 1;
                        kept.push((r, reason));
                    }
                }
                MarkKind::Consensus => clears.if_applied.push(r),
            }
        }
    }
    if still_failing > 0 {
        warn!("reconsiderblock {}: {} mark(s) kept: the block still fails the hardening block rules \
               (or its body is pruned and cannot be re-checked)", hex::encode(&hash[..8]), still_failing);
    }
    let before = dag.read().invalid_count();
    {
        let (selected, all_edges) = split_marks(kept);
        dag.write().reset_invalid_sets(selected, all_edges);
    }
    let affected = before.saturating_sub(dag.read().invalid_count());
    info!("reconsiderblock {}: {} mark(s) removed, {} re-validated by the move, {} block(s) re-qualified",
        hex::encode(&hash[..8]), clears.always.len(), clears.if_applied.len(), affected);
    let res = apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded, Vec::new(), clears, affected);
    if let Err(e) = &res {
        after_failed_override(dag, store, e);
    }
    res
}

/// Operator finality settings (RPC `ignorefinalized`, `reconsiderfinalized`,
/// `setfinalitycheckpoint`; PoWit audit findings 2 and 3): the escape hatch
/// Bitcoin Core's `invalidateblock` / `reconsiderblock` give for blocks,
/// for the finality pin. Persist the setting (`powit::apply_finality_op`),
/// recompute the pin, and move the applied chain to the best valid block
/// under it, committed in chunks like [`invalidate_block`]. No block is
/// marked: setting a finalized checkpoint aside leaves its blocks valid; the
/// pin falls back to the node's remaining own finality, which a finalized
/// checkpoint that conflicted with the one set aside may now advance, and
/// the most work decides above it. This is how an operator moves a node off
/// a finality it keeps against a conflict (review HIGH 1). The setting stands even when
/// the move first needs pruned bodies ([`OverrideError::MissingBodies`]: they
/// are requested, retry) or stops on a storage failure (the next acceptance
/// or start resumes it). `affected` in the result is 1 when the pin moved.
#[allow(clippy::too_many_arguments)]
pub fn override_finality(
    op: crate::powit::FinalityOp,
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<ChainOverride, OverrideError> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    crate::powit::apply_finality_op(op, dag, store)?;
    let before = dag.read().finalized();
    let after = crate::powit::refresh_finality_pin(dag, store).pin;
    warn!("operator finality setting {:?}: pin {:?} -> {:?}", op,
        before.map(|(h, x)| (hex::encode(&h[..8]), x)), after.map(|(h, x)| (hex::encode(&h[..8]), x)));
    let res = apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded, Vec::new(),
                                      MarkClears::default(), usize::from(before != after));
    if let Err(e) = &res {
        after_failed_override(dag, store, e);
    }
    res
}

// ── Unified TX validation ────────────────────────────────────────────────────
// FIX #10: Single validation core used by all code paths.

/// Core input validation logic shared by all TX validation paths.
/// Resolves each input's UTXO (rejecting duplicate outpoints), then checks
/// every input script under the rules of a block at header height
/// `block_height` (version rule, witness, pubkey hash vs prevout, hybrid
/// signature under the digest the version selects — cached, see
/// `admission::verify_input_scripts`), value conservation and the consensus
/// minimum fee. All amounts are MoneyRange-checked (VAL-11). Uses the
/// process-wide hardening activation height.
pub fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    spent_set:    Option<&mut HashSet<([u8; 32], u32)>>,
    block_height: u64,
) -> Result<u64, String> {
    // A lookup error is a read failure, reported as such (no verdict).
    let lookup = |txid: &[u8; 32], idx: u32| utxo_lookup(txid, idx).map_err(ViewError::io);
    validate_tx_inputs_classified(
        tx, &lookup, spent_set, block_height, core::activation::hardening_activation_height(),
    )
    .map_err(TxFailure::into_message)
}

/// Prevout lookup used by the input validation: `Ok(None)` = not found, a
/// read failure is a [`ViewError`] (no verdict, re-audit B1-T12).
type UtxoLookup<'a> = dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, ViewError> + 'a;

/// [`validate_tx_inputs`] with the failure classified and an explicit
/// hardening activation height: [`check_tx_inputs_committed`] (id-committed)
/// then [`check_tx_witnesses`] (witness-dependent). Returns the fee.
fn validate_tx_inputs_classified(
    tx:           &core::Transaction,
    utxo_lookup:  &UtxoLookup<'_>,
    spent_set:    Option<&mut HashSet<([u8; 32], u32)>>,
    block_height: u64,
    activation_height: u64,
) -> Result<u64, TxFailure> {
    let committed = check_tx_inputs_committed(tx, utxo_lookup, spent_set, block_height, activation_height)?;
    check_tx_witnesses(tx, &committed, block_height, activation_height, ScriptChecks::Full)?;
    Ok(committed.fee)
}

/// What the id-committed checks of a transaction leave to its witness checks.
#[derive(Debug)]
struct CommittedTx {
    prevouts: Vec<core::TxOutput>,
    fee: u64,
    /// The txids of the prevouts created earlier in the same block (0
    /// confirmations for a relative timelock); empty off the block path.
    in_block: HashSet<[u8; 32]>,
}

/// The checks of `tx` that depend only on data its txid commits to (never
/// witness-dependent, re-audit B1-T13): no duplicate or already-spent
/// outpoint, every prevout exists, the input and output values
/// (MoneyRange, VAL-11; inputs >= outputs), the transaction version rule,
/// and two checks that read witness-bearing rules but that no `script_sig`
/// can satisfy:
///
/// * the fee must reach `min_tx_fee_for_sat` of the size `tx` has with every
///   `script_sig` empty (its one-byte length prefix only: the smallest any
///   body with this txid can have, so at least `MIN_TX_FEE_SAT`); the
///   size-based minimum of the actual body is checked by
///   [`check_tx_witnesses`];
/// * every prevout's `script_pubkey` must be one of the two output kinds
///   (`core::policy::output_kind`): a 20-byte key hash, which a public key
///   must hash to (`sighash::check_input_witnesses`, 20 bytes of SHA3-256),
///   or a 33-byte spend policy, which a revealed policy must hash to. No
///   witness spends any other script (no key hashes to it and no policy
///   witness is accepted for it). Reported as the pubkey-hash failure the
///   witness check would report. (This chain has enforced the output kinds
///   on every output since before the 2026-10-14 reset, so such a coin
///   exists only in a hand-built state.)
///
/// The verdict of a transaction is unchanged (every rule must pass); only
/// which failure is reported first, and so its class, moved.
fn check_tx_inputs_committed(
    tx:           &core::Transaction,
    utxo_lookup:  &UtxoLookup<'_>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
    block_height: u64,
    activation_height: u64,
) -> Result<CommittedTx, TxFailure> {
    let mut total_in = 0u64;

    // C-R3-2: the intra-tx duplicate-outpoint check is UNCONDITIONAL.
    let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut prevouts: Vec<core::TxOutput> = Vec::with_capacity(tx.inputs.len());

    for inp in tx.inputs.iter() {
        let outpoint = (inp.prev_txid, inp.prev_index);
        let cross_tx_dup = spent_set.as_ref().is_some_and(|s| s.contains(&outpoint));
        if cross_tx_dup || !local_spent.insert(outpoint) {
            return Err(format!("double-spend: {}:{} already consumed",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index).into());
        }
        let utxo = utxo_lookup(&inp.prev_txid, inp.prev_index)?
            .ok_or_else(|| format!("UTXO {}:{} not found",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;
        total_in = core::limits::money_add(total_in, utxo.value)
            .map_err(|e| format!("input overflow: {}", e))?;
        prevouts.push(utxo);
    }

    // The version rule depends only on data the txid commits to (and below
    // the activation every version is valid): never witness-dependent.
    core::sighash::check_tx_version(tx.version, block_height, activation_height)?;

    if let Some(spent) = spent_set.as_mut() {
        for inp in &tx.inputs {
            spent.insert((inp.prev_txid, inp.prev_index));
        }
    }

    let total_out = core::limits::check_tx_money_range(tx)
        .map_err(|e| format!("output sum overflow: {}", e))?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out).into());
    }
    let fee = total_in - total_out;
    // The floor no witness can lower (B1-T13): the size with every
    // script_sig empty (a one-byte length each), and the 1% of the value
    // sent to others (outputs and prevouts are committed). Same message as
    // `core::check_min_fee`, of which it is the witness-free part.
    let floor_size = tx.wire_size(false) + tx.inputs.len();
    let floor = core::tokenomics::min_tx_fee_for_sat(floor_size, core::paid_to_others_sat(tx, &prevouts));
    if fee < floor {
        return Err(format!(
            "fee {fee} below consensus minimum {floor} for a transaction of at least {floor_size} bytes \
             (whatever its script_sigs)"
        ).into());
    }
    if let Some(i) = prevouts.iter().position(|p| core::policy::output_kind(&p.script_pubkey).is_none()) {
        return Err(format!(
            "pubkey mismatch at input {} (the coin's script is neither a 20-byte key hash nor a spend policy)", i
        ).into());
    }
    Ok(CommittedTx { prevouts, fee, in_block: HashSet::new() })
}

/// The checks of `tx` that depend on its `script_sig`s, after
/// [`check_tx_inputs_committed`]: the scripts under the rules of a block at
/// `block_height` (`script_sig` framing — canonical from the activation —,
/// public key hash, signature; `admission::verify_input_scripts_at`) and the
/// minimum fee measured on the full wire size (`core::check_min_fee`).
/// Witness-dependent (the caller clears the flag at/after the activation,
/// where the block's witness commitment fixes every `script_sig`). With
/// [`ScriptChecks::SignaturesAssumed`] the signature step is left out
/// (`admission::check_input_scripts_without_signatures_at`; see
/// [`validate_block_in_view_classified_with`]).
fn check_tx_witnesses(
    tx: &core::Transaction,
    committed: &CommittedTx,
    block_height: u64,
    activation_height: u64,
    scripts: ScriptChecks,
) -> Result<(), TxFailure> {
    match scripts {
        ScriptChecks::Full => {
            admission::verify_input_scripts_at(tx, &committed.prevouts, block_height, activation_height)
        }
        ScriptChecks::SignaturesAssumed => admission::check_input_scripts_without_signatures_at(
            tx, &committed.prevouts, block_height, activation_height,
        ),
    }
    .map_err(TxFailure::witness)?;
    core::check_min_fee(tx, committed.fee, &committed.prevouts).map_err(TxFailure::witness)?;
    Ok(())
}

/// Compute the total fee the miner's OWN block template may claim across
/// `txs`, reading prevout values from the persistent UTXO set.
///
/// SECURITY (Legacy N-7): counts each of a transaction's outpoints ONCE —
/// insert-as-check, mirroring the C-R3-2 duplicate-outpoint rejection real
/// admission applies. A transaction listing the same outpoint N times
/// contributes zero (it can never be mined).
pub fn miner_template_total_fees(
    txs:   &[core::Transaction],
    store: &storage::Storage,
) -> u64 {
    txs.iter().map(|tx| {
        let mut seen_outpoints: HashSet<([u8; 32], u32)> = HashSet::new();
        let mut has_duplicate_outpoint = false;
        let mut total_in: u64 = 0;
        for inp in &tx.inputs {
            if !seen_outpoints.insert((inp.prev_txid, inp.prev_index)) {
                has_duplicate_outpoint = true;
                continue;
            }
            if let Ok(Some(out)) = store.get_utxo(&inp.prev_txid, inp.prev_index) {
                total_in = total_in.saturating_add(out.value);
            }
        }
        if has_duplicate_outpoint {
            return 0;
        }
        let total_out: u64 = tx.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
            .unwrap_or(u64::MAX);
        total_in.saturating_sub(total_out)
    }).fold(0u64, |a, b| a.saturating_add(b))
}

/// Validate a transaction within a block context.
/// Uses both in-block outputs and persistent UTXO set, with double-spend
/// tracking. No coinbase-maturity check (see
/// [`validate_tx_in_block_with_maturity`]).
#[allow(dead_code)]
pub fn validate_tx_in_block(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
) -> Result<(), String> {
    validate_tx_in_block_with_maturity(block, tx, store, spent_in_block, 0)?;
    Ok(())
}

/// FIX VULN-03: Validate the non-coinbase transaction `tx` of `block` against
/// the COMMITTED store, including coinbase maturity. Returns the fee.
///
/// SECURITY (Legacy C-2): the in-block prevout map holds ONLY the
/// transactions STRICTLY BEFORE `tx` in `block.transactions` (identified by
/// txid), so a transaction can never spend a later transaction's output.
///
/// Heights: every consensus rule is evaluated at the block's header height
/// `block.height` under the process-wide hardening activation, exactly as
/// the connect path (`validate_block_in_view`) evaluates it for this
/// transaction: the transaction rules (version 3 / sighash v3 / canonical
/// witnesses, `core::sighash`), BIP30 for `tx`'s outputs (audit VAL-2) and
/// no spend of the block's own coinbase (audit VAL-3). `current_height` is
/// used ONLY for coinbase maturity (`0` skips it). Below the activation it
/// is the header height maturity compares (the connect path uses
/// `block.height`); from the activation maturity counts the block's own
/// selected-chain position (its DAG height from its parents' DAG records,
/// [`MaturityRule::SelectedChainDepth`], re-audit B1-T14) and any non-zero
/// `current_height` only switches it on. Unlike the connect path this checks one transaction, so
/// the block-level rules (BIP30 of the other transactions, the coinbase
/// value) are the caller's.
pub fn validate_tx_in_block_with_maturity(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    current_height: u64,
) -> Result<u64, String> {
    let tx_txid = tx.txid();
    let cutoff = block.transactions.iter()
        .position(|t| t.txid() == tx_txid)
        .unwrap_or(block.transactions.len());
    // Same gate and height as `validate_block_in_view_classified_at`.
    let activation_height = core::activation::hardening_activation_height();
    let view: &storage::Storage = store;
    let hardened = core::block_rules::rules_active_at(block.height, activation_height);
    // BIP30 / no own-coinbase spend: this chain's rules at every height
    // (see `validate_block_in_view_classified_at`).
    check_no_unspent_overwrite(view, tx).map_err(TxFailure::into_message)?;
    let same_block_coinbase = block.transactions.first().map(|cb| cb.txid());
    let earlier: HashMap<([u8; 32], u32), core::TxOutput> = block.transactions[..cutoff]
        .iter()
        .filter(|t| !t.is_coinbase())
        .flat_map(|t| {
            let txid = t.txid();
            t.outputs.iter().enumerate().map(move |(i, o)| ((txid, i as u32), o.clone()))
        })
        .collect();
    // Coinbase maturity: off for `current_height == 0`; otherwise the rule
    // of the block's regime, as on the connect path (below the activation
    // the header height `current_height`; from it the block's own
    // selected-chain position, re-audit B1-T14).
    let spend_dag_height = || block_dag_height(view, block);
    let maturity = match (current_height, hardened) {
        (0, _) => MaturityRule::Skip,
        (_, true) => MaturityRule::SelectedChainDepth(&spend_dag_height),
        (h, false) => MaturityRule::HeaderHeights(h),
    };
    // Relative timelocks: the block's own measure, as on the connect path
    // (never skipped).
    let timelocks = if hardened {
        MaturityRule::SelectedChainDepth(&spend_dag_height)
    } else {
        MaturityRule::HeaderHeights(block.height)
    };
    validate_tx_in_view(
        tx, view, &earlier, spent_in_block, block.height, maturity, timelocks, same_block_coinbase.as_ref(),
        activation_height,
    )
    .map_err(TxFailure::into_message)
}

/// Standalone tx validation (no mempool context): the shared admission rules
/// (`mempool::admission::check_transaction`) with signatures, evaluated for a
/// block at `current_height` (`0` skips the maturity check). Returns the fee.
pub fn validate_tx_standalone(
    tx:    &core::Transaction,
    store: &Arc<storage::Storage>,
    current_height: u64,
) -> Result<u64, String> {
    let policy = admission::AdmissionPolicy {
        next_block_height: current_height,
        check_signatures: true,
        use_reject_filter: false,
    };
    admission::check_transaction(store, None, tx, &policy).map_err(|e| e.to_string())
}
