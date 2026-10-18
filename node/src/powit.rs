//! Node side of PoW + PoWit (Proof of Witnesses).
//!
//! Consensus rules live in `gnb_crypto::core::powit` and `core::witness_share`;
//! this module supplies what needs the DAG and storage:
//!
//! - [`block_state`]: validate a block's PoWit section in context (share
//!   proofs, attested blocks, share uniqueness) and compute its PoWit state
//!   from its selected parent's state.
//! - [`PowitPool`]: gossiped shares, attestations and equivocation proofs
//!   waiting for a block, admitted only after validation.
//! - [`template_body`]: the PoWit section for a block template, chosen so the
//!   template is always valid.
//! - [`WitnessDuty`]: a witness node's attestation signer, with persistent
//!   protection against ever signing two conflicting links.
//! - [`mine_share`]: one round of share mining for a payout key.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::consensus::finality::{Anchor, AnchorSetting, PinOutcome, PinPolicy};
use crate::consensus::GhostDAG;
use crate::storage::Storage;
use gnb_crypto::core::powit::poci::{self, Configuration, PociEvidence, PociParams, PociState};
use gnb_crypto::core::powit::{self, Attestation, BlockInput, ChainView, Checkpoint, Equivocation,
                              KeyId, PowitBody, PowitParams, PowitState, Regime, WitnessExit, WitnessRejoin};
use gnb_crypto::core::witness_share::{self, WitnessShare, SHARE_WINDOW};
use gnb_crypto::core::{self, activation, Block};

type Hash = [u8; 32];

mod store;

/// The second hardening activation height the PoWit rules switch at
/// (`core::powit::Regime`; process-wide, the node's chain schedule):
/// consensus (`block_state`), the pool, templates and the witness duty all
/// read this one value, so each judges an item by the rules of the block
/// that may include it.
fn hardening2_height() -> u64 {
    activation::hardening2_activation_height()
}

/// The liveness activation height (witness exits; `core::liveness`),
/// process-wide like [`hardening2_height`].
fn liveness_height() -> u64 {
    core::liveness::liveness_activation_height()
}

/// Longest selected-chain walk any lookup performs.
const MAX_WALK: usize = 8_192;

// ── Chain view over the DAG ──────────────────────────────────────────────────

/// The selected chain starting at `start` (inclusive), walked through
/// `selected_parent` links.
pub struct DagChainView<'a> {
    pub dag: &'a GhostDAG,
    pub start: Option<Hash>,
}

impl ChainView for DagChainView<'_> {
    fn selected_at(&self, slot: u64) -> Option<Hash> {
        let mut cur = self.start;
        for _ in 0..MAX_WALK {
            let h = cur?;
            let d = self.dag.get_block_data(&h)?;
            if d.height < slot {
                return Some(h);
            }
            cur = d.selected_parent;
        }
        None
    }
}

/// Selected-chain blocks from `start` down to (and including) `min_height`:
/// (hash, height), tallest first.
pub fn selected_chain_since(dag: &GhostDAG, start: Option<Hash>, min_height: u64) -> Vec<(Hash, u64)> {
    let mut out = Vec::new();
    let mut cur = start;
    while let Some(h) = cur {
        let Some(d) = dag.get_block_data(&h) else { break };
        if d.height < min_height || out.len() >= MAX_WALK {
            break;
        }
        out.push((h, d.height));
        cur = d.selected_parent;
    }
    out
}

// ── Per-block state storage ──────────────────────────────────────────────────

#[allow(unused_imports)] // docs and tests; the node binary compiles this module too
pub use store::ANCHOR_EVERY;

/// The state's witness exits (`PowitState::exited`, liveness activation),
/// stored beside it only when there are any: the serde encoding of a state
/// leaves them out, so every GnB state is stored exactly as before. The
/// per-epoch layout (`store`) stores the rest of the state.
fn exited_key(hash: &Hash) -> String {
    format!("powit/exited/{}", hex::encode(hash))
}

fn encode_exited(state: &PowitState) -> Result<Option<Vec<u8>>, String> {
    if state.exited.is_empty() {
        return Ok(None);
    }
    bincode::serde::encode_to_vec(&state.exited, bincode::config::standard())
        .map(Some).map_err(|e| format!("powit exits encode: {e}"))
}

/// The state's PoCI ledger (`PowitState::poci`, ObenBlock), stored beside it
/// like the exits. Per block (`powit/poci/<block>`): the id of its history
/// head, the bans and the absence-pruning ledger (pruned keys, pending
/// rejoins, included votes of the last `PRUNE_AFTER + 3` epochs). The
/// configurations are stored once each as history nodes
/// (`powit/pocihist/<node id>`, the configuration and the id of the node
/// before it). A node id commits to the whole history,
/// `SHA3-256("OBB-POCI-store/node" ‖ config_id ‖ prev node id or 32 zero
/// bytes)`: two branches may put the same configuration in force after
/// different ones (a handoff that skips epochs computes the same `C_x`), and
/// each must read its own predecessors (Proof of Corruption names past
/// configurations). Node-local, not consensus. GnB states have none, so
/// nothing changes for them.
fn poci_key(hash: &Hash) -> String {
    format!("powit/poci/{}", hex::encode(hash))
}

fn poci_node_key(id: &Hash) -> String {
    format!("powit/pocihist/{}", hex::encode(id))
}

const POCI_NODE_TAG: &[u8] = b"OBB-POCI-store/node";

fn poci_node_id(config_id: &Hash, prev: Option<&Hash>) -> Hash {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(POCI_NODE_TAG);
    h.update(config_id);
    h.update(prev.unwrap_or(&[0u8; 32]));
    h.finalize().into()
}

/// The node ids of `st`'s history, oldest first.
fn poci_node_ids(st: &PociState) -> Vec<Hash> {
    let configs: Vec<Hash> = st.history().map(|c| c.id()).collect();
    let mut ids: Vec<Hash> = Vec::with_capacity(configs.len());
    for cid in configs.iter().rev() {
        let id = poci_node_id(cid, ids.last());
        ids.push(id);
    }
    ids
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PociRecord {
    head: Hash,
    bans: BTreeMap<KeyId, Vec<poci::Ban>>,
    /// key -> the epoch its pruning started (§4.1).
    pruned: BTreeMap<KeyId, u64>,
    /// key -> where its pending rejoin was included.
    rejoins: BTreeMap<KeyId, u64>,
    /// key -> (block epoch -> lowest `included_at`).
    seen: BTreeMap<KeyId, BTreeMap<u64, u64>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PociNodeRow {
    config: Configuration,
    prev: Option<Hash>,
}

/// Histories by their head node id (shared by every state of a chain; a
/// handful are live at once).
static POCI_HISTORIES: Mutex<Option<HashMap<Hash, PociState>>> = parking_lot::const_mutex(None);
const POCI_HISTORY_CACHE_CAP: usize = 64;

fn bincode_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    match bincode::serde::decode_from_slice(bytes, bincode::config::standard()) {
        Ok((v, used)) if used == bytes.len() => Some(v),
        _ => None,
    }
}

fn load_poci(store: &Storage, hash: &Hash) -> Option<Option<PociState>> {
    let Some(bytes) = store.get_meta(&poci_key(hash)).ok()? else { return Some(None) };
    let rec: PociRecord = bincode_decode(&bytes)?;
    let cached = POCI_HISTORIES.lock().as_ref().and_then(|m| m.get(&rec.head).cloned());
    let st = match cached {
        Some(st) => st,
        None => {
            let mut history: Vec<Arc<Configuration>> = Vec::new();
            let mut ids: Vec<Hash> = Vec::new();
            let mut cur = Some(rec.head);
            while let Some(id) = cur {
                let row: PociNodeRow = bincode_decode(&store.get_meta(&poci_node_key(&id)).ok()??)?;
                ids.push(id);
                history.push(Arc::new(row.config));
                cur = row.prev;
            }
            // Every node id must be the one its contents and predecessors give.
            for i in 0..history.len() {
                if poci_node_id(&history[i].id(), ids.get(i + 1)) != ids[i] {
                    return None;
                }
            }
            let st = PociState::from_history(history, BTreeMap::new())?;
            let mut g = POCI_HISTORIES.lock();
            let m = g.get_or_insert_with(HashMap::new);
            if m.len() >= POCI_HISTORY_CACHE_CAP {
                m.clear();
            }
            m.insert(rec.head, st.clone());
            st
        }
    };
    let pruned = rec.pruned.into_iter().map(|(k, start)| (k, poci::Prune { start, until: None })).collect();
    let mut st = st.with_ledger(pruned, rec.rejoins, rec.seen);
    st.bans = rec.bans;
    Some(Some(st))
}

/// Stage the PoCI rows of `state`: the block's record, and the history nodes
/// not stored yet, newest first until one is (normally only the head's, the
/// first block a configuration is in force at; the walk also covers a state
/// whose earlier heads were never stored).
fn stage_poci(store: &Storage, batch: &mut rocksdb::WriteBatch, hash: &Hash, state: &PowitState) -> Result<(), String> {
    let Some(st) = &state.poci else { return Ok(()) };
    let ids = poci_node_ids(st);
    let head = *ids.last().expect("a history has a configuration in force");
    for (i, config) in (0..ids.len()).rev().zip(st.history()) {
        let nkey = poci_node_key(&ids[i]);
        if store.get_meta(&nkey).map_err(|e| format!("storage: powit poci: {e}"))?.is_some() {
            break;
        }
        let prev = i.checked_sub(1).map(|j| ids[j]);
        let row = PociNodeRow { config: (**config).clone(), prev };
        let bytes = bincode::serde::encode_to_vec(&row, bincode::config::standard())
            .map_err(|e| format!("powit poci encode: {e}"))?;
        store.stage_meta(batch, &nkey, &bytes).map_err(|e| format!("storage: powit poci: {e}"))?;
    }
    debug_assert!(st.pruned.values().all(|p| p.until.is_none()), "a stored ledger holds no handoff in progress");
    let rec = PociRecord { head, bans: st.bans.clone(), pruned: st.pruned.iter().map(|(k, p)| (*k, p.start)).collect(),
                           rejoins: st.rejoins.clone(), seen: st.seen.clone() };
    let bytes = bincode::serde::encode_to_vec(&rec, bincode::config::standard())
        .map_err(|e| format!("powit poci encode: {e}"))?;
    store.stage_meta(batch, &poci_key(hash), &bytes).map_err(|e| format!("storage: powit poci: {e}"))
}

/// `hash`'s stored PoWit state (`store`: per-epoch segments plus per-block
/// diffs, package A3; data dirs of earlier releases are read as written),
/// with its witness exits and its PoCI ledger.
pub fn load_state(store: &Storage, hash: &Hash) -> Option<PowitState> {
    let mut st = store::load(store, hash)?;
    if let Some(x) = store.get_meta(&exited_key(hash)).ok()? {
        st.exited = bincode::serde::decode_from_slice(&x, bincode::config::standard()).ok()?.0;
    }
    st.poci = load_poci(store, hash)?;
    st.cap = store::load_cap(store, hash)?;
    Some(st)
}

/// Write `hash`'s PoWit state on its own, as an anchor record (and its
/// finality row, [`finality_row`]). The acceptance pipeline uses
/// [`stage_state`] (committed with the block's DAG record); this is for
/// tools and tests. Overwriting the state of a block that already has
/// children stored as diffs of it changes theirs too.
#[allow(dead_code)] // tools and tests; the node binary compiles this module too
pub fn save_state(store: &Storage, hash: &Hash, state: &PowitState) -> Result<(), String> {
    let mut batch = rocksdb::WriteBatch::default();
    stage_state(store, &mut batch, hash, None, state)?;
    store.write_batch(batch).map_err(|e| format!("storage: powit state: {e}"))
}

/// [`save_state`] into a caller-owned batch: the acceptance pipeline commits
/// a block's PoWit state in the same batch as its DAG record (the first chunk
/// of the chain move it triggers, or its fork-loser record), so a block is
/// never recorded without its state and a refused block leaves none behind.
/// The block's finality row ([`finality_row`]) goes into the same batch, so
/// the finality index a restart rebuilds holds exactly the recorded blocks.
/// `parent` is the block's selected parent: when its state is stored in the
/// same epoch, this block's record is a diff of it (`store`).
pub fn stage_state(store: &Storage, batch: &mut rocksdb::WriteBatch, hash: &Hash, parent: Option<&Hash>,
                   state: &PowitState) -> Result<(), String>
{
    store::stage(store, batch, hash, parent, state)?;
    if let Some(x) = encode_exited(state)? {
        store.stage_meta(batch, &exited_key(hash), &x).map_err(|e| format!("storage: powit exits: {e}"))?;
    }
    stage_poci(store, batch, hash, state)?;
    store::stage_cap(store, batch, hash, state)?;
    if let Some((key, row)) = finality_row(hash, state) {
        store.stage_meta(batch, &key, &row).map_err(|e| format!("storage: powit finality row: {e}"))?;
    }
    Ok(())
}

/// Whether `hash`'s state is stored as an anchor (`Some(true)`) or a diff
/// (`Some(false)`) in the per-epoch layout; `None` if not in that layout.
#[allow(dead_code)] // tests; the node binary compiles this module too
pub fn state_record_is_anchor(store: &Storage, hash: &Hash) -> Option<bool> {
    store::record_kind(store, hash)
}

/// State a child of `parent` builds on: the parent's stored state, or the
/// genesis state when the parent is below activation or is the genesis
/// block (PoWit from height 0, ObenBlock: the genesis is checkpoint slot 0,
/// justified and final by definition, and stores no state of its own).
fn base_state(dag: &GhostDAG, store: &Storage, parent: Option<Hash>) -> Result<PowitState, String> {
    let act = core::powit_height();
    let Some(p) = parent else { return Err("powit: block without a selected parent".into()) };
    let ph = dag.get_block_data(&p).map(|d| d.height).ok_or("powit: unknown selected parent")?;
    if ph < act || ph == 0 {
        return Ok(PowitState::genesis(act, p));
    }
    load_state(store, &p).ok_or_else(|| format!("storage: missing PoWit state of {}", hex::encode(&p[..8])))
}

// ── Share verification (cached) ──────────────────────────────────────────────

static VERIFIED_SHARES: Mutex<Option<(HashMap<Hash, u128>, std::collections::VecDeque<Hash>)>> =
    parking_lot::const_mutex(None);
const SHARE_CACHE_CAP: usize = 16_384;

fn verify_share_cached(share: &WitnessShare, attested: &Block) -> Result<u128, String> {
    let id = witness_share::share_id(share);
    if let Some(w) = VERIFIED_SHARES.lock().as_ref().and_then(|(m, _)| m.get(&id).copied()) {
        return Ok(w);
    }
    let w = witness_share::verify_share(share, attested, witness_share::smh_v3).map_err(|e| e.to_string())?;
    let mut g = VERIFIED_SHARES.lock();
    let (m, order) = g.get_or_insert_with(Default::default);
    if m.insert(id, w).is_none() {
        order.push_back(id);
        if order.len() > SHARE_CACHE_CAP {
            if let Some(old) = order.pop_front() {
                m.remove(&old);
            }
        }
    }
    Ok(w)
}

/// Share ids already included on the selected chain in `recent`.
fn included_share_ids(store: &Storage, recent: &[(Hash, u64)]) -> Result<HashSet<Hash>, String> {
    let act = core::powit_height();
    let mut ids = HashSet::new();
    for (h, height) in recent {
        if *height < act {
            continue;
        }
        let b = store.get_block(h).map_err(|e| format!("storage: {e}"))?
            .ok_or_else(|| format!("storage: missing body of {}", hex::encode(&h[..8])))?;
        ids.extend(b.powit.shares.iter().map(witness_share::share_id));
    }
    Ok(ids)
}

/// Check one share against the chain a block at `height` extends: the
/// attested block is on that selected chain within the share window, the
/// share is not already included there, and its proof is valid.
fn check_share(store: &Storage, share: &WitnessShare, height: u64, recent: &[(Hash, u64)],
               included: &HashSet<Hash>) -> Result<(KeyId, u128), String> {
    if !share.payout_is_valid() {
        return Err("witness share pays an invalid script".into());
    }
    let key = share.key_id();
    let (_, ah) = recent.iter().find(|(h, _)| *h == share.attested)
        .ok_or("witness share attests a block that is not on this selected chain")?;
    if *ah >= height || height - ah > SHARE_WINDOW {
        return Err("witness share attests a block outside the share window".into());
    }
    if included.contains(&witness_share::share_id(share)) {
        return Err("witness share already included on this chain".into());
    }
    let attested = store.get_block(&share.attested).map_err(|e| format!("storage: {e}"))?
        .ok_or("storage: attested block body missing")?;
    Ok((key, verify_share_cached(share, &attested)?))
}

// ── Block validation in context ──────────────────────────────────────────────

/// Validate `block`'s PoWit section in context and compute its state.
/// `Ok(None)` below activation. Errors prefixed `storage:` are local
/// failures, never a verdict on the block.
pub fn block_state(block: &Block, block_hash: &Hash, dag: &GhostDAG, store: &Storage)
    -> Result<Option<PowitState>, String>
{
    if !core::powit_active(block.height) {
        return if block.powit.is_empty() { Ok(None) } else { Err("PoWit section before activation".into()) };
    }
    let sp = dag.preview_selected_parent(&block.header.parents);
    let base = base_state(dag, store, sp)?;
    let recent = selected_chain_since(dag, sp, block.height.saturating_sub(SHARE_WINDOW));
    let included = included_share_ids(store, &recent)?;
    let mut share_work = Vec::with_capacity(block.powit.shares.len());
    for s in &block.powit.shares {
        share_work.push(check_share(store, s, block.height, &recent, &included)?);
    }
    let input = BlockInput {
        height: block.height,
        hash: *block_hash,
        share_work: &share_work,
        attestations: &block.powit.attestations,
        evidence: &block.powit.evidence,
        exits: &block.powit.exits,
    };
    let view = DagChainView { dag, start: sp };
    // PoCI on ObenBlock (with the block's PoCI evidence), PoWit on GnB.
    base.apply_block(&powit::params(), core::node_chain_id(), hardening2_height(), liveness_height(), &input,
                     block.header.bits, powit::PociItems::of(&block.powit), &view)
        .map(Some)
}

// ── Pools ────────────────────────────────────────────────────────────────────
//
// Every structure here is bounded, and what a gossiped item costs to check is
// paid only after the cheap context checks pass (PoWit audit, findings 1, 5
// and 7), as Bitcoin Core bounds what it keeps for peers (the orphan pool,
// `DEFAULT_MAX_ORPHAN_TRANSACTIONS`, with eviction; the mempool, `-maxmempool`
// and `TrimToSize`) and checks everything that costs nothing before scripts
// and signatures (`PreChecks` before `CheckInputScripts`):
//
// - an equivocation proof or an attestation is considered only for a key in a
//   recent witness set of this node's tip, checked BEFORE any signature (a
//   proof costs an attacker two signatures once, then one SHA3 per re-rooted
//   KES key: `attestation_message` does not bind the key);
// - an attestation must target an open checkpoint slot (a slot, at most one
//   interval above the tip, includable by the next block) from the tip's
//   justified checkpoint; a key holds at most `ATTESTATIONS_PER_KEY` of them;
// - a full pool evicts its worst entry for a better one, deterministically;
// - templates take proofs against the heaviest witnesses first;
// - the pool follows the selected tip on EVERY node: each use with a new tip
//   first forgets what that tip made stale (`PowitPool::follow`), and main
//   also refreshes it on every tip change, off the acceptance lock.

const POOL_CAP: usize = 4_096;
/// Equivocation proofs held, one per key.
const EVIDENCE_CAP: usize = 256;
/// A key's equivocation is held and relayed while the key is in the witness
/// set of the next block's epoch or of one of this many epochs before it.
const EVIDENCE_MEMBER_EPOCHS: u64 = 4;
/// Pending attestations per key (an honest witness signs one link per
/// checkpoint slot, all from the justified checkpoint): the newest targets.
const ATTESTATIONS_PER_KEY: usize = 2;
/// Links remembered per witness, and in total, to build equivocation proofs
/// from gossip; the oldest go first.
const SEEN_LINKS_PER_KEY: usize = 16;
const SEEN_LINKS_CAP: usize = 2_048;
/// Witness exits held, one per key (liveness activation).
const EXIT_CAP: usize = 256;
/// PoCI rejoins held, one per key (ObenBlock, §4.1).
const REJOIN_CAP: usize = 256;

/// `admit_evidence`'s refusal of a proof against a key outside the recent
/// witness sets: this node's view, never a misbehaviour (`ingress` charges
/// the deliverer's verification budget for it without a refund).
pub const EVIDENCE_NOT_A_WITNESS: &str = "equivocation proof against a key outside the recent witness sets";

/// What the pool needs of a tip's PoWit state, computed once per tip: the
/// justified checkpoint, the barred keys, and the witness sets of every
/// epoch a gossiped item may concern (`witness_set` is O(N log N) in the
/// share keys; it was recomputed for every gossiped attestation).
///
/// Each item is judged by the rules of the earliest block that may include
/// it (`Regime::at`, second hardening activation): an attestation by those of
/// height `max(target, next block)`, an equivocation proof by the next
/// block's. Before the activation `W(e)` is the 64 heaviest keys, held here
/// per epoch; from it every key with weight is a member, looked up in the
/// tip's state directly (`PowitState::member_weight_h2`, no set to build),
/// and a proof is held only against a member of the next block's evidence
/// epochs (`PowitState::may_be_proven_h2`), the consensus rule.
pub struct TipWitnesses {
    pub tip: Hash,
    pub tip_h: u64,
    activation: u64,
    hardening2: u64,
    justified: Checkpoint,
    /// Epoch of the next block.
    epoch: u64,
    /// The tip's state (barred keys; witness weights from the activation;
    /// the PoCI configuration in force on ObenBlock).
    state: PowitState,
    /// PoCI (ObenBlock): its parameters; `None` on GnB.
    poci: Option<PociParams>,
    /// Old-rule W(e) (the 64 heaviest) for the epochs from
    /// `EVIDENCE_MEMBER_EPOCHS` (or the oldest open target) before the next
    /// block's to the newest open target's; empty once the next block is at
    /// or above the second hardening activation.
    sets: BTreeMap<u64, HashMap<KeyId, u128>>,
}

impl TipWitnesses {
    /// From the tip's state (kept), under the second hardening activation
    /// height `hardening2`.
    pub fn of_at(tip: Hash, tip_h: u64, st: PowitState, p: &PowitParams, hardening2: u64) -> Self {
        let act = st.activation;
        let next = tip_h.max(act) + 1;
        let epoch = p.epoch(act, next);
        let sets = if Regime::at(next, hardening2) == Regime::V1 {
            let oldest_open = p.epoch(act, next.saturating_sub(p.vote_ttl).max(act));
            let lo = epoch.saturating_sub(EVIDENCE_MEMBER_EPOCHS).min(oldest_open);
            let hi = p.epoch(act, tip_h.max(act) + p.checkpoint_interval).max(epoch);
            (lo..=hi).map(|e| (e, st.witness_set(p, e).into_iter().collect())).collect()
        } else {
            BTreeMap::new()
        };
        let poci = PociParams::for_chain(core::node_chain_id());
        TipWitnesses { tip, tip_h, activation: act, hardening2, justified: st.justified, epoch, state: st, poci, sets }
    }

    /// The PoCI configuration in force at the tip (ObenBlock after the
    /// launch bootstrap).
    pub fn poci_config(&self) -> Option<&Arc<Configuration>> {
        self.poci.and(self.state.poci_config())
    }

    /// Whether `att` carries a valid signature for the next block: the v3
    /// message of the configuration in force (PoCI), else the PoWit message
    /// of its target's height.
    fn verify_attestation(&self, att: &Attestation, chain: core::ChainId, p: &PowitParams, act: u64) -> bool {
        match (self.poci, self.state.poci_config()) {
            (Some(pp), Some(c)) => att.verify_signature_v3(&pp, &c.id()),
            (Some(_), None) => false,
            (None, _) => att.verify_signature_at(chain, p, act, self.hardening2),
        }
    }

    fn next_height(&self) -> u64 {
        self.tip_h.max(self.activation) + 1
    }

    /// The rules of the next block.
    fn regime(&self) -> Regime {
        Regime::at(self.next_height(), self.hardening2)
    }

    /// `key`'s weight in W(epoch of `target`) under the rules of the earliest
    /// block that may include a vote for `target`, if it is a member.
    pub fn weight_for(&self, p: &PowitParams, target: &Checkpoint, key: &KeyId) -> Option<u128> {
        if self.poci.is_some() {
            // PoCI: the registry weight of the configuration in force.
            return self.poci_config()?.weight(key);
        }
        let e = p.epoch(self.activation, target.height.max(self.activation));
        match Regime::at(target.height.max(self.next_height()), self.hardening2) {
            Regime::V1 => self.sets.get(&e)?.get(key).copied(),
            Regime::Hardening2 => self.state.member_weight_h2(p, e, key),
        }
    }

    /// Whether the next block may carry an equivocation proof against `key`,
    /// and the key's weight for ordering: before the second hardening
    /// activation, its highest weight over the recent witness sets (node
    /// policy); from it, over the next block's evidence epochs (consensus).
    pub fn evidence_weight(&self, p: &PowitParams, key: &KeyId) -> Option<u128> {
        if self.poci.is_some() {
            // PoCI: a key of a configuration the chain has had in force.
            let st = self.state.poci.as_ref()?;
            return st.history().filter_map(|c| c.weight(key)).max();
        }
        match self.regime() {
            Regime::V1 => self.sets.values().filter_map(|s| s.get(key)).max().copied(),
            Regime::Hardening2 => PowitState::evidence_epochs(self.epoch)
                .filter_map(|e| self.state.member_weight_h2(p, e, key))
                .max(),
        }
    }

    fn is_banned(&self, key: &KeyId) -> bool {
        match (self.poci, &self.state.poci) {
            // PoCI: a ban pending or not over refuses new evidence (§5).
            (Some(pp), Some(st)) => st.bans.get(key).is_some_and(|bl| bl.iter().any(|b| {
                b.end(pp.ban_epochs).is_none_or(|end| st.config().epoch() < end)
            })),
            _ => self.state.is_banned(key, self.epoch),
        }
    }

    /// What the next block checks of an exit before its signature
    /// (`PowitState::apply_full`): the liveness rules apply, it is signed for
    /// the next block's epoch or the one before, and its key holds share work
    /// in the tip's state and has not exited.
    fn exit_admissible(&self, key: &KeyId, x: &WitnessExit) -> Result<(), String> {
        if !core::liveness::liveness_active_at(self.next_height()) {
            return Err("witness exits are not active on this chain".into());
        }
        if !core::liveness::exit_epoch_ok(self.epoch, x.epoch) {
            return Err("witness exit not signed for the next block's epoch or the one before".into());
        }
        if self.state.exited.contains_key(key) {
            return Err("witness already exited".into());
        }
        if !self.state.epoch_work.values().any(|m| m.contains_key(key)) {
            return Err("witness exit by a key without share work".into());
        }
        Ok(())
    }

    /// What the next block checks of a PoCI rejoin before its signature
    /// (`PociState::may_rejoin`): PoCI in force at the tip, signed for the
    /// next block's epoch or the one before, the key pruned and without a
    /// rejoin pending.
    fn rejoin_admissible(&self, key: &KeyId, r: &WitnessRejoin) -> Result<(), String> {
        let st = match (self.poci, &self.state.poci) {
            (Some(_), Some(st)) => st,
            (Some(_), None) => return Err("PoCI has no configuration in force yet".into()),
            (None, _) => return Err("rejoin messages exist on PoCI chains only".into()),
        };
        if !core::liveness::liveness_active_at(self.next_height()) {
            return Err("rejoin messages need the membership list (liveness activation)".into());
        }
        st.may_rejoin(self.next_height() + 1, self.state.finalized.height, self.epoch, key, r.epoch)
            .map_err(|e| e.to_string())
    }

    /// Verify an equivocation proof's signatures as the next block will, or
    /// (next block below the activation, a link targeting at or above it)
    /// as a block from the activation will: such a proof is valid there and
    /// is kept for it (templates include what their own block accepts).
    fn verify_evidence(&self, ev: &Equivocation, chain: core::ChainId, p: &PowitParams) -> Result<KeyId, String> {
        let act = self.activation;
        match self.regime() {
            Regime::Hardening2 => ev.verify_at(chain, p, act, self.hardening2).map_err(str::to_string),
            Regime::V1 => match ev.verify_at(chain, p, act, activation::NEVER) {
                Err(_) if ev.a.target.height.max(ev.b.target.height) >= self.hardening2 => {
                    ev.verify_at(chain, p, act, self.hardening2).map_err(str::to_string)
                }
                r => r.map_err(str::to_string),
            },
        }
    }

    /// A target the next block (or the one after, from a peer one block
    /// ahead) may include: a checkpoint slot at most one interval above the
    /// tip, not yet expired for the next block.
    fn open_target(&self, p: &PowitParams, t: &Checkpoint) -> bool {
        p.is_checkpoint(self.activation, t.height)
            && t.height <= self.tip_h + p.checkpoint_interval
            && self.tip_h < t.height + p.vote_ttl
    }
}

struct PendingAttestation {
    att: Attestation,
    key: KeyId,
    weight: u128,
}

struct HeldEvidence {
    ev: Equivocation,
    /// PoCI (ObenBlock): the configuration both votes name.
    config_id: Option<Hash>,
    weight: u128,
}

/// Links seen per witness (gossip), oldest evicted first, per key and in
/// total; never wiped wholesale (that dropped the honest links double votes
/// are caught against).
#[derive(Default)]
struct SeenLinks {
    /// (arrival sequence, link, the PoCI configuration it was verified under).
    by_key: HashMap<KeyId, std::collections::VecDeque<(u64, Attestation, Option<Hash>)>>,
    /// Arrival sequence -> key, oldest first.
    order: BTreeMap<u64, KeyId>,
    next: u64,
}

impl SeenLinks {
    fn of(&self, key: &KeyId) -> impl Iterator<Item = &Attestation> {
        self.by_key.get(key).into_iter().flat_map(|v| v.iter().map(|(_, a, _)| a))
    }

    /// `key`'s links with the PoCI configuration each was verified under.
    fn of_with_config(&self, key: &KeyId) -> impl Iterator<Item = (&Attestation, Option<Hash>)> {
        self.by_key.get(key).into_iter().flat_map(|v| v.iter().map(|(_, a, c)| (a, *c)))
    }

    #[cfg(test)]
    fn record(&mut self, key: KeyId, att: &Attestation) {
        self.record_with(key, att, None)
    }

    fn record_with(&mut self, key: KeyId, att: &Attestation, config_id: Option<Hash>) {
        let links = self.by_key.entry(key).or_default();
        if links.iter().any(|(_, a, c)| a == att && *c == config_id) {
            return;
        }
        let seq = self.next;
        self.next += 1;
        links.push_back((seq, att.clone(), config_id));
        self.order.insert(seq, key);
        if links.len() > SEEN_LINKS_PER_KEY {
            if let Some((old, _, _)) = links.pop_front() {
                self.order.remove(&old);
            }
        }
        while self.order.len() > SEEN_LINKS_CAP {
            let Some((old, k)) = self.order.pop_first() else { break };
            if let Some(v) = self.by_key.get_mut(&k) {
                v.retain(|(s, _, _)| *s != old);
                if v.is_empty() {
                    self.by_key.remove(&k);
                }
            }
        }
    }

    fn retain_keys(&mut self, keep: impl Fn(&KeyId) -> bool) {
        self.by_key.retain(|k, _| keep(k));
        self.order.retain(|_, k| keep(k));
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

/// Two links, both already verified, that one witness must never have
/// signed together (the shape `Equivocation::verify` checks after the
/// signatures).
fn links_conflict(a: &Attestation, b: &Attestation) -> bool {
    let double = a.target.height == b.target.height && a.target != b.target;
    let surround = (a.source.height < b.source.height && b.target.height < a.target.height)
        || (b.source.height < a.source.height && a.target.height < b.target.height);
    a.witness == b.witness && a != b && (double || surround)
}

#[derive(Default)]
struct PoolInner {
    shares: BTreeMap<Hash, (WitnessShare, u64)>,
    attestations: BTreeMap<Hash, PendingAttestation>,
    evidence: BTreeMap<KeyId, HeldEvidence>,
    /// Witness exits waiting for a block, one per key.
    exits: BTreeMap<KeyId, WitnessExit>,
    /// PoCI rejoins waiting for a block, one per key (ObenBlock).
    rejoins: BTreeMap<KeyId, WitnessRejoin>,
    /// Links seen per witness-set member (gossip), to build equivocation proofs.
    seen_links: SeenLinks,
    /// The tip the pool was last pruned for, and its witness sets (`None`
    /// below the PoWit activation).
    followed: Option<Hash>,
    view: Option<Arc<TipWitnesses>>,
}

impl PoolInner {
    /// Hold `ev` against `key`. Full: the lightest key's proof (then the
    /// greatest KeyId's) makes room for a heavier one, never the reverse.
    #[cfg(test)]
    fn insert_evidence(&mut self, key: KeyId, ev: Equivocation, weight: u128) -> Result<(), String> {
        self.insert_evidence_for(key, ev, None, weight)
    }

    /// [`Self::insert_evidence`] with the PoCI configuration the proof names.
    fn insert_evidence_for(&mut self, key: KeyId, ev: Equivocation, config_id: Option<Hash>, weight: u128)
        -> Result<(), String>
    {
        if self.evidence.contains_key(&key) {
            return Ok(());
        }
        if self.evidence.len() >= EVIDENCE_CAP {
            let rank = |k: &KeyId, w: u128| (w, std::cmp::Reverse(*k));
            let worst = self.evidence.iter().map(|(k, h)| (*k, rank(k, h.weight))).min_by_key(|(_, r)| *r);
            match worst {
                Some((k, r)) if rank(&key, weight) > r => {
                    self.evidence.remove(&k);
                }
                _ => return Err("evidence pool full".into()),
            }
        }
        self.evidence.insert(key, HeldEvidence { ev, config_id, weight });
        Ok(())
    }

    /// Hold an admissible attestation: a key keeps its newest
    /// `ATTESTATIONS_PER_KEY` targets; a full pool drops its entry closest to
    /// expiry (lowest target, then lightest key, then greatest id) for a
    /// better one.
    fn insert_attestation(&mut self, id: Hash, pa: PendingAttestation) -> Result<(), String> {
        let mine: Vec<(u64, Hash)> = self.attestations.iter()
            .filter(|(_, x)| x.key == pa.key)
            .map(|(i, x)| (x.att.target.height, *i))
            .collect();
        if mine.len() >= ATTESTATIONS_PER_KEY {
            let &(oldest_h, oldest) = mine.iter().min().expect("non-empty");
            if pa.att.target.height <= oldest_h {
                return Err("witness already has pending attestations for newer checkpoints".into());
            }
            self.attestations.remove(&oldest);
        }
        if self.attestations.len() >= POOL_CAP {
            let rank = |x: &PendingAttestation, i: &Hash| (x.att.target.height, x.weight, std::cmp::Reverse(*i));
            let worst = self.attestations.iter().map(|(i, x)| (*i, rank(x, i))).min_by_key(|(_, r)| *r);
            match worst {
                Some((i, r)) if rank(&pa, &id) > r => {
                    self.attestations.remove(&i);
                }
                _ => return Err("attestation pool full".into()),
            }
        }
        self.attestations.insert(id, pa);
        Ok(())
    }

    /// Forget what the tip at `tip_h` (witness sets `view`) made stale.
    fn prune_to(&mut self, view: Option<&TipWitnesses>, tip_h: u64, p: &PowitParams) {
        self.shares.retain(|_, (_, ah)| tip_h < *ah + SHARE_WINDOW);
        let Some(v) = view else { return };
        self.attestations.retain(|_, x| {
            let t = x.att.target;
            if x.att.source != v.justified || !v.open_target(p, &t) {
                return false;
            }
            match v.weight_for(p, &t, &x.key) {
                Some(w) => {
                    x.weight = w;
                    true
                }
                None => false,
            }
        });
        self.evidence.retain(|k, _| !v.is_banned(k));
        self.exits.retain(|k, x| v.exit_admissible(k, x).is_ok());
        self.rejoins.retain(|k, r| v.rejoin_admissible(k, r).is_ok());
        self.seen_links.retain_keys(|k| v.evidence_weight(p, k).is_some());
    }
}

/// Validated PoWit items waiting for a block.
#[derive(Default)]
pub struct PowitPool {
    inner: Mutex<PoolInner>,
}

/// The node's single pool (shared by gossip, the miner and RPC).
pub fn pool() -> &'static PowitPool {
    static POOL: std::sync::LazyLock<PowitPool> = std::sync::LazyLock::new(PowitPool::default);
    &POOL
}

/// Gossip frame kinds for `NetworkMessage::NewPowitItem`.
pub const ITEM_SHARE: u8 = 1;
pub const ITEM_ATTESTATION: u8 = 2;
pub const ITEM_EVIDENCE: u8 = 3;
/// A witness exit (liveness activation, ObenBlock).
pub const ITEM_EXIT: u8 = 4;
/// The highest item kind on GnB (unchanged: GnB has no rejoin).
pub const ITEM_KIND_MAX: u8 = ITEM_EXIT;
/// A PoCI rejoin (ObenBlock only, `docs/DESIGN-obenblock-poci.md` §4.1).
pub const ITEM_REJOIN: u8 = 5;

/// The highest item kind of the node's chain: [`ITEM_REJOIN`] on PoCI
/// chains, [`ITEM_KIND_MAX`] on GnB, where kind 5 stays unknown.
pub fn item_kind_max() -> u8 {
    if powit::poci_active() { ITEM_REJOIN } else { ITEM_KIND_MAX }
}

/// `PowitPool::admit_rejoin`'s refusal of a bad signature (context-free).
pub const POWIT_BAD_REJOIN_SIGNATURE: &str = "invalid PoCI rejoin signature";

/// `PowitPool::admit_exit`'s refusal of a bad signature (context-free).
pub const POWIT_BAD_EXIT_SIGNATURE: &str = "invalid witness exit signature";

pub fn item_id(kind: u8, data: &[u8]) -> Hash {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"GNB-POWIT-v1/item");
    h.update([kind]);
    h.update(data);
    h.finalize().into()
}

fn tip_context(dag: &GhostDAG) -> Option<(Hash, u64)> {
    let t = dag.selected_tip()?;
    Some((t, dag.get_block_data(&t)?.height))
}

impl PowitPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let g = self.inner.lock();
        (g.shares.len(), g.attestations.len(), g.evidence.len())
    }

    /// Every link of `key` the pool holds (pending and seen in gossip), and
    /// whether it holds an equivocation proof against it: the signer's
    /// rollback guard (`WitnessDuty::scan_for_rollback`).
    pub fn votes_of(&self, key: &KeyId) -> (Vec<Attestation>, bool) {
        let g = self.inner.lock();
        let mut out: Vec<Attestation> = g.seen_links.of(key).cloned().collect();
        out.extend(g.attestations.values().filter(|x| x.key == *key).map(|x| x.att.clone()));
        (out, g.evidence.contains_key(key))
    }

    /// Links remembered for equivocation detection (tests, metrics).
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn seen_links_len(&self) -> usize {
        self.inner.lock().seen_links.len()
    }

    /// Follow the tip `tip` at `tip_h`: when it is not the tip the pool was
    /// last pruned for, decode its PoWit state and compute its witness sets
    /// (outside the pool lock), then forget what it made stale. Returns its
    /// witness sets (`None` below the PoWit activation).
    fn follow(&self, tip: Hash, tip_h: u64, store: &Storage) -> Option<Arc<TipWitnesses>> {
        {
            let g = self.inner.lock();
            if g.followed == Some(tip) {
                return g.view.clone();
            }
        }
        let p = powit::params();
        let view = load_state(store, &tip).map(|st| Arc::new(TipWitnesses::of_at(tip, tip_h, st, &p, hardening2_height())));
        let mut g = self.inner.lock();
        g.prune_to(view.as_deref(), tip_h, &p);
        // An activated tip whose state is not readable yet is retried on the
        // next use rather than followed as "no PoWit" until the next tip.
        if view.is_some() || !core::powit_active(tip_h) {
            g.followed = Some(tip);
        }
        g.view = view.clone();
        view
    }

    fn follow_tip(&self, dag: &GhostDAG, store: &Storage) -> Option<Arc<TipWitnesses>> {
        let (tip, tip_h) = tip_context(dag)?;
        self.follow(tip, tip_h, store)
    }

    /// The witness sets of `tip` if the pool currently follows it.
    fn view_of(&self, tip: &Hash) -> Option<Arc<TipWitnesses>> {
        let g = self.inner.lock();
        g.view.as_ref().filter(|v| v.tip == *tip).cloned()
    }

    /// Admit a gossiped or locally mined share for the next block on the
    /// current tip. Cheap checks first; the proof (~90 ms) last.
    pub fn admit_share(&self, share: WitnessShare, dag: &GhostDAG, store: &Storage) -> Result<Hash, String> {
        let id = witness_share::share_id(&share);
        self.follow_tip(dag, store);
        if self.inner.lock().shares.contains_key(&id) {
            return Ok(id);
        }
        let (tip, tip_h) = tip_context(dag).ok_or("no tip")?;
        let next = tip_h + 1;
        if !core::powit_active(next) {
            return Err("PoWit not active".into());
        }
        let recent = selected_chain_since(dag, Some(tip), next.saturating_sub(SHARE_WINDOW));
        let included = included_share_ids(store, &recent)?;
        let (_, _) = check_share(store, &share, next, &recent, &included)?;
        let ah = recent.iter().find(|(h, _)| *h == share.attested).map(|(_, h)| *h).unwrap_or(0);
        let mut g = self.inner.lock();
        if g.shares.len() >= POOL_CAP {
            return Err("share pool full".into());
        }
        g.shares.insert(id, (share, ah));
        Ok(id)
    }

    /// Admit an attestation by a member of its target's witness set, for an
    /// open checkpoint slot (`TipWitnesses::open_target`), linking from the
    /// tip's justified checkpoint. The target, then membership, are checked
    /// before the signature. A conflict with a link the same witness was seen
    /// signing becomes an equivocation proof.
    pub fn admit_attestation(&self, att: Attestation, dag: &GhostDAG, store: &Storage) -> Result<Hash, String> {
        let id = att.id();
        let view = self.follow_tip(dag, store).ok_or("PoWit not active at the tip")?;
        if self.inner.lock().attestations.contains_key(&id) {
            return Ok(id);
        }
        let chain = core::node_chain_id();
        let p = powit::params();
        let act = core::powit_height();
        let t = att.target;
        // What `verify_signature` refuses before any signature check: a
        // link that is never valid anywhere.
        if t.height <= att.source.height || t.height < view.activation {
            return Err("invalid attestation signature".into());
        }
        // Review MEDIUM 5: the attacker-chosen target first (O(1)), then the
        // attester's weight (from the second hardening activation it reads the
        // frozen finalized window), then the signature.
        if !view.open_target(&p, &t) {
            return Err("attestation target is not an open checkpoint slot".into());
        }
        let key = att.key_id();
        let weight = view.weight_for(&p, &t, &key).ok_or("attester is not in the witness set")?;
        // The message of the target's height (v2 from the second hardening
        // activation: it commits the witness key); PoCI: the v3 message of
        // the configuration in force.
        if !view.verify_attestation(&att, chain, &p, act) {
            return Err("invalid attestation signature".into());
        }
        let config_id = view.poci_config().map(|c| c.id());
        {
            let mut g = self.inner.lock();
            if g.attestations.contains_key(&id) {
                return Ok(id);
            }
            // Every recorded link passed `verify_signature`: the shape check
            // is the rest of `Equivocation::verify` (PoCI: under the same
            // configuration).
            let conflicting = g.seen_links.of_with_config(&key)
                .find(|(o, c)| *c == config_id && links_conflict(o, &att)).map(|(o, _)| o.clone());
            if let Some(o) = conflicting {
                // PoCI: only evidence the next block may carry (one ban at a time).
                let admissible = match (view.poci, &view.state.poci, &config_id) {
                    (Some(pp), Some(st), Some(cid)) => st.may_ban(&pp, &key, cid).is_ok(),
                    _ => true,
                };
                if admissible {
                    let _ = g.insert_evidence_for(key, Equivocation { a: o, b: att.clone() }, config_id, weight);
                }
            }
            g.seen_links.record_with(key, &att, config_id);
        }
        if att.source != view.justified {
            return Err("attestation source is not the tip's justified checkpoint".into());
        }
        self.inner.lock().insert_attestation(id, PendingAttestation { att, key, weight })?;
        Ok(id)
    }

    /// Admit an equivocation proof against a key in a recent witness set of
    /// the tip (checked before the signatures), not yet barred, whose proof
    /// the pool does not hold yet; then verified.
    pub fn admit_evidence(&self, ev: Equivocation, dag: &GhostDAG, store: &Storage) -> Result<KeyId, String> {
        if ev.a.witness != ev.b.witness {
            return Err("equivocation: different witnesses".into());
        }
        let key = ev.a.key_id();
        let view = self.follow_tip(dag, store).ok_or("PoWit not active at the tip")?;
        let p = powit::params();
        let weight = view.evidence_weight(&p, &key).ok_or(EVIDENCE_NOT_A_WITNESS)?;
        if view.is_banned(&key) {
            return Err("equivocation proof against an already barred key".into());
        }
        if self.inner.lock().evidence.contains_key(&key) {
            return Err("equivocation proof for this key already held".into());
        }
        if view.poci.is_some() {
            return Err("PoWit equivocation proof on a PoCI chain (PoCI evidence names its configuration)".into());
        }
        let k = view.verify_evidence(&ev, core::node_chain_id(), &p)?;
        debug_assert_eq!(k, key);
        self.inner.lock().insert_evidence_for(key, ev, None, weight)?;
        Ok(key)
    }

    /// Admit PoCI evidence (ObenBlock) as the next block will check it: the
    /// one-ban-at-a-time rule and the named configuration's membership
    /// before the two signatures (`poci::check_evidence`), one proof per key.
    pub fn admit_poci_evidence(&self, ev: PociEvidence, dag: &GhostDAG, store: &Storage) -> Result<KeyId, String> {
        if ev.a.witness != ev.b.witness {
            return Err("equivocation: different witnesses".into());
        }
        let key = ev.key_id();
        let view = self.follow_tip(dag, store).ok_or("PoWit not active at the tip")?;
        let pp = view.poci.ok_or("PoCI evidence on a chain without PoCI")?;
        let st = view.state.poci.as_ref().ok_or("PoCI has no configuration in force yet")?;
        let weight = st.find_config(&ev.config_id).and_then(|c| c.weight(&key)).ok_or(EVIDENCE_NOT_A_WITNESS)?;
        st.may_ban(&pp, &key, &ev.config_id).map_err(|e| e.to_string())?;
        if self.inner.lock().evidence.contains_key(&key) {
            return Err("equivocation proof for this key already held".into());
        }
        let (a, b) = ev.votes();
        poci::check_evidence(&pp, &a, &b, |id| st.find_config(id)).map_err(|e| e.to_string())?;
        self.inner.lock().insert_evidence_for(key, Equivocation { a: ev.a, b: ev.b }, Some(ev.config_id), weight)?;
        Ok(key)
    }

    /// Admit a witness exit for the next block (liveness activation): the
    /// cheap checks of the next block (`TipWitnesses::exit_admissible`), then
    /// the KES signature. One exit per key.
    pub fn admit_exit(&self, x: WitnessExit, dag: &GhostDAG, store: &Storage) -> Result<KeyId, String> {
        let key = x.key_id();
        let view = self.follow_tip(dag, store).ok_or("PoWit not active at the tip")?;
        view.exit_admissible(&key, &x)?;
        if self.inner.lock().exits.contains_key(&key) {
            return Ok(key);
        }
        if !x.verify_signature(core::node_chain_id().to_u32()) {
            return Err(POWIT_BAD_EXIT_SIGNATURE.into());
        }
        let mut g = self.inner.lock();
        if g.exits.len() >= EXIT_CAP {
            return Err("witness exit pool full".into());
        }
        g.exits.insert(key, x);
        Ok(key)
    }

    /// Exits in the pool, by key.
    pub fn exits_snapshot(&self) -> Vec<WitnessExit> {
        self.inner.lock().exits.values().cloned().collect()
    }

    /// Admit a PoCI rejoin for the next block (ObenBlock, §4.1): the cheap
    /// checks of the next block (`TipWitnesses::rejoin_admissible`), then the
    /// KES signature. One rejoin per key.
    pub fn admit_rejoin(&self, r: WitnessRejoin, dag: &GhostDAG, store: &Storage) -> Result<KeyId, String> {
        let key = r.key_id();
        let view = self.follow_tip(dag, store).ok_or("PoWit not active at the tip")?;
        view.rejoin_admissible(&key, &r)?;
        if self.inner.lock().rejoins.contains_key(&key) {
            return Ok(key);
        }
        let pp = view.poci.ok_or("rejoin messages exist on PoCI chains only")?;
        if !r.verify_signature(pp.chain_id) {
            return Err(POWIT_BAD_REJOIN_SIGNATURE.into());
        }
        let mut g = self.inner.lock();
        if g.rejoins.len() >= REJOIN_CAP {
            return Err("rejoin pool full".into());
        }
        g.rejoins.insert(key, r);
        Ok(key)
    }

    /// Rejoins in the pool, by key.
    pub fn rejoins_snapshot(&self) -> Vec<WitnessRejoin> {
        self.inner.lock().rejoins.values().cloned().collect()
    }

    /// Forget what the current selected tip made stale (also done by every
    /// admission against a new tip).
    pub fn prune(&self, dag: &GhostDAG, store: &Storage) {
        self.follow_tip(dag, store);
    }

    /// [`Self::prune`] for main's tip-change task: the DAG read lock is held
    /// only to read the tip; the state decode and witness sets run without it.
    pub fn follow_selected_tip(&self, dag: &parking_lot::RwLock<GhostDAG>, store: &Storage) {
        let tip = tip_context(&dag.read());
        if let Some((tip, tip_h)) = tip {
            self.follow(tip, tip_h, store);
        }
    }

    /// Shares; attestations by target height, then heaviest key first (then
    /// id): from the second hardening activation every share key may vote
    /// and a block holds 32 votes, so the votes that carry the most weight
    /// toward two thirds go first; proofs heaviest key first (then KeyId),
    /// by the weights of the tip they were admitted at.
    /// Held proofs with the PoCI configuration each names (ObenBlock), in
    /// the order of [`Self::snapshot`].
    pub fn evidence_snapshot(&self) -> Vec<(Equivocation, Option<Hash>)> {
        let g = self.inner.lock();
        let mut ev: Vec<(&KeyId, &HeldEvidence)> = g.evidence.iter().collect();
        ev.sort_by(|a, b| b.1.weight.cmp(&a.1.weight).then(a.0.cmp(b.0)));
        ev.into_iter().map(|(_, h)| (h.ev.clone(), h.config_id)).collect()
    }

    pub fn snapshot(&self) -> (Vec<WitnessShare>, Vec<Attestation>, Vec<Equivocation>) {
        let g = self.inner.lock();
        let mut held: Vec<(&Hash, &PendingAttestation)> = g.attestations.iter().collect();
        held.sort_by(|a, b| a.1.att.target.height.cmp(&b.1.att.target.height)
            .then(b.1.weight.cmp(&a.1.weight)).then(a.0.cmp(b.0)));
        let atts: Vec<Attestation> = held.into_iter().map(|(_, x)| x.att.clone()).collect();
        let mut ev: Vec<(&KeyId, &HeldEvidence)> = g.evidence.iter().collect();
        ev.sort_by(|a, b| b.1.weight.cmp(&a.1.weight).then(a.0.cmp(b.0)));
        (g.shares.values().map(|(s, _)| s.clone()).collect(), atts, ev.into_iter().map(|(_, h)| h.ev.clone()).collect())
    }
}

// ── Templates ────────────────────────────────────────────────────────────────

/// PoWit section for a template extending `tip` at `height`: every item is
/// re-checked against the template's own context, so the section is valid.
/// Equivocation proofs go by the key's witness weight on `tip` (heaviest
/// first, then KeyId): a KeyId is free to grind, a weight is not.
///
/// The template's compact bits are not known here: [`template_body_with_bits`]
/// takes them. They never change which items are valid (the ObenBlock growth
/// cap records an epoch's first-block bits for a handoff at least two
/// epochs later), so the bits of a GnB template do not matter.
#[allow(dead_code)] // tests; the node binary compiles this module too
pub fn template_body(pool: &PowitPool, dag: &GhostDAG, store: &Storage, tip: Hash, height: u64) -> PowitBody {
    template_body_with_bits(pool, dag, store, tip, height, 0)
}

/// [`template_body`] for a template whose compact bits are `bits`.
pub fn template_body_with_bits(pool: &PowitPool, dag: &GhostDAG, store: &Storage, tip: Hash, height: u64, bits: u32)
    -> PowitBody
{
    if !core::powit_active(height) {
        return PowitBody::default();
    }
    let Ok(base) = base_state(dag, store, Some(tip)) else { return PowitBody::default() };
    let p = powit::params();
    let chain = core::node_chain_id();
    let h2 = hardening2_height();
    let live = liveness_height();
    let epoch = p.epoch(base.activation, height);
    let recent = selected_chain_since(dag, Some(tip), height.saturating_sub(SHARE_WINDOW));
    let Ok(included) = included_share_ids(store, &recent) else { return PowitBody::default() };
    let (shares, atts, _) = pool.snapshot();
    let mut evidence = pool.evidence_snapshot();
    if !evidence.is_empty() {
        let tip_h = dag.get_block_data(&tip).map(|d| d.height).unwrap_or(height.saturating_sub(1));
        let w = pool.view_of(&tip).unwrap_or_else(|| Arc::new(TipWitnesses::of_at(tip, tip_h, base.clone(), &p, h2)));
        evidence.sort_by_cached_key(|(e, _)| {
            let k = e.a.key_id();
            (std::cmp::Reverse(w.evidence_weight(&p, &k).unwrap_or(0)), k)
        });
    }
    let poci_chain = PociParams::for_chain(chain).is_some();

    let mut body = PowitBody::default();
    let mut share_work = Vec::new();
    for s in shares {
        if body.shares.len() >= witness_share::MAX_SHARES_PER_BLOCK {
            break;
        }
        if let Ok((k, w)) = check_share(store, &s, height, &recent, &included) {
            // A key that exited (liveness) earns no shares while its record lives.
            if !base.is_banned(&k, epoch) && !base.exited.contains_key(&k) && !body.shares.contains(&s) {
                body.shares.push(s);
                share_work.push((k, w));
            }
        }
    }
    let view = DagChainView { dag, start: Some(tip) };
    let try_apply = |b: &PowitBody, sw: &[(KeyId, u128)]| {
        let input = BlockInput { height, hash: [0; 32], share_work: sw, attestations: &b.attestations,
                                 evidence: &b.evidence, exits: &b.exits };
        base.apply_block(&p, chain, h2, live, &input, bits, powit::PociItems::of(b), &view).is_ok()
    };
    for (ev, config_id) in evidence {
        if body.evidence.len() + body.poci_evidence.len() >= p.max_evidence_per_block {
            break;
        }
        match (poci_chain, config_id) {
            (true, Some(config_id)) => {
                body.poci_evidence.push(PociEvidence { config_id, a: ev.a, b: ev.b });
                if !try_apply(&body, &share_work) {
                    body.poci_evidence.pop();
                }
            }
            (false, None) => {
                body.evidence.push(ev);
                if !try_apply(&body, &share_work) {
                    body.evidence.pop();
                }
            }
            _ => {}
        }
    }
    if core::liveness::liveness_active_at(height) {
        for x in pool.exits_snapshot() {
            if body.exits.len() >= core::liveness::MAX_EXITS_PER_BLOCK {
                break;
            }
            // A share credited to a key exiting in this same block is
            // invalid: the exit (the witness's own request) goes first.
            let k = x.key_id();
            let mut trial = body.clone();
            let mut trial_work = share_work.clone();
            let keep: Vec<bool> = trial_work.iter().map(|(sk, _)| *sk != k).collect();
            let mut i = 0;
            trial.shares.retain(|_| { i += 1; keep[i - 1] });
            trial_work.retain(|(sk, _)| *sk != k);
            trial.exits.push(x);
            if try_apply(&trial, &trial_work) {
                body = trial;
                share_work = trial_work;
            }
        }
        // PoCI (ObenBlock, §4.1): pruned keys' rejoins, after the exits.
        if poci_chain {
            for r in pool.rejoins_snapshot() {
                if body.rejoins.len() >= powit::MAX_REJOINS_PER_BLOCK {
                    break;
                }
                body.rejoins.push(r);
                if !try_apply(&body, &share_work) {
                    body.rejoins.pop();
                }
            }
        }
    }
    for a in atts {
        if body.attestations.len() >= p.max_attestations_per_block {
            break;
        }
        body.attestations.push(a);
        if !try_apply(&body, &share_work) {
            body.attestations.pop();
        }
    }
    // Shares of a key barred by evidence in this same block are invalid.
    if !try_apply(&body, &share_work) {
        body.shares.clear();
        share_work.clear();
        if !try_apply(&body, &share_work) {
            return PowitBody::default();
        }
    }
    body
}

// ── Witness duty ─────────────────────────────────────────────────────────────

use crate::powit_signer::{write_durable, CrashPoint, ObservedVote, Signed, VoteGuard};

/// A witness's forward-secure KES key, its payout script and its signer
/// protection (`powit_signer::VoteGuard`, DESIGN-obenblock-poci.md §8). The
/// KES state evolves to each target's epoch (erasing every earlier seed, on
/// disk first) before signing; the guard persists every vote before its
/// signature is released, refuses double and surround votes, holds the
/// key's exclusive signer lock, and stops signing on a vote of this key in
/// the chain or the pool that its record does not hold (rollback guard).
pub struct WitnessDuty {
    pub key_id: KeyId,
    pub payout_script: Vec<u8>,
    key_path: PathBuf,
    /// CRY-4: the key-file password is kept for the node's whole run (it
    /// re-opens the KES key file at every epoch), so it lives in a
    /// `SecretBytes` region: locked in RAM where the platform allows, wiped
    /// on drop (Bitcoin Core keeps wallet passphrases in `SecureString`,
    /// secure-allocator memory, for the same reason).
    password: gnb_crypto::crypto::SecretBytes,
    signer: Mutex<gnb_crypto::core::kes::KesSigner>,
    guard: VoteGuard,
}

/// The witness password held in secret memory, as the `&str` the key file
/// API takes. It was read as UTF-8 text and trimmed at character
/// boundaries, so it is always valid UTF-8.
fn password_str(password: &gnb_crypto::crypto::SecretBytes) -> &str {
    std::str::from_utf8(password).expect("the witness password was read as UTF-8")
}

/// Votes of `key` the next block's view knows: the tip state's included
/// links (source height, target) and the pool's links and held evidence.
fn observed_votes(st: &PowitState, key: &KeyId) -> (Vec<ObservedVote>, bool) {
    let mut seen: Vec<ObservedVote> = st.links.get(key).into_iter().flatten()
        .map(|&(sh, th, thash)| ObservedVote { source_height: sh, source_hash: None,
                                              target: Checkpoint { height: th, hash: thash } })
        .collect();
    let (pooled, evidence) = pool().votes_of(key);
    seen.extend(pooled.iter().map(ObservedVote::of));
    (seen, evidence)
}

impl WitnessDuty {
    /// Load a KES witness key (`gnb-cli witnesskeygen`); the password is read
    /// from `password_file` (first line), never from the command line.
    /// Opens the key's signer guard: refuses a second signer of the key, and
    /// a vote record or high-water file that exists but cannot be read (it
    /// would otherwise read as "never signed").
    pub fn load(key: &Path, password_file: &Path, payout_script: Vec<u8>, data_dir: &Path) -> Result<Self, String> {
        // CRY-4: the file's contents are wiped once the first line is copied.
        let pw = zeroize::Zeroizing::new(
            std::fs::read_to_string(password_file).map_err(|e| format!("witness password file: {e}"))?);
        let password = gnb_crypto::crypto::SecretBytes::from_slice(pw.lines().next().unwrap_or("").trim().as_bytes());
        drop(pw);
        let file = gnb_crypto::core::kes::KesKeyFile::load(key)?;
        let signer = file.open(password_str(&password))?;
        let key_id = signer.public().witness_id();
        let guard = VoteGuard::open(key_id, key, &crate::powit_signer::record_path(data_dir, &key_id))?;
        Ok(WitnessDuty {
            key_id,
            payout_script,
            key_path: key.to_path_buf(),
            password,
            signer: Mutex::new(signer),
            guard,
        })
    }

    /// The signer guard (status, alert, record).
    pub fn guard(&self) -> &VoteGuard {
        &self.guard
    }

    /// Tests: make the next signature stop at `p` as a crash would.
    #[doc(hidden)]
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn set_crash_point(&self, p: Option<CrashPoint>) {
        self.guard.set_crash_point(p, false);
    }

    /// Rollback guard against the selected tip's state and the pool: at
    /// start (main) and before every vote (`maybe_attest`). Returns the
    /// alert if the signer is (now) halted.
    pub fn scan_for_rollback(&self, dag: &GhostDAG, store: &Storage) -> Option<String> {
        let st = tip_context(dag).and_then(|(tip, _)| load_state(store, &tip));
        let (seen, evidence) = match &st {
            Some(st) => observed_votes(st, &self.key_id),
            None => {
                let (pooled, evidence) = pool().votes_of(&self.key_id);
                (pooled.iter().map(ObservedVote::of).collect(), evidence)
            }
        };
        self.guard.observe(&seen, evidence, "chain or pool")
    }

    /// If this key is a witness for the checkpoint to vote for above the
    /// tip's justified one, sign that link once (the message of the target's
    /// height). Returns the new attestation (or, once per process, one
    /// persisted but maybe never released before a crash). The checkpoint is
    /// the newest slot at or below the next block's height; from the second
    /// hardening activation, the justified checkpoint's direct child while a
    /// vote for it can still be included.
    pub fn maybe_attest(&self, dag: &GhostDAG, store: &Storage) -> Result<Option<Attestation>, String> {
        if self.guard.alert().is_some() {
            return Ok(None);
        }
        let Some((tip, tip_h)) = tip_context(dag) else { return Ok(None) };
        let Some(st) = load_state(store, &tip) else { return Ok(None) };
        // Rollback guard before every vote.
        let (seen, evidence) = observed_votes(&st, &self.key_id);
        if let Some(alert) = self.guard.observe(&seen, evidence, "chain or pool") {
            return Err(format!("PoWit signer halted: {alert}"));
        }
        let p: PowitParams = powit::params();
        let act = st.activation;
        if tip_h < act {
            return Ok(None);
        }
        // Newest checkpoint slot at or below the next block's height.
        let next = tip_h + 1;
        let newest = act + (next - act) / p.checkpoint_interval * p.checkpoint_interval;
        let h2 = hardening2_height();
        let regime = Regime::at(next, h2);
        // The slots to vote for, in order of preference.
        let mut candidates = vec![newest];
        if regime == Regime::Hardening2 {
            // From the second hardening activation every share key may vote
            // and a block holds 32 votes, so justifying a slot can take more
            // than one checkpoint interval. A justified checkpoint is final
            // only once its direct child is justified (Casper FFG), so the
            // duty votes for that child while a block can still include the
            // vote, and for the newest slot otherwise (also when this key
            // can no longer sign the child): votes that move on to the newest
            // slot each interval justify slots two intervals apart and
            // finalize nothing.
            let child = st.justified.height + p.checkpoint_interval;
            if child < newest && next <= child + p.vote_ttl {
                candidates.insert(0, child);
            }
        }
        let source = st.justified;
        // PoCI (ObenBlock): votes name the configuration in force, and only
        // its keys vote; nothing to sign during the launch bootstrap.
        let poci = PociParams::for_chain(core::node_chain_id());
        let config = st.poci_config().cloned();
        if poci.is_some() && config.is_none() {
            return Ok(None);
        }
        let config_id = config.as_ref().map(|c| c.id());
        // The next block's view of the slot: its selected chain starts at tip.
        let view = DagChainView { dag, start: Some(tip) };
        let mut signer = self.signer.lock();
        let mut chosen = None;
        for slot in candidates {
            if slot <= st.justified.height {
                return Ok(None);
            }
            let te = p.epoch(act, slot);
            // A member under the rules of the block that will include the
            // vote (from the next block on: slot <= next).
            let member = match (&config, regime) {
                (Some(c), _) => c.weight(&self.key_id).is_some(),
                (None, Regime::V1) => st.witness_set(&p, te).iter().any(|(k, _)| *k == self.key_id),
                (None, Regime::Hardening2) => st.member_weight_h2(&p, te, &self.key_id).is_some(),
            };
            // Not a member for this slot's epoch, no block for it, a conflict
            // with the record, or an epoch whose leaf is gone (forward
            // security): try the next slot, if any.
            if !member {
                continue;
            }
            let Some(hash) = view.selected_at(slot) else { continue };
            let target = Checkpoint { height: slot, hash };
            if self.guard.holds(&source, &target) {
                // Signed: the guard returns the stored attestation once per
                // process (persisted, maybe not released before a restart),
                // then nothing while it waits to be included.
                return match self.guard.sign_link(source, target, config_id, || Err("already signed".into()))? {
                    Signed::Stored { att, first_release: true } => Ok(Some(att)),
                    _ => Ok(None),
                };
            }
            if !self.guard.permits(&source, &target) || te < signer.epoch() {
                continue;
            }
            chosen = Some((target, te));
            break;
        }
        let Some((target, te)) = chosen else { return Ok(None) };
        let signed = self.guard.sign_link(source, target, config_id, || {
            self.evolve(&mut signer, te)?;
            // PoCI (ObenBlock): the v3 message naming the configuration in
            // force. GnB: the message of the target's height (v2, committing
            // this key, from the second hardening activation).
            match (poci, &config_id) {
                (Some(pp), Some(cid)) => Attestation::sign_v3(pp.chain_id, cid, source, target, &signer),
                _ => Attestation::sign_at(core::node_chain_id(), h2, source, target, &signer),
            }
        })?;
        match signed {
            Signed::Fresh(att) | Signed::Stored { att, first_release: true } => Ok(Some(att)),
            _ => Ok(None),
        }
    }

    /// Evolve the signer to KES epoch `e`: every earlier seed is erased ON
    /// DISK FIRST (durably), then in memory. No-op at or above `e`.
    fn evolve(&self, signer: &mut gnb_crypto::core::kes::KesSigner, e: u64) -> Result<(), String> {
        if e <= signer.epoch() {
            return Ok(());
        }
        let password = password_str(&self.password);
        let mut next_state = gnb_crypto::core::kes::KesKeyFile::load(&self.key_path)?.open(password)?;
        next_state.evolve_to(e)?;
        let sealed = gnb_crypto::core::kes::KesKeyFile::seal(&next_state, password)?;
        let json = serde_json::to_vec_pretty(&sealed).map_err(|e| format!("kes save: {e}"))?;
        write_durable(&self.key_path, &json).map_err(|e| format!("kes save: {e}"))?;
        *signer = next_state;
        Ok(())
    }

    /// PoCI (ObenBlock, DESIGN-obenblock-poci.md §4.1): this key was pruned
    /// for absence at the tip and is online again, so it asks to come back.
    /// Signs a rejoin for the next block's epoch when the key is pruned, has
    /// no rejoin pending in the chain and none in the pool. A rejoin is not a
    /// vote (it can never be evidence), so the vote guard is not involved;
    /// a halted signer still publishes none.
    pub fn maybe_rejoin(&self, dag: &GhostDAG, store: &Storage) -> Result<Option<WitnessRejoin>, String> {
        let Some(pp) = PociParams::for_chain(core::node_chain_id()) else { return Ok(None) };
        if self.guard.alert().is_some() {
            return Ok(None);
        }
        // The pool's view of the tip (cached per tip: no state load per tick).
        let Some(view) = pool().follow_tip(dag, store) else { return Ok(None) };
        let Some(ledger) = view.state.poci.as_ref() else { return Ok(None) };
        if !ledger.pruned.contains_key(&self.key_id) || ledger.rejoins.contains_key(&self.key_id)
            || pool().inner.lock().rejoins.contains_key(&self.key_id)
        {
            return Ok(None);
        }
        let e = pp.epoch_of(view.tip_h + 1);
        let mut signer = self.signer.lock();
        if signer.epoch() > e {
            return Ok(None);
        }
        self.evolve(&mut signer, e)?;
        WitnessRejoin::sign(pp.chain_id, &signer).map(Some)
    }
}

// ── Share mining ─────────────────────────────────────────────────────────────

/// SHA-256d CPU share mining: header nonces per GnB-SMH attempt (one GnB-SMH
/// v3 evaluation costs about as much as 2^18 SHA-256d ones).
const SHA256D_ATTEMPTS_SHIFT: u32 = 18;

/// Try `attempts` nonces for a share attesting `attested` (normally the
/// current tip), crediting `witness` and paying `payout` (any valid script).
/// GnB-SMH v3, 4 MiB. Takes no lock: the caller reads the tip first.
/// Under the SHA-256d scheme: one job (`start_nonce` is its job nonce) and
/// `attempts << SHA256D_ATTEMPTS_SHIFT` header nonces, about the same time.
pub fn mine_share(attested: &Block, attested_hash: Hash, witness: KeyId, payout: &[u8], start_nonce: u64,
                  attempts: u64, stop: &std::sync::atomic::AtomicBool) -> Option<WitnessShare> {
    if let Some(p) = core::pow_scheme::node_sha256d_params() {
        let job = witness_share::sha256d::ShareJob::new(attested, witness, payout, start_nonce, &p)?;
        return job.mine_cpu(0, attempts.saturating_mul(1 << SHA256D_ATTEMPTS_SHIFT), stop);
    }
    let stream = witness_share::tx_stream(attested);
    let root = attested.witness_root();
    let target = witness_share::share_target(&gnb_smh::difficulty::bits_to_target(attested.header.bits));
    let mut sp = gnb_smh::v3::Scratchpad::new(gnb_smh::v3::LOG2_N);
    let mut share = WitnessShare { attested: attested_hash, witness, payout: payout.to_vec(),
                                   bits: attested.header.bits, nonce: 0, sha256d: None };
    for i in 0..attempts {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        share.nonce = start_nonce.wrapping_add(i);
        let pre = witness_share::pow_preimage(&share, &root, &stream);
        let out = gnb_smh::v3::hash_with(&mut sp, &pre, share.nonce);
        if gnb_smh::difficulty::meets_target(&out, &target) {
            return Some(share);
        }
    }
    None
}

/// Equivocation proofs in the pool (for gossip).
#[allow(dead_code)] // tests; gossip uses `pool_evidence_items`
pub fn pool_evidence() -> Vec<Equivocation> {
    pool().snapshot().2
}

/// The pool's proofs as gossip items, by key: GnB equivocation proofs, or
/// PoCI evidence on ObenBlock (`ITEM_EVIDENCE` carries `PociEvidence` there).
pub fn pool_evidence_items() -> Vec<(KeyId, (Hash, u8, Vec<u8>))> {
    pool().evidence_snapshot().into_iter().map(|(ev, cfg)| {
        let key = ev.a.key_id();
        let item = match cfg {
            Some(config_id) => poci_evidence_item(&PociEvidence { config_id, a: ev.a, b: ev.b }),
            None => evidence_item(&ev),
        };
        (key, item)
    }).collect()
}

/// JSON summary for `getpowitinfo`.
pub fn info_json(dag: &GhostDAG, store: &Storage) -> serde_json::Value {
    let act = core::powit_height();
    let p = powit::params();
    let tip = dag.selected_tip();
    let tip_h = tip.and_then(|t| dag.get_block_data(&t)).map(|d| d.height).unwrap_or(0);
    // The tip's state is written just after the tip is accepted; until then,
    // report the latest selected-chain block that has one instead of nothing.
    let st = selected_chain_since(dag, tip, tip_h.saturating_sub(16))
        .into_iter()
        .find_map(|(h, _)| load_state(store, &h));
    let (ps, pa, pe) = pool().counts();
    let cp = |c: &Checkpoint| serde_json::json!({
        "slot": c.height,
        "hash": hex::encode(c.hash),
        "block_height": dag.get_block_data(&c.hash).map(|d| d.height),
    });
    // The witness set the next block is checked against (second hardening
    // activation: every key with weight, two thirds of the total).
    let h2 = hardening2_height();
    let regime = Regime::at(tip_h + 1, h2);
    let ws = st.as_ref().map(|s| s.witness_set_in(&p, s.epoch, regime)).unwrap_or_default();
    let total: u128 = ws.iter().fold(0u128, |a, (_, w)| a.saturating_add(*w));
    serde_json::json!({
        "activation_height": if act == u64::MAX { serde_json::Value::Null } else { act.into() },
        "active": core::powit_active(tip_h + 1),
        "pow": core::pow_algo(tip_h + 1).name(),
        "hardening2_activation_height": if h2 == activation::NEVER { serde_json::Value::Null } else { h2.into() },
        "rules": match regime { Regime::V1 => "v1", Regime::Hardening2 => "hardening2" },
        "params": {
            "epoch_len": p.epoch_len, "checkpoint_interval": p.checkpoint_interval,
            "window_epochs": p.window_epochs,
            // The 64-key cap applies only before the second hardening activation.
            "max_witnesses": p.max_witnesses,
        },
        "tip_height": tip_h,
        "epoch": st.as_ref().map(|s| s.epoch),
        "justified": st.as_ref().map(|s| cp(&s.justified)),
        "finalized": st.as_ref().map(|s| cp(&s.finalized)),
        "witness_set": {
            "size": ws.len(),
            "total_weight": total.to_string(),
            "top": ws.iter().take(10).map(|(k, w)| serde_json::json!({
                "key": hex::encode(k), "weight": w.to_string() })).collect::<Vec<_>>(),
        },
        "barred_keys": st.as_ref().map(|s| s.banned.len()).unwrap_or(0),
        "pool": { "shares": ps, "attestations": pa, "evidence": pe, "exits": pool().exits_snapshot().len(),
                  "rejoins": pool().rejoins_snapshot().len() },
        // Hardening 2: the witness set comes from finalized history.
        "witness_set_from_finalized_history": core::activation::hardening2_active_at(tip_h + 1),
        // The node's fork-choice pin (`getfinalityinfo` has the details).
        "pin": dag.finalized().map(|(h, height)| serde_json::json!({
            "hash": hex::encode(h), "block_height": height,
            "origin": dag.finality_outcome().origin.as_str() })),
        "finality_conflict": dag.finality_outcome().conflict.is_some(),
        // Liveness (ObenBlock): the leak rule and the witness exits.
        "liveness_active": core::liveness::liveness_active_at(tip_h + 1),
        // PoCI (ObenBlock): absence never changes the finality weight
        // (DESIGN-obenblock-poci.md §4.1; DESIGN-obenblock.md §5.2 superseded).
        "inactivity_leak": if powit::poci_active() { "none (PoCI)" } else {
            match p.leak { powit::InactivityLeak::Sixteenth => "1/16", powit::InactivityLeak::Half => "1/2" }
        },
        "exited_keys": st.as_ref().map(|s| s.exited.len()).unwrap_or(0),
        // Signer protection (DESIGN-obenblock-poci.md §8): this node's
        // witness signers; `signer_halted` is the alert.
        "signer_halted": crate::powit_signer::any_halted(),
        "signers": crate::powit_signer::statuses(),
        // PoCI (ObenBlock, DESIGN-obenblock-poci.md): the configuration in
        // force (`null` on GnB and during the launch bootstrap).
        "poci": poci_info_json(st.as_ref()),
    })
}

/// The PoCI part of `getpowitinfo`: the configuration in force (epoch, id,
/// exact total, entries, quorum threshold) and the bans.
fn poci_info_json(st: Option<&PowitState>) -> serde_json::Value {
    let Some(pp) = PociParams::for_chain(core::node_chain_id()) else { return serde_json::Value::Null };
    let Some(ps) = st.and_then(|s| s.poci.as_ref()) else {
        return serde_json::json!({ "active": false, "bootstrap_epochs": pp.bootstrap_epochs });
    };
    let c = ps.config();
    // The weight of C_e with no vote included in a block of each recent
    // epoch (not final: blocks above the finalized checkpoint count), so
    // operators see it grow long before it reaches a third.
    let now = st.map(|s| s.epoch).unwrap_or(0);
    let absent: Vec<serde_json::Value> = (now.saturating_sub(poci::POCI_PRUNE_AFTER_EPOCHS)..=now)
        .filter(|e| *e >= c.epoch())
        .map(|e| {
            let w = ps.absent_weight(e);
            serde_json::json!({ "epoch": e, "weight": w.to_string(),
                                "over_a_third": w.checked_mul(3).is_none_or(|x| x > c.total()) })
        }).collect();
    let bans: Vec<serde_json::Value> = ps.bans.iter().flat_map(|(k, bl)| bl.iter().map(move |b| serde_json::json!({
        "key": hex::encode(k), "config_id": hex::encode(b.config_id), "included_at": b.included_at,
        "start": b.start, "end": b.end(pp.ban_epochs),
    }))).collect();
    serde_json::json!({
        "active": true,
        "config_epoch": c.epoch(),
        "config_id": hex::encode(c.id()),
        // u128 as a decimal string (JSON numbers lose precision).
        "total": c.total().to_string(),
        "entries": c.len(),
        "params_digest": hex::encode(pp.digest()),
        "previous_config_id": ps.previous().map(|p| hex::encode(p.id())),
        "configurations": ps.history().count(),
        "bans": bans,
        // §4.1: absence pruning by the old committee.
        "prune_after_epochs": poci::POCI_PRUNE_AFTER_EPOCHS,
        "absent_weight": absent,
        "pruned": ps.pruned.iter().map(|(k, p)| serde_json::json!({
            "key": hex::encode(k), "since_epoch": p.start, "rejoin_included_at": ps.rejoins.get(k) })).collect::<Vec<_>>(),
        "growth_cap": growth_cap_json(st.and_then(|s| s.cap.as_ref())),
    })
}

/// The growth cap of `getpowitinfo` (DESIGN-obenblock.md §6.3: the capture
/// is visible the whole time): the ledger's epoch and, for the last cap
/// step (the one that built the configuration in force), `W`, the budget
/// `G`, `sum(x)`, what it admitted, what new keys got and what it dropped.
/// Integers as decimal strings.
fn growth_cap_json(cap: Option<&gnb_crypto::core::powit::growth_cap::CapState>) -> serde_json::Value {
    let Some(c) = cap else { return serde_json::Value::Null };
    let last = c.ledger.report().map(|r| serde_json::json!({
        "epoch": r.epoch, "w": r.w.to_string(), "g": r.g.to_string(), "sum_x": r.sum_x.to_string(),
        "admitted": r.admitted.to_string(), "admitted_new": r.admitted_new.to_string(),
        "dropped": r.dropped.to_string(),
    }));
    serde_json::json!({
        "ledger_epoch": c.ledger.epoch(),
        "credited_epochs": c.ledger.credits().len(),
        "last_step": last,
    })
}

/// JSON for `getpowitkeyvotes <key id hex>`: the votes of one witness key
/// the selected tip's PoWit state includes (source height, target) and the
/// pool holds, and whether the pool holds an equivocation proof against it.
/// Read by `gnb-cli powitattest`'s rollback guard (signer protection).
pub fn key_votes_json(dag: &GhostDAG, store: &Storage, key: &KeyId) -> serde_json::Value {
    let st = tip_context(dag).and_then(|(tip, _)| load_state(store, &tip));
    let chain: Vec<serde_json::Value> = st.as_ref().and_then(|s| s.links.get(key)).into_iter().flatten()
        .map(|(sh, th, thash)| serde_json::json!({
            "source_height": sh, "target_height": th, "target_hash": hex::encode(thash) }))
        .collect();
    let (pooled, evidence) = pool().votes_of(key);
    let pool_votes: Vec<serde_json::Value> = pooled.iter().map(|a| serde_json::json!({
        "source_height": a.source.height, "source_hash": hex::encode(a.source.hash),
        "target_height": a.target.height, "target_hash": hex::encode(a.target.hash) })).collect();
    serde_json::json!({ "key": hex::encode(key), "chain": chain, "pool": pool_votes, "evidence": evidence })
}

/// Parse `getpowitkeyvotes`'s answer into observed votes (`gnb-cli`).
#[allow(dead_code)] // gnb-cli only; the node binary compiles this module too
pub fn parse_key_votes(v: &serde_json::Value) -> Result<(Vec<crate::powit_signer::ObservedVote>, bool), String> {
    if let Some(e) = v.get("error") {
        return Err(format!("getpowitkeyvotes: {e}"));
    }
    let h32 = |x: &serde_json::Value| -> Result<[u8; 32], String> {
        let b = hex::decode(x.as_str().ok_or("hash is not a string")?).map_err(|e| e.to_string())?;
        b.try_into().map_err(|_| "hash is not 32 bytes".to_string())
    };
    let u = |x: &serde_json::Value| x.as_u64().ok_or_else(|| "height is not a number".to_string());
    let mut out = Vec::new();
    for (list, with_source) in [("chain", false), ("pool", true)] {
        for x in v.get(list).and_then(|l| l.as_array()).ok_or(format!("getpowitkeyvotes: no {list}"))? {
            out.push(crate::powit_signer::ObservedVote {
                source_height: u(&x["source_height"])?,
                source_hash: if with_source { Some(h32(&x["source_hash"])?) } else { None },
                target: Checkpoint { height: u(&x["target_height"])?, hash: h32(&x["target_hash"])? },
            });
        }
    }
    Ok((out, v.get("evidence").and_then(|e| e.as_bool()).unwrap_or(false)))
}

// ── Gossip ingress ───────────────────────────────────────────────────────────

/// Decode and admit one gossiped PoWit item. `Ok(())` means valid (relay).
pub fn admit_item(kind: u8, data: &[u8], dag: &GhostDAG, store: &Storage) -> Result<(), String> {
    let mut cur = std::io::Cursor::new(data);
    let done = |cur: &std::io::Cursor<&[u8]>| -> Result<(), String> {
        if cur.position() as usize == data.len() { Ok(()) } else { Err("trailing bytes".into()) }
    };
    match kind {
        ITEM_SHARE => {
            let s = WitnessShare::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_share(s, dag, store).map(|_| ())
        }
        ITEM_ATTESTATION => {
            let a = Attestation::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_attestation(a, dag, store).map(|_| ())
        }
        ITEM_EVIDENCE if powit::poci_active() => {
            let e = PociEvidence::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_poci_evidence(e, dag, store).map(|_| ())
        }
        ITEM_EVIDENCE => {
            let e = Equivocation::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_evidence(e, dag, store).map(|_| ())
        }
        ITEM_EXIT => {
            let x = WitnessExit::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_exit(x, dag, store).map(|_| ())
        }
        ITEM_REJOIN if powit::poci_active() => {
            let r = WitnessRejoin::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_rejoin(r, dag, store).map(|_| ())
        }
        _ => Err("unknown PoWit item kind".into()),
    }
}

/// Encode a local item for gossip: (id, kind, data).
pub fn share_item(s: &WitnessShare) -> (Hash, u8, Vec<u8>) {
    let d = s.to_wire_bytes();
    (item_id(ITEM_SHARE, &d), ITEM_SHARE, d)
}

pub fn attestation_item(a: &Attestation) -> (Hash, u8, Vec<u8>) {
    let d = a.to_wire_bytes();
    (item_id(ITEM_ATTESTATION, &d), ITEM_ATTESTATION, d)
}

pub fn evidence_item(e: &Equivocation) -> (Hash, u8, Vec<u8>) {
    let d = e.to_wire_bytes();
    (item_id(ITEM_EVIDENCE, &d), ITEM_EVIDENCE, d)
}

/// PoCI evidence as a gossip item (ObenBlock: kind `ITEM_EVIDENCE`).
pub fn poci_evidence_item(e: &PociEvidence) -> (Hash, u8, Vec<u8>) {
    let d = e.to_wire_bytes();
    (item_id(ITEM_EVIDENCE, &d), ITEM_EVIDENCE, d)
}

/// A PoCI rejoin as a gossip item (ObenBlock: kind [`ITEM_REJOIN`]).
#[allow(dead_code)] // the node's duty loop and tests; gnb-cli compiles this module too
pub fn rejoin_item(r: &WitnessRejoin) -> (Hash, u8, Vec<u8>) {
    let d = r.to_wire_bytes();
    (item_id(ITEM_REJOIN, &d), ITEM_REJOIN, d)
}

#[allow(dead_code)] // RPC and tests relay exits through `admit_item`; kept beside its siblings
pub fn exit_item(x: &WitnessExit) -> (Hash, u8, Vec<u8>) {
    let d = x.to_wire_bytes();
    (item_id(ITEM_EXIT, &d), ITEM_EXIT, d)
}

// ── Finality pin (node-local fork choice) ────────────────────────────────────
//
// PoWit audit findings 2 and 3, and the review of their fix (HIGH 1, MEDIUM
// 3). The pin (`GhostDAG::finalized`) is computed from the PoWit state of any
// stored, not disqualified block (`consensus::finality`): finalized
// checkpoints whose sources reach the minimum chain work and which agree
// with the weak-subjectivity anchor (the release finality checkpoint below,
// or the operator's). The finality the node has reached on its own chain is
// sticky: a finalized checkpoint learned from another chain only advances it,
// one that conflicts with it raises an alert and never moves it. The
// (block, checkpoint) pairs are persisted with each block's state
// (`finality_row`), and the pinned checkpoint itself (`FINALITY_PIN_META`),
// so a restart rebuilds the same pin.

/// A release finality checkpoint (weak subjectivity, as Bitcoin Core's
/// release checkpoints and `-assumevalid`, and the weak-subjectivity
/// checkpoint of finality protocols): a block of the real chain somewhat
/// below the tip when the release was cut, read from two or more
/// independent nodes by `tools/release/min_chain_work.py`, which prints
/// this constant with the minimum chain work. No finalized checkpoint that
/// conflicts with it is ever pinned (none at or below its height that is
/// not its ancestor, none above it that does not descend from it), and once
/// the node holds it, it pins fork choice itself: a chain that forks below
/// it is never selected, whatever its work. Node-local: no block's validity
/// reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseCheckpoint {
    /// DAG height (`getblockdag` `height` of a selected-chain block).
    pub height: u64,
    pub hash: Hash,
}

impl ReleaseCheckpoint {
    /// From the 64 hex digits the RPC prints and the block's DAG height, the
    /// line `tools/release/min_chain_work.py` prints (a malformed literal is
    /// a compile error where the constant is defined).
    #[allow(dead_code)] // the form a release sets `MAINNET_FINALITY_CHECKPOINT` in
    pub const fn from_hex(hex: &str, height: u64) -> Self {
        ReleaseCheckpoint { height, hash: crate::assumevalid::hash_from_hex(hex) }
    }
}

/// Mainnet release finality checkpoint. None yet: this tree was cut with no
/// mainnet node reachable, so no block of the real chain could be read; the
/// next release sets it from `tools/release/min_chain_work.py` (docs/RUNNING.md,
/// "Initial sync and minimum chain work"). Until then a node syncing while
/// eclipsed relies on the minimum chain work and on seeing the honest chain's
/// own finality (a conflict falls back to the most work).
pub const MAINNET_FINALITY_CHECKPOINT: Option<ReleaseCheckpoint> = None;
/// Testnet and regtest: none (a public test network is reset at will).
pub const TESTNET_FINALITY_CHECKPOINT: Option<ReleaseCheckpoint> = None;

static RELEASE_FINALITY_CHECKPOINT: std::sync::OnceLock<Option<ReleaseCheckpoint>> = std::sync::OnceLock::new();
/// Whether the release finality checkpoint in force comes from
/// `--finalitycheckpoint` ([`set_finality_checkpoint_flag`]).
static FINALITY_CHECKPOINT_FROM_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Parse `--finalitycheckpoint` (review MEDIUM 6): `HASH:HEIGHT` (the block
/// id in 64 hex digits, as the RPC prints it, and its DAG height), or `none`
/// (no release checkpoint).
pub fn parse_finality_checkpoint(s: &str) -> Result<Option<ReleaseCheckpoint>, String> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let (hash, height) = s.split_once(':')
        .ok_or("expected HASH:HEIGHT (the block id in 64 hex digits and its DAG height) or none")?;
    let hash = hex::decode(hash.trim_start_matches("0x")).ok()
        .and_then(|b| <Hash>::try_from(b.as_slice()).ok())
        .ok_or("the block id must be 64 hex digits")?;
    let height = height.parse::<u64>().map_err(|_| "the DAG height must be a decimal number")?;
    Ok(Some(ReleaseCheckpoint { height, hash }))
}

/// `--finalitycheckpoint`: replace the release finality checkpoint of the
/// node's network for this process, before anything reads it (start-up).
/// The block need not be held yet: that is the point of a weak-subjectivity
/// checkpoint given before syncing. An operator setting persisted by
/// `setfinalitycheckpoint` still takes precedence; `setfinalitycheckpoint
/// default` returns to this one.
pub fn set_finality_checkpoint_flag(cp: Option<ReleaseCheckpoint>) -> Result<(), String> {
    set_release_finality_checkpoint(cp).map_err(|_| "the release finality checkpoint was already set".to_string())?;
    FINALITY_CHECKPOINT_FROM_FLAG.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Set the process-wide release finality checkpoint once (tests, tools);
/// later calls are refused. Nodes use the constant of their network.
pub fn set_release_finality_checkpoint(cp: Option<ReleaseCheckpoint>) -> Result<(), Option<ReleaseCheckpoint>> {
    RELEASE_FINALITY_CHECKPOINT.set(cp)
}

/// The release finality checkpoint in force: the one set by
/// [`set_release_finality_checkpoint`], else the network's constant.
pub fn release_finality_checkpoint() -> Option<ReleaseCheckpoint> {
    match RELEASE_FINALITY_CHECKPOINT.get() {
        Some(c) => *c,
        None => match core::node_chain_id() {
            core::ChainId::Mainnet => MAINNET_FINALITY_CHECKPOINT,
            core::ChainId::Testnet => TESTNET_FINALITY_CHECKPOINT,
            // A clean chain from genesis: no release checkpoint yet.
            core::ChainId::ObenBlockMainnet | core::ChainId::ObenBlockRegtest => None,
        },
    }
}

/// CF_META prefix of a block's finality row: `powit/fin/<block hex>` =
/// checkpoint hash (32) ‖ slot (u64 LE), for every block whose PoWit state
/// finalized a checkpoint beyond the activation one.
const FIN_ROW_PREFIX: &str = "powit/fin/";
/// Set once every stored PoWit state of a data dir has its finality row
/// (the rows of data dirs written before them are derived from the states).
const FIN_INDEX_READY: &str = "powit/fin_index_v1";
/// The operator's anchor (`setfinalitycheckpoint`): absent = the release
/// checkpoint, `none` = no anchor, else block hash (32) ‖ DAG height (u64 LE).
pub const FINALITY_ANCHOR_META: &str = "powit/finality/anchor";
/// Blocks the operator set aside (`ignorefinalized`): `powit/finality/ignored/<hex>`.
const FINALITY_IGNORED_PREFIX: &str = "powit/finality/ignored/";
/// The finalized checkpoint the node pinned last (its own finality, sticky:
/// `consensus::finality::PinPolicy::sticky`): block hash (32); absent when
/// the pin is the anchor or nothing.
pub const FINALITY_PIN_META: &str = "powit/finality/pin";

/// The finality row of `hash` with PoWit state `state`, if that state
/// finalized a checkpoint beyond the activation one.
fn finality_row(hash: &Hash, state: &PowitState) -> Option<(String, Vec<u8>)> {
    (state.finalized.height > state.activation).then(|| {
        let mut row = state.finalized.hash.to_vec();
        row.extend_from_slice(&state.finalized.height.to_le_bytes());
        (format!("{FIN_ROW_PREFIX}{}", hex::encode(hash)), row)
    })
}

/// Record in the DAG's finality index the checkpoint `hash`'s PoWit state
/// finalized: `state` (computed on acceptance), else the stored state (tools
/// and tests that save states themselves). Call once the block is in the DAG.
pub fn note_block_finality(dag: &parking_lot::RwLock<GhostDAG>, store: &Storage, hash: &Hash,
                           state: Option<&PowitState>) {
    let loaded;
    let st = match state {
        Some(s) => s,
        None => match load_state(store, hash) {
            Some(s) => {
                loaded = s;
                &loaded
            }
            None => return,
        },
    };
    if st.finalized.height > st.activation {
        dag.write().note_finality_source(*hash, st.finalized.hash, st.finalized.height);
    }
}

/// Rebuild the DAG's finality index from storage (start-up; idempotent): the
/// operator settings, then every finality row whose block and checkpoint are
/// in the DAG. A data dir written before the rows existed gets them first,
/// derived from every stored block's PoWit state (once; a crash before the
/// ready flag repeats it). Returns the number of rows loaded.
pub fn load_finality_index(dag: &parking_lot::RwLock<GhostDAG>, store: &Storage) -> Result<usize, String> {
    let io = |e: crate::storage::StorageError| format!("finality index: {e}");
    if store.get_meta(FIN_INDEX_READY).map_err(io)?.is_none() {
        let blocks: Vec<Hash> = dag.read().store.data.iter().map(|(h, _)| *h).collect();
        let mut written = 0usize;
        for h in blocks {
            if let Some((key, row)) = load_state(store, &h).and_then(|st| finality_row(&h, &st)) {
                store.put_meta(&key, &row).map_err(io)?;
                written += 1;
            }
        }
        store.put_meta(FIN_INDEX_READY, &[1]).map_err(io)?;
        if written > 0 {
            log::info!("PoWit finality index: {written} row(s) derived from the stored PoWit states");
        }
    }
    let anchor = match store.get_meta(FINALITY_ANCHOR_META).map_err(io)? {
        None => AnchorSetting::Release,
        Some(v) if v == b"none" => AnchorSetting::Disabled,
        Some(v) if v.len() == 40 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&v[..32]);
            let height = u64::from_le_bytes(v[32..].try_into().expect("8 bytes"));
            AnchorSetting::Operator(Anchor { hash, height })
        }
        Some(v) => return Err(format!("finality index: {FINALITY_ANCHOR_META} holds {} bytes", v.len())),
    };
    let mut ignored = HashSet::new();
    for (k, _) in store.scan_meta_prefix(FINALITY_IGNORED_PREFIX).map_err(io)? {
        let hex_part = &k[FINALITY_IGNORED_PREFIX.len()..];
        let h = std::str::from_utf8(hex_part).ok().and_then(|x| hex::decode(x).ok())
            .and_then(|b| <Hash>::try_from(b.as_slice()).ok())
            .ok_or("finality index: malformed ignored-checkpoint key")?;
        ignored.insert(h);
    }
    let sticky = match store.get_meta(FINALITY_PIN_META).map_err(io)? {
        None => None,
        Some(v) => Some(<Hash>::try_from(v.as_slice())
            .map_err(|_| format!("finality index: {FINALITY_PIN_META} holds {} bytes", v.len()))?),
    };
    let rows = store.scan_meta_prefix(FIN_ROW_PREFIX).map_err(io)?;
    let mut d = dag.write();
    d.clear_finality_sources();
    {
        let idx = d.finality_index_mut();
        idx.anchor_setting = anchor;
        idx.ignored = ignored;
        idx.set_sticky(sticky);
    }
    let mut loaded = 0usize;
    for (k, v) in rows {
        let source = std::str::from_utf8(&k[FIN_ROW_PREFIX.len()..]).ok().and_then(|x| hex::decode(x).ok())
            .and_then(|b| <Hash>::try_from(b.as_slice()).ok());
        let (Some(source), true) = (source, v.len() == 40) else {
            return Err("finality index: malformed finality row".into());
        };
        let mut cp = [0u8; 32];
        cp.copy_from_slice(&v[..32]);
        let slot = u64::from_le_bytes(v[32..].try_into().expect("8 bytes"));
        if d.note_finality_source(source, cp, slot) {
            loaded += 1;
        }
    }
    Ok(loaded)
}

/// The anchor in force: the operator's setting, else the release checkpoint.
fn anchor_in_force(setting: AnchorSetting) -> Option<Anchor> {
    match setting {
        AnchorSetting::Release => release_finality_checkpoint().map(|c| Anchor { hash: c.hash, height: c.height }),
        AnchorSetting::Disabled => None,
        AnchorSetting::Operator(a) => Some(a),
    }
}

/// How many epochs past that of the node's next block the target of a
/// finality claim may lie (review round 4, item 6). The lighter side of a
/// partition mines its heights at its own pace and the clocks drift, so an
/// honest vote can be a few epochs ahead of the node; one further away is
/// ignored. The first rule's witness sets a claim builds stay bounded by
/// the `max_checks` of [`authenticated_finality_claim`]
/// (`ingress::MAX_CLAIM_SIGNATURE_CHECKS`).
pub const MAX_CLAIM_EPOCHS_AHEAD: u64 = 3;

/// Review round 2 of the PoWit finality pin, H1 (and round 3, LOW 2-3): the
/// target (block, checkpoint slot) of a vote of `block` that authentically
/// claims a finality newer than the node's: its source lies above `floor`
/// (`ingress::finality_claim_floor`), its target's epoch is at most
/// [`MAX_CLAIM_EPOCHS_AHEAD`] epochs after that of the node's next block,
/// and it is signed by a key with weight in the witness set `state` (the
/// node's selected tip's PoWit state) derives for the vote's target epoch,
/// not barred at the node's current epoch. The rules are those of a block
/// at `max(block.height, next_height)` (`next_height`: the node's next
/// block): the orphan's wire height is the sender's choice, and must not
/// select the first rule's witness set once the node's chain has the second
/// hardening activation's. From that activation a chain that shares the
/// node's finality reads the same frozen finalized window
/// (`PowitState::h2_window_epoch`); before it, the node's own share history
/// of the target's window, of which at most `max_checks` distinct target
/// epochs are built per orphan. At most `max_checks` signatures are
/// verified (membership is checked first). Whether the target lies on the
/// chain the vote reaches the node along is checked by
/// `ingress::OrphanPool::claim_backs`.
pub fn authenticated_finality_claim(block: &Block, floor: u64, state: &PowitState, next_height: u64,
                                    max_checks: usize) -> Option<(Hash, u64)>
{
    let p = powit::params();
    let chain = core::node_chain_id();
    let act = state.activation;
    let h2 = hardening2_height();
    let regime = Regime::at(block.height.max(next_height), h2);
    let msg_h2 = if regime == Regime::Hardening2 { h2 } else { activation::NEVER };
    let now_epoch = p.epoch(act, next_height.max(act));
    let mut v1_sets: Vec<(u64, Vec<(KeyId, u128)>)> = Vec::new();
    let mut checks = 0usize;
    for a in &block.powit.attestations {
        if a.source.height <= floor || a.target.height <= a.source.height || a.target.height < act {
            continue;
        }
        let te = p.epoch(act, a.target.height);
        let key = a.key_id();
        if te > now_epoch + MAX_CLAIM_EPOCHS_AHEAD || state.is_banned(&key, now_epoch) {
            continue;
        }
        let member = match regime {
            Regime::Hardening2 => state.member_weight_h2(&p, te, &key).is_some(),
            Regime::V1 => {
                if !v1_sets.iter().any(|(e, _)| *e == te) {
                    if v1_sets.len() >= max_checks {
                        continue;
                    }
                    v1_sets.push((te, state.witness_set(&p, te)));
                }
                v1_sets.iter().find(|(e, _)| *e == te)
                    .is_some_and(|(_, set)| set.iter().any(|(k, w)| *k == key && *w > 0))
            }
        };
        if !member {
            continue;
        }
        if checks >= max_checks {
            return None;
        }
        checks += 1;
        if a.verify_signature_at(chain, &p, act, msg_h2) {
            return Some((a.target.hash, a.target.height));
        }
    }
    None
}

/// How long a configured anchor may stay unknown, out of initial block
/// download, before the node alerts whatever height it names (review round
/// 3, LOW 4).
pub const UNKNOWN_ANCHOR_ALERT_AFTER: std::time::Duration = std::time::Duration::from_secs(30 * 60);

thread_local! {
    static ALERT_AFTER_OVERRIDE: std::cell::Cell<Option<std::time::Duration>> = const { std::cell::Cell::new(None) };
}

/// Test seam (this thread): replace [`UNKNOWN_ANCHOR_ALERT_AFTER`]; `None`
/// restores it.
#[allow(dead_code)] // tests only; the node binary compiles this module too
pub fn set_unknown_anchor_alert_after(d: Option<std::time::Duration>) {
    ALERT_AFTER_OVERRIDE.with(|c| c.set(d));
}

fn unknown_anchor_alert_after() -> std::time::Duration {
    ALERT_AFTER_OVERRIDE.with(|c| c.get()).unwrap_or(UNKNOWN_ANCHOR_ALERT_AFTER)
}

/// The applied tip: the block the UTXO set sits on (the persisted tip
/// pointer), else, for a store without one the DAG knows (fixtures), the
/// selected tip.
fn applied_tip(dag: &GhostDAG, store: &Storage) -> Option<Hash> {
    store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <Hash>::try_from(v.as_slice()).ok())
        .filter(|t| dag.has_block(t))
        .or_else(|| dag.selected_tip())
}

/// Recompute the pin from every recorded finalized checkpoint
/// (`GhostDAG::compute_finality_pin`) and apply it: after every acceptance
/// (before the chain move, so the move goes to the best chain under the new
/// pin), at each step of a chain move (a disqualified block's finality stops
/// counting), at start-up, and after an operator setting. The node's own
/// finality comes from its applied tip and the checkpoint it pinned last,
/// which is persisted here when it changes. Logs a change of pin, and the
/// conflict alert whenever the set of conflicting checkpoints changes (and
/// at start-up), and keeps the `gnb_finality_conflicts` metric at the number
/// of counted checkpoints that conflict with the pin. Returns the outcome.
pub fn refresh_finality_pin(dag: &parking_lot::RwLock<GhostDAG>, store: &Storage) -> PinOutcome {
    let min_chain_work = crate::ingress::minimum_chain_work();
    let (mut outcome, previous, sticky, unknown_since, in_ibd) = {
        let d = dag.read();
        let idx = d.finality_index();
        let policy = PinPolicy {
            min_chain_work,
            anchor: anchor_in_force(idx.anchor_setting),
            ignored: &idx.ignored,
            applied: applied_tip(&d, store),
            sticky: idx.sticky(),
        };
        (d.compute_finality_pin(&policy), d.finality_outcome().clone(), idx.sticky(), idx.anchor_unknown_since,
         crate::ingress::below_minimum_chain_work(&d, min_chain_work))
    };
    // Review round 3, LOW 4: the height an unknown anchor names is
    // unchecked (a typo above the tip would silence the alert), so the node
    // also alerts once the anchor has stayed unknown for a while out of
    // initial block download, by its own clock.
    let now = std::time::Instant::now();
    let unknown_since = (outcome.anchor == crate::consensus::finality::AnchorStatus::Unknown && !in_ibd)
        .then(|| unknown_since.unwrap_or(now));
    if unknown_since.is_some_and(|t| now.saturating_duration_since(t) >= unknown_anchor_alert_after()) {
        outcome.anchor_overdue = true;
    }
    if outcome.pin != previous.pin {
        match outcome.pin {
            Some((h, height)) => log::info!("PoWit finality pin: {} (DAG height {height}, {})",
                hex::encode(&h[..8]), outcome.origin.as_str()),
            None => log::warn!("PoWit finality pin cleared (was {:?})", previous.pin.map(|(h, x)| (hex::encode(&h[..8]), x))),
        }
    }
    crate::metrics::set_finality_conflicts(outcome.conflicting as i64);
    if outcome.conflict.is_some() && (outcome.conflict, outcome.conflicting) != (previous.conflict, previous.conflicting) {
        let ((a, ah), (b, bh)) = outcome.conflict.expect("checked");
        match outcome.resolution {
            crate::consensus::finality::ConflictResolution::MostWork => log::error!(
                "PoWit FINALITY CONFLICT: {} finalized checkpoint(s) conflict with {} (DAG height {ah}), the highest \
                 {} (DAG height {bh}); this node had no finality of its own above them and pinned the one whose \
                 chain carries the most work. At least a third of the witness weight signed both, or the chains \
                 derived different witness sets. An operator can choose with `setfinalitycheckpoint <hash>` \
                 (docs/RUNNING.md)",
                outcome.conflicting, hex::encode(&a[..8]), hex::encode(&b[..8])),
            _ => log::error!(
                "PoWit FINALITY CONFLICT: {} finalized checkpoint(s) conflict with this node's finality {} (DAG \
                 height {ah}), the highest {} (DAG height {bh}). At least a third of the witness weight signed \
                 both (the equivocation is provable on chain), or the chains derived different witness sets (a \
                 fork from before any common finality, a long partition finalized through inactivity decay, or a \
                 majority of the hashrate building its own witness set). This node keeps the finality it reached \
                 and never follows the other chain on its own, whatever its work; if this node is the one on the \
                 wrong side, an operator moves it with `setfinalitycheckpoint <hash>` or `ignorefinalized <hash>` \
                 (docs/RUNNING.md)",
                outcome.conflicting, hex::encode(&a[..8]), hex::encode(&b[..8])),
        }
    }
    crate::metrics::set_finality_anchor_unknown(outcome.anchor_overdue);
    if outcome.anchor_overdue && !previous.anchor_overdue {
        let a = anchor_in_force(dag.read().finality_index().anchor_setting);
        log::error!("PoWit finality anchor {} (DAG height {}) is UNKNOWN while this node's chain is above that \
            height, or has been for {} min out of initial block download: no finalized checkpoint above it counts \
            until the block arrives. The node holds its pin ({}) instead of following the most work. Check the \
            checkpoint (`getfinalityinfo`; `--finalitycheckpoint`, `setfinalitycheckpoint`) and its peers: the \
            block is on a chain it has not received, or on none",
            a.map(|a| hex::encode(a.hash)).unwrap_or_default(), a.map(|a| a.height).unwrap_or(0),
            unknown_anchor_alert_after().as_secs() / 60,
            outcome.pin.map(|(h, _)| hex::encode(&h[..8])).unwrap_or_else(|| "none".into()));
    }
    if outcome.anchor != previous.anchor && matches!(outcome.anchor,
        crate::consensus::finality::AnchorStatus::Invalid | crate::consensus::finality::AnchorStatus::HeightMismatch)
    {
        log::error!("PoWit finality anchor {:?}: {:?} (a release or operator checkpoint this node finds invalid or \
            at another height; check it, or `setfinalitycheckpoint none`)",
            anchor_in_force(dag.read().finality_index().anchor_setting).map(|a| hex::encode(a.hash)), outcome.anchor);
    }
    {
        let mut d = dag.write();
        d.finality_index_mut().anchor_unknown_since = unknown_since;
        d.set_finality_pin(outcome.clone());
    }
    // The pinned block is the node's own finality from now on (a finalized
    // checkpoint), or the pin it holds should an anchor become unknown:
    // persist it (a lost write falls back to the applied chain's finality).
    let pinned = dag.read().finality_index().sticky();
    if pinned != sticky {
        let r = match pinned {
            Some(h) => store.put_meta(FINALITY_PIN_META, &h),
            None => store.delete_meta(FINALITY_PIN_META),
        };
        if let Err(e) = r {
            log::warn!("PoWit finality pin: not persisted ({e})");
        }
    }
    outcome
}

/// [`refresh_finality_pin`], under its former name (main's start-up call).
pub fn update_finalized(dag: &parking_lot::RwLock<GhostDAG>, store: &Storage) {
    refresh_finality_pin(dag, store);
}

/// An operator finality setting (RPC `ignorefinalized`, `reconsiderfinalized`,
/// `setfinalitycheckpoint`), the PoWit analogue of Bitcoin Core's
/// `invalidateblock` / `reconsiderblock`: the escape hatch when the node is
/// pinned to a chain the operator knows is wrong, or when finality conflicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityOp {
    /// Never pin a finalized checkpoint at or above this block on its chain
    /// (the blocks stay valid; the pin falls back to the node's remaining own
    /// finality, which a checkpoint that conflicted with the one set aside
    /// may now advance; the most work decides above it).
    Ignore(Hash),
    /// Remove [`FinalityOp::Ignore`] for this block: its checkpoints count
    /// again. Not an undo of a move: if setting it aside let a conflicting
    /// finality become the node's own, the node keeps that one (the way back
    /// is [`FinalityOp::SetAnchor`] on the original chain).
    Reconsider(Hash),
    /// Trust this block, which the node holds, as final (an operator
    /// weak-subjectivity checkpoint): it replaces the release checkpoint as
    /// the anchor.
    SetAnchor(Hash),
    /// [`FinalityOp::SetAnchor`] by hash and DAG height, whether or not the
    /// node holds the block yet (review MEDIUM 6): a weak-subjectivity
    /// checkpoint set before syncing, which is when it protects. Until the
    /// block arrives nothing above its height counts and nothing at or below
    /// it is decided (`AnchorStatus::Unknown`); a held block must be at that
    /// height.
    SetAnchorAt(Hash, u64),
    /// No anchor at all, not even the release checkpoint.
    DisableAnchor,
    /// Back to the release checkpoint.
    DefaultAnchor,
}

/// Persist `op` and apply it to the DAG's finality index (the caller then
/// refreshes the pin and moves the chain, `accept::override_finality`).
pub fn apply_finality_op(op: FinalityOp, dag: &parking_lot::RwLock<GhostDAG>, store: &Storage) -> Result<(), String> {
    let io = |e: crate::storage::StorageError| format!("storage: {e}");
    match op {
        FinalityOp::Ignore(h) | FinalityOp::Reconsider(h) => {
            if !dag.read().has_block(&h) {
                return Err(format!("block {} not found", hex::encode(h)));
            }
            let key = format!("{FINALITY_IGNORED_PREFIX}{}", hex::encode(h));
            if let FinalityOp::Ignore(_) = op {
                store.put_meta(&key, &[]).map_err(io)?;
                dag.write().finality_index_mut().ignored.insert(h);
            } else {
                store.delete_meta(&key).map_err(io)?;
                dag.write().finality_index_mut().ignored.remove(&h);
            }
        }
        FinalityOp::SetAnchor(h) | FinalityOp::SetAnchorAt(h, _) => {
            let height = {
                let d = dag.read();
                match (d.get_block_data(&h), op) {
                    (None, FinalityOp::SetAnchorAt(_, height)) => height,
                    (None, _) => return Err(format!(
                        "block {} not found; to set a checkpoint before the node holds it, give its DAG height \
                         too (setfinalitycheckpoint <hash> <height>)", hex::encode(h))),
                    (Some(data), op) => {
                        if d.is_invalid_persistently(&h) {
                            return Err(format!("block {} is disqualified on this node", hex::encode(h)));
                        }
                        if let FinalityOp::SetAnchorAt(_, height) = op {
                            if height != data.height {
                                return Err(format!("block {} is at DAG height {}, not {height}",
                                    hex::encode(h), data.height));
                            }
                        }
                        data.height
                    }
                }
            };
            let mut v = h.to_vec();
            v.extend_from_slice(&height.to_le_bytes());
            store.put_meta(FINALITY_ANCHOR_META, &v).map_err(io)?;
            dag.write().finality_index_mut().anchor_setting = AnchorSetting::Operator(Anchor { hash: h, height });
        }
        FinalityOp::DisableAnchor => {
            store.put_meta(FINALITY_ANCHOR_META, b"none").map_err(io)?;
            dag.write().finality_index_mut().anchor_setting = AnchorSetting::Disabled;
        }
        FinalityOp::DefaultAnchor => {
            store.delete_meta(FINALITY_ANCHOR_META).map_err(io)?;
            dag.write().finality_index_mut().anchor_setting = AnchorSetting::Release;
        }
    }
    Ok(())
}

/// JSON for `getfinalityinfo`: the pin, where it comes from, the anchor,
/// the counted finalized checkpoints (at most `max`), any conflict, and the
/// operator settings.
pub fn finality_info_json(dag: &GhostDAG, max: usize) -> serde_json::Value {
    let idx = dag.finality_index();
    let o = dag.finality_outcome();
    let block = |h: &Hash, height: u64| serde_json::json!({ "hash": hex::encode(h), "block_height": height });
    let anchor = anchor_in_force(idx.anchor_setting);
    serde_json::json!({
        "pin": dag.finalized().map(|(h, height)| block(&h, height)),
        "origin": o.origin.as_str(),
        "own_finality": o.own.map(|(h, height)| block(&h, height)),
        "anchor": anchor.map(|a| block(&a.hash, a.height)),
        "anchor_source": match idx.anchor_setting {
            AnchorSetting::Release if FINALITY_CHECKPOINT_FROM_FLAG.load(std::sync::atomic::Ordering::Relaxed) =>
                if anchor.is_some() { "flag" } else { "none" },
            AnchorSetting::Release => if anchor.is_some() { "release" } else { "none" },
            AnchorSetting::Disabled => "disabled",
            AnchorSetting::Operator(_) => "operator",
        },
        "anchor_status": format!("{:?}", o.anchor).to_lowercase(),
        // Round 2, M3: the anchor is unknown while the applied tip is above
        // its height (the pin is held, `origin: held`).
        "anchor_overdue": o.anchor_overdue,
        "finalized": o.counted.iter().take(max).map(|(h, height, slot)| serde_json::json!({
            "hash": hex::encode(h), "block_height": height, "slot": slot })).collect::<Vec<_>>(),
        "finalized_count": o.counted.len(),
        // The persistent conflict alert: [the pinned checkpoint, the highest
        // counted checkpoint that conflicts with it], how many conflict, and
        // whether the node kept its own finality or chose by work.
        "conflict": o.conflict.map(|(a, b)| serde_json::json!([block(&a.0, a.1), block(&b.0, b.1)])),
        "conflicting_finalized": o.conflicting,
        "conflict_resolution": o.resolution.as_str(),
        "against_anchor": o.against_anchor,
        "ignored": idx.ignored.iter().map(hex::encode).collect::<Vec<_>>(),
        "ignored_finalized": o.ignored,
        "recorded_checkpoints": idx.candidates(),
        "recorded_sources": idx.sources(),
        "minimum_chain_work": crate::ingress::minimum_chain_work().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnb_crypto::core::kes::{KesPublic, KesSignature};

    /// A link by witness `w` (unsigned: these tests exercise the pool's
    /// bounded structures, which hold items only after verification).
    fn link(w: u64, n: u64, target: u64) -> Attestation {
        let mut root = [0u8; 32];
        root[..8].copy_from_slice(&w.to_le_bytes());
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&n.to_le_bytes());
        Attestation {
            source: Checkpoint { height: 1, hash: [0; 32] },
            target: Checkpoint { height: target, hash },
            witness: KesPublic { depth: 1, root },
            sig: KesSignature { index: 0, leaf_pk: vec![], sig: n.to_le_bytes().to_vec(), path: vec![] },
        }
    }

    fn proof(w: u64) -> (KeyId, Equivocation) {
        let a = link(w, 0, 10);
        (a.key_id(), Equivocation { a, b: link(w, 1, 10) })
    }

    /// PoCI rejoins (ObenBlock, DESIGN-obenblock-poci.md §4.1): the pool
    /// holds one only as the next block would accept it (PoCI in force, the
    /// key pruned, no rejoin pending, signed for the next block's epoch or the
    /// one before), drops it once the tip makes it stale, and GnB has no
    /// rejoin (kind 5 stays unknown there).
    #[test]
    fn rejoins_are_held_only_as_the_next_block_accepts_them() {
        let _live = core::liveness::scoped_override(0);
        let pp = poci::OBB_REGTEST_POCI;
        let p = PowitParams { epoch_len: pp.epoch_len, checkpoint_interval: pp.checkpoint_interval,
                              vote_ttl: pp.vote_ttl, ..powit::TESTNET_PARAMS };
        let rejoin = |root: u8, epoch: u64| WitnessRejoin {
            witness: KesPublic { depth: 1, root: [root; 32] }, epoch,
            sig: KesSignature { index: 0, leaf_pk: vec![], sig: vec![], path: vec![] },
        };
        // A pruned key and a member of the configuration in force.
        let (rp, rm) = (rejoin(1, 8), rejoin(2, 8));
        let mut ledger = PociState::launch(&pp, &[(rp.key_id(), 10u128), (rm.key_id(), 30)].into_iter().collect())
            .unwrap();
        ledger.pruned.insert(rp.key_id(), poci::Prune { start: 8, until: None });
        let mut st = PowitState::genesis(0, [0; 32]);
        st.poci = Some(ledger);
        st.finalized = Checkpoint { height: pp.opening(8), hash: [8; 32] };
        // The tip is in epoch 8; the next block too.
        let tip_h = pp.opening(8) + 7;
        let mut view = TipWitnesses::of_at([9; 32], tip_h, st, &p, 0);
        assert!(view.poci.is_none(), "the test process runs GnB");
        assert!(view.rejoin_admissible(&rp.key_id(), &rp).unwrap_err().contains("PoCI chains only"));
        view.poci = Some(pp);
        assert_eq!(view.rejoin_admissible(&rp.key_id(), &rp), Ok(()));
        assert!(view.rejoin_admissible(&rp.key_id(), &rejoin(1, 7)).is_ok(), "the epoch before");
        assert!(view.rejoin_admissible(&rp.key_id(), &rejoin(1, 6)).unwrap_err().contains("epoch"));
        assert!(view.rejoin_admissible(&rm.key_id(), &rm).unwrap_err().contains("not_pruned"));
        // A pending rejoin makes another one stale: the pool drops it.
        let mut g = PoolInner::default();
        g.rejoins.insert(rp.key_id(), rp.clone());
        g.prune_to(Some(&view), tip_h, &p);
        assert_eq!(g.rejoins.len(), 1);
        view.state.poci.as_mut().unwrap().rejoins.insert(rp.key_id(), tip_h);
        assert!(view.rejoin_admissible(&rp.key_id(), &rp).unwrap_err().contains("pending"));
        g.prune_to(Some(&view), tip_h, &p);
        assert!(g.rejoins.is_empty());
        // GnB: the gossip kind range is unchanged.
        assert_eq!(item_kind_max(), ITEM_KIND_MAX);
        assert_eq!(ITEM_KIND_MAX, ITEM_EXIT);
        let (id, kind, data) = rejoin_item(&rp);
        assert_eq!((kind, id), (ITEM_REJOIN, item_id(ITEM_REJOIN, &data)));
    }

    /// A full evidence pool makes room for a heavier key's proof by evicting
    /// the lightest key's, and refuses a proof lighter than everything held.
    #[test]
    fn a_full_evidence_pool_evicts_the_lightest_key() {
        let mut g = PoolInner::default();
        for w in 0..EVIDENCE_CAP as u64 {
            let (k, ev) = proof(w);
            g.insert_evidence(k, ev, 10 + u128::from(w)).unwrap();
        }
        let (lightest, _) = proof(0);
        let (heavy, ev) = proof(10_000);
        g.insert_evidence(heavy, ev, 1_000_000).unwrap();
        assert_eq!(g.evidence.len(), EVIDENCE_CAP);
        assert!(g.evidence.contains_key(&heavy) && !g.evidence.contains_key(&lightest));
        let (light, ev) = proof(10_001);
        assert!(g.insert_evidence(light, ev, 1).is_err(), "lighter than every proof held");
        assert_eq!(g.evidence.len(), EVIDENCE_CAP);
    }

    /// A full attestation pool evicts the entry closest to expiry (lowest
    /// target) for a newer target instead of refusing it; per key, the two
    /// newest targets are kept.
    #[test]
    fn a_full_attestation_pool_evicts_the_oldest_target() {
        let mut g = PoolInner::default();
        for w in 0..POOL_CAP as u64 {
            let a = link(w, 0, 100 + w % 7);
            g.insert_attestation(a.id(), PendingAttestation { key: a.key_id(), att: a, weight: 5 }).unwrap();
        }
        let newer = link(1_000_000, 0, 200);
        let (id, key) = (newer.id(), newer.key_id());
        g.insert_attestation(id, PendingAttestation { att: newer, key, weight: 5 }).expect("evicts an old target");
        assert_eq!(g.attestations.len(), POOL_CAP);
        assert_eq!(g.attestations.values().filter(|x| x.att.target.height == 100).count(),
                   (POOL_CAP as u64).div_ceil(7) as usize - 1, "one entry at the lowest target went");
        let older = link(1_000_001, 0, 99);
        let (id, key) = (older.id(), older.key_id());
        assert!(g.insert_attestation(id, PendingAttestation { att: older, key, weight: 5 }).is_err());

        let mut g = PoolInner::default();
        for t in [50, 60, 55, 40] {
            let a = link(7, t, t);
            let _ = g.insert_attestation(a.id(), PendingAttestation { key: a.key_id(), att: a, weight: 1 });
        }
        let mut kept: Vec<u64> = g.attestations.values().map(|x| x.att.target.height).collect();
        kept.sort();
        assert_eq!(kept, vec![55, 60]);
    }

    /// Templates take a target's votes heaviest first (then id): from the
    /// second hardening activation every share key may vote and a block holds
    /// 32 votes, so the 32 that carry the most weight toward two thirds go
    /// first; older targets still go before newer ones.
    #[test]
    fn snapshot_orders_votes_by_target_then_weight() {
        let pool = PowitPool::new();
        {
            let mut g = pool.inner.lock();
            for (w, t, weight) in [(1u64, 20u64, 5u128), (2, 20, 50), (3, 15, 1), (4, 20, 7)] {
                let a = link(w, 0, t);
                g.insert_attestation(a.id(), PendingAttestation { key: a.key_id(), att: a, weight }).unwrap();
            }
        }
        let (_, atts, _) = pool.snapshot();
        let order: Vec<(u64, u8)> = atts.iter().map(|a| (a.target.height, a.witness.root[0])).collect();
        assert_eq!(order, vec![(15, 3), (20, 2), (20, 4), (20, 1)]);
    }

    /// Seen links: at most `SEEN_LINKS_PER_KEY` per witness and
    /// `SEEN_LINKS_CAP` in total, the oldest evicted first; never wiped.
    #[test]
    fn seen_links_evict_the_oldest_per_key_and_in_total() {
        let mut s = SeenLinks::default();
        let first = link(1, 0, 10);
        let k1 = first.key_id();
        for n in 0..=SEEN_LINKS_PER_KEY as u64 {
            s.record(k1, &link(1, n, 10 + n));
        }
        assert_eq!(s.of(&k1).count(), SEEN_LINKS_PER_KEY);
        assert!(!s.of(&k1).any(|a| *a == first), "its oldest link went");
        s.record(k1, &link(1, 5, 15));
        assert_eq!(s.len(), SEEN_LINKS_PER_KEY, "a duplicate is not recorded twice");

        let mut w = 2;
        while s.len() < SEEN_LINKS_CAP {
            let a = link(w, 0, 10);
            s.record(a.key_id(), &a);
            w += 1;
        }
        let a = link(w, 0, 10);
        s.record(a.key_id(), &a);
        assert_eq!(s.len(), SEEN_LINKS_CAP);
        assert_eq!(s.of(&k1).count(), SEEN_LINKS_PER_KEY - 1, "the globally oldest link went");
        assert_eq!(s.of(&a.key_id()).count(), 1, "the newest is kept");
        assert_eq!(s.by_key.values().map(|v| v.len()).sum::<usize>(), SEEN_LINKS_CAP);
    }

    /// A vote by a fresh KES key (depth 2) for `target`, signed under `h2`.
    fn vote_by(seed: u8, source: Checkpoint, target: Checkpoint, act: u64, h2: u64) -> (KeyId, Attestation) {
        let p = powit::params();
        let mut signer = gnb_crypto::core::kes::KesSigner::generate(2, [seed; 32], |_| {}).unwrap();
        let e = p.epoch(act, target.height);
        if e > signer.epoch() {
            signer.evolve_to(e).unwrap();
        }
        let a = Attestation::sign_at(core::node_chain_id(), h2, source, target, &signer).unwrap();
        (a.key_id(), a)
    }

    fn claim_block(height: u64, vote: Attestation) -> Block {
        Block {
            header: core::BlockHeader { version: 1, parents: vec![[9; 32]], merkle_root: core::MerkleRoot::ZERO,
                                        timestamp: 0, bits: 0x2100ffff, nonce: 0 },
            transactions: Vec::new(),
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: PowitBody { shares: Vec::new(), attestations: vec![vote], evidence: Vec::new(), exits: Vec::new(),
                               poci_evidence: Vec::new(), rejoins: Vec::new() },
        }
    }

    /// Review round 3, LOW 2: a claim is authenticated under the rules of
    /// the node's next block at least (the orphan's wire height is the
    /// sender's choice), and a key barred NOW is no witness, whatever epoch
    /// its vote's target names.
    #[test]
    fn a_claim_is_judged_by_the_bars_of_now() {
        let p = powit::params();
        let act = 1_000u64;
        let e = p.epoch_len;
        let target = Checkpoint { height: act + 3 * e, hash: [3; 32] };
        let source = Checkpoint { height: act + 3 * e - p.checkpoint_interval, hash: [2; 32] };
        let next = act + 2 * e + 1;
        {
            // A key barred until epoch 3 votes for a target in epoch 3.
            let _g = activation::scoped_override_v2(activation::NEVER);
            let (k, vote) = vote_by(41, source, target, act, activation::NEVER);
            let mut st = PowitState::genesis(act, [1; 32]);
            st.epoch = 2;
            for ep in 0..=1 {
                st.epoch_work.entry(ep).or_default().insert(k, 1_000);
            }
            st.banned.insert(k, 3);
            let r = authenticated_finality_claim(&claim_block(target.height, vote.clone()), act, &st, next, 2);
            assert_eq!(r, None, "barred at the node's epoch");
            st.banned.clear();
            let r = authenticated_finality_claim(&claim_block(target.height, vote), act, &st, next, 2);
            assert_eq!(r, Some((target.hash, target.height)), "the same vote once the bar is lifted");
        }
    }

    /// Review round 4, item 6: the lighter side of a partition can be a few
    /// epochs ahead of the node by height (each side's heights advance at
    /// its own pace): a member's votes for targets up to three epochs ahead
    /// are judged, beyond that they are ignored (with the margin at four the
    /// last case authenticates: it is the margin that drops it).
    #[test]
    fn a_claim_may_target_up_to_three_epochs_ahead() {
        let p = powit::params();
        let act = 1_000u64;
        let e = p.epoch_len;
        let _g = activation::scoped_override_v2(activation::NEVER);
        let next = act + 1;
        let vote = |seed: u8, ahead: u64| {
            let target = Checkpoint { height: act + ahead * e, hash: [3; 32] };
            let source = Checkpoint { height: target.height - p.checkpoint_interval, hash: [2; 32] };
            let mut signer = gnb_crypto::core::kes::KesSigner::generate(3, [seed; 32], |_| {}).unwrap();
            signer.evolve_to(ahead).unwrap();
            let a = Attestation::sign_at(core::node_chain_id(), activation::NEVER, source, target, &signer).unwrap();
            (a.key_id(), a)
        };
        for (ahead, judged) in [(2u64, true), (3, true), (4, false)] {
            let (k, v) = vote(50 + ahead as u8, ahead);
            let mut st = PowitState::genesis(act, [1; 32]);
            st.epoch_work.entry(0).or_default().insert(k, 1_000);
            let r = authenticated_finality_claim(&claim_block(act + ahead * e, v), act, &st, next, 2);
            assert_eq!(r.is_some(), judged, "{ahead} epochs ahead");
        }
    }

    /// Review round 3, LOW 2 (the regime half).
    #[test]
    fn a_claim_is_judged_by_the_rules_of_the_nodes_next_block() {
        let p = powit::params();
        let act = 1_000u64;
        let e = p.epoch_len;
        let target = Checkpoint { height: act + 3 * e, hash: [3; 32] };
        let source = Checkpoint { height: act + 3 * e - p.checkpoint_interval, hash: [2; 32] };
        let next = act + 2 * e + 1;
        {
            // From the second hardening activation (at epoch 2) the frozen
            // finalized window holds only epoch 0: K2 (work in epoch 1 only)
            // is no witness there, but would be under the first rule, which an
            // orphan claiming a wire height below the activation selected.
            let h2 = act + 2 * e;
            let _g = activation::scoped_override_v2(h2);
            let (k2, vote) = vote_by(42, source, target, act, activation::NEVER);
            let mut st = PowitState::genesis(act, [1; 32]);
            st.epoch = 2;
            st.finalized = Checkpoint { height: act + e, hash: [1; 32] };
            st.justified = st.finalized;
            st.epoch_work.entry(0).or_default().insert([0xAA; 20], 1_000);
            st.epoch_work.entry(1).or_default().insert(k2, 1_000);
            let r = authenticated_finality_claim(&claim_block(act + 100, vote), act, &st, next, 2);
            assert_eq!(r, None, "judged by the rules of the node's next block ({next})");
        }
    }

    /// Review MEDIUM 6: `--finalitycheckpoint HASH:HEIGHT` (or `none`).
    #[test]
    fn the_finality_checkpoint_flag_parses_hash_and_height() {
        let h = hex::encode([0xAB; 32]);
        assert_eq!(parse_finality_checkpoint(&format!("{h}:20")),
            Ok(Some(ReleaseCheckpoint { height: 20, hash: [0xAB; 32] })));
        assert_eq!(parse_finality_checkpoint(&format!(" 0x{h}:7 ")),
            Ok(Some(ReleaseCheckpoint { height: 7, hash: [0xAB; 32] })));
        assert_eq!(parse_finality_checkpoint("NONE"), Ok(None));
        for bad in [h.clone(), format!("{h}:"), format!("{h}:-1"), format!("{}:5", &h[..62]), "zz:5".into(), String::new()] {
            assert!(parse_finality_checkpoint(&bad).is_err(), "{bad:?}");
        }
    }

    /// The links that make an equivocation: a double vote or a surround vote
    /// by one witness; not two different witnesses, not one link twice.
    #[test]
    fn links_conflict_matches_the_equivocation_shapes() {
        let a = link(1, 0, 20);
        assert!(links_conflict(&a, &link(1, 1, 20)), "double vote");
        assert!(!links_conflict(&a, &a.clone()));
        assert!(!links_conflict(&a, &link(2, 1, 20)), "another witness");
        assert!(!links_conflict(&a, &link(1, 1, 25)), "same source, another height");
        let mut inner = link(1, 2, 15);
        inner.source.height = 5;
        assert!(links_conflict(&a, &inner) && links_conflict(&inner, &a), "surround vote");
    }
}
