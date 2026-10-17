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
use gnb_crypto::core::powit::{self, Attestation, BlockInput, ChainView, Checkpoint, Equivocation,
                              KeyId, PowitBody, PowitParams, PowitState, Regime};
use gnb_crypto::core::witness_share::{self, WitnessShare, SHARE_WINDOW};
use gnb_crypto::core::{self, activation, Block};

type Hash = [u8; 32];

/// The second hardening activation height the PoWit rules switch at
/// (`core::powit::Regime`; process-wide, the node's chain schedule):
/// consensus (`block_state`), the pool, templates and the witness duty all
/// read this one value, so each judges an item by the rules of the block
/// that may include it.
fn hardening2_height() -> u64 {
    activation::hardening2_activation_height()
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

fn state_key(hash: &Hash) -> String {
    format!("powit/state/{}", hex::encode(hash))
}

pub fn load_state(store: &Storage, hash: &Hash) -> Option<PowitState> {
    let bytes = store.get_meta(&state_key(hash)).ok().flatten()?;
    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).ok().map(|(s, _)| s)
}

fn encode_state(state: &PowitState) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(state, bincode::config::standard())
        .map_err(|e| format!("powit state encode: {e}"))
}

/// Write `hash`'s PoWit state on its own (and its finality row,
/// [`finality_row`]). The acceptance pipeline uses [`stage_state`]
/// (committed with the block's DAG record); this is for tools and tests.
#[allow(dead_code)] // tools and tests; the node binary compiles this module too
pub fn save_state(store: &Storage, hash: &Hash, state: &PowitState) -> Result<(), String> {
    let bytes = encode_state(state)?;
    store.put_meta(&state_key(hash), &bytes).map_err(|e| format!("storage: powit state: {e}"))?;
    if let Some((key, row)) = finality_row(hash, state) {
        store.put_meta(&key, &row).map_err(|e| format!("storage: powit finality row: {e}"))?;
    }
    Ok(())
}

/// [`save_state`] into a caller-owned batch: the acceptance pipeline commits
/// a block's PoWit state in the same batch as its DAG record (the first chunk
/// of the chain move it triggers, or its fork-loser record), so a block is
/// never recorded without its state and a refused block leaves none behind.
/// The block's finality row ([`finality_row`]) goes into the same batch, so
/// the finality index a restart rebuilds holds exactly the recorded blocks.
pub fn stage_state(store: &Storage, batch: &mut rocksdb::WriteBatch, hash: &Hash, state: &PowitState)
    -> Result<(), String>
{
    let bytes = encode_state(state)?;
    store.stage_meta(batch, &state_key(hash), &bytes).map_err(|e| format!("storage: powit state: {e}"))?;
    if let Some((key, row)) = finality_row(hash, state) {
        store.stage_meta(batch, &key, &row).map_err(|e| format!("storage: powit finality row: {e}"))?;
    }
    Ok(())
}

/// State a child of `parent` builds on: the parent's stored state, or the
/// genesis state when the parent is below activation.
fn base_state(dag: &GhostDAG, store: &Storage, parent: Option<Hash>) -> Result<PowitState, String> {
    let act = core::powit_height();
    let Some(p) = parent else { return Err("powit: block without a selected parent".into()) };
    let ph = dag.get_block_data(&p).map(|d| d.height).ok_or("powit: unknown selected parent")?;
    if ph < act {
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
    };
    let view = DagChainView { dag, start: sp };
    base.apply_at(&powit::params(), core::node_chain_id(), hardening2_height(), &input, &view).map(Some)
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
    /// The tip's state (barred keys; witness weights from the activation).
    state: PowitState,
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
        TipWitnesses { tip, tip_h, activation: act, hardening2, justified: st.justified, epoch, state: st, sets }
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
        match self.regime() {
            Regime::V1 => self.sets.values().filter_map(|s| s.get(key)).max().copied(),
            Regime::Hardening2 => PowitState::evidence_epochs(self.epoch)
                .filter_map(|e| self.state.member_weight_h2(p, e, key))
                .max(),
        }
    }

    fn is_banned(&self, key: &KeyId) -> bool {
        self.state.is_banned(key, self.epoch)
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
    weight: u128,
}

/// Links seen per witness (gossip), oldest evicted first, per key and in
/// total; never wiped wholesale (that dropped the honest links double votes
/// are caught against).
#[derive(Default)]
struct SeenLinks {
    by_key: HashMap<KeyId, std::collections::VecDeque<(u64, Attestation)>>,
    /// Arrival sequence -> key, oldest first.
    order: BTreeMap<u64, KeyId>,
    next: u64,
}

impl SeenLinks {
    fn of(&self, key: &KeyId) -> impl Iterator<Item = &Attestation> {
        self.by_key.get(key).into_iter().flat_map(|v| v.iter().map(|(_, a)| a))
    }

    fn record(&mut self, key: KeyId, att: &Attestation) {
        let links = self.by_key.entry(key).or_default();
        if links.iter().any(|(_, a)| a == att) {
            return;
        }
        let seq = self.next;
        self.next += 1;
        links.push_back((seq, att.clone()));
        self.order.insert(seq, key);
        if links.len() > SEEN_LINKS_PER_KEY {
            if let Some((old, _)) = links.pop_front() {
                self.order.remove(&old);
            }
        }
        while self.order.len() > SEEN_LINKS_CAP {
            let Some((old, k)) = self.order.pop_first() else { break };
            if let Some(v) = self.by_key.get_mut(&k) {
                v.retain(|(s, _)| *s != old);
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
    fn insert_evidence(&mut self, key: KeyId, ev: Equivocation, weight: u128) -> Result<(), String> {
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
        self.evidence.insert(key, HeldEvidence { ev, weight });
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
    /// tip's justified checkpoint. Membership and the target are checked
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
        let key = att.key_id();
        let weight = view.weight_for(&p, &t, &key).ok_or("attester is not in the witness set")?;
        if !view.open_target(&p, &t) {
            return Err("attestation target is not an open checkpoint slot".into());
        }
        // The message of the target's height (v2 from the second hardening
        // activation: it commits the witness key).
        if !att.verify_signature_at(chain, &p, act, view.hardening2) {
            return Err("invalid attestation signature".into());
        }
        {
            let mut g = self.inner.lock();
            if g.attestations.contains_key(&id) {
                return Ok(id);
            }
            // Every recorded link passed `verify_signature`: the shape check
            // is the rest of `Equivocation::verify`.
            let conflicting = g.seen_links.of(&key).find(|o| links_conflict(o, &att)).cloned();
            if let Some(o) = conflicting {
                let _ = g.insert_evidence(key, Equivocation { a: o, b: att.clone() }, weight);
            }
            g.seen_links.record(key, &att);
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
        let k = view.verify_evidence(&ev, core::node_chain_id(), &p)?;
        debug_assert_eq!(k, key);
        self.inner.lock().insert_evidence(key, ev, weight)?;
        Ok(key)
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
pub fn template_body(pool: &PowitPool, dag: &GhostDAG, store: &Storage, tip: Hash, height: u64) -> PowitBody {
    if !core::powit_active(height) {
        return PowitBody::default();
    }
    let Ok(base) = base_state(dag, store, Some(tip)) else { return PowitBody::default() };
    let p = powit::params();
    let chain = core::node_chain_id();
    let h2 = hardening2_height();
    let epoch = p.epoch(base.activation, height);
    let recent = selected_chain_since(dag, Some(tip), height.saturating_sub(SHARE_WINDOW));
    let Ok(included) = included_share_ids(store, &recent) else { return PowitBody::default() };
    let (shares, atts, mut evidence) = pool.snapshot();
    if !evidence.is_empty() {
        let tip_h = dag.get_block_data(&tip).map(|d| d.height).unwrap_or(height.saturating_sub(1));
        let w = pool.view_of(&tip).unwrap_or_else(|| Arc::new(TipWitnesses::of_at(tip, tip_h, base.clone(), &p, h2)));
        evidence.sort_by_cached_key(|e| {
            let k = e.a.key_id();
            (std::cmp::Reverse(w.evidence_weight(&p, &k).unwrap_or(0)), k)
        });
    }

    let mut body = PowitBody::default();
    let mut share_work = Vec::new();
    for s in shares {
        if body.shares.len() >= witness_share::MAX_SHARES_PER_BLOCK {
            break;
        }
        if let Ok((k, w)) = check_share(store, &s, height, &recent, &included) {
            if !base.is_banned(&k, epoch) && !body.shares.contains(&s) {
                body.shares.push(s);
                share_work.push((k, w));
            }
        }
    }
    let view = DagChainView { dag, start: Some(tip) };
    let try_apply = |b: &PowitBody, sw: &[(KeyId, u128)]| {
        let input = BlockInput { height, hash: [0; 32], share_work: sw, attestations: &b.attestations,
                                 evidence: &b.evidence };
        base.apply_at(&p, chain, h2, &input, &view).is_ok()
    };
    for ev in evidence {
        if body.evidence.len() >= p.max_evidence_per_block {
            break;
        }
        body.evidence.push(ev);
        if !try_apply(&body, &share_work) {
            body.evidence.pop();
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

/// Write `bytes` to `path` so that it survives a crash or a power loss:
/// a temp file in the same directory, fsync'd, renamed over `path`, then the
/// directory fsync'd (the rename itself is durable only then). Owner-only
/// permissions (the KES key file holds the encrypted seed).
fn write_durable(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let name = path.file_name().ok_or_else(|| format!("{}: not a file path", path.display()))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let io = |what: &str, e: std::io::Error| format!("{what} {}: {e}", tmp.display());
    let mut f = opts.open(&tmp).map_err(|e| io("create", e))?;
    f.write_all(bytes).map_err(|e| io("write", e))?;
    f.sync_all().map_err(|e| io("fsync", e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::File::open(dir).and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync directory {}: {e}", dir.display()))
}

/// Read a JSON file that may be absent (`None`), refusing one that exists but
/// cannot be read or parsed: an unreadable vote record must never read as
/// "no votes" (that re-opens every link the key signed).
fn read_json_if_present<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<Option<T>, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| format!(
            "{what} {} is corrupt ({e}); refusing to sign: restore it from a backup (deleting it can make \
             this key sign a double vote and be barred)", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{what} {} is unreadable ({e}); refusing to sign", path.display())),
    }
}

/// The highest source and target heights a key ever signed (EIP-3076's
/// minimal slashing protection): a link with a lower source or a target not
/// above it is never signed, so no double or surround vote is possible even
/// if the full record is lost. Kept in the record and, so that it moves with
/// the key on a failover onto a fresh data directory, beside the key file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct HighWater {
    source: u64,
    target: u64,
}

impl HighWater {
    fn of(signed: &[(Checkpoint, Checkpoint)]) -> Self {
        signed.iter().fold(HighWater::default(), |h, (s, t)| h.max(&HighWater { source: s.height, target: t.height }))
    }
    fn max(self, o: &HighWater) -> Self {
        HighWater { source: self.source.max(o.source), target: self.target.max(o.target) }
    }
    fn allows(&self, source: &Checkpoint, target: &Checkpoint) -> bool {
        source.height >= self.source && target.height > self.target
    }
}

/// A witness's forward-secure KES key, its payout script and its persistent
/// vote record. The KES state evolves to each target's epoch (erasing every
/// earlier seed, on disk first) before signing, and the record makes a double
/// or surround vote impossible even across restarts and reorgs. Both files
/// are written durably (`write_durable`) before a signature is released; a
/// record that exists but cannot be read refuses to load; the highest
/// signed heights (`HighWater`) are enforced and kept beside the key too.
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
    record_path: PathBuf,
    highwater_path: PathBuf,
    signed: Mutex<(Vec<(Checkpoint, Checkpoint)>, HighWater)>,
}

/// The witness password held in secret memory, as the `&str` the key file
/// API takes. It was read as UTF-8 text and trimmed at character
/// boundaries, so it is always valid UTF-8.
fn password_str(password: &gnb_crypto::crypto::SecretBytes) -> &str {
    std::str::from_utf8(password).expect("the witness password was read as UTF-8")
}

impl WitnessDuty {
    /// Load a KES witness key (`gnb-cli witnesskeygen`); the password is read
    /// from `password_file` (first line), never from the command line.
    /// Refuses a vote record or high-water file that exists but cannot be
    /// read (it would otherwise read as "never signed").
    pub fn load(key: &Path, password_file: &Path, payout_script: Vec<u8>, data_dir: &Path) -> Result<Self, String> {
        // CRY-4: the file's contents are wiped once the first line is copied.
        let pw = zeroize::Zeroizing::new(
            std::fs::read_to_string(password_file).map_err(|e| format!("witness password file: {e}"))?);
        let password = gnb_crypto::crypto::SecretBytes::from_slice(pw.lines().next().unwrap_or("").trim().as_bytes());
        drop(pw);
        let file = gnb_crypto::core::kes::KesKeyFile::load(key)?;
        let signer = file.open(password_str(&password))?;
        let key_id = signer.public().witness_id();
        let record_path = data_dir.join(format!("powit-votes-{}.json", hex::encode(key_id)));
        let mut hw_name = key.file_name().ok_or("witness key path has no file name")?.to_os_string();
        hw_name.push(".votes-highwater.json");
        let highwater_path = key.with_file_name(hw_name);
        let signed: Vec<(Checkpoint, Checkpoint)> =
            read_json_if_present(&record_path, "witness vote record")?.unwrap_or_default();
        let beside_key: HighWater =
            read_json_if_present(&highwater_path, "witness vote high-water file")?.unwrap_or_default();
        let hw = HighWater::of(&signed).max(&beside_key);
        Ok(WitnessDuty {
            key_id,
            payout_script,
            key_path: key.to_path_buf(),
            password,
            signer: Mutex::new(signer),
            record_path,
            highwater_path,
            signed: Mutex::new((signed, hw)),
        })
    }

    fn conflicts(&self, source: &Checkpoint, target: &Checkpoint) -> bool {
        let g = self.signed.lock();
        !g.1.allows(source, target) || g.0.iter().any(|(s, t)| {
            (t.height == target.height && t != target)
                || (s.height < source.height && target.height < t.height)
                || (source.height < s.height && t.height < target.height)
        })
    }

    /// If this key is a witness for the checkpoint to vote for above the
    /// tip's justified one, sign that link once (the message of the target's
    /// height). Returns the new attestation. The checkpoint is the newest slot
    /// at or below the next block's height; from the second hardening
    /// activation, the justified checkpoint's direct child while a vote for
    /// it can still be included.
    pub fn maybe_attest(&self, dag: &GhostDAG, store: &Storage) -> Result<Option<Attestation>, String> {
        let Some((tip, tip_h)) = tip_context(dag) else { return Ok(None) };
        let Some(st) = load_state(store, &tip) else { return Ok(None) };
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
            let member = match regime {
                Regime::V1 => st.witness_set(&p, te).iter().any(|(k, _)| *k == self.key_id),
                Regime::Hardening2 => st.member_weight_h2(&p, te, &self.key_id).is_some(),
            };
            // Not a member for this slot's epoch, no block for it, a conflict
            // with the record, or an epoch whose leaf is gone (forward
            // security): try the next slot, if any.
            if !member {
                continue;
            }
            let Some(hash) = view.selected_at(slot) else { continue };
            let target = Checkpoint { height: slot, hash };
            if self.signed.lock().0.iter().any(|(s, t)| *s == source && *t == target) {
                return Ok(None); // signed: waiting for it to be included
            }
            if self.conflicts(&source, &target) || te < signer.epoch() {
                continue;
            }
            chosen = Some((target, te));
            break;
        }
        let Some((target, te)) = chosen else { return Ok(None) };
        if te > signer.epoch() {
            // Erase every earlier seed, ON DISK FIRST (durably), then in memory.
            let password = password_str(&self.password);
            let mut next_state = gnb_crypto::core::kes::KesKeyFile::load(&self.key_path)?.open(password)?;
            next_state.evolve_to(te)?;
            let sealed = gnb_crypto::core::kes::KesKeyFile::seal(&next_state, password)?;
            let json = serde_json::to_vec_pretty(&sealed).map_err(|e| format!("kes save: {e}"))?;
            write_durable(&self.key_path, &json).map_err(|e| format!("kes save: {e}"))?;
            *signer = next_state;
        }
        // The message of the target's height (v2, committing this key, from
        // the second hardening activation).
        let att = Attestation::sign_at(core::node_chain_id(), h2, source, target, &signer)?;
        {
            let mut g = self.signed.lock();
            g.0.push((source, target));
            g.1 = g.1.max(&HighWater { source: source.height, target: target.height });
            // Persist BEFORE releasing the signature: the record, then the
            // high-water mark beside the key.
            let bytes = serde_json::to_vec(&g.0).map_err(|e| e.to_string())?;
            write_durable(&self.record_path, &bytes).map_err(|e| format!("witness vote record: {e}"))?;
            let hw = serde_json::to_vec(&g.1).map_err(|e| e.to_string())?;
            write_durable(&self.highwater_path, &hw).map_err(|e| format!("witness vote high-water file: {e}"))?;
        }
        Ok(Some(att))
    }
}

// ── Share mining ─────────────────────────────────────────────────────────────

/// Try `attempts` nonces for a share attesting `attested` (normally the
/// current tip), crediting `witness` and paying `payout` (any valid script).
/// GnB-SMH v3, 4 MiB. Takes no lock: the caller reads the tip first.
pub fn mine_share(attested: &Block, attested_hash: Hash, witness: KeyId, payout: &[u8], start_nonce: u64,
                  attempts: u64, stop: &std::sync::atomic::AtomicBool) -> Option<WitnessShare> {
    let stream = witness_share::tx_stream(attested);
    let root = attested.witness_root();
    let target = witness_share::share_target(&gnb_smh::difficulty::bits_to_target(attested.header.bits));
    let mut sp = gnb_smh::v3::Scratchpad::new(gnb_smh::v3::LOG2_N);
    let mut share = WitnessShare { attested: attested_hash, witness, payout: payout.to_vec(),
                                   bits: attested.header.bits, nonce: 0 };
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
pub fn pool_evidence() -> Vec<Equivocation> {
    pool().snapshot().2
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
        "pool": { "shares": ps, "attestations": pa, "evidence": pe },
        // Hardening 2: the witness set comes from finalized history.
        "witness_set_from_finalized_history": core::activation::hardening2_active_at(tip_h + 1),
        // The node's fork-choice pin (`getfinalityinfo` has the details).
        "pin": dag.finalized().map(|(h, height)| serde_json::json!({
            "hash": hex::encode(h), "block_height": height,
            "origin": dag.finality_outcome().origin.as_str() })),
        "finality_conflict": dag.finality_outcome().conflict.is_some(),
    })
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
        ITEM_EVIDENCE => {
            let e = Equivocation::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_evidence(e, dag, store).map(|_| ())
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
    let (outcome, previous, sticky) = {
        let d = dag.read();
        let idx = d.finality_index();
        let policy = PinPolicy {
            min_chain_work,
            anchor: anchor_in_force(idx.anchor_setting),
            ignored: &idx.ignored,
            applied: applied_tip(&d, store),
            sticky: idx.sticky(),
        };
        (d.compute_finality_pin(&policy), d.finality_outcome().clone(), idx.sticky())
    };
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
    if outcome.anchor != previous.anchor && matches!(outcome.anchor,
        crate::consensus::finality::AnchorStatus::Invalid | crate::consensus::finality::AnchorStatus::HeightMismatch)
    {
        log::error!("PoWit finality anchor {:?}: {:?} (a release or operator checkpoint this node finds invalid or \
            at another height; check it, or `setfinalitycheckpoint none`)",
            anchor_in_force(dag.read().finality_index().anchor_setting).map(|a| hex::encode(a.hash)), outcome.anchor);
    }
    dag.write().set_finality_pin(outcome.clone());
    // The pinned checkpoint is the node's own finality from now on: persist
    // it (a lost write falls back to the applied chain's finality).
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
    /// Undo [`FinalityOp::Ignore`] for this block.
    Reconsider(Hash),
    /// Trust this block as final (an operator weak-subjectivity checkpoint):
    /// it replaces the release checkpoint as the anchor.
    SetAnchor(Hash),
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
        FinalityOp::SetAnchor(h) => {
            let height = {
                let d = dag.read();
                let data = d.get_block_data(&h).ok_or_else(|| format!("block {} not found", hex::encode(h)))?;
                if d.is_invalid(&h) {
                    return Err(format!("block {} is disqualified on this node", hex::encode(h)));
                }
                data.height
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
            AnchorSetting::Release => if anchor.is_some() { "release" } else { "none" },
            AnchorSetting::Disabled => "disabled",
            AnchorSetting::Operator(_) => "operator",
        },
        "anchor_status": format!("{:?}", o.anchor).to_lowercase(),
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
