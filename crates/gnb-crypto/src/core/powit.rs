//! PoWit — Proof of Witnesses: witness-set finality on top of proof of work.
//!
//! Consensus from `core::powit_height()` (see `docs/DESIGN-pow-powit.md`).
//! Pure, deterministic logic: everything here is a function of a block and
//! the state of its selected parent, so every node derives the same result.
//!
//! - **Witness shares** (`core::witness_share`) carry custody work. The work of
//!   the shares a key earned over a window of epochs is its weight.
//! - **Witness set** `W(e)`: the `max_witnesses` heaviest keys over epochs
//!   `e-1-window ..= e-2` (lagged two epochs, so forks shallower than an
//!   epoch agree on it). Banned keys are excluded; inactive keys decay.
//!   From the second hardening upgrade (`activation::hardening2_*`, PoWit
//!   audit finding 3) the window counts finalized history only: it ends at
//!   the last epoch entirely below the finalized checkpoint
//!   ([`PowitState::finalized_window_epoch`]), so every chain that shares a
//!   finalized checkpoint derives the same witness set until it finalizes
//!   another one, and a fork cannot build its own.
//! - **Attestations**: a member signs a link `source -> target` between two
//!   checkpoints with its forward-secure KES key (`core::kes`, hybrid
//!   ML-DSA-65 ‖ Falcon-1024 leaves), using the leaf of the target's epoch. Included in
//!   blocks; counted only when `source` is the chain's current justified
//!   checkpoint and `target` is on the including block's selected chain.
//! - **Justification / finality** (Casper-style): links worth >= 2/3 of
//!   `W(epoch(target))` justify `target`; a justified target whose height is
//!   exactly one checkpoint interval above its source finalizes the source.
//! - **Accountable safety**: two attestations by one key with the same
//!   target height and different targets (double vote), or one surrounding
//!   the other (surround vote), are an `Equivocation`; any block may carry it
//!   and the key is barred from the witness set and from shares.
//! - **Inactivity decay**: when nothing has finalized for `leak_after_epochs`,
//!   members whose attestations were not included in the previous epoch lose
//!   1/16 of their weight per epoch until finality resumes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::activation;
use super::witness_share::WitnessShare;
use super::kes::{self, KesPublic, KesSignature, KesSigner};
use super::{read_varint, write_varint, ChainId};

/// 20-byte key id: SHA3-256(public key)[0..20], the same hash a
/// pay-to-pubkey-hash `script_pubkey` holds.
pub type KeyId = [u8; 20];

pub fn key_id(public_key: &[u8]) -> KeyId {
    let h = Sha3_256::digest(public_key);
    let mut id = [0u8; 20];
    id.copy_from_slice(&h[..20]);
    id
}

// ── Parameters ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowitParams {
    /// Blocks per epoch.
    pub epoch_len: u64,
    /// Checkpoints every this many heights (counted from activation).
    pub checkpoint_interval: u64,
    /// Epochs of share work that form the witness weight.
    pub window_epochs: u64,
    /// Size cap of the witness set.
    pub max_witnesses: usize,
    /// Attestations one block may carry.
    pub max_attestations_per_block: usize,
    /// Equivocation proofs one block may carry.
    pub max_evidence_per_block: usize,
    /// An attestation may be included until this many heights after its target.
    pub vote_ttl: u64,
    /// Epochs without finality before inactivity decay starts.
    pub leak_after_epochs: u64,
    /// Epochs an equivocating key stays barred.
    pub ban_epochs: u64,
}

/// Mainnet: 6 h epochs (720 blocks at 30 s), checkpoints every 30 min, a
/// 7-day window, 64 witnesses.
pub const MAINNET_PARAMS: PowitParams = PowitParams {
    epoch_len: 720,
    checkpoint_interval: 60,
    window_epochs: 28,
    max_witnesses: 64,
    max_attestations_per_block: 32,
    max_evidence_per_block: 4,
    vote_ttl: 720,
    leak_after_epochs: 4,
    ban_epochs: 28,
};

/// Testnet: the same rules on a short clock, so a test network reaches
/// finality within an hour.
pub const TESTNET_PARAMS: PowitParams = PowitParams {
    epoch_len: 20,
    checkpoint_interval: 5,
    window_epochs: 3,
    max_witnesses: 64,
    max_attestations_per_block: 32,
    max_evidence_per_block: 4,
    vote_ttl: 20,
    leak_after_epochs: 4,
    ban_epochs: 3,
};

pub fn params_for(chain: ChainId) -> PowitParams {
    match chain {
        ChainId::Mainnet => MAINNET_PARAMS,
        ChainId::Testnet => TESTNET_PARAMS,
    }
}

pub fn params() -> PowitParams {
    params_for(super::node_chain_id())
}

impl PowitParams {
    /// Epoch of `height` (activation height `act`, `height >= act`).
    pub fn epoch(&self, act: u64, height: u64) -> u64 {
        (height - act) / self.epoch_len
    }

    pub fn is_checkpoint(&self, act: u64, height: u64) -> bool {
        height >= act && (height - act) % self.checkpoint_interval == 0
    }
}

// ── Checkpoints, attestations, equivocations ─────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: [u8; 32],
}

const DS_ATTEST: &[u8] = b"GNB-POWIT-v1/attest";
const DS_BODY: &[u8] = b"GNB-POWIT-v1/body";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub source: Checkpoint,
    pub target: Checkpoint,
    /// The witness's forward-secure key (`core::kes`); its id is the witness.
    pub witness: KesPublic,
    /// Signature by the leaf of `epoch(target.height)`.
    pub sig: KesSignature,
}

/// The digest a witness signs for a link.
pub fn attestation_message(chain: ChainId, source: &Checkpoint, target: &Checkpoint) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update((DS_ATTEST.len() as u32).to_le_bytes());
    h.update(DS_ATTEST);
    h.update(chain.to_le_bytes());
    h.update(source.height.to_le_bytes());
    h.update(source.hash);
    h.update(target.height.to_le_bytes());
    h.update(target.hash);
    h.finalize().into()
}

impl Attestation {
    pub fn key_id(&self) -> KeyId {
        self.witness.witness_id()
    }

    /// Unique id (gossip and in-block dedup).
    pub fn id(&self) -> [u8; 32] {
        Sha3_256::digest(self.to_wire_bytes()).into()
    }

    /// The KES epoch this attestation must be signed in: the PoWit epoch of
    /// its target. `None` for a target below activation (never valid).
    pub fn kes_epoch(&self, p: &PowitParams, act: u64) -> Option<u64> {
        (self.target.height >= act).then(|| p.epoch(act, self.target.height))
    }

    /// Link shape + forward-secure signature by the target epoch's leaf.
    pub fn verify_signature(&self, chain: ChainId, p: &PowitParams, act: u64) -> bool {
        let Some(e) = self.kes_epoch(p, act) else { return false };
        self.target.height > self.source.height
            && kes::verify(&self.witness, e, &attestation_message(chain, &self.source, &self.target), &self.sig)
    }

    /// Sign a link with a KES signer already evolved to the target's epoch.
    pub fn sign(chain: ChainId, source: Checkpoint, target: Checkpoint, signer: &KesSigner) -> Result<Self, String> {
        let sig = signer.sign(&attestation_message(chain, &source, &target))?;
        Ok(Attestation { source, target, witness: signer.public(), sig })
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9_000);
        out.extend_from_slice(&self.source.height.to_le_bytes());
        out.extend_from_slice(&self.source.hash);
        out.extend_from_slice(&self.target.height.to_le_bytes());
        out.extend_from_slice(&self.target.hash);
        out.push(self.witness.depth);
        out.extend_from_slice(&self.witness.root);
        self.sig.write_wire(&mut out);
        out
    }

    pub fn read_wire(cur: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        let source = read_checkpoint(cur)?;
        let target = read_checkpoint(cur)?;
        let depth = read_fixed::<1>(cur)?[0];
        let root = read_array32(cur)?;
        let sig = KesSignature::read_wire(cur)?;
        Ok(Attestation { source, target, witness: KesPublic { depth, root }, sig })
    }
}

/// Proof that one witness signed two conflicting links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivocation {
    pub a: Attestation,
    pub b: Attestation,
}

impl Equivocation {
    /// Both signatures valid under the same witness key, and a double or
    /// surround vote.
    pub fn verify(&self, chain: ChainId, p: &PowitParams, act: u64) -> Result<KeyId, &'static str> {
        if self.a.witness != self.b.witness {
            return Err("equivocation: different witnesses");
        }
        if self.a == self.b {
            return Err("equivocation: identical attestations");
        }
        if !self.a.verify_signature(chain, p, act) || !self.b.verify_signature(chain, p, act) {
            return Err("equivocation: invalid signature");
        }
        let (a, b) = (&self.a, &self.b);
        let double = a.target.height == b.target.height && a.target != b.target;
        let surround = (a.source.height < b.source.height && b.target.height < a.target.height)
            || (b.source.height < a.source.height && a.target.height < b.target.height);
        if !(double || surround) {
            return Err("equivocation: links do not conflict");
        }
        Ok(self.a.key_id())
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = self.a.to_wire_bytes();
        out.extend_from_slice(&self.b.to_wire_bytes());
        out
    }

    pub fn read_wire(cur: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        Ok(Equivocation { a: Attestation::read_wire(cur)?, b: Attestation::read_wire(cur)? })
    }
}

// ── The PoWit section of a block ─────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowitBody {
    pub shares: Vec<WitnessShare>,
    pub attestations: Vec<Attestation>,
    pub evidence: Vec<Equivocation>,
}

impl PowitBody {
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty() && self.attestations.is_empty() && self.evidence.is_empty()
    }

    /// Wire: varint n ‖ shares, varint n ‖ attestations, varint n ‖ evidence.
    pub fn write_wire(&self, out: &mut Vec<u8>) {
        write_varint(out, self.shares.len() as u64);
        for s in &self.shares {
            out.extend_from_slice(&s.to_wire_bytes());
        }
        write_varint(out, self.attestations.len() as u64);
        for a in &self.attestations {
            out.extend_from_slice(&a.to_wire_bytes());
        }
        write_varint(out, self.evidence.len() as u64);
        for e in &self.evidence {
            out.extend_from_slice(&e.to_wire_bytes());
        }
    }

    pub fn read_wire(cur: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        let n = read_count(cur, super::witness_share::MAX_SHARES_PER_BLOCK, "shares")?;
        let mut shares = Vec::with_capacity(n);
        for _ in 0..n {
            shares.push(WitnessShare::read_wire(cur)?);
        }
        let n = read_count(cur, MAINNET_PARAMS.max_attestations_per_block, "attestations")?;
        let mut attestations = Vec::with_capacity(n);
        for _ in 0..n {
            attestations.push(Attestation::read_wire(cur)?);
        }
        let n = read_count(cur, MAINNET_PARAMS.max_evidence_per_block, "evidence")?;
        let mut evidence = Vec::with_capacity(n);
        for _ in 0..n {
            evidence.push(Equivocation::read_wire(cur)?);
        }
        Ok(PowitBody { shares, attestations, evidence })
    }

    /// Commitment folded into the block's body Merkle root.
    pub fn root(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        self.write_wire(&mut buf);
        let mut h = Sha3_256::new();
        h.update(DS_BODY);
        h.update(&buf);
        h.finalize().into()
    }
}

fn read_checkpoint(cur: &mut std::io::Cursor<&[u8]>) -> Result<Checkpoint, String> {
    let height = read_u64(cur)?;
    let hash = read_array32(cur)?;
    Ok(Checkpoint { height, hash })
}

fn read_count(cur: &mut std::io::Cursor<&[u8]>, max: usize, what: &str) -> Result<usize, String> {
    let n = read_varint(cur)?;
    if n > max as u64 {
        return Err(format!("{what}: {n} items (max {max})"));
    }
    Ok(n as usize)
}

pub(crate) fn read_bytes(cur: &mut std::io::Cursor<&[u8]>, max: usize, what: &str) -> Result<Vec<u8>, String> {
    let n = read_varint(cur)?;
    if n > max as u64 {
        return Err(format!("{what}: {n} bytes (max {max})"));
    }
    let pos = cur.position() as usize;
    let buf = *cur.get_ref();
    let end = pos.checked_add(n as usize).filter(|&e| e <= buf.len())
        .ok_or_else(|| format!("{what}: truncated"))?;
    cur.set_position(end as u64);
    Ok(buf[pos..end].to_vec())
}

pub(crate) fn read_u64(cur: &mut std::io::Cursor<&[u8]>) -> Result<u64, String> {
    let b = read_fixed::<8>(cur)?;
    Ok(u64::from_le_bytes(b))
}

pub(crate) fn read_u32(cur: &mut std::io::Cursor<&[u8]>) -> Result<u32, String> {
    let b = read_fixed::<4>(cur)?;
    Ok(u32::from_le_bytes(b))
}

pub(crate) fn read_array32(cur: &mut std::io::Cursor<&[u8]>) -> Result<[u8; 32], String> {
    read_fixed::<32>(cur)
}

pub(crate) fn read_fixed<const N: usize>(cur: &mut std::io::Cursor<&[u8]>) -> Result<[u8; N], String> {
    let pos = cur.position() as usize;
    let buf = *cur.get_ref();
    if pos + N > buf.len() {
        return Err("truncated".into());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[pos..pos + N]);
    cur.set_position((pos + N) as u64);
    Ok(out)
}

// ── State machine ────────────────────────────────────────────────────────────

/// What a block contributes, after the node has checked everything that
/// needs storage (share proofs, attested blocks, share uniqueness).
pub struct BlockInput<'a> {
    pub height: u64,
    pub hash: [u8; 32],
    /// (payout key, work) of every share in the block, already verified.
    pub share_work: &'a [(KeyId, u128)],
    pub attestations: &'a [Attestation],
    pub evidence: &'a [Equivocation],
}

/// The including block's selected chain, for target checks.
///
/// Checkpoint slot `c` names the highest block on the selected chain whose
/// height is strictly below `c`. Heights along a selected chain can skip
/// (a selected parent need not be the tallest parent), so a slot always has
/// a block, and the same slot names the same block on every node that shares
/// that part of the chain.
pub trait ChainView {
    /// The block slot `c` names, on the including block's selected chain
    /// (which excludes the including block itself), or `None` if unknown.
    fn selected_at(&self, slot: u64) -> Option<[u8; 32]>;
}

/// PoWit state after a block. Stored per block; deterministic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowitState {
    pub activation: u64,
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
    /// Height at which `finalized` last advanced.
    pub finalized_at: u64,
    /// Share work per epoch per key, for the last `window_epochs + 2` epochs.
    pub epoch_work: BTreeMap<u64, BTreeMap<KeyId, u128>>,
    /// Votes for targets linked from `justified`: target -> key -> weight.
    pub votes: BTreeMap<Checkpoint, BTreeMap<KeyId, u128>>,
    /// Every link a key has had included, (source height, target height,
    /// target hash), kept for `ban`-relevant history (bounded by the window).
    pub links: BTreeMap<KeyId, Vec<(u64, u64, [u8; 32])>>,
    /// Keys barred until (exclusive) this epoch.
    pub banned: BTreeMap<KeyId, u64>,
    /// Inactivity decay steps per key (each = 15/16 of weight).
    pub decay: BTreeMap<KeyId, u32>,
    /// Keys whose attestations were included in the current epoch.
    pub active_this_epoch: BTreeSet<KeyId>,
    pub epoch: u64,
}

impl PowitState {
    /// Base state for the first block at or above activation on a chain:
    /// the checkpoint at slot `activation` (the last selected-chain block
    /// below activation) is justified and final by definition. The first
    /// activated block is then applied on top of it like any other.
    pub fn genesis(activation: u64, activation_hash: [u8; 32]) -> Self {
        let cp = Checkpoint { height: activation, hash: activation_hash };
        PowitState {
            activation,
            justified: cp,
            finalized: cp,
            finalized_at: activation,
            epoch_work: BTreeMap::new(),
            votes: BTreeMap::new(),
            links: BTreeMap::new(),
            banned: BTreeMap::new(),
            decay: BTreeMap::new(),
            active_this_epoch: BTreeSet::new(),
            epoch: 0,
        }
    }

    pub fn is_banned(&self, key: &KeyId, epoch: u64) -> bool {
        self.banned.get(key).is_some_and(|&until| epoch < until)
    }

    /// Witness set for `epoch`: (key, weight), heaviest first, at most
    /// `max_witnesses`, banned keys excluded, decay applied.
    pub fn witness_set(&self, p: &PowitParams, epoch: u64) -> Vec<(KeyId, u128)> {
        if epoch < 2 {
            return Vec::new();
        }
        let hi = epoch - 2;
        let lo = (epoch - 1).saturating_sub(p.window_epochs);
        let mut total: BTreeMap<KeyId, u128> = BTreeMap::new();
        for (_, m) in self.epoch_work.range(lo..=hi) {
            for (k, w) in m {
                let e = total.entry(*k).or_insert(0);
                *e = e.saturating_add(*w);
            }
        }
        let mut v: Vec<(KeyId, u128)> = total
            .into_iter()
            .filter(|(k, _)| !self.is_banned(k, epoch))
            .map(|(k, w)| (k, decayed(w, self.decay.get(&k).copied().unwrap_or(0))))
            .filter(|(_, w)| *w > 0)
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(p.max_witnesses);
        v
    }

    /// Epochs entirely below the finalized checkpoint's slot: every block of
    /// epochs `0..n` on this chain is the finalized block or one of its
    /// selected-chain ancestors (a slot names the highest selected-chain
    /// block strictly below it), i.e. part of LOG_fin.
    pub fn finalized_epochs(&self, p: &PowitParams) -> u64 {
        self.finalized.height.saturating_sub(self.activation) / p.epoch_len
    }

    /// Second hardening upgrade (PoWit audit finding 3;
    /// docs/DESIGN-pow-powit.md §7.4, "W_e is computed only from LOG_fin"):
    /// the epoch whose window [`witness_set`](Self::witness_set) reads for a
    /// target in `epoch`.
    ///
    /// With `nf` = [`finalized_epochs`](Self::finalized_epochs):
    ///
    /// - `nf == 0`, nothing beyond the activation checkpoint is final: the
    ///   chain bootstraps from its own shares, `epoch` (the first rule). The
    ///   first finalization always lies in epoch 2 or later (the witness set
    ///   is empty before), so `nf` jumps from 0 to at least 2.
    /// - otherwise `min(epoch, nf + 1)`: the window ends at
    ///   `min(epoch - 2, nf - 1)`, the last epoch entirely in LOG_fin. While
    ///   finality keeps up (the finalized slot lies in `epoch - 1` or later)
    ///   that is `epoch` itself, the first rule's set; when finality lags,
    ///   the set freezes at the last finalized window (the spec's
    ///   "W_e = W_{e-1}") until a new checkpoint is finalized.
    ///
    /// Two chains whose states finalized the same checkpoint (same slot and
    /// block) therefore read the same share history, below that block, for
    /// every target until one of them finalizes another checkpoint.
    pub fn finalized_window_epoch(&self, p: &PowitParams, epoch: u64) -> u64 {
        match self.finalized_epochs(p) {
            0 => epoch,
            nf => epoch.min(nf + 1),
        }
    }

    /// The witness set a block uses for a target in `epoch`: under the
    /// first rule (`from_finalized == false`) `witness_set(epoch)`; from the
    /// second hardening upgrade `witness_set(finalized_window_epoch(epoch))`.
    /// A frozen window with no share work left in it (possible only across
    /// the upgrade, for a chain whose finality had stalled long enough for
    /// the first rule to prune that window, or one whose shares all fell in
    /// the epoch the frozen window drops) gives way to `epoch`'s own window,
    /// so finality can always start again; a frozen window is never empty
    /// on a chain that finalized with its members (bans aside).
    pub fn witness_set_at(&self, p: &PowitParams, epoch: u64, from_finalized: bool) -> Vec<(KeyId, u128)> {
        let anchored = if from_finalized { self.finalized_window_epoch(p, epoch) } else { epoch };
        if anchored == epoch {
            return self.witness_set(p, epoch);
        }
        let w = self.witness_set(p, anchored);
        if w.is_empty() { self.witness_set(p, epoch) } else { w }
    }

    /// [`witness_set_at`](Self::witness_set_at) for a block at header height
    /// `block_height` under the process-wide second hardening height
    /// (`activation::hardening2_activation_height`): what every producer
    /// (pool admission, the witness duty, templates through `apply`, RPC)
    /// reads for the block it builds or admits for.
    pub fn witness_set_for_block(&self, p: &PowitParams, epoch: u64, block_height: u64) -> Vec<(KeyId, u128)> {
        self.witness_set_at(p, epoch, activation::hardening2_active_at(block_height))
    }

    /// The epochs of the frozen window from the second hardening upgrade
    /// (`(nf - window) ..= nf - 1`), which must outlive the first rule's
    /// pruning while finality lags; `None` while nothing is final.
    fn finalized_window(&self, p: &PowitParams) -> Option<(u64, u64)> {
        match self.finalized_epochs(p) {
            0 => None,
            nf => Some((nf.saturating_sub(p.window_epochs), nf - 1)),
        }
    }

    /// Apply one block (height > activation) on top of its selected parent's
    /// state. Any rule violation makes the block invalid. The second
    /// hardening upgrade applies from the process-wide height
    /// (`activation::hardening2_activation_height`); see [`Self::apply_at`].
    pub fn apply(&self, p: &PowitParams, chain: ChainId, b: &BlockInput<'_>, view: &dyn ChainView)
        -> Result<PowitState, String>
    {
        self.apply_at(p, chain, b, view, activation::hardening2_activation_height())
    }

    /// [`apply`](Self::apply) with the second hardening activation height
    /// `h2` explicit. From `h2` (compared with the block's header height
    /// `b.height`, as the upgrade's block rules) every witness set the block
    /// reads (attester weights, justification totals, inactivity-decay
    /// membership) comes from finalized history
    /// ([`witness_set_at`](Self::witness_set_at)), and the epochs of the
    /// frozen window are kept. Below `h2` this is the first rule, bit for
    /// bit.
    pub fn apply_at(&self, p: &PowitParams, chain: ChainId, b: &BlockInput<'_>, view: &dyn ChainView, h2: u64)
        -> Result<PowitState, String>
    {
        let from_finalized = activation::is_active_at(b.height, h2);
        let act = self.activation;
        if b.height < act {
            return Err("powit: block below activation".into());
        }
        if b.attestations.len() > p.max_attestations_per_block {
            return Err("powit: too many attestations".into());
        }
        if b.evidence.len() > p.max_evidence_per_block {
            return Err("powit: too many equivocation proofs".into());
        }
        let mut s = self.clone();
        let epoch = p.epoch(act, b.height);

        // ── Epoch boundary: inactivity decay, then prune old history ──────
        if epoch > s.epoch {
            for e in s.epoch..epoch {
                let stalled = b.height.saturating_sub(s.finalized_at) >= p.leak_after_epochs * p.epoch_len;
                if stalled {
                    let members: Vec<KeyId> =
                        s.witness_set_at(p, e, from_finalized).into_iter().map(|(k, _)| k).collect();
                    for k in members {
                        if !s.active_this_epoch.contains(&k) {
                            *s.decay.entry(k).or_insert(0) += 1;
                        }
                    }
                }
                s.active_this_epoch.clear();
            }
            s.epoch = epoch;
            let keep_from = epoch.saturating_sub(p.window_epochs + 2);
            let mut kept = s.epoch_work.split_off(&keep_from);
            if let Some((lo, hi)) = from_finalized.then(|| s.finalized_window(p)).flatten() {
                // Hardening 2: the frozen window, older than the first
                // rule's horizon while finality lags. Nothing else below it
                // is ever read again: a newly finalized checkpoint lies at
                // most `vote_ttl + checkpoint_interval` (under two epochs)
                // below the block, so its window starts within the horizon.
                kept.extend(std::mem::take(&mut s.epoch_work).into_iter().filter(|(e, _)| (lo..=hi).contains(e)));
            }
            s.epoch_work = kept;
            s.banned.retain(|_, until| *until > epoch);
            let link_floor = b.height.saturating_sub((p.window_epochs + 2) * p.epoch_len);
            for v in s.links.values_mut() {
                v.retain(|(_, th, _)| *th >= link_floor);
            }
            s.links.retain(|_, v| !v.is_empty());
        }

        // ── Equivocation proofs ──────────────────────────────────────────
        for ev in b.evidence {
            let k = ev.verify(chain, p, act).map_err(|e| format!("powit: {e}"))?;
            if s.is_banned(&k, epoch) {
                return Err("powit: equivocation for an already barred key".into());
            }
            s.banned.insert(k, epoch + p.ban_epochs);
            for votes in s.votes.values_mut() {
                votes.remove(&k);
            }
        }

        // ── Shares: custody work for the current epoch ───────────────────
        for (k, w) in b.share_work {
            if s.is_banned(k, epoch) {
                return Err("powit: share paid to a barred key".into());
            }
            let e = s.epoch_work.entry(epoch).or_default().entry(*k).or_insert(0);
            *e = e.saturating_add(*w);
        }

        // ── Attestations ─────────────────────────────────────────────────
        let mut seen_in_block: BTreeSet<(KeyId, Checkpoint)> = BTreeSet::new();
        for a in b.attestations {
            let k = a.key_id();
            let t = a.target;
            if !p.is_checkpoint(act, t.height) || t.height > b.height {
                return Err("powit: target is not a checkpoint slot at or below this block".into());
            }
            if b.height > t.height + p.vote_ttl {
                return Err("powit: attestation expired".into());
            }
            if a.source != s.justified {
                return Err("powit: source is not the justified checkpoint".into());
            }
            if view.selected_at(t.height) != Some(t.hash) {
                return Err("powit: target is not on this block's selected chain".into());
            }
            let te = p.epoch(act, t.height);
            if s.is_banned(&k, epoch) {
                return Err("powit: attestation by a barred key".into());
            }
            let weight = s.witness_set_at(p, te, from_finalized).into_iter().find(|(m, _)| *m == k).map(|(_, w)| w)
                .ok_or("powit: attester is not in the witness set")?;
            if !seen_in_block.insert((k, t)) || s.votes.get(&t).is_some_and(|v| v.contains_key(&k)) {
                return Err("powit: duplicate attestation".into());
            }
            // A key's own on-chain history must stay conflict-free.
            if let Some(hist) = s.links.get(&k) {
                for &(sh, th, thash) in hist {
                    let double = th == t.height && thash != t.hash;
                    let surround = (sh < a.source.height && t.height < th)
                        || (a.source.height < sh && th < t.height);
                    if double || surround {
                        return Err("powit: attestation conflicts with this key's earlier vote".into());
                    }
                }
            }
            if !a.verify_signature(chain, p, act) {
                return Err("powit: invalid attestation signature (KES leaf must be the target's epoch)".into());
            }
            s.votes.entry(t).or_default().insert(k, weight);
            s.links.entry(k).or_default().push((a.source.height, t.height, t.hash));
            s.active_this_epoch.insert(k);
        }

        // ── Justification and finality ───────────────────────────────────
        let mut newly: Option<Checkpoint> = None;
        for (t, votes) in &s.votes {
            let total: u128 =
                s.witness_set_at(p, p.epoch(act, t.height), from_finalized).iter().map(|(_, w)| *w).sum();
            if total == 0 {
                continue;
            }
            let got: u128 = votes.values().sum();
            if got.saturating_mul(3) >= total.saturating_mul(2) && t.height > s.justified.height
                && newly.is_none_or(|n| t.height > n.height)
            {
                newly = Some(*t);
            }
        }
        if let Some(t) = newly {
            if t.height == s.justified.height + p.checkpoint_interval {
                s.finalized = s.justified;
                s.finalized_at = b.height;
                s.decay.clear();
            }
            s.justified = t;
            s.votes.clear();
        }
        // Votes for targets that can no longer be included are dropped.
        s.votes.retain(|t, _| b.height <= t.height + p.vote_ttl);
        Ok(s)
    }
}

fn decayed(w: u128, steps: u32) -> u128 {
    let mut w = w;
    for _ in 0..steps.min(64) {
        w -= w / 16;
    }
    w
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod finalized_history_tests;
