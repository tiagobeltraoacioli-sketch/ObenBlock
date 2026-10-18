//! PoCI, Proof of Corruption or Integrity: ObenBlock's strict finality
//! (`docs/DESIGN-obenblock-poci.md`, package O11).
//!
//! Every finality decision ends in one of two verifiable objects:
//!
//! - **Proof of Integrity**: a finality certificate ([`Certificate`]): votes
//!   worth strictly more than two thirds of one frozen, authenticated
//!   configuration ([`Configuration`]) link a justified source to its direct
//!   child.
//! - **Proof of Corruption**: two votes by one key under one configuration
//!   that the rules forbid (double or surround vote, [`check_evidence`]). The
//!   key is excluded for [`POCI_BAN_EPOCHS`] epochs ([`PociState`]).
//!
//! The byte-level definitions are those of `reference/poci_reference.py`,
//! which is normative: `crates/gnb-crypto/tests/poci_vectors.rs` reproduces
//! every case of `reference/poci_vectors.json`.
//!
//! ```text
//! params_digest = SHA-256d("OBB-POCI-v1/params" ‖ u32le(chain_id) ‖ u64le × 11 ‖ u32le(2) ‖ u32le(3))
//! leaf(k, w)    = tagged("OBB-POCI-v1/leaf", key_id[20] ‖ u128le(w))
//! node(l, r)    = tagged("OBB-POCI-v1/node", l ‖ r)        odd last node carried up
//! merkle_root   = tagged("OBB-POCI-v1/root", u32le(n) ‖ tree_root)
//! config_id     = SHA-256d("OBB-POCI-v1/config" ‖ u32le(chain_id) ‖ u64le(epoch)
//!                          ‖ u128le(total) ‖ merkle_root ‖ params_digest)
//! msg_v3        = SHA3-256(u32le(18) ‖ "OBB-POCI-v1/attest" ‖ u32le(chain_id) ‖ config_id
//!                          ‖ u8(depth) ‖ root ‖ u64le(src.h) ‖ src.hash ‖ u64le(tgt.h) ‖ tgt.hash)
//! tagged(t, m)  = SHA-256(SHA-256(t) ‖ SHA-256(t) ‖ m)
//! ```
//!
//! Signatures are pluggable ([`VoteScheme`]): the node uses [`Kes`] (the
//! forward-secure KES signatures of `core::kes`, signed by the leaf of
//! `epoch(target.height)`); the reference vectors use a test scheme that the
//! vector tests implement.
//!
//! Heights. ObenBlock runs PoWit from height 0, so `epoch(h) = h / epoch_len`
//! and every multiple of `checkpoint_interval` is a checkpoint slot. The
//! ledger ([`PociState`]) takes the height at which evidence is included as
//! `included_at`, compared with finalized checkpoint heights as the reference
//! does (`included_at <= F.height` means "in the history finalized by F").
//! In the node a slot `c` names the highest selected-chain block strictly
//! below `c`, so a block at height `h` passes `included_at = h + 1`
//! ([`PowitState::apply_poci`](super::PowitState::apply_poci)).

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;

use super::{Attestation, Checkpoint, KeyId};
use crate::core::kes::{self, KesPublic, KesSignature, KesSigner};
use crate::core::ChainId;

// ── Constants ────────────────────────────────────────────────────────────────

pub const DS_PARAMS: &[u8] = b"OBB-POCI-v1/params";
pub const DS_CONFIG: &[u8] = b"OBB-POCI-v1/config";
pub const DS_LEAF: &[u8] = b"OBB-POCI-v1/leaf";
pub const DS_NODE: &[u8] = b"OBB-POCI-v1/node";
pub const DS_ROOT: &[u8] = b"OBB-POCI-v1/root";
pub const DS_ATTEST_V3: &[u8] = b"OBB-POCI-v1/attest";
/// Finality certificate wire version.
pub const CERT_VERSION: u8 = 1;
/// Epochs an equivocating key is excluded (§5).
pub const POCI_BAN_EPOCHS: u64 = 100;
/// PoW-only epochs at launch; `C_4` is the first configuration (§9).
pub const POCI_BOOTSTRAP_EPOCHS: u64 = 4;
/// Growth cap divisor of DESIGN-obenblock.md §6.3 (committed in the digest).
pub const POCI_GROWTH_DIV: u64 = 64;
/// `G_min` is the expected share work of `1 / G_MIN_EPOCH_DIV` epoch (§6.3).
pub const POCI_G_MIN_EPOCH_DIV: u64 = 8;
/// Absence pruning (§4.1): a key of `C_e` with no included vote in the
/// finalized history of the last this many epochs leaves the next configuration.
pub const POCI_PRUNE_AFTER_EPOCHS: u64 = 4;
/// Domain of the rejoin message (§4.1).
pub const DS_REJOIN: &[u8] = b"OBB-POCI-v1/rejoin";
/// Rejoin messages one block may carry.
pub const MAX_REJOINS_PER_BLOCK: usize = 4;
/// Length of the rejoin message preimage.
pub const REJOIN_PREIMAGE_LEN: usize = 67;
/// Length of the v3 message preimage.
pub const V3_PREIMAGE_LEN: usize = 171;
/// Length of the configuration id preimage.
pub const CONFIG_PREIMAGE_LEN: usize = 110;
/// Length of the parameters digest preimage.
pub const PARAMS_PREIMAGE_LEN: usize = 118;

// ── Hash primitives ──────────────────────────────────────────────────────────

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA-256(SHA-256(b)).
pub fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256(&[&sha256(&[b])])
}

/// The repo's tagged hash: SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ msg).
pub fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256(&[tag]);
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ── Parameters ───────────────────────────────────────────────────────────────

/// The PoWit parameters a configuration id commits to (§2, `params_digest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PociParams {
    pub chain_id: u32,
    pub epoch_len: u64,
    pub checkpoint_interval: u64,
    pub window_epochs: u64,
    pub vote_ttl: u64,
    pub max_attestations_per_block: u64,
    pub max_evidence_per_block: u64,
    pub ban_epochs: u64,
    pub bootstrap_epochs: u64,
    /// §9: blocks that must bury the launch checkpoint (the slot opening
    /// `bootstrap_epochs`) before `C_bootstrap` enters into force
    /// ([`Self::launch_height`]): one epoch, `epoch_len`.
    pub launch_bury: u64,
    pub growth_div: u64,
    pub g_min_epoch_div: u64,
    pub quorum_num: u32,
    pub quorum_den: u32,
}

/// ObenBlock mainnet: 6-hour epochs of 720 blocks, slots every 60, the
/// 112-epoch window (reference `PARAMS["mainnet"]`).
pub const OBB_MAINNET_POCI: PociParams = PociParams {
    chain_id: ChainId::ObenBlockMainnet.to_u32(),
    epoch_len: 720,
    checkpoint_interval: 60,
    window_epochs: super::OBB_WINDOW_EPOCHS,
    vote_ttl: 720,
    max_attestations_per_block: 32,
    max_evidence_per_block: 4,
    ban_epochs: POCI_BAN_EPOCHS,
    bootstrap_epochs: POCI_BOOTSTRAP_EPOCHS,
    launch_bury: 720,
    growth_div: POCI_GROWTH_DIV,
    g_min_epoch_div: POCI_G_MIN_EPOCH_DIV,
    quorum_num: 2,
    quorum_den: 3,
};

/// ObenBlock regtest: the short test clock (20 / 5 / ttl 20) with the same
/// window and ban as mainnet in the digest (reference `PARAMS["regtest"]`).
pub const OBB_REGTEST_POCI: PociParams = PociParams {
    chain_id: ChainId::ObenBlockRegtest.to_u32(),
    epoch_len: 20,
    checkpoint_interval: 5,
    vote_ttl: 20,
    launch_bury: 20,
    ..OBB_MAINNET_POCI
};

/// §9: the launch checkpoint is buried by exactly one epoch.
pub const fn launch_bury_is_one_epoch(p: &PociParams) -> bool {
    p.launch_bury == p.epoch_len
}

const _: () = assert!(launch_bury_is_one_epoch(&OBB_MAINNET_POCI));
const _: () = assert!(launch_bury_is_one_epoch(&OBB_REGTEST_POCI));

/// What [`PociState::trim_seen`] relies on: a checkpoint finalized by a
/// block lies less than two epochs below it (`vote_ttl + checkpoint_interval
/// < 2 epoch_len`), so a block of epoch `E` hands off to an epoch `>= E - 2`.
pub const fn params_bound_the_finalized_lag(p: &PociParams) -> bool {
    p.vote_ttl + p.checkpoint_interval < 2 * p.epoch_len && p.checkpoint_interval > 0 && p.epoch_len > 0
}

const _: () = assert!(params_bound_the_finalized_lag(&OBB_MAINNET_POCI));
const _: () = assert!(params_bound_the_finalized_lag(&OBB_REGTEST_POCI));

impl PociParams {
    /// The PoCI parameters of `chain`; `None` for GnB, which keeps PoWit.
    pub const fn for_chain(chain: ChainId) -> Option<PociParams> {
        match chain {
            ChainId::ObenBlockMainnet => Some(OBB_MAINNET_POCI),
            ChainId::ObenBlockRegtest => Some(OBB_REGTEST_POCI),
            ChainId::Mainnet | ChainId::Testnet => None,
        }
    }

    /// The 118-byte preimage of [`Self::digest`].
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PARAMS_PREIMAGE_LEN);
        out.extend_from_slice(DS_PARAMS);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        for v in [self.epoch_len, self.checkpoint_interval, self.window_epochs, self.vote_ttl,
                  self.max_attestations_per_block, self.max_evidence_per_block, self.ban_epochs,
                  self.bootstrap_epochs, self.launch_bury, self.growth_div, self.g_min_epoch_div] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&self.quorum_num.to_le_bytes());
        out.extend_from_slice(&self.quorum_den.to_le_bytes());
        out
    }

    /// `params_digest`.
    pub fn digest(&self) -> [u8; 32] {
        sha256d(&self.preimage())
    }

    /// The epoch of `height` (PoWit from height 0).
    pub fn epoch_of(&self, height: u64) -> u64 {
        height / self.epoch_len
    }

    pub fn is_slot(&self, height: u64) -> bool {
        height % self.checkpoint_interval == 0
    }

    /// The checkpoint slot that opens `epoch`.
    pub fn opening(&self, epoch: u64) -> u64 {
        epoch.saturating_mul(self.epoch_len)
    }

    /// §9: the first block at or above this height puts `C_bootstrap` in
    /// force, with the slot opening `bootstrap_epochs` justified and final:
    /// that checkpoint is then buried by `launch_bury` blocks on the block's
    /// selected chain. Below it no state carries a finalized checkpoint
    /// above genesis, so nothing is pinned and a fork at the boundary of
    /// epoch `bootstrap_epochs` is settled by work.
    pub fn launch_height(&self) -> u64 {
        self.opening(self.bootstrap_epochs).saturating_add(self.launch_bury)
    }
}

// ── Registry Merkle tree ─────────────────────────────────────────────────────

pub fn leaf_hash(key: &KeyId, weight: u128) -> [u8; 32] {
    tagged(DS_LEAF, &[key, &weight.to_le_bytes()])
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    tagged(DS_NODE, &[left, right])
}

fn next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = level.chunks_exact(2).map(|p| node_hash(&p[0], &p[1])).collect();
    if level.len() % 2 == 1 {
        out.push(level[level.len() - 1]);
    }
    out
}

/// The tree over the entries' leaves (32 zero bytes when empty).
pub fn tree_root(entries: &[(KeyId, u128)]) -> [u8; 32] {
    if entries.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = entries.iter().map(|(k, w)| leaf_hash(k, *w)).collect();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// `merkle_root` from the entry count and the tree root.
pub fn merkle_root_from_tree(n: u32, tree_root: &[u8; 32]) -> [u8; 32] {
    tagged(DS_ROOT, &[&n.to_le_bytes(), tree_root])
}

/// The siblings of entry `index`, bottom up; a level where it is the carried
/// odd last node contributes none. `None` if `index` is out of range.
pub fn merkle_path(entries: &[(KeyId, u128)], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= entries.len() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = entries.iter().map(|(k, w)| leaf_hash(k, *w)).collect();
    let mut path = Vec::new();
    let mut i = index;
    while level.len() > 1 {
        if !(i == level.len() - 1 && level.len() % 2 == 1) {
            path.push(level[i ^ 1]);
        }
        level = next_level(&level);
        i /= 2;
    }
    Some(path)
}

/// The tree root `path` proves for `leaf` at `index` of `n`, or `None` if
/// its shape is wrong (index out of range, too few or too many siblings).
pub fn path_root(leaf: &[u8; 32], index: u32, n: u32, path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if index >= n {
        return None;
    }
    let (mut cur, mut i, mut width, mut used) = (*leaf, index, n, 0usize);
    while width > 1 {
        if !(i == width - 1 && width % 2 == 1) {
            let s = path.get(used)?;
            used += 1;
            cur = if i % 2 == 1 { node_hash(s, &cur) } else { node_hash(&cur, s) };
        }
        i /= 2;
        width = width.div_ceil(2);
    }
    (used == path.len()).then_some(cur)
}

/// The 110-byte preimage of a configuration id.
pub fn config_preimage(chain_id: u32, epoch: u64, total: u128, merkle_root: &[u8; 32], params_digest: &[u8; 32])
    -> Vec<u8>
{
    let mut out = Vec::with_capacity(CONFIG_PREIMAGE_LEN);
    out.extend_from_slice(DS_CONFIG);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(merkle_root);
    out.extend_from_slice(params_digest);
    out
}

pub fn config_id_from(chain_id: u32, epoch: u64, total: u128, merkle_root: &[u8; 32], params_digest: &[u8; 32])
    -> [u8; 32]
{
    sha256d(&config_preimage(chain_id, epoch, total, merkle_root, params_digest))
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Why entries are not a registry (reference `check_entries`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A weight is zero.
    Weight,
    /// Entries not strictly ascending by key id.
    Order,
    /// The same key twice.
    Duplicate,
    /// The total does not fit in u128.
    TotalOverflow,
    /// More entries than a u32 counts.
    TooMany,
}

impl ConfigError {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigError::Weight => "weight",
            ConfigError::Order => "order",
            ConfigError::Duplicate => "duplicate",
            ConfigError::TotalOverflow => "total_overflow",
            ConfigError::TooMany => "too_many",
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "poci configuration: {}", self.as_str())
    }
}

/// The total of `entries` if they are a valid registry, else the reason
/// (reference `check_entries`: per entry weight then order, the total last).
pub fn check_entries(entries: &[(KeyId, u128)]) -> Result<u128, ConfigError> {
    if u32::try_from(entries.len()).is_err() {
        return Err(ConfigError::TooMany);
    }
    let mut total: u128 = 0;
    let mut overflow = false;
    let mut prev: Option<&KeyId> = None;
    for (k, w) in entries {
        if *w == 0 {
            return Err(ConfigError::Weight);
        }
        if let Some(p) = prev {
            if k <= p {
                return Err(if k == p { ConfigError::Duplicate } else { ConfigError::Order });
            }
        }
        prev = Some(k);
        match total.checked_add(*w) {
            Some(t) => total = t,
            None => overflow = true,
        }
    }
    if overflow {
        return Err(ConfigError::TotalOverflow);
    }
    Ok(total)
}

/// The configuration `C_e` (§2): the frozen registry of finality voters of
/// one epoch, with its exact total and id. Immutable once built; serde
/// re-validates and recomputes everything derived (only the chain id, the
/// epoch, the parameters digest and the entries are encoded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ConfigurationRaw", into = "ConfigurationRaw")]
pub struct Configuration {
    chain_id: u32,
    epoch: u64,
    params_digest: [u8; 32],
    entries: Vec<(KeyId, u128)>,
    total: u128,
    tree_root: [u8; 32],
    id: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct ConfigurationRaw {
    chain_id: u32,
    epoch: u64,
    params_digest: [u8; 32],
    entries: Vec<(KeyId, u128)>,
}

impl TryFrom<ConfigurationRaw> for Configuration {
    type Error = ConfigError;
    fn try_from(r: ConfigurationRaw) -> Result<Self, ConfigError> {
        Configuration::from_parts(r.chain_id, r.epoch, r.params_digest, r.entries)
    }
}

impl From<Configuration> for ConfigurationRaw {
    fn from(c: Configuration) -> Self {
        ConfigurationRaw { chain_id: c.chain_id, epoch: c.epoch, params_digest: c.params_digest, entries: c.entries }
    }
}

impl Configuration {
    /// `C_epoch` from entries that must already be a registry.
    pub fn new(params: &PociParams, epoch: u64, entries: Vec<(KeyId, u128)>) -> Result<Self, ConfigError> {
        Self::from_parts(params.chain_id, epoch, params.digest(), entries)
    }

    /// `C_epoch` from candidate weights (reference `make_config`): keys of
    /// weight 0 are dropped, the rest sorted by key id.
    pub fn from_weights(params: &PociParams, epoch: u64, weights: &BTreeMap<KeyId, u128>)
        -> Result<Self, ConfigError>
    {
        Self::new(params, epoch, weights.iter().filter(|(_, w)| **w > 0).map(|(k, w)| (*k, *w)).collect())
    }

    pub fn from_parts(chain_id: u32, epoch: u64, params_digest: [u8; 32], entries: Vec<(KeyId, u128)>)
        -> Result<Self, ConfigError>
    {
        let total = check_entries(&entries)?;
        let tree_root = tree_root(&entries);
        let mroot = merkle_root_from_tree(entries.len() as u32, &tree_root);
        let id = config_id_from(chain_id, epoch, total, &mroot, &params_digest);
        Ok(Configuration { chain_id, epoch, params_digest, entries, total, tree_root, id })
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn params_digest(&self) -> &[u8; 32] {
        &self.params_digest
    }

    /// Entries, strictly ascending by key id.
    pub fn entries(&self) -> &[(KeyId, u128)] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The exact sum of the weights.
    pub fn total(&self) -> u128 {
        self.total
    }

    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    pub fn tree_root(&self) -> [u8; 32] {
        self.tree_root
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        merkle_root_from_tree(self.entries.len() as u32, &self.tree_root)
    }

    pub fn preimage(&self) -> Vec<u8> {
        config_preimage(self.chain_id, self.epoch, self.total, &self.merkle_root(), &self.params_digest)
    }

    pub fn index_of(&self, key: &KeyId) -> Option<usize> {
        self.entries.binary_search_by(|(k, _)| k.cmp(key)).ok()
    }

    /// The registry weight of `key`, `None` if it is not an entry.
    pub fn weight(&self, key: &KeyId) -> Option<u128> {
        self.index_of(key).map(|i| self.entries[i].1)
    }

    pub fn merkle_path(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        merkle_path(&self.entries, index)
    }

    /// Strict quorum of this configuration for `got` (§3).
    pub fn quorum(&self, got: u128) -> bool {
        quorum(got, self.total)
    }

    /// The registry proof for the voters of a certificate, in its order
    /// (§6); `None` if one of them is not an entry.
    pub fn registry_proof(&self, voters: &[KeyId]) -> Option<RegistryProof> {
        let mut members = Vec::with_capacity(voters.len());
        for k in voters {
            let i = self.index_of(k)?;
            members.push(RegistryMember { weight: self.entries[i].1, index: i as u32, path: self.merkle_path(i)? });
        }
        Some(RegistryProof { epoch: self.epoch, total: self.total, n: self.entries.len() as u32,
                             tree_root: self.tree_root, members })
    }
}

// ── Votes ────────────────────────────────────────────────────────────────────

/// The 171-byte preimage of [`attestation_message_v3`].
pub fn attestation_message_v3_preimage(chain_id: u32, config_id: &[u8; 32], witness: &KesPublic,
                                       source: &Checkpoint, target: &Checkpoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(V3_PREIMAGE_LEN);
    out.extend_from_slice(&(DS_ATTEST_V3.len() as u32).to_le_bytes());
    out.extend_from_slice(DS_ATTEST_V3);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(config_id);
    out.push(witness.depth);
    out.extend_from_slice(&witness.root);
    out.extend_from_slice(&source.height.to_le_bytes());
    out.extend_from_slice(&source.hash);
    out.extend_from_slice(&target.height.to_le_bytes());
    out.extend_from_slice(&target.hash);
    out
}

/// The digest a PoCI voter signs (§2, attestation message v3): v2's fields
/// plus the configuration the vote names. A vote counts only for that
/// configuration, with the registry's weight.
pub fn attestation_message_v3(chain_id: u32, config_id: &[u8; 32], witness: &KesPublic, source: &Checkpoint,
                              target: &Checkpoint) -> [u8; 32] {
    Sha3_256::digest(attestation_message_v3_preimage(chain_id, config_id, witness, source, target)).into()
}

/// The 67-byte preimage of [`rejoin_message`].
pub fn rejoin_message_preimage(chain_id: u32, witness: &KesPublic, epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(REJOIN_PREIMAGE_LEN);
    out.extend_from_slice(&(DS_REJOIN.len() as u32).to_le_bytes());
    out.extend_from_slice(DS_REJOIN);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.push(witness.depth);
    out.extend_from_slice(&witness.root);
    out.extend_from_slice(&epoch.to_le_bytes());
    out
}

/// The digest a pruned key signs, with the KES leaf of `epoch`, to return
/// (§4.1):
///
/// ```text
/// SHA3-256( u32le(18) ‖ "OBB-POCI-v1/rejoin" ‖ u32le(chain_id) ‖ u8(depth) ‖ root[32] ‖ u64le(epoch) )
/// ```
pub fn rejoin_message(chain_id: u32, witness: &KesPublic, epoch: u64) -> [u8; 32] {
    Sha3_256::digest(rejoin_message_preimage(chain_id, witness, epoch)).into()
}

/// Strictly more than two thirds (§3): `3 got > 2 total`, exact. With
/// `got <= total` it is `got > 2 (total - got)`, false when that overflows;
/// `got > total` (never for a registry) is `got > 0`. An empty
/// configuration never reaches a quorum. (GnB: [`super::two_thirds`], `>=`.)
pub fn quorum(got: u128, total: u128) -> bool {
    if got >= total {
        return got > 0;
    }
    let d = total - got;
    match d.checked_mul(2) {
        Some(d2) => got > d2,
        None => false,
    }
}

/// Decoding failures (reference `DecodeError` reasons).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Version,
    Truncated,
    /// A non-minimal varint.
    Varint,
    Trailing,
    /// A malformed signature (beyond truncation: sizes over the bounds).
    Signature,
}

impl DecodeError {
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeError::Version => "version",
            DecodeError::Truncated => "truncated",
            DecodeError::Varint => "varint",
            DecodeError::Trailing => "trailing",
            DecodeError::Signature => "signature_encoding",
        }
    }
}

/// Byte reader with the reference's failure reasons.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.data.len()).ok_or(DecodeError::Truncated)?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn u128(&mut self) -> Result<u128, DecodeError> {
        Ok(u128::from_le_bytes(self.array()?))
    }

    /// Bitcoin's CompactSize, minimal.
    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let first = self.u8()?;
        let (v, low) = match first {
            0xFD => (u64::from(u16::from_le_bytes(self.array()?)), 0xFD),
            0xFE => (u64::from(u32::from_le_bytes(self.array()?)), 0x1_0000),
            0xFF => (self.u64()?, 0x1_0000_0000),
            n => return Ok(u64::from(n)),
        };
        if v < low {
            return Err(DecodeError::Varint);
        }
        Ok(v)
    }

    pub fn checkpoint(&mut self) -> Result<Checkpoint, DecodeError> {
        Ok(Checkpoint { height: self.u64()?, hash: self.array()? })
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    crate::core::write_varint(out, n)
}

/// A signature scheme for PoCI votes: KES on the node ([`Kes`]), a test
/// scheme in the reference vectors.
pub trait VoteScheme {
    type Sig: Clone + PartialEq + Eq + std::fmt::Debug;
    /// `sig` is `key`'s signature of `msg` with the leaf of `kes_epoch`.
    fn verify(key: &KesPublic, kes_epoch: u64, msg: &[u8; 32], sig: &Self::Sig) -> bool;
    /// The signature's encoding inside a certificate.
    fn write_sig(sig: &Self::Sig, out: &mut Vec<u8>);
    fn read_sig(r: &mut Reader<'_>) -> Result<Self::Sig, DecodeError>;
}

/// The node's scheme: `core::kes` signatures, `KesSignature`'s wire encoding.
#[derive(Clone, Copy, Debug)]
pub struct Kes;

impl VoteScheme for Kes {
    type Sig = KesSignature;

    fn verify(key: &KesPublic, kes_epoch: u64, msg: &[u8; 32], sig: &KesSignature) -> bool {
        kes::verify(key, kes_epoch, msg, sig)
    }

    fn write_sig(sig: &KesSignature, out: &mut Vec<u8>) {
        sig.write_wire(out)
    }

    fn read_sig(r: &mut Reader<'_>) -> Result<KesSignature, DecodeError> {
        let index = r.u32()?;
        let n = r.varint()?;
        if n > kes::MAX_LEAF_PK_LEN as u64 {
            return Err(DecodeError::Signature);
        }
        let leaf_pk = r.take(n as usize)?.to_vec();
        let n = r.varint()?;
        if n > kes::MAX_LEAF_SIG_LEN as u64 {
            return Err(DecodeError::Signature);
        }
        let sig = r.take(n as usize)?.to_vec();
        let depth = r.u8()?;
        if depth > kes::MAX_DEPTH {
            return Err(DecodeError::Signature);
        }
        let mut path = Vec::with_capacity(depth as usize);
        for _ in 0..depth {
            path.push(r.array()?);
        }
        Ok(KesSignature { index, leaf_pk, sig, path })
    }
}

/// One v3 vote: a link `source -> target` under the configuration
/// `config_id`, signed by `witness`.
pub struct PociVote<S: VoteScheme> {
    pub config_id: [u8; 32],
    pub witness: KesPublic,
    pub source: Checkpoint,
    pub target: Checkpoint,
    pub sig: S::Sig,
}

impl<S: VoteScheme> Clone for PociVote<S> {
    fn clone(&self) -> Self {
        PociVote { config_id: self.config_id, witness: self.witness, source: self.source, target: self.target,
                   sig: self.sig.clone() }
    }
}

impl<S: VoteScheme> PartialEq for PociVote<S> {
    fn eq(&self, o: &Self) -> bool {
        self.config_id == o.config_id && self.witness == o.witness && self.source == o.source
            && self.target == o.target && self.sig == o.sig
    }
}

impl<S: VoteScheme> Eq for PociVote<S> {}

impl<S: VoteScheme> std::fmt::Debug for PociVote<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PociVote").field("config_id", &hex::encode(self.config_id)).field("witness", &self.witness)
            .field("source", &self.source).field("target", &self.target).field("sig", &self.sig).finish()
    }
}

impl<S: VoteScheme> PociVote<S> {
    pub fn key_id(&self) -> KeyId {
        self.witness.witness_id()
    }

    pub fn message(&self, chain_id: u32) -> [u8; 32] {
        attestation_message_v3(chain_id, &self.config_id, &self.witness, &self.source, &self.target)
    }

    /// Link shape and the signature of the target epoch's leaf over msg_v3.
    pub fn verify(&self, params: &PociParams) -> bool {
        self.target.height > self.source.height
            && S::verify(&self.witness, params.epoch_of(self.target.height), &self.message(params.chain_id), &self.sig)
    }
}

impl PociVote<Kes> {
    /// The vote of an in-block attestation, which names `config_id`
    /// implicitly (the configuration its block counts it under).
    pub fn from_attestation(a: &Attestation, config_id: [u8; 32]) -> Self {
        PociVote { config_id, witness: a.witness, source: a.source, target: a.target, sig: a.sig.clone() }
    }

    pub fn into_attestation(self) -> Attestation {
        Attestation { source: self.source, target: self.target, witness: self.witness, sig: self.sig }
    }
}

impl Attestation {
    /// Sign the v3 message naming `config_id` with a KES signer already
    /// evolved to `epoch(target.height)` (PoCI, ObenBlock).
    pub fn sign_v3(chain_id: u32, config_id: &[u8; 32], source: Checkpoint, target: Checkpoint,
                   signer: &KesSigner) -> Result<Self, String> {
        let witness = signer.public();
        let sig = signer.sign(&attestation_message_v3(chain_id, config_id, &witness, &source, &target))?;
        Ok(Attestation { source, target, witness, sig })
    }

    /// Link shape and the KES signature of `epoch(target)` over the v3
    /// message naming `config_id` (PoCI, ObenBlock).
    pub fn verify_signature_v3(&self, params: &PociParams, config_id: &[u8; 32]) -> bool {
        PociVote::<Kes>::from_attestation(self, *config_id).verify(params)
    }
}

/// The distinct keys of `config` with a valid vote for `source -> target`
/// naming `config.id()`, in vote order (reference `counted_keys`); a vote
/// naming another configuration counts nowhere.
pub fn counted_keys<S: VoteScheme>(params: &PociParams, config: &Configuration, votes: &[PociVote<S>],
                                   source: &Checkpoint, target: &Checkpoint) -> Vec<KeyId> {
    let id = config.id();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for v in votes {
        if v.config_id != id || v.source != *source || v.target != *target {
            continue;
        }
        let k = v.key_id();
        if config.weight(&k).is_none() || seen.contains(&k) || !v.verify(params) {
            continue;
        }
        seen.insert(k);
        out.push(k);
    }
    out
}

/// Weight of the distinct keys of `config` with a valid vote for
/// `source -> target` naming `config.id()`; a vote naming another
/// configuration counts nowhere (reference `counted_weight`).
pub fn counted_weight<S: VoteScheme>(params: &PociParams, config: &Configuration, votes: &[PociVote<S>],
                                     source: &Checkpoint, target: &Checkpoint) -> u128 {
    // Distinct entries: never above the total.
    counted_keys(params, config, votes, source, target).iter()
        .fold(0u128, |got, k| got.saturating_add(config.weight(k).unwrap_or(0)))
}

// ── Casper FFG under one configuration ───────────────────────────────────────

/// What a quorum for one target did (§3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FfgStep {
    /// The target is justified.
    pub justified: bool,
    /// The checkpoint this finalized (the previous justified one).
    pub finalized: Option<Checkpoint>,
}

/// Casper FFG: a quorum for a slot `t > J` justifies it; if
/// `t = J + checkpoint_interval` it also finalizes `J`. `justified` is
/// updated in place.
pub fn ffg_step(params: &PociParams, justified: &mut Checkpoint, target: &Checkpoint, quorum: bool) -> FfgStep {
    if !(quorum && target.height > justified.height && params.is_slot(target.height)) {
        return FfgStep { justified: false, finalized: None };
    }
    let src = *justified;
    *justified = *target;
    let finalized = (target.height == src.height + params.checkpoint_interval).then_some(src);
    FfgStep { justified: true, finalized }
}

// ── Proof of Corruption ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Same target height, different targets.
    Double,
    /// One link strictly surrounds the other.
    Surround,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::Double => "double",
            EvidenceKind::Surround => "surround",
        }
    }
}

/// Why evidence is invalid (reference verdict strings, [`Self::as_str`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceReject {
    DifferentKeys,
    DifferentConfigs,
    Identical,
    UnknownConfig,
    NonMember,
    NoConflict,
    Signature,
    /// The including block is at or below the finalized checkpoint.
    BelowFinality,
    /// The key was already banned for the configuration the evidence names.
    AlreadyBannedForConfig,
    /// The key has a ban without a start yet, or one not over.
    BanPendingOrActive,
}

impl EvidenceReject {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceReject::DifferentKeys => "different_keys",
            EvidenceReject::DifferentConfigs => "different_configs",
            EvidenceReject::Identical => "identical",
            EvidenceReject::UnknownConfig => "unknown_config",
            EvidenceReject::NonMember => "non_member",
            EvidenceReject::NoConflict => "no_conflict",
            EvidenceReject::Signature => "signature",
            EvidenceReject::BelowFinality => "below_finality",
            EvidenceReject::AlreadyBannedForConfig => "already_banned_for_config",
            EvidenceReject::BanPendingOrActive => "ban_pending_or_active",
        }
    }
}

impl std::fmt::Display for EvidenceReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "poci evidence: {}", self.as_str())
    }
}

/// Whether two links conflict: double (same target height, different
/// targets) or strict surround (`s1 < s2 < t2 < t1`, either way round).
pub fn conflict(a_source: u64, a_target: &Checkpoint, b_source: u64, b_target: &Checkpoint) -> Option<EvidenceKind> {
    if a_target.height == b_target.height && a_target != b_target {
        return Some(EvidenceKind::Double);
    }
    if (a_source < b_source && b_target.height < a_target.height)
        || (b_source < a_source && a_target.height < b_target.height)
    {
        return Some(EvidenceKind::Surround);
    }
    None
}

/// The context-free part of Proof of Corruption (reference
/// `check_evidence`), first failure wins: same key, same `config_id`, not
/// identical, a configuration `lookup` knows (one the chain has had in
/// force), the key an entry of it, conflicting links, both signatures last
/// (the costly checks after every cheap one).
pub fn check_evidence<'c, S: VoteScheme>(params: &PociParams, a: &PociVote<S>, b: &PociVote<S>,
                                         lookup: impl Fn(&[u8; 32]) -> Option<&'c Configuration>)
    -> Result<EvidenceKind, EvidenceReject>
{
    if a.witness != b.witness {
        return Err(EvidenceReject::DifferentKeys);
    }
    if a.config_id != b.config_id {
        return Err(EvidenceReject::DifferentConfigs);
    }
    if a == b {
        return Err(EvidenceReject::Identical);
    }
    let cfg = lookup(&a.config_id).ok_or(EvidenceReject::UnknownConfig)?;
    if cfg.weight(&a.key_id()).is_none() {
        return Err(EvidenceReject::NonMember);
    }
    let kind = conflict(a.source.height, &a.target, b.source.height, &b.target).ok_or(EvidenceReject::NoConflict)?;
    if !a.verify(params) || !b.verify(params) {
        return Err(EvidenceReject::Signature);
    }
    Ok(kind)
}

/// Proof of Corruption as a block carries it on ObenBlock: the configuration
/// both votes name, then the two attestations.
///
/// Wire: `config_id[32] ‖ a ‖ b` (each `Attestation`'s wire encoding).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PociEvidence {
    pub config_id: [u8; 32],
    pub a: Attestation,
    pub b: Attestation,
}

impl PociEvidence {
    pub fn key_id(&self) -> KeyId {
        self.a.key_id()
    }

    pub fn votes(&self) -> (PociVote<Kes>, PociVote<Kes>) {
        (PociVote::from_attestation(&self.a, self.config_id), PociVote::from_attestation(&self.b, self.config_id))
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = self.config_id.to_vec();
        out.extend_from_slice(&self.a.to_wire_bytes());
        out.extend_from_slice(&self.b.to_wire_bytes());
        out
    }

    pub fn read_wire(cur: &mut Cursor<&[u8]>) -> Result<Self, String> {
        let config_id = super::read_array32(cur)?;
        Ok(PociEvidence { config_id, a: Attestation::read_wire(cur)?, b: Attestation::read_wire(cur)? })
    }

    /// Unique id (gossip and pool dedup).
    pub fn id(&self) -> [u8; 32] {
        Sha3_256::digest(self.to_wire_bytes()).into()
    }
}

// ── The ledger: configurations in force, handoff and bans ────────────────────

/// One exclusion (§5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ban {
    /// The configuration the evidence named.
    pub config_id: [u8; 32],
    /// Where the evidence was included (module docs, "Heights").
    pub included_at: u64,
    /// `ban_start`: set at the first handoff at or after the finalization of
    /// the block holding the evidence.
    pub start: Option<u64>,
}

impl Ban {
    pub fn end(&self, ban_epochs: u64) -> Option<u64> {
        self.start.map(|s| s.saturating_add(ban_epochs))
    }
}

/// Absence pruning (§4.1): the key is left out of every configuration from
/// epoch `start` on, until a finalized rejoin ends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prune {
    pub start: u64,
    /// Set only while the handoff that a finalized rejoin ends it at computes
    /// its configuration (the key is not excluded from that epoch on); never
    /// stored.
    pub until: Option<u64>,
}

impl Prune {
    pub fn covers(&self, epoch: u64) -> bool {
        self.start <= epoch && self.until.is_none_or(|u| epoch < u)
    }
}

/// Why a rejoin message is invalid (reference verdict strings, [`Self::as_str`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejoinReject {
    /// The including block is at or below the finalized checkpoint.
    BelowFinality,
    /// Not signed for the block's epoch or the one before.
    Epoch,
    /// The key is not pruned.
    NotPruned,
    /// The key already has a rejoin waiting for finality.
    Pending,
    Signature,
}

impl RejoinReject {
    pub fn as_str(self) -> &'static str {
        match self {
            RejoinReject::BelowFinality => "below_finality",
            RejoinReject::Epoch => "epoch",
            RejoinReject::NotPruned => "not_pruned",
            RejoinReject::Pending => "pending",
            RejoinReject::Signature => "signature",
        }
    }
}

impl std::fmt::Display for RejoinReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "poci rejoin: {}", self.as_str())
    }
}

/// The configurations a chain has had in force, newest first; shared
/// between the states of one chain (each handoff adds one node).
#[derive(Debug)]
struct HistoryNode {
    config: Arc<Configuration>,
    prev: Option<Arc<HistoryNode>>,
}

/// PoCI state of one chain (reference `PociChain`, without the checkpoints,
/// which `PowitState` keeps): the configuration in force, the ones before it,
/// the bans, and the absence-pruning ledger (§4.1). The checkpoints and the
/// vote tally are the caller's.
#[derive(Clone, Debug)]
pub struct PociState {
    head: Arc<HistoryNode>,
    /// key -> its bans, latest last.
    pub bans: BTreeMap<KeyId, Vec<Ban>>,
    /// Keys pruned for absence (§4.1), until a finalized rejoin.
    pub pruned: BTreeMap<KeyId, Prune>,
    /// Pruned keys with a rejoin included (at that height) and not yet final.
    pub rejoins: BTreeMap<KeyId, u64>,
    /// Included votes of the configuration's keys: key -> (epoch of the
    /// including block -> the lowest `included_at` in it). The reference keeps
    /// every height; the lowest per epoch answers the same question
    /// ([`Self::present`]), and [`Self::trim_seen`] drops the epochs no later
    /// handoff can read.
    pub seen: BTreeMap<KeyId, BTreeMap<u64, u64>>,
}

impl PartialEq for PociState {
    fn eq(&self, o: &Self) -> bool {
        self.bans == o.bans && self.pruned == o.pruned && self.rejoins == o.rejoins && self.seen == o.seen
            && self.history().map(|c| c.id()).eq(o.history().map(|c| c.id()))
    }
}

impl Eq for PociState {}

/// The weights of a new configuration (DESIGN-obenblock.md §6.3, package
/// O10, the growth cap): candidate weights of `C_epoch` computed from the
/// finalized history up to `opening(epoch)` (never above it, even though
/// `finalized` may lie higher: §4, one configuration per epoch), of every
/// key with weight, including
/// the keys the ledger excludes at that epoch (bans, absence pruning); the
/// ledger leaves those out.
pub trait WeightProvider {
    fn weights(&mut self, epoch: u64, finalized: &Checkpoint) -> BTreeMap<KeyId, u128>;
}

impl<F: FnMut(u64, &Checkpoint) -> BTreeMap<KeyId, u128>> WeightProvider for F {
    fn weights(&mut self, epoch: u64, finalized: &Checkpoint) -> BTreeMap<KeyId, u128> {
        self(epoch, finalized)
    }
}

impl PociState {
    /// §9: the first configuration, `C_bootstrap`, from the candidate
    /// `weights` (computed from the chain up to the checkpoint that opens
    /// epoch `bootstrap_epochs`).
    pub fn launch(params: &PociParams, weights: &BTreeMap<KeyId, u128>) -> Result<Self, ConfigError> {
        let config = Configuration::from_weights(params, params.bootstrap_epochs, weights)?;
        Ok(PociState { head: Arc::new(HistoryNode { config: Arc::new(config), prev: None }), bans: BTreeMap::new(),
                       pruned: BTreeMap::new(), rejoins: BTreeMap::new(), seen: BTreeMap::new() })
    }

    /// A state from its configurations (newest first, the one in force at
    /// index 0) and bans, with an empty pruning ledger ([`Self::with_ledger`]
    /// sets it): what the node stores.
    pub fn from_history(history: Vec<Arc<Configuration>>, bans: BTreeMap<KeyId, Vec<Ban>>) -> Option<Self> {
        let mut head: Option<Arc<HistoryNode>> = None;
        for config in history.into_iter().rev() {
            head = Some(Arc::new(HistoryNode { config, prev: head }));
        }
        Some(PociState { head: head?, bans, pruned: BTreeMap::new(), rejoins: BTreeMap::new(), seen: BTreeMap::new() })
    }

    /// `self` with the absence-pruning ledger of a stored state.
    pub fn with_ledger(mut self, pruned: BTreeMap<KeyId, Prune>, rejoins: BTreeMap<KeyId, u64>,
                       seen: BTreeMap<KeyId, BTreeMap<u64, u64>>) -> Self {
        self.pruned = pruned;
        self.rejoins = rejoins;
        self.seen = seen;
        self
    }

    /// The configuration in force.
    pub fn config(&self) -> &Arc<Configuration> {
        &self.head.config
    }

    /// The configuration in force before the current one.
    pub fn previous(&self) -> Option<&Arc<Configuration>> {
        self.head.prev.as_ref().map(|n| &n.config)
    }

    /// Every configuration the chain has had in force, newest first.
    pub fn history(&self) -> impl Iterator<Item = &Arc<Configuration>> {
        let mut cur = Some(&self.head);
        std::iter::from_fn(move || {
            let n = cur?;
            cur = n.prev.as_ref();
            Some(&n.config)
        })
    }

    /// A configuration the chain has had in force, by id.
    pub fn find_config(&self, id: &[u8; 32]) -> Option<&Configuration> {
        self.history().find(|c| c.id() == *id).map(|c| &**c)
    }

    /// `key` is excluded from `C_epoch` by a ban.
    pub fn banned_at(&self, params: &PociParams, key: &KeyId, epoch: u64) -> bool {
        self.bans.get(key).is_some_and(|bl| {
            bl.iter().any(|b| b.start.is_some_and(|s| s <= epoch && epoch < s.saturating_add(params.ban_epochs)))
        })
    }

    /// `key` is excluded from `C_epoch` by absence pruning (§4.1).
    pub fn pruned_at(&self, key: &KeyId, epoch: u64) -> bool {
        self.pruned.get(key).is_some_and(|p| p.covers(epoch))
    }

    /// Banned or pruned at `epoch`: what a [`WeightProvider`] (or
    /// `ConfigWeights`) leaves out of the epochs a handoff covers, e.g. the
    /// growth cap's excluded keys. Valid for every epoch up to the one a
    /// handoff in progress enters.
    pub fn excluded_at(&self, params: &PociParams, key: &KeyId, epoch: u64) -> bool {
        self.banned_at(params, key, epoch) || self.pruned_at(key, epoch)
    }

    /// The epoch of the configuration that finalizing `f` under the one in
    /// force hands off to, if any (§4: `epoch(f) > e`).
    pub fn handoff_epoch(&self, params: &PociParams, f: &Checkpoint) -> Option<u64> {
        let e = params.epoch_of(f.height);
        (e > self.config().epoch()).then_some(e)
    }

    /// Record that a block included a vote of `key` at `included_at` (module
    /// docs, "Heights"). Only keys of the configuration in force can have one.
    pub fn record_vote(&mut self, params: &PociParams, key: &KeyId, included_at: u64) {
        if self.config().weight(key).is_none() {
            return;
        }
        let bucket = params.epoch_of(included_at.saturating_sub(1));
        let m = self.seen.entry(*key).or_default().entry(bucket).or_insert(included_at);
        *m = (*m).min(included_at);
    }

    /// §4.1: a vote of `key` was included at a height `h` with
    /// `opening(x - PRUNE_AFTER) < h <= opening(x)`: in the blocks of epochs
    /// `x - PRUNE_AFTER ..= x - 1`, history that every checkpoint of epoch
    /// `x` finalizes (§4: `C_x` reads nothing above `opening(x)`). The lowest
    /// inclusion of each block epoch decides: a block epoch `y` holds heights
    /// in `(opening(y), opening(y + 1)]`, so an inclusion of `y` inside the
    /// bounds exists iff its lowest one is inside them.
    pub fn present(&self, params: &PociParams, key: &KeyId, x: u64) -> bool {
        let lo = params.opening(x.saturating_sub(POCI_PRUNE_AFTER_EPOCHS));
        let hi = params.opening(x);
        self.seen.get(key).is_some_and(|m| m.values().any(|&h| lo < h && h <= hi))
    }

    /// §4.1: the weight of the configuration in force whose keys are
    /// [`present`](Self::present) for a handoff to `x`.
    pub fn present_weight(&self, params: &PociParams, x: u64) -> u128 {
        self.config().entries().iter().filter(|(k, _)| self.present(params, k, x))
            .fold(0u128, |a, (_, w)| a.saturating_add(*w))
    }

    /// §4.1: `key` has been an entry of every configuration in force since
    /// epoch `x - PRUNE_AFTER` or earlier (a key that entered later is in its
    /// grace period).
    pub fn prune_eligible(&self, key: &KeyId, x: u64) -> bool {
        for c in self.history() {
            if c.weight(key).is_none() {
                return false;
            }
            if c.epoch().saturating_add(POCI_PRUNE_AFTER_EPOCHS) <= x {
                return true;
            }
        }
        false
    }

    /// The weight of the configuration in force `C_e` absent for a step to
    /// `x` (`getpowitinfo`, §4.1: operators see absent weight grow long
    /// before it reaches a third): its keys with no vote included in
    /// `(opening(x - PRUNE_AFTER), opening(x)]`, the window of
    /// [`Self::present`]. Not final: blocks above the finalized checkpoint
    /// count too, and the window is the one this ledger still holds
    /// ([`Self::trim_seen`]). Informational: the quorum gate of a step to `x`
    /// is `!self.config().quorum(total - absent)` only when `x = e + 1`; the
    /// later steps of a handoff gate on their own `C_{x-1}`.
    pub fn absent_weight(&self, params: &PociParams, x: u64) -> u128 {
        self.config().entries().iter().filter(|(k, _)| !self.present(params, k, x))
            .fold(0u128, |a, (_, w)| a.saturating_add(*w))
    }

    /// Drop the included votes no later handoff step reads, for a chain
    /// whose blocks are now in epoch `block_epoch`: such a block finalizes a
    /// checkpoint of epoch `>= block_epoch - 2`
    /// ([`params_bound_the_finalized_lag`]), and a handoff steps through
    /// every epoch from `e + 1` (`C_e` in force), the step to `x` reading
    /// inclusions above `opening(x - PRUNE_AFTER)` only. So the block epochs
    /// from `min(block_epoch - 2, e + 1) - PRUNE_AFTER` on are kept. Never
    /// changes a verdict; it bounds the ledger at `PRUNE_AFTER + 3` epochs
    /// per key while finality runs (during a stall it keeps every block
    /// epoch from `e - 3` on, one entry per key and epoch).
    pub fn trim_seen(&mut self, block_epoch: u64) {
        let first_step = block_epoch.saturating_sub(2).min(self.config().epoch().saturating_add(1));
        let keep = first_step.saturating_sub(POCI_PRUNE_AFTER_EPOCHS);
        for m in self.seen.values_mut() {
            m.retain(|y, _| *y >= keep);
        }
        self.seen.retain(|_, m| !m.is_empty());
    }

    /// The epochs a handoff triggered by finalizing `f` under the
    /// configuration in force `C_e` steps through (§4): `e + 1 ..= epoch(f)`,
    /// in order, one [`Self::begin_step`] + [`Self::enter`] each; empty when
    /// `f` does not hand off.
    pub fn handoff_steps(&self, params: &PociParams, f: &Checkpoint) -> std::ops::RangeInclusive<u64> {
        match self.handoff_epoch(params, f) {
            Some(x) => self.config().epoch().saturating_add(1)..=x,
            None => 1..=0,
        }
    }

    /// The first half of one handoff step `C_{x-1} -> C_x` (§4, §4.1, §5),
    /// `x = self.config().epoch() + 1`, from the history up to `cut =
    /// opening(x)` only: every pending ban included at or below `cut` starts
    /// at `x`; every pending rejoin included at or below `cut` ends its key's
    /// pruning at `x`; and, if the keys of `C_{x-1}`
    /// [`present`](Self::present) for `x` hold a strict quorum of `C_{x-1}`,
    /// every key of `C_{x-1}` that has been an entry since `x - PRUNE_AFTER`
    /// or earlier and is not present is pruned from `x`. Without that quorum
    /// (a finality stall covered the window: the committee that ends it has
    /// no votes there) nobody is pruned. A handoff to `epoch(F)` runs one
    /// step per epoch boundary ([`Self::handoff_steps`]), so `C_x` depends
    /// on the history only, never on which checkpoints were finalized on the
    /// way. The caller computes the candidate weights (with this state) and
    /// calls [`Self::enter`] with the same `x`.
    pub fn begin_step(&mut self, params: &PociParams, x: u64) {
        debug_assert_eq!(x, self.config().epoch() + 1, "one handoff step at a time");
        let cut = params.opening(x);
        for bl in self.bans.values_mut() {
            for b in bl.iter_mut() {
                if b.start.is_none() && b.included_at <= cut {
                    b.start = Some(x);
                }
            }
        }
        let done: Vec<KeyId> = self.rejoins.iter().filter(|(_, h)| **h <= cut).map(|(k, _)| *k).collect();
        for k in done {
            self.rejoins.remove(&k);
            if let Some(p) = self.pruned.get_mut(&k) {
                p.until = Some(x);
            }
        }
        if self.config().quorum(self.present_weight(params, x)) {
            let absent: Vec<KeyId> = self.config().entries().iter().map(|(k, _)| *k)
                .filter(|k| !self.pruned.contains_key(k) && self.prune_eligible(k, x) && !self.present(params, k, x))
                .collect();
            for k in absent {
                self.pruned.insert(k, Prune { start: x, until: None });
            }
        }
    }

    /// The second half of a handoff step: `C_x` enters into force from the
    /// provider's `candidates`, without the keys banned or pruned at `x` and
    /// those `also_excluded` (exits, which the PoWit state keeps). A pruned
    /// key without candidate weight (no share work left) is forgotten; the
    /// included votes are kept for the keys of `C_x` only. Never empty
    /// (§4.1): if nothing is left, `C_x` holds the entries of `C_{x-1}`
    /// unchanged and the prunings this step started are void (a
    /// configuration that can reach no quorum would halt finality for good).
    pub fn enter(&mut self, params: &PociParams, x: u64, candidates: &BTreeMap<KeyId, u128>,
                 also_excluded: &dyn Fn(&KeyId) -> bool) -> Result<(), ConfigError>
    {
        let forgotten: Vec<KeyId> = self.pruned.iter()
            .filter(|(k, p)| p.until.is_none() && candidates.get(*k).is_none_or(|w| *w == 0))
            .map(|(k, _)| *k).collect();
        for k in forgotten {
            self.pruned.remove(&k);
            self.rejoins.remove(&k);
        }
        let mut w: BTreeMap<KeyId, u128> = candidates.iter()
            .filter(|(k, w)| **w > 0 && !self.excluded_at(params, k, x) && !also_excluded(k))
            .map(|(k, w)| (*k, *w)).collect();
        if w.is_empty() {
            self.pruned.retain(|_, p| !(p.start == x && p.until.is_none()));
            w = self.config().entries().iter().copied().collect();
        }
        let config = Configuration::from_weights(params, x, &w)?;
        self.head = Arc::new(HistoryNode { config: Arc::new(config), prev: Some(self.head.clone()) });
        self.pruned.retain(|_, p| p.until.is_none());
        let cfg = self.head.config.clone();
        let keep_from = x.saturating_sub(3);
        self.seen.retain(|k, m| {
            m.retain(|y, _| *y >= keep_from);
            cfg.weight(k).is_some() && !m.is_empty()
        });
        Ok(())
    }

    /// §4 + §4.1 + §5 in one call: every step of [`Self::handoff_steps`]
    /// ([`Self::begin_step`], then [`Self::enter`] with `weights(self, x)`).
    /// Returns whether it handed off.
    pub fn finalized(&mut self, params: &PociParams, f: &Checkpoint,
                     mut weights: impl FnMut(&PociState, u64) -> BTreeMap<KeyId, u128>) -> Result<bool, ConfigError>
    {
        let steps = self.handoff_steps(params, f);
        if steps.is_empty() {
            return Ok(false);
        }
        for x in steps {
            self.begin_step(params, x);
            let w = weights(self, x);
            self.enter(params, x, &w, &|_| false)?;
        }
        Ok(true)
    }

    /// [`Self::finalized`] with a [`WeightProvider`].
    pub fn finalized_with(&mut self, params: &PociParams, f: &Checkpoint, provider: &mut dyn WeightProvider)
        -> Result<bool, ConfigError>
    {
        self.finalized(params, f, |_, e| provider.weights(e, f))
    }

    /// Admit evidence included at `included_at` above the finalized
    /// checkpoint `finalized_height` (reference `PociChain.evidence`): the
    /// context-free checks, then one ban at a time per key. Records the ban
    /// (pending until a handoff starts it); nothing in force changes.
    pub fn admit_evidence<S: VoteScheme>(&mut self, params: &PociParams, included_at: u64, finalized_height: u64,
                                         a: &PociVote<S>, b: &PociVote<S>) -> Result<EvidenceKind, EvidenceReject> {
        if included_at <= finalized_height {
            return Err(EvidenceReject::BelowFinality);
        }
        let kind = check_evidence(params, a, b, |id| self.find_config(id))?;
        self.may_ban(params, &a.key_id(), &a.config_id)?;
        self.bans.entry(a.key_id()).or_default().push(Ban { config_id: a.config_id, included_at, start: None });
        Ok(kind)
    }

    /// The one-ban-at-a-time rule alone (§5), for pools that check it before
    /// the signatures: `key` has no ban for `config_id`, and none pending or
    /// not over under the configuration in force.
    pub fn may_ban(&self, params: &PociParams, key: &KeyId, config_id: &[u8; 32]) -> Result<(), EvidenceReject> {
        let now = self.config().epoch();
        for ban in self.bans.get(key).map(Vec::as_slice).unwrap_or(&[]) {
            if ban.config_id == *config_id {
                return Err(EvidenceReject::AlreadyBannedForConfig);
            }
            match ban.end(params.ban_epochs) {
                Some(end) if now >= end => {}
                _ => return Err(EvidenceReject::BanPendingOrActive),
            }
        }
        Ok(())
    }

    /// What a block checks of a rejoin before its signature (reference
    /// `PociChain.rejoin`, first failure wins): included above the finalized
    /// checkpoint, signed for the block's epoch or the one before, the key
    /// pruned and without a rejoin pending.
    pub fn may_rejoin(&self, included_at: u64, finalized_height: u64, block_epoch: u64, key: &KeyId, epoch: u64)
        -> Result<(), RejoinReject>
    {
        if included_at <= finalized_height {
            return Err(RejoinReject::BelowFinality);
        }
        if !(epoch <= block_epoch && block_epoch <= epoch.saturating_add(1)) {
            return Err(RejoinReject::Epoch);
        }
        if !self.pruned.get(key).is_some_and(|p| p.until.is_none()) {
            return Err(RejoinReject::NotPruned);
        }
        if self.rejoins.contains_key(key) {
            return Err(RejoinReject::Pending);
        }
        Ok(())
    }

    /// Admit a rejoin of `key` signed for `epoch` in a block of `block_epoch`
    /// included at `included_at` ([`Self::may_rejoin`], then `verify`, the
    /// signature check, last). It ends the pruning at the handoff its
    /// finalization triggers, or the next one.
    pub fn admit_rejoin(&mut self, included_at: u64, finalized_height: u64, block_epoch: u64, key: &KeyId,
                        epoch: u64, verify: impl FnOnce() -> bool) -> Result<(), RejoinReject>
    {
        self.may_rejoin(included_at, finalized_height, block_epoch, key, epoch)?;
        if !verify() {
            return Err(RejoinReject::Signature);
        }
        self.rejoins.insert(*key, included_at);
        Ok(())
    }
}

// ── Proof of Integrity: the finality certificate ─────────────────────────────

/// A finality certificate (§6): votes strictly ascending by key id.
pub struct Certificate<S: VoteScheme> {
    pub version: u8,
    pub chain_id: u32,
    pub config_id: [u8; 32],
    pub source: Checkpoint,
    pub target: Checkpoint,
    pub votes: Vec<(KesPublic, S::Sig)>,
}

/// Why a certificate does not verify (reference reason strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertReject {
    Decode(DecodeError),
    ChainId,
    ConfigId,
    Link,
    Order,
    Duplicate,
    NonMember,
    Quorum,
    Signature,
    /// A registry proof path (or weight) that does not prove membership.
    Path,
}

impl CertReject {
    pub fn as_str(self) -> &'static str {
        match self {
            CertReject::Decode(d) => d.as_str(),
            CertReject::ChainId => "chain_id",
            CertReject::ConfigId => "config_id",
            CertReject::Link => "link",
            CertReject::Order => "order",
            CertReject::Duplicate => "duplicate",
            CertReject::NonMember => "non_member",
            CertReject::Quorum => "quorum",
            CertReject::Signature => "signature",
            CertReject::Path => "path",
        }
    }
}

impl std::fmt::Display for CertReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "poci certificate: {}", self.as_str())
    }
}

impl From<DecodeError> for CertReject {
    fn from(d: DecodeError) -> Self {
        CertReject::Decode(d)
    }
}

/// Smallest encoded vote (depth, root, an empty signature byte).
const MIN_VOTE_BYTES: usize = 34;

impl<S: VoteScheme> Clone for Certificate<S> {
    fn clone(&self) -> Self {
        Certificate { version: self.version, chain_id: self.chain_id, config_id: self.config_id, source: self.source,
                      target: self.target, votes: self.votes.clone() }
    }
}

impl<S: VoteScheme> PartialEq for Certificate<S> {
    fn eq(&self, o: &Self) -> bool {
        self.version == o.version && self.chain_id == o.chain_id && self.config_id == o.config_id
            && self.source == o.source && self.target == o.target && self.votes == o.votes
    }
}

impl<S: VoteScheme> Eq for Certificate<S> {}

impl<S: VoteScheme> std::fmt::Debug for Certificate<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate").field("version", &self.version).field("chain_id", &self.chain_id)
            .field("config_id", &hex::encode(self.config_id)).field("source", &self.source)
            .field("target", &self.target).field("votes", &self.votes.len()).finish()
    }
}

impl<S: VoteScheme> Certificate<S> {
    /// The certificate of `votes` (any order; sorted here by key id).
    pub fn new(chain_id: u32, config_id: [u8; 32], source: Checkpoint, target: Checkpoint,
               mut votes: Vec<(KesPublic, S::Sig)>) -> Self {
        votes.sort_by_key(|(k, _)| k.witness_id());
        Certificate { version: CERT_VERSION, chain_id, config_id, source, target, votes }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.config_id);
        out.extend_from_slice(&self.source.height.to_le_bytes());
        out.extend_from_slice(&self.source.hash);
        out.extend_from_slice(&self.target.height.to_le_bytes());
        out.extend_from_slice(&self.target.hash);
        write_varint(&mut out, self.votes.len() as u64);
        for (k, sig) in &self.votes {
            out.push(k.depth);
            out.extend_from_slice(&k.root);
            S::write_sig(sig, &mut out);
        }
        out
    }

    /// Decode (version, truncated, non-minimal varint, trailing bytes).
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let version = r.u8()?;
        if version != CERT_VERSION {
            return Err(DecodeError::Version);
        }
        let chain_id = r.u32()?;
        let config_id = r.array()?;
        let source = r.checkpoint()?;
        let target = r.checkpoint()?;
        let n = r.varint()?;
        // No allocation from the claimed count: at most what the bytes hold.
        let mut votes = Vec::with_capacity((n as usize).min(r.remaining() / MIN_VOTE_BYTES));
        for _ in 0..n {
            let depth = r.u8()?;
            let root = r.array()?;
            votes.push((KesPublic { depth, root }, S::read_sig(&mut r)?));
        }
        if !r.done() {
            return Err(DecodeError::Trailing);
        }
        Ok(Certificate { version, chain_id, config_id, source, target, votes })
    }

    /// Chain, configuration, link and order (reference `_check_shape`).
    fn check_shape(&self, params: &PociParams, trusted_id: &[u8; 32]) -> Result<(), CertReject> {
        if self.chain_id != params.chain_id {
            return Err(CertReject::ChainId);
        }
        if self.config_id != *trusted_id {
            return Err(CertReject::ConfigId);
        }
        let (s, t) = (self.source.height, self.target.height);
        if !(params.is_slot(s) && params.is_slot(t) && s.checked_add(params.checkpoint_interval) == Some(t)) {
            return Err(CertReject::Link);
        }
        let mut prev: Option<KeyId> = None;
        for (k, _) in &self.votes {
            let id = k.witness_id();
            if let Some(p) = prev {
                if id <= p {
                    return Err(if id == p { CertReject::Duplicate } else { CertReject::Order });
                }
            }
            prev = Some(id);
        }
        Ok(())
    }

    fn check_signatures(&self, params: &PociParams) -> Result<(), CertReject> {
        let kes_epoch = params.epoch_of(self.target.height);
        for (k, sig) in &self.votes {
            let msg = attestation_message_v3(self.chain_id, &self.config_id, k, &self.source, &self.target);
            if !S::verify(k, kes_epoch, &msg, sig) {
                return Err(CertReject::Signature);
            }
        }
        Ok(())
    }

    /// Verify against a trusted configuration (its entries), first failure
    /// wins: chain id, config id, link, order, membership, quorum, signatures.
    pub fn verify(&self, params: &PociParams, config: &Configuration) -> Result<(), CertReject> {
        self.check_shape(params, &config.id())?;
        let mut got: u128 = 0;
        for (k, _) in &self.votes {
            let w = config.weight(&k.witness_id()).ok_or(CertReject::NonMember)?;
            got = got.saturating_add(w);
        }
        if !quorum(got, config.total()) {
            return Err(CertReject::Quorum);
        }
        self.check_signatures(params)
    }

    /// Verify against a trusted `config_id` and a registry proof: the proof
    /// must recompute that id, and each voter's leaf its tree root.
    pub fn verify_with_proof(&self, params: &PociParams, trusted_id: &[u8; 32], proof: &RegistryProof)
        -> Result<(), CertReject>
    {
        self.check_shape(params, trusted_id)?;
        let mroot = merkle_root_from_tree(proof.n, &proof.tree_root);
        if config_id_from(params.chain_id, proof.epoch, proof.total, &mroot, &params.digest()) != *trusted_id {
            return Err(CertReject::ConfigId);
        }
        if proof.members.len() != self.votes.len() {
            return Err(CertReject::Path);
        }
        let mut got: u128 = 0;
        for ((k, _), m) in self.votes.iter().zip(&proof.members) {
            if m.weight == 0
                || path_root(&leaf_hash(&k.witness_id(), m.weight), m.index, proof.n, &m.path) != Some(proof.tree_root)
            {
                return Err(CertReject::Path);
            }
            got = got.checked_add(m.weight).ok_or(CertReject::Path)?;
        }
        if got > proof.total {
            return Err(CertReject::Path);
        }
        if !quorum(got, proof.total) {
            return Err(CertReject::Quorum);
        }
        self.check_signatures(params)
    }
}

/// Decode and verify a certificate against a trusted configuration.
pub fn verify_certificate<S: VoteScheme>(data: &[u8], params: &PociParams, config: &Configuration)
    -> Result<Certificate<S>, CertReject>
{
    let c = Certificate::<S>::decode(data)?;
    c.verify(params, config)?;
    Ok(c)
}

/// Decode and verify a certificate against a trusted `config_id` and an
/// encoded registry proof (decoding failures of either come first).
pub fn verify_certificate_with_proof<S: VoteScheme>(data: &[u8], proof: &[u8], params: &PociParams,
                                                    trusted_id: &[u8; 32]) -> Result<Certificate<S>, CertReject> {
    let c = Certificate::<S>::decode(data)?;
    let p = RegistryProof::decode(proof, c.votes.len())?;
    c.verify_with_proof(params, trusted_id, &p)?;
    Ok(c)
}

/// One voter's registry entry and Merkle path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryMember {
    pub weight: u128,
    pub index: u32,
    pub path: Vec<[u8; 32]>,
}

/// A registry proof (§6): the configuration's epoch, total, entry count and
/// tree root, then per vote of the certificate (in its order) the entry's
/// weight, index and path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryProof {
    pub epoch: u64,
    pub total: u128,
    pub n: u32,
    pub tree_root: [u8; 32],
    pub members: Vec<RegistryMember>,
}

impl RegistryProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&self.n.to_le_bytes());
        out.extend_from_slice(&self.tree_root);
        for m in &self.members {
            out.extend_from_slice(&m.weight.to_le_bytes());
            out.extend_from_slice(&m.index.to_le_bytes());
            out.push(m.path.len() as u8);
            for s in &m.path {
                out.extend_from_slice(s);
            }
        }
        out
    }

    /// Decode a proof for a certificate of `n_votes` votes.
    pub fn decode(data: &[u8], n_votes: usize) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let (epoch, total, n, tree_root) = (r.u64()?, r.u128()?, r.u32()?, r.array()?);
        let mut members = Vec::with_capacity(n_votes.min(r.remaining() / 21));
        for _ in 0..n_votes {
            let (weight, index, len) = (r.u128()?, r.u32()?, r.u8()?);
            let mut path = Vec::with_capacity(len as usize);
            for _ in 0..len {
                path.push(r.array()?);
            }
            members.push(RegistryMember { weight, index, path });
        }
        if !r.done() {
            return Err(DecodeError::Trailing);
        }
        Ok(RegistryProof { epoch, total, n, tree_root, members })
    }
}
