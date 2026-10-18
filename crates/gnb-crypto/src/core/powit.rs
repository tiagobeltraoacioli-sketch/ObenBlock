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
//!   1/16 of their weight per epoch until finality resumes (half, on a chain
//!   whose [`PowitParams::leak`] is [`InactivityLeak::Half`]).
//! - **Witness exits** (from the liveness activation, `core::liveness`): a
//!   witness signs an exit with its KES key ([`WitnessExit`]) and its weight
//!   leaves `W` from the next epoch.
//!
//! # Second hardening activation ([`Regime::Hardening2`])
//!
//! From `activation::hardening2_activation_height()` (mainnet: not yet
//! scheduled; testnet and regtest: 0), PoWit audit findings 1 and 4
//! (docs/CONSENSUS.md, "PoWit"; docs/DESIGN-pow-powit.md, §4-§5):
//!
//! - **The signed message commits the witness key** (attestations whose
//!   *target* height is at or above the activation,
//!   [`attestation_message_v2`]): a leaf signature is valid for exactly one
//!   KES key, so a leaf can no longer be re-rooted into unlimited keys.
//! - **Evidence only against witnesses** (blocks at or above the
//!   activation): a block of epoch `E` may carry an equivocation proof only
//!   against a member of `W(E-1)`, `W(E)` or `W(E+1)`.
//! - **Two thirds of all the weight** (blocks at or above the activation):
//!   `W(e)` is every unbarred share key with weight (no 64-key cap), so the
//!   justification threshold is two thirds of the total window weight, as
//!   Casper FFG measures two thirds of all stake.
//!
//! Below the activation every rule is the one above, bit for bit
//! (`hardening2_tests::old_regime_transition_is_pinned`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::activation;
use super::witness_share::WitnessShare;
use super::kes::{self, KesPublic, KesSignature, KesSigner};
use super::{read_varint, write_varint, ChainId};

pub mod growth_cap;
pub mod poci;
use growth_cap::CapState;
use poci::{PociEvidence, PociParams, PociState};

pub use poci::MAX_REJOINS_PER_BLOCK;

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
    /// What one inactivity-decay step takes from a weight.
    pub leak: InactivityLeak,
}

/// The weight one inactivity-decay step takes (`docs/DESIGN-obenblock.md`
/// §5.2). A constant of the chain, never height-gated: `PowitState::decay`
/// stores step counts, which mean one thing per chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InactivityLeak {
    /// GnB: `w -= w / 16` per step, at most 64 steps ([`decayed`]).
    Sixteenth,
    /// ObenBlock: half per step, `ceil(w / 2^n)` after `n` steps (at most
    /// 128, which leaves every weight at 1 or 0; [`decayed_half`]). After a
    /// fraction `a` of the weight left, finality resumes after at most
    /// `24 h + 6 h × ceil(log2(2a / (1 - a)))` on 6-hour epochs.
    Half,
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
    leak: InactivityLeak::Sixteenth,
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
    leak: InactivityLeak::Sixteenth,
};

/// The parameter relation the frozen-window retention of the second
/// hardening activation relies on (review LOW 10; `PowitState::apply_at`,
/// "Nothing else below it is ever read again"): a vote is includable for at
/// most one epoch (`vote_ttl <= epoch_len`, which also keeps every open
/// vote's target epoch within [`PowitState::evidence_epochs`]), and a newly
/// finalized checkpoint lies less than two epochs below the block that
/// finalizes it (`vote_ttl + checkpoint_interval < 2 * epoch_len`), so its
/// window starts within the first rule's `window_epochs + 2` horizon.
pub const fn params_keep_the_frozen_window(p: &PowitParams) -> bool {
    p.vote_ttl <= p.epoch_len && p.vote_ttl + p.checkpoint_interval < 2 * p.epoch_len
}

const _: () = assert!(params_keep_the_frozen_window(&MAINNET_PARAMS));
const _: () = assert!(params_keep_the_frozen_window(&TESTNET_PARAMS));

/// ObenBlock's witness-weight window (docs/DESIGN-obenblock.md §6.2): 112
/// epochs, 28 days of 6-hour epochs (GnB mainnet: 28 epochs, 7 days). To own
/// two thirds of `W` an attacker must out-mine the honest share work for
/// about four weeks.
pub const OBB_WINDOW_EPOCHS: u64 = 112;

/// `p` with ObenBlock's long window. The ban lasts as long as the window, as
/// on GnB (28 and 28, testnet 3 and 3), so a barred key's earlier share work
/// has left the window when the ban ends. The state then keeps
/// `OBB_WINDOW_EPOCHS + 2` epochs of share work and of links per key.
pub const fn obenblock_window(p: PowitParams) -> PowitParams {
    PowitParams { window_epochs: OBB_WINDOW_EPOCHS, ban_epochs: OBB_WINDOW_EPOCHS, ..p }
}

/// ObenBlock mainnet (`docs/DESIGN-obenblock.md` §5.2, §6.2): GnB mainnet's
/// clock and bounds with the half leak and the 112-epoch window and ban of
/// [`obenblock_window`]. The constant is the complete parameter set
/// [`params_for`] returns for [`ChainId::ObenBlockMainnet`], so no caller
/// can pick up GnB's 28-epoch window through it.
pub const OBENBLOCK_MAINNET_PARAMS: PowitParams =
    obenblock_window(PowitParams { leak: InactivityLeak::Half, ..MAINNET_PARAMS });

/// ObenBlock regtest: the short test clock (and window) with the half leak.
pub const OBENBLOCK_REGTEST_PARAMS: PowitParams = PowitParams { leak: InactivityLeak::Half, ..TESTNET_PARAMS };

const _: () = assert!(params_keep_the_frozen_window(&OBENBLOCK_MAINNET_PARAMS));
const _: () = assert!(params_keep_the_frozen_window(&OBENBLOCK_REGTEST_PARAMS));

/// The PoWit parameters of `chain`. ObenBlock mainnet uses the mainnet
/// clock with the half leak (docs/DESIGN-obenblock.md §5.2) and the
/// 112-epoch window (§6.2); its regtest keeps the short test clock and
/// window, with the half leak.
pub fn params_for(chain: ChainId) -> PowitParams {
    match chain {
        ChainId::Mainnet => MAINNET_PARAMS,
        ChainId::Testnet => TESTNET_PARAMS,
        ChainId::ObenBlockMainnet => OBENBLOCK_MAINNET_PARAMS,
        ChainId::ObenBlockRegtest => OBENBLOCK_REGTEST_PARAMS,
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

// ── Rules in force ───────────────────────────────────────────────────────────

/// The PoWit rules a block is checked under: before or from the second
/// hardening activation (module docs). A block's regime compares its header
/// height with the activation height ([`Regime::at`]); an attestation's
/// message version compares its *target* height instead
/// ([`Attestation::message_at`]), so a witness, which signs before any block
/// includes its vote, knows which message to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regime {
    /// Below the second hardening activation: the rules that produced the
    /// existing chain.
    V1,
    /// From the second hardening activation.
    Hardening2,
}

impl Regime {
    /// The regime of a block at `height` when the second hardening upgrade
    /// activates at `hardening2_height` (`activation::is_active_at`).
    pub fn at(height: u64, hardening2_height: u64) -> Regime {
        if activation::is_active_at(height, hardening2_height) { Regime::Hardening2 } else { Regime::V1 }
    }
}

// ── Checkpoints, attestations, equivocations ─────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: [u8; 32],
}

const DS_ATTEST: &[u8] = b"GNB-POWIT-v1/attest";
const DS_ATTEST_V2: &[u8] = b"GNB-POWIT-v2/attest";
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

/// The digest a witness signs for a link whose target is below the second
/// hardening activation (v1). It does not commit the witness key: PoWit
/// audit finding 1 (a leaf's signature verifies under every root its path
/// can be re-hashed to). Kept bit for bit for those targets.
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

/// The digest a witness signs for a link whose target is at or above the
/// second hardening activation (v2): v1's fields plus the witness's KES
/// public key, so a signature is valid for exactly one key.
///
/// ```text
/// SHA3-256( u32le(19) ‖ "GNB-POWIT-v2/attest" ‖ u32le(chain_id)
///           ‖ u8(depth) ‖ root[32]
///           ‖ u64le(source.height) ‖ source.hash[32]
///           ‖ u64le(target.height) ‖ target.hash[32] )             // 140-byte preimage
/// ```
///
/// Binding the key in the signed message is what every signature scheme
/// whose verification key is not fixed by the signature needs (Bitcoin's
/// BIP-340 commits the public key in the challenge for the same reason).
pub fn attestation_message_v2(chain: ChainId, witness: &KesPublic, source: &Checkpoint, target: &Checkpoint)
    -> [u8; 32]
{
    let mut h = Sha3_256::new();
    h.update((DS_ATTEST_V2.len() as u32).to_le_bytes());
    h.update(DS_ATTEST_V2);
    h.update(chain.to_le_bytes());
    h.update([witness.depth]);
    h.update(witness.root);
    h.update(source.height.to_le_bytes());
    h.update(source.hash);
    h.update(target.height.to_le_bytes());
    h.update(target.hash);
    h.finalize().into()
}

/// The message `witness` signs for `source -> target`: v2 iff the target
/// height is at or above `hardening2_height`.
pub fn attestation_message_at(chain: ChainId, hardening2_height: u64, witness: &KesPublic,
                              source: &Checkpoint, target: &Checkpoint) -> [u8; 32] {
    if activation::is_active_at(target.height, hardening2_height) {
        attestation_message_v2(chain, witness, source, target)
    } else {
        attestation_message(chain, source, target)
    }
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

    /// The message this attestation's signature must cover
    /// ([`attestation_message_at`]).
    pub fn message_at(&self, chain: ChainId, hardening2_height: u64) -> [u8; 32] {
        attestation_message_at(chain, hardening2_height, &self.witness, &self.source, &self.target)
    }

    /// [`Self::verify_signature_at`] under the process-wide second hardening
    /// height (`activation::hardening2_activation_height`).
    pub fn verify_signature(&self, chain: ChainId, p: &PowitParams, act: u64) -> bool {
        self.verify_signature_at(chain, p, act, activation::hardening2_activation_height())
    }

    /// Link shape + forward-secure signature by the target epoch's leaf over
    /// the message of the target's height ([`Self::message_at`]).
    pub fn verify_signature_at(&self, chain: ChainId, p: &PowitParams, act: u64, hardening2_height: u64) -> bool {
        let Some(e) = self.kes_epoch(p, act) else { return false };
        self.target.height > self.source.height
            && kes::verify(&self.witness, e, &self.message_at(chain, hardening2_height), &self.sig)
    }

    /// [`Self::sign_at`] under the process-wide second hardening height. A
    /// signer that is not a node (no chain id set) passes
    /// `activation::hardening2_activation_height_for_signer(chain)` to
    /// [`Self::sign_at`] instead.
    pub fn sign(chain: ChainId, source: Checkpoint, target: Checkpoint, signer: &KesSigner) -> Result<Self, String> {
        Self::sign_at(chain, activation::hardening2_activation_height(), source, target, signer)
    }

    /// Sign a link with a KES signer already evolved to the target's epoch,
    /// over the message of the target's height.
    pub fn sign_at(chain: ChainId, hardening2_height: u64, source: Checkpoint, target: Checkpoint,
                   signer: &KesSigner) -> Result<Self, String> {
        let witness = signer.public();
        let sig = signer.sign(&attestation_message_at(chain, hardening2_height, &witness, &source, &target))?;
        Ok(Attestation { source, target, witness, sig })
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
    /// [`Self::verify_at`] under the process-wide second hardening height.
    pub fn verify(&self, chain: ChainId, p: &PowitParams, act: u64) -> Result<KeyId, &'static str> {
        self.verify_at(chain, p, act, activation::hardening2_activation_height())
    }

    /// Both signatures valid under the same witness key (each over the
    /// message of its own target's height), and a double or surround vote.
    /// Context-free; whether a block may carry the proof is
    /// [`PowitState::apply_at`]'s question (the evidence epochs).
    pub fn verify_at(&self, chain: ChainId, p: &PowitParams, act: u64, hardening2_height: u64)
        -> Result<KeyId, &'static str>
    {
        if self.a.witness != self.b.witness {
            return Err("equivocation: different witnesses");
        }
        if self.a == self.b {
            return Err("equivocation: identical attestations");
        }
        if !self.a.verify_signature_at(chain, p, act, hardening2_height)
            || !self.b.verify_signature_at(chain, p, act, hardening2_height)
        {
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

/// A witness's clean exit (`docs/DESIGN-obenblock.md` §5.2): signed with the
/// KES leaf of `epoch` over `liveness::exit_message`. A block of epoch `E`
/// may carry it iff `epoch <= E <= epoch + 1` (`liveness::exit_epoch_ok`);
/// the key's weight then leaves `W` from epoch `E + 1`
/// ([`PowitState::apply_full`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessExit {
    pub witness: KesPublic,
    pub epoch: u64,
    pub sig: KesSignature,
}

impl WitnessExit {
    pub fn key_id(&self) -> KeyId {
        self.witness.witness_id()
    }

    /// The forward-secure signature of the leaf of `epoch` over the exit
    /// message of `chain_id` (raw u32 chain id: `liveness::exit_message_raw`).
    pub fn verify_signature(&self, chain_id: u32) -> bool {
        kes::verify(&self.witness, self.epoch, &super::liveness::exit_message_raw(chain_id, &self.witness, self.epoch),
                    &self.sig)
    }

    /// Sign an exit with a KES signer evolved to `epoch` (its current epoch).
    pub fn sign(chain_id: u32, signer: &KesSigner) -> Result<Self, String> {
        let witness = signer.public();
        let epoch = signer.epoch();
        let sig = signer.sign(&super::liveness::exit_message_raw(chain_id, &witness, epoch))?;
        Ok(WitnessExit { witness, epoch, sig })
    }

    /// Wire: u8 depth ‖ root[32] ‖ u64le epoch ‖ KES signature.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9_000);
        out.push(self.witness.depth);
        out.extend_from_slice(&self.witness.root);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        self.sig.write_wire(&mut out);
        out
    }

    pub fn read_wire(cur: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        let depth = read_fixed::<1>(cur)?[0];
        let root = read_array32(cur)?;
        let epoch = read_u64(cur)?;
        let sig = KesSignature::read_wire(cur)?;
        Ok(WitnessExit { witness: KesPublic { depth, root }, epoch, sig })
    }

    /// Unique id (gossip and pool dedup).
    pub fn id(&self) -> [u8; 32] {
        Sha3_256::digest(self.to_wire_bytes()).into()
    }
}

/// A pruned witness's return (PoCI, ObenBlock; `docs/DESIGN-obenblock-poci.md`
/// §4.1): signed with the KES leaf of `epoch` over [`poci::rejoin_message`].
/// A block of epoch `E` may carry it iff `epoch <= E <= epoch + 1`, the key
/// is pruned and has no rejoin pending; once the block is final, the key's
/// share work counts again from the next handoff ([`PowitState::apply_poci`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRejoin {
    pub witness: KesPublic,
    pub epoch: u64,
    pub sig: KesSignature,
}

impl WitnessRejoin {
    pub fn key_id(&self) -> KeyId {
        self.witness.witness_id()
    }

    /// The forward-secure signature of the leaf of `epoch` over the rejoin
    /// message of `chain_id`.
    pub fn verify_signature(&self, chain_id: u32) -> bool {
        kes::verify(&self.witness, self.epoch, &poci::rejoin_message(chain_id, &self.witness, self.epoch), &self.sig)
    }

    /// Sign a rejoin with a KES signer evolved to `epoch` (its current epoch).
    pub fn sign(chain_id: u32, signer: &KesSigner) -> Result<Self, String> {
        let witness = signer.public();
        let epoch = signer.epoch();
        let sig = signer.sign(&poci::rejoin_message(chain_id, &witness, epoch))?;
        Ok(WitnessRejoin { witness, epoch, sig })
    }

    /// Wire: u8 depth ‖ root[32] ‖ u64le epoch ‖ KES signature (an exit's layout).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9_000);
        out.push(self.witness.depth);
        out.extend_from_slice(&self.witness.root);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        self.sig.write_wire(&mut out);
        out
    }

    pub fn read_wire(cur: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        let depth = read_fixed::<1>(cur)?[0];
        let root = read_array32(cur)?;
        let epoch = read_u64(cur)?;
        let sig = KesSignature::read_wire(cur)?;
        Ok(WitnessRejoin { witness: KesPublic { depth, root }, epoch, sig })
    }

    /// Unique id (gossip and pool dedup).
    pub fn id(&self) -> [u8; 32] {
        Sha3_256::digest(self.to_wire_bytes()).into()
    }
}

/// Item tags of the PoCI format's membership list ([`PowitBody::write_wire_for`]).
const MEMBERSHIP_EXIT: u8 = 0;
const MEMBERSHIP_REJOIN: u8 = 1;

// ── The PoWit section of a block ─────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowitBody {
    pub shares: Vec<WitnessShare>,
    pub attestations: Vec<Attestation>,
    pub evidence: Vec<Equivocation>,
    /// Witness exits: on the wire and in the root only from the liveness
    /// activation ([`Self::write_wire_with`]); empty below it.
    #[serde(default)]
    pub exits: Vec<WitnessExit>,
    /// PoCI equivocation evidence (ObenBlock, `docs/DESIGN-obenblock-poci.md`
    /// §5): on the wire in place of `evidence` in the PoCI body format
    /// ([`BodyFormat`]); always empty on GnB, where `evidence` is used.
    #[serde(default)]
    pub poci_evidence: Vec<PociEvidence>,
    /// PoCI rejoin messages (ObenBlock, §4.1): in the PoCI format's
    /// membership list, after the exits ([`Self::write_wire_for`]); always
    /// empty on GnB.
    #[serde(default)]
    pub rejoins: Vec<WitnessRejoin>,
}

/// The encoding of a block's PoWit section: with the exits list (liveness
/// activation) and with PoCI evidence in place of GnB's equivocation proofs
/// (ObenBlock). An empty section encodes the same in every format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyFormat {
    pub exits: bool,
    pub poci: bool,
}

impl BodyFormat {
    /// GnB before the liveness activation: `PowitBody::write_wire`, bit for bit.
    pub const GNB: BodyFormat = BodyFormat { exits: false, poci: false };

    /// The format of a block at `height` on the node's chain.
    pub fn at(height: u64) -> Self {
        BodyFormat { exits: super::liveness::liveness_active_at(height), poci: poci_active() }
    }
}

/// Whether the node's chain runs PoCI (ObenBlock, from genesis).
pub fn poci_active() -> bool {
    PociParams::for_chain(super::node_chain_id()).is_some()
}

impl PowitBody {
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty() && self.attestations.is_empty() && self.evidence.is_empty() && self.exits.is_empty()
            && self.poci_evidence.is_empty() && self.rejoins.is_empty()
    }

    /// The section's encoding for a block where exits are (`with_exits`) or
    /// are not part of it: below the liveness activation the GnB encoding
    /// ([`Self::write_wire`], bit for bit), from it the same followed by
    /// `varint n ‖ exits`.
    pub fn write_wire_with(&self, out: &mut Vec<u8>, with_exits: bool) {
        self.write_wire(out);
        if with_exits {
            write_varint(out, self.exits.len() as u64);
            for x in &self.exits {
                out.extend_from_slice(&x.to_wire_bytes());
            }
        }
    }

    /// Inverse of [`Self::write_wire_with`].
    pub fn read_wire_with(cur: &mut std::io::Cursor<&[u8]>, with_exits: bool) -> Result<Self, String> {
        let mut b = Self::read_wire(cur)?;
        if with_exits {
            let n = read_count(cur, super::liveness::MAX_EXITS_PER_BLOCK, "exits")?;
            for _ in 0..n {
                b.exits.push(WitnessExit::read_wire(cur)?);
            }
        }
        Ok(b)
    }

    /// The section's encoding in `fmt`: [`Self::write_wire_with`] unless
    /// `fmt.poci`; with PoCI the evidence list holds `poci_evidence`
    /// (`varint n ‖ n × PociEvidence`) and `evidence` is not encoded (a PoCI
    /// block carries none: `PowitState::apply_poci`), and the exits list is
    /// the membership list `varint n ‖ n × (u8 tag ‖ item)`: the exits (tag
    /// 0, `WitnessExit`) then the rejoins (tag 1, `WitnessRejoin`), so an
    /// empty section is still the same bytes as GnB's. Without `fmt.exits`
    /// there is no membership list (and a block carries no rejoin).
    pub fn write_wire_for(&self, out: &mut Vec<u8>, fmt: BodyFormat) {
        if !fmt.poci {
            return self.write_wire_with(out, fmt.exits);
        }
        write_varint(out, self.shares.len() as u64);
        for s in &self.shares {
            out.extend_from_slice(&s.to_wire_bytes());
        }
        write_varint(out, self.attestations.len() as u64);
        for a in &self.attestations {
            out.extend_from_slice(&a.to_wire_bytes());
        }
        write_varint(out, self.poci_evidence.len() as u64);
        for e in &self.poci_evidence {
            out.extend_from_slice(&e.to_wire_bytes());
        }
        if fmt.exits {
            write_varint(out, (self.exits.len() + self.rejoins.len()) as u64);
            for x in &self.exits {
                out.push(MEMBERSHIP_EXIT);
                out.extend_from_slice(&x.to_wire_bytes());
            }
            for r in &self.rejoins {
                out.push(MEMBERSHIP_REJOIN);
                out.extend_from_slice(&r.to_wire_bytes());
            }
        }
    }

    /// Inverse of [`Self::write_wire_for`].
    pub fn read_wire_for(cur: &mut std::io::Cursor<&[u8]>, fmt: BodyFormat) -> Result<Self, String> {
        if !fmt.poci {
            return Self::read_wire_with(cur, fmt.exits);
        }
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
        let mut poci_evidence = Vec::with_capacity(n);
        for _ in 0..n {
            poci_evidence.push(PociEvidence::read_wire(cur)?);
        }
        let mut exits = Vec::new();
        let mut rejoins = Vec::new();
        if fmt.exits {
            let n = read_count(cur, super::liveness::MAX_EXITS_PER_BLOCK + MAX_REJOINS_PER_BLOCK, "membership items")?;
            for _ in 0..n {
                // Exits first, then rejoins: one encoding per body.
                match read_fixed::<1>(cur)?[0] {
                    MEMBERSHIP_EXIT if rejoins.is_empty() => {
                        if exits.len() == super::liveness::MAX_EXITS_PER_BLOCK {
                            return Err("exits: too many".into());
                        }
                        exits.push(WitnessExit::read_wire(cur)?);
                    }
                    MEMBERSHIP_REJOIN => {
                        if rejoins.len() == MAX_REJOINS_PER_BLOCK {
                            return Err("rejoins: too many".into());
                        }
                        rejoins.push(WitnessRejoin::read_wire(cur)?);
                    }
                    MEMBERSHIP_EXIT => return Err("membership items: an exit after a rejoin".into()),
                    t => return Err(format!("membership items: unknown tag {t}")),
                }
            }
        }
        Ok(PowitBody { shares, attestations, evidence: Vec::new(), exits, poci_evidence, rejoins })
    }

    /// [`Self::root`] of the encoding [`Self::write_wire_for`].
    pub fn root_for(&self, fmt: BodyFormat) -> [u8; 32] {
        let mut buf = Vec::new();
        self.write_wire_for(&mut buf, fmt);
        let mut h = Sha3_256::new();
        h.update(DS_BODY);
        h.update(&buf);
        h.finalize().into()
    }

    /// [`Self::root`] of the encoding [`Self::write_wire_with`].
    pub fn root_with(&self, with_exits: bool) -> [u8; 32] {
        let mut buf = Vec::new();
        self.write_wire_with(&mut buf, with_exits);
        let mut h = Sha3_256::new();
        h.update(DS_BODY);
        h.update(&buf);
        h.finalize().into()
    }

    /// GnB wire (no exits): varint n ‖ shares, varint n ‖ attestations,
    /// varint n ‖ evidence. Exits are not part of it.
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
        Ok(PowitBody { shares, attestations, evidence, exits: Vec::new(), poci_evidence: Vec::new(), rejoins: Vec::new() })
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
    /// Witness exits (from the liveness activation only).
    pub exits: &'a [WitnessExit],
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
    /// Witnesses that exited: key -> first epoch whose `W` leaves them out
    /// (liveness activation only). A key has an entry only while it has share
    /// work in `epoch_work`. Not part of the serde encoding, so the stored
    /// encoding of every GnB state is unchanged; the node stores it beside
    /// the state (`node/src/powit.rs`).
    #[serde(skip)]
    pub exited: BTreeMap<KeyId, u64>,
    /// PoCI (ObenBlock, `docs/DESIGN-obenblock-poci.md`): the configuration
    /// in force, the ones before it and the bans; `None` on GnB and during
    /// the PoCI launch bootstrap (§9). Not part of the serde encoding, like
    /// `exited`: the node stores it beside the state.
    #[serde(skip)]
    pub poci: Option<PociState>,
    /// The growth cap (ObenBlock, `docs/DESIGN-obenblock.md` §6.3): the
    /// credit ledger of the configuration in force and the first-block bits
    /// the next handoff needs; `None` on GnB. Not part of the serde encoding,
    /// like `poci`: the node stores it beside the state.
    #[serde(skip)]
    pub cap: Option<CapState>,
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
            exited: BTreeMap::new(),
            poci: None,
            cap: None,
        }
    }

    pub fn is_banned(&self, key: &KeyId, epoch: u64) -> bool {
        self.banned.get(key).is_some_and(|&until| epoch < until)
    }

    /// Whether `key` exited before `epoch` (it is not a member of `W(epoch)`).
    pub fn has_exited(&self, key: &KeyId, epoch: u64) -> bool {
        self.exited.get(key).is_some_and(|&from| from <= epoch)
    }

    /// Witness set for `epoch` under the rules before the second hardening
    /// activation ([`Regime::V1`]): (key, weight), heaviest first, at most
    /// `max_witnesses`, banned keys excluded, decay applied. Code that runs
    /// for a block (or a next block) uses [`Self::witness_set_in`] with that
    /// block's regime.
    pub fn witness_set(&self, p: &PowitParams, epoch: u64) -> Vec<(KeyId, u128)> {
        self.witness_set_in(p, epoch, Regime::V1)
    }

    /// Witness set for `epoch` under `regime`: (key, weight), heaviest first
    /// (ties by key), banned keys excluded, decay applied. Weight = the share
    /// work credited to the key in epochs `epoch-1-window ..= epoch-2`.
    /// [`Regime::V1`] keeps the `max_witnesses` heaviest;
    /// [`Regime::Hardening2`] keeps every key with weight (PoWit finding 4:
    /// the cap let a minority split over many keys own the set).
    ///
    /// Under [`Regime::Hardening2`] the window is the one of
    /// [`h2_window_epoch`](Self::h2_window_epoch): finalized history (PoWit
    /// finding 3), frozen while finality lags.
    pub fn witness_set_in(&self, p: &PowitParams, epoch: u64, regime: Regime) -> Vec<(KeyId, u128)> {
        let mut v = match regime {
            Regime::V1 => self.window_weights(p, epoch),
            Regime::Hardening2 => self.window_weights_at(p, self.h2_window_epoch(p, epoch), epoch),
        };
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        if regime == Regime::V1 {
            v.truncate(p.max_witnesses);
        }
        v
    }

    /// Every unbarred key with positive decayed window weight for `epoch`,
    /// in key order (`W(epoch)` before sorting and capping).
    fn window_weights(&self, p: &PowitParams, epoch: u64) -> Vec<(KeyId, u128)> {
        self.window_weights_at(p, epoch, epoch)
    }

    /// The window weights of `window_epoch`'s share window with bars applied
    /// at `bar_epoch` (the epoch the set is used for; under
    /// [`Regime::Hardening2`] the window may be an earlier, frozen one).
    fn window_weights_at(&self, p: &PowitParams, window_epoch: u64, bar_epoch: u64) -> Vec<(KeyId, u128)> {
        let epoch = window_epoch;
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
        total
            .into_iter()
            .filter(|(k, _)| !self.is_banned(k, bar_epoch) && !self.has_exited(k, bar_epoch))
            .map(|(k, w)| (k, decayed_with(p.leak, w, self.decay.get(&k).copied().unwrap_or(0))))
            .filter(|(_, w)| *w > 0)
            .collect()
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

    /// The epoch whose share window `W(epoch)` reads under
    /// [`Regime::Hardening2`]: [`finalized_window_epoch`](Self::finalized_window_epoch),
    /// except that a frozen window with no share work left in it (possible
    /// only across the upgrade, for a chain whose finality had stalled long
    /// enough for the first rule to prune that window, or one whose shares
    /// all fell in the epoch the frozen window drops) gives way to `epoch`'s
    /// own window, so finality can always start again; a frozen window is
    /// never empty on a chain that finalized with its members (bans aside).
    ///
    /// Cost (review MEDIUM 5): the emptiness test stops at the first unbarred
    /// key with work ([`window_has_weight`](Self::window_has_weight)); it
    /// used to aggregate the whole window on every membership lookup.
    pub fn h2_window_epoch(&self, p: &PowitParams, epoch: u64) -> u64 {
        let anchored = self.finalized_window_epoch(p, epoch);
        if anchored != epoch && !self.window_has_weight(p, anchored, epoch) {
            epoch
        } else {
            anchored
        }
    }

    /// `!self.window_weights_at(p, window_epoch, bar_epoch).is_empty()`,
    /// stopping at the first member: some key not barred at `bar_epoch` has
    /// positive work in the window (its decayed sum is then positive too:
    /// [`decayed`] keeps every positive weight positive).
    fn window_has_weight(&self, p: &PowitParams, window_epoch: u64, bar_epoch: u64) -> bool {
        if window_epoch < 2 {
            return false;
        }
        let hi = window_epoch - 2;
        let lo = (window_epoch - 1).saturating_sub(p.window_epochs);
        self.epoch_work.range(lo..=hi)
            .any(|(_, m)| m.iter().any(|(k, w)| *w > 0 && !self.is_banned(k, bar_epoch)))
    }

    /// The witness set a block uses for a target in `epoch`: the first rule
    /// (`from_finalized == false`, [`Regime::V1`]) or the second hardening
    /// rule ([`Regime::Hardening2`]: every key with weight in the window of
    /// [`h2_window_epoch`](Self::h2_window_epoch), finalized history).
    pub fn witness_set_at(&self, p: &PowitParams, epoch: u64, from_finalized: bool) -> Vec<(KeyId, u128)> {
        self.witness_set_in(p, epoch, if from_finalized { Regime::Hardening2 } else { Regime::V1 })
    }

    /// [`witness_set_in`](Self::witness_set_in) for a block at header height
    /// `block_height` under the process-wide second hardening height
    /// (`activation::hardening2_activation_height`): what every producer
    /// (pool admission, the witness duty, templates through `apply`, RPC)
    /// reads for the block it builds or admits for.
    pub fn witness_set_for_block(&self, p: &PowitParams, epoch: u64, block_height: u64) -> Vec<(KeyId, u128)> {
        self.witness_set_in(p, epoch, Regime::at(block_height, activation::hardening2_activation_height()))
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

    /// `key`'s weight in `W(epoch)` under [`Regime::Hardening2`] (`None` if it
    /// is not a member), without building the set: the sum of its window
    /// work, decayed, if positive and the key is not barred at `epoch`.
    ///
    /// The window is the one of [`h2_window_epoch`](Self::h2_window_epoch)
    /// (finalized history, PoWit finding 3); bars apply at `epoch`.
    pub fn member_weight_h2(&self, p: &PowitParams, epoch: u64, key: &KeyId) -> Option<u128> {
        if self.is_banned(key, epoch) || self.has_exited(key, epoch) {
            return None;
        }
        let we = self.h2_window_epoch(p, epoch);
        if we < 2 {
            return None;
        }
        let hi = we - 2;
        let lo = (we - 1).saturating_sub(p.window_epochs);
        let w = self.epoch_work.range(lo..=hi)
            .filter_map(|(_, m)| m.get(key))
            .fold(0u128, |acc, w| acc.saturating_add(*w));
        let w = decayed_with(p.leak, w, self.decay.get(key).copied().unwrap_or(0));
        (w > 0).then_some(w)
    }

    /// Total weight of `W(epoch)` under [`Regime::Hardening2`]: the
    /// justification threshold is two thirds of it.
    pub fn total_weight_h2(&self, p: &PowitParams, epoch: u64) -> u128 {
        self.window_weights_at(p, self.h2_window_epoch(p, epoch), epoch).iter()
            .fold(0u128, |acc, (_, w)| acc.saturating_add(*w))
    }

    /// The epochs whose witness sets a block of PoWit epoch `epoch` checks
    /// an equivocation proof's key against under [`Regime::Hardening2`]:
    /// `epoch-1 ..= epoch+1`. They are exactly the sets the block's state can
    /// compute (it keeps `window + 2` epochs of share work), they hold the
    /// target epoch of every vote the chain can still include (`vote_ttl <=
    /// epoch_len`), and a key in one of them is a voter now, was one for the
    /// open votes, or is about to be one.
    pub fn evidence_epochs(epoch: u64) -> std::ops::RangeInclusive<u64> {
        epoch.saturating_sub(1)..=epoch + 1
    }

    /// Whether a block of PoWit epoch `epoch` (after its epoch step) may
    /// carry an equivocation proof against `key` under
    /// [`Regime::Hardening2`]: `key` is a member of `W(e)` for some `e` in
    /// [`Self::evidence_epochs`]. Ethereum's slashing likewise accepts
    /// evidence only against a validator that is slashable at the current
    /// epoch (`is_slashable_validator`); the old rule accepted any key.
    pub fn may_be_proven_h2(&self, p: &PowitParams, epoch: u64, key: &KeyId) -> bool {
        Self::evidence_epochs(epoch).any(|e| self.member_weight_h2(p, e, key).is_some())
    }

    /// [`Self::apply_at`] under the process-wide second hardening height
    /// (`activation::hardening2_activation_height`).
    pub fn apply(&self, p: &PowitParams, chain: ChainId, b: &BlockInput<'_>, view: &dyn ChainView)
        -> Result<PowitState, String>
    {
        self.apply_at(p, chain, activation::hardening2_activation_height(), b, view)
    }

    /// Apply one block (height > activation) on top of its selected parent's
    /// state, under the rules of its height (`Regime::at(b.height,
    /// hardening2_height)`; attestation messages by their target heights).
    /// From the second hardening height every witness set the block reads
    /// (attester weights, justification totals, inactivity-decay membership,
    /// equivocation evidence) is uncapped (finding 4) and comes from
    /// finalized history ([`Self::h2_window_epoch`], finding 3), and the
    /// epochs of the frozen window are kept. Below it this is the first
    /// rule, bit for bit. Any rule violation makes the block invalid.
    pub fn apply_at(&self, p: &PowitParams, chain: ChainId, hardening2_height: u64, b: &BlockInput<'_>,
                    view: &dyn ChainView) -> Result<PowitState, String>
    {
        self.apply_full(p, chain, hardening2_height, super::liveness::liveness_activation_height(), b, view)
    }

    /// [`Self::apply_at`] with an explicit liveness activation height. From `liveness_height` a block may
    /// carry witness exits (`b.exits`), checked after the equivocation proofs
    /// and before the shares: at most `liveness::MAX_EXITS_PER_BLOCK`; each
    /// signed for this block's epoch or the one before; by a key with share
    /// work in the kept epochs that has not exited (nor earlier in the block);
    /// signature last. It records `exited[k] = epoch + 1`. While the record
    /// lives, shares credited to `k` are invalid and an equivocation proof
    /// against `k` stays valid; the record goes at the first epoch boundary
    /// that leaves `k` without share work.
    pub fn apply_full(&self, p: &PowitParams, chain: ChainId, hardening2_height: u64, liveness_height: u64,
                      b: &BlockInput<'_>, view: &dyn ChainView) -> Result<PowitState, String>
    {
        if let Some(pp) = PociParams::for_chain(chain) {
            // ObenBlock: PoCI from genesis (its evidence comes through `apply_block`).
            return self.apply_poci(&pp, p, chain, liveness_height, b, None, PociItems::default(), view,
                                   &mut ObbConfigWeights::default());
        }
        let exits_on = activation::is_active_at(b.height, liveness_height);
        if !b.exits.is_empty() && !exits_on {
            return Err("powit: witness exit before the liveness activation".into());
        }
        if b.exits.len() > super::liveness::MAX_EXITS_PER_BLOCK {
            return Err("powit: too many witness exits".into());
        }
        let regime = Regime::at(b.height, hardening2_height);
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
        let h2 = regime == Regime::Hardening2;
        // Message versions in this block: below the activation every message
        // is v1 (the old rule, also for an equivocation's links that target
        // a later height); from it, by each attestation's target height.
        let msg_h2 = if h2 { hardening2_height } else { activation::NEVER };
        let mut s = self.clone();
        let epoch = p.epoch(act, b.height);

        // ── Epoch boundary: inactivity decay, then prune old history ──────
        if epoch > s.epoch {
            for e in s.epoch..epoch {
                let stalled = b.height.saturating_sub(s.finalized_at) >= p.leak_after_epochs * p.epoch_len;
                if stalled {
                    let members: Vec<KeyId> = s.witness_set_in(p, e, regime).into_iter().map(|(k, _)| k).collect();
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
            if let Some((lo, hi)) = h2.then(|| s.finalized_window(p)).flatten() {
                // Hardening 2 (finding 3): the frozen window, older than the
                // first rule's horizon while finality lags. Nothing else below
                // it is ever read again: a newly finalized checkpoint lies at
                // most `vote_ttl + checkpoint_interval` (under two epochs)
                // below the block, so its window starts within the horizon.
                kept.extend(std::mem::take(&mut s.epoch_work).into_iter().filter(|(e, _)| (lo..=hi).contains(e)));
            }
            s.epoch_work = kept;
            if h2 || !s.exited.is_empty() {
                let live: BTreeSet<KeyId> = s.epoch_work.values().flat_map(|m| m.keys().copied()).collect();
                if h2 {
                    // Every share key with weight is a member (and decays while
                    // finality stalls): a decay entry outlives the key's work
                    // only until here, so `decay` holds at most the keys of
                    // `epoch_work` instead of every key a stall ever touched.
                    s.decay.retain(|k, _| live.contains(k));
                }
                // An exit record lives while its key has work (bounded the same way).
                s.exited.retain(|k, _| live.contains(k));
            }
            s.banned.retain(|_, until| *until > epoch);
            let link_floor = b.height.saturating_sub((p.window_epochs + 2) * p.epoch_len);
            for v in s.links.values_mut() {
                v.retain(|(_, th, _)| *th >= link_floor);
            }
            s.links.retain(|_, v| !v.is_empty());
        }

        // ── Equivocation proofs ──────────────────────────────────────────
        for ev in b.evidence {
            let k = if h2 {
                // PoWit finding 1: only against a witness of the evidence
                // epochs, checked before the two signatures.
                if ev.a.witness != ev.b.witness {
                    return Err("powit: equivocation: different witnesses".into());
                }
                let k = ev.a.key_id();
                if s.is_banned(&k, epoch) {
                    return Err("powit: equivocation for an already barred key".into());
                }
                // An exited witness stays provable while its record lives.
                if !s.may_be_proven_h2(p, epoch, &k) && !s.exited.contains_key(&k) {
                    return Err("powit: equivocation proof against a key that is not a member of the \
                                witness sets of epochs E-1..=E+1".into());
                }
                ev.verify_at(chain, p, act, msg_h2).map_err(|e| format!("powit: {e}"))?
            } else {
                ev.verify_at(chain, p, act, msg_h2).map_err(|e| format!("powit: {e}"))?
            };
            if s.is_banned(&k, epoch) {
                return Err("powit: equivocation for an already barred key".into());
            }
            s.banned.insert(k, epoch + p.ban_epochs);
            for votes in s.votes.values_mut() {
                votes.remove(&k);
            }
        }

        // ── Witness exits (liveness activation) ──────────────────────────
        for x in b.exits {
            if !super::liveness::exit_epoch_ok(epoch, x.epoch) {
                return Err("powit: witness exit not signed for this block's epoch or the one before".into());
            }
            let k = x.key_id();
            if s.exited.contains_key(&k) {
                return Err("powit: witness already exited".into());
            }
            if !s.epoch_work.values().any(|m| m.contains_key(&k)) {
                return Err("powit: witness exit by a key without share work".into());
            }
            if !x.verify_signature(chain.to_u32()) {
                return Err("powit: invalid witness exit signature (KES leaf must be the exit's epoch)".into());
            }
            s.exited.insert(k, epoch + 1);
        }

        // ── Shares: custody work for the current epoch ───────────────────
        for (k, w) in b.share_work {
            if s.is_banned(k, epoch) {
                return Err("powit: share paid to a barred key".into());
            }
            if s.exited.contains_key(k) {
                return Err("powit: share credited to a witness that exited".into());
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
            let weight = if h2 {
                s.member_weight_h2(p, te, &k)
            } else {
                s.witness_set(p, te).into_iter().find(|(m, _)| *m == k).map(|(_, w)| w)
            }
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
            if !a.verify_signature_at(chain, p, act, msg_h2) {
                return Err("powit: invalid attestation signature (KES leaf must be the target's epoch)".into());
            }
            s.votes.entry(t).or_default().insert(k, weight);
            s.links.entry(k).or_default().push((a.source.height, t.height, t.hash));
            s.active_this_epoch.insert(k);
        }

        // ── Justification and finality ───────────────────────────────────
        let mut newly: Option<Checkpoint> = None;
        for (t, votes) in &s.votes {
            // From hardening 2 two thirds of ALL the window weight (finding 4).
            let total: u128 = if h2 {
                s.total_weight_h2(p, p.epoch(act, t.height))
            } else {
                s.witness_set(p, p.epoch(act, t.height)).iter().map(|(_, w)| *w).sum()
            };
            if total == 0 {
                continue;
            }
            let got: u128 = if h2 {
                votes.values().fold(0u128, |acc, w| acc.saturating_add(*w))
            } else {
                votes.values().sum()
            };
            if two_thirds(got, total) && t.height > s.justified.height
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

/// The PoCI items of a block (ObenBlock, `PowitBody::poci_evidence` and
/// `PowitBody::rejoins`), beside [`BlockInput`]. GnB blocks carry none.
#[derive(Clone, Copy, Debug, Default)]
pub struct PociItems<'a> {
    pub evidence: &'a [PociEvidence],
    pub rejoins: &'a [WitnessRejoin],
}

impl<'a> PociItems<'a> {
    pub fn of(body: &'a PowitBody) -> Self {
        PociItems { evidence: &body.poci_evidence, rejoins: &body.rejoins }
    }

    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty() && self.rejoins.is_empty()
    }
}

/// The configuration weights ObenBlock runs with ([`ConfigWeights`]): the
/// growth cap of DESIGN-obenblock.md §6.3 ([`GrowthCapWeights`]).
pub type ObbConfigWeights = GrowthCapWeights;

impl PowitState {
    /// One block under the rules of `chain`: PoCI on ObenBlock
    /// ([`Self::apply_poci`] with the block's compact `bits`, its PoCI items
    /// and the chain's configuration weights, [`ObbConfigWeights`], the
    /// growth cap); PoWit on GnB ([`Self::apply_full`]), where a block
    /// carries no PoCI item and `bits` are not used.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_block(&self, p: &PowitParams, chain: ChainId, hardening2_height: u64, liveness_height: u64,
                       b: &BlockInput<'_>, bits: u32, poci: PociItems<'_>, view: &dyn ChainView)
        -> Result<PowitState, String>
    {
        match PociParams::for_chain(chain) {
            Some(pp) => self.apply_poci(&pp, p, chain, liveness_height, b, Some(bits), poci, view,
                                        &mut ObbConfigWeights::default()),
            None if !poci.evidence.is_empty() => Err("powit: PoCI evidence on a chain without PoCI".into()),
            None if !poci.rejoins.is_empty() => Err("powit: PoCI rejoin on a chain without PoCI".into()),
            None => self.apply_full(p, chain, hardening2_height, liveness_height, b, view),
        }
    }

    /// The PoCI configuration in force, if any (ObenBlock after the launch
    /// bootstrap).
    pub fn poci_config(&self) -> Option<&std::sync::Arc<poci::Configuration>> {
        self.poci.as_ref().map(PociState::config)
    }

    /// Whether `key` is left out of `C_epoch` (PoCI): banned, pruned for
    /// absence (§4.1) or exited by `epoch`. What a [`ConfigWeights`] provider
    /// excludes in every epoch a handoff covers (the growth cap's exclusions).
    pub fn poci_excluded_at(&self, pp: &PociParams, key: &KeyId, epoch: u64) -> bool {
        self.has_exited(key, epoch) || self.poci.as_ref().is_some_and(|st| st.excluded_at(pp, key, epoch))
    }

    /// One block under PoCI (`docs/DESIGN-obenblock-poci.md`; ObenBlock, PoWit
    /// from height 0). What differs from PoWit ([`Self::apply_full`]):
    ///
    /// - **Launch** (§9): the first `bootstrap_epochs` epochs are PoW only (no
    ///   votes, no evidence, no rejoins). The first block of epoch
    ///   `bootstrap_epochs` makes the slot opening it justified and final and
    ///   puts `C_4` in force (weights from `weights`, the history below that
    ///   slot).
    /// - **Votes** name the configuration in force: an attestation's signature
    ///   covers the v3 message with its `config_id`
    ///   ([`Attestation::verify_signature_v3`]); its weight is the registry's.
    ///   A key outside the configuration cannot vote. Every included vote is
    ///   recorded for absence pruning (`included_at = b.height + 1`).
    /// - **Strict quorum** of the configuration's frozen total ([`poci::quorum`],
    ///   `3 got > 2 total`); Casper FFG otherwise ([`poci::ffg_step`]).
    /// - **Handoff** (§4, §4.1): finalizing `F` with `epoch(F) = x` above the
    ///   configuration's epoch starts the pending bans and ends the prunings
    ///   of the pending rejoins that `F` finalizes, prunes the keys of the
    ///   configuration absent from the finalized history of the last
    ///   `PRUNE_AFTER` epochs ([`PociState::begin_handoff`]), and puts `C_x`
    ///   in force from `weights` for `F`, without the keys banned, pruned or
    ///   exited at `x` ([`PociState::enter`]).
    /// - **Proof of Corruption** (§5): `poci.evidence` ([`PociState::admit_evidence`],
    ///   included at `b.height + 1` in the ledger's convention); GnB's
    ///   `evidence` is refused. Nothing in force changes.
    /// - **Rejoins** (§4.1): `poci.rejoins`, at most
    ///   [`MAX_REJOINS_PER_BLOCK`] ([`PociState::admit_rejoin`]; signature last).
    /// - **No inactivity leak**: absence never changes a weight in force
    ///   (`decay` and `banned` stay empty). Exits, bans and pruning take effect
    ///   at the next handoff.
    /// - **Growth cap** (DESIGN-obenblock.md §6.3): `bits` are the block's
    ///   compact bits; the first block of each epoch on the chain records
    ///   them (`G_min` of that epoch; `None`, as from [`Self::apply_full`],
    ///   records nothing and that epoch's `G_min` is 0). Share work is kept
    ///   from the epoch the next handoff starts at (`ledger.epoch - 1`) even
    ///   past the window, so a handoff after a long finality stall still
    ///   reads the finalized history it needs.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_poci(&self, pp: &PociParams, p: &PowitParams, chain: ChainId, liveness_height: u64,
                      b: &BlockInput<'_>, bits: Option<u32>, poci: PociItems<'_>, view: &dyn ChainView,
                      weights: &mut dyn ConfigWeights) -> Result<PowitState, String>
    {
        if self.activation != 0 {
            return Err("powit: PoCI runs PoWit from height 0".into());
        }
        if pp.chain_id != chain.to_u32() || pp.epoch_len != p.epoch_len || pp.checkpoint_interval != p.checkpoint_interval
            || pp.vote_ttl != p.vote_ttl
        {
            return Err("powit: PoCI parameters do not match the chain's PoWit parameters".into());
        }
        let exits_on = activation::is_active_at(b.height, liveness_height);
        if !b.exits.is_empty() && !exits_on {
            return Err("powit: witness exit before the liveness activation".into());
        }
        if !poci.rejoins.is_empty() && !exits_on {
            return Err("powit: PoCI rejoin before the liveness activation (no membership list)".into());
        }
        if b.exits.len() > super::liveness::MAX_EXITS_PER_BLOCK {
            return Err("powit: too many witness exits".into());
        }
        if poci.rejoins.len() > MAX_REJOINS_PER_BLOCK {
            return Err("powit: too many PoCI rejoins".into());
        }
        if !b.evidence.is_empty() {
            return Err("powit: PoWit equivocation proofs on a PoCI chain (PoCI evidence names its configuration)".into());
        }
        if b.attestations.len() > p.max_attestations_per_block {
            return Err("powit: too many attestations".into());
        }
        if poci.evidence.len() > p.max_evidence_per_block {
            return Err("powit: too many equivocation proofs".into());
        }
        let mut s = self.clone();
        let epoch = p.epoch(0, b.height);
        // Where this block's items sit in the ledger (module docs of `poci`, "Heights").
        let included_at = b.height + 1;
        if s.cap.is_none() {
            if s.poci.is_some() {
                return Err("powit: PoCI state without its growth cap ledger".into());
            }
            s.cap = Some(CapState::default());
        }
        let cap_from = s.cap.as_ref().map_or(0, |c| c.ledger.epoch().saturating_sub(1));

        // ── Epoch boundary: prune old history (no inactivity decay) ───────
        if epoch > s.epoch {
            s.active_this_epoch.clear();
            s.epoch = epoch;
            let keep_from = epoch.saturating_sub(p.window_epochs + 2).min(cap_from);
            s.epoch_work = s.epoch_work.split_off(&keep_from);
            if !s.exited.is_empty() {
                let live: BTreeSet<KeyId> = s.epoch_work.values().flat_map(|m| m.keys().copied()).collect();
                s.exited.retain(|k, _| live.contains(k));
            }
            let link_floor = b.height.saturating_sub((p.window_epochs + 2) * p.epoch_len);
            for v in s.links.values_mut() {
                v.retain(|(_, th, _)| *th >= link_floor);
            }
            s.links.retain(|_, v| !v.is_empty());
            if let Some(st) = s.poci.as_mut() {
                st.trim_seen(epoch);
            }
        }

        s.cap.as_mut().expect("set above").note_block(epoch, bits);

        // ── Launch (§9) ──────────────────────────────────────────────────
        if s.poci.is_none() && epoch >= pp.bootstrap_epochs {
            let height = pp.opening(pp.bootstrap_epochs);
            let hash = view.selected_at(height).ok_or("powit: PoCI launch checkpoint is not on the selected chain")?;
            let cp = Checkpoint { height, hash };
            let candidates = weights.weights(&mut s, pp, pp.bootstrap_epochs, &cp)?;
            let w: BTreeMap<KeyId, u128> = candidates.into_iter()
                .filter(|(k, _)| !s.has_exited(k, pp.bootstrap_epochs)).collect();
            s.poci = Some(PociState::launch(pp, &w).map_err(|e| format!("powit: {e}"))?);
            s.justified = cp;
            s.finalized = cp;
            s.finalized_at = b.height;
            s.votes.clear();
        }
        if s.poci.is_none() && (!b.attestations.is_empty() || !poci.is_empty()) {
            return Err("powit: PoCI launch bootstrap: no finality votes, evidence or rejoins before its first \
                        configuration".into());
        }

        // ── Proof of Corruption ──────────────────────────────────────────
        let finalized_height = s.finalized.height;
        for ev in poci.evidence {
            let st = s.poci.as_mut().expect("checked above");
            let (va, vb) = ev.votes();
            st.admit_evidence(pp, included_at, finalized_height, &va, &vb).map_err(|e| format!("powit: {e}"))?;
        }

        // ── Witness exits (as PoWit; they leave at the next handoff) ─────
        for x in b.exits {
            if !super::liveness::exit_epoch_ok(epoch, x.epoch) {
                return Err("powit: witness exit not signed for this block's epoch or the one before".into());
            }
            let k = x.key_id();
            if s.exited.contains_key(&k) {
                return Err("powit: witness already exited".into());
            }
            if !s.epoch_work.values().any(|m| m.contains_key(&k)) {
                return Err("powit: witness exit by a key without share work".into());
            }
            if !x.verify_signature(chain.to_u32()) {
                return Err("powit: invalid witness exit signature (KES leaf must be the exit's epoch)".into());
            }
            s.exited.insert(k, epoch + 1);
        }

        // ── Rejoins (§4.1): back from the handoff that finalizes them ────
        for r in poci.rejoins {
            let st = s.poci.as_mut().expect("checked above");
            st.admit_rejoin(included_at, finalized_height, epoch, &r.key_id(), r.epoch, || r.verify_signature(pp.chain_id))
                .map_err(|e| format!("powit: {e}"))?;
        }

        // ── Shares ───────────────────────────────────────────────────────
        for (k, w) in b.share_work {
            if s.poci.as_ref().is_some_and(|st| st.banned_at(pp, k, epoch)) {
                return Err("powit: share paid to a barred key".into());
            }
            if s.exited.contains_key(k) {
                return Err("powit: share credited to a witness that exited".into());
            }
            let e = s.epoch_work.entry(epoch).or_default().entry(*k).or_insert(0);
            *e = e.saturating_add(*w);
        }

        let Some(config) = s.poci_config().cloned() else { return Ok(s) };

        // ── Attestations: v3 votes under the configuration in force ──────
        let config_id = config.id();
        let mut seen_in_block: BTreeSet<(KeyId, Checkpoint)> = BTreeSet::new();
        for a in b.attestations {
            let k = a.key_id();
            let t = a.target;
            if !pp.is_slot(t.height) || t.height > b.height {
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
            let weight = config.weight(&k).ok_or("powit: attester is not in the PoCI configuration in force")?;
            if !seen_in_block.insert((k, t)) || s.votes.get(&t).is_some_and(|v| v.contains_key(&k)) {
                return Err("powit: duplicate attestation".into());
            }
            if let Some(hist) = s.links.get(&k) {
                for &(sh, th, thash) in hist {
                    let earlier = Checkpoint { height: th, hash: thash };
                    if poci::conflict(sh, &earlier, a.source.height, &t).is_some() {
                        return Err("powit: attestation conflicts with this key's earlier vote".into());
                    }
                }
            }
            if !a.verify_signature_v3(pp, &config_id) {
                return Err("powit: invalid attestation signature (v3 message of the configuration in force, \
                            KES leaf of the target's epoch)".into());
            }
            s.votes.entry(t).or_default().insert(k, weight);
            s.links.entry(k).or_default().push((a.source.height, t.height, t.hash));
            s.active_this_epoch.insert(k);
            s.poci.as_mut().expect("in force").record_vote(pp, &k, included_at);
        }

        // ── Justification, finality and handoff ──────────────────────────
        let mut newly: Option<Checkpoint> = None;
        for (t, votes) in &s.votes {
            let got = votes.values().fold(0u128, |acc, w| acc.saturating_add(*w));
            if config.quorum(got) && t.height > s.justified.height && newly.is_none_or(|n| t.height > n.height) {
                newly = Some(*t);
            }
        }
        if let Some(t) = newly {
            let step = poci::ffg_step(pp, &mut s.justified, &t, true);
            if let Some(f) = step.finalized {
                s.finalized = f;
                s.finalized_at = b.height;
                if let Some(x) = s.poci.as_mut().expect("in force").begin_handoff(pp, &f) {
                    let candidates = weights.weights(&mut s, pp, x, &f)?;
                    let exited: BTreeSet<KeyId> =
                        candidates.keys().filter(|k| s.has_exited(k, x)).copied().collect();
                    s.poci.as_mut().expect("in force").enter(pp, x, &candidates, &|k: &KeyId| exited.contains(k))
                        .map_err(|e| format!("powit: {e}"))?;
                }
            }
            s.votes.clear();
        }
        s.votes.retain(|t, _| b.height <= t.height + p.vote_ttl);
        Ok(s)
    }
}

/// The candidate weights of a new PoCI configuration `C_epoch`, computed
/// from the chain's state when `finalized` (the checkpoint whose
/// finalization hands off, or the launch checkpoint) is final.
///
/// Contract (B2, DESIGN-obenblock-poci.md §4 and §4.1):
///
/// - `state.poci` is the ledger in the middle of the handoff: `config()` is
///   still `C_e`, the configuration being replaced (the growth cap's
///   `W = total(C_{x-1})` when no epoch is skipped), and the bans started,
///   rejoins ended and keys pruned by this handoff are already recorded, so
///   [`PowitState::poci_excluded_at`] answers for every epoch `e < y <= epoch`
///   the handoff covers (the growth cap runs one step per such epoch and
///   gives an excluded key no new credit there). At the launch `state.poci`
///   is `None`.
/// - Only finalized history may be read: share work of epochs `< epoch` (all
///   below `finalized`, which lies in `epoch`), never the blocks above it.
/// - Return every key with weight, the excluded ones included: the ledger
///   leaves out the keys banned, pruned or exited at `epoch`, and forgets a
///   pruned key the provider gives no weight.
/// - The provider may update the part of `state` it derives the weights
///   from (the growth cap's credit ledger, [`GrowthCapWeights`]): it runs
///   exactly once per launch or handoff, on the state of the block that
///   performs it.
pub trait ConfigWeights {
    fn weights(&mut self, state: &mut PowitState, params: &PociParams, epoch: u64, finalized: &Checkpoint)
        -> Result<BTreeMap<KeyId, u128>, String>;
}

/// The consensus provider on ObenBlock: the growth cap of DESIGN-obenblock.md
/// §6.3 ([`growth_cap`], reference `reference/obb_growth_cap.py`). It runs
/// the cap step for every epoch from the ledger's (the configuration in
/// force) to `epoch`, from the finalized history of the state: share work
/// of epoch `n = x - 2` (`epoch_work`), the first-block bits of `n`
/// (`G_min`), and the keys excluded at each `x`
/// ([`PowitState::poci_excluded_at`]: banned, pruned or exited at `x`; the
/// bans and prunings this handoff starts are already in the ledger, see
/// [`ConfigWeights`]). An excluded key gets no credit and does not compete;
/// a pruned key's share work counts again, as new weight under the cap,
/// from the first handoff after its rejoin is finalized (§4.1). Every
/// input is finalized history: `n <= epoch - 2`, and an exit recorded for
/// `x <= epoch` was included in an epoch below `epoch`, below `finalized`.
/// It stores the new ledger in `state.cap` and returns every key with
/// credit, excluded keys included ([`ConfigWeights`]: the PoCI ledger
/// leaves them out of `C_epoch`, and forgets a pruned key whose credits
/// have all expired).
#[derive(Clone, Copy, Debug, Default)]
pub struct GrowthCapWeights;

impl ConfigWeights for GrowthCapWeights {
    fn weights(&mut self, state: &mut PowitState, params: &PociParams, epoch: u64, _finalized: &Checkpoint)
        -> Result<BTreeMap<KeyId, u128>, String>
    {
        let mut cap = state.cap.take().ok_or("powit: growth cap ledger missing")?;
        let result = {
            let st: &PowitState = state;
            let excluded = |k: &KeyId, x: u64| -> bool { st.poci_excluded_at(params, k, x) };
            let work = |n: u64| st.epoch_work.get(&n);
            let bits = |n: u64| cap.first_bits.get(&n).copied();
            cap.ledger.advance(epoch, params.epoch_len, params.window_epochs, params.growth_div,
                               params.g_min_epoch_div, &work, &bits, &excluded)
        };
        match result {
            Ok(ledger) => {
                let w = ledger.weights();
                cap.ledger = ledger;
                cap.prune();
                state.cap = Some(cap);
                Ok(w)
            }
            Err(e) => {
                state.cap = Some(cap);
                Err(format!("powit: {e}"))
            }
        }
    }
}

/// Plain window weights, without the growth cap (tests and comparisons; not
/// a consensus provider): every key's share work over epochs
/// `epoch - window_epochs ..= epoch - 1` (history entirely below the slot
/// opening `epoch`, as far as the state keeps it). Exclusions are the
/// ledger's ([`ConfigWeights`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowWeights;

impl ConfigWeights for WindowWeights {
    fn weights(&mut self, state: &mut PowitState, params: &PociParams, epoch: u64, _finalized: &Checkpoint)
        -> Result<BTreeMap<KeyId, u128>, String>
    {
        let mut out: BTreeMap<KeyId, u128> = BTreeMap::new();
        if epoch == 0 {
            return Ok(out);
        }
        let lo = epoch.saturating_sub(params.window_epochs);
        for (_, m) in state.epoch_work.range(lo..epoch) {
            for (k, w) in m {
                let e = out.entry(*k).or_insert(0);
                *e = e.saturating_add(*w);
            }
        }
        Ok(out)
    }
}

/// The justification threshold: `got` is at least two thirds of `total`
/// (`3 got >= 2 total`, saturating) and `total` is not zero. `total` is the
/// weight of `W(epoch(target))`: of the 64 heaviest keys before the second
/// hardening activation, of every key with weight from it.
pub fn two_thirds(got: u128, total: u128) -> bool {
    total != 0 && got.saturating_mul(3) >= total.saturating_mul(2)
}

/// A weight after `steps` inactivity-decay steps under `leak`.
pub fn decayed_with(leak: InactivityLeak, w: u128, steps: u32) -> u128 {
    match leak {
        InactivityLeak::Sixteenth => decayed(w, steps),
        InactivityLeak::Half => decayed_half(w, steps),
    }
}

/// [`InactivityLeak::Half`]: `ceil(w / 2^min(steps, 128))`, the same as
/// `steps` rounds of `w -= w / 2`.
pub fn decayed_half(w: u128, steps: u32) -> u128 {
    let s = steps.min(128);
    if s == 0 {
        return w;
    }
    if s == 128 {
        return u128::from(w != 0);
    }
    (w >> s) + u128::from(w & ((1u128 << s) - 1) != 0)
}

/// A weight after `steps` inactivity-decay steps (each keeps 15/16, integer
/// division; at most 64 steps count).
pub fn decayed(w: u128, steps: u32) -> u128 {
    let mut w = w;
    for _ in 0..steps.min(64) {
        w -= w / 16;
    }
    w
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod hardening2_tests;
#[cfg(test)]
mod finalized_history_tests;
#[cfg(test)]
mod liveness_tests;
#[cfg(test)]
mod poci_tests;
