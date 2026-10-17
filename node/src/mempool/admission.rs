//! Shared transaction standardness + admission (audit MEM-1, MEM-4, MEM-5,
//! MEM-6, MEM-7).
//!
//! Before this module the node had three admission paths with different
//! rules: gossip (`validate_tx_standalone`: no dust check, maturity against
//! the DAG block COUNT), RPC `sendrawtransaction` (dust check, tip height) and
//! reorg re-injection (UTXO presence only). A single gossiped dust transaction
//! was therefore admitted from any peer and made every block template
//! consensus-invalid (MEM-1). Every ingress path now calls [`admit`] (or
//! [`check_transaction`] when only the verdict is needed), whose rules are a
//! superset of the block rules a pooled transaction must satisfy to be mined.
//!
//! Checks run cheapest first (MEM-5), so the expensive, size-dependent
//! signature work only ever runs on a transaction that passed everything else:
//!
//!  1. structure: not a coinbase, has inputs and outputs;
//!  2. size: canonical wire size and bincode size within `MAX_TX_SIZE` — this
//!     bounds the quadratic sighash-v2 cost before any signature is checked
//!     (sighash v3, the only digest valid at/after the hardening activation,
//!     is linear: MEM-5 residual closed by CRY-3);
//!  3. known: already pooled, already confirmed, or recently rejected (a
//!     replay costs one size-bounded hash);
//!  4. standardness: canonical-encoding limits (VAL-12), MoneyRange (VAL-11),
//!     no dust output (the consensus `Block::validate_dust` rule), no
//!     zero-value output (policy: UTXO-set bloat, VAL-11 note), canonical
//!     witnesses at EVERY height and the hybrid signature suite only
//!     ([`check_standard_witnesses`], CRY-1/CRY-2 policy; a non-canonical
//!     witness is consensus-invalid for version 3 at/after the activation:
//!     [`check_witnesses_for_next_block`]);
//!  5. next-block rules ([`check_tx_for_next_block`]): the version valid AND
//!     standard for the next block's height
//!     (`core::sighash::check_tx_version_standard`: version 3 from the
//!     hardening activation height; below it version >= 3 is non-standard
//!     although consensus-valid with sighash v2) and, at/after the
//!     activation, no 64-byte txid preimage (VAL-10);
//!  6. duplicate inputs within the tx (C-R3-2);
//!  7. inputs: each one in the UTXO set OR an output of a pooled transaction
//!     (MEM-6: chains of unconfirmed transactions); otherwise "missing
//!     inputs" (the gossip relay buffers it in the orphanage). The spent
//!     outputs (amount and `script_pubkey`, taken from the pooled parent for
//!     an unconfirmed input) are the prevouts the witness check and sighash
//!     v3 commit to;
//!  8. coinbase maturity at the height of the NEXT block (the node's next
//!     template height, `Mempool::next_height`; never `dag.block_count()`,
//!     MEM-4);
//!  9. value: inputs ≥ outputs, MoneyRange of the input sum, consensus
//!     minimum fee, relay fee rate, rolling minimum fee (MEM-6);
//! 10. pool policy (MEM-6): a conflict with pooled transactions is resolved
//!     by the full-RBF replacement rules (BIP125 rules 2-6, see the
//!     `mempool` module docs) and the ancestor / descendant limits must hold
//!     (`Mempool::preflight`);
//! 11. scripts: the consensus input-script rule at the next block's height
//!     ([`verify_input_scripts`]: witnesses, pubkey hash, signatures under
//!     the digest the version selects), LAST, with a bounded
//!     verified-signature cache shared with block validation. A caller may
//!     put a gate in front of this step (`admit_gated`): the gossip relay
//!     charges the delivering connection's signature budget there (MEM-5),
//!     only on a cache miss ([`verify_input_scripts_gated_at`]: one
//!     cache-key computation for the lookup and the insertion; the version
//!     and witness checks run before the gate, so they cost it nothing).
//!
//! Every error says whether the transaction is consensus-INVALID
//! ([`AdmissionError::Rejected`]: no upgraded node relays it; the gossip
//! relay penalises the delivering peer once no older release can be a peer
//! on the chain, see `relay::TxRelay`) or merely refused by local policy
//! (every other variant). Relay policy (the version policy, canonical
//! witnesses below the activation or for a version other than 3, suite
//! 0x0002, zero-value outputs, size) and every rule whose verdict depends on
//! the next block's height (the version rule, the 64-byte rule, coinbase
//! maturity, and the PF-4 key-identity rule of the second hardening upgrade
//! when it is the only rule a transaction fails: `classify_chain_rule_failure`)
//! are policy refusals ([`AdmissionError::NonStandard`] /
//! [`AdmissionError::Immature`]): a peer one block behind across the
//! activation relays such a transaction honestly. A non-canonical witness on
//! a version-3 transaction for a block at/after the activation is
//! `Rejected`: there the canonical witness is the consensus rule (CRY-1) and
//! a peer one block behind refuses version 3 as non-standard
//! ([`check_witnesses_for_next_block`]). Rejections other than "missing
//! inputs", duplicates and rate limiting are remembered in the mempool's
//! bounded recent-rejects filter until the next block's height or the
//! selected tip changes, so a peer replaying the same invalid transaction
//! costs a hash lookup (MEM-5); a verdict computed before such a change is
//! never remembered after it (`Mempool::note_rejected_in_epoch`).
//!
//! # Which height
//!
//! Every height-dependent decision (version / sighash regime, coinbase
//! maturity) uses ONE next-block height: the header height of the node's own
//! next template (`template::next_template_height` = the largest DAG height
//! among the template parents + 1), cached in `Mempool::next_height` under the
//! acceptance lock after every DAG change ([`pool_next_height`]). Admission,
//! post-connect eviction, reorg re-injection, the template self-check and
//! `getdaginfo.next_block_height` (wallets) therefore agree at the activation
//! boundary, also when a tip with a greater DAG height but less blue work
//! makes the template height exceed the selected tip's DAG height + 1
//! (DAG-8). [`admit`] re-checks the height-dependent rules against the cached
//! height under the acceptance lock, so a block connected while a transaction
//! was being verified cannot let a transaction that is invalid for the new
//! next height into the pool.

use std::collections::HashSet;

use crate::core::sighash::SighashVersion;
use crate::core::{self, Transaction, TxOutput};
use crate::mempool::{AddOutcome, Mempool, MempoolError, MAX_TX_SIZE, MIN_RELAY_FEE_RATE};
use crate::storage::Storage;

/// Which checks an admission runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// Header height of the block the transaction would be mined in (for
    /// coinbase maturity). `0` skips the maturity check (genesis-only node).
    pub next_block_height: u64,
    /// Verify the witnesses (standardness: canonical witness, hybrid suite)
    /// and the signatures. `false` ONLY for re-injection of transactions from
    /// disconnected blocks, whose witnesses and signatures were accepted when
    /// the block was connected: standardness is then skipped, and so are the
    /// signatures below the activation (every version is sighash v2 there, as
    /// when the block was mined); at/after it the input scripts are verified
    /// anyway, since the block may have been mined below it under v2. The
    /// version rule and policy at `next_block_height` apply either way.
    /// `false` also selects the re-admission insert (audit B1-T20, Core's
    /// `bypass_limits`): no rolling-minimum check and no per-transaction
    /// trim (the caller trims once), but a transaction the trim would evict
    /// at once is refused (`Mempool::would_only_trim`).
    pub check_signatures: bool,
    /// Consult and update the recent-rejects filter.
    pub use_reject_filter: bool,
}

impl AdmissionPolicy {
    /// Gossip and RPC relay admission.
    pub fn relay(next_block_height: u64) -> Self {
        Self { next_block_height, check_signatures: true, use_reject_filter: true }
    }

    /// Re-injection of transactions from blocks a reorg disconnected (MEM-7).
    pub fn reinjection(next_block_height: u64) -> Self {
        Self { next_block_height, check_signatures: false, use_reject_filter: false }
    }
}

/// Why a transaction was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// Consensus-INVALID for this exact transaction: it can never be mined
    /// in any block (bad signature, inputs < outputs, below the consensus
    /// minimum fee, dust, MoneyRange, canonical limits, duplicate inputs, no
    /// inputs, a coinbase outside a block), or, for a version-3 transaction
    /// whose next block is at/after the hardening activation, a
    /// non-canonical witness. The gossip relay reports `Reject` and the
    /// delivering peer is penalised once no older release can be a peer on
    /// the chain (`relay::TxRelay`; `Ignore` before that).
    Rejected(String),
    /// Refused by local relay policy only (size above `MAX_TX_SIZE`, no
    /// outputs, a zero-value output, a non-canonical witness where it is not
    /// a consensus rule, a single-algorithm suite, the version policy) or by
    /// a rule whose verdict depends on this node's next block height (the
    /// version rule, the 64-byte rule: [`check_tx_for_next_block`]; the
    /// PF-4 key-identity rule of the second hardening upgrade when every
    /// other chain rule passes). The relay reports `Ignore`.
    NonStandard(String),
    /// An input is neither in the UTXO set nor an output of a pooled
    /// transaction (unknown parent, or already spent by a confirmed
    /// transaction). Not cached: it may become valid later.
    MissingInputs(String),
    /// Conflicts with a pooled transaction and replacement was not possible.
    Conflict(String),
    /// MEM-6: conflicts with pooled transactions and fails the full-RBF
    /// replacement rules.
    Replacement(String),
    /// MEM-6: would exceed the ancestor / descendant limits.
    ChainLimit(String),
    /// Coinbase input not yet mature at the next block height.
    Immature(String),
    /// Fee below the relay or rolling minimum (pool policy).
    LowFee(String),
    /// Already pooled / already confirmed / recently rejected.
    Duplicate(String),
    /// MEM-5: the delivering connection's signature-verification budget is
    /// spent. Not cached: the transaction may be perfectly valid.
    RateLimited(String),
    /// The pool refused it (full, or another mempool-level rule).
    Pool(String),
}

impl AdmissionError {
    /// Whether the rejection belongs in the recent-rejects filter.
    pub fn is_cacheable(&self) -> bool {
        !matches!(
            self,
            AdmissionError::MissingInputs(_) | AdmissionError::Duplicate(_) | AdmissionError::RateLimited(_)
        )
    }

    /// True iff the transaction is consensus-invalid (see [`Self::Rejected`]).
    pub fn is_consensus_invalid(&self) -> bool {
        matches!(self, AdmissionError::Rejected(_))
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::Rejected(m)
            | AdmissionError::NonStandard(m)
            | AdmissionError::MissingInputs(m)
            | AdmissionError::Conflict(m)
            | AdmissionError::Replacement(m)
            | AdmissionError::ChainLimit(m)
            | AdmissionError::Immature(m)
            | AdmissionError::LowFee(m)
            | AdmissionError::Duplicate(m)
            | AdmissionError::RateLimited(m)
            | AdmissionError::Pool(m) => write!(f, "{}", m),
        }
    }
}

/// Map a mempool insertion error onto the admission error space.
fn from_mempool_error(e: MempoolError) -> AdmissionError {
    match e {
        MempoolError::Duplicate => AdmissionError::Duplicate(e.to_string()),
        MempoolError::Conflict { .. } => AdmissionError::Conflict(e.to_string()),
        MempoolError::Replacement(_) => AdmissionError::Replacement(e.to_string()),
        MempoolError::ChainLimit(_) => AdmissionError::ChainLimit(e.to_string()),
        other => AdmissionError::Pool(other.to_string()),
    }
}

/// Witness-inclusive transaction id: SHA3-256 over the full canonical wire
/// encoding INCLUDING script_sigs. Two encodings of the same txid with
/// different signatures get different wtxids (reject filter, sig cache).
pub fn wtxid(tx: &Transaction) -> [u8; 32] {
    wtxid_of_canonical_bytes(&tx.to_wire_bytes(true))
}

/// The wtxid of the transaction whose canonical wire encoding
/// (`to_wire_bytes(true)`) is `bytes` — B1-T19: the gossip relay hashes the
/// frame it received (checked canonical by [`decode_tx_canonical`]) once,
/// instead of re-encoding the decoded transaction for every use.
pub fn wtxid_of_canonical_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"gnb-wtxid-v1");
    h.update(bytes);
    h.finalize().into()
}

/// [`decode_tx_strict`] that also proves `bytes` IS the canonical encoding
/// byte for byte (not only of the canonical length), so
/// [`wtxid_of_canonical_bytes`]`(bytes) == `[`wtxid`]`(&tx)`. One
/// re-encoding, as `decode_tx_strict` already did.
pub fn decode_tx_canonical(bytes: &[u8]) -> Result<Transaction, String> {
    if bytes.len() > MAX_TX_SIZE {
        return Err(format!("transaction of {} bytes exceeds MAX_TX_SIZE {}", bytes.len(), MAX_TX_SIZE));
    }
    let tx = Transaction::from_wire_bytes(bytes)?;
    let canonical = tx.to_wire_bytes(true);
    if canonical.len() != bytes.len() {
        return Err(format!(
            "non-canonical transaction encoding: {} trailing byte(s)",
            bytes.len().saturating_sub(canonical.len())
        ));
    }
    if canonical != bytes {
        return Err("non-canonical transaction encoding".into());
    }
    Ok(tx)
}

/// Strict gossip/RPC decode (MEM-5): `Transaction::from_wire_bytes` ignores
/// trailing bytes, so one transaction had unboundedly many byte-distinct
/// encodings (each a fresh gossipsub message id costing a full validation).
/// Only the exact canonical encoding is accepted here.
pub fn decode_tx_strict(bytes: &[u8]) -> Result<Transaction, String> {
    if bytes.len() > MAX_TX_SIZE {
        return Err(format!("transaction of {} bytes exceeds MAX_TX_SIZE {}", bytes.len(), MAX_TX_SIZE));
    }
    let tx = Transaction::from_wire_bytes(bytes)?;
    let canonical_len = tx.to_wire_bytes(true).len();
    if canonical_len != bytes.len() {
        return Err(format!(
            "non-canonical transaction encoding: {} trailing byte(s)",
            bytes.len().saturating_sub(canonical_len)
        ));
    }
    Ok(tx)
}

/// The selected tip's DAG height + 1: the smallest header height a child of
/// the selected tip alone can declare (`max(parent DAG heights) + 1`). Never
/// `dag.block_count()` (MEM-4: the DAG block count includes merged/red blocks
/// and exceeded the chain height by >10k on the Bloch chain, making every
/// immature coinbase look mature).
///
/// NOT the height admission uses: a template that merges a tip with a
/// greater DAG height sits higher (DAG-8). Admission, eviction, templates and
/// wallets use [`pool_next_height`]; this is its fallback when the node has
/// no bodied tip.
pub fn next_block_height(dag: &crate::consensus::GhostDAG) -> u64 {
    dag.selected_tip()
        .and_then(|t| dag.get_block_data(&t).map(|d| d.height))
        .unwrap_or(0)
        .saturating_add(1)
}

/// The height of the next block for every mempool / wallet decision (see
/// "Which height" in the module docs): `Mempool::next_height` (kept current
/// under the acceptance lock by `accept.rs`), or, before the first DAG
/// change of the process, the node's next template height computed from
/// `dag` (`template::next_template_height`). The caller holds the DAG read
/// lock (lock order: acceptance → DAG).
pub fn pool_next_height(dag: &crate::consensus::GhostDAG, store: &Storage, mempool: &Mempool) -> u64 {
    match mempool.next_height() {
        0 => crate::template::next_template_height(dag, store),
        h => h,
    }
}

// ── Verified-signature cache (shared with block validation) ─────────────────

const SIG_CACHE_CAPACITY: usize = 100_000;

fn sig_cache() -> &'static parking_lot::Mutex<(HashSet<[u8; 32]>, std::collections::VecDeque<[u8; 32]>)> {
    static CACHE: std::sync::OnceLock<
        parking_lot::Mutex<(HashSet<[u8; 32]>, std::collections::VecDeque<[u8; 32]>)>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| parking_lot::Mutex::new((HashSet::new(), std::collections::VecDeque::new())))
}

/// Cache key of a verified transaction: EVERYTHING the cached verdict
/// depends on, so a "valid" entry can never answer for another digest
/// version, prevout set or height regime (mandated with CRY-3):
///
/// * the chain id (every digest commits to it);
/// * the digest / witness regime (`SighashVersion`: v2 + lenient witness, or
///   v3 + canonical witness + bound signatures) and whether the hardening
///   activation is in force at the block height (the regime is a function of
///   both, so a version-3 transaction verified under v2 below the activation
///   never hits at/after it, and vice versa);
/// * the signature suites valid at the block height (P5-S: the conservative
///   suite 0x0003 from the second hardening height,
///   `core::sighash::suite_rules_at`);
/// * the wtxid (every input's outpoint, sequence, script_sig, every output,
///   version and locktime);
/// * every spent output (value and `script_pubkey`, in input order): sighash
///   v3 commits to them, and the witness check hashes the public key against
///   the spent script. Included for v2 too, so the key never depends on the
///   regime-specific reasoning above.
fn sig_cache_key(
    tx: &Transaction,
    version: SighashVersion,
    active: bool,
    suites: crate::crypto::SuiteRules,
    prevouts: &[TxOutput],
) -> [u8; 32] {
    sig_cache_key_for(&wtxid(tx), version, active, suites, prevouts)
}

/// [`sig_cache_key`] from the transaction's wtxid (B1-T19: the gossip relay
/// computes it once per frame, from the frame's canonical bytes).
fn sig_cache_key_for(
    wtxid: &[u8; 32],
    version: SighashVersion,
    active: bool,
    suites: crate::crypto::SuiteRules,
    prevouts: &[TxOutput],
) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    #[cfg(test)]
    tests::SIG_KEYS_COMPUTED.with(|c| c.set(c.get() + 1));
    let mut h = Sha3_256::new();
    h.update(b"gnb-sigcache-v5");
    h.update(core::node_chain_id().to_le_bytes());
    // P5-S: whether the conservative suite 0x0003 is valid at the height
    // (the second hardening height), so a conservative spend verified from
    // that height never answers below it.
    h.update([
        match version { SighashVersion::V2 => 2u8, SighashVersion::V3 => 3u8 },
        u8::from(active),
        u8::from(suites.conservative_suite()),
    ]);
    h.update(wtxid);
    h.update((prevouts.len() as u64).to_le_bytes());
    for p in prevouts {
        h.update(p.value.to_le_bytes());
        h.update((p.script_pubkey.len() as u64).to_le_bytes());
        h.update(&p.script_pubkey);
    }
    h.finalize().into()
}

/// The hardening activation height the transaction rules are evaluated
/// under (process-wide; a `scoped_override` on the calling thread in tests).
fn activation_height() -> u64 {
    core::activation::hardening_activation_height()
}

/// The second hardening activation height (P5-S: the conservative suite;
/// PF-4), process-wide like [`activation_height`].
fn hardening2_activation_height() -> u64 {
    core::activation::hardening2_activation_height()
}

/// True iff the signatures of `tx` spending `prevouts` in a block at header
/// height `block_height` are in the verified-signature cache, i.e.
/// [`verify_input_scripts`] would skip the expensive step. Same key as the
/// cache ([`sig_cache_key`]: regime, activation state, wtxid, prevouts), so
/// a hit under one regime or prevout set never answers for another. `false`
/// when the version is invalid at that height. The gossip relay charges a
/// peer's signature budget only on a miss (MEM-5).
pub fn signatures_cached(tx: &Transaction, prevouts: &[TxOutput], block_height: u64) -> bool {
    signatures_cached_at(tx, prevouts, block_height, activation_height())
}

/// [`signatures_cached`] for an explicit hardening activation height.
pub fn signatures_cached_at(tx: &Transaction, prevouts: &[TxOutput], block_height: u64, act: u64) -> bool {
    match core::sighash::check_tx_version(tx.version, block_height, act) {
        Ok(version) => {
            let suites = core::sighash::suite_rules_at(block_height, act, hardening2_activation_height());
            let key = sig_cache_key(tx, version, core::activation::is_active_at(block_height, act), suites, prevouts);
            sig_cache().lock().0.contains(&key)
        }
        Err(_) => false,
    }
}

/// The consensus input-script rule of a non-coinbase transaction in a block
/// at header height `block_height` — the ONE function block acceptance and
/// connect (`accept::validate_tx_inputs`), reorg connect, template self-check
/// and mempool admission (at the next block's height) all call:
///
/// 1. version: `core::sighash::check_tx_version` (below the hardening
///    activation every version, 3 included, is valid with sighash v2 — the
///    pre-upgrade rule exactly; at/after it only version 3 is valid, with
///    sighash v3);
/// 2. witnesses (`core::sighash::check_input_witnesses`): below the
///    activation the historical lenient `script_sig` framing; from it the
///    canonical witness (exact framing, enveloped canonical signature,
///    CRY-1); the public key must hash to the spent `script_pubkey`
///    (`prevouts[i]`);
/// 3. signatures (`core::sighash::verify_input_signatures`): sighash v2 with
///    the historical verifier, or sighash v3 (spent amounts and scripts, the
///    suite and the input index committed; linear cost) with component-bound
///    signatures (CRY-2, CRY-3).
///
/// Steps 1–2 run on every call (they depend on the height and the prevouts).
/// The expensive signature results are cached under a key that covers the
/// regime, the activation state at `block_height` and the prevouts (see
/// [`sig_cache_key`]); only successes are cached. Relay policy (version >= 3
/// non-standard below the activation) is NOT part of this rule: see
/// [`check_version_for_next_block`]. Uses the process-wide activation height.
pub fn verify_input_scripts(tx: &Transaction, prevouts: &[TxOutput], block_height: u64) -> Result<(), String> {
    verify_input_scripts_at(tx, prevouts, block_height, activation_height())
}

/// [`verify_input_scripts`] for an explicit hardening activation height (the
/// node's `accept::validate_block_in_view_at` evaluates every rule of a block
/// under one activation height).
pub fn verify_input_scripts_at(
    tx: &Transaction,
    prevouts: &[TxOutput],
    block_height: u64,
    act: u64,
) -> Result<(), String> {
    verify_input_scripts_gated_at(tx, prevouts, block_height, act, &mut |_| Ok(())).map_err(|e| e.to_string())
}

/// [`verify_input_scripts_at`] with a [`SignatureGate`] called once, right
/// before the signature math, only on a verified-signature cache MISS (after
/// the version and witness checks, so a transaction that fails those costs
/// the gate nothing). The cache key is computed once: admission used to hash
/// the transaction for [`signatures_cached`] and again here (integration
/// open issue). A script failure is [`AdmissionError::Rejected`]; a gate
/// refusal is returned as the gate gave it.
pub fn verify_input_scripts_gated_at(
    tx: &Transaction,
    prevouts: &[TxOutput],
    block_height: u64,
    act: u64,
    gate: &mut SignatureGate<'_>,
) -> Result<(), AdmissionError> {
    verify_input_scripts_gated_with_wtxid_at(tx, &wtxid(tx), prevouts, block_height, act, gate)
}

/// [`verify_input_scripts_gated_at`] with the transaction's wtxid already
/// computed (`tx_wtxid` MUST be [`wtxid`]`(tx)`; B1-T19: once per frame).
pub fn verify_input_scripts_gated_with_wtxid_at(
    tx: &Transaction,
    tx_wtxid: &[u8; 32],
    prevouts: &[TxOutput],
    block_height: u64,
    act: u64,
    gate: &mut SignatureGate<'_>,
) -> Result<(), AdmissionError> {
    let version = core::sighash::check_tx_version(tx.version, block_height, act).map_err(AdmissionError::Rejected)?;
    // P5-S: the signature suites of the block's height (the conservative
    // suite 0x0003 from the second hardening height, process-wide).
    let suites = core::sighash::suite_rules_at(block_height, act, hardening2_activation_height());
    let witnesses = core::sighash::check_input_witnesses_under(tx, prevouts, version, suites)
        .map_err(AdmissionError::Rejected)?;
    let key = sig_cache_key_for(tx_wtxid, version, core::activation::is_active_at(block_height, act), suites, prevouts);
    if sig_cache().lock().0.contains(&key) {
        count_signature_inputs(|c| c.cached += tx.inputs.len() as u64);
        return Ok(());
    }
    gate(tx)?;
    count_signature_inputs(|c| c.verified += tx.inputs.len() as u64);
    core::sighash::verify_input_signatures_under(tx, prevouts, &witnesses, version, core::node_chain_id(), suites)
        .map_err(AdmissionError::Rejected)?;
    let mut g = sig_cache().lock();
    let (set, order) = &mut *g;
    if set.insert(key) {
        order.push_back(key);
        while order.len() > SIG_CACHE_CAPACITY {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
    }
    Ok(())
}

/// The input-script rule of [`verify_input_scripts_at`] WITHOUT its
/// signature step: the version rule (`core::sighash::check_tx_version`) and
/// every witness check (`core::sighash::check_input_witnesses`: the
/// `script_sig` framing, canonical from the hardening activation; the public
/// key hashed against the spent 20-byte script; a revealed spend policy
/// hashed against the spent policy output, its signature count and key
/// indices). Only `core::sighash::verify_input_signatures` is left out —
/// exactly what a verified-signature cache hit skips. The block connect runs
/// this for a block whose signatures are assumed valid (`crate::assumevalid`,
/// Bitcoin Core's `-assumevalid`); nothing else calls it.
pub fn check_input_scripts_without_signatures_at(
    tx: &Transaction,
    prevouts: &[TxOutput],
    block_height: u64,
    act: u64,
) -> Result<(), String> {
    let version = core::sighash::check_tx_version(tx.version, block_height, act)?;
    // P5-S: the witness rules of the block's height, as the full path
    // ([`verify_input_scripts_at`]): a conservative suite-0x0003 witness is
    // valid from the second hardening height on the assumed-valid path too.
    let suites = core::sighash::suite_rules_at(block_height, act, hardening2_activation_height());
    core::sighash::check_input_witnesses_under(tx, prevouts, version, suites)?;
    count_signature_inputs(|c| c.assumed += tx.inputs.len() as u64);
    Ok(())
}

/// Inputs whose signature step the calling thread ran, by outcome (P5-G
/// measurement: what the assumed-valid block saves).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignatureInputCounts {
    /// Signature verifications run (`core::sighash::verify_input_signatures`,
    /// valid or not), counted per input.
    pub verified: u64,
    /// Inputs of transactions answered by the verified-signature cache.
    pub cached: u64,
    /// Inputs whose signatures were assumed valid
    /// ([`check_input_scripts_without_signatures_at`]).
    pub assumed: u64,
}

thread_local! {
    static SIGNATURE_INPUTS: std::cell::Cell<SignatureInputCounts> =
        const { std::cell::Cell::new(SignatureInputCounts { verified: 0, cached: 0, assumed: 0 }) };
}

fn count_signature_inputs(f: impl FnOnce(&mut SignatureInputCounts)) {
    SIGNATURE_INPUTS.with(|c| {
        let mut v = c.get();
        f(&mut v);
        c.set(v);
    });
}

/// [`SignatureInputCounts`] of the calling thread since it started (block
/// validation runs on the thread that accepts the block).
pub fn signature_inputs_on_this_thread() -> SignatureInputCounts {
    SIGNATURE_INPUTS.with(|c| c.get())
}

/// Standardness rules that need no chain state (steps 1–3).
pub fn check_standard(tx: &Transaction) -> Result<(), AdmissionError> {
    check_structure_and_size(tx)?;
    check_policy(tx)
}

/// Steps 1–2: structure and size. Run before anything that hashes or walks
/// the whole transaction, so their cost is bounded by `MAX_TX_SIZE`.
fn check_structure_and_size(tx: &Transaction) -> Result<(), AdmissionError> {
    // Consensus: a coinbase is only valid as the first transaction of a
    // block, and a transaction without inputs pays a zero fee (below the
    // consensus minimum) — neither can ever be mined.
    if tx.is_coinbase() {
        return Err(AdmissionError::Rejected("coinbase not accepted".into()));
    }
    if tx.inputs.is_empty() {
        return Err(AdmissionError::Rejected("no inputs".into()));
    }
    // Policy (MEM-5 verdicts): an output-less transaction or one above
    // MAX_TX_SIZE can be consensus-valid inside a block; refusing to RELAY
    // it is local policy, never grounds for penalising the sender.
    if tx.outputs.is_empty() {
        return Err(AdmissionError::NonStandard("no outputs".into()));
    }
    let wire = tx.to_wire_bytes(true).len();
    if wire > MAX_TX_SIZE {
        return Err(AdmissionError::NonStandard(format!(
            "transaction too large: {} bytes (max {})", wire, MAX_TX_SIZE)));
    }
    let size = tx.actual_size();
    if size > MAX_TX_SIZE {
        return Err(AdmissionError::NonStandard(format!(
            "transaction too large: {} bytes (max {})", size, MAX_TX_SIZE)));
    }
    Ok(())
}

/// Step 3: canonical limits, MoneyRange, dust, zero-value outputs. (The
/// witness standardness of step 4 runs in [`check_transaction`] together with
/// the signature policy.)
fn check_policy(tx: &Transaction) -> Result<(), AdmissionError> {
    core::limits::check_tx_canonical_limits(tx).map_err(AdmissionError::Rejected)?;
    core::limits::check_tx_money_range(tx).map_err(AdmissionError::Rejected)?;
    for (i, o) in tx.outputs.iter().enumerate() {
        if o.value > 0 && o.value < core::DUST_THRESHOLD {
            return Err(AdmissionError::Rejected(format!(
                "output {} below dust threshold ({} < {} sats)", i, o.value, core::DUST_THRESHOLD)));
        }
        if o.value == 0 {
            return Err(AdmissionError::NonStandard(format!(
                "output {} has zero value (non-standard)", i)));
        }
    }
    Ok(())
}

/// Witness standardness (relay policy at EVERY height; no signature math):
///
/// * CRY-1: every `script_sig` must be the canonical witness
///   (`core::sighash::canonical_witness`: exactly
///   `[u32 sig_len][sig][u32 pk_len][pk]`, enveloped canonical signature —
///   compact Falcon half, exact ML-DSA length). Consensus requires it only
///   for version 3 (at/after the activation); below it a non-canonical
///   witness is still consensus-valid but is not relayed or mined from the
///   pool, so third parties cannot malleate pooled transactions. Wallets
///   always emit canonical witnesses.
/// * CRY-2: the public key must name the hybrid suite
///   (`crypto::is_hybrid_public_key`: suite 0x0001, or the raw legacy hybrid
///   key of a carry-over address). Single-algorithm suite 0x0002 stays
///   consensus-valid (outputs that may already be locked to such keys are not
///   frozen) but is non-standard: no new 0x0002 spend enters the pool.
/// * P5-S: from the second hardening height (`crypto::SuiteRules` of the
///   next block, [`check_standard_witnesses_classified_under`]) a
///   conservative suite-0x0003 key and canonical signature are standard too.
///   This entry point has the rules below that height.
pub fn check_standard_witnesses(tx: &Transaction) -> Result<(), String> {
    check_standard_witnesses_classified(tx).map_err(|(_, m)| m)
}

/// Why [`check_standard_witnesses`] refused a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessRefusal {
    /// Some input's `script_sig` is not the canonical witness
    /// (`core::sighash::canonical_witness`: framing or signature encoding).
    /// Consensus requires exactly this for a version-3 transaction at/after
    /// the hardening activation (CRY-1); policy everywhere else.
    Framing,
    /// Every witness is canonical, but some public key is not hybrid (suite
    /// 0x0002 or an unknown key): policy at every height (CRY-2).
    Suite,
    /// P5-S: a key-hash witness carries the conservative suite 0x0003 (a
    /// canonical signature or a key of that suite) for a block below the
    /// second hardening height. Consensus-invalid there (exactly the old
    /// verdict), but valid one block later across the height, so a peer
    /// ahead of this node relays it honestly: policy, never a penalty.
    SuiteNotYetActive,
}

/// [`check_standard_witnesses`] with the kind of refusal. The framing of
/// EVERY input is checked before any suite, so a transaction that fails both
/// (on different inputs) is reported as [`WitnessRefusal::Framing`], the
/// failure that can be a consensus rule.
pub fn check_standard_witnesses_classified(tx: &Transaction) -> Result<(), (WitnessRefusal, String)> {
    check_standard_witnesses_classified_under(tx, crate::crypto::SuiteRules::LEGACY)
}

/// [`check_standard_witnesses_classified`] under the signature suites of
/// the next block (`core::sighash::suite_rules_at`): from the second
/// hardening height a conservative suite-0x0003 key-hash witness (canonical
/// signature, a key of exactly that suite) is standard. Below it such a
/// witness is [`WitnessRefusal::SuiteNotYetActive`] (checked after the
/// framing of every input, so a real framing failure elsewhere still
/// classifies as [`WitnessRefusal::Framing`]).
pub fn check_standard_witnesses_classified_under(
    tx: &Transaction,
    suites: crate::crypto::SuiteRules,
) -> Result<(), (WitnessRefusal, String)> {
    use crate::crypto::SuiteRules;
    let mut keys = Vec::with_capacity(tx.inputs.len());
    let mut premature: Option<usize> = None;
    for (i, inp) in tx.inputs.iter().enumerate() {
        // A policy spend (multisig / timelocks) carries a strictly parsed
        // policy witness, not the single-key framing; whether it matches the
        // spent output, and whether its keys' suites are valid at the height,
        // is consensus (`core::sighash::check_input_witnesses_under`,
        // `blockval`). Recognised in its widest form (every suite).
        if core::policy::AnyPolicyWitness::decode_under(&inp.script_sig, SuiteRules::HARDENING2).is_ok() {
            continue;
        }
        let (_sig, pk) = match core::sighash::canonical_witness_under(&inp.script_sig, suites) {
            Ok(w) => w,
            Err(e) => match core::sighash::canonical_witness_under(&inp.script_sig, SuiteRules::HARDENING2) {
                // Canonical once the conservative suite is valid: only the
                // suite is premature.
                Ok(w) if !suites.conservative_suite() => {
                    premature.get_or_insert(i);
                    w
                }
                _ => return Err((WitnessRefusal::Framing, format!("input {i}: {e} (non-standard)"))),
            },
        };
        keys.push(pk);
    }
    if let Some(i) = premature {
        return Err((WitnessRefusal::SuiteNotYetActive, format!(
            "input {i}: the conservative signature suite 0x0003 is not valid before the second \
             hardening height (non-standard for this block)"
        )));
    }
    for (i, pk) in keys.into_iter().enumerate() {
        let conservative = crate::crypto::is_conservative_public_key(pk);
        if conservative && !suites.conservative_suite() {
            return Err((WitnessRefusal::SuiteNotYetActive, format!(
                "input {i}: a conservative suite-0x0003 key is not valid before the second \
                 hardening height (non-standard for this block)"
            )));
        }
        if !crate::crypto::is_hybrid_public_key(pk) && !conservative {
            return Err((WitnessRefusal::Suite, format!(
                "input {i}: single-algorithm signature suite (non-standard; only the hybrid \
                 ML-DSA-65 + Falcon-1024 suite 0x0001 and, from the second hardening height, \
                 the conservative suite 0x0003 are relayed)"
            )));
        }
    }
    Ok(())
}

/// Step 4's witness check as an admission verdict for the block at
/// `next_block_height` (process-wide activation height). Every refusal is
/// [`AdmissionError::NonStandard`] (relay policy, no penalty) EXCEPT a
/// non-canonical witness when the canonical witness is the consensus rule
/// there: the transaction is version 3 and the next block is at/after the
/// hardening activation (`core::sighash::check_tx_version` selects sighash
/// v3, whose witness rule is exactly `core::sighash::canonical_witness`,
/// CRY-1). Such a transaction can never be mined at that height and no
/// upgraded node relays it (below the activation version 3 is non-standard),
/// so it is [`AdmissionError::Rejected`]. A suite-0x0002 key stays
/// `NonStandard` at every height (consensus-valid, CRY-2).
pub fn check_witnesses_for_next_block(tx: &Transaction, next_block_height: u64) -> Result<(), AdmissionError> {
    check_witnesses_for_next_block_at(tx, next_block_height, activation_height())
}

/// [`check_witnesses_for_next_block`] for an explicit activation height.
pub fn check_witnesses_for_next_block_at(tx: &Transaction, next_block_height: u64, act: u64) -> Result<(), AdmissionError> {
    let suites = core::sighash::suite_rules_at(next_block_height, act, hardening2_activation_height());
    match check_standard_witnesses_classified_under(tx, suites) {
        Ok(()) => Ok(()),
        Err((WitnessRefusal::Framing, m))
            if matches!(core::sighash::check_tx_version(tx.version, next_block_height, act), Ok(SighashVersion::V3)) =>
        {
            Err(AdmissionError::Rejected(format!(
                "{m}: bad-witness: the canonical witness is a consensus rule for version 3 at height \
                 {next_block_height} (hardening activation {act})"
            )))
        }
        Err((_, m)) => Err(AdmissionError::NonStandard(m)),
    }
}

/// Step 5: the version rule AND policy at the next block's height
/// (`core::sighash::check_tx_version_standard`): consensus (only version 3
/// at/after the hardening activation) plus relay policy (version >= 3 is
/// non-standard below it, although consensus-valid there with sighash v2).
/// Cheap; runs even when signatures are not checked (reorg re-injection), in
/// post-connect eviction, in `accept::revalidate_mempool` and in the
/// template self-check, so the pool never holds a version-1 transaction for a
/// block at/after the activation, nor a version >= 3 one for a block below it.
///
/// Whatever passes this check at two heights uses the same digest at both, so
/// a pooled transaction's verified signatures stay valid while the next
/// height moves (only a move across the activation changes the regime, and
/// then no version passes on both sides).
pub fn check_version_for_next_block(tx: &Transaction, next_block_height: u64) -> Result<(), String> {
    core::sighash::check_tx_version_standard(tx.version, next_block_height, activation_height()).map(|_| ())
}

/// Step 5: every signature-free rule a transaction must satisfy for the block
/// at `next_block_height` that is a function of that height alone (no chain
/// state): the version rule and policy ([`check_version_for_next_block`],
/// CRY-3) and, at/after the hardening activation, no 64-byte txid preimage
/// (`core::block_rules::check_tx_not_64_bytes`, VAL-10). THE height check
/// admission, the re-check under the acceptance lock in [`admit`],
/// post-connect eviction (`accept::evict_version_invalid`),
/// `accept::revalidate_mempool` and the template self-check share, so a pool
/// whose next height crosses the activation drops (or a template at another
/// height skips) every transaction that block could not contain.
///
/// ONE gate for both rules: the transaction-rule predicate
/// `activation::is_active_at(next_block_height, activation)` that the
/// version rule uses. For every height a next block can have (>= 1,
/// `template::next_template_height`) it equals the block-rule predicate
/// `block_rules::rules_active_at` the connect path applies to the 64-byte
/// rule; at `next_block_height = 0` (only callers without a height context,
/// such as `accept::validate_tx_standalone(.., 0)`) both rules still switch
/// together (docs/CONSENSUS.md, "Activation").
pub fn check_tx_for_next_block(tx: &Transaction, next_block_height: u64) -> Result<(), String> {
    check_version_for_next_block(tx, next_block_height)?;
    if core::activation::is_active_at(next_block_height, activation_height()) {
        core::block_rules::check_tx_not_64_bytes(tx).map_err(str::to_string)?;
    }
    Ok(())
}

/// Run every admission check (steps 1–11) WITHOUT inserting. Returns the fee.
/// `mempool = None` skips the pool-relative checks (known/conflict/rolling
/// fee), which is what block-independent callers such as
/// `validate_tx_standalone` want.
pub fn check_transaction(
    store: &Storage,
    mempool: Option<&Mempool>,
    tx: &Transaction,
    policy: &AdmissionPolicy,
) -> Result<u64, AdmissionError> {
    check_transaction_gated(store, mempool, tx, policy, &mut |_| Ok(()))
}

/// The gate type of [`check_transaction_gated`] / [`admit_gated`]: called
/// once, right before the signatures are verified, and only when they are
/// not already in the verified-signature cache. An `Err` aborts the
/// admission with that error.
pub type SignatureGate<'a> = dyn FnMut(&Transaction) -> Result<(), AdmissionError> + 'a;

/// [`check_transaction`] with a [`SignatureGate`] in front of step 11.
pub fn check_transaction_gated(
    store: &Storage,
    mempool: Option<&Mempool>,
    tx: &Transaction,
    policy: &AdmissionPolicy,
    gate: &mut SignatureGate<'_>,
) -> Result<u64, AdmissionError> {
    check_transaction_gated_with_wtxid(store, mempool, tx, &wtxid(tx), policy, gate)
}

/// [`check_transaction_gated`] with the transaction's wtxid already
/// computed (`tx_wtxid` MUST be [`wtxid`]`(tx)`; B1-T19: the gossip relay
/// computes it once per frame).
pub fn check_transaction_gated_with_wtxid(
    store: &Storage,
    mempool: Option<&Mempool>,
    tx: &Transaction,
    tx_wtxid: &[u8; 32],
    policy: &AdmissionPolicy,
    gate: &mut SignatureGate<'_>,
) -> Result<u64, AdmissionError> {
    check_structure_and_size(tx)?;

    // Known: pooled, recently rejected (a replay costs one bounded hash), or
    // already confirmed.
    let txid = tx.txid();
    if let Some(mp) = mempool {
        if mp.contains(&txid) {
            return Err(AdmissionError::Duplicate("duplicate transaction".into()));
        }
        if policy.use_reject_filter && mp.is_recently_rejected(tx_wtxid) {
            return Err(AdmissionError::Duplicate("recently rejected".into()));
        }
    }
    if let Ok(Some(_)) = store.get_tx_location(&txid) {
        return Err(AdmissionError::Duplicate("transaction already confirmed".into()));
    }

    check_policy(tx)?;
    if policy.check_signatures {
        // Witness standardness travels with the signature policy: a
        // re-injected transaction was already mined (its witness accepted by
        // consensus), relayed ones must be standard.
        // Policy, not invalidity (MEM-5 verdicts): a non-canonical witness
        // or a suite-0x0002 key is consensus-valid below the activation, so
        // the sender is not penalised. The one exception is consensus: a
        // version-3 transaction for a block at/after the activation must
        // carry canonical witnesses (CRY-1), so a framing failure there is
        // `Rejected` (`check_witnesses_for_next_block`).
        check_witnesses_for_next_block(tx, policy.next_block_height)?;
    }
    // Version rule / policy (CRY-3) and the 64-byte rule (VAL-10), judged at
    // the height of the block the transaction would be mined in: neither a
    // version-1 transaction nor a 64-byte txid preimage can be mined at/after
    // the activation, so neither is pooled there. A policy refusal: the
    // verdict depends on this node's next height (a peer one block behind
    // across the activation relays it honestly) and on the version policy.
    check_tx_for_next_block(tx, policy.next_block_height).map_err(AdmissionError::NonStandard)?;

    // Duplicate inputs (cheap, no I/O). Conflicts with the pool are NOT an
    // early exit any more: they are resolved by the replacement rules in
    // step 10 (MEM-6, full-RBF).
    let mut seen: HashSet<([u8; 32], u32)> = HashSet::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        let op = (inp.prev_txid, inp.prev_index);
        if !seen.insert(op) {
            return Err(AdmissionError::Rejected(format!(
                "double-spend: {}:{} already consumed", hex::encode(&inp.prev_txid[..8]), inp.prev_index)));
        }
    }

    // Input presence + input sum: the UTXO set, else (MEM-6) an output of a
    // pooled transaction.
    let mut prevouts: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
    let mut total_in: u64 = 0;
    for inp in &tx.inputs {
        let confirmed = store.get_utxo(&inp.prev_txid, inp.prev_index)
            .map_err(|e| AdmissionError::Pool(format!("storage: {}", e)))?;
        let out = match confirmed {
            Some(o) => o,
            None => mempool
                .and_then(|mp| mp.pool_output(&inp.prev_txid, inp.prev_index))
                .ok_or_else(|| AdmissionError::MissingInputs(format!(
                    "UTXO {}:{} not found", hex::encode(&inp.prev_txid[..8]), inp.prev_index)))?,
        };
        total_in = core::limits::money_add(total_in, out.value)
            .map_err(|e| AdmissionError::Rejected(format!("input total: {}", e)))?;
        prevouts.push(out);
    }

    // Coinbase maturity at the next block's height (MEM-4).
    coinbase_maturity_for_next_block(store, tx, policy.next_block_height)
        .map_err(|e| AdmissionError::Pool(format!("storage: {}", e)))?
        .map_err(AdmissionError::Immature)?;

    // This chain's rules (`blockval`): finality at the next height, output
    // kinds, dust, policy timelocks. An output of a pooled (unconfirmed)
    // parent has no confirmation height yet: a relative timelock on it is
    // not satisfied. Relative timelocks count confirmations in the connect
    // path's measure for the next block (re-audit B1-T14).
    let confirmations = |t: &[u8; 32]| -> Result<Option<u64>, String> {
        confirmations_for_next_block(store, t, policy.next_block_height).map_err(|e| e.msg)
    };
    crate::blockval::check_tx_chain_rules_with_confirmations(tx, &prevouts, policy.next_block_height, &confirmations)
        .map_err(|e| classify_chain_rule_failure(tx, &prevouts, policy.next_block_height, &confirmations, e))?;

    // Value + fees.
    let total_out = core::limits::check_tx_money_range(tx).map_err(AdmissionError::Rejected)?;
    if total_in < total_out {
        return Err(AdmissionError::Rejected(format!("inputs {} < outputs {}", total_in, total_out)));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee).map_err(AdmissionError::Rejected)?;
    let size = tx.actual_size();
    if fee < (size as u64).saturating_mul(MIN_RELAY_FEE_RATE) {
        return Err(AdmissionError::LowFee(format!(
            "fee {} below minimum relay rate ({} sat/byte for {} bytes)", fee, MIN_RELAY_FEE_RATE, size)));
    }
    if let Some(mp) = mempool {
        if policy.check_signatures {
            if !mp.meets_rolling_min(fee, size) {
                return Err(AdmissionError::LowFee(format!(
                    "fee {} below the mempool's rolling minimum ({} sat/byte)", fee, mp.rolling_min_fee_rate())));
            }
        } else if mp.would_only_trim(fee, size) {
            // Re-admission after a reorg (B1-T20, Bitcoin Core's
            // `MaybeUpdateMempoolForReorg`): the rolling minimum (relay
            // policy) does not apply to a transaction that was mined, but
            // one the pool's final trim would evict at once is not inserted.
            return Err(AdmissionError::LowFee(format!(
                "the pool is full and fee {} for {} bytes does not beat its cheapest package", fee, size)));
        }
        // MEM-6: replacement rules (when it conflicts) and chain limits,
        // still before any signature work.
        mp.preflight(tx, fee).map_err(from_mempool_error)?;
    }

    // Signatures last (the most expensive step). Re-injection skips them only
    // where the digest regime cannot have changed since the transaction was
    // mined: below the activation every version is verified with sighash v2
    // at every height. From the activation the scripts are verified again (a
    // verified-signature cache hit when the disconnected block was itself at
    // or after it): a version-3 transaction mined BELOW the activation was
    // checked against the v2 digest, which says nothing about v3. The
    // prevouts of an unconfirmed input are the pooled parent's outputs.
    let regime_may_have_changed = !policy.check_signatures
        && core::activation::is_active_at(policy.next_block_height, activation_height());
    if policy.check_signatures || regime_may_have_changed {
        // Behind the caller's gate (MEM-5: the relay's per-connection
        // budget), charged only when the work is not already cached; one
        // cache-key computation for the lookup and the insertion.
        verify_input_scripts_gated_with_wtxid_at(tx, tx_wtxid, &prevouts, policy.next_block_height, activation_height(), gate)?;
    }
    Ok(fee)
}

/// The admission error for a failure `e` of this chain's rules
/// (`blockval::check_tx_chain_rules_with_confirmations`) at the next block's
/// height: a storage failure is `Pool`; a failure of the PF-4 key-identity
/// rule of the second hardening upgrade ALONE (the transaction passes every
/// other chain rule: `blockval::check_tx_chain_rules_without_key_identity_rule`)
/// is a policy refusal, `NonStandard`; anything else is `Rejected`.
///
/// The identity rule depends on the next block's height and only tightens
/// the rules: a peer one block behind across the hardening-2 height, and
/// every release without the rule, accepts and relays a spend of a
/// twin-key policy honestly, so refusing it must not penalise the peer
/// (module docs; Bitcoin Core's standard / mandatory script-flag split,
/// `PolicyScriptChecks`). Below the hardening-2 height the rule is off and
/// the second check is skipped.
fn classify_chain_rule_failure(
    tx: &Transaction,
    prevouts: &[TxOutput],
    next_block_height: u64,
    confirmations: &crate::blockval::ConfirmationsLookup<'_>,
    e: String,
) -> AdmissionError {
    if e.starts_with(crate::blockval::STORAGE_ERR) {
        return AdmissionError::Pool(e);
    }
    if core::activation::hardening2_active_at(next_block_height) {
        match crate::blockval::check_tx_chain_rules_without_key_identity_rule(
            tx, prevouts, next_block_height, confirmations)
        {
            Ok(()) => return AdmissionError::NonStandard(e),
            Err(other) if other.starts_with(crate::blockval::STORAGE_ERR) => return AdmissionError::Pool(other),
            Err(_) => {}
        }
    }
    // P5-S: a revealed policy that lists a conservative suite-0x0003 key for
    // a block below the second hardening height. Invalid there (exactly the
    // old verdict), valid one block later: a policy refusal when it is the
    // only failure (the conservative suite only loosens the rules from the
    // height; same split as the PF-4 rule above).
    let lists_conservative_key = tx.inputs.iter().any(|i| {
        core::policy::AnyPolicyWitness::decode_under(&i.script_sig, crate::crypto::SuiteRules::HARDENING2)
            .is_ok_and(|w| w.policy().has_conservative_key())
    });
    if lists_conservative_key && !core::sighash::suite_rules_for_height(next_block_height).conservative_suite() {
        match crate::blockval::check_tx_chain_rules_with_conservative_suite(tx, prevouts, next_block_height, confirmations) {
            Ok(()) => return AdmissionError::NonStandard(format!(
                "{e} (a policy key of the conservative signature suite 0x0003 is not valid before the second \
                 hardening height; non-standard for this block)")),
            Err(other) if other.starts_with(crate::blockval::STORAGE_ERR) => return AdmissionError::Pool(other),
            Err(_) => {}
        }
    }
    AdmissionError::Rejected(e)
}

/// Coinbase maturity of `tx` for the next block, at header height
/// `next_block_height` (`0` skips it), under the connect path's own rule
/// (`accept::check_coinbase_maturity_in_view`, re-audit B1-T14): below the
/// activation header heights, from it the selected-chain depth, the next
/// block being a child of the applied tip (its selected parent: the
/// template's first parent is the applied tip, whose UTXO set the template's
/// transactions are checked against). `Ok(Err(reason))` when an input spends
/// an immature coinbase, `Err` when a height could not be read. A failed
/// read is never "not a coinbase" (re-audit B1-T12: the lookups used
/// `.ok().flatten()`, which skipped the check). Shared by admission, the
/// post-connect revalidation and the template self-check.
pub fn coinbase_maturity_for_next_block(
    store: &Storage,
    tx: &Transaction,
    next_block_height: u64,
) -> Result<Result<(), String>, crate::storage::StorageError> {
    use crate::accept::{check_coinbase_maturity_in_view, MaturityRule};
    let next_dag_height = || next_block_dag_height(store);
    let rule = if next_block_height == 0 {
        MaturityRule::Skip
    } else if core::block_rules::rules_active_at(next_block_height, activation_height()) {
        MaturityRule::SelectedChainDepth(&next_dag_height)
    } else {
        MaturityRule::HeaderHeights(next_block_height)
    };
    check_coinbase_maturity_in_view(tx, store, rule)
        .map_err(|e| crate::storage::StorageError::ReadFailed(e.msg))
}

/// The confirmations the outputs of the confirmed transaction `txid` have at
/// the next block, at header height `next_block_height`, for relative
/// timelocks (`blockval::check_policy_spends_with_confirmations`), under the
/// connect path's own measure (`accept::confirmations_in_view`, the
/// coinbase-maturity measure, re-audit B1-T14): below the activation header
/// heights, from it selected-chain depth (the next block a child of the
/// applied tip, as for [`coinbase_maturity_for_next_block`]). `Ok(None)`:
/// `txid` is not confirmed. Shared by admission and the template self-check.
pub fn confirmations_for_next_block(
    store: &Storage,
    txid: &[u8; 32],
    next_block_height: u64,
) -> Result<Option<u64>, crate::reorg::ViewError> {
    use crate::accept::{confirmations_in_view, MaturityRule};
    let next_dag_height = || next_block_dag_height(store);
    let rule = if core::block_rules::rules_active_at(next_block_height, activation_height()) {
        MaturityRule::SelectedChainDepth(&next_dag_height)
    } else {
        MaturityRule::HeaderHeights(next_block_height)
    };
    confirmations_in_view(store, rule, txid)
}

/// The DAG height of the next block: the applied tip's (`tip_hash`, its DAG
/// record) plus one.
fn next_block_dag_height(store: &Storage) -> Result<u64, crate::reorg::ViewError> {
    use crate::reorg::{UtxoView, ViewError};
    let tip = store.get_meta("tip_hash").map_err(|e| ViewError::from_storage(&e))?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| ViewError::inconsistent("no applied tip pointer"))?;
    let data = store.view_dag_data(&tip)?
        .ok_or_else(|| ViewError::inconsistent(format!("applied tip {} has no DAG record", hex::encode(&tip[..8]))))?;
    Ok(data.height + 1)
}

/// The `coinbase_height` `getutxos` reports for an output of the coinbase
/// `txid` (`None`: not a coinbase), for wallets, which treat such an output
/// as spendable in the next block iff
/// `next_block_height - coinbase_height >= COINBASE_MATURITY`
/// (`wallet::send::utxo_row_spendable_at`,
/// `next_block_height` from `getdaginfo`): below the activation (of the next
/// block) the header height of the coinbase's block, as before; from it
/// `next_block_height` minus the coinbase's selected-chain depth at the next
/// block (re-audit B1-T14), so the same comparison applies the rule in
/// force. Both values are for the same next block.
pub fn coinbase_height_for_wallets(
    store: &Storage,
    txid: &[u8; 32],
    next_block_height: u64,
) -> Result<Option<u64>, crate::storage::StorageError> {
    use crate::reorg::UtxoView;
    let read = |e: crate::reorg::ViewError| crate::storage::StorageError::ReadFailed(e.msg);
    if next_block_height == 0 || !core::block_rules::rules_active_at(next_block_height, activation_height()) {
        return store.view_coinbase_height(txid).map_err(read);
    }
    let Some(cb) = crate::accept::coinbase_dag_height(store, txid).map_err(read)? else {
        return Ok(None);
    };
    let depth = next_block_dag_height(store).map_err(read)?.saturating_sub(cb);
    Ok(Some(next_block_height.saturating_sub(depth)))
}

/// Check and insert `tx` into `mempool`. On success returns the txid.
///
/// The final insert runs under the store's acceptance lock with a re-check
/// that every input is still available (unspent in the UTXO set, or an
/// output of a pooled transaction), so it cannot race a block connect that
/// spends an input and sweeps conflicts (MEM-3) between the check and the
/// insert. Conflicting pooled transactions are replaced when the full-RBF
/// rules hold (MEM-6). Under the same lock the height-dependent rules
/// (version rule and policy, the 64-byte rule, coinbase maturity:
/// [`check_tx_for_next_block`] and `core::check_coinbase_maturity`) are
/// re-checked against the pool's CURRENT next height (`Mempool::next_height`)
/// when it differs from the height the checks ran at: a block connected
/// meanwhile (whose post-connect eviction ran before this insert) cannot let
/// in a transaction invalid for the new next block. Signatures need no
/// re-check: a version that passes the policy at both heights selects the
/// same digest at both.
pub fn admit(
    store: &Storage,
    mempool: &Mempool,
    tx: Transaction,
    policy: &AdmissionPolicy,
) -> Result<[u8; 32], AdmissionError> {
    admit_gated(store, mempool, tx, policy, &mut |_| Ok(())).map(|o| o.txid)
}

/// [`admit`] with a [`SignatureGate`]; returns what the insertion did
/// (including any replaced transactions).
pub fn admit_gated(
    store: &Storage,
    mempool: &Mempool,
    tx: Transaction,
    policy: &AdmissionPolicy,
    gate: &mut SignatureGate<'_>,
) -> Result<AddOutcome, AdmissionError> {
    let w = wtxid(&tx);
    admit_gated_with_wtxid(store, mempool, tx, &w, policy, gate)
}

/// [`admit_gated`] with the transaction's wtxid already computed
/// (`tx_wtxid` MUST be [`wtxid`]`(&tx)`). B1-T19: the gossip relay hashes
/// each frame once ([`wtxid_of_canonical_bytes`]) instead of re-encoding and
/// re-hashing the whole transaction for the reject filter, the signature
/// cache key and the rejection record (three SHA3 passes over up to 400 kB
/// per frame, budget-refused frames included).
pub fn admit_gated_with_wtxid(
    store: &Storage,
    mempool: &Mempool,
    tx: Transaction,
    tx_wtxid: &[u8; 32],
    policy: &AdmissionPolicy,
    gate: &mut SignatureGate<'_>,
) -> Result<AddOutcome, AdmissionError> {
    // The filter's epoch BEFORE any state is read: a verdict computed against
    // a next height or a tip that changed meanwhile (the change clears the
    // filter and starts a new epoch) is not remembered, so it can never be
    // replayed at the new height (review finding).
    let epoch = mempool.recent_rejects_epoch();
    let fee = match check_transaction_gated_with_wtxid(store, Some(mempool), &tx, tx_wtxid, policy, gate) {
        Ok(fee) => fee,
        Err(e) => {
            if policy.use_reject_filter && e.is_cacheable() {
                mempool.note_rejected_in_epoch(*tx_wtxid, epoch);
            }
            return Err(e);
        }
    };
    let _guard = store.acceptance_lock();
    for inp in &tx.inputs {
        let confirmed = matches!(store.get_utxo(&inp.prev_txid, inp.prev_index), Ok(Some(_)));
        if !confirmed && mempool.pool_output(&inp.prev_txid, inp.prev_index).is_none() {
            return Err(AdmissionError::MissingInputs(format!(
                "UTXO {}:{} spent while admitting", hex::encode(&inp.prev_txid[..8]), inp.prev_index)));
        }
    }
    let current = mempool.next_height();
    if current != 0 && current != policy.next_block_height {
        check_tx_for_next_block(&tx, current).map_err(|e| AdmissionError::NonStandard(format!(
            "{e} (the next block moved to height {current} while the transaction was being checked)")))?;
        coinbase_maturity_for_next_block(store, &tx, current)
            .map_err(|e| AdmissionError::Pool(format!("storage: {}", e)))?
            .map_err(AdmissionError::Immature)?;
    }
    if policy.check_signatures {
        mempool.add_with_replacement(tx, fee).map_err(from_mempool_error)
    } else {
        // Re-admission (B1-T20): no per-transaction trim; the caller
        // (`reorg::reinject_disconnected`) trims once after the batch.
        mempool.add_readmitted(tx, fee).map_err(from_mempool_error)
    }
}

/// Parent txids of `tx` that are neither confirmed (an unspent output in
/// the UTXO set) nor pooled — what an orphan is waiting for (MEM-6).
pub fn missing_parents(store: &Storage, mempool: &Mempool, tx: &Transaction) -> std::collections::BTreeSet<[u8; 32]> {
    tx.inputs.iter()
        .filter(|i| {
            !matches!(store.get_utxo(&i.prev_txid, i.prev_index), Ok(Some(_)))
                && mempool.pool_output(&i.prev_txid, i.prev_index).is_none()
        })
        .map(|i| i.prev_txid)
        .collect()
}

/// True iff some input of `tx` is neither confirmed nor pooled. Stops at the
/// first missing input — use it wherever only emptiness of
/// [`missing_parents`] matters (the orphan re-try path, review finding).
pub fn has_missing_input(store: &Storage, mempool: &Mempool, tx: &Transaction) -> bool {
    tx.inputs.iter().any(|i| {
        !matches!(store.get_utxo(&i.prev_txid, i.prev_index), Ok(Some(_)))
            && mempool.pool_output(&i.prev_txid, i.prev_index).is_none()
    })
}

/// True iff the transaction `txid` is pooled or confirmed: one lookup per
/// recorded missing parent is the cheap pre-filter of the periodic orphan
/// sweep (a parent that is neither cannot have made its child admissible).
pub fn parent_available(store: &Storage, mempool: &Mempool, txid: &[u8; 32]) -> bool {
    mempool.contains(txid) || matches!(store.get_tx_location(txid), Ok(Some(_)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::core::TxInput;
    use sha3::{Digest, Sha3_256};

    thread_local! {
        /// Signature-cache keys computed on this thread ([`sig_cache_key`]).
        pub(crate) static SIG_KEYS_COMPUTED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn keys_computed() -> u64 {
        SIG_KEYS_COMPUTED.with(|c| c.get())
    }

    fn signed(sk: &[u8], pk: &[u8], prev: [u8; 32]) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 900_000, script_pubkey: vec![0x01; 20] }],
            locktime: 0,
        };
        let sig = crate::crypto::sign(sk, &tx.sighash(0, core::node_chain_id())).expect("sign");
        tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, pk);
        tx
    }

    /// Integration open issue: admission hashed the whole transaction twice
    /// for the verified-signature cache on a miss (`signatures_cached`, then
    /// `verify_input_scripts`). Now one key per admission, hit or miss; the
    /// gate (the relay's signature budget) is called only on a miss, and
    /// never for a transaction whose witnesses already fail (pubkey not
    /// matching the spent script): those cost the budget nothing.
    #[test]
    fn admission_computes_the_signature_cache_key_once_and_gates_only_signature_math() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = Storage::open(&tmp.path().join("db")).expect("storage");
        let (pk, sk) = crate::crypto::generate_keypair();
        let spk = Sha3_256::digest(&pk)[..20].to_vec();
        store.put_utxo(&[0x11; 32], 0, &TxOutput { value: 1_000_000, script_pubkey: spk }).unwrap();
        store.put_utxo(&[0x12; 32], 0, &TxOutput { value: 1_000_000, script_pubkey: vec![0x77; 20] }).unwrap();
        let policy = AdmissionPolicy::relay(1);
        let mut gate_calls = 0u32;

        let tx = signed(&sk, &pk, [0x11; 32]);
        let before = keys_computed();
        check_transaction_gated(&store, None, &tx, &policy, &mut |_| { gate_calls += 1; Ok(()) }).expect("valid");
        assert_eq!(keys_computed() - before, 1, "one key for the lookup AND the insertion");
        assert_eq!(gate_calls, 1, "a miss is gated");

        let before = keys_computed();
        check_transaction_gated(&store, None, &tx, &policy, &mut |_| { gate_calls += 1; Ok(()) }).expect("valid");
        assert_eq!(keys_computed() - before, 1);
        assert_eq!(gate_calls, 1, "a cache hit is not gated");

        // A spend of an output locked to another key: refused by the witness
        // check, before any key or gate.
        let wrong = signed(&sk, &pk, [0x12; 32]);
        let before = keys_computed();
        let err = check_transaction_gated(&store, None, &wrong, &policy, &mut |_| { gate_calls += 1; Ok(()) }).unwrap_err();
        assert!(matches!(&err, AdmissionError::Rejected(m) if m.contains("pubkey mismatch")), "{err}");
        assert_eq!(keys_computed() - before, 0);
        assert_eq!(gate_calls, 1, "the budget is not charged for a witness failure");

        // A refusing gate aborts before the signature math, with its error.
        let mut fresh = signed(&sk, &pk, [0x11; 32]);
        fresh.outputs[0].value -= 1; // another txid: a cache miss
        let sig = crate::crypto::sign(&sk, &fresh.sighash(0, core::node_chain_id())).unwrap();
        fresh.inputs[0].script_sig = Transaction::build_script_sig(&sig, &pk);
        let err = check_transaction_gated(&store, None, &fresh, &policy,
            &mut |_| Err(AdmissionError::RateLimited("budget".into()))).unwrap_err();
        assert_eq!(err, AdmissionError::RateLimited("budget".into()));
        assert!(!signatures_cached(&fresh, &[store.get_utxo(&[0x11; 32], 0).unwrap().unwrap()], 1));
    }

    /// Review finding (P4 merge): the witness verdict depends on whether the
    /// canonical witness is the consensus rule at the next block's height.
    #[test]
    fn non_canonical_witness_is_rejected_only_where_consensus_requires_it() {
        let (pk, sk) = crate::crypto::generate_keypair();
        let mut v3 = signed(&sk, &pk, [0x13; 32]);
        v3.version = core::sighash::TX_VERSION_V3;
        v3.inputs[0].script_sig.push(0); // trailing byte: non-canonical framing
        let mut v1 = v3.clone();
        v1.version = 1;
        const ACT: u64 = 10;
        // At/after the activation, version 3: consensus-invalid.
        for h in [ACT, ACT + 1] {
            let err = check_witnesses_for_next_block_at(&v3, h, ACT).unwrap_err();
            assert!(matches!(&err, AdmissionError::Rejected(m) if m.contains("bad-witness")), "{err}");
        }
        // Below it (version 3 is v2 there), or another version: policy.
        let err = check_witnesses_for_next_block_at(&v3, ACT - 1, ACT).unwrap_err();
        assert!(matches!(err, AdmissionError::NonStandard(_)), "{err}");
        let err = check_witnesses_for_next_block_at(&v1, ACT, ACT).unwrap_err();
        assert!(matches!(err, AdmissionError::NonStandard(_)), "{err}");
        assert_eq!(check_witnesses_for_next_block_at(&signed(&sk, &pk, [0x13; 32]), ACT, ACT), Ok(()));
    }
}
