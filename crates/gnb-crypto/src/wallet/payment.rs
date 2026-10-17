//! Payment construction shared by every wallet front end: the Rust
//! [`super::TxBuilder`] and [`super::Wallet`], the browser core
//! (`gnb-wallet-wasm`), `gnb-cli` and `gnb-wallet`.
//!
//! Audit findings addressed here:
//!
//! * **WAL-1** — the sighash does not commit to the value of the coins it
//!   spends, so a server that under-reports a UTXO value makes the wallet sign
//!   the difference away as fee. Two defences:
//!   - [`PrevTxs`]: when the creating transaction of a UTXO is available, its
//!     raw bytes are hashed and must reproduce the claimed txid; the value and
//!     script are then read from that transaction, and any disagreement with
//!     the server's claim aborts the payment before anything is signed.
//!     Outputs whose creating transaction cannot be fetched (the genesis
//!     carryover, bodies pruned on non-archival nodes) stay *unverified*; they
//!     are reported to the user, avoided by coin selection when possible and
//!     refused when [`PaymentOptions::require_verified_inputs`] is set. This
//!     check is needed only for version-1 (sighash v2) transactions. Every
//!     front end signs an unverified input only after an explicit
//!     acknowledgement: the web wallet's checkbox, the interactive
//!     confirmation of `gnb-cli send` / `gnb-wallet send` (or
//!     `--allow-unverified-inputs` with `--yes`), and, for the library path
//!     with no confirmation step, `WalletClient::send_payment_with` with
//!     `SendOptions::allow_unverified_inputs` (refused by default).
//!   - **Full fix: sighash v3.** From the hardening activation height the
//!     builder produces version-3 transactions whose signatures commit to
//!     every spent amount and `script_pubkey`
//!     (`core::sighash::SighashV3Precomputed`): a server that lies about a
//!     UTXO makes the wallet sign a transaction every node rejects, so
//!     nothing can be lost and the previous transactions need not be fetched.
//!     [`PaymentOptions::next_block_height`] (the node's `getdaginfo`
//!     `next_block_height`) selects the version; the builder refuses to sign
//!     without it.
//!   - [`FeePolicy`]: an absolute and a per-kB ceiling on the fee, enforced on
//!     the ACTUAL fee and size of the signed transaction. The consensus
//!     minimum is always allowed; anything above the ceilings needs an
//!     explicit override ([`FeePolicy::UNLIMITED`] or a custom policy).
//! * **WAL-6** — coin selection minimises the number of ~8.6 kB post-quantum
//!   inputs (smallest single input that covers the payment, else largest
//!   first with a smallest-sufficient last input), fees are size-aware from
//!   the consensus formula ([`tokenomics::min_tx_fee_sat`]), sub-dust change
//!   is reported as part of the fee, and there is one dust comparison
//!   ([`keeps_change`]).
//! * **CRY-1/CRY-2 (wallet side)** — every input is signed through a
//!   verifying signer ([`crate::crypto::sign_checked`] for sighash v2,
//!   [`crate::crypto::sign_bound_checked`] for v3), so the witness is
//!   canonical: enveloped signature, compact Falcon encoding, exact-length
//!   `script_sig`. Wallets sign with the hybrid suite 0x0001
//!   ([`crate::crypto::is_hybrid_public_key`]) and never produce 0x0002;
//!   P5-S: a conservative suite-0x0003 key signs only for a block at/after
//!   the second hardening height of its chain ([`check_signing_suite`]).

use super::Utxo;
use crate::core::sighash::{self, SighashV3Precomputed, SighashVersion};
use crate::core::{activation, tokenomics, ChainId, Transaction, TxInput, TxOutput, DUST_THRESHOLD};
use std::collections::{BTreeSet, HashMap};

/// A verifying signer of transaction digests: `(digest, version)` -> the
/// enveloped signature under the binding of `version` (see [`build_payment`]).
pub type DigestSigner<'a> = dyn Fn(&[u8; 32], SighashVersion) -> Result<Vec<u8>, String> + 'a;

/// Largest transaction the node's mempool admits (`mempool::MAX_TX_SIZE`).
pub const MAX_STANDARD_TX_BYTES: usize = 400 * 1024;

/// Upper bound on the raw size of a previous transaction accepted for
/// verification (four times the mempool limit; blocks may hold larger ones
/// only in principle).
pub const MAX_PREV_TX_BYTES: usize = 4 * MAX_STANDARD_TX_BYTES;

/// Smallest change output a wallet creates. A change amount below this would
/// be a consensus-invalid dust output (`Block::validate_dust`) and is added
/// to the fee instead.
pub const DUST_THRESHOLD_SATS: u64 = DUST_THRESHOLD;

/// The single dust comparison used by every builder: change of
/// [`DUST_THRESHOLD_SATS`] or more becomes an output, anything less is fee.
pub const fn keeps_change(change: u64) -> bool {
    change >= DUST_THRESHOLD_SATS
}

// ── Fee ceiling ──────────────────────────────────────────────────────────────

/// Maximum-fee guard (WAL-1). Checked against the actual fee and the actual
/// serialized size of the signed transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    /// Absolute ceiling on the fee, base units.
    pub max_fee_sat: u64,
    /// Ceiling on the fee per 1,000 bytes of signed transaction.
    pub max_fee_rate_sat_per_kb: u64,
}

impl FeePolicy {
    /// Default absolute ceiling: 0.02 GNB (more than twice the consensus
    /// minimum of a maximum-size 400 kB transaction).
    pub const DEFAULT_MAX_FEE_SAT: u64 = 2_000_000;
    /// Default rate ceiling: 50 × the consensus minimum rate (0.001 GNB/kB).
    pub const DEFAULT_MAX_FEE_RATE_SAT_PER_KB: u64 = 50 * tokenomics::MIN_FEE_RATE_SAT_PER_KB;

    /// The guard every front end applies unless the user overrides it.
    pub const DEFAULT: FeePolicy = FeePolicy {
        max_fee_sat: Self::DEFAULT_MAX_FEE_SAT,
        max_fee_rate_sat_per_kb: Self::DEFAULT_MAX_FEE_RATE_SAT_PER_KB,
    };

    /// No ceiling. Only for an explicit user override.
    pub const UNLIMITED: FeePolicy = FeePolicy { max_fee_sat: u64::MAX, max_fee_rate_sat_per_kb: u64::MAX };

    /// Policy with a user-chosen absolute ceiling (the rate ceiling is lifted
    /// to at least the rate the absolute ceiling implies for this size, so an
    /// explicit `--max-fee` is honoured as written).
    pub const fn with_max_fee(max_fee_sat: u64) -> FeePolicy {
        FeePolicy { max_fee_sat, max_fee_rate_sat_per_kb: u64::MAX }
    }

    /// `Ok` when `fee` is acceptable for a signed transaction of `size_bytes`.
    /// The consensus minimum for that size is always acceptable.
    pub fn check(&self, fee: u64, size_bytes: usize) -> Result<(), String> {
        if fee <= tokenomics::min_tx_fee_sat(size_bytes) {
            return Ok(());
        }
        if fee > self.max_fee_sat {
            return Err(format!(
                "fee {fee} sat exceeds the maximum-fee guard of {} sat; refusing to sign \
                 (override the guard explicitly if this fee is intended)",
                self.max_fee_sat
            ));
        }
        let cap = (size_bytes as u128)
            .saturating_mul(self.max_fee_rate_sat_per_kb as u128)
            .div_ceil(1000);
        if fee as u128 > cap {
            return Err(format!(
                "fee {fee} sat for {size_bytes} bytes exceeds the guard of {} sat/kB; \
                 refusing to sign (override the guard explicitly if this fee is intended)",
                self.max_fee_rate_sat_per_kb
            ));
        }
        Ok(())
    }
}

impl Default for FeePolicy {
    fn default() -> Self { Self::DEFAULT }
}

/// How the fee of a payment is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeChoice {
    /// Exactly this fee plus any sub-dust change (legacy builder semantics;
    /// not raised to the consensus minimum).
    Exact(u64),
    /// max(requested, consensus minimum for the signed size).
    AtLeast(u64),
    /// max(consensus minimum, size × rate / 1000), rate in base units per kB.
    Rate(u64),
}

impl FeeChoice {
    /// Size-aware consensus minimum.
    pub const AUTO: FeeChoice = FeeChoice::AtLeast(0);

    fn fee_for(self, size_upper_bound: usize) -> u64 {
        let min = tokenomics::min_tx_fee_sat(size_upper_bound);
        match self {
            FeeChoice::Exact(fee) => fee,
            FeeChoice::AtLeast(fee) => fee.max(min),
            FeeChoice::Rate(rate) => {
                let by_rate = (size_upper_bound as u128).saturating_mul(rate as u128).div_ceil(1000);
                min.max(u64::try_from(by_rate).unwrap_or(u64::MAX))
            }
        }
    }
}

// ── Previous-transaction verification ────────────────────────────────────────

/// Previous transactions fetched to verify claimed UTXO values (WAL-1).
#[derive(Clone, Debug, Default)]
pub struct PrevTxs {
    txs: HashMap<[u8; 32], Transaction>,
}

impl PrevTxs {
    pub fn new() -> Self { Self::default() }

    /// Add the raw wire bytes (`Transaction::to_wire_bytes(true)`) of the
    /// transaction claimed to have id `txid`. The id is recomputed from the
    /// bytes; a mismatch means the source lied and is an error.
    pub fn insert_raw(&mut self, txid: &[u8; 32], raw: &[u8]) -> Result<(), String> {
        if raw.len() > MAX_PREV_TX_BYTES {
            return Err(format!("previous transaction {} is implausibly large", hex::encode(txid)));
        }
        let tx = Transaction::from_wire_bytes(raw)
            .map_err(|e| format!("previous transaction {} does not decode: {e}", hex::encode(txid)))?;
        if &tx.txid() != txid {
            return Err(format!(
                "server returned a transaction that does not hash to {}; refusing to trust it",
                hex::encode(txid)
            ));
        }
        self.txs.insert(*txid, tx);
        Ok(())
    }

    /// Hex form of [`Self::insert_raw`].
    pub fn insert_hex(&mut self, txid_hex: &str, raw_hex: &str) -> Result<(), String> {
        let txid: [u8; 32] = hex::decode(txid_hex).ok().and_then(|b| b.try_into().ok())
            .ok_or_else(|| "previous transaction id must be 32 bytes of hex".to_string())?;
        if raw_hex.len() > 2 * MAX_PREV_TX_BYTES {
            return Err(format!("previous transaction {txid_hex} is implausibly large"));
        }
        let raw = hex::decode(raw_hex).map_err(|_| format!("previous transaction {txid_hex} is not hex"))?;
        self.insert_raw(&txid, &raw)
    }

    pub fn len(&self) -> usize { self.txs.len() }
    pub fn is_empty(&self) -> bool { self.txs.is_empty() }
    pub fn contains(&self, txid: &[u8; 32]) -> bool { self.txs.contains_key(txid) }

    /// `Ok(true)` when the claimed UTXO matches its verified creating
    /// transaction, `Ok(false)` when that transaction is not available, `Err`
    /// when the claim contradicts it.
    pub fn check(&self, utxo: &Utxo) -> Result<bool, String> {
        let Some(tx) = self.txs.get(&utxo.txid) else { return Ok(false) };
        let actual = tx.outputs.get(utxo.index as usize).ok_or_else(|| format!(
            "server claimed output {}:{} which does not exist; refusing to sign",
            hex::encode(utxo.txid), utxo.index
        ))?;
        if actual.value != utxo.output.value || actual.script_pubkey != utxo.output.script_pubkey {
            return Err(format!(
                "server reported {} sat for {}:{} but the transaction says {} sat \
                 (or a different owner); refusing to sign",
                utxo.output.value, hex::encode(utxo.txid), utxo.index, actual.value
            ));
        }
        Ok(true)
    }
}

// ── Options and result ───────────────────────────────────────────────────────

/// Payment options. `Default` = size-aware consensus-minimum fee, default
/// fee guard, no previous transactions, unverified inputs allowed.
#[derive(Clone, Copy, Debug)]
pub struct PaymentOptions<'a> {
    pub fee: FeeChoice,
    pub fee_policy: FeePolicy,
    pub prev_txs: Option<&'a PrevTxs>,
    /// Refuse to spend any input whose value could not be verified (version-1
    /// transactions; a version-3 signature commits to every spent value).
    pub require_verified_inputs: bool,
    pub max_tx_bytes: usize,
    /// Header height of the block the payment targets: the node's `getdaginfo`
    /// `next_block_height` (the height its mempool admission and block
    /// template check against; `tip_height` + 1 from a node that predates
    /// that field, see `send::next_block_height_from_daginfo`). With the
    /// hardening activation height of the
    /// wallet's chain it selects the transaction version
    /// (`core::sighash::tx_version_for_height`): 3 and sighash v3 at/after the
    /// activation, 1 and sighash v2 below it. `None` (the default) refuses to
    /// sign: a wrong guess makes a transaction the network rejects.
    pub next_block_height: Option<u64>,
}

impl Default for PaymentOptions<'_> {
    fn default() -> Self {
        Self {
            fee: FeeChoice::AUTO,
            fee_policy: FeePolicy::DEFAULT,
            prev_txs: None,
            require_verified_inputs: false,
            max_tx_bytes: MAX_STANDARD_TX_BYTES,
            next_block_height: None,
        }
    }
}

impl PaymentOptions<'_> {
    /// Transaction version these options produce for `chain_id`.
    pub fn tx_version(&self, chain_id: ChainId) -> Result<u32, String> {
        let next = self.next_block_height.ok_or_else(|| {
            "the height of the next block is unknown; ask the node (getdaginfo: next_block_height) \
             before signing".to_string()
        })?;
        Ok(sighash::tx_version_for_height(next, activation::hardening_activation_height_for_signer(chain_id)))
    }
}

/// Whether a payment for `chain_id` targeting `next_block_height` is a
/// version-3 transaction, whose signatures commit to the spent amounts (the
/// previous transactions need not be fetched, WAL-1).
pub fn amounts_committed_at(next_block_height: u64, chain_id: ChainId) -> bool {
    sighash::tx_version_for_height(next_block_height, activation::hardening_activation_height_for_signer(chain_id))
        == sighash::TX_VERSION_V3
}

/// A signed payment and what it actually does.
#[derive(Clone, Debug)]
pub struct BuiltPayment {
    pub tx: Transaction,
    /// Amount paid to the recipient.
    pub amount: u64,
    /// Actual fee: inputs − outputs, including any sub-dust change.
    pub fee: u64,
    /// Part of `fee` that is change below the dust threshold.
    pub dust_to_fee: u64,
    /// Change returned to the wallet (0 when there is no change output).
    pub change: u64,
    /// Sum of the spent inputs (as verified or claimed).
    pub inputs_total: u64,
    /// Signed wire size in bytes.
    pub size: usize,
    /// Inputs whose value was verified against their creating transaction,
    /// or, for a version-3 transaction, every input (its signature commits to
    /// the spent value, so a wrong claim invalidates the transaction).
    pub verified_inputs: usize,
    /// Inputs whose value comes only from the server's claim (always 0 for
    /// version 3).
    pub unverified_inputs: usize,
    /// `true` for a version-3 (sighash v3) transaction: the signatures commit
    /// to every spent amount and script.
    pub amounts_committed: bool,
}

// ── Size estimation ──────────────────────────────────────────────────────────

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        _ if n as u64 <= 0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// Upper bound on the signed wire size: every signature at its maximum
/// encoded length for the key's suite (P5-S: 9,322 bytes for a conservative
/// suite-0x0003 key, `crypto::max_signature_len_for_public_key_len`).
pub fn signed_size_upper_bound(n_inputs: usize, output_spk_lens: &[usize], public_key_len: usize) -> usize {
    let script_sig = 8 + crate::crypto::max_signature_len_for_public_key_len(public_key_len) + public_key_len;
    let per_input = 32 + 4 + varint_len(script_sig) + script_sig + 4;
    let outputs: usize = output_spk_lens.iter().map(|l| 8 + varint_len(*l) + l).sum();
    4 + varint_len(n_inputs) + n_inputs.saturating_mul(per_input)
        + varint_len(output_spk_lens.len()) + outputs + 4
}

// ── Selection ────────────────────────────────────────────────────────────────

struct Plan {
    inputs: Vec<usize>,
    change: u64,
    fee: u64,
    dust_to_fee: u64,
}

/// Choose inputs among `candidates` (indices into `utxos`). Minimises the
/// input count: the smallest single input that covers the payment, else
/// largest-first with the smallest sufficient last input.
fn select(
    utxos: &[Utxo],
    candidates: &[usize],
    amount: u64,
    fee_for: &dyn Fn(usize, bool) -> u64,
) -> Option<Vec<usize>> {
    let mut asc: Vec<usize> = candidates.to_vec();
    asc.sort_by(|&a, &b| {
        let (ua, ub) = (&utxos[a], &utxos[b]);
        ua.output.value.cmp(&ub.output.value)
            .then(ua.txid.cmp(&ub.txid))
            .then(ua.index.cmp(&ub.index))
    });
    let need = |n: usize| amount.checked_add(fee_for(n, false));

    // 1. One input: the smallest that covers (exact match or least change).
    let need1 = need(1)?;
    if let Some(&i) = asc.iter().find(|&&i| utxos[i].output.value >= need1) {
        return Some(vec![i]);
    }

    // 2. Largest first; the last slot takes the smallest sufficient coin.
    let mut chosen: Vec<usize> = Vec::new();
    let mut total: u64 = 0;
    let mut remaining: Vec<usize> = asc.clone();
    while let Some(&largest) = remaining.last() {
        let n = chosen.len() + 1;
        let target = need(n)?;
        let missing = target.saturating_sub(total);
        if let Some(pos) = remaining.iter().position(|&i| utxos[i].output.value >= missing) {
            chosen.push(remaining[pos]);
            return Some(chosen);
        }
        remaining.pop();
        chosen.push(largest);
        total = total.checked_add(utxos[largest].output.value)?;
    }
    None
}

fn plan(
    utxos: &[Utxo],
    candidates: &[usize],
    amount: u64,
    to_spk_len: usize,
    change_spk_len: usize,
    public_key_len: usize,
    fee: FeeChoice,
) -> Option<Plan> {
    let fee_for = |n: usize, with_change: bool| {
        let outputs: &[usize] = if with_change { &[to_spk_len, change_spk_len] } else { &[to_spk_len] };
        fee.fee_for(signed_size_upper_bound(n, outputs, public_key_len))
    };
    let inputs = select(utxos, candidates, amount, &fee_for)?;
    let total = inputs.iter().try_fold(0u64, |t, &i| t.checked_add(utxos[i].output.value))?;
    let n = inputs.len();
    let fee_with_change = fee_for(n, true);
    let change = total.checked_sub(amount)?.checked_sub(fee_with_change);
    match change {
        Some(change) if keeps_change(change) => {
            Some(Plan { inputs, change, fee: fee_with_change, dust_to_fee: 0 })
        }
        _ => {
            let base_fee = fee_for(n, false);
            let fee = total.checked_sub(amount)?;
            Some(Plan { inputs, change: 0, fee, dust_to_fee: fee.saturating_sub(base_fee) })
        }
    }
}

/// Validate the UTXO list, verify what can be verified and return the
/// candidate order (verified inputs are preferred when there are any).
fn prepare(
    utxos: &[Utxo],
    own_spk: &[u8],
    prev_txs: Option<&PrevTxs>,
) -> Result<(Vec<bool>, u64), String> {
    let mut outpoints = BTreeSet::new();
    let mut total: u64 = 0;
    let mut verified = Vec::with_capacity(utxos.len());
    for utxo in utxos {
        if !outpoints.insert((utxo.txid, utxo.index)) {
            return Err("duplicate UTXO outpoint".into());
        }
        if utxo.output.script_pubkey != own_spk {
            return Err(format!(
                "UTXO {}:{} does not belong to this wallet",
                hex::encode(utxo.txid), utxo.index
            ));
        }
        total = total.checked_add(utxo.output.value).ok_or("UTXO value total overflow")?;
        verified.push(match prev_txs {
            Some(p) => p.check(utxo)?,
            None => false,
        });
    }
    Ok((verified, total))
}

/// Inputs a payment would spend, chosen on the claimed values. Front ends
/// call this first, fetch the creating transactions of the returned
/// outpoints into a [`PrevTxs`], then call [`build_payment`] with them.
pub fn plan_payment_inputs(
    utxos: &[Utxo],
    amount: u64,
    public_key_len: usize,
    fee: FeeChoice,
) -> Result<Vec<([u8; 32], u32)>, String> {
    let candidates: Vec<usize> = (0..utxos.len()).collect();
    let total = utxos.iter().try_fold(0u64, |t, u| t.checked_add(u.output.value))
        .ok_or("UTXO value total overflow")?;
    let plan = plan(utxos, &candidates, amount, 20, 20, public_key_len, fee)
        .ok_or_else(|| insufficient(total, amount))?;
    Ok(plan.inputs.iter().map(|&i| (utxos[i].txid, utxos[i].index)).collect())
}

/// Whether a wallet may sign a payment with `public_key` for the block at
/// [`PaymentOptions::next_block_height`] of `chain_id`: a hybrid key
/// always (CRY-2: never the single-algorithm suite 0x0002); P5-S: a
/// conservative suite-0x0003 key only at/after the chain's second hardening
/// height (`crypto::KeySuite::check_allowed_at`), where consensus accepts its
/// signature.
pub fn check_signing_suite(public_key: &[u8], chain_id: ChainId, opts: &PaymentOptions<'_>) -> Result<(), String> {
    use crate::crypto::KeySuite;
    match KeySuite::of_public_key(public_key) {
        Some(KeySuite::Hybrid) => Ok(()),
        Some(KeySuite::Conservative) => {
            let next = opts.next_block_height.ok_or_else(|| {
                "the height of the next block is unknown; ask the node (getdaginfo: next_block_height) \
                 before signing".to_string()
            })?;
            KeySuite::Conservative.check_allowed_at(next, activation::hardening2_activation_height_for_signer(chain_id))
        }
        None => Err("wallets sign only with the hybrid ML-DSA-65 + Falcon-1024 suite (0x0001) or, from the \
                     second hardening height, the conservative suite (0x0003); this key is neither".into()),
    }
}

fn insufficient(have: u64, amount: u64) -> String {
    format!("insufficient funds: have {have} sats, need {amount} sats plus the fee")
}

/// Build and sign a payment of `amount` to `to_spk`, change to `own_spk`.
///
/// `sign(digest, version)` returns the enveloped signature of a 32-byte
/// digest under the binding of `version` and must verify it (see
/// [`crate::crypto::sign_checked`] for [`SighashVersion::V2`] and
/// [`crate::crypto::sign_bound_checked`] for [`SighashVersion::V3`]);
/// `public_key` goes into every `script_sig`. The transaction version follows
/// [`PaymentOptions::next_block_height`].
#[allow(clippy::too_many_arguments)]
pub fn build_payment(
    utxos: &[Utxo],
    to_spk: &[u8],
    amount: u64,
    own_spk: &[u8],
    public_key: &[u8],
    chain_id: ChainId,
    opts: &PaymentOptions<'_>,
    sign: &DigestSigner<'_>,
) -> Result<BuiltPayment, String> {
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    if to_spk.len() != 20 {
        return Err("destination address hash must contain exactly 20 bytes".into());
    }
    if utxos.is_empty() {
        return Err(insufficient(0, amount));
    }
    check_signing_suite(public_key, chain_id, opts)?;
    let version = opts.tx_version(chain_id)?;
    let amounts_committed = SighashVersion::for_tx_version(version) == SighashVersion::V3;
    let (verified, total) = prepare(utxos, own_spk, opts.prev_txs)?;

    // Version 1: prefer inputs whose value was verified, fall back to every
    // input. Version 3: every input is equivalent (the signature commits to
    // its value).
    let verified_only: Vec<usize> = (0..utxos.len()).filter(|&i| verified[i]).collect();
    let all: Vec<usize> = (0..utxos.len()).collect();
    let plan_with = |c: &[usize]| plan(utxos, c, amount, to_spk.len(), own_spk.len(), public_key.len(), opts.fee);
    let plan = (!amounts_committed && !verified_only.is_empty()).then(|| plan_with(&verified_only)).flatten()
        .or_else(|| plan_with(&all))
        .ok_or_else(|| insufficient(total, amount))?;

    let verified_inputs = if amounts_committed {
        plan.inputs.len()
    } else {
        plan.inputs.iter().filter(|&&i| verified[i]).count()
    };
    let unverified_inputs = plan.inputs.len() - verified_inputs;
    if opts.require_verified_inputs && unverified_inputs > 0 {
        return Err(format!(
            "{unverified_inputs} input(s) could not be verified against their creating \
             transaction (carryover or pruned history); refusing to sign"
        ));
    }

    let inputs: Vec<TxInput> = plan.inputs.iter().map(|&i| TxInput {
        prev_txid: utxos[i].txid,
        prev_index: utxos[i].index,
        script_sig: Vec::new(),
        sequence: u32::MAX,
    }).collect();
    let mut outputs = vec![TxOutput { value: amount, script_pubkey: to_spk.to_vec() }];
    if plan.change > 0 {
        outputs.push(TxOutput { value: plan.change, script_pubkey: own_spk.to_vec() });
    }
    let mut tx = Transaction { version, inputs, outputs, locktime: 0 };

    // Guard before signing on the upper-bound size, then again on the
    // actual signed size below.
    let spk_lens: Vec<usize> = tx.outputs.iter().map(|o| o.script_pubkey.len()).collect();
    let bound = signed_size_upper_bound(tx.inputs.len(), &spk_lens, public_key.len());
    opts.fee_policy.check(plan.fee, bound)?;

    let spent: Vec<TxOutput> = plan.inputs.iter().map(|&i| utxos[i].output.clone()).collect();
    sign_inputs(&mut tx, &spent, public_key, chain_id, sign)?;

    let size = tx.to_wire_bytes(true).len();
    if size > opts.max_tx_bytes {
        return Err(format!(
            "this payment needs {} inputs ({size} bytes), above the {} kB limit; \
             send a smaller amount and repeat",
            tx.inputs.len(), opts.max_tx_bytes / 1024
        ));
    }
    let inputs_total = plan.inputs.iter().map(|&i| utxos[i].output.value).sum::<u64>();
    let outputs_total = tx.total_output().ok_or("output value overflow")?;
    let fee = inputs_total.checked_sub(outputs_total).ok_or("outputs exceed inputs")?;
    debug_assert_eq!(fee, plan.fee);
    opts.fee_policy.check(fee, size)?;
    if !matches!(opts.fee, FeeChoice::Exact(_)) && fee < tokenomics::min_tx_fee_sat(size) {
        return Err(format!("fee {fee} below the consensus minimum for {size} bytes"));
    }

    Ok(BuiltPayment {
        tx,
        amount,
        fee,
        dust_to_fee: plan.dust_to_fee,
        change: plan.change,
        inputs_total,
        size,
        verified_inputs,
        unverified_inputs,
        amounts_committed,
    })
}

/// Sign every input of `tx` (spending `spent`, one output per input, in
/// order) under the digest its version selects, and write canonical
/// witnesses. Version 3 computes the per-transaction hashes once (linear in
/// the transaction size) and signs each input's digest, which commits to the
/// suite of `public_key`.
pub fn sign_inputs(
    tx: &mut Transaction,
    spent: &[TxOutput],
    public_key: &[u8],
    chain_id: ChainId,
    sign: &DigestSigner<'_>,
) -> Result<(), String> {
    if spent.len() != tx.inputs.len() {
        return Err(format!("{} spent outputs for {} inputs", spent.len(), tx.inputs.len()));
    }
    let version = SighashVersion::for_tx_version(tx.version);
    let sigs: Vec<Vec<u8>> = match version {
        SighashVersion::V2 => (0..tx.inputs.len())
            .map(|i| sign(&tx.sighash(i, chain_id), version))
            .collect::<Result<_, _>>()?,
        SighashVersion::V3 => {
            // P5-S: every suite a wallet signs with (the callers decided the
            // key's suite is valid at the target height: `check_signing_suite`).
            let suite = crate::crypto::public_key_suite_under(public_key, crate::crypto::SuiteRules::HARDENING2)
                .ok_or("public key has no recognised signature suite")?;
            let pre = SighashV3Precomputed::new(tx, spent).map_err(|e| e.to_string())?;
            (0..tx.inputs.len())
                .map(|i| sign(&pre.digest(i, suite, chain_id).map_err(|e| e.to_string())?, version))
                .collect::<Result<_, _>>()?
        }
    };
    for (input, sig) in tx.inputs.iter_mut().zip(sigs) {
        input.script_sig = Transaction::build_script_sig(&sig, public_key);
        if version == SighashVersion::V3 {
            // The consensus witness rule of version 3 (format only).
            sighash::canonical_witness_under(&input.script_sig, crate::crypto::SuiteRules::HARDENING2)?;
        }
    }
    Ok(())
}

/// Fee-guard check for an UNSIGNED transaction (e.g. `Wallet::build_tx`),
/// using the signed-size upper bound for the rate ceiling.
pub fn check_unsigned_fee(tx: &Transaction, fee: u64, public_key_len: usize, policy: &FeePolicy) -> Result<(), String> {
    let spks: Vec<usize> = tx.outputs.iter().map(|o| o.script_pubkey.len()).collect();
    policy.check(fee, signed_size_upper_bound(tx.inputs.len(), &spks, public_key_len))
}

/// Coin selection for an unsigned build with an exact fee: returns the chosen
/// inputs (indices into `utxos`) and the change.
pub(crate) fn select_exact_fee(
    utxos: &[Utxo],
    amount: u64,
    fee: u64,
    public_key_len: usize,
) -> Option<(Vec<usize>, u64)> {
    let candidates: Vec<usize> = (0..utxos.len()).collect();
    let plan = plan(utxos, &candidates, amount, 20, 20, public_key_len, FeeChoice::Exact(fee))?;
    Some((plan.inputs, plan.change))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{generate_keypair, Keypair};

    const SAT: u64 = 100_000_000;

    fn utxo(kp: &Keypair, tag: u8, value: u64) -> Utxo {
        Utxo { txid: [tag; 32], index: 0, output: TxOutput { value, script_pubkey: kp.address_bytes() } }
    }

    /// Mainnet payment; without an explicit next block height the tests below
    /// target height 1 (far below the mainnet activation: version 1, sighash v2).
    fn build(kp: &Keypair, utxos: &[Utxo], amount: u64, opts: &PaymentOptions<'_>) -> Result<BuiltPayment, String> {
        let opts = PaymentOptions { next_block_height: opts.next_block_height.or(Some(1)), ..*opts };
        build_payment(utxos, &[5u8; 20], amount, &kp.address_bytes(), &kp.public_key,
            ChainId::Mainnet, &opts, &|h, v| kp.sign_tx_digest(h, v))
    }

    /// A previous transaction paying `value` to the keypair, and the UTXO
    /// pointing at it.
    fn funded(kp: &Keypair, value: u64) -> (Transaction, Utxo) {
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0x77; 32], prev_index: 0, script_sig: vec![1, 2, 3], sequence: u32::MAX }],
            outputs: vec![
                TxOutput { value: 3 * SAT, script_pubkey: vec![9; 20] },
                TxOutput { value, script_pubkey: kp.address_bytes() },
            ],
            locktime: 0,
        };
        let u = Utxo { txid: tx.txid(), index: 1, output: TxOutput { value, script_pubkey: kp.address_bytes() } };
        (tx, u)
    }

    #[test]
    fn fee_policy_allows_the_minimum_and_caps_the_rest() {
        let p = FeePolicy::DEFAULT;
        assert!(p.check(tokenomics::min_tx_fee_sat(8_600), 8_600).is_ok());
        assert!(p.check(50_000, 8_600).is_ok());
        assert!(p.check(99 * SAT, 8_600).unwrap_err().contains("maximum-fee guard"));
        // Under the absolute cap but far above the per-kB cap.
        assert!(p.check(1_500_000, 8_600).unwrap_err().contains("sat/kB"));
        // The consensus minimum of the largest transaction is allowed.
        assert!(p.check(tokenomics::min_tx_fee_sat(MAX_STANDARD_TX_BYTES), MAX_STANDARD_TX_BYTES).is_ok());
        assert!(FeePolicy::UNLIMITED.check(99 * SAT, 8_600).is_ok());
        assert!(FeePolicy::with_max_fee(99 * SAT).check(99 * SAT, 8_600).is_ok());
    }

    /// WAL-1 regression: a server that under-reports a UTXO value is caught
    /// when the creating transaction is supplied, before anything is signed.
    #[test]
    fn lied_utxo_value_is_detected_against_the_previous_transaction() {
        let kp = generate_keypair(false);
        let (prev, honest) = funded(&kp, 100 * SAT);
        let mut prevs = PrevTxs::new();
        prevs.insert_raw(&honest.txid, &prev.to_wire_bytes(true)).unwrap();

        let mut lied = honest.clone();
        lied.output.value = SAT + 50_000;
        let opts = PaymentOptions { prev_txs: Some(&prevs), ..Default::default() };
        let err = build(&kp, &[lied], SAT, &opts).unwrap_err();
        assert!(err.contains("refusing to sign"), "{err}");

        // The honest claim verifies and pays the change back.
        let paid = build(&kp, &[honest], SAT, &opts).unwrap();
        assert_eq!(paid.verified_inputs, 1);
        assert_eq!(paid.unverified_inputs, 0);
        assert_eq!(paid.change, 100 * SAT - SAT - paid.fee);
        assert!(paid.fee < 100_000);
    }

    #[test]
    fn previous_transaction_must_hash_to_the_claimed_txid() {
        let kp = generate_keypair(false);
        let (prev, honest) = funded(&kp, 100 * SAT);
        let mut forged = prev.clone();
        forged.outputs[1].value = SAT;
        let mut prevs = PrevTxs::new();
        assert!(prevs.insert_raw(&honest.txid, &forged.to_wire_bytes(true)).unwrap_err().contains("does not hash"));
        assert!(prevs.is_empty());
        assert!(prevs.insert_hex(&hex::encode(honest.txid), &hex::encode(prev.to_wire_bytes(true))).is_ok());
        assert!(prevs.contains(&honest.txid));
        // A claimed output index that does not exist is a lie too.
        let mut bogus = honest;
        bogus.index = 7;
        assert!(prevs.check(&bogus).is_err());
    }

    #[test]
    fn unverified_inputs_are_reported_and_refusable() {
        let kp = generate_keypair(false);
        let u = utxo(&kp, 1, 2 * SAT);
        let paid = build(&kp, std::slice::from_ref(&u), SAT, &PaymentOptions::default()).unwrap();
        assert_eq!(paid.unverified_inputs, 1);
        let strict = PaymentOptions { require_verified_inputs: true, ..Default::default() };
        assert!(build(&kp, &[u], SAT, &strict).unwrap_err().contains("could not be verified"));
    }

    #[test]
    fn verified_inputs_are_preferred_by_selection() {
        let kp = generate_keypair(false);
        let (prev, verified) = funded(&kp, 5 * SAT);
        let unverified = utxo(&kp, 2, 3 * SAT); // the smaller single cover
        let mut prevs = PrevTxs::new();
        prevs.insert_raw(&verified.txid, &prev.to_wire_bytes(true)).unwrap();
        let opts = PaymentOptions { prev_txs: Some(&prevs), ..Default::default() };
        let paid = build(&kp, &[unverified, verified.clone()], 2 * SAT, &opts).unwrap();
        assert_eq!(paid.tx.inputs.len(), 1);
        assert_eq!(paid.tx.inputs[0].prev_txid, verified.txid);
        assert_eq!(paid.unverified_inputs, 0);
    }

    /// WAL-6 regression: one 10 GNB coin is preferred over six 0.2 GNB coins.
    #[test]
    fn selection_minimises_inputs_and_fee_is_size_aware() {
        let kp = generate_keypair(false);
        let mut utxos = vec![utxo(&kp, 0xEE, 10 * SAT)];
        for i in 0..10u8 { utxos.push(utxo(&kp, i, SAT / 5)); }
        let paid = build(&kp, &utxos, SAT, &PaymentOptions::default()).unwrap();
        assert_eq!(paid.tx.inputs.len(), 1);
        assert!(paid.size < 10_000);
        assert!(paid.fee >= tokenomics::min_tx_fee_sat(paid.size));
        // The fee is computed from an upper bound, so it is never far above the minimum.
        assert!(paid.fee - tokenomics::min_tx_fee_sat(paid.size) < 2_000);
        assert_eq!(paid.inputs_total - paid.amount - paid.change, paid.fee);

        // Without a single covering coin: largest first, smallest sufficient last.
        let utxos = vec![utxo(&kp, 1, SAT), utxo(&kp, 2, SAT / 2), utxo(&kp, 3, 3 * SAT / 5), utxo(&kp, 4, SAT / 10)];
        let paid = build(&kp, &utxos, 3 * SAT / 2, &PaymentOptions::default()).unwrap();
        let spent: Vec<u8> = paid.tx.inputs.iter().map(|i| i.prev_txid[0]).collect();
        assert_eq!(spent, vec![1, 3]);
    }

    /// WAL-6 regression: sub-dust change is reported as part of the fee, and
    /// change of exactly the dust threshold is kept (one comparison everywhere).
    #[test]
    fn dust_change_is_reported_and_threshold_is_inclusive() {
        let kp = generate_keypair(false);
        let fee = 50_000;
        let opts = PaymentOptions { fee: FeeChoice::Exact(fee), ..Default::default() };
        let paid = build(&kp, &[utxo(&kp, 1, SAT + fee + 545)], SAT, &opts).unwrap();
        assert_eq!(paid.tx.outputs.len(), 1);
        assert_eq!(paid.fee, fee + 545);
        assert_eq!(paid.dust_to_fee, 545);
        let paid = build(&kp, &[utxo(&kp, 1, SAT + fee + 546)], SAT, &opts).unwrap();
        assert_eq!(paid.tx.outputs.len(), 2);
        assert_eq!(paid.change, 546);
        assert_eq!(paid.fee, fee);
        assert!(keeps_change(DUST_THRESHOLD_SATS) && !keeps_change(DUST_THRESHOLD_SATS - 1));
    }

    /// WAL-1: the guard applies to the actual fee, including a requested one.
    #[test]
    fn requested_fee_above_the_guard_is_refused_unless_overridden() {
        let kp = generate_keypair(false);
        let u = utxo(&kp, 1, 100 * SAT);
        let greedy = PaymentOptions { fee: FeeChoice::AtLeast(99 * SAT - 1), ..Default::default() };
        assert!(build(&kp, std::slice::from_ref(&u), 1, &greedy).unwrap_err().contains("guard"));
        let explicit = PaymentOptions { fee_policy: FeePolicy::UNLIMITED, ..greedy };
        assert_eq!(build(&kp, &[u], 1, &explicit).unwrap().fee, 99 * SAT - 1);
    }

    /// Wallet side of CRY-1/CRY-2: emitted witnesses are canonical (v2 below
    /// the activation; the mainnet schedule is used, height 1).
    #[test]
    fn emitted_witnesses_are_canonical_and_exact_length() {
        let kp = generate_keypair(false);
        let paid = build(&kp, &[utxo(&kp, 1, 2 * SAT), utxo(&kp, 2, 2 * SAT)], 3 * SAT, &PaymentOptions::default()).unwrap();
        assert_eq!(paid.tx.version, 1);
        for (i, input) in paid.tx.inputs.iter().enumerate() {
            let (sig, pk) = Transaction::parse_script_sig(&input.script_sig).unwrap();
            assert_eq!(input.script_sig.len(), 8 + sig.len() + pk.len(), "no trailing bytes");
            assert!(sighash::canonical_witness(&input.script_sig).is_ok());
            let sighash = paid.tx.sighash(i, ChainId::Mainnet);
            assert!(crate::crypto::verify_enveloped_canonical(&pk, &sighash, &sig));
        }
    }

    // ── WAL-1 full fix: sighash v3 ───────────────────────────────────────

    /// The signer follows the next block height: version 1 below the
    /// activation, version 3 at it; no height, no signature.
    #[test]
    fn version_follows_the_next_block_height() {
        let kp = generate_keypair(true); // testnet: activation height 0
        let utxos = [utxo(&kp, 1, 2 * SAT)];
        let pay = |next: Option<u64>| build_payment(&utxos, &[5u8; 20], SAT, &kp.address_bytes(), &kp.public_key,
            ChainId::Testnet, &PaymentOptions { next_block_height: next, ..Default::default() },
            &|h, v| kp.sign_tx_digest(h, v));
        assert!(pay(None).unwrap_err().contains("next block is unknown"));
        let v3 = pay(Some(1)).unwrap();
        assert_eq!(v3.tx.version, 3);
        assert!(v3.amounts_committed);
        assert_eq!((v3.verified_inputs, v3.unverified_inputs), (1, 0));
        // Mainnet just below / at its activation height.
        let kp = generate_keypair(false);
        let utxos = [utxo(&kp, 1, 2 * SAT)];
        let act = activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
        let below = build(&kp, &utxos, SAT, &PaymentOptions { next_block_height: Some(act - 1), ..Default::default() }).unwrap();
        assert_eq!((below.tx.version, below.amounts_committed), (1, false));
        let at = build(&kp, &utxos, SAT, &PaymentOptions { next_block_height: Some(act), ..Default::default() }).unwrap();
        assert_eq!((at.tx.version, at.amounts_committed), (3, true));
        // A scoped override moves the boundary for signers too (tests only).
        let _g = activation::scoped_override(10);
        assert_eq!(build(&kp, &utxos, SAT, &PaymentOptions { next_block_height: Some(9), ..Default::default() }).unwrap().tx.version, 1);
        assert_eq!(build(&kp, &utxos, SAT, &PaymentOptions { next_block_height: Some(10), ..Default::default() }).unwrap().tx.version, 3);
    }

    /// WAL-1 full fix: under v3 a lied UTXO value (or script) produces a
    /// signature over the claimed value, which the consensus verifier, fed
    /// the TRUE spent output, rejects. No previous transaction is needed.
    #[test]
    fn v3_signature_commits_to_the_spent_amount_and_script() {
        let kp = generate_keypair(true);
        let honest = utxo(&kp, 1, 100 * SAT);
        let mut lied = honest.clone();
        lied.output.value = SAT + 50_000;
        let opts = PaymentOptions { next_block_height: Some(5), require_verified_inputs: true, ..Default::default() };
        let paid = build_payment(std::slice::from_ref(&lied), &[5u8; 20], SAT, &kp.address_bytes(), &kp.public_key,
            ChainId::Testnet, &opts, &|h, v| kp.sign_tx_digest(h, v)).unwrap();
        assert_eq!(paid.tx.version, 3);
        let verify = |spent: &TxOutput| sighash::verify_tx_scripts(&paid.tx, std::slice::from_ref(spent),
            ChainId::Testnet, 5, 0);
        assert_eq!(verify(&lied.output), Ok(SighashVersion::V3), "valid for the value it was signed for");
        assert!(verify(&honest.output).unwrap_err().contains("invalid signature"), "the real UTXO value invalidates it");
        // The digest also commits to the spent script: the same signature
        // checked against another script (here re-encoded with a trailing
        // byte, so the key hash check fails first) is rejected too.
        let mut other_script = lied.output.clone();
        other_script.script_pubkey.push(0);
        assert!(verify(&other_script).is_err());
        let pre_lied = SighashV3Precomputed::new(&paid.tx, std::slice::from_ref(&lied.output)).unwrap();
        let pre_other = SighashV3Precomputed::new(&paid.tx, std::slice::from_ref(&other_script)).unwrap();
        assert_ne!(pre_lied.hash_scripts, pre_other.hash_scripts);
        assert_ne!(pre_lied.digest(0, 1, ChainId::Testnet), pre_other.digest(0, 1, ChainId::Testnet));
    }

    /// CRY-2: wallets refuse to sign with a single-algorithm (0x0002) key.
    #[test]
    fn single_algorithm_keys_are_refused() {
        use pqcrypto_traits::sign::PublicKey as _;
        use sha3::Digest as _;
        let (mpk, _msk) = pqcrypto_mldsa::mldsa65::keypair();
        let pk = crate::crypto::wrap_envelope(crate::crypto::SUITE_MLDSA65_ONLY, mpk.as_bytes());
        let spk = sha3::Sha3_256::digest(&pk)[..20].to_vec();
        let u = Utxo { txid: [1; 32], index: 0, output: TxOutput { value: 2 * SAT, script_pubkey: spk.clone() } };
        let err = build_payment(&[u], &[5u8; 20], SAT, &spk, &pk, ChainId::Mainnet,
            &PaymentOptions { next_block_height: Some(1), ..Default::default() },
            &|_, _| Err("must not be asked to sign".into())).unwrap_err();
        assert!(err.contains("hybrid"), "{err}");
    }

    /// P5-S: a conservative suite-0x0003 key pays from the second hardening
    /// height of its chain: the payment passes the consensus verifier there
    /// and fails one block below. Below the height the wallet refuses before
    /// signing, and the fee is sized for the 9,322-byte signature.
    #[test]
    fn conservative_keys_pay_from_the_second_hardening_height() {
        use crate::crypto::KeySuite;
        let _act = activation::scoped_override(0);
        let _act2 = activation::scoped_override_v2(10);
        let kp = crate::wallet::generate_keypair_for_suite(true, KeySuite::Conservative).unwrap();
        let utxos = [utxo(&kp, 1, 2 * SAT)];
        let pay = |next: u64| build_payment(&utxos, &[5u8; 20], SAT, &kp.address_bytes(), &kp.public_key,
            ChainId::Testnet, &PaymentOptions { next_block_height: Some(next), ..Default::default() },
            &|h, v| kp.sign_tx_digest(h, v));
        let err = pay(9).unwrap_err();
        assert!(err.contains("block at height 9") && err.contains("height 10"), "{err}");
        let paid = pay(10).unwrap();
        assert_eq!(paid.tx.version, 3);
        let spent = [utxos[0].output.clone()];
        assert_eq!(sighash::verify_tx_scripts_at(&paid.tx, &spent, ChainId::Testnet, 10, 0, 10), Ok(SighashVersion::V3));
        assert!(sighash::verify_tx_scripts_at(&paid.tx, &spent, ChainId::Testnet, 9, 0, 10).is_err(),
            "one block below the second hardening height the same transaction is invalid");
        let spks: Vec<usize> = paid.tx.outputs.iter().map(|o| o.script_pubkey.len()).collect();
        let bound = signed_size_upper_bound(1, &spks, kp.public_key.len());
        assert!(bound >= crate::crypto::CONSERVATIVE_MAX_SIGNATURE_LEN + kp.public_key.len());
        assert!(paid.size <= bound);
        assert!(paid.fee >= tokenomics::min_tx_fee_sat(paid.size));
    }

    /// P5-S: where the second hardening is not scheduled (mainnet today) a
    /// conservative key never signs.
    #[test]
    fn conservative_keys_never_pay_where_hardening2_is_not_scheduled() {
        let kp = crate::wallet::generate_keypair_for_suite(false, crate::crypto::KeySuite::Conservative).unwrap();
        let utxos = [utxo(&kp, 1, 2 * SAT)];
        let err = build_payment(&utxos, &[5u8; 20], SAT, &kp.address_bytes(), &kp.public_key, ChainId::Mainnet,
            &PaymentOptions { next_block_height: Some(10_000_000), ..Default::default() },
            &|_, _| Err("must not be asked to sign".into())).unwrap_err();
        assert!(err.contains("not scheduled"), "{err}");
    }

    #[test]
    fn plan_reports_the_outpoints_to_prefetch() {
        let kp = generate_keypair(false);
        let utxos = vec![utxo(&kp, 1, SAT), utxo(&kp, 2, 5 * SAT)];
        let plan = plan_payment_inputs(&utxos, 2 * SAT, kp.public_key.len(), FeeChoice::AUTO).unwrap();
        assert_eq!(plan, vec![([2; 32], 0)]);
        assert!(plan_payment_inputs(&utxos, 7 * SAT, kp.public_key.len(), FeeChoice::AUTO).is_err());
    }

    #[test]
    fn size_bound_is_an_upper_bound() {
        let kp = generate_keypair(false);
        for n in 1..4u8 {
            let utxos: Vec<Utxo> = (0..n).map(|i| utxo(&kp, i + 1, SAT)).collect();
            let paid = build(&kp, &utxos, u64::from(n) * SAT - 100_000, &PaymentOptions::default()).unwrap();
            let spks: Vec<usize> = paid.tx.outputs.iter().map(|o| o.script_pubkey.len()).collect();
            assert!(paid.size <= signed_size_upper_bound(paid.tx.inputs.len(), &spks, kp.public_key.len()));
        }
    }
}
