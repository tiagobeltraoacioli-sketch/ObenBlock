//! Async JSON-RPC client for wallet ↔ node communication.
//!
//! WalletClient is the network side of the wallet. It talks to a Bloch-SIS Protocol
//! daemon (local or remote) over HTTP JSON-RPC and exposes wallet-friendly
//! high-level operations.
//!
//! Design choices:
//!
//!   - `async/await` with `reqwest` — works on desktop, mobile, WASM
//!   - RpcClientTrait allows mocking for tests
//!   - WalletClient takes an RpcClient trait object, not a URL directly,
//!     so users can inject custom transports (e.g. IPC for local daemons,
//!     WebSocket for browsers)
//!
//! Not done here:
//!   - Retries and caller-specific rate limits are not implemented here.
//!     HTTP requests have a 30-second deadline and responses a 64 MiB read budget.
//!   - Request signing / authentication — none needed while RPC is public
//!   - Response caching — caller decides
//!
//! Example:
//!
//! ```ignore
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use bloch::wallet::{Wallet, WalletClient};
//! use bloch::address::Network;
//!
//! let rpc = WalletClient::new("https://scan.blochlayer.com/rpc");
//! let (wallet, _seed) = Wallet::generate(Network::Mainnet)?;
//!
//! let balance = rpc.balance(wallet.address()).await?;
//! println!("Balance: {} sats", balance.confirmed);
//! # Ok(())
//! # }
//! ```

use super::errors::WalletError;
use crate::address::Address;
use crate::core::{Transaction, TxOutput};
use super::Utxo;
use super::payment::{self, BuiltPayment, FeeChoice, FeePolicy, PaymentOptions, PrevTxs};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// RpcClientTrait — abstraction layer for injectable transports
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait RpcClientTrait: Send + Sync {
    /// Invoke a JSON-RPC method with the given params.
    async fn call(&self, method: &str, params: Value) -> Result<Value, WalletError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Input-byte budget; parsed JSON allocations are additional.
const MAX_RPC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Default HTTP RPC client using reqwest.
pub struct WalletClient {
    endpoint: String,
    http: reqwest::Client,
    next_id: AtomicU64,
}

impl WalletClient {
    /// Construct with a JSON-RPC endpoint URL.
    ///
    /// Panics if the HTTP transport cannot initialize. Prefer `try_new` when
    /// callers need to handle initialization failures without unwinding.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self::try_new(endpoint).expect("HTTP transport initialization failed")
    }

    /// Fallible HTTP transport initialization. Endpoint errors remain request errors.
    pub fn try_new(endpoint: impl Into<String>) -> Result<Self, WalletError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| WalletError::Network(error.without_url().to_string()))?;
        Ok(Self {
            endpoint: endpoint.into(),
            http,
            next_id: AtomicU64::new(1),
        })
    }

    // High-level wallet operations.
    //
    // These map to specific RPC methods and return strongly-typed results.
    // The Value returned by `call()` is parsed and mapped to wallet types.

    /// Get balance (confirmed + pending) for an address.
    pub async fn balance(&self, address: &Address) -> Result<Balance, WalletError> {
        let bal_response = self.call("getbalance", json!([address.to_string()])).await?;
        // Satoshi amounts are decimal strings on the V4 wire (rule R3) and
        // JSON numbers on the live G3 wire — `sat_u64` accepts both.
        // Older nodes may not expose pending information. Preserve that fallback.
        let addr_info = self.call("getaddressinfo", json!([address.to_string()])).await
            .unwrap_or_else(|_| json!({}));
        parse_balance(&bal_response, &addr_info)
    }

    /// Every unspent output the node reports for an address, coinbase
    /// outputs included whether mature or not. To pay, use
    /// [`Self::spendable_utxos`].
    pub async fn utxos(&self, address: &Address) -> Result<Vec<Utxo>, WalletError> {
        let response = self.call("getutxos", json!([address.to_string()])).await?;
        parse_utxos(&response, address)
    }

    /// The unspent outputs of `address` spendable in the block at
    /// `next_block_height`, and how many coinbase outputs were left out as
    /// not yet mature there (`send::utxo_row_spendable_at`, the rule
    /// `gnb-cli send` applies too). A payment that selected an immature
    /// coinbase output was refused by every node.
    pub async fn spendable_utxos(&self, address: &Address, next_block_height: u64)
        -> Result<(Vec<Utxo>, usize), WalletError>
    {
        let response = self.call("getutxos", json!([address.to_string()])).await?;
        parse_spendable_utxos(&response, address, next_block_height)
    }

    /// Get estimated fee rates.
    ///
    /// Informational only: payments built by [`Self::send`] never use a
    /// node-chosen absolute fee (WAL-1). Amounts are decimal strings on the
    /// V4 wire and numbers on the G3 wire; both are read.
    pub async fn estimate_fee(&self) -> Result<FeeEstimate, WalletError> {
        let response = self.call("estimatefeeadvanced", json!([])).await?;
        Ok(fee_estimate_from_response(&response))
    }

    /// Height of the next block: the node's `getdaginfo` `next_block_height`
    /// (the height its mempool admission and template check against;
    /// `tip_height` + 1 from a node that predates the field). Selects the
    /// version of the transactions this wallet signs (3 at/after the
    /// hardening activation, 1 below it).
    pub async fn next_block_height(&self) -> Result<u64, WalletError> {
        let response = self.call("getdaginfo", json!([])).await?;
        super::send::next_block_height_from_daginfo(&response).map_err(WalletError::BadResponse)
    }

    /// Fetch the creating transactions of `outpoints` through
    /// `getrawtransaction` so their claimed values can be verified (WAL-1).
    ///
    /// Best effort per transaction: one the node cannot serve (genesis
    /// carryover, body pruned, method missing on an old node) stays
    /// unverified; one that does not hash to its id is an error, because the
    /// node is then lying.
    pub async fn fetch_prev_txs(&self, outpoints: &[([u8; 32], u32)]) -> Result<PrevTxs, WalletError> {
        let mut prevs = PrevTxs::new();
        let mut seen = std::collections::BTreeSet::new();
        for (txid, _) in outpoints {
            if !seen.insert(*txid) { continue; }
            let txid_hex = hex::encode(txid);
            match self.call("getrawtransaction", json!([txid_hex])).await {
                Ok(v) => {
                    if let Some(raw) = v.get("hex").and_then(Value::as_str) {
                        prevs.insert_hex(&txid_hex, raw).map_err(WalletError::Payment)?;
                    }
                }
                Err(WalletError::RpcError(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(prevs)
    }

    /// Broadcast a signed transaction.
    pub async fn broadcast(&self, tx: &Transaction) -> Result<[u8; 32], WalletError> {
        // Sprint 1.d: Bitcoin-format wire (replaces bincode). Infallible.
        let tx_bytes = tx.to_wire_bytes(true);
        let tx_hex = hex::encode(&tx_bytes);
        let response = self.call("sendrawtransaction", json!([tx_hex])).await?;

        let txid_hex = response.get("txid").and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::BadResponse("broadcast: missing txid".into()))?;
        let txid_bytes = hex::decode(txid_hex)
            .map_err(|e| WalletError::BadResponse(format!("bad txid: {}", e)))?;
        if txid_bytes.len() != 32 {
            return Err(WalletError::BadResponse("txid not 32 bytes".into()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&txid_bytes);
        Ok(out)
    }

    /// Get tx status (pending / confirmed / unknown).
    pub async fn tx_status(&self, txid: &[u8; 32]) -> Result<TxStatus, WalletError> {
        let response = self.call("gettxstatus", json!([hex::encode(txid)])).await?;
        parse_tx_status(&response)
    }

    /// Convenience: send a full tx from an address, signed by a Wallet.
    ///
    /// Handles: utxo fetch → coin selection → previous-transaction
    /// verification → sign → broadcast, under the default maximum-fee guard
    /// and [`SendOptions::default`]: an input whose value cannot be verified
    /// is refused (see [`Self::send_payment_with`]). See
    /// [`Self::send_payment`] for the actual fee and an explicit guard.
    pub async fn send(
        &self,
        wallet: &super::Wallet,
        to: &Address,
        amount: u64,
        fee_rate_preference: FeePreference,
    ) -> Result<[u8; 32], WalletError> {
        self.send_payment_with(wallet, to, amount, fee_rate_preference, &SendOptions::default())
            .await
            .map(|(txid, _)| txid)
    }

    /// Send and report what was actually paid, under `fee_policy` and the
    /// default refusal of unverifiable inputs ([`Self::send_payment_with`]).
    pub async fn send_payment(
        &self,
        wallet: &super::Wallet,
        to: &Address,
        amount: u64,
        fee_rate_preference: FeePreference,
        fee_policy: &FeePolicy,
    ) -> Result<([u8; 32], BuiltPayment), WalletError> {
        let opts = SendOptions { fee_policy: *fee_policy, ..SendOptions::default() };
        self.send_payment_with(wallet, to, amount, fee_rate_preference, &opts).await
    }

    /// Send and report what was actually paid.
    ///
    /// WAL-1/WAL-6: the fee is size-aware from the consensus formula at the
    /// rate `fee_rate_preference` selects (never a node-chosen absolute fee),
    /// and `opts.fee_policy` caps the actual fee. The next block's height
    /// (`getdaginfo`) selects the version: a version-3 signature commits to
    /// every spent value, so nothing else is fetched; for version 1 the
    /// claimed values of the selected UTXOs are verified against their
    /// creating transactions where the node can serve them.
    ///
    /// WAL-1 residual: a version-1 input whose creating transaction the node
    /// does not serve (genesis carryover, pruned body, or a node that simply
    /// withholds it) can be signed only on the node's claimed value, which
    /// the fee guard cannot check when it is under-reported (the difference
    /// silently becomes fee). This library path has no confirmation step, so
    /// such a payment is refused before anything is signed or broadcast
    /// unless `opts.allow_unverified_inputs` is set: the caller's explicit
    /// acknowledgement, the same one every front end asks for (the web
    /// wallet's checkbox, `gnb-cli send` / `gnb-wallet send` confirmation or
    /// `--allow-unverified-inputs`). From the hardening activation (version
    /// 3) every input is committed by the signature and the option has no
    /// effect.
    pub async fn send_payment_with(
        &self,
        wallet: &super::Wallet,
        to: &Address,
        amount: u64,
        fee_rate_preference: FeePreference,
        opts: &SendOptions,
    ) -> Result<([u8; 32], BuiltPayment), WalletError> {
        let fee = fee_rate_preference.fee_choice();
        let next_block_height = self.next_block_height().await?;
        // Coinbase outputs not yet mature at the next block are never selected.
        let (utxos, immature) = self.spendable_utxos(wallet.address(), next_block_height).await?;
        if utxos.is_empty() && immature > 0 {
            return Err(WalletError::Payment(super::send::all_immature_message(
                &wallet.address().to_string(), immature, next_block_height)));
        }
        let chain_id = crate::core::ChainId::for_network(wallet.network());
        let prevs = if payment::amounts_committed_at(next_block_height, chain_id) {
            PrevTxs::new()
        } else {
            let planned = payment::plan_payment_inputs(&utxos, amount, wallet.public_key().len(), fee)
                .map_err(WalletError::Payment)?;
            self.fetch_prev_txs(&planned).await?
        };
        let payment_opts = PaymentOptions {
            fee,
            fee_policy: opts.fee_policy,
            prev_txs: Some(&prevs),
            require_verified_inputs: !opts.allow_unverified_inputs,
            next_block_height: Some(next_block_height),
            ..PaymentOptions::default()
        };
        let built = wallet.build_payment(&utxos, to, amount, &payment_opts)?;
        let txid = self.broadcast(&built.tx).await?;
        if txid != built.tx.txid() {
            return Err(WalletError::BadResponse("broadcast: node reported a different txid".into()));
        }
        Ok((txid, built))
    }
}

#[async_trait]
impl RpcClientTrait for WalletClient {
    async fn call(&self, method: &str, params: Value) -> Result<Value, WalletError> {
        let request_id = self.next_id.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| WalletError::Overflow)?;
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id,
        });

        let response = self.http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| WalletError::Network(e.without_url().to_string()))?;

        if !response.status().is_success() {
            // Status is sufficient; do not download or reflect an arbitrary peer body.
            return Err(WalletError::Network(format!("HTTP {}", response.status())));
        }

        let bytes = read_bounded_response(response, MAX_RPC_RESPONSE_BYTES).await?;
        let resp_json: Value = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::Parse(format!("parse response: {}", e)))?;

        parse_rpc_envelope(resp_json, request_id)
    }
}

fn parse_rpc_envelope(response: Value, request_id: u64) -> Result<Value, WalletError> {
    let object = response.as_object().ok_or_else(|| WalletError::BadResponse("RPC envelope must be an object".into()))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || object.get("id").and_then(Value::as_u64) != Some(request_id) {
        return Err(WalletError::BadResponse("RPC version or request ID mismatch".into()));
    }
    if let Some(error) = object.get("error").filter(|value| !value.is_null()) {
        if object.contains_key("result") {
            return Err(WalletError::BadResponse("RPC envelope contains result and error".into()));
        }
        let code = error.get("code").and_then(Value::as_i64)
            .ok_or_else(|| WalletError::BadResponse("RPC error code must be an integer".into()))?;
        if error.get("message").and_then(Value::as_str).is_none() {
            return Err(WalletError::BadResponse("RPC error message must be a string".into()));
        }
        return Err(WalletError::RpcError(format!("RPC error code {code}")));
    }
    object.get("result").cloned()
        .ok_or_else(|| WalletError::BadResponse("missing result field".into()))
}

fn parse_tx_status(response: &Value) -> Result<TxStatus, WalletError> {
    let status = response.get("status").and_then(Value::as_str)
        .ok_or_else(|| WalletError::BadResponse("missing transaction status".into()))?;
    let confirmations = response.get("confirmations").and_then(Value::as_u64).unwrap_or(0);
    Ok(match status {
        "pending" => TxStatus::Pending,
        "confirmed" => TxStatus::Confirmed { confirmations },
        "final" => TxStatus::Final { confirmations },
        "included" => TxStatus::Included,
        "justified" => TxStatus::Justified,
        "finalized" => TxStatus::Finalized,
        _ => TxStatus::Unknown,
    })
}

async fn read_bounded_response(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, WalletError> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err(WalletError::BadResponse("RPC response exceeds byte limit".into()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| WalletError::Network(error.without_url().to_string()))? {
        let length = bytes.len().checked_add(chunk.len()).ok_or(WalletError::Overflow)?;
        if length > limit { return Err(WalletError::BadResponse("RPC response exceeds byte limit".into())); }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn parse_balance(balance: &Value, pending: &Value) -> Result<Balance, WalletError> {
    let confirmed = balance.get("balance").and_then(super::sat_u64)
        .ok_or_else(|| WalletError::BadResponse("missing balance field".into()))?;
    let pending_in = pending.get("pending_incoming").and_then(super::sat_u64).unwrap_or(0);
    let pending_out = pending.get("pending_outgoing").and_then(super::sat_u64).unwrap_or(0);
    Ok(Balance { confirmed, pending_incoming: pending_in, pending_outgoing: pending_out,
        total: confirmed.checked_add(pending_in).ok_or(WalletError::Overflow)? })
}

/// [`parse_utxos`] without the rows not spendable at `next_block_height`
/// (`send::utxo_row_spendable_at`), and how many were left out.
fn parse_spendable_utxos(response: &Value, address: &Address, next_block_height: u64)
    -> Result<(Vec<Utxo>, usize), WalletError>
{
    let utxos = parse_utxos(response, address)?;
    let rows = response.get("utxos").and_then(|v| v.as_array())
        .ok_or_else(|| WalletError::BadResponse("missing utxos array".into()))?;
    let mut spendable = Vec::with_capacity(utxos.len());
    let mut immature = 0;
    for (utxo, row) in utxos.into_iter().zip(rows) {
        if super::send::utxo_row_spendable_at(row, next_block_height).map_err(WalletError::BadResponse)? {
            spendable.push(utxo);
        } else {
            immature += 1;
        }
    }
    Ok((spendable, immature))
}

fn parse_utxos(response: &Value, address: &Address) -> Result<Vec<Utxo>, WalletError> {
    let utxos_json = response.get("utxos")
        .and_then(|v| v.as_array())
        .ok_or_else(|| WalletError::BadResponse("missing utxos array".into()))?;

    let mut utxos = Vec::with_capacity(utxos_json.len());
    for utxo_val in utxos_json {
        let txid_hex = utxo_val.get("txid").and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::BadResponse("utxo missing txid".into()))?;
        let index = utxo_val.get("index").and_then(|v| v.as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| WalletError::BadResponse("utxo index must fit u32".into()))?;
        // R3: `value` is a satoshi amount — string or number on the wire.
        let value = utxo_val.get("value").and_then(super::sat_u64)
            .ok_or_else(|| WalletError::BadResponse("utxo missing value".into()))?;

        let txid_bytes = hex::decode(txid_hex)
            .map_err(|e| WalletError::BadResponse(format!("bad txid hex: {}", e)))?;
        if txid_bytes.len() != 32 {
            return Err(WalletError::BadResponse(format!("txid not 32 bytes: {}", txid_bytes.len())));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        utxos.push(Utxo {
            txid,
            index,
            output: TxOutput {
                value,
                script_pubkey: address.hash().to_vec(),
            },
        });
    }
    Ok(utxos)
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet-friendly types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance {
    pub confirmed:         u64,
    pub pending_incoming:  u64,
    pub pending_outgoing:  u64,
    pub total:             u64,
}

#[derive(Debug, Clone, Copy)]
pub struct FeeEstimate {
    pub next_block: u64,
    pub medium:     u64,
    pub slow:       u64,
}

/// The node's `estimatefeeadvanced` answer as a [`FeeEstimate`] (B1-T21 /
/// MEM-6). Missing fields fall back to, and every value is floored at, the
/// consensus minimum fee: the fallbacks were 10,000 / 5,000 / 1,000 sat, and
/// a node from before the fix reports 5,000 / 1,000 sat on a quiet pool,
/// both below the 10,000-sat minimum every node enforces.
pub fn fee_estimate_from_response(response: &Value) -> FeeEstimate {
    let min = crate::core::tokenomics::MIN_TX_FEE_SAT;
    let field = |k: &str| response.get(k).and_then(super::sat_u64).unwrap_or(min).max(min);
    FeeEstimate {
        next_block: field("next_block_sats"),
        medium:     field("medium_priority"),
        slow:       field("slow_priority"),
    }
}

/// Options of [`WalletClient::send_payment_with`]. `Default`: the default
/// maximum-fee guard and no unverified inputs.
#[derive(Debug, Clone, Copy, Default)]
pub struct SendOptions {
    /// Maximum-fee guard on the actual fee.
    pub fee_policy: FeePolicy,
    /// The caller's explicit acknowledgement (WAL-1 residual) that a
    /// version-1 payment may spend inputs whose value comes only from the
    /// node's claim, because their creating transaction could not be fetched
    /// and hashed against its txid. Set it only after showing the user the
    /// [`BuiltPayment`]-style summary another way, as the front ends do;
    /// `false` (the default) refuses such a payment before signing.
    pub allow_unverified_inputs: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum FeePreference {
    NextBlock,
    Medium,
    Slow,
}

impl FeePreference {
    /// Size-aware fee rate for this preference, as a multiple of the
    /// consensus minimum rate (WAL-6).
    pub fn fee_choice(self) -> FeeChoice {
        let min = crate::core::tokenomics::MIN_FEE_RATE_SAT_PER_KB;
        FeeChoice::Rate(match self {
            FeePreference::NextBlock => 4 * min,
            FeePreference::Medium    => 2 * min,
            FeePreference::Slow      => min,
        })
    }
}

#[derive(Debug, Clone)]
pub enum TxStatus {
    Pending,
    Confirmed { confirmations: u64 },
    /// Legacy depth-based status; distinct from G4 checkpoint finality.
    Final { confirmations: u64 },
    Included,
    Justified,
    /// The queried G4 node reports checkpoint finality, not independent proof.
    Finalized,
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRpc {
        responses: std::collections::HashMap<String, Value>,
    }

    #[async_trait]
    impl RpcClientTrait for MockRpc {
        async fn call(&self, method: &str, _params: Value) -> Result<Value, WalletError> {
            self.responses.get(method).cloned()
                .ok_or_else(|| WalletError::RpcError(format!("no mock for: {}", method)))
        }
    }

    #[tokio::test]
    async fn tx_status_parses_correctly() {
        // Real HTTP client test would need a running daemon.
        // Here we just verify the type parsing logic works.
        let s1 = TxStatus::Confirmed { confirmations: 5 };
        let s2 = TxStatus::Final { confirmations: 100 };
        assert!(matches!(s1, TxStatus::Confirmed { confirmations: 5 }));
        assert!(matches!(s2, TxStatus::Final { confirmations: 100 }));
    }

    /// B1-T21 / MEM-6: the client never reports a fee below the consensus
    /// minimum, whatever (or whether) the node answers.
    #[test]
    fn fee_estimate_is_floored_at_the_consensus_minimum() {
        let min = crate::core::tokenomics::MIN_TX_FEE_SAT;
        // A node from before the fix, on a quiet pool.
        let old = fee_estimate_from_response(&json!({
            "next_block_sats": "10000", "medium_priority": "5000", "slow_priority": "1000"}));
        assert_eq!((old.next_block, old.medium, old.slow), (min, min, min));
        // Fields missing: the consensus minimum, not 5,000 / 1,000.
        let none = fee_estimate_from_response(&json!({}));
        assert_eq!((none.next_block, none.medium, none.slow), (min, min, min));
        // Real values above the floor are kept (G3 numbers or V4 strings).
        let busy = fee_estimate_from_response(&json!({
            "next_block_sats": 90_000, "medium_priority": "40000", "slow_priority": "17200"}));
        assert_eq!((busy.next_block, busy.medium, busy.slow), (90_000, 40_000, 17_200));
    }

    #[test]
    fn fee_preference_select() {
        let est = FeeEstimate { next_block: 10000, medium: 5000, slow: 1000 };
        let sel_next = match FeePreference::NextBlock {
            FeePreference::NextBlock => est.next_block,
            _ => unreachable!(),
        };
        assert_eq!(sel_next, 10000);
    }
}

#[cfg(test)]
mod audit_rpc_input_tests {
    use super::*;
    use crate::address::Network;

    #[test]
    fn balance_total_refuses_overflow_and_keeps_legacy_missing_pending() {
        assert!(matches!(parse_balance(&json!({"balance": u64::MAX.to_string()}),
            &json!({"pending_incoming": "1"})), Err(WalletError::Overflow)));
        assert_eq!(parse_balance(&json!({"balance": "9007199254740993"}), &json!({})).unwrap().total,
            9_007_199_254_740_993);
        assert_eq!(parse_balance(&json!({"balance": 100}), &json!({"pending_incoming": 20})).unwrap().total, 120);
    }

    #[test]
    fn utxo_index_cannot_wrap_to_another_outpoint() {
        let address = Address::from_hash([1; 20], Network::Testnet);
        let mut row = json!({"txid": "ab".repeat(32), "index": u32::MAX, "value": "9007199254740993"});
        let parsed = parse_utxos(&json!({"utxos": [row.clone()]}), &address).unwrap();
        assert_eq!(parsed[0].index, u32::MAX);
        assert_eq!(parsed[0].output.value, 9_007_199_254_740_993);
        for invalid in [json!(4294967296u64), json!(-1), json!(1.5)] {
            row["index"] = invalid;
            assert!(matches!(parse_utxos(&json!({"utxos": [row.clone()]}), &address), Err(WalletError::BadResponse(_))));
        }
    }
}

#[cfg(test)]
mod audit_rpc_http_budget_tests {
    use super::*;
    use std::io::{Read, Write};

    fn serve(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            stream.set_write_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(&response);
        });
        (format!("http://{address}"), worker)
    }

    #[tokio::test]
    async fn actual_chunked_responses_enforce_read_budget_and_exact_boundary() {
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(2)).build().unwrap();
        let body = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n";
        for limit in [7, 8] {
            let (url, worker) = serve(body.to_vec());
            let response = client.get(url).send().await.unwrap();
            let result = read_bounded_response(response, limit).await;
            if limit == 8 { assert_eq!(result.unwrap(), b"abcdefgh"); }
            else { assert!(matches!(result, Err(WalletError::BadResponse(message)) if message.contains("byte limit"))); }
            worker.join().unwrap();
        }
    }

    #[tokio::test]
    async fn advertised_oversize_is_refused_before_body_and_http_error_does_not_echo() {
        let (url, worker) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\nConnection: close\r\n\r\n".to_vec());
        let response = reqwest::get(url).await.unwrap();
        assert!(matches!(read_bounded_response(response, 8).await, Err(WalletError::BadResponse(_))));
        worker.join().unwrap();
        let (url, worker) = serve(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\nsynthetic-peer-body-marker".to_vec());
        let error = WalletClient::new(url).call("getbalance", json!([])).await.unwrap_err().to_string();
        assert!(error.contains("500"));
        assert!(!error.contains("synthetic-peer-body-marker"));
        worker.join().unwrap();
    }
    #[tokio::test]
    async fn redirect_does_not_forward_rpc_to_target_and_url_errors_are_redacted() {
        let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let response = format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/private-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target.local_addr().unwrap());
        let (url, worker) = serve(response.into_bytes());
        let error = WalletClient::try_new(url).unwrap().call("sendrawtransaction", json!(["public-signed-data"])).await.unwrap_err().to_string();
        assert!(error.contains("307"));
        assert!(matches!(target.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
        worker.join().unwrap();

        // Port zero cannot be a remote service endpoint.  Using it directly
        // keeps this a deterministic connection error instead of probing an
        // ephemeral port, dropping the listener and racing another process
        // to claim that port before the request runs.
        let endpoint = "http://127.0.0.1:0/private-path?token=synthetic-query-marker";
        let error = WalletClient::try_new(endpoint).unwrap().call("getbalance", json!([])).await.unwrap_err().to_string();
        assert!(!error.contains("synthetic-query-marker"));
        assert!(!error.contains("private-path"));
    }

    #[tokio::test]
    async fn successive_calls_reject_a_stale_response_id() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut ids = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut body_len = 0;
                loop {
                    let mut line = String::new();
                    std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
                    if line == "\r\n" { break; }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        body_len = value.trim().parse::<usize>().unwrap();
                    }
                }
                assert!(body_len < 4096);
                let mut body = vec![0; body_len];
                reader.read_exact(&mut body).unwrap();
                ids.push(serde_json::from_slice::<Value>(&body).unwrap()["id"].as_u64().unwrap());
                drop(reader);
                stream.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":42}").unwrap();
            }
            ids
        });
        let client = WalletClient::new(format!("http://{address}"));
        assert_eq!(client.call("getbalance", json!([])).await.unwrap(), json!(42));
        assert!(matches!(client.call("getbalance", json!([])).await, Err(WalletError::BadResponse(message)) if message.contains("ID mismatch")));
        assert_eq!(worker.join().unwrap(), vec![1, 2]);
    }

    #[tokio::test]
    async fn rpc_error_retains_numeric_code_without_peer_message_or_data() {
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"synthetic-peer-marker\",\"data\":\"synthetic-peer-marker\"}}";
        let (url, worker) = serve(response.to_vec());
        let error = WalletClient::new(url).call("getbalance", json!([])).await.unwrap_err().to_string();
        assert!(error.contains("-32602"));
        assert!(!error.contains("synthetic-peer-marker"));
        worker.join().unwrap();
    }

}

#[cfg(test)]
mod audit_2026_10_send_tests {
    use super::*;
    use crate::address::Network;
    use crate::core::TxInput;
    use std::io::{Read, Write};

    /// Serve JSON-RPC by method name until `stop` is set; record the methods.
    fn serve(responses: std::collections::HashMap<&'static str, Value>)
        -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>)
    {
        let (url, seen, _params) = serve_recording(responses);
        (url, seen)
    }

    /// [`serve`], also recording the params of every call.
    #[allow(clippy::type_complexity)]
    fn serve_recording(responses: std::collections::HashMap<&'static str, Value>)
        -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>, std::sync::Arc<std::sync::Mutex<Vec<Value>>>)
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let params = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let params_log = params.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut body_len = 0;
                loop {
                    let mut line = String::new();
                    if std::io::BufRead::read_line(&mut reader, &mut line).unwrap_or(0) == 0 { break; }
                    if line == "\r\n" { break; }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        body_len = v.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; body_len];
                reader.read_exact(&mut body).unwrap();
                drop(reader);
                let req: Value = serde_json::from_slice(&body).unwrap();
                let method = req["method"].as_str().unwrap().to_string();
                log.lock().unwrap().push(method.clone());
                params_log.lock().unwrap().push(req["params"].clone());
                let result = responses.get(method.as_str()).cloned().unwrap_or(json!({"error": "unknown"}));
                let doc = json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string();
                let _ = stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{doc}", doc.len()).as_bytes());
            }
        });
        (format!("http://{address}"), seen, params)
    }

    /// The library client never selects a coinbase output that is not mature
    /// at the next block (the same defect `gnb-cli send` had: every node
    /// refused the broadcast "coinbase maturity"), even when it alone covers
    /// the payment, and refuses before signing when only immature coins are
    /// left.
    #[tokio::test]
    async fn send_payment_skips_immature_coinbase_outputs() {
        use crate::core::COINBASE_MATURITY as M;
        let (wallet, _) = crate::wallet::Wallet::generate(Network::Testnet).unwrap();
        let tip = 1_000u64;
        let row = |txid: u8, value: &str, cb: Option<u64>| {
            let mut r = json!({"txid": hex::encode([txid; 32]), "index": 0, "value": value});
            if let Some(h) = cb { r["coinbase_height"] = json!(h); }
            r
        };
        let rows = json!({"utxos": [
            row(1, "10000000000", Some(tip)),         // 100 GNB, 1 confirmation: immature
            row(2, "200000000", Some(tip + 1 - M)),   // 2 GNB, exactly mature at tip + 1
            row(3, "200000000", None),                // 2 GNB, not a coinbase output
        ]});
        let responses = std::collections::HashMap::from([
            ("getdaginfo", json!({"tip_height": tip, "next_block_height": tip + 1})),
            ("getutxos", rows),
            ("sendrawtransaction", json!({"txid": "00"})),
        ]);
        let (url, seen, params) = serve_recording(responses);
        let client = WalletClient::new(url);
        let to = Address::from_hash([7; 20], Network::Testnet);
        let (spendable, immature) = client.spendable_utxos(wallet.address(), tip + 1).await.unwrap();
        assert_eq!((spendable.len(), immature), (2, 1));
        assert_eq!(client.utxos(wallet.address()).await.unwrap().len(), 3, "utxos() still lists every output");
        // The mock echoes a wrong txid: `send` fails AFTER broadcasting.
        let err = client.send(&wallet, &to, 300_000_000, FeePreference::Slow).await.unwrap_err();
        assert!(matches!(err, WalletError::BadResponse(_)), "{err}");
        let sent = {
            let seen = seen.lock().unwrap();
            let i = seen.iter().position(|m| m == "sendrawtransaction").expect("broadcast");
            params.lock().unwrap()[i][0].as_str().unwrap().to_string()
        };
        let tx = Transaction::from_wire_bytes(&hex::decode(sent).unwrap()).unwrap();
        let spent: Vec<[u8; 32]> = tx.inputs.iter().map(|i| i.prev_txid).collect();
        assert_eq!(spent.len(), 2);
        assert!(!spent.contains(&[1u8; 32]), "the immature 100 GNB coinbase output was selected");

        let responses = std::collections::HashMap::from([
            ("getdaginfo", json!({"tip_height": tip})),
            ("getutxos", json!({"utxos": [row(1, "10000000000", Some(tip))]})),
            ("sendrawtransaction", json!({"txid": "00"})),
        ]);
        let (url, seen) = serve(responses);
        let err = WalletClient::new(url).send(&wallet, &to, 100_000_000, FeePreference::Slow).await.unwrap_err();
        assert!(matches!(&err, WalletError::Payment(m) if m.contains("immature")), "{err}");
        assert!(!seen.lock().unwrap().iter().any(|m| m == "sendrawtransaction"), "nothing is broadcast");
    }

    /// WAL-1 regression (version-1 payments, below the activation): a node
    /// that under-reports a UTXO value while serving the real previous
    /// transaction is caught; nothing is broadcast. (Mainnet wallet, tip far
    /// below the mainnet activation height.)
    #[tokio::test]
    async fn send_detects_a_lied_utxo_value_and_does_not_broadcast() {
        let (wallet, _) = crate::wallet::Wallet::generate(Network::Mainnet).unwrap();
        let prev = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [3; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 100 * 100_000_000, script_pubkey: wallet.address().hash().to_vec() }],
            locktime: 0,
        };
        let txid = hex::encode(prev.txid());
        let responses = std::collections::HashMap::from([
            ("getdaginfo", json!({"tip_height": 10})),
            ("getutxos", json!({"utxos": [{"txid": txid, "index": 0, "value": "100050000"}]})),
            ("getrawtransaction", json!({"txid": txid, "hex": hex::encode(prev.to_wire_bytes(true))})),
            ("sendrawtransaction", json!({"txid": "00"})),
        ]);
        let (url, seen) = serve(responses);
        let client = WalletClient::new(url);
        let to = Address::from_hash([7; 20], Network::Mainnet);
        let err = client.send(&wallet, &to, 100_000_000, FeePreference::Slow).await.unwrap_err();
        assert!(matches!(&err, WalletError::Payment(m) if m.contains("refusing to sign")), "{err}");
        assert!(!seen.lock().unwrap().iter().any(|m| m == "sendrawtransaction"));
    }

    /// WAL-1 full fix: at/after the activation (testnet: from genesis) the
    /// client signs version 3 and fetches no previous transaction; a lied
    /// value only yields a transaction every node rejects.
    #[tokio::test]
    async fn send_signs_version_3_without_fetching_previous_transactions() {
        let (wallet, _) = crate::wallet::Wallet::generate(Network::Testnet).unwrap();
        let utxo_txid = hex::encode([9u8; 32]);
        let responses = std::collections::HashMap::from([
            ("getdaginfo", json!({"tip_height": 41})),
            ("getutxos", json!({"utxos": [{"txid": utxo_txid, "index": 0, "value": "300000000"}]})),
            ("sendrawtransaction", json!({"txid": "00"})),
        ]);
        let (url, seen) = serve(responses);
        let client = WalletClient::new(url);
        assert_eq!(client.next_block_height().await.unwrap(), 42);
        let to = Address::from_hash([7; 20], Network::Testnet);
        // The mock echoes a wrong txid, so `send` reports an error AFTER
        // building and broadcasting the version-3 transaction.
        let err = client.send(&wallet, &to, 100_000_000, FeePreference::Slow).await.unwrap_err();
        assert!(matches!(err, WalletError::BadResponse(_)), "{err}");
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|m| m == "sendrawtransaction"));
        assert!(!seen.iter().any(|m| m == "getrawtransaction"), "{seen:?}");
    }

    /// WAL-1 residual (re-audit challenge): below the activation (version 1,
    /// the signature does not commit to spent values) the library path
    /// signed and broadcast inputs whose value could not be verified, with
    /// no acknowledgement, and reported them only afterwards. The finding's
    /// scenario: a lying node reports a 100 GNB coin as 1.0005 GNB and does
    /// not serve its creating transaction; paying 1 GNB burnt 99 GNB as fee.
    /// Now nothing is signed or broadcast unless the caller acknowledges
    /// unverified inputs explicitly, as every front end requires (the web
    /// checkbox, the interactive CLI confirmation, `--allow-unverified-inputs`).
    #[tokio::test]
    async fn send_refuses_unverifiable_inputs_unless_acknowledged() {
        let (wallet, _) = crate::wallet::Wallet::generate(Network::Mainnet).unwrap();
        let utxo_txid = hex::encode([5u8; 32]);
        // getrawtransaction is not served (the mock answers an error object
        // without `hex`, as a pruned or lying node would).
        let responses = || std::collections::HashMap::from([
            ("getdaginfo", json!({"tip_height": 10, "next_block_height": 11})),
            ("getutxos", json!({"utxos": [{"txid": utxo_txid, "index": 0, "value": "100050000"}]})),
            ("sendrawtransaction", json!({"txid": "00"})),
        ]);
        let to = Address::from_hash([7; 20], Network::Mainnet);

        let (url, seen) = serve(responses());
        let client = WalletClient::new(url);
        let err = client.send(&wallet, &to, 100_000_000, FeePreference::Slow).await.unwrap_err();
        assert!(matches!(&err, WalletError::Payment(m) if m.contains("could not be verified")), "{err}");
        {
            let seen = seen.lock().unwrap();
            assert!(seen.iter().any(|m| m == "getrawtransaction"), "verification was attempted: {seen:?}");
            assert!(!seen.iter().any(|m| m == "sendrawtransaction"), "nothing is broadcast: {seen:?}");
        }
        let err = client.send_payment(&wallet, &to, 100_000_000, FeePreference::Slow, &FeePolicy::DEFAULT)
            .await.unwrap_err();
        assert!(matches!(&err, WalletError::Payment(m) if m.contains("could not be verified")), "{err}");

        // An explicit acknowledgement signs on the claimed value (and the
        // result reports the unverified input). The mock echoes a wrong txid,
        // so the call fails AFTER the broadcast.
        let (url, seen) = serve(responses());
        let opts = SendOptions { allow_unverified_inputs: true, ..SendOptions::default() };
        let err = WalletClient::new(url)
            .send_payment_with(&wallet, &to, 100_000_000, FeePreference::Slow, &opts).await.unwrap_err();
        assert!(matches!(err, WalletError::BadResponse(_)), "{err}");
        assert!(seen.lock().unwrap().iter().any(|m| m == "sendrawtransaction"));
        assert!(!SendOptions::default().allow_unverified_inputs, "refusal is the default");
    }

    #[test]
    fn fee_preferences_are_size_aware_rates() {
        let min = crate::core::tokenomics::MIN_FEE_RATE_SAT_PER_KB;
        assert_eq!(FeePreference::Slow.fee_choice(), FeeChoice::Rate(min));
        assert_eq!(FeePreference::NextBlock.fee_choice(), FeeChoice::Rate(4 * min));
    }
}

#[cfg(test)]
mod audit_rpc_envelope_tests {
    use super::*;

    #[test]
    fn envelopes_require_version_id_and_unambiguous_result_or_error() {
        for invalid in [
            json!([]), json!({"result": 1}),
            json!({"jsonrpc":"1.0","id":7,"result":1}),
            json!({"jsonrpc":"2.0","id":8,"result":1}),
            json!({"jsonrpc":"2.0","id":"7","result":1}),
            json!({"jsonrpc":"2.0","id":null,"result":1}),
            json!({"jsonrpc":"2.0","id":7}),
            json!({"jsonrpc":"2.0","id":7,"error":null}),
            json!({"jsonrpc":"2.0","id":7,"result":null,"error":{"code":-1,"message":"bad"}}),
            json!({"jsonrpc":"2.0","id":7,"error":{"code":1.5,"message":"bad"}}),
            json!({"jsonrpc":"2.0","id":7,"error":{"code":-1,"message":3}}),
        ] {
            assert!(matches!(parse_rpc_envelope(invalid, 7), Err(WalletError::BadResponse(_))));
        }
        assert_eq!(parse_rpc_envelope(json!({"jsonrpc":"2.0","id":7,"result":null}), 7).unwrap(), Value::Null);
        assert_eq!(parse_rpc_envelope(json!({"jsonrpc":"2.0","id":7,"result":[1],"error":null}), 7).unwrap(), json!([1]));
        assert!(matches!(parse_rpc_envelope(json!({"jsonrpc":"2.0","id":7,"error":{"code":-1,"message":"private-marker"}}), 7),
            Err(WalletError::RpcError(message)) if message == "RPC error code -1"));
    }

    #[test]
    fn preserves_legacy_depth_and_distinguishes_g4_checkpoint_states() {
        assert!(matches!(parse_tx_status(&json!({"status":"pending"})).unwrap(), TxStatus::Pending));
        assert!(matches!(parse_tx_status(&json!({"status":"confirmed","confirmations":12})).unwrap(), TxStatus::Confirmed { confirmations:12 }));
        assert!(matches!(parse_tx_status(&json!({"status":"final","confirmations":100})).unwrap(), TxStatus::Final { confirmations:100 }));
        assert!(matches!(parse_tx_status(&json!({"status":"included"})).unwrap(), TxStatus::Included));
        assert!(matches!(parse_tx_status(&json!({"status":"justified"})).unwrap(), TxStatus::Justified));
        assert!(matches!(parse_tx_status(&json!({"status":"finalized"})).unwrap(), TxStatus::Finalized));
        assert!(matches!(parse_tx_status(&json!({"status":"unknown"})).unwrap(), TxStatus::Unknown));
        assert!(parse_tx_status(&json!({})).is_err());
    }

    #[tokio::test]
    async fn exhausted_request_ids_fail_before_network_and_never_wrap() {
        let client = WalletClient::new("http://127.0.0.1:1");
        client.next_id.store(u64::MAX, Ordering::Relaxed);
        for _ in 0..2 {
            assert!(matches!(client.call("getbalance", json!([])).await, Err(WalletError::Overflow)));
            assert_eq!(client.next_id.load(Ordering::Relaxed), u64::MAX);
        }
    }
}
