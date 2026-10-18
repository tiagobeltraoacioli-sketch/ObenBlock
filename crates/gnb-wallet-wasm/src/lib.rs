//! ObenBlock browser wallet core, built for `wasm32-wasip1`.
//!
//! One entry point, JSON in and JSON out:
//!
//! ```text
//! gnb_alloc(len) -> ptr            gnb_free(ptr, len)
//! gnb_call(ptr, len) -> u64        (result_ptr << 32) | result_len; free with gnb_free
//! ```
//!
//! The core is an ObenBlock wallet (docs/DESIGN-obenblock.md §2, §3): every
//! request first fixes the process chain to ObenBlock (`ensure_obenblock`), so
//! every signature commits to the ObenBlock chain id (mainnet `0x4F420001`,
//! regtest `0x4F420002`) and every transaction is version 3 / sighash v3,
//! which ObenBlock requires from height 0. Addresses are shown as `obb1…`;
//! `gnb1…` and `bloch1…` strings are accepted as the same script (aliases).
//! A network is `"mainnet"` (the default) or `"regtest"` (`"testnet"` is
//! accepted as its old name: regtest uses the `Testnet` address network).
//!
//! Requests: `{"op": ...}` with
//!
//! ```text
//! chain {network?}            the chain this core signs for: name, chain id,
//!                             address prefix, `tx_version` (3) and the height
//!                             from which version 3 applies (0)
//! open {json, password, network?}
//!                             unlock a keystore (v3/v2, `gnb1q…`/`bloch1q…`
//!                             accepted for v2; then v1) of `network`: v3 and v1
//!                             must authenticate that network, a v2 file (which
//!                             authenticates none) must record an address of it
//!                             (CRY-7)
//! create {mnemonic?, network?}
//!                             new key from the WASI CSPRNG (browser crypto).
//!                             Mainnet, by default (`mnemonic` absent or true), is
//!                             derived from a fresh 24-word phrase, returned ONCE
//!                             as `words` for the user to write down (WAL-7);
//!                             `mnemonic: false` or regtest (`network:
//!                             "regtest"`, or the older `testnet: true`) makes a
//!                             random key with no phrase.
//! restore {words}             unlock the mainnet key of a 24-word phrase
//! setnetwork {network} | {testnet}
//!                             use the unlocked key on mainnet or regtest
//! export {password}           encrypted keystore v3 JSON of the unlocked key
//! (`utxos` are the node's getutxos rows; a coinbase output, `coinbase_height`
//! in its row, is never selected before it is mature at `next_height`.)
//! plan {utxos, to, amount, fee, next_height}
//!                             the transaction `version` a payment targeting block
//!                             `next_height` (the node's getdaginfo next_block_height)
//!                             gets: 3 on ObenBlock at every height. A version-3
//!                             signature commits to every spent value and script,
//!                             so `prev_txids` (the transactions a version-1
//!                             payment had to fetch, WAL-1) is always empty.
//! pay {utxos, to, amount, fee, next_height, prevtxs?, max_fee?, require_verified?}
//!                             build and sign a payment (amounts in base units),
//!                             version 3 / sighash v3 under the ObenBlock chain id.
//!                             `prevtxs` (txid -> raw transaction hex) is still
//!                             accepted: each is hashed against its txid and the
//!                             claimed UTXO values are checked against it before
//!                             anything is signed. The response reports the ACTUAL
//!                             fee, dust added to the fee, change, verified/unverified
//!                             inputs, `version` and `amounts_committed`.
//! address {} · wipe {} · normalize {address, format?} · minfee {size}
//! ```
//!
//! The secret key never crosses the boundary: responses carry addresses,
//! public keys, signed transactions, encrypted keystores and — only from
//! `create` — the new recovery phrase. Request buffers are wiped by the
//! loader (`core.js`) and the password copies made here are wiped on drop.
//!
//! Keystores keep the address string they always stored (the `gnb1…` form,
//! which the v3 associated data binds), so a keystore exported here opens in
//! the GnB tools and the ObenBlock CLI alike; only what this core shows is
//! the `obb1…` form (`address::display_address`).

use gnb_crypto::address::{display_address, Address, AddressFamily, Network};
use gnb_crypto::core::chain::{set_process_chain, Chain};
use gnb_crypto::core::{tokenomics, ChainId, TxOutput};
use gnb_crypto::wallet::payment::amounts_committed_at;
use gnb_crypto::wallet::send::{all_immature_message, utxo_row_spendable_at};
use gnb_crypto::wallet::{
    generate_keypair, generate_mnemonic_keypair, keypair_from_mnemonic, FeeChoice, FeePolicy,
    Keypair, PaymentOptions, PrevTxs, TxBuilder, Utxo, Wallet,
};
use serde_json::{json, Value};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

static SESSION: Mutex<Option<Keypair>> = Mutex::new(None);

/// The address family this core parses and shows (`obb1…`, GnB and Bloch
/// forms accepted as aliases).
const FAMILY: AddressFamily = AddressFamily::ObenBlock;

/// Fix the process chain to ObenBlock before anything is parsed, derived or
/// signed: `ChainId::for_network` then maps a key's network to the ObenBlock
/// chain id (folded into every sighash), the activation schedule is
/// ObenBlock's (version 3 from height 0) and `address::process_family` is
/// `obb`. Idempotent; it can only fail if something fixed the GnB chain
/// first, and then nothing is signed.
fn ensure_obenblock() -> Result<(), String> {
    set_process_chain(Chain::ObenBlock)
        .map_err(|other| format!("this wallet core signs for ObenBlock only (the process chain is {})", other.name()))
}

/// An address string as this core shows it: `obb1…`.
fn shown(address: &str) -> String {
    display_address(address)
}

/// The key `kp` as a response: its `obb1…` address and its public key.
fn identity(kp: &Keypair) -> Value {
    json!({ "address": shown(&kp.address), "public_key": hex::encode(&kp.public_key) })
}

fn set_session(kp: Keypair) {
    let mut s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = s.as_mut() {
        old.private_key.zeroize();
    }
    *s = Some(kp);
}

fn with_session<R>(f: impl FnOnce(&Keypair) -> Result<R, String>) -> Result<R, String> {
    let s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    s.as_ref().ok_or_else(|| "wallet is locked".to_string()).and_then(f)
}

fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| format!("missing string field `{k}`"))
}

/// A secret string field, copied into wiping storage (CRY-4).
fn secret(v: &Value, k: &str) -> Result<Zeroizing<String>, String> {
    s(v, k).map(|x| Zeroizing::new(x.to_owned()))
}

/// Overwrite every secret string field of a request in place, so the parsed
/// `serde_json::Value` does not keep the password or phrase after dispatch.
fn wipe_secret_fields(req: &mut Value) {
    if let Some(obj) = req.as_object_mut() {
        for key in ["password", "words"] {
            if let Some(Value::String(text)) = obj.get_mut(key) {
                text.zeroize();
            }
        }
    }
}

/// Dispatch one request and wipe its secret fields (CRY-4).
pub fn handle_owned(mut req: Value) -> Result<Value, String> {
    dispatch_wiping(&mut req)
}

/// [`handle`], then wipe the request's secret fields in place.
fn dispatch_wiping(req: &mut Value) -> Result<Value, String> {
    let out = handle(req);
    wipe_secret_fields(req);
    out
}

/// Overwrite every string of `v` (recursively) in place. A response can
/// carry a secret (`create` returns the new recovery phrase as `words`): once
/// it has been serialised into the output buffer, the `Value` copy is wiped
/// before it is dropped (CRY-4).
fn wipe_value(v: &mut Value) {
    match v {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_value),
        Value::Object(map) => map.values_mut().for_each(wipe_value),
        _ => {}
    }
}

/// Serialise `v` into one buffer of exactly its length: the size is counted
/// first, so the buffer is allocated once and never grows (each growth of a
/// `Vec` frees an unwiped copy of what it held), and the boxed slice needs
/// no shrinking reallocation either (CRY-4).
fn serialize_exact(v: &Value) -> Box<[u8]> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let mut count = Count(0);
    // Serialising a `Value` cannot fail.
    let _ = serde_json::to_writer(&mut count, v);
    let mut buf = Vec::with_capacity(count.0.max(1));
    let _ = serde_json::to_writer(&mut buf, v);
    if buf.len() != buf.capacity() {
        // Never taken (exact capacity, or the 1-byte minimum for an empty
        // value): copy into an exact allocation and wipe the original.
        let exact: Box<[u8]> = buf.as_slice().into();
        buf.zeroize();
        return exact;
    }
    buf.into_boxed_slice()
}

/// The whole of [`gnb_call`] on safe types: parse the request, dispatch it,
/// wipe the request's secret fields, serialise the response into one exact
/// buffer, then wipe every string of the response `Value` (CRY-4). The
/// returned buffer is the only copy left; the page frees it through
/// `gnb_free`, which wipes it.
pub fn call_bytes(input: &[u8]) -> Box<[u8]> {
    let mut req = if gnb_crypto::wallet::descriptor::mentions_descriptor_operation(input) {
        gnb_crypto::wallet::descriptor::request_from_json(input)
    } else {
        serde_json::from_slice::<Value>(input).map_err(|e| e.to_string())
    };
    let mut out = match &mut req {
        Ok(req) => match dispatch_wiping(req) {
            Ok(v) => json!({ "ok": v }),
            Err(e) => json!({ "error": e }),
        },
        Err(e) => json!({ "error": format!("bad request: {e}") }),
    };
    let bytes = serialize_exact(&out);
    wipe_value(&mut out);
    #[cfg(test)]
    observe_wiped(req.as_ref().ok(), &out);
    bytes
}

#[cfg(test)]
type WipeObserver = Box<dyn FnMut(Option<&Value>, &Value)>;

#[cfg(test)]
thread_local! {
    /// Test hook: called by [`call_bytes`] with the request and the response
    /// `Value`s as they are when `call_bytes` drops them.
    static WIPE_OBSERVER: std::cell::RefCell<Option<WipeObserver>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn observe_wiped(req: Option<&Value>, out: &Value) {
    WIPE_OBSERVER.with(|o| {
        if let Some(f) = o.borrow_mut().as_mut() {
            f(req, out);
        }
    });
}

/// The public formats (descriptors, PQ-PSBT) name ObenBlock regtest by the
/// address network it uses, "testnet"; accept "regtest" there too.
fn public_format_request(req: &Value) -> std::borrow::Cow<'_, Value> {
    if req.get("network").and_then(Value::as_str) == Some("regtest") {
        let mut owned = req.clone();
        owned["network"] = json!("testnet");
        std::borrow::Cow::Owned(owned)
    } else {
        std::borrow::Cow::Borrowed(req)
    }
}

/// Show every `address` / `bech32m` string field of a public-format answer
/// (recursively) in the ObenBlock form; descriptor strings and scripts are
/// unchanged.
fn show_addresses(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                match value {
                    Value::String(text) if key == "address" || key == "bech32m" => *text = shown(text),
                    other => show_addresses(other),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(show_addresses),
        _ => {}
    }
}

/// Dispatch one request. Pure Rust, testable on the host.
pub fn handle(req: &Value) -> Result<Value, String> {
    ensure_obenblock()?;
    match s(req, "op")? {
        "chain" => {
            let network = parse_network(req)?;
            let id = ChainId::for_chain(Chain::ObenBlock, network);
            let version = PaymentOptions { next_block_height: Some(0), ..PaymentOptions::default() }.tx_version(id)?;
            Ok(json!({
                "chain": Chain::ObenBlock.name(),
                "network": network_name(network),
                "chain_id": format!("{:#010x}", id.to_u32()),
                "address_prefix": FAMILY.key_prefix(network),
                "policy_prefix": FAMILY.policy_prefix(network),
                "tx_version": version,
                "tx_version_3_from_height":
                    gnb_crypto::core::activation::hardening_activation_height_for_chain(id),
            }))
        }
        "descriptor" => gnb_crypto::wallet::descriptor::public_request(&public_format_request(req)).map(|mut v| {
            show_addresses(&mut v);
            v
        }),
        "pqpsbt" => gnb_crypto::wallet::pqpsbt::public_request(&public_format_request(req)),
        "pqpsbt_sign" => {
            use gnb_crypto::wallet::pqpsbt::{self, PqPsbt};
            let req = &*public_format_request(req);
            pqpsbt::check_request_fields(req, &["op", "hex", "network", "next_height", "max_fee"])?;
            let context = pqpsbt::context_from_request(req)?;
            let mut document = PqPsbt::from_bytes(&pqpsbt::decode_hex(s(req, "hex")?, pqpsbt::MAX_BYTES)?)?;
            let review = document.review(&context)?;
            let key_index = with_session(|kp| {
                Address::parse_for_network(&kp.address, context.network).map_err(|e| e.to_string())?;
                document.sign(&context, &kp.public_key, |digest, version| kp.sign_tx_digest(digest, version))
            })?;
            Ok(json!({"hex": hex::encode(document.to_bytes()?), "key_index": key_index, "review": review.to_json()}))
        }
        "open" => {
            let kp = open_keypair(req)?;
            let out = identity(&kp);
            set_session(kp);
            Ok(out)
        }
        "create" => {
            // Regtest (`network: "regtest"`, or the older `testnet: true`)
            // makes a random key with no phrase: the phrase derivation is
            // mainnet's.
            let network = if req.get("network").is_some() {
                parse_network(req)?
            } else if req.get("testnet").and_then(Value::as_bool).unwrap_or(false) {
                Network::Testnet
            } else {
                Network::Mainnet
            };
            let testnet = network == Network::Testnet;
            let with_phrase = !testnet && req.get("mnemonic").and_then(Value::as_bool).unwrap_or(true);
            if with_phrase {
                let (kp, phrase) = generate_mnemonic_keypair(Network::Mainnet).map_err(|e| e.to_string())?;
                let words = Zeroizing::new(phrase.words().join(" "));
                let mut out = identity(&kp);
                out["words"] = json!(words.as_str());
                set_session(kp);
                Ok(out)
            } else {
                let kp = generate_keypair(testnet);
                let out = identity(&kp);
                set_session(kp);
                Ok(out)
            }
        }
        "restore" => {
            let words = secret(req, "words")?;
            let kp = keypair_from_mnemonic(&words, Network::Mainnet).map_err(|e| e.to_string())?;
            let out = identity(&kp);
            set_session(kp);
            Ok(out)
        }
        "address" => with_session(|kp| Ok(json!({ "address": shown(&kp.address), "network": network_name(kp.network()?) }))),
        // Use the unlocked key on mainnet or regtest: the address network
        // picks the chain id every signature commits to. `{network}` or the
        // older `{testnet: bool}`.
        "setnetwork" => {
            let testnet = match (req.get("network"), req.get("testnet")) {
                (Some(_), _) => parse_network(req)? == Network::Testnet,
                (None, Some(Value::Bool(t))) => *t,
                _ => return Err("missing `network` (\"mainnet\" or \"regtest\")".into()),
            };
            let mut s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
            let kp = s.as_mut().ok_or("wallet is locked")?;
            kp.address = gnb_crypto::crypto::address_from_pubkey(&kp.public_key, testnet);
            Ok(json!({ "address": shown(&kp.address), "network": network_name(kp.network()?) }))
        }
        // The GnB build locked GNB in the Bloch bridge vault here. ObenBlock
        // has no bridge: refuse, so no page can lock OBB into a vault that no
        // signer watches.
        "bridgelock" => Err("ObenBlock has no Bloch bridge: bridgelock is not available".into()),
        "export" => {
            let pw = secret(req, "password")?;
            with_session(|kp| kp.to_encrypted_json(&pw).map(|j| json!({ "keystore": j })))
        }
        "plan" => {
            let next_height = parse_height(req)?;
            let utxos = parse_spendable_utxos(req.get("utxos").ok_or("missing `utxos`")?, next_height)?;
            let amount = parse_amount(req, "amount")?;
            let fee = FeeChoice::AtLeast(parse_amount(req, "fee")?);
            with_session(|kp| {
                let chain = ChainId::for_network(kp.network()?);
                let opts = PaymentOptions { next_block_height: Some(next_height), ..PaymentOptions::default() };
                let version = opts.tx_version(chain)?;
                if amounts_committed_at(next_height, chain) {
                    return Ok(json!({ "prev_txids": [], "version": version }));
                }
                let outpoints = TxBuilder::plan_inputs(kp, &utxos, amount, fee)?;
                let mut txids: Vec<String> = outpoints.iter().map(|(t, _)| hex::encode(t)).collect();
                txids.dedup();
                Ok(json!({ "prev_txids": txids, "version": version }))
            })
        }
        "pay" => {
            let next_height = parse_height(req)?;
            let utxos = parse_spendable_utxos(req.get("utxos").ok_or("missing `utxos`")?, next_height)?;
            let amount = parse_amount(req, "amount")?;
            let fee = parse_amount(req, "fee")?;
            let to = s(req, "to")?;
            let mut prevs = PrevTxs::new();
            if let Some(map) = req.get("prevtxs").and_then(Value::as_object) {
                for (txid, raw) in map {
                    prevs.insert_hex(txid, raw.as_str().ok_or("prevtxs values must be hex strings")?)?;
                }
            }
            let fee_policy = match req.get("max_fee").and_then(Value::as_str) {
                Some(cap) => FeePolicy::with_max_fee(cap.parse().map_err(|_| "invalid max_fee")?),
                None => FeePolicy::DEFAULT,
            };
            let opts = PaymentOptions {
                fee: FeeChoice::AtLeast(fee),
                fee_policy,
                prev_txs: Some(&prevs),
                require_verified_inputs: req.get("require_verified").and_then(Value::as_bool).unwrap_or(false),
                next_block_height: Some(next_height),
                ..PaymentOptions::default()
            };
            with_session(|kp| pay(kp, &utxos, to, amount, &opts))
        }
        "wipe" => {
            let mut s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(kp) = s.as_mut() {
                kp.private_key.zeroize();
            }
            *s = None;
            Ok(json!({ "locked": true }))
        }
        "normalize" => {
            // Any accepted form (obb1, gnb1, bloch1, v2 Bech32m) of a
            // single-key address, shown as the ObenBlock form. Formatting is
            // opt-in: "legacy" (the default, `obb1q…`/`obb1t…`) or "bech32m"
            // (`obb1z…`/`tobb1z…`, BIP350, which binds the network).
            let address = Address::parse_in(s(req, "address")?.trim(), FAMILY)
                .map_err(|e| format!("invalid address: {e:?}"))?;
            let formatted = match req.get("format") {
                None => address.to_string_in(FAMILY),
                Some(Value::String(format)) if format == "legacy" => address.to_string_in(FAMILY),
                Some(Value::String(format)) if format == "bech32m" => address.to_bech32m_in(FAMILY),
                _ => return Err("unsupported address format; expected legacy or bech32m".into()),
            };
            Ok(json!({ "address": formatted, "network": network_name(address.network()) }))
        }
        "minfee" => {
            let size = req.get("size").and_then(Value::as_u64).ok_or("missing `size`")?;
            // CRY-8: `as usize` wrapped modulo 2^32 on wasm32 and quoted the
            // floor fee for sizes >= 2^32 (e.g. 2^32 + 100 -> 100 bytes).
            let size = usize::try_from(size).map_err(|_| "`size` too large")?;
            Ok(json!({ "fee": tokenomics::min_tx_fee_sat(size).to_string() }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

/// The key of an `open` request (CRY-7): the page states the network it
/// serves (the web wallet is a mainnet wallet; default "mainnet"). A keystore
/// v3 or keyfile v1 authenticates its own network, which must be this one; a
/// v2 file authenticates nothing and opens only as a key of this network
/// (`Keypair::from_encrypted_bytes_on`). `pay` then trusts the session key's
/// network.
fn open_keypair(req: &Value) -> Result<Keypair, String> {
    ensure_obenblock()?;
    let raw = s(req, "json")?.as_bytes();
    let pw = secret(req, "password")?;
    let network = parse_network(req)?;
    match Keypair::from_encrypted_bytes_on(raw, &pw, network) {
        Ok(kp) => Ok(kp),
        Err(e2) => match Wallet::from_encrypted_bytes(raw, &pw) {
            Ok(w) if w.network() == network => Ok(w.into_keypair()),
            Ok(_) => Err(format!("could not open the wallet: it is not a {} wallet", network_name(network))),
            Err(e1) => Err(format!("could not open the wallet: {e2} / {e1}")),
        },
    }
}

/// `network` of a request: "mainnet" (the default) or "regtest". "testnet"
/// is accepted as regtest's older name (ObenBlock has no public testnet;
/// its regtest uses the `Testnet` address network).
fn parse_network(req: &Value) -> Result<Network, String> {
    match req.get("network") {
        None => Ok(Network::Mainnet),
        Some(Value::String(n)) if n == "mainnet" => Ok(Network::Mainnet),
        Some(Value::String(n)) if n == "regtest" || n == "testnet" => Ok(Network::Testnet),
        Some(other) => Err(format!("unknown network `{}` (expected mainnet or regtest)",
            other.as_str().map_or_else(|| other.to_string(), str::to_owned))),
    }
}

fn network_name(n: Network) -> &'static str {
    if n == Network::Testnet { "regtest" } else { "mainnet" }
}

fn parse_amount(req: &Value, k: &str) -> Result<u64, String> {
    s(req, k)?.parse().map_err(|_| format!("invalid {k}"))
}

/// `next_height`: height of the block the payment targets (decimal string or
/// JSON number). Required: it selects the transaction version, and a guess
/// would sign a transaction the network rejects.
fn parse_height(req: &Value) -> Result<u64, String> {
    match req.get("next_height") {
        Some(Value::String(v)) => v.trim().parse().map_err(|_| "invalid next_height".to_string()),
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| "invalid next_height".to_string()),
        _ => Err("missing `next_height` (the node's getdaginfo next_block_height)".into()),
    }
}

fn pay(kp: &Keypair, utxos: &[Utxo], to: &str, amount: u64, opts: &PaymentOptions<'_>) -> Result<Value, String> {
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    // obb1 (and the gnb1 / bloch1 / v2 aliases of the same script).
    let dest = Address::parse_in(to.trim(), FAMILY).map_err(|e| format!("invalid destination: {e:?}"))?;
    let mine = Address::parse(&kp.address).map_err(|e| format!("{e:?}"))?;
    if dest.network() != mine.network() {
        return Err("destination is on another network".into());
    }
    let paid = TxBuilder::build_payment(kp, utxos, &dest, amount, opts)?;
    let raw = paid.tx.to_wire_bytes(true);
    Ok(json!({
        "raw": hex::encode(&raw), "txid": hex::encode(paid.tx.txid()), "size": paid.size,
        // WAL-1/WAL-6: the ACTUAL fee (inputs − outputs), including sub-dust change.
        "fee": paid.fee.to_string(), "dust_to_fee": paid.dust_to_fee.to_string(),
        "inputs": paid.tx.inputs.len(), "amount": amount.to_string(),
        "change": paid.change.to_string(), "inputs_total": paid.inputs_total.to_string(),
        "verified_inputs": paid.verified_inputs, "unverified_inputs": paid.unverified_inputs,
        // WAL-1 full fix: version 3 (sighash v3) commits every spent value.
        "version": paid.tx.version, "amounts_committed": paid.amounts_committed,
    }))
}

/// The `getutxos` rows spendable in the block at `next_height`: a coinbase
/// output (`coinbase_height` in its row) only from `COINBASE_MATURITY` blocks
/// after its coinbase (`send::utxo_row_spendable_at`, the rule `gnb-cli send`
/// applies too). Selecting an immature one signed a transaction every node
/// refuses; with only immature coins left, nothing is signed.
fn parse_spendable_utxos(rows: &Value, next_height: u64) -> Result<Vec<Utxo>, String> {
    let utxos = parse_utxos(rows)?;
    let rows = rows.as_array().ok_or("`utxos` must be an array")?;
    let mut spendable = Vec::with_capacity(utxos.len());
    let mut immature = 0;
    for (utxo, row) in utxos.into_iter().zip(rows) {
        if utxo_row_spendable_at(row, next_height)? { spendable.push(utxo) } else { immature += 1 }
    }
    if spendable.is_empty() && immature > 0 {
        let address = with_session(|kp| Ok(kp.address.clone())).unwrap_or_else(|_| "this wallet".into());
        return Err(all_immature_message(&address, immature, next_height));
    }
    Ok(spendable)
}

fn parse_utxos(rows: &Value) -> Result<Vec<Utxo>, String> {
    let rows = rows.as_array().ok_or("`utxos` must be an array")?;
    rows.iter().map(|row| {
        let txid: [u8; 32] = hex::decode(s(row, "txid")?).map_err(|e| e.to_string())?
            .try_into().map_err(|_| "UTXO txid must be 32 bytes".to_string())?;
        let index = row["index"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("bad UTXO index")?;
        let value = match &row["value"] {
            Value::String(v) => v.parse().map_err(|_| "bad UTXO value")?,
            Value::Number(n) => n.as_u64().ok_or("bad UTXO value")?,
            _ => return Err("bad UTXO value".into()),
        };
        let script_pubkey = hex::decode(s(row, "script_pubkey")?).map_err(|e| e.to_string())?;
        Ok(Utxo { txid, index, output: TxOutput { value, script_pubkey } })
    }).collect()
}

// ── C ABI ────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn gnb_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `ptr`/`len` must come from `gnb_alloc` or a `gnb_call` result.
#[no_mangle]
pub unsafe extern "C" fn gnb_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let mut v = Vec::from_raw_parts(ptr, len, len.max(1));
        v.zeroize();
    }
}

/// # Safety
/// `ptr`/`len` must describe a readable UTF-8 JSON buffer from `gnb_alloc`.
#[no_mangle]
pub unsafe extern "C" fn gnb_call(ptr: *const u8, len: usize) -> u64 {
    let input = std::slice::from_raw_parts(ptr, len);
    // CRY-4: `call_bytes` wipes the request's secrets and the response
    // `Value`, and returns the response in one exact buffer (no reallocation
    // copies); `gnb_free` wipes that buffer when the page frees it. (The
    // previous `out.to_string().into_bytes().into_boxed_slice()` freed
    // unwiped copies while growing and shrinking, and dropped the response
    // `Value` with the new recovery phrase in it.)
    let bytes = call_bytes(input);
    let n = bytes.len();
    let p = Box::into_raw(bytes) as *mut u8;
    ((p as u64) << 32) | n as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnb_crypto::core::{Transaction, TxInput};

    /// The session is process-global: tests that change it take this lock.
    static SESSION_TESTS: Mutex<()> = Mutex::new(());

    #[test]
    fn pqpsbt_public_decode_reaches_the_format_parser() {
        let err = handle(&json!({"op": "pqpsbt", "action": "decode", "hex": ""})).unwrap_err();
        assert!(err.contains("PQ-PSBT magic"), "missing public decoder: {err}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "key generation, signing and verification run the PQClean ML-DSA-65 and Falcon-1024 C code, which Miri cannot execute")]
    fn pqpsbt_wasm_roles_sign_in_session_and_reject_bad_context() {
        use gnb_crypto::core::policy::SpendPolicy;
        use gnb_crypto::wallet::{policy_spend::PolicySpend, pqpsbt::PqPsbt};
        let _session = SESSION_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        // The policy spend below is built before any request: fix the chain
        // first, as every request does.
        ensure_obenblock().unwrap();
        let mut keys = (0..3).map(|_| generate_keypair(false)).collect::<Vec<_>>();
        let policy = SpendPolicy::new(2, keys.iter().map(|k| k.public_key.clone()).collect(), 0, 0).unwrap();
        let mut spend = PolicySpend::new(Network::Mainnet, policy, &[([7;32],0,5_000_000)], vec![9;20], 1_000_000,0,0).unwrap();
        spend.target_height(17_500).unwrap();
        let document=PqPsbt::from_policy_spend(spend).unwrap();
        let hex=hex::encode(document.to_bytes().unwrap());
        let public=json!({"op":"pqpsbt","action":"decode","hex":hex});
        let decoded=handle(&public).unwrap();
        assert_eq!(handle(&json!({"op":"pqpsbt","action":"encode","json":decoded["json"]})).unwrap()["hex"],hex);
        let sign=json!({"op":"pqpsbt_sign","hex":hex,"network":"mainnet","next_height":"17500","max_fee":"5000000"});
        handle(&json!({"op":"wipe"})).unwrap();
        assert!(handle(&sign).unwrap_err().contains("locked"));
        set_session(keys.remove(0));
        // ObenBlock signs version 3 at every height, so an earlier height is
        // no longer a version mismatch; a malformed one is still refused.
        for (field,value) in [("max_fee","0"),("network","testnet"),("network","regtest"),("next_height","17x")] {
            let mut bad=sign.clone(); bad[field]=value.into(); assert!(handle(&bad).is_err(), "{field}={value}");
        }
        handle(&json!({"op":"setnetwork","testnet":true})).unwrap();
        assert!(handle(&sign).is_err(),"session network must be independently checked");
        handle(&json!({"op":"setnetwork","testnet":false})).unwrap();
        let first=handle(&sign).unwrap();
        assert_eq!(first["review"]["current_unspentness"],"not_checked_offline");
        set_session(keys.remove(1));
        let second=handle(&sign).unwrap();
        let combined=handle(&json!({"op":"pqpsbt","action":"combine","hex":first["hex"],"other_hex":second["hex"]})).unwrap();
        let finalized=handle(&json!({"op":"pqpsbt","action":"finalize","hex":combined["hex"],"network":"mainnet","next_height":"17500","max_fee":"5000000"})).unwrap();
        let tx=Transaction::from_wire_bytes(&hex::decode(finalized["hex"].as_str().unwrap()).unwrap()).unwrap();
        assert!(!tx.inputs[0].script_sig.is_empty());
        assert_eq!(finalized["txid"],hex::encode(document.spend.tx.txid()));
        handle(&json!({"op":"wipe"})).unwrap();
    }

    /// The ObenBlock mainnet form of a 20-byte key hash.
    fn obb(hash: [u8; 20], network: Network) -> String {
        Address::from_hash(hash, network).to_string_in(FAMILY)
    }

    /// The 20-byte script of an `obb1q…`/`obb1t…` address the core showed.
    fn spk_of(address: &str) -> Vec<u8> {
        Address::parse_in(address, FAMILY).unwrap().hash().to_vec()
    }

    #[test]
    fn chain_reports_the_obenblock_identity() {
        let main = handle(&json!({"op": "chain"})).unwrap();
        assert_eq!(main["chain"], "obenblock");
        assert_eq!(main["network"], "mainnet");
        assert_eq!(main["chain_id"], "0x4f420001");
        assert_eq!(main["address_prefix"], "obb1q");
        assert_eq!(main["policy_prefix"], "obb1m");
        assert_eq!(main["tx_version"], 3);
        assert_eq!(main["tx_version_3_from_height"], 0);
        let reg = handle(&json!({"op": "chain", "network": "regtest"})).unwrap();
        assert_eq!((reg["chain_id"].as_str(), reg["address_prefix"].as_str()), (Some("0x4f420002"), Some("obb1t")));
        assert_eq!(handle(&json!({"op": "chain", "network": "testnet"})).unwrap()["chain_id"], "0x4f420002",
            "testnet is regtest's older name");
        assert!(handle(&json!({"op": "chain", "network": "gnb"})).unwrap_err().contains("unknown network"));
        assert_eq!(gnb_crypto::core::chain::process_chain(), Chain::ObenBlock);
        assert_eq!(gnb_crypto::address::process_family(), AddressFamily::ObenBlock);
    }

    #[test]
    fn normalize_shows_obb_and_accepts_gnb_and_bloch_aliases() {
        let hash = [0x5a; 20];
        let main = obb(hash, Network::Mainnet);
        assert!(main.starts_with("obb1q"), "{main}");
        let gnb = Address::from_hash(hash, Network::Mainnet).to_string();
        let bloch = format!("bloch1q{}", &gnb[5..]);
        for form in [main.clone(), gnb.clone(), bloch, Address::from_hash(hash, Network::Mainnet).to_bech32m(),
                     Address::from_hash(hash, Network::Mainnet).to_bech32m_in(FAMILY)] {
            let r = handle(&json!({"op": "normalize", "address": form})).unwrap();
            assert_eq!(r["address"], main, "{form}");
            assert_eq!(r["network"], "mainnet");
        }
        let v2 = handle(&json!({"op": "normalize", "address": gnb, "format": "bech32m"})).unwrap();
        assert!(v2["address"].as_str().unwrap().starts_with("obb1z"), "{v2}");
        let reg = handle(&json!({"op": "normalize", "address": Address::from_hash(hash, Network::Testnet).to_string()})).unwrap();
        assert_eq!(reg["address"], obb(hash, Network::Testnet));
        assert_eq!(reg["network"], "regtest");
        let mut bad = main.clone();
        bad.replace_range(10..11, if &main[10..11] == "0" { "1" } else { "0" });
        assert!(handle(&json!({"op": "normalize", "address": bad})).is_err(), "checksum is checked");
    }

    // The session is process-global: keep every flow in one test.
    #[test]
    #[cfg_attr(miri, ignore = "key generation, signing and verification run the PQClean ML-DSA-65 and Falcon-1024 C code, which Miri cannot execute")]
    fn create_export_open_roundtrip_and_pay() {
        let _session = SESSION_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let created = handle(&json!({"op": "create"})).unwrap();
        let addr = created["address"].as_str().unwrap().to_string();
        assert!(addr.starts_with("obb1q") && addr.len() == 53, "{addr}");
        // WAL-7: phrase-backed by default, and the phrase restores the key.
        let words = created["words"].as_str().unwrap().to_string();
        assert_eq!(words.split_whitespace().count(), 24);
        let ks = handle(&json!({"op": "export", "password": "Correct-Horse-9-battery"})).unwrap();
        let ks = ks["keystore"].as_str().unwrap().to_string();
        assert!(ks.contains("\"version\": 3"), "exports keystore v3");
        // The keystore keeps the address string it always bound (gnb1q…),
        // so the GnB tools and the ObenBlock CLI open it alike.
        assert!(ks.contains(&format!("gnb1q{}", &addr[5..])), "{ks}");
        handle(&json!({"op": "wipe"})).unwrap();
        assert!(handle(&json!({"op": "address"})).is_err());
        let restored = handle(&json!({"op": "restore", "words": words})).unwrap();
        assert_eq!(restored["address"], addr);
        handle(&json!({"op": "wipe"})).unwrap();
        let opened = handle(&json!({"op": "open", "json": ks, "password": "Correct-Horse-9-battery"})).unwrap();
        assert_eq!(opened["address"], addr);
        assert_eq!(handle(&json!({"op": "address"})).unwrap(), json!({"address": addr, "network": "mainnet"}));

        // Pay 3 OBB from two 2 OBB outputs owned by this key.
        let spk = spk_of(&addr);
        let utxos = json!([
            {"txid": "11".repeat(32), "index": 0, "value": "200000000", "script_pubkey": hex::encode(&spk)},
            {"txid": "22".repeat(32), "index": 1, "value": "200000000", "script_pubkey": hex::encode(&spk)},
        ]);
        let to = obb([7u8; 20], Network::Mainnet);
        // Without the next block's height the core refuses to sign.
        let err = handle(&json!({"op": "pay", "utxos": utxos, "to": to, "amount": "300000000", "fee": "0"})).unwrap_err();
        assert!(err.contains("next_height"), "{err}");
        // ObenBlock: version 3 / sighash v3 from height 0, at every height.
        for next in [0u64, 1, 11, 17_499, 17_500, 1_000_000] {
            let plan = handle(&json!({"op": "plan", "utxos": utxos, "to": to, "amount": "300000000", "fee": "0",
                "next_height": next})).unwrap();
            assert_eq!(plan, json!({"prev_txids": [], "version": 3}), "next_height {next}");
        }
        let r = handle(&json!({"op": "pay", "utxos": utxos, "to": to, "amount": "300000000", "fee": "0",
            "next_height": "11"})).unwrap();
        assert_eq!(r["version"], 3);
        assert_eq!(r["amounts_committed"], true);
        assert_eq!(r["unverified_inputs"], 0);
        let size = r["size"].as_u64().unwrap() as usize;
        assert_eq!(r["inputs"], 2);
        let fee: u64 = r["fee"].as_str().unwrap().parse().unwrap();
        assert!(fee >= tokenomics::min_tx_fee_sat(size));
        // The reported fee is the actual one: inputs − amount − change.
        let change: u64 = r["change"].as_str().unwrap().parse().unwrap();
        assert_eq!(400_000_000 - 300_000_000 - change, fee);
        let raw = hex::decode(r["raw"].as_str().unwrap()).unwrap();
        assert_eq!(&raw[..4], &3u32.to_le_bytes(), "the wire transaction is version 3");
        let tx = Transaction::from_wire_bytes(&raw).unwrap();
        assert_eq!(hex::encode(tx.txid()), r["txid"].as_str().unwrap());
        assert_eq!(tx.outputs[0].script_pubkey, vec![7u8; 20]);
        // Every input verifies under the ObenBlock mainnet chain id, and
        // under no GnB chain id (the chain id keeps the chains apart).
        let spent: Vec<TxOutput> = (0..2).map(|_| TxOutput { value: 200_000_000, script_pubkey: spk.clone() }).collect();
        let verify = |chain: ChainId| gnb_crypto::core::sighash::verify_tx_scripts(&tx, &spent, chain, 11, 0);
        assert!(verify(ChainId::ObenBlockMainnet).is_ok());
        for other in [ChainId::Mainnet, ChainId::Testnet, ChainId::ObenBlockRegtest] {
            assert!(verify(other).is_err(), "{other:?}");
        }
        // gnb1q… and bloch1q… destinations are the same script.
        let gnb_to = Address::from_hash([7u8; 20], Network::Mainnet).to_string();
        for alias in [gnb_to.clone(), format!("bloch1q{}", &gnb_to[5..])] {
            let r = handle(&json!({"op": "pay", "utxos": utxos, "to": alias, "amount": "300000000", "fee": "0",
                "next_height": 11})).unwrap();
            let tx = Transaction::from_wire_bytes(&hex::decode(r["raw"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(tx.outputs[0].script_pubkey, vec![7u8; 20], "{alias}");
        }
        // A regtest destination is another network.
        let err = handle(&json!({"op": "pay", "utxos": utxos, "to": obb([7u8; 20], Network::Testnet),
            "amount": "300000000", "fee": "0", "next_height": 11})).unwrap_err();
        assert!(err.contains("another network"), "{err}");

        // ── WAL-1: a lied UTXO value cannot be spent: the v3 signature
        // commits to the value the page claimed ───────────────────────────
        let prev = Transaction {
            version: 3,
            inputs: vec![TxInput { prev_txid: [9; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 10_000_000_000, script_pubkey: spk.clone() }],
            locktime: 0,
        };
        let txid = hex::encode(prev.txid());
        let lied = json!([{"txid": txid, "index": 0, "value": "100050000", "script_pubkey": hex::encode(&spk)}]);
        // A supplied previous transaction is still checked before signing.
        let prevtxs = json!({ txid.clone(): hex::encode(prev.to_wire_bytes(true)) });
        let err = handle(&json!({"op": "pay", "utxos": lied, "to": to, "amount": "100000000", "fee": "0",
            "next_height": "11", "prevtxs": prevtxs})).unwrap_err();
        assert!(err.contains("refusing to sign"), "{err}");
        let r = handle(&json!({"op": "pay", "utxos": lied, "to": to, "amount": "100000000", "fee": "0",
            "next_height": "11", "require_verified": true})).unwrap();
        assert_eq!(r["amounts_committed"], true);
        let tx = Transaction::from_wire_bytes(&hex::decode(r["raw"].as_str().unwrap()).unwrap()).unwrap();
        let claimed = TxOutput { value: 100_050_000, script_pubkey: spk.clone() };
        let real = prev.outputs[0].clone();
        let verify = |spent: &TxOutput| gnb_crypto::core::sighash::verify_tx_scripts(
            &tx, std::slice::from_ref(spent), ChainId::ObenBlockMainnet, 11, 0);
        assert!(verify(&claimed).is_ok(), "valid for the value it was signed over");
        assert!(verify(&real).is_err(), "the lie invalidates it against the real coin");
        // The maximum-fee guard cannot be bypassed through `fee`.
        let honest = json!([{"txid": txid, "index": 0, "value": "10000000000", "script_pubkey": hex::encode(&spk)}]);
        let err = handle(&json!({"op": "pay", "utxos": honest, "to": to, "amount": "1", "fee": "9900000000",
            "next_height": "11"})).unwrap_err();
        assert!(err.contains("guard"), "{err}");

        // ── Coinbase maturity: an immature coinbase output is never selected ─
        // (it used to be, largest-first, and every node refused the payment).
        let m = gnb_crypto::core::COINBASE_MATURITY;
        let row = |txid: &str, value: &str, cb: Option<u64>| {
            let mut r = json!({"txid": txid.repeat(32), "index": 0, "value": value, "script_pubkey": hex::encode(&spk)});
            if let Some(h) = cb { r["coinbase_height"] = json!(h); }
            r
        };
        let coins = json!([
            row("33", "10000000000", Some(1_000)),       // 100 OBB, immature at 1_001
            row("44", "200000000", Some(1_001 - m)),     // mature at 1_001 exactly
            row("55", "200000000", None),                // not a coinbase output
        ]);
        let pay_at = |utxos: &Value, h: u64| handle(&json!({"op": "pay", "utxos": utxos, "to": to,
            "amount": "300000000", "fee": "0", "next_height": h.to_string()}));
        let spent = |r: &Value| -> Vec<[u8; 32]> {
            let tx = Transaction::from_wire_bytes(&hex::decode(r["raw"].as_str().unwrap()).unwrap()).unwrap();
            tx.inputs.iter().map(|i| i.prev_txid).collect()
        };
        let r = pay_at(&coins, 1_001).unwrap();
        assert_eq!(r["inputs"], 2);
        assert!(!spent(&r).contains(&[0x33; 32]), "the immature coinbase output was selected");
        // At coinbase_height + COINBASE_MATURITY it is spendable (and, the
        // largest coin, chosen alone).
        assert_eq!(spent(&pay_at(&coins, 1_000 + m).unwrap()), vec![[0x33; 32]]);
        // Only immature coins: refused before anything is signed.
        let err = pay_at(&json!([row("33", "10000000000", Some(1_000))]), 1_001).unwrap_err();
        assert!(err.contains("immature"), "{err}");
        let mut bad = coins.clone();
        bad[0]["coinbase_height"] = json!("1000");
        assert!(pay_at(&bad, 1_001).is_err(), "a malformed coinbase_height is refused");

        // ── Network selector: the same key on regtest signs for 0x4F420002 ─
        let reg = handle(&json!({"op": "setnetwork", "network": "regtest"})).unwrap();
        let reg_addr = reg["address"].as_str().unwrap().to_string();
        assert_eq!(reg_addr, format!("obb1t{}", &addr[5..]));
        assert_eq!(reg["network"], "regtest");
        let reg_to = obb([7u8; 20], Network::Testnet);
        let r = handle(&json!({"op": "pay", "utxos": utxos, "to": reg_to, "amount": "300000000", "fee": "0",
            "next_height": 1})).unwrap();
        let tx = Transaction::from_wire_bytes(&hex::decode(r["raw"].as_str().unwrap()).unwrap()).unwrap();
        let spent2: Vec<TxOutput> = (0..2).map(|_| TxOutput { value: 200_000_000, script_pubkey: spk.clone() }).collect();
        assert!(gnb_crypto::core::sighash::verify_tx_scripts(&tx, &spent2, ChainId::ObenBlockRegtest, 1, 0).is_ok());
        assert!(gnb_crypto::core::sighash::verify_tx_scripts(&tx, &spent2, ChainId::ObenBlockMainnet, 1, 0).is_err());
        assert!(handle(&json!({"op": "setnetwork", "network": "signet"})).is_err());
        assert_eq!(handle(&json!({"op": "setnetwork", "testnet": false})).unwrap()["address"], addr);
        handle(&json!({"op": "wipe"})).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "key generation runs the PQClean keygen")]
    fn regtest_create_makes_a_random_regtest_key() {
        let _session = SESSION_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        for req in [json!({"op": "create", "network": "regtest"}), json!({"op": "create", "testnet": true})] {
            let created = handle(&req).unwrap();
            assert!(created["address"].as_str().unwrap().starts_with("obb1t"), "{created}");
            assert!(created.get("words").is_none(), "no phrase on regtest");
        }
        assert!(handle(&json!({"op": "create", "network": "testnet3"})).is_err());
        handle(&json!({"op": "wipe"})).unwrap();
    }

    /// CRY-8: a size of 2^32 + 100 bytes must not be quoted as 100 bytes on a
    /// 32-bit target (wasm32, i686). 64-bit: the exact fee; 32-bit: an error.
    #[test]
    fn minfee_does_not_truncate_sizes_on_32_bit_targets() {
        let fee = |size: u64| handle(&json!({"op": "minfee", "size": size}));
        assert_eq!(fee(100).unwrap()["fee"], tokenomics::MIN_TX_FEE_SAT.to_string());
        let max32 = u64::from(u32::MAX);
        assert_eq!(fee(max32).unwrap()["fee"], tokenomics::min_tx_fee_sat(u32::MAX as usize).to_string());
        let huge = max32 + 101; // 2^32 + 100
        if usize::BITS == 32 {
            assert_eq!(fee(huge).unwrap_err(), "`size` too large");
        } else {
            assert_eq!(fee(huge).unwrap()["fee"], "8589934792");
        }
    }

    /// One request through the C ABI exactly as `site/wallet/core.js` makes
    /// it: gnb_alloc, write, gnb_call, gnb_free of the input, unpack
    /// `(ptr << 32) | len`, read, gnb_free of the output. The packing is valid
    /// only where pointers have 32 bits (wasm32), so this runs on i686: in the
    /// `i686` job natively and under Miri in `miri-cross`
    /// (scripts/sanitizers.sh), which checks every pointer, length and
    /// (de)allocation layout on this path.
    #[cfg(target_pointer_width = "32")]
    fn call_through_abi(input: &[u8]) -> Value {
        // SAFETY: the buffers come from gnb_alloc / gnb_call with the lengths
        // they were created with, and each is freed exactly once.
        unsafe {
            let p = gnb_alloc(input.len());
            std::ptr::copy_nonoverlapping(input.as_ptr(), p, input.len());
            let packed = gnb_call(p, input.len());
            gnb_free(p, input.len());
            let out_ptr: *mut u8 = std::ptr::with_exposed_provenance_mut((packed >> 32) as usize);
            let out_len = (packed & 0xFFFF_FFFF) as usize;
            let out = serde_json::from_slice(std::slice::from_raw_parts(out_ptr, out_len)).unwrap();
            gnb_free(out_ptr, out_len);
            out
        }
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn c_abi_roundtrip_on_32_bit() {
        let call = |req: Value| call_through_abi(req.to_string().as_bytes());
        assert_eq!(call(json!({"op": "minfee", "size": 100})), json!({"ok": {"fee": tokenomics::MIN_TX_FEE_SAT.to_string()}}));
        assert_eq!(call(json!({"op": "minfee", "size": 1u64 << 32})), json!({"error": "`size` too large"}));
        let to = Address::from_hash([7u8; 20], Network::Mainnet).to_string();
        let bloch = format!("bloch1q{}", &to[5..]);
        assert_eq!(call(json!({"op": "normalize", "address": bloch})),
            json!({"ok": {"address": format!("obb1q{}", &to[5..]), "network": "mainnet"}}));
        assert_eq!(call(json!({"op": "nope"})), json!({"error": "unknown op `nope`"}));
        let bad = call_through_abi(b"{not json");
        assert!(bad["error"].as_str().unwrap().starts_with("bad request: "), "{bad}");
        // Empty request: gnb_alloc(0) still returns a freeable buffer.
        assert!(call_through_abi(b"")["error"].as_str().unwrap().starts_with("bad request: "));
        // CRY-4 through the real ABI: the request's secret fields are wiped
        // by the time gnb_call drops them.
        let seen: std::rc::Rc<std::cell::RefCell<Vec<Value>>> = Default::default();
        let sink = seen.clone();
        WIPE_OBSERVER.with(|o| *o.borrow_mut() = Some(Box::new(move |req, _| {
            sink.borrow_mut().extend(req.cloned());
        })));
        call(json!({"op": "minfee", "size": 1, "password": "hunter2-hunter2", "words": "a b"}));
        WIPE_OBSERVER.with(|o| *o.borrow_mut() = None);
        assert_eq!(seen.borrow()[0]["password"], "");
        assert_eq!(seen.borrow()[0]["words"], "");
    }

    /// CRY-7: `open` opens a keystore of the network the page states
    /// (default mainnet) and refuses one of the other network, so `pay`,
    /// which trusts the session key's network, never runs on a key of the
    /// wrong network. (v2 files: gnb-crypto's
    /// `every_open_path_authenticates_the_network`.)
    #[test]
    #[cfg_attr(miri, ignore = "keystore encryption runs Argon2 and the PQClean keygen")]
    fn open_authenticates_the_network() {
        // `open_keypair` is the `open` op without the session (the session
        // is process-global: the round-trip test owns it).
        let testnet_key = gnb_crypto::wallet::generate_keypair(true);
        let ks = testnet_key.to_encrypted_json("Correct-Horse-9-battery").unwrap();
        let err = open_keypair(&json!({"json": ks, "password": "Correct-Horse-9-battery"})).unwrap_err();
        assert!(err.contains("mainnet was requested"), "{err}");
        // ObenBlock regtest uses the Testnet address network: "regtest", or
        // "testnet" as its older name.
        for network in ["regtest", "testnet"] {
            let opened = open_keypair(&json!({"json": ks, "password": "Correct-Horse-9-battery",
                "network": network})).unwrap();
            assert_eq!(opened.address, testnet_key.address);
        }
        assert!(open_keypair(&json!({"json": ks, "password": "x", "network": "signet"}))
            .unwrap_err().contains("unknown network"));
    }

    /// CRY-4: exactly what `gnb_call` does — `call_bytes` — leaves no secret
    /// in the request or response `Value`s it drops: the password and phrase
    /// fields of a request are wiped, and so is the new recovery phrase in
    /// the `create` response once it is serialised into the output buffer
    /// (which the page frees through the wiping `gnb_free`). Fails if
    /// `call_bytes` stops wiping either side.
    #[test]
    #[cfg_attr(miri, ignore = "create runs the PQClean keygen")]
    fn gnb_call_path_wipes_request_and_response_secrets() {
        let _session = SESSION_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        type Seen = std::rc::Rc<std::cell::RefCell<Vec<(Option<Value>, Value)>>>;
        let seen: Seen = Default::default();
        let sink = seen.clone();
        WIPE_OBSERVER.with(|o| *o.borrow_mut() = Some(Box::new(move |req, out| {
            sink.borrow_mut().push((req.cloned(), out.clone()));
        })));

        let out = call_bytes(br#"{"op":"minfee","size":10,"password":"hunter2-hunter2","words":"alpha beta"}"#);
        assert_eq!(serde_json::from_slice::<Value>(&out).unwrap()["ok"]["fee"], tokenomics::MIN_TX_FEE_SAT.to_string());
        let out = call_bytes(br#"{"op":"create"}"#);
        let created: Value = serde_json::from_slice(&out).unwrap();
        let words = created["ok"]["words"].as_str().unwrap().to_string();
        assert_eq!(words.split(' ').count(), 24, "the page still receives the phrase");
        WIPE_OBSERVER.with(|o| *o.borrow_mut() = None);
        handle(&json!({"op": "wipe"})).unwrap();

        let seen = seen.borrow();
        assert_eq!(seen.len(), 2);
        let (req, _) = &seen[0];
        let req = req.as_ref().unwrap();
        assert_eq!((req["password"].as_str(), req["words"].as_str()), (Some(""), Some("")),
            "request secrets wiped: {req}");
        let (_, resp) = &seen[1];
        assert!(resp["ok"]["words"] == "", "the phrase in the response Value must be wiped");
        fn all_strings_empty(v: &Value) -> bool {
            match v {
                Value::String(s) => s.is_empty(),
                Value::Array(a) => a.iter().all(all_strings_empty),
                Value::Object(m) => m.values().all(all_strings_empty),
                _ => true,
            }
        }
        assert!(all_strings_empty(resp), "every string of the response Value must be wiped");
        assert!(!String::from_utf8_lossy(&out).is_empty());
    }

    /// CRY-4: `gnb_call` is `call_bytes` behind the C ABI (the 32-bit ABI
    /// test exercises it end to end on i686), and a response is serialised
    /// into exactly its own length.
    #[test]
    fn gnb_call_delegates_to_the_wiping_path() {
        let src = include_str!("lib.rs");
        let body = &src[src.find("pub unsafe extern \"C\" fn gnb_call(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let code: String = body.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
        assert!(code.contains("call_bytes(input)"), "gnb_call must go through call_bytes");
        assert!(!code.contains("to_string()") && !code.contains("handle("), "{code}");
        let v = json!({"ok": {"words": "ab \"c\" \u{e9}", "n": [1, 2, {"x": null}]}});
        assert_eq!(&*serialize_exact(&v), serde_json::to_vec(&v).unwrap().as_slice());
    }

    #[test]
    fn secret_request_fields_are_wiped_after_dispatch() {
        let mut req = json!({"op": "minfee", "size": 10, "password": "hunter2-hunter2", "words": "a b c"});
        wipe_secret_fields(&mut req);
        assert_eq!(req["password"], "");
        assert_eq!(req["words"], "");
        assert!(handle_owned(json!({"op": "minfee", "size": 10, "password": "x"})).is_ok());
    }

    #[test]
    fn bridgelock_is_refused_on_obenblock() {
        let err = handle(&json!({"op": "bridgelock", "utxos": [], "vault_script": "", "amount": "1",
            "l2": "0x00", "fee": "0", "next_height": 1})).unwrap_err();
        assert!(err.contains("no Bloch bridge"), "{err}");
    }

}
