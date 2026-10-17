//! GnB PQ-PSBT v1, deliberately distinct from Bitcoin's wire format.
//! BIP174 roles / previous-transaction binding and BIP370 explicit versioning:
//! https://bips.dev/174/ and https://bips.dev/370/.
//! Only inputs of one policy or one tree branch are supported. Offline
//! previous-transaction authentication never proves current unspentness.

use super::policy_spend::PolicySpend;
use crate::address::Network;
use crate::core::policy::{PolicyTree, SpendPolicy};
use crate::core::sighash::SighashVersion;
use crate::core::{self, Transaction, TxOutput};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAGIC: &[u8; 8] = b"GNBPSBT\xff";
pub const VERSION: u16 = 1;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
// Every hex payload comes from the <= MAX_BYTES binary representation.
// The non-hex metadata is bounded by 181,504 bytes: 256 + 64 *
// (256 + 7 * (128 + 16 * 11) + 7 * 64). These conservative per-object
// budgets cover field names, delimiters, 20-digit u64 and 10-digit u32.
// The extra 256 KiB therefore preserves JSON transport for every binary.
pub const MAX_JSON_BYTES: usize = 2 * MAX_BYTES + 256 * 1024;
pub const MAX_INPUTS: usize = 64;
pub const MAX_OUTPUTS: usize = 64;
pub const MAX_TX_BYTES: usize = 1_000_000;
const MAX_POLICY: usize = 65_536;
const MAX_TREE: usize = 262_144;
const MAX_SCRIPT: usize = 10_000;
const MAX_SIG: usize = 8192;
const MAX_KEYS: usize = 7;
const MAX_PATH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derivation {
    pub key_index: u8,
    pub fingerprint: [u8; 4],
    pub path: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct InputData {
    pub prevout: TxOutput,
    pub previous_tx: Option<Vec<u8>>,
    /// Informational only: never an ownership/change/unspentness proof.
    pub derivations: Vec<Derivation>,
}

#[derive(Clone, Debug)]
pub struct PqPsbt {
    pub spend: PolicySpend,
    pub inputs: Vec<InputData>,
}

/// Trusted caller context, not fields imported from the transaction file.
#[derive(Clone, Copy, Debug)]
pub struct SignContext {
    pub network: Network,
    pub next_height: u64,
    /// Strict absolute ceiling, with no minimum-fee exception.
    pub max_fee: u64,
}

#[derive(Clone, Debug)]
pub struct Review {
    pub total_inputs: u64,
    pub total_outputs: u64,
    pub fee: u64,
    pub change: u64,
    pub previous_transactions_verified: usize,
}

impl Review {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"total_inputs": self.total_inputs.to_string(),
            "total_outputs": self.total_outputs.to_string(), "fee": self.fee.to_string(),
            "change": self.change.to_string(), "previous_transactions_verified": self.previous_transactions_verified,
            "current_unspentness": "not_checked_offline"})
    }
}

/// A validated final transaction. Private fields prevent forged finalized state.
pub struct Finalized(Transaction);
impl Finalized {
    pub fn extract(&self) -> Transaction {
        self.0.clone()
    }
}

fn strict_tx(bytes: &[u8]) -> Result<Transaction, String> {
    if bytes.len() > MAX_TX_BYTES {
        return Err("transaction exceeds PQ-PSBT limit".into());
    }
    let (tx, consumed) = Transaction::read_wire_bytes(bytes)?;
    if consumed != bytes.len() || tx.to_wire_bytes(true) != bytes {
        return Err("noncanonical or trailing transaction bytes".into());
    }
    Ok(tx)
}

impl PqPsbt {
    /// Creator/importer: transaction bytes and existing partials are fixed.
    /// v1 may still need previous transactions added by the updater.
    pub fn from_policy_spend(spend: PolicySpend) -> Result<Self, String> {
        spend.check_signing_shape()?;
        let script = spend.locking_script();
        let inputs = spend
            .amounts
            .iter()
            .map(|value| InputData {
                prevout: TxOutput {
                    value: *value,
                    script_pubkey: script.clone(),
                },
                previous_tx: None,
                derivations: Vec::new(),
            })
            .collect();
        let psbt = Self { spend, inputs };
        psbt.validate()?;
        Ok(psbt)
    }

    /// Cheap checks precede any signature verification on every public role,
    /// also for objects constructed by direct mutation of public fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.inputs.len() > MAX_INPUTS
            || self.spend.tx.inputs.len() > MAX_INPUTS
            || self.spend.tx.outputs.len() > MAX_OUTPUTS
        {
            return Err("PQ-PSBT input/output limit".into());
        }
        self.spend.check_signing_shape()?;
        if self.inputs.len() != self.spend.tx.inputs.len() {
            return Err("PQ-PSBT input count mismatch".into());
        }
        if self.spend.tx.wire_size(true) > MAX_TX_BYTES {
            return Err("transaction exceeds PQ-PSBT limit".into());
        }
        let script = self.spend.locking_script();
        let mut retained = 26 + self.spend.tx.wire_size(true) + self.spend.policy.encode().len();
        if let Some((tree, _)) = &self.spend.tree {
            retained += tree.encode().len();
        }
        for (i, input) in self.inputs.iter().enumerate() {
            if input.prevout.value != self.spend.amounts[i] || input.prevout.script_pubkey != script
            {
                return Err(format!(
                    "input {i}: value/script does not match the signing policy"
                ));
            }
            if input.derivations.len() > MAX_KEYS {
                return Err("too many derivations".into());
            }
            let mut previous_key = None;
            for derivation in &input.derivations {
                if derivation.key_index as usize >= self.spend.policy.pubkeys.len()
                    || previous_key.is_some_and(|k| k >= derivation.key_index)
                    || derivation.path.len() > MAX_PATH
                {
                    return Err("noncanonical derivation index/path".into());
                }
                previous_key = Some(derivation.key_index);
            }
            if let Some(raw) = &input.previous_tx {
                if raw.is_empty() || raw.len() > MAX_TX_BYTES {
                    return Err("previous transaction size".into());
                }
                retained = retained
                    .checked_add(raw.len())
                    .ok_or("PQ-PSBT size overflow")?;
                if retained > MAX_BYTES {
                    return Err("PQ-PSBT exceeds total byte limit".into());
                }
                // BIP174: authenticate the complete non-witness UTXO against
                // the outpoint before trusting its value or locking script.
                let previous = strict_tx(raw)?;
                let outpoint = &self.spend.tx.inputs[i];
                if previous.txid() != outpoint.prev_txid
                    || !previous
                        .outputs
                        .get(outpoint.prev_index as usize)
                        .is_some_and(|o| same_output(o, &input.prevout))
                {
                    return Err(format!("input {i}: previous transaction/outpoint mismatch"));
                }
            }
            retained += 18
                + input.prevout.script_pubkey.len()
                + input
                    .derivations
                    .iter()
                    .map(|d| 6 + 4 * d.path.len())
                    .sum::<usize>()
                + self.spend.signatures[i]
                    .values()
                    .map(|s| 5 + s.len())
                    .sum::<usize>();
            if retained > MAX_BYTES {
                return Err("PQ-PSBT exceeds total byte limit".into());
            }
        }
        Ok(())
    }

    /// Updater adds information only. Contradictory previously present data
    /// is never replaced, including derivation hints.
    pub fn update_input(&mut self, index: usize, update: InputData) -> Result<(), String> {
        self.validate()?;
        if update
            .previous_tx
            .as_ref()
            .is_some_and(|raw| raw.len() > MAX_TX_BYTES)
            || update.derivations.len() > MAX_KEYS
            || update
                .derivations
                .windows(2)
                .any(|p| p[0].key_index >= p[1].key_index)
            || update.derivations.iter().any(|d| d.path.len() > MAX_PATH)
        {
            return Err("noncanonical or oversized input update".into());
        }
        let mut next = self.clone();
        let current = next
            .inputs
            .get_mut(index)
            .ok_or("input index out of range")?;
        merge_input(current, &update)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// BIP174 permits rejecting contradictory maps; this format always does.
    /// Metadata cannot modify the exact unsigned transaction (BIP370 intent).
    pub fn combine(&self, other: &Self) -> Result<Self, String> {
        self.validate()?;
        other.validate()?;
        if self.spend.network != other.spend.network
            || self.spend.tx.to_wire_bytes(true) != other.spend.tx.to_wire_bytes(true)
            || self.spend.policy != other.spend.policy
            || self.spend.tree != other.spend.tree
        {
            return Err("cannot combine different transactions/policies/networks".into());
        }
        let mut out = self.clone();
        for i in 0..self.inputs.len() {
            merge_input(&mut out.inputs[i], &other.inputs[i])?;
            for (key, sig) in &other.spend.signatures[i] {
                match out.spend.signatures[i].get(key) {
                    Some(existing) if existing != sig => {
                        return Err("conflicting partial signature".into())
                    }
                    Some(_) => {}
                    None => {
                        out.spend.signatures[i].insert(*key, sig.clone());
                    }
                }
            }
        }
        out.validate()?;
        Ok(out)
    }

    pub fn review(&self, context: &SignContext) -> Result<Review, String> {
        self.validate()?;
        if self.spend.network != context.network {
            return Err("signing context network mismatch".into());
        }
        let activation =
            core::activation::hardening_activation_height_for_signer(self.spend.chain_id());
        core::sighash::check_tx_version_standard(
            self.spend.tx.version,
            context.next_height,
            activation,
        )?;
        if self.spend.tx.locktime as u64 > context.next_height {
            return Err("transaction is not final at the supplied height".into());
        }
        // PF-4: the second hardening upgrade's key-identity rule at the
        // supplied height, like the version and finality rules above (every
        // signer and the finalizer review through here).
        self.spend.check_key_identities_for_height(context.next_height)?;
        let verified = self
            .inputs
            .iter()
            .filter(|i| i.previous_tx.is_some())
            .count();
        if self.spend.tx.version == 1 && verified != self.inputs.len() {
            return Err("v1 signing requires every complete previous transaction".into());
        }
        // BIP174 signer checks include the transaction's basic validity.
        // Reuse the node's MoneyRange helpers; u64-only structural decoding
        // remains available to the updater and independent codec reference.
        let total_outputs = core::limits::check_tx_money_range(&self.spend.tx)?;
        let total_inputs = self
            .inputs
            .iter()
            .try_fold(0u64, |s, i| core::limits::money_add(s, i.prevout.value))
            .map_err(|e| format!("input total: {e}"))?;
        let fee = total_inputs
            .checked_sub(total_outputs)
            .ok_or("outputs exceed inputs")?;
        // A signer-supplied absolute ceiling is binding even when a large
        // witness would require a higher minimum. Do not reuse FeePolicy's
        // separate, intentional minimum-fee exception here.
        if fee > context.max_fee {
            return Err(format!(
                "fee {fee} exceeds explicit ceiling {}",
                context.max_fee
            ));
        }
        // This floor is independent of eventual witness size. Check the
        // exact shared minimum only once the final witness exists below.
        if fee < core::tokenomics::MIN_TX_FEE_SAT {
            return Err("fee below absolute consensus minimum".into());
        }
        let script = self.spend.locking_script();
        let change = self
            .spend
            .tx
            .outputs
            .iter()
            .filter(|o| o.script_pubkey == script)
            .try_fold(0u64, |s, o| s.checked_add(o.value))
            .ok_or("change total overflows")?;
        Ok(Review {
            total_inputs,
            total_outputs,
            fee,
            change,
            previous_transactions_verified: verified,
        })
    }

    fn verify_partials(&self) -> Result<(), String> {
        for (i, signatures) in self.spend.signatures.iter().enumerate() {
            for (key, sig) in signatures {
                let pk = &self.spend.policy.pubkeys[*key as usize];
                if !self.spend.verifies(pk, &self.spend.digest(i, pk)?, sig) {
                    return Err(format!("invalid partial signature at input {i}, key {key}"));
                }
            }
        }
        Ok(())
    }

    /// Public-data preflight, usable before opening a keystore. The signer
    /// repeats it so callers cannot accidentally skip partial validation.
    pub fn review_for_signing(&self, context: &SignContext) -> Result<Review, String> {
        let review = self.review(context)?;
        self.verify_partials()?;
        Ok(review)
    }

    pub fn sign(
        &mut self,
        context: &SignContext,
        public_key: &[u8],
        sign: impl Fn(&[u8; 32], SighashVersion) -> Result<Vec<u8>, String>,
    ) -> Result<u8, String> {
        self.review_for_signing(context)?;
        let index = self
            .spend
            .policy
            .pubkeys
            .iter()
            .position(|k| k == public_key)
            .ok_or("key is not in policy")? as u8;
        let mut next = self.spend.clone();
        let position = std::cell::Cell::new(0);
        next.sign_digest(public_key, |digest, version| {
            let i = position.get();
            position.set(i + 1);
            match self.spend.signatures[i].get(&index) {
                Some(sig) => Ok(sig.clone()),
                None => sign(digest, version),
            }
        })?;
        let candidate = Self {
            spend: next,
            inputs: self.inputs.clone(),
        };
        // Partial signatures themselves consume the document's byte budget.
        // Commit atomically only if the whole candidate can still be encoded.
        candidate.validate()?;
        *self = candidate;
        Ok(index)
    }

    pub fn finalize(&self, context: &SignContext) -> Result<Finalized, String> {
        let review = self.review(context)?;
        self.verify_partials()?;
        let tx = self.spend.finalize()?;
        if tx.wire_size(true) > MAX_TX_BYTES {
            return Err("final transaction exceeds size limit".into());
        }
        core::check_min_fee(&tx, review.fee)?;
        let prevouts: Vec<_> = self.inputs.iter().map(|i| i.prevout.clone()).collect();
        let activation =
            core::activation::hardening_activation_height_for_signer(self.spend.chain_id());
        core::sighash::verify_tx_scripts(
            &tx,
            &prevouts,
            self.spend.chain_id(),
            context.next_height,
            activation,
        )
        .map_err(|e| format!("final witness: {e:?}"))?;
        Ok(Finalized(tx))
    }
}

fn same_output(a: &TxOutput, b: &TxOutput) -> bool {
    a.value == b.value && a.script_pubkey == b.script_pubkey
}

fn merge_input(current: &mut InputData, incoming: &InputData) -> Result<(), String> {
    if !same_output(&current.prevout, &incoming.prevout) {
        return Err("conflicting input value/script".into());
    }
    match (&current.previous_tx, &incoming.previous_tx) {
        (Some(a), Some(b)) if a != b => return Err("conflicting previous transaction".into()),
        (None, Some(raw)) => current.previous_tx = Some(raw.clone()),
        _ => {}
    }
    for d in &incoming.derivations {
        match current
            .derivations
            .iter()
            .find(|x| x.key_index == d.key_index)
        {
            Some(existing) if existing != d => return Err("conflicting derivation metadata".into()),
            Some(_) => {}
            None => current.derivations.push(d.clone()),
        }
    }
    current.derivations.sort_by_key(|d| d.key_index);
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.0.len() {
            return Err("truncated PQ-PSBT".into());
        }
        let (out, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        if n > max {
            return Err("PQ-PSBT field length exceeds limit".into());
        }
        self.take(n)
    }
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

impl PqPsbt {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.push(match self.spend.network {
            Network::Mainnet => 0,
            Network::Testnet => 1,
        });
        blob(&mut out, &self.spend.tx.to_wire_bytes(true));
        blob(&mut out, &self.spend.policy.encode());
        match &self.spend.tree {
            Some((tree, branch)) => {
                blob(&mut out, &tree.encode());
                out.push(*branch);
            }
            None => {
                blob(&mut out, &[]);
                out.push(255);
            }
        }
        out.extend_from_slice(&(self.inputs.len() as u16).to_le_bytes());
        for (i, input) in self.inputs.iter().enumerate() {
            out.extend_from_slice(&input.prevout.value.to_le_bytes());
            blob(&mut out, &input.prevout.script_pubkey);
            blob(&mut out, input.previous_tx.as_deref().unwrap_or_default());
            out.push(input.derivations.len() as u8);
            for d in &input.derivations {
                out.push(d.key_index);
                out.extend_from_slice(&d.fingerprint);
                out.push(d.path.len() as u8);
                for child in &d.path {
                    out.extend_from_slice(&child.to_le_bytes());
                }
            }
            out.push(self.spend.signatures[i].len() as u8);
            for (key, sig) in &self.spend.signatures[i] {
                out.push(*key);
                blob(&mut out, sig);
            }
        }
        if out.len() > MAX_BYTES {
            return Err("PQ-PSBT exceeds total byte limit".into());
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_BYTES {
            return Err("PQ-PSBT exceeds total byte limit".into());
        }
        if !bytes.starts_with(MAGIC) {
            return Err("invalid PQ-PSBT magic".into());
        }
        let mut r = Reader(&bytes[MAGIC.len()..]);
        if r.u16()? != VERSION {
            return Err("unsupported PQ-PSBT version".into());
        }
        let network = match r.u8()? {
            0 => Network::Mainnet,
            1 => Network::Testnet,
            _ => return Err("unknown PQ-PSBT network".into()),
        };
        let tx = strict_tx(r.blob(MAX_TX_BYTES)?)?;
        let policy =
            SpendPolicy::decode(r.blob(MAX_POLICY)?).map_err(|e| format!("policy: {e}"))?;
        let tree_bytes = r.blob(MAX_TREE)?;
        let branch = r.u8()?;
        let tree = if tree_bytes.is_empty() {
            if branch != 255 {
                return Err("branch without a tree".into());
            }
            None
        } else {
            Some((
                PolicyTree::decode(tree_bytes).map_err(|e| format!("tree: {e}"))?,
                branch,
            ))
        };
        let count = r.u16()? as usize;
        if count == 0 || count > MAX_INPUTS || count != tx.inputs.len() {
            return Err("PQ-PSBT input count mismatch/limit".into());
        }
        let mut inputs = Vec::new();
        let mut signatures = Vec::new();
        for _ in 0..count {
            let value = r.u64()?;
            let script_pubkey = r.blob(MAX_SCRIPT)?.to_vec();
            let previous = r.blob(MAX_TX_BYTES)?;
            let previous_tx = (!previous.is_empty()).then(|| previous.to_vec());
            let n = r.u8()? as usize;
            if n > MAX_KEYS {
                return Err("too many derivations".into());
            }
            let mut derivations = Vec::new();
            for _ in 0..n {
                let key_index = r.u8()?;
                let fingerprint = r.take(4)?.try_into().unwrap();
                let depth = r.u8()? as usize;
                if depth > MAX_PATH {
                    return Err("derivation path too long".into());
                }
                let mut path = Vec::new();
                for _ in 0..depth {
                    path.push(r.u32()?);
                }
                derivations.push(Derivation {
                    key_index,
                    fingerprint,
                    path,
                });
            }
            let n = r.u8()? as usize;
            if n > MAX_KEYS {
                return Err("too many partial signatures".into());
            }
            let mut partials = BTreeMap::new();
            let mut last = None;
            for _ in 0..n {
                let key = r.u8()?;
                if last.is_some_and(|p| p >= key) {
                    return Err("noncanonical partial signature index".into());
                }
                last = Some(key);
                partials.insert(key, r.blob(MAX_SIG)?.to_vec());
            }
            signatures.push(partials);
            inputs.push(InputData {
                prevout: TxOutput {
                    value,
                    script_pubkey,
                },
                previous_tx,
                derivations,
            });
        }
        if !r.0.is_empty() {
            return Err("trailing PQ-PSBT bytes".into());
        }
        let amounts = inputs.iter().map(|i| i.prevout.value).collect();
        let out = Self {
            spend: PolicySpend {
                network,
                policy,
                tree,
                tx,
                signatures,
                amounts,
            },
            inputs,
        };
        out.validate()?;
        Ok(out)
    }
}

/// Bounded sequence deserialization prevents tiny JSON elements from
/// expanding into unbounded metadata allocations before validation.
#[derive(Serialize)]
#[serde(transparent)]
struct Limited<T, const N: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Limited<T, N> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Visitor<T, N> {
            type Value = Limited<T, N>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "at most {N} entries")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while out.len() < N {
                    let Some(value) = seq.next_element()? else {
                        return Ok(Limited(out));
                    };
                    out.push(value);
                }
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("PQ-PSBT array limit"));
                }
                Ok(Limited(out))
            }
        }
        de.deserialize_seq(Visitor::<T, N>(std::marker::PhantomData))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDerivation {
    key_index: u8,
    fingerprint: String,
    path: Limited<u32, MAX_PATH>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSignature {
    key_index: u8,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonInput {
    value: String,
    script: String,
    #[serde(deserialize_with = "required_option")]
    previous_tx: Option<String>,
    derivations: Limited<JsonDerivation, MAX_KEYS>,
    signatures: Limited<JsonSignature, MAX_KEYS>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonPsbt {
    format: String,
    version: u16,
    network: String,
    transaction: String,
    policy: String,
    #[serde(deserialize_with = "required_option")]
    tree: Option<String>,
    #[serde(deserialize_with = "required_option")]
    branch: Option<u8>,
    inputs: Limited<JsonInput, MAX_INPUTS>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    de: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(de)
}

pub fn decimal(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|c| c.is_ascii_digit())
    {
        return Err("noncanonical decimal u64".into());
    }
    value.parse().map_err(|_| "decimal exceeds u64".into())
}
pub fn decode_hex(value: &str, max: usize) -> Result<Vec<u8>, String> {
    if value.len() > max.saturating_mul(2)
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("noncanonical/oversized lowercase hex".into());
    }
    hex::decode(value).map_err(|_| "invalid hex".into())
}

impl JsonInput {
    fn into_input(self) -> Result<(InputData, BTreeMap<u8, Vec<u8>>), String> {
        let prevout = TxOutput {
            value: decimal(&self.value)?,
            script_pubkey: decode_hex(&self.script, MAX_SCRIPT)?,
        };
        let previous_tx = self
            .previous_tx
            .map(|s| decode_hex(&s, MAX_TX_BYTES))
            .transpose()?;
        let derivations = self
            .derivations
            .0
            .into_iter()
            .map(|d| {
                Ok(Derivation {
                    key_index: d.key_index,
                    fingerprint: decode_hex(&d.fingerprint, 4)?
                        .try_into()
                        .map_err(|_| "fingerprint length")?,
                    path: d.path.0,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut signatures = BTreeMap::new();
        let mut last = None;
        for s in self.signatures.0 {
            if last.is_some_and(|i| i >= s.key_index) {
                return Err("noncanonical signature key index".into());
            }
            last = Some(s.key_index);
            signatures.insert(s.key_index, decode_hex(&s.signature, MAX_SIG)?);
        }
        Ok((
            InputData {
                prevout,
                previous_tx,
                derivations,
            },
            signatures,
        ))
    }
}

impl PqPsbt {
    pub fn from_json(text: &str) -> Result<Self, String> {
        if text.len() > MAX_JSON_BYTES {
            return Err("PQ-PSBT JSON exceeds limit".into());
        }
        let document: JsonPsbt =
            serde_json::from_str(text).map_err(|e| format!("PQ-PSBT JSON: {e}"))?;
        if document.format != "gnb-pqpsbt" || document.version != VERSION {
            return Err("unsupported PQ-PSBT format/version".into());
        }
        let network = parse_network(&document.network)?;
        let tx = strict_tx(&decode_hex(&document.transaction, MAX_TX_BYTES)?)?;
        let policy = SpendPolicy::decode(&decode_hex(&document.policy, MAX_POLICY)?)
            .map_err(|e| format!("policy: {e}"))?;
        let tree = match (document.tree, document.branch) {
            (None, None) => None,
            (Some(t), Some(b)) => Some((
                PolicyTree::decode(&decode_hex(&t, MAX_TREE)?).map_err(|e| format!("tree: {e}"))?,
                b,
            )),
            _ => return Err("tree and branch must be supplied together".into()),
        };
        let mut inputs = Vec::new();
        let mut signatures = Vec::new();
        for input in document.inputs.0 {
            let (input, partials) = input.into_input()?;
            inputs.push(input);
            signatures.push(partials);
        }
        let amounts = inputs.iter().map(|i| i.prevout.value).collect();
        let out = Self {
            spend: PolicySpend {
                network,
                policy,
                tree,
                tx,
                signatures,
                amounts,
            },
            inputs,
        };
        out.validate()?;
        Ok(out)
    }

    pub fn to_json(&self) -> Result<String, String> {
        self.validate()?;
        let document = JsonPsbt {
            format: "gnb-pqpsbt".into(),
            version: VERSION,
            network: network_name(self.spend.network).into(),
            transaction: hex::encode(self.spend.tx.to_wire_bytes(true)),
            policy: hex::encode(self.spend.policy.encode()),
            tree: self
                .spend
                .tree
                .as_ref()
                .map(|(t, _)| hex::encode(t.encode())),
            branch: self.spend.tree.as_ref().map(|(_, b)| *b),
            inputs: Limited(
                self.inputs
                    .iter()
                    .enumerate()
                    .map(|(i, input)| JsonInput {
                        value: input.prevout.value.to_string(),
                        script: hex::encode(&input.prevout.script_pubkey),
                        previous_tx: input.previous_tx.as_ref().map(hex::encode),
                        derivations: Limited(
                            input
                                .derivations
                                .iter()
                                .map(|d| JsonDerivation {
                                    key_index: d.key_index,
                                    fingerprint: hex::encode(d.fingerprint),
                                    path: Limited(d.path.clone()),
                                })
                                .collect(),
                        ),
                        signatures: Limited(
                            self.spend.signatures[i]
                                .iter()
                                .map(|(k, s)| JsonSignature {
                                    key_index: *k,
                                    signature: hex::encode(s),
                                })
                                .collect(),
                        ),
                    })
                    .collect(),
            ),
        };
        let text = serde_json::to_string(&document).map_err(|e| e.to_string())?;
        if text.len() > MAX_JSON_BYTES {
            return Err("PQ-PSBT JSON exceeds limit".into());
        }
        Ok(text)
    }
}

pub fn parse_network(network: &str) -> Result<Network, String> {
    match network {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        _ => Err("unknown network".into()),
    }
}
fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

/// Strict migration boundary. The old file's index maps must not silently
/// overwrite duplicate names or numeric aliases such as `0` and `00`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyFile {
    network: String,
    policy: String,
    tx: String,
    #[serde(default)]
    tree: Option<String>,
    #[serde(default)]
    branch: Option<u8>,
    signatures: Limited<LegacySignatures, MAX_INPUTS>,
    amounts: Limited<String, MAX_INPUTS>,
}
struct LegacySignatures(BTreeMap<u8, Vec<u8>>);
impl<'de> Deserialize<'de> for LegacySignatures {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = LegacySignatures;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("unique canonical signature indices")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if out.len() == MAX_KEYS {
                        return Err(serde::de::Error::custom("too many partials"));
                    }
                    let index = decimal(&key).map_err(serde::de::Error::custom)?;
                    if index >= MAX_KEYS as u64 || out.contains_key(&(index as u8)) {
                        return Err(serde::de::Error::custom(
                            "duplicate/out-of-range signature index",
                        ));
                    }
                    let value = map.next_value::<String>()?;
                    out.insert(
                        index as u8,
                        decode_hex(&value, MAX_SIG).map_err(serde::de::Error::custom)?,
                    );
                }
                Ok(LegacySignatures(out))
            }
        }
        de.deserialize_map(Visitor)
    }
}
impl PqPsbt {
    pub fn from_legacy_json(text: &str) -> Result<Self, String> {
        if text.len() > MAX_JSON_BYTES {
            return Err("legacy spend exceeds JSON limit".into());
        }
        let f: LegacyFile = serde_json::from_str(text).map_err(|e| format!("legacy spend: {e}"))?;
        let policy =
            SpendPolicy::decode(&decode_hex(&f.policy, MAX_POLICY)?).map_err(|e| e.to_string())?;
        let tree = match (f.tree, f.branch) {
            (None, None) => None,
            (Some(t), Some(b)) => Some((
                PolicyTree::decode(&decode_hex(&t, MAX_TREE)?).map_err(|e| e.to_string())?,
                b,
            )),
            _ => return Err("tree and branch must be supplied together".into()),
        };
        let tx = strict_tx(&decode_hex(&f.tx, MAX_TX_BYTES)?)?;
        // Preserve the old single-policy file's fixed payment/change convention.
        if tree.is_none()
            && tx
                .outputs
                .get(1)
                .is_some_and(|o| o.script_pubkey != policy.script_pubkey())
        {
            return Err("change output does not return to the policy".into());
        }
        Self::from_policy_spend(PolicySpend {
            network: parse_network(&f.network)?,
            policy,
            tree,
            tx,
            signatures: f.signatures.0.into_iter().map(|s| s.0).collect(),
            amounts: f
                .amounts
                .0
                .iter()
                .map(|s| decimal(s))
                .collect::<Result<_, _>>()?,
        })
    }
}

fn field<'a>(request: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    request
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("missing string field `{name}`"))
}

/// No private material or extension fields belong in these public-data roles.
pub fn check_request_fields(request: &serde_json::Value, allowed: &[&str]) -> Result<(), String> {
    let object = request
        .as_object()
        .ok_or("PQ-PSBT request must be an object")?;
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unknown PQ-PSBT request field `{key}`"));
        }
    }
    Ok(())
}

pub fn context_from_request(request: &serde_json::Value) -> Result<SignContext, String> {
    Ok(SignContext {
        network: parse_network(field(request, "network")?)?,
        next_height: decimal(field(request, "next_height")?)?,
        max_fee: decimal(field(request, "max_fee")?)?,
    })
}

pub fn public_request(request: &serde_json::Value) -> Result<serde_json::Value, String> {
    public_request_with_limits(request, MAX_INPUTS, MAX_INPUTS * MAX_KEYS)
}

/// Transport frontends can impose a smaller CPU budget. All decoding and
/// counting here is structural; no PQ verification occurs before this cap.
pub fn public_request_with_limits(
    request: &serde_json::Value,
    max_inputs: usize,
    max_signatures: usize,
) -> Result<serde_json::Value, String> {
    fn limit(p: &PqPsbt, inputs: usize, signatures: usize) -> Result<(), String> {
        if p.inputs.len() > inputs
            || p.spend.signatures.iter().map(BTreeMap::len).sum::<usize>() > signatures
        {
            Err("PQ-PSBT transport input/signature budget exceeded".into())
        } else {
            Ok(())
        }
    }
    let action = field(request, "action")?;
    let fields: &[&str] = match action {
        "decode" => &["op", "action", "hex"],
        "encode" => &["op", "action", "json"],
        "create" => &["op", "action", "spend_json"],
        "update" => &["op", "action", "hex", "index", "input_json"],
        "combine" => &["op", "action", "hex", "other_hex"],
        "review" | "finalize" | "extract" => {
            &["op", "action", "hex", "network", "next_height", "max_fee"]
        }
        _ => return Err("unknown PQ-PSBT action".into()),
    };
    check_request_fields(request, fields)?;
    let mut p = match action {
        "encode" => PqPsbt::from_json(field(request, "json")?)?,
        "create" => PqPsbt::from_legacy_json(field(request, "spend_json")?)?,
        "decode" | "update" | "combine" | "review" | "finalize" | "extract" => {
            PqPsbt::from_bytes(&decode_hex(field(request, "hex")?, MAX_BYTES)?)?
        }
        _ => return Err("unknown PQ-PSBT action".into()),
    };
    limit(&p, max_inputs, max_signatures)?;
    match action {
        "decode" => return Ok(serde_json::json!({"json": p.to_json()?})),
        "update" => {
            let index = request
                .get("index")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("missing integer input index")?;
            let text = field(request, "input_json")?;
            if text.len() > MAX_JSON_BYTES {
                return Err("input JSON exceeds limit".into());
            }
            let input: JsonInput = serde_json::from_str(text).map_err(|e| e.to_string())?;
            let (input, partials) = input.into_input()?;
            p.update_input(index, input)?;
            let current = p
                .spend
                .signatures
                .get_mut(index)
                .ok_or("input index out of range")?;
            for (key, sig) in partials {
                if current.get(&key).is_some_and(|old| old != &sig) {
                    return Err("conflicting partial signature".into());
                }
                current.insert(key, sig);
            }
            p.validate()?;
        }
        "combine" => {
            let other = PqPsbt::from_bytes(&decode_hex(field(request, "other_hex")?, MAX_BYTES)?)?;
            limit(&other, max_inputs, max_signatures)?;
            p = p.combine(&other)?;
        }
        "review" | "finalize" | "extract" => {
            let context = context_from_request(request)?;
            let review = p.review(&context)?.to_json();
            if action == "review" {
                return Ok(serde_json::json!({"review": review}));
            }
            let tx = p.finalize(&context)?.extract();
            return Ok(
                serde_json::json!({"hex": hex::encode(tx.to_wire_bytes(true)),
                "txid": hex::encode(tx.txid()), "review": review}),
            );
        }
        _ => {}
    }
    limit(&p, max_inputs, max_signatures)?;
    Ok(serde_json::json!({"hex": hex::encode(p.to_bytes()?)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TxInput;
    use crate::wallet::{generate_keypair, Keypair};

    fn fixture() -> (Vec<Keypair>, PqPsbt, SignContext) {
        let keys = (0..3).map(|_| generate_keypair(false)).collect::<Vec<_>>();
        let policy =
            SpendPolicy::new(2, keys.iter().map(|k| k.public_key.clone()).collect(), 0, 0).unwrap();
        let previous = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0; 32],
                prev_index: u32::MAX,
                script_sig: vec![42],
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 5_000_000,
                script_pubkey: policy.script_pubkey(),
            }],
            locktime: 0,
        };
        let spend = PolicySpend::new(
            Network::Mainnet,
            policy,
            &[(previous.txid(), 0, 5_000_000)],
            vec![9; 20],
            1_000_000,
            0,
            0,
        )
        .unwrap();
        let mut p = PqPsbt::from_policy_spend(spend).unwrap();
        let mut input = p.inputs[0].clone();
        input.previous_tx = Some(previous.to_wire_bytes(true));
        p.update_input(0, input).unwrap();
        let context = SignContext {
            network: Network::Mainnet,
            next_height: 17_499,
            max_fee: 5_000_000,
        };
        (keys, p, context)
    }

    /// PF-4 producers (shared rule 3, review finding): a spend of a policy
    /// listing one key twice (raw and enveloped) is reviewed, signed and
    /// finalized for a block one below the second hardening height, as
    /// before, and refused for a block at it, where every node refuses it.
    /// Where hardening 2 holds from genesis (testnet, regtest) such a spend
    /// is refused before any role runs. Before the fix every role accepted
    /// it at every height.
    #[test]
    fn twin_key_policy_spends_are_refused_from_hardening2() {
        use crate::core::activation;
        let _h1 = activation::scoped_override(0); // version 3 / sighash v3
        let k = generate_keypair(false);
        let other = generate_keypair(false);
        let raw = k.public_key[crate::crypto::SUITE_HEADER_LEN..].to_vec();
        let twin = SpendPolicy { threshold: 2, pubkeys: vec![raw, k.public_key.clone()], after: 0, older: 0 };
        let twin = SpendPolicy::decode(&twin.encode()).expect("consensus decoding accepts it");
        let honest = SpendPolicy::new(2, vec![k.public_key.clone(), other.public_key.clone()], 0, 0).unwrap();
        let build = |policy: SpendPolicy, next: u64| -> Result<PqPsbt, String> {
            let mut spend = PolicySpend::new(Network::Mainnet, policy, &[([0x31; 32], 0, 5_000_000)],
                vec![9; 20], 1_000_000, 0, 0)?;
            spend.target_height(next)?;
            PqPsbt::from_policy_spend(spend)
        };
        const H2: u64 = 40;
        let _h2 = activation::scoped_override_v2(H2);
        let context = |next_height| SignContext { network: Network::Mainnet, next_height, max_fee: 20_000_000 };

        // One block below hardening 2: built, reviewed and signed.
        let mut below = build(twin.clone(), H2 - 1).expect("valid below hardening 2");
        assert_eq!(below.spend.tx.version, 3);
        below.review(&context(H2 - 1)).expect("reviewed below hardening 2");
        below.sign(&context(H2 - 1), &k.public_key, |d, v| k.sign_tx_digest(d, v)).expect("signed");
        // At hardening 2: the builder, every reviewing role, the signer and
        // the finalizer refuse it.
        let e = build(twin.clone(), H2).unwrap_err();
        assert!(e.contains("same key twice"), "{e}");
        for h in [H2, H2 + 1, 1_000_000] {
            let e = below.review(&context(h)).unwrap_err();
            assert!(e.contains("same key twice"), "{h}: {e}");
            let e = below.clone().sign(&context(h), &k.public_key, |d, v| k.sign_tx_digest(d, v)).unwrap_err();
            assert!(e.contains("same key twice"), "{h}: {e}");
            assert!(below.finalize(&context(h)).is_err_and(|e| e.contains("same key twice")));
        }
        // An honest 2-of-2 is unaffected on both sides.
        for h in [H2 - 1, H2] {
            build(honest.clone(), h).unwrap().review(&context(h)).expect("honest policy");
        }
        // Hardening 2 from genesis (testnet, regtest): refused by the spend
        // builder, and by every role for a spend built past it.
        let mut spend = PolicySpend::new(Network::Mainnet, twin.clone(), &[([0x31; 32], 0, 5_000_000)],
            vec![9; 20], 1_000_000, 0, 0).unwrap();
        spend.target_height(H2 - 1).unwrap();
        let _genesis = activation::scoped_override_v2(0);
        assert!(PolicySpend::new(Network::Mainnet, twin, &[([0x31; 32], 0, 5_000_000)],
            vec![9; 20], 1_000_000, 0, 0).is_err_and(|e| e.contains("same key twice")));
        assert!(PqPsbt::from_policy_spend(spend.clone()).is_err_and(|e| e.contains("same key twice")));
        assert!(spend.sign_digest(&k.public_key, |d, v| k.sign_tx_digest(d, v))
            .is_err_and(|e| e.contains("same key twice")));
    }

    #[test]
    fn pqpsbt_two_of_three_roles_preserve_bytes_and_verify_final_witness() {
        let (keys, p, context) = fixture();
        let bytes = p.to_bytes().unwrap();
        assert_eq!(
            PqPsbt::from_json(&p.to_json().unwrap())
                .unwrap()
                .to_bytes()
                .unwrap(),
            bytes
        );
        let mut first = PqPsbt::from_bytes(&bytes).unwrap();
        let mut second = PqPsbt::from_bytes(&bytes).unwrap();
        first
            .sign(&context, &keys[0].public_key, |d, v| {
                keys[0].sign_tx_digest(d, v)
            })
            .unwrap();
        second
            .sign(&context, &keys[2].public_key, |d, v| {
                keys[2].sign_tx_digest(d, v)
            })
            .unwrap();
        assert!(first.finalize(&context).is_err());
        let combined = first.combine(&second).unwrap();
        assert_eq!(
            combined.to_bytes().unwrap(),
            second.combine(&first).unwrap().to_bytes().unwrap()
        );
        let final_tx = combined.finalize(&context).unwrap().extract();
        assert!(!final_tx.inputs[0].script_sig.is_empty());
        assert_eq!(final_tx.txid(), p.spend.tx.txid());
        let req = serde_json::json!({"action":"extract","hex":hex::encode(combined.to_bytes().unwrap()),
            "network":"mainnet","next_height":"17499","max_fee":"5000000"});
        assert_eq!(
            public_request(&req).unwrap()["hex"],
            hex::encode(final_tx.to_wire_bytes(true))
        );
        let before = combined.to_bytes().unwrap();
        let mut again = combined;
        again
            .sign(&context, &keys[0].public_key, |_, _| {
                panic!("already signed")
            })
            .unwrap();
        assert_eq!(again.to_bytes().unwrap(), before);
    }

    #[test]
    fn pqpsbt_strict_documents_reject_duplicates_missing_fields_and_trailing_transactions() {
        let (_, p, _) = fixture();
        let json = p.to_json().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        for field in ["tree", "branch"] {
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove(field);
            assert!(
                PqPsbt::from_json(&v.to_string()).is_err(),
                "missing {field}"
            );
        }
        value["inputs"][0]
            .as_object_mut()
            .unwrap()
            .remove("previous_tx");
        assert!(PqPsbt::from_json(&value.to_string()).is_err());
        assert!(PqPsbt::from_json(&json.replacen(
            "\"version\":1",
            "\"version\":1,\"version\":1",
            1
        ))
        .is_err());
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["transaction"] = format!("{}00", value["transaction"].as_str().unwrap()).into();
        assert!(PqPsbt::from_json(&value.to_string()).is_err());
        let mut bytes = p.to_bytes().unwrap();
        bytes.push(0);
        assert!(PqPsbt::from_bytes(&bytes).is_err());
        let legacy = serde_json::from_str::<serde_json::Value>(&p.spend.to_json().unwrap())
            .unwrap()
            .to_string();
        assert!(PqPsbt::from_legacy_json(&legacy).is_ok());
        for map in ["{\"0\":\"01\",\"0\":\"02\"}", "{\"00\":\"01\"}"] {
            assert!(
                PqPsbt::from_legacy_json(&legacy.replace("[{}]", &format!("[{map}]"))).is_err()
            );
        }
    }

    #[test]
    fn pqpsbt_signer_rejects_bad_public_data_before_callback_and_honors_activation() {
        let (keys, p, context) = fixture();
        let mut bad = Vec::new();
        let mut x = p.clone();
        x.inputs[0].prevout.value += 1;
        bad.push((x, context));
        let mut x = p.clone();
        x.inputs[0].previous_tx = None;
        bad.push((x, context));
        let mut x = p.clone();
        x.spend.amounts[0] = 1;
        bad.push((x, context));
        let mut x = p.clone();
        x.spend.signatures[0].insert(1, vec![1]);
        bad.push((x, context));
        bad.push((
            p.clone(),
            SignContext {
                max_fee: 0,
                ..context
            },
        ));
        bad.push((
            p.clone(),
            SignContext {
                network: Network::Testnet,
                ..context
            },
        ));
        bad.push((
            p.clone(),
            SignContext {
                next_height: 17_500,
                ..context
            },
        ));
        for (mut x, ctx) in bad {
            let calls = std::cell::Cell::new(0);
            assert!(x
                .sign(&ctx, &keys[0].public_key, |d, v| {
                    calls.set(calls.get() + 1);
                    keys[0].sign_tx_digest(d, v)
                })
                .is_err());
            assert_eq!(calls.get(), 0);
        }
        let mut v3 = p.clone();
        v3.spend.target_height(17_500).unwrap();
        v3.inputs[0].previous_tx = None;
        assert!(v3.review(&context).is_err());
        let ctx = SignContext {
            next_height: 17_500,
            ..context
        };
        v3.sign(&ctx, &keys[0].public_key, |d, v| {
            keys[0].sign_tx_digest(d, v)
        })
        .unwrap();
        v3.sign(&ctx, &keys[2].public_key, |d, v| {
            keys[2].sign_tx_digest(d, v)
        })
        .unwrap();
        assert!(v3.finalize(&ctx).is_ok());
    }
    #[test]
    fn pqpsbt_transport_budget_precedes_all_actual_signature_verification() {
        use crate::crypto::POLICY_VERIFICATION_CALLS;
        let (keys, mut p, context) = fixture();
        for key in [&keys[0], &keys[2]] {
            p.sign(&context, &key.public_key, |d, v| key.sign_tx_digest(d, v))
                .unwrap();
        }
        let request = serde_json::json!({"action":"extract","hex":hex::encode(p.to_bytes().unwrap()),
            "network":"mainnet","next_height":"17499","max_fee":"5000000"});
        for (inputs, signatures) in [(0, 16), (4, 1)] {
            POLICY_VERIFICATION_CALLS.with(|n| n.set(0));
            let result = public_request_with_limits(&request, inputs, signatures);
            assert!(result.unwrap_err().contains("budget"));
            assert_eq!(POLICY_VERIFICATION_CALLS.with(|n| n.get()), 0);
        }
        POLICY_VERIFICATION_CALLS.with(|n| n.set(0));
        assert!(public_request_with_limits(&request, 4, 16).is_ok());
        let calls = POLICY_VERIFICATION_CALLS.with(|n| n.get());
        // All partials, selected witnesses, then existing consensus verifier.
        assert_eq!(calls, 6);
        eprintln!("PQ-PSBT verification calls: rejected=0; accepted 2 partials={calls}");
    }

    #[test]
    fn pqpsbt_combine_conflicts_and_failed_signing_are_atomic() {
        let (keys, mut p, context) = fixture();
        let mut input = p.inputs[0].clone();
        input.derivations.push(Derivation {
            key_index: 0,
            fingerprint: [1; 4],
            path: vec![0x80000001],
        });
        p.update_input(0, input).unwrap();
        let before = p.to_bytes().unwrap();
        let mut other = p.clone();
        other.inputs[0].derivations[0].fingerprint = [2; 4];
        assert!(p.combine(&other).is_err());
        assert_eq!(p.to_bytes().unwrap(), before);
        let mut update = p.inputs[0].clone();
        update.prevout.value += 1;
        assert!(p.update_input(0, update).is_err());
        assert_eq!(p.to_bytes().unwrap(), before);
        assert!(p
            .sign(&context, &keys[0].public_key, |_, _| Err(
                "hardware signer refused".into()
            ))
            .is_err());
        assert_eq!(p.to_bytes().unwrap(), before);
        p.spend.signatures[0].insert(0, vec![1]);
        other = p.clone();
        other.spend.signatures[0].insert(0, vec![2]);
        assert!(p.combine(&other).is_err());
        other = p.clone();
        other.spend.tx.outputs[0].value += 1;
        assert!(p.combine(&other).is_err());
    }

    fn binary_limit_fixture() -> (Vec<Keypair>, PqPsbt) {
        let (keys, mut p, _) = fixture();
        let original = strict_tx(p.inputs[0].previous_tx.as_ref().unwrap()).unwrap();
        p.inputs = vec![p.inputs[0].clone(); 9];
        p.spend.amounts = vec![5_000_000; 9];
        p.spend.signatures = vec![BTreeMap::new(); 9];
        p.spend.tx.inputs = vec![p.spend.tx.inputs[0].clone(); 9];
        for i in 0..9 {
            let mut previous = original.clone();
            previous.inputs = vec![previous.inputs[0].clone(); 100];
            for (j, input) in previous.inputs.iter_mut().enumerate() {
                input.prev_txid = [i as u8; 32];
                input.prev_index = j as u32;
                input.script_sig = vec![i as u8; 9000];
            }
            p.spend.tx.inputs[i].prev_txid = previous.txid();
            p.inputs[i].previous_tx = Some(previous.to_wire_bytes(true));
        }
        let mut remaining = MAX_BYTES - 1 - p.to_bytes().unwrap().len();
        for i in 0..9 {
            let mut previous = strict_tx(p.inputs[i].previous_tx.as_ref().unwrap()).unwrap();
            let add = remaining.min(MAX_TX_BYTES - previous.wire_size(true));
            let mut extra = add;
            for input in &mut previous.inputs {
                let chunk = extra.min(10_000 - input.script_sig.len());
                input.script_sig.extend(std::iter::repeat_n(i as u8, chunk));
                extra -= chunk;
            }
            assert_eq!(extra, 0);
            p.spend.tx.inputs[i].prev_txid = previous.txid();
            p.inputs[i].previous_tx = Some(previous.to_wire_bytes(true));
            remaining -= add;
        }
        assert_eq!(remaining, 0);
        (keys, p)
    }

    #[test]
    fn pqpsbt_binary_limit_preserves_equivalent_bounded_json() {
        let (_, p) = binary_limit_fixture();
        assert_eq!(p.to_bytes().unwrap().len(), MAX_BYTES - 1);
        let text = p.to_json().unwrap();
        assert!(
            text.len() > 2 * MAX_BYTES,
            "fixture must exercise the old insufficient JSON cap"
        );
        assert!(text.len() <= MAX_JSON_BYTES);
        assert_eq!(
            PqPsbt::from_json(&text).unwrap().to_bytes().unwrap(),
            p.to_bytes().unwrap()
        );
        assert!(PqPsbt::from_json(&" ".repeat(MAX_JSON_BYTES + 1)).is_err());
        eprintln!(
            "maximum-size binary={} JSON={} cap={MAX_JSON_BYTES}",
            MAX_BYTES - 1,
            text.len()
        );
    }

    #[test]
    fn pqpsbt_public_request_rejects_unknown_and_secret_fields() {
        let (_, p, _) = fixture();
        let request =
            serde_json::json!({"action":"decode","hex":hex::encode(p.to_bytes().unwrap())});
        assert!(public_request(&request).is_ok());
        for field in ["private_key", "password", "wallet", "unexpected"] {
            let mut bad = request.clone();
            bad[field] = "untrusted metadata".into();
            assert!(
                public_request(&bad).is_err(),
                "unexpected field {field} was accepted"
            );
        }
    }

    #[test]
    fn pqpsbt_max_transport_budget_measures_48_verifications_and_zero_when_over() {
        use crate::crypto::POLICY_VERIFICATION_CALLS;
        let keys = (0..4).map(|_| generate_keypair(false)).collect::<Vec<_>>();
        let policy =
            SpendPolicy::new(4, keys.iter().map(|k| k.public_key.clone()).collect(), 0, 0).unwrap();
        let inputs = (1..=4).map(|i| ([i; 32], 0, 5_000_000)).collect::<Vec<_>>();
        let mut spend = PolicySpend::new(
            Network::Mainnet,
            policy,
            &inputs,
            vec![9; 20],
            1_000_000,
            0,
            0,
        )
        .unwrap();
        spend.target_height(17_500).unwrap();
        let mut p = PqPsbt::from_policy_spend(spend).unwrap();
        let context = SignContext {
            network: Network::Mainnet,
            next_height: 17_500,
            max_fee: 20_000_000,
        };
        for key in keys {
            p.sign(&context, &key.public_key, |d, v| key.sign_tx_digest(d, v))
                .unwrap();
        }
        let request = serde_json::json!({"action":"finalize","hex":hex::encode(p.to_bytes().unwrap()),
            "network":"mainnet","next_height":"17500","max_fee":"20000000"});
        for (inputs, signatures) in [(3, 16), (4, 15)] {
            POLICY_VERIFICATION_CALLS.with(|n| n.set(0));
            assert!(public_request_with_limits(&request, inputs, signatures)
                .unwrap_err()
                .contains("budget"));
            assert_eq!(POLICY_VERIFICATION_CALLS.with(|n| n.get()), 0);
        }
        POLICY_VERIFICATION_CALLS.with(|n| n.set(0));
        assert!(public_request_with_limits(&request, 4, 16).is_ok());
        assert_eq!(POLICY_VERIFICATION_CALLS.with(|n| n.get()), 48);
        eprintln!("PQ-PSBT maximum transport: 4 inputs/16 partials, accepted=48 verifier calls, over-budget=0");
    }

    #[test]
    fn pqpsbt_signer_does_not_commit_earlier_input_when_later_callback_fails() {
        let (keys, mut p, _) = fixture();
        p.spend.target_height(17_500).unwrap();
        p.inputs[0].previous_tx = None;
        p.inputs.push(p.inputs[0].clone());
        p.spend.amounts.push(p.spend.amounts[0]);
        p.spend.signatures.push(BTreeMap::new());
        let mut input = p.spend.tx.inputs[0].clone();
        input.prev_index = 1;
        p.spend.tx.inputs.push(input);
        let before = p.to_bytes().unwrap();
        let calls = std::cell::Cell::new(0);
        let context = SignContext {
            network: Network::Mainnet,
            next_height: 17_500,
            max_fee: 10_000_000,
        };
        assert!(p
            .sign(&context, &keys[0].public_key, |d, v| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err("signer refused second input".into())
                } else {
                    keys[0].sign_tx_digest(d, v)
                }
            })
            .is_err());
        assert_eq!(calls.get(), 2);
        assert_eq!(p.to_bytes().unwrap(), before);
    }
    fn v3_review_fixture() -> (Vec<Keypair>, PqPsbt, SignContext) {
        let (keys, mut p, mut context) = fixture();
        p.spend.target_height(17_500).unwrap();
        p.inputs[0].previous_tx = None;
        context.next_height = 17_500;
        context.max_fee = u64::MAX;
        (keys, p, context)
    }

    fn check_no_callback(mut p: PqPsbt, context: SignContext, key: &Keypair) -> String {
        p.validate().unwrap(); // Codec remains structural u64, by contract.
        let calls = std::cell::Cell::new(0);
        let result = p.sign(&context, &key.public_key, |d, v| {
            calls.set(calls.get() + 1);
            key.sign_tx_digest(d, v)
        });
        assert_eq!(
            calls.get(),
            0,
            "invalid preflight data reached the secret callback"
        );
        result.unwrap_err()
    }

    #[test]
    fn pqpsbt_review_rejects_input_above_money_range_before_callback() {
        let (keys, mut p, context) = v3_review_fixture();
        p.inputs[0].prevout.value = core::tokenomics::MAX_SUPPLY_SAT + 1;
        p.spend.amounts[0] = p.inputs[0].prevout.value;
        assert!(check_no_callback(p, context, &keys[0]).contains("input"));
    }

    #[test]
    fn pqpsbt_review_rejects_output_above_money_range_before_callback() {
        let (keys, mut p, context) = v3_review_fixture();
        p.inputs[0].prevout.value = core::tokenomics::MAX_SUPPLY_SAT + 50_001;
        p.spend.amounts[0] = p.inputs[0].prevout.value;
        p.spend.tx.outputs = vec![TxOutput {
            value: core::tokenomics::MAX_SUPPLY_SAT + 1,
            script_pubkey: vec![9; 20],
        }];
        assert!(check_no_callback(p, context, &keys[0]).contains("output"));
    }

    #[test]
    fn pqpsbt_review_rejects_input_sum_above_money_range_before_callback() {
        let (keys, mut p, context) = v3_review_fixture();
        let value = core::tokenomics::MAX_SUPPLY_SAT / 2 + 1;
        p.inputs[0].prevout.value = value;
        p.inputs.push(p.inputs[0].clone());
        p.spend.amounts = vec![value; 2];
        p.spend.signatures.push(BTreeMap::new());
        let mut input = p.spend.tx.inputs[0].clone();
        input.prev_index = 1;
        p.spend.tx.inputs.push(input);
        assert!(check_no_callback(p, context, &keys[0]).contains("input total"));
    }

    #[test]
    fn pqpsbt_review_rejects_output_sum_above_money_range_before_callback() {
        let (keys, mut p, context) = v3_review_fixture();
        let value = core::tokenomics::MAX_SUPPLY_SAT / 2 + 1;
        p.inputs[0].prevout.value = value;
        p.inputs.push(p.inputs[0].clone());
        p.spend.amounts = vec![value; 2];
        p.spend.signatures.push(BTreeMap::new());
        let mut input = p.spend.tx.inputs[0].clone();
        input.prev_index = 1;
        p.spend.tx.inputs.push(input);
        p.spend.tx.outputs = vec![
            TxOutput {
                value,
                script_pubkey: vec![9; 20]
            };
            2
        ];
        assert!(check_no_callback(p, context, &keys[0]).contains("output total"));
    }

    #[test]
    fn pqpsbt_review_rejects_fee_below_absolute_minimum_before_callback() {
        let (keys, mut p, context) = v3_review_fixture();
        p.spend.tx.outputs = vec![TxOutput {
            value: 5_000_000,
            script_pubkey: vec![9; 20],
        }];
        assert!(check_no_callback(p, context, &keys[0]).contains("minimum"));
    }

    #[test]
    fn pqpsbt_finalizer_rechecks_exact_consensus_minimum_with_real_witness() {
        let (keys, mut p, context) = v3_review_fixture();
        let fee = core::tokenomics::MIN_TX_FEE_SAT;
        p.spend.tx.outputs = vec![TxOutput {
            value: 5_000_000 - fee,
            script_pubkey: vec![9; 20],
        }];
        for key in [&keys[0], &keys[2]] {
            p.sign(&context, &key.public_key, |d, v| key.sign_tx_digest(d, v))
                .unwrap();
        }
        let transaction = p.spend.finalize().unwrap();
        eprintln!(
            "exact fee check: fee={fee}, bytes={}, minimum={}",
            transaction.wire_size(true),
            core::tokenomics::min_tx_fee_sat(transaction.wire_size(true))
        );
        assert!(
            core::check_min_fee(&transaction, fee).is_err(),
            "fixture must fail shared consensus minimum"
        );
        assert!(
            p.finalize(&context).is_err(),
            "finalized a transaction below its exact consensus fee"
        );
    }

    #[test]
    fn pqpsbt_signing_at_binary_limit_fails_atomically() {
        let (keys, mut p) = binary_limit_fixture();
        p.spend.target_height(17_500).unwrap();
        let context = SignContext {
            network: Network::Mainnet,
            next_height: 17_500,
            max_fee: 50_000_000,
        };
        let before = p.to_bytes().unwrap();
        let calls = std::cell::Cell::new(0);
        let result = p.sign(&context, &keys[0].public_key, |d, v| {
            calls.set(calls.get() + 1);
            keys[0].sign_tx_digest(d, v)
        });
        let after = p.to_bytes();
        eprintln!(
            "binary-limit signing: callbacks={}, result_ok={}, serializable={}, state_unchanged={}",
            calls.get(),
            result.is_ok(),
            after.is_ok(),
            after.as_ref().is_ok_and(|bytes| bytes == &before)
        );
        assert!(
            result.is_err(),
            "signing accepted a candidate beyond the binary byte limit"
        );
        assert_eq!(
            after.unwrap(),
            before,
            "failed signing must preserve the whole document"
        );
    }
}
