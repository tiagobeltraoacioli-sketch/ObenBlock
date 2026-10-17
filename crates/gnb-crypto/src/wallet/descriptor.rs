//! Static public descriptors and portable, bounded public identity pools.
//!
//! This is a GnB script language, not Bitcoin script descriptors. Only the
//! checksum follows BIP380: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>.
//! No key derivation or signing occurs. Exact public key bytes are preserved.
//! `create` builds policies with `SpendPolicy::new`, which also refuses a raw
//! key and its envelope in one policy (PF-4: one signer in two encodings).
//! `parse` (inspect, export, import) restores existing descriptors under the
//! consensus policy checks only, so a descriptor an earlier release created
//! with such a policy can still be inspected and its pool restored; its info
//! then carries `twin_key_encodings: true` (unspendable from the second
//! hardening height, docs/DESCRIPTORS.md).

use crate::address::{Address, Network, PolicyAddress};
use crate::core::policy::{PolicyTree, SpendPolicy, MAX_POLICY_KEYS};
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_DESCRIPTOR_BYTES: usize = 262_144;
pub const MAX_POOL_BYTES: usize = 1_048_576;
pub const MAX_POOL_ENTRIES: usize = 64;
pub const POOL_FORMAT: &str = "gnb-watch-only-v1";

const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(state: u64, symbol: u64) -> u64 {
    let high = state >> 35;
    let mut next = ((state & 0x7ffffffff) << 5) ^ symbol;
    for (bit, generator) in [
        0xf5dee51989,
        0xa9fdca3312,
        0x1bab10e32d,
        0x3706b1677a,
        0x644d626ffd,
    ]
    .iter()
    .enumerate()
    {
        if high & (1 << bit) != 0 {
            next ^= generator;
        }
    }
    next
}

/// The eight-character BIP380 checksum, not a language validator. The larger
/// GnB size limit does not inherit BIP380's shorter-length multi-error bounds.
pub fn checksum(body: &str) -> Result<String, String> {
    if body.len() > MAX_DESCRIPTOR_BYTES - 9 {
        return Err("descriptor too large".into());
    }
    let (mut state, mut group, mut count) = (1, 0, 0);
    for byte in body.bytes() {
        let value = INPUT_CHARSET
            .iter()
            .position(|&ch| ch == byte)
            .ok_or("invalid checksum character")? as u64;
        state = polymod(state, value & 31);
        group = group * 3 + (value >> 5);
        count += 1;
        if count == 3 {
            state = polymod(state, group);
            group = 0;
            count = 0;
        }
    }
    if count != 0 {
        state = polymod(state, group);
    }
    for _ in 0..8 {
        state = polymod(state, 0);
    }
    state ^= 1;
    Ok((0..8)
        .map(|i| CHECKSUM_CHARSET[((state >> (5 * (7 - i))) & 31) as usize] as char)
        .collect())
}

pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    }
}

fn parse_network(name: &str) -> Result<Network, String> {
    match name {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        _ => Err("invalid descriptor network".into()),
    }
}

fn public_key(text: &str) -> Result<Vec<u8>, String> {
    // Bound before allocating/decoding. Existing accepted hybrid shapes are
    // raw or the four-byte suite envelope; the predicate is authoritative.
    if text.len()
        > 2 * (crate::crypto::MLDSA_PUBKEY_LEN
            + crate::crypto::falcon::pubkey_len()
            + crate::crypto::SUITE_HEADER_LEN)
        || text.is_empty()
        || text
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("expected lowercase hybrid public key hex".into());
    }
    let bytes = hex::decode(text).map_err(|_| "invalid public key hex")?;
    if !crate::crypto::is_hybrid_public_key(&bytes) {
        return Err("unsupported public key representation".into());
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expression {
    Pkh(Vec<u8>),
    Policy(SpendPolicy),
    Tree(PolicyTree),
}

/// Descriptor text plus how policies are checked: `strict` (creating a
/// descriptor) refuses one key listed twice in its two encodings (PF-4,
/// `SpendPolicy::new`); otherwise (restoring one) only the consensus policy
/// checks apply.
struct Parser<'a>(&'a str, bool);
impl<'a> Parser<'a> {
    fn token(&mut self, token: &str) -> Result<(), String> {
        self.0 = self
            .0
            .strip_prefix(token)
            .ok_or("invalid descriptor grammar")?;
        Ok(())
    }
    fn number(&mut self) -> Result<u32, String> {
        let end = self.0.bytes().take_while(u8::is_ascii_digit).count();
        let text = &self.0[..end];
        if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
            return Err("noncanonical integer".into());
        }
        let number = text.parse().map_err(|_| "integer exceeds u32")?;
        self.0 = &self.0[end..];
        Ok(number)
    }
    fn key(&mut self) -> Result<Vec<u8>, String> {
        let end = self.0.find([',', ')']).ok_or("unterminated key")?;
        let bytes = public_key(&self.0[..end])?;
        self.0 = &self.0[end..];
        Ok(bytes)
    }
    fn policy(&mut self) -> Result<SpendPolicy, String> {
        self.token("policy(")?;
        let threshold = u8::try_from(self.number()?).map_err(|_| "threshold exceeds u8")?;
        self.token(",")?;
        let after = self.number()?;
        self.token(",")?;
        let older = self.number()?;
        self.token(",")?;
        let mut keys = vec![self.key()?];
        while self.0.starts_with(',') {
            if keys.len() == MAX_POLICY_KEYS {
                return Err("too many policy keys".into());
            }
            self.token(",")?;
            keys.push(self.key()?);
        }
        self.token(")")?;
        if self.1 {
            SpendPolicy::new(threshold, keys, after, older).map_err(|e| e.to_string())
        } else {
            // The consensus checks of every height (threshold, key count,
            // hybrid keys, byte-distinct keys): what the chain accepts as a
            // policy output, so what an earlier release may have created.
            SpendPolicy::decode(&SpendPolicy { threshold, pubkeys: keys, after, older }.encode())
                .map_err(|e| e.to_string())
        }
    }
    fn expression(&mut self) -> Result<Expression, String> {
        if self.0.starts_with("pkh(") {
            self.token("pkh(")?;
            let key = self.key()?;
            self.token(")")?;
            Ok(Expression::Pkh(key))
        } else if self.0.starts_with("policy(") {
            self.policy().map(Expression::Policy)
        } else {
            self.token("tree(")?;
            let mut branches = vec![self.policy()?];
            while self.0.starts_with(',') {
                if branches.len() == 4 {
                    return Err("too many tree branches".into());
                }
                self.token(",")?;
                branches.push(self.policy()?);
            }
            self.token(")")?;
            PolicyTree::new(branches)
                .map(Expression::Tree)
                .map_err(|e| e.to_string())
        }
    }
}

/// Validated descriptor. Private fields prevent bypassing the grammar/bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    network: Network,
    expression: Expression,
    text: String,
}
impl Descriptor {
    /// Create from a checksum-free, canonical body. A policy (or tree
    /// branch) that lists one key in its raw and its enveloped encoding is
    /// refused (PF-4).
    pub fn create(body: &str) -> Result<Self, String> {
        Self::build(body, true)
    }

    fn build(body: &str, strict: bool) -> Result<Self, String> {
        if body.len() > MAX_DESCRIPTOR_BYTES - 9 {
            return Err("descriptor too large".into());
        }
        if !body.is_ascii()
            || body
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_uppercase() || b == b'#')
        {
            return Err("noncanonical descriptor text".into());
        }
        let mut parser = Parser(body, strict);
        parser.token("gnbd1(")?;
        let end = parser.0.find(',').ok_or("missing descriptor network")?;
        let network = parse_network(&parser.0[..end])?;
        parser.0 = &parser.0[end + 1..];
        let expression = parser.expression()?;
        parser.token(")")?;
        if !parser.0.is_empty() {
            return Err("trailing descriptor data".into());
        }
        Ok(Self {
            network,
            expression,
            text: format!("{body}#{}", checksum(body)?),
        })
    }
    /// Import requires exactly one valid checksum and canonical spelling.
    ///
    /// Unlike [`Self::create`], a policy that lists one key in both
    /// encodings is restored (PF-4 review finding): an earlier release
    /// created and exported such descriptors, and refusing them would abort
    /// the whole pool's restore and hide the output its owner must move
    /// before the second hardening height. [`Self::info`] flags it.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_DESCRIPTOR_BYTES {
            return Err("descriptor too large".into());
        }
        let (body, supplied) = text.split_once('#').ok_or("descriptor checksum required")?;
        if supplied.len() != 8 || checksum(body)? != supplied {
            return Err("descriptor checksum mismatch".into());
        }
        Self::build(body, false)
    }

    /// PF-4: `true` when the policy, or a branch of the tree, lists one key
    /// twice (raw and enveloped encodings, `policy::key_identity`). A spend
    /// of that policy or branch is invalid from the second hardening height.
    pub fn has_twin_key_encodings(&self) -> bool {
        match &self.expression {
            Expression::Pkh(_) => false,
            Expression::Policy(policy) => policy.check_key_identities().is_err(),
            Expression::Tree(tree) => tree.branches.iter().any(|b| b.check_key_identities().is_err()),
        }
    }
    pub fn network(&self) -> Network {
        self.network
    }
    pub fn as_str(&self) -> &str {
        &self.text
    }
    pub fn script_pubkey(&self) -> Vec<u8> {
        match &self.expression {
            Expression::Pkh(key) => Address::from_pubkey(key, self.network).hash().to_vec(),
            Expression::Policy(policy) => policy.script_pubkey(),
            Expression::Tree(tree) => tree.script_pubkey(),
        }
    }
    pub fn info(&self) -> Value {
        let script = self.script_pubkey();
        let (kind, address, bech32m, activation) = match &self.expression {
            Expression::Pkh(key) => {
                let address = Address::from_pubkey(key, self.network);
                ("pkh", address.to_string(), address.to_bech32m(), false)
            }
            expression => {
                // Both constructors above return the existing policy script.
                let address = PolicyAddress::from_script(&script, self.network)
                    .expect("validated descriptor policy script");
                let tree = matches!(expression, Expression::Tree(_));
                (
                    if tree { "tree" } else { "policy" },
                    address.to_string(),
                    address.to_bech32m(),
                    tree,
                )
            }
        };
        let mut info = json!({"descriptor": self.text, "network": network_name(self.network), "kind": kind,
            "script_pubkey": hex::encode(script), "address": address, "bech32m": bech32m,
            "requires_policy_tree_activation": activation});
        // Present only when true, so the info of every other descriptor is
        // byte-for-byte what it was (docs/DESCRIPTORS.md).
        if self.has_twin_key_encodings() {
            info["twin_key_encodings"] = Value::Bool(true);
        }
        info
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PoolWire {
    format: String,
    network: String,
    descriptors: Vec<String>,
}

/// Public identity restoration only: no private keys, balance or chain scan.
#[derive(Debug, Clone)]
pub struct PublicPool {
    network: Network,
    entries: Vec<Descriptor>,
}
impl PublicPool {
    pub fn from_descriptors(network: Network, descriptors: &[String]) -> Result<Self, String> {
        if descriptors.is_empty() || descriptors.len() > MAX_POOL_ENTRIES {
            return Err("pool requires 1..=64 descriptors".into());
        }
        // A lower bound on the canonical bundle size, checked before parsing
        // entries or cloning strings. The exact serialized bound is checked too.
        let mut size = 0usize;
        for text in descriptors {
            size = size.checked_add(text.len()).ok_or("pool too large")?;
            if size > MAX_POOL_BYTES {
                return Err("pool too large".into());
            }
        }
        let mut scripts = BTreeSet::new();
        let mut entries = Vec::with_capacity(descriptors.len());
        for text in descriptors {
            let entry = Descriptor::parse(text)?;
            if entry.network != network {
                return Err("descriptor network mismatch".into());
            }
            if !scripts.insert(entry.script_pubkey()) {
                return Err("duplicate pool script".into());
            }
            entries.push(entry);
        }
        let pool = Self { network, entries };
        pool.to_bundle()?;
        Ok(pool)
    }
    pub fn from_public_keys(network: Network, keys: &[String]) -> Result<Self, String> {
        if keys.is_empty() || keys.len() > MAX_POOL_ENTRIES {
            return Err("pool requires 1..=64 public keys".into());
        }
        let mut descriptors = Vec::with_capacity(keys.len());
        for key in keys {
            public_key(key)?;
            descriptors.push(
                Descriptor::create(&format!("gnbd1({},pkh({key}))", network_name(network)))?.text,
            );
        }
        Self::from_descriptors(network, &descriptors)
    }
    pub fn from_bundle(bundle: &str, expected_network: Network) -> Result<Self, String> {
        if bundle.len() > MAX_POOL_BYTES {
            return Err("pool too large".into());
        }
        // Derive's map visitor rejects duplicate fields as well as unknowns.
        let wire: PoolWire =
            serde_json::from_str(bundle).map_err(|e| format!("invalid pool: {e}"))?;
        if wire.format != POOL_FORMAT {
            return Err("unsupported pool format".into());
        }
        if parse_network(&wire.network)? != expected_network {
            return Err("pool network mismatch".into());
        }
        Self::from_descriptors(expected_network, &wire.descriptors)
    }
    pub fn to_bundle(&self) -> Result<String, String> {
        // Struct declaration order fixes the canonical JSON field order.
        let wire = PoolWire {
            format: POOL_FORMAT.into(),
            network: network_name(self.network).into(),
            descriptors: self
                .entries
                .iter()
                .map(|entry| entry.text.clone())
                .collect(),
        };
        let bundle = serde_json::to_string(&wire).map_err(|e| e.to_string())?;
        if bundle.len() > MAX_POOL_BYTES {
            return Err("pool too large".into());
        }
        Ok(bundle)
    }
    pub fn response(&self) -> Result<Value, String> {
        Ok(
            json!({"bundle": self.to_bundle()?, "count": self.entries.len(), "entries": self.entries.iter().map(Descriptor::info).collect::<Vec<_>>()}),
        )
    }
}

fn string<'a>(request: &'a Value, key: &str) -> Result<&'a str, String> {
    request
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field `{key}`"))
}
fn strings(request: &Value, key: &str) -> Result<Vec<String>, String> {
    let values = request
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field `{key}`"))?;
    if values.is_empty() || values.len() > MAX_POOL_ENTRIES {
        return Err("pool requires 1..=64 entries".into());
    }
    // Validate aggregate bytes before cloning any caller-supplied strings.
    let mut bytes = 0usize;
    for value in values {
        bytes = bytes
            .checked_add(value.as_str().ok_or("expected string array")?.len())
            .ok_or("pool too large")?;
        if bytes > MAX_POOL_BYTES {
            return Err("pool too large".into());
        }
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "expected string array".into())
        })
        .collect()
}

/// Shared public API. Callers holding raw JSON use [`request_from_json`] first
/// because a pre-parsed Value cannot retain duplicate JSON field information.
pub fn public_request(request: &Value) -> Result<Value, String> {
    let fields = request
        .as_object()
        .ok_or("descriptor request must be an object")?;
    let action = string(request, "action")?;
    let argument = match action {
        "create" => "body",
        "inspect" => "descriptor",
        "export" => "descriptors",
        "import" => "bundle",
        "pool" => "public_keys",
        _ => return Err("unknown public descriptor action".into()),
    };
    if fields
        .keys()
        .any(|key| !["op", "action", "network", argument].contains(&key.as_str()))
    {
        return Err("unknown descriptor request field".into());
    }
    if fields
        .get("op")
        .is_some_and(|value| value.as_str() != Some("descriptor"))
    {
        return Err("invalid descriptor operation".into());
    }
    let network = parse_network(string(request, "network")?)?;
    match action {
        "create" | "inspect" => {
            let text = string(request, argument)?;
            let descriptor = if action == "create" {
                Descriptor::create(text)?
            } else {
                Descriptor::parse(text)?
            };
            if descriptor.network != network {
                return Err("descriptor network mismatch".into());
            }
            Ok(descriptor.info())
        }
        "export" => PublicPool::from_descriptors(network, &strings(request, argument)?)?.response(),
        "pool" => PublicPool::from_public_keys(network, &strings(request, argument)?)?.response(),
        "import" => PublicPool::from_bundle(string(request, argument)?, network)?.response(),
        _ => unreachable!("validated public action"),
    }
}

struct UniqueRequest(Value);
impl<'de> Deserialize<'de> for UniqueRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = UniqueRequest;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a public descriptor request object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if ![
                        "op",
                        "action",
                        "network",
                        "body",
                        "descriptor",
                        "descriptors",
                        "bundle",
                        "public_keys",
                    ]
                    .contains(&key.as_str())
                    {
                        return Err(de::Error::custom("unknown descriptor request field"));
                    }
                    if fields.contains_key(&key) {
                        return Err(de::Error::custom("duplicate descriptor request field"));
                    }
                    fields.insert(key, map.next_value()?);
                }
                Ok(UniqueRequest(Value::Object(fields)))
            }
        }
        deserializer.deserialize_map(Object)
    }
}

/// Parse raw JSON without losing duplicate fields; validate the public envelope.
pub fn request_from_json(input: &[u8]) -> Result<Value, String> {
    let request = serde_json::from_slice::<UniqueRequest>(input)
        .map_err(|e| format!("invalid descriptor request: {e}"))?
        .0;
    // Keep this function a parser, so execution occurs exactly once at caller.
    Ok(request)
}

struct DescriptorMarker(bool);
impl<'de> Deserialize<'de> for DescriptorMarker {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Marker;
        impl<'de> Visitor<'de> for Marker {
            type Value = DescriptorMarker;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(DescriptorMarker(value == "descriptor"))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(DescriptorMarker(false))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(DescriptorMarker(false))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(DescriptorMarker(false))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(DescriptorMarker(false))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(DescriptorMarker(false))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(DescriptorMarker(false))
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(DescriptorMarker(false))
            }
        }
        deserializer.deserialize_any(Marker)
    }
}

/// WASM routing probe: inspect every `op` occurrence, ignoring other values
/// without building a second Value tree or copying password/phrase values.
/// This adds one linear JSON scan. Only requests mentioning descriptor use
/// the new strict parser; all legacy operation parsing remains unchanged.
pub fn mentions_descriptor_operation(input: &[u8]) -> bool {
    struct Probe;
    impl<'de> Deserialize<'de> for Probe {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            IgnoredAny::deserialize(deserializer).map(|_| Probe)
        }
    }
    struct OperationProbe(bool);
    impl<'de> Deserialize<'de> for OperationProbe {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Object;
            impl<'de> Visitor<'de> for Object {
                type Value = OperationProbe;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("request object")
                }
                fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                    let mut found = false;
                    while let Some(key) = map.next_key::<String>()? {
                        if key == "op" {
                            found |= map.next_value::<DescriptorMarker>()?.0;
                        } else {
                            map.next_value::<Probe>()?;
                        }
                    }
                    Ok(OperationProbe(found))
                }
            }
            deserializer.deserialize_map(Object)
        }
    }
    serde_json::from_slice::<OperationProbe>(input).is_ok_and(|probe| probe.0)
}
