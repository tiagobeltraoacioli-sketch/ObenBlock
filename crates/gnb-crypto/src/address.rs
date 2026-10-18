//! Bloch-SIS Protocol — Unified Address type
//!
//! Replaces scattered `[u8; 20]`, `Vec<u8>`, `String` address handling
//! with a single ergonomic type. Works in all three forms:
//!
//!   - On-chain: 20-byte hash (`&[u8; 20]`)
//!   - User-facing: "gnb1q..." / "gnb1t..." string with checksum (ObenBlock:
//!     "obb1q..." / "obb1t...", see [`AddressFamily`])
//!   - Raw bytes: 24-byte payload (20 hash + 4 checksum)
//!
//! All validation, parsing, and display logic lives here. Other modules
//! should take `&Address` instead of `&[u8]`.

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use thiserror::Error;

use crate::core::{MAINNET_PREFIX, TESTNET_PREFIX};

mod bech32m;

/// Bloch address prefixes. A Bloch address and a GnB address with the same
/// 20-byte hash and checksum belong to the same key.
pub const LEGACY_BLOCH_MAINNET_PREFIX: &str = "bloch1q";
pub const LEGACY_BLOCH_TESTNET_PREFIX: &str = "bloch1t";

/// Map a Bloch address string to its GnB form (same hash and checksum);
/// anything else is returned unchanged. This is the GnB rule; see
/// [`normalize_legacy_address_in`] for ObenBlock.
pub fn normalize_legacy_address(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(LEGACY_BLOCH_MAINNET_PREFIX) {
        format!("{MAINNET_PREFIX}{rest}")
    } else if let Some(rest) = s.strip_prefix(LEGACY_BLOCH_TESTNET_PREFIX) {
        format!("{TESTNET_PREFIX}{rest}")
    } else {
        s.to_string()
    }
}

/// Map any address string `family` accepts to that family's form, keeping
/// the format (legacy hex stays legacy hex, Bech32m v2 stays v2).
///
/// * GnB: exactly [`normalize_legacy_address`] (`bloch1q`/`bloch1t` to
///   `gnb1q`/`gnb1t`; nothing else changes).
/// * ObenBlock: a valid `bloch1q`/`bloch1t`, `gnb1q`/`gnb1t`, `gnb1m`/`gnb1n`
///   or GnB v2 string, or an ObenBlock one, is shown as the `obb1…` (or
///   `obb1z…`/`tobb1z…`) address of the same output script
///   (DESIGN-obenblock.md §2). A legacy policy string gets a new checksum,
///   because that checksum covers the prefix. A string that does not parse
///   is returned unchanged, so the caller's parser reports the error.
pub fn normalize_legacy_address_in(s: &str, family: AddressFamily) -> String {
    if family == AddressFamily::Gnb {
        return normalize_legacy_address(s);
    }
    let Ok((network, script)) = destination_script_in(s, family) else {
        return s.to_string();
    };
    let v2 = bech32m::is_v2_candidate(s, family);
    if let Ok(hash) = <[u8; 20]>::try_from(script.as_slice()) {
        let a = Address::from_hash(hash, network);
        return if v2 { a.to_bech32m_in(family) } else { a.to_string_in(family) };
    }
    match PolicyAddress::from_script(&script, network) {
        Some(p) if v2 => p.to_bech32m_in(family),
        Some(p) => p.to_string_in(family),
        // destination_script_in returns only 20- or 33-byte policy scripts.
        None => s.to_string(),
    }
}

// ── Address families (GnB, ObenBlock) ─────────────────────────────────────────

/// Prefix of an ObenBlock mainnet single-key address.
pub const OBB_MAINNET_PREFIX: &str = "obb1q";
/// Prefix of an ObenBlock regtest single-key address.
pub const OBB_REGTEST_PREFIX: &str = "obb1t";
/// Prefix of an ObenBlock mainnet policy address.
pub const OBB_POLICY_MAINNET_PREFIX: &str = "obb1m";
/// Prefix of an ObenBlock regtest policy address.
pub const OBB_POLICY_REGTEST_PREFIX: &str = "obb1n";

/// Which chain's address strings are written and read. Scripts, hashes and
/// [`Network`] are the same for both: the family only picks the prefixes,
/// the Bech32m HRPs and the aliases a parser accepts.
///
/// * `Gnb`: `gnb1q`/`gnb1t`, `gnb1m`/`gnb1n`, v2 `gnb`/`tgnb`; Bloch's
///   `bloch1q`/`bloch1t` accepted. Every API without a family argument is
///   this family, unchanged.
/// * `ObenBlock`: `obb1q`/`obb1t`, `obb1m`/`obb1n`, v2 `obb`/`tobb`. Its
///   regtest uses the `Testnet` slot of [`Network`]. Every GnB form (and the
///   Bloch aliases) is also accepted as the same script (DESIGN-obenblock.md
///   §2); a GnB testnet string therefore names an ObenBlock regtest script,
///   and callers must still require the expected network.
///
/// Integration point: the node/wallet chain selector (O6a) picks the family
/// together with the network and passes it to the `*_in` functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Gnb,
    ObenBlock,
}

impl AddressFamily {
    /// Prefix of a legacy single-key address.
    pub const fn key_prefix(self, network: Network) -> &'static str {
        match (self, network) {
            (AddressFamily::Gnb, Network::Mainnet) => MAINNET_PREFIX,
            (AddressFamily::Gnb, Network::Testnet) => TESTNET_PREFIX,
            (AddressFamily::ObenBlock, Network::Mainnet) => OBB_MAINNET_PREFIX,
            (AddressFamily::ObenBlock, Network::Testnet) => OBB_REGTEST_PREFIX,
        }
    }

    /// Prefix of a legacy policy address.
    pub const fn policy_prefix(self, network: Network) -> &'static str {
        match (self, network) {
            (AddressFamily::Gnb, Network::Mainnet) => POLICY_MAINNET_PREFIX,
            (AddressFamily::Gnb, Network::Testnet) => POLICY_TESTNET_PREFIX,
            (AddressFamily::ObenBlock, Network::Mainnet) => OBB_POLICY_MAINNET_PREFIX,
            (AddressFamily::ObenBlock, Network::Testnet) => OBB_POLICY_REGTEST_PREFIX,
        }
    }

    /// The families whose strings this family's parsers accept, own first.
    /// GnB accepts only its own, so its diagnostics are unchanged.
    pub(crate) const fn accepted(self) -> &'static [AddressFamily] {
        match self {
            AddressFamily::Gnb => &[AddressFamily::Gnb],
            AddressFamily::ObenBlock => &[AddressFamily::ObenBlock, AddressFamily::Gnb],
        }
    }
}

// Process-wide address family of the wallet/CLI/RPC display and input
// paths. Set once at startup from the chain selection; GnB if never set, so
// a process that selects nothing behaves exactly as before.
static PROCESS_FAMILY: std::sync::OnceLock<AddressFamily> = std::sync::OnceLock::new();

/// Fix the process's address family (idempotent for the same value).
/// Returns `Err(existing)` if it was already set to the other family.
///
/// Unset, [`process_family`] follows the process chain
/// (`core::chain::process_chain`, fixed by `set_node_chain_id` or the
/// wallet's `--chain`).
pub fn set_process_family(family: AddressFamily) -> Result<(), AddressFamily> {
    match PROCESS_FAMILY.set(family) {
        Ok(()) => Ok(()),
        Err(_) => {
            let current = process_family();
            if current == family { Ok(()) } else { Err(current) }
        }
    }
}

/// The process's address family: the one [`set_process_family`] fixed,
/// else the process chain's (GnB unless the process selected ObenBlock).
/// Consensus never reads this; scripts and hashes are family-independent.
pub fn process_family() -> AddressFamily {
    PROCESS_FAMILY.get().copied().unwrap_or_else(|| match crate::core::chain::process_chain() {
        crate::core::chain::Chain::Gnb => AddressFamily::Gnb,
        crate::core::chain::Chain::ObenBlock => AddressFamily::ObenBlock,
    })
}

/// An address string as this process shows it: unchanged on GnB, the
/// `obb1…` form of the same script on ObenBlock (see
/// [`normalize_legacy_address_in`]).
pub fn display_address(s: &str) -> String {
    match process_family() {
        AddressFamily::Gnb => s.to_string(),
        family => normalize_legacy_address_in(s, family),
    }
}

/// The legacy single-key address of a 20-byte hash as this process shows it
/// (`gnb1q…`/`gnb1t…` on GnB, `obb1q…`/`obb1t…` on ObenBlock). For RPC and
/// explorer output; keystores keep the GnB string
/// (`crypto::address_from_hash`), which their AAD binds.
pub fn display_hash(hash: &[u8; 20], network: Network) -> String {
    Address::from_hash(*hash, network).to_string_in(process_family())
}

const NETWORKS: [Network; 2] = [Network::Mainnet, Network::Testnet];

/// Rewrite an accepted alias prefix of a legacy single-key string to the
/// family's own prefix. The legacy checksum covers only the hash, so the
/// rest of the string is kept as it is. For GnB this is
/// [`normalize_legacy_address`].
fn alias_key_prefix(s: &str, family: AddressFamily) -> String {
    for network in NETWORKS {
        let bloch = match network {
            Network::Mainnet => LEGACY_BLOCH_MAINNET_PREFIX,
            Network::Testnet => LEGACY_BLOCH_TESTNET_PREFIX,
        };
        let aliases = std::iter::once(bloch)
            .chain(family.accepted().iter().filter(|&&f| f != family).map(|f| f.key_prefix(network)));
        for alias in aliases {
            if let Some(rest) = s.strip_prefix(alias) {
                return format!("{}{rest}", family.key_prefix(network));
            }
        }
    }
    s.to_string()
}

// ── Policy addresses (multisig / timelocks, core::policy) ─────────────────────

/// Prefix of a mainnet policy address.
pub const POLICY_MAINNET_PREFIX: &str = "gnb1m";
/// Prefix of a testnet policy address.
pub const POLICY_TESTNET_PREFIX: &str = "gnb1n";

/// Address of a spend policy: `prefix ‖ hex(hash32 ‖ checksum4)`, where the
/// checksum is `SHA3-256(SHA3-256(prefix ‖ hash))[..4]` — it covers the
/// network prefix, so a mainnet policy address cannot be mistyped into a
/// valid testnet one. It also covers the family: `gnb1m…` and `obb1m…` of the
/// same policy have different checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyAddress {
    hash: [u8; 32],
    network: Network,
}

impl PolicyAddress {
    pub fn from_policy(policy: &crate::core::policy::SpendPolicy, network: Network) -> Self {
        Self { hash: policy.hash(), network }
    }

    /// Address of any policy output script (`0x02 ‖ hash`), e.g. a policy tree.
    pub fn from_script(script: &[u8], network: Network) -> Option<Self> {
        if script.len() != crate::core::policy::POLICY_SPK_LEN || script[0] != crate::core::policy::POLICY_TAG {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script[1..]);
        Some(Self { hash, network })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Opt-in GnB v2 address. The Bech32m checksum binds the network and kind.
    /// `Display` retains the legacy representation for stored identities.
    pub fn to_bech32m(&self) -> String {
        self.to_bech32m_in(AddressFamily::Gnb)
    }

    /// [`Self::to_bech32m`] with `family`'s HRP.
    pub fn to_bech32m_in(&self, family: AddressFamily) -> String {
        bech32m::encode_address(family, self.network, 1, &self.hash)
    }

    /// Legacy string with `family`'s prefix (and the checksum over it).
    /// `Display` is the GnB form.
    pub fn to_string_in(&self, family: AddressFamily) -> String {
        let prefix = family.policy_prefix(self.network);
        let mut payload = self.hash.to_vec();
        payload.extend_from_slice(&Self::checksum(prefix, &self.hash));
        format!("{prefix}{}", hex::encode(payload))
    }

    /// The 33-byte output script (`0x02 ‖ hash`).
    pub fn script_pubkey(&self) -> Vec<u8> {
        let mut s = vec![crate::core::policy::POLICY_TAG];
        s.extend_from_slice(&self.hash);
        s
    }

    fn checksum(prefix: &str, hash: &[u8; 32]) -> [u8; 4] {
        let mut h = Sha3_256::new();
        h.update(prefix.as_bytes());
        h.update(hash);
        let outer = Sha3_256::digest(h.finalize());
        [outer[0], outer[1], outer[2], outer[3]]
    }

    /// Parse a GnB policy address (legacy or v2).
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        Self::parse_in(s, AddressFamily::Gnb)
    }

    /// Parse a policy address of any family `family` accepts. A legacy
    /// string's checksum is checked against the prefix it carries.
    pub fn parse_in(s: &str, family: AddressFamily) -> Result<Self, AddressError> {
        if bech32m::is_v2_candidate(s, family) {
            let (network, kind, hash) = bech32m::decode_address(s, family)?;
            if kind != 1 {
                return Err(AddressError::BadEncoding);
            }
            let mut policy_hash = [0; 32];
            policy_hash.copy_from_slice(&hash);
            return Ok(Self { hash: policy_hash, network });
        }
        let (network, prefix, payload) = family
            .accepted()
            .iter()
            .flat_map(|&f| NETWORKS.map(|n| (n, f.policy_prefix(n))))
            .find_map(|(n, prefix)| s.strip_prefix(prefix).map(|rest| (n, prefix, rest)))
            .ok_or(AddressError::BadPrefix)?;
        if payload.len() != 72 {
            return Err(AddressError::BadLength { got: payload.len(), expected: 72 });
        }
        let bytes = hex::decode(payload).map_err(|_| AddressError::BadHex)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[..32]);
        if bytes[32..36] != Self::checksum(prefix, &hash) {
            return Err(AddressError::BadChecksum);
        }
        Ok(Self { hash, network })
    }
}

impl std::fmt::Display for PolicyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string_in(AddressFamily::Gnb))
    }
}

/// Parse any payable address — single-key (`gnb1q…`/`gnb1t…`, Bloch forms
/// accepted), policy (`gnb1m…`/`gnb1n…`), or GnB v2 Bech32m — into its
/// network and output script. Equivalent representations produce identical
/// scripts; callers must still require the expected network.
pub fn destination_script(s: &str) -> Result<(Network, Vec<u8>), AddressError> {
    destination_script_in(s, AddressFamily::Gnb)
}

/// [`destination_script`] for every form `family` accepts: on ObenBlock,
/// `obb1q`/`obb1t`/`obb1m`/`obb1n`/`obb1z`/`tobb1z` and all GnB forms.
pub fn destination_script_in(s: &str, family: AddressFamily) -> Result<(Network, Vec<u8>), AddressError> {
    if bech32m::is_v2_candidate(s, family) {
        let (network, kind, hash) = bech32m::decode_address(s, family)?;
        let mut script = Vec::with_capacity(hash.len() + usize::from(kind == 1));
        if kind == 1 {
            script.push(crate::core::policy::POLICY_TAG);
        }
        script.extend_from_slice(&hash);
        return Ok((network, script));
    }
    let policy = family
        .accepted()
        .iter()
        .any(|&f| NETWORKS.iter().any(|&n| s.starts_with(f.policy_prefix(n))));
    if policy {
        let a = PolicyAddress::parse_in(s, family)?;
        return Ok((a.network(), a.script_pubkey()));
    }
    let a = Address::parse_in(s, family)?;
    Ok((a.network(), a.hash().to_vec()))
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn prefix(&self) -> &'static str {
        match self {
            Network::Mainnet => MAINNET_PREFIX,
            Network::Testnet => TESTNET_PREFIX,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    hash: [u8; 20],
    network: Network,
}

impl Address {
    /// Create an address from a known-good 20-byte pubkey hash.
    pub fn from_hash(hash: [u8; 20], network: Network) -> Self {
        Self { hash, network }
    }

    /// Opt-in GnB v2 address. The Bech32m checksum binds the network and kind.
    /// `Display` and serde retain the legacy representation and stored fields.
    pub fn to_bech32m(&self) -> String {
        self.to_bech32m_in(AddressFamily::Gnb)
    }

    /// [`Self::to_bech32m`] with `family`'s HRP.
    pub fn to_bech32m_in(&self, family: AddressFamily) -> String {
        bech32m::encode_address(family, self.network, 0, &self.hash)
    }

    /// Legacy string with `family`'s prefix. The checksum covers only the
    /// hash, so the forms differ only in the prefix. `Display` is the GnB form.
    pub fn to_string_in(&self, family: AddressFamily) -> String {
        let inner = Sha3_256::digest(self.hash);
        let outer = Sha3_256::digest(inner);
        let mut payload = self.hash.to_vec();
        payload.extend_from_slice(&outer[..4]);
        format!("{}{}", family.key_prefix(self.network), hex::encode(&payload))
    }

    /// Borrow the 20-byte pubkey hash component of the address.
    pub fn hash_bytes(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Derive an address from a raw ML-DSA-65 public key.
    pub fn from_pubkey(pubkey: &[u8], network: Network) -> Self {
        let digest = Sha3_256::digest(pubkey);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&digest[..20]);
        Self { hash, network }
    }

    /// Parse a user-facing address string (gnb1q... or gnb1t...). Bloch
    /// addresses (bloch1q... / bloch1t...) name the same owner — the checksum
    /// covers only the hash — and are accepted as their GnB equivalent.
    /// Also accepts GnB v2 Bech32m single-key addresses, whose checksum binds
    /// the network. Validates the selected format, length and checksum.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        Self::parse_in(s, AddressFamily::Gnb)
    }

    /// [`Self::parse`] for every single-key form `family` accepts. On
    /// ObenBlock: `obb1q`/`obb1t`, `obb1z`/`tobb1z`, and the GnB and Bloch
    /// forms of the same hash.
    pub fn parse_in(s: &str, family: AddressFamily) -> Result<Self, AddressError> {
        if bech32m::is_v2_candidate(s, family) {
            let (network, kind, hash) = bech32m::decode_address(s, family)?;
            if kind != 0 {
                return Err(AddressError::BadEncoding);
            }
            let mut key_hash = [0; 20];
            key_hash.copy_from_slice(&hash);
            return Ok(Self { hash: key_hash, network });
        }
        let normalized = alias_key_prefix(s, family);
        let s = normalized.as_str();
        let (network, payload) = if let Some(rest) = s.strip_prefix(family.key_prefix(Network::Mainnet)) {
            (Network::Mainnet, rest)
        } else if let Some(rest) = s.strip_prefix(family.key_prefix(Network::Testnet)) {
            (Network::Testnet, rest)
        } else {
            return Err(AddressError::BadPrefix);
        };

        // Payload is hex of 20-byte hash + 4-byte checksum = 48 hex chars.
        if payload.len() != 48 {
            return Err(AddressError::BadLength { got: payload.len(), expected: 48 });
        }

        let bytes = hex::decode(payload).map_err(|_| AddressError::BadHex)?;
        if bytes.len() != 24 {
            return Err(AddressError::BadLength { got: bytes.len(), expected: 24 });
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[..20]);
        let expected_checksum = &bytes[20..24];

        // Verify checksum: SHA3-256(SHA3-256(hash))[0..4]
        let inner = Sha3_256::digest(&hash);
        let outer = Sha3_256::digest(&inner);
        let actual_checksum = &outer[..4];

        if expected_checksum != actual_checksum {
            return Err(AddressError::BadChecksum);
        }

        Ok(Self { hash, network })
    }

    /// Parse an address and require it to belong to `network` (CRY-7).
    ///
    /// The legacy 4-byte checksum covers only the 20-byte hash, NOT the prefix, so
    /// `gnb1q…` and `gnb1t…` forms of the same hash both pass [`Self::parse`].
    /// Every place that turns a user-supplied address into a script_pubkey
    /// for a specific chain (node `--miner-address`, wallet recipients) must
    /// therefore compare the network explicitly; this helper does that.
    ///
    /// Residual risk (documented, unchanged for interoperability): the
    /// checksum format itself is not network-bound, so a prefix typo between
    /// gnb1q and gnb1t is not caught by the checksum. It is caught by this
    /// network comparison wherever the expected network is known; binding the
    /// prefix into the checksum is provided by the opt-in [`Self::to_bech32m`]
    /// format. The network comparison is required for both formats.
    pub fn parse_for_network(s: &str, network: Network) -> Result<Self, AddressError> {
        Self::parse_for_network_in(s, network, AddressFamily::Gnb)
    }

    /// [`Self::parse_for_network`] for every form `family` accepts.
    pub fn parse_for_network_in(s: &str, network: Network, family: AddressFamily) -> Result<Self, AddressError> {
        let address = Self::parse_in(s, family)?;
        if address.network != network {
            return Err(AddressError::WrongNetwork { expected: network, got: address.network });
        }
        Ok(address)
    }

    /// The 20-byte pubkey hash (for storage, script_pubkey, etc.)
    pub fn hash(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Network enum.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Is this a mainnet address?
    pub fn is_mainnet(&self) -> bool {
        matches!(self.network, Network::Mainnet)
    }

    /// Is this a testnet address?
    pub fn is_testnet(&self) -> bool {
        matches!(self.network, Network::Testnet)
    }

}

/// User-facing string form with checksum: `prefix ‖ hex(hash ‖ SHA3d(hash)[..4])`.
///
/// This is the definition of the legacy address string. It used to live in an
/// inherent `to_string(&self)` that `Display` called, which shadowed the
/// blanket `ToString` impl (clippy `inherent_to_string_shadow_display`, a
/// deny-level lint that the CI clippy gate stops on). `addr.to_string()`
/// still works everywhere and produces byte-identical output, now through
/// `Display`.
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string_in(AddressFamily::Gnb))
    }
}

impl std::str::FromStr for Address {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid prefix (expected gnb1q or gnb1t)")]
    BadPrefix,
    #[error("invalid length: got {got} chars, expected {expected}")]
    BadLength { got: usize, expected: usize },
    #[error("invalid hex encoding")]
    BadHex,
    #[error("invalid Bech32m address encoding")]
    BadEncoding,
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("address is for {got:?}, expected {expected:?}")]
    WrongNetwork { expected: Network, got: Network },
}

// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn roundtrip_pubkey_address() {
        let (pk, _) = crypto::generate_keypair();
        let addr = Address::from_pubkey(&pk, Network::Mainnet);
        let as_str = addr.to_string();
        let parsed = Address::parse(&as_str).unwrap();
        assert_eq!(addr, parsed);
    }

    /// No library test selects a family, so this binary is a process that
    /// chose no chain: GnB, and display leaves every string as it is (even a
    /// Bloch one, as before). ObenBlock is tested in its own process
    /// (`tests/obb_process_family.rs`).
    #[test]
    fn unset_process_family_is_gnb_and_display_is_unchanged() {
        assert_eq!(process_family(), AddressFamily::Gnb);
        let gnb = Address::from_hash([3u8; 20], Network::Mainnet).to_string();
        let bloch = gnb.replacen(MAINNET_PREFIX, LEGACY_BLOCH_MAINNET_PREFIX, 1);
        for s in [gnb.as_str(), bloch.as_str(), "not an address", ""] {
            assert_eq!(display_address(s), s);
        }
    }

    #[test]
    fn mainnet_address_starts_with_gnb1q() {
        let addr = Address::from_hash([0u8; 20], Network::Mainnet);
        assert!(addr.to_string().starts_with("gnb1q"));
    }

    #[test]
    fn testnet_address_starts_with_gnb1t() {
        let addr = Address::from_hash([0u8; 20], Network::Testnet);
        assert!(addr.to_string().starts_with("gnb1t"));
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        let result = Address::parse("bc1qabc123");
        assert!(matches!(result, Err(AddressError::BadPrefix)));
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let mut addr_str = Address::from_hash([0u8; 20], Network::Mainnet).to_string();
        // Flip one char of the checksum
        let last = addr_str.len() - 1;
        let new_char = if addr_str.as_bytes()[last] == b'0' { '1' } else { '0' };
        addr_str.replace_range(last..last+1, &new_char.to_string());
        let result = Address::parse(&addr_str);
        assert!(matches!(result, Err(AddressError::BadChecksum)));
    }

    #[test]
    fn parse_rejects_bad_length() {
        let result = Address::parse("gnb1qshort");
        assert!(matches!(result, Err(AddressError::BadLength { .. })));
    }

    #[test]
    fn parse_for_network_rejects_the_other_prefix_with_a_valid_checksum() {
        let main = Address::from_hash([0x42; 20], Network::Mainnet).to_string();
        let swapped = main.replacen("gnb1q", "gnb1t", 1);
        // The checksum does not cover the prefix (documented residual risk)...
        assert!(Address::parse(&swapped).is_ok());
        // ...so callers that know their network must reject the swap.
        assert_eq!(
            Address::parse_for_network(&swapped, Network::Mainnet),
            Err(AddressError::WrongNetwork { expected: Network::Mainnet, got: Network::Testnet }),
        );
        assert!(Address::parse_for_network(&main, Network::Mainnet).is_ok());
        assert!(Address::parse_for_network(&swapped, Network::Testnet).is_ok());
    }

    #[test]
    fn treasury_address_parses() {
        // Treasury vault address (genesis-locked, see TOKENOMICS_V1.md §8)
        let s = "gnb1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31";
        let addr = Address::parse(s).unwrap();
        assert!(addr.is_mainnet());
        assert_eq!(addr.to_string(), s);
    }

    #[test]
    fn policy_address_roundtrips_and_binds_the_network() {
        use crate::core::policy::SpendPolicy;
        let keys: Vec<Vec<u8>> = (0..2).map(|_| crate::crypto::generate_keypair().0).collect();
        let p = SpendPolicy::new(2, keys, 0, 0).unwrap();
        let main = PolicyAddress::from_policy(&p, Network::Mainnet);
        let s = main.to_string();
        assert!(s.starts_with("gnb1m") && s.len() == 5 + 72);
        assert_eq!(PolicyAddress::parse(&s).unwrap(), main);
        assert_eq!(destination_script(&s).unwrap(), (Network::Mainnet, p.script_pubkey()));
        // Same hash and checksum under the testnet prefix: refused.
        let swapped = s.replacen("gnb1m", "gnb1n", 1);
        assert_eq!(PolicyAddress::parse(&swapped), Err(AddressError::BadChecksum));
        // One flipped hex digit: refused.
        let mut bad = s.clone().into_bytes();
        bad[10] = if bad[10] == b'0' { b'1' } else { b'0' };
        assert!(PolicyAddress::parse(std::str::from_utf8(&bad).unwrap()).is_err());
    }

    #[test]
    fn destination_script_accepts_single_key_addresses() {
        let a = Address::from_hash([7u8; 20], Network::Testnet);
        assert_eq!(destination_script(&a.to_string()).unwrap(), (Network::Testnet, vec![7u8; 20]));
        assert!(destination_script("gnb1zzz").is_err());
    }
}
