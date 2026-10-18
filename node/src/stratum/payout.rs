//! Who a block found through stratum pays (solo mode).
//!
//! Solo semantics, as in the legacy Bloch server: a block pays its whole
//! coinbase (subsidy share and fees, `BlockTemplate::coinbase_outputs`) to
//! one script. The script comes from:
//!
//! 1. the worker name, when it is an address of this chain: `obb1…` (or the
//!    `gnb1…` / `bloch1…` forms of the same script, DESIGN-obenblock.md §2),
//!    a key hash or a spend policy, of the node's network. A conventional
//!    `.rig` suffix (`obb1q….rig1`) is a worker label and is ignored;
//! 2. otherwise the operator's configured payout address
//!    (`--stratum-payout`, else `--miner-address`), for a plain worker label
//!    such as `rig1` (the operator's own machines, a rental the operator
//!    configured with a label).
//!
//! Everything else is refused, never paid to a fallback: an address of
//! another chain or network, a mistyped address (bad checksum, wrong
//! length), or anything that is not a short label. Mapping a miner's
//! foreign or mistyped address to the operator's would take the miner's
//! reward without their consent.

use crate::address;
use crate::core;

/// Longest plain worker label that may fall back to the operator's payout.
/// Shorter than any Bitcoin address (26+ characters), so a Bitcoin address
/// can never be taken for a label.
pub const MAX_WORKER_LABEL_LEN: usize = 24;

/// A payout destination: the output script and the address as shown back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// The address in this chain's display form (`obb1…` on ObenBlock).
    pub address: String,
    /// The coinbase output script (20-byte key hash or 33-byte policy).
    pub script_pubkey: Vec<u8>,
}

/// Parse `s` as a payout address of this node's chain and network.
pub fn parse_payout_address(s: &str) -> Result<Payout, String> {
    let family = address::process_family();
    let network = core::node_chain_id().network();
    let (got, script) = address::destination_script_in(s, family)
        .map_err(|e| format!("{s:?} is not a valid address: {e}"))?;
    if got != network {
        return Err(format!("{s:?} is a {got:?} address; this node runs {network:?}"));
    }
    Ok(Payout { address: address::normalize_legacy_address_in(s, family), script_pubkey: script })
}

/// Address prefixes the worker name is checked against: a name starting
/// with one of them is meant as an address and must parse as one.
const ADDRESS_LIKE_PREFIXES: &[&str] = &["obb1", "tobb1", "gnb1", "tgnb1", "bloch1", "bc1", "tb1", "bcrt1"];

fn is_plain_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_WORKER_LABEL_LEN
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && !ADDRESS_LIKE_PREFIXES.iter().any(|p| s.to_ascii_lowercase().starts_with(p))
}

/// The payout of a worker that authorized as `username` (V1
/// `mining.authorize`, SV2 `user_identity`), and its worker label if any.
pub fn resolve_worker(username: &str, fallback: Option<&Payout>) -> Result<(Payout, Option<String>), String> {
    let username = username.trim();
    let (head, label) = match username.split_once('.') {
        Some((h, l)) => (h, Some(l.to_string())),
        None => (username, None),
    };
    match parse_payout_address(head) {
        Ok(p) => Ok((p, label)),
        Err(e) if !is_plain_label(head) => Err(format!(
            "worker name must be an obb1… address of this network (optionally followed by .label): {e}")),
        Err(_) => match fallback {
            Some(p) => Ok((p.clone(), Some(username.to_string()))),
            None => Err(format!(
                "worker {head:?} is not an obb1… address and the node has no payout address \
                 configured (--stratum-payout or --miner-address)")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lib test binary runs GnB mainnet: `gnb1q…` is this chain's form.
    fn gnb_address(fill: u8) -> String {
        address::Address::from_hash([fill; 20], address::Network::Mainnet).to_string()
    }

    #[test]
    fn worker_address_pays_itself() {
        let a = gnb_address(7);
        let (p, label) = resolve_worker(&a, None).unwrap();
        assert_eq!(p.script_pubkey, vec![7u8; 20]);
        assert_eq!(label, None);
        let (p, label) = resolve_worker(&format!("{a}.rig42"), None).unwrap();
        assert_eq!(p.script_pubkey, vec![7u8; 20]);
        assert_eq!(label.as_deref(), Some("rig42"));
    }

    #[test]
    fn bloch_form_of_the_same_key_is_accepted() {
        let a = gnb_address(9);
        let bloch = a.replacen("gnb1q", "bloch1q", 1);
        assert_eq!(resolve_worker(&bloch, None).unwrap().0.script_pubkey, vec![9u8; 20]);
    }

    #[test]
    fn labels_fall_back_to_the_operator_only() {
        let op = parse_payout_address(&gnb_address(1)).unwrap();
        let (p, label) = resolve_worker("rig1", Some(&op)).unwrap();
        assert_eq!(p, op);
        assert_eq!(label.as_deref(), Some("rig1"));
        assert!(resolve_worker("rig1", None).is_err(), "no fallback configured");
    }

    #[test]
    fn foreign_or_mistyped_addresses_never_fall_back() {
        let op = parse_payout_address(&gnb_address(1)).unwrap();
        let mut typo = gnb_address(2);
        let last = typo.pop().unwrap();
        typo.push(if last == '0' { '1' } else { '0' });
        let testnet = address::Address::from_hash([3; 20], address::Network::Testnet).to_string();
        for bad in [
            typo.as_str(),
            testnet.as_str(),
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "worker with spaces",
            "",
        ] {
            assert!(resolve_worker(bad, Some(&op)).is_err(), "{bad:?} must be refused");
        }
    }
}
