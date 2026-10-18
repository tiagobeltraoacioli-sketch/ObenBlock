//! Chain identity and network parameters (docs/DESIGN-obenblock.md §2).
//!
//! One code base runs two chains:
//!
//! | chain | networks | chain ids |
//! | --- | --- | --- |
//! | GnB ([`Chain::Gnb`]) | mainnet, testnet | `0x474E_0001`, `0x474E_0002` |
//! | ObenBlock ([`Chain::ObenBlock`]) | mainnet, regtest | `0x4F42_0001`, `0x4F42_0002` |
//!
//! The chain id ([`ChainId`]) is folded into every sighash (v2 and v3), every
//! signed message and every PoWit message, so no transaction, attestation or
//! signed message is valid on more than one of the four networks. GnB keeps
//! every identifier it has always used; ObenBlock has no public testnet, only
//! a local regtest.
//!
//! A network is selected once per process, at start-up, from the binary's
//! flags (`--chain gnb|obenblock`, then `--testnet` for GnB or `--regtest`
//! for ObenBlock; [`select`]):
//!
//! - a node calls [`super::set_node_chain_id`], which also fixes the
//!   process [`Chain`];
//! - a wallet or CLI process, which may handle both networks of its chain
//!   (the keystore states which one), calls [`set_process_chain`] only.
//!   [`ChainId::for_network`] then maps an address network (`Mainnet`, or
//!   `Testnet` for the test network of either chain) to the chain id of the
//!   process chain, so a key signs for ObenBlock exactly when the process
//!   was started for ObenBlock.
//!
//! Without either call the process is GnB, as before this module existed
//! (unit tests, older tools, the browser wallet).
//!
//! [`ChainParams`] collects the network-level defaults that are not
//! consensus: default ports, the DNS seeds, the P2P protocol ids and the
//! default data directory.

use std::sync::OnceLock;

use crate::address::Network;

use super::ChainId;

/// The chain a process runs. Selects the chain ids and every network-level
/// default; the consensus regime of each network is still read from its
/// [`ChainId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// The GnB chain (GnB-SMH proof of work), mainnet and testnet.
    Gnb,
    /// The ObenBlock relaunch (docs/DESIGN-obenblock.md), mainnet and regtest.
    ObenBlock,
}

impl Chain {
    /// The name `--chain` takes and `getnetworkinfo` reports.
    pub const fn name(self) -> &'static str {
        match self {
            Chain::Gnb => "gnb",
            Chain::ObenBlock => "obenblock",
        }
    }

    /// Parse a `--chain` value (ASCII case-insensitive).
    pub fn parse(s: &str) -> Result<Chain, String> {
        match s.to_ascii_lowercase().as_str() {
            "gnb" => Ok(Chain::Gnb),
            "obenblock" | "obb" => Ok(Chain::ObenBlock),
            other => Err(format!("unknown chain {other:?} (expected gnb or obenblock)")),
        }
    }

    /// The name of this chain's test network: GnB's public testnet, or
    /// ObenBlock's local regtest.
    pub const fn test_network_name(self) -> &'static str {
        match self {
            Chain::Gnb => "testnet",
            Chain::ObenBlock => "regtest",
        }
    }
}

/// Network-level parameters of one network. Nothing here is consensus except
/// `chain_id`, which is the [`ChainId`] the node validates under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParams {
    pub chain: Chain,
    pub chain_id: ChainId,
    /// The address network: `Mainnet` for a main network, `Testnet` for the
    /// test network of either chain (GnB testnet, ObenBlock regtest). It
    /// selects the address prefix family and the keystore `network` field.
    pub network: Network,
    /// `"mainnet"`, `"testnet"` or `"regtest"`: what `getnetworkinfo`
    /// `network` and the metrics report.
    pub network_name: &'static str,
    /// Default P2P listen port.
    pub p2p_port: u16,
    /// Default RPC port.
    pub rpc_port: u16,
    /// Default Prometheus metrics port.
    pub metrics_port: u16,
    /// DNS seeds dialed at start when the operator names none (`--dns-seed`).
    pub dns_seeds: &'static [&'static str],
    /// multistream-select id of the post-quantum transport upgrade
    /// (`node/src/transport/upgrade.rs`): two networks with different ids
    /// never complete a connection.
    pub transport_protocol: &'static str,
    /// Default data directory.
    pub data_dir: &'static str,
}

/// GnB mainnet: the identifiers every released GnB node uses.
pub const GNB_MAINNET: ChainParams = ChainParams {
    chain: Chain::Gnb,
    chain_id: ChainId::Mainnet,
    network: Network::Mainnet,
    network_name: "mainnet",
    p2p_port: 17110,
    rpc_port: 17210,
    metrics_port: 17310,
    dns_seeds: &[],
    transport_protocol: "/gnb/pq/2.0.0",
    data_dir: "./gnb-data",
};

/// GnB testnet: the same ports and transport as GnB mainnet (testnet nodes
/// are told apart by the chain marker, the identify version and the topics;
/// `node/src/network/chain_separation.rs`).
pub const GNB_TESTNET: ChainParams = ChainParams {
    chain: Chain::Gnb,
    chain_id: ChainId::Testnet,
    network: Network::Testnet,
    network_name: "testnet",
    ..GNB_MAINNET
};

/// ObenBlock mainnet (§2): its own ports, so one host can run both chains.
pub const OBENBLOCK_MAINNET: ChainParams = ChainParams {
    chain: Chain::ObenBlock,
    chain_id: ChainId::ObenBlockMainnet,
    network: Network::Mainnet,
    network_name: "mainnet",
    p2p_port: 18110,
    rpc_port: 18210,
    metrics_port: 18310,
    dns_seeds: &["seed.obenblock.xyz"],
    transport_protocol: "/obenblock/pq/1.0.0",
    data_dir: "./obenblock-data",
};

/// ObenBlock regtest: local development only. No DNS seed, and every
/// protocol id names the network.
pub const OBENBLOCK_REGTEST: ChainParams = ChainParams {
    chain: Chain::ObenBlock,
    chain_id: ChainId::ObenBlockRegtest,
    network: Network::Testnet,
    network_name: "regtest",
    p2p_port: 18111,
    rpc_port: 18211,
    metrics_port: 18311,
    dns_seeds: &[],
    transport_protocol: "/obenblock-regtest/pq/1.0.0",
    data_dir: "./obenblock-regtest-data",
};

/// Every network, for tests and registries.
pub const ALL: [ChainParams; 4] = [GNB_MAINNET, GNB_TESTNET, OBENBLOCK_MAINNET, OBENBLOCK_REGTEST];

/// The parameters of the network `id` names.
pub const fn params(id: ChainId) -> &'static ChainParams {
    match id {
        ChainId::Mainnet => &GNB_MAINNET,
        ChainId::Testnet => &GNB_TESTNET,
        ChainId::ObenBlockMainnet => &OBENBLOCK_MAINNET,
        ChainId::ObenBlockRegtest => &OBENBLOCK_REGTEST,
    }
}

/// The network of `chain` a binary's flags select: `test` is `--testnet`
/// (GnB) or `--regtest` (ObenBlock), resolved by [`select_flags`].
pub const fn select(chain: Chain, test: bool) -> &'static ChainParams {
    match (chain, test) {
        (Chain::Gnb, false) => &GNB_MAINNET,
        (Chain::Gnb, true) => &GNB_TESTNET,
        (Chain::ObenBlock, false) => &OBENBLOCK_MAINNET,
        (Chain::ObenBlock, true) => &OBENBLOCK_REGTEST,
    }
}

/// Resolve a binary's network flags: `--chain` (default GnB), `--testnet`
/// and `--regtest`. `--testnet` names GnB's public testnet and `--regtest`
/// ObenBlock's regtest; the other combination is refused (ObenBlock has no
/// public testnet, §1; GnB has no regtest chain id), as is giving both.
pub fn select_flags(chain: Option<Chain>, testnet: bool, regtest: bool) -> Result<&'static ChainParams, String> {
    let chain = chain.unwrap_or(Chain::Gnb);
    match (chain, testnet, regtest) {
        (_, true, true) => Err("--testnet and --regtest are mutually exclusive".into()),
        (Chain::ObenBlock, true, false) => {
            Err("ObenBlock has no public testnet: use --regtest for a local test network".into())
        }
        (Chain::Gnb, false, true) => {
            Err("GnB has no regtest network: use --testnet (or --chain obenblock --regtest)".into())
        }
        (c, t, r) => Ok(select(c, t || r)),
    }
}

impl ChainId {
    /// Every chain id, in registry order.
    pub const ALL: [ChainId; 4] =
        [ChainId::Mainnet, ChainId::Testnet, ChainId::ObenBlockMainnet, ChainId::ObenBlockRegtest];

    /// The chain id with the value `v`, if it is registered.
    pub const fn from_u32(v: u32) -> Option<ChainId> {
        match v {
            0x474E_0001 => Some(ChainId::Mainnet),
            0x474E_0002 => Some(ChainId::Testnet),
            0x4F42_0001 => Some(ChainId::ObenBlockMainnet),
            0x4F42_0002 => Some(ChainId::ObenBlockRegtest),
            _ => None,
        }
    }

    /// The chain this id belongs to.
    pub const fn chain(self) -> Chain {
        match self {
            ChainId::Mainnet | ChainId::Testnet => Chain::Gnb,
            ChainId::ObenBlockMainnet | ChainId::ObenBlockRegtest => Chain::ObenBlock,
        }
    }

    /// The address network of this id (`Testnet` for either test network).
    pub const fn network(self) -> Network {
        match self {
            ChainId::Mainnet | ChainId::ObenBlockMainnet => Network::Mainnet,
            ChainId::Testnet | ChainId::ObenBlockRegtest => Network::Testnet,
        }
    }

    /// `true` for a test network (GnB testnet, ObenBlock regtest).
    pub const fn is_test_network(self) -> bool {
        matches!(self.network(), Network::Testnet)
    }

    /// The chain id of the address network `net` on `chain`.
    pub const fn for_chain(chain: Chain, net: Network) -> ChainId {
        match (chain, net) {
            (Chain::Gnb, Network::Mainnet) => ChainId::Mainnet,
            (Chain::Gnb, Network::Testnet) => ChainId::Testnet,
            (Chain::ObenBlock, Network::Mainnet) => ChainId::ObenBlockMainnet,
            (Chain::ObenBlock, Network::Testnet) => ChainId::ObenBlockRegtest,
        }
    }

    /// The chain id of the address network `net` on the process chain
    /// ([`process_chain`]): what a wallet signs for. GnB unless the process
    /// selected ObenBlock at start-up.
    pub fn for_network(net: Network) -> ChainId {
        ChainId::for_chain(process_chain(), net)
    }

    /// This network's parameters.
    pub const fn params(self) -> &'static ChainParams {
        params(self)
    }
}

// The chain of this process. Set once at start-up (directly by wallets and
// CLIs, through `set_node_chain_id` by a node); GnB if never set.
static PROCESS_CHAIN: OnceLock<Chain> = OnceLock::new();

/// Fix the process chain (idempotent for the same value). Returns
/// `Err(existing)` if it is already set to the other chain.
pub fn set_process_chain(chain: Chain) -> Result<(), Chain> {
    match PROCESS_CHAIN.set(chain) {
        Ok(()) => Ok(()),
        Err(_) => {
            let cur = *PROCESS_CHAIN.get().expect("OnceLock set");
            if cur == chain { Ok(()) } else { Err(cur) }
        }
    }
}

/// The process chain: the one set at start-up, otherwise GnB.
pub fn process_chain() -> Chain {
    PROCESS_CHAIN.get().copied().unwrap_or(Chain::Gnb)
}

/// The parameters of the node's network ([`super::node_chain_id`]).
pub fn node_params() -> &'static ChainParams {
    params(super::node_chain_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_ids_are_the_registered_values() {
        assert_eq!(ChainId::Mainnet.to_u32(), 0x474E_0001);
        assert_eq!(ChainId::Testnet.to_u32(), 0x474E_0002);
        assert_eq!(ChainId::ObenBlockMainnet.to_u32(), 0x4F42_0001);
        assert_eq!(ChainId::ObenBlockRegtest.to_u32(), 0x4F42_0002);
        // "OB" in the high half, little-endian on the wire.
        assert_eq!(ChainId::ObenBlockMainnet.to_le_bytes(), [0x01, 0x00, 0x42, 0x4F]);
        assert_eq!(&0x4F42u16.to_be_bytes(), b"OB");
        for id in ChainId::ALL {
            assert_eq!(ChainId::from_u32(id.to_u32()), Some(id));
        }
        for v in [0, 0x474E_0000, 0x474E_0003, 0x4F42_0000, 0x4F42_0003, u32::MAX] {
            assert_eq!(ChainId::from_u32(v), None);
        }
    }

    #[test]
    fn params_table_is_consistent() {
        for p in ALL {
            assert_eq!(params(p.chain_id), &p);
            assert_eq!(p.chain_id.chain(), p.chain);
            assert_eq!(p.chain_id.network(), p.network);
            assert_eq!(ChainId::for_chain(p.chain, p.network), p.chain_id);
            assert_eq!(select(p.chain, p.chain_id.is_test_network()), &p);
            assert_eq!(p.network_name == "mainnet", !p.chain_id.is_test_network());
        }
        // ObenBlock's ports never collide with GnB's, so one host runs both.
        let gnb = [GNB_MAINNET.p2p_port, GNB_MAINNET.rpc_port, GNB_MAINNET.metrics_port];
        for p in [OBENBLOCK_MAINNET, OBENBLOCK_REGTEST] {
            for port in [p.p2p_port, p.rpc_port, p.metrics_port] {
                assert!(!gnb.contains(&port), "{port}");
            }
        }
        let mut transports: Vec<_> = [GNB_MAINNET, OBENBLOCK_MAINNET, OBENBLOCK_REGTEST]
            .iter().map(|p| p.transport_protocol).collect();
        transports.sort_unstable();
        transports.dedup();
        assert_eq!(transports.len(), 3);
    }

    #[test]
    fn design_values() {
        // docs/DESIGN-obenblock.md §2.
        assert_eq!(OBENBLOCK_MAINNET.transport_protocol, "/obenblock/pq/1.0.0");
        assert_eq!((OBENBLOCK_MAINNET.p2p_port, OBENBLOCK_MAINNET.rpc_port), (18110, 18210));
        assert_eq!(OBENBLOCK_MAINNET.dns_seeds, &["seed.obenblock.xyz"]);
        // GnB keeps what it shipped.
        assert_eq!((GNB_MAINNET.p2p_port, GNB_MAINNET.rpc_port, GNB_MAINNET.metrics_port), (17110, 17210, 17310));
        assert_eq!(GNB_MAINNET.transport_protocol, "/gnb/pq/2.0.0");
        assert_eq!(GNB_TESTNET.transport_protocol, "/gnb/pq/2.0.0");
        assert!(GNB_MAINNET.dns_seeds.is_empty() && GNB_TESTNET.dns_seeds.is_empty());
    }

    #[test]
    fn flags_select_one_network() {
        assert_eq!(select_flags(None, false, false), Ok(&GNB_MAINNET));
        assert_eq!(select_flags(None, true, false), Ok(&GNB_TESTNET));
        assert_eq!(select_flags(Some(Chain::Gnb), true, false), Ok(&GNB_TESTNET));
        assert_eq!(select_flags(Some(Chain::ObenBlock), false, false), Ok(&OBENBLOCK_MAINNET));
        assert_eq!(select_flags(Some(Chain::ObenBlock), false, true), Ok(&OBENBLOCK_REGTEST));
        assert!(select_flags(Some(Chain::ObenBlock), true, false).unwrap_err().contains("no public testnet"));
        assert!(select_flags(None, false, true).unwrap_err().contains("no regtest"));
        assert!(select_flags(Some(Chain::ObenBlock), true, true).is_err());
        assert_eq!(Chain::parse("ObenBlock"), Ok(Chain::ObenBlock));
        assert_eq!(Chain::parse("obb"), Ok(Chain::ObenBlock));
        assert_eq!(Chain::parse("gnb"), Ok(Chain::Gnb));
        assert!(Chain::parse("bloch").is_err());
    }

    /// Unit tests never select a chain: the process is GnB and a wallet
    /// signs for GnB's ids, as before the ObenBlock ids existed.
    #[test]
    fn unset_process_is_gnb() {
        assert_eq!(process_chain(), Chain::Gnb);
        assert_eq!(ChainId::for_network(Network::Mainnet), ChainId::Mainnet);
        assert_eq!(ChainId::for_network(Network::Testnet), ChainId::Testnet);
        assert_eq!(node_params(), &GNB_MAINNET);
    }
}
