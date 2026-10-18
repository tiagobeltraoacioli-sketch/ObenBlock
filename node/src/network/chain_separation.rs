//! Wire separation between networks (audit POW-9 residual).
//!
//! Mainnet and testnet share the genesis block and the ASERT anchor
//! (`docs/CONSENSUS.md`, "Networks"), so nothing in a block tells the two
//! chains apart below the mainnet hardening activation except the rules
//! themselves. Transactions are domain-separated by the chain id in every
//! sighash (v2 and v3). The peer-to-peer layer must be too: Bitcoin Core
//! gives each network its own message start bytes (`pchMessageStart`,
//! `src/kernel/chainparams.cpp`), and a node drops any connection whose
//! frames carry another network's magic before it parses anything.
//!
//! The libp2p equivalent is the protocol identifiers: the gossip topics, the
//! directed-sync stream protocol and the identify protocol version all name
//! the network, so a node of one network never subscribes to, requests from
//! or serves the other's frames, and a peer that identifies with another
//! network's protocol version is disconnected ([`same_network`]). Mainnet
//! keeps the identifiers it has always used (deployed nodes stay
//! compatible); testnet gets its own.
//!
//! ObenBlock (docs/DESIGN-obenblock.md §2) has a different genesis, so its
//! blocks never validate on GnB; it still gets its own identifiers on every
//! layer, the post-quantum transport included (`/obenblock/pq/1.0.0`,
//! [`ChainProtocols::transport`]): a GnB node and an ObenBlock node do not
//! even complete a connection.

use libp2p::StreamProtocol;

use crate::core::ChainId;

/// The protocol identifiers of one network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainProtocols {
    /// identify protocol version (`identify::Config::new`).
    pub identify: &'static str,
    /// gossipsub topic of `NewBlock` frames.
    pub blocks_topic: &'static str,
    /// gossipsub topic of `NewTransaction` frames.
    pub txs_topic: &'static str,
    /// gossipsub topic of the other gossip frames.
    pub sync_topic: &'static str,
    /// request-response protocol of the directed sync (`sync_rr`).
    pub sync_protocol: StreamProtocol,
    /// multistream-select id of the post-quantum transport upgrade
    /// (`transport::upgrade::PqConfig`), `core::chain::ChainParams::transport_protocol`.
    pub transport: &'static str,
}

/// Mainnet: the identifiers every released node uses.
pub const MAINNET: ChainProtocols = ChainProtocols {
    identify: "/gnb/1.0.0",
    blocks_topic: super::TOPIC_BLOCKS,
    txs_topic: super::TOPIC_TXS,
    sync_topic: super::TOPIC_SYNC,
    sync_protocol: super::sync_rr::SYNC_PROTOCOL,
    transport: crate::transport::upgrade::PQ_PROTOCOL_ID,
};

/// Testnet: every identifier names the network.
pub const TESTNET: ChainProtocols = ChainProtocols {
    identify: "/gnb-testnet/1.0.0",
    blocks_topic: "gnb-testnet/blocks/1",
    txs_topic: "gnb-testnet/txs/1",
    sync_topic: "gnb-testnet/sync/1",
    sync_protocol: StreamProtocol::new("/gnb-testnet/sync/1"),
    transport: crate::transport::upgrade::PQ_PROTOCOL_ID,
};

/// ObenBlock mainnet.
pub const OBENBLOCK_MAINNET: ChainProtocols = ChainProtocols {
    identify: "/obenblock/1.0.0",
    blocks_topic: "obenblock/blocks/1",
    txs_topic: "obenblock/txs/1",
    sync_topic: "obenblock/sync/1",
    sync_protocol: StreamProtocol::new("/obenblock/sync/1"),
    transport: crate::core::chain::OBENBLOCK_MAINNET.transport_protocol,
};

/// ObenBlock regtest: every identifier names the network.
pub const OBENBLOCK_REGTEST: ChainProtocols = ChainProtocols {
    identify: "/obenblock-regtest/1.0.0",
    blocks_topic: "obenblock-regtest/blocks/1",
    txs_topic: "obenblock-regtest/txs/1",
    sync_topic: "obenblock-regtest/sync/1",
    sync_protocol: StreamProtocol::new("/obenblock-regtest/sync/1"),
    transport: crate::core::chain::OBENBLOCK_REGTEST.transport_protocol,
};

/// The protocol identifiers of `chain`.
pub const fn chain_protocols(chain: ChainId) -> ChainProtocols {
    match chain {
        ChainId::Mainnet => MAINNET,
        ChainId::Testnet => TESTNET,
        ChainId::ObenBlockMainnet => OBENBLOCK_MAINNET,
        ChainId::ObenBlockRegtest => OBENBLOCK_REGTEST,
    }
}

/// `true` iff a peer whose identify protocol version is `theirs` runs the
/// network `ours` describes. Anything else (another network, or a peer that
/// does not speak GnB at all) is disconnected on identify.
pub fn same_network(ours: &ChainProtocols, theirs: &str) -> bool {
    theirs == ours.identify
}

/// Dialed addresses waiting for the peer's identify before they enter the
/// keyed "tried" table (`addrbook::TriedTable`, persisted as
/// `known_peers.json`). An outbound connection proves the address
/// reaches A node, not a node of THIS network: a node of the other network
/// accepts the connection and is dropped only when its identify arrives.
/// Bitcoin Core marks an address good (`CAddrMan::Good`) only after the
/// VERSION handshake, whose message start already carried the network's
/// magic; here the address is promoted on a same-network identify, and on
/// another network's it is removed from the tried table and the address
/// book, so it is neither saved to `known_peers.json`, redialed at start nor
/// served to `GetPeers`, and never evicts a same-netgroup address of this
/// network. The peer is also remembered (bounded) as one of another
/// network, so an address of it that peer exchange offers again is not
/// dialed during this run ([`PendingTried::is_other_network`]).
#[derive(Debug, Default)]
pub struct PendingTried {
    by_peer: std::collections::HashMap<libp2p::PeerId, String>,
    other_network: std::collections::HashSet<libp2p::PeerId>,
    other_order: std::collections::VecDeque<libp2p::PeerId>,
}

/// At most this many dialed addresses wait for identify (one per
/// connection; the connection limits keep it far below).
pub const PENDING_TRIED_CAP: usize = 1_024;

/// At most this many peers are remembered as another network's (oldest
/// forgotten first).
pub const OTHER_NETWORK_CAP: usize = 1_024;

impl PendingTried {
    /// An outbound connection to `peer` at the canonical `addr` is up.
    pub fn on_dialed(&mut self, peer: libp2p::PeerId, addr: String) {
        if self.by_peer.len() < PENDING_TRIED_CAP || self.by_peer.contains_key(&peer) {
            self.by_peer.insert(peer, addr);
        }
    }

    /// The last connection to `peer` closed before (or after) identify.
    pub fn on_closed(&mut self, peer: &libp2p::PeerId) {
        self.by_peer.remove(peer);
    }

    /// `peer` identified. Same network: its dialed address (if any) leaves
    /// the new table and enters the keyed tried table (R3's `TriedTable`,
    /// Core's `Good`; a full bucket queues a test-before-evict collision).
    /// Another network: every address of it is dropped from the tried table,
    /// and the dialed one from the new table. Returns the dialed address it
    /// acted on.
    pub fn on_identified(
        &mut self,
        peer: &libp2p::PeerId,
        same_network: bool,
        tried: &mut super::addrbook::TriedTable,
        addr_book: &mut super::addrbook::AddrBook,
        now: std::time::Instant,
    ) -> Option<String> {
        let dialed = self.by_peer.remove(peer);
        if same_network {
            if self.other_network.remove(peer) {
                self.other_order.retain(|p| p != peer);
            }
            if let Some(a) = &dialed {
                addr_book.remove(a);
                if let super::pex_validator::TriedInsert::Collision { existing } = tried.insert(a, now) {
                    log::debug!("tried table: {} collides with {}; the occupant will be tested", a, existing);
                }
            }
        } else {
            let suffix = format!("/p2p/{peer}");
            for a in tried.addresses() {
                if a.ends_with(&suffix) || Some(&a) == dialed.as_ref() {
                    tried.remove(&a);
                }
            }
            if let Some(a) = &dialed {
                addr_book.remove(a);
            }
            if self.other_network.insert(*peer) {
                self.other_order.push_back(*peer);
                if self.other_order.len() > OTHER_NETWORK_CAP {
                    if let Some(old) = self.other_order.pop_front() {
                        self.other_network.remove(&old);
                    }
                }
            }
        }
        dialed
    }

    /// `peer` identified as a node of another network during this run: an
    /// address of it is not dialed from the address book.
    pub fn is_other_network(&self, peer: &libp2p::PeerId) -> bool {
        self.other_network.contains(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(p: &ChainProtocols) -> [&str; 5] {
        [p.identify, p.blocks_topic, p.txs_topic, p.sync_topic, p.sync_protocol.as_ref()]
    }

    /// Mainnet keeps its deployed identifiers byte for byte.
    #[test]
    fn mainnet_identifiers_are_the_deployed_ones() {
        assert_eq!(
            fields(&chain_protocols(ChainId::Mainnet)),
            ["/gnb/1.0.0", "gnb/blocks/1", "gnb/txs/1", "gnb/sync/1", "/gnb/sync/1"]
        );
    }

    /// No identifier of one network is an identifier of the other.
    #[test]
    fn networks_share_no_identifier() {
        let (main, test) = (chain_protocols(ChainId::Mainnet), chain_protocols(ChainId::Testnet));
        let (m, t) = (fields(&main), fields(&test));
        for a in m {
            assert!(!t.contains(&a), "{a} is used by both networks");
        }
        let mut all: Vec<&str> = m.iter().chain(t.iter()).copied().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 10, "every identifier is distinct");
    }

    /// No identifier of one of the four networks is used by another, and
    /// ObenBlock's transport is a different protocol from GnB's.
    #[test]
    fn obenblock_shares_no_identifier_with_gnb() {
        let protos = ChainId::ALL.map(chain_protocols);
        let mut all: Vec<&str> = protos.iter().flat_map(fields).collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "every identifier is distinct");
        assert_eq!(OBENBLOCK_MAINNET.transport, "/obenblock/pq/1.0.0");
        assert_eq!(MAINNET.transport, "/gnb/pq/2.0.0");
        assert_eq!(TESTNET.transport, MAINNET.transport, "GnB keeps one transport id");
        for id in ChainId::ALL {
            assert_eq!(chain_protocols(id).transport, id.params().transport_protocol);
        }
        assert_ne!(OBENBLOCK_MAINNET.transport, OBENBLOCK_REGTEST.transport);
        assert!(!same_network(&OBENBLOCK_MAINNET, MAINNET.identify));
        assert!(!same_network(&MAINNET, OBENBLOCK_MAINNET.identify));
        assert!(!same_network(&OBENBLOCK_MAINNET, OBENBLOCK_REGTEST.identify));
    }

    #[test]
    fn identify_from_another_network_is_refused() {
        assert!(same_network(&MAINNET, "/gnb/1.0.0"));
        assert!(!same_network(&MAINNET, "/gnb-testnet/1.0.0"));
        assert!(same_network(&TESTNET, "/gnb-testnet/1.0.0"));
        assert!(!same_network(&TESTNET, "/gnb/1.0.0"));
        assert!(!same_network(&MAINNET, ""));
        assert!(!same_network(&MAINNET, "/ipfs/0.1.0"));
    }

    /// POW-9 (review): a dialed address enters the tried table only once
    /// identify confirms the network; one of another network is removed
    /// from it (an entry an earlier release saved included) and from the
    /// address book.
    #[test]
    fn a_dialed_address_is_tried_only_after_a_same_network_identify() {
        use crate::network::addrbook::{random_key, AddrBook, TriedTable};
        let (ours, theirs) = (libp2p::PeerId::random(), libp2p::PeerId::random());
        let ours_addr = format!("/ip4/1.2.3.4/tcp/17110/p2p/{ours}");
        let theirs_addr = format!("/ip4/1.2.9.9/tcp/17110/p2p/{theirs}");
        let now = std::time::Instant::now();
        let mut known = TriedTable::with_key(random_key());
        let mut book = AddrBook::with_key(random_key());
        let mut p = PendingTried::default();

        p.on_dialed(ours, ours_addr.clone());
        p.on_dialed(theirs, theirs_addr.clone());
        assert!(known.is_empty(), "nothing is tried before identify");
        assert!(book.add(&ours_addr));
        assert_eq!(p.on_identified(&ours, true, &mut known, &mut book, now), Some(ours_addr.clone()));
        assert!(known.contains(&ours_addr));
        assert!(!book.contains(&ours_addr), "promoted from the new table to the tried table");

        // Saved by an earlier release (both networks shared topics and PEX).
        let _ = known.insert(&theirs_addr, now);
        assert!(known.contains(&theirs_addr));
        assert!(book.add(&theirs_addr));
        assert_eq!(p.on_identified(&theirs, false, &mut known, &mut book, now), Some(theirs_addr.clone()));
        assert!(!known.contains(&theirs_addr), "another network's address leaves the tried table");
        assert!(!book.contains(&theirs_addr), "and the address book");
        assert!(known.contains(&ours_addr));

        // It is not dialed again from the address tables during this run.
        assert!(p.is_other_network(&theirs) && !p.is_other_network(&ours));

        // A connection that closes before identify leaves nothing behind.
        p.on_dialed(theirs, theirs_addr.clone());
        p.on_closed(&theirs);
        assert_eq!(p.on_identified(&theirs, true, &mut known, &mut book, now), None);
        assert!(!known.contains(&theirs_addr));
        assert!(!p.is_other_network(&theirs), "a same-network identify clears the mark");
    }

    /// The set of other-network peers is bounded (oldest forgotten first).
    #[test]
    fn other_network_peers_are_bounded() {
        use crate::network::addrbook::{random_key, AddrBook, TriedTable};
        let now = std::time::Instant::now();
        let mut known = TriedTable::with_key(random_key());
        let mut book = AddrBook::with_key(random_key());
        let mut p = PendingTried::default();
        let first = libp2p::PeerId::random();
        p.on_identified(&first, false, &mut known, &mut book, now);
        for _ in 0..OTHER_NETWORK_CAP {
            p.on_identified(&libp2p::PeerId::random(), false, &mut known, &mut book, now);
        }
        assert!(!p.is_other_network(&first));
        assert_eq!(p.other_network.len(), OTHER_NETWORK_CAP);
        assert_eq!(p.other_order.len(), OTHER_NETWORK_CAP);
    }
}
