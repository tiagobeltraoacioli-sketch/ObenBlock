//! Review (mainnet launch blocker): a node that selects ObenBlock
//! (`core::set_node_chain_id`) binds the process address family, so its RPC,
//! CLI and explorer answers show `obb1…` and still parse `gnb1…` and
//! `bloch1…` as aliases. Own test process: the chain and family are
//! process-wide and fixed once.

use gnb_crypto::address::{
    display_address, display_hash, process_family, set_process_family, Address, AddressFamily, Network,
    LEGACY_BLOCH_TESTNET_PREFIX, OBB_REGTEST_PREFIX,
};
use gnb_crypto::core::chain::{self, Chain};
use gnb_crypto::core::{self, ChainId, TESTNET_PREFIX};

#[test]
fn obenblock_node_chain_fixes_the_obb_family() {
    assert_eq!(core::set_node_chain_id(ChainId::ObenBlockRegtest), Ok(()));
    assert_eq!(process_family(), AddressFamily::ObenBlock);
    // Bound, not merely defaulted: the GnB family can no longer be set, and
    // the process chain cannot switch either.
    assert_eq!(set_process_family(AddressFamily::Gnb), Err(AddressFamily::ObenBlock));
    assert_eq!(set_process_family(AddressFamily::ObenBlock), Ok(()));
    assert_eq!(chain::set_process_chain(Chain::Gnb), Err(Chain::ObenBlock));
    assert_eq!(chain::set_process_chain(Chain::ObenBlock), Ok(()));

    // What the explorer and the rich list print for an output script.
    let hash = [9u8; 20];
    let shown = display_hash(&hash, core::node_chain_id().network());
    assert!(shown.starts_with(OBB_REGTEST_PREFIX), "{shown}");
    // What the RPC echoes for an input in any accepted form.
    let gnb = Address::from_hash(hash, Network::Testnet).to_string();
    assert!(gnb.starts_with(TESTNET_PREFIX));
    let bloch = gnb.replacen(TESTNET_PREFIX, LEGACY_BLOCH_TESTNET_PREFIX, 1);
    for s in [&gnb, &bloch, &shown] {
        assert_eq!(display_address(s), shown, "{s}");
        assert_eq!(Address::parse_for_network_in(s, Network::Testnet, process_family()).unwrap().hash(), &hash);
    }
}
