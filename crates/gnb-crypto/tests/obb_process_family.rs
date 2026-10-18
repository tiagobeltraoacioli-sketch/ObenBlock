//! The process-wide address family on ObenBlock (DESIGN-obenblock.md §2), in
//! its own test process: selecting ObenBlock here cannot leak into the GnB
//! library tests.
use gnb_crypto::address::{
    display_address, process_family, set_process_family, Address, AddressFamily, Network, PolicyAddress,
    LEGACY_BLOCH_MAINNET_PREFIX, OBB_MAINNET_PREFIX,
};
use gnb_crypto::core::MAINNET_PREFIX;

#[test]
fn obenblock_process_shows_obb_and_parses_every_form() {
    set_process_family(AddressFamily::ObenBlock).unwrap();
    // Idempotent for the same family; the other family is refused.
    assert_eq!(set_process_family(AddressFamily::ObenBlock), Ok(()));
    assert_eq!(set_process_family(AddressFamily::Gnb), Err(AddressFamily::ObenBlock));
    assert_eq!(process_family(), AddressFamily::ObenBlock);

    let a = Address::from_hash([5u8; 20], Network::Mainnet);
    let gnb = a.to_string();
    let bloch = gnb.replacen(MAINNET_PREFIX, LEGACY_BLOCH_MAINNET_PREFIX, 1);
    let obb = a.to_string_in(AddressFamily::ObenBlock);
    assert!(obb.starts_with(OBB_MAINNET_PREFIX));
    for s in [&gnb, &bloch, &obb] {
        assert_eq!(display_address(s), obb, "{s}");
        assert_eq!(Address::parse_in(s, process_family()), Ok(a));
    }
    // v2 stays v2, in the obb HRP.
    assert_eq!(display_address(&a.to_bech32m()), a.to_bech32m_in(AddressFamily::ObenBlock));

    // A policy keeps its script; the legacy checksum is recomputed for obb1m.
    let p = PolicyAddress::from_script(&[&[0x02u8][..], &[8u8; 32]].concat(), Network::Testnet).unwrap();
    let shown = display_address(&p.to_string());
    assert!(shown.starts_with("obb1n"), "{shown}");
    assert_eq!(PolicyAddress::parse_in(&shown, process_family()), Ok(p));

    // What does not parse is returned for the caller's parser to refuse.
    assert_eq!(display_address("gnb1qzz"), "gnb1qzz");
}
