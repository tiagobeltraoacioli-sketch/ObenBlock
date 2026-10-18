//! ObenBlock address-family vectors, generated independently by the Python
//! reference (`reference/obb_address.py` -> `reference/obb_address_vectors.json`,
//! written by `reference/obb_address_vectors.py`). DESIGN-obenblock.md §2:
//! `obb1…` addresses, with the GnB and Bloch forms parsed as the same script.
use gnb_crypto::address::{
    destination_script, destination_script_in, normalize_legacy_address, normalize_legacy_address_in,
    Address, AddressFamily, Network, PolicyAddress,
};
use serde_json::Value;

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_address_vectors.json"));

fn family(name: &str) -> AddressFamily {
    match name {
        "gnb" => AddressFamily::Gnb,
        "obenblock" => AddressFamily::ObenBlock,
        other => panic!("unknown family {other}"),
    }
}

fn network(name: &str) -> Network {
    match name {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        other => panic!("unknown network {other}"),
    }
}

#[test]
fn every_vector_parses_and_displays_as_the_reference_says() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(doc["format"], "obenblock-address-family-v1");
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() > 400);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let address = c["address"].as_str().unwrap();
        let fam = family(c["family"].as_str().unwrap());
        let got = destination_script_in(address, fam);
        assert_eq!(normalize_legacy_address_in(address, fam), c["display"].as_str().unwrap(), "{name}");
        if !c["valid"].as_bool().unwrap() {
            assert!(got.is_err(), "{name}: accepted {address:?}");
            assert!(Address::parse_in(address, fam).is_err() && PolicyAddress::parse_in(address, fam).is_err(), "{name}");
            continue;
        }
        let net = network(c["network"].as_str().unwrap());
        let script = hex::decode(c["script_hex"].as_str().unwrap()).unwrap();
        assert_eq!(got, Ok((net, script.clone())), "{name}");
        if c["kind"] == "single-key" {
            let a = Address::parse_in(address, fam).unwrap();
            assert_eq!((a.network(), a.hash().to_vec()), (net, script.clone()), "{name}");
            assert!(Address::parse_for_network_in(address, net, fam).is_ok());
            let other = if net == Network::Mainnet { Network::Testnet } else { Network::Mainnet };
            assert!(Address::parse_for_network_in(address, other, fam).is_err(), "{name}");
            assert!(PolicyAddress::parse_in(address, fam).is_err(), "{name}");
        } else {
            let p = PolicyAddress::parse_in(address, fam).unwrap();
            assert_eq!((p.network(), p.script_pubkey()), (net, script.clone()), "{name}");
            assert!(Address::parse_in(address, fam).is_err(), "{name}");
        }
        // The display parses back to the same script.
        assert_eq!(destination_script_in(c["display"].as_str().unwrap(), fam), Ok((net, script)), "{name}");
        // GnB: the family-less API is the GnB family, unchanged.
        if fam == AddressFamily::Gnb {
            assert_eq!(destination_script(address), got, "{name}");
            assert_eq!(normalize_legacy_address(address), normalize_legacy_address_in(address, fam));
        }
    }
}

#[test]
fn obb_renderings_of_the_zero_hash() {
    let main = Address::from_hash([0; 20], Network::Mainnet);
    assert_eq!(main.to_string(), "gnb1q0000000000000000000000000000000000000000335d2ee7");
    assert_eq!(main.to_string_in(AddressFamily::ObenBlock), "obb1q0000000000000000000000000000000000000000335d2ee7");
    assert_eq!(
        Address::from_hash([0; 20], Network::Testnet).to_string_in(AddressFamily::ObenBlock),
        "obb1t0000000000000000000000000000000000000000335d2ee7"
    );
    assert!(main.to_bech32m_in(AddressFamily::ObenBlock).starts_with("obb1zq"));
    assert!(Address::from_hash([0; 20], Network::Testnet).to_bech32m_in(AddressFamily::ObenBlock).starts_with("tobb1zq"));
    let mut script = vec![2];
    script.extend_from_slice(&[0; 32]);
    let policy = PolicyAddress::from_script(&script, Network::Mainnet).unwrap();
    assert!(policy.to_string_in(AddressFamily::ObenBlock).starts_with("obb1m"));
    assert!(PolicyAddress::from_script(&script, Network::Testnet).unwrap().to_string_in(AddressFamily::ObenBlock).starts_with("obb1n"));
    assert!(policy.to_bech32m_in(AddressFamily::ObenBlock).starts_with("obb1zp"));
    // Display and the GnB-family renderings stay the GnB strings.
    assert_eq!(policy.to_string(), policy.to_string_in(AddressFamily::Gnb));
    assert_eq!(main.to_bech32m(), main.to_bech32m_in(AddressFamily::Gnb));
}
