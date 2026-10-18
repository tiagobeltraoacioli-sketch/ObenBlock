//! User-facing address strings (`address::Address::parse`,
//! `parse_for_network`, `FromStr`, `Display`): RPC parameters, the
//! `--miner-address` flag, wallet recipients and keystore files.
//!
//! * For legacy inputs, `parse` returns exactly the verdict (value or error kind) of an
//!   independent parser written from the format: prefix `gnb1q` / `gnb1t`
//!   (or the Bloch `bloch1q` / `bloch1t` alias), 48 hex digits of
//!   `hash(20) || SHA3-256(SHA3-256(hash))[..4]`.
//! * An accepted string's canonical form (`to_string`) parses to the same
//!   address. Legacy input differs only by hex case and the Bloch alias;
//!   v2 input matches the explicit Bech32m renderer, ignoring uniform case.
//!   `parse_for_network` accepts it for its own network only (CRY-7).
//! * Generated addresses round-trip; changing any one hex digit of the
//!   payload to another value is refused with `BadChecksum`; swapping the
//!   prefix keeps the hash and changes the network (the documented residual:
//!   the checksum does not cover the prefix).
//! * V2 strings retain parsing/network/round-trip invariants and reject one
//!   changed character or a network-prefix swap. The independent v2 verdict
//!   comparison is the Python differential corpus, not this legacy reference.
//! * ObenBlock (DESIGN-obenblock.md §2) accepts every string GnB accepts as
//!   the same address, and its display (`normalize_legacy_address_in`)
//!   parses back to it with an `obb` prefix or HRP.
#![no_main]

mod common;

use common::*;
use gnb_crypto::address::{normalize_legacy_address, normalize_legacy_address_in, Address, AddressError, AddressFamily, Network};
use libfuzzer_sys::fuzz_target;

fn ref_parse(s: &str) -> Result<([u8; 20], Network), AddressError> {
    let (net, payload) = if let Some(p) = s.strip_prefix("gnb1q").or_else(|| s.strip_prefix("bloch1q")) {
        (Network::Mainnet, p)
    } else if let Some(p) = s.strip_prefix("gnb1t").or_else(|| s.strip_prefix("bloch1t")) {
        (Network::Testnet, p)
    } else {
        return Err(AddressError::BadPrefix);
    };
    if payload.len() != 48 {
        return Err(AddressError::BadLength { got: payload.len(), expected: 48 });
    }
    let mut raw = [0u8; 24];
    let pb = payload.as_bytes();
    for (i, out) in raw.iter_mut().enumerate() {
        let nib = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        match (nib(pb[2 * i]), nib(pb[2 * i + 1])) {
            (Some(h), Some(l)) => *out = h << 4 | l,
            _ => return Err(AddressError::BadHex),
        }
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&raw[..20]);
    if sha3(&sha3(&hash))[..4] != raw[20..] {
        return Err(AddressError::BadChecksum);
    }
    Ok((hash, net))
}

fn other(n: Network) -> Network {
    match n {
        Network::Mainnet => Network::Testnet,
        Network::Testnet => Network::Mainnet,
    }
}

/// `AddressError` is not `Clone`.
fn copy_err(e: &AddressError) -> AddressError {
    match e {
        AddressError::BadPrefix => AddressError::BadPrefix,
        AddressError::BadLength { got, expected } => AddressError::BadLength { got: *got, expected: *expected },
        AddressError::BadHex => AddressError::BadHex,
        AddressError::BadEncoding => AddressError::BadEncoding,
        AddressError::BadChecksum => AddressError::BadChecksum,
        AddressError::WrongNetwork { expected, got } => AddressError::WrongNetwork { expected: *expected, got: *got },
    }
}

fn check_str(s: &str) {
    let got = Address::parse(s);
    let lib = match &got {
        Ok(a) => Ok((*a.hash(), a.network())),
        Err(e) => Err(format!("{e:?}")),
    };
    let is_v2 = s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("gnb1z"))
        || s.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("tgnb1z"));
    if !is_v2 {
        assert_eq!(lib, ref_parse(s).map_err(|e| format!("{e:?}")), "legacy parse differs from the reference");
    }
    assert_eq!(s.parse::<Address>(), got, "FromStr differs from parse");
    let obb = Address::parse_in(s, AddressFamily::ObenBlock);
    if let Ok(a) = &got {
        assert_eq!(obb.as_ref().ok(), Some(a), "ObenBlock refused or changed a GnB address");
    }
    if let Ok(a) = obb {
        let shown = normalize_legacy_address_in(s, AddressFamily::ObenBlock);
        assert_eq!(Address::parse_in(&shown, AddressFamily::ObenBlock), Ok(a), "ObenBlock display does not round-trip");
        assert!(shown.starts_with("obb1") || shown.starts_with("tobb1"), "ObenBlock display is not obb");
    }
    match got {
        Ok(a) => {
            let canon = a.to_string();
            assert_eq!(Address::parse(&canon), Ok(a), "canonical form does not round-trip");
            if is_v2 {
                assert!(a.to_bech32m().eq_ignore_ascii_case(s), "v2 form differs beyond case");
            } else {
                assert!(canon.eq_ignore_ascii_case(&normalize_legacy_address(s)), "legacy form differs beyond case/alias");
            }
            assert!(canon.starts_with(a.network().prefix()));
            assert_eq!(Address::parse_for_network(s, a.network()), Ok(a));
            assert_eq!(
                Address::parse_for_network(s, other(a.network())),
                Err(AddressError::WrongNetwork { expected: other(a.network()), got: a.network() })
            );
            assert_eq!(a.is_mainnet(), a.network() == Network::Mainnet);
            assert_eq!(a.is_testnet(), !a.is_mainnet());
            assert_eq!(a.hash_bytes(), a.hash());
        }
        Err(e) => {
            for n in [Network::Mainnet, Network::Testnet] {
                assert_eq!(Address::parse_for_network(s, n), Err(copy_err(&e)));
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    if inp.u8() & 1 == 0 {
        let rest = inp.rest();
        check_str(&String::from_utf8_lossy(rest));
        return;
    }
    let hash: [u8; 20] = inp.arr();
    let net = if inp.bool() { Network::Testnet } else { Network::Mainnet };
    let a = Address::from_hash(hash, net);
    let s = a.to_string();
    assert_eq!(s.len(), 5 + 48);
    assert_eq!(Address::parse(&s), Ok(a));
    check_str(&s);
    let v2 = a.to_bech32m();
    check_str(&v2);
    check_str(&v2.to_ascii_uppercase());
    let swapped_v2 = if net == Network::Mainnet { format!("t{v2}") } else { v2[1..].to_owned() };
    assert!(Address::parse(&swapped_v2).is_err(), "v2 checksum did not bind the network");
    let mut changed_v2 = v2.as_bytes().to_vec();
    let position = inp.below(changed_v2.len());
    changed_v2[position] = if changed_v2[position] == b'q' { b'p' } else { b'q' };
    let changed_v2 = String::from_utf8(changed_v2).unwrap();
    assert!(Address::parse(&changed_v2).is_err(), "v2 single-character change accepted");
    check_str(&changed_v2);
    assert_eq!(Address::from_pubkey(&inp.var_bytes(64), net).network(), net);

    // One hex digit of the payload changed to another value.
    let i = 5 + inp.below(48);
    let c = s.as_bytes()[i];
    let cur = (c as char).to_digit(16).unwrap() as u8;
    let new = (cur + 1 + (inp.u8() % 15)) % 16;
    let mut b = s.clone().into_bytes();
    b[i] = if inp.bool() { b"0123456789abcdef"[new as usize] } else { b"0123456789ABCDEF"[new as usize] };
    let changed = String::from_utf8(b).unwrap();
    assert_eq!(Address::parse(&changed), Err(AddressError::BadChecksum), "a one-digit change was accepted");
    check_str(&changed);

    // Upper-case digits are the same address.
    let upper = format!("{}{}", &s[..5], s[5..].to_ascii_uppercase());
    assert_eq!(Address::parse(&upper), Ok(a));

    // Prefix swap and the Bloch alias.
    let swapped = format!("{}{}", other(net).prefix(), &s[5..]);
    assert_eq!(Address::parse(&swapped), Ok(Address::from_hash(hash, other(net))));
    let bloch = format!("{}{}", if net == Network::Mainnet { "bloch1q" } else { "bloch1t" }, &s[5..]);
    assert_eq!(Address::parse(&bloch), Ok(a));
    check_str(&bloch);
});
