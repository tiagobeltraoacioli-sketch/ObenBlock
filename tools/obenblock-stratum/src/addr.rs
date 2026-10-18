//! ObenBlock addresses -> coinbase output scripts (docs/DESIGN-obenblock.md
//! §2, docs/ADDRESS-V2.md; reference: `reference/obb_address.py`, whose
//! vectors `reference/obb_address_vectors.json` the tests replay for the
//! `obenblock` family).
//!
//! Accepted, on the configured network (mainnet, or the testnet slot that
//! ObenBlock regtest uses):
//!
//! * v2 Bech32m: `obb1z…` / `tobb1z…` (and the GnB HRPs `gnb` / `tgnb`);
//! * legacy policy: `obb1m…` / `obb1n…` (and `gnb1m…` / `gnb1n…`);
//! * legacy single key: `obb1q…` / `obb1t…` (and `gnb1…`, `bloch1…`).
//!
//! The script is the 20-byte key hash, or `0x02 ‖` the 32-byte policy hash.

use sha3::{Digest, Sha3_256};

use crate::types::Network;

const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M: u32 = 0x2BC8_30A3;
const GENERATORS: [u32; 5] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3];
const MAX_ADDRESS_LENGTH: usize = 90;

/// (family HRP or prefix base, mainnet value, testnet value)
const V2_HRPS: [(&str, &str); 2] = [("obb", "tobb"), ("gnb", "tgnb")];
const POLICY_PREFIXES: [(&str, &str); 2] = [("obb1m", "obb1n"), ("gnb1m", "gnb1n")];
const KEY_PREFIXES: [(&str, &str); 3] = [("bloch1q", "bloch1t"), ("obb1q", "obb1t"), ("gnb1q", "gnb1t")];

/// A decoded address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub mainnet: bool,
    pub script_pubkey: Vec<u8>,
}

fn sha3d(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(Sha3_256::digest(data)).into()
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1FF_FFFF) << 5) ^ v as u32;
        for (i, g) in GENERATORS.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn expanded_hrp(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    let mut v: Vec<u8> = b.iter().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(b.iter().map(|c| c & 31));
    v
}

/// Generic Bech32m validation: (hrp, data words without the checksum).
fn bech32m_decode(address: &str) -> Result<(String, Vec<u8>), String> {
    if !(8..=MAX_ADDRESS_LENGTH).contains(&address.len()) {
        return Err("address length".into());
    }
    if address.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err("address must be printable ASCII".into());
    }
    if address != address.to_ascii_lowercase() && address != address.to_ascii_uppercase() {
        return Err("mixed case".into());
    }
    let lower = address.to_ascii_lowercase();
    let sep = lower.rfind('1').ok_or("no separator")?;
    if sep < 1 || sep + 7 > lower.len() {
        return Err("separator or checksum length".into());
    }
    let (hrp, data) = (&lower[..sep], &lower[sep + 1..]);
    let words = data.bytes()
        .map(|c| ALPHABET.iter().position(|&a| a == c).map(|p| p as u8).ok_or("data alphabet"))
        .collect::<Result<Vec<u8>, _>>()?;
    let mut all = expanded_hrp(hrp);
    all.extend_from_slice(&words);
    if polymod(&all) != BECH32M {
        return Err("Bech32m checksum".into());
    }
    Ok((hrp.to_string(), words[..words.len() - 6].to_vec()))
}

/// 5-bit words to bytes, refusing non-canonical padding.
fn words_to_bytes(words: &[u8]) -> Result<Vec<u8>, String> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for &w in words {
        acc = (acc << 5) | w as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 5 || acc != 0 {
        return Err("non-canonical padding".into());
    }
    Ok(out)
}

fn is_v2(address: &str) -> bool {
    V2_HRPS.iter().flat_map(|(m, t)| [*m, *t]).any(|hrp| {
        let head = format!("{hrp}1z");
        address.len() >= head.len() && address.as_bytes()[..head.len()].eq_ignore_ascii_case(head.as_bytes())
    })
}

fn hex_payload(rest: &str, len: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
    if rest.len() != 2 * (len + 4) {
        return Err("length".into());
    }
    let raw = hex::decode(rest).map_err(|_| "hex")?;
    Ok((raw[..len].to_vec(), raw[len..].to_vec()))
}

/// Decode an address of the ObenBlock family (any network).
pub fn decode_any(address: &str) -> Result<Decoded, String> {
    if is_v2(address) {
        let (hrp, words) = bech32m_decode(address)?;
        let mainnet = match V2_HRPS.iter().find_map(|(m, t)| {
            if hrp == *m { Some(true) } else if hrp == *t { Some(false) } else { None }
        }) {
            Some(m) => m,
            None => return Err("unknown HRP".into()),
        };
        if words.len() < 2 || words[0] != 2 || words[1] > 1 {
            return Err("version or kind".into());
        }
        let payload = words_to_bytes(&words[2..])?;
        let script = match (words[1], payload.len()) {
            (0, 20) => payload,
            (1, 32) => [&[0x02u8][..], &payload].concat(),
            _ => return Err("hash length".into()),
        };
        return Ok(Decoded { mainnet, script_pubkey: script });
    }
    for (m, t) in POLICY_PREFIXES {
        for (prefix, mainnet) in [(m, true), (t, false)] {
            if let Some(rest) = address.strip_prefix(prefix) {
                let (hash, check) = hex_payload(rest, 32)?;
                let mut pre = prefix.as_bytes().to_vec();
                pre.extend_from_slice(&hash);
                if check != sha3d(&pre)[..4] {
                    return Err("policy checksum".into());
                }
                return Ok(Decoded { mainnet, script_pubkey: [&[0x02u8][..], &hash].concat() });
            }
        }
    }
    for (m, t) in KEY_PREFIXES {
        for (prefix, mainnet) in [(m, true), (t, false)] {
            if let Some(rest) = address.strip_prefix(prefix) {
                let (hash, check) = hex_payload(rest, 20)?;
                if check != sha3d(&hash)[..4] {
                    return Err("checksum".into());
                }
                return Ok(Decoded { mainnet, script_pubkey: hash });
            }
        }
    }
    Err("not an ObenBlock address (obb1q…, obb1m…, obb1z…; regtest obb1t…, obb1n…, tobb1z…)".into())
}

/// The output script of `address` on `network`.
pub fn script_for(address: &str, network: Network) -> Result<Vec<u8>, String> {
    let d = decode_any(address.trim())?;
    match (network, d.mainnet) {
        (Network::Mainnet, true) | (Network::Regtest, false) => Ok(d.script_pubkey),
        (Network::Mainnet, false) => Err("a regtest/testnet address on mainnet".into()),
        (Network::Regtest, true) => Err("a mainnet address on regtest".into()),
    }
}

/// The payout address part of a stratum username: `<address>` or
/// `<address>.<worker>` (also `_` and `/` separators, which some rental
/// services use).
pub fn username_address(user: &str) -> &str {
    let u = user.trim();
    u.split(['.', '/', '_', '+']).next().unwrap_or(u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../../reference/obb_address_vectors.json");

    #[test]
    fn replays_the_obenblock_family_vectors() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let mut n = 0;
        for c in v["cases"].as_array().unwrap().iter().filter(|c| c["family"] == "obenblock") {
            let addr = c["address"].as_str().unwrap();
            let got = decode_any(addr);
            if c["valid"].as_bool().unwrap() {
                let d = got.unwrap_or_else(|e| panic!("{} should decode: {e}", c["name"]));
                assert_eq!(hex::encode(&d.script_pubkey), c["script_hex"].as_str().unwrap(), "{}", c["name"]);
                assert_eq!(d.mainnet, c["network"] == "mainnet", "{}", c["name"]);
            } else {
                assert!(got.is_err(), "{} must be refused, got {got:?}", c["name"]);
            }
            n += 1;
        }
        assert!(n > 100);
    }

    #[test]
    fn network_is_enforced() {
        let main = "obb1q0000000000000000000000000000000000000000335d2ee7";
        assert_eq!(script_for(main, Network::Mainnet).unwrap(), vec![0u8; 20]);
        assert!(script_for(main, Network::Regtest).is_err());
    }

    #[test]
    fn usernames_carry_the_address_first() {
        assert_eq!(username_address("obb1qabc.rig7"), "obb1qabc");
        assert_eq!(username_address(" obb1qabc "), "obb1qabc");
        assert_eq!(username_address("obb1qabc_rig7"), "obb1qabc");
        assert_eq!(username_address("obb1qabc"), "obb1qabc");
    }
}
