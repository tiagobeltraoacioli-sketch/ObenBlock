//! Bounded GnB address codec; no transaction or consensus encoding lives here.
//!
//! The checksum, alphabet and case rules follow Bitcoin BIP 173 / BIP 350:
//! https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//! https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
//! BIP 350's constant avoids the original Bech32 insertion weakness. Including
//! the HRP binds transcription checks to the network. Our first data word, 2,
//! is a GnB *address format* version, not a Bitcoin witness/consensus version.
//! This checksum is not authentication and these are not Bitcoin addresses.

use super::{AddressError, AddressFamily, Network};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32M: u32 = 0x2bc830a3;
const FORMAT_VERSION: u8 = 2;

/// HRP of a v2 address of `family` on `network`. ObenBlock's regtest uses
/// the testnet slot of [`Network`], so its HRP is `tobb` (like `tgnb`).
pub(super) fn hrp(family: AddressFamily, network: Network) -> &'static str {
    match (family, network) {
        (AddressFamily::Gnb, Network::Mainnet) => "gnb",
        (AddressFamily::Gnb, Network::Testnet) => "tgnb",
        (AddressFamily::ObenBlock, Network::Mainnet) => "obb",
        (AddressFamily::ObenBlock, Network::Testnet) => "tobb",
    }
}

/// Version 2 begins with `z`, disjoint from all exact legacy prefixes. This
/// leaves legacy acceptance and diagnostics unchanged, including hex casing.
/// Only the HRPs `family` accepts are candidates, so a GnB parser keeps its
/// exact pre-ObenBlock diagnostics for `obb1z…` strings.
pub(super) fn is_v2_candidate(s: &str, family: AddressFamily) -> bool {
    // Bytes, not `str` slices: an untrusted string may split a UTF-8
    // character anywhere, and only an ASCII match is a candidate.
    let bytes = s.as_bytes();
    family.accepted().iter().any(|&f| {
        [Network::Mainnet, Network::Testnet].into_iter().any(|n| {
            let hrp = hrp(f, n).as_bytes();
            bytes.len() >= hrp.len() + 2
                && bytes[..hrp.len()].eq_ignore_ascii_case(hrp)
                && bytes[hrp.len()..hrp.len() + 2].eq_ignore_ascii_case(b"1z")
        })
    })
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut check = 1u32;
    for value in values {
        let top = check >> 25;
        check = ((check & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (bit, generator) in GENERATORS.iter().enumerate() {
            if top & (1 << bit) != 0 {
                check ^= generator;
            }
        }
    }
    check
}

fn hrp_words(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes()
        .map(|c| c >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|c| c & 31))
}

fn encode(hrp: &str, words: &[u8]) -> String {
    let check = polymod(hrp_words(hrp).chain(words.iter().copied()).chain([0; 6])) ^ BECH32M;
    let mut encoded = String::with_capacity(hrp.len() + 1 + words.len() + 6);
    encoded.push_str(hrp);
    encoded.push('1');
    for &word in words {
        encoded.push(char::from(CHARSET[usize::from(word)]));
    }
    for shift in (0..6).rev() {
        encoded.push(char::from(CHARSET[((check >> (shift * 5)) & 31) as usize]));
    }
    encoded
}

fn decode(s: &str) -> Result<(String, Vec<u8>), AddressError> {
    // Check before allocating or lowercasing. Every supported address is ASCII.
    if s.len() > 90 || s.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(AddressError::BadEncoding);
    }
    if s.bytes().any(|c| c.is_ascii_lowercase()) && s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(AddressError::BadEncoding);
    }
    let lower = s.to_ascii_lowercase();
    let separator = lower.rfind('1').ok_or(AddressError::BadEncoding)?;
    if separator == 0 || lower.len() - separator - 1 < 6 {
        return Err(AddressError::BadEncoding);
    }
    let (hrp, encoded) = lower.split_at(separator);
    let mut words = Vec::with_capacity(encoded.len() - 1);
    for c in encoded.bytes().skip(1) {
        let word = CHARSET
            .iter()
            .position(|&candidate| candidate == c)
            .ok_or(AddressError::BadEncoding)?;
        words.push(word as u8);
    }
    if polymod(hrp_words(hrp).chain(words.iter().copied())) != BECH32M {
        return Err(AddressError::BadChecksum);
    }
    words.truncate(words.len() - 6);
    Ok((hrp.to_owned(), words))
}

// Private callers use only 8->5 (encoding) and 5->8 (strict decoding). The
// accumulator is masked to the maximum live bits, independently of word size.
fn convert_bits(data: &[u8], from: u8, to: u8, pad: bool) -> Option<Vec<u8>> {
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let max_value = (1u32 << to) - 1;
    let max_accumulator = (1u32 << (from + to - 1)) - 1;
    let mut result = Vec::new();
    for &value in data {
        if u32::from(value) >> from != 0 {
            return None;
        }
        accumulator = ((accumulator << from) | u32::from(value)) & max_accumulator;
        bits += from;
        while bits >= to {
            bits -= to;
            result.push(((accumulator >> bits) & max_value) as u8);
        }
    }
    if pad {
        if bits != 0 {
            result.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {
        return None;
    }
    Some(result)
}

pub(super) fn encode_address(family: AddressFamily, network: Network, kind: u8, hash: &[u8]) -> String {
    debug_assert!((kind == 0 && hash.len() == 20) || (kind == 1 && hash.len() == 32));
    let hrp = hrp(family, network);
    let mut words = vec![FORMAT_VERSION, kind];
    // Every byte fits in eight bits; failure is impossible for this conversion.
    words.extend(convert_bits(hash, 8, 5, true).expect("8-bit bytes"));
    encode(hrp, &words)
}

/// Decode a v2 address whose HRP `family` accepts (see [`is_v2_candidate`]).
pub(super) fn decode_address(s: &str, family: AddressFamily) -> Result<(Network, u8, Vec<u8>), AddressError> {
    let (decoded_hrp, words) = decode(s)?;
    let network = family
        .accepted()
        .iter()
        .flat_map(|&f| [Network::Mainnet, Network::Testnet].map(|n| (hrp(f, n), n)))
        .find(|(candidate, _)| *candidate == decoded_hrp)
        .map(|(_, n)| n)
        .ok_or(AddressError::BadPrefix)?;
    if words.len() < 2 || words[0] != FORMAT_VERSION {
        return Err(AddressError::BadEncoding);
    }
    let expected = match words[1] {
        0 => 20,
        1 => 32,
        _ => return Err(AddressError::BadEncoding),
    };
    let hash = convert_bits(&words[2..], 5, 8, false).ok_or(AddressError::BadEncoding)?;
    if hash.len() != expected {
        return Err(AddressError::BadEncoding);
    }
    Ok((network, words[1], hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_bip350_generic_checksum_vectors() {
        // Generic BIP 350 vectors test the checksum layer; their HRPs and data
        // are not valid GnB addresses. Source linked in the module comment.
        for valid in [
            "A1LQFN3A", "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "?1v759aa",
        ] {
            let (hrp, words) = decode(valid).unwrap_or_else(|e| panic!("{valid}: {e}"));
            assert_eq!(encode(&hrp, &words), valid.to_ascii_lowercase());
            assert!(decode_address(valid, AddressFamily::Gnb).is_err());
        }
        for invalid in [
            "\u{20}1xj0phk", "\u{7f}1g6xzxy", "\u{80}1vctc34",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m", "1qyrz8wqd2c9m", "y1b0jsk6g", "lt1igcx5c0",
            "in1muywd", "mm1crxm3i", "au1s5cgom", "M1VUXWEZ", "16plkw9", "1p2gdwpf",
        ] {
            assert!(decode(invalid).is_err(), "{invalid:?}");
        }
        // A BIP 173 checksum must not be accepted as Bech32m.
        assert_eq!(decode("a12uel5l"), Err(AddressError::BadChecksum));
    }

    fn words(kind: u8, hash_len: usize) -> Vec<u8> {
        let mut words = vec![2, kind];
        words.extend(convert_bits(&vec![0; hash_len], 8, 5, true).unwrap());
        words
    }

    #[test]
    fn application_format_rejects_unknown_hrp_version_kind_and_lengths() {
        let valid = words(0, 20);
        assert!(decode_address(&encode("other", &valid), AddressFamily::Gnb).is_err());
        for version in [0, 1, 3, 31] {
            let mut bad = valid.clone();
            bad[0] = version;
            assert!(decode_address(&encode("gnb", &bad), AddressFamily::Gnb).is_err());
        }
        for kind in [2, 3, 31] {
            assert!(decode_address(&encode("gnb", &words(kind, 20)), AddressFamily::Gnb).is_err());
        }
        for (kind, wrong_len) in [
            (0, 0),
            (0, 19),
            (0, 21),
            (0, 32),
            (1, 0),
            (1, 20),
            (1, 31),
            (1, 33),
        ] {
            assert!(decode_address(&encode("gnb", &words(kind, wrong_len)), AddressFamily::Gnb).is_err());
        }
        for too_short in [vec![], vec![2]] {
            assert!(decode_address(&encode("gnb", &too_short), AddressFamily::Gnb).is_err());
        }
    }

    #[test]
    fn strict_padding_rejects_nonzero_and_superfluous_bits() {
        let mut nonzero = words(1, 32);
        *nonzero.last_mut().unwrap() |= 1;
        assert_eq!(
            decode_address(&encode("gnb", &nonzero), AddressFamily::Gnb),
            Err(AddressError::BadEncoding)
        );
        let mut excessive = words(0, 20);
        excessive.push(0); // A whole extra data word is not permitted padding.
        assert_eq!(
            decode_address(&encode("gnb", &excessive), AddressFamily::Gnb),
            Err(AddressError::BadEncoding)
        );
        assert_eq!(
            decode_address(&encode("gnb", &words(0, 20)), AddressFamily::Gnb).unwrap().2,
            vec![0; 20]
        );
        assert_eq!(
            decode_address(&encode("gnb", &words(1, 32)), AddressFamily::Gnb).unwrap().2,
            vec![0; 32]
        );
    }

    #[test]
    fn bound_case_and_network_are_enforced_before_acceptance() {
        let valid = encode_address(AddressFamily::Gnb, Network::Mainnet, 0, &[42; 20]);
        assert!(decode_address(&valid.to_ascii_uppercase(), AddressFamily::Gnb).is_ok());
        assert_eq!(
            decode_address(&valid.replacen("gnb", "Gnb", 1), AddressFamily::Gnb),
            Err(AddressError::BadEncoding)
        );
        assert_eq!(
            decode_address(&valid.replacen("gnb", "tgnb", 1), AddressFamily::Gnb),
            Err(AddressError::BadChecksum)
        );
        assert_eq!(
            decode_address(&format!("gnb1z{}", "q".repeat(86)), AddressFamily::Gnb),
            Err(AddressError::BadEncoding)
        );
        assert_eq!(
            decode_address(&format!("{valid}é"), AddressFamily::Gnb),
            Err(AddressError::BadEncoding)
        );
        assert_eq!(
            decode_address(&format!("{valid}\n"), AddressFamily::Gnb),
            Err(AddressError::BadEncoding)
        );
    }

    #[test]
    fn obenblock_hrps_and_gnb_aliases() {
        for network in [Network::Mainnet, Network::Testnet] {
            for (kind, len) in [(0u8, 20usize), (1, 32)] {
                let obb = encode_address(AddressFamily::ObenBlock, network, kind, &vec![7; len]);
                let gnb = encode_address(AddressFamily::Gnb, network, kind, &vec![7; len]);
                assert!(obb.starts_with(if network == Network::Mainnet { "obb1z" } else { "tobb1z" }));
                assert!(is_v2_candidate(&obb, AddressFamily::ObenBlock));
                // GnB does not know the obb HRPs: not a candidate, so its
                // legacy diagnostics stay what they were.
                assert!(!is_v2_candidate(&obb, AddressFamily::Gnb));
                assert_eq!(decode_address(&obb, AddressFamily::Gnb), Err(AddressError::BadPrefix));
                for s in [&obb, &gnb] {
                    assert_eq!(decode_address(s, AddressFamily::ObenBlock).unwrap(), (network, kind, vec![7; len]));
                }
                assert!(is_v2_candidate(&gnb.to_ascii_uppercase(), AddressFamily::ObenBlock));
            }
        }
    }

    #[test]
    fn candidate_check_never_slices_inside_a_character() {
        for s in ["ob\u{e9}1zqqqqqq", "obb\u{e9}zqqqq", "\u{e9}", "tob\u{1F600}", "gn\u{e9}1z", ""] {
            assert!(!is_v2_candidate(s, AddressFamily::ObenBlock), "{s:?}");
            assert!(!is_v2_candidate(s, AddressFamily::Gnb), "{s:?}");
        }
    }
}
