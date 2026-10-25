//! Bloch Genesis-3 carryover: the opening ledger of GnB.
//!
//! GnB's genesis state is the Bloch Genesis-3 terminal snapshot (the same file
//! Bloch Genesis-4 opened with), converted proportionally into 8% of the hard
//! cap (80,000 OBB). The snapshot is a TSV, one unspent output per line:
//!
//! ```text
//! txid_hex \t vout \t value_blch_sat \t script_pubkey_hex(20 bytes)
//! ```
//!
//! Consensus rules, all checked before anything is written:
//!
//! 1. SHA3-256 over the file's raw bytes equals `CARRYOVER_SNAPSHOT_SHA3`
//!    (no sorting or normalisation: any edit, truncation or reordering fails).
//! 2. Exactly `CARRYOVER_SOURCE_ROWS` well-formed lines summing to
//!    `CARRYOVER_SOURCE_TOTAL_SAT`, every outpoint distinct.
//! 3. Each output converts to `floor(v × CARRYOVER_ALLOCATION_SAT /
//!    CARRYOVER_SOURCE_TOTAL_SAT)` base units. Outputs that convert to zero are
//!    dropped (exactly one in this snapshot: a zero-value Bloch output).
//! 4. Known exporter defect: 38 rows carry vout `16777216` (`0x01000000`), the
//!    little-endian encoding of 1 read big-endian. GnB records them at vout 1,
//!    the real Genesis-3 outpoint; no `(txid, 1)` row exists for those txids.
//!
//! Owners are 20-byte public-key hashes. A Bloch address `bloch1q<hash><cs>`
//! is the GnB address `gnb1q<hash><cs>`: the checksum covers only the hash,
//! so only the prefix changes, and the same keys spend the coins (signing
//! under the GnB sighash domain and chain id).

use super::tokenomics::{CARRYOVER_ALLOCATION_SAT, SAT_PER_GNB};
use super::TxOutput;
use sha3::{Digest, Sha3_256};

/// SHA3-256 of the uncompressed snapshot (`genesis/bloch-g3-carryover.tsv`).
pub const CARRYOVER_SNAPSHOT_SHA3: [u8; 32] = [
    0x3d, 0x67, 0x24, 0x6e, 0x94, 0x88, 0x1a, 0x17,
    0xd3, 0x02, 0xb4, 0x64, 0xf7, 0x9f, 0xee, 0x55,
    0x88, 0x6d, 0x80, 0x68, 0x79, 0x4e, 0x76, 0xfe,
    0xd4, 0x30, 0x81, 0x11, 0x7f, 0xbe, 0x30, 0x8d,
];
/// Lines in the snapshot.
pub const CARRYOVER_SOURCE_ROWS: u64 = 452_726;
/// Sum of the snapshot's values, Bloch base units (3,810,744,000 BLCH).
pub const CARRYOVER_SOURCE_TOTAL_SAT: u64 = 3_810_744_000 * SAT_PER_GNB;
/// UTXOs written to the GnB genesis ledger (zero conversions dropped).
pub const CARRYOVER_CONVERTED_UTXOS: u64 = 452_725;
/// Base units written to the genesis ledger (79,999.99675352 OBB).
pub const CARRYOVER_CONVERTED_TOTAL_SAT: u64 = 7_999_999_675_352;
/// Corrupted vout written by the Bloch exporter, and the real vout.
pub const CARRYOVER_BAD_VOUT: u32 = 0x0100_0000;
pub const CARRYOVER_FIXED_VOUT: u32 = 1;

const _: () = assert!(CARRYOVER_CONVERTED_TOTAL_SAT <= CARRYOVER_ALLOCATION_SAT);

/// Convert a Bloch carryover value into GNB base units (rounds down).
pub const fn convert_value(blch_sat: u64) -> u64 {
    ((blch_sat as u128 * CARRYOVER_ALLOCATION_SAT as u128) / CARRYOVER_SOURCE_TOTAL_SAT as u128) as u64
}

/// One converted genesis output.
#[derive(Clone, Debug)]
pub struct CarryoverUtxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub output: TxOutput,
}

/// A snapshot that passed every check, already converted to GNB.
#[derive(Debug)]
pub struct VerifiedCarryover {
    pub utxos: Vec<CarryoverUtxo>,
    pub sha3: [u8; 32],
    pub source_rows: u64,
    pub source_total_sat: u128,
    pub converted_total_sat: u64,
    pub dropped_zero: u64,
    pub fixed_vouts: u64,
}

/// Structural parse + conversion of a snapshot's bytes, without comparing
/// against this chain's constants. Returns every failure found.
pub fn parse_and_convert(bytes: &[u8]) -> Result<VerifiedCarryover, Vec<String>> {
    let sha3: [u8; 32] = Sha3_256::digest(bytes).into();
    let mut failures = Vec::new();
    let mut lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let mut seen = std::collections::HashSet::with_capacity(lines.len());
    let mut utxos = Vec::with_capacity(lines.len());
    let (mut source_total, mut converted_total) = (0u128, 0u64);
    let (mut dropped_zero, mut fixed_vouts, mut bad) = (0u64, 0u64, 0u64);
    for (i, line) in lines.iter().enumerate() {
        let Some((txid, mut vout, value, spk)) = parse_line(line) else {
            bad += 1;
            if bad <= 5 {
                failures.push(format!("line {} is malformed (want txid\\tvout\\tvalue\\tspk20)", i + 1));
            }
            continue;
        };
        if vout == CARRYOVER_BAD_VOUT {
            vout = CARRYOVER_FIXED_VOUT;
            fixed_vouts += 1;
        }
        if !seen.insert((txid, vout)) {
            bad += 1;
            if bad <= 5 {
                failures.push(format!("line {} duplicates outpoint {}:{}", i + 1, hex::encode(txid), vout));
            }
            continue;
        }
        source_total += value as u128;
        let converted = convert_value(value);
        if converted == 0 {
            dropped_zero += 1;
            continue;
        }
        converted_total += converted;
        utxos.push(CarryoverUtxo { txid, vout, output: TxOutput { value: converted, script_pubkey: spk } });
    }
    if bad > 5 {
        failures.push(format!("... {} bad line(s) in total", bad));
    }
    if failures.is_empty() {
        Ok(VerifiedCarryover {
            utxos,
            sha3,
            source_rows: lines.len() as u64,
            source_total_sat: source_total,
            converted_total_sat: converted_total,
            dropped_zero,
            fixed_vouts,
        })
    } else {
        Err(failures)
    }
}

/// Verify a snapshot against this chain's constants and convert it.
/// Fail closed: every mismatch is reported and nothing is returned.
pub fn verify_and_convert(bytes: &[u8]) -> Result<VerifiedCarryover, Vec<String>> {
    let c = parse_and_convert(bytes)?;
    let mut failures = Vec::new();
    if c.sha3 != CARRYOVER_SNAPSHOT_SHA3 {
        failures.push(format!(
            "snapshot SHA3-256 {} != required {}",
            hex::encode(c.sha3), hex::encode(CARRYOVER_SNAPSHOT_SHA3)));
    }
    if c.source_rows != CARRYOVER_SOURCE_ROWS {
        failures.push(format!("snapshot has {} rows, chain requires {}", c.source_rows, CARRYOVER_SOURCE_ROWS));
    }
    if c.source_total_sat != CARRYOVER_SOURCE_TOTAL_SAT as u128 {
        failures.push(format!("snapshot sums to {} BLCH sat, chain requires {}",
            c.source_total_sat, CARRYOVER_SOURCE_TOTAL_SAT));
    }
    if c.utxos.len() as u64 != CARRYOVER_CONVERTED_UTXOS {
        failures.push(format!("{} converted UTXOs, chain requires {}", c.utxos.len(), CARRYOVER_CONVERTED_UTXOS));
    }
    if c.converted_total_sat != CARRYOVER_CONVERTED_TOTAL_SAT {
        failures.push(format!("converted total {} sat, chain requires {}",
            c.converted_total_sat, CARRYOVER_CONVERTED_TOTAL_SAT));
    }
    if failures.is_empty() { Ok(c) } else { Err(failures) }
}

/// `txid_hex \t vout \t value \t spk_hex` with a 32-byte txid and a 20-byte
/// script. Zero values are well-formed (they convert to zero and are dropped).
fn parse_line(line: &[u8]) -> Option<([u8; 32], u32, u64, Vec<u8>)> {
    let s = std::str::from_utf8(line).ok()?;
    let mut it = s.split('\t');
    let txid: [u8; 32] = hex::decode(it.next()?).ok()?.try_into().ok()?;
    let vout: u32 = it.next()?.parse().ok()?;
    let value: u64 = it.next()?.parse().ok()?;
    let spk = hex::decode(it.next()?).ok()?;
    if it.next().is_some() || spk.len() != 20 {
        return None;
    }
    Some((txid, vout, value, spk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Network};

    fn row(txid: u8, vout: u32, value: u64, spk: u8) -> String {
        format!("{}\t{}\t{}\t{}\n", hex::encode([txid; 32]), vout, value, hex::encode([spk; 20]))
    }

    #[test]
    fn conversion_is_proportional_and_rounds_down() {
        assert_eq!(convert_value(CARRYOVER_SOURCE_TOTAL_SAT), CARRYOVER_ALLOCATION_SAT);
        assert_eq!(convert_value(0), 0);
        // One Genesis-3 coinbase (8,400 BLCH) = 0.17634351 OBB.
        assert_eq!(convert_value(8_400 * SAT_PER_GNB), 17_634_351);
        assert_eq!(convert_value(1), 0);
        assert_eq!(convert_value(u64::MAX), ((u64::MAX as u128 * CARRYOVER_ALLOCATION_SAT as u128) / CARRYOVER_SOURCE_TOTAL_SAT as u128) as u64);
    }

    #[test]
    fn parses_converts_fixes_vout_and_drops_zero() {
        let text = [row(1, 0, 8_400 * SAT_PER_GNB, 7), row(2, CARRYOVER_BAD_VOUT, 100 * SAT_PER_GNB, 8), row(3, 0, 0, 9)].concat();
        let c = parse_and_convert(text.as_bytes()).unwrap();
        assert_eq!(c.source_rows, 3);
        assert_eq!(c.utxos.len(), 2);
        assert_eq!(c.dropped_zero, 1);
        assert_eq!(c.fixed_vouts, 1);
        assert_eq!(c.utxos[1].vout, 1);
        assert_eq!(c.utxos[0].output.script_pubkey, vec![7u8; 20]);
        assert_eq!(c.converted_total_sat, c.utxos.iter().map(|u| u.output.value).sum::<u64>());
        // Not this chain's snapshot.
        assert!(verify_and_convert(text.as_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_and_duplicate_rows() {
        let dup = [row(1, 0, 5, 7), row(1, 0, 5, 7)].concat();
        assert!(parse_and_convert(dup.as_bytes()).is_err());
        // The vout fix must not create a collision silently.
        let collide = [row(1, 1, 5, 7), row(1, CARRYOVER_BAD_VOUT, 5, 7)].concat();
        assert!(parse_and_convert(collide.as_bytes()).is_err());
        assert!(parse_and_convert(b"zz\t0\t1\tab\n").is_err());
        let short_spk = format!("{}\t0\t5\tabcd\n", hex::encode([1u8; 32]));
        assert!(parse_and_convert(short_spk.as_bytes()).is_err());
    }

    /// Failure reporting: the first five bad lines are named (1-based), and a
    /// sixth or later bad line adds one summary with the total.
    #[test]
    fn failure_report_names_five_lines_then_summarises() {
        let good = row(1, 0, 5, 7);
        let bad = |n: usize| -> String { (0..n).map(|_| "garbage\n").collect::<String>() };
        let f = parse_and_convert(format!("{good}{}", bad(1)).as_bytes()).unwrap_err();
        assert_eq!(f, vec!["line 2 is malformed (want txid\\tvout\\tvalue\\tspk20)".to_string()]);
        let f = parse_and_convert(bad(5).as_bytes()).unwrap_err();
        assert_eq!(f.len(), 5);
        assert!(f[0].starts_with("line 1 is malformed") && f[4].starts_with("line 5 is malformed"));
        let f = parse_and_convert(bad(6).as_bytes()).unwrap_err();
        assert_eq!(f.len(), 6);
        assert_eq!(f[5], "... 6 bad line(s) in total");
        let f = parse_and_convert(bad(9).as_bytes()).unwrap_err();
        assert_eq!(f.len(), 6);
        assert_eq!(f[5], "... 9 bad line(s) in total");
        // Duplicates count as bad lines and are named with their outpoint.
        let f = parse_and_convert([row(1, 0, 5, 7), row(1, 0, 6, 7)].concat().as_bytes()).unwrap_err();
        assert_eq!(f, vec![format!("line 2 duplicates outpoint {}:0", hex::encode([1u8; 32]))]);
        let dups = row(1, 0, 5, 7).repeat(8);
        let f = parse_and_convert(dups.as_bytes()).unwrap_err();
        assert_eq!(f.len(), 6);
        assert_eq!(f[5], "... 7 bad line(s) in total");
    }

    /// Totals and counters of a parsed snapshot, and the trailing-newline rule.
    #[test]
    fn parsed_totals_and_counters() {
        let text = [row(1, 0, 3, 7), row(2, 5, 8_400 * SAT_PER_GNB, 8), row(3, 0, 0, 9)].concat();
        let c = parse_and_convert(text.as_bytes()).unwrap();
        assert_eq!(c.source_rows, 3);
        assert_eq!(c.source_total_sat, 3 + 8_400 * SAT_PER_GNB as u128);
        assert_eq!(c.converted_total_sat, 17_634_351);
        assert_eq!((c.dropped_zero, c.fixed_vouts), (2, 0), "1 sat and 0 sat both convert to 0");
        assert_eq!(c.utxos.len(), 1);
        assert_eq!((c.utxos[0].txid, c.utxos[0].vout), ([2; 32], 5));
        // Without the final newline: the same rows.
        let c2 = parse_and_convert(text.trim_end().as_bytes()).unwrap();
        assert_eq!(c2.source_rows, 3);
        // An empty line in the middle is a malformed row.
        let gap = [row(1, 0, 3, 7), "\n".to_string(), row(2, 0, 3, 7)].concat();
        assert!(parse_and_convert(gap.as_bytes()).is_err());
        // A fifth column is malformed.
        let five = format!("{}\t0\t5\t{}\textra\n", hex::encode([1u8; 32]), hex::encode([7u8; 20]));
        assert!(parse_and_convert(five.as_bytes()).is_err());
    }

    /// Every constant check of `verify_and_convert` reports its own failure.
    #[test]
    fn verify_reports_every_mismatch() {
        let text = [row(1, 0, 8_400 * SAT_PER_GNB, 7), row(2, 0, 0, 8)].concat();
        let f = verify_and_convert(text.as_bytes()).unwrap_err();
        assert_eq!(f.len(), 5, "{f:?}");
        assert!(f[0].starts_with("snapshot SHA3-256 "));
        assert_eq!(f[1], format!("snapshot has 2 rows, chain requires {CARRYOVER_SOURCE_ROWS}"));
        assert_eq!(f[2], format!("snapshot sums to {} BLCH sat, chain requires {CARRYOVER_SOURCE_TOTAL_SAT}", 8_400 * SAT_PER_GNB));
        assert_eq!(f[3], format!("1 converted UTXOs, chain requires {CARRYOVER_CONVERTED_UTXOS}"));
        assert_eq!(f[4], format!("converted total 17634351 sat, chain requires {CARRYOVER_CONVERTED_TOTAL_SAT}"));
        // A structurally broken snapshot reports the parse failures only.
        assert_eq!(verify_and_convert(b"x\n").unwrap_err().len(), 1);
    }

    #[test]
    fn bloch_address_maps_to_gnb_address_with_same_hash_and_checksum() {
        let hash = [0x5au8; 20];
        let gnb = Address::from_hash(hash, Network::Mainnet).to_string();
        assert!(gnb.starts_with("gnb1q"));
        let body = &gnb["gnb1q".len()..];
        // The Bloch address of the same owner is "bloch1q" + the same body.
        let bloch = format!("bloch1q{body}");
        let reparsed = Address::parse(&format!("gnb1q{}", &bloch["bloch1q".len()..])).unwrap();
        assert_eq!(reparsed.hash(), &hash);
    }

    /// The snapshot shipped in the repository (genesis/bloch-g3-carryover.tsv.gz),
    /// decompressed in memory, verifies against this chain's constants. Runs by
    /// default; the consensus hash is over the uncompressed bytes, so the gzip
    /// framing itself is not pinned.
    #[test]
    fn shipped_snapshot_verifies() {
        use std::io::Read;
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../genesis/bloch-g3-carryover.tsv.gz");
        let gz = std::fs::File::open(path).expect("genesis/bloch-g3-carryover.tsv.gz is shipped in the repository");
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(gz).read_to_end(&mut bytes).expect("snapshot gzip decodes");
        let c = verify_and_convert(&bytes).unwrap_or_else(|f| panic!("{f:?}"));
        assert_eq!(c.fixed_vouts, 38);
        assert_eq!(c.dropped_zero, 1);
    }
}
