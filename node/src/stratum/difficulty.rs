//! Share difficulty, the miner-facing unit of stratum.
//!
//! Stratum V1 (`mining.set_difficulty`) and most SV2 firmware speak
//! Bitcoin's difficulty: `difficulty = diff1_target / target` with
//! `diff1_target = target(0x1d00ffff)`. ObenBlock's header and proof are
//! Bitcoin's (docs/DESIGN-obenblock.md §4.1: the id, read as a 256-bit
//! little-endian integer, is at most the target), so the same unit means the
//! same expected hashes per share on an ObenBlock job as on a Bitcoin one:
//! about `difficulty * 2^32`.
//!
//! The share target only decides what a miner gets back for a share. A block
//! is judged by its own `bits` (the job's consensus target) through the
//! acceptance path; nothing here is consensus.

use gnb_smh::difficulty::{bits_to_target, Target};
use primitive_types::U256;

/// Bitcoin's difficulty-1 compact target (also ObenBlock's mainnet pow
/// limit).
pub const DIFF1_BITS: u32 = 0x1D00_FFFF;

fn diff1() -> U256 {
    U256::from_big_endian(&bits_to_target(DIFF1_BITS).0)
}

fn u256_to_f64(x: U256) -> f64 {
    // At most 256 bits: four 64-bit limbs, most significant first.
    x.0.iter().rev().fold(0.0f64, |acc, limb| acc * 18_446_744_073_709_551_616.0 + *limb as f64)
}

fn f64_to_u256(x: f64) -> U256 {
    if !x.is_finite() || x >= 2f64.powi(256) {
        return U256::MAX;
    }
    if x < 1.0 {
        return U256::zero();
    }
    // x = m * 2^e with m a 53-bit integer.
    let e = x.log2().floor() as i32 - 52;
    if e <= 0 {
        return U256::from(x as u64);
    }
    let m = (x / 2f64.powi(e)) as u64;
    U256::from(m) << (e as usize)
}

/// Bitcoin difficulty of a big-endian `target` (`f64::INFINITY` for a zero
/// target).
pub fn difficulty_from_target(target: &Target) -> f64 {
    let t = U256::from_big_endian(&target.0);
    if t.is_zero() {
        return f64::INFINITY;
    }
    u256_to_f64(diff1()) / u256_to_f64(t)
}

/// Bitcoin difficulty of compact `bits` (the network difficulty of a job).
pub fn difficulty_from_bits(bits: u32) -> f64 {
    difficulty_from_target(&bits_to_target(bits))
}

/// The share target of difficulty `d` (`diff1_target / d`, rounded down),
/// saturating at the all-ones target for a difficulty at or below
/// `diff1 / 2^256`. A non-positive or non-finite `d` is treated as the
/// easiest target.
pub fn target_from_difficulty(d: f64) -> Target {
    if !d.is_finite() || d <= 0.0 {
        return Target::MAX;
    }
    let t = f64_to_u256(u256_to_f64(diff1()) / d);
    Target(t.to_big_endian())
}

/// The easier (numerically larger) of two big-endian targets.
pub fn easier(a: &Target, b: &Target) -> Target {
    if a.0 >= b.0 { *a } else { *b }
}

/// The harder (numerically smaller) of two big-endian targets.
pub fn harder(a: &Target, b: &Target) -> Target {
    if a.0 <= b.0 { *a } else { *b }
}

/// The share target a miner of `hashes_per_sec` meets about once per
/// `secs` seconds (`2^256 / (h * secs)`), for a channel opened with a
/// nominal hash rate. Zero or non-finite rates give the easiest target.
pub fn target_for_rate(hashes_per_sec: f64, secs: f64) -> Target {
    let work = hashes_per_sec * secs;
    if !work.is_finite() || work <= 1.0 {
        return Target::MAX;
    }
    Target(f64_to_u256(2f64.powi(256) / work).to_big_endian())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_one_is_the_bitcoin_diff1_target() {
        assert!((difficulty_from_bits(DIFF1_BITS) - 1.0).abs() < 1e-12);
        assert_eq!(target_from_difficulty(1.0), bits_to_target(DIFF1_BITS));
    }

    #[test]
    fn difficulty_and_target_round_trip() {
        for d in [1e-9, 0.001, 0.5, 1.0, 2.0, 1024.0, 65_536.0, 1e12, 1e15] {
            let back = difficulty_from_target(&target_from_difficulty(d));
            assert!(((back - d) / d).abs() < 1e-9, "{d} -> {back}");
        }
        // A harder difficulty is a smaller target.
        assert!(target_from_difficulty(4.0).0 < target_from_difficulty(2.0).0);
    }

    #[test]
    fn degenerate_inputs_saturate() {
        assert_eq!(target_from_difficulty(0.0), Target::MAX);
        assert_eq!(target_from_difficulty(f64::NAN), Target::MAX);
        assert_eq!(target_from_difficulty(1e-80), Target::MAX);
        assert_eq!(difficulty_from_target(&Target::ZERO), f64::INFINITY);
        assert_eq!(target_for_rate(0.0, 10.0), Target::MAX);
    }

    #[test]
    fn regtest_pow_limit_is_far_below_difficulty_one() {
        // ObenBlock regtest's limit (0x207fffff, about one hash in two)
        // is about 2^-31 of difficulty 1.
        let d = difficulty_from_bits(0x207F_FFFF);
        assert!(d > 4.0e-10 && d < 5.0e-10, "{d}");
    }

    #[test]
    fn rate_target_matches_expected_hashes() {
        // 2^32 H/s for 1 s: about one share per 2^32 hashes = difficulty 1.
        let t = target_for_rate(4_294_967_296.0, 1.0);
        let d = difficulty_from_target(&t);
        assert!((d - 1.0).abs() < 1e-3, "{d}");
        assert_eq!(easier(&t, &Target::ZERO), t);
        assert_eq!(harder(&t, &Target::MAX), t);
    }
}
