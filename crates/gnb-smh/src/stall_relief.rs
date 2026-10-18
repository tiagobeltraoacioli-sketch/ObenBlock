//! Stall relief: a late block relaxes its own target (ObenBlock,
//! `docs/DESIGN-obenblock.md` §5.1).
//!
//! ASERT fixes a block's target from its parents. If most of the hashrate
//! leaves, the next block at that target can take hours. On top of the ASERT
//! target, the block's own timestamp relaxes it once the block is late:
//!
//! ```text
//! late     = max(0, time - parent_time - grace)                 grace = 6 T = 180 s
//! steps    = floor(late / step)                                 step = 60 s
//! exponent = floor(steps * step * 65536 / halflife)             halflife = 1,800 s
//! shifts   = floor(exponent / 65536),  frac = exponent mod 65536
//! factor   = 65536 + ((195766423245049*frac + 971821376*frac^2 + 5127*frac^3 + 2^47) >> 48)
//! relaxed  = floor(base * factor * 2^(shifts - 16))
//! target   = base                            if steps = 0
//!            max(base, min(pow_limit, relaxed))  otherwise
//! ```
//!
//! `base` is the target of the block's ASERT `bits` (the canonical compact
//! value, so a pool needs only the template's bits and parent time to follow
//! the steps) and `parent_time` is the ASERT input, the latest timestamp over
//! the block's parents. `2^x` uses the same 16.16 fixed point and aserti3-2d
//! cubic as ASERT (`crate::difficulty`), so the relief at 30 steps (30
//! minutes) is exactly a doubling. The relief never makes a block harder:
//! with no step it returns `base` itself, and otherwise never less than
//! `base`. The normative executable definition is `reference/obb_liveness.py`;
//! `reference/liveness_vectors.json` pins it.

use crate::difficulty::{mul_wide, shift_to_u256, target_to_bits, try_bits_to_target, Target};

/// Stall-relief constants of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StallReliefParams {
    /// Seconds after the parent time before relief starts.
    pub grace_secs: i64,
    /// Relief grows in steps of this many seconds (one job per step for a
    /// pool; `ntime` rolling within a step keeps `bits`).
    pub step_secs: i64,
    /// Seconds of lateness that double the target.
    pub halflife_secs: i64,
}

/// ObenBlock: after 3 minutes (6 blocks of 30 s) without a block the target
/// doubles every 30 minutes, in 60-second steps.
pub const OBENBLOCK_STALL_RELIEF: StallReliefParams =
    StallReliefParams { grace_secs: 6 * 30, step_secs: 60, halflife_secs: 1_800 };

/// Whole relief steps a block stamped `time` has earned over `parent_time`
/// (0 while it is within the grace period, or stamped before its parents).
pub fn relief_steps(params: &StallReliefParams, parent_time: i64, time: i64) -> u64 {
    let late = (time as i128 - parent_time as i128 - params.grace_secs as i128).max(0);
    // `late` < 2^65, so the quotient fits u64 for any positive step.
    (late / params.step_secs.max(1) as i128) as u64
}

/// The relaxed target (module docs) of a block whose ASERT target is `base`.
pub fn relieved_target(params: &StallReliefParams, base: &Target, parent_time: i64, time: i64, pow_limit: &Target)
    -> Target
{
    let steps = relief_steps(params, parent_time, time);
    if steps == 0 || base.is_zero() {
        return *base;
    }
    // steps < 2^65 and step * 65536 < 2^80: the product fits i128.
    let exponent = (steps as i128 * params.step_secs as i128 * 65_536).div_euclid(params.halflife_secs.max(1) as i128);
    let shifts = exponent >> 16;
    let frac = (exponent & 0xFFFF) as u128;
    let factor = 65_536
        + ((195_766_423_245_049u128 * frac + 971_821_376u128 * frac.pow(2) + 5_127u128 * frac.pow(3) + (1u128 << 47))
            >> 48) as u64;
    let relaxed = if shifts >= 256 {
        *pow_limit
    } else {
        match shift_to_u256(&mul_wide(&base.0, factor), shifts - 16) {
            Some(t) => Target(t).min(*pow_limit),
            None => *pow_limit, // >= 2^256: above any pow limit
        }
    };
    relaxed.max(*base)
}

/// Compact `bits` of [`relieved_target`] for a block whose ASERT bits are
/// `base_bits`. With no relief step the result is `base_bits` itself
/// (unchanged, bit for bit); malformed `base_bits` are returned unchanged
/// (no expected value is ever malformed).
pub fn relieved_bits(params: &StallReliefParams, base_bits: u32, parent_time: i64, time: i64, pow_limit: &Target)
    -> u32
{
    if relief_steps(params, parent_time, time) == 0 {
        return base_bits;
    }
    match try_bits_to_target(base_bits) {
        Ok(base) => {
            let t = relieved_target(params, &base, parent_time, time, pow_limit);
            if t == base { base_bits } else { target_to_bits(&t) }
        }
        Err(_) => base_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty::bits_to_target;

    const P: StallReliefParams = OBENBLOCK_STALL_RELIEF;
    const OBB_LIMIT: u32 = 0x1D00_FFFF;

    fn limit() -> Target {
        bits_to_target(OBB_LIMIT)
    }

    #[test]
    fn no_relief_within_the_grace_period() {
        let base = 0x1B04_04CB;
        for dt in [-1_000i64, 0, 30, 179, 180, 239] {
            assert_eq!(relief_steps(&P, 1_000, 1_000 + dt), 0, "dt={dt}");
            assert_eq!(relieved_bits(&P, base, 1_000, 1_000 + dt, &limit()), base, "dt={dt}");
        }
        assert_eq!(relief_steps(&P, 1_000, 1_240), 1);
        assert_eq!(relief_steps(&P, 1_000, 1_299), 1);
        assert_eq!(relief_steps(&P, 1_000, 1_300), 2);
    }

    fn shl(t: &Target, n: u32) -> Target {
        let mut out = t.0;
        for _ in 0..n {
            let mut carry = 0u16;
            for b in out.iter_mut().rev() {
                let v = ((*b as u16) << 1) | carry;
                *b = v as u8;
                carry = v >> 8;
            }
        }
        Target(out)
    }

    /// Every 30 steps (30 minutes of lateness) are exactly one doubling.
    #[test]
    fn thirty_steps_double_the_target() {
        let base = bits_to_target(0x1B04_04CB);
        assert_eq!(relieved_target(&P, &base, 0, 180 + 30 * 60, &limit()), shl(&base, 1));
        assert_eq!(relieved_target(&P, &base, 0, 180 + 330 * 60 + 59, &limit()), shl(&base, 11));
        // One step: 2^(1/30), about 2.3 % easier.
        let one = relieved_target(&P, &base, 0, 240, &limit());
        assert!(one > base && one < shl(&base, 1));
    }

    #[test]
    fn monotone_and_clamped() {
        let base = bits_to_target(0x1B04_04CB);
        let mut prev = base;
        for dt in (0..200_000).step_by(37) {
            let t = relieved_target(&P, &base, 0, dt, &limit());
            assert!(t >= prev, "dt={dt}");
            assert!(t <= limit());
            prev = t;
        }
        assert_eq!(prev, limit());
        // A base above the limit (never produced by ASERT) is not made harder.
        let easy = bits_to_target(0x1E00_FFFF);
        assert_eq!(relieved_target(&P, &easy, 0, 100_000, &limit()), easy);
        // Extreme inputs do not panic.
        let _ = relieved_bits(&P, 0x1B04_04CB, i64::MIN, i64::MAX, &limit());
        let _ = relieved_bits(&P, 0x1B04_04CB, i64::MAX, i64::MIN, &limit());
        assert_eq!(relieved_bits(&P, 0xFF00_FFFF, 0, 100_000, &limit()), 0xFF00_FFFF);
    }
}
