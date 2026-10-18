//! Difficulty: compact `bits` ⇄ 256-bit target, chain work, and ASERT.
//!
//! The compact form follows Bitcoin's `nBits`: the high byte is a byte
//! exponent, the low 23 bits a mantissa, `target = mantissa << 8*(exp-3)`.
//! Decoding fails hard on every malformed encoding; the infallible wrapper
//! maps malformed bits to the zero target, which no output can meet.
//!
//! Retargeting is ASERT (absolutely scheduled exponentially rising targets,
//! the aserti3-2d construction): every block's target is computed from one
//! fixed anchor and the parent's timestamp, so there is no window to game
//! and no accumulated rounding drift.
//!
//! ```text
//! ahead    = parent_time - anchor_time - T * (height - anchor_height - 1)
//! exponent = floor(ahead * 65536 / halflife)           // 16.16 fixed point, rounds toward -inf
//! shifts   = floor(exponent / 65536),  frac = exponent mod 65536
//! factor   = 65536 + ((195766423245049*frac + 971821376*frac^2 + 5127*frac^3 + 2^47) >> 48)
//! target   = floor(anchor_target * factor * 2^(shifts - 16)),  clamped to [1, pow_limit]
//! ```
//!
//! `2^frac` for the fractional part uses the aserti3-2d cubic in 16-bit
//! fixed point; the product with the anchor target is exact and the net shift
//! is applied once, as in aserti3-2d. The normative executable definition is
//! `reference/gnb_difficulty.py`; `reference/difficulty_vectors.json` pins it
//! and `tests/difficulty_vectors.rs` checks this module against those vectors.

use core::cmp::Ordering;
use core::fmt;

/// A 256-bit target as 32 big-endian bytes. Valid iff `out < target`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Target(pub [u8; 32]);

impl Target {
    /// The largest target (easiest).
    pub const MAX: Target = Target([0xFF; 32]);
    /// The zero target. No output meets it; consensus never produces it.
    pub const ZERO: Target = Target([0x00; 32]);

    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Target(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl PartialOrd for Target {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Target {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0) // big-endian bytes compare as integers
    }
}

/// Why a compact `bits` value does not encode a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitsError {
    /// The sign bit (0x0080_0000) is set.
    NegativeFlag,
    /// The mantissa is zero.
    ZeroMantissa,
    /// The exponent shifts the mantissa out of the 256-bit range.
    ExponentOutOfRange { exponent: u32 },
    /// High mantissa bytes would spill past the top of the target.
    MantissaOverflow,
    /// The encoding rounds down to the zero target.
    ZeroTarget,
}

impl fmt::Display for BitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeFlag => f.write_str("compact bits has the negative flag set"),
            Self::ZeroMantissa => f.write_str("compact bits has a zero mantissa"),
            Self::ExponentOutOfRange { exponent } => {
                write!(f, "compact bits exponent {exponent} is out of the 256-bit range")
            }
            Self::MantissaOverflow => f.write_str("compact bits mantissa overflows 256 bits"),
            Self::ZeroTarget => f.write_str("compact bits encodes the zero target"),
        }
    }
}

impl std::error::Error for BitsError {}

/// Decode compact `bits`, rejecting every malformed or zero encoding.
pub fn try_bits_to_target(bits: u32) -> Result<Target, BitsError> {
    if bits & 0x0080_0000 != 0 {
        return Err(BitsError::NegativeFlag);
    }
    let exponent = bits >> 24;
    let mantissa = bits & 0x007F_FFFF;
    if mantissa == 0 {
        return Err(BitsError::ZeroMantissa);
    }
    let mut out = [0u8; 32];
    if exponent <= 3 {
        // Right shift drops low bytes: rounds the target down (harder).
        let m = mantissa >> (8 * (3 - exponent));
        out[29..32].copy_from_slice(&m.to_be_bytes()[1..4]);
    } else {
        let shift_bytes = (exponent - 3) as usize;
        if shift_bytes > 31 {
            return Err(BitsError::ExponentOutOfRange { exponent });
        }
        let low = 31 - shift_bytes; // where the lowest mantissa byte lands
        let m = mantissa.to_be_bytes(); // [0, b0, b1, b2]
        if (low < 2 && m[1] != 0) || (low < 1 && m[2] != 0) {
            return Err(BitsError::MantissaOverflow);
        }
        out[low] = m[3];
        if low >= 1 {
            out[low - 1] = m[2];
        }
        if low >= 2 {
            out[low - 2] = m[1];
        }
    }
    let t = Target(out);
    if t.is_zero() {
        return Err(BitsError::ZeroTarget);
    }
    Ok(t)
}

/// Infallible decode: malformed bits map to [`Target::ZERO`], which no block
/// can meet, so consensus fails closed.
pub fn bits_to_target(bits: u32) -> Target {
    try_bits_to_target(bits).unwrap_or(Target::ZERO)
}

/// Encode a target in compact form. Keeps the top three significant bytes,
/// so encode-then-decode rounds down (harder), never up.
pub fn target_to_bits(target: &Target) -> u32 {
    let b = &target.0;
    let Some(idx) = b.iter().position(|&x| x != 0) else {
        return 0;
    };
    let mut exponent = (32 - idx) as u32;
    let at = |k: usize| b.get(k).copied().unwrap_or(0) as u32;
    let mut mantissa = (at(idx) << 16) | (at(idx + 1) << 8) | at(idx + 2);
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }
    (exponent << 24) | (mantissa & 0x007F_FFFF)
}

/// `out < target`, both big-endian.
pub fn meets_target(out: &[u8; 32], target: &Target) -> bool {
    out < &target.0
}

/// Chain-work contribution of `target`: an approximation of the expected
/// number of evaluations, 2^256 / target. CONSENSUS DEFINITION (blue work is
/// the sum of these values), exactly:
///
/// ```text
/// work(target) = max(floor((2^128 - 1) / (floor(target / 2^128) + 1)), 1)   for 1 <= target < 2^256
/// work(0)      = 0
/// ```
///
/// This is the definition of `work` in the normative references
/// (`reference/gnb_smh.py`, `reference/gnb_difficulty.py`), pinned by
/// `reference/difficulty_vectors.json`. It is neither floor(2^256 / target)
/// nor Bitcoin Core's floor(2^256 / (target + 1)) (`GetBlockProof`): it never
/// exceeds either, falls short of the latter (`core`) by at most
/// core / floor(target / 2^128) + 2, i.e. by less than one part in 2^64 (plus
/// 2) for every target at or above 2^192, and is monotone (a harder target
/// never carries less work). Targets below 2^128 saturate at
/// `u128::MAX` = 2^128 - 1. The zero target (malformed bits) has work 0: it
/// never validates and must never add weight.
pub fn work(target: &Target) -> u128 {
    if target.is_zero() {
        return 0;
    }
    let idx = target.0.iter().position(|&x| x != 0).unwrap_or(31);
    if idx >= 16 {
        // target < 2^128: floor(target / 2^128) = 0, so the formula gives
        // (2^128 - 1) / 1 = u128::MAX.
        return u128::MAX;
    }
    // target >= 2^128: divide 2^128 - 1 by floor(target / 2^128) + 1 (the
    // top 16 bytes plus one); the sum overflows only for a top half of all
    // ones, where the quotient is 0 and the result is clamped to 1.
    let mut hi: u128 = 0;
    for &x in &target.0[..16] {
        hi = (hi << 8) | x as u128;
    }
    match hi.checked_add(1) {
        Some(d) => (u128::MAX / d).max(1),
        None => 1,
    }
}

/// Work for compact `bits`; malformed bits have work 0 (they never validate).
pub fn work_from_bits(bits: u32) -> u128 {
    work(&bits_to_target(bits))
}

// ── ASERT ────────────────────────────────────────────────────────────────────

/// ASERT parameters. All fields are consensus constants of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsertParams {
    /// Target spacing in seconds.
    pub target_spacing: i64,
    /// Half-life in seconds: an excess of one half-life over schedule halves
    /// the difficulty (doubles the target).
    pub halflife: i64,
    /// Easiest target the chain accepts. The result never exceeds it.
    pub pow_limit: Target,
}

/// Anchor of the schedule (the genesis block on GnB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsertAnchor {
    pub height: u64,
    pub bits: u32,
    /// Timestamp of the anchor block itself.
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsertError {
    /// `height` must be strictly above the anchor height.
    HeightNotAboveAnchor,
    /// The anchor bits do not decode to a target.
    InvalidAnchor(BitsError),
    /// A schedule intermediate overflowed i128.
    ArithmeticOverflow,
}

impl fmt::Display for AsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightNotAboveAnchor => f.write_str("ASERT height is not above the anchor"),
            Self::InvalidAnchor(e) => write!(f, "invalid ASERT anchor bits: {e}"),
            Self::ArithmeticOverflow => f.write_str("ASERT arithmetic overflow"),
        }
    }
}

impl std::error::Error for AsertError {}

/// Target for the block at `height` whose parent has timestamp `parent_time`.
///
/// On GnB the caller passes the latest timestamp among the block's parents
/// and `height = max(parent heights) + 1` (see `docs/CONSENSUS.md`); this
/// function itself is a pure function of its arguments.
pub fn asert_next_target(
    params: &AsertParams,
    anchor: &AsertAnchor,
    parent_time: i64,
    height: u64,
) -> Result<Target, AsertError> {
    if height <= anchor.height {
        return Err(AsertError::HeightNotAboveAnchor);
    }
    let anchor_target = try_bits_to_target(anchor.bits).map_err(AsertError::InvalidAnchor)?;

    // Blocks between the anchor and the parent, inclusive of the parent.
    let height_delta = (height - anchor.height - 1) as i128;
    let time_delta = parent_time as i128 - anchor.timestamp as i128;
    let schedule = (params.target_spacing as i128)
        .checked_mul(height_delta)
        .ok_or(AsertError::ArithmeticOverflow)?;
    let ahead = time_delta.checked_sub(schedule).ok_or(AsertError::ArithmeticOverflow)?;
    // Exponent in 1/65536 units: floor(ahead * 65536 / halflife), i.e. the
    // quotient rounded toward negative infinity (`div_euclid` with a positive
    // half-life). This is NOT the rounding of BCHN's aserti3-2d, whose C++ `/`
    // truncates toward zero: the two agree when `ahead * 65536` is >= 0 or a
    // multiple of the half-life, and otherwise GnB's exponent is one unit
    // (2^-16 of a half-life) lower, i.e. very slightly harder. GnB's rule is
    // pinned by `reference/gnb_difficulty.py` and its vectors.
    let exponent = (ahead.checked_mul(65_536).ok_or(AsertError::ArithmeticOverflow)?)
        .div_euclid(params.halflife as i128);

    let shifts = exponent >> 16; // floor
    let frac = (exponent & 0xFFFF) as u64; // 0..65535
    // 2^(frac/65536) * 65536, aserti3-2d cubic (max error < 0.013%).
    let factor: u64 = 65_536
        + ((195_766_423_245_049u128 * frac as u128
            + 971_821_376u128 * (frac as u128).pow(2)
            + 5_127u128 * (frac as u128).pow(3)
            + (1u128 << 47))
            >> 48) as u64;

    if shifts >= 256 {
        return Ok(params.pow_limit);
    }
    // aserti3-2d fixed-point step: multiply the full anchor target by the
    // 17-bit factor (exact, in 320 bits) and apply the net shift
    // `shifts - 16` once. No intermediate is truncated or saturated, so the
    // result is floor(anchor_target * factor * 2^(shifts - 16)) exactly; a
    // value of 2^256 or more is clamped to the pow limit like any other
    // value above it.
    //
    // (Before the 2026-10 audit fix AUD-1 the product was shifted right by 16
    // and saturated at 2^256 - 1 first, then shifted bit by bit. That
    // saturation made anchors at or above ~2^255 up to 2x too hard after a
    // negative shift. Below 2^255 nothing saturates: for `shifts <= 0` the two
    // orders give the same target (floors compose), and for `shifts > 0` they
    // differ only in bits below position `shifts`. The compact form keeps the
    // top 24 bits, which lie above that position whenever the anchor target is
    // at least 2^24, so for anchors in [2^24, 2^255) -- GnB's genesis anchor is
    // ~2^244 -- every compact `bits` value is unchanged. A tiny anchor (below
    // 2^24) now keeps fraction bits the old order discarded.)
    let product = mul_wide(&anchor_target.0, factor);
    let net = shifts - 16;
    let mut out = match shift_to_u256(&product, net) {
        Some(t) => Target(t),
        None => return Ok(params.pow_limit), // >= 2^256: above any pow limit
    };
    if out > params.pow_limit {
        out = params.pow_limit;
    }
    if out.is_zero() {
        let mut one = [0u8; 32];
        one[31] = 1;
        out = Target(one);
    }
    Ok(out)
}

/// Compact bits of [`asert_next_target`]. The compact round-down never
/// produces a target above the computed one.
pub fn asert_next_bits(
    params: &AsertParams,
    anchor: &AsertAnchor,
    parent_time: i64,
    height: u64,
) -> Result<u32, AsertError> {
    asert_next_target(params, anchor, parent_time, height).map(|t| target_to_bits(&t))
}

/// Number of 64-bit limbs of the ASERT intermediate: 320 bits hold
/// `target * factor` < 2^256 * 2^17.
pub(crate) const WIDE_LIMBS: usize = 5;

/// `t * factor` exactly, as little-endian 64-bit limbs. `factor` < 2^17.
pub(crate) fn mul_wide(t: &[u8; 32], factor: u64) -> [u64; WIDE_LIMBS] {
    let mut out = [0u64; WIDE_LIMBS];
    let mut carry: u128 = 0;
    for (i, limb) in out.iter_mut().take(4).enumerate() {
        // Limb i (little-endian) is big-endian bytes [32 - 8(i+1), 32 - 8i).
        let mut be = [0u8; 8];
        be.copy_from_slice(&t[32 - 8 * (i + 1)..32 - 8 * i]);
        let p = u64::from_be_bytes(be) as u128 * factor as u128 + carry;
        *limb = p as u64;
        carry = p >> 64;
    }
    out[4] = carry as u64;
    out
}

/// `floor(v * 2^net)` as a 256-bit big-endian integer, or `None` when the
/// result is 2^256 or more. A right shift of 320 bits or more yields zero.
pub(crate) fn shift_to_u256(v: &[u64; WIDE_LIMBS], net: i128) -> Option<[u8; 32]> {
    const BITS: i128 = 64 * WIDE_LIMBS as i128;
    let len = v
        .iter()
        .rposition(|&l| l != 0)
        .map_or(0, |i| 64 * i as i128 + 64 - v[i].leading_zeros() as i128);
    let mut r = [0u64; WIDE_LIMBS];
    if len == 0 || net <= -BITS {
        // Zero stays zero; a shift past every bit leaves nothing.
    } else if net >= 0 {
        if len + net > 256 {
            return None;
        }
        // len >= 1 and len + net <= 256, so 0 <= net <= 255.
        let (limbs, bits) = ((net / 64) as usize, (net % 64) as u32);
        for i in (limbs..WIDE_LIMBS).rev() {
            let src = i - limbs;
            let mut x = v[src] << bits;
            if bits != 0 && src >= 1 {
                x |= v[src - 1] >> (64 - bits);
            }
            r[i] = x;
        }
    } else {
        let s = -net; // 1..BITS-1
        let (limbs, bits) = ((s / 64) as usize, (s % 64) as u32);
        for i in 0..WIDE_LIMBS - limbs {
            let src = i + limbs;
            let mut x = v[src] >> bits;
            if bits != 0 && src + 1 < WIDE_LIMBS {
                x |= v[src + 1] << (64 - bits);
            }
            r[i] = x;
        }
    }
    if r[4] != 0 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, limb) in r.iter().take(4).enumerate() {
        out[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
    Some(out)
}

// ── Canonical compact encoding (audit POW-9) ────────────────────────────────
//
// `try_bits_to_target` keeps Bitcoin Core's `SetCompact` semantics: it decodes
// every well-formed encoding, canonical or not (17.7 M of the 268 M accepted
// values are non-canonical, e.g. `0x21007fff` and `0x207fff00` are the same
// target), exactly like Core, whose consensus then compares `nBits` with the
// expected value as a u32. These helpers name the canonical subset: the
// encodings `target_to_bits` produces. (Placed after the code above so its
// line numbers do not move.)

/// `true` iff `bits` decodes and is the encoding [`target_to_bits`] produces
/// for the target it decodes to (`target_to_bits(target(bits)) == bits`).
/// Every value [`target_to_bits`] returns for a non-zero target is canonical,
/// hence so is every expected `bits` of the difficulty schedule.
pub fn is_canonical_bits(bits: u32) -> bool {
    match try_bits_to_target(bits) {
        Ok(t) => target_to_bits(&t) == bits,
        Err(_) => false,
    }
}

/// [`try_bits_to_target`] restricted to canonical encodings
/// ([`is_canonical_bits`]): `None` for a malformed or a non-canonical value.
pub fn try_canonical_bits_to_target(bits: u32) -> Option<Target> {
    let t = try_bits_to_target(bits).ok()?;
    (target_to_bits(&t) == bits).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT_BITS: u32 = 0x2100_FFFF;

    /// In-place ×2; returns true on overflow.
    fn shl1(t: &mut [u8; 32]) -> bool {
        let mut carry = 0u8;
        for b in t.iter_mut().rev() {
            let v = ((*b as u16) << 1) | carry as u16;
            *b = v as u8;
            carry = (v >> 8) as u8;
        }
        carry != 0
    }

    /// In-place floor(÷2).
    fn shr1(t: &mut [u8; 32]) {
        let mut carry = 0u8;
        for b in t.iter_mut() {
            let v = ((carry as u16) << 8) | *b as u16;
            *b = (v >> 1) as u8;
            carry = (v & 1) as u8;
        }
    }

    /// The ASERT step as written before audit fix AUD-1: `(t * factor) >> 16`
    /// saturated at 2^256 - 1, then shifted one bit at a time. Kept only to
    /// prove that the fix leaves every compact result for anchors in
    /// [2^24, 2^255) (GnB's genesis anchor among them) unchanged.
    fn legacy_asert_bits(p: &AsertParams, a: &AsertAnchor, parent_time: i64, height: u64) -> u32 {
        let anchor_target = try_bits_to_target(a.bits).unwrap();
        let ahead = parent_time as i128
            - a.timestamp as i128
            - p.target_spacing as i128 * (height - a.height - 1) as i128;
        let exponent = (ahead * 65_536).div_euclid(p.halflife as i128);
        let shifts = exponent >> 16;
        let frac = (exponent & 0xFFFF) as u128;
        let factor = 65_536
            + ((195_766_423_245_049u128 * frac
                + 971_821_376u128 * frac.pow(2)
                + 5_127u128 * frac.pow(3)
                + (1u128 << 47))
                >> 48) as u64;
        let mut wide = [0u8; 35];
        let mut carry: u64 = 0;
        for i in (0..32).rev() {
            let v = anchor_target.0[i] as u64 * factor + carry;
            wide[i + 3] = v as u8;
            carry = v >> 8;
        }
        wide[2] = carry as u8;
        wide[1] = (carry >> 8) as u8;
        wide[0] = (carry >> 16) as u8;
        let mut t = [0xFFu8; 32];
        if wide[0] == 0 {
            t.copy_from_slice(&wide[1..33]);
        }
        if shifts >= 256 {
            return target_to_bits(&p.pow_limit);
        }
        if shifts > 0 {
            for _ in 0..shifts {
                if shl1(&mut t) {
                    return target_to_bits(&p.pow_limit);
                }
            }
        } else {
            for _ in 0..(-shifts).min(256) {
                shr1(&mut t);
            }
        }
        let mut out = Target(t);
        if out > p.pow_limit {
            out = p.pow_limit;
        }
        if out.is_zero() {
            out.0[31] = 1;
        }
        target_to_bits(&out)
    }

    fn params() -> AsertParams {
        AsertParams { target_spacing: 30, halflife: 7_200, pow_limit: bits_to_target(LIMIT_BITS) }
    }

    fn anchor() -> AsertAnchor {
        AsertAnchor { height: 0, bits: 0x1F00_FFFF, timestamp: 1_000_000 }
    }

    #[test]
    fn rejects_malformed_bits() {
        assert_eq!(try_bits_to_target(0x0480_0001), Err(BitsError::NegativeFlag));
        assert_eq!(try_bits_to_target(0x2000_0000), Err(BitsError::ZeroMantissa));
        assert_eq!(try_bits_to_target(0xFF00_FFFF), Err(BitsError::ExponentOutOfRange { exponent: 0xFF }));
        assert_eq!(try_bits_to_target(0x2201_0000), Err(BitsError::MantissaOverflow));
        assert_eq!(try_bits_to_target(0x0100_0001), Err(BitsError::ZeroTarget));
        assert_eq!(bits_to_target(0xFF00_FFFF), Target::ZERO);
    }

    /// Audit POW-9: the canonical subset is exactly the set of
    /// `target_to_bits` outputs; decoding stays Core-compatible.
    #[test]
    fn canonical_bits_are_the_encoder_outputs() {
        for (bits, canonical) in [
            (0x207F_FF00, true), (0x2100_7FFF, false), // same target
            (0x1F0E_9036, true), (0x2100_FFFF, true), (0x1D00_FFFF, true),
            (0x0201_0000, true), (0x0400_0001, false), // target 256 both
            (0x1F00_0E90, false), (0x1E0E_9000, true), // same target
            (0x0480_0001, false), (0x2000_0000, false), (0x0100_0001, false), (0, false),
        ] {
            assert_eq!(is_canonical_bits(bits), canonical, "{bits:#x}");
            assert_eq!(try_canonical_bits_to_target(bits).is_some(), canonical, "{bits:#x}");
            if canonical {
                assert_eq!(try_canonical_bits_to_target(bits), try_bits_to_target(bits).ok());
            }
        }
        assert_eq!(try_bits_to_target(0x2100_7FFF), try_bits_to_target(0x207F_FF00));
        assert_eq!(try_bits_to_target(0x0400_0001), try_bits_to_target(0x0201_0000));
        assert_eq!(try_bits_to_target(0x1F00_0E90), try_bits_to_target(0x1E0E_9000));
    }

    #[test]
    fn compact_round_trip() {
        for bits in [0x1D00_FFFF, 0x1F00_FFFF, 0x2000_FFFF, LIMIT_BITS, 0x1B04_04CB, 0x0300_7FFF] {
            if let Ok(t) = try_bits_to_target(bits) {
                assert_eq!(bits_to_target(target_to_bits(&t)), t, "bits {bits:#x}");
            }
        }
        let t = bits_to_target(LIMIT_BITS);
        assert_eq!(&t.0[..3], &[0xFF, 0xFF, 0x00]);
    }

    #[test]
    fn compact_encoding_rounds_down() {
        let mut t = [0u8; 32];
        t[10] = 0x12;
        t[11] = 0x34;
        t[12] = 0x56;
        t[13] = 0x78; // dropped by the compact form
        let r = bits_to_target(target_to_bits(&Target(t)));
        assert!(r < Target(t));
    }

    #[test]
    fn work_is_monotone_and_saturates() {
        let easy = work_from_bits(LIMIT_BITS);
        let hard = work_from_bits(0x1F00_FFFF);
        assert_eq!(easy, 1);
        assert!(hard > easy);
        assert_eq!(work_from_bits(0x1000_FFFF), u128::MAX);
        assert_eq!(work_from_bits(0xFF00_FFFF), 0);
    }

    #[test]
    fn asert_on_schedule_keeps_anchor_target() {
        let p = params();
        let a = anchor();
        for h in [1u64, 2, 100, 10_000] {
            let parent_time = a.timestamp + 30 * (h as i64 - 1);
            assert_eq!(asert_next_bits(&p, &a, parent_time, h).unwrap(), a.bits, "h={h}");
        }
    }

    #[test]
    fn asert_halflife_doubles_and_halves() {
        let p = params();
        let a = anchor();
        let base = bits_to_target(a.bits);
        let slow = asert_next_target(&p, &a, a.timestamp + 7_200, 1).unwrap();
        let mut doubled = base.0;
        assert!(!shl1(&mut doubled));
        assert_eq!(slow, Target(doubled));
        let fast = asert_next_target(&p, &a, a.timestamp - 7_200, 1).unwrap();
        let mut halved = base.0;
        shr1(&mut halved);
        assert_eq!(fast, Target(halved));
    }

    #[test]
    fn asert_fraction_is_monotone() {
        let p = params();
        let a = anchor();
        let mut prev = Target::ZERO;
        for dt in (0..7_200).step_by(97) {
            let t = asert_next_target(&p, &a, a.timestamp + dt, 1).unwrap();
            assert!(t >= prev);
            prev = t;
        }
    }

    #[test]
    fn asert_clamps_to_pow_limit_and_one() {
        let p = params();
        let a = anchor();
        let t = asert_next_target(&p, &a, a.timestamp + 10_000_000, 1).unwrap();
        assert_eq!(t, p.pow_limit);
        let t = asert_next_target(&p, &a, a.timestamp, 50_000_000).unwrap();
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(t, Target(one));
    }

    /// The pow-limit clamp also applies when the computed target is below
    /// 2^256 (the exact-shift path), not only when the shift overflows.
    #[test]
    fn asert_clamps_a_representable_target_above_the_limit() {
        let a = anchor();
        let p = AsertParams { pow_limit: bits_to_target(a.bits), ..params() };
        // One half-life behind schedule: the target doubles, above the limit.
        let t = asert_next_target(&p, &a, a.timestamp + 7_200, 1).unwrap();
        assert_eq!(t, p.pow_limit);
        // Exactly on schedule the anchor target IS the limit and is kept.
        assert_eq!(asert_next_target(&p, &a, a.timestamp, 1).unwrap(), p.pow_limit);
        // One half-life ahead: half the limit, untouched by the clamp.
        let mut half = p.pow_limit.0;
        shr1(&mut half);
        assert_eq!(asert_next_target(&p, &a, a.timestamp - 7_200, 1).unwrap(), Target(half));
    }

    #[test]
    fn meets_target_is_strict_big_endian() {
        let t = Target::from_be_bytes({
            let mut b = [0u8; 32];
            b[0] = 0x01;
            b
        });
        let mut below = [0xFFu8; 32];
        below[0] = 0x00;
        assert!(meets_target(&below, &t), "2^248 - 1 < 2^248");
        assert!(!meets_target(&t.0, &t), "equal is not below");
        let mut above = t.0;
        above[31] = 1;
        assert!(!meets_target(&above, &t));
        assert!(!meets_target(&[0u8; 32], &Target::ZERO), "nothing meets the zero target");
        assert!(meets_target(&[0u8; 32], &Target::MAX));
    }

    #[test]
    fn asert_rejects_bad_inputs() {
        let p = params();
        let a = anchor();
        assert_eq!(asert_next_bits(&p, &a, a.timestamp, 0), Err(AsertError::HeightNotAboveAnchor));
        let bad = AsertAnchor { bits: 0xFF00_FFFF, ..a };
        assert!(matches!(asert_next_bits(&p, &bad, a.timestamp, 1), Err(AsertError::InvalidAnchor(_))));
        // Extreme timestamps do not panic.
        let _ = asert_next_bits(&p, &a, i64::MIN, u64::MAX);
        let _ = asert_next_bits(&p, &a, i64::MAX, 1);
    }

    /// AUD-1: an anchor near the pow limit, eight half-lives behind schedule.
    /// The saturating legacy step returned 0x1f7fffff; the exact aserti3-2d
    /// arithmetic gives 0x2000a349.
    #[test]
    fn high_anchor_negative_shift_does_not_saturate() {
        let p = params();
        let a = AsertAnchor { bits: 0x2100_A34E, ..anchor() };
        let parent_time = a.timestamp - 57_601;
        assert_eq!(asert_next_bits(&p, &a, parent_time, 1).unwrap(), 0x2000_A349);
        assert_eq!(legacy_asert_bits(&p, &a, parent_time, 1), 0x1F7F_FFFF, "legacy saturated");
        // Anchor 2^255 exactly eight half-lives behind: 2^247, no saturation.
        let a = AsertAnchor { bits: 0x2100_8000, ..anchor() };
        let t = asert_next_target(&p, &a, a.timestamp - 8 * 7_200, 1).unwrap();
        let mut expect = [0u8; 32];
        expect[1] = 0x80;
        assert_eq!(t, Target(expect));
    }

    /// The fix changes no compact result for anchors in [2^24, 2^255): sweep
    /// the genesis anchor and others over heights and skews on both sides of
    /// the schedule, including both clamps.
    #[test]
    fn low_anchor_bits_match_legacy_order() {
        let p = params();
        // ~132,000 points natively; a coarse grid over the same ranges (132
        // points) under Miri, where the legacy bit-by-bit shifts make each
        // point ~0.45 s.
        let (height_step, skew_step) = if cfg!(miri) { (1_999_993, 799_999) } else { (99_991, 9_973) };
        for bits in [0x1F0E_9036u32, 0x1D00_FFFF, 0x2000_FFFF, 0x207F_FFFF] {
            let a = AsertAnchor { bits, ..anchor() };
            for height in (1u64..=4_000_001).step_by(height_step) {
                for skew in (-4_000_000i64..=4_000_000).step_by(skew_step) {
                    let parent_time = a.timestamp + 30 * (height as i64 - 1) + skew;
                    assert_eq!(
                        asert_next_bits(&p, &a, parent_time, height).unwrap(),
                        legacy_asert_bits(&p, &a, parent_time, height),
                        "anchor={bits:#x} height={height} skew={skew}"
                    );
                }
            }
        }
    }

    #[test]
    fn shift_to_u256_boundaries() {
        let one = [1u64, 0, 0, 0, 0];
        let bit = |n: usize| {
            let mut t = [0u8; 32];
            t[31 - n / 8] = 1 << (n % 8);
            t
        };
        assert_eq!(shift_to_u256(&one, 255), Some(bit(255)));
        assert_eq!(shift_to_u256(&one, 256), None);
        assert_eq!(shift_to_u256(&one, 0), Some(bit(0)));
        assert_eq!(shift_to_u256(&one, -1), Some([0u8; 32]));
        let high = [0, 0, 0, 0, 1u64]; // 2^256
        assert_eq!(shift_to_u256(&high, 0), None);
        assert_eq!(shift_to_u256(&high, -1), Some(bit(255)));
        assert_eq!(shift_to_u256(&high, -256), Some(bit(0)));
        assert_eq!(shift_to_u256(&high, -257), Some([0u8; 32]));
        assert_eq!(shift_to_u256(&high, -320), Some([0u8; 32]));
        assert_eq!(shift_to_u256(&high, i128::MIN / 2), Some([0u8; 32]));
        assert_eq!(shift_to_u256(&[0; 5], 1_000), Some([0u8; 32]));
        // Bits cross limb boundaries in both directions.
        let v = [0x8000_0000_0000_0001u64, 0x1, 0, 0, 0]; // 2^64 + 2^63 + 1
        let mut e = [0u8; 32];
        e[23] = 0x03; // 2^65 + 2^64
        e[31] = 0x02;
        assert_eq!(shift_to_u256(&v, 1), Some(e));
        let mut e = [0u8; 32];
        e[24] = 0xC0; // 2^63 + 2^62
        assert_eq!(shift_to_u256(&v, -1), Some(e));
    }

    #[test]
    fn target_accessors_round_trip() {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        let t = Target::from_be_bytes(b);
        assert_eq!(t, Target(b));
        assert_eq!(t.as_bytes(), &b);
        assert_eq!(Target::MAX.as_bytes(), &[0xFF; 32]);
        assert_eq!(Target::ZERO.as_bytes(), &[0x00; 32]);
    }

    /// Error texts reach node logs and RPC rejections; pin them.
    #[test]
    fn error_messages() {
        assert_eq!(BitsError::NegativeFlag.to_string(), "compact bits has the negative flag set");
        assert_eq!(BitsError::ZeroMantissa.to_string(), "compact bits has a zero mantissa");
        assert_eq!(
            BitsError::ExponentOutOfRange { exponent: 0xFF }.to_string(),
            "compact bits exponent 255 is out of the 256-bit range"
        );
        assert_eq!(BitsError::MantissaOverflow.to_string(), "compact bits mantissa overflows 256 bits");
        assert_eq!(BitsError::ZeroTarget.to_string(), "compact bits encodes the zero target");
        assert_eq!(AsertError::HeightNotAboveAnchor.to_string(), "ASERT height is not above the anchor");
        assert_eq!(
            AsertError::InvalidAnchor(BitsError::ZeroMantissa).to_string(),
            "invalid ASERT anchor bits: compact bits has a zero mantissa"
        );
        assert_eq!(AsertError::ArithmeticOverflow.to_string(), "ASERT arithmetic overflow");
    }

    #[test]
    fn mul_wide_is_exact() {
        // (2^256 - 1)(2^17 - 1) = 2^273 - 2^256 - 2^17 + 1
        let max = mul_wide(&[0xFF; 32], 131_071);
        assert_eq!(max[4], (1u64 << 17) - 2);
        assert_eq!(max[3], u64::MAX);
        assert_eq!(max[2], u64::MAX);
        assert_eq!(max[1], u64::MAX);
        assert_eq!(max[0], (1u64 << 17).wrapping_neg() + 1);
    }
}
