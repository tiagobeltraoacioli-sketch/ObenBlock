//! SHA-256d proof of work over an 80-byte, Bitcoin-ASIC-compatible header
//! (ObenBlock, docs/DESIGN-obenblock.md §4). Not used by GnB, which stays on
//! GnB-SMH; a chain selects this scheme explicitly
//! (`gnb_crypto::core::pow_scheme`).
//!
//! ```text
//! pow_header = u32le(version) ‖ parents_commitment ‖ merkle_root
//!            ‖ u32le(time) ‖ u32le(bits) ‖ u32le(nonce)                  80 bytes
//! parents_commitment = SHA-256d("OBB-PARENTS-v1" ‖ u32le(n) ‖ parent_0 ‖ … ‖ parent_{n-1})
//! block_id   = SHA-256d(pow_header)
//! valid     <=> le256(block_id) <= target(bits),   1 <= target
//! work       = floor(2^256 / (target + 1))                     (Bitcoin's GetBlockProof)
//! ```
//!
//! The layout is Bitcoin's block header with `hashPrevBlock` replaced by the
//! commitment to the DAG parent list, so an unmodified SHA-256d ASIC and its
//! stratum firmware mine it: the 32-bit nonce, BIP 320 version rolling
//! ([`BIP320_VERSION_MASK`]) and an extranonce in the coinbase (which changes
//! `merkle_root`). The comparison is Bitcoin's (`hash <= target`, the hash read
//! as a little-endian integer), unlike GnB-SMH (`be256(out) < target`).
//!
//! The normative executable definition is `reference/obb_pow.py`;
//! `reference/obb_pow_vectors.json` pins it and `tests/vectors_sha256d.rs`
//! checks this module against those vectors (including Bitcoin's genesis
//! header, which this serialization reproduces byte for byte).

use sha2::{Digest, Sha256};

use crate::difficulty::{try_bits_to_target, Target};

/// Length of the serialized proof-of-work header.
pub const POW_HEADER_LEN: usize = 80;

/// Domain-separation tag of the parent-list commitment.
pub const PARENTS_TAG: &[u8] = b"OBB-PARENTS-v1";

/// Easiest target of the SHA-256d scheme on ObenBlock mainnet: Bitcoin's
/// `0x1d00ffff` (difficulty 1, about 2^32 hashes per block).
pub const POW_LIMIT_BITS: u32 = 0x1D00_FFFF;

/// BIP 320: the version bits a miner may roll freely (bits 13 to 28). Every
/// other bit of a header's `version` must equal the chain's block version.
pub const BIP320_VERSION_MASK: u32 = 0x1FFF_E000;

/// SHA-256(SHA-256(data)).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// `SHA-256d("OBB-PARENTS-v1" ‖ u32le(n) ‖ parent_0 ‖ … ‖ parent_{n-1})` over
/// the parents in the order given. Validity of the list itself (sorted
/// strictly ascending, at most the chain's maximum) is [`check_parents`].
///
/// Panics if the list has more than `u32::MAX` entries; consensus bounds it to
/// a few hundred long before (`check_parents`, and the wire decoder).
pub fn parents_commitment(parents: &[[u8; 32]]) -> [u8; 32] {
    let n = u32::try_from(parents.len()).expect("parent list longer than u32::MAX");
    let mut h = Sha256::new();
    h.update(PARENTS_TAG);
    h.update(n.to_le_bytes());
    for p in parents {
        h.update(p);
    }
    Sha256::digest(h.finalize()).into()
}

/// Why a parent list is not canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParentsError {
    /// More than the chain's maximum number of parents.
    TooMany,
    /// Two entries are equal.
    Duplicate,
    /// The entries are not in ascending byte order.
    NotSorted,
}

impl core::fmt::Display for ParentsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooMany => "too many parents",
            Self::Duplicate => "duplicate parent",
            Self::NotSorted => "parents not sorted ascending",
        })
    }
}

impl std::error::Error for ParentsError {}

/// The canonical form of a parent list: at most `max_parents` entries, in
/// strictly ascending byte order (so no duplicates). The order is unique, so a
/// parent set has exactly one commitment and one block id. The emptiness of
/// the list (genesis only) is the caller's rule.
pub fn check_parents(parents: &[[u8; 32]], max_parents: usize) -> Result<(), ParentsError> {
    if parents.len() > max_parents {
        return Err(ParentsError::TooMany);
    }
    for w in parents.windows(2) {
        match w[0].cmp(&w[1]) {
            core::cmp::Ordering::Less => {}
            core::cmp::Ordering::Equal => return Err(ParentsError::Duplicate),
            core::cmp::Ordering::Greater => return Err(ParentsError::NotSorted),
        }
    }
    Ok(())
}

/// The six fields of the 80-byte header, in serialization order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PowHeader {
    pub version: u32,
    pub parents_commitment: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl PowHeader {
    /// The 80-byte serialization (Bitcoin's header layout).
    pub fn to_bytes(&self) -> [u8; POW_HEADER_LEN] {
        let mut b = [0u8; POW_HEADER_LEN];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.parents_commitment);
        b[36..68].copy_from_slice(&self.merkle_root);
        b[68..72].copy_from_slice(&self.time.to_le_bytes());
        b[72..76].copy_from_slice(&self.bits.to_le_bytes());
        b[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    /// Inverse of [`PowHeader::to_bytes`] (every 80-byte string is a header).
    pub fn from_bytes(b: &[u8; POW_HEADER_LEN]) -> Self {
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        PowHeader {
            version: u32_at(0),
            parents_commitment: b[4..36].try_into().unwrap(),
            merkle_root: b[36..68].try_into().unwrap(),
            time: u32_at(68),
            bits: u32_at(72),
            nonce: u32_at(76),
        }
    }

    /// `SHA-256d(to_bytes())`: the block id and the proof-of-work hash.
    pub fn id(&self) -> [u8; 32] {
        block_id(&self.to_bytes())
    }
}

/// `SHA-256d(pow_header)`, as raw digest bytes (Bitcoin's internal byte
/// order; Bitcoin displays it reversed).
pub fn block_id(pow_header: &[u8; POW_HEADER_LEN]) -> [u8; 32] {
    sha256d(pow_header)
}

/// The id read as a little-endian 256-bit integer, as a big-endian
/// [`Target`]-ordered value (the bytes reversed).
pub fn id_as_target_order(id: &[u8; 32]) -> Target {
    let mut be = *id;
    be.reverse();
    Target(be)
}

/// `le256(id) <= target`. A zero target never validates (consensus never
/// produces it; malformed bits decode to it).
pub fn meets_target(id: &[u8; 32], target: &Target) -> bool {
    !target.is_zero() && id_as_target_order(id) <= *target
}

/// Consensus proof check of one serialized header against its own `bits`
/// field: the bits decode (any well-formed encoding; canonicality and the pow
/// limit are the caller's rules, checked first) and the id meets the target.
pub fn verify_header(pow_header: &[u8; POW_HEADER_LEN]) -> bool {
    let bits = u32::from_le_bytes(pow_header[72..76].try_into().unwrap());
    match try_bits_to_target(bits) {
        Ok(t) => meets_target(&block_id(pow_header), &t),
        Err(_) => false,
    }
}

/// BIP 320 version rule: outside [`BIP320_VERSION_MASK`] the header version
/// equals `block_version`, which itself has no bit inside the mask.
pub fn version_ok(version: u32, block_version: u32) -> bool {
    block_version & BIP320_VERSION_MASK == 0 && version & !BIP320_VERSION_MASK == block_version
}

// ── Work ────────────────────────────────────────────────────────────────────

/// A 256-bit unsigned integer as (high, low) 128-bit halves.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    fn from_target(t: &Target) -> Self {
        U256 {
            hi: u128::from_be_bytes(t.0[..16].try_into().unwrap()),
            lo: u128::from_be_bytes(t.0[16..].try_into().unwrap()),
        }
    }

    fn to_target(self) -> Target {
        let mut b = [0u8; 32];
        b[..16].copy_from_slice(&self.hi.to_be_bytes());
        b[16..].copy_from_slice(&self.lo.to_be_bytes());
        Target(b)
    }

    fn is_zero(self) -> bool {
        self.hi == 0 && self.lo == 0
    }

    fn wrapping_sub(self, o: U256) -> U256 {
        let (lo, borrow) = self.lo.overflowing_sub(o.lo);
        let hi = self.hi.wrapping_sub(o.hi).wrapping_sub(borrow as u128);
        U256 { hi, lo }
    }

    fn checked_add_one(self) -> Option<U256> {
        let (lo, carry) = self.lo.overflowing_add(1);
        let hi = self.hi.checked_add(carry as u128)?;
        Some(U256 { hi, lo })
    }

    /// (self << 1, the bit shifted out).
    fn shl1(self) -> (U256, bool) {
        let out = self.hi >> 127 == 1;
        (U256 { hi: (self.hi << 1) | (self.lo >> 127), lo: self.lo << 1 }, out)
    }

    fn bit(self, i: u32) -> bool {
        if i >= 128 {
            (self.hi >> (i - 128)) & 1 == 1
        } else {
            (self.lo >> i) & 1 == 1
        }
    }

    fn set_bit(&mut self, i: u32) {
        if i >= 128 {
            self.hi |= 1 << (i - 128);
        } else {
            self.lo |= 1 << i;
        }
    }

    /// `floor(n / d)` and `n mod d` by restoring long division; `d != 0`.
    fn div_rem(n: U256, d: U256) -> (U256, U256) {
        debug_assert!(!d.is_zero());
        let mut q = U256 { hi: 0, lo: 0 };
        let mut r = U256 { hi: 0, lo: 0 };
        for i in (0..256).rev() {
            // r < d before the shift, so 2r + 1 < 2d < 2^257: the shifted-out
            // bit, when set, means r >= 2^256 > d.
            let (mut s, carry) = r.shl1();
            if n.bit(i) {
                s.lo |= 1;
            }
            if carry || s >= d {
                s = s.wrapping_sub(d);
                q.set_bit(i);
            }
            r = s;
        }
        (q, r)
    }
}

/// Chain work of a SHA-256d block with `target`: Bitcoin's
/// `floor(2^256 / (target + 1))` exactly, computed as Bitcoin Core does,
/// `floor(~target / (target + 1)) + 1`.
///
/// The value fits in u128 for every target at or above 2^128 (it is then at
/// most 2^128 - 1, except 2^128 for `target = 2^128 - 1`). A target below
/// that, which needs more than 2^128 expected hashes per block and lies about
/// 2^96 times below Bitcoin's pow limit, saturates at `u128::MAX`, like
/// GnB's work. The zero target (malformed bits) has work 0: it never
/// validates and must never add weight.
pub fn work(target: &Target) -> u128 {
    let t = U256::from_target(target);
    if t.is_zero() {
        return 0;
    }
    let Some(d) = t.checked_add_one() else {
        return 1; // target = 2^256 - 1: floor(2^256 / 2^256)
    };
    if d.hi == 0 || (d.hi == 1 && d.lo == 0) {
        // d <= 2^128: the quotient is at least 2^128.
        return u128::MAX;
    }
    let not_t = U256 { hi: !t.hi, lo: !t.lo };
    let (q, _) = U256::div_rem(not_t, d);
    // d > 2^128, so q < 2^128 and q + 1 <= 2^128 - 1 + 1; q + 1 = 2^128 is
    // impossible here (it needs d <= 2^128).
    debug_assert_eq!(q.hi, 0);
    q.lo + 1
}

/// [`work`] of compact `bits`; malformed bits have work 0.
pub fn work_from_bits(bits: u32) -> u128 {
    work(&crate::difficulty::bits_to_target(bits))
}

/// The target whose expected number of hashes per block is
/// `hashrate_hps × spacing_secs`, i.e. the largest `t` with
/// `work(t) >= hashes`: `t = floor(2^256 / hashes) - 1` (at least 1). The
/// launch difficulty of a chain is `target_to_bits` of it (rounded down,
/// harder). `hashes = 0` returns [`Target::MAX`].
pub fn target_for_hashes(hashrate_hps: u128, spacing_secs: u64) -> Target {
    let Some(hashes) = hashrate_hps.checked_mul(spacing_secs as u128) else {
        // More than 2^128 hashes per block: the hardest representable work.
        let mut one = [0u8; 32];
        one[31] = 1;
        return Target(one);
    };
    if hashes <= 1 {
        return Target::MAX;
    }
    // floor(2^256 / h) = floor((2^256 - 1) / h) unless h divides 2^256, i.e.
    // h is a power of two, where it is one more.
    let max = U256 { hi: u128::MAX, lo: u128::MAX };
    let (mut q, r) = U256::div_rem(max, U256 { hi: 0, lo: hashes });
    if r.lo == hashes - 1 && r.hi == 0 {
        q = q.checked_add_one().expect("2^256 / h < 2^256 for h >= 2");
    }
    let t = q.wrapping_sub(U256 { hi: 0, lo: 1 });
    if t.is_zero() {
        let mut one = [0u8; 32];
        one[31] = 1;
        return Target(one);
    }
    t.to_target()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty::{bits_to_target, target_to_bits};

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (k, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * k..2 * k + 2], 16).unwrap();
        }
        out
    }

    fn rev(mut b: [u8; 32]) -> [u8; 32] {
        b.reverse();
        b
    }

    /// Bitcoin's genesis header, with `hashPrevBlock` (zero) in the
    /// commitment slot: same bytes, same id, valid at `0x1d00ffff`.
    #[test]
    fn bitcoin_genesis_header_reproduces() {
        let h = PowHeader {
            version: 1,
            parents_commitment: [0u8; 32],
            merkle_root: rev(hex32("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")),
            time: 1_231_006_505,
            bits: 0x1D00_FFFF,
            nonce: 2_083_236_893,
        };
        let id = h.id();
        assert_eq!(rev(id), hex32("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        assert!(verify_header(&h.to_bytes()));
        assert_eq!(PowHeader::from_bytes(&h.to_bytes()), h);
        let mut bad = h;
        bad.nonce += 1;
        assert!(!verify_header(&bad.to_bytes()));
    }

    #[test]
    fn comparison_is_little_endian_and_inclusive() {
        let target = Target(hex32("00000000ffff0000000000000000000000000000000000000000000000000000"));
        let at = rev(target.0); // le256(at) == target
        assert!(meets_target(&at, &target), "hash == target is valid (Bitcoin's <=)");
        let mut above = at;
        above[0] = 1; // le256 = target + 1
        assert!(!meets_target(&above, &target));
        assert!(!meets_target(&[0u8; 32], &Target::ZERO), "zero target never validates");
        assert!(meets_target(&[0u8; 32], &target));
    }

    #[test]
    fn work_matches_bitcoin_core() {
        // GetBlockProof at difficulty 1: 0x100010001.
        assert_eq!(work_from_bits(0x1D00_FFFF), 0x1_0001_0001);
        assert_eq!(work(&Target::ZERO), 0);
        assert_eq!(work(&Target::MAX), 1);
        let mut half = [0u8; 32];
        half[0] = 0x80; // 2^255: floor(2^256 / (2^255 + 1)) = 1
        assert_eq!(work(&Target(half)), 1);
        let mut t = [0u8; 32];
        t[15] = 1; // 2^128
        assert_eq!(work(&Target(t)), u128::MAX, "floor(2^256 / (2^128 + 1)) = 2^128 - 1");
        t[15] = 0;
        t[16..].copy_from_slice(&[0xFF; 16]); // 2^128 - 1: work 2^128, saturates
        assert_eq!(work(&Target(t)), u128::MAX);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(work(&Target(one)), u128::MAX);
        assert_eq!(work_from_bits(0), 0, "malformed bits");
    }

    #[test]
    fn work_is_monotone_on_compact_targets() {
        let mut prev = 0u128;
        // Easiest to hardest: exponent down, mantissa down.
        for exp in (17u32..=0x20).rev() {
            for mant in [0x7F_FFFFu32, 0x40_0000, 0x00_8000] {
                let w = work_from_bits((exp << 24) | mant);
                assert!(w >= prev, "work must not fall as the target falls");
                prev = w;
            }
        }
    }

    #[test]
    fn target_for_hashes_inverts_work() {
        for (rate, spacing) in [(1u128, 30u64), (7, 30), (1 << 20, 30), (1_000_000_000_000_000_000, 30), (3, 1)] {
            let t = target_for_hashes(rate, spacing);
            let hashes = rate * spacing as u128;
            assert!(work(&t) >= hashes, "t is hard enough");
            let t1 = U256::from_target(&t).checked_add_one().unwrap().to_target();
            assert!(work(&t1) < hashes, "t is the largest such target");
        }
        // Powers of two divide 2^256 exactly.
        let t = target_for_hashes(1 << 32, 1);
        let mut want = [0u8; 32];
        want[4..].copy_from_slice(&[0xFF; 28]); // 2^224 - 1
        assert_eq!(t, Target(want));
        assert_eq!(target_for_hashes(0, 30), Target::MAX);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(target_for_hashes(u128::MAX, 2), Target(one));
    }

    #[test]
    fn parents_rules() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(check_parents(&[a, b], 2), Ok(()));
        assert_eq!(check_parents(&[], 0), Ok(()));
        assert_eq!(check_parents(&[a, b], 1), Err(ParentsError::TooMany));
        assert_eq!(check_parents(&[b, a], 2), Err(ParentsError::NotSorted));
        assert_eq!(check_parents(&[a, a], 2), Err(ParentsError::Duplicate));
        assert_ne!(parents_commitment(&[a, b]), parents_commitment(&[b, a]));
        assert_ne!(parents_commitment(&[]), parents_commitment(&[[0u8; 32]]));
    }

    #[test]
    fn bip320_version_rolling() {
        let base = 0x2000_0000;
        assert!(version_ok(base, base));
        assert!(version_ok(base | BIP320_VERSION_MASK, base));
        assert!(version_ok(base | 0x0000_2000, base));
        assert!(!version_ok(base | 0x0000_1000, base), "bit 12 is not rollable");
        assert!(!version_ok(base | 0x4000_0000, base), "bit 30");
        assert!(!version_ok(1, base));
        assert!(!version_ok(0x2000_2000, 0x2000_2000), "a base version inside the mask");
    }

    #[test]
    fn pow_limit_round_trips() {
        assert_eq!(target_to_bits(&bits_to_target(POW_LIMIT_BITS)), POW_LIMIT_BITS);
    }
}
