//! Proof-of-work scheme selector: GnB-SMH (GnB) or SHA-256d (ObenBlock,
//! docs/DESIGN-obenblock.md §4).
//!
//! The scheme is a process-wide consensus input, set once at node startup
//! from the chain the node runs ([`set_node_pow_scheme`]), like the chain id.
//! It defaults to [`PowScheme::GnbSmh`], under which every function of
//! `core` behaves exactly as before this module existed: GnB's chain rules,
//! vectors and legacy regimes are untouched. Under [`PowScheme::Sha256d`]:
//!
//! * `Block::block_hash` is the SHA-256d of the 80-byte header
//!   ([`BlockHeader::sha256d_block_id`]), which is also the PoW hash;
//! * `Block::validate_pow` is [`check_sha256d_pow`]: the header fits the
//!   80-byte layout (u32 time and nonce), BIP 320 version, canonical parent
//!   list, canonical `bits` at or below the pow limit, `le256(id) <= target`;
//! * `block_work` is Bitcoin's `floor(2^256 / (target + 1))`, with no
//!   GnB-SMH shift (`POW_V3_DIFFICULTY_SHIFT`);
//! * `expected_bits` is ASERT (30 s, half-life 2 h) anchored at the genesis
//!   block, clamped to the scheme's pow limit, at every height (no hardening
//!   switch: ObenBlock applies its rules from genesis).
//!
//! The executable reference is `reference/obb_pow.py`; its vectors
//! (`reference/obb_pow_vectors.json`) are checked by
//! `crates/gnb-crypto/tests/obb_pow_vectors.rs` and
//! `crates/gnb-smh/tests/vectors_sha256d.rs`.
//!
//! Choices this module makes where the design is silent (all conservative):
//! * regtest pow limit `0x207fffff` (Bitcoin regtest's), so a CPU can mine it;
//!   mainnet is `0x1d00ffff` as specified;
//! * block version `0x20000000` (Bitcoin's BIP 9 base, which ASIC firmware and
//!   pool software expect); BIP 320 bits 13 to 28 roll on top of it;
//! * a header whose u64 `timestamp` or `nonce` does not fit u32 is invalid,
//!   and its id is a SHA-256d over a tagged, longer-than-80-byte preimage, so
//!   it can never equal the id of a valid header;
//! * launch bits are `target_to_bits(floor(2^256 / (LAUNCH_HASHRATE_HPS * 30)) - 1)`,
//!   pinned as [`OBB_LAUNCH_BITS`].

use std::sync::OnceLock;

use gnb_smh::difficulty::{self, AsertAnchor, AsertParams, Target};
use gnb_smh::sha256d::{self, ParentsError, PowHeader};

use super::{pow_cache, Block, BlockHeader, ASERT_HALFLIFE_SECS, MAX_PARENTS, TARGET_BLOCK_TIME};

// ── ObenBlock constants ─────────────────────────────────────────────────────

/// Mainnet pow limit: Bitcoin's `0x1d00ffff`.
pub const OBB_POW_LIMIT_BITS: u32 = sha256d::POW_LIMIT_BITS;
/// Regtest pow limit: Bitcoin regtest's `0x207fffff` (about two hashes per block).
pub const OBB_REGTEST_POW_LIMIT_BITS: u32 = 0x207F_FFFF;
/// SHA-256d hashrate the launch difficulty assumes: 1 EH/s (§4.2 "start high").
pub const LAUNCH_HASHRATE_HPS: u128 = 1_000_000_000_000_000_000;
/// Genesis (and ASERT anchor) bits of ObenBlock mainnet: the target of
/// [`LAUNCH_HASHRATE_HPS`] at 30 s blocks, rounded down by the compact
/// encoding (work 30,000,392,575,492,696,099, about 1 EH/s).
pub const OBB_LAUNCH_BITS: u32 = 0x1900_9D69;
/// Block version; BIP 320 lets miners roll bits 13 to 28 on top of it.
pub const OBB_BLOCK_VERSION: u32 = 0x2000_0000;
/// Slow start (§4.2): the subsidy ramps from 0 to full over these blocks.
pub const SLOW_START_BLOCKS: u64 = 5_760;

/// Consensus parameters of the SHA-256d scheme for one chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sha256dParams {
    /// Easiest compact target the chain accepts.
    pub pow_limit_bits: u32,
    /// Bits of the genesis block, which anchors ASERT.
    pub genesis_bits: u32,
    /// Timestamp of the genesis block (the ASERT anchor time).
    pub genesis_timestamp: u64,
    /// Header version outside the BIP 320 rolling mask.
    pub block_version: u32,
}

impl Sha256dParams {
    /// ObenBlock mainnet with the genesis timestamp of its genesis block
    /// (package O6c fixes it).
    pub const fn obenblock_mainnet(genesis_timestamp: u64) -> Self {
        Sha256dParams {
            pow_limit_bits: OBB_POW_LIMIT_BITS,
            genesis_bits: OBB_LAUNCH_BITS,
            genesis_timestamp,
            block_version: OBB_BLOCK_VERSION,
        }
    }

    /// ObenBlock regtest: the genesis target is the (easy) pow limit.
    pub const fn obenblock_regtest(genesis_timestamp: u64) -> Self {
        Sha256dParams {
            pow_limit_bits: OBB_REGTEST_POW_LIMIT_BITS,
            genesis_bits: OBB_REGTEST_POW_LIMIT_BITS,
            genesis_timestamp,
            block_version: OBB_BLOCK_VERSION,
        }
    }

    pub fn pow_limit(&self) -> Target {
        difficulty::bits_to_target(self.pow_limit_bits)
    }

    /// ASERT as on GnB (30 s spacing, 2 h half-life), clamped to this pow limit.
    pub fn asert_params(&self) -> AsertParams {
        AsertParams {
            target_spacing: TARGET_BLOCK_TIME as i64,
            halflife: ASERT_HALFLIFE_SECS,
            pow_limit: self.pow_limit(),
        }
    }

    /// The ASERT anchor: the genesis block.
    pub fn asert_anchor(&self) -> AsertAnchor {
        AsertAnchor { height: 0, bits: self.genesis_bits, timestamp: self.genesis_timestamp as i64 }
    }

    /// Expected `bits` of a block at `height` (>= 1) whose parents' latest
    /// timestamp is `parent_timestamp` (`difficulty_parent_timestamp`).
    /// Always canonical (`target_to_bits`).
    pub fn expected_bits(&self, parent_timestamp: u64, height: u64) -> Result<u32, String> {
        let parent_time = i64::try_from(parent_timestamp)
            .map_err(|_| format!("parent timestamp {parent_timestamp} out of range"))?;
        if i64::try_from(self.genesis_timestamp).is_err() {
            return Err(format!("genesis timestamp {} out of range", self.genesis_timestamp));
        }
        difficulty::asert_next_bits(&self.asert_params(), &self.asert_anchor(), parent_time, height)
            .map_err(|e| e.to_string())
    }
}

/// The proof-of-work scheme of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PowScheme {
    /// GnB-SMH v1/v3 (by height, `core::pow_algo`): GnB.
    GnbSmh,
    /// SHA-256d over the 80-byte header: ObenBlock.
    Sha256d(Sha256dParams),
}

impl PowScheme {
    pub fn name(&self) -> &'static str {
        match self {
            PowScheme::GnbSmh => "gnb-smh",
            PowScheme::Sha256d(_) => "sha256d",
        }
    }

    pub fn sha256d_params(&self) -> Option<Sha256dParams> {
        match self {
            PowScheme::GnbSmh => None,
            PowScheme::Sha256d(p) => Some(*p),
        }
    }
}

static NODE_POW_SCHEME: OnceLock<PowScheme> = OnceLock::new();

/// Set the process-wide PoW scheme (once, at startup, before any block is
/// hashed). Idempotent for the same value; `Err(existing)` otherwise.
pub fn set_node_pow_scheme(scheme: PowScheme) -> Result<(), PowScheme> {
    match NODE_POW_SCHEME.set(scheme) {
        Ok(()) => Ok(()),
        Err(_) => {
            let cur = *NODE_POW_SCHEME.get().expect("OnceLock set");
            if cur == scheme { Ok(()) } else { Err(cur) }
        }
    }
}

/// The process-wide PoW scheme; [`PowScheme::GnbSmh`] until set.
pub fn node_pow_scheme() -> PowScheme {
    NODE_POW_SCHEME.get().copied().unwrap_or(PowScheme::GnbSmh)
}

/// The SHA-256d parameters when the process runs the SHA-256d scheme.
#[inline]
pub fn node_sha256d_params() -> Option<Sha256dParams> {
    NODE_POW_SCHEME.get().and_then(PowScheme::sha256d_params)
}

// ── The header under SHA-256d ───────────────────────────────────────────────

/// Why a header fails the SHA-256d proof-of-work rules (in check order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha256dHeaderError {
    /// `timestamp` does not fit u32.
    TimeOutOfRange,
    /// `nonce` does not fit u32.
    NonceOutOfRange,
    /// The version differs from the block version outside the BIP 320 mask.
    Version,
    /// The parent list is not canonical.
    Parents(ParentsError),
    /// `bits` is malformed or not the canonical encoding.
    BitsNotCanonical,
    /// The target is easier than the pow limit.
    AbovePowLimit,
    /// The block id does not meet the target.
    InsufficientWork,
}

impl std::fmt::Display for Sha256dHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeOutOfRange => f.write_str("timestamp does not fit u32"),
            Self::NonceOutOfRange => f.write_str("nonce does not fit u32"),
            Self::Version => f.write_str("version outside the BIP 320 rolling mask"),
            Self::Parents(e) => write!(f, "parent list: {e}"),
            Self::BitsNotCanonical => f.write_str("bits malformed or not canonical"),
            Self::AbovePowLimit => f.write_str("target above the pow limit"),
            Self::InsufficientWork => f.write_str("block id above the target"),
        }
    }
}

impl std::error::Error for Sha256dHeaderError {}

/// Tag of the id of a header that does not fit the 80-byte layout.
const NONCANONICAL_ID_TAG: &[u8] = b"OBB-NONCANONICAL-HEADER-v1";

impl BlockHeader {
    /// The six fields of the 80-byte header: the parent commitment is over
    /// `parents` in header order (canonical order is checked separately).
    pub fn sha256d_pow_header(&self) -> Result<PowHeader, Sha256dHeaderError> {
        let time = u32::try_from(self.timestamp).map_err(|_| Sha256dHeaderError::TimeOutOfRange)?;
        let nonce = u32::try_from(self.nonce).map_err(|_| Sha256dHeaderError::NonceOutOfRange)?;
        Ok(PowHeader {
            version: self.version,
            parents_commitment: sha256d::parents_commitment(&self.parents),
            merkle_root: self.merkle_root.0,
            time,
            bits: self.bits,
            nonce,
        })
    }

    /// The 80-byte serialization an ASIC hashes.
    pub fn sha256d_pow_bytes(&self) -> Result<[u8; sha256d::POW_HEADER_LEN], Sha256dHeaderError> {
        self.sha256d_pow_header().map(|h| h.to_bytes())
    }

    /// Block id under SHA-256d: `SHA-256d(pow_header)`. A header whose time
    /// or nonce does not fit u32 is invalid; its id is
    /// `SHA-256d(tag ‖ pow_preimage ‖ u64le(nonce))`, a preimage longer than
    /// 80 bytes, so it cannot collide with a valid id.
    pub fn sha256d_block_id(&self) -> [u8; 32] {
        match self.sha256d_pow_header() {
            Ok(h) => h.id(),
            Err(_) => {
                let mut b = NONCANONICAL_ID_TAG.to_vec();
                b.extend_from_slice(&self.pow_preimage());
                b.extend_from_slice(&self.nonce.to_le_bytes());
                sha256d::sha256d(&b)
            }
        }
    }
}

/// Every SHA-256d proof-of-work rule of one header, cheap ones first. That
/// `bits` equals the expected value ([`Sha256dParams::expected_bits`]) is the
/// caller's check, as on GnB.
pub fn check_sha256d_pow(header: &BlockHeader, params: &Sha256dParams) -> Result<(), Sha256dHeaderError> {
    let pow = header.sha256d_pow_header()?;
    if !sha256d::version_ok(header.version, params.block_version) {
        return Err(Sha256dHeaderError::Version);
    }
    sha256d::check_parents(&header.parents, MAX_PARENTS).map_err(Sha256dHeaderError::Parents)?;
    let target = difficulty::try_canonical_bits_to_target(header.bits).ok_or(Sha256dHeaderError::BitsNotCanonical)?;
    if target > params.pow_limit() {
        return Err(Sha256dHeaderError::AbovePowLimit);
    }
    if !sha256d::meets_target(&pow.id(), &target) {
        return Err(Sha256dHeaderError::InsufficientWork);
    }
    Ok(())
}

/// Chain work of a SHA-256d block: Bitcoin's `floor(2^256 / (target + 1))`;
/// 0 for malformed bits.
pub fn sha256d_block_work(bits: u32) -> u128 {
    sha256d::work_from_bits(bits)
}

/// Slow start (§4.2): `floor(full_sat * min(height, SLOW_START_BLOCKS) / SLOW_START_BLOCKS)`.
/// Pure helper; the coinbase rule that applies it belongs to the chain
/// parameters (package O6c).
pub fn slow_start_subsidy_sat(full_sat: u64, height: u64) -> u64 {
    if height >= SLOW_START_BLOCKS {
        return full_sat;
    }
    (full_sat as u128 * height as u128 / SLOW_START_BLOCKS as u128) as u64
}

// ── Dispatch used by `core` (one line at each GnB call site) ────────────────

/// `Block::validate_pow` under SHA-256d. Valid proofs enter the same process
/// cache as GnB-SMH proofs, so `Block::pow_is_cached` keeps its meaning.
pub(super) fn validate_pow_sha256d(block: &Block, params: &Sha256dParams) -> bool {
    let ok = check_sha256d_pow(&block.header, params).is_ok();
    if ok {
        if let Ok(mut cache) = pow_cache().lock() {
            cache.insert(block.block_hash());
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::MerkleRoot;

    fn header(parents: Vec<[u8; 32]>, bits: u32, nonce: u64) -> BlockHeader {
        BlockHeader { version: OBB_BLOCK_VERSION, parents, merkle_root: MerkleRoot([7; 32]), timestamp: 1_800_000_000, bits, nonce }
    }

    /// Grind a nonce at the regtest pow limit (about two hashes).
    fn mined(mut h: BlockHeader, params: &Sha256dParams) -> BlockHeader {
        while check_sha256d_pow(&h, params) == Err(Sha256dHeaderError::InsufficientWork) {
            h.nonce += 1;
        }
        h
    }

    #[test]
    fn launch_bits_are_the_launch_hashrate() {
        let t = sha256d::target_for_hashes(LAUNCH_HASHRATE_HPS, TARGET_BLOCK_TIME);
        assert_eq!(difficulty::target_to_bits(&t), OBB_LAUNCH_BITS);
        assert!(difficulty::is_canonical_bits(OBB_LAUNCH_BITS));
        assert_eq!(sha256d_block_work(OBB_LAUNCH_BITS), 30_000_392_575_492_696_099);
        assert!(difficulty::bits_to_target(OBB_LAUNCH_BITS) < difficulty::bits_to_target(OBB_POW_LIMIT_BITS));
    }

    #[test]
    fn asert_is_anchored_at_genesis() {
        let p = Sha256dParams::obenblock_mainnet(1_800_000_000);
        assert_eq!(p.expected_bits(p.genesis_timestamp, 1).unwrap(), OBB_LAUNCH_BITS);
        assert_eq!(p.expected_bits(p.genesis_timestamp + 30 * 99, 100).unwrap(), OBB_LAUNCH_BITS);
        // One half-life behind schedule doubles the target.
        let late = p.expected_bits(p.genesis_timestamp + 7_200, 1).unwrap();
        let want = difficulty::target_to_bits(&Target(
            (primitive_types::U256::from_big_endian(&difficulty::bits_to_target(OBB_LAUNCH_BITS).0) << 1).to_big_endian(),
        ));
        assert_eq!(late, want);
        // Far behind: clamped to the pow limit, never easier.
        assert_eq!(p.expected_bits(p.genesis_timestamp + 10_000_000, 1).unwrap(), OBB_POW_LIMIT_BITS);
        assert!(p.expected_bits(p.genesis_timestamp, 0).is_err());
        assert!(p.expected_bits(u64::MAX, 1).is_err());
    }

    #[test]
    fn regtest_mines_and_checks() {
        let p = Sha256dParams::obenblock_regtest(1_800_000_000);
        let h = mined(header(vec![[1; 32], [2; 32]], OBB_REGTEST_POW_LIMIT_BITS, 0), &p);
        assert_eq!(check_sha256d_pow(&h, &p), Ok(()));
        assert_eq!(h.sha256d_block_id(), PowHeader::from_bytes(&h.sha256d_pow_bytes().unwrap()).id());

        let mut bad = h.clone();
        bad.parents = vec![[2; 32], [1; 32]];
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::Parents(ParentsError::NotSorted)));
        bad.parents = vec![[1; 32], [1; 32]];
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::Parents(ParentsError::Duplicate)));
        bad.parents = (0..=MAX_PARENTS as u16).map(|i| { let mut x = [0u8; 32]; x[..2].copy_from_slice(&i.to_be_bytes()); x }).collect();
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::Parents(ParentsError::TooMany)));

        let mut bad = h.clone();
        bad.version |= 0x0000_1000;
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::Version));
        let mut rolled = h.clone();
        rolled.version |= 0x0000_2000;
        assert_ne!(check_sha256d_pow(&rolled, &p), Err(Sha256dHeaderError::Version));

        let mut bad = h.clone();
        bad.nonce = u32::MAX as u64 + 1;
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::NonceOutOfRange));
        let mut alias = h.clone();
        alias.nonce += 1 << 32;
        assert_ne!(alias.sha256d_block_id(), h.sha256d_block_id(), "no alias of a valid id");
        let mut bad = h.clone();
        bad.timestamp = u32::MAX as u64 + 1;
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::TimeOutOfRange));

        let mut bad = h.clone();
        bad.bits = 0x2100_7FFF; // same target family, non-canonical / above limit
        assert!(check_sha256d_pow(&bad, &p).is_err());
        bad.bits = 0x2100_FFFF;
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::AbovePowLimit));
        bad.bits = 0x0080_0001;
        assert_eq!(check_sha256d_pow(&bad, &p), Err(Sha256dHeaderError::BitsNotCanonical));

        // Mainnet rejects a regtest-easy target.
        let m = Sha256dParams::obenblock_mainnet(1_800_000_000);
        assert_eq!(check_sha256d_pow(&h, &m), Err(Sha256dHeaderError::AbovePowLimit));
    }

    #[test]
    fn slow_start_ramps_linearly() {
        let full = super::super::tokenomics::INITIAL_SUBSIDY_SAT;
        assert_eq!(slow_start_subsidy_sat(full, 0), 0);
        assert_eq!(slow_start_subsidy_sat(full, 2_880), full / 2);
        assert_eq!(slow_start_subsidy_sat(full, SLOW_START_BLOCKS), full);
        assert_eq!(slow_start_subsidy_sat(full, u64::MAX), full);
        let withheld: u64 = (1..SLOW_START_BLOCKS).map(|h| full - slow_start_subsidy_sat(full, h)).sum();
        assert_eq!(withheld / super::super::tokenomics::SAT_PER_GNB, 3_081, "about 3,080 OBB (§4.2)");
        assert_eq!(slow_start_subsidy_sat(u64::MAX, SLOW_START_BLOCKS - 1), (u64::MAX as u128 * 5_759 / 5_760) as u64);
    }

    #[test]
    fn default_scheme_is_gnb_smh() {
        // The lib test binary never sets the scheme; GnB code paths are the default.
        assert_eq!(node_pow_scheme(), PowScheme::GnbSmh);
        assert_eq!(node_sha256d_params(), None);
        assert_eq!(PowScheme::GnbSmh.name(), "gnb-smh");
    }
}
