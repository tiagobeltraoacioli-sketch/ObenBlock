//! GnB core consensus types.
//!
//! GnB-SMH proof of work (sequential memory-hard SHAKE-256) · hybrid
//! ML-DSA-65 ‖ Falcon-1024 signatures · GhostDAG BlockDAG.

use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};

/// Monetary policy: 12,500,000 GNB hard cap (carryover, locked team and founder, mining), consensus minimum fee.
pub mod tokenomics;
pub mod policy;      // m-of-n multisig + absolute/relative timelocks
pub mod vesting;     // locked team and founder allocations (genesis ledger)
pub mod witness_share; // reward for proven witness custody (from powit_height)
pub mod kes;           // forward-secure (key-evolving) hybrid signatures for witnesses
pub mod powit;         // Proof of Witnesses: witness-set finality (from powit_height)

/// Bloch Genesis-3 carryover: verified, converted opening ledger.
pub mod carryover;
pub mod activation;

/// Sighash v2/v3, the transaction-version activation rule and the shared
/// input-script (witness + signature) rules (audit CRY-1/2/3, MEM-5).
pub mod sighash;

/// Block-validity rules of the hardening activation (audit VAL-2, VAL-3,
/// VAL-10, CRY-1, VAL-12, POW-3): tagged Merkle root, 64-byte transactions,
/// coinbase height / parents / witness commitment, wire-size block limit,
/// pow limit.
pub mod block_rules;

/// MoneyRange and canonical-encoding size helpers (audit VAL-11 / VAL-12).
pub mod limits;

// ── Network identity ─────────────────────────────────────────────────────────

pub const MAINNET_PREFIX:        &str  = "gnb1q";
pub const TESTNET_PREFIX:        &str  = "gnb1t";
/// P2P magic: "GNB1". Distinct from every Bloch network.
pub const NETWORK_MAGIC:         u32   = 0x474E_4231;

// ── Sighash domain (replay separation) ──────────────────────────────────────
//
// Sighash v2 (every transaction below the hardening activation, whatever its
// version):
//   preimage = SIGHASH_DOMAIN(16) ‖ [SIGHASH_VERSION](1) ‖ chain_id.to_le_bytes()(4)
//              ‖ wire(stripped_tx)   (Transaction::to_wire_bytes(true))
//   sighash  = SHA3-256(preimage)
// Sighash v3 (version-3 transactions, the only valid version at/after the
// hardening activation): see `sighash` (module) — commits the spent amounts
// and scripts and the signature suite, linear cost.
//
// The domain and the chain ids differ from Bloch's, so no signature made for a
// Bloch chain verifies on GnB and vice versa, even over coinciding outpoints.
pub const SIGHASH_DOMAIN:  [u8; 16] = *b"GNB-SIGHASH-v1\0\0";
pub const SIGHASH_VERSION: u8       = 0x02;

/// Chain-ID registry (u32, serialized little-endian). 0x474E = "GN".
/// An explicit consensus input derived from the node's network, never from a
/// transaction and never from a compile-time flag. New networks get a new
/// discriminant; never reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ChainId {
    Mainnet = 0x474E_0001,
    Testnet = 0x474E_0002,
}

impl ChainId {
    #[inline] pub const fn to_u32(self) -> u32 { self as u32 }
    #[inline] pub fn to_le_bytes(self) -> [u8; 4] { (self as u32).to_le_bytes() }

    pub const fn for_network(net: crate::address::Network) -> ChainId {
        match net {
            crate::address::Network::Mainnet => ChainId::Mainnet,
            crate::address::Network::Testnet => ChainId::Testnet,
        }
    }
}

// Process-wide chain-id used by consensus validation. Set once at node startup
// from the network selection; defaults to Mainnet if never set.
static NODE_CHAIN_ID: std::sync::OnceLock<ChainId> = std::sync::OnceLock::new();

/// Set the process-wide node chain-id (idempotent for the same value). Returns
/// `Err(existing)` if already set to a different value.
pub fn set_node_chain_id(id: ChainId) -> Result<(), ChainId> {
    match NODE_CHAIN_ID.set(id) {
        Ok(()) => Ok(()),
        Err(_) => {
            let cur = *NODE_CHAIN_ID.get().expect("OnceLock set");
            if cur == id { Ok(()) } else { Err(cur) }
        }
    }
}

/// The node-level chain-id. Defaults to Mainnet until `set_node_chain_id`.
pub fn node_chain_id() -> ChainId {
    *NODE_CHAIN_ID.get().unwrap_or(&ChainId::Mainnet)
}

// ── PoW + PoWit activation ───────────────────────────────────────────────────
//
// From `powit_height()` the chain switches its proof of work to GnB-SMH v3 and
// enables witness shares and witness-set finality (`core::powit`). A testnet
// node may set it at startup (`--powit-height`). Changing the mainnet value is
// a hard fork.

/// Mainnet activation height (fixed 2026-10-14 for the chain relaunched from
/// genesis that day).
pub const POWIT_HEIGHT_MAINNET: u64 = 10_000;

/// Testnet default when no `--powit-height` is given: off.
pub const POWIT_HEIGHT_TESTNET: u64 = u64::MAX;

static POWIT_HEIGHT_OVERRIDE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Set the activation height for this process (testnet nodes and tests only;
/// the mainnet node never calls it). Idempotent for the same value.
pub fn set_powit_height_override(height: u64) -> Result<(), u64> {
    match POWIT_HEIGHT_OVERRIDE.set(height) {
        Ok(()) => Ok(()),
        Err(_) => {
            let cur = *POWIT_HEIGHT_OVERRIDE.get().expect("OnceLock set");
            if cur == height { Ok(()) } else { Err(cur) }
        }
    }
}

/// First height at which PoW + PoWit rules apply.
pub fn powit_height() -> u64 {
    POWIT_HEIGHT_OVERRIDE.get().copied().unwrap_or(match node_chain_id() {
        ChainId::Mainnet => POWIT_HEIGHT_MAINNET,
        ChainId::Testnet => POWIT_HEIGHT_TESTNET,
    })
}

/// Whether PoW + PoWit rules apply at `height`.
pub fn powit_active(height: u64) -> bool {
    height >= powit_height()
}

/// The proof-of-work function for a block at `height`.
pub fn pow_algo(height: u64) -> gnb_smh::Algo {
    pow_algo_with(height, powit_height())
}

/// [`pow_algo`] against an explicit activation height (testable).
pub fn pow_algo_with(height: u64, activation: u64) -> gnb_smh::Algo {
    if height >= activation { gnb_smh::Algo::V3 } else { gnb_smh::Algo::V1 }
}

/// GnB-SMH v3 attempts are ~6x cheaper than v1 (90 ms vs 527 ms on one core),
/// so from activation the target is 2^POW_V3_DIFFICULTY_SHIFT times harder
/// than the ASERT schedule, and each block's chain work is divided by the same
/// factor so that cumulative work stays comparable across the switch.
pub const POW_V3_DIFFICULTY_SHIFT: u32 = 2;

// ── Consensus constants ─────────────────────────────────────────────────────

pub const GHOSTDAG_K:            usize = 10;
pub const HALVING_INTERVAL:      u64   = tokenomics::HALVING_INTERVAL;
pub const MAX_BLOCK_SIZE:        usize = 1_000_000;
/// Bytes of non-coinbase transactions a block template may hold: the block
/// limit minus room for the header (up to `MAX_PARENTS` parent hashes), the
/// coinbase and encoding overhead. Templates filled past this would produce
/// blocks `validate_structure_cheap` rejects as too large.
pub const MAX_TEMPLATE_TX_BYTES:  usize = MAX_BLOCK_SIZE - 32 * 1024;
pub const TARGET_BLOCK_TIME:     u64   = tokenomics::TARGET_BLOCK_TIME_SECS;
pub const PROTOCOL_VERSION:      u32   = 1;
/// Mainnet minimum chain work (Bitcoin Core's `nMinimumChainWork`): the
/// default of the node's `ingress::MAINNET_MINIMUM_CHAIN_WORK`. While its
/// selected tip carries less blue work, a node is in initial block download:
/// it does not mine or serve block templates, advertises no frontier to
/// peers, processes no block it did not request unless that block's own
/// chain reaches the value, and refuses `submitblock` blocks below it.
/// Below it a node may be on a cheap chain an attacker fed it
/// (ASERT eases the difficulty of a chain behind schedule, so a long low-work
/// chain from genesis is cheap to build). Unlike a checkpoint it names no
/// block and gives no one authority over which chain wins.
///
/// Node-local policy, not consensus: no block's validity, GhostDAG data or
/// fork choice depends on it (the PoWit finalized checkpoint included), so
/// nodes with different values, `--minimumchainwork` or an older release,
/// reach the same verdicts on the same blocks; only when a node processes
/// an unrequested block, and when it leaves initial block download, differ.
///
/// Unit: the `blue_work` of the selected tip (`getdaginfo` `tip_blue_work`,
/// decimal), the sum of `block_work` over the blocks it counts:
/// `bits_to_work` of each block (about 2^256 / target; the genesis target
/// is 4,500 and the pre-activation pow limit 1), divided by
/// 2^[`POW_V3_DIFFICULTY_SHIFT`] for GnB-SMH v3 blocks, whose target is that
/// much harder, so the sum is continuous across the v1 -> v3 switch. Below
/// the hardening activation the selected chain's blocks count, from it the
/// merged blues as well (docs/CONSENSUS.md); both only add work.
///
/// Value: 7,000,000 = 0x6acfc0, docs/MAINNET-READINESS.md §1. The newest
/// reading is the one mainnet node's on 2026-10-14 04:25 UTC: tip height
/// 8,302 (GnB-SMH v1), `tip_blue_work` 7,782,451, consistent with the ASERT
/// schedule (a steady ~29 evaluations/s from genesis reaches height ~8,308
/// and ~7.77M work by then; test `min_chain_work_cross_check`). 7,000,000 is
/// 10% below it, the work of a block about 900 blocks below that tip; the
/// network's best chain work only grows, and its tip was near 14,500 at
/// release time, so the value lies more than 6,000 blocks below it. Raised
/// at each release (docs/RUNNING.md, "Initial sync and minimum chain work":
/// `tools/release/min_chain_work.py`); testnet and regtest keep 0.
pub const MIN_CHAIN_WORK: u128 = 7_000_000;

pub const COINBASE_MATURITY:     u64   = 100;        // blocks before coinbase is spendable

/// Verify that none of `tx.inputs` references an immature coinbase output
/// (depth < `COINBASE_MATURITY`). `lookup_coinbase_height(txid)` returns the
/// height of a coinbase txid, or `None` for non-coinbase / unknown txids.
/// Shared by block validation and mempool admission.
pub fn check_coinbase_maturity<F>(
    tx: &Transaction,
    current_height: u64,
    mut lookup_coinbase_height: F,
) -> Result<(), String>
where
    F: FnMut(&[u8; 32]) -> Option<u64>,
{
    if current_height == 0 {
        return Ok(());
    }
    for (i, inp) in tx.inputs.iter().enumerate() {
        if let Some(cb_height) = lookup_coinbase_height(&inp.prev_txid) {
            let depth = current_height.saturating_sub(cb_height);
            if depth < COINBASE_MATURITY {
                return Err(format!(
                    "coinbase maturity: input {} references coinbase at h={}, only {} confirmations (need {})",
                    i, cb_height, depth, COINBASE_MATURITY
                ));
            }
        }
    }
    Ok(())
}
pub const DUST_THRESHOLD:        u64   = 546;        // minimum output value (base units)
/// Maximum timestamp drift into the future. Kept short (20 blocks) because
/// ASERT reads parent timestamps: a block stamped `MAX_FUTURE_SECS` ahead can
/// ease the next target by at most 2^(600/7200) ≈ 6%.
pub const MAX_FUTURE_SECS:       u64   = 600;
pub const DNS_SEED_DOMAIN: &str = "";
/// No public seed infrastructure yet; peers are supplied with --peer.
pub const DEFAULT_SEEDS: &[&str] = &[];

pub const CHECKPOINT_DEPTH:      u64   = 1_000;      // node-local ingress window + deep-reorg alert depth; NOT a reorg-depth limit, no finality (audit DAG-6)
pub const PRUNING_DEPTH:         u64   = 10_000;     // block bodies pruned below tip - this; undo records are kept, so reorgs of any depth still work

// Hybrid ML-DSA-65 ‖ Falcon-1024 sizes, including the 4-byte crypto-agility
// suite header. SIG_SIZE is an upper bound (Falcon is variable length) used
// for fee sizing only.
pub const PUBKEY_SIZE:  usize = 4 + 1952 + 1793; // 3749
pub const PRIVKEY_SIZE: usize = 4 + 4032 + 2305; // 6341
pub const SIG_SIZE:     usize = 4 + 3309 + 1462; // 4775

// ── Proof of work and difficulty ────────────────────────────────────────────
//
// PoW: GnB-SMH v1 (crate `gnb-smh`) over `BlockHeader::pow_preimage()` and the
// header's 64-bit nonce. A block is valid iff GnB-SMH(preimage, nonce), read as
// a big-endian 256-bit integer, is strictly below the target encoded by `bits`.
//
// Difficulty: ASERT anchored at the genesis block. The expected `bits` of a
// block is a pure function of its parent set: the LATEST timestamp over all
// parents (`difficulty_parent_timestamp`) and the block height
// max(parent heights) + 1 -- not the GhostDAG selected parent's timestamp or
// height (docs/CONSENSUS.md, "Difficulty input"). Miner and validator agree
// regardless of arrival order or parent order.

/// True when built with the `test-pow-limit` feature, which pins every
/// expected target to the pow limit so tests do not depend on the wall clock.
/// Consensus-breaking; a node binary with it refuses mainnet, and an
/// optimised one every network (node/src/main.rs `test_pow_limit_guard`).
pub const TEST_POW_LIMIT: bool = cfg!(feature = "test-pow-limit");

/// Easiest target the chain accepts below the hardening activation (≈ one
/// evaluation per block). At/after the activation the pow limit is the genesis
/// target (`block_rules::HARDENED_POW_LIMIT_BITS`, audit POW-3).
pub const POW_LIMIT_BITS: u32 = 0x2100_FFFF;
/// ASERT half-life: two hours (240 blocks at 30 s).
pub const ASERT_HALFLIFE_SECS: i64 = 2 * 60 * 60;

/// The chain's ASERT parameters below the hardening activation
/// (`pow_limit = POW_LIMIT_BITS`). Use [`asert_params_at`] for a given height.
pub fn asert_params() -> gnb_smh::difficulty::AsertParams {
    gnb_smh::difficulty::AsertParams {
        target_spacing: TARGET_BLOCK_TIME as i64,
        halflife: ASERT_HALFLIFE_SECS,
        pow_limit: gnb_smh::difficulty::bits_to_target(POW_LIMIT_BITS),
    }
}

/// The chain's ASERT parameters for a block at header height `height`: the
/// pow limit is `block_rules::pow_limit_bits_at(height, activation_height)`
/// (the genesis target at/after the activation, POW-3).
pub fn asert_params_at(height: u64, activation_height: u64) -> gnb_smh::difficulty::AsertParams {
    gnb_smh::difficulty::AsertParams {
        pow_limit: gnb_smh::difficulty::bits_to_target(block_rules::pow_limit_bits_at(height, activation_height)),
        ..asert_params()
    }
}

/// The chain's ASERT anchor: the genesis block.
pub fn asert_anchor() -> gnb_smh::difficulty::AsertAnchor {
    gnb_smh::difficulty::AsertAnchor {
        height: 0,
        bits: GENESIS_BITS,
        timestamp: GENESIS_TIMESTAMP as i64,
    }
}

/// Consensus minimum fee check for a non-coinbase transaction paying `fee`.
pub fn check_min_fee(tx: &Transaction, fee: u64) -> Result<(), String> {
    let size = tx.to_wire_bytes(true).len();
    let min = tokenomics::min_tx_fee_sat(size);
    if fee < min {
        return Err(format!("fee {fee} below consensus minimum {min} for a {size}-byte transaction"));
    }
    Ok(())
}

/// Timestamp the difficulty of a child block is computed from: the latest
/// timestamp among its parents. Pure function of the parent set, so every
/// node derives the same value regardless of arrival order.
pub fn difficulty_parent_timestamp<I: IntoIterator<Item = u64>>(parent_timestamps: I) -> u64 {
    parent_timestamps.into_iter().max().unwrap_or(GENESIS_TIMESTAMP)
}

/// Expected compact `bits` for a block at `height` (>= 1) whose parents'
/// latest timestamp is `parent_timestamp` (see `difficulty_parent_timestamp`). Single source of truth for the
/// validator, the internal miner and every block-template producer. Uses the
/// process-wide hardening activation height (pow limit, POW-3).
pub fn expected_bits(parent_timestamp: u64, height: u64) -> Result<u32, String> {
    #[cfg(feature = "test-pow-limit")]
    if pow_limit_pinned_on_this_thread() {
        let _ = (parent_timestamp, height);
        return Ok(target_to_bits(&bits_to_target(POW_LIMIT_BITS)));
    }
    #[allow(unreachable_code)]
    expected_bits_at(parent_timestamp, height, activation::hardening_activation_height())
}

/// The real ASERT rule with an explicit activation height. Never pinned by
/// the `test-pow-limit` feature, so the pow-limit boundary can be tested in
/// any build.
pub fn expected_bits_at(parent_timestamp: u64, height: u64, activation_height: u64) -> Result<u32, String> {
    let parent_time = i64::try_from(parent_timestamp)
        .map_err(|_| format!("parent timestamp {parent_timestamp} out of range"))?;
    let bits = gnb_smh::difficulty::asert_next_bits(
        &asert_params_at(height, activation_height), &asert_anchor(), parent_time, height,
    )
    .map_err(|e| e.to_string())?;
    Ok(adjust_bits_for_algo(bits, pow_algo(height)))
}

/// ASERT bits for `algo`: v3 targets are `POW_V3_DIFFICULTY_SHIFT` bits lower.
pub fn adjust_bits_for_algo(bits: u32, algo: gnb_smh::Algo) -> u32 {
    match algo {
        gnb_smh::Algo::V1 => bits,
        gnb_smh::Algo::V3 => {
            let t = bits_to_target(bits);
            let v = primitive_types::U256::from_big_endian(&t) >> POW_V3_DIFFICULTY_SHIFT;
            let v = v.max(primitive_types::U256::one());
            target_to_bits(&v.to_big_endian())
        }
    }
}

// ── BlockHeader ───────────────────────────────────────────────────────────────

/// Strongly-typed wrapper around a 32-byte merkle root.
///
/// Audit L-2 fix: previously `BlockHeader::merkle_root` was a bare
/// `[u8; 32]`, indistinguishable at the type level from block hashes,
/// txids, address hashes, and every other 32-byte identifier in the
/// system. The compiler could not catch a mix-up like
///
/// ```ignore
/// let b = lookup_block(&store, header.merkle_root); // wanted block_hash
/// ```
///
/// With `MerkleRoot`, that call is now a compile error.
///
/// ## Serialization invariant
///
/// `#[serde(transparent)]` guarantees that a `MerkleRoot(x)` serializes
/// as byte-identical output to the bare `[u8; 32]` `x`. This is
/// **critical for consensus** — the change must be invisible on the
/// wire, in RocksDB, and inside `BlockHeader::pow_bytes`. Any existing
/// block encoded with the pre-L-2 type decodes correctly with the
/// post-L-2 type, and vice versa. A dedicated round-trip test pins
/// this invariant (`merkle_root_serde_is_byte_identical_to_array`).
///
/// ## Usage
///
/// - `MerkleRoot::ZERO` — conventional all-zero root, used for empty
///   or placeholder blocks in tests.
/// - `MerkleRoot::from([u8; 32])` — convert a computed digest.
/// - `root.as_ref()` / `&root[..]` — obtain a byte slice for hashing,
///   serialization, or hex encoding without unwrapping the newtype.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleRoot(pub [u8; 32]);

impl MerkleRoot {
    /// The all-zero root, used as a sentinel for empty tx lists.
    pub const ZERO: MerkleRoot = MerkleRoot([0u8; 32]);

    /// Expose the inner array. Prefer `as_ref()` for byte-slice
    /// operations — this accessor exists mainly for interop with
    /// storage code that stores/reads `[u8; 32]` keys.
    pub fn into_inner(self) -> [u8; 32] { self.0 }
}

impl Default for MerkleRoot {
    fn default() -> Self { Self::ZERO }
}

impl From<[u8; 32]> for MerkleRoot {
    fn from(bytes: [u8; 32]) -> Self { MerkleRoot(bytes) }
}

impl From<MerkleRoot> for [u8; 32] {
    fn from(m: MerkleRoot) -> Self { m.0 }
}

impl AsRef<[u8]> for MerkleRoot {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl std::ops::Deref for MerkleRoot {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] { &self.0 }
}

// Show as hex in debug/display so log lines stay readable. Otherwise
// MerkleRoot([0xab, 0xcd, …]) dumps 32 decimal integers per line.
impl std::fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleRoot({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version:     u32,
    pub parents:     Vec<[u8; 32]>,
    pub merkle_root: MerkleRoot,
    pub timestamp:   u64,
    pub bits:        u32,
    pub nonce:       u64,
}

/// Maximum number of parents a header may reference.
pub const MAX_PARENTS: usize = 256;

impl BlockHeader {
    /// Canonical header serialization without the nonce — the `header` input
    /// of GnB-SMH. Every consensus field of the header is committed here.
    ///
    /// ```text
    ///   version      u32 LE
    ///   n_parents    u32 LE
    ///   parents      n × 32 bytes, in header order
    ///   merkle_root  32 bytes
    ///   timestamp    u64 LE
    ///   bits         u32 LE
    /// ```
    pub fn pow_preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + 4 + self.parents.len() * 32 + 32 + 8 + 4);
        b.extend_from_slice(&self.version.to_le_bytes());
        b.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents { b.extend_from_slice(p); }
        b.extend_from_slice(self.merkle_root.as_ref());
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&self.bits.to_le_bytes());
        b
    }

    /// GnB-SMH output for this header (64 MiB, ~1M Keccak permutations).
    /// Expensive: use `Block::validate_pow`, which caches verified blocks.
    pub fn pow_hash(&self, height: u64) -> [u8; 32] {
        gnb_smh::hash_algo(pow_algo(height), &self.pow_preimage(), self.nonce)
    }

    // Audit POW-9: `dag_hash`, a SHA3-256 header digest nothing but a test
    // called, was removed. Blocks are identified, indexed, stored and relayed
    // by `Block::block_hash` only (docs/CONSENSUS.md, "Block header and proof
    // of work"). These comment lines keep the line numbers of the code below
    // that the browser wallet core compiles: panic locations are part of the
    // reproducible WASM (audit WAL-5).
    //
    //

    /// Wire serialization: `pow_preimage` fields, then the nonce, then the
    /// DAG metadata carried with the block (blue_score, height).
    ///
    /// ```text
    ///   version u32 | varint n_parents | parents | merkle_root | timestamp u64
    ///   | bits u32 | nonce u64 | blue_score u64 | height u64
    /// ```
    pub fn to_wire_bytes(&self, blue_score: u64, height: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 9 + self.parents.len() * 32 + 32 + 8 + 4 + 8 + 8 + 8);
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, self.parents.len() as u64);
        for p in &self.parents {
            out.extend_from_slice(p);
        }
        out.extend_from_slice(self.merkle_root.as_ref());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&blue_score.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out
    }

    /// Parse a header from the front of `bytes`. Returns
    /// (header, blue_score, height, bytes consumed).
    pub fn read_wire_bytes(bytes: &[u8]) -> Result<(Self, u64, u64, usize), String> {
        let mut cur = Cursor::new(bytes);
        let version = read_u32_le(&mut cur).map_err(|e| format!("version: {e}"))?;
        let n = read_varint(&mut cur)?;
        if n > MAX_PARENTS as u64 {
            return Err(format!("implausible parent count {n}"));
        }
        let mut parents = Vec::with_capacity(n as usize);
        for _ in 0..n {
            parents.push(read_32(&mut cur).map_err(|e| format!("parents: {e}"))?);
        }
        let merkle_root = MerkleRoot(read_32(&mut cur).map_err(|e| format!("merkle_root: {e}"))?);
        let timestamp = read_u64_le(&mut cur).map_err(|e| format!("timestamp: {e}"))?;
        let bits = read_u32_le(&mut cur).map_err(|e| format!("bits: {e}"))?;
        let nonce = read_u64_le(&mut cur).map_err(|e| format!("nonce: {e}"))?;
        let blue_score = read_u64_le(&mut cur).map_err(|e| format!("blue_score: {e}"))?;
        let height = read_u64_le(&mut cur).map_err(|e| format!("height: {e}"))?;
        let header = BlockHeader { version, parents, merkle_root, timestamp, bits, nonce };
        Ok((header, blue_score, height, cur.position() as usize))
    }

    /// Parse exactly one header; trailing bytes are an error.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<(Self, u64, u64), String> {
        let (h, blue, height, used) = Self::read_wire_bytes(bytes)?;
        if used != bytes.len() {
            return Err(format!("trailing bytes after header: parsed {used} of {}", bytes.len()));
        }
        Ok((h, blue, height))
    }
}

// ── Transaction ───────────────────────────────────────────────────────────────

/// script_sig encoding: [4B sig_len][sig][4B pubkey_len][pubkey]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_txid:  [u8; 32],
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence:   u32,
}

/// script_pubkey: 20-byte SHA3-256(pubkey)[0..20]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub value:         u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version:  u32,
    pub inputs:   Vec<TxInput>,
    pub outputs:  Vec<TxOutput>,
    pub locktime: u32,
}

use std::io::{Cursor, Read};

// ── Bitcoin-format varint + cursor helpers ─────────────────────────────────
// Used by Transaction::to_wire_bytes / from_wire_bytes so that external
// miners and the node agree on txid wire format.

pub(crate) fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Encoded length of `write_varint(n)`.
fn varint_len(n: u64) -> usize {
    if n < 0xFD {
        1
    } else if n <= 0xFFFF {
        3
    } else if n <= 0xFFFF_FFFF {
        5
    } else {
        9
    }
}

/// Read one CompactSize varint. Only the minimal encoding of a value is
/// accepted (Bitcoin Core's `ReadCompactSize`, "non-canonical
/// ReadCompactSize()"), so every wire value has exactly one encoding.
/// Accepting `FD 05 00` for 5 gave every block, header and transaction many
/// byte-distinct encodings, and made `Block::from_wire_bytes` frame the next
/// transaction at the re-encoded length of the previous one, fewer bytes than
/// it consumed (fuzz target `wire_roundtrip`, docs/testing/FUZZING.md).
fn read_varint(cur: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut tag = [0u8; 1];
    cur.read_exact(&mut tag).map_err(|_| "varint: unexpected EOF on tag".to_string())?;
    let (value, min) = match tag[0] {
        0xFF => { let mut b = [0u8; 8]; cur.read_exact(&mut b).map_err(|_| "varint u64 EOF")?; (u64::from_le_bytes(b), 0x1_0000_0000) }
        0xFE => { let mut b = [0u8; 4]; cur.read_exact(&mut b).map_err(|_| "varint u32 EOF")?; (u32::from_le_bytes(b) as u64, 0x1_0000) }
        0xFD => { let mut b = [0u8; 2]; cur.read_exact(&mut b).map_err(|_| "varint u16 EOF")?; (u16::from_le_bytes(b) as u64, 0xFD) }
        n    => return Ok(n as u64),
    };
    if value < min {
        return Err(format!("{NON_MINIMAL_VARINT}: {value} encoded with the 0x{:02X} form", tag[0]));
    }
    Ok(value)
}

/// The text of every wire decoder error caused by a non-minimal CompactSize
/// varint (`read_varint`); see [`is_non_minimal_varint_error`].
pub const NON_MINIMAL_VARINT: &str = "non-canonical varint";

/// Whether an error of `Block::from_wire_bytes` (or of the header and
/// transaction decoders) is the minimal-varint rule: the first thing the
/// decoder refused was a CompactSize varint written in a longer form than its
/// value needs.
///
/// Every byte string that the decoders before this rule accepted and the
/// current ones refuse fails this way. Both decoders read the same fields in
/// the same order with the same checks; they differ only in refusing a
/// non-minimal varint and in where the next transaction of a block starts
/// (the bytes consumed, or the re-encoded length). A transaction whose
/// varints are minimal consumes exactly its re-encoded length, so the two
/// agree byte for byte up to the first non-minimal varint, which the current
/// decoder refuses with this error (`core::wire_canonical_tests::
/// pre_fix_acceptances_fail_on_a_non_minimal_varint`). The node uses this to
/// tell a widened copy that an older node may have accepted and relayed from
/// other malformed bytes (`ingress::verdict_for_block_decode_error`).
pub fn is_non_minimal_varint_error(err: &str) -> bool {
    err.contains(NON_MINIMAL_VARINT)
}

fn read_u32_le(cur: &mut Cursor<&[u8]>) -> Result<u32, String> {
    let mut b = [0u8; 4];
    cur.read_exact(&mut b).map_err(|_| "u32 EOF".to_string())?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64_le(cur: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut b = [0u8; 8];
    cur.read_exact(&mut b).map_err(|_| "u64 EOF".to_string())?;
    Ok(u64::from_le_bytes(b))
}

fn read_32(cur: &mut Cursor<&[u8]>) -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    cur.read_exact(&mut b).map_err(|_| "32-byte EOF".to_string())?;
    Ok(b)
}

fn read_bytes(cur: &mut Cursor<&[u8]>, n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    cur.read_exact(&mut b).map_err(|_| format!("{}-byte EOF", n))?;
    Ok(b)
}

// ── Coherence C2: shielded-transaction (de)serialization ──────────────────────

/// `write_shielded_tx(tx).len()`, computed without encoding.
fn shielded_tx_wire_size(tx: &coherence_core::ShieldedTx) -> usize {
    32 + varint_len(tx.nullifiers.len() as u64) + 32 * tx.nullifiers.len()
        + varint_len(tx.outputs.len() as u64) + 32 * tx.outputs.len()
        + 8
        + varint_len(tx.proof.len() as u64) + tx.proof.len()
        + varint_len(tx.binding_sig.len() as u64) + tx.binding_sig.len()
}

fn write_shielded_tx(out: &mut Vec<u8>, tx: &coherence_core::ShieldedTx) {
    out.extend_from_slice(&tx.anchor);
    write_varint(out, tx.nullifiers.len() as u64);
    for nf in &tx.nullifiers { out.extend_from_slice(nf); }
    write_varint(out, tx.outputs.len() as u64);
    for o in &tx.outputs { out.extend_from_slice(o); }
    out.extend_from_slice(&tx.fee.to_le_bytes());
    write_varint(out, tx.proof.len() as u64);
    out.extend_from_slice(&tx.proof);
    write_varint(out, tx.binding_sig.len() as u64);
    out.extend_from_slice(&tx.binding_sig);
}

fn read_shielded_tx(cur: &mut Cursor<&[u8]>) -> Result<coherence_core::ShieldedTx, String> {
    let anchor = read_32(cur)?;
    let nf_n = read_varint(cur)?;
    if nf_n > 100_000 { return Err(format!("implausible nullifier count {}", nf_n)); }
    let mut nullifiers = Vec::with_capacity(nf_n.min(1024) as usize);
    for _ in 0..nf_n { nullifiers.push(read_32(cur)?); }
    let out_n = read_varint(cur)?;
    if out_n > 100_000 { return Err(format!("implausible output count {}", out_n)); }
    let mut outputs = Vec::with_capacity(out_n.min(1024) as usize);
    for _ in 0..out_n { outputs.push(read_32(cur)?); }
    let fee = read_u64_le(cur)?;
    let proof_len = read_varint(cur)?;
    if proof_len > 8_000_000 { return Err(format!("implausible proof length {}", proof_len)); }
    let proof = read_bytes(cur, proof_len as usize)?;
    let sig_len = read_varint(cur)?;
    if sig_len > 100_000 { return Err(format!("implausible binding_sig length {}", sig_len)); }
    let binding_sig = read_bytes(cur, sig_len as usize)?;
    Ok(coherence_core::ShieldedTx { anchor, nullifiers, outputs, fee, proof, binding_sig })
}

// ────────────────────────────────────────────────────────────────────────────

/// Largest `script_sig` the wire decoder accepts: the largest policy witness
/// (`policy::MAX_POLICY_WITNESS_LEN`, about 112 KiB). It used to be 10,000
/// bytes, which silently made every policy with more than one key (1-of-2:
/// 12,113 B; 2-of-3: 20,453 B) impossible to relay, mine or store although
/// consensus accepted it. A single-key witness (~8.4 KB) is far below it.
pub const MAX_SCRIPT_SIG_LEN: usize = policy::MAX_POLICY_WITNESS_LEN;

/// Bitcoin-style Merkle root (SHA-256d, last hash duplicated on odd levels).
/// Duplicate-leaf ambiguity (CVE-2012-2459) is excluded by
/// `Block::validate_no_duplicate_txs`.
fn merkle_of(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
    if hashes.is_empty() { return [0u8; 32]; }
    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            if let Some(last) = hashes.last().copied() {
                hashes.push(last);
            }
        }
        hashes = hashes.chunks(2).map(|p| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&p[0]);
            buf[32..].copy_from_slice(&p[1]);
            Sha256::digest(Sha256::digest(buf)).into()
        }).collect();
    }
    hashes[0]
}

/// From this height every block commits to its witnesses (the full
/// `script_sig` of each transaction): the coinbase `script_sig` must end with
/// [`WITNESS_COMMITMENT_TAG`] followed by [`Block::witness_root`]. The txid
/// excludes witnesses (no third-party malleability), so before this a block
/// hash did not cover them: a relay could alter witnesses of a valid block.
/// Activated ahead of the live tip (2,888 on 2026-10-12) so every miner can
/// upgrade first.
pub const WITNESS_COMMITMENT_HEIGHT: u64 = 5_000;

/// Whether a block at `height` must carry the `|wc:` suffix commitment: from
/// [`WITNESS_COMMITMENT_HEIGHT`] up to (excluding) the hardening activation,
/// where the audit's 80-byte coinbase commitment
/// (`block_rules::check_coinbase_commitment`, which also commits to the
/// witness root) replaces it.
pub fn suffix_witness_commitment_required(height: u64) -> bool {
    height >= WITNESS_COMMITMENT_HEIGHT
        && !activation::is_active_at(height, activation::hardening_activation_height())
}

/// Whether the block id commits to every witness at `height` (either
/// commitment): a witness failure is then a verdict on the block.
pub fn witnesses_committed(height: u64) -> bool {
    height >= WITNESS_COMMITMENT_HEIGHT
}
/// Marker before the 32-byte witness root at the end of the coinbase script_sig.
pub const WITNESS_COMMITMENT_TAG: &[u8; 4] = b"|wc:";

impl Transaction {
    /// Canonical stratum/Bitcoin-format serialization.
    ///
    /// Used for `txid()` (consensus-critical) and for stratum V1
    /// coinbase splitting. Unlike bincode, this format is stable
    /// across language implementations and matches the byte layout
    /// every external mining client (cgminer, cpuminer, Braiins OS)
    /// already knows how to produce.
    ///
    /// Layout (little-endian integers, varint for counts/lengths):
    ///
    /// ```text
    ///   version (4B LE)
    ///   input_count (varint)
    ///   for each input:
    ///     prev_txid (32B)
    ///     prev_index (4B LE)
    ///     [if include_script_sig: script_sig_len (varint), script_sig bytes]
    ///     sequence (4B LE)
    ///   output_count (varint)
    ///   for each output:
    ///     value (8B LE)
    ///     script_pubkey_len (varint)
    ///     script_pubkey bytes
    ///   locktime (4B LE)
    /// ```
    ///
    /// When `include_script_sig = false`, inputs' script_sig is
    /// omitted entirely (not just zero-length). This matches
    /// Bitcoin's SegWit wtxid convention and preserves the VULN-06
    /// malleability fix for non-coinbase transactions.
    pub fn to_wire_bytes(&self, include_script_sig: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, self.inputs.len() as u64);
        for inp in &self.inputs {
            out.extend_from_slice(&inp.prev_txid);
            out.extend_from_slice(&inp.prev_index.to_le_bytes());
            if include_script_sig {
                write_varint(&mut out, inp.script_sig.len() as u64);
                out.extend_from_slice(&inp.script_sig);
            }
            out.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for outp in &self.outputs {
            out.extend_from_slice(&outp.value.to_le_bytes());
            write_varint(&mut out, outp.script_pubkey.len() as u64);
            out.extend_from_slice(&outp.script_pubkey);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// `to_wire_bytes(include_script_sig).len()`, computed without encoding.
    pub fn wire_size(&self, include_script_sig: bool) -> usize {
        let mut n = 4 + varint_len(self.inputs.len() as u64);
        for inp in &self.inputs {
            n += 32 + 4 + 4;
            if include_script_sig {
                n += varint_len(inp.script_sig.len() as u64) + inp.script_sig.len();
            }
        }
        n += varint_len(self.outputs.len() as u64);
        for o in &self.outputs {
            n += 8 + varint_len(o.script_pubkey.len() as u64) + o.script_pubkey.len();
        }
        n + 4
    }

    /// Witness transaction id (consensus, audit CRY-1): SHA-256d over the
    /// FULL wire encoding, `script_sig`s included (`to_wire_bytes(true)`).
    /// Equal to `txid()` for a coinbase. The block's witness root commits to
    /// these (`block_rules::witness_root`). Not the mempool's node-local
    /// `admission::wtxid` cache key.
    pub fn wtxid(&self) -> [u8; 32] {
        Sha256::digest(Sha256::digest(self.to_wire_bytes(true))).into()
    }

    /// Parse a Transaction from its stratum/Bitcoin-format serialization.
    /// Inverse of `to_wire_bytes(true)` — requires `include_script_sig=true`
    /// bytes since a round-trip without script_sig cannot recover the input's
    /// signature. Bytes after the transaction are ignored (the gossip/RPC
    /// decoder `mempool::admission::decode_tx_strict` refuses them); every
    /// varint must be minimal, so the bytes consumed are exactly
    /// `to_wire_bytes(true)` of the result.
    ///
    /// Returns Err with a short diagnostic on malformed input.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, String> {
        Self::read_wire_bytes(bytes).map(|(tx, _)| tx)
    }

    /// Parse a transaction from the front of `bytes`: the transaction and the
    /// number of bytes it occupies (the framing `Block::from_wire_bytes` uses).
    pub fn read_wire_bytes(bytes: &[u8]) -> Result<(Self, usize), String> {
        let mut cur = Cursor::new(bytes);

        let version = read_u32_le(&mut cur)?;
        let in_count = read_varint(&mut cur)?;
        if in_count > 100_000 { return Err(format!("implausible input count {}", in_count)); }

        // SECURITY (audit M1): never pre-size from the untrusted count alone —
        // bound the pre-allocation by how many inputs the remaining bytes could
        // possibly hold (min input = 32+4+1+4 = 41 bytes). The Vec still grows
        // if the payload really is that large.
        let remaining = bytes.len().saturating_sub(cur.position() as usize);
        let mut inputs = Vec::with_capacity((in_count as usize).min(remaining / 41 + 1));
        for _ in 0..in_count {
            let prev_txid = read_32(&mut cur)?;
            let prev_index = read_u32_le(&mut cur)?;
            let sig_len = read_varint(&mut cur)?;
            if sig_len > MAX_SCRIPT_SIG_LEN as u64 { return Err(format!("implausible script_sig length {}", sig_len)); }
            let script_sig = read_bytes(&mut cur, sig_len as usize)?;
            let sequence = read_u32_le(&mut cur)?;
            inputs.push(TxInput { prev_txid, prev_index, script_sig, sequence });
        }

        let out_count = read_varint(&mut cur)?;
        if out_count > 100_000 { return Err(format!("implausible output count {}", out_count)); }

        // SECURITY (audit M1): bound by remaining bytes (min output = 8+1 = 9 bytes).
        let remaining = bytes.len().saturating_sub(cur.position() as usize);
        let mut outputs = Vec::with_capacity((out_count as usize).min(remaining / 9 + 1));
        for _ in 0..out_count {
            let value = read_u64_le(&mut cur)?;
            let spk_len = read_varint(&mut cur)?;
            if spk_len > 10_000 { return Err(format!("implausible script_pubkey length {}", spk_len)); }
            let script_pubkey = read_bytes(&mut cur, spk_len as usize)?;
            outputs.push(TxOutput { value, script_pubkey });
        }

        let locktime = read_u32_le(&mut cur)?;

        Ok((Transaction { version, inputs, outputs, locktime }, cur.position() as usize))
    }

    /// Transaction ID. SHA-256d over stratum-format bytes.
    ///
    /// Non-coinbase: serialized WITHOUT script_sig to prevent
    /// third-party signature malleability (VULN-06 preservation).
    /// Coinbase: serialized WITH script_sig, so the txid commits to it; the
    /// coinbase has no signature to malleate. Below the hardening activation
    /// the script_sig is free-form (the node's miner writes
    /// `gnb:h<height>:<random>`); at/after it, it starts with the 80-byte
    /// commitment of `block_rules` (tag, header height, parent-list hash,
    /// witness root), which makes every coinbase applied on one selected
    /// chain unique (docs/CONSENSUS.md).
    ///
    /// **v0.6.0 change:** previously computed via bincode. Switched
    /// to stratum-format bytes so that external miners (which receive
    /// coinb1/coinb2 byte fragments via mining.notify) and the node
    /// agree on txids. Consensus-breaking, part of the AA.0 hard fork.
    pub fn txid(&self) -> [u8; 32] {
        let bytes = self.to_wire_bytes(self.is_coinbase());
        Sha256::digest(Sha256::digest(&bytes)).into()
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev_txid == [0u8; 32]
            && self.inputs[0].prev_index == u32::MAX
    }

    /// Sighash (v2) for input at `index`, bound to `chain_id`.
    ///
    /// The digest of every transaction below the hardening activation,
    /// whatever its version (see the `core::sighash` module for the selection
    /// and the activation rule). Specified
    /// byte for byte in `docs/CONSENSUS.md` (the bincode body is re-derived
    /// by an independent encoder in `reference/gnb_sighash.py`) and pinned by
    /// golden vectors; it must never change. Costs O(size) per input, so
    /// O(size²) per transaction (bounded by the size limits, and invalid
    /// at/after the activation). An out-of-range `input_index` silently
    /// omits the marker (historical behaviour, kept for digest stability);
    /// [`Transaction::sighash_v2_checked`] reports it as an error instead.
    ///
    /// `chain_id` is an EXPLICIT consensus input threaded from the node's network
    /// (`ChainId::for_network` / `node_chain_id()`), never a compile-time flag and
    /// never taken from the transaction. Folding it into the preimage prevents
    /// cross-fork / testnet↔mainnet replay: the same signature bytes verify to a
    /// different 32-byte digest on another chain, so ML-DSA and Falcon both fail
    /// (design §1). This changes the signed bytes of every tx — a hard fork.
    pub fn sighash(&self, input_index: usize, chain_id: ChainId) -> [u8; 32] {
        let mut stripped = self.clone();
        for (i, inp) in stripped.inputs.iter_mut().enumerate() {
            inp.script_sig = if i == input_index {
                b"GNB_SIGHASH".to_vec()
            } else {
                vec![]
            };
        }
        // SIGHASH_ALL: the digest commits to version, locktime, every input's
        // outpoint (prev_txid/prev_index/sequence) and the signed input's index
        // (via the marker), and EVERY output — so signatures cannot be replayed
        // across txs (outpoints) nor have outputs redirected/tampered. The spent
        // UTXO's value is bound implicitly via its outpoint (the verifier looks it
        // up). `.expect` not `.unwrap_or_default`: a silent empty encoding would
        // make the sighash a FIXED constant (replayable signatures) — encoding an
        // owned struct into an in-memory Vec cannot fail, so fail loud if it ever
        // does rather than degrade security.
        //
        // The fixed 21-byte domain+version+chain-id prefix precedes the body;
        // only the trailing body is variable, so simple concatenation is
        // unambiguous.
        //
        // v2 body: the stripped transaction in the hand-written wire format
        // (`to_wire_bytes(true)`), not a serde/bincode encoding, so no
        // dependency upgrade or attribute change can alter what is signed.
        let body = stripped.to_wire_bytes(true);
        let mut h = Sha3_256::new();
        h.update(SIGHASH_DOMAIN);           // 16 bytes (fixed)
        h.update([SIGHASH_VERSION]);        //  1 byte  (fixed)
        h.update(chain_id.to_le_bytes());   //  4 bytes (fixed)
        h.update(&body);                    //  variable (wire body)
        h.finalize().into()
    }

    /// The PRE-activation transaction Merkle root (SHA-256d, last node
    /// duplicated on odd levels), unchanged. A block's header root depends on
    /// its height: use `Block::body_merkle_root` (or
    /// `block_rules::tx_merkle_root`), which switches to the tagged tree at
    /// the hardening activation (audit VAL-10).
    pub fn merkle_root(txs: &[Transaction]) -> MerkleRoot {
        let ids: Vec<[u8; 32]> = txs.iter().map(|t| t.txid()).collect();
        block_rules::legacy_merkle_root(&ids)
    }

    /// Parse sig + pubkey out of script_sig: the exact framing, bytes after
    /// the public key are refused (on this chain at every height since
    /// cc5c450; the historical lenient framing that ignored them is gone).
    /// Owned copy of [`Self::parse_script_sig_borrowed`].
    pub fn parse_script_sig(script_sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        Self::parse_script_sig_borrowed(script_sig).map(|(s, p)| (s.to_vec(), p.to_vec()))
    }

    /// The sighash v2 witness framing `[u32 LE sig_len][sig][u32 LE
    /// pk_len][pk]`, borrowed. Exact length: no trailing bytes, so a relay
    /// cannot pad a witness (consensus on this chain at every height since
    /// cc5c450; identical to [`Self::parse_script_sig_exact`]).
    pub fn parse_script_sig_borrowed(script_sig: &[u8]) -> Option<(&[u8], &[u8])> {
        Self::parse_script_sig_exact(script_sig)
    }

    /// The canonical witness framing: exactly
    /// `[u32 LE sig_len][sig][u32 LE pk_len][pk]` with no trailing bytes
    /// (CRY-1; consensus at/after the hardening activation, relay policy at
    /// every height).
    pub fn parse_script_sig_exact(script_sig: &[u8]) -> Option<(&[u8], &[u8])> {
        match Self::parse_script_sig_prefix(script_sig) {
            Some((s, p, end)) if end == script_sig.len() => Some((s, p)),
            _ => None,
        }
    }

    /// (sig, pk, bytes consumed).
    fn parse_script_sig_prefix(script_sig: &[u8]) -> Option<(&[u8], &[u8], usize)> {
        // CRY-8: checked arithmetic. On 64-bit targets no sum below can
        // overflow (lengths are u32), so acceptance is unchanged; on 32-bit
        // targets a huge declared length now returns None instead of panicking.
        if script_sig.len() < 8 { return None; }
        let sig_len = usize::try_from(u32::from_le_bytes(script_sig[..4].try_into().ok()?)).ok()?;
        let sig_end = sig_len.checked_add(4)?;
        let pk_len_end = sig_end.checked_add(4)?;
        if script_sig.len() < pk_len_end { return None; }
        let sig = &script_sig[4..sig_end];
        let pk_len = usize::try_from(u32::from_le_bytes(
            script_sig[sig_end..pk_len_end].try_into().ok()?
        )).ok()?;
        let pk_end = pk_len_end.checked_add(pk_len)?;
        if script_sig.len() < pk_end { return None; }
        let pk = &script_sig[pk_len_end..pk_end];
        Some((sig, pk, pk_end))
    }

    /// Build script_sig from sig + pubkey
    pub fn build_script_sig(sig: &[u8], pubkey: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + sig.len() + pubkey.len());
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
        out.extend_from_slice(&(pubkey.len() as u32).to_le_bytes());
        out.extend_from_slice(pubkey);
        out
    }

    /// Sprint A: Estimate the serialized size of a transaction BEFORE signing.
    pub fn estimate_size(n_inputs: usize, n_outputs: usize) -> usize {
        const PER_INPUT:  usize = 4 + 32 + 4
                                  + 4 + crate::core::SIG_SIZE
                                  + 4 + crate::core::PUBKEY_SIZE;
        const PER_OUTPUT: usize = 8 + 4 + 20;
        const BASE:       usize = 4 + 4 + 4 + 4;
        BASE + (n_inputs * PER_INPUT) + (n_outputs * PER_OUTPUT)
    }

    /// Sprint A: Calculate fee given size and rate (sats per 1000 bytes).
    pub fn calc_fee(size_bytes: usize, fee_rate_per_kb: u64, min_fee: u64) -> u64 {
        let calculated = (size_bytes as u64).saturating_mul(fee_rate_per_kb) / 1000;
        calculated.max(min_fee)
    }

    /// Sprint A: Full fee estimation for a planned transaction.
    pub fn estimate_fee(n_inputs: usize, n_outputs: usize, fee_rate_per_kb: u64) -> u64 {
        let size = Self::estimate_size(n_inputs, n_outputs);
        Self::calc_fee(size, fee_rate_per_kb, 1000)
    }

    /// Consensus dust rule for a non-coinbase transaction: no output with
    /// `0 < value < DUST_THRESHOLD`. Block validation applies it to every
    /// non-coinbase transaction, so the mempool and templates must too.
    pub fn validate_dust(&self) -> Result<(), &'static str> {
        if self.outputs.iter().any(|o| o.value > 0 && o.value < DUST_THRESHOLD) {
            return Err("output below dust threshold");
        }
        Ok(())
    }

    /// Sprint A: Actual serialized size of this transaction (after signing).
    pub fn actual_size(&self) -> usize {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Sprint A: Total value of outputs (None on overflow).
    pub fn total_output(&self) -> Option<u64> {
        self.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
    }

    /// Sprint A: Count distinct addresses in outputs.
    pub fn unique_output_addresses(&self) -> usize {
        use std::collections::HashSet;
        let addrs: HashSet<&[u8]> = self.outputs.iter()
            .map(|o| o.script_pubkey.as_slice())
            .collect();
        addrs.len()
    }
}

// ── Block ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header:       BlockHeader,
    pub transactions: Vec<Transaction>,
    pub blue_score:   u64,
    pub height:       u64,
    /// Coherence: shielded (private) transactions in this block. Committed via
    /// `body_merkle_root` and serialized after the transparent transactions.
    #[serde(default)]
    pub shielded_transactions: Vec<coherence_core::ShieldedTx>,
    /// PoWit section (witness shares, attestations, equivocation proofs).
    /// Present on the wire and committed in the body root only from
    /// `powit_height()`; must be empty below it.
    #[serde(default)]
    pub powit: powit::PowitBody,
}

/// Bounded cache of block ids whose GnB-SMH proof has been verified. A block
/// id commits to the full PoW preimage and nonce, so a hit is exactly as good
/// as re-running the 64 MiB evaluation. Entries are only inserted after a
/// successful verification.
struct PowCache {
    set: std::collections::HashSet<[u8; 32]>,
    order: std::collections::VecDeque<[u8; 32]>,
}

const POW_CACHE_CAPACITY: usize = 16_384;

fn pow_cache() -> &'static std::sync::Mutex<PowCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<PowCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        std::sync::Mutex::new(PowCache {
            set: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
        })
    })
}

impl Block {
    /// Block identity: SHA3-256 over a domain label, the PoW preimage and the
    /// nonce. Cheap, and distinct from the (expensive) PoW output.
    pub fn block_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"GNB-BLOCK-ID-v1");
        h.update(self.header.pow_preimage());
        h.update(self.header.nonce.to_le_bytes());
        h.finalize().into()
    }

    /// Wire format:
    ///
    /// ```text
    ///   header       BlockHeader::to_wire_bytes(blue_score, height)
    ///   tx_count     varint
    ///   transactions Transaction::to_wire_bytes(true) × tx_count
    ///   sh_count     varint
    ///   shielded     shielded tx × sh_count
    ///   powit        PowitBody (only when height >= powit_height())
    /// ```
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_wire_bytes(self.blue_score, self.height);
        write_varint(&mut out, self.transactions.len() as u64);
        for tx in &self.transactions {
            out.extend_from_slice(&tx.to_wire_bytes(true));
        }
        write_varint(&mut out, self.shielded_transactions.len() as u64);
        for stx in &self.shielded_transactions {
            write_shielded_tx(&mut out, stx);
        }
        if powit_active(self.height) {
            self.powit.write_wire(&mut out);
        }
        out
    }

    /// `to_wire_bytes().len()`, computed without encoding. The size measure
    /// of `MAX_BLOCK_SIZE` at/after the hardening activation (VAL-12).
    pub fn wire_size(&self) -> usize {
        let header = 4 + varint_len(self.header.parents.len() as u64) + 32 * self.header.parents.len()
            + 32 + 8 + 4 + 8 + 8 + 8;
        let txs: usize = self.transactions.iter().map(|t| t.wire_size(true)).sum();
        let shielded: usize = self.shielded_transactions.iter().map(shielded_tx_wire_size).sum();
        // The PoWit section is part of the encoding from `powit_height()`.
        let powit = if powit_active(self.height) {
            let mut v = Vec::new();
            self.powit.write_wire(&mut v);
            v.len()
        } else {
            0
        };
        header
            + varint_len(self.transactions.len() as u64) + txs
            + varint_len(self.shielded_transactions.len() as u64) + shielded
            + powit
    }

    /// Strict inverse of `to_wire_bytes`: trailing bytes and non-minimal
    /// varints are rejected, so an accepted `bytes` is exactly
    /// `to_wire_bytes()` of the result.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (header, blue_score, height, header_len) = BlockHeader::read_wire_bytes(bytes)?;
        let body = &bytes[header_len..];
        let mut cur = Cursor::new(body);
        let tx_count = read_varint(&mut cur)?;
        if tx_count > 1_000_000 {
            return Err(format!("implausible tx count {}", tx_count));
        }
        // Bound the pre-allocation by the remaining bytes (a minimal tx is 10
        // bytes), never by the untrusted count alone.
        let remaining = body.len().saturating_sub(cur.position() as usize);
        let mut transactions = Vec::with_capacity((tx_count as usize).min(remaining / 10 + 1));
        let mut offset = cur.position() as usize;
        for i in 0..tx_count {
            // Advance by the bytes the transaction decoder consumed, never by
            // the length of a re-encoding (a different frame for any input
            // that does not round-trip byte for byte).
            let (tx, used) = Transaction::read_wire_bytes(&body[offset..])
                .map_err(|e| format!("tx[{}] parse: {}", i, e))?;
            offset += used;
            transactions.push(tx);
        }

        let mut sh_cur = Cursor::new(&body[offset..]);
        let sh_count = read_varint(&mut sh_cur).map_err(|e| format!("shielded count: {e}"))?;
        if sh_count > 100_000 {
            return Err(format!("implausible shielded count {}", sh_count));
        }
        let mut shielded_transactions = Vec::new();
        for i in 0..sh_count {
            shielded_transactions.push(
                read_shielded_tx(&mut sh_cur).map_err(|e| format!("shielded[{}]: {}", i, e))?);
        }
        offset += sh_cur.position() as usize;

        let powit = if powit_active(height) {
            let mut pc = Cursor::new(&body[offset..]);
            let pb = powit::PowitBody::read_wire(&mut pc).map_err(|e| format!("powit section: {e}"))?;
            offset += pc.position() as usize;
            pb
        } else {
            powit::PowitBody::default()
        };

        if offset != body.len() {
            return Err(format!("trailing bytes in block body: parsed {} of {}", offset, body.len()));
        }
        Ok(Block { header, transactions, blue_score, height, shielded_transactions, powit })
    }

    /// Merkle commitment over the block body — transparent and shielded txs —
    /// under the process-wide hardening activation height (see
    /// [`Block::body_merkle_root_at`]).
    pub fn body_merkle_root(&self) -> MerkleRoot {
        self.body_merkle_root_at(activation::hardening_activation_height())
    }

    /// Merkle commitment over the block body for an explicit activation
    /// height. The transaction root is `Transaction::merkle_root` (legacy)
    /// below the activation and the tagged tree of `block_rules` at/after it
    /// (audit VAL-10), judged at this block's header height. From
    /// `powit_height()` the body root is v2 (transparent, shielded and PoWit
    /// sections, always); below it, with no shielded txs the commitment is
    /// the transaction root itself.
    pub fn body_merkle_root_at(&self, activation_height: u64) -> MerkleRoot {
        let hardened = block_rules::rules_active_at(self.height, activation_height);
        let tx_root = block_rules::tx_merkle_root(&self.transactions, hardened);
        if powit_active(self.height) {
            let mut c = Sha3_256::new();
            c.update(b"gnb:block:body:v2");
            c.update(tx_root.0);
            c.update(self.shielded_root());
            c.update(self.powit.root());
            return MerkleRoot(c.finalize().into());
        }
        if self.shielded_transactions.is_empty() {
            return tx_root;
        }
        let mut sh = Sha3_256::new();
        sh.update(b"gnb:block:shielded:v1");
        for stx in &self.shielded_transactions {
            let mut buf = Vec::new();
            write_shielded_tx(&mut buf, stx);
            let h: [u8; 32] = Sha3_256::digest(&buf).into();
            sh.update(h);
        }
        let sh_root: [u8; 32] = sh.finalize().into();
        let mut c = Sha3_256::new();
        c.update(b"gnb:block:body:v1");
        c.update(tx_root.0);
        c.update(sh_root);
        MerkleRoot(c.finalize().into())
    }

    /// Root of the shielded section (also over an empty list).
    fn shielded_root(&self) -> [u8; 32] {
        let mut sh = Sha3_256::new();
        sh.update(b"gnb:block:shielded:v1");
        for stx in &self.shielded_transactions {
            let mut buf = Vec::new();
            write_shielded_tx(&mut buf, stx);
            let h: [u8; 32] = Sha3_256::digest(&buf).into();
            sh.update(h);
        }
        sh.finalize().into()
    }

    pub fn validate_merkle(&self) -> bool {
        self.body_merkle_root() == self.header.merkle_root
    }

    /// [`Block::validate_merkle`] for an explicit activation height.
    pub fn validate_merkle_at(&self, activation_height: u64) -> bool {
        self.body_merkle_root_at(activation_height) == self.header.merkle_root
    }

    /// GnB-SMH proof of work: GnB-SMH(pow_preimage, nonce) < target(bits).
    ///
    /// Malformed, zero or non-canonical (POW-9) `bits` never validate. This
    /// checks the proof against the header's own `bits`; that `bits` equals
    /// the consensus-expected value is checked by the caller (`expected_bits`,
    /// always canonical) — first, since it is cheap and this is not.
    pub fn validate_pow(&self) -> bool {
        let target = match gnb_smh::difficulty::try_canonical_bits_to_target(self.header.bits) {
            Some(t) => t,
            None => return false,
        };
        // POW-9 (audit): explicit `target <= pow_limit`. Below the hardening
        // activation the largest decodable compact target IS the pow limit,
        // but the proof must never rely on that coincidence of the encoding.
        // At/after it (POW-3) the limit is the genesis target, judged at the
        // block's header height (`accept_block` checks that height against
        // the parents before the proof is used). Fails closed before any
        // evaluation is spent.
        if target.0 > Self::pow_limit_target_for_height(self.height) {
            return false;
        }
        let id = self.block_hash();
        if let Ok(cache) = pow_cache().lock() {
            if cache.set.contains(&id) {
                return true;
            }
        }
        let ok = gnb_smh::verify_algo(pow_algo(self.height), &self.header.pow_preimage(),
                                      self.header.nonce, &target);
        if ok {
            if let Ok(mut cache) = pow_cache().lock() {
                // Insert with FIFO eviction: `PowCache::insert`, defined at
                // the end of this file so that the code the browser wallet
                // core compiles keeps its line numbers (panic locations are
                // part of the reproducible WASM, audit WAL-5; this comment
                // fills the lines the inlined insert took). It is a function
                // of its own so that its eviction bound can be tested
                // (docs/testing/MUTATION.md).
                cache.insert(id);
            }
        }
        ok
    }

    /// Whether this block's proof of work was already verified (valid) by
    /// this process. Never evaluates GnB-SMH.
    pub fn pow_is_cached(&self) -> bool {
        let id = self.block_hash();
        pow_cache().lock().map(|c| c.set.contains(&id)).unwrap_or(false)
    }

    /// POW-9: `target <= POW_LIMIT_BITS` (both big-endian), the pre-activation
    /// pow limit. `validate_pow` checks the limit of the block's own height
    /// ([`Block::pow_limit_target_for_height`]).
    pub fn target_within_pow_limit(target: &[u8; 32]) -> bool {
        *target <= bits_to_target(POW_LIMIT_BITS)
    }

    /// POW-3: `target <= pow limit at header height `height`` for an explicit
    /// activation height (`block_rules::pow_limit_bits_at`): the genesis
    /// target at/after the activation, `POW_LIMIT_BITS` before.
    pub fn target_within_pow_limit_at(target: &[u8; 32], height: u64, activation_height: u64) -> bool {
        *target <= bits_to_target(block_rules::pow_limit_bits_at(height, activation_height))
    }

    /// The pow limit `validate_pow` enforces for a block at header height
    /// `height` under the process-wide activation height. Under the dev-only
    /// `test-pow-limit` feature every expected target is pinned to
    /// `POW_LIMIT_BITS`, so the limit stays `POW_LIMIT_BITS` there too (a
    /// node binary with that feature refuses mainnet; POW-9 / POW-3 are
    /// therefore not reachable in the functional tests).
    pub fn pow_limit_target_for_height(height: u64) -> [u8; 32] {
        if TEST_POW_LIMIT {
            return bits_to_target(POW_LIMIT_BITS);
        }
        bits_to_target(block_rules::pow_limit_bits_at(height, activation::hardening_activation_height()))
    }

    /// Basic coinbase format check (value is checked with fees in accept_block).
    pub fn validate_coinbase_format(&self) -> bool {
        if self.transactions.is_empty() { return false; }
        let cb = &self.transactions[0];
        if !cb.is_coinbase() { return false; }
        if self.transactions.iter().skip(1).any(|t| t.is_coinbase()) { return false; }
        true
    }

    /// Coinbase value rule. Called after computing the block's total fees.
    ///
    /// Fair launch: the coinbase has exactly one output, paid to an address of
    /// the miner's choice, worth at most `block_subsidy_sat(height) + fees`.
    /// Paying less burns the difference.
    pub fn validate_coinbase_value(&self, total_fees: u64) -> Result<(), &'static str> {
        if self.transactions.is_empty() { return Err("no transactions"); }
        if powit_active(self.height) {
            return self.validate_coinbase_value_powit(total_fees);
        }
        let cb = &self.transactions[0];
        if cb.outputs.len() != 1 {
            return Err("coinbase must have 1 output (miner)");
        }
        // checked_add, not saturating_add: an overflowing sum must be rejected,
        // never clamped into "any value is allowed".
        let subsidy = tokenomics::block_subsidy_sat(self.height);
        let max_allowed = subsidy.checked_add(total_fees)
            .ok_or("coinbase reward computation overflowed (subsidy + fees)")?;
        if cb.outputs[0].value > max_allowed {
            return Err("miner coinbase output exceeds allowed amount");
        }
        Ok(())
    }

    /// From `powit_height()`: output 0 pays the miner at most its share of
    /// the subsidy (`witness_share::split_subsidy`) plus fees; output `1 + k`
    /// pays exactly `per_attester` to share `k`'s payout script. Nothing else.
    fn validate_coinbase_value_powit(&self, total_fees: u64) -> Result<(), &'static str> {
        let cb = &self.transactions[0];
        let shares = &self.powit.shares;
        if shares.len() > witness_share::MAX_SHARES_PER_BLOCK {
            return Err("too many witness shares");
        }
        if cb.outputs.len() != 1 + shares.len() {
            return Err("coinbase must have 1 miner output plus 1 output per witness share");
        }
        let split = witness_share::split_subsidy(self.height, shares.len());
        let max_miner = split.miner.checked_add(total_fees)
            .ok_or("coinbase reward computation overflowed (subsidy + fees)")?;
        if cb.outputs[0].value > max_miner {
            return Err("miner coinbase output exceeds allowed amount");
        }
        for (out, share) in cb.outputs[1..].iter().zip(shares) {
            if out.value != split.per_attester || out.script_pubkey != share.payout {
                return Err("coinbase witness-share output does not match its share");
            }
        }
        Ok(())
    }

    /// Build the coinbase outputs for a block template from `powit_height()`:
    /// the miner output followed by one output per share. Below activation
    /// it is just the miner output.
    pub fn coinbase_outputs(height: u64, miner_script: Vec<u8>, total_fees: u64,
                            shares: &[witness_share::WitnessShare]) -> Vec<TxOutput> {
        if !powit_active(height) {
            let v = tokenomics::block_subsidy_sat(height).saturating_add(total_fees);
            return vec![TxOutput { value: v, script_pubkey: miner_script }];
        }
        let split = witness_share::split_subsidy(height, shares.len());
        let mut outs = vec![TxOutput { value: split.miner.saturating_add(total_fees), script_pubkey: miner_script }];
        outs.extend(shares.iter().map(|s| TxOutput { value: split.per_attester, script_pubkey: s.payout.clone() }));
        outs
    }

    /// Validate the timestamp is within acceptable bounds.
    /// `parent_timestamp`: the latest timestamp over all of the block's
    /// parents (the node passes the max; 0 for genesis).
    pub fn validate_timestamp(&self, parent_timestamp: u64) -> Result<(), &'static str> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.header.timestamp > now + MAX_FUTURE_SECS {
            return Err("timestamp too far in the future");
        }
        if self.header.timestamp < parent_timestamp {
            return Err("timestamp before parent");
        }
        Ok(())
    }

    /// Merkle root of the block's wtxids, the coinbase counted as all-zero
    /// (it carries the commitment, so it cannot commit to itself).
    pub fn witness_root(&self) -> [u8; 32] {
        merkle_of(self.transactions.iter().enumerate()
            .map(|(i, t)| if i == 0 { [0u8; 32] } else { t.wtxid() })
            .collect())
    }

    /// The bytes the coinbase script_sig must end with from
    /// [`WITNESS_COMMITMENT_HEIGHT`]: tag ‖ witness root.
    pub fn witness_commitment(&self) -> Vec<u8> {
        [&WITNESS_COMMITMENT_TAG[..], &self.witness_root()[..]].concat()
    }

    /// For block producers: at or above [`WITNESS_COMMITMENT_HEIGHT`], append
    /// the witness commitment to the coinbase script_sig and refresh the
    /// header's merkle root. Call after the transaction list is final.
    pub fn commit_witnesses(&mut self) {
        if !suffix_witness_commitment_required(self.height) || self.transactions.is_empty() {
            return;
        }
        let commitment = self.witness_commitment();
        if let Some(input) = self.transactions[0].inputs.first_mut() {
            input.script_sig.extend_from_slice(&commitment);
        }
        self.header.merkle_root = self.body_merkle_root();
    }

    /// From [`WITNESS_COMMITMENT_HEIGHT`], the coinbase commits to every
    /// witness in the block, so the block hash covers them.
    pub fn validate_witness_commitment(&self) -> Result<(), &'static str> {
        if !suffix_witness_commitment_required(self.height) {
            return Ok(());
        }
        let cb = self.transactions.first().and_then(|t| t.inputs.first())
            .ok_or("no coinbase input")?;
        if !cb.script_sig.ends_with(&self.witness_commitment()) {
            return Err("coinbase does not commit to the block's witnesses");
        }
        Ok(())
    }

    /// Check all non-coinbase outputs meet the dust threshold
    /// ([`Transaction::validate_dust`]).
    pub fn validate_dust(&self) -> Result<(), &'static str> {
        self.transactions.iter().skip(1).try_for_each(Transaction::validate_dust)
    }

    /// Reject blocks with duplicate transactions (CVE-2012-2459: the merkle
    /// tree duplicates the last hash on odd levels, so [A, B, C] and
    /// [A, B, C, C] share a root).
    pub fn validate_no_duplicate_txs(&self) -> Result<(), &'static str> {
        use std::collections::HashSet;
        let mut seen = HashSet::with_capacity(self.transactions.len());
        for tx in &self.transactions {
            if !seen.insert(tx.txid()) {
                return Err("duplicate transaction in block (CVE-2012-2459)");
            }
        }
        Ok(())
    }

    /// Every context-free check that costs microseconds (no proof of work);
    /// same as [`Block::validate_structure_without_pow`].
    pub fn validate_structure_cheap(&self) -> Result<(), &'static str> {
        self.validate_structure_without_pow()
    }

    /// Structural validation. Cheap checks run first; the proof of work runs
    /// last. Does NOT check coinbase value, fees, bits or height (those need
    /// consensus context).
    ///
    /// Exactly `validate_structure_without_pow()` followed by `validate_pow()`.
    /// Network ingress (NET-2) calls the two halves separately so the cheap
    /// contextual checks (expected bits, height, timestamp, or the orphan
    /// anti-DoS work floor) can run BETWEEN them, before the 64 MiB
    /// evaluation; the proof itself is still verified on every ingress path.
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        self.validate_structure_without_pow()?;
        if !self.validate_pow()                       { return Err("invalid PoW"); }
        Ok(())
    }

    /// The cheap, context-free half of [`Block::validate_structure`]: parent
    /// count, size, merkle commitment, coinbase format, duplicate txs, dust,
    /// and at/after the hardening activation the 64-byte rule and the
    /// coinbase commitment. Does NOT verify the proof of work — a caller that
    /// uses this MUST call [`Block::validate_pow`] (directly or through the
    /// node's `accept_block`) before treating the block as valid. Uses the
    /// process-wide activation height and the block's (claimed) header
    /// height; `accept_block` re-checks the height-dependent rules once the
    /// height is verified against the parents.
    pub fn validate_structure_without_pow(&self) -> Result<(), &'static str> {
        self.validate_structure_without_pow_at(activation::hardening_activation_height())
    }

    /// [`Block::validate_structure_without_pow`] for an explicit activation
    /// height. Below the activation: the wire size (`legacy_block_size`, never
    /// dependent on the uncommitted blue_score, B1-T0), legacy Merkle root.
    pub fn validate_structure_without_pow_at(&self, activation_height: u64) -> Result<(), &'static str> {
        let hardened = block_rules::rules_active_at(self.height, activation_height);
        if self.header.parents.len() > MAX_PARENTS   { return Err("too many parents"); }
        block_rules::check_block_size_at(self, activation_height)?; // VAL-12; B1-T0: blue_score-independent
        if !self.validate_merkle_at(activation_height) { return Err("invalid merkle root"); }
        if !self.validate_coinbase_format()           { return Err("invalid coinbase format"); }
        if hardened {
            block_rules::check_hardened_body(self)?;
        }
        self.validate_no_duplicate_txs()?;
        self.validate_dust()?;
        self.validate_witness_commitment()?;
        self.validate_powit_structure()?;
        Ok(())
    }

    /// Context-free PoWit checks: empty below activation; bounded counts;
    /// every share pays a valid script; no duplicate share ids.
    pub fn validate_powit_structure(&self) -> Result<(), &'static str> {
        if !powit_active(self.height) {
            return if self.powit.is_empty() { Ok(()) } else { Err("PoWit section before activation") };
        }
        let p = powit::params();
        if self.powit.shares.len() > witness_share::MAX_SHARES_PER_BLOCK { return Err("too many witness shares"); }
        if self.powit.attestations.len() > p.max_attestations_per_block { return Err("too many attestations"); }
        if self.powit.evidence.len() > p.max_evidence_per_block { return Err("too many equivocation proofs"); }
        let mut ids = std::collections::HashSet::with_capacity(self.powit.shares.len());
        for sh in &self.powit.shares {
            if !sh.payout_is_valid() { return Err("witness share pays an invalid script"); }
            if !ids.insert(witness_share::share_id(sh)) { return Err("duplicate witness share"); }
        }
        Ok(())
    }

    /// Consensus size: the hand-written wire encoding (`to_wire_bytes`), the
    /// bytes that are relayed and stored, never a serde/bincode encoding.
    pub fn size_bytes(&self) -> usize {
        self.to_wire_bytes().len()
    }
}

#[cfg(test)]
mod structure_split_tests {
    //! NET-2 / POW-9 regressions: the cheap structural half is separable from
    //! the proof of work, and `validate_pow` checks `target <= pow_limit`.
    use super::*;

    fn block_with(bits: u32, nonce: u64) -> Block {
        let txs = vec![Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: u32::MAX,
                script_sig: b"structure-split".to_vec(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: 1, script_pubkey: vec![7u8; 20] }],
            locktime: 0,
        }];
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                parents: vec![[0x11; 32]],
                merkle_root: MerkleRoot::ZERO,
                timestamp: GENESIS_TIMESTAMP,
                bits,
                nonce,
            },
            transactions: txs,
            blue_score: 1,
            height: 1,
            shielded_transactions: vec![],
            powit: Default::default(),
        };
        b.header.merkle_root = b.body_merkle_root();
        b
    }

    #[test]
    fn target_above_pow_limit_is_rejected() {
        assert!(!Block::target_within_pow_limit(&[0xFF; 32]), "target above the limit must fail");
        assert!(Block::target_within_pow_limit(&bits_to_target(POW_LIMIT_BITS)), "the limit itself is allowed");
        assert!(Block::target_within_pow_limit(&bits_to_target(GENESIS_BITS)));
        // One unit above the limit is already out of range.
        let mut above = bits_to_target(POW_LIMIT_BITS);
        let last = above.iter().rposition(|&b| b != 0xFF).expect("limit is not all-ones");
        above[last] = above[last].wrapping_add(1);
        for b in above.iter_mut().skip(last + 1) { *b = 0; }
        assert!(!Block::target_within_pow_limit(&above));
    }

    #[test]
    fn malformed_bits_never_validate_and_cost_no_evaluation() {
        // Negative-flag bits: rejected by the decoder before any evaluation.
        let b = block_with(0x0480_0001, 0);
        let t = std::time::Instant::now();
        assert!(!b.validate_pow());
        assert!(t.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn cheap_half_accepts_well_formed_block_regardless_of_pow() {
        // Hard target, arbitrary nonce: the PoW fails, the cheap half passes.
        let mut b = block_with(GENESIS_BITS, 0);
        assert!((0..16).any(|n| { b.header.nonce = n; !b.validate_pow() }), "no FAILING nonce in 16 (each passes w.p. ~1/4,500; bounded: a broken proof check or cache must fail, not hang)");
        assert_eq!(b.validate_structure_without_pow(), Ok(()));
        assert_eq!(b.validate_structure(), Err("invalid PoW"),
            "validate_structure must still verify the proof of work");
    }

    #[test]
    fn cheap_half_still_rejects_structural_faults() {
        let mut b = block_with(POW_LIMIT_BITS, 0);
        b.header.merkle_root = MerkleRoot([9u8; 32]);
        assert_eq!(b.validate_structure_without_pow(), Err("invalid merkle root"));
        let mut b = block_with(POW_LIMIT_BITS, 0);
        b.header.parents = vec![[1u8; 32]; MAX_PARENTS + 1];
        assert_eq!(b.validate_structure_without_pow(), Err("too many parents"));
        let mut b = block_with(POW_LIMIT_BITS, 0);
        b.transactions.clear();
        b.header.merkle_root = b.body_merkle_root();
        assert_eq!(b.validate_structure_without_pow(), Err("invalid coinbase format"));
    }
}

#[cfg(test)]
mod wire_canonical_tests {
    //! Regressions found by the `wire_roundtrip` fuzz target: the wire
    //! decoders accepted non-minimal CompactSize varints, so a block, header
    //! or transaction had many byte encodings, and `Block::from_wire_bytes`
    //! advanced past each transaction by the length of its RE-ENCODING, not by
    //! the bytes it consumed.
    use super::*;

    fn tx(script_len: usize, locktime: u32) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [7; 32], prev_index: 1, script_sig: vec![0xAB; script_len], sequence: 9 }],
            outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![0x5A; 20] }],
            locktime,
        }
    }

    fn block(txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader { version: 1, parents: vec![[1; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 5, bits: POW_LIMIT_BITS, nonce: 3 },
            transactions: txs,
            blue_score: 2,
            height: 2,
            shielded_transactions: vec![],
            powit: Default::default(),
        }
    }

    /// Replace the one-byte varint at `at` (value < 0xFD) by `FD v 00`.
    fn widen(bytes: &[u8], at: usize) -> Vec<u8> {
        assert!(bytes[at] < 0xFD);
        let mut v = bytes[..at].to_vec();
        v.extend_from_slice(&[0xFD, bytes[at], 0x00]);
        v.extend_from_slice(&bytes[at + 1..]);
        v
    }

    /// Each form accepts exactly the values the shorter forms cannot hold.
    #[test]
    fn varint_minimality_boundaries() {
        let rd = |b: &[u8]| read_varint(&mut Cursor::new(b));
        assert_eq!(rd(&[0xFC]), Ok(0xFC));
        assert!(rd(&[0xFD, 0xFC, 0x00]).is_err());
        assert_eq!(rd(&[0xFD, 0xFD, 0x00]), Ok(0xFD));
        assert_eq!(rd(&[0xFD, 0xFF, 0xFF]), Ok(0xFFFF));
        assert!(rd(&[0xFE, 0xFF, 0xFF, 0x00, 0x00]).is_err());
        assert_eq!(rd(&[0xFE, 0x00, 0x00, 0x01, 0x00]), Ok(0x1_0000));
        assert!(rd(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]).is_err());
        assert_eq!(rd(&[0xFF, 0, 0, 0, 0, 1, 0, 0, 0]), Ok(0x1_0000_0000));
        for n in [0u64, 0xFC, 0xFD, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000, u64::MAX] {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            assert_eq!(v.len(), varint_len(n));
            let mut c = Cursor::new(&v[..]);
            assert_eq!(read_varint(&mut c), Ok(n));
            assert_eq!(c.position() as usize, v.len());
        }
    }

    #[test]
    fn non_minimal_varints_are_refused_by_every_decoder() {
        let t = tx(12, 0);
        let enc = t.to_wire_bytes(true);
        // input count (offset 4), script_sig length (4 + 1 + 36), output
        // count, script_pubkey length.
        let sig_len_at = 4 + 1 + 32 + 4;
        let out_count_at = sig_len_at + 1 + 12 + 4;
        for at in [4, sig_len_at, out_count_at, out_count_at + 1 + 8] {
            let wide = widen(&enc, at);
            assert!(Transaction::from_wire_bytes(&wide).is_err(), "tx varint at {at} accepted in a 3-byte form");
        }
        // The 5- and 9-byte forms of a small value.
        let mut five = enc[..4].to_vec();
        five.extend_from_slice(&[0xFE, 1, 0, 0, 0]);
        five.extend_from_slice(&enc[5..]);
        assert!(Transaction::from_wire_bytes(&five).is_err());
        let mut nine = enc[..4].to_vec();
        nine.extend_from_slice(&[0xFF, 1, 0, 0, 0, 0, 0, 0, 0]);
        nine.extend_from_slice(&enc[5..]);
        assert!(Transaction::from_wire_bytes(&nine).is_err());

        // Header parent count, block tx count, shielded count.
        let b = block(vec![t.clone()]);
        let h = b.header.to_wire_bytes(2, 2);
        assert!(BlockHeader::from_wire_bytes(&widen(&h, 4)).is_err(), "parent count");
        let w = b.to_wire_bytes();
        assert!(Block::from_wire_bytes(&widen(&w, h.len())).is_err(), "tx count");
        assert!(Block::from_wire_bytes(&widen(&w, w.len() - 1)).is_err(), "shielded count");
        assert!(Block::from_wire_bytes(&w).is_ok());

        // Minimal multi-byte forms stay valid at the boundaries.
        for n in [0xFC, 0xFD, 0xFE, 0xFF, 0x100, 9_999] {
            let t = tx(n, 1);
            let e = t.to_wire_bytes(true);
            let (back, used) = Transaction::read_wire_bytes(&e).unwrap();
            assert_eq!((back.inputs[0].script_sig.len(), used), (n, e.len()));
        }
    }

    /// `is_non_minimal_varint_error` names the minimal-varint refusals of
    /// every decoder and no other decode error. The node answers the former
    /// with Ignore and every other malformed block with Reject
    /// (`ingress::verdict_for_block_decode_error`), so a classifier that
    /// matched any error would spare every malformed block its penalty.
    #[test]
    fn non_minimal_varint_error_names_only_that_refusal() {
        fn refusal<T>(r: Result<T, String>, what: &str) -> String {
            match r {
                Ok(_) => panic!("{what}: accepted"),
                Err(e) => e,
            }
        }
        let t = tx(12, 0);
        let e = t.to_wire_bytes(true);
        let b = block(vec![t.clone()]);
        let h = b.header.to_wire_bytes(2, 2);
        let w = b.to_wire_bytes();
        let widened = [
            refusal(Transaction::from_wire_bytes(&widen(&e, 4)), "tx input count"),
            refusal(Transaction::read_wire_bytes(&widen(&e, 4 + 1 + 32 + 4)), "tx script_sig length"),
            refusal(BlockHeader::from_wire_bytes(&widen(&h, 4)), "header parent count"),
            refusal(Block::from_wire_bytes(&widen(&w, h.len())), "block tx count"),
            refusal(Block::from_wire_bytes(&widen(&w, w.len() - 1)), "block shielded count"),
        ];
        for err in &widened {
            assert!(is_non_minimal_varint_error(err), "{err}");
        }

        let mut trailing = w.clone();
        trailing.push(0);
        let mut too_many = w.clone();
        too_many[h.len()] = 2; // two transactions announced, one present
        let mut bad_tag = w.clone();
        bad_tag[h.len()] = 0xFD; // a 3-byte tx count with its bytes missing
        bad_tag.truncate(h.len() + 2);
        let other = [
            refusal(Block::from_wire_bytes(&w[..w.len() - 1]), "block truncated"),
            refusal(Block::from_wire_bytes(&trailing), "block with a trailing byte"),
            refusal(Block::from_wire_bytes(&too_many), "block missing a transaction"),
            refusal(Block::from_wire_bytes(&bad_tag), "block with a cut varint"),
            refusal(Block::from_wire_bytes(&[]), "empty block"),
            refusal(BlockHeader::from_wire_bytes(&h[..h.len() - 1]), "header truncated"),
            refusal(Transaction::from_wire_bytes(&e[..e.len() - 1]), "tx truncated"),
            refusal(Transaction::from_wire_bytes(&[]), "empty tx"),
        ];
        for err in &other {
            assert!(!is_non_minimal_varint_error(err), "{err}");
        }
    }

    /// The pre-fix decoder accepted these bytes: the transaction's script
    /// length is `FD 0C 00` (two bytes longer than minimal), the block parser
    /// then read the shielded count from the transaction's last two locktime
    /// bytes (`FD 00`) plus the real count byte, and the frame "fit".
    #[test]
    fn block_transactions_are_framed_by_the_bytes_consumed() {
        let t = tx(12, u32::from_le_bytes([0x11, 0x22, 0xFD, 0x00]));
        let b = block(vec![t]);
        let w = b.to_wire_bytes();
        let hdr = b.header.to_wire_bytes(2, 2).len();
        let sig_len_at = hdr + 1 + 4 + 1 + 32 + 4;
        assert_eq!(w[sig_len_at], 12);
        let crafted = widen(&w, sig_len_at);
        assert!(Block::from_wire_bytes(&crafted).is_err(), "a mis-framed block encoding was accepted");
        // Canonical encodings: consumed bytes == encoding length.
        for t in &b.transactions {
            let e = t.to_wire_bytes(true);
            let mut longer = e.clone();
            longer.extend_from_slice(&[1, 2, 3]);
            assert_eq!(Transaction::read_wire_bytes(&longer).unwrap().1, e.len());
        }
        let back = Block::from_wire_bytes(&w).unwrap();
        assert_eq!(back.to_wire_bytes(), w);
        // The pre-fix decoder (below) read these bytes as the same block.
        let old = pre_fix_block(&crafted).expect("the pre-fix decoder accepted the crafted bytes");
        assert_eq!(old.to_wire_bytes(), w);
        assert!(is_non_minimal_varint_error(&Block::from_wire_bytes(&crafted).unwrap_err()));
    }

    // ── The block decoder before the minimal-varint rule ────────────────────
    // A copy of the decoder of the releases before H-fuzz (origin/main at
    // 6321605): lenient varints, each transaction framed at its re-encoded
    // length. Kept only to pin which bytes the rule newly refuses.

    fn pre_fix_varint(cur: &mut Cursor<&[u8]>) -> Result<u64, String> {
        let mut tag = [0u8; 1];
        cur.read_exact(&mut tag).map_err(|_| "varint: unexpected EOF on tag".to_string())?;
        match tag[0] {
            0xFF => { let mut b = [0u8; 8]; cur.read_exact(&mut b).map_err(|_| "varint u64 EOF")?; Ok(u64::from_le_bytes(b)) }
            0xFE => { let mut b = [0u8; 4]; cur.read_exact(&mut b).map_err(|_| "varint u32 EOF")?; Ok(u32::from_le_bytes(b) as u64) }
            0xFD => { let mut b = [0u8; 2]; cur.read_exact(&mut b).map_err(|_| "varint u16 EOF")?; Ok(u16::from_le_bytes(b) as u64) }
            n => Ok(n as u64),
        }
    }

    fn pre_fix_tx(bytes: &[u8]) -> Result<Transaction, String> {
        let mut cur = Cursor::new(bytes);
        let version = read_u32_le(&mut cur)?;
        let in_count = pre_fix_varint(&mut cur)?;
        if in_count > 100_000 { return Err(format!("implausible input count {in_count}")); }
        let mut inputs = Vec::new();
        for _ in 0..in_count {
            let prev_txid = read_32(&mut cur)?;
            let prev_index = read_u32_le(&mut cur)?;
            let sig_len = pre_fix_varint(&mut cur)?;
            if sig_len > 10_000 { return Err(format!("implausible script_sig length {sig_len}")); }
            let script_sig = read_bytes(&mut cur, sig_len as usize)?;
            let sequence = read_u32_le(&mut cur)?;
            inputs.push(TxInput { prev_txid, prev_index, script_sig, sequence });
        }
        let out_count = pre_fix_varint(&mut cur)?;
        if out_count > 100_000 { return Err(format!("implausible output count {out_count}")); }
        let mut outputs = Vec::new();
        for _ in 0..out_count {
            let value = read_u64_le(&mut cur)?;
            let spk_len = pre_fix_varint(&mut cur)?;
            if spk_len > 10_000 { return Err(format!("implausible script_pubkey length {spk_len}")); }
            let script_pubkey = read_bytes(&mut cur, spk_len as usize)?;
            outputs.push(TxOutput { value, script_pubkey });
        }
        let locktime = read_u32_le(&mut cur)?;
        Ok(Transaction { version, inputs, outputs, locktime })
    }

    fn pre_fix_shielded(cur: &mut Cursor<&[u8]>) -> Result<coherence_core::ShieldedTx, String> {
        let anchor = read_32(cur)?;
        let nf_n = pre_fix_varint(cur)?;
        if nf_n > 100_000 { return Err(format!("implausible nullifier count {nf_n}")); }
        let mut nullifiers = Vec::new();
        for _ in 0..nf_n { nullifiers.push(read_32(cur)?); }
        let out_n = pre_fix_varint(cur)?;
        if out_n > 100_000 { return Err(format!("implausible output count {out_n}")); }
        let mut outputs = Vec::new();
        for _ in 0..out_n { outputs.push(read_32(cur)?); }
        let fee = read_u64_le(cur)?;
        let proof_len = pre_fix_varint(cur)?;
        if proof_len > 8_000_000 { return Err(format!("implausible proof length {proof_len}")); }
        let proof = read_bytes(cur, proof_len as usize)?;
        let sig_len = pre_fix_varint(cur)?;
        if sig_len > 100_000 { return Err(format!("implausible binding_sig length {sig_len}")); }
        let binding_sig = read_bytes(cur, sig_len as usize)?;
        Ok(coherence_core::ShieldedTx { anchor, nullifiers, outputs, fee, proof, binding_sig })
    }

    fn pre_fix_block(bytes: &[u8]) -> Result<Block, String> {
        let mut cur = Cursor::new(bytes);
        let version = read_u32_le(&mut cur)?;
        let n = pre_fix_varint(&mut cur)?;
        if n > MAX_PARENTS as u64 { return Err(format!("implausible parent count {n}")); }
        let mut parents = Vec::new();
        for _ in 0..n { parents.push(read_32(&mut cur)?); }
        let merkle_root = MerkleRoot(read_32(&mut cur)?);
        let timestamp = read_u64_le(&mut cur)?;
        let bits = read_u32_le(&mut cur)?;
        let nonce = read_u64_le(&mut cur)?;
        let blue_score = read_u64_le(&mut cur)?;
        let height = read_u64_le(&mut cur)?;
        let header = BlockHeader { version, parents, merkle_root, timestamp, bits, nonce };
        let body = &bytes[cur.position() as usize..];
        let mut cur = Cursor::new(body);
        let tx_count = pre_fix_varint(&mut cur)?;
        if tx_count > 1_000_000 { return Err(format!("implausible tx count {tx_count}")); }
        let mut offset = cur.position() as usize;
        let mut transactions = Vec::new();
        for _ in 0..tx_count {
            let tx = pre_fix_tx(&body[offset..])?;
            offset += tx.to_wire_bytes(true).len();
            transactions.push(tx);
        }
        let mut sh_cur = Cursor::new(&body[offset..]);
        let sh_count = pre_fix_varint(&mut sh_cur)?;
        if sh_count > 100_000 { return Err(format!("implausible shielded count {sh_count}")); }
        let mut shielded_transactions = Vec::new();
        for _ in 0..sh_count { shielded_transactions.push(pre_fix_shielded(&mut sh_cur)?); }
        offset += sh_cur.position() as usize;
        // The PoWit section (from powit_height), read as the real decoder does.
        let powit = if powit_active(height) {
            let mut pc = Cursor::new(&body[offset..]);
            let pb = powit::PowitBody::read_wire(&mut pc).map_err(|e| format!("powit section: {e}"))?;
            offset += pc.position() as usize;
            pb
        } else {
            powit::PowitBody::default()
        };
        if offset != body.len() { return Err("trailing bytes in block body".into()); }
        Ok(Block { header, transactions, blue_score, height, shielded_transactions, powit })
    }

    /// Bytes the pre-fix decoder accepts are either accepted by the current
    /// decoder as the same block, or refused with the minimal-varint error
    /// (`is_non_minimal_varint_error`), never with another error: a node
    /// can answer a widened copy relayed by an older node without a penalty
    /// and keep the penalty for every other malformed block. Frames: every
    /// one-byte value widened to the 3-, 5- and 9-byte forms, and seeded
    /// random byte edits of those and of the canonical encodings.
    #[test]
    fn pre_fix_acceptances_fail_on_a_non_minimal_varint() {
        let fd00 = u32::from_le_bytes([0x11, 0x22, 0xFD, 0x00]);
        let mut shielded = block(vec![tx(3, 0)]);
        shielded.shielded_transactions = vec![coherence_core::ShieldedTx {
            anchor: [5; 32], nullifiers: vec![[6; 32]], outputs: vec![[7; 32], [8; 32]], fee: 3,
            proof: vec![1, 2, 3], binding_sig: vec![4; 5],
        }];
        let bases = [
            block(vec![tx(12, fd00)]),
            block(vec![tx(0xFC, 7), tx(1, 0x00FD_0000), tx(12, fd00)]),
            block(vec![tx(0xFD, 1), tx(0, 2)]),
            shielded,
        ];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let (mut frames, mut newly_refused, mut misframed) = (0usize, 0usize, 0usize);
        for b in &bases {
            let w = b.to_wire_bytes();
            // The transactions' bytes (after the header and the 1-byte count).
            let txs_at = b.header.to_wire_bytes(b.blue_score, b.height).len() + 1;
            let txs_end = txs_at + b.transactions.iter().map(|t| t.wire_size(true)).sum::<usize>();
            // (frame, widened inside a transaction)
            let mut cands = vec![(w.clone(), false)];
            for at in 0..w.len() {
                if w[at] < 0xFD {
                    for form in [&[0xFD, w[at], 0][..], &[0xFE, w[at], 0, 0, 0], &[0xFF, w[at], 0, 0, 0, 0, 0, 0, 0]] {
                        let mut v = w[..at].to_vec();
                        v.extend_from_slice(form);
                        v.extend_from_slice(&w[at + 1..]);
                        cands.push((v, (txs_at..txs_end).contains(&at)));
                    }
                }
            }
            for i in 0..cands.len() * 4 {
                let mut v = cands[i % cands.len()].0.clone();
                for _ in 0..1 + rnd(3) {
                    let at = rnd(v.len());
                    match rnd(3) {
                        0 => v[at] = rnd(256) as u8,
                        1 => v.insert(at, rnd(256) as u8),
                        _ => { v.remove(at); }
                    }
                }
                cands.push((v, false));
            }
            for (f, in_tx) in &cands {
                frames += 1;
                match (pre_fix_block(f), Block::from_wire_bytes(f)) {
                    (old, Ok(new)) => {
                        assert_eq!(new.to_wire_bytes(), *f, "an accepted frame is the encoding of its block");
                        let old = old.expect("bytes the current decoder accepts were accepted before");
                        assert_eq!(old.to_wire_bytes(), *f);
                    }
                    (Ok(_), Err(e)) => {
                        assert!(is_non_minimal_varint_error(&e),
                            "bytes the pre-fix decoder accepted are refused for another reason: {e}");
                        newly_refused += 1;
                        // Widened inside a transaction: framed at the
                        // re-encoded length, the old decoder read the next
                        // field from inside that transaction and still "fit".
                        if *in_tx {
                            misframed += 1;
                        }
                    }
                    (Err(_), Err(_)) => {}
                }
            }
        }
        assert!(frames > 20_000, "{frames} frames");
        assert!(newly_refused > 100, "{newly_refused} frames newly refused");
        assert!(misframed >= 2, "{misframed} mis-framed acceptances");
    }
}

#[cfg(test)]
mod validate_coinbase_value_tests {
    use super::*;

    fn one_output_coinbase_block(height: u64, miner_value: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                parents: vec![],
                merkle_root: MerkleRoot([0u8; 32]),
                timestamp: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: u32::MAX,
                    script_sig: vec![],
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOutput { value: miner_value, script_pubkey: vec![0u8; 20] }],
                locktime: 0,
            }],
            blue_score: 0,
            height,
            shielded_transactions: vec![], powit: Default::default(),
        }
    }

    #[test]
    fn overflowing_subsidy_plus_fees_is_rejected_not_clamped() {
        let block = one_output_coinbase_block(1, u64::MAX);
        assert_eq!(
            block.validate_coinbase_value(u64::MAX),
            Err("coinbase reward computation overflowed (subsidy + fees)"),
        );
    }

    #[test]
    fn subsidy_plus_fees_is_the_exact_limit() {
        let subsidy = tokenomics::block_subsidy_sat(1);
        let fees = 1_000u64;
        assert_eq!(one_output_coinbase_block(1, subsidy + fees).validate_coinbase_value(fees), Ok(()));
        assert_eq!(
            one_output_coinbase_block(1, subsidy + fees + 1).validate_coinbase_value(fees),
            Err("miner coinbase output exceeds allowed amount"),
        );
    }

    #[test]
    fn genesis_height_pays_only_fees() {
        assert_eq!(one_output_coinbase_block(0, 0).validate_coinbase_value(0), Ok(()));
        assert!(one_output_coinbase_block(0, 1).validate_coinbase_value(0).is_err());
    }

    #[test]
    fn coinbase_must_have_exactly_one_output() {
        let mut b = one_output_coinbase_block(1, 1);
        b.transactions[0].outputs.push(TxOutput { value: 1, script_pubkey: vec![1u8; 20] });
        assert_eq!(b.validate_coinbase_value(0), Err("coinbase must have 1 output (miner)"));
    }
}

// ── Sprint U.1: Reorg undo data ───────────────────────────────────────────────
//
// Audit finding C-1: accept_block is forward-only. When a fork with higher
// blue work replaces the current selected chain, UTXOs mutated by the
// losing branch must be reverted. We persist an UndoData record per block
// so the eventual rollback_block() primitive (Sprint U.2) can replay the
// mutations in reverse. Kept for every connected block (never pruned): there
// is no reorg-depth limit (audit DAG-6).

/// A single input consumed by a block that must be restored on rollback.
/// Captures the full pre-spend output so we can re-insert it verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoEntry {
    pub prev_txid:  [u8; 32],
    pub prev_index: u32,
    pub output:     TxOutput,
}

/// Rows a block REPLACED when it was applied (audit VAL-2 undo fix): an
/// output whose outpoint was already unspent (a duplicate coinbase txid
/// before the hardening activation), the coinbase-height row of a reused
/// coinbase txid, and the tx-index row of a reused txid. Rollback deletes the
/// block's own rows and then restores these, so a node that applied and then
/// disconnected the block ends with exactly the state of a node that never
/// applied it. Empty for every block that overwrote nothing (all of them in
/// practice, and every block at/after the activation for UTXOs: BIP30).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UndoOverwrites {
    /// Unspent coins replaced by an output of the block, with their old value.
    pub utxos:            Vec<UndoEntry>,
    /// Coinbase-height rows replaced: (txid, previous height).
    pub coinbase_heights: Vec<([u8; 32], u64)>,
    /// Tx-index rows replaced: (txid, previous block hash, previous height).
    pub tx_index:         Vec<([u8; 32], [u8; 32], u64)>,
}

impl UndoOverwrites {
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty() && self.coinbase_heights.is_empty() && self.tx_index.is_empty()
    }
}

/// Magic that introduces the version-1 undo extension ([`UndoOverwrites`])
/// after the legacy encoding of an [`UndoData`] record.
pub const UNDO_EXTENSION_MAGIC: [u8; 4] = *b"UDX1";

/// Everything accept_block mutated for a given block that rollback_block
/// needs to undo. Recorded on accept, replayed in reverse on reorg.
///
/// The four vectors mirror the four side effects in accept_block:
///   1. spent_utxos       — UTXOs deleted via delete_utxo (restore by re-put)
///   2. created_utxo_keys — UTXOs inserted via put_utxo    (undo by delete)
///   3. coinbase_txids    — coinbase rows in CF_COINBASE   (undo by delete)
///   4. tx_index_keys     — rows in CF_TX_INDEX            (undo by delete)
///
/// plus `overwritten`, the rows those inserts replaced (restored after the
/// deletes).
///
/// # Stored encoding (backward compatible)
///
/// [`UndoData::to_bytes`] writes the bincode (standard config) encoding of
/// the six legacy fields — byte-identical to the records written before the
/// extension existed — and, ONLY when `overwritten` is non-empty, appends
/// `UNDO_EXTENSION_MAGIC || bincode(UndoOverwrites)`. [`UndoData::from_bytes`]
/// decodes a record without trailing bytes (every record already on disk) as
/// having nothing overwritten. Old binaries ignore the trailing extension.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UndoData {
    pub block_hash:        [u8; 32],
    pub block_height:      u64,
    pub spent_utxos:       Vec<UndoEntry>,
    pub created_utxo_keys: Vec<([u8; 32], u32)>,
    pub coinbase_txids:    Vec<[u8; 32]>,
    pub tx_index_keys:     Vec<[u8; 32]>,
    /// Not part of the legacy serde encoding; stored as the trailing
    /// extension (see the type docs).
    #[serde(skip)]
    pub overwritten:       UndoOverwrites,
}

impl UndoData {
    pub fn new(block_hash: [u8; 32], block_height: u64) -> Self {
        Self {
            block_hash,
            block_height,
            spent_utxos:       Vec::new(),
            created_utxo_keys: Vec::new(),
            coinbase_txids:    Vec::new(),
            tx_index_keys:     Vec::new(),
            overwritten:       UndoOverwrites::default(),
        }
    }

    /// Total mutations recorded — useful for metrics & sanity tests.
    pub fn mutation_count(&self) -> usize {
        self.spent_utxos.len()
            + self.created_utxo_keys.len()
            + self.coinbase_txids.len()
            + self.tx_index_keys.len()
    }

    /// The stored encoding (see the type docs).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let cfg = bincode::config::standard();
        let mut out = bincode::serde::encode_to_vec(self, cfg)
            .map_err(|e| format!("undo record encode: {e}"))?;
        if !self.overwritten.is_empty() {
            out.extend_from_slice(&UNDO_EXTENSION_MAGIC);
            out.extend_from_slice(&bincode::serde::encode_to_vec(&self.overwritten, cfg)
                .map_err(|e| format!("undo extension encode: {e}"))?);
        }
        Ok(out)
    }

    /// Decode a stored record, legacy (no extension) or extended.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let cfg = bincode::config::standard();
        let (mut undo, used): (UndoData, usize) = bincode::serde::decode_from_slice(bytes, cfg)
            .map_err(|e| format!("undo record decode: {e}"))?;
        let rest = &bytes[used..];
        if rest.is_empty() {
            return Ok(undo);
        }
        if rest.len() < UNDO_EXTENSION_MAGIC.len() || rest[..UNDO_EXTENSION_MAGIC.len()] != UNDO_EXTENSION_MAGIC {
            return Err(format!("undo record: {} unexpected trailing byte(s)", rest.len()));
        }
        let body = &rest[UNDO_EXTENSION_MAGIC.len()..];
        let (ext, n): (UndoOverwrites, usize) = bincode::serde::decode_from_slice(body, cfg)
            .map_err(|e| format!("undo extension decode: {e}"))?;
        if n != body.len() {
            return Err(format!("undo extension: {} trailing byte(s)", body.len() - n));
        }
        undo.overwritten = ext;
        Ok(undo)
    }
}

// ── Genesis ───────────────────────────────────────────────────────────────────
//
// The GnB genesis state is the converted Bloch Genesis-3 carryover (see
// `carryover`) plus the locked team and founder tranches (see `vesting`),
// written into the UTXO set when the genesis is initialised; the genesis
// coinbase text commits to the snapshot's SHA3-256, the conversion and the
// vesting keys. The coinbase pays 0 to an unspendable all-zero script, so the
// first mined subsidy is at height 1. Its proof of work is a real GnB-SMH
// solution at GENESIS_BITS, found once by `gnb-mine-genesis` and baked below;
// the node refuses to start if the genesis does not validate.

/// Coinbase text of the genesis block.
pub const GENESIS_COINBASE_TEXT: &str =
    "GnB genesis: Godel and Bell, GnB-SMH memory-hard PoW, 12.5M GNB cap. \
Carryover Bloch G3 terminal snapshot sha3 3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d \
3810744000 BLCH -> 1000000 GNB. \
Team 1250000 + founder 1250000 GNB locked, 1y cliff + 36 monthly, keys sha3 \
e24828c3cc6d56fe635581b8214af8733f4b060784d13bd92f2d558940d90d20.";
/// Unix time of the genesis block (2026-10-11 02:27:28 UTC), the relaunch moment. Also the
/// ASERT anchor timestamp.
pub const GENESIS_TIMESTAMP: u64 = 1791685648;
/// Genesis difficulty and ASERT anchor bits: ≈ 4,500 evaluations per block,
/// i.e. 30 s at the launch hashrate (7 hosts × 11 threads ≈ 150 evaluations/s).
pub const GENESIS_BITS:      u32 = 0x1F0E_9036;
/// GnB-SMH nonce of the genesis block.
pub const GENESIS_NONCE:     u64 = 6499;
/// `block_hash()` of the genesis block:
/// a63fd2c124cf34312d2730609204dc3071b8924e24d54f938cf738968fb8f810.
pub const GENESIS_EXPECTED_HASH: [u8; 32] = [
    0xa6, 0x3f, 0xd2, 0xc1, 0x24, 0xcf, 0x34, 0x31,
    0x2d, 0x27, 0x30, 0x60, 0x92, 0x04, 0xdc, 0x30,
    0x71, 0xb8, 0x92, 0x4e, 0x24, 0xd5, 0x4f, 0x93,
    0x8c, 0xf7, 0x38, 0x96, 0x8f, 0xb8, 0xf8, 0x10,
];

/// Genesis block with explicit header parameters (used by the mining tool).
pub fn create_genesis_block_with(timestamp: u64, bits: u32, nonce: u64) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: GENESIS_COINBASE_TEXT.as_bytes().to_vec(),
            sequence:   u32::MAX,
        }],
        outputs: vec![TxOutput { value: 0, script_pubkey: vec![0u8; 20] }],
        locktime: 0,
    };
    let merkle = Transaction::merkle_root(std::slice::from_ref(&coinbase));
    Block {
        header: BlockHeader {
            version: 1,
            parents: vec![],
            merkle_root: merkle,
            timestamp,
            bits,
            nonce,
        },
        transactions: vec![coinbase],
        blue_score: 0,
        height: 0,
        shielded_transactions: Vec::new(), powit: Default::default(),
    }
}

/// The canonical GnB genesis block. Shared by mainnet and testnet; the two
/// networks are separated by chain id (sighash domain) and P2P identity.
pub fn genesis_block() -> Block {
    create_genesis_block_with(GENESIS_TIMESTAMP, GENESIS_BITS, GENESIS_NONCE)
}

// ── Difficulty helpers ────────────────────────────────────────────────────────
//
// Thin wrappers over `gnb_smh::difficulty` on plain big-endian byte arrays.

/// Decode compact `bits` into a big-endian target; malformed bits decode to
/// the all-zero target, which nothing meets (fail closed).
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    gnb_smh::difficulty::bits_to_target(bits).0
}

/// Encode a big-endian target in compact form (rounds down).
pub fn target_to_bits(target: &[u8; 32]) -> u32 {
    gnb_smh::difficulty::target_to_bits(&gnb_smh::difficulty::Target(*target))
}

/// `hash < target`, both big-endian. Strict, as in GnB-SMH.
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash < target
}

/// Chain-work contribution of a block at `bits`: ≈ 2^256 / target (exact
/// definition: `gnb_smh::difficulty::work`), 0 for
/// malformed bits.
pub fn bits_to_work(bits: u32) -> u128 {
    gnb_smh::difficulty::work_from_bits(bits)
}

/// Chain-work contribution of a block at `height` with `bits`: v3 blocks are
/// normalised by `POW_V3_DIFFICULTY_SHIFT` so cumulative work is continuous
/// across the switch. Every place that adds a block's work must call this.
pub fn block_work(bits: u32, height: u64) -> u128 {
    match pow_algo(height) {
        gnb_smh::Algo::V1 => bits_to_work(bits),
        gnb_smh::Algo::V3 => bits_to_work(bits) >> POW_V3_DIFFICULTY_SHIFT,
    }
}

fn u256_to_f64(v: primitive_types::U256) -> f64 {
    v.0.iter().rev().fold(0.0, |acc, &limb| acc * 18_446_744_073_709_551_616.0 + limb as f64)
}

/// Human-facing difficulty: expected GnB-SMH evaluations per block relative
/// to the pow limit (difficulty 1 = `POW_LIMIT_BITS`).
pub fn difficulty_from_bits(bits: u32) -> f64 {
    use primitive_types::U256;
    let limit  = U256::from_big_endian(&bits_to_target(POW_LIMIT_BITS));
    let target = U256::from_big_endian(&bits_to_target(bits));
    if target.is_zero() {
        return f64::INFINITY;
    }
    u256_to_f64(limit) / u256_to_f64(target)
}

/// Inverse of [`difficulty_from_bits`]: target for a (fractional) difficulty,
/// never easier than the pow limit.
pub fn difficulty_to_target(diff: f64) -> [u8; 32] {
    use primitive_types::U256;
    let limit = U256::from_big_endian(&bits_to_target(POW_LIMIT_BITS));
    if !diff.is_finite() || diff <= 1.0 {
        return limit.to_big_endian();
    }
    // limit / diff with 2^-32 resolution on diff: (limit / round(diff * 2^32)) * 2^32.
    let scaled = (diff * 4_294_967_296.0).min(3.4e38) as u128;
    let t = (limit / U256::from(scaled.max(1))) << 32;
    t.min(limit).to_big_endian()
}

#[cfg(test)]
mod powit_pow_tests {
    use super::*;
    use primitive_types::U256;

    /// Shared activation for this binary. Tests of the switch initialize it
    /// explicitly; ordinary low-height fixtures remain below it.
    pub(super) const TEST_ACTIVATION: u64 = 1 << 40;

    pub(super) fn activate() {
        set_powit_height_override(TEST_ACTIVATION).expect("one activation height per test binary");
    }

    #[test]
    fn algorithm_switches_exactly_at_activation() {
        assert_eq!(pow_algo_with(99, 100), gnb_smh::Algo::V1);
        assert_eq!(pow_algo_with(100, 100), gnb_smh::Algo::V3);
        assert_eq!(pow_algo_with(POWIT_HEIGHT_MAINNET - 1, POWIT_HEIGHT_MAINNET), gnb_smh::Algo::V1);
        activate();
        assert_eq!(pow_algo(TEST_ACTIVATION - 1), gnb_smh::Algo::V1);
        assert_eq!(pow_algo(TEST_ACTIVATION), gnb_smh::Algo::V3);
        assert!(!powit_active(TEST_ACTIVATION - 1) && powit_active(TEST_ACTIVATION));
    }

    #[test]
    fn v3_target_is_four_times_harder() {
        for bits in [GENESIS_BITS, POW_LIMIT_BITS, 0x1E0F_FFFF, 0x1D00_FFFF] {
            let t1 = U256::from_big_endian(&bits_to_target(bits));
            let t3 = U256::from_big_endian(&bits_to_target(adjust_bits_for_algo(bits, gnb_smh::Algo::V3)));
            // Compact encoding keeps 3 mantissa bytes, so allow its rounding.
            let want = t1 >> POW_V3_DIFFICULTY_SHIFT;
            assert!(t3 <= want && t3 >= want - (want >> 15), "bits 0x{bits:08x}");
            assert_eq!(adjust_bits_for_algo(bits, gnb_smh::Algo::V1), bits);
        }
    }

    #[test]
    fn chain_work_is_continuous_across_the_switch() {
        activate();
        let v1_bits = GENESIS_BITS;
        let v3_bits = adjust_bits_for_algo(v1_bits, gnb_smh::Algo::V3);
        let before = block_work(v1_bits, TEST_ACTIVATION - 1);
        let after = block_work(v3_bits, TEST_ACTIVATION);
        let diff = before.abs_diff(after);
        assert!(diff <= before >> 12, "work jumps across activation: {before} vs {after}");
    }

    #[test]
    fn v3_block_validates_only_with_v3() {
        activate();
        // The test target is far easier than the hardened pow limit (the
        // genesis target), so keep the hardening rules off here.
        let _h = activation::scoped_override(activation::NEVER);
        // Target 2^252: 1 in 16 evaluations pass, so v1 and v3 disagree often.
        let bits = target_to_bits(&(U256::MAX >> 4).to_big_endian());
        let mut b = genesis_block();
        b.height = TEST_ACTIVATION;
        b.header.bits = bits;
        let pre = b.header.pow_preimage();
        let target = gnb_smh::difficulty::bits_to_target(bits);
        let mut nonce = 0u64;
        loop {
            let v3_ok = gnb_smh::verify_algo(gnb_smh::Algo::V3, &pre, nonce, &target);
            let v1_ok = gnb_smh::verify_algo(gnb_smh::Algo::V1, &pre, nonce, &target);
            if v3_ok && !v1_ok { break; }
            nonce += 1;
            assert!(nonce < 4_000, "no separating nonce found");
        }
        b.header.nonce = nonce;
        assert!(b.validate_pow(), "v3 proof must validate at the activation height");
        assert_eq!(b.header.pow_hash(TEST_ACTIVATION), gnb_smh::v3::hash_thread_local(&pre, nonce));

        let mut early = b.clone();
        early.height = TEST_ACTIVATION - 1;
        early.header.timestamp += 1; // different block id, so no pow-cache hit
        let pre_e = early.header.pow_preimage();
        let mut n = 0u64;
        loop {
            let v3_ok = gnb_smh::verify_algo(gnb_smh::Algo::V3, &pre_e, n, &target);
            let v1_ok = gnb_smh::verify_algo(gnb_smh::Algo::V1, &pre_e, n, &target);
            if v3_ok && !v1_ok { break; }
            n += 1;
            assert!(n < 4_000);
        }
        early.header.nonce = n;
        assert!(!early.validate_pow(), "a v3-only proof must fail below the activation height");
    }
}

/// [`MIN_CHAIN_WORK`] against the reading it is derived from
/// (docs/MAINNET-READINESS.md §1) and the ASERT arithmetic that relates a
/// chain's height and time to its work. Every input is a constant, so the
/// relations are stable; they catch a value in another unit (a hexadecimal
/// reading taken as decimal, a blue score, an unnormalised v3 work) or one
/// above the reading.
#[cfg(test)]
mod min_chain_work_tests {
    use super::*;

    /// The reading: mainnet tip height 8,302 (all GnB-SMH v1 blocks, below
    /// the PoWit height 10,000 and the hardening activation 17,500),
    /// `getdaginfo` `tip_blue_work` 7,782,451, on 2026-10-14 04:25 UTC.
    const READING_HEIGHT: u64 = 8_302;
    const READING_WORK: u128 = 7_782_451;
    const READING_TIME: u64 = 1_791_951_900;

    fn asert_work(parent_time: u64, height: u64) -> u128 {
        // Pre-activation pow limit, v1 (both readings and every height here
        // are below the mainnet switches, whatever this test binary's PoWit
        // override).
        bits_to_work(expected_bits_at(parent_time, height, activation::MAINNET_HARDENING_ACTIVATION_HEIGHT).unwrap())
    }

    #[test]
    fn min_chain_work_cross_check() {
        // The unit. Per-block work at the ASERT anchor (genesis target) and
        // at the pre-activation pow limit; a v3 block on the same ASERT
        // target (4x harder) counts the same once normalised.
        assert_eq!(bits_to_work(GENESIS_BITS), 4_500);
        assert_eq!(bits_to_work(POW_LIMIT_BITS), 1);
        let v3 = adjust_bits_for_algo(GENESIS_BITS, gnb_smh::Algo::V3);
        assert_eq!(bits_to_work(v3), 18_000);
        assert_eq!(bits_to_work(v3) >> POW_V3_DIFFICULTY_SHIFT, 4_500);

        // The reading in that unit. 573 blocks behind the schedule, the next
        // block's ASERT work is 859 (4,500 * 2^(-573/240)). A chain mined at
        // a steady rate H from genesis settles at a constant lag where a
        // block's work is 30 s * H, and its work is H * elapsed: here
        // 859 * 8,875 = 7,623,625. The reading is within 3% of it (a steady
        // ~29.2 evaluations/s, i.e. the one 28-thread v1 miner).
        let elapsed = READING_TIME - GENESIS_TIMESTAMP;
        let schedule = elapsed / TARGET_BLOCK_TIME;
        assert_eq!((elapsed, schedule, schedule - READING_HEIGHT), (266_252, 8_875, 573));
        let w_next = asert_work(READING_TIME, READING_HEIGHT + 1);
        assert_eq!(w_next, 859);
        let steady = w_next * u128::from(schedule);
        assert!(READING_WORK * 100 >= steady * 97 && READING_WORK * 100 <= steady * 103,
            "reading {READING_WORK} vs steady-rate model {steady}");
        // Consensus floor: no chain of that height can carry less work than
        // one whose every block is stamped at the reading time (the easiest
        // targets ASERT gives); the minimum is far above it, so it excludes
        // the cheapest chains, while the pow limit alone would admit 8,302.
        let floor: u128 = (1..=READING_HEIGHT).map(|h| asert_work(READING_TIME, h)).sum();
        assert_eq!(floor, 301_774);
        assert!(floor < MIN_CHAIN_WORK && u128::from(READING_HEIGHT) < floor);

        // The constant: 7,000,000 = 0x6acfc0, 10% below the reading (about
        // 900 blocks of 859), never above it.
        assert_eq!(MIN_CHAIN_WORK, 0x6a_cfc0);
        assert!(MIN_CHAIN_WORK > READING_WORK - 1_000 * w_next, "within ~1,000 blocks of it");
    }

    // At least 10% below the reading (checked at compile time).
    const _: () = assert!(MIN_CHAIN_WORK * 10 <= READING_WORK * 9);
}

#[cfg(test)]
mod difficulty_tests {
    use super::*;

    #[test]
    fn pow_limit_is_difficulty_one() {
        assert!((difficulty_from_bits(POW_LIMIT_BITS) - 1.0).abs() < 1e-9);
        assert!(difficulty_from_bits(GENESIS_BITS) > 200.0);
        assert_eq!(difficulty_from_bits(0xFF00_FFFF), f64::INFINITY);
    }

    #[test]
    fn malformed_bits_fail_closed() {
        assert_eq!(bits_to_target(0x0480_0001), [0u8; 32]);
        assert_eq!(bits_to_work(0x0480_0001), 0);
        assert!(!hash_meets_target(&[0u8; 32], &bits_to_target(0x0480_0001)));
    }

    #[test]
    fn target_compare_is_strict() {
        let t = bits_to_target(GENESIS_BITS);
        assert!(!hash_meets_target(&t, &t));
    }

    #[test]
    #[cfg_attr(feature = "test-pow-limit", ignore = "test-pow-limit pins expected bits")]
    fn expected_bits_at_schedule_is_genesis_bits() {
        assert_eq!(expected_bits(GENESIS_TIMESTAMP, 1).unwrap(), GENESIS_BITS);
        assert_eq!(expected_bits(GENESIS_TIMESTAMP + 30 * 99, 100).unwrap(), GENESIS_BITS);
        // Late chain: the target eases toward the pow limit, never past it.
        let late = expected_bits(GENESIS_TIMESTAMP + 365 * 86_400, 1).unwrap();
        assert_eq!(late, target_to_bits(&bits_to_target(POW_LIMIT_BITS)));
        assert!(expected_bits(u64::MAX, 1).is_err());
    }

    #[test]
    fn genesis_block_shape() {
        let g = genesis_block();
        assert_eq!(g.height, 0);
        assert!(g.header.parents.is_empty());
        assert!(g.validate_merkle());
        assert!(g.validate_coinbase_format());
        assert_eq!(g.validate_coinbase_value(0), Ok(()));
        assert_eq!(g.transactions[0].outputs[0].value, 0);
    }

    #[test]
    fn genesis_pow_is_valid() {
        let g = genesis_block();
        assert!(g.validate_pow(), "genesis nonce does not meet GENESIS_BITS");
        if GENESIS_EXPECTED_HASH != [0u8; 32] {
            assert_eq!(g.block_hash(), GENESIS_EXPECTED_HASH);
        }
    }
}

// ── Roadmap #8 §1 — chain-id sighash replay regression ───────────────────────
#[cfg(test)]
mod chain_id_tests {
    use super::*;

    fn two_input_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![
                TxInput { prev_txid: [3u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff },
                TxInput { prev_txid: [4u8; 32], prev_index: 1, script_sig: vec![], sequence: 0xffff_ffff },
            ],
            outputs: vec![TxOutput { value: 42, script_pubkey: vec![9u8; 20] }],
            locktime: 0,
        }
    }

    #[test]
    fn chain_id_registry_values() {
        assert_eq!(ChainId::Mainnet.to_u32(), 0x474E_0001);
        assert_eq!(ChainId::Testnet.to_u32(), 0x474E_0002);
        assert_eq!(ChainId::Mainnet.to_le_bytes(), [0x01, 0x00, 0x4E, 0x47]);
        assert_eq!(ChainId::for_network(crate::address::Network::Mainnet), ChainId::Mainnet);
        assert_eq!(ChainId::for_network(crate::address::Network::Testnet), ChainId::Testnet);
    }

    #[test]
    fn sighash_is_domain_and_chain_separated() {
        let tx = two_input_tx();
        // Distinct per chain-id.
        assert_ne!(tx.sighash(0, ChainId::Mainnet), tx.sighash(0, ChainId::Testnet),
                   "mainnet and testnet must sign different digests");
        // Still distinct per input index (v1 property preserved).
        assert_ne!(tx.sighash(0, ChainId::Mainnet), tx.sighash(1, ChainId::Mainnet));
    }

    /// The core invariant (design §4.3.4): a signature valid under Mainnet MUST
    /// be rejected when verified under Testnet — cross-chain replay ⇒ false.
    #[test]
    fn cross_chain_id_replay_is_rejected() {
        let tx = two_input_tx();
        let (pk, sk) = crate::crypto::generate_keypair();

        let h_main = tx.sighash(0, ChainId::Mainnet);
        let sig = crate::crypto::sign(&sk, &h_main).unwrap();

        // Same chain: accepts.
        assert!(crate::crypto::verify(&pk, &h_main, &sig),
                "a correctly chain-id'd signature must verify");
        // Replay onto testnet: the verifier recomputes with the Testnet domain →
        // a different digest → both ML-DSA and Falcon fail.
        let h_test = tx.sighash(0, ChainId::Testnet);
        assert!(!crate::crypto::verify(&pk, &h_test, &sig),
                "cross-chain-id replay MUST be rejected");
    }
}


#[cfg(test)]
mod canonical_encoding_tests {
    use super::*;

    fn varint(bytes: &[u8]) -> Result<u64, String> {
        read_varint(&mut Cursor::new(bytes))
    }

    /// Each value has exactly one varint encoding (CompactSize rules).
    #[test]
    fn non_canonical_varints_are_refused() {
        assert_eq!(varint(&[0xFC]), Ok(0xFC));
        assert_eq!(varint(&[0xFD, 0xFD, 0x00]), Ok(0xFD));
        assert!(varint(&[0xFD, 0x05, 0x00]).is_err(), "5 must be one byte");
        assert_eq!(varint(&[0xFE, 0x00, 0x00, 0x01, 0x00]), Ok(0x1_0000));
        assert!(varint(&[0xFE, 0xFF, 0xFF, 0x00, 0x00]).is_err());
        assert!(varint(&[0xFF, 1, 0, 0, 0, 0, 0, 0, 0]).is_err());
        for v in [0u64, 0xFC, 0xFD, 0xFFFF, 0x1_0000, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            assert_eq!(varint(&out), Ok(v), "round trip {v}");
        }
    }

    /// A single-key witness is exactly `len‖sig‖len‖pk`: trailing bytes
    /// (a relay padding a block) make it malformed.
    #[test]
    fn script_sig_must_have_exact_length() {
        let ss = Transaction::build_script_sig(&[1u8; 10], &[2u8; 12]);
        assert_eq!(Transaction::parse_script_sig(&ss), Some((vec![1u8; 10], vec![2u8; 12])));
        let mut padded = ss.clone();
        padded.push(0);
        assert_eq!(Transaction::parse_script_sig(&padded), None);
        assert_eq!(Transaction::parse_script_sig(&ss[..ss.len() - 1]), None);
        let mut huge = ss.clone();
        huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Transaction::parse_script_sig(&huge), None, "length overflow is refused, not a panic");
    }

    /// The sighash commits to the wire encoding: it changes with every field
    /// it covers, and differs per input and per chain.
    #[test]
    fn sighash_is_over_the_wire_encoding() {
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: vec![9; 50], sequence: u32::MAX },
                TxInput { prev_txid: [2; 32], prev_index: 1, script_sig: vec![], sequence: u32::MAX },
            ],
            outputs: vec![TxOutput { value: 5_000, script_pubkey: vec![3; 20] }],
            locktime: 7,
        };
        let h = tx.sighash(0, ChainId::Mainnet);
        let mut stripped = tx.clone();
        stripped.inputs[0].script_sig = b"GNB_SIGHASH".to_vec();
        stripped.inputs[1].script_sig = vec![];
        let mut pre = SIGHASH_DOMAIN.to_vec();
        pre.push(SIGHASH_VERSION);
        pre.extend_from_slice(&ChainId::Mainnet.to_le_bytes());
        pre.extend_from_slice(&stripped.to_wire_bytes(true));
        assert_eq!(h, <[u8; 32]>::from(Sha3_256::digest(&pre)));
        assert_ne!(h, tx.sighash(1, ChainId::Mainnet));
        assert_ne!(h, tx.sighash(0, ChainId::Testnet));
        let mut other = tx.clone();
        other.outputs[0].value += 1;
        assert_ne!(h, other.sighash(0, ChainId::Mainnet));
        let mut witness_only = tx.clone();
        witness_only.inputs[0].script_sig = vec![1; 3];
        assert_eq!(h, witness_only.sighash(0, ChainId::Mainnet), "witnesses are not signed");
    }

    /// From WITNESS_COMMITMENT_HEIGHT the coinbase must commit to every
    /// witness: a block without it, or with any witness changed afterwards,
    /// fails the structure check; below the height nothing is required.
    #[test]
    fn witness_commitment_binds_every_witness() {
        let spend = |w: u8| Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [w; 32], prev_index: 0, script_sig: vec![w; 40], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 10_000, script_pubkey: vec![3; 20] }],
            locktime: 0,
        };
        let mut b = genesis_block();
        b.transactions.push(spend(1));
        b.transactions.push(spend(2));
        b.height = WITNESS_COMMITMENT_HEIGHT - 1;
        b.header.merkle_root = Transaction::merkle_root(&b.transactions);
        assert!(b.validate_witness_commitment().is_ok(), "not required below the height");
        b.commit_witnesses();
        assert!(!b.transactions[0].inputs[0].script_sig.ends_with(WITNESS_COMMITMENT_TAG.as_slice())
                || b.height < WITNESS_COMMITMENT_HEIGHT);

        b.height = WITNESS_COMMITMENT_HEIGHT;
        assert!(b.validate_witness_commitment().is_err(), "required from the height");
        b.commit_witnesses();
        assert!(b.validate_witness_commitment().is_ok());
        assert!(b.validate_merkle(), "merkle root refreshed");

        // Same txids, different witness: the commitment no longer matches.
        let mut tampered = b.clone();
        tampered.transactions[2].inputs[0].script_sig[0] ^= 1;
        assert_eq!(Transaction::merkle_root(&tampered.transactions), b.header.merkle_root,
                   "the txid ignores witnesses");
        assert!(tampered.validate_witness_commitment().is_err(), "but the commitment covers them");

        // The commitment must be at the very end.
        let mut trailing = b.clone();
        trailing.transactions[0].inputs[0].script_sig.push(0);
        assert!(trailing.validate_witness_commitment().is_err());
    }

    /// The block size rule counts the wire bytes that are relayed and stored.
    #[test]
    fn block_size_is_the_wire_size() {
        let b = genesis_block();
        assert_eq!(b.size_bytes(), b.to_wire_bytes().len());
    }
}
// ── Hardening activation: core regressions (VAL-2 undo, VAL-12, POW-3) ──────
#[cfg(test)]
mod hardening_core_tests {
    use super::*;

    fn tx(n_in: usize, n_out: usize, ss: usize, spk: usize) -> Transaction {
        Transaction {
            version: 7,
            inputs: (0..n_in).map(|i| TxInput {
                prev_txid: [i as u8; 32], prev_index: i as u32, script_sig: vec![0xAB; ss], sequence: 3,
            }).collect(),
            outputs: (0..n_out).map(|i| TxOutput { value: 1_000 + i as u64, script_pubkey: vec![0xCD; spk] }).collect(),
            locktime: 9,
        }
    }

    /// VAL-12: the arithmetic wire size equals the encoding's length, across
    /// every varint width.
    #[test]
    fn wire_size_matches_the_encoding() {
        for (n_in, n_out, ss, spk) in [(0, 0, 0, 0), (1, 1, 0, 5), (2, 3, 252, 20), (1, 1, 253, 0xFFFF),
                                      (300, 2, 10, 20), (1, 260, 4, 0x1_0000)] {
            let t = tx(n_in, n_out, ss, spk);
            for with_ss in [false, true] {
                assert_eq!(t.wire_size(with_ss), t.to_wire_bytes(with_ss).len(), "{n_in} {n_out} {ss} {spk}");
            }
        }
        let mut b = genesis_block();
        b.transactions.push(tx(2, 2, 300, 20));
        b.header.parents = vec![[1u8; 32]; 3];
        b.shielded_transactions.push(coherence_core::ShieldedTx {
            anchor: [1; 32], nullifiers: vec![[2; 32]; 3], outputs: vec![[3; 32]; 300], fee: 5,
            proof: vec![9; 70_000], binding_sig: vec![8; 64],
        });
        assert_eq!(b.wire_size(), b.to_wire_bytes().len());
        assert_eq!(genesis_block().wire_size(), genesis_block().to_wire_bytes().len());
        // From powit_height the encoding carries the PoWit section.
        let mut p = genesis_block();
        p.height = u64::MAX;
        assert!(powit_active(p.height));
        assert_eq!(p.wire_size(), p.to_wire_bytes().len());
    }

    /// The 6-field record layout written before the extension existed.
    #[derive(Serialize)]
    struct LegacyUndo {
        block_hash: [u8; 32],
        block_height: u64,
        spent_utxos: Vec<UndoEntry>,
        created_utxo_keys: Vec<([u8; 32], u32)>,
        coinbase_txids: Vec<[u8; 32]>,
        tx_index_keys: Vec<[u8; 32]>,
    }

    fn sample() -> UndoData {
        let mut u = UndoData::new([0x42; 32], 7);
        u.spent_utxos.push(UndoEntry { prev_txid: [1; 32], prev_index: 2, output: TxOutput { value: 3, script_pubkey: vec![4; 20] } });
        u.created_utxo_keys.push(([5; 32], 0));
        u.coinbase_txids.push([5; 32]);
        u.tx_index_keys.push([5; 32]);
        u
    }

    /// VAL-2: records already on disk (legacy layout, no extension) still
    /// decode, and a record that overwrote nothing is still written
    /// byte-identically to the legacy layout.
    #[test]
    fn undo_records_stay_backward_compatible() {
        let u = sample();
        let legacy = bincode::serde::encode_to_vec(&LegacyUndo {
            block_hash: u.block_hash, block_height: u.block_height, spent_utxos: u.spent_utxos.clone(),
            created_utxo_keys: u.created_utxo_keys.clone(), coinbase_txids: u.coinbase_txids.clone(),
            tx_index_keys: u.tx_index_keys.clone(),
        }, bincode::config::standard()).unwrap();
        assert_eq!(u.to_bytes().unwrap(), legacy, "no overwrite: byte-identical to the legacy record");
        // Golden prefix: the legacy encoding starts with the raw block hash.
        assert_eq!(&legacy[..32], &[0x42; 32]);
        assert_eq!(legacy[32], 7, "height 7 as a one-byte varint");
        let back = UndoData::from_bytes(&legacy).unwrap();
        assert_eq!(back.block_height, 7);
        assert_eq!(back.spent_utxos.len(), 1);
        assert!(back.overwritten.is_empty());

        // With an extension: round-trips, and an old decoder (plain bincode)
        // still reads the six legacy fields.
        let mut x = sample();
        x.overwritten.utxos.push(UndoEntry { prev_txid: [5; 32], prev_index: 0, output: TxOutput { value: 77, script_pubkey: vec![6; 20] } });
        x.overwritten.coinbase_heights.push(([5; 32], 3));
        x.overwritten.tx_index.push(([5; 32], [0x99; 32], 3));
        let bytes = x.to_bytes().unwrap();
        assert_eq!(&bytes[..legacy.len()], &legacy[..]);
        assert_eq!(&bytes[legacy.len()..legacy.len() + 4], b"UDX1");
        let back = UndoData::from_bytes(&bytes).unwrap();
        assert_eq!(back.overwritten.utxos[0].output.value, 77);
        assert_eq!(back.overwritten.coinbase_heights, vec![([5; 32], 3)]);
        assert_eq!(back.overwritten.tx_index, vec![([5; 32], [0x99; 32], 3)]);
        let (old_view, _): (UndoData, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(old_view.block_height, 7);

        // Garbage after a record is refused, not silently dropped.
        let mut junk = legacy.clone();
        junk.extend_from_slice(b"XXXX");
        assert!(UndoData::from_bytes(&junk).is_err());
        let mut junk = bytes.clone();
        junk.push(0);
        assert!(UndoData::from_bytes(&junk).is_err());
    }

    /// POW-3 at the boundary, on the real ASERT path (explicit activation):
    /// a chain far behind schedule eases to POW_LIMIT_BITS below the
    /// activation and is clamped to the genesis target from it.
    #[test]
    fn pow_limit_clamp_switches_at_the_activation_height() {
        let late = GENESIS_TIMESTAMP + 365 * 86_400;
        let act = 1_000;
        let below = expected_bits_at(late, act - 1, act).unwrap();
        let at = expected_bits_at(late, act, act).unwrap();
        assert_eq!(below, target_to_bits(&bits_to_target(POW_LIMIT_BITS)));
        assert_eq!(at, GENESIS_BITS);
        assert_eq!(expected_bits_at(late, act + 1, act).unwrap(), GENESIS_BITS);
        // On schedule nothing changes; harder than genesis is never clamped.
        let on = GENESIS_TIMESTAMP + 30 * (act - 1);
        assert_eq!(expected_bits_at(on, act, act).unwrap(), GENESIS_BITS);
        let ahead = GENESIS_TIMESTAMP;
        assert_eq!(expected_bits_at(ahead, act, act).unwrap(), expected_bits_at(ahead, act, activation::NEVER).unwrap());
        // Mainnet schedule: identical to the pre-activation rule below its
        // activation height.
        for h in [1u64, 2, 100, activation::MAINNET_HARDENING_ACTIVATION_HEIGHT - 1] {
            assert_eq!(
                expected_bits_at(late, h, activation::MAINNET_HARDENING_ACTIVATION_HEIGHT).unwrap(),
                // From powit_height the v3 shift applies on top of ASERT.
                adjust_bits_for_algo(
                    gnb_smh::difficulty::asert_next_bits(&asert_params(), &asert_anchor(), late as i64, h).unwrap(),
                    pow_algo(h)),
            );
        }
        // The limit check validate_pow applies.
        let limit = bits_to_target(POW_LIMIT_BITS);
        assert!(Block::target_within_pow_limit_at(&limit, act - 1, act));
        assert!(!Block::target_within_pow_limit_at(&limit, act, act));
        assert!(Block::target_within_pow_limit_at(&bits_to_target(GENESIS_BITS), act, act));
    }

    /// validate_pow rejects a post-activation block claiming a target easier
    /// than genesis before evaluating anything.
    #[test]
    fn validate_pow_enforces_the_height_pow_limit() {
        if TEST_POW_LIMIT {
            return; // the dev-only feature pins the limit to POW_LIMIT_BITS
        }
        let mut b = genesis_block();
        b.header.bits = POW_LIMIT_BITS;
        b.header.parents = vec![[3u8; 32]];
        b.height = 5;
        let _g = activation::scoped_override(5);
        let t = std::time::Instant::now();
        assert!(!b.validate_pow(), "target above the genesis target at/after activation");
        assert!(t.elapsed() < std::time::Duration::from_millis(50), "rejected before any evaluation");
        drop(_g);
        let _g = activation::scoped_override(6);
        // Below the activation the pow-limit target is allowed: almost any
        // nonce passes (one or two evaluations).
        // Bounded: a broken proof check must fail the test, not hang it.
        assert!((0..32).any(|n| { b.header.nonce = n; b.validate_pow() }), "no valid nonce in 32");
    }
}

// Test-only fixture support, kept at the END of the file: the code the
// browser wallet core compiles keeps its line numbers (panic locations are
// part of the reproducible WASM, audit WAL-5).
#[cfg(feature = "test-pow-limit")]
impl Block {
    /// TEST FIXTURES ONLY — compiled only with the `test-pow-limit` feature,
    /// which the node binary refuses to run with. Records this block's id in
    /// the proof-of-work cache WITHOUT evaluating GnB-SMH, so integration
    /// tests can build thousand-block chains (one evaluation takes most of a
    /// second in a dev build). `validate_pow` still decodes `bits` and
    /// enforces the pow limit before it consults the cache, and every check
    /// after the proof (height, expected bits, timestamp, transactions,
    /// GhostDAG, connect) runs unchanged.
    pub fn test_only_assume_pow_valid(&self) {
        let id = self.block_hash();
        if let Ok(mut cache) = pow_cache().lock() {
            cache.insert(id);
        }
    }
}

// Added after the browser wallet core was pinned, so kept at the END of the
// file for the same reason as the fixture above (audit WAL-5).
impl PowCache {
    /// Record a verified block id; the oldest entry is evicted once more than
    /// `POW_CACHE_CAPACITY` ids are held (FIFO). Re-inserting a held id is a
    /// no-op.
    fn insert(&mut self, id: [u8; 32]) {
        if self.set.insert(id) {
            self.order.push_back(id);
            if self.order.len() > POW_CACHE_CAPACITY {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

/// Boundary and encoding tests of this module's consensus functions
/// (mutation-tested: docs/testing/MUTATION.md).
#[cfg(test)]
mod consensus_tests;

// Test seam for the node's real-ASERT tests (re-audit POW-5), kept at the
// END of the file like the fixture above (audit WAL-5). `test-pow-limit`
// pins `expected_bits` to the pow limit for every node test; a test that
// holds [`scoped_real_expected_bits`] gets the real ASERT rule on its
// thread, so the node's call sites (accept_block's height and parent
// timestamp, the template's bits, the ingress orphan floor) are exercised
// against it. Compiled with that feature and in this crate's own unit tests
// (`cfg(test)`, never in a build artifact): the mutation gate runs those
// tests without the feature, and `consensus_tests` tests the seam's state
// directly there, so its mutants are compiled and caught
// (docs/testing/MUTATION.md).
#[cfg(any(test, feature = "test-pow-limit"))]
thread_local! {
    static REAL_EXPECTED_BITS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the `test-pow-limit` pin applies to [`expected_bits`] on the
/// calling thread: true unless the thread holds a
/// [`scoped_real_expected_bits`] guard. Only a build with the feature has the
/// pin; without it `expected_bits` is the real rule whatever this returns.
#[cfg(any(test, feature = "test-pow-limit"))]
fn pow_limit_pinned_on_this_thread() -> bool {
    !REAL_EXPECTED_BITS.with(|c| c.get())
}

/// Restores the calling thread's previous `expected_bits` mode on drop.
#[cfg(any(test, feature = "test-pow-limit"))]
pub struct RealExpectedBitsGuard {
    previous: bool,
}

#[cfg(any(test, feature = "test-pow-limit"))]
impl Drop for RealExpectedBitsGuard {
    fn drop(&mut self) {
        let previous = self.previous;
        REAL_EXPECTED_BITS.with(|c| c.set(previous));
    }
}

/// TEST FIXTURES ONLY (`test-pow-limit`): until the guard drops,
/// [`expected_bits`] on the calling thread computes the real ASERT rule
/// ([`expected_bits_at`] under the process-wide activation height) instead
/// of returning the pinned pow limit.
#[cfg(any(test, feature = "test-pow-limit"))]
pub fn scoped_real_expected_bits() -> RealExpectedBitsGuard {
    RealExpectedBitsGuard { previous: REAL_EXPECTED_BITS.with(|c| c.replace(true)) }
}

// Test seam of package P5-G, kept at the END of the file like the fixtures
// above (audit WAL-5: the code the browser wallet core compiles keeps its
// line numbers).
#[cfg(feature = "test-pow-limit")]
impl Block {
    /// TEST FIXTURES ONLY (`test-pow-limit`): forget this block's verified
    /// proof of work in the process cache, as a restart of the node does, so
    /// a test can tell whether the node evaluates the proof again
    /// ([`Block::pow_is_cached`] afterwards).
    pub fn test_only_forget_pow(&self) {
        let id = self.block_hash();
        if let Ok(mut cache) = pow_cache().lock() {
            cache.set.remove(&id);
            cache.order.retain(|x| *x != id);
        }
    }
}
