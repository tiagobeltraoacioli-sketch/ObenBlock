//! GnB-SMH proof-of-work adapter: the seam between the block layer and the
//! `gnb-smh` crate.
//!
//! - Validation goes through `Block::validate_pow` (gnb-crypto), which runs
//!   GnB-SMH v1 at the canonical 64 MiB parameter and caches verified block ids.
//! - Difficulty goes through [`expected_bits`], ASERT anchored at genesis, a
//!   pure function of the parent set: the latest timestamp over ALL parents
//!   and the height max(parent heights) + 1 (not the GhostDAG selected
//!   parent's; see docs/CONSENSUS.md). The validator, the internal miner and
//!   `getblocktemplate` all call it.
//! - Mining here is a plain CPU search: one 64 MiB scratchpad per thread,
//!   disjoint nonce ranges, cooperative stop flag.
//! - Under the SHA-256d scheme (ObenBlock, `core::pow_scheme`) the built-in
//!   miner searches the 32-bit nonce of the 80-byte header instead
//!   ([`mine_sha256d_parallel`]); [`mine_header_round`] picks the scheme the
//!   process runs. It is a CPU miner for regtest and development; real
//!   SHA-256d hashrate comes from ASICs through `getblocktemplate`
//!   (docs/OBENBLOCK-MINING.md).

pub mod verifier;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};


/// Chain-work contribution of a block at compact `bits` (≈ 2^256 / target;
/// exact definition: `gnb_smh::difficulty::work`).
#[inline]
pub fn work_from_bits(bits: u32) -> u128 {
    gnb_crypto::core::bits_to_work(bits)
}

/// Chain-work contribution of a block at `height` (normalised across the
/// v1 -> v3 switch, see `core::block_work`).
#[inline]
pub fn block_work(bits: u32, height: u64) -> u128 {
    gnb_crypto::core::block_work(bits, height)
}

/// Expected `bits` for the block at `height` (= max parent height + 1) whose
/// parents' LATEST timestamp is `parent_timestamp` (see
/// `core::difficulty_parent_timestamp`). CONSENSUS-CRITICAL: miner and
/// validator must call exactly this.
#[inline]
pub fn expected_bits(parent_timestamp: u64, height: u64) -> Result<u32, String> {
    gnb_crypto::core::expected_bits(parent_timestamp, height)
}

/// The proof-of-work check of a block whose id is ALREADY in the DAG: a body
/// restored for it (`accept::accept_block`'s body replacement: a body pruned
/// and needed again, audit DAG-6, or one rejected for a witness-dependent
/// reason). Its header entered the DAG only after `Block::validate_pow`
/// passed at this same header height: the id commits to the proof's
/// preimage and nonce, and acceptance binds the copy's height to the parents
/// the id commits before calling this. The DAG record is therefore the
/// verified result of this very proof, kept across restarts for free (P5-G:
/// a PoW result cache keyed by header hash). Only `validate_pow`'s cheap
/// checks run again — canonical bits and a target within the pow limit of
/// the height, which an older release may have judged under another limit —
/// never the GnB-SMH evaluation (64 MiB and about half a second for v1),
/// which used to run again for every restored body once the process cache
/// had forgotten it (any restart). Bitcoin Core re-checks a header's proof
/// when the block's data arrives because it costs one SHA-256d.
pub fn proof_recorded_in_dag(block: &gnb_crypto::core::Block) -> bool {
    match gnb_smh::difficulty::try_canonical_bits_to_target(block.header.bits) {
        Some(t) => t.0 <= gnb_crypto::core::Block::pow_limit_target_for_height(block.height),
        None => false,
    }
}

/// Verify a (preimage, nonce) pair for a block at `height` against compact `bits`.
pub fn verify(pow_preimage: &[u8], nonce: u64, bits: u32, height: u64) -> bool {
    match gnb_smh::difficulty::try_bits_to_target(bits) {
        Ok(target) => gnb_smh::verify_algo(gnb_crypto::core::pow_algo(height), pow_preimage, nonce, &target),
        Err(_) => false,
    }
}

/// Single-threaded search over `[start_nonce, start_nonce + max_attempts)`
/// for a block at `height`.
pub fn mine(pow_preimage: &[u8], bits: u32, height: u64, start_nonce: u64, max_attempts: u64) -> Option<u64> {
    mine_parallel(pow_preimage, bits, height, start_nonce, max_attempts, 1, None)
}

/// Search with `threads` workers, each over a disjoint nonce range of
/// `attempts_per_thread` nonces starting at `start_nonce + k * attempts_per_thread`.
/// Returns the first nonce found, or `None` when every worker exhausts its
/// range or `stop` is raised. Memory: `threads` × the algorithm's scratchpad
/// (64 MiB for v1, 4 MiB for v3); the algorithm follows `height`.
pub fn mine_parallel(
    pow_preimage: &[u8],
    bits: u32,
    height: u64,
    start_nonce: u64,
    attempts_per_thread: u64,
    threads: usize,
    stop: Option<&AtomicBool>,
) -> Option<u64> {
    let target = gnb_smh::difficulty::try_bits_to_target(bits).ok()?;
    let algo = gnb_crypto::core::pow_algo(height);
    let threads = threads.max(1);
    let found = AtomicBool::new(false);
    let winner = AtomicU64::new(0);
    std::thread::scope(|s| {
        for k in 0..threads {
            let found = &found;
            let winner = &winner;
            let target = &target;
            s.spawn(move || {
                let mut sp = gnb_smh::AnyScratchpad::new(algo);
                let base = start_nonce.wrapping_add((k as u64).wrapping_mul(attempts_per_thread));
                for i in 0..attempts_per_thread {
                    if found.load(Ordering::Relaxed) || stop.is_some_and(|f| f.load(Ordering::Relaxed)) {
                        return;
                    }
                    let nonce = base.wrapping_add(i);
                    let out = sp.hash(pow_preimage, nonce);
                    if gnb_smh::difficulty::meets_target(&out, target) {
                        if !found.swap(true, Ordering::AcqRel) {
                            winner.store(nonce, Ordering::Release);
                        }
                        return;
                    }
                }
            });
        }
    });
    found.load(Ordering::Acquire).then(|| winner.load(Ordering::Acquire))
}

/// Nonces per thread in one round of the built-in GnB-SMH miner (about 10
/// to 20 s on a typical core): the template is rebuilt after each round.
pub const GNB_SMH_ROUND_ATTEMPTS: u64 = 64;

/// Nonces per thread in one round of the built-in SHA-256d miner (well under
/// a second per thread on a typical core, about 4M SHA-256d evaluations).
pub const SHA256D_ROUND_ATTEMPTS: u64 = 1 << 22;

/// One round of the built-in miner on `header` (of a block at `height`)
/// under the process's proof-of-work scheme: GnB-SMH
/// ([`mine_parallel`] over `pow_preimage`, [`GNB_SMH_ROUND_ATTEMPTS`] nonces
/// per thread) or SHA-256d ([`mine_sha256d_parallel`] over the 80-byte
/// header, [`SHA256D_ROUND_ATTEMPTS`] nonces per thread, starting at the low
/// 32 bits of `start_nonce`). Returns the winning nonce; the header's other
/// fields (version, time) are not rolled. `None` when no nonce of the round
/// wins, `stop` is raised, or the header does not fit the scheme (a SHA-256d
/// header whose time does not fit u32).
pub fn mine_header_round(
    header: &gnb_crypto::core::BlockHeader,
    height: u64,
    start_nonce: u64,
    threads: usize,
    stop: Option<&AtomicBool>,
) -> Option<u64> {
    if gnb_crypto::core::pow_scheme::node_sha256d_params().is_some() {
        let mut h = header.clone();
        h.nonce = 0;
        let bytes = h.sha256d_pow_bytes().ok()?;
        return mine_sha256d_parallel(&bytes, header.bits, start_nonce as u32, SHA256D_ROUND_ATTEMPTS, threads, stop)
            .map(u64::from);
    }
    mine_parallel(&header.pow_preimage(), header.bits, height, start_nonce, GNB_SMH_ROUND_ATTEMPTS, threads, stop)
}

/// Offset of the nonce in the 80-byte SHA-256d header.
const SHA256D_NONCE_OFFSET: usize = 76;

/// SHA-256d search over the 32-bit nonce of the 80-byte header `header`
/// (its own nonce field is ignored) against compact `bits`. `threads`
/// workers each search a disjoint range of `attempts_per_thread` nonces
/// starting at `start_nonce + k * attempts_per_thread` (mod 2^32); the
/// per-thread count is capped so the ranges never overlap (at most 2^32
/// nonces in all). Returns the first winning nonce found, or `None` when
/// every worker exhausts its range, `stop` is raised, or `bits` is
/// malformed. The first 64 bytes (version, parent commitment, most of the
/// Merkle root) are hashed once per call (the SHA-256 midstate); each nonce
/// costs the last block of the first SHA-256 and the second SHA-256.
pub fn mine_sha256d_parallel(
    header: &[u8; gnb_smh::sha256d::POW_HEADER_LEN],
    bits: u32,
    start_nonce: u32,
    attempts_per_thread: u64,
    threads: usize,
    stop: Option<&AtomicBool>,
) -> Option<u32> {
    use sha2::{Digest, Sha256};
    let target = gnb_smh::difficulty::try_bits_to_target(bits).ok()?;
    let threads = threads.max(1);
    let attempts = attempts_per_thread.min((1u64 << 32) / threads as u64);
    let mut midstate = Sha256::new();
    midstate.update(&header[..64]);
    let mut tail = [0u8; 16];
    tail.copy_from_slice(&header[64..]);
    let found = AtomicBool::new(false);
    let winner = std::sync::atomic::AtomicU32::new(0);
    std::thread::scope(|s| {
        for k in 0..threads {
            let (found, winner, target, midstate) = (&found, &winner, &target, &midstate);
            s.spawn(move || {
                let base = start_nonce.wrapping_add((k as u64 * attempts) as u32);
                let mut tail = tail;
                for i in 0..attempts {
                    // Checked every 4096 nonces: a SHA-256d is far cheaper
                    // than the atomic loads.
                    if i % 4096 == 0
                        && (found.load(Ordering::Relaxed) || stop.is_some_and(|f| f.load(Ordering::Relaxed)))
                    {
                        return;
                    }
                    let nonce = base.wrapping_add(i as u32);
                    tail[SHA256D_NONCE_OFFSET - 64..].copy_from_slice(&nonce.to_le_bytes());
                    let mut h = midstate.clone();
                    h.update(tail);
                    let id: [u8; 32] = Sha256::digest(h.finalize()).into();
                    if gnb_smh::sha256d::meets_target(&id, target) {
                        if !found.swap(true, Ordering::AcqRel) {
                            winner.store(nonce, Ordering::Release);
                        }
                        return;
                    }
                }
            });
        }
    });
    found.load(Ordering::Acquire).then(|| winner.load(Ordering::Acquire))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnb_crypto::core::POW_LIMIT_BITS;

    #[test]
    fn mined_nonce_verifies_and_matches_block_validation() {
        // At the pow limit almost every evaluation passes, so this is one or
        // two 64 MiB evaluations.
        let mut block = gnb_crypto::core::genesis_block();
        block.header.bits = POW_LIMIT_BITS;
        let pre = block.header.pow_preimage();
        let nonce = mine_parallel(&pre, POW_LIMIT_BITS, block.height, 0, 16, 2, None).expect("pow limit is trivially mineable");
        assert!(verify(&pre, nonce, POW_LIMIT_BITS, block.height));
        block.header.nonce = nonce;
        assert!(block.validate_pow());
    }

    #[test]
    fn malformed_bits_never_mine_or_verify() {
        assert_eq!(mine(b"x", 0xFF00_FFFF, 1, 0, 4), None);
        assert!(!verify(b"x", 0, 0xFF00_FFFF, 1));
        assert_eq!(work_from_bits(0xFF00_FFFF), 0);
    }

    /// Under the regtest pow limit (about one hash in two wins) the SHA-256d
    /// search finds a nonce whose header verifies, from the midstate path,
    /// against the reference `gnb_smh::sha256d::verify_header`; the ranges of
    /// the workers stay disjoint at any thread count.
    #[test]
    fn sha256d_search_finds_a_verifying_nonce() {
        use gnb_crypto::core::pow_scheme::{check_sha256d_pow, Sha256dParams, OBB_REGTEST_POW_LIMIT_BITS};
        use gnb_crypto::core::{BlockHeader, MerkleRoot};
        let params = Sha256dParams::obenblock_regtest(1_800_000_000);
        let mut h = BlockHeader {
            version: params.block_version, parents: vec![[1; 32], [2; 32]], merkle_root: MerkleRoot([3; 32]),
            timestamp: 1_800_000_030, bits: OBB_REGTEST_POW_LIMIT_BITS, nonce: 0,
        };
        let bytes = h.sha256d_pow_bytes().unwrap();
        for threads in [1, 3, 8] {
            let n = mine_sha256d_parallel(&bytes, h.bits, u32::MAX - 1, 64, threads, None).expect("regtest limit");
            h.nonce = n as u64;
            let b = h.sha256d_pow_bytes().unwrap();
            assert!(gnb_smh::sha256d::verify_header(&b));
            assert_eq!(check_sha256d_pow(&h, &params), Ok(()));
        }
        // A target no nonce of a short range meets.
        assert_eq!(mine_sha256d_parallel(&bytes, 0x0300_0001, 0, 1_000, 2, None), None);
        assert_eq!(mine_sha256d_parallel(&bytes, 0xFF00_FFFF, 0, 1_000, 2, None), None, "malformed bits");
        let stop = AtomicBool::new(true);
        assert_eq!(mine_sha256d_parallel(&bytes, 0x1D00_FFFF, 0, u64::MAX, 4, Some(&stop)), None);
    }

    /// The SHA-256d search returns exactly the first winning nonce of a
    /// single-threaded range, matching a plain loop over `sha256d`.
    #[test]
    fn sha256d_midstate_matches_plain_hashing() {
        let mut bytes = [0u8; 80];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        let bits = 0x2000_FFFF; // about one hash in 128 wins
        let target = gnb_smh::difficulty::bits_to_target(bits);
        let first = (0u32..).find(|n| {
            bytes[76..].copy_from_slice(&n.to_le_bytes());
            gnb_smh::sha256d::meets_target(&gnb_smh::sha256d::block_id(&bytes), &target)
        }).unwrap();
        assert_eq!(mine_sha256d_parallel(&bytes, bits, 0, 1 << 20, 1, None), Some(first));
    }

    #[test]
    fn stop_flag_aborts() {
        let stop = AtomicBool::new(true);
        // An essentially impossible target with the stop flag already raised.
        assert_eq!(mine_parallel(b"x", 0x0300_0001, 1, 0, u64::MAX, 2, Some(&stop)), None);
    }
}
