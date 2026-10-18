//! GnB-SMH v1 (Gödel and Bell Sequential Memory-Hard) — proof-of-work over SHAKE-256.
//!
//! Normative definition: `reference/gnb_smh.py`. This crate must reproduce
//! `reference/test_vectors.json` byte for byte (see `tests/vectors.rs`).
//!
//! ```text
//! X_0   = SHAKE256(enc(DS_SEED) || u8(log2_n) || enc(header) || u64le(nonce), 128)
//! fill:  for i in 0..N:  V[i] = X;  X = SHAKE256(X || u32le(i) || 0x01, 128)
//! mix:   for i in 0..N:  j = u64le(X[0..8]) mod N;  X = SHAKE256((X ^ V[j]) || u32le(i) || 0x02, 128)
//! out   = SHAKE256(enc(DS_FINAL) || X, 32)
//! valid <=> out (big-endian u256) < target,  1 <= target <= 2^256 - 1
//! ```
//!
//! Every inner call has a 133-byte input, so it costs exactly one
//! Keccak-f[1600] permutation; this crate computes it directly on lanes.

#![forbid(unsafe_code)]

pub mod difficulty;
/// Stall relief: a late block relaxes its own target (ObenBlock, `docs/DESIGN-obenblock.md` 5.1).
pub mod stall_relief;
/// GnB-SMH v2 draft (SHA-256). Not consensus.
pub mod v2;
/// GnB-SMH v3 (Argon2d-style fill, 4 MiB): consensus from the PoWit activation height.
pub mod v3;

/// The proof-of-work function consensus selects for a height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algo {
    /// GnB-SMH v1: ROMix over 64 MiB.
    V1,
    /// GnB-SMH v3: Argon2d-style 2-pass fill over 4 MiB.
    V3,
}

impl Algo {
    pub fn name(self) -> &'static str {
        match self {
            Algo::V1 => "gnb-smh-v1",
            Algo::V3 => "gnb-smh-v3",
        }
    }

    /// Scratchpad bytes one evaluation holds.
    pub fn memory_bytes(self) -> usize {
        match self {
            Algo::V1 => BLOCK << LOG2_N,
            Algo::V3 => v3::BLOCK << v3::LOG2_N,
        }
    }
}

/// A canonical scratchpad for either algorithm (one per mining thread).
pub enum AnyScratchpad {
    V1(Scratchpad),
    V3(v3::Scratchpad),
}

impl AnyScratchpad {
    pub fn new(algo: Algo) -> Self {
        match algo {
            Algo::V1 => AnyScratchpad::V1(Scratchpad::new(LOG2_N)),
            Algo::V3 => AnyScratchpad::V3(v3::Scratchpad::new(v3::LOG2_N)),
        }
    }

    pub fn algo(&self) -> Algo {
        match self {
            AnyScratchpad::V1(_) => Algo::V1,
            AnyScratchpad::V3(_) => Algo::V3,
        }
    }

    pub fn hash(&mut self, header: &[u8], nonce: u64) -> [u8; 32] {
        match self {
            AnyScratchpad::V1(sp) => hash_with(sp, header, nonce),
            AnyScratchpad::V3(sp) => v3::hash_with(sp, header, nonce),
        }
    }
}

/// Canonical output of `algo` with a per-thread scratchpad.
pub fn hash_algo(algo: Algo, header: &[u8], nonce: u64) -> [u8; 32] {
    match algo {
        Algo::V1 => hash_thread_local(header, nonce),
        Algo::V3 => v3::hash_thread_local(header, nonce),
    }
}

/// Consensus check of one proof under `algo`. A zero target never validates.
pub fn verify_algo(algo: Algo, header: &[u8], nonce: u64, target: &difficulty::Target) -> bool {
    !target.is_zero() && difficulty::meets_target(&hash_algo(algo, header, nonce), target)
}

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Scratchpad block size in bytes.
pub const BLOCK: usize = 128;
/// Lanes (u64) per block.
pub const LANES: usize = BLOCK / 8;
/// Canonical v1 memory parameter (consensus): N = 2^19 blocks = 64 MiB.
pub const LOG2_N: u32 = 19;
/// Range accepted for tests and experiments. Consensus uses `LOG2_N` only.
pub const MIN_LOG2_N: u32 = 1;
pub const MAX_LOG2_N: u32 = 30;

const DS_SEED: &[u8] = b"GNB-SMH-v1/seed";
const DS_FINAL: &[u8] = b"GNB-SMH-v1/final";
const TAG_FILL: u64 = 0x01;
const TAG_MIX: u64 = 0x02;

fn check_log2_n(log2_n: u32) -> usize {
    assert!(
        (MIN_LOG2_N..=MAX_LOG2_N).contains(&log2_n),
        "log2_n must be in [{MIN_LOG2_N}, {MAX_LOG2_N}]"
    );
    1usize.checked_shl(log2_n).expect("2^log2_n does not fit in usize")
}

/// SHAKE-256 padding for a 133-byte message in a 136-byte rate:
/// byte 132 = tag, byte 133 = 0x1F (SHAKE suffix + first pad bit),
/// byte 135 = 0x80 (last pad bit). Lane 16 = i | tag<<32 | 0x1F<<40 | 0x80<<56.
#[inline(always)]
fn lane16(i: u32, tag: u64) -> u64 {
    (i as u64) | (tag << 32) | (0x1F_u64 << 40) | (0x80_u64 << 56)
}

/// One inner step: X <- SHAKE256(X || u32le(i) || tag, 128), in place on lanes.
#[inline(always)]
fn step(x: &mut [u64; LANES], i: u32, tag: u64) {
    let mut st = [0u64; 25];
    st[..LANES].copy_from_slice(x);
    st[LANES] = lane16(i, tag);
    keccak::f1600(&mut st);
    x.copy_from_slice(&st[..LANES]);
}

fn enc(h: &mut Shake256, b: &[u8]) {
    let len = u32::try_from(b.len()).expect("field longer than u32::MAX");
    h.update(&len.to_le_bytes());
    h.update(b);
}

fn bytes_to_lanes(b: &[u8; BLOCK]) -> [u64; LANES] {
    let mut x = [0u64; LANES];
    for (k, lane) in x.iter_mut().enumerate() {
        *lane = u64::from_le_bytes(b[8 * k..8 * k + 8].try_into().unwrap());
    }
    x
}

fn lanes_to_bytes(x: &[u64; LANES]) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    for (k, lane) in x.iter().enumerate() {
        b[8 * k..8 * k + 8].copy_from_slice(&lane.to_le_bytes());
    }
    b
}

/// X_0 for (header, nonce).
pub fn seed(header: &[u8], nonce: u64, log2_n: u32) -> [u8; BLOCK] {
    check_log2_n(log2_n);
    let mut h = Shake256::default();
    enc(&mut h, DS_SEED);
    h.update(&[log2_n as u8]);
    enc(&mut h, header);
    h.update(&nonce.to_le_bytes());
    let mut out = [0u8; BLOCK];
    h.finalize_xof().read(&mut out);
    out
}

/// Reusable 2^log2_n-block scratchpad (allocate once per mining thread).
pub struct Scratchpad {
    v: Vec<[u64; LANES]>,
    log2_n: u32,
}

impl Scratchpad {
    pub fn new(log2_n: u32) -> Self {
        let n = check_log2_n(log2_n);
        Self { v: vec![[0u64; LANES]; n], log2_n }
    }

    pub fn log2_n(&self) -> u32 {
        self.log2_n
    }

    /// Bytes of memory the scratchpad occupies.
    pub fn bytes(&self) -> usize {
        self.v.len() * BLOCK
    }
}

/// Intermediate values, exposed for test vectors and debugging.
pub struct Trace {
    pub seed: [u8; BLOCK],
    pub x_after_fill: [u8; BLOCK],
    pub x_after_mix: [u8; BLOCK],
    pub out: [u8; 32],
}

/// Full evaluation with intermediates.
pub fn trace_with(sp: &mut Scratchpad, header: &[u8], nonce: u64) -> Trace {
    let n = sp.v.len();
    let mask = (n - 1) as u64;
    let s = seed(header, nonce, sp.log2_n);
    let mut x = bytes_to_lanes(&s);

    // Phase 1 — fill: hash chain of length N. (i < 2^30 always fits in u32.)
    for (i, slot) in sp.v.iter_mut().enumerate() {
        *slot = x;
        step(&mut x, i as u32, TAG_FILL);
    }
    let x_after_fill = lanes_to_bytes(&x);

    // Phase 2 — mix: N data-dependent reads, each step depends on the previous.
    for i in 0..n {
        let j = (x[0] & mask) as usize;
        let vj = &sp.v[j];
        for k in 0..LANES {
            x[k] ^= vj[k];
        }
        step(&mut x, i as u32, TAG_MIX);
    }
    let x_after_mix = lanes_to_bytes(&x);

    let mut h = Shake256::default();
    enc(&mut h, DS_FINAL);
    h.update(&x_after_mix);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);

    Trace { seed: s, x_after_fill, x_after_mix, out }
}

/// GnB-SMH output for (header, nonce), reusing `sp` at whatever size it has.
pub fn hash_with(sp: &mut Scratchpad, header: &[u8], nonce: u64) -> [u8; 32] {
    trace_with(sp, header, nonce).out
}

/// GnB-SMH output at the canonical parameter (allocates 64 MiB).
pub fn hash(header: &[u8], nonce: u64) -> [u8; 32] {
    hash_with(&mut Scratchpad::new(LOG2_N), header, nonce)
}

/// out < target, both big-endian 256-bit integers. Consensus requires target != 0.
pub fn meets_target(out: &[u8; 32], target: &[u8; 32]) -> bool {
    out < target
}

/// Consensus check for one header. Panics if `sp` is not the canonical size.
pub fn verify_with(sp: &mut Scratchpad, header: &[u8], nonce: u64, target: &[u8; 32]) -> bool {
    assert_eq!(sp.log2_n, LOG2_N, "consensus verification requires the canonical scratchpad");
    if target.iter().all(|&b| b == 0) {
        return false; // target 0 is invalid: no output can be below it
    }
    meets_target(&hash_with(sp, header, nonce), target)
}

std::thread_local! {
    static THREAD_SCRATCHPAD: std::cell::RefCell<Option<Scratchpad>> =
        const { std::cell::RefCell::new(None) };
}

/// Canonical GnB-SMH output using a per-thread canonical scratchpad that is
/// allocated on first use and kept for the life of the thread, so repeated
/// verification does not reallocate 64 MiB per call.
pub fn hash_thread_local(header: &[u8], nonce: u64) -> [u8; 32] {
    THREAD_SCRATCHPAD.with(|cell| {
        let mut slot = cell.borrow_mut();
        let sp = slot.get_or_insert_with(|| Scratchpad::new(LOG2_N));
        hash_with(sp, header, nonce)
    })
}

/// Consensus check at the canonical parameter using the per-thread scratchpad.
pub fn verify(header: &[u8], nonce: u64, target: &difficulty::Target) -> bool {
    if target.is_zero() {
        return false;
    }
    difficulty::meets_target(&hash_thread_local(header, nonce), target)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One Keccak-f[1600] permutation takes about 0.4 s under Miri (measured,
    /// docs/testing/SANITIZERS.md), so the hashing tests below run a few
    /// iterations there and the full count natively.
    const HASH_TRIALS: u64 = if cfg!(miri) { 3 } else { 200 };

    /// The lane-level step must equal FIPS 202 SHAKE256(x || u32le(i) || tag, 128).
    #[test]
    fn step_matches_shake256() {
        let mut x = [0u64; LANES];
        for trial in 0u64..HASH_TRIALS {
            for (k, lane) in x.iter_mut().enumerate() {
                *lane = trial
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .rotate_left(k as u32 * 7)
                    ^ (k as u64);
            }
            let i = (trial as u32).wrapping_mul(2_654_435_761);
            for tag in [TAG_FILL, TAG_MIX] {
                let xb = lanes_to_bytes(&x);
                let mut h = Shake256::default();
                h.update(&xb);
                h.update(&i.to_le_bytes());
                h.update(&[tag as u8]);
                let mut want = [0u8; BLOCK];
                h.finalize_xof().read(&mut want);

                let mut got = x;
                step(&mut got, i, tag);
                assert_eq!(lanes_to_bytes(&got), want);
            }
        }
    }

    #[test]
    fn target_compare_is_big_endian() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 0xFF;
        b[0] = 0x01;
        assert!(meets_target(&a, &b));
        assert!(!meets_target(&b, &a));
        assert!(!meets_target(&a, &a));
    }

    #[test]
    fn nonce_and_header_change_output() {
        // 2^8 blocks natively; 2 blocks (still both phases, both tags) under Miri.
        let mut sp = Scratchpad::new(if cfg!(miri) { MIN_LOG2_N } else { 8 });
        let a = hash_with(&mut sp, b"gnb", 0);
        assert_ne!(a, hash_with(&mut sp, b"gnb", 1));
        assert_ne!(a, hash_with(&mut sp, b"gnc", 0));
        assert_eq!(a, hash_with(&mut sp, b"gnb", 0));
    }

    #[test]
    #[should_panic]
    fn rejects_log2_n_out_of_range() {
        let _ = Scratchpad::new(MAX_LOG2_N + 1);
    }

    /// Every profile must trap integer overflow (root Cargo.toml: release sets
    /// `overflow-checks = true`, dev/test inherit it from debug assertions).
    /// Checks the profile this binary was built with, so CI also runs it as
    /// `cargo test --release -p gnb-smh --lib integer_overflow`.
    #[test]
    fn integer_overflow_panics_in_this_profile() {
        let r = std::panic::catch_unwind(|| std::hint::black_box(u32::MAX) + std::hint::black_box(1u32));
        assert!(r.is_err(), "overflow-checks are off in this build profile");
    }

    #[test]
    #[should_panic]
    fn verify_rejects_non_canonical_scratchpad() {
        let mut sp = Scratchpad::new(8);
        let _ = verify_with(&mut sp, b"gnb", 0, &[0xFF; 32]);
    }

    #[test]
    fn scratchpad_reports_its_parameter_and_size() {
        for (log2_n, bytes) in [(1u32, 256usize), (8, 32_768), (10, 131_072)] {
            let sp = Scratchpad::new(log2_n);
            assert_eq!(sp.log2_n(), log2_n);
            assert_eq!(sp.bytes(), (1usize << log2_n) * BLOCK);
            assert_eq!(sp.bytes(), bytes);
        }
    }

    /// `lane16` is the SHAKE-256 padding of the 133-byte message as one lane:
    /// bytes 0..4 = i, byte 4 = tag, byte 5 = 0x1F, byte 7 = 0x80.
    #[test]
    fn lane16_layout() {
        let l = lane16(0x0403_0201, TAG_MIX);
        assert_eq!(l.to_le_bytes(), [0x01, 0x02, 0x03, 0x04, 0x02, 0x1F, 0x00, 0x80]);
        assert_eq!(lane16(u32::MAX, TAG_FILL).to_le_bytes(), [0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x1F, 0x00, 0x80]);
    }

    /// Canonical reference vector (reference/test_vectors.json, log2_n = 19,
    /// header "gnb", nonce 0).
    const CANONICAL_OUT: &str = "c05129a877e99e4fd8f1bd6bd39963a95c9ece39bc5055047db51bfaa4f44bef";

    fn canonical_out() -> [u8; 32] {
        let mut out = [0u8; 32];
        for (k, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&CANONICAL_OUT[2 * k..2 * k + 2], 16).unwrap();
        }
        out
    }

    /// `out + 1` as a big-endian integer (the vector's out does not end in 0xFF).
    fn plus_one(mut t: [u8; 32]) -> [u8; 32] {
        assert_ne!(t[31], 0xFF);
        t[31] += 1;
        t
    }

    /// Every canonical entry point (`hash`, `hash_thread_local`,
    /// `verify_with`, `verify`) reproduces the reference output and decides
    /// validity exactly at `out < target`.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "five canonical evaluations (log2_n = 19, 64 MiB, ~2^20 Keccak-f[1600] permutations each at \
                  ~0.4 s per permutation under Miri); the log2_n <= 2 Python vectors in tests/vectors.rs run \
                  the same pipeline there"
    )]
    fn canonical_entry_points_match_the_reference_vector() {
        let out = canonical_out();
        assert_eq!(hash(b"gnb", 0), out);
        assert_eq!(hash_thread_local(b"gnb", 0), out);

        let mut sp = Scratchpad::new(LOG2_N);
        assert!(verify_with(&mut sp, b"gnb", 0, &plus_one(out)), "out < out + 1");
        assert!(!verify_with(&mut sp, b"gnb", 0, &out), "out < out is false");
        assert!(!verify_with(&mut sp, b"gnb", 0, &[0u8; 32]), "the zero target never validates");

        use difficulty::Target;
        assert!(verify(b"gnb", 0, &Target(plus_one(out))));
        assert!(!verify(b"gnb", 0, &Target(out)));
        assert!(!verify(b"gnb", 0, &Target::ZERO));
    }
}

/// SHA-256d over an 80-byte Bitcoin-ASIC-compatible header (ObenBlock,
/// docs/DESIGN-obenblock.md §4). Not GnB's proof of work. (Declared at the
/// end of the file so the line numbers above do not move.)
pub mod sha256d;
