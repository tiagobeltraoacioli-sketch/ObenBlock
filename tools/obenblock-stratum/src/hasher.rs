//! The CPU miner's nonce scanner: SHA-256d of an 80-byte header over a range
//! of nonces, from the header's midstate.
//!
//! Per header (one extranonce2): the SHA-256 state after the first 64 bytes
//! (the midstate) and the first three rounds of the second block, whose
//! message words (the end of the Merkle root, `time`, `bits`) do not depend
//! on the nonce. Per nonce: rounds 3..64 of the second block, then the
//! outer SHA-256 of the 32-byte digest, stopped after round 60: the id's
//! most significant 32 bits (`le256(id) >> 224`, the last state word) are
//! final there, and only a nonce whose top word is at or below the
//! target's goes on to the full check ([`crate::validator::meets_target`]
//! on the id recomputed with the plain path).
//!
//! The rounds are written once over `[u32; N]` lanes (N nonces at a time)
//! and instantiated per instruction set: the compiler turns the lane loops
//! into SSE2 (N = 4, every x86-64), AVX2 (N = 8) or AVX-512 (N = 16, native
//! rotates) code inside functions compiled for that set, selected at run
//! time (`is_x86_feature_detected!`). [`Kernel::Sha2`] is the `sha2`
//! crate's compression function per nonce (it uses SHA-NI when the CPU has
//! it, detected at run time by `cpufeatures`), the miner's original path.
//! [`Kernel::fastest`] measures every available kernel and picks the best.

use std::time::Instant;

use crate::validator::{id_from_midstate, midstate, tail_block, POW_HEADER_LEN};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

/// A header prepared for scanning: everything that does not depend on the
/// nonce.
#[derive(Clone, Copy, Debug)]
pub struct Prepared {
    /// SHA-256 state after the first 64 header bytes.
    pub mid: [u32; 8],
    /// Message words 0..3 of the second block (header bytes 64..76).
    pub w012: [u32; 3],
    /// Working state after rounds 0..3 of the second block.
    pub state3: [u32; 8],
    /// The header's second block (the scalar check path).
    pub tail: [u8; 64],
}

#[inline(always)]
fn big_s0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
#[inline(always)]
fn big_s1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
#[inline(always)]
fn small_s0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
#[inline(always)]
fn small_s1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

impl Prepared {
    pub fn new(header: &[u8; POW_HEADER_LEN]) -> Self {
        let mid = midstate(header);
        let w = |i: usize| u32::from_be_bytes(header[64 + 4 * i..68 + 4 * i].try_into().unwrap());
        let w012 = [w(0), w(1), w(2)];
        let mut s = mid;
        for (t, &wt) in w012.iter().enumerate() {
            let [a, b, c, d, e, f, g, h] = s;
            let t1 = h.wrapping_add(big_s1(e)).wrapping_add((e & f) ^ (!e & g)).wrapping_add(K[t]).wrapping_add(wt);
            let t2 = big_s0(a).wrapping_add((a & b) ^ (a & c) ^ (b & c));
            s = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
        }
        Prepared { mid, w012, state3: s, tail: tail_block(header) }
    }

    /// `SHA-256d(header)` with `nonce` (the plain path).
    pub fn id(&self, nonce: u32) -> [u8; 32] {
        let mut tail = self.tail;
        tail[12..16].copy_from_slice(&nonce.to_le_bytes());
        id_from_midstate(&self.mid, &tail)
    }
}

/// The most significant 32 bits of a target (big-endian bytes 0..4): a nonce
/// whose id's top word exceeds them can never meet the target.
pub fn target_top_word(target_be: &[u8; 32]) -> u32 {
    u32::from_be_bytes(target_be[0..4].try_into().unwrap())
}

// ── The lane kernel ─────────────────────────────────────────────────────

type L<const N: usize> = [u32; N];

#[inline(always)]
fn map2<const N: usize>(a: L<N>, b: L<N>, f: impl Fn(u32, u32) -> u32) -> L<N> {
    let mut r = [0u32; N];
    for i in 0..N {
        r[i] = f(a[i], b[i]);
    }
    r
}
#[inline(always)]
fn add<const N: usize>(a: L<N>, b: L<N>) -> L<N> {
    map2(a, b, u32::wrapping_add)
}
#[inline(always)]
fn addk<const N: usize>(a: L<N>, k: u32) -> L<N> {
    let mut r = a;
    for x in r.iter_mut() {
        *x = x.wrapping_add(k);
    }
    r
}
#[inline(always)]
fn map1<const N: usize>(a: L<N>, f: impl Fn(u32) -> u32) -> L<N> {
    let mut r = a;
    for x in r.iter_mut() {
        *x = f(*x);
    }
    r
}

/// One round over N lanes with `kw = K[t] + W[t]` already summed.
#[inline(always)]
fn round<const N: usize>(s: &mut [L<N>; 8], kw: L<N>) {
    let [a, b, c, d, e, f, g, h] = *s;
    let mut t1 = [0u32; N];
    let mut t2 = [0u32; N];
    for i in 0..N {
        let ch = (e[i] & f[i]) ^ (!e[i] & g[i]);
        let maj = (a[i] & b[i]) | (c[i] & (a[i] | b[i]));
        t1[i] = h[i].wrapping_add(big_s1(e[i])).wrapping_add(ch).wrapping_add(kw[i]);
        t2[i] = big_s0(a[i]).wrapping_add(maj);
    }
    *s = [add(t1, t2), a, b, c, add(d, t1), e, f, g];
}

/// The message schedule word `t >= 16` from the rolling window `w[t % 16]`.
#[inline(always)]
fn schedule<const N: usize>(w: &mut [L<N>; 16], t: usize) -> L<N> {
    let v = add(add(map1(w[(t - 2) & 15], small_s1), w[(t - 7) & 15]), add(map1(w[(t - 15) & 15], small_s0), w[t & 15]));
    w[t & 15] = v;
    v
}

/// Scan `count` nonces from `start` (count a multiple of N) and push every
/// nonce whose id's top word is `<= top` to `out`.
#[inline(always)]
#[allow(clippy::needless_range_loop)] // `t` indexes both the schedule and K
fn scan_lanes<const N: usize>(p: &Prepared, start: u32, count: u32, top: u32, out: &mut Vec<u32>) {
    let mid: [L<N>; 8] = core::array::from_fn(|i| [p.mid[i]; N]);
    let s3: [L<N>; 8] = core::array::from_fn(|i| [p.state3[i]; N]);
    let mut base = start;
    let end = start.wrapping_add(count);
    while base != end {
        let nonce: L<N> = core::array::from_fn(|i| base.wrapping_add(i as u32));
        // Second block of the header: W3 = the nonce's header bytes read
        // big-endian, W4 = padding, W5..W14 = 0, W15 = 640 bits.
        let mut w: [L<N>; 16] = [[0; N]; 16];
        w[0] = [p.w012[0]; N];
        w[1] = [p.w012[1]; N];
        w[2] = [p.w012[2]; N];
        w[3] = map1(nonce, u32::swap_bytes);
        w[4] = [0x8000_0000; N];
        w[15] = [640; N];
        let mut s = s3;
        for t in 3..16 {
            round(&mut s, addk(w[t], K[t]));
        }
        for t in 16..64 {
            let wt = schedule(&mut w, t);
            round(&mut s, addk(wt, K[t]));
        }
        let d1: [L<N>; 8] = core::array::from_fn(|i| add(s[i], mid[i]));
        // Outer SHA-256 of the 32-byte digest, to round 60.
        let mut w: [L<N>; 16] = [[0; N]; 16];
        w[..8].copy_from_slice(&d1);
        w[8] = [0x8000_0000; N];
        w[15] = [256; N];
        let mut s: [L<N>; 8] = core::array::from_fn(|i| [H0[i]; N]);
        for t in 0..16 {
            round(&mut s, addk(w[t], K[t]));
        }
        for t in 16..61 {
            let wt = schedule(&mut w, t);
            round(&mut s, addk(wt, K[t]));
        }
        // After round 60 the working `e` is the final `h`: H7 = H0[7] + e.
        // The id's top word (le256) is that word byte-swapped.
        let mut hit = false;
        let h7 = addk(s[4], H0[7]);
        for x in h7 {
            hit |= x.swap_bytes() <= top;
        }
        if hit {
            for (i, x) in h7.iter().enumerate() {
                if x.swap_bytes() <= top {
                    out.push(nonce[i]);
                }
            }
        }
        base = base.wrapping_add(N as u32);
    }
}

fn scan_portable(p: &Prepared, start: u32, count: u32, top: u32, out: &mut Vec<u32>) {
    scan_lanes::<4>(p, start, count, top, out)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_avx2(p: &Prepared, start: u32, count: u32, top: u32, out: &mut Vec<u32>) {
    scan_lanes::<8>(p, start, count, top, out)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vl")]
unsafe fn scan_avx512(p: &Prepared, start: u32, count: u32, top: u32, out: &mut Vec<u32>) {
    scan_lanes::<16>(p, start, count, top, out)
}

fn scan_sha2(p: &Prepared, start: u32, count: u32, top: u32, out: &mut Vec<u32>) {
    let mut tail = p.tail;
    for k in 0..count {
        let n = start.wrapping_add(k);
        tail[12..16].copy_from_slice(&n.to_le_bytes());
        let id = id_from_midstate(&p.mid, &tail);
        if u32::from_le_bytes(id[28..32].try_into().unwrap()) <= top {
            out.push(n);
        }
    }
}

/// A nonce-scanning implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    /// The `sha2` crate per nonce (SHA-NI when the CPU has it).
    Sha2,
    /// 4 lanes, baseline x86-64 (SSE2) or any other target.
    Lanes4,
    /// 8 lanes, AVX2.
    Avx2,
    /// 16 lanes, AVX-512 (F + VL).
    Avx512,
}

impl Kernel {
    /// Nonces per call must be a multiple of this.
    pub const BATCH_MULTIPLE: u32 = 16;

    pub fn name(self) -> &'static str {
        match self {
            Kernel::Sha2 => "sha2",
            Kernel::Lanes4 => "lanes4",
            Kernel::Avx2 => "avx2",
            Kernel::Avx512 => "avx512",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::all().into_iter().find(|k| k.name() == s)
    }

    pub fn all() -> [Kernel; 4] {
        [Kernel::Sha2, Kernel::Lanes4, Kernel::Avx2, Kernel::Avx512]
    }

    /// Whether this CPU can run the kernel.
    pub fn available(self) -> bool {
        match self {
            Kernel::Sha2 | Kernel::Lanes4 => true,
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => std::is_x86_feature_detected!("avx2"),
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx512 => std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512vl"),
            #[cfg(not(target_arch = "x86_64"))]
            _ => false,
        }
    }

    /// Kernels this CPU can run.
    pub fn available_all() -> Vec<Kernel> {
        Self::all().into_iter().filter(|k| k.available()).collect()
    }

    /// Scan `count` nonces from `start` (a multiple of
    /// [`Self::BATCH_MULTIPLE`]); push candidates (top word `<= top`) to
    /// `out`. Panics if the kernel is not [`available`](Self::available).
    pub fn scan(self, p: &Prepared, start: u32, count: u32, top: u32, out: &mut Vec<u32>) {
        assert_eq!(count % Self::BATCH_MULTIPLE, 0, "count must be a multiple of {}", Self::BATCH_MULTIPLE);
        assert!(self.available(), "kernel {} not available on this CPU", self.name());
        match self {
            Kernel::Sha2 => scan_sha2(p, start, count, top, out),
            Kernel::Lanes4 => scan_portable(p, start, count, top, out),
            // SAFETY: `available()` checked the CPU features above.
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => unsafe { scan_avx2(p, start, count, top, out) },
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx512 => unsafe { scan_avx512(p, start, count, top, out) },
            #[cfg(not(target_arch = "x86_64"))]
            _ => unreachable!(),
        }
    }

    /// Hashes per second of this kernel on the calling thread, measured for
    /// about `secs`.
    pub fn measure(self, secs: f64) -> f64 {
        let mut h = [0u8; POW_HEADER_LEN];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let p = Prepared::new(&h);
        let mut out = Vec::new();
        const CHUNK: u32 = 1 << 14;
        let t0 = Instant::now();
        let mut n: u64 = 0;
        while t0.elapsed().as_secs_f64() < secs {
            self.scan(&p, n as u32, CHUNK, 0, &mut out);
            n += CHUNK as u64;
            out.clear();
        }
        std::hint::black_box(&out);
        n as f64 / t0.elapsed().as_secs_f64()
    }

    /// The fastest available kernel on this CPU (each measured for `secs`),
    /// with every measurement.
    pub fn fastest(secs: f64) -> (Kernel, Vec<(Kernel, f64)>) {
        let rates: Vec<(Kernel, f64)> = Self::available_all().into_iter().map(|k| (k, k.measure(secs))).collect();
        let best = rates.iter().copied().fold((Kernel::Sha2, 0.0), |b, r| if r.1 > b.1 { r } else { b });
        (best.0, rates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{block_id, header80};

    fn header(seed: u8) -> [u8; POW_HEADER_LEN] {
        let mut root = [0u8; 32];
        for (i, b) in root.iter_mut().enumerate() {
            *b = seed.wrapping_mul(13).wrapping_add(i as u8);
        }
        header80(0x2000_0000 | seed as u32, &[seed; 32], &root, 1_800_000_000 + seed as u32, 0x1d00_ffff, 0)
    }

    fn top_word(id: &[u8; 32]) -> u32 {
        u32::from_le_bytes(id[28..32].try_into().unwrap())
    }

    #[test]
    fn prepared_id_is_block_id() {
        for seed in 0..4u8 {
            let h = header(seed);
            let p = Prepared::new(&h);
            for nonce in [0u32, 1, 0x1234_5678, u32::MAX] {
                let mut hn = h;
                hn[76..80].copy_from_slice(&nonce.to_le_bytes());
                assert_eq!(p.id(nonce), block_id(&hn));
            }
        }
    }

    /// Every available kernel reports exactly the nonces whose id's top word
    /// is at or below the bound, against the node's `block_id`.
    #[test]
    fn every_kernel_finds_exactly_the_candidates() {
        for k in Kernel::available_all() {
            for seed in 0..3u8 {
                let h = header(seed);
                let p = Prepared::new(&h);
                let start = (seed as u32).wrapping_mul(0x0101_0101).wrapping_sub(64); // wraps for seed 0
                let count = 2048;
                let ids: Vec<(u32, u32)> = (0..count).map(|i| {
                    let n = start.wrapping_add(i);
                    let mut hn = h;
                    hn[76..80].copy_from_slice(&n.to_le_bytes());
                    (n, top_word(&block_id(&hn)))
                }).collect();
                for top in [u32::MAX, 0x8000_0000, 0x0400_0000, 0] {
                    let mut out = Vec::new();
                    k.scan(&p, start, count, top, &mut out);
                    let want: Vec<u32> = ids.iter().filter(|x| x.1 <= top).map(|x| x.0).collect();
                    assert_eq!(out, want, "kernel {} seed {seed} top {top:08x}", k.name());
                }
            }
        }
    }

    #[test]
    fn kernel_names_round_trip() {
        for k in Kernel::all() {
            assert_eq!(Kernel::parse(k.name()), Some(k));
        }
        assert!(Kernel::Sha2.available() && Kernel::Lanes4.available());
        assert_eq!(target_top_word(&[0xab; 32]), 0xabab_abab);
    }
}
