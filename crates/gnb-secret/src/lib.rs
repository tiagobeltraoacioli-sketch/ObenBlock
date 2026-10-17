//! Secret memory for GnB key material (audit CRY-4).
//!
//! [`SecretBytes`] is the one owner of secret key bytes in GnB: hybrid
//! ML-DSA-65 ‖ Falcon-1024 secret keys, BIP39 seeds, HD-wallet master keys,
//! KES seeds and the passwords a long-running process keeps. It is
//!
//! * **not `Copy` and not `Clone`**: a secret is never duplicated implicitly
//!   (an explicit [`SecretBytes::duplicate`] exists for the rare deliberate
//!   copy); `assert_not_copy_or_clone!` turns a regression into a build
//!   failure;
//! * **wiped on drop** (and by [`zeroize::Zeroize`]) with volatile writes
//!   before its memory is released;
//! * **locked in RAM where the platform allows**: on Unix each buffer gets
//!   its own anonymous mapping, rounded up to whole pages, which is
//!   `mlock`ed (never written to swap) and, on Linux and FreeBSD, excluded
//!   from core dumps (`MADV_DONTDUMP` / `MADV_NOCORE`). Locking is best
//!   effort: when it fails (`RLIMIT_MEMLOCK`, `ulimit -l`) the buffer is
//!   still wiped, a warning is logged once and [`locked_memory`] counts the
//!   failure. Other targets (Windows, WebAssembly) get wiped heap memory.
//!
//! This is the analogue of Bitcoin Core's secure allocator
//! (`secure_allocator`, `LockedPoolManager`, `PosixLockedPageAllocator`:
//! `mlock` + `MADV_DONTDUMP`, `memory_cleanse` before release) for this
//! codebase. Core pools small allocations in 256 KiB locked arenas; here a
//! secret owns whole pages (a hybrid secret key, 6,341 bytes, takes two),
//! which keeps the code small at the cost of address space. Secrets are
//! few and long-lived, except during KES key generation, where each
//! transient leaf key takes and returns its pages.
//!
//! [`pq`] generates and uses ML-DSA-65 and Falcon-1024 keys directly in such
//! buffers through PQClean's C functions: the `pqcrypto` wrapper types
//! (`SecretKey`) are `Copy` fixed arrays that every call copies on the
//! stack and that can never be wiped by ownership. [`scrub_stack`]
//! overwrites the stack the C signers and key generators used for their
//! expanded keys and temporaries, which nothing else can reach.
//!
//! The crate is the only place outside `pqcrypto-internals` where GnB uses
//! `unsafe`: `gnb-crypto` keeps `#![forbid(unsafe_code)]`.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroize;

pub mod pq;
mod region;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use region::Region;

/// Secret bytes in locked (where possible), wiped-on-drop memory. See the
/// crate documentation.
pub struct SecretBytes {
    /// `None` for the empty value (no allocation).
    region: Option<Region>,
    len: usize,
}

// SAFETY: `SecretBytes` uniquely owns its region (like `Box<[u8]>`); shared
// access only reads through `&self`, mutation needs `&mut self`.
unsafe impl Send for SecretBytes {}
// SAFETY: see `Send`; `&SecretBytes` gives out only `&[u8]`.
unsafe impl Sync for SecretBytes {}

impl SecretBytes {
    /// An empty value (no allocation).
    pub const fn new() -> Self {
        SecretBytes { region: None, len: 0 }
    }

    /// `len` zero bytes in a fresh secret region.
    pub fn zeroed(len: usize) -> Self {
        if len == 0 {
            return Self::new();
        }
        SecretBytes { region: Some(Region::new(len)), len }
    }

    /// A secret holding a copy of `bytes`. The caller still owns (and must
    /// wipe) `bytes`; prefer [`SecretBytes::from_vec`] for a `Vec` you own.
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut s = Self::zeroed(bytes.len());
        s.as_mut_slice().copy_from_slice(bytes);
        s
    }

    /// Move `bytes` into a secret region and wipe the `Vec` (its spare
    /// capacity included) before it is freed.
    pub fn from_vec(mut bytes: Vec<u8>) -> Self {
        let s = Self::from_slice(&bytes);
        bytes.zeroize();
        s
    }

    /// A deliberate copy (`SecretBytes` is not `Clone`, so a secret is never
    /// duplicated by accident). The copy has its own region.
    pub fn duplicate(&self) -> Self {
        Self::from_slice(self.as_slice())
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` for zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes.
    pub fn as_slice(&self) -> &[u8] {
        match &self.region {
            Some(r) => &r.as_slice()[..self.len],
            None => &[],
        }
    }

    /// The bytes, mutable.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len;
        match &mut self.region {
            Some(r) => &mut r.as_mut_slice()[..len],
            None => &mut [],
        }
    }

    /// Whether the region is locked in RAM (`mlock` succeeded). Always
    /// `false` for an empty value and on targets without page locking.
    pub fn is_locked(&self) -> bool {
        self.region.as_ref().is_some_and(Region::is_locked)
    }

    /// Address of the first byte (diagnostics and tests).
    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
}

impl Default for SecretBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for SecretBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl From<Vec<u8>> for SecretBytes {
    /// [`SecretBytes::from_vec`]: the `Vec` is wiped.
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_vec(bytes)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }
}

impl From<zeroize::Zeroizing<Vec<u8>>> for SecretBytes {
    /// Copies the bytes; the `Zeroizing` owner wipes its `Vec` when dropped.
    fn from(bytes: zeroize::Zeroizing<Vec<u8>>) -> Self {
        Self::from_slice(&bytes)
    }
}

/// Constant-time in the contents (the lengths are not secret).
impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.as_slice(), other.as_slice())
    }
}

impl Eq for SecretBytes {}

impl PartialEq<[u8]> for SecretBytes {
    fn eq(&self, other: &[u8]) -> bool {
        ct_eq(self.as_slice(), other)
    }
}

impl PartialEq<Vec<u8>> for SecretBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        ct_eq(self.as_slice(), other)
    }
}

impl<const N: usize> PartialEq<[u8; N]> for SecretBytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        ct_eq(self.as_slice(), other)
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Never prints the contents.
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {}])", self.len)
    }
}

impl Zeroize for SecretBytes {
    /// Wipe and release the region now; the value becomes empty (like
    /// `Vec::zeroize`, which also clears the length).
    fn zeroize(&mut self) {
        self.region = None; // Region::drop wipes before release
        self.len = 0;
    }
}

impl zeroize::ZeroizeOnDrop for SecretBytes {}

// ── Statistics (Bitcoin Core: `getmemoryinfo` "locked") ─────────────────────

static LOCKED_BYTES: AtomicUsize = AtomicUsize::new(0);
static LOCKED_REGIONS: AtomicUsize = AtomicUsize::new(0);
static UNLOCKED_REGIONS: AtomicUsize = AtomicUsize::new(0);
static LOCK_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Locked-memory statistics of this process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockedMemoryStats {
    /// Bytes currently locked (whole pages).
    pub locked_bytes: usize,
    /// Live regions that are locked.
    pub locked_regions: usize,
    /// Live regions that could not be locked (or are on a platform without
    /// page locking).
    pub unlocked_regions: usize,
    /// `mlock` failures since the start of the process.
    pub lock_failures: usize,
}

/// Current [`LockedMemoryStats`].
pub fn locked_memory() -> LockedMemoryStats {
    LockedMemoryStats {
        locked_bytes: LOCKED_BYTES.load(Ordering::Relaxed),
        locked_regions: LOCKED_REGIONS.load(Ordering::Relaxed),
        unlocked_regions: UNLOCKED_REGIONS.load(Ordering::Relaxed),
        lock_failures: LOCK_FAILURES.load(Ordering::Relaxed),
    }
}

// ── Stack scrubbing ──────────────────────────────────────────────────────────

/// Bytes of stack [`scrub_stack`] overwrites. PQClean's Falcon-1024 signer
/// keeps a 72 KiB temporary plus its expanded key on the stack, its key
/// generator 28 KiB, ML-DSA-65's signer about 60 KiB of polynomial vectors
/// derived from the secret key: 128 KiB covers each of them.
pub const STACK_SCRUB_BYTES: usize = 128 * 1024;

/// Overwrite the [`STACK_SCRUB_BYTES`] of stack below the caller's frame
/// with zeros (volatile writes).
///
/// Call it right after a function that handled secret material in stack
/// frames this crate does not own (the PQClean C code, a hash function's
/// state): those frames sit below the caller's frame and are dead, but
/// their bytes stay in memory until something else is pushed there. This
/// is the analogue of libsodium's `sodium_stackzero`. Best effort: it
/// cannot reach registers, or frames deeper than the scrubbed range.
#[inline(never)]
pub fn scrub_stack() {
    let mut buf = [0u8; STACK_SCRUB_BYTES];
    buf.zeroize();
    std::hint::black_box(&buf);
}

// ── Static assertion: no `Copy`, no `Clone` ──────────────────────────────────

/// Compile-time assertion that a type implements neither `Copy` nor `Clone`
/// (CRY-4: secret holders are never duplicated implicitly). If the type
/// implements either trait the assertion fails to compile with an
/// "ambiguous associated item" error.
///
/// ```
/// struct Secret(Vec<u8>);
/// gnb_secret::assert_not_copy_or_clone!(Secret);
/// ```
///
/// ```compile_fail
/// #[derive(Clone)]
/// struct Leaky(Vec<u8>);
/// gnb_secret::assert_not_copy_or_clone!(Leaky);
/// ```
///
/// ```compile_fail
/// #[derive(Clone, Copy)]
/// struct Leaky([u8; 32]);
/// gnb_secret::assert_not_copy_or_clone!(Leaky);
/// ```
#[macro_export]
macro_rules! assert_not_copy_or_clone {
    ($t:ty) => {
        const _: fn() = || {
            trait AmbiguousIfClone<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfClone<()> for T {}
            impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
            let _ = <$t as AmbiguousIfClone<_>>::some_item;

            trait AmbiguousIfCopy<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
            impl<T: ?Sized + Copy> AmbiguousIfCopy<u8> for T {}
            let _ = <$t as AmbiguousIfCopy<_>>::some_item;
        };
    };
}

assert_not_copy_or_clone!(SecretBytes);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_reads_and_compares_its_bytes() {
        let s = SecretBytes::from_slice(b"correct horse");
        assert_eq!(s.as_slice(), b"correct horse");
        assert_eq!(&s[..7], b"correct");
        assert_eq!(s.len(), 13);
        assert_eq!(s, *b"correct horse".as_slice());
        assert_eq!(s, s.duplicate());
        assert_ne!(s, SecretBytes::from_slice(b"correct horsf"));
        assert_ne!(s, SecretBytes::from_slice(b"correct"));
        assert_eq!(format!("{s:?}"), "SecretBytes([REDACTED; 13])");
        let e = SecretBytes::default();
        assert!(e.is_empty() && e.as_slice().is_empty() && !e.is_locked());
        assert_eq!(SecretBytes::zeroed(0), e);
        let mut z = SecretBytes::zeroed(5000);
        assert!(z.iter().all(|&b| b == 0));
        z[4999] = 7;
        assert_eq!(z[4999], 7);
    }

    #[test]
    fn from_vec_wipes_the_source_and_zeroize_empties() {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&[0x5A; 40]);
        let mut s = SecretBytes::from_vec(v);
        assert_eq!(s.as_slice(), &[0x5A; 40][..]);
        s.zeroize();
        assert!(s.is_empty());
    }

    /// The region of a dropped secret is all zeros before it is released
    /// (read after the drop, through the test quarantine that keeps it
    /// mapped).
    #[test]
    fn a_dropped_secret_buffer_is_zeroed() {
        let q = test_support::Quarantine::start();
        let s = SecretBytes::from_slice(&[0xA5; 6341]);
        let ptr = s.as_ptr();
        let len = s.len();
        drop(s);
        // SAFETY: the quarantine keeps every region released on this thread
        // mapped (wiped, not unmapped) until `q` is dropped.
        let after = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(after.iter().all(|&b| b == 0), "a dropped secret left bytes behind");
        let released = q.released();
        assert_eq!(released.len(), 1);
        assert!(released[0].iter().all(|&b| b == 0));
        assert!(released[0].len() >= len, "the whole region is wiped, page padding included");

        drop(q);
        // `zeroize` wipes the same way.
        let q = test_support::Quarantine::start();
        let mut s = SecretBytes::from_slice(&[0x3C; 32]);
        let ptr = s.as_ptr();
        s.zeroize();
        // SAFETY: as above.
        assert_eq!(unsafe { std::slice::from_raw_parts(ptr, 32) }, &[0u8; 32]);
        assert_eq!(q.released().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn regions_are_page_aligned_and_locked_where_the_limit_allows() {
        let s = SecretBytes::from_slice(&[1; 100]);
        assert_eq!(s.as_ptr() as usize % region::page_size(), 0, "own pages");
        // Other tests allocate and release regions concurrently: only what
        // `s`, alive here, guarantees is checked.
        let during = locked_memory();
        if s.is_locked() {
            assert!(during.locked_regions >= 1 && during.locked_bytes >= region::page_size(), "{during:?}");
        } else {
            assert!(during.lock_failures >= 1 && during.unlocked_regions >= 1, "{during:?}");
        }
    }

    #[test]
    fn scrub_stack_runs() {
        scrub_stack();
    }
}
