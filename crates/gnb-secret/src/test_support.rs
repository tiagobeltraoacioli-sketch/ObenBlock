//! Test support (feature `test-support`): observe what a dropped secret
//! leaves in memory.
//!
//! While a [`Quarantine`] is alive, every region released on the calling
//! thread is wiped as usual but kept mapped instead of returned, so a test
//! can read it after the owner was dropped. [`Quarantine::released`] returns
//! copies of those regions; every byte must be zero.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::ptr::NonNull;

struct Held {
    ptr: NonNull<u8>,
    size: usize,
    locked: bool,
    mapped: bool,
}

thread_local! {
    static QUARANTINE: RefCell<Option<Vec<Held>>> = const { RefCell::new(None) };
}

/// Keeps the regions released on this thread mapped until dropped.
pub struct Quarantine {
    _not_send: PhantomData<*const ()>,
}

impl Quarantine {
    /// Start quarantining on this thread. Panics if one is already active.
    pub fn start() -> Quarantine {
        QUARANTINE.with(|q| {
            let mut q = q.borrow_mut();
            assert!(q.is_none(), "a Quarantine is already active on this thread");
            *q = Some(Vec::new());
        });
        Quarantine { _not_send: PhantomData }
    }

    /// The contents of every region released on this thread since
    /// [`Quarantine::start`], read after their owners were dropped (whole
    /// regions, page padding included).
    pub fn released(&self) -> Vec<Vec<u8>> {
        QUARANTINE.with(|q| {
            q.borrow().as_ref().map_or_else(Vec::new, |held| {
                held.iter()
                    .map(|h| {
                        // SAFETY: a held region stays mapped (and is not
                        // reused) until this quarantine is dropped.
                        unsafe { std::slice::from_raw_parts(h.ptr.as_ptr(), h.size) }.to_vec()
                    })
                    .collect()
            })
        })
    }

    /// `true` iff every byte of every released region is zero.
    pub fn all_released_zeroed(&self) -> bool {
        self.released().iter().all(|r| r.iter().all(|&b| b == 0))
    }
}

impl Drop for Quarantine {
    fn drop(&mut self) {
        let held = QUARANTINE.with(|q| q.borrow_mut().take()).unwrap_or_default();
        for h in held {
            // SAFETY: each held region was handed over once by `Region::drop`
            // instead of being released.
            unsafe { crate::region::release(h.ptr, h.size, h.locked, h.mapped) };
        }
    }
}

/// Called by `Region::drop` after the wipe: keep the region if a quarantine
/// is active on this thread.
pub(crate) fn hold(ptr: NonNull<u8>, size: usize, locked: bool, mapped: bool) -> bool {
    QUARANTINE
        .try_with(|q| match q.borrow_mut().as_mut() {
            Some(list) => {
                list.push(Held { ptr, size, locked, mapped });
                true
            }
            None => false,
        })
        .unwrap_or(false)
}

// ── Stack residue ────────────────────────────────────────────────────────────

/// Bytes of dead stack [`dead_stack_below_caller`] copies: twice
/// [`crate::STACK_SCRUB_BYTES`], so a secret left just past the scrubbed
/// range is seen too.
pub const STACK_PROBE_BYTES: usize = 2 * crate::STACK_SCRUB_BYTES;

/// A copy of the [`STACK_PROBE_BYTES`] of stack directly below the caller's
/// frame: the memory the frames of the functions the caller called before
/// used, and left behind when they returned.
///
/// Call it right after the function under test, from the same function
/// (both calls then start their frames at the same stack pointer), and look
/// for copies of the secret with [`residue`]. This is how the CRY-4 tests
/// show that signing and key generation leave no copy of a secret key in
/// dead stack frames (the `Copy` `pqcrypto` `SecretKey` values, a seed
/// returned by value, the C code's expanded keys).
///
/// Test-only: it reads stack memory no live Rust value owns (volatile byte
/// reads of the probe's own, never-written frame).
#[inline(never)]
pub fn dead_stack_below_caller() -> Vec<u8> {
    let frame = std::mem::MaybeUninit::<[u8; STACK_PROBE_BYTES]>::uninit();
    let base = frame.as_ptr().cast::<u8>();
    let mut out = Vec::with_capacity(STACK_PROBE_BYTES);
    for i in 0..STACK_PROBE_BYTES {
        // SAFETY: `base..base + STACK_PROBE_BYTES` is this function's own
        // stack array, valid for reads; it is never written, so each byte is
        // whatever an earlier, returned frame left there (test-only read of
        // dead memory, no value is formed from it but a `u8`).
        out.push(unsafe { std::ptr::read_volatile(base.add(i)) });
    }
    std::hint::black_box(&frame);
    out
}

/// Window length [`residue`] matches.
pub const RESIDUE_WINDOW: usize = 16;

/// Where `memory` holds a copy of part of `secret`: every
/// [`RESIDUE_WINDOW`]-byte window of `secret` found in `memory`, as
/// `(offset in secret, offset in memory)`. Windows of one repeated byte are
/// skipped (they also occur by chance, e.g. as zero padding).
pub fn residue(memory: &[u8], secret: &[u8]) -> Vec<(usize, usize)> {
    use std::collections::HashMap;
    let mut windows: HashMap<&[u8], usize> = HashMap::new();
    for (i, w) in secret.windows(RESIDUE_WINDOW).enumerate() {
        if w.iter().any(|&b| b != w[0]) {
            windows.entry(w).or_insert(i);
        }
    }
    let mut hits = Vec::new();
    for (j, w) in memory.windows(RESIDUE_WINDOW).enumerate() {
        if let Some(&i) = windows.get(w) {
            hits.push((i, j));
        }
    }
    hits
}

#[cfg(test)]
mod residue_tests {
    use super::*;

    #[inline(never)]
    fn leave_a_copy(secret: &[u8; 64]) -> u8 {
        // A by-value copy in a frame that is dead once this returns.
        let copy: [u8; 64] = std::hint::black_box(*secret);
        std::hint::black_box(&copy);
        copy[0]
    }

    /// The probe sees a copy a returned frame left, and sees none after
    /// `scrub_stack`.
    #[test]
    fn the_probe_sees_dead_frames_and_scrub_stack_clears_them() {
        let mut secret = [0u8; 64];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        leave_a_copy(&secret);
        let stack = dead_stack_below_caller();
        assert!(!residue(&stack, &secret).is_empty(), "the probe sees a dead frame's copy");
        leave_a_copy(&secret);
        crate::scrub_stack();
        let stack = dead_stack_below_caller();
        assert!(residue(&stack, &secret).is_empty(), "scrub_stack wiped it");
        assert!(residue(&[7; 64], &[7; 64]).is_empty(), "repeated-byte windows are ignored");
    }
}
