//! The memory behind a [`crate::SecretBytes`]: whole pages of an anonymous,
//! locked mapping on Unix (Bitcoin Core's `PosixLockedPageAllocator`), wiped
//! heap memory elsewhere.

use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;
use std::sync::Once;

use zeroize::Zeroize;

use crate::{LOCKED_BYTES, LOCKED_REGIONS, LOCK_FAILURES, UNLOCKED_REGIONS};

/// Alignment of the heap fallback.
const HEAP_ALIGN: usize = 16;

/// One secret's memory. `size` is a whole number of pages (or of
/// `HEAP_ALIGN` units on the heap) and at least the secret's length.
pub(crate) struct Region {
    ptr: NonNull<u8>,
    size: usize,
    locked: bool,
    mapped: bool,
}

/// The system page size (4,096 where it cannot be read).
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn page_size() -> usize {
    static PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        #[cfg(unix)]
        {
            // SAFETY: sysconf has no preconditions.
            let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if n > 0 {
                return n as usize;
            }
        }
        4096
    })
}

fn round_up(len: usize, unit: usize) -> usize {
    let len = len.max(1);
    len.div_ceil(unit).checked_mul(unit).expect("secret region size overflows usize")
}

impl Region {
    /// A zero-filled region of at least `len` bytes.
    pub(crate) fn new(len: usize) -> Region {
        #[cfg(unix)]
        {
            if let Some(r) = Self::map(round_up(len, page_size())) {
                return r;
            }
        }
        Self::heap(round_up(len, HEAP_ALIGN))
    }

    #[cfg(unix)]
    fn map(size: usize) -> Option<Region> {
        // SAFETY: an anonymous private read-write mapping at an address the
        // kernel chooses; no file descriptor, nothing else is affected.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return None;
        }
        let ptr = NonNull::new(p.cast::<u8>())?;
        // SAFETY: [p, p + size) is exactly the mapping created above.
        let locked = unsafe { libc::mlock(p, size) } == 0;
        exclude_from_core_dumps(p, size);
        account_new(locked, size);
        if !locked {
            lock_failed();
        }
        Some(Region { ptr, size, locked, mapped: true })
    }

    fn heap(size: usize) -> Region {
        let layout = Layout::from_size_align(size, HEAP_ALIGN).expect("secret region layout");
        // SAFETY: `layout` has a non-zero size (`round_up` returns >= 1 unit).
        let p = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(p).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
        account_new(false, size);
        #[cfg(unix)]
        lock_failed(); // only reached when mmap failed
        Region { ptr, size, locked: false, mapped: false }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for reads of `size` initialised bytes for
        // the region's lifetime (zero-filled at creation) and uniquely owned.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`, and `&mut self` makes the access unique.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }

    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // Volatile writes (zeroize), never elided, over the whole region.
        self.as_mut_slice().zeroize();
        #[cfg(any(test, feature = "test-support"))]
        if crate::test_support::hold(self.ptr, self.size, self.locked, self.mapped) {
            return; // the test quarantine releases it later
        }
        // SAFETY: the region is released exactly once, here.
        unsafe { release(self.ptr, self.size, self.locked, self.mapped) };
    }
}

/// Return a region's memory (after it was wiped).
///
/// # Safety
/// `ptr`/`size`/`locked`/`mapped` describe one live region created by
/// [`Region::new`], and it is released only once.
pub(crate) unsafe fn release(ptr: NonNull<u8>, size: usize, locked: bool, mapped: bool) {
    account_release(locked, size);
    #[cfg(unix)]
    if mapped {
        let p = ptr.as_ptr().cast::<libc::c_void>();
        if locked {
            // SAFETY: [p, p + size) is a locked mapping we own.
            unsafe { libc::munlock(p, size) };
        }
        // SAFETY: [p, p + size) is a mapping we own and nothing refers to it.
        unsafe { libc::munmap(p, size) };
        return;
    }
    let _ = (locked, mapped);
    let layout = Layout::from_size_align(size, HEAP_ALIGN).expect("secret region layout");
    // SAFETY: allocated by `Region::heap` with this exact layout.
    unsafe { std::alloc::dealloc(ptr.as_ptr(), layout) };
}

#[cfg(unix)]
fn exclude_from_core_dumps(p: *mut libc::c_void, size: usize) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SAFETY: advisory flag on a mapping we own.
        unsafe { libc::madvise(p, size, libc::MADV_DONTDUMP) };
    }
    #[cfg(target_os = "freebsd")]
    {
        // SAFETY: advisory flag on a mapping we own.
        unsafe { libc::madvise(p, size, libc::MADV_NOCORE) };
    }
    let _ = (p, size);
}

fn account_new(locked: bool, size: usize) {
    if locked {
        LOCKED_BYTES.fetch_add(size, Ordering::Relaxed);
        LOCKED_REGIONS.fetch_add(1, Ordering::Relaxed);
    } else {
        UNLOCKED_REGIONS.fetch_add(1, Ordering::Relaxed);
    }
}

fn account_release(locked: bool, size: usize) {
    if locked {
        LOCKED_BYTES.fetch_sub(size, Ordering::Relaxed);
        LOCKED_REGIONS.fetch_sub(1, Ordering::Relaxed);
    } else {
        UNLOCKED_REGIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Count a failed lock and warn once, as Bitcoin Core does
/// ("Failed to lock memory ... ulimit -l").
#[cfg(unix)]
fn lock_failed() {
    static WARN: Once = Once::new();
    LOCK_FAILURES.fetch_add(1, Ordering::Relaxed);
    WARN.call_once(|| {
        log::warn!(
            "could not lock secret key memory in RAM (mlock): it may be swapped to disk; \
             raise the locked-memory limit (ulimit -l / LimitMEMLOCK) to avoid this"
        );
    });
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn lock_failed() {
    let _ = Once::new();
}
