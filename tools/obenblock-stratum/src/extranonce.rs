//! extranonce1 allocation.
//!
//! The Bloch proxy received each worker's `extranonce1` from the node's
//! stratum and could only detect collisions. Here the server assigns it, so
//! search spaces are disjoint by construction: every live connection holds a
//! distinct 4-byte value from [`ExtranonceRegistry`], released when the
//! connection ends ([`ExtranonceLease`] is RAII). Values start at a random
//! point so two servers mining for the same address (same coinbase script)
//! are unlikely to search the same space either; give each server its own
//! payout address to make that impossible.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::types::EXTRANONCE1_LEN;

#[derive(Debug)]
pub struct ExtranonceRegistry {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    next: u32,
    live: HashSet<u32>,
}

impl ExtranonceRegistry {
    pub fn new() -> Self {
        Self::starting_at(rand::random())
    }

    pub fn starting_at(start: u32) -> Self {
        Self { inner: Mutex::new(Inner { next: start, live: HashSet::new() }) }
    }

    /// Lease a value no live connection holds. `None` only when all 2^32
    /// values are taken (far above any connection cap).
    pub fn lease(self: &Arc<Self>) -> Option<ExtranonceLease> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.live.len() as u64 >= u32::MAX as u64 {
            return None;
        }
        loop {
            let v = g.next;
            g.next = g.next.wrapping_add(1);
            if g.live.insert(v) {
                return Some(ExtranonceLease { registry: self.clone(), value: v });
            }
        }
    }

    pub fn live(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).live.len()
    }

    fn release(&self, v: u32) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).live.remove(&v);
    }
}

impl Default for ExtranonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// One connection's extranonce1; released on drop.
#[derive(Debug)]
pub struct ExtranonceLease {
    registry: Arc<ExtranonceRegistry>,
    value: u32,
}

impl ExtranonceLease {
    pub fn bytes(&self) -> [u8; EXTRANONCE1_LEN] {
        self.value.to_be_bytes()
    }
}

impl Drop for ExtranonceLease {
    fn drop(&mut self) {
        self.registry.release(self.value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_are_distinct_and_released() {
        let r = Arc::new(ExtranonceRegistry::starting_at(u32::MAX - 1));
        let a = r.lease().unwrap();
        let b = r.lease().unwrap();
        let c = r.lease().unwrap(); // wraps around
        assert_eq!(a.bytes(), [0xff, 0xff, 0xff, 0xfe]);
        assert_eq!(c.bytes(), [0, 0, 0, 0]);
        assert_ne!(a.bytes(), b.bytes());
        assert_eq!(r.live(), 3);
        drop(b);
        assert_eq!(r.live(), 2);
    }

    #[test]
    fn a_held_value_is_skipped() {
        let r = Arc::new(ExtranonceRegistry::starting_at(5));
        let five = r.lease().unwrap();
        {
            let mut g = r.inner.lock().unwrap();
            g.next = 5; // force the counter back onto a held value
        }
        let next = r.lease().unwrap();
        assert_ne!(next.bytes(), five.bytes());
        assert_eq!(next.bytes(), 6u32.to_be_bytes());
    }
}
