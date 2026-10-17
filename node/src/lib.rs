//! GnB (Gödel and Bell) — a post-quantum proof-of-work BlockDAG L1.
//!
//! This is the node's library crate; embedders consume it via
//! `gnb = { path = "node" }`.
//!
//! Typical wallet imports:
//!
//!   use gnb::prelude::*;
//!
//! This gives you: Address, Network, Transaction, TxInput, TxOutput,
//! Block, all core errors, and wallet utilities.

// The lean crypto/wallet/tx surface lives in the `gnb-crypto` crate now
// (crates/gnb-crypto). Re-export its modules under the original paths so every
// `crate::core::…` / `crate::crypto::…` reference in the node keeps resolving
// unchanged, and so external embedders keep importing `gnb::{core,crypto,…}`.
pub use gnb_crypto::{types, crypto, core, address, wallet, hd_wallet, util, bridge, bloch_anchor};

#[cfg(feature = "node")]
pub mod analytics;   // Sprint B      // Sprint A — new unified Address type
#[cfg(feature = "node")]
pub mod storage;
#[cfg(feature = "node")]
pub mod consensus;
#[cfg(feature = "node")]
pub mod mining;
#[cfg(feature = "node")]
pub mod mempool;
#[cfg(feature = "node")]
pub mod network;
#[cfg(feature = "node")]
pub mod rpc;
#[cfg(feature = "node")]
pub mod metrics;
#[cfg(feature = "node")]
pub mod pow;         // GnB-SMH PoW adapter
#[cfg(feature = "node")]
pub mod transport;

#[cfg(feature = "node")]
pub mod tip;

// Sprint U.3 — Reorg detection & execution primitives (towards audit C-1).
#[cfg(feature = "node")]
pub mod reorg;
pub mod blockval;   // single block-transaction rule set (accept + reorg)
#[cfg(feature = "node")]
pub mod attestation;  // Bloch-SIS-Linux L3 — pluggable remote attestation
#[cfg(feature = "node")]
pub mod coherence;    // Coherence C2 — shielded pool (notes, tree, spend statement)
#[cfg(feature = "node")]
pub mod sync;         // Phase 2 — drop-in Kaspa sync-negotiation layer (frontier reconciliation)
#[cfg(feature = "node")]
pub mod powit;        // PoW + PoWit node side (shares, attestations, finality)
pub mod ingress;      // audit fixes: block-ingress / orphan / IBD-latch policy
// Block acceptance pipeline (accept / connect split, audit DAG-1/10/11),
// moved out of main.rs so integration tests drive the real path.
#[cfg(feature = "node")]
pub mod accept;
// Assumed-valid block (Bitcoin Core's -assumevalid): which connects skip the
// signature checks (P5-G).
#[cfg(feature = "node")]
pub mod assumevalid;
// Block-template construction shared by the miner and getblocktemplate
// (audit MEM-2, DAG-2).
#[cfg(feature = "node")]
pub mod template;

// The libp2p crate the node is built with, for code that drives the node's
// protocol implementations through libp2p traits and must name the SAME crate
// instance (the fuzz target `sync_rr_codec` calls `BlochSyncCodec` through
// `request_response::Codec`). Naming libp2p in such a crate with its own
// version requirement could resolve to another 0.x minor, whose traits
// `BlochSyncCodec` does not implement.
#[cfg(feature = "node")]
#[doc(hidden)]
pub use libp2p;

/// Convenience re-exports for consumers of the library (wallet UIs,
/// block explorers, etc.). Import with `use gnb::prelude::*`.
pub mod prelude {
    // Address handling (Sprint A)
    pub use crate::address::{Address, Network, AddressError};

    // Core blockchain types
    pub use crate::core::{
        Block, BlockHeader,
        Transaction, TxInput, TxOutput,
        // Constants commonly needed in wallet UIs:
        COINBASE_MATURITY,
        DUST_THRESHOLD, TARGET_BLOCK_TIME,
        MAINNET_PREFIX, TESTNET_PREFIX,
        SIG_SIZE, PUBKEY_SIZE,
    };

    // Crypto primitives
    pub use crate::crypto::{
        generate_keypair, sign, verify,
        address_from_pubkey, address_from_hash,
    };

    // Mempool types (for RPC consumers and wallet indicators)
    #[cfg(feature = "node")]
    pub use crate::mempool::{Mempool, MempoolEntry, MempoolError, AddressTxInfo};
}

#[cfg(test)]
mod build_profile_tests {
    /// The node's lib tests run with debug assertions and overflow checks:
    /// both are on by default in the dev/test profile (the root Cargo.toml
    /// overrides only opt-level per package), and this test fails if a
    /// profile change ever turns them off (docs/testing/SANITIZERS.md).
    #[test]
    fn test_build_traps_integer_overflow_and_debug_assertions() {
        let d = std::panic::catch_unwind(|| debug_assert!(std::hint::black_box(false)));
        assert!(d.is_err(), "debug_assert! did not fire: lib tests must run with debug assertions");
        let r =std::panic::catch_unwind(|| std::hint::black_box(u64::MAX) + std::hint::black_box(1u64));
        assert!(r.is_err(), "integer overflow did not panic: overflow-checks are off for the node lib");
    }
}
