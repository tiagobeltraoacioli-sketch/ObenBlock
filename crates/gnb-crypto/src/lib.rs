//! `gnb-crypto` — the lean crypto / wallet / transaction surface of the
//! Bloch-SIS Protocol, extracted from the `bloch` node so downstream products
//! (mobile wallets, explorers, messengers) can depend on it WITHOUT pulling the
//! full node (rocksdb, libp2p, axum, …).
//!
//! This crate is a pure code-move of the node's non-`node`-feature island:
//! `types, crypto, core, address, wallet, hd_wallet, util`. The node re-exports
//! these modules so every `crate::core::…` / `crate::crypto::…` path in the node
//! keeps resolving unchanged.

// I-4: this crate never needs `unsafe` — every FFI/low-level concern lives
// in `pqcrypto-internals` (deliberately excluded from this forbid, since it
// legitimately wraps C bindings). Forbidding it here (not just `deny`) means
// no `#[allow(unsafe_code)]` anywhere in this crate can quietly re-permit it.
#![forbid(unsafe_code)]

pub mod types;
pub mod crypto;
pub mod core;
pub mod address;
pub mod wallet;
pub mod hd_wallet;
pub mod util;
pub mod bridge;   // Bloch bridge v1, GnB side: vault, lock and release shapes
pub mod bloch_anchor; // Bloch finalized checkpoints anchored in GnB-SMH transactions
