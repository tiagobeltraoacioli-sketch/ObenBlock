//! Liveness when hashrate arrives and leaves (ObenBlock,
//! `docs/DESIGN-obenblock.md` §5; `docs/CONSENSUS.md`, "Liveness").
//!
//! - **Stall relief** (§5.1): a block's own timestamp relaxes its ASERT
//!   target once it is more than 3 minutes later than its parents
//!   ([`expected_block_bits`], `gnb_smh::stall_relief`).
//! - **Faster inactivity leak** (§5.2): the absent members of W lose half of
//!   their weight per epoch instead of 1/16 (`powit::InactivityLeak`, a PoWit
//!   parameter of the chain).
//! - **Witness exit**: a witness signs an exit with its KES key and its weight
//!   leaves W from the next epoch (`powit::WitnessExit`, [`exit_message`]).
//!
//! # Activation
//!
//! Each chain selects a liveness activation height
//! ([`liveness_activation_height_for_chain`]): the GnB networks never
//! activate it (GnB's rules are unchanged), ObenBlock applies it from the
//! genesis block ([`OBENBLOCK_LIVENESS_ACTIVATION_HEIGHT`]). Stall relief
//! applies to a block whose header height is at or above it; a block may
//! carry witness exits, and its PoWit section carries the exits list on the
//! wire, iff its height is at or above it. The leak rule is not height-gated:
//! decay steps are stored as counts, so their size is a constant of the
//! chain (`powit::PowitParams::leak`).
//!
//! The normative executable definition is `reference/obb_liveness.py`;
//! `reference/liveness_vectors.json` pins it
//! (`crates/gnb-crypto/tests/liveness_vectors.rs`).

use std::cell::Cell;

use sha3::{Digest, Sha3_256};

use super::activation::{self, NEVER};
use super::kes::KesPublic;
use super::ChainId;

pub use gnb_smh::stall_relief::{StallReliefParams, OBENBLOCK_STALL_RELIEF};

/// GnB mainnet and testnet: the liveness rules never activate.
pub const GNB_LIVENESS_ACTIVATION_HEIGHT: u64 = NEVER;

/// ObenBlock (mainnet and regtest): every liveness rule from the genesis
/// block ([`liveness_activation_height_for_chain`] maps the ObenBlock chain
/// ids here).
pub const OBENBLOCK_LIVENESS_ACTIVATION_HEIGHT: u64 = 0;

/// Witness exits one block may carry (each costs a KES verification).
pub const MAX_EXITS_PER_BLOCK: usize = 4;

/// Liveness activation height of a chain.
pub const fn liveness_activation_height_for_chain(id: ChainId) -> u64 {
    match id {
        ChainId::Mainnet | ChainId::Testnet => GNB_LIVENESS_ACTIVATION_HEIGHT,
        ChainId::ObenBlockMainnet | ChainId::ObenBlockRegtest => OBENBLOCK_LIVENESS_ACTIVATION_HEIGHT,
    }
}

thread_local! {
    static THREAD_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The process-wide liveness activation height: a [`scoped_override`] on the
/// calling thread (tests), then the node's chain id, then the GnB mainnet
/// value (never), as `activation::hardening_activation_height` does.
pub fn liveness_activation_height() -> u64 {
    if let Some(h) = THREAD_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    match super::NODE_CHAIN_ID.get() {
        Some(id) => liveness_activation_height_for_chain(*id),
        None => GNB_LIVENESS_ACTIVATION_HEIGHT,
    }
}

/// `true` iff the liveness rules apply to a block at `height` under the
/// process-wide activation height.
pub fn liveness_active_at(height: u64) -> bool {
    activation::is_active_at(height, liveness_activation_height())
}

/// Guard returned by [`scoped_override`]; restores the previous value on drop.
#[must_use = "the override ends when the guard is dropped"]
pub struct OverrideGuard {
    previous: Option<u64>,
}

impl Drop for OverrideGuard {
    fn drop(&mut self) {
        let prev = self.previous;
        THREAD_OVERRIDE.with(|c| c.set(prev));
    }
}

/// Override [`liveness_activation_height`] on the calling thread until the
/// guard is dropped (tests only; see `activation::scoped_override`).
pub fn scoped_override(activation_height: u64) -> OverrideGuard {
    let previous = THREAD_OVERRIDE.with(|c| c.replace(Some(activation_height)));
    OverrideGuard { previous }
}

// ── Stall relief ─────────────────────────────────────────────────────────────

/// Expected compact `bits` of a block at `height` stamped `time` whose
/// parents' latest timestamp is `parent_timestamp`: the ASERT bits
/// ([`super::expected_bits`]), relaxed by the stall relief when the liveness
/// rules apply at `height`. Below the liveness activation (always, on GnB)
/// this is `expected_bits` itself, bit for bit. Single source of truth for
/// the validator, the miner and every template producer once a block's own
/// timestamp is known.
pub fn expected_block_bits(parent_timestamp: u64, height: u64, time: u64) -> Result<u32, String> {
    let base = super::expected_bits(parent_timestamp, height)?;
    Ok(relieve_at(base, parent_timestamp, height, time, activation::hardening_activation_height(),
                  liveness_activation_height()))
}

/// [`expected_block_bits`] with explicit hardening and liveness activation
/// heights (never pinned by the `test-pow-limit` feature).
pub fn expected_block_bits_at(parent_timestamp: u64, height: u64, time: u64, hardening_height: u64,
                              liveness_height: u64) -> Result<u32, String> {
    let base = super::expected_bits_at(parent_timestamp, height, hardening_height)?;
    Ok(relieve_at(base, parent_timestamp, height, time, hardening_height, liveness_height))
}

/// `base` (a block's ASERT bits) relaxed for a block stamped `time` (no
/// change below the liveness activation). The relief is clamped to the ASERT
/// pow limit of `height`. For producers that hold a template's base bits.
pub fn relieve_at(base: u32, parent_timestamp: u64, height: u64, time: u64, hardening_height: u64,
              liveness_height: u64) -> u32 {
    if !activation::is_active_at(height, liveness_height) {
        return base;
    }
    // Saturate to i64: the relief only compares the two times.
    let as_i64 = |t: u64| i64::try_from(t).unwrap_or(i64::MAX);
    let limit = super::asert_params_at(height, hardening_height).pow_limit;
    gnb_smh::stall_relief::relieved_bits(&OBENBLOCK_STALL_RELIEF, base, as_i64(parent_timestamp), as_i64(time),
                                         &limit)
}

/// The easiest target an honest block at `height` stamped no later than
/// `latest_time` can carry over a parent stamped `parent_timestamp`, given
/// its ASERT target `reference` (anti-DoS references; never consensus).
/// Below the liveness activation: `reference`.
pub fn relieved_reference(reference: &[u8; 32], parent_timestamp: u64, height: u64, latest_time: u64)
    -> [u8; 32]
{
    if !liveness_active_at(height) {
        return *reference;
    }
    let as_i64 = |t: u64| i64::try_from(t).unwrap_or(i64::MAX);
    let limit = super::asert_params_at(height, activation::hardening_activation_height()).pow_limit;
    let base = gnb_smh::difficulty::Target(*reference);
    gnb_smh::stall_relief::relieved_target(&OBENBLOCK_STALL_RELIEF, &base, as_i64(parent_timestamp),
                                           as_i64(latest_time), &limit.max(base)).0
}

// ── Witness exit message ─────────────────────────────────────────────────────

const DS_EXIT: &[u8] = b"OBB-POWIT-v1/exit";

/// The digest a witness signs to exit, with the KES leaf of `epoch`, on the
/// chain with id `chain_id`:
///
/// ```text
/// SHA3-256( u32le(17) ‖ "OBB-POWIT-v1/exit" ‖ u32le(chain_id)
///           ‖ u8(depth) ‖ root[32] ‖ u64le(epoch) )                // 66-byte preimage
/// ```
///
/// It commits the key (as the v2 attestation message does, PoWit finding 1)
/// and the chain id (no exit is valid on two chains).
pub fn exit_message_raw(chain_id: u32, witness: &KesPublic, epoch: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update((DS_EXIT.len() as u32).to_le_bytes());
    h.update(DS_EXIT);
    h.update(chain_id.to_le_bytes());
    h.update([witness.depth]);
    h.update(witness.root);
    h.update(epoch.to_le_bytes());
    h.finalize().into()
}

/// [`exit_message_raw`] for a [`ChainId`].
pub fn exit_message(chain: ChainId, witness: &KesPublic, epoch: u64) -> [u8; 32] {
    exit_message_raw(chain.to_u32(), witness, epoch)
}

/// Whether an exit signed for KES epoch `exit_epoch` may be included in a
/// block of PoWit epoch `block_epoch`: the same epoch or the next one, so an
/// exit signed late in an epoch still reaches a block, and an old exit can
/// never be replayed.
pub const fn exit_epoch_ok(block_epoch: u64, exit_epoch: u64) -> bool {
    exit_epoch <= block_epoch && block_epoch <= exit_epoch.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnb_never_activates_and_the_override_is_scoped() {
        assert_eq!(liveness_activation_height_for_chain(ChainId::Mainnet), NEVER);
        assert_eq!(liveness_activation_height_for_chain(ChainId::Testnet), NEVER);
        if super::super::NODE_CHAIN_ID.get().is_none() {
            assert_eq!(liveness_activation_height(), NEVER);
        }
        let before = liveness_activation_height();
        {
            let _g = scoped_override(0);
            assert!(liveness_active_at(0));
            let other = std::thread::spawn(liveness_activation_height).join().unwrap();
            assert_eq!(other, before);
        }
        assert_eq!(liveness_activation_height(), before);
    }

    /// Below the activation the expected bits are ASERT's, whatever the
    /// block's own timestamp.
    #[test]
    fn inactive_relief_is_asert_bit_for_bit() {
        let g = super::super::GENESIS_TIMESTAMP;
        for (pt, h, t) in [(g, 1, g + 30), (g, 1, g + 100_000), (g + 3_000, 50, g + 90_000)] {
            let base = super::super::expected_bits_at(pt, h, 0).unwrap();
            assert_eq!(expected_block_bits_at(pt, h, t, 0, NEVER).unwrap(), base);
            assert_eq!(expected_block_bits_at(pt, h, t, 0, h + 1).unwrap(), base);
        }
    }

    #[test]
    fn active_relief_eases_late_blocks_only() {
        let g = super::super::GENESIS_TIMESTAMP;
        let base = super::super::expected_bits_at(g, 1, NEVER).unwrap();
        assert_eq!(expected_block_bits_at(g, 1, g + 179, NEVER, 0).unwrap(), base);
        let late = expected_block_bits_at(g, 1, g + 180 + 1_800, NEVER, 0).unwrap();
        let (b, l) = (gnb_smh::difficulty::bits_to_target(base), gnb_smh::difficulty::bits_to_target(late));
        assert!(l > b);
    }

    #[test]
    fn exit_epoch_window() {
        assert!(exit_epoch_ok(5, 5) && exit_epoch_ok(6, 5));
        assert!(!exit_epoch_ok(4, 5) && !exit_epoch_ok(7, 5));
        assert!(exit_epoch_ok(u64::MAX, u64::MAX));
    }
}
