//! GNB monetary policy. Consensus rules: changing anything here is a hard fork.
//!
//! Hard cap of 12,500,000 GNB, split in four fixed allocations:
//!
//! - **Bloch carryover, 1,000,000 GNB (8%).** The Bloch Genesis-3 terminal
//!   snapshot (3,810,744,000 BLCH over 452,726 outputs) is converted
//!   proportionally into the genesis ledger: every output of `v` BLCH base
//!   units becomes `floor(v × CARRYOVER_ALLOCATION_SAT / CARRYOVER_SOURCE_TOTAL_SAT)`
//!   GNB base units, same 20-byte owner hash. See `core::carryover`.
//! - **Team, 1,250,000 GNB (10%), and founder, 1,250,000 GNB (10%), locked.**
//!   Written into the genesis ledger as 36 monthly tranches each, every
//!   tranche an output locked by a spend policy (`core::policy`) with an
//!   absolute timelock: nothing is spendable during the first year
//!   ([`VESTING_CLIFF_BLOCKS`]), then one tranche unlocks every
//!   [`VESTING_TRANCHE_BLOCKS`] for three years; the last unlocks at height
//!   4,204,800. The lock is a consensus rule, not a promise. Keys and tranche
//!   layout: `core::vesting`.
//! - **Mining, 9,000,000 GNB (72%).** 100% of every block subsidy and 100% of
//!   every transaction fee go to the miner. The subsidy starts at
//!   `INITIAL_SUBSIDY_SAT` and halves (integer right shift, in base units)
//!   every `HALVING_INTERVAL` blocks, about 4 years at 30-second blocks.
//!   After 27 halvings it is zero and stays zero: there is no tail emission.
//!   Mined issuance is 8,999,998.51392253 GNB.
//! - The genesis coinbase is unspendable and pays nothing, so mining starts
//!   at height 1. Carryover, team, founder and mining together are
//!   12,499,998.51182046 GNB, strictly below `MAX_SUPPLY_SAT` (asserted by
//!   the tests below).
//! - Once the subsidy is exhausted, miners are paid by fees alone. Every
//!   non-coinbase transaction must pay at least [`min_tx_fee_sat`] by
//!   consensus, so block production always carries a revenue floor.

/// Base units per GNB.
pub const SAT_PER_GNB: u64 = 100_000_000;

/// Hard cap: total issuance never reaches this.
pub const MAX_SUPPLY_SAT: u64 = 12_500_000 * SAT_PER_GNB;

/// Converted Bloch Genesis-3 carryover (8% of the cap).
pub const CARRYOVER_ALLOCATION_SAT: u64 = 1_000_000 * SAT_PER_GNB;

/// Team allocation, locked (10%).
pub const TEAM_ALLOCATION_SAT: u64 = 1_250_000 * SAT_PER_GNB;

/// Founder allocation, locked (10%).
pub const FOUNDER_ALLOCATION_SAT: u64 = 1_250_000 * SAT_PER_GNB;

/// Emitted by mining (72%).
pub const MINING_ALLOCATION_SAT: u64 = 9_000_000 * SAT_PER_GNB;

const _: () = assert!(
    CARRYOVER_ALLOCATION_SAT + TEAM_ALLOCATION_SAT + FOUNDER_ALLOCATION_SAT + MINING_ALLOCATION_SAT
        == MAX_SUPPLY_SAT
);

/// Blocks per year at 30 s (365 × 2,880).
pub const BLOCKS_PER_YEAR: u64 = 365 * 2_880;

/// Team and founder allocations: nothing unlocks before this height (1 year).
pub const VESTING_CLIFF_BLOCKS: u64 = BLOCKS_PER_YEAR;

/// One monthly tranche (1/12 year).
pub const VESTING_TRANCHE_BLOCKS: u64 = BLOCKS_PER_YEAR / 12;

/// Monthly tranches after the cliff (3 years).
pub const VESTING_TRANCHES: u32 = 36;

/// Height from which tranche `k` (1-based, 1..=36) is spendable.
pub const fn vesting_unlock_height(k: u32) -> u64 {
    VESTING_CLIFF_BLOCKS + k as u64 * VESTING_TRANCHE_BLOCKS
}

/// Value of tranche `k` (1-based) of an allocation of `total`: equal
/// tranches rounded down, the remainder in the last one, so the tranches sum
/// to exactly `total`.
pub const fn vesting_tranche_value(total: u64, k: u32) -> u64 {
    let base = total / VESTING_TRANCHES as u64;
    if k == VESTING_TRANCHES {
        total - base * (VESTING_TRANCHES as u64 - 1)
    } else {
        base
    }
}

/// Target block spacing in seconds.
pub const TARGET_BLOCK_TIME_SECS: u64 = 30;

/// Blocks per halving: 4 years of 365 days at 30 s (4 × 365 × 2,880).
pub const HALVING_INTERVAL: u64 = 4 * 365 * 2_880;

/// Subsidy of the first halving epoch:
/// floor(MINING_ALLOCATION / (2 × HALVING_INTERVAL)) = 1.07020547 GNB.
pub const INITIAL_SUBSIDY_SAT: u64 = MINING_ALLOCATION_SAT / (2 * HALVING_INTERVAL);

/// Number of halvings after which the subsidy is zero.
pub const SUBSIDY_HALVINGS: u64 = 64 - INITIAL_SUBSIDY_SAT.leading_zeros() as u64;

/// First height whose subsidy is zero.
pub const LAST_SUBSIDY_HEIGHT_EXCLUSIVE: u64 = SUBSIDY_HALVINGS * HALVING_INTERVAL;

/// Block subsidy in base units at `height` on the node's chain. Height 0
/// (genesis) pays nothing. GnB: [`schedule_subsidy_sat`]. ObenBlock (both
/// networks): the same schedule under the slow start of
/// docs/DESIGN-obenblock.md §4.2, `floor(full × min(height, 5,760) / 5,760)`
/// (`pow_scheme::slow_start_subsidy_sat`); the withheld part (about 3,080
/// OBB) is never issued, so [`issued_through_sat`] stays an upper bound.
pub fn block_subsidy_sat(height: u64) -> u64 {
    let full = schedule_subsidy_sat(height);
    match super::node_chain_id().chain() {
        super::chain::Chain::Gnb => full,
        super::chain::Chain::ObenBlock => super::pow_scheme::slow_start_subsidy_sat(full, height),
    }
}

/// The halving schedule: `INITIAL_SUBSIDY_SAT >> (height / HALVING_INTERVAL)`,
/// 0 at height 0 (genesis) and after 64 halvings.
pub const fn schedule_subsidy_sat(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY_SAT >> halvings
}

/// Total mining subsidy issued by blocks `0..=height` under the halving
/// schedule (excludes the carryover): exact on GnB, an upper bound on
/// ObenBlock (slow start, [`block_subsidy_sat`]).
pub fn issued_through_sat(height: u64) -> u64 {
    let mut total: u64 = 0;
    let mut epoch = 0u64;
    loop {
        let start = (epoch * HALVING_INTERVAL).max(1);
        if start > height || epoch >= 64 {
            return total;
        }
        let end = ((epoch + 1) * HALVING_INTERVAL - 1).min(height);
        total += (end - start + 1) * (INITIAL_SUBSIDY_SAT >> epoch);
        epoch += 1;
    }
}

// ── Fees ─────────────────────────────────────────────────────────────────────

/// Consensus minimum fee rate, base units per 1,000 bytes of serialized
/// transaction (0.00002 GNB/kB).
pub const MIN_FEE_RATE_SAT_PER_KB: u64 = 2_000;

/// Consensus minimum fee of any non-coinbase transaction (0.0001 GNB).
pub const MIN_TX_FEE_SAT: u64 = 10_000;

/// Minimum fee a non-coinbase transaction of `size_bytes` must pay:
/// max(MIN_TX_FEE_SAT, ceil(size × MIN_FEE_RATE_SAT_PER_KB / 1000)).
///
/// A typical one-input, two-output transaction (hybrid ML-DSA-65 + Falcon-1024
/// signature and public key, about 8.6 kB) pays about 0.00017 GNB.
pub const fn min_tx_fee_sat(size_bytes: usize) -> u64 {
    let by_size = (size_bytes as u64).saturating_mul(MIN_FEE_RATE_SAT_PER_KB).div_ceil(1000);
    if by_size > MIN_TX_FEE_SAT {
        by_size
    } else {
        MIN_TX_FEE_SAT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vesting_schedule_is_one_year_cliff_then_36_monthly_tranches() {
        assert_eq!(VESTING_TRANCHE_BLOCKS, 87_600);
        assert_eq!(vesting_unlock_height(1), 1_051_200 + 87_600, "first tranche: month 13");
        assert_eq!(vesting_unlock_height(VESTING_TRANCHES), 4_204_800, "last tranche: 4 years");
        assert_eq!(vesting_unlock_height(VESTING_TRANCHES), HALVING_INTERVAL);
        for total in [TEAM_ALLOCATION_SAT, FOUNDER_ALLOCATION_SAT, 1, 35, 37, u64::MAX / 2] {
            let sum: u128 = (1..=VESTING_TRANCHES).map(|k| vesting_tranche_value(total, k) as u128).sum();
            assert_eq!(sum, total as u128, "tranches must sum to the allocation ({total})");
        }
        assert_eq!(vesting_tranche_value(TEAM_ALLOCATION_SAT, 1), 3_472_222_222_222);
        assert_eq!(vesting_tranche_value(TEAM_ALLOCATION_SAT, 36), 3_472_222_222_230);
    }

    #[test]
    fn schedule_constants() {
        assert_eq!(HALVING_INTERVAL, 4_204_800);
        assert_eq!(INITIAL_SUBSIDY_SAT, 107_020_547);
        assert_eq!(CARRYOVER_ALLOCATION_SAT + TEAM_ALLOCATION_SAT + FOUNDER_ALLOCATION_SAT
                   + MINING_ALLOCATION_SAT, MAX_SUPPLY_SAT);
        assert_eq!(SUBSIDY_HALVINGS, 27);
        assert_eq!(INITIAL_SUBSIDY_SAT >> SUBSIDY_HALVINGS, 0);
        assert!(INITIAL_SUBSIDY_SAT >> (SUBSIDY_HALVINGS - 1) > 0);
    }

    #[test]
    fn total_issuance_is_below_the_hard_cap() {
        let total = issued_through_sat(u64::MAX);
        assert_eq!(total, 899_999_851_392_253);
        assert!(total <= MINING_ALLOCATION_SAT);
        let carryover = crate::core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT;
        assert!(carryover <= CARRYOVER_ALLOCATION_SAT);
        assert_eq!(total + carryover, 999_999_851_182_046);
        let all = total + carryover + TEAM_ALLOCATION_SAT + FOUNDER_ALLOCATION_SAT;
        assert_eq!(all, 1_249_999_851_182_046);
        assert!(all < MAX_SUPPLY_SAT);
        assert_eq!(issued_through_sat(LAST_SUBSIDY_HEIGHT_EXCLUSIVE - 1), total);
    }

    #[test]
    fn issuance_matches_block_by_block_sum_at_boundaries() {
        let naive = |to: u64| (0..=to).map(block_subsidy_sat).sum::<u64>();
        for h in [0, 1, 2, 1_000, 50_000] {
            assert_eq!(issued_through_sat(h), naive(h), "h={h}");
        }
        let b = HALVING_INTERVAL;
        assert_eq!(issued_through_sat(b), (b - 1) * INITIAL_SUBSIDY_SAT + INITIAL_SUBSIDY_SAT / 2);
    }

    #[test]
    fn subsidy_halves_and_ends() {
        assert_eq!(block_subsidy_sat(0), 0, "genesis pays nothing");
        assert_eq!(block_subsidy_sat(1), INITIAL_SUBSIDY_SAT);
        assert_eq!(block_subsidy_sat(HALVING_INTERVAL - 1), INITIAL_SUBSIDY_SAT);
        assert_eq!(block_subsidy_sat(HALVING_INTERVAL), INITIAL_SUBSIDY_SAT / 2);
        assert_eq!(block_subsidy_sat(LAST_SUBSIDY_HEIGHT_EXCLUSIVE - 1), 1);
        assert_eq!(block_subsidy_sat(LAST_SUBSIDY_HEIGHT_EXCLUSIVE), 0);
        assert_eq!(block_subsidy_sat(u64::MAX), 0);
    }

    #[test]
    fn hard_cap_and_allocations() {
        assert_eq!(MAX_SUPPLY_SAT, 1_250_000_000_000_000);
        assert_eq!(TEAM_ALLOCATION_SAT + FOUNDER_ALLOCATION_SAT, 250_000_000_000_000);
        assert_eq!(CARRYOVER_ALLOCATION_SAT, 100_000_000_000_000);
        assert_eq!(MINING_ALLOCATION_SAT, 900_000_000_000_000);
        assert_eq!(LAST_SUBSIDY_HEIGHT_EXCLUSIVE, 27 * 4_204_800);
    }

    /// The shift guard: from the 64th halving on the subsidy is zero without
    /// shifting by 64 or more (which would overflow).
    #[test]
    fn subsidy_and_issuance_past_the_sixty_fourth_halving() {
        for h in [63 * HALVING_INTERVAL, 64 * HALVING_INTERVAL - 1, 64 * HALVING_INTERVAL, 65 * HALVING_INTERVAL] {
            assert_eq!(block_subsidy_sat(h), 0, "h={h}");
        }
        let total = issued_through_sat(u64::MAX);
        assert_eq!(issued_through_sat(64 * HALVING_INTERVAL), total);
        assert_eq!(issued_through_sat(64 * HALVING_INTERVAL - 1), total);
        assert_eq!(issued_through_sat(70 * HALVING_INTERVAL), total);
    }

    /// The closed form matches the block-by-block sum around every boundary
    /// of the first epochs, including the genesis (which pays nothing).
    #[test]
    fn issuance_at_epoch_edges() {
        let b = HALVING_INTERVAL;
        assert_eq!(issued_through_sat(0), 0);
        assert_eq!(issued_through_sat(1), INITIAL_SUBSIDY_SAT);
        assert_eq!(issued_through_sat(b - 1), (b - 1) * INITIAL_SUBSIDY_SAT);
        let e1 = (b - 1) * INITIAL_SUBSIDY_SAT;
        assert_eq!(issued_through_sat(b + 1), e1 + 2 * (INITIAL_SUBSIDY_SAT >> 1));
        let e2 = e1 + b * (INITIAL_SUBSIDY_SAT >> 1);
        assert_eq!(issued_through_sat(2 * b - 1), e2);
        assert_eq!(issued_through_sat(2 * b), e2 + (INITIAL_SUBSIDY_SAT >> 2));
        assert_eq!(issued_through_sat(3 * b + 5), e2 + b * (INITIAL_SUBSIDY_SAT >> 2) + 6 * (INITIAL_SUBSIDY_SAT >> 3));
    }

    #[test]
    fn min_fee_has_a_floor_and_scales_with_size() {
        assert_eq!(min_tx_fee_sat(0), MIN_TX_FEE_SAT);
        assert_eq!(min_tx_fee_sat(5_000), MIN_TX_FEE_SAT);
        assert_eq!(min_tx_fee_sat(8_600), 17_200);
        assert_eq!(min_tx_fee_sat(8_601), 17_202);
        // The floor and the size rule meet at 5,000 bytes; 5,001 rounds up.
        assert_eq!(min_tx_fee_sat(5_001), 10_002);
        assert_eq!(min_tx_fee_sat(1), MIN_TX_FEE_SAT);
        assert_eq!(MIN_FEE_RATE_SAT_PER_KB, 2_000);
        // The product is computed in u64 on every target, so a size that fits
        // in 32 bits gets the same, exact fee on 32- and 64-bit platforms.
        assert_eq!(min_tx_fee_sat(u32::MAX as usize), 2 * u32::MAX as u64);
        // The largest size: on 64-bit targets the product saturates at
        // u64::MAX; with a 32-bit usize (i686, wasm32 wallets) it cannot
        // overflow and stays exact. (Before the i686 CI job this test asserted
        // the 64-bit value unconditionally and failed on 32-bit targets.)
        #[cfg(target_pointer_width = "64")]
        assert_eq!(min_tx_fee_sat(usize::MAX), u64::MAX.div_ceil(1000));
        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(min_tx_fee_sat(usize::MAX), 2 * usize::MAX as u64);
    }
}
