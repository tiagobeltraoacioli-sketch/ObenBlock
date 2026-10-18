//! Scheduled activation of consensus-rule changes ("hardening" upgrade).
//!
//! Audit 2026-10-14 found consensus bugs whose fixes change the result of
//! validation (GhostDAG blue work, k-cluster coloring, mergeset and
//! merge-depth limits, and further rules added later). A node cannot simply
//! switch to the corrected rules: every block already on the chain was
//! validated, colored and stored under the old rules, and a node replaying or
//! extending that history must reach the same `GhostdagData` and the same
//! verdicts as every other node. The fixes therefore activate at a scheduled
//! height:
//!
//! | network | activation height |
//! | --- | --- |
//! | mainnet | [`MAINNET_HARDENING_ACTIVATION_HEIGHT`] = 17,500 (about 2026-10-17 04:17 UTC on the ASERT schedule; see the constant) |
//! | testnet | [`TESTNET_HARDENING_ACTIVATION_HEIGHT`] = 0 (active from genesis) |
//! | regtest | [`REGTEST_HARDENING_ACTIVATION_HEIGHT`] = 0 (active from genesis) |
//! | ObenBlock mainnet | [`OBENBLOCK_HARDENING_ACTIVATION_HEIGHT`] = 0 (active from genesis) |
//!
//! "mainnet" and "testnet" are GnB's networks. ObenBlock
//! (docs/DESIGN-obenblock.md §3) applies every rule of both upgrades from its
//! genesis block on both its networks; its regtest uses the regtest schedule.
//! None of the legacy regimes is reachable on ObenBlock.
//!
//! A second upgrade ("hardening 2", the Phase-5 audit fixes) has its own
//! schedule with the same API suffixed `2` / `_v2`
//! ([`hardening2_activation_height`], [`hardening2_active_at`],
//! [`scoped_override_v2`]): mainnet [`MAINNET_HARDENING2_ACTIVATION_HEIGHT`]
//! = [`NEVER`] until the owner schedules it, testnet and regtest 0. Its rules
//! build on the first upgrade's and activate at or after it on every network.
//!
//! A gated rule applies to a block iff `block_height >= activation_height`
//! ([`is_active_at`]). Below the activation height the old behaviour must be
//! reproduced *exactly*, including its bugs.
//!
//! # Which height
//!
//! Each gated rule must document which height it compares. The GhostDAG rules
//! (`node/src/consensus/mod.rs`) compare `GhostdagData::height` of the block
//! being added, i.e. `selected_parent.height + 1`. That value is a pure
//! function of the block's parents and the DAG, so every node gates the same
//! block the same way regardless of arrival order. A rule that runs before the
//! block reaches GhostDAG (for example a structural or transaction rule) should
//! use the header height checked by `accept_block`; mixing the two on one rule
//! is a consensus bug.
//!
//! # How to use it
//!
//! Production code reads the process-wide value once, where it builds its
//! long-lived state, and keeps it:
//!
//! ```
//! use gnb_crypto::core::activation;
//! let activation_height = activation::hardening_activation_height();
//! # let block_height = 0u64;
//! if activation::is_active_at(block_height, activation_height) {
//!     // new rule
//! } else {
//!     // old rule, bit-identical to the pre-activation code
//! }
//! ```
//!
//! [`hardening_activation_height`] derives the height from the node's chain id
//! (`super::set_node_chain_id`, called once at startup from `--testnet`).
//! Code that needs to test both regimes should take the activation height as a
//! parameter (as `GhostDAG::with_k_and_activation` does) instead of reading
//! the global, and call the `*_for_*` / [`is_active_at`] helpers. Where that is
//! impractical, [`scoped_override`] sets a per-thread value for the duration of
//! a test.
//!
//! # When no chain id was set
//!
//! Unit and integration tests never call `set_node_chain_id`, and
//! `node_chain_id()` then reports Mainnet. [`hardening_activation_height`]
//! follows the same rule and returns the **mainnet** height. Consequences:
//!
//! - a test that builds its DAG far below the mainnet height, as almost
//!   every test does, keeps exercising the old rules; a test that needs a
//!   mainnet-regime height above it, or a boundary height, derives it from
//!   [`MAINNET_HARDENING_ACTIVATION_HEIGHT`] or pins its own activation
//!   height, never a literal (the two that replay old-rules history at
//!   heights the mainnet activation may fall below,
//!   `node/tests/backfill_flood_lab.rs` and
//!   `node/tests/ghostdag_replay_snapshot.rs`, pin [`NEVER`]);
//! - a binary that forgot to set its chain id behaves like a mainnet node, the
//!   conservative choice (it never applies the new rules early);
//! - tests of the new rules must opt in explicitly, with an activation-height
//!   parameter (0 = new rules from genesis, [`NEVER`] = old rules forever) or
//!   with [`scoped_override`].
//!
//! # Adding another gated rule
//!
//! 1. Reuse this height unless the rule genuinely needs a separate schedule;
//!    one coordinated upgrade is easier to deploy and reason about than
//!    several.
//! 2. Gate it with [`is_active_at`] on a documented height (see above).
//! 3. Keep the old code path untouched below the height and prove it with a
//!    replay test that runs the old path with the activation height set to
//!    [`NEVER`].
//! 4. Add the rule to the activation section of `docs/CONSENSUS.md`.
//!
//! Changing [`MAINNET_HARDENING_ACTIVATION_HEIGHT`] after release is a
//! coordinated network upgrade in its own right: lowering it below the tip of
//! any node's chain re-validates history under new rules and can split the
//! network. Raising it is safe only before the old value is reached.
//!
//! Moving it before the release (as on 2026-10-16, from 110,000 to 17,500)
//! is one change of this constant plus its copies in the independent
//! references, which must move with it: the generator of the consensus
//! vectors (`crates/gnb-crypto/tests/gen_consensus_vectors.rs`,
//! `MAINNET_ACT`) and the Python references (`reference/gnb_validity.py`,
//! `reference/gnb_merkle.py`, `reference/gnb_difficulty.py`), followed by
//! regenerating `reference/{tx,block,merkle,difficulty}_vectors.json` with
//! their generators. The pinned web-wallet core (`site/wallet/gnb_wallet.wasm`)
//! compiles the height in (`hardening_activation_height_for_signer`) and must
//! be rebuilt and re-pinned (`scripts/build-wallet-wasm.sh`, which also
//! refreshes the site's SRI hashes) and the site redeployed. The node's
//! package version (`node/Cargo.toml`) should change with it, so that
//! `getnetworkinfo` `version` and the identify agent tell the builds apart
//! (`getnetworkinfo` / `getdaginfo` also report the height itself).

use std::cell::Cell;

use super::ChainId;

/// Mainnet activation height of the hardening rules: about one day after the
/// decision of 2026-10-16 (it was 110,000, about 30 days after the release,
/// before that decision).
///
/// Derivation (no mainnet node was reachable, so the height comes from the
/// ASERT schedule, not from an observed tip): genesis timestamp
/// 1,791,685,648 (2026-10-11 02:27:28 UTC, the relaunched chain), 30 s
/// target spacing. At the decision, 2026-10-16 03:47 UTC, the schedule
/// height is about 14,560; one day more is 86,400 / 30 = 2,880 blocks, about
/// 17,440, rounded to 17,500, whose scheduled time is 1,791,685,648 +
/// 17,500 * 30 = 1,792,210,648 (2026-10-17 04:17:28 UTC). An earlier move
/// to 25,800 was derived from the pre-relaunch genesis (2026-10-08); on this
/// chain 25,800 is scheduled for 2026-10-20 01:27 UTC.
///
/// The ASERT schedule bounds the real height only loosely. ASERT is anchored
/// at the genesis block (`GENESIS_TIMESTAMP`, `GENESIS_BITS`) with 30 s
/// spacing and a 2 h half-life ([`super::ASERT_HALFLIFE_SECS`]), so the
/// schedule height at time `t` is `(t - GENESIS_TIMESTAMP) / 30 s`. At a
/// steady network hashrate `H` the chain runs `240 * log2(H / H0)` blocks
/// ahead of the schedule (behind it when negative), where `H0` is the
/// hashrate at which the scheduled target gives 30 s blocks. Below
/// `powit_height` (GnB-SMH v1) that target is the genesis target, about
/// 4,500 evaluations per block, so `H0` is about 150 v1 evaluations/s. From
/// `powit_height` (mainnet 10,000) the proof of work is GnB-SMH v3 and
/// `adjust_bits_for_algo` makes the ASERT target
/// 2^[`super::POW_V3_DIFFICULTY_SHIFT`] = 4 times harder, about 18,000
/// evaluations per block on the schedule, so `H0` is about 600 v3
/// evaluations/s; the shift is applied after ASERT and leaves the anchor,
/// and so the schedule height, unchanged (a v3 evaluation costs about a
/// sixth of a v1 one, so the same hardware tracks the schedule at about two
/// thirds of the v1 `H0`). Each doubling of `H` above `H0` brings the
/// activation 240 blocks (2 h) ahead of its scheduled time: at 16 times `H0`
/// the chain reaches 17,500 about 8 h before 2026-10-17 04:17 UTC, at 128
/// times about 14 h before, and it would already have passed 17,500 at the
/// decision only above about 4,900 times `H0`. The two tips recorded in this
/// repository were behind the schedule, not ahead: 2,888 on 2026-10-12
/// 10:06 UTC ([`super::WITNESS_COMMITMENT_HEIGHT`]) and 8,302 on 2026-10-14
/// 04:25 UTC (`docs/MAINNET-READINESS.md`), 909 and 574 blocks behind, i.e.
/// about 0.07 and 0.19 times the v1 `H0`. If the network is still below
/// `H0`, the height arrives after its scheduled time (2 h later per halving
/// of `H / H0`), and from the activation the hardened pow limit (the genesis
/// target, POW-3, applied to the ASERT target before the v3 shift) stretches
/// block times to about 30 s * `H0 / H` (`docs/CONSENSUS.md`, "Pow limit
/// (POW-3)"). So before the release the real tip and bits must be read from
/// a mainnet node (`docs/RUNNING.md`, "Hardening activation"): the tip must
/// be well below this height, or it must be moved again (before the chain
/// reaches it; module docs), and the deadline is the height, not the date.
pub const MAINNET_HARDENING_ACTIVATION_HEIGHT: u64 = 17_500;

/// Testnet activates the hardening rules from genesis.
pub const TESTNET_HARDENING_ACTIVATION_HEIGHT: u64 = 0;

/// Regtest activates the hardening rules from genesis.
pub const REGTEST_HARDENING_ACTIVATION_HEIGHT: u64 = 0;

/// ObenBlock mainnet activates the hardening rules from genesis
/// (docs/DESIGN-obenblock.md §3).
pub const OBENBLOCK_HARDENING_ACTIVATION_HEIGHT: u64 = 0;

/// An activation height that is never reached: old rules forever. Use it in
/// tests that prove the pre-activation behaviour is unchanged.
pub const NEVER: u64 = u64::MAX;

/// The networks an activation schedule (and the node-local release values
/// keyed by it: minimum chain work, assumed-valid block) is defined for.
/// `Mainnet` and `Testnet` are GnB's; ObenBlock's regtest chain id maps to
/// [`ActivationNetwork::Regtest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivationNetwork {
    Mainnet,
    Testnet,
    Regtest,
    ObenBlockMainnet,
}

impl From<ChainId> for ActivationNetwork {
    fn from(id: ChainId) -> Self {
        match id {
            ChainId::Mainnet => ActivationNetwork::Mainnet,
            ChainId::Testnet => ActivationNetwork::Testnet,
            ChainId::ObenBlockMainnet => ActivationNetwork::ObenBlockMainnet,
            ChainId::ObenBlockRegtest => ActivationNetwork::Regtest,
        }
    }
}

/// Hardening activation height for a network.
pub const fn hardening_activation_height_for_network(net: ActivationNetwork) -> u64 {
    match net {
        ActivationNetwork::Mainnet => MAINNET_HARDENING_ACTIVATION_HEIGHT,
        ActivationNetwork::Testnet => TESTNET_HARDENING_ACTIVATION_HEIGHT,
        ActivationNetwork::Regtest => REGTEST_HARDENING_ACTIVATION_HEIGHT,
        ActivationNetwork::ObenBlockMainnet => OBENBLOCK_HARDENING_ACTIVATION_HEIGHT,
    }
}

/// Hardening activation height for a chain id.
pub const fn hardening_activation_height_for_chain(id: ChainId) -> u64 {
    match id {
        ChainId::Mainnet => MAINNET_HARDENING_ACTIVATION_HEIGHT,
        ChainId::Testnet => TESTNET_HARDENING_ACTIVATION_HEIGHT,
        ChainId::ObenBlockMainnet => OBENBLOCK_HARDENING_ACTIVATION_HEIGHT,
        ChainId::ObenBlockRegtest => REGTEST_HARDENING_ACTIVATION_HEIGHT,
    }
}

/// `true` iff a rule with activation height `activation_height` applies to a
/// block at `height`. The single definition of "at or above activation".
#[inline]
pub const fn is_active_at(height: u64, activation_height: u64) -> bool {
    height >= activation_height
}

thread_local! {
    static THREAD_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The process-wide hardening activation height.
///
/// Order of precedence:
/// 1. a [`scoped_override`] active on the calling thread (tests only);
/// 2. the node's chain id, if `set_node_chain_id` was called;
/// 3. otherwise the height of `node_chain_id()`'s default: the GnB mainnet
///    height (see the module documentation for why), or ObenBlock
///    mainnet's in a process that selected ObenBlock.
pub fn hardening_activation_height() -> u64 {
    if let Some(h) = THREAD_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    hardening_activation_height_for_chain(super::node_chain_id())
}

/// Activation height for code that knows the chain it signs for but is not a
/// node (wallets and other transaction signers never call
/// `set_node_chain_id`, so [`hardening_activation_height`] would answer with
/// the mainnet schedule for a testnet wallet). Order of precedence: a
/// [`scoped_override`] on the calling thread (tests that move the boundary
/// for node and wallet together), otherwise the schedule of `id`.
pub fn hardening_activation_height_for_signer(id: ChainId) -> u64 {
    if let Some(h) = THREAD_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    hardening_activation_height_for_chain(id)
}

/// `true` iff the hardening rules apply at `height` under the process-wide
/// activation height. Prefer [`is_active_at`] with a stored height in code
/// that must be testable in both regimes.
pub fn hardening_active_at(height: u64) -> bool {
    is_active_at(height, hardening_activation_height())
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

/// Override [`hardening_activation_height`] on the **calling thread** until
/// the returned guard is dropped. Intended for tests: test threads run in
/// parallel and a per-thread value cannot leak into another test. It does not
/// reach work spawned onto other threads, and state that captured the height
/// before the override (for example an existing `GhostDAG`) keeps its value.
/// Never call it from node code.
pub fn scoped_override(activation_height: u64) -> OverrideGuard {
    let previous = THREAD_OVERRIDE.with(|c| c.replace(Some(activation_height)));
    OverrideGuard { previous }
}

// ---------------------------------------------------------------------------
// Second hardening upgrade
// ---------------------------------------------------------------------------

/// Second hardening upgrade: consensus fixes from the Phase-5 audit
/// (2026-10-16) of the relaunched mainnet line (PoWit accountability and
/// finality, spend-policy key normalisation). It builds on the first
/// hardening rules, so on every network it activates at or after
/// [`MAINNET_HARDENING_ACTIVATION_HEIGHT`] and its counterparts.
///
/// Mainnet is not scheduled yet ([`NEVER`]): the owner sets the height at
/// release, with the same derivation as the first upgrade (a height on the
/// ASERT schedule far enough ahead for every node to upgrade, checked
/// against the real tip; see [`MAINNET_HARDENING_ACTIVATION_HEIGHT`]).
pub const MAINNET_HARDENING2_ACTIVATION_HEIGHT: u64 = NEVER;

/// Testnet activates the second hardening rules from genesis.
pub const TESTNET_HARDENING2_ACTIVATION_HEIGHT: u64 = 0;

/// Regtest activates the second hardening rules from genesis.
pub const REGTEST_HARDENING2_ACTIVATION_HEIGHT: u64 = 0;

/// ObenBlock mainnet activates the second hardening rules from genesis
/// (docs/DESIGN-obenblock.md §3).
pub const OBENBLOCK_HARDENING2_ACTIVATION_HEIGHT: u64 = 0;

/// Second hardening activation height for a network.
pub const fn hardening2_activation_height_for_network(net: ActivationNetwork) -> u64 {
    match net {
        ActivationNetwork::Mainnet => MAINNET_HARDENING2_ACTIVATION_HEIGHT,
        ActivationNetwork::Testnet => TESTNET_HARDENING2_ACTIVATION_HEIGHT,
        ActivationNetwork::Regtest => REGTEST_HARDENING2_ACTIVATION_HEIGHT,
        ActivationNetwork::ObenBlockMainnet => OBENBLOCK_HARDENING2_ACTIVATION_HEIGHT,
    }
}

/// Second hardening activation height for a chain id.
pub const fn hardening2_activation_height_for_chain(id: ChainId) -> u64 {
    match id {
        ChainId::Mainnet => MAINNET_HARDENING2_ACTIVATION_HEIGHT,
        ChainId::Testnet => TESTNET_HARDENING2_ACTIVATION_HEIGHT,
        ChainId::ObenBlockMainnet => OBENBLOCK_HARDENING2_ACTIVATION_HEIGHT,
        ChainId::ObenBlockRegtest => REGTEST_HARDENING2_ACTIVATION_HEIGHT,
    }
}

thread_local! {
    static THREAD_OVERRIDE_V2: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The process-wide second hardening activation height. Same precedence as
/// [`hardening_activation_height`]: a [`scoped_override_v2`] on the calling
/// thread, then the node's chain id, then the height of `node_chain_id()`'s
/// default.
pub fn hardening2_activation_height() -> u64 {
    if let Some(h) = THREAD_OVERRIDE_V2.with(|c| c.get()) {
        return h;
    }
    hardening2_activation_height_for_chain(super::node_chain_id())
}

/// Second hardening activation height for a signer of chain `id` (see
/// [`hardening_activation_height_for_signer`]).
pub fn hardening2_activation_height_for_signer(id: ChainId) -> u64 {
    if let Some(h) = THREAD_OVERRIDE_V2.with(|c| c.get()) {
        return h;
    }
    hardening2_activation_height_for_chain(id)
}

/// `true` iff the second hardening rules apply at `height` under the
/// process-wide second activation height.
pub fn hardening2_active_at(height: u64) -> bool {
    is_active_at(height, hardening2_activation_height())
}

/// Guard returned by [`scoped_override_v2`]; restores the previous value on drop.
#[must_use = "the override ends when the guard is dropped"]
pub struct OverrideGuardV2 {
    previous: Option<u64>,
}

impl Drop for OverrideGuardV2 {
    fn drop(&mut self) {
        let prev = self.previous;
        THREAD_OVERRIDE_V2.with(|c| c.set(prev));
    }
}

/// Override [`hardening2_activation_height`] on the **calling thread** until
/// the returned guard is dropped (tests only; see [`scoped_override`]). It is
/// independent of the first upgrade's override.
pub fn scoped_override_v2(activation_height: u64) -> OverrideGuardV2 {
    let previous = THREAD_OVERRIDE_V2.with(|c| c.replace(Some(activation_height)));
    OverrideGuardV2 { previous }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_matches_the_decision() {
        // The decision of 2026-10-16 (see the constant's documentation).
        assert_eq!(MAINNET_HARDENING_ACTIVATION_HEIGHT, 17_500);
        assert_eq!(TESTNET_HARDENING_ACTIVATION_HEIGHT, 0);
        assert_eq!(REGTEST_HARDENING_ACTIVATION_HEIGHT, 0);
        assert_eq!(hardening_activation_height_for_chain(ChainId::Mainnet), MAINNET_HARDENING_ACTIVATION_HEIGHT);
        assert_eq!(hardening_activation_height_for_chain(ChainId::Testnet), 0);
        for net in [ActivationNetwork::Mainnet, ActivationNetwork::Testnet, ActivationNetwork::Regtest] {
            let via_chain = match net {
                ActivationNetwork::Mainnet => Some(ChainId::Mainnet),
                ActivationNetwork::Testnet => Some(ChainId::Testnet),
                ActivationNetwork::Regtest | ActivationNetwork::ObenBlockMainnet => None,
            };
            if let Some(id) = via_chain {
                assert_eq!(ActivationNetwork::from(id), net);
                assert_eq!(
                    hardening_activation_height_for_network(net),
                    hardening_activation_height_for_chain(id)
                );
            }
        }
        assert_eq!(hardening_activation_height_for_network(ActivationNetwork::Regtest), 0);
    }

    /// The documented derivation of the mainnet height: its time on the ASERT
    /// schedule of the relaunched chain (genesis timestamp + height * target
    /// spacing) is 1,792,210,648 = 2026-10-17 04:17:28 UTC.
    #[test]
    fn mainnet_height_matches_its_documented_schedule_time() {
        assert_eq!(super::super::TARGET_BLOCK_TIME, 30);
        assert_eq!(super::super::GENESIS_TIMESTAMP, 1_791_685_648);
        assert_eq!(
            super::super::GENESIS_TIMESTAMP + MAINNET_HARDENING_ACTIVATION_HEIGHT * super::super::TARGET_BLOCK_TIME,
            1_792_210_648
        );
    }

    #[test]
    fn boundary_is_inclusive() {
        assert!(!is_active_at(MAINNET_HARDENING_ACTIVATION_HEIGHT - 1, MAINNET_HARDENING_ACTIVATION_HEIGHT));
        assert!(is_active_at(MAINNET_HARDENING_ACTIVATION_HEIGHT, MAINNET_HARDENING_ACTIVATION_HEIGHT));
        assert!(is_active_at(0, 0));
        assert!(!is_active_at(u64::MAX - 1, NEVER));
    }

    #[test]
    fn unset_chain_id_defaults_to_mainnet_and_override_is_scoped() {
        // The gnb-crypto unit tests never set the chain id.
        if chain_id_unset() {
            assert_eq!(hardening_activation_height(), MAINNET_HARDENING_ACTIVATION_HEIGHT);
        }
        let before = hardening_activation_height();
        {
            let _g = scoped_override(0);
            assert_eq!(hardening_activation_height(), 0);
            assert!(hardening_active_at(0));
            {
                let _inner = scoped_override(NEVER);
                assert_eq!(hardening_activation_height(), NEVER);
            }
            assert_eq!(hardening_activation_height(), 0);
            // Another thread does not see this thread's override.
            let other = std::thread::spawn(hardening_activation_height).join().unwrap();
            assert_eq!(other, before);
        }
        assert_eq!(hardening_activation_height(), before);
    }

    /// Signers follow their own chain's schedule (never the node's global),
    /// unless a test override is active on the thread.
    #[test]
    fn signer_height_follows_the_signer_chain_and_the_override() {
        assert_eq!(hardening_activation_height_for_signer(ChainId::Mainnet), MAINNET_HARDENING_ACTIVATION_HEIGHT);
        assert_eq!(hardening_activation_height_for_signer(ChainId::Testnet), TESTNET_HARDENING_ACTIVATION_HEIGHT);
        let _g = scoped_override(7);
        assert_eq!(hardening_activation_height_for_signer(ChainId::Mainnet), 7);
        assert_eq!(hardening_activation_height_for_signer(ChainId::Testnet), 7);
    }

    #[test]
    fn process_wide_predicate_uses_the_process_wide_height() {
        let _g = scoped_override(1_000);
        assert!(!hardening_active_at(0));
        assert!(!hardening_active_at(999));
        assert!(hardening_active_at(1_000));
        assert!(hardening_active_at(u64::MAX));
        if chain_id_unset() {
            drop(_g);
            assert!(!hardening_active_at(MAINNET_HARDENING_ACTIVATION_HEIGHT - 1));
            assert!(hardening_active_at(MAINNET_HARDENING_ACTIVATION_HEIGHT));
        }
    }

    #[test]
    fn second_upgrade_follows_the_first_on_every_network() {
        assert_eq!(MAINNET_HARDENING2_ACTIVATION_HEIGHT, NEVER);
        assert_eq!(TESTNET_HARDENING2_ACTIVATION_HEIGHT, 0);
        assert_eq!(REGTEST_HARDENING2_ACTIVATION_HEIGHT, 0);
        for net in [ActivationNetwork::Mainnet, ActivationNetwork::Testnet, ActivationNetwork::Regtest] {
            assert!(hardening2_activation_height_for_network(net) >= hardening_activation_height_for_network(net));
        }
        for id in [ChainId::Mainnet, ChainId::Testnet] {
            assert_eq!(
                hardening2_activation_height_for_chain(id),
                hardening2_activation_height_for_network(ActivationNetwork::from(id))
            );
        }
    }

    #[test]
    fn second_upgrade_override_is_scoped_and_independent() {
        if chain_id_unset() {
            assert_eq!(hardening2_activation_height(), MAINNET_HARDENING2_ACTIVATION_HEIGHT);
            assert!(!hardening2_active_at(u64::MAX - 1));
        }
        let first = hardening_activation_height();
        let before = hardening2_activation_height();
        {
            let _g = scoped_override_v2(5);
            assert_eq!(hardening2_activation_height(), 5);
            assert!(!hardening2_active_at(4));
            assert!(hardening2_active_at(5));
            assert_eq!(hardening2_activation_height_for_signer(ChainId::Mainnet), 5);
            assert_eq!(hardening_activation_height(), first);
            let other = std::thread::spawn(hardening2_activation_height).join().unwrap();
            assert_eq!(other, before);
        }
        assert_eq!(hardening2_activation_height(), before);
        assert_eq!(hardening2_activation_height_for_signer(ChainId::Testnet), TESTNET_HARDENING2_ACTIVATION_HEIGHT);
    }

    fn chain_id_unset() -> bool {
        super::super::NODE_CHAIN_ID.get().is_none()
    }

    /// docs/DESIGN-obenblock.md §3: both upgrades apply from genesis on
    /// both ObenBlock networks; GnB's schedules are unchanged.
    #[test]
    fn obenblock_applies_every_rule_from_genesis() {
        for id in [ChainId::ObenBlockMainnet, ChainId::ObenBlockRegtest] {
            assert_eq!(hardening_activation_height_for_chain(id), 0);
            assert_eq!(hardening2_activation_height_for_chain(id), 0);
            assert_eq!(hardening_activation_height_for_network(id.into()), 0);
            assert_eq!(hardening2_activation_height_for_network(id.into()), 0);
            assert_eq!(hardening_activation_height_for_signer(id), 0);
            assert_eq!(hardening2_activation_height_for_signer(id), 0);
        }
        assert_eq!(ActivationNetwork::from(ChainId::ObenBlockMainnet), ActivationNetwork::ObenBlockMainnet);
        assert_eq!(ActivationNetwork::from(ChainId::ObenBlockRegtest), ActivationNetwork::Regtest);
        assert_eq!(hardening_activation_height_for_chain(ChainId::Mainnet), MAINNET_HARDENING_ACTIVATION_HEIGHT);
        assert_eq!(hardening2_activation_height_for_chain(ChainId::Mainnet), MAINNET_HARDENING2_ACTIVATION_HEIGHT);
        // A process that selected no chain keeps GnB mainnet's schedule.
        if chain_id_unset() {
            assert_eq!(hardening_activation_height(), MAINNET_HARDENING_ACTIVATION_HEIGHT);
            assert_eq!(hardening2_activation_height(), MAINNET_HARDENING2_ACTIVATION_HEIGHT);
        }
    }
}
