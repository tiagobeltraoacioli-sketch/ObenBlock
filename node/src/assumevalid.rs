//! The assumed-valid block: Bitcoin Core's `-assumevalid` (package P5-G).
//!
//! A release names a block of the real chain (its hash, [`MAINNET_ASSUME_VALID`],
//! read from independent nodes by `tools/release/min_chain_work.py` next to
//! the minimum chain work), and `--assumevalid=<hash|0>` replaces it or turns
//! it off. When the node connects a block the release vouches for, it skips
//! the block's transaction SIGNATURE checks and nothing else: the version
//! rule, every witness check (framing, public key hash, revealed policy
//! hash), amounts and MoneyRange, UTXO existence and double spends, coinbase
//! maturity, relative and absolute timelocks, the minimum fee, BIP30, the
//! coinbase value, the shielded state and every acceptance check (proof of
//! work, difficulty, height, timestamp, commitments, PoWit) still run. It is
//! the step a verified-signature cache hit skips
//! (`mempool::admission::check_input_scripts_without_signatures_at`).
//!
//! # Conditions (Core's `Chainstate::ConnectBlock`, validation.cpp)
//!
//! Core skips the script checks of block B when all of these hold:
//!
//! 1. the assumed-valid block AV is in the block index (its header is known);
//! 2. B is an ancestor of AV (`AV->GetAncestor(B->nHeight) == B`);
//! 3. B is an ancestor of the best header (`m_best_header->GetAncestor(...)`);
//! 4. the best header has at least the minimum chain work;
//! 5. the best header is more than two weeks of proof-equivalent time above
//!    B (`GetBlockProofEquivalentTime(*m_best_header, *B, *m_best_header) >
//!    60 * 60 * 24 * 7 * 2`).
//!
//! The GnB equivalents ([`Assumption`]):
//!
//! 1. AV is in the DAG. The DAG is GnB's header tree: every block in it
//!    passed acceptance (proof of work, ASERT bits, height, timestamp, the
//!    context-free block rules), and a block enters it only after its
//!    parents. Stricter than Core: AV must not carry a persistent verdict on
//!    this node (`GhostDAG::is_invalid_persistently`: a consensus failure of
//!    it or of its selected chain, or the operator's `invalidateblock`).
//! 2. B is AV or lies on AV's SELECTED chain (`reachability` chain
//!    ancestry, the selected-parent tree; O(1)). Only selected-chain blocks
//!    are connected (merged blocks never touch the UTXO set), so a block in
//!    AV's past that is not on its selected chain was never validated by the
//!    nodes that vouch for AV: it is never skipped.
//! 3. B is the best block or lies on its selected chain. The best header is
//!    `GhostDAG::selected_tip`: the best block of the DAG by blue work that
//!    is not disqualified and is on the PoWit finalized chain (Core's
//!    `m_best_header` excludes failed headers likewise).
//! 4. Its blue work is at least the node's minimum chain work
//!    (`ingress::minimum_chain_work`, Core's `nMinimumChainWork`).
//! 5. `(blue_work(best) - blue_work(B)) * TARGET_BLOCK_TIME / work(best)` is
//!    more than [`MIN_BURIAL_SECS`], two weeks: Core's formula with GnB's
//!    chain work (blue work), its 30 s target spacing and the best block's
//!    own work ([`own_work`], `core::block_work` of its bits: normalised
//!    across the GnB-SMH v1 -> v3 switch). The same two weeks of
//!    the network's work at the best block's difficulty (40,320 blocks at
//!    30 s), for Core's two reasons: a demand to set `--assumevalid` to a
//!    fresh invalid block achieves nothing unless that block is buried under
//!    two weeks of the heaviest chain, and a release candidate still checks
//!    the signatures of its last two weeks of blocks.
//!
//! And one GnB condition Core gets from its segwit commitment: B's id
//! commits to every witness byte of its body (`accept::witnesses_fixed_at`:
//! from `core::WITNESS_COMMITMENT_HEIGHT` or the hardening activation). Below
//! both, a relay can swap a block's `script_sig` bytes without changing its
//! id, so the body this node holds need not be the body the assumed-valid
//! chain was validated with: such a block is always checked in full (Core's
//! "this is safe because block merkle hashes are still computed and
//! checked"). Applied by `accept::validate_block_in_view_classified_with`.
//!
//! # Where it applies
//!
//! One decision per chain move, on the one connect path
//! (`accept::commit_chunk`, before `reorg::connect_plan`): extensions,
//! reorgs (a node on a minority or eclipsed branch that receives the release
//! chain connects it once it is the heaviest, with AV in its DAG), the
//! start-up reconnection, the reconnection of blocks whose bodies came back
//! (audit DAG-6) and the chain-state rebuild (`accept::rebuild_chain_state`,
//! Core's `-reindex-chainstate`). Nothing else changes: mempool admission,
//! templates and `blockval::validate_block_transactions` always verify in
//! full.
//!
//! Forward initial block download gets nothing from it today: GnB connects a
//! block as soon as it arrives with its parents (there is no header-first
//! download: `/gnb/sync/1` `Headers` carry ids and claimed scores, not
//! headers), so AV's header is not known when its ancestors connect
//! (condition 1); and with Core's two-week burial nothing on a chain younger
//! than two weeks plus AV's depth would qualify anyway. Condition 1 needs a
//! header tree in place before the blocks connect (Core's headers-first
//! sync; package P5-B2 adds verified headers to `/gnb/sync/1`); the
//! decision reads nothing of that tree but membership, selected-chain
//! ancestry, blue work and the best block ([`Assumption`]).
//!
//! # Not consensus
//!
//! The assumed-valid block changes no verdict on a valid chain: every rule
//! but the signatures still runs, and the signatures of a valid chain are
//! valid. A node only ever skips the signatures of blocks that a release
//! (or its operator) vouches for, as in Core; a wrong release value is a
//! software bug in the same way a wrong consensus rule is. Proofs of work
//! are never skipped (Core never skips them either): they are what makes a
//! header part of the header tree in the first place.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::consensus::{BlockHash, GhostDAG};
use crate::core;

/// How the input scripts of a block's transactions are checked when it is
/// connected (`accept::validate_block_in_view_classified_with`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptChecks {
    /// Every input-script rule, signatures included (the default).
    Full,
    /// The block is vouched for by the assumed-valid block ([`Assumption`]):
    /// every input-script rule except the signature verification.
    SignaturesAssumed,
}

/// A block a release names as assumed valid (Core's `defaultAssumeValid`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssumedValidBlock {
    /// Its id (`getblockdag` `hash`, the hex the RPC prints).
    pub hash: [u8; 32],
    /// Its DAG height (`getblockdag` `height`, its selected-chain position),
    /// for the release review and the start-up log. The conditions use the
    /// hash only, as Core's.
    pub height: u64,
}

impl AssumedValidBlock {
    /// From the 64 hex digits the RPC prints (a malformed literal is a
    /// compile error where the constant is defined).
    #[allow(dead_code)] // the form a release sets `MAINNET_ASSUME_VALID` in
    pub const fn from_hex(hex: &str, height: u64) -> Self {
        AssumedValidBlock { hash: hash_from_hex(hex), height }
    }
}

/// A block id from the 64 hex digits the RPC prints, at compile time (for
/// the release constants: this one and `powit::MAINNET_FINALITY_CHECKPOINT`;
/// a malformed literal is a compile error where the constant is defined).
#[allow(dead_code)] // the form a release sets the constants in
pub(crate) const fn hash_from_hex(hex: &str) -> [u8; 32] {
    let b = hex.as_bytes();
    assert!(b.len() == 64, "a block hash has 64 hex digits");
    let mut hash = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        hash[i] = (hex_digit(b[2 * i]) << 4) | hex_digit(b[2 * i + 1]);
        i += 1;
    }
    hash
}

#[allow(dead_code)] // see `hash_from_hex`
const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

/// Mainnet's assumed-valid block, set by the release process (Core sets
/// `defaultAssumeValid` in every release): `tools/release/min_chain_work.py`
/// reads, from two or more independent nodes, the selected-chain block about
/// a day below the tip — the block whose blue work becomes
/// `core::MIN_CHAIN_WORK` — and prints this line with its hash and height
/// (docs/RUNNING.md, "Initial sync and minimum chain work", the release
/// step, and "The assumed-valid block"). `None` until a release sets it: no
/// block of the relaunched mainnet has been read for it yet, and none is
/// more than two weeks deep.
pub const MAINNET_ASSUME_VALID: Option<AssumedValidBlock> = None;
/// Testnet: none (reset at will).
pub const TESTNET_ASSUME_VALID: Option<AssumedValidBlock> = None;
/// Regtest: none (Core's regtest has none either).
pub const REGTEST_ASSUME_VALID: Option<AssumedValidBlock> = None;

/// The default assumed-valid block of a network.
pub const fn default_assume_valid(net: core::activation::ActivationNetwork) -> Option<AssumedValidBlock> {
    match net {
        core::activation::ActivationNetwork::Mainnet => MAINNET_ASSUME_VALID,
        core::activation::ActivationNetwork::Testnet => TESTNET_ASSUME_VALID,
        core::activation::ActivationNetwork::Regtest => REGTEST_ASSUME_VALID,
    }
}

/// Burial a block needs below the best block before its signatures are
/// skipped: two weeks of proof-equivalent time (Core's
/// `60 * 60 * 24 * 7 * 2`; condition 5 of the module documentation).
pub const MIN_BURIAL_SECS: u64 = 14 * 24 * 60 * 60;

/// Parse an `--assumevalid` value: `0` turns the assumed-valid block off
/// (Core's `-assumevalid=0`); otherwise exactly 64 hexadecimal digits, the
/// block id as the RPC prints it (`getblockdag`, `getselectedchain`). An
/// optional `0x` prefix is accepted. Anything else is refused, so a typo can
/// never silently mean "no assumed-valid block" or another block.
pub fn parse_assume_valid(s: &str) -> Result<Option<[u8; 32]>, String> {
    let t = s.trim();
    if t == "0" {
        return Ok(None);
    }
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid assumed-valid block {s:?}: expected 0 or a block id of 64 hex digits"));
    }
    let v = hex::decode(t).map_err(|e| format!("invalid assumed-valid block {s:?}: {e}"))?;
    let mut h = [0u8; 32];
    h.copy_from_slice(&v);
    Ok(Some(h))
}

/// The assumed-valid block a node runs with, as chosen at start-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssumeValidSetting {
    /// The block in force (`None`: off).
    pub block: Option<[u8; 32]>,
    /// The network's default ([`default_assume_valid`]).
    pub default: Option<AssumedValidBlock>,
    /// Set by `--assumevalid`.
    pub overridden: bool,
}

impl AssumeValidSetting {
    /// Resolve `--assumevalid` (`arg`) against the default of `net`.
    pub fn resolve(arg: Option<&str>, net: core::activation::ActivationNetwork) -> Result<Self, String> {
        let default = default_assume_valid(net);
        Ok(match arg {
            Some(s) => AssumeValidSetting { block: parse_assume_valid(s)?, default, overridden: true },
            None => AssumeValidSetting { block: default.map(|d| d.hash), default, overridden: false },
        })
    }

    /// The start-up log line (Core: "Assuming ancestors of block %s have
    /// valid signatures.").
    pub fn describe(&self) -> String {
        match (self.block, self.overridden) {
            (None, true) => "assumed-valid block: off (--assumevalid=0): every signature is checked".into(),
            (None, false) => "assumed-valid block: none for this network: every signature is checked".into(),
            (Some(h), overridden) => {
                let height = self.default.filter(|d| d.hash == h).map(|d| format!(" (height {})", d.height));
                format!("assumed-valid block {}{} ({}): the signatures of its selected-chain ancestors buried \
                         two weeks below the best block are not checked",
                    hex::encode(h), height.unwrap_or_default(),
                    if overridden { "--assumevalid" } else { "release default" })
            }
        }
    }
}

static ASSUME_VALID: OnceLock<Option<[u8; 32]>> = OnceLock::new();

/// Set the process-wide assumed-valid block once, at start-up (the node's
/// `--assumevalid`, else the network default). Later calls are refused.
pub fn set_assume_valid(block: Option<[u8; 32]>) -> Result<(), Option<[u8; 32]>> {
    ASSUME_VALID.set(block)
}

/// The process-wide assumed-valid block: the value set at start-up, else
/// the default of the node's network (mainnet when no chain id is set, as
/// for the minimum chain work).
pub fn assume_valid() -> Option<[u8; 32]> {
    match ASSUME_VALID.get() {
        Some(v) => *v,
        None => default_assume_valid(core::node_chain_id().into()).map(|d| d.hash),
    }
}

/// Everything the decision reads besides the DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The assumed-valid block (`None`: off).
    pub block: Option<[u8; 32]>,
    /// Condition 5's burial ([`MIN_BURIAL_SECS`]).
    pub min_burial_secs: u64,
    /// Condition 4's minimum (`None`: the node's,
    /// `ingress::minimum_chain_work`).
    pub min_chain_work: Option<u128>,
}

thread_local! {
    static THREAD_OVERRIDE: std::cell::Cell<Option<Policy>> = const { std::cell::Cell::new(None) };
}

/// The policy in force on the calling thread: a [`scoped_override`] (tests),
/// else the node's: [`assume_valid`], [`MIN_BURIAL_SECS`] and its minimum
/// chain work.
pub fn policy() -> Policy {
    THREAD_OVERRIDE.with(|c| c.get()).unwrap_or(Policy {
        block: assume_valid(),
        min_burial_secs: MIN_BURIAL_SECS,
        min_chain_work: None,
    })
}

/// Guard returned by [`scoped_override`]; restores the previous value on drop.
#[allow(dead_code)] // tests only; the node binary compiles this module too
pub struct OverrideGuard {
    previous: Option<Policy>,
}

impl Drop for OverrideGuard {
    fn drop(&mut self) {
        let previous = self.previous;
        THREAD_OVERRIDE.with(|c| c.set(previous));
    }
}

/// Override [`policy`] on the CALLING THREAD until the guard drops (tests
/// only, like `core::activation::scoped_override`: the block pipeline runs
/// on the thread that accepts the block). Never call it from node code.
#[allow(dead_code)] // tests only; the node binary compiles this module too
pub fn scoped_override(policy: Policy) -> OverrideGuard {
    OverrideGuard { previous: THREAD_OVERRIDE.with(|c| c.replace(Some(policy))) }
}

/// Core's `GetBlockProofEquivalentTime(to, from, tip)` for `to` above
/// `from`: the seconds the network takes to add `to_work - from_work` of
/// chain work at `tip_work` per `TARGET_BLOCK_TIME`. `0` when `to` is not
/// above `from`; saturates at `u64::MAX`; `0` for a zero `tip_work`
/// (never buried: every block carries work).
pub fn proof_equivalent_secs(to_work: u128, from_work: u128, tip_work: u128) -> u64 {
    if tip_work == 0 {
        return 0;
    }
    let delta = to_work.saturating_sub(from_work);
    match delta.checked_mul(u128::from(core::TARGET_BLOCK_TIME)) {
        Some(v) => u64::try_from(v / tip_work).unwrap_or(u64::MAX),
        // Over 2^128 / 30 of work above: buried beyond any bound.
        None => u64::MAX,
    }
}

/// The proof-of-work contribution of DAG block `hash` (Core's
/// `GetBlockProof`, read from the header's `nBits`): `core::block_work` of
/// its bits at its header height, normalised across the GnB-SMH v1 -> v3
/// switch. The bits are the ASERT value of its parents
/// (`pow::expected_bits` of their latest timestamp at the height
/// `max(parent DAG heights) + 1`), which acceptance requires every DAG
/// block's header to carry, so this is exactly the work the block was added
/// with, from the parents' records alone (O(parents), no body read). `None`
/// for the genesis or an unknown block.
pub fn own_work(dag: &GhostDAG, hash: &BlockHash) -> Option<u128> {
    let d = dag.get_block_data(hash)?;
    if d.parents.is_empty() {
        return None;
    }
    let mut height = 0u64;
    let mut timestamps = Vec::with_capacity(d.parents.len());
    for p in &d.parents {
        let pd = dag.get_block_data(p)?;
        height = height.max(pd.height.saturating_add(1));
        timestamps.push(pd.timestamp);
    }
    let bits = crate::pow::expected_bits(core::difficulty_parent_timestamp(timestamps), height).ok()?;
    Some(crate::pow::block_work(bits, height))
}

/// `a == b` or `a` lies on `b`'s selected chain.
fn on_selected_chain_of(dag: &GhostDAG, a: &BlockHash, b: &BlockHash) -> bool {
    if a == b {
        return dag.has_block(a);
    }
    if dag.maintains_reachability_index() {
        dag.reachability().is_chain_ancestor(a, b)
    } else {
        dag.is_on_selected_chain_of(a, b)
    }
}

/// The assumed-valid block's conditions evaluated once for a chain move
/// (conditions 1 and 4, and the best block's work for 5); [`Self::covers`]
/// answers 2, 3 and 5 per block.
#[derive(Clone, Debug)]
pub struct Assumption {
    av: BlockHash,
    best: BlockHash,
    best_work: u128,
    best_own_work: u128,
    min_burial_secs: u64,
}

impl Assumption {
    /// `None` when no block can be skipped under `policy` on `dag`: no
    /// assumed-valid block, its header unknown (condition 1), no best block,
    /// or the best block below the minimum chain work (condition 4).
    /// `min_chain_work` is the node's minimum, used when `policy` names none.
    pub fn new(dag: &GhostDAG, policy: &Policy, min_chain_work: u128) -> Option<Self> {
        let av = policy.block?;
        if !dag.has_block(&av) {
            return None;
        }
        // Stricter than Core (which only looks the block up): an
        // assumed-valid block this node holds a persistent verdict against
        // (a consensus failure of it or of a block on its selected chain, or
        // the operator's `invalidateblock`) vouches for nothing. No effect
        // with a correct release value.
        if dag.is_invalid_persistently(&av) {
            return None;
        }
        let best = dag.selected_tip()?;
        let best_work = dag.get_block_data(&best)?.blue_work;
        if best_work < policy.min_chain_work.unwrap_or(min_chain_work) {
            return None;
        }
        let best_own_work = own_work(dag, &best)?;
        Some(Assumption { av, best, best_work, best_own_work, min_burial_secs: policy.min_burial_secs })
    }

    /// Whether `block`'s signatures are assumed valid: it is the assumed-valid
    /// block or on its selected chain (2), on the best block's selected chain
    /// (3), and more than the burial below the best block (5).
    pub fn covers(&self, dag: &GhostDAG, block: &BlockHash) -> bool {
        let Some(work) = dag.get_block_data(block).map(|d| d.blue_work) else {
            return false;
        };
        on_selected_chain_of(dag, block, &self.av)
            && on_selected_chain_of(dag, block, &self.best)
            && proof_equivalent_secs(self.best_work, work, self.best_own_work) > self.min_burial_secs
    }
}

/// The blocks of a chain move (`to_apply`) whose signature checks are
/// skipped under the calling thread's [`policy`] (each one [`Assumption::covers`]).
/// Empty, at the cost of one hash lookup, without an assumed-valid block or
/// while its header is not in the DAG. The caller holds the DAG read lock
/// for the call only (lock order: acceptance -> DAG).
pub fn assumed_valid_blocks(dag: &GhostDAG, to_apply: &[BlockHash]) -> HashSet<BlockHash> {
    let p = policy();
    if p.block.is_none() {
        return HashSet::new();
    }
    let min_work = p.min_chain_work.unwrap_or_else(crate::ingress::minimum_chain_work);
    match Assumption::new(dag, &p, min_work) {
        Some(a) => to_apply.iter().filter(|b| a.covers(dag, b)).copied().collect(),
        None => HashSet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(tag: u8, i: u64) -> BlockHash {
        let mut x = [tag; 32];
        x[..8].copy_from_slice(&i.to_le_bytes());
        x
    }

    /// Add `b` on `parent` with the work `accept_block` would add it with
    /// (its parent's ASERT bits; the test pow limit in lib tests).
    fn add(d: &mut GhostDAG, b: BlockHash, parent: BlockHash, ts: u64) {
        let p = d.get_block_data(&parent).unwrap().clone();
        let height = p.height + 1;
        let bits = crate::pow::expected_bits(p.timestamp, height).unwrap();
        d.add_block(b, vec![parent], ts, crate::pow::block_work(bits, height)).unwrap();
    }

    /// genesis G; selected chain A1..A10 (one block's work W each); a side
    /// branch S1, S2 on A3 (never selected: 5 W < 10 W).
    fn dag() -> (GhostDAG, Vec<BlockHash>, Vec<BlockHash>) {
        let mut d = GhostDAG::with_default_k();
        let g = h(0, 0);
        d.add_genesis(g, 1_000);
        let mut chain = vec![g];
        for i in 1..=10 {
            let b = h(0xA, i);
            add(&mut d, b, *chain.last().unwrap(), 1_000 + 30 * i);
            chain.push(b);
        }
        let s1 = h(0x5, 1);
        add(&mut d, s1, chain[3], 1_100);
        let s2 = h(0x5, 2);
        add(&mut d, s2, s1, 1_130);
        (d, chain, vec![s1, s2])
    }

    fn p(block: Option<BlockHash>, burial: u64, min_work: u128) -> Policy {
        Policy { block, min_burial_secs: burial, min_chain_work: Some(min_work) }
    }

    #[test]
    fn release_values_and_core_burial() {
        assert_eq!(MIN_BURIAL_SECS, 1_209_600, "Core's two weeks");
        assert_eq!(MIN_BURIAL_SECS / core::TARGET_BLOCK_TIME, 40_320, "two weeks of 30 s blocks");
        // No release has set mainnet's yet; testnet and regtest have none.
        for net in [core::activation::ActivationNetwork::Mainnet, core::activation::ActivationNetwork::Testnet,
                    core::activation::ActivationNetwork::Regtest] {
            assert_eq!(default_assume_valid(net), None);
        }
        // The node's policy without an override: the release value, Core's
        // two weeks, the node's minimum chain work.
        assert_eq!(policy(), Policy { block: None, min_burial_secs: MIN_BURIAL_SECS, min_chain_work: None });
        let b = AssumedValidBlock::from_hex(&"0a".repeat(32), 7);
        assert_eq!((b.hash, b.height), ([0x0A; 32], 7));
        let mixed = AssumedValidBlock::from_hex(
            "00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff", 1);
        assert_eq!(mixed.hash[..4], [0x00, 0x11, 0x22, 0x33]);
        assert_eq!(mixed.hash[31], 0xFF);
    }

    #[test]
    fn assumevalid_argument_is_zero_or_a_full_block_id() {
        assert_eq!(parse_assume_valid("0"), Ok(None));
        assert_eq!(parse_assume_valid(" 0 "), Ok(None));
        let id = "ab".repeat(32);
        assert_eq!(parse_assume_valid(&id), Ok(Some([0xAB; 32])));
        assert_eq!(parse_assume_valid(&format!("0x{id}")), Ok(Some([0xAB; 32])));
        for bad in ["", "00", "1", &"ab".repeat(31), &"ab".repeat(33), &format!("{}zz", "ab".repeat(31)), "none"] {
            assert!(parse_assume_valid(bad).is_err(), "{bad:?}");
        }
        let net = core::activation::ActivationNetwork::Mainnet;
        let off = AssumeValidSetting::resolve(Some("0"), net).unwrap();
        assert_eq!((off.block, off.overridden), (None, true));
        assert!(off.describe().contains("off"));
        let set = AssumeValidSetting::resolve(Some(&id), net).unwrap();
        assert_eq!((set.block, set.overridden), (Some([0xAB; 32]), true));
        assert!(set.describe().contains(&id));
        let default = AssumeValidSetting::resolve(None, net).unwrap();
        assert_eq!((default.block, default.overridden), (MAINNET_ASSUME_VALID.map(|b| b.hash), false));
    }

    /// Core's `GetBlockProofEquivalentTime`: work above / tip work * 30 s.
    #[test]
    fn proof_equivalent_time_is_cores_formula() {
        assert_eq!(proof_equivalent_secs(1_000, 400, 100), 180, "six blocks of 30 s");
        assert_eq!(proof_equivalent_secs(400, 1_000, 100), 0, "below is not buried");
        assert_eq!(proof_equivalent_secs(1_000, 1_000, 100), 0);
        assert_eq!(proof_equivalent_secs(1_000, 0, 0), 0, "no tip work: never buried");
        assert_eq!(proof_equivalent_secs(u128::MAX, 0, 1), u64::MAX, "saturates");
        // Two weeks of blocks at constant work is exactly the bound (Core:
        // skipped only when STRICTLY more than two weeks).
        let w = 4_500u128;
        assert_eq!(proof_equivalent_secs(40_320 * w, 0, w), MIN_BURIAL_SECS);
        assert_eq!(proof_equivalent_secs(40_321 * w, 0, w), MIN_BURIAL_SECS + 30);
        // A harder best block (more work per block) makes the same work
        // above a block fewer seconds.
        assert_eq!(proof_equivalent_secs(40_320 * w, 0, 2 * w), MIN_BURIAL_SECS / 2);
    }

    /// Each of Core's conditions on its own: with burial 150 s (five blocks
    /// of work W at 30 s) and AV = A6, best = A10: A1..A4 are skipped
    /// (A10 is 6..9 blocks above them, more than five), A5 is exactly five
    /// blocks below (not more), A6..A10 are not buried enough or above AV;
    /// the side branch is never covered. (A chain move never applies the
    /// genesis, so it is not in the lists.)
    #[test]
    fn cores_conditions_one_by_one() {
        let (d, a, side) = dag();
        let moves: Vec<BlockHash> = a[1..].iter().chain(side.iter()).copied().collect();
        assert_eq!(d.selected_tip(), Some(a[10]));
        let w = own_work(&d, &a[10]).expect("a block's work");
        assert!(w > 0);
        assert_eq!(d.get_block_data(&a[10]).unwrap().blue_work, 10 * w, "the work each block was added with");
        assert_eq!(own_work(&d, &a[0]), None, "the genesis has no parents");
        assert_eq!(own_work(&d, &[0xEE; 32]), None);
        let skipped = |pol: Policy| -> Vec<usize> {
            let _g = scoped_override(pol);
            let s = assumed_valid_blocks(&d, &moves);
            assert!(side.iter().all(|x| !s.contains(x)), "a side-branch block is never on the best chain");
            (0..a.len()).filter(|i| s.contains(&a[*i])).collect()
        };
        assert_eq!(skipped(p(Some(a[6]), 150, 0)), vec![1, 2, 3, 4], "the four buried ancestors");
        // Condition 1: AV unknown.
        assert!(skipped(p(Some([0xEE; 32]), 150, 0)).is_empty());
        // Off.
        assert!(skipped(p(None, 150, 0)).is_empty());
        // Condition 2: AV on the side branch: A1..A3 are its chain ancestors
        // (and buried); A4.. are not on its chain, the side blocks not on
        // the best chain.
        assert_eq!(skipped(p(Some(side[1]), 150, 0)), vec![1, 2, 3]);
        // AV = A2: only A1 and A2 (AV itself is covered when buried enough).
        assert_eq!(skipped(p(Some(a[2]), 150, 0)), vec![1, 2]);
        // Condition 4: the best block (blue work 10 W) below the minimum.
        assert!(skipped(p(Some(a[6]), 150, 10 * w + 1)).is_empty());
        assert_eq!(skipped(p(Some(a[6]), 150, 10 * w)), vec![1, 2, 3, 4], "at the minimum");
        // Condition 4 with the node's own minimum (`None`): the process
        // default, mainnet's `core::MIN_CHAIN_WORK`, far above this chain.
        assert_eq!(crate::ingress::minimum_chain_work(), core::MIN_CHAIN_WORK);
        assert!(skipped(Policy { block: Some(a[6]), min_burial_secs: 150, min_chain_work: None }).is_empty());
        // Condition 5: two weeks bury nothing on a ten-block chain; a burial
        // of 149 s (A5 is 150 s below) adds A5.
        assert!(skipped(p(Some(a[6]), MIN_BURIAL_SECS, 0)).is_empty());
        assert_eq!(skipped(p(Some(a[6]), 149, 0)), vec![1, 2, 3, 4, 5]);
        // AV = the best block, no burial: every block strictly below it.
        assert_eq!(skipped(p(Some(a[10]), 0, 0)), vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    /// Stricter than Core: an assumed-valid block the node holds a
    /// persistent verdict against (here A5, below AV = A6, is disqualified:
    /// AV inherits it) vouches for nothing. The best block is then the side
    /// branch's S2 (5 W, above A4's 4 W), on A3.
    #[test]
    fn a_disqualified_assumed_valid_block_vouches_for_nothing() {
        let (mut d, a, side) = dag();
        d.mark_invalid(a[5]);
        assert!(d.is_invalid_persistently(&a[6]));
        assert_eq!(d.selected_tip(), Some(side[1]));
        let _g = scoped_override(p(Some(a[6]), 0, 0));
        assert!(assumed_valid_blocks(&d, &a[1..]).is_empty());
        // AV = A3 (not disqualified) with no burial: A1..A3, all strictly
        // below the best block S2 on its selected chain.
        let _g = scoped_override(p(Some(a[3]), 0, 0));
        let s = assumed_valid_blocks(&d, &a[1..]);
        let v: Vec<usize> = (0..a.len()).filter(|i| s.contains(&a[*i])).collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    /// Condition 3: a block on AV's selected chain that is not on the best
    /// block's selected chain is not skipped. Here a heavier branch from A3
    /// (13 W) becomes the best block: A4.. leave the best chain.
    #[test]
    fn a_block_off_the_best_chain_is_not_covered() {
        let (mut d, a, _) = dag();
        let mut tip = a[3];
        for i in 1..=10 {
            let b = h(0xB, i);
            add(&mut d, b, tip, 2_000 + 30 * i);
            tip = b;
        }
        assert_eq!(d.selected_tip(), Some(tip));
        let _g = scoped_override(p(Some(a[6]), 150, 0));
        let s = assumed_valid_blocks(&d, &a[1..]);
        let v: Vec<usize> = (0..a.len()).filter(|i| s.contains(&a[*i])).collect();
        assert_eq!(v, vec![1, 2, 3], "A4..A6 are on AV's chain but not on the best one");
    }
}
