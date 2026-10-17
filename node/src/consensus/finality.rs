//! The PoWit finality pin: node-local fork choice (PoWit audit findings 2
//! and 3; docs/CONSENSUS.md "Selected parent and fork choice",
//! docs/DESIGN-pow-powit.md §7.6).
//!
//! The pin ([`GhostDAG::finalized`]) restricts which blocks are selectable:
//! a block whose selected-parent chain misses it is never selected nor
//! offered as a template parent. It used to come from the PoWit state of the
//! node's own applied tip only, so a node that never applied the blocks
//! carrying a finalization never learned it (a healed partition split
//! forever), and a restart restored it from the applied tip only (it could
//! drop). As in Gasper, whose fork choice starts from the highest justified
//! checkpoint learned from ANY block, the pin is now a pure function of the
//! blocks the node holds:
//!
//! * a **candidate** is a finalized checkpoint (beyond the activation one)
//!   carried by the PoWit state of a stored block, its **source**;
//!   [`FinalityIndex`] records every (source, checkpoint) pair;
//! * it **counts** when some source is not disqualified
//!   ([`GhostDAG::is_invalid`]) and has at least the node's minimum chain
//!   work (a cheap chain pulled during initial sync proves nothing,
//!   `ingress::minimum_chain_work`), the operator did not set it aside, and
//!   it agrees with the weak-subjectivity **anchor** (the release finality
//!   checkpoint, or the operator's): a candidate at or below the anchor's
//!   height never counts (the anchor dominates it), one above it counts only
//!   if the anchor is on its selected chain;
//! * the **pin** is the highest counted candidate when all of them lie on
//!   one selected chain; when two conflict (neither is on the other's
//!   selected chain: accountable safety says at least a third of the
//!   witness weight signed both, or the two chains derived different
//!   witness sets, e.g. a fork that branched before any common finality, or
//!   inactivity decay through a long partition) it is their latest common
//!   block, so the most work decides above it and the node reports the
//!   conflict; and never below the anchor, once the anchor block is known.
//!
//! Two nodes holding the same blocks (and the same disqualifications,
//! minimum chain work, anchor and operator settings) therefore compute the
//! same pin whatever the arrival order, and a restart rebuilds it from the
//! persisted (source, checkpoint) rows (`powit::load_finality_index`).

use std::collections::{HashMap, HashSet};

use super::{BlockHash, GhostDAG};

/// One finalized checkpoint and the blocks whose PoWit state carries it.
#[derive(Clone, Debug, Default)]
struct Candidate {
    /// Its PoWit slot (`Checkpoint::height`).
    slot: u64,
    sources: Vec<BlockHash>,
}

/// A weak-subjectivity anchor: a block the node trusts as final (release
/// finality checkpoint, or the operator's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub hash: BlockHash,
    /// Its DAG height.
    pub height: u64,
}

/// The operator's anchor setting (`setfinalitycheckpoint`), persisted by the
/// node (`powit::FINALITY_ANCHOR_META`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnchorSetting {
    /// The release finality checkpoint of the node's network, if any.
    #[default]
    Release,
    /// No anchor at all, not even the release one.
    Disabled,
    /// This block.
    Operator(Anchor),
}

/// Inputs of the pin that do not come from the DAG.
#[derive(Clone, Copy, Debug)]
pub struct PinPolicy<'a> {
    pub min_chain_work: u128,
    pub anchor: Option<Anchor>,
    /// Blocks the operator set aside (`ignorefinalized`): no candidate at or
    /// above one of them on its selected chain counts.
    pub ignored: &'a HashSet<BlockHash>,
}

/// Where the pin comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PinOrigin {
    #[default]
    None,
    /// The anchor (no counted candidate above it).
    Anchor,
    /// The highest counted finalized checkpoint.
    Finalized,
    /// The latest common block of conflicting finalized checkpoints.
    Conflict,
}

impl PinOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            PinOrigin::None => "none",
            PinOrigin::Anchor => "anchor",
            PinOrigin::Finalized => "finalized",
            PinOrigin::Conflict => "conflict",
        }
    }
}

/// What the anchor of a [`PinPolicy`] amounts to on this DAG.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnchorStatus {
    /// No anchor configured.
    #[default]
    None,
    /// The block is in the DAG, valid, at the configured height.
    Known,
    /// Not in the DAG yet: nothing above its height counts until it arrives.
    Unknown,
    /// In the DAG but disqualified: nothing through it counts (alert).
    Invalid,
    /// In the DAG at another DAG height than configured (the DAG's height is
    /// used; a release or operator typo, alert).
    HeightMismatch,
}

/// Result of [`GhostDAG::compute_finality_pin`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinOutcome {
    /// (block, DAG height).
    pub pin: Option<(BlockHash, u64)>,
    pub origin: PinOrigin,
    pub anchor: AnchorStatus,
    /// Counted candidates: (checkpoint, DAG height, slot), highest first.
    pub counted: Vec<(BlockHash, u64, u64)>,
    /// The two highest conflicting counted checkpoints (block, DAG height),
    /// when any two conflict.
    pub conflict: Option<((BlockHash, u64), (BlockHash, u64))>,
    /// Supported candidates refused because they conflict with the anchor.
    pub against_anchor: usize,
    /// Supported candidates the operator set aside.
    pub ignored: usize,
}

/// Every (source, finalized checkpoint) pair the node knows (memory: about
/// 70 bytes per post-activation block whose state finalized something).
#[derive(Clone, Debug, Default)]
pub struct FinalityIndex {
    by_checkpoint: HashMap<BlockHash, Candidate>,
    by_source: HashMap<BlockHash, BlockHash>,
    /// Operator settings (loaded from storage at start-up, changed by RPC).
    pub(crate) anchor_setting: AnchorSetting,
    pub(crate) ignored: HashSet<BlockHash>,
    /// The last outcome applied ([`GhostDAG::set_finality_pin`]), for RPC and
    /// for logging changes once.
    pub(crate) last: PinOutcome,
}

impl FinalityIndex {
    pub fn candidates(&self) -> usize {
        self.by_checkpoint.len()
    }

    pub fn sources(&self) -> usize {
        self.by_source.len()
    }

    /// The checkpoint `source`'s state finalized, if recorded.
    #[allow(dead_code)] // tests and tools; the node binary compiles this module too
    pub fn checkpoint_of(&self, source: &BlockHash) -> Option<BlockHash> {
        self.by_source.get(source).copied()
    }
}

impl GhostDAG {
    /// The finality index (read).
    pub fn finality_index(&self) -> &FinalityIndex {
        &self.finality
    }

    /// The finality index (operator settings, start-up reload).
    pub fn finality_index_mut(&mut self) -> &mut FinalityIndex {
        &mut self.finality
    }

    /// Record that `source`'s PoWit state finalized `checkpoint` (slot
    /// `slot`). Both must be in the DAG; idempotent.
    pub fn note_finality_source(&mut self, source: BlockHash, checkpoint: BlockHash, slot: u64) -> bool {
        if !self.store.has(&source) || !self.store.has(&checkpoint) || self.finality.by_source.contains_key(&source) {
            return false;
        }
        self.finality.by_source.insert(source, checkpoint);
        let c = self.finality.by_checkpoint.entry(checkpoint).or_default();
        c.slot = slot;
        c.sources.push(source);
        true
    }

    /// Forget `source` (its block left the DAG: a rolled-back acceptance).
    pub(super) fn forget_finality_source(&mut self, source: &BlockHash) {
        let Some(cp) = self.finality.by_source.remove(source) else { return };
        if let Some(c) = self.finality.by_checkpoint.get_mut(&cp) {
            c.sources.retain(|s| s != source);
            if c.sources.is_empty() {
                self.finality.by_checkpoint.remove(&cp);
            }
        }
    }

    /// Drop every recorded pair (start-up reload), keeping operator settings.
    pub fn clear_finality_sources(&mut self) {
        self.finality.by_checkpoint.clear();
        self.finality.by_source.clear();
    }

    /// `a == b` or `a` is on `b`'s selected-parent chain. O(1) through the
    /// reachability index; a selected-chain walk where it is not maintained.
    pub fn is_chain_ancestor_or_self(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b {
            return true;
        }
        if self.maintains_reachability_index() && self.reach.has(a) && self.reach.has(b) {
            return self.reach.is_chain_ancestor(a, b);
        }
        self.is_on_selected_chain_of(a, b)
    }

    /// The latest block on both `a`'s and `b`'s selected chains.
    pub fn selected_chain_meet(&self, a: &BlockHash, b: &BlockHash) -> Option<BlockHash> {
        let (ha, hb) = (self.store.get(a)?.height, self.store.get(b)?.height);
        let (mut x, other) = if ha >= hb { (*a, *b) } else { (*b, *a) };
        loop {
            if self.is_chain_ancestor_or_self(&x, &other) {
                return Some(x);
            }
            x = self.store.get(&x)?.selected_parent?;
        }
    }

    /// The pin these blocks and `policy` give (see the module docs). Pure:
    /// it reads the DAG, the disqualified set and the index, and changes
    /// nothing.
    pub fn compute_finality_pin(&self, policy: &PinPolicy<'_>) -> PinOutcome {
        let mut out = PinOutcome::default();
        // The anchor: the block if known and valid, and the height that
        // separates what it dominates from what must descend from it.
        let (anchor_block, anchor_height) = match policy.anchor {
            None => (None, None),
            Some(a) => match self.store.get(&a.hash) {
                None => {
                    out.anchor = AnchorStatus::Unknown;
                    (None, Some(a.height))
                }
                Some(d) => {
                    out.anchor = if self.invalid.contains(&a.hash) {
                        AnchorStatus::Invalid
                    } else if d.height != a.height {
                        AnchorStatus::HeightMismatch
                    } else {
                        AnchorStatus::Known
                    };
                    let usable = out.anchor != AnchorStatus::Invalid;
                    (usable.then_some(Anchor { hash: a.hash, height: d.height }), Some(d.height))
                }
            },
        };

        let mut counted: Vec<(BlockHash, u64, u64)> = Vec::new();
        for (cp, cand) in &self.finality.by_checkpoint {
            let Some(d) = self.store.get(cp) else { continue };
            let supported = cand.sources.iter().any(|s| {
                !self.invalid.contains(s)
                    && self.store.get(s).is_some_and(|sd| sd.blue_work >= policy.min_chain_work)
            });
            if !supported {
                continue;
            }
            if policy.ignored.iter().any(|i| self.is_chain_ancestor_or_self(i, cp)) {
                out.ignored += 1;
                continue;
            }
            if let Some(ah) = anchor_height {
                let descends = anchor_block.is_some_and(|a| d.height > ah && self.is_chain_ancestor_or_self(&a.hash, cp));
                if !descends {
                    // Above the anchor's height without it on its chain:
                    // against it (were the anchor on that chain, it would be
                    // in the DAG). At or below: dominated if it is on the
                    // anchor's chain, against it if not, undecided while
                    // the anchor is unknown.
                    let against = d.height > ah
                        || anchor_block.is_some_and(|a| !self.is_chain_ancestor_or_self(cp, &a.hash));
                    if against {
                        out.against_anchor += 1;
                    }
                    continue;
                }
            }
            counted.push((*cp, d.height, cand.slot));
        }
        // Highest first; ties (two blocks at one DAG height) by hash, so the
        // order, and every choice below, is independent of insertion order.
        counted.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
        // The maximal candidates: none on the selected chain of another.
        // Selected-chain heights strictly increase, so a candidate can only
        // be an ancestor of one already taken.
        let mut maximal: Vec<(BlockHash, u64)> = Vec::new();
        for (h, ht, _) in &counted {
            if !maximal.iter().any(|(m, _)| self.is_chain_ancestor_or_self(h, m)) {
                maximal.push((*h, *ht));
            }
        }
        let finalized_pin = match maximal.as_slice() {
            [] => None,
            [only] => {
                out.origin = PinOrigin::Finalized;
                Some(*only)
            }
            [first, second, rest @ ..] => {
                out.origin = PinOrigin::Conflict;
                out.conflict = Some((*first, *second));
                let mut meet = Some(first.0);
                for (m, _) in std::iter::once(second).chain(rest) {
                    meet = meet.and_then(|x| self.selected_chain_meet(&x, m));
                }
                meet.and_then(|m| self.store.get(&m).map(|d| (m, d.height)))
            }
        };
        out.counted = counted;
        out.pin = match (anchor_block, finalized_pin) {
            (Some(a), None) => {
                out.origin = PinOrigin::Anchor;
                Some((a.hash, a.height))
            }
            // Every counted candidate descends from the anchor, so does
            // their latest common block: the higher of the two is the pin.
            (Some(a), Some(p)) if p.1 < a.height => {
                out.origin = PinOrigin::Anchor;
                Some((a.hash, a.height))
            }
            (_, p) => p,
        };
        out
    }

    /// Replace the pin (it may move back: a conflict, a disqualification or
    /// an operator setting changes what counts). [`GhostDAG::set_finalized`]
    /// only ever advances it.
    pub fn set_finality_pin(&mut self, outcome: PinOutcome) {
        self.finalized = outcome.pin;
        self.finality.last = outcome;
    }

    /// The last outcome applied by [`set_finality_pin`](Self::set_finality_pin).
    pub fn finality_outcome(&self) -> &PinOutcome {
        &self.finality.last
    }

    /// Every recorded candidate: (checkpoint, slot, sources).
    #[allow(dead_code)] // tests and tools; the node binary compiles this module too
    pub fn finality_candidates(&self) -> Vec<(BlockHash, u64, usize)> {
        let mut v: Vec<(BlockHash, u64, usize)> = self.finality.by_checkpoint.iter()
            .map(|(h, c)| (*h, c.slot, c.sources.len()))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(tag: u8, n: u64) -> BlockHash {
        let mut x = [0u8; 32];
        x[0] = tag;
        x[1..9].copy_from_slice(&n.to_le_bytes());
        x
    }

    /// genesis g; chain a = g -> a1..a10; chain b = a3 -> b4..b12 (heavier).
    fn dag() -> GhostDAG {
        let mut d = GhostDAG::with_default_k();
        d.add_genesis(h(0, 0), 0);
        let mut p = h(0, 0);
        for i in 1..=10 {
            d.add_block(h(1, i), vec![p], i, 10).unwrap();
            p = h(1, i);
        }
        let mut p = h(1, 3);
        for i in 4..=12 {
            d.add_block(h(2, i), vec![p], i, 10).unwrap();
            p = h(2, i);
        }
        d
    }

    fn policy(ignored: &HashSet<BlockHash>) -> PinPolicy<'_> {
        PinPolicy { min_chain_work: 0, anchor: None, ignored }
    }

    #[test]
    fn the_pin_is_the_highest_candidate_of_one_chain_and_the_meet_of_conflicting_ones() {
        let none = HashSet::new();
        let mut d = dag();
        assert_eq!(d.compute_finality_pin(&policy(&none)).pin, None);
        d.note_finality_source(h(1, 8), h(1, 2), 3);
        d.note_finality_source(h(1, 9), h(1, 5), 6);
        let o = d.compute_finality_pin(&policy(&none));
        assert_eq!((o.pin, o.origin, o.conflict), (Some((h(1, 5), 5)), PinOrigin::Finalized, None));
        // b finalizes b6: conflicts with a5 (a3 is their latest common block).
        d.note_finality_source(h(2, 11), h(2, 6), 7);
        let o = d.compute_finality_pin(&policy(&none));
        assert_eq!(o.pin, Some((h(1, 3), 3)));
        assert_eq!(o.origin, PinOrigin::Conflict);
        assert_eq!(o.conflict, Some(((h(2, 6), 6), (h(1, 5), 5))));
        // The same set in another insertion order gives the same outcome.
        let mut e = dag();
        e.note_finality_source(h(2, 11), h(2, 6), 7);
        e.note_finality_source(h(1, 9), h(1, 5), 6);
        e.note_finality_source(h(1, 8), h(1, 2), 3);
        assert_eq!(e.compute_finality_pin(&policy(&none)), o);
        // Disqualifying b's source drops b6: back to a5.
        d.mark_invalid(h(2, 10));
        assert_eq!(d.compute_finality_pin(&policy(&none)).pin, Some((h(1, 5), 5)));
        // The operator sets a5 aside: a2 remains.
        let ignored: HashSet<BlockHash> = [h(1, 4)].into_iter().collect();
        let o = d.compute_finality_pin(&policy(&ignored));
        assert_eq!((o.pin, o.ignored), (Some((h(1, 2), 2)), 1));
    }

    #[test]
    fn the_anchor_dominates_below_and_must_be_an_ancestor_above() {
        let none = HashSet::new();
        let mut d = dag();
        d.note_finality_source(h(1, 9), h(1, 5), 6);
        d.note_finality_source(h(2, 11), h(2, 6), 7);
        // Anchor b4: a5 conflicts with it, b6 descends from it.
        let anchor = Some(Anchor { hash: h(2, 4), height: 4 });
        let o = d.compute_finality_pin(&PinPolicy { min_chain_work: 0, anchor, ignored: &none });
        assert_eq!((o.pin, o.origin, o.against_anchor, o.anchor), (Some((h(2, 6), 6)), PinOrigin::Finalized, 1,
            AnchorStatus::Known));
        // Anchor b8, above b6: b6 is below it (dominated), a5 conflicts.
        let anchor = Some(Anchor { hash: h(2, 8), height: 8 });
        let o = d.compute_finality_pin(&PinPolicy { min_chain_work: 0, anchor, ignored: &none });
        assert_eq!((o.pin, o.origin, o.against_anchor), (Some((h(2, 8), 8)), PinOrigin::Anchor, 1));
        // An anchor not in the DAG yet: nothing above its height counts, and
        // nothing pins (a fork the node is eclipsed on cannot pin it).
        let anchor = Some(Anchor { hash: h(9, 4), height: 4 });
        let o = d.compute_finality_pin(&PinPolicy { min_chain_work: 0, anchor, ignored: &none });
        assert_eq!((o.pin, o.anchor, o.counted.len()), (None, AnchorStatus::Unknown, 0));
        // A disqualified anchor pins nothing (and nothing through it counts).
        d.mark_invalid(h(2, 4));
        let anchor = Some(Anchor { hash: h(2, 4), height: 4 });
        let o = d.compute_finality_pin(&PinPolicy { min_chain_work: 0, anchor, ignored: &none });
        assert_eq!((o.pin, o.anchor), (None, AnchorStatus::Invalid));
    }

    #[test]
    #[ignore]
    fn tmp_cost_probe() {
        let none = HashSet::new();
        let mut d = GhostDAG::with_default_k();
        d.add_genesis(h(0, 0), 0);
        let mut p = h(0, 0);
        let n = 20_000u64;
        for i in 1..=n {
            d.add_block(h(1, i), vec![p], i, 10).unwrap();
            p = h(1, i);
        }
        for i in (2..=n).step_by(2) {
            d.note_finality_source(h(1, i), h(1, i - 1), i);
            d.note_finality_source(h(1, i - 1), h(1, i.saturating_sub(3).max(1)), i);
        }
        let t = std::time::Instant::now();
        let mut o = PinOutcome::default();
        for _ in 0..10 {
            o = d.compute_finality_pin(&policy(&none));
        }
        eprintln!("candidates {} -> {:?} per compute; pin {:?}", d.finality_index().candidates(),
            t.elapsed() / 10, o.pin.map(|x| x.1));
    }

    #[test]
    fn a_source_below_the_minimum_chain_work_does_not_count() {
        let none = HashSet::new();
        let mut d = dag();
        d.note_finality_source(h(1, 6), h(1, 2), 3);
        let w6 = d.get_block_data(&h(1, 6)).unwrap().blue_work;
        let p = |min| PinPolicy { min_chain_work: min, anchor: None, ignored: &none };
        assert_eq!(d.compute_finality_pin(&p(w6)).pin, Some((h(1, 2), 2)));
        assert_eq!(d.compute_finality_pin(&p(w6 + 1)).pin, None);
        // A later source of the same checkpoint reaching the minimum counts.
        d.note_finality_source(h(1, 7), h(1, 2), 3);
        assert_eq!(d.compute_finality_pin(&p(w6 + 1)).pin, Some((h(1, 2), 2)));
        // Removing the block forgets its source.
        assert!(d.remove_block(&h(2, 12)));
        d.note_finality_source(h(2, 11), h(2, 5), 6);
        assert!(d.remove_block(&h(2, 11)));
        assert_eq!(d.finality_index().checkpoint_of(&h(2, 11)), None);
        assert_eq!(d.finality_candidates().len(), 1);
    }
}
