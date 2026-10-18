//! The growth cap on the finality weight W (ObenBlock only;
//! docs/DESIGN-obenblock.md §6.3, normative reference
//! `reference/obb_growth_cap.py`, vectors `reference/obb_growth_cap_vectors.json`,
//! reproduced by `tests/growth_cap_vectors.rs`).
//!
//! Under PoCI (docs/DESIGN-obenblock-poci.md §2, §4) the cap computes the
//! weights of every new finality configuration. Weights are **credits**: the
//! weight of key `k` in `C_x` is the sum of its admitted credits over the
//! window epochs of `x` (`n` in `max(0, x-1-window) ..= x-2`). One step builds
//! `C_x` from `C_{x-1}`; the epoch entering the window is `n = x-2`, the one
//! leaving it `o = x-2-window`:
//!
//! ```text
//! W       = total(C_{x-1}) over the keys not excluded at x-1
//! N_k     = finalized share work of k in epoch n   (0 for a key excluded at x)
//! R_k     = credit of k in epoch o                 (the expiring credit)
//! renew_k = min(N_k, R_k)                          renewal first
//! x_k     = N_k - renew_k
//! G       = max(floor(W / 64), G_min(n))
//! S       = sum of x_k                             exact, 256 bits
//! admit_k = x_k if S <= G, else floor(x_k * G / S) exact 256-bit product and quotient
//! credit_k(n) = renew_k + admit_k                  the rest is dropped, never deferred
//! ```
//!
//! A handoff from `C_e` to `C_{e+j}` runs the step for every `x` in
//! `e+1 ..= e+j`, in order ([`CapLedger::advance`]), so `C_x` depends on
//! the finalized history only. GnB never runs any of this.

use std::collections::BTreeMap;
use std::sync::Arc;

use primitive_types::U256;
use sha3::{Digest, Sha3_256};

use super::KeyId;
use crate::core::witness_share::{MAX_SHARES_PER_BLOCK, SHARE_TARGET_SHIFT};

/// `GROWTH_DIV`: the budget is `W / 64` per epoch (§6.3).
pub const GROWTH_DIV: u64 = 64;
/// `G_min` is `1 / G_MIN_DIV` of the share work one epoch can carry.
pub const G_MIN_DIV: u64 = 8;

/// One epoch's map of key -> share work or key -> credit.
pub type EpochMap = BTreeMap<KeyId, u128>;

fn u256(v: u128) -> U256 {
    U256::from(v)
}

/// `v` as a u128 when it fits (callers only narrow values bounded by a u128).
fn narrow(v: U256) -> u128 {
    if v > u256(u128::MAX) { u128::MAX } else { v.low_u128() }
}

// ── G_min ────────────────────────────────────────────────────────────────────

/// Share work of a share at the share target of a block with compact `bits`:
/// `min(floor(2^256 / (share_target + 1)), 2^128 - 1)`, `share_target =
/// min(target(bits) * 16, 2^256 - 1)`; malformed bits carry 0 work.
pub fn share_work(bits: u32) -> u128 {
    let t = U256::from_big_endian(&crate::core::bits_to_target(bits));
    if t.is_zero() {
        return 0;
    }
    let st = if t.leading_zeros() < SHARE_TARGET_SHIFT { U256::MAX } else { t << SHARE_TARGET_SHIFT };
    // floor(2^256 / (st + 1)) = floor((2^256 - 1 - st) / (st + 1)) + 1; st = 2^256 - 1 gives 1.
    let work = if st == U256::MAX { U256::one() } else { (U256::MAX - st) / (st + U256::one()) + U256::one() };
    narrow(work)
}

/// `G_min(n) = floor(epoch_len * 16 * share_work(bits) / g_min_div)`,
/// saturating at `2^128 - 1`; `bits` are those of the first block of epoch `n`.
pub fn g_min_with(epoch_len: u64, bits: u32, g_min_div: u64) -> u128 {
    if g_min_div == 0 {
        return u128::MAX;
    }
    let v = u256(epoch_len as u128) * u256(MAX_SHARES_PER_BLOCK as u128) * u256(share_work(bits));
    narrow(v / u256(g_min_div as u128))
}

/// [`g_min_with`] at the §6.3 divisor (8).
pub fn g_min(epoch_len: u64, bits: u32) -> u128 {
    g_min_with(epoch_len, bits, G_MIN_DIV)
}

// ── One step ─────────────────────────────────────────────────────────────────

/// What one step did (reference `StepResult`). Aggregates over keys are
/// exact (256 bits); per-key values are u128.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepResult {
    /// Every key with weight > 0 after the step (excluded keys too).
    pub weights: EpochMap,
    /// The credit of the entering epoch, keys with credit > 0 only.
    pub credit: EpochMap,
    /// W used for the budget.
    pub w: u128,
    /// The growth budget G.
    pub g: u128,
    /// S: the excess over renewal, before the cap.
    pub sum_x: U256,
    pub renewed: U256,
    pub admitted: U256,
    /// Share work not credited (cut by the cap, and excluded keys' work).
    pub dropped: U256,
    /// Admitted to keys without weight before the step.
    pub admitted_new: U256,
    /// The part of `dropped` that excluded keys mined.
    pub excluded_work: U256,
}

/// One cap step on plain maps (reference `cap_step`). `prev_weights` holds
/// every key with weight > 0, excluded ones too; `w_total` defaults to the
/// saturating total of `prev_weights` over the keys not in `excluded`.
/// `excluded` tells whether a key is barred at the step's epoch.
///
/// An expiring credit above the key's weight cannot happen in a ledger (the
/// weight is the sum of the key's credits); the reference refuses it, the
/// weight here saturates at 0 instead.
pub fn cap_step(prev_weights: &EpochMap, new_work: &EpochMap, expiring: &EpochMap, g_min_value: u128,
                w_total: Option<u128>, growth_div: u64, excluded: &dyn Fn(&KeyId) -> bool) -> StepResult
{
    let w_total = w_total.unwrap_or_else(|| {
        prev_weights.iter().filter(|(k, _)| !excluded(k)).fold(0u128, |a, (_, w)| a.saturating_add(*w))
    });
    let mut renew: EpochMap = BTreeMap::new();
    let mut xs: EpochMap = BTreeMap::new();
    let mut excl = U256::zero();
    let mut total_n = U256::zero();
    for (k, n) in new_work {
        total_n += u256(*n);
        if *n == 0 {
            continue;
        }
        if excluded(k) {
            excl += u256(*n);
            continue;
        }
        let rn = (*n).min(expiring.get(k).copied().unwrap_or(0));
        renew.insert(*k, rn);
        xs.insert(*k, n - rn);
    }
    let g = (w_total / growth_div.max(1) as u128).max(g_min_value);
    let s = xs.values().fold(U256::zero(), |a, x| a + u256(*x));
    let admit: EpochMap = if s <= u256(g) {
        xs.clone()
    } else {
        // x_k * G < 2^256 and the quotient is below x_k: exact, then narrowed.
        xs.iter().map(|(k, x)| (*k, (u256(*x) * u256(g) / s).low_u128())).collect()
    };
    let mut credit: EpochMap = BTreeMap::new();
    for (k, rn) in &renew {
        // renew_k + admit_k <= N_k: no overflow.
        let c = rn + admit.get(k).copied().unwrap_or(0);
        if c > 0 {
            credit.insert(*k, c);
        }
    }
    let mut weights: EpochMap = BTreeMap::new();
    for k in prev_weights.keys().chain(credit.keys()) {
        if weights.contains_key(k) {
            continue;
        }
        let prev = prev_weights.get(k).copied().unwrap_or(0);
        let w = prev.saturating_sub(expiring.get(k).copied().unwrap_or(0))
            .saturating_add(credit.get(k).copied().unwrap_or(0));
        if w > 0 {
            weights.insert(*k, w);
        }
    }
    let credited = credit.values().fold(U256::zero(), |a, c| a + u256(*c));
    let sum = |m: &EpochMap| m.values().fold(U256::zero(), |a, v| a + u256(*v));
    let admitted_new = admit.iter().filter(|(k, _)| prev_weights.get(*k).copied().unwrap_or(0) == 0)
        .fold(U256::zero(), |a, (_, v)| a + u256(*v));
    StepResult {
        w: w_total,
        g,
        sum_x: s,
        renewed: sum(&renew),
        admitted: sum(&admit),
        dropped: total_n - credited,
        admitted_new,
        excluded_work: excl,
        weights,
        credit,
    }
}

// ── The ledger of credits ────────────────────────────────────────────────────

/// What the last step of a handoff reported (`getpowitinfo`: the capture is
/// visible the whole time). Aggregates as decimal-free 256-bit integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapReport {
    /// The epoch `x` of the configuration the step built.
    pub epoch: u64,
    pub w: u128,
    pub g: u128,
    pub sum_x: U256,
    pub admitted: U256,
    pub admitted_new: U256,
    pub dropped: U256,
}

impl CapReport {
    fn of(epoch: u64, r: &StepResult) -> CapReport {
        CapReport { epoch, w: r.w, g: r.g, sum_x: r.sum_x, admitted: r.admitted, admitted_new: r.admitted_new,
                    dropped: r.dropped }
    }
}

/// The credits of the window epochs of `C_epoch` (reference ledger
/// `{"epoch": x, "credits": {n: {key: credit}}}`). Immutable once built; each
/// epoch's map is shared (`Arc`), so the per-block copies of a PoWit state
/// share them. `id` is a content digest for node-local storage (not
/// consensus): it commits to the epoch, every credit and the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapLedger {
    epoch: u64,
    credits: BTreeMap<u64, Arc<EpochMap>>,
    report: Option<CapReport>,
    id: [u8; 32],
}

const DS_LEDGER: &[u8] = b"OBB-GROWTH-CAP-v1/ledger";

impl Default for CapLedger {
    fn default() -> Self {
        CapLedger::empty()
    }
}

impl CapLedger {
    /// The ledger of `C_1` (and `C_0`): no window epoch yet.
    pub fn empty() -> CapLedger {
        CapLedger::from_parts(1, BTreeMap::new(), None)
    }

    /// A ledger from its parts (what the node stores); empty credit maps are
    /// dropped (the reference keeps an epoch only when something was credited).
    pub fn from_parts(epoch: u64, credits: BTreeMap<u64, Arc<EpochMap>>, report: Option<CapReport>) -> CapLedger {
        let credits: BTreeMap<u64, Arc<EpochMap>> = credits.into_iter()
            .map(|(n, m)| {
                if m.values().any(|c| *c == 0) {
                    (n, Arc::new(m.iter().filter(|(_, c)| **c > 0).map(|(k, c)| (*k, *c)).collect()))
                } else {
                    (n, m)
                }
            })
            .filter(|(_, m)| !m.is_empty())
            .collect();
        let id = Self::digest(epoch, &credits, report.as_ref());
        CapLedger { epoch, credits, report, id }
    }

    fn digest(epoch: u64, credits: &BTreeMap<u64, Arc<EpochMap>>, report: Option<&CapReport>) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DS_LEDGER);
        h.update(epoch.to_le_bytes());
        h.update((credits.len() as u64).to_le_bytes());
        for (n, m) in credits {
            h.update(n.to_le_bytes());
            h.update((m.len() as u64).to_le_bytes());
            for (k, c) in m.iter() {
                h.update(k);
                h.update(c.to_le_bytes());
            }
        }
        match report {
            None => h.update([0u8]),
            Some(r) => {
                h.update([1u8]);
                h.update(r.epoch.to_le_bytes());
                h.update(r.w.to_le_bytes());
                h.update(r.g.to_le_bytes());
                for v in [r.sum_x, r.admitted, r.admitted_new, r.dropped] {
                    h.update(v.to_little_endian());
                }
            }
        }
        h.finalize().into()
    }

    /// The configuration epoch `x` whose window these credits are.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Credits by window epoch (only epochs with a credit).
    pub fn credits(&self) -> &BTreeMap<u64, Arc<EpochMap>> {
        &self.credits
    }

    /// The last step's report (the step that built `C_epoch`), if one ran.
    pub fn report(&self) -> Option<&CapReport> {
        self.report.as_ref()
    }

    /// Content digest (node-local storage key).
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Every key's weight: the saturating sum of its credits, weight > 0
    /// (reference `ledger_weights`), excluded keys included.
    pub fn weights(&self) -> EpochMap {
        let mut out: EpochMap = BTreeMap::new();
        for m in self.credits.values() {
            for (k, c) in m.iter() {
                let e = out.entry(*k).or_insert(0);
                *e = e.saturating_add(*c);
            }
        }
        out.retain(|_, w| *w > 0);
        out
    }

    /// The candidate entries of `C_epoch`: [`Self::weights`] without the keys
    /// excluded at `epoch` (reference `configuration`).
    pub fn configuration(&self, excluded: &dyn Fn(&KeyId, u64) -> bool) -> EpochMap {
        let x = self.epoch;
        self.weights().into_iter().filter(|(k, _)| !excluded(k, x)).collect()
    }

    /// Run the cap from this ledger's epoch to `to_epoch` (a handoff,
    /// possibly skipping epochs; reference `advance`). `work(n)` is the
    /// finalized share work of epoch `n`, `first_bits(n)` the compact bits of
    /// epoch `n`'s first block (`None`: G_min(n) = 0), `excluded(k, x)`
    /// whether `k` is barred at `x`. `to_epoch` below the ledger's epoch is
    /// refused: the window only moves forward.
    ///
    /// Cost: one pass over the window's keys per epoch stepped; only the
    /// last step's report is kept ([`Self::report`]), so a handoff after a
    /// long stall holds one weight map at a time.
    #[allow(clippy::too_many_arguments)]
    pub fn advance<'h>(&self, to_epoch: u64, epoch_len: u64, window_epochs: u64, growth_div: u64, g_min_div: u64,
                       work: &dyn Fn(u64) -> Option<&'h EpochMap>, first_bits: &dyn Fn(u64) -> Option<u32>,
                       excluded: &dyn Fn(&KeyId, u64) -> bool) -> Result<CapLedger, String>
    {
        self.advance_traced(to_epoch, epoch_len, window_epochs, growth_div, g_min_div, work, first_bits, excluded,
                            &mut |_, _| {})
    }

    /// [`Self::advance`], calling `on_step(x, result)` for every step `x` in
    /// order (`None` for `x < 2`: no epoch enters the window). Tests and
    /// diagnostics.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_traced<'h>(&self, to_epoch: u64, epoch_len: u64, window_epochs: u64, growth_div: u64,
                              g_min_div: u64, work: &dyn Fn(u64) -> Option<&'h EpochMap>,
                              first_bits: &dyn Fn(u64) -> Option<u32>, excluded: &dyn Fn(&KeyId, u64) -> bool,
                              on_step: &mut dyn FnMut(u64, Option<&StepResult>)) -> Result<CapLedger, String>
    {
        if to_epoch < self.epoch {
            return Err("growth cap: the window only moves forward".into());
        }
        let mut credits = self.credits.clone();
        let mut weights = self.weights();
        let mut report = self.report;
        let empty: EpochMap = BTreeMap::new();
        for x in self.epoch + 1..=to_epoch {
            if x < 2 {
                on_step(x, None);
                continue;
            }
            let w_total = weights.iter().filter(|(k, _)| !excluded(k, x - 1))
                .fold(0u128, |a, (_, w)| a.saturating_add(*w));
            let n = x - 2;
            let expiring = match n.checked_sub(window_epochs) {
                Some(o) => credits.remove(&o),
                None => None,
            };
            let gm = first_bits(n).map_or(0, |b| g_min_with(epoch_len, b, g_min_div));
            let mut r = cap_step(&weights, work(n).unwrap_or(&empty), expiring.as_deref().unwrap_or(&empty),
                                 gm, Some(w_total), growth_div, &|k| excluded(k, x));
            report = Some(CapReport::of(x, &r));
            on_step(x, Some(&r));
            let credit = std::mem::take(&mut r.credit);
            if !credit.is_empty() {
                credits.insert(n, Arc::new(credit));
            }
            weights = std::mem::take(&mut r.weights);
        }
        Ok(CapLedger::from_parts(to_epoch, credits, report))
    }
}

/// The smallest `t` with `(65/64)^t > factor_num / factor_den` (exact):
/// starting from W, the weight is at most `W (65/64)^t` after `t` epochs
/// (reference `epochs_to_grow`). 512-bit integers; `u64::MAX` if the
/// answer is beyond them (a factor far above anything §6.3 asks about).
pub fn epochs_to_grow(factor_num: u64, factor_den: u64) -> u64 {
    use primitive_types::U512;
    let (mut lhs, mut rhs) = (U512::from(factor_den), U512::from(factor_num));
    let mut t = 0;
    // 65^t * den <= num * 64^t: both sides scaled each round.
    while lhs <= rhs {
        match (lhs.checked_mul(U512::from(GROWTH_DIV + 1)), rhs.checked_mul(U512::from(GROWTH_DIV))) {
            (Some(l), Some(r)) => (lhs, rhs) = (l, r),
            _ => return u64::MAX,
        }
        t += 1;
    }
    t
}

// ── State kept beside the PoWit state ────────────────────────────────────────

/// The growth cap's part of a PoCI chain's state (`PowitState::cap`): the
/// ledger of the configuration in force (`C_1` until the launch) and the
/// compact bits of the first block of every epoch the next handoff may
/// still need (`n >= ledger.epoch - 1`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapState {
    pub ledger: CapLedger,
    pub first_bits: BTreeMap<u64, u32>,
}

impl CapState {
    /// Record `bits` for `epoch` if no earlier block of the epoch did.
    pub fn note_block(&mut self, epoch: u64, bits: Option<u32>) {
        if let Some(b) = bits {
            self.first_bits.entry(epoch).or_insert(b);
        }
    }

    /// Drop bits no handoff can need any more.
    pub fn prune(&mut self) {
        let keep = self.ledger.epoch().saturating_sub(1);
        self.first_bits = self.first_bits.split_off(&keep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(i: u8) -> KeyId {
        [i; 20]
    }

    #[test]
    fn share_work_edges() {
        assert_eq!(share_work(0x207F_FFFF), 1);
        assert_eq!(share_work(0x1D00_FFFF | 0x0080_0000), 0);
        assert_eq!(share_work(0x0300_0001), u128::MAX);
        assert_eq!(g_min(720, 0x207F_FFFF), 1440);
    }

    #[test]
    fn excess_cut_pro_rata_is_never_more_than_the_budget() {
        let prev: EpochMap = [(k(1), 64 * 1000)].into();
        let work: EpochMap = [(k(2), u128::MAX), (k(3), u128::MAX), (k(4), 7)].into();
        let r = cap_step(&prev, &work, &BTreeMap::new(), 0, None, GROWTH_DIV, &|_| false);
        assert_eq!(r.g, 1000);
        assert!(r.admitted <= U256::from(r.g));
        assert_eq!(r.admitted_new, r.admitted);
    }

    #[test]
    fn bound_constants() {
        assert_eq!(epochs_to_grow(3, 1), 71);
        assert_eq!(epochs_to_grow(2, 1), 45);
    }
}
