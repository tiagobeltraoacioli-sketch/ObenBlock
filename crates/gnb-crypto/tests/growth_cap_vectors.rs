//! The ObenBlock growth cap (docs/DESIGN-obenblock.md §6.3) against its
//! normative reference (`reference/obb_growth_cap.py` ->
//! `reference/obb_growth_cap_vectors.json`): G_min, single steps (renewal
//! first, pro rata with 256-bit intermediates, exclusions), stateful
//! sequences (handoffs every epoch, skipping handoffs, a ban), the flood
//! traces and the launch from genesis, every case. Then the flood scenario
//! of the reference rebuilt here for k = 2, 10 and 100, and the bound: no
//! flood of new keys holds strictly more than 2/3 before 71 epochs.

use std::collections::BTreeMap;
use std::sync::Arc;

use gnb_crypto::core::powit::growth_cap::{
    cap_step, epochs_to_grow, g_min, share_work, CapLedger, EpochMap, StepResult, GROWTH_DIV, G_MIN_DIV,
};
use gnb_crypto::core::powit::KeyId;
use primitive_types::U256;
use serde_json::Value;
use sha3::{Digest, Sha3_256};

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_growth_cap_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn u128s(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn u256s(v: &Value) -> U256 {
    U256::from_dec_str(v.as_str().unwrap()).unwrap()
}

fn key(hexs: &str) -> KeyId {
    hex::decode(hexs).unwrap().try_into().unwrap()
}

fn kmap(v: &Value) -> EpochMap {
    v.as_object().unwrap().iter().map(|(k, w)| (key(k), u128s(w))).collect()
}

fn params(name: &str) -> (u64, u64) {
    let p = &doc()["constants"]["params"][name];
    (p["epoch_len"].as_u64().unwrap(), p["window_epochs"].as_u64().unwrap())
}

fn check_step(r: &StepResult, want: &Value, what: &str) {
    assert_eq!(r.w, u128s(&want["w"]), "{what}: w");
    assert_eq!(r.g, u128s(&want["g"]), "{what}: g");
    assert_eq!(r.sum_x, u256s(&want["sum_x"]), "{what}: sum_x");
    assert_eq!(r.renewed, u256s(&want["renewed"]), "{what}: renewed");
    assert_eq!(r.admitted, u256s(&want["admitted"]), "{what}: admitted");
    assert_eq!(r.dropped, u256s(&want["dropped"]), "{what}: dropped");
    assert_eq!(r.admitted_new, u256s(&want["admitted_new"]), "{what}: admitted_new");
    assert_eq!(r.credit, kmap(&want["credit"]), "{what}: credit");
    assert_eq!(r.weights, kmap(&want["weights"]), "{what}: weights");
}

#[test]
fn constants() {
    let d = doc();
    let c = &d["constants"];
    assert_eq!(d["format"], "obb-growth-cap-vectors-v1");
    assert_eq!(c["growth_div"].as_u64(), Some(GROWTH_DIV));
    assert_eq!(c["g_min_div"].as_u64(), Some(G_MIN_DIV));
    assert_eq!(c["max_shares_per_block"].as_u64(), Some(gnb_crypto::core::witness_share::MAX_SHARES_PER_BLOCK as u64));
    assert_eq!(c["share_target_shift"].as_u64(), Some(gnb_crypto::core::witness_share::SHARE_TARGET_SHIFT as u64));
    assert_eq!(c["epochs_to_triple_w"].as_u64(), Some(epochs_to_grow(3, 1)));
    assert_eq!(c["epochs_to_double_w"].as_u64(), Some(epochs_to_grow(2, 1)));
    assert_eq!(epochs_to_grow(3, 1), 71);
    // The PoCI parameters commit the same divisors.
    let pp = gnb_crypto::core::powit::poci::OBB_MAINNET_POCI;
    assert_eq!((pp.growth_div, pp.g_min_epoch_div), (GROWTH_DIV, G_MIN_DIV));
    assert_eq!((pp.epoch_len, pp.window_epochs), params("obenblock"));
}

#[test]
fn g_min_vectors() {
    let d = doc();
    let cases = d["g_min"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for c in cases {
        let bits = c["bits"].as_u64().unwrap() as u32;
        let el = c["epoch_len"].as_u64().unwrap();
        assert_eq!(share_work(bits), u128s(&c["share_work"]), "share_work({bits:#x})");
        assert_eq!(g_min(el, bits), u128s(&c["g_min"]), "g_min({el}, {bits:#x})");
    }
}

#[test]
fn step_vectors() {
    let d = doc();
    let cases = d["steps"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let excluded: Vec<KeyId> = c["excluded"].as_array().unwrap().iter().map(|k| key(k.as_str().unwrap())).collect();
        let wt = (!c["w_total"].is_null()).then(|| u128s(&c["w_total"]));
        let r = cap_step(&kmap(&c["prev_weights"]), &kmap(&c["new_work"]), &kmap(&c["expiring"]), u128s(&c["g_min"]),
                         wt, GROWTH_DIV, &|k| excluded.contains(k));
        check_step(&r, &c["result"], name);
    }
}

struct History {
    work: BTreeMap<u64, EpochMap>,
    bits: BTreeMap<u64, u32>,
}

impl History {
    fn of(v: &Value) -> History {
        History {
            work: v["share_work"].as_object().unwrap().iter().map(|(n, m)| (n.parse().unwrap(), kmap(m))).collect(),
            bits: v["first_block_bits"].as_object().unwrap().iter()
                .map(|(n, b)| (n.parse().unwrap(), b.as_u64().unwrap() as u32)).collect(),
        }
    }
}

fn advance(led: &CapLedger, h: &History, to: u64, (el, win): (u64, u64), excluded: &dyn Fn(&KeyId, u64) -> bool)
    -> (CapLedger, Vec<Option<StepResult>>)
{
    let mut steps = Vec::new();
    let next = led.advance_traced(to, el, win, GROWTH_DIV, G_MIN_DIV, &|n| h.work.get(&n), &|n| h.bits.get(&n).copied(),
                                  excluded, &mut |_, r| steps.push(r.cloned()))
        .unwrap();
    let plain = led.advance(to, el, win, GROWTH_DIV, G_MIN_DIV, &|n| h.work.get(&n), &|n| h.bits.get(&n).copied(),
                            excluded).unwrap();
    assert_eq!(plain, next, "advance and advance_traced agree");
    (next, steps)
}

#[test]
fn sequence_vectors() {
    let d = doc();
    let cases = d["sequences"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let p = params(c["params"].as_str().unwrap());
        let hist = History::of(&c["history"]);
        let excl: Vec<(KeyId, u64, u64)> = c["exclusions"].as_array().unwrap().iter()
            .map(|e| (key(e[0].as_str().unwrap()), e[1].as_u64().unwrap(), e[2].as_u64().unwrap())).collect();
        let excluded = |k: &KeyId, x: u64| excl.iter().any(|(ek, lo, hi)| ek == k && *lo <= x && x < *hi);
        let mut led = CapLedger::empty();
        for h in c["handoffs"].as_array().unwrap() {
            let to = h["to_epoch"].as_u64().unwrap();
            let (next, reps) = advance(&led, &hist, to, p, &excluded);
            let want = h["steps"].as_array().unwrap();
            assert_eq!(reps.len(), want.len(), "{name} -> {to}: steps");
            for (i, (r, w)) in reps.iter().zip(want).enumerate() {
                match r {
                    None => assert!(w.is_null(), "{name} -> {to}: step {i}"),
                    Some(r) => check_step(r, w, &format!("{name} -> {to}: step {i}")),
                }
            }
            let credits: BTreeMap<u64, EpochMap> = h["credits"].as_object().unwrap().iter()
                .map(|(n, m)| (n.parse().unwrap(), kmap(m))).collect();
            let got: BTreeMap<u64, EpochMap> = next.credits().iter().map(|(n, m)| (*n, (**m).clone())).collect();
            assert_eq!(got, credits, "{name} -> {to}: credits");
            assert_eq!(next.epoch(), to);
            let cfg: Vec<(KeyId, u128)> = h["configuration"].as_array().unwrap().iter()
                .map(|e| (key(e[0].as_str().unwrap()), u128s(&e[1]))).collect();
            let mine: Vec<(KeyId, u128)> = next.configuration(&excluded).into_iter().collect();
            assert_eq!(mine, cfg, "{name} -> {to}: configuration");
            let total = mine.iter().fold(0u128, |a, (_, w)| a.saturating_add(*w));
            assert_eq!(total, u128s(&h["total"]), "{name} -> {to}: total");
            led = next;
        }
    }
}

#[test]
fn the_window_only_moves_forward() {
    let led = CapLedger::from_parts(5, BTreeMap::new(), None);
    let none = |_: u64| -> Option<&EpochMap> { None };
    assert!(led.advance(4, 20, 3, GROWTH_DIV, G_MIN_DIV, &none, &|_| None, &|_, _| false).is_err());
    let same = led.advance(5, 20, 3, GROWTH_DIV, G_MIN_DIV, &none, &|_| None, &|_, _| false).unwrap();
    assert_eq!(same, led);
}

// ── Floods ───────────────────────────────────────────────────────────────────

/// Reference `key(label, i)`.
fn ref_key(label: &str, i: u32) -> KeyId {
    let mut h = Sha3_256::new();
    h.update(b"obb-growth-cap-key");
    h.update(label.as_bytes());
    h.update(i.to_le_bytes());
    h.finalize()[..20].try_into().unwrap()
}

const EASY_BITS: u32 = 0x207F_FFFF;

struct FloodStep {
    epoch: u64,
    total: u128,
    attacker: u128,
    honest: Vec<u128>,
    report: StepResult,
}

/// Reference `flood_scenario`: honest-only weight at steady state over the
/// full window (10 keys credit 1,000,000 each epoch), then from epoch x0 an
/// attacker brings `k` times the honest share work on 5 new keys.
fn flood(k: u128, epochs: u64) -> (Vec<FloodStep>, Vec<KeyId>, Vec<KeyId>) {
    let (el, win) = params("obenblock");
    let per_key: u128 = 1_000_000;
    let honest: Vec<KeyId> = (0..10).map(|i| ref_key("honest", i)).collect();
    let attacker: Vec<KeyId> = (0..5).map(|i| ref_key(&format!("attacker-{k}"), i)).collect();
    let x0 = win + 2;
    let steady: Arc<EpochMap> = Arc::new(honest.iter().map(|h| (*h, per_key)).collect());
    let mut led = CapLedger::from_parts(x0 - 1, (0..win).map(|n| (n, steady.clone())).collect(), None);
    let attack_per_key = k * per_key * honest.len() as u128 / attacker.len() as u128;
    let mut hist = History { work: BTreeMap::new(), bits: BTreeMap::new() };
    for n in 0..x0 + epochs {
        let mut m: EpochMap = honest.iter().map(|h| (*h, per_key)).collect();
        if n >= x0 - 2 {
            m.extend(attacker.iter().map(|a| (*a, attack_per_key)));
        }
        hist.work.insert(n, m);
        hist.bits.insert(n, EASY_BITS);
    }
    let mut trace = Vec::new();
    for x in x0..x0 + epochs {
        let (next, mut reps) = advance(&led, &hist, x, (el, win), &|_, _| false);
        led = next;
        let w = led.weights();
        trace.push(FloodStep {
            epoch: x,
            total: w.values().sum(),
            attacker: attacker.iter().map(|a| w.get(a).copied().unwrap_or(0)).sum(),
            honest: honest.iter().map(|h| w.get(h).copied().unwrap_or(0)).collect(),
            report: reps.pop().unwrap().unwrap(),
        });
    }
    (trace, honest, attacker)
}

/// Epochs (from the attack's first step, 1-based) until the attacker holds
/// strictly more than two thirds, if ever in the trace.
fn first_strict_two_thirds(trace: &[FloodStep]) -> Option<usize> {
    trace.iter().position(|s| 3 * s.attacker > 2 * s.total).map(|i| i + 1)
}

#[test]
fn flood_vectors_k_2_10_100() {
    let d = doc();
    let cases = d["floods"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let k = c["k"].as_u64().unwrap() as u128;
        let (trace, honest, _) = flood(k, 130);
        let want = c["epochs_to_strict_two_thirds"].as_u64().map(|v| v as usize);
        assert_eq!(first_strict_two_thirds(&trace), want, "k = {k}");
        let rows = c["trace"].as_array().unwrap();
        assert_eq!(rows.len(), 75);
        for (s, w) in trace.iter().zip(rows) {
            assert_eq!(s.epoch, w["epoch"].as_u64().unwrap());
            assert_eq!(s.total, u128s(&w["total"]), "k = {k}, epoch {}", s.epoch);
            assert_eq!(s.attacker, u128s(&w["attacker"]), "k = {k}, epoch {}", s.epoch);
            assert_eq!(U256::from(s.report.g), u256s(&w["g"]));
            assert_eq!(s.report.admitted_new, u256s(&w["admitted_new"]));
            assert_eq!(s.report.dropped, u256s(&w["dropped"]));
        }
        // Honest keys that keep mining keep their weight throughout (renewal first).
        let (_, win) = params("obenblock");
        for s in &trace {
            assert!(s.honest.iter().all(|w| *w == win as u128 * 1_000_000), "k = {k}, epoch {}", s.epoch);
        }
        assert_eq!(honest.len(), 10);
    }
    // §6.3 "Measured": k = 2 never, k = 10 and k = 100 after exactly 71 epochs.
    assert_eq!(first_strict_two_thirds(&flood(2, 130).0), None);
    assert_eq!(first_strict_two_thirds(&flood(10, 130).0), Some(71));
    assert_eq!(first_strict_two_thirds(&flood(100, 130).0), Some(71));
}

/// The bound of §6.3: whatever the rented hashrate, new keys never hold
/// strictly more than two thirds of W before 71 epochs, and while the
/// attack runs the weight of the new keys grows by at most G per epoch.
#[test]
fn no_flood_owns_two_thirds_before_71_epochs() {
    for k in [1u128, 2, 3, 5, 10, 100, 1_000, 1_000_000, 1u128 << 64] {
        let (trace, _, _) = flood(k, 80);
        if let Some(t) = first_strict_two_thirds(&trace) {
            assert!(t >= epochs_to_grow(3, 1) as usize, "k = {k}: {t} epochs");
        }
        let mut prev_att = 0u128;
        for s in &trace {
            assert!(s.attacker - prev_att <= s.report.g, "k = {k}, epoch {}", s.epoch);
            assert!(s.report.admitted_new <= U256::from(s.report.g));
            prev_att = s.attacker;
        }
    }
}

#[test]
fn launch_vector() {
    let d = doc();
    let l = &d["launch"];
    let p = params("obenblock");
    let bits = l["bits"].as_u64().unwrap() as u32;
    assert_eq!(share_work(bits), u128s(&l["share_work"]));
    let gm = g_min(p.0, bits);
    assert_eq!(gm, u128s(&l["g_min"]));
    let full = 8 * gm;
    assert_eq!(full, u128s(&l["work_per_epoch"]));
    let keys: Vec<KeyId> = (0..4).map(|i| ref_key("launch", i)).collect();
    let hist = History {
        work: (0..80).map(|n| (n, keys.iter().map(|k| (*k, full / 4)).collect())).collect(),
        bits: (0..80).map(|n| (n, bits)).collect(),
    };
    let mut led = CapLedger::empty();
    let rows = l["steps"].as_array().unwrap();
    assert_eq!(rows.len(), 78);
    for (x, w) in (2..80u64).zip(rows) {
        let (next, mut reps) = advance(&led, &hist, x, p, &|_, _| false);
        led = next;
        let r = reps.pop().unwrap().unwrap();
        assert_eq!(w["epoch"].as_u64(), Some(x));
        assert_eq!(r.w, u128s(&w["w"]), "launch x = {x}");
        assert_eq!(r.g, u128s(&w["g"]), "launch x = {x}");
        assert_eq!(r.admitted, u256s(&w["admitted"]), "launch x = {x}");
        let total = led.configuration(&|_, _| false).values().fold(0u128, |a, w| a.saturating_add(*w));
        assert_eq!(total, u128s(&w["total"]), "launch x = {x}");
    }
}
