//! ObenBlock liveness (`docs/DESIGN-obenblock.md` §5) against the executable
//! reference (`reference/obb_liveness.py` -> `reference/liveness_vectors.json`):
//! the stall relief alone and composed with ASERT, the half and 1/16 decay,
//! the leak schedule of the design's table, the exit message byte for byte,
//! the exit epoch window, and `W(e)` with exits and the half leak.

use gnb_crypto::core::kes::KesPublic;
use gnb_crypto::core::liveness;
use gnb_crypto::core::powit::{self, InactivityLeak, KeyId, PowitState, Regime};
use gnb_smh::difficulty::{bits_to_target, AsertAnchor, AsertParams};
use gnb_smh::stall_relief::{relief_steps, relieved_bits, OBENBLOCK_STALL_RELIEF as P};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/liveness_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

fn i(v: &Value) -> i64 {
    v.as_i64().unwrap()
}

fn u128s(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn key(s: &str) -> KeyId {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn leak(s: &str) -> InactivityLeak {
    match s {
        "half" => InactivityLeak::Half,
        "sixteenth" => InactivityLeak::Sixteenth,
        other => panic!("unknown leak {other}"),
    }
}

#[test]
fn constants_match() {
    let d = doc();
    let c = &d["constants"];
    assert_eq!(u(&c["grace_secs"]) as i64, P.grace_secs);
    assert_eq!(u(&c["step_secs"]) as i64, P.step_secs);
    assert_eq!(u(&c["relief_halflife"]) as i64, P.halflife_secs);
    assert_eq!(u(&c["max_exits_per_block"]) as usize, liveness::MAX_EXITS_PER_BLOCK);
}

#[test]
fn stall_relief_matches() {
    let d = doc();
    let cases = d["relief"].as_array().unwrap();
    assert!(cases.len() >= 90);
    for c in cases {
        let (pt, t) = (i(&c["parent_time"]), i(&c["time"]));
        let limit = bits_to_target(u(&c["pow_limit_bits"]) as u32);
        assert_eq!(relief_steps(&P, pt, t), u(&c["steps"]), "{c}");
        assert_eq!(relieved_bits(&P, u(&c["base_bits"]) as u32, pt, t, &limit), u(&c["bits"]) as u32, "{c}");
    }
}

#[test]
fn asert_with_relief_matches() {
    let d = doc();
    let b = &d["blocks"];
    let limit = bits_to_target(u(&b["pow_limit_bits"]) as u32);
    let params = AsertParams { target_spacing: 30, halflife: 7_200, pow_limit: limit };
    let anchor = AsertAnchor { height: 0, bits: u(&b["anchor_bits"]) as u32, timestamp: i(&b["anchor_time"]) };
    for c in b["cases"].as_array().unwrap() {
        let (h, pt, t, lh) = (u(&c["height"]), i(&c["parent_time"]), i(&c["time"]), u(&c["liveness_height"]));
        let base = gnb_smh::difficulty::asert_next_bits(&params, &anchor, pt, h).unwrap();
        assert_eq!(base, u(&c["asert_bits"]) as u32, "{c}");
        let bits = if h >= lh { relieved_bits(&P, base, pt, t, &limit) } else { base };
        assert_eq!(bits, u(&c["bits"]) as u32, "{c}");
    }
}

#[test]
fn decay_and_leak_schedule_match() {
    let d = doc();
    for c in d["decayed"].as_array().unwrap() {
        let (w, n) = (u128s(&c["weight"]), u(&c["steps"]) as u32);
        assert_eq!(powit::decayed_with(InactivityLeak::Half, w, n), u128s(&c["half"]), "{c}");
        assert_eq!(powit::decayed_with(InactivityLeak::Sixteenth, w, n), u128s(&c["sixteenth"]), "{c}");
    }
    // The design's table (24 h + 6 h per halving, 6-hour epochs, worst phase):
    // 50 % -> 30 h, 90 % -> 54 h, 99 % -> 72 h; GnB's 1/16 never recovers 99 %.
    let rows = d["leak_schedule"]["rows"].as_array().unwrap();
    let worst = |pct: u64, l: &str| {
        rows.iter().find(|r| u(&r["absent_pct"]) == pct).unwrap()["resume"][l]["worst_epoch"].as_u64()
    };
    assert_eq!(worst(50, "half"), Some(5));
    assert_eq!(worst(90, "half"), Some(9));
    assert_eq!(worst(99, "half"), Some(12));
    assert_eq!(worst(99, "sixteenth"), None);
    // The same schedule from the Rust decay and threshold.
    let p = powit::MAINNET_PARAMS;
    for r in rows {
        let pct = u(&r["absent_pct"]) as u128;
        let (absent, present) = (pct * 10u128.pow(16), (100 - pct) * 10u128.pow(16));
        for l in ["half", "sixteenth"] {
            for (phase, field) in [(0u64, "best_epoch"), (p.epoch_len - 1, "worst_epoch")] {
                let (mut steps, mut n) = (0u32, 0u64);
                let got = loop {
                    if powit::two_thirds(present, present + powit::decayed_with(leak(l), absent, steps)) {
                        break Some(n);
                    }
                    n += 1;
                    if n * p.epoch_len - phase >= p.leak_after_epochs * p.epoch_len {
                        steps += 1;
                    }
                    if steps > 129 {
                        break None;
                    }
                };
                assert_eq!(got, r["resume"][l][field].as_u64(), "{r} {l} {field}");
            }
        }
    }
}

#[test]
fn exit_messages_match_byte_for_byte() {
    let d = doc();
    for m in d["exit_messages"].as_array().unwrap() {
        let root: [u8; 32] = hex::decode(m["root"].as_str().unwrap()).unwrap().try_into().unwrap();
        let w = KesPublic { depth: u(&m["depth"]) as u8, root };
        let chain = u(&m["chain_id"]) as u32;
        let epoch = u(&m["epoch"]);
        let pre = hex::decode(m["preimage"].as_str().unwrap()).unwrap();
        assert_eq!(pre.len(), 66);
        let msg = liveness::exit_message_raw(chain, &w, epoch);
        assert_eq!(<[u8; 32]>::from(Sha3_256::digest(&pre)), msg);
        assert_eq!(hex::encode(msg), m["message"].as_str().unwrap());
        assert_eq!(hex::encode(w.witness_id()), m["witness_id"].as_str().unwrap());
    }
    for e in d["exit_epochs"].as_array().unwrap() {
        assert_eq!(liveness::exit_epoch_ok(u(&e["block_epoch"]), u(&e["exit_epoch"])), e["ok"].as_bool().unwrap(), "{e}");
    }
}

#[test]
fn witness_sets_with_exits_match() {
    let d = doc();
    let ws = &d["witness_sets"];
    let s = &ws["state"];
    let mut st = PowitState::genesis(0, [0; 32]);
    for (e, m) in s["epoch_work"].as_object().unwrap() {
        for (k, w) in m.as_object().unwrap() {
            st.epoch_work.entry(e.parse().unwrap()).or_default().insert(key(k), u128s(w));
        }
    }
    for (k, until) in s["banned"].as_object().unwrap() {
        st.banned.insert(key(k), u(until));
    }
    for (k, n) in s["decay"].as_object().unwrap() {
        st.decay.insert(key(k), u(n) as u32);
    }
    for (k, from) in s["exited"].as_object().unwrap() {
        st.exited.insert(key(k), u(from));
    }
    for c in ws["cases"].as_array().unwrap() {
        let p = powit::PowitParams { leak: leak(c["leak"].as_str().unwrap()), ..powit::TESTNET_PARAMS };
        let e = u(&c["epoch"]);
        let got: Vec<(String, String)> = st.witness_set_in(&p, e, Regime::Hardening2).iter()
            .map(|(k, w)| (hex::encode(k), w.to_string())).collect();
        let want: Vec<(String, String)> = c["set"].as_array().unwrap().iter()
            .map(|x| (x[0].as_str().unwrap().to_string(), x[1].as_str().unwrap().to_string())).collect();
        assert_eq!(got, want, "{c}");
        for (k, w) in &want {
            assert_eq!(st.member_weight_h2(&p, e, &key(k)), Some(w.parse().unwrap()));
        }
        let total = want.iter().fold(0u128, |a, (_, w)| a.saturating_add(w.parse().unwrap()));
        assert_eq!(st.total_weight_h2(&p, e), total);
    }
}
