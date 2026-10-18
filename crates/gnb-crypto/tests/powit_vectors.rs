//! PoWit messages, witness sets, justification threshold and evidence rule
//! against the executable reference (`reference/powit_reference.py` ->
//! `reference/powit_vectors.json`; PoWit audit findings 1 and 4, second
//! hardening activation): the v1 and v2 attestation messages byte for byte,
//! the witness id, the regime boundary, the inactivity decay, the two-thirds
//! rule, `W(e)` under both regimes (cap, window, bans, decay, saturation),
//! the evidence epochs, and the finding's numbers.

use gnb_crypto::core::kes::KesPublic;
use gnb_crypto::core::powit::{self, Checkpoint, KeyId, PowitParams, PowitState, Regime};
use gnb_crypto::core::ChainId;
use serde_json::Value;
use sha3::{Digest, Sha3_256};

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/powit_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

fn u128s(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn key(s: &str) -> KeyId {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn chain(v: &Value) -> ChainId {
    match u(v) {
        0x474E_0001 => ChainId::Mainnet,
        0x474E_0002 => ChainId::Testnet,
        other => panic!("unknown chain id {other:#x}"),
    }
}

fn params(name: &str) -> PowitParams {
    match name {
        "mainnet" => powit::MAINNET_PARAMS,
        "testnet" => powit::TESTNET_PARAMS,
        other => panic!("unknown params {other}"),
    }
}

fn cp(v: &Value) -> Checkpoint {
    Checkpoint { height: u(&v["height"]), hash: h32(&v["hash"]) }
}

fn regime(s: &str) -> Regime {
    match s {
        "v1" => Regime::V1,
        "hardening2" => Regime::Hardening2,
        other => panic!("unknown regime {other}"),
    }
}

fn state(v: &Value) -> PowitState {
    // Finding 3: the PoWit activation and the finalized checkpoint's slot
    // (the window of a `Regime::Hardening2` set ends below it).
    let act = v.get("activation").map_or(0, u);
    let mut st = PowitState::genesis(act, [0; 32]);
    if let Some(f) = v.get("finalized_height") {
        st.finalized.height = u(f);
    }
    for (e, m) in v["epoch_work"].as_object().unwrap() {
        let e: u64 = e.parse().unwrap();
        for (k, w) in m.as_object().unwrap() {
            st.epoch_work.entry(e).or_default().insert(key(k), u128s(w));
        }
    }
    for (k, until) in v["banned"].as_object().unwrap() {
        st.banned.insert(key(k), u(until));
    }
    for (k, d) in v["decay"].as_object().unwrap() {
        st.decay.insert(key(k), u(d) as u32);
    }
    st
}

fn set_json(ws: &[(KeyId, u128)]) -> Vec<(String, String)> {
    ws.iter().map(|(k, w)| (hex::encode(k), w.to_string())).collect()
}

fn json_set(v: &Value) -> Vec<(String, String)> {
    v.as_array().unwrap().iter()
        .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_str().unwrap().to_string()))
        .collect()
}

fn total(ws: &[(KeyId, u128)]) -> u128 {
    ws.iter().fold(0u128, |a, (_, w)| a.saturating_add(*w))
}

#[test]
fn constants_and_parameters_match() {
    let d = doc();
    let c = &d["constants"];
    assert_eq!(u(&c["chain_mainnet"]), u64::from(ChainId::Mainnet.to_u32()));
    assert_eq!(u(&c["chain_testnet"]), u64::from(ChainId::Testnet.to_u32()));
    assert_eq!(u(&c["never"]), gnb_crypto::core::activation::NEVER);
    assert_eq!(c["v2_preimage_len"].as_u64(), Some(140));
    for name in ["mainnet", "testnet"] {
        let p = params(name);
        let j = &c["params"][name];
        assert_eq!(
            [p.epoch_len, p.checkpoint_interval, p.window_epochs, p.max_witnesses as u64,
             p.max_attestations_per_block as u64, p.max_evidence_per_block as u64, p.vote_ttl,
             p.leak_after_epochs, p.ban_epochs],
            ["epoch_len", "checkpoint_interval", "window_epochs", "max_witnesses", "max_attestations_per_block",
             "max_evidence_per_block", "vote_ttl", "leak_after_epochs", "ban_epochs"].map(|f| u(&j[f])),
            "{name}"
        );
    }
}

#[test]
fn attestation_messages_match_byte_for_byte() {
    let d = doc();
    let msgs = d["messages"].as_array().unwrap();
    assert!(msgs.len() >= 24);
    for m in msgs {
        let ch = chain(&m["chain_id"]);
        let w = KesPublic { depth: m["depth"].as_u64().unwrap() as u8, root: h32(&m["root"]) };
        let (src, tgt) = (cp(&m["source"]), cp(&m["target"]));
        let h2 = u(&m["hardening2_height"]);
        assert_eq!(hex::encode(powit::attestation_message(ch, &src, &tgt)), m["v1"].as_str().unwrap());
        let pre = hex::decode(m["v2_preimage"].as_str().unwrap()).unwrap();
        assert_eq!(pre.len(), 140);
        let v2 = powit::attestation_message_v2(ch, &w, &src, &tgt);
        assert_eq!(hex::encode(v2), m["v2"].as_str().unwrap());
        assert_eq!(<[u8; 32]>::from(Sha3_256::digest(&pre)), v2, "the v2 digest is SHA3 of the spelled-out preimage");
        assert_eq!(hex::encode(powit::attestation_message_at(ch, h2, &w, &src, &tgt)),
                   m["message_at"].as_str().unwrap(), "h2={h2}");
        assert_eq!(hex::encode(w.witness_id()), m["witness_id"].as_str().unwrap());
    }
}

#[test]
fn regime_decay_and_threshold_match() {
    let d = doc();
    for r in d["regimes"].as_array().unwrap() {
        assert_eq!(Regime::at(u(&r["height"]), u(&r["hardening2_height"])), regime(r["regime"].as_str().unwrap()), "{r}");
    }
    for v in d["decayed"].as_array().unwrap() {
        assert_eq!(powit::decayed(u128s(&v["weight"]), u(&v["steps"]) as u32), u128s(&v["decayed"]), "{v}");
    }
    for v in d["two_thirds"].as_array().unwrap() {
        assert_eq!(powit::two_thirds(u128s(&v["got"]), u128s(&v["total"])), v["justifies"].as_bool().unwrap(), "{v}");
    }
}

#[test]
fn witness_sets_and_the_evidence_rule_match() {
    let d = doc();
    for case in d["witness_sets"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let p = params(case["params"].as_str().unwrap());
        let st = state(&case["state"]);
        for e in case["epochs"].as_array().unwrap() {
            let epoch = u(&e["epoch"]);
            let v1 = st.witness_set_in(&p, epoch, Regime::V1);
            let h2 = st.witness_set_in(&p, epoch, Regime::Hardening2);
            assert_eq!(v1, st.witness_set(&p, epoch), "witness_set is the V1 set");
            assert_eq!(set_json(&v1), json_set(&e["v1"]), "{name} epoch {epoch} v1");
            assert_eq!(set_json(&h2), json_set(&e["hardening2"]), "{name} epoch {epoch} hardening2");
            assert_eq!(total(&v1), u128s(&e["total_v1"]), "{name} epoch {epoch}");
            assert_eq!(total(&h2), u128s(&e["total_hardening2"]), "{name} epoch {epoch}");
            assert_eq!(st.total_weight_h2(&p, epoch), u128s(&e["total_hardening2"]), "{name} epoch {epoch}");
            for (k, w) in &h2 {
                assert_eq!(st.member_weight_h2(&p, epoch, k), Some(*w), "{name} epoch {epoch}");
            }
        }
        for ev in case["evidence"].as_array().unwrap() {
            let (epoch, k) = (u(&ev["block_epoch"]), key(ev["key"].as_str().unwrap()));
            assert_eq!(st.may_be_proven_h2(&p, epoch, &k), ev["may_be_proven"].as_bool().unwrap(), "{name} {ev}");
            let epochs: Vec<u64> = PowitState::evidence_epochs(epoch).collect();
            let want: Vec<u64> = ev["member_weights"].as_object().unwrap().keys().map(|x| x.parse().unwrap()).collect();
            let mut want_sorted = want.clone();
            want_sorted.sort();
            assert_eq!(epochs, want_sorted, "{name}: evidence epochs");
            for (x, w) in ev["member_weights"].as_object().unwrap() {
                let x: u64 = x.parse().unwrap();
                let want = w.as_str().map(|s| s.parse::<u128>().unwrap());
                assert_eq!(st.member_weight_h2(&p, x, &k), want, "{name} {ev} epoch {x}");
            }
        }
    }
}

/// PoWit audit finding 4 in numbers (the reference's verdicts): under the old
/// rule the 30% attacker justifies alone and the honest 70% cannot; from
/// hardening 2 neither the attacker alone nor its abstention decides.
#[test]
fn finding4_numbers_match() {
    let d = doc();
    let case = d["witness_sets"].as_array().unwrap().iter().find(|c| c["name"] == "finding4").unwrap();
    let st = state(&case["state"]);
    let p = powit::TESTNET_PARAMS;
    for (r, name) in [(Regime::V1, "v1"), (Regime::Hardening2, "hardening2")] {
        let f = &d["finding4"][name];
        let ws = st.witness_set_in(&p, 2, r);
        let t = total(&ws);
        assert_eq!(ws.len() as u64, u(&f["members"]));
        assert_eq!(t, u128s(&f["total"]));
        let attacker: u128 = ws.iter().filter(|(_, w)| *w == 50).map(|(_, w)| *w).sum();
        let honest: u128 = ws.iter().filter(|(_, w)| *w == 35).map(|(_, w)| *w).sum();
        assert_eq!(attacker, u128s(&f["attacker_weight_in_w"]));
        assert_eq!(honest, u128s(&f["honest_weight_in_w"]));
        assert_eq!(powit::two_thirds(attacker, t), f["attacker_alone_justifies"].as_bool().unwrap(), "{name}");
        assert_eq!(powit::two_thirds(honest, t), f["honest_alone_justify"].as_bool().unwrap(), "{name}");
    }
    assert!(!d["finding4"]["hardening2"]["attacker_alone_justifies"].as_bool().unwrap());
    assert!(d["finding4"]["hardening2"]["honest_alone_justify"].as_bool().unwrap());
    assert_eq!(d["finding4"]["hardening2"]["honest_voters_needed"].as_u64(), Some(191));
}
