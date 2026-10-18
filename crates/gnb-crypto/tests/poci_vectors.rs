//! PoCI against its normative reference (`reference/poci_reference.py` ->
//! `reference/poci_vectors.json`, docs/DESIGN-obenblock-poci.md): parameter
//! digests, configurations, registry Merkle trees and paths, v3 messages, the
//! strict quorum, evidence verdicts, the FFG + handoff + ban sequences and
//! the finality certificates (with and without registry proofs), every case.
//!
//! The vectors sign with the reference's test scheme (`sig = sha256d(
//! "OBB-POCI-test/sig" ‖ u8(depth) ‖ root ‖ u64le(epoch(target)) ‖ msg_v3)`,
//! encoded `varint(len) ‖ bytes` in certificates), plugged in here as a
//! [`VoteScheme`]; `poci_kes.rs` checks the same code with real KES keys.

use std::collections::BTreeMap;

use gnb_crypto::core::kes::KesPublic;
use gnb_crypto::core::powit::poci::{
    self, attestation_message_v3, attestation_message_v3_preimage, check_entries, check_evidence, counted_weight,
    ffg_step, leaf_hash, merkle_path, path_root, quorum, tree_root, verify_certificate,
    verify_certificate_with_proof, Configuration, DecodeError, PociParams, PociState, PociVote, Reader,
    RegistryProof, VoteScheme, OBB_MAINNET_POCI, OBB_REGTEST_POCI,
};
use gnb_crypto::core::powit::{two_thirds, Checkpoint, KeyId};
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/poci_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

fn u128s(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

fn key(v: &Value) -> KeyId {
    bytes(v).try_into().unwrap()
}

fn cp(v: &Value) -> Checkpoint {
    Checkpoint { height: u(&v["height"]), hash: h32(&v["hash"]) }
}

fn params(name: &str) -> PociParams {
    match name {
        "mainnet" => OBB_MAINNET_POCI,
        "regtest" => OBB_REGTEST_POCI,
        other => panic!("unknown params {other}"),
    }
}

fn entries(v: &Value) -> Vec<(KeyId, u128)> {
    v.as_array().unwrap().iter().map(|e| (key(&e[0]), u128s(&e[1]))).collect()
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    poci::sha256d(b)
}

// ── The reference's test signature scheme ────────────────────────────────────

struct TestSig;

fn test_sign(k: &KesPublic, kes_epoch: u64, msg: &[u8; 32]) -> Vec<u8> {
    let mut m = b"OBB-POCI-test/sig".to_vec();
    m.push(k.depth);
    m.extend_from_slice(&k.root);
    m.extend_from_slice(&kes_epoch.to_le_bytes());
    m.extend_from_slice(msg);
    sha256d(&m).to_vec()
}

impl VoteScheme for TestSig {
    type Sig = Vec<u8>;

    fn verify(k: &KesPublic, kes_epoch: u64, msg: &[u8; 32], sig: &Vec<u8>) -> bool {
        *sig == test_sign(k, kes_epoch, msg)
    }

    fn write_sig(sig: &Vec<u8>, out: &mut Vec<u8>) {
        poci::write_varint(out, sig.len() as u64);
        out.extend_from_slice(sig);
    }

    fn read_sig(r: &mut Reader<'_>) -> Result<Vec<u8>, DecodeError> {
        let n = r.varint()?;
        Ok(r.take(usize::try_from(n).map_err(|_| DecodeError::Truncated)?)?.to_vec())
    }
}

fn kes_key(v: &Value) -> KesPublic {
    KesPublic { depth: u(&v["depth"]) as u8, root: h32(&v["root"]) }
}

fn vote(v: &Value) -> PociVote<TestSig> {
    let k = kes_key(v);
    assert_eq!(k.witness_id(), key(&v["key_id"]), "key id = witness_id(depth, root)");
    PociVote { config_id: h32(&v["config_id"]), witness: k, source: cp(&v["source"]), target: cp(&v["target"]),
               sig: bytes(&v["sig"]) }
}

fn sign(p: &PociParams, config_id: [u8; 32], k: KesPublic, source: Checkpoint, target: Checkpoint)
    -> PociVote<TestSig>
{
    let msg = attestation_message_v3(p.chain_id, &config_id, &k, &source, &target);
    PociVote { config_id, witness: k, source, target, sig: test_sign(&k, p.epoch_of(target.height), &msg) }
}

fn config_json_check(p: &PociParams, c: &Configuration, v: &Value) {
    assert_eq!(c.epoch(), u(&v["epoch"]));
    assert_eq!(c.entries(), entries(&v["entries"]).as_slice());
    assert_eq!(c.total(), u128s(&v["total"]));
    assert_eq!(c.tree_root(), h32(&v["tree_root"]));
    assert_eq!(c.merkle_root(), h32(&v["merkle_root"]));
    assert_eq!(c.preimage(), bytes(&v["preimage"]));
    assert_eq!(c.id(), h32(&v["config_id"]));
    assert_eq!(c.chain_id(), p.chain_id);
}

fn config_of(v: &Value) -> (PociParams, Configuration) {
    let p = params(v["params"].as_str().unwrap());
    let c = Configuration::new(&p, u(&v["epoch"]), entries(&v["entries"])).unwrap();
    config_json_check(&p, &c, v);
    (p, c)
}

// ── Constants and parameters ─────────────────────────────────────────────────

#[test]
fn constants() {
    let d = doc();
    assert_eq!(d["format"], "obb-poci-vectors-v1");
    let c = &d["constants"];
    assert_eq!(u(&c["chain_obb_mainnet"]), u64::from(OBB_MAINNET_POCI.chain_id));
    assert_eq!(u(&c["chain_obb_regtest"]), u64::from(OBB_REGTEST_POCI.chain_id));
    for (name, val) in [("ds_params", poci::DS_PARAMS), ("ds_config", poci::DS_CONFIG), ("ds_leaf", poci::DS_LEAF),
                        ("ds_node", poci::DS_NODE), ("ds_root", poci::DS_ROOT), ("ds_attest_v3", poci::DS_ATTEST_V3)] {
        assert_eq!(c[name].as_str().unwrap().as_bytes(), val, "{name}");
    }
    assert_eq!(u(&c["certificate_version"]), u64::from(poci::CERT_VERSION));
    assert_eq!(u(&c["v3_preimage_len"]) as usize, poci::V3_PREIMAGE_LEN);
    assert_eq!(u(&c["config_preimage_len"]) as usize, poci::CONFIG_PREIMAGE_LEN);
    assert_eq!(u(&c["params_preimage_len"]) as usize, poci::PARAMS_PREIMAGE_LEN);
}

#[test]
fn params_digests() {
    let d = doc();
    let list = d["params"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    for v in list {
        let p = params(v["params"].as_str().unwrap());
        let vals = &v["values"];
        let want = PociParams {
            chain_id: u(&vals["chain_id"]) as u32,
            epoch_len: u(&vals["epoch_len"]),
            checkpoint_interval: u(&vals["checkpoint_interval"]),
            window_epochs: u(&vals["window_epochs"]),
            vote_ttl: u(&vals["vote_ttl"]),
            max_attestations_per_block: u(&vals["max_attestations_per_block"]),
            max_evidence_per_block: u(&vals["max_evidence_per_block"]),
            ban_epochs: u(&vals["ban_epochs"]),
            bootstrap_epochs: u(&vals["bootstrap_epochs"]),
            growth_div: u(&vals["growth_div"]),
            g_min_epoch_div: u(&vals["g_min_epoch_div"]),
            quorum_num: u(&vals["quorum_num"]) as u32,
            quorum_den: u(&vals["quorum_den"]) as u32,
        };
        assert_eq!(p, want);
        assert_eq!(p.preimage(), bytes(&v["preimage"]));
        assert_eq!(p.digest(), h32(&v["params_digest"]));
    }
}

// ── Configurations and the registry tree ─────────────────────────────────────

#[test]
fn configurations_and_paths() {
    let d = doc();
    let mut valid = 0;
    for v in d["configs"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        if let Some(reason) = v.get("invalid") {
            let got = check_entries(&entries(&v["entries"])).map(|_| ()).map_err(|e| e.as_str());
            assert_eq!(got, Err(reason.as_str().unwrap()), "{name}");
            assert!(Configuration::new(&OBB_MAINNET_POCI, 4, entries(&v["entries"])).is_err(), "{name}");
            continue;
        }
        valid += 1;
        let (p, c) = config_of(v);
        // The candidate-weights constructor gives the same configuration.
        let w: BTreeMap<KeyId, u128> = c.entries().iter().copied().collect();
        assert_eq!(Configuration::from_weights(&p, c.epoch(), &w).unwrap(), c, "{name}");
        // Serde re-validates and recomputes the derived fields.
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Configuration>(&json).unwrap(), c, "{name}");
        assert_eq!(tree_root(c.entries()), c.tree_root());
        let n = c.len() as u32;
        for pv in v["paths"].as_array().unwrap() {
            let i = u(&pv["index"]) as usize;
            let (k, w) = c.entries()[i];
            let leaf = leaf_hash(&k, w);
            assert_eq!(leaf, h32(&pv["leaf"]), "{name} leaf {i}");
            let path: Vec<[u8; 32]> = pv["path"].as_array().unwrap().iter().map(h32).collect();
            assert_eq!(merkle_path(c.entries(), i).unwrap(), path, "{name} path {i}");
            assert_eq!(path_root(&leaf, i as u32, n, &path), Some(c.tree_root()), "{name} path {i}");
            // Wrong shapes prove nothing.
            assert_eq!(path_root(&leaf, n, n, &path), None);
            if !path.is_empty() {
                assert_eq!(path_root(&leaf, i as u32, n, &path[..path.len() - 1]), None);
            }
            let mut long = path.clone();
            long.push([0; 32]);
            assert_eq!(path_root(&leaf, i as u32, n, &long), None);
        }
        assert_eq!(v["paths"].as_array().unwrap().len(), c.len());
    }
    assert_eq!(valid, 9);
    // A forged serde encoding (unsorted entries) is refused.
    let (k1, k2) = ([1u8; 20], [2u8; 20]);
    let bad = serde_json::json!({"chain_id": OBB_MAINNET_POCI.chain_id, "epoch": 4,
        "params_digest": OBB_MAINNET_POCI.digest(), "entries": [[k2, 1], [k1, 1]]});
    let good = serde_json::json!({"chain_id": OBB_MAINNET_POCI.chain_id, "epoch": 4,
        "params_digest": OBB_MAINNET_POCI.digest(), "entries": [[k1, 1], [k2, 1]]});
    assert!(serde_json::from_value::<Configuration>(good).is_ok());
    assert!(serde_json::from_value::<Configuration>(bad).is_err());
}

// ── Messages and quorum ──────────────────────────────────────────────────────

#[test]
fn v3_messages() {
    let d = doc();
    let list = d["messages"].as_array().unwrap();
    assert_eq!(list.len(), 12);
    for v in list {
        let k = kes_key(v);
        assert_eq!(k.witness_id(), key(&v["key_id"]));
        let chain = u(&v["chain_id"]) as u32;
        let (cid, s, t) = (h32(&v["config_id"]), cp(&v["source"]), cp(&v["target"]));
        let pre = attestation_message_v3_preimage(chain, &cid, &k, &s, &t);
        assert_eq!(pre.len(), poci::V3_PREIMAGE_LEN);
        assert_eq!(pre, bytes(&v["preimage"]));
        let msg = attestation_message_v3(chain, &cid, &k, &s, &t);
        assert_eq!(msg, h32(&v["msg_v3"]));
        assert_eq!(test_sign(&k, OBB_MAINNET_POCI.epoch_of(t.height), &msg), bytes(&v["test_sig"]));
    }
}

#[test]
fn strict_quorum() {
    let d = doc();
    let list = d["quorum"].as_array().unwrap();
    assert_eq!(list.len(), 20);
    for v in list {
        let (g, t) = (u128s(&v["got"]), u128s(&v["total"]));
        assert_eq!(quorum(g, t), v["quorum"].as_bool().unwrap(), "{g} of {t}");
        // GnB's rule is unchanged (>= two thirds, saturating).
        assert_eq!(two_thirds(g, t), v["gnb_two_thirds"].as_bool().unwrap(), "gnb {g} of {t}");
    }
}

// ── Proof of Corruption ──────────────────────────────────────────────────────

#[test]
fn evidence_verdicts() {
    let d = doc();
    let ev = &d["evidence"];
    let configs: Vec<Configuration> = ev["configs"].as_array().unwrap().iter().map(|v| config_of(v).1).collect();
    let cases = ev["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let (a, b) = (vote(&c["a"]), vote(&c["b"]));
        let got = check_evidence(&OBB_MAINNET_POCI, &a, &b, |id| configs.iter().find(|x| x.id() == *id));
        let got = got.map(|k| k.as_str()).map_err(|e| e.as_str());
        match c["kind"].as_str() {
            Some(kind) => {
                assert_eq!(c["verdict"], "ok", "{name}");
                assert_eq!(got, Ok(kind), "{name}");
            }
            None => assert_eq!(got, Err(c["verdict"].as_str().unwrap()), "{name}"),
        }
    }
}

// ── FFG, handoff and bans ────────────────────────────────────────────────────

/// The reference `PociChain` on the Rust ledger: checkpoints here,
/// configurations and bans in [`PociState`].
struct Chain {
    p: PociParams,
    provider: BTreeMap<u64, (Checkpoint, BTreeMap<KeyId, u128>)>,
    justified: Checkpoint,
    finalized: Checkpoint,
    state: PociState,
}

fn cp_hash(height: u64, branch: u32) -> [u8; 32] {
    let mut m = b"poci-vector-cp".to_vec();
    m.extend_from_slice(&height.to_le_bytes());
    m.extend_from_slice(&branch.to_le_bytes());
    sha256d(&m)
}

fn cph(height: u64) -> Checkpoint {
    Checkpoint { height, hash: cp_hash(height, 0) }
}

impl Chain {
    fn weights(&self, e: u64, finalized: &Checkpoint) -> BTreeMap<KeyId, u128> {
        let (f, w) = self.provider.get(&e).unwrap_or_else(|| panic!("provider call for epoch {e}"));
        assert_eq!(f, finalized, "provider called for epoch {e} with the finalized checkpoint");
        w.clone()
    }

    fn launch(p: PociParams, provider: BTreeMap<u64, (Checkpoint, BTreeMap<KeyId, u128>)>) -> Chain {
        let c = cph(p.opening(p.bootstrap_epochs));
        let (f, w) = provider[&p.bootstrap_epochs].clone();
        assert_eq!(f, c);
        let state = PociState::launch(&p, &w).unwrap();
        Chain { p, provider, justified: c, finalized: c, state }
    }

    fn votes(&mut self, target: Checkpoint, votes: &[PociVote<TestSig>]) -> Value {
        let src = self.justified;
        let cfg = self.state.config().clone();
        let got = counted_weight(&self.p, &cfg, votes, &src, &target);
        let q = quorum(got, cfg.total());
        let step = ffg_step(&self.p, &mut self.justified, &target, q);
        let mut handoff = false;
        if let Some(f) = step.finalized {
            self.finalized = f;
            let w = self.state.handoff_epoch(&self.p, &f).map(|e| self.weights(e, &f));
            handoff = self.state.finalized(&self.p, &f, |_| w.unwrap()).unwrap();
        }
        serde_json::json!({"weight": got.to_string(), "total": cfg.total().to_string(), "quorum": q,
                           "justified": step.justified, "finalized": step.finalized.is_some(), "handoff": handoff})
    }

    fn state_json(&self) -> Value {
        let c = self.state.config();
        serde_json::json!({"config_epoch": c.epoch(), "config_id": hex::encode(c.id()), "total": c.total().to_string(),
                           "justified": {"height": self.justified.height, "hash": hex::encode(self.justified.hash)},
                           "finalized": {"height": self.finalized.height, "hash": hex::encode(self.finalized.hash)}})
    }

    fn bans_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        for (k, bl) in &self.state.bans {
            m.insert(hex::encode(k), bl.iter().map(|b| serde_json::json!({
                "config_id": hex::encode(b.config_id), "height": b.included_at, "start": b.start,
                "end": b.end(self.p.ban_epochs)})).collect());
        }
        Value::Object(m)
    }
}

#[test]
fn sequences() {
    let d = doc();
    let seqs = d["sequences"].as_array().unwrap();
    assert_eq!(seqs.len(), 8);
    for sq in seqs {
        let name = sq["name"].as_str().unwrap();
        let p = params(sq["params"].as_str().unwrap());
        let keys: Vec<KesPublic> = sq["keys"].as_array().unwrap().iter().map(|k| {
            let kk = kes_key(k);
            assert_eq!(kk.witness_id(), key(&k["key_id"]));
            kk
        }).collect();
        let provider = sq["provider_calls"].as_object().unwrap().iter().map(|(e, v)| {
            (e.parse::<u64>().unwrap(), (cp(&v["finalized"]), entries(&v["weights"]).into_iter().collect()))
        }).collect();
        let mut ch = Chain::launch(p, provider);
        assert_eq!(ch.state_json(), sq["initial"], "{name}: initial");
        for (i, st) in sq["steps"].as_array().unwrap().iter().enumerate() {
            match st["op"].as_str().unwrap() {
                "votes" => {
                    let target = cph(u(&st["target"]));
                    let cfg = if st["config"] == "previous" { ch.state.previous().unwrap().clone() }
                              else { ch.state.config().clone() };
                    assert_eq!(cfg.id(), h32(&st["named_config_id"]), "{name} step {i}");
                    let src = st.get("source").map(|s| cph(u(s))).unwrap_or(ch.justified);
                    let bad: Vec<u64> = st.get("bad_sig").map(|b| b.as_array().unwrap().iter().map(u).collect())
                        .unwrap_or_default();
                    let votes: Vec<PociVote<TestSig>> = st["voters"].as_array().unwrap().iter().map(|ix| {
                        let mut v = sign(&p, cfg.id(), keys[u(ix) as usize], src, target);
                        if bad.contains(&u(ix)) {
                            v.sig = vec![0; 32];
                        }
                        v
                    }).collect();
                    assert_eq!(ch.votes(target, &votes), st["result"], "{name} step {i}");
                }
                "evidence" => {
                    let (a, b) = (vote(&st["a"]), vote(&st["b"]));
                    let fin = ch.finalized.height;
                    let r = ch.state.admit_evidence(&p, u(&st["height"]), fin, &a, &b);
                    let r = r.map(|_| "ok").unwrap_or_else(|e| e.as_str());
                    assert_eq!(r, st["result"].as_str().unwrap(), "{name} step {i}");
                }
                other => panic!("unknown op {other}"),
            }
            assert_eq!(ch.state_json(), st["state"], "{name} step {i}: state");
            assert_eq!(ch.bans_json(), st["bans"], "{name} step {i}: bans");
        }
        // The configurations in order of entry into force.
        let hist: Vec<_> = ch.state.history().cloned().collect::<Vec<_>>().into_iter().rev().collect();
        let want = sq["configs"].as_array().unwrap();
        assert_eq!(hist.len(), want.len(), "{name}: configurations");
        for (c, v) in hist.iter().zip(want) {
            config_json_check(&p, c, v);
            assert_eq!(c.entries(), config_of(v).1.entries());
        }
        // The node's stored form rebuilds the same state.
        let again = PociState::from_history(ch.state.history().cloned().collect(), ch.state.bans.clone()).unwrap();
        assert_eq!(again, ch.state, "{name}: from_history");
    }
}

// ── Proof of Integrity ───────────────────────────────────────────────────────

#[test]
fn certificates() {
    let d = doc();
    let cs = &d["certificates"];
    let p = params(cs["params"].as_str().unwrap());
    let (_, trusted) = config_of(&cs["trusted_config"]);
    let keys: Vec<KesPublic> = cs["keys"].as_array().unwrap().iter().map(kes_key).collect();
    // The two edge configurations of the reference (exact and just above two thirds).
    let edge = |w0: u128| {
        let w: BTreeMap<KeyId, u128> =
            [(keys[0].witness_id(), w0), (keys[1].witness_id(), 200), (keys[2].witness_id(), 200)].into();
        Configuration::from_weights(&p, 4, &w).unwrap()
    };
    let cases = cs["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let config = match name {
            "exactly_two_thirds" => edge(200),
            "just_above_two_thirds" => edge(201),
            _ => trusted.clone(),
        };
        let data = bytes(&c["certificate"]);
        let r = verify_certificate::<TestSig>(&data, &p, &config);
        let verdict = match &r {
            Ok(_) => "ok",
            Err(e) => e.as_str(),
        };
        assert_eq!(verdict, c["verdict"].as_str().unwrap(), "{name}");
        // Encoding round trip for every certificate that decodes.
        if let Ok(cert) = poci::Certificate::<TestSig>::decode(&data) {
            assert_eq!(cert.encode(), data, "{name}: encode");
            if let Some(proof) = c.get("registry_proof") {
                let proof = bytes(proof);
                let voters: Vec<KeyId> = cert.votes.iter().map(|(k, _)| k.witness_id()).collect();
                if let Some(own) = config.registry_proof(&voters) {
                    // The proofs that do not lie are the configuration's own.
                    if !name.starts_with("proof_") {
                        assert_eq!(own.encode(), proof, "{name}: registry proof");
                    }
                    assert_eq!(RegistryProof::decode(&own.encode(), voters.len()).unwrap(), own);
                }
                let r = verify_certificate_with_proof::<TestSig>(&data, &proof, &p, &config.id());
                let verdict = match &r {
                    Ok(_) => "ok",
                    Err(e) => e.as_str(),
                };
                assert_eq!(verdict, c["verdict_with_proof"].as_str().unwrap(), "{name}: with proof");
            } else {
                assert!(c.get("verdict_with_proof").is_none(), "{name}");
            }
        }
    }
}
