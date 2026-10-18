//! SHA-256d witness shares (`core::witness_share::sha256d`) and ObenBlock's
//! 112-epoch window (`core::powit::obenblock_window`) against
//! `reference/obb_shares.py` through `reference/obb_shares_vectors.json`, and
//! the share dispatch in `core` under a process-wide SHA-256d scheme. Setting
//! the scheme is irreversible, so this runs in its own test process (one test
//! function), like `obb_pow_vectors.rs`.

use std::sync::atomic::AtomicBool;

use gnb_crypto::core::pow_scheme::{self, PowScheme, Sha256dParams, OBB_BLOCK_VERSION};
use gnb_crypto::core::powit::{self, KeyId, PowitState, Regime, MAINNET_PARAMS, OBB_WINDOW_EPOCHS};
use gnb_crypto::core::witness_share::sha256d::{self as ws, AttestedParts, ShareJob};
use gnb_crypto::core::witness_share::{self, Sha256dShareFields, ShareError, WitnessShare};
use gnb_crypto::core::{Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use serde_json::Value;

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_shares_vectors.json"));

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hx(v).try_into().unwrap()
}

fn h20(v: &Value) -> [u8; 20] {
    hx(v).try_into().unwrap()
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

fn u128s(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn share_of(s: &Value) -> WitnessShare {
    WitnessShare {
        attested: h32(&s["attested_hex"]),
        witness: h20(&s["witness_hex"]),
        payout: hx(&s["payout_hex"]),
        bits: u(&s["bits"]) as u32,
        nonce: u(&s["job_nonce"]),
        sha256d: Some(Sha256dShareFields {
            version: u(&s["version"]) as u32,
            time: u(&s["time"]) as u32,
            nonce: u(&s["nonce"]) as u32,
        }),
    }
}

fn verdict(r: &Result<u128, ShareError>) -> Option<&'static str> {
    r.as_ref().err().map(|e| match e {
        ShareError::PayoutTooLong => "PayoutTooLong",
        ShareError::WrongScheme => "WrongScheme",
        ShareError::WrongAttestedBlock => "WrongAttestedBlock",
        ShareError::WrongBits => "WrongBits",
        ShareError::Version => "Version",
        ShareError::WrongTime => "WrongTime",
        ShareError::BadTarget => "BadTarget",
        ShareError::InsufficientWork => "InsufficientWork",
        other => panic!("unexpected {other:?}"),
    })
}

fn key(s: &str) -> KeyId {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn state(v: &Value) -> PowitState {
    let mut st = PowitState::genesis(0, [0; 32]);
    for (e, m) in v["epoch_work"].as_object().unwrap() {
        for (k, w) in m.as_object().unwrap() {
            st.epoch_work.entry(e.parse().unwrap()).or_default().insert(key(k), u128s(w));
        }
    }
    for (k, until) in v["banned"].as_object().unwrap() {
        st.banned.insert(key(k), u(until));
    }
    assert!(v["decay"].as_object().unwrap().is_empty(), "decay is package O4's");
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

/// A block whose share target (2^252) one hash in 16 meets.
fn easy_block() -> Block {
    let cb = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: vec![0x42; 700], sequence: 0 }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![0xAB; 22] }],
        locktime: 0,
    };
    let header = BlockHeader {
        version: OBB_BLOCK_VERSION, parents: vec![[7; 32]], merkle_root: MerkleRoot([3; 32]),
        timestamp: 1_800_000_321, bits: 0x2001_0000, nonce: 9,
    };
    Block { header, transactions: vec![cb], height: 40, blue_score: 40, shielded_transactions: vec![],
            powit: Default::default() }
}

fn panics(_: &[u8], _: u64) -> [u8; 32] {
    panic!("GnB-SMH must not run under the SHA-256d scheme")
}

#[test]
fn sha256d_shares_match_the_reference_and_drive_core() {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    let c = &d["constants"];
    assert_eq!(c["ds_idx"].as_str().unwrap().as_bytes(), ws::DS_IDX);
    assert_eq!(c["ds_job"].as_str().unwrap().as_bytes(), ws::DS_JOB);
    assert_eq!(c["ds_id"].as_str().unwrap().as_bytes(), ws::DS_ID);
    assert_eq!(u(&c["share_target_factor"]) as u32, witness_share::SHARE_TARGET_FACTOR);
    assert_eq!(u(&c["sample_chunks"]) as usize, witness_share::SAMPLE_CHUNKS);
    assert_eq!(u(&c["chunk_bytes"]) as usize, witness_share::CHUNK_BYTES);
    assert_eq!(u(&c["max_payout_script"]) as usize, witness_share::MAX_PAYOUT_SCRIPT);
    assert_eq!(u(&c["block_version"]) as u32, OBB_BLOCK_VERSION);
    assert_eq!(u(&c["window_epochs"]), OBB_WINDOW_EPOCHS);
    let obb = powit::obenblock_window(MAINNET_PARAMS);
    let cp = &c["params"];
    assert_eq!((u(&cp["epoch_len"]), u(&cp["window_epochs"]), u(&cp["ban_epochs"])),
               (obb.epoch_len, obb.window_epochs, obb.ban_epochs));

    // Jobs: chunk selection and commitment, byte for byte.
    for j in d["jobs"].as_array().unwrap() {
        let (a, w, p, jn, st) = (h32(&j["attested_hex"]), h20(&j["witness_hex"]), hx(&j["payout_hex"]),
                                 u(&j["job_nonce"]), hx(&j["stream_hex"]));
        let n = u(&j["n_chunks"]);
        let want: Vec<u64> = j["indices"].as_array().unwrap().iter().map(u).collect();
        assert_eq!(ws::sample_indices(&a, &p, jn, n).to_vec(), want);
        assert_eq!(ws::job_commitment(&a, &w, &p, jn, &st), h32(&j["job_commitment_hex"]));
    }

    // Shares, scheme-independent API: header, id, wire, verdict, work.
    let regtest = Sha256dParams::obenblock_regtest(1_800_000_000);
    for v in d["shares"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let s = share_of(&v["share"]);
        let at = &v["attested"];
        let stream = hx(&at["stream_hex"]);
        let parts = AttestedParts { id: h32(&at["id_hex"]), bits: u(&at["bits"]) as u32, timestamp: u(&at["timestamp"]),
                                    stream: &stream };
        let f = s.sha256d.unwrap();
        let job = ws::job_commitment(&s.attested, &s.witness, &s.payout, s.nonce, &stream);
        assert_eq!(ws::share_header(f.version, &s.attested, &job, f.time, s.bits, f.nonce).to_vec(), hx(&v["header_hex"]),
                   "{name}");
        assert_eq!(ws::share_id(&s, &f), h32(&v["share_id_hex"]), "{name}");
        assert_eq!(s.to_wire_bytes(), hx(&v["wire_hex"]), "{name}");
        let r = ws::verify_share_parts(&s, &parts, &regtest);
        assert_eq!(verdict(&r), v["verdict"].as_str(), "{name}");
        assert_eq!(r.unwrap_or(0), u128s(&v["work"]), "{name}");
    }
    // A share without header fields is the wrong form.
    let s0 = share_of(&d["shares"][0]["share"]);
    let stream0 = hx(&d["shares"][0]["attested"]["stream_hex"]);
    let a0 = &d["shares"][0]["attested"];
    let parts0 = AttestedParts { id: h32(&a0["id_hex"]), bits: u(&a0["bits"]) as u32, timestamp: u(&a0["timestamp"]),
                                 stream: &stream0 };
    assert_eq!(ws::verify_share_parts(&WitnessShare { sha256d: None, ..s0.clone() }, &parts0, &regtest),
               Err(ShareError::WrongScheme));

    // The 112-epoch window, against powit_reference's W(e).
    for w in d["windows"].as_array().unwrap() {
        let st = state(&w["state"]);
        for e in w["epochs"].as_array().unwrap() {
            let x = u(&e["epoch"]);
            let got = st.witness_set_in(&obb, x, Regime::Hardening2);
            assert_eq!(set_json(&got), json_set(&e["obenblock"]), "{} e={x}", w["name"]);
            assert_eq!(st.total_weight_h2(&obb, x).to_string(), e["total_obenblock"].as_str().unwrap());
            assert_eq!(set_json(&st.witness_set_in(&MAINNET_PARAMS, x, Regime::Hardening2)), json_set(&e["gnb_mainnet"]));
        }
    }

    // ── Dispatch in `core` ───────────────────────────────────────────────
    let b = easy_block();
    let wire0 = s0.to_wire_bytes();

    // GnB (scheme unset): GnB's decoder, GnB's verification and id.
    assert_eq!(pow_scheme::node_pow_scheme(), PowScheme::GnbSmh);
    let mut cur = std::io::Cursor::new(&wire0[..]);
    assert_eq!(WitnessShare::read_wire(&mut cur).unwrap().sha256d, None);
    assert_eq!(cur.position() as usize, wire0.len() - 12);
    let job = ShareJob::new(&b, [0x31; 20], b"\x51", 77, &regtest).unwrap();
    let mined = job.mine_cpu(0, 1 << 16, &AtomicBool::new(false)).unwrap();
    assert_eq!(witness_share::verify_share(&WitnessShare { attested: b.block_hash(), ..mined.clone() }, &b, |_, _| [0; 32]),
               Err(ShareError::WrongScheme));
    let gnb_form = WitnessShare { sha256d: None, ..mined.clone() };
    assert_ne!(witness_share::share_id(&gnb_form), witness_share::share_id(&mined));

    // SHA-256d.
    assert_eq!(pow_scheme::set_node_pow_scheme(PowScheme::Sha256d(regtest)), Ok(()));
    let mut cur = std::io::Cursor::new(&wire0[..]);
    assert_eq!(WitnessShare::read_wire(&mut cur).unwrap(), s0);
    assert_eq!(cur.position() as usize, wire0.len());
    assert_eq!(b.block_hash(), b.header.sha256d_block_id());
    assert_eq!(mined.attested, b.block_hash());
    let w = witness_share::verify_share(&mined, &b, panics).unwrap();
    assert_eq!(w, 15);
    assert_eq!(witness_share::share_id(&mined), ws::share_id(&mined, &mined.sha256d.unwrap()));
    assert_eq!(witness_share::verify_share(&gnb_form, &b, panics), Err(ShareError::WrongScheme));
    // Block-level rules use the dispatch too.
    let other = job.mine_cpu(mined.sha256d.unwrap().nonce + 1, 1 << 16, &AtomicBool::new(false)).unwrap();
    assert_eq!(witness_share::verify_block_shares(41, &[(&mined, &b), (&other, &b)], panics), Ok(30));
    assert!(matches!(witness_share::verify_block_shares(41, &[(&mined, &b), (&mined, &b)], panics),
                     Err(ShareError::Duplicate(_))));
}
