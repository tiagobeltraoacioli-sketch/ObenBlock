//! ObenBlock SHA-256d mining (docs/DESIGN-obenblock.md §4, package O3b):
//! the built-in miner, `getblocktemplate`'s `sha256d` object and header
//! jobs, and the `submitblock` share solution, driven through the real
//! template builder and `accept::accept_block` under a process-wide SHA-256d
//! scheme (regtest pow limit; `test-pow-limit` pins the expected bits to it)
//! with the hardening rules from genesis and PoWit from height 1 (every
//! block after genesis, as on ObenBlock; a genesis at the PoWit height needs
//! its own stored PoWit state, which belongs to the genesis package).
//!
//! Also produces and checks `reference/obb_job_vectors.json`, which
//! `reference/obb_job_test.py` recomputes from the job fields alone (the
//! computation a pool does). Regenerate with
//! `OBB_JOB_VECTORS_WRITE=1 cargo test --release -p gnb --test obb_sha256d_mining`.
//!
//! Setting the scheme is irreversible, so these tests run in their own test
//! process and all set the same scheme.

mod fix_common;
use fix_common::*;

use std::sync::OnceLock;

use gnb::core::pow_scheme::{self, check_sha256d_pow, PowScheme, Sha256dParams, OBB_BLOCK_VERSION, OBB_REGTEST_POW_LIMIT_BITS};
use gnb::core::{self, Block, Transaction, TxInput, TxOutput};
use gnb::mining::sha256d::{self as job, HeaderJob};
use gnb::template::{self, BlockTemplate};
use gnb::pow;
use serde_json::{json, Value};

const VECTORS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../reference/obb_job_vectors.json");

/// The scheme of this process: ObenBlock regtest, PoWit from height 1.
fn obb() -> Sha256dParams {
    static P: OnceLock<Sha256dParams> = OnceLock::new();
    *P.get_or_init(|| {
        let p = Sha256dParams::obenblock_regtest(1_800_000_000);
        core::set_powit_height_override(1).expect("PoWit height settable once");
        pow_scheme::set_node_pow_scheme(PowScheme::Sha256d(p)).expect("scheme settable once");
        p
    })
}

fn regtest_target() -> gnb_smh::difficulty::Target {
    gnb_smh::difficulty::bits_to_target(OBB_REGTEST_POW_LIMIT_BITS)
}

/// Header-job header with a share's rolled fields.
fn rolled(header: &[u8; 80], version: u32, time: u32, nonce: u32) -> [u8; 80] {
    let mut h = *header;
    h[0..4].copy_from_slice(&version.to_le_bytes());
    h[68..72].copy_from_slice(&time.to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

/// The first nonce from 0 whose rolled header meets `bits`.
fn solve(header: &[u8; 80], version: u32, time: u32, bits: u32) -> u32 {
    pow::mine_sha256d_parallel(&rolled(header, version, time, 0), bits, 0, 1 << 20, 1, None).expect("regtest target")
}

fn submit(n: &Node, job: &HeaderJob, solution: Value) -> Result<[u8; 32], String> {
    let mut block = Block::from_wire_bytes(&hex::decode(job.to_json()["block"].as_str().unwrap()).unwrap()).unwrap();
    job::apply_submit_solution(&mut block, Some(&solution))?;
    accept(n, &block)
}

#[test]
fn built_in_miner_and_header_jobs_produce_accepted_blocks() {
    let params = obb();
    let _act = core::activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x9Eu8; 32], 0u32, out(1_000_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let gh = genesis.block_hash();
    assert_eq!(gh, genesis.header.sha256d_block_id(), "block id is the SHA-256d id");

    // A template with an empty mempool (mined later as a sibling).
    let tmpl_empty = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert!(tmpl_empty.hardened && core::powit_active(tmpl_empty.height));
    assert_eq!(tmpl_empty.bits, OBB_REGTEST_POW_LIMIT_BITS);

    // ── Built-in miner on a template with one transaction ─────────────────
    let spend = signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2), vec![out(999_000_000, &[0x44; 20])], 1);
    n.mempool.add(spend.clone(), 1_000_000).unwrap();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.transactions.len(), 1);
    let mut b1 = template::assemble_block(&tmpl, tmpl.miner_coinbase(vec![0xC1; 20]), unix_now()).unwrap();
    assert_eq!(b1.header.version, OBB_BLOCK_VERSION, "the scheme's block version");
    let nonce = pow::mine_header_round(&b1.header, b1.height, 0, 2, None).expect("regtest target");
    b1.header.nonce = nonce;
    assert_eq!(check_sha256d_pow(&b1.header, &params), Ok(()));
    let h1 = accept(&n, &b1).expect("self-mined SHA-256d block is accepted");
    assert_eq!(h1, gnb_smh::sha256d::block_id(&b1.header.sha256d_pow_bytes().unwrap()));

    // A sibling of b1 on genesis, mined from the earlier template.
    let mut b1b = template::assemble_block(&tmpl_empty, tmpl_empty.miner_coinbase(vec![0xC2; 20]), unix_now()).unwrap();
    b1b.header.nonce = pow::mine_header_round(&b1b.header, b1b.height, 1 << 30, 1, None).unwrap();
    let h1b = accept(&n, &b1b).unwrap();

    // ── Header job on the two tips ────────────────────────────────────────
    let tmpl2 = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    let mut both = vec![h1, h1b];
    both.sort_unstable();
    assert_eq!(tmpl2.parents, both, "SHA-256d templates carry the parents sorted ascending");
    assert_eq!(tmpl2.height, 2);

    let now = unix_now();
    let spk = vec![0x5A; 20];
    let fields = job::template_fields(&tmpl2, Some(&json!([{"header_job": {
        "coinbase_script_pubkey": hex::encode(&spk), "extranonce": "0001020304050607",
    }}])), now).unwrap();
    assert_eq!(fields["version"], json!(OBB_BLOCK_VERSION));
    assert_eq!(fields["version_rolling_mask"], json!("1fffe000"));
    assert_eq!(fields["bits"], json!(format!("{:08x}", OBB_REGTEST_POW_LIMIT_BITS)));
    assert_eq!(fields["mintime"], json!(tmpl2.parent_timestamp));
    assert_eq!(fields["merkle_root_rule"], json!("gnb-body-v2"));
    let commitment = gnb_smh::sha256d::parents_commitment(&tmpl2.parents);
    assert_eq!(fields["parents_commitment"], json!(hex::encode(commitment)));
    let mut display = commitment;
    display.reverse();
    assert_eq!(fields["previousblockhash"], json!(hex::encode(display)));

    let job = job::header_job(&tmpl2, &params, &spk, [0, 1, 2, 3, 4, 5, 6, 7], now).unwrap();
    let jf = &fields["header_job"];
    assert_eq!(jf["header"], json!(hex::encode(job.header)));
    assert_eq!(jf["coinb1"], json!(hex::encode(&job.coinb1)));
    assert_eq!(&job.header[4..36], &commitment);
    // A pool recomputes the root for another extranonce from the job alone.
    let other = [9u8; 8];
    let mut cb = job.coinb1.clone();
    cb.extend_from_slice(&other);
    cb.extend_from_slice(&job.coinb2);
    let root = job::header_merkle_root(&tmpl2, &gnb_smh::sha256d::sha256d(&cb)).unwrap();
    assert_eq!(root, job::header_job(&tmpl2, &params, &spk, other, now).unwrap().block.header.merkle_root);

    // Shares: version rolled inside the BIP 320 mask and time rolled ahead.
    let (version, time) = (OBB_BLOCK_VERSION | 0x0000_6000, job.block.header.timestamp as u32 + 1);
    let target = regtest_target();
    let losing = (0u32..).find(|&x| !gnb_smh::sha256d::meets_target(&gnb_smh::sha256d::block_id(&rolled(&job.header, version, time, x)), &target)).unwrap();
    let err = submit(&n, &job, json!({"version": version, "time": time, "nonce": losing})).unwrap_err();
    assert!(err.contains("proof") || err.contains("pow") || err.contains("PoW"), "{err}");
    let bad_version = OBB_BLOCK_VERSION | 0x0000_1000;
    let nonce = solve(&job.header, bad_version, time, OBB_REGTEST_POW_LIMIT_BITS);
    assert!(submit(&n, &job, json!({"version": bad_version, "time": time, "nonce": nonce})).is_err(),
        "a version outside the BIP 320 mask is invalid");
    assert!(submit(&n, &job, json!({"version": version, "time": time})).is_err());

    let nonce = solve(&job.header, version, time, OBB_REGTEST_POW_LIMIT_BITS);
    let h2 = submit(&n, &job, json!({"version": version, "time": time, "nonce": nonce})).expect("header-job share is a valid block");
    assert_eq!(h2, gnb_smh::sha256d::block_id(&rolled(&job.header, version, time, nonce)));
    assert_eq!(sel_tip(&n), Some(h2));

    // Job requests a pool gets wrong are refused, not silently changed.
    for bad in [
        json!([{"header_job": {"coinbase_script_pubkey": ""}}]),
        json!([{"header_job": {"coinbase_script_pubkey": "00".repeat(65)}}]),
        json!([{"header_job": {"coinbase_script_pubkey": "00".repeat(22)}}]),
        json!([{"header_job": {"coinbase_script_pubkey": "00".repeat(33)}}]),
        json!([{"header_job": {"coinbase_script_pubkey": "00", "extranonce": "00"}}]),
    ] {
        assert!(job::template_fields(&tmpl2, Some(&bad), now).is_err(), "{bad}");
    }
    let mut unsorted = tmpl2.clone();
    unsorted.parents.reverse();
    assert!(job::header_job(&unsorted, &params, &spk, other, now).unwrap_err().contains("header order"));
}

// ── Reference vectors ───────────────────────────────────────────────────────

/// A 33-byte spend-policy output script (tag byte + 32-byte policy hash).
fn policy_spk() -> Vec<u8> {
    let mut s = vec![core::policy::POLICY_TAG];
    s.extend_from_slice(&[0x51; 32]);
    s
}

fn fake_tx(tag: u8, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [tag; 32], prev_index: 0, script_sig: vec![tag; 40], sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey: vec![tag; 20] }],
        locktime: 0,
    }
}

/// A synthetic template (no DAG: deterministic) at `height` over `parents`
/// with `n_tx` fake transactions of fee 1,000 each.
fn synthetic_template(height: u64, parents: Vec<[u8; 32]>, n_tx: u8, parent_timestamp: u64) -> BlockTemplate {
    let transactions: Vec<(Transaction, u64)> = (0..n_tx).map(|i| (fake_tx(0x30 + i, 50_000 + i as u64), 1_000)).collect();
    BlockTemplate {
        parents,
        height,
        blue_score: height,
        bits: OBB_REGTEST_POW_LIMIT_BITS,
        parent_timestamp,
        total_fees: 1_000 * n_tx as u64,
        transactions,
        subsidy: core::tokenomics::block_subsidy_sat(height),
        evicted: 0,
        tx_byte_budget: 0,
        activation_height: 0,
        hardened: true,
        powit: Default::default(),
    }
}

fn vector_cases(params: &Sha256dParams) -> Value {
    let cases = [
        ("one parent, coinbase only", 1u64, vec![[0x11u8; 32]], 0u8, [0u8; 8], vec![0x76; 20]),
        ("two parents, three transactions", 7, vec![[0x11; 32], [0x22; 32]], 3, [1, 2, 3, 4, 5, 6, 7, 8], vec![0xA9; 20]),
        ("policy script, five transactions", 40, vec![[0x01; 32], [0x80; 32], [0xFE; 32]], 5, [0xFF; 8], policy_spk()),
    ];
    let target = regtest_target();
    let mut out = Vec::new();
    for (name, height, parents, n_tx, extranonce, spk) in cases {
        let time = 1_800_000_000 + height * 30;
        let tmpl = synthetic_template(height, parents.clone(), n_tx, time - 30);
        let j = job::header_job(&tmpl, params, &spk, extranonce, time).unwrap();
        let block_version = params.block_version;
        let mut shares = Vec::new();
        for (version, dt) in [(block_version, 0u32), (block_version | 0x1FFF_E000, 1), (block_version | 0x0000_2000, 7)] {
            for nonce in [0u32, 1, 2, 0xFFFF_FFFF] {
                let h = rolled(&j.header, version, time as u32 + dt, nonce);
                let id = gnb_smh::sha256d::block_id(&h);
                shares.push(json!({
                    "version": version, "time": time as u32 + dt, "nonce": nonce,
                    "header": hex::encode(h), "block_id": hex::encode(id),
                    "meets_target": gnb_smh::sha256d::meets_target(&id, &target),
                }));
            }
        }
        // The share solution, applied to the job's block, gives that block id.
        let mut b = j.block.clone();
        let last = shares.last().unwrap();
        job::apply_submit_solution(&mut b, Some(&json!({
            "version": last["version"], "time": last["time"], "nonce": last["nonce"],
        }))).unwrap();
        assert_eq!(hex::encode(b.block_hash()), last["block_id"].as_str().unwrap());
        out.push(json!({
            "name": name,
            "height": height,
            "parents": parents.iter().map(hex::encode).collect::<Vec<_>>(),
            "txids": tmpl.transactions.iter().map(|(t, _)| hex::encode(t.txid())).collect::<Vec<_>>(),
            "job": {
                "coinb1": hex::encode(&j.coinb1),
                "coinb2": hex::encode(&j.coinb2),
                "extranonce": hex::encode(j.extranonce),
                "coinbase_merkle_branch": tmpl.coinbase_merkle_branch().iter().map(hex::encode).collect::<Vec<_>>(),
                "merkle_root_rule": "gnb-body-v2",
                "shielded_root": hex::encode(job::empty_shielded_root()),
                "powit_root": hex::encode(job::powit_root(&tmpl)),
                "version": block_version,
                "bits": OBB_REGTEST_POW_LIMIT_BITS,
                "time": time,
            },
            "expect": {
                "coinbase_txid": hex::encode(j.block.transactions[0].txid()),
                "merkle_root": hex::encode(j.block.header.merkle_root.0),
                "header": hex::encode(j.header),
                "block_id": hex::encode(gnb_smh::sha256d::block_id(&j.header)),
            },
            "shares": shares,
        }));
    }
    json!({
        "description": "ObenBlock SHA-256d header jobs (docs/OBENBLOCK-MINING.md). Produced by \
            node/tests/obb_sha256d_mining.rs, recomputed from the job fields by reference/obb_job_test.py.",
        "extranonce_bytes": job::EXTRANONCE_LEN,
        "coinbase_tag": hex::encode(job::COINBASE_TAG),
        "bip320_mask": gnb_smh::sha256d::BIP320_VERSION_MASK,
        "cases": out,
    })
}

#[test]
fn header_job_vectors_match_the_reference_file() {
    let params = obb();
    let _act = core::activation::scoped_override(0);
    let got = vector_cases(&params);
    let text = serde_json::to_string_pretty(&got).unwrap() + "\n";
    if std::env::var_os("OBB_JOB_VECTORS_WRITE").is_some() {
        std::fs::write(VECTORS_PATH, &text).unwrap();
    }
    let want = std::fs::read_to_string(VECTORS_PATH).expect("reference/obb_job_vectors.json");
    let want: Value = serde_json::from_str(&want).unwrap();
    assert_eq!(got, want, "header jobs differ from reference/obb_job_vectors.json (regenerate, then rerun the Python check)");
    // Every case has at least one share that wins at the regtest target.
    for c in got["cases"].as_array().unwrap() {
        assert!(c["shares"].as_array().unwrap().iter().any(|s| s["meets_target"] == json!(true)), "{}", c["name"]);
    }
}
