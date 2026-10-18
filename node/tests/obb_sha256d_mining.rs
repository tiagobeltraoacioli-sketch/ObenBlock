//! ObenBlock SHA-256d mining (docs/DESIGN-obenblock.md §4, package O3b):
//! the built-in miner, `getblocktemplate`'s `sha256d` object and header
//! jobs, a simulated stock Stratum V1 miner (Bitcoin's merkle root from
//! `mining.notify` alone), the ntime window under stall relief, and the
//! `submitblock` share solution, driven through the real
//! template builder and `accept::accept_block` under a process-wide SHA-256d
//! scheme (regtest pow limit; `test-pow-limit` pins the expected bits to it)
//! with the hardening and liveness rules from genesis (thread overrides,
//! as ObenBlock has them) and PoWit from height 1 (every
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
    let _live = core::liveness::scoped_override(0);
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
    assert_eq!(fields["merkle_root_rule"], json!("bitcoin-sha256d"));
    assert_eq!(fields["asert_bits"], fields["bits"], "no stall relief at curtime: the job is not late");
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
    let other_job = job::header_job(&tmpl2, &params, &spk, other, now).unwrap();
    assert_eq!(root, other_job.block.header.merkle_root);
    // That root is Bitcoin's root of the block's txids (the consensus rule).
    let txids: Vec<[u8; 32]> = other_job.block.transactions.iter().map(Transaction::txid).collect();
    assert_eq!(pow_scheme::bitcoin_merkle_root(&txids), (root, false));

    // Shares: version rolled inside the BIP 320 mask and time rolled ahead.
    let (version, time) = (OBB_BLOCK_VERSION | 0x0000_6000, job.block.header.timestamp as u32 + 1);
    let target = regtest_target();
    let losing = (0u32..).find(|&x| !gnb_smh::sha256d::meets_target(&gnb_smh::sha256d::block_id(&rolled(&job.header, version, time, x)), &target)).unwrap();
    let err = submit(&n, &job, json!({"version": version, "time": time, "nonce": losing})).unwrap_err();
    assert!(err.contains("proof") || err.contains("pow") || err.contains("PoW"), "{err}");
    // `accept_block` itself names the scheme the proof was judged under.
    let mut lb = Block::from_wire_bytes(&hex::decode(job.to_json()["block"].as_str().unwrap()).unwrap()).unwrap();
    job::apply_submit_solution(&mut lb, Some(&json!({"version": version, "time": time, "nonce": losing}))).unwrap();
    let err = gnb::accept::accept_block(&lb, lb.block_hash(), lb.height, &n.dag, &n.store, &n.mempool, &n.node_state,
                                        Some(&n.tip_tx), &n.shielded).unwrap_err();
    assert_eq!(err, "consensus rejection: invalid SHA-256d proof of work");
    assert_eq!(gnb::ingress::verdict_for_accept_error(&err), gnb::network::GossipVerdict::Reject);
    assert_eq!(gnb::ingress::accept_error_fault(&err), gnb::ingress::BlockFault::ContextFree);
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
    let _live = core::liveness::scoped_override(0);
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
                "merkle_branch": j.merkle_branch.iter().map(hex::encode).collect::<Vec<_>>(),
                "merkle_root_rule": job::MERKLE_RULE,
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
            "stratum": j.stratum_json(),
            "shares": shares,
        }));
    }
    json!({
        "description": "ObenBlock SHA-256d header jobs (docs/OBENBLOCK-MINING.md). Produced by \
            node/tests/obb_sha256d_mining.rs, recomputed from the job fields by reference/obb_job_test.py.",
        "extranonce_bytes": job::EXTRANONCE_LEN,
        "merkle_root_rule": job::MERKLE_RULE,
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

// ── A stock Stratum V1 miner ────────────────────────────────────────────────

/// What unmodified Stratum V1 firmware does with `mining.notify` (the job's
/// `stratum` object), its `extranonce1` from `mining.subscribe` and its own
/// `extranonce2`: no knowledge of ObenBlock at all.
fn stock_firmware_header(notify: &Value, en1: &[u8], en2: &[u8], ntime: u32, nonce: u32, version_bits: u32) -> [u8; 80] {
    let hexs = |k: &str| hex::decode(notify[k].as_str().unwrap()).unwrap();
    let be_u32 = |k: &str| u32::from_str_radix(notify[k].as_str().unwrap(), 16).unwrap();
    let words = hexs("prevhash");
    let mut prev = [0u8; 32];
    for i in 0..8 {
        for k in 0..4 {
            prev[4 * i + k] = words[4 * i + 3 - k];
        }
    }
    let mut cb = hexs("coinb1");
    cb.extend_from_slice(en1);
    cb.extend_from_slice(en2);
    cb.extend_from_slice(&hexs("coinb2"));
    let mut root = gnb_smh::sha256d::sha256d(&cb);
    for s in notify["merkle_branch"].as_array().unwrap() {
        let mut buf = root.to_vec();
        buf.extend_from_slice(&hex::decode(s.as_str().unwrap()).unwrap());
        root = gnb_smh::sha256d::sha256d(&buf);
    }
    let mut h = [0u8; 80];
    h[0..4].copy_from_slice(&(be_u32("version") | version_bits).to_le_bytes());
    h[4..36].copy_from_slice(&prev);
    h[36..68].copy_from_slice(&root);
    h[68..72].copy_from_slice(&ntime.to_le_bytes());
    h[72..76].copy_from_slice(&be_u32("nbits").to_le_bytes());
    h[76..80].copy_from_slice(&nonce.to_le_bytes());
    h
}

/// End to end on regtest: a node cuts a header job over a template with
/// several transactions (a non-trivial merkle branch); a simulated stock
/// miner rolls extranonce2, version bits, ntime and the nonce from the
/// `mining.notify` fields alone; the pool hands the share back with
/// `submitblock [block, {version, time, nonce, extranonce}]` and the node
/// accepts exactly the block the miner hashed. GnB-style roots (the
/// pre-change header root) are not what the miner computes.
#[test]
fn stock_stratum_v1_miner_finds_a_block_the_node_accepts() {
    let params = obb();
    let _act = core::activation::scoped_override(0);
    let _live = core::liveness::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 20);
    let k = key();
    let funds: Vec<_> = (0..3u8).map(|i| ([0xA0 + i; 32], 0u32, out(1_000_000_000, &k.spk))).collect();
    let n = node_with(&genesis, &funds);
    for (i, f) in funds.iter().enumerate() {
        let spend = signed_spend_at(&k, &[(f.0, 0)], std::slice::from_ref(&f.2),
                                    vec![out(999_000_000 - i as u64, &[0x44 + i as u8; 20])], 1);
        n.mempool.add(spend, 1_000_000).unwrap();
    }
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.transactions.len(), 3, "coinbase + 3: a two-level branch");
    let now = unix_now();
    let job = job::header_job(&tmpl, &params, &[0x5A; 20], [0; 8], now).unwrap();
    let notify = job.stratum_json();
    assert_eq!(notify["merkle_branch"].as_array().unwrap().len(), 2);
    assert_eq!(notify["extranonce_size"], json!(8));
    assert_eq!(notify["nbits"], json!(format!("{:08x}", job.block.header.bits)));

    // Pool: extranonce1 per connection; the miner owns extranonce2.
    let en1 = [0xE1, 0xE1, 0x00, 0x07];
    let target = gnb_smh::difficulty::bits_to_target(job.block.header.bits);
    let ntime = job.block.header.timestamp as u32 + 2;
    assert!(u64::from(ntime) <= job.window.maxtime);
    let version_bits = 0x0000_4000;
    let (en2, nonce, header) = (0u32..).find_map(|e2| {
        let en2 = e2.to_be_bytes();
        (0u32..64).find_map(|nonce| {
            let h = stock_firmware_header(&notify, &en1, &en2, ntime, nonce, version_bits);
            gnb_smh::sha256d::meets_target(&gnb_smh::sha256d::block_id(&h), &target).then_some((en2, nonce, h))
        })
    }).unwrap();
    let mut extranonce = en1.to_vec();
    extranonce.extend_from_slice(&en2);

    // The pool's view of the same share: the job fields and the rolled values.
    let mut block = job.block.clone();
    job::apply_submit_solution(&mut block, Some(&json!({
        "version": OBB_BLOCK_VERSION | version_bits, "time": ntime, "nonce": nonce,
        "extranonce": hex::encode(&extranonce),
    }))).unwrap();
    assert_eq!(block.header.sha256d_pow_bytes().unwrap(), header, "the node rebuilds the miner's header");
    let id = accept(&n, &block).expect("the stock-firmware share is a valid ObenBlock block");
    assert_eq!(id, gnb_smh::sha256d::block_id(&header));
    assert_eq!(sel_tip(&n), Some(id));
    assert_eq!(block_id_root(&n, &id), block.header.merkle_root);

    // A share whose extranonce does not reach the node (pool forgot it) is
    // the job's own coinbase: another root, not the miner's block.
    let mut wrong = job.block.clone();
    job::apply_submit_solution(&mut wrong, Some(&json!({
        "version": OBB_BLOCK_VERSION | version_bits, "time": ntime, "nonce": nonce,
    }))).unwrap();
    assert_ne!(wrong.header.merkle_root, block.header.merkle_root);
    // An extranonce on a block that is not a header job's is refused.
    let mut foreign = genesis.clone();
    assert!(job::apply_submit_solution(&mut foreign, Some(&json!({
        "version": 1, "time": 1, "nonce": 1, "extranonce": "0000000000000000",
    }))).is_err());
}

fn block_id_root(n: &Node, id: &[u8; 32]) -> core::MerkleRoot {
    n.store.get_block(id).unwrap().unwrap().header.merkle_root
}

/// Stall relief (DESIGN-obenblock.md §5.1): `bits` depend on the block's own
/// time in 60-second steps after a 180 s grace. Every job's `[mintime,
/// maxtime]` stays inside one step, so any rolled `ntime` in it keeps the
/// job's bits, and the next step starts at `next_bits_time`.
#[test]
fn ntime_window_never_crosses_a_relief_step() {
    let params = obb();
    let _act = core::activation::scoped_override(0);
    let _live = core::liveness::scoped_override(0);
    let parent = 1_800_000_000u64;
    // A harder ASERT base than the pow limit, so relief steps change bits.
    let mut tmpl = synthetic_template(5, vec![[0x11; 32]], 2, parent);
    tmpl.bits = 0x1d00_ffff;
    let relief = core::liveness::OBENBLOCK_STALL_RELIEF;
    let bits_at = |t: u64| core::liveness::relieve_at(tmpl.bits, parent, tmpl.height, t, 0,
                                                     core::liveness::liveness_activation_height());
    for now in [parent - 5, parent, parent + 30, parent + 239, parent + 240, parent + 299, parent + 300,
                parent + 1_000, parent + 1_799, parent + 36_000] {
        let w = job::time_window(&tmpl, now);
        assert!(w.mintime <= w.curtime && w.curtime <= w.maxtime, "now={now} {w:?}");
        assert!(w.mintime >= parent && w.maxtime <= now.max(parent) + core::MAX_FUTURE_SECS);
        for t in w.mintime..=w.maxtime {
            assert_eq!(bits_at(t), w.bits, "now={now} t={t}");
        }
        let next = w.next_bits_time.unwrap();
        assert_eq!((next - parent - relief.grace_secs as u64) % relief.step_secs as u64, 0);
        assert!(w.maxtime < next);
        // (Far behind, every step is clamped to the pow limit.)
        if w.relief_step > 0 && now < parent + 3_000 {
            assert_ne!(bits_at(w.mintime - 1), w.bits, "the window starts at its step");
        }
        let j = job::header_job(&tmpl, &params, &[0x76; 20], [3; 8], now).unwrap();
        assert_eq!(j.block.header.bits, w.bits);
        assert_eq!(j.block.header.timestamp, w.curtime);
        let f = job::template_fields(&tmpl, None, now).unwrap();
        assert_eq!(f["bits"], json!(format!("{:08x}", w.bits)), "sha256d.bits is the job time's");
        assert_eq!(f["asert_bits"], json!("1d00ffff"));
        assert_eq!((f["mintime"].as_u64(), f["maxtime"].as_u64()), (Some(w.mintime), Some(w.maxtime)));
    }
    // Late enough for relief: bits are easier than the ASERT base.
    assert_ne!(job::time_window(&tmpl, parent + 1_000).bits, tmpl.bits);
}

/// The coordinator's finding on obenblock/integration: header jobs hashed
/// the PoWit section without its exits list (`PowitBody::root`) while
/// consensus commits `root_with(exits)` from the liveness activation, so
/// every job failed its self-check. Now the section is committed through
/// the coinbase commitment, from the same block the validator sees: a job
/// over a template whose PoWit section carries an exit is consistent, and
/// dropping the exit breaks the commitment.
#[test]
fn header_jobs_commit_the_powit_section_with_exits() {
    let params = obb();
    let _act = core::activation::scoped_override(0);
    let _live = core::liveness::scoped_override(0);
    let signer = core::kes::KesSigner::generate(4, [7; 32], |_| {}).unwrap();
    let exit = core::powit::WitnessExit::sign(core::ChainId::ObenBlockRegtest.to_u32(), &signer).unwrap();
    let mut tmpl = synthetic_template(3, vec![[0x22; 32]], 1, 1_800_000_000);
    tmpl.powit.exits.push(exit);
    let j = job::header_job(&tmpl, &params, &[0x76; 20], [9; 8], 1_800_000_030).expect("the job's self-check passes");
    let b = &j.block;
    assert_eq!(b.powit.exits.len(), 1);
    assert!(b.validate_merkle());
    assert_eq!(core::block_rules::check_block_hardened_at(b, 0), Ok(()));
    assert_eq!(&b.transactions[0].inputs[0].script_sig[..80], &tmpl.coinbase_commitment().unwrap()[..]);
    // The wire round trip keeps the exit and the verdict.
    let back = Block::from_wire_bytes(&b.to_wire_bytes()).unwrap();
    assert_eq!(back.block_hash(), b.block_hash());
    assert_eq!(core::block_rules::check_block_hardened_at(&back, 0), Ok(()));
    let mut stripped = b.clone();
    stripped.powit.exits.clear();
    assert_eq!(stripped.block_hash(), b.block_hash(), "the section is not in the header");
    assert!(core::block_rules::check_block_hardened_at(&stripped, 0).unwrap_err().starts_with("bad witness commitment"));
}
