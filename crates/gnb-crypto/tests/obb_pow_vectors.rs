//! The SHA-256d scheme (`core::pow_scheme`) against `reference/obb_pow.py`
//! through `reference/obb_pow_vectors.json`, and the `core` dispatch under a
//! process-wide SHA-256d scheme. Setting the scheme is irreversible, so this
//! runs in its own test process (one test function), like `node_chain_id.rs`.

use gnb_crypto::core::pow_scheme::{
    self, check_sha256d_pow, PowScheme, Sha256dHeaderError, Sha256dParams, OBB_BLOCK_VERSION, OBB_LAUNCH_BITS,
    OBB_POW_LIMIT_BITS, OBB_REGTEST_POW_LIMIT_BITS, SLOW_START_BLOCKS,
};
use gnb_crypto::core::{self, Block, BlockHeader, MerkleRoot};
use gnb_smh::sha256d::ParentsError;
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/obb_pow_vectors.json"));

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn header_of(h: &Value) -> BlockHeader {
    BlockHeader {
        version: h["version"].as_u64().unwrap() as u32,
        parents: h["parents"].as_array().unwrap().iter().map(h32).collect(),
        merkle_root: MerkleRoot(h32(&h["merkle_root_hex"])),
        timestamp: h["timestamp"].as_u64().unwrap(),
        bits: h["bits"].as_u64().unwrap() as u32,
        nonce: h["nonce"].as_u64().unwrap(),
    }
}

fn verdict(r: Result<(), Sha256dHeaderError>) -> Option<String> {
    r.err().map(|e| match e {
        Sha256dHeaderError::TimeOutOfRange => "TimeOutOfRange".into(),
        Sha256dHeaderError::NonceOutOfRange => "NonceOutOfRange".into(),
        Sha256dHeaderError::Version => "Version".into(),
        Sha256dHeaderError::Parents(ParentsError::TooMany) => "Parents:TooMany".into(),
        Sha256dHeaderError::Parents(ParentsError::Duplicate) => "Parents:Duplicate".into(),
        Sha256dHeaderError::Parents(ParentsError::NotSorted) => "Parents:NotSorted".into(),
        Sha256dHeaderError::BitsNotCanonical => "BitsNotCanonical".into(),
        Sha256dHeaderError::AbovePowLimit => "AbovePowLimit".into(),
        Sha256dHeaderError::InsufficientWork => "InsufficientWork".into(),
    })
}

#[test]
fn sha256d_scheme_matches_the_reference_and_drives_core() {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    let c = &d["constants"];
    assert_eq!(c["pow_limit_bits"].as_u64().unwrap() as u32, OBB_POW_LIMIT_BITS);
    assert_eq!(c["regtest_pow_limit_bits"].as_u64().unwrap() as u32, OBB_REGTEST_POW_LIMIT_BITS);
    assert_eq!(c["launch_bits"].as_u64().unwrap() as u32, OBB_LAUNCH_BITS);
    assert_eq!(c["block_version"].as_u64().unwrap() as u32, OBB_BLOCK_VERSION);
    assert_eq!(c["bip320_mask"].as_u64().unwrap() as u32, gnb_smh::sha256d::BIP320_VERSION_MASK);
    assert_eq!(c["max_parents"].as_u64().unwrap() as usize, core::MAX_PARENTS);
    assert_eq!(c["slow_start_blocks"].as_u64().unwrap(), SLOW_START_BLOCKS);
    assert_eq!(c["full_subsidy_sat"].as_u64().unwrap(), core::tokenomics::INITIAL_SUBSIDY_SAT);
    assert_eq!(
        c["launch_hashrate_hps"].as_str().unwrap().parse::<u128>().unwrap(),
        pow_scheme::LAUNCH_HASHRATE_HPS
    );
    let genesis_time = c["genesis_time"].as_u64().unwrap();
    let mainnet = Sha256dParams::obenblock_mainnet(genesis_time);
    let regtest = Sha256dParams::obenblock_regtest(genesis_time);

    // Before the scheme is set, `core` is GnB's.
    assert_eq!(pow_scheme::node_pow_scheme(), PowScheme::GnbSmh);
    let first = header_of(&d["headers"][0]["header"]);
    let gnb_id = Block {
        header: first.clone(),
        transactions: vec![],
        blue_score: 0,
        height: 1,
        shielded_transactions: vec![],
        powit: Default::default(),
    }
    .block_hash();
    assert_ne!(gnb_id, first.sha256d_block_id());
    let gnb_work_v3 = core::block_work(OBB_POW_LIMIT_BITS, 50_000);

    assert_eq!(pow_scheme::set_node_pow_scheme(PowScheme::Sha256d(regtest)), Ok(()));
    assert_eq!(pow_scheme::set_node_pow_scheme(PowScheme::Sha256d(regtest)), Ok(()));
    assert_eq!(pow_scheme::set_node_pow_scheme(PowScheme::GnbSmh), Err(PowScheme::Sha256d(regtest)));
    assert_eq!(pow_scheme::node_pow_scheme().name(), "sha256d");

    // Headers: ids, every rule, and `Block::block_hash` / `validate_pow`.
    let mut valid = 0;
    for v in d["headers"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let header = header_of(&v["header"]);
        assert_eq!(header.sha256d_block_id(), h32(&v["block_id_hex"]), "{name}");
        let want_r = v["check_regtest"].as_str().map(String::from);
        let want_m = v["check_mainnet"].as_str().map(String::from);
        assert_eq!(verdict(check_sha256d_pow(&header, &regtest)), want_r, "{name} regtest");
        assert_eq!(verdict(check_sha256d_pow(&header, &mainnet)), want_m, "{name} mainnet");
        let block = Block {
            header,
            transactions: vec![],
            blue_score: 0,
            height: 1,
            shielded_transactions: vec![],
            powit: Default::default(),
        };
        assert_eq!(block.block_hash(), h32(&v["block_id_hex"]), "{name}: block id is the PoW hash");
        assert_eq!(block.validate_pow(), want_r.is_none(), "{name}");
        if want_r.is_none() {
            valid += 1;
            assert!(block.pow_is_cached());
        }
    }
    assert!(valid >= 9);
    assert_eq!(
        core::Block::pow_limit_target_for_height(1),
        core::bits_to_target(OBB_REGTEST_POW_LIMIT_BITS)
    );

    // Expected bits: mainnet through the params, regtest through `core`.
    for v in d["expected_bits"].as_array().unwrap() {
        let (pt, h) = (v["parent_time"].as_u64().unwrap(), v["height"].as_u64().unwrap());
        let want = v["bits"].as_u64().unwrap() as u32;
        match v["network"].as_str().unwrap() {
            "mainnet" => assert_eq!(mainnet.expected_bits(pt, h).unwrap(), want, "{pt} {h}"),
            _ => {
                assert_eq!(regtest.expected_bits(pt, h).unwrap(), want);
                assert_eq!(core::expected_bits_at(pt, h, u64::MAX).unwrap(), want);
            }
        }
    }

    // Work: Bitcoin's, with no GnB-SMH shift, at every height.
    assert_eq!(core::block_work(OBB_POW_LIMIT_BITS, 1), 0x1_0001_0001);
    assert_eq!(core::block_work(OBB_POW_LIMIT_BITS, 50_000), 0x1_0001_0001);
    assert_eq!(gnb_work_v3, core::bits_to_work(OBB_POW_LIMIT_BITS) >> core::POW_V3_DIFFICULTY_SHIFT,
               "before the scheme was set, GnB's v3 shift applied");
    assert_eq!(core::block_work(0, 1), 0);

    // Slow start.
    let full = c["full_subsidy_sat"].as_u64().unwrap();
    for v in d["slow_start"].as_array().unwrap() {
        assert_eq!(
            pow_scheme::slow_start_subsidy_sat(full, v["height"].as_u64().unwrap()),
            v["subsidy_sat"].as_u64().unwrap()
        );
    }
    let withheld: u64 = (1..SLOW_START_BLOCKS).map(|h| full - pow_scheme::slow_start_subsidy_sat(full, h)).sum();
    assert_eq!(withheld, c["slow_start_withheld_sat"].as_u64().unwrap());
}
