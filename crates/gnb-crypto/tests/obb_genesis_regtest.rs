//! A process that runs ObenBlock regtest (`core::set_node_chain_id`), as the
//! node does at start-up: the genesis, the proof-of-work scheme and every
//! rule of docs/DESIGN-obenblock.md §3 from height 0, with no legacy regime
//! reachable. The chain id is process-wide and fixed once, so this runs in
//! its own test process (one test function).

use gnb_crypto::core::genesis::{self, chain_genesis, OBB_REGTEST_GENESIS_HASH, OBB_REGTEST_GENESIS_TIMESTAMP};
use gnb_crypto::core::pow_scheme::{self, PowScheme, Sha256dParams, OBB_REGTEST_POW_LIMIT_BITS, SLOW_START_BLOCKS};
use gnb_crypto::core::{self, activation, block_rules, tokenomics, ChainId};
use gnb_crypto::crypto::SuiteRules;

#[test]
fn obenblock_regtest_runs_every_rule_from_genesis() {
    assert_eq!(core::set_node_chain_id(ChainId::ObenBlockRegtest), Ok(()));
    assert_eq!(core::node_chain_id(), ChainId::ObenBlockRegtest);

    // SHA-256d is bound to the chain id, anchored at this genesis; nothing
    // can switch the process to another scheme or chain afterwards.
    let p = Sha256dParams::obenblock_regtest(OBB_REGTEST_GENESIS_TIMESTAMP);
    assert_eq!(pow_scheme::node_pow_scheme(), PowScheme::Sha256d(p));
    assert_eq!(pow_scheme::set_node_pow_scheme(PowScheme::GnbSmh), Err(PowScheme::Sha256d(p)));
    assert!(core::set_node_chain_id(ChainId::ObenBlockMainnet).is_err());
    assert!(core::set_node_chain_id(ChainId::Testnet).is_err());
    assert_eq!(core::set_node_chain_id(ChainId::ObenBlockRegtest), Ok(()), "idempotent");

    // The genesis of the node's chain: SHA-256d id, valid proof, the body
    // root of height 0 under the process's own rules, the coinbase
    // commitment.
    let g = core::genesis_block();
    assert_eq!(g.block_hash(), OBB_REGTEST_GENESIS_HASH);
    assert_eq!(g.block_hash(), g.header.sha256d_block_id());
    assert_eq!(g.block_hash(), chain_genesis(ChainId::ObenBlockRegtest).block().block_hash());
    assert!(g.validate_pow());
    assert!(g.validate_merkle(), "the header root is the body root the node computes at height 0");
    assert_eq!(g.body_merkle_root(), genesis::obenblock_genesis_merkle_root(&g.transactions[0]));
    assert_eq!(block_rules::check_coinbase_commitment(&g), Ok(()));
    assert_eq!(g.validate_coinbase_value(0), Ok(()));
    assert_eq!(g.to_wire_bytes().len(), g.wire_size());
    let back = core::Block::from_wire_bytes(&g.to_wire_bytes()).unwrap();
    assert_eq!(back.block_hash(), g.block_hash());
    assert_eq!(genesis::launch_refusal(ChainId::ObenBlockRegtest), None);

    // ASERT from the genesis: on schedule or behind it, the regtest pow
    // limit; ahead of it, harder. `expected_bits_at` is the real rule: a
    // workspace build unifies the `test-pow-limit` feature (node tests),
    // which pins `expected_bits` to the pow limit.
    let real = |ts: u64, h: u64| core::expected_bits_at(ts, h, activation::hardening_activation_height()).unwrap();
    assert_eq!(real(OBB_REGTEST_GENESIS_TIMESTAMP, 1), OBB_REGTEST_POW_LIMIT_BITS);
    assert_eq!(real(OBB_REGTEST_GENESIS_TIMESTAMP + 86_400, 2), OBB_REGTEST_POW_LIMIT_BITS);
    let ahead = real(OBB_REGTEST_GENESIS_TIMESTAMP, 2_000);
    assert!(gnb_smh::difficulty::bits_to_target(ahead) < gnb_smh::difficulty::bits_to_target(OBB_REGTEST_POW_LIMIT_BITS));
    assert_eq!(core::block_work(OBB_REGTEST_POW_LIMIT_BITS, 1), gnb_smh::sha256d::work_from_bits(OBB_REGTEST_POW_LIMIT_BITS));

    // Both hardening activations and PoWit at height 0; the test override
    // of the PoWit height is ignored on ObenBlock.
    assert_eq!(activation::hardening_activation_height(), 0);
    assert_eq!(activation::hardening2_activation_height(), 0);
    assert!(block_rules::rules_active(1) && !block_rules::rules_active(0), "the genesis is outside the block rules");
    let _ = core::set_powit_height_override(1_000);
    assert_eq!(core::powit_height(), 0);
    assert!(core::powit_active(0) && core::powit_active(1));
    // v3 transactions, sighash v3 and the canonical witnesses from block 1;
    // the conservative suite 0x0003 (second activation) too.
    let act = activation::hardening_activation_height();
    assert_eq!(core::sighash::tx_version_for_height(1, act), core::sighash::TX_VERSION_V3);
    assert!(core::sighash::check_tx_version(1, 1, act).is_err());
    assert_eq!(core::sighash::check_tx_version(3, 1, act), Ok(core::sighash::SighashVersion::V3));
    let suites = core::sighash::suite_rules_for_height(1);
    assert_eq!(suites, SuiteRules::HARDENING2);
    assert!(suites.conservative_suite());
    // Every block's witnesses are committed (the coinbase commitment); the
    // GnB-only `|wc:` suffix never applies.
    assert_eq!(genesis::witness_commitment_height(), 0);
    assert!(core::witnesses_committed(1));
    assert!(!core::suffix_witness_commitment_required(1) && !core::suffix_witness_commitment_required(6_000));

    // Slow start (§4.2): the subsidy ramps from 0 to full over 5,760 blocks,
    // then follows GnB's halving schedule; the witness split uses it.
    let full = tokenomics::INITIAL_SUBSIDY_SAT;
    assert_eq!(tokenomics::block_subsidy_sat(0), 0);
    assert_eq!(tokenomics::block_subsidy_sat(1), full / SLOW_START_BLOCKS);
    assert_eq!(tokenomics::block_subsidy_sat(SLOW_START_BLOCKS / 2), full / 2);
    assert_eq!(tokenomics::block_subsidy_sat(SLOW_START_BLOCKS), full);
    assert_eq!(tokenomics::block_subsidy_sat(tokenomics::HALVING_INTERVAL), full / 2);
    assert_eq!(tokenomics::schedule_subsidy_sat(1), full);
    let split = core::witness_share::split_subsidy(1, 0);
    assert_eq!(split.miner + split.unissued, tokenomics::block_subsidy_sat(1));
    for h in [1, 100, 5_759, 5_760, 10_000] {
        assert!(tokenomics::block_subsidy_sat(h) <= tokenomics::schedule_subsidy_sat(h));
    }
    assert!(tokenomics::issued_through_sat(SLOW_START_BLOCKS)
        >= (1..=SLOW_START_BLOCKS).map(tokenomics::block_subsidy_sat).sum::<u64>(), "an upper bound");

    // The allocations are GnB's.
    assert_eq!(tokenomics::MAX_SUPPLY_SAT, 12_500_000 * tokenomics::SAT_PER_GNB);
    assert_eq!(tokenomics::MINING_ALLOCATION_SAT, 9_000_000 * tokenomics::SAT_PER_GNB);
    assert_eq!(tokenomics::CARRYOVER_ALLOCATION_SAT, 1_000_000 * tokenomics::SAT_PER_GNB);
    assert_eq!(tokenomics::TEAM_ALLOCATION_SAT, 1_250_000 * tokenomics::SAT_PER_GNB);
    assert_eq!(tokenomics::FOUNDER_ALLOCATION_SAT, 1_250_000 * tokenomics::SAT_PER_GNB);
}
