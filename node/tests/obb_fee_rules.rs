//! ObenBlock fee rules end to end (owner decision 2026-10-25): the 1%
//! minimum on the value sent to others (change exempt) and the 80/20 split
//! of a block's fees between the miner and the witness slots. The chain id
//! is process-wide and fixed once, so this runs in its own test process.

mod fix_common;
use fix_common::*;

use gnb::core::pow_scheme::OBB_BLOCK_VERSION;
use gnb::core::{self, ChainId};
use gnb::template;

/// A SHA-256d nonce at the regtest pow limit (about two hashes).
fn mine(b: &mut core::Block) {
    b.header.version = OBB_BLOCK_VERSION;
    while !b.validate_pow() {
        b.header.nonce += 1;
    }
}

/// ObenBlock fees (owner decision 2026-10-25): every transaction pays at
/// least 1% of the value it sends to others (an output back to a spent
/// coin's script is change and exempt), and the block's fees are split like
/// its subsidy: the miner may claim 80% of them with no witness share, the
/// empty slots are burned.
#[test]
fn one_percent_fee_change_exemption_and_fee_split() {
    core::set_node_chain_id(ChainId::ObenBlockRegtest).expect("fresh process");
    let _act = core::activation::scoped_override(0);
    let _live = core::liveness::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let low_fund = ([0x7Au8; 32], 0u32, out(1_000_000_000, &k.spk));
    let ok_fund = ([0x7Bu8; 32], 0u32, out(1_000_000_000, &k.spk));
    let n = node_with(&genesis, &[low_fund.clone(), ok_fund.clone()]);

    // 9 OBB to someone else, 0.05 OBB of fee: below 1% (0.09 OBB).
    let low = signed_spend_at(&k, &[(low_fund.0, 0)], std::slice::from_ref(&low_fund.2),
                              vec![out(900_000_000, &[0x44; 20]), out(95_000_000, &k.spk)], 1);
    let low_fee = 5_000_000;
    assert!(core::check_min_fee(&low, low_fee, std::slice::from_ref(&low_fund.2)).is_err());
    // 5 OBB to someone else, 4.9 OBB back as change, 0.1 OBB of fee: the
    // change is exempt, so 1% of 5 OBB (0.05 OBB) is enough.
    let ok = signed_spend_at(&k, &[(ok_fund.0, 0)], std::slice::from_ref(&ok_fund.2),
                             vec![out(500_000_000, &[0x45; 20]), out(490_000_000, &k.spk)], 1);
    let ok_fee = 10_000_000;
    assert_eq!(core::paid_to_others_sat(&ok, std::slice::from_ref(&ok_fund.2)), 500_000_000);
    assert_eq!(core::min_fee_of(&ok, std::slice::from_ref(&ok_fund.2)), 5_000_000);
    assert!(core::check_min_fee(&ok, ok_fee, std::slice::from_ref(&ok_fund.2)).is_ok());
    // Without the exemption (every output counted) the same fee would not do.
    assert!(core::check_min_fee(&ok, 9_899_999, &[]).is_err());

    n.mempool.add(low.clone(), low_fee).unwrap();
    n.mempool.add(ok.clone(), ok_fee).unwrap();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    let txids: Vec<_> = tmpl.transactions.iter().map(|(t, _)| t.txid()).collect();
    assert_eq!(txids, vec![ok.txid()], "the template drops the transaction below 1%");
    assert_eq!(tmpl.total_fees, ok_fee);

    // No witness share: the miner gets its subsidy part and 80% of the fees.
    let split = core::witness_share::split_reward(tmpl.height, ok_fee, 0).unwrap();
    let sub = core::witness_share::split_subsidy(tmpl.height, 0);
    assert_eq!(split.miner, sub.miner + ok_fee * 8 / 10);
    assert_eq!(split.unissued, sub.unissued + ok_fee * 2 / 10, "the empty fee slots are burned");
    let cb = tmpl.miner_coinbase(vec![0xC1; 20]);
    assert_eq!(cb.outputs.len(), 1);
    assert_eq!(cb.outputs[0].value, split.miner);

    let mut b = template::assemble_block(&tmpl, cb.clone(), unix_now()).unwrap();
    mine(&mut b);
    accept(&n, &b).expect("a block paying 80% of the fees to the miner is valid");

    // A miner claiming 100% of the fees breaks the coinbase rule.
    let mut greedy = b.clone();
    greedy.transactions[0].outputs[0].value = sub.miner + ok_fee;
    assert_eq!(greedy.validate_coinbase_value(ok_fee), Err("miner coinbase output exceeds allowed amount"));
    let mut greedy_cb = cb;
    greedy_cb.outputs[0].value = sub.miner + ok_fee;
    assert!(template::assemble_block(&tmpl, greedy_cb, unix_now()).is_err());

    // A block carrying the low-fee transaction is invalid.
    let mut bad_tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    bad_tmpl.transactions = vec![(low.clone(), low_fee)];
    bad_tmpl.total_fees = low_fee;
    let bad_cb = bad_tmpl.miner_coinbase(vec![0xC2; 20]);
    let mut bad = template::assemble_block(&bad_tmpl, bad_cb, unix_now()).unwrap();
    mine(&mut bad);
    let err = accept(&n, &bad).unwrap_err();
    assert!(err.contains("below consensus minimum"), "{err}");
}
