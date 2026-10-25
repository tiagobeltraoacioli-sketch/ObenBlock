//! The data-driven consensus vectors (`reference/tx_vectors.json`,
//! `reference/block_vectors.json`; docs/testing/VECTORS.md) against
//! gnb-crypto's consensus functions, in this crate's own invocation (the real
//! pow limit: the node's dev feature `test-pow-limit` is off here).
//!
//! What this runner checks (the node runner, `node/tests/consensus_vectors.rs`,
//! runs the node's own connect path and mempool admission):
//!
//! * every recorded derived value (txid, wtxid, sizes, sighash v2/v3 digests,
//!   Merkle and witness roots, parent commitment, subsidy, block id) is what
//!   the code computes;
//! * transactions: strict decoding; the context-free per-transaction rules of
//!   a block, which must reject exactly the cases whose class is context-free
//!   (`context_free_expectation`, the output-side MoneyRange included); then
//!   the connect-time rules in the node's order through gnb-crypto's own
//!   functions: the id-committed ones (`core::check_coinbase_maturity`, the
//!   input sum with `limits::money_add`, `core::sighash::check_tx_version`,
//!   `limits::check_tx_money_range`, inputs >= outputs, the fee floor
//!   `tokenomics::min_tx_fee_sat` of the size with empty script_sigs,
//!   prevout scripts of the two output kinds), then the witness ones
//!   (`core::sighash::verify_tx_scripts` with the case's chain id,
//!   `core::check_min_fee`; re-audit B1-T13). The rules implemented in the node crate (BIP30,
//!   the same-block coinbase rule, duplicate and missing inputs:
//!   [`TX_DEFERRED_TO_NODE`]) are left to the node runner, explicitly: every
//!   case is either decided here or listed as deferred;
//! * blocks: decoding, `Block::validate_structure_without_pow_at`,
//!   `block_rules::check_block_hardened_at`, the pow limit, the GnB-SMH proof
//!   (`Block::validate_pow` under the case's activation height wherever the
//!   limit refuses the bits or the case is `pow: full`) and
//!   `limits::check_block_context_free`, which together must give exactly
//!   the context-free class (or pass, for a connect-time class or a valid
//!   block, whose final verdict is the node runner's).
//!
//! A case whose `activation_source` is `schedule` is evaluated under
//! `activation::hardening_activation_height_for_chain(chain)` (and
//! `validate_pow` under the process-wide height, the mainnet schedule here),
//! never under its recorded height.

#[path = "consensus_vectors_common/mod.rs"]
mod common;

use common::*;
use gnb_crypto::core::sighash::SighashV3Precomputed;
use gnb_crypto::core::{self, activation, block_rules, limits, Block, ChainId, Transaction, TxOutput};
use gnb_crypto::crypto;

fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}

/// Transaction classes whose rule is implemented in the node crate
/// (`node/src/accept.rs`: BIP30, the same-block coinbase rule of VAL-3,
/// duplicate and missing inputs), not in gnb-crypto. This runner checks
/// every rule before them and leaves the verdict to the node runner.
const TX_DEFERRED_TO_NODE: &[&str] = &[
    "bip30", "same-block-coinbase", "double-spend", "missing-input", "non-final", "bad-output-script",
];

enum Connect {
    /// The verdict of the connect-time rules this runner can evaluate.
    Decided(Result<(), String>),
    /// The case's class belongs to a rule of the node crate.
    Deferred,
}

/// The connect-time rules for the one transaction of a wrapper block, in the
/// node's order (`accept::check_tx_in_view_committed`, the coinbase value,
/// then `check_tx_witnesses`), through gnb-crypto's functions.
fn connect_core(c: &TxVector, tx: &Transaction, chain: ChainId, act: u64, expected: &str) -> Connect {
    let fail = |e: String| Connect::Decided(Err(classify(&e).to_string()));
    // BIP30 (checked for the whole block first) and VAL-3: accept.rs.
    if matches!(expected, "bip30" | "same-block-coinbase") {
        return Connect::Deferred;
    }
    // This chain's locktime and output-kind rules (node/src/blockval.rs),
    // evaluated after maturity once every prevout is found.
    if matches!(expected, "non-final" | "bad-output-script") {
        return Connect::Deferred;
    }
    // Coinbase maturity: below the activation the block's header height and
    // the coinbases' header heights; from it the block's DAG height and the
    // DAG heights of the coinbases' blocks (re-audit B1-T14).
    let hardened = block_rules::rules_active_at(c.height, act);
    let maturity = if hardened {
        core::check_coinbase_maturity(tx, c.dag_height, |txid| {
            c.prevouts.iter().find(|p| !p.block_coinbase && p.txid == *txid).and_then(|p| p.coinbase_dag_height)
        })
    } else {
        core::check_coinbase_maturity(tx, c.height, |txid| {
            c.prevouts.iter().find(|p| !p.block_coinbase && p.txid == *txid).and_then(|p| p.coinbase_height)
        })
    };
    if let Err(e) = maturity {
        return fail(e);
    }
    // Per input: duplicate outpoints and presence (accept.rs), then the
    // input sum's MoneyRange (`limits::money_add`).
    if matches!(expected, "double-spend" | "missing-input") {
        return Connect::Deferred;
    }
    // Below the activation the block's own coinbase outputs are spendable
    // in the block (at/after it VAL-3 rejected the spend above).
    let mut spent = Vec::with_capacity(tx.inputs.len());
    let mut total_in = 0u64;
    for inp in &tx.inputs {
        let coin = c.prevouts.iter().find(|p| {
            p.txid == inp.prev_txid && p.vout == inp.prev_index && !(p.block_coinbase && hardened)
        });
        let Some(coin) = coin else {
            return Connect::Decided(Err("missing-input".into()));
        };
        total_in = match limits::money_add(total_in, coin.amount) {
            Ok(t) => t,
            Err(e) => return fail(e),
        };
        spent.push(coin.out());
    }
    // The id-committed rest: the version rule, the values, the fee floor no
    // script_sig can lower (the size with every script_sig empty: one length
    // byte each) and prevout scripts of the two output kinds (no public key
    // hashes to another 20-byte script length, no policy witness spends a
    // non-policy script).
    if let Err(e) = core::sighash::check_tx_version(tx.version, c.height, act) {
        return fail(e);
    }
    let total_out = match limits::check_tx_money_range(tx) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    if total_in < total_out {
        return Connect::Decided(Err("inputs-below-outputs".into()));
    }
    let fee = total_in - total_out;
    if fee < core::tokenomics::min_tx_fee_for_sat(tx.wire_size(false) + tx.inputs.len(), core::paid_to_others_sat(tx, &spent)) {
        return Connect::Decided(Err("min-fee".into()));
    }
    if spent.iter().any(|o| core::policy::output_kind(&o.script_pubkey).is_none()) {
        return Connect::Decided(Err("pubkey-mismatch".into()));
    }
    // Then the witness rules: witnesses, public-key hashes, signatures, and
    // the size-based minimum fee.
    if let Err(e) = core::sighash::verify_tx_scripts(tx, &spent, chain, c.height, act) {
        return fail(e);
    }
    match core::check_min_fee(tx, fee, &spent) {
        Ok(()) => Connect::Decided(Ok(())),
        Err(e) => fail(e),
    }
}

#[test]
fn tx_vectors_core() {
    let v = load_tx_vectors();
    assert!(v.cases.len() >= 150, "{} tx cases", v.cases.len());
    assert_eq!(v.constants["wrapper_coinbase_script_sig"], hexs(WRAPPER_COINBASE_SCRIPT_SIG));
    let max_supply = max_supply_sat(&v.constants);
    let mut rep = Report::default();
    let mut ids = std::collections::HashSet::new();
    let mut decided = 0usize;
    let mut deferred: Vec<(String, String)> = Vec::new();
    for c in &v.cases {
        assert!(ids.insert(c.id.clone()), "duplicate id {}", c.id);
        let chain = chain_of(&c.network);
        let act = if c.schedule { activation::hardening_activation_height_for_chain(chain) } else { c.activation };
        let expected = want(&c.error);
        let Some(tx) = decode_tx(&c.bytes) else {
            rep.expect(&c.id, "strict decode", &expected, "decode");
            assert!(c.derived.is_null(), "{}: no derived values for undecodable bytes", c.id);
            decided += 1;
            continue;
        };
        // Derived values.
        let d = &c.derived;
        rep.expect(&c.id, "txid", d["txid"].as_str().unwrap(), &hexs(&tx.txid()));
        rep.expect(&c.id, "wtxid", d["wtxid"].as_str().unwrap(), &hexs(&tx.wtxid()));
        rep.expect(&c.id, "wire_size", &d["wire_size"].to_string(), &tx.wire_size(true).to_string());
        rep.expect(&c.id, "txid_preimage_size", &d["txid_preimage_size"].to_string(),
            &block_rules::txid_preimage_len(&tx).to_string());
        let spent: Option<Vec<TxOutput>> = tx.inputs.iter().map(|i| {
            c.prevouts.iter().find(|p| p.txid == i.prev_txid && p.vout == i.prev_index).map(Prevout::out)
        }).collect();
        let digests = d["digests"].as_array().unwrap();
        assert_eq!(digests.len(), tx.inputs.len(), "{}", c.id);
        for (i, dg) in digests.iter().enumerate() {
            rep.expect(&c.id, &format!("sighash_v2[{i}]"), dg["sighash_v2"].as_str().unwrap(), &hexs(&tx.sighash(i, chain)));
            let suite = dg["sighash_v3_suite"].as_u64().unwrap() as u16;
            let got = spent.as_ref()
                .map(|s| hexs(&SighashV3Precomputed::new(&tx, s).unwrap().digest(i, suite, chain).unwrap()))
                .unwrap_or_else(|| "null".into());
            rep.expect(&c.id, &format!("sighash_v3[{i}]"), dg["sighash_v3"].as_str().unwrap_or("null"), &got);
        }

        // The context-free per-transaction rules must reject exactly the
        // context-free classes.
        let block = wrapper_block(&tx, c.height, &c.prevouts);
        let cf = tx_context_free(&block, act).map_err(|e| classify(&e).to_string());
        let expected_cf = context_free_expectation(&expected, &block, max_supply);
        rep.expect(&c.id, "context-free rules", &expected_cf, &verdict(&cf));
        if cf.is_err() || expected_cf != "valid" {
            decided += 1;
            continue;
        }

        // The connect-time rules gnb-crypto implements.
        match connect_core(c, &tx, chain, act, &expected) {
            Connect::Decided(got) => {
                decided += 1;
                rep.expect(&c.id, "connect-time rules (gnb-crypto)", &expected, &verdict(&got));
            }
            Connect::Deferred => {
                assert!(TX_DEFERRED_TO_NODE.contains(&expected.as_str()), "{}: deferred class {expected}", c.id);
                deferred.push((c.id.clone(), expected.clone()));
            }
        }
    }
    assert_eq!(decided + deferred.len(), v.cases.len(), "every case is decided here or deferred to the node runner");
    eprintln!(
        "tx vectors (gnb-crypto): {decided} cases decided here, {} deferred to the node runner ({})",
        deferred.len(),
        deferred.iter().map(|(id, class)| format!("{id}: {class}")).collect::<Vec<_>>().join(", ")
    );
    rep.finish("tx vectors (gnb-crypto)");
}

#[test]
fn block_vectors_core() {
    let b = load_block_vectors();
    let max_supply = max_supply_sat(&b.constants);
    assert!(b.cases.len() >= 60, "{} block cases", b.cases.len());
    let mut rep = Report::default();
    let (mut decided, mut connect_deferred) = (0usize, 0usize);
    for c in &b.cases {
        let act = if c.schedule { activation::hardening_activation_height_for_chain(ChainId::Mainnet) } else { c.activation };
        let expected = want(&c.error);
        let block = match Block::from_wire_bytes(&c.bytes) {
            Ok(b) => b,
            Err(_) => {
                rep.expect(&c.id, "decode", &expected, "decode");
                decided += 1;
                continue;
            }
        };
        assert_eq!(block.height, c.height, "{}", c.id);
        assert_eq!(block.to_wire_bytes(), c.bytes, "{}: canonical encoding", c.id);
        let d = &c.derived;
        let ids: Vec<[u8; 32]> = block.transactions.iter().map(Transaction::txid).collect();
        rep.expect(&c.id, "block_hash", d["block_hash"].as_str().unwrap(), &hexs(&block.block_hash()));
        let txids: Vec<String> = d["txids"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        rep.expect(&c.id, "txids", &txids.join(","), &ids.iter().map(|i| hexs(i)).collect::<Vec<_>>().join(","));
        rep.expect(&c.id, "legacy_merkle_root", d["legacy_merkle_root"].as_str().unwrap(), &hexs(&Transaction::merkle_root(&block.transactions).0));
        rep.expect(&c.id, "tagged_merkle_root", d["tagged_merkle_root"].as_str().unwrap(), &hexs(&block_rules::tx_merkle_root(&block.transactions, true).0));
        rep.expect(&c.id, "witness_root", d["witness_root"].as_str().unwrap(), &hexs(&block_rules::witness_root(&block.transactions).0));
        rep.expect(&c.id, "parents_commitment", d["parents_commitment"].as_str().unwrap(), &hexs(&block_rules::parents_commitment(&block.header.parents)));
        rep.expect(&c.id, "subsidy", d["subsidy"].as_str().unwrap(), &core::tokenomics::block_subsidy_sat(block.height).to_string());
        rep.expect(&c.id, "wire_size", &d["wire_size"].to_string(), &block.wire_size().to_string());
        rep.expect(&c.id, "wire_size is the encoding", &d["wire_size"].to_string(), &c.bytes.len().to_string());
        // Re-audit B1-T0: the pre-activation measure is the wire length too.
        rep.expect(&c.id, "legacy size is the wire size", &d["wire_size"].to_string(), &block_rules::legacy_block_size(&block).to_string());

        if c.scope == "connect" {
            connect_deferred += 1; // connect-time rules only: node runner
            continue;
        }
        let got = (|| -> Result<(), String> {
            block.validate_structure_without_pow_at(act).map_err(|e| classify(e).to_string())?;
            block_rules::check_block_hardened_at(&block, act).map_err(|e| classify(e).to_string())?;
            if c.pow != "skip" {
                let limit = pow_limit(&block, act);
                // `validate_pow` under the case's activation height (the
                // process-wide schedule for a `schedule` case): it must agree,
                // without an evaluation, wherever the limit fails, and decide
                // the proof of a `pow: full` case. A workspace-wide build
                // unifies the node's dev feature `test-pow-limit`, which pins
                // `validate_pow`'s limit to 0x2100ffff: there only the
                // `pow: full` cases are evaluated.
                if core::TEST_POW_LIMIT {
                    if c.pow == "full" && limit.is_ok() && !block.validate_pow() {
                        return Err("bad-pow".into());
                    }
                } else if limit.is_err() || c.pow == "full" {
                    let _g = (!c.schedule).then(|| activation::scoped_override(c.activation));
                    let t = std::time::Instant::now();
                    let ok = block.validate_pow();
                    if limit.is_err() {
                        assert!(!ok, "{}: validate_pow accepted bits the pow-limit rule refuses", c.id);
                        assert!(t.elapsed() < std::time::Duration::from_millis(200), "{}: refused without an evaluation", c.id);
                    } else if !ok {
                        return Err("bad-pow".into());
                    }
                }
                limit.map_err(str::to_string)?;
            }
            limits::check_block_context_free(&block).map_err(|e| classify(&e).to_string())
        })();
        let expected_cf = context_free_expectation(&expected, &block, max_supply);
        rep.expect(&c.id, "context-free block rules", &expected_cf, &verdict(&got));
        if expected_cf == "valid" {
            connect_deferred += 1; // the final verdict is the connect-time rules': node runner
        } else {
            decided += 1;
        }
    }
    assert_eq!(decided + connect_deferred, b.cases.len());
    eprintln!("block vectors (gnb-crypto): {decided} verdicts decided by the context-free stages here, {connect_deferred} decided at connect time (node runner)");
    rep.finish("block vectors (gnb-crypto)");
}

/// The two files cover what docs/testing/VECTORS.md promises: both regimes,
/// every error class, both networks, and every version x regime.
#[test]
fn vector_coverage() {
    let v = load_tx_vectors();
    let has = |f: &dyn Fn(&TxVector) -> bool| v.cases.iter().any(f);
    for class in [
        "decode", "coinbase-format", "tx-64-bytes", "dust", "value-out-of-range", "bip30", "same-block-coinbase",
        "immature-coinbase", "double-spend", "missing-input", "bad-version", "witness-malformed",
        "witness-non-canonical", "pubkey-mismatch", "bad-signature", "inputs-below-outputs", "min-fee",
        "non-final", "bad-output-script",
    ] {
        assert!(has(&|c| c.error.as_deref() == Some(class)), "tx class {class} not covered");
    }
    for policy in [
        "non-standard-witness", "non-standard-version", "non-standard-suite", "non-standard-zero-value",
        "non-standard-no-outputs", "no-inputs", "already-confirmed", "missing-input",
    ] {
        assert!(has(&|c| c.policy_class.as_deref() == Some(policy)), "policy {policy} not covered");
    }
    // A non-canonical witness is relay policy below the activation and, for
    // version 3, the consensus canonical-witness rule from it (admission's
    // `check_witnesses_for_next_block`).
    assert!(has(&|c| c.policy_class.as_deref() == Some("non-standard-witness") && c.height < c.activation));
    assert!(has(&|c| c.policy_class.as_deref() == Some("witness-non-canonical") && c.height >= c.activation));
    // Its gate is the version rule's verdict (version 3 at/after the
    // activation), not the height alone nor the version alone: a version
    // other than 3 at/after the activation, and version 3 below it, keep the
    // policy class.
    let version = |c: &TxVector| decode_tx(&c.bytes).map(|t| t.version);
    assert!(has(&|c| c.policy_class.as_deref() == Some("non-standard-witness") && c.height >= c.activation
        && version(c).is_some_and(|v| v != 3)), "no non-standard witness on a version other than 3 at/after the activation");
    assert!(has(&|c| c.policy_class.as_deref() == Some("non-standard-witness") && c.height < c.activation
        && version(c) == Some(3)), "no non-standard witness on version 3 below the activation");
    // Consensus-invalid cases refused by an earlier admission rule, and
    // ones refused by the admission's own copy of the consensus rule.
    assert!(has(&|c| c.error.is_some() && c.policy_class.as_deref() != c.error.as_deref()));
    assert!(has(&|c| c.error.is_some() && c.policy_class.as_deref() == c.error.as_deref()));
    for net in ["mainnet", "testnet"] {
        for post in [false, true] {
            assert!(has(&|c| c.network == net && (c.height >= c.activation) == post), "{net} post={post}");
        }
        assert!(has(&|c| c.network == net && c.schedule), "{net}: no case under the network's own schedule");
    }
    for version in [0u32, 1, 2, 3, 4, u32::MAX] {
        for post in [false, true] {
            assert!(has(&|c| decode_tx(&c.bytes).is_some_and(|t| t.version == version) && (c.height >= c.activation) == post),
                "version {version} post={post}");
        }
    }
    // Raw carry-over keys and the 0x0002 suite appear in valid spends.
    let pk_len = |c: &TxVector| decode_tx(&c.bytes)
        .and_then(|t| Transaction::parse_script_sig(&t.inputs.first()?.script_sig).map(|(_, pk)| pk.len()));
    assert!(has(&|c| c.error.is_none() && pk_len(c) == Some(crypto::MLDSA_PUBKEY_LEN + crypto::falcon::pubkey_len())));
    assert!(has(&|c| c.error.is_none() && pk_len(c) == Some(4 + crypto::MLDSA_PUBKEY_LEN)));

    let b = load_block_vectors().cases;
    for class in [
        "decode", "bad-merkle-root", "coinbase-format", "tx-64-bytes", "cb-commitment-missing", "cb-commitment-tag",
        "cb-height", "cb-parents", "witness-commitment", "duplicate-tx", "block-size", "pow-limit", "bad-bits",
        "bad-pow", "value-out-of-range", "bip30", "coinbase-value", "coinbase-output-count", "same-block-coinbase",
        "witness-commitment-suffix", "bad-output-script", "witness-malformed",
    ] {
        assert!(b.iter().any(|c| c.error.as_deref() == Some(class)), "block class {class} not covered");
    }
    for post in [false, true] {
        assert!(b.iter().filter(|c| (c.height >= c.activation) == post && c.error.is_none()).count() >= 10);
    }
    // A mined proof at a target most outputs miss (bits at or below the
    // genesis target 0x1f0e9036: about 1 output in 4,500 meets it).
    let hard = |c: &&BlockVector| c.pow == "full" && Block::from_wire_bytes(&c.bytes).is_ok_and(|blk| blk.header.bits <= 0x1F0E_9036);
    assert!(b.iter().filter(hard).any(|c| c.error.is_none()), "no valid mined proof at the genesis target");
    assert!(b.iter().filter(hard).any(|c| c.error.as_deref() == Some("bad-pow")), "no failing proof at the genesis target");
    // Re-audit B1-T1: blocks whose outputs sum above MAX_SUPPLY_SAT with
    // every transaction in range are valid, chained in-block spends
    // included, on both sides of the activation.
    for id in ["value/block-output-total-above-max-supply", "value/chained-spends-output-total-above-max-supply"] {
        for r in ["pre", "post"] {
            let full = format!("{id}/{r}");
            assert!(b.iter().any(|c| c.id == full && c.error.is_none()), "{full} must be a valid case");
        }
    }
    // Re-audit B1-T0 / B2-T8: one block id at the size limit, carried with
    // two blue_score values, has the verdict of every other copy.
    for (id, err) in [("size/wire-exactly-1000000", None), ("size/wire-1000001-bincode-below", Some("block-size"))] {
        let ids: Vec<&BlockVector> = ["pre", "pre-blue-score-0", "pre-blue-score-max"].iter()
            .map(|t| {
                let full = match *t { "pre" => format!("{id}/pre"), t => format!("{id}-{}/pre", &t[4..]) };
                b.iter().find(|c| c.id == full).unwrap_or_else(|| panic!("{full} missing"))
            })
            .collect();
        let hash = |c: &BlockVector| Block::from_wire_bytes(&c.bytes).expect("decodes").block_hash();
        assert!(ids.iter().all(|c| c.error.as_deref() == err && hash(c) == hash(ids[0])), "{id}: one id, one verdict");
    }
    // Re-audit B1-T13: the connect order (the rules the block id commits to
    // for every transaction before any witness rule) is pinned.
    for r in ["pre", "post"] {
        let full = format!("order/bad-signature-then-overspend/{r}");
        assert!(b.iter().any(|c| c.id == full && c.error.as_deref() == Some("inputs-below-outputs")), "{full}");
        let full = format!("fee/zero-with-a-bad-signature/{r}");
        assert!(has(&|c| c.id == full && c.error.as_deref() == Some("min-fee")), "{full}");
    }
}
