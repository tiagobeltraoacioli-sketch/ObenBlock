//! P5-S: the conservative signature suite 0x0003 (SLH-DSA-SHAKE-128s AND
//! Falcon-1024), opt-in, activated at the second hardening height.
//!
//! Before P5-S every input needed ML-DSA-65 AND Falcon-1024, two lattice
//! schemes: one lattice break could forge both. Suite 0x0003 pairs Falcon-1024
//! with the hash-based SLH-DSA, so a forgery needs a lattice AND a hash break.
//! The consensus rule (docs/CONSENSUS.md, "Conservative suite 0x0003"):
//!
//! * below the second hardening height a suite-0x0003 key or signature is
//!   invalid exactly as before (an unknown suite: a non-canonical signature
//!   for a key-hash spend, a non-hybrid policy key for a policy spend);
//! * from it, a version-3 (sighash v3) input may carry a canonical suite-0x0003
//!   signature under a suite-0x0003 key, and a spend policy (or a revealed
//!   branch) may list suite-0x0003 keys next to hybrid ones.
//!
//! Every test moves both activations to small heights on its own thread
//! (`activation::scoped_override` / `scoped_override_v2`): the first hardening
//! (sighash v3) at `H1`, the second at `H2`. Blocks go through the REAL
//! pipeline (`fix_common::accept` -> `accept::accept_block`), mempool
//! admission and templates through their real entry points, and every verdict
//! comes from the ONE rule function they share
//! (`admission::verify_input_scripts_at`, `blockval`'s policy-spend rules).
//!
//! A conservative signature takes about 2.5 s in the dev profile, so each
//! test signs as little as it can and reuses one signed transaction across
//! heights (a signature does not depend on the height).

mod fix_common;
use fix_common::*;

use std::sync::atomic::{AtomicU64, Ordering};

use gnb::blockval::{self, SpendContext};
use gnb::consensus::BlockHash;
use gnb::core::sighash::{SighashV3Precomputed, TX_VERSION_V3};
use gnb::core::{self, activation, policy, Block, Transaction, TxInput, TxOutput};
use gnb::crypto::{self, SecretBytes};
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::template;
use sha3::{Digest, Sha3_256};

/// First hardening (sighash v3) height of these tests.
const H1: u64 = 0;
/// Second hardening height of these tests (the conservative suite).
const H2: u64 = 3;
const FEE: u64 = 100_000;
const SAT: u64 = 100_000_000;

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// A signing key of either suite.
struct Signer {
    pk: Vec<u8>,
    sk: SecretBytes,
    spk: Vec<u8>,
}

fn spk_of(pk: &[u8]) -> Vec<u8> {
    Sha3_256::digest(pk)[..20].to_vec()
}

/// A conservative (suite 0x0003) key from a seed byte (deterministic).
fn conservative(seed: u8) -> Signer {
    let (pk, sk) = crypto::generate_conservative_keypair_from_seed_secret(&[seed; 32]).unwrap();
    assert!(crypto::is_conservative_public_key(&pk));
    Signer { spk: spk_of(&pk), pk, sk }
}

/// A hybrid (suite 0x0001) key from a seed byte.
fn hybrid(seed: u8) -> Signer {
    let (pk, sk) = crypto::generate_keypair_from_seed_secret(&[seed; 32]).unwrap();
    Signer { spk: spk_of(&pk), pk, sk }
}

fn suite_of(pk: &[u8]) -> u16 {
    crypto::public_key_suite_under(pk, crypto::SuiteRules::HARDENING2).expect("a known suite")
}

fn fund(tag: u8, value: u64, spk: &[u8]) -> ([u8; 32], u32, TxOutput) {
    ([tag; 32], 0, out(value, spk))
}

fn unsigned(ins: &[([u8; 32], u32)], outs: Vec<TxOutput>) -> Transaction {
    Transaction {
        version: TX_VERSION_V3,
        inputs: ins.iter().map(|(t, i)| TxInput { prev_txid: *t, prev_index: *i, script_sig: vec![], sequence: u32::MAX }).collect(),
        outputs: outs,
        locktime: 0,
    }
}

/// A version-3 key-hash spend of `coin` by `k` (either suite).
fn key_spend(k: &Signer, coin: &([u8; 32], u32, TxOutput), outs: Vec<TxOutput>) -> Transaction {
    let mut tx = unsigned(&[(coin.0, coin.1)], outs);
    let pre = SighashV3Precomputed::new(&tx, std::slice::from_ref(&coin.2)).unwrap();
    let d = pre.digest(0, suite_of(&k.pk), core::node_chain_id()).unwrap();
    let sig = crypto::sign_bound_checked(&k.sk, &k.pk, &d).expect("sign");
    tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &k.pk);
    tx
}

/// A policy built straight to bytes (no tooling checks).
fn raw_policy(threshold: u8, pubkeys: Vec<Vec<u8>>) -> policy::SpendPolicy {
    policy::SpendPolicy { threshold, pubkeys, after: 0, older: 0 }
}

/// A version-3 spend of `coin` (locked to `pol`), `signers[i]` signing the
/// slot of key index `slot`, each under its own suite's digest.
fn policy_spend(pol: &policy::SpendPolicy, coin: &([u8; 32], u32, TxOutput), signers: &[(&Signer, u8)]) -> Transaction {
    let mut tx = unsigned(&[(coin.0, coin.1)], vec![out(coin.2.value - FEE, &[0x9A; 20])]);
    let pre = SighashV3Precomputed::new(&tx, std::slice::from_ref(&coin.2)).unwrap();
    let signatures = signers.iter()
        .map(|(k, slot)| {
            let d = pre.digest(0, suite_of(&k.pk), core::node_chain_id()).unwrap();
            (*slot, crypto::sign_bound_checked(&k.sk, &k.pk, &d).expect("sign"))
        })
        .collect();
    tx.inputs[0].script_sig = policy::PolicyWitness { policy: pol.clone(), signatures }.encode();
    tx
}

/// The node's full transaction rule set (`blockval::validate_tx_inputs`:
/// chain rules incl. the policy-spend rules, scripts, value, fee) for `tx`
/// spending `coin` in a block at `height`.
fn verdict(tx: &Transaction, coin: &([u8; 32], u32, TxOutput), height: u64) -> Result<u64, String> {
    let c = coin.clone();
    let lookup = move |t: &[u8; 32], i: u32| -> Result<Option<TxOutput>, String> {
        Ok((*t == c.0 && i == c.1).then(|| c.2.clone()))
    };
    let confirm = |_: &[u8; 32]| -> Result<Option<u64>, String> { Ok(Some(0)) };
    blockval::validate_tx_inputs(tx, &lookup, None, &SpendContext { height, confirm_height: &confirm })
}

/// The consensus input-script rule alone (`admission::verify_input_scripts`,
/// the function connect, reorg connect, templates and admission share).
fn scripts(tx: &Transaction, coin: &([u8; 32], u32, TxOutput), height: u64) -> Result<(), String> {
    admission::verify_input_scripts(tx, std::slice::from_ref(&coin.2), height)
}

static TAG: AtomicU64 = AtomicU64::new(0);

fn dag_height(n: &Node, b: &BlockHash) -> u64 {
    n.dag.read().get_block_data(b).unwrap().height
}

fn fee_of(n: &Node, t: &Transaction) -> u64 {
    let ins: u64 = t.inputs.iter()
        .map(|i| n.store.get_utxo(&i.prev_txid, i.prev_index).unwrap().map(|o| o.value).unwrap_or(0))
        .sum();
    ins.saturating_sub(t.outputs.iter().map(|o| o.value).sum())
}

/// A child of `parent` carrying `txs`, its coinbase claiming subsidy + fees.
fn child_where(n: &Node, parent: BlockHash, txs: Vec<Transaction>, pred: impl Fn(&BlockHash) -> bool) -> Block {
    let h = dag_height(n, &parent) + 1;
    let fees: u64 = txs.iter().map(|t| fee_of(n, t)).sum();
    let tag = format!("fix-p5s-{}-{}", h, TAG.fetch_add(1, Ordering::Relaxed));
    let mut all = vec![coinbase(&tag, core::tokenomics::block_subsidy_sat(h) + fees, vec![0xC0; 20])];
    all.extend(txs);
    mk_block_where(n, vec![parent], all, pred)
}

fn extend(n: &Node, txs: Vec<Transaction>) -> Result<BlockHash, String> {
    let b = child_where(n, sel_tip(n).unwrap(), txs, |_| true);
    accept(n, &b)
}

fn tip_height(n: &Node) -> u64 {
    dag_height(n, &sel_tip(n).unwrap())
}

fn advance_to(n: &Node, height: u64) {
    while tip_height(n) < height {
        extend(n, vec![]).unwrap();
    }
}

fn next_height(n: &Node) -> u64 {
    let d = n.dag.read();
    admission::pool_next_height(&d, &n.store, &n.mempool)
}

fn admit(n: &Node, tx: &Transaction) -> Result<[u8; 32], AdmissionError> {
    admission::admit(&n.store, &n.mempool, tx.clone(), &AdmissionPolicy::relay(next_height(n)))
}

fn spent(n: &Node, f: &([u8; 32], u32, TxOutput)) -> bool {
    n.store.get_utxo(&f.0, f.1).unwrap().is_none()
}

// ── Single-key spends ────────────────────────────────────────────────────────

/// A key-hash output locked to a conservative key: its spend is invalid
/// below the second hardening height with exactly the old verdict (the
/// signature's suite is unknown: a non-canonical witness under sighash v3),
/// also when the upgrade is never scheduled, and valid from the height on.
#[test]
fn a_conservative_key_spend_is_invalid_below_hardening2_and_valid_from_it() {
    let _h1 = activation::scoped_override(H1);
    let c = conservative(0x31);
    let coin = fund(0x31, 2 * SAT, &c.spk);
    let tx = key_spend(&c, &coin, vec![out(2 * SAT - FEE, &[0x77; 20])]);
    {
        let _never = activation::scoped_override_v2(activation::NEVER);
        for h in [1, H2, 1_000_000] {
            let e = verdict(&tx, &coin, h).expect_err("never scheduled: invalid");
            assert!(e.contains("non-canonical signature encoding"), "{h}: {e}");
            assert!(scripts(&tx, &coin, h).is_err());
        }
    }
    let _h2 = activation::scoped_override_v2(H2);
    let e = verdict(&tx, &coin, H2 - 1).expect_err("one block below hardening 2");
    assert!(e.contains("input 0: non-canonical signature encoding"), "the old verdict: {e}");
    for h in [H2, H2 + 1, 1_000_000] {
        assert_eq!(verdict(&tx, &coin, h), Ok(FEE), "valid from hardening 2 (height {h})");
        assert_eq!(scripts(&tx, &coin, h), Ok(()));
    }
    // The signature commits to the suite: relabelling the envelope (or the
    // digest's suite) breaks it; another chain id breaks it.
    let mut relabel = tx.clone();
    let (sig, pk) = Transaction::parse_script_sig_exact(&tx.inputs[0].script_sig).unwrap();
    let mut s = sig.to_vec();
    s[2] = 0x01;
    relabel.inputs[0].script_sig = Transaction::build_script_sig(&s, pk);
    assert!(verdict(&relabel, &coin, H2).is_err());
}

/// Malformed, oversized and trailing-byte conservative witnesses are refused
/// from the second hardening height (and below it, as before).
#[test]
fn malformed_conservative_witnesses_are_rejected() {
    let _h1 = activation::scoped_override(H1);
    let _h2 = activation::scoped_override_v2(H2);
    let c = conservative(0x32);
    let coin = fund(0x32, 2 * SAT, &c.spk);
    let tx = key_spend(&c, &coin, vec![out(2 * SAT - FEE, &[0x78; 20])]);
    assert_eq!(verdict(&tx, &coin, H2), Ok(FEE), "control");
    let (sig, pk) = Transaction::parse_script_sig_exact(&tx.inputs[0].script_sig).unwrap();
    let (sig, pk) = (sig.to_vec(), pk.to_vec());
    let split = crypto::SUITE_HEADER_LEN + crypto::slhdsa::SIGNATURE_LEN;
    let with = |s: Vec<u8>, k: Vec<u8>| {
        let mut t = tx.clone();
        t.inputs[0].script_sig = Transaction::build_script_sig(&s, &k);
        t
    };
    let cases: Vec<(&str, Transaction)> = vec![
        ("trailing byte after the witness", { let mut t = tx.clone(); t.inputs[0].script_sig.push(0); t }),
        ("trailing byte after the signature", with({ let mut s = sig.clone(); s.push(0); s }, pk.clone())),
        ("truncated signature", with(sig[..sig.len() - 1].to_vec(), pk.clone())),
        ("SLH-DSA half one byte short", with({ let mut s = sig[..split - 1].to_vec(); s.extend_from_slice(&sig[split..]); s }, pk.clone())),
        ("oversized signature", with({ let mut s = sig.clone(); s.resize(crypto::CONSERVATIVE_MAX_SIGNATURE_LEN + 1, 0); s }, pk.clone())),
        ("no Falcon half", with(sig[..split].to_vec(), pk.clone())),
        ("signature without its envelope", with(sig[crypto::SUITE_HEADER_LEN..].to_vec(), pk.clone())),
        ("header-only signature", with(sig[..crypto::SUITE_HEADER_LEN].to_vec(), pk.clone())),
    ];
    for (what, t) in &cases {
        assert!(verdict(t, &coin, H2).is_err(), "{what}");
        assert!(verdict(t, &coin, H2 - 1).is_err(), "{what} (below hardening 2)");
    }
    // A public key with a trailing byte (an output committed to that exact
    // byte string): not a conservative key.
    let mut long_pk = pk.clone();
    long_pk.push(0);
    let lcoin = fund(0x33, 2 * SAT, &spk_of(&long_pk));
    let mut t = unsigned(&[(lcoin.0, 0)], vec![out(2 * SAT - FEE, &[0x78; 20])]);
    t.inputs[0].script_sig = Transaction::build_script_sig(&sig, &long_pk);
    let e = verdict(&t, &lcoin, H2).unwrap_err();
    assert!(e.contains("invalid signature"), "{e}");
}

// ── Policy spends (multisig, trees) ──────────────────────────────────────────

/// A 2-of-3 over [hybrid, conservative, conservative] spent by the hybrid
/// key and one conservative key; a 1-of-2 [hybrid, conservative] spent by
/// the hybrid key ALONE. Below the second hardening height both are invalid
/// with the old verdict (a policy key must be hybrid: the revealed policy
/// does not decode), even the one no conservative key signs; from it both are
/// valid. The PF-4 identity rule covers the new keys: a conservative key
/// listed twice is refused, and its identity is itself (no second encoding).
#[test]
fn policies_may_list_conservative_keys_from_hardening2() {
    let _h1 = activation::scoped_override(H1);
    let k = hybrid(0x41);
    let c1 = conservative(0x42);
    let c2 = conservative(0x43);
    let mixed = raw_policy(2, vec![k.pk.clone(), c1.pk.clone(), c2.pk.clone()]);
    let coin = fund(0x41, 5 * SAT, &mixed.script_pubkey());
    let tx = policy_spend(&mixed, &coin, &[(&k, 0), (&c1, 1)]);
    let either = raw_policy(1, vec![k.pk.clone(), c1.pk.clone()]);
    let ecoin = fund(0x42, 5 * SAT, &either.script_pubkey());
    let etx = policy_spend(&either, &ecoin, &[(&k, 0)]);
    for (h2, h, valid) in [(activation::NEVER, 5, false), (H2, H2 - 1, false), (H2, H2, true), (H2, 1_000_000, true)] {
        let _h2 = activation::scoped_override_v2(h2);
        for (t, c) in [(&tx, &coin), (&etx, &ecoin)] {
            match verdict(t, c, h) {
                Ok(fee) => {
                    assert!(valid, "hardening 2 at {h2}, height {h}: accepted below the height");
                    assert_eq!(fee, FEE);
                }
                Err(e) => {
                    assert!(!valid, "hardening 2 at {h2}, height {h}: {e}");
                    assert!(e.contains("malformed policy witness at input 0: NotHybridKey(1)"), "the old verdict: {e}");
                }
            }
        }
    }
    let _h2 = activation::scoped_override_v2(H2);
    // A conservative key twice in one policy (PF-4 identity rule: the same
    // bytes, the same identity).
    assert_eq!(policy::key_identity(&c1.pk).as_ref(), c1.pk.as_slice(), "a conservative key is its own identity");
    let twice = raw_policy(1, vec![c1.pk.clone(), c1.pk.clone()]);
    let tcoin = fund(0x43, 5 * SAT, &twice.script_pubkey());
    let ttx = policy_spend(&twice, &tcoin, &[(&k, 0)]); // wrong signer on purpose: refused before any signature
    let e = verdict(&ttx, &tcoin, H2).unwrap_err();
    assert!(e.contains("DuplicateKey"), "{e}");
    // A conservative key's raw body (no envelope) is not a policy key.
    let raw = raw_policy(1, vec![c1.pk[crypto::SUITE_HEADER_LEN..].to_vec()]);
    let rcoin = fund(0x44, 5 * SAT, &raw.script_pubkey());
    let mut rtx = unsigned(&[(rcoin.0, 0)], vec![out(5 * SAT - FEE, &[0x9A; 20])]);
    rtx.inputs[0].script_sig = policy::PolicyWitness { policy: raw.clone(), signatures: vec![(0, vec![0; 16])] }.encode();
    let e = verdict(&rtx, &rcoin, H2).unwrap_err();
    assert!(e.contains("NotHybridKey(0)"), "{e}");
    // Each signature is checked under its key's suite: a conservative slot
    // filled with the hybrid key's signature fails.
    let wrong = policy_spend(&mixed, &coin, &[(&k, 0), (&k, 1)]);
    let e = verdict(&wrong, &coin, H2).unwrap_err();
    assert!(e.contains("invalid signature by policy key 1"), "{e}");
}

/// A policy-tree branch may list conservative keys from the second
/// hardening height (branches are active from the PoWit height).
#[test]
fn a_policy_tree_branch_with_conservative_keys() {
    let _h1 = activation::scoped_override(H1);
    let k = hybrid(0x51);
    let c = conservative(0x52);
    let release = raw_policy(1, vec![c.pk.clone()]);
    let recovery = raw_policy(1, vec![k.pk.clone()]);
    let tree = policy::PolicyTree::new(vec![release.clone(), recovery]).unwrap();
    let coin = fund(0x51, 5 * SAT, &tree.script_pubkey());
    let mut tx = policy_spend(&release, &coin, &[(&c, 0)]);
    let w = policy::PolicyWitness::decode_under(&tx.inputs[0].script_sig, crypto::SuiteRules::HARDENING2).unwrap();
    tx.inputs[0].script_sig = policy::BranchWitness {
        n_branches: 2, index: 0, path: tree.path(0), branch: release, signatures: w.signatures,
    }.encode();
    let powit = core::powit_height();
    let h2 = powit + 1;
    let _h2 = activation::scoped_override_v2(h2);
    let e = verdict(&tx, &coin, h2 - 1).unwrap_err();
    assert!(e.contains("NotHybridKey(0)"), "the old verdict: {e}");
    assert_eq!(verdict(&tx, &coin, h2), Ok(FEE));
}

// ── The node: mempool, connect, templates, reorg connect, the cache ─────────

/// Mempool admission, block connect and the template apply the rule at the
/// height they decide for. Below the second hardening height a conservative
/// spend is refused by admission as a POLICY refusal (no penalty: a peer one
/// block ahead across the height relays it honestly; it fails before any
/// signature work) and invalid in a block; from it, admitted, mined by the
/// template and connected.
#[test]
fn mempool_connect_and_template_follow_the_second_hardening_height() {
    let _h1 = activation::scoped_override(H1);
    let c = conservative(0x61);
    let coin = fund(0x61, 2 * SAT, &c.spk);
    let tx = key_spend(&c, &coin, vec![out(2 * SAT - FEE, &[0x62; 20])]);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    for (h2, valid) in [(activation::NEVER, false), (2, false), (1, true)] {
        let _h2 = activation::scoped_override_v2(h2);
        let n = node_with(&genesis, std::slice::from_ref(&coin));
        assert_eq!(next_height(&n), 1);
        match admit(&n, &tx) {
            Ok(_) => assert!(valid, "admitted below hardening 2 ({h2})"),
            Err(AdmissionError::NonStandard(m)) => {
                assert!(!valid, "{h2}: {m}");
                assert!(m.contains("conservative"), "{m}");
            }
            Err(e) => panic!("hardening 2 at {h2}: {e:?}"),
        }
        // Connect: the block at height 1 carrying it.
        let b = child_where(&n, gh, vec![tx.clone()], |_| true);
        let connected = accept(&n, &b);
        assert_eq!(connected.is_ok(), valid, "connect, hardening 2 at {h2}: {connected:?}");
        assert_eq!(spent(&n, &coin), valid);
    }
    // Templates: pooled for a block at the height, mined, connected.
    let _h2 = activation::scoped_override_v2(1);
    let n = node_with(&genesis, std::slice::from_ref(&coin));
    let txid = admit(&n, &tx).expect("admitted at hardening 2");
    let reserve = template::miner_coinbase(u64::MAX, u64::MAX, vec![0xCB; 20]).actual_size();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, reserve).unwrap();
    assert!(tmpl.transactions.iter().any(|(t, _)| t.txid() == txid), "the template includes it");
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    let mut block = template::assemble_block(&tmpl, cb, unix_now()).expect("template self-check");
    while !block.validate_pow() {
        block.header.nonce += 1;
    }
    accept(&n, &block).expect("the template block is valid");
    assert!(spent(&n, &coin));
}

/// A template for a block below the second hardening height leaves a pooled
/// conservative spend out (pooled while the next block was at the height,
/// e.g. after a reorg to a shorter chain): the self-check applies the rule.
#[test]
fn a_template_below_hardening2_skips_a_conservative_spend() {
    let _h1 = activation::scoped_override(H1);
    let c = conservative(0x63);
    let coin = fund(0x63, 2 * SAT, &c.spk);
    let tx = key_spend(&c, &coin, vec![out(2 * SAT - FEE, &[0x64; 20])]);
    let n = node_with(&mk_genesis(unix_now() - 10_000), std::slice::from_ref(&coin));
    let txid = {
        let _h2 = activation::scoped_override_v2(1);
        admit(&n, &tx).expect("pooled for a block at hardening 2")
    };
    let _h2 = activation::scoped_override_v2(2);
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.height, 1);
    assert!(!tmpl.transactions.iter().any(|(t, _)| t.txid() == txid), "skipped below hardening 2");
}

/// Reorg connect runs the same rule: a fork block below H2 carrying a
/// conservative spend is disqualified when its chain becomes heavier; a fork
/// carrying it at H2 wins the reorg.
#[test]
fn reorg_connect_applies_the_conservative_suite_rule() {
    let _h1 = activation::scoped_override(H1);
    let _h2 = activation::scoped_override_v2(H2);
    let c = conservative(0x65);
    let coin = fund(0x65, 2 * SAT, &c.spk);
    let tx = key_spend(&c, &coin, vec![out(2 * SAT - FEE, &[0x66; 20])]);
    let n = node_with(&mk_genesis(unix_now() - 10_000), std::slice::from_ref(&coin));
    advance_to(&n, H2 - 2);
    let t = sel_tip(&n).unwrap();
    // Main chain: an empty block at H2 - 1.
    let x = child_where(&n, t, vec![], |h| h[0] >= 0xC0);
    let xh = x.block_hash();
    accept(&n, &x).unwrap();
    // Fork Y: the conservative spend at H2 - 1 (invalid there); stored as a
    // fork-loser, then made heavier by Y2.
    let y = child_where(&n, t, vec![tx.clone()], |h| *h < xh);
    let yh = accept(&n, &y).expect("stored as a fork-loser, not validated yet");
    assert_eq!(applied_tip(&n), Some(xh));
    let y2 = child_where(&n, yh, vec![], |_| true);
    let err = accept(&n, &y2).unwrap_err();
    assert!(err.contains("invalid"), "{err}");
    assert_eq!(applied_tip(&n), Some(xh), "the invalid fork was disqualified on reorg connect");
    assert!(!spent(&n, &coin));
    // Fork Z: an empty block at H2 - 1, then the spend at H2, wins.
    let z = child_where(&n, t, vec![], |h| *h < xh);
    let zh = accept(&n, &z).unwrap();
    let z2 = child_where(&n, zh, vec![tx.clone()], |_| true);
    let z2h = accept(&n, &z2).expect("the spend at hardening 2");
    assert_eq!(applied_tip(&n), Some(z2h), "reorg to the fork carrying the valid spend");
    assert!(spent(&n, &coin));
}

/// The verified-signature cache never answers across the second hardening
/// height: a conservative spend verified (and cached) at H2 is invalid at
/// H2 - 1 and when the upgrade is never scheduled.
#[test]
fn the_signature_cache_is_keyed_by_the_suite_rules() {
    let _h1 = activation::scoped_override(H1);
    let _h2 = activation::scoped_override_v2(H2);
    let c = conservative(0x67);
    let coin = fund(0x67, 2 * SAT, &c.spk);
    let tx = key_spend(&c, &coin, vec![out(2 * SAT - FEE, &[0x68; 20])]);
    scripts(&tx, &coin, H2).expect("valid at hardening 2");
    assert!(admission::signatures_cached(&tx, std::slice::from_ref(&coin.2), H2), "cached");
    assert!(!admission::signatures_cached(&tx, std::slice::from_ref(&coin.2), H2 - 1), "not across the height");
    assert!(scripts(&tx, &coin, H2 - 1).is_err());
    {
        let _never = activation::scoped_override_v2(activation::NEVER);
        assert!(!admission::signatures_cached(&tx, std::slice::from_ref(&coin.2), H2));
        assert!(scripts(&tx, &coin, H2).is_err(), "same height, never scheduled");
    }
    scripts(&tx, &coin, H2 + 1).expect("still valid in its own regime");
}

/// Relay pricing: a conservative signature costs the measured multiple of a
/// hybrid verification in the gossip signature budget (relay tokens).
#[test]
fn the_relay_budget_prices_conservative_signatures_by_verification_cost() {
    use gnb::mempool::relay;
    let _h1 = activation::scoped_override(H1);
    let c = conservative(0x69);
    let k = hybrid(0x69);
    let ccoin = fund(0x69, 2 * SAT, &c.spk);
    let hcoin = fund(0x6A, 2 * SAT, &k.spk);
    let ctx = key_spend(&c, &ccoin, vec![out(2 * SAT - FEE, &[0x6B; 20])]);
    let htx = key_spend(&k, &hcoin, vec![out(2 * SAT - FEE, &[0x6B; 20])]);
    let cost = |t: &Transaction| relay::signature_gate_cost(t, t.to_wire_bytes(true).len(), 1, 0);
    assert_eq!(relay::input_signature_count(&ctx.inputs[0].script_sig), 1);
    assert_eq!(relay::input_verification_tokens(&htx.inputs[0].script_sig), 1);
    assert_eq!(relay::input_verification_tokens(&ctx.inputs[0].script_sig), relay::CONSERVATIVE_VERIFY_TOKENS);
    assert!(cost(&ctx) >= cost(&htx) - 1 + relay::CONSERVATIVE_VERIFY_TOKENS, "{} vs {}", cost(&ctx), cost(&htx));
    // A policy witness: per signature, by its suite.
    let mixed = raw_policy(2, vec![k.pk.clone(), c.pk.clone()]);
    let pcoin = fund(0x6C, 5 * SAT, &mixed.script_pubkey());
    let mut p = unsigned(&[(pcoin.0, 0)], vec![out(5 * SAT - FEE, &[0x6B; 20])]);
    let sig_c = Transaction::parse_script_sig_exact(&ctx.inputs[0].script_sig).unwrap().0.to_vec();
    let sig_h = Transaction::parse_script_sig_exact(&htx.inputs[0].script_sig).unwrap().0.to_vec();
    p.inputs[0].script_sig = policy::PolicyWitness { policy: mixed, signatures: vec![(0, sig_h), (1, sig_c)] }.encode();
    assert_eq!(relay::input_verification_tokens(&p.inputs[0].script_sig), 1 + relay::CONSERVATIVE_VERIFY_TOKENS);
}

/// The assumed-valid path (P5-G, `admission::check_input_scripts_without_signatures_at`,
/// which a block vouched for by the assumed-valid block runs instead of the
/// full input-script rule) applies the same witness rules of the block's
/// height: a conservative spend is refused below the second hardening height
/// and accepted from it, exactly like the full path. Without the suite rules
/// there, an assumed-valid block carrying a valid conservative spend would be
/// refused (the integration of P5-G and P5-S).
#[test]
fn the_assumed_valid_path_follows_the_conservative_suite_rule() {
    let _h1 = activation::scoped_override(H1);
    let _h2 = activation::scoped_override_v2(H2);
    let c = conservative(0x3a);
    let coin = fund(0x3a, 2 * SAT, &c.spk);
    let tx = key_spend(&c, &coin, vec![out(2 * SAT - FEE, &[0x78; 20])]);
    let assumed = |h: u64| {
        admission::check_input_scripts_without_signatures_at(&tx, std::slice::from_ref(&coin.2), h, H1)
    };
    assert!(assumed(H2 - 1).is_err(), "below hardening 2 the suite is unknown on the assumed path too");
    assert!(scripts(&tx, &coin, H2 - 1).is_err());
    for h in [H2, H2 + 1, 1_000_000] {
        assert_eq!(assumed(h), Ok(()), "assumed path at {h}");
        assert_eq!(scripts(&tx, &coin, h), Ok(()), "full path at {h}");
    }
}
