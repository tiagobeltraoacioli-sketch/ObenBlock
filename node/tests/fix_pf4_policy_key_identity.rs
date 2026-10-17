//! Phase-5 PF-4: the distinct-keys rule of spend policies was bypassed by the
//! two encodings of one hybrid key.
//!
//! A policy key is accepted as the enveloped hybrid key (`B1 0C 01 00 ‖
//! mldsa_pk ‖ falcon_pk`, 3,749 bytes) or as the raw hybrid key of a genesis
//! carry-over wallet (`mldsa_pk ‖ falcon_pk`, 3,745 bytes), and
//! `SpendPolicy::check` compared the BYTES of the keys. So a policy listing
//! one key twice, once raw and once enveloped, passed as "2 distinct keys";
//! under sighash v3 (`crypto::verify_bound`, which accepts either encoding
//! and does not bind it) ONE signature by that key verifies at both indexes.
//! A "2-of-2" or "2-of-3" whose participants see distinct keys is then
//! spendable by one of them alone (or by a coordinator who slipped its key in
//! twice).
//!
//! The fix (second hardening upgrade, `activation::hardening2_*`): from the
//! hardening-2 height a policy spend is invalid when two keys of the revealed
//! policy (or branch) have the same identity (`core::policy::key_identity`:
//! the enveloped encoding); below it the old verdict is reproduced exactly.
//! The rule lives in `blockval::check_policy_spends_with_confirmations`, the
//! one function block connect, mempool admission and the template self-check
//! call. Wallet / CLI tooling (`SpendPolicy::new`) refuses to build such a
//! policy at every height. Bitcoin Core's analogue: one encoding per key in
//! a script context (segwit v0 standardness of compressed keys, BIP340
//! x-only keys in tapscript) and miniscript's duplicate-key sanity check.

mod fix_common;
use fix_common::*;

use gnb::blockval::{self, SpendContext};
use gnb::core::{self, activation, policy, Transaction, TxInput, TxOutput};
use gnb::crypto;
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::mempool::relay::TxRelay;
use gnb::network::GossipVerdict;
use libp2p::PeerId;

/// Second hardening height used by the boundary tests.
const H2: u64 = 40;

/// The raw (pre-envelope) encoding of an enveloped hybrid public key.
fn raw_of(enveloped: &[u8]) -> Vec<u8> {
    assert_eq!(crypto::public_key_suite(enveloped), Some(crypto::SUITE_MLDSA65_FALCON1024));
    enveloped[crypto::SUITE_HEADER_LEN..].to_vec()
}

/// A policy built the way an attacker writes it: straight to bytes, past the
/// tooling constructor.
fn policy_of(threshold: u8, pubkeys: Vec<Vec<u8>>) -> policy::SpendPolicy {
    let p = policy::SpendPolicy { threshold, pubkeys, after: 0, older: 0 };
    // The consensus decoder accepts it (as every node below hardening 2 does).
    policy::SpendPolicy::decode(&p.encode()).expect("consensus decoding accepts both encodings")
}

/// A version-3 spend of `coin` (locked to `pol`) with `signers[i]` signing
/// the slot of key index `slots[i]`. Paying 4,000,000 to a key hash.
fn spend(pol: &policy::SpendPolicy, coin: &([u8; 32], u32, TxOutput), signers: &[(&Key, u8)]) -> Transaction {
    let mut tx = Transaction {
        version: core::sighash::TX_VERSION_V3,
        inputs: vec![TxInput { prev_txid: coin.0, prev_index: coin.1, script_sig: vec![], sequence: u32::MAX }],
        outputs: vec![out(4_000_000, &[0x9A; 20])],
        locktime: 0,
    };
    let pre = core::sighash::SighashV3Precomputed::new(&tx, std::slice::from_ref(&coin.2)).unwrap();
    let digest = pre.digest(0, crypto::SUITE_MLDSA65_FALCON1024, core::node_chain_id()).unwrap();
    let signatures = signers.iter()
        .map(|(k, slot)| (*slot, crypto::sign_bound(&k.sk, &digest).expect("sign")))
        .collect();
    tx.inputs[0].script_sig = policy::PolicyWitness { policy: pol.clone(), signatures }.encode();
    tx
}

/// The node's full transaction rule set (`blockval::validate_tx_inputs`:
/// chain rules incl. the policy-spend rules, scripts, value, fee) at `height`.
fn verdict(tx: &Transaction, coin: &([u8; 32], u32, TxOutput), height: u64) -> Result<u64, String> {
    let c = coin.clone();
    let lookup = move |t: &[u8; 32], i: u32| -> Result<Option<TxOutput>, String> {
        Ok((*t == c.0 && i == c.1).then(|| c.2.clone()))
    };
    let confirm = |_: &[u8; 32]| -> Result<Option<u64>, String> { Ok(Some(0)) };
    blockval::validate_tx_inputs(tx, &lookup, None, &SpendContext { height, confirm_height: &confirm })
}

/// The finding's attack: a 2-of-2 over [K raw, K enveloped] spent with ONE
/// signature by K at both indexes. Accepted under the first hardening rules
/// (sighash v3) below the hardening-2 height, exactly as before; refused from
/// it. An honest 2-of-2 over two distinct keys is valid on both sides.
#[test]
fn one_key_in_two_encodings_cannot_fill_two_slots_from_hardening2() {
    let _h1 = activation::scoped_override(0); // sighash v3 at every height
    let k = key();
    let l = key();
    let twin = policy_of(2, vec![raw_of(&k.pk), k.pk.clone()]);
    let coin = ([0xF4u8; 32], 0u32, out(5_000_000, &twin.script_pubkey()));
    let attack = spend(&twin, &coin, &[(&k, 0), (&k, 1)]);
    // Both slots are filled by K alone (two signatures of the same digest).
    let w = policy::PolicyWitness::decode(&attack.inputs[0].script_sig).unwrap();
    assert_eq!(w.signatures.iter().map(|s| s.0).collect::<Vec<_>>(), vec![0, 1]);

    // Old regime (hardening 2 never active): the bypass verifies, as on
    // every release so far. This pins the pre-activation verdict.
    {
        let _h2 = activation::scoped_override_v2(activation::NEVER);
        assert_eq!(verdict(&attack, &coin, 1), Ok(1_000_000), "old regime reproduced");
        assert_eq!(verdict(&attack, &coin, 1_000_000), Ok(1_000_000));
    }
    // Boundary: valid at H2 - 1, invalid at H2 and above.
    let _h2 = activation::scoped_override_v2(H2);
    assert_eq!(verdict(&attack, &coin, H2 - 1), Ok(1_000_000), "below hardening 2: unchanged");
    for h in [H2, H2 + 1, 1_000_000] {
        let e = verdict(&attack, &coin, h).expect_err("one key cannot fill two slots");
        assert!(e.contains("same key"), "{h}: {e}");
    }
    // The enveloped key twice was always refused (byte-identical).
    assert_eq!(policy::SpendPolicy::decode(&policy::SpendPolicy {
        threshold: 1, pubkeys: vec![k.pk.clone(), k.pk.clone()], after: 0, older: 0 }.encode()),
        Err(policy::PolicyError::DuplicateKey));

    // Honest policies stay valid on both sides: two distinct keys, and a
    // carry-over (raw) key next to another key.
    let honest = policy_of(2, vec![k.pk.clone(), l.pk.clone()]);
    let hcoin = ([0xF5u8; 32], 0u32, out(5_000_000, &honest.script_pubkey()));
    let ok = spend(&honest, &hcoin, &[(&k, 0), (&l, 1)]);
    let mixed = policy_of(2, vec![raw_of(&k.pk), l.pk.clone()]);
    let mcoin = ([0xF6u8; 32], 0u32, out(5_000_000, &mixed.script_pubkey()));
    let mixed_ok = spend(&mixed, &mcoin, &[(&k, 0), (&l, 1)]);
    for h in [H2 - 1, H2, 1_000_000] {
        assert_eq!(verdict(&ok, &hcoin, h), Ok(1_000_000), "honest 2-of-2 at {h}");
        assert_eq!(verdict(&mixed_ok, &mcoin, h), Ok(1_000_000), "raw + other key at {h}");
    }

    // A 1-of-2 over the twin encodings: the policy itself is malformed from
    // hardening 2 (its key list names one key twice), whatever the
    // threshold: refused as well.
    let one_of_twin = policy_of(1, vec![raw_of(&k.pk), k.pk.clone()]);
    let ocoin = ([0xF7u8; 32], 0u32, out(5_000_000, &one_of_twin.script_pubkey()));
    let single = spend(&one_of_twin, &ocoin, &[(&k, 1)]);
    assert_eq!(verdict(&single, &ocoin, H2 - 1), Ok(1_000_000));
    assert!(verdict(&single, &ocoin, H2).unwrap_err().contains("same key"));
}

/// The same rule on a policy-tree branch: the revealed branch's keys are
/// checked like a single policy's (branches are independent; the same key
/// in two branches is fine).
#[test]
fn a_revealed_branch_is_checked_like_a_policy() {
    let _h1 = activation::scoped_override(0);
    let _h2 = activation::scoped_override_v2(H2);
    let k = key();
    let l = key();
    let twin = policy_of(2, vec![raw_of(&k.pk), k.pk.clone()]);
    let other = policy_of(1, vec![k.pk.clone()]);
    let tree = policy::PolicyTree::new(vec![twin.clone(), other.clone()]).unwrap();
    let coin = ([0xF8u8; 32], 0u32, out(5_000_000, &tree.script_pubkey()));
    let branch_spend = |index: usize, branch: &policy::SpendPolicy, signers: &[(&Key, u8)]| {
        let mut tx = spend(branch, &coin, signers);
        let w = policy::PolicyWitness::decode(&tx.inputs[0].script_sig).unwrap();
        tx.inputs[0].script_sig = policy::BranchWitness {
            n_branches: 2, index: index as u8, path: tree.path(index), branch: branch.clone(),
            signatures: w.signatures,
        }.encode();
        tx
    };
    // Policy-tree spends need PoWit to be active (core::powit_height(), 10,000
    // on the default mainnet chain id); the test asks the rule function
    // directly, as connect, mempool and template do, at heights where
    // branches are active, with the hardening-2 height just above the PoWit
    // height so both regimes are seen with branch spends valid.
    let powit = core::powit_height();
    assert!(powit < u64::MAX - 2, "policy-tree spends must activate on the test chain");
    let attack = branch_spend(0, &twin, &[(&k, 0), (&k, 1)]);
    let honest = branch_spend(1, &other, &[(&k, 0)]);
    let confirm = |_: &[u8; 32]| -> Result<Option<u64>, String> { Ok(Some(0)) };
    let prev = std::slice::from_ref(&coin.2);
    // Old regime (hardening 2 never active, or one block below it): the
    // twin-key branch is accepted by the policy-spend rule, as before.
    {
        let _never = activation::scoped_override_v2(activation::NEVER);
        for h in [powit, powit + 1, 1_000_000] {
            assert_eq!(blockval::check_policy_spends_with_confirmations(&attack, prev, h, &confirm), Ok(()),
                "old regime at {h}");
        }
    }
    let h2 = powit + 1;
    let _h2 = activation::scoped_override_v2(h2);
    assert_eq!(blockval::check_policy_spends_with_confirmations(&attack, prev, h2 - 1, &confirm), Ok(()),
        "one block below hardening 2: unchanged");
    for h in [h2, h2 + 1, 1_000_000] {
        let e = blockval::check_policy_spends_with_confirmations(&attack, prev, h, &confirm).unwrap_err();
        assert!(e.contains("same key"), "{h}: {e}");
        assert_eq!(blockval::check_policy_spends_with_confirmations(&honest, prev, h, &confirm), Ok(()),
            "the honest branch of the same tree at {h}");
    }
    // Branches are independent: the same key in two branches is fine.
    let across = policy::PolicyTree::new(vec![policy_of(1, vec![raw_of(&k.pk)]), policy_of(1, vec![k.pk.clone(), l.pk.clone()])])
        .unwrap();
    assert!(across.branches.iter().all(|b| b.check_key_identities().is_ok()));
}

/// Mempool admission and block connect call the same rule: from hardening 2
/// the attack is refused by both; below it both accept it, as before.
#[test]
fn mempool_admission_and_block_connect_apply_the_rule_at_its_height() {
    let _h1 = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let twin = policy_of(2, vec![raw_of(&k.pk), k.pk.clone()]);
    let coin = ([0xF9u8; 32], 0u32, out(5_000_000, &twin.script_pubkey()));
    let attack = spend(&twin, &coin, &[(&k, 0), (&k, 1)]);

    for (h2, refused) in [(activation::NEVER, false), (1, true)] {
        let _h2 = activation::scoped_override_v2(h2);
        let n = node_with(&genesis, std::slice::from_ref(&coin));
        n.store.put_tx_index(&coin.0, &gh, 0).unwrap();
        let next = admission::next_block_height(&n.dag.read());
        assert_eq!(next, 1);
        let admitted = admission::admit(&n.store, &n.mempool, attack.clone(), &AdmissionPolicy::relay(next));
        assert_eq!(admitted.is_err(), refused, "mempool, hardening 2 at {h2}: {admitted:?}");
        if refused {
            // A policy refusal, not consensus-invalid: a peer one block
            // behind across the hardening-2 height relays it honestly.
            assert!(matches!(&admitted, Err(AdmissionError::NonStandard(m)) if m.contains("same key")),
                "{admitted:?}");
        }

        let mut txs = vec![coinbase("pf4", core::tokenomics::block_subsidy_sat(1) + 1_000_000, vec![0xC3; 20])];
        txs.push(attack.clone());
        let b = mk_block(&n, vec![gh], txs);
        let view: &gnb::storage::Storage = &n.store;
        let connected = gnb::accept::validate_block_in_view_classified_at(view, &b, 0);
        match (refused, connected) {
            (false, Ok(_)) => {}
            (true, Err(gnb::accept::ConnectFailure::Invalid(e))) => {
                assert!(e.reason.contains("same key"), "{e:?}");
            }
            (r, other) => panic!("connect, hardening 2 at {h2} (refuse: {r}): {other:?}"),
        }
    }
}

/// Relay classification (review finding): the hardening-2 identity rule only
/// tightens the rules from a height, so every older release, and an upgraded
/// node one block below the height, accepts and relays a twin-key spend.
/// Refusing it must not penalise the delivering peer: the gossip verdict is
/// `Ignore` (admission answers `NonStandard`), with relay penalties in force.
/// A twin-key spend that ALSO fails an older consensus rule (here its
/// absolute timelock) is still consensus-invalid (`Reject`), as in Bitcoin
/// Core, where only a failure of the mandatory script flags is penalised.
/// Before the fix every such refusal was `Rejected` and so `Reject`.
#[test]
fn a_gossiped_twin_key_spend_at_hardening2_is_ignored_not_penalised() {
    let _h1 = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let twin = policy_of(2, vec![raw_of(&k.pk), k.pk.clone()]);
    let coin = ([0xFBu8; 32], 0u32, out(5_000_000, &twin.script_pubkey()));
    let attack = spend(&twin, &coin, &[(&k, 0), (&k, 1)]);
    let mut locked = policy_of(2, vec![raw_of(&k.pk), k.pk.clone()]);
    locked.after = 50;
    let locked = policy_of_full(locked);
    let lcoin = ([0xFCu8; 32], 0u32, out(5_000_000, &locked.script_pubkey()));
    let also_invalid = spend(&locked, &lcoin, &[(&k, 0), (&k, 1)]);
    assert_eq!(also_invalid.locktime, 0, "below the policy's absolute timelock");

    let _h2 = activation::scoped_override_v2(1);
    let n = node_with(&genesis, &[coin.clone(), lcoin.clone()]);
    n.store.put_tx_index(&coin.0, &gh, 0).unwrap();
    n.store.put_tx_index(&lcoin.0, &gh, 0).unwrap();
    let next = admission::next_block_height(&n.dag.read());
    assert_eq!(next, 1, "the next block is at the hardening-2 height");
    let mut relay = TxRelay::new().with_penalty_height(0);
    assert!(relay.penalties_in_force(next));
    let peer = Some(PeerId::random());
    let wire = |tx: &Transaction| tx.to_wire_bytes(true);

    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &attack.txid(), &wire(&attack), peer,
        std::time::Instant::now(), unix_now());
    assert_eq!(o.verdict, GossipVerdict::Ignore, "{}", o.detail);
    assert!(!o.invalid, "{}", o.detail);
    assert!(o.detail.contains("same key"), "{}", o.detail);
    assert!(!n.mempool.contains(&attack.txid()));

    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &also_invalid.txid(), &wire(&also_invalid), peer,
        std::time::Instant::now(), unix_now());
    assert_eq!(o.verdict, GossipVerdict::Reject, "{}", o.detail);
    assert!(o.invalid);
    // The same through admission directly (past the recent-rejects filter
    // the relay just filled): the older rule's failure classifies.
    let unfiltered = AdmissionPolicy { use_reject_filter: false, ..AdmissionPolicy::relay(next) };
    let e = admission::admit(&n.store, &n.mempool, also_invalid.clone(), &unfiltered).unwrap_err();
    assert!(matches!(&e, AdmissionError::Rejected(m) if m.contains("same key")), "{e:?}");
    let e = admission::admit(&n.store, &n.mempool, attack.clone(), &unfiltered).unwrap_err();
    assert!(matches!(&e, AdmissionError::NonStandard(m) if m.contains("same key")), "{e:?}");
}

/// A policy with every field set by the caller, through consensus decoding.
fn policy_of_full(p: policy::SpendPolicy) -> policy::SpendPolicy {
    policy::SpendPolicy::decode(&p.encode()).expect("consensus decoding")
}

/// Producers: a template for a block below the hardening-2 height includes a
/// pooled twin-key spend (valid there, as before); a template for a block
/// at the height leaves it out and evicts it (the template self-check runs
/// the same rule), so no producer emits a block the rule refuses.
#[test]
fn templates_include_the_spend_below_hardening2_and_evict_it_at_it() {
    let _h1 = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let twin = policy_of(2, vec![raw_of(&k.pk), k.pk.clone()]);
    let coin = ([0xFAu8; 32], 0u32, out(5_000_000, &twin.script_pubkey()));
    let attack = spend(&twin, &coin, &[(&k, 0), (&k, 1)]);
    for (h2, included) in [(2, true), (1, false)] {
        let n = node_with(&genesis, std::slice::from_ref(&coin));
        n.store.put_tx_index(&coin.0, &gh, 0).unwrap();
        let txid = {
            // Pooled while the next block (height 1) is below hardening 2.
            let _old = activation::scoped_override_v2(activation::NEVER);
            admission::admit(&n.store, &n.mempool, attack.clone(), &AdmissionPolicy::relay(1)).expect("pooled")
        };
        let _h2 = activation::scoped_override_v2(h2);
        let tmpl = gnb::template::build_block_template(&n.dag, &n.store, &n.mempool,
            gnb::template::EXTERNAL_COINBASE_RESERVE).unwrap();
        assert_eq!(tmpl.height, 1);
        let has = tmpl.transactions.iter().any(|(t, _)| t.txid() == txid);
        assert_eq!(has, included, "hardening 2 at {h2}: template height 1");
        assert_eq!(tmpl.evicted, usize::from(!included), "hardening 2 at {h2}");
    }
}

/// Tooling never builds such a policy, at any height: `SpendPolicy::new`
/// (every wallet / CLI / bridge constructor goes through it) refuses two
/// encodings of one key.
#[test]
fn tooling_refuses_to_build_a_policy_with_one_key_twice() {
    let k = key();
    let l = key();
    for h2 in [activation::NEVER, 0] {
        let _g = activation::scoped_override_v2(h2);
        assert_eq!(policy::SpendPolicy::new(2, vec![raw_of(&k.pk), k.pk.clone()], 0, 0),
                   Err(policy::PolicyError::DuplicateKey));
        assert_eq!(policy::SpendPolicy::new(2, vec![k.pk.clone(), l.pk.clone(), raw_of(&k.pk)], 0, 0),
                   Err(policy::PolicyError::DuplicateKey));
        assert!(policy::SpendPolicy::new(2, vec![raw_of(&k.pk), l.pk.clone()], 0, 0).is_ok());
    }
    // The bridge vault constructor (gnb-cli vaultcreate) goes through
    // SpendPolicy::new for each branch, and its "signer is not a recovery
    // key" check compares identities, not bytes.
    let m = key();
    let net = gnb::address::Network::Mainnet;
    let dup = gnb::bridge::Vault::create(net, 2, vec![raw_of(&k.pk), k.pk.clone(), l.pk.clone()], 1, vec![m.pk.clone()], 100);
    assert!(dup.as_ref().is_err_and(|e| e.contains("DuplicateKey")), "{dup:?}");
    let cross = gnb::bridge::Vault::create(net, 1, vec![raw_of(&k.pk), l.pk.clone()], 1, vec![k.pk.clone()], 100);
    assert!(cross.as_ref().is_err_and(|e| e.contains("both a signer and a recovery key")), "{cross:?}");
    assert!(gnb::bridge::Vault::create(net, 1, vec![raw_of(&k.pk), l.pk.clone()], 1, vec![m.pk.clone()], 100).is_ok());
}

/// PF-4 tooling gap (review finding): `gnb-cli` loads every published vault
/// file through `Vault::tree` (`load_vault`, before `vaultlock`,
/// `vaultchecklock`, `vaultrelease`, `vaultrecover`, ...). A hand-made vault
/// whose release branch is 2-of-[A enveloped, A raw, B] shows signers three
/// byte-distinct keys while A alone fills two slots; it is now refused like
/// `Vault::create` refuses it. Before the fix `Vault::tree` only checked that
/// the tree hashes to the published script, and the CLI went on.
#[test]
fn gnb_cli_refuses_a_published_vault_that_lists_one_key_twice() {
    let (a, b, cold) = (key(), key(), key());
    let net = gnb::address::Network::Mainnet;
    let honest = gnb::bridge::Vault::create(net, 2, vec![a.pk.clone(), b.pk.clone()], 1, vec![cold.pk.clone()], 100)
        .unwrap();
    let tree = honest.tree().unwrap();
    let twin_release = policy_of(2, vec![a.pk.clone(), raw_of(&a.pk), b.pk.clone()]);
    let crafted_tree = policy::PolicyTree { branches: vec![twin_release, tree.branches[1].clone()] };
    let script = crafted_tree.script_pubkey();
    let crafted = gnb::bridge::Vault {
        tree: hex::encode(crafted_tree.encode()),
        script: hex::encode(&script),
        address: gnb::address::PolicyAddress::from_script(&script, net).unwrap().to_string(),
        signers: 3,
        ..honest.clone()
    };
    let tmp = tempfile::tempdir().unwrap();
    let dest = gnb::address::Address::from_hash([7; 20], net).to_string();
    let run = |vault: &gnb::bridge::Vault, name: &str| {
        let path = tmp.path().join(name);
        std::fs::write(&path, serde_json::to_string(vault).unwrap()).unwrap();
        let out = tmp.path().join(format!("{name}.spend.json"));
        std::process::Command::new(env!("CARGO_BIN_EXE_gnb-cli"))
            .args(["vaultrecover", path.to_str().unwrap(), &dest, "0.01",
                   "--utxo", &format!("{}:0:5000000", "ab".repeat(32)), "--out", out.to_str().unwrap()])
            .env_remove("GNB_RPC_API_KEY").stdin(std::process::Stdio::null())
            .output().expect("run gnb-cli")
    };
    let ok = run(&honest, "honest.json");
    assert!(ok.status.success(), "honest vault: {}", String::from_utf8_lossy(&ok.stderr));
    let refused = run(&crafted, "crafted.json");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "a twin-key vault must not load");
    assert!(stderr.contains("release branch") && stderr.contains("DuplicateKey"), "{stderr}");
    assert!(!tmp.path().join("crafted.json.spend.json").exists(), "nothing was written");
}
