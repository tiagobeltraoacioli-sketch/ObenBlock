//! Boundary and encoding tests of the consensus functions of `core`
//! (difficulty wrappers, proof-of-work checks, coinbase rules, Merkle and
//! wire encodings, size measures, script_sig framing, coinbase maturity,
//! undo records). Each test pins an exact boundary or an exact byte layout,
//! so that changing a comparison, an arithmetic operator or a return value
//! in the code under test fails it (docs/testing/MUTATION.md).

use super::*;
use std::collections::{HashSet, VecDeque};
use std::io::Cursor;

// ── Builders ─────────────────────────────────────────────────────────────────

fn coinbase_tx(script_sig: Vec<u8>, value: u64, script_pubkey: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey }],
        locktime: 0,
    }
}

fn spend_tx(tag: u8, values: &[u64]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [tag; 32], prev_index: tag as u32, script_sig: vec![tag; 70], sequence: 7 }],
        outputs: values.iter().map(|&value| TxOutput { value, script_pubkey: vec![tag ^ 0x55; 20] }).collect(),
        locktime: 3,
    }
}

/// A block at `height` that is structurally valid under `activation`: the
/// coinbase carries the commitment when the hardening rules apply, and the
/// header root is the root of that regime.
fn valid_block(height: u64, parents: Vec<[u8; 32]>, cb_pad: usize, extra: Vec<Transaction>, activation: u64) -> Block {
    let mut txs = vec![coinbase_tx(b"cb".to_vec(), 50, vec![0x5A; cb_pad])];
    txs.extend(extra);
    let mut b = Block {
        header: BlockHeader { version: 1, parents, merkle_root: MerkleRoot::ZERO, timestamp: 0, bits: 0, nonce: 0 },
        transactions: txs,
        blue_score: height,
        height,
        shielded_transactions: vec![],
        powit: Default::default(),
    };
    if block_rules::rules_active_at(height, activation) {
        let c = block_rules::expected_coinbase_commitment(&b);
        b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&c, b"cb");
    }
    b.header.merkle_root = b.body_merkle_root_at(activation);
    b
}

/// [`valid_block`] padded (coinbase output script) to exactly `size` bytes
/// of the size measure of its regime: wire size at/after the activation,
/// bincode before it.
fn block_of_size(size: usize, height: u64, activation: u64) -> Block {
    let hardened = block_rules::rules_active_at(height, activation);
    let mut pad = size - 2_000;
    for _ in 0..4 {
        let b = valid_block(height, vec![[0x11; 32]], pad, vec![], activation);
        let have = block_rules::block_size_for_rules(&b, hardened);
        if have == size {
            return b;
        }
        pad = (pad as i64 + size as i64 - have as i64) as usize;
    }
    panic!("could not size the block to {size} bytes");
}

fn shielded(tag: u8, n_nf: usize, n_out: usize, proof: usize) -> coherence_core::ShieldedTx {
    coherence_core::ShieldedTx {
        anchor: [tag; 32],
        nullifiers: (0..n_nf).map(|i| [tag ^ i as u8; 32]).collect(),
        outputs: (0..n_out).map(|i| [tag.wrapping_add(i as u8); 32]).collect(),
        fee: 1_000 + tag as u64,
        proof: vec![tag; proof],
        binding_sig: vec![tag ^ 0xFF; 64],
    }
}

// ── Constants and difficulty wrappers ────────────────────────────────────────

/// The size constants are the real encoded sizes of the hybrid suite.
#[test]
fn key_and_signature_size_constants_match_the_suite() {
    assert_eq!((PUBKEY_SIZE, PRIVKEY_SIZE, SIG_SIZE), (3_749, 6_341, 4_775));
    let (pk, sk) = crate::crypto::generate_keypair_from_seed(&[3u8; 32]).unwrap();
    assert_eq!(pk.len(), PUBKEY_SIZE);
    assert_eq!(sk.len(), PRIVKEY_SIZE);
    assert_eq!(crate::crypto::max_signature_len(), SIG_SIZE);
    let sig = crate::crypto::sign(&sk, b"size").unwrap();
    assert!(sig.len() <= SIG_SIZE);
}

#[test]
fn asert_parameters_and_anchor() {
    assert_eq!(ASERT_HALFLIFE_SECS, 7_200);
    let p = asert_params();
    assert_eq!((p.target_spacing, p.halflife), (30, 7_200));
    assert_eq!(p.pow_limit.0, bits_to_target(POW_LIMIT_BITS));
    let a = asert_anchor();
    assert_eq!((a.height, a.bits, a.timestamp), (0, GENESIS_BITS, GENESIS_TIMESTAMP as i64));
    let below = asert_params_at(4, 5);
    let at = asert_params_at(5, 5);
    assert_eq!(below, p);
    assert_eq!(at.pow_limit.0, bits_to_target(GENESIS_BITS));
    assert_eq!((at.target_spacing, at.halflife), (30, 7_200));
}

#[test]
fn difficulty_wrappers() {
    let g = bits_to_target(GENESIS_BITS);
    assert_eq!(g[..4], [0x00, 0x0E, 0x90, 0x36]);
    assert!(g[4..].iter().all(|&b| b == 0));
    assert_eq!(target_to_bits(&g), GENESIS_BITS);
    assert_eq!(bits_to_work(GENESIS_BITS), 4_500);
    assert!(hash_meets_target(&[0u8; 32], &g));
    let mut just_below = g;
    just_below[3] -= 1;
    assert!(hash_meets_target(&just_below, &g));
    assert!(!hash_meets_target(&g, &g));
    assert!(!hash_meets_target(&[0xFF; 32], &g));
}

#[test]
fn difficulty_parent_timestamp_is_the_latest_parent() {
    assert_eq!(difficulty_parent_timestamp([5u64, 9, 7]), 9);
    assert_eq!(difficulty_parent_timestamp([GENESIS_TIMESTAMP + 3]), GENESIS_TIMESTAMP + 3);
    assert_eq!(difficulty_parent_timestamp(std::iter::empty()), GENESIS_TIMESTAMP);
}

#[test]
fn merkle_root_newtype_is_transparent() {
    let m = MerkleRoot::from([7u8; 32]);
    assert_eq!(m, MerkleRoot([7u8; 32]));
    assert_eq!(m.into_inner(), [7u8; 32]);
    let a: [u8; 32] = m.into();
    assert_eq!(a, [7u8; 32]);
    assert_eq!(m.as_ref(), &[7u8; 32][..]);
    assert_eq!(*m, [7u8; 32]);
    assert_eq!(MerkleRoot::default(), MerkleRoot::ZERO);
}

// ── Header digests and proof of work ─────────────────────────────────────────

/// Computed independently with the Python references (reference/gnb_smh.py,
/// reference/gnb_merkle.py) from the genesis constants.
#[test]
fn genesis_header_digests_match_the_python_reference() {
    let g = genesis_block();
    assert_eq!(
        hex::encode(g.header.pow_preimage()),
        "01000000000000006af2543ab67b047d3ef1d63c7141fd308cf9c8b96e223d8ce9ecdc1b7db8190d10f4ca6a0000000036900e1f"
    );
    assert_eq!(hex::encode(g.block_hash()), "a63fd2c124cf34312d2730609204dc3071b8924e24d54f938cf738968fb8f810");
    let pow = g.header.pow_hash(0);
    assert_eq!(hex::encode(pow), "00009bf116a2451ac6af9a11c2ff40808efe96abf4238feb084596826e516682");
    assert!(hash_meets_target(&pow, &bits_to_target(GENESIS_BITS)));
}

#[test]
fn pow_limit_target_follows_the_activation() {
    let _g = activation::scoped_override(5);
    assert_eq!(Block::pow_limit_target_for_height(4), bits_to_target(POW_LIMIT_BITS));
    let at = Block::pow_limit_target_for_height(5);
    if TEST_POW_LIMIT {
        assert_eq!(at, bits_to_target(POW_LIMIT_BITS));
    } else {
        assert_eq!(at, bits_to_target(GENESIS_BITS));
    }
}

/// A target exactly at the pow limit is allowed (`target <= limit`), and a
/// block meeting it passes the whole structural check including the proof.
#[test]
fn target_equal_to_the_pow_limit_validates() {
    let _g = activation::scoped_override(activation::NEVER);
    let mut b = valid_block(1, vec![[0x21; 32]], 20, vec![], activation::NEVER);
    b.header.bits = POW_LIMIT_BITS;
    let found = (0..32u64).any(|nonce| {
        b.header.nonce = nonce;
        b.validate_pow()
    });
    assert!(found, "a pow-limit target is met by almost every nonce");
    assert_eq!(b.validate_structure(), Ok(()));
    assert!(pow_cache().lock().unwrap().set.contains(&b.block_hash()), "a verified block id is cached");
}

#[test]
fn pow_cache_is_a_bounded_fifo() {
    let mut c = PowCache { set: HashSet::new(), order: VecDeque::new() };
    let id = |i: usize| {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&(i as u64).to_le_bytes());
        b
    };
    for i in 0..POW_CACHE_CAPACITY {
        c.insert(id(i));
    }
    assert_eq!((c.set.len(), c.order.len()), (POW_CACHE_CAPACITY, POW_CACHE_CAPACITY));
    assert!(c.set.contains(&id(0)));
    c.insert(id(0)); // already held: no-op
    assert_eq!(c.order.len(), POW_CACHE_CAPACITY);
    assert_eq!(c.order.front(), Some(&id(0)));
    c.insert(id(POW_CACHE_CAPACITY));
    assert_eq!((c.set.len(), c.order.len()), (POW_CACHE_CAPACITY, POW_CACHE_CAPACITY));
    assert!(!c.set.contains(&id(0)), "the oldest id is evicted");
    assert!(c.set.contains(&id(1)) && c.set.contains(&id(POW_CACHE_CAPACITY)));
}

/// Audit POW-9 (residual): `validate_pow` refuses a NON-CANONICAL compact
/// encoding before any evaluation, even when the proof meets the target it
/// decodes to. `0x21007fff` decodes (Bitcoin Core's `SetCompact` semantics,
/// which `try_bits_to_target` keeps) to `0x7fff << 240`, whose canonical
/// encoding is `0x207fff00`. About one nonce in two meets that target.
#[test]
fn non_canonical_bits_never_validate() {
    let _g = activation::scoped_override(activation::NEVER);
    const NON_CANONICAL: u32 = 0x2100_7FFF;
    const CANONICAL: u32 = 0x207F_FF00;
    let t = gnb_smh::difficulty::try_bits_to_target(NON_CANONICAL).expect("decodes");
    assert_eq!(gnb_smh::difficulty::target_to_bits(&t), CANONICAL);
    assert_eq!(gnb_smh::difficulty::try_bits_to_target(CANONICAL), Ok(t), "same target");
    assert!(!gnb_smh::difficulty::is_canonical_bits(NON_CANONICAL));
    assert!(gnb_smh::difficulty::is_canonical_bits(CANONICAL));
    let mut b = valid_block(1, vec![[0x22; 32]], 20, vec![], activation::NEVER);
    b.header.bits = NON_CANONICAL;
    // A nonce whose GnB-SMH output meets the decoded target.
    let nonce = (0..64u64)
        .find(|&n| {
            b.header.nonce = n;
            hash_meets_target(&b.header.pow_hash(b.height), &t.0)
        })
        .expect("half of all nonces meet a 2^255 target");
    b.header.nonce = nonce;
    assert!(!b.validate_pow(), "non-canonical bits must not validate (nonce {nonce})");
    assert_eq!(b.validate_structure(), Err("invalid PoW"));
    // The canonical encoding of the same target validates with a nonce of its own.
    b.header.bits = CANONICAL;
    assert!((0..64u64).any(|n| {
        b.header.nonce = n;
        b.validate_pow()
    }));
}

/// Why the canonical requirement changes no verdict: every block must carry
/// `bits == expected_bits(...)` (checked before the proof), and
/// `expected_bits` encodes with `target_to_bits`, whose output is always
/// canonical. Checked over the whole schedule's range of targets (every
/// exponent, random mantissas, both activation regimes, both proofs of work)
/// and the constants.
#[test]
fn expected_bits_are_always_canonical() {
    super::powit_pow_tests::activate();
    use gnb_smh::difficulty::{is_canonical_bits, target_to_bits, Target};
    for bits in [POW_LIMIT_BITS, GENESIS_BITS, block_rules::HARDENED_POW_LIMIT_BITS] {
        assert!(is_canonical_bits(bits), "{bits:#x}");
    }
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..20_000 {
        let mut t = [0u8; 32];
        let first = (next() % 32) as usize;
        for b in t.iter_mut().skip(first) {
            *b = next() as u8;
        }
        if t == [0u8; 32] {
            continue;
        }
        let bits = target_to_bits(&Target(t));
        assert!(is_canonical_bits(bits), "target_to_bits({}) = {bits:#x} is not canonical", hex::encode(t));
    }
    // Both proofs of work: from this binary's shared activation the ASERT bits are
    // shifted for GnB-SMH v3 (`adjust_bits_for_algo`), re-encoded with
    // `target_to_bits` too.
    let switch = super::powit_pow_tests::TEST_ACTIVATION;
    let heights = [
        1u64, 2, 1_000, POWIT_HEIGHT_MAINNET - 1, POWIT_HEIGHT_MAINNET,
        POWIT_HEIGHT_MAINNET + 1, 500_000, switch - 1, switch, switch + 1,
    ];
    assert_eq!(pow_algo(switch - 1), gnb_smh::Algo::V1);
    assert_eq!(pow_algo(switch), gnb_smh::Algo::V3);
    assert_eq!(pow_algo(switch + 1), gnb_smh::Algo::V3);
    for (act, heights) in [(0u64, heights), (activation::NEVER, heights)] {
        for h in heights {
            for dt in [-1_000_000i64, -7_200, -30, 0, 30, 7_200, 1_000_000, 50_000_000] {
                let ts = (GENESIS_TIMESTAMP as i64 + 30 * h as i64 + dt).max(0) as u64;
                let bits = expected_bits_at(ts, h, act).expect("in range");
                assert!(is_canonical_bits(bits), "expected_bits_at({ts}, {h}, {act}) = {bits:#x}");
            }
        }
    }
}

// ── The real-ASERT test seam (re-audit POW-5) ────────────────────────────────
//
// The node's real-ASERT tests (node/tests/fix_pow_real_asert*.rs) hold
// `scoped_real_expected_bits()` to lift the `test-pow-limit` pin on their
// thread. If the seam leaked or ignored its scope, those tests would check
// the pinned pow limit (and every other node test the real rule) without
// failing for that reason, so the scope itself is pinned here. These tests
// run with and without the feature; the mutation gate runs them without it.

/// The pin is lifted on the calling thread exactly while a guard is held.
#[test]
fn real_expected_bits_scope_lifts_the_pin_until_the_guard_drops() {
    assert!(pow_limit_pinned_on_this_thread(), "pinned outside any scope");
    let guard = scoped_real_expected_bits();
    assert!(!pow_limit_pinned_on_this_thread(), "lifted inside the scope");
    drop(guard);
    assert!(pow_limit_pinned_on_this_thread(), "pinned again once the guard drops");
}

/// Each guard restores the mode it found: dropping an inner guard keeps the
/// outer scope's real rule.
#[test]
fn real_expected_bits_scopes_nest() {
    let outer = scoped_real_expected_bits();
    let inner = scoped_real_expected_bits();
    assert!(!pow_limit_pinned_on_this_thread());
    drop(inner);
    assert!(!pow_limit_pinned_on_this_thread(), "the outer guard still holds");
    drop(outer);
    assert!(pow_limit_pinned_on_this_thread());
}

/// A panic inside the scope (a failed assertion) drops the guard while
/// unwinding, and the scope belongs to its thread: another thread stays
/// pinned.
#[test]
fn real_expected_bits_scope_unwinds_and_is_per_thread() {
    let unwound = std::panic::catch_unwind(|| {
        let _real = scoped_real_expected_bits();
        assert!(!pow_limit_pinned_on_this_thread());
        // No panic hook: the test output stays quiet.
        std::panic::resume_unwind(Box::new("inside the scope"));
    });
    assert!(unwound.is_err());
    assert!(pow_limit_pinned_on_this_thread(), "the guard dropped while unwinding");
    let _real = scoped_real_expected_bits();
    let other = std::thread::spawn(pow_limit_pinned_on_this_thread).join().unwrap();
    assert!(other, "another thread keeps the pin");
    assert!(!pow_limit_pinned_on_this_thread());
}

/// `expected_bits` itself: with `test-pow-limit` the pinned pow limit
/// outside the scope and the real ASERT bits inside it; without the feature
/// the real rule either way.
#[test]
fn expected_bits_follows_the_real_expected_bits_scope() {
    let (ts, height) = (GENESIS_TIMESTAMP, 1);
    let real = expected_bits_at(ts, height, activation::hardening_activation_height()).unwrap();
    let pinned = target_to_bits(&bits_to_target(POW_LIMIT_BITS));
    assert_eq!(real, GENESIS_BITS);
    assert_ne!(real, pinned, "the two modes must be told apart");
    let outside = if TEST_POW_LIMIT { pinned } else { real };
    assert_eq!(expected_bits(ts, height).unwrap(), outside);
    {
        let _real = scoped_real_expected_bits();
        assert_eq!(expected_bits(ts, height).unwrap(), real);
    }
    assert_eq!(expected_bits(ts, height).unwrap(), outside);
}

// ── Coinbase, dust, duplicates, timestamps, fees, maturity ───────────────────

#[test]
fn coinbase_shape_is_exact() {
    let cb = coinbase_tx(vec![1, 2, 3], 0, vec![0; 20]);
    assert!(cb.is_coinbase());
    let mut two = cb.clone();
    two.inputs.push(spend_tx(1, &[1]).inputs[0].clone());
    assert!(!two.is_coinbase(), "two inputs");
    let mut txid = cb.clone();
    txid.inputs[0].prev_txid[31] = 1;
    assert!(!txid.is_coinbase(), "non-null prev_txid");
    let mut index = cb.clone();
    index.inputs[0].prev_index = 0;
    assert!(!index.is_coinbase(), "prev_index is not u32::MAX");
    let mut none = cb.clone();
    none.inputs.clear();
    assert!(!none.is_coinbase(), "no input");

    let block = |txs: Vec<Transaction>| Block { transactions: txs, ..genesis_block() };
    assert!(block(vec![cb.clone(), spend_tx(1, &[1_000])]).validate_coinbase_format());
    assert!(!block(vec![spend_tx(1, &[1_000])]).validate_coinbase_format(), "first tx is not a coinbase");
    assert!(!block(vec![]).validate_coinbase_format());
    let mut cb2 = cb.clone();
    cb2.inputs[0].script_sig = vec![9];
    assert!(!block(vec![cb, spend_tx(1, &[1_000]), cb2]).validate_coinbase_format(), "a second coinbase");
}

#[test]
fn dust_threshold_is_exact_and_skips_the_coinbase() {
    let block = |values: &[u64]| Block {
        transactions: vec![coinbase_tx(vec![1], 1, vec![0; 20]), spend_tx(2, values)],
        ..genesis_block()
    };
    assert_eq!(block(&[DUST_THRESHOLD, 0, 1_000_000]).validate_dust(), Ok(()), "zero-value outputs are allowed");
    assert_eq!(block(&[DUST_THRESHOLD - 1]).validate_dust(), Err("output below dust threshold"));
    assert_eq!(block(&[1]).validate_dust(), Err("output below dust threshold"));
}

#[test]
fn duplicate_transactions_are_rejected() {
    let cb = coinbase_tx(vec![1], 1, vec![0; 20]);
    let ok = Block { transactions: vec![cb.clone(), spend_tx(1, &[1_000]), spend_tx(2, &[1_000])], ..genesis_block() };
    assert_eq!(ok.validate_no_duplicate_txs(), Ok(()));
    let dup = Block { transactions: vec![cb, spend_tx(1, &[1_000]), spend_tx(1, &[1_000])], ..genesis_block() };
    assert_eq!(dup.validate_no_duplicate_txs(), Err("duplicate transaction in block (CVE-2012-2459)"));
}

#[test]
fn timestamp_bounds_are_inclusive() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let at = |ts: u64| {
        let mut b = genesis_block();
        b.header.timestamp = ts;
        b
    };
    assert_eq!(at(now).validate_timestamp(now - 10), Ok(()));
    assert_eq!(at(now).validate_timestamp(now), Ok(()), "equal to the parent is allowed");
    assert_eq!(at(now).validate_timestamp(now + 1), Err("timestamp before parent"));
    assert_eq!(at(now + MAX_FUTURE_SECS).validate_timestamp(0), Ok(()), "exactly MAX_FUTURE_SECS ahead");
    assert_eq!(at(now + MAX_FUTURE_SECS + 120).validate_timestamp(0), Err("timestamp too far in the future"));
}

#[test]
fn min_fee_boundary_is_inclusive() {
    let mut big = spend_tx(1, &[1_000]);
    big.inputs[0].script_sig = vec![0xAB; 6_000];
    let size = big.to_wire_bytes(true).len();
    let min = tokenomics::min_tx_fee_sat(size);
    assert!(min > tokenomics::MIN_TX_FEE_SAT, "size-based minimum");
    assert_eq!(check_min_fee(&big, min, &[]), Ok(()));
    assert_eq!(check_min_fee(&big, min + 1, &[]), Ok(()));
    assert_eq!(
        check_min_fee(&big, min - 1, &[]),
        Err(format!("fee {} below consensus minimum {min} for a {size}-byte transaction", min - 1))
    );
    let small = spend_tx(2, &[1_000]);
    assert_eq!(check_min_fee(&small, tokenomics::MIN_TX_FEE_SAT, &[]), Ok(()));
    assert!(check_min_fee(&small, tokenomics::MIN_TX_FEE_SAT - 1, &[]).is_err());
}

#[test]
fn change_is_an_output_to_a_spent_coin_script() {
    let mut tx = spend_tx(1, &[700, 300]);
    tx.outputs[0].script_pubkey = vec![0x11; 20];
    tx.outputs[1].script_pubkey = vec![0x22; 20];
    let own = TxOutput { value: 1_000, script_pubkey: vec![0x22; 20] };
    let other = TxOutput { value: 1_000, script_pubkey: vec![0x33; 20] };
    assert_eq!(paid_to_others_sat(&tx, &[own.clone()]), 700, "output 1 is change");
    assert_eq!(paid_to_others_sat(&tx, &[other.clone()]), 1_000, "no change");
    assert_eq!(paid_to_others_sat(&tx, &[]), 1_000);
    tx.outputs[0].script_pubkey = vec![0x22; 20];
    assert_eq!(paid_to_others_sat(&tx, &[other, own]), 0, "everything back to a spent script");
    let max = Transaction { outputs: vec![TxOutput { value: u64::MAX, script_pubkey: vec![1; 20] }; 3], ..tx };
    assert_eq!(paid_to_others_sat(&max, &[]), 3 * u64::MAX as u128, "exact in u128");
}

#[test]
fn coinbase_maturity_boundary_is_exact() {
    let mut tx = spend_tx(1, &[1_000]);
    tx.inputs.push(TxInput { prev_txid: [0xCB; 32], prev_index: 0, script_sig: vec![], sequence: 0 });
    let lookup = |t: &[u8; 32]| if *t == [0xCB; 32] { Some(1_000u64) } else { None };
    assert_eq!(check_coinbase_maturity(&tx, 1_000 + COINBASE_MATURITY, lookup), Ok(()));
    assert_eq!(check_coinbase_maturity(&tx, 5_000, lookup), Ok(()));
    assert_eq!(
        check_coinbase_maturity(&tx, 1_000 + COINBASE_MATURITY - 1, lookup),
        Err("coinbase maturity: input 1 references coinbase at h=1000, only 99 confirmations (need 100)".into())
    );
    assert!(check_coinbase_maturity(&tx, 1_000, lookup).is_err(), "same height: depth 0");
    // Height 0 (the genesis) spends nothing and is never checked.
    assert_eq!(check_coinbase_maturity(&tx, 0, |_: &[u8; 32]| Some(0)), Ok(()));
    // Inputs that do not spend a coinbase are never checked.
    assert_eq!(check_coinbase_maturity(&tx, 1, |_: &[u8; 32]| None), Ok(()));
}

// ── Structure: inclusive limits and the Merkle commitment ────────────────────

#[test]
fn parent_count_limit_is_inclusive() {
    let parents: Vec<[u8; 32]> = (0..MAX_PARENTS).map(|i| [i as u8; 32]).collect();
    for activation in [activation::NEVER, 0] {
        let b = valid_block(1, parents.clone(), 20, vec![spend_tx(1, &[1_000])], activation);
        assert_eq!(b.validate_structure_without_pow_at(activation), Ok(()), "activation {activation}");
    }
}

#[test]
fn block_size_limit_is_inclusive_under_both_measures() {
    for activation in [activation::NEVER, 0] {
        let hardened = block_rules::rules_active_at(1, activation);
        let at = block_of_size(MAX_BLOCK_SIZE, 1, activation);
        assert_eq!(at.validate_structure_without_pow_at(activation), Ok(()), "hardened={hardened}");
        let over = block_of_size(MAX_BLOCK_SIZE + 1, 1, activation);
        assert_eq!(over.validate_structure_without_pow_at(activation), Err("block too large"), "hardened={hardened}");
        // This chain measures both regimes on the wire encoding.
        assert_eq!(at.wire_size(), at.size_bytes());
        assert_eq!(block_rules::block_size_for_rules(&at, true), at.wire_size());
        assert_eq!(block_rules::block_size_for_rules(&at, false), at.size_bytes());
        if hardened {
            assert_eq!(block_rules::check_block_hardened_at(&at, activation), Ok(()));
            assert_eq!(block_rules::check_block_hardened_at(&over, activation), Err("block too large"));
        }
    }
}

/// Re-audit B1-T0 / B2-T8: the block id does not commit to `blue_score`, and
/// the node replaces the received value before it stores and serves a body
/// (POW-8). The size verdict of a block id must therefore be the same for
/// every `blue_score` a copy can carry (under the audit's bincode measure a
/// block of exactly `MAX_BLOCK_SIZE` bytes with `blue_score` 0 was "too
/// large" with 251 or more, a 3-, 5- or 9-byte varint). This chain measures
/// the wire encoding in both regimes, where it is a fixed-width u64.
#[test]
fn size_verdict_does_not_depend_on_the_uncommitted_blue_score() {
    let scores = [0u64, 1, 250, 251, 65_535, 65_536, 70_000, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX];
    for activation in [activation::NEVER, 0] {
        let at = block_of_size(MAX_BLOCK_SIZE, 1, activation);
        let over = block_of_size(MAX_BLOCK_SIZE + 1, 1, activation);
        for &bs in &scores {
            let (mut a, mut o) = (at.clone(), over.clone());
            a.blue_score = bs;
            o.blue_score = bs;
            assert_eq!(a.block_hash(), at.block_hash(), "the id does not commit to blue_score");
            assert_eq!(a.validate_structure_without_pow_at(activation), Ok(()), "activation {activation}, blue_score {bs}");
            assert_eq!(o.validate_structure_without_pow_at(activation), Err("block too large"),
                "activation {activation}, blue_score {bs}");
            assert_eq!(block_rules::check_block_size_at(&a, activation), Ok(()));
            assert_eq!(block_rules::check_block_size_at(&o, activation), Err("block too large"));
        }
    }
}

/// `legacy_block_size` (the measure below the activation) is the length of
/// the wire encoding, `to_wire_bytes().len()`, whatever the `blue_score` (the
/// same as with it written as 0), the PoWit section included from
/// `powit_height()` (main's 45c9c97: what this chain's nodes measure), and
/// equal to the hardened measure `wire_size()`.
#[test]
fn legacy_block_size_is_the_wire_length_whatever_the_blue_score() {
    super::powit_pow_tests::activate();
    let powit = super::powit_pow_tests::TEST_ACTIVATION;
    for (height, n_shielded) in [(1u64, 0usize), (300, 2), (70_000, 1), (powit - 1, 0), (powit, 1)] {
        let mut b = valid_block(height, vec![[2; 32], [3; 32]], 20, vec![spend_tx(4, &[1_000, 2_000])], activation::NEVER);
        b.shielded_transactions = (0..n_shielded).map(|i| shielded(i as u8, 2, 1, 50)).collect();
        let mut zero = b.clone();
        zero.blue_score = 0;
        let len0 = zero.to_wire_bytes().len();
        let mut section = Vec::new();
        b.powit.write_wire(&mut section);
        let without_powit = len0 - if height >= powit { section.len() } else { 0 };
        assert_eq!(height >= powit, len0 > without_powit, "the PoWit section is counted from powit_height");
        for bs in [0u64, 1, 250, 251, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000, u64::MAX] {
            b.blue_score = bs;
            assert_eq!(block_rules::legacy_block_size(&b), len0, "height {height}, blue_score {bs}");
            assert_eq!(b.to_wire_bytes().len(), len0);
            assert_eq!(block_rules::block_size_for_rules(&b, false), len0);
            assert_eq!(block_rules::block_size_for_rules(&b, true), len0);
        }
    }
}

#[test]
fn size_bytes_is_the_wire_length() {
    let b = valid_block(3, vec![[1; 32]], 20, vec![spend_tx(1, &[1_000])], activation::NEVER);
    let len = b.to_wire_bytes().len();
    assert_eq!(b.size_bytes(), len);
    assert!(len > 100);
}

#[test]
fn actual_size_is_the_bincode_length_that_size_bytes_sums() {
    // `Transaction::actual_size` is one transaction's share of the
    // pre-activation block-size measure (`Block::size_bytes`): the node's
    // mempool admission (MAX_TX_SIZE, fee rates) and the miner's coinbase
    // reserve rely on it.
    let tx = spend_tx(7, &[1_000, 2_000]);
    let len = bincode::serde::encode_to_vec(&tx, bincode::config::standard()).unwrap().len();
    assert_eq!(tx.actual_size(), len);
    assert!(len > 100);
    let without = valid_block(3, vec![[1; 32]], 20, vec![spend_tx(1, &[1_000])], activation::NEVER);
    let mut with = without.clone();
    with.transactions.push(tx.clone());
    // The block measure is the wire encoding on this chain.
    assert_eq!(with.size_bytes(), without.size_bytes() + tx.wire_size(true));
}

#[test]
fn merkle_validation_compares_with_the_header() {
    let g = genesis_block();
    assert!(g.validate_merkle());
    let mut bad = g.clone();
    bad.header.merkle_root.0[0] ^= 1;
    assert!(!bad.validate_merkle());
    assert!(!bad.validate_merkle_at(activation::NEVER));
    assert_eq!(bad.body_merkle_root(), g.header.merkle_root);
}

// ── Wire encodings ───────────────────────────────────────────────────────────

#[test]
fn varint_encoding_boundaries() {
    let cases: [(u64, Vec<u8>); 8] = [
        (0, vec![0x00]),
        (0xFC, vec![0xFC]),
        (0xFD, vec![0xFD, 0xFD, 0x00]),
        (0xFFFF, vec![0xFD, 0xFF, 0xFF]),
        (0x1_0000, vec![0xFE, 0x00, 0x00, 0x01, 0x00]),
        (0xFFFF_FFFF, vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
        (0x1_0000_0000, vec![0xFF, 0, 0, 0, 0, 1, 0, 0, 0]),
        (u64::MAX, vec![0xFF; 9]),
    ];
    for (n, enc) in cases {
        let mut out = Vec::new();
        write_varint(&mut out, n);
        assert_eq!(out, enc, "{n:#x}");
        assert_eq!(varint_len(n), enc.len(), "{n:#x}");
        assert_eq!(read_varint(&mut Cursor::new(&enc[..])), Ok(n), "{n:#x}");
    }
    assert_eq!(read_varint(&mut Cursor::new(&[0xFD, 0x01][..])), Err("varint u16 EOF".into()));
    assert_eq!(read_varint(&mut Cursor::new(&[][..])), Err("varint: unexpected EOF on tag".into()));
}

#[test]
fn header_wire_round_trip_and_parent_cap() {
    let h = BlockHeader {
        version: 0x0102_0304,
        parents: (0..MAX_PARENTS).map(|i| [i as u8; 32]).collect(),
        merkle_root: MerkleRoot([0xAB; 32]),
        timestamp: 0x1122_3344_5566_7788,
        bits: 0x1F0E_9036,
        nonce: 0x99AA_BBCC_DDEE_FF00,
    };
    let bytes = h.to_wire_bytes(7, 9);
    assert_eq!(bytes.len(), 4 + 3 + 32 * MAX_PARENTS + 32 + 8 + 4 + 8 + 8 + 8);
    let (back, blue, height) = BlockHeader::from_wire_bytes(&bytes).unwrap();
    assert_eq!((blue, height), (7, 9));
    assert_eq!((back.version, back.timestamp, back.bits, back.nonce), (h.version, h.timestamp, h.bits, h.nonce));
    assert_eq!(back.parents, h.parents);
    assert_eq!(back.merkle_root, h.merkle_root);
    assert_eq!(back.to_wire_bytes(7, 9), bytes);

    let mut trailing = bytes.clone();
    trailing.push(0xEE);
    assert_eq!(BlockHeader::read_wire_bytes(&trailing).unwrap().3, bytes.len());
    assert_eq!(
        BlockHeader::from_wire_bytes(&trailing).unwrap_err(),
        format!("trailing bytes after header: parsed {} of {}", bytes.len(), bytes.len() + 1)
    );
    let mut over = h.clone();
    over.parents.push([0xFF; 32]);
    assert_eq!(BlockHeader::from_wire_bytes(&over.to_wire_bytes(7, 9)).unwrap_err(), "implausible parent count 257");
}

fn sample_block() -> Block {
    let mut b = genesis_block();
    b.header.parents = vec![[1; 32], [2; 32], [3; 32]];
    b.header.nonce = 0x0102_0304_0506_0708;
    b.blue_score = 0x1_0000_0001;
    b.height = 77;
    b.transactions[0].inputs[0].script_sig = vec![0xC0; 300];
    let mut t = spend_tx(4, &[5_000, 6_000]);
    t.inputs.push(TxInput { prev_txid: [9; 32], prev_index: 3, script_sig: vec![1, 2, 3], sequence: 11 });
    b.transactions.push(t);
    b.transactions.push(spend_tx(5, &[7_000]));
    b.shielded_transactions = vec![shielded(0x31, 2, 3, 500), shielded(0x42, 1, 0, 70)];
    b
}

#[test]
fn block_wire_round_trip_preserves_every_field() {
    let b = sample_block();
    let bytes = b.to_wire_bytes();
    assert_eq!(b.wire_size(), bytes.len());
    let back = Block::from_wire_bytes(&bytes).unwrap();
    assert_eq!(back.to_wire_bytes(), bytes);
    assert_eq!((back.blue_score, back.height), (b.blue_score, b.height));
    assert_eq!(back.transactions.len(), 3);
    for (x, y) in back.transactions.iter().zip(&b.transactions) {
        assert_eq!(x.wtxid(), y.wtxid());
    }
    assert_eq!(back.transactions[1].inputs[1].script_sig, vec![1, 2, 3]);
    assert_eq!(back.transactions[1].inputs[1].sequence, 11);
    assert_eq!(back.transactions[1].outputs[1].value, 6_000);
    let (s, t) = (&back.shielded_transactions[0], &b.shielded_transactions[0]);
    assert_eq!((s.anchor, &s.nullifiers, &s.outputs, s.fee), (t.anchor, &t.nullifiers, &t.outputs, t.fee));
    assert_eq!((&s.proof, &s.binding_sig), (&t.proof, &t.binding_sig));
    assert_eq!(back.shielded_transactions[1].fee, b.shielded_transactions[1].fee);

    let mut trailing = bytes.clone();
    trailing.push(0);
    let body = bytes.len() - b.header.to_wire_bytes(b.blue_score, b.height).len();
    assert_eq!(
        Block::from_wire_bytes(&trailing).unwrap_err(),
        format!("trailing bytes in block body: parsed {body} of {}", body + 1)
    );
}

#[test]
fn transaction_wire_round_trip_and_ids() {
    let mut t = spend_tx(6, &[1, 2, 3]);
    t.inputs[0].script_sig = vec![0xEE; 300];
    let full = t.to_wire_bytes(true);
    let back = Transaction::from_wire_bytes(&full).unwrap();
    assert_eq!(back.to_wire_bytes(true), full);
    assert_eq!(back.inputs[0].script_sig, t.inputs[0].script_sig);
    assert_eq!(t.wire_size(true), full.len());
    assert_eq!(t.wire_size(false), t.to_wire_bytes(false).len());
    // txid hashes the stripped encoding, wtxid the full one.
    let d = |b: &[u8]| -> [u8; 32] { Sha256::digest(Sha256::digest(b)).into() };
    assert_eq!(t.txid(), d(&t.to_wire_bytes(false)));
    assert_eq!(t.wtxid(), d(&full));
    assert_ne!(t.txid(), t.wtxid());
    // A coinbase's txid covers its script_sig: txid == wtxid.
    let cb = coinbase_tx(vec![4; 9], 1, vec![0; 20]);
    assert_eq!(cb.txid(), cb.wtxid());
}

/// Every count/length cap of the wire parser, at the cap and one above it.
/// A count at the cap passes the cap check and fails later on missing bytes;
/// one above it fails the cap check itself.
#[test]
fn wire_parser_caps_are_exact() {
    let v = |n: u64| {
        let mut o = Vec::new();
        write_varint(&mut o, n);
        o
    };
    let cat = |parts: &[&[u8]]| parts.concat();
    let ver = 1u32.to_le_bytes();
    let tx = |b: Vec<u8>| Transaction::from_wire_bytes(&b).unwrap_err();
    assert_eq!(tx(cat(&[&ver, &v(100_000)])), "32-byte EOF");
    assert_eq!(tx(cat(&[&ver, &v(100_001)])), "implausible input count 100001");
    let input = cat(&[&ver, &v(1), &[0u8; 32], &[0u8; 4]]);
    let cap = MAX_SCRIPT_SIG_LEN as u64;
    assert_eq!(tx(cat(&[&input, &v(cap)])), format!("{cap}-byte EOF"));
    assert_eq!(tx(cat(&[&input, &v(cap + 1)])), format!("implausible script_sig length {}", cap + 1));
    let no_inputs = cat(&[&ver, &v(0)]);
    assert_eq!(tx(cat(&[&no_inputs, &v(100_000)])), "u64 EOF");
    assert_eq!(tx(cat(&[&no_inputs, &v(100_001)])), "implausible output count 100001");
    let output = cat(&[&no_inputs, &v(1), &[0u8; 8]]);
    assert_eq!(tx(cat(&[&output, &v(10_000)])), "10000-byte EOF");
    assert_eq!(tx(cat(&[&output, &v(10_001)])), "implausible script_pubkey length 10001");

    let header = genesis_block().header.to_wire_bytes(0, 0);
    let blk = |b: Vec<u8>| Block::from_wire_bytes(&b).unwrap_err();
    assert_eq!(blk(cat(&[&header, &v(1_000_000)])), "tx[0] parse: u32 EOF");
    assert_eq!(blk(cat(&[&header, &v(1_000_001)])), "implausible tx count 1000001");
    let no_txs = cat(&[&header, &v(0)]);
    assert_eq!(blk(cat(&[&no_txs, &v(100_000)])), "shielded[0]: 32-byte EOF");
    assert_eq!(blk(cat(&[&no_txs, &v(100_001)])), "implausible shielded count 100001");
    let stx = cat(&[&no_txs, &v(1), &[0u8; 32]]);
    assert_eq!(blk(cat(&[&stx, &v(100_000)])), "shielded[0]: 32-byte EOF");
    assert_eq!(blk(cat(&[&stx, &v(100_001)])), "shielded[0]: implausible nullifier count 100001");
    let stx = cat(&[&stx, &v(0)]);
    assert_eq!(blk(cat(&[&stx, &v(100_000)])), "shielded[0]: 32-byte EOF");
    assert_eq!(blk(cat(&[&stx, &v(100_001)])), "shielded[0]: implausible output count 100001");
    let stx = cat(&[&stx, &v(0), &[0u8; 8]]);
    assert_eq!(blk(cat(&[&stx, &v(8_000_000)])), "shielded[0]: 8000000-byte EOF");
    assert_eq!(blk(cat(&[&stx, &v(8_000_001)])), "shielded[0]: implausible proof length 8000001");
    let stx = cat(&[&stx, &v(0)]);
    assert_eq!(blk(cat(&[&stx, &v(100_000)])), "shielded[0]: 100000-byte EOF");
    assert_eq!(blk(cat(&[&stx, &v(100_001)])), "shielded[0]: implausible binding_sig length 100001");
    // A complete minimal block body (no txs, no shielded) parses.
    assert!(Block::from_wire_bytes(&cat(&[&no_txs, &v(0)])).is_ok());
}

// ── script_sig framing ───────────────────────────────────────────────────────

#[test]
fn script_sig_framing_boundaries() {
    let sig = [1u8, 2, 3];
    let pk = [4u8, 5];
    let w = Transaction::build_script_sig(&sig, &pk);
    assert_eq!(w, [3, 0, 0, 0, 1, 2, 3, 2, 0, 0, 0, 4, 5]);
    assert_eq!(Transaction::parse_script_sig(&w), Some((sig.to_vec(), pk.to_vec())));
    assert_eq!(Transaction::parse_script_sig_borrowed(&w), Some((&sig[..], &pk[..])));
    assert_eq!(Transaction::parse_script_sig_exact(&w), Some((&sig[..], &pk[..])));

    // The shortest witness: 8 bytes, empty signature and key.
    let empty = Transaction::build_script_sig(&[], &[]);
    assert_eq!(empty.len(), 8);
    assert_eq!(Transaction::parse_script_sig_exact(&empty), Some((&[][..], &[][..])));
    assert_eq!(Transaction::parse_script_sig_borrowed(&empty[..7]), None);
    assert_eq!(Transaction::parse_script_sig_borrowed(&[3, 0, 0]), None, "shorter than a length field");
    // An empty key right at the end of the bytes.
    let no_pk = Transaction::build_script_sig(&sig, &[]);
    assert_eq!(Transaction::parse_script_sig_exact(&no_pk), Some((&sig[..], &[][..])));
    // Truncated inside the key-length field and inside the key.
    for cut in [w.len() - 1, 4 + sig.len() + 3, 4 + sig.len(), 9, 8] {
        assert_eq!(Transaction::parse_script_sig_borrowed(&w[..cut]), None, "cut {cut}");
        assert_eq!(Transaction::parse_script_sig(&w[..cut]), None, "cut {cut}");
    }
    // A declared length past the end never panics.
    let mut huge = w.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Transaction::parse_script_sig_borrowed(&huge), None);
    // Trailing bytes: refused by both (this chain's v2 framing is exact).
    let mut trailing = w.clone();
    trailing.extend_from_slice(&[0, 0]);
    assert_eq!(Transaction::parse_script_sig_borrowed(&trailing), None);
    assert_eq!(Transaction::parse_script_sig_exact(&trailing), None);
}

// ── Undo records ─────────────────────────────────────────────────────────────

#[test]
fn undo_mutation_count_sums_the_four_lists() {
    let mut u = UndoData::new([1; 32], 3);
    assert_eq!(u.mutation_count(), 0);
    let e = UndoEntry { prev_txid: [2; 32], prev_index: 1, output: TxOutput { value: 5, script_pubkey: vec![1; 20] } };
    u.spent_utxos = vec![e.clone(), e];
    u.created_utxo_keys = vec![([3; 32], 0); 3];
    u.coinbase_txids = vec![[4; 32]; 5];
    u.tx_index_keys = vec![[5; 32]; 7];
    assert_eq!(u.mutation_count(), 17);
}

/// Any single non-empty overwrite list forces the extension, and the record
/// round-trips with exactly that list.
#[test]
fn undo_extension_is_written_for_each_single_overwrite() {
    assert!(UndoOverwrites::default().is_empty());
    for which in 0..3 {
        let mut u = UndoData::new([1; 32], 3);
        match which {
            0 => u.overwritten.utxos.push(UndoEntry {
                prev_txid: [2; 32], prev_index: 4, output: TxOutput { value: 9, script_pubkey: vec![3; 20] },
            }),
            1 => u.overwritten.coinbase_heights.push(([2; 32], 6)),
            _ => u.overwritten.tx_index.push(([2; 32], [3; 32], 6)),
        }
        assert!(!u.overwritten.is_empty(), "case {which}");
        let bytes = u.to_bytes().unwrap();
        assert_eq!(&bytes[37..41], b"UDX1", "37-byte legacy record, then the extension (case {which})");
        let back = UndoData::from_bytes(&bytes).unwrap();
        assert_eq!((back.block_hash, back.block_height), ([1; 32], 3));
        let o = &back.overwritten;
        assert_eq!((o.utxos.len(), o.coinbase_heights.len(), o.tx_index.len()),
            [(1, 0, 0), (0, 1, 0), (0, 0, 1)][which]);
    }
}

#[test]
fn undo_trailing_bytes_are_classified() {
    let u = UndoData::new([1; 32], 3);
    let legacy = u.to_bytes().unwrap();
    assert_eq!(legacy.len(), 37, "hash, height and four empty lists");
    let with = |tail: &[u8]| UndoData::from_bytes(&[&legacy[..], tail].concat()).unwrap_err();
    assert_eq!(with(b"XXXX"), "undo record: 4 unexpected trailing byte(s)");
    assert_eq!(with(b"UD"), "undo record: 2 unexpected trailing byte(s)");
    assert!(with(b"UDX1").starts_with("undo extension decode"), "magic without a body");
    let mut x = UndoData::new([1; 32], 3);
    x.overwritten.coinbase_heights.push(([2; 32], 6));
    let mut bytes = x.to_bytes().unwrap();
    bytes.push(0);
    assert_eq!(UndoData::from_bytes(&bytes).unwrap_err(), "undo extension: 1 trailing byte(s)");
}
