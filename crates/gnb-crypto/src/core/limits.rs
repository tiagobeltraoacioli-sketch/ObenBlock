//! Consensus value-range and canonical-size helpers (audit VAL-11, VAL-12).
//!
//! # VAL-11: MoneyRange
//!
//! The 1 M OBB cap follows from the genesis ledger, the subsidy schedule,
//! the coinbase rule (witness-share outputs included) and value conservation; nothing compared amounts with
//! [`tokenomics::MAX_SUPPLY_SAT`] at validation time. [`money_range`] and the
//! `check_*_money_range` helpers below are the Bitcoin-Core-style defence in
//! depth, on exactly the sums Bitcoin Core bounds: every output, each
//! transaction's output total (here), each transaction's input total and the
//! block's accumulated fees (the connect path, `node/src/accept.rs`) must
//! stay within `0..=MAX_SUPPLY_SAT`. Each of these is a sum of DISTINCT coins
//! (a transaction's inputs are distinct outpoints, its outputs at most its
//! inputs, and fees are conserved along in-block chains), so no valid block
//! violates them and adding them changes no validity outcome; they only turn
//! a hypothetical future arithmetic bug into a clean rejection instead of an
//! inflation. A block-wide output total is NOT such a sum: chained in-block
//! spends count the same coins once per hop. The VAL-11 remediation had added
//! one, which rejected valid blocks at every height; it was removed
//! (re-audit B1-T1, [`check_block_money_range`]).
//!
//! # VAL-12: canonical-encoding size rules
//!
//! The wire parser (`Transaction::from_wire_bytes`, `Block::from_wire_bytes`)
//! enforces count and length caps (10,000-byte scripts, 100,000 inputs /
//! outputs, ...). A block built in-process (RPC `submitblock` after decode is
//! fine, but the miner, a test harness or any future in-process producer is
//! not) never went through the parser, so it could carry a larger field, be
//! accepted, persisted, and then fail to load from disk. The constants below
//! mirror the parser's caps exactly and [`check_block_canonical_limits`]
//! enforces them on the in-memory value, so every accepted block is guaranteed
//! to round-trip through its canonical wire encoding. Again a no-op for every
//! block that arrives over the network (it was parsed, so it already obeys
//! the caps). `limits_match_the_wire_parser` (script lengths) and
//! `count_and_size_caps_match_the_wire_parser` (every other cap) keep the two
//! in sync, each cap at and one past its value.
//!
//! Block SIZE (`MAX_BLOCK_SIZE`) is not measured here. On this chain the
//! consensus measure is the canonical wire encoding at every height (below
//! the hardening activation `super::block_rules::legacy_block_size`,
//! `Block::size_bytes`; at and after it `Block::wire_size()`, the same
//! length, `super::block_rules::block_size_for_rules`, audit VAL-12
//! residual), which writes the uncommitted `blue_score` at a fixed width
//! (re-audit B1-T0). Both are checked by `block_rules::check_block_size_at`,
//! called by `Block::validate_structure` and by `accept_block` at the
//! verified height, and every producer (miner template, `getblocktemplate`)
//! budgets with the measure of the template's height.

use super::{tokenomics, Block, Transaction, MAX_PARENTS};

/// Maximum `script_sig` length (wire parser cap, `core::MAX_SCRIPT_SIG_LEN`):
/// the largest policy witness (7-of-7 multisig, `core::policy`), so every
/// policy output stays spendable (a 10,000-byte cap made the 2-of-3 team
/// vesting unspendable, review F1).
pub const MAX_SCRIPT_SIG_SIZE: usize = super::MAX_SCRIPT_SIG_LEN;
/// Maximum `script_pubkey` length (wire parser cap).
pub const MAX_SCRIPT_PUBKEY_SIZE: usize = 10_000;
/// Maximum inputs per transaction (wire parser cap).
pub const MAX_TX_INPUTS: usize = 100_000;
/// Maximum outputs per transaction (wire parser cap).
pub const MAX_TX_OUTPUTS: usize = 100_000;
/// Maximum transparent transactions per block (wire parser cap).
pub const MAX_BLOCK_TXS: usize = 1_000_000;
/// Maximum shielded transactions per block (wire parser cap).
pub const MAX_BLOCK_SHIELDED_TXS: usize = 100_000;
/// Maximum nullifiers / output commitments per shielded tx (wire parser cap).
pub const MAX_SHIELDED_NULLIFIERS: usize = 100_000;
/// Maximum output commitments per shielded tx (wire parser cap).
pub const MAX_SHIELDED_OUTPUTS: usize = 100_000;
/// Maximum shielded proof length (wire parser cap).
pub const MAX_SHIELDED_PROOF_SIZE: usize = 8_000_000;
/// Maximum shielded binding-signature length (wire parser cap).
pub const MAX_SHIELDED_BINDING_SIG_SIZE: usize = 100_000;

/// `MoneyRange`: an amount is valid iff it does not exceed the hard cap.
#[inline]
pub const fn money_range(value: u64) -> bool {
    value <= tokenomics::MAX_SUPPLY_SAT
}

/// Add two amounts, failing on overflow OR on leaving the money range.
pub fn money_add(a: u64, b: u64) -> Result<u64, String> {
    let s = a.checked_add(b).ok_or_else(|| "amount sum overflows u64".to_string())?;
    if !money_range(s) {
        return Err(format!("amount sum {s} exceeds MAX_SUPPLY_SAT"));
    }
    Ok(s)
}

/// Every output of `tx` and their running sum must be within the money
/// range. Returns the output total.
pub fn check_tx_money_range(tx: &Transaction) -> Result<u64, String> {
    let mut total: u64 = 0;
    for (i, o) in tx.outputs.iter().enumerate() {
        if !money_range(o.value) {
            return Err(format!("output {i} value {} exceeds MAX_SUPPLY_SAT", o.value));
        }
        total = money_add(total, o.value).map_err(|e| format!("output total: {e}"))?;
    }
    Ok(total)
}

/// MoneyRange over every transaction of a block (coinbase included, its
/// witness-share outputs from `powit_height()` too): each output and each
/// transaction's output total (`check_tx_money_range`), and each shielded
/// fee. The coinbase's total is further bounded by the subsidy plus the
/// fees (`Block::validate_coinbase_value`: the miner output plus one
/// `per_attester` output per witness share).
///
/// There is NO block-wide output total (re-audit B1-T1). The value moving
/// through a chain of in-block spends is counted once per hop, so the
/// outputs of a valid block can sum far above the supply (three hops of
/// 400,000 OBB sum to 1,200,000, above the 1,000,000 cap); the sum
/// bounds nothing. The remaining
/// bounds are Bitcoin Core's: `nValueOut` per transaction (CheckTransaction),
/// the input total per transaction (CheckTxInputs, `accept.rs`) and the
/// accumulated block fees (ConnectBlock, `bad-txns-accumulated-fee-
/// outofrange`, `accept.rs`), a conserved quantity. A block-wide output sum
/// briefly existed (VAL-11 remediation): it rejected valid blocks at every
/// height and poisoned templates carrying such a mempool chain.
pub fn check_block_money_range(block: &Block) -> Result<(), String> {
    for (i, tx) in block.transactions.iter().enumerate() {
        check_tx_money_range(tx).map_err(|e| format!("tx[{i}]: {e}"))?;
    }
    for (i, stx) in block.shielded_transactions.iter().enumerate() {
        if !money_range(stx.fee) {
            return Err(format!("shielded[{i}] fee exceeds MAX_SUPPLY_SAT"));
        }
    }
    Ok(())
}

/// The wire parser's per-transaction caps, enforced on the in-memory value.
pub fn check_tx_canonical_limits(tx: &Transaction) -> Result<(), String> {
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err(format!("{} inputs exceed the {} cap", tx.inputs.len(), MAX_TX_INPUTS));
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err(format!("{} outputs exceed the {} cap", tx.outputs.len(), MAX_TX_OUTPUTS));
    }
    for (i, inp) in tx.inputs.iter().enumerate() {
        if inp.script_sig.len() > MAX_SCRIPT_SIG_SIZE {
            return Err(format!(
                "input {i} script_sig of {} bytes exceeds the {} cap",
                inp.script_sig.len(), MAX_SCRIPT_SIG_SIZE
            ));
        }
    }
    for (i, out) in tx.outputs.iter().enumerate() {
        if out.script_pubkey.len() > MAX_SCRIPT_PUBKEY_SIZE {
            return Err(format!(
                "output {i} script_pubkey of {} bytes exceeds the {} cap",
                out.script_pubkey.len(), MAX_SCRIPT_PUBKEY_SIZE
            ));
        }
    }
    Ok(())
}

/// The wire parser's block-level caps (parents, tx counts, every tx, every
/// shielded field), enforced on the in-memory value. A block passing this
/// check is guaranteed to round-trip through `to_wire_bytes` /
/// `from_wire_bytes`.
pub fn check_block_canonical_limits(block: &Block) -> Result<(), String> {
    if block.header.parents.len() > MAX_PARENTS {
        return Err(format!("{} parents exceed the {} cap", block.header.parents.len(), MAX_PARENTS));
    }
    if block.transactions.len() > MAX_BLOCK_TXS {
        return Err(format!("{} transactions exceed the {} cap", block.transactions.len(), MAX_BLOCK_TXS));
    }
    for (i, tx) in block.transactions.iter().enumerate() {
        check_tx_canonical_limits(tx).map_err(|e| format!("tx[{i}]: {e}"))?;
    }
    if block.shielded_transactions.len() > MAX_BLOCK_SHIELDED_TXS {
        return Err(format!(
            "{} shielded transactions exceed the {} cap",
            block.shielded_transactions.len(), MAX_BLOCK_SHIELDED_TXS
        ));
    }
    for (i, stx) in block.shielded_transactions.iter().enumerate() {
        if stx.nullifiers.len() > MAX_SHIELDED_NULLIFIERS
            || stx.outputs.len() > MAX_SHIELDED_OUTPUTS
            || stx.proof.len() > MAX_SHIELDED_PROOF_SIZE
            || stx.binding_sig.len() > MAX_SHIELDED_BINDING_SIG_SIZE
        {
            return Err(format!("shielded[{i}] exceeds a wire-format cap"));
        }
    }
    Ok(())
}

/// Context-free consensus checks added by the 2026-10 audit fixes, in one
/// call: canonical-encoding limits (VAL-12) then MoneyRange (VAL-11).
pub fn check_block_context_free(block: &Block) -> Result<(), String> {
    check_block_canonical_limits(block)?;
    check_block_money_range(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BlockHeader, MerkleRoot, TxInput, TxOutput};

    fn tx(script_sig_len: usize, spk_len: usize, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32], prev_index: 0,
                script_sig: vec![0xAB; script_sig_len], sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value, script_pubkey: vec![0xCD; spk_len] }],
            locktime: 0,
        }
    }

    fn block_with(txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1, parents: vec![[7u8; 32]], merkle_root: MerkleRoot::ZERO,
                timestamp: 0, bits: 0, nonce: 0,
            },
            transactions: txs,
            blue_score: 1, height: 1, shielded_transactions: vec![],
            powit: Default::default(),
        }
    }

    /// The constants must equal the parser's caps: a field at the cap parses,
    /// one byte over is refused by BOTH the parser and the consensus helper.
    #[test]
    fn limits_match_the_wire_parser() {
        let at = tx(MAX_SCRIPT_SIG_SIZE, MAX_SCRIPT_PUBKEY_SIZE, 1);
        assert!(Transaction::from_wire_bytes(&at.to_wire_bytes(true)).is_ok());
        assert!(check_tx_canonical_limits(&at).is_ok());

        let big_sig = tx(MAX_SCRIPT_SIG_SIZE + 1, 20, 1);
        assert!(Transaction::from_wire_bytes(&big_sig.to_wire_bytes(true)).is_err());
        assert!(check_tx_canonical_limits(&big_sig).is_err());

        let big_spk = tx(10, MAX_SCRIPT_PUBKEY_SIZE + 1, 1);
        assert!(Transaction::from_wire_bytes(&big_spk.to_wire_bytes(true)).is_err());
        assert!(check_tx_canonical_limits(&big_spk).is_err());
    }

    /// Every count and length cap of the parser other than the scripts (above),
    /// at the cap and one past it: at the cap the value passes the consensus
    /// helper and its wire encoding parses back to the same encoding; one
    /// past, the parser refuses it ON THAT CAP (its own "implausible ..."
    /// error, not a truncation) and the helper refuses it too. An off-by-one
    /// between `check_*_canonical_limits` and the parser on any cap fails
    /// here. (The fuzz target `wire_roundtrip` generates values at and past
    /// the script and parent caps only: the count caps need megabytes.)
    /// Peak memory about 150 MB (a block of 1,000,001 empty transactions).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "builds, encodes and parses a block of 1,000,000 transactions (block_count_caps_are_inclusive \
                  only builds and checks it and was still running after 17 minutes under Miri), transactions \
                  of 100,000 inputs and outputs and an 8 MB proof; the parser and check_*_canonical_limits run \
                  under Miri in limits_match_the_wire_parser and the other tests of this module"
    )]
    fn count_and_size_caps_match_the_wire_parser() {
        use coherence_core::ShieldedTx;

        fn bare_tx(n_in: usize, n_out: usize) -> Transaction {
            Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [2u8; 32], prev_index: 0, script_sig: vec![], sequence: 0 }; n_in],
                outputs: vec![TxOutput { value: 1, script_pubkey: vec![] }; n_out],
                locktime: 0,
            }
        }
        fn stx(nullifiers: usize, outputs: usize, proof: usize, sig: usize) -> ShieldedTx {
            ShieldedTx {
                anchor: [3u8; 32],
                nullifiers: vec![[4u8; 32]; nullifiers],
                outputs: vec![[5u8; 32]; outputs],
                fee: 0,
                proof: vec![6u8; proof],
                binding_sig: vec![7u8; sig],
            }
        }
        fn check_tx(tx: &Transaction, within: bool, refusal: &str) {
            let bytes = tx.to_wire_bytes(true);
            assert_eq!(check_tx_canonical_limits(tx).is_ok(), within, "{refusal}: consensus helper");
            match Transaction::from_wire_bytes(&bytes) {
                Ok(back) => {
                    assert!(within, "{refusal}: the parser accepted a value past the cap");
                    assert!(back.to_wire_bytes(true) == bytes, "{refusal}: round trip changed the encoding");
                }
                Err(e) => {
                    assert!(!within, "{refusal}: the parser refused a value at the cap: {e}");
                    assert!(e.contains(refusal), "{refusal}: refused for another reason: {e}");
                }
            }
        }
        fn check_block(b: &Block, within: bool, refusal: &str) {
            let bytes = b.to_wire_bytes();
            assert_eq!(check_block_canonical_limits(b).is_ok(), within, "{refusal}: consensus helper");
            match Block::from_wire_bytes(&bytes) {
                Ok(back) => {
                    assert!(within, "{refusal}: the parser accepted a value past the cap");
                    assert!(back.to_wire_bytes() == bytes, "{refusal}: round trip changed the encoding");
                }
                Err(e) => {
                    assert!(!within, "{refusal}: the parser refused a value at the cap: {e}");
                    assert!(e.contains(refusal), "{refusal}: refused for another reason: {e}");
                }
            }
        }

        // Inputs and outputs per transaction.
        for (n, within) in [(MAX_TX_INPUTS, true), (MAX_TX_INPUTS + 1, false)] {
            check_tx(&bare_tx(n, 1), within, "implausible input count");
        }
        for (n, within) in [(MAX_TX_OUTPUTS, true), (MAX_TX_OUTPUTS + 1, false)] {
            check_tx(&bare_tx(1, n), within, "implausible output count");
        }

        // Parents per header.
        for (n, within) in [(MAX_PARENTS, true), (MAX_PARENTS + 1, false)] {
            let mut b = block_with(vec![]);
            b.header.parents = vec![[9u8; 32]; n];
            check_block(&b, within, "implausible parent count");
        }

        // Transactions per block (empty transactions: 10 wire bytes each).
        for (n, within) in [(MAX_BLOCK_TXS, true), (MAX_BLOCK_TXS + 1, false)] {
            check_block(&block_with(vec![bare_tx(0, 0); n]), within, "implausible tx count");
        }

        // Shielded transactions per block, and each shielded field.
        let shielded = |txs: Vec<ShieldedTx>| {
            let mut b = block_with(vec![]);
            b.shielded_transactions = txs;
            b
        };
        for (n, within) in [(MAX_BLOCK_SHIELDED_TXS, true), (MAX_BLOCK_SHIELDED_TXS + 1, false)] {
            check_block(&shielded(vec![stx(0, 0, 0, 0); n]), within, "implausible shielded count");
        }
        for (n, within) in [(MAX_SHIELDED_NULLIFIERS, true), (MAX_SHIELDED_NULLIFIERS + 1, false)] {
            check_block(&shielded(vec![stx(n, 0, 0, 0)]), within, "implausible nullifier count");
        }
        for (n, within) in [(MAX_SHIELDED_OUTPUTS, true), (MAX_SHIELDED_OUTPUTS + 1, false)] {
            check_block(&shielded(vec![stx(0, n, 0, 0)]), within, "implausible output count");
        }
        for (n, within) in [(MAX_SHIELDED_PROOF_SIZE, true), (MAX_SHIELDED_PROOF_SIZE + 1, false)] {
            check_block(&shielded(vec![stx(0, 0, n, 0)]), within, "implausible proof length");
        }
        for (n, within) in [(MAX_SHIELDED_BINDING_SIG_SIZE, true), (MAX_SHIELDED_BINDING_SIG_SIZE + 1, false)] {
            check_block(&shielded(vec![stx(0, 0, 0, n)]), within, "implausible binding_sig length");
        }
    }

    /// VAL-12 regression: an in-process block with a script_sig one byte
    /// over the parser cap (the audit PoC shape, scaled to this chain's
    /// policy-witness cap) is refused by the consensus helper; a block that
    /// passes the helper always round-trips through its wire encoding.
    #[test]
    fn oversized_script_block_is_refused_and_valid_block_round_trips() {
        let bad = block_with(vec![tx(MAX_SCRIPT_SIG_SIZE + 1, 20, 1_000)]);
        assert!(check_block_context_free(&bad).is_err());
        assert!(Block::from_wire_bytes(&bad.to_wire_bytes()).is_err(),
            "the parser refuses it too: such a block could never be read back");

        let good = block_with(vec![tx(8_000, 20, 1_000)]);
        assert!(check_block_context_free(&good).is_ok());
        assert!(Block::from_wire_bytes(&good.to_wire_bytes()).is_ok());
    }

    #[test]
    fn too_many_parents_is_refused() {
        let mut b = block_with(vec![tx(1, 20, 1)]);
        b.header.parents = vec![[1u8; 32]; MAX_PARENTS + 1];
        assert!(check_block_canonical_limits(&b).is_err());
        b.header.parents.truncate(MAX_PARENTS);
        assert!(check_block_canonical_limits(&b).is_ok());
    }

    /// VAL-11: amounts above the cap, and sums leaving the money range, are
    /// rejected; the cap itself is in range.
    #[test]
    fn money_range_rejects_amounts_and_sums_above_the_cap() {
        let cap = tokenomics::MAX_SUPPLY_SAT;
        assert!(money_range(0) && money_range(cap) && !money_range(cap + 1));
        assert_eq!(money_add(cap - 1, 1), Ok(cap));
        assert!(money_add(cap, 1).is_err());
        assert!(money_add(u64::MAX, 1).is_err());

        assert!(check_tx_money_range(&tx(1, 20, cap)).is_ok());
        assert!(check_tx_money_range(&tx(1, 20, cap + 1)).is_err());

        let mut two = tx(1, 20, cap / 2 + 1);
        two.outputs.push(two.outputs[0].clone());
        assert!(check_tx_money_range(&two).is_err(), "sum of two in-range outputs above the cap");

        // Block-wide: no rule bounds the sum of all outputs of a block
        // (re-audit B1-T1); each transaction is checked on its own.
        let b = block_with(vec![tx(1, 20, cap / 2 + 1), tx(2, 20, cap / 2 + 1)]);
        assert_eq!(check_block_money_range(&b), Ok(()));
        let ok = block_with(vec![tx(1, 20, 1_000), tx(2, 20, 2_000)]);
        assert!(check_block_money_range(&ok).is_ok());
        let bad = block_with(vec![tx(1, 20, 1_000), tx(2, 20, cap + 1)]);
        assert_eq!(check_block_money_range(&bad), Err(format!("tx[1]: output 0 value {} exceeds MAX_SUPPLY_SAT", cap + 1)));
    }

    /// Re-audit B1-T1: a chain of in-block spends moves the same coins once
    /// per hop. Three hops of 400,000 OBB (1,200,000 OBB of outputs, above
    /// the 1,000,000 OBB supply) are within every MoneyRange rule; the
    /// block-wide output total the VAL-11 remediation added refused it.
    #[test]
    fn chained_spends_above_the_supply_in_total_are_in_range() {
        let v = 400_000 * tokenomics::SAT_PER_GNB;
        let mut txs = Vec::new();
        let mut prev = [0x31u8; 32];
        for hop in 0..3u64 {
            let mut t = tx(hop as usize + 1, 20, v - 100_000 * (hop + 1));
            t.inputs[0].prev_txid = prev;
            prev = t.txid();
            txs.push(t);
        }
        let total: u128 = txs.iter().flat_map(|t| &t.outputs).map(|o| u128::from(o.value)).sum();
        assert!(total > u128::from(tokenomics::MAX_SUPPLY_SAT));
        let b = block_with(txs);
        assert_eq!(check_block_money_range(&b), Ok(()));
        assert_eq!(check_block_context_free(&b), Ok(()));
    }

    fn shielded(fee: u64) -> coherence_core::ShieldedTx {
        coherence_core::ShieldedTx {
            anchor: [0; 32], nullifiers: vec![], outputs: vec![], fee, proof: vec![], binding_sig: vec![],
        }
    }

    #[test]
    fn shielded_fee_is_in_the_money_range() {
        let cap = tokenomics::MAX_SUPPLY_SAT;
        let mut b = block_with(vec![tx(1, 20, 1_000)]);
        b.shielded_transactions = vec![shielded(5), shielded(cap)];
        assert_eq!(check_block_money_range(&b), Ok(()));
        b.shielded_transactions.push(shielded(cap + 1));
        assert_eq!(check_block_money_range(&b), Err("shielded[2] fee exceeds MAX_SUPPLY_SAT".into()));
    }

    /// Input and output counts: the cap is allowed, one more is not.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "builds a transaction of 100,000 inputs and 100,000 outputs and clones it (one heap \
                  allocation per input and output): still running after 9 minutes under Miri; \
                  check_tx_canonical_limits runs under Miri in the other tests of this module"
    )]
    fn transaction_count_caps_are_inclusive() {
        let mut t = tx(1, 20, 1);
        t.inputs = vec![t.inputs[0].clone(); MAX_TX_INPUTS];
        t.outputs = vec![t.outputs[0].clone(); MAX_TX_OUTPUTS];
        assert_eq!(check_tx_canonical_limits(&t), Ok(()));
        let mut more_in = t.clone();
        more_in.inputs.push(more_in.inputs[0].clone());
        assert_eq!(check_tx_canonical_limits(&more_in), Err("100001 inputs exceed the 100000 cap".into()));
        let mut more_out = t;
        more_out.outputs.push(more_out.outputs[0].clone());
        assert_eq!(check_tx_canonical_limits(&more_out), Err("100001 outputs exceed the 100000 cap".into()));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "builds blocks of 1,000,000 transactions and 100,000 shielded transactions (one clone, one \
                  check and one drop per element): still running after 17 minutes under Miri; \
                  check_block_canonical_limits runs under Miri in the other cap tests of this module"
    )]
    fn block_count_caps_are_inclusive() {
        let empty_tx = Transaction { version: 1, inputs: vec![], outputs: vec![], locktime: 0 };
        let mut b = block_with(vec![empty_tx; MAX_BLOCK_TXS]);
        assert_eq!(check_block_canonical_limits(&b), Ok(()));
        b.transactions.push(b.transactions[0].clone());
        assert_eq!(check_block_canonical_limits(&b), Err("1000001 transactions exceed the 1000000 cap".into()));

        let mut b = block_with(vec![tx(1, 20, 1)]);
        b.shielded_transactions = vec![shielded(0); MAX_BLOCK_SHIELDED_TXS];
        assert_eq!(check_block_canonical_limits(&b), Ok(()));
        b.shielded_transactions.push(shielded(0));
        assert_eq!(check_block_canonical_limits(&b), Err("100001 shielded transactions exceed the 100000 cap".into()));
    }

    /// Every per-shielded-transaction field: at the cap passes, one over fails.
    #[test]
    fn shielded_field_caps_are_inclusive() {
        type Set = fn(&mut coherence_core::ShieldedTx, usize);
        let fields: [(Set, usize); 4] = [
            (|s, n| s.nullifiers = vec![[1; 32]; n], MAX_SHIELDED_NULLIFIERS),
            (|s, n| s.outputs = vec![[2; 32]; n], MAX_SHIELDED_OUTPUTS),
            (|s, n| s.proof = vec![3; n], MAX_SHIELDED_PROOF_SIZE),
            (|s, n| s.binding_sig = vec![4; n], MAX_SHIELDED_BINDING_SIG_SIZE),
        ];
        for (k, (set, cap)) in fields.into_iter().enumerate() {
            let mut b = block_with(vec![tx(1, 20, 1)]);
            let mut s = shielded(0);
            set(&mut s, cap);
            b.shielded_transactions = vec![shielded(0), s];
            assert_eq!(check_block_canonical_limits(&b), Ok(()), "field {k} at the cap");
            set(&mut b.shielded_transactions[1], cap + 1);
            assert_eq!(check_block_canonical_limits(&b), Err("shielded[1] exceeds a wire-format cap".into()), "field {k}");
        }
    }

    #[test]
    fn context_free_check_runs_both_rules() {
        let mut b = block_with(vec![tx(1, 20, tokenomics::MAX_SUPPLY_SAT + 1)]);
        assert_eq!(check_block_context_free(&b), Err(format!("tx[0]: output 0 value {} exceeds MAX_SUPPLY_SAT", tokenomics::MAX_SUPPLY_SAT + 1)));
        b.transactions[0].outputs[0].value = 1;
        assert_eq!(check_block_context_free(&b), Ok(()));
        b.header.parents = vec![[1; 32]; MAX_PARENTS + 1];
        assert_eq!(check_block_context_free(&b), Err("257 parents exceed the 256 cap".into()));
    }

    /// Supply invariant: the whole mining schedule plus the carryover is in
    /// range, so MoneyRange can never reject an honestly issued amount.
    #[test]
    fn issued_supply_is_within_money_range() {
        let mined = tokenomics::issued_through_sat(u64::MAX);
        let total = money_add(mined, crate::core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT)
            .expect("issued supply is in range");
        assert!(money_range(total));
        assert!(money_range(tokenomics::block_subsidy_sat(1)));
    }
}
