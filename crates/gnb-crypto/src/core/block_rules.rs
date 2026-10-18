//! Hardening block-validity rules (audit 2026-10-14: VAL-2, VAL-3, VAL-10,
//! CRY-1 witness commitment, VAL-12 block size, POW-3 pow limit).
//!
//! Every rule here applies to a block iff [`rules_active_at`]`(block.height,
//! activation_height)`: the block is not the genesis and its HEADER height
//! (`Block::height`, which `accept_block` requires to equal
//! `max(parent DAG heights) + 1`) is at or above the hardening activation
//! height (`super::activation`). Below that height the old rules apply
//! bit-for-bit. `docs/CONSENSUS.md` ("Block rules at the hardening
//! activation") is the byte-exact specification and `reference/gnb_merkle.py`
//! the executable one; `reference/merkle_vectors.json` pins both
//! (`crates/gnb-crypto/tests/merkle_vectors.rs`).
//!
//! Context-free rules (checked before the block is stored, before any
//! signature work):
//!
//! * **Header Merkle root (VAL-10)**: tagged SHA-256 with distinct leaf and
//!   inner-node tags; an odd node is carried up unchanged (never paired with
//!   itself), so duplicating the last transaction changes the root.
//! * **64-byte transactions (VAL-10)**: a transaction whose txid preimage is
//!   exactly 64 bytes is invalid.
//! * **Coinbase commitment (VAL-2 BIP34 + CRY-1)**: the coinbase `script_sig`
//!   starts with an 80-byte commitment: tag, header height, a hash of the
//!   header's parent list and the witness root (the tagged Merkle root of the
//!   block's wtxids). The block id commits to it through header ->
//!   merkle_root -> coinbase txid (a coinbase txid covers its `script_sig`).
//! * **Block size (VAL-12)**: `MAX_BLOCK_SIZE` is measured on the canonical
//!   wire encoding in both regimes ([`check_block_size_at`], B1-T0 / B2-T8).
//! * **Distinct parents (B2-T10)**: the header lists each parent once
//!   ([`check_parents_distinct`]).
//!
//! In-context rules live in the node's `validate_block_in_view` (BIP30
//! no-overwrite, no spend of the same block's coinbase) and the pow limit in
//! `super::expected_bits` / `Block::validate_pow`.

use sha2::{Digest, Sha256};

use super::{activation, Block, MerkleRoot, Transaction, GENESIS_BITS, POW_LIMIT_BITS};

// ── Activation ───────────────────────────────────────────────────────────────

/// `true` iff the hardening block rules apply to a block at header height
/// `height`: every non-genesis block at or above the activation height. The
/// genesis (height 0) is a constant the node checks by its hash and proof; it
/// never passes through `accept_block`.
#[inline]
pub const fn rules_active_at(height: u64, activation_height: u64) -> bool {
    height >= 1 && activation::is_active_at(height, activation_height)
}

/// [`rules_active_at`] under the process-wide activation height.
pub fn rules_active(height: u64) -> bool {
    rules_active_at(height, activation::hardening_activation_height())
}

// ── Tagged hashing and the Merkle tree (VAL-10) ─────────────────────────────

/// BIP-340-style tagged hash:
/// `SHA-256(SHA-256(tag) || SHA-256(tag) || parts[0] || parts[1] || ...)`.
pub fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t: [u8; 32] = Sha256::digest(tag).into();
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Tag of a Merkle leaf (the hash of one 32-byte id).
pub const MERKLE_LEAF_TAG: &[u8] = b"GnB/merkle/leaf";
/// Tag of an inner Merkle node (the hash of two 32-byte children).
pub const MERKLE_NODE_TAG: &[u8] = b"GnB/merkle/node";

/// `leaf(id) = tagged_hash("GnB/merkle/leaf", id)`.
pub fn merkle_leaf(id: &[u8; 32]) -> [u8; 32] {
    tagged_hash(MERKLE_LEAF_TAG, &[id])
}

/// `node(l, r) = tagged_hash("GnB/merkle/node", l || r)`.
pub fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    tagged_hash(MERKLE_NODE_TAG, &[left, right])
}

/// The tagged Merkle root of `ids`:
///
/// * no ids: 32 zero bytes;
/// * level 0 is `leaf(id)` for every id, in order;
/// * each next level pairs the nodes left to right with `node(l, r)`; when a
///   level has an odd number of nodes its LAST node is carried up unchanged
///   (not hashed, not duplicated);
/// * the root is the single node left.
///
/// Leaves and inner nodes use different tags, so no inner node can be
/// presented as a leaf, and no two id lists of different lengths or contents
/// share a root without a SHA-256 collision (in particular `[.., x]` and
/// `[.., x, x]` differ, unlike Bitcoin's duplicate-last rule).
pub fn tagged_merkle_root(ids: &[[u8; 32]]) -> MerkleRoot {
    if ids.is_empty() {
        return MerkleRoot::ZERO;
    }
    let mut level: Vec<[u8; 32]> = ids.iter().map(merkle_leaf).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => merkle_node(l, r),
                [single] => *single,
                _ => unreachable!("chunks(2) yields one or two items"),
            })
            .collect();
    }
    MerkleRoot(level[0])
}

/// The pre-activation root: SHA-256d over `left || right`, the last node of
/// an odd level paired with itself (Bitcoin's rule). Bit-for-bit the root
/// `Transaction::merkle_root` has always computed.
pub fn legacy_merkle_root(ids: &[[u8; 32]]) -> MerkleRoot {
    if ids.is_empty() {
        return MerkleRoot::ZERO;
    }
    let mut hashes: Vec<[u8; 32]> = ids.to_vec();
    while hashes.len() > 1 {
        if !hashes.len().is_multiple_of(2) {
            if let Some(last) = hashes.last().copied() {
                hashes.push(last);
            }
        }
        hashes = hashes
            .chunks(2)
            .map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                Sha256::digest(Sha256::digest(buf)).into()
            })
            .collect();
    }
    MerkleRoot(hashes[0])
}

/// The header transaction root of `txs` under the rules of the regime:
/// tagged when `hardened`, legacy otherwise.
pub fn tx_merkle_root(txs: &[Transaction], hardened: bool) -> MerkleRoot {
    let ids: Vec<[u8; 32]> = txs.iter().map(Transaction::txid).collect();
    if hardened {
        tagged_merkle_root(&ids)
    } else {
        legacy_merkle_root(&ids)
    }
}

/// Sibling hashes on the path from position 0 (the coinbase) to the root,
/// bottom-up, for a tree over `ids` (`ids[0]` is ignored: the path of
/// position 0 does not depend on it). External miners fold their own coinbase
/// txid through it with [`merkle_root_from_coinbase_branch`].
pub fn coinbase_merkle_branch(ids: &[[u8; 32]], hardened: bool) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    if ids.len() < 2 {
        return branch;
    }
    let mut level: Vec<[u8; 32]> = if hardened {
        ids.iter().map(merkle_leaf).collect()
    } else {
        ids.to_vec()
    };
    while level.len() > 1 {
        branch.push(level[1]);
        if hardened {
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [l, r] => merkle_node(l, r),
                    [single] => *single,
                    _ => unreachable!("chunks(2) yields one or two items"),
                })
                .collect();
        } else {
            if !level.len().is_multiple_of(2) {
                let last = level[level.len() - 1];
                level.push(last);
            }
            level = level
                .chunks(2)
                .map(|p| {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(&p[0]);
                    buf[32..].copy_from_slice(&p[1]);
                    Sha256::digest(Sha256::digest(buf)).into()
                })
                .collect();
        }
    }
    branch
}

/// Fold a coinbase txid through a [`coinbase_merkle_branch`].
pub fn merkle_root_from_coinbase_branch(coinbase_txid: &[u8; 32], branch: &[[u8; 32]], hardened: bool) -> MerkleRoot {
    if hardened {
        let mut cur = merkle_leaf(coinbase_txid);
        for s in branch {
            cur = merkle_node(&cur, s);
        }
        MerkleRoot(cur)
    } else {
        let mut cur = *coinbase_txid;
        for s in branch {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(s);
            cur = Sha256::digest(Sha256::digest(buf)).into();
        }
        MerkleRoot(cur)
    }
}

// ── 64-byte transactions (VAL-10) ───────────────────────────────────────────

/// The forbidden txid-preimage length: a 64-byte preimage has the shape of an
/// inner Merkle node (two 32-byte hashes).
pub const FORBIDDEN_TXID_PREIMAGE_LEN: usize = 64;

/// Length of the bytes `Transaction::txid` hashes:
/// `to_wire_bytes(is_coinbase)` (with `script_sig` for a coinbase, without
/// for every other transaction).
pub fn txid_preimage_len(tx: &Transaction) -> usize {
    tx.wire_size(tx.is_coinbase())
}

/// The 64-byte rule for one transaction.
pub fn check_tx_not_64_bytes(tx: &Transaction) -> Result<(), &'static str> {
    if txid_preimage_len(tx) == FORBIDDEN_TXID_PREIMAGE_LEN {
        return Err("64-byte transaction (txid preimage of exactly 64 bytes)");
    }
    Ok(())
}

// ── Witness ids and the coinbase commitment (VAL-2 BIP34, CRY-1) ─────────────

/// Tag of the parent-list commitment.
pub const PARENTS_TAG: &[u8] = b"GnB/coinbase/parents";
/// First 8 bytes of every coinbase `script_sig` at/after activation.
pub const COINBASE_COMMITMENT_TAG: [u8; 8] = *b"GNB-CB01";
/// Length of the coinbase commitment (tag, height, parents, witness root).
pub const COINBASE_COMMITMENT_LEN: usize = 8 + 8 + 32 + 32;
/// The wtxid the coinbase contributes to the witness tree (its own
/// `script_sig` holds the commitment, so it cannot commit to itself).
pub const COINBASE_WTXID: [u8; 32] = [0u8; 32];

/// `parents_commitment = tagged_hash("GnB/coinbase/parents",
/// u32le(n_parents) || parent_0 || ... || parent_{n-1})`, parents in header
/// order.
pub fn parents_commitment(parents: &[[u8; 32]]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(4 + parents.len() * 32);
    bytes.extend_from_slice(&(parents.len() as u32).to_le_bytes());
    for p in parents {
        bytes.extend_from_slice(p);
    }
    tagged_hash(PARENTS_TAG, &[&bytes])
}

/// Witness root of a block's transaction list: [`tagged_merkle_root`] over
/// `[COINBASE_WTXID, wtxid(tx_1), ..., wtxid(tx_n)]`. Position 0 is the
/// coinbase whatever it contains.
pub fn witness_root(txs: &[Transaction]) -> MerkleRoot {
    let ids: Vec<[u8; 32]> = txs
        .iter()
        .enumerate()
        .map(|(i, t)| if i == 0 { COINBASE_WTXID } else { t.wtxid() })
        .collect();
    tagged_merkle_root(&ids)
}

/// The 80-byte coinbase commitment:
///
/// ```text
/// offset  size  field
///  0       8    "GNB-CB01"
///  8       8    header height, u64 LE (= Block::height)
/// 16      32    parents_commitment(header.parents)
/// 48      32    witness_root(block.transactions)
/// ```
pub fn coinbase_commitment(height: u64, parents: &[[u8; 32]], witness_root: &MerkleRoot) -> [u8; COINBASE_COMMITMENT_LEN] {
    let mut c = [0u8; COINBASE_COMMITMENT_LEN];
    c[0..8].copy_from_slice(&COINBASE_COMMITMENT_TAG);
    c[8..16].copy_from_slice(&height.to_le_bytes());
    c[16..48].copy_from_slice(&parents_commitment(parents));
    c[48..80].copy_from_slice(&witness_root.0);
    c
}

/// The commitment `block` must carry (computed from its height, its header
/// parents and its non-coinbase transactions).
pub fn expected_coinbase_commitment(block: &Block) -> [u8; COINBASE_COMMITMENT_LEN] {
    coinbase_commitment(block.height, &block.header.parents, &body_commitment_root(block))
}

/// The coinbase `script_sig` for a commitment and arbitrary miner bytes.
pub fn coinbase_script_sig(commitment: &[u8; COINBASE_COMMITMENT_LEN], extra: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(COINBASE_COMMITMENT_LEN + extra.len());
    s.extend_from_slice(commitment);
    s.extend_from_slice(extra);
    s
}

/// Check the coinbase commitment of a block whose coinbase format is valid
/// (`Block::validate_coinbase_format`). Byte-exact: any other tag, height
/// encoding, parent commitment or witness root is rejected.
pub fn check_coinbase_commitment(block: &Block) -> Result<(), &'static str> {
    let ss = match block.transactions.first().and_then(|cb| cb.inputs.first()) {
        Some(inp) => &inp.script_sig,
        None => return Err("invalid coinbase format"),
    };
    if ss.len() < COINBASE_COMMITMENT_LEN {
        return Err("coinbase commitment missing (script_sig shorter than 80 bytes)");
    }
    if ss[0..8] != COINBASE_COMMITMENT_TAG {
        return Err("bad coinbase commitment tag");
    }
    if ss[8..16] != block.height.to_le_bytes() {
        return Err("bad-cb-height: coinbase height commitment differs from the block height");
    }
    if ss[16..48] != parents_commitment(&block.header.parents) {
        return Err("bad coinbase parents commitment");
    }
    if ss[48..80] != body_commitment_root(block).0 {
        return Err("bad witness commitment (witness root mismatch)");
    }
    Ok(())
}

// ── Block size (VAL-12; re-audit B1-T0 / B2-T8) ─────────────────────────────

/// The pre-activation `MAX_BLOCK_SIZE` measure: the length of the block's
/// wire encoding, `Block::size_bytes()` (`to_wire_bytes().len()`, the PoWit
/// section included from `powit_height()`): the measure this chain's nodes
/// apply at every height, never a bincode encoding (the audit's VAL-12
/// measured bincode below its activation; this chain never did).
///
/// It does not depend on the uncommitted `blue_score` (re-audit B1-T0 /
/// B2-T8): the wire header writes it as a fixed-width u64, so every copy of
/// a block id (the one gossiped with any value, the one a node stores and
/// serves with the value derived from the parents, POW-8) measures the same,
/// the same as with `blue_score` written as 0. `height` is measured as
/// carried: `accept_block` requires it to equal `max(parent DAG heights) +
/// 1`, so every accepted copy carries the same value (and the same PoWit
/// section presence). docs/CONSENSUS.md, "Block size (VAL-12)";
/// `reference/gnb_validity.py` (`check_structure`).
pub fn legacy_block_size(block: &Block) -> usize {
    block.size_bytes()
}

/// The size `MAX_BLOCK_SIZE` is compared with: the canonical wire encoding
/// (`Block::wire_size`, every field fixed-width or committed, the PoWit
/// section counted) when `hardened`, [`legacy_block_size`] otherwise. On
/// this chain both are the length of `to_wire_bytes()`; neither depends on
/// the uncommitted `blue_score`.
pub fn block_size_for_rules(block: &Block, hardened: bool) -> usize {
    if hardened {
        block.wire_size()
    } else {
        legacy_block_size(block)
    }
}

/// The `MAX_BLOCK_SIZE` rule for a block at its header height under
/// `activation_height`: the ONE size check of `Block::validate_structure`,
/// `check_block_hardened_at` (at/after the activation), `accept_block` and
/// the template self-check.
pub fn check_block_size_at(block: &Block, activation_height: u64) -> Result<(), &'static str> {
    if block_size_for_rules(block, rules_active_at(block.height, activation_height)) > super::MAX_BLOCK_SIZE {
        return Err("block too large");
    }
    Ok(())
}

// ── Pow limit (POW-3) ────────────────────────────────────────────────────────

/// The pow limit at/after activation: the genesis target (Bitcoin's
/// convention, the pow limit is the genesis difficulty).
pub const HARDENED_POW_LIMIT_BITS: u32 = GENESIS_BITS;

/// Pow limit (compact) for a block at header height `height`: the genesis
/// target at/after activation, `POW_LIMIT_BITS` before. Never affected by
/// the `test-pow-limit` feature.
pub const fn pow_limit_bits_at(height: u64, activation_height: u64) -> u32 {
    if rules_active_at(height, activation_height) {
        HARDENED_POW_LIMIT_BITS
    } else {
        POW_LIMIT_BITS
    }
}

// ── The context-free hardening checks ───────────────────────────────────────

/// The context-free rules added at the activation, for a block whose coinbase
/// format is valid: distinct parents (B2-T10), no 64-byte transaction, then
/// the coinbase commitment (tag, height, parents, witness root). Run by
/// `Block::validate_structure` and by `accept_block`.
pub fn check_hardened_body(block: &Block) -> Result<(), &'static str> {
    check_parents_distinct(&block.header.parents)?;
    for tx in &block.transactions {
        check_tx_not_64_bytes(tx)?;
    }
    check_coinbase_commitment(block)
}

/// Every context-free rule that changes at the activation, in cheap-first
/// order: wire size, tagged Merkle root, coinbase format, distinct parents,
/// 64-byte transactions, coinbase commitment. `Ok(())` for a block below the
/// activation (the legacy structural rules are `Block::validate_structure`'s).
/// `accept_block` runs this BEFORE storing the block, so a block whose
/// witnesses were altered in transit (same block id, different `script_sig`
/// bytes) is rejected without being stored or marked invalid.
pub fn check_block_hardened_at(block: &Block, activation_height: u64) -> Result<(), &'static str> {
    if !rules_apply(block.height, activation_height) {
        return Ok(());
    }
    check_block_size_at(block, activation_height)?;
    if !block.validate_merkle_at(activation_height) {
        return Err(super::pow_scheme::merkle_error(block));
    }
    if !block.validate_coinbase_format() {
        return Err("invalid coinbase format");
    }
    check_hardened_body(block)
}

// ── Parent list (audit B2-T10) ──────────────────────────────────────────────

/// From the activation, a header lists each parent once (Kaspa rejects a
/// repeated parent too). A repeated parent is never useful: the DAG treats
/// the list as a set, so `[X, X, Y]` has the GhostDAG data of `[X, Y]`, while
/// the block id and the coinbase parents commitment hash the list as written.
/// O(n log n) over at most `MAX_PARENTS` ids. Parents in the past of another
/// parent stay valid (docs/CONSENSUS.md, "Parent list").
pub fn check_parents_distinct(parents: &[[u8; 32]]) -> Result<(), &'static str> {
    let mut sorted: Vec<&[u8; 32]> = parents.iter().collect();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err("duplicate parent");
    }
    Ok(())
}

// ── ObenBlock (SHA-256d scheme) ─────────────────────────────────────────────

/// Whether the hardening block rules apply to a block at header height
/// `height`: [`rules_active_at`], and under the SHA-256d scheme (ObenBlock)
/// at every height from 1 whatever `activation_height` says. ObenBlock's
/// activation height is 0 on both its networks; this makes the coinbase
/// commitment (and so the commitment of every witness and section byte,
/// which its header root no longer covers) mandatory from the first block
/// even under a test override of the activation height.
pub fn rules_apply(height: u64, activation_height: u64) -> bool {
    rules_active_at(height, activation_height)
        || (height >= 1 && super::pow_scheme::node_sha256d_params().is_some())
}

/// The 32 bytes at offset 48 of the coinbase commitment: GnB's
/// [`witness_root`] (unchanged), or under the SHA-256d scheme the ObenBlock
/// body commitment (`pow_scheme::obb_body_commitment`: witness root,
/// shielded section root and PoWit section root), since there the header
/// root is Bitcoin's transaction tree and covers no other part of the body.
/// Also the key under which a node remembers a rejected body of a block id
/// (`accept_block`).
pub fn body_commitment_root(block: &Block) -> MerkleRoot {
    if super::pow_scheme::node_sha256d_params().is_some() {
        super::pow_scheme::obb_body_commitment(block)
    } else {
        witness_root(&block.transactions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BlockHeader, TxInput, TxOutput};

    fn id(i: u8) -> [u8; 32] {
        [i; 32]
    }

    fn spend(tag: u8, spk_len: usize) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [tag; 32], prev_index: 0, script_sig: vec![tag; 12], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![0x5A; spk_len] }],
            locktime: 0,
        }
    }

    fn coinbase(script_sig: Vec<u8>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 50, script_pubkey: vec![7; 20] }],
            locktime: 0,
        }
    }

    /// Block at `height` whose coinbase carries the right commitment and whose
    /// header root follows the rules at `activation`.
    fn hardened_block(height: u64, activation: u64, txs: Vec<Transaction>) -> Block {
        let mut all = vec![coinbase(vec![])];
        all.extend(txs);
        let mut b = Block {
            header: BlockHeader { version: 1, parents: vec![[0x11; 32], [0x22; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 0, bits: 0, nonce: 0 },
            transactions: all,
            blue_score: height,
            height,
            shielded_transactions: vec![],
            powit: Default::default(),
        };
        let c = expected_coinbase_commitment(&b);
        b.transactions[0].inputs[0].script_sig = coinbase_script_sig(&c, b"extranonce");
        b.header.merkle_root = b.body_merkle_root_at(activation);
        b
    }

    #[test]
    fn activation_predicate_excludes_genesis_and_is_inclusive() {
        assert!(!rules_active_at(0, 0), "the genesis is never subject to the new rules");
        assert!(rules_active_at(1, 0));
        let mainnet = activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
        assert!(!rules_active_at(mainnet - 1, mainnet));
        assert!(rules_active_at(mainnet, mainnet));
        assert!(!rules_active_at(u64::MAX - 1, activation::NEVER));
    }

    /// Tree sizes for the Merkle tests. Under Miri one SHA-256 compression
    /// takes ~0.2 s (docs/testing/SANITIZERS.md), so it covers the shapes that
    /// matter (empty, one leaf, odd and even levels, a carried-up odd node)
    /// and stops at 5 leaves.
    const MAX_LEAVES: u8 = if cfg!(miri) { 5 } else { 17 };

    #[test]
    fn legacy_root_is_bit_identical_to_transaction_merkle_root() {
        for n in 0..12u8.min(MAX_LEAVES + 1) {
            let txs: Vec<Transaction> = (0..n).map(|i| spend(i, 20)).collect();
            let ids: Vec<[u8; 32]> = txs.iter().map(Transaction::txid).collect();
            assert_eq!(legacy_merkle_root(&ids), Transaction::merkle_root(&txs), "n={n}");
            assert_eq!(tx_merkle_root(&txs, false), Transaction::merkle_root(&txs));
        }
    }

    /// The values quoted in docs/CONSENSUS.md ("Block rules at the hardening
    /// activation"), also produced by reference/gnb_merkle.py.
    #[test]
    fn golden_values_from_the_specification() {
        let hx = |b: &[u8]| hex::encode(b);
        assert_eq!(hx(&Sha256::digest(MERKLE_LEAF_TAG)), "f5374e50a66ea5c3d4dd804b6b56ea72f76cc838936f6cf8fdf41de204cfbb39");
        assert_eq!(hx(&Sha256::digest(MERKLE_NODE_TAG)), "d3a90495918b57c20ec960f8474e5273b173a4f60bb5f914eec9dcbe3b4df3ef");
        assert_eq!(hx(&Sha256::digest(PARENTS_TAG)), "d8bddbf4dc09ba30778915646735c84bea68357e54cbd7a2755981cf08a9ebdd");
        let z = [0u8; 32];
        assert_eq!(hx(&merkle_leaf(&z)), "d970168d7ab96cf00e27d7600b8ba51e294ef1708fc990ef1758792061211826");
        assert_eq!(hx(&tagged_merkle_root(&[z, z]).0), "1a90316515bd8a4deade0bb85be8daa5bcd23ccfa1274793622730e72d847326");
        assert_eq!(hx(&legacy_merkle_root(&[z, z]).0), "e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9");
        assert_eq!(hx(&parents_commitment(&[])), "27e1375e12cde54c991c14a28ea371a8317b11276df15d24bd7771b4384ff500");
        assert_eq!(&COINBASE_COMMITMENT_TAG, &[0x47, 0x4e, 0x42, 0x2d, 0x43, 0x42, 0x30, 0x31]);
    }

    #[test]
    fn tagged_root_shapes() {
        assert_eq!(tagged_merkle_root(&[]), MerkleRoot::ZERO);
        let (a, b, c) = (id(1), id(2), id(3));
        assert_eq!(tagged_merkle_root(&[a]).0, merkle_leaf(&a), "one id: the root is its leaf");
        assert_eq!(tagged_merkle_root(&[a, b]).0, merkle_node(&merkle_leaf(&a), &merkle_leaf(&b)));
        // Odd node carried up unchanged.
        let ab = merkle_node(&merkle_leaf(&a), &merkle_leaf(&b));
        assert_eq!(tagged_merkle_root(&[a, b, c]).0, merkle_node(&ab, &merkle_leaf(&c)));
        // Leaves and nodes are separated: the leaf of an id is not the id.
        assert_ne!(merkle_leaf(&a), a);
        assert_ne!(merkle_leaf(&a), tagged_hash(MERKLE_NODE_TAG, &[&a]));
    }

    /// VAL-10 / CVE-2012-2459: duplicating the last id (or the last pair)
    /// keeps the legacy root but never the tagged one.
    #[test]
    fn duplicate_last_mutation_changes_the_tagged_root_only() {
        for n in 1..10u8.min(MAX_LEAVES + 1) {
            let ids: Vec<[u8; 32]> = (1..=n).map(id).collect();
            let mut dup = ids.clone();
            dup.push(*ids.last().unwrap());
            if n % 2 == 1 && n > 1 {
                assert_eq!(legacy_merkle_root(&ids), legacy_merkle_root(&dup), "legacy is ambiguous, n={n}");
            }
            assert_ne!(tagged_merkle_root(&ids), tagged_merkle_root(&dup), "n={n}");
        }
        // Six vs eight (the last two duplicated): the legacy root collides.
        let six: Vec<[u8; 32]> = (1..=6).map(id).collect();
        let mut eight = six.clone();
        eight.extend_from_slice(&six[4..6]);
        assert_eq!(legacy_merkle_root(&six), legacy_merkle_root(&eight));
        assert_ne!(tagged_merkle_root(&six), tagged_merkle_root(&eight));
    }

    #[test]
    fn coinbase_branch_reproduces_the_root() {
        for hardened in [false, true] {
            for n in 1..=MAX_LEAVES {
                let ids: Vec<[u8; 32]> = (1..=n).map(id).collect();
                let want = if hardened { tagged_merkle_root(&ids) } else { legacy_merkle_root(&ids) };
                let branch = coinbase_merkle_branch(&ids, hardened);
                assert_eq!(merkle_root_from_coinbase_branch(&ids[0], &branch, hardened), want, "n={n} hardened={hardened}");
                // The branch does not depend on position 0.
                let mut other = ids.clone();
                other[0] = [0xEE; 32];
                assert_eq!(coinbase_merkle_branch(&other, hardened), branch);
            }
        }
    }

    /// The audit's shape: one input, one output with a 5-byte script.
    #[test]
    fn sixty_four_byte_transaction_is_detected() {
        let tx = spend(9, 5);
        assert_eq!(tx.to_wire_bytes(false).len(), 64);
        assert_eq!(txid_preimage_len(&tx), 64);
        assert!(check_tx_not_64_bytes(&tx).is_err());
        assert!(check_tx_not_64_bytes(&spend(9, 4)).is_ok());
        assert!(check_tx_not_64_bytes(&spend(9, 6)).is_ok());
        assert!(check_tx_not_64_bytes(&spend(9, 20)).is_ok());
    }

    #[test]
    fn coinbase_commitment_layout_is_byte_exact() {
        let parents = [[0xAA; 32], [0xBB; 32]];
        let wr = MerkleRoot([0xCC; 32]);
        let c = coinbase_commitment(0x0102_0304_0506_0708, &parents, &wr);
        assert_eq!(&c[0..8], b"GNB-CB01");
        assert_eq!(&c[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
        let mut pre = vec![2, 0, 0, 0];
        pre.extend_from_slice(&[0xAA; 32]);
        pre.extend_from_slice(&[0xBB; 32]);
        assert_eq!(&c[16..48], &tagged_hash(b"GnB/coinbase/parents", &[&pre]));
        assert_eq!(&c[48..80], &[0xCC; 32]);
        // Parent order matters (header order is committed).
        assert_ne!(parents_commitment(&[[0xAA; 32], [0xBB; 32]]), parents_commitment(&[[0xBB; 32], [0xAA; 32]]));
    }

    #[test]
    fn commitment_check_accepts_and_rejects_byte_exactly() {
        let b = hardened_block(5, 0, vec![spend(1, 20), spend(2, 20)]);
        assert_eq!(check_block_hardened_at(&b, 0), Ok(()));

        // Wrong height encoding (height + 1, and a big-endian encoding).
        let mut bad = b.clone();
        bad.transactions[0].inputs[0].script_sig[8..16].copy_from_slice(&6u64.to_le_bytes());
        assert!(check_coinbase_commitment(&bad).unwrap_err().starts_with("bad-cb-height"));
        let mut bad = b.clone();
        bad.transactions[0].inputs[0].script_sig[8..16].copy_from_slice(&5u64.to_be_bytes());
        assert!(check_coinbase_commitment(&bad).unwrap_err().starts_with("bad-cb-height"));
        // Wrong tag, truncated, wrong parents.
        let mut bad = b.clone();
        bad.transactions[0].inputs[0].script_sig[7] ^= 1;
        assert_eq!(check_coinbase_commitment(&bad), Err("bad coinbase commitment tag"));
        let mut bad = b.clone();
        bad.transactions[0].inputs[0].script_sig.truncate(79);
        assert!(check_coinbase_commitment(&bad).is_err());
        let mut bad = b.clone();
        bad.header.parents.reverse();
        assert_eq!(check_coinbase_commitment(&bad), Err("bad coinbase parents commitment"));

        // CRY-1: swapping/padding a witness keeps every txid (so the header
        // root) but changes the witness root.
        let mut swapped = b.clone();
        swapped.transactions[1].inputs[0].script_sig.extend_from_slice(&[0u8; 100]);
        assert_eq!(swapped.transactions[1].txid(), b.transactions[1].txid());
        assert!(swapped.validate_merkle_at(0), "the header root does not see witnesses");
        assert_eq!(check_block_hardened_at(&swapped, 0), Err("bad witness commitment (witness root mismatch)"));
    }

    #[test]
    fn checks_are_noops_below_activation() {
        let mut b = hardened_block(5, 0, vec![spend(1, 5)]);
        b.transactions[0].inputs[0].script_sig = b"legacy".to_vec();
        b.header.merkle_root = b.body_merkle_root_at(activation::NEVER);
        assert_eq!(check_block_hardened_at(&b, activation::NEVER), Ok(()));
        assert_eq!(check_block_hardened_at(&b, 6), Ok(()), "height 5 < activation 6");
        assert!(check_block_hardened_at(&b, 5).is_err(), "height 5 >= activation 5");
    }

    #[test]
    fn process_wide_predicate_follows_the_override() {
        let _g = activation::scoped_override(5);
        assert!(!rules_active(0));
        assert!(!rules_active(4));
        assert!(rules_active(5));
        let _g0 = activation::scoped_override(0);
        assert!(!rules_active(0), "never the genesis");
        assert!(rules_active(1));
    }

    /// Position 0 of the witness tree is the fixed coinbase placeholder
    /// whatever the coinbase holds; every other position is the wtxid.
    #[test]
    fn witness_root_layout() {
        let txs = vec![coinbase(vec![1; 90]), spend(1, 20), spend(2, 21)];
        let want = tagged_merkle_root(&[COINBASE_WTXID, txs[1].wtxid(), txs[2].wtxid()]);
        assert_eq!(witness_root(&txs), want);
        let mut other_cb = txs.clone();
        other_cb[0] = coinbase(vec![2; 7]);
        assert_eq!(witness_root(&other_cb), want);
        assert_ne!(txs[1].wtxid(), txs[1].txid(), "a witness id covers the script_sig");
    }

    #[test]
    fn commitment_check_boundaries() {
        // Exactly the 80-byte commitment, no extra miner bytes: valid.
        let mut b = hardened_block(5, 0, vec![spend(1, 20)]);
        let c = expected_coinbase_commitment(&b);
        b.transactions[0].inputs[0].script_sig = c.to_vec();
        assert_eq!(check_coinbase_commitment(&b), Ok(()));
        let mut short = b.clone();
        short.transactions[0].inputs[0].script_sig.pop();
        assert_eq!(check_coinbase_commitment(&short),
            Err("coinbase commitment missing (script_sig shorter than 80 bytes)"));
        // No coinbase input, or no transaction at all.
        let mut no_input = b.clone();
        no_input.transactions[0].inputs.clear();
        assert_eq!(check_coinbase_commitment(&no_input), Err("invalid coinbase format"));
        let mut empty = b.clone();
        empty.transactions.clear();
        assert_eq!(check_coinbase_commitment(&empty), Err("invalid coinbase format"));
    }

    /// `check_block_hardened_at` reports each rule it runs.
    #[test]
    fn hardened_check_reports_each_rule() {
        let b = hardened_block(5, 0, vec![spend(1, 20)]);
        assert_eq!(check_block_hardened_at(&b, 0), Ok(()));
        let mut bad_root = b.clone();
        bad_root.header.merkle_root.0[0] ^= 1;
        assert_eq!(check_block_hardened_at(&bad_root, 0), Err("invalid merkle root"));
        // The legacy root is not the hardened root.
        let mut legacy_root = b.clone();
        legacy_root.header.merkle_root = legacy_root.body_merkle_root_at(activation::NEVER);
        assert_eq!(check_block_hardened_at(&legacy_root, 0), Err("invalid merkle root"));
        // A non-coinbase first transaction (with a matching root).
        let mut no_cb = b.clone();
        no_cb.transactions.remove(0);
        no_cb.header.merkle_root = no_cb.body_merkle_root_at(0);
        assert_eq!(check_block_hardened_at(&no_cb, 0), Err("invalid coinbase format"));
        // A 64-byte transaction inside an otherwise valid block.
        let b64 = hardened_block(5, 0, vec![spend(1, 20), spend(9, 5)]);
        assert_eq!(check_block_hardened_at(&b64, 0), Err("64-byte transaction (txid preimage of exactly 64 bytes)"));
        assert_eq!(check_hardened_body(&b64), Err("64-byte transaction (txid preimage of exactly 64 bytes)"));
        assert_eq!(check_hardened_body(&b), Ok(()));
    }

    /// B2-T10: a repeated parent anywhere in the list is refused from the
    /// activation (and by `check_hardened_body` first, before the 64-byte
    /// and commitment rules); below it the check does not run.
    #[test]
    fn repeated_parent_is_refused_from_the_activation() {
        assert_eq!(check_parents_distinct(&[]), Ok(()));
        assert_eq!(check_parents_distinct(&[id(1)]), Ok(()));
        assert_eq!(check_parents_distinct(&[id(2), id(1), id(3)]), Ok(()));
        assert_eq!(check_parents_distinct(&[id(1), id(1)]), Err("duplicate parent"));
        assert_eq!(check_parents_distinct(&[id(3), id(1), id(2), id(1)]), Err("duplicate parent"));
        let mut differ_last = id(1);
        differ_last[31] = 2;
        assert_eq!(check_parents_distinct(&[id(1), differ_last]), Ok(()));
        let mut b = hardened_block(5, 0, vec![spend(1, 20)]);
        b.header.parents = vec![[0x11; 32], [0x22; 32], [0x11; 32]];
        let c = expected_coinbase_commitment(&b);
        b.transactions[0].inputs[0].script_sig = coinbase_script_sig(&c, b"extranonce");
        b.header.merkle_root = b.body_merkle_root_at(0);
        assert_eq!(check_coinbase_commitment(&b), Ok(()), "the commitment covers the list as written");
        assert_eq!(check_block_hardened_at(&b, 0), Err("duplicate parent"));
        assert_eq!(check_block_hardened_at(&b, 5), Err("duplicate parent"), "height 5 >= activation 5");
        assert_eq!(check_hardened_body(&b), Err("duplicate parent"));
        assert_eq!(b.validate_structure_without_pow_at(0), Err("duplicate parent"));
        // Below the activation (legacy root) the list is not checked.
        b.header.merkle_root = b.body_merkle_root_at(6);
        assert_eq!(check_block_hardened_at(&b, 6), Ok(()));
        assert_eq!(b.validate_structure_without_pow_at(6), Ok(()));
    }

    #[test]
    fn pow_limit_switches_at_the_boundary() {
        let mainnet = activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
        assert_eq!(pow_limit_bits_at(mainnet - 1, mainnet), POW_LIMIT_BITS);
        assert_eq!(pow_limit_bits_at(mainnet, mainnet), GENESIS_BITS);
        assert_eq!(pow_limit_bits_at(1, activation::NEVER), POW_LIMIT_BITS);
        assert_eq!(pow_limit_bits_at(1, 0), GENESIS_BITS);
    }
}
