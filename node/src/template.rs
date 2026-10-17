//! Block-template construction shared by the internal miner and the
//! `getblocktemplate` RPC (audit MEM-2, DAG-2, MEM-1/MEM-3 template side).
//!
//! * Parents: at most `core::MAX_PARENTS` bodied, non-disqualified tips
//!   whose body passes the hardening block rules of its height (verdict
//!   memoized per block hash, [`eligible_parent`]),
//!   highest blue work first (`GhostDAG::template_parents`,
//!   [`template_parents_and_height`]) — the stock code
//!   used EVERY tip, so more than 256 tips made every template invalid
//!   (`too many parents`) with nobody able to merge them (DAG-2).
//! * Transactions: whole ANCESTOR PACKAGES by package fee rate, parents
//!   before children (child-pays-for-parent, audit MEM-6 —
//!   `mempool::select_packages`; without in-pool chains this is highest fee
//!   rate first), under a BYTE budget measured exactly as the consensus rule
//!   measures AT THE TEMPLATE'S HEIGHT (on this chain the wire encoding at
//!   every height: `block_rules::legacy_block_size` below the hardening
//!   activation, `Block::wire_size` at/after it, audit VAL-12, neither
//!   reading the uncommitted `blue_score`, re-audit B1-T0 — package sizes
//!   and fee rates use the same measure, the PoWit section and the
//!   witness-share coinbase outputs are budgeted on top): the budget is
//!   `MAX_BLOCK_SIZE` minus an upper bound of the
//!   header and block framing (every varint at its maximum width) minus a
//!   coinbase reserve. A count-only cap let ~116 ordinary transactions push
//!   every template past `MAX_BLOCK_SIZE` (MEM-2).
//! * Hardening rules (docs/CONSENSUS.md, "Block rules at the hardening
//!   activation"): a template at/after the activation height gets the
//!   tagged Merkle root and a coinbase whose `script_sig` starts with the
//!   80-byte commitment (height, parents, witness root) —
//!   [`assemble_block`] writes it — and never contains a 64-byte
//!   transaction or a spend of its own coinbase (inputs must be in the UTXO
//!   set or outputs of pooled transactions placed earlier in the template).
//!   A template below the height is built exactly as before.
//! * Self-check: every selected transaction is re-validated against the
//!   current UTXO set plus the outputs of the transactions placed before it
//!   in the template (standardness, inputs present and not already used by
//!   the template, coinbase maturity at the template height, the
//!   transaction-version rule and policy and the 64-byte rule at the template
//!   height (`admission::check_tx_for_next_block`, CRY-3 / VAL-10
//!   activation), MoneyRange, consensus minimum fee, input scripts at the
//!   template height, with the spent amounts and scripts of in-template
//!   parents as sighash-v3 prevouts — normally verified-signature cache
//!   hits). A transaction that fails is EVICTED from the mempool together
//!   with its in-pool descendants instead of making every template invalid
//!   (MEM-1, MEM-3, MEM-6) — except a transaction that fails ONLY those
//!   height rules at the template height while it passes them at the pool's
//!   own next height (`Mempool::next_height`), which is skipped, never
//!   evicted (its in-pool descendants are not selected either). A package
//!   is included all-or-nothing. The fees the coinbase may claim are
//!   recomputed from those inputs, never taken from the pool.
//! * Height: [`template_parents_and_height`] — the ONE "next block height"
//!   of the node. Mempool admission, post-connect eviction, re-injection and
//!   wallets (`getdaginfo.next_block_height`) use the same value
//!   ([`next_template_height`], cached in `Mempool::next_height`), so they
//!   can never sit on opposite sides of the hardening activation (the header
//!   height of a block that merges a tip with a greater DAG height than its
//!   selected parent exceeds the selected tip's DAG height + 1, DAG-8).
//!
//! The template is built under the store's acceptance lock, so the DAG and
//! UTXO snapshot it reads are consistent with each other.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::consensus::{BlockHash, GhostDAG};
use crate::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use crate::mempool::{self, admission, Mempool};
use crate::storage::Storage;

/// `(txid, output index)`.
type Outpoint = ([u8; 32], u32);

/// Bytes reserved for a coinbase the template builder does not construct
/// itself (`getblocktemplate` consumers build their own coinbase). Far above
/// the node's own coinbase (~80 bytes). The WHOLE external coinbase, measured
/// with the template's size rule, must fit in it: a template filled to its
/// budget leaves no other room ([`external_coinbase_max_extra`]).
pub const EXTERNAL_COINBASE_RESERVE: usize = 1_000;

/// Largest `script_pubkey` (in bytes) of the single coinbase output that
/// [`external_coinbase_max_extra`] budgets for (`getblocktemplate` reports it
/// as `max_coinbase_script_pubkey_bytes`). Covers this chain's 20-byte pubkey
/// hash and any 32-byte script hash with room to spare.
pub const EXTERNAL_COINBASE_MAX_SPK: usize = 64;

/// Size of the WIDEST coinbase with one input carrying a `script_sig_len`-byte
/// `script_sig` and one output carrying a `spk_len`-byte `script_pubkey`, in
/// the measure of the size rule (wire encoding when `hardened`, bincode
/// otherwise): every other field at its widest encoding (version, locktime,
/// sequence and value at their maxima). Non-decreasing in both lengths.
fn widest_coinbase_size(script_sig_len: usize, spk_len: usize, hardened: bool) -> usize {
    let cb = Transaction {
        version: u32::MAX,
        inputs: vec![TxInput {
            prev_txid: [0xFF; 32],
            prev_index: u32::MAX,
            script_sig: vec![0xFF; script_sig_len],
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: u64::MAX, script_pubkey: vec![0xFF; spk_len] }],
        locktime: u32::MAX,
    };
    // This chain's size rule is the wire encoding at every height.
    let _ = hardened;
    cb.wire_size(true)
}

/// The number of miner bytes an external coinbase may append after its
/// `prefix_len` commitment bytes (`getblocktemplate`'s
/// `max_coinbase_extra_bytes`): the largest `extra` such that a coinbase with
/// one input (`script_sig` of `prefix_len + extra` bytes) and one output
/// (`script_pubkey` of at most [`EXTERNAL_COINBASE_MAX_SPK`] bytes) fits in
/// `reserve` bytes under the size rule of the template's height (`hardened`:
/// wire, otherwise bincode), capped by the consensus `script_sig` limit.
///
/// Why the reserve and not the `script_sig` cap: the template selects
/// transactions up to `MAX_BLOCK_SIZE - framing_upper_bound - reserve`, so on
/// a full mempool only `reserve` bytes (plus the framing slack) remain for the
/// coinbase. Advertising the consensus cap (9,920 extra bytes) let an external
/// miner build a block over `MAX_BLOCK_SIZE` after spending the proof of work.
pub fn external_coinbase_max_extra(prefix_len: usize, hardened: bool, reserve: usize) -> usize {
    let fits = |extra: usize| {
        widest_coinbase_size(prefix_len + extra, EXTERNAL_COINBASE_MAX_SPK, hardened) <= reserve
    };
    let cap = core::limits::MAX_SCRIPT_SIG_SIZE.saturating_sub(prefix_len);
    if !fits(0) {
        return 0;
    }
    // `fits` is monotone: binary search for the largest fitting value.
    let (mut lo, mut hi) = (0usize, cap);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if fits(mid) { lo = mid } else { hi = mid - 1 }
    }
    lo
}

/// A block template: everything needed to assemble a candidate block.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// Parents, the selected parent first.
    pub parents: Vec<BlockHash>,
    /// Header height: max parent DAG height + 1 (the `accept_block` rule).
    pub height: u64,
    /// Informational blue score (max parent blue score + 1).
    pub blue_score: u64,
    /// Expected ASERT bits for these parents.
    pub bits: u32,
    /// Latest parent timestamp (the minimum block timestamp).
    pub parent_timestamp: u64,
    /// Non-coinbase transactions in block order, with their recomputed fees.
    pub transactions: Vec<(Transaction, u64)>,
    /// Sum of the fees of `transactions`.
    pub total_fees: u64,
    /// Block subsidy at `height`.
    pub subsidy: u64,
    /// Transactions evicted from the mempool by the self-check.
    pub evicted: usize,
    /// The byte budget the transactions were selected under.
    pub tx_byte_budget: usize,
    /// The hardening activation height the template was built under.
    pub activation_height: u64,
    /// Whether the hardening block rules apply at `height`.
    pub hardened: bool,
    /// PoWit section (from `core::powit_height()`): witness shares,
    /// attestations and equivocation proofs, valid in this template's
    /// context (`powit::template_body`).
    pub powit: core::powit::PowitBody,
}

impl BlockTemplate {
    /// The coinbase outputs of a block built from this template paying the
    /// miner at `script_pubkey`: the miner output (subsidy share + fees)
    /// followed by one output per PoWit witness share
    /// (`core::Block::coinbase_outputs`).
    pub fn coinbase_outputs(&self, script_pubkey: Vec<u8>) -> Vec<TxOutput> {
        Block::coinbase_outputs(self.height, script_pubkey, self.total_fees, &self.powit.shares)
    }

    /// The node's own coinbase for this template ([`miner_coinbase`] with
    /// [`Self::coinbase_outputs`]).
    pub fn miner_coinbase(&self, script_pubkey: Vec<u8>) -> Transaction {
        let mut cb = miner_coinbase(self.height, 0, script_pubkey.clone());
        cb.outputs = self.coinbase_outputs(script_pubkey);
        cb
    }

    /// The 80-byte coinbase commitment a block built from this template must
    /// carry at the start of its coinbase `script_sig` (`None` below the
    /// activation, where the `script_sig` is free-form).
    pub fn coinbase_commitment(&self) -> Option<[u8; core::block_rules::COINBASE_COMMITMENT_LEN]> {
        if !self.hardened {
            return None;
        }
        // The witness root ignores position 0 (the coinbase).
        let placeholder = Transaction { version: 0, inputs: vec![], outputs: vec![], locktime: 0 };
        let txs: Vec<Transaction> = std::iter::once(placeholder)
            .chain(self.transactions.iter().map(|(t, _)| t.clone()))
            .collect();
        Some(core::block_rules::coinbase_commitment(
            self.height, &self.parents, &core::block_rules::witness_root(&txs)))
    }

    /// The sibling hashes from the coinbase leaf to the header Merkle root,
    /// under the rule of the template's height.
    pub fn coinbase_merkle_branch(&self) -> Vec<[u8; 32]> {
        let ids: Vec<[u8; 32]> = std::iter::once([0u8; 32])
            .chain(self.transactions.iter().map(|(t, _)| t.txid()))
            .collect();
        core::block_rules::coinbase_merkle_branch(&ids, self.hardened)
    }

    /// In-template dependencies (BIP22 `depends`): for each listed
    /// transaction, in template order, the 1-based positions in
    /// [`Self::transactions`] of the EARLIER listed transactions whose
    /// outputs it spends (its direct in-template parents, ascending). Since
    /// ancestor-package selection (MEM-6) a template can carry a chain whose
    /// child's input exists only as its in-template parent's output, so a
    /// block built from a SUBSET of the listed transactions is valid only if
    /// the subset is closed under these dependencies (transitively) and keeps
    /// the listed order: dropping a parent but keeping its child makes the
    /// block invalid (input not found). Below the hardening activation no
    /// coinbase commitment fixes the list, so an external miner may drop
    /// transactions; at/after it `coinbase_commitment` covers exactly the
    /// listed transactions in this order.
    pub fn depends(&self) -> Vec<Vec<usize>> {
        let mut position: HashMap<[u8; 32], usize> = HashMap::with_capacity(self.transactions.len());
        let mut out = Vec::with_capacity(self.transactions.len());
        for (i, (tx, _)) in self.transactions.iter().enumerate() {
            let mut deps: Vec<usize> = tx.inputs.iter()
                .filter_map(|inp| position.get(&inp.prev_txid).copied())
                .collect();
            deps.sort_unstable();
            deps.dedup();
            out.push(deps);
            position.insert(tx.txid(), i + 1);
        }
        out
    }
}

/// Upper bound of the size of a block with these parents and NO
/// transactions, in the measure of the regime (wire when `hardened`,
/// bincode otherwise): every variable-width integer at its widest encoding.
fn framing_upper_bound(parents: &[BlockHash], hardened: bool) -> usize {
    if hardened {
        // header (fixed fields + parents varint + parents) + tx-count varint
        // (at most 9) + shielded-count varint (1: templates carry none).
        return 4 + 9 + 32 * parents.len() + 32 + 8 + 4 + 8 + 8 + 8 + 9 + 1;
    }
    let empty = Block {
        header: BlockHeader {
            version: u32::MAX,
            parents: parents.to_vec(),
            merkle_root: MerkleRoot::ZERO,
            timestamp: u64::MAX,
            bits: u32::MAX,
            nonce: u64::MAX,
        },
        transactions: Vec::new(),
        blue_score: u64::MAX,
        height: u64::MAX,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    };
    // The rule's own measure (`legacy_block_size`, the wire length, with
    // the PoWit section of a height at/after `powit_height()`; blue_score
    // fixed-width, re-audit B1-T0). + 9: the transaction-count varint grows
    // from 1 byte (empty) to at most 9.
    core::block_rules::legacy_block_size(&empty).saturating_add(9)
}

/// The node's own coinbase for `height` paying `value` to `script_pubkey`.
/// Height plus a random tag: two blocks at the same height (common in a DAG)
/// must never share a coinbase txid. At/after the hardening activation
/// [`assemble_block`] prefixes this `script_sig` with the 80-byte commitment
/// (the tag stays as the miner's extra bytes).
pub fn miner_coinbase(height: u64, value: u64, script_pubkey: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("gnb:h{}:{:016x}", height, rand::random::<u64>()).into_bytes(),
            sequence:   u32::MAX,
        }],
        outputs: vec![TxOutput { value, script_pubkey }],
        locktime: 0,
    }
}

/// Bytes the miner reserves for its own coinbase: the widest coinbase it can
/// build (maximal value and tag, plus the 80-byte hardening commitment) in
/// the larger of the two size measures, so the reserve holds on both sides of
/// the activation.
pub fn miner_coinbase_reserve(script_pubkey: &[u8]) -> usize {
    let mut cb = miner_coinbase(u64::MAX, u64::MAX, script_pubkey.to_vec());
    let mut ss = vec![0xFF; core::block_rules::COINBASE_COMMITMENT_LEN];
    ss.extend_from_slice(&cb.inputs[0].script_sig);
    cb.inputs[0].script_sig = ss;
    cb.actual_size().max(cb.wire_size(true))
}

/// The parents a template on the current DAG would use (at most
/// `core::MAX_PARENTS` eligible, non-disqualified tips,
/// `GhostDAG::template_parents`) and the template's header height: the
/// largest parent DAG height + 1 (the `accept_block` rule). With no eligible
/// tip, no parents and the selected tip's DAG height + 1
/// (`admission::next_block_height`). Under the process-wide hardening
/// activation height (see [`template_parents_and_height_at`]).
pub fn template_parents_and_height(d: &GhostDAG, store: &Storage) -> (Vec<BlockHash>, u64) {
    template_parents_and_height_at(d, store, core::activation::hardening_activation_height())
}

/// [`template_parents_and_height`] for an explicit activation height. A tip
/// is an eligible parent iff its body is stored and (defense in depth behind
/// the start-up recheck, `accept::recheck_stored_blocks_under_hardening`) that
/// body passes the hardening block rules of its own height
/// (`core::block_rules::check_block_hardened_at`, a no-op below the
/// activation): a block a pre-upgrade binary stored can never be accepted by
/// an upgraded peer, and neither can a block that references it. The SAME
/// predicate decides the template's parents and the node's next height
/// ([`next_template_height`]), so the mempool and the template never
/// disagree about which tips count ([`eligible_parent`]).
pub fn template_parents_and_height_at(d: &GhostDAG, store: &Storage, activation_height: u64) -> (Vec<BlockHash>, u64) {
    let parents = d.template_parents(core::MAX_PARENTS, |h| eligible_parent(store, h, activation_height));
    if parents.is_empty() {
        return (parents, admission::next_block_height(d));
    }
    let height = parents.iter()
        .filter_map(|t| d.get_block_data(t))
        .map(|x| x.height)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    (parents, height)
}

/// The template's parent predicate: a body is stored for `h` and it passes
/// `core::block_rules::check_block_hardened_at(body, activation_height)`.
///
/// It runs on every valid tip (and, with no eligible tip, along the
/// selected chain) at every block acceptance, through
/// [`next_template_height`]. The verdict on a stored body is a pure function
/// of the body and the activation height, so it is memoized per block hash
/// (`Storage::body_verdict`; a body write or delete drops the hash's entry):
/// each body is decoded and hashed (wire size, tagged Merkle root, witness
/// root) once, not once per acceptance, and a failing body is logged once,
/// when its verdict is computed.
pub fn eligible_parent(store: &Storage, h: &BlockHash, activation_height: u64) -> bool {
    let verdict = store.body_verdict(h, activation_height, |b| {
        match core::block_rules::check_block_hardened_at(b, activation_height) {
            Ok(()) => true,
            Err(e) => {
                log::error!("template: parent candidate {} fails the hardening block rules ({}); skipped",
                    hex::encode(&h[..8]), e);
                false
            }
        }
    });
    matches!(verdict, Ok(Some(true)))
}

/// Header height of the node's next template (see
/// [`template_parents_and_height`]): the height the mempool, the template
/// self-check and the wallets evaluate the height-dependent transaction rules
/// (version / sighash, the 64-byte rule, coinbase maturity) at. Never smaller
/// than 1.
pub fn next_template_height(d: &GhostDAG, store: &Storage) -> u64 {
    template_parents_and_height(d, store).1.max(1)
}

/// `Some((applied, best))` when the block the UTXO set sits on (the persisted
/// tip pointer `tip_hash`) is not the DAG's selected tip: a chain move that
/// commits in chunks (audit B2-T0, `accept::resolve_best_chain`) stopped after
/// committed chunks (a storage failure; Bitcoin Core aborts the node on such
/// a failure) and resumes with the next acceptance or at the next start. In
/// between, a template would take its parents and height from the DAG tip but
/// check its transactions against the UTXO set of an intermediate block (a
/// transaction the best chain already confirmed or conflicts with would pass),
/// so [`build_block_template_with`] refuses to build one. `None` when they
/// agree, or without a tip pointer (fixtures).
pub fn chain_move_incomplete(d: &GhostDAG, store: &Storage) -> Option<(BlockHash, BlockHash)> {
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .filter(|t| d.has_block(t))?;
    let best = d.selected_tip()?;
    (best != applied).then_some((applied, best))
}

/// Build a template on the current DAG / UTXO / mempool state.
///
/// `coinbase_reserve` is the number of bytes kept free for the coinbase
/// (`EXTERNAL_COINBASE_RESERVE` for `getblocktemplate`; the miner passes the
/// size of its own coinbase with a maximal value).
pub fn build_block_template(
    dag: &Arc<RwLock<GhostDAG>>,
    store: &Storage,
    mempool: &Mempool,
    coinbase_reserve: usize,
) -> Result<BlockTemplate, String> {
    build_block_template_with(dag, store, mempool, &TemplateOptions { coinbase_reserve, verify_scripts: true })
}

/// Template-building knobs.
#[derive(Clone, Copy, Debug)]
pub struct TemplateOptions {
    /// Bytes kept free for the coinbase.
    pub coinbase_reserve: usize,
    /// Verify each selected transaction's input scripts (signatures). On by
    /// default; normally served from the verified-signature cache. Tests with
    /// synthetic unsigned transactions turn it off.
    pub verify_scripts: bool,
}

/// [`build_block_template`] with explicit options.
pub fn build_block_template_with(
    dag: &Arc<RwLock<GhostDAG>>,
    store: &Storage,
    mempool: &Mempool,
    options: &TemplateOptions,
) -> Result<BlockTemplate, String> {
    let coinbase_reserve = options.coinbase_reserve;
    let _guard = store.acceptance_lock();
    // Audit F1: a stopped node (`accept`'s no-verdict guard) builds nothing.
    if let Some(m) = store.abort_reason() {
        return Err(format!("node stopped: {m}"));
    }
    let activation_height = core::activation::hardening_activation_height();

    let (parents, height, blue_score, parent_ts) = {
        let d = dag.read();
        if let Some((applied, best)) = chain_move_incomplete(&d, store) {
            return Err(format!(
                "chain move in progress: the UTXO set is at {} but the best chain's tip is {}; no \
                 template until the move completes (next block or restart)",
                hex::encode(&applied[..8]), hex::encode(&best[..8])));
        }
        let (parents, height) = template_parents_and_height_at(&d, store, activation_height);
        if parents.is_empty() {
            return Err("node has no bodied tip yet (still syncing genesis?)".into());
        }
        let blue_score = parents.iter()
            .filter_map(|t| d.get_block_data(t))
            .map(|x| x.blue_score)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let parent_ts = core::difficulty_parent_timestamp(
            parents.iter().filter_map(|t| d.get_block_data(t)).map(|x| x.timestamp));
        (parents, height, blue_score, parent_ts)
    };
    let bits = crate::pow::expected_bits(parent_ts, height)
        .map_err(|e| format!("expected bits not derivable: {}", e))?;
    // The rules of the template's height (header height, as accept_block
    // will judge the block).
    let hardened = core::block_rules::rules_active_at(height, activation_height);

    // PoWit section (from powit_height), valid in this template's context.
    let powit_body = {
        let d = dag.read();
        crate::powit::template_body(crate::powit::pool(), &d, store, parents[0], height)
    };
    let powit_bytes = {
        let mut v = Vec::new();
        powit_body.write_wire(&mut v);
        v.len()
    };
    // One coinbase output per witness share: value (8) + script length
    // varint (1) + the share's payout script.
    let share_outputs: usize = powit_body.shares.iter().map(|s| 9 + s.payout.len()).sum();

    let budget = core::MAX_BLOCK_SIZE
        .saturating_sub(framing_upper_bound(&parents, hardened))
        .saturating_sub(coinbase_reserve)
        .saturating_sub(powit_bytes)
        .saturating_sub(share_outputs);

    // Ancestor packages by package fee rate (CPFP), byte budget, self-check
    // of every package member in block order, eviction.
    let mut spent_by_template: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut created_by_template: HashMap<([u8; 32], u32), TxOutput> = HashMap::new();
    let mut selected: Vec<(Transaction, u64)> = Vec::new();
    let mut total_fees: u64 = 0;
    let mut evict: HashSet<[u8; 32]> = HashSet::new();
    // The pool's own next height. Equal to `height` whenever the cache is
    // current (both come from `template_parents_and_height` on the same DAG
    // under the acceptance lock); 0 (unknown) means "the template height".
    let pool_height = match mempool.next_height() {
        0 => height,
        h => h,
    };
    // The pool records bincode sizes; the consensus measure at/after the
    // activation is the wire encoding (VAL-12): package sizes, package fee
    // rates and the budget all use the measure of the template's height.
    // This chain's size rule is the wire encoding at every height.
    let candidates = mempool.package_candidates_with(|tx, _pool_size| tx.wire_size(true));
    mempool::select_packages(&candidates, budget, usize::MAX, |package| {
        // Dry-run the whole package against the template state; commit only
        // if every member passes (all-or-nothing).
        let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();
        let mut local_created: HashMap<([u8; 32], u32), TxOutput> = HashMap::new();
        let mut local_fees = total_fees;
        let mut staged: Vec<(Transaction, u64)> = Vec::with_capacity(package.len());
        for txid in package {
            let Some(tx) = mempool.get_tx(txid) else { return Err(*txid) };
            let is_spent = |op: &([u8; 32], u32)| spent_by_template.contains(op) || local_spent.contains(op);
            let created = |op: &([u8; 32], u32)| {
                local_created.get(op).or_else(|| created_by_template.get(op)).cloned()
            };
            match self_check(store, &tx, height, pool_height, &is_spent, &created, options.verify_scripts) {
                Ok(fee) => {
                    local_fees = match core::limits::money_add(local_fees, fee) {
                        Ok(t) => t,
                        Err(_) => return Err(*txid),
                    };
                    for inp in &tx.inputs {
                        local_spent.insert((inp.prev_txid, inp.prev_index));
                    }
                    for (j, o) in tx.outputs.iter().enumerate() {
                        local_created.insert((*txid, j as u32), o.clone());
                    }
                    staged.push((tx, fee));
                }
                Err(TemplateReject::Evict(reason)) => {
                    log::info!("template: evicting tx {} (and its descendants) from the mempool: {}",
                        hex::encode(&txid[..8]), reason);
                    evict.insert(*txid);
                    return Err(*txid);
                }
                Err(TemplateReject::Skip) => return Err(*txid),
            }
        }
        spent_by_template.extend(local_spent);
        created_by_template.extend(local_created);
        total_fees = local_fees;
        selected.extend(staged);
        Ok(())
    });
    let evicted = evict.len();
    if evicted > 0 {
        mempool.retain_valid(|e| !evict.contains(&e.tx.txid()));
    }

    Ok(BlockTemplate {
        parents,
        height,
        blue_score,
        bits,
        parent_timestamp: parent_ts,
        transactions: selected,
        total_fees,
        subsidy: core::tokenomics::block_subsidy_sat(height),
        evicted,
        tx_byte_budget: budget,
        activation_height,
        hardened,
        powit: powit_body,
    })
}

enum TemplateReject {
    /// The transaction can never be mined on this chain: drop it from the pool.
    Evict(String),
    /// Not includable in THIS template (its input is used by an earlier
    /// template transaction, or it passes the height rules — version, 64-byte
    /// rule — at the pool's next height but not at this template's height);
    /// keep it pooled.
    Skip,
}

/// In-context check of one candidate (see the module docs): its inputs come
/// from `created` (outputs of transactions placed earlier in the template —
/// MEM-6 package parents) or the UTXO set. `pool_height` is the mempool's
/// next height (normally equal to `height`).
fn self_check(
    store: &Storage,
    tx: &Transaction,
    height: u64,
    pool_height: u64,
    spent_by_template: &dyn Fn(&Outpoint) -> bool,
    created: &dyn Fn(&Outpoint) -> Option<TxOutput>,
    verify_scripts: bool,
) -> Result<u64, TemplateReject> {
    admission::check_standard(tx).map_err(|e| TemplateReject::Evict(e.to_string()))?;
    // The rules of the TEMPLATE height that depend on that height alone
    // (`admission::check_tx_for_next_block`): the version rule and policy
    // (CRY-3: version 3 from the hardening activation, version < 3 below it)
    // and the 64-byte rule (VAL-10: pooled before the activation, unminable
    // from it); checked even when scripts are not verified. A transaction
    // that fails only because this template's height differs from the pool's
    // next height is still minable in the block the pool targets: skip it,
    // never evict it.
    if let Err(e) = admission::check_tx_for_next_block(tx, height) {
        if pool_height != height && admission::check_tx_for_next_block(tx, pool_height).is_ok() {
            return Err(TemplateReject::Skip);
        }
        return Err(TemplateReject::Evict(e));
    }
    let mut seen: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut total_in: u64 = 0;
    let mut prevouts: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        let op = (inp.prev_txid, inp.prev_index);
        if !seen.insert(op) {
            return Err(TemplateReject::Evict("duplicate input".into()));
        }
        if spent_by_template(&op) {
            return Err(TemplateReject::Skip);
        }
        let out = match created(&op) {
            Some(o) => o,
            None => match store.get_utxo(&inp.prev_txid, inp.prev_index) {
                Ok(Some(o)) => o,
                Ok(None) => return Err(TemplateReject::Evict(format!(
                    "input {}:{} is neither in the UTXO set nor created earlier in the template",
                    hex::encode(&inp.prev_txid[..8]), inp.prev_index))),
                Err(_) => return Err(TemplateReject::Skip),
            },
        };
        total_in = core::limits::money_add(total_in, out.value)
            .map_err(TemplateReject::Evict)?;
        prevouts.push(out);
    }
    // A height that cannot be read is no verdict: skip, never evict, and
    // never treat the input as "not a coinbase" (re-audit B1-T12).
    admission::coinbase_maturity_for_next_block(store, tx, height)
        .map_err(|_| TemplateReject::Skip)?
        .map_err(TemplateReject::Evict)?;
    // This chain's rules (`blockval`): finality at the template height,
    // output kinds, dust, policy timelocks. An output created earlier in the
    // template is confirmed in the template's block (0 confirmations); a
    // confirmed one counts in the connect path's measure for the template's
    // height (`admission::confirmations_for_next_block`, re-audit B1-T14).
    let confirmations = |t: &[u8; 32]| -> Result<Option<u64>, String> {
        // Every transaction has an output 0: its presence among the
        // template's outputs means `t` was placed earlier in the template.
        if created(&(*t, 0)).is_some() {
            return Ok(Some(0));
        }
        admission::confirmations_for_next_block(store, t, height).map_err(|e| e.msg)
    };
    match crate::blockval::check_tx_chain_rules_with_confirmations(tx, &prevouts, height, &confirmations) {
        Ok(()) => {}
        Err(e) if e.starts_with(crate::blockval::STORAGE_ERR) => return Err(TemplateReject::Skip),
        // A timelock or locktime that is not yet satisfied may be later.
        Err(e) if e.contains("timelock") || e.contains("non-final") => return Err(TemplateReject::Skip),
        Err(e) => return Err(TemplateReject::Evict(e)),
    }
    let total_out = core::limits::check_tx_money_range(tx).map_err(TemplateReject::Evict)?;
    if total_in < total_out {
        return Err(TemplateReject::Evict(format!("inputs {} < outputs {}", total_in, total_out)));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee).map_err(TemplateReject::Evict)?;
    if verify_scripts {
        // Normally a verified-signature cache hit: pooled transactions were
        // verified at admission, re-injected ones when their block connected.
        admission::verify_input_scripts(tx, &prevouts, height).map_err(TemplateReject::Evict)?;
    }
    Ok(fee)
}

/// Assemble the candidate block for `template` with the given coinbase, and
/// run the context-free consensus checks a mined block must pass (size,
/// parents, dust, duplicates, canonical limits, MoneyRange, coinbase value,
/// and at/after the activation the hardening rules). The returned block
/// still needs a nonce.
///
/// At/after the hardening activation the coinbase's `script_sig` is
/// rewritten to `commitment || extra`, where `extra` is the caller's
/// `script_sig` (with a leading commitment, if the caller already wrote one,
/// removed): every in-process producer that goes through this function emits
/// a valid coinbase on both sides of the boundary. The header Merkle root
/// follows the rule of the template's height.
pub fn assemble_block(template: &BlockTemplate, coinbase: Transaction, timestamp: u64) -> Result<Block, String> {
    let all: Vec<Transaction> = std::iter::once(coinbase)
        .chain(template.transactions.iter().map(|(t, _)| t.clone()))
        .collect();
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            parents: template.parents.clone(),
            merkle_root: MerkleRoot::ZERO,
            timestamp: timestamp.max(template.parent_timestamp),
            bits: template.bits,
            nonce: 0,
        },
        transactions: all,
        blue_score: template.blue_score,
        height: template.height,
        shielded_transactions: Vec::new(),
        powit: template.powit.clone(),
    };
    if template.hardened {
        let commitment = core::block_rules::expected_coinbase_commitment(&block);
        if let Some(input) = block.transactions[0].inputs.first_mut() {
            let tag = &core::block_rules::COINBASE_COMMITMENT_TAG;
            let extra = if input.script_sig.len() >= core::block_rules::COINBASE_COMMITMENT_LEN
                && input.script_sig.starts_with(tag)
            {
                input.script_sig[core::block_rules::COINBASE_COMMITMENT_LEN..].to_vec()
            } else {
                std::mem::take(&mut input.script_sig)
            };
            input.script_sig = core::block_rules::coinbase_script_sig(&commitment, &extra);
        }
    }
    block.header.merkle_root = block.body_merkle_root_at(template.activation_height);
    // From WITNESS_COMMITMENT_HEIGHT to the activation: the `|wc:` suffix
    // (refreshes the Merkle root; a no-op elsewhere).
    block.commit_witnesses();
    check_template_block_at(&block, template.total_fees, template.activation_height)?;
    Ok(block)
}

/// The template self-check on an assembled (not yet mined) block: every
/// structural rule of `validate_structure` except the proof of work, plus
/// the coinbase value, under the process-wide activation height.
pub fn check_template_block(block: &Block, total_fees: u64) -> Result<(), String> {
    check_template_block_at(block, total_fees, core::activation::hardening_activation_height())
}

/// [`check_template_block`] for an explicit activation height.
pub fn check_template_block_at(block: &Block, total_fees: u64, activation_height: u64) -> Result<(), String> {
    let hardened = core::block_rules::rules_active_at(block.height, activation_height);
    let size = core::block_rules::block_size_for_rules(block, hardened);
    if size > core::MAX_BLOCK_SIZE {
        return Err(format!(
            "block too large: {} > {} ({} encoding)",
            size, core::MAX_BLOCK_SIZE, if hardened { "wire" } else { "bincode" }
        ));
    }
    block.validate_structure_without_pow_at(activation_height).map_err(|e| e.to_string())?;
    core::limits::check_block_context_free(block)?;
    block.validate_coinbase_value(total_fees).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod external_coinbase_tests {
    use super::*;

    /// `max_coinbase_extra_bytes` is exactly the largest value whose widest
    /// coinbase fits the reserve in the template's size measure (one more
    /// byte does not), and the values pinned in docs/CONSENSUS.md ("Mining").
    #[test]
    fn external_coinbase_max_extra_is_tight_against_the_reserve() {
        // This chain measures both regimes on the wire encoding.
        for (hardened, prefix, pinned) in [(true, 80usize, 794usize), (false, 0, 874)] {
            let e = external_coinbase_max_extra(prefix, hardened, EXTERNAL_COINBASE_RESERVE);
            assert!(widest_coinbase_size(prefix + e, EXTERNAL_COINBASE_MAX_SPK, hardened) <= EXTERNAL_COINBASE_RESERVE);
            assert!(widest_coinbase_size(prefix + e + 1, EXTERNAL_COINBASE_MAX_SPK, hardened) > EXTERNAL_COINBASE_RESERVE);
            assert_eq!(e, pinned, "hardened={hardened}");
            // Any coinbase the miner may build within the two fields is no
            // larger than the widest one.
            let cb = Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX,
                    script_sig: vec![7; prefix + e], sequence: 0 }],
                outputs: vec![TxOutput { value: 50 * 100_000_000, script_pubkey: vec![1; EXTERNAL_COINBASE_MAX_SPK] }],
                locktime: 0,
            };
            let size = cb.wire_size(true);
            assert!(size <= EXTERNAL_COINBASE_RESERVE, "{size}");
        }
        // Capped by the consensus script_sig limit when the reserve allows more.
        assert_eq!(external_coinbase_max_extra(80, true, 1_000_000), core::limits::MAX_SCRIPT_SIG_SIZE - 80);
        assert_eq!(external_coinbase_max_extra(0, false, 1_000_000), core::limits::MAX_SCRIPT_SIG_SIZE);
        // A reserve too small for any coinbase.
        assert_eq!(external_coinbase_max_extra(80, true, 100), 0);
    }
}
