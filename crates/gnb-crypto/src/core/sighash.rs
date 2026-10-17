//! Transaction signature digests and input-script rules (audit CRY-1, CRY-2,
//! CRY-3, MEM-5, WAL-1).
//!
//! Two digests exist. The hardening activation (`core::activation`) and the
//! transaction's own `version` field select one ([`check_tx_version`]); the
//! height compared is the header height of the block containing the
//! transaction (`Block::height`, validated by `accept_block`):
//!
//! | height | `tx.version` | consensus | digest | witness | component binding |
//! | --- | --- | --- | --- | --- | --- |
//! | below the activation | any (3 included) | valid | sighash v2 ([`Transaction::sighash`]) | exact framing, any signature encoding the verifier accepts | every component signs the digest verbatim |
//! | at/after the activation | 3 | valid | sighash v3 ([`SighashV3Precomputed`]) | canonical ([`canonical_witness`]) | each component signs `crypto::bound_component_message` |
//! | at/after the activation | anything else | invalid | — | — | — |
//!
//! Below the activation every transaction, whatever its version, is verified
//! exactly as before the upgrade (nodes that predate it accept a version-3
//! transaction signed over the v2 digest; refusing it would split the network
//! before the flag day). Relay policy ([`check_tx_version_standard`], mempool
//! admission and templates) refuses version ≥ 3 below the activation, so
//! upgraded nodes never relay or mine one there; signers emit version 1 below
//! the activation and version 3 from it ([`tx_version_for_height`]). Mempool
//! and wallets evaluate these rules at the height of the next block.
//!
//! # Sighash v3 (byte-exact; normative text in `docs/CONSENSUS.md`)
//!
//! ```text
//! list_hash(tag, items) = SHA3-256( u8 len(tag) ‖ tag ‖ u32 LE count ‖ items )
//!
//! hash_prevouts   = list_hash("GNB-SIGHASH-v3/prevouts",  for each input:  prev_txid(32) ‖ prev_index u32 LE)
//! hash_sequences  = list_hash("GNB-SIGHASH-v3/sequences", for each input:  sequence u32 LE)
//! hash_amounts    = list_hash("GNB-SIGHASH-v3/amounts",   for each input:  spent value u64 LE)
//! hash_scripts    = list_hash("GNB-SIGHASH-v3/scripts",   for each input:  u32 LE len ‖ spent script_pubkey)
//! hash_outputs    = list_hash("GNB-SIGHASH-v3/outputs",   for each output: value u64 LE ‖ u32 LE len ‖ script_pubkey)
//!
//! preimage (195 bytes) =
//!     "GNB-SIGHASH-v3\0\0" (16) ‖ 0x03 (1) ‖ chain_id u32 LE (4)
//!   ‖ tx.version u32 LE (4) ‖ tx.locktime u32 LE (4)
//!   ‖ hash_prevouts ‖ hash_sequences ‖ hash_amounts ‖ hash_scripts ‖ hash_outputs (5 × 32)
//!   ‖ input_index u32 LE (4) ‖ suite_id u16 LE (2)
//! sighash_v3 = SHA3-256(preimage)
//! ```
//!
//! `count` is the number of inputs (outputs for `hash_outputs`). The five
//! list hashes are computed once per transaction, so signing or verifying
//! every input costs O(transaction size) in total (BIP143/BIP341-style
//! precomputation; closes the MEM-5 quadratic residual). `input_index` must
//! be below the input count: an out-of-range index is an error
//! ([`SighashError::InputIndexOutOfRange`]), never a different digest.
//! `suite_id` is the suite of the signature (its envelope).
//!
//! Reference implementation and golden vectors: `reference/gnb_sighash.py`,
//! `reference/sighash_vectors.json` (pinned by `tests/sighash_vectors.rs`).

use sha3::{Digest, Sha3_256};

use super::{activation, policy, ChainId, Transaction, TxOutput};
use crate::crypto;

/// The only non-coinbase transaction version valid at/after the activation
/// height, where it selects sighash v3.
pub const TX_VERSION_V3: u32 = 3;
/// Version signers give non-coinbase transactions below the activation
/// height (the historical wallet output; below the activation every version
/// is verified with sighash v2).
pub const TX_VERSION_LEGACY: u32 = 1;

/// First 16 bytes of every sighash v3 preimage.
pub const SIGHASH_V3_DOMAIN: [u8; 16] = *b"GNB-SIGHASH-v3\0\0";
/// Sighash version byte of a v3 preimage.
pub const SIGHASH_V3_VERSION: u8 = 0x03;
/// Length of a sighash v3 preimage: 16 + 1 + 4 + 4 + 4 + 5 × 32 + 4 + 2.
pub const SIGHASH_V3_PREIMAGE_LEN: usize = 195;

/// List-hash tags of sighash v3 (each hashed with a one-byte length prefix).
pub const TAG_PREVOUTS: &[u8] = b"GNB-SIGHASH-v3/prevouts";
pub const TAG_SEQUENCES: &[u8] = b"GNB-SIGHASH-v3/sequences";
pub const TAG_AMOUNTS: &[u8] = b"GNB-SIGHASH-v3/amounts";
pub const TAG_SCRIPTS: &[u8] = b"GNB-SIGHASH-v3/scripts";
pub const TAG_OUTPUTS: &[u8] = b"GNB-SIGHASH-v3/outputs";

/// Which digest (and component binding) a transaction's signatures use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SighashVersion {
    /// Historical digest ([`Transaction::sighash`]); components sign it
    /// verbatim; exact witness framing, any signature encoding the verifier
    /// accepts.
    V2,
    /// [`SighashV3Precomputed::digest`]; components sign bound messages;
    /// canonical witnesses.
    V3,
}

impl SighashVersion {
    /// The digest a SIGNER uses for a transaction of `version` that targets a
    /// block at/after the activation height (3 selects v3, anything else v2).
    /// Not a validity rule: below the activation every version, 3 included,
    /// is verified with v2 ([`check_tx_version`]), and signers never emit
    /// version 3 there ([`tx_version_for_height`]).
    pub const fn for_tx_version(version: u32) -> Self {
        if version == TX_VERSION_V3 { SighashVersion::V3 } else { SighashVersion::V2 }
    }
}

/// The version a signer gives a non-coinbase transaction targeting a block
/// at `height`: 3 at/after the activation, [`TX_VERSION_LEGACY`] below it.
pub const fn tx_version_for_height(height: u64, activation_height: u64) -> u32 {
    if activation::is_active_at(height, activation_height) { TX_VERSION_V3 } else { TX_VERSION_LEGACY }
}

/// Consensus rule: the version of a NON-COINBASE transaction in a block at
/// header height `height`. Returns the digest (and witness rule) that applies.
///
/// * below the activation: every version is valid and uses sighash v2 with
///   the v2 witness rule (exact framing, any signature encoding the verifier
///   accepts) — exactly the pre-upgrade rule of this chain (version 3
///   included: nodes that predate the upgrade accept it);
/// * at/after the activation: only version 3 is valid; it uses sighash v3
///   with the canonical witness rule.
///
/// Error strings start with `bad-txns-version`. Relay policy adds
/// [`check_tx_version_standard`].
pub fn check_tx_version(version: u32, height: u64, activation_height: u64) -> Result<SighashVersion, String> {
    if !activation::is_active_at(height, activation_height) {
        return Ok(SighashVersion::V2);
    }
    if version == TX_VERSION_V3 {
        Ok(SighashVersion::V3)
    } else {
        Err(format!(
            "bad-txns-version: version {version} is invalid at height {height} \
             (only version 3 is valid at/after the hardening activation height {activation_height})"
        ))
    }
}

/// P5-S: the signature suites a transaction input may use in a block at
/// header height `height` (`crypto::SuiteRules`): the conservative suite
/// 0x0003 from the second hardening height `hardening2_activation_height`,
/// and only under sighash v3 (at/after the first activation
/// `activation_height`; on every network the second height is at or above the
/// first, so this is just the second height there). Below either height the
/// historical rules ([`crypto::SuiteRules::LEGACY`]) apply exactly. The ONE
/// mapping from heights to suite rules: the witness rule, the signature rule
/// and the policy-spend rules (`node::blockval`) all derive the rules here.
pub fn suite_rules_at(height: u64, activation_height: u64, hardening2_activation_height: u64) -> crypto::SuiteRules {
    if activation::is_active_at(height, activation_height) {
        crypto::SuiteRules::at(height, hardening2_activation_height)
    } else {
        crypto::SuiteRules::LEGACY
    }
}

/// [`suite_rules_at`] under the process-wide activation heights (the node's
/// chain; a test's `scoped_override` / `scoped_override_v2`).
pub fn suite_rules_for_height(height: u64) -> crypto::SuiteRules {
    suite_rules_at(height, activation::hardening_activation_height(), activation::hardening2_activation_height())
}

/// Relay policy (standardness) for the version of a non-coinbase transaction
/// targeting a block at `height`: the consensus rule ([`check_tx_version`])
/// plus, below the activation, version ≥ 3 is NON-STANDARD. Such a
/// transaction is consensus-valid there (sighash v2) but upgraded nodes never
/// admit, relay or mine it, so no version-3 transaction verified under the v2
/// digest ever sits in a pool that crosses the activation.
///
/// Policy error strings start with `non-standard-version`.
pub fn check_tx_version_standard(version: u32, height: u64, activation_height: u64) -> Result<SighashVersion, String> {
    let digest = check_tx_version(version, height, activation_height)?;
    if !activation::is_active_at(height, activation_height) && version >= TX_VERSION_V3 {
        return Err(format!(
            "non-standard-version: version {version} is not relayed or mined below the hardening \
             activation height {activation_height} (next block {height}); it is consensus-valid there \
             with sighash v2, and signers use version {TX_VERSION_LEGACY}"
        ));
    }
    Ok(digest)
}

/// Why a digest could not be computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SighashError {
    /// The signed input index is not below the input count.
    InputIndexOutOfRange { index: usize, inputs: usize },
    /// Sighash v3 needs exactly one spent output per input.
    SpentOutputCount { spent: usize, inputs: usize },
    /// A count or length does not fit the u32 the preimage encodes it in.
    TooLarge(&'static str),
}

impl std::fmt::Display for SighashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SighashError::InputIndexOutOfRange { index, inputs } =>
                write!(f, "sighash input index {index} out of range ({inputs} inputs)"),
            SighashError::SpentOutputCount { spent, inputs } =>
                write!(f, "sighash v3 needs one spent output per input ({spent} for {inputs} inputs)"),
            SighashError::TooLarge(what) => write!(f, "sighash: {what} does not fit in u32"),
        }
    }
}

impl std::error::Error for SighashError {}

fn u32_len(n: usize, what: &'static str) -> Result<u32, SighashError> {
    u32::try_from(n).map_err(|_| SighashError::TooLarge(what))
}

/// SHA3-256 that counts the bytes it absorbs (cost accounting for MEM-5).
struct CountingHasher {
    h: Sha3_256,
    n: usize,
}

impl CountingHasher {
    fn tagged(tag: &[u8], count: u32) -> Self {
        let mut c = CountingHasher { h: Sha3_256::new(), n: 0 };
        // Tags are short constants; their length fits a byte.
        c.put(&[tag.len() as u8]);
        c.put(tag);
        c.put(&count.to_le_bytes());
        c
    }

    fn put(&mut self, b: &[u8]) {
        self.n = self.n.saturating_add(b.len());
        self.h.update(b);
    }

    fn finish(self, total: &mut usize) -> [u8; 32] {
        *total = total.saturating_add(self.n);
        self.h.finalize().into()
    }
}

/// The per-transaction part of sighash v3, computed once and shared by every
/// input's digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SighashV3Precomputed {
    pub tx_version: u32,
    pub locktime: u32,
    pub n_inputs: usize,
    pub hash_prevouts: [u8; 32],
    pub hash_sequences: [u8; 32],
    pub hash_amounts: [u8; 32],
    pub hash_scripts: [u8; 32],
    pub hash_outputs: [u8; 32],
    /// Bytes absorbed by the five list hashes. Linear in the transaction size;
    /// every per-input digest then hashes exactly [`SIGHASH_V3_PREIMAGE_LEN`]
    /// bytes (diagnostics and the MEM-5 cost tests).
    pub hashed_bytes: usize,
}

impl SighashV3Precomputed {
    /// Precompute the list hashes of `tx` spending `spent` (one output per
    /// input, in input order: the value and `script_pubkey` each input spends).
    pub fn new(tx: &Transaction, spent: &[TxOutput]) -> Result<Self, SighashError> {
        if spent.len() != tx.inputs.len() {
            return Err(SighashError::SpentOutputCount { spent: spent.len(), inputs: tx.inputs.len() });
        }
        let n_in = u32_len(tx.inputs.len(), "input count")?;
        let n_out = u32_len(tx.outputs.len(), "output count")?;
        let mut total = 0usize;

        let mut h = CountingHasher::tagged(TAG_PREVOUTS, n_in);
        for inp in &tx.inputs {
            h.put(&inp.prev_txid);
            h.put(&inp.prev_index.to_le_bytes());
        }
        let hash_prevouts = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_SEQUENCES, n_in);
        for inp in &tx.inputs {
            h.put(&inp.sequence.to_le_bytes());
        }
        let hash_sequences = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_AMOUNTS, n_in);
        for s in spent {
            h.put(&s.value.to_le_bytes());
        }
        let hash_amounts = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_SCRIPTS, n_in);
        for s in spent {
            h.put(&u32_len(s.script_pubkey.len(), "spent script_pubkey length")?.to_le_bytes());
            h.put(&s.script_pubkey);
        }
        let hash_scripts = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_OUTPUTS, n_out);
        for o in &tx.outputs {
            h.put(&o.value.to_le_bytes());
            h.put(&u32_len(o.script_pubkey.len(), "output script_pubkey length")?.to_le_bytes());
            h.put(&o.script_pubkey);
        }
        let hash_outputs = h.finish(&mut total);

        Ok(SighashV3Precomputed {
            tx_version: tx.version,
            locktime: tx.locktime,
            n_inputs: tx.inputs.len(),
            hash_prevouts,
            hash_sequences,
            hash_amounts,
            hash_scripts,
            hash_outputs,
            hashed_bytes: total,
        })
    }

    /// The 195-byte preimage of input `input_index` signed under `suite`.
    pub fn preimage(
        &self,
        input_index: usize,
        suite: u16,
        chain_id: ChainId,
    ) -> Result<[u8; SIGHASH_V3_PREIMAGE_LEN], SighashError> {
        if input_index >= self.n_inputs {
            return Err(SighashError::InputIndexOutOfRange { index: input_index, inputs: self.n_inputs });
        }
        let index = u32_len(input_index, "input index")?;
        let mut p = [0u8; SIGHASH_V3_PREIMAGE_LEN];
        let mut at = 0usize;
        let mut put = |b: &[u8]| {
            p[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        };
        put(&SIGHASH_V3_DOMAIN);
        put(&[SIGHASH_V3_VERSION]);
        put(&chain_id.to_le_bytes());
        put(&self.tx_version.to_le_bytes());
        put(&self.locktime.to_le_bytes());
        put(&self.hash_prevouts);
        put(&self.hash_sequences);
        put(&self.hash_amounts);
        put(&self.hash_scripts);
        put(&self.hash_outputs);
        put(&index.to_le_bytes());
        put(&suite.to_le_bytes());
        debug_assert_eq!(at, SIGHASH_V3_PREIMAGE_LEN);
        Ok(p)
    }

    /// Sighash v3 of input `input_index` signed under `suite`.
    pub fn digest(&self, input_index: usize, suite: u16, chain_id: ChainId) -> Result<[u8; 32], SighashError> {
        Ok(Sha3_256::digest(self.preimage(input_index, suite, chain_id)?).into())
    }
}

impl Transaction {
    /// Sighash v3 of one input (see the module documentation). Precomputes
    /// the list hashes on every call: to sign or verify several inputs, build
    /// one [`SighashV3Precomputed`] and call its `digest`.
    pub fn sighash_v3(
        &self,
        spent: &[TxOutput],
        input_index: usize,
        suite: u16,
        chain_id: ChainId,
    ) -> Result<[u8; 32], SighashError> {
        SighashV3Precomputed::new(self, spent)?.digest(input_index, suite, chain_id)
    }

    /// [`Transaction::sighash`] (v2) with the input index range-checked.
    pub fn sighash_v2_checked(&self, input_index: usize, chain_id: ChainId) -> Result<[u8; 32], SighashError> {
        if input_index >= self.inputs.len() {
            return Err(SighashError::InputIndexOutOfRange { index: input_index, inputs: self.inputs.len() });
        }
        Ok(self.sighash(input_index, chain_id))
    }
}

// ── Witnesses (CRY-1, canonical-witness half) ───────────────────────────────

/// The canonical witness rule: `script_sig` is EXACTLY
/// `[u32 LE sig_len][sig][u32 LE pk_len][pk]` with no trailing bytes, and
/// `sig` is the canonical suite-enveloped encoding
/// (`crypto::is_canonical_signature_encoding`: mandatory envelope, compact
/// Falcon half, exact ML-DSA length). The PUBLIC key is not required to be
/// enveloped: genesis carry-over addresses commit to raw keys.
///
/// Consensus for every non-coinbase transaction at/after the activation
/// (sighash v3); relay policy at every height.
pub fn canonical_witness(script_sig: &[u8]) -> Result<Witness<'_>, String> {
    canonical_witness_under(script_sig, crypto::SuiteRules::LEGACY)
}

/// [`canonical_witness`] under `rules`: from the second hardening height a
/// canonical conservative suite-0x0003 signature is canonical too
/// (`crypto::is_canonical_signature_encoding_under`). Same error strings.
pub fn canonical_witness_under(script_sig: &[u8], rules: crypto::SuiteRules) -> Result<Witness<'_>, String> {
    let (sig, pk) = Transaction::parse_script_sig_exact(script_sig)
        .ok_or_else(|| "non-canonical script_sig framing (expected exactly \
                         [u32 sig_len][sig][u32 pk_len][pk])".to_string())?;
    if !crypto::is_canonical_signature_encoding_under(sig, rules) {
        return Err("non-canonical signature encoding (envelope missing, unknown suite, \
                    padded or malformed Falcon half, or wrong ML-DSA length)".into());
    }
    Ok((sig, pk))
}

fn pubkey_hash_matches(pk: &[u8], script_pubkey: &[u8]) -> bool {
    Sha3_256::digest(pk)[..20] == *script_pubkey
}

/// One parsed witness: `(signature, public key)`, borrowed from `script_sig`.
pub type Witness<'a> = (&'a [u8], &'a [u8]);

/// Parse every input's witness under the rules of `version` and check that
/// its public key hashes to the spent `script_pubkey` (`prevouts[i]`).
/// No signature math.
///
/// * V2: the exact `Transaction::parse_script_sig_borrowed` framing (no
///   trailing bytes: on this chain at every height since cc5c450), any
///   signature encoding the verifier accepts.
/// * V3: [`canonical_witness`].
pub fn check_input_witnesses<'a>(
    tx: &'a Transaction,
    prevouts: &[TxOutput],
    version: SighashVersion,
) -> Result<Vec<Witness<'a>>, String> {
    check_input_witnesses_under(tx, prevouts, version, crypto::SuiteRules::LEGACY)
}

/// The suite rules that apply under `version`: the conservative suite
/// exists only under sighash v3, so v2 always has the historical rules
/// (unchanged at every height).
fn effective_rules(version: SighashVersion, rules: crypto::SuiteRules) -> crypto::SuiteRules {
    match version {
        SighashVersion::V2 => crypto::SuiteRules::LEGACY,
        SighashVersion::V3 => rules,
    }
}

/// [`check_input_witnesses`] under `rules` ([`suite_rules_at`] of the
/// block's height): from the second hardening height a version-3 key-hash
/// witness may carry a canonical conservative signature and a policy witness
/// may list conservative keys. Under [`crypto::SuiteRules::LEGACY`] exactly
/// [`check_input_witnesses`].
pub fn check_input_witnesses_under<'a>(
    tx: &'a Transaction,
    prevouts: &[TxOutput],
    version: SighashVersion,
    rules: crypto::SuiteRules,
) -> Result<Vec<Witness<'a>>, String> {
    let rules = effective_rules(version, rules);
    if prevouts.len() != tx.inputs.len() {
        return Err(format!("{} prevouts for {} inputs", prevouts.len(), tx.inputs.len()));
    }
    let mut out = Vec::with_capacity(tx.inputs.len());
    for (i, (inp, prev)) in tx.inputs.iter().zip(prevouts).enumerate() {
        // Spend of a policy output (`core::policy`, multisig and timelocks):
        // the revealed policy must hash to the output. Its signatures are
        // checked by `verify_input_signatures`; the witness slot carries the
        // whole `script_sig` and an empty key.
        if policy::output_kind(&prev.script_pubkey) == Some(policy::OutputKind::Policy) {
            let w = policy::AnyPolicyWitness::decode_under(&inp.script_sig, rules)
                .map_err(|e| format!("malformed policy witness at input {}: {}", i, e))?;
            if w.script_pubkey() != prev.script_pubkey {
                return Err(format!("policy does not match the output at input {}", i));
            }
            out.push((inp.script_sig.as_slice(), &[][..]));
            continue;
        }
        let (sig, pk) = match version {
            SighashVersion::V2 => Transaction::parse_script_sig_borrowed(&inp.script_sig)
                .ok_or_else(|| format!("malformed script_sig at input {}", i))?,
            SighashVersion::V3 => canonical_witness_under(&inp.script_sig, rules)
                .map_err(|e| format!("input {i}: {e}"))?,
        };
        if !pubkey_hash_matches(pk, &prev.script_pubkey) {
            return Err(format!("pubkey mismatch at input {}", i));
        }
        out.push((sig, pk));
    }
    Ok(out)
}

/// Verify the signature of every input. `witnesses` comes from
/// [`check_input_witnesses`] with the same `version`.
///
/// * V2: `crypto::verify(pk, tx.sighash(i, chain_id), sig)` (historical).
/// * V3: `crypto::verify_bound(pk, d_i, sig)` with
///   `d_i = sighash_v3(i, suite(sig))` from ONE precomputation (linear).
pub fn verify_input_signatures(
    tx: &Transaction,
    prevouts: &[TxOutput],
    witnesses: &[Witness<'_>],
    version: SighashVersion,
    chain_id: ChainId,
) -> Result<(), String> {
    verify_input_signatures_under(tx, prevouts, witnesses, version, chain_id, crypto::SuiteRules::LEGACY)
}

/// [`verify_input_signatures`] under `rules` ([`suite_rules_at`] of the
/// block's height; `witnesses` from [`check_input_witnesses_under`] with the
/// same rules). Under sighash v3 every signature is
/// `crypto::verify_bound_under(pk, d_i, sig, rules)` with `d_i` committing to
/// the signature's suite; from the second hardening height that admits the
/// conservative suite 0x0003 (both its SLH-DSA and its Falcon component must
/// verify, each over its bound message). Under [`crypto::SuiteRules::LEGACY`]
/// exactly [`verify_input_signatures`].
pub fn verify_input_signatures_under(
    tx: &Transaction,
    prevouts: &[TxOutput],
    witnesses: &[Witness<'_>],
    version: SighashVersion,
    chain_id: ChainId,
    rules: crypto::SuiteRules,
) -> Result<(), String> {
    let rules = effective_rules(version, rules);
    if witnesses.len() != tx.inputs.len() {
        return Err(format!("{} witnesses for {} inputs", witnesses.len(), tx.inputs.len()));
    }
    let is_policy = |i: usize| prevouts.get(i)
        .is_some_and(|p| policy::output_kind(&p.script_pubkey) == Some(policy::OutputKind::Policy));
    match version {
        SighashVersion::V2 => {
            for (i, (sig, pk)) in witnesses.iter().enumerate() {
                let sighash = tx.sighash(i, chain_id);
                if is_policy(i) {
                    // Exactly the listed keys sign, each in the strict
                    // enveloped canonical form.
                    let w = policy::AnyPolicyWitness::decode(sig)
                        .map_err(|e| format!("malformed policy witness at input {}: {}", i, e))?;
                    let pol = w.policy();
                    for (idx, psig) in w.signatures() {
                        let key = pol.pubkeys.get(*idx as usize)
                            .ok_or_else(|| format!("policy key {} out of range at input {}", idx, i))?;
                        if !crypto::verify_enveloped_canonical(key, &sighash, psig) {
                            return Err(format!("invalid signature by policy key {} at input {}", idx, i));
                        }
                    }
                    continue;
                }
                // Hybrid ML-DSA-65 ‖ Falcon-1024 signature, Falcon in its
                // canonical compact encoding (one byte string per signature).
                if !crypto::verify_canonical(pk, &sighash, sig) {
                    return Err(format!("invalid signature at input {}", i));
                }
            }
        }
        SighashVersion::V3 => {
            let pre = SighashV3Precomputed::new(tx, prevouts).map_err(|e| e.to_string())?;
            for (i, (sig, pk)) in witnesses.iter().enumerate() {
                if is_policy(i) {
                    let w = policy::AnyPolicyWitness::decode_under(sig, rules)
                        .map_err(|e| format!("malformed policy witness at input {}: {}", i, e))?;
                    let pol = w.policy();
                    for (idx, psig) in w.signatures() {
                        let key = pol.pubkeys.get(*idx as usize)
                            .ok_or_else(|| format!("policy key {} out of range at input {}", idx, i))?;
                        if !crypto::is_canonical_signature_encoding_under(psig, rules) {
                            return Err(format!("non-canonical signature by policy key {} at input {}", idx, i));
                        }
                        let suite = crypto::split_envelope(psig)
                            .map(|(s, _)| s)
                            .ok_or_else(|| format!("input {i}: policy signature has no suite envelope"))?;
                        let digest = pre.digest(i, suite, chain_id).map_err(|e| e.to_string())?;
                        if !crypto::verify_bound_under(key, &digest, psig, rules) {
                            return Err(format!("invalid signature by policy key {} at input {}", idx, i));
                        }
                    }
                    continue;
                }
                let suite = crypto::split_envelope(sig)
                    .map(|(s, _)| s)
                    .ok_or_else(|| format!("input {i}: signature has no suite envelope"))?;
                let digest = pre.digest(i, suite, chain_id).map_err(|e| e.to_string())?;
                if !crypto::verify_bound_under(pk, &digest, sig, rules) {
                    return Err(format!("invalid signature at input {}", i));
                }
            }
        }
    }
    Ok(())
}

/// The complete input-script rule of a non-coinbase transaction in a block at
/// header height `height` (no cache): version rule, witnesses, signatures.
/// The node's `mempool::admission::verify_input_scripts` is this function
/// plus a verified-signature cache; wallets use it to self-check.
pub fn verify_tx_scripts(
    tx: &Transaction,
    prevouts: &[TxOutput],
    chain_id: ChainId,
    height: u64,
    activation_height: u64,
) -> Result<SighashVersion, String> {
    verify_tx_scripts_at(tx, prevouts, chain_id, height, activation_height, activation::NEVER)
}

/// [`verify_tx_scripts`] with the second hardening height
/// `hardening2_activation_height` too (the conservative suite 0x0003 from it,
/// [`suite_rules_at`]). `NEVER` gives exactly [`verify_tx_scripts`].
pub fn verify_tx_scripts_at(
    tx: &Transaction,
    prevouts: &[TxOutput],
    chain_id: ChainId,
    height: u64,
    activation_height: u64,
    hardening2_activation_height: u64,
) -> Result<SighashVersion, String> {
    let version = check_tx_version(tx.version, height, activation_height)?;
    let rules = suite_rules_at(height, activation_height, hardening2_activation_height);
    let witnesses = check_input_witnesses_under(tx, prevouts, version, rules)?;
    verify_input_signatures_under(tx, prevouts, &witnesses, version, chain_id, rules)?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TxInput;

    fn tx_with(n_in: usize, n_out: usize, version: u32) -> (Transaction, Vec<TxOutput>) {
        let tx = Transaction {
            version,
            inputs: (0..n_in).map(|i| TxInput {
                prev_txid: [(i % 251) as u8; 32],
                prev_index: i as u32,
                script_sig: vec![0xAB; 64],
                sequence: u32::MAX - i as u32,
            }).collect(),
            outputs: (0..n_out).map(|i| TxOutput { value: 1_000 + i as u64, script_pubkey: vec![i as u8; 20] }).collect(),
            locktime: 7,
        };
        let spent = (0..n_in).map(|i| TxOutput { value: 50_000 + i as u64, script_pubkey: vec![0x5A; 20] }).collect();
        (tx, spent)
    }

    #[test]
    fn version_rule_is_gated_at_the_activation_height() {
        let h = 100;
        for v in [0u32, 1, 2, 4, u32::MAX] {
            assert_eq!(check_tx_version(v, h - 1, h), Ok(SighashVersion::V2), "v{v} below activation");
            assert!(check_tx_version(v, h, h).unwrap_err().starts_with("bad-txns-version"));
        }
        // Below the activation version 3 is consensus-valid with the v2 digest
        // (exactly the pre-upgrade rule: no split before the flag day).
        assert_eq!(check_tx_version(3, h - 1, h), Ok(SighashVersion::V2));
        assert_eq!(check_tx_version(3, 0, h), Ok(SighashVersion::V2));
        assert_eq!(check_tx_version(3, h, h), Ok(SighashVersion::V3));
        assert_eq!(check_tx_version(3, u64::MAX, h), Ok(SighashVersion::V3));
        // NEVER: the historical rule forever (every version is v2).
        for v in [0u32, 1, 2, 3, 4, u32::MAX] {
            assert_eq!(check_tx_version(v, u64::MAX - 1, activation::NEVER), Ok(SighashVersion::V2));
        }
        assert_eq!(tx_version_for_height(h - 1, h), TX_VERSION_LEGACY);
        assert_eq!(tx_version_for_height(h, h), TX_VERSION_V3);
        assert_eq!(SighashVersion::for_tx_version(3), SighashVersion::V3);
        assert_eq!(SighashVersion::for_tx_version(2), SighashVersion::V2);
    }

    /// Relay policy: below the activation version >= 3 is non-standard (it is
    /// consensus-valid there); at/after it the policy is the consensus rule.
    #[test]
    fn version_policy_refuses_version_3_and_above_below_the_activation() {
        let h = 100;
        for v in [0u32, 1, 2] {
            assert_eq!(check_tx_version_standard(v, h - 1, h), Ok(SighashVersion::V2));
            assert!(check_tx_version_standard(v, h, h).unwrap_err().starts_with("bad-txns-version"));
        }
        for v in [3u32, 4, u32::MAX] {
            assert_eq!(check_tx_version(v, h - 1, h), Ok(SighashVersion::V2), "consensus-valid");
            assert!(check_tx_version_standard(v, h - 1, h).unwrap_err().starts_with("non-standard-version"));
            assert!(check_tx_version_standard(v, 0, activation::NEVER).unwrap_err().starts_with("non-standard-version"));
        }
        assert_eq!(check_tx_version_standard(3, h, h), Ok(SighashVersion::V3));
        assert!(check_tx_version_standard(4, h, h).unwrap_err().starts_with("bad-txns-version"));
        // Whatever passes the policy at two heights uses the same digest at
        // both (so a pooled transaction never needs re-verifying when the
        // next height moves).
        for v in [0u32, 1, 2, 3, 4] {
            let at = |height| check_tx_version_standard(v, height, h).ok();
            for (a, b) in [(0, h - 1), (h, u64::MAX), (h - 1, h)] {
                if let (Some(x), Some(y)) = (at(a), at(b)) {
                    assert_eq!(x, y, "v{v} at {a} and {b}");
                }
            }
        }
    }

    #[test]
    fn out_of_range_index_is_an_error_never_a_digest() {
        let (tx, spent) = tx_with(2, 1, 3);
        let pre = SighashV3Precomputed::new(&tx, &spent).unwrap();
        assert!(pre.digest(1, 1, ChainId::Mainnet).is_ok());
        assert_eq!(pre.digest(2, 1, ChainId::Mainnet),
            Err(SighashError::InputIndexOutOfRange { index: 2, inputs: 2 }));
        assert_eq!(tx.sighash_v2_checked(2, ChainId::Mainnet),
            Err(SighashError::InputIndexOutOfRange { index: 2, inputs: 2 }));
        assert_eq!(SighashV3Precomputed::new(&tx, &spent[..1]),
            Err(SighashError::SpentOutputCount { spent: 1, inputs: 2 }));
    }

    #[test]
    fn v3_commits_to_every_field() {
        let (tx, spent) = tx_with(3, 2, 3);
        let d = |t: &Transaction, s: &[TxOutput], i: usize, suite: u16, c: ChainId| t.sighash_v3(s, i, suite, c).unwrap();
        let base = d(&tx, &spent, 1, 1, ChainId::Mainnet);
        assert_ne!(base, d(&tx, &spent, 0, 1, ChainId::Mainnet), "input index");
        assert_ne!(base, d(&tx, &spent, 1, 2, ChainId::Mainnet), "suite id");
        assert_ne!(base, d(&tx, &spent, 1, 1, ChainId::Testnet), "chain id");
        let mut s = spent.clone(); s[2].value += 1;
        assert_ne!(base, d(&tx, &s, 1, 1, ChainId::Mainnet), "another input's spent amount");
        let mut s = spent.clone(); s[0].script_pubkey[0] ^= 1;
        assert_ne!(base, d(&tx, &s, 1, 1, ChainId::Mainnet), "another input's spent script");
        let mut t = tx.clone(); t.locktime += 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "locktime");
        let mut t = tx.clone(); t.inputs[2].sequence ^= 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "sequence");
        let mut t = tx.clone(); t.inputs[0].prev_index ^= 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "prevout");
        let mut t = tx.clone(); t.outputs[1].value += 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "output value");
        let mut t = tx.clone(); t.outputs[1].script_pubkey.push(0);
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "output script");
        // The witness is not committed (txid-style, segwit-like).
        let mut t = tx.clone(); t.inputs[1].script_sig.clear();
        assert_eq!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "script_sig is not committed");
    }

    /// MEM-5: signing/verifying every input of a v3 transaction hashes
    /// O(size) bytes; the v2 digest hashes O(size) bytes PER input. Counted,
    /// not timed, so the test is deterministic.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "absorbs ~40 KB into SHA3-256 (~300 Keccak-f[1600] permutations, ~0.4 s each under \
                  Miri); a byte-counting cost test, its arithmetic also runs in v3_commits_to_every_field"
    )]
    fn v3_cost_is_linear_in_the_input_count() {
        let cost_v3 = |n: usize| {
            let (tx, spent) = tx_with(n, 2, 3);
            let pre = SighashV3Precomputed::new(&tx, &spent).unwrap();
            for i in 0..n {
                let p = pre.preimage(i, 1, ChainId::Mainnet).unwrap();
                assert_eq!(p.len(), SIGHASH_V3_PREIMAGE_LEN);
            }
            pre.hashed_bytes + n * SIGHASH_V3_PREIMAGE_LEN
        };
        let (c50, c500) = (cost_v3(50), cost_v3(500));
        // Linear: 10x the inputs costs (at most a little over) 10x the bytes.
        assert!(c500 <= 11 * c50, "v3 cost {c50} -> {c500} is not linear");
        assert!(c500 >= 9 * c50);

        // v2 for comparison: every input re-encodes the whole stripped tx.
        let cost_v2 = |n: usize| {
            let (tx, _) = tx_with(n, 2, 1);
            let body = bincode::serde::encode_to_vec(&tx, bincode::config::standard()).unwrap().len();
            n * body
        };
        assert!(cost_v2(500) >= 90 * cost_v2(50), "v2 is quadratic");
    }

    #[test]
    fn exact_witness_framing() {
        let sig = vec![1u8; 10];
        let pk = vec![2u8; 7];
        let w = Transaction::build_script_sig(&sig, &pk);
        assert_eq!(Transaction::parse_script_sig_exact(&w), Some((&sig[..], &pk[..])));
        let mut trailing = w.clone();
        trailing.push(0);
        assert_eq!(Transaction::parse_script_sig_exact(&trailing), None);
        // This chain's v2 framing is exact too (consensus since cc5c450).
        assert_eq!(Transaction::parse_script_sig(&trailing), None);
        assert_eq!(Transaction::parse_script_sig_borrowed(&trailing), None);
        assert_eq!(Transaction::parse_script_sig_exact(&w[..w.len() - 1]), None);
        assert!(canonical_witness(&w).is_err(), "a non-enveloped signature is not canonical");
    }

    // ── End-to-end input-script rule with real hybrid signatures ────────────

    struct Signer {
        pk: Vec<u8>,
        sk: Vec<u8>,
        spk: Vec<u8>,
    }

    fn signer(seed: u8) -> Signer {
        let (pk, sk) = crypto::generate_keypair_from_seed(&[seed; 32]).unwrap();
        let spk = Sha3_256::digest(&pk)[..20].to_vec();
        Signer { pk, sk, spk }
    }

    /// A two-input transaction spending two outputs of `s`, every input
    /// signed under `digest` (version 3 for v3, version 1 for v2).
    fn signed_tx(s: &Signer, digest: SighashVersion, chain: ChainId) -> (Transaction, Vec<TxOutput>) {
        let mut tx = Transaction {
            version: if digest == SighashVersion::V3 { TX_VERSION_V3 } else { TX_VERSION_LEGACY },
            inputs: (0..2u8).map(|i| TxInput {
                prev_txid: [0x30 + i; 32],
                prev_index: i as u32,
                script_sig: vec![],
                sequence: u32::MAX,
            }).collect(),
            outputs: vec![TxOutput { value: 40_000, script_pubkey: vec![0x77; 20] }],
            locktime: 0,
        };
        let prevouts: Vec<TxOutput> =
            (0..2u64).map(|i| TxOutput { value: 25_000 + i, script_pubkey: s.spk.clone() }).collect();
        let sigs: Vec<Vec<u8>> = match digest {
            SighashVersion::V2 => (0..2).map(|i| crypto::sign(&s.sk, &tx.sighash(i, chain)).unwrap()).collect(),
            SighashVersion::V3 => {
                let pre = SighashV3Precomputed::new(&tx, &prevouts).unwrap();
                (0..2)
                    .map(|i| {
                        let d = pre.digest(i, crypto::SUITE_MLDSA65_FALCON1024, chain).unwrap();
                        crypto::sign_bound(&s.sk, &d).unwrap()
                    })
                    .collect()
            }
        };
        for (inp, sig) in tx.inputs.iter_mut().zip(sigs) {
            inp.script_sig = Transaction::build_script_sig(&sig, &s.pk);
        }
        (tx, prevouts)
    }

    /// At/after the activation: a correctly signed version-3 transaction
    /// verifies, and every single fault is rejected with its own error.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "generates hybrid keys and signs/verifies through the PQClean ML-DSA-65 and Falcon-1024 C code, \
                  which Miri cannot execute (it runs under ASan, UBSan and i686: scripts/sanitizers.sh)"
    )]
    fn v3_scripts_verify_and_every_fault_is_rejected() {
        use SighashVersion::V3;
        let (h, main) = (100, ChainId::Mainnet);
        let s = signer(7);
        let (tx, prev) = signed_tx(&s, V3, main);
        assert_eq!(verify_tx_scripts(&tx, &prev, main, h, h), Ok(V3));

        let w = check_input_witnesses(&tx, &prev, V3).unwrap();
        assert_eq!(w.len(), 2);
        for (i, (sig, pk)) in w.iter().enumerate() {
            assert_eq!(Transaction::parse_script_sig_exact(&tx.inputs[i].script_sig), Some((*sig, *pk)));
        }
        assert_eq!(verify_input_signatures(&tx, &prev, &w, V3, main), Ok(()));

        // Replay on another chain id, and a v3 signature checked as v2.
        assert_eq!(verify_tx_scripts(&tx, &prev, ChainId::Testnet, h, h), Err("invalid signature at input 0".into()));
        assert_eq!(verify_input_signatures(&tx, &prev, &w, SighashVersion::V2, main),
            Err("invalid signature at input 0".into()));
        // Only version 3 is valid at/after the activation.
        let mut t = tx.clone();
        t.version = TX_VERSION_LEGACY;
        assert!(verify_tx_scripts(&t, &prev, main, h, h).unwrap_err().starts_with("bad-txns-version"));
        // v3 commits every spent amount: changing input 1's breaks input 0.
        let mut p = prev.clone();
        p[1].value += 1;
        assert_eq!(verify_tx_scripts(&tx, &p, main, h, h), Err("invalid signature at input 0".into()));
        // Input 0 valid, input 1 carries input 0's signature (other index).
        let mut t = tx.clone();
        t.inputs[1].script_sig = t.inputs[0].script_sig.clone();
        assert_eq!(verify_tx_scripts(&t, &prev, main, h, h), Err("invalid signature at input 1".into()));
        // The public key must hash to the spent script.
        let mut p = prev.clone();
        p[1].script_pubkey[0] ^= 1;
        assert_eq!(verify_tx_scripts(&tx, &p, main, h, h), Err("pubkey mismatch at input 1".into()));
        // One prevout per input.
        assert_eq!(verify_tx_scripts(&tx, &prev[..1], main, h, h), Err("1 prevouts for 2 inputs".into()));
        // Canonical framing: a trailing byte is invalid at/after the activation.
        let mut t = tx.clone();
        t.inputs[1].script_sig.push(0);
        assert!(verify_tx_scripts(&t, &prev, main, h, h).unwrap_err()
            .starts_with("input 1: non-canonical script_sig framing"));

        // verify_input_signatures' own guards.
        assert_eq!(verify_input_signatures(&tx, &prev, &w[..1], V3, main), Err("1 witnesses for 2 inputs".into()));
        let unenveloped = [(&b"no suite envelope"[..], w[0].1), w[1]];
        assert_eq!(verify_input_signatures(&tx, &prev, &unenveloped, V3, main),
            Err("input 0: signature has no suite envelope".into()));
        assert_eq!(verify_input_signatures(&tx, &prev[..1], &w, V3, main),
            Err("sighash v3 needs one spent output per input (1 for 2 inputs)".into()));
    }

    /// Below the activation: the v2 rule, its exact framing included.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "generates hybrid keys and signs/verifies through the PQClean ML-DSA-65 and Falcon-1024 C code, \
                  which Miri cannot execute (it runs under ASan, UBSan and i686: scripts/sanitizers.sh)"
    )]
    fn v2_scripts_verify_below_the_activation() {
        use SighashVersion::V2;
        let (h, main) = (100, ChainId::Mainnet);
        let s = signer(8);
        let (tx, prev) = signed_tx(&s, V2, main);
        assert_eq!(verify_tx_scripts(&tx, &prev, main, h - 1, h), Ok(V2));
        assert_eq!(tx.sighash_v2_checked(1, main), Ok(tx.sighash(1, main)));
        assert_ne!(tx.sighash(1, main), tx.sighash(0, main));

        // A trailing byte after the public key is invalid below the
        // activation too (this chain's exact v2 framing).
        let mut t = tx.clone();
        t.inputs[1].script_sig.push(0);
        assert_eq!(verify_tx_scripts(&t, &prev, main, h - 1, h), Err("malformed script_sig at input 1".into()));
        // The same transaction is invalid at the activation (version 1).
        assert!(verify_tx_scripts(&tx, &prev, main, h, h).unwrap_err().starts_with("bad-txns-version"));

        assert_eq!(verify_tx_scripts(&tx, &prev, ChainId::Testnet, h - 1, h), Err("invalid signature at input 0".into()));
        let mut t = tx.clone();
        t.inputs[1].script_sig = t.inputs[0].script_sig.clone();
        assert_eq!(verify_tx_scripts(&t, &prev, main, h - 1, h), Err("invalid signature at input 1".into()));
        let mut t = tx.clone();
        t.inputs[0].script_sig.truncate(7);
        assert_eq!(verify_tx_scripts(&t, &prev, main, h - 1, h), Err("malformed script_sig at input 0".into()));
        let mut p = prev.clone();
        p[0].script_pubkey[19] ^= 0x80;
        assert_eq!(verify_tx_scripts(&tx, &p, main, h - 1, h), Err("pubkey mismatch at input 0".into()));
    }

    #[test]
    fn sighash_error_messages() {
        assert_eq!(SighashError::InputIndexOutOfRange { index: 2, inputs: 2 }.to_string(),
            "sighash input index 2 out of range (2 inputs)");
        assert_eq!(SighashError::SpentOutputCount { spent: 1, inputs: 3 }.to_string(),
            "sighash v3 needs one spent output per input (1 for 3 inputs)");
        assert_eq!(SighashError::TooLarge("input count").to_string(), "sighash: input count does not fit in u32");
    }
}
