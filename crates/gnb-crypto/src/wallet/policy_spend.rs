//! Multi-party spending from a policy address (multisig / timelocks).
//!
//! Flow, each step on the machine that holds what it needs:
//!
//! 1. [`PolicySpend::new`] — anyone: picks the outputs, fixes amount, change
//!    (back to the policy) and a fee that covers the largest possible witness,
//!    and produces an unsigned spend.
//! 2. [`PolicySpend::sign`] — each signer, with their own keystore: adds a
//!    signature for every input. The secret key never leaves that machine;
//!    only the spend file travels.
//! 3. [`PolicySpend::finalize`] — anyone: once `threshold` signers have
//!    signed, builds the witnesses and returns the broadcastable transaction.
//!
//! The transaction (and so every sighash) is fixed at step 1; signatures
//! cannot be applied to a different transaction.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::address::Network;
use crate::core::policy::{BranchWitness, PolicyTree, PolicyWitness, SpendPolicy};
use crate::core::sighash::{SighashV3Precomputed, SighashVersion};
use crate::core::{self, ChainId, Transaction, TxInput, TxOutput};
use crate::crypto;

/// An in-progress spend from one policy.
#[derive(Debug, Clone)]
pub struct PolicySpend {
    pub network: Network,
    /// The policy that signs: the whole policy, or the revealed branch of `tree`.
    pub policy: SpendPolicy,
    /// For a policy-tree output: the tree and the branch being used.
    pub tree: Option<(PolicyTree, u8)>,
    pub tx: Transaction,
    /// Per input: key index → signature.
    pub signatures: Vec<BTreeMap<u8, Vec<u8>>>,
    /// Per input: the value of the spent output (its script is
    /// [`Self::locking_script`]). A version-3 (sighash v3) signature commits
    /// to it.
    pub amounts: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
struct SpendFile {
    network: String,
    policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tree: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    branch: Option<u8>,
    tx: String,
    signatures: Vec<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    amounts: Vec<String>,
}

/// Upper bound on a policy witness (sets the fee before anyone signs): every
/// one of the `threshold` signatures at the maximum length of the policy's
/// widest key suite (P5-S: 9,322 bytes once a conservative suite-0x0003 key
/// is listed, `crypto::max_signature_len_for_public_key_len`).
pub fn max_witness_size(policy: &SpendPolicy) -> usize {
    let max_sig = policy.pubkeys.iter()
        .map(|k| crypto::max_signature_len_for_public_key_len(k.len()))
        .max()
        .unwrap_or(core::SIG_SIZE)
        .max(core::SIG_SIZE);
    1 + 4 + policy.encode().len() + 1 + policy.threshold as usize * (1 + 4 + max_sig)
}

/// Largest partial signature the spend tooling carries: a conservative
/// suite-0x0003 signature (9,322 bytes) within the consensus policy
/// signature bound of the second hardening height (10 KiB; 8 KiB below it).
pub const MAX_PARTIAL_SIGNATURE_LEN: usize = 10 * 1024;

/// The suite rules the spend tooling reads a policy under: the widest
/// ([`crypto::SuiteRules::HARDENING2`], conservative keys included).
/// Whether a policy with such keys can be spent at the target block's
/// height is checked against that height ([`PolicySpend::check_suites_for_height`]).
const TOOLING_RULES: crypto::SuiteRules = crypto::SuiteRules::HARDENING2;

/// Upper bound on a branch witness of a policy tree.
pub fn max_branch_witness_size(branch: &SpendPolicy) -> usize {
    max_witness_size(branch) + 2 + 2 * 32
}

impl PolicySpend {
    /// Unsigned spend of `inputs` (`(txid, vout, value)`, all locked by
    /// `policy`) paying `amount` to `to_script`, change back to the policy.
    /// The fee is raised to the consensus minimum for the largest possible
    /// witnesses; sub-dust change is left to the fee.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        policy: SpendPolicy,
        inputs: &[([u8; 32], u32, u64)],
        to_script: Vec<u8>,
        amount: u64,
        fee: u64,
        locktime: u32,
    ) -> Result<Self, String> {
        if inputs.is_empty() {
            return Err("no inputs".into());
        }
        if core::policy::output_kind(&to_script).is_none() {
            return Err("unsupported destination script".into());
        }
        if amount < core::DUST_THRESHOLD {
            return Err(format!("amount below the dust threshold ({} base units)", core::DUST_THRESHOLD));
        }
        if policy.after != 0 && locktime < policy.after {
            return Err(format!("policy is time-locked until height {}: set locktime ≥ {}", policy.after, policy.after));
        }
        let total = inputs.iter().try_fold(0u64, |t, (_, _, v)| t.checked_add(*v))
            .ok_or("input total overflows")?;
        let mut tx = Transaction {
            version: 1,
            inputs: inputs.iter().map(|(txid, vout, _)| TxInput {
                prev_txid: *txid, prev_index: *vout, script_sig: Vec::new(), sequence: u32::MAX,
            }).collect(),
            outputs: vec![
                TxOutput { value: amount, script_pubkey: to_script },
                TxOutput { value: 0, script_pubkey: policy.script_pubkey() },
            ],
            locktime,
        };
        // Size with the largest possible witnesses → minimum fee.
        let witness_upper = max_witness_size(&policy) * inputs.len();
        let size = tx.to_wire_bytes(true).len() + witness_upper;
        let fee = fee.max(core::tokenomics::min_tx_fee_sat(size));
        let change = total.checked_sub(amount).and_then(|r| r.checked_sub(fee))
            .ok_or_else(|| format!("insufficient funds: {} available, {} + fee {} needed", total, amount, fee))?;
        if change >= core::DUST_THRESHOLD {
            tx.outputs[1].value = change;
        } else {
            tx.outputs.pop(); // sub-dust change goes to the fee
        }
        let amounts = inputs.iter().map(|(_, _, v)| *v).collect();
        let spend = Self { network, policy, tree: None, tx, signatures: vec![BTreeMap::new(); inputs.len()], amounts };
        // PF-4: never valid where hardening 2 holds from genesis.
        spend.check_key_identities_for_height(0)?;
        // P5-S: never valid where hardening 2 is not scheduled.
        spend.check_suites_scheduled()?;
        Ok(spend)
    }

    /// Unsigned spend of policy-tree `inputs` through branch `branch`, paying
    /// exactly `outputs` (in order), with change back to the tree last. The
    /// fee is raised to the consensus minimum for the largest witnesses and
    /// taken from the change.
    pub fn new_branch(
        network: Network,
        tree: PolicyTree,
        branch: u8,
        inputs: &[([u8; 32], u32, u64)],
        outputs: Vec<TxOutput>,
        fee: u64,
        locktime: u32,
    ) -> Result<Self, String> {
        let policy = tree.branches.get(branch as usize).cloned().ok_or("no such branch")?;
        if inputs.is_empty() || outputs.is_empty() {
            return Err("no inputs or outputs".into());
        }
        for o in &outputs {
            if core::policy::output_kind(&o.script_pubkey).is_none() {
                return Err("unsupported output script".into());
            }
            if o.value < core::DUST_THRESHOLD {
                return Err("output below the dust threshold".into());
            }
        }
        if policy.after != 0 && locktime < policy.after {
            return Err(format!("branch is time-locked until height {}: set locktime ≥ {}", policy.after, policy.after));
        }
        let total = inputs.iter().try_fold(0u64, |t, (_, _, v)| t.checked_add(*v)).ok_or("input total overflows")?;
        let paid = outputs.iter().try_fold(0u64, |t, o| t.checked_add(o.value)).ok_or("output total overflows")?;
        let mut tx = Transaction {
            version: 1,
            inputs: inputs.iter().map(|(txid, vout, _)| TxInput {
                prev_txid: *txid, prev_index: *vout, script_sig: Vec::new(), sequence: u32::MAX,
            }).collect(),
            outputs,
            locktime,
        };
        tx.outputs.push(TxOutput { value: 0, script_pubkey: tree.script_pubkey() });
        let size = tx.to_wire_bytes(true).len() + max_branch_witness_size(&policy) * inputs.len();
        let fee = fee.max(core::tokenomics::min_tx_fee_sat(size));
        let change = total.checked_sub(paid).and_then(|r| r.checked_sub(fee))
            .ok_or_else(|| format!("insufficient funds: {} available, {} + fee {} needed", total, paid, fee))?;
        if change >= core::DUST_THRESHOLD {
            tx.outputs.last_mut().expect("change").value = change;
        } else {
            tx.outputs.pop();
        }
        let amounts = inputs.iter().map(|(_, _, v)| *v).collect();
        let spend = Self { network, policy, tree: Some((tree, branch)), tx, signatures: vec![BTreeMap::new(); inputs.len()], amounts };
        // PF-4: never valid where hardening 2 holds from genesis.
        spend.check_key_identities_for_height(0)?;
        // P5-S: never valid where hardening 2 is not scheduled.
        spend.check_suites_scheduled()?;
        Ok(spend)
    }

    /// The script the inputs are locked by (and change returns to).
    pub fn locking_script(&self) -> Vec<u8> {
        match &self.tree {
            Some((t, _)) => t.script_pubkey(),
            None => self.policy.script_pubkey(),
        }
    }

    pub fn chain_id(&self) -> ChainId {
        ChainId::for_network(self.network)
    }

    /// Fee this spend pays (needs the input values it was built from).
    pub fn outputs_total(&self) -> u64 {
        self.tx.outputs.iter().map(|o| o.value).sum()
    }

    /// Give the spend the transaction version (and so the sighash) of a
    /// block at `next_block_height` (the node's getdaginfo
    /// `next_block_height`): 3 / sighash v3 at/after the hardening
    /// activation, 1 / sighash v2 below it. Only before anyone signed.
    ///
    /// PF-4: refused when the spent policy (or revealed branch) lists one
    /// key twice and the second hardening rules hold at `next_block_height`
    /// ([`Self::check_key_identities_for_height`]).
    pub fn target_height(&mut self, next_block_height: u64) -> Result<(), String> {
        if self.signatures.iter().any(|m| !m.is_empty()) {
            return Err("the spend already carries signatures; its version is fixed".into());
        }
        self.check_key_identities_for_height(next_block_height)?;
        self.check_suites_for_height(next_block_height)?;
        let act = core::activation::hardening_activation_height_for_signer(self.chain_id());
        self.tx.version = core::sighash::tx_version_for_height(next_block_height, act);
        Ok(())
    }

    /// PF-4 for producers: from the second hardening height
    /// (`activation::hardening2_activation_height_for_signer`) a spend whose
    /// policy (or revealed branch) lists one key twice, in its raw and its
    /// enveloped encoding, is consensus-invalid (`SpendPolicy::
    /// check_key_identities`, applied by the node's policy-spend rule), so
    /// no tool builds, signs or finalizes one for a block at or above that
    /// height. Below it such a spend is valid, as before, and is not refused
    /// (it is how the owner of such an output moves it before the height).
    /// `next_block_height` is the height of the block the spend targets.
    pub fn check_key_identities_for_height(&self, next_block_height: u64) -> Result<(), String> {
        let h2 = core::activation::hardening2_activation_height_for_signer(self.chain_id());
        if core::activation::is_active_at(next_block_height, h2) && self.policy.check_key_identities().is_err() {
            return Err(format!(
                "the policy names the same key twice (raw and enveloped encodings): such a spend is \
                 invalid from the second hardening height {h2} (PF-4)"));
        }
        Ok(())
    }

    /// P5-S for producers: a policy (or revealed branch) that lists a
    /// conservative suite-0x0003 key decodes only from the second hardening
    /// height (`core::sighash::suite_rules_at`), so no tool targets such a
    /// spend at a block below it.
    pub fn check_suites_for_height(&self, next_block_height: u64) -> Result<(), String> {
        if !self.policy.has_conservative_key() {
            return Ok(());
        }
        let h2 = core::activation::hardening2_activation_height_for_signer(self.chain_id());
        crypto::KeySuite::Conservative.check_allowed_at(next_block_height, h2)
            .map_err(|e| format!("the policy lists a conservative suite-0x0003 key: {e}"))
    }

    /// [`Self::check_suites_for_height`] for a spend not yet targeted at a
    /// height: refused only where no height accepts it (the second
    /// hardening is not scheduled on the spend's chain).
    fn check_suites_scheduled(&self) -> Result<(), String> {
        let h2 = core::activation::hardening2_activation_height_for_signer(self.chain_id());
        if h2 == core::activation::NEVER {
            return self.check_suites_for_height(0);
        }
        Ok(())
    }

    /// The sighash version this spend's signatures use.
    pub fn sighash_version(&self) -> SighashVersion {
        SighashVersion::for_tx_version(self.tx.version)
    }

    /// The digest `public_key` signs for input `i`.
    pub(super) fn digest(&self, i: usize, public_key: &[u8]) -> Result<[u8; 32], String> {
        let chain_id = self.chain_id();
        match self.sighash_version() {
            SighashVersion::V2 => Ok(self.tx.sighash(i, chain_id)),
            SighashVersion::V3 => {
                if self.amounts.len() != self.tx.inputs.len() {
                    return Err("the spend file has no input values (needed by sighash v3); rebuild it".into());
                }
                let spk = self.locking_script();
                let spent: Vec<TxOutput> = self.amounts.iter()
                    .map(|v| TxOutput { value: *v, script_pubkey: spk.clone() })
                    .collect();
                let suite = crypto::public_key_suite_under(public_key, TOOLING_RULES)
                    .ok_or("unknown public key suite")?;
                SighashV3Precomputed::new(&self.tx, &spent)
                    .and_then(|p| p.digest(i, suite, chain_id))
                    .map_err(|e| e.to_string())
            }
        }
    }

    pub(super) fn verifies(&self, public_key: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        match self.sighash_version() {
            SighashVersion::V2 => crypto::verify_enveloped_canonical(public_key, digest, sig),
            // P5-S: the widest rules; the target height was checked by
            // `check_suites_for_height`.
            SighashVersion::V3 => crypto::verify_bound_under(public_key, digest, sig, TOOLING_RULES),
        }
    }

    /// Add `public_key`'s signature (made by `sign` over each input's
    /// digest) to every input. Version 1 (sighash v2) only: the message is
    /// signed as is. Returns the key's index in the policy.
    pub fn sign(
        &mut self,
        public_key: &[u8],
        sign: impl Fn(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<u8, String> {
        if self.sighash_version() != SighashVersion::V2 {
            return Err("a version-3 spend is signed with sign_digest (sighash v3)".into());
        }
        self.sign_digest(public_key, |d, _| sign(d))
    }

    /// Add `public_key`'s signature to every input. `sign(digest, version)`
    /// signs one input's digest: `crypto::sign` for sighash v2,
    /// `crypto::sign_bound` for v3 (`Keypair::sign_tx_digest` does both).
    /// Returns the key's index in the policy.
    pub fn sign_digest(
        &mut self,
        public_key: &[u8],
        sign: impl Fn(&[u8; 32], SighashVersion) -> Result<Vec<u8>, String>,
    ) -> Result<u8, String> {
        self.check_signing_shape()?;
        let idx = self.policy.pubkeys.iter().position(|k| k == public_key)
            .ok_or("this key is not part of the policy")? as u8;
        let version = self.sighash_version();
        if version == SighashVersion::V2 && crypto::is_conservative_public_key(public_key) {
            return Err("a conservative suite-0x0003 key signs only version-3 spends (sighash v3) for a block \
                        at or above the second hardening height: target the spend at that height first".into());
        }
        for i in 0..self.tx.inputs.len() {
            let digest = self.digest(i, public_key)?;
            let sig = sign(&digest, version)?;
            if !self.verifies(public_key, &digest, &sig) {
                return Err("produced signature does not verify (wrong key or non-canonical encoding)".into());
            }
            self.signatures[i].insert(idx, sig);
        }
        Ok(idx)
    }

    /// Distinct signers that signed every input.
    pub fn signers(&self) -> Vec<u8> {
        let mut common: Option<Vec<u8>> = None;
        for m in &self.signatures {
            let keys: Vec<u8> = m.keys().copied().collect();
            common = Some(match common {
                None => keys,
                Some(c) => c.into_iter().filter(|k| keys.contains(k)).collect(),
            });
        }
        common.unwrap_or_default()
    }

    /// Build the witnesses from the `threshold` lowest-indexed signers.
    pub fn finalize(&self) -> Result<Transaction, String> {
        self.check_signing_shape()?;
        let need = self.policy.threshold as usize;
        let signers = self.signers();
        if signers.len() < need {
            return Err(format!("{} of {} required signatures", signers.len(), need));
        }
        let chosen = &signers[..need];
        let mut tx = self.tx.clone();
        for (i, input) in tx.inputs.iter_mut().enumerate() {
            let mut signatures = Vec::with_capacity(need);
            for k in chosen {
                let sig = self.signatures[i][k].clone();
                let key = &self.policy.pubkeys[*k as usize];
                if !self.verifies(key, &self.digest(i, key)?, &sig) {
                    return Err(format!("signature of key {} on input {} does not verify", k, i));
                }
                signatures.push((*k, sig));
            }
            input.script_sig = match &self.tree {
                None => PolicyWitness { policy: self.policy.clone(), signatures }.encode(),
                Some((tree, b)) => BranchWitness {
                    n_branches: tree.branches.len() as u8,
                    index: *b,
                    path: tree.path(*b as usize),
                    branch: self.policy.clone(),
                    signatures,
                }.encode(),
            };
        }
        Ok(tx)
    }

    /// Wallet boundary, not a new consensus rule. Imported JSON and public
    /// fields can bypass the constructor. BIP174's signer input validation
    /// must happen before any signing callback, not after a partial signature:
    /// https://bips.dev/174/#data-signers-check-for
    pub(super) fn check_signing_shape(&self) -> Result<(), String> {
        let check_policy = |p: &SpendPolicy| -> Result<(), String> {
            if p.pubkeys.len() > core::policy::MAX_POLICY_KEYS || p.pubkeys.iter().any(|k| k.len() > 8192) {
                return Err("policy exceeds wallet limits".into());
            }
            SpendPolicy::decode_under(&p.encode(), TOOLING_RULES).map_err(|e| format!("policy: {e}"))?;
            Ok(())
        };
        check_policy(&self.policy)?;
        // PF-4: where the second hardening rules hold from genesis (testnet,
        // regtest: active at height 0, so at every height), a twin-key spend
        // can never be valid. Elsewhere the roles that know the target
        // height refuse it (`target_height`, `PqPsbt::review`).
        self.check_key_identities_for_height(0)?;
        if let Some((tree, branch)) = &self.tree {
            if !(2..=core::policy::MAX_POLICY_BRANCHES).contains(&tree.branches.len()) {
                return Err("invalid policy tree size".into());
            }
            for p in &tree.branches { check_policy(p)?; }
            if tree.branches.get(*branch as usize) != Some(&self.policy) {
                return Err("policy does not match tree branch".into());
            }
        }
        let n = self.tx.inputs.len();
        if n == 0 || self.tx.outputs.is_empty() || self.tx.is_coinbase()
            || self.amounts.len() != n || self.signatures.len() != n {
            return Err("policy spend input/output metadata shape mismatch".into());
        }
        if !matches!(self.tx.version, 1 | 3) {
            return Err("policy wallet supports only transaction versions 1 and 3".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for input in &self.tx.inputs {
            if !input.script_sig.is_empty() || !seen.insert((input.prev_txid, input.prev_index)) {
                return Err("policy spend must be unsigned with distinct outpoints".into());
            }
        }
        for signatures in &self.signatures {
            if signatures.iter().any(|(i, s)| *i as usize >= self.policy.pubkeys.len() || s.is_empty()
                || s.len() > MAX_PARTIAL_SIGNATURE_LEN)
            {
                return Err("invalid partial signature index or size".into());
            }
        }
        for out in &self.tx.outputs {
            if core::policy::output_kind(&out.script_pubkey).is_none() || out.value < core::DUST_THRESHOLD {
                return Err("invalid policy spend output".into());
            }
        }
        if self.tx.locktime < self.policy.after {
            return Err("policy absolute timelock is not satisfied by locktime".into());
        }
        let input_total = self.amounts.iter().try_fold(0u64, |sum, v| sum.checked_add(*v))
            .ok_or("policy input total overflows")?;
        let output_total = self.tx.outputs.iter().try_fold(0u64, |sum, o| sum.checked_add(o.value))
            .ok_or("policy output total overflows")?;
        input_total.checked_sub(output_total).ok_or("policy outputs exceed declared inputs")?;
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, String> {
        let file = SpendFile {
            network: match self.network { Network::Mainnet => "mainnet", Network::Testnet => "testnet" }.into(),
            policy: hex::encode(self.policy.encode()),
            tree: self.tree.as_ref().map(|(t, _)| hex::encode(t.encode())),
            branch: self.tree.as_ref().map(|(_, b)| *b),
            tx: hex::encode(self.tx.to_wire_bytes(true)),
            signatures: self.signatures.iter().map(|m| {
                m.iter().map(|(k, v)| (k.to_string(), hex::encode(v))).collect()
            }).collect(),
            amounts: self.amounts.iter().map(|v| v.to_string()).collect(),
        };
        serde_json::to_string_pretty(&file).map_err(|e| e.to_string())
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        let f: SpendFile = serde_json::from_str(s).map_err(|e| format!("spend file: {}", e))?;
        let network = match f.network.as_str() {
            "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            other => return Err(format!("unknown network {}", other)),
        };
        let policy = SpendPolicy::decode_under(&hex::decode(&f.policy).map_err(|_| "policy hex")?, TOOLING_RULES)
            .map_err(|e| format!("policy: {}", e))?;
        let tx = Transaction::from_wire_bytes(&hex::decode(&f.tx).map_err(|_| "tx hex")?)?;
        if f.signatures.len() != tx.inputs.len() {
            return Err("signature list does not match the inputs".into());
        }
        let mut signatures = Vec::with_capacity(f.signatures.len());
        for m in f.signatures {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                let k: u8 = k.parse().map_err(|_| "signature key index")?;
                if k as usize >= policy.pubkeys.len() {
                    return Err("signature key index out of range".into());
                }
                out.insert(k, hex::decode(&v).map_err(|_| "signature hex")?);
            }
            signatures.push(out);
        }
        let tree = match (f.tree, f.branch) {
            (Some(t), Some(b)) => {
                let tree = PolicyTree::decode_under(&hex::decode(&t).map_err(|_| "tree hex")?, TOOLING_RULES)
                    .map_err(|e| format!("tree: {}", e))?;
                if tree.branches.get(b as usize) != Some(&policy) {
                    return Err("policy is not the named branch of the tree".into());
                }
                Some((tree, b))
            }
            (None, None) => None,
            _ => return Err("tree and branch must come together".into()),
        };
        match &tree {
            // Single policy: the change output, if any, must return to it.
            None => {
                if let Some(change) = tx.outputs.get(1) {
                    if change.script_pubkey != policy.script_pubkey() {
                        return Err("change output does not return to the policy".into());
                    }
                }
            }
            // Tree: fixed outputs first; the last output, if it pays the tree, is change.
            Some(_) => {}
        }
        let amounts = f.amounts.iter()
            .map(|v| v.parse::<u64>().map_err(|_| "input value".to_string()))
            .collect::<Result<Vec<u64>, String>>()?;
        if !amounts.is_empty() && amounts.len() != tx.inputs.len() {
            return Err("input value list does not match the inputs".into());
        }
        Ok(Self { network, policy, tree, tx, signatures, amounts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(m: u8, n: usize, after: u32) -> (Vec<(Vec<u8>, Vec<u8>)>, SpendPolicy) {
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|_| crypto::generate_keypair()).collect();
        let policy = SpendPolicy::new(m, keys.iter().map(|k| k.0.clone()).collect(), after, 0).unwrap();
        (keys, policy)
    }

    #[test]
    fn two_of_three_flow_through_json_produces_a_valid_witness() {
        let (keys, policy) = setup(2, 3, 0);
        let spend = PolicySpend::new(Network::Testnet, policy.clone(), &[([1u8; 32], 0, 5_000_000)],
                                     vec![9u8; 20], 1_000_000, 0, 0).unwrap();
        // Signer 2, then signer 0, each on "their own machine" (via JSON).
        let mut s = PolicySpend::from_json(&spend.to_json().unwrap()).unwrap();
        assert_eq!(s.sign(&keys[2].0, |m| crypto::sign(&keys[2].1, m).map_err(|e| format!("{e:?}"))).unwrap(), 2);
        let mut s = PolicySpend::from_json(&s.to_json().unwrap()).unwrap();
        assert!(s.finalize().is_err(), "one signature is not enough");
        s.sign(&keys[0].0, |m| crypto::sign(&keys[0].1, m).map_err(|e| format!("{e:?}"))).unwrap();
        let tx = PolicySpend::from_json(&s.to_json().unwrap()).unwrap().finalize().unwrap();

        let w = PolicyWitness::decode(&tx.inputs[0].script_sig).unwrap();
        assert_eq!(w.policy, policy);
        assert_eq!(w.signatures.iter().map(|(k, _)| *k).collect::<Vec<_>>(), vec![0, 2]);
        // Change returns to the policy; fee covers the minimum for the real size.
        assert_eq!(tx.outputs[1].script_pubkey, policy.script_pubkey());
        let fee = 5_000_000 - tx.outputs.iter().map(|o| o.value).sum::<u64>();
        assert!(fee >= core::tokenomics::min_tx_fee_sat(tx.to_wire_bytes(true).len()));
    }

    fn signer(sk: &[u8]) -> impl Fn(&[u8; 32], SighashVersion) -> Result<Vec<u8>, String> + '_ {
        move |d, v| match v {
            SighashVersion::V2 => crypto::sign(sk, d),
            SighashVersion::V3 => crypto::sign_bound(sk, d),
        }.map_err(|e| format!("{e:?}"))
    }

    /// P5-S: a 2-of-2 of one hybrid and one conservative suite-0x0003 key.
    /// The tooling carries it through spend files, refuses to target it
    /// below the second hardening height or to sign it under sighash v2, and
    /// from the height builds a spend the consensus rules accept there and
    /// reject one block below.
    #[test]
    fn a_policy_with_a_conservative_key_spends_from_the_second_hardening_height() {
        let _act = core::activation::scoped_override(0);
        let _act2 = core::activation::scoped_override_v2(10);
        let (hpk, hsk) = crypto::generate_keypair();
        let (cpk, csk) = crypto::generate_conservative_keypair_from_seed_secret(&[0x42; 32]).unwrap();
        let keys = vec![hpk.clone(), cpk.clone()];
        assert!(SpendPolicy::new(2, keys.clone(), 0, 0).is_err(), "below the height such a policy is not valid");
        let policy = SpendPolicy::new_under(2, keys, 0, 0, crypto::SuiteRules::HARDENING2).unwrap();
        let spend = PolicySpend::new(Network::Testnet, policy.clone(), &[([1u8; 32], 0, 5_000_000)],
                                     vec![9u8; 20], 1_000_000, 0, 0).unwrap();
        let mut v1 = PolicySpend::from_json(&spend.to_json().unwrap()).unwrap();
        assert!(v1.sign_digest(&cpk, signer(&csk)).unwrap_err().contains("version-3"));
        let mut below = spend.clone();
        assert!(below.target_height(9).unwrap_err().contains("conservative"));
        let mut s = spend.clone();
        s.target_height(10).unwrap();
        assert_eq!(s.tx.version, 3);
        let mut s = PolicySpend::from_json(&s.to_json().unwrap()).unwrap();
        assert_eq!(s.sign_digest(&cpk, signer(&csk)).unwrap(), 1);
        let mut s = PolicySpend::from_json(&s.to_json().unwrap()).unwrap();
        assert_eq!(s.sign_digest(&hpk, signer(&hsk)).unwrap(), 0);
        let tx = PolicySpend::from_json(&s.to_json().unwrap()).unwrap().finalize().unwrap();
        let spent = [TxOutput { value: 5_000_000, script_pubkey: policy.script_pubkey() }];
        assert_eq!(core::sighash::verify_tx_scripts_at(&tx, &spent, ChainId::Testnet, 10, 0, 10), Ok(SighashVersion::V3));
        assert!(core::sighash::verify_tx_scripts_at(&tx, &spent, ChainId::Testnet, 9, 0, 10).is_err());
        assert!(tx.inputs[0].script_sig.len() <= max_witness_size(&policy));
        let fee = 5_000_000 - tx.outputs.iter().map(|o| o.value).sum::<u64>();
        assert!(fee >= core::tokenomics::min_tx_fee_sat(tx.to_wire_bytes(true).len()));
    }

    /// P5-S: where the second hardening is not scheduled no spend of a
    /// policy listing a conservative key is built.
    #[test]
    fn a_conservative_policy_is_refused_where_hardening2_is_not_scheduled() {
        let _act2 = core::activation::scoped_override_v2(core::activation::NEVER);
        let (cpk, _) = crypto::generate_conservative_keypair_from_seed_secret(&[0x42; 32]).unwrap();
        let policy = SpendPolicy::new_under(1, vec![cpk], 0, 0, crypto::SuiteRules::HARDENING2).unwrap();
        let err = PolicySpend::new(Network::Mainnet, policy, &[([1u8; 32], 0, 5_000_000)],
                                   vec![9u8; 20], 1_000_000, 0, 0).unwrap_err();
        assert!(err.contains("not scheduled"), "{err}");
    }

    #[test]
    fn an_outside_key_cannot_sign() {
        let (_keys, policy) = setup(1, 2, 0);
        let (pk, sk) = crypto::generate_keypair();
        let mut s = PolicySpend::new(Network::Mainnet, policy, &[([1u8; 32], 0, 5_000_000)],
                                     vec![9u8; 20], 1_000_000, 0, 0).unwrap();
        assert!(s.sign(&pk, |m| crypto::sign(&sk, m).map_err(|e| format!("{e:?}"))).is_err());
    }

    #[test]
    fn a_timelocked_policy_needs_a_matching_locktime() {
        let (_keys, policy) = setup(1, 1, 700);
        assert!(PolicySpend::new(Network::Mainnet, policy.clone(), &[([1u8; 32], 0, 5_000_000)],
                                 vec![9u8; 20], 1_000_000, 0, 699).is_err());
        assert!(PolicySpend::new(Network::Mainnet, policy, &[([1u8; 32], 0, 5_000_000)],
                                 vec![9u8; 20], 1_000_000, 0, 700).is_ok());
    }

    #[test]
    fn a_spend_file_with_redirected_change_is_refused() {
        let (_keys, policy) = setup(1, 2, 0);
        let s = PolicySpend::new(Network::Mainnet, policy, &[([1u8; 32], 0, 5_000_000)],
                                 vec![9u8; 20], 1_000_000, 0, 0).unwrap();
        let mut f: serde_json::Value = serde_json::from_str(&s.to_json().unwrap()).unwrap();
        let mut tx = s.tx.clone();
        tx.outputs[1].script_pubkey = vec![6u8; 20];
        f["tx"] = serde_json::Value::String(hex::encode(tx.to_wire_bytes(true)));
        assert!(PolicySpend::from_json(&f.to_string()).is_err());
    }

    #[test]
    fn pqpsbt_policy_signer_checks_all_amounts_before_the_signing_callback() {
        let (keys, policy) = setup(1, 1, 0);
        let mut spend = PolicySpend::new(Network::Mainnet, policy,
            &[([1; 32], 0, 5_000_000)], vec![9; 20], 1_000_000, 0, 0).unwrap();
        // The public object / imported coordinator file can contradict the
        // original constructor. No secret operation should run in that case.
        spend.amounts[0] = 1;
        let callbacks = std::cell::Cell::new(0);
        let result = spend.sign_digest(&keys[0].0, |digest, _| {
            callbacks.set(callbacks.get() + 1);
            crypto::sign(&keys[0].1, digest).map_err(|e| format!("{e:?}"))
        });
        assert_eq!(callbacks.get(), 0, "an inconsistent imported spend reached the signer");
        assert!(result.is_err());
    }
}
