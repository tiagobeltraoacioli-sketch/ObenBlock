//! Spend policies: m-of-n multisig with absolute and relative timelocks.
//!
//! GnB has no general script language, by design: a script interpreter is
//! the largest consensus attack surface Bitcoin has. Instead there are exactly
//! two output types:
//!
//! | `script_pubkey` | Spent by |
//! | --- | --- |
//! | 20 bytes: `SHA3-256(pubkey)[..20]` | one hybrid signature (`len‖sig‖len‖pk`) |
//! | 33 bytes: `0x02 ‖ SHA3-256("GNB-POLICY-v1" ‖ policy)` | a [`PolicyWitness`] revealing the policy and `threshold` signatures |
//!
//! A [`SpendPolicy`] is:
//!
//! - `threshold`-of-`pubkeys` hybrid ML-DSA-65 ‖ Falcon-1024 keys (1 ≤ m ≤ n ≤
//!   [`MAX_POLICY_KEYS`], keys distinct, each a hybrid key; from the second
//!   hardening upgrade distinct by [`key_identity`], not only by bytes, and
//!   each a hybrid key OR a conservative suite-0x0003 key, P5-S:
//!   [`SpendPolicy::decode_under`] with `crypto::SuiteRules`);
//! - `after`: absolute timelock — spendable only by a transaction whose
//!   `locktime ≥ after`, and a transaction is only valid in a block at height
//!   `≥ locktime`. `0` = none;
//! - `older`: relative timelock — spendable only `older` blocks after the
//!   output was confirmed. `0` = none.
//!
//! Encodings are canonical and strictly parsed (fixed field order, explicit
//! lengths, no trailing bytes), so one policy has exactly one hash and one
//! witness byte string per signature set.

use sha3::{Digest, Sha3_256};
use std::borrow::Cow;

/// The identity of a policy key (PF-4): its enveloped hybrid encoding.
///
/// A policy key is accepted in two encodings of the same key: the enveloped
/// hybrid key `B1 0C 01 00 ‖ mldsa_pk(1,952) ‖ falcon_pk(1,793)` (3,749
/// bytes, every current key) and the raw hybrid key `mldsa_pk ‖ falcon_pk`
/// (3,745 bytes) of a genesis carry-over wallet, told apart by their exact
/// lengths (`crypto::public_key_suite`). The sighash-v3 verifier
/// (`crypto::verify_bound`) accepts a signature under either encoding and
/// does not bind which one, so the two encodings are one signer:
///
/// ```text
/// key_identity(k) = k                   if len(k) = 3,749 (enveloped)
///                 = B1 0C 01 00 ‖ k     if len(k) = 3,745 (raw hybrid)
/// ```
///
/// (Any other length is not a policy key; it is returned unchanged.)
///
/// A conservative suite-0x0003 key (P5-S, from the second hardening height)
/// has ONE encoding, the enveloped `B1 0C 03 00 ‖ slh_pk ‖ falcon_pk` (1,829
/// bytes, `crypto::public_key_suite_under`: no raw form, no other length), so
/// its identity is itself; it never equals the identity of a hybrid key
/// (different length and suite header).
pub fn key_identity(key: &[u8]) -> Cow<'_, [u8]> {
    if key.len() == crate::crypto::legacy_hybrid_pubkey_len() {
        Cow::Owned(crate::crypto::wrap_envelope(crate::crypto::SUITE_MLDSA65_FALCON1024, key))
    } else {
        Cow::Borrowed(key)
    }
}

/// Maximum keys in one policy (a hybrid key is 3,749 bytes).
pub const MAX_POLICY_KEYS: usize = 7;

/// First byte of a policy `script_pubkey` and of a policy witness.
pub const POLICY_TAG: u8 = 0x02;

/// Length of a policy `script_pubkey`.
pub const POLICY_SPK_LEN: usize = 33;

/// Length of a single-key (P2PKH-style) `script_pubkey`.
pub const PKH_SPK_LEN: usize = 20;

/// Policy encoding version.
const POLICY_VERSION: u8 = 1;
const POLICY_DOMAIN: &[u8] = b"GNB-POLICY-v1";

/// Upper bound on one encoded signature (hybrid ML-DSA-65 ‖ Falcon-1024,
/// enveloped, with Falcon's variable length): generous, rejects absurd input.
/// The bound of every height below the second hardening upgrade.
const MAX_SIG_LEN: usize = 8 * 1024;
/// P5-S: the per-signature bound from the second hardening height, where a
/// policy signature may be a conservative suite-0x0003 signature (at most
/// `crypto::CONSERVATIVE_MAX_SIGNATURE_LEN` = 9,322 bytes): generous like
/// [`MAX_SIG_LEN`]. The witness as a whole stays within
/// [`MAX_POLICY_WITNESS_LEN`], the wire parser's cap, which is unchanged.
const MAX_SIG_LEN_HARDENING2: usize = 10 * 1024;
/// Upper bound on one encoded public key.
const MAX_PK_LEN: usize = 8 * 1024;

/// The per-signature bound of `rules` ([`MAX_SIG_LEN`] below the second
/// hardening height, [`MAX_SIG_LEN_HARDENING2`] from it).
const fn max_sig_len(rules: SuiteRules) -> usize {
    if rules.conservative_suite() { MAX_SIG_LEN_HARDENING2 } else { MAX_SIG_LEN }
}

/// Largest policy witness the wire parser carries (`core::MAX_SCRIPT_SIG_LEN`):
/// tag, policy length and the largest policy (`version ‖ m ‖ n`,
/// `MAX_POLICY_KEYS` keys of [`MAX_PK_LEN`], `after`, `older`), signature
/// count, then `MAX_POLICY_KEYS` × (index, length, [`MAX_SIG_LEN`]-byte
/// signature), plus a branch witness's extra fields. The transaction decoder
/// must carry any `script_sig` up to this size, or valid policy spends (a
/// 2-of-3 is about 20 KB) cannot be relayed. The value (114,834 bytes) is
/// part of the wire format and does not move with the hardening-2 signature
/// bound: the largest VALID witness of any height, a 7-of-7 conservative
/// branch witness (about 78 kB), fits well within it
/// (`tests::every_valid_policy_witness_fits_the_wire_cap`).
pub const MAX_POLICY_WITNESS_LEN: usize = 1 + 4
    + (3 + MAX_POLICY_KEYS * (4 + MAX_PK_LEN) + 8)
    + 1 + MAX_POLICY_KEYS * (1 + 4 + MAX_SIG_LEN)
    // a branch witness adds n_branches, index and a 2-level Merkle path
    + 2 + 2 * 32;

use crate::crypto::SuiteRules;

/// The two output types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// Single hybrid key, 20-byte hash.
    PubkeyHash,
    /// Spend policy, 32-byte hash.
    Policy,
}

/// Classify a `script_pubkey`; `None` for anything else (not a valid output).
pub fn output_kind(script_pubkey: &[u8]) -> Option<OutputKind> {
    match script_pubkey.len() {
        PKH_SPK_LEN => Some(OutputKind::PubkeyHash),
        POLICY_SPK_LEN if script_pubkey[0] == POLICY_TAG => Some(OutputKind::Policy),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    BadVersion,
    BadThreshold,
    TooManyKeys,
    DuplicateKey,
    NotHybridKey(usize),
    Truncated,
    TrailingBytes,
    TooLarge,
    BadTag,
    WrongSignatureCount { got: usize, want: usize },
    BadBranchCount,
    KeyIndexOrder,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An m-of-n multisig with optional absolute and relative timelocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendPolicy {
    pub threshold: u8,
    pub pubkeys: Vec<Vec<u8>>,
    /// Absolute timelock (block height); 0 = none.
    pub after: u32,
    /// Relative timelock (blocks since the output confirmed); 0 = none.
    pub older: u32,
}

impl SpendPolicy {
    /// Build and validate a policy (wallets, CLIs, the bridge vault: every
    /// tool that CREATES a policy). Besides the consensus checks of
    /// [`Self::decode`] it refuses, at every height, two keys with the same
    /// [`key_identity`] (PF-4): such a policy names one signer twice, and
    /// from the second hardening upgrade it can no longer be spent.
    pub fn new(threshold: u8, pubkeys: Vec<Vec<u8>>, after: u32, older: u32) -> Result<Self, PolicyError> {
        Self::new_under(threshold, pubkeys, after, older, SuiteRules::LEGACY)
    }

    /// [`Self::new`] for a policy whose spends are valid under `rules` (P5-S:
    /// with [`SuiteRules::HARDENING2`] the keys may also be conservative
    /// suite-0x0003 keys). Tooling passes the rules of the height its
    /// producer targets (`crypto::KeySuite::check_allowed_at`), so no tool
    /// creates an output whose keys cannot sign yet.
    pub fn new_under(
        threshold: u8,
        pubkeys: Vec<Vec<u8>>,
        after: u32,
        older: u32,
        rules: SuiteRules,
    ) -> Result<Self, PolicyError> {
        let p = Self { threshold, pubkeys, after, older };
        p.check_under(rules)?;
        p.check_key_identities()?;
        Ok(p)
    }

    /// Whether any key is a conservative suite-0x0003 key (P5-S).
    pub fn has_conservative_key(&self) -> bool {
        self.pubkeys.iter().any(|k| crate::crypto::is_conservative_public_key(k))
    }

    /// PF-4: [`PolicyError::DuplicateKey`] when two keys have the same
    /// [`key_identity`] (the raw and the enveloped encoding of one key).
    ///
    /// The byte-wise distinctness of [`Self::decode`] let a policy list one
    /// key twice, once raw and once enveloped; under sighash v3 one signer
    /// then fills both slots, so an "m-of-n" whose participants see n
    /// distinct keys is spendable with fewer signers. Consensus from the
    /// second hardening height (`activation::hardening2_*`, applied by the
    /// node's policy-spend rule `blockval::check_policy_spends_with_confirmations`
    /// to the revealed policy or branch); [`Self::new`] at every height.
    /// Bitcoin Core's analogue: one encoding per key in a script context
    /// (compressed-only keys in segwit v0 standardness, BIP340 x-only keys in
    /// tapscript) and miniscript's duplicate-key sanity check.
    pub fn check_key_identities(&self) -> Result<(), PolicyError> {
        let ids: Vec<Cow<'_, [u8]>> = self.pubkeys.iter().map(|k| key_identity(k)).collect();
        for (i, id) in ids.iter().enumerate() {
            if ids[..i].contains(id) {
                return Err(PolicyError::DuplicateKey);
            }
        }
        Ok(())
    }

    /// The consensus checks of a policy under `rules`: threshold range, key
    /// count, policy keys (hybrid; from the second hardening height also
    /// conservative, `crypto::is_policy_key_under`), byte-wise distinct keys.
    /// (The identity rule, [`Self::check_key_identities`], is height-gated
    /// and not part of it.) Under [`SuiteRules::LEGACY`] exactly the check of
    /// every earlier release (a non-hybrid key is `NotHybridKey`).
    fn check_under(&self, rules: SuiteRules) -> Result<(), PolicyError> {
        let n = self.pubkeys.len();
        if n > MAX_POLICY_KEYS {
            return Err(PolicyError::TooManyKeys);
        }
        if self.threshold == 0 || self.threshold as usize > n {
            return Err(PolicyError::BadThreshold);
        }
        for (i, k) in self.pubkeys.iter().enumerate() {
            if !crate::crypto::is_policy_key_under(k, rules) {
                return Err(PolicyError::NotHybridKey(i));
            }
            if self.pubkeys[..i].contains(k) {
                return Err(PolicyError::DuplicateKey);
            }
        }
        Ok(())
    }

    /// Canonical encoding: `version ‖ m ‖ n ‖ (u32le len ‖ key)* ‖ after u32le ‖ older u32le`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![POLICY_VERSION, self.threshold, self.pubkeys.len() as u8];
        for k in &self.pubkeys {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.after.to_le_bytes());
        out.extend_from_slice(&self.older.to_le_bytes());
        out
    }

    /// Strict decoding of [`encode`](Self::encode); validates the policy
    /// under the rules below the second hardening height
    /// ([`Self::decode_under`] with [`SuiteRules::LEGACY`]: hybrid keys only).
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        Self::decode_under(bytes, SuiteRules::LEGACY)
    }

    /// Strict decoding of [`encode`](Self::encode); validates the policy
    /// under `rules` (the consensus rules of the spending block's height,
    /// `core::sighash::suite_rules_at`).
    pub fn decode_under(bytes: &[u8], rules: SuiteRules) -> Result<Self, PolicyError> {
        let mut r = Reader(bytes);
        if r.u8()? != POLICY_VERSION {
            return Err(PolicyError::BadVersion);
        }
        let threshold = r.u8()?;
        let n = r.u8()? as usize;
        if n > MAX_POLICY_KEYS {
            return Err(PolicyError::TooManyKeys);
        }
        let mut pubkeys = Vec::with_capacity(n);
        for _ in 0..n {
            pubkeys.push(r.bytes(MAX_PK_LEN)?.to_vec());
        }
        let after = r.u32()?;
        let older = r.u32()?;
        r.end()?;
        // Consensus decoding: the checks of every height only. The PF-4
        // identity rule is applied by the spend rule from its activation
        // height, so a revealed policy below it decodes exactly as before.
        let p = Self { threshold, pubkeys, after, older };
        p.check_under(rules)?;
        Ok(p)
    }

    /// `SHA3-256("GNB-POLICY-v1" ‖ encode())`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(POLICY_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }

    /// The 33-byte output script paying to this policy.
    pub fn script_pubkey(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(POLICY_SPK_LEN);
        s.push(POLICY_TAG);
        s.extend_from_slice(&self.hash());
        s
    }
}

/// The `script_sig` of an input spending a policy output: the policy itself
/// and exactly `threshold` signatures, each tagged with the index of its key,
/// indices strictly increasing.
///
/// Encoding: `0x02 ‖ u32le len ‖ policy ‖ u8 count ‖ (u8 index ‖ u32le len ‖ sig)*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWitness {
    pub policy: SpendPolicy,
    /// `(key index, signature)`, strictly increasing indices.
    pub signatures: Vec<(u8, Vec<u8>)>,
}

impl PolicyWitness {
    pub fn encode(&self) -> Vec<u8> {
        let policy = self.policy.encode();
        let mut out = vec![POLICY_TAG];
        out.extend_from_slice(&(policy.len() as u32).to_le_bytes());
        out.extend_from_slice(&policy);
        out.push(self.signatures.len() as u8);
        for (idx, sig) in &self.signatures {
            out.push(*idx);
            out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            out.extend_from_slice(sig);
        }
        out
    }

    /// Strict decoding: valid policy, exactly `threshold` signatures,
    /// strictly increasing in-range key indices, no trailing bytes; under the
    /// rules below the second hardening height ([`Self::decode_under`] with
    /// [`SuiteRules::LEGACY`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        Self::decode_under(bytes, SuiteRules::LEGACY)
    }

    /// [`Self::decode`] under `rules`: the policy's keys are checked with
    /// [`SpendPolicy::decode_under`] and each signature may be up to the
    /// rules' bound (8 KiB, from the second hardening height 10 KiB for the
    /// conservative suite's 9,322-byte signatures).
    pub fn decode_under(bytes: &[u8], rules: SuiteRules) -> Result<Self, PolicyError> {
        let mut r = Reader(bytes);
        if r.u8()? != POLICY_TAG {
            return Err(PolicyError::BadTag);
        }
        let policy = SpendPolicy::decode_under(r.bytes(MAX_POLICY_KEYS * (MAX_PK_LEN + 4) + 16)?, rules)?;
        let count = r.u8()? as usize;
        if count != policy.threshold as usize {
            return Err(PolicyError::WrongSignatureCount { got: count, want: policy.threshold as usize });
        }
        let mut signatures = Vec::with_capacity(count);
        let mut prev: Option<u8> = None;
        for _ in 0..count {
            let idx = r.u8()?;
            if idx as usize >= policy.pubkeys.len() || prev.is_some_and(|p| idx <= p) {
                return Err(PolicyError::KeyIndexOrder);
            }
            prev = Some(idx);
            signatures.push((idx, r.bytes(max_sig_len(rules))?.to_vec()));
        }
        r.end()?;
        Ok(Self { policy, signatures })
    }
}

// ── Policy trees (version 2): alternative branches ───────────────────────────
//
// A policy tree commits to 2..=4 alternative branches, each an ordinary
// [`SpendPolicy`] (m-of-n plus its own timelocks), through a Merkle root:
//
//   leaf_i      = SHA3("GNB-POLICY-v2/leaf" ‖ branch_i.encode())
//   empty leaf  = SHA3("GNB-POLICY-v2/empty")          (pads to a power of two)
//   node        = SHA3("GNB-POLICY-v2/node" ‖ left ‖ right)
//   commitment  = 0x02 ‖ u8(n_branches) ‖ root           (never a v1 encoding: those start 0x01)
//   script      = 0x02 ‖ SHA3("GNB-POLICY-v1" ‖ commitment)   (the same 33-byte output type)
//
// A spend reveals ONE branch, its index and its Merkle path ([`BranchWitness`]);
// the other branches (e.g. a cold recovery quorum) stay private. Consensus
// from `core::powit_height()` (off on mainnet): before it a branch witness is
// invalid and policy-tree outputs, though creatable, cannot be spent.

/// Most branches a tree may have.
pub const MAX_POLICY_BRANCHES: usize = 4;
const TREE_VERSION: u8 = 2;
/// Witness tag of a branch spend (a v1 policy witness starts with 0x02).
pub const BRANCH_WITNESS_TAG: u8 = 0x03;

fn tree_leaf(branch: &SpendPolicy) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"GNB-POLICY-v2/leaf");
    h.update(branch.encode());
    h.finalize().into()
}

fn tree_empty() -> [u8; 32] {
    Sha3_256::digest(b"GNB-POLICY-v2/empty").into()
}

fn tree_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"GNB-POLICY-v2/node");
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn tree_depth(n: usize) -> usize {
    if n <= 2 { 1 } else { 2 }
}

fn commitment_script(n: usize, root: &[u8; 32]) -> Vec<u8> {
    let mut c = vec![TREE_VERSION, n as u8];
    c.extend_from_slice(root);
    let mut h = Sha3_256::new();
    h.update(POLICY_DOMAIN);
    h.update(&c);
    let mut s = Vec::with_capacity(POLICY_SPK_LEN);
    s.push(POLICY_TAG);
    s.extend_from_slice(&h.finalize());
    s
}

fn fold_path(leaf: [u8; 32], index: usize, path: &[[u8; 32]]) -> [u8; 32] {
    let mut node = leaf;
    let mut i = index;
    for sib in path {
        node = if i & 1 == 0 { tree_node(&node, sib) } else { tree_node(sib, &node) };
        i >>= 1;
    }
    node
}

/// 2..=4 alternative spend branches under one output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTree {
    pub branches: Vec<SpendPolicy>,
}

impl PolicyTree {
    pub fn new(branches: Vec<SpendPolicy>) -> Result<Self, PolicyError> {
        if branches.len() < 2 || branches.len() > MAX_POLICY_BRANCHES {
            return Err(PolicyError::BadBranchCount);
        }
        Ok(PolicyTree { branches })
    }

    fn leaves(&self) -> Vec<[u8; 32]> {
        let width = 1usize << tree_depth(self.branches.len());
        let mut v: Vec<[u8; 32]> = self.branches.iter().map(tree_leaf).collect();
        v.resize(width, tree_empty());
        v
    }

    pub fn root(&self) -> [u8; 32] {
        let mut level = self.leaves();
        while level.len() > 1 {
            level = level.chunks(2).map(|c| tree_node(&c[0], &c[1])).collect();
        }
        level[0]
    }

    /// The 33-byte output script (same type as a single policy).
    pub fn script_pubkey(&self) -> Vec<u8> {
        commitment_script(self.branches.len(), &self.root())
    }

    /// Merkle path of branch `index`.
    pub fn path(&self, index: usize) -> Vec<[u8; 32]> {
        let mut level = self.leaves();
        let mut i = index;
        let mut path = Vec::new();
        while level.len() > 1 {
            path.push(level[i ^ 1]);
            level = level.chunks(2).map(|c| tree_node(&c[0], &c[1])).collect();
            i >>= 1;
        }
        path
    }

    /// Canonical encoding for tools (not consensus): `0x02 ‖ n ‖ (u32 len ‖ branch)*`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TREE_VERSION, self.branches.len() as u8];
        for b in &self.branches {
            let e = b.encode();
            out.extend_from_slice(&(e.len() as u32).to_le_bytes());
            out.extend_from_slice(&e);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        Self::decode_under(bytes, SuiteRules::LEGACY)
    }

    /// [`Self::decode`] with every branch decoded under `rules`
    /// ([`SpendPolicy::decode_under`]).
    pub fn decode_under(bytes: &[u8], rules: SuiteRules) -> Result<Self, PolicyError> {
        let mut r = Reader(bytes);
        if r.u8()? != TREE_VERSION {
            return Err(PolicyError::BadVersion);
        }
        let n = r.u8()? as usize;
        if !(2..=MAX_POLICY_BRANCHES).contains(&n) {
            return Err(PolicyError::BadBranchCount);
        }
        let mut branches = Vec::with_capacity(n);
        for _ in 0..n {
            branches.push(SpendPolicy::decode_under(r.bytes(MAX_POLICY_KEYS * (MAX_PK_LEN + 4) + 16)?, rules)?);
        }
        r.end()?;
        Self::new(branches)
    }
}

/// `script_sig` spending a policy-tree output through one branch.
///
/// Encoding: `0x03 ‖ u8 n_branches ‖ u8 index ‖ path (depth × 32) ‖ u32le len ‖ branch policy
/// ‖ u8 count ‖ (u8 key index ‖ u32le len ‖ sig)*`, exactly `threshold` signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchWitness {
    pub n_branches: u8,
    pub index: u8,
    pub path: Vec<[u8; 32]>,
    pub branch: SpendPolicy,
    pub signatures: Vec<(u8, Vec<u8>)>,
}

impl BranchWitness {
    /// The output script this witness opens.
    pub fn script_pubkey(&self) -> Vec<u8> {
        let root = fold_path(tree_leaf(&self.branch), self.index as usize, &self.path);
        commitment_script(self.n_branches as usize, &root)
    }

    pub fn encode(&self) -> Vec<u8> {
        let branch = self.branch.encode();
        let mut out = vec![BRANCH_WITNESS_TAG, self.n_branches, self.index];
        for n in &self.path {
            out.extend_from_slice(n);
        }
        out.extend_from_slice(&(branch.len() as u32).to_le_bytes());
        out.extend_from_slice(&branch);
        out.push(self.signatures.len() as u8);
        for (idx, sig) in &self.signatures {
            out.push(*idx);
            out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            out.extend_from_slice(sig);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        Self::decode_under(bytes, SuiteRules::LEGACY)
    }

    /// [`Self::decode`] under `rules` (the branch's keys, the signature
    /// bound; see [`PolicyWitness::decode_under`]).
    pub fn decode_under(bytes: &[u8], rules: SuiteRules) -> Result<Self, PolicyError> {
        let mut r = Reader(bytes);
        if r.u8()? != BRANCH_WITNESS_TAG {
            return Err(PolicyError::BadTag);
        }
        let n_branches = r.u8()?;
        if !(2..=MAX_POLICY_BRANCHES).contains(&(n_branches as usize)) {
            return Err(PolicyError::BadBranchCount);
        }
        let index = r.u8()?;
        if index >= n_branches {
            return Err(PolicyError::BadBranchCount);
        }
        let mut path = Vec::new();
        for _ in 0..tree_depth(n_branches as usize) {
            path.push(r.take(32)?.try_into().expect("32 bytes"));
        }
        let branch = SpendPolicy::decode_under(r.bytes(MAX_POLICY_KEYS * (MAX_PK_LEN + 4) + 16)?, rules)?;
        let count = r.u8()? as usize;
        if count != branch.threshold as usize {
            return Err(PolicyError::WrongSignatureCount { got: count, want: branch.threshold as usize });
        }
        let mut signatures = Vec::with_capacity(count);
        let mut prev: Option<u8> = None;
        for _ in 0..count {
            let idx = r.u8()?;
            if idx as usize >= branch.pubkeys.len() || prev.is_some_and(|p| idx <= p) {
                return Err(PolicyError::KeyIndexOrder);
            }
            prev = Some(idx);
            signatures.push((idx, r.bytes(max_sig_len(rules))?.to_vec()));
        }
        r.end()?;
        Ok(Self { n_branches, index, path, branch, signatures })
    }
}

/// Either kind of policy spend, told apart by the first byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyPolicyWitness {
    Single(PolicyWitness),
    Branch(BranchWitness),
}

impl AnyPolicyWitness {
    /// Decode under the rules below the second hardening height
    /// ([`Self::decode_under`] with [`SuiteRules::LEGACY`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        Self::decode_under(bytes, SuiteRules::LEGACY)
    }

    /// Decode under `rules` (P5-S: the consensus callers pass the rules of
    /// the spending block's height, `core::sighash::suite_rules_at`).
    pub fn decode_under(bytes: &[u8], rules: SuiteRules) -> Result<Self, PolicyError> {
        match bytes.first() {
            Some(&POLICY_TAG) => PolicyWitness::decode_under(bytes, rules).map(AnyPolicyWitness::Single),
            Some(&BRANCH_WITNESS_TAG) => BranchWitness::decode_under(bytes, rules).map(AnyPolicyWitness::Branch),
            _ => Err(PolicyError::BadTag),
        }
    }

    /// The policy whose keys and timelocks govern this spend.
    pub fn policy(&self) -> &SpendPolicy {
        match self {
            AnyPolicyWitness::Single(w) => &w.policy,
            AnyPolicyWitness::Branch(w) => &w.branch,
        }
    }

    pub fn signatures(&self) -> &[(u8, Vec<u8>)] {
        match self {
            AnyPolicyWitness::Single(w) => &w.signatures,
            AnyPolicyWitness::Branch(w) => &w.signatures,
        }
    }

    pub fn script_pubkey(&self) -> Vec<u8> {
        match self {
            AnyPolicyWitness::Single(w) => w.policy.script_pubkey(),
            AnyPolicyWitness::Branch(w) => w.script_pubkey(),
        }
    }

    pub fn is_branch(&self) -> bool {
        matches!(self, AnyPolicyWitness::Branch(_))
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PolicyError> {
        if self.0.len() < n {
            return Err(PolicyError::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, PolicyError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, PolicyError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8], PolicyError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(PolicyError::TooLarge);
        }
        self.take(len)
    }
    fn end(&self) -> Result<(), PolicyError> {
        if self.0.is_empty() { Ok(()) } else { Err(PolicyError::TrailingBytes) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|_| crate::crypto::generate_keypair().0).collect()
    }

    #[test]
    fn policy_roundtrips_and_hash_is_stable() {
        let p = SpendPolicy::new(2, keys(3), 1_000, 144).unwrap();
        let back = SpendPolicy::decode(&p.encode()).unwrap();
        assert_eq!(p, back);
        assert_eq!(p.hash(), back.hash());
        let spk = p.script_pubkey();
        assert_eq!(spk.len(), POLICY_SPK_LEN);
        assert_eq!(output_kind(&spk), Some(OutputKind::Policy));
        assert_eq!(output_kind(&[7u8; 20]), Some(OutputKind::PubkeyHash));
        assert_eq!(output_kind(&[7u8; 32]), None);
        assert_eq!(output_kind(&{ let mut s = spk.clone(); s[0] = 0x03; s }), None);
    }

    #[test]
    fn any_field_change_changes_the_hash() {
        let k = keys(3);
        let base = SpendPolicy::new(2, k.clone(), 0, 0).unwrap().hash();
        assert_ne!(base, SpendPolicy::new(3, k.clone(), 0, 0).unwrap().hash());
        assert_ne!(base, SpendPolicy::new(2, k.clone(), 1, 0).unwrap().hash());
        assert_ne!(base, SpendPolicy::new(2, k.clone(), 0, 1).unwrap().hash());
        let mut swapped = k.clone();
        swapped.swap(0, 1);
        assert_ne!(base, SpendPolicy::new(2, swapped, 0, 0).unwrap().hash(), "key order is committed");
    }

    #[test]
    fn invalid_policies_are_refused() {
        let k = keys(MAX_POLICY_KEYS + 1);
        assert_eq!(SpendPolicy::new(0, k[..2].to_vec(), 0, 0), Err(PolicyError::BadThreshold));
        assert_eq!(SpendPolicy::new(3, k[..2].to_vec(), 0, 0), Err(PolicyError::BadThreshold));
        assert_eq!(SpendPolicy::new(1, k.clone(), 0, 0), Err(PolicyError::TooManyKeys));
        assert_eq!(SpendPolicy::new(1, vec![k[0].clone(), k[0].clone()], 0, 0), Err(PolicyError::DuplicateKey));
        let mut short = k[0].clone();
        short.truncate(short.len() - 1793); // ML-DSA half only
        assert_eq!(SpendPolicy::new(1, vec![short], 0, 0), Err(PolicyError::NotHybridKey(0)));
    }

    /// PF-4 golden vectors: the identity of the raw encoding of a key is its
    /// enveloped encoding (`B1 0C 01 00 ‖ raw`), the enveloped one is itself;
    /// consensus decoding keeps the byte-wise rule of every height while the
    /// tooling constructor and the hardening-2 rule refuse the twin.
    #[test]
    fn key_identity_vectors_and_the_twin_encoding_policy() {
        let (pk, _) = crate::crypto::generate_keypair_from_seed(&[0x42; 32]).unwrap();
        assert_eq!(pk.len(), 3_749);
        assert_eq!(pk[..4], [0xB1, 0x0C, 0x01, 0x00]);
        let raw = pk[4..].to_vec();
        assert_eq!(raw.len(), 3_745);
        assert_eq!(&*key_identity(&raw), pk.as_slice());
        assert!(matches!(key_identity(&pk), Cow::Borrowed(k) if k == pk.as_slice()));
        assert!(matches!(key_identity(b"short"), Cow::Borrowed(b"short")));
        // Pinned: SHA3-256 of the identity of the seed-0x42 hybrid key.
        assert_eq!(hex::encode(Sha3_256::digest(&*key_identity(&raw))), PIN_IDENTITY_SHA3);

        let twin = SpendPolicy { threshold: 2, pubkeys: vec![raw.clone(), pk.clone()], after: 0, older: 0 };
        // Consensus decoding (every height): unchanged, the bytes differ.
        assert_eq!(SpendPolicy::decode(&twin.encode()), Ok(twin.clone()));
        // Pinned: the policy hash of that twin policy (its encoding).
        assert_eq!(hex::encode(twin.hash()), PIN_TWIN_POLICY_HASH);
        // The identity rule refuses it, in either order.
        assert_eq!(twin.check_key_identities(), Err(PolicyError::DuplicateKey));
        let swapped = SpendPolicy { pubkeys: vec![pk.clone(), raw.clone()], ..twin.clone() };
        assert_eq!(swapped.check_key_identities(), Err(PolicyError::DuplicateKey));
        assert_eq!(SpendPolicy::new(2, twin.pubkeys.clone(), 0, 0), Err(PolicyError::DuplicateKey));
        assert_eq!(SpendPolicy::new(1, vec![pk.clone(), raw.clone()], 0, 0), Err(PolicyError::DuplicateKey));
        // A raw key next to another key is fine.
        let (other, _) = crate::crypto::generate_keypair_from_seed(&[0x43; 32]).unwrap();
        assert!(SpendPolicy::new(2, vec![raw.clone(), other.clone()], 0, 0).is_ok());
        assert_eq!(SpendPolicy { threshold: 2, pubkeys: vec![raw, other], after: 0, older: 0 }
            .check_key_identities(), Ok(()));
    }

    const PIN_IDENTITY_SHA3: &str = "2aeeb67335c518247b6a7c92dbe857f3a72e7806609a2c179ce87aa95de2ccd8";
    const PIN_TWIN_POLICY_HASH: &str = "f27d1c6e16aaa5eda18ef3372bd38e56397f8f857b62f8cdaa82d34742dbaf6f";

    #[test]
    fn decoding_is_strict() {
        let p = SpendPolicy::new(1, keys(2), 5, 6).unwrap();
        let mut b = p.encode();
        b.push(0);
        assert_eq!(SpendPolicy::decode(&b), Err(PolicyError::TrailingBytes));
        let b = p.encode();
        assert_eq!(SpendPolicy::decode(&b[..b.len() - 1]), Err(PolicyError::Truncated));
        let mut b = p.encode();
        b[0] = 9;
        assert_eq!(SpendPolicy::decode(&b), Err(PolicyError::BadVersion));
    }

    #[test]
    fn witness_requires_exactly_threshold_sigs_in_increasing_order() {
        let p = SpendPolicy::new(2, keys(3), 0, 0).unwrap();
        let w = |sigs: Vec<(u8, Vec<u8>)>| PolicyWitness { policy: p.clone(), signatures: sigs }.encode();
        assert!(PolicyWitness::decode(&w(vec![(0, vec![1]), (2, vec![2])])).is_ok());
        assert!(matches!(PolicyWitness::decode(&w(vec![(0, vec![1])])),
                         Err(PolicyError::WrongSignatureCount { got: 1, want: 2 })));
        assert!(matches!(PolicyWitness::decode(&w(vec![(0, vec![1]), (1, vec![1]), (2, vec![1])])),
                         Err(PolicyError::WrongSignatureCount { .. })));
        assert_eq!(PolicyWitness::decode(&w(vec![(2, vec![1]), (0, vec![2])])), Err(PolicyError::KeyIndexOrder));
        assert_eq!(PolicyWitness::decode(&w(vec![(1, vec![1]), (1, vec![2])])), Err(PolicyError::KeyIndexOrder));
        assert_eq!(PolicyWitness::decode(&w(vec![(0, vec![1]), (3, vec![2])])), Err(PolicyError::KeyIndexOrder));
        let mut b = w(vec![(0, vec![1]), (2, vec![2])]);
        b.push(0);
        assert_eq!(PolicyWitness::decode(&b), Err(PolicyError::TrailingBytes));
    }

    #[test]
    fn policy_tree_roundtrips_and_commits_to_every_branch() {
        let b0 = SpendPolicy::new(2, keys(3), 0, 0).unwrap();
        let b1 = SpendPolicy::new(1, keys(2), 0, 1_000).unwrap();
        let b2 = SpendPolicy::new(1, keys(1), 5_000, 0).unwrap();
        let t2 = PolicyTree::new(vec![b0.clone(), b1.clone()]).unwrap();
        let t3 = PolicyTree::new(vec![b0.clone(), b1.clone(), b2.clone()]).unwrap();
        assert_eq!(PolicyTree::decode(&t3.encode()).unwrap(), t3);
        assert_ne!(t2.script_pubkey(), t3.script_pubkey(), "branch count is committed");
        assert_ne!(t2.script_pubkey(), b0.script_pubkey(), "a tree is never a single policy");
        assert_eq!(output_kind(&t3.script_pubkey()), Some(OutputKind::Policy));
        // Every branch's witness opens the same output.
        for (i, b) in t3.branches.iter().enumerate() {
            let w = BranchWitness { n_branches: 3, index: i as u8, path: t3.path(i), branch: b.clone(),
                                    signatures: (0..b.threshold).map(|k| (k, vec![1])).collect() };
            assert_eq!(w.script_pubkey(), t3.script_pubkey(), "branch {i}");
            assert_eq!(BranchWitness::decode(&w.encode()).unwrap(), w);
            assert!(AnyPolicyWitness::decode(&w.encode()).unwrap().is_branch());
        }
        // Swapping branch order changes the output.
        let swapped = PolicyTree::new(vec![b1, b0]).unwrap();
        assert_ne!(swapped.script_pubkey(), t2.script_pubkey());
    }

    #[test]
    fn policy_tree_limits_and_strict_witnesses() {
        let b = || SpendPolicy::new(1, keys(1), 0, 0).unwrap();
        assert_eq!(PolicyTree::new(vec![b()]), Err(PolicyError::BadBranchCount));
        assert_eq!(PolicyTree::new(vec![b(), b(), b(), b(), b()]), Err(PolicyError::BadBranchCount));
        let t = PolicyTree::new(vec![b(), b()]).unwrap();
        let w = BranchWitness { n_branches: 2, index: 0, path: t.path(0), branch: t.branches[0].clone(),
                                signatures: vec![(0, vec![1])] };
        let mut bad = w.encode();
        bad.push(0);
        assert_eq!(BranchWitness::decode(&bad), Err(PolicyError::TrailingBytes));
        let mut bad = w.encode();
        bad[2] = 2; // index out of range for 2 branches
        assert_eq!(BranchWitness::decode(&bad), Err(PolicyError::BadBranchCount));
        let mut bad = w.encode();
        bad[1] = 9;
        assert_eq!(BranchWitness::decode(&bad), Err(PolicyError::BadBranchCount));
        assert_eq!(AnyPolicyWitness::decode(&[0x07]), Err(PolicyError::BadTag));
    }

    // ── P5-S: conservative suite-0x0003 keys ────────────────────────────────

    fn conservative_key(seed: u8) -> Vec<u8> {
        crate::crypto::generate_conservative_keypair_from_seed_secret(&[seed; 32]).unwrap().0
    }

    /// The wire parser's cap (`MAX_POLICY_WITNESS_LEN`, part of the wire
    /// format) is unchanged by the hardening-2 signature bound, and the
    /// largest VALID witness of any height fits in it: a 7-of-7 branch witness
    /// over conservative keys with maximal (9,322-byte) signatures, and over
    /// hybrid keys with maximal signatures.
    #[test]
    fn every_valid_policy_witness_fits_the_wire_cap() {
        assert_eq!(MAX_POLICY_WITNESS_LEN, 114_834, "the wire cap is part of the wire format");
        assert_eq!(crate::core::MAX_SCRIPT_SIG_LEN, MAX_POLICY_WITNESS_LEN);
        let worst = |key_len: usize, sig_len: usize| {
            let policy = 3 + MAX_POLICY_KEYS * (4 + key_len) + 8;
            1 + 4 + policy + 1 + MAX_POLICY_KEYS * (1 + 4 + sig_len) + 2 + 2 * 32
        };
        let conservative = worst(crate::crypto::CONSERVATIVE_PUBLIC_KEY_LEN, crate::crypto::CONSERVATIVE_MAX_SIGNATURE_LEN);
        let hybrid = worst(crate::crypto::HYBRID_PUBLIC_KEY_LEN, crate::crypto::max_signature_len());
        assert!(conservative <= MAX_POLICY_WITNESS_LEN, "{conservative}");
        assert!(hybrid <= MAX_POLICY_WITNESS_LEN, "{hybrid}");
        assert!(crate::crypto::CONSERVATIVE_MAX_SIGNATURE_LEN <= MAX_SIG_LEN_HARDENING2);
        assert!(crate::crypto::max_signature_len() <= MAX_SIG_LEN);
    }

    /// Below the second hardening height (`SuiteRules::LEGACY`, also
    /// `decode`) a conservative key is not a policy key (`NotHybridKey`,
    /// the old verdict) and a signature over 8 KiB is `TooLarge`; from it
    /// both decode. Tooling (`new` / `new_under`) follows the same rules.
    #[test]
    fn conservative_keys_and_signatures_decode_from_hardening2_only() {
        let (c, h) = (conservative_key(0x71), keys(1).remove(0));
        let p = SpendPolicy { threshold: 1, pubkeys: vec![h.clone(), c.clone()], after: 0, older: 0 };
        assert_eq!(SpendPolicy::decode(&p.encode()), Err(PolicyError::NotHybridKey(1)));
        assert_eq!(SpendPolicy::decode_under(&p.encode(), SuiteRules::LEGACY), Err(PolicyError::NotHybridKey(1)));
        assert_eq!(SpendPolicy::decode_under(&p.encode(), SuiteRules::HARDENING2), Ok(p.clone()));
        assert_eq!(SpendPolicy::new(1, p.pubkeys.clone(), 0, 0), Err(PolicyError::NotHybridKey(1)));
        assert_eq!(SpendPolicy::new_under(1, p.pubkeys.clone(), 0, 0, SuiteRules::HARDENING2), Ok(p.clone()));
        assert!(p.has_conservative_key());
        // A 9,322-byte signature: TooLarge below, decodes from hardening 2
        // (whether it verifies is the signature rule's business).
        let w = PolicyWitness { policy: p.clone(), signatures: vec![(1, vec![0x5A; 9_322])] }.encode();
        assert_eq!(PolicyWitness::decode_under(&w, SuiteRules::LEGACY), Err(PolicyError::NotHybridKey(1)));
        assert!(AnyPolicyWitness::decode_under(&w, SuiteRules::HARDENING2).is_ok());
        let hp = SpendPolicy::new(1, vec![h.clone()], 0, 0).unwrap();
        let big = PolicyWitness { policy: hp.clone(), signatures: vec![(0, vec![0x5A; 9_322])] }.encode();
        assert_eq!(PolicyWitness::decode(&big), Err(PolicyError::TooLarge));
        assert!(PolicyWitness::decode_under(&big, SuiteRules::HARDENING2).is_ok());
        let huge = PolicyWitness { policy: hp, signatures: vec![(0, vec![0x5A; 10 * 1024 + 1])] }.encode();
        assert_eq!(PolicyWitness::decode_under(&huge, SuiteRules::HARDENING2), Err(PolicyError::TooLarge));
        // Trees: a branch with a conservative key decodes from hardening 2.
        let t = PolicyTree::new(vec![p.clone(), SpendPolicy::new(1, vec![h.clone()], 0, 0).unwrap()]).unwrap();
        assert_eq!(PolicyTree::decode(&t.encode()), Err(PolicyError::NotHybridKey(1)));
        assert_eq!(PolicyTree::decode_under(&t.encode(), SuiteRules::HARDENING2), Ok(t.clone()));
        let bw = BranchWitness { n_branches: 2, index: 0, path: t.path(0), branch: p, signatures: vec![(0, vec![1])] };
        assert_eq!(BranchWitness::decode(&bw.encode()), Err(PolicyError::NotHybridKey(1)));
        assert_eq!(BranchWitness::decode_under(&bw.encode(), SuiteRules::HARDENING2), Ok(bw.clone()));
        assert_eq!(bw.script_pubkey(), t.script_pubkey());
    }

    /// PF-4 covers the new keys: a conservative key is its own identity (one
    /// encoding), it is distinct from every hybrid identity, and listing it
    /// twice is a duplicate (byte-wise already).
    #[test]
    fn key_identity_of_conservative_keys() {
        let c = conservative_key(0x72);
        assert_eq!(c.len(), crate::crypto::CONSERVATIVE_PUBLIC_KEY_LEN);
        assert!(matches!(key_identity(&c), Cow::Borrowed(k) if k == c.as_slice()));
        let h = keys(1).remove(0);
        assert_ne!(key_identity(&c), key_identity(&h));
        assert_ne!(key_identity(&c), key_identity(&h[4..]));
        let twice = SpendPolicy { threshold: 1, pubkeys: vec![c.clone(), c.clone()], after: 0, older: 0 };
        assert_eq!(SpendPolicy::decode_under(&twice.encode(), SuiteRules::HARDENING2), Err(PolicyError::DuplicateKey));
        assert_eq!(SpendPolicy::new_under(1, twice.pubkeys.clone(), 0, 0, SuiteRules::HARDENING2), Err(PolicyError::DuplicateKey));
        let pair = SpendPolicy::new_under(2, vec![c.clone(), conservative_key(0x73), h], 0, 0, SuiteRules::HARDENING2).unwrap();
        assert_eq!(pair.check_key_identities(), Ok(()));
        // The raw (unenveloped) body of a conservative key is no key at all.
        assert_eq!(
            SpendPolicy::new_under(1, vec![c[4..].to_vec()], 0, 0, SuiteRules::HARDENING2),
            Err(PolicyError::NotHybridKey(0))
        );
    }
}
