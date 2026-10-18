//! Deterministic generator of the data-driven consensus vectors
//! `reference/tx_vectors.json` and `reference/block_vectors.json` (format and
//! coverage: `docs/testing/VECTORS.md`).
//!
//! ```text
//! cargo test -p gnb-crypto --test gen_consensus_vectors -- --ignored            # the frozen files are reproduced
//! GNB_WRITE_VECTORS=1 cargo test -p gnb-crypto --test gen_consensus_vectors -- --ignored   # rewrite them
//! ```
//!
//! Every key comes from a fixed seed and every signature is made inside a
//! seeded RNG scope (`pqcrypto_internals::with_seeded_rng_scope`; Falcon is the
//! bit-exact `clean` variant), so the output is byte-identical on every run and
//! platform; CI regenerates both files and diffs them.
//!
//! The EXPECTED verdict and error class of each case are written here by hand,
//! next to the construction they describe. The generator never asks a
//! validation function for a verdict (that would make the vectors
//! tautological): it builds, signs and serializes. Boundary values (dust,
//! maturity, minimum fee, subsidy, MoneyRange, sizes) are computed from this
//! file's OWN constants, so a changed constant in the consensus code moves no
//! vector. The derived fields recorded with each case (txid, wtxid, sighash
//! digests, Merkle and witness roots, sizes) are what the current code
//! computes; `reference/check_consensus_vectors.py` recomputes every one of
//! them independently, and the runners (`tests/consensus_vectors.rs`,
//! `node/tests/consensus_vectors.rs`) check every verdict through the node's
//! validation functions. Mining (the nonces of the `pow: full` cases) uses
//! the GnB-SMH hash with the generator's own target decoding and comparison
//! (`proof_holds`, `mine_from`), not `Block::validate_pow`.

use gnb_crypto::core::sighash::SighashV3Precomputed;
use gnb_crypto::core::{
    self, block_rules, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput, TxOutput,
};
use gnb_crypto::crypto;
use sha3::{Digest, Sha3_256};

// ── This file's own copy of the consensus constants (see the module docs) ───

const DUST_THRESHOLD: u64 = 546;
const COINBASE_MATURITY: u64 = 100;
const MAX_SUPPLY_SAT: u64 = 1_250_000_000_000_000;
const MIN_TX_FEE_SAT: u64 = 10_000;
const MIN_FEE_RATE_SAT_PER_KB: u64 = 2_000;
const INITIAL_SUBSIDY_SAT: u64 = 107_020_547;
const HALVING_INTERVAL: u64 = 4_204_800;
const MAX_BLOCK_SIZE: usize = 1_000_000;
/// `script_sig` cap of the wire parser: the largest policy witness
/// (`core::MAX_SCRIPT_SIG_LEN`, a 7-of-7 multisig spend).
const MAX_SCRIPT_SIG_LEN: usize = 114_834;
/// `script_pubkey` cap of the wire parser.
const MAX_SCRIPT_PUBKEY_LEN: usize = 10_000;
const POW_LIMIT_BITS: u32 = 0x2100_FFFF;
const GENESIS_BITS: u32 = 0x1F0E_9036;
const GENESIS_TIMESTAMP: u64 = 1_791_685_648;
/// Mainnet PoW + PoWit activation (`core::POWIT_HEIGHT_MAINNET`): from it the
/// body root covers the PoWit section and the coinbase pays the miner's
/// share of the subsidy (`witness_share::split_subsidy`).
const POWIT_HEIGHT: u64 = 10_000;
/// From this height up to the hardening activation the coinbase script_sig
/// ends with `|wc:` and the witness root (`core::WITNESS_COMMITMENT_HEIGHT`).
const WITNESS_COMMITMENT_HEIGHT: u64 = 5_000;
const WITNESS_POOL_BPS: u64 = 2_000;
const MAX_SHARES_PER_BLOCK: u64 = 16;
const INCLUSION_BONUS_BPS: u64 = 1_000;

fn min_fee(wire_size: usize) -> u64 {
    MIN_TX_FEE_SAT.max((wire_size as u64 * MIN_FEE_RATE_SAT_PER_KB).div_ceil(1000))
}

fn subsidy(height: u64) -> u64 {
    if height == 0 || height / HALVING_INTERVAL >= 64 {
        return 0;
    }
    INITIAL_SUBSIDY_SAT >> (height / HALVING_INTERVAL)
}

/// The most a coinbase at `height` may pay the miner before fees, with no
/// witness shares: the whole subsidy below POWIT_HEIGHT, the subsidy minus
/// the witness pool from it.
fn miner_subsidy(height: u64) -> u64 {
    let s = subsidy(height);
    if height < POWIT_HEIGHT {
        return s;
    }
    let pool = s * WITNESS_POOL_BPS / 10_000;
    let _ = (MAX_SHARES_PER_BLOCK, INCLUSION_BONUS_BPS); // shares only add (bonus x shares)
    s - pool
}

/// The explicit activation height of most cases, and the heights either side.
const ACT: u64 = 1_000;
/// The networks' activation schedules (docs/CONSENSUS.md, "Activation"):
/// this file's own copy of `activation::MAINNET_HARDENING_ACTIVATION_HEIGHT`
/// (17,500 since 2026-10-16; 110,000 before). The `schedule` cases built
/// from it (their ids and descriptions carry the height) pin the consensus
/// constant: the runners take the height from the schedule, so they fail if
/// the two disagree.
const MAINNET_ACT: u64 = 17_500;
const TESTNET_ACT: u64 = 0;
const NEVER: u64 = u64::MAX;

/// A height with thousands separators ("110,000"), as the case descriptions
/// write it.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// `"schedule"` when `activation` is `chain`'s own activation schedule: the
/// runners then take the height from the schedule (the chain id's height in
/// gnb-crypto, the node's process-wide height) instead of installing it, so
/// such a case pins the schedule itself. `"explicit"` otherwise.
fn activation_source(chain: ChainId, activation: u64) -> &'static str {
    let schedule = match chain {
        ChainId::Mainnet => MAINNET_ACT,
        ChainId::Testnet => TESTNET_ACT,
        // The vectors cover GnB's two networks only.
        ChainId::ObenBlockMainnet | ChainId::ObenBlockRegtest => unreachable!("GnB vectors only"),
    };
    if activation == schedule { "schedule" } else { "explicit" }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Regime {
    Pre,
    Post,
}
use Regime::{Post, Pre};
const BOTH: [Regime; 2] = [Pre, Post];

impl Regime {
    fn height(self) -> u64 {
        match self {
            Pre => ACT - 1,
            Post => ACT,
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Pre => "pre",
            Post => "post",
        }
    }
    /// The version an honest signer writes in this regime.
    fn version(self) -> u32 {
        match self {
            Pre => 1,
            Post => 3,
        }
    }
    fn how(self) -> How {
        match self {
            Pre => How::V2,
            Post => How::V3,
        }
    }
    /// The class mempool admission's witness check
    /// (`admission::check_witnesses_for_next_block`) gives a non-canonical
    /// witness on the honest signer's version: relay policy below the
    /// activation (`non-standard-witness`, `AdmissionError::NonStandard`);
    /// from it the canonical witness is the consensus rule for version 3
    /// (CRY-1), so admission refuses with the consensus class
    /// (`witness-non-canonical`, `AdmissionError::Rejected`).
    fn witness_refusal(self) -> &'static str {
        match self {
            Pre => "non-standard-witness",
            Post => "witness-non-canonical",
        }
    }
}

fn regime_at(height: u64, activation: u64) -> &'static str {
    if height >= activation { "post-activation" } else { "pre-activation" }
}

// ── Minimal ordered JSON (deterministic whatever serde_json's features) ─────

enum J {
    S(String),
    N(u64),
    B(bool),
    Null,
    A(Vec<J>),
    O(Vec<(&'static str, J)>),
}

fn s(v: impl Into<String>) -> J {
    J::S(v.into())
}
fn hx(b: &[u8]) -> J {
    J::S(hex::encode(b))
}
fn dec(v: u64) -> J {
    J::S(v.to_string())
}

fn write_json(j: &J, depth: usize, out: &mut String) {
    let pad = |d: usize, out: &mut String| {
        out.push('\n');
        for _ in 0..d {
            out.push(' ');
        }
    };
    match j {
        J::S(v) => {
            out.push('"');
            for c in v.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        J::N(v) => out.push_str(&v.to_string()),
        J::B(v) => out.push_str(if *v { "true" } else { "false" }),
        J::Null => out.push_str("null"),
        J::A(items) if items.is_empty() => out.push_str("[]"),
        J::A(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                pad(depth + 1, out);
                write_json(it, depth + 1, out);
            }
            pad(depth, out);
            out.push(']');
        }
        J::O(fields) if fields.is_empty() => out.push_str("{}"),
        J::O(fields) => {
            out.push('{');
            for (i, (k, v)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                pad(depth + 1, out);
                out.push('"');
                out.push_str(k);
                out.push_str("\": ");
                write_json(v, depth + 1, out);
            }
            pad(depth, out);
            out.push('}');
        }
    }
}

fn to_json(j: &J) -> String {
    let mut out = String::new();
    write_json(j, 0, &mut out);
    out.push('\n');
    out
}

// ── Keys and signatures ─────────────────────────────────────────────────────

fn tag(label: &str) -> [u8; 32] {
    Sha3_256::digest(label.as_bytes()).into()
}

fn spk_of(pk: &[u8]) -> Vec<u8> {
    Sha3_256::digest(pk)[..20].to_vec()
}

const ENV_HYBRID: [u8; 4] = [0xB1, 0x0C, 0x01, 0x00];
const ENV_MLDSA: [u8; 4] = [0xB1, 0x0C, 0x02, 0x00];
const MLDSA_PK: usize = crypto::MLDSA_PUBKEY_LEN;
const MLDSA_SK: usize = crypto::MLDSA_SECRET_LEN;
const MLDSA_SIG: usize = crypto::MLDSA_SIG_LEN;

#[derive(Clone)]
struct Key {
    name: &'static str,
    kind: &'static str,
    pk: Vec<u8>,
    sk: Vec<u8>,
}

impl Key {
    fn seeded(name: &'static str) -> Key {
        let seed = tag(&format!("gnb-consensus-vectors/key/{name}"));
        let (pk, sk) = crypto::generate_keypair_from_seed(&seed).expect("seeded keygen");
        assert_eq!(pk[..4], ENV_HYBRID);
        Key { name, kind: "hybrid 0x0001, enveloped public key", pk, sk }
    }

    /// The same key pair with the RAW (pre-envelope) public key a genesis
    /// carry-over address commits to.
    fn raw(&self, name: &'static str) -> Key {
        Key { name, kind: "hybrid 0x0001, raw carry-over public key (no envelope)", pk: self.pk[4..].to_vec(), sk: self.sk.clone() }
    }

    /// The suite-0x0002 (ML-DSA-65 only) key made of this key's ML-DSA half.
    fn mldsa_only(&self, name: &'static str) -> Key {
        let mut pk = ENV_MLDSA.to_vec();
        pk.extend_from_slice(&self.pk[4..4 + MLDSA_PK]);
        let mut sk = ENV_MLDSA.to_vec();
        sk.extend_from_slice(&self.sk[4..4 + MLDSA_SK]);
        Key { name, kind: "ML-DSA-65 only 0x0002 (the ML-DSA half of a hybrid key)", pk, sk }
    }

    fn spk(&self) -> Vec<u8> {
        spk_of(&self.pk)
    }

    fn suite(&self) -> u16 {
        crypto::public_key_suite(&self.pk).expect("live suite")
    }

    /// The Falcon-1024 secret key of a hybrid key.
    fn falcon_sk(&self) -> Vec<u8> {
        self.sk[4 + MLDSA_SK..].to_vec()
    }
}

struct Keys {
    a: Key,
    b: Key,
    c: Key,
    a_raw: Key,
    a_mldsa: Key,
}

fn seeded<T>(label: &str, f: impl FnOnce() -> T) -> T {
    pqcrypto_internals::with_seeded_rng_scope(&tag(&format!("gnb-consensus-vectors/sig/{label}")), f)
}

/// Legacy binding: every component signs `msg` verbatim (`crypto::sign`).
fn sign_legacy(k: &Key, msg: &[u8; 32], label: &str) -> Vec<u8> {
    seeded(label, || crypto::sign(&k.sk, msg).expect("sign"))
}

/// v3 binding: every component signs its bound message (`crypto::sign_bound`).
fn sign_bound(k: &Key, digest: &[u8; 32], label: &str) -> Vec<u8> {
    seeded(label, || crypto::sign_bound(&k.sk, digest).expect("sign_bound"))
}

fn v2_digest(tx: &Transaction, i: usize, chain: ChainId) -> [u8; 32] {
    tx.sighash(i, chain)
}

fn v3_digest(tx: &Transaction, spent: &[TxOutput], i: usize, suite: u16, chain: ChainId) -> [u8; 32] {
    SighashV3Precomputed::new(tx, spent).expect("spent list").digest(i, suite, chain).expect("index")
}

fn script_sig(sig: &[u8], pk: &[u8]) -> Vec<u8> {
    Transaction::build_script_sig(sig, pk)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum How {
    /// Sighash v2, legacy binding (the historical signer).
    V2,
    /// Sighash v3, bound components (the signer from the activation).
    V3,
}

// ── Prevouts ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Prev {
    txid: [u8; 32],
    vout: u32,
    amount: u64,
    spk: Vec<u8>,
    coinbase_height: Option<u64>,
    /// The DAG height of the block holding that coinbase, when it differs
    /// from its header height `coinbase_height` (emitted only then; re-audit
    /// B1-T14: from the activation maturity compares DAG heights).
    coinbase_dag_height: Option<u64>,
    /// Created by the coinbase of the block the transaction is evaluated in
    /// (tx vectors only; never in the UTXO view).
    block_coinbase: bool,
}

impl Prev {
    fn out(&self) -> TxOutput {
        TxOutput { value: self.amount, script_pubkey: self.spk.clone() }
    }
}

fn fund(label: &str, amount: u64, spk: &[u8]) -> Prev {
    Prev {
        txid: tag(&format!("gnb-consensus-vectors/prevout/{label}")),
        vout: 0,
        amount,
        spk: spk.to_vec(),
        coinbase_height: None,
        coinbase_dag_height: None,
        block_coinbase: false,
    }
}

fn fund_cb(label: &str, amount: u64, spk: &[u8], cb_height: u64) -> Prev {
    Prev { coinbase_height: Some(cb_height), ..fund(label, amount, spk) }
}

fn prev_json(p: &Prev) -> J {
    let mut fields = vec![
        ("txid", hx(&p.txid)),
        ("vout", J::N(p.vout as u64)),
        ("amount", dec(p.amount)),
        ("script_pubkey", hx(&p.spk)),
        ("is_coinbase", J::B(p.coinbase_height.is_some() || p.block_coinbase)),
        ("coinbase_height", p.coinbase_height.map(dec).unwrap_or(J::Null)),
        ("source", s(if p.block_coinbase { "block-coinbase" } else { "utxo" })),
    ];
    if let Some(h) = p.coinbase_dag_height {
        fields.push(("coinbase_dag_height", dec(h)));
    }
    J::O(fields)
}

/// A 20-byte destination nobody in the vectors spends.
fn dest(label: &str) -> Vec<u8> {
    tag(&format!("gnb-consensus-vectors/dest/{label}"))[..20].to_vec()
}

fn pay(value: u64, label: &str) -> TxOutput {
    TxOutput { value, script_pubkey: dest(label) }
}

// ── Transactions ────────────────────────────────────────────────────────────

fn unsigned(version: u32, ins: &[&Prev], outs: Vec<TxOutput>) -> Transaction {
    Transaction {
        version,
        inputs: ins
            .iter()
            .map(|p| TxInput { prev_txid: p.txid, prev_index: p.vout, script_sig: vec![], sequence: u32::MAX })
            .collect(),
        outputs: outs,
        locktime: 0,
    }
}

/// Sign every input `i` with `signers[i]` (honest signer for `how`).
fn sign_all(tx: &mut Transaction, signers: &[&Key], spent: &[TxOutput], how: How, chain: ChainId, label: &str) {
    assert_eq!(signers.len(), tx.inputs.len());
    let mut sigs = Vec::new();
    for (i, k) in signers.iter().enumerate() {
        let l = format!("{label}/in{i}");
        let sig = match how {
            How::V2 => sign_legacy(k, &v2_digest(tx, i, chain), &l),
            How::V3 => sign_bound(k, &v3_digest(tx, spent, i, k.suite(), chain), &l),
        };
        sigs.push(sig);
    }
    for (i, sig) in sigs.into_iter().enumerate() {
        tx.inputs[i].script_sig = script_sig(&sig, &signers[i].pk);
    }
}

fn outs_of(prevs: &[&Prev]) -> Vec<TxOutput> {
    prevs.iter().map(|p| p.out()).collect()
}

/// Rebuild `make(out_value, attempt)` until the fee `total_in - out_value`
/// equals `min_fee(wire size) + delta` (the size depends on the variable-length
/// Falcon signature, which depends on the outputs).
fn exact_fee(total_in: u64, delta: i64, make: impl Fn(u64, u32) -> Transaction) -> Transaction {
    for attempt in 0..32u32 {
        let mut fee = 20_000u64;
        for _ in 0..8 {
            let tx = make(total_in - fee, attempt);
            let want = (min_fee(tx.wire_size(true)) as i64 + delta) as u64;
            if want == fee {
                return tx;
            }
            fee = want;
        }
    }
    panic!("exact_fee did not converge");
}

// ── Cases ───────────────────────────────────────────────────────────────────

/// Mempool admission (`admission::check_transaction`, relay policy) of the
/// transaction for a block at the case height. A refusal always names the
/// class of the admission rule that refuses it FIRST: for a consensus-invalid
/// case that is usually the admission's own copy of the violated consensus
/// rule (`TxCases::invalid`), but an earlier admission rule (relay policy,
/// the pool's view of the inputs, or admission's own consensus "no inputs"
/// rule) decides where the admission order says so
/// (`TxCases::invalid_refused`).
#[derive(Clone)]
enum Policy {
    Accept,
    Reject(&'static str),
}

struct TxCase {
    id: String,
    description: String,
    chain: ChainId,
    activation: u64,
    height: u64,
    prevouts: Vec<Prev>,
    bytes: Vec<u8>,
    /// `None`: valid.
    error: Option<&'static str>,
    /// Mempool admission at the case height.
    policy: Policy,
    /// The DAG height of the evaluation block (its selected parent's plus
    /// one), when it differs from its header height `height` (emitted only
    /// then; re-audit B1-T14).
    dag_height: Option<u64>,
}

fn net_name(c: ChainId) -> &'static str {
    match c {
        ChainId::Mainnet => "mainnet",
        ChainId::Testnet => "testnet",
        ChainId::ObenBlockMainnet | ChainId::ObenBlockRegtest => unreachable!("GnB vectors only"),
    }
}

struct TxCases {
    cases: Vec<TxCase>,
}

impl TxCases {
    #[allow(clippy::too_many_arguments)]
    fn push_full(
        &mut self,
        id: impl Into<String>,
        description: impl Into<String>,
        chain: ChainId,
        activation: u64,
        height: u64,
        prevouts: Vec<Prev>,
        bytes: Vec<u8>,
        error: Option<&'static str>,
        policy: Policy,
    ) {
        let id = id.into();
        assert!(!self.cases.iter().any(|c| c.id == id), "duplicate case id {id}");
        assert!(error.is_none() || matches!(policy, Policy::Reject(_)), "{id}: an invalid case is never admitted");
        // `admission::check_witnesses_for_next_block`: a non-canonical
        // witness of a version-3 transaction for a block at/after the
        // activation is refused by the consensus witness rule, never as
        // non-standard (see `Regime::witness_refusal`).
        // Conversely, that consensus refusal is reserved to exactly those
        // transactions: any other version at/after the activation, and every
        // version below it, gets the policy class.
        let v3_post = bytes.len() >= 4 && bytes[..4] == 3u32.to_le_bytes() && height >= activation;
        assert!(!(v3_post && matches!(policy, Policy::Reject("non-standard-witness"))),
            "{id}: version 3 at/after the activation: a non-canonical witness is `witness-non-canonical`");
        assert!(v3_post || !matches!(policy, Policy::Reject("witness-non-canonical")),
            "{id}: only version 3 at/after the activation is refused with `witness-non-canonical`; elsewhere it is `non-standard-witness`");
        self.cases.push(TxCase { id, description: description.into(), chain, activation, height, prevouts, bytes, error, policy, dag_height: None });
    }

    /// Sets the DAG height of the evaluation block of the last case pushed
    /// (re-audit B1-T14: a block that merges a long side tip has a header
    /// height above its selected-chain position).
    fn with_dag_height(&mut self, dag_height: u64) {
        let c = self.cases.last_mut().expect("a case");
        assert!(dag_height <= c.height, "{}: the header height is at least the DAG height", c.id);
        c.dag_height = Some(dag_height);
    }

    /// A mainnet case at the regime's height under `ACT`.
    #[allow(clippy::too_many_arguments)]
    fn push(&mut self, id: &str, r: Regime, description: &str, prevouts: Vec<Prev>, tx: &Transaction, error: Option<&'static str>, policy: Policy) {
        self.push_full(format!("{id}/{}", r.tag()), description, ChainId::Mainnet, ACT, r.height(), prevouts, tx.to_wire_bytes(true), error, policy);
    }

    fn valid(&mut self, id: &str, r: Regime, description: &str, prevouts: Vec<Prev>, tx: &Transaction) {
        self.push(id, r, description, prevouts, tx, None, Policy::Accept);
    }

    /// A consensus-invalid case that mempool admission refuses for the same
    /// rule (the admission's own copy of it decides).
    fn invalid(&mut self, id: &str, r: Regime, description: &str, prevouts: Vec<Prev>, tx: &Transaction, class: &'static str) {
        self.push(id, r, description, prevouts, tx, Some(class), Policy::Reject(class));
    }

    /// A consensus-invalid case that mempool admission refuses earlier, for
    /// `policy_class` (an admission rule that runs before the admission's
    /// copy of the violated consensus rule: relay policy, the pool's view of
    /// the inputs, or the consensus "no inputs" rule).
    #[allow(clippy::too_many_arguments)]
    fn invalid_refused(&mut self, id: &str, r: Regime, description: &str, prevouts: Vec<Prev>, tx: &Transaction, class: &'static str, policy_class: &'static str) {
        self.push(id, r, description, prevouts, tx, Some(class), Policy::Reject(policy_class));
    }
}

const FUND: u64 = 1_000_000;
const PAY: u64 = 900_000;

/// One input of `FUND` locked to `k`, one output of `PAY`, honestly signed
/// for regime `r` (version 1 / sighash v2 below the activation, version 3 /
/// sighash v3 from it).
fn simple(k: &Key, r: Regime, label: &str) -> (Transaction, Prev) {
    simple_with(k, r, label, |_| {})
}

fn simple_with(k: &Key, r: Regime, label: &str, edit: impl Fn(&mut Transaction)) -> (Transaction, Prev) {
    let p = fund(label, FUND, &k.spk());
    let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, label)]);
    edit(&mut tx);
    sign_all(&mut tx, &[k], &[p.out()], r.how(), ChainId::Mainnet, label);
    (tx, p)
}

/// Replace input `i`'s script_sig.
fn with_ss(tx: &Transaction, i: usize, ss: Vec<u8>) -> Transaction {
    let mut t = tx.clone();
    t.inputs[i].script_sig = ss;
    t
}

/// (sig, pk) of input `i` (lenient framing; the generator only reads witnesses it built).
fn witness(tx: &Transaction, i: usize) -> (Vec<u8>, Vec<u8>) {
    Transaction::parse_script_sig(&tx.inputs[i].script_sig).expect("witness built by the generator")
}

fn tx_cases(k: &Keys) -> Vec<TxCase> {
    let mut c = TxCases { cases: Vec::new() };
    let (ka, kb, kc) = (&k.a, &k.b, &k.c);

    // ── Baseline ────────────────────────────────────────────────────────────
    for r in BOTH {
        let (tx, p) = simple(ka, r, &format!("basic/one/{}", r.tag()));
        c.valid("basic/one-input-one-output", r,
            "The honest signer of the regime: version 1 + sighash v2 below the activation, version 3 + sighash v3 + bound signatures from it.",
            vec![p], &tx);

        let l = format!("basic/two/{}", r.tag());
        let p0 = fund(&format!("{l}/0"), FUND, &ka.spk());
        let p1 = fund(&format!("{l}/1"), 2 * FUND, &kb.spk());
        let mut tx = unsigned(r.version(), &[&p0, &p1], vec![pay(PAY, &l), pay(2 * PAY, &format!("{l}/b"))]);
        sign_all(&mut tx, &[ka, kb], &outs_of(&[&p0, &p1]), r.how(), ChainId::Mainnet, &l);
        c.valid("basic/two-inputs-two-outputs", r, "Two inputs locked to two different keys, two outputs.", vec![p0, p1], &tx);

        let l = format!("basic/three/{}", r.tag());
        let ps: Vec<Prev> = (0..3).map(|i| fund(&format!("{l}/{i}"), FUND, &kc.spk())).collect();
        let refs: Vec<&Prev> = ps.iter().collect();
        let mut tx = unsigned(r.version(), &refs, vec![pay(3 * PAY, &l)]);
        sign_all(&mut tx, &[kc, kc, kc], &outs_of(&refs), r.how(), ChainId::Mainnet, &l);
        c.valid("basic/three-inputs-same-key", r, "Three inputs locked to one key; each signature commits to its own input index.", ps, &tx);
    }
    for (id, act, h, r, desc) in [
        (format!("basic/mainnet-schedule/{}", MAINNET_ACT - 1), MAINNET_ACT, MAINNET_ACT - 1, Pre,
            format!("The mainnet activation height {}: the last pre-activation height.", grouped(MAINNET_ACT))),
        (format!("basic/mainnet-schedule/{MAINNET_ACT}"), MAINNET_ACT, MAINNET_ACT, Post,
            format!("The mainnet activation height {}: the first post-activation height.", grouped(MAINNET_ACT))),
        ("basic/activation-zero/height-1".to_string(), 0, 1, Post, "Activation height 0 (testnet/regtest schedule): the rules apply from height 1.".to_string()),
        ("basic/never-activated/height-4000000".to_string(), NEVER, 4_000_000, Pre, "Activation height u64::MAX (never): the old rules at any height.".to_string()),
    ] {
        let (tx, p) = simple(ka, r, &id);
        c.push_full(&id, &desc, ChainId::Mainnet, act, h, vec![p], tx.to_wire_bytes(true), None, Policy::Accept);
    }

    // ── Structure ───────────────────────────────────────────────────────────
    for r in BOTH {
        let l = format!("struct/no-outputs/{}", r.tag());
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.push("struct/no-outputs", r,
            "No outputs: the whole input value is the fee. Consensus-valid (there is no output-count rule); relay policy refuses it.",
            vec![p], &tx, None, Policy::Reject("non-standard-no-outputs"));

        let tx = Transaction { version: r.version(), inputs: vec![], outputs: vec![pay(0, "struct/no-inputs")], locktime: 0 };
        c.invalid_refused("struct/no-inputs", r,
            "No inputs (one zero-value output): there is no input-count rule, but the fee is 0, below the consensus minimum. Mempool admission refuses it first with its own consensus rule \"no inputs\" (`AdmissionError::Rejected`: a zero fee can never be mined).",
            vec![], &tx, "min-fee", "no-inputs");

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: b"not the first".to_vec(), sequence: u32::MAX }],
            outputs: vec![pay(1_000, "struct/coinbase-shaped")],
            locktime: 0,
        };
        if r == Post {
            tx.version = 3;
        }
        c.invalid("struct/coinbase-shaped-transaction", r,
            "A coinbase-shaped transaction (one input spending the null outpoint) outside position 0 of its block.",
            vec![], &tx, "coinbase-format");

        let (tx, p) = simple(ka, r, &format!("struct/missing/{}", r.tag()));
        let _ = p;
        c.invalid("struct/missing-input", r, "The spent outpoint is not in the UTXO set (otherwise a correctly signed spend).", vec![], &tx, "missing-input");

        let l = format!("struct/dup/{}", r.tag());
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p, &p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka, ka], &outs_of(&[&p, &p]), r.how(), ChainId::Mainnet, &l);
        c.invalid("struct/duplicate-input", r, "The same outpoint spent twice by one transaction, both inputs correctly signed.", vec![p], &tx, "double-spend");

        let l = format!("struct/two-vouts/{}", r.tag());
        let p0 = fund(&l, FUND, &ka.spk());
        let p1 = Prev { vout: 1, ..p0.clone() };
        let mut tx = unsigned(r.version(), &[&p0, &p1], vec![pay(PAY + FUND, &l)]);
        sign_all(&mut tx, &[ka, ka], &outs_of(&[&p0, &p1]), r.how(), ChainId::Mainnet, &l);
        c.valid("struct/same-txid-different-vouts", r, "Two outputs of one transaction spent together: distinct outpoints.", vec![p0, p1], &tx);

        let h = r.height() as u32;
        let l = format!("struct/locktime/{}", r.tag());
        let (tx, p) = simple_with(ka, r, &l, |t| {
            t.locktime = h;
            t.inputs[0].sequence = 0;
        });
        c.valid("struct/locktime-equal-to-the-height", r,
            "locktime = the block height and sequence = 0: a transaction is final in a block at height >= locktime (sequence carries no rule).",
            vec![p], &tx);
        let l = format!("struct/locktime-above/{}", r.tag());
        let (tx, p) = simple_with(ka, r, &l, |t| t.locktime = h + 1);
        c.invalid("struct/locktime-above-the-height", r,
            "locktime = the block height + 1: not final in this block (locktime is a block height, every height).",
            vec![p], &tx, "non-final");
        let l = format!("struct/locktime-max/{}", r.tag());
        let (tx, p) = simple_with(ka, r, &l, |t| t.locktime = u32::MAX);
        c.invalid("struct/locktime-u32-max", r, "locktime = 2^32-1: never final.", vec![p], &tx, "non-final");
    }
    {
        let l = "struct/null-prevout-second-input";
        let p0 = fund(l, FUND, &ka.spk());
        let null = Prev { txid: [0; 32], vout: u32::MAX, amount: FUND, spk: ka.spk(), coinbase_height: None, coinbase_dag_height: None, block_coinbase: false };
        let mut tx = unsigned(1, &[&p0, &null], vec![pay(PAY, l)]);
        sign_all(&mut tx, &[ka, ka], &outs_of(&[&p0, &null]), How::V2, ChainId::Mainnet, l);
        c.invalid(l, Pre, "A two-input transaction whose second input names the null outpoint: not a coinbase (two inputs), and no such coin exists.",
            vec![p0], &tx, "missing-input");
    }

    // ── Encoding and size limits ────────────────────────────────────────────
    {
        let (tx, p) = simple(ka, Pre, "decode/base");
        let good = tx.to_wire_bytes(true);
        let mut truncated = good.clone();
        truncated.pop();
        let mut trailing = good.clone();
        trailing.push(0);
        // Input count 1 written as a 3-byte varint.
        let mut nonminimal = good[..4].to_vec();
        nonminimal.extend_from_slice(&[0xFD, 0x01, 0x00]);
        nonminimal.extend_from_slice(&good[5..]);
        let mut many_inputs = 1u32.to_le_bytes().to_vec();
        many_inputs.extend_from_slice(&[0xFE]);
        many_inputs.extend_from_slice(&100_001u32.to_le_bytes());
        let mut many_outputs = 1u32.to_le_bytes().to_vec();
        many_outputs.push(0);
        many_outputs.extend_from_slice(&[0xFE]);
        many_outputs.extend_from_slice(&100_001u32.to_le_bytes());
        for (id, bytes, desc) in [
            ("decode/truncated", truncated, "A correctly signed transaction with its last byte removed."),
            ("decode/trailing-byte", trailing, "A correctly signed transaction followed by one extra byte: not the canonical encoding."),
            ("decode/non-minimal-varint", nonminimal, "The input count written as FD 01 00, not the minimal encoding of 1: the decoder refuses it."),
            ("decode/empty", vec![], "Zero bytes."),
            ("decode/input-count-above-cap", many_inputs, "An input count of 100,001 (the decoder's cap is 100,000)."),
            ("decode/output-count-above-cap", many_outputs, "No inputs and an output count of 100,001 (cap 100,000)."),
        ] {
            c.push_full(id, desc, ChainId::Mainnet, ACT, Pre.height(), vec![p.clone()], bytes, Some("decode"), Policy::Reject("decode"));
        }

        // A script_sig one byte above its cap and an output script of 10,001 bytes.
        let mut long_ss = tx.clone();
        long_ss.inputs[0].script_sig.resize(MAX_SCRIPT_SIG_LEN + 1, 0);
        c.push_full("decode/script-sig-above-the-cap", "A script_sig one byte above the 114,834-byte cap (the largest policy witness; the signature, then zero padding).",
            ChainId::Mainnet, ACT, Pre.height(), vec![p.clone()], long_ss.to_wire_bytes(true), Some("decode"), Policy::Reject("decode"));
        let mut long_spk = tx.clone();
        long_spk.outputs[0].script_pubkey = vec![0x51; MAX_SCRIPT_PUBKEY_LEN + 1];
        c.push_full("decode/script-pubkey-10001-bytes", "An output script one byte above the 10,000-byte cap.",
            ChainId::Mainnet, ACT, Pre.height(), vec![p.clone()], long_spk.to_wire_bytes(true), Some("decode"), Policy::Reject("decode"));
    }
    for r in BOTH {
        let l = format!("size/script-sig-10000/{}", r.tag());
        let (tx, p) = simple(ka, r, &l);
        let mut padded = tx.clone();
        padded.inputs[0].script_sig.resize(10_000, 0);
        let (err, pol) = match r {
            // This chain's v2 framing is exact: the padding is malformed.
            Pre => (Some("witness-malformed"), Policy::Reject(Pre.witness_refusal())),
            // Admission's witness check refuses it with the consensus
            // canonical-witness rule (version 3 at/after the activation).
            Post => (Some("witness-non-canonical"), Policy::Reject(Post.witness_refusal())),
        };
        c.push("size/script-sig-10000-bytes", r,
            "A valid signature followed by zero padding up to 10,000 script_sig bytes: the exact framing refuses the padding (below the activation as malformed, from it as a non-canonical witness).",
            vec![p], &padded, err, pol);

        let l = format!("size/script-pubkey-10000/{}", r.tag());
        let (tx, p) = simple_with(ka, r, &l, |t| t.outputs[0].script_pubkey = vec![0x51; MAX_SCRIPT_PUBKEY_LEN]);
        c.invalid("size/script-pubkey-10000-bytes", r,
            "An output script of exactly 10,000 bytes (the parser cap): it decodes, but only a 20-byte key hash or a 33-byte spend policy may be created.",
            vec![p], &tx, "bad-output-script");

        let l = format!("size/300-outputs/{}", r.tag());
        let p = fund(&l, 400 * FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], (0..300).map(|i| pay(FUND, &format!("{l}/{i}"))).collect());
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.valid("size/300-outputs", r, "300 outputs to 300 different scripts.", vec![p], &tx);
    }

    // ── Values, MoneyRange, fees, dust ──────────────────────────────────────
    for r in BOTH {
        let t = r.tag();
        let l = format!("value/above-max/{t}");
        let p = fund(&l, MAX_SUPPLY_SAT, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(MAX_SUPPLY_SAT + 1, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.invalid("value/output-above-max-supply", r, "One output of MAX_SUPPLY_SAT + 1 (MoneyRange).", vec![p], &tx, "value-out-of-range");

        let l = format!("value/sum-above-max/{t}");
        let p = fund(&l, MAX_SUPPLY_SAT, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(MAX_SUPPLY_SAT, &l), pay(MAX_SUPPLY_SAT, &format!("{l}/b"))]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.invalid("value/outputs-sum-above-max-supply", r, "Two outputs of MAX_SUPPLY_SAT each: each in range, the sum is not.", vec![p], &tx, "value-out-of-range");

        let l = format!("value/u64-max/{t}");
        let p = fund(&l, MAX_SUPPLY_SAT, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(u64::MAX, &l), pay(DUST_THRESHOLD, &format!("{l}/b"))]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.invalid("value/output-u64-max", r, "An output of 2^64 - 1 (and a second output that would overflow the sum).", vec![p], &tx, "value-out-of-range");

        let l = format!("value/max-boundary/{t}");
        let p = fund(&l, MAX_SUPPLY_SAT, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(MAX_SUPPLY_SAT - 100_000, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.valid("value/max-supply-boundary", r, "Spending a coin of exactly MAX_SUPPLY_SAT (in range) to one output of MAX_SUPPLY_SAT - 100,000.", vec![p], &tx);

        let l = format!("value/prevout-above-max/{t}");
        let p = fund(&l, MAX_SUPPLY_SAT + 1, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.invalid("value/prevout-above-max-supply", r, "The spent coin holds MAX_SUPPLY_SAT + 1 (unreachable on a real chain): the input sum fails MoneyRange.", vec![p], &tx, "value-out-of-range");

        let l = format!("value/prevouts-sum-above-max/{t}");
        let p0 = fund(&format!("{l}/0"), MAX_SUPPLY_SAT, &ka.spk());
        let p1 = fund(&format!("{l}/1"), 1, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p0, &p1], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka, ka], &outs_of(&[&p0, &p1]), r.how(), ChainId::Mainnet, &l);
        c.invalid("value/prevouts-sum-above-max-supply", r, "Two spent coins of MAX_SUPPLY_SAT and 1: the input sum leaves the money range.", vec![p0, p1], &tx, "value-out-of-range");

        let l = format!("value/in-lt-out/{t}");
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(FUND + 1, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.invalid("value/inputs-below-outputs", r, "Outputs exceed the input by one base unit.", vec![p], &tx, "inputs-below-outputs");

        let l = format!("value/zero-fee/{t}");
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(FUND, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.invalid("fee/zero", r, "Inputs equal outputs: fee 0.", vec![p], &tx, "min-fee");

        // Re-audit B1-T13: the fee floor no script_sig can lower is checked
        // with the rules the block id commits to, before any witness rule.
        let l = format!("value/zero-fee-bad-sig/{t}");
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(FUND, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        let (sig, pk) = witness(&tx, 0);
        let mut f = sig.clone();
        f[4 + MLDSA_SIG + 5] ^= 0x01; // inside the Falcon nonce: still canonical
        c.invalid("fee/zero-with-a-bad-signature", r,
            "Fee 0 and a signature that does not verify: the fee floor (the minimum fee of the transaction with every script_sig empty, at least 10,000) is a rule the txid commits to and is checked before any witness rule, so the class is min-fee (re-audit B1-T13).",
            vec![p], &with_ss(&tx, 0, script_sig(&f, &pk)), "min-fee");

        for (delta, id, err) in [(0i64, "fee/exact-minimum", None), (-1, "fee/minimum-minus-one", Some("min-fee"))] {
            let l = format!("{id}/{t}");
            let p = fund(&l, FUND, &ka.spk());
            let tx = exact_fee(FUND, delta, |out, attempt| {
                let mut tx = unsigned(r.version(), &[&p], vec![pay(out, &l)]);
                tx.locktime = attempt;
                sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &format!("{l}/{out}/{attempt}"));
                tx
            });
            let size = tx.wire_size(true);
            let desc = format!(
                "Fee {} the size-based minimum: max(10,000, ceil({size} wire bytes x 2,000 / 1,000)) = {}.",
                if delta == 0 { "exactly" } else { "one base unit below" },
                min_fee(size)
            );
            if err.is_none() {
                c.valid(id, r, &desc, vec![p], &tx);
            } else {
                c.invalid(id, r, &desc, vec![p], &tx, "min-fee");
            }
        }

        for (v, id, err) in [
            (DUST_THRESHOLD - 1, "dust/output-545", Some("dust")),
            (DUST_THRESHOLD, "dust/output-546", None),
            (1, "dust/output-1", Some("dust")),
        ] {
            let l = format!("{id}/{t}");
            let p = fund(&l, FUND, &ka.spk());
            let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l), pay(v, &format!("{l}/d"))]);
            sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
            let desc = format!("A second output of {v} base units (dust threshold 546: 0 < value < 546 is invalid).");
            match err {
                None => c.valid(id, r, &desc, vec![p], &tx),
                Some(e) => c.invalid(id, r, &desc, vec![p], &tx, e),
            }
        }

        let l = format!("value/zero-output/{t}");
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l), pay(0, &format!("{l}/z"))]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.push("value/zero-value-output", r, "A zero-value output: not dust by consensus (only 0 < value < 546 is), refused by relay policy.",
            vec![p], &tx, None, Policy::Reject("non-standard-zero-value"));
    }
    {
        let l = "fee/witness-padding-raises-the-minimum";
        let p = fund(l, FUND, &ka.spk());
        // Exactly the minimum fee for the unpadded size, then 50 bytes of
        // padding after the public key (ignored by the lenient framing, but
        // counted by the wire size the minimum fee is measured on).
        let tx = exact_fee(FUND, 0, |out, attempt| {
            let mut tx = unsigned(1, &[&p], vec![pay(out, l)]);
            tx.locktime = attempt;
            sign_all(&mut tx, &[ka], &[p.out()], How::V2, ChainId::Mainnet, &format!("{l}/{out}/{attempt}"));
            tx
        });
        let mut padded = tx.clone();
        padded.inputs[0].script_sig.extend_from_slice(&[0u8; 50]);
        c.invalid_refused(l, Pre, "Fee exactly the minimum of the unpadded transaction, then 50 padding bytes after the public key: this chain's exact v2 framing refuses the padding itself (before the fee rule, which also counts witness bytes). The mempool refuses the padded witness first (non-standard).",
            vec![p], &padded, "witness-malformed", "non-standard-witness");
    }

    // ── Coinbase maturity ───────────────────────────────────────────────────
    for r in BOTH {
        let h = r.height();
        for (depth, id, err) in [
            (COINBASE_MATURITY as i64, "maturity/depth-100", None),
            (COINBASE_MATURITY as i64 - 1, "maturity/depth-99", Some("immature-coinbase")),
            (0, "maturity/depth-0-parallel-coinbase", Some("immature-coinbase")),
            (-5, "maturity/coinbase-height-above-block", Some("immature-coinbase")),
        ] {
            let l = format!("{id}/{}", r.tag());
            let cbh = (h as i64 - depth) as u64;
            let p = fund_cb(&l, FUND, &ka.spk(), cbh);
            let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
            sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
            let desc = format!("Spends the coinbase of a block at height {cbh} from a block at height {h} (depth {depth}; 100 needed).");
            match err {
                None => c.valid(id, r, &desc, vec![p], &tx),
                Some(e) => c.invalid(id, r, &desc, vec![p], &tx, e),
            }
        }

        // The coinbase of the evaluation block itself (VAL-3).
        let l = format!("maturity/same-block-coinbase/{}", r.tag());
        let cb_value = 100_000_000;
        let wrapper_cb = wrapper_coinbase(cb_value, &ka.spk());
        let p = Prev { txid: wrapper_cb.txid(), vout: 0, amount: cb_value, spk: ka.spk(), coinbase_height: None, coinbase_dag_height: None, block_coinbase: true };
        let mut tx = unsigned(r.version(), &[&p], vec![pay(cb_value - 100_000, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        match r {
            Pre => c.invalid_refused("maturity/same-block-coinbase", r,
                "Spends output 0 of the coinbase of its own block (the wrapper coinbase pays the prevout): invalid at every height on this chain. Mempool admission cannot see an unconfirmed coinbase (missing input).",
                vec![p], &tx, "same-block-coinbase", "missing-input"),
            Post => c.invalid_refused("maturity/same-block-coinbase", r,
                "Spends output 0 of the coinbase of its own block: invalid from the activation (VAL-3). Mempool admission cannot see an unconfirmed coinbase (missing input).",
                vec![p], &tx, "same-block-coinbase", "missing-input"),
        }
    }
    {
        let r = Post;
        let l = "maturity/second-input-immature/post";
        let p0 = fund(&format!("{l}/0"), FUND, &ka.spk());
        let p1 = fund_cb(&format!("{l}/1"), FUND, &ka.spk(), r.height() - 50);
        let mut tx = unsigned(3, &[&p0, &p1], vec![pay(PAY, l)]);
        sign_all(&mut tx, &[ka, ka], &outs_of(&[&p0, &p1]), How::V3, ChainId::Mainnet, l);
        c.push_full(l, "The second input spends a coinbase 50 blocks deep.", ChainId::Mainnet, ACT, r.height(), vec![p0, p1],
            tx.to_wire_bytes(true), Some("immature-coinbase"), Policy::Reject("immature-coinbase"));

        let l = "maturity/carryover-coin-at-height-1";
        let (tx, p) = simple(ka, Pre, l);
        c.push_full(l, "A non-coinbase coin (a genesis carry-over output) spent at height 1: no maturity rule applies.",
            ChainId::Mainnet, ACT, 1, vec![p], tx.to_wire_bytes(true), None, Policy::Accept);
    }
    // Header height vs selected-chain depth (re-audit B1-T14): below the
    // activation maturity compares header heights, from it DAG heights
    // (`dag_height` of the evaluation block, `coinbase_dag_height` of the
    // coinbase's block).
    for r in BOTH {
        let h = r.height();
        // The evaluation block merges a long side tip: header depth 100,
        // selected-chain depth 10.
        let id = "maturity/merge-header-depth-100-dag-depth-10";
        let l = format!("{id}/{}", r.tag());
        let p = Prev { coinbase_dag_height: Some(h - 100), ..fund_cb(&l, FUND, &ka.spk(), h - 100) };
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        let desc = format!("Spends the coinbase of a block at header and DAG height {} from a block at header height {h} whose selected parent is at DAG height {} (it merges a side tip at DAG height {}): header depth 100, selected-chain depth 10. Valid below the activation (header heights), immature from it (selected-chain depth).", h - 100, h - 91, h - 1);
        match r {
            Pre => c.valid(id, r, &desc, vec![p], &tx),
            Post => c.invalid(id, r, &desc, vec![p], &tx, "immature-coinbase"),
        }
        c.with_dag_height(h - 90);

        // The coinbase's own block merged a long side tip: header depth 51,
        // selected-chain depth 100.
        let id = "maturity/inflated-coinbase-header-dag-depth-100";
        let l = format!("{id}/{}", r.tag());
        let p = Prev { coinbase_dag_height: Some(h - 100), ..fund_cb(&l, FUND, &ka.spk(), h - 51) };
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        let desc = format!("Spends the coinbase of a block at header height {} but DAG height {} (it merged a side tip) from a block at header and DAG height {h}: header depth 51, selected-chain depth 100. Immature below the activation (header heights), valid from it (selected-chain depth).", h - 51, h - 100);
        match r {
            Pre => c.invalid(id, r, &desc, vec![p], &tx, "immature-coinbase"),
            Post => c.valid(id, r, &desc, vec![p], &tx),
        }
    }

    // ── Version rule (v0..v4, 2^32-1 x regime) ──────────────────────────────
    for v in [0u32, 1, 2, 3, 4, u32::MAX] {
        let l = format!("version/v{v}/pre");
        let (tx, p) = simple_with(ka, Pre, &l, |t| t.version = v);
        let policy = if v >= 3 { Policy::Reject("non-standard-version") } else { Policy::Accept };
        c.push(&format!("version/v{v}-sighash-v2"), Pre,
            &format!("Version {v} signed over sighash v2 below the activation: every version is valid there with sighash v2 and the lenient witness{}.",
                if v >= 3 { "; version >= 3 is non-standard (relay policy only)" } else { "" }),
            vec![p], &tx, None, policy);

        if v == 3 {
            let (tx, p) = simple(ka, Post, "version/v3/post");
            c.valid("version/v3-sighash-v3", Post, "Version 3 signed over sighash v3 from the activation: the only valid version.", vec![p], &tx);
        } else {
            let l = format!("version/v{v}/post");
            let (tx, p) = simple_with(ka, Pre, &l, |t| t.version = v);
            c.invalid(&format!("version/v{v}-sighash-v2"), Post,
                &format!("Version {v} (signed over sighash v2, as a legacy wallet would) from the activation: only version 3 is valid."),
                vec![p], &tx, "bad-version");
        }
    }
    {
        let (tx, p) = simple_with(ka, Post, "version/v3-v3-digest-pre", |_| {});
        c.invalid_refused("version/v3-signed-sighash-v3", Pre,
            "Version 3 signed over sighash v3 (bound) below the activation: there every version is verified against sighash v2, so the signature fails. The mempool refuses version 3 below the activation first (non-standard).",
            vec![p], &tx, "bad-signature", "non-standard-version");
        let (tx, p) = simple_with(ka, Pre, "version/v3-v2-digest-post", |t| t.version = 3);
        c.invalid("version/v3-signed-sighash-v2", Post,
            "Version 3 signed over sighash v2 (legacy binding) from the activation: verified against sighash v3, the signature fails. No transaction is valid in both regimes.",
            vec![p], &tx, "bad-signature");
        for (id, act, h, r, ver, err, pol, desc) in [
            (format!("version/mainnet-boundary/v1-at-{MAINNET_ACT}"), MAINNET_ACT, MAINNET_ACT, Pre, 1u32, Some("bad-version"), Policy::Reject("bad-version"),
                format!("Version 1 at the mainnet activation height {}.", grouped(MAINNET_ACT))),
            (format!("version/mainnet-boundary/v3-sighash-v2-at-{}", MAINNET_ACT - 1), MAINNET_ACT, MAINNET_ACT - 1, Pre, 3, None, Policy::Reject("non-standard-version"),
                format!("Version 3 over sighash v2 at height {} under the mainnet schedule: consensus-valid, non-standard.", grouped(MAINNET_ACT - 1))),
            ("version/never/v3-sighash-v2".to_string(), NEVER, 4_000_000, Pre, 3, None, Policy::Reject("non-standard-version"),
                "Never activated: version 3 over sighash v2 at height 4,000,000 is consensus-valid, non-standard.".to_string()),
            ("version/never/v2".to_string(), NEVER, 4_000_000, Pre, 2, None, Policy::Accept, "Never activated: version 2 at height 4,000,000.".to_string()),
        ] {
            let (tx, p) = simple_with(ka, r, &id, |t| t.version = ver);
            c.push_full(&id, &desc, ChainId::Mainnet, act, h, vec![p], tx.to_wire_bytes(true), err, pol);
        }
    }

    // ── Sighash v2 / v3 signatures ──────────────────────────────────────────
    // Wrong amount / wrong script: v3 commits to them, v2 does not.
    for (what, r) in [("amount", Pre), ("amount", Post), ("script", Pre), ("script", Post)] {
        let l = format!("sig/wrong-{what}/{}", r.tag());
        let p = fund(&l, FUND, &ka.spk());
        let mut told = p.out();
        if what == "amount" {
            told.value += 1;
        } else {
            told.script_pubkey = dest("sig/wrong-script/told");
        }
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], std::slice::from_ref(&told), r.how(), ChainId::Mainnet, &l);
        let id = format!("sig/signer-told-wrong-{what}");
        match r {
            Pre => c.valid(&id, r, &format!("The signer was told the wrong spent {what}. Sighash v2 does not commit to the spent {what}, so the signature is valid (the audit's WAL-1 weakness, kept below the activation)."), vec![p], &tx),
            Post => c.invalid(&id, r, &format!("The signer was told the wrong spent {what}. Sighash v3 commits to every spent {what}: the signature fails."), vec![p], &tx, "bad-signature"),
        }
    }
    {
        let l = "sig/v3-wrong-amount-of-other-input/post";
        let p0 = fund(&format!("{l}/0"), FUND, &ka.spk());
        let p1 = fund(&format!("{l}/1"), FUND, &kb.spk());
        let mut tx = unsigned(3, &[&p0, &p1], vec![pay(PAY, l)]);
        sign_all(&mut tx, &[ka, kb], &outs_of(&[&p0, &p1]), How::V3, ChainId::Mainnet, l);
        let mut told = outs_of(&[&p0, &p1]);
        told[1].value -= 1;
        let sig = sign_bound(ka, &v3_digest(&tx, &told, 0, 1, ChainId::Mainnet), &format!("{l}/bad"));
        let tx = with_ss(&tx, 0, script_sig(&sig, &ka.pk));
        c.push_full("sig/v3-wrong-amount-of-other-input/post",
            "Input 0's signer was told a wrong amount for INPUT 1's coin: sighash v3 commits to every input's spent amount.",
            ChainId::Mainnet, ACT, Post.height(), vec![p0, p1], tx.to_wire_bytes(true), Some("bad-signature"), Policy::Reject("bad-signature"));
    }
    // Wrong index and wrong chain id, both regimes.
    for r in BOTH {
        let l = format!("sig/wrong-index/{}", r.tag());
        let p0 = fund(&format!("{l}/0"), FUND, &ka.spk());
        let p1 = fund(&format!("{l}/1"), FUND, &ka.spk());
        let spent = outs_of(&[&p0, &p1]);
        let mut tx = unsigned(r.version(), &[&p0, &p1], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka, ka], &spent, r.how(), ChainId::Mainnet, &l);
        let d = match r {
            Pre => v2_digest(&tx, 1, ChainId::Mainnet),
            Post => v3_digest(&tx, &spent, 1, 1, ChainId::Mainnet),
        };
        let sig = match r {
            Pre => sign_legacy(ka, &d, &format!("{l}/bad")),
            Post => sign_bound(ka, &d, &format!("{l}/bad")),
        };
        let bad = with_ss(&tx, 0, script_sig(&sig, &ka.pk));
        c.invalid("sig/signed-for-the-wrong-input-index", r, "Input 0 carries a signature over input 1's digest (same key, same transaction).",
            vec![p0, p1], &bad, "bad-signature");

        let l = format!("sig/testnet-signature-on-mainnet/{}", r.tag());
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Testnet, &l);
        c.invalid("sig/testnet-signature-on-mainnet", r, "Signed for the testnet chain id, evaluated on mainnet (replay protection).", vec![p], &tx, "bad-signature");

        // Components swapped between two inputs' signatures.
        let l = format!("sig/components-swapped-between-inputs/{}", r.tag());
        let p0 = fund(&format!("{l}/0"), FUND, &ka.spk());
        let p1 = fund(&format!("{l}/1"), FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p0, &p1], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka, ka], &outs_of(&[&p0, &p1]), r.how(), ChainId::Mainnet, &l);
        let (s0, _) = witness(&tx, 0);
        let (s1, _) = witness(&tx, 1);
        let mut mixed = ENV_HYBRID.to_vec();
        mixed.extend_from_slice(&s1[4..4 + MLDSA_SIG]);
        mixed.extend_from_slice(&s0[4 + MLDSA_SIG..]);
        let bad = with_ss(&tx, 0, script_sig(&mixed, &ka.pk));
        c.invalid("sig/components-swapped-between-inputs", r,
            "Input 0's signature is input 1's ML-DSA component followed by input 0's Falcon component (each a valid signature of the same key over another message).",
            vec![p0, p1], &bad, "bad-signature");

        // Tampered components.
        let l = format!("sig/tampered/{}", r.tag());
        let (tx, p) = simple(ka, r, &l);
        let (sig, pk) = witness(&tx, 0);
        let mut m = sig.clone();
        m[4 + 100] ^= 0x01;
        c.invalid("sig/mldsa-component-tampered", r, "One bit flipped inside the ML-DSA-65 component (the encoding stays canonical).",
            vec![p.clone()], &with_ss(&tx, 0, script_sig(&m, &pk)), "bad-signature");
        let mut f = sig.clone();
        f[4 + MLDSA_SIG + 5] ^= 0x01; // inside the 40-byte Falcon nonce
        c.invalid("sig/falcon-nonce-tampered", r, "One bit flipped inside the Falcon-1024 nonce (the encoding stays canonical).",
            vec![p], &with_ss(&tx, 0, script_sig(&f, &pk)), "bad-signature");

        // Wrong key, wrong public key.
        let l = format!("sig/other-key/{}", r.tag());
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[kb], &[p.out()], r.how(), ChainId::Mainnet, &l);
        let (sig_b, _) = witness(&tx, 0);
        c.invalid("sig/signature-by-another-key", r, "A valid signature by key B presented with key A's public key (A owns the coin).",
            vec![p.clone()], &with_ss(&tx, 0, script_sig(&sig_b, &ka.pk)), "bad-signature");
        c.invalid("sig/public-key-does-not-match-the-coin", r, "Key B's correct signature and public key spending a coin locked to key A.",
            vec![p], &tx, "pubkey-mismatch");

        // Second input bad.
        let l = format!("sig/second-input-bad/{}", r.tag());
        let p0 = fund(&format!("{l}/0"), FUND, &ka.spk());
        let p1 = fund(&format!("{l}/1"), FUND, &kb.spk());
        let mut tx = unsigned(r.version(), &[&p0, &p1], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka, kb], &outs_of(&[&p0, &p1]), r.how(), ChainId::Mainnet, &l);
        let (mut s1, pk1) = witness(&tx, 1);
        s1[4 + 7] ^= 0x80;
        c.invalid("sig/second-input-signature-bad", r, "Input 0 is correct; input 1's ML-DSA component has one flipped bit.",
            vec![p0, p1], &with_ss(&tx, 1, script_sig(&s1, &pk1)), "bad-signature");
    }
    {
        // v2-only: the historical out-of-range marker.
        let l = "sig/v2-out-of-range-index-digest/pre";
        let p = fund(l, FUND, &ka.spk());
        let tx = unsigned(1, &[&p], vec![pay(PAY, l)]);
        let sig = sign_legacy(ka, &v2_digest(&tx, 5, ChainId::Mainnet), l);
        let tx = with_ss(&tx, 0, script_sig(&sig, &ka.pk));
        c.push_full(l, "Signed over the v2 digest of input index 5 of a one-input transaction (no marker anywhere: the historical out-of-range quirk) instead of index 0.",
            ChainId::Mainnet, ACT, Pre.height(), vec![p], tx.to_wire_bytes(true), Some("bad-signature"), Policy::Reject("bad-signature"));

        // v3 bindings.
        let r = Post;
        let l = "sig/v3-legacy-binding/post";
        let p = fund(l, FUND, &ka.spk());
        let tx = unsigned(3, &[&p], vec![pay(PAY, l)]);
        let d = v3_digest(&tx, &[p.out()], 0, 1, ChainId::Mainnet);
        let sig = sign_legacy(ka, &d, l);
        c.push_full(l, "The correct sighash v3 digest signed with the LEGACY binding (each component signs the digest verbatim): from the activation each component must sign its bound message.",
            ChainId::Mainnet, ACT, r.height(), vec![p.clone()], with_ss(&tx, 0, script_sig(&sig, &ka.pk)).to_wire_bytes(true), Some("bad-signature"), Policy::Reject("bad-signature"));

        let l = "sig/v2-bound-binding/pre";
        let p = fund(l, FUND, &ka.spk());
        let tx = unsigned(1, &[&p], vec![pay(PAY, l)]);
        let sig = sign_bound(ka, &v2_digest(&tx, 0, ChainId::Mainnet), l);
        c.push_full(l, "The correct sighash v2 digest signed with the v3 BOUND binding: below the activation components sign the digest verbatim.",
            ChainId::Mainnet, ACT, Pre.height(), vec![p], with_ss(&tx, 0, script_sig(&sig, &ka.pk)).to_wire_bytes(true), Some("bad-signature"), Policy::Reject("bad-signature"));

        let l = "sig/v3-component-ids-swapped/post";
        let p = fund(l, FUND, &ka.spk());
        let tx = unsigned(3, &[&p], vec![pay(PAY, l)]);
        let d = v3_digest(&tx, &[p.out()], 0, 1, ChainId::Mainnet);
        let m_mldsa = crypto::bound_component_message(1, crypto::COMPONENT_MLDSA65, &d);
        let m_falcon = crypto::bound_component_message(1, crypto::COMPONENT_FALCON1024, &d);
        // ML-DSA signs the Falcon component's message and vice versa.
        let mldsa_part = seeded(&format!("{l}/m"), || crypto::sign(&k.a_mldsa.sk, &m_falcon).expect("sign"))[4..].to_vec();
        let falcon_part = seeded(&format!("{l}/f"), || crypto::falcon::sign(&ka.falcon_sk(), &m_mldsa).expect("sign"));
        let mut sig = ENV_HYBRID.to_vec();
        sig.extend_from_slice(&mldsa_part);
        sig.extend_from_slice(&falcon_part);
        c.push_full(l, "Each component signs the OTHER component's bound message (component ids swapped).",
            ChainId::Mainnet, ACT, r.height(), vec![p], with_ss(&tx, 0, script_sig(&sig, &ka.pk)).to_wire_bytes(true), Some("bad-signature"), Policy::Reject("bad-signature"));

        let l = "sig/v3-digest-with-another-suite/post";
        let p = fund(l, FUND, &ka.spk());
        let tx = unsigned(3, &[&p], vec![pay(PAY, l)]);
        let d = v3_digest(&tx, &[p.out()], 0, 2, ChainId::Mainnet);
        let sig = sign_bound(ka, &d, l);
        c.push_full(l, "A hybrid (suite 0x0001) signature over the sighash v3 digest computed with suite id 0x0002: the digest commits to the signature's own suite.",
            ChainId::Mainnet, ACT, r.height(), vec![p], with_ss(&tx, 0, script_sig(&sig, &ka.pk)).to_wire_bytes(true), Some("bad-signature"), Policy::Reject("bad-signature"));
    }

    // ── Networks ────────────────────────────────────────────────────────────
    for (r, signed_for, evaluated_on, err) in [
        (Pre, ChainId::Testnet, ChainId::Testnet, None),
        (Post, ChainId::Testnet, ChainId::Testnet, None),
        (Pre, ChainId::Mainnet, ChainId::Testnet, Some("bad-signature")),
        (Post, ChainId::Mainnet, ChainId::Testnet, Some("bad-signature")),
    ] {
        let l = format!("net/{}-signed-on-{}/{}", net_name(signed_for), net_name(evaluated_on), r.tag());
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), signed_for, &l);
        let pol = match err {
            None => Policy::Accept,
            Some(e) => Policy::Reject(e),
        };
        c.push_full(l, format!("Signed for {}, evaluated by a {} node.", net_name(signed_for), net_name(evaluated_on)),
            evaluated_on, ACT, r.height(), vec![p], tx.to_wire_bytes(true), err, pol);
    }
    {
        let l = "net/testnet-schedule/height-1";
        let p = fund(l, FUND, &ka.spk());
        let mut tx = unsigned(3, &[&p], vec![pay(PAY, l)]);
        sign_all(&mut tx, &[ka], &[p.out()], How::V3, ChainId::Testnet, l);
        c.push_full(l, "The testnet schedule (activation 0): version 3 / sighash v3 with the testnet chain id at height 1.",
            ChainId::Testnet, TESTNET_ACT, 1, vec![p], tx.to_wire_bytes(true), None, Policy::Accept);
    }

    // ── Signature suites (CRY-2) ────────────────────────────────────────────
    let km = &k.a_mldsa;
    for r in BOTH {
        let t = r.tag();
        // Split-and-relabel: the ML-DSA half of key A's hybrid signature, relabelled 0x0002,
        // spending a coin locked to the 0x0002 key made of A's ML-DSA half.
        let l = format!("suite/relabel/{t}");
        let p = fund(&l, FUND, &km.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l); // hybrid signer A
        let (sig, _) = witness(&tx, 0);
        let mut relabelled = ENV_MLDSA.to_vec();
        relabelled.extend_from_slice(&sig[4..4 + MLDSA_SIG]);
        let tx = with_ss(&tx, 0, script_sig(&relabelled, &km.pk));
        match r {
            Pre => c.push("suite/hybrid-split-and-relabelled-0x0002", r,
                "Key A's hybrid signature with its Falcon half stripped and the envelope relabelled 0x0002, spending a coin locked to the 0x0002 key made of A's ML-DSA half. Below the activation the components sign the digest verbatim, so this verifies (the audit's CRY-2 weakness, kept below the activation); 0x0002 keys are non-standard.",
                vec![p], &tx, None, Policy::Reject("non-standard-suite")),
            Post => c.invalid_refused("suite/hybrid-split-and-relabelled-0x0002", r,
                "The same split-and-relabel from the activation: the components sign suite-bound messages and the digest commits to the suite, so it fails. The mempool refuses the 0x0002 key first (non-standard suite).",
                vec![p], &tx, "bad-signature", "non-standard-suite"),
        }

        let l = format!("suite/mldsa-only-key/{t}");
        let p = fund(&l, FUND, &km.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[km], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.push("suite/mldsa-only-0x0002-spend", r,
            "A genuine suite-0x0002 (ML-DSA-65 only) key spends its coin: consensus-valid at every height (coins locked to 0x0002 keys are never frozen), non-standard.",
            vec![p], &tx, None, Policy::Reject("non-standard-suite"));

        let l = format!("suite/mldsa-sig-hybrid-key/{t}");
        let (tx, p) = simple(ka, r, &l);
        let (sig, pk) = witness(&tx, 0);
        let mut relabelled = ENV_MLDSA.to_vec();
        relabelled.extend_from_slice(&sig[4..4 + MLDSA_SIG]);
        c.invalid("suite/0x0002-signature-with-hybrid-key", r, "A 0x0002-relabelled ML-DSA half presented with the hybrid public key: a key of one suite never verifies a signature of another.",
            vec![p], &with_ss(&tx, 0, script_sig(&relabelled, &pk)), "bad-signature");

        let l = format!("suite/hybrid-sig-mldsa-key/{t}");
        let p = fund(&l, FUND, &km.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &l)]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        let (sig, _) = witness(&tx, 0);
        c.invalid_refused("suite/hybrid-signature-with-0x0002-key", r, "Key A's full hybrid signature presented with the 0x0002 public key (the coin is locked to the 0x0002 key). The mempool refuses the 0x0002 key first (non-standard suite).",
            vec![p], &with_ss(&tx, 0, script_sig(&sig, &km.pk)), "bad-signature", "non-standard-suite");

        for (suite, name) in [(0x0000u16, "reserved-0x0000"), (0xFFFF, "reserved-0xffff"), (0x0003, "unknown-0x0003")] {
            let l = format!("suite/{name}/{t}");
            let (tx, p) = simple(ka, r, &l);
            let (mut sig, pk) = witness(&tx, 0);
            sig[2..4].copy_from_slice(&suite.to_le_bytes());
            let (cls, desc) = match r {
                Pre => ("bad-signature", format!("A valid hybrid signature relabelled to suite {suite:#06x}: the key's suite (0x0001) differs, so verification fails.")),
                Post => ("witness-non-canonical", format!("A valid hybrid signature relabelled to suite {suite:#06x}: not a live suite, so not a canonical witness.")),
            };
            // A relabelled envelope is not a canonical signature: the
            // mempool's witness check refuses it in both regimes (policy
            // below the activation, the consensus rule from it).
            c.invalid_refused(&format!("suite/relabelled-{name}"), r, &desc, vec![p], &with_ss(&tx, 0, script_sig(&sig, &pk)), cls, r.witness_refusal());
        }
    }
    {
        let l = "suite/mldsa-only-sig-3310-bytes";
        for r in BOTH {
            let ll = format!("{l}/{}", r.tag());
            let p = fund(&ll, FUND, &km.spk());
            let mut tx = unsigned(r.version(), &[&p], vec![pay(PAY, &ll)]);
            sign_all(&mut tx, &[km], &[p.out()], r.how(), ChainId::Mainnet, &ll);
            let (mut sig, pk) = witness(&tx, 0);
            sig.push(0);
            let cls = if r == Pre { "bad-signature" } else { "witness-non-canonical" };
            c.invalid_refused(l, r, "A 0x0002 signature with one extra byte (3,310-byte body): the 0x0002 verifier requires exactly 3,309 bytes; from the activation it is not canonical. The mempool refuses the non-canonical signature first in both regimes.",
                vec![p], &with_ss(&tx, 0, script_sig(&sig, &pk)), cls, r.witness_refusal());
        }
    }

    // ── Raw carry-over public keys ──────────────────────────────────────────
    let kr = &k.a_raw;
    for r in BOTH {
        let t = r.tag();
        let (tx, p) = simple(kr, r, &format!("raw/enveloped-sig/{t}"));
        c.valid("raw/raw-public-key", r,
            "A genesis carry-over address commits to the RAW 3,745-byte hybrid public key; the enveloped signature verifies at every height (exact length decides the key's encoding).",
            vec![p], &tx);

        let (tx, p) = simple(kr, r, &format!("raw/raw-sig/{t}"));
        let (sig, pk) = witness(&tx, 0);
        assert_ne!(sig[4..6], [0xB1, 0x0C], "a raw signature must not look enveloped");
        let raw_sig = with_ss(&tx, 0, script_sig(&sig[4..], &pk));
        match r {
            Pre => c.push("raw/raw-public-key-raw-signature", r,
                "Raw public key and a raw (non-enveloped) signature: below the activation an envelope-less signature is read as hybrid and verifies; it is not a canonical witness, so relay policy refuses it.",
                vec![p], &raw_sig, None, Policy::Reject("non-standard-witness")),
            Post => c.invalid("raw/raw-public-key-raw-signature", r,
                "Raw public key and a raw signature from the activation: the signature envelope is mandatory in the canonical witness (the mempool's witness check refuses it with the same consensus rule).",
                vec![p], &raw_sig, "witness-non-canonical"),
        }

        let l = format!("raw/enveloped-pk-for-raw-address/{t}");
        let (tx, p) = simple(kr, r, &l);
        let (sig, _) = witness(&tx, 0);
        c.invalid("raw/enveloped-public-key-for-raw-address", r,
            "A coin locked to the RAW key's hash, spent with the ENVELOPED encoding of the same key: the address commits to the exact bytes.",
            vec![p], &with_ss(&tx, 0, script_sig(&sig, &ka.pk)), "pubkey-mismatch");

        let l = format!("raw/raw-pk-for-enveloped-address/{t}");
        let (tx, p) = simple(ka, r, &l);
        let (sig, _) = witness(&tx, 0);
        c.invalid("raw/raw-public-key-for-enveloped-address", r,
            "A coin locked to the ENVELOPED key's hash, spent with the RAW encoding of the same key.",
            vec![p], &with_ss(&tx, 0, script_sig(&sig, &kr.pk)), "pubkey-mismatch");
    }

    // ── Witness encodings (canonical vs lenient) x regime ───────────────────
    // Every witness below is non-canonical: the mempool's witness check
    // refuses each of them before its copy of the consensus signature rules,
    // as relay policy below the activation (version 1) and with the
    // consensus canonical-witness rule from it (version 3, CRY-1:
    // `Regime::witness_refusal`).
    for r in BOTH {
        let t = r.tag();
        let pre = r == Pre;
        let nsw = r.witness_refusal();
        // Below the activation this chain's v2 rule decides (`pre_class`:
        // None = consensus-valid); from it the canonical witness rule.
        let lenient_ok = |c: &mut TxCases, id: &str, desc: &str, p: Prev, tx: &Transaction, pre_class: Option<&'static str>| {
            if pre {
                match pre_class {
                    None => c.push(id, r, desc, vec![p], tx, None, Policy::Reject(nsw)),
                    Some(cls) => c.invalid_refused(id, r, desc, vec![p], tx, cls, nsw),
                }
            } else {
                c.invalid(id, r, desc, vec![p], tx, "witness-non-canonical");
            }
        };

        let (tx, p) = simple(ka, r, &format!("wit/trailing-byte/{t}"));
        let mut ss = tx.inputs[0].script_sig.clone();
        ss.push(0);
        lenient_ok(&mut c, "witness/one-trailing-byte",
            "One byte after the public key: this chain's framing is exact at every height (malformed below the activation, not canonical from it).",
            p, &with_ss(&tx, 0, ss), Some("witness-malformed"));

        let (tx, p) = simple(ka, r, &format!("wit/trailing-1000/{t}"));
        let mut ss = tx.inputs[0].script_sig.clone();
        ss.extend_from_slice(&[0xEE; 1000]);
        lenient_ok(&mut c, "witness/1000-trailing-bytes", "1,000 bytes after the public key (the fee still covers the larger size): refused by the exact framing.", p, &with_ss(&tx, 0, ss), Some("witness-malformed"));

        let (tx, p) = simple(ka, r, &format!("wit/raw-sig/{t}"));
        let (sig, pk) = witness(&tx, 0);
        assert_ne!(sig[4..6], [0xB1, 0x0C], "a raw signature must not look enveloped");
        lenient_ok(&mut c, "witness/signature-without-envelope",
            "The signature without its 4-byte suite envelope: read as hybrid below the activation (carried-over raw signatures stay valid); the envelope is mandatory from it.",
            p, &with_ss(&tx, 0, script_sig(&sig[4..], &pk)), None);

        let (tx, p) = simple(ka, r, &format!("wit/padded-falcon/{t}"));
        let (sig, pk) = witness(&tx, 0);
        let mut padded = sig.clone();
        let flen = padded.len() - 4 - MLDSA_SIG;
        assert!(flen < crypto::falcon::padded_signature_len(), "the compact Falcon signature must be shorter than the padded form");
        padded.resize(4 + MLDSA_SIG + crypto::falcon::padded_signature_len(), 0);
        lenient_ok(&mut c, "witness/falcon-zero-padded-1280",
            "The Falcon half in the alternate 1,280-byte zero-padded form (same signature): only the compact form verifies on this chain (`crypto::verify_canonical` below the activation, the canonical witness rule from it).",
            p, &with_ss(&tx, 0, script_sig(&padded, &pk)), Some("bad-signature"));

        let (tx, p) = simple(ka, r, &format!("wit/falcon-extra-byte/{t}"));
        let (mut sig, pk) = witness(&tx, 0);
        sig.push(0x01);
        let cls = if pre { "bad-signature" } else { "witness-non-canonical" };
        c.invalid_refused("witness/falcon-extra-nonzero-byte", r, "A non-zero byte appended to the Falcon half (inside sig_len): neither compact nor the padded form.",
            vec![p], &with_ss(&tx, 0, script_sig(&sig, &pk)), cls, nsw);

        let (tx, p) = simple(ka, r, &format!("wit/falcon-truncated/{t}"));
        let (mut sig, pk) = witness(&tx, 0);
        sig.truncate(sig.len() - 10);
        c.invalid_refused("witness/falcon-truncated", r, "The Falcon half missing its last 10 bytes.", vec![p], &with_ss(&tx, 0, script_sig(&sig, &pk)), cls, nsw);

        let (tx, p) = simple(ka, r, &format!("wit/empty-sig/{t}"));
        let (_, pk) = witness(&tx, 0);
        c.invalid_refused("witness/empty-signature", r, "sig_len = 0 followed by the correct public key.", vec![p], &with_ss(&tx, 0, script_sig(&[], &pk)), cls, nsw);

        let (tx, p) = simple(ka, r, &format!("wit/sig-len-overflow/{t}"));
        let mut ss = tx.inputs[0].script_sig.clone();
        let declared = u32::from_le_bytes(ss[..4].try_into().unwrap()) + 100_000;
        ss[..4].copy_from_slice(&declared.to_le_bytes());
        let cls_framing = if pre { "witness-malformed" } else { "witness-non-canonical" };
        c.invalid_refused("witness/sig-length-beyond-the-script", r, "sig_len declares 100,000 more bytes than the script_sig holds.", vec![p], &with_ss(&tx, 0, ss), cls_framing, nsw);

        let (tx, p) = simple(ka, r, &format!("wit/empty-ss/{t}"));
        c.invalid_refused("witness/empty-script-sig", r, "An empty script_sig.", vec![p], &with_ss(&tx, 0, vec![]), cls_framing, nsw);

        let (tx, p) = simple(ka, r, &format!("wit/seven-bytes/{t}"));
        c.invalid_refused("witness/seven-byte-script-sig", r, "A 7-byte script_sig (shorter than the two length fields).", vec![p], &with_ss(&tx, 0, vec![0; 7]), cls_framing, nsw);

        let (tx, p) = simple(ka, r, &format!("wit/pk-len-short/{t}"));
        let (sig, pk) = witness(&tx, 0);
        let mut ss = script_sig(&sig, &pk);
        let at = 4 + sig.len();
        ss[at..at + 4].copy_from_slice(&((pk.len() - 1) as u32).to_le_bytes());
        let cls_pk = if pre { "witness-malformed" } else { "witness-non-canonical" };
        c.invalid_refused("witness/pk-length-one-short", r,
            "pk_len one byte short: the key's last byte is left over after the framing, which the exact framing refuses at every height.",
            vec![p], &with_ss(&tx, 0, ss), cls_pk, nsw);
    }

    // The gate of that consensus refusal is the VERSION RULE's verdict at the
    // next block's height (`check_tx_version(..) == V3`), neither the height
    // alone nor the version alone: a non-canonical witness on any other
    // version at/after the activation, or on version 3 below it (where
    // version 3 is verified with sighash v2 and the lenient framing), is
    // relay policy (`NonStandard`).
    {
        let l = "witness/version-1-one-trailing-byte-from-the-activation";
        let (tx, p) = simple(ka, Pre, &format!("{l}/post"));
        let mut ss = tx.inputs[0].script_sig.clone();
        ss.push(0);
        c.invalid_refused(l, Post,
            "Version 1 (signed over sighash v2, as a legacy wallet would) with one byte after the public key, from the activation: consensus refuses the version first. Mempool admission's witness check runs before its version rule and refuses the non-canonical witness as relay policy: the canonical witness is the consensus rule only for version 3 from the activation.",
            vec![p], &with_ss(&tx, 0, ss), "bad-version", "non-standard-witness");

        let l = "witness/version-3-sighash-v2-one-trailing-byte";
        let (tx, p) = simple_with(ka, Pre, &format!("{l}/pre"), |t| t.version = 3);
        let mut ss = tx.inputs[0].script_sig.clone();
        ss.push(0);
        c.invalid_refused(l, Pre,
            "Version 3 signed over sighash v2 with one byte after the public key, below the activation: version 3 is verified there with sighash v2 and this chain's exact v2 framing, which refuses the byte (malformed). Mempool admission refuses the non-canonical witness as relay policy (before its version policy): below the activation the canonical witness is not a consensus rule for any version.",
            vec![p], &with_ss(&tx, 0, ss), "witness-malformed", "non-standard-witness");
    }

    // ── 64-byte transactions (VAL-10) ───────────────────────────────────────
    for r in BOTH {
        for (spk_len, id) in [(5usize, "tx64/64-byte-transaction"), (4, "tx64/63-byte-transaction"), (6, "tx64/65-byte-transaction")] {
            let l = format!("{id}/{}", r.tag());
            let p = fund(&l, FUND, &ka.spk());
            let mut tx = unsigned(r.version(), &[&p], vec![TxOutput { value: PAY, script_pubkey: vec![0x51; spk_len] }]);
            sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
            assert_eq!(tx.wire_size(false), 59 + spk_len);
            let desc = format!("One input, one output with a {spk_len}-byte script: the txid preimage (no script_sig) is {} bytes. On this chain no output may carry such a script (only 20-byte key hashes and 33-byte policies), so a 64-byte transaction cannot be valid at any height.", 59 + spk_len);
            if spk_len == 5 && r == Post {
                c.invalid(id, r, &format!("{desc} From the activation the context-free 64-byte rule (VAL-10) refuses it first."), vec![p], &tx, "tx-64-bytes");
            } else {
                c.invalid(id, r, &desc, vec![p], &tx, "bad-output-script");
            }
        }
    }
    for (h, err, pol) in [(MAINNET_ACT - 1, Some("bad-output-script"), Policy::Reject("bad-output-script")), (MAINNET_ACT, Some("tx-64-bytes"), Policy::Reject("tx-64-bytes"))] {
        let r = if h >= MAINNET_ACT { Post } else { Pre };
        let l = format!("tx64/mainnet-boundary/{h}");
        let p = fund(&l, FUND, &ka.spk());
        let mut tx = unsigned(r.version(), &[&p], vec![TxOutput { value: PAY, script_pubkey: vec![0x51; 5] }]);
        sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
        c.push_full(l, format!("A 64-byte transaction at height {h} under the mainnet schedule."), ChainId::Mainnet, MAINNET_ACT, h,
            vec![p], tx.to_wire_bytes(true), err, pol);
    }

    // ── BIP30 at the transaction level ──────────────────────────────────────
    for r in BOTH {
        let l = format!("bip30/tx-output/{}", r.tag());
        let (tx, p) = simple(ka, r, &l);
        let stale = Prev { txid: tx.txid(), vout: 0, amount: 777, spk: dest("bip30/stale"), coinbase_height: None, coinbase_dag_height: None, block_coinbase: false };
        match r {
            Pre => c.invalid_refused("bip30/output-overwrites-an-unspent-coin", r,
                "An unspent coin already sits at this transaction's output 0 (models a coin created before): invalid at every height on this chain (BIP30). The mempool refuses it as already confirmed (the coin's txid is this transaction's).",
                vec![p, stale], &tx, "bip30", "already-confirmed"),
            Post => c.invalid_refused("bip30/output-overwrites-an-unspent-coin", r,
                "An unspent coin already sits at this transaction's output 0: invalid from the activation (VAL-2, BIP30). The mempool refuses it as already confirmed (the coin's txid is this transaction's).",
                vec![p, stale], &tx, "bip30", "already-confirmed"),
        }
    }

    c.cases
}

/// The coinbase the tx-vector runners put in front of the transaction: one
/// null-outpoint input with the fixed script_sig below, one output.
const WRAPPER_COINBASE_SCRIPT_SIG: &[u8] = b"gnb-tx-vectors/coinbase";

fn wrapper_coinbase(value: u64, spk: &[u8]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: WRAPPER_COINBASE_SCRIPT_SIG.to_vec(), sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey: spk.to_vec() }],
        locktime: 0,
    }
}

fn tx_case_json(case: &TxCase) -> J {
    let decoded = Transaction::from_wire_bytes(&case.bytes).ok().filter(|t| t.to_wire_bytes(true) == case.bytes);
    let mut fields: Vec<(&'static str, J)> = vec![
        ("id", s(case.id.clone())),
        ("description", s(case.description.clone())),
        ("network", s(net_name(case.chain))),
        ("activation_height", dec(case.activation)),
        ("activation_source", s(activation_source(case.chain, case.activation))),
        ("height", dec(case.height)),
        ("regime", s(regime_at(case.height, case.activation))),
        ("prevouts", J::A(case.prevouts.iter().map(prev_json).collect())),
        ("tx", hx(&case.bytes)),
        ("expected", J::O(vec![
            ("verdict", s(if case.error.is_none() { "valid" } else { "invalid" })),
            ("error_class", case.error.map(s).unwrap_or(J::Null)),
        ])),
        ("policy", match &case.policy {
            Policy::Accept => J::O(vec![("verdict", s("accept")), ("error_class", J::Null)]),
            Policy::Reject(c) => J::O(vec![("verdict", s("reject")), ("error_class", s(*c))]),
        }),
    ];
    let derived = match decoded {
        None => J::Null,
        Some(tx) => {
            // Spent outputs by outpoint (v3 digests need one per input).
            let spent: Option<Vec<TxOutput>> = tx.inputs.iter().map(|i| {
                case.prevouts.iter().find(|p| p.txid == i.prev_txid && p.vout == i.prev_index).map(Prev::out)
            }).collect();
            let digests = (0..tx.inputs.len()).map(|i| {
                let suite = Transaction::parse_script_sig(&tx.inputs[i].script_sig)
                    .and_then(|(sig, _)| crypto::split_envelope(&sig).map(|(s, _)| s))
                    .unwrap_or(crypto::SUITE_MLDSA65_FALCON1024);
                let v3 = spent.as_ref().map(|sp| hx(&v3_digest(&tx, sp, i, suite, case.chain))).unwrap_or(J::Null);
                J::O(vec![
                    ("input", J::N(i as u64)),
                    ("sighash_v2", hx(&v2_digest(&tx, i, case.chain))),
                    ("sighash_v3_suite", J::N(suite as u64)),
                    ("sighash_v3", v3),
                ])
            }).collect();
            J::O(vec![
                ("txid", hx(&tx.txid())),
                ("wtxid", hx(&tx.wtxid())),
                ("wire_size", J::N(tx.wire_size(true) as u64)),
                ("txid_preimage_size", J::N(tx.wire_size(tx.is_coinbase()) as u64)),
                ("digests", J::A(digests)),
            ])
        }
    };
    if let Some(d) = case.dag_height {
        let at = fields.iter().position(|(k, _)| *k == "height").expect("height") + 1;
        fields.insert(at, ("dag_height", dec(d)));
    }
    fields.push(("derived", derived));
    J::O(fields)
}

fn keys_json(k: &Keys) -> J {
    J::A([&k.a, &k.b, &k.c, &k.a_raw, &k.a_mldsa].iter().map(|key| J::O(vec![
        ("name", s(key.name)),
        ("kind", s(key.kind)),
        ("public_key_sha3", hx(&Sha3_256::digest(&key.pk))),
        ("public_key_len", J::N(key.pk.len() as u64)),
        ("script_pubkey", hx(&key.spk())),
    ])).collect())
}

fn constants_json() -> J {
    J::O(vec![
        ("chain_id_mainnet", J::N(ChainId::Mainnet.to_u32() as u64)),
        ("chain_id_testnet", J::N(ChainId::Testnet.to_u32() as u64)),
        ("coinbase_maturity", J::N(COINBASE_MATURITY)),
        ("dust_threshold", J::N(DUST_THRESHOLD)),
        ("max_supply_sat", dec(MAX_SUPPLY_SAT)),
        ("min_tx_fee_sat", J::N(MIN_TX_FEE_SAT)),
        ("min_fee_rate_sat_per_kb", J::N(MIN_FEE_RATE_SAT_PER_KB)),
        ("initial_subsidy_sat", J::N(INITIAL_SUBSIDY_SAT)),
        ("halving_interval", J::N(HALVING_INTERVAL)),
        ("max_block_size", J::N(MAX_BLOCK_SIZE as u64)),
        ("max_script_sig_len", J::N(MAX_SCRIPT_SIG_LEN as u64)),
        ("max_script_pubkey_len", J::N(MAX_SCRIPT_PUBKEY_LEN as u64)),
        ("powit_height", J::N(POWIT_HEIGHT)),
        ("witness_commitment_height", J::N(WITNESS_COMMITMENT_HEIGHT)),
        ("pow_limit_bits", J::N(POW_LIMIT_BITS as u64)),
        ("hardened_pow_limit_bits", J::N(GENESIS_BITS as u64)),
        ("wrapper_coinbase_script_sig", hx(WRAPPER_COINBASE_SCRIPT_SIG)),
    ])
}

fn tx_doc(k: &Keys) -> (J, usize) {
    let cases = tx_cases(k);
    let n = cases.len();
    let doc = J::O(vec![
        ("format", s("gnb-consensus-tx-vectors/1")),
        ("description", s(
            "Transaction validity in both activation regimes. Each case is ONE non-coinbase transaction evaluated in a block at `height` \
             (header height) under `activation_height` (`activation_source`: `explicit`, or `schedule` = the network's own activation \
             schedule, which the runners take from the schedule instead of installing it), on `network`, against a UTXO view holding exactly `prevouts` \
             (source `utxo`; a `block-coinbase` prevout is output 0 of the block's own coinbase). The block is [wrapper coinbase, tx]: \
             the wrapper coinbase has one input (32 zero bytes, index 0xffffffff, script_sig `constants.wrapper_coinbase_script_sig`, \
             sequence 0xffffffff), one output (the block-coinbase prevout's amount and script, or 0 to 20 zero bytes), version 1, \
             locktime 0. `expected` is the consensus verdict and the class of the first rule that fails in the node's order; `policy` \
             is mempool admission for a block at `height` on a store holding the `utxo` prevouts, each prevout's txid indexed as a \
             confirmed transaction (a node applies every coin with its creating transaction): accept, or reject with the class of \
             the first admission rule that refuses it (a consensus-invalid case is always rejected). `derived` holds values the code computes and the Python reference recomputes. Format: docs/testing/VECTORS.md.")),
        ("generator", s("crates/gnb-crypto/tests/gen_consensus_vectors.rs")),
        ("constants", constants_json()),
        ("keys", keys_json(k)),
        ("cases", J::A(cases.iter().map(tx_case_json).collect())),
    ]);
    (doc, n)
}

// ── Blocks ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pow {
    Skip,
    Limit,
    Full,
}

struct BlockCase {
    id: String,
    description: String,
    activation: u64,
    block: Block,
    prevouts: Vec<Prev>,
    error: Option<&'static str>,
    scope: &'static str,
    pow: Pow,
    /// Serialize as run-length parts (big blocks): (start, unit length, repeat).
    rle: Option<(usize, usize, usize)>,
    /// Bytes that are not the encoding of `block` (decode cases).
    raw: Option<Vec<u8>>,
}

fn parent(label: &str) -> [u8; 32] {
    tag(&format!("gnb-consensus-vectors/parent/{label}"))
}

fn coinbase(value: u64, label: &str, extra: &[u8]) -> Transaction {
    let mut ss = format!("gnb-block-vectors/{label}/").into_bytes();
    ss.extend_from_slice(extra);
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: ss, sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey: dest(&format!("{label}/miner")) }],
        locktime: 0,
    }
}

fn raw_block(height: u64, activation: u64, parents: Vec<[u8; 32]>, txs: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: MerkleRoot::ZERO,
            timestamp: GENESIS_TIMESTAMP + 30 * height,
            bits: block_rules::pow_limit_bits_at(height, activation),
            nonce: 0,
        },
        transactions: txs,
        blue_score: height,
        height,
        shielded_transactions: vec![],
        powit: Default::default(),
    }
}

/// Commitment (when the block's height is at/after `activation`) then the
/// header root of the regime.
fn seal(b: &mut Block, activation: u64) {
    if block_rules::rules_active_at(b.height, activation) && !b.transactions.is_empty() {
        let c = block_rules::expected_coinbase_commitment(b);
        let extra = std::mem::take(&mut b.transactions[0].inputs[0].script_sig);
        b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&c, &extra);
    } else if b.height >= WITNESS_COMMITMENT_HEIGHT && !b.transactions.is_empty() {
        append_wc_suffix(b);
    }
    reroot(b, activation);
}

/// `|wc:` followed by the legacy (SHA-256d, last node duplicated) Merkle
/// root of [32 zero bytes, wtxid(tx_1), ...], appended to the coinbase
/// script_sig (this chain's witness commitment from WITNESS_COMMITMENT_HEIGHT
/// below the activation).
fn append_wc_suffix(b: &mut Block) {
    let mut ids: Vec<[u8; 32]> = vec![[0; 32]];
    ids.extend(b.transactions[1..].iter().map(Transaction::wtxid));
    let root = block_rules::legacy_merkle_root(&ids);
    let ss = &mut b.transactions[0].inputs[0].script_sig;
    ss.extend_from_slice(b"|wc:");
    ss.extend_from_slice(&root.0);
}

fn reroot(b: &mut Block, activation: u64) {
    b.header.merkle_root = b.body_merkle_root_at(activation);
}

/// The target of compact `bits` as 32 big-endian bytes (the generator's own
/// decoder; only well-formed bits are mined).
fn target_of_bits(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as i64;
    let mantissa = bits & 0x007F_FFFF;
    assert!(bits & 0x0080_0000 == 0 && mantissa != 0, "well-formed bits");
    let mut t = [0u8; 32];
    for (i, byte) in mantissa.to_be_bytes()[1..].iter().enumerate() {
        let pos = 32 - exponent + i as i64;
        if (0..32).contains(&pos) {
            t[pos as usize] = *byte;
        } else {
            assert_eq!(*byte, 0, "bits {bits:#x}: the target must fit 256 bits");
        }
    }
    t
}

/// The generator's own GnB-SMH check (not `Block::validate_pow`): the
/// 256-bit big-endian output for the header's preimage and nonce is strictly
/// below the target of its bits.
fn proof_holds(b: &Block) -> bool {
    gnb_smh::hash_thread_local(&b.header.pow_preimage(), b.header.nonce) < target_of_bits(b.header.bits)
}

/// The first nonce `>= from` for which [`proof_holds`]. Two threads search
/// interleaved nonces; a thread stops once its next nonce is above the best
/// success so far, so every nonce below the result was evaluated and the
/// result does not depend on timing. One evaluation is ~0.6 s; the hint
/// constants below make regeneration a single evaluation per mined block.
fn mine_from(b: &Block, from: u64) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    const THREADS: u64 = 2;
    let best = AtomicU64::new(u64::MAX);
    let pre = b.header.pow_preimage();
    let target = target_of_bits(b.header.bits);
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let (best, pre) = (&best, &pre);
            scope.spawn(move || {
                let mut n = from + t;
                while n < best.load(Ordering::SeqCst) {
                    if gnb_smh::hash_thread_local(pre, n) < target {
                        best.fetch_min(n, Ordering::SeqCst);
                        return;
                    }
                    n += THREADS;
                }
            });
        }
    });
    best.into_inner()
}

/// Where the nonce search of `pow/genesis-bits-mined/post` starts: the first
/// nonce from 0 that meets the genesis target for that block (found once by
/// `mine_from(.., 0)`, about 4,500 evaluations expected). A change to the
/// block's header moves the search on from here.
const GENESIS_BITS_NONCE_HINT: u64 = 4_440;

/// The bincode-2 "standard" size of a block (a filler target only: no rule
/// of this chain measures it).
fn bincode_size(b: &Block) -> usize {
    bincode::serde::encode_to_vec(b, bincode::config::standard()).expect("encode").len()
}

struct BlockCases {
    cases: Vec<BlockCase>,
}

impl BlockCases {
    fn push(&mut self, id: &str, r: Regime, desc: &str, block: Block, prevouts: Vec<Prev>, error: Option<&'static str>) {
        self.push_full(format!("{id}/{}", r.tag()), desc, ACT, block, prevouts, error, "full", Pow::Skip);
    }

    #[allow(clippy::too_many_arguments)]
    fn push_full(&mut self, id: String, desc: &str, activation: u64, block: Block, prevouts: Vec<Prev>, error: Option<&'static str>, scope: &'static str, pow: Pow) {
        assert!(!self.cases.iter().any(|c| c.id == id), "duplicate case id {id}");
        self.cases.push(BlockCase { id, description: desc.into(), activation, block, prevouts, error, scope, pow, rle: None, raw: None });
    }
}

/// A signed one-input spend of a fresh coin locked to `k` (fee 100,000).
fn block_spend(k: &Key, r: Regime, label: &str, value_in: u64) -> (Transaction, Prev) {
    let p = fund(label, value_in, &k.spk());
    let mut tx = unsigned(r.version(), &[&p], vec![pay(value_in - 100_000, label)]);
    sign_all(&mut tx, &[k], &[p.out()], r.how(), ChainId::Mainnet, label);
    (tx, p)
}

fn block_cases(k: &Keys) -> Vec<BlockCase> {
    let mut c = BlockCases { cases: Vec::new() };
    let ka = &k.a;
    let kb = &k.b;
    let one_parent = || vec![parent("p1")];

    for r in BOTH {
        let h = r.height();
        let t = r.tag();
        let l = |s: &str| format!("block/{s}/{t}");

        // Baseline.
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("cb-only"), b"")]);
        seal(&mut b, ACT);
        c.push("basic/coinbase-only", r, "A coinbase paying exactly the subsidy, nothing else. Below the activation: legacy root, free-form coinbase script_sig; from it: tagged root and the 80-byte commitment.", b, vec![], None);

        let (tx, p) = block_spend(ka, r, &l("spend"), FUND);
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 100_000, &l("spend"), b""), tx.clone()]);
        seal(&mut b, ACT);
        c.push("basic/coinbase-and-spend", r, "A coinbase claiming subsidy + fees and one signed spend.", b.clone(), vec![p.clone()], None);

        // Chained spends inside the block.
        let p0 = fund(&l("chain"), FUND, &ka.spk());
        let mut t1 = unsigned(r.version(), &[&p0], vec![TxOutput { value: FUND - 100_000, script_pubkey: kb.spk() }]);
        sign_all(&mut t1, &[ka], &[p0.out()], r.how(), ChainId::Mainnet, &l("chain/1"));
        let mid = Prev { txid: t1.txid(), vout: 0, amount: FUND - 100_000, spk: kb.spk(), coinbase_height: None, coinbase_dag_height: None, block_coinbase: false };
        let mut t2 = unsigned(r.version(), &[&mid], vec![pay(FUND - 200_000, &l("chain"))]);
        sign_all(&mut t2, &[kb], &[mid.out()], r.how(), ChainId::Mainnet, &l("chain/2"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 200_000, &l("chain"), b""), t1.clone(), t2.clone()]);
        seal(&mut b, ACT);
        c.push("order/spend-of-an-earlier-transaction", r, "Transaction 2 spends transaction 1's output in the same block.", b, vec![p0.clone()], None);
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 200_000, &l("chain-rev"), b""), t2.clone(), t1.clone()]);
        seal(&mut b, ACT);
        c.push("order/spend-before-the-creating-transaction", r, "The same two transactions in the opposite order: an output is only spendable by a LATER transaction.", b, vec![p0.clone()], Some("missing-input"));

        // Two transactions spending one coin.
        let pd = fund(&l("double"), FUND, &ka.spk());
        let mut d1 = unsigned(r.version(), &[&pd], vec![pay(FUND - 100_000, &l("double/1"))]);
        sign_all(&mut d1, &[ka], &[pd.out()], r.how(), ChainId::Mainnet, &l("double/1"));
        let mut d2 = unsigned(r.version(), &[&pd], vec![pay(FUND - 200_000, &l("double/2"))]);
        sign_all(&mut d2, &[ka], &[pd.out()], r.how(), ChainId::Mainnet, &l("double/2"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("double"), b""), d1, d2]);
        seal(&mut b, ACT);
        c.push("order/two-transactions-spend-one-coin", r, "Two different transactions of the block spend the same coin.", b, vec![pd], Some("double-spend"));

        // Re-audit B1-T13: the rules the block id commits to are checked for
        // EVERY transaction before any witness rule.
        let (mut bad_sig, pb) = block_spend(ka, r, &l("bad-sig-then-overspend/1"), FUND);
        let (sig, pk) = witness(&bad_sig, 0);
        let mut f = sig.clone();
        f[4 + MLDSA_SIG + 5] ^= 0x01; // inside the Falcon nonce: still canonical
        bad_sig = with_ss(&bad_sig, 0, script_sig(&f, &pk));
        let po = fund(&l("bad-sig-then-overspend/2"), FUND, &ka.spk());
        let mut over = unsigned(r.version(), &[&po], vec![pay(FUND + 1, &l("bad-sig-then-overspend/2"))]);
        sign_all(&mut over, &[ka], &[po.out()], r.how(), ChainId::Mainnet, &l("bad-sig-then-overspend/2"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("bad-sig-then-overspend"), b""), bad_sig, over]);
        seal(&mut b, ACT);
        c.push("order/bad-signature-then-overspend", r,
            "Transaction 1's signature does not verify and transaction 2 spends more than its input: the connect checks the rules the block id commits to for every transaction before any witness rule, so the class is inputs-below-outputs (below the activation the failure is then id-committed, re-audit B1-T13).",
            b, vec![pb, po], Some("inputs-below-outputs"));

        // Merkle roots.
        let base = {
            let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 100_000, &l("merkle"), b""), tx.clone()]);
            seal(&mut b, ACT);
            b
        };
        let mut other = base.clone();
        other.header.merkle_root = block_rules::tx_merkle_root(&other.transactions, r == Pre);
        c.push(if r == Pre { "merkle/tagged-root-below-the-activation" } else { "merkle/legacy-root-from-the-activation" }, r,
            "The header carries the OTHER regime's root over the right transactions.", other, vec![p.clone()], Some("bad-merkle-root"));
        let mut zero = base.clone();
        zero.header.merkle_root = MerkleRoot::ZERO;
        c.push("merkle/zero-root", r, "An all-zero header root.", zero, vec![p.clone()], Some("bad-merkle-root"));

        // CVE-2012-2459: duplicate the last transaction of an odd list.
        let (ta, pa) = block_spend(ka, r, &l("cve/a"), FUND);
        let (tb, pb) = block_spend(kb, r, &l("cve/b"), FUND);
        let mut honest = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 200_000, &l("cve"), b""), ta.clone(), tb.clone()]);
        seal(&mut honest, ACT);
        c.push("merkle/three-transactions", r, "Coinbase and two spends (an odd list: the base of the mutation below).", honest.clone(), vec![pa.clone(), pb.clone()], None);
        let mut mutated = honest.clone();
        mutated.transactions.push(tb.clone());
        c.push("merkle/duplicated-last-transaction", r,
            "The block above with its last transaction duplicated and the header unchanged. The legacy root of [cb, a, b, b] equals that of [cb, a, b] (CVE-2012-2459), so below the activation only the duplicate-transaction rule rejects it; the tagged root differs.",
            mutated, vec![pa.clone(), pb.clone()], Some(if r == Pre { "duplicate-tx" } else { "bad-merkle-root" }));
        let mut dup = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 200_000, &l("dup"), b""), ta.clone(), ta.clone()]);
        seal(&mut dup, ACT);
        c.push("dup/same-transaction-twice", r, "The same transaction twice, with the root (and commitment) computed over the duplicated list.", dup, vec![pa.clone()], Some("duplicate-tx"));

        // Coinbase shape and position.
        let mut b = raw_block(h, ACT, one_parent(), vec![tx.clone(), coinbase(subsidy(h), &l("late-cb"), b"")]);
        b.header.merkle_root = b.body_merkle_root_at(ACT);
        c.push("coinbase/not-first", r, "The coinbase is the second transaction.", b, vec![p.clone()], Some("coinbase-format"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("two-cb/1"), b""), coinbase(0, &l("two-cb/2"), b"")]);
        seal(&mut b, ACT);
        c.push("coinbase/two-coinbases", r, "A second coinbase-shaped transaction.", b, vec![], Some("coinbase-format"));
        let mut b = raw_block(h, ACT, one_parent(), vec![]);
        reroot(&mut b, ACT);
        c.push("coinbase/no-transactions", r, "No transactions at all.", b, vec![], Some("coinbase-format"));
        let mut cb2 = coinbase(subsidy(h) / 2, &l("cb-2-outs"), b"");
        cb2.outputs.push(pay(subsidy(h) / 2, &l("cb-2-outs/b")));
        let mut b = raw_block(h, ACT, one_parent(), vec![cb2]);
        seal(&mut b, ACT);
        c.push("coinbase/two-outputs", r, "A coinbase with two outputs (the rule: exactly one, to the miner).", b, vec![], Some("coinbase-output-count"));
        let mut cb0 = coinbase(0, &l("cb-0-outs"), b"");
        cb0.outputs.clear();
        let mut b = raw_block(h, ACT, one_parent(), vec![cb0]);
        seal(&mut b, ACT);
        c.push("coinbase/no-outputs", r, "A coinbase without outputs.", b, vec![], Some("coinbase-output-count"));

        // Coinbase value.
        for (extra, fees, id, err) in [
            (1u64, false, "coinbase/subsidy-plus-one", Some("coinbase-value")),
            (0, true, "coinbase/subsidy-plus-fees", None),
            (1, true, "coinbase/subsidy-plus-fees-plus-one", Some("coinbase-value")),
        ] {
            let mut txs = vec![coinbase(subsidy(h) + extra + if fees { 100_000 } else { 0 }, &l(id), b"")];
            let mut prevs = vec![];
            if fees {
                let (t, p) = block_spend(ka, r, &l(&format!("{id}/spend")), FUND);
                txs.push(t);
                prevs.push(p);
            }
            let mut b = raw_block(h, ACT, one_parent(), txs);
            seal(&mut b, ACT);
            c.push(id, r, &format!("The coinbase claims subsidy ({}){}{}.", subsidy(h),
                if fees { " + the fee (100,000)" } else { "" }, if extra > 0 { " + 1" } else { "" }), b, prevs, err);
        }
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(0, &l("cb-burn"), b"")]);
        seal(&mut b, ACT);
        c.push("coinbase/pays-zero", r, "A coinbase paying 0: paying less than allowed burns the difference.", b, vec![], None);
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(MAX_SUPPLY_SAT + 1, &l("cb-above-max"), b"")]);
        seal(&mut b, ACT);
        c.push("coinbase/above-max-supply", r, "A coinbase output of MAX_SUPPLY_SAT + 1 (MoneyRange, checked before the subsidy rule).", b, vec![], Some("value-out-of-range"));
        let (t1, p1) = block_spend(ka, r, &l("block-total/1"), MAX_SUPPLY_SAT);
        let (t2, p2) = block_spend(kb, r, &l("block-total/2"), MAX_SUPPLY_SAT);
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 200_000, &l("block-total"), b""), t1, t2]);
        seal(&mut b, ACT);
        c.push("value/block-output-total-above-max-supply", r,
            "Two spends of MAX_SUPPLY_SAT coins, each paying MAX_SUPPLY_SAT - 100,000: every transaction is in the money range and the block's outputs sum to about twice MAX_SUPPLY_SAT, which no rule bounds (re-audit B1-T1: like Bitcoin Core, MoneyRange applies to each output, each transaction's output and input totals and the accumulated fees, never to the sum of a block's outputs).",
            b, vec![p1, p2], None);

        // Re-audit B1-T1: chained spends inside the block move the same coins
        // once per hop. Three hops of 4,500,000 GNB: outputs sum to about
        // 13,500,000 GNB, above the 12,500,000 GNB supply, in a valid block.
        let v = 450_000_000_000_000u64;
        let keys = [ka, kb, &k.c, ka];
        let p0 = fund(&l("chained-total"), v, &keys[0].spk());
        let mut prev = p0.clone();
        let mut hops = Vec::new();
        for i in 0..3 {
            let mut t = unsigned(r.version(), &[&prev], vec![TxOutput { value: prev.amount - 100_000, script_pubkey: keys[i + 1].spk() }]);
            sign_all(&mut t, &[keys[i]], &[prev.out()], r.how(), ChainId::Mainnet, &l(&format!("chained-total/{i}")));
            prev = Prev { txid: t.txid(), vout: 0, amount: prev.amount - 100_000, spk: keys[i + 1].spk(), coinbase_height: None, coinbase_dag_height: None, block_coinbase: false };
            hops.push(t);
        }
        let total: u128 = hops.iter().flat_map(|t| &t.outputs).map(|o| u128::from(o.value)).sum();
        assert!(total > u128::from(MAX_SUPPLY_SAT));
        let mut txs = vec![coinbase(subsidy(h) + 300_000, &l("chained-total"), b"")];
        txs.extend(hops);
        let mut b = raw_block(h, ACT, one_parent(), txs);
        seal(&mut b, ACT);
        c.push("value/chained-spends-output-total-above-max-supply", r,
            "Three chained spends of a 4,500,000 GNB coin inside the block (each spends the previous transaction's output, fee 100,000 each): every transaction is in the money range, the outputs sum to about 13,500,000 GNB, above MAX_SUPPLY_SAT (12,500,000 GNB). Valid in both regimes (re-audit B1-T1: the block-wide output total the VAL-11 remediation added rejected it).",
            b, vec![p0], None);

        // Dust and in-block value rules.
        let pdust = fund(&l("dust"), FUND, &ka.spk());
        let mut tdust = unsigned(r.version(), &[&pdust], vec![pay(PAY, &l("dust")), pay(DUST_THRESHOLD - 1, &l("dust/d"))]);
        sign_all(&mut tdust, &[ka], &[pdust.out()], r.how(), ChainId::Mainnet, &l("dust"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("dust"), b""), tdust]);
        seal(&mut b, ACT);
        c.push("value/dust-output-in-block", r, "A non-coinbase output of 545 base units.", b, vec![pdust], Some("dust"));
        let pim = fund_cb(&l("immature"), FUND, &ka.spk(), h - 99);
        let mut tim = unsigned(r.version(), &[&pim], vec![pay(PAY, &l("immature"))]);
        sign_all(&mut tim, &[ka], &[pim.out()], r.how(), ChainId::Mainnet, &l("immature"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("immature"), b""), tim]);
        seal(&mut b, ACT);
        c.push("maturity/immature-coinbase-spend-in-block", r, "A spend of a coinbase 99 blocks deep.", b, vec![pim], Some("immature-coinbase"));
        let (mut tbad, pbad) = block_spend(ka, r, &l("badsig"), FUND);
        let (mut sig, pk) = witness(&tbad, 0);
        sig[4 + 50] ^= 1;
        tbad.inputs[0].script_sig = script_sig(&sig, &pk);
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 100_000, &l("badsig"), b""), tbad]);
        seal(&mut b, ACT);
        c.push("sig/bad-signature-in-block", r, "A spend whose ML-DSA component has one flipped bit.", b, vec![pbad], Some("bad-signature"));

        // 64-byte transaction.
        let p64 = fund(&l("tx64"), FUND, &ka.spk());
        let mut t64 = unsigned(r.version(), &[&p64], vec![TxOutput { value: PAY, script_pubkey: vec![0x51; 5] }]);
        sign_all(&mut t64, &[ka], &[p64.out()], r.how(), ChainId::Mainnet, &l("tx64"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 100_000, &l("tx64"), b""), t64]);
        seal(&mut b, ACT);
        c.push("tx64/64-byte-transaction-in-block", r, "A transaction whose txid preimage is exactly 64 bytes: its 5-byte output script is not an output kind of this chain (connect time); from the activation the context-free 64-byte rule (VAL-10) refuses it first.",
            b, vec![p64], Some(if r == Pre { "bad-output-script" } else { "tx-64-bytes" }));

        // BIP30.
        let stale = Prev { txid: tx.txid(), vout: 0, amount: 777, spk: dest("bip30/stale"), coinbase_height: None, coinbase_dag_height: None, block_coinbase: false };
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 100_000, &l("bip30-tx"), b""), tx.clone()]);
        seal(&mut b, ACT);
        c.push("bip30/transaction-output-overwrites-an-unspent-coin", r,
            "An unspent coin already sits at the spend's output 0 in the parent state: invalid at every height on this chain (BIP30).",
            b, vec![p.clone(), stale], Some("bip30"));
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("bip30-cb"), b"")]);
        seal(&mut b, ACT);
        let stale_cb = Prev { txid: b.transactions[0].txid(), vout: 0, amount: 777, spk: dest("bip30/stale-cb"), coinbase_height: Some(h - 500), coinbase_dag_height: None, block_coinbase: false };
        c.push("bip30/coinbase-overwrites-an-unspent-coin", r,
            "An unspent coin already sits at the coinbase's output 0 (a repeated coinbase txid): invalid at every height on this chain (BIP30).", b, vec![stale_cb], Some("bip30"));

        // Version rule inside a block.
        let (tv, pv) = block_spend(ka, if r == Pre { Post } else { Pre }, &l("wrong-version"), FUND);
        let mut tv = tv;
        if r == Pre {
            // A version-3 transaction signed over sighash v2 below the activation.
            tv = unsigned(3, &[&pv], vec![pay(FUND - 100_000, &l("wrong-version"))]);
            sign_all(&mut tv, &[ka], &[pv.out()], How::V2, ChainId::Mainnet, &l("wrong-version/v3"));
        }
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h) + 100_000, &l("version"), b""), tv]);
        seal(&mut b, ACT);
        if r == Pre {
            c.push("version/v3-over-sighash-v2-in-block", r, "A version-3 transaction signed over sighash v2 below the activation: non-standard, but a block carrying it is valid.", b, vec![pv], None);
        } else {
            c.push("version/v1-in-block", r, "A version-1 transaction (sighash v2) in a block at the activation height.", b, vec![pv], Some("bad-version"));
        }

        // Witness malleation: same txids, different witness bytes.
        let mut padded = base.clone();
        padded.transactions[1].inputs[0].script_sig.extend_from_slice(&[0u8; 16]);
        c.push("witness/padded-witness-same-block-id", r,
            "The coinbase-and-spend block with 16 zero bytes appended to the spend's script_sig: same txids, same header. Below the activation this chain's exact v2 framing refuses the padded witness (connect time); from it the witness commitment no longer matches.",
            padded, vec![p.clone()], Some(if r == Pre { "witness-malformed" } else { "witness-commitment" }));
    }

    // ── Coinbase commitment (from the activation) ───────────────────────────
    {
        let r = Post;
        let h = r.height();
        let l = |s: &str| format!("block/commitment/{s}");
        let two_parents = vec![parent("p1"), parent("p2")];
        let (tx, p) = block_spend(ka, r, &l("spend"), FUND);
        let mut base = raw_block(h, ACT, two_parents.clone(), vec![coinbase(subsidy(h) + 100_000, &l("base"), b"extra"), tx.clone()]);
        seal(&mut base, ACT);
        c.push("commitment/two-parents-valid", r, "The base of the commitment cases: two parents, a spend, the 80-byte commitment followed by miner bytes.", base.clone(), vec![p.clone()], None);

        let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = base.clone();
            f(&mut b.transactions[0].inputs[0].script_sig);
            reroot(&mut b, ACT);
            b
        };
        for (id, desc, b, err) in [
            ("commitment/script-sig-79-bytes", "The coinbase script_sig is the first 79 bytes of the commitment.",
                mutate(&|ss: &mut Vec<u8>| ss.truncate(79)), "cb-commitment-missing"),
            ("commitment/bad-tag", "The tag reads GNB-CB02.", mutate(&|ss: &mut Vec<u8>| ss[7] = b'2'), "cb-commitment-tag"),
            ("commitment/height-plus-one", "The committed height is the block height + 1.",
                mutate(&|ss: &mut Vec<u8>| ss[8..16].copy_from_slice(&(h + 1).to_le_bytes())), "cb-height"),
            ("commitment/height-big-endian", "The committed height in big-endian byte order.",
                mutate(&|ss: &mut Vec<u8>| ss[8..16].copy_from_slice(&h.to_be_bytes())), "cb-height"),
            ("commitment/witness-root-zero", "The witness root is 32 zero bytes.",
                mutate(&|ss: &mut Vec<u8>| ss[48..80].copy_from_slice(&[0; 32])), "witness-commitment"),
        ] {
            c.push_full(format!("{id}/post"), desc, ACT, b, vec![p.clone()], Some(err), "full", Pow::Skip);
        }
        let mut b = base.clone();
        b.header.parents.reverse();
        reroot(&mut b, ACT);
        c.push("commitment/parents-reordered", r, "The header lists the two parents in the other order (the commitment covers header order).", b, vec![p.clone()], Some("cb-parents"));
        let mut b = base.clone();
        b.header.parents.pop();
        reroot(&mut b, ACT);
        c.push("commitment/parent-dropped", r, "The header drops the second parent.", b, vec![p.clone()], Some("cb-parents"));

        // The witness root covers [0^32, wtxid(tx_1), ...]: committing to the
        // coinbase's own position with anything else fails.
        let mut b = raw_block(h, ACT, two_parents.clone(), vec![coinbase(subsidy(h) + 100_000, &l("wr-cb"), b""), tx.clone()]);
        let ids: Vec<[u8; 32]> = vec![b.transactions[0].wtxid(), tx.wtxid()];
        let wrong = block_rules::tagged_merkle_root(&ids);
        let cmt = block_rules::coinbase_commitment(h, &b.header.parents, &wrong);
        let extra = std::mem::take(&mut b.transactions[0].inputs[0].script_sig);
        b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&cmt, &extra);
        reroot(&mut b, ACT);
        c.push("commitment/witness-root-with-coinbase-wtxid", r, "The witness root computed with the coinbase's own (pre-commitment) wtxid at position 0 instead of 32 zero bytes.",
            b, vec![p.clone()], Some("witness-commitment"));
        let mut b = raw_block(h, ACT, two_parents.clone(), vec![coinbase(subsidy(h) + 100_000, &l("wr-txid"), b""), tx.clone()]);
        let ids: Vec<[u8; 32]> = vec![[0; 32], tx.txid()];
        let wrong = block_rules::tagged_merkle_root(&ids);
        let cmt = block_rules::coinbase_commitment(h, &b.header.parents, &wrong);
        let extra = std::mem::take(&mut b.transactions[0].inputs[0].script_sig);
        b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&cmt, &extra);
        reroot(&mut b, ACT);
        c.push("commitment/witness-root-over-txids", r, "The witness root computed over txids instead of wtxids.", b, vec![p.clone()], Some("witness-commitment"));

        // Miner bytes up to the script_sig cap (114,834 bytes).
        let prefix_len = format!("gnb-block-vectors/{}/", l("max-extra")).len();
        let mut b = raw_block(h, ACT, one_parent(), vec![coinbase(subsidy(h), &l("max-extra"), &vec![0x42; MAX_SCRIPT_SIG_LEN - 80 - prefix_len])]);
        seal(&mut b, ACT);
        assert_eq!(b.transactions[0].inputs[0].script_sig.len(), MAX_SCRIPT_SIG_LEN);
        c.push("commitment/script-sig-at-the-cap", r, "The commitment followed by miner bytes up to exactly 114,834 script_sig bytes (the cap).", b.clone(), vec![], None);
        let mut over = b.clone();
        over.transactions[0].inputs[0].script_sig.push(0x42);
        reroot(&mut over, ACT);
        let bytes = over.to_wire_bytes();
        c.push_full("commitment/script-sig-above-the-cap/post".into(), "One miner byte more: a 114,835-byte script_sig does not decode.", ACT, over, vec![], Some("decode"), "full", Pow::Skip);
        c.cases.last_mut().unwrap().raw = Some(bytes);

        // The commitment is not required (and not checked) below the activation.
        let mut b = raw_block(Pre.height(), ACT, one_parent(), vec![coinbase(subsidy(Pre.height()), "block/commitment/pre-wrong", b"")]);
        let cmt = block_rules::coinbase_commitment(Pre.height() + 7, &[], &MerkleRoot([9; 32]));
        b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&cmt, b"");
        reroot(&mut b, ACT);
        c.push("commitment/wrong-commitment-ignored-below-the-activation", Pre, "A coinbase script_sig that looks like a commitment with the wrong height, parents and root: free-form below the activation.", b, vec![], None);

        // The mainnet boundary.
        for (hh, err) in [(MAINNET_ACT - 1, Some("witness-commitment-suffix")), (MAINNET_ACT, Some("cb-commitment-missing"))] {
            let mut b = raw_block(hh, MAINNET_ACT, one_parent(), vec![coinbase(miner_subsidy(hh), &format!("block/commitment/mainnet-{hh}"), b"")]);
            b.header.merkle_root = b.body_merkle_root_at(MAINNET_ACT);
            c.push_full(format!("commitment/no-commitment-at-mainnet-height-{hh}"),
                &format!("A coinbase with no commitment at all (paying the miner's PoWit share of the subsidy, v2 body root), at height {hh} under the mainnet schedule: below the activation the `|wc:` witness commitment is missing; from it the 80-byte commitment."),
                MAINNET_ACT, b, vec![], err, "full", Pow::Skip);
        }
        {
            let hh = MAINNET_ACT - 1;
            let (tx, p) = block_spend(ka, Pre, "block/commitment/mainnet-wc/spend", FUND);
            let mut b = raw_block(hh, MAINNET_ACT, one_parent(), vec![coinbase(miner_subsidy(hh) + 100_000, "block/commitment/mainnet-wc", b""), tx]);
            seal(&mut b, MAINNET_ACT);
            c.push_full(format!("commitment/wc-suffix-at-mainnet-height-{hh}"),
                &format!("Height {} under the mainnet schedule (PoWit active, below the activation): the coinbase pays the miner's share + the fee and its script_sig ends with `|wc:` and the witness root.", grouped(hh)),
                MAINNET_ACT, b.clone(), vec![p.clone()], None, "full", Pow::Skip);
            let mut over = b.clone();
            over.transactions[0].outputs[0].value += 1;
            reroot(&mut over, MAINNET_ACT);
            c.push_full(format!("coinbase/powit-miner-share-plus-one-at-mainnet-height-{hh}"),
                "The same block with the coinbase claiming one base unit above the miner's share + fee: from the PoWit height the witness pool (20% of the subsidy) is not the miner's.",
                MAINNET_ACT, over, vec![p.clone()], Some("coinbase-value"), "full", Pow::Skip);
            let mut stale = b.clone();
            stale.transactions[1].inputs[0].script_sig.extend_from_slice(&[0u8; 8]);
            c.push_full(format!("commitment/wc-suffix-stale-witness-at-mainnet-height-{hh}"),
                "The same block with 8 bytes appended to the spend's witness: same txids and header root, but the `|wc:` commitment no longer matches the witnesses.",
                MAINNET_ACT, stale, vec![p], Some("witness-commitment-suffix"), "full", Pow::Skip);
        }

        // 256 parents (the cap) are committed; 257 do not decode.
        let parents: Vec<[u8; 32]> = (0..256).map(|i| parent(&format!("many/{i}"))).collect();
        let mut b = raw_block(h, ACT, parents.clone(), vec![coinbase(subsidy(h), &l("256-parents"), b"")]);
        seal(&mut b, ACT);
        c.push("structure/256-parents", r, "256 parents (MAX_PARENTS), all committed.", b.clone(), vec![], None);
        let mut b257 = b.clone();
        b257.header.parents.push(parent("many/256"));
        reroot(&mut b257, ACT);
        let bytes = b257.to_wire_bytes();
        c.push_full("structure/257-parents/post".into(), "257 parents: the header decoder refuses more than 256.", ACT, b257, vec![], Some("decode"), "full", Pow::Skip);
        c.cases.last_mut().unwrap().raw = Some(bytes);

        // A repeated parent (audit B2-T10): valid below the activation, invalid
        // from it. The commitment covers the list as written, so the repeat is
        // the only fault. (A parent in the past of another parent needs DAG
        // context: reference/ghostdag_vectors.json, parents/redundant-ancestor.)
        for r in [Pre, Post] {
            let hh = r.height();
            let mut b = raw_block(hh, ACT, vec![parent("p1"), parent("p2"), parent("p1")],
                vec![coinbase(subsidy(hh), &format!("block/parents/duplicate/{}", r.tag()), b"")]);
            seal(&mut b, ACT);
            c.push("parents/duplicate", r,
                "The header lists parent p1 twice (p1, p2, p1); from the activation the coinbase commitment covers that list. Valid below the activation (the DAG treats the list as a set), invalid from it.",
                b, vec![], if r == Pre { None } else { Some("duplicate-parent") });
        }
        // Both heights are past the mainnet PoWit height: the coinbase pays
        // the miner's share of the subsidy (no witness shares).
        for (hh, err) in [(MAINNET_ACT - 1, None), (MAINNET_ACT, Some("duplicate-parent"))] {
            let mut b = raw_block(hh, MAINNET_ACT, vec![parent("p1"), parent("p1")],
                vec![coinbase(miner_subsidy(hh), &format!("block/parents/duplicate/mainnet-{hh}"), b"")]);
            seal(&mut b, MAINNET_ACT);
            c.push_full(format!("parents/duplicate-at-mainnet-height-{hh}"),
                &format!("Parent p1 listed twice at height {hh} under the mainnet schedule (activation {}).", grouped(MAINNET_ACT)),
                MAINNET_ACT, b, vec![], err, "full", Pow::Skip);
        }

        // Minimal varints only (docs/CONSENSUS.md, "Wire encoding"), in both
        // regimes: a valid block's bytes with one one-byte varint written in
        // the 3-byte form `FD v 00`. The block id and the decoded contents
        // would be the same; the bytes do not decode.
        let widen = |w: &[u8], at: usize| -> Vec<u8> {
            assert!(w[at] < 0xFD, "a one-byte varint at {at}");
            let mut v = w[..at].to_vec();
            v.extend_from_slice(&[0xFD, w[at], 0x00]);
            v.extend_from_slice(&w[at + 1..]);
            v
        };
        let w = base.to_wire_bytes();
        let hdr = base.header.to_wire_bytes(base.blue_score, base.height).len();
        c.push_full("decode/non-minimal-tx-count/post".into(),
            "The two-parent commitment base block with its transaction count written as FD 02 00 (same block id and contents): not the minimal encoding of 2, the decoder refuses the bytes.",
            ACT, base.clone(), vec![], Some("decode"), "full", Pow::Skip);
        c.cases.last_mut().unwrap().raw = Some(widen(&w, hdr));
        // The coinbase's locktime ends `FD 00` (locktime is not a consensus
        // rule): a decoder with lenient varints that frames each transaction at
        // its re-encoded length (the decoder before the fix) stops two bytes
        // early, reads the shielded count as `FD 00 00` (0) from those two
        // locktime bytes and the real count byte, and accepts the bytes as
        // this (valid) block. A lenient decoder that frames by the bytes
        // consumed accepts them too; only the minimal-varint rule refuses them.
        let mut cb = coinbase(subsidy(Pre.height()), "block/decode/pre", b"");
        cb.locktime = u32::from_le_bytes([0x11, 0x22, 0xFD, 0x00]);
        let mut pre = raw_block(Pre.height(), ACT, one_parent(), vec![cb]);
        reroot(&mut pre, ACT);
        let w = pre.to_wire_bytes();
        assert!(w.ends_with(&[0x11, 0x22, 0xFD, 0x00, 0x00]), "locktime, then a shielded count of 0");
        let hdr = pre.header.to_wire_bytes(pre.blue_score, pre.height).len();
        // Transaction count, version, input count, outpoint, script_sig length.
        let ss_len_at = hdr + 1 + 4 + 1 + 36;
        assert_eq!(w[ss_len_at] as usize, pre.transactions[0].inputs[0].script_sig.len());
        c.push_full("decode/non-minimal-script-sig-length/pre".into(),
            "A coinbase-only block below the activation with the coinbase's script_sig length written in the 3-byte form (same block id and contents) and a coinbase locktime whose last two bytes are FD 00: the decoder refuses the bytes at every height. Decoders before the fix accepted them as this block: they framed the shielded count at the coinbase's re-encoded length, two bytes early, and read it as FD 00 00 (0).",
            ACT, pre, vec![], Some("decode"), "full", Pow::Skip);
        c.cases.last_mut().unwrap().raw = Some(widen(&w, ss_len_at));
    }

    // ── Same-block coinbase spend (VAL-3) ───────────────────────────────────
    for (r, scope, err, desc) in [
        (Pre, "full", Some("same-block-coinbase"), "The block's spend spends output 0 of the block's OWN coinbase: invalid at every height on this chain."),
        (Post, "connect", Some("same-block-coinbase"), "The same spend at the activation height, evaluated by the connect-time rule alone (scope `connect`): invalid (VAL-3)."),
        (Post, "full", Some("witness-commitment"), "The same spend at the activation height through every rule: such a block cannot carry a valid commitment (the commitment covers the spend's wtxid, which covers the coinbase txid, which covers the commitment), so the commitment check rejects it first."),
    ] {
        let h = r.height();
        let l = format!("block/same-block-cb/{}/{scope}", r.tag());
        let value = subsidy(h) + 100_000;
        let mk = |cb: &Transaction| {
            let src = Prev { txid: cb.txid(), vout: 0, amount: value, spk: ka.spk(), coinbase_height: None, coinbase_dag_height: None, block_coinbase: false };
            let mut spend = unsigned(r.version(), &[&src], vec![pay(subsidy(h), &l)]);
            sign_all(&mut spend, &[ka], &[src.out()], r.how(), ChainId::Mainnet, &l);
            raw_block(h, ACT, vec![parent("p1")], vec![cb.clone(), spend])
        };
        let cb0 = Transaction { outputs: vec![TxOutput { value, script_pubkey: ka.spk() }], ..coinbase(value, &l, b"") };
        let mut b = mk(&cb0);
        if scope == "full" && r == Post {
            // The best a miner can do: commit to the body spending the
            // commitment-less coinbase, then point the spend at the committed
            // coinbase, which changes the spend's wtxid and so the witness root.
            let cmt = block_rules::expected_coinbase_commitment(&b);
            let mut cb1 = cb0.clone();
            cb1.inputs[0].script_sig.splice(0..0, cmt.iter().copied());
            b = mk(&cb1);
        }
        reroot(&mut b, ACT);
        c.push_full(format!("same-block-coinbase/{}/{scope}", r.tag()), desc, ACT, b, vec![], err, scope, Pow::Skip);
    }

    // ── Halving boundary (post-activation regime) ───────────────────────────
    for (hh, value, err) in [
        (HALVING_INTERVAL - 1, miner_subsidy(HALVING_INTERVAL - 1), None),
        (HALVING_INTERVAL, miner_subsidy(HALVING_INTERVAL - 1), Some("coinbase-value")),
        (HALVING_INTERVAL, miner_subsidy(HALVING_INTERVAL), None),
    ] {
        let mut b = raw_block(hh, ACT, vec![parent("p1")], vec![coinbase(value, &format!("block/halving/{hh}/{value}"), b"")]);
        seal(&mut b, ACT);
        c.push_full(format!("coinbase/halving/height-{hh}-claims-{value}"),
            &format!("The subsidy halves at height 4,204,800 ({} -> {}); with PoWit the miner's share (no witness shares) is the subsidy minus its 20% witness pool ({} -> {}); this coinbase claims {value} at height {hh}.",
                INITIAL_SUBSIDY_SAT, INITIAL_SUBSIDY_SAT >> 1, miner_subsidy(HALVING_INTERVAL - 1), miner_subsidy(HALVING_INTERVAL)),
            ACT, b, vec![], err, "full", Pow::Skip);
    }

    // ── Pow limit (POW-3) ───────────────────────────────────────────────────
    let mainnet_pre = MAINNET_ACT - 1;
    let (mainnet_pre_id, mainnet_pre_desc) = (
        format!("pow/mainnet-{mainnet_pre}-pow-limit-bits"),
        format!("bits = 0x2100ffff at height {} under the mainnet schedule.", grouped(mainnet_pre)),
    );
    let (mainnet_at_id, mainnet_at_desc) = (
        format!("pow/mainnet-{MAINNET_ACT}-pow-limit-bits"),
        format!("bits = 0x2100ffff at height {} under the mainnet schedule.", grouped(MAINNET_ACT)),
    );
    for (id, act, hh, bits, pow, err, desc) in [
        ("pow/pow-limit-bits-below-the-activation", ACT, ACT - 1, POW_LIMIT_BITS, Pow::Full, None,
            "bits = 0x2100ffff (the pre-activation pow limit) below the activation; the proof is evaluated and holds (at this target all but about 1 output in 65,536 do, so this case pins the limit, not the proof: see pow/genesis-bits-*)."),
        ("pow/pow-limit-bits-from-the-activation", ACT, ACT, POW_LIMIT_BITS, Pow::Limit, Some("pow-limit"),
            "bits = 0x2100ffff from the activation: above the pow limit (the genesis target 0x1f0e9036); refused before any evaluation."),
        ("pow/genesis-bits-from-the-activation", ACT, ACT, GENESIS_BITS, Pow::Limit, None,
            "bits = 0x1f0e9036 (the genesis target) from the activation: exactly the pow limit (the proof itself is not evaluated: pow `limit`)."),
        ("pow/genesis-target-plus-one-from-the-activation", ACT, ACT, GENESIS_BITS + 1, Pow::Limit, Some("pow-limit"),
            "bits = 0x1f0e9037: one mantissa unit above the genesis target, from the activation."),
        ("pow/genesis-target-plus-one-below-the-activation", ACT, ACT - 1, GENESIS_BITS + 1, Pow::Limit, None,
            "bits = 0x1f0e9037 below the activation: within the old pow limit."),
        (mainnet_pre_id.as_str(), MAINNET_ACT, mainnet_pre, POW_LIMIT_BITS, Pow::Limit, None, mainnet_pre_desc.as_str()),
        (mainnet_at_id.as_str(), MAINNET_ACT, MAINNET_ACT, POW_LIMIT_BITS, Pow::Limit, Some("pow-limit"), mainnet_at_desc.as_str()),
        ("pow/negative-bits", ACT, ACT, 0x0480_0001, Pow::Limit, Some("bad-bits"), "bits with the sign bit set: malformed."),
        ("pow/zero-mantissa-bits", ACT, ACT - 1, 0x1F00_0000, Pow::Limit, Some("bad-bits"), "bits with a zero mantissa: malformed."),
        ("pow/exponent-out-of-range-bits", ACT, ACT - 1, 0x2300_0001, Pow::Limit, Some("bad-bits"), "bits with exponent 0x23: the target does not fit 256 bits."),
        ("pow/mantissa-overflow-bits", ACT, ACT - 1, 0x2201_0000, Pow::Limit, Some("bad-bits"), "bits 0x22010000: the target is 2^264."),
        ("pow/non-canonical-bits", ACT, ACT - 1, 0x2100_7FFF, Pow::Limit, Some("bad-bits"),
            "bits 0x21007fff decode (as Bitcoin Core's SetCompact decodes them) to 0x7fff << 240, within the pow limit, but the canonical encoding of that target is 0x207fff00: non-canonical bits never validate (audit POW-9), at every height. No block an expected_bits check accepts is affected (expected bits are always canonical)."),
    ] {
        let mut b = raw_block(hh, act, vec![parent("p1")], vec![coinbase(miner_subsidy(hh), &format!("block/{id}"), b"")]);
        b.header.bits = bits;
        seal(&mut b, act);
        if pow == Pow::Full {
            b.header.nonce = mine_from(&b, 0);
        }
        c.push_full(id.to_string(), desc, act, b, vec![], err, "full", pow);
    }

    // ── The GnB-SMH proof itself (pow `full`) ───────────────────────────────
    // At the genesis target 0x1f0e9036 about one output in 4,500 is below the
    // target, so a changed preimage, nonce, hash or comparison fails the mined
    // case, and a proof check that is skipped or inverted fails the other. The
    // bits are the hardened pow limit exactly (and within the node test
    // build's pinned limit 0x2100ffff, so both runners evaluate both).
    {
        let id = "pow/genesis-bits";
        let mut b = raw_block(ACT, ACT, vec![parent("p1")], vec![coinbase(subsidy(ACT), &format!("block/{id}"), b"")]);
        b.header.bits = GENESIS_BITS;
        seal(&mut b, ACT);
        b.header.nonce = mine_from(&b, GENESIS_BITS_NONCE_HINT);
        let mut bad = b.clone();
        bad.header.nonce += 1;
        while proof_holds(&bad) {
            bad.header.nonce += 1;
        }
        c.push_full(format!("{id}-mined/post"),
            &format!("bits = 0x1f0e9036 (the genesis target, the pow limit from the activation) and a nonce ({}) whose GnB-SMH output is below the target: the proof is evaluated and holds.", b.header.nonce),
            ACT, b, vec![], None, "full", Pow::Full);
        c.push_full(format!("{id}-proof-fails/post"),
            &format!("The same block with nonce {}: its GnB-SMH output is not below the target, so the proof fails.", bad.header.nonce),
            ACT, bad, vec![], Some("bad-pow"), "full", Pow::Full);
    }

    // ── Block size: the wire encoding at every height on this chain ─────────
    // Filler: one signed transaction with many identical outputs. 546-unit
    // outputs are 29 wire bytes but 24 bincode bytes; 5,000,000,000-unit
    // outputs are 29 wire bytes but 30 bincode bytes. (The audit's VAL-12
    // measured bincode below the activation; this chain never did. The wire
    // header writes the uncommitted blue_score as a fixed-width u64, so the
    // measure is the same for every copy of a block id, re-audit B1-T0.)
    for (id, r, value, target_wire, target_bincode, err) in [
        ("size/wire-1000001-bincode-below", Post, DUST_THRESHOLD, Some(MAX_BLOCK_SIZE + 1), None, Some("block-size")),
        ("size/wire-1000001-bincode-below", Pre, DUST_THRESHOLD, Some(MAX_BLOCK_SIZE + 1), None, Some("block-size")),
        ("size/wire-exactly-1000000", Post, DUST_THRESHOLD, Some(MAX_BLOCK_SIZE), None, None),
        ("size/wire-exactly-1000000", Pre, DUST_THRESHOLD, Some(MAX_BLOCK_SIZE), None, None),
        ("size/bincode-1000001-wire-below", Pre, 5_000_000_000, None, Some(MAX_BLOCK_SIZE + 1), None),
        ("size/bincode-1000001-wire-below", Post, 5_000_000_000, None, Some(MAX_BLOCK_SIZE + 1), None),
    ] {
        let h = r.height();
        let l = format!("block/{id}/{}", r.tag());
        let unit_wire = 29usize;
        let unit = if value == DUST_THRESHOLD { 29 } else { 30 }; // in the measure that matters
        let measure = |b: &Block| if target_wire.is_some() { b.wire_size() } else { bincode_size(b) };
        let want = target_wire.or(target_bincode).unwrap();
        // The coin pays every output and a 4,000,000 fee (above the minimum).
        let p = fund(&l, 40_000 * value + 4_000_000, &ka.spk());
        let one = pay(value, &format!("{l}/out"));
        let filler = |n: usize| {
            let mut tx = unsigned(r.version(), &[&p], vec![one.clone(); n]);
            tx.outputs.push(pay(40_000 * value - value * n as u64, &format!("{l}/change")));
            sign_all(&mut tx, &[ka], &[p.out()], r.how(), ChainId::Mainnet, &l);
            assert!(min_fee(tx.wire_size(true)) < 4_000_000);
            tx
        };
        let build = |tx: &Transaction, extra: usize| {
            let mut b = raw_block(h, ACT, vec![parent("p1")], vec![coinbase(0, &l, &vec![0x20; extra]), tx.clone()]);
            seal(&mut b, ACT);
            b
        };
        let mut n = (MAX_BLOCK_SIZE - 10_000) / unit;
        let (tx, b) = loop {
            let tx = filler(n);
            let now = measure(&build(&tx, 0));
            if now > want {
                n -= (now - want) / unit + 1;
                continue;
            }
            if want - now > 150 {
                n += (want - now - 100) / unit;
                continue;
            }
            match (0..200).map(|e| build(&tx, e)).find(|b| measure(b) == want) {
                Some(b) => break (tx, b),
                None => n -= 1,
            }
        };
        match (target_wire, target_bincode) {
            (Some(w), None) => {
                assert_eq!(b.wire_size(), w);
                assert!(bincode_size(&b) < MAX_BLOCK_SIZE);
            }
            (None, Some(bc)) => {
                assert_eq!(bincode_size(&b), bc);
                assert!(b.wire_size() < MAX_BLOCK_SIZE);
            }
            _ => unreachable!(),
        }
        // Locate the run of identical outputs in the encoding.
        let bytes = b.to_wire_bytes();
        let unit = {
            let o = &tx.outputs[0];
            let mut u = o.value.to_le_bytes().to_vec();
            u.push(o.script_pubkey.len() as u8);
            u.extend_from_slice(&o.script_pubkey);
            u
        };
        assert_eq!(unit.len(), unit_wire);
        let start = bytes.windows(unit.len()).position(|w| w == unit.as_slice()).expect("filler output in the encoding");
        assert!(bytes[start..start + n * unit.len()].chunks(unit.len()).all(|ch| ch == unit.as_slice()));
        let desc = format!(
            "A coinbase and one signed transaction with {n} outputs of {value}: wire size {}, bincode size {}. The limit (1,000,000) is measured on the wire encoding at every height (bincode is no consensus measure on this chain).",
            b.wire_size(), bincode_size(&b)
        );
        let rle = Some((start, unit.len(), n));
        c.push(id, r, &desc, b.clone(), vec![p.clone()], err);
        c.cases.last_mut().unwrap().rle = rle;
        // Re-audit B1-T0 / B2-T8: the same block id with other blue_score
        // values (the field is not committed, and a node stores and serves
        // the value derived from the parents): the size verdict is the same
        // for every copy, the wire header writing blue_score as a
        // fixed-width u64 (the run of outputs starts at the same offset).
        // Paired with the two blocks at the wire limit below the activation.
        if target_wire.is_some() && r == Pre {
            for (tag, blue) in [("blue-score-0", 0u64), ("blue-score-max", u64::MAX)] {
                let mut copy = b.clone();
                copy.blue_score = blue;
                assert_eq!(copy.block_hash(), b.block_hash());
                assert_eq!(copy.wire_size(), b.wire_size());
                assert_eq!(copy.to_wire_bytes()[start..start + n * unit.len()], bytes[start..start + n * unit.len()]);
                let desc = format!(
                    "The block of {id}/pre (same block id) carrying blue_score {blue}: wire size {} (blue_score is a fixed-width u64 there), bincode size {}. The verdict is that of every other copy of the id (re-audit B1-T0 / B2-T8).",
                    copy.wire_size(), bincode_size(&copy)
                );
                c.push_full(format!("{id}-{tag}/pre"), &desc, ACT, copy, vec![p.clone()], err, "full", Pow::Skip);
                c.cases.last_mut().unwrap().rle = rle;
            }
        }
    }

    c.cases
}

fn block_case_json(case: &BlockCase) -> J {
    let b = &case.block;
    let bytes = case.raw.clone().unwrap_or_else(|| b.to_wire_bytes());
    let encoding = match case.rle {
        None => J::O(vec![("block", hx(&bytes))]),
        Some((start, unit, n)) => {
            let end = start + unit * n;
            J::O(vec![("block_parts", J::A(vec![
                J::O(vec![("hex", hx(&bytes[..start])), ("repeat", J::N(1))]),
                J::O(vec![("hex", hx(&bytes[start..start + unit])), ("repeat", J::N(n as u64))]),
                J::O(vec![("hex", hx(&bytes[end..])), ("repeat", J::N(1))]),
            ]))])
        }
    };
    let decodes = case.raw.is_none();
    let derived = if decodes {
        let ids: Vec<[u8; 32]> = b.transactions.iter().map(Transaction::txid).collect();
        J::O(vec![
            ("block_hash", hx(&b.block_hash())),
            ("txids", J::A(ids.iter().map(|i| hx(i)).collect())),
            ("legacy_merkle_root", hx(&block_rules::legacy_merkle_root(&ids).0)),
            ("tagged_merkle_root", hx(&block_rules::tagged_merkle_root(&ids).0)),
            ("witness_root", hx(&block_rules::witness_root(&b.transactions).0)),
            ("parents_commitment", hx(&block_rules::parents_commitment(&b.header.parents))),
            ("subsidy", dec(core::tokenomics::block_subsidy_sat(b.height))),
            ("wire_size", J::N(b.wire_size() as u64)),
        ])
    } else {
        J::Null
    };
    let mut fields: Vec<(&'static str, J)> = vec![
        ("id", s(case.id.clone())),
        ("description", s(case.description.clone())),
        ("network", s("mainnet")),
        ("activation_height", dec(case.activation)),
        ("activation_source", s(activation_source(ChainId::Mainnet, case.activation))),
        ("height", dec(b.height)),
        ("regime", s(regime_at(b.height, case.activation))),
        ("scope", s(case.scope)),
        ("pow", s(match case.pow { Pow::Skip => "skip", Pow::Limit => "limit", Pow::Full => "full" })),
        ("prevouts", J::A(case.prevouts.iter().map(prev_json).collect())),
    ];
    if let J::O(enc) = encoding {
        fields.extend(enc);
    }
    fields.push(("expected", J::O(vec![
        ("verdict", s(if case.error.is_none() { "valid" } else { "invalid" })),
        ("error_class", case.error.map(s).unwrap_or(J::Null)),
    ])));
    fields.push(("derived", derived));
    J::O(fields)
}

fn block_doc(k: &Keys) -> (J, usize) {
    let cases = block_cases(k);
    let n = cases.len();
    let doc = J::O(vec![
        ("format", s("gnb-consensus-block-vectors/1")),
        ("description", s(
            "Block validity in both activation regimes. Each case is one block (hex of Block::to_wire_bytes; big blocks as \
             `block_parts`, the concatenation of each part's hex repeated `repeat` times) at header height `height` under the \
             `activation_height` (`activation_source` as in tx_vectors.json), connected on a parent state whose UTXO view holds exactly `prevouts`. Scope `full`: \
             decode, the structural rules, the hardening block rules, the pow limit (`pow`: `skip` = not checked, `limit` = bits \
             decode and the target is within the pow limit of the height, `full` = also the GnB-SMH proof), the context-free \
             MoneyRange / encoding limits, then the connect-time rules (BIP30, every transaction, coinbase value). Scope \
             `connect`: decode, then the connect-time rules only. Header-chain context (parents known, height = max parent height \
             + 1, expected bits, timestamps) is not part of these vectors. Format: docs/testing/VECTORS.md.")),
        ("generator", s("crates/gnb-crypto/tests/gen_consensus_vectors.rs")),
        ("constants", constants_json()),
        ("keys", keys_json(k)),
        ("cases", J::A(cases.iter().map(block_case_json).collect())),
    ]);
    (doc, n)
}

fn keys() -> Keys {
    let a = Key::seeded("A");
    let a_raw = a.raw("A-raw");
    let a_mldsa = a.mldsa_only("A-mldsa-only");
    Keys { b: Key::seeded("B"), c: Key::seeded("C"), a, a_raw, a_mldsa }
}

#[test]
#[ignore = "generator: ~1 minute of seeded signing; run explicitly (CI does, then diffs the files)"]
fn regenerate_consensus_vectors() {
    let k = keys();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference");
    let (tx, ntx) = tx_doc(&k);
    let (blk, nblk) = block_doc(&k);
    assert!(ntx >= 150, "{ntx} tx cases");
    assert!(nblk >= 60, "{nblk} block cases");
    let write = std::env::var("GNB_WRITE_VECTORS").is_ok_and(|v| v == "1");
    for (name, doc) in [("tx_vectors.json", tx), ("block_vectors.json", blk)] {
        let text = to_json(&doc);
        let path = root.join(name);
        if write {
            std::fs::write(&path, &text).unwrap();
            eprintln!("wrote {} ({} bytes)", path.display(), text.len());
        } else {
            let frozen = std::fs::read_to_string(&path).unwrap_or_default();
            assert!(frozen == text, "{name} is not what the generator produces; rerun with GNB_WRITE_VECTORS=1 and review the diff");
        }
    }
    eprintln!("{ntx} tx cases, {nblk} block cases");
}
