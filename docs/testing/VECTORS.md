# Data-driven consensus vectors

`reference/tx_vectors.json` and `reference/block_vectors.json` pin transaction
and block validity in both regimes of the hardening activation, the way
Bitcoin Core's `src/test/data/tx_valid.json`, `tx_invalid.json` and
`script_tests.json` pin Bitcoin's rules. Each case is data: bytes, the UTXO
state they are evaluated against, a height, an activation height, the
expected verdict with the class of the rule that rejects it, and (for a
transaction) the mempool verdict with the class of the admission rule that
refuses it. A change to a rule the vectors exercise changes a verdict, or the
stage that reaches it, and fails a runner (see "Effectiveness" for the
mutations checked).

## This chain's rules (mainnet line, 2026-10)

The vectors were written by the 2026-10 audit for the pre-relaunch rules and
migrated to the rules this chain has enforced at every height since before
its 2026-10-14 reset. Where those differ from the audit's "below the
activation" regime, the vectors pin this chain's rule:

- **BIP30 and no spend of the block's own coinbase at every height**
  (`bip30`, `same-block-coinbase` below the activation too).
- **Exact v2 witness framing**: no bytes after the public key
  (`witness-malformed` below the activation), and Falcon's compact encoding
  is part of the v2 signature check (`crypto::verify_canonical`: the
  zero-padded 1,280-byte form is `bad-signature`). An unenveloped
  (carried-over raw) signature stays valid below the activation.
- **Sighash v2 over the wire encoding** with version byte 0x02
  (`reference/gnb_sighash.py`).
- **Block size on the wire encoding at every height** (`block-size`); no
  vector records a bincode size any more.
- **Finality and output kinds** (`node/src/blockval.rs`): a transaction is
  valid only in a block at height >= `locktime` (`non-final`), and every
  output, the coinbase's included, is a 20-byte key hash or a 33-byte spend
  policy (`bad-output-script`). So no 64-byte transaction exists on this
  chain: the audit's 64-byte cases (a 5-byte script) are `bad-output-script`
  below the activation and `tx-64-bytes` (the context-free rule, first) from
  it; the 10,000-byte output script is `bad-output-script`.
- **Caps**: `script_sig` up to 114,834 bytes (the largest policy witness),
  `script_pubkey` up to 10,000; `MAX_SUPPLY_SAT` 12,500,000 GNB; genesis
  timestamp 1,791,685,648.
- **PoW + PoWit from height 10,000** (mainnet): the block encoding and body
  root carry the PoWit section (`reference/gnb_merkle.py` `header_root`),
  and a coinbase may pay the miner at most the subsidy minus its 20% witness
  pool, plus fees (the halving, pow and mainnet-boundary cases).
- **The `|wc:` witness commitment** from height 5,000 up to the hardening
  activation (`witness-commitment-suffix`: the mainnet 17,499 cases).

Dropped premises: the audit's "valid below the activation" cases for
overwriting an unspent coin, spending the own coinbase, lenient witness
padding, a zero-padded Falcon half, a bincode-measured size and the
`locktime = 2^32-1` "no lock-time rule" case are kept with this chain's
verdict instead (no case was removed).

What the vectors do NOT pin:

- **Header-chain context.** `accept_block`'s checks against the DAG (parents
  known, height = max parent height + 1, the expected ASERT bits,
  timestamps) are not evaluated; `reference/difficulty_vectors.json` pins
  ASERT, `reference/ghostdag_vectors.json` (from `reference/gnb_ghostdag.py`,
  checked by `node/tests/ghostdag_vectors.rs`) pins the GhostDAG data of
  small DAGs at/after the activation (selected parent, DAG and header
  heights, the candidate order and coloring, blue score and work; audit
  B2-T9), the parent-list shapes (repeated and redundant parents, B2-T10)
  and the mergeset-size limit (64 merged blocks at every height, this
  chain's `MERGESET_SIZE_LIMIT`), the node's own tests pin the rest (the
  PoWit finalized checkpoint, which only restricts fork choice, included).
- **The production composition of the stages.** The runners call the
  stage functions in the node's order (the node runner: the ingress
  structure check `Block::validate_structure_without_pow`,
  `check_block_hardened_at`, the pow limit, `Block::validate_pow`,
  `limits::check_block_context_free`, `accept::validate_block_in_view_classified`,
  `admission::check_transaction`), but neither runner calls `accept_block`
  or the gossip/RPC pipeline around them, and a tx case reaches the block
  rules through the test helper `tx_context_free` (the per-transaction
  subset of `Block::validate_structure_without_pow_at`).
- **The proof of work beyond three blocks.** Two `pow: full` cases evaluate
  the GnB-SMH proof at the genesis target (a mined nonce and a failing one);
  the third, at 0x2100ffff, pins the limit only (nearly every output meets
  that target). Every other case skips the proof or checks the limit alone.
- **Shielded transactions, the 400 KiB mempool size limit, pool-relative
  admission** (full-RBF replacement, chains of unconfirmed transactions and
  their limits, the rolling fee, the reject filter, the orphanage, the
  signature budget; `docs/MEMPOOL.md` and the node's `fix_mempool_*` tests)
  and the mempool's own data structure.

| What | Where |
| --- | --- |
| Transaction vectors (197 cases) | `reference/tx_vectors.json` |
| Block vectors (118 cases) | `reference/block_vectors.json` |
| Generator (deterministic Rust, seeded keys and signatures) | `crates/gnb-crypto/tests/gen_consensus_vectors.rs` |
| Runner through gnb-crypto (real pow limit, explicit chain ids) | `crates/gnb-crypto/tests/consensus_vectors.rs` |
| Runner through the node (connect path, mempool admission, testnet) | `node/tests/consensus_vectors.rs` |
| Shared loader, stage expectations (`context_free_expectation`) and error-class mapping | `crates/gnb-crypto/tests/consensus_vectors_common/mod.rs` |
| Independent Python check (no Rust) | `reference/check_consensus_vectors.py` over `reference/gnb_validity.py`, `gnb_merkle.py`, `gnb_sighash.py`, `gnb_difficulty.py`, `gnb_smh.py` |
| CI | `python-reference` (Python check), `consensus-crates` (gnb-crypto runner; regenerate and `git diff --exit-code`), `workspace-test` (node runner) |

```text
cargo test -p gnb-crypto --test consensus_vectors                     # gnb-crypto runner
cargo test -p gnb --test consensus_vectors                            # node runner
python3 reference/check_consensus_vectors.py                          # Python check
cargo test -p gnb-crypto --test gen_consensus_vectors -- --ignored    # the generator reproduces the files
GNB_WRITE_VECTORS=1 cargo test -p gnb-crypto --test gen_consensus_vectors -- --ignored   # rewrite them
```

## Three independent judges

1. **The generator writes the expected verdicts by hand.** Next to every
   construction (`c.valid(..)`, `c.invalid(.., "min-fee")`,
   `c.invalid_refused(.., "min-fee", "no-inputs")`) the
   expected verdict, class, mempool verdict and refusal class are literals.
   The generator never calls a validation function to decide a verdict, and
   boundary values (dust 546,
   maturity 100, minimum fee `max(10,000, ceil(size x 2,000 / 1,000))`, the
   subsidy schedule and the PoWit miner share, `MAX_SUPPLY_SAT`, the
   1,000,000-byte limit, the script caps) come from the generator's own
   constants, not from
   the code under test. Regenerating after a rule change therefore does not
   move a vector; the runners fail instead. Mining does not use a validation
   function either: the `pow: full` nonces come from the GnB-SMH hash with
   the generator's own target decoding and comparison (`proof_holds`,
   `mine_from`; the search for the genesis-target case starts at a recorded
   hint, so regeneration costs one evaluation instead of about 4,500).
2. **The Rust runners** check every verdict through the functions the node
   runs (see "Evaluation" below), stage by stage (the context-free stages
   must reject exactly the context-free classes), and every recorded
   derived value (txid, wtxid, sighash digests, roots, sizes) against the
   current code.
3. **The Python check** re-derives every derived value and every
   non-signature verdict from the specification (`docs/CONSENSUS.md`), with
   its own decoder, Merkle trees, commitments, both sighash digests,
   Falcon compact-encoding parser and validity rules
   (`reference/gnb_validity.py`), and evaluates the GnB-SMH proof of the
   `pow: full` blocks with `reference/gnb_smh.py` (about 2 s each). It cannot
   verify ML-DSA-65 / Falcon-1024 signatures, so a case whose class is
   `bad-signature` must pass every other rule in Python, and every other
   class must be exactly the first rule Python sees fail. It re-derives every
   mempool verdict and refusal class the same way.

Deliberately corrupting a vector (an expected class, a digest, a size, a
policy verdict) makes the Python check fail; so does a rule flipped in the
code for the Rust runners (see "Effectiveness").

## Determinism

Keys come from `crypto::generate_keypair_from_seed(SHA3-256("gnb-consensus-vectors/key/<name>"))`.
Every signature is made inside `pqcrypto_internals::with_seeded_rng_scope`
with a seed derived from the case label, so ML-DSA-65's hedged signing and
Falcon-1024's nonce and sampler are deterministic; Falcon is pinned to
PQClean's integer-only `clean` variant, which is bit-exact across platforms.
The JSON is written by a small ordered emitter (no dependence on
`serde_json` features). CI regenerates both files and diffs them.

Keys (`keys` in both files): `A`, `B`, `C` (hybrid suite 0x0001, enveloped
public keys), `A-raw` (key A's raw 3,745-byte public key, as a genesis
carry-over address commits to it) and `A-mldsa-only` (a suite-0x0002 key made
of key A's ML-DSA-65 half, which is what the split-and-relabel attack of
CRY-2 needs).

## Regimes and heights

Every case carries `activation_height` and `height` (decimal strings). The
regime is `pre-activation` iff `height < activation_height` (the block rules
additionally never apply at height 0; no case uses it). Most cases use
activation height 1,000 with heights 999 (pre) and 1,000 (post: the boundary
itself). Further cases use activation 0 on mainnet, "never"
(`18446744073709551615`) and heights around the halving at 4,204,800.

`activation_source` says where a runner takes the activation height from:

- `explicit`: the recorded height, installed for the case
  (`activation::scoped_override` in the node runner, the `_at` functions'
  argument in the gnb-crypto runner);
- `schedule`: the case's network's own activation schedule (mainnet 17,500,
  testnet 0; docs/CONSENSUS.md, "Activation"), which the runners do NOT
  install: the gnb-crypto runner evaluates the case under
  `activation::hardening_activation_height_for_chain(chain)` (and
  `validate_pow` under the process-wide height), the node runner under the
  process-wide height of its chain id (mainnet in the main process, testnet
  in the testnet child). These cases (mainnet 17,499 / 17,500 for the
  version rule, the 64-byte rule, the coinbase commitment and the pow limit;
  testnet activation 0 at height 1) therefore pin the schedule constants and
  the chain-id-to-schedule mapping; the Python check verifies that the
  recorded height is the documented schedule.

`network` is `mainnet` or `testnet` (the chain id signatures commit to). The
node's chain id is process-wide, so the node runner evaluates the testnet
cases in a child process of its own test binary.

## `tx_vectors.json`

```text
{
  "format": "gnb-consensus-tx-vectors/1",
  "description", "generator", "constants", "keys",
  "cases": [ {
    "id":                 "witness/one-trailing-byte/pre",
    "description":        what the case is and why the verdict holds,
    "network":            "mainnet" | "testnet",
    "activation_height":  "1000",
    "activation_source":  "explicit" | "schedule",
    "height":             "999",                 header height of the evaluation block
    "dag_height":         "909",                 optional: its DAG height (default: height)
    "regime":             "pre-activation" | "post-activation",
    "prevouts": [ {                              the UTXO view, exactly
       "txid", "vout", "amount" (decimal), "script_pubkey",
       "is_coinbase", "coinbase_height" (decimal or null),
       "source": "utxo" | "block-coinbase",
       "coinbase_dag_height" (optional decimal: the DAG height of the
                              coinbase's block; default: coinbase_height) } ],
    "tx":                 wire hex (Transaction::to_wire_bytes(true)),
    "expected": { "verdict": "valid" | "invalid", "error_class": null | class },
    "policy":   { "verdict": "accept" | "reject", "error_class": null (accept) | class (reject) },
    "derived":  null (undecodable) | { "txid", "wtxid", "wire_size", "txid_preimage_size",
                 "digests": [ { "input", "sighash_v2", "sighash_v3_suite", "sighash_v3" | null } ] }
  } ]
}
```

**Evaluation.** The transaction is decoded strictly (the bytes must be the
canonical encoding: no trailing byte, minimal varints; the node's gossip and
RPC decoder `admission::decode_tx_strict`). It is then the only
non-coinbase transaction of a block `[wrapper coinbase, tx]` at `height`. The
wrapper coinbase has version 1, one input (32 zero bytes, index 0xffffffff,
script_sig `constants.wrapper_coinbase_script_sig`, sequence 0xffffffff), one
output and locktime 0; the output pays the `block-coinbase` prevout (whose
txid is then the wrapper coinbase's), or 0 to 20 zero bytes. The rules,
in the node's order:

1. the per-transaction context-free block rules: not coinbase-shaped
   (`Block::validate_coinbase_format`), at/after the activation not 64 bytes
   (`block_rules::check_tx_not_64_bytes`), no dust (`Block::validate_dust`),
   encoding caps and MoneyRange (`limits::check_block_context_free`);
2. connection, `accept::validate_block_in_view_classified` (the function
   the acceptance pipeline calls for an extension and for every block of a
   reorg; the case's activation height installed, or the schedule's) on a
   RocksDB store holding
   exactly the `utxo` prevouts: BIP30 and the coinbase's own finality and
   output kinds; then, in two passes (re-audit B1-T13), for every
   transaction the rules the block id commits to — no spend of the block's
   own coinbase; coinbase maturity (header heights below the activation,
   DAG heights from it, re-audit B1-T14); once every prevout is found,
   finality (`locktime`) and output kinds; double spends; missing inputs;
   input MoneyRange; the version rule; value; the minimum-fee floor no
   `script_sig` can lower (`min-fee`: the fee rule on the size with every
   `script_sig` empty); every spent coin's script of an output kind
   (`pubkey-mismatch`) —; the coinbase value; then for every transaction
   the witness rules — the policy-spend rules (not modelled by the vectors);
   witnesses; public-key hashes; signatures (sighash v2 or v3 as the version
   rule selects); the consensus minimum fee.

The block-level rules of the wrapper (Merkle root, commitment, size) are the
block vectors' subject.

`expected` is the consensus verdict and the class of the FIRST rule that
fails. Invalid cases are built to violate one rule where the rules allow it
(otherwise the class is the first in the order above, which the Python check
reproduces). The runners compare stage by stage: step 1 must reject exactly
the cases whose class is a step-1 class (`coinbase-format`, `tx-64-bytes`,
`dust`, the encoding caps, and `value-out-of-range` when an output, an
output total or the block total is above `MAX_SUPPLY_SAT`, which the runner
computes from the data); every other case must pass step 1 and get its
verdict from step 2. A step-1 rule that is dropped therefore fails the
runners even where a step-2 rule would reject the case with the same class
(the output MoneyRange is checked in both).

The gnb-crypto runner evaluates step 2 through gnb-crypto's own functions in
the node's order (`core::check_coinbase_maturity`, the input sum with
`limits::money_add`, `core::sighash::check_tx_version`,
`limits::check_tx_money_range`, inputs >= outputs, the fee floor with
`tokenomics::min_tx_fee_sat`, prevout scripts of an output kind, then
`core::sighash::verify_tx_scripts` and `core::check_min_fee`).
BIP30, the same-block coinbase rule, duplicate inputs and missing inputs
(`node/src/accept.rs`) and finality and output kinds (`node/src/blockval.rs`)
are node rules, so for the 21 cases of those classes it
checks every earlier rule and lists the case as deferred to the node runner
(`TX_DEFERRED_TO_NODE`; the test asserts that every case is either decided or
deferred, and prints the deferred ones).

`policy` is mempool admission (`admission::check_transaction`, relay policy,
signatures on) for a block at `height`, on the same store, in which every
`utxo` prevout's txid is also indexed as a confirmed transaction (a node
applies every coin together with its creating transaction): `accept`, or
`reject` with the class of the FIRST admission rule that refuses it. A
consensus-invalid case is always refused. Admission runs its relay-policy
rules before its copies of the consensus rules (structure, already
confirmed, MoneyRange / dust / zero value, the witness framing of every
input and then the hybrid suite, the version rule and policy, the 64-byte
rule, duplicate inputs, presence, maturity, finality and output kinds,
value, the minimum fee, the relay fee, signatures: `docs/MEMPOOL.md`
section 1), so 28 of the 140 invalid cases are refused by an earlier
admission rule, whose class differs from the consensus class:

- 22 by relay policy (`NonStandard`): 18 `non-standard-witness` (a
  non-canonical witness where it is not the consensus rule: below the
  activation, or on a version other than 3), 3 `non-standard-suite` (a
  0x0002 key) and 1 `non-standard-version`;
- 2 by admission's own consensus rule "no inputs" (`Rejected`, class
  `no-inputs`: a zero fee is below the consensus minimum, so the consensus
  class of `struct/no-inputs/*` is `min-fee`);
- 2 as `missing-input` (`MissingInputs`: the block's own coinbase) and 2 as
  `already-confirmed` (`Duplicate`: the BIP30 cases).

The other 112 are refused by the admission's own copy of the violated
rule, with the consensus class. That includes the 17 post-activation cases
whose version-3 witness is not canonical: from the activation the witness
check of admission is the consensus rule for version 3 (CRY-1,
`admission::check_witnesses_for_next_block`), so their refusal class is
`witness-non-canonical`. The gate of that consensus refusal is the version
rule's verdict at the next block's height (`check_tx_version(..) == V3`),
and two cases pin it from both sides:
`witness/version-1-one-trailing-byte-from-the-activation/post` (version 1
at the activation: consensus `bad-version`, refused as
`non-standard-witness`) and `witness/version-3-sighash-v2-one-trailing-byte/pre`
(version 3 below the activation: consensus `witness-malformed` under this
chain's exact v2 framing, refused as `non-standard-witness`). The node runner fails on a different class, and on
a storage or pool error.

The node runner also pins the relay verdict of every refusal, the
`AdmissionError` variant the class must come with (`admission_variant` in
`node/tests/consensus_vectors.rs`; `docs/MEMPOOL.md` section 2). The relay
reports `Reject`, and may penalise the peer, only for `Rejected`; every
other variant is `Ignore`:

| Variant | Policy classes |
| --- | --- |
| `Rejected` (consensus-invalid for this exact transaction) | `coinbase-format`, `no-inputs` (a zero fee is below the consensus minimum), `canonical-limit`, `value-out-of-range`, `dust`, `witness-non-canonical`, `double-spend`, `inputs-below-outputs`, `min-fee`, `pubkey-mismatch`, `bad-signature` |
| `NonStandard` (relay policy, or a rule of the next block's height) | `non-standard-no-outputs`, `non-standard-size`, `non-standard-zero-value`, `non-standard-witness`, `non-standard-suite`, `non-standard-version`, `bad-version`, `tx-64-bytes` |
| `MissingInputs`, `Immature`, `LowFee`, `Duplicate` | `missing-input`, `immature-coinbase`, `low-relay-fee`, `already-confirmed` |

`bad-version` and `tx-64-bytes` are consensus classes, but admission judges
them at the node's next height, which a peer one block behind across the
activation sees differently, so they are `NonStandard`.

`derived.digests` are the sighash v2 digest of every input under the
network's chain id and the sighash v3 digest (spent outputs from `prevouts`;
suite = the signature envelope's, 0x0001 when there is none; null when an
input's coin is not in `prevouts`). The Python check recomputes them with
`reference/gnb_sighash.py`.

## `block_vectors.json`

```text
{
  "format": "gnb-consensus-block-vectors/1",
  "description", "generator", "constants", "keys",
  "cases": [ {
    "id", "description", "network" ("mainnet"), "activation_height", "height", "regime",
    "scope":    "full" | "connect",
    "pow":      "skip" | "limit" | "full",
    "prevouts": [ ... ]                      the parent state's UTXO view, as above
    "block":    wire hex (Block::to_wire_bytes)
      or "block_parts": [ { "hex", "repeat" } ]   concatenation of each part repeated (1 MB blocks)
    "expected": { "verdict", "error_class" },
    "derived":  null (undecodable) | { "block_hash", "txids", "legacy_merkle_root", "tagged_merkle_root",
                "witness_root", "parents_commitment", "subsidy", "wire_size" }
  } ]
}
```

**Evaluation** (scope `full`): `Block::from_wire_bytes`;
`Block::validate_structure_without_pow` / `_at` (parent count, size measure of the
regime, header Merkle root of the regime, coinbase format, at/after the
activation the 64-byte rule and the coinbase commitment, duplicate
transactions, dust); `block_rules::check_block_hardened_at`; the pow limit
(`pow: limit`: the bits decode and the target is within the pow limit of the
height, `pow_limit_bits_at`; `pow: full`: also the GnB-SMH proof,
`Block::validate_pow`); `limits::check_block_context_free`; then
`accept::validate_block_in_view_classified` against a store holding the
prevouts. As for transactions, the stages up to `check_block_context_free`
must reject exactly the context-free classes (the output-side
`value-out-of-range` included), and every other case must reach the connect
step. Scope `connect` decodes and runs the last step only: it pins VAL-3
(no spend of the block's own coinbase) at/after the activation, which a
complete block cannot reach because its coinbase commitment would have to
commit to itself (the matching `full` case shows the commitment rejecting
it).

The node runner calls the ingress check `Block::validate_structure_without_pow`
(process-wide activation height: the case's installed height, or the
schedule) and `accept::validate_block_in_view_classified`, the variant the
acceptance pipeline calls; the gnb-crypto runner calls the `_at` variants.

The GnB-SMH proof (`pow: full`) is evaluated for three blocks:
`pow/genesis-bits-mined/post` (bits 0x1f0e9036, the genesis target and the
pow limit from the activation, with a mined nonce: about one output in 4,500
meets this target, so a changed preimage, nonce, hash or comparison fails
it), `pow/genesis-bits-proof-fails/post` (the same block with a nonce whose
output misses the target: `bad-pow`, so a skipped or inverted proof check
fails it) and `pow/pow-limit-bits-below-the-activation` (0x2100ffff, where
nearly every output meets the target: it pins the limit, not the proof).
The node's test build pins `validate_pow`'s limit to 0x2100ffff
(`test-pow-limit`); all three are within it, so the node runner evaluates
them too, and the gnb-crypto runner, built without the feature, also
evaluates `validate_pow` with the real limit for every pow-limit case (it
must refuse them without an evaluation). Not part of the block vectors: the
header-chain context `accept_block` checks against the DAG (see the top of
this page).

## Error classes

Consensus classes (`expected.error_class`; the node string the runners map
from in `consensus_vectors_common::classify`):

| Class | Rule | Node error (contains) |
| --- | --- | --- |
| `decode` | the bytes are not a canonical encoding: truncated, trailing bytes, non-minimal varint, a count or length above the decoder caps (100,000 inputs / outputs, a 114,834-byte `script_sig`, a 10,000-byte `script_pubkey`, 256 parents) | decoder error |
| `coinbase-format` | first transaction not a coinbase, or a second coinbase-shaped transaction, or no transactions | `invalid coinbase format` |
| `tx-64-bytes` | at/after the activation, a txid preimage of exactly 64 bytes (VAL-10) | `64-byte transaction` |
| `dust` | a non-coinbase output with 0 < value < 546 | `below dust threshold` |
| `value-out-of-range` | MoneyRange: an output, an output sum, an input sum or the block total above `MAX_SUPPLY_SAT` (VAL-11) | `MAX_SUPPLY_SAT`, `overflows u64` |
| `bip30` | an output at the outpoint of an unspent coin (every height on this chain; VAL-2) | `BIP30` |
| `same-block-coinbase` | a spend of the block's own coinbase (every height on this chain; VAL-3) | `spends the coinbase of its own block` |
| `non-final` | `locktime` above the block height | `non-final: locktime` |
| `bad-output-script` | an output (the coinbase's included) that is neither a 20-byte key hash nor a 33-byte spend policy | `unsupported script_pubkey` |
| `witness-commitment-suffix` | from height 5,000 below the activation, the coinbase `script_sig` does not end with `|wc:` and the witness root | `coinbase does not commit to the block's witnesses` |
| `immature-coinbase` | a coinbase spent before depth 100 | `coinbase maturity` |
| `double-spend` | an outpoint spent twice in a transaction or a block | `double-spend` |
| `missing-input` | the outpoint is not in the view nor created earlier in the block | `UTXO ... not found` |
| `bad-version` | at/after the activation, version != 3 | `bad-txns-version` |
| `witness-malformed` | below the activation, the exact v2 witness framing does not parse (or leaves bytes after the key) | `malformed script_sig` |
| `witness-non-canonical` | at/after the activation, not exactly `[u32 sig_len][sig][u32 pk_len][pk]` or not the canonical signature encoding | `non-canonical` |
| `pubkey-mismatch` | SHA3-256(public key)[0..20] differs from the coin's script | `pubkey mismatch` |
| `bad-signature` | a signature does not verify under the digest and binding of the regime | `invalid signature` |
| `inputs-below-outputs` | outputs exceed inputs | `inputs ... < outputs ...` |
| `min-fee` | fee below `max(10,000, ceil(wire size x 2,000 / 1,000))` | `below consensus minimum` |
| `block-size` | above 1,000,000 bytes on the wire encoding (every height on this chain; `blue_score` fixed-width, so one verdict per block id, re-audit B1-T0) | `block too large` |
| `bad-merkle-root` | the header root is not the regime's root (legacy below, tagged from the activation) | `invalid merkle root` |
| `duplicate-tx` | the same txid twice (CVE-2012-2459) | `duplicate transaction in block` |
| `duplicate-parent` | at/after the activation, a parent listed twice in the header (audit B2-T10) | `duplicate parent` |
| `cb-commitment-missing`, `cb-commitment-tag`, `cb-height`, `cb-parents`, `witness-commitment` | the 80-byte coinbase commitment: shorter than 80 bytes, wrong tag, wrong height, wrong parent list, wrong witness root (VAL-2, CRY-1) | `coinbase commitment missing`, `bad coinbase commitment tag`, `bad-cb-height`, `bad coinbase parents commitment`, `bad witness commitment` |
| `coinbase-output-count` | the coinbase does not have exactly one output (from the PoWit height: one plus one per witness share) | `coinbase must have 1 output`, `coinbase must have 1 miner output` |
| `coinbase-value` | the coinbase claims more than subsidy + fees (from the PoWit height: the miner share of the subsidy + fees) | `miner coinbase output exceeds allowed amount` |
| `pow-limit` | the target is above the pow limit of the height (POW-3) | runner (`pow_limit_bits_at`) |
| `bad-bits` | the compact bits do not decode, or are not the canonical encoding of the target they decode to (audit POW-9) | runner (`try_canonical_bits_to_target`, as `Block::validate_pow`) |
| `bad-pow` | the GnB-SMH output is not below the target of the bits | `Block::validate_pow` false |

Policy classes (`policy.error_class` of a refused case; the
`AdmissionError` variant of each is in the table under `tx_vectors.json`):

- any consensus class above that admission's own copy of the rule decides
  (`decode` for bytes `admission::decode_tx_strict` refuses;
  `witness-non-canonical` for a version-3 transaction at/after the
  activation), plus `no-inputs`, admission's own consensus rule for a
  transaction without inputs (`Rejected`; such a case's consensus class is
  `min-fee`);
- relay policy (`NonStandard`): `non-standard-witness` (a non-canonical
  witness where it is policy: below the activation, or a version other than
  3), `non-standard-version` (version >= 3 below the activation),
  `non-standard-suite` (a suite-0x0002 key), `non-standard-zero-value`,
  `non-standard-no-outputs`;
- pool state: `missing-input` (an unconfirmed coin: the block's own
  coinbase), `already-confirmed` (the txid is already in the transaction
  index).

## Coverage

Transactions (197: 103 pre-activation, 94 post-activation; 53 valid; 192 on mainnet, 5 on testnet):

| Area | Cases | What |
| --- | --- | --- |
| `basic/` | 10 | honest signers of both regimes; 1-3 inputs; the mainnet schedule (17,499 / 17,500, `activation_source: schedule`), activation 0 on mainnet, never activated |
| `struct/` | 19 | no outputs (valid, non-standard), no inputs, coinbase-shaped transaction, missing input, null outpoint in a 2-input transaction, duplicate inputs, two vouts of one txid, lock time and sequence not enforced |
| `decode/` | 8 | truncated, trailing byte, non-minimal varint, empty, input / output count above the cap, 10,001-byte script_sig and script_pubkey |
| `size/` | 6 | a 10,000-byte script_sig (lenient padding: valid pre, non-canonical post), a 10,000-byte output script, 300 outputs |
| `value/`, `fee/`, `dust/` | 31 | MoneyRange of outputs, output sums, `u64::MAX`, the `MAX_SUPPLY_SAT` boundary, prevout amounts and sums; inputs below outputs; zero fee; zero fee with a bad signature (`min-fee`: the fee floor is checked before the witness rules, re-audit B1-T13); fee exactly the minimum and one below (fixed point over the variable Falcon length); witness padding raising the minimum; dust 1 / 545 / 546; zero-value outputs |
| `maturity/` | 16 | depth 100 / 99 / 0 (a parallel block's coinbase) / negative, a second immature input, a carry-over coin at height 1, the block's own coinbase (valid pre, `same-block-coinbase` post); header depth vs selected-chain depth (re-audit B1-T14: a block merging a side tip, header depth 100 and DAG depth 10, valid pre / immature post; a coinbase whose block merged a side tip, header depth 51 and DAG depth 100, immature pre / valid post) |
| `version/` | 18 | versions 0, 1, 2, 3, 4, 2^32-1 in both regimes; version 3 over the wrong digest in each regime; the mainnet boundary; never-activated |
| `sig/` | 26 | wrong amount and wrong script (v2 does not commit: valid; v3 does: invalid), another input's amount, wrong input index, the v2 out-of-range marker quirk, testnet signature on mainnet, components swapped between inputs, component ids swapped, legacy binding over a v3 digest and bound binding over a v2 digest, a digest with another suite id, tampered ML-DSA and Falcon nonce bytes, another key's signature, a key that does not hash to the coin, a bad second input |
| `net/` | 5 | testnet-signed on testnet (both regimes), mainnet-signed on testnet, the testnet schedule (activation 0, `schedule`) |
| `suite/` | 16 | split-and-relabel of a hybrid signature to 0x0002 (valid pre: the CRY-2 weakness kept below the activation; invalid post), genuine 0x0002 spends (valid, non-standard), cross-suite key/signature pairs, relabelled to reserved 0x0000 / 0xffff and unknown 0x0003, a 3,310-byte 0x0002 body |
| `raw/` | 8 | raw carry-over public keys with enveloped and raw signatures, and the address committing to the exact key encoding |
| `witness/` | 24 | trailing bytes, signature without envelope, Falcon in the 1,280-byte zero-padded form (valid pre, non-canonical post), an extra non-zero Falcon byte, truncated Falcon, empty signature, sig_len beyond the script, empty and 7-byte script_sigs, pk_len one short; the version gate of admission's witness verdict (a trailing byte on version 1 at the activation and on version 3 over sighash v2 below it: both `non-standard-witness`) |
| `tx64/` | 8 | 63 / 64 / 65-byte txid preimages in both regimes; the mainnet boundary |
| `bip30/` | 2 | an output on an unspent coin's outpoint (valid pre, invalid post) |

Blocks (118: 54 pre-activation, 64 post-activation; 37 valid):

| Area | Cases | What |
| --- | --- | --- |
| `basic/`, `order/` | 12 | coinbase only, coinbase and spend, a spend of an earlier transaction in the block, the reverse order, two transactions spending one coin, a bad signature followed by an overspend (`inputs-below-outputs`: the rules the block id commits to are checked for every transaction before any witness rule, re-audit B1-T13) |
| `merkle/`, `dup/` | 10 | the other regime's root, a zero root, a three-transaction block and its CVE-2012-2459 mutation (duplicate-tx pre, bad root post), a duplicated transaction |
| `coinbase/` | 24 | not first, two coinbases, no transactions, two / zero outputs, subsidy + 1, subsidy + fees (exact and + 1), paying zero, above `MAX_SUPPLY_SAT`, the halving at 4,204,800 |
| `decode/` | 2 | a valid block's bytes with one varint in the non-minimal 3-byte form (the transaction count post; a coinbase script_sig length pre, with a coinbase locktime ending `FD 00` so that the decoder before the rule, which framed each transaction at its re-encoded length, accepted the bytes as the same block): the decoder accepts only minimal varints, at every height (docs/CONSENSUS.md, "Wire encoding"). The decoder before the rule (the Python reference before H-fuzz too) accepts both byte strings |
| `commitment/`, `structure/` | 19 | two parents; script_sig of 79 bytes; bad tag; height + 1 and big-endian; parents reordered and dropped; witness root zero, over txids, and with the coinbase's own wtxid; 10,000-byte script_sig (valid) and one byte more (decode); a wrong commitment ignored pre; the mainnet boundary; 256 parents (valid) and 257 (decode) |
| `parents/` | 4 | a parent listed twice (valid pre, `duplicate-parent` post) and the mainnet boundary (17,499 valid, 17,500 invalid); a parent in the past of another needs DAG context and is pinned by `reference/ghostdag_vectors.json` |
| `same-block-coinbase/` | 3 | valid pre; `connect` scope post; `full` scope post (the commitment cannot match) |
| `pow/` | 14 | the GnB-SMH proof at the genesis target: a mined nonce (valid) and a failing nonce (`bad-pow`), post; 0x2100ffff evaluated pre (limit only), refused post; the genesis target exactly and one unit above, in both regimes; the mainnet boundary; four malformed bits; a decodable but non-canonical encoding, `0x21007fff` (audit POW-9) |
| `size/` | 10 | 1 MB blocks, measured on the wire encoding at every height: wire 1,000,001 with bincode below (invalid in both regimes), wire exactly 1,000,000 (valid in both), bincode 1,000,001 with wire below (valid in both: bincode is no measure on this chain); the two pre-activation blocks at the wire limit again under the same block id with `blue_score` 0 and `u64::MAX` (`*-blue-score-0/pre`, `*-blue-score-max/pre`): same verdicts, the wire header writing `blue_score` at a fixed width (re-audit B1-T0 / B2-T8) |
| `value/`, `maturity/`, `sig/`, `tx64/`, `bip30/`, `version/`, `witness/` | 20 | the transaction rules inside a block: dust, outputs summing above `MAX_SUPPLY_SAT` with every transaction in range (valid: no block-wide output total, re-audit B1-T1) and three chained in-block spends of 4,500,000 GNB summing above it (valid in both regimes), an immature spend, a bad signature, a 64-byte transaction, BIP30 on a spend's and on the coinbase's output, the version rule, a padded witness under the same block id (valid pre, witness commitment post) |

`crates/gnb-crypto/tests/consensus_vectors.rs::vector_coverage` fails if a
class, a policy class, a network x regime pair, a network's schedule case, a
version x regime pair, either side of the witness refusal's version gate (a
`non-standard-witness` refusal on a version other than 3 at/after the
activation, and on version 3 below it), a raw key, a 0x0002 key, the mined and the failing
proof at the genesis target, or one of the two valid blocks whose outputs
sum above `MAX_SUPPLY_SAT` (`value/block-output-total-above-max-supply/*`,
`value/chained-spends-output-total-above-max-supply/*`, re-audit B1-T1)
disappears from the files or stops being valid.

## Adding a case

Add it to the generator, next to its neighbours, with the verdict, class and
mempool verdict (and refusal class) you expect as literals: `c.invalid(..)`
when admission refuses it for the same rule, `c.invalid_refused(.., class,
policy_class)` when an earlier admission rule does; keep it to one violated
rule when the rules allow it. Regenerate with `GNB_WRITE_VECTORS=1`, run the three judges,
and review the JSON diff (an existing case must not change unless the change
is the point). A new rejection string must be classified in
`consensus_vectors_common::classify` (the runners panic on an unknown one)
and, for Python, produced by `reference/gnb_validity.py`.

## Effectiveness

Each rule below was flipped in the code, one at a time (anchored source
edits); both Rust runners were rebuilt and run, then the code was restored
and the tree checked clean. The Python check does not read the Rust code, so
it is unaffected by these and is exercised instead by corrupting the files
(13 corruptions in the first round, 5 in the second, each reported).

**First round** (the runners as first committed; 16 mutations, each made at
least one runner fail, naming the cases; the baseline passed in the same
build):

| Mutation | Runner | Cases that fail |
| --- | --- | --- |
| dust threshold off by one (546 is dust) | both | `dust/output-546/*`, `value/output-u64-max/*` (its second output is 546), the 1 MB blocks of 546-unit outputs |
| coinbase maturity off by one (depth 99 accepted) | node | `maturity/depth-99/*` (consensus and mempool), `maturity/immature-coinbase-spend-in-block/*` |
| maturity by header heights from the activation (B1-T14 reverted), or by DAG heights below it | node, gnb-crypto runner, Python | `maturity/merge-header-depth-100-dag-depth-10/*`, `maturity/inflated-coinbase-header-dag-depth-100/*` (consensus and mempool) |
| VAL-3 removed (same-block coinbase) | node | `maturity/same-block-coinbase/post`, `same-block-coinbase/post/connect` |
| 64-byte rule measured with script_sig | both | gnb-crypto: the recorded txid preimage size of 175 cases; node: `tx64/64-byte-transaction/post`, `tx64/mainnet-boundary/17500`, `tx64/64-byte-transaction-in-block/post` |
| version 2 accepted from the activation | both | `version/v2-sighash-v2/post` |
| canonical witness accepts trailing bytes | both | `witness/one-trailing-byte/post`, `witness/1000-trailing-bytes/post`, `witness/pk-length-one-short/post`, `size/script-sig-10000-bytes/post`, and the mempool verdicts of the padded pre-activation cases |
| sighash v3 verifier ignores the signature's suite | both | `suite/mldsa-only-0x0002-spend/post` |
| BIP30 removed | node | `bip30/output-overwrites-an-unspent-coin/post`, both block `bip30/*/post` |
| minimum fee off by one | node | `fee/exact-minimum/*` (consensus and mempool) |
| tagged Merkle tree pairs an odd node with itself | both | gnb-crypto: tagged and witness roots of 25 block cases; node: the 5 post-activation blocks with an odd transaction count |
| coinbase may not claim the full subsidy + fees | node | 27 block cases |
| block size measured on bincode from the activation | both | `size/bincode-1000001-wire-below/post` |
| hardened pow limit = the old pow limit | both | `pow/pow-limit-bits-from-the-activation`, `pow/genesis-target-plus-one-from-the-activation`, `pow/mainnet-17500-pow-limit-bits` |
| commitment height also accepted big-endian | both | `commitment/height-big-endian/post` |
| lenient witness framing made exact below the activation | both | `witness/one-trailing-byte/pre`, `witness/1000-trailing-bytes/pre`, `size/script-sig-10000-bytes/pre`, `fee/witness-padding-raises-the-minimum/pre`, `witness/padded-witness-same-block-id/pre` |
| MoneyRange allows `MAX_SUPPLY_SAT + 1` | node | `value/output-above-max-supply/*`, `value/prevout-above-max-supply/*`, `coinbase/above-max-supply/*` (the gnb-crypto runner of that round compared no `value-out-of-range` verdict at all, on either side; fixed in the second round) |

**Second round** (after review, 2026-10-15). A review found mutations the
first-round runners did not see: they compared a context-free class only when
the context-free stage failed, let every other case fall through silently,
recorded no refusal class for consensus-invalid transactions, evaluated no
GnB-SMH proof that can fail, and installed the activation height of the
schedule cases instead of reading the schedule. The runners now compare each
stage against `context_free_expectation`, decide or explicitly defer every
case, compare every refusal class, run `schedule` cases on the schedule, and
the files gained the genesis-target proof pair and the block-total MoneyRange
case. Each mutation below was run against the first-round runners and files
(column "before") and the current ones ("now"), in a scratch copy of the tree
with its own target dir; the baselines passed in both.

| Mutation | Before | Now: cases that fail |
| --- | --- | --- |
| `check_block_context_free` without its MoneyRange (`check_block_money_range`) | gnb-crypto runner passed; node runner failed only `coinbase/above-max-supply/*` (the connect path's own output MoneyRange rejected the tx cases with the same class) | both runners: `value/output-above-max-supply/*`, `value/outputs-sum-above-max-supply/*`, `value/output-u64-max/*` (context-free stage), `coinbase/above-max-supply/*`, `value/block-output-total-above-max-supply/*` |
| block-wide output total not summed | (no vector) | both runners: `value/block-output-total-above-max-supply/*` |
| `validate_pow` skips the GnB-SMH evaluation (limit kept) | both runners passed | both runners: `pow/genesis-bits-proof-fails/post` |
| `validate_pow` evaluates the proof for `nonce ^ 1` | (not run: the only proof, at 0x2100ffff, holds for nearly any nonce) | both runners: `pow/genesis-bits-mined/post`, `pow/genesis-bits-proof-fails/post` |
| admission without its "no inputs" rule (still refused, as zero-value) | node runner passed | node runner: `struct/no-inputs/*` (refusal class) |
| `core::check_min_fee` accepts one unit below the minimum | gnb-crypto runner passed | gnb-crypto runner: `fee/minimum-minus-one/*` |
| `core::check_coinbase_maturity` accepts depth 99 | gnb-crypto runner passed | gnb-crypto runner: `maturity/depth-99/*` |
| `MAINNET_HARDENING_ACTIVATION_HEIGHT` + 1 (run as 110,001 when the height was 110,000, the cases then named `.../110000`; re-run as 17,501 on 2026-10-16 against both runners after the move to 17,500, in the working tree, and reverted: each failed exactly these five cases, the node runner 7 checks of 694 on mainnet, the gnb-crypto runner 3 of 1,475 tx and 2 of 1,013 block checks) | both runners passed | both runners: `basic/mainnet-schedule/17500`, `version/mainnet-boundary/v1-at-17500`, `tx64/mainnet-boundary/17500`, `commitment/no-commitment-at-mainnet-height-17500`, `pow/mainnet-17500-pow-limit-bits` (node: also the mempool verdicts of the three transaction cases) |
| `TESTNET_HARDENING_ACTIVATION_HEIGHT` = 2 | node runner passed | both runners: `net/testnet-schedule/height-1` (node: the testnet child, consensus and mempool) |

Python corruptions of the second round, each reported: the mined nonce + 1
(`bad-pow` and a stale block id), the failing proof relabelled valid, the
refusal class of `witness/one-trailing-byte/post` set to its consensus class
(that class became the recorded one with the mempool-policy merge, see
"History" below),
that of `struct/no-inputs/pre` set to `min-fee`, and `basic/activation-zero/height-1`
labelled `schedule`.

**Third round** (review of the vectors merge, 2026-10-15). The gate of
admission's consensus witness refusal (`check_witnesses_for_next_block_at`:
`Rejected` only when `check_tx_version(tx.version, next_block_height, act)`
selects sighash v3) had no vector on either side: every non-canonical
witness in the files was version 1 below the activation or version 3 from
it. Each gate below replaced the version-rule verdict, in the node
(`node/src/mempool/admission.rs`) and in the Python model
(`reference/gnb_validity.py::admission`, `version_rule(..) == "v3"`). The
node runner (`tx_vectors_mainnet`) was rebuilt and run against the files
with and without the two cases added in this round; the baselines passed.

| Gate mutation | Without the two cases | Now: cases that fail |
| --- | --- | --- |
| the height alone (`is_active_at(next_block_height, act)`; Python `tx_rules_active(height, activation)`) | node runner and Python check passed | node runner and Python check: `witness/version-1-one-trailing-byte-from-the-activation/post` (refusal class) |
| the version alone (`tx.version == 3`) | node runner and Python check passed | node runner and Python check: `witness/version-3-sighash-v2-one-trailing-byte/pre` (refusal class) |

Without the two cases, `vector_coverage` fails ("no non-standard witness on
a version other than 3 at/after the activation"). Both mutations also fail
the node's unit test
`mempool::admission::tests::non_canonical_witness_is_rejected_only_where_consensus_requires_it`,
which checks version 3 at, after and below an explicit activation height and
version 1 at it.

## History

- **Mempool-policy merge (MEM-5 verdicts).** Admission's refusals were split
  into consensus (`AdmissionError::Rejected`) and policy
  (`AdmissionError::NonStandard`) verdicts, and a non-canonical witness on a
  version-3 transaction for a block at/after the activation became a
  consensus refusal (`admission::check_witnesses_for_next_block`). The
  refusal class of the 17 post-activation cases with such a witness
  (`size/script-sig-10000-bytes/post`, `suite/relabelled-*/post` (3),
  `suite/mldsa-only-sig-3310-bytes/post`,
  `raw/raw-public-key-raw-signature/post` and 11 `witness/*/post`) moved from
  `non-standard-witness` to `witness-non-canonical`, the class of the rule
  that now refuses them; no consensus verdict and no other refusal class
  changed, and `block_vectors.json` is unchanged. The generator states the
  rule once (`Regime::witness_refusal`) and refuses to record
  `non-standard-witness` for a version-3 case at/after the activation; the
  Python model checks every input's framing before any suite, as admission
  does. The node runner pins the `AdmissionError` variant of every refusal
  (table above). Checked by mutation: admission refusing dust as
  `NonStandard` and dropping the version-3 arm of
  `check_witnesses_for_next_block` makes the node runner fail
  `dust/output-1/*` and `dust/output-545/*` (variant) and the 17 cases above
  (class); against the pre-merge file, the Python check reports exactly
  those 17 refusal classes.

- **Review of the vectors merge.** Two cases pin the version gate of
  admission's witness verdict from both sides
  (`witness/version-1-one-trailing-byte-from-the-activation/post`,
  `witness/version-3-sighash-v2-one-trailing-byte/pre`; see "Effectiveness",
  third round), and `vector_coverage` requires both. The refusal class
  `non-standard-no-inputs` was renamed `no-inputs` (`struct/no-inputs/*`, 2
  cases): admission refuses a transaction without inputs with its own
  consensus rule (`AdmissionError::Rejected`: a zero fee is below the
  consensus minimum), so the class no longer names it relay policy. The
  generator also refuses to record `witness-non-canonical` as the refusal
  class of anything but a version-3 transaction at/after the activation. No
  other case changed; `block_vectors.json` is unchanged.

- **Mainnet activation moved to 17,500 (2026-10-16).** The generator's
  `MAINNET_ACT` went from 110,000 to 17,500 with
  `MAINNET_HARDENING_ACTIVATION_HEIGHT`, and both files were regenerated. The
  13 `activation_source: schedule` cases of the mainnet boundary moved from
  109,999 / 110,000 to 17,499 / 17,500 and are named with their heights:
  6 transactions (`basic/mainnet-schedule/*`, `version/mainnet-boundary/*`,
  `tx64/mainnet-boundary/*`) and 7 blocks
  (`commitment/no-commitment-at-mainnet-height-*`,
  `commitment/wc-suffix-at-mainnet-height-17499`,
  `commitment/wc-suffix-stale-witness-at-mainnet-height-17499`,
  `coinbase/powit-miner-share-plus-one-at-mainnet-height-17499`,
  `pow/mainnet-*-pow-limit-bits`). Both heights are above the PoWit height
  (10,000) and the `|wc:` height (5,000), as 109,999 / 110,000 were, so
  every case keeps its regime. The id seeds a transaction case's funding
  outpoint and destination, so its prevouts, bytes, txid, wtxid, digests and
  wire size changed (the txid preimage size did not); a block case's header
  height changed, and so its block hash, and where the coinbase label
  carries the height (the no-commitment and pow cases) also its txids,
  Merkle roots and wire size. Subsidy, parents commitment and witness root
  are unchanged. Every verdict, error and refusal class, regime, activation
  source, scope and pow mode is unchanged, the case counts (191 / 105) too,
  and no other case changed. In `merkle_vectors.json` the block at the
  mainnet activation height moved from 110,000 to 17,500 (its commitment
  height and so its coinbase and header roots), and `difficulty_vectors.json`
  section `hardening_pow_limit` moved its 12 mainnet cases to 17,499 / 17,500
  / 17,501 with their parent times, with the same bits.
- **Phase 4, package R1b (audit POW-9 residual).** One block case was
  added, `pow/non-canonical-bits` (bits `0x21007fff`, a decodable but
  non-canonical encoding of `0x7fff << 240`, whose canonical encoding is
  `0x207fff00`): `bad-bits` at every height. `Block::validate_pow` now
  accepts canonical encodings only (`gnb_smh::difficulty::
  try_canonical_bits_to_target`), and so do the Python model
  (`gnb_difficulty.is_canonical_bits` in `check_pow_limit`) and the runners'
  pow-limit stage. No other case changed: every case whose bits decode is
  canonical, and every block an `expected_bits` check accepts has canonical
  bits (docs/CONSENSUS.md, "Block header and proof of work").
- **Phase 4, package R1b (audit B2-T10).** Four block cases were added:
  `parents/duplicate/pre` (valid), `parents/duplicate/post`
  (`duplicate-parent`) and the mainnet boundary
  `parents/duplicate-at-mainnet-height-17499` (valid) and `-17500`
  (`duplicate-parent`; the package was merged after the activation move
  above, and the generator, run with `MAINNET_ACT` = 17,500, names them with
  the heights it builds them at). From the activation a header must list
  each parent once (`block_rules::check_parents_distinct`); the Python model
  checks it first among the hardened structural rules, as
  `check_hardened_body` does. No existing case changed: none lists a parent
  twice. With the POW-9 case above, `block_vectors.json` holds 110 cases.

- **Re-audit B1-T0 / B2-T8 (phase 4): the size verdict of a block id.**
  This chain measures the block size on the wire encoding at every height
  (`block_rules::legacy_block_size` below the activation, the length of
  `Block::size_bytes`, the PoWit section included from `powit_height()`;
  Python `legacy_block_size`), which writes the uncommitted `blue_score` as
  a fixed-width u64, so every copy of a block id has the same size verdict
  (the audit's bincode measure did not). Four cases are new: the two
  pre-activation block ids at the wire limit carrying `blue_score` 0 and
  `u64::MAX` (`size/wire-exactly-1000000-blue-score-{0,max}/pre`, valid, and
  `size/wire-1000001-bincode-below-blue-score-{0,max}/pre`, `block-size`),
  with the verdict of the original; both runners and the Python check
  assert that the recorded `wire_size` is the pre-activation measure, and
  `vector_coverage` that the copies share the id and the verdict. No
  existing case changed.

- **Re-audit B1-T1 (phase 4): no block-wide output total.** The VAL-11
  remediation's block-wide output-total MoneyRange rule is removed (chained
  in-block spends count coins once per hop; Bitcoin Core has no such sum).
  `value/block-output-total-above-max-supply/{pre,post}` changed from
  `value-out-of-range` to valid (the verdict cb60040 pinned, from the
  audit's VAL-11 remediation merged by 28a619d; every release of this chain
  before 28a619d accepts these blocks), and
  `value/chained-spends-output-total-above-max-supply/{pre,post}` (three
  chained spends of a 4,500,000 GNB coin, outputs summing to about
  13,500,000 GNB, above the 12,500,000 GNB supply) are new and valid. The effectiveness rows above that name
  the block-wide sum ("block-wide output total not summed", and that case in
  the `check_block_money_range` row) describe the rule as it was; the runners
  now require both cases to be valid (`vector_coverage`), and restoring the
  block-wide sum fails both runners on the four cases. No other case changed.

- **Re-audit B1-T13 (phase 4): the connect order.** The connect validates a
  block in two passes: the rules the block id commits to for every
  transaction (now including the minimum-fee floor computed on the size with
  every `script_sig` empty, and prevout scripts of an output kind; this
  chain's locktime and output-kind rules among them) and the coinbase value,
  then the witness rules of every transaction (the policy-spend rules,
  which the vectors do not model, first). No verdict changes;
  the class of a case failing several rules can. Four cases are new and pin
  the order: `fee/zero-with-a-bad-signature/{pre,post}` (`min-fee`, not
  `bad-signature`) and `order/bad-signature-then-overspend/{pre,post}`
  (`inputs-below-outputs`, not `bad-signature`). The gnb-crypto runner and
  the Python model follow the same order. Checked by mutation: running the
  witness rules of each transaction inside the first pass (the old order)
  fails the node runner on both block cases, and dropping the fee floor
  fails it on both transaction cases. No existing case changed.

- **Re-audit B1-T14 (phase 4): coinbase maturity by selected-chain depth
  from the activation.** Optional fields `dag_height` (case) and
  `coinbase_dag_height` (prevout), emitted only when they differ from
  `height` / `coinbase_height`. Four transaction cases are new:
  `maturity/merge-header-depth-100-dag-depth-10/{pre,post}` (valid pre,
  `immature-coinbase` post) and
  `maturity/inflated-coinbase-header-dag-depth-100/{pre,post}`
  (`immature-coinbase` pre, valid post). The relative timelocks of spend
  policies follow the same measure (docs/CONSENSUS.md, "Coinbase
  maturity"); the vectors do not model policy spends, the node tests do
  (`fix_connect_rules.rs`). No existing case changed.

## PoWit vectors (second hardening activation)

`reference/powit_vectors.json`, generated by `reference/powit_reference.py`
(the executable specification of docs/CONSENSUS.md, "PoWit"; its own tests
in `reference/powit_reference_test.py`) and checked against the Rust code by
`crates/gnb-crypto/tests/powit_vectors.rs`, pins what PoWit audit findings 1
and 4 changed: the v1 and v2 attestation messages (with the 140-byte v2
preimage spelled out) and the version chosen by target height, the witness
id, the regime boundary, inactivity decay, the two-thirds threshold, `W(e)`
under both regimes (the 64-key cap, the window and its lag, bans, decay,
saturation), the evidence epochs, and the finding's numbers. CI's
`python-reference` job runs the reference's tests and `--check` (the file is
exactly what the generator writes). Signatures are not in the vectors: the
state-machine tests in `crates/gnb-crypto/src/core/powit/hardening2_tests.rs`
run real KES signatures, and `old_regime_transition_is_pinned` pins the
digest of a 180-block run under the old rules.

## Findings while building the vectors

- Mempool admission does not apply BIP30 (an output on the outpoint of an
  unspent coin), which block validation applies from the activation. It is
  unreachable: a coin at `(txid, i)` exists only if a transaction with that
  txid was applied, which spent that transaction's inputs (a non-coinbase
  txid commits to them) and wrote its transaction-index row, and admission
  refuses an already-confirmed txid and spent inputs; a coinbase is never
  admitted. The policy store of the vectors models the transaction index, and
  `bip30/output-overwrites-an-unspent-coin/pre` pins the `already-confirmed`
  refusal.
- Pinned pre-activation behaviour that is easy to forget: sighash v2 does not
  commit to the spent amount or script (WAL-1), so a signer told a wrong
  amount still signs a valid transaction; a hybrid signature split and
  relabelled to suite 0x0002 verifies (CRY-2); lock time and sequence are not
  enforced at any height; a transaction with no outputs is consensus-valid.
