# ObenBlock ledger v1: stateless validation without a committee

Status: draft with a tested reference implementation. Not audited.
Normative definition: [`reference/gnb_ledger.py`](../reference/gnb_ledger.py).
Rust port: [`rust/src/ledger.rs`](../rust/src/ledger.rs). Both must reproduce
[`reference/ledger_vectors.json`](../reference/ledger_vectors.json), including the error code and
fault class of every invalid case. `rust/tests/ledger_differential.rs` also compares them on
random blocks. It mutates blocks from the Python producer and requires identical verdicts from
`reference/ledger_oracle.py`.

## 1. What it guarantees

Every GnB node checks every block while holding only two 32-byte state roots. A block's effect on
the state is a deterministic function of the parent's roots and the committed block, so no
committee, vote or trusted prover takes part in validity. Ordering stays where GnB-SMH puts it:
proof-of-work over GhostDAG.

| Property | GnB ledger v1 |
| --- | --- |
| Validity of state | Deterministic. A hashrate majority cannot make validating nodes accept a spend of a missing output, a double spend, an overspend, coins beyond subsidy plus fees, or an unauthorized spend |
| Ordering and finality | Probabilistic, by PoW depth. A hashrate majority can still reorder, double-spend inside the reorg window and censor |
| State a node keeps | 64 bytes of roots, plus headers |
| Witness per touched key | 32 + 32·(log2 n + 0.3) bytes for n live outputs: 680 B at 2^20, about 1.0 KB at 2^30 |
| Cost to check one witness | 256 Keccak-f[1600] permutations |
| Proof system on the accept path | None. Recursive STARK proofs are for sync and pruning only (section 8) |

This is the design Bloch's ZK Ledger describes ("one kilobyte, one proof", no committee), adapted to
GnB: the roots are committed in GnB's own header, and the accumulator is a sparse Merkle tree rather
than a Utreexo forest (section 3 explains why).

## 2. Hashing and encodings

All integers are little-endian unless stated otherwise. `enc(b) = u32le(len(b)) || b`.

```
H(label, data) = SHAKE256(enc("GNB-LEDGER-v1/" || label) || data, 32)
```

| Label | Input | Use |
| --- | --- | --- |
| `node` | left ‖ right | tree node |
| `leaf` | key ‖ value | present leaf |
| `outpoint` | txid ‖ u32le(vout) | key of an output in the tree |
| `utxo` | 49-byte record | value of an output |
| `txid` | tx_bytes | transaction identity used by outpoints (no authorization) |
| `wtxid` | wire bytes | exact transaction bytes, authorization included; the header commits to these |
| `txnode`, `txroot` | | transaction tree |
| `state` | utxo_root ‖ nullifier_root | state commitment in the header |
| `block` | header ‖ u64le(nonce) | block id |
| `witness` | witness bundle bytes | `witness_root` in the header |
| `test-owner` | secret | test-only authorization |

## 3. State tree

The state is a sparse Merkle tree of depth 256 keyed by 32-byte keys.

- Leaves are at height 0, the root at height 256. At height h, the path node is a right child iff
  bit (255 − h) of the key is 1, counting from the most significant bit of `key[0]`.
- An absent leaf is `EMPTY` (32 zero bytes). A present leaf is `H(leaf, key ‖ value)`.
- `DEFAULTS[0] = EMPTY` and `DEFAULTS[h+1] = H(node, DEFAULTS[h] ‖ DEFAULTS[h])`. The empty root is
  `DEFAULTS[256]`.
- A **witness** for a key is its 256 siblings, encoded as a 32-byte bitmap followed by the siblings
  that differ from their default, in increasing height. Bit h sits in byte h>>3 at position h&7,
  counting from the least significant bit. A listed sibling equal to its default is rejected, so
  each witness has exactly one encoding.
- The same witness proves either presence (`H(leaf, key ‖ value)` hashes up to the root) or absence
  (`EMPTY` does). Recomputing with a new leaf gives the root after an insert or a delete.

There are two trees. `utxo_root` holds unspent outputs. `nullifier_root` is reserved for the shielded
pool and stays at the empty root in v1. The header commits to
`state_commitment = H(state, utxo_root ‖ nullifier_root)`.

**Why not Utreexo.** A Utreexo forest proves membership only. GnB needs absence proofs in two
places: rejecting a transaction whose input is already spent (section 5) without trusting the
producer, and the nullifier set of a shielded pool, which must prove that a nullifier is new. Bloch's
Coherence pool never committed its nullifier set (finding F9 in its repository); this tree is where
that commitment goes.

## 4. Transactions

```
tx_bytes = u32le(1) || u8(kind)
           || [kind = coinbase: u64le(height) || parents_root[32] || enc(extra)]
           || u32le(n_in)  || (txid[32] || u32le(vout)) * n_in
           || u32le(n_out) || (u64le(amount) || owner[32]) * n_out
wire     = tx_bytes || u32le(n_auth) || enc(auth_i) * n_auth
txid     = H(txid, tx_bytes)          wtxid = H(wtxid, wire)
record   = u64le(amount) || owner[32] || u64le(created_height) || u8(is_coinbase)   (49 bytes)
key      = H(outpoint, txid || u32le(vout))       value = H(utxo, record)
```

Rules checked without state ("isolation"; a committed transaction that fails them makes the block
invalid):

- 1 to 1,024 outputs, each amount ≤ MAX_MONEY, and the sum ≤ MAX_MONEY.
- A regular transaction has 1 to 1,024 distinct inputs, one authorization entry per input of at most
  16,384 bytes, and no coinbase fields.
- The coinbase is the first transaction and only the first, has no inputs, at most 100 bytes of
  `extra`, and carries the block height and the header's `parents_root` (a regular transaction
  carries neither). Two blocks can therefore share a coinbase, and with it the coinbase's output
  keys, only if they are built on the same parent set at the same height and pay the same outputs
  with the same `extra`: a choice of their own producer. Another miner cannot force a collision on
  a block without mining a sibling block on the same parents that pays that block's payee exactly.
  When such twins meet in a mergeset, the second one forfeits its coinbase (section 7).
- Per block: at most 65,536 transactions, at most 16,384 inputs plus outputs, at most 4,000,000 bytes
  of transactions, and a witness bundle of at most `MAX_WITNESS_BYTES` = 33,554,432 bytes (32 MiB).
  The bundle cap leaves room for one maximal transaction (1,024 inputs and 1,024 outputs, every
  proof at full depth: about 17 MB) next to a maximal coinbase. A typical full block at 2^30 live
  outputs needs about 18 MB.

Authorization is a pluggable function of the transaction and the spent records. The reference ships
`test_preimage_auth`, which is test-only and insecure. GnB spends will be authorized by the hybrid
ML-DSA-65 ‖ Falcon-1024 scheme over the txid. That rule is not specified yet (section 10).

## 5. Witness bundle and outcomes

A block travels with a witness bundle, and the header commits to it:
`witness_root = H(witness, bundle)`. It lists one entry per transaction, regular transactions first
in block order, then the coinbase. Every proof is checked against the root left by the previous
operation.

The commitment bounds the work a bad bundle can cause. A bundle that does not hash to
`witness_root` is rejected after one hash over its bytes, before any proof is checked (transient:
fetch it again). A bundle that does hash to it but proves something false makes the block
permanently invalid, so a node runs the proof checks of a block id (up to 16,384 witness checks,
about 8.4 M Keccak-f permutations with the updates) to completion at most once, and every further
attempt needs a new header with valid proof of work. Without the commitment a peer could resend
the same header with a bundle whose last proof is wrong and make the node redo all of that work,
without bound.

| Tag | Entry | Proves |
| --- | --- | --- |
| 0 `ACCEPT` | per input: record ‖ witness; then per output: witness | inputs present (then deleted), context rules pass, outputs absent (then inserted) |
| 1 `REJECT_MISSING_INPUT` | u32 index ‖ witness | that input is absent |
| 2 `REJECT_OUTPUT_EXISTS` | u32 index ‖ value ‖ witness | that output key is taken |
| 3 `REJECT_CONTEXT` | per input: record ‖ witness (no updates) | inputs present and a context rule fails |

A transaction is accepted iff all its inputs are present, the context rules pass (coinbase maturity,
inputs ≥ outputs, authorization), and all its output keys are absent. Each tag proves either all three
conditions or the failure of one. The validator re-evaluates the context rules itself and rejects any
entry that contradicts them. The producer therefore chooses only which transactions to include, never
their outcome, and the post-state root is unique.

The coinbase is applied last, so it can claim the subsidy plus the fees of transactions accepted in
the same block. Its entry is `ACCEPT` with one absence witness per output. If one of its output keys
is already taken, the entry can instead be a `REJECT_OUTPUT_EXISTS` proof, which shows the block is
invalid.

Rejected transactions pay no fee but still cost witness checks. The per-block cap on inputs plus
outputs bounds that cost at 16,384 witness checks per block, once per block id.

## 6. Header and validation order

```
header = u32le(version) || parents_root[32] || tx_root[32] || witness_root[32]
         || state_commitment[32] || u64le(timestamp) || target[32, big-endian]   (172 bytes)
tx_root = H(txroot, u32le(count) || top)   top = binary tree of H(txnode, l ‖ r) over wtxids,
                                           odd node promoted unchanged
PoW     = GnB-SMH(header, nonce) < target
```

`parents_root` is the GhostDAG layer's commitment to the parents. `tx_root` covers wtxids, so
authorization is committed: a relaying peer cannot change a transaction's outcome by editing its
signature.

Validation runs in two stages, and every failure has a class:

1. **Header** (cacheable per block id): length and version (`header`), 1 ≤ target ≤ max
   (`target`), GnB-SMH below target (`pow`).
2. **Body**: the received transactions must hash to `tx_root` (`tx-root`). A received bundle
   larger than `MAX_WITNESS_BYTES` is refused before it is hashed (`witness-size`). Otherwise it must
   hash to `witness_root` (`witness-commitment`). Then come the block byte limit and decoding
   (`isolation`), the isolation rules (`isolation`, including the coinbase's height and
   `parents_root`), the witness bundle (`witness-format`, `noncanonical-proof`,
   `witness-mismatch`, `accept-invalid`, `reject-invalid`), the coinbase claim (`coinbase`), and
   finally the state commitment (`state-commitment`).

| Class | Codes | Meaning | Node action |
| --- | --- | --- | --- |
| Permanent | header, target, pow, isolation, witness-format, noncanonical-proof, witness-mismatch, accept-invalid, reject-invalid, coinbase, state-commitment | the committed block (transactions and bundle) is invalid | mark the block id invalid |
| Transient | tx-root, witness-size, witness-commitment | the body or bundle received does not hash to the header's commitments, or the bundle is larger than any committed bundle may be | penalize the peer, fetch again |

A relayer cannot damage a block into a permanent verdict: any change to the transactions or the
bundle fails one of the two hash checks first. A header replayed with junk bodies or bundles costs
one hash per attempt and no second GnB-SMH run if nodes cache the header verdict. A bundle over
`MAX_WITNESS_BYTES` is refused unhashed. Such a bundle cannot be attributed to the header, so the
code is transient. But a block whose committed bundle exceeds the cap can never be validated, so
the cap is a consensus rule that costs no node more than `MAX_WITNESS_BYTES` of hashing per attempt.
Peers' oversized bodies and bundles should also be cut at the network layer.

## 7. GhostDAG

The transition function applies an ordered list of transactions to a state. The reference
implements the single-parent case: a block's own transactions on its selected parent's state. The
REJECT outcomes exist for the multi-parent case. A chain block that merges parallel blocks applies
their transactions in GhostDAG order, and a conflicting transaction from a parallel block becomes a
proven rejection, not an invalid block. Most mergeset rules are still open item 1.

**Coinbase collision in a mergeset (audit LED-1).** Two blocks share their coinbase output keys
only if they are built on the same parents at the same height and carry identical coinbases
(section 4). A merged block is applied with `apply_block_txs(..., merged=True)` (Rust:
`apply_merged_block_txs`). If its coinbase outputs already exist because its twin was applied
first, its coinbase entry is `REJECT_OUTPUT_EXISTS`: a presence proof of one output key whose value
must equal `H(utxo, record)` for the record this coinbase would create (same amount, owner and
height, coinbase flag set), otherwise `coinbase`. The merged block then **forfeits its coinbase**.
No coinbase output is created, its other outcomes stand, and the merging block stays valid. The
payee was paid once by the twin, and no value is minted twice. The same entry in a block applied on
its own selected parent still makes that block invalid (`coinbase`), as before. Invalidating the
merging block instead would let anyone who mines a twin that pays its payee make every honest
merger of both invalid. The coinbase claim check (subsidy plus fees) does **not** apply to a
forfeited coinbase: it mints nothing, and the identical coinbase holding the output passed that
check when its block was applied. It must not apply: a twin built from the same template carries
the same transactions, which the first block already spent, so the merged twin's own fees are 0
while its coinbase claims subsidy plus the first block's fees. The check still applies to every
coinbase that is created (the `ACCEPT` entry, merged or not) and to a non-merged block whose entry
is `REJECT_OUTPUT_EXISTS`. A non-twin merged block whose fee-paying transactions conflict with
already-applied ones can still fail it; that is part of open item 1 (fee attribution). Vectors: the
`mergeset` section of `ledger_vectors.json`.

## 8. Proofs stay off the accept path

This keeps the rule Bloch already fixed for its ledger: no consensus validity rule may require a
proof that a third party has to produce within bounded time. A recursive STARK proving
"state_commitment at height h follows from genesis under these rules" is still useful, for two
purposes:

- **Fast sync:** a new node verifies one proof plus the headers instead of replaying history.
- **Pruning:** archival data may be dropped only when three things hold together: the proof
  verifies, the data is available, and a burial floor is passed. This is Bloch's `PruneGate`. With no
  proof, nothing is pruned and the disk grows; acceptance never stalls.

Raw FRI proofs are tens to hundreds of KB, so the "one kilobyte" is the roots and the per-key
witness, not the proof. None of this is implemented in v1.

## 9. Costs

| Item | Size or time |
| --- | --- |
| State kept by a validating node | 64 B of roots |
| Witness, n = 2^20 live outputs (measured) | 680 B |
| Witness, n = 2^30 (extrapolated, +32 B per doubling) | about 1,000 B |
| Witness entry for a 1-input, 2-output transaction at n = 2^30 | about 3.1 KB, on top of the transaction (a hybrid signature alone is 4,589 B) |
| One witness check | 256 Keccak-f[1600]; 0.18 ms on the reference container (0.61 µs per permutation) |
| Worst-case block (16,384 keys) | about 3 s on one core of that container |

Witness checks are independent once the bundle is in hand, so they can run in parallel; only the
chain of root comparisons is sequential. Sizes come from `analysis/witness_size.py`, times from
`smh-bench witness`.

Block producers and bridge nodes hold the full state to build witnesses; validating nodes do not.
The reference `SparseMerkleTree` stores every node on every path and is for tests only. A production
store must compress single-leaf chains.

## 10. Open items

1. **GhostDAG mergeset rules:** acceptance order, one coinbase per merged block, the context
   (height, maturity) of a merged block's transactions, and fee attribution (a merged block whose
   fee-paying transactions lost to conflicts can overclaim; only the identical twin is settled). The
   coinbase collision is settled: the merged twin forfeits its coinbase and is exempt from the claim
   check (section 7).
2. **Authorization:** the hybrid ML-DSA-65 ‖ Falcon-1024 rule, its sighash, and its per-input
   encoding. Wallets and mempools must track outcomes by wtxid. A producer can include a copy of a
   user's transaction with garbage authorization; that copy is rejected without effect, and the
   genuine transaction can still be included later.
3. **Shielded pool on the nullifier tree.** Bloch's Coherence could not be ported as is: its nullifier
   set had no root (fixed here), and its spend statement did not bind `nk` to spending authority
   (CR-01). Statement v2 in `coherence-core` now binds it (audit COH-1, `docs/CONSENSUS.md`). Moving
   the pool onto this tree is still open.
4. **Parameters:** MAX_MONEY, subsidy, coinbase maturity, and the block limits are placeholders.
5. **Weight-cap anchor:** the GnB-SMH spec anchors its heavy-block cap to an FFG-finalized block,
   which does not exist without a committee. Proposed: anchor it to an objective point, such as the
   block's own selected-chain ancestor at a fixed depth.
6. **Witness relay:** multiproofs that share upper tree levels across a block, and relay limits. The
   bundle size cap is `MAX_WITNESS_BYTES` (section 4).
7. **Header sync cost:** a GnB-SMH header takes about 0.55 s to check, and the ledger does not change
   that. Options are FlyClient-style sampling, or proving header PoW inside the recursive STARK.
8. **Recursive proof system:** choose between SP1 and Plonky3 over FRI. In-circuit hybrid
   signatures are expensive: Bloch measured 7.27 M RV32IM instructions per signature.
