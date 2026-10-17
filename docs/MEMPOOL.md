# Transaction relay and mempool policy

This is **node-local policy**. Nothing here changes which blocks or
transactions are valid (see `CONSENSUS.md` for that); two nodes with different
policies agree on every block. The policy decides what a node keeps in its
mempool, what it relays, and what it puts into its own block templates.

Implementation: `node/src/mempool/` (`mod.rs` the pool, `admission.rs` the
shared admission function, `orphanage.rs` the orphan pool, `relay.rs` the
gossip relay) and `node/src/template.rs`. The values below are the constants
of those files; `getmempoolinfo` reports them under `policy`.

## 1. Admission (one function for every ingress)

Gossip, RPC `sendrawtransaction` and the re-injection of transactions from
blocks disconnected by a reorg all call `admission::admit`. Checks run
cheapest first, so the size-dependent signature work only runs on a
transaction that passed everything else:

1. structure: not a coinbase, at least one input and one output;
2. size: canonical wire size and bincode size at most `MAX_TX_SIZE`
   (409,600 bytes);
3. known: already pooled, already confirmed, or in the recent-rejects filter
   (50,000 wtxids, cleared whenever the selected tip or the next block's
   height changes — a fork-loser with a greater DAG height or a
   disqualification can move the height without moving the tip; a verdict
   computed before such a change is never remembered after it);
4. standardness: canonical-encoding limits, MoneyRange, no dust output
   (< 546 sat), no zero-value output, the canonical witness of every input
   and a hybrid (suite 0x0001) public key (`CONSENSUS.md`, "Relay policy
   (all heights)"; skipped for re-injection). Every witness's framing is
   checked before any key's suite. A non-canonical witness is policy, except
   on a version-3 transaction whose next block is at/after the hardening
   activation: there it breaks the consensus witness rule (CRY-1) and the
   transaction is consensus-invalid;
5. next-block rules: the version valid **and standard** for the height of
   the next block, and from the hardening activation no 64-byte txid
   preimage (`admission::check_tx_for_next_block`; `CONSENSUS.md`, "Which
   height");
6. no input spent twice;
7. every input is an unspent output in the UTXO set **or an output of a
   pooled transaction** (§4); otherwise "missing inputs" (§3);
8. coinbase maturity at the height of the next block;
9. fees: inputs ≥ outputs, consensus minimum fee, 1 sat/byte relay minimum,
   the rolling minimum fee rate (§6);
10. pool policy: replacement rules when it conflicts with pooled transactions
    (§7), ancestor/descendant limits (§4);
11. input scripts and signatures under the consensus rule of the next block's
    height (the digest the version selects; sighash v3 from the activation,
    which commits to every spent amount and script — for an input spending a
    pooled parent, that parent's output), last, through a bounded
    verified-signature cache shared with block validation (keyed by the
    digest regime, the activation state, the wtxid and the spent outputs;
    the key is computed once per admission). The witnesses and public-key
    hashes are checked before the cache lookup; only a cache miss reaches
    the signature budget (§2) and the signature math.

"The next block" is the node's own next template
(`template::next_template_height`, cached in `Mempool::next_height`), the
one height admission, eviction, re-injection, templates and wallets use. The
final insertion runs under the acceptance lock: it re-checks that every input
is still unspent or pooled and, when a block moved the next height while the
transaction was being checked, re-checks steps 5 and 8 at the new height.

## 2. Gossip relay

A gossiped `NewTransaction` frame is **not forwarded until the node has
judged it** (gossipsub `validate_messages`, verdict reported by the message
processor, exactly as for blocks):

| verdict | when | effect |
|---|---|---|
| Accept | the transaction entered the pool | forwarded to the mesh |
| Reject | penalties in force (below) AND a malformed frame (non-canonical bytes, wrong claimed txid) or a consensus-invalid transaction (check 1 coinbase / no inputs, 4 canonical limits / MoneyRange / dust / the canonical witness of a version-3 transaction at/after the activation, 6, 9 consensus parts, 11) | not forwarded; the delivering peer takes gossipsub's invalid-message penalty on the transaction topic |
| Ignore | a malformed frame or a consensus-invalid transaction while penalties are not in force (still remembered in the recent-rejects filter and charged to the signature budget); policy refusals (size, no outputs, zero-value output, a non-canonical witness where it is not the consensus rule, suite 0x0002, the version policy, fee below the relay or rolling minimum, replacement and chain limits, pool full); the rules whose verdict depends on this node's next block height (step 5, an immature coinbase spend, and a spend that fails only the second hardening upgrade's policy key-identity rule, PF-4: a peer one block behind across the activation relays such a transaction honestly); duplicates, recently rejected ids, missing inputs, signature budget exhausted | not forwarded, no penalty |

**Penalties and older releases.** Every release before the validating relay
forwards every `NewTransaction` frame without validating it, on the same
topic (`gnb/txs/1`). Gossipsub charges a `Reject` to the delivering peer and
to every peer that delivered a duplicate; with the transaction topic's
weights (−50 per invalid delivery, squared, topic weight 0.3, decay ×0.5 per
minute, graylist threshold −400) about six invalid frames within a minute or
two graylist a peer, after which all its gossip, blocks included, is ignored.
So while such a release can be an honest peer on the chain, a `Reject` would
let an attacker have every upgraded node graylist every non-upgraded one by
sending it a few garbage frames. Those releases reject the hardening
activation block (`CONSENSUS.md`, "Block rules at the hardening
activation"), so **penalties are in force once the node's next block height
is above the activation height** (the chain contains the activation block;
`TxRelay::penalties_in_force`; mainnet from height 17,501, testnet and
regtest from block 1). From then on every peer that follows the chain
validates before forwarding, an invalid frame is delivered only by its
author, and the penalty lands on the author and never on an honest relay.
Before that, the node still never forwards an invalid frame.

**Signature budget.** Step 11 is charged to the **connection that delivered
the frame** (the gossipsub `propagation_source`), never to the signed gossip
author: one connection can sign every frame with a fresh keypair, so an
author key bounds nothing. All-or-nothing, from a token bucket per
connection (burst 400, refill 20 per second, at most 4,096 connections
tracked, far above the connection limit) **and** from one node-wide bucket
shared by every connection (burst 4,000, refill 400 per second). A cache hit
costs nothing. The tokens are **refunded when the transaction enters the
pool**, so a connection pays only for verification that did not lead to
admission (an invalid signature, a full pool, a failed orphan re-try) and an
honest relay forwarding valid traffic is never throttled. A connection
without enough tokens gets `Ignore` and no signature is checked. A
connection's bucket is dropped when it disconnects.

The price (audit B1-T19, Phase 4; `relay::signature_gate_cost`,
`relay::frame_cost`). A token pays for one signature check or for
64 KiB hashed or decoded (about the same time). Step 11 costs one token per
signature plus the bytes its digests hash. An input spending a policy output
carries the policy's `m` signatures (up to 7), each verified, so it costs `m`
(audit F5, `relay::input_signature_count`: the policy witness is decoded, not
verified; any other input costs one; before F5 a 7-of-7 input cost one). The
bytes: under sighash v2 (below the
activation; mainnet's regime until height 17,500) every input clones,
re-encodes and hashes the whole transaction, outputs included, so the bytes
are inputs × size; under sighash v3 the transaction is hashed once into
precomputed midstates plus a fixed preimage of at most 256 bytes per input.
Before Phase 4 a token was one input whatever the size: a one-input
transaction carrying 390 kB of outputs cost one token, and 50 connections
each spent their own full burst at once. Decoding a frame, checking its
canonical encoding and hashing its wtxid (once per frame, from the received
bytes; the transaction used to be re-encoded and hashed up to four times per
frame: the orphan check, the reject filter, the signature cache key and the
rejection record) are charged before decoding, at one token per
64 KiB of frame, so a connection out of budget costs one size check.

**Its own task.** Transactions are judged on a task of their own, fed by a
channel of their own (`network::IngestSink::Validated`, `txs`), not by the
block processor: a backlog of expensive transaction frames used to queue the
blocks of every peer behind it (and fill the shared channel, dropping
blocks). `node/tests/fix_ingress_live.rs::live_tx_flood_does_not_delay_blocks`
(one attacker floods 1,500 frames, an honest peer's block arrives within a
fraction of a second) and its control on a shared channel (the block does not
arrive within 5 s). PoWit items (witness shares, attestations, equivocation
proofs), the transaction topic's other message, take the same channel and
task (`network::goes_to_tx_ingest`); their verification runs off the task on
a bounded, budgeted pool of its own (`ingress::PowitIngress`, docs/CONSENSUS.md
"PoWit gossip"), so neither blocks nor transactions wait behind it
(`fix_ingress_live.rs::live_powit_flood_does_not_delay_blocks`).

## 3. Orphan transactions

A gossiped transaction with missing inputs that passed the context-free checks
is kept in the orphan pool instead of being dropped:

* orphans are keyed by **wtxid** (the hash of the full encoding, script_sigs
  included), as in Bitcoin Core: a copy of a transaction with garbage
  script_sigs has the same txid but cannot occupy the genuine copy's slot —
  both are buffered, the one that fails its signatures on re-try is dropped;
* at most 100 orphans and 10 MiB in total, 25 orphans and 2 MiB per
  delivering connection; an orphan spends at most 100 inputs (no valid
  transaction within 400 KiB has more: every input carries at least an
  ML-DSA-65 key and signature);
* a connection over its quota loses its own oldest orphan; when the global
  bound is reached, the oldest orphan of the connection holding the most is
  evicted; the orphans of a connection that closes are dropped;
* an orphan expires after 20 minutes;
* when a transaction enters the pool, or a block connected to the APPLIED
  (selected) chain confirms it, or a reorg disconnects the block that
  confirmed it (it returns to the pool — unless that block's body was
  pruned, see section 6), the orphans waiting on it are
  re-tried (breadth-first through their own children, at most 25 orphans
  and 400 inputs per event); there is no scan of the whole orphan pool per
  block. A 30 s sweep finds orphans whose parents arrived by another path
  (RPC, the miner, a block accepted outside the gossip path): one lookup
  per recorded missing parent, stopping at the first one still missing, at
  most 1,000 lookups per sweep, round-robin. Orphans confirmed by a block
  connected to the applied chain (in any encoding) or spending an outpoint
  such a block spent are erased. A block stored as a fork-loser or merge
  candidate applies none of its transactions (`CONSENSUS.md`, "Ledger
  semantics: selected-chain-only") and changes nothing here, exactly as for
  the mempool (§6);
* a re-tried orphan's signatures are charged to the connection that
  delivered it.

**Verdicts of orphan frames.** The verdict of an orphan's gossip frame is
withheld, keyed by the frame's wtxid and timed from the frame's arrival at
the network loop (gossipsub keeps an unvalidated frame for 12 heartbeats of
1 s; the window is 10 s). It is settled when the orphan's fate is known:

| outcome | verdict of the withheld frame |
|---|---|
| exactly these bytes entered the pool, within the window | Accept (gossipsub forwards the original frame) |
| the re-try proved these bytes consensus-invalid, penalties in force (§2) | Reject within the window (the delivering connection takes the P4 penalty); after it, an application-score penalty on that connection |
| evicted, expired, erased, another encoding admitted, refused by policy, or proved consensus-invalid while penalties are not in force | Ignore |

Every admitted orphan is also re-announced by the node 35 s later (after
gossipsub's 30 s duplicate window), so one admitted after its frame left the
cache still propagates.

## 4. Chains of unconfirmed transactions

A transaction may spend outputs of pooled transactions. Every entry records
its in-pool parents and children. A transaction is refused when

* its in-pool ancestors, itself included, would exceed 25 transactions or
  500,000 bytes, or
* any of its ancestors would get more than 25 descendants (itself included)
  or a descendant package above 500,000 bytes.

Sizes are bincode sizes, the measure of the consensus block-size rule below
the hardening activation; a whole package always fits half a block. (Block
templates at/after the activation measure in the canonical wire encoding, §5.)

## 5. Block templates: child pays for parent

The template builder (`template::build_block_template`, used by the miner and
`getblocktemplate`) selects **ancestor packages**: it repeatedly takes the
pooled transaction whose package — itself plus every not-yet-selected in-pool
ancestor — has the highest package fee rate (Σ fee / Σ size), and appends the
whole package with parents before children (`mempool::select_packages`). A
package that does not fit the remaining byte budget is skipped. Sizes, package
fee rates and the budget use the block-size measure of the template's height
(bincode below the hardening activation, the canonical wire encoding at/after
it); the budget is `MAX_BLOCK_SIZE` minus the block framing and the coinbase
reserve. Every package member is re-validated at the template's height against
the UTXO set plus the outputs placed earlier in the template (the version and
64-byte rules, coinbase maturity, fees, and the input scripts with the
in-template parents' outputs as the spent outputs); a member that fails is
evicted from the pool together with its descendants and the package is not
included (all or nothing). A member that fails only the version / 64-byte
rules at the template's height but passes them at the pool's next height is
skipped instead (kept pooled; its descendants are not selected either).
Without in-pool chains this is plain highest-fee-rate-first selection.

A template can therefore contain a child whose input exists only as the
output of an earlier listed parent. `getblocktemplate` lists, for every
transaction entry, `depends`: the 1-based positions in `transactions` of its
in-template parents (BIP22 semantics, `BlockTemplate::depends`). A block
built from a subset of the entries is valid only if the subset is closed
under `depends` (transitively) and keeps the listed order; dropping a parent
but keeping its child makes the block invalid ("UTXO … not found"). Below
the hardening activation nothing else fixes the list; at/after it the
coinbase commitment covers exactly the listed transactions in that order.

## 6. Removal, eviction, expiry

* A transaction confirmed by a connected block leaves the pool; its in-pool
  children stay (they now spend a confirmed output).
* In every other case a transaction leaves **with all its in-pool
  descendants**: conflict with a connected block, failed re-validation after a
  reorg, expiry after 72 hours, eviction, replacement, a failed template
  self-check.
* After a reorg the transactions of disconnected blocks are re-admitted
  oldest disconnected block first, in block order (parents first; witness
  standardness and, below the hardening activation, signatures not
  re-checked — from the activation the input scripts are verified again,
  normally a verified-signature cache hit), pooled transactions that spent
  their outputs become their children again, and the whole pool is
  re-validated against the new UTXO set plus the pool.
  At most 20 MB of them are considered (Bitcoin Core's
  `MAX_DISCONNECTED_TX_POOL_BYTES`, `reorg::MAX_DISCONNECTED_TX_POOL_BYTES`,
  measured with `Transaction::actual_size`): the transactions of the OLDEST
  disconnected blocks, in block order. Beyond the budget the most recently
  confirmed ones are dropped, as in Core, so no kept transaction misses a
  parent; dropped ones must be rebroadcast (the node logs the truncation).
  Re-admission follows Core's `MaybeUpdateMempoolForReorg`: the rolling
  minimum fee rate (relay policy) does not apply to a transaction that was
  mined; the pool is not trimmed after each one but once, at the end (Core's
  `LimitMempoolSize`), so it keeps the best-paying packages of the pooled and
  the re-added transactions; and a transaction the final trim would evict at
  once (the pool is full and it pays no more than the cheapest pooled
  package) is not inserted at all. The orphan-transaction bookkeeping reads
  the moved blocks back within the same budget.
  Exception: a disconnected block whose body this node had pruned is rolled
  back from its undo record alone, so its transactions are not available to
  re-admit. They leave the pool's view (and the orphan-transaction
  bookkeeping), pooled transactions spending their outputs are evicted by
  the re-validation, and they come back only if their senders (or peers)
  rebroadcast them; the node logs how many such blocks a reorg rolled back.
  Only a pruned node reorganizing deeper than its pruning depth is
  affected.
* Whenever the next block's height moves, transactions whose version or
  size (64-byte rule) the next block could not contain are evicted with
  their descendants.
* The pool holds at most 50,000 transactions and 300 MiB. When full, the
  entry with the lowest **descendant score** — max(own fee rate, fee rate of
  itself plus all its descendants) — is evicted with its descendants, and the
  **rolling minimum fee rate** rises to that rate plus the incremental relay
  fee rate (1 sat/byte); it halves every 12 hours. If the package to evict
  contains the incoming transaction, the incoming transaction is refused
  instead.

## 7. Replacement: full-RBF

GnB uses full replace-by-fee without opt-in signalling (as Bitcoin Core since
v28). A transaction that spends an outpoint already spent by pooled
transactions (its *direct conflicts*) replaces them, together with all their
descendants (the *evicted set*), if and only if:

* **rule 2** — every input it spends from a pooled transaction spends an
  output of a transaction that one of the direct conflicts already spent from
  (no new unconfirmed inputs);
* **rule 3** — its absolute fee is at least the sum of the fees of the whole
  evicted set;
* **rule 4** — its fee minus that sum is at least the incremental relay fee
  (1 sat/byte) times its own size;
* **rule 5** — the evicted set has at most 100 transactions;
* **rule 6** — its fee rate is higher than the fee rate of each direct
  conflict;
* it does not spend an output of any transaction in the evicted set;
* it passes every other admission check (§1), including the chain limits
  computed without the evicted set.

Rules 2–6 are checked before the signatures (step 10) and again atomically when
the pool is modified. The replacement is relayed like any new transaction; the
evicted transactions are dropped. Why not first-seen: with block producers free
to mine any valid transaction, first-seen only protects the first broadcaster
on nodes that enforce it, while a fee-bumping rule lets a sender fix a stuck
transaction and lets miners and relays converge on the most valuable version;
rules 3–5 make each replacement pay for the bandwidth it consumes and bound
the work one replacement can cause.

The raw `Mempool::add` used by tools and tests stays first-seen; replacement
is an admission decision (`Mempool::add_with_replacement`).

## 8. RPC

* `sendrawtransaction` runs the same admission, replacement included; an
  error names the failed rule.
* `getmempoolinfo` returns `size`, `bytes`, the current rolling minimum fee
  rate and this policy's parameters under `policy`.
* `estimatefee` returns a fee rate never below the consensus minimum nor the
  rolling minimum.
* `estimatefeeadvanced [n_inputs=1, n_outputs=2]` (re-audit B1-T21) returns
  ABSOLUTE fees for a transaction of that shape (`tx_bytes`,
  `Transaction::estimate_size`): `slow_priority` at the floor rate (the
  consensus minimum rate or the rolling minimum, whichever is higher),
  `medium_priority` (also `mempool_median` and `recommended_gnb`) at the
  median pooled fee rate, `next_block_sats` at the 75th-percentile pooled
  rate, none of them below `min_tx_fee_sat(tx_bytes)`; the rates are reported
  under `feerate_sat_per_kb`. It used to return raw absolute-fee percentiles
  that ignored the size, and 5,000 / 1,000 sat on a quiet pool, below the
  10,000-sat consensus minimum. The wallet client floors whatever a node
  answers at the consensus minimum.
