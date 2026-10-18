# ObenBlock consensus

This document specifies the rules the code implements today, which are still
GnB's: the GnB-SMH proof of work, the `gnb` chain ids and the GnB genesis.
The ObenBlock relaunch replaces those parts as specified in
[DESIGN-obenblock.md](DESIGN-obenblock.md); that is not implemented yet.

## Block header and proof of work

```text
BlockHeader { version u32, parents [hash32], merkle_root hash32, timestamp u64, bits u32, nonce u64 }

pow_preimage = version u32le | n_parents u32le | parents | merkle_root | timestamp u64le | bits u32le
pow          = GnB-SMH(height)(header = pow_preimage, nonce)     // 32 bytes; v1, v3 from the PoWit height
valid       <=> be256(pow) < target(bits)
block_hash   = SHA3-256("GNB-BLOCK-ID-v1" | pow_preimage | nonce u64le)
```

GnB-SMH v1 is specified in `crates/gnb-smh/README.md`; the Python file in
`crates/gnb-smh/reference/` is normative and the Rust crate reproduces its
vectors byte for byte. One evaluation costs 64 MiB and about 0.5 s on one core
of a current x86-64 or Apple CPU (`smh-bench verify 19`). Verified block ids are
cached, so a block's proof is evaluated once per node. From the PoWit height
(`core::pow_algo(height)`; mainnet 10,000, testnet off unless
`--powit-height`) the function is GnB-SMH v3 (`crates/gnb-smh/src/v3.rs`, a
4 MiB Argon2d-style fill), and the expected bits are the ASERT bits with the
target lowered by `POW_V3_DIFFICULTY_SHIFT` (2) and re-encoded with
`target_to_bits` (`core::adjust_bits_for_algo`); see "Chain work" for the
matching work normalisation and docs/DESIGN-pow-powit.md.

`bits` is the Bitcoin compact encoding. Malformed encodings never validate.
The easiest allowed target is `POW_LIMIT_BITS = 0x2100ffff` below the
hardening activation and the genesis target `0x1f0e9036` at and after it
(see "Block rules at the hardening activation", POW-3).

Non-canonical encodings never validate either (audit POW-9, every height):
`bits` must be the encoding `target_to_bits` produces for the target it
decodes to, `target_to_bits(target(bits)) == bits`
(`gnb_smh::difficulty::is_canonical_bits`; `reference/gnb_difficulty.py`
`is_canonical_bits`). Decoding itself keeps Bitcoin Core's `SetCompact`
semantics (`try_bits_to_target` decodes `0x21007fff` and `0x207fff00` to the
same target), and `Block::validate_pow` refuses the non-canonical one before
any evaluation. The rule changes no verdict: every block must also carry
`bits == expected_bits(parents, height)`, checked before the proof, and
`expected_bits` is a `target_to_bits` output, which is always canonical,
on both sides of the v3 switch (`expected_bits_are_always_canonical`). A
witness share's `bits` must equal its attested block's
(`witness_share::verify_share`), so they are canonical too. Like Bitcoin Core, whose consensus
compares `nBits` with the expected value as a u32, GnB never relied on
decoding to reject a non-canonical header; the explicit check only makes
that independent of the equality check. Vector:
`block_vectors.json` `pow/non-canonical-bits`.

## Difficulty

ASERT (aserti3-2d construction) anchored at the genesis block
(`genesis_time = 1791429092`, `genesis_target = target(0x1f0e9036)`, spacing
30 s, half-life 7200 s, `pow_limit = target(pow_limit_bits_at(height))`:
`target(0x2100ffff)` below the hardening activation, `genesis_target` at and
after it). The normative
executable definition is `reference/gnb_difficulty.py`; its vectors
(`reference/difficulty_vectors.json`) are checked by `reference/check_vectors.py`,
`crates/gnb-smh/tests/difficulty_vectors.rs` and
`crates/gnb-crypto/tests/difficulty_vectors.rs`.

### Difficulty input

For a block `B` with parent set `P` (each parent's `height` and `timestamp` as
stored in the DAG):

```text
parent_time = max(p.timestamp for p in P)       // the LATEST parent timestamp
height      = max(p.height for p in P) + 1      // must equal B.height
bits(B)     = expected_bits(parent_time, height)
```

Both inputs are taken over ALL parents. Neither is the GhostDAG selected
parent's: the selected parent is the parent with the highest blue work, which
need not be the parent with the latest timestamp or the greatest height. The
rule is order-independent and deterministic, but it differs from the DAG's
own notion of height: GhostDAG stores `height = selected_parent.height + 1`
for every block, and the difficulty height above is computed from those
stored parent heights. So block validity (the `height` and `bits` checks)
depends on the parents' GhostDAG-derived heights, and a block that merges a
deep side branch is scheduled from its highest parent.

### ASERT step

```text
ahead    = parent_time - genesis_time - 30 * (height - 1)
exponent = floor(ahead * 65536 / 7200)        // 16.16 fixed point, rounds toward -infinity
shifts   = floor(exponent / 65536);   frac = exponent mod 65536
factor   = 65536 + ((195766423245049*frac + 971821376*frac^2 + 5127*frac^3 + 2^47) >> 48)
target   = floor(genesis_target * factor * 2^(shifts - 16)), clamped to [1, pow_limit_at(height)]
bits     = compact(target)                     // keeps the top 3 bytes: rounds down
```

The product `genesis_target * factor` is exact and the net shift is applied
once, as in aserti3-2d. The exponent rounds toward negative infinity, which
differs from BCHN's aserti3-2d (C++ `/` truncates toward zero) by one unit of
2^-16 half-life when `ahead` is negative and `ahead * 65536` is not a
multiple of 7200. The intermediates are i128 and the timestamp an i64; a
parent timestamp above i64::MAX makes `expected_bits` fail, so no block can
carry it.

`expected_bits` is a pure function of the block's parents, so every node
computes the same value regardless of arrival order. It is enforced for every
block, before the proof of work is evaluated.

### Chain work

Each block contributes

```text
work(target) = max(floor((2^128 - 1) / (floor(target / 2^128) + 1)), 1),   work(0) = 0
```

to blue work (`gnb_smh::difficulty::work`, u128); a GnB-SMH v3 block (from
the PoWit height, mainnet 10,000) contributes `work(target) >>
POW_V3_DIFFICULTY_SHIFT` (2), the factor its target is lowered by, so
cumulative work is continuous across the switch (`core::block_work(bits,
height)`, the one function every place that adds a block's work calls). This approximates
2^256 / target: it never exceeds floor(2^256 / target) or Bitcoin Core's
floor(2^256 / (target + 1)), is monotone in the target, saturates at
2^128 - 1 for targets below 2^128, and is within one part in 2^64 of the
exact value for every target at or above 2^192. Implementations must use this
formula, not floor(2^256 / target), or they compute different blue work.

Block timestamps must be at least the latest parent timestamp and at most
600 s ahead of the validator's clock, which bounds the easing a miner can
obtain from a future timestamp to about 6%.

## Networks (mainnet and testnet)

Mainnet and testnet share the genesis block (`core::genesis_block()`, the
same id `a63fd2c1…`), so they also share the ASERT anchor (the genesis time
and target) and the genesis ledger (the carryover and the locked team and
founder allocations). They differ in the chain id (`ChainId`: mainnet
`0x474E0001`, testnet `0x474E0002`, set with `--testnet`), in the hardening
activation height derived from it (mainnet 17,500, testnet 0) and in the
PoWit height (GnB-SMH v3 and PoWit: mainnet 10,000; testnet off unless
`--powit-height`). Consequences, and what separates them (audit POW-9):

- **Transactions cannot be replayed across networks.** Every signature digest
  commits to the chain id: sighash v2 and v3 both hash `chain_id u32 LE`
  right after the version byte ("Transaction signatures"), so a mainnet
  signature never verifies on testnet and vice versa, below and after the
  activation (`core::chain_id_tests::cross_chain_id_replay_is_rejected`;
  vectors `net/*` in `tx_vectors.json`). A transaction is replayable only
  where its digest is, i.e. on its own network. Policy (multisig, timelock)
  spends sign the same digests. PoWit's own signatures are bound too: a
  witness attestation signs `attestation_message(chain_id, source, target)`
  (from the second hardening activation, by target height,
  `attestation_message_v2(chain_id, key, source, target)`, which also commits
  the witness key; "PoWit"), so it never verifies on the other network even
  for the same checkpoints, and a witness share commits to a block id of its
  network.
- **Blocks cannot be valid on both networks**, but only because their rules
  differ, not because a block names its network. A block above the genesis
  at header height h < 17,500 follows the pre-activation rules on mainnet
  (legacy Merkle root, free-form coinbase) and the hardening rules on
  testnet (tagged Merkle root, 80-byte coinbase commitment), which exclude
  each other. From 17,500 the rules agree, but every block there descends
  from blocks of one network only, which the other never accepts, so its
  parents are unknown to the other network.
- **The networks are separated on the wire** (node-local), as Bitcoin Core
  separates them with per-network message start bytes: each network has its
  own gossip topics, directed-sync protocol and identify protocol version
  (`network::chain_separation`; mainnet keeps `gnb/blocks/1`,
  `gnb/txs/1`, `gnb/sync/1`, `/gnb/sync/1` and `/gnb/1.0.0`, testnet uses
  `gnb-testnet/...`; PoWit items travel on the transaction topic), so
  neither network subscribes to, pulls from or serves the other's frames,
  and a peer that identifies with another network's
  protocol version is disconnected (`node/tests/fix_pow9_network_separation.rs`).
  A dialed address enters the tried table (`known_peers`) only after a
  same-network identify, as Core marks an address good only after the
  version handshake; another network's address is removed from it.
- **A data directory belongs to one network**: the genesis check at start-up
  cannot tell the networks apart, so the data dir records its chain id in
  CF_META (`chain_id`, written on its first start) and a node of the other
  network refuses it (`Storage::check_chain_marker`; docs/RUNNING.md). A
  data dir without the marker (from an earlier release) that holds chain
  blocks is marked only for the network its blocks follow: the first stored
  body among the highest chain-index rows at header height 1..17,499
  carries the hardened coinbase commitment and passes the hardened body
  rules (`block_rules::check_hardened_body`) on testnet and fails them on
  mainnet (`Storage::stored_chain_network`); a node of the other network is
  refused. The Merkle root is not used: from a network's PoWit height the
  body root is the v2 commitment, and which heights that covers depends on
  the running node's PoWit height, not on the stored chain's.

## Genesis ledger

The genesis ledger is the set of outputs that exist from the genesis without
a transaction creating them, written into the UTXO set before block 0
(`Storage::ingest_carryover`, one atomic batch): the converted Bloch
Genesis-3 carryover (`core::carryover`: 20-byte key-hash outputs only, the
snapshot format admits no other script, at their Bloch outpoints) and the 72
locked team and founder vesting tranches (`core::vesting`: 33-byte policy
outputs, each with an absolute timelock `after` = its unlock height and no
relative timelock, `older = 0`, at synthetic outpoints `txid = SHA3-256(
"GNB-VESTING-v1" ‖ role ‖ k ‖ policy hash)`, `vout = 0`). Both sets are
consensus constants (`CARRYOVER_SNAPSHOT_SHA3`, `VESTING_SPEC_SHA3`).

**Confirmation point (audit F1).** A genesis-ledger output is confirmed at
the genesis: header height 0, DAG height 0, chain position 0. A rule that
counts its confirmations at a block B (a relative timelock: "Coinbase
maturity", **Timelocks**) counts `B.height` below the activation and
`dag_height(B)` from it. No transaction created these outputs, so they have
no transaction-index row; the node records their txids instead
(`genesis_ledger/<txid>` rows in CF_META, written with the ledger and, for a
data dir ingested by an earlier release, at start-up by
`Storage::migrate_genesis_ledger_index`: the vesting tranches from the
embedded specification, the carryover from the key-hash outputs, unspent or
spent by an applied block, that have no transaction-index row), and the one
confirmation lookup of the connect, reorg, mempool and template paths
(`accept::confirmations_in_view`, through `UtxoView::view_genesis_ledger`)
answers the genesis for them. Before, an output found in the UTXO set without
a transaction-index row was "confirmation unknown", a read failure (no
verdict, "Coinbase commitment"), and a made-up policy could ask for it (see
**Timelocks**).

This changes no verdict of any block on this chain: the only genesis-ledger
outputs a confirmation-reading rule can reach are policy outputs (maturity
reads coinbases only, relative timelocks policy outputs only), i.e. the
vesting tranches, whose policies all have `older = 0`, and a spend that
reveals another policy fails the policy hash before any timelock is read.

## Acceptance order

`accept_block` runs the cheap checks first and the proof of work last:

1. not already known (a block in the DAG that waits for a body — after a
   witness-dependent failure below the activation, see "Coinbase commitment",
   or because its body is missing, e.g. pruned and needed again, see "Selected
   parent and fork choice" — is not "known": a copy replaces the body after
   the same checks); parents present in the DAG;
2. height = max parent height + 1;
3. `bits == expected_bits(parents, height)`;
4. timestamp bounds;
5. at/after the hardening activation: the context-free block rules (wire
   size, tagged Merkle root, each parent listed once, no 64-byte
   transaction, coinbase commitment), and at every height the block-size
   limit of the block's verified height in the measure of the regime (see
   "Block size (VAL-12)"), before the block is stored;
6. GnB-SMH proof (64 MiB, cached by block id). A body that replaces the
   body of a block already in the DAG (same id, so the same proof preimage
   and nonce, and the height just bound to the same parents) carries the
   proof the DAG record already verified at that height: only the cheap
   parts run again (canonical bits, target within the pow limit of the
   height; `pow::proof_recorded_in_dag`, P5-G), never the GnB-SMH
   evaluation. Same verdict, also after a restart, when the process no
   longer holds the proof in its cache;
7. transactions (version rule, witnesses and signatures as specified in
   "Transaction signatures" below, double spends, coinbase maturity and
   relative timelocks in the depth measure of the block's regime ("Coinbase
   maturity"), this chain's locktime, output-kind, dust and policy-spend
   rules (`node/src/blockval.rs`), consensus minimum fee, BIP30 and no
   same-block coinbase spend, this chain's rules at every height),
   coinbase value (the miner output and, from `powit_height()`, one
   witness-share output per PoWit share). Step 7 runs when the block is
   connected; for a block the node's assumed-valid block vouches for, it
   leaves out the signature verification only (node-local, see "Assumed-valid
   block" below).

Structural checks (size, merkle root, coinbase shape, duplicates, dust, and
at/after the activation distinct parents, the 64-byte rule and the coinbase
commitment) also run before `accept_block` on every ingress path, on the
height the block claims, so no proof of work is spent on a block that fails
them.

The `blue_score` a block carries on the wire is not committed by its id and
no rule reads it. `accept_block` stores the body with the value derived from
its parents (`max(parent blue_score) + 1`), whichever path delivered it
(gossip, directed sync, orphan drain, body re-fetch, `submitblock`, the
miner), so every node stores, serves and relays the same bytes for one block
id (POW-8; re-audit B1-T0).

## Value ranges (MoneyRange, all heights)

`MAX_SUPPLY_SAT = 12,500,000 GNB = 1.25 x 10^15` base units. A block is
invalid if any of these values leaves `0..=MAX_SUPPLY_SAT` (a sum that
overflows u64 is out of range too):

- every output value of every transaction, the coinbase included (its
  witness-share outputs from `powit_height()` too) (context-free:
  `limits::check_block_context_free`, before the block is stored; also
  mempool admission and the template self-check);
- each transaction's output total (context-free, same check);
- each shielded transaction's fee (context-free);
- each non-coinbase transaction's input total (connect time);
- the block's accumulated fees, the sum over its non-coinbase transactions
  of inputs minus outputs (connect time).

These are Bitcoin Core's bounds (`nValueOut` in CheckTransaction, `nValueIn`
and the fee in CheckTxInputs, `bad-txns-accumulated-fee-outofrange` in
ConnectBlock). Each is a sum of distinct coins (a transaction's inputs are
distinct outpoints, its outputs at most its inputs, fees are conserved along
in-block chains), so a block whose amounts are conserved never violates
them. The coinbase's own total is bounded by the coinbase value rule
(subsidy plus fees: the miner output at most its share plus the fees, each
witness-share output exactly `per_attester`, `Block::validate_coinbase_value`).
The sum of ALL outputs of a block is not bounded: a chain of in-block
spends moves the same coins once per hop, so the outputs of a valid block
can sum above the supply (three hops of 4,500,000 GNB: 13,500,000 GNB).
The VAL-11 remediation (commit e3e45df, merged into this chain's line by
28a619d) had also bounded that sum; the rule rejected such valid blocks at
every height and made the template self-check refuse every template
carrying such a mempool chain, so it is removed (re-audit B1-T1): only a
node running 28a619d .. cb60040 rejects such a block, every release of this
chain before them accepts it. Vectors: `value/*`, among them
`value/chained-spends-output-total-above-max-supply/*` (valid in both
regimes) and `value/block-output-total-above-max-supply/*` (valid; the
vectors of cb60040 pinned the removed rule there).

Node-local (not consensus; NET-2 residual, Phase 4): on the message
processor, the GnB-SMH proof of a gossiped or pulled block is evaluated only
after every check above that precedes it, and not on the processor itself.
The ingress core (`ingress::BlockIngress::handle_block_gated`) runs the
cheap checks — for a block whose parents are known the anti-DoS work rule
and steps 2–5 (`ingress::passes_pre_pow_checks`; a block that fails one goes
to `accept_block`, which refuses it before evaluating anything), for an
orphan the floor — and then hands the block to a bounded proof-of-work
scheduler (`pow::verifier`): at most half the logical CPUs (1 to 4)
evaluations at a time on the blocking thread pool, a queue bounded
globally, per delivering peer and per network group, and a budget of
failed evaluations per peer and per network group (a valid proof is
refunded). The evaluation is `Block::validate_pow`, whose algorithm follows
the header height: GnB-SMH v1 (64 MiB) below the PoW + PoWit activation
(`core::powit_height()`), v3 (4 MiB) from it — results are keyed by block id
and height for that reason. The processor resumes the block when its result
arrives (the proof is then in `validate_pow`'s cache, so `accept_block` does
not evaluate it again). A gossip frame whose block waited in the queue longer
than gossipsub keeps it is answered `Ignore` unevaluated; every queued
frame gets exactly one verdict. See "Anti-DoS work rule" below for the
budgets and for who is charged.

## Wire encoding (all heights)

Blocks are relayed (gossip `NewBlock`, `/gnb/sync/1` block responses,
`submitblock`) and stored in the encoding of `Block::to_wire_bytes`; a
transaction alone (gossip, `sendrawtransaction`) in that of
`Transaction::to_wire_bytes(true)`:

```text
block      = header ‖ varint(n_tx) ‖ tx* ‖ varint(n_shielded) ‖ shielded_tx*
header     = version u32le ‖ varint(n_parents) ‖ parent* (32 bytes) ‖ merkle_root
             ‖ timestamp u64le ‖ bits u32le ‖ nonce u64le ‖ blue_score u64le ‖ height u64le
tx         = version u32le ‖ varint(n_in) ‖ input* ‖ varint(n_out) ‖ output* ‖ locktime u32le
input      = prev_txid (32 bytes) ‖ prev_index u32le ‖ varint(len) ‖ script_sig ‖ sequence u32le
output     = value u64le ‖ varint(len) ‖ script_pubkey
varint(v)  = v (one byte)            if v < 0xFD
           = 0xFD ‖ u16le(v)         if 0xFD <= v <= 0xFFFF
           = 0xFE ‖ u32le(v)         if 0x10000 <= v <= 0xFFFFFFFF
           = 0xFF ‖ u64le(v)         otherwise
```

(`shielded_tx` uses the same varint for its counts and lengths; no shielded
transaction is valid today.) The decoders (`Block::from_wire_bytes`,
`BlockHeader::from_wire_bytes`, `Transaction::from_wire_bytes`) accept exactly
this encoding, as Bitcoin Core's `ReadCompactSize` does:

1. a varint in a longer form than its value needs is refused (`FD 05 00` for
   5, an `FE` form below 0x10000, an `FF` form below 2^32;
   `non-canonical varint`);
2. each transaction of a block starts where the previous one ended, at the
   bytes its decoder consumed (`Transaction::read_wire_bytes`);
3. no byte may follow the block, and the gossip / RPC transaction decoder
   (`admission::decode_tx_strict`) refuses bytes after a transaction.

So a byte string that decodes is exactly `to_wire_bytes` of what it decodes
to: every block and transaction has one encoding. This is a decoding rule,
not a validity rule, and it applies at every height (no activation). It does
not change which blocks are valid. The block id commits to `pow_preimage`
(fixed-width fields, the parent count as u32le) and the nonce, and txids,
wtxids, the Merkle roots, the coinbase commitment and the block size are all
computed from the canonical encodings of the decoded transactions, so the
id and validity of a block never depended on how its varints were written.
Every block has its minimal encoding, which the decoders read as before (with
minimal varints the bytes a transaction consumes are its canonical length).
Every encoder in the code base (`write_varint`, used by the node, its miner
and templates, the wallets and the WASM wallet core) writes only minimal
varints (`core::wire_canonical_tests::varint_minimality_boundaries`), and the
node stores blocks as `to_wire_bytes()` (with the `blue_score` derived from
the parents, see "Acceptance order") and serves those bytes to sync
requests and gossip. An external miner that assembles a block from
`getblocktemplate` must write the transaction count and the coinbase's
varints minimally, as Bitcoin's CompactSize writers do: `submitblock` refuses
other bytes (`deserialise failed: ... non-canonical varint`).

What changed (H-fuzz, found by the fuzz target `wire_roundtrip`) is which
byte strings are accepted for an already valid block id. A widened varint
used to be accepted, so one block had many encodings. A widened varint
inside a transaction also made the block decoder frame the next transaction,
or the shielded count, at the re-encoded length, which is fewer bytes than
the decoder consumed, so the body decoded from inside the previous
transaction. Such bytes are now refused before the block id is computed:
nothing is recorded about the id (no invalid mark, no orphan entry), the copy
is dropped, and the block is accepted from its canonical encoding, for
example from another relay or when a descendant's missing parent is fetched
by directed sync. Vectors: `decode/non-minimal-tx-count/post` and
`decode/non-minimal-script-sig-length/pre` (blocks; the decoder before the
rule accepts both byte strings, the second only through its framing at the
re-encoded length), `decode/non-minimal-varint` (transactions);
`core::wire_canonical_tests`; `node/tests/fuzz_regressions.rs`.

Mixed versions. A release without this rule (origin/main before H-fuzz)
accepts a widened encoding of a valid block, answers `Accept`, and gossipsub
forwards the bytes it received. Anyone can widen a varint of a fresh block
and hand that copy to such nodes first, so an honest older node can deliver
widened bytes to an upgraded one. The upgraded node therefore answers a
`NewBlock` whose `block_data` fails with the minimal-varint error
(`core::is_non_minimal_varint_error`) with `Ignore`: not relayed, no gossipsub
invalid-delivery (P4) penalty, nothing recorded
(`ingress::verdict_for_block_decode_error`). Every other malformed body is
still `Reject` (P4 penalty on the delivering peer). With `Reject`, three such
frames from one older peer within a couple of minutes (block topic: weight
0.5, -100 per invalid delivery squared, decay 0.5 per minute) would pass the
graylist threshold (-400) and the upgraded node would ignore all of that
peer's gossip. The classification covers every older relay: the two
decoders read the same fields with the same checks and differ only in the
varint rule and in where the next transaction starts after a widened varint,
so every byte string the older decoder accepts and this one refuses fails on
a non-minimal varint
(`core::wire_canonical_tests::pre_fix_acceptances_fail_on_a_non_minimal_varint`,
`node/tests/fix_net_ingress.rs::widened_block_varints_are_ignored_and_other_malformed_bodies_rejected`).
A party sending such bytes directly is not penalized either; it costs the
receiver one decode. The same holds for the gossip envelope: a non-canonical
bincode frame (`WireDecodeError::NonCanonical`) of a `NewBlock` or
`NewTransaction`, the messages that nodes relay after validating them, is
dropped without penalty (an older release relays it), while a non-canonical
frame of any other message, which no honest node relays, is a penalized
protocol violation (`network::tests::non_canonical_relayable_frames_are_dropped_without_penalty`).
The transaction bytes inside a `NewTransaction` need no such rule: the older
gossip decoder (`admission::decode_tx_strict`) already refused a transaction
that is not its canonical length, so older nodes never relay a widened
transaction. Once no
release without the rule can be a peer, `Reject` can be restored for both
classes; that needs a peer protocol version that older releases cannot
advertise (they follow the hardening activation block, so the activation
height cannot serve as the cut-off).

## GhostDAG

k = 10. Blocks below the hardening activation height use the interval-index
("Fast") coloring, which is applied from genesis but does not count the whole
selected chain in a candidate's anticone. From the activation height (mainnet
17,500; testnet and regtest 0) the exact GHOSTDAG coloring, Kaspa blue work
and the mergeset limits below apply.

## GhostDAG rules, ledger semantics and the hardening activation

The 2026-10-14 audit found that fork choice ignored merged blue work (DAG-3),
that the live coloring broke the k-cluster rule (DAG-4), and that per-block
cost was unbounded (DAG-7). The fixes change consensus results, so they take
effect at a scheduled height. Blocks below that height keep the old rules
exactly, and their stored `GhostdagData` stays valid.

### Activation

| Network | Hardening activation height |
| --- | --- |
| mainnet | 17,500 (`MAINNET_HARDENING_ACTIVATION_HEIGHT`; about 2026-10-17 04:17 UTC) |
| testnet | 0 (from genesis) |
| regtest | 0 (from genesis) |

The mainnet height was moved on 2026-10-16 from 110,000 (about 30 days after
the release) to about one day after that decision. No mainnet node was
reachable, so it was derived from the ASERT schedule, not from an observed
tip. Genesis timestamp 1,791,685,648 (2026-10-11 02:27:28 UTC, the relaunched
chain), 30 s target spacing: at the decision, 2026-10-16 03:47 UTC, the
schedule height is about 14,560; one day is 2,880 blocks, about 17,440,
rounded to 17,500, whose scheduled time is 1,791,685,648 + 17,500 × 30 =
1,792,210,648 (2026-10-17 04:17:28 UTC). An earlier move to 25,800 was
derived from the pre-relaunch genesis (2026-10-08 03:11:32 UTC); on this
chain 25,800 is scheduled for 2026-10-20 01:27 UTC.

The ASERT schedule bounds the real height only loosely. ASERT is anchored at
the genesis block (`GENESIS_TIMESTAMP`, `GENESIS_BITS`) with 30 s spacing and
a 2 h half-life, so the schedule height at time `t` is `(t - genesis time) /
30 s`, and at a steady network hashrate `H` the chain runs `240 × log2(H /
H0)` blocks ahead of the schedule (behind it when negative), where `H0` is the
hashrate at which the scheduled target gives 30 s blocks. Below the PoWit
height (GnB-SMH v1) that target is the genesis target, about 4,500
evaluations per block: `H0` ≈ 150 v1 evaluations/s. From the PoWit height
(mainnet 10,000) blocks use GnB-SMH v3 and `core::adjust_bits_for_algo`
shifts the ASERT target right by `POW_V3_DIFFICULTY_SHIFT` = 2 bits (4 times
harder; `DESIGN-pow-powit.md`), about 18,000 v3 evaluations per block on the
schedule: `H0` ≈ 600 v3 evaluations/s. The shift is applied after ASERT, so
the anchor and the schedule height are unchanged; only `H0` moves (a v3
evaluation costs about a sixth of a v1 one, so the same hardware tracks the
schedule at about two thirds of the v1 `H0`). Each doubling of `H` above `H0`
brings the activation 240 blocks (2 h) before its scheduled time: at 16 ×
`H0` 17,500 arrives about 8 h before 2026-10-17 04:17 UTC, at 128 × `H0`
about 14 h before, and the chain would already have been past it at the
decision only above about 4,900 × `H0`. The two tips recorded in this
repository were behind the schedule: 2,888 on 2026-10-12 10:06 UTC (909
blocks, `WITNESS_COMMITMENT_HEIGHT`) and 8,302 on 2026-10-14 04:25 UTC (574
blocks, `MAINNET-READINESS.md`), about 0.07 and 0.19 × the v1 `H0`. If the
network is still below `H0`, the activation comes after its scheduled time
(2 h later per halving of `H / H0`), and from the activation the hardened
pow limit (the genesis target, "Pow limit (POW-3)", which clamps the ASERT
target before the v3 shift, so a v3 block needs at least about 18,000
evaluations) stretches block times to about 30 s × `H0 / H` until the
hashrate rises.
Before the release, the mainnet tip (`getdaginfo` `tip_height`,
`next_block_height`) and the current `bits` must be read from a node: the tip
must be well below the activation height, else the height must be moved
again before the chain reaches it; the observed block rate gives the real
time of the activation; template `bits` easier than `0x1f03a40d` (the
genesis target shifted for v3; `0x1f0e9036` below the PoWit height) mean the
post-activation slowdown above (`RUNNING.md`, "Hardening activation"). The
rules switch at the height, whatever the time.

Every node and miner must run a release with this height before the chain
reaches it (`RUNNING.md`, "Hardening activation"); a node with the old height
(or none) keeps the old rules there and splits from the upgraded nodes.
Moving the height again is one constant
(`crates/gnb-crypto/src/core/activation.rs`), its copies in the generator of
the consensus vectors (`MAINNET_ACT`) and the three Python references
(`gnb_validity.py`, `gnb_merkle.py`, `gnb_difficulty.py`), the regenerated
`reference/{tx,block,merkle,difficulty}_vectors.json`, a rebuilt and re-pinned
web-wallet core (`site/wallet/gnb_wallet.wasm` compiles the height in;
`scripts/build-wallet-wasm.sh`) and a new node package version.

Every consensus change of the 2026-10-14 audit activates at this ONE height.
The schedule is defined in `crates/gnb-crypto/src/core/activation.rs`, and the
node derives it from its chain id (`--testnet`). A process with no chain id
set, such as a unit or integration test, follows the mainnet schedule. Tests
choose a regime explicitly with `GhostDAG::with_k_and_activation(k, h)` or
`activation::scoped_override(h)`. The Phase-5 audit's rule changes use the
second hardening height of the same module ("Second hardening activation"
below). The rules, and the height each one compares with the
activation height:

| Rules | Findings | Height compared | Specified in |
| --- | --- | --- | --- |
| Kaspa blue work in fork choice, exact GHOSTDAG coloring, `MAX_MERGESET_SIZE`, `MERGE_DEPTH` | DAG-3, DAG-4, DAG-7 | `GhostdagData::height` | this section |
| Transaction version 3 only, sighash v3, component-bound signatures, canonical witnesses | CRY-1, CRY-2, CRY-3, MEM-5 (residual), WAL-1 | header height `B.height` of the containing block | "Transaction signatures" |
| Tagged Merkle root and the 64-byte transaction rule | VAL-10 | `B.height` | "Block rules at the hardening activation" |
| Coinbase commitment: header height (BIP34), parent list, witness root | VAL-2, CRY-1 | `B.height` | same |
| No overwrite of an unspent coin (BIP30) | VAL-2 | `B.height` | same |
| No spend of the same block's coinbase | VAL-3 | `B.height` | same |
| Coinbase maturity and relative timelocks (`older`) count selected-chain blocks (DAG heights) instead of header heights | re-audit B1-T14 | `B.height` (the regime); the depth itself compares `GhostdagData::height` | "Coinbase maturity" |
| `MAX_BLOCK_SIZE` measured on the wire encoding | VAL-12 | `B.height` | same |
| Each parent listed once | B2-T10 (DAG-12) | `B.height` | same, "Parent list" |
| Pow limit = genesis target | POW-3 | `B.height` (the height `expected_bits` is computed for) | same |

A GhostDAG rule applies to block B iff `height(B) >= activation`, where
`height(B)` is `GhostdagData::height`, the selected parent's height + 1, which
depends only on B's parents. The block and transaction rules compare
`B.height`, the header height that `accept_block` requires to equal
`max(parent DAG heights) + 1`; these rules are checked before a block reaches
GhostDAG, as the activation module prescribes. The two heights differ only for
a block that merges a parent with a greater DAG height than its selected
parent (DAG-8). The predicates:

```text
block rule applies at h        iff  h >= 1 and h >= activation   // block_rules::rules_active_at
transaction rule applies at h  iff  h >= activation              // activation::is_active_at (core::sighash::check_tx_version)
```

The block-rule predicate excludes the genesis (height 0), a constant checked
by its hash and proof. The transaction-rule predicate is the one the "Version
rule" table and `reference/sighash_vectors.json` (`version_rule`) pin. The two
agree at every height `h >= 1`, which is every height a validated block or a
next block can have (`template::next_template_height` is never below 1); they
differ only at `h = 0` with activation 0, a height no block other than the
genesis has. `admission::check_tx_for_next_block`, which applies the version
rule and the 64-byte rule at a next-block height, gates both with the
transaction-rule predicate, so the two switch together even for a caller that
passes `h = 0`. Everything that decides for a block not yet built (mempool
admission and eviction, reorg re-injection, templates, `getblocktemplate`,
wallets) evaluates the block and transaction rules at ONE next-block height,
the header height of the node's own next template (see "Transaction
signatures", "Which height").

Below the activation, every GhostDAG rule in this section is replaced by the
pre-activation rule named with it (the block and transaction rules state their
own pre-activation behaviour in their sections). That pre-activation behaviour is proven
bit-identical to the code that produced the existing chain by
`node/tests/fix_ghostdag_preactivation_identity.rs`.

The block-wide output total that the VAL-11 remediation (e3e45df, merged
here by 28a619d) introduced at every height is removed, which restores the
verdict every earlier release of this chain gives ("Value ranges",
re-audit B1-T1). The pre-activation block-size measure is this chain's own,
the wire encoding (`Block::size_bytes`, the PoWit section included from
`powit_height()`), unchanged: it does not read the uncommitted
`blue_score`, which the audit's bincode measure did (re-audit B1-T0 /
B2-T8, "Block size (VAL-12)").

### Second hardening activation (hardening 2)

The first hardening height (17,500 on mainnet) cannot move again, so the
consensus fixes of the Phase-5 audit (2026-10-16) take effect at a second
scheduled height, with the same API in `crates/gnb-crypto/src/core/activation.rs`
suffixed `2` / `_v2` (`hardening2_activation_height`, `hardening2_active_at`,
`hardening2_activation_height_for_chain`, `_for_signer`, `scoped_override_v2`):

| Network | Second hardening activation height |
| --- | --- |
| mainnet | not scheduled (`MAINNET_HARDENING2_ACTIVATION_HEIGHT = NEVER`; the owner sets it at release, derived like the first) |
| testnet | 0 (from genesis) |
| regtest | 0 (from genesis) |

It is never below the first hardening height on any network. Below it every
rule is the one that produced the existing chain, bit for bit. The rules:

| Rules | Findings | Height compared | Specified in |
| --- | --- | --- | --- |
| PoWit attestation message v2: the signed digest commits the witness's KES key (depth, root) | PoWit audit 1 | the attestation's **target** height (every message checked in a block below the activation is v1) | "PoWit", "Attestation messages" |
| An equivocation proof is valid only against a member of `W(E-1)`, `W(E)` or `W(E+1)` | PoWit audit 1 | `B.height` of the containing block | "PoWit", "Equivocation proofs" |
| `W(e)` = every unbarred share key with weight (no 64-key cap); justification = two thirds of the total window weight; decay entries go with their key's share work | PoWit audit 4 | `B.height` | "PoWit", "Witness set and justification" |
| A revealed spend policy (or policy-tree branch) may not name one key twice in its raw and enveloped encodings | PF-4 | `B.height` of the containing block (mempool and templates: the next block's height) | "Spend-policy key identity (PF-4)" |
| The conservative signature suite 0x0003 (SLH-DSA-SHAKE-128s AND Falcon-1024) is valid in sighash-v3 key-hash witnesses and spend-policy keys; policy signatures may be up to 10 KiB | P5-S (opt-in conservative suite) | `B.height` of the containing block (mempool and templates: the next block's height) | "Conservative suite 0x0003" |

The PoWit rules are evaluated by one function for every path that judges a
block or an item for a block: `PowitState::apply_at` (block acceptance,
reorg connect and the template's `try_apply`), with the pool and the witness
duty using its building blocks (`member_weight_h2`, `may_be_proven_h2`,
`attestation_message_at`) under the rules of the block that may include the
item (`node/src/powit.rs`). Tests choose the regime with
`activation::scoped_override_v2(h)` or the explicit `*_at` functions.

#### Spend-policy key identity (PF-4)

A policy key (`core::policy`, `docs/MULTISIG.md`) is a hybrid ML-DSA-65 ‖
Falcon-1024 public key in one of two encodings, told apart by exact length
(`crypto::public_key_suite`): enveloped, `B1 0C 01 00 ‖ mldsa_pk(1,952) ‖
falcon_pk(1,793)` (3,749 bytes), or raw, `mldsa_pk ‖ falcon_pk` (3,745
bytes, genesis carry-over keys). Its identity is its enveloped encoding:

```text
key_identity(k) = k                   if len(k) = 3,749
                = B1 0C 01 00 ‖ k     if len(k) = 3,745
```

Every height: the keys of a policy are pairwise distinct as byte strings
(`SpendPolicy::decode`). With sighash v3 (`crypto::verify_bound`) a
signature verifies under either encoding of its key and does not bind which,
so a policy listing one key raw AND enveloped let one signer fill both
slots: a "2-of-2" or "2-of-3" whose participants saw distinct keys was
spendable by that signer alone (Phase-5 finding PF-4).

From the second hardening height: a policy spend in a block at header height
`B.height >= hardening2_activation_height` (mempool admission and templates:
at the next block's height) is invalid if the revealed policy, or the
revealed branch of a policy tree, has two keys `i != j` with
`key_identity(k_i) = key_identity(k_j)`. The rule reads the witness, so like
the other policy-spend rules its failure is witness-dependent (a block whose
id does not commit to its witnesses is not disqualified for it). Below the
height the verdict is unchanged. The rule is
`blockval::check_policy_spends_with_confirmations`, the one function block
connect, reorg connect, mempool admission and the template self-check call;
the check is `SpendPolicy::check_key_identities`.

Relay (node-local): the rule depends on the next block's height and only
tightens the rules, so a peer one block behind across the height, and every
release without the rule, relays such a spend honestly. Mempool admission
therefore classifies a transaction that fails ONLY this rule (it passes
`blockval::check_tx_chain_rules_without_key_identity_rule`, every other
chain rule) as a policy refusal (`AdmissionError::NonStandard`, gossip
verdict `Ignore`, no penalty), and one that also fails another rule as
consensus-invalid (`Rejected`): Bitcoin Core's split between the standard
and the mandatory script-verify flags (`PolicyScriptChecks`).

Outputs locked to such a policy become unspendable from the height, the
behaviour of a new script version that admits one encoding per key (Bitcoin
Core: compressed-only keys in segwit v0 standardness, BIP340 x-only keys in
tapscript; miniscript refuses duplicate keys). Tools never create one:
`SpendPolicy::new` (wallets, `gnb-cli policyaddress`, the bridge vault
`Vault::create`, whose signer/recovery overlap check also compares
identities, and `Descriptor::create` of the public descriptors,
`wallet::descriptor`) refuses two keys with one identity at every height.
Every participant loads a published bridge vault through `Vault::tree`,
which applies the same key checks to the published tree. The producers of
spends apply the rule at their target height: `PolicySpend::target_height`
and the PQ-PSBT roles (`PqPsbt::review`, run by every signer and the
finalizer, with the node's next block height in `gnb-cli policysign`) refuse
a spend of such a policy or branch for a block at or above the height, and
where the height is 0 (testnet, regtest) the spend builders refuse it
outright. Below the height they build and sign it, so its owner can move the
funds. An existing descriptor of that shape (the release before PF-4 created
them) is still restored by `inspect`, `export` and `import`, flagged with
`twin_key_encodings: true` (`docs/DESCRIPTORS.md`). The independent Python
descriptor reference does the same (`reference/descriptor.py`,
`key_identity`; vectors `policy-twin-encoding` / `tree-twin-encoding` (create
refused, inspect accepted and flagged) and `export-twin-encoding` /
`import-twin-encoding` in `reference/descriptor_vectors.json`, regenerated
with `reference/descriptor_vectors.py`).

Vectors (`core::policy::tests::key_identity_vectors_and_the_twin_encoding_policy`):
for the hybrid key derived from seed `0x42 × 32`
(`crypto::generate_keypair_from_seed`), `SHA3-256(key_identity(raw)) =
SHA3-256(enveloped) =
2aeeb67335c518247b6a7c92dbe857f3a72e7806609a2c179ce87aa95de2ccd8`, and the
2-of-2 policy `[raw, enveloped]` (after 0, older 0), which decodes at every
height and is refused from hardening 2, hashes to
`f27d1c6e16aaa5eda18ef3372bd38e56397f8f857b62f8cdaa82d34742dbaf6f`. Both
regimes and the attack are tested end to end in
`node/tests/fix_pf4_policy_key_identity.rs`.

### Selected parent and fork choice

The selected parent of B is the parent with the largest `(blue_work,
blue_score, hash)`. The selected tip is the tip with the largest
`(blue_work, blue_score, hash)`. These rules are unchanged at every height.

The applied chain (the UTXO set, see "Ledger semantics" below) is the
selected-parent chain of the best block, in that order, that is valid in its
own selected-chain context. Blocks that fail connect-time validation, and
every block whose selected-parent chain passes through one, are disqualified
and never selected.

There is no reorg-depth limit and no depth-based finality (audit DAG-6).
From the PoWit height (mainnet 10,000) the checkpoint the applied chain's
witness set has finalized pins fork choice: a block whose selected-parent
chain does not pass through it is never selected, nor offered as a template
parent (`GhostDAG::set_finalized`; docs/DESIGN-pow-powit.md). It restricts
which blocks are selectable, never a block's GhostDAG data (selected parent,
coloring, blue work). A node takes or advances the pin only while the chain
whose state finalized it has at least the node's minimum chain work
(node-local, "Minimum chain work and unrequested blocks" below): a cheap fork
carries its own witness set, so its finality pins nothing while the node may
still be syncing a low-work chain. The
former 1,000-block `MAX_REORG_DEPTH` and the `finalized_height` gate compared
a fork with the node's own history, so nodes that received the same blocks in
different orders could end on different chains. As in Bitcoin Core (no depth
limit, no checkpoints), a node ends on the best valid chain of the blocks it
holds, whatever their arrival order and however deep the fork. What bounds
merging objectively is the merge depth below, a function of each block's
past. Reorgs deeper than 1,000 selected-chain blocks are logged and counted
(`gnb_deep_reorgs_total`), never refused. Undo records are kept for every
connected block and a pruned body of an applied block leaves a rollback
record, so a reorg of any depth also works on a pruned node. A move is
committed in atomic chunks of at most `reorg::MAX_BLOCKS_PER_COMMIT` (16)
blocks, each with the tip pointer at its end (node-local; Bitcoin Core's
`ActivateBestChain` steps the same way): its memory is bounded by one chunk,
every intermediate state is a consistent applied tip, and start-up continues
an interrupted move. When a block of a later chunk turns out invalid the best
valid chain is resolved again from where the applied chain stands, which can
move back to the old branch; the end state is the same as with one batch.
The PoWit finality pin above (`GhostDAG::set_finalized`) moves with the
applied chain: each committed chunk pins the checkpoint its applied tip
finalized before the move goes on, and start-up restores the pin
from the applied tip before it resumes a move, so neither a block of a later
chunk that turns out invalid nor a crash between chunks takes the node back
across finality its applied chain reached (it ends where a node that
followed the branch block by block ends). A block's PoWit state and the
reachability records its insertion changed are committed in the same batch
as its DAG record (the in-memory copy of those records is marked written
only once that batch commits), and the selected-chain index rows of the
blocks a chunk moves, keyed by chain position (`Storage::stage_chain_index`),
in that chunk's batch. A pruned node that reorganized away from
blocks whose bodies it had pruned and needs them again (the old chain became
the heaviest once more, or an operator override below moves to it) re-fetches
those bodies from its peers before it connects them; nothing is written in
between. On acceptance the blocks of the best chain that lack a body wait for
one, together, while the node stays on the best chain it can connect; the
chain is connected once the last body is back. A block whose body was
dropped because it failed a rule that depends on witness bytes the block id
does not commit to (below the hardening activation, see "Ledger semantics")
waits the same way: both are one state, "a body of this DAG block is wanted",
decided in one place, fetched through one request path (the node's directed
pulls of missing parents, retried with backoff, at most 1,024 bodies being
fetched at once) and accepted through one path. The node accepts a copy of a block already in its DAG only while a body
of it is wanted, only as the answer to its own directed pull, and only for a
block that is not applied (an applied block is rolled back from its undo
record); any other copy is ignored before decoding. A copy is checked exactly
like a new block — header height = the largest parent DAG height + 1 (neither
`height` nor `blue_score` is committed by the block id), expected bits,
timestamp, the hardening block rules (the witness commitment at/after the
activation), proof of work, and a witness root not rejected before for that
block — and stored exactly as on acceptance.

An operator can override the choice, node-locally and persistently, with the
RPCs `invalidateblock <hash>` (disqualify the block and every block whose
selected chain passes through it, and move to the best remaining chain) and
`reconsiderblock <hash>` (reconsider those marks for the block, its
selected-chain ancestors and descendants, and re-evaluate); see
`docs/RUNNING.md`. These are not consensus rules. `reconsiderblock` never
lifts a consensus verdict without re-validating it: operator marks and marks
inherited from a disqualified selected parent are removed; a mark for the
hardening block rules (start-up recheck of blocks an older release stored) is
removed only if the stored body now passes those rules; a mark for a
connect-time failure is removed only by the atomic batch that connects the
block after validating it again in its own context (a block the move does not
connect keeps its mark, on disk and in memory, also when the move dropped its
stored body as witness-rejected; one that fails again is disqualified again).
Conversely every committed move — an override or an ordinary acceptance —
deletes the connect-time or inherited mark of each block it applies, which it
has just validated in its own context, so an applied block never carries a
mark that would disqualify it again at the next start. On a
pruned node, an override whose new chain needs pruned bodies changes nothing,
requests the next (at most 4,096) of those bodies and asks to be retried.

### Blue work

```text
blue_work(genesis) = 0
blue_work(B)       = blue_work(sp) + Σ work(m) for m in mergeset_blues(B) + work(B)   // at/after activation
blue_work(B)       = blue_work(sp) + work(B)                                          // before activation
work(B)            = block_work(B.bits, B.height)   // "Chain work": v3 blocks >> 2
```

After activation, `blue_work(B)` is the total work of `blue(B) ∪ {B}`.
Kaspa's blue work is the work of `blue(B)`. GnB has always counted the block's
own work, so GnB's value equals Kaspa's plus `work(B)`. `blue_work(sp)`
already includes the selected parent's own work, so the sum covers the
selected parent, which Kaspa stores as `mergeset_blues[0]`. For a block that
merges no blue, both formulas give the same value, so there is no jump at the
boundary.

### Coloring

`mergeset(B) = past(B) \ past(sp) \ {sp}`. The coloring is greedy, so the
order in which the candidates are processed decides which of them become
blue; it is part of consensus (audit B2-T9) and is, at every height (the
pre-activation coloring uses the same order):

1. the in-degree of a candidate is the number of its distinct parents that
   are themselves in the mergeset;
2. a FIFO queue starts with the candidates of in-degree 0, in ascending byte
   order of their 32-byte block ids;
3. repeatedly the candidate at the FRONT of the queue is taken; the
   candidates whose in-degree drops to 0 by its removal are appended at the
   BACK of the queue, in ascending byte order of their ids.

This is Kahn's algorithm with a FIFO queue. It is NOT "always the lowest id
among the candidates ready at that point": a candidate that becomes ready
later is processed after every candidate already queued, whatever its id.
The two readings color differently (`reference/ghostdag_vectors.json`, case
`order/fifo-not-lowest-id`: a mergeset of eleven siblings T1..T11 of the
selected parent and U, a child of T1 with the lowest id; FIFO colors
T1..T10 blue, the other reading T1, U, T2..T9). `reference/gnb_ghostdag.py`
is the executable definition of the order and of the coloring below, and
`node/tests/ghostdag_vectors.rs` checks the node against its vectors. (Kaspa
orders the mergeset by blue work, then hash; GnB keeps its own order, which
every GnB release since genesis has used.)

With `blue` = blue(sp) ∪ {sp} ∪ the candidates already colored blue,
candidate c is blue iff:

1. |anticone(c) ∩ blue| ≤ k, and
2. every x in anticone(c) ∩ blue has |anticone(x) ∩ blue| + 1 ≤ k.

After activation, both counts range over the full blue anticone, including
selected-chain blocks: exact PHANTOM/GHOSTDAG, so blue(B) is a k-cluster.
`mergeset_blues` excludes the selected parent, so it holds at most k blocks,
and `blue_score(B) = blue_score(sp) + |mergeset_blues(B)| + 1 = |blue(B)|`.
`blues_anticone_sizes` records the exact |anticone(x) ∩ blue(B)| for the
selected parent, the new blues and every older blue whose count grew.
`node/tests/fix_ghostdag_exact_coloring.rs` checks this against a
brute-force implementation of the definition.

Before activation the old walk is used. It never counts selected-chain blocks
below the selected parent, and it restarts older blues' anticone counts at 0,
so it can color blue a block with more than k blues in its anticone.

### Mergeset size and merge depth

- `|mergeset(B)| ≤ MERGESET_SIZE_LIMIT = 64`, at every height: blocks merged
  besides the selected parent. This chain's rule since before the
  2026-10-14 reset; it is tighter than the audit's hardened bound
  (`|mergeset(B)| + 1 ≤ MAX_MERGESET_SIZE = 180`, Kaspa's production limit),
  so it is the one limit on both sides of the activation. With k = 10 at
  most 10 merged blocks are blue, and one block's coloring is bounded to 64
  candidates. A larger mergeset is rejected with `MergesetTooLarge` before
  any coloring work, and nothing is inserted (vector case
  `mergeset/size-limit` in `reference/ghostdag_vectors.json`).
- Merge depth (at/after the activation): let R be the highest selected-chain block of B with
  `blue_score(R) ≤ blue_score(B) - MERGE_DEPTH`, where `MERGE_DEPTH = 360`
  (3 hours at 30 s). Every red in B's
  mergeset must be R itself, in the future of R, or in the past of a blue in
  B's mergeset that is in the future of R (Kaspa's "kosherizing" rule).
  Otherwise B is rejected with `MergeDepthViolation`. Blues need no check: a
  blue that deep would have more than k blues in its anticone.

A rejected block is not inserted. Since `MAX_PARENTS` (256) exceeds the
mergeset limit, block templates must choose parents with
`GhostDAG::select_parents_for_template(&bodied_tips, MAX_PARENTS)`. It puts the
selected parent first, adds the other tips by decreasing blue work while the
mergeset fits `MERGESET_SIZE_LIMIT`, and drops tips that would break the
merge depth; the budgeted selection runs on both sides of the activation.

A tip that is not the lowest possible merge-depth root of the template (the
root of a block with no mergeset blue: `blue_score = sp.blue_score + 1`) and
not in its future can never be merged again (audit B1-T15): it is red (in the
anticone of every chain block from the root to the selected parent) and, being
a tip, in no block's past, so nothing kosherizes it; its whole branch is below
the root. Such tips are skipped with one reachability query each, before their
bodies are looked up and before any mergeset work, and one final
`compute_block` checks the result (Kaspa filters virtual-parent candidates the
same way). They stay in the DAG and among the valid tips: chain selection is
unchanged. Previously each one cost a full `compute_block` and a stored-body
lookup at every template computation (twice per accepted block), forever.
This is template policy: no verdict changes.

### Ledger semantics: selected-chain-only

This is the specification at every height, before and after the activation.

- The UTXO set at the selected tip is the result of applying, in order from
  genesis, the blocks of the selected chain (the tip, its selected parent, and
  so on). Each block contributes its transactions and its coinbase.
- Blocks that are merged, blue or red, but are not on the selected chain
  change nothing. Their transactions are not applied, their outputs do not
  exist, and their coinbases pay nothing. A transaction is confirmed only when
  a selected-chain block includes it. A parallel block's transactions stay
  unconfirmed until a selected-chain block includes them.
- A reorg moves the UTXO set by rolling back and applying blocks along the old
  and new selected chains (`node/src/reorg.rs`). Mergesets are never applied.

GhostDAG therefore decides which chain is selected (blue work, after
activation including merged blues) and the blue scores. It never moves value.
After activation, honest parallel blocks add weight to the honest chain in
fork choice, but their miners are still not paid. The mergeset transaction
rules sketched in `docs/LEDGER.md` section 7 are not implemented. Adopting
them would be a further consensus change with its own activation.

### Per-block cost (all heights, output-preserving)

These changes leave every result unchanged and apply at all heights:

- The mergeset comes from the reachability index in O(|mergeset|), not from
  O(|past|) `compute_past`.
- The pre-activation walk stops after k + 1 anticone blues and skips
  selected-chain blocks that merged nothing.
- Reachability reindexing computes subtree sizes once per reindex instead of
  once per visited node.
- Reachability reindexing follows Kaspa's reindex-root scheme (audit DAG-7
  residual, `node/src/consensus/reachability.rs`): a selected-chain block
  100 to 200 blocks below the heaviest tip is the reindex root; when it
  advances (in jumps of 100), the chain from the old root to the new one is
  concentrated, with 4,096 free slots reserved around the children of every
  chain block. A block above the root is reindexed inside that window; a
  deep side block or a genesis sibling reclaims slack along the chain toward
  the root and re-lays out only its own branch and the side branches it
  shifts. The previous scheme re-laid out the whole subtree under the first
  ancestor with room: O(DAG) for one such block, under the DAG write lock.
  The answers of the index are exact under any layout, so GhostDAG's output
  is unchanged; the reindex root is a performance hint persisted with the
  root's reachability record.

At the audit's 12,000-block scenario (dev profile), these changes reduced a
deep side block from 10–26 s to 50–84 ms, a genesis sibling that forces a
reindex from 46 s to 0.1 s, and the 1,000-block side-chain merge from 35 s to
29 ms. After activation, that merge is rejected in under 1 ms.

Before the reindex-root scheme, the reachability reindex that one genesis
sibling or one deep side block triggers on insertion stayed proportional to
the DAG (about 100 ms at 12,000 blocks, dev profile); counted in
`node/tests/fix_dag_hot_path_cost.rs`, the largest of 83 such insertions
re-laid out 18,009 nodes of an 8,000-block DAG (4,509 at 2,000 blocks), and
now 101 at both sizes. What remains, before activation, is the coloring walk
for a candidate that forks deep. Such blocks are not inserted unless a chain
carrying enough work backs them: the node-local anti-DoS work rule below
runs before the proof of work, storage or insertion of every block whose
parents are known. GhostDAG's results and the reachability index's answers
are unchanged by it. Measured in `node/tests/fix_ghostdag_dag7_perf.rs` (80
such blocks, dev profile): 747 ms of insertions at 12,000 blocks become
0.5 ms of refusals.

Why a peer cannot reach the pre-activation coloring walk without passing the
work rule:

- The walk (`candidate_anticone_blues`) runs only inside
  `GhostDAG::add_block`, and blocks from the network reach `add_block` only
  through `accept::accept_block`. Genesis and the start-up load insert stored
  `GhostdagData` and color nothing; storing a wanted body of a block already
  in the DAG (a pruned body needed again, DAG-6, or a replacement for a body
  rejected for its witness bytes) inserts nothing.
- `accept_block` is called by the ingress core for a block whose parents are
  all known, after the work rule admitted it; by the orphan drain, for a
  buffered orphan whose last missing parent was just inserted, after the
  work rule admitted it again with its parents known (Phase 4, B1-T5: the
  orphan passed only the bits floor and its proof of work to be buffered);
  by the RPC `submitblock`, after the minimum chain work (Phase 4, POW-3;
  not the tip-relative work threshold, like Bitcoin Core's `submitblock`, so
  an operator can feed the node a heavier chain that forks deep below its
  tip); and by the built-in miner. Every call checks the
  header height, the exact ASERT bits, the timestamp and the proof of work
  before insertion.

What the rule still admits is bounded by work. For a candidate c merged by a
new block B, the walk visits B's selected chain downward, skipping chain
blocks that merged no blue, and stops at the first chain block in c's past
or after k + 1 blues in c's anticone. A visited chain block that adds no blue
merged only blues of c's past (none can be in c's future), so beyond k + 1
steps each step is a distinct block of c's past that the selected chain
merged as blue without that chain block being in c's past. All of these
blocks, and c, entered the DAG through the work rule: within the 360-block
window (a chain keeping pace with ours), merge-backed (each needs a buffered,
proof-of-work-verified orphan that passes its contextual checks and whose
blue-work bound reaches the threshold — below the activation only — and
every such admission is charged to one shared budget: 4, then one per
30 s), or chain-backed (announced orphans covering the fork's whole depth
below the window). A walk therefore lengthens by at most one
step per such paid admission. After activation, the mergeset limit and the
merge depth bound every block's coloring outright.

### Anti-DoS work rule (node-local policy, not consensus)

Audit POW-3. Blocks on deep forks can be nearly free (absolute-schedule ASERT).
A node therefore stores and processes a block B whose parents are all in its
DAG only if, with `T` = the blue work of the selected-chain block 360
(`ANTI_DOS_WINDOW_BLOCKS` = `MERGE_DEPTH`) below its selected tip (0 for a
shorter chain) and `lb(B)` = the largest parent blue work + `work(B)`, a lower
bound of B's blue work:

1. `lb(B) ≥ T`; or
2. `lb(B)` + the work announced on top of B reaches `T`. The announced work
   is the summed header work of the distinct orphans that wait on B directly
   or through one another, each counted once, whatever the shape of the fork
   (a DAG-shaped fork is summed, not measured along one path: after
   activation `T` includes merged blues, and a fork of parallel blocks must be
   credited the same way). The orphans are buffered, or were evicted from the
   bounded orphan pool and are kept without their bodies (at most 50,000,
   by block id, so a re-sent orphan never counts twice); if larger, the work
   of the heaviest single path of buffered orphans plus the work remembered
   along an evicted path is used instead (it chains through any number of
   evictions, so a linear fork deeper than every store still proves its work).
   Each orphan passed the orphan bits floor (the target a child of the
   selected tip would carry now — re-expressed in the orphan's own GnB-SMH
   algorithm when the two heights straddle the v1 -> v3 switch, v3 targets
   being 2^`POW_V3_DIFFICULTY_SHIFT` harder for equal work
   (`ingress::reference_for_height`) — eased 16-fold and capped at the pow limit of
   the height the orphan claims — the limit its own proof of work is checked
   against: the genesis target at/after the hardening activation, the legacy
   limit below it, see "Pow limit (POW-3)" — so the pre-activation blocks of
   a fork that branches below the activation stay admissible after the tip
   passed it) and its proof of work. Both
   remembered stores are keyed only by an evicted orphan's missing parents
   (at most 8), charged to the peer that delivered it (at most a quarter of
   each store per peer) and, when full, give way only to an entry of greater
   work, so orphans at the floor cannot flush them; or
3. a buffered orphan VOUCHES for B (it merges B, a lower-work block):
   Phase 4 (B1-T5) — the orphan waits on B directly and every other parent
   of it is in the DAG; its header passes, with B in hand, the contextual
   checks `accept_block` will apply (header height = max parent height + 1,
   bits = the expected ASERT bits of its parent set, timestamp at least the
   latest parent's and at most 600 s ahead); its height is below the
   hardening activation; and its own bound (largest parent blue work, `lb(B)`
   for B, + its work) reaches `T`. Every such admission is charged to one
   budget (4, then one per 30 s), once, when B is about to be stored with
   its proof known valid (charged before the proof, a block whose proof the
   PoW workers evaluated was charged twice, and junk-nonce candidates spent
   it). Before Phase 4 the bound came from the
   self-declared parents and bits of any orphan above B, directly or through
   other orphans, unchecked: one orphan listing the tip and a low-work block
   (even one stamped before its parents, so never valid) got that block
   admitted, and only admissions more than 1,000 blocks deep were rationed.
   From the activation no orphan vouches: B's own chain cannot come within
   the 360-block window, so B is below the merge-depth root of every block
   that builds on the tip and merging it is a `MergeDepthViolation`.

Otherwise B is ignored without penalty (a refused block is not re-evaluated
until the orphan pool, the DAG or the selected tip changes). A chain that
carries the work is accepted (this is Bitcoin's anti-DoS work threshold, with
the orphan pool as the header buffer), so for honest data the final chain is
the same with or without the rule. The one bound is memory: a DAG-shaped fork
with more blocks above its first block than the pool and the 50,000 kept
evicted orphans hold is credited the summed work of the part they hold, or
its heaviest path if larger.

The rule applies again to every buffered orphan the drain connects once its
last missing parent is in the DAG (Phase 4, B1-T5; it used to be stored
without any work check, so the low-work fork above a merge-backed block was
stored whole); one it refuses is not stored, and the orphans above it keep
waiting (if more work is announced above it, the orphan sweep fetches it
again). The gossip verdict of a buffered orphan's frame is withheld until
the orphan connects (`Accept`, relayed then), is refused (`Ignore`, or the
penalty below for an `accept_block` rejection), leaves the pool or outlives
gossipsub's cache (`Ignore`): an orphan has passed only the floor and its
proof, and relaying it at once let floor-meeting orphans travel the whole
network, charged at every hop to the honest relay that forwarded them
(`ingress::DeferredBlockVerdicts`).

### Minimum chain work and unrequested blocks (node-local policy, not consensus)

Audit POW-3 (Phase 4). The work rule's threshold is relative to the node's
own tip, so it does not protect a node whose tip is far behind the network
(initial sync, or a node that was offline): an attacker mines one block A on
that tip stamped "now", and under the absolute-schedule ASERT every child of
A has the pow-limit target — near-free blocks, all above the threshold.
Bitcoin Core's defences, adapted (`ingress::unrequested_block_admission`):

- **Minimum chain work** (Core's `nMinimumChainWork`), in blue work:
  `ingress::MAINNET_MINIMUM_CHAIN_WORK` (testnet and regtest: 0), or
  `--minimumchainwork <hex>`. While the selected tip's blue work is below it
  the node is in initial block download: it latches the IBD state (the
  miner stays paused, stalled sync or not) and processes no block it did
  not ask for, unless that block's own bound reaches the minimum. Mainnet's
  value is `core::MIN_CHAIN_WORK` = 7,000,000, derived from the mainnet
  reading of docs/MAINNET-READINESS.md §1 (tip height 8,302, blue work
  7,782,451, 14 Oct 2026; 10% below it, and far below the tip of the
  release); docs/RUNNING.md gives the release step that raises it. Its unit
  is the selected tip's blue work, the sum of `core::block_work`: a block's
  `bits_to_work` (the genesis target 4,500, the pre-activation pow limit
  1), divided by 4 for GnB-SMH v3 blocks, whose target is 4 times harder,
  so the sum is continuous across the v1 -> v3 switch (below the hardening
  activation the selected chain's blocks, from it the merged blues too).
  Block work bounds (`lb`, the announced work of orphans) count each block
  as `accept_block` adds it to the DAG. The minimum is not consensus: no
  block's validity, GhostDAG data or the heaviest-chain choice among the
  blocks a node holds reads it, so nodes with other values (an override, a
  release without it) reach the same verdicts on the same blocks. One
  node-local fork-choice input does read it: no PoWit finality pin is taken
  or restored below the minimum (`powit::pin_finalized_of`, PoWit audit
  finding 3), so a cheap chain pulled during initial sync cannot pin a
  node; a node running a lower override can pin earlier than its peers,
  which, like every pin, only affects that node's own choice.
- **Below the minimum, no chain of record**: blocks the node requested are
  processed below the minimum (as in Core), so an eclipsing peer that
  answers its pulls can make a cheap chain its selected tip (no header chain
  with proofs tells the node a chain's work before it downloads it, as
  Core's headers presync does). While the tip is below the minimum the node
  therefore mines nothing and `getblocktemplate` refuses
  (`ingress::ibd_template_refusal`), a witness node neither attests
  checkpoints nor mines shares, and GetTips / GetHeaders are answered
  empty (`network::serve::serve_sync_request`; Core ignores `getheaders` in
  initial block download), so such a chain is neither mined on nor
  advertised to peers; blocks it stores are still served by GetBlock.
- **Unrequested blocks** (Core's `AcceptBlock`, `!fRequested`): a block that
  is neither the answer to one of this node's directed pulls nor a block it
  has an outstanding request for (whoever delivers it) is processed only if
  `lb(B)` reaches the blue work of the selected-chain block
  `UNREQUESTED_WINDOW_BLOCKS` = k + 1 = 11 below the tip (Core requires at
  least the tip's work; GhostDAG's honest concurrency, and `lb` omitting the
  merged blues after the activation, need the k + 1 margin). A deeper fork
  block is processed only when requested (the parent of a buffered orphan,
  a frontier tip, an IBD pull), where the 360-block rule above applies. An
  unrequested orphan is buffered only outside initial block download; one
  claiming a height more than 1,000 above the tip is dropped before decoding
  (`ingress::unsolicited_height_too_far_ahead`).
- **`submitblock`**: refused below the minimum chain work
  (`ingress::submitted_block_admission`, before the proof of work). The
  tip-relative threshold `T` is not applied, as Bitcoin Core's `submitblock`
  (`ProcessNewBlock` with `force_processing`) skips its anti-DoS checks: the
  RPC is how an operator replays the heavier chain to a node that sat on a
  minority branch (a partition or an eclipse), and that chain's first blocks
  above a deep fork point are, judged one at a time, below `T` (a review of
  an earlier Phase-4 version, which applied `T`, found such a replay refused
  block by block). A deep-fork block is cheap below the activation, so a
  public RPC should run with `--rpc-require-auth-for-writes`.

What remains: a node that is behind but above the minimum is protected
only by the rules relative to its tip, so a block A as above and its cheap
children (each costing one evaluation) are processed — at most at the rate
the attacker evaluates proofs, and within the per-peer and per-network-group
proof-of-work budgets below; raising the minimum at each release closes
this for every node that has not reached it. Blocks this node requested
(IBD pulls answered by an attacker's header list) are not checked against
the minimum: that needs a header chain with proofs (Core's headers
presync), which the sync protocol (`/gnb/sync/1` `Headers`: ids and claimed
scores only) does not carry. Such a chain can become the selected tip of an
eclipsed node below the minimum, but not its chain of record (above): it is
neither mined on nor advertised, and the node stays in initial block
download, so it moves to the real chain when that chain's blocks arrive
(the heavier chain wins at any depth), unless a PoWit finalized checkpoint
of the cheap chain pins its fork choice: a chain past the PoWit height can
carry one, and the pin does not read the minimum chain work here
(docs/DESIGN-pow-powit.md, "Node finality").

### Assumed-valid block (node-local policy, not consensus)

Package P5-G, Bitcoin Core's `-assumevalid` (`node/src/assumevalid.rs`). A
release names a block of the real chain, `assumevalid::MAINNET_ASSUME_VALID`
(its id and DAG height; none yet on mainnet, testnet or regtest), and
`--assumevalid=<id>` replaces it or `--assumevalid=0` turns it off. When the
node CONNECTS a block B (`accept::commit_chunk`, the one connect path:
extensions, reorgs, the start-up reconnection, the chain-state rebuild), it
skips B's transaction signature verification
(`core::sighash::verify_input_signatures`) if all of Core's conditions
(`Chainstate::ConnectBlock`) hold, evaluated once per chain move on the DAG,
which is GnB's header tree:

1. the assumed-valid block AV is in the DAG (stricter than Core: and carries
   no persistent verdict on this node, neither a consensus failure of it or
   of its selected chain nor the operator's `invalidateblock`);
2. B is AV or lies on AV's selected chain (only selected-chain blocks are
   connected: a block merged by AV's chain was never validated by the nodes
   that vouch for AV and is never skipped);
3. B is the best block (`GhostDAG::selected_tip`, Core's `m_best_header`) or
   lies on its selected chain;
4. the best block's blue work is at least the minimum chain work above;
5. `(blue_work(best) - blue_work(B)) * 30 / work(best) > 1,209,600`
   (`assumevalid::MIN_BURIAL_SECS`): more than two weeks of
   proof-equivalent time, Core's `GetBlockProofEquivalentTime` with blue work,
   the 30 s target spacing and the best block's own work (`core::block_work`
   of the ASERT bits of its parents, which its header carries);

and one condition Core gets from its witness commitment: B's id commits to
every witness byte (`accept::witnesses_fixed_at`: from
`WITNESS_COMMITMENT_HEIGHT` or the hardening activation). Below both, a
relay can replace `script_sig` bytes without changing the id, so the held
body need not be the one the assumed-valid chain was validated with, and B is
checked in full.

Only the signature step is skipped (the step a verified-signature cache hit
skips, `admission::check_input_scripts_without_signatures_at`): the version
rule, the witness framing (canonical from the activation), the public key
hash against the spent script, a revealed policy's hash, signature count and
key indices, the policy timelocks, amounts and MoneyRange, UTXO existence and
double spends, coinbase maturity, BIP30, the size-based minimum fee and the
coinbase value still run, as do every acceptance check (the proof of work
above all: never skipped, as in Core) and the PoWit state. Mempool admission,
templates and `blockval::validate_block_transactions` always verify in full.

It changes no verdict on a valid chain: every rule but the signatures runs,
and a valid chain's signatures are valid. Nodes with different settings
reach different verdicts only on a chain whose blocks below AV carry invalid
signatures, i.e. only if AV itself is not a block of a valid chain — the
trust Core places in its release value, reviewed like any consensus constant
(`tools/release/min_chain_work.py` prints it from the same block as the
minimum chain work, read on two or more independent nodes).

Without a header-first download (`/gnb/sync/1` `Headers` carry ids and
claimed scores, not headers) a block is connected as soon as its parents
are, so during a fresh initial block download AV's header is not in the DAG
when its ancestors connect (condition 1) and they are checked in full; with
condition 5 nothing on a chain younger than two weeks qualifies either. The
skip applies when the node connects blocks with AV already in its DAG: a
chain-state rebuild (Core's `-reindex-chainstate`), the move onto the real
chain of a node that sat on another branch (partition, eclipse), bodies
that come back (audit DAG-6) and a resumed chain move. What condition 1
needs during initial sync is a header tree in place before the blocks
connect (Core's headers-first sync; package P5-B2 adds verified headers to
`/gnb/sync/1`); the decision reads nothing of that tree but membership,
selected-chain ancestry, blue work and the best block.

### Gossip penalties and proof-of-work budgets (node-local policy, not consensus)

Audit NET-2 residual, B1-T7, NET-4 residual (Phase 4).

**Who is charged for a refused block frame** (`ingress::block_penalty`).
Gossipsub's `Reject` charges its invalid-message penalty (P4) to the peer
that delivered the frame and to every peer that delivered a duplicate.
Releases older than the validated relay (NET-2) forward every frame
unvalidated and follow the chain until the hardening activation block
(which they reject); releases older than Phase 4 relay an orphan once its
bits meet their own floor and its proof is valid, before its parents are
known, at every height. Either can be an honest peer that delivers a frame
this node refuses (Bitcoin Core: never punish for data that may be invalid
only because of a rule change, `BLOCK_RECENT_CONSENSUS_CHANGE`; punish the
peer that sent it). So:

- a frame the delivering peer authored (gossipsub's signed source is the
  propagation source), or sent as the answer to this node's pull, is charged
  to it as a misbehaviour: the peer is disconnected and its address
  discouraged (below), and gossipsub is told `Ignore` (no relay that
  forwarded a duplicate is charged) unless the next rule applies;
- a relayed frame is charged (`Reject`, and a misbehaviour) only for a
  context-free fault — malformed body, id or height binding, structure,
  proof of work: what every release on the chain checks before relaying —
  and only once the selected chain contains the activation block
  (`ingress::block_penalties_in_force`, the transaction relay's gate);
- a relayed frame with a contextual fault (height, bits, timestamp,
  coinbase) or below the orphan floor (a function of the node's own tip and
  clock) is never charged to the relay; an orphan below the floor that
  answers this node's own pull is dropped without any charge
  (`ingress::orphan_floor_penalty`: the node asked for it, and an old block
  of an era with far easier bits fails the floor honestly).

Before the activation a frame signed by a throwaway author key and delivered
by another connection is a relayed frame: an attacker that signs each
invalid block with a fresh key is never disconnected or discouraged for it
(an honest legacy relay cannot be told apart from it), and is limited only
by the per-peer and per-network-group proof-of-work budgets below.
Discouragement before the activation covers self-signed gossip and answers
to this node's pulls.

Wire violations (oversized, bounds-violating, padded or non-canonical
frames, which releases older than NET-2 forward) follow the same rule
(`network::wire_violation_penalty`): the application-score penalty is charged
to an author that delivered its own frame, or once penalties are in force;
`Reject` (P4 on duplicates too) only once they are in force. A peer the
bounded wire-penalty tracker forgets has its application score reset (it
used to keep its last score forever).

**Address discouragement** (`network::discourage`, Bitcoin Core's
`m_discouraged`): a misbehaving peer is disconnected and its address — the
IPv4 address, or the IPv6 /64 — discouraged for 24 hours (at most 50,000
addresses); a connection from a discouraged address is closed at once, so a
fresh libp2p identity from the same address buys nothing. Local addresses
(loopback) and operator-configured peers (`--peer`) are never discouraged.

**Proof-of-work budgets** (`pow::verifier`, see "Acceptance order"): every
gossip evaluation is charged to the delivering peer (4, refilled one per
60 s) and to its network group (IPv4 /16, IPv6 /32: 8, one per 30 s) and
refunded when the proof is valid, so only failed proofs — and gossip orphans
whose bits fail the floor, which are charged one evaluation — consume them;
a gossip block from a peer or group whose budget is spent, or when the queue
is full (64 gossip blocks, 4 per peer, 8 per group), is answered `Ignore`
unevaluated. Answers to this node's own pulls are not charged up front (sync
keeps up to 16 pulls in flight per peer, answered faster than proofs are
evaluated): they have their own queue bound of 1,024, go first, and are
charged to the peer and its group only when the proof is invalid (the peer
is then also disconnected and discouraged). Results are remembered by block
id and header height (the pow limit a proof is judged against depends on the
height, which the id does not commit). The audit measured about three
zero-cost invalid blocks per libp2p identity, identities being free; now
identities and addresses inside one /16 share eight evaluations, and an
author that delivers one invalid block of its own is disconnected and its
address discouraged.

**Proof-of-work cost of sync** (P5-G). Every proof is evaluated once, on the
worker pool: half the logical CPUs (1 to 4) normally, and while the IBD latch
holds (the miner and the witness duties wait) every CPU but one, at least
that and at most eight (`pow::verifier::ibd_workers`; eight GnB-SMH v1
scratchpads are 512 MiB), as Bitcoin Core verifies with every core during
IBD. A body fetched again for a block already in the DAG (a pruned body a
reorg needs, a body rejected for a witness-dependent reason) is never handed
to the workers and its proof is never evaluated again: the DAG record is the
verified result of that proof at that height, and it survives restarts
(acceptance order, step 6). Proofs are never skipped, below the assumed-valid
block either (Core never skips them): a block's proof is what admits its
header to the DAG, and no header chain is known before it.

**PoWit gossip** (`NewPowitItem`: witness shares, attestations, equivocation
proofs; `ingress::PowitIngress`). Merged from the mainnet line, where each
item was verified with `powit::admit_item` awaited inline on the block
processor, unbudgeted — a share's proof is a GnB-SMH v3 evaluation (4 MiB,
~90 ms), an attestation a KES signature check, both free to fake — and an
item whose claimed id did not match was `Reject`ed whoever delivered it.
Now the items, which travel on the transaction topic, are delivered to the
transaction relay task (`network::goes_to_tx_ingest`), never to the block
processor. The claimed id and the item's encoding are checked first
(`ingress::powit_item_precheck`); verification then runs on the blocking
pool through a proof-of-work scheduler of its own
(`pow::verifier::PowLimits::powit_items`: half the block pool's workers, at
least one; a queue of 256, 32 per peer, 64 per network group; budgets of
failed verifications of 16 per peer, one per 5 s, and 32 per group, one per
2 s; a stale queued item is answered `Ignore` unverified). An admitted item
is relayed and refunded. A context-free fault — wrong id, malformed item,
invalid share proof (or bits, target or payout that the share's attested
block contradicts), invalid witness signature, an equivocation proof that
does not verify (`ingress::powit_admit_error_fault`): what no release that
knows `NewPowitItem` relays, since they all admit an item before relaying
it — keeps its charge and is penalised through `ingress::block_penalty`,
the block gate above (its author when it delivered the item itself; a relay
only once penalties are in force). A refusal that depends on this node's
chain or state (a share for a block that is not on its selected chain or is
outside the share window, an attestation from another justified checkpoint
or by a key outside the witness set, a full pool) is refunded and answered
`Ignore`, never penalised.

## PoWit (witness set, attestations and evidence)

From the PoWit height (mainnet 10,000) a block's PoWit section (witness
shares, attestations, equivocation proofs; `core::powit::PowitBody`) is
checked in context before the block is stored, and the block's PoWit state is
`PowitState::apply_at(parent state, block)` (`powit::block_state`), a pure
function of the block, its selected-parent chain and the parent's state.
docs/DESIGN-pow-powit.md describes the design; this section specifies the
rules the second hardening activation changes (PoWit audit findings 1 and
4), byte for byte where they define encodings. The executable reference is
`reference/powit_reference.py`, its vectors `reference/powit_vectors.json`
(regenerated and diffed by CI's `python-reference` job), checked against the
Rust code by `crates/gnb-crypto/tests/powit_vectors.rs`.

Epochs count from the PoWit activation `act`: `epoch(h) = (h - act) /
epoch_len`; checkpoint slots are `act + k × checkpoint_interval`. Mainnet:
epochs of 720 blocks, slots every 60, a 28-epoch window, vote lifetime 720,
32 attestations and 4 proofs per block; testnet: 20, 5, 3, 20, 32, 4
(`MAINNET_PARAMS`, `TESTNET_PARAMS`).

### Regime

A block at header height `h` is checked under the old rules (`Regime::V1`)
when `h < H2` and under the second hardening rules (`Regime::Hardening2`)
when `h >= H2`, `H2` being the second hardening activation height
(`Regime::at`). An attestation's message version follows its **target**
height instead, so that a witness, which signs before any block includes
its vote, knows what to sign: v2 iff `target.height >= H2`. A block below
`H2` checks every message as v1, also an equivocation proof's links that
target a later slot (the old rule, unchanged).

### Attestation messages

```text
msg_v1 = SHA3-256( u32le(19) ‖ "GNB-POWIT-v1/attest" ‖ u32le(chain_id)
                   ‖ u64le(source.height) ‖ source.hash[32]
                   ‖ u64le(target.height) ‖ target.hash[32] )          // 107-byte preimage
msg_v2 = SHA3-256( u32le(19) ‖ "GNB-POWIT-v2/attest" ‖ u32le(chain_id)
                   ‖ u8(depth) ‖ root[32]
                   ‖ u64le(source.height) ‖ source.hash[32]
                   ‖ u64le(target.height) ‖ target.hash[32] )          // 140-byte preimage
```

`(depth, root)` is the attestation's KES public key (`KesPublic`, already on
the wire: no encoding changes); `chain_id` is the network's (0x474E0001
mainnet, 0x474E0002 testnet). The signature is `kes::verify(witness,
epoch(target.height), msg, sig)`: the leaf of the target's epoch, its path to
`root`, and a canonical hybrid signature over `msg`
(`attestation_message`, `attestation_message_v2`, `attestation_message_at`).

Why v2 (finding 1): `msg_v1` does not depend on the key, and `kes::verify`
only checks that the leaf hash and the supplied path reach the root, so one
leaf's signature re-rooted under any sibling hash is a valid signature by
another key, one SHA3 per key. One leaf's double vote was therefore an
unlimited supply of valid equivocation proofs against keys nobody holds.
Committing the key in the signed message (as BIP-340 commits the public key
in its challenge) makes a signature valid for exactly one key.

### Witness set and justification

`W(e)` of a state, `e >= 2` (`W(0) = W(1) = {}`): for every key with share
work credited in epochs `max(0, e-1-window) ..= e-2` (the state's
`epoch_work`), its weight is that work summed (saturating at 2^128-1), after
`decay[k]` decay steps (`w -= w / 16`, at most 64 steps); keys barred at `e`
(`banned[k] > e`) and keys of weight 0 are left out; sorted by weight
descending, then key ascending.

- `Regime::V1`: the first `max_witnesses` (64) of them.
- `Regime::Hardening2`: all of them (`witness_set_in`, `member_weight_h2`).

An attestation in a block is counted with its key's weight in
`W(epoch(target))` (a non-member's attestation makes the block invalid). The
votes for a target `t` from the justified checkpoint justify `t` iff
`total(W(epoch(t))) != 0` and `3 × votes >= 2 × total` (both sides saturating;
`powit::two_thirds`): over the 64 heaviest keys under V1, over every key under
Hardening2 (`total_weight_h2`). The rest of the rule is unchanged: the
highest such target becomes the justified checkpoint, and a target exactly
one interval above the justified checkpoint finalizes it.

Inactivity decay at an epoch boundary (nothing finalized for
`leak_after_epochs` epochs) applies to every member of `W(e)` whose
attestations were not included in epoch `e`, so from the activation to every
share key with weight. From the activation the boundary also drops the decay
entry of every key that has no share work left in the kept epochs
(`epoch_work` keeps `window + 2` epochs): such a key is a member of no set the
state can compute, and `decay` stays bounded by the keys of `epoch_work`
instead of every key a stall ever touched.

Why (finding 4): with W capped at the 64 heaviest keys and two thirds
measured over them, a minority split over many keys owned W. With 200 honest
keys of 0.35% of the share work (70%) and an attacker's 30% over 60 keys of
0.5%, W was the attacker's 60 keys and 4 honest ones: the attacker held 95.5%
of W and justified alone, and the honest 70% could not vote at all. From the
activation the threshold is two thirds of all the window weight, as Casper
FFG counts two thirds of all stake: the attacker (30%) cannot justify alone
and the honest keys (70%) justify without it (191 of the 200 votes, six
blocks of 32), which `finding4_a_split_minority_neither_justifies_alone_nor_stalls_from_hardening2`
runs with real signatures.

### Equivocation proofs

A proof (two attestations by one key, both signatures valid over their own
messages, forming a double vote — same target height, different targets —
or a surround vote) bars its key for `ban_epochs` epochs (one `banned` entry
per key, holding the epoch it expires at; a proof against a barred key is
invalid). From the activation a block of PoWit epoch `E` (after its epoch
step) may carry a proof only against a key that is a member of `W(x)` for
some `x` in `E-1 ..= E+1` (saturating at 0; `PowitState::evidence_epochs`,
`may_be_proven_h2`), checked before the two signatures; below it, against
any key. The three sets are exactly the ones the block's state can compute
(it keeps `window + 2` epochs of share work), they include the target epoch
of every vote the chain can still include (`vote_ttl <= epoch_len`), and a
key in one of them is a voter now, was one for the open votes, or is about
to be one: a key stays provable for the whole window after its last share
(as Ethereum keeps a validator slashable until it is withdrawable,
`is_slashable_validator`), and its proof may be about links of any age. A
proof against a key that holds no share work was valid before the activation
(finding 1); every node verified, stored and relayed it, and each barred an
unheld key in every later block's state.

### Producers

Every producer emits what the block that includes it accepts: the witness
duty (`powit::WitnessDuty::maybe_attest`) signs the message of its target's
height and is a member under the rules of the next block; from the
activation it votes for the justified checkpoint's direct child while a
block can still include that vote, else for the newest slot (below the
activation, always the newest slot). `gnb-cli powitattest` signs on the
schedule of the chain it names (`hardening2_activation_height_for_signer`).
The pool (gossip and the `submitpowititem` RPC, `powit::admit_item`) admits
an attestation by the rules of a block at `max(target, next height)` and a
proof by the next block's, and templates re-check every item with
`apply_at` and take a target's votes heaviest first (node-local). Tests:
`node/tests/fix_powit_hardening2.rs` (producers at the target heights H-1
and H, the evidence rule in the pool), `node/tests/fix_powit_hardening2_chain.rs`
(a chain crossing the activation through the miner's path; replay, restart
and reorgs in both directions give every node the same state for every
block).

### Safety and liveness from the activation

- **Accountable safety.** Two different checkpoints justified at one target
  height (one epoch, so one weight function on both sides when they share
  the history up to two epochs before it, which the two-epoch lag gives
  forks shallower than an epoch) need two quorums of two thirds of the same
  total: keys holding at least a third of ALL the window weight signed both
  and are provable while they hold weight. Before the activation the bound
  was a third of the 64 heaviest keys' weight, which finding 4 shows can be
  a small part of the share work. Surround votes across epochs give the bound
  up to the weight that entered or left between the two epochs' sets (one
  epoch of work out of the window, about 1/28 on mainnet, plus decay and
  bans), as for Gasper with a changing validator set.
- **Bounded verification.** A block still carries at most 32 attestations and
  4 proofs: at most 40 KES verifications per block, whatever the number of
  share keys. Membership and the evidence rule are checked before any
  signature; the pool keeps two pending votes per key and, full, evicts the
  entry closest to expiry, lightest first.
- **Liveness trade-off.** Every key with weight may vote, but at most 32
  votes fit in a block, and a vote for slot `t` is includable only in blocks
  `t ..= t + vote_ttl`: at most 32 × (vote_ttl + 1) votes per target (23,072
  on mainnet, 672 on testnet). Let `K` be the smallest number of keys,
  heaviest first, holding two thirds of the total. Justifying a slot takes
  `ceil(K / 32)` blocks of inclusion; finality keeps pace with the chain
  while that is at most one checkpoint interval (`K <= 1,920` on mainnet,
  160 on testnet), falls behind and becomes intermittent above it (the duty
  keeps voting for the justified checkpoint's child until that vote expires,
  then for the newest slot), and needs the inactivity leak above 32 ×
  (vote_ttl + 1): after `leak_after_epochs` epochs without finality every key
  whose votes were not included loses 1/16 of its weight per epoch, so the
  included voters regain two thirds (Gasper's inactivity leak). The 64-key
  cap made `K <= 64` always, at the cost of the safety bound above; the
  second hardening upgrade trades finality latency under extreme dispersion
  of the share work for a two-thirds-of-all-weight guarantee. An attacker
  with less than a third of the weight cannot stall finality (the honest keys
  justify without it, within the bound above), nor crowd honest votes out of
  honest templates (they take a target's heaviest votes first).

## Transaction signatures (sighash v2 and v3, hardening activation)

The audit found that the signature digest was whatever a serialization
library emitted and did not commit to the spent amounts or scripts (CRY-3,
WAL-1), that its cost was quadratic in the transaction size (MEM-5), that a
hybrid signature could be split into a valid ML-DSA-only signature (CRY-2),
and that witnesses were malleable (CRY-1). The fixes below change validity, so
the consensus parts take effect at the hardening activation height (mainnet
17,500; testnet and regtest 0). The rules live in
`crates/gnb-crypto/src/core/sighash.rs`; the node applies them through one
function, `mempool::admission::verify_input_scripts`, which block acceptance
and connect (`accept::validate_tx_inputs`), reorg connect, the template
self-check and mempool admission all call.

### Which height

A transaction rule compares the HEADER height `h` of the block that contains
the transaction (`Block::height`, which `accept_block` requires to equal the
largest parent DAG height + 1).

Everything that decides for a block not yet built — mempool admission,
post-connect eviction, reorg re-injection, the template self-check and the
wallets — uses ONE next-block height: the header height of the node's own
next template, i.e. the largest DAG height (`GhostdagData::height`) among the
template parents (`GhostDAG::template_parents` over the bodied tips whose
body passes the hardening block rules of its height,
`template::template_parents_and_height`) + 1
(`template::next_template_height`). The node keeps it in
`Mempool::next_height`, recomputed under the acceptance lock after every DAG
change (a connect, a stored fork-loser or merge candidate, a
disqualification), and reports it as `getdaginfo` `next_block_height`, which
wallets sign for (`tip_height` + 1 only from a node without that field).

- It is never the new tip's header height + 1. The header height of a tip
  that merged a parent with a greater DAG height than its selected parent
  exceeds its DAG height (DAG-8), while a child of that tip alone sits at its
  DAG height + 1.
- It can exceed the selected tip's DAG height + 1: a tip with less blue work
  but a greater DAG height is a template parent too (below the activation
  every bodied valid tip is; from it, every one within the mergeset and
  merge-depth bounds).
- A template skips, and never evicts, a transaction that fails only the
  height rules (the version rule and policy, and the 64-byte rule of "Block
  rules at the hardening activation": `admission::check_tx_for_next_block`)
  at the template's height while it passes them at the pool's next height
  (only possible while the cached height is stale).
- Mempool admission re-checks those height rules and coinbase maturity
  against the current next height when it inserts, under the acceptance
  lock, so a block connected while a transaction was being checked cannot let
  in a transaction that is invalid for the new next block.

### Version rule (consensus, non-coinbase transactions)

| | version 0, 1, 2 | version 3 | version ≥ 4 |
| --- | --- | --- | --- |
| `h` < activation | valid: sighash v2, lenient witness | valid: sighash v2, lenient witness (non-standard) | valid: sighash v2, lenient witness (non-standard) |
| `h` ≥ activation | invalid | valid: sighash v3, canonical witness | invalid |

(`core::sighash::check_tx_version`.) Below the activation the version is
ignored: every transaction, version 3 included, is verified exactly as before
the upgrade, with sighash v2 and the historical lenient witness rules. From
the activation only version 3 is valid, and it uses sighash v3, the canonical
witness and component-bound signatures. Coinbase transactions are not signed
and keep no version rule.

Rationale. Nodes that predate the upgrade ignore the version and accept a
non-coinbase version-3 transaction signed over the v2 digest. If upgraded
nodes refused it below the activation, anyone could split the network before
the flag day: submit such a transaction to a non-upgraded node, wait for a
non-upgraded miner to mine it, and upgraded nodes would disqualify that block
and its selected-chain descendants while old nodes extended it. So consensus
below the activation stays exactly the old rule, and version ≥ 3 below the
activation is refused only by relay POLICY
(`core::sighash::check_tx_version_standard`, error strings starting with
`non-standard-version`): upgraded nodes never admit, relay or mine one, and
wallets write version 1 there. Consequences:

- A version-3 transaction signed over the v3 digest is invalid below the
  activation (its signatures are checked against the v2 digest), and one
  signed over the v2 digest is invalid from the activation. No transaction
  is valid under both regimes.
- A pooled transaction always passed the policy at the pool's next height,
  so the pool never holds a version-3 transaction verified under v2.
  Re-injection of a disconnected block's transactions at/after the
  activation re-verifies their input scripts (a version-3 transaction mined
  below it was checked under v2 only).
- The node's verified-signature cache is keyed by the chain id, the regime
  (sighash v2 or v3) and whether the activation is in force at the height,
  the wtxid and every spent output (value and script), so a cached "valid"
  never answers for another digest version, prevout set or height regime.

`node/tests/fix_signatures.rs`
(`never_activated_regime_reproduces_the_old_verdicts`,
`pre_activation_version_3_with_the_v2_digest_is_valid_but_non_standard`)
proves the pre-activation verdicts unchanged.

Consensus error strings for this rule start with `bad-txns-version`.

### Sighash v2 (historical; unchanged)

```text
preimage = "GNB-SIGHASH-v1\0\0" (16 bytes) ‖ 0x01 ‖ chain_id u32 LE ‖ body
body     = bincode-2 "standard" encoding of the transaction in which the
           signed input's script_sig is "GNB_SIGHASH" (11 bytes) and every
           other input's script_sig is empty
sighash  = SHA3-256(preimage)
```

The bincode-2 standard encoding, spelled out so the digest no longer depends
on the library:

```text
Transaction = varint(version) ‖ varint(n_inputs) ‖ TxInput* ‖ varint(n_outputs) ‖ TxOutput* ‖ varint(locktime)
TxInput     = prev_txid (32 raw bytes) ‖ varint(prev_index) ‖ varint(len) ‖ script_sig ‖ varint(sequence)
TxOutput    = varint(value) ‖ varint(len) ‖ script_pubkey
varint(v)   = v                     if v ≤ 250
            = 0xFB ‖ u16 LE(v)      if v ≤ 0xFFFF
            = 0xFC ‖ u32 LE(v)      if v ≤ 0xFFFF_FFFF
            = 0xFD ‖ u64 LE(v)      otherwise
```

An out-of-range input index puts the marker nowhere (historical; no signature
is ever made for one). The cost is O(size) per input, O(size²) per
transaction, bounded by the size limits; v2 is invalid from the activation.
Chain ids: mainnet `0x474E0001`, testnet `0x474E0002`.

### Sighash v3

```text
list_hash(tag, count, items) = SHA3-256( u8 len(tag) ‖ tag ‖ u32 LE count ‖ items )

hash_prevouts  = list_hash("GNB-SIGHASH-v3/prevouts",  n_in,  for each input:  prev_txid (32) ‖ prev_index u32 LE)
hash_sequences = list_hash("GNB-SIGHASH-v3/sequences", n_in,  for each input:  sequence u32 LE)
hash_amounts   = list_hash("GNB-SIGHASH-v3/amounts",   n_in,  for each input:  spent value u64 LE)
hash_scripts   = list_hash("GNB-SIGHASH-v3/scripts",   n_in,  for each input:  u32 LE len ‖ spent script_pubkey)
hash_outputs   = list_hash("GNB-SIGHASH-v3/outputs",   n_out, for each output: value u64 LE ‖ u32 LE len ‖ script_pubkey)

preimage (195 bytes) =
      "GNB-SIGHASH-v3\0\0" (16) ‖ 0x03 (1) ‖ chain_id u32 LE (4)
    ‖ version u32 LE (4) ‖ locktime u32 LE (4)
    ‖ hash_prevouts ‖ hash_sequences ‖ hash_amounts ‖ hash_scripts ‖ hash_outputs  (5 × 32)
    ‖ input_index u32 LE (4) ‖ suite_id u16 LE (2)
sighash_v3 = SHA3-256(preimage)
```

- The "spent" value and script of input i are those of the output it spends
  (from the UTXO set, or from an earlier transaction of the same block).
- `input_index` must be below `n_in`; otherwise there is no digest and the
  input is invalid. A wrong number of spent outputs is likewise an error.
- `suite_id` is the suite in the signature's envelope.
- The five list hashes are computed once per transaction, so signing or
  verifying all inputs hashes O(size) bytes.
- The digest commits to every spent amount and script: a wallet told a wrong
  value or script signs a transaction every node rejects (WAL-1).
- The witness (`script_sig`) is not committed, as before.

### Signature binding

Sighash v2 signatures (legacy binding): every component signs the 32-byte
digest verbatim (`crypto::verify`, unchanged).

Sighash v3 signatures (bound): component `c` of a suite-`s` signature signs

```text
"GNB-TXSIG-v3" (12) ‖ s u16 LE ‖ c (1) ‖ sighash_v3 (32)          (47 bytes)
c = 0x01 for ML-DSA-65, 0x02 for Falcon-1024,
    0x03 for SLH-DSA-SHAKE-128s (suite 0x0003 only, "Conservative suite 0x0003")
```

Suite 0x0001 (hybrid) signature body: `mldsa_sig (3,309) ‖ falcon_sig`; both
components must verify, each over its own message. Suite 0x0002 body: the
3,309-byte ML-DSA-65 signature over its message. A key of one suite never
verifies a signature of another. Because the suite is in every component
message (and in the digest), stripping the Falcon half of a hybrid signature
and relabelling it 0x0002 never verifies (`crypto::verify_bound`).

### ML-DSA-65 verification

Every ML-DSA-65 component, at every height and under both sighash versions,
is verified by FIPS 204 ML-DSA.Verify with the empty context, including the
bound ‖z‖∞ < γ1 − β (also checked by `crypto::mldsa65_z_within_bound` before
the library) and UseHint as in Algorithm 40 (h = 1 with r0 ≤ 0, r0 = 0
included, gives (r1 − 1) mod 16). Nodes link PQClean's portable `clean`
implementation only (`pqcrypto-mldsa` without its `avx2` / `neon` features):
its AVX2 code, which those features select at run time on AVX2 CPUs, skips
the z bound and moves r1 up at r0 = 0, so nodes on different CPUs gave
different verdicts on crafted signatures, which needed no secret key under a
public key with t1 = 0 (docs/testing/SANITIZERS.md, F6). The Wycheproof
ML-DSA-65 vectors (`crates/gnb-crypto/tests/wycheproof_mldsa65.rs`) pin the
verdicts.

### Witnesses

`script_sig` = `[u32 LE sig_len][sig][u32 LE pk_len][pk]`, and the public key
must hash to the spent output: `SHA3-256(pk)[0..20] == script_pubkey`.

- Below the activation (sighash v2, every version; unchanged): bytes after
  `pk` are ignored; `sig` may lack the envelope (it is then read as hybrid)
  and its Falcon half may use the 1,280-byte zero-padded form.
- From the activation (version 3, sighash v3): the canonical witness is
  required. `script_sig` is exactly the framing above with no trailing bytes,
  and `sig` has its single canonical encoding
  (`crypto::is_canonical_signature_encoding`): the 4-byte envelope
  `B1 0C ‖ suite u16 LE` is present and names suite 0x0001 or 0x0002 (from
  the second hardening height also 0x0003, "Conservative suite 0x0003"); for
  0x0001 the Falcon half is the COMPACT encoding (header byte 0x3A, 40-byte
  nonce, exactly framed coefficients, zero padding bits, nothing after it, at
  most 1,462 bytes); for 0x0002 the body is exactly 3,309 bytes.
- The PUBLIC key is never required to carry an envelope: genesis carry-over
  addresses commit to the raw 3,745-byte hybrid key, which keeps verifying as
  suite 0x0001 (exact length decides; an enveloped key is 4 bytes longer).

The block-level witness commitment is specified separately.

### Suite 0x0002 (ML-DSA-65 only)

Consensus-valid at every height: outputs may already be locked to 0x0002 keys
(anyone could lock funds to such a key before this change), and making the
suite invalid would freeze them. It is non-standard: mempool admission refuses
every input whose key is not hybrid (`crypto::is_hybrid_public_key`), and
wallets never sign with such a key. A holder of a 0x0002 output needs a miner
to include the spend directly.

### Conservative suite 0x0003

Suite 0x0003 is SLH-DSA-SHAKE-128s AND Falcon-1024, an opt-in suite for
holders who want the two halves of a signature to rest on different
families of assumptions. SLH-DSA (NIST FIPS 205) is stateless and
hash-based: its security rests on SHAKE256 alone. Falcon-1024 rests on NTRU
lattices. A forgery therefore needs a break of a hash function AND of a
lattice problem. The everyday suite 0x0001 pairs two lattice schemes
(Module-LWE and NTRU). The suite is part of the second hardening
("Second hardening activation (hardening 2)"): mainnet not scheduled,
testnet and regtest from genesis.

Encodings, with the fixed-length component first like suite 0x0001 and no
raw (unenveloped) form (`crypto::SUITE_SLHDSA128S_FALCON1024`):

```text
pk  = B1 0C 03 00 ‖ slh_pk (32) ‖ falcon_pk (1,793)                    exactly 1,829 bytes
sig = B1 0C 03 00 ‖ slh_sig (7,856) ‖ falcon_sig (compact, ≤ 1,462)   at most 9,322 bytes
sk  = B1 0C 03 00 ‖ slh_sk (64) ‖ falcon_sk (2,305)                    2,373 bytes (wallet only)
```

`slh_pk` is `PK.seed ‖ PK.root` and `slh_sk` is `SK.seed ‖ SK.prf ‖ PK.seed ‖
PK.root` (FIPS 205, parameter set SLH-DSA-SHAKE-128s: n = 16, h = 63,
d = 7, h' = 9, a = 12, k = 14, lg w = 4, m = 30; category 1).

Which rule applies is decided by the header height `h` of the block that
contains the transaction (mempool and producers: the next block's height,
"Which height"), through ONE function, `core::sighash::suite_rules_at`
(`crypto::SuiteRules`), which the witness rule, the signature rule, the
policy-spend rule (`node::blockval`) and the assumed-valid path all call:

| Height | Suite 0x0003 |
| --- | --- |
| below the second hardening height | invalid everywhere, exactly the historical verdict: an unknown suite in a key-hash witness, and a policy listing such a key does not decode (`NotHybridKey`) |
| from it | valid in sighash-v3 transaction signatures: key-hash witnesses and spend-policy keys (up to 7 per policy, mixed freely with hybrid keys) |

At every height suite 0x0003 is refused by every other verifier: sighash v2
(which keeps the historical rules at every height; the second hardening
height is never below the first, so the suite never meets sighash v2),
`crypto::verify`, signed messages, disclosures, KES keys, PoWit shares and
attestations, and the P2P identity.

From the second hardening height a suite-0x0003 signature verifies under a
key (`crypto::verify_bound_under` with `SuiteRules::HARDENING2`) iff:

1. the key is exactly 1,829 bytes with the envelope `B1 0C 03 00`
   (`crypto::public_key_suite_under`), and the signature's envelope names
   the same suite;
2. the signature is canonical (`crypto::is_canonical_signature_encoding_under`):
   its body is longer than 7,856 bytes and the bytes after the first 7,856
   are a canonical COMPACT Falcon-1024 signature, the same rule as the Falcon
   half of suite 0x0001 ("Witnesses");
3. both components verify, each over its own bound message ("Signature
   binding") with `s` = 0x0003: the first 7,856 bytes by FIPS 205
   `slh_verify` (Algorithm 24, pure, with the EMPTY context, so the signed
   string is `M' = 00 ‖ 00 ‖ message`) under `slh_pk` with `c` = 0x03, and
   the rest by the canonical Falcon-1024 verification of suite 0x0001 under
   `falcon_pk` with `c` = 0x02.

The digest is sighash v3, which commits the suite id like for every suite.
A policy signature may be up to 10 KiB from the second hardening height
(8 KiB below it). The policy-witness wire cap (`MAX_POLICY_WITNESS_LEN`,
114,834 bytes) does not move: the largest valid witness, a 7-of-7 branch
witness with conservative keys, is about 78 kB. A suite-0x0003 key has one
encoding, so its PF-4 identity is the key itself and never equals the
identity of a hybrid key ("Spend-policy key identity (PF-4)").

SLH-DSA is implemented by the `fips205` crate (pure Rust, FIPS 205 final,
pinned exactly). It is validated against the NIST ACVP keyGen, sigGen and
sigVer vectors of the parameter set
(`crates/gnb-crypto/tests/acvp_slhdsa.rs`) and differentially against the
independent RustCrypto `slh-dsa` crate
(`crates/gnb-crypto/tests/slhdsa_differential.rs`). It is integer-only code, so
every platform gives the same verdict. Signing is hedged (16 fresh bytes of
`opt_rand`); the verdict does not depend on them.

Cost, measured in a release build on the reference machine
(`cargo test --release -p gnb-crypto --test conservative_suite_cost --
--ignored --nocapture`):

| | suite 0x0001 | suite 0x0003 |
| --- | --- | --- |
| public key | 3,749 bytes | 1,829 bytes |
| signature | at most 4,775 bytes | at most 9,322 bytes (about 9,130 typical) |
| verification | about 0.25 ms | about 1.8 to 2.0 ms (about 7×) |
| signing | about 9 ms | about 2 s |

Every suite-0x0003 signature carries at least 7,860 bytes, so a 1,000,000-byte
block holds at most 127 of them: about 0.25 s of signature verification in
the worst case. Every hybrid signature carries at least 3,313 bytes, so the
hybrid worst case is 301 signatures, about 0.08 s.

Relay policy: from the next block's second hardening height a suite-0x0003
key-hash witness (canonical signature, key of exactly that suite) and a
policy listing such keys are standard. Below it they are non-standard
(`WitnessRefusal::SuiteNotYetActive`, and for a policy the admission split
of `blockval::check_tx_chain_rules_with_conservative_suite`). The relay
answers `Ignore` without a penalty, since a peer one block ahead across the
height relays them honestly. The signature budget charges
`CONSERVATIVE_VERIFY_TOKENS` = 8 tokens for each suite-0x0003 signature
against 1 for any other (`mempool::relay::input_verification_tokens`), so a
peer cannot make the node verify conservative signatures at the hybrid
price (Bitcoin Core prices verification the same way: BIP342's validation
weight and the sigops cost).

Producers (`crypto::KeySuite`). Wallets and `gnb-cli` generate hybrid keys
by default, and conservative keys only on request (`gnb-cli newwallet` /
`restorewallet --suite conservative`, `wallet::generate_keypair_for_suite`).
A conservative key is the seed-phrase key derived from
`SHA3-256("GNB-SUITE-0003/keygen-v1" ‖ seed[..32])`, so one mnemonic gives
independent keys for the two suites. The hybrid key of a phrase is unchanged.

- Creating a conservative key, or a policy address listing one
  (`policyaddress`), is refused on a chain where the second hardening is not
  scheduled (mainnet today), since coins locked to it could never move.
  Where the height is scheduled, these offline commands print it.
- The paths that know the next block's height refuse to sign below it
  (`KeySuite::check_allowed_at`): a payment
  (`wallet::payment::check_signing_suite`: `send`, `WalletClient`) and a
  policy spend (`PolicySpend::target_height` /
  `check_suites_for_height`). A conservative key never signs a
  version-1 (sighash v2) spend.
- Fees are sized for the 9,322-byte signature
  (`crypto::max_signature_len_for_public_key_len`). The policy-spend files
  carry signatures of up to 10 KiB.
- The PQ-PSBT format (`docs/PQ-PSBT.md`), descriptors, the bridge vault and
  the browser wallet still carry hybrid keys only. Their independent
  references pin that, and extending them is a separate change.

### Relay policy (all heights)

Mempool admission (gossip, RPC; not reorg re-injection of already-mined
transactions) additionally requires, at every height, the canonical witness of
every input and a hybrid public key (from the next block's second hardening
height also a conservative suite-0x0003 key, "Conservative suite 0x0003"). Transactions are admitted only if valid
and standard for the next block's height (see "Which height"): below the
activation version ≥ 3 is non-standard, at/after it only version 3 is valid.
Whenever the next height moves (after every connect, and after a DAG change
that moves the template height without connecting), pooled transactions whose
version is invalid or non-standard at the new next height, or that the 64-byte
rule forbids there, are evicted (a version-1 transaction admitted for block
H-1 is mined in H-1 or evicted when the next block is H); the template
self-check applies the same rules at the template height. Relay policy is
never a block-validity verdict: a block below the activation that carries a
non-standard transaction (version ≥ 3 signed over sighash v2, a non-canonical
witness, a suite 0x0002 key) is valid. Nor is it a verdict on the peer that
relayed it: the gossip relay answers these refusals, and the next-height
rules above, `Ignore` without a penalty (`docs/MEMPOOL.md`, §2), since a peer
one block behind across the activation relays such a transaction honestly.
A non-canonical witness on a version-3 transaction for a block at/after the
activation is not policy but the consensus witness rule ("Witnesses"): no
upgraded node relays such a transaction (one block behind, version 3 is
non-standard), so admission treats it as consensus-invalid, like a bad
signature. Releases before the validating relay forward every transaction
frame without validating it, so the relay answers malformed or
consensus-invalid transaction frames with a penalty (`Reject`) only once the
node's next block height is above the activation height, i.e. once its chain
contains the activation block, which those releases reject; before that it
answers them `Ignore` (never forwarded). From then on every peer that follows
the chain validates transaction frames before forwarding them.

### Signers

Every signer (the `gnb-crypto` wallet API, `gnb-cli send`, `gnb-wallet send`,
`WalletClient::send`, the browser wallet core) learns the next block's height
from the node (`getdaginfo`: `next_block_height`, or `tip_height` + 1 from a
node without that field) and produces version 3 with
sighash v3 and bound signatures at/after the activation of its chain, and
version 1 with sighash v2 below it. Without the height they refuse to sign.
Below the activation, wallets still fetch the previous transactions to verify
claimed values; under v3 that is unnecessary. An input whose previous
transaction the node does not serve is signed on the claimed value only after
an explicit acknowledgement (wallet-local, every height below the
activation): the web wallet's checkbox, the `gnb-cli send` / `gnb-wallet
send` confirmation or `--allow-unverified-inputs`, and for the library path
`WalletClient::send_payment_with` with `SendOptions::allow_unverified_inputs`
(`WalletClient::send` and `send_payment` refuse such inputs before signing;
WAL-1 residual).

### Vectors

`reference/gnb_sighash.py` is the normative reference for both digests and the
component messages. `reference/sighash_vectors.json` holds its golden vectors:
many inputs, empty scripts, maximum field values, long scripts, every suite
id, both chain ids, the out-of-range and spent-count errors, and random
transactions, plus `version_rule` vectors: the consensus verdict
(`v2` / `v3` / `invalid`) and the relay-policy verdict (adding
`non-standard`) for versions 0, 1, 2, 3, 4 and 2³²−1 at heights around
activations 0, 100 and `NEVER`. `crates/gnb-crypto/tests/sighash_vectors.rs`
pins them, and CI regenerates the file and diffs it.

Whole-transaction and whole-block verdicts in both regimes (signatures,
witnesses, suites, versions, values, maturity, the block rules below) are
pinned by the data-driven vectors `reference/tx_vectors.json` and
`reference/block_vectors.json`; see `docs/testing/VECTORS.md`.

## Mining

The built-in miner (`gnb --mine --miner-address gnb1q…`) uses one 64 MiB
scratchpad per thread (`--mine-threads`, default all CPUs), mines on the
bodied tips, rebuilds its template every 64 nonces per thread, and aborts a
round as soon as a new tip arrives. External miners use `getblocktemplate`
(which returns the preimage fields, `bits`, `target` and `min_time`) and
`submitblock`. `getblocktemplate` also returns the rules of the template's
height: `hardening_active`, `merkle_rule` (`sha256d-duplicate-last` or
`gnb-tagged-v1`), `size_rule` (`bincode` or `wire`: the audit's regime;
`chain_size_rule` is this chain's, `wire` at every height),
`coinbase_script_sig_prefix` (the 80-byte coinbase commitment for exactly the
listed transactions in that order, empty before the activation),
`max_coinbase_extra_bytes`, `max_coinbase_script_pubkey_bytes`, and
`coinbase_merkle_branch` (the siblings from the coinbase leaf to the header
root under `merkle_rule`). Each transaction entry carries `txid`, `fee`,
`data` and `depends`: the 1-based positions of the earlier entries whose
outputs it spends (BIP22). The template mines unconfirmed chains parent
first (`docs/MEMPOOL.md`, §5), so a block built from a subset of the entries
must keep every dependency of every entry it keeps, in the listed order.

The listed transactions may fill the block up to `max_block_size` minus a
framing bound minus `coinbase_reserve` (1,000 bytes), so the WHOLE coinbase,
measured on the wire encoding (`chain_size_rule`), must fit in
`coinbase_reserve`.
`max_coinbase_extra_bytes` (the miner bytes allowed after the prefix) already
includes that bound: it is the largest number of extra bytes for which a
coinbase with one input and one output whose `script_pubkey` is at most
`max_coinbase_script_pubkey_bytes` (64) bytes, with every other field at its
widest encoding, fits in `coinbase_reserve`, capped by the 10,000-byte
`script_sig` limit (`template::external_coinbase_max_extra`). That is 794
bytes at/after the activation (80-byte prefix) and 874 bytes before it (no
prefix), both on the wire measure. A coinbase within both fields never
pushes a block built from the template over `max_block_size`.

## Block rules at the hardening activation

The 2026-10-14 audit found block-validity gaps that need a consensus change:
duplicate coinbase txids could overwrite a coin and make rollbacks diverge
(VAL-2), a block could spend its own coinbase (VAL-3), the Merkle tree had no
domain separation and no 64-byte rule (VAL-10), nothing committed to witness
bytes (CRY-1), the block-size limit used a different encoding than fees
(VAL-12), and the pow limit allowed blocks worth one evaluation (POW-3). The
rules below take effect at the same hardening activation height as the
GhostDAG rules (mainnet 17,500; testnet and regtest 0). The code is
`crates/gnb-crypto/src/core/block_rules.rs` and `validate_block_in_view` in
`node/src/accept.rs`. The executable reference is `reference/gnb_merkle.py`
(pow limit: `reference/gnb_difficulty.py`). The golden vectors in
`reference/merkle_vectors.json` and `reference/difficulty_vectors.json`
(section `hardening_pow_limit`) are checked by
`crates/gnb-crypto/tests/merkle_vectors.rs`,
`crates/gnb-crypto/tests/difficulty_vectors.rs` and
`reference/check_vectors.py`.

### Which height

These are block rules. They compare the block's HEADER height `B.height`,
which `accept_block` requires to equal `max(parent DAG heights) + 1` (see
"Difficulty input"), not `GhostdagData::height`. A rule applies to B iff

```text
B.height >= 1  and  B.height >= activation_height
```

The genesis block (height 0) is a constant checked by its hash and proof, and
it is never subject to these rules. (The transaction rules of "Transaction
signatures" use `h >= activation_height` without the `h >= 1` term; the two
predicates agree at every height >= 1, see "GhostDAG rules, ledger semantics
and the hardening activation", "Activation".) Mempool admission and eviction, block
templates and `getblocktemplate` use the height of the block being built: the
node's next template height (`template::next_template_height`, the largest
DAG height among the template parents + 1, the same height the transaction
rules use; see "Transaction signatures", "Which height"), which can exceed
the selected tip's DAG height + 1. Below the activation every rule in this
section is absent, and the old behaviour is reproduced bit for bit.
`node/tests/fix_block_rules.rs` runs each rule in both regimes.

### Hashes

```text
sha256d(m)          = SHA-256(SHA-256(m))
tagged_hash(tag, m) = SHA-256(SHA-256(tag) || SHA-256(tag) || m)      // BIP-340 construction
```

Tags are ASCII strings without a terminator:

| tag | SHA-256(tag) |
| --- | --- |
| `GnB/merkle/leaf` | `f5374e50a66ea5c3d4dd804b6b56ea72f76cc838936f6cf8fdf41de204cfbb39` |
| `GnB/merkle/node` | `d3a90495918b57c20ec960f8474e5273b173a4f60bb5f914eec9dcbe3b4df3ef` |
| `GnB/coinbase/parents` | `d8bddbf4dc09ba30778915646735c84bea68357e54cbd7a2755981cf08a9ebdd` |

`txid` is unchanged: `sha256d(to_wire_bytes(include_script_sig =
is_coinbase))`. It covers the `script_sig` only for a coinbase. Every
transaction also has a witness id, which covers every `script_sig`:

```text
wtxid(tx) = sha256d(to_wire_bytes(include_script_sig = true))
```

`to_wire_bytes` is the encoding documented on `Transaction::to_wire_bytes`
(version u32le, varint input count, inputs, varint output count, outputs,
locktime u32le).

### Header Merkle root (VAL-10)

From the activation, `header.merkle_root` is the tagged tree over the
transaction ids in block order. With shielded transactions present it is
combined as before (`gnb:block:body:v1`).

```text
root([])        = 32 zero bytes
level_0         = [ tagged_hash("GnB/merkle/leaf", txid_i) for each transaction i ]
level_{k+1}     = pair level_k left to right:
                    (l, r)      -> tagged_hash("GnB/merkle/node", l || r)
                    a last node without a partner is carried up UNCHANGED
root            = the single node left
```

A single transaction's root is its leaf hash (not its txid). Leaves and inner
nodes cannot be confused, and no node is ever paired with itself. So
`[.., x]` and `[.., x, x]` (CVE-2012-2459) have different roots, and a block
whose transaction list was mutated by duplicating a tail no longer matches its
header. Example: `root([0^32, 0^32]) =
1a90316515bd8a4deade0bb85be8daa5bcd23ccfa1274793622730e72d847326` (the
legacy root of the same list is `e2f61c3f…974e8cf9`).

Before the activation the root is Bitcoin's: `sha256d(l || r)` over the txids,
with the last node of an odd level paired with itself
(`Transaction::merkle_root`, unchanged). There the duplicate-transaction rule
is what rejects a mutated list.

### 64-byte transactions (VAL-10)

From the activation, a block containing a transaction whose txid preimage
(`to_wire_bytes(is_coinbase)`) is exactly 64 bytes is invalid. For a
non-coinbase transaction that is one input and one output with a 5-byte
`script_pubkey`. Mempool admission refuses such a transaction when the next
block is at or above the activation, the pool evicts it when its next height
reaches the activation, and templates at/after the activation evict it
(`admission::check_tx_for_next_block`, shared with the version rule). Wallet payments
use 20-byte scripts and can never have this size.

### Coinbase commitment (VAL-2 BIP34, CRY-1)

From the activation, the coinbase `script_sig` must start with exactly these
80 bytes, followed by 0 to 9,920 arbitrary miner bytes (the existing
10,000-byte `script_sig` cap):

```text
offset size field
 0      8   "GNB-CB01"                               (47 4e 42 2d 43 42 30 31)
 8      8   B.height, u64 little-endian              (the header height)
16     32   parents_commitment = tagged_hash("GnB/coinbase/parents",
                u32le(n_parents) || parent_0 || ... || parent_{n-1})   (header order)
48     32   witness_root = tagged Merkle root (as above) over
                [ 32 zero bytes, wtxid(tx_1), ..., wtxid(tx_n) ]       (block order;
                position 0 is the coinbase, which cannot commit to itself)
```

Each field is fixed-width, so there is exactly one valid encoding. Any other
tag, a height that differs from `B.height` (`bad-cb-height`), another parent
list or order, another witness root, or a shorter `script_sig` is invalid.
The coinbase still has exactly one output. The commitment sits inside the
coinbase `script_sig`, which the coinbase txid covers, so the block id covers
it: block id → `pow_preimage` → `merkle_root` → coinbase txid → `script_sig`.

**Witness commitment (CRY-1).** Non-coinbase txids exclude `script_sig`, so
before the activation a relay could pad or replace witnesses without changing
the block id. That changed the block's size and fee verdicts, and with the
persisted invalid-block marks it could get an honest block id disqualified.
From the activation every witness byte is committed. `accept_block` checks the
commitment after the height check and before the proof of work, before the
block is stored, and before any signature work. A copy whose witnesses were
altered in transit is therefore refused without being stored or marked
invalid, and the honest copy of the same id is still accepted. The witness
encoding itself is made canonical by the version-3 rule of the same
activation ("Transaction signatures", "Witnesses"): with both rules there is
exactly one valid block body per block id.

**Below the activation (node-local, all heights of the old rules).** On
this chain the block id commits to every witness from
`WITNESS_COMMITMENT_HEIGHT` (5,000) up to the activation too: the coinbase
`script_sig` ends with the `|wc:` suffix and the witness root
(`Block::validate_witness_commitment`, checked by `accept_block` before the
block is stored), so a connect failure of a block at a height >= 5,000 is
id-committed whatever rule failed (`accept::witnesses_fixed_at`). The
blocks below 5,000 stay malleable forever, so a node must not let a
mutated copy disqualify their ids. This is node policy, not a consensus
rule: it changes no verdict, only what a node remembers. A connect-time
failure of a block below both heights is classified by whether another body
with the same id could cure it (`accept::BlockInvalidity::witness_dependent`;
Bitcoin Core likewise caches every failure as `BLOCK_CONSENSUS` except a
detected malleation):

- witness-dependent (curable): a non-coinbase `script_sig` that does not
  parse, a public key that does not hash to the prevout's 20-byte
  `script_pubkey` (the key lives in the `script_sig`), a signature that does
  not verify (sighash v2: below the activation every transaction version is
  verified with it, under the lenient witness framing), a policy-spend rule
  (`blockval::check_policy_spends`: the policy witness's framing, the
  revealed policy's (or branch's) hash against the 33-byte policy output, a
  policy-tree branch before `powit_height()`, the revealed policy's
  absolute or relative timelock; the policy, its branch and so its
  timelocks are revealed by the `script_sig`; the hash is checked FIRST,
  before any field of the revealed policy is read, audit F1), and the size-based
  consensus minimum fee (measured on the wire size, `script_sig` included)
  when the fee reaches the floor below. Size limits measured with witnesses
  are context-free and checked before a block is stored, so they never
  reach this point;
- id-committed: everything else — missing or double-spent inputs, coinbase
  maturity, values and MoneyRange, coinbase value, shielded state, the
  transaction version rule (the txid covers the version, and the rule can
  fail only at/after the activation), BIP30 and the same-block coinbase
  spend, this chain's context-free transaction rules (locktime finality,
  the two output kinds, dust: `blockval::check_tx_context_free`, of the
  coinbase too) — and the failures no witness can cure (re-audit B1-T13): a
  fee below `min_tx_fee_sat(s)` with `s` the size of the transaction with
  every `script_sig` empty (one length byte each: the smallest any body
  with this txid can have; at least `MIN_TX_FEE_SAT`, so a transaction
  without inputs, whose fee is 0, is here too), and a spend of a coin whose
  `script_pubkey` is neither output kind (neither a 20-byte key hash nor a
  33-byte spend policy: no public key hashes to it and no policy witness
  is accepted for it).

The PoWit section (from `powit_height()`) is covered by the block id (the
v2 body root) and checked in context before the block is stored
(`powit::block_state`): a failure there is refused like a bad height, it
never reaches this classification.

The class is decided by the whole block: the connect validates in two passes
(`accept::validate_block_in_view_classified_at`, and the reference
`reference/gnb_validity.py` `connect_block`): first the id-committed checks
of every transaction in block order (same-block coinbase spend and maturity,
once every prevout is found this chain's context-free rules, inputs,
version rule, values, the fee floor, prevout output kinds), then the
coinbase value; then the witness checks of every transaction in block
order (the policy-spend rules, the revealed policy checked against the
spent output before its timelocks, the scripts, then the size-based minimum
fee). A block with a bad
signature in one transaction and an overspend in a later one is therefore
id-committed. The verdict is the one of any order (every rule must hold);
only the first failure reported, and so the error class of a block failing
several rules, follows this order. It also means no signature is checked
for a block that fails a cheap rule (Bitcoin Core's `ConnectBlock` likewise
runs `CheckTxInputs` for every transaction and leaves the scripts to its
check queue).

The failures that exist only at/after the activation (an invalid version, a
non-canonical witness, a sighash-v3 signature) are id-committed there like
every other failure. Relay-policy verdicts (`non-standard-version`, a
non-canonical witness or a suite 0x0002 key below the activation) are not
block-validity rules and never reach this classification.

A failure to READ the node's own UTXO view while a block is validated (an
I/O error, a corrupted or undecodable row, a coin row without its index
row, a policy coin with neither a tx-index row nor a genesis-ledger row when
the relative timelock of the policy it commits to needs its confirmation)
is neither: it is no verdict at all, at every height (re-audit B1-T12). No
block can cause one: every coin a transaction creates is written with its
tx-index row in one batch, a genesis-ledger coin is confirmed at the genesis
("Genesis ledger"), and only the policy the coin commits to is read (audit
F1: a made-up policy with `older != 0` spending a vesting tranche used to
ask for a confirmation that did not exist, so any block carrying that free
transaction could not be judged). The connect is abandoned before anything
of it is written and nothing is marked or persisted. A coinbase-height row
that cannot be read is never taken for "not a coinbase" (which skipped the
maturity rule). Bitcoin Core draws the same line: a coins-database read
error aborts the node (`CCoinsViewErrorCatcher`), it is never cached as an
invalid block.

A no-verdict is never a silent permanent stall, and never a way to stop a
node from outside (node-local, audit F1 and its review; no verdict
changes). Two classes are told apart (`reorg::ViewErrorKind`):

* a storage-engine failure (`Io`: a RocksDB read or write error, which
  includes the corruption RocksDB's checksums detect, or a missing column
  family), which no block can cause;
* an inconsistent chain state (`Inconsistent`: a row an invariant requires
  is absent, such as a coin without its tx-index row or a block without its
  DAG record, or a row that does not decode). This is a logic class: if any
  such miss ever became reachable from block data, one block could stop
  every node that receives it.

Either way the block keeps its body, is not marked, and is PARKED in
memory with its selected-chain descendants (`GhostDAG::park_no_verdict`,
like a block waiting for a body). The node resolves the best chain it can
judge from where its applied chain is, exactly as after an invalid block,
so a move that had committed its rollback chunks re-applies the old branch,
the parked branch is not selected, and templates are built on the tip the
node can judge. A parked block is retried on a bounded schedule (1 minute,
doubling up to 1 hour; `accept::unpark_due_no_verdicts`, the node's own
blocks included) and is shown by `getdaginfo` (`no_verdict`: class,
attempts, last reason, seconds to the next retry). The due blocks are
unparked right before an acceptance's resolution, after the arriving block
passed its acceptance checks (a frame refused for its height, bits or proof
of work unparks nothing) and after the selected tip was snapshotted (a retry
that moves the tip sends `TipChanged` like any move), all at once with one
re-derivation of the disqualified set; if that resolution fails before
judging them they are parked again, still due (review of PR #15, finding 1).
A copy received meanwhile is a known block (it is not processed or
downloaded again).

A stored BODY of a block to apply that cannot be read is attributed the
same way (review of PR #15, findings 4 and 6), whether the read is the
presence check before a move, the shielded staging or the connect itself:
a storage-engine error is that block's no-verdict (`Io`: parked, counted
toward the stop below); a body that does not decode is deleted and the
block, with its selected-chain descendants, waits for a copy from peers
like a block whose body is missing (`GhostDAG::mark_body_pending`; the
fetched copy goes through the body replacement of `accept_block`). A body
of a block to roll back that cannot be read is attributed to the first
block the same commit applies. Such a failure after committed chunks never
discards them: the move ends as a stopped move at its last committed chunk.

A parked branch is not a disqualified one (review of PR #15, finding 2): the
IBD latch counts a peer's tip on it as servable work (one failure during
sync does not report the node synced), and while it has more chain work
than the applied tip `getblocktemplate`, `getdaginfo` and `getnetworkinfo`
carry a warning in `warnings` (`accept::no_verdict_branch_warning`). The
node never stops for it.

Only storage-engine failures can stop the node: `accept::NO_VERDICT_ABORT_AFTER`
(3) of them in a row on one block, with no validation of it reaching a
verdict in between, stop it like Core's `AbortNode` / `FatalError`:
acceptance and templates refuse at once, the `gnb` process exits with an
operator message naming the block and the recovery (docs/RUNNING.md,
"Blocks without a verdict"), and a restart that meets a storage-engine
failure refuses to start, whatever the tips (a parked block makes the
applied tip the selected one). A chain-state rebuild (`rebuild_chain_state`)
during which a block has no verdict is not complete: its pending flag stays
set, it reports the failure, and it resumes from its applied tip at the
next start (review of PR #15, finding 3). An inconsistent chain state never stops the node: it is logged at
error level (at most one line a minute) and the block stays parked and
retried. Nothing is marked, so a failure that clears (a repaired disk or
index) leaves no trace beyond the record, which goes when the block is
validated.

The deepest rollbacks of a move, up to `reorg::MAX_BLOCKS_PER_COMMIT`
(16) blocks, are committed in ONE batch together with the first apply chunk
(`reorg::ReorgPlan::chunks_with_rollback_tail`; review of audit F1, finding
3, and of PR #15, finding 5): the first blocks of the new branch are
validated against that staged rollback before anything of it is written,
so a reorg up to 16 blocks deep is one commit. A first apply chunk that
fails for any reason (no verdict, a body that cannot be read, a failed
write) leaves the node on its old tip, never on the fork point, and a
pruned node never commits a rollback it could not undo (re-applying the old
branch needs its bodies). A deeper reorg commits its first rollbacks in
earlier chunks, each a consistent applied tip; if the new branch then
cannot be judged, the node re-applies the old branch from there, and if
those bodies were pruned the old branch waits for them from peers like any
best chain whose bodies are missing.

An id-committed failure disqualifies the block and its selected-chain
descendants and is persisted (`invalid_block/<id>`), as before. A
witness-dependent failure does not: the stored body is deleted (so it is no
longer served to peers), nothing is persisted, and the block, with its
selected-chain descendants, waits in memory for another body
(`GhostDAG::mark_body_pending`); the next-best chain is used meanwhile. Header
sync and `submitblock` treat such a block as not yet known
(`accept::is_known_block`). The message processor requests its body from a
peer at once through the missing-parent fetch tracker (a directed pull,
retried with backoff by the periodic sweep), and over block relay it takes
only the answer to such a pull: an unsolicited gossip copy of a block already
in the DAG is ignored before decoding and not relayed, also while a body of
it is wanted, because every copy taken re-validates the chain through the
block and a relay could otherwise make the node do that endlessly with
re-malleated bodies (see "Selected parent and fork choice"). Recovery
therefore depends on the directed pulls: a peer that answers with the same
rejected body again is refused cheaply (rejected-witness-root memo below) and
the pull is retried at the sweep's backoff. `accept_block` takes a copy of the
same id whose witness root differs from every body already rejected for it:
the copy passes the same acceptance checks as a new block, replaces the body,
and the chain is re-evaluated. A block in the DAG whose body is missing (for example after a
restart) is treated the same way.

Waiting is bounded by the best chain (re-audit B1-T13,
`GhostDAG::is_body_wanted`): the body of a waiting block is wanted — requested
from peers, chased by the sweep, and a copy processed — only while some
block on whose selected chain it lies (itself included, with no persisted
disqualification in between) orders above the selected tip under the tip
order (`blue_work`, then `blue_score`, then hash), or while an operator
override needs it (`accept::request_bodies`, and a body dropped during the
override's own move), until a body arrives. Once the honest chain is heavier
than the waiting branch its bodies are neither fetched nor taken (a copy is
known, like an unrequested block with less work than the tip in Bitcoin
Core); they are wanted again if the branch becomes heavier. A branch whose
selected chain misses the PoWit-finalized checkpoint
(`GhostDAG::set_finalized`, `conflicts_with_finality`) can never be
selected, so its bodies are never wanted, however heavy it is. A block whose
body no witness can fix is disqualified outright (above), so it never
waits. At/after the activation the witness
commitment fixes every byte of a stored body, so every connect-time failure is
id-committed and is persisted as before. `node/tests/fix_block_rules.rs`
(`witness_corrupted_*`) covers the corrupted-then-honest order, restarts, and
a corrupted fork-loser whose branch later becomes the heaviest.

**Uniqueness of coinbase txids (VAL-2).** The header height alone does NOT
make coinbases unique on GnB. The header height is `max(parent DAG heights) +
1`, and the DAG height follows the selected parent, so a block that merges a
long side branch can have a header height above its own DAG height. Its
selected-chain descendants then repeat lower and equal header heights (DAG-8,
`GhostdagData::height`). The commitment therefore also covers the parent list.
Within one selected chain every two applied blocks are ancestor and
descendant, and a block's parent set can never equal an ancestor's: the
ancestor would have to be its own ancestor. So every coinbase applied from
the activation on has a distinct `script_sig`, and therefore a distinct
txid. A coinbase applied before the activation could equal a later one only
if it committed to the hash of its own block or of one of that block's
descendants, which is a hash cycle. BIP30 below is the rule that guarantees
safety in any case.

### No overwrite of an unspent coin (VAL-2 BIP30)

(On this chain BIP30 and the rule of the next section apply at every
height, as they have since before the 2026-10-14 reset; the audit's text
below describes them from its activation.)

From the activation, a block is invalid if any output `(txid, i)` of any of
its transactions, the coinbase included, is an UNSPENT coin in the state of
its selected parent. This is checked against that state before any of the
block's transactions is applied, as in Bitcoin Core's `bad-txns-BIP30`. The
rule is part of `validate_block_in_view`, the one function behind extension,
reorg and re-validation.

**Undo (all heights).** A block applied before the activation can still
overwrite a coin. Its undo record now stores the replaced rows (the coin, its
coinbase-height row and its tx-index row), and rollback deletes the block's
own rows and then restores them. A node that applied and disconnected such a
block therefore ends with the same UTXO set as a node that never applied it.
This changes no validity verdict, so it applies at every height. Stored
encoding: the legacy record (bincode, standard config, six fields), byte
identical when nothing was replaced, followed by `"UDX1"` and
`bincode(UndoOverwrites)` only when something was. Records already on disk
decode unchanged.

### No spend of the same block's coinbase (VAL-3)

From the activation, the outputs of a block's coinbase are not spendable
within that block. They are not in the in-block prevout map, and an input
that names the coinbase txid is a coinbase-maturity violation. Before the
activation the old behaviour stays. The extension and reorg paths already
share `validate_block_in_view`, so they agree in both regimes. A block from
the activation that spends its own coinbase also cannot carry a valid coinbase
commitment: the commitment covers the spend's wtxid, which covers the coinbase
txid, which covers the commitment. Mempool admission and templates never
produce such a spend, because a coinbase can be referenced only after its
block is connected, and it is then immature.

### Coinbase maturity (re-audit B1-T14)

An output of the coinbase of block C may be spent by a transaction of block B
only if `depth(B, C) >= COINBASE_MATURITY` (100). Every output of the
coinbase counts, the witness-share outputs of a PoWit coinbase (from
`powit_height()`) as much as the miner's: the coinbase-height row is kept
per txid. C is always on B's selected chain: only selected-chain blocks are
applied, and the coinbase-height row of a coinbase exists exactly while its
block is applied.

- Below the activation (`B.height < activation`): `depth = B.height -
  C.height`, both HEADER heights (saturating at 0; the coinbase-height row
  stores `C.height`). This is the historical rule, kept exactly. A header
  height is `max(parent DAG heights) + 1`, so it is not a position on the
  selected chain: a B that merges a long, light side tip sits far above its
  selected-chain position, and B can then spend a coinbase with fewer than
  100 selected-chain confirmations (and, symmetrically, a coinbase whose own
  block merged such a tip stays immature longer).
- From the activation (`B.height >= activation`, the block-rule predicate):
  `depth = dag_height(B) - dag_height(C)` (saturating at 0), where
  `dag_height` is `GhostdagData::height` (selected parent's + 1). `dag_height(B)`
  is computed from B's parents' DAG records: the parent GhostDAG selects
  (greatest `(blue_work, blue_score, hash)`) plus one. `dag_height(C)` is the
  DAG record of the block the transaction index names for the coinbase txid.
  This is the number of selected-chain blocks from C's child to B inclusive,
  as Bitcoin Core's `nSpendHeight - coin.nHeight` counts active-chain blocks.

One function decides, `accept::check_coinbase_maturity_in_view`, for the
connect path (extension, reorg, start-up: `validate_block_in_view`), the fork
state check (`reorg::validate_fork_block_state`), mempool admission and the
post-connect revalidation, and the template self-check
(`admission::coinbase_maturity_for_next_block`). For a block not yet built
the regime is that of the node's next block height, and `dag_height(B)` is
the applied tip's DAG height + 1 (the template's selected parent is the
applied tip). A read failure of any of these rows is a storage error, never
"not a coinbase" (re-audit B1-T12).

**Timelocks.** A relative timelock (`older` of a spend policy,
docs/MULTISIG.md; `blockval::check_policy_spends_with_confirmations`)
counts the confirmations of the output it spends, the quantity maturity
counts, and the same measure decides it (`accept::MaturityRule`,
`accept::confirmations_in_view`): below the activation `B.height` minus the
header height the transaction index records for the spent output's
transaction (this chain's rule, kept exactly); from the activation
`dag_height(B)` minus the DAG height of the block the transaction index
names for it. A genesis-ledger output is confirmed at the genesis (header
and DAG height 0, "Genesis ledger"). An output created earlier in B itself
has 0 confirmations in both regimes; an output of an unconfirmed transaction
has none (a relative timelock on it is not met). The timelocks read are
those of the policy the spent output commits to: the revealed policy (or
branch) must hash to the output before any of its fields is read (audit
F1). The connect path, mempool admission and the
template self-check use it (`admission::confirmations_for_next_block` for
a block not yet built). Absolute heights are not depths: the locktime
finality rule (`locktime <= B.height`) and a policy's absolute timelock
(`after <= locktime`) compare with B's header height in both regimes, the
height every other height-gated rule (subsidy, activations, PoWit) reads,
and are unchanged. A coinbase output locked to a policy needs both its
maturity and its policy's timelocks.

Wallets: `getutxos` reports, for a coinbase output (witness-share outputs
included), a `coinbase_height` such that the wallets' unchanged comparison
`next_block_height - coinbase_height >= COINBASE_MATURITY`
(`next_block_height` from `getdaginfo`; `wallet::send::utxo_row_spendable_at`,
which the CLI and web wallets use to leave immature rows out) applies the
rule in force for the next block: below the activation the header height of
C; from it `next_block_height - depth(next block, C)`
(`admission::coinbase_height_for_wallets`). The CLI wallet and the WASM wallet
therefore need no change.

Vectors: `maturity/merge-header-depth-100-dag-depth-10/{pre,post}` (valid
below, immature from the activation) and
`maturity/inflated-coinbase-header-dag-depth-100/{pre,post}` (immature below,
valid from it) in `reference/tx_vectors.json`. A case's optional `dag_height`
is the evaluation block's DAG height and a prevout's optional
`coinbase_dag_height` the DAG height of the coinbase's block; when absent
they equal `height` and `coinbase_height` (a linear chain).

### Block size (VAL-12)

On this chain `MAX_BLOCK_SIZE = 1,000,000` bytes is compared with the
canonical wire encoding `Block::to_wire_bytes` at every height: from the
activation `Block::wire_size`, below it `block_rules::legacy_block_size`
(`Block::size_bytes`, "the bytes that are relayed and stored"), the same
length. That is the encoding transaction fee rates and the minimum fee use,
so witness bytes count as they do for fees. From `powit_height()` (10,000 on
mainnet) the encoding carries the PoWit section, and the section counts in
both measures (`wire_size` since main's 45c9c97, `size_bytes` since PoWit
itself). The audit's VAL-12 measured bincode below its activation; this
chain never did.

```text
size(B) = 4 + cs(n_parents) + 32*n_parents + 32 + 8 + 4 + 8      // version, parents, merkle_root, timestamp, bits, nonce
        + 8 + 8                                                  // blue_score, height: fixed-width u64 LE
        + cs(n_tx) + Σ tx.to_wire_bytes(true)                    // transactions, block order
        + cs(n_shielded) + Σ shielded                            // none is valid today
        + powit_section                                          // from powit_height(): PowitBody::write_wire
```

(`cs` the minimal CompactSize varint of "Wire encoding".) The measure does
not depend on the `blue_score` a copy carries (re-audit B1-T0 / B2-T8): the
block id does not commit to it (POW-8), and the node replaces the received
value with the one derived from the block's parents (`max(parent
blue_score) + 1`) before it stores, serves or relays the body. A measure
that read the received value could put one block id within the limit in the
copy gossip delivered and over it in the copy every upgraded node served (the
audit's bincode measure: a block of exactly 1,000,000 bytes mined with
`blue_score` 0 was accepted by the online network and refused by every node
that synced it later once blue scores pass 250, a 3-byte varint; a
permanent split). The wire header writes `blue_score` as a fixed-width u64,
so every copy measures the same, the same as with `blue_score` written as 0:
one verdict per block id. Main's nodes measure exactly this
(`Block::size_bytes`, PoWit section included), so the rule changes no
verdict of theirs: no block they accepted becomes invalid and none they
refused becomes valid. Heights are measured as carried: `accept_block`
requires `height = max(parent DAG heights) + 1`, so every accepted copy
carries the same value and the same PoWit section presence.

`accept_block` checks the size rule of the block's verified header height
(`block_rules::check_block_size_at`, the one size check of both regimes,
also called by `Block::validate_structure_without_pow_at`,
`check_block_hardened_at` and the template self-check), and every ingress
path checks it before (no proof of work is spent on a block that is too
large). Templates budget with the measure of their own height, the PoWit
section and the witness-share coinbase outputs on top of the transactions.
Vectors: `size/*` in `reference/block_vectors.json` (`wire_size` recorded
for every block); the `size/wire-exactly-1000000-blue-score-*/pre` and
`size/wire-1000001-bincode-below-blue-score-*/pre` cases are the same block
ids as `size/wire-exactly-1000000/pre` (valid) and
`size/wire-1000001-bincode-below/pre` (`block-size`) carrying `blue_score` 0
and `u64::MAX`, with the same verdicts (`node/tests/fix_wire_metadata.rs`
replays the finding end to end).

### Parent list (B2-T10, DAG-12)

`header.parents` is a list of 32-byte block ids, encoded as `varint(n) ‖ n ×
id` ("Wire encoding"). The rules, at every height unless stated:

- **Count**: `1 ≤ n ≤ MAX_PARENTS = 256` for every block but the genesis
  (which has none). A header with more than 256 parents does not decode.
- **Known**: every listed parent must be in the DAG; a block with an unknown
  parent waits as an orphan until it is (never accepted before).
- **Order**: free. The list as written is committed by the block id (it is
  part of `pow_preimage`) and, from the activation, by the coinbase parents
  commitment ("Coinbase commitment", which covers header order: a reordered
  list is another commitment). Nothing else depends on the order: the
  selected parent is the maximum of a total order (`(blue_work, blue_score,
  id)`), and the mergeset and the coloring depend only on the set of
  parents.
- **Repeated parent**: below the activation a parent may be listed more
  than once; the DAG treats the list as a set, so `[X, Y, X]` has exactly
  the GhostDAG data of `[X, Y]` (only the stored parent list differs). At and
  after the activation (`B.height`, the block-rule predicate of "Which
  height") a header that lists any id twice is invalid: `duplicate parent`
  (`block_rules::check_parents_distinct`, run by `check_hardened_body`, so by
  `Block::validate_structure` on every ingress path, by `accept_block`
  before the block is stored, and by the start-up recheck of blocks a
  pre-upgrade binary stored, which disqualifies such a block with its id).
  Why: a repeated parent is never useful (it changes no GhostDAG data), it
  only adds a second header (and block id) for the same DAG position and
  spends the parent budget, and Kaspa, whose post-activation rules GnB
  follows, rejects it; a second implementation following Kaspa would
  otherwise split from GnB on such a block. Every producer lists each parent
  once (`GhostDAG::select_parents_for_template` takes distinct tips; the
  template self-check runs the rule), on both sides of the boundary
  (`node/tests/fix_b2t10_parent_list.rs`).
- **Redundant parent** (a parent in the past of another listed parent): valid
  at every height. It is never the selected parent (its blue work is below
  that of the parent it is an ancestor of: blue work strictly grows along
  every parent edge) and adds nothing to the mergeset (it is already in that
  parent's past). It does count in the header height below. GnB does not
  forbid it, unlike Kaspa: the check needs a reachability query per pair of
  parents at header validation, a DAG-context rule rather than a
  context-free one, and no producer emits one (template parents are tips,
  which are never ancestors of each other). Forbidding it later would be a
  new activation.
- **Header height**: `B.height = 1 + max(p.height for p in parents)`, where
  `p.height` is the DAG height `GhostdagData::height` of the listed parent
  (the selected-parent chain length), over EVERY listed parent: a repeated
  parent does not change it; a redundant parent can raise it (a parent with
  a larger DAG height than the parent it is an ancestor of, which DAG-8
  allows), and with it the height-gated rules, the expected bits and the
  coinbase maturity of B.

Vectors: `reference/block_vectors.json` `parents/duplicate/*` and
`parents/duplicate-at-mainnet-height-*`; `reference/ghostdag_vectors.json`
`parents/duplicate` and `parents/redundant-ancestor` (the GhostDAG data of
both shapes and their header heights, `node/tests/ghostdag_vectors.rs`).

### Pow limit (POW-3)

From the activation, the pow limit that clamps the expected ASERT target, and
that `validate_pow` enforces before evaluating a proof, is the genesis
target:

```text
pow_limit_bits_at(h) = 0x1f0e9036 (GENESIS_BITS)   if h >= 1 and h >= activation
                       0x2100ffff (POW_LIMIT_BITS)  otherwise
```

Choice: Bitcoin's convention, the pow limit equals the genesis difficulty.
`POW_LIMIT_BITS` is the largest decodable target. One GnB-SMH evaluation
meets it with probability 65535/65536 (`work() = 1`), so a fork from any
parent that is far enough behind the ASERT schedule produces unlimited
near-free blocks (POW-3). The genesis target costs about 4,500 evaluations
(`work = 4500`). No code relies on a difficulty easier than genesis. The
genesis bits were calibrated to the launch hashrate, about 150 evaluations/s;
the miner, the templates and the validator all derive bits from the same
`expected_bits`; and the only ways to reach an easier target are a network
hashrate below the launch calibration or a chain behind schedule, which is
exactly the attack. Consequences: from the activation, block times stretch
in proportion if the network hashrate falls below about 150 evaluations/s.
A testnet with one 4-thread miner (about 8 evaluations/s) produces a block
roughly every 9 minutes. At the activation height itself the target steps
back to at most the genesis target if the chain was running easier.
`expected_bits_at(parent_time, height, activation)` is the real ASERT rule
for any activation height. The dev-only `test-pow-limit` feature pins every
target to `POW_LIMIT_BITS`. A node binary built with it refuses mainnet, and
an optimised (release-profile) one refuses every network
(`test_pow_limit_guard` in `node/src/main.rs`; the node's own feature does
not compile in a release build); only a debug test build runs, on
`--testnet`, for the functional tests (`docs/testing/FUNCTIONAL.md`).

### Blocks stored before the upgrade (node-local)

A node that ran a binary without these rules past the activation height may
hold blocks at header height >= the activation that the rules reject (a
legacy-format fork-loser, or a legacy chain it applied). An upgraded node
never stores such a block, so neither it nor any block referencing it can be
accepted elsewhere. At start-up, before the applied chain is reconnected,
`accept::recheck_stored_blocks_under_hardening` checks every stored block at
header height >= the activation (computed from the DAG; no body is read when
there is none) against the context-free rules above, once per activation
height (meta key `hardening_block_rules_checked`, u64 LE). The recheck runs
at the first start of a binary with these rules, before any block is accepted,
so every candidate was stored by a binary without them. A candidate whose body
is gone (a pre-upgrade binary pruned it, keeping its undo record) cannot be
read, and is disqualified conservatively, like an id-committed failure
(re-audit B2-T1): that binary checked the LEGACY header root against the body
before storing the block, so its id commits to a legacy root that no body
can match under the tagged rule, and no upgraded node ever accepted it. It
used to be counted as unchecked while the recheck still recorded itself as
done, so a pruned legacy block stayed valid and could become the best valid
tip once its unpruned descendants were disqualified (Bitcoin Core likewise
never trusts blocks connected without a newly activated deployment's checks:
`NeedsRedownload` requires them to be validated again). The recheck runs
again whenever the recorded activation height differs from the binary's (a
switch between builds with different activation heights), when the candidates
can include blocks this node accepted under the rules and pruned since. So
pruning writes, in the batch that deletes a body, a marker (CF_META key
`hardened_body/<hash>`) when that body passed every context-free rule above as
if active; these rules depend only on the block's own height, so the marker
holds for every activation at or below it. A body-less candidate with the
marker stays valid; one without it is disqualified as above. If the recheck itself
fails (a storage error), nothing is recorded and the node refuses to start,
so it never stores a block before the recheck has completed. A failure the
block id commits to (legacy or wrong header root, coinbase format, a 64-byte
transaction, the commitment's tag, height or parents, or any failure of a body
whose witness root matches) disqualifies the block and EVERY block that
descends from it through any parent edge, merged edges included
(`GhostDAG::mark_invalid_all_edges`); a block arriving later that references
one of them is disqualified on insertion. The roots are persisted with a reason
starting with `fails the hardening block rules`, which reloads them with the
same reach. The reconnect then rolls the applied chain back off a
disqualified branch (a disconnect-only plan), at any depth (there is no
reorg-depth limit, audit DAG-6; the rollback also works through pruned
bodies). `reconsiderblock` removes such a mark only if the stored body now
passes these rules. A block whose only failure is its witness root keeps its id:
its body is dropped and it waits for another copy, as above. The template
builder also skips any parent whose stored body fails these rules, through the
same function that gives the node's next block height
(`template::template_parents_and_height`), so the mempool, the wallets and
the template keep agreeing on that height.
`stored_blocks_failing_the_hardening_rules_are_disqualified_at_startup`
covers the scenario.

## Shielded pool (inactive)

No shielded transaction is valid today. The node compiles exactly one proof
verifier, `RejectAll`, and `accept_block` rejects every block that carries a
shielded transaction before it reaches the DAG. The rules below therefore
change no block's validity and need no activation height. Enabling a
verifier would be a separate consensus change with its own activation, and
it is guarded in code (see "Verifier guard").

### Spend statement v2 (audit COH-1)

Version 1 of the statement took the nullifier key `nk` as a free witness.
Anyone who knew a note's opening could spend it, and one note produced a
fresh nullifier for every `nk` (the audit spent one 1,000-value note 8 times).
Version 2 (`coherence_core::SPEND_STATEMENT_VERSION = 2`) binds spending
authority. `H(x)` is SHAKE-256 squeezed to 32 bytes, `‖` is concatenation,
the domain tags are ASCII without a terminator, and integers are unsigned
little-endian:

```text
sk   : 32-byte spending key (private witness)
ak   = H("gnb:coherence:ak:v2"  ‖ sk)
nk   = H("gnb:coherence:nk:v2"  ‖ sk)
pk_d = H("gnb:coherence:pkd:v2" ‖ ak ‖ nk)
cm   = H("gnb:coherence:cm:v1"  ‖ v as u64 ‖ pk_d ‖ rho ‖ psi)     (unchanged)
nf   = H("gnb:coherence:nf:v2"  ‖ nk ‖ cm ‖ position as u64)
```

The commitment tree is unchanged: depth 32, `parent = H("gnb:coherence:mt:v1"
‖ left ‖ right)`, the empty leaf is `H("gnb:coherence:mt:v1" ‖ "empty-leaf")`,
and a missing right child at height `d` is the empty subtree of height `d`.

`check_spend(public, witness)` accepts iff all of the following hold:

1. `|public.out_commitments| = |witness.outputs|` and
   `|public.nullifiers| = |witness.inputs|`.
2. No two inputs have the same position.
3. For each input `i`:
   - `position < 2^32`;
   - `cm_i` is a member under `public.anchor` with the witness path;
   - `pk_d(sk_i) = note_i.pk_d` (spending authority, otherwise `Unauthorized(i)`);
   - `public.nullifiers[i] = nf(nk(sk_i), cm_i, position_i)`.
4. `public.out_commitments[j] = cm(outputs[j])` for each output `j`.
5. `Σ inputs.v = Σ outputs.v + public.fee`, computed in u128 with no
   overflow.

SHAKE-256 is collision resistant, so a note's `pk_d` fixes `(ak, nk)`. Each
(note, position) therefore has exactly one nullifier, and only the holder of
`sk` can produce it. `(ak, nk)` is a viewing key: it recognises `pk_d` and
computes nullifiers, but the statement takes `sk`, so it cannot spend.

Golden vectors, pinned by `crates/coherence-core/tests/statement_v2.rs` and
reproduced independently with Python's `hashlib.shake_256`. The inputs are
`sk = 00 01 02 … 1f`, `v = 1000`, `rho = 0x11 × 32`, `psi = 0x22 × 32`,
`position = 5`:

| value | hex |
| --- | --- |
| `ak` | `1d64f855d802d8d73b185b6c3c8666fce5ed176d3d2e1b480fa5f8620d981223` |
| `nk` | `0004a2dfbb1a21b7ef2584349aa057e6980430a6bac9a0124159aa2f6ffa738d` |
| `pk_d` | `d9a13fe370b6169dd975132432296e614e31902be55d0c542b606c3aaa20b551` |
| `cm` | `ca6218f92e0f20ffb2e285a05af2e33efcc5f576e48989dd6cec2dd707a70a6f` |
| `nf` | `f7c0d16ea5c3034bbf561e57da5a31da7080309bb1a922072106af8a6abc51ce` |
| empty tree root | `91225423fd45e8d61ce70c068f075176eacdcebf5d0df94fdb80a1b4aa5d251a` |

### Verifier guard and committed public values

`node/src/coherence/verifier.rs` refuses any accepting verifier unless
`statement_binds_authority(SPEND_STATEMENT_VERSION)` holds, which is true for
version ≥ 2. A `const` assertion fails the build, `ShieldedVerifier::from_env`
panics at start-up when an accepting backend is selected, and `verify` and
`is_active` re-check the condition on every call. A proof's committed public
values must equal the bincode-v1 (`legacy`, fixed-width little-endian)
encoding of the pair `(SPEND_STATEMENT_VERSION, public)`:

```text
u32 version (= 2) ‖ anchor (32) ‖ u64 n ‖ nullifiers (32·n)
                  ‖ u64 m ‖ out_commitments (32·m) ‖ u64 fee
```

A proof from a guest built for another version, including a v1 guest that
committed only `SpendPublic`, never binds. No guest prover lives in this
repository.

### State (audit COH-2)

The shielded state is the commitment tree, the spent-nullifier set and the
window of the last 100 distinct tree roots that are accepted as anchors.
Applying a transaction validates it against the accumulated state (known
anchor, unseen nullifiers, no duplicate within the transaction, valid proof),
marks its nullifiers spent, appends its output commitments, and records the
new root as an anchor. A block is applied atomically: if any of its
transactions fails, the block is invalid in its own context.

Like the UTXO set, the state follows the applied selected chain only. A
block is applied when it joins the selected chain and disconnected when a
reorg removes it, in the same atomic RocksDB batch as its UTXO changes.
`ShieldedPool::stage_plan` moves the state and `StagedShielded::stage_into`
writes it. The batch carries the leaves, nullifiers, anchor window, a
per-block undo record (tree length, spent nullifiers and anchor window
before the block) and the shielded tip, laid out in column family `shielded`
(`node/src/coherence/persist.rs`). At start-up the node reloads the state
and refuses to run if a non-empty state's tip differs from the UTXO tip.
Applying a block costs O(outputs × 32 + nullifiers): the tree is incremental,
and nothing is cloned.

## Witness shares on SHA-256d (ObenBlock)

Under the SHA-256d proof-of-work scheme (`core::pow_scheme`, ObenBlock,
docs/DESIGN-obenblock.md §6) a witness share is an 80-byte SHA-256d header
(`core::witness_share::sha256d`; normative reference `reference/obb_shares.py`,
vectors `reference/obb_shares_vectors.json`). GnB's GnB-SMH shares, their wire
encoding and their id are unchanged.

```text
stream(B)      = wire(tx_0, with witness) | wire(tx_1) | …            64-byte chunks, last zero-padded
idx_k          = u64le(sha256d("OBB-WSHARE-v1/idx" | attested | sha256d(payout)
                               | job_nonce u64le | k u8)[0..8]) mod n_chunks    k = 0..7
job_commitment = sha256d("OBB-WSHARE-v1/job" | attested | witness | sha256d(payout)
                         | job_nonce u64le | chunk[idx_0] | … | chunk[idx_7])
share_header   = version u32le | attested | job_commitment | time u32le | bits u32le | nonce u32le
valid         <=> le256(sha256d(share_header)) <= min(target(bits) × 16, 2^256 - 1)
work           = floor(2^256 / (share_target + 1))
share_id       = sha256d("OBB-WSHARE-v1/id" | attested | witness | sha256d(payout) | bits u32le
                         | job_nonce u64le | version u32le | time u32le | nonce u32le)
```

The share's `nonce` field is `job_nonce`. Wire: GnB's encoding followed by
`version u32le | time u32le | nonce u32le`; a node decodes the trailing
fields exactly when it runs the SHA-256d scheme. A share is valid against
its attested block `B` iff, in this order: the payout is at most 128 bytes;
it carries the SHA-256d fields (a GnB-SMH share on this chain, or a SHA-256d
share on GnB, is `WrongScheme`); `attested` is `B`'s SHA-256d id; `bits`
equals `B`'s; `version` passes BIP 320 against the block version
(`0x20000000`); `time` equals `B`'s timestamp; the target is nonzero; the
header meets the share target. The window, slots, rewards and block rules
are GnB's ("Witness shares" in docs/DESIGN-witness-shares.md).

`time` is pinned to the attested block: a free `time` would give every job
2^32 more attempts, so one job (one set of eight chunks) would feed an ASIC
indefinitely and custody would no longer be checked per job. An ASIC still
rolls the nonce and the BIP 320 bits, 2^48 attempts per job.

Witness weight on ObenBlock is the share work above over a window of
`OBB_WINDOW_EPOCHS` = 112 epochs (28 days of 6-hour epochs;
`core::powit::obenblock_window`), with `ban_epochs` = 112 as well. The state
keeps `window + 2` epochs of share work and of links per key.
