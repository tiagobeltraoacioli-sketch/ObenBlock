# ObenBlock checkpoints anchored in Bloch

ObenBlock publishes one **anchor record** per epoch in Bloch: the first
PoWit-finalized checkpoint of the epoch (one every 6 hours). Once Bloch has
finalized the record, contradicting that checkpoint means attacking Bloch's
finality as well as ObenBlock's. A node started with `--bloch-rpc` reads the
newest record from its own Bloch node and uses it as a weak-subjectivity
checkpoint. This is the ObenBlock-to-Bloch half of the mutual anchoring
([DESIGN-obenblock.md](DESIGN-obenblock.md) §8, phase 1). The other half,
Bloch's checkpoints in ObenBlock transactions, is
[BLOCH-ANCHOR.md](BLOCH-ANCHOR.md).

Nothing here is a consensus rule on either chain. A node without
`--bloch-rpc` behaves exactly as before.

Status: the record format, the node side and the reference daemon are
implemented. The **Bloch registry** (the Bloch transaction and its state)
needs the Bloch code base and is not built yet. Its interface is specified
below: the registry must implement it as written, and the node and the daemon
are tested against it.

## The anchor record (version 1)

84 bytes; every integer is little-endian:

```text
record    = u32le(chain_id) ‖ u64le(slot) ‖ block_id ‖ u64le(finalized_at) ‖ w_digest
                 4               8           32            8                 32      = 84
w_digest  = SHA-256d("OBB-ANCHOR-v1/W" ‖ u32le(n) ‖ key_0 ‖ u128le(weight_0) ‖ … ‖ key_{n-1} ‖ u128le(weight_{n-1}))
            keys ascending, no duplicates
record_id = SHA-256d(record)
```

| Field | Meaning |
| --- | --- |
| `chain_id` | the chain (`0x4F420001` ObenBlock mainnet, `0x4F420002` regtest; GnB's `0x474E000x`) |
| `slot` | the checkpoint slot (PoWit `Checkpoint.height`) |
| `block_id` | the block the slot names on the finalized chain (`Checkpoint.hash`, the 32 bytes as the node stores them; RPC hex is of these bytes) |
| `finalized_at` | DAG height of the selected-chain block whose PoWit state first holds this checkpoint as finalized; always above `slot` |
| `w_digest` | the witness set that finalized it: (20-byte key id, weight) |

Which checkpoint and which witness set, exactly:

- **Epoch anchor.** For epoch `e` (`(slot - activation) / epoch_len`) the record is
  the lowest-slot checkpoint of `e` that the chain finalized. That is the
  epoch-boundary slot when finality reached it, and otherwise the next
  finalized one. An epoch in which nothing was finalized has no record. The
  activation checkpoint (final by definition) is never anchored.
- **Witness set.** A checkpoint is finalized by the block that justifies the
  next slot. That block's PoWit state `S` holds the checkpoint as `finalized`
  and the next one as `justified`. The set is
  `S.witness_set_in(epoch(S.justified), Regime::at(finalized_at))`, the
  electorate of the finalizing vote. `S` has just reset inactivity decay
  (finality advanced), so the weights are the undecayed window share work of
  the unbarred keys.
- **Fixed bytes.** A node builds records only from blocks at or below its
  pinned finalized checkpoint. The block that finalized a record can then no
  longer be reorganized away, so every node on the chain builds the same bytes.

Decoding is exact: the length is 84, `block_id` is not all zero, and
`finalized_at > slot`. The record has no version byte. A later format is a
new registry method (`obbanchor2_*`), never a reinterpretation.

Code: `crates/gnb-crypto/src/obb_anchor.rs` (format),
`node/src/anchoring.rs` (records, reader, pin). Reference:
`reference/obb_anchor.py`, vectors `reference/obb_anchor_vectors.json`
(`--check` regenerates and compares; `crates/gnb-crypto/tests/obb_anchor_vectors.rs`
checks the Rust code against them).

## The Bloch registry: required interface

**Publication** is a Bloch transaction to the registry whose payload is the
84-byte record. It can be sent from any Bloch account, at an ordinary
transaction fee. The registry keeps, per `(chain_id, slot)`:

1. **First record wins.** The first record included for a `(chain_id, slot)`
   is the anchor for that slot.
2. **Duplicates are no-ops.** A later record with the same bytes changes
   nothing. It may be refused or accepted.
3. **Conflicts are evidence.** A later record with other bytes for the same
   `(chain_id, slot)` is kept as a conflict and never replaces the anchor.
4. The registry checks only the decoding rules above. It cannot check
   ObenBlock's chain, and it does not try to.

**Reading** is JSON-RPC 2.0 over HTTP POST on the Bloch node's RPC URL. Every
answer reports only records in Bloch blocks that **Bloch has finalized**
(FFG). A record still in a non-final Bloch block is not reported.

| Method | Params | Result |
| --- | --- | --- |
| `obbanchor_latest` | `[chain_id]` | the entry with the highest slot, or `null` |
| `obbanchor_get` | `[chain_id, slot]` | the entry for that slot, or `null` |
| `obbanchor_list` | `[chain_id, from_slot, limit]` (limit ≤ 64) | entries with slot ≥ `from_slot`, ascending |
| `obbanchor_conflicts` | `[chain_id, slot]` | the conflicting records for that slot (entries, oldest first) |

An entry:

```json
{
  "record": "<168 hex characters: the 84-byte record>",
  "chain_id": 1329725441, "slot": 2220, "block_id": "<64 hex>",
  "finalized_at": 2345, "w_digest": "<64 hex>", "record_id": "<64 hex>",
  "bloch": { "height": 123456, "block": "<Bloch block id>", "tx": "<Bloch tx id>", "finalized": true }
}
```

`record` is authoritative. The convenience fields are optional, but a
reader refuses an entry whose fields disagree with its record.
`bloch.finalized` must be `true`. Errors use the JSON-RPC `error` object.

## Node side: `--bloch-rpc`

```text
obenblock --bloch-rpc http://127.0.0.1:<bloch rpc port> [--bloch-anchor-interval 300]
```

The URL is the operator's **own** Bloch node, which is the trust model of
the bridge signers ([SIDECHAIN-BLOCH.md](SIDECHAIN-BLOCH.md): each signer
reads from its own follower). Phase 2 replaces the trusted RPC with a Bloch
light client in the node.

Every `--bloch-anchor-interval` seconds, the node calls `obbanchor_latest`
with its chain id.

- **Moves forward only.** A newer slot replaces the held anchor and is
  persisted (`bloch_anchor/latest` in the node's database), so a restart with
  Bloch unreachable still enforces it. An older slot, or other bytes for the
  held slot, are refused and raise `registry_alarm`.
- **Weak-subjectivity anchor.** Call the anchor `A` at slot `s`, and the
  node's pinned finalized checkpoint `F`:
  - `F` at or above `s`: the node checks that its finalized chain names `A`
    at `s`. If it does, the status is `consistent`. If it does not, the
    status is **`conflict`**: an error is logged, nothing changes, and the
    operator decides, as for a conflicting finalization (package A2).
  - `A` known and `F` below `s`: if `A`'s selected chain passes through `F`,
    fork choice is pinned to `A` (`accept::set_finality_checkpoint`, the
    `setfinalitycheckpoint` path). The status is `pinned`, and from then on
    no chain that misses `A` is selected; the applied chain moves at once.
    If `A`'s chain does not pass through `F`, the status is `conflict` and
    nothing changes. The pin re-checks this under the acceptance lock, as
    the node's own finality may have advanced meanwhile.
  - `A` not known yet (initial sync, or a node fed a fork): the status is
    `pending`. If the selected chain already passed `s` with another block,
    its first block past `s` is disqualified (`invalidateblock`; reversible
    with `reconsiderblock`), and the node waits below `s` for `A`'s chain.
    A pin to an unknown block would leave no selectable tip, so the node
    never takes one.
- Once the status is `consistent` for an anchor it stays so (the pin only
  moves forward along the finalized chain), and later polls returning the
  same anchor skip the check.
- `getblochanchor` reports `source`, `anchor`, `status`
  (`none`/`consistent`/`pinned`/`pending`/`conflict`), `detail`,
  `last_poll`, `last_error` and `registry_alarm`.

## Building and publishing records

```text
getfinalityanchors [from_epoch, count]          node RPC (count <= 32, default 8)
scripts/obenblock-anchor.py --node-rpc URL[,URL] --state S --publisher P [--min-agree N]
```

`getfinalityanchors` returns the newest `count` records of the epochs from
`from_epoch`, ascending, with `epoch`, `finalizing_block`, `justified`,
`w_size` and `w_total`. It walks back from the pinned finalized block through
`finalized_at` links. That costs one PoWit state read per finalized
checkpoint plus one per record, at most 128 per call (about ten epochs).
`complete: false` says that older records exist beyond that budget. The call
goes through the heavy-read gate (one at a time, cached).

The daemon:

- checks every record itself (re-encoding, id, decoding rules, chain id);
- publishes, oldest first, the epochs that every answering node returned with
  identical bytes, after the last one it published;
- treats disagreeing nodes, or a record that changed after it was published,
  as an alarm (exit 3) and publishes nothing.

Publishers:

| `--publisher` | |
| --- | --- |
| `dry-run` | log only; no state written |
| `jsonl:PATH` | append each record as a JSON line (a spool to submit by hand until the registry exists) |
| `command:PATH` | run PATH with the record as JSON on stdin; exit 0 and `{"ref": …}` on the last stdout line means published |
| `bloch` | the registry transaction: **pending the Bloch registry** (exit 5) |

Exit codes: 0 done, 2 nodes unavailable, 3 alarm, 4 publisher failed,
5 publisher not available. Tests: `python3 scripts/test_obenblock_anchor.py`.

Deployment (`deploy/obenblock-anchor/`): a oneshot service and a timer
(every 10 minutes), run as the user `obb-anchor`, which is not the node's
user. Copy `anchor.env.example` to `/etc/obenblock/anchor.env` and install
the script as `/opt/obenblock/bin/obenblock-anchor.py`.
