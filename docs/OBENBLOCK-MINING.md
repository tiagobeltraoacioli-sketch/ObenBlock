# ObenBlock mining: SHA-256d, getblocktemplate and stratum

Status: implementation notes for package O3b (docs/DESIGN-obenblock.md §4,
§9 O3). Everything here applies only when the node runs the SHA-256d proof
of work scheme (`core::pow_scheme`, set at startup by the chain parameters).
A GnB node is unchanged: its built-in miner is GnB-SMH and
`getblocktemplate` has no `sha256d` object.

Code: `node/src/pow/mod.rs` (CPU search), `node/src/mining/sha256d.rs`
(pool interface), `node/src/template.rs` (block version, parent order).
Reference: `reference/obb_job.py`, vectors `reference/obb_job_vectors.json`
(produced by `node/tests/obb_sha256d_mining.rs`, recomputed by
`reference/obb_job_test.py`, including from the `mining.notify` fields
alone as stock firmware does). The header root is specified in
docs/CONSENSUS.md, "Header Merkle root and body commitment (ObenBlock)"
(`reference/obb_merkle.py`).

## 1. The header

```text
offset  size  field                 source in getblocktemplate (sha256d object)
     0     4  version, u32le        version (0x20000000) + BIP 320 bits in version_rolling_mask
     4    32  parents_commitment    parents_commitment (header byte order)
    36    32  merkle_root           Bitcoin's root, computed by the miner (section 3.3)
    68     4  time, u32le           curtime, in [mintime, maxtime] (section 3.5)
    72     4  bits, u32le           bits (hex, as Bitcoin's getblocktemplate)
    76     4  nonce, u32le          noncerange 00000000ffffffff
```

`block_id = SHA-256d(header)`, and the proof is valid when the id, read as
a 256-bit little-endian integer, is at most `target` (big-endian hex in
`target`). This is Bitcoin's header, byte for byte, with the parent list
commitment in place of the previous block hash. `previousblockhash` is the
same 32 bytes reversed, the order Bitcoin's `getblocktemplate` displays a
hash in: a pool that already reverses `previousblockhash` into header order
gets `parents_commitment`.

- **version**: the bits outside `0x1fffe000` must equal `0x20000000`.
  ASICs may roll the 16 bits of the mask (BIP 320; stratum's
  `mining.configure` `version-rolling.mask` = `1fffe000`).
- **time**: consensus requires at least the latest parent timestamp and at
  most 600 s ahead of the validating node's clock, and the time also
  selects the stall-relief step of `bits` (section 3.5). `[mintime,
  maxtime]` is the range in which a rolled time keeps the job's `bits`.
  The coinbase does not commit to the time, so a miner may roll it.
- **parents**: the template's `parents`, sorted ascending (the SHA-256d
  header rule). The full list travels in the block.

## 2. The built-in miner

`--mine --miner-address …` mines with the CPU: one SHA-256 midstate per
round, then the 32-bit nonce, 4,194,304 nonces per thread per round
(`pow::SHA256D_ROUND_ATTEMPTS`), a fresh template after each round or at
once on a new tip. It rolls neither version nor time; a new template
carries a new time. It is meant for regtest (pow limit `0x207fffff`, about
two hashes per block) and development. Mainnet starts at 1 EH/s
(§4.2), which only ASICs reach.

## 3. Pool interface

### 3.1 `getblocktemplate`

Everything a GnB template had stays (transactions, `depends`,
`coinbase_script_sig_prefix`, `coinbase_outputs`, `powit`,
`coinbase_merkle_branch`, size limits). Under SHA-256d, `pow` is `sha256d`,
`pow_log2_n` is `null`, and the `sha256d` object adds:

| Field | Meaning |
| --- | --- |
| `header_layout` | the six fields above |
| `version`, `version_rolling_mask` | block version, BIP 320 mask (hex) |
| `parents_commitment`, `previousblockhash` | header bytes 4..36; the same reversed |
| `bits`, `target` | compact bits (hex) and target (big-endian hex) of `curtime`: stall relief applied, the same value as the top-level `bits` and a header job's |
| `asert_bits` | the template's ASERT bits before stall relief (hex; the top-level `asert_bits` as hex) |
| `curtime`, `mintime`, `maxtime`, `noncerange` | the job time, the time window that keeps `bits` (3.5), nonce range |
| `relief_step`, `next_bits_time` | the stall-relief step of the window, the first time of the next step (`null` without stall relief) |
| `merkle_root_rule` | `bitcoin-sha256d` |
| `merkle_branch` | Bitcoin merkle branch of the coinbase (hex, hashing byte order); the same list as the top-level `coinbase_merkle_branch` |
| `extranonce_bytes` | 8 |
| `header_job` | `null`, or a job when one was requested (3.2) |

The top-level `merkle_rule` is `bitcoin-sha256d` too, and
`coinbase_script_sig_prefix` is the 80-byte coinbase commitment (its last
32 bytes are the body commitment, which also covers the template's PoWit
section, so a pool must carry `powit` into the block exactly as listed).

### 3.2 Header jobs

```text
getblocktemplate [{"header_job": {"coinbase_script_pubkey": "<hex>", "extranonce": "<16 hex>"}}]
```

The node builds a complete block: the template's transactions and PoWit
section, and a coinbase paying `coinbase_outputs` to the pool's script (a
20-byte key hash or a 33-byte spend policy; anything else is refused before
any hash is spent) with the `script_sig`
`coinbase_commitment ‖ "/obb/" ‖ extranonce`. Without `extranonce` the node
picks a random one. `header_job` returns:

| Field | Meaning |
| --- | --- |
| `header` | the 80-byte header, nonce 0, `time` = `curtime` |
| `block` | the full block (`submitblock` wire hex), nonce 0 |
| `merkle_root`, `coinbase_txid`, `time`, `bits` | of that block |
| `mintime`, `maxtime` | the time window of `bits` (3.5) |
| `coinb1`, `coinb2`, `extranonce` | the coinbase wire bytes around the extranonce |
| `merkle_branch` | the Bitcoin merkle branch of the coinbase |
| `stratum` | the parameters of a Stratum V1 `mining.notify` (section 4.1) |

The extranonce is the last 8 bytes of the coinbase `script_sig`, so
`coinb1` ends with `"/obb/"` and `coinb2` starts with the input's
`sequence`. A pool splits the 8 bytes into `extranonce1` (per connection,
`mining.subscribe`) and `extranonce2` (`extranonce2_size`, rolled by the
device), for example 4 + 4. The answer is cached for 5 s per parameter set
(the `getblocktemplate` gate, L-8). One job serves every device of a pool:
each device's extranonce gives it its own Merkle root.

### 3.3 The Merkle root

The header root is Bitcoin's transaction Merkle root (consensus,
docs/CONSENSUS.md "Header Merkle root and body commitment (ObenBlock)"),
which is what stratum firmware computes:

```text
coinbase_txid = SHA-256d(coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2)
merkle_root   = fold: cur = coinbase_txid; cur = SHA-256d(cur ‖ s) for s in merkle_branch
```

`coinb1 ‖ extranonce ‖ coinb2` is the coinbase's wire encoding (Bitcoin's
legacy transaction serialization, no segwit marker), and the coinbase txid
is SHA-256d of exactly those bytes. The rest of the block (witnesses, the
PoWit section) is committed by the coinbase commitment inside `coinb1`, so
it never changes the branch. `reference/obb_job.py` is the executable
form (`stock_firmware_header` builds the header from `mining.notify` alone).

### 3.4 `submitblock`

```text
submitblock ["<block hex>", {"version": <u32>, "time": <u32>, "nonce": <u32>[, "extranonce": "<16 hex>"]}]
```

The optional second parameter writes a share's rolled fields into the
`block` of its job: `version`, `time` and `nonce` into the header and, with
`extranonce` (`extranonce1 ‖ extranonce2`, 8 bytes), the last 8 bytes of the
coinbase `script_sig` (which must follow `"/obb/"`, as in every header job),
after which the node recomputes the header root. Without it the block is
submitted as given (a pool that patches the block itself, or any full
block). The block then goes through the normal acceptance path; nothing is
trusted from the solution. `version`, `time` and `nonce` are required, and
any other field is an error. Under GnB-SMH the second parameter is ignored,
as before.

### 3.5 Time rolling and stall relief

A block's `bits` depend on its own time (DESIGN-obenblock.md §5.1): with
`P` the latest parent timestamp, `step(t) = floor(max(0, t - P - 180) / 60)`,
and every step relaxes the target. `bits` must equal the expected value
exactly, so a share whose rolled time falls in another step than its job's
is not a block. Every job therefore carries the window of its step:

```text
k        = step(curtime)
mintime  = P                    if k = 0,   P + 180 + 60 k   otherwise
maxtime  = min(P + 180 + 60 (k + 1) - 1,  now + 600)
next_bits_time = P + 180 + 60 (k + 1)
```

Rules for a pool:

- never accept a share whose `ntime` is outside `[mintime, maxtime]`
  (stratum firmware rolls `ntime` forward from the job's; how far is
  firmware-specific, and a step is only 60 s, so the pool checks every
  share, and sends jobs with `ntime` = `curtime`);
- fetch a new template when its clock reaches `next_bits_time`: the next
  step has an easier target, and the old job's window has ended. Send it
  with `clean_jobs = false` (the old job's shares in its window are still
  valid blocks), unless the parents changed;
- with no block for long, steps repeat every 60 s: one job per minute.

## 4. Stratum notes

### 4.1 Stratum V1 (stock firmware)

A pool serves an unmodified Bitcoin ASIC with the header job's `stratum`
object:

| Stratum V1 | Source |
| --- | --- |
| `mining.subscribe` result `extranonce1`, `extranonce2_size` | the pool's split of `extranonce_size` (8): e.g. 4 bytes per connection + 4 |
| `mining.configure` `version-rolling.mask` | `version_rolling_mask` (`1fffe000`, BIP 320) |
| `mining.notify` `job_id` | the pool's |
| `prevhash` | `stratum.prevhash`: `parents_commitment` with each 4-byte word byte-reversed (stratum's encoding of the header's bytes 4..36) |
| `coinb1`, `coinb2` | `stratum.coinb1`, `stratum.coinb2` |
| `merkle_branch` | `stratum.merkle_branch` (hex, hashing byte order, bottom-up) |
| `version`, `nbits`, `ntime` | `stratum.version`, `stratum.nbits`, `stratum.ntime` (big-endian hex of the u32, as Bitcoin pools send them) |
| `clean_jobs` | true when the template's `parents` changed |
| `mining.set_difficulty` | the pool's share difficulty |
| `mining.submit` (`extranonce2`, `ntime`, `nonce`, version bits) | `submitblock [job.block, {"version": stratum.version | bits, "time": ntime, "nonce": nonce, "extranonce": extranonce1 ‖ extranonce2}]` when the share's id meets `target` |

`stratum.ntime_min` / `ntime_max` are the job's window (3.5). Shares below
`target` are the pool's business (share difficulty as on Bitcoin). The
device builds the header itself: `version ‖ prevhash (words swapped back) ‖
merkle_root (3.3) ‖ ntime ‖ nbits ‖ nonce`, all little-endian, exactly as
for Bitcoin. `node/tests/obb_sha256d_mining.rs`
(`stock_stratum_v1_miner_finds_a_block_the_node_accepts`) and
`reference/obb_job_test.py` simulate such a device end to end.

Pools that build their own coinbase instead of using `header_job`: the
coinbase `script_sig` is `coinbase_script_sig_prefix ‖ miner bytes` (at
most `max_coinbase_extra_bytes`), its outputs are `coinbase_outputs` with
the pool's script as the first one's, the transactions are the listed ones
in order, and the block carries the template's `powit` section; the branch
is `coinbase_merkle_branch`.

### 4.2 Other protocols

- **Stratum V2, standard channels (header-only mining)**: maps directly.
  `SetNewPrevHash.prev_hash` = `parents_commitment` (header byte order),
  `nBits` = `bits`, `min_ntime` = `mintime`; `NewMiningJob.version` =
  `version`, `version_rolling_allowed` = true, `merkle_root` = the job's
  root. The device rolls nonce, version bits and time; the pool submits
  with 3.4. Firmware that speaks SV2 (or any driver that takes an 80-byte
  header, as `getwork` did) mines ObenBlock unmodified.
- **SV2 extended channels**: the same coinbase prefix / suffix and merkle
  path as Stratum V1 (4.1); the root is Bitcoin's, so they map directly.
- **Stratum V1 server**: `tools/obenblock-stratum` (a solo-pool job server
  and `obenblock-cpu-miner`) serves stock Stratum V1 jobs straight from the
  header job's `stratum` object, rebuilds the coinbase per share and submits
  blocks with their extranonce; its README has the details.
- **Share difficulty**: pools set it as on Bitcoin; a share is a block when
  its id meets `target`.
- **Witness shares** (PoWit, §6 of the design) are a separate header and a
  separate package (O5). Their header puts the job commitment where a block
  header has `merkle_root`, so they need header-only mining (SV2 standard
  channels or a driver that takes an 80-byte header); stock Stratum V1
  firmware, which rebuilds that field from a coinbase, cannot mine them.
