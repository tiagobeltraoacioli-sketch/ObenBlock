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
`reference/obb_job_test.py`).

## 1. The header

```text
offset  size  field                 source in getblocktemplate (sha256d object)
     0     4  version, u32le        version (0x20000000) + BIP 320 bits in version_rolling_mask
     4    32  parents_commitment    parents_commitment (header byte order)
    36    32  merkle_root           computed by the job server (section 3)
    68     4  time, u32le           curtime, in [mintime, maxtime]
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
- **time**: at least `mintime` (the latest parent timestamp) and at most 600
  s ahead of the validating node's clock (`maxtime` is that bound on the
  answering node's clock). The coinbase does not commit to the time, so a
  miner may roll it.
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
| `bits`, `target` | compact bits (hex), target (big-endian hex) |
| `curtime`, `mintime`, `maxtime`, `noncerange` | time window, nonce range |
| `merkle_root_rule` | `gnb-body-v2` (ObenBlock) or `gnb-tagged-v1` |
| `shielded_root`, `powit_root` | inputs of the body root (section 3.3) |
| `extranonce_bytes` | 8 |
| `header_job` | `null`, or a job when one was requested (3.2) |

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
| `merkle_root`, `coinbase_txid`, `time` | of that block |
| `coinb1`, `coinb2`, `extranonce` | the coinbase wire bytes around the extranonce |

A job server that serves many devices calls it once and rolls the
extranonce itself (3.3), or calls it once per device. The answer is cached
for 5 s per parameter set (the `getblocktemplate` gate, L-8). One header
with version and time rolling holds 2^48 hashes per second of time, enough
for any single device, so one job per device per template is the normal
use.

### 3.3 The Merkle root

The header's root is this chain's body root, not Bitcoin's transaction tree:

```text
coinbase_txid = SHA-256d(coinb1 ‖ extranonce ‖ coinb2)
tx_root       = fold: cur = leaf(coinbase_txid); cur = node(cur, s) for s in coinbase_merkle_branch
                leaf(x) = tagged("GnB/merkle/leaf", x), node(l, r) = tagged("GnB/merkle/node", l ‖ r)
                tagged(t, m) = SHA-256(SHA-256(t) ‖ SHA-256(t) ‖ m)
merkle_root   = SHA3-256("gnb:block:body:v2" ‖ tx_root ‖ shielded_root ‖ powit_root)   (gnb-body-v2)
              = tx_root                                                              (gnb-tagged-v1)
```

`reference/obb_job.py` is the executable form.

### 3.4 `submitblock`

```text
submitblock ["<block hex>", {"version": <u32>, "time": <u32>, "nonce": <u32>}]
```

The optional second parameter writes a share's rolled fields into the
`block` of its job; without it the block is submitted as given (a pool that
patches the header itself, or any full block). The block then goes through
the normal acceptance path; nothing is trusted from the solution. All
three fields are required, and any other field is an error. Under GnB-SMH
the second parameter is ignored, as before.

## 4. Stratum notes

The node's own V1 and V2 servers (`--stratum`, `--stratum-v2`) implement
these notes: docs/STRATUM.md.

- **Stratum V2, standard channels (header-only mining)**: maps directly.
  `SetNewPrevHash.prev_hash` = `parents_commitment` (header byte order),
  `nBits` = `bits`, `min_ntime` = `mintime`; `NewMiningJob.version` =
  `version`, `version_rolling_allowed` = true, `merkle_root` = the job's
  root. The device rolls nonce, version bits and time; the pool submits
  with 3.4. Firmware that speaks SV2 (or any driver that takes an 80-byte
  header, as `getwork` did) mines ObenBlock unmodified.
- **Stratum V1 and SV2 extended channels**: the miner builds the Merkle
  root itself from `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2` with
  Bitcoin's SHA-256d tree. That is not this chain's root (3.3), so shares
  computed that way are never blocks here. V1-only firmware needs either a
  proxy that hands the device a fixed header (the proxy's own work, not
  stratum's), or a consensus change of the header root to Bitcoin's tree
  with the body roots committed in the coinbase. That change is an open
  point for the owner (package O3b report); nothing in this package
  depends on it.
- **Share difficulty**: pools set it as on Bitcoin; a share is a block when
  its id meets `target`.
- **Witness shares** (PoWit, §6 of the design) are a separate header and a
  separate package (O5).
