# obenblock-stratum

A Stratum V1 job server (solo pool) for ObenBlock's SHA-256d proof of work,
and `obenblock-cpu-miner`, a multi-threaded SHA-256d CPU miner that mines
through it.

- **Upstream**: the ObenBlock node's JSON-RPC: `getdaginfo` (tip poll),
  `getblocktemplate` header jobs and `submitblock`
  ([docs/OBENBLOCK-MINING.md](../../docs/OBENBLOCK-MINING.md)).
- **Downstream**: Stratum V1 over TCP, as SHA-256d ASIC firmware speaks it:
  version rolling, vardiff, `extranonce1`/`extranonce2`.
- **Solo pool**: every block pays one configured `obb1` address. No custody,
  no payouts. PPLNS accounting is available and off by default.

It is a port of the Bloch pool proxy (`bloch-pos/pool-proxy`). Merged mining
is removed (owner decision). The Bloch proxy forwarded the node's own
stratum; the ObenBlock node has none, so this server builds the jobs itself.

## 1. ASICs: read this first

**Unmodified Stratum V1 firmware cannot mine ObenBlock blocks under the
current consensus rules.** This covers stock Antminer and Whatsminer
firmware, NiceHash, MiningRigRentals and every other V1 rental service.

The reason is the header's Merkle root:

- A Stratum V1 miner builds the root itself. It takes
  `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2` and the branch, and folds
  them with **Bitcoin's SHA-256d tree**.
- ObenBlock's header root is the **body root**
  (docs/OBENBLOCK-MINING.md §3.3):
  - the tagged-SHA-256 transaction tree;
  - then `SHA3-256("gnb:block:body:v2" ‖ tx_root ‖ shielded_root ‖ powit_root)`.
- So the header a V1 ASIC hashes is never the header of an ObenBlock block.
  No choice of `coinb1`, `coinb2` or branch can fix that: the miner would
  have to hit a chosen SHA-256d output.

The ASIC hashes the right header layout (80 bytes, nonce, BIP 320 version
bits). Only the root inside it is wrong.

What the server does about it:

- It judges every share exactly as the node judges a block (ObenBlock root),
  so such work is rejected as low difficulty.
- It recognizes that work and counts it in
  `obb_stratum_shares_bitcoin_root_total`.
- It logs once per connection: "shares are valid work over Bitcoin's
  SHA-256d Merkle root".

Pointing rented hashrate at this server costs the rent and finds nothing. The
metric shows it within the first shares.

What works today:

- Miners that implement the `obenblock-root` stratum extension (§5.2), such
  as `obenblock-cpu-miner`.
- Stratum V2 standard channels (header-only mining, the pool sends the root)
  would map directly (docs/OBENBLOCK-MINING.md §4). This server does not
  implement SV2.

What would make stock V1 ASICs work is a consensus change, to be decided
before genesis:

- the header root becomes Bitcoin's SHA-256d transaction tree;
- the body roots move into a commitment inside the coinbase.

This is the open point recorded by package O3b. It is the owner's decision;
nothing in this tool depends on it. Once the node's `getblocktemplate`
reports such a root rule, this server needs one more `RootRule` (see
`src/validator.rs`). Its stratum side is already standard V1.

## 2. Quick start

Build. The tool is its own cargo workspace, and the node is built from the
repository root:

```text
cargo build --release --manifest-path tools/obenblock-stratum/Cargo.toml
cargo build --release -p gnb --bin gnb
```

Run a node with an RPC API key (at least 16 characters). `getblocktemplate`
and `submitblock` are privileged methods:

```text
gnb --chain obenblock --rpc-api-key-file /etc/obenblock/rpc.key ...
```

Run the server next to it:

```text
OBB_STRATUM_PAYOUT_ADDRESS=<obb1 address> \
OBB_STRATUM_RPC_API_KEY_FILE=/etc/obenblock/rpc.key \
tools/obenblock-stratum/target/release/obenblock-stratum
```

Mine with the CPUs of the same machine:

```text
obenblock-cpu-miner -o stratum+tcp://127.0.0.1:3333 -u <obb1 address>.server1
```

## 3. Miner settings

| Field | Value |
| --- | --- |
| URL | `stratum+tcp://<STRATUM_HOST>:3333` |
| Worker / user | an ObenBlock address of the network, optionally `.<worker>`: `obb1q…`, `obb1m…`, `obb1z…` (GnB `gnb1…` and Bloch `bloch1…` single-key aliases also parse) |
| Password | `x`, or `d=<difficulty>` for a starting share difficulty |
| Version rolling (AsicBoost) | supported: `mining.configure` grants the BIP 320 mask `1fffe000` intersected with the miner's |
| Difficulty | vardiff aims at one share per `OBB_STRATUM_SHARE_SECS` (10 s) |

Difficulty is Bitcoin's pool difficulty: difficulty 1 is the target of
`0x1d00ffff`, about 2^32 hashes. For one share per 10 s:

```text
difficulty ≈ hashrate (H/s) × 10 / 2^32
```

| Hashrate | Difficulty |
| --- | --- |
| 100 TH/s | 232,831 |
| 1 PH/s | 2,328,306 |

The username does not change who is paid: every block pays
`OBB_STRATUM_PAYOUT_ADDRESS`. The address in the username is checked (it
must be valid for the network) so a typo shows at once. Set
`OBB_STRATUM_ANY_USER=on` for a rental service that rewrites usernames.

Remember §1: an ASIC on stock V1 firmware produces no ObenBlock blocks.

### obenblock-cpu-miner

```text
obenblock-cpu-miner -o stratum+tcp://HOST:3333 -u <obb1 address>[.<worker>] [-p x] [-t THREADS]
```

- **Threads**: all logical CPUs by default. Each thread owns an
  `extranonce2` lane (thread i takes i, i + T, i + 2T, …). The server's
  unique `extranonce1` keeps machines apart.
- **Hashing**: per lane, the coinbase txid, the ObenBlock root
  (`obenblock-root` extension) and the SHA-256 midstate are computed once.
  Each nonce costs the second block and the outer SHA-256 only.
- **Difficulty**: a 0.5 s self-benchmark at start, then a
  `mining.suggest_difficulty` of about one share per 10 s.
- **Submissions**: every hash that meets the easier of the share target and
  the block target, so no block is dropped below the share difficulty.
  After a block, the lane waits for the next job: more blocks on the same
  parents would only be siblings.
- **Connection**: reconnects every 5 s if it drops.

What CPU mining yields: about 2^32 × difficulty hashes per block. Against an
ASIC-scale target, CPU hashrate finds blocks only after stall relief
(DESIGN-obenblock.md §5.1) has lowered the target, at one doubling per 30
minutes of lateness.

## 4. Configuration

Configuration comes from environment variables
(`deploy/stratum.env.example`). An unset variable keeps its default. A set
but invalid one stops the server at startup.

| Variable | Default | Meaning |
| --- | --- | --- |
| `OBB_STRATUM_PAYOUT_ADDRESS` | (required) | The address every block pays |
| `OBB_STRATUM_NETWORK` | `mainnet` | `mainnet` or `regtest` (regtest uses `obb1t…`/`obb1n…`/`tobb1z…` addresses) |
| `OBB_STRATUM_LISTEN` | `0.0.0.0:3333` | Stratum listen address |
| `OBB_STRATUM_METRICS` | `127.0.0.1:9333` | Prometheus endpoint (empty: off) |
| `OBB_STRATUM_RPC` | `127.0.0.1:18210` (regtest `:18211`) | Node RPC `host:port` |
| `OBB_STRATUM_RPC_API_KEY_FILE` | | File whose first line is the node's API key |
| `OBB_STRATUM_RPC_API_KEY` | | The key itself (prefer the file) |
| `OBB_STRATUM_DIFFICULTY` | `65536` | Starting share difficulty |
| `OBB_STRATUM_DIFFICULTY_MIN` / `_MAX` | `1` / `2^42` | Vardiff band |
| `OBB_STRATUM_SHARE_SECS` | `10` | Vardiff target seconds per share |
| `OBB_STRATUM_POLL_MS` | `500` | Tip poll interval |
| `OBB_STRATUM_REFRESH_SECS` | `30` | Fresh job (time, mempool) at least this often |
| `OBB_STRATUM_HANDSHAKE_SECS` | `15` | Time to subscribe and authorize |
| `OBB_STRATUM_IDLE_SECS` | `600` | A silent connection is closed |
| `OBB_STRATUM_ANY_USER` | `off` | Accept any username |
| `OBB_STRATUM_PPLNS_WINDOW` | `0` (off) | PPLNS window in shares (accounting only, `/pplns`) |
| `OBB_STRATUM_PPLNS_WINDOW_SECS` | `0` | PPLNS window in seconds |
| `OBB_STRATUM_MAX_WORKERS` | `4096` | Connection cap |
| `OBB_STRATUM_MAX_PER_IP` | `64` | Connections per source IP (a rental proxy or a farm behind NAT shares one IP) |
| `RUST_LOG` | `info` | Log level |

## 5. Protocol

### 5.1 Stratum V1

- **`mining.configure`** (BIP 310):
  - `version-rolling`: granted with the mask `1fffe000` intersected with the
    miner's mask;
  - `minimum-difficulty`: honored as the starting difficulty;
  - `obenblock-root`: granted (§5.2);
  - any other extension: declined (`false`).
- **`mining.subscribe`**: the result is
  `[[["mining.set_difficulty", en1], ["mining.notify", en1]], en1, 4]`.
  - `en1` is a 4-byte `extranonce1`, unique among live connections, so
    connections never search the same space.
  - It starts at a random point. Two servers paying one address still
    rarely overlap; give each server its own payout address to rule it out.
- **`mining.authorize [user, password]`**: user as in §3. Work starts with
  `mining.set_difficulty` and a clean `mining.notify`.
- **`mining.notify`**:
  `[job_id, prevhash, coinb1, coinb2, branch, version, nbits, ntime, clean_jobs]`.
  - `prevhash` is the parents commitment (header bytes 4..36) in stratum's
    word-swapped form.
  - `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2` is the node's coinbase.
  - `branch` is the tagged-tree branch (`coinbase_merkle_branch`).
- **`mining.submit [user, job_id, extranonce2, ntime, nonce, version_bits?]`**:
  - checked against the job: `extranonce2` of 4 bytes, the time window,
    duplicates, the share target, the block target;
  - the version bits apply inside the granted mask.
- **Also handled**: `mining.extranonce.subscribe` and
  `mining.suggest_difficulty`.
- **Error codes**:
  - 20 other
  - 21 stale or unknown job, or ntime out of the job's window
  - 22 duplicate
  - 23 low difficulty
  - 24 unauthorized
  - 25 not subscribed

### 5.2 The `obenblock-root` extension

A miner that sends `mining.configure [["obenblock-root"], {}]` and gets
`{"obenblock-root": true}` receives a tenth `mining.notify` element:

```json
{"merkle_root_rule": "gnb-body-v2", "shielded_root": "<hex>", "powit_root": "<hex>"}
```

With it, the miner computes the header root as the node does:

```text
coinbase_txid = SHA-256d(coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2)
tx_root       = cur = leaf(coinbase_txid); cur = node(cur, s) for s in branch
                leaf(x) = tagged("GnB/merkle/leaf", x), node(l, r) = tagged("GnB/merkle/node", l ‖ r)
                tagged(t, m) = SHA-256(SHA-256(t) ‖ SHA-256(t) ‖ m)
merkle_root   = SHA3-256("gnb:block:body:v2" ‖ tx_root ‖ shielded_root ‖ powit_root)   (gnb-body-v2)
              = tx_root                                                              (gnb-tagged-v1)
header        = u32le(version) ‖ parents_commitment ‖ merkle_root ‖ u32le(ntime) ‖ u32le(nbits) ‖ u32le(nonce)
```

`reference/obb_job.py` is the executable reference.
`src/validator.rs` reproduces `reference/obb_job_vectors.json`.

### 5.3 Jobs and blocks

- **Template**: the server asks the node for one header job with an all-zero
  extranonce. Every connection fills those 8 bytes with its own
  `extranonce1 ‖ extranonce2`.
- **Self-check**: each job is checked against itself before it is served.
  The node's header must equal the one computed from the job fields, and the
  node's block bytes must carry that header and the coinbase.
- **New jobs**:
  - on a new tip (clean: miners drop older work);
  - every `OBB_STRATUM_REFRESH_SECS` (fresh time and mempool);
  - when the stall-relief step changes (DESIGN-obenblock.md §5.1: a late
    block's bits ease every 60 s);
  - right after a block is found.
- **Share time**: inside the job's window:
  - not before the parents' time;
  - at most 570 s past the server's clock (the node allows 600 s);
  - in the job's stall-relief step, because the header's bits are those of
    that step.
- **Blocks**: a share that meets the block target becomes a block. The
  server writes the share's extranonce and root into the job's block bytes.
  It sends `submitblock [block, {"version", "time", "nonce"}]`. The node
  judges it like any block, and the verdict is logged and counted.

## 6. Metrics

Prometheus text on `OBB_STRATUM_METRICS`. `GET /pplns` returns the PPLNS
credit as JSON (empty while accounting is off).

- **Connections**: `obb_stratum_workers_active`, `_workers_total`,
  `_workers_authorized`.
- **Shares**: `obb_stratum_shares_accepted_total`, `_rejected_total`,
  `_stale_total`, `_duplicate_total`, `_low_difficulty_total`.
- **Bitcoin-root work** (§1): `obb_stratum_shares_bitcoin_root_total`.
- **Hashrate**: `obb_stratum_share_work_total`. Its rate times 2^32 is the
  hashrate in H/s.
- **Blocks**: `obb_stratum_blocks_found_total`, `_blocks_accepted_total`,
  `_blocks_rejected_total`.
- **Node and jobs**: `obb_stratum_rpc_failures_total`, `_templates_total`,
  `_template_height`, `_template_bits`, `_template_parent_count`.
- **PPLNS**: `obb_stratum_pplns_*`.
- **Traffic**: `obb_stratum_bytes_in_total`, `_bytes_out_total`.

## 7. Deployment

`deploy/` has systemd units and environment examples:

- `obenblock-stratum.service` and `stratum.env.example`: the server, next
  to a node.
- `obenblock-cpu-miner.service` and `cpu-miner.env.example`: the CPU miner.
  It runs at `Nice=19` with a low `CPUWeight`, so the node stays ahead.

Both units carry the repository's sandboxing set
(`deploy/test_deploy_files.py`).

Notes:

- **RPC**: the server needs only the node's RPC, normally on 127.0.0.1. Do
  not expose the node RPC to reach a remote stratum server; run one server
  per node instead.
- **Port**: open TCP 3333 to miners only (or to the world for rented
  hashrate).
- **No TLS**: Stratum V1 is plaintext, and nothing secret travels on it.
  The payout address is fixed server-side.
- **DNS**: Cloudflare's proxy does not carry raw TCP on port 3333 without
  Spectrum. A stratum hostname such as `<STRATUM_HOST>` must be a DNS-only
  (grey cloud) A record to the server's IP.
- **Three servers**: each server may run node + stratum + CPU miner, with
  the miner pointed at its local server. Give each server its own payout
  address, or accept a negligible chance of overlapping work (§5.1).

## 8. Tests

```text
cargo test --release --manifest-path tools/obenblock-stratum/Cargo.toml
```

- **Unit tests**: codec, vardiff, PPLNS, metrics, RPC client, addresses
  (the `obenblock` family of `reference/obb_address_vectors.json`), the job
  vectors, share validation, version rolling, the session state machine
  and the configuration.
- **`tests/mock_node.rs`**: the real server and `obenblock-cpu-miner`
  against a mock node RPC. Submitted blocks must carry a header that meets
  its bits.
- **`tests/e2e_regtest.rs`** (`--ignored`): a real regtest node from a fresh
  data directory, the server and the CPU miner. The node must accept every
  block, its tip must grow and the coinbases must pay the address. It needs
  the node binary:

```text
cargo build --release -p gnb --bin gnb
cargo test --release --manifest-path tools/obenblock-stratum/Cargo.toml --test e2e_regtest -- --ignored
```

`OBB_NODE_BIN` overrides the binary path.

## 9. From the Bloch proxy

Kept:

- the bounded line codec;
- vardiff with retarget grace and the low-share escape;
- the PPLNS ledger, now per account and off by default;
- the Prometheus endpoint;
- the RPC client;
- per-IP and global connection caps;
- the job store;
- the rehearsal miner, as `obenblock-cpu-miner`.

Changed:

- jobs come from `getblocktemplate` header jobs, not from a node stratum;
- the server assigns `extranonce1` values, which are disjoint by
  construction (the Bloch proxy could only detect collisions);
- shares are validated with the node's own `gnb-smh` functions and the
  ObenBlock root rule;
- vardiff has an idle escape for miners that honor a difficulty they
  cannot reach.

Removed:

- merged mining (`merged_*`, `mergedmining`, `btc_rpc`, `btc_block`);
- the transparent upstream/router path;
- the endianness fork gate, which was Bloch history (ObenBlock compares
  little-endian from genesis).
