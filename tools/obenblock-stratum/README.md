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
stratum; this server builds its jobs from the node's RPC header jobs
instead, so it runs next to any ObenBlock node and adds vardiff, PPLNS
accounting and metrics (the node's own built-in solo V1/V2 servers live on
branch `obenblock/stratum-node`, docs/STRATUM.md there).

## 1. ASICs and rental services

**Stock Stratum V1 firmware mines ObenBlock unmodified.** This covers stock
Antminer and Whatsminer firmware, cgminer/bmminer-style drivers, V1 proxies
and rental services such as MiningRigRentals (MRR) and NiceHash.

The reason is the header's Merkle root (docs/CONSENSUS.md "Header Merkle
root and body commitment (ObenBlock)", docs/OBENBLOCK-MINING.md §3.3):

- A Stratum V1 miner builds the root itself: it hashes
  `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2` with SHA-256d and folds the
  txid up the branch with **Bitcoin's SHA-256d tree**.
- ObenBlock's header root is exactly that tree (`merkle_root_rule`
  `bitcoin-sha256d`). The rest of the block body (witnesses, the shielded
  and PoWit sections) is committed inside the coinbase, in `coinb1`, so it
  never changes the branch.
- The header layout is Bitcoin's too (80 bytes; the parents commitment
  stands where Bitcoin has the previous block hash; BIP 320 version bits).

So the server sends plain Stratum V1 jobs (§5.1) built from the node's
`stratum` object, judges every share as the node judges the block, and
submits blocks with their extranonce. Older nodes whose header root was the
GnB body root (`gnb-body-v2`) are refused at the first template.

**MiningRigRentals**: create a pool entry with
`stratum+tcp://<STRATUM_HOST>:3333`, the worker `<obb1 address>.<label>`
(or set `OBB_STRATUM_ANY_USER=on`, since MRR may rewrite usernames) and
password `x` (or `d=<difficulty>`). Set the starting difficulty to your
rig's hashrate (§3); vardiff takes over after the first shares. MRR's own
pool test connects, subscribes and authorizes like any V1 miner.

Not measured here: real ASICs or MRR rigs against this server. The
end-to-end test (§8) uses a regtest node, the CPU miner and a stock-firmware
style client written from the protocol alone.

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

### obenblock-cpu-miner

```text
obenblock-cpu-miner -o stratum+tcp://HOST:3333 -u <obb1 address>[.<worker>] [-p x] [-t THREADS] [--kernel K]
obenblock-cpu-miner --bench SECS [-t THREADS] [--kernel K]
```

It speaks plain Stratum V1 like ASIC firmware, so it also mines through any
other ObenBlock V1 server (the node's built-in one, a pool).

- **Threads**: all logical CPUs by default. Each thread owns an
  `extranonce2` lane (thread i takes i, i + T, i + 2T, …). The server's
  unique `extranonce1` keeps machines apart.
- **Hashing** (`src/hasher.rs`): per lane, the coinbase txid, Bitcoin's
  Merkle fold, the SHA-256 midstate and the first three rounds of the
  second block (end of the root, time, bits) are computed once. Per nonce:
  rounds 3..64 of the second block and the outer SHA-256 stopped after
  round 60 (the id's top 32 bits are final there); only a nonce whose top
  word is at or below the target's is checked in full.
- **Kernels**: the rounds are written once over N lanes and compiled per
  instruction set, chosen at run time: `avx512` (16 nonces at a time,
  AVX-512F/VL), `avx2` (8), `lanes4` (4, baseline x86-64) and `sha2` (the
  `sha2` crate per nonce, which uses the SHA-NI extensions when the CPU has
  them, detected at run time by `cpufeatures`; no build flag needed). At
  start every available kernel is measured for 0.2 s and the fastest is
  used; `--kernel` forces one.
- **Difficulty**: a self-benchmark at start, then a
  `mining.suggest_difficulty` of about one share per 10 s.
- **Submissions**: every hash that meets the easier of the share target and
  the block target, so no block is dropped below the share difficulty.
  After a block, the lane waits for the next job: more blocks on the same
  parents would only be siblings.
- **Connection**: reconnects every 5 s if it drops.

Measured (`--bench`, 2026-10-18, on a 32-vCPU Intel Xeon Cascade Lake
build host, no SHA-NI, load average about 1):

| Kernel | 1 thread | 32 threads (total) |
| --- | --- | --- |
| `sha2` (the previous miner's path) | 1.69 MH/s | 53.5 MH/s (1.67 per thread) |
| `avx2` | 6.34 MH/s | 205 MH/s (6.41 per thread) |
| `avx512` | 14.3 MH/s | 442 MH/s (13.8 per thread) |
| `lanes4` | 1.42 MH/s | |

The previous miner reported 1.5 to 1.7 MH/s for one thread on the same host.
CPUs with SHA-NI (AMD Zen, recent Intel) were not measured; run
`obenblock-cpu-miner --bench 10` there and the miner picks the fastest
kernel by itself.

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
  `[job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]`,
  field for field the header job's `stratum` object
  (docs/OBENBLOCK-MINING.md §4.1):
  - `prevhash` is the parents commitment (header bytes 4..36) in stratum's
    word-swapped form;
  - `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2` is the node's coinbase
    (`coinb1` ends with `/obb/`; the 8-byte extranonce closes the
    `script_sig`);
  - `merkle_branch` is Bitcoin's branch of the coinbase (hashing byte
    order, bottom-up);
  - `version`, `nbits`, `ntime` are big-endian hex, as Bitcoin pools send
    them.
- **`mining.submit [user, job_id, extranonce2, ntime, nonce, version_bits?]`**:
  - checked against the job: `extranonce2` of 4 bytes, the time window,
    duplicates, the share target, the block target;
  - the version bits apply inside the granted mask;
  - duplicates are keyed on the share's header id, so the same work under
    another job id or hex spelling is still error 22; only shares that met
    the share or block target are remembered;
  - after 256 refused submits in a row (stale shares excepted) the
    connection is closed.
- **Also handled**: `mining.extranonce.subscribe` and
  `mining.suggest_difficulty`. Difficulty hints (`suggest_difficulty`,
  `d=`, `minimum-difficulty`) apply only until the first credited share;
  after that vardiff owns the difficulty.
- **Error codes**:
  - 20 other
  - 21 stale or unknown job, or ntime out of the job's window
  - 22 duplicate
  - 23 low difficulty
  - 24 unauthorized
  - 25 not subscribed

### 5.2 The header a share hashes

```text
coinbase_txid = SHA-256d(coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2)
merkle_root   = cur = coinbase_txid; cur = SHA-256d(cur ‖ s) for s in merkle_branch   (bitcoin-sha256d)
header        = u32le(version) ‖ parents_commitment ‖ merkle_root ‖ u32le(ntime) ‖ u32le(nbits) ‖ u32le(nonce)
block_id      = SHA-256d(header);  a block  <=>  le256(block_id) <= target(nbits)
```

`reference/obb_job.py` is the executable reference (`stock_firmware_header`
builds the header from `mining.notify` alone). `src/validator.rs`
reproduces `reference/obb_job_vectors.json`. The `obenblock-root` extension
of earlier versions is gone (declined if a miner asks for it).

### 5.3 Jobs and blocks

- **Template**: the server asks the node for one header job with an all-zero
  extranonce. Every connection fills those 8 bytes with its own
  `extranonce1 ‖ extranonce2`.
- **Self-check**: each job is checked against itself before it is served.
  The node's header and root must equal the ones computed from `coinb1`,
  `coinb2` and `merkle_branch` with Bitcoin's math, the `stratum` object
  must encode the same job, and the node's block bytes must carry that
  header and the coinbase.
- **New jobs**:
  - on a new tip (clean: miners drop older work);
  - every `OBB_STRATUM_REFRESH_SECS` (fresh time and mempool);
  - when the job's `ntime` window ends: at the node's `next_bits_time`
    (the next stall-relief step, DESIGN-obenblock.md §5.1: a late block's
    bits ease every 60 s) or once `maxtime` has passed; not clean, since the
    old job's shares inside its window are still blocks. A job that arrives
    with its window already over (the node caches templates for 5 s) is not
    published, and the next poll asks again;
  - right after a block is found.
- **Share time**: inside the job's window `[mintime, maxtime]` (the header
  job's, one stall-relief step, at or after the parents, at most 600 s past
  the node's clock), and at most 570 s past the server's clock.
- **Blocks**: a share that meets the block target becomes a block. The
  server writes the share's extranonce, root, version, time and nonce into
  the job's block bytes and sends
  `submitblock [block, {"version", "time", "nonce", "extranonce"}]`
  (`extranonce` = `extranonce1 ‖ extranonce2`, docs/OBENBLOCK-MINING.md
  §3.4); the node writes the same fields, recomputes the root and judges
  the block like any other. The verdict is logged and counted.

## 6. Metrics

Prometheus text on `OBB_STRATUM_METRICS`. `GET /pplns` returns the PPLNS
credit as JSON (empty while accounting is off).

- **Connections**: `obb_stratum_workers_active`, `_workers_total`,
  `_workers_authorized`.
- **Shares**: `obb_stratum_shares_accepted_total`, `_rejected_total`,
  `_stale_total`, `_duplicate_total`, `_low_difficulty_total`.
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
- **Kernels** (`src/hasher.rs`): every kernel the CPU supports must report
  exactly the nonces whose id's top word is at or below a bound, against
  the node's `block_id`.
- **`tests/mock_node.rs`**: the real server and `obenblock-cpu-miner`
  against a mock node RPC. Submitted blocks must carry a header that meets
  its bits, and `submitblock`'s solution (with the extranonce) must match
  the block.
- **`tests/e2e_regtest.rs`** (`--ignored`): a real regtest node from a fresh
  data directory, the server, the CPU miner, then a stock-firmware-style
  device written in the test from the Stratum V1 protocol alone (Bitcoin
  coinbase and Merkle math, version rolling, a rolled `ntime`). The node
  must accept every block, its block count must grow by them and the
  coinbases must pay the address. It needs the node binary:

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
- shares are validated with the node's own `gnb-smh` functions and
  Bitcoin's Merkle math (ObenBlock's header root);
- vardiff has an idle escape for miners that honor a difficulty they
  cannot reach.

Removed:

- merged mining (`merged_*`, `mergedmining`, `btc_rpc`, `btc_block`);
- the transparent upstream/router path;
- the endianness fork gate, which was Bloch history (ObenBlock compares
  little-endian from genesis).
