# ObenBlock stratum: the node's built-in V1 and V2 servers

Status: implemented on branch `obenblock/stratum-node` (node/src/stratum,
node/src/stratum_v2). Ported from the built-in servers of the legacy Bloch
PoW node (genesis3-node `src/stratum`, `src/stratum_v2`, GIP-0003) to
ObenBlock's SHA-256d header (docs/DESIGN-obenblock.md §4,
docs/OBENBLOCK-MINING.md).

| Server | Flag | Default bind | Transport | Use |
| --- | --- | --- | --- | --- |
| Stratum V1 | `--stratum` | `0.0.0.0:3333` | plaintext JSON lines | stock Bitcoin ASIC firmware, MiningRigRentals, V1 proxies |
| Stratum V2 | `--stratum-v2` | `0.0.0.0:3334` | Noise NX, encrypted | SV2 firmware and SRI proxies, standard channels |

Both are off by default, run only on SHA-256d chains (ObenBlock mainnet and
regtest; a GnB node refuses to start with either flag), and mine **solo**:
every block found pays its whole coinbase (subsidy share and fees, after the
PoWit witness outputs) to the worker's address. There is no share accounting
and no payout logic; shares below the block target are acknowledged so a
miner sees its hashrate.

## 1. How a job is built

### 1.1 One template path

One work feed per node builds block templates with the same builder as
`getblocktemplate` (`template::build_block_template`, the same coinbase
reserve and the same refusal during initial block download) and publishes a
new template:

- on every tip change (the node's tip broadcast): clean jobs;
- every 60 s (mempool refresh): not clean when the parents are unchanged;
- at every stall-relief step (DESIGN-obenblock.md §5.1): once a block is
  late, the expected `bits` change every 60 s. A job keeps the bits it was
  built with, so the feed republishes as soon as the bits for the current
  time change, and every miner gets a job with the easier target within a
  second of the step. Each job carries its `ntime` window (`mintime` to
  `maxtime` of the header job: one relief step, at or after the parents,
  at most 600 s ahead); a share outside it is refused (V1 error 21 when the
  step changed, else 20; V2 `stale-share` / `invalid-time`).

Each session turns the template into its own job: exactly the RPC header job
(`getblocktemplate [{"header_job": {...}}]`, `mining::sha256d::header_job`)
for its payout script and extranonce. So for one template, script,
extranonce and time, the V1 notify, the V2 job, the RPC header job and the
block the node finally checks carry the same 80 bytes:

```text
u32le version ‖ parents_commitment ‖ merkle_root ‖ u32le time ‖ u32le bits ‖ u32le nonce
```

`node/tests/stratum_e2e.rs` checks this byte identity. Jobs are light: they
share the template and its coinbase commitment and Merkle branch (computed
once per work publication, and checked once against a full header job), and
hold only their own coinbase split and header fields, never a block. A share
is judged on its header (coinbase txid, branch, header hash); only a share
that meets the block target is rebuilt into its block, with two checks
before anything is submitted: the root derived from the extranonce equals
the block's own root, and the header hashed equals the block's serialized
header. Found blocks go to the
same hook as RPC `submitblock` (dedup, minimum chain work, structure, then
`accept_block` and gossip); the node's verdict is the answer to the miner.

### 1.2 Header fields

- `version`: `0x20000000`. Miners may roll the 16 bits of the BIP 320 mask
  `0x1fffe000` (V1 `mining.configure` version rolling, V2 by default).
- `parents_commitment`: in the previous-block slot (V1 sends it with each
  32-bit word byte-swapped, as Bitcoin pools do; V2 `SetNewPrevHash.prev_hash`
  carries the header bytes).
- `merkle_root`: Bitcoin's SHA-256d transaction tree over the wire txids
  (OBENBLOCK-MINING.md §3.3); the rest of the body (witnesses, shielded and
  PoWit sections) is committed in the coinbase's 80-byte commitment, which
  sits in `coinb1`.
- `time`: inside the job's window (1.1).
- `bits`: the job's.

### 1.3 V1 with stock firmware

`mining.notify` is the header job's `stratum` object field for field:
`prevhash` (`parents_commitment` with each 4-byte word byte-swapped, as
Bitcoin pools send the previous hash), `coinb1`, `coinb2`, the Bitcoin
`merkle_branch`, and `version` / `nbits` / `ntime` as big-endian hex. An
unmodified Bitcoin miner (Antminer, Whatsminer, Braiins OS, cgminer, every
rig rented on MiningRigRentals) builds the header exactly as for Bitcoin:
`coinbase = coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2`, the root is
`SHA-256d(coinbase)` folded with `SHA-256d(root ‖ s)` over the branch. The
server rebuilds the same coinbase for every share, so V1, V2,
`getblocktemplate` and the node's proof check see the same 80 bytes.

## 2. Running the servers

```bash
obenblock --chain obenblock \
  --stratum --stratum-addr 0.0.0.0:3333 --stratum-max-sessions 256 \
  --stratum-v2 --stratum-v2-addr 0.0.0.0:3334 \
  --stratum-v2-key /var/lib/obenblock/stratum-v2-authority.json \
  --stratum-payout obb1q…
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--stratum` | off | start the V1 server |
| `--stratum-addr` | `0.0.0.0:3333` | V1 bind address |
| `--stratum-max-sessions` | 256 | V1 session cap (1..=10,000) |
| `--stratum-max-sessions-per-ip` | 16 | V1 sessions from one IP address (raise it for a rental proxy or a farm behind NAT) |
| `--stratum-mode` | `solo` | only `solo` exists (kept for the legacy command line) |
| `--stratum-payout` | `--miner-address` | payout of workers that use a plain label instead of an address |
| `--stratum-v2` | off | start the V2 server |
| `--stratum-v2-addr` | `0.0.0.0:3334` | V2 bind address |
| `--stratum-v2-key` | `<data-dir>/stratum-v2-authority.json` | authority keypair file (created on first start, mode 0600) |
| `--stratum-v2-max-sessions` | 500 | V2 session cap |
| `--stratum-v2-max-sessions-per-ip` | 16 | V2 sessions from one IP address |

The node checks everything at start-up and refuses to start on a mistake:
a GnB-SMH chain, an unknown mode, a payout address of another chain or
network, a bad bind address, V1 and V2 on the same port. Templates follow
the node: none while it is in initial block download (the first job arrives
once it has synced) or while a chain move is incomplete.

### 2.1 Worker names and payout

The worker name (V1 `mining.authorize` username, V2 `user_identity`) is the
payout:

- an ObenBlock address of the node's network: `obb1q…` / `obb1m…` on
  mainnet, `obb1t…` / `obb1n…` on regtest, or the `gnb1…` / `bloch1…` form of
  the same key (DESIGN-obenblock.md §2). A `.label` suffix
  (`obb1q….rig7`) is a worker label;
- otherwise, a plain label (letters, digits, `_`, `-`, at most 24
  characters) pays the operator's `--stratum-payout` (else
  `--miner-address`); without one it is refused.

Anything else is refused (V1 error 24, V2 `unknown-user`), never paid to the
operator: an address of another chain or network (a Bitcoin address, a
regtest address on mainnet), a mistyped address, an over-long name. The V1
password is ignored.

## 3. Stratum V1 (port 3333)

ASIC or proxy configuration:

| Field | Value |
| --- | --- |
| URL | `stratum+tcp://<node-host>:3333` |
| Worker | `obb1q…` (optionally `obb1q….rig1`) |
| Password | anything (`x`) |

Supported methods: `mining.subscribe` (extranonce1 4 bytes, extranonce2 4
bytes), `mining.authorize`, `mining.configure` (`version-rolling` with mask
`1fffe000` intersected with the miner's; others are declined), `mining.submit` (with the BIP 310 sixth parameter, the rolled
version bits), `mining.suggest_difficulty`, `mining.extranonce.subscribe`,
`mining.ping`.

Share difficulty is per session (vardiff, about one share every 10 s, never
harder than a block; Bitcoin's difficulty unit, so `difficulty × 2^32` hashes
per share). Error codes: 20 other or block rejected by the node, 21 unknown
or stale job (also a time outside the job's stall-relief step), 22
duplicate, 23 low difficulty, 24 unauthorized, 25 not subscribed.

Vardiff starts at difficulty 1 (`OBB_STRATUM_START_DIFF`), or at the
miner's `mining.suggest_difficulty` or `d=<difficulty>` password if it sends
one before its first accepted share; after that, hints are acknowledged and
ignored. Without a share for 180 s the difficulty drops by 4 (to the floor,
`OBB_STRATUM_MIN_DIFF`) and the job is re-sent.

Limits per session:

- 8 KiB per line, 16 jobs kept, 30 s to authorize;
- an authorized session with no accepted share for 30 minutes is closed
  (`OBB_STRATUM_SHARE_IDLE_SECS`); at the session cap, a session without a
  share for 2 minutes may be evicted for a new connection;
- control requests (subscribe, authorize, configure, suggest, ping,
  unknown methods): 16, then one per 30 s, else the session is closed;
  `mining.authorize` may switch to a new worker at most 4 times (repeating
  the current worker is free and builds no job);
- 16 malformed or refused requests close the session; peer strings in the
  log are truncated to 64 bytes and escaped, and per-session warnings are
  rate-limited;
- submits: every share is hashed first, and a share that meets the block
  target is always submitted. Above 60 submits per minute other shares are
  refused (error 20) and the difficulty jumps to the observed rate (shares
  at the previous difficulty still count for 10 s); above 600 per minute
  the session is closed. Duplicates are keyed on the header id, so another
  hex spelling or job id is still error 22.

### 3.1 MiningRigRentals

MRR rigs are Bitcoin SHA-256 ASICs that speak Stratum V1. In MRR, add a pool
with host `stratum+tcp://<node-host>:3333` (or the ParallelismLinux proxy's
port, 4.1), worker `obb1q….mrr` and password `x`, then point a rental at it.
The rental mines unmodified (1.3); its blocks pay the address in the
worker name. The server's vardiff starts at difficulty 1 and jumps to the
rig's rate within seconds (capped at the network difficulty); `d=<diff>` in
the password sets the start. MRR connects from a few proxy addresses: raise
`--stratum-max-sessions-per-ip` and keep `--stratum-max-sessions` above the
number of rigs. MRR checks a pool with a short test connection
before a rental starts; it shows as a session that authorizes and closes.

## 4. Stratum V2 (port 3334)

Standard channels (header-only mining), the Mining Protocol only. The
authority key is created on first start; the node logs the pool URL:

```text
stratum_v2: pool URL stratum2+tcp://<host>:3334/9b…Ef (authority key file …/stratum-v2-authority.json)
```

- The key in the URL is the authority public key in SRI's key-utils form
  (Base58Check of `u16le(1) ‖ x-only key`); the key file also has it as
  `public_b58` and `public_hex`. Miners pin it: the Noise NX handshake
  proves the server holds the key (a certificate of the session key signed
  by it), so a miner cannot be redirected to another server.
- Keep the key file (back it up with the node's data directory): a new key
  changes the URL every miner configured.
- SetupConnection: protocol 0 (Mining), version 2. `REQUIRES_STANDARD_JOBS`
  and `REQUIRES_VERSION_ROLLING` are accepted; `REQUIRES_WORK_SELECTION` is
  refused. Version rolling is allowed (the success flags never set
  `REQUIRES_FIXED_VERSION`).
- OpenStandardMiningChannel: `user_identity` is the worker name of 2.1. The
  channel gets an 8-byte extranonce (all of the coinbase extranonce) and a
  share target for about one share every 10 s at its nominal hash rate,
  never harder than a block and never easier than its `max_target`.
  Extended channels are refused (`unsupported-extended-channels`).
- Jobs: `NewMiningJob` (future job, `merkle_root` = the channel's body
  root) followed by `SetNewPrevHash` (`prev_hash` = `parents_commitment`,
  `min_ntime` = the job time, `nbits` = the job bits), on every work update.
- SubmitSharesStandard: answered with SubmitShares.Success, or
  SubmitShares.Error with `invalid-channel-id`, `invalid-job-id`,
  `duplicate-share`, `invalid-version`, `invalid-time`, `stale-share` (the
  time left the job's stall-relief step), `difficulty-too-low`,
  `block-rejected` (the node refused the block), `rate-limited`.
- Limits: 8 channels per session and 2,048 across the server; a session
  that opens no channel within 10 s of SetupConnection, or has no accepted
  share for 30 minutes, is closed (and one idle for 2 minutes may be
  evicted at the cap); at most 64 connections in the Noise handshake at
  once (the handshake's secp256k1 work runs off the async runtime). Each
  channel may submit 120 shares per minute judged below the block target:
  a block share is never refused for rate, and an over-rate channel gets a
  harder target (SetTarget; the previous target still counts for 10 s).
  2,000 submits per minute, or 16 undecodable messages, close the session.

SV2 firmware (for example Braiins OS) and SRI's translator or job
declarator clients connect with the URL above. Messages, framing and the
handshake are SRI's own crates (`noise_sv2` 1.4.2, `binary_sv2` 5.0.1,
`mining_sv2` 8.0.0, `common_messages_sv2` 7.0.0: the constituents of the
`stratum-core` 0.2.1 umbrella the legacy node used), and the end-to-end
test drives the server with SRI's client-side codec.

## 5. Security notes

- **V1 is plaintext and unauthenticated.** Anyone who reaches port 3333 can
  mine to their own address (that is solo mining), read the jobs and the
  worker names, and a man in the middle can rewrite the worker name or
  steal shares. Bind it to a private interface or firewall it to known
  addresses (the node warns when it is bound to a public address), or put
  a TLS terminator in front (`stratum+ssl://`).
- **V2 is encrypted and authenticated** from the first message after the
  64-byte handshake act: ChaCha20-Poly1305 with keys from an ephemeral
  secp256k1 ECDH, and the server's identity is the pinned authority key.
  A miner that does not pin the key (or pins the wrong one) gets no
  protection against an impostor; always configure the full URL.
- The authority key file is a secret (mode 0600). It never signs anything
  on the chain; it only identifies the server to miners.
- Both servers bound every input: line and frame sizes, sessions (in total
  and per IP, with idle eviction), channels, control requests, jobs and
  shares per session, submit rates, handshake, authorization and share
  idle deadlines, and the log volume a peer can cause.
  Shares are checked by the server; blocks only by the node's acceptance
  path, never trusted from the miner.
- secp256k1 (libsecp256k1 0.28.2) is linked only for the V2 handshake and
  the authority key, under a scoped exception of the audit CRY-6 ban
  (deny.toml `wrappers`, node/tests/supply_chain_lockfile_guard.rs, which
  also fails if code outside node/src/stratum_v2/ names the crate). A node
  built without the `stratum-v2` feature has no secp256k1 at all.

## 6. The external proxies

The node's servers are the reference end of two tools being prepared
outside this package:

- **ParallelismLinux stratum proxy** (`pool/proxy.py`, port 3336): accepts
  miners (MRR rentals, farm ASICs) and forwards them to this node's 3333,
  adding connection accounting and monitoring. It forwards V1 as it is:
  the worker names (obb1 addresses) and the share answers pass through
  unchanged, and the stock-firmware path of 1.3 works behind it.
- **`tools/obenblock-stratum`** (Rust port of the job server): a standalone
  pool built on `getblocktemplate` header jobs and `submitblock` with the
  share solution (OBENBLOCK-MINING.md §3), for operators who run the job
  server on another host than the node. Built on the same header job
  (`stratum` object, `extranonce` in `submitblock`) and the same SV2
  messages, a miner can move between it and the built-in servers by
  changing only the URL.

## 7. Monitoring

With `--metrics`:

- `gnb_stratum_sessions_total{protocol}`: connections accepted;
- `gnb_stratum_sessions_active{protocol}`: sessions open;
- `gnb_stratum_shares_submitted_total{protocol,result}`: `ok`, `stale`,
  `dup`, `low_diff`, `unauthorized`, `rejected`;
- `gnb_stratum_blocks_found_total{protocol}`: blocks found and accepted.

These are the legacy server's `stratum_*` series with the node's prefix
and a `protocol` label (`v1`, `v2`). Log lines to watch:

```text
stratum: V1 listening on 0.0.0.0:3333
stratum: work #12 h=4521 bits=1d00ffff txs=3 (TipChanged, clean=true)
stratum: session 7 authorized obb1q….rig1 -> pays obb1q…
stratum: session 7 BLOCK FOUND h=4522 id=… (by obb1q….rig1, version 20004000 ntime …)
stratum_v2: session 3 channel 1 opened for obb1q….sv2 -> pays obb1q…
stratum_v2: session 3 channel 1 BLOCK FOUND h=4523 id=…
stratum: work #13 h=4523 stall-relief step: bits 1c3fffc0 -> 1c41756d
```

## 8. Differences from the legacy Bloch servers

- Jobs are `getblocktemplate` header jobs on one shared work feed, with
  ObenBlock's parents commitment; the stall-relief step is a job event and
  bounds the job's `ntime` window.
- V1 accepts BIP 310 version rolling (the legacy server declined it); the
  notify is the header job's `stratum` object; payout is the `obb1…` worker
  name or the operator's label fallback.
- V2 uses SRI's message types and the spec's framing (the legacy server's
  hand-written codecs sent the target big-endian, never sent
  `SetNewPrevHash`, encrypted whole frames as one message and dropped a
  miner after 10 s of silence). Its jobs honour version rolling.
- Removed: the legacy pool / solo-connect fee split (never wired), the
  shared V1 password, the legacy `cert.rs` (noise_sv2 signs the handshake
  certificate itself), the Template Distribution Protocol (not served).
