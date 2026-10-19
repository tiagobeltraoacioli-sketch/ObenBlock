# ObenBlock mainnet launch runbook

This runbook launches ObenBlock mainnet on three servers. Every step runs
from the Mac, through `obb-launch.sh` in this folder. Each step prints what
it did; the checks to make before you go on are listed after each step.

The code launched is branch `obenblock/mainnet-launch` (PoCI from genesis,
Bitcoin's header Merkle tree, the node's built-in Stratum V1/V2, the
SIMD CPU miner, the explorer API and the site). What that means for the
launch:

- **Stock SHA-256 ASICs work.** The header Merkle root is Bitcoin's
  transaction tree (the rest of the body is committed in the coinbase), so
  unmodified Antminer/Whatsminer firmware, NiceHash and MiningRigRentals mine
  ObenBlock over Stratum V1 (`tools/obenblock-stratum/README.md` §1,
  `docs/STRATUM.md`). SV2 firmware uses the V2 server.
- **PoCI is strict from genesis.** The first 4 epochs (24 h) have no
  finality. The configuration that then enters into force is built from the
  witness share work of those epochs, and only at block 3,600 (one epoch of
  burial). **No witness running from the genesis means no finality, ever,
  and the first outside witness would own it.** The kit runs one witness on
  each host, from the first start.
- The genesis target is sized for 1 EH/s; stall relief lowers it while
  blocks are late (see "First blocks").

| Host | Login | Role |
| --- | --- | --- |
| 136.244.93.186 | key `~/.ssh/edgevana_fleet_g4`, user `ubuntu` | build host; node, witness, Stratum V1/V2, CPU miner, explorer API |
| 209.250.236.240 | key `~/.ssh/edgevana_fleet_g4`, user `ubuntu` | node, witness, Stratum V1/V2, CPU miner, explorer API |
| 152.236.5.112 | password only (`senha:` line of `~/Desktop/gnb-servidor-teste-152.txt`), user `ubuntu` | node, witness, Stratum V1/V2, CPU miner, explorer API |

On every host:

| Item | Value |
| --- | --- |
| users | `obenblock` (node), `obenblock-miner` (CPU miner), `obenblock-api` (explorer API), `obenblock-pool` (optional proxy) |
| binaries | `/opt/obenblock/current/` → `/opt/obenblock/releases/<id>/` (the id carries a content digest) |
| data | `/var/lib/obenblock` (archive node), with `witness/` (KES key, vote record) and `stratum-v2-authority.json` |
| config | `/etc/obenblock/obenblock.env`, `miner.env`, `explorer-api.env`, `rpc.key`, `explorer-api.key`, `witness.pw` (0600 root, given to the node by systemd `LoadCredential`) |
| units | `obenblock-node`, `obenblock-cpu-miner`, `obenblock-explorer-api` (and `obenblock-stratum` only with `STRATUM_PROXY="on"`) |
| ports | P2P 18110/tcp public; Stratum V1 3333/tcp and V2 3334/tcp public (ufw); explorer API 2087/tcp from Cloudflare's IPv4 ranges only (ufw per range AND the nftables table `inet gnb_explorer` of `obenblock-explorer-firewall`, re-applied every 5 min); RPC 18210 and metrics 18310 on 127.0.0.1 only |
| explorer API | TLS on 2087 with a Let's Encrypt certificate for `nodeN.obenblock.xyz` (+ the sslip.io name as a second SAN during the move); every request HMAC-signed by the Worker (`OBB_API_AUTH=hmac+static` at launch, then `hmac`); clock on NTP |
| node | `--stratum --stratum-max-sessions 1024 --stratum-max-sessions-per-ip 256 --stratum-v2 --stratum-v2-max-sessions 1024 --stratum-v2-max-sessions-per-ip 64 --stratum-payout <OWNER> --witness-key … --share-threads 1 --rpc-api-key-file … --archive --metrics`, `--peer` = the other two hosts, no `--mine` |
| CPU miner | `obenblock-cpu-miner -o stratum+tcp://127.0.0.1:3333 -u <OWNER>.cpu-<ip-dashes> -p d=<0.03 × threads> -t <logical CPUs - 2>` |
| payout | `OWNER_ADDRESS` = `obb1q52273b58c1032291d562f582c413bbf05efabcdd0df82055`, the owner's GnB miner key `gnb1q52273…df82055` in ObenBlock notation (same key hash; only the prefix differs) |

Why a separate CPU miner and not the node's `--mine`: `obenblock-cpu-miner`
picks AVX-512/AVX2/SHA-NI kernels at run time (about 8× the node's
per-thread rate on the build host), it mines through exactly the stratum
path the ASICs use (so the V1 server is exercised from block 1), and it runs
as its own unprivileged, loopback-only, lowest-priority unit. Running both
would only split the same cores. `NODE_MINE="on"` exists for a fallback.

The kit never stops, starts, edits or removes GnB's `gnb-node`, its data
(`/opt/gnb`, `/var/lib/gnb`) or any `bloch-*` unit. `preflight` and
`verify` report their state and nothing more.

## The command sequence

```
cp kit.conf.example kit.conf
./obb-launch.sh preflight
./obb-launch.sh genesis --rehearsal
./obb-launch.sh dns
./obb-launch.sh genesis
git -C <SRC_DIR> add <the four files the step prints>
git -C <SRC_DIR> -c user.name=gnb-smh -c user.email=gnb-smh@proton.me commit -m "obenblock: mainnet genesis <id>"
./obb-launch.sh build
./obb-launch.sh deploy
./obb-launch.sh explorer-tls
./obb-launch.sh start
./obb-launch.sh verify
./obb-launch.sh backup-keys
./obb-launch.sh site
```

then the `node scripts/site-launch-fill.mjs …` and `npx wrangler …`
commands that `site` prints, run by the owner, and once the Worker reads
all three origins: `./obb-launch.sh explorer-auth hmac` and the key
rotation of step 8.

## 0. Prepare (the day before)

1. The launch checkout is the worktree of `obenblock/mainnet-launch`
   (`/Users/tiagobulhoes/worktrees/obenblock-mainnet`). Merge this kit's
   branch into it if it is not merged yet. Note the commit.
2. Fill `kit.conf` (copy it from `kit.conf.example`):
   - `OWNER_ADDRESS`: already the owner's key in `obb1` form (both forms
     are recorded there);
   - `SRC_DIR`: the launch checkout;
   - `LAUNCH_TS`: the launch moment in Unix seconds, or empty for the moment
     the genesis step runs;
   - `EXPLORER_NAMES`: the explorer origin names (default
     `node1/node2/node3.obenblock.xyz`); remove an entry to use the host's
     sslip.io name instead.
3. Create the DNS records `./obb-launch.sh dns` prints, in the Cloudflare
   dashboard of `obenblock.xyz`: the three A records `node1/node2/node3`
   (the host's IP, proxy status **DNS only**, grey cloud) and the CAA record
   `obenblock.xyz CAA 0 issue "letsencrypt.org"`. The A records must resolve
   before step 4.
4. Rehearse the genesis step. It runs on a scratch copy at the documented
   rehearsal time and never touches `SRC_DIR`:

   ```
   ./obb-launch.sh genesis --rehearsal
   ```

   It must print `GENESIS BLOCK ID (display order):
   00000000f9db8f81e92e293fae6032d359f731c1c7afebcaca1b75f47bfc32bc` and
   `rehearsal genesis reproduced`.
5. Run the read-only checks:

   ```
   ./obb-launch.sh preflight
   ```

   Check for each host:
   - `sudo=passwordless` on 136 and 209, `sudo=password-ok` on 152;
   - `gnb-node=inactive` (GnB is stopped on these hosts);
   - no `port … in use` line for 18110, 18210, 18310, 3333, 3334, 2087
     (3335 only matters with the proxy);
   - the `cpu:` line (AVX2 / AVX-512 / SHA-NI flags: the miner picks its
     kernel from them);
   - `python3` present, `ufw: Status: active`. If ufw is inactive the rules
     are recorded but not enforced; decide this before the launch.
   Port 80 must be free for the certificate step.
6. ASICs: line up the rented hashrate (MiningRigRentals, NiceHash) for the
   launch time, pool settings in "Stratum" below. They are what makes the
   first blocks come in minutes instead of hours.

## 1. Genesis (launch day, T − about 1 h)

```
./obb-launch.sh genesis
```

Type `MINE` when asked. The step:

1. copies `SRC_DIR` to `136:~/obenblock-launch/src` (without `.git`,
   `target/`, this kit's `state/` and `kit.conf`: no secret leaves the Mac);
2. builds `gnb-mine-genesis` and mines the 80-byte SHA-256d header at
   `LAUNCH_TS` (ObenBlock mode: Bitcoin's root over the coinbase txid, the
   body commitment in the coinbase; about 2^32 hashes, seconds on 32
   threads);
3. writes the constants into `crates/gnb-crypto/src/core/genesis.rs` and
   `reference/obb_genesis.py`, rewrites `reference/obb_genesis_vectors.json`
   and checks the reference;
4. runs the genesis, Merkle and SHA-256d mining tests (`--full-tests`: the
   whole workspace);
5. copies the four changed files into a scratch tree, checks them, and only
   then replaces them in `SRC_DIR` together.

Before you go on:

- the step ends with `GENESIS BLOCK ID (display order): 00000000…`;
- `git -C $SRC_DIR status` shows exactly the four files;
- commit them with the command the step printed. **The build refuses a
  tree with uncommitted or untracked files** and a genesis that differs
  from the committed one, so the release is exactly that commit.

The timestamp is also the ASERT anchor time. A block may not be stamped more
than 600 s ahead of the nodes' clocks, and none can come before `LAUNCH_TS`:
never set it more than a few minutes in the future. A timestamp somewhat in
the past is harmless (stall relief already counts from it).

The browser wallet core compiles the genesis constants in: rebuild and
re-pin it with `scripts/build-wallet-wasm.sh` in `SRC_DIR` and commit, for
the site (step 8).

## 2. Build

```
./obb-launch.sh build
```

On 136, from the committed tree:

- `obenblock` (the node, built as `gnb`, with the built-in Stratum V1 and V2
  servers), `obenblock-cli`, `obenblock-wallet`, `obenblock-mine-genesis`;
- `obenblock-cpu-miner` and `obenblock-stratum` (`tools/obenblock-stratum`,
  its own workspace and lock file);
- the launchers, units, host scripts, explorer API, carry-over snapshot,
  `RELEASE` and `SHA256SUMS`, as
  `obenblock-release-<commit>-g<last 8 hex of the genesis id>-c<content digest>`.

The tarball and its `.sha256` are copied to `state/dist/`.

Before you go on: `RELEASE` shows `genesis=<raw id>` equal to the genesis
step's raw id; the Mac's checksum check says OK.

## 3. Deploy

```
./obb-launch.sh deploy
```

For each host the step copies the tarball and the explorer API key to
`/tmp/obenblock-kit/` and runs `install.sh` with sudo. It:

- checks `SHA256SUMS`; refuses a release without a mainnet genesis, without
  the CPU miner, a port that belongs to another process, and a release id
  that is already installed with other contents;
- creates the users; installs the release and points `current` at it
  (`previous` keeps the last one);
- writes the env files; creates `rpc.key` once;
- **generates the host's PoWit witness key** once (`obenblock-cli
  witnesskeygen`, KES depth 12, 4,096 epochs ≈ 2.8 years) in
  `/var/lib/obenblock/witness/`, with a random password in
  `/etc/obenblock/witness.pw` (0600 root; the node reads it through systemd
  `LoadCredential`; it is never logged or put on a command line). It prints
  the witness id;
- installs and enables the units; opens 18110, 3333, 3334 and, for the
  explorer API, 2087 from each Cloudflare IPv4 range in ufw; installs and
  starts `obenblock-explorer-firewall` (+ its 5-minute re-apply timer: the
  nftables table `inet gnb_explorer`, nothing else) — the API's drop-in
  requires it and refuses to start without the table; turns NTP on if it is
  off (the API refuses requests 60 s off);
- if the node already runs (an upgrade or a config change), restarts the
  node and then the miner and the explorer API on the new release, one host
  at a time.

The explorer API's shared secret is created once on the Mac
(`state/secrets/explorer-api.key`), the same on the three hosts: it is the
Worker secret `OBB_API_KEY`.

Before you go on: each host prints `witness key … (witness id …)` and
`installed release <id> (genesis <raw id>); units enabled, not started`.

## 4. Explorer API certificates

```
./obb-launch.sh explorer-tls
```

It prints the DNS records again, then on each host checks that the names
resolve to that host, and gets one Let's Encrypt certificate for
`nodeN.obenblock.xyz` and the host's sslip.io name (certbot standalone;
`EXPLORER_SSLIP_SAN="off"` drops the second name at a later issuance). The hooks live in this certificate's own renewal file:
80/tcp is opened only if it was not already allowed, and only the rule the
kit added is deleted afterwards. The certificate is copied to
`/etc/obenblock/tls`, and the explorer API is enabled and started.

The Worker's `OBB_ORIGINS` are `https://nodeN.obenblock.xyz:2087`, its
`OBB_FALLBACK_ORIGINS` the sslip.io names (used only while no in-zone origin
answers). If port 80 is taken on a host, the step refuses: leave that host out
of the origins, or set `EXPLORER_TLS="none"` and use a Cloudflare Tunnel
(`deploy/explorer-api/README.md`).

## 5. Start

```
./obb-launch.sh start
```

On 136 first, then 209, then 152: the node (waits for its RPC), then the
CPU miner, the explorer API and the optional proxy. It refuses a host
where an `obenblock` process runs outside the unit.

The node writes the genesis ledger on its first boot (the log says
`carryover VERIFIED: 452726 Bloch outputs`; 72 vesting tranches), after
checking the genesis proof and its pinned id. It creates the **Stratum V2
authority key** (`/var/lib/obenblock/stratum-v2-authority.json`). The step
prints, per host:

```
STRATUM V1 on 136.244.93.186: stratum+tcp://136.244.93.186:3333
STRATUM V2 on 136.244.93.186: stratum2+tcp://136.244.93.186:3334/<authority key>
```

and keeps the keys in `state/stratum-v2-<host>.key`. These URLs go into
the miners' configuration and the site.

## 6. Verify

```
./obb-launch.sh verify
```

It runs `status.py` (as root, read-only) on each host, takes two samples
15 s apart, and prints one row per host, the stratum endpoints and
`RESULT OK` or `RESULT FAIL`.

FAIL means one of these:

- not exactly one node process, or one CPU miner process; the node or the
  miner unit not active; a process running another release than
  `/opt/obenblock/current` (a deploy that was not restarted);
- the RPC silent, public, or without its API key;
- chain id not `0x4f420001`; genesis differs from the mined one or between
  hosts;
- **a chain split**: different block ids at the lowest common height, or
  different finalized checkpoints at one height; tips more than 29 blocks
  apart; a node syncing or behind;
- a peer list without the other two kit hosts;
- Stratum V1 or V2 off or not listening;
- the miner with the wrong thread count (logical CPUs − 2), not hashing
  (CPU time between the samples), or not connected to the V1 server; the
  node's own `--mine` on;
- the witness missing or halted; and, from block 3,600 + 2 checkpoint
  intervals on: PoCI not active, the host's witness not in the PoCI
  configuration in force,
  or none of its votes included in the chain; a finality conflict.

WARN: GnB running, the explorer API not active, the V2 key not readable
yet, a tip that did not move between the samples (normal while only CPUs
mine at the launch difficulty), finalized heights apart, a witness whose
last included vote is more than an epoch old, no share work in the
bootstrap epochs.

Run it a few minutes after the start, after the first block, during the
bootstrap (the witnesses must show share work), and after block 3,600 (the
witnesses must be in the configuration and voting).
`./obb-launch.sh logs <host> [lines] [obenblock-cpu-miner]` shows a journal.

## 7. Back up the keys

```
./obb-launch.sh backup-keys
```

Copies each host's witness directory (KES key, vote record, high-water
file), vote records and V2 authority key into
`state/secrets/keys-<host>-<time>.tgz` (0600). Keep them off the hosts.

- The V2 authority key is what miners pin: if it is lost, every V2 miner
  must be reconfigured with a new URL.
- A witness key must never run on two nodes at once (PoCI §8: a double vote
  is evidence and bars the key). Restore a backup only on a replacement host
  with the original stopped; the signer's rollback guard halts signing if
  its record is stale, and `gnb-cli powitsignerclear` clears it once the
  operator has checked (`docs/RUNNING.md`, "Witness signer protection").

## 8. Site and Worker

```
./obb-launch.sh site
```

Refuses unless the last verify was `RESULT OK`. It copies `site/`,
`worker/`, `wrangler.toml` and `scripts/site-launch-fill.mjs` from
`SRC_DIR` to `state/site-deploy/` and:

- writes `launch.json` (genesis hash, launch time, seed nodes, Stratum V1
  and V2 endpoints with the V2 keys, release id and tarball SHA-256, the
  launch bits), checked against every `data-launch` key of the pages, and
  fills the pages with `--strict` when `node` is installed;
- sets the Worker's `[vars]` in the copied `wrangler.toml`:
  `OBB_ORIGIN_ZONE=obenblock.xyz`, `OBB_ORIGINS` (the three
  `https://nodeN.obenblock.xyz:2087`), `OBB_FALLBACK_ORIGINS` (the sslip.io
  names), `OBB_CHAIN_ID=0x4f420001`, `OBB_GENESIS_HASH` (`getblockhash 0`
  of the mined genesis, the raw order the origins sign);
- prints the commands, which it never runs:

```
cd state/site-deploy
node scripts/site-launch-fill.mjs launch.json site --strict
npx wrangler login
npx wrangler secret delete OBB_ORIGINS
npx wrangler secret put OBB_API_KEY < state/secrets/explorer-api.key
npx wrangler deploy
```

(with absolute paths; `secret delete` removes an `OBB_ORIGINS` secret of an
older deploy, a variable and a secret cannot share a name). Then check
`https://obenblock.xyz/api/originstatus` (the three hosts `ok`, `fallback:
false`), `https://obenblock.xyz/api/getnetworkinfo` (`chain_id`
`0x4f420001`) and `https://obenblock.xyz/#launch`.

Once the three origins have answered through the Worker:

1. `./obb-launch.sh explorer-auth hmac` (the API stops accepting the old
   static header);
2. rotate the shared key: move `state/secrets/explorer-api.key` aside, run
   `./obb-launch.sh deploy` (a new key is created and installed; the running
   units are restarted), then
   `npx wrangler secret put OBB_API_KEY < state/secrets/explorer-api.key`;
3. later, empty `OBB_FALLBACK_ORIGINS` in `wrangler.toml`, redeploy the
   Worker, and set `EXPLORER_SSLIP_SAN="off"` for the next certificate.

## Stratum (ASICs and rentals)

Every host serves both, solo (a block pays the address in the worker
name):

| | V1 | V2 |
| --- | --- | --- |
| URL | `stratum+tcp://<host>:3333` | `stratum2+tcp://<host>:3334/<authority key>` (from `start`) |
| worker | `<obb1 address>.<rig>` (e.g. `obb1q52273…df82055.mrr1`) | the same, as `user_identity` |
| password | `x` | – |
| firmware | stock Bitcoin firmware, MRR, NiceHash, V1 proxies (version rolling BIP 320 supported) | SV2 firmware (Braiins OS), SRI translator |

- A plain label (`rig1`) pays `OWNER_ADDRESS` (`--stratum-payout`). An
  address of another chain or network is refused, never paid to the owner.
- V1 is plaintext: anyone who reaches 3333 can mine to their own address
  (that is solo mining), and a man in the middle can rewrite the worker
  name. V2 is encrypted and authenticated by the pinned key.
- MiningRigRentals: pool `stratum+tcp://<host>:3333`, worker
  `<OWNER_ADDRESS>.mrr`, password `d=<difficulty>` (or `x`). MRR rigs
  arrive from a few MRR proxy addresses: the kit raises the per-IP caps
  (V1 256 and V2 64 sessions per address, 1,024 in all per host).
- Start difficulty: the server starts a session at difficulty 1 unless the
  miner sends `mining.suggest_difficulty` or a `d=<difficulty>` password.
  For an ASIC set `d=` to about one share per 10 s:
  `d ≈ hashrate (H/s) × 10 / 2^32` (100 TH/s → `d=232831`, 1 PH/s →
  `d=2328306`); vardiff takes over after the first shares. The kit's CPU
  miner sends `d=0.03 × threads` (about 0.9 for 30 AVX-512 threads).
- Test one rig first: its shares show in `verify`
  (`stratum blocks …; shares …`), a found block in
  `./obb-launch.sh logs <host>` (`BLOCK FOUND`).
- `STRATUM_PROXY="on"` adds `tools/obenblock-stratum` on 3335 (vardiff
  tuning, PPLNS accounting, metrics on 127.0.0.1:9333); it is optional.

## First blocks: what to expect

The genesis is anchored at the launch difficulty, 1 EH/s of SHA-256d
(`OBB_LAUNCH_BITS = 0x19009d69`). ASERT cannot lower block 1, whose parent
is the genesis; stall relief does (DESIGN §5.1): once a block is 180 s
late its target doubles every 30 minutes, in 60 s steps. The slow start
pays almost nothing for the first blocks (the subsidy ramps up over 5,760
blocks).

Median times from the genesis timestamp (`lib/first_blocks.py`, the
consensus formulas, Monte Carlo):

| hashrate | block 1 | block 10 | block 100 | block 1,000 |
| --- | --- | --- | --- | --- |
| 3 CPU hosts, `obenblock-cpu-miner` (about 3 × 0.4 GH/s, see note) | about 10 h | about 1.7 d | about 2.3 d | about 2.9 d |
| 100 TH/s | 3.3 h | 13.8 h | 23 h | 35 h |
| 1 PH/s | 1.5 h | 8 h | 17 h | 28 h |
| 10 PH/s | 30 min | 3.4 h | 10 h | 21 h |
| 100 PH/s | 3 min | 40 min | 4.2 h | 15 h |
| 1 EH/s | 24 s | 5 min | 50 min | 8.3 h (on schedule) |

CPU note: `obenblock-cpu-miner --bench` on the build host (Cascade Lake,
no SHA-NI) measured 14.3 MH/s per thread with AVX-512 and 6.3 with AVX2;
30 threads per host is about 0.2–0.43 GH/s. Run
`python3 lib/first_blocks.py 25P` for the rented hashrate (also with
`--start-delay <s>` if the ASICs start later than `LAUNCH_TS`).

Finality: none before block 3,600 (24 h of epochs plus one epoch of burial
at 30 s blocks, so about 30 h after the genesis if blocks are on schedule,
later if they are not). Wallets and exchanges treat everything before it as
provisional.

## Known issues from the rehearsal (2026-10-19)

- **Fixed (branch `obenblock/poci-net-fix`): peers banned each other on
  PoWit votes after the PoCI launch height.** A PoCI vote's v3 signature
  covers the `config_id` in force at the voter's tip, and the vote does not
  carry it. Right after a handoff (every finalized epoch boundary) a node
  one block ahead or behind verifies a neighbour's honest vote under
  another configuration; the signature fails there, and gossip classified
  that as `invalid attestation signature`, a context-free fault: the author
  was disconnected and discouraged, and the hosts split into partitions
  finalizing different checkpoints. The node now refuses such a vote for
  its own view only (`Ignore`, never misbehaviour; the deliverer keeps the
  verification charge unless the vote verifies under the previous
  configuration), and a misbehaviour line now names the refusal reason
  (rate-limited). Regression tests: `ingress::tests::poci_vote_under_another_configuration_is_not_a_fault`,
  `node/tests/poci_partition.rs` `votes_across_a_handoff_are_never_a_peer_fault`.
- **Fixed (same branch): finality stuck at the launch checkpoint.** Each
  witness share thread mined, admitted and gossiped every share it found;
  where shares are cheap (regtest at the pow limit, and any block whose
  bits are easy) that is thousands per second, which filled every node's
  share pool and the transaction topic until gossipsub dropped frames,
  votes among them (`absent_weight` over a third with votes in the chain;
  configurations built from very uneven share work). A witness now
  publishes at most one share per attested block. The rehearsal also paces
  its CPU miners (`obenblock-cpu-miner --block-pause-ms`, set only by
  `rehearse-regtest.sh`): unpaced, regtest at the pow limit runs at tens of
  blocks per second, which no node, the 5-block checkpoint interval or the
  20-block vote lifetime is made for (mainnet: 30 s blocks, launch target
  1 EH/s). The "not in the witness set" FAIL read the share-work set of the
  epoch; `status.py` now reads the key's weight in the PoCI configuration
  in force (`getpowitinfo.poci.signer_weights`).
- The node's `stratum_e2e` test `v1_submit_hashes_first_forwards_blocks_over_the_rate_and_dedups_on_the_header`
  failed twice inside the rehearsal on the loaded build host and passed
  when run alone (timing-sensitive).
- **Three equal witnesses: one host down halts finality.** Strict PoCI
  needs more than two thirds of the configuration in force (§3 of
  `docs/DESIGN-obenblock-poci.md`): with three keys of equal weight that is
  all three (2/3 is not enough). If one host is offline, blocks go on but
  nothing is finalized until it returns: wallets and exchanges wait, and
  the absent key is not pruned (a stall is not absence, §4.1). The rule is
  not changed. Operational guidance:
  - run four or more witness keys, each on its own machine and power or
    network domain, with weights as even as possible: with four equal keys
    one may be down (3/4 > 2/3); with seven, two;
  - never run one key in two places (the signer lock and the rollback
    guard stop the second instance; a double vote is evidence and a
    100-epoch ban, §5); a standby host takes over with the same key only
    after the first one is stopped for good;
  - watch `getpowitinfo.poci.absent_weight` (`over_a_third`) and the
    `verify` warning for a witness whose last included vote is more than
    an epoch old; restore the host before an outage outlasts what
    settlement can wait;
  - if a key is lost for good with no quorum left, recovery is the
    coordinated `setfinalitycheckpoint` procedure of §7, never automatic.
- After the hosts' CPU blocks become rare (ASICs raise the difficulty), the
  CPU witness share threads still produce the only witness share work; an
  outside party mining witness shares with header-only ASIC hardware could
  grow its weight, limited by the growth cap (DESIGN-obenblock.md §6.3).

## Stop and rollback

| Command | Effect |
| --- | --- |
| `./obb-launch.sh stop [host…]` | stops and disables the obenblock units; data kept |
| `./obb-launch.sh rollback [host…]` | `current` back to `previous`, that release's units reinstalled, every enabled obenblock unit restarted (also a failed one) |
| `./obb-launch.sh remove [host…]` | stops the units and deletes them, their drop-ins, the kit's ufw rules (by their `ObenBlock` comment) and the explorer certificate; moves `/etc/obenblock`, `/opt/obenblock`, `/var/lib/obenblock` (with the witness and V2 keys) to `*.removed-<UTC time>`; deletes nothing else |

A wrong genesis (a wrong timestamp, for example) is a new chain:

1. `stop` on all hosts, then `remove` on all hosts (the data is moved
   aside);
2. revert the genesis commit in `SRC_DIR`;
3. repeat steps 1 to 6. The witness keys are generated anew by `deploy`
   (the old ones are in the moved-aside data and in your backups).

## Rehearsal (done before the launch)

`rehearse-regtest.sh` runs the kit end to end on the build host, without
root or systemd and without touching any service:

```
~/worktrees/obb-remote.sh run ~/worktrees/obenblock-launch bash deploy/obenblock-launch/rehearse-regtest.sh
```

It covers: the kit tests; `genesis --rehearsal` on a scratch copy (the
documented id); the release build of every binary; a staged install with
the real owner address and a real witness key; a loopback boot of the
rehearsal mainnet genesis with V1 + V2 (V2 key created, owner address
valid in both forms); the placeholder build's refusal; three regtest nodes
from the release launcher on separate ports, peered, each with V1 + V2 and
a witness and no `--mine`, one CPU miner per node through its V1 server,
run past the regtest PoCI launch height (100) until finality advances;
`status.py` + `verify_summary.py` on them; the explorer API over TLS; the
node's V1/V2 end-to-end test (SRI's codec) and the job server's own test;
the site values; a clean stop.

What it cannot cover: systemd (units, `LoadCredential`, sandboxing are
checked statically and with `systemd-analyze` only), ufw, certbot and the
DNS names, the password host's expect path, the real hosts' CPUs and
network, real ASICs or MRR rigs, an SV2 firmware (the V2 path is covered by
the SRI-codec test), mainnet difficulty and timing (regtest blocks are at
the pow limit), the Worker and wrangler.
