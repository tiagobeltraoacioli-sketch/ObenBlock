# ObenBlock mainnet launch runbook

> **Read this before you rent ASICs.** Under the consensus rules of this
> code base, stock Stratum V1 firmware cannot find ObenBlock blocks. This
> covers Antminer and Whatsminer stock firmware, NiceHash,
> MiningRigRentals and every V1 rental service. A V1 miner computes
> Bitcoin's SHA-256d Merkle root, while the ObenBlock header commits to its
> own body root (`docs/OBENBLOCK-MINING.md` §4,
> `tools/obenblock-stratum/README.md` §1).
>
> The stratum proxy accepts such devices. It counts their work in
> `obb_stratum_shares_bitcoin_root_total`, and `verify` warns about it. The
> work never becomes a block, so rented V1 hashrate costs the rent and
> finds nothing.
>
> ASIC mining needs one of these:
>
> - the open consensus change of package O3b (header root = Bitcoin's
>   transaction tree, body roots in the coinbase), decided **before the
>   genesis is mined**;
> - firmware that speaks the proxy's `obenblock-root` extension;
> - Stratum V2 standard channels (not implemented).
>
> Without one of them, the launch runs on the three CPU hosts alone. Expect
> the first block about half a day after the genesis (see "First blocks").

This runbook launches ObenBlock mainnet on three servers. Every step runs
from the Mac, through `obb-launch.sh` in this folder. Each step prints what
it did. The checks to make before you go on are listed after each step.

| Host | Login | Role |
| --- | --- | --- |
| 136.244.93.186 | key `~/.ssh/edgevana_fleet_g4`, user `ubuntu` | build host, node, CPU miner, explorer API, **stratum :3333** |
| 209.250.236.240 | key `~/.ssh/edgevana_fleet_g4`, user `ubuntu` | node, CPU miner, explorer API |
| 152.236.5.112 | password only (`senha:` line of `~/Desktop/gnb-servidor-teste-152.txt`), user `ubuntu` | node, CPU miner, explorer API |

On every host:

| Item | Value |
| --- | --- |
| user | `obenblock` (node), `obenblock-api` (explorer API), `obenblock-pool` (stratum, on 136 only) |
| binaries | `/opt/obenblock/current/` → `/opt/obenblock/releases/<id>/` |
| data | `/var/lib/obenblock` (archive node: every block body is kept) |
| config | `/etc/obenblock/obenblock.env`, `explorer-api.env`, `stratum.env`, `rpc.key`, `explorer-api.key` |
| units | `obenblock-node`, `obenblock-explorer-api`, `obenblock-stratum` (136) |
| ports | P2P 18110/tcp public (ufw), RPC 18210 on 127.0.0.1 only, stratum 3333/tcp public on 136, explorer API 2087/tcp open to Cloudflare's IPv4 ranges only |
| miner | `--mine --mine-threads <logical CPUs - 1>` (31 on these hosts), paid to `OWNER_ADDRESS` |
| peers | `--peer /ip4/<other host>/tcp/18110` for the other two hosts |

The kit never stops, starts, edits or removes GnB's `gnb-node`, its data
(`/opt/gnb`, `/var/lib/gnb`) or any `bloch-*` unit. `preflight` and
`verify` report their state and nothing more.

Mainnet launches with the current PoWit rules. PoCI
(`docs/DESIGN-obenblock-poci.md`) comes later through a hard fork.

## 0. Prepare (the day before)

1. Create the launch checkout from the final integration tip. Merge this
   kit's branch into it if it is not merged yet. Note the commit.

   ```
   git -C ~/repos/github/gnb-smh worktree add -b obenblock/mainnet-launch ~/worktrees/obenblock-mainnet obenblock/integration
   ```

2. Fill `kit.conf` (copy it from `kit.conf.example`):
   - `OWNER_ADDRESS`: the owner's `obb1…` payout address;
   - `SRC_DIR`: the launch checkout, for example
     `/Users/tiagobulhoes/worktrees/obenblock-mainnet`;
   - `LAUNCH_TS`: the launch moment in Unix seconds, or leave it empty to
     use the moment the genesis step runs.
3. Rehearse the genesis step. It runs on a scratch copy at the documented
   rehearsal time and never touches `SRC_DIR`:

   ```
   ./obb-launch.sh genesis --rehearsal
   ```

   It must print `GENESIS BLOCK ID (display order):
   00000000721a9cb402747bea3f34d0ecc7095952173a5606cd50711230c74d6d`.
4. Run the read-only checks:

   ```
   ./obb-launch.sh preflight
   ```

   Check for each host:
   - `sudo=passwordless` on 136 and 209, and `sudo=password-ok` on 152;
   - `gnb-node=inactive`;
   - no `port … in use` line for 18110, 18210, 3333 or 2087;
   - `python3` present;
   - `ufw: Status: active`. If ufw is inactive, the rules are recorded but
     not enforced; decide this before the launch.
   Port 80 must also be free for the certificate step (step 4).
5. ASICs: read the warning at the top first. Rent hashrate only for
   devices that can mine the ObenBlock root, and keep their pool settings at
   hand (section "Stratum").

## 1. Genesis (launch day, T - about 1 h)

```
./obb-launch.sh genesis
```

Type `MINE` when asked. The step does the following:

1. It copies `SRC_DIR` to `136:~/obenblock-launch/src`.
2. It builds `gnb-mine-genesis` and mines the 80-byte SHA-256d header at
   `LAUNCH_TS`. This takes about 2^32 hashes, about 10 s on 32 threads.
3. It writes the constants into `crates/gnb-crypto/src/core/genesis.rs`
   (the LAUNCH PLACEHOLDER block) and `reference/obb_genesis.py`.
4. It rewrites `reference/obb_genesis_vectors.json` and checks the
   reference.
5. It runs the genesis tests and the SHA-256d mining test.
6. It copies the four changed files back into `SRC_DIR`.

Add `--full-tests` to run the whole workspace, which takes much longer.

Before you go on:

- the step ends with `GENESIS BLOCK ID (display order): 00000000…` and
  `launched <timestamp> <display id> <raw id>`;
- `git -C $SRC_DIR diff --stat` shows exactly these files:
  - `crates/gnb-crypto/src/core/genesis.rs`;
  - `reference/obb_genesis.py`;
  - `reference/obb_genesis_vectors.json`;
  - `docs/OBENBLOCK-GENESIS.md`.

Commit the files with the command the step printed. The release label is
that commit. A tree with uncommitted changes builds as `<sha>-dirty`.

The timestamp matters:

- It is also the ASERT anchor time.
- A block must not be stamped more than 600 s ahead of the nodes' clocks,
  and no block can come before `LAUNCH_TS`. Never set it in the future by
  more than a few minutes.
- A timestamp somewhat in the past is harmless: the first block's stall
  relief already counts from it (see "First blocks").

The browser wallet core compiles the genesis constants in. Rebuild and
re-pin it with `scripts/build-wallet-wasm.sh` from `SRC_DIR`, for the site
deploy (step 7).

## 2. Build

```
./obb-launch.sh build
```

The step runs on 136 and builds these binaries (release profile):

- `obenblock` (the node, built as `gnb`);
- `obenblock-cli`;
- `obenblock-wallet`;
- `obenblock-mine-genesis`;
- the stratum proxy, when `tools/obenblock-stratum` exists in the source.

The CPU miner is the node's built-in SHA-256d miner (`--mine`). The step
then assembles `obenblock-release-<commit>-g<last 8 hex of the genesis
id>/`. It holds the binaries, the launchers, the units, the host scripts,
the explorer API, the carry-over snapshot, `RELEASE` and `SHA256SUMS`. The
tarball and its `.sha256` are copied to `state/dist/`.

Before you go on:

- `RELEASE` shows `genesis=<raw id>` equal to the genesis step's raw id;
- the tarball checksum is OK on the Mac (the step checks it);
- if the source has a stratum proxy, `stratum=<program>` is set.

## 3. Deploy

```
./obb-launch.sh deploy
```

For each host, the step copies the tarball and the explorer API key to
`/tmp/obenblock-kit/`. It then runs `install.sh` with sudo. Nothing is
started yet. `install.sh` does the following:

- It checks `SHA256SUMS`. It refuses a release without a mainnet genesis
  and a port that belongs to another process.
- It creates the users.
- It installs the release under `/opt/obenblock/releases/<id>` and points
  `current` at it. The previous release becomes `previous`.
- It unpacks the carry-over snapshot.
- It writes the env files. It creates `rpc.key` once.
- It installs and enables the units.
- It adds the ufw rules:
  - `18110/tcp`;
  - `3333/tcp` on 136;
  - `2087/tcp` from each Cloudflare IPv4 range.

The explorer API's shared secret is created once on the Mac, in
`state/secrets/explorer-api.key`. It is the same on all three hosts, and it
is the Worker secret `GNB_API_KEY`.

Before you go on:

- each host prints `installed release <id> (genesis <raw id>); units
  enabled, not started`;
- on 136, `/etc/obenblock/stratum.env` exists, with
  `OBB_STRATUM_PAYOUT_ADDRESS` = the owner address (see "Stratum" below).

## 4. Explorer API certificates

```
./obb-launch.sh explorer-tls
```

For each host, the step gets a Let's Encrypt certificate for
`<ip-with-dashes>.sslip.io` with certbot's standalone challenge:

- port 80 is open only during the challenge;
- the renewal hooks do the same;
- the certificate is copied to `/etc/obenblock/tls`;
- the explorer API is enabled and started.

The Worker origins are:

```
https://136-244-93-186.sslip.io:2087
https://209-250-236-240.sslip.io:2087
https://152-236-5-112.sslip.io:2087
```

If port 80 is taken on a host, the step refuses. Leave that host out of
the Worker's origins, or set `EXPLORER_TLS="none"` and use a Cloudflare
Tunnel (`deploy/explorer-api/README.md`).

## 5. Start

```
./obb-launch.sh start
```

The step starts `obenblock-node` on 136 first, then on 209, then on 152. It
waits for each RPC to answer. Then it starts the explorer API and the
stratum unit where they are enabled.

The step refuses to start a host where an `obenblock` process already runs
outside the unit.

The node writes the genesis ledger on its first boot:

- 452,725 carry-over UTXOs (the log says `carryover VERIFIED: 452726 Bloch outputs`);
- 72 vesting tranches.

It verifies the genesis proof and its pinned id first.

## 6. Verify

```
./obb-launch.sh verify
```

The step prints one row per host and `RESULT OK` or `RESULT FAIL`.

FAIL means one of these:

- not exactly one node process on the host;
- the unit is not active;
- the RPC does not answer;
- the chain id is not `0x4f420001`;
- the genesis differs from the mined one, or between hosts;
- fewer than 2 peers;
- the miner is off, or does not run with `nproc - 1` threads.

WARN means one of these:

- GnB is running;
- the explorer API or stratum is not active;
- the tips are more than 3 blocks apart.

Run the step again a few minutes after the start, and after the first
block. `./obb-launch.sh logs <host> [lines]` shows the node's journal.

Known display quirk: `getnetworkinfo` reports `"chain": "gnb"` (a duplicate
key in the RPC code overrides `"obenblock"`). The verify step checks
`chain_id` instead.

## Stratum (ASICs)

The ASICs connect to:

```
stratum+tcp://136.244.93.186:3333
worker / username: <OWNER_ADDRESS>.<rig name>   (an obb1… mainnet address; rig name optional)
password:          x
```

Enable version rolling (BIP 320, mask `1fffe000`) in the firmware if it
asks.

The proxy is `tools/obenblock-stratum`, a solo pool:

- It takes the node's `getblocktemplate` header jobs and submits with
  `submitblock` (`docs/OBENBLOCK-MINING.md` §3).
- Every block it finds pays `OBB_STRATUM_PAYOUT_ADDRESS`, the owner
  address. The worker name only identifies the device. The username must
  be an ObenBlock address of the network unless `OBB_STRATUM_ANY_USER=true`.
- It reads the node key `/etc/obenblock/rpc.key` (group `obenblock-rpc`).

`/etc/obenblock/stratum.env` on 136 is written once, so a redeploy keeps
your edits:

- `OBB_STRATUM_NETWORK=mainnet`;
- `OBB_STRATUM_LISTEN=0.0.0.0:3333`;
- `OBB_STRATUM_RPC=127.0.0.1:18210`;
- `OBB_STRATUM_RPC_API_KEY_FILE`;
- `OBB_STRATUM_PAYOUT_ADDRESS`;
- `OBB_STRATUM_METRICS=127.0.0.1:9333`.

Optional tuning is described in the proxy's README:

- `OBB_STRATUM_DIFFICULTY`, `_DIFFICULTY_MIN` and `_MAX`;
- `OBB_STRATUM_SHARE_SECS`.

After you edit the file, run `sudo systemctl restart obenblock-stratum` on
136, then `./obb-launch.sh verify 136.244.93.186`.

When the integration branch that is built has no `tools/obenblock-stratum`,
the release has no proxy: `RELEASE` shows `stratum=` empty, and the
stratum unit refuses to start. `verify` warns "nothing listens on :3333".

Test one device first. `./obb-launch.sh verify 136.244.93.186` prints the
proxy's counters (workers, shares). It warns if any share was computed over
Bitcoin's Merkle root: that device runs stock V1 firmware and will never
find a block. A found block shows as `accepted` in the node log
(`./obb-launch.sh logs 136.244.93.186`). Only then point the rest of the
rented hashrate at the endpoint.

The proxy package also ships `obenblock-cpu-miner`, which mines through
stratum with the `obenblock-root` extension. The kit does not use it on the
three hosts: their CPUs mine through the node's built-in miner.

## First blocks: what to expect

The genesis is anchored at the launch difficulty, 1 EH/s of SHA-256d
(`OBB_LAUNCH_BITS = 0x19009d69`). ASERT does not lower block 1, because
block 1's parent is the genesis. The stall relief lowers it (DESIGN §5.1):
once a block is 180 s late, its target doubles every 30 minutes, in 60 s
steps. The slow start pays almost nothing for the first blocks: the
subsidy ramps up over 5,760 blocks.

The table below gives median times from the genesis timestamp, from
`lib/first_blocks.py` (the consensus formulas, Monte Carlo):

| hashrate | block 1 | block 10 | block 100 | block 1,000 |
| --- | --- | --- | --- | --- |
| 3 CPU hosts only (0.15 to 0.65 GH/s, see note) | 12 to 13 h | 1.9 to 2 d | 2.4 to 2.6 d | 2.9 to 3.1 d |
| 100 TH/s | 3.3 h | 13.8 h | 23 h | 35 h |
| 1 PH/s | 1.5 h | 8 h | 17 h | 28 h |
| 10 PH/s | 30 min | 3.4 h | 10 h | 21 h |
| 100 PH/s | 3 min | 40 min | 4.2 h | 15 h |
| 1 EH/s | 24 s | 5 min | 50 min | 8.3 h (on schedule) |

CPU rate note: the rehearsal measured the CPU rate twice on the build host.

- The genesis search ran on a host busy with other builds: 1.6 MH/s per
  thread.
- The node's regtest miners reported about 7 MH/s per thread.

For 3 × 31 threads that is 0.15 to 0.65 GH/s. Either way, the CPUs alone do
not make a fast launch.

To get the times for the rented hashrate, run
`python3 lib/first_blocks.py 25P` (also with `--start-delay <s>`, if the
ASICs start that long after `LAUNCH_TS`).

What to read from the table:

- Below 1 EH/s, the first block comes after one to a few hours. The
  following blocks also need relief until ASERT has moved the target.
- After that, blocks settle at 30 s.
- The CPUs alone are a lottery of many hours. The ASICs are what makes the
  launch.
- DESIGN §4.2 says "at 1 PH/s, the first block comes after about 6 h". That
  is when the target reaches the 1 PH/s level. The median first block comes
  earlier.

## 7. Publish

Once `verify` is OK and block 1 is in:

1. **Genesis hash**: the display-order id printed in step 1, in the release
   notes, `docs/OBENBLOCK-GENESIS.md` (the genesis step already filled the
   table) and on the site.
2. **Seeds**:
   - create `seed.obenblock.xyz` A records (DNS only, not proxied) for
     136.244.93.186, 209.250.236.240 and 152.236.5.112;
   - publish the fixed peers `/ip4/<ip>/tcp/18110`;
   - then set `DNS_SEED="default"` in `kit.conf` and redeploy with
     `./obb-launch.sh deploy`, then `./obb-launch.sh start`, one host at a
     time.
3. **Binaries**: the tarball and its `SHA256SUMS` from `state/dist/`
   (downloads page and GitHub release).
4. **Stratum endpoint**: `stratum+tcp://136.244.93.186:3333`, if it is
   public.
5. **Site placeholders** (obenblock.xyz, `site/` in the repository): every
   `At launch` / `MAINNET NOT LAUNCHED YET` marker. Find them with:

   ```
   grep -rn "At launch\|NOT LAUNCHED\|AT LAUNCH" site
   ```

   They are:
   - `site/index.html`, network table: DNS seed, genesis block hash,
     binaries; the FAQ "Is ObenBlock live yet?"; the announcement bar;
   - `site/downloads.html`, release files and checksums, genesis block
     hash, DNS seed, the three download cards; the announcement bar;
   - `site/brand.html` and the footers: `MAINNET NOT LAUNCHED YET`;
   - the Worker: `GNB_ORIGINS` = the three https origins of step 4, and
     `GNB_API_KEY` = `state/secrets/explorer-api.key`;
   - the browser wallet core rebuilt with the genesis (step 1).
6. Tell the owner's other agents the genesis hash. The anchoring
   (`deploy/obenblock-anchor`) and the bridge need it.

## Stop and rollback

| Command | Effect |
| --- | --- |
| `./obb-launch.sh stop [host…]` | stops and disables the obenblock units; data kept |
| `./obb-launch.sh rollback [host…]` | `current` back to `previous` (a bad binary upgrade); restarts what was running |
| `./obb-launch.sh remove [host…]` | stops the units and deletes them and the ufw rules; moves `/etc/obenblock`, `/opt/obenblock`, `/var/lib/obenblock` to `*.removed-<UTC time>`; deletes nothing |

A wrong genesis (a wrong timestamp, for example) is a new chain:

1. Run `stop` on all hosts.
2. Run `remove` on all hosts. The data is moved aside.
3. Revert the genesis commit in `SRC_DIR`.
4. Repeat steps 1 to 6.

## Rehearsal (done before the launch)

`rehearse-regtest.sh` runs the kit end to end on the build host. It needs
no root, does not use systemd and touches no service:

1. the kit tests;
2. the genesis step on a scratch copy at the rehearsal time (it reproduces
   the documented id);
3. the release step and its checksums;
4. a staged install;
5. an isolated loopback boot of the rehearsal genesis, and the placeholder
   build's refusal;
6. three regtest nodes from the release launcher, peered and mining, run
   through `status.py` and `verify_summary.py`;
7. stop.

```
~/worktrees/obb-remote.sh run ~/worktrees/obenblock-launch bash deploy/obenblock-launch/rehearse-regtest.sh
```
