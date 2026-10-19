# ObenBlock mainnet launch

Status: launch documentation for release 0.2.0. Every value marked
`[AT LAUNCH: …]` is not known yet. It is published when the mainnet genesis
is mined (docs/OBENBLOCK-GENESIS.md, "Launch: mining the mainnet genesis").
Until those values appear in the release notes, in this repository and on
obenblock.xyz, there is no ObenBlock network to join.

Search this file for `AT LAUNCH` to find every placeholder.

## 1. What launches

ObenBlock (ticker OBB) is a new chain built from the GnB-SMH code base. It
has a clean genesis. The GnB chain is not changed by it
(docs/DESIGN-obenblock.md §1).

| Item | At launch |
| --- | --- |
| Networks | mainnet only. There is no public testnet. Regtest is for local development (DESIGN-obenblock.md §1). |
| Proof of work | SHA-256d on Bitcoin's 80-byte header layout. Stock Bitcoin ASICs can mine it (DESIGN-obenblock.md §4.1, docs/OBENBLOCK-MINING.md). There is no merged mining. |
| Block time | 30 s target, ASERT with a 2 h half-life, plus stall relief (DESIGN-obenblock.md §4.2, §5.1). |
| Finality | none for the first 3,599 blocks. From height 3,600: PoCI (§5 below). |
| Supply cap | 12,500,000 OBB: 9.0M mined, 1.0M Bloch carry-over, 1.25M team (locked), 1.25M founder (locked) (DESIGN-obenblock.md §3, docs/MONETARY-POLICY.md). |
| Genesis ledger | no balance from the GnB chain. It holds the Bloch Genesis-3 carry-over, paid to the same keys as in GnB's genesis, and 72 locked team and founder tranches (docs/OBENBLOCK-GENESIS.md). |
| Subsidy | slow start: block `h` pays `floor(full × min(h, 5,760) / 5,760)`, then GnB's halving schedule. The withheld part (about 3,080 OBB) is never issued (`crates/gnb-crypto/src/core/pow_scheme.rs`, `SLOW_START_BLOCKS`). |
| Subsidy split | 80 % to the block's miner, 20 % to 16 witness-share slots. Fees go 100 % to the miner (docs/MONETARY-POLICY.md, "Mining subsidy"). |
| Release finality checkpoint, assumed-valid block, minimum chain work | none at launch (`MIN_CHAIN_WORK` = 0). Later releases set them from independent nodes (DESIGN-obenblock.md §3). |

What does **not** launch:

- a Bloch sidechain or bridge;
- automatic use of Bloch anchors. Anchors are advisory only (§6);
- pools with share accounting run by the project. The node's built-in
  Stratum servers mine solo (docs/MINING-ASIC.md).

## 2. Network identity

These values are compiled into the release
(`crates/gnb-crypto/src/core/chain.rs`, `OBENBLOCK_MAINNET`).

| Item | Mainnet | Regtest |
| --- | --- | --- |
| Chain id | `0x4F420001` | `0x4F420002` |
| Address prefix | `obb1q…` (key hash), `obb1m…` (spend policy) | `obb1t…`, `obb1n…` |
| P2P port | 18110 | 18111 |
| RPC port | 18210 (bound to 127.0.0.1 by default) | 18211 |
| Metrics port | 18310 (off unless `--metrics`) | |
| P2P protocol id | `/obenblock/pq/1.0.0` | |
| Built-in DNS seed | `seed.obenblock.xyz` `[AT LAUNCH: DNS records published]` | none |
| Seed peers | `[AT LAUNCH: list of /ip4/<host>/tcp/18110 multiaddrs]` | |
| Genesis block id (display order) | `[AT LAUNCH: GENESIS_HASH]` | `6918ae0c…0117163d` |
| Genesis timestamp | `[AT LAUNCH: LAUNCH_TIME, Unix seconds and UTC]` | 1,792,281,600 |
| Genesis header bits | `0x1d00ffff` | `0x207fffff` |
| ASERT anchor bits | `0x19009d69` (1 EH/s at 30 s blocks) | `0x207fffff` |
| Release | `[AT LAUNCH: release tag, tarball name and SHA256SUMS]` | |

Addresses made by GnB (`gnb1q…`, `gnb1m…`) and the `bloch1q…` form are
accepted and shown back as `obb1…` (DESIGN-obenblock.md §2,
`address::normalize_legacy_address`). The same key controls coins on both
chains. The chain id is folded into every signature hash, so no
transaction, vote or share is valid on both chains.

The Bloch carry-over is claimed with the same JSON keystore a holder uses
for Bloch and GnB today (DESIGN-obenblock.md §3).

## 3. Running a node

The release binaries are `obenblock` (node), `obenblock-cli` and
`obenblock-wallet`. Inside the source tree they are still built as `gnb`,
`gnb-cli` and `gnb-wallet` (node/Cargo.toml) until the rename.

### 3.1 Get and check the release

1. Download the release tarball and `SHA256SUMS` from
   `[AT LAUNCH: GitHub release URL]` and from obenblock.xyz/downloads.
2. Check that both sources list the same checksums, then run
   `sha256sum -c SHA256SUMS`.
3. The release folder name ends in `-g<last 8 hex digits of the genesis id>`.
   Its `RELEASE` file names the genesis id
   (deploy/obenblock-launch/LAUNCH-RUNBOOK.md, step 2, branch
   `obenblock/launch-kit`).

To build from source instead, check out the release tag and run, from the
repository root:

```text
cargo build --release -p gnb --bin gnb --bin gnb-cli
cargo build --release -p gnb --bin gnb-wallet --features gnb-crypto/wallet-cli
```

The wallet binary needs the `wallet-cli` feature (node/Cargo.toml).

### 3.2 Start the node

The node writes the genesis ledger on its first start. It needs the
carry-over snapshot that ships with the release
(`genesis/bloch-g3-carryover.tsv.gz`, unpacked):

```text
obenblock --chain obenblock \
  --carryover-snapshot bloch-g3-carryover.tsv \
  --data-dir /var/lib/obenblock \
  --peer [AT LAUNCH: /ip4/<seed host>/tcp/18110]
```

On first start:

- the node checks the genesis proof of work and its pinned id before it
  writes anything (docs/OBENBLOCK-GENESIS.md, step 7);
- the log shows `carryover VERIFIED: 452726 Bloch outputs`, and the ledger
  gets 72 vesting tranches (LAUNCH-RUNBOOK.md, step 5).

Useful flags (node/src/main.rs):

| Flag | Meaning |
| --- | --- |
| `--peer <multiaddr>` | a peer to dial; repeatable |
| `--dns-seed <host>` | another DNS seed; `--no-default-dns-seed` skips `seed.obenblock.xyz` |
| `--archive` | keep every block body |
| `--rpc-api-key-file <file>` | API key for privileged RPC methods (`getblocktemplate`, `submitblock`) |
| `--mine --miner-address obb1… --mine-threads N` | built-in CPU miner. On mainnet it is a lottery (docs/MINING-ASIC.md §7). |
| `--stratum`, `--stratum-v2` | built-in Stratum servers for ASICs (docs/MINING-ASIC.md) |
| `--witness-key`, `--witness-password-file`, `--witness-payout` | run a PoWit witness (docs/RUNNING.md) |
| `--finalitycheckpoint HASH:HEIGHT` | treat a block you read from nodes you trust as final (weak subjectivity) |
| `--bloch-rpc <url>` | compare finality with the anchors on your own Bloch node; advisory only (docs/OBB-ANCHOR.md) |

Open P2P port 18110/tcp. Keep RPC on 127.0.0.1. `--rpc-public` exposes it
to the internet.

### 3.3 Check that it runs

```text
obenblock-cli --chain obenblock getnetworkinfo
obenblock-cli --chain obenblock getblockcount
obenblock-cli --chain obenblock getpeerinfo
obenblock-cli --chain obenblock getfinalityinfo
```

`getnetworkinfo` reports `chain_id` `0x4f420001`. Check `chain_id`, not
the `chain` field: some builds of the launch kit printed `"chain": "gnb"`
there (LAUNCH-RUNBOOK.md, step 6).

## 4. Verifying the genesis hash

The genesis id is the first thing to check. A node that starts with another
genesis is on another chain. Compare the id from at least three
independent sources, and do not rely on one website alone.

Byte order matters. The id is SHA-256d of the 80-byte header:

- **Display order** starts with zeros (`00000000…`). Release notes,
  docs/OBENBLOCK-GENESIS.md, the site and the launch kit print this form.
- **Raw order** is the same 32 bytes reversed. `getblockhash 0` returns
  this form (`node/src/rpc/mod.rs`, `hex::encode` of the stored id), and so
  does the `RELEASE` file's `genesis=` line.

To turn one form into the other:

```text
python3 -c 'import sys; print(bytes.fromhex(sys.argv[1])[::-1].hex())' <64 hex digits>
```

Sources to compare:

1. **Your own binary.** The genesis constants are compiled into
   `gnb-crypto` (`crates/gnb-crypto/src/core/genesis.rs`). The node refuses
   to start mainnet with the placeholder constants and checks the genesis
   proof and id on first start. Then run
   `obenblock-cli --chain obenblock getblockhash 0` and reverse the result.
2. **The source code.** At the release tag, read the mainnet constants
   (`OBB_MAINNET_GENESIS_TIMESTAMP`, `_VERSION`, `_NONCE`, `_HASH`) in
   `crates/gnb-crypto/src/core/genesis.rs`, and recompute the header with
   the reference implementation:

   ```text
   python3 reference/obb_genesis.py --check
   ```

   `reference/obb_genesis_vectors.json` then holds the mined header and
   `"launched": true`. The Python reference uses only the standard library,
   so this check does not depend on the Rust build.
3. **The documentation.** The mainnet column of the table in
   docs/OBENBLOCK-GENESIS.md is filled at launch.
4. **The GitHub release notes** `[AT LAUNCH: URL]` and
   **obenblock.xyz/downloads** (the "Genesis block hash" row).
5. **Other node operators.** Ask an operator you know to run
   `getblockhash 0` on their node.

Check two more things while you are at it:

- the id meets the genesis bits `0x1d00ffff`: in display order it starts
  with at least eight zero hex digits;
- the genesis timestamp equals the published launch time
  `[AT LAUNCH: LAUNCH_TIME]`. Block 1 cannot be older than it.

If the sources disagree, do not mine and do not accept payments. Report it
(§8).

For comparison only, the launch rehearsal (not the mainnet genesis) at
timestamp 1,792,281,600 gave
`00000000721a9cb402747bea3f34d0ecc7095952173a5606cd50711230c74d6d`
(docs/OBENBLOCK-GENESIS.md, "Example run"). A node that reports this id is
running a rehearsal build.

## 5. How finality works at launch

### 5.1 Heights 0 to 3,599: proof of work only

PoCI needs a finalized history to build its first voter configuration, and
there is none at genesis (docs/DESIGN-obenblock-poci.md §9):

- The first `POCI_BOOTSTRAP_EPOCHS = 4` epochs (4 × 720 blocks, about 24 h
  at 30 s blocks) have no finality.
- The first configuration `C_4` is computed from the chain up to the
  checkpoint that opens epoch 4 (height 2,880).
- `C_4` enters into force, with that checkpoint justified and finalized,
  only at the first block whose height is at least
  `launch_height = 2,880 + 720 = 3,600`. The checkpoint is then buried by
  one epoch of blocks (`launch_bury`, part of the PoCI `params_digest`,
  `crates/gnb-crypto/src/core/powit/poci.rs`).

Before height 3,600:

- every block is probabilistic, as in Bitcoin. A fork is settled by work;
- `getfinalityinfo` shows no finalized checkpoint above the genesis;
- exchanges and wallets should treat everything as provisional and wait
  for many confirmations, or for height 3,600 and finality.

The 3,600 blocks take about 30 h if blocks keep the 30 s schedule. If the
hashrate at launch is far below 1 EH/s, the first blocks are slower
(docs/MINING-ASIC.md §5), and height 3,600 comes later.

### 5.2 From height 3,600: PoCI

PoCI (Proof of Corruption or Integrity) is ObenBlock's finality profile of
PoWit (docs/DESIGN-obenblock-poci.md):

- **Voters.** For each epoch there is one frozen configuration `C_e`: the
  witness keys and their weights. The weight of a key is its admitted
  witness-share work from finalized history, over a 112-epoch window
  (28 days), under the growth cap (DESIGN-obenblock.md §6.2, §6.3). There
  is no stake.
- **Quorum.** A checkpoint link counts only with votes worth strictly more
  than two thirds of `total(C_e)`. Justification and finality follow
  Casper FFG (DESIGN-obenblock-poci.md §3).
- **Proof of Integrity.** Every finalized checkpoint has a finality
  certificate, served by `getfinalitycertificate <checkpoint>`
  (DESIGN-obenblock-poci.md §6).
- **Proof of Corruption.** A double or surround vote by one key under one
  configuration is evidence. The key is excluded for 100 epochs
  (DESIGN-obenblock-poci.md §5).
- **Handoff.** `C_{e+1}` enters into force only when the checkpoint that
  opens epoch `e+1` is finalized under `C_e` (DESIGN-obenblock-poci.md §4).
- **No quorum.** Absence never lowers the quorum: there is no inactivity
  leak for finality on ObenBlock. Blocks keep coming, but finality waits
  until more than two thirds of `C_e` vote again. If that weight is gone
  for good, recovery is a coordinated release applied with
  `setfinalitycheckpoint`, never automatic (DESIGN-obenblock-poci.md §7).
- **Growth cap.** New share work can raise the total weight by at most
  `W / 64` per epoch, after incumbents renew. Capturing two thirds of the
  weight takes at least 71 epochs (about 18 days), whatever the rented
  hashrate, and the growth is visible in `getpowitinfo`
  (DESIGN-obenblock.md §6.3).
- **Finality is sticky.** A node never reorganizes below a checkpoint it
  has finalized. A conflicting finalization raises an alert and waits for
  the operator (DESIGN-obenblock.md §7).

### 5.3 What this means in the first weeks

- **The first window is the weakest period.** The growth cap's floor
  `G_min` lets the weight fill from zero at launch, so early weight is
  small and new. Releases during the first 28 days are expected to ship a
  release finality checkpoint (DESIGN-obenblock.md §6.3, "Launch").
- **Finality needs witnesses.** `C_4` is made from the witness-share work
  in the first epochs. An empty configuration never reaches a quorum
  (DESIGN-obenblock-poci.md §3). Witness shares are mined by nodes that run
  with `--witness-key`. They are not mined by the Stratum servers, and
  stock Stratum V1 firmware cannot mine them (docs/MINING-ASIC.md §8). If
  too little share work is in the configuration, finality starts late or
  waits for a coordinated release.
- **Credit at finality.** Wallets and exchanges should credit deposits at
  "finalized" in `getfinalityinfo`, not at a fixed number of blocks
  (DESIGN-obenblock.md §7).

## 6. Bloch anchors

Operators may publish finalized ObenBlock checkpoints to Bloch, and a node
started with `--bloch-rpc` compares them with its own finality. At launch
the anchors are **advisory only**:

- an anchor never sets or moves a checkpoint;
- a contradiction raises the conflict alert (`getblochanchor`,
  `getfinalityinfo`), and the operator decides;
- the Bloch-side anchor registry depends on the Bloch code base and is not
  part of this release (DESIGN-obenblock.md §8, docs/OBB-ANCHOR.md).

## 7. Mining

See docs/MINING-ASIC.md for ASICs, MiningRigRentals, the Stratum
endpoints, difficulty and first-block timing.

## 8. Reporting a problem

- Security issues: report them privately to
  `[AT LAUNCH: security contact]`, not in public issues. The repository
  has no SECURITY policy file yet.
- Other issues: https://github.com/tiagobeltraoacioli-sketch/ObenBlock/issues.
- Include the output of `getnetworkinfo`, `getblockhash 0` and
  `getfinalityinfo`.
