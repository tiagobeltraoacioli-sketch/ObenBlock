# ObenBlock 0.2.0 release notes

Status: draft for the mainnet launch release. Values marked
`[AT LAUNCH: …]` are filled in when the genesis is mined
(docs/OBENBLOCK-GENESIS.md, deploy/obenblock-launch/LAUNCH-RUNBOOK.md on
branch `obenblock/launch-kit`).

| | |
| --- | --- |
| Release | 0.2.0 `[AT LAUNCH: tag and commit]` |
| Chain | ObenBlock mainnet, chain id `0x4F420001` |
| Genesis block id (display order) | `[AT LAUNCH: GENESIS_HASH]` |
| Genesis timestamp | `[AT LAUNCH: LAUNCH_TIME]` |
| Binaries | `obenblock`, `obenblock-cli`, `obenblock-wallet` `[AT LAUNCH: tarball and SHA256SUMS]` |
| Seeds | `seed.obenblock.xyz`, `[AT LAUNCH: seed peer multiaddrs]` |

0.2.0 is the first ObenBlock release. ObenBlock is a new chain built from
the GnB-SMH code base, with a clean genesis. These notes list what changed
compared with GnB. The GnB chain itself is not changed: a node started
without `--chain obenblock` still runs GnB with GnB's rules.

How to run a node and check the genesis: docs/LAUNCH.md. Mining:
docs/MINING-ASIC.md.

## Changes since GnB

### Proof of work: SHA-256d

- Blocks are mined with SHA-256d on Bitcoin's 80-byte header layout:
  `version ‖ parents_commitment ‖ merkle_root ‖ time ‖ bits ‖ nonce`. The
  block id is the PoW hash (DESIGN-obenblock.md §4.1).
- `parents_commitment = SHA-256d("OBB-PARENTS-v1" ‖ u32le(n) ‖ parents…)`
  takes the previous-hash slot. The full parent list travels with the block.
- Work is Bitcoin's chain work, and the pow limit is Bitcoin's `0x1d00ffff`.
  GnB-SMH's memory-hard PoW and its difficulty shift do not apply
  (DESIGN-obenblock.md §4.2).
- ASERT (30 s blocks, 2 h half-life) is anchored at the genesis with launch
  bits `0x19009d69`, the target for 1 EH/s (`OBB_LAUNCH_BITS`,
  `crates/gnb-crypto/src/core/pow_scheme.rs`).
- **Stall relief**: once a block is 180 s late, its own target doubles every
  30 min, in 60 s steps. Block production recovers in hours when hashrate
  leaves (DESIGN-obenblock.md §5.1).
- **Slow start**: the subsidy ramps linearly over the first 5,760 blocks.
  About 3,080 OBB are never issued (DESIGN-obenblock.md §4.2).
- Code and reference: `node/src/pow/mod.rs`, `node/src/mining/sha256d.rs`,
  `reference/obb_job.py` (docs/OBENBLOCK-MINING.md).

### Bitcoin header Merkle root

- The header's `merkle_root` is Bitcoin's SHA-256d transaction tree over
  the wire txids (pairs, odd last duplicated, Bitcoin Core's mutation
  check).
- Witnesses, the shielded section and the PoWit section are committed by
  the 80-byte coinbase commitment (`GNB-CB01`), so they never change the
  merkle branch (docs/CONSENSUS.md, "Header Merkle root and body commitment
  (ObenBlock)", `reference/obb_merkle.py`).
- Effect: stock Stratum V1 ASIC firmware builds the header root itself from
  `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2` and the branch, as for
  Bitcoin (branch `obenblock/asic-merkle`, merged).

### PoCI finality

PoWit finality on ObenBlock uses the strict PoCI profile
(docs/DESIGN-obenblock-poci.md):

- one frozen voter configuration `C_e` per epoch, identified by `config_id`;
- quorum strictly above two thirds of `total(C_e)`;
- handoff to the next configuration only through a checkpoint finalized
  under the current one;
- no inactivity leak for finality: absence never lowers the quorum, so a
  partition cannot finalize on both sides. Without a quorum, finality waits;
- absence pruning only by the current configuration while it has its
  quorum (§4.1);
- equivocation evidence (double and surround votes) bars a key for 100
  epochs (§5);
- finality certificates for every finalized checkpoint, served by
  `getfinalitycertificate` (§6);
- signer protection: votes are persisted before release, conflicting votes
  are refused, and a stale or duplicated signer record stops signing
  (`node/src/powit_signer.rs`, §8);
- buried launch: no finality before height 3,600. The first configuration
  `C_4` comes from the chain up to height 2,880 and enters into force at
  the first block at height 3,600 or above (§9).

The reference model is `reference/poci_reference.py` with
`reference/poci_vectors.json`.

### Witness weight: 28-day window and growth cap

- Witness shares are SHA-256d headers that an ASIC can mine, with custody
  sampled per job (DESIGN-obenblock.md §6.1, `core::witness_share::sha256d`).
- Weight is share work only (no stake), from finalized history, over a
  window of 112 epochs, 28 days (GnB: 7 days) (DESIGN-obenblock.md §6.2).
- **Growth cap**: per epoch, incumbents renew first. All new keys together
  can add at most `max(W / 64, G_min)`, pro rata. Excess work is dropped.
  Capturing two thirds needs at least 71 epochs, about 18 days, whatever
  the rented hashrate (DESIGN-obenblock.md §6.3, `reference/obb_growth_cap.py`,
  `crates/gnb-crypto/src/core/powit/growth_cap.rs`).

### Chain identity

- Chain id `0x4F420001` (mainnet), `0x4F420002` (regtest), folded into
  every sighash and PoWit message. No transaction, vote or share is valid
  on both GnB and ObenBlock (DESIGN-obenblock.md §2).
- P2P protocol id `/obenblock/pq/1.0.0`; ports 18110 (P2P), 18210 (RPC),
  18310 (metrics), so one host can run GnB and ObenBlock side by side
  (`crates/gnb-crypto/src/core/chain.rs`).
- Mainnet and regtest only. There is no public testnet.
- Every hardening rule applies from height 0 (v3 transactions, sighash v3,
  canonical witnesses, PF-4, suite 0x0003, the H2 PoWit rules). No legacy
  GnB regime is reachable on ObenBlock (docs/OBENBLOCK-GENESIS.md).
- Clean genesis: no balance from the GnB chain. The Bloch Genesis-3
  carry-over is paid to the same keys and with the same conversion as in
  GnB's genesis, plus the same 72 locked team and founder tranches. Supply
  cap 12,500,000 OBB (DESIGN-obenblock.md §3).

### `obb1` addresses

- Human-readable part `obb`: `obb1q…` (key hash) and `obb1m…` (spend
  policy) on mainnet, `obb1t…` and `obb1n…` on regtest.
- `gnb1…` and `bloch1…` strings are parsed as the same script and shown as
  `obb1…` (`address::normalize_legacy_address`).
- GnB keystores (v2, v3) open unchanged. The same key controls its coins on
  both chains, and the chain id keeps the signatures apart.

### Stratum V1 and V2

Built into the node (branch `obenblock/stratum-node`, docs/STRATUM.md):

- `--stratum` (V1, `0.0.0.0:3333`) for stock ASIC firmware and
  MiningRigRentals, with BIP 310 / BIP 320 version rolling and vardiff;
- `--stratum-v2` (V2, `0.0.0.0:3334`), Noise NX with a pinned authority
  key, standard channels, built on SRI's crates;
- solo only: each block pays the worker name's `obb1` address (or the
  operator's `--stratum-payout` for plain labels);
- one shared work feed with `getblocktemplate`; stall-relief steps are job
  events, and every job carries its `ntime` window;
- metrics `gnb_stratum_*` with a `protocol` label.

Also available: `tools/obenblock-stratum` (branch `obenblock/stratum`), a
standalone V1 job server built on `getblocktemplate` header jobs and
`submitblock`, with vardiff and optional PPLNS accounting, and the
`obenblock-cpu-miner`.

`getblocktemplate` gains the `sha256d` object and header jobs, and
`submitblock` takes a share's rolled fields (docs/OBENBLOCK-MINING.md §3).

### Wallet

- `obenblock-wallet` (CLI) and the browser wallet core
  (`crates/gnb-wallet-wasm`, served at obenblock.xyz/wallet, branch
  `obenblock/site-deploy`) are fixed to the ObenBlock chain: every
  signature commits to `0x4F420001` (or `0x4F420002` on regtest), every
  payment is version 3 / sighash v3, and addresses are shown as `obb1…`.
- Keystores keep their format and still bind the `gnb1` form of the
  address, so GnB tools and the ObenBlock CLI open the same file.
- The GnB-to-Bloch bridge operation (`bridgelock`) is refused. ObenBlock
  has no bridge.
- The explorer API and site have an ObenBlock view (`obb1`, SHA-256d, PoWit
  finality).

### Bloch anchoring (phase 1)

- Record encoding, `getfinalityanchors`, the reference `obenblock-anchor`
  daemon, and `--bloch-rpc` to compare a node's finality with anchors read
  from the operator's own Bloch node (docs/OBB-ANCHOR.md).

## Known limits

- **Witness shares need header-only mining.** A witness share puts its job
  commitment where a block header has the Merkle root. Stock Stratum V1
  firmware rebuilds that field from a coinbase and cannot mine them. They
  need SV2 standard channels or a driver that takes an 80-byte header
  (docs/OBENBLOCK-MINING.md §4.2). The built-in Stratum servers serve block
  jobs only. In this release, witness shares are mined by nodes that run
  with `--witness-key`. So ASIC hashrate on V1 secures blocks but adds no
  finality weight.
- **Finality starts only with witnesses.** The first configuration `C_4`
  is built from the share work of the first epochs. An empty configuration
  never reaches a quorum (DESIGN-obenblock-poci.md §3), and a configuration
  whose weight is gone needs a coordinated release (§7).
- **Anchors are advisory.** An anchor in Bloch never sets or moves a
  checkpoint. A record carries no proof that the voters finalized it, and
  anyone with a Bloch account can publish first. Contradictions raise an
  alert, and the operator decides (DESIGN-obenblock.md §8). The Bloch-side
  anchor registry is not part of this release.
- **Wallet core pin.** The browser wallet loads `gnb_wallet.wasm` only if
  its SHA-256 matches the pinned `WASM_SHA256` in `site/wallet/app.js`
  (WAL-5, `site/wallet/core.js`). The genesis constants are compiled into
  the core, so the core must be rebuilt and re-pinned with
  `scripts/build-wallet-wasm.sh` after the genesis is mined. A site served
  with a pre-launch core does not know the mainnet genesis.
- **No real-hardware test.** The Stratum servers are tested with simulated
  stock-firmware clients and SRI's client codec, not with real ASICs or
  MiningRigRentals rigs.
- **Stratum V1 is plaintext.** Bind it privately or put TLS in front of it
  (docs/STRATUM.md §5).
- **No release checkpoint at launch.** Minimum chain work is 0, and there
  is no assumed-valid block or release finality checkpoint. The first
  28-day window is the weakest period; later releases set these values
  (DESIGN-obenblock.md §3, §6.3).
- **Names in transition.** Binaries are built as `gnb`, `gnb-cli`,
  `gnb-wallet` inside the source tree, the internal crates keep their GnB
  names, metrics keep the `gnb_` prefix, and protocol tags such as
  `GNB-TXSIG-v3` stay as they are (DESIGN-obenblock.md §2).

## Verifying this release

1. Compare `SHA256SUMS` from the GitHub release and from
   obenblock.xyz/downloads, then run `sha256sum -c SHA256SUMS`.
2. Compare the genesis block id from several sources (docs/LAUNCH.md §4).
3. Run `python3 reference/obb_genesis.py --check` at the release tag.
