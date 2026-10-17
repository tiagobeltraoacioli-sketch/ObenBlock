# ObenBlock

ObenBlock (ticker **OBB**, [obenblock.xyz](https://obenblock.xyz)) is a
post-quantum proof-of-work BlockDAG. It relaunches the GnB code base as a new
chain. Its genesis carries over none of the GnB chain's history. It pays the
Bloch carry-over to the same keys as GnB's genesis did. Blocks are mined with **SHA-256d** on a
Bitcoin-ASIC compatible header. Finality comes from **PoWit** witness votes
weighted by share work. Transactions carry hybrid post-quantum signatures.
Finalized checkpoints are anchored in **Bloch**, in both directions. The
design is [docs/DESIGN-obenblock.md](docs/DESIGN-obenblock.md). The GnB chain
itself is not changed by the relaunch.

**Status: the relaunch is in progress.** The code in this repository still
runs GnB: the GnB-SMH proof of work, the `gnb` chain ids and `gnb1…`
addresses, amounts in GNB, and the GnB genesis with its Bloch carryover. The
SHA-256d proof of work (package O3), the ObenBlock genesis and identity (O6)
and the renamed binaries and texts (O7) have not landed yet. There is no
ObenBlock network yet. Pre-release; not externally audited.

| | ObenBlock (design) | This code today (GnB) |
| --- | --- | --- |
| Proof of work | SHA-256d on Bitcoin's 80-byte header layout, mineable by unmodified SHA-256d ASICs (32-bit nonce, BIP 320 version rolling, coinbase extranonce); no merged mining | GnB-SMH, a sequential memory-hard function over SHAKE-256 |
| Finality | PoWit: witness votes weighted by share work only, over a 28-day window, active from genesis | PoWit with GnB's parameters (7-day window), from mainnet height 10,000 |
| Consensus | GhostDAG BlockDAG (k = 10), 30-second blocks | The same |
| Difficulty | ASERT anchored at genesis, 2-hour half-life, plus stall relief when hashrate leaves | ASERT anchored at genesis, 2-hour half-life, computed per block from its parents |
| Signatures | Hybrid ML-DSA-65 ‖ Falcon-1024; opt-in conservative suite SLH-DSA-SHAKE-128s ‖ Falcon-1024 (`0x0003`), valid from genesis | The same suites; `0x0003` only where the second hardening upgrade is active (testnet, regtest; not scheduled on mainnet) |
| Networks | Mainnet only; regtest for development | Mainnet, testnet, regtest |
| Addresses | `obb1q…` (key hash), `obb1m…` (spend policy); GnB's `gnb1…` and `bloch1q…` addresses stay valid and are shown as `obb1…` | `gnb1q…`, `gnb1m…` (testnet `gnb1t…`, `gnb1n…`); `bloch1q…` accepted |
| Genesis and supply | No balances from the GnB chain; the Bloch carryover is paid as in GnB's genesis (same snapshot, conversion and keys). Hard cap 12,500,000 OBB with GnB's allocations: 72% mining, 8% Bloch carryover, 10% team, 10% founder | Hard cap 12,500,000 GNB: 8% Bloch carryover, 10% team and 10% founder (locked: 1-year cliff, then 36 monthly tranches), 72% mining |
| Bloch anchoring | Mutual: ObenBlock's finalized checkpoints recorded in Bloch, and Bloch's recorded in ObenBlock | Bloch's finalized checkpoints recorded in ordinary transactions ([docs/BLOCH-ANCHOR.md](docs/BLOCH-ANCHOR.md)); the other direction is package O8 |
| Unit | 1 OBB = 10^8 base units | 1 GNB = 10^8 base units |

## Layout

| Path | What it is |
| --- | --- |
| `crates/gnb-smh` | The current proof of work (GnB-SMH v1, which the relaunch replaces with SHA-256d), compact targets, ASERT. Includes the normative Python reference and test vectors |
| `crates/gnb-crypto` | Consensus types (blocks, transactions, genesis, carryover, monetary policy), signatures, wallet |
| `crates/coherence-core` | Shielded-pool primitives carried in the block format |
| `node` | The full node and its tools; binaries `gnb`, `gnb-cli`, `gnb-wallet`, `gnb-mine-genesis` (names unchanged until package O7) |
| `crates/gnb-wallet-wasm` | Browser wallet core (keystores, coin selection, hybrid signing) for `wasm32-wasip1` |
| `site/`, `worker/` | The website: static pages, explorer (`/explorer`) and web wallet (`/wallet`), served by a Cloudflare Worker that also proxies the read-only explorer API |
| `deploy/` | Node and explorer-API systemd units and install scripts |
| `genesis/` | The Bloch Genesis-3 terminal snapshot the GnB genesis ledger is built from; ObenBlock's genesis pays the same carryover from it |
| `crates/pqcrypto-internals` | Vendored fork (patched in through `[patch.crates-io]`), a workspace member so its guard test runs. (The `libp2p-yamux` fork was retired with libp2p 0.57; `node/tests/supply_chain_lockfile_guard.rs` keeps a single yamux >= 0.13.10 and hickory >= 0.26.1 in `Cargo.lock`.) |
| `node/fuzz` | cargo-fuzz targets (own workspace, nightly): wire decoders and round trips, difficulty, PoW and signature verify, Merkle paths, mempool, block rules, sighash, witnesses, undo records, keystores, addresses, the sync codec, block acceptance in any arrival order ([docs/testing/FUZZING.md](docs/testing/FUZZING.md)) |
| `docs/` | Protocol notes: [ObenBlock relaunch design](docs/DESIGN-obenblock.md), [consensus](docs/CONSENSUS.md), [monetary policy and carryover](docs/MONETARY-POLICY.md), [running a node](docs/RUNNING.md), [ledger v1](docs/LEDGER.md), [P2P security](docs/P2P.md), [multisig and timelocks](docs/MULTISIG.md); testing: [sanitizers, Miri, 32-bit](docs/testing/SANITIZERS.md), [fuzzing](docs/testing/FUZZING.md), [functional tests](docs/testing/FUNCTIONAL.md) |
| `test/functional` | Multi-node functional tests and their framework (Python, stdlib only) |
| `reference/`, `rust/`, `analysis/` | Standalone GnB-SMH v1 reference implementation and the ledger v1 research prototype (see below) |

## Build and test

```sh
cargo build --release
cargo test --workspace --locked
# The consensus crates in their own invocations: in a workspace-wide run the
# node's dev-only `test-pow-limit` feature is unified into gnb-crypto and pins
# every expected target to the pow limit.
cargo test -p gnb-smh --locked
cargo test -p gnb-crypto --locked
cargo clippy --workspace --all-targets --locked
cargo deny check && cargo audit
# Functional tests: real gnb / gnb-cli processes on loopback, built with the
# test-only `test-pow-limit` feature (docs/testing/FUNCTIONAL.md)
python3 test/functional/test_runner.py
```

CI (`.github/workflows/ci.yml`) runs all of these, the Python references, the
standalone `rust/` crate, the vendored-crate and Falcon guards, the sanitizer,
Miri and 32-bit jobs ([docs/testing/SANITIZERS.md](docs/testing/SANITIZERS.md)),
and, on pull requests and nightly, every fuzz target for 60 s
(`.github/workflows/fuzz.yml`, which also runs a weekly 10-minute-per-target
campaign; [docs/testing/FUZZING.md](docs/testing/FUZZING.md)). Mutation
testing of the consensus code (`.github/workflows/mutants.yml`, [docs/testing/MUTATION.md](docs/testing/MUTATION.md))
runs weekly and, on the lines a pull request changes, on every pull request.

The toolchain is pinned in `rust-toolchain.toml`.

## Run a node

```sh
gunzip -k genesis/bloch-g3-carryover.tsv.gz
./target/release/gnb --carryover-snapshot genesis/bloch-g3-carryover.tsv \
    --mine --miner-address gnb1q... --peer /ip4/<seed>/tcp/17110
```

The first boot verifies the snapshot against the consensus constants and
writes the converted ledger before block 0. See [docs/RUNNING.md](docs/RUNNING.md).
This runs the code as it is today, on the GnB network. ObenBlock's genesis,
ports and binary names come with packages O6 and O7.

## Web wallet

The web wallet (`site/wallet.html`, served at `/wallet`) opens GnB and Bloch
keystores (a `bloch1q…` keystore opens as the same `gnb1q…` address), creates
new wallets, and sends and receives GNB. Decryption (Argon2id, AES-256-GCM)
and signing run in WebAssembly inside the page; the private key never leaves
the WebAssembly memory and nothing secret is uploaded. The page is served with
a strict Content-Security-Policy (same-origin scripts only, no framing).
Rebuild the core with `scripts/build-wallet-wasm.sh` (needs a wasi-sdk).

## Relationship to GnB

ObenBlock keeps GnB's block format, GhostDAG, transaction and spend-policy
model, signature suites, wallet key derivation, keystores and network stack.
The relaunch changes ([docs/DESIGN-obenblock.md](docs/DESIGN-obenblock.md)):

- **Proof of work:** SHA-256d on Bitcoin's 80-byte header layout instead of
  GnB-SMH.
- **Network identity:** chain ids `0x4F420001` (mainnet) and `0x4F420002`
  (regtest), P2P protocol `/obenblock/pq/1.0.0`, ports 18110 (P2P) and 18210
  (RPC), so one host can run both chains. No transaction, attestation or
  share is valid on both chains.
- **Genesis:**
  - every rule of both hardening upgrades and PoWit active from height 0;
  - no balances from the GnB chain;
  - the Bloch carryover paid exactly as in GnB's genesis, so a Bloch or GnB
    JSON keystore spends it with the same key;
  - the subsidy ramps up over the first 5,760 blocks (slow start).
- **Addresses:** `obb1…`. GnB's `gnb1…` strings (and `bloch1q…`) parse as the
  same script, a GnB keystore opens unchanged, and the same key controls its
  coins on both chains.
- **Finality:** a 28-day PoWit window (GnB: 7 days) and a faster inactivity
  leak, so finality resumes when witness weight disappears.

Domain-separation tags such as `GNB-TXSIG-v3` stay as they are: they are
protocol constants, and the chain id already keeps the chains apart. None of
these changes is implemented yet.

## GnB's relationship to Bloch

GnB keeps Bloch's block format, GhostDAG, transaction model, signatures,
wallet key derivation and network stack, and changes:

- **Proof of work:** GnB-SMH instead of Bloch-SIS / SHA-256d. No AuxPoW, no
  Stratum (Stratum V1/V2 are SHA-256d ASIC protocols).
- **Network identity:** chain ids `0x474E0001` / `0x474E0002`, sighash domain
  `GNB-SIGHASH-v1`, P2P topics `gnb/*`, magic `GNB1`, ports 17110 (P2P),
  17210 (RPC), 17310 (metrics). No signature or block is valid on both chains.
- **History:** no Bloch flag days or height-gated legacy rules. Every rule
  that Bloch activated at a height applies from GnB genesis.
- **Ledger:** genesis state is the Bloch Genesis-3 terminal snapshot converted
  to 1,000,000 GNB. Owners keep their keys; `bloch1q<hash><checksum>` becomes
  `gnb1q<hash><checksum>`.

## Reference implementation and ledger v1

`reference/`, `rust/` and `analysis/` hold a standalone GnB-SMH v1 reference and the
**ledger v1** research prototype: stateless validation without a committee. Every node checks every
block holding only two 32-byte state roots; each block travels with O(log n)
sparse-Merkle witnesses (about 1 KB per touched key at 2^30 outputs), and every
transaction outcome must be proven. Specification: [`docs/LEDGER.md`](docs/LEDGER.md).
Not yet wired into the node.

| Path | What it is |
| --- | --- |
| `reference/gnb_smh.py` | GnB-SMH normative definition (Python standard library only) |
| `reference/check_vectors.py`, `test_vectors.json` | 17 PoW vectors (log2_n = 1, 2, 10, 19) and the checker of both vector files |
| `reference/gnb_difficulty.py` | Difficulty normative definition: compact bits, chain work, ASERT, GnB's difficulty input |
| `reference/gen_difficulty_vectors.py`, `difficulty_vectors.json` | Compact, chain-work, ASERT and multi-parent expected-bits vectors, checked by `crates/gnb-smh` and `crates/gnb-crypto` |
| `reference/gnb_sighash.py`, `sighash_vectors.json` | Transaction signature digests (sighash v2 byte by byte, sighash v3, v3 component messages) and their vectors (`python3 reference/gnb_sighash.py` regenerates them), checked by `crates/gnb-crypto/tests/sighash_vectors.rs` |
| `reference/gnb_ledger.py` | Ledger normative definition: sparse Merkle tree, transactions, witness bundle, validation |
| `reference/gen_ledger_vectors.py`, `ledger_vectors.json` | 5 valid and 25 single-fault invalid blocks, tree vectors |
| `reference/test_ledger.py` | Ledger tests, including a producer-versus-validator differential test |
| `rust/` | Standalone crate (`#![forbid(unsafe_code)]`, outside the workspace): PoW, `ledger` module, `smh-bench` |
| `analysis/` | PoW statistics and measured witness size versus live outputs |

```sh
python3 reference/check_vectors.py      # Python 3.10 or newer
python3 reference/test_ledger.py
cd rust && cargo test --release --locked
```

## License

The node and `gnb-crypto` are AGPL-3.0-or-later, as inherited from Bloch
(see `LICENSE`). `crates/gnb-smh`, `reference/`, `rust/` and `analysis/` are MIT OR Apache-2.0
(see `LICENSE-APACHE` and `LICENSE-MIT`).
