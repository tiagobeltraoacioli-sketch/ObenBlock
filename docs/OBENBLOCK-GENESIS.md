# ObenBlock genesis and launch

Status: implemented (package O6c of docs/DESIGN-obenblock.md). The regtest
genesis is mined and in use. The mainnet genesis is complete except for its
launch timestamp, the BIP 320 version bits and the nonce. By owner decision
these are mined at launch.

## What the genesis is

Both ObenBlock networks have their own genesis block. The code is in
`crates/gnb-crypto/src/core/genesis.rs` and the executable reference is in
`reference/obb_genesis.py`. The vectors in `reference/obb_genesis_vectors.json`
pin both.

| | mainnet | regtest |
| --- | --- | --- |
| chain id | `0x4F420001` | `0x4F420002` |
| header bits | `0x1d00ffff` (pow limit, difficulty 1) | `0x207fffff` (pow limit) |
| ASERT anchor | genesis height and time, launch bits `0x19009d69` (1 EH/s) | genesis height and time, `0x207fffff` |
| timestamp | 1792398411 | 1,792,281,600 (2026-10-18 00:00 UTC) |
| version | `0x20000000` | `0x20000000` |
| nonce | 2042483606 | 0 |
| block id (display order) | `000000002f515b31fd21a057705d081567616836b529439184ce2196d756dda0` | `6918ae0c…0117163d` |

The header is the 80-byte SHA-256d header (§4.1). It has no parents, so the
parent commitment is `SHA-256d("OBB-PARENTS-v1" ‖ 00000000)`. The Merkle
field is Bitcoin's transaction root, as in every ObenBlock header
(docs/CONSENSUS.md, "Header Merkle root and body commitment (ObenBlock)"):
with one transaction, `txid(coinbase)`.

The coinbase `script_sig` starts with the 80-byte commitment of height 0
(`GNB-CB01`), like every later coinbase; its last 32 bytes are the body
commitment over the empty witness list, the empty shielded section and the
empty PoWit section (PoWit and liveness apply from height 0). The genesis text follows it. The
text commits to the SHA3-256 of the Bloch Genesis-3 snapshot, to the
conversion, and to the SHA3-256 of the vesting keys. The coinbase has one
output of 0 to an all-zero script.

The genesis ledger is GnB's (§3):

- the same snapshot (`genesis/bloch-g3-carryover.tsv.gz`);
- the same fixed conversion to 1,000,000 OBB;
- the same 20-byte key hashes;
- the same 72 locked team and founder tranches (`genesis/vesting.json`).

The node writes the ledger on first boot with the code it uses for GnB
(`node/src/genesis_init.rs`). Start it with `--carryover-snapshot` exactly
as for GnB.

## Rules from height 0

A process running ObenBlock reaches none of GnB's legacy regimes:

- **Hardening activations.** Both are at height 0: v3 transactions, sighash
  v3, canonical witnesses, PF-4, the conservative suite 0x0003, and the H2
  PoWit rules.
- **PoWit.** It applies from height 0, and `--powit-height` is refused. The
  genesis is checkpoint slot 0, justified and final. The witness set is
  empty for the first two epochs.
- **Proof of work.** SHA-256d is bound to the chain id
  (`core::set_node_chain_id`). A process that only selected the chain (a
  wallet or the CLI) uses it as well.
- **Witness commitment.** Every block commits its witnesses from height 1,
  through the coinbase commitment. The GnB `|wc:` suffix never applies.
- **Slow start (§4.2).** The subsidy is
  `floor(full × min(h, 5,760) / 5,760)`, then GnB's halving schedule.
- **Launch policy.** The minimum chain work is 0. There is no assumed-valid
  block and no release finality checkpoint.

## Launch: mining the mainnet genesis

Until the launch constants are pasted, a node refuses to start ObenBlock
mainnet and prints the command below.

1. Fix the launch time `T` in Unix seconds. It must fit in a `u32` and
   should be the real launch moment. It is also the ASERT anchor time: the
   schedule height at time `t` is `(t - T) / 30`.
2. On a multi-core machine, run:

   ```text
   cargo run --release -p gnb --bin gnb-mine-genesis -- --chain obenblock --timestamp T
   ```

   The search needs about 2^32 SHA-256d. The rehearsal took 10 s on 32 threads
   of the build host. When a version's 2^32 nonces are exhausted, the search
   rolls the BIP 320 version bits and keeps `T` as given. It prints
   `OBB_MAINNET_GENESIS_TIMESTAMP`, `_VERSION`, `_NONCE` and `_HASH`.
3. Replace the LAUNCH PLACEHOLDER block in
   `crates/gnb-crypto/src/core/genesis.rs` with the printed constants.
4. In `reference/obb_genesis.py`, add the same `timestamp`, `version` and
   `nonce` to `NETWORKS["mainnet"]`. Then run
   `python3 reference/obb_genesis.py --write`. The vectors then carry the
   mined header and `"launched": true`.
5. Run the checks:

   ```text
   python3 reference/obb_genesis.py --check
   cargo test --release -p gnb-crypto genesis
   cargo test --release -p gnb-crypto --test obb_genesis_vectors --test obb_genesis_process_chain
   ```

   Then run the workspace tests.
6. The genesis constants are compiled into `gnb-crypto`, so rebuild and
   re-pin the browser wallet core (`scripts/build-wallet-wasm.sh`).
7. Start the first nodes:

   ```text
   obenblock --chain obenblock --carryover-snapshot bloch-g3-carryover.tsv …
   ```

   The binary is still named `gnb` until the rebrand. The first node
   verifies the genesis proof and its pinned id before it writes anything.

### Example run

The vectors include this run as `mainnet.rehearsal`, with
`T = 1,792,281,600`. It is not the mainnet genesis.

- nonce: 1,492,736,395;
- version: `0x20000000`;
- id: `00000000721a9cb402747bea3f34d0ecc7095952173a5606cd50711230c74d6d`.

## Regtest

```text
gnb --chain obenblock --regtest --carryover-snapshot bloch-g3-carryover.tsv
```

The regtest genesis was mined with
`gnb-mine-genesis --chain obenblock --regtest`. The test
`node/tests/obb_regtest_genesis.rs` boots a fresh data directory through
`genesis_init`, mines blocks on it with SHA-256d through the real template
and acceptance code, and restarts the node.
