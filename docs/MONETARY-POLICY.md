# ObenBlock monetary policy

Consensus rules, defined in `crates/gnb-crypto/src/core/tokenomics.rs` and
`crates/gnb-crypto/src/core/carryover.rs`. They are GnB's (ticker GNB), as
the code implements them today. The ObenBlock relaunch (ticker OBB) keeps the
same cap and allocations. Its genesis carries no balance from the GnB chain
and pays the Bloch carryover exactly as GnB's genesis does: the same
snapshot, conversion and keys. It adds a slow start, in which the subsidy
ramps up over the first 5,760 blocks
([DESIGN-obenblock.md](DESIGN-obenblock.md) §3, §4.2). That is not
implemented yet.

## Hard cap: 12,500,000 GNB

| Allocation | Share | Amount |
| --- | --- | --- |
| Bloch Genesis-3 carryover | 8% | 1,000,000 GNB (999,999.99789793 issued after rounding) |
| Team, locked | 10% | 1,250,000 GNB |
| Founder, locked | 10% | 1,250,000 GNB |
| Mining | 72% | 9,000,000 GNB (8,999,998.51392253 issued after rounding) |
| **Total issued** | | **12,499,998.51182046 GNB** |

No pools. **Until PoWit activates**, 100% of every subsidy and fee goes to the
miner. From `powit_height()`, 20% of the subsidy pays witness shares (see
[Mining subsidy](#mining-subsidy)); fees still go 100% to the miner. Mainnet
keeps PoWit off (`POWIT_HEIGHT_MAINNET = u64::MAX`).

## Team and founder allocations (locked)

Defined in `crates/gnb-crypto/src/core/vesting.rs`. Both allocations are
written into the genesis ledger as 36 outputs each. Every output pays to a
spend policy (see [MULTISIG.md](MULTISIG.md)) with an absolute timelock, so
the lock is a consensus rule: before its height a tranche cannot be spent by
anyone, the beneficiary included.

| | |
| --- | --- |
| Cliff | 1,051,200 blocks (1 year): nothing unlocks |
| Tranches | 36, one every 87,600 blocks (1 month) |
| Tranche k unlocks at | 1,051,200 + k × 87,600 (first 1,138,800; last 4,204,800, 4 years) |
| Tranche value | 1,250,000 GNB / 36 = 34,722.22222222 GNB, remainder in the last |
| Founder | one key (1-of-1) |
| Team | m-of-n multisig |

The public keys live in `crates/gnb-crypto/genesis/vesting.json`; its
SHA3-256 is the consensus constant `VESTING_SPEC_SHA3`, and the relaunch genesis
coinbase text must commit to it (re-mined once the keys are set). Outpoints are synthetic, like the carryover:
`txid = SHA3-256("GNB-VESTING-v1" ‖ role ‖ k ‖ policy hash)`, `vout = 0`.
Until the file holds the keys, nodes refuse to create a genesis ledger.

## Mining subsidy

- Initial subsidy 1.07020547 GNB per block (floor(9,000,000 GNB / (2 × 4,204,800))).
- Halving every 4,204,800 blocks (4 × 365 days at 30 s), by integer right
  shift in base units.
- The subsidy reaches zero after 27 halvings (height 113,529,600, about 108
  years) and stays zero. There is no tail emission.
- The genesis block pays nothing; mining starts at height 1.
- **Before PoWit:** the coinbase has exactly one output, worth at most
  subsidy + fees, paid to an address of the miner's choice. 100% of fees go
  to the miner.
- **From PoWit activation:** the subsidy splits 80% to the miner and 20% to
  16 witness-share slots (`core::witness_share::split_subsidy`). Each
  included share pays 90% of a slot to its payout script, and the miner gets
  the other 10% as an inclusion bonus. Coinbase output 0 pays the miner (at
  most its part plus 100% of fees); outputs `1..=n` pay the shares exactly.
  Empty slots are not issued, so mined issuance can only fall below the
  schedule above, never exceed it. See
  [DESIGN-witness-shares.md](DESIGN-witness-shares.md).

## Fees

Every non-coinbase transaction must pay, by consensus,

```text
min_fee = max(10,000, ceil(size_bytes × 2,000 / 1,000))   base units
        = max(0.0001 GNB, 0.00002 GNB per kB)
```

A typical one-input, two-output transaction (hybrid ML-DSA-65 + Falcon-1024
signature and public key, about 8.6 kB) pays at least about 0.00017 GNB. When
the subsidy is exhausted, fees are the only miner revenue, and this floor
keeps it from going to zero.

## Bloch Genesis-3 carryover

The genesis ledger is the Bloch Genesis-3 terminal snapshot, the same file
Bloch Genesis-4 opened with (`genesis/bloch-g3-carryover.tsv.gz`):

| | |
| --- | --- |
| Rows | 452,726 |
| Total | 3,810,744,000 BLCH |
| SHA3-256 (uncompressed) | `3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d` |
| SHA-256 (uncompressed) | `84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6` |

Conversion, per output: `gnb = floor(blch × 1,000,000 GNB / 3,810,744,000 BLCH)`,
same owner hash. A Genesis-3 block reward of 8,400 BLCH becomes 2.20429396 GNB.

- One row of value 0 converts to nothing and is dropped: 452,725 UTXOs are
  written.
- 38 rows carry vout `16777216`, a Bloch exporter defect (`1` written
  little-endian, read big-endian). GnB records them at vout `1`, the real
  Genesis-3 outpoint.
- The genesis coinbase text commits to the snapshot hash and the conversion.
- A node's first boot requires `--carryover-snapshot`; the file is verified
  (hash, rows, totals, converted totals) before anything is written, and the
  node refuses to start on any mismatch.

### Owners

Addresses are 20-byte public-key hashes and the address checksum covers only
the hash, so a Bloch address `bloch1q<hash><checksum>` is the GnB address
`gnb1q<hash><checksum>`. Wallet key derivation is unchanged from Bloch: the
same seed or keystore yields the same keys, which sign GnB transactions under
the GnB sighash domain. Signatures never replay between the two chains.
