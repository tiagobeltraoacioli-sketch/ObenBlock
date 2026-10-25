# ObenBlock monetary policy

Consensus rules, defined in `crates/gnb-crypto/src/core/tokenomics.rs`,
`crates/gnb-crypto/src/core/carryover.rs` and
`crates/gnb-crypto/src/core/witness_share.rs`. ObenBlock (ticker OBB) keeps
the four allocations of GnB's tokenomics, scaled to a 1,000,000 OBB cap
(owner decision, 2026-10-25). Its genesis carries no balance from the GnB
chain and pays the Bloch carryover from the same snapshot to the same keys,
converted proportionally to 8% of the cap. The subsidy ramps up over the
first 5,760 blocks (slow start, [DESIGN-obenblock.md](DESIGN-obenblock.md)
§3, §4.2). The constants are shared with the discontinued GnB chain; the 1%
payment fee and the fee split below are ObenBlock rules (GnB keeps the size
floor and 100% of fees to the miner).

## Hard cap: 1,000,000 OBB

| Allocation | Share | Amount |
| --- | --- | --- |
| Bloch Genesis-3 carryover | 8% | 80,000 OBB (79,999.99675352 issued after rounding) |
| Team, locked | 10% | 100,000 OBB |
| Founder, locked | 10% | 100,000 OBB |
| Mining | 72% | 720,000 OBB (at most 719,999.33953557 issued after rounding) |
| **Total, at most** | | **999,999.33628909 OBB** |

The slow start withholds about 246 OBB more, and empty witness slots and
rounding are never issued, so the real total is lower.

No pools. Every block's subsidy AND its transaction fees are split between
the miner (80%, plus an inclusion bonus) and the PoWit witnesses whose shares
the block includes (20%, in 16 slots); see [Rewards](#rewards).

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
| Tranche value | 100,000 OBB / 36 = 2,777.77777777 OBB, remainder in the last (2,777.77777805 OBB) |
| Founder | one key (1-of-1) |
| Team | m-of-n multisig |

The public keys live in `crates/gnb-crypto/genesis/vesting.json`; its
SHA3-256 is the consensus constant `VESTING_SPEC_SHA3`, and the genesis
coinbase text commits to it. Outpoints are synthetic, like the carryover:
`txid = SHA3-256("GNB-VESTING-v1" ‖ role ‖ k ‖ policy hash)`, `vout = 0`.
Until the file holds the keys, nodes refuse to create a genesis ledger.

## Mining subsidy

- Initial subsidy 0.08561643 OBB per block (floor(720,000 OBB / (2 × 4,204,800))),
  reached after the slow start (`floor(full × min(h, 5,760) / 5,760)`).
- Halving every 4,204,800 blocks (4 × 365 days at 30 s), by integer right
  shift in base units.
- The subsidy reaches zero after 24 halvings (height 100,915,200, about 96
  years) and stays zero. There is no tail emission.
- The genesis block pays nothing; mining starts at height 1.

## Rewards

PoWit applies from height 0 on ObenBlock. The subsidy and the block's total
fees are each split the same way (`core::witness_share::split_reward`):

- 20% of the amount goes to 16 witness-share slots; each included share pays
  90% of a slot to its payout script, and the miner gets the other 10% as an
  inclusion bonus;
- the miner gets the other 80%, plus the bonuses;
- slots left empty are not paid: not issued for the subsidy, burned for the
  fees. So the miner never gains by dropping other people's shares.

Coinbase output 0 pays the miner at most its part; outputs `1..=n` pay each
share exactly its slot of the subsidy plus its slot of the fees. See
[DESIGN-witness-shares.md](DESIGN-witness-shares.md).

## Fees

Every non-coinbase transaction must pay, by consensus,

```text
size_fee  = max(10,000, ceil(size_bytes × 2,000 / 1,000))        base units
value_fee = ceil(paid_to_others × 100 / 10,000)                  (1%)
min_fee   = max(size_fee, value_fee)
```

`paid_to_others` is the value of the outputs that are not change. An output
is change when its `script_pubkey` is the script of one of the coins the
transaction spends (`core::paid_to_others_sat`). A consolidation to oneself
pays the size floor only. Sending 1 OBB costs at least 0.01 OBB; a tiny
payment pays the size floor (a typical one-input, two-output transaction of
about 8.6 kB: about 0.00017 OBB).

The rule is checked on data the txid commits to (outputs and spent coins), so
no witness can lower it. A payee that contributes an input of its own to the
transaction makes its output "change" by this definition; that is the one
way around the 1%, and it needs the payee's signature.

## Bloch Genesis-3 carryover

The genesis ledger is the Bloch Genesis-3 terminal snapshot, the same file
Bloch Genesis-4 opened with (`genesis/bloch-g3-carryover.tsv.gz`):

| | |
| --- | --- |
| Rows | 452,726 |
| Total | 3,810,744,000 BLCH |
| SHA3-256 (uncompressed) | `3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d` |
| SHA-256 (uncompressed) | `84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6` |

Conversion, per output: `obb = floor(blch × 80,000 OBB / 3,810,744,000 BLCH)`,
same owner hash. A Genesis-3 block reward of 8,400 BLCH becomes 0.17634351 OBB.

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
