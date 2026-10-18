# Witness shares

Consensus **from `core::powit_height()`**, together with GnB-SMH v3 and PoWit
finality (see [DESIGN-pow-powit.md](DESIGN-pow-powit.md)). Mainnet keeps the
activation off (`POWIT_HEIGHT_MAINNET = u64::MAX`); a testnet node sets it
with `--testnet --powit-height <h>`.

Code: `crates/gnb-crypto/src/core/witness_share.rs` (rules), `node/src/powit.rs`
(context checks, pool, template, share miner).

## What it rewards

Proven custody of recent block data, witnesses included. A *witness share*
is a GnB-SMH v3 proof 16× easier than a block. It attests a block `B` on the
including block's selected chain, at most 16 heights below it. Each nonce
selects 8 pseudo-random 64-byte chunks of `B`'s transaction stream (every
transaction's wire bytes, signatures included), and those bytes are part of
the PoW input. Without `B`'s full data you cannot try a single nonce, so
blind (SPV) mining earns nothing.

```
stream(B) = wire(tx_0) ‖ wire(tx_1) ‖ …                         64-byte chunks
binding   = witness ‖ SHA3(payout)
idx_k     = SHA3(DS_IDX ‖ attested ‖ SHA3(binding) ‖ nonce ‖ k) mod n_chunks
preimage  = enc(DS_POW) ‖ attested ‖ witness_root(B) ‖ witness ‖ SHA3(payout) ‖ bits
            ‖ chunk[idx_0..7]
valid    <=> GnB-SMH v3(preimage, nonce) < 16 × target(bits of B)
```

- `attested` is the block id (`Block::block_hash`).
- `witness` is the 20-byte witness id of a forward-secure KES key
  ([DESIGN-powit-kes.md](DESIGN-powit-kes.md)). The share's work counts
  toward that witness's weight in the witness set.
- `payout` is any valid output script (a key hash or an m-of-n policy).
  Identity and money are separate, so rewards can go to a cold wallet.

Both `witness` and `payout` are inside the preimage, so a share cannot be
re-pointed to another witness or another payout after it is mined.

## Money

| Parameter | Value |
| --- | --- |
| Pool for shares | 20% of the block subsidy |
| Slots per block | 16 (`MAX_SHARES_PER_BLOCK`) |
| Attester per share | 90% of a slot ≈ 0.01204 GNB at the initial subsidy |
| Miner inclusion bonus | 10% of a slot per included share |
| Empty slots | not issued (the cap stays an upper bound) |

The miner gets 80% of the subsidy, plus fees, plus 10% of every slot it fills.
Including someone else's share therefore always pays more than dropping it,
and dropping it never moves the attester's money to the miner. Coinbase
layout from activation: output 0 to the miner, then one output per share, in
order, paying exactly `per_attester` to that share's payout.

## Block rules

- At most 16 shares, and no duplicate `share_id` in the block or on the
  selected chain within the window.
- Each share attests a selected-chain ancestor at height `h-16 … h-1`, with
  the attested block's own `bits`.
- Each share meets the share target, and its payout is a valid script.
- The coinbase pays every share exactly, as above.
- A share credited to a barred witness (one proven to have equivocated)
  makes the block invalid.

## Cost

Each share is one GnB-SMH v3 verification (~90 ms on one core); a full block
of 16 shares adds ~1.4 s. A peer can only make a node verify shares after
presenting a block with a valid proof of work, and verified shares are
cached by id.

## Relay

Shares travel as `NewPowitItem` (kind 1). They are validated before relay,
with the same per-peer budget as transactions, and wait in the node's PoWit
pool until a template includes them.

## ObenBlock: SHA-256d shares

On a chain that runs the SHA-256d proof of work (ObenBlock,
[DESIGN-obenblock.md](DESIGN-obenblock.md) §6) the share proof is an
80-byte SHA-256d header a Bitcoin ASIC mines
(`crates/gnb-crypto/src/core/witness_share/sha256d.rs`; reference
`reference/obb_shares.py`). The eight chunks are sampled per *job*
(`job_nonce`, the share's `nonce` field) and committed in the header; the
ASIC rolls the 32-bit nonce and the BIP 320 version bits. The header's
`time` must equal the attested block's timestamp, so no job outlives its
2^48 attempts. Verification is about a dozen SHA-256d (under 1 KiB in all) plus
assembling the stream. Rewards, slots, the share window (16 heights) and the
block rules are the ones above. The witness weight window is 112 epochs
(28 days) instead of 28; docs/CONSENSUS.md, "Witness shares on SHA-256d".

A node runs the CPU share miner on SHA-256d too (`--witness-wallet`), one
job per round; that is for regtest. Mainnet shares need an ASIC and a job
server (`ShareJob`: the header template and the chunks it committed to).

## Open

- Whether share work should also count in fork choice. Today shares pay and
  select witnesses; they do not add chain work.
