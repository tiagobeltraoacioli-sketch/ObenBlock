# PoWit escrow: burning the rewards of an equivocating witness (design)

Status: **design, not implemented.** Today an equivocation proof bars the key
from the witness set and from new share rewards for `ban_epochs`. This
document adds the economic half: rewards the key already earned are held in
escrow and burned when it is caught.

## Goal

Make equivocation cost money, not only future income. A witness that signs two
conflicting checkpoints should lose every share reward it earned during the
window in which its vote carried weight.

## Rules

1. **Escrowed outputs.** From `powit_height()`, coinbase outputs `1..=n` (the
   witness-share payouts) mature after `ESCROW_BLOCKS` instead of
   `COINBASE_MATURITY` (100):

   | | Mainnet | Testnet |
   | --- | --- | --- |
   | `ESCROW_BLOCKS` | `window_epochs × epoch_len` = 20,160 (~7 days) | 60 |

   The miner output (index 0) keeps the normal 100-block maturity. Spending an
   escrowed output early is a consensus failure, enforced by the same check
   as coinbase maturity (`check_coinbase_maturity`, extended with the output
   index).

2. **Escrow ledger in the PoWit state.** `PowitState` gains
   `escrow: BTreeMap<KeyId, Vec<EscrowEntry>>`, where an entry is
   `(txid, vout, value, mature_at)`. Each block appends its share payouts and
   drops entries whose `mature_at` has passed. The ledger is part of the
   deterministic per-block state, so every node agrees on it.

3. **Burn on proof.** When a block carries an `Equivocation` for key `K`,
   every entry in `escrow[K]` is burned:
   - the outpoints are removed from the UTXO set when the block is applied;
   - the removal is recorded in the block's undo data, so a reorg that
     rolls the block back restores them exactly;
   - `escrow[K]` is cleared.

   Burned coins are destroyed: total supply only decreases, so the 1M cap
   still holds.

4. **No bounty.** The including miner gets nothing extra. A bounty would pay
   a colluding miner to "catch" its own sock-puppet key and recover part of
   the slashed value. Including evidence is still rational because the
   evidence also bars the key from the witness set, which protects the chain
   the miner is mining on.

## Why this shape

- **Deterministic:** the burn set is derived from chain state, not from
  scanning the UTXO set by address, so it cannot differ between nodes with
  different indexes.
- **Reorg-safe:** burns are ordinary UTXO deletions with undo records,
  reusing the path that `apply_block_atomic_with` and `execute_reorg_full`
  already take for spends.
- **Bounded:** `escrow[K]` holds at most the shares a key can earn in
  `ESCROW_BLOCKS` (≤ 16 per block), and entries leave the state as soon as
  they mature.

## Attack analysis

| Attack | Outcome with escrow |
| --- | --- |
| Equivocate, then spend rewards before being caught | Impossible: rewards are locked for the whole window |
| Equivocate on a fork that later loses | The proof is chain-independent and can be included on the winning chain |
| Split identity across many keys | Each key's escrow covers only its own weight; splitting changes nothing |
| Grief an honest witness with a fake proof | Impossible: both signatures must verify under the victim's key |
| Withhold the proof until escrow matures | Detection is automatic in every pool. Anyone can include it at any time inside the window, so the attacker would need every miner to collude |

## Implementation steps

1. `core::powit`: the `EscrowEntry` type, the `escrow` map, appending in
   `apply`, and the burn set returned from `apply` on an equivocation.
2. `core`: an `ESCROW_BLOCKS` parameter, and the maturity check by output
   index for coinbase outputs from activation.
3. `node/src/reorg.rs`: `apply_block_atomic_with` deletes the burn set and
   writes undo records; `rollback` restores them.
4. Wallet and RPC: show escrowed share rewards as locked until `mature_at`.
5. Tests:
   - burn then rollback restores the UTXO set byte for byte;
   - spending an escrowed output early is rejected;
   - escrow entries mature and leave the state;
   - burning on a fork and replaying on the winning chain gives the same set.
