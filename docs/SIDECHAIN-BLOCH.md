# GnB ↔ Bloch sidechain

How GNB moves to the Bloch L2 (as wGnB) and back. This is the bridge of the
GnB chain as the code runs today; the ObenBlock relaunch
([DESIGN-obenblock.md](DESIGN-obenblock.md)) does not cover it yet. Two
models:

- **v1, set-once signers:** no new consensus rule on Bloch, and on GnB only
  the policy tree. Build first.
- **v2, cross light clients:** each chain verifies the other. A hard fork on
  both. Later.

Ecosystem plan: `~/Desktop/ECOSSISTEMA-BTC-BLOCH-GNB/PLANO-ECOSSISTEMA-v0.2.md`
(phase 1). The interface shared with the Bloch side, including message
formats and testnet hosts, is
`~/Desktop/ECOSSISTEMA-BTC-BLOCH-GNB/INTERFACE-PONTE-BLOCH-GNB.md`.

Rule for every model: **no periodic signing.** Keys, thresholds and caps are
fixed once, at deployment. A signer signs only what it rebuilt and verified
itself from its own nodes.

## v1: vault + set-once automatic signers

### Parties

| Party | Holds | Runs |
| --- | --- | --- |
| Signer `i` (n of them, 1 ≤ k ≤ n ≤ 7) | one hybrid GnB key + one key for the L2 contract | its own GnB node, a Bloch L2 follower, the signer program |
| Recovery holders | cold hybrid keys | nothing (used only in a disaster) |
| User | GNB or wGnB | a wallet |

### The vault (GnB side)

A **policy tree** output (`gnb1m…`, see [MULTISIG.md](MULTISIG.md)) with two
branches:

| Branch | Policy | Used for |
| --- | --- | --- |
| 0: release | `k`-of-`n` signer keys, no timelock | every bridge release |
| 1: recovery | `r`-of-`s` cold keys, `older = R` (relative) | only if the signers are lost |

`older` counts from each deposit's confirmation. A deposit left untouched for
`R` blocks becomes recoverable by the cold keys. With `R` = 1 year
(1,051,200 blocks) nothing ever needs refreshing, which keeps to the
no-periodic-signing rule.

The output commits to the root of the branches. A spend reveals only the
branch it uses and a Merkle path, so a release never reveals the recovery
keys. The policy tree is a consensus change on GnB (policy version 2),
active from the same height as PoWit: on in the testnet, off on mainnet. A
single-branch `k`-of-`n` vault (no recovery) works on mainnet today.

### Lock (GNB → wGnB)

A lock is an ordinary GnB transaction with this exact shape:

| Output | Script | Value |
| --- | --- | --- |
| 0 | the vault | the amount locked (≥ the minimum deposit) |
| 1 | **destination marker:** the 20-byte L2 (EVM) address, as a key-hash script | exactly `DUST_THRESHOLD` (546 base units) |
| 2… | anything (change) | any |

GnB has no `OP_RETURN`, but an EVM address is 20 bytes, the size of a GnB
key-hash script. Output 1 therefore carries the destination in a form every
node already accepts. Nobody can spend it: that would need a hybrid key
whose SHA3-256 starts with those 20 bytes, a 160-bit preimage. Each lock
burns 546 base units and leaves one dust output in the UTXO set. A
zero-value data output type would avoid both, at the cost of a hard fork
(see v2).

A lock is identified by `(txid, 0)`. Signers ignore anything that does not
match the shape exactly: a wrong marker value, a marker that is not 20 bytes,
the all-zero address, or the vault not in output 0. Coins sent to the vault
in any other shape stay in the vault, recoverable through branch 1.

### Depth before minting

| Situation | Signer waits for |
| --- | --- |
| Before PoWit (today) | **N = 1,000 confirmations** (~8.3 h): GnB nodes refuse reorganisations deeper than 1,000 blocks, so below that depth the signer's own node cannot move the lock |
| With PoWit active | the lock's block at or below the **finalized** checkpoint (`getpowitinfo`) |

While GnB runs on one miner, 1,000 blocks bounds the signer's node, not the
cost of rewriting history. Caps in the wGnB contract bound the loss.

### Mint (on the Bloch L2)

Each signer verifies the lock on its own GnB node: shape, depth, and that it
was never minted (the contract also refuses replays). It then signs the mint
message defined in the interface file: chain ids, `txid`, `vout`, amount and
L2 address. The contract mints after `k` valid signatures, within fixed caps.

### Burn (wGnB → GNB)

The user burns wGnB on the L2, naming a `gnb1…` address and an amount. Each
signer reads the burn at the L2 **finalized** level from its own follower
(FFG replay; no checkpoint signatures).

### Release (GnB side)

A release spends vault UTXOs through branch 0 with `k` signatures (`gnb-cli`
`vault-release` → `policysign` × `k` → `policysend`). Its exact shape:

| Output | Script | Value |
| --- | --- | --- |
| 0 | the burn's `gnb1…` address | burn amount − fixed release fee |
| 1 | **burn marker:** `SHA3-256("GNB-RELEASE-v1" ‖ burn id)[..20]` as a key-hash script | 546 |
| 2 | the vault (change) | the rest |

Before signing, each signer checks:
- the inputs are vault UTXOs;
- the outputs are exactly the three above;
- the fee is at most the fixed release fee;
- the burn is finalized on the L2;
- no release with this burn marker exists on GnB.

The burn marker makes every release auditable on chain: anyone can match
each burn to exactly one GnB transaction.

### Trust and limits

- **Honest k-of-n.** `k` colluding signers can mint without a lock, or release
  without a burn. The caps bound the damage per period and in total.
- **Liveness.** If more than `n − k` signers are offline, the bridge stops. The
  vault stays safe, and recovery after `R` needs the cold keys.
- **Post-quantum.** The GnB side is fully hybrid ML-DSA-65 + Falcon-1024. On
  the L2, the contract verifies the signers' keys with a precompile, or with
  secp256k1 keys, which are not post-quantum (decision on the Bloch side).

## v2: cross light clients (hard fork on both chains)

| Direction | What it needs |
| --- | --- |
| Bloch verifies GnB | A GnB header verifier on Bloch (an L1 rule or an L2 precompile) from a one-time pin. With PoWit it follows finalized checkpoints (64 KES-signed witnesses, ≥ 2/3 weight) instead of every header, and a lock is proven by a Merkle inclusion proof. |
| GnB verifies Bloch | A new GnB output type, "bridge vault", released only by a Bloch finality proof plus a burn inclusion proof. Bloch's validator set is followed from a one-time pin. Costly: ≥ 2/3 of the committee, ~4.6 KB per hybrid signature. |
| Data output | A zero-value `0x03 ‖ ≤ 80 bytes` output type for the L2 destination, instead of the dust marker. |

v2 removes the signers' trust assumption. It is a consensus change on both
chains and a large engineering effort, so it waits until v1 has run.

## Decisions (owner: the project)

| Decision | Recommendation |
| --- | --- |
| `k`-of-`n` signers | **3-of-5**, five machines run by different operators (tolerates two offline or two compromised) |
| Recovery branch | **2-of-3** cold keys, `older` = **1,051,200** (1 year) |
| Depth before PoWit | **1,000 confirmations** (the node's reorg limit), with low caps while GnB has one miner |
| Destination field | **Dust marker output** (works today); a data output type in the next hard fork |
| PoWit mainnet height | only once independent miners and witnesses exist (see the mainnet-readiness proposal) |
