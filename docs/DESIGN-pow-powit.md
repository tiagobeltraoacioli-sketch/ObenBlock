# PoW + PoWit (Proof of Witnesses)

A pure proof-of-work chain (no stake, no appointed validators) in which the
miners who *proved custody of the chain's witness data* over the last week
deterministically form the set that finalizes checkpoints with post-quantum
signatures. Built from three pieces:

| Piece | Code |
| --- | --- |
| Block PoW: GnB-SMH v3 (4 MiB, Argon2d-style fill) | `crates/gnb-smh/src/v3.rs`, `core::pow_algo` |
| Witness shares (custody proof + reward) | `core::witness_share`, `node/src/powit.rs` |
| Witness set, attestations, justification/finality, equivocation, decay | `core::powit` (pure state machine), `node/src/powit.rs` |

## Status

Implemented and consensus from `core::powit_height()`: mainnet from height
10,000 (`POWIT_HEIGHT_MAINNET`, since ef123fd); testnet off unless a node sets
it with `--testnet --powit-height <h>` (`POWIT_HEIGHT_TESTNET = u64::MAX`).

Implementation choices that refine the design below:

- **Witness set size 64** (not 256) before the second hardening activation:
  every attestation carries a hybrid public key and signature (~8 KiB), so
  64 members keep a full round of votes under ~0.5 MB per checkpoint. The
  cap let a minority split over many keys own the set (PoWit audit finding
  4), so from the second hardening activation (mainnet: not scheduled;
  testnet and regtest: 0) every share key with weight is a member and two
  thirds are measured over the total window weight (§3, §4, §7.9); the
  per-block cap of 32 attestations keeps the signature cost bounded.
- **Checkpoint slots.** Slot `c` names the highest selected-chain block with
  height strictly below `c`. Heights along a selected chain can skip, so a
  slot always resolves, identically on every node sharing that chain.
- **Work continuity.** v3 targets are 4x harder than the ASERT schedule and
  each v3 block's chain work is divided by 4, so cumulative work (and
  `MIN_CHAIN_WORK`) stays comparable across the switch.
- **Accountability.** An equivocation bars the key from the witness set and
  from share rewards for `ban_epochs`; burning already-paid share rewards
  (escrow) is not implemented.
- **Witness node.** `--witness-wallet <gnb-cli wallet> --witness-password-file <f>`
  mines shares paying that key (`--share-threads`, default 2) and signs the
  newest checkpoint once it is a member (from the second hardening
  activation: the justified checkpoint's direct child while a vote for it
  can still be included, else the newest; §7.9), with a persistent vote record that
  refuses any double or surround vote, across restarts and reorgs (written
  durably; an unreadable record refuses to start; the highest signed source
  and target heights are also kept beside the key file and enforced).
- **Node finality.** The node never reorganises below the height of the block
  its tip's chain finalized (`finalized_height`), in addition to the depth rule.
  (As implemented now: there is no depth rule, audit DAG-6, and the pin is
  `GhostDAG::set_finalized` from the applied tip's witness set, taken and
  restored only while the tip's blue work reaches the node's minimum chain
  work (`MIN_CHAIN_WORK` or `--minimumchainwork`; `powit::pin_finalized_of`,
  PoWit audit finding 3): a cheap chain an eclipsing peer feeds a node in
  initial block download is neither pinned, mined on nor advertised,
  docs/CONSENSUS.md. A fork's witness set still comes from the fork's own
  shares, not from finalized history; that is a consensus change for a
  later activation. Package A2, `node/src/finality.rs`: the pin is
  persisted and restored at start-up, moves only to a checkpoint that
  extends it, from any held block's state (§7.6 convergence), and a
  conflicting finalization raises an alert for the operator,
  `getfinalityinfo` / `setfinalitycheckpoint` / `ignorefinalized`.)

Parameters (`core::powit::MAINNET_PARAMS` / `TESTNET_PARAMS`):

| | Mainnet | Testnet |
| --- | --- | --- |
| Epoch | 720 blocks (~6 h) | 20 |
| Checkpoint interval | 60 (~30 min) | 5 |
| Window | 28 epochs (~7 days) | 3 |
| Witnesses (cap before the second hardening activation; none from it) | 64 | 64 |
| Attestations / block | 32 | 32 |
| Vote lifetime | 720 blocks | 20 |
| Decay starts after | 4 epochs without finality | 4 |
| Ban | 28 epochs | 3 |


## 1. Block PoW: GnB-SMH v3

```
V[0] = SHAKE256(seed(header, nonce))
pass 0: V[i] = SHAKE256(V[i-1] ‖ V[r] ‖ i ‖ 0),  r = V[i-1] mod i
pass p: V[i] = SHAKE256(V[i-1] ‖ V[r] ‖ i ‖ p),  r = V[i-1] mod N
out  = SHAKE256(DS_FINAL ‖ V[N-1])        N = 2^15 blocks of 128 B (4 MiB), 2 passes
```

| | v1 (live) | v3 (from activation) |
| --- | --- | --- |
| Memory | 64 MiB | 4 MiB |
| Verify (Mac, 1 core) | 527 ms | 90 ms |
| Fill | plain hash chain (linear TMTO) | each block depends on a content-chosen earlier block (cascading TMTO, as Argon2d) |
| Grover | needs 64 MiB QRAM, 1M sequential steps | needs 4 MiB QRAM, 65k steps of 2 permutations; dropping memory to save QRAM cascades |

The hash is replaceable: the same structure with SHA-256 is a one-function
change (see v2). Off-the-shelf Bitcoin ASICs still cannot run it.

## 2. Witness shares

A GnB-SMH v3 proof 16× easier than a block that attests one of the last 16
blocks on the including block's selected chain. Every nonce pulls 8 random
64-byte chunks of that block's transactions (signatures included) into the
PoW input. 20% of the subsidy pays up to 16 shares per block. Each share
names the witness id it credits and pays any valid script. See
[DESIGN-witness-shares.md](DESIGN-witness-shares.md).

## 3. The witness set (deterministic, from the DAG)

- Epoch = 720 blocks (~6 h). Window = 28 epochs (~7 days).
- The weight of a witness id in epoch `e` is the total work of the shares
  credited to it in selected-chain blocks of epochs `e-1-window … e-2`. The
  two-epoch lag means forks shallower than an epoch agree on the set.
- W_e = the **64** heaviest witness ids (ties by id), minus barred ids, with
  inactivity decay applied. Every node computes the same W_e from the chain:
  no registration, no stake, no vote.
- From the second hardening activation (blocks at or above it): W_e = every
  witness id with weight, minus barred ids, decay applied (no cap). With the
  cap, 30% of the share work split over 60 keys of 0.5% against 200 honest
  keys of 0.35% held 95.5% of W_e (finding 4).

## 4. Checkpoint attestations

- A checkpoint slot every 60 heights from activation. Slot `c` names the
  highest selected-chain block with height strictly below `c`.
- Each member of W_e signs a link `source → target` (source = the chain's
  current justified checkpoint) over `DS ‖ chain_id ‖ source ‖ target`; for a
  target at or above the second hardening activation over
  `DS_v2 ‖ chain_id ‖ depth ‖ root ‖ source ‖ target`, which also commits its
  KES key (finding 1: without it one leaf signature, re-rooted under any
  sibling hash, was a signature by unlimited keys). Byte layouts:
  docs/CONSENSUS.md, "PoWit", "Attestation messages". The signature uses its
  forward-secure KES key, with the leaf of the target's epoch
  ([DESIGN-powit-kes.md](DESIGN-powit-kes.md)).
- Attestations are gossiped as `NewPowitItem` (kind 2), validated before
  relay, and included in blocks (up to 32 per block).
- Links worth ≥ 2/3 of W_e's weight **justify** the target (from the second
  hardening activation W_e has no cap, so this is two thirds of the total
  window weight of every share key, as Casper FFG counts all stake). A justified
  target exactly one interval above its source **finalizes** the source.
  Nodes never reorganise below the finalized block.

## 5. Accountability without stake

Two attestations by one witness with the same target slot and different
blocks (double vote), or one link surrounding another (surround vote), form
an equivocation proof. Any block may carry it (kind 3 on the wire); from
the second hardening activation only against a key that is a member of
W(E-1), W(E) or W(E+1), E the including block's epoch (a key nobody holds
share work for cannot be barred, finding 1; the rule and why those three
sets: docs/CONSENSUS.md, "PoWit", "Equivocation proofs"). The
witness is barred from the witness set and from share rewards for
`ban_epochs` (28 epochs on mainnet).

Burning rewards already paid to the witness (escrow) is designed in
[DESIGN-powit-escrow.md](DESIGN-powit-escrow.md) but **not implemented**.
Today the penalty is the ban.

## 6. Liveness fallback

If no checkpoint finalizes for 1,000 blocks, the chain keeps running as pure
PoW under the depth-finality rule (`CHECKPOINT_DEPTH`) until attestations
resume. Finality can stall; block production cannot.

## 7. Hardening (revision 2)

### 7.1 Two ledgers: available and final ("ebb-and-flow")

Impossibility results bound every design: no permissionless protocol is
both always available and always consistent under network partitions (CAP),
and deterministic agreement needs fewer than 1/3 faulty weight under partial
synchrony (Dwork–Lynch–Stockmeyer). PoW + PoWit therefore keeps **two
ledgers** (Neu–Tas–Tse, 2021):

- **LOG_avail**: the GHOSTDAG order of the PoW DAG. Always grows while
  honest miners hold a hashrate majority, even with most witnesses offline
  or the network partitioned.
- **LOG_fin**: the prefix of LOG_avail up to the last finalized checkpoint.
  Never reverted while < 1/3 of the witness weight is Byzantine, whatever the
  network delays.

LOG_fin is always a prefix of LOG_avail. Users pick their guarantee:
fast/probabilistic (LOG_avail) or deterministic (LOG_fin).

### 7.2 Byzantine generals mapping

| Generals problem | PoW + PoWit |
| --- | --- |
| Generals | Members of the witness set W_e (earned by custody work, not chosen) |
| Messages | Attestations signed with ML-DSA-65 ‖ Falcon-1024 (unforgeable, also against quantum adversaries) |
| Traitors | Any member; tolerated while their weight is < 1/3 of W_e |
| Agreement | Two checkpoints at the same height can never both finalize unless ≥ 1/3 of the weight signed both, and that is provable on chain |
| Sybil generals | Weight is work, so splitting a key into many keys gains nothing: true from the second hardening activation (two thirds of all the weight); before it, the 64-key cap let a minority split over many keys own W_e (finding 4) |

### 7.3 Vote rule with accountable safety

Each attestation is a link `source → target` between two checkpoints
(source = the latest justified checkpoint the signer knows):

- a checkpoint is **justified** when links from a justified source carry
  ≥ 2/3 of W_e; it is **final** when its direct child checkpoint is justified
  from it;
- **slashable** (escrow burned, key barred for K epochs): two different
  targets at the same height (double vote), or a link that surrounds another
  link by the same key (surround vote).

Theorem (as in Casper's accountable safety): two conflicting final
checkpoints imply that keys holding ≥ 1/3 of W_e broke one of the two rules
(from the second hardening activation ≥ 1/3 of the total window weight;
before it ≥ 1/3 of the 64 heaviest keys' weight only),
and the evidence is publishable in any block. The voters here are earned by
PoW custody work; there is no stake and no appointed validator.

### 7.4 Agreeing on who the generals are

W_e is computed only from **LOG_fin as of the end of epoch e-2**. Every honest
node therefore derives the same set, even while LOG_avail tips disagree. If
nothing has finalized for two epochs, W_e = W_{e-1}.

### 7.5 Finality liveness: inactivity decay

If no checkpoint finalizes for 4 epochs, the weight of every member whose
attestations are not being included decays by 1/16 per epoch (deterministic,
from included attestations only). Online members regain 2/3 and finality
resumes, so > 1/3 offline or withholding can only delay finality, not stop it.

### 7.6 Fork choice

Heaviest blue-work DAG **among the branches that contain the latest final
checkpoint**. A partitioned side may keep producing blocks (LOG_avail), but
at most one side can finalize, and the other side rejoins it on heal.

### 7.7 Other attacks

- **Selfish mining / withholding**: witness shares pay every 16× easier
  proof, so small miners earn without pools and withheld blocks forfeit
  their share slots.
- **Long-range rewrite**: impossible past LOG_fin for online nodes; new
  nodes start from `MIN_CHAIN_WORK` + the release checkpoint (weak
  subjectivity, as every finality protocol).
- **Bribing witnesses**: the bribe must exceed the 7-day escrow of ≥ 1/3 of
  the weight, and the attack is attributable.
- **Data withholding**: a block whose data no one can sample earns no shares
  and no attestations.

### 7.8 What remains impossible (honest limits)

- A sustained > 2/3 majority of the 7-day witness weight controls LOG_fin.
- A hashrate majority still controls LOG_avail after the last final checkpoint.
- Finality needs partial synchrony: during long partitions, LOG_fin stalls
  (by design it never forks).

### 7.9 Witness-set size and finality liveness (second hardening activation)

From the activation every share key with weight may vote and two thirds are
counted over all of them. Signature cost stays bounded per block (32
attestations and 4 proofs, at most 40 KES verifications), so what the
uncapped set costs is inclusion bandwidth: a vote for slot `t` is includable
in blocks `t ..= t + vote_ttl`, at most 23,072 votes per target on mainnet
(672 on testnet). With `K` the smallest number of keys (heaviest first)
holding two thirds of the weight, a slot takes `ceil(K / 32)` blocks to
justify:

- `K <= 32 × checkpoint_interval` (1,920 keys on mainnet, 160 on testnet):
  finality keeps pace with the chain, one interval per interval.
- Above that, finality falls behind and becomes intermittent: the witness
  duty votes for the justified checkpoint's direct child (the only target
  whose justification finalizes, as in Casper FFG) while a block can still
  include the vote, then for the newest slot.
- Above `32 × (vote_ttl + 1)`, no slot is justified until the inactivity
  leak (§7.5) has decayed the keys whose votes were not included.

The 64-key cap bounded `K` by 64 but measured two thirds over those 64 only,
so a minority split over many keys controlled or stalled finality
(finding 4). The rule from the activation keeps the guarantee Casper FFG
states, two thirds of all the weight, and pays for it with finality latency
when the share work is spread over thousands of keys. Templates take a
target's heaviest votes first and a full pool evicts the entry closest to
expiry, lightest first, so a flood of one-share keys cannot push honest
weight out of honest blocks; an attacker
with under a third of the weight can neither justify alone nor stall
finality (the honest keys justify without it). Numbers and tests:
docs/CONSENSUS.md, "PoWit", "Safety and liveness from the activation".

## What it buys against a 51% attacker

| Attacker | Bitcoin | PoW + PoWit |
| --- | --- | --- |
| Rents >50% hashrate for hours | Can reorg as deep as its lead allows | Reorgs at most the ~60 blocks after the last final checkpoint |
| Rents >50% for days | Same, deeper | Same bound; it is still a minority of the 7-day witness weight |
| Holds >1/3 of the 7-day witness weight | — | Can stall finality (chain keeps running) |
| Holds >2/3 of the 7-day witness weight | — | Controls finality; equivocating burns its escrow |
| Mines without the data (SPV mining) | Allowed | Earns no shares, never enters W |

Honest limits:

- This does not make a sustained majority harmless; nothing permissionless
  can. It moves the bar from *hashrate now* to *proven contribution over
  the last week*, and makes reverting finalized history cost the escrow.
- Long-range forks that rebuild W from far back are stopped by nodes already
  online and, for new nodes, by `MIN_CHAIN_WORK` and the release checkpoint
  (weak subjectivity).
- Not externally reviewed; parameters (window, epoch, 2/3, the 32 votes per
  block that bound finality latency from the second hardening activation)
  need simulation at mainnet scale.
