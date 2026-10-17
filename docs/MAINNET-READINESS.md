# GnB mainnet readiness (proposal, not applied)

This proposal concerns the GnB chain. ObenBlock relaunches the code base with
a clean genesis ([DESIGN-obenblock.md](DESIGN-obenblock.md)) and has no
mainnet yet.

Status on 14 Oct 2026 (read-only, from the running node):

| | |
| --- | --- |
| Nodes | one (152.236.5.112), 0 peers, mining with 28 threads |
| Tip | height 8,302, blue score 9,023, chain work 7,782,451 |
| Proof of work | GnB-SMH v1 (64 MiB); PoWit, SMH v3 and policy trees off (`POWIT_HEIGHT_MAINNET = u64::MAX`) |
| `MIN_CHAIN_WORK` | 0 (7,000,000 from the release after it, §1) |
| DNS seeds | none |

Only §1 is applied (2026-10-16). Each item is a release decision.

## 1. `MIN_CHAIN_WORK`

**Why.** With 0, a fresh node accepts any chain from genesis, including a
fake one fed by an attacker who isolates it.

**Proposal.** At every release, set it to the chain work of a block buried
at least about one week below the tip at release time. Never use the tip
itself: a node must still be able to sync while the network keeps growing.

| Release | Value |
| --- | --- |
| Next release (if cut today) | **7,000,000** (tip 7,782,451; leaves room below the tip) |
| Later releases | the work of the tip minus ~20,160 blocks (one week), rounded down |

A value the real chain has not reached keeps every new node in initial
block download, so a low value is safe and a high value is harmful. Err
low. (Finality, a reorg-depth cap and pruning do not read it: the depth
rules are gone since audit DAG-6, pruning keeps undo records, and the
PoWit pin reads the witness set.)

**Applied (2026-10-16): `core::MIN_CHAIN_WORK = 7_000_000` (0x6acfc0).**
The reading above is in the constant's unit: `getdaginfo` `tip_blue_work`,
the selected tip's blue work (below the hardening activation, the sum of
`core::block_work` over the selected chain: 4,500 per block at the genesis
target, 1 at the pow limit, v3 blocks divided by 4 so the sum is continuous
across the switch at 10,000). It is consistent with the ASERT schedule: at
04:25 UTC the chain was 573 blocks behind schedule, where a block's work is
859, and a steady ~29 v1 evaluations/s from genesis gives height ~8,308 and
work ~7.77M then (model 859 * 8,875 = 7.62M; the reading is 2% above it;
`core::min_chain_work_tests`). 7,000,000 is 10% below the reading (the work
of a block about 900 below that tip, near height 7,400), and the mainnet tip
was near 14,500 when it was set, so it lies about 7,000 blocks (over two
days) below the tip, more than the one-day margin of the release tool.
Even if the reading were 28% too high (the work of a chain mined at 0.07 x
H0 until the 2,888 reading of 12 Oct and steadily after it: 5.6M at 8,302),
the real chain passes 7,000,000 by about height 9,900, some 4,500 blocks
below the tip of 2026-10-16. Later releases: `tools/release/min_chain_work.py` on two or more
independent nodes (docs/RUNNING.md, "Initial sync and minimum chain work").

**Assumed-valid block (P5-G, not set).** The same tool prints the release's
assumed-valid block (`assumevalid::MAINNET_ASSUME_VALID`, Bitcoin Core's
`defaultAssumeValid`) from the same block. It saves signature checks only for
blocks more than two weeks of chain work below a node's best block, so it has
no effect before the chain is that deep; set it from the first release cut
after that.

## 2. Seeds

- **Hardcoded peers** in the release: at least three nodes run by different
  operators on different providers.
- **DNS seeds** under the project domain: `seed1.gnb-smh.com`,
  `seed2.gnb-smh.com`, `seed3.gnb-smh.com`, each answering with several node
  addresses, run by at least two different people.
- **Pinned post-quantum P2P keys** (`p2p_pq_pins.json`) for the seed nodes,
  published with the release.

## 3. Leaving the single node

Today one machine mines, validates and stores the chain. Any outage halts
it, and any operator mistake is final.

| Step | Goal | Done when |
| --- | --- | --- |
| 1 | Publish binaries, `RUNNING.md`, the seed list and the pinned P2P keys | a stranger can join from the docs alone |
| 2 | Two archival nodes (`--archive`) on separate providers | a fresh node syncs from genesis with the main node offline |
| 3 | At least three independent miners (different operators, machines and payout keys) | no single coinbase address finds more than 50% of blocks for 7 days |
| 4 | Public testnet with PoWit (§4) running at least two weeks | the adversarial tests (double vote, silent witnesses, private fork below finality) pass on it |
| 5 | Monitoring: tip age, peer count, orphan rate, reorg depth | alerts reach more than one person |

## 4. PoWit activation (mainnet)

A witness set needs many independent witnesses. With one miner, PoWit
finalizes whatever that miner wants. That is no worse than today, but it
adds nothing.

**Activation criterion (all of):**
1. Steps 1 to 4 of §3 are done.
2. An external audit of `core::powit`, `core::kes`, `core::witness_share` and
   the policy trees in `core::policy`, with its findings fixed.
3. On the public testnet, at least **10 distinct witness ids** each hold at
   least 1% of witness weight, and none holds more than 33%, for 7 days.
4. On mainnet, no single coinbase address finds more than 33% of blocks over
   the 14 days before the height is fixed.

**Height.** Announce at least **6 weeks** ahead: `activation = tip at
announcement + 120,960` (6 × 20,160 blocks), rounded up to a multiple of the
epoch length (720). The height goes into `POWIT_HEIGHT_MAINNET` in a release
that every node must run before it.

PoWit, GnB-SMH v3 (the target becomes 4× harder, with chain work continuous
across the switch), witness-share payouts and policy trees (bridge vault
recovery) all switch at that height.

## 5. Bridge parameters tied to readiness

| Parameter | Before PoWit | With PoWit |
| --- | --- | --- |
| Lock depth before mint | 1,000 confirmations (the node's reorg limit) | the lock's block at or below the finalized checkpoint |
| Vault type | single-branch `k`-of-`n` (no recovery: trees are off) | two-branch tree with cold recovery after `older` = 1 year |
| Caps | low (the chain has one miner) | raised as miners and witnesses diversify |

## Decisions (owner: the project)

| Decision | Recommendation |
| --- | --- |
| `MIN_CHAIN_WORK` next release | 7,000,000 (applied, §1) |
| Seeds | 3 hardcoded peers + 3 DNS seeds, two or more operators |
| PoWit mainnet height | none yet; fix it only when §4 criteria 1-4 hold, 6 weeks ahead |
| Lock depth N before PoWit | 1,000 |
