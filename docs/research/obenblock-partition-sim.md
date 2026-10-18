# Partition simulator: current PoWit rules vs PoCI (ObenBlock O11)

Status: research note, 2026-10-18. Tool: `reference/sim/partition_sim.py`
(tests: `reference/sim/partition_sim_test.py`, results:
`reference/sim/partition_sim_results.json`, all Python, integer arithmetic).
Spec: `docs/DESIGN-obenblock-poci.md`, `docs/DESIGN-obenblock.md` §5.2 and
§6.3, `docs/CONSENSUS.md` "PoWit". No Rust change.

```text
python3 -I reference/sim/partition_sim.py            # summary table
python3 -I reference/sim/partition_sim_test.py -v    # required outcomes
python3 -I reference/sim/partition_sim.py --check    # results file is current
```

## Model

Deterministic, discrete events at checkpoint granularity: one slot = one
checkpoint (60 blocks), 12 slots per 6-hour epoch. Every voter on a branch
votes (justified checkpoint -> new checkpoint) and the vote is included in the
same slot (best case for liveness, so rule-1 double finalization is as early
as it can be). Casper FFG: a quorum link justifies its target, a justified
direct child finalizes its source. Witness weight = share work per epoch
(seeded history before epoch 0, no bootstrap). At a partition each side
builds its own branch; honest keys vote and mine on their side only; `byz`
keys vote and mine on every side. At heal, conflicting finalized checkpoints
keep their sticky pins (split); otherwise everybody adopts the branch with the
highest finalized checkpoint (ties: most share work since the fork, then the
label), and the other side's equivocation evidence and exit messages are
included in it. Honest signers keep a monotone record (PoCI §8).

| Rule set | Quorum | Weight | Absence | Exit / ban / expiry |
|---|---|---|---|---|
| R1-OBB | `3 got >= 2 total` | frozen finalized window (H2), 112 epochs | after 4 stalled epochs, absent members of W(e) lose half (`w -= w // 2`), reset on finalization | exit leaves W next epoch; ban at once; on the branch that included it |
| R1-GnB | same | 28 epochs | `w -= w // 16` | no exit message; ban at once |
| PoCI | `3 got > 2 total` | frozen `C_e` named by the vote, §6.3 growth cap, 112 epochs | none | only at the next handoff; ban 100 epochs |

## Results

Partitions start at epoch 2 (the last finalization is at slot 23, the end of
epoch 1). "yes@E": the side finalized a checkpoint above the fork in epoch E.
"split": the sides finalized conflicting checkpoints and stay apart after the
heal. Weights are shares of the configuration in force at the fork.

| scenario | rules | A/B | A final | B final | conflict epoch | resume epoch | evidence keys |
|---|---|---|---|---|---|---|---|
| 50/50, 2 epochs | R1-OBB / R1-GnB / PoCI | 50/50 | no | no | - | 4 | 0 |
| 50/50, 30 epochs | R1-OBB | 50/50 | yes@6 | yes@6 | **6** | split | 0 |
| | R1-GnB | | yes@17 | yes@17 | **17** | split | 0 |
| | PoCI | | no | no | - | 32 | 0 |
| 60/40, 30 epochs | R1-OBB | 60/40 | yes@6 | yes@7 | **7** | split | 0 |
| | R1-GnB | | yes@10 | yes@23 | **23** | split | 0 |
| | PoCI | | no | no | - | 32 | 0 |
| 70/30, 30 epochs | R1-OBB | 70/30 | yes@2 | yes@8 | **8** | split | 0 |
| | R1-GnB | | yes@2 | yes@31 | **31** | split | 0 |
| | PoCI | | yes@2 | no | - | 32 | 0 |
| 50/50, window + 8 | R1-OBB / R1-GnB | 50/50 | yes@6 / @17 | yes@6 / @17 | 6 / 17 | split | 0 |
| | PoCI | | no | no | - | 122 | 0 |
| 60/40, window + 8 | PoCI | 60/40 | no | no | - | 122 | 0 |
| 70/30, window + 8 | PoCI | 70/30 | yes@2 | no | - | 122 | 0 |
| exactly 2/3 vs 1/3 | R1-OBB | 66.7/33.3 | yes@2 | yes@7 | 7 | split | 0 |
| | PoCI | | no | no | - | 32 | 0 |
| 33 % equivocators on both sides | R1-OBB / R1-GnB | 67/66 | yes@2 | yes@6 | 6 | split | 33 |
| | PoCI | | yes@2 | no | - | 12 | 33 |
| 34 % equivocators on both sides | all | 67/67 | yes@2 | yes@2 | 2 | split | 34 |
| stall, 40 % offline epochs 3-15 (window 6) | R1-OBB | - | finalizes @8 in the stall | | - | 15 | 1 |
| | R1-GnB / PoCI | | no finality in the stall | | - | 15 | 1 |
| 50/50 epochs 2-12, exit + evidence on A only | R1-OBB | 50/50 | yes@7 | yes@6 | 7 | split | 1 |
| | R1-GnB / PoCI | | no | no | - | 12 | 1 |

The full table (every scenario under every rule set) is what
`partition_sim.py` prints.

Findings:

1. **Rule set 1 double-finalizes every long partition, with no evidence.**
   ObenBlock §5.2 (half leak): 50/50 at epoch 6 (slot 73), 24.5 h after the
   partition, nobody signs twice. One halving is enough because the quorum
   is inclusive (`3 x 50 >= 2 x 75`). GnB (1/16 leak): 50/50 at epoch 17
   (about 3.75 days); 70/30 at epoch 31, which is past the 28-epoch window.
   (DESIGN-obenblock.md §5.2 quotes about 30 h for 50 % of the weight; the
   model gives 24 h plus one checkpoint, because decay starts at the first
   boundary after 4 stalled epochs and the absent half then counts 25 at
   once.)
2. **PoCI never finalizes conflicting checkpoints with honest witnesses**, in
   any split, for partitions longer than the window, and with up to 33 %
   equivocating on both sides. Only a side holding more than 2/3 of the
   configuration in force at the fork advances (70/30 and the 67 % side of
   the 33 % case); exactly 2/3 does not.
3. **A conflict needs more than 1/3 to sign twice.** With 34 % equivocating
   on both sides both sides finalize under every rule set; under PoCI the
   evidence names keys holding more than 1/3 of the configuration (34 of
   100), which is the accountable-safety bound of §3/§11.
4. **After the heal finality resumes in the heal epoch**, with the frozen
   configuration (PoCI) or after one finalized side wins (70/30). No honest
   key is ever proven or has to refuse a vote.
5. **Exit, ban and expiry during a stall (§10).** PoCI keeps one
   configuration from epoch 2 to 15 on every node (and on both sides of a
   partition when only side A included the exit and the evidence); finality
   resumes at 15 with exactly one handoff `C_2 -> C_15`, which drops the
   exited key, the banned key (ban `[15, 115)`) and the expired key; every
   certificate keeps verifying against its named configuration. Rule set 1
   changes the denominator during the stall (590 -> 180) and differently on
   the two sides of a partition.

Consequences to carry into the Rust work and the spec:

- **Weight of an orphaned side.** After a partition longer than the window
  the first handoff after the heal computes the configuration from the
  winning branch only: the losing side's share work is on the orphaned
  branch, so its keys leave the configuration (50/50 + window: `C_122` holds
  only side A) and re-enter through new share work and the growth cap.
  Safe, but the winner of a tie (most work, then an arbitrary order) decides
  who keeps weight.
- **Thin configuration after a long stall.** The first configuration after a
  stall longer than the window holds only the keys that kept mining (3 of 10
  keys in the stall scenario); the returning keys are admitted at the growth
  budget. If those few keys go offline the chain stalls again until the next
  handoff. A floor on the entries of a configuration, or keeping the old
  configuration's keys for the first handoff, is worth a decision.

## Interpretations made in the simulator

- Handoff: `C_x` (x = the epoch of the newly finalized checkpoint, when
  x > the current config's epoch) is computed from the epochs `< x`; the
  window is the `window` epochs `x - window ..= x - 1` of growth-capped
  (admitted) work.
- §6.3 `R_k` is the admitted work of key k in the epoch leaving the window,
  not its raw work (with raw work a key whose work was cut by the cap could
  "renew" more than it holds and grow past `G_e`).
- Ban: `ban_start` is the epoch of the first configuration computed from a
  finalized checkpoint at or above the block holding the evidence. Share work
  mined while banned is not admitted (dropped, like work over the cap), so a
  key banned for `[s, s + 100)` is eligible at `s + 100` and holds weight from
  `C_{s+101}` (conservative reading of "may return by the ordinary rules (new
  share work)").
- Exit: the key stops voting at once and leaves at the next handoff after the
  exit is finalized; exits seen on an orphaned branch are included again in
  the surviving one.
- `config_id` uses a sim-local Merkle encoding; only its equality matters here.

## Results file (`partition_sim_results.json`)

`format: "obenblock-partition-sim/1"`, `slots_per_epoch`, `rule_sets` (the
parameters above) and `scenarios[]`, each with `name`, `title`, `witnesses`
(`[key, rate per epoch, role]`), `sides`, `start`, `heal` /
`heal_after_window`, `window_override`, `events` (`[epoch, kind, key, branch]`,
kinds `exit`, `equivocate`, `stop_mining`), `offline` (`key: [from, to)`) and
`results[rule set]`: `conflict_slot` / `conflict_epoch`, `split_after_heal`,
`resume_epoch`, `branches[label]` (`finalized_slot`, `finalized_in_partition`,
`first_finalized_after_fork_epoch`, `weight`, `weight_pct_x100`),
`original_total`, `evidence_keys`, `honest_evidence`, `refused_votes`,
`certificates_verify`, optional `stall` (`finalized_during`, `resume_epoch`,
`totals`), and for PoCI `handoffs[]` (`at_slot`, `from_epoch`, `to_epoch`,
`config_id`, `total`, `entries`) and `bans` (`key: [start, end)`). A node-level
partition test can replay a scenario's witnesses and events and compare these
outcomes (slots are checkpoint indices: height = slot x 60).
