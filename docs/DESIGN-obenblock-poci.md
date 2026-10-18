# PoCI: Proof of Corruption or Integrity (ObenBlock strict finality)

Status: design, 2026-10-18 (owner request, from the technical note
"Votes on shares, compact proofs and safe finality", P0 items).
Applies to ObenBlock only; GnB keeps its PoWit rules. Package O11.

PoCI is the strict finality profile of PoWit on ObenBlock. Every finality
decision ends in exactly one of two verifiable objects:

- **Proof of Integrity**: a finality certificate. Votes worth **more than
  two thirds** of one frozen, authenticated configuration link a justified
  source to its direct child.
- **Proof of Corruption**: equivocation evidence. Two votes signed by the
  same key, under the same configuration, that the rules forbid (double or
  surround vote). The key is excluded for 100 epochs.

Nothing else changes the finality weight of a decision: no absence, timeout,
partition or local clock.

## 1. The problem it fixes

DESIGN-obenblock.md §5.2 (faster inactivity leak) lets each side of a
partition decay the weight of the voters it does not see. Each side then
counts against its own, smaller total and both can finalize, with nobody
signing twice. With 100 units split 50/50 and decay by half per epoch:

| step | local weight | remote weight seen locally | local fraction |
|---|---|---|---|
| before decay | 50 | 50 | 50.00 % |
| one halving | 50 | 25 | 66.67 % |
| two halvings | 50 | 12.5 | 80.00 % |

The fix: absence never redefines who counts toward the quorum of the same
finality instance.

## 2. Configuration

For each epoch `e` the configuration `C_e` is the registry of finality
voters:

```text
entries_e  = sorted (key_id, weight) for every eligible key, weight > 0
             (weights from finalized history, the window and the growth cap
             of DESIGN-obenblock.md §6.3; keys banned in e excluded)
total_e    = sum of weights in entries_e
config_id  = SHA-256d("OBB-POCI-v1/config" ‖ u32le(chain_id) ‖ u64le(e)
                      ‖ u128le(total_e) ‖ merkle_root(entries_e)
                      ‖ params_digest)
```

- `params_digest` commits to the PoWit parameters in force (window, epoch
  length, thresholds, ban length), so two nodes with different rules never
  share an id.
- A vote names its `config_id` (attestation message v3:
  `DS ‖ chain_id ‖ config_id ‖ source ‖ target`). A vote counts only for the
  configuration it names, with the registry's weight, never a weight the
  voter states.
- `C_e` is fixed while it is in force. Its weights, total and eligibility do
  not change for any reason.

## 3. Quorum (strict)

```text
quorum(C, votes) <=> 3 × sum(weight of distinct keys of C voting the link) > 2 × total(C)
```

- Strictly more than two thirds (GnB counts `>=`). Any two quorums of one
  configuration then intersect in more than one third of its weight, so with
  under a third Byzantine weight the intersection holds an honest key, and
  the voting rules (§5) keep that key from supporting both.
- Justification and finality follow Casper FFG as today: a supermajority
  link from a justified source justifies the target; a justified direct
  child finalizes its source.

## 4. Handoff: how a configuration changes

- `C_{e+1}` enters into force only when the checkpoint that opens epoch
  `e+1` is **finalized under `C_e`**. The registry then advances by one
  epoch.
- Until that happens `C_e` stays in force: votes keep naming it, its weights
  do not expire, and new share work waits in the finalized history for the
  next handoff. The window advances only through handoffs, so partitions
  cannot age it differently.
- Exits (the KES-signed exit message of §5.2), bans and expiring weight take
  effect at the next handoff, never in the current configuration.
- A handoff may skip epochs: when `C_e` finalizes a checkpoint of epoch
  `e+k`, the next configuration is `C_{e+k}`, computed from the finalized
  history up to that checkpoint.

### 4.1 Absence pruning by the old committee (owner, 2026-10-18)

Dead weight is removed **by the current configuration, while it still has its
quorum**, never by a local timeout:

- A key of `C_e` whose votes were not included in any block of the finalized
  history during the last `PRUNE_AFTER = 4` epochs (24 h) is left out of the
  next configuration. The rule reads only finalized history, so every node
  computes the same set, and it takes effect through the handoff, which more
  than two thirds of `C_e` finalized: the old committee authorizes it.
- A pruned key returns by publishing a **rejoin** message signed with its KES
  key; once that message is in finalized history, the key's share work counts
  again from the next handoff, as new weight under the growth cap
  (DESIGN-obenblock.md §6.3).
- `getpowitinfo` reports the absent weight of `C_e` per epoch, so operators
  see it grow long before it reaches a third.
- What it covers: weight that fades out (operators going offline over
  hours or days). What it cannot cover: more than a third of `C_e` vanishing
  at once. Then `C_e` has no quorum to authorize anything and finality halts
  until the weight returns or the coordinated recovery of §7. No rule inside
  one partition can safely decide that the old committee is gone.

**The inactivity leak does not apply to finality weight on ObenBlock.**
DESIGN-obenblock.md §5.2 is replaced by this section for finality; block
production (§5.1 stall relief) is unchanged.

## 5. Proof of Corruption

Evidence is two attestations by the same key under the same `config_id`:

- **double vote**: same target height, different targets;
- **surround vote**: one link strictly surrounds the other
  (`s1 < s2 < t2 < t1`).

Rules:

- Valid evidence is included in a block like today's equivocation proofs.
  It is checked against the named configuration's registry (the key must be
  an entry of it).
- **Exclusion**: `ban_start` = the first configuration that enters into
  force after the block holding the evidence is finalized. The key is
  ineligible for every epoch `ban_start <= e < ban_start + 100` (72,000
  blocks, about 25 days at nominal cadence). The epoch is the protocol's,
  never a local clock.
- No retroactive effect: the ban does not change `total` or any vote of a
  configuration already in force or past.
- After the ban the key may return by the ordinary rules (new share work);
  weight that expired meanwhile is not restored.
- **Never punished**: absence, slowness, a vote that was not included, a
  vote for a branch that lost, a refusal to vote for an invalid block. These
  are not evidence: an attacker who can cut honest nodes off must not be able
  to turn that into bans.
- Without stake, the exclusion and the lost share rewards of the window are
  the whole penalty. PoCI makes corruption **detectable and attributable**,
  not costly beyond that.

## 6. Proof of Integrity: the finality certificate

```text
certificate = (version, chain_id, config_id, source, target,
               votes: sorted by key_id, each (key_id, signature))
```

- Verification: the configuration registry (from the chain, or shipped with
  the certificate as entries + Merkle paths), each signature over the exact
  v3 message, distinct keys, strict quorum.
- RPC `getfinalitycertificate <checkpoint>` serves it; nodes keep the
  certificates of every finalized checkpoint (they are what the node already
  stores as included votes).
- Size: PQ signatures make it large (a hybrid ML-DSA-65 + Falcon-1024
  signature alone is about 4.6 kB). A compact proof of the certificate
  (STARK for the PQ goal) is research (P1), not a requirement of PoCI.
- Bloch anchors (DESIGN-obenblock.md §8) stay advisory until the anchor
  registry verifies a certificate; then the record carries the certificate
  hash and the registry checks it, instead of "first record wins".

## 7. No quorum

- Blocks keep coming (PoW, GhostDAG); their ordering is provisional above
  the last finalized checkpoint. Wallets and exchanges credit at finality
  (DESIGN-obenblock.md §7), so they wait.
- Finality resumes when more than two thirds of `C_e` vote again.
- If that weight is gone for good, finality stays halted. Recovery is a
  coordinated, explicit act, never automatic: a release that names a
  recovery checkpoint and a new configuration, applied by operators with
  `setfinalitycheckpoint` (the A2 escape hatch). The procedure is
  documented and announced in advance; it does not undo payments settled on
  another history.

## 8. Signer protection (no accidental corruption)

The witness duty and `gnb-cli powitattest` must never produce evidence
against their own key:

1. **Persist before release.** The vote record (key, config_id, source,
   target) is written and fsynced before the signature leaves the process;
   a repeat of the same request returns the stored signature.
2. **Refuse double and surround votes** against the record, for every path:
   duty, CLI, restart, failover.
3. **Rollback guard.** At start, and before every vote, the signer scans the
   chain and the pool for votes of its key newer than its record. If it
   finds one, the record is stale (restored backup, second instance): it stops
   signing and raises an alert.
4. **One active signer per key.** An exclusive lock on the record and an
   instance id in it; a second instance refuses to start.
5. KES erasure as today (past epochs cannot be signed again from backups).

## 9. Launch

`C` needs a finalized history, which does not exist at genesis. The first
`POCI_BOOTSTRAP_EPOCHS = 4` epochs (24 h) are PoW-probabilistic: no
finality. The configuration `C_4` is computed from the chain up to the
checkpoint that opens epoch 4. The launch release names that checkpoint
once it is buried (weak subjectivity, as Ethereum's checkpoint sync), and
`C_4` comes into force from it. Until then wallets treat everything as
provisional.

## 10. Tests that must try to break it

| Scenario | Required result |
|---|---|
| partitions 50/50, 60/40, 70/30, also longer than the window | never two conflicting finalized checkpoints; only a side with more than 2/3 of the original `C` advances |
| double and surround votes, evidence, 100-epoch ban | evidence verified; ban start/end exact; no ban for a timeout or a missing vote |
| exit, ban and expiry during a stall | same `C` and denominators on every honest node; one handoff; old certificates keep verifying |
| weight fading out (5 %, 20 %, 30 % offline over days) | pruned at handoffs, finality never halts; 40 % vanishing at once halts finality (expected) and no node prunes locally |
| pruned key rejoins | rejoin message finalized, weight back from the next handoff through the growth cap |
| crash before/after persisting, before/after signing | no sequence releases two conflicting votes; restart is idempotent |
| restored old record, two signer instances | signing stops with an alert |
| forged weight, duplicate key, key outside `C` | certificate verification refuses it |

The reference model (`reference/powit_reference.py`) gets the PoCI rules
and vectors; the partition cases run there and in node tests.

## 11. Relation to the other packages

- O2 (sticky finality pin): kept; with PoCI two conflicting certificates mean
  more than a third of `C` signed both, which is evidence by construction.
- O4: the half leak (§5.2) is not used for finality on ObenBlock; the stall
  relief and the exit message are.
- O10 (growth cap): computes the weights of each new configuration.
- O8 (anchors): advisory until the registry verifies certificates (§6).
