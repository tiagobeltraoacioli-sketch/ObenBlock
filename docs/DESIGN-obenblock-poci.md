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

- `entries_e` is strictly ascending by `key_id` (so no key twice), every
  weight is > 0, and `total_e` is their exact sum, which must fit in u128.
- `merkle_root` (exact definition, reference `reference/poci_reference.py`):
  the repo's tagged-tree shape (`gnb_merkle.tagged_merkle_root`: adjacent
  nodes paired left to right, an odd last node carried up unchanged) with
  PoCI's own tags, and the entry count committed on top so that a Merkle
  path's shape is fixed by `(index, n)`:

  ```text
  tagged(tag, m)    = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ m)
  leaf(k, w)        = tagged("OBB-POCI-v1/leaf", key_id[20] ‖ u128le(w))
  node(l, r)        = tagged("OBB-POCI-v1/node", l ‖ r)
  tree_root([])     = 32 zero bytes
  merkle_root(E)    = tagged("OBB-POCI-v1/root", u32le(len(E)) ‖ tree_root(E))
  ```

- `params_digest` commits to the PoWit parameters in force, so two nodes
  with different rules never share an id:

  ```text
  params_digest = SHA-256d("OBB-POCI-v1/params" ‖ u32le(chain_id)
      ‖ u64le(epoch_len) ‖ u64le(checkpoint_interval) ‖ u64le(window_epochs)
      ‖ u64le(vote_ttl) ‖ u64le(max_attestations_per_block)
      ‖ u64le(max_evidence_per_block) ‖ u64le(ban_epochs = 100)
      ‖ u64le(bootstrap_epochs = 4) ‖ u64le(growth_div = 64)
      ‖ u64le(g_min_epoch_div = 8) ‖ u32le(2) ‖ u32le(3))       // 110 bytes
  ```

- A vote names its `config_id` (attestation message v3). Like v2 it commits
  the voter's KES public key `(depth, root)`: without it one leaf signature
  re-roots into valid signatures of other keys (PoWit audit finding 1), and
  Proof of Corruption would be forgeable against keys nobody holds.

  ```text
  msg_v3 = SHA3-256( u32le(18) ‖ "OBB-POCI-v1/attest" ‖ u32le(chain_id)
                     ‖ config_id[32] ‖ u8(depth) ‖ root[32]
                     ‖ u64le(source.height) ‖ source.hash[32]
                     ‖ u64le(target.height) ‖ target.hash[32] )   // 171-byte preimage
  ```

  signed by the KES leaf of `epoch(target.height)`; `key_id =
  witness_id(depth, root)`. A vote counts only for the configuration it
  names, with the registry's weight, never a weight the voter states.
- `C_e` is fixed while it is in force. Its weights, total and eligibility do
  not change for any reason.

## 3. Quorum (strict)

```text
quorum(C, votes) <=> 3 × sum(weight of distinct keys of C voting the link) > 2 × total(C)
```

- Exact integers, no saturation (u128 code: with `got <= total`,
  `3 got > 2 total <=> got > 2 (total - got)`, false when `2 (total - got)`
  overflows). An empty configuration never reaches a quorum.
- Strictly more than two thirds (GnB counts `>=`). Any two quorums of one
  configuration then intersect in more than one third of its weight, so with
  under a third Byzantine weight the intersection holds an honest key, and
  the voting rules (§5) keep that key from supporting both.
- Justification and finality follow Casper FFG as today: a supermajority
  link from the justified checkpoint `J` justifies the target slot `t > J`;
  if `t = J + checkpoint_interval` it also finalizes `J`.

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
  history up to that checkpoint. In one rule: finalizing `F` under `C_e`
  hands off to `C_{epoch(F)}` iff `epoch(F) > e` (the opening checkpoint of
  `e+1` is the usual case; a checkpoint later in `e+1` or beyond also hands
  off when the opening one was skipped).

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

Normative reading (package B2; reference `reference/poci_reference.py`,
`PociChain`, vectors `sequences` 8 to 10 of `reference/poci_vectors.json`):

- **Included at.** A vote, rejoin or evidence in a block at height `h` sits
  at ledger height `h + 1` (§12, "Heights"): it is in the history finalized
  by `F` iff `h + 1 <= F.height`.
- **Order at the handoff** triggered by finalizing `F` under `C_e`, with
  `x = epoch(F) > e`: (1) pending bans whose evidence `F` finalizes start at
  `x` (§5); (2) pending rejoins that `F` finalizes end their key's pruning
  (the key is not excluded at `x`); (3) every key `k` of `C_e` is pruned from
  `x` on iff it is *eligible*, walking the configurations in force newest
  first `k` is an entry of each until one whose epoch is `<= x - 4` (a key
  that entered later is in its grace period), and *absent*, no vote of `k`
  was included at a ledger height `h` with `opening(x - 4) < h <= F.height`;
  (4) `C_x` = the provider's candidate weights minus the keys banned, pruned
  or exited at `x`.
- **Votes above `F` do not count**, including the votes of the link that
  finalizes `F`: every node that finalized `F` then computes the same `C_x`.
  Consequence: keys whose votes return only after a halt longer than four
  epochs are pruned at the handoff their votes enable, and rejoin.
- **Rejoin message**, signed with the KES leaf of `epoch`:

  ```text
  rejoin_msg = SHA3-256( u32le(18) ‖ "OBB-POCI-v1/rejoin" ‖ u32le(chain_id)
                         ‖ u8(depth) ‖ root[32] ‖ u64le(epoch) )            // 67-byte preimage
  ```

  A block of epoch `E` may carry it iff, first failure wins: it is above the
  finalized checkpoint, `epoch <= E <= epoch + 1`, the key is pruned, it has
  no rejoin pending, the signature verifies (last). At most 4 per block.
  The key is not excluded from the handoff that finalizing the rejoin's
  block triggers (or the next one); under the growth cap its share work
  then competes as new weight.
- **Forgotten.** A pruned key the provider gives no weight (no share work
  left in its window) is forgotten at a handoff: its later share work counts
  as a new key's, with a new grace period.
- **Rule constant.** `PRUNE_AFTER = 4` is not part of `params_digest`
  (configuration ids are unchanged); changing it is a new rule set.
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
  an entry of it). The named configuration may be the one in force or any
  past one; an unknown `config_id`, two different `config_id`s, two
  different keys, identical attestations, non-conflicting links (shared
  source or shared target with different heights, consecutive links) or a
  bad signature make it invalid.
- **Exclusion**: `ban_start` = the epoch of the first configuration that
  enters into force at or after the finalization of the block holding the
  evidence (the handoff triggered by that same finalization counts: its
  configuration is computed from a history that holds the evidence). The key
  is ineligible for every epoch `ban_start <= e < ban_start + 100` (72,000
  blocks, about 25 days at nominal cadence). The epoch is the protocol's,
  never a local clock.
- One ban at a time: evidence against a key whose ban is pending (no
  `ban_start` yet) or not over (`epoch(C in force) < ban_start + 100`), or
  that names a configuration the key was already banned for, is invalid. A
  key that returns after its ban and equivocates under a later configuration
  is banned again.
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
               votes: sorted by key_id, each (KES public key, signature))
```

- Wire encoding (votes carry the KES public key, from which `key_id =
  witness_id(depth, root)` follows; `signature` is `KesSignature`'s wire
  encoding):

  ```text
  u8(version = 1) ‖ u32le(chain_id) ‖ config_id[32]
  ‖ u64le(source.height) ‖ source.hash[32] ‖ u64le(target.height) ‖ target.hash[32]
  ‖ varint(n) ‖ n × ( u8(depth) ‖ root[32] ‖ signature )        // votes strictly ascending by key_id
  ```

- Verification: the configuration registry (from the chain, or shipped with
  the certificate as entries + Merkle paths), each signature over the exact
  v3 message, distinct keys, strict quorum. In order, first failure wins:
  decode (version, truncated, non-minimal varint, trailing bytes),
  `chain_id`, `config_id` equal to the trusted configuration's, link (both
  heights slots, `target = source + checkpoint_interval`), order (strictly
  ascending; equal ids are a duplicate), membership, quorum, signatures.
- Registry proof (when the verifier holds a trusted `config_id` but not the
  entries): `u64le(epoch) ‖ u128le(total) ‖ u32le(n) ‖ tree_root[32]`, then
  per vote in the certificate's order `u128le(weight) ‖ u32le(index) ‖
  u8(len) ‖ len × sibling[32]` (siblings bottom up; a level where the node
  is the carried odd last one has none). The verifier recomputes
  `config_id` from it and each voter's leaf through its path.
- The certificate's `config_id` must be one the verifier trusts (its own
  chain's, or reached through certificates across handoffs from a trusted
  one); a certificate under a configuration its signers made up proves
  nothing.
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

Implementation (node-local, so it applies to GnB as well):
`node/src/powit_signer.rs` (`VoteGuard`), used by the witness duty
(`powit::WitnessDuty`) and `gnb-cli powitattest`; operator side in
docs/RUNNING.md, "Witness signer protection"; tests in
`node/tests/fix_powit_signer_protection.rs` (the §10 crash and
restored-record rows, in process and by aborting the CLI). Choices:

- The entry is written once, after signing and before release, with the
  signed attestation in it (record, then the high-water file beside the
  key). A crash before that write released nothing; a crash after it
  releases the stored attestation on restart. No intent entry is needed.
- The guard compares links whatever `config_id` they name, a stricter rule
  than the evidence of §5 (same `config_id`): a key never needs a vote that
  double-votes or surrounds one of its own votes under another
  configuration, so refusing it costs nothing.
- "Newer than the record" is a vote the record does not hold whose target is
  at or above the record's highest signed target, or whose source is above
  its highest source. Lower unknown votes (from before a failover onto a
  fresh data directory) are already covered by the high-water mark.
- The halt is persisted (the record's `alert`) and the votes found are
  adopted into the record; only an operator clears the alert.

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

The reference model `reference/poci_reference.py` (next to
`reference/powit_reference.py`, which keeps GnB's rules) specifies the
PoCI rules byte for byte and writes `reference/poci_vectors.json`
(`--check` in CI; tests `reference/poci_reference_test.py`): parameter
digests, configurations and Merkle paths, v3 messages, quorum edges (exactly
2/3 vs just above, u128 extremes), evidence, handoff and ban sequences, and
certificate accept/reject cases. The partition cases run there and in node
tests.

## 11. Relation to the other packages

- O2 (sticky finality pin): kept; with PoCI two conflicting certificates mean
  more than a third of `C` signed both, which is evidence by construction.
- O4: the half leak (§5.2) is not used for finality on ObenBlock; the stall
  relief and the exit message are.
- O10 (growth cap): computes the weights of each new configuration.
- O8 (anchors): advisory until the registry verifies certificates (§6).

## 12. Implementation (package B1, PoCI core)

- `core::powit::poci` (`crates/gnb-crypto/src/core/powit/poci.rs`): the
  byte-level rules of `reference/poci_reference.py`. `PociParams`
  (`OBB_MAINNET_POCI`, `OBB_REGTEST_POCI`, `for_chain`; GnB has none),
  `Configuration` (validated registry, `id`, `weight`, Merkle paths,
  `registry_proof`), `attestation_message_v3`, `quorum`, `ffg_step`,
  `check_evidence` / `PociEvidence`, the ledger `PociState` (configurations
  in force, `finalized` = handoff with `ban_start`, `admit_evidence`), and
  `Certificate` / `RegistryProof`. Signatures go through `VoteScheme`
  (`Kes` on the node). `crates/gnb-crypto/tests/poci_vectors.rs` reproduces
  every case of `reference/poci_vectors.json`.
- Heights: the ledger compares the height at which evidence is included
  with finalized checkpoint heights as the reference does
  (`included_at <= F.height`). The node passes `block height + 1`, since a
  slot names the highest selected-chain block strictly below it.
- `PowitState::apply_poci` (ObenBlock; `apply_full` and `apply_block`
  dispatch to it by chain id): launch at the first block of epoch 4, v3
  votes of the configuration in force only, strict quorum, handoff on
  finalization, PoCI evidence, no inactivity decay. The configuration
  weights come from a `ConfigWeights` provider: on ObenBlock
  `GrowthCapWeights`, the growth cap of DESIGN-obenblock.md §6.3 (package
  B3, §14); the absence pruning of §4.1 is the ledger's (§13).
- `PowitState::poci` is not part of the serde encoding (GnB states are
  stored as before); the node stores it beside the state
  (`powit/poci/<block>`, `powit/pocicfg/<config id>`).
- Block body: in the PoCI format (`BodyFormat { poci: true }`) the evidence
  list carries `PociEvidence` (`config_id ‖ a ‖ b`) instead of GnB's
  equivocation proofs. An empty section encodes the same in every format.
  The gossip item `ITEM_EVIDENCE` carries `PociEvidence` on ObenBlock.
- The witness duty and `gnb-cli powitattest --config-id=<hex>` sign v3 with
  the configuration in force, recorded in the vote record (§8).

## 13. Implementation (package B2: handoff, no leak, pruning, rejoin, ban)

- Ledger (`core::powit::poci::PociState`): `pruned` (key -> `Prune { start }`),
  `rejoins` (key -> included at), `seen` (key -> block epoch -> lowest
  `included_at`; the lowest inclusion of each block epoch answers §4.1's
  question exactly, `PociState::present`). A handoff is two calls:
  `begin_handoff` (ban starts, rejoins, pruning; returns `x`) and `enter`
  (candidate weights minus bans, pruning and exits; forgetting; `C_x` in
  force). `finalized` does both for ledger-only callers.
  `crates/gnb-crypto/tests/poci_vectors.rs` reproduces every pruning and
  rejoin sequence of the reference.
- Bounds: `trim_seen` keeps the included votes of the last `PRUNE_AFTER + 3`
  block epochs per key (a block of epoch `E` finalizes a checkpoint of epoch
  `>= E - 2`, `params_bound_the_finalized_lag`), and only for keys of the
  configuration in force. A block carries at most 4 rejoins.
- `PowitState::apply_poci` records every included vote, admits rejoins
  (`PowitBody::rejoins`, `PociItems`), and hands off through the ledger with
  a `ConfigWeights` provider. The provider contract is on `ConfigWeights`:
  it is called mid-handoff (`state.poci.config()` is still `C_e`; this
  handoff's bans and pruning are recorded, `PowitState::poci_excluded_at`
  answers for every epoch the handoff covers), reads finalized history only,
  and returns every key with weight, excluded ones included. ObenBlock uses
  `ObbConfigWeights`, an alias of `GrowthCapWeights` (§14).
- No inactivity leak: `apply_poci` never decays (the O4 half leak and the
  GnB 1/16 leak stay in `apply_full`, GnB's path, unchanged); exits and bans
  take effect at the next handoff. `getpowitinfo` reports
  `inactivity_leak: "none (PoCI)"` on ObenBlock.
- Body: in the PoCI format the exits list is the membership list,
  `varint n ‖ n × (u8 tag ‖ item)`, exits (tag 0) then rejoins (tag 1); an
  empty one is the same byte as before, so genesis roots are unchanged.
- Node: rejoins are pool items (one per key, checked as the next block
  will, signature last), gossip item kind 5 (`ITEM_REJOIN`, ObenBlock only:
  on GnB kind 5 stays unknown), `submitpowititem [5, hex]`, templates after
  the exits, `gnb-cli powitrejoin`; the witness duty publishes the rejoin
  of its own key when the tip shows it pruned (`WitnessDuty::maybe_rejoin`). The ledger is stored per block
  (`powit/poci/<block>`: head, bans, pruned, rejoins, seen); configurations
  as history nodes `powit/pocihist/<node id>` whose id commits to the whole
  history, so two branches with the same `C_x` after different predecessors
  each reload their own (tests `node/tests/poci_state_store.rs`).

## 14. Implementation (package B3, growth cap)

- `core::powit::growth_cap` (`crates/gnb-crypto/src/core/powit/growth_cap.rs`):
  `reference/obb_growth_cap.py` in Rust. `share_work`, `g_min`, `cap_step`
  (renewal first with `R_k` = the expiring admitted credit, pro rata with
  exact 256-bit `S` and `x_k × G / S`, the rest dropped), the ledger
  `CapLedger` (credits per window epoch, `advance` over skipped epochs,
  `configuration`), `epochs_to_grow`. `crates/gnb-crypto/tests/growth_cap_vectors.rs`
  reproduces every case of `reference/obb_growth_cap_vectors.json` and the
  flood traces (k = 2: never; k = 10, 100: exactly 71 epochs), and checks
  that no flood up to `k = 2^64` gets strictly more than 2/3 before 71
  epochs.
- `GrowthCapWeights` is the `ConfigWeights` provider of `apply_block` on
  ObenBlock. At the launch (C_1 -> C_4) and at every handoff (C_e -> C_epoch(F))
  it advances the ledger kept in `PowitState::cap` from finalized history
  only: share work of epoch `n = x - 2` (`epoch_work`), the first-block bits
  of `n` (`G_min`), and the keys excluded at each `x`
  (`PowitState::poci_excluded_at`: banned, pruned or exited at `x`; the bans
  and prunings the handoff starts are already in the ledger, §13). An
  excluded key gets no credit and does not compete, so a pruned key's share
  work counts again only after its rejoin is finalized, as new weight under
  the cap (§4.1). The provider returns every key with credit, excluded ones
  included; the ledger leaves out the keys excluded at `epoch(F)` and
  forgets a pruned key whose credits have all expired. The provider trait
  takes `&mut PowitState` for this.
- `b_n` (the block whose bits give `G_min(n)`) is the first block of epoch
  `n` on the chain's selected chain that has a PoWit state: the block at
  height `n × epoch_len` when the selected chain has it, and for `n = 0` the
  block at height 1 (the genesis block has no PoWit state). `apply_block`
  takes the block's compact bits for this; GnB ignores them.
- On ObenBlock the state keeps share work from epoch `ledger.epoch - 1`
  even when that is older than `window + 2` epochs, so a handoff after a
  finality stall longer than the window reads the same finalized history
  on every chain (memory grows by one epoch of share work per stalled
  epoch, bounded by the share slots: at most 11,520 entries).
- `PowitState::cap` is not part of the serde encoding. The node stores the
  admitted credits per key per window epoch as content-addressed segments
  of the per-epoch store (`powit/epoch/<digest>`), each ledger once
  (`powit/capl/<ledger id>`), and per block the ledger id and the bits
  (`powit/cap/<block>`). `getpowitinfo` reports, under `poci.growth_cap`,
  the last step's `W`, `G`, `sum(x)`, admitted, admitted to new keys and
  dropped.

## 15. Implementation (package B4: certificates, RPC, partition tests)

- Certificates on the node (`node/src/powit/certificate.rs`). The block `B`
  whose state first carries a finalized checkpoint `F` is the one that
  certifies it: under the configuration `C` in force at `B`'s selected
  parent (whose justified checkpoint is `F`), the certificate holds every
  included vote `F -> t` (`t = F + checkpoint_interval`, `B`'s justified
  checkpoint) by a key of `C`, from the blocks of `B`'s selected chain at
  heights `t ..= B` (the only blocks that may include such a vote; the
  duplicate rule keeps one per key). `C` cannot change in between: only a
  finalization changes it, and that moves the justified checkpoint away
  from `F` first. On acceptance of `B` the node builds it, verifies it once
  against `C` (every signature) and keeps it (`powit/pocicert/<F hash>`,
  with the block that finalized `F` and the configuration it handed off
  to); a checkpoint without a kept row is rebuilt from the selected chain on
  request (at most `vote_ttl + 1` bodies) and kept then. The genesis slot
  and the launch checkpoint of §9 are final by definition and have none.
- RPC `getfinalitycertificate [slot | checkpoint hash]` (default: the latest
  finalized checkpoint of the selected tip; `gnb-cli finalitycertificate`)
  returns the certificate's wire bytes, the registry proof for its voters,
  the configuration (epoch, `config_id`, exact total as a decimal string,
  entry count), the signed weight, the block that finalized it and the
  configuration it handed off to. It is in the single-flight read group of
  the RPC server (a rebuild verifies signatures).
- `getpowitinfo.poci` and `getfinalityinfo.poci`: the configuration in
  force, the absent weight of §4.1 (`absent_weight`, §13; per epoch the
  weight and number of its keys), the bans, and the latest finalized
  checkpoint with its kept certificate's summary.
- Ledger storage fix (found while testing partitions; B2 found and fixed
  the same bug, and the merge keeps B2's rows, §13): a block's PoCI record
  names a history node whose id commits to the whole sequence of
  configurations (`powit/pocihist/<node id>`). Two forks that reach the
  same configuration through different handoffs (one skips an epoch) used
  to read back the same history, so evidence naming a past configuration
  could be judged against the other fork's history (a consensus split
  between nodes that saw the forks in a different order).
  `node/tests/poci_state_store.rs` covers it.
- Partition tests, node level (`node/tests/poci_partition.rs`, ObenBlock
  regtest, real acceptance pipeline, SHA-256d shares, KES keys, v3 votes):
  50/50 over 2 epochs, 60/40 and 70/30 over 6, exactly 2/3 (6 of 9) over 4,
  and 50/50, 60/40, 70/30 over the window + 8 epochs (120). Each checks
  that only a side with more than 2/3 of the configuration at the split
  finalizes, that a side without it keeps that configuration, its total and
  its finalized checkpoint at every block, that after the heal both nodes
  select the same chain (the finalizing side is given less work, so the
  finality pin is what decides) with no conflict alert, that finality
  resumes under the configuration of the split when nothing was finalized
  meanwhile, and that both nodes serve the same certificate, which verifies
  against its `config_id` with the registry proof (and a forged weight
  changes the id). `exit_and_ban_during_a_stall` covers §10's exit, ban and
  stall row: 40 % offline for 6 epochs, an exit and an evidence included
  during the stall, the same configuration and total on both nodes at every
  block, one handoff at the end (the exited and the banned key out,
  `ban_start` = that epoch, 100 epochs), and the certificate kept before
  the stall still verifies. Expiry during a stall is not shown at node
  level: the regtest window is 112 epochs (part of `params_digest`); the
  reference simulation covers it.
