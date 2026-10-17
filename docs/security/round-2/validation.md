# Round 2 execution evidence

## Starting evidence

- [Round 1 execution record](../round-1/validation.md): local full node
  1,714 test executions passed (eight ignored); separate crypto 448 passed
  (four ignored); references, site/Worker/wallet, explorer and release tools
  passed. Local macOS functional run: 13 passed, one failed, zero skipped.
- [Push CI 38908791122](https://github.com/gnb-smh/ObenBlock/actions/runs/38908791122)
  for `ce7d60b084cb9436b6b278b6569ecd3258ec6ad3` concluded **failure** in
  `workspace-test`. The failure is
  `block_accepted_from_gossip_and_served_from_storage_is_accepted_by_a_fresh_node`
  at `node/tests/fix_wire_metadata.rs:216`: `blue_score 0: Known`.
  Miri, i686, WASM reproducibility and the Linux functional job passed in that
  run; these successes do not override the failing overall result.
- The owner merged PR #10 while final PR checks were still running. The
  merge's success is not a testing result. No mainnet activation was added.
- [Merge CI 38911370624](https://github.com/gnb-smh/ObenBlock/actions/runs/38911370624)
  for `f607e077f035733509aa9a6c549ee36b26f61870` subsequently completed
  successfully (observed 2026-10-16 14:11 UTC). All executed jobs passed;
  `fuzz` and `i686-node` were skipped by event filters. The preceding PR
  run's fuzz job was still running at that observation. This does not erase
  the separate push-CI or local macOS functional failures.
- The [merge functional job](https://github.com/gnb-smh/ObenBlock/actions/runs/38911370624/job/117007762302)
  log was also inspected, rather than relying only on its green status:
  all 14 named scenarios were `Passed`, none `Skipped`; the summary reports
  249 seconds. `mining_full_template.py` was the longest scenario at 146
  seconds; `feature_partition_heal.py` passed in 25.2 seconds for the entire
  scenario. This is Linux baseline evidence, not a measurement of
  the fixed shared deadline or closure of the macOS finding.
- [PR CI 38909984512](https://github.com/gnb-smh/ObenBlock/actions/runs/38909984512)
  for `ce7d60b084cb9436b6b278b6569ecd3258ec6ad3` subsequently completed
  **successfully**, including `fuzz / fuzz` (observed 2026-10-16 14:25 UTC).
  The event-filtered `i686-node` job remained skipped. This later success
  does not establish green CI at the time of merge or invalidate the
  earlier same-SHA push failure that motivated the fixture correction.

## Package and integration results

Wire package `0f674831826e5c9128b6659695a4edfbf17065f4` and functional package
`36c33cb8f0f9278f9cd37de0de2dbca5b7c76011` were reviewed independently by
`review_verdict`, `review_paths` and `evidence_baseline`. All three found no
blocking issue within their package scopes. The first two independently ran
the 22 Python unit tests and confirmed the same 14 selected functional scripts;
all three inspected the diffs and red/green/reversal logs. None independently
executed Cargo or the live functional suite in that review. Focused `rustc`
linking and its archive provenance are documented in [wire-fixture.md](wire-fixture.md),
and do not replace a Cargo build.

After those reviews, the packages were integrated as `2797222` and `b425436`
on the merge base `f607e077`. The integrated checks use isolated target
`/private/tmp/gnb-security-target-r2-integration`, codegen-units **41**,
Rust/Cargo 1.94.1, Python 3.12.15 and Node.js 22.23.3. Node and crypto tests
run in separate Cargo invocations. The functional binaries are explicitly
built with `test-pow-limit`; the runner snapshots them and verifies that they
refuse mainnet before executing scenarios.

### Integrated revision `b425436`

The script and per-command logs are retained at
`/private/tmp/gnb-r2-run-checks.py` and `/private/tmp/gnb-r2-integrated-checks/`.
`results.json` records the exact full revision and each exit code.

| Check | Result |
| --- | --- |
| PoW/difficulty/Merkle/GhostDAG Python references | Passed |
| Consensus Python reference | 197 transaction cases, 118 block cases, 4,830 checks; zero failures |
| Python ledger | 23 passed |
| Site, Worker and wallet JavaScript | 33 passed; zero skipped |
| Explorer API | 16 passed |
| Deployment checks | Five passed; three platform-dependent skips (systemd/ShellCheck); Linux CI required |
| Minimum-chain-work release tooling | 10 passed |
| Functional harness unit tests | 22 passed; zero skipped |
| Full `gnb` Cargo invocation | Exit 0; 1,714 test executions passed, zero failed, eight existing ignores across 103 target summaries |
| Separate `gnb-crypto` Cargo invocation | Exit 0; 448 passed, zero failed, four existing ignores across 11 target summaries |
| Test-only functional binary build | Exit 0; explicit `test-pow-limit` build |
| 14 live functional scenarios | Exit 1; 12 passed, zero skipped, two failed; 14/14 completed in 534 seconds |

The node count includes repeated unit suites in different targets, not 1,714
distinct scenarios. Its corrected `fix_wire_metadata` target passed all four
tests with zero failures or ignores through Cargo, in the isolated CGU41 build.
The full node command/log and exit code are retained in
`/private/tmp/gnb-r2-integration/{node.log,crypto.log,functional-build.log,results.json}`.
The functional binaries were snapshotted as `bin-345a729b84b4a3ae`. The command
retained `--ci --jobs 2 --timeout 300`, with the default timeout factor of one.
Full output is `/private/tmp/gnb-r2-integration/functional.log`, with failed
scenario artifacts under `/private/tmp/gnb-r2-functional`.

- **R1-FUNC-1 recurred:** the partition's restarted node recorded macOS
  `EADDRINUSE` for both initial dials. The shared deadline refused the peer
  observation after 30.003 seconds. The scenario failed in 58.2 seconds in
  the runner, including setup. This verifies a refusal at the new deadline,
  not successful healing or closure of the reconnect finding.
- **R2-FUNC-3 is newly open:** `mining_full_template.py` reached the unchanged
  outer timeout at 300.2 seconds. Its preparation needs 179 blocks from
  height 110 through 289; it accepted 165 through height 275 before the
  runner sent SIGTERM. The actual payments, large template and over-1-MiB
  submit body assertions were never reached in this run. The round-1 run
  of that scenario passed in 186.6 seconds.

Two independent read-only reviewers (`review_paths`, `review_verdict`)
confirmed the timeout stage and continuous progress in the existing logs.
There are 166 `getrawmempool`, `getblocktemplate` and `submitblock` requests,
165 acceptances and 165 following `getdaginfo` calls: one attempt per block,
with the last submission interrupted. At the logs' one-second resolution,
`submitblock` to acceptance sums to about 290 seconds, while acceptance to
the next submission sums to about one second. This includes service/queue
time and does not distinguish CPU, PoW, storage or scheduling. It does not
show new polling loops or a prolonged stall.

The scenario, block-generation helper, outer 300-second timeout and production
code are unchanged by this round. Initial connection setup was about 5.44
seconds, close to 5.21 in round 1. Later synchronization assertions were not
reached. Concurrent compilation and other user processes were present, and
the binary builds differ (CGU29 versus CGU41); neither fact establishes the
cause of the slowdown. No timeout was raised or test disabled. The cause is
still unknown, and the lost coverage is recorded in the independent scorecard.

### Merge and remote CI

[PR #11](https://github.com/gnb-smh/ObenBlock/pull/11) was opened as a draft at
head `88d0e9309ed2e85a7fc7f75ad4317e82e3205448`. The owner merged it at
2026-10-16 14:52:06 UTC as `f06b7f8dc05af107fd16f2cebdd89d62a360662a`, before
the local functional result and final remote CI were complete. At the
15:07 UTC observation, the PR's workspace and fuzz jobs were still running;
other executed checks had passed. The full mutation campaign and `i686-node`
were event-filtered skips. No green-at-merge claim is supported. This final
local evidence is carried forward in the following round's documentation.

Subsequent read-only observation on 2026-10-16 confirmed successful merge
runs [38919256180](https://github.com/gnb-smh/ObenBlock/actions/runs/38919256180)
and [38919616610](https://github.com/gnb-smh/ObenBlock/actions/runs/38919616610),
both at `f06b7f8dc05af107fd16f2cebdd89d62a360662a`. In the latter, `fuzz`
and `i686-node` were skipped by event filters; all executed jobs passed.
The actual Linux functional step in
[job 117035844906](https://github.com/gnb-smh/ObenBlock/actions/runs/38919616610/job/117035844906)
reports **14 passed, zero skipped, zero failed; 14/14 completed in 240 seconds**.
The partition scenario passed in 22.4 seconds and full-template in 133.2
seconds. This is the live functional step, not its preceding unit tests'
simulated pass/fail output. The inspected log is retained locally at
`/private/tmp/gnb-r2-ci-main-functional.log`.

The PR-head workspace job subsequently completed successfully at 15:09:07
UTC. Its fuzz job was still running when inspected. These later results do
not imply green CI at merge, and the Linux passes do not close either local
macOS finding or establish the cause of the full-template timeout.

The subsequent query of [PR run 38919107108](https://github.com/gnb-smh/ObenBlock/actions/runs/38919107108)
returned `status: completed`, `conclusion: success`, with no pending jobs.
This closes the remote CI gate for the published PR head `88d0e93`, after
the owner had already merged it; it does not change the local failure record.

Do not infer passing tests from compilation, source definitions, workflow
configuration or an earlier revision. Preserve failures and skipped counts.
Green CI for the exact proposed head is required before the next merge.
