# Round 1 execution evidence

All baseline results below refer to
`7b02dccbaa9c9dac15b2a18c72c32fc29b2acb3c`, before package integration.
Execution by the coordinating engineer is distinct from the independent
[source assessment](scorecard.md).

## Baseline local runs

Environment: macOS x86_64, Rust/Cargo 1.94.1, Python 3.12.15, Node.js
22.23.3. The Node.js official distribution was SHA-256 checked against
`8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8`.

| Command | Result | Scope / limitation |
| --- | --- | --- |
| `python3 reference/check_vectors.py` | passed | Existing PoW, difficulty, Merkle and GhostDAG vectors |
| `python3 reference/check_consensus_vectors.py` | passed | 197 transaction cases, 118 block cases, 4,830 checks, zero failures; not 10^7 random differential cases |
| `python3 reference/test_ledger.py` | passed | Existing reference ledger tests |
| `python3 deploy/test_deploy_files.py -v` | passed with platform limitations | Linux systemd/ShellCheck gates must be checked on Linux CI |
| `python3 deploy/explorer-api/test_gnb_explorer_api.py -v` | 16 passed | Required loopback socket permission; initial sandbox run failed to bind |
| `python3 tools/release/test_min_chain_work.py -v` | passed | Fake-node unit tests; not a multi-node live release reading |
| `node --test site/tests/*.test.mjs` | 33 passed, zero skipped | Required loopback socket permission for the local explorer fixture |
| `cargo test -p gnb-crypto --locked --offline` | failed: 416 passed, 4 failed, 1 ignored (library stage) | Three HTTP fixture bind failures from sandbox permissions; one genuine test-ordering failure; remaining targets did not run after this failure |

The first attempt used the system Python 3.9.6, which cannot evaluate a
reference's `bytes | None` annotation. It was replaced with the available
Python 3.12.15 interpreter. No source compatibility claim or code fix was
made from that environment failure.

## Newly observed test-harness findings

- **R1-TEST-1 — test activation state depends on execution order (open).**
  `core::consensus_tests::expected_bits_are_always_canonical` assumes the
  mainnet PoWit boundary, but sibling unit tests set the process-wide
  override to `1 << 40`. The baseline failed at
  `crates/gnb-crypto/src/core/consensus_tests.rs:278`, observing V1 instead
  of V3. This is evidence of a broken test premise, not evidence that
  production nodes disagree. The test-isolation package also reproduced
  the failure in the single test with explicit setup before changing the
  expectation to the shared test boundary.
- **R1-TEST-2 — Miri tries to execute an unsupported C FFI call (open).**
  The base [CI run](https://github.com/gnb-smh/ObenBlock/actions/runs/38893867410)
  failed in the i686 wallet Miri test
  `bridgelock_signs_the_version_of_the_target_height`, calling
  `PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair`. Miri's diagnostic explicitly
  says unsupported foreign calls do not establish a program bug. Native
  and i686 execution must retain this signing test; Miri must retain its
  existing ABI checks and passed-test minimum.

## Baseline CI

The base run above completed with **failure** in `miri`; it is not green.
The other non-skipped jobs succeeded. `i686-node` and `fuzz` in this
workflow were skipped by their event filters. Separate fuzz/mutation
workflows are not inferred to have passed from this run.

## Package and integration results

Test-isolation package `e09d8cafbb07cbcde41e4c86e951b5b2094753b1`:
the separate full `gnb-crypto` invocation passed 420 unit tests, 27
integration tests and one doctest (448 passed, zero failed; four existing
ignores across the targets). The native wallet bridge test passed with
zero ignored tests. See [its reproduction brief](test-isolation.md).
Three independent static/log reviews (`review_verdict`, `review_paths`,
`evidence_baseline`) found no blocking issue in that package. They did not
independently run the tests. Miri/i686 and the final integration run remain
pending.

RPC package `59738aa121237a9d8a669c177e4911c769c309f6`:
11 focused measured regressions pass after final restoration; the affected
RPC suite passes 131 tests outside the sandbox. All five production-only
reversals failed by regression assertion, with the final tests retained;
source files were restored byte-for-byte. The 70-test standalone auth run
also passed. Its [brief](rpc.md) separates the initial invalid fixture from
the corrected reproduction and documents the operator availability policy
and real-clock test limitation. Three independent reviewers (`review_verdict`,
`review_paths`, `evidence_baseline`) reviewed the final full package, including
the HTTP handler, storage aggregates and pending totals. None found a remaining
blocking issue. These were static/log reviews, not separate executions. The
package was integrated as `91bb719` after those reviews.

### Integrated revision `91bb719`

Executed after both package integrations, using the same Python/Node versions
as the baseline:

| Check | Result |
| --- | --- |
| PoW/difficulty/Merkle/GhostDAG Python references | passed |
| Consensus Python reference | 197 transaction cases, 118 block cases, 4,830 checks; zero failures |
| Python ledger | 23 passed |
| Site, Worker and wallet JavaScript | 33 passed, zero skipped |
| Explorer API | 16 passed |
| Deployment checks | Five passed, three platform-dependent skips (systemd/ShellCheck); Linux CI still required |
| Minimum-chain-work release tooling | 10 passed |
| `cargo test -p gnb --locked --offline` | Exit 0; 1,714 test executions passed, zero failed, eight ignored, across 103 target summaries |
| Separate `cargo test -p gnb-crypto --locked --offline` | Exit 0; 448 passed, zero failed, four ignored, across 11 target summaries; real-ASERT and canonicality tests passed |
| Test-only functional binary build | Passed; `test-pow-limit` feature explicitly enabled, isolated binaries verified to refuse mainnet |
| Existing functional suite on macOS, `--jobs 2 --timeout 300` | Exit 1; 13 passed, one failed, zero skipped; 449 seconds |

The node count includes repeated unit suites in separate targets; it is not
a claim of 1,714 distinct scenarios. Existing ignored tests include an explicit
child-process vector entry, historical/offline snapshot cases and the unfinished
address-checksum test. Crypto ignores include the unfurnished full NIST KAT
wiring, explicit vector generator and two documentation examples. The generator
is a separate CI step; this test command does not establish its result.

The functional run failed `feature_partition_heal.py`: after
restart, node2 did not reconnect to node1 within the existing deadline. Logs
record `Address already in use` (OS error 48) on macOS. The other 13 scenarios
passed. No timeout was relaxed or scenario ignored to change that result.
Two independent read-only reviewers (`test_isolation`, `review_paths`) found
that the test supplies manual peer addresses without `/p2p/<id>`, for which
the existing documented policy retries only while there is no manual connection
or pending dial. Retrying n0 therefore suppresses the n1 retry. This is a
fixture/documentation-contract mismatch, plus an unresolved TCP failure; it
does not establish a consensus disagreement. The network code, framework,
scenario and dependencies relevant to this failure are unchanged from the base.
Linux CI must be reported separately and cannot erase this macOS result.

Final CI was pending when this evidence was committed. Check the exact PR
revision's Actions results before merge. This is a partial hardening round,
not fulfillment of the complete acceptance scope.
Red tests, a test definition, compilation,
or successful baseline jobs are not equivalent to green CI of the final
integration commit. Three final review lenses, full node/crypto invocations,
functional tests and final CI must be recorded before the round is called
complete.
