# Security hardening — round 2

Base: `f607e077f035733509aa9a6c549ee36b26f61870`, the owner's merge of
[PR #10](https://github.com/gnb-smh/ObenBlock/pull/10) at
2026-10-16 13:53:26 UTC. Integration branch:
`codex/security-round-2-20261016`, codegen-units **41**.

The prior round's push CI failed `fix_wire_metadata` while its other executed
jobs passed. Its PR CI and the merge CI were still running at the start of
this round. The merge is not evidence of green CI or completion of the broad
security goal. The existing macOS partition/reconnection failure remains open.

## Packages

| Package | Branch | codegen-units | Acceptance |
| --- | --- | ---: | --- |
| Wire-metadata fixture | `codex/security-r2-wire-fixture` | 37 | Deterministic reproduction of the observed `Known` failure; preserve exact size boundaries and all metadata variants; fix only the fixture |
| Functional harness | `codex/security-r2-functional-harness` | 43 (reserved; Python/CI package) | Reproduce false-success skip accounting and the non-absolute partition deadline; enforce actual CI execution and the existing 30-second deadline |

Each package uses a separate worktree. Reproduction precedes correction;
the same regression must fail when the correction is reversed. Three reviewers
independently check semantics, input paths/resource bounds, and test strength.
The reviewed packages change tests, their Python harness, CI and documentation.
They change no production Rust, consensus, network policy, wallet code,
dependencies or compiled WASM inputs.

The wire package `0f674831826e5c9128b6659695a4edfbf17065f4` and harness package
`36c33cb8f0f9278f9cd37de0de2dbca5b7c76011` passed all three independent review
lenses before integration as `2797222` and `b425436`. See their
[wire-fixture](wire-fixture.md) and [functional-harness](functional-harness.md)
reproduction records. Full integration and exact-head CI remain separate gates.

The full original acceptance scope and activation requirements remain in
force. The one-day activation window recorded in [round 1](../round-1/README.md)
does not activate any rule. A consensus package would need a fresh live-tip
reading and enough remaining update time before its height could be scheduled.

Independent assessment: [scorecard.md](scorecard.md). Execution evidence:
[validation.md](validation.md). Finding status: [findings.md](findings.md).
No numerical rating or Bitcoin superiority
claim is assigned by the coordinating engineer. An external independent audit
and bug-bounty program remain prerequisites recommended before relaunch/bridge.
