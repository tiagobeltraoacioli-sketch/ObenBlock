# Round 1: test harness isolation

Base: `7b02dcc`. These changes affect test code only. No consensus behavior,
production source positions, WASM artifact, CI filters, or minimum test counts
change.

## PoW activation ordering

`expected_bits_are_always_canonical` assumed the mainnet PoWit activation
(`10_000`), while `powit_pow_tests` and the wire-size test initialized the
process-wide `OnceLock` override to `1 << 40`. Depending on ordering, the
canonicality test observed V1 where it expected V3.

The tests now share the existing test activation constant and idempotent setup.
Canonicality initializes it explicitly, then checks V1 just before the switch
and V3 at/after it. All original sampled heights, the 20,000 generated targets,
constant checks, and both hardening regimes (`0` and `NEVER`) remain; the shared
switch adds three sampled heights. Every unit-test override writer uses the
same value, so concurrent setup cannot select a different activation.

Deterministic red: add the explicit setup call but retain the old
`let switch = POWIT_HEIGHT_MAINNET;` and original V3 assertion. The exact test
fails alone with `left: V1, right: V3` (exit 101). This reproduces the full-suite
failure without relying on scheduler order. The setup-only patch and log are
`/private/tmp/gnb-r1-test-isolation-red.patch` and
`/private/tmp/gnb-r1-test-isolation-red.log`.

All local test commands use:

```sh
export CARGO_BUILD_JOBS=2
export CARGO_TARGET_DIR=/private/tmp/gnb-security-target-test-isolation
export RUSTFLAGS='-C codegen-units=31'
cargo test -p gnb-crypto --lib core::consensus_tests::expected_bits_are_always_canonical -- --exact --nocapture
cargo test -p gnb-crypto
cargo test -p gnb-wallet-wasm --lib tests::bridgelock_signs_the_version_of_the_target_height -- --exact --nocapture
```

Validation on Rust/Cargo 1.94.1, native x86_64 macOS:

- Exact canonicality: 1 passed, 0 failed, 420 filtered out
  (`/private/tmp/gnb-r1-test-isolation-green.log`).
- Full crypto: 420 unit tests, 27 integration tests, and 1 doctest passed;
  0 failures; 4 pre-existing ignores across those targets
  (`/private/tmp/gnb-r1-test-isolation-crypto-full.log`). The run used local TCP
  listener permissions for its existing HTTP tests; all three tests previously
  blocked by sandbox permissions passed.
- Exact native bridge-wallet test: 1 passed, 0 failed, 0 ignored, 6 filtered out
  (`/private/tmp/gnb-r1-test-isolation-wallet-native.log`).
- `git diff --check`: clean.

## Wallet Miri annotation

[Base CI run 38893867410](https://github.com/gnb-smh/ObenBlock/actions/runs/38893867410)
failed the i686 Miri wallet test
`bridgelock_signs_the_version_of_the_target_height` on unsupported foreign
function `PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair`. The local copy is
`/private/tmp/gnb-r1-base-ci-failures.log`, lines 327 onward.

Only that test gains `cfg_attr(miri, ignore = "...")`, with a reason naming
PQClean key generation/signing and unsupported C FFI, consistent with the other
signing tests. Its body and assertions are unchanged; it remains enabled in
normal native and i686 builds. The Miri wallet minimum in
`scripts/sanitizers.sh` remains 3. Of 8 tests on i686, 4 require PQClean and are
annotated to be ignored under Miri; the other 4 remain enabled, including the
32-bit C ABI round trip. This is an expected configuration count, not a local
Miri result.

Local `cargo +nightly miri --version` reports the component is not installed.
No local Miri or i686 pass is claimed; the exact gate must be verified in CI.
