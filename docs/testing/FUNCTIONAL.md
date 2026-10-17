# Functional tests

`test/functional/` drives real `gnb` and `gnb-cli` processes on loopback, in
the style of Bitcoin Core's functional tests: several nodes with their own
data directories, ports and API keys, connected over libp2p, observed only
through JSON-RPC, `gnb-cli` and their logs. Unit and integration tests
(`cargo test`) call library functions; these tests check that the shipped
binaries behave as a network.

The framework is Python 3 standard library only.

## Running

```sh
# Build the test-only binaries, prepare the cached start states, run all tests
python3 test/functional/test_runner.py

# A subset, more parallelism, an explicit binary directory
python3 test/functional/test_runner.py rpc_auth.py mempool_tx_relay.py
python3 test/functional/test_runner.py --jobs 4 --timeout 300
python3 test/functional/test_runner.py --bindir /path/to/test-build

# Local exploratory run: explicitly accept skips, always counted separately
python3 test/functional/test_runner.py --allow-skips

# One test on its own (same options; --nocleanup keeps its temp dir and logs)
python3 test/functional/feature_partition_heal.py --nocleanup
```

`test_runner.py` options: `--jobs` (parallel tests, default half the CPUs, at
most 4), `--timeout` (seconds per test, default 240), `--timeout-factor`
(scales relative waits once, including the partition's shared heal budget), `--bindir` / `--no-build`,
`--cachedir`, `--tmpdir`, `--keep-failed` (keep the temp dir of a failed
test), `--list`, `--ci` (explicit strict mode, also the default),
`--allow-skips` (local mode, incompatible with `--ci`). Each test accepts `--bindir`, `--no-build`, `--cachedir`,
`--tmpdir`, `--nocleanup`, `--keep-failed`, `--portseed`,
`--timeout-factor` and `--loglevel`.

Individual scenario exit codes follow Bitcoin Core: 0 passed, 1 failed,
77 skipped. The runner reports passed, skipped and failed counts separately.
By default and in `--ci` mode, it exits 0 only when every selected scenario
executed and passed; even one skip makes the run incomplete. Only an explicit
local `--allow-skips` run accepts skips, without counting them as passes.

The harness has deterministic unit tests that need neither node binaries nor
network sockets. They exercise the real runner and partition/wait logic with
simulated process results, nodes and a monotonic clock:

```sh
python3 -m unittest discover -s test/functional/unit -v
```

## The test-only build

Real proof of work is GnB-SMH, a 64 MiB memory-hard hash, at a difficulty no
test can wait for. The node therefore has a test-only feature:

```sh
cargo build -p gnb --features test-pow-limit --bin gnb --bin gnb-cli
```

`test-pow-limit` (node/Cargo.toml) forwards gnb-crypto's dev feature of the
same name: every expected target is the pow limit (`0x2100ffff`), so about one
GnB-SMH evaluation (well under a second) finds a block. The pow limit
itself is pinned to that value too (`Block::pow_limit_target_for_height`),
which is the largest target compact bits can encode: a block above the pow
limit (POW-9, and POW-3's lower limit after the activation) cannot be built
with this binary, and those rules are covered by Rust tests only. Everything
else is the production code path, including the evaluation itself, which
every node still runs for every block.

Because every node test (`cargo test -p gnb`) is built with the same feature,
the node's own difficulty call sites (`accept_block`'s height and parent
timestamp, the template's bits, the ingress orphan floor as
`BlockIngress::handle_block` computes it from the selected tip's height) are exercised with
the real ASERT rule by `node/tests/fix_pow_real_asert.rs` (re-audit POW-5):
the test-only seam `core::scoped_real_expected_bits()`, compiled only with
this feature or in gnb-crypto's own unit tests (which pin its scope: the
pin is lifted on the calling thread while the guard is held and restored
when it drops, also when unwinding), makes `expected_bits` compute the real rule on
the calling thread, and the tests reject bits computed for the wrong height
or parent timestamp. The GnB-SMH v3 switch (`core::adjust_bits_for_algo`: from
`powit_height()`, 10,000 on mainnet, the ASERT target is 4x harder) is
covered twice: at the mainnet height for the rule and the ingress reference
(`expected_bits_switch_to_v3_at_the_mainnet_powit_height`), and at the call
sites by `node/tests/fix_pow_real_asert_v3.rs`, a binary that moves the
switch to height 3 (`core::set_powit_height_override`) so that
`accept_block`, the template and `handle_block` judge the first v3 block
(its unshifted v1 bits are refused, the template carries the shifted bits,
an orphan at the v1 floor is dropped).

The feature is consensus-breaking, so it is fenced in four ways:

| Guard | Where | What it checks |
| --- | --- | --- |
| Runtime refusal | `test_pow_limit_guard`, node/src/main.rs | Keyed on gnb-crypto's `TEST_POW_LIMIT`, so it holds however the feature was enabled. An optimised build (debug assertions off: the release profile) with it exits with code 2 on every network. A debug build with it exits with code 2 without `--testnet`, before it creates the data dir, opens a port or reads a key file, and runs on `--testnet`. Unit tests `test_pow_limit_guard_tests`; functional test `feature_test_build_guard.py`. |
| No release build of the node feature | `compile_error!` in node/src/main.rs | `--features test-pow-limit` with the release profile does not compile. gnb-crypto's feature reached another way (`--features gnb-crypto/test-pow-limit`, or the dev-dependency that `cargo test --release` unifies into the binary) compiles, and the runtime refusal stops that binary. |
| CI assertion | job `workspace-test`, step "Artifact builds never enable test-pow-limit" | Before `cargo test` runs: the workspace build graph (`cargo tree -e features,normal,build -i gnb-crypto`) does not reach the feature, it is not a default feature of `gnb`, and the binary CI built gets past the guard (it is not a test build). |
| Framework probe | `binaries.verify_test_build` | Before any test runs, the binary must refuse mainnet with the guard message; a production binary, or a test binary without the guard, fails the suite. |

What is not fenced: after a plain `cargo test`, `target/debug/gnb` is a
debug test build (the node's dev-dependency enables the feature for every
target cargo builds in that invocation). It refuses mainnet and runs on
testnet, like the binary the functional tests build on purpose. No artifact
is a debug build.

Because the test build refuses mainnet, every functional test runs on
testnet, where the hardening activation height is 0 (see
`crates/gnb-crypto/src/core/activation.rs`).

When several checkouts share one `CARGO_TARGET_DIR`, `target/debug/gnb` may
be another checkout's build; pass `--bindir` with a private copy. The runner
snapshots the binaries into the cache directory before it starts, so a
rebuild during a run cannot swap them.

## How a test is set up

`test_framework/test_framework.py` (`GnbTestFramework`) does, for every test:

1. resolves the binaries (`binaries.py`: cargo build of the test feature, or
   `--bindir`) and verifies they are a test build;
2. copies a cached start state into one data dir per node (`cache.py`);
3. starts the nodes (`node.py`, `TestNode`) and connects them
   (`setup_network`, default: node *i* dials nodes 0..*i*-1);
4. runs `run_test()`;
5. always stops every node (SIGTERM, then SIGKILL), also when the test is
   interrupted (SIGTERM / SIGINT are turned into an exception that unwinds
   through the cleanup), and fails the test, even when `run_test()` passed,
   if a node had exited on its own (a crash; `kill()` is the deliberate
   way), exited on SIGTERM with another code or needed SIGKILL, or logged a
   panic (`panicked at` anywhere in its log: a panic in a spawned task does
   not end the process);
6. on failure prints the tail of every node's log; removes the temp dir.

Every node runs with:

```
gnb --testnet --data-dir <tmp>/nodeN --carryover-snapshot <cache>/carryover.tsv \
    --rpc-bind 127.0.0.1 --rpc-port <p> --listen /ip4/127.0.0.1/tcp/<q> \
    --rpc-api-key-file <tmp>/nodeN.apikey --rpc-require-auth-for-writes [--peer ...]
```

The key file has mode 0600 and a random key per node; the RPC proxy
(`authproxy.py`) presents it, `gnb-cli` gets it through `GNB_RPC_API_KEY`.
Ports come from a per-test window (`--portseed`, set by the runner) and are
bind-checked, so parallel tests and unrelated processes do not collide. The
node's stdout and stderr go to `<datadir>/node.log`.

### Cached start states

`cache.py` builds, once per binary digest, under `--cachedir`:

- `carryover.tsv`: `genesis/bloch-g3-carryover.tsv.gz` decompressed;
- `base`: the data dir right after first boot (genesis plus the carryover
  ledger), used by tests with `setup_clean_chain = True`;
- `chain`: `base` plus 110 blocks mined through getblocktemplate and
  submitblock. Blocks 1-10 pay the cache wallet, a real `gnb-cli` keystore
  (hybrid ML-DSA-65 + Falcon-1024 key) whose file is kept with the chain;
  blocks 11-110 pay a filler address, so all ten of the wallet's coinbase
  outputs are mature (`COINBASE_MATURITY` = 100). `self.wallet_copy()` gives a
  test its own copy; `self.chain_info` has the wallet address and the tip.

Building `chain` takes about 100 s and is done before the tests start, so
tests running in parallel share it. Only `db/` is copied into a node (its
`.sst` files are hard-linked); each node creates its own P2P identity.

### Mining in tests

- `node.generate(n, address)`: per block, `getblocktemplate`, a block built
  in Python (`messages.block_from_template`: coinbase, hardening commitment,
  tagged Merkle root, wire encoding) and `submitblock`. The node computes
  GnB-SMH; on "invalid PoW" (probability 2^-16 at the pow limit) the next
  nonce is tried. Deterministic: no background miner.
- The node caches `getblocktemplate` while the template's parents and height
  are unchanged (`template_cache_key`; a template is stored under the parents
  it was built on, `template_result_key`, and at most four are kept): a new
  block, an `invalidateblock` / `reconsiderblock` or a parent's body arriving
  misses the cache at once, a mempool change shows within 5 s
  (`TEMPLATE_CACHE_TTL`, as Bitcoin Core). `generate` uses
  `node.fresh_template()`, which waits until the template offers every
  mempool transaction (at most one cache period).
- `node.start(mine=True, miner_address=...)`: the node's own miner (`--mine`,
  one thread), for tests of the production mining loop. A miner started with
  `--peer` waits for a connected peer and a remote tip before it mines
  (fresh-miner fork guard); start it without peers when that matters.

### Synchronisation helpers

- `wait_until(predicate, timeout=..., deadline=...)`: polls; relative timeouts
  scale once with `--timeout-factor`. An optional absolute monotonic deadline
  caps the relative timeout and is never scaled. The predicate must finish
  successfully before that deadline. A synchronous RPC already in progress
  cannot be interrupted by this helper: it may return late, but its late
  result is rejected. The runner's process timeout remains the outer bound.
- `wait_for_peers(pairs=...)`: both ends log `✓ connected: <peer id>`, then
  two gossipsub heartbeats. All peer directions and settling share one
  deadline; `deadline=...` can also cap it. (The RPC peer count, distinct peers, is updated
  on every connect and disconnect; the log line is still the earliest
  signal.)
- `sync_blocks()`: same selected tip and same valid tips
  (`getblocktemplate` parents) on every node. `getdaginfo.tips` also lists
  disqualified blocks a node keeps in its DAG (DAG-1), which only the node
  that saw them has. The partition scenario gives peer waits, settling and
  `sync_blocks` the same deadline, 30 seconds after node2's restart returns
  at the default factor. An explicit `--timeout-factor` scales this budget
  once when the deadline is created; inner waits cannot rescale or renew it.
  It cannot pass with an observation at or after that deadline. CI keeps
  the default factor of one.
- `sync_mempools()`, `assert_same_chain_state(addresses)`: same tip, valid
  tips, height, blue work, and the exact UTXO list (txid, index, value) of
  every given address. The RPC has no UTXO-set digest; per-address
  `getutxos` is the strongest comparison it offers.

### gnb-cli on a terminal

`gnb-cli` reads passwords with rpassword, which opens `/dev/tty`. The
framework runs it on a pseudo-terminal (`interactive.py`, `pty.fork`) and
types the password at the prompt, exactly as a user would:
`node.cli_new_wallet(path)`, `node.cli_send(wallet, to, amount)`.
`node.cli(...)` / `node.cli_json(...)` run non-interactive commands.

## The tests

| Test | Nodes | What it checks |
| --- | --- | --- |
| `feature_test_build_guard.py` | 1 | The test build refuses mainnet (exit 2, nothing written) with any command line, runs on testnet, asks for the pow limit, and `getnetworkinfo` reports `testnet`. |
| `feature_assumevalid.py` | 2 | `--assumevalid` (P5-G, Core's `-assumevalid`): a malformed value (not `0` and not 64 hex digits) is refused with exit code 2; testnet's default (no release value) is logged; a fresh node started with a block id logs it and syncs the other node's chain to the same tip; `--assumevalid 0` is logged as off. The skip itself is tested in `node/tests/fix_assumevalid.rs` (it needs a chain with an invalid signature). |
| `p2p_block_propagation.py` | 3, line topology | The internal miner's blocks reach the far node through the middle one (validate-then-relay); afterwards every node has the same block at every height, each paying the miner; a block submitted at the far end travels back. |
| `mempool_tx_relay.py` | 3 | `gnb-cli send` (version 3 transaction) reaches every mempool with the same bytes and fee; a block mined elsewhere confirms it on all nodes; balances and UTXO lists agree; a second payment from another node does the same. |
| `mempool_replacement.py` | 3 | Full-RBF (MEM-6) end to end: a `gnb-cli send` conflicting with a pooled payment at the same fee fails the replacement rules on the node it is sent to and the original stays everywhere; with a higher fee it replaces the original on all three nodes; a block mined at the third node confirms the replacement everywhere. |
| `wallet_coinbase_maturity.py` | 1 | `getutxos` marks coinbase outputs; `gnb-cli send` never selects an immature one, and a wallet with only immature coins refuses before signing. |
| `feature_partition_heal.py` | 3 | A partition with competing branches (one confirming a payment) heals within 30 s: the branch with more blue work is selected everywhere, both branch tips are kept, a merging block joins them, and every node ends with the same chain state. The payment follows the ledger rule: unconfirmed on every node while its branch is off the selected chain (payee empty, the payment back in side A's mempools), then confirmed in the merging block on every node, the payee holding exactly 3 GNB. |
| `feature_restart_persistence.py` | 2 | Stop/start keeps tip, tips, heights, block hashes, balances, tx index and P2P identity; the mempool is memory-only by design and a re-broadcast re-admits the transaction; SIGKILL right after a block is accepted loses nothing. |
| `feature_invalidateblock.py` | 2 | Operator `invalidateblock` / `reconsiderblock` (DAG-6): invalidating the block that confirmed a payment rolls node0 back two blocks and re-admits the payment to its mempool while node1 keeps the blocks; `submitblock` of a block on the invalidated chain is refused; node0 mines a competing block (re-confirming the payment) that node1 stores as a fork block; the invalidation survives a restart; `reconsiderblock` re-qualifies the chain, including the descendant whose mark was inherited, moves node0 to it (1 block rolled back, 3 connected) and both nodes converge on the same chain state. |
| `mining_getblocktemplate_submitblock.py` | 2 | External mining: template fields and coinbase commitment match the Python encoding; a Python-built block is accepted, relayed and becomes the template's parent at once (the cached template never outlives the tips); duplicates refused; a mempool transaction is offered with its fee within the 5 s template cache period; a coinbase claiming one satoshi too much is refused and not relayed; two blocks on one template are both kept and merged by the next template. |
| `rpc_gettxoutsetinfo.py` | 2 | The supply audit (VAL-11): on the cached chain the UTXO set holds no more than carryover + the subsidy of every connected block, with one undo record per chain position and the scan agreeing with the maintained aggregates; a payment and its block leave the unclaimed amount unchanged (fees are not issuance); a coinbase claiming 1,234 sat less raises it by exactly that; both nodes report the same count, total and hash, also after a restart. |
| `mining_full_template.py` | 2 | A full template mined externally (audit B1-T4): two fresh wallets with 40 coinbase outputs each pay 40-input hybrid-signed transactions (mempool above 0.6 MB); the block built from the template (above 600 kB, a `submitblock` body above the old 1 MiB cap) is accepted, confirms both, and is relayed. |
| `rpc_auth.py` | 2 | `getblocktemplate`, `submitblock`, `sendrawtransaction` without or with a wrong key: 401 / -32001 and no effect; a wrong key is refused for reads too and answered slowly; the key works as `X-API-Key` and `Bearer`; browser Origin / foreign Host refused; batches refused; `gnb-cli` without the key cannot write; `GNB_RPC_REQUIRE_AUTH_FOR_READS=1`; start-up refusals (auth without key, loose or empty key file, short key). |
| `p2p_invalid_blocks_txs.py` | 3 | Invalid transactions (malformed, coinbase, duplicate input, missing input, outputs above inputs, dust, version 1, forged signature, conflicts under full-RBF: one at T's fee rate fails the replacement rules before any signature work, one paying more fails the signature check; duplicate) and invalid blocks (malformed, bad / legacy Merkle root, every coinbase-commitment defect, no / two coinbases, duplicate tx, undecodable or unexpected bits, wrong height, unknown parent, timestamps, coinbase over-claim, two coinbase outputs, a confirmed tx again: BIP30) are rejected with the right reason and never move the tip. None of them is delivered to the observer node: checked on its receipt trace (every gossiped block is logged at info, every gossiped transaction with the debug target `gnb_gossip_rx_tx`), not on its storage, since the observer would drop most of them itself; the trace does show the valid transaction and blocks node0 relays. |
| `feature_activation_testnet.py` | 2 | Testnet activation 0: the template announces the hardened rules at height 1; the pre-activation block format, and each half of the change alone, is rejected at height 1; the hardened block is accepted; blocks from the internal miner satisfy the rules, checked in Python. |

Runtime depends on the host, cached chain and scenario. The runner reports
each scenario's duration and the total; the [round 2 execution record](../security/round-2/validation.md)
includes a Linux baseline run of 249 seconds, with the longest scenario at
146 seconds. CI (`.github/workflows/ci.yml`, job `functional`) builds the test
binaries, runs the harness unit tests and runs
`test_runner.py --ci --jobs 2 --timeout 300`, uploading the logs of failed tests.

## Behaviour the tests rely on (and document)

- The RPC peer count, and the miner's "has peers" check, count distinct
  peers and change on every connect and disconnect
  (`peer_count_counts_distinct_peers_not_connections`). The network
  heartbeat's first tick comes 30 s after start-up, so start-up does not
  re-dial the bootstrap peers it has just dialed
  (`heartbeat_first_tick_is_one_period_after_start`). From then on every
  heartbeat re-dials each `--peer` that is not connected, whatever else is
  connected (re-audit B1-T9: it used to happen only with no peer at all).
- A disqualified block stays in the DAG and in `getdaginfo.tips` (DAG-1), but
  is never selected, never offered as a parent and never relayed.
- The mempool is not persisted across restarts.
- Peer exchange ignores loopback addresses unless `--allow-private-peers`, so
  a test's topology is exactly what its `--peer` flags say.
- After a partition heals, nodes converge in a few seconds without new
  blocks (4-7 s in `feature_partition_heal.py`, counted from node2 being
  back up, the 2 s connection settle included): on connect each node asks
  the new peer for its
  frontier directly (a directed `GetTips`), and a tip claim ahead of ours
  makes the node ask the claiming peer for its frontier. (The header pulls a
  claim triggers still go to the pull selector's choice: a `Headers` answer
  is not deduplicated against block requests already in flight, so asking
  the claimant too would download blocks twice; the frontier pulled from the
  claimant is what the heal needs.) A pulled block a
  peer does not have (`BlockNotFound`) is retried on another peer at once.
  Before these, the on-connect gossip announcements to a second peer within
  the same second were dropped as gossipsub duplicates and the claim-
  triggered pulls went to the pull selector's choice, so the 30 s nudge and
  the 60 s announce did the work (about 60 s; the test then allowed 120 s).
  The test allows 30 s.

## Out of scope

- A raw TCP / libp2p adversary peer. Invalid objects are fed through the RPC
  submit paths, which run the same `accept_block` and `admission::admit` as
  gossip ingress; the wire decoders are covered by `node/fuzz` and
  `node/tests`.
- The mainnet side of the activation (17,500): unreachable by a build that
  refuses mainnet; covered by Rust tests with `activation::scoped_override`.
- A target above the pow limit (POW-9, POW-3): the test build pins the pow
  limit to the largest encodable target, so no such block exists for it;
  covered by `validate_pow_enforces_the_height_pow_limit` and the
  difficulty tests.
- An invalid proof of work at the pow limit (a failing nonce occurs once in
  2^16 evaluations; Python would need minutes per evaluation to find one).
  Covered by `gnb-crypto` and `node` unit tests.

## Writing a test

```python
#!/usr/bin/env python3
"""One line saying what is tested.

What exactly, and why it matters."""

from test_framework.messages import hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal

ADDR = hash_to_address(bytes(range(20)))


class ExampleTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2            # setup_clean_chain = True: genesis only

    def run_test(self):
        n0, n1 = self.nodes
        h = n0.generate(1, ADDR)[0]
        self.sync_blocks()
        assert_equal(n1.tip(), h)


if __name__ == "__main__":
    ExampleTest().main()
```

Add it to `ALL_TESTS` in `test_runner.py`. Keep a test under about two
minutes, wait with `wait_until` / the sync helpers instead of sleeping, and
prefer `generate` over the internal miner unless the miner is what is tested.

## Follow-ups

`wallet_descriptor_restore.py` exercises the public descriptor RPCs and offline
CLI against a live testnet node. It exports a public pool, funds the independently
pinned identity, imports the pool again and observes the same output. It also
checks wrong-network restoration and preservation of an existing output file.
This proves public identity restoration only: no spending key, transaction
history scan or persistent watch-only wallet index is restored.

Added after the operator-RPC (P3) and mempool-policy (P4) merges:
`feature_invalidateblock.py` and `mempool_replacement.py` above. Still to add,
each end to end on three nodes like `mempool_tx_relay.py`: mempool policy
beyond replacement (package / ancestor-descendant limits, eviction and the
rolling minimum fee under a full pool, expiry, and re-broadcast of
unconfirmed transactions; today only a mining node re-broadcasts). They need
a wallet that can spend unconfirmed outputs and a quick way to fill the pool.
