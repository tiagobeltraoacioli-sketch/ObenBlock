# Running a GnB node

## Hardening activation: upgrade before mainnet height 17,500

> **Every mainnet node and miner must run this release before the chain
> reaches height 17,500.** The deadline is the height: watch `getdaginfo`
> `next_block_height`. On the ASERT schedule (genesis time + 17,500 × 30 s)
> that is **2026-10-17 04:17 UTC**, but the chain runs ahead of the schedule
> by about 240 blocks (2 h) per doubling of the network hashrate above about
> 600 GnB-SMH v3 evaluations/s (8 h early at 16 times that), so do not wait
> for the date. Below that hashrate it arrives later, and blocks after it
> are slower (release check below).

- From height 17,500 the consensus rules of the 2026-10-14 audit apply on
  mainnet (`docs/CONSENSUS.md`, "Activation"; testnet and regtest apply them
  from genesis). The height is `MAINNET_HARDENING_ACTIVATION_HEIGHT` in
  `crates/gnb-crypto/src/core/activation.rs`.
- A node that has not upgraded by then keeps the old rules: it accepts
  blocks and transactions the upgraded nodes reject (and the reverse), so it
  splits from the upgraded network at the activation block and follows a
  separate chain. A build made before the 2026-10-16 decision activates at
  110,000 (version 0.1.0) and splits the same way: upgrade it too. (Version
  0.1.1 builds of the hardening branch activate at 25,800 and carry the
  pre-relaunch genesis: they do not follow this chain at all.)
- Independently of the activation height, this release makes ML-DSA-65
  verification the same on every CPU (`docs/CONSENSUS.md`, "ML-DSA-65
  verification"). Earlier builds verified with PQClean's AVX2 code on x86_64
  CPUs with AVX2 and with its portable code everywhere else, and the two give
  opposite verdicts on signatures anyone can craft (Wycheproof tcId 161), so
  a crafted spend can split AVX2 nodes from the others at any height. Upgrade
  every node, whatever its CPU.
- Check the upgrade on each node: `getnetworkinfo` reports `version` 0.1.2
  and `hardening_activation_height` 17500, and `getdaginfo` the same height
  and `hardening_active` for `next_block_height`. A node reporting another
  version or height, or no `hardening_activation_height` there, is a build
  from before the move (`getblocktemplate` shows 110000 on the 0.1.0 build
  of the audit merge, and nothing on the pre-hardening release) and must be
  replaced. Peers see the identify agent `gnb/0.1.2/...`; the RPC does not
  list peers' agents (`getpeerinfo` reports only counts), so network-wide
  adoption cannot be read from one node.
- Miners: a template for the activation block and after must come from an
  upgraded node. `getblocktemplate` reports `hardening_activation_height`
  (17500 on mainnet) and `hardening_active` for the template's height.
- Wallets sign version-3 transactions from the activation height on; a
  wallet built before this release (including a web-wallet core compiled
  with another height) signs version 1 there, which every upgraded node
  refuses. The committed web-wallet core (`site/wallet/gnb_wallet.wasm`) is
  built with 17,500; the site must be deployed from this release before the
  activation.
- Transactions signed before the activation (version 1) that are still
  unconfirmed when `next_block_height` reaches 17,500 are dropped from every
  upgraded node's mempool and refused from then on (no transaction is valid
  under both regimes: `docs/CONSENSUS.md`, "Transaction signatures" and
  "Which height"). Services holding pending or pre-signed payments must
  sign them again, as version 3, after the activation.
- Release check (before tagging, by whoever ships it): read the mainnet tip
  (`getdaginfo` `tip_height`, `next_block_height`) and the current `bits`
  (`getblocktemplate`) from a mainnet node. The height 17,500 was derived
  from the schedule, not from an observed tip (`docs/CONSENSUS.md`,
  "Activation"; the tips recorded on 2026-10-12 and 2026-10-14 lagged the
  schedule by 909 and 574 blocks). The tip must be well below 17,500, and
  (17,500 - `next_block_height`) × the observed block interval is the real
  time left. If the template's `bits` are easier than `0x1f03a40d`, the
  genesis target shifted for GnB-SMH v3 (network hashrate below about 600
  v3 evaluations/s), blocks after the activation slow to about 30 s × (that
  target's work / current work) until the hashrate rises (POW-3,
  `docs/CONSENSUS.md`, "Activation"): record the expected interval here, or
  reconsider the timing.
- If the release ships later than planned, or the chain is too close to the
  height, the height must be moved again before the chain reaches it: the
  constant `MAINNET_HARDENING_ACTIVATION_HEIGHT`, its copies in
  `crates/gnb-crypto/tests/gen_consensus_vectors.rs` (`MAINNET_ACT`),
  `reference/gnb_validity.py` (`HARDENING_ACTIVATION_HEIGHT`),
  `reference/gnb_merkle.py` and `reference/gnb_difficulty.py`
  (`MAINNET_HARDENING_ACTIVATION_HEIGHT`), the regenerated
  `reference/{tx,block,merkle,difficulty}_vectors.json` (with their
  generators), a rebuilt and re-pinned web-wallet core
  (`scripts/build-wallet-wasm.sh`, then deploy the site), a new node package
  version, and these notes (see the module documentation of `activation.rs`).

## Requirements

- 64-bit Linux or macOS, Rust toolchain from `rust-toolchain.toml`.
- Memory: ~1 GB for the node plus 64 MiB per mining thread.
- Ports: 17110/tcp (P2P) open to peers. RPC (17210) and metrics (17310) bind
  to 127.0.0.1 by default.

## First boot

```sh
cargo build --release --bin gnb
gunzip -k genesis/bloch-g3-carryover.tsv.gz
./target/release/gnb --data-dir ./gnb-data \
    --carryover-snapshot genesis/bloch-g3-carryover.tsv \
    --peer /ip4/<seed-ip>/tcp/17110
```

The node verifies the snapshot, writes the 452,725 carryover UTXOs, verifies
the genesis proof of work and starts syncing. Later boots only need
`--data-dir`; a data-dir from another chain or genesis is refused.

Use one data dir per network. Mainnet and testnet (`--testnet`) share the
genesis block, so the genesis check alone cannot tell their data dirs apart;
the data dir records the chain id of the network it was first started on
(CF_META `chain_id`), and a node of the other network refuses it with "this
data dir belongs to chain id ...". A data dir from an earlier release has no
marker yet; it is not simply marked for the network that opens it first:
when it holds chain blocks, the node reads their network from the blocks
(below height 17,500, the mainnet hardening activation, a mainnet block
follows the pre-activation rules and a testnet block the hardening rules,
which exclude each other: only a testnet coinbase carries the hardened
coinbase commitment, whatever either network's PoWit height) and refuses to
start on the other network with "this data dir has no chain id marker yet,
but its block ... belongs to chain id ...". A testnet data dir from before
testnet's hardening reads as mainnet-shaped: its blocks fail the testnet
rules anyway, so start testnet with a new `--data-dir`. Only a data dir
whose recent blocks are all at or above height 17,500 (or that holds only
the genesis) is marked for the running network without this check. The two
networks also use different gossip topics and sync protocols, and a node
disconnects a peer of the other network after the identify exchange
(docs/CONSENSUS.md, "Networks"). A dialed address enters `known_peers.json`
only once the peer's identify shows it runs the same network; an address of
the other network is removed from it (entries saved by an earlier release,
when both networks shared topics and peer exchange, included) and is not
dialed again from peer exchange during that run.

## Mining

```sh
./target/release/gnb --data-dir ./gnb-data --mine \
    --miner-address gnb1q... --mine-threads 8 --peer /ip4/<seed-ip>/tcp/17110
```

A node given `--peer`/`--dns-seed` waits until it has seen the network tip
before it mines, so it never forks from genesis.

## Initial sync and minimum chain work

A mainnet node has a minimum chain work (Bitcoin Core's `nMinimumChainWork`):
the blue work, in the unit of `getdaginfo`'s `tip_blue_work`, below which
the node is in initial block download. Mainnet's default is
`core::MIN_CHAIN_WORK` = 7,000,000 (`0x6acfc0`), derived from the mainnet
reading of 2026-10-14 (tip height 8,302, blue work 7,782,451;
docs/MAINNET-READINESS.md §1); testnet's is 0. While the selected tip
carries less, the node:

- processes no block it did not request unless that block's own chain
  reaches the value (docs/CONSENSUS.md, "Minimum chain work and unrequested
  blocks"), and refuses such blocks from `submitblock`;
- does not mine, even when the sync stalls, and `getblocktemplate` answers
  "in initial block download" (Bitcoin Core's miners get no template there
  either); a witness node (`--witness-wallet`) neither attests checkpoints
  nor mines shares;
- advertises no frontier or headers to peers (GetTips / GetHeaders are
  answered empty, as Core ignores `getheaders` in initial block download),
  while still serving the blocks it stores: blocks it requested are
  processed below the minimum, so its tip may be a cheap chain an eclipsing
  peer fed it, and that chain is not passed on;
- reports `syncing: true` (`getnetworkinfo`) and
  `below_minimum_chain_work: true` (`getdaginfo`, next to
  `minimum_chain_work`, both decimal).

It logs at start-up when its chain is below the value, and warns every 30
minutes while it stays below it ("has been below the minimum for N min ...
restart it with a lower --minimumchainwork"). A fresh mainnet node reaches
the value after about 7,400 blocks of the mainnet chain.

`--minimumchainwork <hex>` (hexadecimal, at most 32 digits, `0x` optional)
replaces the default: a higher value (the blue work of a block you know is
on the real chain, e.g. a trusted node's `tip_blue_work` converted to hex)
protects a fresh sync further; a lower one, `0` to turn it off, is for a
node that must leave initial block download on a chain with less work,
for example the only node of a network restarted from an empty data dir
with no peer to sync from. The node warns at start-up when the value is below
the default, as Core does. A value the network has not reached keeps the
node in initial block download for good.

The minimum is node-local policy, not consensus: no block's validity, no
GhostDAG data and no fork choice among the blocks a node holds depend on
it, so nodes with different values (an override, or a release before this
one, which has none) reach the same verdicts on the same blocks.

Release step (each mainnet release, as Bitcoin Core's release process sets
`nMinimumChainWork`): read the value from at least two independent nodes
(different operators and machines) that are in sync, with

```sh
python3 tools/release/min_chain_work.py \
    --rpc http://127.0.0.1:17210 --rpc https://node2.example:17210
```

It reads, on each node, the selected-chain block 2,880 blocks (about a day)
below the tip (`getselectedchain`, `getblockdag`), takes the LOWER reading,
checks that its block is on every node's selected chain with the same blue
work, rounds it down to two significant digits, refuses a value below the
one the nodes already run, and prints the line for `core::MIN_CHAIN_WORK`
(`crates/gnb-crypto/src/core/mod.rs`) and its `--minimumchainwork` hex form
(`--depth 20160` takes a block a week deep; deeper is only lower). It also
prints the assumed-valid block of the release, the same block (Core sets
`defaultAssumeValid` and `nMinimumChainWork` from one block): the line for
`MAINNET_ASSUME_VALID` (`node/src/assumevalid.rs`, its id and DAG height)
and its `--assumevalid` form; reviewers check the id with `getblockdag` on
their own nodes. Update the
reading in the constant's documentation, docs/MAINNET-READINESS.md §1 and
the test `min_chain_work_cross_check`, then confirm that a node started on
an empty data dir syncs from the seeds and leaves initial block download.
Blue work is continuous across the GnB-SMH v1 -> v3 switch and the hardening
activation (it only gains the merged blues), so the value needs no
adjustment for either.

Block proofs of work (GnB-SMH v1, 64 MiB, below the PoW + PoWit activation;
v3, 4 MiB, from it) are evaluated on a bounded pool of threads (half the
logical CPUs, 1 to 4; while the IBD latch holds and the miner waits, every
CPU but one, at most 8, which with v1 holds up to 512 MiB of scratchpads),
each peer and each network group (IPv4 /16, IPv6 /32) with a small budget of
failed evaluations. A body the node fetches again for a block already in its
DAG (a pruned body a reorg needs again, or a body rejected for a
witness-dependent reason) costs no evaluation: the DAG record is the
verified proof, also after a restart. Proofs are never skipped, not below
the assumed-valid block either (Bitcoin Core never skips them). A peer that
delivers a block it authored that fails validation is disconnected, and both its identity and
its address (IPv4 address, IPv6 /64) are refused for 24 hours; loopback
addresses are never refused (only disconnected) and `--peer` peers are
exempt. The same happens to a peer whose misbehaviour score (one shared
decaying score: wire violations, gossip frames proven invalid, directed
answers that break the request/response contract) crosses its threshold.
The sets are in memory (a restart clears them). The connection manager
(below) dials no discouraged address, and a peer connected from an address
discouraged since (another identity there misbehaved) is the first inbound
peer evicted when the slots are full.

Gossiped PoWit items (witness shares, attestations, equivocation proofs) are
verified with transactions, never on the block path, on their own bounded
pool (half the block pool, at least one thread) with their own per-peer and
per-network-group budgets of failed verifications; an item whose id or
encoding is wrong, or whose share proof or witness signature is invalid,
counts against its sender like an invalid block.

The PoWit pool that holds them is bounded and follows the selected tip on
every node (not only witnesses): each tip change forgets shares out of the
window, attestations no next block can include and proofs against barred
keys. An attestation is held only by a member of its target's witness set
(under the rules of the block that may include it: from the second hardening
activation every share key with weight is a member), for a checkpoint slot
at most one interval above the tip and not expired, from the tip's justified
checkpoint; a key holds at most two (its newest targets), and templates take
a target's heaviest votes first. An equivocation proof is held and relayed
only against a key in a recent witness set (from the second hardening
activation, a member of the next block's evidence epochs, the consensus rule;
checked before its signatures; a refused proof keeps its sender's
verification-budget charge, as a forged one is free to make), at most 256 of
them, one per key, and templates take the heaviest witnesses' proofs first.
Full pools evict their worst entry for a better one.

### The assumed-valid block (`--assumevalid`)

As Bitcoin Core's `-assumevalid`, a release can name a block of the real
chain (`assumevalid::MAINNET_ASSUME_VALID`, its id and DAG height). When the
node connects a block that block vouches for, it does not verify that
block's transaction signatures; every other check runs as always (proof of
work, difficulty, height, timestamps, commitments, amounts, UTXO existence,
double spends, coinbase maturity, timelocks, the public key and policy
hashes a spend reveals, fees, the coinbase value). A block is vouched for,
with Bitcoin Core's conditions, when the assumed-valid block is in the
node's DAG, the block is it or lies on its selected chain and on the
selected chain of the node's best block, the best block has at least the
minimum chain work, and the best block is more than two weeks of
proof-equivalent time above it (its chain work above the block at the best
block's difficulty, 30 s per block: 40,320 blocks at constant difficulty).
A block whose id does not commit to its witnesses (below height 5,000 and
the hardening activation) is always checked in full, and an assumed-valid
block this node has found invalid (or that the operator invalidated)
vouches for nothing. The node logs "connecting N block(s) with their
signatures assumed valid" when it applies.

- `--assumevalid <id>` (64 hex digits, as `getblockdag` prints it) names
  another block; `--assumevalid 0` checks every signature.
- Mainnet has no release value yet: the relaunched chain is younger than two
  weeks, so no block would qualify. The release step above prints one.
- It is node-local, not consensus: a valid chain is accepted either way; the
  setting only saves signature checks (docs/CONSENSUS.md, "Assumed-valid
  block").
- Where it helps today: the node connects a block as soon as it has its
  parents (there is no header-first download yet), so during a fresh initial
  sync the assumed-valid block's header is not known when its ancestors
  connect and they are checked in full. It applies when the node connects
  blocks with that block already in its DAG: a chain-state rebuild, the move
  onto the real chain of a node that sat on another branch (a partition or
  an eclipse), bodies fetched again, and a restart that resumes a chain move.

## Peers and connections

Connection management follows Bitcoin Core's `CConnman` / `addrman` design
(audit NET-11, re-audit B1-T8 and B1-T9); the code is in
`node/src/network/{connmgr,addrbook,gossip_gate,pex_validator}.rs`.

Settings:

- `--peer <multiaddr>` (repeatable): a manual connection (Core's
  `-addnode`). It is dialed at start-up and re-dialed every 30 s while it is
  not connected (an entry without `/p2p/<id>` is re-dialed while no manual
  connection is up). It never uses an automatic outbound slot. A host name is
  resolved by the node; like an IP literal given here, it may resolve to a
  private or loopback address (docker / LAN setups) whatever
  `--allow-private-peers` says, but never into an invalid range (unspecified,
  multicast, documentation, link-local such as 169.254.169.254, …). The
  30 s re-dial resolves names on a separate task (at most 10 s per lookup),
  so a configured host that is down or slow to resolve never stalls the
  node's network loop.
- `--dns-seed <host[:port]>` (repeatable, opt-in): resolved at start-up and
  dialed as manual connections. Answers that are not routable public
  addresses are ignored unless `--allow-private-peers` is set.
- `--max-peers <n>` (default 50): the INBOUND slots. Outbound slots come on
  top of them and cannot be used by inbound connections.
- `--allow-private-peers`: dev/test only. Accepts loopback, RFC 1918, CGNAT,
  ULA and link-local IPv6 addresses in the address tables.
- `--enable-mdns`: zero-config LAN discovery (off by default).

Outbound connections. The node keeps 8 full-relay and 2 block-relay-only
outbound connections (Core's 8 + 2), whatever the inbound count, and opens
at most one automatic outbound connection per second to fill a free slot
(full-relay slots first, then block-relay-only). Addresses come from the
address tables, half the time from the tried table and half from the new
table; at most one automatic outbound peer per netgroup (an IPv4 /16, an
IPv6 /32; an IPv6 literal that embeds an IPv4 — `::ffff:a.b.c.d`, 6to4,
Teredo, NAT64 — counts as that IPv4's /16); an address tried in the last 10
minutes is not tried again. Small-network fallback (not in Core, which
relies on seeds; this network ships with none): when neither table holds a
candidate outside the netgroups already used, a full-relay slot may take a
peer in a used netgroup, up to 4 automatic outbound peers per netgroup, so
nodes hosted in one /16 still connect to each other after a restart.
Block-relay-only slots never relax the one-per-netgroup rule.

Inbound connections. When a new inbound connection finds the `--max-peers`
slots full, an existing inbound peer is evicted, chosen as Core's
`SelectNodeToEvict` does: the peers in 4 netgroups picked by a secret key,
the 8 lowest-latency peers (libp2p ping), the 4 that most recently delivered
a new transaction, the 4 that most recently delivered a new block, and the
longest-connected half of the rest are protected; among the rest, a peer
connected from an address discouraged since it connected (see "Initial sync
and minimum chain work" above) is evicted first (Core's `m_prefer_evict`);
otherwise the most recently connected peer of the netgroup with the most
remaining peers is evicted.
With fewer than 21 inbound peers everyone is protected and the newcomer is
refused. At the transport level a node accepts `--max-peers` + 1 inbound
connections (the extra one is the newcomer under evaluation), at most 2
connections per peer, and `max(2 × max-peers, max-peers + 32)` connections in
all.

Address tables. Peer exchange (`GetPeers` over `/gnb/sync/1`) carries IP
literals only — host names are refused, and so is any address that is not a
routable public address once an embedded IPv4 is taken into account (so
`/ip6/::ffff:127.0.0.1/…` is refused like `/ip4/127.0.0.1/…`). A received
address goes into the in-memory **new** table (1,024 slots: 64 buckets of
16); a successful outbound connection moves it to the **tried** table
(1,000 slots: 125 buckets of 8), saved every minute as `known_peers.json`,
once the peer's identify shows it runs this node's network (audit POW-9; a
peer of the other network is disconnected, its addresses leave the tables
and it is not dialed again during the run).
Bucket and slot are chosen by a keyed hash (a secret derived from the node's
P2P identity key, never sent anywhere), as in Core's addrman: the addresses
one peer's netgroup sends can only reach 4 of the 64 new buckets, and one
netgroup can hold at most 16 tried entries. A full tried bucket never evicts
on the spot: the occupant is tested first by a feeler connection and kept if
it answers (Core's test-before-evict); it is also kept, and the newcomer
dropped, if its feeler fails but it connected successfully in the last 4
hours (Core's `ADDRMAN_REPLACEMENT`; entries loaded from `known_peers.json`
count as successful at start-up). Addresses are read only from the answer to
the node's own `GetPeers`; a `Peers` answer to any other request is ignored. The node asks for addresses only on
its outbound full-relay and manual connections and answers only inbound
peers, once per connection, from a sample of the tried table cached for 21
to 27 hours (Core's getaddr cache), so asking repeatedly reveals no more of
the table. 20 addresses per answer and 100 per 5 minutes per answering peer
are read.

Feelers. While every outbound slot is full, the node opens a short-lived
"feeler" connection about every 2 minutes (exponentially distributed): to a
tried-table occupant awaiting a collision test, else to a random new-table
address. A feeler carries no gossip and none of the node's requests, and is
closed about a second after it is established (once the remote has finished
its side of the connection setup, as Core waits for the version handshake);
a new-table address that answered moves to the tried table.

Block-relay-only connections and anchors. The 2 block-relay-only
connections carry no gossip at all (no transactions, no addresses, no block
announcements): gossipsub never sees them, so they cannot be found through
transaction or address relay. The node learns blocks over them by polling
the peer's frontier (`GetTips` every 30 s) and pulling what it lacks. Their
addresses are saved in `anchors.json` (at most 2) whenever that set changes;
at start-up the file is read once, deleted, and its peers are re-dialed
first as block-relay-only connections (Core's `anchors.dat`). Nothing the
node publishes crosses a block-relay-only connection (the remote treats it
as an ordinary inbound peer without gossip and does not poll us), so these
peers are left out of the peer count the node reports (RPC `peers`, and the
miner's wait-for-peers check): a node connected only to its anchors does not
mine as if it were on the network.

External address. A peer-reported observed address becomes the node's
advertised address only when peers in 3 different netgroups report it.

Differences from Bitcoin Core, by design or not yet done: no AS-map (netgroups
are IP prefixes); no Tor / I2P / CJDNS networks, so no protection quota for
them; the new table is not persisted and a new-table address is dropped once
dialed (no attempt counters); an occupied keyed slot probes to the next free
slot of the same bucket (bucket bounds unchanged; avoids losing addresses to
collisions at this table size); block-relay-only peers do not push blocks to
us (we poll them every 30 s); no extra rotating block-relay-only peer or
stale-tip extra outbound connection; anchors are written when the set
changes rather than at shutdown (the node has no orderly network shutdown).

Block-relay-only connections carry no PoWit items either: witness shares,
attestations and equivocation proofs (`NewPowitItem`) are gossiped on the
transaction topic, and gossipsub never sees those connections. A PoWit item
accepted from a peer does not count as a novel transaction for the inbound
eviction protection (Core protects for novel blocks and transactions only).

Transaction privacy: transactions are gossiped from the node that creates
them; the origin IP is not hidden (the unused Dandelion++ sketch was removed,
NET-17). The P2P transport (`/gnb/pq/2.0.0`, `docs/P2P.md`) authenticates
each peer with its Ed25519 libp2p key and its hybrid ML-DSA-65 ‖ Falcon-1024
key, and derives session keys from ML-KEM-768 and X25519.

## Genesis

`gnb-mine-genesis` recomputes the genesis nonce. It is only needed if the
genesis constants in `crates/gnb-crypto/src/core/mod.rs` change, which is a
new chain.

## RPC

JSON-RPC on 127.0.0.1:17210. Useful methods: `getblockcount`, `getdaginfo`,
`getblocktemplate`, `submitblock`, `getsupplyinfo`, `getbalance`,
`sendrawtransaction`. See `node/src/rpc/mod.rs`.

Transaction relay and mempool policy (unconfirmed chains, child-pays-for-parent
templates, full-RBF, orphan transactions): `docs/MEMPOOL.md`;
`getmempoolinfo` reports the parameters in force.

Heights in `getblockhash`, `getblockbyheight`, `getrecentblocks`,
`getblock` given a number, the address history (`listtransactions`'
`block_height`, `getaddressbalance_at_height`) and the pruning cursor
(`pruned_height`) are positions on the applied selected chain: the DAG
height, 0 for the genesis and one more per selected-parent step (audit DAG-8),
like Bitcoin Core's active-chain heights. `getblockhash N` names exactly one
block, the selected-chain block at position N. A block's header height
(`getblock`'s `height`, the height its difficulty and coinbase commitment
use) can be larger than its position when it merges a parent with a greater
DAG height; header heights can repeat along the selected chain, which is why
the indexes are not keyed by them. A data dir from an earlier release (keyed
by header height, where two chain blocks could share a row) is migrated once
at start-up (log line "DAG-8: selected-chain indexes migrated …"), before
reconciliation moves the chain, over the chain reconciliation leaves applied
(the block it re-tips to when it rolls back blocks that have UTXO effects but
no DAG record). The address history of a block whose body is stored is
rebuilt from the body; that of a pruned block is moved to its position, from
its pruned-body record, or, for a body pruned by a release before that
record existed, from the rows themselves (each attributed to its block
through the transaction index; a record naming them is written so that a
later reorg deletes them). A row that an earlier release had overwritten
with another block's, or that cannot be attributed to a block, cannot be
recovered and is reported as lost. The rebuild also drops the rows earlier
releases wrote for blocks that never joined the chain and restores the spend
rows of bodied blocks that a reorg had deleted (each block's undo record
holds the outputs it spent). `--reindex-addresses` runs the same rebuild on
demand at start-up, after reconciliation, over the applied chain ("address
history rebuilt: N blocks, R rows, U unresolved inputs"); it needs no
`--carryover-snapshot`, since spends of genesis-ledger outputs are resolved
from the undo records too. The rows are always exactly what connecting the
block writes, keyed by chain position, so the migration and the flag can
never produce two layouts.

The explorer statistics (`getchainstats`, `gethashrate`, `getrichlist`,
`getsupplydistribution`, `getaddresscount`) are served from aggregates the
node keeps in the same write batches as its UTXO set. A data directory
written by an older node gets them built once at start-up (log line
"NET-12: explorer aggregates rebuilt …", one pass over the UTXO set and the
undo records); until then those methods answer with an error instead of
scanning. Every start-up also checks that the stored aggregates describe the
connected chain on disk (block count and a fingerprint of the connected
blocks against the undo records) and rebuilds them when they do not, instead
of serving stale statistics. (An older release can no longer move the chain
of an upgraded data directory forward: see "Upgrading and downgrading".)
`hashrate_hs` counts every DAG block (the selected-chain blocks and the blue
and red blocks they merge, `avg_dag_block_interval_secs`);
`avg_block_time_secs` is the interval between selected-chain blocks. A
storage failure behind any of these methods is answered with the generic
`STORAGE_ERROR` response; the detail only goes to the node's log.

### Supply audit: `gettxoutsetinfo` (audit VAL-11)

`gettxoutsetinfo` is the counterpart of Bitcoin Core's method of the same
name. It reads the whole UTXO set and every undo record in one RocksDB
snapshot (a block connected meanwhile is wholly in the answer or not at all)
and answers:

| Field | Meaning |
|---|---|
| `height`, `bestblock` | the applied tip and its chain position |
| `txouts`, `total_amount_sat` | unspent outputs and their total |
| `hash_serialized` | SHA3-256 of the UTXO rows in key order (domain `gnb/utxo-set/v1`; each row `u32 LE len ‖ key ‖ u32 LE len ‖ value`). Two nodes with the same set report the same hash; compare it across nodes at the same `bestblock` |
| `applied_blocks`, `undo_off_chain`, `chain_without_undo`, `chain_ok` | blocks with an undo record (the connected chain, genesis excluded); of those, the ones not on the selected chain of `bestblock` (a stale record, whose subsidy would inflate `max_supply_sat`); the blocks of that chain without a record (their subsidy is missing from it; a chain whose walk stops at a missing DAG record counts one more); `chain_ok` when the records are exactly that chain (both counts 0 and `applied_blocks` = `height`) |
| `expected.carryover_sat` | the genesis ledger's verified Bloch carryover |
| `expected.locked_sat` | the genesis ledger's locked team and founder allocations (2 × 1,250,000 GNB in 72 timelocked policy outputs, `core::vesting`; in the set whether unlocked or not) |
| `expected.subsidy_sat` | the subsidy of every connected block, at the header height its coinbase was checked against |
| `expected.max_supply_sat` | carryover + locked + subsidy: the most the set may hold |
| `expected.schedule_issued_sat` | `issued_through_sat(height)`, the schedule through the tip's position, an upper bound of `subsidy_sat` |
| `unclaimed_sat` | `max_supply_sat - total_amount_sat`, `null` when the set holds more |
| `supply_ok` | the set holds no more than `max_supply_sat` and every row decodes |
| `aggregates` | the scan's count and total over address (20-byte) scripts against the aggregates the node keeps in the same write batches as the UTXO set |
| `ok` | all of the above hold |

`unclaimed_sat` is value that can never be spent, and is expected to be
positive and to grow: a miner that claims less than its allowance burns the
difference (consensus allows it); from the PoWit activation (mainnet height
10,000) 20% of each subsidy is reserved for 16 witness-share slots, and the
slots a block leaves empty, with the rounding of the split, are never issued
(`witness_share::split_subsidy`; the shares that are paid are coinbase
outputs like the miner's, in the total); and value that enters the shielded
pool leaves the transparent set (no shielded transaction is valid while the
pool is inactive). No coin is ever overwritten: BIP30 is enforced at every
height. Fees are not issuance: they move value from transaction outputs to
the coinbase, and the proof of work (GnB-SMH v3 from the PoWit activation)
does not change the subsidy. Outputs paying unspendable scripts (the genesis
coinbase creates none) stay in the set and in the total, as in Core. Policy
outputs (multisig, timelocks, the locked tranches) are in the total but not
in `aggregates`, which counts address (20-byte) scripts only. A total above
`max_supply_sat` (`supply_ok: false`) means inflation or a corrupted set; an
aggregates mismatch with the supply bound intact means a UTXO row changed
outside the node (disk corruption, an edited data dir). Either way stop the
node and resync from a fresh `--data-dir` (or an archival node's data dir):
the node has no `-reindex-chainstate` yet, and the start-up rebuild of
"Chain-state check at start-up" only runs when it finds an interrupted
commit.

The method is in the heavy class (one computation at a time; a result is
cached for 30 s per applied tip, so a block connected or disconnected since
is never answered from the cache, and `bestblock` says which chain it
describes) and is
cancelled at the RPC deadline (25 s inside the 30 s request timeout),
answering `{"error":"cancelled"}`; it never blocks block acceptance.

The per-address reads are bounded the same way (audit B1-T11): `getbalance`
and the balance in `getaddresshistory` are one read of the holder aggregate,
the history `total` is a per-address counter kept in the same batches as the
address index (aggregate layout 2: a data directory written by an earlier
release rebuilds its aggregates once at start-up, and `total` is `null`
until then), and a `getaddresshistory [address, limit<=100, offset, cursor]`
page walks the index newest-first from its end, or from `cursor` (the
`next_cursor` of the previous page, 32 hex characters, `null` on the last
page). `offset` is at most 10,000 (`max_offset`); a larger one is refused
with an error that names the cursor (it is not clamped: a clamped offset
returned the page at 10,000 again and again), and deeper pages use the
cursor. `listtransactions` refuses an offset above 10,000 the same way; over
a height range other than the whole history it counts at most 11,000 entries
(`total_available` is `null` above that, and `total_at_least` gives the
count it reached). The explorer's selected-chain cache follows the tip
incrementally and takes the DAG lock for at most 4,096 blocks at a time, also
when it catches up after a long gap (NET-15).

The node serves plain HTTP. To reach a remote node, put a TLS reverse proxy in
front of its RPC port or use an SSH tunnel
(`ssh -L 17210:127.0.0.1:17210 host`). Both CLI wallets speak HTTPS (audit
WAL-7): `gnb-cli --rpc-url https://node.example …` or
`gnb-wallet --rpc https://node.example …`. They verify the certificate chain
against the Mozilla roots (`webpki-roots`) and check the host name. For a
private CA or a self-signed certificate, pass the trust anchor with
`gnb-cli --rpc-ca ca.pem` or set `GNB_RPC_CA=ca.pem` for `gnb-wallet`.
`GNB_RPC_API_KEY` is sent over HTTPS to any host, but over plain HTTP only
to loopback addresses. Each call has one 30-second deadline covering name
resolution, connect, the TLS handshake, the request and the response; every
socket read and write gets only the time left, so a server that stalls or
drips its answer cannot hold the wallet longer than that.

### Remote RPC through a proxy or tunnel (audit B2-T11)

A reverse proxy or a tunnel delivers every remote request from loopback, so
the node cannot tell its operator from anyone the proxy serves by the
connection alone. Any setup that exposes the RPC port this way MUST:

1. set an API key (`--rpc-api-key-file <file>`) and require it for writes
   (`--rpc-require-auth-for-writes`), so `sendrawtransaction`, `submitblock`,
   `submitpowititem` and the administrative methods need the key (Bitcoin
   Core never serves RPC without credentials);
2. NOT use `--rpc-trust-loopback`. The node never extends that trust to a
   request that carries a forwarding header, but a proxy that adds none (a
   raw TCP forward, an SSH tunnel from another user) would make every remote
   caller an administrator;
3. have the proxy append the client's address to `X-Forwarded-For` (nginx
   `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`, HAProxy
   `option forwardfor`, Caddy and cloudflared by default), or, if it writes
   another header, name that header with `--rpc-proxy-client-header`
   (`x-real-ip`, `cf-connecting-ip`, `forwarded`, ...). The node reads the
   client from that one header only: a proxy that sets only `X-Real-IP`
   passes a client's own `X-Forwarded-For` through, so with the default the
   client would name its own bucket.

A request carrying any forwarding header (`X-Forwarded-For`, `X-Real-IP`,
`True-Client-IP`, `CF-Connecting-IP`, `Forwarded`, ... : `FORWARDING_HEADERS`
in `node/src/rpc/auth.rs`) is treated as a remote request even when it
arrives from loopback, and it is never a trusted caller. When the proxy
connects from loopback (or from a trusted private range with
`--rpc-trust-private-ranges`), the request is rate-limited in the bucket of
the client named by `--rpc-proxy-client-header` (for `X-Forwarded-For` and
`Forwarded` the last entry, the one the nearest proxy wrote; a request
without a parsable address there shares the proxy's own bucket). A request
from any other address is limited in the bucket of that address, whatever
its headers say, so a remote client cannot pick a fresh bucket per request.
A caller that presents the API key through a proxy skips the separate
read/write method buckets. Every remote or forwarded request first consumes
a source token **before key verification and body parsing**, including
malformed requests and requests with a correct key. This pre-authentication
budget is the sum of the configured read and write rates (each at least one),
**65 requests/minute by default**, with a burst of the same size and continuous
refill. Once exhausted, it refuses **all** methods with HTTP 429, including a
valid `submitblock`. Size `--rpc-rate-limit-reads` and `--rpc-rate-limit-writes`
for the pool's combined polling/submission rate and leave headroom for found
blocks. Template polling below this overall bound does not consume the
write-method bucket. This is a deliberate availability tradeoff: checking a
key cannot bypass the budget that bounds the work of checking keys.

Named clients of a trusted proxy retain separate source budgets. Unnamed
forwarded clients share the proxy address's budget. IPv4 and its IPv4-mapped
IPv6 spelling share the same /32 budget; unrelated mapped IPv4 clients are
independent. Native IPv6 sources share their /64 budget.

Direct loopback callers without a forwarding header
(the operator's `gnb-cli`, a co-located pool) keep the loopback exemption.
The header is never trusted for authorization: it can only take trust away.

`submitblock` runs the cheap checks first (structure without the proof of
work, known parents, height, expected bits, timestamp) and evaluates the
64 MiB proof of work last, as gossip ingress does, so an invalid submission
costs no proof evaluation unless it is otherwise a valid next block.

### Request bodies (audit B1-T4)

RPC request bodies are capped at 1 MiB, except `submitblock`, whose body
carries the block as hex (twice its wire size): it may be up to 4 MiB, room
for a full 1,000,000-byte block. At most four bodies above 1 MiB are read at
a time (the rest are answered HTTP 503, JSON-RPC -32005, "busy"), plus two
more reserved for the operator's callers (a caller that presents the API key,
or a direct loopback caller without forwarding headers): the method is only
known once the body is read, so anonymous uploads that stall could otherwise
hold every permit and lock the operator's miner out of full-block
`submitblock`. A body that is not `submitblock` and exceeds 1 MiB is answered
HTTP 413. Bitcoin Core accepts bodies up to 32 MiB.

### Anonymous transaction submissions (audit B1-T10)

`sendrawtransaction` from a caller that is not trusted (no API key, not a
trusted direct caller) is charged to one node-wide budget by its size before
its signatures are verified: 2,000,000 bytes, refilled at 50,000 bytes per
second. An admitted transaction is refunded, so the budget only runs out
under transactions the node refuses (a flood of forged signatures relayed
by the explorer API, from any number of addresses). `submitpowititem` (a
PoWit share, attestation or equivocation proof, whose KES signature is
checked) is charged to the same budget the same way. While it is exhausted,
anonymous submissions are answered "busy: ..."; callers presenting the API
key are never charged.

## Chain selection and operator recovery

The node always follows the best valid chain of the blocks it holds, at any
depth: there is no reorg-depth limit and no finality checkpoint. A reorg of
more than 1,000 blocks is logged at error level ("DEEP REORG committed") and
counted in `gnb_deep_reorgs_total`; it is never refused.

To leave a chain anyway (for example while an incident is investigated), or
to return to it:

```sh
GNB_RPC_API_KEY=<key> gnb-cli invalidateblock <block-hash>
GNB_RPC_API_KEY=<key> gnb-cli reconsiderblock <block-hash>
```

`invalidateblock` disqualifies the block and every block whose selected chain
passes through it, rolls the node back past it if needed and moves to the
best remaining chain. `reconsiderblock` reconsiders the marks of the block, of
its selected-chain ancestors and of its selected-chain descendants and lets the
node re-evaluate: operator marks (and marks a block only inherited from a
marked ancestor) are removed; a block the node found invalid itself keeps its
mark unless it is re-validated — a block that failed the hardening block rules
at start-up (stored by an older release) only if its stored body now passes
them, a block that failed in its chain context only when the move connects it
after validating it again (a block that really is invalid is disqualified
again; a block the move cannot connect yet, for example because its stored
body is rejected and dropped or a body below it must be re-fetched, keeps its
mark: run `reconsiderblock` again once the body is back). Both
are persisted and survive restarts, and they are the RPC methods of the same
name (parameter: the block hash in hex). They are never served to an
anonymous caller: they need the configured API key (`--rpc-api-key` /
`--rpc-api-key-file`) or a trusted caller (`--rpc-trust-loopback`).

A pruned node (the default; `--archive` keeps every block body) deletes, in
steps of 1,000 blocks, the bodies of ALL blocks more than 10,000 DAG heights
below its tip: the blocks of its chain and also merged, fork and unsolicited
blocks (Bitcoin Core prunes stale blocks with the rest). It keeps every undo
record, and for each pruned block of its chain the few index keys a rollback
needs, so a reorg of any depth still works. A body it fetches back because a
heavier chain needs it is kept until that chain is connected. The first
pruning after an upgrade from a release before the 2026-10 phase-4 fixes
indexes the stored bodies by height once (one pass over the block bodies).

On a pruned node (the default; not `--archive`) the chain to move to may
contain blocks whose bodies were pruned: for example, `invalidateblock` on the
first block of a fork the node followed in a reorg deeper than the pruning
depth, or `reconsiderblock` after an `invalidateblock` that rolled the node
back through pruned blocks. The call then returns an error saying how many
block bodies it is re-fetching from the peers (at most 4,096
per call, nearest the new tip first; the node keeps at most 1,024 body
requests in flight and sends the next ones as bodies arrive, so the transfer
never crowds out its other block requests). Repeat the same call once they have
arrived (a few seconds to minutes, depending on the count); each retry
requests the next missing bodies, until the call succeeds. A chain move
commits in steps of at most 16 blocks, each one atomic, so this error (or a
storage error) can come after some steps were already written, the mark
included: the node then sits on a consistent intermediate block, builds no
block template until the move completes, and finishes the move on the
retried call, with the next block or at the next start. Ordinary block
acceptance needs no retry: when a heavier chain needs pruned bodies, the node
accepts its blocks, fetches the bodies and moves to it once they are back.
The transactions of blocks rolled back from pruned bodies cannot be put back
into the mempool (docs/MEMPOOL.md, section 6); their senders must rebroadcast
them. A body of a block the node already holds is accepted only while the node waits
for it (it requested it, or the body it had was rejected) and only as the
answer to its own request; it is checked like a new block (height implied by
its parents, difficulty, timestamp, proof of work, the witness commitment
rules) before it is stored.

## Chain-state check at start-up

Before anything else the node verifies the integrity chain over its stored
GhostDAG records. A data dir written by a release from before the 2026-10
audit fixes can fail it without any tampering: that release ignored a failed
DAG write and zero-filled the missing parent link of the next block. The
node then repairs the records instead of refusing to start (audit DAG-11): a
record consistent with its own integrity hash is kept and relinked, a
missing or corrupted record is recomputed from the stored block header with
the consensus code, and a block that cannot be recomputed (its body is gone
too) is dropped together with its descendants and fetched again from peers.
The log says how many blocks were relinked, recomputed and dropped, and the
next start verifies strictly. If a block that would be dropped is applied
(on a pruned node, a lost record in the pruned range), the UTXO set cannot be
repaired in place and the node refuses to start: resync from a fresh
`--data-dir` (or an archival node's data dir).

If start-up reconciliation cannot connect the best valid chain (a storage
error), the node refuses to start ("Refusing to start: the best valid chain
cannot be connected"), as Bitcoin Core does when it fails to connect the
best block at init; fix the cause it names (disk space, permissions) and
restart. If it persists, the data directory is damaged: resynchronize into
a fresh, empty `--data-dir` (or start from a copy of an archival node's data
directory). A restart with `--carryover-snapshot` does not help here: the
start-up rebuild below only runs when the chain-state check finds the
footprint of an interrupted commit. Later acceptances always connect from
the applied tip recorded on disk, so a move that failed once is retried by
the next block.

### Blocks without a verdict, and "gnb stopped"

A block the node cannot judge because it cannot read its own chain state is
never marked invalid (docs/CONSENSUS.md, the no-verdict paragraphs under
"Coinbase commitment"). It keeps its body and is parked with its
descendants: the node stays on (and mines on)
the best chain it can judge and retries the block after 1 minute, then
2, 4, ... up to every hour. `getdaginfo` lists such blocks under
`no_verdict` (`class`, `attempts`, `reason`, `retry_in_secs`) and reports
`stopped` when the node has stopped. While a parked branch has more chain
work than the tip the node mines on, `getblocktemplate`, `getdaginfo` and
`getnetworkinfo` say so in `warnings` ("a branch with more chain work than
the applied tip is parked without a verdict ..."), and the node does not
report itself synced to a peer serving that branch (the IBD latch counts it).
A block whose stored body cannot be read is handled the same way (an engine
error is its `storage-engine` no-verdict); a stored body that does not
decode is deleted and fetched again from peers (`getdaginfo` shows nothing
for it; the log says "the stored body is dropped and fetched again").

* `class: "inconsistent-chain-state"` (a row the node's indexes require is
  missing, or a row does not decode) never stops the node. It is logged at
  error level ("the local chain state is INCONSISTENT", at most once a
  minute). A node whose own writes are intact never gets there: report it.
  If the block stays parked and the network moves on without this node,
  resynchronize as below.
* `class: "storage-engine"` (a RocksDB read or write error, a missing column
  family): three failures in a row on one block stop the node, like Bitcoin
  Core's `AbortNode`. Acceptance and templates refuse at once and the
  process exits with `gnb stopped: block <hash> could not be validated 3
  times in a row because the storage engine failed ...`; a restart that
  meets the same failure refuses to start. Check the disk (free space,
  permissions, I/O errors in the system log) and restart. If the failure
  persists, the data directory is damaged: stop the node and resynchronize
  into a fresh, empty `--data-dir` (or start from a copy of an archival
  node's data directory). The node has no `-reindex-chainstate`, and
  `--carryover-snapshot` alone rebuilds nothing in this case. A chain-state
  rebuild (below) during which a block cannot be validated does not complete:
  it says `chain-state rebuild incomplete ... the rebuild stays pending`, the
  node refuses to start, and the next start resumes the rebuild.

At every start the node checks its chain state for the footprint of an
interrupted or failed commit written by releases before the 2026-10 audit
fixes (UTXO effects of a block without its undo record), after the repairs the
start-up reconciliation makes on its own. If it finds one it rebuilds the
chain state from the block bodies — the UTXO set and its indexes, the undo
records, the shielded-pool state and the explorer statistics — which needs the
carryover snapshot:

```sh
./target/release/gnb --data-dir ./gnb-data \
    --carryover-snapshot genesis/bloch-g3-carryover.tsv
```

Without `--carryover-snapshot`, or on a pruned node whose old block bodies are
gone, it refuses to start and says why; resync from a fresh `--data-dir` (or
from an archival node's data dir). This includes a data dir last written by a
release from before blocks carried undo records: its applied blocks cannot be
rolled back, so the state is rebuilt (an archival node) or resynced (a pruned
node). Data dirs written by this release cannot
produce the footprint: every chain move is committed in atomic chunks of at
most 16 blocks, each together with its undo records, the tip pointer and the
shielded state (Bitcoin Core's `ActivateBestChain` steps through a reorg the
same way), so the memory a reorg needs does not grow with its depth and a
crash in the middle of a long reorg leaves a consistent intermediate chain
state that the next start continues from (with the PoWit finality pin
restored from it first). An interrupted rebuild likewise
resumes from its last committed chunk.

## Directed sync (`/gnb/sync/1`) and misbehaving peers

Block, header, frontier and peer-address requests go to one peer at a time
over the directed `/gnb/sync/1` request-response protocol. None of the
limits below changes which blocks are valid; they are node-local and apply
from the first start of this release (re-audit B1-T2, B1-T3, B1-T6, B1-T18,
B2-T5, B2-T6, B2-T7, NET-9, NET-10; code in `node/src/network/{pull,serve,
misbehaviour,sync_rr}.rs`).

As a client the node:

- accepts an answer only if it answers the request it was sent for: a block
  or "not found" for the requested hash, at most the requested number of
  headers and none below the requested blue score, tips for a tips request,
  addresses for an address request, or Busy. Any other answer is a protocol
  violation: it is dropped, the request goes to another peer, and the peer
  is penalized;
- sends a block request first to the peer whose answer announced the block
  (peers it dialed before peers that connected to it), never again to a
  peer that answered it (a Busy answer or a closed connection excepted: the
  peer may be asked again after its back-off or once reconnected), to at
  most 8 peers, with a growing delay from the third attempt on (250 ms
  doubling, at most 4 s), and drops it after 10 minutes or once every
  connected peer has answered it;
- ranks a peer down for a "not found" to one of its own requests or to a
  block that a peer it dialed announced (taken back when every peer asked
  answered "not found" and the request ran out of peers or attempts); for
  a "not found" to a block that a peer which connected to it announced
  (the announcement may be made up) only once a peer it dialed serves that
  block; the announcing peer for its own "not found", or when it answered
  Busy for the block and nobody served it; a peer for an empty header
  answer after claiming to be ahead, and for each Busy back-off after the
  first two in a row without a useful answer. A peer that keeps answering
  uselessly is asked only when no better peer could take the request at
  all;
- sends a header request first to up to 4 peers that recently claimed to
  be ahead, one after the other: peers it dialed first, then in an order
  keyed by a per-node secret (never by the size of the claim or by peer
  id); a shorter answer than asked from one of them is used and the request
  also goes to the next of them;
- keeps each peer's cooldown, scores and rotation slot when it disconnects
  (up to 1,024 peers), so reconnecting does not clear a stall cooldown
  (60 s, doubling for repeat offenders up to 16 minutes);
- lets the answers of one peer start at most 1,024 of the 4,096 queued
  block requests, those of all peers that connected to it together at most
  2,048, and at most 64 of the 512 frontier tips in flight; when the queue
  is full, its own requests (orphan parents, the 30 s nudge) take the place
  of a queued request another peer's answer announced, and a request
  announced by a peer it dialed takes the place of one announced by a peer
  that connected to it; otherwise the request is refused and re-issued
  later;
- counts a "not found" toward abandoning an advertised frontier tip only
  from a peer it dialed, and forgets an abandoned tip after one hour.

As a server it answers on two background workers (not on the network
event loop), each answer costing O(log n + limit) whatever the size of the
DAG; requests wait in a bounded queue (32 per peer, 512 in all) served
round-robin across peers. Per peer it answers at most 128 block requests in
a burst then 24 per second, 16 header requests then 2 per second, 8 tips
requests then one per 2 s, 4 address requests then one per 10 s, and 256
requests per second in all; a peer whose unwritten answers reach 4 MiB, or
all peers' 64 MiB, gets Busy without the answer being computed. Peers that
connected to the node share only 48 MiB of that: the last 16 MiB is kept
for peers it dialed and `--peer` peers. An answer
not written within 15 s is dropped, and a connection keeps at most 64
directed-sync streams open. Blocks are sent as stored (from the PoWit
activation with their PoWit section). The tips answer is the selected tip
and the best other valid tips by blue work, at most 256, never a
chain-disqualified block nor one whose chain misses the PoWit finalized
checkpoint; releases before this one sent every DAG
leaf, which upgraded requesters refuse without penalty. `getdaginfo` no
longer walks the selected chain.

Misbehaviour from every source feeds one decaying per-peer score (the
gossipsub application score; each offence -100, decaying 10 % a minute): an
invalid gossip frame the node rejects, a wire-rule violation on gossip or
on `/gnb/sync/1`, a malformed request, a wrong answer, an invalid block
sent as the answer to the node's own request, an invalid orphan
transaction. At -400 (four offences in a short time; also gossipsub's
graylist threshold) the peer is disconnected and its identity refused for
24 hours (up to 4,096 identities remembered). Bitcoin Core disconnects and
discourages a misbehaving peer the same way; it also discourages the
address, which this release does not do.

## Secret key memory (audit CRY-4)

Every long-lived secret key, seed and password GnB itself keeps lives in
its own `gnb_secret::SecretBytes` region (crate `crates/gnb-secret`), the
analogue of Bitcoin Core's secure allocator (`LockedPoolManager`: `mlock`,
`MADV_DONTDUMP`, `memory_cleanse` before release); the exceptions are listed
at the end of this section:

- on Unix each region is whole pages of an anonymous mapping, locked in RAM
  with `mlock` (never written to swap) and, on Linux and FreeBSD, left out
  of core dumps (`MADV_DONTDUMP` / `MADV_NOCORE`); it is wiped with volatile
  writes before it is unmapped. Other targets (Windows, the WebAssembly
  wallet) get wiped heap memory;
- the holders are neither `Copy` nor `Clone` (a static assertion fails the
  build otherwise): wallet and HD-wallet keys, the BIP39 seed and the HD
  master key, the node's P2P identity key, the KES witness seed and every
  leaf key derived from it, the witness key-file password, and the
  ephemeral ML-KEM-768 key and shared secrets of every P2P handshake;
- ML-DSA-65, Falcon-1024 and ML-KEM-768 keys are generated and used directly
  in those regions through PQClean's C functions (`gnb_secret::pq`): the
  `pqcrypto` wrapper types hold secret keys in `Copy` arrays that every call
  copies and nothing can wipe, so production code never builds one (the
  `secret_hygiene` test fails the build if it does). After a signature,
  key generation or KEM operation the stack the C code and the hash
  functions used is overwritten (`gnb_secret::scrub_stack`, 128 KiB, like
  libsodium's `sodium_stackzero`), and tests read the dead stack back to
  check that no copy of the secret is left. Registers and copies the
  compiler makes outside these paths are out of reach: this is best effort,
  like Core's.

Locking is best effort. The locked-memory limit (`ulimit -l`, systemd
`LimitMEMLOCK`) bounds it: a node needs a few pages for its long-lived
secrets plus two per concurrent P2P handshake, a wallet two per key. When
`mlock` fails the secret is still wiped on release, the failure is counted
and logged once ("could not lock secret key memory in RAM"), exactly as
Core warns. `deploy/gnb-node.service` sets `LimitMEMLOCK=16M`; for a manual
start raise `ulimit -l` if the warning appears.

Not in secret memory (wiped on drop where the code owns them, but neither
locked nor kept out of core dumps):

- short-lived secrets: passwords and phrases typed into the CLIs, decrypted
  keystore buffers (`Zeroizing`);
- the node's libp2p Ed25519 identity key (`p2p_identity.bin`, the key of its
  `PeerId`): libp2p holds it in its own `identity::Keypair` for the whole
  run, and libp2p offers no way to place it in memory the node allocates.
  It authenticates the node's libp2p identity only; the post-quantum
  transport identity (`PqIdentity`) is in secret memory;
- the ChaCha20-Poly1305 keys of each P2P connection's two cipher streams
  (`transport::TxStream` / `RxStream`), alive as long as the connection:
  `Zeroizing`, wiped when the connection closes. Bitcoin Core keeps its
  BIP324 session keys in ordinary memory the same way (`FSChaCha20Poly1305`,
  wiped with `memory_cleanse`); only its wallet keys use the secure
  allocator.

## Upgrading and downgrading

The upgrade to a release that keeps the shielded-pool state on disk (audit
COH-2) is one-way. From its first start the data directory holds the
RocksDB column family `shielded`. Every earlier release opens its database
read-write with a fixed list of column families that does not name it, and
RocksDB refuses that open (`Invalid argument: Column families not opened:
shielded`), so the earlier release stops at start-up. To downgrade, restore a
copy of the data directory taken before the upgrade (with the node stopped)
or resynchronize from a new data directory.

The first block a node accepts after upgrading to a release with the
reindex-root reachability layout (2026-10 phase-4 fixes, audit DAG-7)
re-lays out the reachability index once, from genesis, and writes every
record of it with that block (one pass over the index; later blocks rewrite
only the few records a reindex touches). The index is a cache: an earlier
release reads the new records (it ignores the reindex-root trailer of the
genesis record) and keeps answering exactly.

## Wallet keystores (audit CRY-7)

Every front end writes keystore **v3**, which authenticates the network and
the address in the AES-GCM associated data. Older **v2** files, from Bloch
or from GnB before the fix, authenticate neither: editing `gnb1q…` to
`gnb1t…` (and the `network` field) in a v2 file used to load the key for the
other network. Every path that opens a keystore therefore authenticates the
network (re-audit CRY-7): a v3 file proves its own; a v2 file opens only for
a network the caller states, on every path, not only for spending:
`gnb-cli send`, `keyinfo`, `importfounder` and `pubkey` (`--mainnet` /
`--testnet`), `gnb-cli policysign` and `vaultlock` (the network of the spend
or vault file), `gnb-wallet send`, `sign`, `address` and `pubkey` (same
flags), the web
wallet's `open` (the page states mainnet; this takes effect with the
rebuilt `site/wallet/gnb_wallet.wasm`: the file the site serves, pinned in
`site/wallet/app.js`, was built before this fix, and the same holds for the
wallet fixes B2-T2, CRY-4 and CRY-8, so the WASM must be rebuilt and
re-pinned before release), and the library
(`Keypair::from_encrypted_bytes_on` / `load_encrypted_on`;
`from_encrypted_bytes` / `load_encrypted` open v3 files only). The stored
address must be a valid address of that network and match the decrypted
key, and the file's `network` field must not name the other network; an HD
wallet refuses to import a key of the other network. When it is unlocked
for spending or signing, a v2 file is then rewritten as v3 under the same password,
but only once the command went ahead: after the send was checked and
confirmed (`send`) or the message was signed (`sign`); an aborted command
leaves the v2 file as it was. Before the rewrite the original v2 file is
copied byte for byte to a new `<file>.v2.bak` (`<file>.v2.bak.1`, `.2`, …
if that name is taken; an existing backup is never overwritten), mode 0600
and fsynced; if the copy cannot be written, nothing is rewritten. Keep that
copy if you use the key elsewhere: **Bloch wallets and GnB releases before
keystore v3 read only version-2 keystores** and cannot open the v3 file.
The rewrite itself is atomic (temp file, fsync, rename), mode 0600, and the
new bytes are decrypted and checked before they replace the old file. A v3
keystore needs no flag, but a stated network must match it. The library
calls are `Keypair::unlock_for_spending` (verify in memory, then
`PendingKeystoreMigration::commit`), `Keypair::load_for_spending` (both at
once) and, for front ends without a filesystem,
`Keypair::unlock_for_spending_bytes` (a front end that stores the v3 JSON
must also keep, or offer for download, the original v2 bytes).

### Address checksum and the network (CRY-7)

A GnB address is `gnb1q` (mainnet) or `gnb1t` (testnet) followed by the hex
of the 20-byte key hash and a 4-byte checksum, `SHA3-256(SHA3-256(hash))[..4]`.
The checksum does not cover the prefix, so `gnb1q…` and `gnb1t…` forms of one
hash both pass `Address::parse`. An opt-in second encoding whose checksum
commits to the network, address v2 (Bech32m, human-readable part `gnb` /
`tgnb`, `docs/ADDRESS-V2.md`), is accepted by the node, the wallets, the
explorer API and the Worker as an additional encoding of the same
destination. The legacy form stays the default output: released GnB wallets,
the Bloch wallets that share these keys and third-party integrations parse
only it.

The prefix risk is closed where it matters, in either encoding: every payment
path compares the destination's network with the wallet's own network,
which is authenticated (keystore v3, keyfile v1, or the network the caller
states for a v2 file): `TxBuilder::build_payment`, `Wallet` payments,
`gnb-cli send`, `gnb-wallet send` and the web wallet's `pay` refuse a
destination of the other network, and the node's `--miner-address` uses
`Address::parse_for_network`. The policy and bridge-vault commands do the
same against the network of the spend: `gnb-cli policyspend` (the network
stated with `--testnet` / `--mainnet`, mainnet by default),
`vaultrelease`, `vaultrecover` and `vaultcheckrelease` (the vault file's
network) refuse a destination of the other network, `vaultlock` opens the
paying keystore for the vault's network and `policysign` for the spend's.
A prefix typo therefore fails before anything
is signed, and a transaction signed for one chain is invalid on the other
(the chain id is in every sighash).

Policy addresses (multisig / timelocks: `gnb1m` mainnet, `gnb1n` testnet,
`address::PolicyAddress`) are newer and already commit to the network: their
checksum is `SHA3-256(SHA3-256(prefix ‖ hash))[..4]`, so the other network's
prefix on the same hash fails to parse.

Address RPCs now require the node's selected network, including read-only
queries. A mainnet node rejects a valid testnet address, and conversely, before
querying address storage. This is local RPC policy; it changes no transaction
or block rule. The previous read-only behavior accepted either network prefix.

`validateaddress` (`gnb-cli validateaddress ADDRESS`) and
`validateaddressverbose` use the shared address parser for legacy GnB, legacy
Bloch single-key aliases and optional v2 Bech32m addresses. `isvalid` / `valid`
means valid **for this node's network**. They retain `network` as the recognized
address network; `validateaddress.checksum` describes syntactic validation, so
a valid address of the other network has `checksum: true`, `isvalid: false`
and a `reason`. Successful results additionally return `canonical_address`
(the existing legacy GnB string) and `bech32m` (the optional network-bound v2
string). The `address` field continues to echo the supplied string. Conversion
fields are absent on failure. Default address generation and persisted wallet
strings are unchanged.

Equivalent encodings query the same existing hash or full-script index; they
do not create additional balances. `getutxos` accepts both single-key and
policy addresses. The existing balance, holder and history APIs remain
single-key only and reject policy addresses in either encoding.
