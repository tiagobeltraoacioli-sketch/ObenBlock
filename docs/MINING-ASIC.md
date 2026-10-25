# Mining ObenBlock with Bitcoin ASICs

Status: launch documentation for release 0.2.0. Values marked
`[AT LAUNCH: …]` are published at launch (docs/LAUNCH.md).

ObenBlock blocks are mined with SHA-256d on Bitcoin's 80-byte header
layout. A stock Bitcoin ASIC, or a rig rented on MiningRigRentals (MRR),
mines it with the same firmware and the same Stratum V1 protocol it uses
for Bitcoin. The only change is the pool URL and the worker name.

Sources: docs/DESIGN-obenblock.md §4 and §5.1, docs/OBENBLOCK-MINING.md,
and docs/STRATUM.md with the code in `node/src/stratum` and
`node/src/stratum_v2` (branch `obenblock/stratum-node`).

## 1. Why stock firmware works

- **Header.** The header is Bitcoin's: `version ‖ parents_commitment ‖
  merkle_root ‖ time ‖ bits ‖ nonce`. The parents commitment stands where
  Bitcoin has the previous block hash (DESIGN-obenblock.md §4.1).
- **Merkle root.** The header's root is Bitcoin's SHA-256d transaction tree
  over the txids. The miner computes it from `coinb1 ‖ extranonce1 ‖
  extranonce2 ‖ coinb2` and the merkle branch, exactly as for Bitcoin. The
  rest of the block body (witnesses, the shielded and PoWit sections) is
  committed inside the coinbase, so it never changes the branch
  (docs/OBENBLOCK-MINING.md §3.3, docs/CONSENSUS.md "Header Merkle root and
  body commitment (ObenBlock)").
- **Proof.** A block is valid when its id, `SHA-256d(header)` read as a
  256-bit little-endian integer, is at most the target of `bits`. This is
  Bitcoin's rule.

`node/tests/obb_sha256d_mining.rs`
(`stock_stratum_v1_miner_finds_a_block_the_node_accepts`) and
`reference/obb_job_test.py` simulate a stock-firmware device from the
`mining.notify` fields alone. **No real ASIC or MRR rig has been tested
against these servers yet** (tools/obenblock-stratum/README.md §1 says the
same of the external proxy). Test one device before you point more
hashrate at an endpoint (§9).

## 2. The node's built-in Stratum servers

The node has two built-in servers. Both are off by default, and both mine
**solo**: each block found pays its whole miner part to the address in the
worker name (docs/STRATUM.md).

| Server | Flag | Default bind | Transport | For |
| --- | --- | --- | --- | --- |
| Stratum V1 | `--stratum` | `0.0.0.0:3333` | plaintext JSON lines | stock ASIC firmware, MRR, V1 proxies |
| Stratum V2 | `--stratum-v2` | `0.0.0.0:3334` | Noise NX, encrypted and authenticated | SV2 firmware (for example Braiins OS) and SRI proxies, standard channels |

Run a node with both servers:

```text
obenblock --chain obenblock \
  --carryover-snapshot bloch-g3-carryover.tsv \
  --stratum --stratum-addr 0.0.0.0:3333 --stratum-max-sessions 256 \
  --stratum-v2 --stratum-v2-addr 0.0.0.0:3334 \
  --stratum-v2-key /var/lib/obenblock/stratum-v2-authority.json \
  --stratum-payout obb1q…
```

- `--stratum-payout` (or `--miner-address`) pays workers that use a plain
  label instead of an address (§3).
- The servers hand out no job while the node is in initial block download.
  The first job comes once the node has synced.
- The node refuses to start on a mistake: a GnB chain, a payout address of
  another chain or network, a bad bind address, or V1 and V2 on one port.

The public endpoints run by the launch operators are
`[AT LAUNCH: STRATUM_ENDPOINT, V1 host:3333]` and
`[AT LAUNCH: STRATUM_V2_URL, stratum2+tcp://host:3334/<authority pubkey>]`.
You can also run your own node and point your miners at it. That is the
recommended setup: you then check your own blocks.

## 3. Worker name and payout

The worker name (V1 `mining.authorize` username, V2 `user_identity`) is the
payout (docs/STRATUM.md §2.1):

| Worker name | Pays |
| --- | --- |
| `obb1q…` or `obb1m…` (a mainnet address) | that address |
| `obb1q….rig7` | that address; `rig7` is a label for your logs |
| `gnb1…` or `bloch1…` form of the same key | the same key, shown as `obb1…` |
| a plain label (letters, digits, `_`, `-`, at most 24 characters) | the node operator's `--stratum-payout`, else `--miner-address`; refused if neither is set |
| anything else (a Bitcoin address, a regtest address on mainnet, a typo, a name that is too long) | refused (V1 error 24, V2 `unknown-user`), never paid to the operator |

The V1 password is ignored. Use `x`.

Get an address with `obenblock-wallet` or the web wallet at
obenblock.xyz/wallet, and keep the keystore backed up. A block mined to an
address you cannot spend from is lost.

## 4. Configuration

### 4.1 Stratum V1 (ASICs and MRR)

| Field | Value |
| --- | --- |
| URL | `stratum+tcp://<node-host>:3333` |
| Worker | `obb1q…` or `obb1q….rig1` |
| Password | `x` |
| Version rolling | allowed, BIP 320 mask `1fffe000` (`mining.configure`) |

Supported methods: `mining.subscribe` (4-byte extranonce1, 4-byte
extranonce2), `mining.authorize`, `mining.configure` (`version-rolling`
only), `mining.submit` (with the BIP 310 version bits),
`mining.suggest_difficulty`, `mining.extranonce.subscribe`, `mining.ping`.

V1 is plaintext and unauthenticated. Anyone on the path can read jobs and
worker names, and a man in the middle can rewrite the worker name. Bind V1
to a private interface or firewall it to known addresses, or put a TLS
terminator in front of it (docs/STRATUM.md §5).

### 4.2 MiningRigRentals

MRR rigs are Bitcoin SHA-256 ASICs that speak Stratum V1
(docs/STRATUM.md §3.1):

1. In MRR, add a pool with host `stratum+tcp://<node-host>:3333`, worker
   `obb1q….mrr` and password `x`.
2. Point a SHA-256 rental at it.
3. MRR first tests the pool with a short connection. It shows up in the
   node log as a session that authorizes and closes.

MRR may rewrite the username. If it does, the worker name is no longer
your address, and the plain-label rule of §3 applies: the block pays the
node operator's `--stratum-payout`. Only rent against a node whose payout
you control, or check the worker name in the node log
(`session N authorized … -> pays obb1q…`) before the rental runs for long.

Set the rental's minimum difficulty in MRR, and keep the node's
`--stratum-max-sessions` above the number of rigs.

### 4.3 Stratum V2 (port 3334)

The node creates the authority key on its first start and logs the pool
URL:

```text
stratum_v2: pool URL stratum2+tcp://<host>:3334/9b…Ef (authority key file …/stratum-v2-authority.json)
```

- The last path element is the **authority public key** (SRI key-utils
  form, Base58Check). The key file also holds it as `public_b58` and
  `public_hex`.
- Configure the **full URL, with the key**. The Noise NX handshake then
  proves that the server holds the key. A miner that does not pin the key
  gets no protection against an impostor.
- The operator must back up the key file (mode 0600). A new key changes the
  URL for every miner.
- Standard channels only (header-only mining). Extended channels are
  refused (`unsupported-extended-channels`), and so is work selection.
- The public V2 authority key of the launch endpoint is
  `[AT LAUNCH: STRATUM_V2_AUTHORITY_PUBKEY]`. Compare it across two
  sources (docs/LAUNCH.md §4 lists them) before you configure it.

## 5. Difficulty

### 5.1 Network difficulty at launch

- The genesis anchors ASERT at `bits = 0x19009d69`, the target for
  **1 EH/s** of SHA-256d at 30 s blocks (`OBB_LAUNCH_BITS`,
  `crates/gnb-crypto/src/core/pow_scheme.rs`).
- In Bitcoin's difficulty unit this is about **6.98 × 10⁹**, about
  3.0 × 10¹⁹ expected hashes per block.
- The pow limit is Bitcoin's difficulty 1 (`0x1d00ffff`). The difficulty
  never goes below it.
- After block 1, ASERT moves the difficulty toward the real hashrate:
  30 s target, 2 h half-life (DESIGN-obenblock.md §4.2).

### 5.2 Stall relief

If the hashrate is far below the target, ASERT alone would stall. Stall
relief eases a late block's own target (DESIGN-obenblock.md §5.1):

- after 180 s without a block, the target doubles every 30 min, in 60 s
  steps;
- each step is a new job: the node republishes work within a second of the
  step, and every job carries its `ntime` window (`mintime` to `maxtime`);
- a share whose `ntime` falls outside the job's window is refused (V1
  error 21 when the step changed, V2 `stale-share` / `invalid-time`). This
  is normal at a step boundary.

A miner cannot fake lateness by more than 600 s (`MAX_FUTURE_SECS`), which
is at most about 1.26 times easier.

### 5.3 Share difficulty

Share difficulty is per session, in Bitcoin's unit (`difficulty × 2^32`
hashes per share), never harder than a block (docs/STRATUM.md §3):

- V1 vardiff aims at one share every 10 s. It starts at 0.01 and changes by
  at most 4× per retarget, after 8 shares or 90 s
  (`node/src/stratum/session.rs`).
- A V1 session may submit at most 30 times per minute. Further submits are
  refused with error 20.
- V2 sets the share target from the channel's nominal hash rate.

A fast ASIC starts far below its ideal share difficulty: a 100 TH/s device
wants about 2.3 × 10⁵. Until vardiff catches up, many of its submits hit the
30-per-minute limit. To avoid that:

- the node operator can raise the start with `OBB_STRATUM_START_DIFF`
  (environment variable, default 0.01);
- miners whose firmware supports it can send `mining.suggest_difficulty`;
- MRR renters can set the rental's minimum difficulty.

How long vardiff takes to settle on real ASICs has not been measured.

## 6. What a block pays

- Slow start: block `h` pays a subsidy of
  `floor(0.08561643 OBB × min(h, 5,760) / 5,760)` (DESIGN-obenblock.md
  §4.2, `pow_scheme::slow_start_subsidy_sat`). Block 1 pays 0.00001486 OBB,
  block 720 pays 0.01070205 OBB, block 3,600 pays 0.05351026 OBB, and the
  full 0.08561643 OBB is reached at block 5,760.
- The miner gets 80 % of the subsidy and 80 % of the fees, plus 10 % of
  every witness-share slot it fills. The other 20 % pays witness shares;
  fee slots left empty are burned (docs/MONETARY-POLICY.md, "Rewards").
- A coinbase is spendable after 100 blocks (`COINBASE_MATURITY`).
- Before height 3,600 there is no finality (docs/LAUNCH.md §5). A block
  can be reorganized out by a heavier chain, and its reward with it.

## 7. Expected first-block timing

The first block must meet the launch difficulty, made easier only by stall
relief: block 1's parent is the genesis, so ASERT does not lower it. The
table below gives **median** times from the genesis timestamp. It comes
from `deploy/obenblock-launch/lib/first_blocks.py` (consensus formulas,
Monte Carlo) in deploy/obenblock-launch/LAUNCH-RUNBOOK.md, "First blocks"
(branch `obenblock/launch-kit`). An independent calculation of the median
first block gives the same values within a few percent.

| Hashrate | Block 1 | Block 10 | Block 100 | Block 1,000 |
| --- | --- | --- | --- | --- |
| CPUs only (0.15 to 0.65 GH/s) | 12 to 13 h | 1.9 to 2 d | 2.4 to 2.6 d | 2.9 to 3.1 d |
| 100 TH/s | 3.3 h | 13.8 h | 23 h | 35 h |
| 1 PH/s | 1.5 h | 8 h | 17 h | 28 h |
| 10 PH/s | 30 min | 3.4 h | 10 h | 21 h |
| 100 PH/s | 3 min | 40 min | 4.2 h | 15 h |
| 1 EH/s | 24 s | 5 min | 50 min | 8.3 h (on schedule) |

How to read it:

- These are medians. Block 1 can come much earlier or later.
- Below 1 EH/s, the following blocks also need relief until ASERT has moved
  the target. Then blocks settle at 30 s.
- If hashrate starts after the genesis timestamp, relief has already run
  for that long. `python3 lib/first_blocks.py 25P --start-delay <s>` gives
  the times for your case.
- DESIGN-obenblock.md §4.2 says "at 1 PH/s, the first block comes after
  about 6 h". That is when the target reaches the 1 PH/s level. The median
  first block comes earlier.
- The node's built-in CPU miner (`--mine`) is meant for regtest. On
  mainnet it is a lottery of many hours (docs/OBENBLOCK-MINING.md §2).

## 8. What not to expect

- **No pool.** The built-in servers are solo: no shares are paid, no
  balances are kept, and there is no pool fee. A share below the block
  target only shows your hashrate. With small hashrate you may find no
  block for a long time.
- **Little reward in the first two days.** The slow start pays almost
  nothing for the first blocks (§6). It exists so that an early hashrate
  surge cannot take a large part of the supply.
- **No finality before height 3,600**, and no finality from your ASICs
  alone after it. Finality weight comes from witness shares (PoWit), not
  from blocks (docs/LAUNCH.md §5).
- **ASICs on Stratum V1 cannot mine witness shares.** A witness share's
  header puts a job commitment where a block header has its Merkle root.
  Stock V1 firmware rebuilds that field from a coinbase, so it cannot mine
  them. They need header-only mining: SV2 standard channels or a driver
  that takes an 80-byte header (docs/OBENBLOCK-MINING.md §4.2). The
  built-in V1 and V2 servers serve block jobs only, not witness-share jobs
  (docs/STRATUM.md). Witness shares are mined by nodes that run with
  `--witness-key`.
- **No merged mining** with Bitcoin (DESIGN-obenblock.md §1). Hashrate on
  ObenBlock is hashrate not on Bitcoin.
- **No price, no market, no guaranteed return.** Rented hashrate costs the
  rent whether or not it finds a block.
- **No hardware validation yet.** The protocol path is tested in software
  only (§1).

## 9. Before you rent or move hashrate

1. Check the genesis hash from several sources (docs/LAUNCH.md §4).
2. Connect **one** device. In the node log, check:
   - `stratum: session N authorized obb1q….rig1 -> pays obb1q…` with your
     address;
   - share results, and no stream of error 23 (low difficulty) or 20.
3. With `--metrics`, watch `gnb_stratum_shares_submitted_total{protocol,result}`
   and `gnb_stratum_blocks_found_total{protocol}` (docs/STRATUM.md §7).
4. A found block shows as `BLOCK FOUND h=…` in the log and is accepted by
   the node. Only then point more hashrate at the endpoint.
