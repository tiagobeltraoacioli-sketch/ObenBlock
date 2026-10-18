# ObenBlock mainnet monitor

A small, read-only monitor for the three ObenBlock mainnet hosts
(136.244.93.186, 209.250.236.240, 152.236.5.112). It runs from the
operator's Mac, logs in over SSH, runs a probe on each host, and prints one
block per host plus a cross-host check. Nothing is installed on the hosts
and nothing on them is changed.

| File | What it is |
| --- | --- |
| `obbmon.py` | Runs on the Mac. Ships the probe, summarizes each host, runs the cross-host checks, prints the report or JSON. Also has the `offline` and `local` modes. |
| `probe.py` | Runs on a host. Reads only, uses the standard library only, and prints one `OBB-PROBE {json}` line. |
| `pw-run.exp` | Expect wrapper for the host that only accepts a password (152). It reads the `senha:` line of the password file and never prints the password. |
| `prometheus/` | Optional scrape config and alert rules, used through SSH tunnels. |
| `systemd/` | Optional oneshot service and timer that write a JSON status file on a host. **No script installs them.** |
| `test_obbmon.py`, `testdata/` | Tests for the parsing and the checks. They run against captured sample RPC outputs. |

## Use

From the Mac, in this directory:

```
python3 -I obbmon.py status
```

```
python3 -I obbmon.py status --json
```

The defaults match `deploy/obenblock-launch/kit.conf.example`: user `ubuntu`,
key `~/.ssh/edgevana_fleet_g4` for 136 and 209, and a password login for 152
from the `senha:` line of `~/Desktop/gnb-servidor-teste-152.txt`. To override
them, use `--hosts`, `--pw-hosts`, `--user`, `--ssh-key` and `--pw-file`.
SSH runs with `BatchMode=yes`, so a key host that would prompt fails instead
of hanging. Host keys must already be in `~/.ssh/known_hosts`. The monitor
never adds them.

Exit status: 0 means OK, 1 means warnings, 2 means at least one critical
alert, and 3 means a usage error. That makes the command easy to wrap in a
loop or in `watch`:

```
watch -n 60 python3 -I obbmon.py status
```

Each run saves the tip of every host to `~/.cache/obenblock-monitor/state.json`.
The next run uses it to detect a stalled height. Use `--state FILE` to save
it somewhere else, or `--no-state` to turn it off. With
`--save-raw DIR`, the monitor keeps every host's probe JSON. The `offline`
mode can analyse those files again later:

```
python3 -I obbmon.py offline 136=DIR/136.244.93.186.json 209=DIR/209.250.236.240.json 152=DIR/152.236.5.112.json
```

You can tune the thresholds with `--stall-secs` (default 900, which is 30
block targets), `--split-depth` (2), `--lag-blocks` (6), `--min-peers` (2),
`--disk-warn-pct` / `--disk-crit-pct` (80/90), `--mem-warn-avail-pct` (10)
and `--absent-warn-frac` (0.20).

## What each host reports

| Area | Source |
| --- | --- |
| Node process: pid, uptime (etime), CPU, RSS, full arguments | `ps -eo pid,etimes,etime,pcpu,rss,comm,args`, filtered on command name `obenblock` |
| Units | `systemctl is-active` for obenblock-node, -stratum, -cpu-miner, -explorer-api |
| Chain identity, version, syncing, behind_by, warnings | `getnetworkinfo` |
| Tip height, hash, tip count, stopped / no-verdict / min-work warnings | `getdaginfo` |
| Tip age and average block time; the recent selected chain (height to hash) | `getselectedchain [0, 32]` |
| Genesis hash | `getblockhash [0]` |
| Peers (count and IPs) | `getpeers` |
| Mempool size and bytes | `getmempoolinfo` |
| PoWit epoch, justified/finalized, witness set, signer protection | `getpowitinfo` |
| PoCI: bootstrap `launch_height` (and blocks left), then config epoch / config_id / entries / total, finalized checkpoint and its certificate, absent weight of the latest epoch (fraction of total, over a third), bans, pruned keys | `getfinalityinfo.poci` (same object as `getpowitinfo.poci`) |
| Finality pin, origin, anchor status, counted checkpoints, conflict alert | `getfinalityinfo` |
| Bloch anchor: status, alert, slot, record id, last poll and error | `getfinalityinfo.bloch_anchor` (same as `getblochanchor`) |
| Network hashrate | `gethashrate` |
| Stratum sessions, shares and blocks | proxy `http://127.0.0.1:9333/metrics` (`obb_stratum_*`), and the node's built-in `gnb_stratum_*` series when `--metrics` is on (127.0.0.1:18310) |
| CPU miner hashrate | the newest `[miner] N MH/s, shares accepted A rejected R` line in `journalctl -u obenblock-cpu-miner`. The node's own `--mine` threads report no rate, so the report shows their thread count and the node's CPU instead |
| Memory, load, disk (`/` and `/var/lib/obenblock`) | `/proc/meminfo`, `/proc/loadavg`, `statvfs` |

All RPC calls are read methods on the node's loopback port 18210. On
loopback, read methods need no API key (`node/src/rpc/auth.rs`). If you set
`--rpc-key-file` on the probe, it sends `X-API-Key`.

## Alerts

These are raised per host:

- **CRIT**: UNREACHABLE, NODE_NOT_RUNNING, NODE_DUPLICATE, UNIT_NOT_ACTIVE, RPC_DOWN,
  NODE_STOPPED, STALLED (tip older than `--stall-secs`), NO_PEERS,
  FINALITY_CONFLICT, FINALITY_AGAINST_ANCHOR, FINALITY_ANCHOR_UNKNOWN,
  BLOCH_ANCHOR_CONFLICT, SIGNER_HALTED, POCI_ABSENT_OVER_THIRD, DISK_FULL.
- **WARN**: SYNCING, BEHIND, NODE_WARNING, NO_VERDICT_BLOCKS, BELOW_MIN_CHAIN_WORK,
  LOW_PEERS, POCI_ABSENT_HIGH, POCI_ABSENT_PAST, BLOCH_ANCHOR_ERROR,
  BLOCH_ANCHOR_STALE, STRATUM_BLOCKS_REJECTED, CPU_MINER_SILENT, TASK_PANICS,
  DEEP_REORGS, MEMORY_LOW, DISK_HIGH.

The cross-host checks compare every reachable host:

- **SPLIT_TIPS** (CRIT): two hosts have different selected-chain hashes at
  `--split-depth` blocks (default 2) below the lowest tip. Tips that differ
  only in the last 2 blocks are normal propagation and show as INFO
  TIPS_DIFFER.
- **SPLIT_UNCHECKED** (WARN): a host is so far ahead that its 32-block window
  does not reach that height. **HEIGHT_SPREAD** (WARN): the tips are more
  than `--lag-blocks` apart.
- **FINALITY_DIVERGENCE**, **PIN_DIVERGENCE**, **PIN_OFF_CHAIN** (CRIT): the
  same finalized slot holds different checkpoints, the pins differ at the
  same height, or one host's pin is not on another host's selected chain.
- **POCI_CONFIG_DIVERGENCE**, **POCI_PARAMS_MISMATCH** (CRIT): the same
  configuration epoch has different `config_id`s, or the PoCI parameter
  digests differ.
- **BLOCH_ANCHOR_DIVERGENCE** (CRIT): the same Bloch slot was read as
  different records. **BLOCH_ANCHOR_CONFLICT_MULTI** (CRIT): two or more
  hosts raise the Bloch alert.
- **GENESIS_MISMATCH**, **CHAIN_ID_MISMATCH** (CRIT).
- **STALLED_HEIGHT** (one host's tip has not changed since earlier runs) and
  **NETWORK_STALLED** (no host has passed the best height seen) (CRIT). Both
  use the state file.

The monitor only reports. Every remedy, such as `setfinalitycheckpoint`,
`ignorefinalized` or restarts, stays an operator decision
(`docs/OBB-ANCHOR.md`, `docs/RUNNING.md`).

## Prometheus (optional)

`prometheus/prometheus.yml` scrapes the node and the stratum proxy through
SSH tunnels from the Mac, and `prometheus/obenblock-alerts.yml` holds the
alert rules. Open the tunnels before starting Prometheus, one terminal per
host. Host 152 asks for its password at the prompt.

```
ssh -N -i ~/.ssh/edgevana_fleet_g4 -L 19310:127.0.0.1:18310 -L 19333:127.0.0.1:9333 ubuntu@136.244.93.186
```

```
ssh -N -i ~/.ssh/edgevana_fleet_g4 -L 29310:127.0.0.1:18310 -L 29333:127.0.0.1:9333 ubuntu@209.250.236.240
```

```
ssh -N -L 39310:127.0.0.1:18310 -L 39333:127.0.0.1:9333 ubuntu@152.236.5.112
```

```
prometheus --config.file=prometheus/prometheus.yml
```

The node serves metrics only when it runs with `--metrics`. Without it,
the `obenblock-node` job shows `up == 0` and only the stratum job has data.
Split and finality divergence need block hashes, which are not metrics, so
only `obbmon.py status` checks them.

## systemd timer (optional, not installed)

`systemd/obenblock-monitor.service` is a oneshot unit. It runs
`obbmon.py local` and writes that host's summary and alerts to
`/var/lib/obenblock-monitor/status.json`, as a `DynamicUser` that can write
only its state directory. The timer runs it every minute. To install it by
hand on a host, copy `obbmon.py` and `probe.py` to `/opt/obenblock-monitor/`
and the two units to `/etc/systemd/system/`, then enable the timer. No
script in this repository does that. The status file covers one host only,
so the cross-host checks stay with `obbmon.py status`.

## Tests

```
python3 -I deploy/obenblock-monitor/test_obbmon.py
```

`testdata/probe-healthy.json` is one host's probe document. Its RPC results
have the field names and shapes of the node's handlers (`node/src/rpc/mod.rs`
dispatch, `node/src/powit.rs` `info_json` / `finality_info_json` /
`poci_info_json`, `node/src/anchoring.rs` `status_json`,
`node/src/rpc/explorer.rs` `get_selected_chain`). Its values are synthetic:
hashes are patterned hex and the miner address is a `LAUNCH-PLACEHOLDER`.
The other files hold raw `ps`, Prometheus text (the proxy's
`render_prometheus` format and the node's), journal and `/proc/meminfo`
samples. The tests derive every scenario from these files: split, finality
conflict, Bloch conflict, PoCI absence and bootstrap, stall, resources. They
also run the shipped command through `/bin/sh` the way SSH would.
