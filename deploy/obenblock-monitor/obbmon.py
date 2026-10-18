#!/usr/bin/env python3
"""ObenBlock mainnet monitor: per-host status and cross-host checks.

    obbmon.py status  [--json] [--hosts H1,H2,...] [--state FILE | --no-state]
    obbmon.py offline HOST=probe.json ... [--json] [--now UNIX]
    obbmon.py local   [--out FILE] [probe options]

`status` (run from the Mac) ships probe.py to every host over SSH, runs it
there read-only, and prints one block per host plus the cross-host checks.
Key hosts log in with --ssh-key; password hosts (--pw-hosts) go through
pw-run.exp, which reads the 'senha:' line of --pw-file and never prints it.
`offline` analyses saved probe outputs (one `OBB-PROBE {json}` line or the
bare JSON per file). `local` runs the probe in this process and writes the
host's summary as JSON (the systemd timer, systemd/obenblock-monitor.*).

Exit status: 0 nothing to report, 1 warnings, 2 critical alerts, 3 usage.
Nothing here changes a host: the probe only reads (see probe.py).
"""
import argparse
import base64
import concurrent.futures
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# Defaults of deploy/obenblock-launch/kit.conf.example (the three hosts).
KEY_HOSTS = ("136.244.93.186", "209.250.236.240")
PW_HOSTS = ("152.236.5.112",)
SSH_USER = "ubuntu"
SSH_KEY = "~/.ssh/edgevana_fleet_g4"
PW_FILE = "~/Desktop/gnb-servidor-teste-152.txt"

TARGET_BLOCK_SECS = 30          # TARGET_BLOCK_TIME_SECS (crates/gnb-crypto)
DEFAULTS = {
    "stall_secs": 900,          # no new selected-chain block for 30 targets
    "split_depth": 2,           # selected tips may differ in the last 2 blocks
    "lag_blocks": 6,            # tip height spread that is worth a warning
    "min_peers": 2,
    "disk_warn_pct": 80.0, "disk_crit_pct": 90.0,
    "mem_warn_avail_pct": 10.0,
    "absent_warn_frac": 0.20,   # PoCI absent weight / total, latest epoch
}
CRIT, WARN, INFO = "CRIT", "WARN", "INFO"
LEVELS = {CRIT: 2, WARN: 1, INFO: 0}


# ── Loading probe.py by path (python3 -I drops the script dir) ───────────────

def load_probe():
    spec = importlib.util.spec_from_file_location("obb_probe", os.path.join(HERE, "probe.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def probe_source():
    with open(os.path.join(HERE, "probe.py"), "rb") as fh:
        return fh.read()


def parse_probe_output(text):
    """The probe's JSON from its stdout (an `OBB-PROBE {json}` line, CRs from
    an expect pty allowed), or the bare JSON of a saved file. None if absent."""
    for line in text.replace("\r", "").splitlines():
        i = line.find("OBB-PROBE ")
        if i >= 0:
            try:
                return json.loads(line[i + len("OBB-PROBE "):])
            except ValueError:
                return None
    try:
        doc = json.loads(text)
        return doc if isinstance(doc, dict) and "probe_version" in doc else None
    except ValueError:
        return None


# ── Small helpers ────────────────────────────────────────────────────────────

def ok(v):
    """A JSON-RPC result that is not an error object."""
    return v is not None and not (isinstance(v, dict) and set(v) == {"error"})


def err_of(v):
    return v.get("error") if isinstance(v, dict) and "error" in v else None


def g(d, *path, default=None):
    for k in path:
        if isinstance(d, dict) and k in d:
            d = d[k]
        elif isinstance(d, list) and isinstance(k, int) and -len(d) <= k < len(d):
            d = d[k]
        else:
            return default
    return d if d is not None else default


def short(h, n=16):
    return h[:n] if isinstance(h, str) else h


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def human_bytes(n):
    if n is None:
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0


def human_secs(s):
    if s is None:
        return "?"
    s = int(s)
    if s < 120:
        return f"{s}s"
    if s < 7200:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


# ── Per-host summary ─────────────────────────────────────────────────────────

def summarize(label, p, cfg=None, now=None):
    """One host's summary and alerts from its probe document `p` (or None
    when the probe could not run, with `p` = {"transport_error": ...})."""
    cfg = {**DEFAULTS, **(cfg or {})}
    alerts = []

    def alert(level, code, msg):
        alerts.append({"level": level, "code": code, "host": label, "msg": msg})

    s = {"host": label, "alerts": alerts}
    if not p or "transport_error" in (p or {}):
        alert(CRIT, "UNREACHABLE", (p or {}).get("transport_error", "probe produced no output"))
        s["reachable"] = False
        return s
    now = now if now is not None else p.get("time") or int(time.time())
    s.update(reachable=True, hostname=p.get("host"), probe_time=p.get("time"))
    r = p.get("rpc") or {}

    # Node process and units.
    procs = p.get("processes")
    s["processes"] = procs
    if procs is not None and not procs:
        alert(CRIT, "NODE_NOT_RUNNING", f"no '{p.get('proc_name')}' process")
    elif procs and len(procs) > 1:
        alert(CRIT, "NODE_DUPLICATE", f"{len(procs)} '{p.get('proc_name')}' processes: "
              + ", ".join(str(x["pid"]) for x in procs))
    units = p.get("units") or {}
    s["units"] = units
    if units.get("obenblock-node") not in (None, "active", "unknown"):
        # A node started by hand (no unit) still runs: a warning then.
        alert(WARN if procs else CRIT, "UNIT_NOT_ACTIVE", f"obenblock-node is {units.get('obenblock-node')}")
    for u in ("obenblock-stratum", "obenblock-cpu-miner"):
        if units.get(u) in ("failed", "activating"):
            alert(WARN, "UNIT_NOT_ACTIVE", f"{u} is {units[u]}")

    # RPC reachability.
    ni = r.get("getnetworkinfo")
    s["rpc_ok"] = ok(ni)
    if not ok(ni):
        alert(CRIT, "RPC_DOWN", f"getnetworkinfo: {err_of(ni) or 'no answer'}")
    else:
        s["network"] = {k: ni.get(k) for k in ("network", "chain", "chain_id", "version", "protocol",
                                               "peers", "mempool", "syncing", "best_announced",
                                               "behind_by", "pruned_height", "warnings")}
        if ni.get("syncing"):
            alert(WARN, "SYNCING", f"syncing, behind_by={ni.get('behind_by')}")
        elif (ni.get("behind_by") or 0) > cfg["split_depth"]:
            alert(WARN, "BEHIND", f"behind_by={ni.get('behind_by')} blue score (peers announce more)")
        for w in ni.get("warnings") or []:
            alert(WARN, "NODE_WARNING", str(w)[:300])
    s["genesis"] = r.get("genesis") if isinstance(r.get("genesis"), str) else None

    # Tip.
    dag = r.get("getdaginfo")
    if ok(dag):
        s["tip"] = {"hash": dag.get("tip"), "height": dag.get("tip_height"), "blue_score": dag.get("tip_blue_score"),
                    "tip_count": dag.get("tip_count"), "block_count": dag.get("block_count"),
                    "below_minimum_chain_work": dag.get("below_minimum_chain_work")}
        if dag.get("stopped"):
            alert(CRIT, "NODE_STOPPED", f"storage stopped: {dag['stopped']}")
        if dag.get("no_verdict"):
            alert(WARN, "NO_VERDICT_BLOCKS", f"{len(dag['no_verdict'])} block(s) without a verdict")
        if dag.get("below_minimum_chain_work"):
            alert(WARN, "BELOW_MIN_CHAIN_WORK", "tip below minimum chain work (initial block download)")
        for w in dag.get("warnings") or []:
            if not ok(ni) or w not in (ni.get("warnings") or []):
                alert(WARN, "NODE_WARNING", str(w)[:300])
    chain = g(r, "getselectedchain", "blocks", default=None)
    if isinstance(chain, list):
        s["chain"] = {str(b["height"]): b["hash"] for b in chain if b.get("height") is not None and b.get("hash")}
        ts = [b.get("timestamp") for b in chain[:1] if b.get("timestamp") is not None]
        if ts:
            s.setdefault("tip", {})["timestamp"] = ts[0]
            s["tip"]["age_secs"] = max(0, now - int(ts[0]))
            if s["tip"]["age_secs"] > cfg["stall_secs"]:
                alert(CRIT, "STALLED", f"last selected-chain block is {human_secs(s['tip']['age_secs'])} old "
                      f"(threshold {human_secs(cfg['stall_secs'])})")
        if len(chain) >= 2:
            span = (chain[0].get("timestamp") or 0) - (chain[-1].get("timestamp") or 0)
            n = (chain[0].get("height") or 0) - (chain[-1].get("height") or 0)
            if n > 0 and span >= 0:
                s.setdefault("tip", {})["avg_block_secs"] = round(span / n, 1)

    # Peers and mempool.
    peers = r.get("getpeers")
    if ok(peers):
        s["peers"] = {"count": peers.get("peer_count"),
                      "ips": sorted({x.get("ip") or x.get("address") for x in peers.get("peers") or []})}
    elif ok(ni):
        s["peers"] = {"count": ni.get("peers"), "ips": []}
    pc = g(s, "peers", "count")
    if pc is not None:
        if pc == 0:
            alert(CRIT, "NO_PEERS", "0 peers")
        elif pc < cfg["min_peers"]:
            alert(WARN, "LOW_PEERS", f"{pc} peer(s)")
    mp = r.get("getmempoolinfo")
    if ok(mp):
        s["mempool"] = {"size": mp.get("size"), "bytes": mp.get("bytes"),
                        "min_fee_rate": mp.get("rolling_min_fee_rate_sat_per_byte")}

    # PoWit / PoCI.
    pw = r.get("getpowitinfo")
    fi = r.get("getfinalityinfo")
    if ok(pw):
        s["powit"] = {
            "active": pw.get("active"), "activation_height": pw.get("activation_height"),
            "epoch": pw.get("epoch"), "rules": pw.get("rules"),
            "justified": pw.get("justified"), "finalized": pw.get("finalized"),
            "witness_set_size": g(pw, "witness_set", "size"),
            "witness_total_weight": g(pw, "witness_set", "total_weight"),
            "signer_halted": pw.get("signer_halted"),
            "signers": [{"key": short(x.get("key")), "halted": x.get("halted"), "alert": x.get("alert")}
                        for x in pw.get("signers") or []],
            "pool": pw.get("pool"),
        }
        if pw.get("signer_halted"):
            why = "; ".join(str(x.get("alert")) for x in pw.get("signers") or [] if x.get("halted"))
            alert(CRIT, "SIGNER_HALTED", f"witness signer halted: {why or 'see getpowitinfo.signers'}")
        if pw.get("finality_conflict"):
            alert(CRIT, "FINALITY_CONFLICT", "getpowitinfo.finality_conflict is true")
    poci = (fi.get("poci") if ok(fi) else None) or (pw.get("poci") if ok(pw) else None)
    if isinstance(poci, dict):
        ps = {"active": poci.get("active")}
        if not poci.get("active"):
            ps.update(launch_height=poci.get("launch_height"), bootstrap_epochs=poci.get("bootstrap_epochs"))
            th = g(s, "tip", "height")
            ps["blocks_to_launch"] = (poci["launch_height"] - th) if isinstance(poci.get("launch_height"), int) \
                and isinstance(th, int) else None
        else:
            total = to_int(poci.get("total"))
            absent = poci.get("absent_weight") or []
            last = absent[-1] if absent else None
            ps.update(config_epoch=poci.get("config_epoch"), config_id=poci.get("config_id"),
                      entries=poci.get("entries"), total=poci.get("total"),
                      previous_config_id=poci.get("previous_config_id"),
                      finalized=poci.get("finalized"),
                      certificate=g(poci, "finalized_certificate", "available"),
                      bans=len(poci.get("bans") or []), pruned=len(poci.get("pruned") or []),
                      params_digest=poci.get("params_digest"))
            if last:
                w = to_int(last.get("weight"))
                ps["absent"] = {"epoch": last.get("epoch"), "weight": last.get("weight"), "keys": last.get("keys"),
                                "over_a_third": last.get("over_a_third"),
                                "frac": round(w / total, 4) if w is not None and total else None}
                if last.get("over_a_third"):
                    alert(CRIT, "POCI_ABSENT_OVER_THIRD",
                          f"epoch {last.get('epoch')}: absent weight {last.get('weight')} of {total} "
                          f"({last.get('keys')} keys) is over a third: finality cannot advance")
                elif ps["absent"]["frac"] is not None and ps["absent"]["frac"] > cfg["absent_warn_frac"]:
                    alert(WARN, "POCI_ABSENT_HIGH", f"epoch {last.get('epoch')}: absent fraction "
                          f"{ps['absent']['frac']:.1%} ({last.get('keys')} keys)")
            older = [a for a in absent[:-1] if a.get("over_a_third")]
            if older:
                alert(WARN, "POCI_ABSENT_PAST", "over a third absent in epoch(s) "
                      + ",".join(str(a.get("epoch")) for a in older))
        s["poci"] = ps
    if ok(fi):
        bl = fi.get("bloch_anchor") or {}
        s["finality"] = {
            "pin": fi.get("pin"), "origin": fi.get("origin"), "own_finality": fi.get("own_finality"),
            "anchor": fi.get("anchor"), "anchor_source": fi.get("anchor_source"),
            "anchor_status": fi.get("anchor_status"), "anchor_overdue": fi.get("anchor_overdue"),
            "finalized_count": fi.get("finalized_count"),
            "finalized": {str(x.get("slot")): x.get("hash") for x in fi.get("finalized") or []
                          if x.get("slot") is not None},
            "conflict": fi.get("conflict"), "conflicting_finalized": fi.get("conflicting_finalized"),
            "conflict_resolution": fi.get("conflict_resolution"), "against_anchor": fi.get("against_anchor"),
            "ignored": len(fi.get("ignored") or []),
        }
        if fi.get("conflict") or (fi.get("conflicting_finalized") or 0) > 0:
            c = fi.get("conflict") or []
            alert(CRIT, "FINALITY_CONFLICT",
                  f"{fi.get('conflicting_finalized')} finalized checkpoint(s) conflict with the pin "
                  f"(resolution {fi.get('conflict_resolution')}): "
                  + " vs ".join(f"{short(x.get('hash'))}@{x.get('block_height')}" for x in c if isinstance(x, dict)))
        if fi.get("against_anchor"):
            alert(CRIT, "FINALITY_AGAINST_ANCHOR", "finalized checkpoint(s) against the release/operator anchor")
        if fi.get("anchor_overdue") or fi.get("anchor_status") in ("unknown", "invalid", "heightmismatch"):
            alert(CRIT, "FINALITY_ANCHOR_UNKNOWN",
                  f"finality anchor {fi.get('anchor_status')} (overdue={fi.get('anchor_overdue')}, pin {fi.get('origin')})")
        s["bloch"] = {
            "enabled": bl.get("enabled"), "status": bl.get("status"), "alert": bl.get("alert"),
            "detail": bl.get("detail"), "registry_alarm": bl.get("registry_alarm"),
            "slot": g(bl, "anchor", "slot"), "record_id": g(bl, "anchor", "record_id"),
            "block_id": g(bl, "anchor", "block_id"), "corroborated_slot": bl.get("corroborated_slot"),
            "last_poll": bl.get("last_poll"), "last_error": bl.get("last_error"),
        }
        if bl.get("alert"):
            alert(CRIT, "BLOCH_ANCHOR_CONFLICT", f"Bloch anchor {bl.get('status')}: "
                  f"{bl.get('detail') or bl.get('registry_alarm') or 'see getblochanchor'}")
        elif bl.get("enabled") and bl.get("last_error"):
            alert(WARN, "BLOCH_ANCHOR_ERROR", f"Bloch registry poll failed: {str(bl['last_error'])[:200]}")
        elif bl.get("enabled") and bl.get("last_poll") and now - int(bl["last_poll"]) > 3 * 3600:
            alert(WARN, "BLOCH_ANCHOR_STALE", f"last Bloch poll {human_secs(now - int(bl['last_poll']))} ago")

    # Hashrate, stratum, CPU miner.
    hr = r.get("gethashrate")
    if ok(hr):
        s["network_hashrate"] = {"hs": hr.get("hashrate_hs"), "human": hr.get("hashrate_human"),
                                 "avg_block_secs": hr.get("avg_block_time_secs"),
                                 "difficulty": hr.get("current_difficulty")}
    sm = g(p, "metrics", "stratum")
    nm = g(p, "metrics", "node")
    st = {}
    if isinstance(sm, dict) and sm:
        st["proxy"] = {k[len("obb_stratum_"):]: v for k, v in sm.items() if k.startswith("obb_stratum_")}
        if st["proxy"].get("blocks_rejected_total"):
            alert(WARN, "STRATUM_BLOCKS_REJECTED",
                  f"stratum proxy: {int(st['proxy']['blocks_rejected_total'])} submitted block(s) refused by the node")
        if st["proxy"].get("rpc_failures_total"):
            alert(INFO, "STRATUM_RPC_FAILURES", f"stratum proxy: {int(st['proxy']['rpc_failures_total'])} node RPC failure(s)")
    if isinstance(nm, dict) and nm:
        builtin = {k[len("gnb_stratum_"):]: v for k, v in nm.items() if k.startswith("gnb_stratum_")}
        if builtin:
            st["builtin"] = builtin
        s["node_metrics"] = {k: nm.get(k) for k in ("gnb_finality_conflicts", "gnb_finality_anchor_unknown",
                                                    "gnb_powit_signer_halted", "gnb_bloch_anchor_conflict",
                                                    "gnb_deep_reorgs_total", "gnb_fork_depth",
                                                    "gnb_block_rejected_total", "gnb_task_panics_total") if k in nm}
        if nm.get("gnb_task_panics_total"):
            alert(WARN, "TASK_PANICS", f"{int(nm['gnb_task_panics_total'])} task panic(s) since start")
        if nm.get("gnb_deep_reorgs_total"):
            alert(WARN, "DEEP_REORGS", f"{int(nm['gnb_deep_reorgs_total'])} deep reorg(s) since start")
    s["stratum"] = st or None
    proc = (procs or [None])[0] if procs else None
    cm = p.get("cpu_miner")
    s["cpu_mining"] = {
        "node_miner": ("--mine" in (proc or {}).get("args", "").split()) if proc else None,
        "node_mine_threads": _flag((proc or {}).get("args", ""), "--mine-threads"),
        "node_pcpu": (proc or {}).get("pcpu"),
        "cpu_miner_mhs": (cm or {}).get("mhs"),
        "cpu_miner_kind": (cm or {}).get("kind"),
        "cpu_miner_accepted": (cm or {}).get("accepted"),
        "cpu_miner_rejected": (cm or {}).get("rejected"),
        "cpu_miner_age_secs": (now - int(cm["at"])) if cm and cm.get("at") else None,
    }
    if units.get("obenblock-cpu-miner") == "active" and cm and cm.get("at") and now - int(cm["at"]) > 300:
        alert(WARN, "CPU_MINER_SILENT", f"CPU miner last reported {human_secs(now - int(cm['at']))} ago")

    # System.
    sysd = p.get("system") or {}
    mem = sysd.get("mem") or {}
    s["system"] = {"nproc": sysd.get("nproc"), "load": sysd.get("load"), "mem": mem, "disk": []}
    if mem.get("MemTotal"):
        avail_pct = 100.0 * mem.get("MemAvailable", 0) / mem["MemTotal"]
        s["system"]["mem_avail_pct"] = round(avail_pct, 1)
        if avail_pct < cfg["mem_warn_avail_pct"]:
            alert(WARN, "MEMORY_LOW", f"{avail_pct:.1f}% memory available")
    for d in sysd.get("disk") or []:
        if not d.get("total"):
            continue
        used = 100.0 * (d["total"] - d["free"]) / d["total"]
        s["system"]["disk"].append({"path": d["path"], "used_pct": round(used, 1), "free": d["free"], "total": d["total"]})
        if used >= cfg["disk_crit_pct"]:
            alert(CRIT, "DISK_FULL", f"{d['path']} {used:.1f}% used")
        elif used >= cfg["disk_warn_pct"]:
            alert(WARN, "DISK_HIGH", f"{d['path']} {used:.1f}% used")
    return s


def _flag(args, name):
    parts = (args or "").split()
    return parts[parts.index(name) + 1] if name in parts and parts.index(name) + 1 < len(parts) else None


# ── Cross-host checks ────────────────────────────────────────────────────────

def cross_check(sums, cfg=None, state=None, now=None):
    """Alerts that compare the hosts: split selected tips, diverging finality,
    PoCI configuration, Bloch anchors, genesis/chain id; and stalled heights
    against the previous run's `state` (updated in place when given)."""
    cfg = {**DEFAULTS, **(cfg or {})}
    now = now if now is not None else int(time.time())
    alerts = []

    def alert(level, code, msg):
        alerts.append({"level": level, "code": code, "host": "*", "msg": msg})

    live = [s for s in sums if s.get("reachable") and g(s, "tip", "height") is not None]

    # Identity.
    for field, code in (("genesis", "GENESIS_MISMATCH"),):
        vals = {s["host"]: s.get(field) for s in live if s.get(field)}
        if len(set(vals.values())) > 1:
            alert(CRIT, code, "hosts disagree on the genesis: "
                  + ", ".join(f"{h}={short(v)}" for h, v in sorted(vals.items())))
    ids = {s["host"]: g(s, "network", "chain_id") for s in live if g(s, "network", "chain_id")}
    if len(set(ids.values())) > 1:
        alert(CRIT, "CHAIN_ID_MISMATCH", ", ".join(f"{h}={v}" for h, v in sorted(ids.items())))

    # Split tips: every host's selected chain must agree `split_depth` blocks
    # below the lowest tip (tips may differ above while blocks propagate).
    if len(live) >= 2:
        heights = {s["host"]: s["tip"]["height"] for s in live}
        lo, hi = min(heights.values()), max(heights.values())
        ref = lo - cfg["split_depth"]
        if hi - lo > cfg["lag_blocks"]:
            alert(WARN, "HEIGHT_SPREAD", f"tip heights {lo}..{hi}: "
                  + ", ".join(f"{h}={v}" for h, v in sorted(heights.items())))
        if ref >= 0:
            at = {}
            missing = []
            for s in live:
                hsh = (s.get("chain") or {}).get(str(ref))
                if hsh:
                    at.setdefault(hsh, []).append(s["host"])
                else:
                    missing.append(s["host"])
            if len(at) > 1:
                alert(CRIT, "SPLIT_TIPS", f"selected chains differ at height {ref} "
                      f"({cfg['split_depth']} below the lowest tip {lo}): "
                      + "; ".join(f"{short(h)}: {','.join(sorted(hs))}" for h, hs in sorted(at.items())))
            if missing and at:
                alert(WARN, "SPLIT_UNCHECKED", f"no block hash at height {ref} from {','.join(sorted(missing))} "
                      "(tip too far ahead of the chain window, or getselectedchain failed)")
        tips = {s["host"]: s["tip"].get("hash") for s in live}
        if len(set(tips.values())) > 1 and not any(a["code"] == "SPLIT_TIPS" for a in alerts):
            alerts.append({"level": INFO, "code": "TIPS_DIFFER", "host": "*",
                           "msg": "selected tips differ within the last blocks: "
                                  + ", ".join(f"{h}={short(v, 12)}@{heights[h]}" for h, v in sorted(tips.items()))})

    # Finality: the same slot must carry the same checkpoint everywhere.
    by_slot = {}
    for s in sums:
        fin = dict(g(s, "finality", "finalized", default={}) or {})
        pf = g(s, "poci", "finalized")
        if isinstance(pf, dict) and pf.get("slot") is not None and pf.get("hash"):
            fin.setdefault(str(pf["slot"]), pf["hash"])
        for slot, h in fin.items():
            by_slot.setdefault(slot, {}).setdefault(h, set()).add(s["host"])
    for slot, hs in sorted(by_slot.items(), key=lambda kv: to_int(kv[0]) or 0):
        if len(hs) > 1:
            alert(CRIT, "FINALITY_DIVERGENCE", f"slot {slot} finalized differently: "
                  + "; ".join(f"{short(h)}: {','.join(sorted(v))}" for h, v in sorted(hs.items())))
    pins = {}
    for s in sums:
        pin = g(s, "finality", "pin")
        if isinstance(pin, dict) and pin.get("hash"):
            pins.setdefault(pin.get("block_height"), {}).setdefault(pin["hash"], set()).add(s["host"])
    for height, hs in pins.items():
        if len(hs) > 1:
            alert(CRIT, "PIN_DIVERGENCE", f"finality pins differ at block height {height}: "
                  + "; ".join(f"{short(h)}: {','.join(sorted(v))}" for h, v in sorted(hs.items())))
    # A host's pin must be on every other host's selected chain where visible.
    for s in sums:
        pin = g(s, "finality", "pin")
        if not (isinstance(pin, dict) and pin.get("hash") and pin.get("block_height") is not None):
            continue
        for o in live:
            if o["host"] == s["host"]:
                continue
            other = (o.get("chain") or {}).get(str(pin["block_height"]))
            if other and other != pin["hash"]:
                alert(CRIT, "PIN_OFF_CHAIN", f"{s['host']} pins {short(pin['hash'])}@{pin['block_height']}, "
                      f"{o['host']}'s selected chain has {short(other)} there")

    # PoCI configuration: one configuration per epoch.
    cfgs = {}
    for s in sums:
        ce, cid = g(s, "poci", "config_epoch"), g(s, "poci", "config_id")
        if ce is not None and cid:
            cfgs.setdefault(ce, {}).setdefault(cid, set()).add(s["host"])
    for ce, ids_ in cfgs.items():
        if len(ids_) > 1:
            alert(CRIT, "POCI_CONFIG_DIVERGENCE", f"configuration epoch {ce} differs: "
                  + "; ".join(f"{short(i)}: {','.join(sorted(v))}" for i, v in sorted(ids_.items())))
    digests = {s["host"]: g(s, "poci", "params_digest") for s in sums if g(s, "poci", "params_digest")}
    if len(set(digests.values())) > 1:
        alert(CRIT, "POCI_PARAMS_MISMATCH", ", ".join(f"{h}={short(v)}" for h, v in sorted(digests.items())))

    # Bloch anchors: one record per slot.
    anchors = {}
    for s in sums:
        slot, rid = g(s, "bloch", "slot"), g(s, "bloch", "record_id")
        if slot is not None and rid:
            anchors.setdefault(slot, {}).setdefault(rid, set()).add(s["host"])
    for slot, rids in anchors.items():
        if len(rids) > 1:
            alert(CRIT, "BLOCH_ANCHOR_DIVERGENCE", f"Bloch anchor slot {slot} read differently: "
                  + "; ".join(f"{short(i)}: {','.join(sorted(v))}" for i, v in sorted(rids.items())))
    flagged = sorted(s["host"] for s in sums if g(s, "bloch", "alert"))
    if len(flagged) >= 2:
        alert(CRIT, "BLOCH_ANCHOR_CONFLICT_MULTI", f"Bloch anchor alert on {','.join(flagged)}")

    # Stalled height against the previous run.
    if state is not None:
        hosts = state.setdefault("hosts", {})
        for s in live:
            h, height, tip = s["host"], s["tip"]["height"], s["tip"].get("hash")
            prev = hosts.get(h)
            if prev and prev.get("height") == height and prev.get("hash") == tip:
                since = prev.get("since", now)
            else:
                since = now
            hosts[h] = {"height": height, "hash": tip, "since": since, "seen": now}
            if now - since > cfg["stall_secs"]:
                alert(CRIT, "STALLED_HEIGHT", f"{h}: tip {height} unchanged for {human_secs(now - since)} "
                      "(previous runs)")
        best = max((s["tip"]["height"] for s in live), default=None)
        prev_best = state.get("best")
        if best is not None:
            if prev_best and prev_best.get("height") is not None and best <= prev_best["height"]:
                state["best"] = {"height": prev_best["height"], "since": prev_best.get("since", now)}
                if now - state["best"]["since"] > cfg["stall_secs"]:
                    alert(CRIT, "NETWORK_STALLED", f"no host passed height {prev_best['height']} for "
                          f"{human_secs(now - state['best']['since'])}")
            else:
                state["best"] = {"height": best, "since": now}
    return alerts


def worst(alerts):
    return max((LEVELS[a["level"]] for a in alerts), default=0)


# ── Text report ──────────────────────────────────────────────────────────────

def render(sums, cross, now=None):
    now = now or int(time.time())
    out = [f"ObenBlock monitor  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}"]
    for s in sums:
        out.append("")
        out.append(f"== {s['host']}" + (f" ({s['hostname']})" if s.get("hostname") else ""))
        if not s.get("reachable"):
            out += [f"   {a['level']} {a['code']}: {a['msg']}" for a in s["alerts"]]
            continue
        for pr in s.get("processes") or []:
            out.append(f"   node     pid {pr['pid']}  up {pr['etime']}  cpu {pr['pcpu']}%  rss "
                       f"{human_bytes(pr['rss_kb'] * 1024)}")
            out.append(f"            {pr['args'][:400]}")
        if s.get("processes") == []:
            out.append("   node     NOT RUNNING")
        n, t = s.get("network") or {}, s.get("tip") or {}
        out.append(f"   chain    {n.get('chain')}/{n.get('network')} {n.get('chain_id')}  v{n.get('version')}  "
                   f"genesis {short(s.get('genesis'))}")
        out.append(f"   tip      height {t.get('height')}  {short(t.get('hash'))}  age {human_secs(t.get('age_secs'))}  "
                   f"tips {t.get('tip_count')}  avg {t.get('avg_block_secs')}s  syncing {n.get('syncing')}  "
                   f"behind {n.get('behind_by')}")
        pe, mp = s.get("peers") or {}, s.get("mempool") or {}
        out.append(f"   peers    {pe.get('count')}  {' '.join(x for x in pe.get('ips') or [] if x)}")
        out.append(f"   mempool  {mp.get('size')} tx  {human_bytes(mp.get('bytes'))}")
        pw, po, fi = s.get("powit") or {}, s.get("poci") or {}, s.get("finality") or {}
        out.append(f"   powit    epoch {pw.get('epoch')}  justified {_cp(pw.get('justified'))}  "
                   f"finalized {_cp(pw.get('finalized'))}  witnesses {pw.get('witness_set_size')}  "
                   f"signer_halted {pw.get('signer_halted')}")
        if po.get("active"):
            ab = po.get("absent") or {}
            out.append(f"   poci     config epoch {po.get('config_epoch')} id {short(po.get('config_id'))}  "
                       f"entries {po.get('entries')}  finalized {_cp(po.get('finalized'))}  cert {po.get('certificate')}")
            out.append(f"            absent epoch {ab.get('epoch')}: weight {ab.get('weight')} keys {ab.get('keys')} "
                       f"frac {ab.get('frac')}  bans {po.get('bans')}  pruned {po.get('pruned')}")
        elif po:
            out.append(f"   poci     bootstrap: launch_height {po.get('launch_height')}  "
                       f"blocks_to_launch {po.get('blocks_to_launch')}  bootstrap_epochs {po.get('bootstrap_epochs')}")
        if fi:
            pin = fi.get("pin") or {}
            out.append(f"   finality pin {short(pin.get('hash'))}@{pin.get('block_height')} origin {fi.get('origin')}  "
                       f"anchor {fi.get('anchor_source')}/{fi.get('anchor_status')}  counted {fi.get('finalized_count')}  "
                       f"conflicts {fi.get('conflicting_finalized')}")
        bl = s.get("bloch") or {}
        if bl:
            out.append(f"   bloch    enabled {bl.get('enabled')}  status {bl.get('status')}  slot {bl.get('slot')}  "
                       f"corroborated {bl.get('corroborated_slot')}  alert {bl.get('alert')}")
        st = s.get("stratum") or {}
        for kind, m in st.items():
            if kind == "proxy":
                out.append(f"   stratum  proxy: workers {_i(m.get('workers_active'))} (auth {_i(m.get('workers_authorized'))})  "
                           f"shares ok {_i(m.get('shares_accepted_total'))} rej {_i(m.get('shares_rejected_total'))} "
                           f"stale {_i(m.get('shares_stale_total'))}  blocks found {_i(m.get('blocks_found_total'))} "
                           f"acc {_i(m.get('blocks_accepted_total'))} rej {_i(m.get('blocks_rejected_total'))}  "
                           f"job height {_i(m.get('template_height'))}")
            else:
                out.append(f"   stratum  built-in: sessions {_i(m.get('sessions_active'))} (total {_i(m.get('sessions_total'))})  "
                           f"shares {_i(m.get('shares_submitted_total'))}  blocks {_i(m.get('blocks_found_total'))}")
        if not st:
            out.append("   stratum  no metrics endpoint answered")
        cm, nh = s.get("cpu_mining") or {}, s.get("network_hashrate") or {}
        rate = f"{cm['cpu_miner_mhs']} MH/s ({cm.get('cpu_miner_kind')}, {human_secs(cm.get('cpu_miner_age_secs'))} ago)" \
            if cm.get("cpu_miner_mhs") is not None else "n/a"
        out.append(f"   mining   node --mine {cm.get('node_miner')} threads {cm.get('node_mine_threads')}  "
                   f"cpu-miner {rate}  network {nh.get('human')}")
        sy = s.get("system") or {}
        mem = sy.get("mem") or {}
        disks = "  ".join(f"{d['path']} {d['used_pct']}% ({human_bytes(d['free'])} free)" for d in sy.get("disk") or [])
        out.append(f"   system   load {sy.get('load')}  cpus {sy.get('nproc')}  mem avail "
                   f"{human_bytes(mem.get('MemAvailable'))}/{human_bytes(mem.get('MemTotal'))} ({sy.get('mem_avail_pct')}%)  "
                   f"{disks}")
        for a in s["alerts"]:
            out.append(f"   {a['level']} {a['code']}: {a['msg']}")
    out.append("")
    out.append("== cross-host")
    if not cross:
        out.append("   OK: selected chains, finality, PoCI configuration and Bloch anchors agree")
    out += [f"   {a['level']} {a['code']}: {a['msg']}" for a in cross]
    allr = [a for s in sums for a in s["alerts"]] + cross
    n_c = sum(a["level"] == CRIT for a in allr)
    n_w = sum(a["level"] == WARN for a in allr)
    out.append("")
    out.append(f"RESULT {'CRIT' if n_c else 'WARN' if n_w else 'OK'}: {n_c} critical, {n_w} warning(s)")
    return "\n".join(out)


def _cp(c):
    if not isinstance(c, dict):
        return "-"
    return f"{c.get('slot')}:{short(c.get('hash'), 12)}"


def _i(v):
    return "-" if v is None else str(int(v))


# ── Transport ────────────────────────────────────────────────────────────────

def remote_command(probe_args):
    """The remote shell command that runs probe.py from the command line
    itself (compressed, base64: only [A-Za-z0-9+/=] inside single quotes)."""
    blob = base64.b64encode(zlib.compress(probe_source(), 9)).decode()
    for a in probe_args:
        if not all(c.isalnum() or c in "-_.:/=" for c in a):
            raise SystemExit(f"obbmon: unsafe probe argument {a!r}")
    code = f"import base64,zlib;exec(compile(zlib.decompress(base64.b64decode('{blob}')),'probe.py','exec'))"
    return f"python3 -I -c \"{code}\" " + " ".join(probe_args)


def run_host(host, a, probe_args):
    cmd = remote_command(probe_args)
    target = f"{a.user}@{host}"
    if host in a.pw_hosts:
        pwfile = os.path.expanduser(a.pw_file)
        if not os.path.isfile(pwfile):
            return {"transport_error": f"password file {a.pw_file} not found"}
        argv = ["expect", "-f", os.path.join(HERE, "pw-run.exp"), target, pwfile, cmd]
    else:
        argv = ["ssh", "-i", os.path.expanduser(a.ssh_key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                "-o", "ServerAliveInterval=15", "-o", "IdentitiesOnly=yes", target, cmd]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=a.timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"transport_error": f"timed out after {a.timeout}s"}
    except OSError as e:
        return {"transport_error": f"{argv[0]}: {e}"}
    doc = parse_probe_output(p.stdout)
    if doc is None:
        tail = (p.stderr or p.stdout or "").replace("\r", "").strip().splitlines()[-3:]
        return {"transport_error": f"exit {p.returncode}: " + " | ".join(tail)[:300]}
    return doc


def load_state(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def write_json_atomic(path, doc):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".obbmon-")
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh, sort_keys=True, indent=1)
        fh.write("\n")
    os.replace(tmp, path)


def report(sums, cross, a, now):
    level = max([worst(cross)] + [worst(s["alerts"]) for s in sums])
    if a.json:
        print(json.dumps({"time": now, "hosts": sums, "cross": cross, "result": ["OK", "WARN", "CRIT"][level]},
                         sort_keys=True, indent=1))
    else:
        print(render(sums, cross, now))
    return level


def thresholds(a):
    return {k: getattr(a, k) for k in DEFAULTS if getattr(a, k, None) is not None}


def cmd_status(a):
    hosts = [h for h in a.hosts.split(",") if h] if a.hosts else list(KEY_HOSTS) + list(PW_HOSTS)
    a.pw_hosts = set(h for h in a.pw_hosts.split(",") if h)
    probe_args = ["--rpc-port", str(a.rpc_port), "--proc-name", a.proc_name]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts)) as ex:
        docs = list(ex.map(lambda h: run_host(h, a, probe_args), hosts))
    now = int(time.time())
    cfg = thresholds(a)
    sums = [summarize(h, d, cfg, now) for h, d in zip(hosts, docs)]
    state = None if a.no_state else load_state(os.path.expanduser(a.state))
    cross = cross_check(sums, cfg, state, now)
    if state is not None:
        write_json_atomic(os.path.expanduser(a.state), state)
    if a.save_raw:
        os.makedirs(a.save_raw, exist_ok=True)
        for h, d in zip(hosts, docs):
            write_json_atomic(os.path.join(a.save_raw, f"{h}.json"), d)
    return report(sums, cross, a, now)


def cmd_offline(a):
    hosts, docs = [], []
    for spec in a.files:
        host, _, path = spec.partition("=")
        if not path:
            print("obbmon offline: give HOST=FILE", file=sys.stderr)
            return 3
        with open(path) as fh:
            doc = parse_probe_output(fh.read())
        hosts.append(host)
        docs.append(doc or {"transport_error": f"{path}: no probe JSON"})
    now = a.now or max((d.get("time") or 0 for d in docs), default=0) or int(time.time())
    cfg = thresholds(a)
    sums = [summarize(h, d, cfg, now) for h, d in zip(hosts, docs)]
    state = load_state(a.state) if a.state else None
    cross = cross_check(sums, cfg, state, now)
    if a.state and state is not None:
        write_json_atomic(a.state, state)
    return report(sums, cross, a, now)


def cmd_local(a):
    probe = load_probe()
    pa = probe.parser().parse_args(["--rpc-port", str(a.rpc_port), "--proc-name", a.proc_name,
                                    "--data-dir", a.data_dir])
    doc = probe.probe(pa)
    now = int(time.time())
    s = summarize(doc.get("host") or "local", doc, thresholds(a), now)
    out = {"time": now, "summary": s, "result": ["OK", "WARN", "CRIT"][worst(s["alerts"])]}
    if a.raw:
        out["probe"] = doc
    if a.out:
        write_json_atomic(a.out, out)
    else:
        print(json.dumps(out, sort_keys=True, indent=1))
    return worst(s["alerts"])


class Parser(argparse.ArgumentParser):
    """Usage errors exit 3: 2 is the critical-alert status."""
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def main(argv=None):
    ap = Parser(description="ObenBlock mainnet monitor (read-only)")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=Parser)
    common = Parser(add_help=False)
    common.add_argument("--json", action="store_true", help="print JSON instead of the text report")
    common.add_argument("--rpc-port", type=int, default=18210)
    common.add_argument("--proc-name", default="obenblock")
    for k, v in DEFAULTS.items():
        common.add_argument("--" + k.replace("_", "-"), dest=k, type=type(v), default=None,
                            help=f"default {v}")
    st = sub.add_parser("status", parents=[common], help="probe the hosts over SSH")
    st.add_argument("--hosts", default=None, help="comma list (default: the three mainnet hosts)")
    st.add_argument("--pw-hosts", default=",".join(PW_HOSTS))
    st.add_argument("--user", default=SSH_USER)
    st.add_argument("--ssh-key", default=SSH_KEY)
    st.add_argument("--pw-file", default=PW_FILE)
    st.add_argument("--timeout", type=int, default=90)
    st.add_argument("--state", default="~/.cache/obenblock-monitor/state.json")
    st.add_argument("--no-state", action="store_true")
    st.add_argument("--save-raw", default=None, help="directory to keep each host's probe JSON")
    of = sub.add_parser("offline", parents=[common], help="analyse saved probe outputs")
    of.add_argument("files", nargs="+", metavar="HOST=FILE")
    of.add_argument("--now", type=int, default=None)
    of.add_argument("--state", default=None)
    lo = sub.add_parser("local", parents=[common], help="probe this host, write its summary JSON")
    lo.add_argument("--out", default=None)
    lo.add_argument("--data-dir", default="/var/lib/obenblock")
    lo.add_argument("--raw", action="store_true", help="include the raw probe document")
    a = ap.parse_args(argv)
    return {"status": cmd_status, "offline": cmd_offline, "local": cmd_local}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
