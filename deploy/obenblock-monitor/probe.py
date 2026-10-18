#!/usr/bin/env python3
"""Read-only probe of one ObenBlock mainnet host.

    probe.py [--rpc-port 18210] [--proc-name obenblock] [--data-dir /var/lib/obenblock]
             [--stratum-metrics 127.0.0.1:9333] [--node-metrics 127.0.0.1:18310]
             [--chain-window 32] [--rpc-key-file FILE]

Prints one line `OBB-PROBE {json}` with the raw facts of this host; the
analysis (alerts, cross-host checks, the text report) is obbmon.py's. The
probe changes nothing: it reads `ps`, /proc, statvfs, `systemctl is-active`,
the CPU miner's journal (when the caller may read it), the node's loopback
JSON-RPC (read methods only, no API key needed on loopback) and the loopback
Prometheus endpoints of the node (`--metrics`, port 18310) and of the stratum
proxy (OBB_STRATUM_METRICS, port 9333). Standard library only; obbmon.py
ships this file over SSH inside the command line (`python3 -I -c ...`), so
it never lands on the host's disk; the systemd timer runs it from disk.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import time
import urllib.request

PROBE_VERSION = 1
UNITS = ("obenblock-node", "obenblock-stratum", "obenblock-cpu-miner", "obenblock-explorer-api")
CPU_MINER_UNIT = "obenblock-cpu-miner"
# The read methods asked of the node, in order. Every one is a read method
# (none is in auth::WRITE_METHODS or ADMIN_METHODS of node/src/rpc/auth.rs).
RPC_CALLS = (
    ("getnetworkinfo", []),
    ("getdaginfo", []),
    ("getmempoolinfo", []),
    ("getpeers", []),
    ("getpowitinfo", []),
    ("getfinalityinfo", []),
    ("gethashrate", []),
    ("genesis", None),           # getblockhash [0]
    ("getselectedchain", None),  # [0, chain_window], trimmed
)
CHAIN_KEEP = ("hash", "height", "timestamp", "blue_score")


def sh(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


# ── Processes ────────────────────────────────────────────────────────────────

PS_FORMAT = "pid=,etimes=,etime=,pcpu=,rss=,comm=,args="


def parse_ps(text, comm):
    """Rows of `ps -eo pid=,etimes=,etime=,pcpu=,rss=,comm=,args=` whose
    command name is `comm`, as dicts. Pure."""
    out = []
    for line in text.splitlines():
        cols = line.split(None, 6)
        if len(cols) < 6 or cols[5] != comm:
            continue
        try:
            out.append({
                "pid": int(cols[0]), "etimes": int(cols[1]), "etime": cols[2],
                "pcpu": float(cols[3]), "rss_kb": int(cols[4]),
                "args": cols[6] if len(cols) > 6 else cols[5],
            })
        except ValueError:
            continue
    return out


def processes(comm):
    code, out = sh(["ps", "-eo", PS_FORMAT])
    return parse_ps(out, comm) if code == 0 else None


def unit_states():
    out = {}
    for u in UNITS:
        code, s = sh(["systemctl", "is-active", u], timeout=5)
        out[u] = s.strip() or ("unknown" if code == 127 else "inactive")
    return out


# ── Node RPC ─────────────────────────────────────────────────────────────────

def rpc(port, method, params=None, key=None, timeout=10):
    """The `result` of one JSON-RPC call, or {"error": ...}. Never raises."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    headers = {"content-type": "application/json"}
    if key:
        headers["x-api-key"] = key
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            doc = json.loads(r.read(4 << 20))
    except Exception as e:  # a stopped node is a status, not a crash
        return {"error": f"{type(e).__name__}: {str(e)[:200]}"}
    if "result" in doc:
        return doc["result"]
    err = doc.get("error")
    return {"error": err.get("message") if isinstance(err, dict) else str(err)}


def trim_chain(sel):
    """getselectedchain's page reduced to what the cross-host check reads."""
    if not isinstance(sel, dict) or "blocks" not in sel:
        return sel
    return {"chain_length": sel.get("chain_length"),
            "blocks": [{k: b.get(k) for k in CHAIN_KEEP} for b in sel.get("blocks") or []]}


def collect_rpc(port, key=None, window=32):
    out = {}
    for method, params in RPC_CALLS:
        if method == "genesis":
            out[method] = rpc(port, "getblockhash", [0], key)
        elif method == "getselectedchain":
            out[method] = trim_chain(rpc(port, method, [0, window], key))
        else:
            out[method] = rpc(port, method, params, key)
        if method == "getnetworkinfo" and isinstance(out[method], dict) and "error" in out[method] \
                and "refused" in str(out[method]["error"]).lower():
            break  # nothing listens: do not wait on every other call
    return out


# ── Prometheus text ──────────────────────────────────────────────────────────

METRIC_LINE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([-+0-9.eE]+|NaN|[+-]Inf)(\s+\d+)?$")


def parse_prometheus(text, prefixes=("gnb_", "obb_")):
    """{series name: sum over its label sets} for the series with one of
    `prefixes`. Histograms keep their _sum/_count/_bucket series. Pure."""
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = METRIC_LINE.match(line.strip())
        if not m or not m.group(1).startswith(prefixes):
            continue
        try:
            v = float(m.group(3))
        except ValueError:
            continue
        out[m.group(1)] = out.get(m.group(1), 0.0) + v
    return out


def scrape(addr, paths=("/metrics",)):
    if not addr:
        return None
    for path in paths:
        try:
            with urllib.request.urlopen(f"http://{addr}{path}", timeout=4) as r:
                return parse_prometheus(r.read(4 << 20).decode(errors="replace"))
        except Exception:
            continue
    return None


# ── CPU miner (obenblock-cpu-miner, tools/obenblock-stratum) ─────────────────

MINER_RATE = re.compile(r"\[miner\] ([0-9.]+) MH/s, shares accepted (\d+) rejected (\d+)")
MINER_START = re.compile(r"\[miner\] (\d+) threads \(([^)]*)\), about ([0-9.]+) MH/s")


def parse_cpu_miner_journal(text):
    """The newest rate line of `journalctl -o short-unix` output of the CPU
    miner (it prints one every 30 s), else its start-up estimate. Pure."""
    best = None
    for line in text.splitlines():
        ts = None
        head = line.split(" ", 1)[0]
        try:
            ts = float(head)
        except ValueError:
            pass
        m = MINER_RATE.search(line)
        if m:
            best = {"mhs": float(m.group(1)), "accepted": int(m.group(2)), "rejected": int(m.group(3)),
                    "at": ts, "kind": "rate"}
            continue
        m = MINER_START.search(line)
        if m and (best is None or best["kind"] == "start"):
            best = {"mhs": float(m.group(3)), "threads": int(m.group(1)), "kernel": m.group(2),
                    "at": ts, "kind": "start"}
    return best


def cpu_miner():
    code, out = sh(["journalctl", "-u", CPU_MINER_UNIT, "-n", "60", "--no-pager", "-o", "short-unix"])
    if code != 0:
        return None
    return parse_cpu_miner_journal(out)


# ── System ───────────────────────────────────────────────────────────────────

def parse_meminfo(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)\s*kB", line)
        if m and m.group(1) in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            out[m.group(1)] = int(m.group(2)) * 1024
    return out


def system(data_dir):
    st = {"nproc": os.cpu_count()}
    try:
        with open("/proc/meminfo") as fh:
            st["mem"] = parse_meminfo(fh.read())
    except OSError:
        st["mem"] = None
    try:
        with open("/proc/loadavg") as fh:
            st["load"] = [float(x) for x in fh.read().split()[:3]]
    except (OSError, ValueError):
        st["load"] = None
    disks = []
    for path in ("/", data_dir):
        if not path or any(d["path"] == path for d in disks):
            continue
        try:
            v = os.statvfs(path)
        except OSError:
            continue
        total, free = v.f_blocks * v.f_frsize, v.f_bavail * v.f_frsize
        disks.append({"path": path, "total": total, "free": free})
    st["disk"] = disks
    return st


def read_key(path):
    if not path:
        return None
    try:
        with open(path) as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def probe(a):
    started = time.time()
    doc = {
        "probe_version": PROBE_VERSION,
        "host": socket.gethostname(),
        "time": int(started),
        "proc_name": a.proc_name,
        "rpc_port": a.rpc_port,
        "processes": processes(a.proc_name),
        "units": unit_states(),
        "rpc": collect_rpc(a.rpc_port, read_key(a.rpc_key_file), a.chain_window),
        "metrics": {
            "node": scrape(a.node_metrics, ("/metrics", "/debug/metrics/prometheus")),
            "stratum": scrape(a.stratum_metrics),
        },
        "cpu_miner": cpu_miner(),
        "system": system(a.data_dir),
    }
    doc["elapsed_ms"] = int((time.time() - started) * 1000)
    return doc


def parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rpc-port", type=int, default=18210)
    ap.add_argument("--proc-name", default="obenblock")
    ap.add_argument("--data-dir", default="/var/lib/obenblock")
    ap.add_argument("--stratum-metrics", default="127.0.0.1:9333")
    ap.add_argument("--node-metrics", default="127.0.0.1:18310")
    ap.add_argument("--chain-window", type=int, default=32)
    ap.add_argument("--rpc-key-file", default=None, help="X-API-Key file (not needed on loopback for reads)")
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    a.chain_window = max(4, min(100, a.chain_window))
    print("OBB-PROBE " + json.dumps(probe(a), sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
