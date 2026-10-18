#!/usr/bin/env python3
"""Status of the ObenBlock node on this host, as one JSON line.

    status.py [--rpc-port 18210] [--proc-name obenblock] [--data-dir DIR] [--no-units]

Prints human lines, then one line `OBB-STATUS {json}` that obb-launch.sh
verify (lib/verify_summary.py) reads. Reads only: the units' states, the
processes (/proc), the node's loopback RPC, listening sockets and, when sudo
needs no password, ufw. Standard library only.
"""
import argparse
import json
import os
import re
import subprocess
import urllib.request

UNITS = ("obenblock-node", "obenblock-explorer-api", "obenblock-stratum")
PORTS = (18110, 18210, 3333, 9333, 2086, 2087)


def sh(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def unit_state(name):
    _, active = sh(["systemctl", "is-active", name])
    _, enabled = sh(["systemctl", "is-enabled", name])
    return {"active": active or "unknown", "enabled": enabled or "unknown"}


def processes(comm, data_dir=None):
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as fh:
                if fh.read().strip() != comm:
                    continue
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                args = [a.decode(errors="replace") for a in fh.read().split(b"\0") if a]
            with open(f"/proc/{pid}/status") as fh:
                threads = int(re.search(r"^Threads:\s+(\d+)", fh.read(), re.M).group(1))
        except (OSError, AttributeError):
            continue
        def flag(name):
            return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else None
        if data_dir and flag("--data-dir") != data_dir:
            continue
        out.append({"pid": int(pid), "threads": threads, "mine": "--mine" in args,
                    "mine_threads": flag("--mine-threads"), "miner_address": flag("--miner-address"),
                    "peers": [args[i + 1] for i, a in enumerate(args[:-1]) if a == "--peer"],
                    "data_dir": flag("--data-dir")})
    return out


def rpc(port, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read()).get("result")
    except Exception as e:  # report, never raise: a stopped node is a status
        return {"error": str(e)[:200]}


def listening():
    _, out = sh(["ss", "-ltnH"])
    ports = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 4:
            m = re.search(r":(\d+)$", cols[3])
            if m and int(m.group(1)) in PORTS:
                ports.add(cols[3])
    return sorted(ports)


def stratum_metrics(port=9333):
    """The proxy's obb_stratum_* counters (tools/obenblock-stratum), or None."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=4) as r:
            text = r.read(1 << 20).decode(errors="replace")
    except Exception:
        return None
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(obb_stratum_[a-z_]+)(?:\{[^}]*\})?\s+([0-9.eE+-]+)$", line)
        if m:
            out[m.group(1)] = out.get(m.group(1), 0) + float(m.group(2))
    return out


def ufw_rules():
    code, out = sh(["sudo", "-n", "ufw", "status"])
    if code == 127:
        return None
    if code != 0:
        return None
    return [line for line in out.splitlines() if "ObenBlock" in line or line.startswith("Status:")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-port", type=int, default=18210)
    ap.add_argument("--proc-name", default="obenblock")
    ap.add_argument("--data-dir", default=None, help="count only the node processes of this data dir (rehearsal)")
    ap.add_argument("--no-units", action="store_true")
    a = ap.parse_args()

    st = {"host": os.uname().nodename, "nproc": os.cpu_count()}
    if not a.no_units:
        st["units"] = {u: unit_state(u) for u in UNITS}
        st["gnb_node"] = unit_state("gnb-node")
        _, bl = sh(["systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "bloch-*"])
        st["bloch_active_units"] = len([x for x in bl.splitlines() if x.strip()])
    st["node_processes"] = processes(a.proc_name, a.data_dir)
    st["gnb_processes"] = len(processes("gnb")) if a.proc_name != "gnb" else None
    info = rpc(a.rpc_port, "getnetworkinfo")
    st["rpc_ok"] = isinstance(info, dict) and "error" not in info
    if st["rpc_ok"]:
        st["network"] = {k: info.get(k) for k in ("chain_id", "network", "version", "blocks", "blue_score", "peers", "syncing", "behind_by", "warnings")}
        st["genesis"] = rpc(a.rpc_port, "getblockhash", [0])
        dag = rpc(a.rpc_port, "getdaginfo") or {}
        st["tip"] = {k: dag.get(k) for k in ("tip", "tip_height", "tip_blue_work", "tip_count")}
        peers = rpc(a.rpc_port, "getpeerinfo") or {}
        st["peer_list"] = [p.get("ip") or p.get("address") for p in peers.get("peers", [])] if isinstance(peers, dict) else []
        hr = rpc(a.rpc_port, "gethashrate") or {}
        st["hashrate"] = hr.get("hashrate_human") if isinstance(hr, dict) else None
    else:
        st["rpc_error"] = info.get("error") if isinstance(info, dict) else str(info)
    st["listening"] = listening()
    st["stratum_metrics"] = stratum_metrics() if any(x.endswith(":3333") for x in st["listening"]) else None
    st["ufw"] = ufw_rules()

    for p in st["node_processes"]:
        print(f"node pid {p['pid']}: mine={p['mine']} mine_threads={p['mine_threads']} os_threads={p['threads']} peers={p['peers']}")
    if st["rpc_ok"]:
        n = st["network"]
        print(f"chain_id {n['chain_id']} {n['network']} blocks={n['blocks']} peers={n['peers']} tip_height={st['tip']['tip_height']} genesis={st['genesis']}")
    else:
        print(f"RPC on 127.0.0.1:{a.rpc_port} not answering: {st.get('rpc_error')}")
    print("OBB-STATUS " + json.dumps(st, sort_keys=True))


if __name__ == "__main__":
    main()
