#!/usr/bin/env python3
"""Check the hosts' status lines (host/status.py) against the launch plan.

    verify_summary.py [--network mainnet|regtest] [--genesis <raw hex>]
                      [--threads auto|N] [--stratum-host <label>] [--no-units]
                      <label>=<file with status.py output> ...

FAIL (exit 1): not exactly one node process, node unit not active, RPC
silent, wrong chain id, genesis differs from the expected one or between
hosts, fewer peers than the other hosts, miner off or with the wrong thread
count. WARN: GnB processes running, explorer or stratum not active, tips
apart by more than 3 blocks. Python 3.9 or later, standard library only.
"""
import argparse
import json
import sys

CHAIN_IDS = {"mainnet": "0x4f420001", "regtest": "0x4f420002"}


def load(path):
    with open(path, errors="replace") as fh:
        for line in fh.read().replace("\r", "").splitlines():
            if line.startswith("OBB-STATUS "):
                return json.loads(line[len("OBB-STATUS "):])
    return None


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", default="mainnet", choices=sorted(CHAIN_IDS))
    ap.add_argument("--genesis", default="")
    ap.add_argument("--threads", default="auto")
    ap.add_argument("--stratum-host", default="")
    ap.add_argument("--no-units", action="store_true")
    ap.add_argument("hosts", nargs="+")
    a = ap.parse_args(argv[1:])

    fails, warns, rows, genesis, tips = [], [], [], {}, {}
    n_hosts = len(a.hosts)
    for item in a.hosts:
        label, _, path = item.partition("=")
        st = load(path)
        if st is None:
            fails.append(f"{label}: no status (host unreachable or status.py failed)")
            rows.append((label, "-", "-", "-", "-", "-", "-"))
            continue
        procs = st.get("node_processes", [])
        if len(procs) != 1:
            fails.append(f"{label}: {len(procs)} node processes running, expected exactly 1")
        if not a.no_units:
            node_unit = st.get("units", {}).get("obenblock-node", {})
            if node_unit.get("active") != "active":
                fails.append(f"{label}: obenblock-node is {node_unit.get('active')}")
            if node_unit.get("enabled") != "enabled":
                warns.append(f"{label}: obenblock-node is {node_unit.get('enabled')} (not enabled at boot)")
            api = st.get("units", {}).get("obenblock-explorer-api", {})
            if api.get("active") != "active":
                warns.append(f"{label}: obenblock-explorer-api is {api.get('active')}")
            if label == a.stratum_host:
                su = st.get("units", {}).get("obenblock-stratum", {})
                if su.get("active") != "active":
                    warns.append(f"{label}: obenblock-stratum is {su.get('active')} (ASICs cannot connect)")
                if not any(x.endswith(":3333") for x in st.get("listening", [])):
                    warns.append(f"{label}: nothing listens on :3333")
        sm = st.get("stratum_metrics") or {}
        if sm.get("obb_stratum_shares_bitcoin_root_total", 0) > 0:
            warns.append(f"{label}: {int(sm['obb_stratum_shares_bitcoin_root_total'])} stratum shares over Bitcoin's Merkle root: "
                         "stock Stratum V1 firmware is connected and cannot find ObenBlock blocks (tools/obenblock-stratum README §1)")
        if sm:
            print(f"{label}: stratum " + ", ".join(f"{k[len('obb_stratum_'):]}={v:g}" for k, v in sorted(sm.items())
                                                  if any(w in k for w in ("worker", "share", "block"))))
        if not a.no_units and st.get("gnb_node", {}).get("active") == "active":
            warns.append(f"{label}: GnB gnb-node is active")
        if st.get("gnb_processes"):
            warns.append(f"{label}: {st['gnb_processes']} GnB 'gnb' processes running")
        p = procs[0] if len(procs) == 1 else {}
        want_threads = (st.get("nproc", 1) - 1 or 1) if a.threads == "auto" else int(a.threads)
        if procs and not p.get("mine"):
            fails.append(f"{label}: the node runs without --mine")
        elif procs and str(p.get("mine_threads")) != str(want_threads):
            fails.append(f"{label}: mine threads {p.get('mine_threads')}, expected {want_threads}")
        if not st.get("rpc_ok"):
            fails.append(f"{label}: RPC not answering ({st.get('rpc_error')})")
            rows.append((label, len(procs), p.get("mine_threads"), "-", "-", "-", "-"))
            continue
        net = st["network"]
        if net.get("chain_id") != CHAIN_IDS[a.network]:
            fails.append(f"{label}: chain id {net.get('chain_id')}, expected {CHAIN_IDS[a.network]}")
        g = st.get("genesis")
        genesis[label] = g
        if a.genesis and g != a.genesis.lower():
            fails.append(f"{label}: genesis {g}, expected {a.genesis.lower()}")
        if (net.get("peers") or 0) < n_hosts - 1:
            fails.append(f"{label}: {net.get('peers')} peers, expected at least {n_hosts - 1}")
        tip_h = (st.get("tip") or {}).get("tip_height")
        tips[label] = tip_h
        rows.append((label, len(procs), p.get("mine_threads"), net.get("peers"), tip_h, st.get("hashrate"), (g or "")[:16]))

    if len(set(genesis.values())) > 1:
        fails.append("hosts disagree on the genesis: " + ", ".join(f"{k}={v}" for k, v in genesis.items()))
    known = [t for t in tips.values() if isinstance(t, int)]
    if len(known) > 1 and max(known) - min(known) > 3:
        warns.append("tips apart by more than 3 blocks: " + ", ".join(f"{k}={v}" for k, v in tips.items()))

    print("%-18s %5s %7s %5s %10s %12s %s" % ("host", "procs", "threads", "peers", "tip", "hashrate", "genesis"))
    for r in rows:
        print("%-18s %5s %7s %5s %10s %12s %s" % tuple("-" if x is None else x for x in r))
    for w in warns:
        print("WARN", w)
    for f in fails:
        print("FAIL", f)
    print("RESULT", "FAIL" if fails else "OK")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
