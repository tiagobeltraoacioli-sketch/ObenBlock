#!/usr/bin/env python3
"""Check the hosts' status lines (host/status.py) against the launch plan.

    verify_summary.py [--network mainnet|regtest] [--genesis <raw hex>]
                      [--miner-threads auto|N] [--node-mine off|on]
                      [--witness on|off] [--no-units]
                      [--miner-hosts <label,...>] [--paced-miner]
                      [--min-finalized <height>]
                      <label>=<file with status.py output> ...

FAIL (exit 1): not exactly one node process, node or CPU miner unit not
active, a process running another release than /opt/obenblock/current, RPC
silent or public, no RPC key, wrong chain id, genesis differs from the
expected one or between hosts, a CHAIN SPLIT (different block ids at the
lowest common height, or different finalized checkpoints at one height),
tips more than 29 blocks apart, a node syncing or behind, a peer list
without the other kit hosts, built-in Stratum V1 or V2 off or not
listening, not exactly one CPU miner, the wrong thread count (auto =
logical CPUs - 2), a miner that is not hashing (CPU time between the two
samples) or not connected to the V1 server, the node's own --mine on when
the plan says off, witness duty missing, and after the PoCI launch height a
witness outside the PoCI configuration in force (getpowitinfo
poci.signer_weights), with no vote included in the chain, or PoCI not
active; a finality conflict; with --min-finalized, a finalized height below
it. Regtest rehearsal options: --miner-hosts names the hosts that run the
CPU miner (the others must run none), --paced-miner skips the busy-cores
check (the miner pauses after each block: --block-pause-ms).
WARN: GnB processes running, explorer not active, V2 authority key not
readable, a halted PoWit signer, a tip that did not move between the
samples, node warnings, finalized heights apart, a witness whose last
included vote is more than an epoch behind, no share work yet in the
bootstrap epochs.
For each host it prints `STRATUM <label> v1=<addr> v2=<addr> key=<b58>`
lines that obb-launch.sh keeps for the runbook and the site step.
Python 3.9 or later, standard library only.
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


def check_witness(label, st, a, fails, warns):
    """The host's PoWit witness against PoCI (docs/DESIGN-obenblock-poci.md §9)."""
    if a.witness != "on":
        return
    pw = st.get("powit")
    if not pw:
        fails.append(f"{label}: getpowitinfo not answering")
        return
    ws = st.get("witness") or []
    if not ws:
        fails.append(f"{label}: no PoWit signer in this node (getpowitinfo.signers is empty)")
        return
    poci = pw.get("poci") or {}
    params = pw.get("params") or {}
    launch = poci.get("launch_height") or 0
    ci = params.get("checkpoint_interval") or 1
    el = params.get("epoch_len") or 1
    tip = pw.get("tip_height") or 0
    for w in ws:
        name = f"{label}: witness {str(w.get('key'))[:16]}"
        if w.get("halted"):
            fails.append(f"{name} HALTED: {w.get('alert')}")
        if tip >= launch + 2 * ci:
            if not poci.get("active"):
                fails.append(f"{label}: PoCI not active at height {tip} (launch height {launch})")
            if w.get("weight") is None:
                fails.append(f"{name} is not in the PoCI configuration in force at height {tip} (its votes do not count)")
            if not w.get("votes_in_chain"):
                fails.append(f"{name} has no vote included in the chain at height {tip}")
            elif (w.get("last_vote_target") or 0) < tip - el:
                warns.append(f"{name}: last included vote targets {w.get('last_vote_target')}, tip {tip}")
        elif tip >= el and w.get("weight") is None and not ((pw.get("pool") or {}).get("shares")):
            warns.append(f"{name}: no share work in the witness set yet at height {tip} (bootstrap: C_4 is built from it)")


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", default="mainnet", choices=sorted(CHAIN_IDS))
    ap.add_argument("--genesis", default="")
    ap.add_argument("--miner-threads", "--threads", dest="threads", default="auto")
    ap.add_argument("--node-mine", default="off", choices=("on", "off"))
    ap.add_argument("--witness", default="on", choices=("on", "off"))
    ap.add_argument("--no-peer-check", action="store_true",
                    help="skip the check that each peer list has the other hosts (labels that are not IPs)")
    ap.add_argument("--no-units", action="store_true")
    ap.add_argument("--miner-hosts", default="",
                    help="comma-separated labels of the hosts that run the CPU miner (default: every host)")
    ap.add_argument("--paced-miner", action="store_true",
                    help="the CPU miners pause after each block (regtest rehearsal): no busy-cores check")
    ap.add_argument("--min-finalized", type=int, default=None,
                    help="FAIL when a host's finalized height is below this")
    ap.add_argument("hosts", nargs="+")
    a = ap.parse_args(argv[1:])

    fails, warns, rows, genesis, tips, stratum = [], [], [], {}, {}, []
    hashes, pins = {}, {}
    labels = [item.partition("=")[0] for item in a.hosts]
    n_hosts = len(a.hosts)
    for item in a.hosts:
        label, _, path = item.partition("=")
        st = load(path)
        if st is None:
            fails.append(f"{label}: no status (host unreachable or status.py failed)")
            rows.append((label, "-", "-", "-", "-", "-", "-", "-"))
            continue
        procs = st.get("node_processes", [])
        if len(procs) != 1:
            fails.append(f"{label}: {len(procs)} node processes running, expected exactly 1")
        units = st.get("units", {})
        if not a.no_units:
            for unit, must in (("obenblock-node", True), ("obenblock-cpu-miner", True), ("obenblock-explorer-api", False)):
                u = units.get(unit, {})
                if u.get("active") != "active":
                    (fails if must else warns).append(f"{label}: {unit} is {u.get('active')}")
                elif u.get("enabled") != "enabled":
                    warns.append(f"{label}: {unit} is {u.get('enabled')} (not enabled at boot)")
            if units.get("obenblock-explorer-api", {}).get("active") == "active":
                for u in ("obenblock-explorer-firewall", "obenblock-explorer-firewall-reapply.timer"):
                    if units.get(u, {}).get("active") not in ("active", None):
                        warns.append(f"{label}: {u} is {units[u].get('active')} (the API port relies on it)")
                if st.get("explorer_nft_table") is False:
                    fails.append(f"{label}: the explorer API runs but the nft table inet gnb_explorer is not loaded")
            if st.get("ntp_synchronized") is False:
                warns.append(f"{label}: the clock is not NTP-synchronized (the explorer API refuses requests 60 s off)")
            if st.get("gnb_node", {}).get("active") == "active":
                warns.append(f"{label}: GnB gnb-node is active")
        if st.get("gnb_processes"):
            warns.append(f"{label}: {st['gnb_processes']} GnB 'gnb' processes running")

        p = procs[0] if len(procs) == 1 else {}
        rel = st.get("release_dir")
        for what, proc in [("node", p)] + [("cpu miner", m) for m in st.get("miner_processes", [])]:
            exe = proc.get("exe") if proc else None
            if rel and exe and not exe.startswith(rel.rstrip("/") + "/"):
                fails.append(f"{label}: the {what} runs {exe}, not the installed release {rel} (restart it: deploy restarts the units)")
        if p:
            if not p.get("stratum"):
                fails.append(f"{label}: the node runs without --stratum (built-in V1)")
            if not p.get("stratum_v2"):
                fails.append(f"{label}: the node runs without --stratum-v2")
            if p.get("mine") and a.node_mine == "off":
                fails.append(f"{label}: the node runs --mine as well as the CPU miner (the plan: miner unit only)")
            if not p.get("mine") and a.node_mine == "on":
                fails.append(f"{label}: the node runs without --mine")
            if a.witness == "on" and not p.get("witness"):
                fails.append(f"{label}: the node runs without the PoWit witness duty (--witness-key)")
            if p.get("rpc_public"):
                fails.append(f"{label}: the node runs with --rpc-public")
            if not p.get("rpc_key"):
                fails.append(f"{label}: the node runs without --rpc-api-key-file")
        listening = st.get("listening", [])
        v1_port, v2_port = st.get("stratum_ports") or [3333, 3334]
        for name, port in (("V1", v1_port), ("V2", v2_port)):
            if not any(x.endswith(f":{port}") for x in listening):
                fails.append(f"{label}: nothing listens on :{port} (stratum {name})")

        ms = st.get("miner_processes", [])
        want = max(1, (st.get("nproc") or 3) - 2) if a.threads == "auto" else int(a.threads)
        miner_here = not a.miner_hosts or label in a.miner_hosts.split(",")
        if not miner_here:
            if ms:
                fails.append(f"{label}: {len(ms)} obenblock-cpu-miner processes, expected none on this host")
        elif len(ms) != 1:
            fails.append(f"{label}: {len(ms)} obenblock-cpu-miner processes, expected exactly 1")
        elif str(ms[0].get("threads")) != str(want):
            fails.append(f"{label}: CPU miner threads {ms[0].get('threads')}, expected {want}")
        m_threads = ms[0].get("threads") if len(ms) == 1 else None
        if (len(ms) == 1 and not a.paced_miner and ms[0].get("cpu_cores_busy") is not None
                and ms[0]["cpu_cores_busy"] < 0.5 * want):
            fails.append(f"{label}: CPU miner used {ms[0]['cpu_cores_busy']} cores over the sample, expected about {want}: not hashing")

        met = st.get("metrics") or {}
        if met.get("powit_signer_halted", 0) > 0:
            warns.append(f"{label}: PoWit signer HALTED (getpowitinfo.signers; docs/RUNNING.md 'Witness signer protection')")
        if ms and met and met.get("stratum_sessions_active.v1", 0) < 1:
            fails.append(f"{label}: no Stratum V1 session open: the CPU miner is not connected to the node")
        found = {k: v for k, v in met.items() if k.startswith("stratum_blocks_found_total")}
        shares = {k: v for k, v in met.items() if k.startswith("stratum_shares_submitted_total")}
        if met:
            print(f"{label}: stratum blocks " + (", ".join(f"{k.split('.', 1)[-1]}={v:g}" for k, v in sorted(found.items())) or "0")
                  + "; shares " + (", ".join(f"{k.split('.', 1)[-1]}={v:g}" for k, v in sorted(shares.items())) or "0"))
        key = (st.get("stratum_v2_key") or {}).get("public_b58")
        if not key:
            warns.append(f"{label}: Stratum V2 authority key not readable yet (the node creates it on first start)")
        stratum.append(f"STRATUM {label} v1={p.get('stratum')} v2={p.get('stratum_v2')} key={key or '-'}")

        if not st.get("rpc_ok"):
            fails.append(f"{label}: RPC not answering ({st.get('rpc_error')})")
            rows.append((label, len(procs), m_threads, "-", "-", "-", "-", "-"))
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
        if net.get("syncing") or (net.get("behind_by") or 0) > 0:
            fails.append(f"{label}: syncing={net.get('syncing')} behind_by={net.get('behind_by')}")
        if net.get("warnings"):
            warns.append(f"{label}: node warnings: {net.get('warnings')}")
        if not a.no_peer_check:
            plist = " ".join(str(x) for x in st.get("peer_list") or [])
            if not plist:
                # getpeerinfo reports only peer_count on this node: the count
                # check above is all that can be verified.
                warns.append(f"{label}: the node does not list peer addresses; only the peer count was checked")
            else:
                for other in labels:
                    if other != label and other not in plist:
                        fails.append(f"{label}: {other} is not among its peers ({plist})")
        fin = st.get("finality") or {}
        if fin.get("conflict"):
            fails.append(f"{label}: finality conflict {fin['conflict']} (docs/RUNNING.md)")
        tip_h = (st.get("tip") or {}).get("tip_height")
        tips[label] = tip_h
        hashes[label] = st.get("hashes") or {}
        if fin.get("pin_height") is not None:
            pins[label] = (fin.get("pin_height"), fin.get("pin_hash"))
        if a.min_finalized is not None and (fin.get("pin_height") or 0) < a.min_finalized:
            fails.append(f"{label}: finalized height {fin.get('pin_height')}, expected at least {a.min_finalized}")
        if st.get("tip_later") is not None and st.get("tip_later") == tip_h:
            warns.append(f"{label}: the tip did not move in {st.get('sample_secs')} s (normal while CPUs mine at the launch difficulty)")
        check_witness(label, st, a, fails, warns)
        rows.append((label, len(procs), m_threads, net.get("peers"), tip_h, fin.get("pin_height"),
                     st.get("hashrate"), (g or "")[:16]))

    if len(set(genesis.values())) > 1:
        fails.append("hosts disagree on the genesis: " + ", ".join(f"{k}={v}" for k, v in genesis.items()))
    known = [t for t in tips.values() if isinstance(t, int)]
    if len(known) > 1:
        low = min(known)
        if max(known) - low > 29:
            fails.append("tips more than 29 blocks apart (split or stuck node): " + ", ".join(f"{k}={v}" for k, v in tips.items()))
        else:
            at = {k: h.get(str(low)) for k, h in hashes.items() if str(low) in h}
            if len(set(map(str, at.values()))) > 1:
                fails.append(f"CHAIN SPLIT: block ids at height {low} differ: " + ", ".join(f"{k}={v}" for k, v in at.items()))
            elif max(known) - low > 3:
                warns.append("tips apart by more than 3 blocks: " + ", ".join(f"{k}={v}" for k, v in tips.items()))
    by_height = {}
    for k, (h, hh) in pins.items():
        by_height.setdefault(h, set()).add(hh)
    for h, ids in by_height.items():
        if len(ids) > 1:
            fails.append(f"CHAIN SPLIT: different finalized checkpoints at height {h}: {sorted(map(str, ids))}")
    if len(by_height) > 1:
        warns.append("finalized heights differ: " + ", ".join(f"{k}={v[0]}" for k, v in pins.items()))

    print("%-18s %5s %7s %5s %8s %9s %12s %s" % ("host", "procs", "miner_t", "peers", "tip", "finalized", "hashrate", "genesis"))
    for r in rows:
        print("%-18s %5s %7s %5s %8s %9s %12s %s" % tuple("-" if x is None else x for x in r))
    for s in stratum:
        print(s)
    for w in warns:
        print("WARN", w)
    for f in fails:
        print("FAIL", f)
    print("RESULT", "FAIL" if fails else "OK")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
