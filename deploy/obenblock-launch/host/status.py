#!/usr/bin/env python3
"""Status of the ObenBlock services on this host, as one JSON line.

    status.py [--rpc-port 18210] [--metrics-port 18310] [--proc-name obenblock]
              [--data-dir DIR] [--v2-key FILE] [--stratum-ports 3333,3334]
              [--no-units]

Prints human lines, then one line `OBB-STATUS {json}` that obb-launch.sh
verify (lib/verify_summary.py) reads. Reads only: the units' states, the
processes (/proc), the node's loopback RPC and metrics, listening sockets,
ufw (as root) and the PUBLIC fields of the Stratum V2 authority key file
(`public_b58`, `fingerprint_hex`; the secret is never read into the output).
obb-launch.sh runs it with sudo. Standard library only.
"""
import argparse
import json
import os
import re
import subprocess
import time
import urllib.request

UNITS = ("obenblock-node", "obenblock-cpu-miner", "obenblock-explorer-api", "obenblock-explorer-firewall",
         "obenblock-explorer-firewall-reapply.timer", "obenblock-stratum")
PORTS = {18110, 18210, 18310, 3333, 3334, 3335, 9333, 2086, 2087}


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


def proc_args(pid):
    with open(f"/proc/{pid}/cmdline", "rb") as fh:
        return [a.decode(errors="replace") for a in fh.read().split(b"\0") if a]


def proc_threads(pid):
    with open(f"/proc/{pid}/status") as fh:
        return int(re.search(r"^Threads:\s+(\d+)", fh.read(), re.M).group(1))


def flag(args, name):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else None


def processes(comm, data_dir=None):
    """The node processes (comm `obenblock`, or `gnb` for GnB)."""
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as fh:
                if fh.read().strip() != comm:
                    continue
            args = proc_args(pid)
            threads = proc_threads(pid)
        except (OSError, AttributeError):
            continue
        if data_dir and flag(args, "--data-dir") != data_dir:
            continue
        try:
            exe = os.path.realpath(f"/proc/{pid}/exe")
        except OSError:
            exe = None
        out.append({"pid": int(pid), "threads": threads, "exe": exe, "mine": "--mine" in args,
                    "mine_threads": flag(args, "--mine-threads"), "miner_address": flag(args, "--miner-address"),
                    "stratum": flag(args, "--stratum-addr") if "--stratum" in args else None,
                    "stratum_v2": flag(args, "--stratum-v2-addr") if "--stratum-v2" in args else None,
                    "stratum_v2_key": flag(args, "--stratum-v2-key"),
                    "stratum_payout": flag(args, "--stratum-payout"),
                    "witness": "--witness-key" in args, "share_threads": flag(args, "--share-threads"),
                    "rpc_key": "--rpc-api-key-file" in args, "rpc_public": "--rpc-public" in args,
                    "peers": [args[i + 1] for i, a in enumerate(args[:-1]) if a == "--peer"],
                    "data_dir": flag(args, "--data-dir")})
    return out


def miners(url_port=None):
    """obenblock-cpu-miner processes (comm is cut to 15 characters: argv[0])."""
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            args = proc_args(pid)
            if not args or os.path.basename(args[0]) != "obenblock-cpu-miner" or "--bench" in args:
                continue
            threads = proc_threads(pid)
        except (OSError, AttributeError):
            continue
        url = flag(args, "-o") or flag(args, "--url")
        if url_port and not (url or "").endswith(f":{url_port}"):
            continue
        try:
            exe = os.path.realpath(f"/proc/{pid}/exe")
        except OSError:
            exe = None
        out.append({"pid": int(pid), "os_threads": threads, "exe": exe, "cpu_ticks": cpu_ticks(pid),
                    "threads": flag(args, "-t") or flag(args, "--threads"),
                    "url": url, "user": flag(args, "-u") or flag(args, "--user")})
    return out


def cpu_ticks(pid):
    """utime + stime of a process, in clock ticks (None when it is gone)."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])
    except (OSError, IndexError, ValueError):
        return None


def rpc(port, method, params=None, key=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    headers = {"content-type": "application/json"}
    if key:
        headers["x-api-key"] = key
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read()).get("result")
    except Exception as e:  # report, never raise: a stopped node is a status
        return {"error": str(e)[:200]}


def listening(ports):
    _, out = sh(["ss", "-ltnH"])
    found = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 4:
            m = re.search(r":(\d+)$", cols[3])
            if m and int(m.group(1)) in ports:
                found.add(cols[3])
    return sorted(found)


def node_metrics(port):
    """The node's gnb_stratum_* series summed per (name, protocol), and the
    PoWit signer alert, from its Prometheus endpoint; None when off."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/debug/metrics/prometheus", timeout=4) as r:
            text = r.read(1 << 21).decode(errors="replace")
    except Exception:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=4) as r:
                text = r.read(1 << 21).decode(errors="replace")
        except Exception:
            return None
    out = {}
    for line in text.splitlines():
        m = re.match(r'^(gnb_stratum_[a-z_]+|gnb_powit_signer_halted)(?:\{([^}]*)\})?\s+([0-9.eE+-]+)$', line)
        if not m:
            continue
        name, labels, value = m.group(1), m.group(2) or "", float(m.group(3))
        proto = re.search(r'protocol="([a-z0-9]+)"', labels)
        result = re.search(r'result="([a-z_]+)"', labels)
        key = name[len("gnb_"):] + (f".{proto.group(1)}" if proto else "") + (f".{result.group(1)}" if result else "")
        out[key] = out.get(key, 0) + value
    return out


def v2_public(path):
    try:
        with open(path) as fh:
            k = json.load(fh)
        return {"public_b58": k.get("public_b58"), "fingerprint_hex": k.get("fingerprint_hex")}
    except (OSError, ValueError):
        return None


def ufw_rules():
    code, out = sh(["ufw", "status"]) if os.geteuid() == 0 else sh(["sudo", "-n", "ufw", "status"])
    if code != 0:
        return None
    return [line for line in out.splitlines() if "ObenBlock" in line or line.startswith("Status:")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-port", type=int, default=18210)
    ap.add_argument("--metrics-port", type=int, default=18310)
    ap.add_argument("--proc-name", default="obenblock")
    ap.add_argument("--data-dir", default=None, help="count only the node processes of this data dir (rehearsal)")
    ap.add_argument("--v2-key", default="/var/lib/obenblock/stratum-v2-authority.json")
    ap.add_argument("--stratum-ports", default="3333,3334")
    ap.add_argument("--rpc-key-file", default="/etc/obenblock/rpc.key")
    ap.add_argument("--release-dir", default="/opt/obenblock/current")
    ap.add_argument("--sample-secs", type=float, default=15.0,
                    help="seconds between the two samples (tip, miner CPU time, shares)")
    ap.add_argument("--no-units", action="store_true")
    a = ap.parse_args()
    v1_port, v2_port = (int(x) for x in a.stratum_ports.split(","))
    ports = PORTS | {a.rpc_port, a.metrics_port, v1_port, v2_port}
    try:
        with open(a.rpc_key_file) as fh:
            key = fh.readline().strip()
    except OSError:
        key = None

    st = {"host": os.uname().nodename, "nproc": os.cpu_count(),
          "release_dir": os.path.realpath(a.release_dir), "release_id": None}
    try:
        with open(os.path.join(a.release_dir, "RELEASE")) as fh:
            st["release_id"] = next((l.split("=", 1)[1].strip() for l in fh if l.startswith("id=")), None)
    except OSError:
        pass
    if not a.no_units:
        st["units"] = {u: unit_state(u) for u in UNITS}
        st["gnb_node"] = unit_state("gnb-node")
        _, bl = sh(["systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "bloch-*"])
        st["bloch_active_units"] = len([x for x in bl.splitlines() if x.strip()])
    st["node_processes"] = processes(a.proc_name, a.data_dir)
    st["miner_processes"] = miners(v1_port)
    st["gnb_processes"] = len(processes("gnb")) if a.proc_name != "gnb" else None
    info = rpc(a.rpc_port, "getnetworkinfo")
    st["rpc_ok"] = isinstance(info, dict) and "error" not in info
    if st["rpc_ok"]:
        st["network"] = {k: info.get(k) for k in ("chain_id", "network", "version", "blocks", "blue_score", "peers", "syncing", "behind_by", "warnings")}
        st["genesis"] = rpc(a.rpc_port, "getblockhash", [0])
        dag = rpc(a.rpc_port, "getdaginfo") or {}
        st["tip"] = {k: dag.get(k) for k in ("tip", "tip_height", "tip_blue_work", "tip_count", "finalized_height")}
        peers = rpc(a.rpc_port, "getpeerinfo") or {}
        st["peer_list"] = [p.get("ip") or p.get("address") for p in peers.get("peers", [])] if isinstance(peers, dict) else []
        hr = rpc(a.rpc_port, "gethashrate") or {}
        st["hashrate"] = hr.get("hashrate_human") if isinstance(hr, dict) else None
        fin = rpc(a.rpc_port, "getfinalityinfo") or {}
        if isinstance(fin, dict) and "error" not in fin:
            pin = fin.get("pin") or {}
            st["finality"] = {"pin_height": pin.get("block_height"), "pin_hash": pin.get("hash"),
                              "finalized_count": fin.get("finalized_count"), "conflict": fin.get("conflict"),
                              "poci": fin.get("poci")}
        # Block ids of the last 30 heights: verify compares the hosts at the
        # lowest common height (a split shows as different ids there).
        th = st["tip"].get("tip_height")
        if isinstance(th, int):
            st["hashes"] = {str(h): rpc(a.rpc_port, "getblockhash", [h]) for h in range(max(0, th - 29), th + 1)}
        pw = rpc(a.rpc_port, "getpowitinfo") or {}
        if isinstance(pw, dict) and "error" not in pw:
            poci = pw.get("poci") or {}
            st["powit"] = {k: pw.get(k) for k in ("epoch", "tip_height", "signer_halted", "finality_conflict")}
            st["powit"]["params"] = pw.get("params")
            st["powit"]["witness_set"] = pw.get("witness_set")
            st["powit"]["pool"] = pw.get("pool")
            st["powit"]["poci"] = {k: poci.get(k) for k in ("active", "launch_height", "bootstrap_epochs", "config_epoch",
                                                              "config_id", "total", "entries", "absent_weight", "pruned",
                                                              "finalized")}
            st["witness"] = []
            for sg in pw.get("signers") or []:
                key = sg.get("key")
                votes = rpc(a.rpc_port, "getpowitkeyvotes", [key]) if key else {}
                chain = votes.get("chain") if isinstance(votes, dict) else None
                chain = chain if isinstance(chain, list) else []
                top = (pw.get("witness_set") or {}).get("top") or []
                st["witness"].append({
                    "key": key, "halted": sg.get("halted"), "alert": sg.get("alert"),
                    "votes_recorded": sg.get("votes_recorded"),
                    "votes_in_chain": len(chain),
                    "last_vote_target": max((v.get("target_height") or 0 for v in chain), default=None),
                    "weight": next((w.get("weight") for w in top if w.get("key") == key), None)})
    else:
        st["rpc_error"] = info.get("error") if isinstance(info, dict) else str(info)
    # Second sample: is the tip advancing, is the miner hashing?
    if a.sample_secs > 0 and st["rpc_ok"]:
        time.sleep(a.sample_secs)
        later = miners(v1_port)
        before = {m["pid"]: m.get("cpu_ticks") for m in st["miner_processes"]}
        tick = os.sysconf("SC_CLK_TCK")
        for m in st["miner_processes"]:
            after = next((x.get("cpu_ticks") for x in later if x["pid"] == m["pid"]), None)
            if after is not None and before.get(m["pid"]) is not None:
                m["cpu_cores_busy"] = round((after - before[m["pid"]]) / tick / a.sample_secs, 2)
        dag2 = rpc(a.rpc_port, "getdaginfo") or {}
        st["tip_later"] = dag2.get("tip_height") if isinstance(dag2, dict) else None
        st["sample_secs"] = a.sample_secs
    st["listening"] = listening(ports)
    st["stratum_ports"] = [v1_port, v2_port]
    st["metrics"] = node_metrics(a.metrics_port)
    st["stratum_v2_key"] = v2_public(a.v2_key)
    st["ufw"] = ufw_rules()
    if not a.no_units:
        code, _ = sh(["nft", "list", "table", "inet", "gnb_explorer"]) if os.geteuid() == 0 else (127, "")
        st["explorer_nft_table"] = None if code == 127 else code == 0
        _, ntp = sh(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        st["ntp_synchronized"] = ntp == "yes" if ntp else None

    for p in st["node_processes"]:
        print(f"node pid {p['pid']}: stratum V1={p['stratum']} V2={p['stratum_v2']} witness={p['witness']} "
              f"mine={p['mine']} os_threads={p['threads']} peers={p['peers']}")
    for m in st["miner_processes"]:
        print(f"cpu miner pid {m['pid']}: threads={m['threads']} busy_cores={m.get('cpu_cores_busy')} url={m['url']} user={m['user']}")
    for w in st.get("witness") or []:
        print(f"witness {w['key']}: weight={w['weight']} votes_in_chain={w['votes_in_chain']} last_target={w['last_vote_target']} halted={w['halted']}")
    if st["rpc_ok"]:
        n = st["network"]
        f = st.get("finality") or {}
        print(f"chain_id {n['chain_id']} {n['network']} blocks={n['blocks']} peers={n['peers']} "
              f"tip_height={st['tip']['tip_height']} finalized={f.get('pin_height')} genesis={st['genesis']}")
    else:
        print(f"RPC on 127.0.0.1:{a.rpc_port} not answering: {st.get('rpc_error')}")
    if st["stratum_v2_key"]:
        print(f"stratum V2 authority key {st['stratum_v2_key']['public_b58']}")
    print("OBB-STATUS " + json.dumps(st, sort_keys=True))


if __name__ == "__main__":
    main()
