#!/usr/bin/env python3
"""Anchor the Bloch finalized checkpoint in a GnB-SMH transaction, once per run.

Run it from a timer (deploy/bloch-anchor.timer). Each run:

  1. reads `getchaininfo` from every --bloch-rpc and requires at least
     --min-agree of them to answer and ALL answers to agree on the
     finalized checkpoint (epoch, root, finalized_height);
  2. refuses a checkpoint older than the last one it anchored (finality
     never goes backwards; that is an alarm, exit 3);
  3. waits while its previous anchor is still unconfirmed;
  4. anchors when the finalized epoch is at least --every-epochs past the
     last anchor: `gnb-cli blochanchor`, and records the txid in --state.

Exit codes: 0 done or nothing to do, 2 Bloch sources unavailable or in
disagreement, 3 finality went backwards, 4 gnb-cli failed.
Standard library only. See docs/BLOCH-ANCHOR.md.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, flush=True)


def bloch_finalized(url, timeout):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getchaininfo", "params": []}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "gnb-bloch-anchor/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        reply = json.load(r)
    if "result" not in reply:
        raise ValueError(f"no result: {str(reply.get('error', reply))[:200]}")
    res = reply["result"]
    fin = res["finalized"]
    root = fin["root"].lower()
    if len(root) != 64 or int(root, 16) == 0:
        raise ValueError(f"bad finalized root {root!r}")
    epoch, height = int(fin["epoch"]), int(res["finalized_height"])
    if epoch > int(res["epoch"]):
        raise ValueError("finalized epoch ahead of the head epoch")
    return {"epoch": epoch, "height": height, "root": root}


def agreed_checkpoint(urls, min_agree, timeout):
    seen = {}
    for url in urls:
        try:
            cp = bloch_finalized(url, timeout)
        except Exception as e:  # one source down is fine, if enough remain
            log(f"bloch source {url}: {e}")
            continue
        seen[url] = cp
        log(f"bloch source {url}: finalized epoch {cp['epoch']} height {cp['height']} root {cp['root']}")
    if len(seen) < min_agree:
        log(f"only {len(seen)} of {len(urls)} bloch sources answered (need {min_agree})")
        return None
    distinct = {(c["epoch"], c["height"], c["root"]) for c in seen.values()}
    if len(distinct) != 1:
        # Sources one epoch apart are normal right at a boundary: retry next run.
        log(f"bloch sources disagree: {sorted(distinct)}")
        return None
    return next(iter(seen.values()))


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(path, state):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".bloch-anchor-")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def gnb_cli(args, cli, extra):
    p = subprocess.run([cli, *extra, *args], capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        raise RuntimeError(f"gnb-cli {args[0]} exit {p.returncode}: {p.stderr.strip() or p.stdout.strip()}")
    return json.loads(p.stdout.strip().splitlines()[-1])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bloch-rpc", required=True, help="comma-separated Bloch JSON-RPC URLs")
    ap.add_argument("--min-agree", type=int, default=2, help="sources that must answer (all answers must agree)")
    ap.add_argument("--wallet", required=True, help="anchoring keystore (password: GNB_WALLET_PASSWORD_FILE)")
    ap.add_argument("--state", required=True, help="state file (last anchored checkpoint)")
    ap.add_argument("--every-epochs", type=int, default=4, help="anchor when finality advanced this many epochs")
    ap.add_argument("--gnb-cli", default="gnb-cli")
    ap.add_argument("--gnb-cli-arg", action="append", default=[],
                    help="extra gnb-cli option, repeatable (e.g. --gnb-cli-arg=--rpc-port --gnb-cli-arg=17210)")
    ap.add_argument("--fee", default=None, help="fee in GSMH (default: gnb-cli's, raised to the minimum)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--dry-run", action="store_true", help="build and print, do not broadcast or save")
    a = ap.parse_args()

    urls = [u.strip() for u in a.bloch_rpc.split(",") if u.strip()]
    if a.min_agree < 1 or a.min_agree > len(urls):
        sys.exit("--min-agree must be between 1 and the number of --bloch-rpc URLs")

    cp = agreed_checkpoint(urls, a.min_agree, a.timeout)
    if cp is None:
        return 2

    state = load_state(a.state)
    last = state.get("last")
    force = False
    if last:
        if cp["epoch"] < last["epoch"] or (cp["epoch"] == last["epoch"] and cp["root"] != last["root"]):
            log(f"ALARM: finalized checkpoint went backwards or changed: anchored {last}, now {cp}")
            return 3
        pending = state.get("pending_txid")
        if pending:
            try:
                v = gnb_cli(["blochcheckanchor", pending, "--min-conf", "1"], a.gnb_cli, a.gnb_cli_arg)
            except Exception as e:
                log(f"check of pending anchor {pending} failed: {e}")
                return 4
            if v.get("ok"):
                log(f"anchor {pending} confirmed at GnB height {v['block_height']}")
                state.pop("pending_txid")
                save_state(a.state, state)
            elif v.get("in_mempool"):
                log(f"anchor {pending} still in the mempool; waiting")
                return 0
            elif "not found" in str(v.get("reason")):
                # Dropped (expired or replaced): anchor the current checkpoint now.
                log(f"anchor {pending} was dropped; anchoring again")
                force = True
            else:
                log(f"cannot check pending anchor {pending}: {v.get('reason')}")
                return 4
        if not force and cp["epoch"] < last["epoch"] + a.every_epochs:
            log(f"finalized epoch {cp['epoch']}; next anchor at epoch {last['epoch'] + a.every_epochs}")
            return 0

    args = ["blochanchor", a.wallet, str(cp["epoch"]), str(cp["height"]), cp["root"]]
    if a.fee:
        args += ["--fee", a.fee]
    if a.dry_run:
        args.append("--dry-run")
    try:
        out = gnb_cli(args, a.gnb_cli, a.gnb_cli_arg)
    except Exception as e:
        log(f"anchor failed: {e}")
        return 4
    if a.dry_run:
        log(f"dry run: would anchor epoch {cp['epoch']} as tx {out['anchor_txid']} (fee {out['fee']} sats)")
        return 0
    log(f"anchored epoch {cp['epoch']} height {cp['height']} root {cp['root']} in tx {out['anchor_txid']} "
        f"(fee {out['fee']} sats)")
    state["last"] = {**cp, "txid": out["anchor_txid"], "at": int(time.time())}
    state["pending_txid"] = out["anchor_txid"]
    save_state(a.state, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
