#!/usr/bin/env python3
"""Publish ObenBlock's finalized checkpoints to the Bloch anchor registry.

Reference `obenblock-anchor` daemon (docs/OBB-ANCHOR.md). Each run (or each
--interval seconds with --interval):

  1. reads `getfinalityanchors [from_epoch, count]` from every --node-rpc
     (ObenBlock nodes) and requires at least --min-agree of them to answer;
  2. checks every record itself: the 84-byte encoding is rebuilt from the
     fields, the record id, the decoding rules and the chain id;
  3. publishes, oldest first, the epochs every answering node returned with
     identical bytes, after the last epoch it published; a node that answers
     other bytes for an epoch another node returned, or for an epoch already
     published, is an alarm (exit 3) and nothing is published;
  4. records what it published in --state.

Publishers (--publisher):
  dry-run          log the records; the state file is not written
  jsonl:PATH       append each record as one JSON line to PATH (a spool an
                   operator submits by hand until the registry exists)
  command:PATH     run PATH with the record as JSON on stdin; exit 0 and a
                   JSON object on the last stdout line ({"ref": ...}) means
                   published
  bloch            the Bloch registry transaction: pending the registry
                   (exit 5)

Exit codes: 0 done or nothing to do, 2 nodes unavailable, 3 alarm
(disagreeing nodes or a changed record), 4 publisher failed, 5 publisher
not available. Standard library only.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

RECORD_LEN = 84
STATE_KEEP = 64


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, flush=True)


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def encode(chain_id, slot, block_id, finalized_at, w_digest):
    return struct.pack("<IQ", chain_id, slot) + block_id + struct.pack("<Q", finalized_at) + w_digest


class Alarm(Exception):
    pass


class PublisherUnavailable(Exception):
    pass


def check_anchor(a, chain_id):
    """A node's anchor entry -> (epoch, slot, record bytes). Raises ValueError."""
    block_id = bytes.fromhex(a["block_id"])
    wd = bytes.fromhex(a["w_digest"])
    if len(block_id) != 32 or len(wd) != 32:
        raise ValueError("bad hash length")
    slot, fat, epoch = int(a["slot"]), int(a["finalized_at"]), int(a["epoch"])
    if int(a["chain_id"]) != chain_id:
        raise ValueError("record for another chain")
    raw = encode(chain_id, slot, block_id, fat, wd)
    if a["record"] != raw.hex():
        raise ValueError("record bytes do not match its fields")
    if a["record_id"] != sha256d(raw).hex():
        raise ValueError("record id mismatch")
    if block_id == bytes(32) or fat <= slot:
        raise ValueError("record breaks the decoding rules")
    return epoch, slot, raw


def node_anchors(url, from_epoch, count, timeout, api_key=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getfinalityanchors",
                       "params": [from_epoch, count]}).encode()
    headers = {"content-type": "application/json", "user-agent": "obenblock-anchor/1"}
    if api_key:
        headers["x-api-key"] = api_key
    req = urllib.request.Request(url, body, headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        reply = json.loads(r.read(4 * 1024 * 1024))
    res = reply.get("result", reply)
    if not isinstance(res, dict) or "error" in res:
        raise ValueError(f"no result: {str(res)[:200]}")
    chain_id = int(res["chain_id"])
    out = {}
    for a in res["anchors"]:
        epoch, slot, raw = check_anchor(a, chain_id)
        if epoch in out:
            raise ValueError(f"two anchors for epoch {epoch}")
        out[epoch] = (slot, raw)
    return chain_id, out, bool(res.get("complete", True))


def agreed(answers):
    """{url: (chain_id, {epoch: (slot, raw)}, complete)} -> (chain_id, [(epoch, slot, raw)] ascending)."""
    chains = {c for c, _, _ in answers.values()}
    if len(chains) != 1:
        raise Alarm(f"nodes run different chains: {sorted(hex(c) for c in chains)}")
    maps = [m for _, m, _ in answers.values()]
    for e in set().union(*maps):
        seen = {m[e] for m in maps if e in m}
        if len(seen) != 1:
            raise Alarm(f"nodes answer different records for epoch {e}")
    common = set(maps[0]).intersection(*maps[1:])
    return chains.pop(), [(e, *maps[0][e]) for e in sorted(common)]


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(path, state):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".obenblock-anchor-")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def record_obj(chain_id, epoch, slot, raw):
    return {"chain_id": chain_id, "epoch": epoch, "slot": slot, "record": raw.hex(),
            "record_id": sha256d(raw).hex()}


class DryRun:
    persistent = False

    def publish(self, rec):
        log(f"dry run: would publish epoch {rec['epoch']} slot {rec['slot']} record {rec['record_id']}")
        return "dry-run"


class Jsonl:
    persistent = True

    def __init__(self, path):
        self.path = path

    def publish(self, rec):
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return f"jsonl:{self.path}"


class Command:
    persistent = True

    def __init__(self, path):
        self.path = path

    def publish(self, rec):
        p = subprocess.run([self.path], input=json.dumps(rec), capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            raise RuntimeError(f"{self.path} exit {p.returncode}: {p.stderr.strip()[:300]}")
        lines = p.stdout.strip().splitlines()
        out = json.loads(lines[-1]) if lines else {}
        return str(out.get("ref", "command"))


class Bloch:
    persistent = True

    def publish(self, rec):
        raise PublisherUnavailable("the Bloch anchor registry is not deployed yet (docs/OBB-ANCHOR.md); "
                                   "use jsonl:PATH or command:PATH meanwhile")


def make_publisher(spec):
    if spec == "dry-run":
        return DryRun()
    if spec == "bloch":
        return Bloch()
    kind, sep, arg = spec.partition(":")
    if sep and arg and kind == "jsonl":
        return Jsonl(arg)
    if sep and arg and kind == "command":
        return Command(arg)
    raise SystemExit(f"unknown --publisher {spec!r}")


def run_once(a, publisher):
    state = load_state(a.state)
    last_epoch = state.get("last_epoch")
    from_epoch = a.from_epoch if last_epoch is None else max(a.from_epoch, last_epoch + 1)
    # Re-read the last published epoch too, to notice a record that changed.
    ask_from = from_epoch if last_epoch is None else last_epoch
    answers = {}
    for url in a.node_rpc:
        try:
            answers[url] = node_anchors(url, ask_from, a.count, a.timeout, a.api_key)
        except Exception as e:  # one node down is fine, if enough remain
            log(f"node {url}: {e}")
    if len(answers) < a.min_agree:
        log(f"only {len(answers)} of {len(a.node_rpc)} nodes answered (need {a.min_agree})")
        return 2
    try:
        chain_id, recs = agreed(answers)
        if state.get("chain_id") not in (None, chain_id):
            raise Alarm(f"nodes run chain {chain_id:#x}, the state file belongs to {state['chain_id']:#x}")
        published = {int(p["epoch"]): p["record"] for p in state.get("published", [])}
        for e, _, raw in recs:
            if e in published and published[e] != raw.hex():
                raise Alarm(f"the record for epoch {e} changed since it was published")
    except Alarm as e:
        log(f"ALARM: {e}")
        return 3
    todo = [(e, s, raw) for e, s, raw in recs if e >= from_epoch]
    if todo and todo[0][0] > from_epoch and not all(c for _, _, c in answers.values()):
        # The node walks back a bounded number of finalized checkpoints
        # (docs/OBB-ANCHOR.md): older epochs stay unpublished.
        log(f"gap: epochs {from_epoch}..{todo[0][0] - 1} are beyond the nodes' read budget and are skipped")
    if not todo:
        log(f"nothing new (next epoch {from_epoch})")
        return 0
    for e, s, raw in todo:
        rec = record_obj(chain_id, e, s, raw)
        try:
            ref = publisher.publish(rec)
        except PublisherUnavailable as x:
            log(f"publisher unavailable: {x}")
            return 5
        except Exception as x:
            log(f"publishing epoch {e} failed: {x}")
            return 4
        log(f"published epoch {e} slot {s} record {rec['record_id']} ({ref})")
        if publisher.persistent:
            state["chain_id"] = chain_id
            state["last_epoch"] = e
            state["published"] = (state.get("published", []) + [{**rec, "ref": ref, "at": int(time.time())}])[-STATE_KEEP:]
            save_state(a.state, state)
    return 0


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--node-rpc", required=True, help="comma-separated ObenBlock node JSON-RPC URLs")
    ap.add_argument("--min-agree", type=int, default=1, help="nodes that must answer (all answers must agree)")
    ap.add_argument("--state", required=True, help="state file (published records)")
    ap.add_argument("--publisher", default="dry-run", help="dry-run | jsonl:PATH | command:PATH | bloch")
    ap.add_argument("--from-epoch", type=int, default=0, help="first epoch to publish on a fresh state")
    ap.add_argument("--count", type=int, default=8, help="anchors asked per node per run (at most 32)")
    ap.add_argument("--interval", type=float, default=0, help="run every this many seconds (0: once)")
    ap.add_argument("--timeout", type=float, default=30.0)
    a = ap.parse_args(argv)
    a.node_rpc = [u.strip() for u in a.node_rpc.split(",") if u.strip()]
    if a.min_agree < 1 or a.min_agree > len(a.node_rpc):
        ap.error("--min-agree must be between 1 and the number of --node-rpc URLs")
    a.count = max(1, min(a.count, 32))
    a.api_key = None
    key_file = os.environ.get("OBB_RPC_API_KEY_FILE")
    if key_file:
        with open(key_file) as f:
            a.api_key = f.read().strip()
    return a


def main(argv=None):
    a = parse_args(argv)
    publisher = make_publisher(a.publisher)
    if a.interval <= 0:
        return run_once(a, publisher)
    while True:
        code = run_once(a, publisher)
        if code in (3, 5):
            return code
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
