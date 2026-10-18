#!/usr/bin/env python3
"""Tests of scripts/obenblock-anchor.py against fake ObenBlock nodes.

The daemon's record encoder is checked against the reference vectors
(reference/obb_anchor_vectors.json); each run talks to local HTTP servers
that answer `getfinalityanchors`.

Run: python3 scripts/test_obenblock_anchor.py
"""

import http.server
import importlib.util
import json
import os
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


daemon = load("obenblock_anchor", os.path.join(HERE, "obenblock-anchor.py"))
CHAIN = 0x4F420001


def anchor(epoch, slot, block_byte, chain=CHAIN):
    block_id, wd = bytes([block_byte]) * 32, bytes([7]) * 32
    raw = daemon.encode(chain, slot, block_id, slot + 125, wd)
    return {"chain_id": chain, "epoch": epoch, "slot": slot, "block_id": block_id.hex(),
            "finalized_at": slot + 125, "w_digest": wd.hex(), "record": raw.hex(),
            "record_id": daemon.sha256d(raw).hex()}


class FakeNode:
    """A node RPC answering `getfinalityanchors` from `self.anchors`."""

    def __init__(self, anchors, chain=CHAIN):
        self.anchors, self.chain, self.calls = anchors, chain, []
        node = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["content-length"])))
                node.calls.append(req)
                frm = req["params"][0]
                res = {"chain_id": node.chain, "complete": True,
                       "anchors": [a for a in node.anchors if a["epoch"] >= frm]}
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}).encode()
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Daemon(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.dir.name, "state.json")
        self.spool = os.path.join(self.dir.name, "spool.jsonl")
        self.nodes = []

    def tearDown(self):
        for n in self.nodes:
            n.close()
        self.dir.cleanup()

    def node(self, anchors, chain=CHAIN):
        n = FakeNode(anchors, chain)
        self.nodes.append(n)
        return n

    def run_daemon(self, *extra, nodes=None, publisher=None):
        urls = ",".join(n.url for n in (nodes or self.nodes))
        return daemon.main(["--node-rpc", urls, "--state", self.state,
                            "--publisher", publisher or f"jsonl:{self.spool}", *extra])

    def spooled(self):
        try:
            with open(self.spool) as f:
                return [json.loads(line) for line in f]
        except FileNotFoundError:
            return []

    def test_encoder_matches_the_reference_vectors(self):
        with open(os.path.join(ROOT, "reference", "obb_anchor_vectors.json")) as f:
            vectors = json.load(f)
        for c in vectors["records"]:
            raw = daemon.encode(c["chain_id"], c["slot"], bytes.fromhex(c["block_id"]), c["finalized_at"],
                                bytes.fromhex(c["w_digest"]))
            self.assertEqual(raw.hex(), c["record"], c["name"])
            self.assertEqual(daemon.sha256d(raw).hex(), c["record_id"], c["name"])

    def test_publishes_new_epochs_once_oldest_first(self):
        n = self.node([anchor(0, 60, 1), anchor(1, 780, 2)])
        self.assertEqual(self.run_daemon(), 0)
        self.assertEqual([r["epoch"] for r in self.spooled()], [0, 1])
        self.assertEqual(self.run_daemon(), 0, "nothing new")
        self.assertEqual(len(self.spooled()), 2)
        self.assertEqual(n.calls[-1]["params"][0], 1, "re-reads the last published epoch")
        n.anchors.append(anchor(3, 2220, 3))
        self.assertEqual(self.run_daemon(), 0)
        self.assertEqual([r["epoch"] for r in self.spooled()], [0, 1, 3])
        with open(self.state) as f:
            st = json.load(f)
        self.assertEqual((st["last_epoch"], st["chain_id"]), (3, CHAIN))

    def test_only_epochs_every_node_returned_are_published(self):
        a = self.node([anchor(0, 60, 1), anchor(1, 780, 2)])
        b = self.node([anchor(0, 60, 1)])
        self.assertEqual(self.run_daemon("--min-agree", "2"), 0)
        self.assertEqual([r["epoch"] for r in self.spooled()], [0])
        self.assertTrue(a.calls and b.calls)

    def test_disagreeing_nodes_are_an_alarm(self):
        self.node([anchor(0, 60, 1)])
        self.node([anchor(0, 60, 9)])
        self.assertEqual(self.run_daemon(), 3)
        self.assertEqual(self.spooled(), [])

    def test_a_changed_published_record_is_an_alarm(self):
        n = self.node([anchor(0, 60, 1)])
        self.assertEqual(self.run_daemon(), 0)
        n.anchors = [anchor(0, 60, 9), anchor(1, 780, 2)]
        self.assertEqual(self.run_daemon(), 3)
        self.assertEqual(len(self.spooled()), 1)

    def test_a_forged_record_is_refused(self):
        bad = anchor(0, 60, 1)
        bad["record"] = bad["record"][:-2] + "00"
        self.node([bad])
        self.assertEqual(self.run_daemon(), 2, "the only node's answer is refused")
        self.assertEqual(self.spooled(), [])

    def test_nodes_down(self):
        n = self.node([anchor(0, 60, 1)])
        n.close()
        self.nodes.remove(n)
        self.assertEqual(daemon.main(["--node-rpc", n.url, "--state", self.state, "--timeout", "2"]), 2)

    def test_dry_run_writes_no_state_and_bloch_is_pending(self):
        self.node([anchor(0, 60, 1)])
        self.assertEqual(self.run_daemon(publisher="dry-run"), 0)
        self.assertFalse(os.path.exists(self.state))
        self.assertEqual(self.run_daemon(publisher="bloch"), 5)
        self.assertFalse(os.path.exists(self.state))


if __name__ == "__main__":
    unittest.main()
