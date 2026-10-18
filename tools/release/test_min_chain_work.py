#!/usr/bin/env python3
"""Unit tests of tools/release/min_chain_work.py (no network: fake nodes).

Run: python3 tools/release/test_min_chain_work.py -v
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import min_chain_work as mcw  # noqa: E402


def h(n: int) -> str:
    return f"{n:064x}"


class FakeNode:
    """A node whose selected chain is blocks 0..len-1, block i carrying
    `work(i)` blue work; `extra` blocks are known but off its chain."""

    def __init__(self, length, work=lambda i: 1_000 * i, network="mainnet", minimum=None, syncing=False,
                 fork_at=None):
        self.length, self.work, self.network = length, work, network
        self.minimum, self.syncing = minimum, syncing
        # A node on another chain from `fork_at`: its blocks there have other hashes.
        self.fork_at = fork_at

    def hash_at(self, i):
        return h(i if self.fork_at is None or i < self.fork_at else 10_000_000 + i)

    def __call__(self, method, params=None):
        if method == "getnetworkinfo":
            return {"network": self.network, "syncing": self.syncing, "version": "0.1.3"}
        if method == "getdaginfo":
            d = {"tip": self.hash_at(self.length - 1), "tip_height": self.length - 1,
                 "tip_blue_work": str(self.work(self.length - 1))}
            if self.minimum is not None:
                d["minimum_chain_work"] = str(self.minimum)
            return d
        if method == "getselectedchain":
            offset, count = params
            idx = self.length - 1 - offset
            blocks = [{"hash": self.hash_at(idx), "height": idx}] if idx >= 0 else []
            return {"chain_length": self.length, "offset": offset, "blocks": blocks[:count]}
        if method == "getblockdag":
            for i in range(self.length):
                if self.hash_at(i) == params[0]:
                    return {"hash": params[0], "height": i, "blue_work": str(self.work(i)),
                            "timestamp": 1_791_685_648 + 30 * i, "colour": "chain"}
            return {"hash": params[0], "colour": "pending", "blue_work": "0"}
        raise AssertionError(method)


def run(nodes, depth=10, allow_single=False):
    readings = [mcw.read_node(n, c, depth, "mainnet") for n, c in nodes.items()]
    return mcw.choose(readings, nodes, allow_single)


class RoundDown(unittest.TestCase):
    def test_two_significant_digits_down(self):
        self.assertEqual(mcw.round_down(7_782_451), 7_700_000)
        self.assertEqual(mcw.round_down(12_999_999), 12_000_000)
        self.assertEqual(mcw.round_down(7_000_000), 7_000_000)
        self.assertEqual(mcw.round_down(99), 99)
        self.assertEqual(mcw.round_down(0), 0)
        self.assertEqual(mcw.round_down(10 ** 30 + 5), 10 ** 30)
        with self.assertRaises(ValueError):
            mcw.round_down(-1)


class Choose(unittest.TestCase):
    def test_lower_reading_rounded_down(self):
        # Node b is 3 blocks behind a: its block `depth` below its tip is lower.
        a, b = FakeNode(200, work=lambda i: 7_782 * i + 451), FakeNode(197, work=lambda i: 7_782 * i + 451)
        cand, value, warnings = run({"a": a, "b": b})
        self.assertEqual(cand["name"], "b")
        self.assertEqual(cand["height"], 186)
        self.assertEqual(cand["blue_work"], 7_782 * 186 + 451)
        self.assertEqual(value, 1_400_000)
        self.assertLessEqual(value, cand["blue_work"])
        self.assertEqual(warnings, [])

    def test_two_nodes_are_required(self):
        with self.assertRaisesRegex(mcw.ReadingError, "at least 2"):
            run({"a": FakeNode(100)})
        _, value, _ = run({"a": FakeNode(100)}, allow_single=True)
        self.assertEqual(value, 89_000)

    def test_nodes_on_different_chains_are_refused(self):
        with self.assertRaisesRegex(mcw.ReadingError, "not on one chain"):
            run({"a": FakeNode(100), "b": FakeNode(100, fork_at=50)})

    def test_disagreeing_work_is_refused(self):
        with self.assertRaisesRegex(mcw.ReadingError, "blue work"):
            run({"a": FakeNode(100), "b": FakeNode(100, work=lambda i: 1_001 * i)})

    def test_the_minimum_never_goes_down(self):
        with self.assertRaisesRegex(mcw.ReadingError, "never goes down"):
            run({"a": FakeNode(100, minimum=95_000), "b": FakeNode(100)})
        _, value, _ = run({"a": FakeNode(100, minimum=7_000), "b": FakeNode(100)})
        self.assertEqual(value, 89_000)

    def test_wrong_network_short_chain_and_syncing(self):
        with self.assertRaisesRegex(mcw.ReadingError, "testnet"):
            run({"a": FakeNode(100, network="testnet"), "b": FakeNode(100)})
        with self.assertRaisesRegex(mcw.ReadingError, "none 10 below"):
            run({"a": FakeNode(5), "b": FakeNode(100)})
        _, _, warnings = run({"a": FakeNode(100, syncing=True), "b": FakeNode(100)})
        self.assertEqual(len(warnings), 1)

    def test_report_prints_the_constant_and_hex(self):
        nodes = {"a": FakeNode(9_000, work=lambda i: 860 * i), "b": FakeNode(9_000, work=lambda i: 860 * i)}
        readings = [mcw.read_node(n, c, 2_880, "mainnet") for n, c in nodes.items()]
        cand, value, warnings = mcw.choose(readings, nodes)
        self.assertEqual(value, 5_200_000)
        text = mcw.report(readings, cand, value, 2_880, warnings)
        self.assertIn("pub const MIN_CHAIN_WORK: u128 = 5_200_000;", text)
        self.assertIn("--minimumchainwork 4f5880", text)
        # The assumed-valid block is the same candidate block (P5-G).
        self.assertEqual(cand["height"], 9_000 - 1 - 2_880)
        self.assertIn(f'Some(AssumedValidBlock::from_hex("{cand["hash"]}", {cand["height"]}));', text)
        self.assertIn(f"--assumevalid {cand['hash']}", text)
        # So is the release finality checkpoint (P5-A2, weak subjectivity).
        self.assertIn(f'Some(ReleaseCheckpoint::from_hex("{cand["hash"]}", {cand["height"]}));', text)

    def test_assume_valid_line_refuses_a_malformed_id(self):
        good = {"hash": h(0xABCDEF), "height": 5}
        self.assertIn(h(0xABCDEF), mcw.assume_valid_line(good))
        for bad in [{"hash": h(0xABCDEF).upper(), "height": 5}, {"hash": h(5)[:-2], "height": 5},
                    {"hash": h(5), "height": 0}, {"hash": None, "height": 5}]:
            with self.assertRaises(mcw.ReadingError):
                mcw.assume_valid_line(bad)


class Transport(unittest.TestCase):
    def test_api_key_never_over_plain_http_to_a_remote_host(self):
        with self.assertRaisesRegex(mcw.ReadingError, "loopback"):
            mcw.make_caller("http://203.0.113.5:17210", "k", None)
        mcw.make_caller("http://127.0.0.1:17210", "k", None)
        mcw.make_caller("http://[::1]:17210", "k", None)
        mcw.make_caller("203.0.113.5:17210", None, None)
        with self.assertRaisesRegex(mcw.ReadingError, "http"):
            mcw.make_caller("ftp://x", None, None)

    def test_unreachable_node_is_an_error_not_a_value(self):
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            code = mcw.main(["--rpc", "http://127.0.0.1:9", "--rpc", "http://127.0.0.1:9"])
        self.assertEqual(code, 1)
        self.assertIn("error:", err.getvalue())
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
