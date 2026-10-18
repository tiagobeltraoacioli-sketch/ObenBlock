"""ObenBlock presentation of the explorer API (docs/DESIGN-obenblock.md §2, §4,
§6): obb1 addresses, SHA-256d difficulty and block ids, PoWit finality, the
RPC port and the OBB_* configuration. Standard library only, no node:

    python3 deploy/explorer-api/test_obenblock_explorer_api.py -v
"""

import hashlib
import importlib.util
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "gnb_explorer_api.py")


def load(**env):
    """A fresh copy of the module with `env` set while it is imported."""
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location(f"api_{len(env)}_{id(env)}", PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


api = load()


def legacy(prefix, payload):
    """A legacy address: a policy checksum covers the prefix, a key one not."""
    body = (prefix.encode() if len(payload) == 32 else b"") + payload
    return prefix + (payload + hashlib.sha3_256(hashlib.sha3_256(body).digest()).digest()[:4]).hex()


H20 = bytes(range(20))
H32 = bytes(range(32))
CHAIN_HASH = "11" * 32
MERGER_HASH = "22" * 32
BLUE_HASH = "33" * 32


class FakeNode:
    """Answers of an ObenBlock node: tip 120, PoWit finalized through 100."""

    def __init__(self, finalized=100):
        self.calls = []
        self.finalized = finalized

    def __call__(self, method, params):
        self.calls.append((method, params))
        miner = legacy("gnb1q", H20)
        if method == "getpowitinfo":
            fin = None if self.finalized is None else {"slot": 96, "hash": CHAIN_HASH, "block_height": self.finalized}
            return {"result": {"pow": "gnb-smh-v3", "tip_height": 120, "finalized": fin,
                               "justified": {"slot": 112, "hash": MERGER_HASH, "block_height": 112}}}
        if method == "getblockdag":
            h = params[0]
            if h == MERGER_HASH:
                return {"result": {"hash": h, "height": 90, "colour": "chain", "bits": "0x1d00ffff"}}
            if h == BLUE_HASH:
                return {"result": {"hash": h, "height": 89, "colour": "blue", "merged_by": MERGER_HASH,
                                   "bits": "0x1c00ffff"}}
            return {"result": {"hash": h, "height": 101, "colour": "chain", "bits": "0x1d00ffff",
                               "difficulty": 123.0, "transactions": [{"outputs": [{"address": miner}]}]}}
        if method == "getselectedchain":
            return {"result": {"chain_length": 121, "blocks": [
                {"hash": CHAIN_HASH, "height": 100, "bits": "0x1d00ffff", "miner": miner},
                {"hash": MERGER_HASH, "height": 101, "bits": "0x1b0404cb", "miner": miner}]}}
        if method == "getaddresshistory":
            return {"result": {"address": params[0], "items": [{"txid": "aa" * 32, "height": 100},
                                                               {"txid": "bb" * 32, "height": 101}]}}
        if method == "gettransactionfull":
            colour = {"aa" * 32: "chain", "bb" * 32: "blue", "cc" * 32: "pending"}[params[0]]
            block = {"chain": CHAIN_HASH, "blue": BLUE_HASH, "pending": "44" * 32}[colour]
            return {"result": {"status": "confirmed", "block_hash": block, "block_height": 99,
                               "block_colour": colour, "transaction": {"outputs": [{"address": miner}]}}}
        if method == "getdaginfo":
            return {"result": {"tip_height": 120}}
        if method == "getnetworkinfo":
            return {"result": {"chain": "gnb", "chain_id": "0x4f420001", "network": "mainnet"}}
        if method == "getdifficultyhistory":
            return {"result": {"points": [{"height": 1, "bits": 0x1d00ffff, "bits_hex": "0x1d00ffff"}]}}
        if method == "getrichlist":
            return {"result": {"items": [{"address": legacy("gnb1m", H32)}, {"address": miner}]}}
        return {"result": {}}


class Presentation(unittest.TestCase):
    def setUp(self):
        api._cache.clear()
        self.node = FakeNode()
        api.rpc = self.node

    def view(self, name, params=()):
        params = list(params)
        return api.present(name, params, api.rpc(name, params))["result"]

    def test_defaults_are_obenblock(self):
        self.assertTrue(api.OBENBLOCK)
        self.assertEqual(api.RPC_URL, "http://127.0.0.1:18210/")
        self.assertEqual(api.Handler.server_version, "obenblock-explorer-api")

    def test_obb_and_gnb_names_and_rpc_url(self):
        gnb = load(OBB_CHAIN="gnb")
        self.assertFalse(gnb.OBENBLOCK)
        self.assertEqual(gnb.RPC_URL, "http://127.0.0.1:17210/")
        self.assertEqual(gnb.present("getblockdag", [], {"result": {"miner": legacy("gnb1q", H20)}}),
                         {"result": {"miner": legacy("gnb1q", H20)}}, "a GnB API shows answers unchanged")
        with self.assertRaises(ValueError):
            gnb.ADDRESS(legacy("obb1q", H20))
        # OBB_* wins over GNB_*.
        both = load(OBB_RPC_URL="http://127.0.0.1:1/", GNB_RPC_URL="http://127.0.0.1:2/")
        self.assertEqual(both.RPC_URL, "http://127.0.0.1:1/")
        self.assertEqual(load(GNB_RPC_URL="http://127.0.0.1:3/").RPC_URL, "http://127.0.0.1:3/")
        r = subprocess.run([sys.executable, "-I", "-c", "import runpy; runpy.run_path(%r)" % PATH],
                           env={"OBB_CHAIN": "bitcoin", "PATH": os.environ.get("PATH", "")},
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("OBB_CHAIN must be obenblock or gnb", r.stderr)

    def test_address_gate_accepts_obb_gnb_and_bloch_forms(self):
        for a in (legacy("obb1q", H20), legacy("obb1t", H20), legacy("gnb1q", H20), "bloch1q" + legacy("gnb1q", H20)[5:],
                  legacy("obb1m", H32), legacy("gnb1n", H32)):
            with self.subTest(address=a):
                self.assertEqual(api.ADDRESS(a), a)
        for a in ("obb1x" + "00" * 24, "bloch1m" + "00" * 36, legacy("obb1q", H20) + "0", "OBB1Q" + "00" * 24):
            with self.subTest(address=a), self.assertRaises(ValueError):
                api.ADDRESS(a)

    def test_legacy_strings_are_shown_as_obb_with_the_right_checksum(self):
        self.assertEqual(api.obb_address(legacy("gnb1q", H20)), legacy("obb1q", H20))
        self.assertEqual(api.obb_address(legacy("gnb1t", H20)), legacy("obb1t", H20))
        self.assertEqual(api.obb_address(legacy("gnb1m", H32)), legacy("obb1m", H32))
        self.assertEqual(api.obb_address(legacy("gnb1n", H32)), legacy("obb1n", H32))
        self.assertNotEqual(legacy("gnb1m", H32)[-8:], legacy("obb1m", H32)[-8:], "policy checksum covers the prefix")
        bad = legacy("gnb1m", H32)[:-1] + ("0" if legacy("gnb1m", H32)[-1] != "0" else "1")
        self.assertEqual(api.obb_address(bad), bad, "a bad checksum is not laundered into a valid one")
        for a in (legacy("gnb1q", H20), legacy("gnb1m", H32), legacy("gnb1n", H32)):
            self.assertEqual(api.gnb_address(api.obb_address(a)), a)
        self.assertEqual(api.gnb_address("bloch1t" + legacy("gnb1t", H20)[5:]), legacy("gnb1t", H20))
        self.assertEqual(api.obb_address("not an address"), "not an address")

    def test_sha256d_difficulty_and_pow_hash(self):
        self.assertEqual(api.sha256d_difficulty("0x1d00ffff"), 1.0)
        self.assertEqual(api.sha256d_difficulty(0x1d00ffff), 1.0)
        # Bitcoin block 32256 (bits 0x1d00d86a): difficulty 1.18.
        self.assertAlmostEqual(api.sha256d_difficulty("0x1d00d86a"), 1.182899534312841, places=12)
        self.assertAlmostEqual(api.sha256d_difficulty("0x1c00ffff"), 256.0)
        for bad in ("0x1d80ffff", "0x00000000", "zz", None, True, 2**32):
            self.assertIsNone(api.sha256d_difficulty(bad), bad)
        self.assertEqual(api.pow_hash("00" * 31 + "ff"), "ff" + "00" * 31)
        self.assertIsNone(api.pow_hash("xyz"))

    def test_block_answers(self):
        b = self.view("getblockdag", [CHAIN_HASH])
        self.assertEqual(b["pow"], "sha256d")
        self.assertEqual(b["difficulty"], 1.0, "Bitcoin scale, not the node's GnB-SMH figure")
        self.assertEqual(b["pow_hash"], bytes.fromhex(CHAIN_HASH)[::-1].hex())
        self.assertEqual(b["finality"], "pending", "height 101 > finalized 100")
        self.assertEqual(b["finalized_height"], 100)
        self.assertEqual(b["transactions"][0]["outputs"][0]["address"], legacy("obb1q", H20))
        blue = self.view("getblockdag", [BLUE_HASH])
        self.assertEqual(blue["finality"], "finalized", "merged by chain block 90 <= 100")
        self.assertEqual(blue["difficulty"], 256.0)
        g = self.view("getblock", [CHAIN_HASH, False])
        self.assertEqual(g["pow"], "sha256d")

    def test_chain_history_and_transactions(self):
        c = self.view("getselectedchain", [0, 2])
        self.assertEqual([b["finality"] for b in c["blocks"]], ["finalized", "pending"])
        self.assertEqual(c["blocks"][0]["miner"], legacy("obb1q", H20))
        self.assertEqual(c["blocks"][0]["difficulty"], 1.0)
        h = self.view("getaddresshistory", [legacy("obb1q", H20), 25, 0])
        self.assertEqual([i["finality"] for i in h["items"]], ["finalized", "pending"])
        self.assertEqual(self.view("gettransactionfull", ["aa" * 32])["finality"], "finalized")
        self.assertEqual(self.view("gettransactionfull", ["bb" * 32])["finality"], "finalized",
                         "a merged block is final when its merging chain block is")
        self.assertEqual(self.view("gettransactionfull", ["cc" * 32])["finality"], "off-chain")
        d = self.view("getdaginfo")
        self.assertEqual((d["finalized_height"], d["finalized_hash"], d["justified_height"]), (100, CHAIN_HASH, 112))
        rich = self.view("getrichlist", [100, 0])
        self.assertEqual([i["address"] for i in rich["items"]], [legacy("obb1m", H32), legacy("obb1q", H20)])

    def test_no_finality_yet_is_not_claimed(self):
        self.node.finalized = None
        self.assertIsNone(self.view("getblockdag", [CHAIN_HASH])["finality"])
        self.assertIsNone(self.view("getselectedchain", [0, 2])["blocks"][0]["finality"])
        self.assertIsNone(self.view("getdaginfo")["finalized_height"])

    def test_network_powit_and_difficulty_history(self):
        n = self.view("getnetworkinfo")
        self.assertEqual((n["chain"], n["network"]), ("obenblock", "mainnet"))
        self.assertEqual(self.view("getpowitinfo")["pow"], "sha256d")
        self.assertEqual(self.view("getdifficultyhistory", [100])["points"][0]["difficulty"], 1.0)

    def test_errors_pass_through(self):
        self.assertEqual(api.present("getblockdag", [], {"error": "not found"}), {"error": "not found"})

    def test_carryover_accepts_obb_and_shows_obb(self):
        saved = dict(api._carry)
        try:
            api._carry.clear()
            api._carry[legacy("gnb1q", H20)] = [5, 1, 7]
            for alias in (legacy("obb1q", H20), legacy("gnb1q", H20), "bloch1q" + legacy("gnb1q", H20)[5:]):
                with self.subTest(alias=alias):
                    r = api.carryover_of(alias)["result"]
                    self.assertEqual((r["address"], r["in_carryover"], r["amount"]), (legacy("obb1q", H20), True, "5"))
            self.assertFalse(api.carryover_of(legacy("obb1t", H20))["result"]["in_carryover"])
        finally:
            api._carry.clear()
            api._carry.update(saved)


if __name__ == "__main__":
    unittest.main()
