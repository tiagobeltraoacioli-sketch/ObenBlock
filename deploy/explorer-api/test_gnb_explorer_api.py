"""Tests for gnb_explorer_api.py (audit WAL-2, WAL-4). Standard library only:

    python3 -m unittest deploy/explorer-api/test_gnb_explorer_api.py
"""

import http.client
import importlib.util
import json
import os
import re
import socket
import stat
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gnb_explorer_api", os.path.join(HERE, "gnb_explorer_api.py"))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

KEY = "k" * 40


class ApiServer:
    def __init__(self, max_connections=4, timeout=1.0, deadline=2.0):
        api.API_KEY = KEY.encode()
        api.Handler.timeout = timeout
        api.Handler.deadline = deadline
        api.rpc = lambda method, params: {"result": {"method": method, "params": params}}
        self.httpd = api.make_server("127.0.0.1", 0, max_connections)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def get(self, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path, headers={"x-gnb-key": KEY, **(headers or {})})
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r.status, json.loads(body) if body else None

    def post(self, path, body, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", path, body=body.encode(),
                     headers={"x-gnb-key": KEY, "content-type": "application/json", **(headers or {})})
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, json.loads(data) if data else None


class ExplorerApiTests(unittest.TestCase):
    def setUp(self):
        api._cache.clear()
        api.GET_LIMIT = api.RateLimiter(1000)
        api.POST_LIMIT = api.RateLimiter(1000)
        if hasattr(api, "ByteBudget"):
            api.POST_BYTES = api.ByteBudget(10**9)
        if hasattr(api, "CROSS_SITE_LIMIT"):
            api.CROSS_SITE_LIMIT = api.RateLimiter(10**6, max_clients=1)
        self.server = ApiServer()

    def tearDown(self):
        self.server.close()

    def test_requires_the_shared_key(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=5)
        conn.request("GET", "/v1/getblockcount", headers={"x-gnb-key": "wrong"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()
        status, doc = self.server.get("/v1/getblockcount")
        self.assertEqual(status, 200)
        self.assertEqual(doc["result"]["method"], "getblockcount")

    def test_getrawtransaction_is_allowed_with_a_hash_only(self):
        status, _ = self.server.get('/v1/getrawtransaction?p=["' + "ab" * 32 + '"]')
        self.assertEqual(status, 200)
        status, _ = self.server.get('/v1/getrawtransaction?p=["<script>"]')
        self.assertEqual(status, 400)
        status, _ = self.server.get("/v1/getdifficultyhistory?p=[500]")
        self.assertEqual(status, 400, "the node caps difficulty history at 100")

    def test_allow_list_matches_the_node_rpc(self):
        """Audit P4 / NET-12: every allowed method exists in the node's RPC
        dispatcher (KNOWN_RPC_METHODS), the Worker's cache table names no
        method the API does not serve, and the rich-list offset bound is the
        node's MAX_RICHLIST_OFFSET."""
        root = os.path.dirname(os.path.dirname(HERE))
        with open(os.path.join(root, "node", "src", "rpc", "mod.rs"), encoding="utf-8") as fh:
            src = fh.read()
        block = src[src.index("const KNOWN_RPC_METHODS"):]
        block = block[:block.index("];")]
        known = set(re.findall(r'"([a-z_]+)"', block))
        self.assertTrue(set(api.ALLOWED) <= known, sorted(set(api.ALLOWED) - known))
        with open(os.path.join(root, "worker", "index.js"), encoding="utf-8") as fh:
            worker = fh.read()
        ttl = worker[worker.index("const TTL = {"):]
        ttl = ttl[:ttl.index("};")]
        cached = set(re.findall(r"([a-z]+):\s*\d+", ttl))
        self.assertTrue(cached <= set(api.ALLOWED) | {"carryover"}, sorted(cached - set(api.ALLOWED)))
        with open(os.path.join(root, "node", "src", "analytics", "mod.rs"), encoding="utf-8") as fh:
            m = re.search(r"pub const MAX_RICHLIST_OFFSET: usize = ([0-9_]+);", fh.read())
        node_max = int(m.group(1).replace("_", ""))
        self.assertEqual(api.ALLOWED["getrichlist"][0][1](node_max), node_max)
        with self.assertRaises(ValueError):
            api.ALLOWED["getrichlist"][0][1](node_max + 1)
        status, _ = self.server.get("/v1/getrichlist?p=[100,10001]")
        self.assertEqual(status, 400)

    def test_idle_connection_is_closed_by_the_handler_timeout(self):
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=10)
        start = time.monotonic()
        data = s.recv(1024)  # send nothing: the server must hang up
        elapsed = time.monotonic() - start
        s.close()
        self.assertEqual(data, b"")
        self.assertLess(elapsed, 5)

    def test_slow_drip_client_hits_the_absolute_deadline(self):
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=10)
        start = time.monotonic()
        s.sendall(b"GET /v1/getblockcount HTTP/1.1\r\n")
        closed = False
        while time.monotonic() - start < 8:
            try:
                s.sendall(b"x-drip: 1\r\n")
            except OSError:
                closed = True
                break
            time.sleep(0.5)
            s.setblocking(False)
            try:
                if s.recv(1024) == b"":
                    closed = True
                    break
            except BlockingIOError:
                pass
            finally:
                s.setblocking(True)
        s.close()
        self.assertTrue(closed, "a dripping client must be cut off at the deadline")
        self.assertLess(time.monotonic() - start, 6)

    def test_connections_beyond_the_cap_are_refused(self):
        idle = [socket.create_connection(("127.0.0.1", self.server.port), timeout=5) for _ in range(4)]
        time.sleep(0.2)
        extra = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        reply = extra.recv(1024)
        self.assertTrue(reply.startswith(b"HTTP/1.1 503"), reply)
        extra.close()
        for s in idle:
            s.close()
        time.sleep(1.5)  # slots are released once the idle sockets are gone
        status, _ = self.server.get("/v1/getblockcount")
        self.assertEqual(status, 200)

    def test_rate_limit_is_per_original_client(self):
        api.GET_LIMIT = api.RateLimiter(2)
        a = {"x-gnb-client-ip": "198.51.100.7"}
        b = {"x-gnb-client-ip": "203.0.113.9"}
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 200)
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 200)
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 429)
        self.assertEqual(self.server.get("/v1/getblockcount", b)[0], 200)

    # ── B1-T10 / B2-T4: limiter keyed by allocation, never fails closed ──────

    def test_ipv6_clients_are_keyed_by_their_64(self):
        """One IPv6 /64 is one client: rotating the source address inside it
        no longer mints fresh clients (the previous per-/128 key let 100 of
        100 broadcasts through where one client gets 6)."""
        api.POST_LIMIT = api.RateLimiter(6)
        body = json.dumps({"hex": "ab" * 100})
        ok = 0
        for i in range(100):
            status, _ = self.server.post("/v1/sendrawtransaction", body,
                                         {"x-gnb-client-ip": f"2001:db8:1:2::{i:x}"})
            ok += status == 200
        self.assertEqual(ok, 6)
        # Another /64 (same /48) is another client; IPv4 is keyed per address.
        status, _ = self.server.post("/v1/sendrawtransaction", body, {"x-gnb-client-ip": "2001:db8:1:3::1"})
        self.assertEqual(status, 200)
        self.assertEqual(api.client_key("2001:db8:1:2:ffff:ffff:ffff:ffff"), api.client_key("2001:db8:1:2::1"))
        self.assertNotEqual(api.client_key("198.51.100.7"), api.client_key("198.51.100.8"))
        self.assertEqual(api.client_key("::ffff:198.51.100.7"), "198.51.100.7")

    def test_a_full_table_never_refuses_a_new_client_and_stays_cheap(self):
        """A table full of one attacker's addresses used to refuse EVERY new
        client for the rest of the minute, rebuilding the whole table under
        the lock on each refusal (about 14 ms at 50,000 entries). Now the
        least recently seen client is evicted in O(1)."""
        limiter = api.RateLimiter(240, max_clients=50_000)
        t0 = 1_000_000.0
        for i in range(50_000):
            self.assertTrue(limiter.allow(api.client_key(f"2001:db8:{i >> 16:x}:{i & 0xffff:x}::1"), now=t0))
        self.assertTrue(limiter.allow(api.client_key("203.0.113.9"), now=t0 + 1),
                        "a first-time visitor must not be refused because the table is full")
        start = time.monotonic()
        refused = sum(not limiter.allow(f"198.18.{i >> 8}.{i & 0xff}", now=t0 + 2) for i in range(2_000))
        elapsed = time.monotonic() - start
        self.assertEqual(refused, 0)
        self.assertLessEqual(len(limiter.windows), 50_000)
        self.assertLess(elapsed, 1.0, f"2,000 checks on a full table took {elapsed:.3f} s")
        # A client still in the table keeps its count: no fresh window.
        busy = api.RateLimiter(2, max_clients=3)
        self.assertTrue(busy.allow("a", now=t0) and busy.allow("a", now=t0))
        self.assertFalse(busy.allow("a", now=t0))
        self.assertTrue(busy.allow("b", now=t0) and busy.allow("c", now=t0))
        self.assertFalse(busy.allow("a", now=t0), "a tracked client keeps its count")
        self.assertTrue(busy.allow("a", now=t0 + 60), "next window")

    def test_requests_are_counted_only_once_validated(self):
        """Unknown methods and invalid parameters are answered before the
        limiter: they can neither use up a client's budget nor occupy a slot
        of the table."""
        api.GET_LIMIT = api.RateLimiter(2)
        a = {"x-gnb-client-ip": "198.51.100.7"}
        for path in ["/v1/zz", "/v1/getblockdag?p=[1]", "/v1/getutxos?p=[\"x\"]", "/v2/getblockcount"]:
            self.assertIn(self.server.get(path, a)[0], (400, 404))
        self.assertEqual(len(api.GET_LIMIT.windows), 0, "no limiter entry for invalid requests")
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 200)
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 200)
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 429)

    def test_broadcasts_are_counted_only_once_validated(self):
        """A malformed broadcast (empty body, no JSON, no hex) is answered 400
        before the limiter: it neither creates a limiter entry nor uses up the
        client's broadcasts (it was counted before the body was checked)."""
        api.POST_LIMIT = api.RateLimiter(2)
        a = {"x-gnb-client-ip": "198.51.100.8"}
        for body in ["", "{", json.dumps({"hex": "zz"}), json.dumps({"hex": "abc"}), json.dumps([1])]:
            self.assertEqual(self.server.post("/v1/sendrawtransaction", body, a)[0], 400, body)
        self.assertEqual(len(api.POST_LIMIT.windows), 0, "no limiter entry for invalid broadcasts")
        tx = json.dumps({"hex": "ab" * 10})
        self.assertEqual([self.server.post("/v1/sendrawtransaction", tx, a)[0] for _ in range(3)], [200, 200, 429])

    def test_broadcast_refuses_non_json_bodies_and_cross_site_requests(self):
        """Re-audit B2-R2-2: the API parsed the body as JSON whatever its
        content type, so a cross-site 'simple request' (text/plain, a form,
        sendBeacon) relayed by a front end was broadcast and charged to the
        visitor. Only application/json is accepted, a request a browser marks
        as cross-site / foreign-origin is refused, and none of it reaches the
        limiter or the node."""
        calls = []
        api.rpc = lambda method, params: calls.append(method) or {"result": {"txid": "00"}}
        api.POST_LIMIT = api.RateLimiter(1000)
        a = {"x-gnb-client-ip": "198.51.100.9"}
        tx = json.dumps({"hex": "ab" * 10})
        for headers in [
            {"content-type": "text/plain;charset=UTF-8"},
            {"content-type": "application/x-www-form-urlencoded"},
            {"content-type": "multipart/form-data; boundary=x"},
            {"content-type": ""},
            {"content-type": "application/json", "origin": "https://evil.example"},
            {"content-type": "application/json", "sec-fetch-site": "cross-site"},
            {"content-type": "application/json", "sec-fetch-site": "same-site"},
        ]:
            status, doc = self.server.post("/v1/sendrawtransaction", tx, {**a, **headers})
            self.assertIn(status, (403, 415), headers)
            self.assertIn("error", doc)
        self.assertEqual(calls, [], "nothing reached the node")
        self.assertEqual(len(api.POST_LIMIT.windows), 0, "refusals use no limiter slot")
        for headers in [{"content-type": "application/json"},
                        {"content-type": "application/json; charset=utf-8"},
                        {"content-type": "application/json", "sec-fetch-site": "same-origin"}]:
            self.assertEqual(self.server.post("/v1/sendrawtransaction", tx, {**a, **headers})[0], 200, headers)
        self.assertEqual(calls, ["sendrawtransaction"] * 3)

    def test_cross_site_reads_share_one_budget(self):
        """Re-audit B2-R2-2, read variant: a page on another site makes each
        of its visitors' browsers send uncached reads, each charged to that
        visitor's own GET budget, so the page got a budget per visitor. A
        read the Worker marks cross-site (X-GnB-Cross-Site: 1) is now also
        charged to one budget all cross-site reads share; same-origin pages
        and non-browser clients keep their own budgets only."""
        self.assertTrue(hasattr(api, "CROSS_SITE_LIMIT"), "a shared cross-site read budget exists")
        api.CROSS_SITE_LIMIT = api.RateLimiter(3, max_clients=1)
        path = "/v1/getblockcount"
        visitors = [{"x-gnb-client-ip": f"198.51.100.{i}", "x-gnb-cross-site": "1"} for i in range(1, 7)]
        self.assertEqual([self.server.get(path, v)[0] for v in visitors], [200, 200, 200, 429, 429, 429],
                         "six visitors of one page share the cross-site budget")
        # The same visitors reading from the site itself (no marker), and a
        # CLI client, are not affected by it.
        for i in range(1, 7):
            self.assertEqual(self.server.get(path, {"x-gnb-client-ip": f"198.51.100.{i}"})[0], 200)
        # A cross-site read still counts against the visitor's own budget.
        api.CROSS_SITE_LIMIT = api.RateLimiter(10**6, max_clients=1)
        api.GET_LIMIT = api.RateLimiter(2)
        v = {"x-gnb-client-ip": "203.0.113.5", "x-gnb-cross-site": "1"}
        self.assertEqual([self.server.get(path, v)[0] for _ in range(3)], [200, 200, 429])
        # Only "1" marks a request; anything else is an ordinary read.
        api.CROSS_SITE_LIMIT = api.RateLimiter(1, max_clients=1)
        api.GET_LIMIT = api.RateLimiter(1000)
        self.assertEqual(self.server.get(path, {"x-gnb-client-ip": "203.0.113.6", "x-gnb-cross-site": "0"})[0], 200)
        self.assertEqual(self.server.get(path, {"x-gnb-client-ip": "203.0.113.6", "x-gnb-cross-site": "1"})[0], 200)
        self.assertEqual(self.server.get(path, {"x-gnb-client-ip": "203.0.113.7", "x-gnb-cross-site": "1"})[0], 429)

    def test_broadcast_verification_budget_is_api_wide(self):
        """Every broadcast costs the node signature verification; one byte
        budget for all clients bounds that work whatever the number of
        client addresses."""
        api.POST_BYTES = api.ByteBudget(10_000)
        tx = json.dumps({"hex": "ab" * 4_000})
        statuses = [self.server.post("/v1/sendrawtransaction", tx, {"x-gnb-client-ip": f"198.51.100.{i}"})[0]
                    for i in range(1, 4)]
        self.assertEqual(statuses, [200, 200, 429])
        budget = api.ByteBudget(600)
        self.assertTrue(budget.take(600, now=budget.last))
        self.assertFalse(budget.take(1, now=budget.last))
        self.assertTrue(budget.take(10, now=budget.last + 1), "refills at per_min / 60 per second")

    # ── B2-T3 / B1-T11: parameter windows agree with their clients ──────────

    def test_getutxos_accepts_the_web_wallets_wide_window(self):
        """The web wallet widens a truncated 50-row window to UTXO_WIDE_WINDOW
        rows (site/wallet/core.js); the API refused anything above 50 with a
        400, so the wallet of a miner never showed a balance."""
        root = os.path.dirname(os.path.dirname(HERE))
        with open(os.path.join(root, "site", "wallet", "core.js"), encoding="utf-8") as fh:
            m = re.search(r"export const [^;]*\bUTXO_WIDE_WINDOW = (\d+)[,;]", fh.read())
        self.assertIsNotNone(m, "core.js exports UTXO_WIDE_WINDOW")
        wide = int(m.group(1))
        addr = "gnb1q" + "00" * 24
        status, doc = self.server.get(f'/v1/getutxos?p=["{addr}",{wide}]')
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["result"]["params"], [addr, wide])
        self.assertEqual(self.server.get(f'/v1/getutxos?p=["{addr}",{wide + 1}]')[0], 400)

    def test_getaddresshistory_offset_is_capped_and_a_cursor_is_accepted(self):
        root = os.path.dirname(os.path.dirname(HERE))
        with open(os.path.join(root, "node", "src", "storage", "indexer.rs"), encoding="utf-8") as fh:
            m = re.search(r"pub const MAX_HISTORY_OFFSET: usize = ([0-9_]+);", fh.read())
        node_max = int(m.group(1).replace("_", ""))
        addr = "gnb1q" + "00" * 24
        cursor = "0" * 31 + "1"
        status, doc = self.server.get(f'/v1/getaddresshistory?p=["{addr}",25,{node_max},"{cursor}"]')
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["result"]["params"], [addr, 25, node_max, cursor])
        self.assertEqual(self.server.get(f'/v1/getaddresshistory?p=["{addr}",25,{node_max + 1}]')[0], 400)
        self.assertEqual(self.server.get(f'/v1/getaddresshistory?p=["{addr}",25,0,"zz"]')[0], 400)

    def test_node_errors_are_not_cached(self):
        # A cancelled heavy read on the node is an error; the next caller
        # must get a fresh computation, not the cached failure.
        answers = [{"error": "cancelled"}, {"result": {"sample_size": 10}}]
        api.rpc = lambda method, params: answers.pop(0)
        status, body = self.server.get("/v1/getblocktimepercentiles")
        self.assertEqual((status, body), (404, {"error": "cancelled"}))
        status, body = self.server.get("/v1/getblocktimepercentiles")
        self.assertEqual((status, body), (200, {"result": {"sample_size": 10}}))
        self.assertEqual(self.server.get("/v1/getblocktimepercentiles")[1], {"result": {"sample_size": 10}}, "successes are cached")

    def test_default_bind_is_loopback_and_key_file_mode_is_checked(self):
        with open(os.path.join(HERE, "gnb-explorer-api.service"), encoding="utf-8") as fh:
            self.assertIn("Environment=GNB_API_BIND=127.0.0.1", fh.read())
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(KEY + "\n")
        try:
            os.chmod(fh.name, 0o600)
            self.assertEqual(api.load_api_key(fh.name), KEY.encode())
            os.chmod(fh.name, 0o644)
            with self.assertRaises(SystemExit):
                api.load_api_key(fh.name)
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
