#!/usr/bin/env python3
"""Read-only HTTP API in front of a GnB node, for the gnb-smh.com explorer.

    GET /v1/<method>?p=<JSON array of params>     -> {"result": ...} | {"error": ...}
    GET /v1/carryover/<address>                    -> carryover share of one address
    GET /v1/health                                 -> {"ok": true, "height": ...}
    POST /v1/sendrawtransaction  body {"hex": ...}  -> broadcast a signed transaction

Only methods in ALLOWED are forwarded, with validated parameters, to the
node's localhost JSON-RPC. Responses are cached briefly. Every request must
carry the shared secret in X-GnB-Key (set by the Cloudflare Worker), so the
origin is not an open public API. Standard library only.

Hardening (audit WAL-2, WAL-4, NET-12, B1-T10, B2-T4):
  * binds 127.0.0.1 by default: expose it through a Cloudflare Tunnel, or
    terminate TLS here (GNB_API_TLS_CERT/KEY) behind the Cloudflare-only
    firewall of firewall-cloudflare.sh; see README.md;
  * every connection has a socket timeout AND an absolute deadline, so idle
    or slow-drip (slowloris) clients cannot hold a worker;
  * at most GNB_API_MAX_CONNECTIONS connections are served at once; further
    connections are refused immediately instead of spawning threads;
  * requests are rate-limited per ORIGINAL client: the X-GnB-Client-IP header
    the Worker sets from CF-Connecting-IP (trusted only on requests that carry
    the shared key), else the peer address, aggregated to the client's
    allocation (IPv4 /32, IPv6 /64, as the node's own RPC limiter does), so
    rotating source addresses inside one /64 does not mint new clients;
  * a full limiter table evicts its least recently seen client in O(1); it
    never refuses a new client because the table is full (the previous
    limiter refused EVERY new client for the rest of the minute once 50,000
    were tracked, and rebuilt its table under its lock on each refusal);
  * only well-formed requests (known method, valid parameters) are counted
    and forwarded: anything else is answered before it can occupy a limiter
    slot or reach the node;
  * broadcasts must be application/json and must not come from a browser
    page of another site (re-audit B2-R2-2, broadcast_refusal): a
    cross-site 'simple request' is refused before it is read, counted or
    forwarded;
  * a read the Worker marks as made by a browser page of another site
    (X-GnB-Cross-Site: 1, trusted only on requests that carry the shared
    key) is charged to the visitor's own GET budget AND to one budget that
    every cross-site read shares (GNB_API_CROSS_SITE_PER_MIN, re-audit
    B2-R2-2): a page that makes each of its visitors' browsers send
    uncached per-address reads gets that one budget, not one per visitor;
  * broadcasts also share one API-wide budget of transaction bytes per minute
    (GNB_API_POST_BYTES_PER_MIN): every forwarded transaction costs the node
    signature verification roughly in proportion to its size, so the
    verification work the API can ask of the node is bounded whatever the
    number of client addresses (the node also applies its own budget to
    anonymous sendrawtransaction calls, docs/RUNNING.md).

Environment:
    GNB_RPC_URL              node JSON-RPC (default http://127.0.0.1:17210/)
    GNB_API_BIND             bind address   (default 127.0.0.1)
    GNB_API_PORT             bind port      (default 2086)
    GNB_API_KEY_FILE         file holding the shared secret (required, mode 0600/0640)
    GNB_API_TLS_CERT         PEM certificate chain: serve HTTPS (optional)
    GNB_API_TLS_KEY          PEM private key for GNB_API_TLS_CERT
    GNB_API_TIMEOUT          per-read socket timeout, seconds (default 10)
    GNB_API_DEADLINE         absolute per-connection deadline, seconds (default 30)
    GNB_API_MAX_CONNECTIONS  concurrent connections (default 64)
    GNB_API_RATE_PER_MIN     GET requests per client per minute (default 240)
    GNB_API_POST_PER_MIN     broadcasts per client per minute (default 6)
    GNB_API_POST_BYTES_PER_MIN  transaction bytes forwarded per minute, all
                             clients together (default 2000000)
    GNB_API_CROSS_SITE_PER_MIN  GET requests per minute that browser pages of
                             other sites may cause, all together (default 240)
    GNB_API_MAX_CLIENTS      clients tracked per limiter (default 50000)
    GNB_CARRYOVER            uncompressed Bloch Genesis-3 carryover TSV (optional)
"""

import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RPC_URL = os.environ.get("GNB_RPC_URL", "http://127.0.0.1:17210/")
API_KEY = b""

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ADDR = re.compile(r"^(gnb1[qt][0-9a-f]{48}|gnb1[mn][0-9a-f]{72})$")
IP_TEXT = re.compile(r"^[0-9a-fA-F:.]{2,45}$")


def load_api_key(path):
    """Read the shared secret; refuse group/world-writable or world-readable files."""
    st = os.stat(path)
    if st.st_mode & (stat.S_IWGRP | stat.S_IRWXO):
        raise SystemExit(f"{path}: the API key file must be mode 0600 or 0640")
    with open(path, "r", encoding="utf-8") as fh:
        key = fh.readline().strip().encode()
    if len(key) < 32:
        raise SystemExit("GNB_API_KEY_FILE must hold a secret of at least 32 characters")
    return key


def _int(lo, hi):
    def check(v):
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f"integer in [{lo}, {hi}] expected")
        return v
    return check


def _re(rx, what):
    def check(v):
        if not isinstance(v, str) or not rx.match(v):
            raise ValueError(f"{what} expected")
        return v
    return check


HASH = _re(HEX64, "64-char lowercase hex")
# Routing is syntax-only. BIP350 checksum/network validation is performed by
# the RPC; carryover is local and therefore uses _carryover_address below.
V2_ADDR = re.compile(r"(?:t?gnb1zq[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}|t?gnb1zp[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58})")


def ADDRESS(value):
    if isinstance(value, str):
        if ADDR.fullmatch(value):
            return value
        if (value == value.lower() or value == value.upper()) and V2_ADDR.fullmatch(value.lower()):
            return value
    raise ValueError("GnB address expected")


U32 = _int(0, 2**32 - 1)
PAGE = _int(1, 100)
OFFSET = _int(0, 10**9)
RICH_OFFSET = _int(0, 10_000)
# B1-T11: the node pages an address's history newest first with a reverse
# iterator; an offset costs one index step per skipped entry, so the node caps
# it (storage::indexer::MAX_HISTORY_OFFSET, the same value). Deeper pages use
# the opaque cursor the node returns as `next_cursor` (16 bytes, hex).
HISTORY_OFFSET = _int(0, 10_000)
CURSOR = _re(re.compile(r"^[0-9a-f]{32}$"), "32-char lowercase hex cursor")
# B2-T3: the web wallet widens a truncated 50-row UTXO window to this many rows
# when immature coinbase outputs took part of it (site/wallet/core.js
# UTXO_WIDE_WINDOW; the tests keep the two equal). Far below the node's own
# cap (gnb_crypto::wallet::send::GETUTXOS_MAX_ROWS = 10,000).
GETUTXOS_MAX = 1000


def BOOL(v):
    if not isinstance(v, bool):
        raise ValueError("true or false expected")
    return v


# method -> (list of parameter checkers, cache seconds)
ALLOWED = {
    "getblockcount":           ([], 3),
    "getdaginfo":              ([], 3),
    "getnetworkinfo":          ([], 5),
    "getsupplyinfo":           ([], 10),
    "getchainstats":           ([], 30),
    "gethashrate":             ([], 30),
    # NET-12: the node caps this at 100 points; bounded walk, single-flight.
    "getdifficultyhistory":    ([_int(1, 100)], 30),
    "getblocktimepercentiles": ([], 30),
    "getmempoolstats":         ([], 5),
    "getrawmempool":           ([], 5),
    "getselectedchain":        ([OFFSET, PAGE], 3),
    "getblockdag":             ([HASH], 5),
    "gettransactionfull":      ([HASH], 5),
    # WAL-1: raw bytes of a previous transaction, hashed by the wallet.
    "getrawtransaction":       ([HASH], 60),
    "getdagwindow":            ([_int(1, 300)], 3),
    # B1-T11: O(limit) on the node (history counter + reverse iterator).
    "getaddresshistory":       ([ADDRESS, PAGE, HISTORY_OFFSET, CURSOR], 5),
    # B1-T11: O(1) on the node (holder aggregate).
    "getbalance":              ([ADDRESS], 5),
    # B2-T3: up to the web wallet's wide window (the sidechain wallet,
    # site/wallet/main.js, asks for 500 rows; the explorer for 100 and 200).
    "getutxos":                ([ADDRESS, _int(1, GETUTXOS_MAX)], 2),
    "getpowitinfo":            ([], 3),
    "getblock":                ([HASH, BOOL], 10),
    "getblockhash":            ([U32], 5),
    "gettransaction":          ([HASH], 5),
    "gettxstatus":             ([HASH], 3),
    # NET-12: served from the node's incremental holder index; the node
    # serves offsets up to analytics::MAX_RICHLIST_OFFSET = 10,000.
    "getrichlist":             ([PAGE, RICH_OFFSET], 60),
    "getsupplydistribution":   ([], 60),
    "validateaddress":         ([_re(re.compile(r"^.{1,80}$"), "string")], 60),
}

_cache = {}
_cache_lock = threading.Lock()
CACHE_MAX = 4096


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        doc = json.loads(resp.read())
    if "result" in doc:
        res = doc["result"]
        if isinstance(res, dict) and "error" in res and len(res) <= 2:
            return {"error": res["error"]}
        return {"result": res}
    return {"error": doc.get("error", "node error")}


def cached(key, ttl, fn):
    """Serve `key` from the cache while fresh, else compute it with `fn`.
    Only successes are cached: a node error (a cancelled or timed-out heavy
    read, aggregates not built yet, busy) must not answer the next callers
    for `ttl` seconds - the node's HeavyGate never caches one either."""
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    value = fn()
    if "error" in value:
        return value
    with _cache_lock:
        if len(_cache) >= CACHE_MAX:
            _cache.clear()
        _cache[key] = (now + ttl, value)
    return value


# ── per-client rate limiting (WAL-4, B1-T10, B2-T4) ─────────────────────────

def client_key(text):
    """The rate-limit identity of a client address: an IPv4 address as is
    (/32), an IPv6 address by its /64 network, the standard allocation of one
    customer, so the 2^64 addresses of one /64 are one client (the node's own
    RPC limiter does the same, node/src/rpc/auth.rs M-2). An IPv4-mapped IPv6
    address is its IPv4 address. Text that is not an IP address (never sent
    by Cloudflare) is its own key."""
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return text
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(ip) >> 64 << 64, 64)))
    return str(ip)


class RateLimiter:
    """At most `per_min` requests per client key and fixed one-minute window.

    The table holds at most `max_clients` keys in least-recently-seen order.
    A new key arriving while it is full evicts the least recently seen one:
    O(1) under the lock, and it never refuses the new client. An evicted
    client only starts a fresh window when it returns, so eviction never
    refuses anyone, and a client that stays in the table keeps its count.
    Windows roll over lazily per key: there is no pruning pass at all."""

    def __init__(self, per_min, max_clients=None):
        self.per_min = per_min
        self.max_clients = max_clients or int(os.environ.get("GNB_API_MAX_CLIENTS", "50000"))
        self.windows = collections.OrderedDict()
        self.evictions = 0
        self.lock = threading.Lock()

    def allow(self, client, now=None):
        minute = int((time.monotonic() if now is None else now) // 60)
        with self.lock:
            entry = self.windows.get(client)
            if entry is None:
                if len(self.windows) >= self.max_clients:
                    self.windows.popitem(last=False)
                    self.evictions += 1
                window, n = minute, 0
            else:
                window, n = entry
                if window != minute:
                    window, n = minute, 0
                self.windows.move_to_end(client)
            if n >= self.per_min:
                self.windows[client] = (window, n)
                return False
            self.windows[client] = (window, n + 1)
            return True


class ByteBudget:
    """Token bucket of `per_min` bytes per minute shared by every client
    (B1-T10). Each forwarded transaction costs the node signature
    verification roughly in proportion to its size (one hybrid input is
    about 8.6 kB), so this bounds the verification work the API can ask of
    the node per minute, however many client addresses send it."""

    def __init__(self, per_min):
        self.capacity = float(per_min)
        self.tokens = float(per_min)
        self.rate = per_min / 60.0
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def take(self, n, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            self.tokens = min(self.capacity, self.tokens + max(0.0, now - self.last) * self.rate)
            self.last = now
            if n > self.tokens:
                return False
            self.tokens -= n
            return True


GET_LIMIT = RateLimiter(int(os.environ.get("GNB_API_RATE_PER_MIN", "240")))
POST_LIMIT = RateLimiter(int(os.environ.get("GNB_API_POST_PER_MIN", "6")))
POST_BYTES = ByteBudget(int(os.environ.get("GNB_API_POST_BYTES_PER_MIN", "2000000")))
# Re-audit B2-R2-2 (reads): one window shared by every cross-site read.
CROSS_SITE_LIMIT = RateLimiter(int(os.environ.get("GNB_API_CROSS_SITE_PER_MIN", "240")), max_clients=1)
CROSS_SITE_KEY = "cross-site"

RATE_LIMITED = {"error": "rate limit exceeded; retry in a minute"}


# ── carryover share per address ─────────────────────────────────────────────

CARRY_ALLOC = 1_000_000 * 10**8
CARRY_SOURCE = 3_810_744_000 * 10**8
_carry = {}


def _address(h20: bytes, testnet=False) -> str:
    c = hashlib.sha3_256(hashlib.sha3_256(h20).digest()).digest()[:4]
    return ("gnb1t" if testnet else "gnb1q") + (h20 + c).hex()


def load_carryover(path):
    if not path or not os.path.exists(path):
        return
    out = {}
    with open(path, "rb") as fh:
        for line in fh:
            parts = line.rstrip(b"\n").split(b"\t")
            if len(parts) != 4:
                continue
            value = int(parts[2]) * CARRY_ALLOC // CARRY_SOURCE
            if value == 0:
                continue
            a = _address(bytes.fromhex(parts[3].decode()))
            v = out.setdefault(a, [0, 0, 0])
            v[0] += value
            v[1] += 1
            v[2] += int(parts[2])
    _carry.update(out)


def _carryover_address(value):
    """Verify a v2 alias and derive the existing carryover key, without RPC.

    Standalone deployment: no import from the uninstalled reference tree.
    BIP350 https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    Application framing is docs/ADDRESS-V2.md; this is not Bitcoin Segwit.
    """
    ADDRESS(value)
    if ADDR.fullmatch(value):
        return value  # Existing legacy behavior and table keys are unchanged.
    lower = value.lower()
    hrp, data = lower.rsplit("1", 1)
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    words = [alphabet.index(c) for c in data]
    checksum = 1
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    for word in expanded + words:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ word
        for bit, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if top & (1 << bit):
                checksum ^= generator
    if checksum != 0x2bc830a3:
        raise ValueError("invalid Bech32m checksum")
    # ADDRESS already checks known HRP, version 2, kind and encoded length.
    kind = words[1]
    acc = bits = 0
    payload = bytearray()
    for word in words[2:-6]:
        acc = ((acc << 5) | word) & 0xfff
        bits += 5
        if bits >= 8:
            bits -= 8
            payload.append((acc >> bits) & 0xff)
    if bits >= 5 or (acc & ((1 << bits) - 1)) or len(payload) != (20 if kind == 0 else 32):
        raise ValueError("invalid address padding or length")
    prefix = ("gnb1t" if hrp == "tgnb" else "gnb1q") if kind == 0 else ("gnb1n" if hrp == "tgnb" else "gnb1m")
    checksum_input = (prefix.encode("ascii") if kind == 1 else b"") + payload
    legacy_checksum = hashlib.sha3_256(hashlib.sha3_256(checksum_input).digest()).digest()[:4]
    return prefix + (payload + legacy_checksum).hex()


def carryover_of(address):
    address = _carryover_address(address)
    v = _carry.get(address)
    if not v:
        return {"result": {"address": address, "in_carryover": False}}
    return {"result": {"address": address, "in_carryover": True, "amount": str(v[0]),
                       "utxos": v[1], "bloch_amount": str(v[2])}}


# ── HTTP ─────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "gnb-explorer-api"
    sys_version = ""
    # Per-read socket timeout (BaseHTTPRequestHandler applies it in setup()).
    timeout = float(os.environ.get("GNB_API_TIMEOUT", "10"))
    # Absolute deadline for a whole connection, whatever the client sends.
    deadline = float(os.environ.get("GNB_API_DEADLINE", "30"))

    def setup(self):
        super().setup()
        self._timer = threading.Timer(self.deadline, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self._timer.cancel()
        try:
            super().finish()
        except OSError:
            pass

    def log_message(self, fmt, *args):  # quiet; systemd keeps errors only
        pass

    def send(self, code, doc, ttl=0):
        data = json.dumps(doc, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", f"public, max-age={ttl}" if ttl and code == 200 else "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        key = self.headers.get("x-gnb-key", "").encode()
        return bool(API_KEY) and hmac.compare_digest(
            hashlib.sha256(key).digest(), hashlib.sha256(API_KEY).digest())

    def client(self):
        """The original client's rate-limit key: the Worker's X-GnB-Client-IP
        (only trusted on authorized requests), else CF-Connecting-IP, else
        the peer address, aggregated by `client_key` (IPv6 /64)."""
        for header in ("x-gnb-client-ip", "cf-connecting-ip"):
            v = self.headers.get(header, "").strip()
            if v and IP_TEXT.match(v):
                return client_key(v)
        return client_key(self.client_address[0])

    def over_limit(self, limiter):
        """Count this (already validated) request; True when over the limit."""
        return not limiter.allow(self.client())

    def cross_site(self):
        """True when the Worker marks this request as made by a browser page
        of another site (X-GnB-Cross-Site: 1, worker/index.js isCrossSite).
        Only called on authorized requests: no one else can set it."""
        return self.headers.get("x-gnb-cross-site", "").strip() == "1"

    def over_read_limit(self):
        """Count this (already validated) read; True when over a limit: the
        client's own GET budget and, for a cross-site read, the one budget
        all cross-site reads share (re-audit B2-R2-2). A page on another
        site runs in every visitor's browser, so the per-client budget alone
        counted each visitor and never the page."""
        if self.over_limit(GET_LIMIT):
            return True
        return self.cross_site() and not CROSS_SITE_LIMIT.allow(CROSS_SITE_KEY)

    def do_GET(self):
        if not self.authorized():
            return self.send(403, {"error": "forbidden"})
        url = urllib.parse.urlsplit(self.path)
        parts = [p for p in url.path.split("/") if p]
        if len(parts) < 2 or parts[0] != "v1":
            return self.send(404, {"error": "not found"})
        name = parts[1]
        # B1-T10: every request is validated before it is counted, so
        # malformed or unknown ones (cheap 404/400 answers, never forwarded)
        # cannot occupy limiter slots.
        try:
            if name == "health" and len(parts) == 2:
                if self.over_read_limit():
                    return self.send(429, RATE_LIMITED)
                r = rpc("getblockcount", [])
                return self.send(200, {"ok": "result" in r, "blocks": r.get("result")})
            if name == "carryover" and len(parts) == 3:
                ADDRESS(parts[2])
                if self.over_read_limit():
                    return self.send(429, RATE_LIMITED)
                return self.send(200, carryover_of(parts[2]), 300)
            if name not in ALLOWED or len(parts) != 2:
                return self.send(404, {"error": "unknown method"})
            checkers, ttl = ALLOWED[name]
            raw = urllib.parse.parse_qs(url.query).get("p", ["[]"])[0]
            if len(raw) > 512:
                raise ValueError("params too long")
            params = json.loads(raw)
            if not isinstance(params, list) or len(params) > len(checkers):
                raise ValueError("params must be a JSON array")
            params = [check(v) for check, v in zip(checkers, params)]
            if self.over_read_limit():
                return self.send(429, RATE_LIMITED)
            ck = name + json.dumps(params)
            result = cached(ck, ttl, lambda: rpc(name, params))
            return self.send(200 if "result" in result else 404, result, ttl)
        except (ValueError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})
        except Exception:  # node unreachable or timed out
            return self.send(502, {"error": "node unavailable"})


HEXTX = re.compile(r"^[0-9a-f]+$")
MAX_TX_HEX = 2 * 400 * 1024


def broadcast_refusal(headers):
    """Why a broadcast must be refused before it is read, as (status,
    message), or None (re-audit B2-R2-2).

    Only an application/json body is accepted: text/plain, form and
    multipart bodies are what a browser sends cross-site without a CORS
    preflight (fetch in no-cors mode, sendBeacon, an HTML form), and parsing
    them as JSON anyway let any web page broadcast through its visitors'
    browsers. A request a browser marks as cross-site (Sec-Fetch-Site other
    than same-origin / none) or that carries an Origin header is refused as
    well: the Worker forwards neither header, and the API is not meant to be
    called by a browser directly."""
    ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype != "application/json":
        return 415, "content-type must be application/json"
    site = headers.get("sec-fetch-site")
    if site is not None and site not in ("same-origin", "none"):
        return 403, "cross-site broadcast refused"
    if headers.get("origin") is not None:
        return 403, "browser-origin broadcast refused"
    return None


class PostHandler(Handler):
    def do_POST(self):
        if not self.authorized():
            return self.send(403, {"error": "forbidden"})
        if urllib.parse.urlsplit(self.path).path != "/v1/sendrawtransaction":
            return self.send(404, {"error": "not found"})
        refusal = broadcast_refusal(self.headers)
        if refusal:
            return self.send(refusal[0], {"error": refusal[1]})
        try:
            n = int(self.headers.get("content-length", "0"))
            if not 0 < n <= MAX_TX_HEX + 64:
                raise ValueError("body size out of range")
            doc = json.loads(self.rfile.read(n))
            raw = doc.get("hex") if isinstance(doc, dict) else None
            if not isinstance(raw, str) or not raw or len(raw) > MAX_TX_HEX or len(raw) % 2 or not HEXTX.match(raw):
                raise ValueError("hex-encoded transaction expected")
            # Counted only once the body is valid (like GET requests): a
            # malformed broadcast neither creates a limiter entry nor uses up
            # the client's broadcasts.
            if self.over_limit(POST_LIMIT):
                return self.send(429, RATE_LIMITED)
            # B1-T10: the API-wide verification budget, in transaction bytes.
            if not POST_BYTES.take(len(raw) // 2):
                return self.send(429, {"error": "broadcast budget exhausted; retry shortly"})
            r = rpc("sendrawtransaction", [raw])
            return self.send(200 if "result" in r else 400, r)
        except (ValueError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})
        except Exception:
            return self.send(502, {"error": "node unavailable"})


class BoundedServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard cap on concurrent connections: a
    connection beyond the cap is closed at once instead of getting a thread."""

    daemon_threads = True
    request_queue_size = 128

    def __init__(self, addr, handler, max_connections=64, ssl_context=None):
        self.slots = threading.BoundedSemaphore(max_connections)
        self.ssl_context = ssl_context
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def handle_error(self, request, client_address):
        # Connections cut at the deadline or dropped by the client are routine.
        if isinstance(sys.exc_info()[1], (OSError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            if self.ssl_context is not None:
                request.settimeout(Handler.timeout)
                request = self.ssl_context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)
        finally:
            self.slots.release()


def make_server(bind, port, max_connections, cert=None, key=None):
    ctx = None
    if cert or key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
    return BoundedServer((bind, port), PostHandler, max_connections, ctx)


def main():
    global API_KEY
    API_KEY = load_api_key(os.environ["GNB_API_KEY_FILE"])
    bind = os.environ.get("GNB_API_BIND", "127.0.0.1")
    port = int(os.environ.get("GNB_API_PORT", "2086"))
    cert, key = os.environ.get("GNB_API_TLS_CERT"), os.environ.get("GNB_API_TLS_KEY")
    if bind not in ("127.0.0.1", "::1", "localhost") and not cert:
        raise SystemExit("refusing to serve plain HTTP on a non-loopback address; set "
                         "GNB_API_TLS_CERT/GNB_API_TLS_KEY or use a Cloudflare Tunnel (README.md)")
    threading.Thread(target=load_carryover, args=(os.environ.get("GNB_CARRYOVER"),), daemon=True).start()
    httpd = make_server(bind, port, int(os.environ.get("GNB_API_MAX_CONNECTIONS", "64")), cert, key)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
