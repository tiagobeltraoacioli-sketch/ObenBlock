#!/usr/bin/env python3
"""Ask an explorer API origin one signed question, as the Worker does.

    explorer_probe.py <https://host:port> <key file> [method] [--insecure]
                      [--expect-chain 0x4f420001] [--expect-genesis <raw hex>]

Signs the request with the shared key (OBB-ORIGIN-v1 HMAC over method,
target, timestamp, nonce and the signed headers: worker/index.js
originHeaders, deploy/explorer-api request_mac), checks the answer's
X-OBB-Resp-Auth over the nonce, status, chain id, genesis, finalized
checkpoint and body, and prints one line. Exit 0 only for a 200 answer
correctly signed back (and naming the expected chain / genesis).
--insecure accepts a self-signed certificate (the rehearsal). Standard
library only; the key never leaves this process.
"""
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.parse
import http.client

SIGNED_HEADERS = ("x-gnb-client-ip", "x-gnb-cross-site", "x-obb-page-origin", "x-obb-probe", "x-obb-body-sha256")


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    opts = argv[1:]
    if len(args) < 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 64
    origin, keyfile = args[0], args[1]
    method = args[2] if len(args) > 2 else "getdaginfo"
    expect_chain = opts[opts.index("--expect-chain") + 1] if "--expect-chain" in opts else None
    expect_genesis = opts[opts.index("--expect-genesis") + 1] if "--expect-genesis" in opts else None
    with open(keyfile) as fh:
        key = fh.readline().strip().encode()
    u = urllib.parse.urlsplit(origin)
    target = f"/v1/{method}"
    h = {"x-obb-body-sha256": hashlib.sha256(b"").hexdigest()}
    ts, nonce = str(int(time.time())), os.urandom(16).hex()
    msg = "\n".join(["OBB-ORIGIN-v1", "GET", target, ts, nonce, *[h.get(n, "") for n in SIGNED_HEADERS]]).encode()
    h.update({"x-obb-ts": ts, "x-obb-nonce": nonce, "x-obb-auth": hmac.new(key, msg, hashlib.sha256).hexdigest()})
    ctx = ssl.create_default_context()
    if "--insecure" in opts:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=15, context=ctx)
    conn.request("GET", target, headers=h)
    r = conn.getresponse()
    body = r.read()
    chain, genesis, fin = (r.getheader(x, "") for x in ("x-obb-chain-id", "x-obb-genesis", "x-obb-finalized"))
    want = hmac.new(key, "\n".join(["OBB-ORIGIN-RESP-v1", nonce, str(r.status), chain, genesis, fin,
                                    hashlib.sha256(body).hexdigest()]).encode(), hashlib.sha256).hexdigest()
    signed_ok = hmac.compare_digest(want, r.getheader("x-obb-resp-auth", ""))
    ok = r.status == 200 and signed_ok and (not expect_chain or chain == expect_chain) \
        and (not expect_genesis or genesis == expect_genesis)
    try:
        summary = json.dumps(json.loads(body).get("result", json.loads(body)))[:200]
    except ValueError:
        summary = body[:200].decode(errors="replace")
    print(f"{'OK' if ok else 'FAIL'} {origin}{target} status={r.status} answer_signed={signed_ok} "
          f"chain={chain} genesis={genesis[:16]} finalized={fin[:40]} {summary}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
