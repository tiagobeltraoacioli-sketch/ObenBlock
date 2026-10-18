// WAL-2 / WAL-3 / WAL-4: Worker headers, origins and caching.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import worker, { parseOrigins, withSecurityHeaders, ttlFor, SITE_CSP, WALLET_CSP } from "../../worker/index.js";
import { installOrigins, envFor, N1 } from "./fake-origin.mjs";

const ctx = { waitUntil: (p) => p };
const assets = { fetch: async () => new Response("<!doctype html>", { headers: { "content-type": "text/html" } }) };

test("only https origins are accepted", () => {
  assert.deepEqual(parseOrigins("http://1.2.3.4:2086, https://a.example.net/ ,https://b.example.net"),
    ["https://a.example.net", "https://b.example.net"]);
  assert.deepEqual(parseOrigins("https://user:pw@a.example.net"), []);
  assert.deepEqual(parseOrigins(undefined), []);
});

test("every static path gets CSP, HSTS and anti-framing headers", async () => {
  for (const path of ["/", "/explorer", "/brand.html", "/assets/site.js"]) {
    const r = await worker.fetch(new Request(`https://obenblock.xyz${path}`), { ASSETS: assets }, ctx);
    assert.equal(r.headers.get("content-security-policy"), SITE_CSP, path);
    assert.match(r.headers.get("strict-transport-security"), /max-age=\d{7,}/);
    assert.equal(r.headers.get("x-frame-options"), "DENY");
    assert.ok(!SITE_CSP.includes("unsafe-eval") && /script-src 'self'(;|$)/.test(SITE_CSP));
  }
  const w = withSecurityHeaders(new URL("https://obenblock.xyz/wallet/gnb_wallet.wasm"), new Response("x"));
  assert.equal(w.headers.get("content-security-policy"), WALLET_CSP);
  assert.equal(w.headers.get("content-type"), "application/wasm");
});

test("the API refuses to run without an https origin", async () => {
  for (const OBB_ORIGINS of [undefined, "http://139-84-201-52.sslip.io:2086"]) {
    const r = await worker.fetch(new Request("https://obenblock.xyz/api/getblockcount"), { ASSETS: assets, OBB_ORIGINS }, ctx);
    assert.equal(r.status, 503);
    assert.ok(r.headers.get("strict-transport-security"));
  }
});

test("origin cache headers are ignored; fixed TTL; client IP forwarded", async () => {
  const stored = [];
  const { seen } = installOrigins({ [N1]: {} }, { cache: false });
  globalThis.caches = { default: { match: async () => undefined, put: async (k, v) => stored.push(v) } };
  const req = new Request("https://obenblock.xyz/api/getbalance?p=%5B%5D", { headers: { "cf-connecting-ip": "198.51.100.4" } });
  const r = await worker.fetch(req, envFor({ OBB_ORIGINS: N1 }), ctx);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("cache-control"), `public, max-age=${ttlFor("getbalance")}`);
  assert.ok(ttlFor("getbalance") <= 5 && ttlFor("unknownmethod") <= 5);
  assert.ok(seen[0].url.startsWith(`${N1}/v1/getbalance`));
  assert.equal(seen[0].init.headers["x-gnb-client-ip"], "198.51.100.4");
  assert.equal(seen[0].init.headers["x-gnb-key"], undefined, "no static secret on the wire");
  assert.match(seen[0].init.headers["x-obb-auth"], /^[0-9a-f]{64}$/);
  assert.equal(stored.length, 1);

  // Errors are never cached.
  installOrigins({ [N1]: { handler: () => ({ status: 400, body: '{"error":"x"}' }) } }, { cache: false });
  globalThis.caches = { default: { match: async () => undefined, put: async (k, v) => stored.push(v) } };
  const e = await worker.fetch(new Request("https://obenblock.xyz/api/getbalance"), envFor({ OBB_ORIGINS: N1 }), ctx);
  assert.equal(e.status, 400);
  assert.equal(e.headers.get("cache-control"), "no-store");
  assert.equal(stored.length, 1);
});

test("wrangler runs the Worker first for every path and the code names no origin", () => {
  const toml = readFileSync(new URL("../../wrangler.toml", import.meta.url), "utf8");
  assert.match(toml, /^run_worker_first = true$/m);
  const code = readFileSync(new URL("../../worker/index.js", import.meta.url), "utf8");
  assert.ok(!/http:\/\/\d|sslip\.io/.test(code), "no hard-coded plain-HTTP or IP origins");
});
