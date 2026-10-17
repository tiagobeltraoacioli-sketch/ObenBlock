// Re-audit B2-R2-2, read variant: "the same trick, aimed at the uncached GET
// address endpoints, multiplies the heavy-read cost too". A script on any
// page (or an ad) can make each visitor's browser send
// fetch("https://gnb-smh.com/api/getutxos?p=...") with a fresh `p` every time
// (an edge-cache miss), and every such read was charged to that visitor's
// own per-client budget in the explorer API (240 a minute), so the page got
// a fresh budget per visitor and never one of its own.
//
// The Worker now marks a read a browser makes from another site's page
// (Sec-Fetch-Site other than same-origin / none, or a foreign Origin) with
// X-GnB-Cross-Site: 1; the explorer API charges it to one budget shared by
// every cross-site read as well (deploy/explorer-api, CROSS_SITE_LIMIT;
// test_cross_site_reads_share_one_budget). Same-origin pages and
// non-browser clients are unchanged, and public reads keep
// access-control-allow-origin: *.
//
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { isCrossSite } from "../../worker/index.js";

const ctx = { waitUntil: (p) => p };
const assets = { fetch: async () => new Response("<!doctype html>") };
const env = { ASSETS: assets, GNB_ORIGINS: "https://origin.example.net", GNB_API_KEY: "k" };
const ADDRESS = "gnb1q0000000000000000000000000000000000000000335d2ee7";

/** A fake origin and an always-missing edge cache; returns forwarded requests. */
function fakeOrigin() {
  const seen = [];
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), init });
    return new Response('{"result":{"utxos":[]}}', { status: 200 });
  };
  return seen;
}

function read(n, headers) {
  const p = encodeURIComponent(JSON.stringify([ADDRESS, n]));
  return new Request(`https://gnb-smh.com/api/getutxos?p=${p}`, { headers: { "cf-connecting-ip": "198.51.100.7", ...headers } });
}

test("a cross-site read of an uncached address endpoint is forwarded marked cross-site", async () => {
  for (const headers of [
    // fetch() from evil.example: CORS mode, Origin and Sec-Fetch-Site
    { origin: "https://evil.example", "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors" },
    // <img src> / fetch(..., {mode: "no-cors"}): no Origin on a GET, but
    // Sec-Fetch-Site still tells
    { "sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors" },
    // a sibling subdomain is the same site but another origin
    { origin: "https://other.gnb-smh.com", "sec-fetch-site": "same-site" },
    // an older browser without Sec-Fetch-*: the Origin of a CORS request
    { origin: "https://evil.example" },
    // sandboxed frames and data: URLs send the opaque origin "null"
    { origin: "null" },
  ]) {
    const seen = fakeOrigin();
    for (let n = 1; n <= 3; n++) {
      const r = await worker.fetch(read(n, headers), env, ctx);
      assert.equal(r.status, 200, JSON.stringify(headers));
      // Public data: a third-party page may still read it.
      assert.equal(r.headers.get("access-control-allow-origin"), "*");
    }
    assert.equal(seen.length, 3, "every distinct p misses the edge cache");
    for (const s of seen) {
      assert.equal(s.init.headers["x-gnb-cross-site"], "1", JSON.stringify(headers));
      assert.equal(s.init.headers["x-gnb-client-ip"], "198.51.100.7", "the visitor's own budget is charged too");
    }
  }
});

test("same-origin pages and non-browser clients are not marked", async () => {
  for (const headers of [
    // the site's explorer and wallet pages
    { origin: "https://gnb-smh.com", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" },
    { "sec-fetch-site": "same-origin" },
    // typed into the address bar / a bookmark
    { "sec-fetch-site": "none" },
    // curl, scripts, CLI wallets: neither header
    {},
  ]) {
    const seen = fakeOrigin();
    const r = await worker.fetch(read(9, headers), env, ctx);
    assert.equal(r.status, 200, JSON.stringify(headers));
    assert.equal(seen.length, 1);
    assert.equal(seen[0].init.headers["x-gnb-cross-site"], undefined, JSON.stringify(headers));
    assert.equal(seen[0].init.headers["x-gnb-client-ip"], "198.51.100.7");
  }
  // The same-origin check follows the host the request was made to.
  const seen = fakeOrigin();
  const www = new Request(`https://www.gnb-smh.com/api/getblockcount?p=%5B%5D`, {
    headers: { origin: "https://www.gnb-smh.com", "sec-fetch-site": "same-origin" },
  });
  assert.equal((await worker.fetch(www, env, ctx)).status, 200);
  assert.equal(seen[0].init.headers["x-gnb-cross-site"], undefined);
});

test("isCrossSite is the one predicate of the read and the broadcast routes", () => {
  const url = new URL("https://gnb-smh.com/api/getutxos");
  const req = (headers) => new Request(url, { headers });
  assert.equal(isCrossSite(req({}), url), false);
  assert.equal(isCrossSite(req({ "sec-fetch-site": "same-origin", origin: "https://gnb-smh.com" }), url), false);
  assert.equal(isCrossSite(req({ "sec-fetch-site": "none" }), url), false);
  assert.equal(isCrossSite(req({ "sec-fetch-site": "cross-site" }), url), true);
  assert.equal(isCrossSite(req({ "sec-fetch-site": "same-site" }), url), true);
  assert.equal(isCrossSite(req({ origin: "https://evil.example" }), url), true);
  // A same-origin Sec-Fetch-Site with a foreign Origin is still cross-site.
  assert.equal(isCrossSite(req({ "sec-fetch-site": "same-origin", origin: "https://evil.example" }), url), true);
});
