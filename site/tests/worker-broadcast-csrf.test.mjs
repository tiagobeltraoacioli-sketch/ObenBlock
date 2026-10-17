// Re-audit B2-R2-2: any web page could make its visitors' browsers broadcast
// through gnb-smh.com. A cross-origin `fetch(url, {method: "POST", mode:
// "no-cors", body})`, `navigator.sendBeacon` or a text/plain form is a CORS
// "simple request": the browser sends it without a preflight, so the
// per-client broadcast limit counted each visitor and never the attacker,
// and `access-control-allow-origin: *` let the page read every answer.
//
// The broadcast route now accepts only application/json bodies (a
// cross-origin request with that type needs a preflight, which the route
// answers 405 without CORS headers), refuses browser requests that are not
// same-origin (Sec-Fetch-Site, Origin) and never sends
// access-control-allow-origin.
//
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../../worker/index.js";

const ctx = { waitUntil: (p) => p };
const assets = { fetch: async () => new Response("<!doctype html>") };
const env = { ASSETS: assets, GNB_ORIGINS: "https://origin.example.net", GNB_API_KEY: "k" };
const URL_ = "https://gnb-smh.com/api/sendrawtransaction";
const BODY = JSON.stringify({ hex: "ab".repeat(100) });

/** Install a fake origin; returns the list of forwarded requests. */
function fakeOrigin() {
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), init });
    return new Response('{"result":{"txid":"00"}}', { status: 200 });
  };
  return seen;
}

function post(headers, body = BODY) {
  return new Request(URL_, {
    method: "POST",
    headers: { "content-length": String(body.length), ...headers },
    body,
  });
}

test("a cross-site simple POST (text/plain, sendBeacon, no-cors fetch) is refused before the origin", async () => {
  const seen = fakeOrigin();
  const attempts = [
    // fetch(url, {method: "POST", mode: "no-cors", body}) from another site
    { "content-type": "text/plain;charset=UTF-8", origin: "https://evil.example", "sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors" },
    // navigator.sendBeacon(url, string) from another site
    { "content-type": "text/plain;charset=UTF-8", origin: "https://evil.example", "sec-fetch-site": "cross-site" },
    // a text/plain HTML form
    { "content-type": "text/plain", origin: "https://evil.example", "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate" },
    // form-urlencoded and multipart are simple requests as well
    { "content-type": "application/x-www-form-urlencoded", origin: "https://evil.example" },
    { "content-type": "multipart/form-data; boundary=x", origin: "https://evil.example" },
    // no content type at all (a Blob without a type)
    { origin: "https://evil.example", "sec-fetch-site": "cross-site" },
  ];
  for (const headers of attempts) {
    const r = await worker.fetch(post(headers), env, ctx);
    assert.ok(r.status === 403 || r.status === 415, `${JSON.stringify(headers)} -> ${r.status}`);
    assert.equal(r.headers.get("access-control-allow-origin"), null, "no CORS on a refusal");
  }
  assert.equal(seen.length, 0, "nothing reached the origin");
});

test("application/json from another site or origin is refused too", async () => {
  const seen = fakeOrigin();
  for (const headers of [
    // a preflighted request a browser would never send after the 405, or a
    // client that forges the type: the Origin / Sec-Fetch-Site still tell
    { "content-type": "application/json", origin: "https://evil.example", "sec-fetch-site": "cross-site" },
    { "content-type": "application/json", origin: "https://evil.example" },
    { "content-type": "application/json", "sec-fetch-site": "cross-site" },
    // a sibling subdomain is the same site but another origin
    { "content-type": "application/json", origin: "https://other.gnb-smh.com", "sec-fetch-site": "same-site" },
    // sandboxed frames and data: URLs send the opaque origin "null"
    { "content-type": "application/json", origin: "null" },
  ]) {
    const r = await worker.fetch(post(headers), env, ctx);
    assert.equal(r.status, 403, JSON.stringify(headers));
    assert.equal(r.headers.get("access-control-allow-origin"), null);
  }
  assert.equal(seen.length, 0);
});

test("the preflight of a cross-origin JSON broadcast fails: 405 without CORS headers", async () => {
  const seen = fakeOrigin();
  const r = await worker.fetch(new Request(URL_, {
    method: "OPTIONS",
    headers: { origin: "https://evil.example", "access-control-request-method": "POST",
               "access-control-request-headers": "content-type" },
  }), env, ctx);
  assert.equal(r.status, 405);
  assert.equal(r.headers.get("access-control-allow-origin"), null);
  assert.equal(r.headers.get("access-control-allow-methods"), null);
  assert.equal(seen.length, 0);
});

test("the site's own wallet and non-browser clients still broadcast; the answer carries no CORS header", async () => {
  for (const headers of [
    // site/wallet/app.js and site/shared/gnb.js: same-origin fetch with JSON
    { "content-type": "application/json", origin: "https://gnb-smh.com", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" },
    { "content-type": "application/json; charset=utf-8", origin: "https://gnb-smh.com" },
    // curl / scripts / CLI wallets send neither Origin nor Sec-Fetch-Site
    { "content-type": "application/json" },
    // typed into the address bar / bookmarklet: Sec-Fetch-Site none
    { "content-type": "application/json", "sec-fetch-site": "none" },
  ]) {
    const seen = fakeOrigin();
    const r = await worker.fetch(post({ ...headers, "cf-connecting-ip": "198.51.100.4" }), env, ctx);
    assert.equal(r.status, 200, JSON.stringify(headers));
    assert.equal(r.headers.get("access-control-allow-origin"), null, "broadcast answer without CORS");
    assert.equal(seen.length, 1);
    assert.equal(seen[0].url, "https://origin.example.net/v1/sendrawtransaction");
    assert.equal(seen[0].init.headers["content-type"], "application/json");
    assert.equal(seen[0].init.headers["x-gnb-client-ip"], "198.51.100.4");
    assert.equal(seen[0].init.body, BODY);
  }
  // The same-origin check follows the host the request was made to (the
  // workers.dev address and www serve the same Worker).
  const seen = fakeOrigin();
  const www = new Request("https://www.gnb-smh.com/api/sendrawtransaction", {
    method: "POST", body: BODY,
    headers: { "content-length": String(BODY.length), "content-type": "application/json",
               origin: "https://www.gnb-smh.com", "sec-fetch-site": "same-origin" },
  });
  assert.equal((await worker.fetch(www, env, ctx)).status, 200);
  assert.equal(seen.length, 1);
});

test("every broadcast refusal is answered without CORS (method, size, backend errors)", async () => {
  fakeOrigin();
  const get = await worker.fetch(new Request(URL_), env, ctx);
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("access-control-allow-origin"), null);
  const big = await worker.fetch(post({ "content-type": "application/json", "content-length": "900000" }), env, ctx);
  assert.equal(big.status, 413);
  assert.equal(big.headers.get("access-control-allow-origin"), null);
  globalThis.fetch = async () => { throw new Error("down"); };
  const down = await worker.fetch(post({ "content-type": "application/json" }), env, ctx);
  assert.equal(down.status, 502);
  assert.equal(down.headers.get("access-control-allow-origin"), null);
});
