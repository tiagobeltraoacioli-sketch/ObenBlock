import { isAddress } from "../site/assets/safe.js";

// gnb-smh.com: static site plus a read-only explorer API proxy.
//
//   /api/<method>?p=<JSON params>  -> origin /v1/<method>  (edge-cached briefly)
//   everything else                -> static assets in ./site
//
// The origin is the explorer API on a GnB node. It accepts only requests that
// carry the shared secret (Worker secret GNB_API_KEY), so the node is reached
// exclusively through this Worker.
//
// Audit fixes:
// - WAL-2: origins come from the GNB_ORIGINS variable (comma- or space-
//   separated) and must be https:// URLs (TLS on the origin or a Cloudflare
//   Tunnel hostname, see deploy/explorer-api/README.md); plain http:// origins
//   are refused, so the shared secret, UTXO values and broadcast transactions
//   never cross the Internet in clear. Origin cache headers are ignored: the
//   edge caches successful reads for a fixed, short TTL per method only.
//   Every response carries HSTS.
// - WAL-3: a strict Content-Security-Policy on every path (wrangler.toml runs
//   this Worker first for all requests), stricter still under /wallet.
// - WAL-4: the original client address (CF-Connecting-IP) is forwarded to the
//   origin in X-GnB-Client-IP, so the explorer API can rate-limit per client.
// - B2-R2-2: /api/sendrawtransaction accepts only same-origin browser
//   requests (or non-browser clients, which send no Origin) with an
//   application/json body, and its answers carry no CORS header. Before, any
//   web page could make its visitors' browsers broadcast through this route
//   with a CORS "simple request" (text/plain fetch in no-cors mode,
//   sendBeacon, a form), so the per-client limit counted every visitor and
//   never the attacker; see broadcastRefusal. The read variant of the same
//   trick (a page making its visitors' browsers send uncached per-address
//   reads, each charged to that visitor's own budget) is bounded too: a read
//   a browser marks as cross-site is forwarded with X-GnB-Cross-Site, and
//   the explorer API charges it to one budget shared by every cross-site
//   read as well as to the visitor's own (see isCrossSite).
const NAME = /^[a-z0-9]{2,40}$/;

// Fixed edge TTLs (seconds). Anything not listed uses DEFAULT_TTL.
const DEFAULT_TTL = 5;
const TTL = {
  getbalance: 2, getutxos: 2, getaddresshistory: 5, getrawmempool: 5, getmempoolstats: 5,
  getblockcount: 3, getdaginfo: 3, getselectedchain: 3, getdagwindow: 3,
  getchainstats: 30, gethashrate: 30, getdifficultyhistory: 30, getblocktimepercentiles: 30,
  getrichlist: 60, getsupplydistribution: 60, getrawtransaction: 60, carryover: 300,
};
export const ttlFor = (path) => TTL[path.split("/")[0]] ?? DEFAULT_TTL;

/** https:// origins from a configuration string; anything else is dropped. */
export function parseOrigins(value) {
  return String(value || "").split(/[\s,]+/).map((s) => s.trim().replace(/\/+$/, "")).filter((s) => {
    try { const u = new URL(s); return u.protocol === "https:" && !u.username && !u.password && u.pathname === "/" && !u.search; }
    catch { return false; }
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return withSecurityHeaders(url, await env.ASSETS.fetch(request));
    const origins = parseOrigins(env.GNB_ORIGINS);
    if (!origins.length) return json({ error: "explorer backend not configured" }, 503);
    if (url.pathname === "/api/sendrawtransaction") return broadcast(request, env, origins);
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
    const rest = url.pathname.slice(5).split("/").filter(Boolean);
    if (!rest.length || !rest.every((s) => NAME.test(s) || isAddress(s))) {
      return json({ error: "not found" }, 404);
    }
    const p = url.searchParams.get("p") || "[]";
    if (p.length > 512) return json({ error: "params too long" }, 400);
    const path = rest.join("/");
    const ttl = ttlFor(path);
    const cacheKey = new Request(`https://cache.gnb-smh.com/${path}?p=${encodeURIComponent(p)}`);
    const cache = caches.default;
    const hit = await cache.match(cacheKey);
    if (hit) return hit;

    // B2-R2-2 (reads): a cross-site read is charged to the budget all
    // cross-site reads share as well (deploy/explorer-api, CROSS_SITE_LIMIT).
    const extra = isCrossSite(request, url) ? { "x-gnb-cross-site": "1" } : {};
    for (const origin of origins) {
      try {
        const r = await fetch(`${origin}/v1/${path}?p=${encodeURIComponent(p)}`, {
          headers: originHeaders(request, env, extra),
          cf: { cacheTtl: 0, cacheEverything: false },
          redirect: "manual",
          signal: AbortSignal.timeout(8000),
        });
        if (r.status >= 500 || (r.status >= 300 && r.status < 400)) continue;
        const body = await r.text();
        // The origin's cache-control is ignored: fixed TTL for successes only.
        const resp = apiResponse(body, r.status, r.status === 200 ? `public, max-age=${ttl}` : "no-store");
        if (r.status === 200) ctx.waitUntil(cache.put(cacheKey, resp.clone()));
        return resp;
      } catch (e) {
        // try the next origin
      }
    }
    return json({ error: "explorer backend unavailable" }, 502);
  },
};

function originHeaders(request, env, extra = {}) {
  return {
    "x-gnb-key": env.GNB_API_KEY,
    "x-gnb-client-ip": request.headers.get("cf-connecting-ip") || "",
    ...extra,
  };
}

/**
 * True when a browser marks `request` as made by a page of another site or
 * origin (re-audit B2-R2-2): Sec-Fetch-Site other than same-origin / none
 * (sent on every request by current browsers, also no-cors ones such as
 * <img>, sendBeacon and fetch(..., {mode: "no-cors"})), or an Origin header
 * that is not this host's (sent on every CORS request). Non-browser clients
 * (CLI wallets, scripts) send neither and are never cross-site.
 *
 * Such a page runs in each visitor's browser, so a per-client limit counts
 * every visitor and never the page: reads it causes are charged, in the
 * explorer API, to one budget all cross-site reads share as well; a
 * broadcast it causes is refused (broadcastRefusal).
 */
export function isCrossSite(request, url) {
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && site !== "none") return true;
  const origin = request.headers.get("origin");
  return origin !== null && origin !== url.origin;
}

/**
 * Why a broadcast request must be refused before it costs anything, as
 * `[status, message]`, or null (B2-R2-2).
 *
 * A browser sends a cross-origin POST without asking first (no CORS
 * preflight) only when it is a "simple request": its Content-Type is
 * text/plain, application/x-www-form-urlencoded or multipart/form-data (or
 * absent). Requiring application/json therefore forces every cross-origin
 * browser broadcast through a preflight, which this route answers 405
 * without CORS headers, so the browser never sends the POST. Independently,
 * a request a browser marks as coming from another origin (Sec-Fetch-Site
 * other than same-origin / none, or an Origin header that is not this
 * host's) is refused: only the site's own pages (site/wallet/app.js,
 * site/shared/gnb.js, both same-origin JSON fetches) and non-browser
 * clients (CLI wallets, scripts: no Origin, no Sec-Fetch-Site) broadcast.
 *
 * Bitcoin Core's RPC has the same property by construction: it sends no
 * CORS headers and needs HTTP authentication, so no third-party page can
 * make a visitor's browser call sendrawtransaction.
 */
export function broadcastRefusal(request, url) {
  const type = (request.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (type !== "application/json") return [415, "content-type must be application/json"];
  if (isCrossSite(request, url)) return [403, "cross-site broadcast refused"];
  return null;
}

// Signed transactions from the web wallet. The node re-validates everything;
// this only bounds the size and shape and refuses cross-site requests. No
// answer of this route carries access-control-allow-origin (B2-R2-2): a
// third-party page can neither send a broadcast through a visitor's browser
// nor read the result.
async function broadcast(request, env, origins) {
  const url = new URL(request.url);
  if (request.method !== "POST") return broadcastJson({ error: "method not allowed" }, 405);
  const refusal = broadcastRefusal(request, url);
  if (refusal) return broadcastJson({ error: refusal[1] }, refusal[0]);
  const len = Number(request.headers.get("content-length") || "0");
  if (!(len > 0 && len <= 820000)) return broadcastJson({ error: "body size out of range" }, 413);
  const body = await request.text();
  let last = 502;
  for (const origin of origins) {
    try {
      const r = await fetch(`${origin}/v1/sendrawtransaction`, {
        method: "POST",
        headers: originHeaders(request, env, { "content-type": "application/json" }),
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(20000),
      });
      if (r.status >= 500 || (r.status >= 300 && r.status < 400)) { last = 502; continue; }
      return apiResponse(await r.text(), r.status, "no-store", { cors: false });
    } catch (e) { last = 502; }
  }
  return broadcastJson({ error: "broadcast backend unavailable" }, last);
}

/** A broadcast-route answer: JSON, never cached, no CORS header. */
function broadcastJson(doc, status) {
  return apiResponse(JSON.stringify(doc), status, "no-store", { cors: false });
}

const HSTS = "max-age=31536000; includeSubDomains";

// Site-wide policy: only same-origin code, no inline script, no framing.
export const SITE_CSP = [
  "default-src 'self'", "script-src 'self'", "connect-src 'self'",
  "img-src 'self' data:", "style-src 'self' 'unsafe-inline'", "font-src 'self' data:",
  "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'",
].join("; ");

// The wallet handles keys: same as the site, plus WebAssembly, and no forms.
export const WALLET_CSP = [
  "default-src 'self'", "script-src 'self' 'wasm-unsafe-eval'", "connect-src 'self'",
  "img-src 'self' data:", "style-src 'self' 'unsafe-inline'", "font-src 'self' data:",
  "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
].join("; ");

// JSON API responses are data, never documents.
const API_CSP = "default-src 'none'; frame-ancestors 'none'";

export function withSecurityHeaders(url, resp) {
  const h = new Headers(resp.headers);
  const wallet = url.pathname === "/wallet" || url.pathname.startsWith("/wallet/") || url.pathname === "/wallet.html";
  h.set("x-content-type-options", "nosniff");
  h.set("referrer-policy", "no-referrer");
  h.set("strict-transport-security", HSTS);
  h.set("content-security-policy", wallet ? WALLET_CSP : SITE_CSP);
  h.set("x-frame-options", "DENY");
  h.set("cross-origin-opener-policy", "same-origin");
  if (wallet && url.pathname.endsWith(".wasm")) h.set("content-type", "application/wasm");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

// Read answers keep `access-control-allow-origin: *` (the explorer data is
// public and third-party explorers read it); broadcast answers never carry
// it (B2-R2-2).
function apiResponse(body, status, cacheControl, { cors = true } = {}) {
  const headers = {
    "content-type": "application/json",
    "cache-control": cacheControl,
    "x-content-type-options": "nosniff",
    "strict-transport-security": HSTS,
    "content-security-policy": API_CSP,
  };
  if (cors) headers["access-control-allow-origin"] = "*";
  return new Response(body, { status, headers });
}

export function json(doc, status) {
  return apiResponse(JSON.stringify(doc), status, "no-store");
}
