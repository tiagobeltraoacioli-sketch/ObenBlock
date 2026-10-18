import { isAddress } from "../site/assets/safe.js";

// obenblock.xyz: static site plus a read-only explorer API proxy.
//
//   /api/<method>?p=<JSON params>  -> origin /v1/<method>  (edge-cached briefly)
//   POST /api/sendrawtransaction   -> origin /v1/sendrawtransaction (broadcast)
//   everything else                -> static assets in ./site
//
// The origin is the explorer API (deploy/explorer-api) on an ObenBlock node.
// Pre-launch review:
// - Origins are host names inside the owner's zone (OBB_ORIGINS, e.g.
//   https://node1.obenblock.xyz:2087; entries outside OBB_ORIGIN_ZONE are
//   ignored). OBB_FALLBACK_ORIGINS (the launch wildcard-DNS names that embed the address) are used only
//   while no in-zone origin is usable. Configuration, never code
//   (worker/README.md).
// - Every request to an origin is signed per request with the secret
//   OBB_API_KEY (HMAC over method, target, timestamp, nonce, the forwarded
//   headers and the body hash; requestMac), and every answer must come back
//   signed over the same nonce together with the node's chain id, genesis
//   hash and finalized checkpoint (responseMac). An answer that is not
//   signed, or names another chain than OBB_CHAIN_ID / OBB_GENESIS_HASH, is
//   discarded: a host that obtained the DNS name or a certificate cannot
//   answer for the origin without the key.
// - Reads go to the origins that agree on the finalized checkpoint (the
//   largest group, then the highest checkpoint; selectOrigins), freshest
//   tip first; a 404 is retried on the others of that set. Broadcasts go to
//   every healthy origin of the pinned chain at once.
// - Answers carry X-OBB-Chain-Id, X-OBB-Genesis and X-OBB-Finalized, so the
//   wallet can bind its session to one chain (site/wallet/core.js).
// The GnB names GNB_ORIGINS / GNB_API_KEY are no longer read.
//
// Redirects (GET/HEAD of pages only, never /api/*):
// - www.<CANONICAL_HOST> -> CANONICAL_HOST (variable; unset: no redirect);
// - the retired GnB pages /wallet/ and /explorer/ -> /wallet and /explorer
//   (the fragment, e.g. #/tx/<id>, is kept by the browser).
//
// Audit fixes:
// - WAL-2: origins come from the OBB_ORIGINS / OBB_FALLBACK_ORIGINS variables (comma- or space-
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
const HEX64 = /^[0-9a-f]{64}$/;

// Fixed edge TTLs (seconds). Anything not listed uses DEFAULT_TTL.
const DEFAULT_TTL = 5;
const TTL = {
  getbalance: 2, getutxos: 2, getaddresshistory: 5, getrawmempool: 5, getmempoolstats: 5,
  getblockcount: 3, getdaginfo: 3, getselectedchain: 3, getdagwindow: 3,
  getchainstats: 30, gethashrate: 30, getdifficultyhistory: 30, getblocktimepercentiles: 30,
  getrichlist: 60, getsupplydistribution: 60, getrawtransaction: 60, carryover: 300,
  getpowitinfo: 3, getfinalityinfo: 5, getnetworkinfo: 5,
};
export const ttlFor = (path) => TTL[path.split("/")[0]] ?? DEFAULT_TTL;

/** https:// origins from a configuration string; anything else is dropped. */
export function parseOrigins(value) {
  return String(value || "").split(/[\s,]+/).map((s) => s.trim().replace(/\/+$/, "")).filter((s) => {
    try { const u = new URL(s); return u.protocol === "https:" && !u.username && !u.password && u.pathname === "/" && !u.search && !u.hash; }
    catch { return false; }
  });
}

// ── origins and the chain they must serve (pre-launch review) ───────────────
export const DEFAULT_CHAIN_ID = "0x4f420001";
export const DEFAULT_ORIGIN_ZONE = "obenblock.xyz";
const HEALTH_TTL_MS = 10000;
const PROBE_TIMEOUT_MS = 4000;

/** The zone the primary origins must be named in (OBB_ORIGIN_ZONE). */
export const originZone = (env) => String(env.OBB_ORIGIN_ZONE ?? DEFAULT_ORIGIN_ZONE).trim().toLowerCase().replace(/^\.+|\.+$/g, "");

export function inZone(origin, zone) {
  const host = new URL(origin).hostname.toLowerCase();
  return zone !== "" && (host === zone || host.endsWith(`.${zone}`));
}

/** `primary`: the OBB_ORIGINS inside the zone; `fallback`: OBB_FALLBACK_ORIGINS
 *  (any https host, e.g. wildcard-DNS names), used only while no primary
 *  origin is usable. */
export function originsOf(env) {
  const zone = originZone(env);
  const primary = parseOrigins(env.OBB_ORIGINS).filter((o) => inZone(o, zone));
  const fallback = parseOrigins(env.OBB_FALLBACK_ORIGINS).filter((o) => !primary.includes(o));
  return { primary, fallback };
}

/** The chain every answer must come from: OBB_CHAIN_ID (default ObenBlock
 *  mainnet) and, once known, OBB_GENESIS_HASH. `error` on a malformed value. */
export function expectedIdentity(env) {
  const chain = String(env.OBB_CHAIN_ID || DEFAULT_CHAIN_ID).trim().toLowerCase();
  const genesis = String(env.OBB_GENESIS_HASH || "").trim().toLowerCase();
  if (!/^0x[0-9a-f]{8}$/.test(chain)) return { error: "OBB_CHAIN_ID is malformed" };
  if (genesis && !HEX64.test(genesis)) return { error: "OBB_GENESIS_HASH is malformed" };
  return { chain, genesis: genesis || null };
}

/** True when an answer's identity is the chain `want` names. */
export function identityMatches(id, want) {
  if (!id || id.chain !== want.chain || !HEX64.test(id.genesis || "")) return false;
  return want.genesis ? id.genesis === want.genesis : true;
}

/** "height:hash" of a finalized checkpoint, or null. */
export function parseFinalized(text) {
  const m = /^(\d{1,15}):([0-9a-f]{64})$/.exec(String(text || ""));
  return m ? { height: Number(m[1]), hash: m[2] } : null;
}

/**
 * The origins to use, from health probes `results` ({origin, ok, identity,
 * tip}): only those on the expected chain; without a pinned genesis, those
 * of the genesis most of them report (a tie is refused); then the largest
 * group agreeing on the finalized checkpoint (ties: the highest checkpoint;
 * two different checkpoints at the same height and support are refused),
 * freshest tip first. `all` is every origin on the chain (broadcasts).
 */
export function selectOrigins(results, want) {
  let ok = results.filter((r) => r.ok && identityMatches(r.identity, want));
  const none = (error) => ({ set: [], all: [], identity: null, finalized: null, error });
  if (!ok.length) return none(null);
  const tally = (rows, keyOf) => {
    const m = new Map();
    for (const r of rows) { const k = keyOf(r); m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()].map(([key, n]) => ({ key, n }));
  };
  if (!want.genesis) {
    const g = tally(ok, (r) => r.identity.genesis).sort((a, b) => b.n - a.n);
    if (g.length > 1 && g[0].n === g[1].n) return none("origins disagree on the genesis hash (set OBB_GENESIS_HASH)");
    ok = ok.filter((r) => r.identity.genesis === g[0].key);
  }
  const heightOf = (key) => parseFinalized(key)?.height ?? -1;
  const groups = tally(ok, (r) => (parseFinalized(r.identity.finalized) ? r.identity.finalized : ""))
    .sort((a, b) => b.n - a.n || heightOf(b.key) - heightOf(a.key));
  if (groups.length > 1 && groups[0].n === groups[1].n && heightOf(groups[0].key) === heightOf(groups[1].key)) {
    return none("origins disagree on the finalized checkpoint");
  }
  const best = groups[0].key;
  const set = ok.filter((r) => (parseFinalized(r.identity.finalized) ? r.identity.finalized : "") === best)
    .sort((a, b) => (b.tip ?? -1) - (a.tip ?? -1)).map((r) => r.origin);
  return { set, all: ok.map((r) => r.origin), identity: { chain: want.chain, genesis: ok[0].identity.genesis }, finalized: best || null, error: null };
}

// ── Worker-to-origin authentication (deploy/explorer-api request_mac) ───────
const enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256Hex = async (data) => toHex(await crypto.subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
const keys = new Map();
async function hmacHex(secret, message) {
  let key = keys.get(secret);
  if (!key) {
    key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    keys.set(secret, key);
  }
  return toHex(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}
export const SIGNED_HEADERS = ["x-gnb-client-ip", "x-gnb-cross-site", "x-obb-page-origin", "x-obb-probe", "x-obb-body-sha256"];
export const requestMac = (secret, method, target, ts, nonce, values) =>
  hmacHex(secret, ["OBB-ORIGIN-v1", method, target, String(ts), nonce, ...values].join("\n"));
export async function responseMac(secret, nonce, status, chainId, genesis, finalized, body) {
  return hmacHex(secret, ["OBB-ORIGIN-RESP-v1", nonce, String(status), chainId, genesis, finalized, await sha256Hex(body)].join("\n"));
}
function sameHex(a, b) {
  if (typeof a !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** The shared secret: at least 32 characters, else none (503). */
const apiKeyOf = (env) => (typeof env.OBB_API_KEY === "string" && env.OBB_API_KEY.length >= 32 ? env.OBB_API_KEY : null);

/**
 * One signed request to `origin` and its verified answer: { status, body
 * (text), identity: {chain, genesis, finalized} }. Throws when the origin is
 * unreachable or the answer is not signed with the key over this request's
 * nonce (an impostor, or the slot-cap 503 of an overloaded origin).
 */
export async function originFetch(env, origin, method, target, { headers = {}, body = "", timeout = 8000 } = {}) {
  const secret = apiKeyOf(env);
  // Sign the target exactly as fetch() will send it (the URL parser
  // percent-encodes some characters encodeURIComponent leaves, such as ').
  const url = new URL(`${origin}${target}`);
  target = url.pathname + url.search;
  const h = {};
  for (const [k, v] of Object.entries(headers)) if (v !== undefined && v !== null && v !== "") h[k.toLowerCase()] = String(v);
  h["x-obb-body-sha256"] = await sha256Hex(body);
  const ts = Math.floor(Date.now() / 1000);
  const nonce = toHex(crypto.getRandomValues(new Uint8Array(16)));
  h["x-obb-ts"] = String(ts);
  h["x-obb-nonce"] = nonce;
  h["x-obb-auth"] = await requestMac(secret, method, target, ts, nonce, SIGNED_HEADERS.map((n) => h[n] ?? ""));
  const init = { method, headers: h, redirect: "manual", signal: AbortSignal.timeout(timeout) };
  if (method === "GET") init.cf = { cacheTtl: 0, cacheEverything: false };
  else init.body = body;
  const r = await fetch(url.toString(), init);
  const bytes = new Uint8Array(await r.arrayBuffer());
  const identity = {
    chain: (r.headers.get("x-obb-chain-id") || "").trim().toLowerCase(),
    genesis: (r.headers.get("x-obb-genesis") || "").trim().toLowerCase(),
    finalized: (r.headers.get("x-obb-finalized") || "").trim().toLowerCase(),
  };
  const want = await responseMac(secret, nonce, r.status, identity.chain, identity.genesis, identity.finalized, bytes);
  if (!sameHex((r.headers.get("x-obb-resp-auth") || "").trim().toLowerCase(), want)) throw new Error("unauthenticated origin answer");
  return { status: r.status, body: new TextDecoder().decode(bytes), identity, origin };
}

/** Probe one origin: getdaginfo, signed both ways, on the expected chain. */
async function probe(env, origin, want) {
  try {
    const r = await originFetch(env, origin, "GET", "/v1/getdaginfo?p=%5B%5D", { headers: { "x-obb-probe": "1" }, timeout: PROBE_TIMEOUT_MS });
    if (r.status !== 200) return { origin, ok: false, why: `HTTP ${r.status}` };
    if (!identityMatches(r.identity, want)) return { origin, ok: false, why: `chain ${r.identity.chain || "?"} genesis ${r.identity.genesis || "?"}`, identity: r.identity };
    let tip = null;
    try { const t = JSON.parse(r.body)?.result?.tip_height; if (Number.isSafeInteger(t)) tip = t; } catch {}
    return { origin, ok: true, identity: r.identity, tip };
  } catch (e) {
    return { origin, ok: false, why: String(e?.message || e) };
  }
}

// Per isolate: the last selection (plain data only; every request that finds
// it stale probes for itself, no I/O is shared between requests).
let health = null;
export function resetOriginHealth() { health = null; }
const forgetHealth = () => { if (health) health.at = 0; };

/** The current origin selection (selectOrigins), probing when stale. */
export async function originHealth(env) {
  const want = expectedIdentity(env);
  if (want.error) return { set: [], all: [], identity: null, error: want.error, probes: [] };
  const cfg = JSON.stringify([env.OBB_ORIGINS, env.OBB_FALLBACK_ORIGINS, env.OBB_ORIGIN_ZONE, want]);
  const now = Date.now();
  if (health && health.cfg === cfg && now - health.at < HEALTH_TTL_MS) return health.sel;
  const { primary, fallback } = originsOf(env);
  let probes = await Promise.all(primary.map((o) => probe(env, o, want)));
  let sel = selectOrigins(probes, want);
  if (!sel.set.length && !sel.error && fallback.length) {
    const more = await Promise.all(fallback.map((o) => probe(env, o, want)));
    probes = probes.concat(more);
    sel = { ...selectOrigins(more, want), fallback: true };
  }
  sel.probes = probes.map(({ origin, ok, why, tip, identity }) => ({ origin, ok, why: why ?? null, tip: tip ?? null, finalized: identity?.finalized || null }));
  health = { cfg, at: now, sel };
  return sel;
}

/** The chain-identity headers of an answer, for the wallet's session pin. */
const identityHeaders = (id) => ({ "x-obb-chain-id": id.chain, "x-obb-genesis": id.genesis, "x-obb-finalized": id.finalized });
const PAGE_ORIGIN = /^(?:null|https?:\/\/[a-z0-9.-]{1,253}(?::[0-9]{1,5})?)$/;

// Pages of the GnB site that ObenBlock does not serve: its sidechain wallet
// and its older explorer.
const RETIRED = new Map([
  ["/wallet/", "/wallet"], ["/wallet/index.html", "/wallet"],
  ["/explorer/", "/explorer"], ["/explorer/index.html", "/explorer"],
]);

/** A 301 for a page request that has a canonical location, or null. */
export function redirectFor(request, url, env) {
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  if (url.pathname.startsWith("/api/")) return null;
  const canonical = typeof env.CANONICAL_HOST === "string" ? env.CANONICAL_HOST.trim().toLowerCase() : "";
  let target = null;
  if (canonical && url.hostname === `www.${canonical}`) {
    target = new URL(url);
    target.hostname = canonical;
  }
  if (RETIRED.has(url.pathname)) {
    target = target || new URL(url);
    target.pathname = RETIRED.get(url.pathname);
  }
  if (!target) return null;
  return withSecurityHeaders(url, new Response(null, { status: 301, headers: { location: target.toString() } }));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) {
      return redirectFor(request, url, env) || withSecurityHeaders(url, await env.ASSETS.fetch(request));
    }
    const { primary, fallback } = originsOf(env);
    if (!primary.length && !fallback.length) return json({ error: "explorer backend not configured" }, 503);
    if (!apiKeyOf(env)) return json({ error: "explorer backend not configured (OBB_API_KEY)" }, 503);
    if (url.pathname === "/api/originstatus") return originStatus(request, env);
    if (url.pathname === "/api/sendrawtransaction") return broadcast(request, env);
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
    const rest = url.pathname.slice(5).split("/").filter(Boolean);
    if (!rest.length || !rest.every((s) => NAME.test(s) || isAddress(s))) {
      return json({ error: "not found" }, 404);
    }
    const p = url.searchParams.get("p") || "[]";
    if (p.length > 512) return json({ error: "params too long" }, 400);
    const path = rest.join("/");
    const ttl = ttlFor(path);

    const sel = await originHealth(env);
    if (sel.error) return json({ error: `explorer backend refused: ${sel.error}` }, 503);
    if (!sel.set.length) return json({ error: "explorer backend unavailable" }, 502);
    // The chain is part of the cache key: an answer cached for one chain is
    // never served for another.
    const cacheKey = new Request(`https://cache.obenblock.xyz/${sel.identity.chain}/${sel.identity.genesis}/${path}?p=${encodeURIComponent(p)}`);
    const cache = caches.default;
    const hit = await cache.match(cacheKey);
    if (hit) return hit;

    // B2-R2-2 (reads): a cross-site read is charged to the budget the
    // cross-site reads of its page origin share (deploy/explorer-api).
    const extra = {};
    if (isCrossSite(request, url)) {
      extra["x-gnb-cross-site"] = "1";
      const origin = (request.headers.get("origin") || "").trim().toLowerCase();
      if (PAGE_ORIGIN.test(origin)) extra["x-obb-page-origin"] = origin;
    }
    const target = `/v1/${path}?p=${encodeURIComponent(p)}`;
    let notFound = null;
    for (const origin of sel.set) {
      let r;
      try {
        r = await originFetch(env, origin, "GET", target, { headers: forwarded(request, extra) });
      } catch {
        forgetHealth();
        continue;
      }
      if (!identityMatches(r.identity, sel.identity)) { forgetHealth(); continue; }
      if (r.status >= 500 || (r.status >= 300 && r.status < 400)) continue;
      // A lagging origin may not know a fresh transaction or block yet: ask
      // the others of the agreeing set before answering 404.
      if (r.status === 404) { notFound = notFound || r; continue; }
      const resp = apiResponse(r.body, r.status, r.status === 200 ? `public, max-age=${ttl}` : "no-store", { extra: identityHeaders(r.identity) });
      if (r.status === 200) ctx.waitUntil(cache.put(cacheKey, resp.clone()));
      return resp;
    }
    if (notFound) return apiResponse(notFound.body, 404, "no-store", { extra: identityHeaders(notFound.identity) });
    return json({ error: "explorer backend unavailable" }, 502);
  },
};

/** The headers forwarded to the origin (all of them signed). */
function forwarded(request, extra = {}) {
  return { "x-gnb-client-ip": request.headers.get("cf-connecting-ip") || "", ...extra };
}

/** Which origins answer and which serve reads (no secrets; never cached). */
async function originStatus(request, env) {
  if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
  const sel = await originHealth(env);
  return json({
    result: {
      chain_id: sel.identity?.chain ?? null, genesis: sel.identity?.genesis ?? null, finalized: sel.finalized ?? null,
      fallback: sel.fallback === true, error: sel.error ?? null, reading: sel.set, broadcasting: sel.all,
      origins: (sel.probes || []).map((p) => ({ host: new URL(p.origin).host, ok: p.ok, why: p.why, tip: p.tip, finalized: p.finalized })),
    },
  }, 200);
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
 * host's) is refused: only the site's own pages (site/wallet/app.js, a
 * same-origin JSON fetch) and non-browser
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
// nor read the result. Pre-launch review: the transaction goes to EVERY
// healthy origin of the pinned chain at once (a lagging or minority node
// alone could accept it and leave it off the majority chain); it is sent
// when any accepts it, and the answer says how many did.
async function broadcast(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST") return broadcastJson({ error: "method not allowed" }, 405);
  const refusal = broadcastRefusal(request, url);
  if (refusal) return broadcastJson({ error: refusal[1] }, refusal[0]);
  const len = Number(request.headers.get("content-length") || "0");
  if (!(len > 0 && len <= 820000)) return broadcastJson({ error: "body size out of range" }, 413);
  const body = await request.text();
  const sel = await originHealth(env);
  if (sel.error) return broadcastJson({ error: `broadcast backend refused: ${sel.error}` }, 503);
  const targets = sel.all;
  const answers = await Promise.all(targets.map((origin) =>
    originFetch(env, origin, "POST", "/v1/sendrawtransaction", {
      headers: forwarded(request, { "content-type": "application/json" }), body, timeout: 20000,
    }).then((r) => (identityMatches(r.identity, sel.identity) ? r : null), () => null)));
  if (answers.some((a) => a === null)) forgetHealth();
  const accepted = answers.filter((a) => a && a.status === 200);
  const tally = { "x-obb-broadcast-accepted": `${accepted.length}/${targets.length}` };
  if (accepted.length) {
    return apiResponse(accepted[0].body, 200, "no-store", { cors: false, extra: { ...identityHeaders(accepted[0].identity), ...tally } });
  }
  const rejected = answers.find((a) => a && a.status >= 400 && a.status < 500);
  if (rejected) return apiResponse(rejected.body, rejected.status, "no-store", { cors: false, extra: { ...identityHeaders(rejected.identity), ...tally } });
  return broadcastJson({ error: "broadcast backend unavailable" }, 502);
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
function apiResponse(body, status, cacheControl, { cors = true, extra = {} } = {}) {
  const headers = {
    "content-type": "application/json",
    "cache-control": cacheControl,
    "x-content-type-options": "nosniff",
    "strict-transport-security": HSTS,
    "content-security-policy": API_CSP,
    ...extra,
  };
  if (cors) {
    headers["access-control-allow-origin"] = "*";
    headers["access-control-expose-headers"] = "x-obb-chain-id, x-obb-genesis, x-obb-finalized";
  }
  return new Response(body, { status, headers });
}

export function json(doc, status) {
  return apiResponse(JSON.stringify(doc), status, "no-store");
}
