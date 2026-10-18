// A fake set of explorer API origins for the Worker tests: each checks the
// Worker's per-request HMAC (deploy/explorer-api auth_failure) and signs its
// answer with its chain identity (Handler.send), as the real API does.
// Not a test file itself (no .test.mjs suffix).
import { requestMac, responseMac, SIGNED_HEADERS, resetOriginHealth } from "../../worker/index.js";

export const KEY = "worker-test-key-0123456789abcdef0123";
export const GENESIS = "ab".repeat(32);
export const FINAL = `100:${"cd".repeat(32)}`;
export const N1 = "https://node1.obenblock.xyz:2087";
export const N2 = "https://node2.obenblock.xyz:2087";
export const N3 = "https://node3.obenblock.xyz:2087";

const enc = new TextEncoder();
const ok = (result) => ({ status: 200, body: JSON.stringify({ result }) });

/**
 * Install `origins` ({ base: options }) as globalThis.fetch and an empty edge
 * cache. Options: chain, genesis, finalized, tip, down (throws), key (signs
 * answers with another key), unsigned, handler({ url, init }) -> {status, body}.
 * Returns { seen, probes }: the non-probe requests and the health probes.
 */
export function installOrigins(origins, { cache = true } = {}) {
  resetOriginHealth();
  const seen = [], probes = [];
  if (cache) globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(String(url));
    const o = origins[u.origin];
    if (!o || o.down) throw new Error(`${u.origin} unreachable`);
    const h = init.headers || {};
    const method = init.method || "GET";
    const want = await requestMac(KEY, method, u.pathname + u.search, h["x-obb-ts"], h["x-obb-nonce"], SIGNED_HEADERS.map((n) => h[n] ?? ""));
    if (h["x-obb-auth"] !== want) return new Response('{"error":"bad authentication"}', { status: 403 });
    const probe = h["x-obb-probe"] === "1";
    (probe ? probes : seen).push({ url: String(url), origin: u.origin, init });
    let answer;
    if (probe) answer = ok({ tip_height: o.tip ?? 120, finalized_height: 100 });
    else answer = o.handler ? await o.handler({ url: u, init }) : ok({ method: u.pathname });
    const identity = [o.chain ?? "0x4f420001", o.genesis ?? GENESIS, o.finalized ?? FINAL];
    const headers = { "x-obb-chain-id": identity[0], "x-obb-genesis": identity[1], "x-obb-finalized": identity[2],
                      "cache-control": "public, max-age=31536000" };
    if (!o.unsigned) headers["x-obb-resp-auth"] = await responseMac(o.key ?? KEY, h["x-obb-nonce"], answer.status, ...identity, enc.encode(answer.body));
    return new Response(answer.body, { status: answer.status, headers });
  };
  return { seen, probes };
}

export const envFor = (extra = {}) => ({
  ASSETS: { fetch: async () => new Response("<!doctype html>") },
  OBB_ORIGINS: `${N1},${N2},${N3}`, OBB_API_KEY: KEY, ...extra,
});
