// Runtime routing tests: bounded public address fixtures, no network sockets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import * as safe from "../assets/safe.js";
import worker from "../../worker/index.js";
import { loadCore, walletNetwork } from "../wallet/core.js";

// ObenBlock (docs/DESIGN-obenblock.md §2): the node's validateaddress answers
// the obb1 form of every accepted alias; a key-hash checksum covers the hash
// only, a policy one covers the prefix (obb1m/obb1n get their own).
const LEGACY = "gnb1q0000000000000000000000000000000000000000335d2ee7";
const OBB = LEGACY.replace("gnb1q", "obb1q");
const V2 = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw";
const OBB_V2 = "obb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqvttus2";
const CASES = [
  [V2, OBB],
  [OBB_V2, OBB],
  ["tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc", LEGACY.replace("gnb1q", "obb1t")],
  ["tobb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2sa8wu", LEGACY.replace("gnb1q", "obb1t")],
  ["gnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqggmvny", "obb1m" + "00".repeat(32) + "e9a3ce56"],
  ["tgnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqht5fkx", "obb1n" + "00".repeat(32) + "a7824a8a"],
  [LEGACY, OBB],
  ["gnb1m" + "00".repeat(32) + "73aa6055", "obb1m" + "00".repeat(32) + "e9a3ce56"],
];
const POLICY = /^(?:obb|gnb)1[mn]/;
const src = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
const noImports = (s) => s.replace(/^import .*;\n/gm, "");
const walletBytes = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const walletPin = src("../wallet/app.js").match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];
async function realCore() {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(walletBytes);
  try { return await loadCore("/wallet/gnb_wallet.wasm", walletPin); }
  finally { globalThis.fetch = original; }
}

function explorer(path, address, valid = true) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { innerHTML: "", value: "", addEventListener(e, fn) { this[e] = fn; }, querySelectorAll: () => [] });
    return elements.get(id);
  };
  const canonical = CASES.find(([a]) => a === address.toLowerCase())?.[1] ?? address;
  const rpc = async (method, args) => {
    calls.push([method, args]);
    if (method === "validateaddress") return { isvalid: valid, canonical_address: valid ? canonical : undefined };
    // Match the dispatcher contract: history indexes only single-key hashes.
    if (method === "getaddresshistory" && POLICY.test(args[0])) throw new Error("invalid address");
    if (method === "getutxos") return { satoshis: "0", utxo_count: 0, utxos: [] };
    return { balance: "0", utxo_count: 0, total: 0, items: [] };
  };
  const context = vm.createContext({
    ...safe, __rpc: rpc, location: { hash: "#/address/" + address },
    document: { getElementById: element, querySelector: (s) => element(s.slice(1)), querySelectorAll: () => [], addEventListener: () => {} },
    window: { addEventListener: () => {}, scrollTo: () => {} },
    clearInterval() {}, clearTimeout() {}, setInterval() {}, setTimeout() {},
    fetch: async () => ({ json: async () => ({ result: { in_carryover: false } }) }),
    localStorage: { getItem: () => "" }, gnb: String, short: String, ago: String,
    V: { loading: () => "loading", fail: String, addressPage: (a) => a },
  });
  const script = noImports(src(path)).replace(/\nroute\(\);\s*$/, "");
  vm.runInContext(script + "\napi = __rpc;", context);
  return { context, calls, elements, route: () => vm.runInContext("route()", context), search: async (q) => {
    element("q").value = q;
    const el = element("search");
    await (el.submit || el.onsubmit)({ preventDefault() {} });
    return context.location.hash;
  } };
}

async function watch(path, address, accepts = true) {
  const calls = [];
  const core = await realCore();
  const code = src(path).slice(src(path).indexOf("// Shareable watch links:"));
  const context = vm.createContext({ ...safe, location: { hash: "#watch/" + address, pathname: "/wallet", search: "" },
    walletNetwork, paintNetBadge() {}, refreshNode: async () => {}, node: {}, state: { mode: "watch" },
    getCore: async () => ({ classify(a) { calls.push(["classify", a]); if (!accepts) throw Error("invalid address"); return core.classify(a); } }),
    enter: (mode, a, _notice, network) => calls.push([mode, a, network]), renderGate: () => calls.push(["gate"]),
  });
  await vm.runInContext(code, context);
  return calls;
}

test("obb1 and gnb1 address gate, explorer and watch links", async () => {
  assert.equal(safe.isAddress(OBB), true);
  assert.equal(safe.isAddress(LEGACY), true, "gnb1 strings stay accepted as aliases");
  const page = explorer("../explorer.js", OBB); await page.route();
  assert.ok(page.calls.some(([m, p]) => ["getaddresshistory", "getutxos"].includes(m) && p[0] === OBB));
  assert.ok(!page.calls.some(([m]) => m === "validateaddress"), "an obb1 string needs no normalization");
  for (const input of [OBB, OBB.toUpperCase(), LEGACY, LEGACY.toUpperCase()]) {
    page.context.location.hash = "#/";
    assert.equal(await page.search(input), "#/address/" + input.toLowerCase());
  }
  // A Bloch address is the same owner, shown as obb1.
  page.context.location.hash = "#/";
  assert.equal(await page.search(LEGACY.replace("gnb1q", "bloch1q")), "#/address/" + OBB);
  const gnb = explorer("../explorer.js", LEGACY); await gnb.route();
  assert.ok(gnb.calls.some(([m, p]) => m === "validateaddress" && p[0] === LEGACY));
  assert.ok(gnb.calls.some(([m, p]) => m === "getaddresshistory" && p[0] === OBB), "a gnb1 alias is shown as obb1");
  assert.deepEqual(await watch("../wallet/app.js", OBB), [["classify", OBB], ["watch", OBB, "mainnet"]]);
  assert.deepEqual(await watch("../wallet/app.js", LEGACY), [["classify", LEGACY], ["watch", OBB, "mainnet"]]);
  assert.deepEqual(await watch("../wallet/app.js", LEGACY.replace("gnb1q", "bloch1q")),
    [["classify", LEGACY.replace("gnb1q", "bloch1q")], ["watch", OBB, "mainnet"]]);
});

test("address syntax gate recognizes v2 and rejects unsafe path characters and mixed case", () => {
  for (const [a, legacy] of CASES) {
    assert.equal(safe.isAddress(legacy), true, legacy);
    assert.equal(safe.isAddress(legacy.toUpperCase()), false, "legacy strings are lowercase");
    for (const c of /^t?(?:gnb|obb)1z/.test(a) ? [a, a.toUpperCase()] : [a]) assert.equal(safe.isAddress(c), true, c);
  }
  for (const a of ["obb1x" + "00".repeat(24), "bloch1q" + "00".repeat(24), "tobb1zq" + "q".repeat(37)]) assert.equal(safe.isAddress(a), false, a);
  for (const a of [V2 + '"', V2 + "/extra", V2 + "\n", V2.slice(0, -1), "G" + V2.slice(1), null]) assert.equal(safe.isAddress(a), false, String(a));
});

for (const path of ["../explorer.js"]) {
  test(`${path} routes all aliases through RPC normalization and rejects invalid checksums`, async () => {
    for (const [a, legacy] of CASES) for (const input of new Set([a, a.toUpperCase()])) {
      if (input !== input.toLowerCase() && !/^t?(?:gnb|obb)1z/i.test(input)) continue; // legacy is lowercase only
      const page = explorer(path, input); await page.route();
      assert.ok(page.calls.some(([m, p]) => m === "validateaddress" && p[0] === input), `${input}: checksum authority not called`);
      if (POLICY.test(legacy)) {
        assert.ok(!page.calls.some(([m]) => m === "getaddresshistory"), "policy must not call the single-key history index");
        assert.match(page.elements.get("app").innerHTML, /history is not available for policy addresses/i);
      } else {
        assert.ok(page.calls.some(([m, p]) => ["getaddresshistory", "getutxos"].includes(m) && p[0] === legacy), `${input}: identity not canonicalized`);
      }
      page.context.location.hash = "#/";
      assert.equal(await page.search(input), "#/address/" + input);
    }
    const bad = V2.slice(0, -1) + "q", page = explorer(path, bad, false);
    await page.route();
    assert.ok(page.calls.some(([m]) => m === "validateaddress"));
    assert.ok(!page.calls.some(([m]) => ["getaddresshistory", "getutxos"].includes(m)));
    page.context.location.hash = "#/";
    assert.equal(await page.search("G" + V2.slice(1)), "#/");
  });
}

for (const path of ["../wallet/app.js"]) {
  test(`${path} watch links use real WASM and keep the single-key scope`, async () => {
    for (const [a, legacy] of CASES) for (const input of new Set([a, a.toUpperCase()])) {
      if (input !== input.toLowerCase() && !/^t?(?:gnb|obb)1z/i.test(input)) continue;
      const expected = POLICY.test(legacy) ? ["gate"] : ["watch", legacy, legacy.startsWith("obb1t") ? "regtest" : "mainnet"];
      assert.deepEqual(await watch(path, input), [["classify", input], expected], input);
    }
    for (const [, legacy] of CASES.filter(([, l]) => POLICY.test(l))) assert.deepEqual(await watch(path, legacy), [["classify", legacy], ["gate"]]);
    assert.deepEqual(await watch(path, V2, false), [["classify", V2], ["gate"]]);
    for (const a of [V2 + "/more", V2 + '"', "G" + V2.slice(1), OBB_V2 + "/x"]) assert.deepEqual(await watch(path, a), [["gate"]]);
  });
}

test("Worker forwards valid-shaped v2 aliases unchanged and retains legacy routing", async () => {
  const originalFetch = globalThis.fetch, originalCaches = globalThis.caches;
  const calls = [];
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  globalThis.fetch = async (url) => { calls.push(String(url)); return new Response('{"result":{}}'); };
  try {
    const env = { OBB_ORIGINS: "https://origin.example.net", OBB_API_KEY: "fixture" }, ctx = { waitUntil() {} };
    for (const a of [LEGACY, OBB, ...CASES.filter(([a]) => /^t?(?:gnb|obb)1z/.test(a)).flatMap(([a]) => [a, a.toUpperCase()])]) {
      const result = await worker.fetch(new Request(`https://example.net/api/carryover/${a}`), env, ctx);
      assert.equal(result.status, 200, a);
      assert.equal(calls.at(-1), `https://origin.example.net/v1/carryover/${a}?p=%5B%5D`);
    }
    for (const a of ["G" + V2.slice(1), V2 + "%22", V2 + "%2Fextra"]) {
      assert.equal((await worker.fetch(new Request(`https://example.net/api/carryover/${a}`), env, ctx)).status, 404);
    }
  } finally { globalThis.fetch = originalFetch; globalThis.caches = originalCaches; }
});
