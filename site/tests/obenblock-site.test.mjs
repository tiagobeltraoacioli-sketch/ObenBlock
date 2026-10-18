// ObenBlock specifics of the explorer views, the wallet page and the Worker:
// SHA-256d difficulty and hashrate units, PoWit finality views (hostile data
// stays inert), the wallet's node-network guard, OBB_* configuration and the
// obenblock.xyz redirects.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as V from "../assets/explorer-views.js";
import worker, { originsOf, redirectFor, ttlFor } from "../../worker/index.js";

const EVIL = `"><img src=x onerror=alert(1)><script>alert(2)</script>" onmouseover="alert(3)`;
const H = "ab".repeat(32);
const H2 = "cd".repeat(32);
const A = "obb1q" + "cd".repeat(24);

function assertInert(markup, where) {
  const s = String(markup);
  for (const bad of ["<img", "<script", "javascript:", `" onmouseover=`]) {
    assert.ok(!s.includes(bad), `${where}: found ${bad} in ${s.slice(Math.max(0, s.indexOf(bad) - 80), s.indexOf(bad) + 80)}`);
  }
}

test("SHA-256d difficulty is on Bitcoin's scale and hashrate reaches ASIC units", () => {
  // The target of bits 0x1d00ffff (ObenBlock's pow limit) is difficulty 1.
  assert.equal(V.targetDifficulty("00000000ffff" + "0".repeat(52)), 1);
  assert.equal(V.targetDifficulty("0x00000000ffff" + "0".repeat(52)), 1);
  // Bitcoin bits 0x1c00ffff: 256.
  assert.equal(V.targetDifficulty("0000000000ffff" + "0".repeat(50)), 256);
  for (const bad of ["", "zz", EVIL, null, "0"]) assert.equal(V.targetDifficulty(bad), 0, String(bad));
  assert.equal(V.hashrate(1.2e18), "1.20 EH/s");
  assert.equal(V.hashrate(350e12), "350.0 TH/s");
  assert.equal(V.hashrate(4.5e6), "4.50 MH/s");
  assert.equal(V.hashrate(EVIL), "—");
  assert.equal(V.diff(3.5e12), "3.50T");
  assert.equal(V.diff(1), "1.00");
  assert.equal(V.diff(0.00042), "0.000420");
});

test("finality views render forged data inertly", () => {
  const block = {
    hash: H, height: 7, colour: "chain", finality: EVIL, finalized_height: EVIL, pow_hash: EVIL, version: EVIL,
    bits: "0x1d00ffff", difficulty: 1, parents: [], mergeset_blues: [], mergeset_reds: [], transactions: [],
  };
  const full = { powit: { shares: EVIL, attestations: [{ witness: EVIL, source: { slot: EVIL }, target: EVIL, kes_epoch: EVIL }], evidence: [EVIL] } };
  assertInert(V.blockPage(block, full), "blockPage with PoWit");
  assertInert(V.blockPage({ ...block, finality: "finalized", pow_hash: H2 }, { powit: EVIL }), "blockPage with forged powit");
  const pw = {
    finalized: { slot: EVIL, hash: EVIL, block_height: EVIL }, justified: EVIL, tip_height: EVIL, epoch: EVIL,
    params: { epoch_len: EVIL, checkpoint_interval: EVIL, max_witnesses: EVIL, window_epochs: EVIL },
    witness_set: { size: EVIL, top: [{ key: EVIL, weight: EVIL }, EVIL] }, barred_keys: EVIL, exited_keys: EVIL,
    inactivity_leak: EVIL,
  };
  const info = { pin: { hash: EVIL, block_height: EVIL }, origin: EVIL, anchor: { hash: H, block_height: EVIL }, anchor_status: EVIL, conflict: EVIL };
  const blocks = [{ hash: EVIL, height: EVIL, powit: { attestations: [{ witness: EVIL, source: EVIL, target: { slot: EVIL }, kes_epoch: EVIL }], shares: [EVIL] } }, EVIL, null];
  assertInert(V.finalityPage(pw, info, blocks), "finalityPage");
  assertInert(V.finalityPage(EVIL, EVIL, EVIL), "finalityPage, all forged");
  const dag = { tip_height: EVIL, tip_blue_score: EVIL, block_count: EVIL, tip_count: EVIL, k: EVIL, finalized_height: EVIL };
  const supply = { issued_sat: EVIL, next_halving_height: EVIL, current_height: EVIL, subsidy_per_block_sat: EVIL, min_tx_fee_sat: EVIL };
  assertInert(V.homeStats({ dag, supply, stats: { hashrate_hs: EVIL }, pct: {}, chain: { blocks: [] }, mem: {}, pw }), "homeStats with PoWit");
  assertInert(V.txPage({ status: "confirmed", block_hash: H, block_height: 3, block_colour: "chain", finality: EVIL, transaction: {} }), "txPage");
  assertInert(V.blocksTable([{ hash: H, height: 1, finality: EVIL }]), "blocksTable");
  assertInert(V.addressPage(A, { items: [{ height: 1, txid: H, direction: "in", amount: "1", finality: EVIL }] }, null, 0, 25), "addressPage");
});

test("valid finality and SHA-256d data render", () => {
  const b = String(V.blockPage({ hash: H, height: 9, colour: "chain", finality: "finalized", finalized_height: 12, pow_hash: H2,
    version: 0x20000000, nonce: 5, bits: "0x1d00ffff", difficulty: 1, parents: [], mergeset_blues: [], mergeset_reds: [], transactions: [] },
  { powit: { shares: [{}, {}], attestations: [{ witness: "ee".repeat(32), source: { slot: 96 }, target: { slot: 112 }, kes_epoch: 4 }], evidence: [] } }));
  assert.ok(b.includes("Finalized by PoWit"));
  assert.ok(b.includes(H2), "the PoW hash in Bitcoin byte order");
  assert.ok(b.includes("0x20000000"));
  assert.ok(b.includes("slot 96 → 112"));
  const pending = String(V.blockPage({ hash: H, height: 20, colour: "chain", finality: "pending", finalized_height: 12, parents: [], transactions: [] }));
  assert.ok(pending.includes("Not final yet") && pending.includes("#12"));
  const page = String(V.finalityPage({ finalized: { slot: 96, hash: H, block_height: 100 }, justified: { slot: 112, hash: H2, block_height: 116 },
    tip_height: 130, epoch: 5, params: { epoch_len: 96, checkpoint_interval: 16, max_witnesses: 128, window_epochs: 112 },
    witness_set: { size: 1, top: [{ key: "ee".repeat(32), weight: "42" }] }, barred_keys: 0, exited_keys: 0, inactivity_leak: "1/2" }, null, []));
  assert.ok(page.includes(`href="#/block/${H}"`) && page.includes("30 blocks above finality") && page.includes("1/2"));
  const table = String(V.blocksTable([{ hash: H, height: 1, finality: "finalized" }, { hash: H2, height: 2, finality: "pending" }]));
  assert.ok(table.includes(">final<") && table.includes(">pending<"));
  const home = String(V.homeStats({ dag: { tip_height: 130, finalized_height: 100 }, supply: {}, stats: {}, pct: {}, chain: { blocks: [] }, mem: {},
    pw: { finalized: { block_height: 100 }, epoch: 5, witness_set: { size: 3 } } }));
  assert.ok(home.includes('href="#/finality"') && home.includes("30 blocks below the tip") && home.includes("3 witnesses"));
});

test("the wallet page signs only for the network the site's ObenBlock node runs", () => {
  const app = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8");
  // The node's network comes from its chain id, never from a default.
  assert.match(app, /node\.network = networkOfChainId\(info\.chain_id\);/);
  // Before signing and again before broadcasting.
  const review = app.indexOf("await refreshNode();\n      requireNodeNetwork(state.network);");
  const pay = app.indexOf("const tx = core.pay(coins, ");
  assert.ok(review > 0 && pay > review, "requireNodeNetwork must run before core.pay");
  const send = app.indexOf("await broadcast(state.pending.raw);");
  assert.ok(app.lastIndexOf("requireNodeNetwork(state.network);", send) > pay, "and again before the broadcast");
  // A destination of the other network is refused before signing.
  assert.match(app, /walletNetwork\(dest\.network\) !== state\.network/);
  assert.ok(!/gnb-wallet-/.test(app), "keystores download as obenblock-wallet-*.json");
});

const assets = { fetch: async (req) => new Response(`asset ${new URL(req.url).pathname}`) };
const ctx = { waitUntil() {} };

test("the Worker reads OBB_* first and falls back to GNB_*", async () => {
  assert.deepEqual(originsOf({ OBB_ORIGINS: "https://a.example.net", GNB_ORIGINS: "https://b.example.net" }), ["https://a.example.net"]);
  assert.deepEqual(originsOf({ GNB_ORIGINS: "https://b.example.net" }), ["https://b.example.net"]);
  assert.deepEqual(originsOf({}), []);
  const originalFetch = globalThis.fetch, originalCaches = globalThis.caches;
  const seen = [];
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  globalThis.fetch = async (url, init) => { seen.push([String(url), init.headers]); return new Response('{"result":{}}'); };
  try {
    const env = { ASSETS: assets, OBB_ORIGINS: "https://o.example.net", OBB_API_KEY: "obb-key", GNB_API_KEY: "gnb-key" };
    assert.equal((await worker.fetch(new Request("https://obenblock.xyz/api/getfinalityinfo"), env, ctx)).status, 200);
    assert.equal(seen[0][0], "https://o.example.net/v1/getfinalityinfo?p=%5B%5D");
    assert.equal(seen[0][1]["x-gnb-key"], "obb-key");
    await worker.fetch(new Request("https://obenblock.xyz/api/getpowitinfo"), { ASSETS: assets, GNB_ORIGINS: "https://g.example.net", GNB_API_KEY: "gnb-key" }, ctx);
    assert.equal(seen[1][1]["x-gnb-key"], "gnb-key");
  } finally { globalThis.fetch = originalFetch; globalThis.caches = originalCaches; }
  assert.ok(ttlFor("getfinalityinfo") <= 5 && ttlFor("getpowitinfo") <= 5);
});

test("www and the retired GnB pages redirect; the API and broadcasts never do", async () => {
  const env = { ASSETS: assets, CANONICAL_HOST: "obenblock.xyz" };
  const get = (url, init) => worker.fetch(new Request(url, init), env, ctx);
  let r = await get("https://www.obenblock.xyz/explorer?x=1");
  assert.equal(r.status, 301);
  assert.equal(r.headers.get("location"), "https://obenblock.xyz/explorer?x=1");
  assert.ok(r.headers.get("strict-transport-security"));
  r = await get("https://www.obenblock.xyz/wallet/");
  assert.equal(r.headers.get("location"), "https://obenblock.xyz/wallet");
  for (const [from, to] of [["/wallet/", "/wallet"], ["/wallet/index.html", "/wallet"], ["/explorer/", "/explorer"], ["/explorer/index.html", "/explorer"]]) {
    r = await get(`https://obenblock.xyz${from}`);
    assert.equal(r.status, 301, from);
    assert.equal(r.headers.get("location"), `https://obenblock.xyz${to}`);
  }
  for (const path of ["/", "/wallet", "/explorer", "/wallet/app.js", "/wallet/gnb_wallet.wasm"]) {
    r = await get(`https://obenblock.xyz${path}`);
    assert.equal(r.status, 200, path);
    assert.equal(await r.text(), `asset ${path}`);
  }
  const api = new Request("https://www.obenblock.xyz/api/sendrawtransaction", { method: "POST", body: "{}", headers: { "content-type": "application/json" } });
  assert.equal(redirectFor(api, new URL(api.url), env), null);
  const read = new Request("https://www.obenblock.xyz/api/getblockcount");
  assert.equal(redirectFor(read, new URL(read.url), env), null);
  // Without CANONICAL_HOST, www is served as is.
  r = await worker.fetch(new Request("https://www.obenblock.xyz/explorer"), { ASSETS: assets }, ctx);
  assert.equal(r.status, 200);
});

test("wrangler.toml names the obenblock Worker, its domains and no secret", () => {
  const toml = readFileSync(new URL("../../wrangler.toml", import.meta.url), "utf8");
  assert.match(toml, /^name = "obenblock"$/m);
  assert.match(toml, /\{ pattern = "obenblock\.xyz", custom_domain = true \}/);
  assert.match(toml, /\{ pattern = "www\.obenblock\.xyz", custom_domain = true \}/);
  assert.match(toml, /^CANONICAL_HOST = "obenblock\.xyz"$/m);
  assert.ok(!/^\s*(OBB|GNB)_(API_KEY|ORIGINS)\s*=/m.test(toml), "secrets are set with wrangler secret put, never in the file");
  assert.ok(!/gnb-smh\.com/.test(toml));
});
