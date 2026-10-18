// Pre-launch review (explorer-worker): the origins were identified only by
// third-party DNS names, authenticated by one static header, chosen as "the
// first that answers" without looking at their chain, and a broadcast went to
// one node. Now every request to an origin is HMAC-signed per request, every
// answer must come back signed with the node's chain identity, reads go to
// the origins that agree on the finalized checkpoint, and broadcasts go to
// every healthy origin of the pinned chain.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import worker, { requestMac, responseMac, originFetch, selectOrigins, originHealth, expectedIdentity, SIGNED_HEADERS } from "../../worker/index.js";
import { installOrigins, envFor, KEY, GENESIS, FINAL, N1, N2, N3 } from "./fake-origin.mjs";

const ctx = { waitUntil() {} };
const get = (path, headers = {}) => new Request(`https://obenblock.xyz/api/${path}`, { headers });
const BODY = JSON.stringify({ hex: "ab".repeat(100) });
const post = () => new Request("https://obenblock.xyz/api/sendrawtransaction", {
  method: "POST", body: BODY,
  headers: { "content-type": "application/json", "content-length": String(BODY.length), origin: "https://obenblock.xyz", "sec-fetch-site": "same-origin" },
});
const answering = (seen) => seen.map((s) => s.origin);

test("the MACs match the explorer API's (shared vectors with test_gnb_explorer_api.py)", async () => {
  const key = "test-key-0123456789-0123456789-0123", nonce = "00112233445566778899aabbccddeeff";
  const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  assert.equal(await requestMac(key, "GET", "/v1/getbalance?p=%5B%22obb1q%22%5D", 1760000000, nonce, ["198.51.100.4", "", "", "", empty]),
    "c3cbbce26b2117702761531fc0d45e65e1d0d8371eba9bb0208bebf1b30c6a00");
  assert.equal(await responseMac(key, nonce, 200, "0x4f420001", "ab".repeat(32), `100:${"cd".repeat(32)}`, new TextEncoder().encode('{"result":1}')),
    "2e475ec4f7ef9feb79822310ea02f37c24579c653c4063ea6f6e9323d75025a1");
  assert.deepEqual(SIGNED_HEADERS, ["x-gnb-client-ip", "x-gnb-cross-site", "x-obb-page-origin", "x-obb-probe", "x-obb-body-sha256"]);
});

// The real explorer API (python3, standard library) with a stub node.
const API_PY = fileURLToPath(new URL("../../deploy/explorer-api/gnb_explorer_api.py", import.meta.url));
const SERVER = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("gnb_explorer_api", sys.argv[1])
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
api.API_KEY = sys.argv[2].encode()
def rpc(method, params):
    return {
        "getnetworkinfo": {"result": {"chain_id": "0x4f420001"}},
        "getblockhash": {"result": "${GENESIS}"},
        "getpowitinfo": {"result": {"finalized": {"block_height": 100, "hash": "${"cd".repeat(32)}"}}},
        "getblockcount": {"result": 123},
    }.get(method, {"error": "unexpected method"})
api.rpc = rpc
httpd = api.make_server("127.0.0.1", 0, 8)
print(httpd.server_address[1], flush=True)
httpd.serve_forever()
`;

test("against the real explorer API: signed both ways; wrong key, stale and replayed requests refused", async () => {
  const py = spawn("python3", ["-I", "-c", SERVER, API_PY, KEY], { stdio: ["ignore", "pipe", "inherit"] });
  try {
    const port = await new Promise((resolve, reject) => {
      py.stdout.once("data", (d) => resolve(Number(String(d).trim().split("\n")[0])));
      py.once("exit", (code) => reject(new Error(`explorer API exited (${code})`)));
    });
    const base = `http://127.0.0.1:${port}`;
    const r = await originFetch({ OBB_API_KEY: KEY }, base, "GET", "/v1/getblockcount?p=%5B%5D", { headers: { "x-gnb-client-ip": "198.51.100.4" } });
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.body), { result: 123 });
    assert.deepEqual(r.identity, { chain: "0x4f420001", genesis: GENESIS, finalized: FINAL });

    // Another key: the origin refuses it, and its unsigned refusal is not
    // taken for an answer.
    await assert.rejects(originFetch({ OBB_API_KEY: "x".repeat(40) }, base, "GET", "/v1/getblockcount?p=%5B%5D"), /unauthenticated/);
    // A stale timestamp and a replayed nonce, signed with the right key.
    const target = "/v1/getblockcount?p=%5B%5D";
    const body = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const signedAt = async (ts, nonce) => ({
      "x-obb-ts": String(ts), "x-obb-nonce": nonce, "x-obb-body-sha256": body,
      "x-obb-auth": await requestMac(KEY, "GET", target, ts, nonce, ["", "", "", "", body]),
    });
    const now = Math.floor(Date.now() / 1000);
    assert.equal((await fetch(base + target, { headers: await signedAt(now - 600, "aa".repeat(16)) })).status, 403, "stale");
    const once = await signedAt(now, "bb".repeat(16));
    assert.equal((await fetch(base + target, { headers: once })).status, 200);
    assert.equal((await fetch(base + target, { headers: once })).status, 403, "replayed");
    assert.equal((await fetch(base + target, { headers: { "x-gnb-key": KEY } })).status, 403, "the static header is gone");
  } finally { py.kill(); }
});

test("an impostor origin (no key) is never used, whatever DNS or certificate it holds", async () => {
  for (const impostor of [{ key: "i".repeat(40) }, { unsigned: true }]) {
    const { seen } = installOrigins({ [N1]: impostor, [N2]: {} });
    const r = await worker.fetch(get("getblockcount"), envFor({ OBB_ORIGINS: `${N1},${N2}` }), ctx);
    assert.equal(r.status, 200);
    assert.deepEqual(answering(seen), [N2]);
    const st = await originHealth(envFor({ OBB_ORIGINS: `${N1},${N2}` }));
    assert.deepEqual(st.set, [N2]);
  }
  installOrigins({ [N1]: { unsigned: true } });
  assert.equal((await worker.fetch(get("getblockcount"), envFor({ OBB_ORIGINS: N1 }), ctx)).status, 502);
});

test("the chain is pinned: another chain id, or another genesis than OBB_GENESIS_HASH, is excluded", async () => {
  let { seen } = installOrigins({ [N1]: { chain: "0x474e0001" }, [N2]: {} });
  await worker.fetch(get("getbalance"), envFor({ OBB_ORIGINS: `${N1},${N2}` }), ctx);
  assert.deepEqual(answering(seen), [N2], "a GnB node is not an ObenBlock origin");

  ({ seen } = installOrigins({ [N1]: { genesis: "ee".repeat(32) }, [N2]: { genesis: "ee".repeat(32) }, [N3]: {} }));
  await worker.fetch(get("getbalance"), envFor({ OBB_GENESIS_HASH: GENESIS }), ctx);
  assert.deepEqual(answering(seen), [N3], "the pinned genesis wins over a majority");

  ({ seen } = installOrigins({ [N1]: { genesis: "ee".repeat(32) }, [N2]: {}, [N3]: {} }));
  await worker.fetch(get("getbalance"), envFor(), ctx);
  assert.ok(!answering(seen).includes(N1), "without a pin: the genesis most origins report");

  installOrigins({ [N1]: { genesis: "ee".repeat(32) }, [N2]: {} });
  const tie = await worker.fetch(get("getbalance"), envFor({ OBB_ORIGINS: `${N1},${N2}` }), ctx);
  assert.equal(tie.status, 503, "two chains, one origin each: refuse rather than guess");
  assert.match((await tie.json()).error, /genesis/);

  installOrigins({ [N1]: {} });
  assert.equal((await worker.fetch(get("getbalance"), envFor({ OBB_GENESIS_HASH: "xyz" }), ctx)).status, 503);
  assert.equal((await worker.fetch(get("getbalance"), envFor({ OBB_API_KEY: "short" }), ctx)).status, 503);
  assert.deepEqual(expectedIdentity({}), { chain: "0x4f420001", genesis: null });
});

test("reads prefer the origins agreeing on the finalized checkpoint, freshest tip first; a 404 is retried", async () => {
  const other = `100:${"ef".repeat(32)}`;
  let { seen } = installOrigins({ [N1]: { finalized: other }, [N2]: { tip: 130 }, [N3]: { tip: 140 } });
  await worker.fetch(get("getbalance"), envFor(), ctx);
  assert.deepEqual(answering(seen), [N3], "N1 is on a minority fork; N3 has the freshest tip");

  // A lone origin claiming a higher checkpoint does not outvote two.
  ({ seen } = installOrigins({ [N1]: { finalized: `120:${"ef".repeat(32)}` }, [N2]: {}, [N3]: {} }));
  await worker.fetch(get("getbalance"), envFor(), ctx);
  assert.notEqual(answering(seen)[0], N1);
  // One each: the highest checkpoint.
  assert.deepEqual(selectOrigins([
    { origin: N1, ok: true, identity: { chain: "0x4f420001", genesis: GENESIS, finalized: FINAL } },
    { origin: N2, ok: true, identity: { chain: "0x4f420001", genesis: GENESIS, finalized: `101:${"ef".repeat(32)}` } },
  ], { chain: "0x4f420001", genesis: null }).set, [N2]);
  // Two different checkpoints at one height and equal support: refused.
  assert.match(selectOrigins([
    { origin: N1, ok: true, identity: { chain: "0x4f420001", genesis: GENESIS, finalized: FINAL } },
    { origin: N2, ok: true, identity: { chain: "0x4f420001", genesis: GENESIS, finalized: other } },
  ], { chain: "0x4f420001", genesis: null }).error, /finalized checkpoint/);

  // A lagging origin's 404 for a fresh transaction: the next one answers.
  ({ seen } = installOrigins({
    [N1]: { tip: 150, handler: () => ({ status: 404, body: '{"error":"transaction not found"}' }) },
    [N2]: { tip: 149 },
  }));
  const r = await worker.fetch(get(`gettransactionfull?p=${encodeURIComponent(JSON.stringify(["aa".repeat(32)]))}`), envFor({ OBB_ORIGINS: `${N1},${N2}` }), ctx);
  assert.equal(r.status, 200);
  assert.deepEqual(answering(seen), [N1, N2]);
  // Every answer names its chain, for the wallet's session pin.
  assert.equal(r.headers.get("x-obb-chain-id"), "0x4f420001");
  assert.equal(r.headers.get("x-obb-genesis"), GENESIS);
  assert.equal(r.headers.get("x-obb-finalized"), FINAL);
  assert.match(r.headers.get("access-control-expose-headers"), /x-obb-chain-id/);
});

test("an answer from another chain after the probe is discarded", async () => {
  const flip = { tip: 150 };
  const { seen } = installOrigins({ [N1]: flip, [N2]: {} });
  const env = envFor({ OBB_ORIGINS: `${N1},${N2}` });
  await originHealth(env);
  flip.chain = "0x474e0001";
  const r = await worker.fetch(get("getutxos"), env, ctx);
  assert.equal(r.status, 200);
  assert.deepEqual(answering(seen), [N1, N2]);
  assert.equal(r.headers.get("x-obb-chain-id"), "0x4f420001");
});

test("the fallback origins are used only while no in-zone origin is usable; out-of-zone primaries are ignored", async () => {
  const FB = "https://1-2-3-4.sslip.io:2087";
  let { seen, probes } = installOrigins({ [N1]: {}, [FB]: {} });
  await worker.fetch(get("getblockcount"), envFor({ OBB_ORIGINS: N1, OBB_FALLBACK_ORIGINS: FB }), ctx);
  assert.deepEqual(answering(seen), [N1]);
  assert.ok(!probes.some((p) => p.origin === FB), "the fallback is not even probed");

  ({ seen } = installOrigins({ [N1]: { down: true }, [FB]: {} }));
  const r = await worker.fetch(get("getblockcount"), envFor({ OBB_ORIGINS: N1, OBB_FALLBACK_ORIGINS: FB }), ctx);
  assert.equal(r.status, 200);
  assert.deepEqual(answering(seen), [FB]);

  ({ seen } = installOrigins({ [FB]: {} }));
  const out = await worker.fetch(get("getblockcount"), envFor({ OBB_ORIGINS: FB }), ctx);
  assert.equal(out.status, 503, "an sslip.io name is not an in-zone origin");
  assert.equal(seen.length, 0);

  installOrigins({ [N1]: { down: true }, [N2]: {} });
  const status = await (await worker.fetch(get("originstatus"), envFor({ OBB_ORIGINS: `${N1},${N2}` }), ctx)).json();
  assert.deepEqual(status.result.reading, [N2]);
  assert.equal(status.result.origins.find((o) => o.host === "node1.obenblock.xyz:2087").ok, false);
  assert.ok(!JSON.stringify(status).includes(KEY));
});

test("a broadcast goes to every healthy origin; any acceptance is success", async () => {
  const accept = () => ({ status: 200, body: '{"result":{"txid":"00"}}' });
  const reject = () => ({ status: 400, body: '{"error":"missing inputs"}' });
  let { seen } = installOrigins({ [N1]: { handler: accept }, [N2]: { handler: accept }, [N3]: { handler: accept } });
  let r = await worker.fetch(post(), envFor(), ctx);
  assert.equal(r.status, 200);
  assert.deepEqual(answering(seen).sort(), [N1, N2, N3]);
  assert.equal(r.headers.get("x-obb-broadcast-accepted"), "3/3");
  assert.equal(r.headers.get("access-control-allow-origin"), null);
  for (const s of seen) assert.equal(s.init.body, BODY);

  // A lagging node refuses (missing inputs) while the others accept.
  installOrigins({ [N1]: { handler: reject }, [N2]: { handler: accept }, [N3]: { down: true } });
  r = await worker.fetch(post(), envFor(), ctx);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("x-obb-broadcast-accepted"), "1/2");

  installOrigins({ [N1]: { handler: reject }, [N2]: { handler: reject } });
  r = await worker.fetch(post(), envFor({ OBB_ORIGINS: `${N1},${N2}` }), ctx);
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "missing inputs");

  // A node of another chain never receives it.
  ({ seen } = installOrigins({ [N1]: { chain: "0x474e0001", handler: accept }, [N2]: { handler: accept } }));
  r = await worker.fetch(post(), envFor({ OBB_ORIGINS: `${N1},${N2}` }), ctx);
  assert.deepEqual(answering(seen), [N2]);
});

test("the signed target is the one fetch() sends, whatever the parameters", async () => {
  const { seen } = installOrigins({ [N1]: {} });
  const p = encodeURIComponent(JSON.stringify(["it's", "(x)*!"]));
  const r = await worker.fetch(get(`validateaddress?p=${p}`), envFor({ OBB_ORIGINS: N1 }), ctx);
  assert.equal(r.status, 200, "the fake origin checks the MAC over the target it receives");
  assert.equal(seen.length, 1);
});
