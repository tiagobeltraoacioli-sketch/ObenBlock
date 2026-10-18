// B2-T3: the web wallet's UTXO windows against the explorer API's real
// parameter validation. The page asks getutxos for UTXO_WINDOW rows and, when
// immature coinbase outputs filled a cut-short list, for UTXO_WIDE_WINDOW;
// the API used to refuse anything above 50 (HTTP 400), so a miner's wallet
// failed every refresh. This runs deploy/explorer-api/gnb_explorer_api.py
// itself (python3, standard library), with a stub in place of the node RPC
// that lists rows exactly as the node does (index order, `truncated` when the
// limit stops the walk), and drives core.js spendableWindow through HTTP.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { spendableWindow, getutxosFetcher, UTXO_WINDOW, UTXO_WIDE_WINDOW } from "../wallet/core.js";
import { originFetch } from "../../worker/index.js";

const API_PY = fileURLToPath(new URL("../../deploy/explorer-api/gnb_explorer_api.py", import.meta.url));
const KEY = "k".repeat(40);
const ADDRESS = "gnb1q" + "ab".repeat(24);

// The API module with its node RPC replaced by the node's getutxos listing.
const SERVER = `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("gnb_explorer_api", sys.argv[1])
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
api.API_KEY = ${JSON.stringify(KEY)}.encode()
rows = json.loads(sys.argv[2])
def rpc(method, params):
    if method != "getutxos":
        return {"error": "unexpected method"}
    limit = params[1] if len(params) > 1 else 10000
    return {"result": {"address": params[0], "utxos": rows[:limit], "returned": min(limit, len(rows)),
                       "truncated": len(rows) > limit}}
api.rpc = rpc
httpd = api.make_server("127.0.0.1", 0, 8)
print(httpd.server_address[1], flush=True)
httpd.serve_forever()
`;

async function startApi(rows) {
  const py = spawn("python3", ["-I", "-c", SERVER, API_PY, JSON.stringify(rows)], { stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise((resolve, reject) => {
    py.stdout.once("data", (d) => resolve(Number(String(d).trim().split("\n")[0])));
    py.once("exit", (code) => reject(new Error(`explorer API exited (${code})`)));
  });
  // The page's api(): result on success, an exception on any error document.
  const api = async (method, params) => {
    // Signed the way the Worker signs (worker/index.js originFetch), whose
    // check of the signed answer runs too.
    const r = await originFetch({ OBB_API_KEY: KEY }, `http://127.0.0.1:${port}`, "GET",
      `/v1/${method}?p=${encodeURIComponent(JSON.stringify(params))}`);
    const doc = JSON.parse(r.body);
    if (doc.error) throw new Error(String(doc.error));
    return doc.result;
  };
  return { api, stop: () => py.kill() };
}

const row = (i, coinbaseHeight) => ({
  txid: i.toString(16).padStart(64, "0"), index: 0, value: "100000000", script_pubkey: "cd".repeat(20),
  ...(coinbaseHeight === undefined ? {} : { coinbase_height: coinbaseHeight }),
});

test("a miner's wallet finds its mature coins behind a window of immature rewards", async () => {
  const next = 5_000;
  // The node's order: 60 immature mining rewards, then 70 mature coins.
  const rows = [
    ...Array.from({ length: 60 }, (_, i) => row(i, next - 1)),
    ...Array.from({ length: 70 }, (_, i) => row(1_000 + i)),
  ];
  const { api, stop } = await startApi(rows);
  try {
    const w = await spendableWindow(getutxosFetcher(api, ADDRESS), next, UTXO_WINDOW, UTXO_WIDE_WINDOW);
    assert.equal(w.widenFailed, false, "the API must accept the wallet's wide window");
    assert.equal(w.spendable.length, UTXO_WINDOW);
    assert.ok(w.spendable.every((r) => r.coinbase_height === undefined));
    assert.equal(w.immature.length, 60);
    assert.equal(w.truncated, false);
    // One row more than the wallet ever asks for is still refused.
    await assert.rejects(api("getutxos", [ADDRESS, UTXO_WIDE_WINDOW + 1]), /integer in \[1, 1000\]/);
  } finally {
    stop();
  }
});

test("a failing wide request keeps the narrow window instead of failing the refresh", async () => {
  const next = 5_000;
  const rows = [...Array.from({ length: 10 }, (_, i) => row(i, next - 1)), ...Array.from({ length: 45 }, (_, i) => row(100 + i))];
  const asked = [];
  const fetchRows = async (limit) => {
    asked.push(limit);
    if (limit > UTXO_WINDOW) throw new Error("integer in [1, 50] expected");
    return { rows: rows.slice(0, limit), truncated: rows.length > limit };
  };
  const w = await spendableWindow(fetchRows, next, UTXO_WINDOW, UTXO_WIDE_WINDOW);
  assert.deepEqual(asked, [UTXO_WINDOW, UTXO_WIDE_WINDOW]);
  assert.equal(w.widenFailed, true);
  assert.equal(w.spendable.length, UTXO_WINDOW - 10, "the mature coins of the narrow window stay spendable");
  assert.equal(w.immature.length, 10);
  assert.equal(w.truncated, true);
});
