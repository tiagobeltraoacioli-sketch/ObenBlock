// Pre-launch review (wallet):
// - a gnb1…/bloch1… destination was silently converted to obb1… and the
//   review showed only the obb1 form: the page now names the address family
//   that was typed, shows both strings and needs an explicit confirmation;
// - the chain was checked on one getnetworkinfo answer while every later call
//   could be answered by another origin: every answer is now bound to the
//   chain the session verified first (core.js ChainSession), and an answer
//   from another chain stops the session with an alert.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import * as safe from "../assets/safe.js";
import * as coreMod from "../wallet/core.js";
import { addressFamily, ChainSession, ChainMismatchError, loadCore } from "../wallet/core.js";

const GENESIS = "ab".repeat(32), OTHER = "ee".repeat(32);
const FIN = (h, x = "cd") => `${h}:${x.repeat(32)}`;
const headers = (chain = "0x4f420001", genesis = GENESIS, finalized = FIN(100)) =>
  new Headers({ "x-obb-chain-id": chain, "x-obb-genesis": genesis, "x-obb-finalized": finalized });

test("addressFamily names the form that was typed", () => {
  const hash = "00".repeat(24);
  assert.equal(addressFamily(`obb1q${hash}`), "obb");
  assert.equal(addressFamily(`  GNB1Q${hash} `), "gnb");
  assert.equal(addressFamily("gnb1zqqqq"), "gnb");
  assert.equal(addressFamily("tgnb1zqqqq"), "gnb");
  assert.equal(addressFamily(`bloch1q${hash}`), "bloch");
  assert.equal(addressFamily("tobb1zqqqq"), "obb");
  assert.equal(addressFamily(undefined), "obb");
});

test("ChainSession binds to the first ObenBlock answer and refuses any other chain for good", () => {
  const s = new ChainSession();
  assert.throws(() => s.check(new Headers()), ChainMismatchError, "an answer that names no chain is not used");
  assert.equal(s.identity, null, "and binds nothing");
  assert.throws(() => s.check(headers("0x474e0001")), /not an ObenBlock node/, "a GnB node cannot start a session");
  assert.deepEqual(s.check(headers()), { chain: "0x4f420001", genesis: GENESIS });
  assert.deepEqual(s.check(headers("0x4F420001", GENESIS.toUpperCase(), FIN(101, "ef"))), { chain: "0x4f420001", genesis: GENESIS });
  assert.deepEqual(s.check(headers("0x4f420001", GENESIS, FIN(99, "11"))), s.identity, "a lagging origin's older checkpoint is fine");
  assert.throws(() => s.check(headers("0x4f420001", OTHER)), /another chain/);
  assert.ok(s.broken);
  assert.throws(() => s.check(headers()), /reload the page/, "broken for good, even for answers of the right chain");

  const t = new ChainSession();
  t.check(headers());
  assert.throws(() => t.check(headers("0x4f420002")), /another chain/, "regtest after mainnet");
  const u = new ChainSession();
  u.check(headers("0x4f420001", GENESIS, FIN(100)));
  assert.throws(() => u.check(headers("0x4f420001", GENESIS, FIN(100, "ef"))), /different finalized blocks at height 100/);
});

// ── app.js in a minimal DOM ─────────────────────────────────────────────────
const src = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8").replace(/^import [^;]*;\n/gm, "");
const walletBytes = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const walletPin = src.match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];
const realCore = async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(walletBytes);
  try { return await loadCore("/wallet/gnb_wallet.wasm", walletPin); } finally { globalThis.fetch = original; }
};

function page({ answer }) {
  const elements = new Map(), fetched = [];
  const make = (id) => {
    const el = {
      id, value: "", checked: false, disabled: false, dataset: {}, style: {}, listeners: {}, textContent: "", title: "",
      _html: "",
      get innerHTML() { return this._html; },
      set innerHTML(v) {
        this._html = String(v);
        for (const m of this._html.matchAll(/<[^>]*\bid="([^"]+)"[^>]*>/g)) {
          const child = elements.get(m[1]) || make(m[1]);
          child.disabled = /\sdisabled(?=[\s>])/.test(m[0]);
          child.checked = false;
          child.present = true;
          elements.set(m[1], child);
        }
      },
      addEventListener(e, f) { this.listeners[e] = f; },
      setAttribute() {}, focus() {}, click() {}, querySelectorAll: () => [],
      classList: { add() {}, remove() {} },
      before(node) { node.present = true; elements.set(node.id, node); },
    };
    return el;
  };
  for (const id of ["app", "lock", "netbadge"]) { const el = make(id); el.present = true; elements.set(id, el); }
  const document = {
    getElementById: (id) => (elements.get(id)?.present ? elements.get(id) : null),
    createElement: () => make(""),
    addEventListener() {}, body: { appendChild() {} },
  };
  const fetch = async (url, init = {}) => {
    const u = new URL(String(url), "https://obenblock.xyz");
    const method = u.pathname.slice(5);
    fetched.push(method);
    const [body, h] = answer(method, init);
    return new Response(JSON.stringify(body), { status: 200, headers: h });
  };
  const context = vm.createContext({
    ...safe, ...coreMod, document, fetch, Response, Headers, URL, Blob,
    window: { addEventListener() {}, qrcode: () => { throw new Error("no qr in tests"); } },
    location: { hash: "", pathname: "/wallet", search: "" },
    navigator: {}, console,
    requestAnimationFrame: (f) => setTimeout(f, 0),
    setTimeout: (f, ms) => (ms > 100 ? 0 : setTimeout(f, ms)), clearTimeout() {}, setInterval: () => 0, clearInterval() {},
  });
  vm.runInContext(src, context);
  const el = (id) => elements.get(id);
  const fire = (id, ev) => el(id).listeners[ev]({ currentTarget: el(id), target: el(id), preventDefault() {} });
  return { context, el, fire, fetched, run: (code) => vm.runInContext(code, context) };
}

const OBB = "obb1q" + "00".repeat(20) + "335d2ee7";
const COIN = { txid: "11".repeat(32), index: 0, value: "500000000", script_pubkey: "00".repeat(20) };
const PAID = { raw: "ab", txid: "cd".repeat(32), amount: "100000000", fee: "20000", inputs: 1, size: 8600, amounts_committed: true, change: "399980000", unverified_inputs: 0, dust_to_fee: "0" };

function node(overrides = {}) {
  return (method) => {
    const h = overrides[method] ?? headers();
    const body = {
      getnetworkinfo: { result: { chain_id: "0x4f420001" } },
      getpowitinfo: { result: { tip_height: 120, finalized: { block_height: 100 } } },
      getdaginfo: { result: { next_block_height: 200, tip_height: 199 } },
      sendrawtransaction: { result: { txid: PAID.txid } },
    }[method] ?? { result: {} };
    return [body, h];
  };
}

async function unlocked(p) {
  const real = await realCore();
  p.context.__core = { classify: (a) => real.classify(a), plan: () => ({ prev_txids: [] }), pay: () => ({ ...PAID }), wipe() {} };
  await p.run("refreshNode()");
  p.run(`core = __core; state = { mode: "keys", address: ${JSON.stringify(OBB)}, network: "mainnet", tab: "send", balance: 500000000n,
    utxos: [${JSON.stringify(COIN)}], immature: [], pending: null }; paintSend(document.getElementById("pane") || (() => { const e = document.createElement("div"); e.id = "pane"; document.getElementById("app").before(e); return e; })())`);
}

test("a gnb1/bloch1 destination is shown as typed, explained and must be confirmed before anything is sent", async () => {
  for (const [prefix, name] of [["gnb1q", "GnB"], ["bloch1q", "Bloch"]]) {
    const p = page({ answer: node() });
    await unlocked(p);
    const typed = prefix + OBB.slice(5);
    p.el("to").value = typed;
    p.el("amt").value = "1";
    await p.fire("review", "click");
    const out = p.el("send-out").innerHTML;
    assert.match(out, new RegExp(`You entered a ${name} address`));
    assert.ok(out.includes(typed) && out.includes(OBB), "both the typed string and the obb1 key are shown");
    assert.match(out, /nothing is sent on/);
    assert.equal(p.el("confirm").disabled, true, "Confirm starts disabled");
    await p.fire("confirm", "click");
    assert.ok(!p.fetched.includes("sendrawtransaction"), "no broadcast without the confirmation");
    p.el("accept-alias").checked = true;
    p.fire("accept-alias", "change");
    assert.equal(p.el("confirm").disabled, false);
    await p.fire("confirm", "click");
    assert.ok(p.fetched.includes("sendrawtransaction"));
  }
  // An obb1 destination needs no extra confirmation.
  const p = page({ answer: node() });
  await unlocked(p);
  p.el("to").value = OBB;
  p.el("amt").value = "1";
  await p.fire("review", "click");
  assert.ok(!p.el("send-out").innerHTML.includes("accept-alias"));
  assert.equal(p.el("confirm").disabled, false);
});

test("an answer from another chain mid-session stops the session: an alert, nothing signed or broadcast", async () => {
  for (const bad of [headers("0x4f420001", OTHER), headers("0x474e0001"), new Headers()]) {
    const p = page({ answer: node({ getdaginfo: bad }) });
    await unlocked(p);
    p.el("to").value = OBB;
    p.el("amt").value = "1";
    await p.fire("review", "click");
    assert.match(p.el("send-out").innerHTML, /alert bad/);
    assert.ok(!p.el("send-out").innerHTML.includes('id="confirm"'), "no payment was prepared");
    assert.ok(!p.fetched.includes("sendrawtransaction"));
    if (bad.get("x-obb-chain-id")) {
      assert.match(p.el("chain-alert")?.textContent || "", /another chain/);
      assert.equal(p.el("netbadge").textContent, "chain mismatch");
      await assert.rejects(p.run("broadcast('ab')"), /reload the page/);
    }
  }
});

test("a node whose report disagrees with the chain its answers are stamped with is refused", async () => {
  const p = page({ answer: (method) => (method === "getnetworkinfo"
    ? [{ result: { chain_id: "0x4f420002" } }, headers()]
    : node()(method)) });
  await p.run("refreshNode()");
  assert.match(p.el("chain-alert")?.textContent || "", /reports chain id 0x4f420002/);
  assert.throws(() => p.run('requireNodeNetwork("mainnet")'), /reload the page/);
});
