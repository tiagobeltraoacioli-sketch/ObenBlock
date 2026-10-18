// Actual pinned WASM, no node, signing or broadcast; synthetic public fixtures.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { loadCore } from "../wallet/core.js";

const wasm = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const pin = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8")
  .match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];
const key = "42".repeat(3745);
const key2 = "43".repeat(3745);
async function coreInstance() {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(wasm);
  try { return await loadCore("/wallet/gnb_wallet.wasm", pin); }
  finally { globalThis.fetch = original; }
}

test("descriptor public frontend normalizes to the ObenBlock form", async () => {
  const core = await coreInstance();
  const address = "gnb1q0000000000000000000000000000000000000000335d2ee7";
  assert.equal(core.normalize(address), address.replace("gnb1q", "obb1q"));
});

for (const network of ["mainnet", "testnet"]) {
  test(`pinned WASM creates all static descriptor kinds and restores public identities on ${network}`, async () => {
    const core = await coreInstance();
    const policy = `policy(1,0,0,${key})`;
    const forms = [["pkh", `pkh(${key})`], ["policy", policy], ["tree", `tree(${policy},policy(1,1,0,${key2}))`]];
    const descriptors = forms.map(([kind, expression]) => {
      const info = core.descriptor({ action: "create", network, body: `gnbd1(${network},${expression})` });
      assert.equal(info.kind, kind);
      assert.equal(info.network, network);
      assert.equal(info.requires_policy_tree_activation, kind === "tree");
      assert.deepEqual(core.descriptor({ action: "inspect", network, descriptor: info.descriptor }), info);
      assert.throws(() => core.descriptor({ action: "inspect", network: network === "mainnet" ? "testnet" : "mainnet", descriptor: info.descriptor }), /network/i);
      // The ObenBlock core shows the obb forms (the descriptor text keeps
      // its gnbd1 format: it names keys, not a chain).
      assert.match(info.bech32m, network === "mainnet" ? /^obb1z/ : /^tobb1z/);
      assert.match(info.address, network === "mainnet" ? /^obb1[qm]/ : /^obb1[tn]/);
      if (kind === "pkh") {
        assert.equal(info.script_pubkey, createHash("sha3-256").update(Buffer.from(key, "hex")).digest("hex").slice(0, 40));
        assert.equal(core.normalize(info.bech32m), info.address);
      }
      return info.descriptor;
    });
    const exported = core.descriptor({ action: "export", network, descriptors });
    const fresh = await coreInstance();
    assert.deepEqual(fresh.descriptor({ action: "import", network, bundle: exported.bundle }), exported);
    assert.equal(exported.count, 3);
    assert.deepEqual(exported.entries.map((e) => e.descriptor), descriptors);
    // Importing a public pool does not create a signing session.
    assert.throws(() => fresh.address(), /locked|wallet|open/i);
  });
}

test("descriptor binding forces a public operation and preserves an unlocked session", async () => {
  const core = await coreInstance();
  const wallet = core.create();
  try {
    for (const op of ["wipe", "pay", "pqpsbt_sign", "create", "export"]) {
      const result = core.descriptor({ op, action: "pool", network: "mainnet", public_keys: [wallet.public_key] });
      assert.equal(result.entries[0].address, wallet.address);
      assert.equal(core.address(), wallet.address);
      assert.equal(result.keystore, undefined);
      assert.equal(result.raw, undefined);
    }
    assert.throws(() => core.descriptor({ op: "wipe", action: "sign", network: "mainnet" }), /action/i);
    assert.equal(core.address(), wallet.address);
  } finally { core.wipe(); }
});

test("descriptor pool preserves raw/enveloped identity and refuses malformed imports", async () => {
  const core = await coreInstance();
  const pool = core.descriptor({ action: "pool", network: "mainnet", public_keys: [key, `b10c0100${key}`] });
  assert.notEqual(pool.entries[0].script_pubkey, pool.entries[1].script_pubkey);
  assert.throws(() => core.descriptor({ action: "pool", network: "mainnet", public_keys: [key, key] }), /duplicate/i);
  assert.throws(() => core.descriptor({ action: "pool", network: "mainnet", public_keys: [key], password: "must-not-use" }), /field|unknown/i);
  assert.throws(() => core.descriptor({ action: "import", network: "mainnet", bundle: pool.bundle.replace('"network":"mainnet"', '"network":"mainnet","network":"mainnet"') }), /duplicate/i);
  assert.throws(() => core.descriptor({ action: "inspect", network: "mainnet", descriptor: pool.entries[0].descriptor.slice(0, -1) + "!" }), /checksum|descriptor/i);
});

test("descriptor rejects an own toJSON hook before it can wipe an active session", async () => {
  const core = await coreInstance();
  const wallet = core.create();
  let error;
  try {
    try {
      core.descriptor({ action: "pool", network: "mainnet", public_keys: [wallet.public_key],
        toJSON() { return { op: "wipe" }; } });
    } catch (e) { error = e; }
    assert.equal(core.address(), wallet.address, "public descriptor call must retain the signing session");
    assert.match(error?.message ?? "", /toJSON|field/i);
  } finally { core.wipe(); }
});

test("descriptor ignores inherited toJSON dispatch redirection without changing legacy bindings", async () => {
  const core = await coreInstance();
  assert.equal(typeof core.descriptor, "function");
  const wallet = core.create();
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  try {
    try {
      Object.defineProperty(Object.prototype, "toJSON", {
        configurable: true, value() { return { op: "wipe" }; },
      });
      // Nested values may fail validation under a poisoned prototype; they
      // must never redirect the top-level public operation to session wipe.
      try { core.descriptor({ action: "pool", network: "mainnet", public_keys: [wallet.public_key] }); }
      catch (error) { assert.ok(error instanceof Error); }
    } finally {
      if (previous) Object.defineProperty(Object.prototype, "toJSON", previous);
      else delete Object.prototype.toJSON;
    }
    assert.equal(core.address(), wallet.address);
  } finally { core.wipe(); }
});
