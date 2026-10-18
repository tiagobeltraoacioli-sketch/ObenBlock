// Additive address format only: no node connection or transaction broadcast.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadCore } from "../wallet/core.js";

// Generated independently from the agreed BIP350 application contract (the
// same construction as deploy/explorer-api/test_address_v2.py, with the
// ObenBlock HRPs obb / tobb of docs/DESIGN-obenblock.md §2).
const V2 = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw";
const V2_TEST = "tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc";
const OBB_V2 = "obb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqvttus2";
const OBB_V2_TEST = "tobb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2sa8wu";
const LEGACY = "gnb1q0000000000000000000000000000000000000000335d2ee7";
const LEGACY_TEST = LEGACY.replace("gnb1q", "gnb1t");
// The ObenBlock forms: a key-hash checksum covers the hash only.
const OBB = LEGACY.replace("gnb1q", "obb1q");
const OBB_TEST = LEGACY.replace("gnb1q", "obb1t");
const wasm = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const pin = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8")
  .match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];

async function coreInstance() {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(wasm);
  try { return await loadCore("/wallet/gnb_wallet.wasm", pin); }
  finally { globalThis.fetch = original; }
}

test("legacy normalization shows obb1 and keeps the GnB and Bloch aliases", async () => {
  const core = await coreInstance();
  assert.equal(core.normalize(OBB), OBB);
  assert.equal(core.normalize(OBB_TEST), OBB_TEST);
  assert.equal(core.normalize(LEGACY), OBB);
  assert.equal(core.normalize(LEGACY_TEST), OBB_TEST);
  assert.equal(core.normalize(LEGACY.replace("gnb1q", "bloch1q")), OBB);
  assert.deepEqual(core.classify(LEGACY_TEST), { address: OBB_TEST, network: "regtest" });
  assert.deepEqual(core.classify(` ${OBB} `), { address: OBB, network: "mainnet" });
});

test("pinned WASM normalizes v2 aliases without changing network or identity", async () => {
  const core = await coreInstance();
  for (const [v2, legacy] of [[V2, OBB], [V2_TEST, OBB_TEST], [OBB_V2, OBB], [OBB_V2_TEST, OBB_TEST]]) {
    assert.equal(core.normalize(v2), legacy, v2);
    assert.equal(core.normalize(v2.toUpperCase()), legacy, v2);
  }
  assert.throws(() => core.normalize(V2.replace(/^gnb/, "tgnb")));
  assert.throws(() => core.normalize(OBB_V2.replace(/^obb/, "tobb")));
});

test("v2 normalization output is explicit and legacy remains the default", async () => {
  const core = await coreInstance();
  assert.equal(core.normalize(LEGACY, "bech32m"), OBB_V2);
  assert.equal(core.normalize(OBB_TEST, "bech32m"), OBB_V2_TEST);
  assert.equal(core.normalize(V2), OBB);
  assert.throws(() => core.normalize(LEGACY, "unknown-format"));
  for (const invalid of [null, 2, {}, ["bech32m"]]) {
    assert.throws(() => core.normalize(LEGACY, invalid), /format/);
  }
});

test("the served wallet entry point loads the pinned binary, an ObenBlock core", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(wasm);
  try {
    const core = await loadCore("/wallet/gnb_wallet.wasm", pin);
    assert.equal(core.normalize(LEGACY), OBB);
    const chain = core.chain();
    assert.equal(chain.chain, "obenblock");
    assert.equal(chain.chain_id, "0x4f420001");
    assert.equal(chain.tx_version, 3);
    assert.equal(chain.tx_version_3_from_height, 0);
    assert.equal(core.chain("regtest").chain_id, "0x4f420002");
    assert.throws(() => core.chain("testnet3"), /unknown wallet network/);
  } finally { globalThis.fetch = original; }
});

const activationSource = readFileSync(new URL("../../crates/gnb-crypto/src/core/activation.rs", import.meta.url), "utf8");
const activation = Number(activationSource.match(/pub const MAINNET_HARDENING_ACTIVATION_HEIGHT:\s*u64\s*=\s*([0-9_]+);/)[1].replaceAll("_", ""));
const reference = fileURLToPath(new URL("../../reference", import.meta.url));
function decodedPayment(raw) {
  return JSON.parse(execFileSync("python3", ["-I", "-c", `
import json,sys
sys.path.insert(0,sys.argv[1])
import gnb_validity
tx=gnb_validity.decode_tx_strict(bytes.fromhex(sys.stdin.read()))
print(json.dumps({"version":tx.version,"value":tx.outputs[0].value,"script":tx.outputs[0].script_pubkey.hex()}))
`, reference], { input: raw, encoding: "utf8" }));
}

// ObenBlock: version 3 from height 0, also below GnB's activation height.
for (const height of [0, 1, activation - 1, activation]) {
  test(`actual WASM v2 payment preserves script and network at height ${height}`, async () => {
    const core = await coreInstance();
    const sender = core.create();
    assert.match(sender.address, /^obb1q[0-9a-f]{48}$/);
    const utxos = [{ txid: "33".repeat(32), index: 0, value: "500000000", script_pubkey: sender.address.slice(5, 45) }];
    const expected = { version: 3, value: 100000000, script: "00".repeat(20) };
    try {
      for (const to of [OBB, LEGACY, V2, OBB_V2]) {
        const payment = core.pay(utxos, to, "100000000", "0", height, {});
        assert.deepEqual(decodedPayment(payment.raw), expected, to);
      }
      for (const other of [V2_TEST, OBB_V2_TEST, OBB_TEST]) {
        assert.throws(() => core.pay(utxos, other, "100000000", "0", height, {}), /network/, other);
      }
    } finally { core.wipe(); }
  });
}
