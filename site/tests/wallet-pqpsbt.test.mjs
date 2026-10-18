// Actual pinned WASM, isolated key sessions and offline document exchange.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { loadCore } from "../wallet/core.js";

const wasm = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const pin = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8")
  .match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];
const activation = Number(readFileSync(new URL("../../crates/gnb-crypto/src/core/activation.rs", import.meta.url), "utf8")
  .match(/pub const MAINNET_HARDENING_ACTIVATION_HEIGHT:\s*u64\s*=\s*([0-9_]+);/)[1].replaceAll("_", ""));

function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; }
function u64(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }

function unsignedSpend(publicKeys, { input = 5_000_000n, payment = 1_000_000n, change = 3_950_000n } = {}) {
  // Independent fixture encoding of the existing policy and transaction formats.
  const keys = publicKeys.map((k) => Buffer.from(k, "hex"));
  const policy = Buffer.concat([Buffer.from([1, 2, 3]),
    ...keys.flatMap((k) => [u32(k.length), k]), u32(0), u32(0)]);
  const script = Buffer.concat([Buffer.from([2]),
    createHash("sha3-256").update("GNB-POLICY-v1").update(policy).digest()]);
  const tx = Buffer.concat([u32(3), Buffer.from([1]), Buffer.alloc(32, 0x11),
    u32(0), Buffer.from([0]), u32(0xffffffff), Buffer.from([2]),
    u64(payment), Buffer.from([20]), Buffer.alloc(20, 0x22),
    u64(change), Buffer.from([script.length]), script, u32(0)]);
  return JSON.stringify({ network: "mainnet", policy: policy.toString("hex"),
    tx: tx.toString("hex"), signatures: [{}], amounts: [String(input)] });
}

test("WASM refuses signing amounts and fees outside known consensus bounds", async (t) => {
  const previousFetch = globalThis.fetch;
  const cores = [];
  try {
    globalThis.fetch = async () => new Response(wasm);
    for (let i = 0; i < 3; i++) cores.push(await loadCore("/wallet/gnb_wallet.wasm", pin));
    const keys = cores.map((c) => c.create().public_key);
    const cases = [
      { name: "zero fee", values: { change: 4_000_000n }, maxFee: "0", error: /fee|minimum/i },
      { name: "amount exceeds monetary cap", values: {
        input: 1_250_000_004_000_001n, payment: 1_250_000_000_000_001n,
      }, maxFee: "50000", error: /money|range|MAX_SUPPLY/i },
    ];
    for (const item of cases) await t.test(item.name, () => {
      const packet = cores[0].pqpsbt({ action: "create", spend_json: unsignedSpend(keys, item.values) }).hex;
      assert.throws(() => cores[0].signPqPsbt(packet, "mainnet", activation, item.maxFee), item.error);
    });
  } finally {
    for (const core of cores) core.wipe();
    globalThis.fetch = previousFetch;
  }
});

test("pinned WASM supports a 2-of-3 PQ-PSBT exchange with no network during signing", async () => {
  const previousFetch = globalThis.fetch;
  const cores = [];
  let networkCalls = 0;
  try {
    globalThis.fetch = async () => new Response(wasm);
    for (let i = 0; i < 3; i++) cores.push(await loadCore("/wallet/gnb_wallet.wasm", pin));
    const created = cores.map((c) => c.create());
    for (let i = 0; i < 3; i++) assert.equal(cores[i].address(), created[i].address);
    assert.equal(new Set(created.map((c) => c.public_key)).size, 3);
    globalThis.fetch = () => { networkCalls++; throw new Error("offline signer must not fetch"); };

    const context = { network: "mainnet", next_height: String(activation), max_fee: "50000" };
    const packet = cores[0].pqpsbt({ action: "create", spend_json: unsignedSpend(created.map((c) => c.public_key)) }).hex;
    assert.match(packet, /^474e4250534254ff0100/);
    const json = cores[0].pqpsbt({ action: "decode", hex: packet }).json;
    assert.equal(cores[0].pqpsbt({ action: "encode", json }).hex, packet);
    assert.equal(cores[0].pqpsbt({ op: "create", action: "decode", hex: packet }).json, json,
      "the public-data binding cannot be redirected to a session operation");
    const decoded = JSON.parse(json);
    assert.equal(decoded.inputs[0].value, "5000000");
    assert.equal(decoded.inputs[0].previous_tx, null);

    assert.throws(() => cores[0].signPqPsbt(packet, "mainnet", Number.MAX_SAFE_INTEGER + 1, "50000"), /exact integer/i);
    assert.throws(() => cores[0].signPqPsbt(packet, "mainnet", activation, Number.MAX_SAFE_INTEGER + 1), /exact integer/i);
    assert.throws(() => cores[0].signPqPsbt(packet, "mainnet", activation, "050000"), /decimal integer/i);
    assert.throws(() => cores[0].signPqPsbt(packet, "mainnet", activation, "49999"), /fee|ceiling/i);
    assert.throws(() => cores[0].signPqPsbt(packet, "testnet", activation, "50000"), /network/i);
    assert.throws(() => cores[0].signPqPsbt(packet, "regtest", activation, "50000"), /network/i);
    // ObenBlock signs version 3 at every height, so an earlier target
    // height is no version mismatch (on GnB it was, below the activation).
    const first = cores[0].signPqPsbt(packet, "mainnet", activation, "50000");
    const third = cores[2].signPqPsbt(packet, "mainnet", activation, "50000");
    assert.equal(first.key_index, 0);
    assert.equal(third.key_index, 2);
    assert.equal(first.review.total_inputs, "5000000");
    assert.equal(first.review.total_outputs, "4950000");
    assert.equal(first.review.fee, "50000");
    assert.equal(first.review.change, "3950000");
    assert.equal(first.review.previous_transactions_verified, 0);
    assert.equal(first.review.current_unspentness, "not_checked_offline");
    assert.throws(() => cores[1].pqpsbt({ action: "finalize", hex: first.hex, ...context }), /signature|required/i);

    const combined = cores[1].pqpsbt({ action: "combine", hex: first.hex, other_hex: third.hex }).hex;
    assert.equal(cores[1].pqpsbt({ action: "combine", hex: combined, other_hex: first.hex }).hex, combined);
    const changed = JSON.parse(json);
    changed.transaction = changed.transaction.slice(0, -8) + "01000000";
    const other = cores[1].pqpsbt({ action: "encode", json: JSON.stringify(changed) }).hex;
    assert.throws(() => cores[1].pqpsbt({ action: "combine", hex: first.hex, other_hex: other }), /different|conflict/i);
    cores.forEach((c) => c.wipe());
    assert.throws(() => cores[0].signPqPsbt(packet, "mainnet", activation, "50000"), /locked/i);
    const final = cores[1].pqpsbt({ action: "finalize", hex: combined, ...context });
    const extracted = cores[1].pqpsbt({ action: "extract", hex: combined, ...context });
    assert.equal(final.hex, extracted.hex);
    assert.equal(final.txid, extracted.txid);
    assert.match(final.txid, /^[0-9a-f]{64}$/);
    assert.ok(final.hex.length > decoded.transaction.length, "final transaction contains the policy witness");
    const duplicate = json.replace('"version":1', '"version":1,"version":1');
    assert.notEqual(duplicate, json);
    assert.throws(() => cores[1].pqpsbt({ action: "encode", json: duplicate }), /duplicate/i);
    assert.throws(() => cores[1].pqpsbt({ action: "decode", hex: packet + "00" }), /trailing/i);
    assert.equal(networkCalls, 0);
  } finally {
    cores.forEach((c) => c.wipe());
    globalThis.fetch = previousFetch;
  }
});
