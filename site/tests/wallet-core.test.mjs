// The committed ObenBlock wallet core, loaded exactly as the page loads it
// (core.js): pinned-hash check (WAL-5), phrase-backed create/restore (WAL-7),
// version-3 plan/pay with the actual fee (WAL-1/WAL-6), obb1 addresses and
// the mainnet / regtest selector.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadCore, splitByMaturity, spendableWindow, networkOfChainId, walletNetwork, COINBASE_MATURITY } from "../wallet/core.js";

const wasm = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const pin = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8").match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];
// GnB's mainnet hardening activation height, read from the consensus source
// (never a literal here). ObenBlock signs version 3 from height 0, also
// below it: the test below checks the committed core does.
const GNB_MAINNET_ACTIVATION = (() => {
  const rust = readFileSync(new URL("../../crates/gnb-crypto/src/core/activation.rs", import.meta.url), "utf8");
  const m = rust.match(/pub const MAINNET_HARDENING_ACTIVATION_HEIGHT:\s*u64\s*=\s*([0-9_]+);/);
  assert.ok(m, "MAINNET_HARDENING_ACTIVATION_HEIGHT not found in crates/gnb-crypto/src/core/activation.rs");
  const obb = rust.match(/pub const OBENBLOCK_HARDENING_ACTIVATION_HEIGHT:\s*u64\s*=\s*([0-9_]+);/);
  assert.ok(obb && Number(obb[1]) === 0, "ObenBlock activates the hardening rules (version 3) from genesis");
  return Number(m[1].replaceAll("_", ""));
})();
globalThis.fetch = async () => new Response(wasm);

test("loadCore refuses a missing or wrong pin", async () => {
  await assert.rejects(loadCore("/wallet/gnb_wallet.wasm"), /not pinned/);
  await assert.rejects(loadCore("/wallet/gnb_wallet.wasm", "0".repeat(64)), /integrity check failed/);
});

test("phrase-backed ObenBlock wallet, plan, pay and the actual fee", async () => {
  const core = await loadCore("/wallet/gnb_wallet.wasm", pin);
  const created = core.create();
  assert.match(created.address, /^obb1q[0-9a-f]{48}$/);
  assert.equal(created.words.split(" ").length, 24);
  core.wipe();
  assert.equal(core.restore(created.words).address, created.address);
  const ks = core.exportKeystore("Correct-Horse-9-battery");
  assert.match(ks, /"version": 3/);
  // The keystore binds the key's gnb1q form (the GnB tools open it too).
  assert.ok(ks.includes(`gnb1q${created.address.slice(5)}`));
  core.wipe();
  assert.equal(core.open(ks, "Correct-Horse-9-battery").address, created.address);
  assert.throws(() => core.open(ks, "Correct-Horse-9-battery", "regtest"), /regtest|testnet/);

  const spk = created.address.slice(5, 45);
  const utxos = [
    { txid: "11".repeat(32), index: 0, value: "500000000", script_pubkey: spk },
    { txid: "22".repeat(32), index: 0, value: "20000000", script_pubkey: spk },
  ];
  const dest = core.normalize(created.address); // own address is a valid destination
  const next = 12;
  const plan = core.plan(utxos, dest, "100000000", "0", next);
  assert.equal(plan.version, 3);
  assert.deepEqual(plan.prev_txids, [], "a version-3 signature commits every spent value");
  // A supplied transaction that does not hash to its claimed id is refused.
  assert.throws(() => core.pay(utxos, dest, "100000000", "0", next, { ["11".repeat(32)]: "00" }));
  const tx = core.pay(utxos, dest, "100000000", "0", next, {});
  assert.equal(tx.version, 3);
  assert.equal(tx.amounts_committed, true);
  assert.equal(tx.inputs, 1);
  assert.equal(tx.unverified_inputs, 0);
  assert.equal(tx.raw.slice(0, 8), "03000000");
  assert.equal(BigInt(tx.fee), 500000000n - 100000000n - BigInt(tx.change));
  assert.ok(BigInt(tx.fee) < 100000n);
  // A gnb1q destination is the same script as its obb1q form.
  const gnbDest = `gnb1q${dest.slice(5)}`;
  // (Falcon signatures vary in length: compare what is paid, not the size.)
  const viaGnb = core.pay(utxos, gnbDest, "100000000", "0", next, {});
  assert.ok(viaGnb.raw.includes(spk), "paid to the same 20-byte script");
  assert.equal(viaGnb.amount, tx.amount);
  // A regtest destination is another network.
  assert.throws(() => core.pay(utxos, `obb1t${dest.slice(5)}`, "100000000", "0", next, {}), /network/);
  // The fee guard holds even if a caller asks for a huge fee.
  assert.throws(() => core.pay(utxos, dest, "1", "490000000", next, {}), /guard/);
  // Without the next block's height the core refuses to sign.
  assert.throws(() => core.pay(utxos, dest, "100000000", "0", undefined, {}), /next_height/);
  core.wipe();
});

test("the core signs version 3 at every height, also below GnB's activation", async () => {
  const core = await loadCore("/wallet/gnb_wallet.wasm", pin);
  const created = core.create();
  const spk = created.address.slice(5, 45);
  const utxos = [{ txid: "33".repeat(32), index: 1, value: "500000000", script_pubkey: spk }];
  const dest = core.normalize(created.address);
  for (const h of [0, 1, GNB_MAINNET_ACTIVATION - 1, GNB_MAINNET_ACTIVATION]) {
    const plan = core.plan(utxos, dest, "100000000", "0", h);
    assert.equal(plan.version, 3, `the committed core does not sign version 3 at ${h}: rebuild and re-pin it (scripts/build-wallet-wasm.sh)`);
    assert.deepEqual(plan.prev_txids, []);
    const tx = core.pay(utxos, dest, "100000000", "0", h, {});
    assert.equal(tx.version, 3);
    assert.equal(tx.raw.slice(0, 8), "03000000");
  }
  core.wipe();
});

test("network selector: regtest keys and the node's chain id", async () => {
  const core = await loadCore("/wallet/gnb_wallet.wasm", pin);
  const reg = core.create("regtest");
  assert.match(reg.address, /^obb1t[0-9a-f]{48}$/);
  assert.equal(reg.words, undefined, "a regtest key has no recovery phrase");
  const ks = core.exportKeystore("Correct-Horse-9-battery");
  core.wipe();
  assert.equal(core.open(ks, "Correct-Horse-9-battery", "regtest").address, reg.address);
  assert.equal(core.open(ks, "Correct-Horse-9-battery", "testnet").address, reg.address, "testnet is regtest's older name");
  assert.throws(() => core.open(ks, "Correct-Horse-9-battery"), /mainnet/);
  assert.match(core.create(true).address, /^obb1t/, "the boolean form still means regtest");
  assert.throws(() => core.create("signet"), /unknown wallet network/);
  core.wipe();
  assert.equal(networkOfChainId("0x4f420001"), "mainnet");
  assert.equal(networkOfChainId("0x4F420002"), "regtest");
  for (const id of ["0x474e0001", "0x474e0002", undefined, 1330774017]) assert.throws(() => networkOfChainId(id), /not an ObenBlock node/);
  assert.equal(walletNetwork("testnet"), "regtest");
});

// Coinbase maturity: the page counts as spendable, and hands the core, only
// the coins the next block can spend (the rule of
// gnb_crypto::wallet::send::utxo_row_spendable_at). The page used to count
// every getutxos row ("Spendable now", Max), so Max asked for immature value
// the core cannot select.
test("COINBASE_MATURITY matches the consensus constant", () => {
  const rust = readFileSync(new URL("../../crates/gnb-crypto/src/core/mod.rs", import.meta.url), "utf8");
  const m = rust.match(/pub const COINBASE_MATURITY:\s*u64\s*=\s*(\d+);/);
  assert.ok(m, "COINBASE_MATURITY not found in crates/gnb-crypto/src/core/mod.rs");
  assert.equal(COINBASE_MATURITY, Number(m[1]));
});

test("splitByMaturity: a coinbase output is spendable from coinbase_height + COINBASE_MATURITY on", () => {
  const M = COINBASE_MATURITY;
  const row = (txid, cb) => ({ txid: txid.repeat(32), index: 0, value: "100000000", ...(cb === undefined ? {} : { coinbase_height: cb }) });
  const rows = [row("11"), row("22", 500), row("33", 500 - M), row("44", null), row("55", "500"), row("66", 900)];
  const ids = (rs) => rs.map((r) => r.txid.slice(0, 2));
  let { spendable, immature } = splitByMaturity(rows, 500 + M - 1);
  assert.deepEqual(ids(spendable), ["11", "33", "44"]);
  assert.deepEqual(ids(immature), ["22", "55", "66"], "one block early, malformed, and above the next height");
  ({ spendable, immature } = splitByMaturity(rows, 500 + M));
  assert.deepEqual(ids(spendable), ["11", "22", "33", "44"]);
  assert.deepEqual(ids(immature), ["55", "66"]);
});

test("spendableWindow widens a cut-short list that immature coinbase outputs filled", async () => {
  const next = 1000;
  // The node's order: 55 immature mining rewards, then 5 mature coins.
  const all = [
    ...Array.from({ length: 55 }, (_, i) => ({ txid: i.toString(16).padStart(64, "0"), index: 0, value: "1000000000", coinbase_height: next - 1 })),
    ...Array.from({ length: 5 }, (_, i) => ({ txid: (100 + i).toString(16).padStart(64, "0"), index: 0, value: "200000000" })),
  ];
  const asked = [];
  const fetchRows = async (limit) => { asked.push(limit); return { rows: all.slice(0, limit), truncated: all.length > limit }; };
  const w = await spendableWindow(fetchRows, next, 50, 1000);
  assert.deepEqual(asked, [50, 1000]);
  assert.equal(w.spendable.length, 5);
  assert.ok(w.spendable.every((r) => r.coinbase_height === undefined));
  assert.equal(w.immature.length, 55);
  assert.equal(w.truncated, false);
  assert.equal(w.listed, 60);

  // Mature coins first, or nothing immature: one call.
  asked.length = 0;
  const mature = all.slice(55);
  const one = await spendableWindow(async (limit) => { asked.push(limit); return { rows: mature, truncated: false }; }, next, 50, 1000);
  assert.deepEqual(asked, [50]);
  assert.equal(one.spendable.length, 5);
  // At most `window` spendable coins are offered.
  const many = Array.from({ length: 80 }, (_, i) => ({ txid: i.toString(16).padStart(64, "0"), index: 0, value: "1" }));
  const capped = await spendableWindow(async (limit) => ({ rows: many.slice(0, limit), truncated: many.length > limit }), next, 50, 1000);
  assert.equal(capped.spendable.length, 50);
  assert.equal(capped.truncated, true);
});

test("the page hands the core only the coins spendable at the next block", async () => {
  const app = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8");
  assert.match(app, /const coins = splitByMaturity\(state\.utxos, next\)\.spendable;/);
  assert.match(app, /core\.plan\(coins, /);
  assert.match(app, /core\.pay\(coins, /);
  assert.doesNotMatch(app, /core\.(plan|pay)\(state\.utxos/);
  assert.match(app, /state\.utxoTotal = total\(coins\.spendable\);/);

  // With the rows the page passes, even a core that does not check maturity
  // itself (the committed binary until it is rebuilt) cannot select an
  // immature output. Given both rows, that core pays 1 OBB from the 2 OBB
  // immature mining reward (the closest fit), a payment every node refuses.
  const core = await loadCore("/wallet/gnb_wallet.wasm", pin);
  const created = core.create();
  const spk = created.address.slice(5, 45);
  const next = 1000;
  const rows = [
    { txid: "77".repeat(32), index: 0, value: "200000000", script_pubkey: spk, coinbase_height: next - 1 },
    { txid: "88".repeat(32), index: 0, value: "10000000000", script_pubkey: spk },
  ];
  const coins = splitByMaturity(rows, next).spendable;
  const tx = core.pay(coins, core.normalize(created.address), "100000000", "0", next, {});
  assert.equal(tx.inputs, 1);
  assert.equal(BigInt(tx.fee) + BigInt(tx.change) + 100000000n, 10000000000n, "paid from the mature coin");
  core.wipe();
});
