// WAL-3 regression: the explorer escapes hostile API data everywhere.
// node --test site/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import * as V from "../assets/explorer-views.js";

const EVIL = `"><img src=x onerror=alert(1)><script>alert(2)</script>" onmouseover="alert(3)`;
const H = "ab".repeat(32);
const A = "gnb1q" + "cd".repeat(24);

function assertInert(markup, where) {
  const s = String(markup);
  // Escaped text such as "onerror=" is inert; a raw "<" or a quote breaking out is not.
  for (const bad of ["<img", "<script", "javascript:", `" onmouseover=`]) {
    assert.ok(!s.includes(bad), `${where}: found ${bad} in ${s.slice(Math.max(0, s.indexOf(bad) - 80), s.indexOf(bad) + 80)}`);
  }
}

// Every string field forged, numbers replaced by markup.
const forgedBlock = {
  hash: EVIL, height: EVIL, blue_score: EVIL, timestamp: EVIL, confirmations: EVIL, difficulty: EVIL,
  bits: EVIL, nonce: EVIL, merkle_root: EVIL, size: EVIL, colour: EVIL, blue_work: EVIL,
  selected_parent: EVIL, merged_by: EVIL, next_chain_block: EVIL,
  parents: [EVIL, H], mergeset_blues: [EVIL], mergeset_reds: EVIL,
  miner: EVIL, reward: EVIL, tx_count: EVIL, merged: EVIL, reds: EVIL,
  transactions: [{
    txid: EVIL, coinbase: false, size: EVIL, fee: EVIL, total_out: EVIL,
    inputs: [{ value: EVIL, address: EVIL, prev_txid: EVIL, prev_index: EVIL }],
    outputs: [{ value: EVIL, address: EVIL, index: EVIL, spent: EVIL }],
  }, { txid: H, coinbase: true, inputs: [{ coinbase: EVIL }], outputs: [] }],
};

test("block, tx, address and holders pages render forged data inertly", () => {
  assertInert(V.blockPage(forgedBlock), "blockPage");
  assertInert(V.blocksTable([forgedBlock]), "blocksTable");
  assertInert(V.txPage({ status: EVIL, block_hash: EVIL, block_height: EVIL, block_colour: EVIL, timestamp: EVIL, transaction: forgedBlock.transactions[0] }), "txPage");
  assertInert(V.addressPage(EVIL, { balance: EVIL, utxo_count: EVIL, total: EVIL, items: [{ height: EVIL, txid: EVIL, direction: EVIL, amount: EVIL }] },
    { in_carryover: true, amount: EVIL, bloch_amount: EVIL, utxos: EVIL }, 0, 25), "addressPage");
  assertInert(V.holdersPage({ items: [{ rank: EVIL, address: EVIL, balance: EVIL, utxos: EVIL, share: EVIL }] },
    { holders: EVIL, total_supply: EVIL, tiers: [{ label: EVIL, address_count: EVIL, total_sats: EVIL, pct_of_supply: EVIL }] }), "holdersPage");
  assertInert(V.blocksPage({ chain_length: EVIL, blocks: [forgedBlock] }, 0, 50), "blocksPage");
});

test("home page stats, charts and DAG render forged data inertly", () => {
  const dag = { tip_height: EVIL, tip_blue_score: EVIL, block_count: EVIL, tip_count: EVIL, k: EVIL };
  const supply = { issued_sat: EVIL, next_halving_height: EVIL, current_height: EVIL, subsidy_per_block_sat: EVIL, min_tx_fee_sat: EVIL };
  const pct = { p50_secs: EVIL, window: EVIL, avg_secs: EVIL, target_secs: EVIL };
  assertInert(V.homeStats({ dag, supply, stats: { hashrate_hs: EVIL }, pct, chain: { blocks: [forgedBlock] }, mem: { size: EVIL } }), "homeStats");
  const hist = { points: [
    { height: EVIL, bits_hex: EVIL, timestamp: 1_700_000_000, target_hex: "00ff" },
    { height: 2, bits_hex: EVIL, timestamp: 1_700_000_030, target_hex: "00fe" },
    { height: 3, bits_hex: "x", timestamp: EVIL, target_hex: EVIL },
  ] };
  const nodes = [
    { hash: H, height: EVIL, blue_score: 1, colour: EVIL, parents: [EVIL], selected_parent: EVIL },
    { hash: EVIL, height: 1, blue_score: 2, colour: "chain", parents: [H] },
  ];
  const out = V.homeRest({ dagWindow: { nodes }, chain: { blocks: [forgedBlock] }, fresh: new Set(), hist });
  assertInert(out, "homeRest");
  // Chart tooltips are stored in data attributes and later set as markup:
  // the decoded attribute must itself be inert.
  const attr = String(out).match(/data-points="([^"]*)"/)[1]
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  for (const [, , label] of JSON.parse(attr)) assertInert(label, "chart label");
});

test("valid data still renders links and amounts", () => {
  const out = String(V.blocksTable([{ hash: H, height: 7, timestamp: 1, miner: A, reward: "107020547", tx_count: 1, merged: 0, reds: 0, difficulty: 2 }]));
  assert.ok(out.includes(`href="#/block/${H}"`));
  assert.ok(out.includes(`href="#/address/${A}"`));
  assert.ok(out.includes("1.0702"));
  assert.equal(String(V.gnb("123456789")), "1.23456789 <small>OBB</small>");
  assert.equal(String(V.gnb(EVIL)), "—");
});
