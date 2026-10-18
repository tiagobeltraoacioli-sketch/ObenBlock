// Launch placeholders (scripts/site-launch-fill.mjs): every key is a known
// one, the pre-launch pages say "At launch" / "Not launched", and filling
// escapes the values and leaves no placeholder behind under --strict.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fillHtml } from "../../scripts/site-launch-fill.mjs";

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const KEYS = ["BANNER", "STATUS", "LAUNCH_TIME", "GENESIS_HASH", "SEED_NODES", "DNS_SEED",
  "STRATUM_ENDPOINT", "RELEASE", "GENESIS_TARGET", "FAQ_LIVE", "FOOTER_STATUS"];

test("the home page carries every launch key and no other", () => {
  const { keys } = fillHtml(read("index.html"), {});
  assert.deepEqual([...keys].sort(), [...KEYS].sort());
});

test("before launch the facts read as not known yet", () => {
  const html = read("index.html");
  for (const k of ["LAUNCH_TIME", "GENESIS_HASH", "SEED_NODES", "STRATUM_ENDPOINT"]) {
    assert.match(html, new RegExp(`<span class="at-launch" data-launch="${k}">At launch</span>`), k);
  }
  assert.match(html, /data-launch="STATUS">Not launched</);
  assert.ok(!/[0-9a-f]{64}/.test(html), "no 64-hex value (a genesis hash) before launch");
});

test("filling escapes text and turns markers into values", () => {
  const values = Object.fromEntries(KEYS.map((k) => [k, `${k} <b>&"</b>`]));
  const { html } = fillHtml(read("index.html"), values);
  assert.ok(!html.includes('class="at-launch" data-launch='), "a marker survived");
  assert.ok(html.includes("GENESIS_HASH &lt;b&gt;&amp;&quot;&lt;/b&gt;"));
  assert.ok(!html.includes("<b>&\"</b>"));
  assert.match(html, /<span class="status live" data-launch="STATUS">/);
  for (const page of ["downloads.html", "brand.html"]) {
    const { keys } = fillHtml(read(page), {});
    for (const k of keys) assert.ok(KEYS.includes(k), `${page}: unknown key ${k}`);
  }
});

test("the home page links the explorer, the wallet, the OBIPs and the PoCI design", () => {
  const html = read("index.html");
  for (const href of ['href="/explorer"', 'href="/wallet"', 'href="/downloads"',
    'href="https://github.com/gnb-smh/ObenBlock/tree/main/docs/obip"',
    'href="https://github.com/gnb-smh/ObenBlock/blob/main/docs/DESIGN-obenblock-poci.md"']) {
    assert.ok(html.includes(href), href);
  }
  for (let n = 2; n <= 13; n++) assert.match(html, new RegExp(`<td class="obip">${n}</td>`));
});
