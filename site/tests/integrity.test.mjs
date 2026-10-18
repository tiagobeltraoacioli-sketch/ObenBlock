// WAL-5 / WAL-3: pinned wasm hash, Subresource Integrity, no inline script,
// no raw template literals assigned to innerHTML.
// node --test site/tests/*.test.mjs   (refresh pins: scripts/build-wallet-wasm.sh --pin-only)
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const site = (p) => new URL(`../${p.replace(/^\//, "")}`, import.meta.url);
const read = (p) => readFileSync(site(p));
const PAGES = ["index.html", "brand.html", "downloads.html", "explorer.html", "wallet.html"];

test("the wallet core hash is pinned in app.js and matches the binary", () => {
  const app = read("wallet/app.js").toString();
  const pin = app.match(/^const WASM_SHA256 = "([0-9a-f]*)";$/m)?.[1];
  assert.ok(pin && pin.length === 64, "WASM_SHA256 must be pinned (scripts/build-wallet-wasm.sh)");
  assert.equal(createHash("sha256").update(read("wallet/gnb_wallet.wasm")).digest("hex"), pin);
  assert.match(app, /loadCore\("\/wallet\/gnb_wallet\.wasm", WASM_SHA256\)/);
});

test("every script and module preload carries a matching SRI hash", () => {
  let checked = 0;
  for (const page of PAGES) {
    const html = read(page).toString();
    const tags = [...html.matchAll(/<(script|link)\b[^>]*>/g)].map((m) => m[0]);
    for (const tag of tags) {
      const src = tag.match(/\b(?:src|href)="([^"]+\.js)"/)?.[1];
      if (!src) continue;
      const sri = tag.match(/\bintegrity="sha384-([A-Za-z0-9+/=]+)"/)?.[1];
      assert.ok(sri, `${page}: ${src} has no integrity`);
      assert.equal(sri, createHash("sha384").update(read(src)).digest("base64"), `${page}: stale SRI for ${src}`);
      checked++;
    }
    assert.ok(!/<script>(?!\s*<\/script>)/.test(html), `${page}: inline script (blocked by the CSP)`);
  }
  assert.ok(checked >= 7);
});

test("no page script assigns a raw template literal to innerHTML", () => {
  for (const f of ["explorer.js", "wallet/app.js", "assets/explorer-views.js", "assets/site.js"]) {
    const code = read(f).toString();
    assert.ok(!/innerHTML\s*=\s*`/.test(code), `${f}: build markup with html\`\``);
  }
});
