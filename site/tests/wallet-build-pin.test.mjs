// Exercise the real pin generator in a disposable, offline file fixture.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";

test("pin-only generator replaces a stale pin in the served wallet", () => {
  const fixture = mkdtempSync(join(tmpdir(), "gnb-wallet-pin-"));
  const files = ["scripts/build-wallet-wasm.sh", "site/wallet/app.js",
    "site/wallet/core.js", "site/wallet/qrcode.js", "site/assets/safe.js",
    "site/assets/site.js", "site/explorer.js", "site/assets/explorer-views.js",
    "site/wallet.html", "site/explorer.html", "site/index.html", "site/brand.html",
    "site/downloads.html"];
  try {
    for (const name of files) {
      const target = join(fixture, name);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, readFileSync(new URL("../../" + name, import.meta.url)));
    }
    for (const [file, constant] of [["app.js", "WASM_SHA256"]]) {
      const target = join(fixture, "site/wallet", file);
      writeFileSync(target, readFileSync(target, "utf8").replace(
        new RegExp(`^const ${constant} = "[0-9a-f]{64}";$`, "m"),
        `const ${constant} = "${"0".repeat(64)}";`));
    }
    const binary = Buffer.from("offline pin-only fixture: no module is executed");
    const binaryPath = join(fixture, "site/wallet/gnb_wallet.wasm");
    writeFileSync(binaryPath, binary);
    execFileSync("sh", [join(fixture, "scripts/build-wallet-wasm.sh"), "--pin-only"], { cwd: fixture });
    const expected = createHash("sha256").update(binary).digest("hex");
    for (const [file, constant] of [["app.js", "WASM_SHA256"]]) {
      const actual = readFileSync(join(fixture, "site/wallet", file), "utf8")
        .match(new RegExp(`^const ${constant} = "([0-9a-f]{64})";$`, "m"))?.[1];
      assert.equal(actual, expected, `${file}: generator left a stale pin`);
    }
    assert.deepEqual(readFileSync(binaryPath), binary, "pin-only must not replace the artifact");
  } finally { rmSync(fixture, { recursive: true, force: true }); }
});
