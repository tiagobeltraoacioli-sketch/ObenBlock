// B2-T3, every page: each numeric argument a site page passes to the explorer
// API as a literal (`api("getutxos", [address, 500])`, ...) must pass the
// API's own parameter validation (deploy/explorer-api/gnb_explorer_api.py
// ALLOWED), or the page asks for something the API answers with HTTP 400.
// The web wallet asked getutxos for 1,000 rows against a cap of 50; the
// sidechain explorer asked getdifficultyhistory for 200 points against 100.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";

const SITE = fileURLToPath(new URL("..", import.meta.url));
const API_PY = fileURLToPath(new URL("../../deploy/explorer-api/gnb_explorer_api.py", import.meta.url));

function pageScripts(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name !== "tests") out.push(...pageScripts(p));
    } else if (name.endsWith(".js")) {
      out.push(p);
    }
  }
  return out;
}

// [file:line, method, position, value] for every numeric or boolean literal
// argument of an api("method", [...]) call.
function literalArguments() {
  const found = [];
  for (const file of pageScripts(SITE)) {
    const src = readFileSync(file, "utf8");
    for (const m of src.matchAll(/\bapi\(\s*"([a-z]+)"\s*,\s*\[([^\]]*)\]/g)) {
      const line = src.slice(0, m.index).split("\n").length;
      m[2].split(",").map((a) => a.trim()).forEach((arg, i) => {
        if (/^\d+$/.test(arg)) found.push([`${relative(SITE, file)}:${line}`, m[1], i, Number(arg)]);
        else if (arg === "true" || arg === "false") found.push([`${relative(SITE, file)}:${line}`, m[1], i, arg === "true"]);
      });
    }
  }
  return found;
}

const CHECK = `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("gnb_explorer_api", sys.argv[1])
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
bad = []
for where, method, i, value in json.loads(sys.argv[2]):
    if method not in api.ALLOWED:
        bad.append(f"{where}: {method} is not served by the explorer API")
        continue
    checkers = api.ALLOWED[method][0]
    if i >= len(checkers):
        bad.append(f"{where}: {method} takes {len(checkers)} parameters, the page passes more")
        continue
    try:
        checkers[i](value)
    except ValueError as e:
        bad.append(f"{where}: {method} parameter {i} = {value!r}: {e}")
print(json.dumps(bad))
`;

test("every literal argument a page sends passes the explorer API's validation", () => {
  const args = literalArguments();
  // The wallet's getutxos limits are constants (core.js UTXO_WINDOW /
  // UTXO_WIDE_WINDOW), checked against the API by wallet-api-window.test.mjs.
  assert.ok(args.some(([, m]) => m === "getdifficultyhistory"), "the scan must see the explorer's calls");
  assert.ok(args.some(([, m]) => m === "getaddresshistory"), "the scan must see the wallet's history call");
  assert.ok(args.length >= 10, `only ${args.length} literal arguments found`);
  const bad = JSON.parse(execFileSync("python3", ["-I", "-c", CHECK, API_PY, JSON.stringify(args)], { encoding: "utf8" }));
  assert.deepEqual(bad, []);
});
