// WAL-2: worker/check-ssl-mode.mjs refuses every Cloudflare configuration in
// which the edge does not verify the explorer origin's certificate.
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkOriginTls, mayMatchHost, pageTargetMayMatchHost } from "../../worker/check-ssl-mode.mjs";

const HOST = "api.obenblock.xyz";

/** A fake Cloudflare API: zone mode, Configuration Rules, Page Rules. */
function cloudflare({ mode = "strict", rules = null, pages = [], status = {} } = {}) {
  const seen = [];
  const fetchFn = async (url, init) => {
    seen.push(url);
    assert.equal(init.headers.authorization, "Bearer tok");
    const reply = (code, body) => new Response(JSON.stringify(body), { status: code });
    if (url.endsWith("/zones/z1/settings/ssl")) {
      if (status.ssl) return reply(status.ssl, { success: false });
      return reply(200, { success: true, result: { id: "ssl", value: mode } });
    }
    if (url.endsWith("/zones/z1/rulesets/phases/http_config_settings/entrypoint")) {
      if (rules === null) return reply(404, { success: false, errors: [{ code: 10003 }] });
      return reply(200, { success: true, result: { rules } });
    }
    if (url.endsWith("/zones/z1/pagerules?status=active")) {
      if (status.pages) return reply(status.pages, { success: false });
      return reply(200, { success: true, result: pages });
    }
    return reply(404, { success: false });
  };
  return { fetchFn, seen };
}

const check = (cf) => checkOriginTls({ token: "tok", zoneId: "z1", hostname: HOST, fetchFn: cf.fetchFn });

test("Full (strict) with no overriding rule passes", async () => {
  const cf = cloudflare();
  const r = await check(cf);
  assert.deepEqual(r, { ok: true, mode: "strict", problems: [] });
  assert.equal(cf.seen.length, 3);
  assert.equal((await check(cloudflare({ mode: "origin_pull" }))).ok, true);
});

test("Full, Flexible and Off are refused: the origin certificate is not verified", async () => {
  for (const mode of ["full", "flexible", "off"]) {
    const r = await check(cloudflare({ mode }));
    assert.equal(r.ok, false, mode);
    assert.match(r.problems.join("\n"), new RegExp(`"${mode}".*Full \\(strict\\)`));
  }
});

test("a Configuration Rule lowering SSL for the API host fails the check", async () => {
  const lowering = { id: "r1", enabled: true, action: "set_config", action_parameters: { ssl: "full" },
                     expression: `(http.host eq "${HOST}")` };
  assert.equal((await check(cloudflare({ rules: [lowering] }))).ok, false);
  // A rule without a host condition applies to every host.
  assert.equal((await check(cloudflare({ rules: [{ ...lowering, expression: "true" }] }))).ok, false);
  // Disabled, other hosts, or a rule that keeps strict: fine.
  assert.equal((await check(cloudflare({ rules: [{ ...lowering, enabled: false }] }))).ok, true);
  assert.equal((await check(cloudflare({ rules: [{ ...lowering, expression: '(http.host eq "www.example.org")' }] }))).ok, true);
  assert.equal((await check(cloudflare({ rules: [{ ...lowering, action_parameters: { ssl: "strict" } }] }))).ok, true);
});

test("a Page Rule lowering SSL for the API host fails the check", async () => {
  const page = (target, value) => ({ targets: [{ target: "url", constraint: { operator: "matches", value: target } }],
                                     actions: [{ id: "ssl", value }], status: "active" });
  assert.equal((await check(cloudflare({ pages: [page(`${HOST}/*`, "full")] }))).ok, false);
  assert.equal((await check(cloudflare({ pages: [page("*.obenblock.xyz/*", "flexible")] }))).ok, false);
  assert.equal((await check(cloudflare({ pages: [page("www.obenblock.xyz/*", "full")] }))).ok, true);
  assert.equal((await check(cloudflare({ pages: [page(`${HOST}/*`, "strict")] }))).ok, true);
});

test("an unreadable setting is a failure, never a pass", async () => {
  assert.equal((await check(cloudflare({ status: { ssl: 403 } }))).ok, false);
  assert.equal((await check(cloudflare({ status: { pages: 403 } }))).ok, false);
  const missing = await checkOriginTls({ token: "", zoneId: "z1", hostname: HOST, fetchFn: async () => assert.fail() });
  assert.equal(missing.ok, false);
});

test("host matching helpers", () => {
  assert.equal(mayMatchHost(`http.host in {"${HOST}" "x.org"}`, HOST), true);
  assert.equal(mayMatchHost('starts_with(http.request.uri.path, "/v1")', HOST), true);
  assert.equal(mayMatchHost('http.request.full_uri eq "https://www.x.org/"', HOST), false);
  assert.equal(mayMatchHost("ip.src eq 1.2.3.4", HOST), true);
  assert.equal(mayMatchHost('http.host ne "www.x.org"', HOST), true);
  assert.equal(mayMatchHost('ends_with(http.host, ".obenblock.xyz")', HOST), true);
  assert.equal(mayMatchHost('http.host eq "www.x.org" and ip.src eq 1.2.3.4', HOST), false);
  assert.equal(pageTargetMayMatchHost(`https://${HOST}/v1/*`, HOST), true);
  assert.equal(pageTargetMayMatchHost("*obenblock.xyz/*", HOST), true);
  assert.equal(pageTargetMayMatchHost("obenblock.xyz/*", HOST), false);
});

test("the explorer README and the Worker README require Full (strict)", () => {
  for (const path of ["../../deploy/explorer-api/README.md", "../../worker/README.md"]) {
    const text = readFileSync(new URL(path, import.meta.url), "utf8");
    assert.match(text, /Full \(strict\)/, path);
    assert.match(text, /check-ssl-mode\.mjs/, path);
  }
});
