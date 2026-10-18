#!/usr/bin/env node
// Fill the launch placeholders of the obenblock.xyz pages (site/index.html,
// downloads.html, brand.html) from a JSON object { "KEY": "text", ... }.
//
//   node scripts/site-launch-fill.mjs launch.json [site-dir] [--strict]
//
// Every element carrying data-launch="KEY" gets its content replaced by the
// HTML-escaped text. An "At launch" marker becomes a plain value
// (class "launch-value"); a status label becomes "status live". Keys absent
// from the JSON are left as they are and listed; --strict makes that an error.
// Values are text only: no markup is ever taken from the JSON.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const PAGES = ["index.html", "downloads.html", "brand.html"];
const KEY = /^[A-Z][A-Z0-9_]*$/;

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// Element with data-launch: <tag attrs data-launch="KEY" attrs>inner</tag>, inner not nesting the same tag.
const ELEMENT = /<(span|p|code|td)\b([^>]*?)\sdata-launch="([A-Z0-9_]+)"([^>]*)>([\s\S]*?)<\/\1>/g;

export function fillHtml(html, values) {
  const seen = new Set();
  const out = html.replace(ELEMENT, (whole, tag, before, key, after, inner) => {
    seen.add(key);
    if (!Object.hasOwn(values, key)) return whole;
    let attrs = `${before} data-launch="${key}"${after}`;
    attrs = attrs.replace(/\bclass="at-launch"/, 'class="launch-value"').replace(/\bclass="status [a-z]+"/, 'class="status live"');
    return `<${tag}${attrs}>${escapeHtml(values[key])}</${tag}>`;
  });
  return { html: out, keys: seen };
}

function main(argv) {
  const strict = argv.includes("--strict");
  const args = argv.filter((a) => a !== "--strict");
  if (!args[0]) { console.error("usage: site-launch-fill.mjs launch.json [site-dir] [--strict]"); return 2; }
  const values = JSON.parse(readFileSync(args[0], "utf8"));
  for (const [k, v] of Object.entries(values)) {
    if (!KEY.test(k) || typeof v !== "string" || !v.trim()) { console.error(`bad entry: ${k}`); return 2; }
  }
  const dir = args[1] ?? new URL("../site/", import.meta.url).pathname;
  const all = new Set();
  for (const page of PAGES) {
    const p = join(dir, page);
    if (!existsSync(p)) continue;
    const { html, keys } = fillHtml(readFileSync(p, "utf8"), values);
    keys.forEach((k) => all.add(k));
    writeFileSync(p, html);
  }
  const unknown = Object.keys(values).filter((k) => !all.has(k));
  const missing = [...all].filter((k) => !Object.hasOwn(values, k)).sort();
  if (unknown.length) { console.error(`keys not on any page: ${unknown.join(", ")}`); return 2; }
  if (missing.length) {
    console.error(`${strict ? "error" : "note"}: placeholders still open: ${missing.join(", ")}`);
    if (strict) return 1;
  }
  console.log(`filled ${Object.keys(values).length} keys in ${dir}`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = main(process.argv.slice(2));
