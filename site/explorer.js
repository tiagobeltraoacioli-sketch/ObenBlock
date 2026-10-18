// obenblock.xyz explorer: data fetching, routing and DOM wiring. All markup is
// built by /assets/explorer-views.js (escaped `html` templates, WAL-3). The
// explorer API (deploy/explorer-api) shows ObenBlock's forms: obb1 addresses,
// SHA-256d difficulty and block ids, and PoWit `finality` per block,
// transaction and address movement.
import { html, isAddress, canonicalAddress } from "/assets/safe.js";
import * as V from "/assets/explorer-views.js";

const app = document.getElementById("app");
let timer = null;

// ── data ─────────────────────────────────────────────────────────────────────
async function api(method, params = []) {
  const r = await fetch(`/api/${method}?p=${encodeURIComponent(JSON.stringify(params))}`);
  let doc; try { doc = await r.json(); } catch { throw new Error(`HTTP ${r.status}`); }
  if (doc.error) throw new Error(String(doc.error));
  if (doc.result === null || typeof doc.result !== "object") throw new Error("unexpected response");
  return doc.result;
}
async function carryover(addr) {
  try { const r = await fetch(`/api/carryover/${addr}`); return (await r.json()).result; } catch { return null; }
}
const show = (el, markup) => { el.innerHTML = String(markup); };

document.addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-copy]"); if (!b) return;
  navigator.clipboard?.writeText(b.dataset.copy).then(() => { b.textContent = "copied"; setTimeout(() => (b.textContent = "copy"), 1200); });
});

// Chart tooltips: labels are markup built by the views with `html`.
function wireCharts(root) {
  root.querySelectorAll("[data-chart]").forEach((el) => {
    let pts; try { pts = JSON.parse(el.dataset.points); } catch { return; }
    const svg = el.querySelector("svg"), tip = el.querySelector(".tip");
    const xh = svg.querySelector(".xh"), xd = svg.querySelector(".xd");
    const move = (ev) => {
      const r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal, x = ((ev.clientX - r.left) / r.width) * vb.width;
      let best = pts[0]; for (const p of pts) if (Math.abs(p[0] - x) < Math.abs(best[0] - x)) best = p;
      xh.setAttribute("x1", best[0]); xh.setAttribute("x2", best[0]); xh.setAttribute("opacity", 1);
      xd.setAttribute("cx", best[0]); xd.setAttribute("cy", best[1]); xd.setAttribute("opacity", 1);
      tip.innerHTML = best[2]; tip.style.left = `${(best[0] / vb.width) * r.width}px`; tip.style.top = `${(best[1] / vb.height) * r.height}px`; tip.style.opacity = 1;
    };
    svg.addEventListener("pointermove", move);
    svg.addEventListener("pointerleave", () => { tip.style.opacity = 0; xh.setAttribute("opacity", 0); xd.setAttribute("opacity", 0); });
  });
  root.querySelectorAll("[data-bars]").forEach((el) => {
    const svg = el.querySelector("svg"), tip = el.querySelector(".tip");
    el.querySelectorAll(".bar-g").forEach((g) => {
      g.addEventListener("pointerenter", () => {
        const r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal, b = g.querySelector("rect");
        tip.innerHTML = g.dataset.tip;
        tip.style.left = `${((+b.getAttribute("x") + +b.getAttribute("width") / 2) / vb.width) * r.width}px`;
        tip.style.top = `${(+b.getAttribute("y") / vb.height) * r.height + 20}px`; tip.style.opacity = 1;
      });
      g.addEventListener("pointerleave", () => (tip.style.opacity = 0));
    });
  });
}
function scrollDagEnd(root) { root.querySelectorAll(".dag").forEach((d) => (d.scrollLeft = d.scrollWidth)); }

// ── views ────────────────────────────────────────────────────────────────────
let lastSeen = new Set();
async function viewHome(refresh = false) {
  if (!refresh) show(app, V.homeHead());
  const [dag, supply, stats, pct, chain, dagWindow, hist, mem, pw] = await Promise.all([
    api("getdaginfo"), api("getsupplyinfo"), api("getchainstats"), api("getblocktimepercentiles"),
    api("getselectedchain", [0, 12]), api("getdagwindow", [90]), api("getdifficultyhistory", [100]), api("getmempoolstats"),
    api("getpowitinfo").catch(() => null),
  ]);
  show(document.getElementById("h-stats"), V.homeStats({ dag, supply, stats, pct, chain, mem, pw }));
  const blocks = Array.isArray(chain.blocks) ? chain.blocks : [];
  const fresh = new Set(blocks.filter((b) => refresh && !lastSeen.has(b.hash)).map((b) => b.hash));
  lastSeen = new Set(blocks.map((b) => b.hash));
  const rest = document.getElementById("h-rest");
  show(rest, V.homeRest({ dagWindow, chain, fresh, hist }));
  wireCharts(rest); scrollDagEnd(rest);
}

async function viewBlocks(page = 0) {
  const per = 50;
  show(app, V.blocksHead());
  const r = await api("getselectedchain", [page * per, per]);
  show(document.getElementById("b-list"), V.blocksPage(r, page, per));
}

async function viewDag() {
  show(app, V.dagHead());
  const w = await api("getdagwindow", [300]);
  const el = document.getElementById("d-dag");
  show(el, V.dagSvg(w.nodes, { height: 300 })); scrollDagEnd(el);
}

async function viewBlock(hash) {
  show(app, V.loading("Loading block"));
  // getblock adds the block's PoWit body (witness shares, attestations).
  const [b, full] = await Promise.all([api("getblockdag", [hash]), api("getblock", [hash, false]).catch(() => null)]);
  show(app, V.blockPage(b, full));
}

async function viewFinality() {
  show(app, V.finalityHead());
  const [pw, info, chain] = await Promise.all([
    api("getpowitinfo"), api("getfinalityinfo").catch(() => null), api("getselectedchain", [0, 10]).catch(() => ({ blocks: [] })),
  ]);
  const hashes = (Array.isArray(chain.blocks) ? chain.blocks : []).map((b) => b?.hash).filter((h) => /^[0-9a-f]{64}$/.test(h));
  const blocks = (await Promise.all(hashes.map((h) => api("getblock", [h, false]).catch(() => null)))).filter(Boolean);
  show(document.getElementById("fi"), V.finalityPage(pw, info, blocks));
}

async function viewTx(txid) {
  show(app, V.loading("Loading transaction"));
  show(app, V.txPage(await api("gettransactionfull", [txid])));
}

// B1-T11: older pages follow the cursor the previous page returned
// (`next_cursor`); the node and the API refuse offsets above 10,000.
async function viewAddress(addr, page = 0, cursor = null) {
  addr = await canonicalAddress(addr, api);
  if (/^(?:obb|gnb)1[mn]/.test(addr)) {
    // The history index is single-key only; a valid policy alias must not
    // be sent to it or presented as an invalid address/empty history.
    show(app, html`<div class="pagehead"><h1>Policy address</h1><div class="hash">${addr}</div></div>
      <p class="empty">Transaction history is not available for policy addresses yet.</p>`);
    return;
  }
  const per = 25;
  show(app, V.loading("Loading address"));
  const params = cursor ? [addr, per, 0, cursor] : [addr, per, page * per];
  const [h, carry] = await Promise.all([api("getaddresshistory", params), carryover(addr)]);
  show(app, V.addressPage(addr, h, carry, page, per));
}

async function viewHolders() {
  show(app, V.holdersHead());
  const [rich, dist] = await Promise.all([api("getrichlist", [100, 0]), api("getsupplydistribution")]);
  show(document.getElementById("ho"), V.holdersPage(rich, dist));
}

// ── search & routing ─────────────────────────────────────────────────────────
document.getElementById("search").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("q").value.trim();
  // Preserve legacy/hex search casing without normalizing mixed-case Bech32m.
  const q = /^(?:[0-9a-f]{64}|(?:obb|gnb|bloch)1[qt][0-9a-f]{48}|(?:obb|gnb)1[mn][0-9a-f]{72})$/i.test(input) ? input.toLowerCase() : input;
  if (!q) return;
  if (isAddress(q)) return go(`#/address/${q}`);
  // A Bloch key-hash address is the same owner: its checksum covers the hash
  // only, so the obb1 form keeps it.
  if (/^bloch1[qt][0-9a-f]{48}$/.test(q)) return go(`#/address/obb1${q[6]}${q.slice(7)}`);
  if (/^\d{1,12}$/.test(q)) {
    try {
      const dag = await api("getdaginfo");
      const off = Number(dag.chain_length) - 1 - Number(q);
      if (!(off >= 0)) return show(app, html`<div class="err">Height ${q} is above the tip (${V.int(dag.tip_height)}).</div>`);
      const r = await api("getselectedchain", [off, 1]);
      const hash = r.blocks?.[0]?.hash;
      if (/^[0-9a-f]{64}$/.test(hash)) return go(`#/block/${hash}`);
    } catch (e) { return show(app, V.fail(e)); }
  }
  if (/^[0-9a-f]{64}$/.test(q)) {
    try { await api("getblockdag", [q]); return go(`#/block/${q}`); } catch {}
    return go(`#/tx/${q}`);
  }
  show(app, html`<div class="err">Not a block hash, transaction id, obb1q… address or height.</div>`);
});
function go(h) { if (location.hash === h) route(); else location.hash = h; }

async function route() {
  clearInterval(timer); timer = null;
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const [v, a, b, c] = parts;
  document.querySelectorAll("[data-nav]").forEach((n) => n.removeAttribute("aria-current"));
  const nav = { "": "home", blocks: "blocks", dag: "dag", finality: "finality", holders: "holders" }[v || ""];
  if (nav) document.querySelector(`[data-nav="${nav}"]`)?.setAttribute("aria-current", "page");
  window.scrollTo(0, 0);
  const pageNo = (s) => (/^\d{1,6}$/.test(s || "") ? Number(s) : 0);
  try {
    if (!v) { await viewHome(); timer = setInterval(() => viewHome(true).catch(() => {}), 10000); }
    else if (v === "blocks") await viewBlocks(pageNo(a));
    else if (v === "dag") { await viewDag(); timer = setInterval(() => viewDag().catch(() => {}), 15000); }
    else if (v === "holders") await viewHolders();
    else if (v === "finality") { await viewFinality(); timer = setInterval(() => viewFinality().catch(() => {}), 15000); }
    else if (v === "block" && /^[0-9a-f]{64}$/.test(a)) await viewBlock(a);
    else if (v === "tx" && /^[0-9a-f]{64}$/.test(a)) await viewTx(a);
    else if (v === "address" && isAddress(a)) await viewAddress(a, pageNo(b), /^[0-9a-f]{32}$/.test(c || "") ? c : null);
    else show(app, html`<div class="err">Page not found. <a href="#/">Back to the overview</a></div>`);
  } catch (e) { show(app, V.fail(e)); }
}
window.addEventListener("hashchange", route);
route();
