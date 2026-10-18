// Explorer views: pure functions from API data to markup (audit WAL-3).
// No DOM access, so `node --test site/tests/` can feed them hostile data.
// Every value goes through the `html` tagged template (escaped) and API
// fields are type-checked (hex64, address, num, sats) before use.
import { html, raw, hex64, address, num, numOr, sats, isHex } from "./safe.js";

export const SAT = 100000000n, CAP = 1250000000000000n, CARRY = 99999999789793n;
// Team and founder allocations (core::vesting): 2 × 36 tranches of 1,250,000 OBB / 36,
// tranche k spendable from height 1,051,200 + k × 87,600.
export const LOCK_EACH = 125000000000000n, LOCK_CLIFF = 1051200, LOCK_STEP = 87600, LOCK_N = 36;
export const unlockedSat = (h) => {
  const k = Math.max(0, Math.min(LOCK_N, Math.floor((h - LOCK_CLIFF) / LOCK_STEP)));
  const base = LOCK_EACH / BigInt(LOCK_N);
  return 2n * (k === LOCK_N ? LOCK_EACH : base * BigInt(k));
};
export const TARGET = 30;
const POW_LIMIT = BigInt("0xffff" + "0".repeat(60)); // target of compact bits 0x2100ffff = difficulty 1

// ── formatting ───────────────────────────────────────────────────────────────
export const int = (n) => numOr(n, (x) => x.toLocaleString("en-US"));
export function gnb(sat, { dp = 8, unit = true } = {}) {
  let v;
  if (typeof sat === "string" && /^-?\d{1,30}$/.test(sat)) v = BigInt(sat);
  else if (typeof sat === "number" && Number.isSafeInteger(sat)) v = BigInt(sat);
  else if (typeof sat === "bigint") v = sat;
  else return html`—`;
  const neg = v < 0n; if (neg) v = -v;
  const whole = (v / SAT).toLocaleString("en-US");
  const frac = (v % SAT).toString().padStart(8, "0").slice(0, dp).replace(/0+$/, "");
  return html`${neg ? "−" : ""}${whole}${frac ? "." + frac : ""}${unit ? raw(" <small>OBB</small>") : ""}`;
}
export function compact(sat) {
  const v = sats(sat) ?? 0n;
  const g = Number(v / 1000000n) / 100;
  if (g >= 1e6) return (g / 1e6).toFixed(2) + "M";
  if (g >= 1e3) return (g / 1e3).toFixed(1) + "k";
  return g.toFixed(2);
}
export const short = (h, n = 10) => {
  const s = String(h ?? "");
  return s.length > 2 * n ? `${s.slice(0, n)}…${s.slice(-6)}` : s;
};
export function ago(ts) {
  const t = num(ts);
  if (!Number.isFinite(t)) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - t));
  if (s < 60) return `${s}s ago`; if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const utc = (ts) => {
  const t = num(ts);
  if (!Number.isFinite(t)) return "—";
  const d = new Date(t * 1000);
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().replace("T", " ").replace(".000Z", " UTC");
};
export function hashrate(v) {
  let h = num(v); if (!Number.isFinite(h)) return "—";
  const u = ["H/s", "kH/s", "MH/s", "GH/s"]; let i = 0;
  while (h >= 1000 && i < 3) { h /= 1000; i++; }
  return `${h.toFixed(h < 10 ? 2 : 1)} ${u[i]}`;
}
export const diff = (v) => numOr(v, (d) => (d >= 1e6 ? (d / 1e6).toFixed(2) + "M" : d >= 1e3 ? (d / 1e3).toFixed(2) + "k" : d.toFixed(2)));

export const link = {
  block: (h, t) => html`<a class="mono" href="#/block/${hex64(h)}">${t ?? short(hex64(h))}</a>`,
  tx: (h, t) => html`<a class="mono" href="#/tx/${hex64(h)}">${t ?? short(hex64(h))}</a>`,
  addr: (a, t) => {
    const ok = address(a);
    return ok ? html`<a class="mono" href="#/address/${ok}">${t ? address(t) || t : short(ok, 9)}</a>` : html`<span class="muted">unknown</span>`;
  },
};
export const copyBtn = (v) => html`<button class="copy" data-copy="${v}" aria-label="Copy">copy</button>`;
const BADGES = {
  chain: raw(`<span class="badge"><i class="dot chain"></i>Selected chain</span>`),
  blue: raw(`<span class="badge"><i class="dot blue"></i>Blue · merged</span>`),
  red: raw(`<span class="badge"><i class="dot red"></i>Red · merged, no reward priority</span>`),
  pending: raw(`<span class="badge"><i class="dot pending"></i>Not yet merged</span>`),
};
export const colourBadge = (c) => (Object.hasOwn(BADGES, c) ? BADGES[c] : html`<span class="badge">${c}</span>`);
const COLOURS = new Set(["chain", "blue", "red", "pending"]);
const colourOf = (c) => (COLOURS.has(c) ? c : "pending");
export const loading = (label = "Loading") => html`<div class="empty"><span class="skel"></span>&nbsp; ${label}…</div>`;
export const fail = (e) => html`<div class="err">${e?.message || e}</div>`;
const arr = (v) => (Array.isArray(v) ? v : []);
const pctWidth = (v) => numOr(v, (n) => Math.min(100, Math.max(0, n)).toFixed(4), "0");

// ── charts (single series, brand mark colour, hover tooltips) ────────────────
export function lineChart(points, { yLabel, fmt, height = 180 }) {
  if (points.length < 2) return html`<div class="empty">Not enough data yet.</div>`;
  const W = 640, H = height, P = { l: 48, r: 10, t: 10, b: 22 };
  const xs = points.map((p) => p.x), ys = points.map((p) => p.y);
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = 0, y1 = Math.max(...ys) * 1.1 || 1;
  const X = (x) => P.l + ((x - x0) / (x1 - x0 || 1)) * (W - P.l - P.r), Y = (y) => H - P.b - ((y - y0) / (y1 - y0)) * (H - P.t - P.b);
  const ticks = [0, .25, .5, .75, 1].map((f) => y0 + f * (y1 - y0));
  const d = points.map((p, i) => `${i ? "L" : "M"}${X(p.x).toFixed(1)},${Y(p.y).toFixed(1)}`).join("");
  const area = `${d}L${X(x1).toFixed(1)},${Y(0)}L${X(x0).toFixed(1)},${Y(0)}Z`;
  const id = "c" + Math.random().toString(36).slice(2, 8);
  // Labels are `html` markup built here; the JSON is escaped into the attribute.
  const data = JSON.stringify(points.map((p) => [X(p.x), Y(p.y), String(p.label)]));
  return html`<div class="chart" data-chart="${id}" data-points="${data}">
  <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${yLabel}">
   <defs><linearGradient id="${id}g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--mark)" stop-opacity=".28"/><stop offset="1" stop-color="var(--mark)" stop-opacity="0"/></linearGradient></defs>
   <g class="grid">${ticks.map((t) => html`<line x1="${P.l}" x2="${W - P.r}" y1="${Y(t)}" y2="${Y(t)}"/>`)}</g>
   <g class="axis">${ticks.map((t) => html`<text x="${P.l - 8}" y="${Y(t) + 3}" text-anchor="end">${fmt(t)}</text>`)}</g>
   <path d="${area}" fill="url(#${id}g)"/>
   <path d="${d}" fill="none" stroke="var(--mark)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
   <line class="xh" x1="0" x2="0" y1="${P.t}" y2="${H - P.b}" stroke="var(--line-2)" stroke-width="1" opacity="0"/>
   <circle class="xd" r="4.5" fill="var(--mark)" stroke="var(--void)" stroke-width="2" opacity="0"/>
   <rect x="${P.l}" y="0" width="${W - P.l - P.r}" height="${H}" fill="transparent" class="hit"/>
  </svg><div class="tip"></div></div>`;
}
export function barChart(bins, { fmt, height = 180 }) {
  const W = 640, H = height, P = { l: 40, r: 6, t: 10, b: 26 };
  const max = Math.max(1, ...bins.map((b) => b.y));
  const bw = (W - P.l - P.r) / bins.length;
  const Y = (y) => H - P.b - (y / max) * (H - P.t - P.b);
  const ticks = [0, .5, 1].map((f) => Math.round(f * max));
  return html`<div class="chart" data-bars>
  <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Histogram">
   <g class="grid">${ticks.map((t) => html`<line x1="${P.l}" x2="${W - P.r}" y1="${Y(t)}" y2="${Y(t)}"/>`)}</g>
   <g class="axis">${ticks.map((t) => html`<text x="${P.l - 8}" y="${Y(t) + 3}" text-anchor="end">${t}</text>`)}
   ${bins.map((b, i) => html`<text x="${P.l + i * bw + bw / 2}" y="${H - 8}" text-anchor="middle">${b.x}</text>`)}</g>
   ${bins.map((b, i) => { const x = P.l + i * bw + 1, h = Math.max(0, H - P.b - Y(b.y)), y = Y(b.y);
      return html`<g class="bar-g" data-tip="${String(fmt(b))}"><rect x="${x}" y="${P.t}" width="${bw - 2}" height="${H - P.t - P.b}" fill="transparent"/>${b.y ? html`<path d="M${x},${y + h}V${y + Math.min(4, h)}Q${x},${y} ${x + Math.min(4, (bw - 2) / 2)},${y}H${x + bw - 2 - Math.min(4, (bw - 2) / 2)}Q${x + bw - 2},${y} ${x + bw - 2},${y + Math.min(4, h)}V${y + h}Z" fill="var(--mark)"/>` : ""}</g>`; })}
  </svg><div class="tip"></div></div>`;
}

// ── DAG drawing ──────────────────────────────────────────────────────────────
export function dagSvg(nodesIn, { height = 230, compactMode = false } = {}) {
  const nodes = arr(nodesIn).filter((n) => n && hex64(n.hash) && Number.isFinite(num(n.blue_score)));
  if (!nodes.length) return html`<div class="empty">No blocks yet.</div>`;
  const byScore = new Map();
  for (const n of nodes) { const s = num(n.blue_score); if (!byScore.has(s)) byScore.set(s, []); byScore.get(s).push(n); }
  const scores = [...byScore.keys()].sort((a, b) => a - b);
  const colW = compactMode ? 34 : 46, H = height, padX = 24;
  const W = Math.max(padX * 2 + (scores.length - 1) * colW, 320);
  const pos = new Map();
  scores.forEach((s, i) => {
    const col = byScore.get(s).sort((a, b) => (a.colour === "chain" ? -1 : b.colour === "chain" ? 1 : a.hash < b.hash ? -1 : 1));
    col.forEach((n, j) => {
      const lane = j === 0 ? 0 : (j % 2 ? 1 : -1) * Math.ceil(j / 2);
      pos.set(n.hash, { x: padX + i * colW, y: H / 2 + lane * 44, n });
    });
  });
  const edges = [], dots = [];
  for (const [, p] of pos) for (const par of arr(p.n.parents)) {
    const q = pos.get(par); if (!q) continue;
    const sp = par === p.n.selected_parent && p.n.colour === "chain";
    const mx = (p.x + q.x) / 2;
    edges.push(html`<path class="edge${sp ? " sp" : ""}" d="M${q.x},${q.y}C${mx},${q.y} ${mx},${p.y} ${p.x},${p.y}"/>`);
  }
  for (const [h, p] of pos) {
    const c = colourOf(p.n.colour), r = c === "chain" ? 9 : 7;
    const fill = c === "chain" ? "var(--dag-chain)" : c === "blue" ? "var(--dag-blue)" : "var(--void)";
    const stroke = c === "red" ? raw(`stroke="var(--dag-red)" stroke-width="2.5" stroke-dasharray="3 2.5"`) : c === "pending" ? raw(`stroke="var(--mute)" stroke-width="2"`) : raw(`stroke="var(--void)" stroke-width="2"`);
    dots.push(html`<a href="#/block/${h}"><title>${`${c} · height ${int(p.n.height)} · blue score ${int(p.n.blue_score)} · ${short(h)}`}</title><circle cx="${p.x}" cy="${p.y}" r="${r}" fill="${fill}" ${stroke}/></a>`);
  }
  return html`<div class="dag"><svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Recent block DAG">${edges}${dots}</svg></div>
  <div class="legend" style="margin-top:12px"><span><i class="dot chain"></i>Selected chain</span><span><i class="dot blue"></i>Blue (merged)</span><span><i class="dot red"></i>Red (merged, outside k-cluster)</span><span><i class="dot pending"></i>Tip, not yet merged</span><span>Left → right: blue score</span></div>`;
}

// ── tables and cards ─────────────────────────────────────────────────────────
export function blocksTable(blocksIn, freshSet = new Set()) {
  const blocks = arr(blocksIn);
  if (!blocks.length) return html`<div class="empty">No blocks.</div>`;
  return html`<div class="tablewrap"><table><thead><tr><th class="num">Height</th><th>Block</th><th>Age</th><th>Miner</th><th class="num">Reward</th><th class="num hide-sm">Txs</th><th class="num hide-sm">Merged</th><th class="num hide-sm">Difficulty</th></tr></thead><tbody>
  ${blocks.map((b) => html`<tr class="${freshSet.has(b.hash) ? "fresh" : ""}"><td class="num mono">${int(b.height)}</td><td>${link.block(b.hash)}</td><td class="muted">${ago(b.timestamp)}</td><td>${link.addr(b.miner)}</td><td class="num amount">${b.reward ? gnb(b.reward, { dp: 4 }) : "—"}</td><td class="num hide-sm">${int(b.tx_count)}</td><td class="num hide-sm">${int(b.merged)}${num(b.reds) > 0 ? html` <span class="muted">(${int(b.reds)} red)</span>` : ""}</td><td class="num hide-sm mono">${b.difficulty ? diff(b.difficulty) : "—"}</td></tr>`)}
  </tbody></table></div>`;
}

export function txCard(t, standalone = false, offChain = false) {
  const ins = t.coinbase
    ? html`<li><span class="meta">Coinbase</span><span class="addr">${arr(t.inputs)[0]?.coinbase || ""}</span></li>`
    : arr(t.inputs).map((i) => html`<li><span class="amt">${i.value ? gnb(i.value) : html`<span class="muted">value from carryover</span>`}</span><span class="addr">${link.addr(i.address, i.address)}</span><span class="meta">${link.tx(i.prev_txid, short(hex64(i.prev_txid), 8))}:${int(i.prev_index)}</span></li>`);
  const outs = arr(t.outputs).map((o) => html`<li><span class="amt">${gnb(o.value)}</span><span class="addr">${link.addr(o.address, o.address)}</span><span class="meta">#${int(o.index)} · ${offChain ? "not applied" : o.spent ? "spent" : "unspent"}</span></li>`);
  return html`<div style="border-top:1px solid var(--line);padding-top:16px;margin-top:16px">
   ${standalone ? "" : html`<div class="cardhead" style="margin-bottom:10px"><div>${link.tx(t.txid, short(hex64(t.txid), 14))} ${t.coinbase ? raw(`<span class="badge" style="margin-left:6px">coinbase</span>`) : ""}</div><span class="note">${int(t.size)} bytes${t.fee ? html` · fee ${gnb(t.fee)}` : ""}</span></div>`}
   <div class="io"><ul aria-label="Inputs">${ins}</ul><div class="arrow">→</div><ul aria-label="Outputs">${outs}</ul></div></div>`;
}

// ── pages ────────────────────────────────────────────────────────────────────
export const homeHead = () => html`<div class="pagehead"><span class="eyebrow">ObenBlock mainnet</span><h1>Network overview</h1><p class="sub">A BlockDAG mined with SHA-256d and finalized by PoWit. Live data, refreshed every 10 seconds.</p></div><div id="h-stats">${loading("Reading the chain")}</div><div id="h-rest"></div>`;

export function homeStats({ dag, supply, stats, pct, chain, mem }) {
  const height = num(supply.current_height);
  const issued = sats(supply.issued_sat) ?? 0n, unlocked = Number.isSafeInteger(height) ? unlockedSat(height) : 0n;
  const locked = 2n * LOCK_EACH - unlocked, total = CARRY + issued + unlocked;
  const nextHalving = num(supply.next_halving_height) - num(supply.current_height);
  const stat = (k, v, d, hot = false) => html`<div class="stat"><span class="k">${k}</span><span class="v ${hot ? "hot" : ""}">${v}</span>${d ? html`<span class="d">${d}</span>` : ""}</div>`;
  const pctCarry = Number((CARRY * 10000n) / CAP) / 100, pctMined = Number((issued * 1000000n) / CAP) / 10000;
  const first = arr(chain.blocks)[0];
  return html`<div class="stats">
   ${stat("Chain height", int(dag.tip_height), `blue score ${int(dag.tip_blue_score)} · ${int(dag.block_count)} blocks in DAG`, true)}
   ${stat("Block time", `${numOr(pct.p50_secs)}s`, `median of last ${numOr(pct.window)} · mean ${numOr(pct.avg_secs, (n) => n.toFixed(1))}s · target ${numOr(pct.target_secs)}s`)}
   ${stat("Hashrate", hashrate(stats.hashrate_hs), "SHA-256d hashes per second")}
   ${stat("Difficulty", diff(first?.difficulty || 0), `ASERT · bits ${first?.bits || ""}`)}
   ${stat("Circulating", compact(total.toString()), html`of 12.5M OBB cap · ${pctCarry.toFixed(2)}% carryover + ${pctMined.toFixed(4)}% mined · ${compact(locked.toString())} team/founder locked<div class="meter" aria-hidden="true"><i style="width:${pctWidth(pctCarry)}%;background:var(--mark)"></i><i style="width:${pctWidth(Math.max(pctMined, 0.3))}%;background:var(--fluor-hi)"></i></div>`)}
   ${stat("Block reward", numOr(supply.subsidy_per_block_sat, (n) => (n / 1e8).toFixed(4)), `OBB · next halving in ${int(nextHalving)} blocks`)}
   ${stat("Mempool", int(mem.size), `min fee ${numOr(supply.min_tx_fee_sat, (n) => (n / 1e8).toFixed(4))} OBB`)}
   ${stat("Tips", int(dag.tip_count), `GhostDAG k = ${numOr(dag.k)}`)}
  </div>`;
}

export function homeRest({ dagWindow, chain, fresh, hist }) {
  const pts = arr(hist.points).filter((p) => Number.isFinite(num(p.timestamp)) && isHex(p.target_hex) && p.target_hex.length > 0).slice().reverse();
  const diffPts = pts.map((p) => {
    const target = BigInt("0x" + p.target_hex.replace(/^0x/i, ""));
    return { x: num(p.timestamp), y: target > 0n ? Number((POW_LIMIT * 1000n) / target) / 1000 : 0, label: html`<b>height ${int(p.height)}</b> · ${p.bits_hex} · ${utc(p.timestamp)}` };
  });
  const gaps = []; for (let i = 1; i < pts.length; i++) gaps.push(Math.max(0, num(pts[i].timestamp) - num(pts[i - 1].timestamp)));
  const edges = [0, 10, 20, 30, 40, 50, 60, 90, 120, 180, 300];
  const bins = edges.map((e, i) => ({ x: i === edges.length - 1 ? `${e}+` : `${e}–${edges[i + 1]}`, lo: e, hi: edges[i + 1] ?? Infinity, y: 0 }));
  for (const g of gaps) bins.find((b) => g >= b.lo && g < b.hi).y++;
  const nodes = arr(dagWindow.nodes);
  return html`
   <section class="block card"><div class="cardhead"><h2>Block DAG</h2><span class="live"><i></i>live · last ${nodes.length} blocks</span></div>${dagSvg(nodes)}</section>
   <section class="block card"><div class="cardhead"><h2>Latest chain blocks</h2><a class="note" href="#/blocks">All blocks →</a></div>${blocksTable(chain.blocks, fresh)}</section>
   <div class="grid2 block" style="margin-top:22px">
    <section class="card"><div class="cardhead"><h2>Difficulty</h2><span class="note">expected evaluations per block, last ${pts.length} blocks</span></div>${lineChart(diffPts, { yLabel: "Difficulty", fmt: (v) => (v >= 1000 ? (v / 1000).toFixed(1) + "k" : Math.round(v).toString()) })}</section>
    <section class="card"><div class="cardhead"><h2>Time between blocks</h2><span class="note">seconds, last ${gaps.length} intervals · target ${TARGET}s</span></div>${barChart(bins, { fmt: (b) => html`<b>${b.y} blocks</b> · ${b.lo}${b.hi === Infinity ? "+" : "–" + b.hi} s` })}</section>
   </div>`;
}

export const blocksHead = () => html`<div class="pagehead"><span class="eyebrow">Selected chain</span><h1>Blocks</h1><p class="sub">Chain blocks, newest first. Blocks merged off the chain are listed in each chain block's mergeset.</p></div><div class="card" id="b-list">${loading()}</div>`;

export function blocksPage(r, page, per) {
  const pages = Math.max(1, Math.ceil(numOr(r.chain_length, (n) => n, 0) / per));
  const off = raw(`aria-disabled="true" style="opacity:.4;pointer-events:none"`);
  return html`${blocksTable(r.blocks)}<div class="pager"><span>page ${page + 1} of ${pages}</span>
   <a class="btn ghost" ${page ? html`href="#/blocks/${page - 1}"` : off}>← Newer</a>
   <a class="btn ghost" ${page + 1 < pages ? html`href="#/blocks/${page + 1}"` : off}>Older →</a></div>`;
}

export const dagHead = () => html`<div class="pagehead"><span class="eyebrow">GhostDAG · k = 10</span><h1>The block DAG</h1><p class="sub">Every block points to all tips it knew about. GhostDAG picks a selected parent chain and colours each merged block blue (inside the k-cluster) or red. Click any block.</p></div><div class="card" id="d-dag">${loading()}</div>`;

export function blockPage(b) {
  const chip = (h, cls) => html`<a class="chip" href="#/block/${hex64(h)}"><i class="dot ${cls}"></i>${short(hex64(h), 8)}</a>`;
  const chips = (list, cls) => arr(list).length ? html`<div class="chips">${arr(list).map((h) => chip(h, cls))}</div>` : html`<span class="muted">none</span>`;
  const txs = arr(b.transactions);
  const cb = txs[0];
  const offChain = b.colour !== "chain";
  return html`<div class="pagehead"><span class="eyebrow">Block</span><h1>Block ${int(b.height)}</h1><div class="hash">${hex64(b.hash)}${copyBtn(hex64(b.hash))}</div><div>${colourBadge(b.colour)}</div></div>
  <div class="grid2">
   <section class="card"><div class="cardhead"><h2>Header</h2></div><div class="kv">
    <div>Timestamp</div><div>${utc(b.timestamp)} <span class="muted">(${ago(b.timestamp)})</span></div>
    <div>Height · blue score</div><div class="mono">${int(b.height)} · ${int(b.blue_score)}</div>
    <div>Confirmations</div><div class="mono">${int(b.confirmations)} <span class="muted">blue score</span></div>
    <div>Difficulty</div><div class="mono">${b.difficulty ? diff(b.difficulty) : "—"} <span class="muted">bits ${b.bits || ""}</span></div>
    <div>Nonce</div><div class="mono">${b.nonce ?? "—"}</div>
    <div>Merkle root</div><div class="hash">${b.merkle_root || "—"}</div>
    <div>Size</div><div class="mono">${b.size ? html`${int(b.size)} bytes` : "—"}</div>
    <div>Miner</div><div class="hash">${cb ? link.addr(arr(cb.outputs)[0]?.address, arr(cb.outputs)[0]?.address) : "—"}</div>
    <div>Reward</div><div class="amount">${cb ? gnb(cb.total_out) : "—"}${cb && offChain ? raw(`<div class="muted" style="font-family:var(--f-text);font-size:.85rem">Not credited: only selected-chain blocks apply their transactions to the ledger.</div>`) : ""}</div>
   </div></section>
   <section class="card"><div class="cardhead"><h2>Place in the DAG</h2></div><div class="kv">
    <div>Selected parent</div><div>${hex64(b.selected_parent) ? chip(b.selected_parent, "chain") : html`<span class="muted">genesis</span>`}</div>
    <div>Parents (${arr(b.parents).length})</div><div>${chips(b.parents, "pending")}</div>
    <div>Merged blue (${arr(b.mergeset_blues).length})</div><div>${chips(b.mergeset_blues, "blue")}</div>
    <div>Merged red (${arr(b.mergeset_reds).length})</div><div>${chips(b.mergeset_reds, "red")}</div>
    ${hex64(b.merged_by) ? html`<div>Merged by</div><div>${chip(b.merged_by, "chain")}</div>` : ""}
    ${hex64(b.next_chain_block) ? html`<div>Next chain block</div><div>${chip(b.next_chain_block, "chain")}</div>` : ""}
    <div>Blue work</div><div class="mono">${int(b.blue_work)}</div>
   </div></section>
  </div>
  <section class="block card"><div class="cardhead"><h2>Transactions (${txs.length})</h2>${offChain ? raw(`<span class="note">off the selected chain · not applied</span>`) : ""}</div>${txs.length ? txs.map((t) => txCard(t, false, offChain)) : raw(`<div class="empty">Block body not stored on this node.</div>`)}</section>`;
}

export function txPage(r) {
  const t = r.transaction || {};
  const mempool = r.status === "mempool";
  return html`<div class="pagehead"><span class="eyebrow">Transaction</span><h1>${t.coinbase ? "Coinbase transaction" : "Transaction"}</h1><div class="hash">${hex64(t.txid)}${copyBtn(hex64(t.txid))}</div><div>${mempool ? raw(`<span class="badge"><i class="dot pending"></i>In mempool</span>`) : colourBadge(r.block_colour)}</div></div>
  <section class="card"><div class="kv">
   <div>Status</div><div>${mempool ? "Waiting in the mempool" : html`Confirmed in ${link.block(r.block_hash)} at height ${int(r.block_height)}`}</div>
   ${r.timestamp ? html`<div>Time</div><div>${utc(r.timestamp)} <span class="muted">(${ago(r.timestamp)})</span></div>` : ""}
   <div>Total out</div><div class="amount">${gnb(t.total_out)}</div>
   <div>Fee</div><div class="amount">${t.fee ? gnb(t.fee) : t.coinbase ? "—" : raw(`<span class="muted">unknown (spends carryover outputs)</span>`)}</div>
   <div>Size</div><div class="mono">${int(t.size)} bytes</div>
  </div>${txCard(t, true, !mempool && r.block_colour !== "chain")}</section>`;
}

export function addressPage(addrIn, h, carry, page, per) {
  const addr = address(addrIn);
  const pages = Math.max(1, Math.ceil(numOr(h.total, (n) => n, 0) / per));
  const balance = sats(h.balance) ?? 0n;
  const items = arr(h.items);
  const off = raw(`style="opacity:.4;pointer-events:none"`);
  const inCarry = carry && carry.in_carryover === true;
  // B1-T11: "Older" follows the page's cursor; "Newer" uses the offset form,
  // which the node serves up to max_offset (deeper: back to the newest page).
  const cursor = typeof h.next_cursor === "string" && /^[0-9a-f]{32}$/.test(h.next_cursor) ? h.next_cursor : null;
  const maxOffset = numOr(h.max_offset, (n) => n, 10000);
  const newer = page === 0 ? off : (page - 1) * per <= maxOffset ? html`href="#/address/${addr}/${page - 1}"` : html`href="#/address/${addr}"`;
  return html`<div class="pagehead"><span class="eyebrow">Address</span><h1 class="amount" style="font-family:var(--f-display)">${gnb(h.balance)}</h1><div class="hash">${addr}${copyBtn(addr)}</div></div>
  <div class="grid2">
   <section class="card"><div class="kv">
    <div>Balance</div><div class="amount">${gnb(h.balance)}</div>
    <div>Unspent outputs</div><div class="mono">${int(h.utxo_count)}</div>
    <div>Share of 12.5M cap</div><div class="mono">${(Number((balance * 1000000n) / CAP) / 10000).toFixed(4)}%</div>
    <div>Transactions</div><div class="mono">${int(h.total)} <span class="muted">indexed movements</span></div>
   </div></section>
   <section class="card"><div class="cardhead"><h2>Bloch carryover</h2></div>${inCarry
      ? html`<div class="kv"><div>Received at genesis</div><div class="amount">${gnb(carry.amount)}</div><div>From Bloch G3</div><div class="mono">${int(((sats(carry.bloch_amount) ?? 0n) / SAT).toString())} BLCH · ${int(carry.utxos)} outputs</div></div><p class="muted" style="margin-top:12px;font-size:.9rem">Same owner hash as the Bloch Genesis-3 address <span class="mono">bloch1q${addr.slice(5)}</span>, converted at 1,000,000 GNB for 3,810,744,000 BLCH.</p>`
      : raw(`<p class="muted">This address held nothing in the Bloch Genesis-3 snapshot.</p>`)}</section>
  </div>
  <section class="block card"><div class="cardhead"><h2>History</h2><span class="note">newest first</span></div>
  ${items.length ? html`<div class="tablewrap"><table><thead><tr><th class="num">Height</th><th>Transaction</th><th>Direction</th><th class="num">Amount</th></tr></thead><tbody>
   ${items.map((i) => { const incoming = i.direction === "in"; return html`<tr><td class="num mono">${int(i.height)}</td><td>${link.tx(i.txid)}</td><td>${incoming ? "received" : "sent"}</td><td class="num amount ${incoming ? "pos" : "neg"}">${incoming ? "+" : "−"}${gnb(i.amount)}</td></tr>`; })}
  </tbody></table></div><div class="pager"><span>page ${page + 1} of ${pages}</span>
   <a class="btn ghost" ${newer}>← Newer</a>
   <a class="btn ghost" ${cursor ? html`href="#/address/${addr}/${page + 1}/${cursor}"` : page + 1 < pages ? html`href="#/address/${addr}/${page + 1}"` : off}>Older →</a></div>`
   : html`<div class="empty">${inCarry ? "No on-chain movements yet; the balance comes from the genesis carryover." : "No movements yet."}</div>`}</section>`;
}

export const holdersHead = () => html`<div class="pagehead"><span class="eyebrow">Distribution</span><h1>Holders</h1><p class="sub">Balances from the UTXO set: the converted Bloch Genesis-3 carryover plus everything mined since genesis.</p></div><div id="ho">${loading()}</div>`;

export function holdersPage(rich, dist) {
  const tiers = arr(dist.tiers);
  const max = Math.max(...tiers.map((t) => numOr(t.pct_of_supply, (n) => n, 0)), 1);
  return html`
  <div class="callout" style="margin-bottom:20px">The carryover is concentrated: in the Bloch Genesis-3 snapshot one address held about 94% of all coins, and that share carries over unchanged.</div>
  <section class="card"><div class="cardhead"><h2>By balance</h2><span class="note">${int(dist.holders)} addresses · ${gnb(dist.total_supply, { dp: 2 })}</span></div>
   <div class="tablewrap"><table><thead><tr><th>Balance</th><th class="num">Addresses</th><th class="num">OBB</th><th style="width:40%">Share of supply</th></tr></thead><tbody>
   ${tiers.map((t) => { const pct = numOr(t.pct_of_supply, (n) => n, 0); return html`<tr><td class="mono">${t.label}</td><td class="num">${int(t.address_count)}</td><td class="num amount">${gnb(t.total_sats, { dp: (sats(t.total_sats) ?? 0n) < SAT ? 8 : 2 })}</td><td><div style="display:flex;align-items:center;gap:10px"><div class="bartrack" style="flex:1"><div class="bar" style="width:${pctWidth((pct / max) * 100)}%"></div></div><span class="mono muted" style="width:7ch;text-align:right">${pct.toFixed(pct < 0.01 ? 4 : 2)}%</span></div></td></tr>`; })}
   </tbody></table></div></section>
  <section class="block card"><div class="cardhead"><h2>Top holders</h2><span class="note">updated every ~2 minutes</span></div>
   <div class="tablewrap"><table><thead><tr><th class="num">#</th><th>Address</th><th class="num">Balance</th><th class="num hide-sm">Outputs</th><th class="num">Share</th></tr></thead><tbody>
   ${arr(rich.items).map((i) => { const share = numOr(i.share, (n) => n, 0); return html`<tr><td class="num mono">${int(i.rank)}</td><td>${link.addr(i.address)}</td><td class="num amount">${gnb(i.balance, { dp: 4 })}</td><td class="num hide-sm">${int(i.utxos)}</td><td class="num mono">${(share * 100).toFixed(share < 0.0001 ? 6 : 3)}%</td></tr>`; })}
   </tbody></table></div></section>`;
}

