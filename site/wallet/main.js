// GnB Wallet: the sidechain-of-Bloch wallet. Keys are decrypted and used only
// inside the WebAssembly core (core.js + gnb_wallet.wasm); this file never sees
// a private key. Chain data comes from the site's read-only /api.
import { watchAddress } from "../assets/safe.js";
import { loadCore, splitByMaturity } from "./core.js";
import { api, broadcast, addressToScript, gnb, short, ago, esc } from "../shared/gnb.js";

const SAT = 100000000n;
const IDLE_LOCK_MS = 10 * 60 * 1000;
const MAX_INPUTS = 50;            // each input carries ~8.5 kB of post-quantum signature
const PRE_POWIT_DEPTH = 1000;     // signers' rule before PoWit finality is active
const CORE_SHA256 = "9f82f116fafca18c875e9199be3579a749932997aeffb433c3e5a69ca37d04d6";

const $ = (s, el = document) => el.querySelector(s);
const content = $("#content");
let core = null;
let net = { network: null, testnet: false, height: null, powit: null, ok: false };
let st = blank();
let idleTimer = null, pollTimer = null;

function blank() {
  return { mode: "locked", address: null, balance: null, utxoCount: null, spendable: [], spendableTotal: 0n, immature: 0n };
}

// ── modules ──────────────────────────────────────────────────────────────────
const ICON = {
  wallet: '<path d="M4 7.5A2.5 2.5 0 0 1 6.5 5H18v3M4 7.5V17a2 2 0 0 0 2 2h13a1 1 0 0 0 1-1v-9a1 1 0 0 0-1-1H6.5A2.5 2.5 0 0 1 4 7.5Z" fill="none" stroke="currentColor" stroke-width="1.7"/><circle cx="16" cy="13.5" r="1.2" fill="currentColor"/>',
  send: '<path d="M5 12h13M13 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  receive: '<path d="M19 12H6M11 6l-6 6 6 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  bridge: '<path d="M3 16c3-6 15-6 18 0M6 12.5V18M12 10.5V18M18 12.5V18M2 18h20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
  activity: '<path d="M3 12h4l3-7 4 14 3-7h4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
  network: '<path d="M12 3 4 7v5c0 4.5 3.4 8 8 9 4.6-1 8-4.5 8-9V7l-8-4Z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
  backup: '<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19h14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
};
const MODULES = [
  { id: "wallet", title: "Wallet", desc: "Balance, address and quick actions", tab: true },
  { id: "send", title: "Send", desc: "Pay any gnb1… address, signed in this tab" },
  { id: "receive", title: "Receive", desc: "Your address and its QR code" },
  { id: "bridge", title: "Bridge to Bloch", desc: "Lock GNB in the vault, receive wGnB on the Bloch L2", tab: true, badge: "L2" },
  { id: "activity", title: "Activity", desc: "Movements of this address on chain", tab: true },
  { id: "network", title: "Finality · PoWit KES", desc: "Proof of Context and Time: who finalizes, and up to where", tab: true, open: true },
  { id: "backup", title: "Backup", desc: "Download the encrypted keystore again", tab: true, keys: true },
];
const svg = (id) => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON[id]}</svg>`;

function paintNav(active) {
  $("#nav").innerHTML = MODULES.map((m, i) => `${i === 3 || i === 5 ? '<div class="sep"></div>' : ""}<a href="#/${m.id}" class="${m.id === active ? "active" : ""}">${svg(m.id)}<span>${esc(m.title)}</span>${m.badge ? `<span class="badge">${m.badge}</span>` : ""}</a>`).join("");
  $("#tabbar").innerHTML = MODULES.filter((m) => m.tab).map((m) => `<a href="#/${m.id}" class="${m.id === active ? "active" : ""}">${svg(m.id)}<span>${esc(m.title.split(" ")[0])}</span></a>`).join("");
}

// ── helpers ──────────────────────────────────────────────────────────────────
const fmt = (sat) => (sat === null || sat === undefined ? "—" : gnb(sat));
function parseGnb(s) {
  s = String(s).trim().replace(/,/g, "");
  if (!/^\d+(\.\d{1,8})?$/.test(s)) throw new Error("Enter an amount like 12.5 (up to 8 decimals).");
  const [w, f = ""] = s.split(".");
  return BigInt(w) * SAT + BigInt(f.padEnd(8, "0"));
}
const num = (n) => Number(n ?? 0).toLocaleString("en-US");
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));
function busy(btn, label) { btn.disabled = true; btn.dataset.label = btn.innerHTML; btn.innerHTML = `<span class="busy"></span>${esc(label)}`; }
function unbusy(btn) { btn.disabled = false; if (btn.dataset.label) btn.innerHTML = btn.dataset.label; }
const errBox = (e) => `<div class="alert bad">${esc(e?.message || e)}</div>`;
function toast(text) {
  const t = document.createElement("div"); t.className = "toast"; t.textContent = text;
  $("#toasts").appendChild(t); setTimeout(() => t.remove(), 5000);
}
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};
async function getCore() {
  if (!core) core = await loadCore("gnb_wallet.wasm", CORE_SHA256);
  return core;
}
const explorer = (path) => `../explorer/#/${path}`;

// ── preferences: theme and privacy (per viewer) ─────────────────────────────
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $("#themeColor").setAttribute("content", t === "light" ? "#f6f2ee" : "#000000");
}
applyTheme(store.get("gnb.wallet.theme", window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark"));
$("#themeBtn").addEventListener("click", () => {
  const t = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(t); store.set("gnb.wallet.theme", t);
});
function applyPrivacy(on) { document.body.classList.toggle("private", on); $("#privacyBtn").setAttribute("aria-pressed", String(on)); }
applyPrivacy(store.get("gnb.wallet.private", false));
$("#privacyBtn").addEventListener("click", () => { const on = !document.body.classList.contains("private"); applyPrivacy(on); store.set("gnb.wallet.private", on); });
$("#navToggle").addEventListener("click", () => {
  const open = !$("#sidebar").classList.contains("open");
  $("#sidebar").classList.toggle("open", open); $("#navToggle").setAttribute("aria-expanded", String(open));
});
$("#nav").addEventListener("click", () => { $("#sidebar").classList.remove("open"); $("#navToggle").setAttribute("aria-expanded", "false"); });

// ── lock ─────────────────────────────────────────────────────────────────────
function armIdleLock() {
  clearTimeout(idleTimer);
  if (st.mode === "keys") idleTimer = setTimeout(() => lock("Locked after 10 minutes without activity."), IDLE_LOCK_MS);
}
["pointerdown", "keydown"].forEach((ev) => document.addEventListener(ev, armIdleLock, { passive: true }));
function lock(message) {
  try { core?.wipe(); } catch {}
  clearTimeout(idleTimer); clearInterval(pollTimer);
  st = blank(); $("#lockBtn").hidden = true;
  if (message) toast(message);
  location.hash = "#/wallet"; route();
}
$("#lockBtn").addEventListener("click", () => lock(st.mode === "keys" ? "Wallet locked. The key was wiped from memory." : null));
window.addEventListener("pagehide", () => { try { core?.wipe(); } catch {} });

// ── network chip ─────────────────────────────────────────────────────────────
async function pollNetwork() {
  try {
    const [info, powit] = await Promise.all([api("getnetworkinfo"), api("getpowitinfo").catch(() => null)]);
    // Older nodes can answer without a finalized checkpoint for a moment; keep the last one seen.
    if (powit?.active && !powit.finalized) { powit.finalized = net.powit?.finalized || { block_height: 0, slot: 0 }; powit.justified = net.powit?.justified || powit.finalized; }
    net = { network: info.network, testnet: info.network !== "mainnet", height: powit?.tip_height ?? info.blocks, powit, ok: true, peers: info.peers, chainId: info.chain_id };
    const fin = powit?.active ? ` · final #${num(powit.finalized.block_height)}` : "";
    $("#chipNode").className = "chip chip-node live";
    $("#chipText").textContent = `${info.network} · #${num(net.height)}${fin}`;
    $("#envBadge").textContent = `${info.chain} ${info.network} · ${info.chain_id} · ${info.peers} peers`;
  } catch {
    net.ok = false;
    $("#chipNode").className = "chip chip-node down";
    $("#chipText").textContent = "node unreachable";
  }
}

// ── balance ──────────────────────────────────────────────────────────────────
async function refresh() {
  if (st.mode === "locked") return;
  try {
    const [bal, u] = await Promise.all([api("getbalance", [st.address]), api("getutxos", [st.address, 500])]);
    st.balance = bal.satoshis ?? "0";
    st.utxoCount = bal.utxo_count ?? 0;
    const rows = u.utxos || [];
    st.immature = rows.filter((r) => r.spendable === false).reduce((s, r) => s + BigInt(r.value), 0n);
    // Largest mature outputs first: one transaction carries at most MAX_INPUTS.
    st.spendable = rows.filter((r) => r.spendable !== false).sort((a, b) => (BigInt(b.value) > BigInt(a.value) ? 1 : -1)).slice(0, MAX_INPUTS);
    st.spendableTotal = st.spendable.reduce((s, r) => s + BigInt(r.value), 0n);
    paintHeroNumbers();
  } catch (e) { const el = $("#hero-err"); if (el) el.innerHTML = errBox(e); }
}

function enter(mode, address, notice) {
  st = { ...blank(), mode, address };
  $("#lockBtn").hidden = false;
  $("#lockBtn").title = mode === "keys" ? "Lock wallet" : "Stop watching";
  armIdleLock();
  if (notice) toast(notice);
  route();
  refresh();
  clearInterval(pollTimer); pollTimer = setInterval(() => { refresh(); pollNetwork(); }, 20000);
}

// ── router ───────────────────────────────────────────────────────────────────
function route() {
  const id = (location.hash.match(/^#\/([a-z]+)/) || [])[1] || "wallet";
  const m = MODULES.find((x) => x.id === id) || MODULES[0];
  paintNav(m.id);
  $("#moduleTitle").textContent = st.mode === "locked" && !m.open ? "GnB Wallet" : m.title;
  $("#moduleDesc").textContent = st.mode === "locked" && !m.open ? "Post-quantum wallet of the GnB sidechain" : m.desc;
  if (st.mode === "locked" && !m.open) return renderGate();
  if (m.keys && st.mode !== "keys") return (content.innerHTML = `<div class="alert info">This needs an unlocked keystore. You are watching an address.</div>`);
  ({ wallet: viewWallet, send: viewSend, receive: viewReceive, bridge: viewBridge, activity: viewActivity, network: viewNetwork, backup: viewBackup }[m.id])();
  content.focus({ preventScroll: true });
}
window.addEventListener("hashchange", route);

// ── gate ─────────────────────────────────────────────────────────────────────
function renderGate() {
  const where = net.ok ? `${esc(net.network)}` : "the network";
  content.innerHTML = `<div class="gate-head"><span class="eyebrow">GnB · sidechain of Bloch</span>
    <h1>Post-quantum keys. Finality you can check.</h1>
    <p>Open a GnB or Bloch keystore, create a new one, or watch an address. The keystore is decrypted in this tab, signing happens here too, and nothing secret is uploaded.</p></div>
  <div class="doors">
   <section class="card door primary"><span class="num">01 · OPEN</span><h2>Open a keystore</h2>
    <p>A <span class="mono">.json</span> keystore from GnB or from Bloch. A <span class="mono">bloch1q…</span> key becomes the same <span class="mono">gnb1q…</span> address.</p>
    <div class="drop" id="drop" tabindex="0" role="button" aria-label="Choose keystore file"><b>Drop the keystore here</b><br>or click to choose a file</div>
    <input type="file" id="file" accept=".json,application/json" hidden>
    <label>Password<input type="password" id="pw" autocomplete="current-password"></label>
    <button class="btn" id="open">Unlock</button><div id="open-msg"></div></section>
   <section class="card door"><span class="num">02 · CREATE</span><h2>Create a wallet</h2>
    <p>A new ML-DSA-65 + Falcon-1024 key for ${where}, generated here. You download its encrypted keystore before using it.</p>
    <label>Password<input type="password" id="npw" autocomplete="new-password"></label>
    <label>Repeat password<input type="password" id="npw2" autocomplete="new-password"></label>
    <p class="note">At least 12 characters, three of upper, lower, digit, symbol. It cannot be recovered.</p>
    <button class="btn ghost" id="create">Create and download</button><div id="create-msg"></div></section>
   <section class="card door"><span class="num">03 · WATCH</span><h2>Watch an address</h2>
    <p>Balance, activity, bridge locks and a receive QR for any address. No keys involved.</p>
    <label>Address<input id="waddr" spellcheck="false" placeholder="gnb1q… / gnb1t… / bloch1q…"></label>
    <button class="btn ghost" id="watch">Watch</button><div id="watch-msg"></div></section>
  </div>
  <div class="trust">
   <div><b>Keys stay in the tab</b><span>Argon2id + AES-256-GCM decryption and signing run in WebAssembly, pinned by hash. The page loads code only from this site.</span></div>
   <div><b>Two signatures per input</b><span>ML-DSA-65 and Falcon-1024 together; both must verify.</span></div>
   <div><b>Locks itself</b><span>The key is wiped on Lock, when the tab closes, and after 10 minutes idle.</span></div>
  </div>`;
  let fileText = null;
  const drop = $("#drop"), file = $("#file");
  const take = async (f) => {
    if (!f) return;
    if (f.size > 4 * 1024 * 1024) { $("#open-msg").innerHTML = errBox("That file is too large to be a keystore."); return; }
    fileText = await f.text(); drop.innerHTML = `<b>${esc(f.name)}</b><br>${(f.size / 1024).toFixed(1)} kB · ready`; $("#pw").focus();
  };
  drop.addEventListener("click", () => file.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); file.click(); } });
  file.addEventListener("change", () => take(file.files[0]));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); take(e.dataTransfer.files[0]); });
  $("#pw").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#open").click(); });

  $("#open").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = $("#open-msg"); msg.innerHTML = "";
    if (!fileText) { msg.innerHTML = errBox("Choose a keystore file first."); return; }
    busy(btn, "Decrypting (a few seconds)…"); await nextFrame();
    try {
      const c = await getCore(); const r = c.open(fileText, $("#pw").value, net.testnet ? "testnet" : "mainnet");
      $("#pw").value = ""; fileText = null;
      const testnetKey = /^gnb1t/.test(r.address);
      enter("keys", r.address, net.ok && testnetKey !== net.testnet ? `This key is for ${testnetKey ? "testnet" : "mainnet"}; the node is ${net.network}.` : null);
    } catch (e) { unbusy(btn); msg.innerHTML = errBox(e); }
  });
  $("#create").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = $("#create-msg"); msg.innerHTML = "";
    const p1 = $("#npw").value, p2 = $("#npw2").value;
    if (p1 !== p2) { msg.innerHTML = errBox("The passwords do not match."); return; }
    busy(btn, "Generating and encrypting…"); await nextFrame();
    try {
      const c = await getCore(); const r = c.create(net.testnet);
      let ks;
      try { ks = c.exportKeystore(p1); } catch (e) { c.wipe(); throw e; }
      download(`gnb-wallet-${r.address.slice(0, 14)}.json`, ks);
      $("#npw").value = $("#npw2").value = "";
      enter("keys", r.address, "New wallet created. Keep the downloaded keystore and its password: they are the only way back in.");
    } catch (e) { unbusy(btn); msg.innerHTML = errBox(e); }
  });
  $("#watch").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = $("#watch-msg"); msg.innerHTML = "";
    busy(btn, "Checking…");
    try { const c = await getCore(); enter("watch", c.normalize($("#waddr").value)); }
    catch (e) { unbusy(btn); msg.innerHTML = errBox(e); }
  });
}

// ── wallet (home) ────────────────────────────────────────────────────────────
function hero() {
  const keys = st.mode === "keys";
  return `<section class="hero">
    <div class="hero-top"><span class="k">Balance</span>
      <div class="row">${keys ? `<span class="tag ok">● unlocked</span>` : `<span class="tag">◌ watching</span>`}<span class="tag ${net.testnet ? "blue" : "hot"}">${esc(net.network || "…")}</span></div></div>
    <div class="bal sens" id="hbal">${st.balance === null ? `<span class="busy"></span>` : esc(fmt(st.balance))}<small>GNB</small></div>
    <div class="subbal"><span>Spendable in one tx: <b class="sens" id="hspend">—</b></span><span>Maturing (coinbase): <b class="sens" id="himm">—</b></span><span>Outputs: <b id="hcount">—</b></span></div>
    <div class="actions">${keys ? `<a class="btn" href="#/send">${svg("send")} Send</a>` : ""}<a class="btn ghost" href="#/receive">${svg("receive")} Receive</a>${keys ? `<a class="btn ghost" href="#/bridge">${svg("bridge")} Bridge to Bloch</a>` : ""}</div>
    <div id="hero-err"></div></section>`;
}
function paintHeroNumbers() {
  if (st.balance === null) return;
  if ($("#hbal")) $("#hbal").innerHTML = `${esc(fmt(st.balance))}<small>GNB</small>`;
  if ($("#hspend")) $("#hspend").textContent = `${fmt(st.spendableTotal)} GNB`;
  if ($("#himm")) $("#himm").textContent = `${fmt(st.immature)} GNB`;
  if ($("#hcount")) $("#hcount").textContent = num(st.utxoCount);
  if ($("#bridge-avail")) $("#bridge-avail").textContent = `${fmt(st.spendableTotal)} GNB`;
}

function viewWallet() {
  const fin = net.powit?.active;
  content.innerHTML = `${hero()}
   <div class="grid g-main">
    <section class="card"><h2>Address <small>${/^gnb1[tq]/.test(st.address) ? "key hash · hybrid post-quantum key" : ""}</small></h2>
      <div class="addr" id="addr">${esc(st.address)}</div>
      <div class="row" style="margin-top:10px"><button class="chip" id="copy">Copy</button><a class="chip" href="${explorer(`address/${esc(st.address)}`)}" target="_blank" rel="noopener">Explorer ↗</a></div>
      <p class="note" style="margin-top:12px">Same key as the Bloch address <span class="mono">bloch1q${esc(st.address.slice(5, 13))}…</span>: one keystore opens both chains.</p></section>
    <section class="card"><h2>Settlement <small>PoWit KES</small></h2>
      ${fin ? `<div class="kv"><div>Finalized</div><div class="mono">#${num(net.powit.finalized.block_height)}</div><div>Tip</div><div class="mono">#${num(net.powit.tip_height)}</div>
        <div>Above finality</div><div class="mono">${num(net.powit.tip_height - net.powit.finalized.block_height)} blocks</div></div>
        <p class="note" style="margin-top:10px">Payments at or below the finalized height cannot be reorganised. <a href="#/network">How it works</a></p>`
        : `<p class="note">PoWit finality is not active on this network yet; a payment is safe after ${num(PRE_POWIT_DEPTH)} confirmations.</p>`}</section>
   </div>`;
  paintHeroNumbers();
  $("#copy").addEventListener("click", (e) => navigator.clipboard?.writeText(st.address).then(() => { e.target.textContent = "Copied"; setTimeout(() => (e.target.textContent = "Copy"), 1200); }));
}

// ── send ─────────────────────────────────────────────────────────────────────
// Match the height used by the node's mempool and template. In a DAG this
// cannot be inferred from the displayed tip height; missing metadata fails
// closed before planning or signing a transaction.
async function nextPaymentHeight() {
  const dag = await api("getdaginfo");
  const value = dag?.next_block_height;
  if ((typeof value !== "number" && typeof value !== "string") || !/^[1-9][0-9]*$/.test(String(value))) {
    throw new Error("The node did not report a valid next block height.");
  }
  const next = Number(value);
  if (!Number.isSafeInteger(next)) throw new Error("The node reported an invalid next block height.");
  return next;
}

// WAL-1: before sighash v3, verify the selected input values against their
// creating transactions. Unavailable/pruned records stay explicitly marked
// unverified; any supplied bytes must pass the core's txid/value checks.
async function paymentPrevTxs(txids) {
  const previous = {};
  await Promise.all(txids.filter(id => /^[0-9a-f]{64}$/i.test(id)).map(async id => {
    try {
      const tx = await api("getrawtransaction", [id]);
      if (typeof tx?.hex === "string") previous[id] = tx.hex;
    } catch {}
  }));
  return previous;
}

function viewSend() {
  content.innerHTML = `${hero()}<section class="card"><h2>Send GNB</h2><div class="form">
   <label>To<input id="to" spellcheck="false" placeholder="${net.testnet ? "gnb1t…" : "gnb1q… (a bloch1q… address is accepted)"}"></label>
   <div class="field-row"><label>Amount (GNB)<input id="amt" inputmode="decimal" placeholder="0.00"></label><button class="btn ghost" id="max">Max</button></div>
   <p class="note">The fee is the consensus minimum for the transaction's real size (≈ 0.00002 GNB per kB, at least 0.0001 GNB). One payment spends up to ${MAX_INPUTS} outputs.</p>
   <div><button class="btn" id="review">Review payment</button></div><div id="out"></div></div></section>`;
  paintHeroNumbers();
  $("#max").addEventListener("click", () => {
    const reserve = 900000n, total = st.spendableTotal;
    $("#amt").value = total > reserve ? gnb(total - reserve).replace(/,/g, "") : "0";
  });
  $("#review").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = $("#out"); out.innerHTML = "";
    try {
      const c = await getCore();
      const to = c.normalize($("#to").value);
      const amount = parseGnb($("#amt").value);
      if (amount <= 0n) throw new Error("Enter an amount above zero.");
      if (!st.spendable.length) throw new Error("No mature outputs to spend yet.");
      busy(btn, "Verifying inputs and signing…"); await nextFrame();
      const next = await nextPaymentHeight();
      const coins = splitByMaturity(st.spendable, next).spendable;
      if (!coins.length) throw new Error("No spendable outputs at the next block; refresh and try again.");
      const plan = c.plan(coins, to, amount.toString(), "0", next);
      const prevtxs = await paymentPrevTxs(plan.prev_txids || []);
      const tx = c.pay(coins, to, amount.toString(), "0", next, prevtxs);
      const unverified = tx.unverified_inputs || 0;
      unbusy(btn);
      out.innerHTML = `<div class="review">
        <div><span>To</span><b>${esc(to)}</b></div><div><span>Amount</span><b>${esc(fmt(tx.amount))} GNB</b></div>
        <div><span>Network fee</span><b>${esc(fmt(tx.fee))} GNB</b></div><div><span>Inputs · size</span><b>${tx.inputs} · ${(tx.size / 1024).toFixed(1)} kB</b></div>
        ${tx.amounts_committed === true
          ? `<div><span>Input values</span><b>committed by the signature (version 3)</b></div>`
          : `<div><span>Inputs verified against their transactions</span><b>${tx.verified_inputs} of ${tx.inputs}</b></div>`}
        <div><span>Change back to you</span><b>${esc(fmt(tx.change))} GNB</b></div></div>
        ${unverified ? `<div class="alert bad" style="margin-top:12px">${unverified} input value(s) come only from the server (genesis carryover or pruned history) and could not be checked against their transaction. If the server lied, the difference would be paid as fee.
          <label class="check"><input type="checkbox" id="accept-unverified"> I accept the unverified input value(s) shown above.</label></div>` : ""}
        <div class="row" style="margin-top:12px"><button class="btn" id="confirm" ${unverified ? "disabled" : ""}>Confirm and send</button><button class="btn ghost" id="cancel">Cancel</button></div>`;
      const confirm = $("#confirm");
      $("#accept-unverified")?.addEventListener("change", e => { confirm.disabled = !e.target.checked; });
      $("#cancel").addEventListener("click", () => (out.innerHTML = ""));
      confirm.addEventListener("click", async (e2) => {
        if (unverified && !$("#accept-unverified")?.checked) return;
        const b2 = e2.currentTarget; busy(b2, "Broadcasting…");
        try {
          await broadcast(tx.raw);
          out.innerHTML = `<div class="alert ok">Sent. Transaction <a class="mono" href="${explorer(`tx/${esc(tx.txid)}`)}" target="_blank" rel="noopener">${esc(short(tx.txid, 16))}</a> is in the mempool.</div>`;
          toast("Payment broadcast."); setTimeout(refresh, 3000);
        } catch (err) { unbusy(b2); out.innerHTML = errBox(err); }
      });
    } catch (e) { unbusy(btn); out.innerHTML = errBox(e); }
  });
}

// ── receive ──────────────────────────────────────────────────────────────────
function viewReceive() {
  let qr = "";
  try { const q = window.qrcode(0, "M"); q.addData(st.address, "Byte"); q.make(); qr = q.createSvgTag({ cellSize: 6, margin: 0, scalable: true }); } catch {}
  content.innerHTML = `<section class="card"><h2>Receive GNB</h2><div class="receive"><div class="qr" aria-label="QR code of the address">${qr}</div>
   <div style="display:grid;gap:12px;min-width:0"><p>Share this address. Anyone can pay it; only this keystore can spend it.</p><div class="addr">${esc(st.address)}</div>
   <div class="row"><button class="chip" id="copy">Copy address</button><a class="chip" href="${explorer(`address/${esc(st.address)}`)}" target="_blank" rel="noopener">Explorer ↗</a></div>
   <p class="note">GNB coming back from the Bloch L2 (a burn of wGnB) is released to the gnb1… address named in the burn.</p></div></div></section>`;
  $("#copy").addEventListener("click", (e) => navigator.clipboard?.writeText(st.address).then(() => { e.target.textContent = "Copied"; setTimeout(() => (e.target.textContent = "Copy address"), 1200); }));
}

// ── bridge ───────────────────────────────────────────────────────────────────
// The vault is published by the bridge operators. It can be pre-selected with
// ?vault=gnb1n… (shared with the explorer through localStorage "gnb.vault").
let bridgeCfg = null;
async function vaultAddress() {
  const q = new URLSearchParams(location.search).get("vault");
  if (q && addressToScript(q)) { try { localStorage.setItem("gnb.vault", q); } catch {} return q; }
  try { const v = localStorage.getItem("gnb.vault"); if (v && addressToScript(v)) return v; } catch {}
  if (bridgeCfg === null) bridgeCfg = await fetch("bridge.json", { cache: "no-store" }).then((r) => (r.ok ? r.json() : {})).catch(() => ({}));
  const v = bridgeCfg[net.testnet ? "testnet" : "mainnet"];
  return v && addressToScript(v) ? v : null;
}
const locksKey = () => `gnb.locks.${st.address}`;

async function viewBridge() {
  const keys = st.mode === "keys";
  const vault = await vaultAddress();
  const vaultOk = vault && /^gnb1[mn]/.test(vault) && (vault[4] === "n") === net.testnet;
  content.innerHTML = `<section class="card"><h2>GnB → Bloch <small>lock here, mint wGnB on the Bloch L2</small></h2>
    <div class="flow">
      <div><b>Lock</b><span>Your GNB goes to the bridge vault. A 546-unit marker output carries the 20-byte Bloch L2 recipient (0x…).</span></div>
      <div><b>Finality</b><span>Signers wait until PoWit KES finalizes the lock's block${net.powit?.active ? "" : ` (before PoWit: ${num(PRE_POWIT_DEPTH)} confirmations)`}. No reorg can undo it after that.</span></div>
      <div><b>Mint</b><span>The bridge signers mint the same amount of wGnB on the Bloch L2 to the 0x address.</span></div>
      <div><b>Come back</b><span>Burn wGnB on the L2; 3 of 5 signers release that amount from the vault to your gnb1… address, once per burn.</span></div>
    </div></section>
   <div class="grid g-main">
    <section class="card"><h2>Lock GNB for the Bloch L2</h2>
     ${!vault ? `<div class="alert info">No bridge vault is published for ${esc(net.network || "this network")} yet. Open this page with <span class="mono">?vault=gnb1${net.testnet ? "n" : "m"}…</span> to use a test vault.</div>`
      : !vaultOk ? `<div class="alert bad">The configured vault <span class="mono">${esc(short(vault, 14))}</span> is not a ${esc(net.network)} policy address.</div>`
      : !keys ? `<div class="alert info">Unlock a keystore to lock GNB. Locks made by this address are listed on the right.</div>`
      : `<div class="form">
        <label>Bloch L2 recipient<input id="l2" spellcheck="false" placeholder="0x… (40 hex digits)"></label>
        <div class="field-row"><label>Amount (GNB)<input id="bamt" inputmode="decimal" placeholder="0.00"></label><button class="btn ghost" id="bmax">Max</button></div>
        <p class="note">Available in one transaction: <b class="sens" id="bridge-avail">—</b>. Fee: consensus minimum for the size.</p>
        <div><button class="btn" id="breview">Review lock</button></div><div id="bout"></div></div>`}
    </section>
    <section class="card"><h2>Vault</h2>
     ${vault ? `<div class="kv"><div>Address</div><div class="mono" style="font-size:.76rem">${esc(vault)}</div>
       <div>Holds</div><div class="mono sens" id="vbal"><span class="busy"></span></div>
       <div>Spend policy</div><div>Release <b>3-of-5</b> signers · recovery <b>2-of-3</b> cold keys after a long timelock</div></div>
       <div class="row" style="margin-top:10px"><a class="chip" href="../explorer/?vault=${esc(vault)}#/vault" target="_blank" rel="noopener">Vault in the explorer ↗</a></div>` : `<p class="empty">—</p>`}
    </section>
   </div>
   <section class="card"><h2>Your locks <small>kept in this browser · status from the chain</small></h2><div id="locks"><p class="empty">Loading…</p></div></section>`;
  paintHeroNumbers();
  if (vault) api("getutxos", [vault, 1]).then((b) => { if ($("#vbal")) $("#vbal").textContent = `${fmt(b.satoshis)} GNB · ${num(b.utxo_count)} outputs`; }).catch((e) => { if ($("#vbal")) $("#vbal").textContent = e.message; });
  paintLocks();
  if (!vaultOk || !keys) return;
  const script = addressToScript(vault);
  $("#bmax").addEventListener("click", () => {
    const reserve = 900000n + 546n, total = st.spendableTotal;
    $("#bamt").value = total > reserve ? gnb(total - reserve).replace(/,/g, "") : "0";
  });
  $("#breview").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = $("#bout"); out.innerHTML = "";
    try {
      const l2 = $("#l2").value.trim();
      if (!/^0x[0-9a-fA-F]{40}$/.test(l2)) throw new Error("The Bloch L2 recipient must be 0x followed by 40 hex digits.");
      if (/^0x0{40}$/i.test(l2)) throw new Error("The zero address cannot receive wGnB.");
      const amount = parseGnb($("#bamt").value);
      if (amount <= 0n) throw new Error("Enter an amount above zero.");
      if (!st.spendable.length) throw new Error("No mature outputs to spend yet.");
      busy(btn, "Building and signing…"); await nextFrame();
      const c = await getCore();
      const tx = c.bridgeLock(st.spendable, script, amount.toString(), l2.toLowerCase());
      unbusy(btn);
      out.innerHTML = `<div class="review">
        <div><span>Vault (output 0)</span><b>${esc(fmt(tx.amount))} GNB → ${esc(short(vault, 14))}</b></div>
        <div><span>L2 recipient (output 1)</span><b>${esc(tx.l2_recipient)}</b></div>
        <div><span>You receive on Bloch</span><b>${esc(fmt(tx.amount))} wGnB</b></div>
        <div><span>Network fee</span><b>${esc(fmt(tx.fee))} GNB · marker 0.00000546</b></div>
        <div><span>Inputs · size</span><b>${tx.inputs} · ${(tx.size / 1024).toFixed(1)} kB</b></div></div>
        <div class="alert info" style="margin-top:10px">A lock is final on GnB. Check the 0x address: wGnB minted to a wrong address cannot be recovered by the signers.</div>
        <div class="row" style="margin-top:12px"><button class="btn" id="bconfirm">Lock and broadcast</button><button class="btn ghost" id="bcancel">Cancel</button></div>`;
      $("#bcancel").addEventListener("click", () => (out.innerHTML = ""));
      $("#bconfirm").addEventListener("click", async (e2) => {
        const b2 = e2.currentTarget; busy(b2, "Broadcasting…");
        try {
          await broadcast(tx.raw);
          const locks = store.get(locksKey(), []);
          locks.unshift({ txid: tx.txid, amount: tx.amount, l2: tx.l2_recipient, vault, at: Math.floor(Date.now() / 1000) });
          store.set(locksKey(), locks.slice(0, 50));
          out.innerHTML = `<div class="alert ok">Locked. Transaction <a class="mono" href="${explorer(`tx/${esc(tx.txid)}`)}" target="_blank" rel="noopener">${esc(short(tx.txid, 16))}</a>; follow it below until finality.</div>`;
          toast("Bridge lock broadcast."); paintLocks(); setTimeout(refresh, 3000);
        } catch (err) { unbusy(b2); out.innerHTML = errBox(err); }
      });
    } catch (e) { unbusy(btn); out.innerHTML = errBox(e); }
  });
}

async function paintLocks() {
  const el = $("#locks"); if (!el) return;
  const locks = store.get(locksKey(), []);
  if (!locks.length) { el.innerHTML = `<p class="empty">No locks from this browser yet.</p>`; return; }
  const pw = net.powit;
  const rows = await Promise.all(locks.map(async (l) => ({ ...l, s: await api("gettxstatus", [l.txid]).catch(() => null) })));
  if (!$("#locks")) return;
  el.innerHTML = rows.map((l) => {
    const h = l.s?.block_height, conf = l.s?.confirmations ?? 0;
    let tag, pct, fin = false, line;
    if (!l.s || (l.s.status === "unknown" && !l.s.in_mempool)) { tag = `<span class="tag">not found</span>`; pct = 0; line = "The node does not know this transaction (dropped, or another network)."; }
    else if (l.s.in_mempool || h == null) { tag = `<span class="tag">mempool</span>`; pct = 2; line = "Waiting for the first block."; }
    else if (pw?.active && h <= pw.finalized.block_height) { tag = `<span class="tag ok">finalized · PoWit KES</span>`; pct = 100; fin = true; line = `Block #${num(h)} is at or below finalized #${num(pw.finalized.block_height)}. The signers can mint wGnB now.`; }
    else if (pw?.active) { const gap = Math.max(1, (pw.tip_height ?? h) - pw.finalized.block_height); pct = Math.min(95, Math.round((conf / (conf + Math.max(0, h - pw.finalized.block_height) + 1)) * 100)); tag = `<span class="tag hot">awaiting finality</span>`; line = `Block #${num(h)} · ${num(conf)} confirmations · finality is at #${num(pw.finalized.block_height)} (${num(gap)} behind the tip).`; }
    else { pct = Math.min(100, Math.round((conf / PRE_POWIT_DEPTH) * 100)); fin = conf >= PRE_POWIT_DEPTH; tag = fin ? `<span class="tag ok">${num(PRE_POWIT_DEPTH)} confirmations</span>` : `<span class="tag hot">${num(conf)} / ${num(PRE_POWIT_DEPTH)}</span>`; line = `Block #${num(h)} · ${num(conf)} confirmations.`; }
    return `<div class="lockrow"><div class="top"><span><b class="sens">${esc(fmt(l.amount))} GNB</b> → <span class="mono">${esc(short(l.l2, 10))}</span></span><span class="row">${tag}<a class="chip" href="${explorer(`tx/${esc(l.txid)}`)}" target="_blank" rel="noopener">${esc(short(l.txid, 10))} ↗</a></span></div>
      <div class="progress"><i class="${fin ? "fin" : ""}" style="width:${pct}%"></i></div><span class="note">${esc(line)} · ${ago(l.at)}</span></div>`;
  }).join("");
}

// ── activity ─────────────────────────────────────────────────────────────────
async function viewActivity() {
  content.innerHTML = `<section class="card"><h2>Activity <small>latest 25</small></h2><div id="act"><p class="empty"><span class="busy"></span>Loading…</p></div></section>`;
  try {
    const h = await api("getaddresshistory", [st.address, 25, 0]);
    const fin = net.powit?.active ? net.powit.finalized.block_height : null;
    $("#act").innerHTML = h.items.length ? `<div class="scroll"><table class="tbl"><thead><tr><th>Height</th><th>Transaction</th><th></th><th class="hide-sm">State</th><th class="num">GNB</th></tr></thead><tbody>
      ${h.items.map((i) => `<tr><td class="mono">${num(i.height)}</td><td><a class="mono" href="${explorer(`tx/${esc(i.txid)}`)}" target="_blank" rel="noopener">${esc(short(i.txid, 12))}</a></td>
        <td class="muted">${i.direction === "in" ? "received" : "sent"}</td>
        <td class="hide-sm">${fin !== null && i.height <= fin ? `<span class="tag ok">final</span>` : `<span class="tag">pending finality</span>`}</td>
        <td class="num sens ${i.direction === "in" ? "in" : ""}">${i.direction === "in" ? "+" : "−"}${esc(fmt(i.amount))}</td></tr>`).join("")}
      </tbody></table></div>${h.total > 25 ? `<p class="note">Latest 25 of ${num(h.total)}. <a href="${explorer(`address/${esc(st.address)}`)}" target="_blank" rel="noopener">Full history in the explorer ↗</a></p>` : ""}`
      : `<p class="empty">No movements yet.</p>`;
  } catch (e) { $("#act").innerHTML = errBox(e); }
}

// ── network: PoWit KES ───────────────────────────────────────────────────────
async function viewNetwork() {
  content.innerHTML = `<p class="empty"><span class="busy"></span>Loading finality…</p>`;
  try {
    await pollNetwork();
    const pw = net.powit;
    if (!pw || !pw.active) {
      content.innerHTML = `<section class="card"><h2>PoWit is not active on this network</h2><p>Activation height: <span class="mono">${pw?.activation_height == null ? "not scheduled" : num(pw.activation_height)}</span>. Until then nodes refuse reorganisations deeper than ${num(PRE_POWIT_DEPTH)} blocks, and the bridge signers wait ${num(PRE_POWIT_DEPTH)} confirmations.</p></section>`;
      return;
    }
    const chain = await api("getselectedchain", [0, 12]).catch(() => ({ blocks: [] }));
    const full = await Promise.all((chain.blocks || []).map((b) => api("getblock", [b.hash, false]).catch(() => null)));
    const atts = [];
    full.forEach((b) => b?.powit?.attestations.forEach((a) => atts.push({ ...a, h: b.height })));
    const last = atts[0];
    const ws = pw.witness_set, total = Number(ws.total_weight) || 1;
    const kesNow = last ? last.kes_epoch : null, span = last ? 2 ** last.kes_depth : 0;
    const kesLine = last ? Array.from({ length: 14 }, (_, i) => kesNow - 9 + i).filter((e) => e >= 0 && e < span)
      .map((e) => `<span class="${e === kesNow ? "now" : e > kesNow ? "fut" : ""}">${e}</span>`).join("") : "";
    content.innerHTML = `<div class="steps">
      <div class="slot fin"><span class="k">Finalized</span><div class="v">#${num(pw.finalized.block_height)}</div><span class="note">slot ${num(pw.finalized.slot)}</span></div>
      <div class="slot just"><span class="k">Justified</span><div class="v">#${num(pw.justified.block_height)}</div><span class="note">slot ${num(pw.justified.slot)}</span></div>
      <div class="slot"><span class="k">Tip</span><div class="v">#${num(pw.tip_height)}</div><span class="note">${num(pw.tip_height - pw.finalized.block_height)} blocks above finality</span></div></div>
     <div class="grid g2">
      <section class="card"><h2>Proof of Context and Time <small>PoWit KES</small></h2>
        <p>Every witness key is a Merkle root over one hybrid ML-DSA-65 + Falcon-1024 key per epoch. A checkpoint is signed with the leaf of <b>its own epoch</b>, and the seeds of past epochs are erased. A key stolen today cannot sign yesterday: the past is closed even to its owner.</p>
        ${last ? `<div class="kes" style="margin-top:12px">${kesLine}</div><p class="note">Latest attestation in block #${num(last.h)} used KES leaf <b>${kesNow}</b> of ${num(span)}. Struck-through leaves are erased.</p>` : `<p class="note">No attestation in the last 12 blocks.</p>`}
      </section>
      <section class="card"><h2>Witness set <small>earned by work, no stake</small></h2>
        ${ws.top.map((w) => `<div class="wbar"><span class="mono">${esc(short(w.key, 8))}</span><span class="track"><span class="fill" style="width:${((Number(w.weight) / total) * 100).toFixed(1)}%"></span></span><span class="mono" style="text-align:right">${((Number(w.weight) / total) * 100).toFixed(1)}%</span></div>`).join("")}
        <p class="note">${num(ws.size)} of ${pw.params.max_witnesses} seats · weight = witness-share work over ${pw.params.window_epochs} epochs · ${num(pw.barred_keys)} keys barred for double votes.</p></section>
     </div>
     <section class="card"><h2>What finality means for this wallet</h2><div class="kv">
      <div>Payments</div><div>A payment at or below the finalized height cannot be reversed by any amount of hashpower.</div>
      <div>Bridge locks</div><div>Signers mint wGnB on the Bloch L2 only for locks in finalized blocks.</div>
      <div>Double votes</div><div>Two conflicting attestations from one key are evidence on chain; the key is barred.</div>
      <div>Explorer</div><div><a href="${explorer("finality")}" target="_blank" rel="noopener">Every attestation with its KES leaf ↗</a></div></div></section>`;
  } catch (e) { content.innerHTML = errBox(e); }
}

// ── backup ───────────────────────────────────────────────────────────────────
function viewBackup() {
  content.innerHTML = `<section class="card"><h2>Back up this wallet</h2><div class="form" style="max-width:520px">
   <p>Download the key again as an encrypted GnB keystore (v2). The password you choose is the only way to open the file.</p>
   <label>Password<input type="password" id="bpw" autocomplete="new-password"></label>
   <label>Repeat password<input type="password" id="bpw2" autocomplete="new-password"></label>
   <div><button class="btn ghost" id="bdl">Download encrypted keystore</button></div><div id="b-out"></div>
   <p class="note">Opens here, with <span class="mono">gnb-cli</span>, and in the Bloch wallet. Never store it together with its password.</p></div></section>`;
  $("#bdl").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = $("#b-out"); out.innerHTML = "";
    if ($("#bpw").value !== $("#bpw2").value) { out.innerHTML = errBox("The passwords do not match."); return; }
    busy(btn, "Encrypting…"); await nextFrame();
    try {
      download(`gnb-wallet-${st.address.slice(0, 14)}.json`, core.exportKeystore($("#bpw").value));
      unbusy(btn); out.innerHTML = `<div class="alert ok">Keystore downloaded.</div>`; $("#bpw").value = $("#bpw2").value = "";
    } catch (e) { unbusy(btn); out.innerHTML = errBox(e); }
  });
}

// ── boot ─────────────────────────────────────────────────────────────────────
// Shareable watch links: #watch/<address>
(async function boot() {
  await pollNetwork();
  const address = watchAddress(location.hash);
  if (address) { try { const c = await getCore(); history.replaceState(null, "", location.pathname + location.search + "#/wallet"); return enter("watch", c.normalize(address)); } catch {} }
  route();
  setInterval(() => { if (st.mode === "locked") pollNetwork(); }, 30000);
})();
