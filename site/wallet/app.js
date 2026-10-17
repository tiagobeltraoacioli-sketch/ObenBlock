// GnB web wallet. Keys are decrypted and used only inside the WebAssembly
// core (core.js / gnb_wallet.wasm); this file never sees a private key.
//
// Audit fixes: all markup is built with the escaping `html` template and API
// values are type-checked (WAL-3); the wasm core is checked against the
// SHA-256 pinned below before it runs (WAL-5); from the hardening activation
// height (read from the node: getdaginfo next_block_height) payments are
// version-3 transactions whose signatures commit to every spent value, below
// it the claimed values of the UTXOs a payment spends are verified against
// their previous transactions inside the core; the review shows the ACTUAL
// fee and any input that could not be verified (WAL-1, WAL-6); new wallets
// are backed by a 24-word recovery phrase (WAL-7). Only coins spendable in the
// next block reach the core: an immature coinbase output is neither counted as
// spendable nor offered to the core (core.js splitByMaturity).
import { loadCore, spendableWindow, splitByMaturity, getutxosFetcher, COINBASE_MATURITY, UTXO_WINDOW, UTXO_WIDE_WINDOW } from "/wallet/core.js";
import { html, raw, isAddress, watchAddress, isHex64, num, sats } from "/assets/safe.js";

// SHA-256 of /wallet/gnb_wallet.wasm. Written by scripts/build-wallet-wasm.sh
// and checked by `node --test site/tests/`; loadCore refuses any other binary.
const WASM_SHA256 = "d3d1d58a39fd3e55cf9a65551e57618e84841c7e2abc8d8341d600050e5bf070";

const SAT = 100000000n;
// UTXO_WINDOW / UTXO_WIDE_WINDOW (core.js): rows asked of getutxos, the same
// constants the explorer API's parameter check is tested against (B2-T3).
const IDLE_LOCK_MS = 10 * 60 * 1000;
const app = document.getElementById("app");
const lockBtn = document.getElementById("lock");
let core = null;
let state = { mode: "locked", address: null, tab: "send", balance: null, utxos: [], immature: [], pending: null };
let idleTimer = null, pollTimer = null;

// ── helpers ──────────────────────────────────────────────────────────────────
const show = (el, markup) => { el.innerHTML = String(markup); };
function fmt(sat, dp = 8) {
  const v = typeof sat === "bigint" ? sat : sats(sat);
  if (v === null || v === undefined) return "—";
  const whole = (v / SAT).toLocaleString("en-US");
  const frac = (v % SAT).toString().padStart(8, "0").slice(0, dp).replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : whole;
}
const count = (v) => { const n = num(v); return Number.isFinite(n) ? n.toLocaleString("en-US") : "—"; };
function parseGnb(s) {
  s = String(s).trim().replace(/,/g, "");
  if (!/^\d+(\.\d{1,8})?$/.test(s)) throw new Error("Enter an amount like 12.5 (up to 8 decimals).");
  const [w, f = ""] = s.split(".");
  return BigInt(w) * SAT + BigInt(f.padEnd(8, "0"));
}
async function api(method, params = []) {
  const r = await fetch(`/api/${method}?p=${encodeURIComponent(JSON.stringify(params))}`, { cache: "no-store" });
  const doc = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  if (doc.error) throw new Error(String(doc.error));
  if (doc.result === null || typeof doc.result !== "object") throw new Error("unexpected response");
  return doc.result;
}
async function broadcast(hex) {
  const r = await fetch("/api/sendrawtransaction", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hex }) });
  const doc = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  if (doc.error) throw new Error(String(doc.error));
  return doc.result;
}
/** Only well-formed UTXO rows reach the core (WAL-3). */
function cleanUtxos(rows) {
  return (Array.isArray(rows) ? rows : []).filter((u) => u && isHex64(u.txid) && Number.isInteger(u.index)
    && u.index >= 0 && sats(u.value) !== null && typeof u.script_pubkey === "string" && /^[0-9a-f]{40}$/.test(u.script_pubkey)
    && (u.coinbase_height === undefined || u.coinbase_height === null || (Number.isSafeInteger(u.coinbase_height) && u.coinbase_height >= 0)));
}
const total = (rows) => rows.reduce((s, u) => s + sats(u.value), 0n);
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));
async function getCore() {
  if (!WASM_SHA256) throw new Error("wallet core hash is not pinned; refusing to load it");
  if (!core) core = await loadCore("/wallet/gnb_wallet.wasm", WASM_SHA256);
  return core;
}
function busy(btn, label) { btn.disabled = true; btn.dataset.label = btn.innerHTML; show(btn, html`<span class="busy"></span>${label}`); }
function unbusy(btn) { btn.disabled = false; if (btn.dataset.label) btn.innerHTML = btn.dataset.label; }
function showError(where, e) { show(where, html`<div class="alert bad">${e?.message || e}</div>`); }

function armIdleLock() {
  clearTimeout(idleTimer);
  if (state.mode === "keys") idleTimer = setTimeout(() => lock("Locked after 10 minutes without activity."), IDLE_LOCK_MS);
}
["pointerdown", "keydown"].forEach((ev) => document.addEventListener(ev, armIdleLock, { passive: true }));

function lock(message) {
  try { core?.wipe(); } catch {}
  clearTimeout(idleTimer); clearInterval(pollTimer);
  state = { mode: "locked", address: null, tab: "send", balance: null, utxos: [], immature: [], pending: null };
  lockBtn.hidden = true;
  renderGate(message);
}
lockBtn.addEventListener("click", () => lock());
window.addEventListener("pagehide", () => { try { core?.wipe(); } catch {} });

// ── the gate (locked) ────────────────────────────────────────────────────────
function renderGate(message) {
  show(app, html`<div class="gate">
  <div class="gate-head"><span class="eyebrow">GnB Wallet</span><h1>Hold GNB with post-quantum keys.</h1>
   <p>Open a GnB or Bloch keystore, create a new one, or watch an address. Your keystore is decrypted in this tab with its password, and signing happens here too. Nothing secret is uploaded.</p></div>
  ${message ? html`<div class="alert ok">${message}</div>` : ""}
  <div class="doors">
   <section class="door primary"><span class="num">01 · OPEN</span><h2>Open a keystore</h2>
    <p>A <span class="mono">.json</span> keystore from GnB or from Bloch (Genesis-3). A Bloch address becomes the same <span class="mono">gnb1q…</span> address.</p>
    <div class="drop" id="drop" tabindex="0" role="button" aria-label="Choose keystore file"><b>Drop the keystore here</b><br>or click to choose a file</div>
    <input type="file" id="file" accept=".json,application/json" hidden>
    <label>Password<input type="password" id="pw" autocomplete="current-password"></label>
    <button class="btn" id="open">Unlock</button><div id="open-msg"></div></section>
   <section class="door"><span class="num">02 · CREATE</span><h2>Create a wallet</h2>
    <p>A new ML-DSA-65 + Falcon-1024 key, generated here from a 24-word recovery phrase that you write down. You also download its encrypted keystore.</p>
    <label>Password<input type="password" id="npw" autocomplete="new-password"></label>
    <label>Repeat password<input type="password" id="npw2" autocomplete="new-password"></label>
    <p class="note">At least 12 characters, three of upper, lower, digit, symbol.</p>
    <button class="btn ghost" id="create">Create</button><div id="create-msg"></div></section>
   <section class="door"><span class="num">03 · RESTORE</span><h2>Restore from words</h2>
    <p>Bring back a wallet created here from its 24-word recovery phrase.</p>
    <label>Recovery phrase<textarea id="rwords" rows="3" spellcheck="false" autocomplete="off"></textarea></label>
    <label>New keystore password<input type="password" id="rpw" autocomplete="new-password"></label>
    <button class="btn ghost" id="restore">Restore and download</button><div id="restore-msg"></div></section>
   <section class="door"><span class="num">04 · WATCH</span><h2>Watch an address</h2>
    <p>Balance, activity and a receive QR for any <span class="mono">gnb1q…</span> or <span class="mono">bloch1q…</span> address. No keys involved.</p>
    <label>Address<input id="waddr" spellcheck="false" placeholder="gnb1q…"></label>
    <button class="btn ghost" id="watch">Watch</button><div id="watch-msg"></div></section>
  </div>
  <div class="trust">
   <div><b>Keys stay in the tab</b><span>Decryption (Argon2id, AES-256-GCM) and signing run in WebAssembly in this page. The page loads only code from gnb-smh.com, checked against pinned hashes.</span></div>
   <div><b>Post-quantum signatures</b><span>Every input is signed with ML-DSA-65 and Falcon-1024 together; both must verify.</span></div>
   <div><b>Locks itself</b><span>The key is wiped from memory on Lock, when the tab closes, and after 10 minutes idle.</span></div>
  </div></div>`);
  let fileText = null;
  const drop = document.getElementById("drop"), file = document.getElementById("file");
  const take = async (f) => { if (!f) return; if (f.size > 4 * 1024 * 1024) return showError(document.getElementById("open-msg"), "That file is too large to be a keystore.");
    fileText = await f.text(); show(drop, html`<b>${f.name}</b><br>${(f.size / 1024).toFixed(1)} kB · ready`); document.getElementById("pw").focus(); };
  drop.addEventListener("click", () => file.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); file.click(); } });
  file.addEventListener("change", () => take(file.files[0]));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); take(e.dataTransfer.files[0]); });

  document.getElementById("open").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("open-msg"); msg.innerHTML = "";
    if (!fileText) return showError(msg, "Choose a keystore file first.");
    busy(btn, "Decrypting (a few seconds)…"); await nextFrame();
    try {
      const c = await getCore(); const r = c.open(fileText, document.getElementById("pw").value);
      document.getElementById("pw").value = ""; fileText = null;
      enter("keys", r.address);
    } catch (e) { unbusy(btn); showError(msg, e); }
  });
  document.getElementById("create").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("create-msg"); msg.innerHTML = "";
    const p1 = document.getElementById("npw").value, p2 = document.getElementById("npw2").value;
    if (p1 !== p2) return showError(msg, "The passwords do not match.");
    busy(btn, "Generating and encrypting…"); await nextFrame();
    try {
      const c = await getCore(); const r = c.create();
      let ks;
      try { ks = c.exportKeystore(p1); } catch (e) { c.wipe(); throw e; }
      document.getElementById("npw").value = document.getElementById("npw2").value = "";
      showPhrase(r, ks);
    } catch (e) { unbusy(btn); showError(msg, e); }
  });
  document.getElementById("restore").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("restore-msg"); msg.innerHTML = "";
    const words = document.getElementById("rwords").value.trim().toLowerCase().split(/\s+/).join(" ");
    busy(btn, "Restoring…"); await nextFrame();
    try {
      const c = await getCore(); const r = c.restore(words);
      let ks;
      try { ks = c.exportKeystore(document.getElementById("rpw").value); } catch (e) { c.wipe(); throw e; }
      document.getElementById("rwords").value = document.getElementById("rpw").value = "";
      download(`gnb-wallet-${String(r.address).slice(0, 14)}.json`, ks);
      enter("keys", r.address, "Wallet restored from its recovery phrase. A new encrypted keystore was downloaded.");
    } catch (e) { unbusy(btn); showError(msg, e); }
  });
  document.getElementById("watch").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("watch-msg"); msg.innerHTML = "";
    busy(btn, "Checking…");
    try { const c = await getCore(); enter("watch", c.normalize(document.getElementById("waddr").value)); }
    catch (e) { unbusy(btn); showError(msg, e); }
  });
}

/** WAL-7: show the new recovery phrase once; continue only after the user
 *  confirms it is written down. */
function showPhrase(created, keystore) {
  const words = String(created.words || "").split(" ").filter(Boolean);
  show(app, html`<div class="gate"><div class="gate-head"><span class="eyebrow">Recovery phrase</span><h1>Write these 24 words down.</h1>
    <p>They restore this wallet on any device. Anyone who has them controls the funds. They are shown once and never stored or sent.</p></div>
    <ol class="phrase">${words.map((w) => html`<li><span class="mono">${w}</span></li>`)}</ol>
    <label class="check"><input type="checkbox" id="wrote"> I have written the 24 words down, in order, offline.</label>
    <div class="row" style="margin-top:14px"><button class="btn" id="phrase-done" disabled>Download keystore and continue</button></div></div>`);
  const done = document.getElementById("phrase-done");
  document.getElementById("wrote").addEventListener("change", (e) => { done.disabled = !e.target.checked; });
  done.addEventListener("click", () => {
    download(`gnb-wallet-${String(created.address).slice(0, 14)}.json`, keystore);
    enter("keys", created.address, "New wallet created. Keep the recovery phrase offline and the keystore with its password.");
  });
}

// ── the vault (unlocked or watching) ─────────────────────────────────────────
function enter(mode, address, notice) {
  if (!isAddress(address)) throw new Error("invalid address");
  state = { mode, address, tab: mode === "keys" ? "send" : "receive", balance: null, utxos: [], immature: [], pending: null, notice };
  lockBtn.hidden = false; lockBtn.textContent = mode === "keys" ? "Lock" : "Close";
  armIdleLock(); renderVault(); refresh();
  clearInterval(pollTimer); pollTimer = setInterval(refresh, 20000);
}

async function refresh() {
  if (state.mode === "locked") return;
  try {
    const address = state.address;
    const fetchUtxos = getutxosFetcher(api, address);
    const fetchRows = async (limit) => {
      const r = await fetchUtxos(limit);
      return { rows: cleanUtxos(r.rows), truncated: r.truncated };
    };
    const [bal, next] = await Promise.all([api("getbalance", [address]), nextBlockHeight()]);
    const coins = await spendableWindow(fetchRows, next, UTXO_WINDOW, UTXO_WIDE_WINDOW);
    if (state.address !== address) return;
    state.balance = sats(bal.satoshis ?? bal.balance) ?? 0n;
    state.utxos = coins.spendable;
    state.utxoTotal = total(coins.spendable);
    state.immature = coins.immature;
    state.immatureTotal = total(coins.immature);
    state.utxosTruncated = coins.truncated || coins.widenFailed;
    state.utxoCount = count(bal.utxo_count ?? coins.listed);
    paintSlab();
    if (state.tab === "activity") paintActivity();
  } catch (e) { const el = document.getElementById("slab-err"); if (el) showError(el, e); }
}

function renderVault() {
  const keys = state.mode === "keys";
  const tabs = keys ? [["send", "Send"], ["receive", "Receive"], ["activity", "Activity"], ["backup", "Backup"]] : [["receive", "Receive"], ["activity", "Activity"]];
  show(app, html`${state.notice ? html`<div class="alert ok" style="margin-bottom:18px">${state.notice}</div>` : ""}<div class="vault">
   <aside class="slab" id="slab"></aside>
   <section class="panel"><div class="tabs" role="tablist">${tabs.map(([k, l]) => html`<button role="tab" data-tab="${k}" aria-selected="${state.tab === k}">${l}</button>`)}</div><div class="pane" id="pane"></div></section></div>`);
  app.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderVault(); }));
  paintSlab(); paintPane();
}

function paintSlab() {
  const el = document.getElementById("slab"); if (!el) return;
  const keys = state.mode === "keys";
  show(el, html`<span class="k">Balance</span>
   <div class="bal">${state.balance === null ? raw(`<span class="busy"></span>`) : fmt(state.balance)}<small>GNB</small></div>
   <div class="row">${keys ? raw(`<span class="chip on">● Unlocked</span>`) : raw(`<span class="chip watch">◌ Watching</span>`)}<a class="chip" href="/explorer#/address/${state.address}" target="_blank" rel="noopener">Explorer ↗</a></div>
   <span class="k">Address</span><div class="addr" id="addr">${state.address}</div>
   <div class="row"><button class="chip" id="copy">Copy address</button><button class="chip" id="refresh">Refresh</button></div>
   <div class="facts"><div><b>${state.utxoCount ?? "—"}</b><span>Unspent outputs</span></div><div><b>${state.utxos.length ? fmt(state.utxoTotal, 4) : "—"}</b><span>Spendable now*</span></div>${state.immature.length ? html`<div><b>${fmt(state.immatureTotal, 4)}</b><span>Immature (mining rewards)</span></div>` : ""}</div>
   <p class="note">* One payment can spend up to ${UTXO_WINDOW} outputs (each input carries an ~8.5 kB post-quantum signature).${state.immature.length ? ` Mining rewards (coinbase outputs) become spendable ${COINBASE_MATURITY} blocks after their block; ${state.immature.length} are not yet and are not counted.` : ""}${state.utxosTruncated ? " The node listed only part of this address's outputs; more may be spendable." : ""}</p><div id="slab-err"></div>`);
  document.getElementById("copy").addEventListener("click", (e) => navigator.clipboard?.writeText(state.address).then(() => { e.target.textContent = "Copied"; setTimeout(() => (e.target.textContent = "Copy address"), 1200); }));
  document.getElementById("refresh").addEventListener("click", refresh);
}

function paintPane() {
  const pane = document.getElementById("pane");
  ({ send: paintSend, receive: paintReceive, activity: paintActivity, backup: paintBackup }[state.tab] || paintReceive)(pane);
}

/** Height of the next block: the node's getdaginfo next_block_height (the
 *  height its mempool and block template check a payment against; it can
 *  exceed tip_height + 1), or tip_height + 1 from a node without the field.
 *  The core signs version 3 (sighash v3, which commits to every spent value)
 *  from the hardening activation height and version 1 below it. */
async function nextBlockHeight() {
  const dag = await api("getdaginfo");
  if (dag.next_block_height !== undefined && dag.next_block_height !== null) {
    const next = num(dag.next_block_height);
    if (!Number.isSafeInteger(next) || next < 1) throw new Error("The node reported an invalid next block height.");
    return next;
  }
  const tip = num(dag.tip_height);
  if (!Number.isSafeInteger(tip) || tip < 0) throw new Error("The node did not report its chain height.");
  return tip + 1;
}

/** WAL-1 (version-1 payments): fetch the creating transactions of the inputs
 *  the core plans to spend. A transaction the server cannot provide
 *  (carryover, pruned) is simply absent: that input stays unverified and is
 *  flagged. The core hashes every provided transaction against its txid, so
 *  a forged one is refused. Version 3 needs none (plan returns no txids). */
async function fetchPrevTxs(txids) {
  const out = {};
  await Promise.all(txids.filter(isHex64).map(async (txid) => {
    try { const r = await api("getrawtransaction", [txid]); if (typeof r.hex === "string") out[txid] = r.hex; } catch {}
  }));
  return out;
}

function paintSend(pane = document.getElementById("pane")) {
  show(pane, html`<h3>Send GNB</h3>
   <label>To<input id="to" spellcheck="false" placeholder="gnb1q… (a bloch1q… address is accepted)"></label>
   <div class="field-row"><label>Amount (GNB)<input id="amt" inputmode="decimal" placeholder="0.00"></label><button class="btn ghost" id="max">Max</button></div>
   <p class="note">The network fee is the consensus minimum for the transaction's real size (≈ 0.00002 GNB per kB, at least 0.0001 GNB). Fees above 0.02 GNB are refused.</p>
   <button class="btn" id="review">Review payment</button><div id="send-out"></div>`);
  document.getElementById("max").addEventListener("click", () => {
    // Leave room for the fee of up to 50 inputs (~430 kB at 2,000 sat/kB).
    // utxoTotal counts only the coins spendable in the next block.
    const reserve = 900000n, spendable = state.utxoTotal || 0n;
    document.getElementById("amt").value = spendable > reserve ? fmt(spendable - reserve) : "0";
  });
  document.getElementById("review").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = document.getElementById("send-out"); out.innerHTML = "";
    try {
      const to = core.normalize(document.getElementById("to").value);
      const amount = parseGnb(document.getElementById("amt").value);
      if (amount <= 0n) throw new Error("Enter an amount above zero.");
      if (!state.utxos.length) {
        throw new Error(state.immature.length
          ? `No spendable outputs yet: ${state.immature.length} mining reward(s) become spendable ${COINBASE_MATURITY} blocks after their block.`
          : "No spendable outputs found for this address yet.");
      }
      busy(btn, "Verifying inputs and signing…"); await nextFrame();
      const next = await nextBlockHeight();
      // The rows of the last refresh, checked again at this height.
      const coins = splitByMaturity(state.utxos, next).spendable;
      if (!coins.length) throw new Error("No spendable outputs at the next block; refresh and try again.");
      const plan = core.plan(coins, to, amount.toString(), "0", next);
      const prevtxs = await fetchPrevTxs(plan.prev_txids || []);
      const tx = core.pay(coins, to, amount.toString(), "0", next, prevtxs);
      state.pending = { ...tx, to };
      unbusy(btn);
      const unverified = num(tx.unverified_inputs) || 0;
      const dust = sats(tx.dust_to_fee) ?? 0n;
      show(out, html`<div class="review">
        <div><span>To</span><b>${to}</b></div>
        <div><span>Amount</span><b>${fmt(tx.amount)} GNB</b></div>
        <div><span>Network fee (actual)</span><b>${fmt(tx.fee)} GNB${dust > 0n ? html` <small>incl. ${fmt(dust)} GNB change too small to return</small>` : ""}</b></div>
        <div><span>Inputs · size</span><b>${count(tx.inputs)} · ${(num(tx.size) / 1024).toFixed(1)} kB</b></div>
        ${tx.amounts_committed === true
          ? html`<div><span>Input values</span><b>committed by the signature (version 3)</b></div>`
          : html`<div><span>Inputs verified against the chain</span><b>${count(tx.verified_inputs)} of ${count(tx.inputs)}</b></div>`}
        <div><span>Change back to you</span><b>${fmt(tx.change)} GNB</b></div>
        <div><span>Total leaving this address</span><b>${fmt((sats(tx.amount) ?? 0n) + (sats(tx.fee) ?? 0n))} GNB</b></div></div>
        ${unverified ? html`<div class="alert bad" style="margin-top:12px">${unverified} input value(s) come only from the server (genesis carryover or pruned history) and could not be checked against their transaction. If the server lied, the difference would be paid as fee.
          <label class="check"><input type="checkbox" id="accept-unverified"> I accept the unverified input value(s) shown above.</label></div>` : ""}
        <div class="row" style="margin-top:14px"><button class="btn" id="confirm" ${unverified ? raw("disabled") : ""}>Confirm and send</button><button class="btn ghost" id="cancel">Cancel</button></div>`);
      const confirmBtn = document.getElementById("confirm");
      document.getElementById("accept-unverified")?.addEventListener("change", (e) => { confirmBtn.disabled = !e.target.checked; });
      document.getElementById("cancel").addEventListener("click", () => { state.pending = null; out.innerHTML = ""; });
      confirmBtn.addEventListener("click", async (e2) => {
        const b2 = e2.currentTarget; busy(b2, "Broadcasting…");
        try {
          await broadcast(state.pending.raw);
          const id = isHex64(state.pending.txid) ? state.pending.txid : ""; state.pending = null;
          show(out, html`<div class="alert ok">Sent. Transaction <a class="mono" href="/explorer#/tx/${id}" target="_blank" rel="noopener">${id.slice(0, 16)}…</a> is in the mempool and will confirm in the next blocks.</div>`);
          setTimeout(refresh, 3000);
        } catch (err) { unbusy(b2); showError(out, err); }
      });
    } catch (e) { unbusy(btn); showError(out, e); }
  });
}

function paintReceive(pane = document.getElementById("pane")) {
  let qr = "";
  // The QR library returns SVG markup for the (validated) address only.
  try { const q = window.qrcode(0, "M"); q.addData(state.address, "Byte"); q.make(); qr = raw(q.createSvgTag({ cellSize: 6, margin: 0, scalable: true })); } catch {}
  show(pane, html`<h3>Receive GNB</h3><div class="receive"><div class="qr" aria-label="QR code of the address">${qr}</div>
   <div style="display:grid;gap:12px"><p>Share this address. Anyone can send GNB to it; only the keystore can spend it.</p><div class="addr">${state.address}</div>
   <p class="note">Same key as the Bloch address <span class="mono">bloch1q${state.address.slice(5)}</span>: GNB from the Genesis-3 carryover is already here.</p></div></div>`);
}

async function paintActivity(pane = document.getElementById("pane")) {
  if (!pane || state.tab !== "activity") return;
  if (!pane.dataset.loaded) show(pane, html`<h3>Activity</h3><p class="muted"><span class="busy"></span>Loading…</p>`);
  try {
    const [h, carry] = await Promise.all([api("getaddresshistory", [state.address, 25, 0]), fetch(`/api/carryover/${state.address}`).then((r) => r.json()).catch(() => null)]);
    pane.dataset.loaded = "1";
    const c = carry?.result;
    const items = Array.isArray(h.items) ? h.items : [];
    show(pane, html`<h3>Activity</h3>
     ${c?.in_carryover === true ? html`<div class="alert ok">Genesis carryover: ${fmt(c.amount)} GNB from the Bloch Genesis-3 snapshot (${count(c.utxos)} outputs).</div>` : ""}
     ${items.length ? html`<table class="activity"><thead><tr><th>Height</th><th>Transaction</th><th></th><th class="num">GNB</th></tr></thead><tbody>
      ${items.map((i) => { const txid = isHex64(i.txid) ? i.txid : ""; const incoming = i.direction === "in";
        return html`<tr><td class="mono">${count(i.height)}</td><td><a class="mono" href="/explorer#/tx/${txid}" target="_blank" rel="noopener">${txid.slice(0, 12)}…</a></td><td class="muted">${incoming ? "received" : "sent"}</td><td class="num ${incoming ? "in" : ""}">${incoming ? "+" : "−"}${fmt(i.amount)}</td></tr>`; })}
      </tbody></table>${num(h.total) > 25 ? html`<p class="note">Showing the latest 25 of ${count(h.total)}. <a href="/explorer#/address/${state.address}" target="_blank" rel="noopener">Full history in the explorer ↗</a></p>` : ""}`
      : html`<p class="muted">No on-chain movements yet.</p>`}`);
  } catch (e) { showError(pane, e); }
}

function paintBackup(pane = document.getElementById("pane")) {
  show(pane, html`<h3>Back up this wallet</h3>
   <p>Download the key again as an encrypted GnB keystore (v3: its network and address are authenticated). Choose a password; it is the only way to open the file.</p>
   <label>Password<input type="password" id="bpw" autocomplete="new-password"></label>
   <label>Repeat password<input type="password" id="bpw2" autocomplete="new-password"></label>
   <button class="btn ghost" id="bdl">Download encrypted keystore</button><div id="b-out"></div>
   <p class="note">The file can be opened here, with <span class="mono">gnb-cli send</span>, and with any GnB node tool. Never share it together with its password.</p>`);
  document.getElementById("bdl").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = document.getElementById("b-out"); out.innerHTML = "";
    const p1 = document.getElementById("bpw").value, p2 = document.getElementById("bpw2").value;
    if (p1 !== p2) return showError(out, "The passwords do not match.");
    busy(btn, "Encrypting…"); await nextFrame();
    try { download(`gnb-wallet-${state.address.slice(0, 14)}.json`, core.exportKeystore(p1)); unbusy(btn); show(out, html`<div class="alert ok">Keystore downloaded.</div>`);
      document.getElementById("bpw").value = document.getElementById("bpw2").value = ""; }
    catch (e) { unbusy(btn); showError(out, e); }
  });
}

// Shareable watch links: /wallet#watch/<address>
async function boot() {
  const address = watchAddress(location.hash);
  if (address) {
    try { const c = await getCore(); return enter("watch", c.normalize(address)); } catch {}
  }
  renderGate();
}
boot();
