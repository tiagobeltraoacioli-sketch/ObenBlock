// ObenBlock web wallet. Keys are decrypted and used only inside the WebAssembly
// core (core.js / gnb_wallet.wasm); this file never sees a private key.
//
// ObenBlock: the core signs for chain id 0x4F420001 (mainnet) or 0x4F420002
// (regtest) only, every payment is a version-3 transaction (sighash v3, from
// height 0), and addresses are shown as obb1… (gnb1… and bloch1… strings are
// accepted as the same script). The network is the one the site's node
// reports (getnetworkinfo chain_id); the page refuses to sign when the node is
// not an ObenBlock node or runs another network than the wallet.
//
// Audit fixes: all markup is built with the escaping `html` template and API
// values are type-checked (WAL-3); the wasm core is checked against the
// SHA-256 pinned below before it runs (WAL-5); a version-3 signature commits
// to every spent value, and the review shows the ACTUAL fee and any input that
// could not be verified (WAL-1, WAL-6); new wallets are backed by a 24-word
// recovery phrase (WAL-7). Only coins spendable in the next block reach the
// core: an immature coinbase output is neither counted as spendable nor
// offered to the core (core.js splitByMaturity). Received coins are final
// once PoWit finalizes their block (getpowitinfo finalized), which the
// activity list shows per movement.
//
// Pre-launch review: every API answer is bound to the chain this page
// verified first (core.js ChainSession: the chain id, genesis hash and
// finalized checkpoints the Worker stamps on each answer); an answer from
// another chain stops the session with an alert instead of being shown or
// signed against. A gnb1…/bloch1… destination is shown as typed next to the
// obb1… key it maps to, and needs an explicit confirmation.
import { loadCore, spendableWindow, splitByMaturity, getutxosFetcher, networkOfChainId, walletNetwork, addressFamily, ChainSession, ChainMismatchError, COINBASE_MATURITY, UTXO_WINDOW, UTXO_WIDE_WINDOW } from "/wallet/core.js";
import { html, raw, isAddress, watchAddress, isHex64, num, sats } from "/assets/safe.js";

// SHA-256 of /wallet/gnb_wallet.wasm. Written by scripts/build-wallet-wasm.sh
// and checked by `node --test site/tests/`; loadCore refuses any other binary.
const WASM_SHA256 = "0ed88e02ff93c3ee9990ab5f50f6cdd2c3f253c70bcdb73518fe175871c1490a";

const SAT = 100000000n;
// UTXO_WINDOW / UTXO_WIDE_WINDOW (core.js): rows asked of getutxos, the same
// constants the explorer API's parameter check is tested against (B2-T3).
const IDLE_LOCK_MS = 10 * 60 * 1000;
const app = document.getElementById("app");
const lockBtn = document.getElementById("lock");
const netBadge = document.getElementById("netbadge");
let core = null;
let state = { mode: "locked", address: null, network: null, tab: "send", balance: null, utxos: [], immature: [], pending: null };
let idleTimer = null, pollTimer = null;
// The site's node: its network (from the chain id it reports), tip and PoWit
// finality. `error` is set when it is unreachable or not an ObenBlock node.
let node = { network: null, error: null, tip: null, finalized: null };
// The one chain every answer of this page must come from.
const session = new ChainSession();

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
/** Bind the answer `r` to the session's chain (core.js ChainSession). A
 *  Worker error without an origin behind it (502, 503) names no chain and is
 *  only an error; every origin answer must name this session's chain. */
function bindAnswer(r) {
  if (!r.ok && !r.headers.get("x-obb-chain-id")) return;
  try { session.check(r.headers); }
  catch (e) { if (session.broken) chainAlert(session.broken); throw e; }
}
function chainAlert(message) {
  clearInterval(pollTimer);
  if (netBadge) { netBadge.textContent = "chain mismatch"; netBadge.dataset.state = "bad"; netBadge.title = message; }
  let el = document.getElementById("chain-alert");
  if (!el) { el = document.createElement("div"); el.id = "chain-alert"; el.className = "alert bad"; el.style.margin = "0 0 18px"; el.setAttribute("role", "alert"); app.before(el); }
  el.textContent = message;
}
async function api(method, params = []) {
  const r = await fetch(`/api/${method}?p=${encodeURIComponent(JSON.stringify(params))}`, { cache: "no-store" });
  const doc = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  bindAnswer(r);
  if (doc.error) throw new Error(String(doc.error));
  if (doc.result === null || typeof doc.result !== "object") throw new Error("unexpected response");
  return doc.result;
}
async function broadcast(hex) {
  if (session.broken) throw new ChainMismatchError(session.broken);
  const r = await fetch("/api/sendrawtransaction", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hex }) });
  const doc = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  bindAnswer(r);
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
/** Ask the site's node which network it runs (getnetworkinfo chain_id) and
 *  how far PoWit has finalized (getpowitinfo). Never throws: `node.error`. */
async function refreshNode() {
  try {
    const info = await api("getnetworkinfo");
    node.network = networkOfChainId(info.chain_id);
    // The node's own report must be the chain the answers are stamped with.
    if (String(info.chain_id).toLowerCase() !== session.identity?.chain) {
      try { session.fail(`The node reports chain id ${info.chain_id}, but its answers are stamped ${session.identity?.chain ?? "with no chain"}.`); }
      catch (e) { chainAlert(session.broken); throw e; }
    }
    node.error = null;
    try {
      const pw = await api("getpowitinfo");
      node.tip = Number.isSafeInteger(num(pw.tip_height)) ? num(pw.tip_height) : null;
      const f = num(pw.finalized?.block_height);
      node.finalized = Number.isSafeInteger(f) ? f : null;
    } catch { node.finalized = null; }
  } catch (e) {
    node.network = null;
    node.error = e?.message || String(e);
  }
  paintNetBadge();
  return node;
}
function paintNetBadge() {
  if (!netBadge) return;
  if (session.broken) return chainAlert(session.broken);
  const text = node.network
    ? `ObenBlock ${node.network}${node.finalized !== null ? ` · finalized #${node.finalized.toLocaleString("en-US")}` : ""}`
    : node.error ? "node unavailable" : "connecting…";
  netBadge.textContent = text;
  netBadge.dataset.state = node.network ? "ok" : node.error ? "bad" : "";
  netBadge.title = node.error || "Network and PoWit finality reported by this site's node";
}
/** The node runs `network`, or an error that says why the page will not sign. */
function requireNodeNetwork(network) {
  if (session.broken) throw new ChainMismatchError(session.broken);
  if (!session.identity) throw new Error("The site's chain is not verified yet; try again.");
  if (!node.network) throw new Error(node.error ? `Cannot reach an ObenBlock node: ${node.error}` : "The node's network is not known yet; try again.");
  if (node.network !== network) throw new Error(`This wallet is on ObenBlock ${network}, but the site's node runs ${node.network}. Nothing was signed.`);
}
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
  state = { mode: "locked", address: null, network: null, tab: "send", balance: null, utxos: [], immature: [], pending: null };
  lockBtn.hidden = true;
  renderGate(message);
}
lockBtn.addEventListener("click", () => lock());
window.addEventListener("pagehide", () => { try { core?.wipe(); } catch {} });

// ── the gate (locked) ────────────────────────────────────────────────────────
function renderGate(message) {
  show(app, html`<div class="gate">
  <div class="gate-head"><span class="eyebrow">ObenBlock Wallet</span><h1>Hold OBB with post-quantum keys.</h1>
   <p>Open an ObenBlock, GnB or Bloch keystore, create a new one, or watch an address. Your keystore is decrypted in this tab with its password, and signing happens here too. Nothing secret is uploaded.</p></div>
  ${message ? html`<div class="alert ok">${message}</div>` : ""}
  <div class="netpick"><label>Network<select id="net">${["mainnet", "regtest"].map((n) => html`<option value="${n}" ${n === (node.network || "mainnet") ? raw("selected") : ""}>ObenBlock ${n}</option>`)}</select></label>
   <p class="note" id="net-note">${node.network ? html`The site's node runs ObenBlock ${node.network}. Signatures commit to its chain id, so a transaction is valid on this network only.` : node.error ? html`The site's node cannot be used: ${node.error}. You can open or create a wallet; sending waits for an ObenBlock node.` : "Asking the site's node which network it runs…"}</p></div>
  <div class="doors">
   <section class="door primary"><span class="num">01 · OPEN</span><h2>Open a keystore</h2>
    <p>A <span class="mono">.json</span> keystore from ObenBlock, GnB or Bloch (Genesis-3). Its <span class="mono">gnb1q…</span> or <span class="mono">bloch1q…</span> address is the same <span class="mono">obb1q…</span> address: the same key holds the genesis carryover here.</p>
    <div class="drop" id="drop" tabindex="0" role="button" aria-label="Choose keystore file"><b>Drop the keystore here</b><br>or click to choose a file</div>
    <input type="file" id="file" accept=".json,application/json" hidden>
    <label>Password<input type="password" id="pw" autocomplete="current-password"></label>
    <button class="btn" id="open">Unlock</button><div id="open-msg"></div></section>
   <section class="door"><span class="num">02 · CREATE</span><h2>Create a wallet</h2>
    <p>A new ML-DSA-65 + Falcon-1024 key, generated here from a 24-word recovery phrase that you write down (mainnet; a regtest key has no phrase). You also download its encrypted keystore.</p>
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
    <p>Balance, activity and a receive QR for any <span class="mono">obb1q…</span> address (a <span class="mono">gnb1q…</span> or <span class="mono">bloch1q…</span> one is the same address). No keys involved.</p>
    <label>Address<input id="waddr" spellcheck="false" placeholder="obb1q…"></label>
    <button class="btn ghost" id="watch">Watch</button><div id="watch-msg"></div></section>
  </div>
  <div class="trust">
   <div><b>Keys stay in the tab</b><span>Decryption (Argon2id, AES-256-GCM) and signing run in WebAssembly in this page. The page loads only code from this site, checked against pinned hashes.</span></div>
   <div><b>Post-quantum signatures</b><span>Every input is signed with ML-DSA-65 and Falcon-1024 together; both must verify. Each signature commits to the ObenBlock chain id and to every spent value (version-3 transactions).</span></div>
   <div><b>Locks itself</b><span>The key is wiped from memory on Lock, when the tab closes, and after 10 minutes idle.</span></div>
  </div></div>`);
  let fileText = null;
  const drop = document.getElementById("drop"), file = document.getElementById("file");
  const picked = () => walletNetwork(document.getElementById("net").value);
  const take = async (f) => { if (!f) return; if (f.size > 4 * 1024 * 1024) return showError(document.getElementById("open-msg"), "That file is too large to be a keystore.");
    fileText = await f.text(); show(drop, html`<b>${f.name}</b><br>${(f.size / 1024).toFixed(1)} kB · ready`); document.getElementById("pw").focus(); };
  document.getElementById("net").addEventListener("change", (e) => { e.target.dataset.touched = "1"; });
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
      const network = picked();
      const c = await getCore(); const r = c.open(fileText, document.getElementById("pw").value, network);
      document.getElementById("pw").value = ""; fileText = null;
      enter("keys", r.address, undefined, network);
    } catch (e) { unbusy(btn); showError(msg, e); }
  });
  document.getElementById("create").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("create-msg"); msg.innerHTML = "";
    const p1 = document.getElementById("npw").value, p2 = document.getElementById("npw2").value;
    if (p1 !== p2) return showError(msg, "The passwords do not match.");
    busy(btn, "Generating and encrypting…"); await nextFrame();
    try {
      const network = picked();
      const c = await getCore(); const r = c.create(network);
      let ks;
      try { ks = c.exportKeystore(p1); } catch (e) { c.wipe(); throw e; }
      document.getElementById("npw").value = document.getElementById("npw2").value = "";
      if (r.words) showPhrase(r, ks, network);
      else {
        download(keystoreName(r.address), ks);
        enter("keys", r.address, "New regtest wallet created (random key, no recovery phrase). Its encrypted keystore was downloaded.", network);
      }
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
      download(keystoreName(r.address), ks);
      enter("keys", r.address, "Wallet restored from its recovery phrase. A new encrypted keystore was downloaded.", "mainnet");
    } catch (e) { unbusy(btn); showError(msg, e); }
  });
  document.getElementById("watch").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("watch-msg"); msg.innerHTML = "";
    busy(btn, "Checking…");
    try { const c = await getCore(); const a = c.classify(document.getElementById("waddr").value); enter("watch", a.address, undefined, walletNetwork(a.network)); }
    catch (e) { unbusy(btn); showError(msg, e); }
  });
}

/** WAL-7: show the new recovery phrase once; continue only after the user
 *  confirms it is written down. */
function showPhrase(created, keystore, network) {
  const words = String(created.words || "").split(" ").filter(Boolean);
  show(app, html`<div class="gate"><div class="gate-head"><span class="eyebrow">Recovery phrase</span><h1>Write these 24 words down.</h1>
    <p>They restore this wallet on any device. Anyone who has them controls the funds. They are shown once and never stored or sent.</p></div>
    <ol class="phrase">${words.map((w) => html`<li><span class="mono">${w}</span></li>`)}</ol>
    <label class="check"><input type="checkbox" id="wrote"> I have written the 24 words down, in order, offline.</label>
    <div class="row" style="margin-top:14px"><button class="btn" id="phrase-done" disabled>Download keystore and continue</button></div></div>`);
  const done = document.getElementById("phrase-done");
  document.getElementById("wrote").addEventListener("change", (e) => { done.disabled = !e.target.checked; });
  done.addEventListener("click", () => {
    download(keystoreName(created.address), keystore);
    enter("keys", created.address, "New wallet created. Keep the recovery phrase offline and the keystore with its password.", network);
  });
}

// ── the vault (unlocked or watching) ─────────────────────────────────────────
/** The download name of a keystore: obenblock-wallet-<address start>.json. */
const keystoreName = (address) => `obenblock-wallet-${String(address).slice(0, 14)}.json`;

function enter(mode, address, notice, network = "mainnet") {
  if (!isAddress(address)) throw new Error("invalid address");
  state = { mode, address, network: walletNetwork(network), tab: mode === "keys" ? "send" : "receive", balance: null, utxos: [], immature: [], pending: null, notice };
  lockBtn.hidden = false; lockBtn.textContent = mode === "keys" ? "Lock" : "Close";
  armIdleLock(); renderVault(); refresh();
  clearInterval(pollTimer); pollTimer = setInterval(refresh, 20000);
}

async function refresh() {
  if (state.mode === "locked") return;
  await refreshNode();
  if (state.network && node.network && node.network !== state.network) {
    const el = document.getElementById("slab-err");
    if (el) showError(el, `This wallet is on ObenBlock ${state.network}; the site's node runs ${node.network}, so its balance is not shown.`);
    return;
  }
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
   <div class="bal">${state.balance === null ? raw(`<span class="busy"></span>`) : fmt(state.balance)}<small>OBB</small></div>
   <div class="row">${keys ? raw(`<span class="chip on">● Unlocked</span>`) : raw(`<span class="chip watch">◌ Watching</span>`)}<span class="chip static">ObenBlock ${state.network || "mainnet"}</span><a class="chip" href="/explorer#/address/${state.address}" target="_blank" rel="noopener">Explorer ↗</a></div>
   <span class="k">Address</span><div class="addr" id="addr">${state.address}</div>
   <div class="row"><button class="chip" id="copy">Copy address</button><button class="chip" id="refresh">Refresh</button></div>
   <div class="facts"><div><b>${state.utxoCount ?? "—"}</b><span>Unspent outputs</span></div><div><b>${state.utxos.length ? fmt(state.utxoTotal, 4) : "—"}</b><span>Spendable now*</span></div>${state.immature.length ? html`<div><b>${fmt(state.immatureTotal, 4)}</b><span>Immature (mining rewards)</span></div>` : ""}</div>
   ${node.finalized !== null ? html`<p class="note">PoWit finalized through height ${count(node.finalized)}${node.tip !== null ? ` (tip ${count(node.tip)})` : ""}. Coins received at or below it are final.</p>` : ""}
   <p class="note">* One payment can spend up to ${UTXO_WINDOW} outputs (each input carries an ~8.6 kB post-quantum signature and key).${state.immature.length ? ` Mining rewards (coinbase outputs) become spendable ${COINBASE_MATURITY} blocks after their block; ${state.immature.length} are not yet and are not counted.` : ""}${state.utxosTruncated ? " The node listed only part of this address's outputs; more may be spendable." : ""}</p><div id="slab-err"></div>`);
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
 *  On ObenBlock the core signs version 3 (sighash v3, which commits to every
 *  spent value) at every height; the height still bounds coinbase maturity. */
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

/** WAL-1 (version-1 payments, never on ObenBlock): fetch the creating
 *  transactions of the inputs the core plans to spend. A transaction the
 *  server cannot provide (carryover, pruned) is simply absent: that input
 *  stays unverified and is flagged. The core hashes every provided
 *  transaction against its txid, so a forged one is refused. Version 3 needs
 *  none (plan returns no txids). */
async function fetchPrevTxs(txids) {
  const out = {};
  await Promise.all(txids.filter(isHex64).map(async (txid) => {
    try { const r = await api("getrawtransaction", [txid]); if (typeof r.hex === "string") out[txid] = r.hex; } catch {}
  }));
  return out;
}

function paintSend(pane = document.getElementById("pane")) {
  show(pane, html`<h3>Send OBB</h3>
   <label>To<input id="to" spellcheck="false" placeholder="obb1q…"></label>
   <div class="field-row"><label>Amount (OBB)<input id="amt" inputmode="decimal" placeholder="0.00"></label><button class="btn ghost" id="max">Max</button></div>
   <p class="note">The network fee is the consensus minimum: 1% of the amount sent (change is exempt), and never below the size floor (≈ 0.00002 OBB per kB, at least 0.0001 OBB). It is split between the miner and the PoWit witnesses. Fees more than 0.02 OBB above the 1% are refused.</p>
   <button class="btn" id="review">Review payment</button><div id="send-out"></div>`);
  document.getElementById("max").addEventListener("click", () => {
    // Leave room for the fee of up to UTXO_WINDOW (47) inputs (~403 kB at
    // 2,000 sat/kB) and for the 1% of the amount (amount × 1.01 must fit).
    // utxoTotal counts only the coins spendable in the next block.
    const reserve = 900000n, spendable = state.utxoTotal || 0n;
    document.getElementById("amt").value = spendable > reserve ? fmt((spendable - reserve) * 100n / 101n) : "0";
  });
  document.getElementById("review").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = document.getElementById("send-out"); out.innerHTML = "";
    try {
      const typed = document.getElementById("to").value.trim();
      const dest = core.classify(typed);
      const to = dest.address;
      // A GnB or Bloch string names the same key on ObenBlock: say so, show
      // what was typed, and ask for an explicit confirmation below.
      const family = addressFamily(typed);
      const alias = family === "obb" ? null : family === "gnb" ? "GnB" : "Bloch";
      if (walletNetwork(dest.network) !== state.network) throw new Error(`That is an ObenBlock ${walletNetwork(dest.network)} address; this wallet is on ${state.network}.`);
      const amount = parseGnb(document.getElementById("amt").value);
      if (amount <= 0n) throw new Error("Enter an amount above zero.");
      if (!state.utxos.length) {
        throw new Error(state.immature.length
          ? `No spendable outputs yet: ${state.immature.length} mining reward(s) become spendable ${COINBASE_MATURITY} blocks after their block.`
          : "No spendable outputs found for this address yet.");
      }
      busy(btn, "Verifying inputs and signing…"); await nextFrame();
      await refreshNode();
      requireNodeNetwork(state.network);
      const next = await nextBlockHeight();
      // The rows of the last refresh, checked again at this height.
      const coins = splitByMaturity(state.utxos, next).spendable;
      if (!coins.length) throw new Error("No spendable outputs at the next block; refresh and try again.");
      const plan = core.plan(coins, to, amount.toString(), "0", next);
      const prevtxs = await fetchPrevTxs(plan.prev_txids || []);
      const tx = core.pay(coins, to, amount.toString(), "0", next, prevtxs);
      state.pending = { ...tx, to, typed };
      unbusy(btn);
      const unverified = num(tx.unverified_inputs) || 0;
      const dust = sats(tx.dust_to_fee) ?? 0n;
      show(out, html`<div class="review">
        <div><span>To</span><b>${to}${alias ? html`<br><small>typed as the ${alias} address ${typed}</small>` : ""}</b></div>
        <div><span>Amount</span><b>${fmt(tx.amount)} OBB</b></div>
        <div><span>Network fee (actual)</span><b>${fmt(tx.fee)} OBB${dust > 0n ? html` <small>incl. ${fmt(dust)} OBB change too small to return</small>` : ""}</b></div>
        <div><span>Inputs · size</span><b>${count(tx.inputs)} · ${(num(tx.size) / 1024).toFixed(1)} kB</b></div>
        ${tx.amounts_committed === true
          ? html`<div><span>Input values</span><b>committed by the signature (version 3)</b></div>`
          : html`<div><span>Inputs verified against the chain</span><b>${count(tx.verified_inputs)} of ${count(tx.inputs)}</b></div>`}
        <div><span>Change back to you</span><b>${fmt(tx.change)} OBB</b></div>
        <div><span>Total leaving this address</span><b>${fmt((sats(tx.amount) ?? 0n) + (sats(tx.fee) ?? 0n))} OBB</b></div></div>
        ${unverified ? html`<div class="alert bad" style="margin-top:12px">${unverified} input value(s) come only from the server (genesis carryover or pruned history) and could not be checked against their transaction. If the server lied, the difference would be paid as fee.
          <label class="check"><input type="checkbox" id="accept-unverified"> I accept the unverified input value(s) shown above.</label></div>` : ""}
        ${alias ? html`<div class="alert bad" id="alias-notice" style="margin-top:12px"><b>You entered a ${alias} address.</b> <span class="mono">${typed}</span> is the ${alias} form of the key <span class="mono">${to}</span>. This payment sends OBB on ObenBlock to that key; nothing is sent on ${alias}. A ${alias} wallet or exchange that does not watch ObenBlock will never see or credit these coins. Send only if the recipient controls this key and uses ObenBlock.
          <label class="check"><input type="checkbox" id="accept-alias"> I confirm: send OBB on ObenBlock to the key of this ${alias} address.</label></div>` : ""}
        <div class="row" style="margin-top:14px"><button class="btn" id="confirm" ${unverified || alias ? raw("disabled") : ""}>Confirm and send</button><button class="btn ghost" id="cancel">Cancel</button></div>`);
      const confirmBtn = document.getElementById("confirm");
      const confirmations = ["accept-unverified", "accept-alias"].map((id) => document.getElementById(id)).filter(Boolean);
      confirmations.forEach((box) => box.addEventListener("change", () => { confirmBtn.disabled = !confirmations.every((b) => b.checked); }));
      document.getElementById("cancel").addEventListener("click", () => { state.pending = null; out.innerHTML = ""; });
      confirmBtn.addEventListener("click", async (e2) => {
        const b2 = e2.currentTarget;
        if (!confirmations.every((b) => b.checked)) return;
        busy(b2, "Broadcasting…");
        try {
          requireNodeNetwork(state.network);
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
  show(pane, html`<h3>Receive OBB</h3><div class="receive"><div class="qr" aria-label="QR code of the address">${qr}</div>
   <div style="display:grid;gap:12px"><p>Share this address. Anyone can send OBB to it; only the keystore can spend it.</p><div class="addr">${state.address}</div>
   ${state.network === "mainnet" && state.address.startsWith("obb1q") ? html`<p class="note">This key also has a GnB form (<span class="mono">gnb1q${state.address.slice(5)}</span>) and a Bloch form (<span class="mono">bloch1q${state.address.slice(5)}</span>), each on its own chain: OBB from the Genesis-3 carryover is already here. Share the obb1q… address. A GnB or Bloch wallet paying those forms sends GnB or Bloch coins on its own chain, and nothing arrives here; only ObenBlock software sending OBB reaches this wallet.</p>` : ""}
   <p class="note">Coins sent to this address are final once PoWit finalizes their block; the Activity tab marks each movement.</p></div></div>`);
}

async function paintActivity(pane = document.getElementById("pane")) {
  if (!pane || state.tab !== "activity") return;
  if (!pane.dataset.loaded) show(pane, html`<h3>Activity</h3><p class="muted"><span class="busy"></span>Loading…</p>`);
  try {
    const [h, c] = await Promise.all([api("getaddresshistory", [state.address, 25, 0]), api(`carryover/${state.address}`).catch((e) => { if (session.broken) throw e; return null; })]);
    pane.dataset.loaded = "1";
    const items = Array.isArray(h.items) ? h.items : [];
    show(pane, html`<h3>Activity</h3>
     ${c?.in_carryover === true ? html`<div class="alert ok">Genesis carryover: ${fmt(c.amount)} OBB from the Bloch Genesis-3 snapshot (${count(c.utxos)} outputs).</div>` : ""}
     ${items.length ? html`<table class="activity"><thead><tr><th>Height</th><th>Transaction</th><th></th><th>Finality</th><th class="num">OBB</th></tr></thead><tbody>
      ${items.map((i) => { const txid = isHex64(i.txid) ? i.txid : ""; const incoming = i.direction === "in";
        return html`<tr><td class="mono">${count(i.height)}</td><td><a class="mono" href="/explorer#/tx/${txid}" target="_blank" rel="noopener">${txid.slice(0, 12)}…</a></td><td class="muted">${incoming ? "received" : "sent"}</td><td class="muted">${finalityOf(i.height)}</td><td class="num ${incoming ? "in" : ""}">${incoming ? "+" : "−"}${fmt(i.amount)}</td></tr>`; })}
      </tbody></table>${num(h.total) > 25 ? html`<p class="note">Showing the latest 25 of ${count(h.total)}. <a href="/explorer#/address/${state.address}" target="_blank" rel="noopener">Full history in the explorer ↗</a></p>` : ""}`
      : html`<p class="muted">No on-chain movements yet.</p>`}`);
  } catch (e) { showError(pane, e); }
}

/** "final" at or below the PoWit-finalized height, else "pending". */
function finalityOf(height) {
  const h = num(height);
  if (node.finalized === null || !Number.isSafeInteger(h)) return "—";
  return h <= node.finalized ? "final" : "pending";
}

function paintBackup(pane = document.getElementById("pane")) {
  show(pane, html`<h3>Back up this wallet</h3>
   <p>Download the key again as an encrypted keystore (v3: its network and address are authenticated). Choose a password; it is the only way to open the file.</p>
   <label>Password<input type="password" id="bpw" autocomplete="new-password"></label>
   <label>Repeat password<input type="password" id="bpw2" autocomplete="new-password"></label>
   <button class="btn ghost" id="bdl">Download encrypted keystore</button><div id="b-out"></div>
   <p class="note">The file can be opened here, with <span class="mono">obenblock-cli send</span>, and with the GnB tools (it records the key's <span class="mono">gnb1…</span> form, the same address). Never share it together with its password.</p>`);
  document.getElementById("bdl").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = document.getElementById("b-out"); out.innerHTML = "";
    const p1 = document.getElementById("bpw").value, p2 = document.getElementById("bpw2").value;
    if (p1 !== p2) return showError(out, "The passwords do not match.");
    busy(btn, "Encrypting…"); await nextFrame();
    try { download(keystoreName(state.address), core.exportKeystore(p1)); unbusy(btn); show(out, html`<div class="alert ok">Keystore downloaded.</div>`);
      document.getElementById("bpw").value = document.getElementById("bpw2").value = ""; }
    catch (e) { unbusy(btn); showError(out, e); }
  });
}

// Shareable watch links: /wallet#watch/<address>
async function boot() {
  paintNetBadge();
  const address = watchAddress(location.hash);
  if (address) {
    try { const c = await getCore(); const a = c.classify(address); refreshNode(); return enter("watch", a.address, undefined, walletNetwork(a.network)); } catch {}
  }
  renderGate();
  await refreshNode();
  // Follow the node's network unless the user already picked one.
  if (state.mode === "locked") {
    const sel = document.getElementById("net");
    if (sel && node.network && !sel.dataset.touched) sel.value = node.network;
    const note = document.getElementById("net-note");
    if (note) note.textContent = node.network
      ? `The site's node runs ObenBlock ${node.network}. Signatures commit to its chain id, so a transaction is valid on this network only.`
      : `The site's node cannot be used: ${node.error}. You can open or create a wallet; sending waits for an ObenBlock node.`;
  }
}
boot();
