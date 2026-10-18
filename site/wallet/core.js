// ObenBlock wallet core loader: runs gnb-wallet-wasm (wasm32-wasip1) in the
// browser. The secret key stays inside the WebAssembly memory; this file only
// moves JSON requests and responses. Randomness comes from
// crypto.getRandomValues. The core signs for ObenBlock only (chain id
// 0x4F420001 on mainnet, 0x4F420002 on regtest; version-3 transactions from
// height 0) and shows obb1 addresses; gnb1 and bloch1 strings are accepted
// as aliases of the same script.
const WASI_EBADF = 8, WASI_ESUCCESS = 0;

// A number may already have lost integer precision before JSON serialization.
// PQ-PSBT context values use exact decimal strings at the WASM boundary.
function exactContextInteger(value, name) {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new Error(`${name} must be an exact integer; use a decimal string`);
  }
  if (!["string", "number", "bigint"].includes(typeof value) || !/^(0|[1-9][0-9]*)$/.test(String(value))) {
    throw new Error(`${name} must be an unsigned decimal integer`);
  }
  return String(value);
}

/** The wallet networks: ObenBlock mainnet and the local regtest ("testnet" is
 *  accepted as regtest's older name, the address network it uses). */
export const NETWORKS = ["mainnet", "regtest"];
export function walletNetwork(value) {
  if (value === "mainnet" || value === "regtest") return value;
  if (value === "testnet") return "regtest";
  throw new Error("unknown wallet network (expected mainnet or regtest)");
}

/** The network of the node an API answers for, from getnetworkinfo's
 *  chain_id: "mainnet" (0x4f420001) or "regtest" (0x4f420002). Anything else
 *  (a GnB node, a missing field) is refused: the page must never sign for a
 *  chain it does not know. */
export function networkOfChainId(chainId) {
  const id = typeof chainId === "string" ? chainId.toLowerCase() : "";
  if (id === "0x4f420001") return "mainnet";
  if (id === "0x4f420002") return "regtest";
  throw new Error(`the node is not an ObenBlock node (chain id ${typeof chainId === "string" ? chainId : "unknown"})`);
}

// WAL-5: the SHA-256 of the binary is mandatory; app.js passes the hash that
// scripts/build-wallet-wasm.sh pins, and any other binary is refused.
export async function loadCore(url, sha256Hex) {
  if (typeof sha256Hex !== "string" || !/^[0-9a-f]{64}$/.test(sha256Hex)) {
    throw new Error("wallet core hash is not pinned; refusing to load it");
  }
  const bytes = new Uint8Array(await (await fetch(url, { cache: "no-cache" })).arrayBuffer());
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (hex !== sha256Hex) throw new Error("wallet core integrity check failed");
  let memory = null;
  const view = () => new DataView(memory.buffer);
  const u8 = () => new Uint8Array(memory.buffer);
  const wasi = {
    random_get(ptr, len) {
      const buf = u8().subarray(ptr, ptr + len);
      for (let off = 0; off < len; off += 65536) crypto.getRandomValues(buf.subarray(off, Math.min(len, off + 65536)));
      return WASI_ESUCCESS;
    },
    environ_sizes_get(countPtr, sizePtr) { view().setUint32(countPtr, 0, true); view().setUint32(sizePtr, 0, true); return WASI_ESUCCESS; },
    environ_get() { return WASI_ESUCCESS; },
    clock_time_get(_id, _precision, outPtr) {
      view().setBigUint64(outPtr, BigInt(Date.now()) * 1000000n, true);
      return WASI_ESUCCESS;
    },
    fd_write(fd, iovs, iovsLen, nwrittenPtr) {
      if (fd !== 1 && fd !== 2) return WASI_EBADF;
      let n = 0, text = "";
      for (let i = 0; i < iovsLen; i++) {
        const p = view().getUint32(iovs + i * 8, true), l = view().getUint32(iovs + i * 8 + 4, true);
        text += new TextDecoder().decode(u8().subarray(p, p + l)); n += l;
      }
      if (text.trim()) console.warn("[gnb-wallet-core]", text.trim());
      view().setUint32(nwrittenPtr, n, true);
      return WASI_ESUCCESS;
    },
    proc_exit(code) { throw new Error(`wallet core exited (${code})`); },
  };
  const { instance } = await WebAssembly.instantiate(bytes, { wasi_snapshot_preview1: wasi });
  memory = instance.exports.memory;
  const { gnb_alloc, gnb_call, gnb_free } = instance.exports;
  const enc = new TextEncoder(), dec = new TextDecoder();

  function call(req) {
    const input = enc.encode(JSON.stringify(req));
    const p = gnb_alloc(input.length);
    u8().set(input, p);
    let packed;
    try { packed = gnb_call(p, input.length); }
    finally { u8().fill(0, p, p + input.length); gnb_free(p, input.length); }
    const outPtr = Number(BigInt.asUintN(64, packed) >> 32n), outLen = Number(BigInt.asUintN(64, packed) & 0xffffffffn);
    const out = JSON.parse(dec.decode(u8().slice(outPtr, outPtr + outLen)));
    gnb_free(outPtr, outLen);
    if (out.error) throw new Error(out.error);
    return out.ok;
  }
  return {
    // The chain this core signs for (name, chain id, prefixes, version 3).
    chain: (network = "mainnet") => call({ op: "chain", network: walletNetwork(network) }),
    open: (json, password, network = "mainnet") => call({ op: "open", json, password, network: walletNetwork(network) }),
    // WAL-7: mainnet keys are phrase-backed. A regtest key is random and
    // backed up by its encrypted keystore. `network` is "mainnet" or
    // "regtest"; a boolean (true = regtest) is accepted for older callers.
    create: (network = "mainnet") => {
      if (typeof network === "boolean") network = network ? "regtest" : "mainnet";
      const net = walletNetwork(network);
      return call({ op: "create", mnemonic: true, network: net });
    },
    setNetwork: (network) => call({ op: "setnetwork", network: walletNetwork(network) }),
    restore: (words) => call({ op: "restore", words }),
    exportKeystore: (password) => call({ op: "export", password }).keystore,
    // WAL-1: `nextHeight` is the node's getdaginfo next_block_height. On
    // ObenBlock every payment is version 3 / sighash v3, whose signature
    // commits to every spent value, so `prev_txids` is always empty...
    plan: (utxos, to, amount, fee, nextHeight) => call({ op: "plan", utxos, to, amount: String(amount), fee: String(fee), next_height: String(nextHeight) }),
    // ...and the payment; supplied previous transactions (txid -> raw hex)
    // are still checked against the claimed UTXO values before signing.
    pay: (utxos, to, amount, fee, nextHeight, prevtxs = {}) => call({ op: "pay", utxos, to, amount: String(amount), fee: String(fee), next_height: String(nextHeight), prevtxs }),
    address: () => call({ op: "address" }).address,
    normalize: (address, format = "legacy") => call({ op: "normalize", address, format }).address,
    // The obb1 form of any accepted address string and its network
    // ("mainnet" or "regtest"); throws on a bad checksum.
    classify: (address) => {
      const r = call({ op: "normalize", address: String(address ?? "").trim() });
      return { address: r.address, network: r.network };
    },
    minFee: (size) => call({ op: "minfee", size }).fee,
    // BIP174-style public roles; the document remains a string so duplicate
    // JSON fields reach the strict shared parser. Caller-supplied `op` cannot
    // redirect this public-data binding to an operation using the session key.
    pqpsbt: (request) => call({ ...request, op: "pqpsbt" }),
    // Public identities only; importing a pool never opens a signing session.
    // R5-VERDICT-1: JSON.stringify calls toJSON before encoding. A caller's
    // own or inherited hook must not replace this envelope with {op:"wipe"}.
    descriptor: (request) => {
      if (!request || typeof request !== "object" || Array.isArray(request)) {
        throw new Error("descriptor request must be an object");
      }
      const message = Object.assign(Object.create(null), request);
      if (Object.hasOwn(message, "toJSON")) throw new Error("unknown descriptor request field: toJSON");
      message.op = "descriptor";
      return call(message);
    },
    // Offline context is supplied by the signer. The core checks commitments
    // and fee/height/network, but cannot attest current chain unspentness.
    signPqPsbt: (hex, network, nextHeight, maxFee) => call({
      op: "pqpsbt_sign", hex, network,
      next_height: exactContextInteger(nextHeight, "nextHeight"),
      max_fee: exactContextInteger(maxFee, "maxFee"),
    }),
    wipe: () => call({ op: "wipe" }),
  };
}

// ── Which coins a payment can spend ──────────────────────────────────────────
// Coinbase outputs are spendable COINBASE_MATURITY blocks after the block that
// created them (gnb_crypto::core::COINBASE_MATURITY; site/tests pins the two).
export const COINBASE_MATURITY = 100;

/** Split getutxos rows into those spendable in the block at `nextHeight` and
 *  the immature coinbase outputs: a row carrying `coinbase_height` only from
 *  coinbase_height + COINBASE_MATURITY on, a row without it always (the rule
 *  of gnb_crypto::wallet::send::utxo_row_spendable_at, which the core and
 *  gnb-cli apply). A malformed coinbase_height counts as immature. */
export function splitByMaturity(rows, nextHeight) {
  const spendable = [], immature = [];
  for (const row of rows) {
    const cb = row.coinbase_height;
    const mature = cb === undefined || cb === null
      || (Number.isSafeInteger(cb) && cb >= 0 && nextHeight - cb >= COINBASE_MATURITY);
    (mature ? spendable : immature).push(row);
  }
  return { spendable, immature };
}

// One payment spends at most UTXO_WINDOW outputs (each hybrid input carries
// an ~8.6 kB post-quantum signature and key: 47 fit under the core's
// MAX_STANDARD_TX_BYTES = 400 KiB, pinned by
// crates/gnb-wallet-wasm/tests/utxo_window.rs), so getutxos is asked for that many rows,
// and for UTXO_WIDE_WINDOW when immature coinbase outputs took part of a
// cut-short list. B2-T3: the explorer API accepts limits up to exactly
// UTXO_WIDE_WINDOW (deploy/explorer-api: GETUTXOS_MAX; its tests and
// site/tests/wallet-api-window.test.mjs keep the two equal).
export const UTXO_WINDOW = 47, UTXO_WIDE_WINDOW = 1000;

/** The coins one payment may spend in the block at `nextHeight`: the first
 *  `window` spendable rows the node lists, and the immature coinbase outputs
 *  seen. `fetchRows(limit)` resolves to { rows, truncated } from getutxos
 *  (the node lists an address's outputs in index order and sets `truncated`
 *  when it stops at the limit). When immature coinbase outputs took part of a
 *  truncated window, a `wide` one is asked for, so mature coins listed after
 *  them are found; `truncated` then says whether even that was cut short.
 *  B2-T3: if the wide request fails, the narrow result is kept (its mature
 *  coins stay spendable and `widenFailed` is set) instead of failing the
 *  whole refresh, which left the wallet with no balance and no coins. */
export async function spendableWindow(fetchRows, nextHeight, window = UTXO_WINDOW, wide = UTXO_WIDE_WINDOW) {
  let { rows, truncated } = await fetchRows(window);
  let { spendable, immature } = splitByMaturity(rows, nextHeight);
  let widenFailed = false;
  if (truncated && immature.length > 0 && wide > window) {
    try {
      const w = await fetchRows(wide);
      ({ rows, truncated } = w);
      ({ spendable, immature } = splitByMaturity(rows, nextHeight));
    } catch {
      widenFailed = true;
    }
  }
  return { spendable: spendable.slice(0, window), immature, truncated: truncated === true, listed: rows.length, widenFailed };
}

/** `fetchRows` for spendableWindow over the explorer API's getutxos:
 *  `api(method, params)` resolves to the method's `result` (throws on error). */
export function getutxosFetcher(api, address) {
  return async (limit) => {
    const r = await api("getutxos", [address, limit]);
    return { rows: Array.isArray(r.utxos) ? r.utxos : [], truncated: r.truncated === true };
  };
}

// ── What the user typed (pre-launch review) ─────────────────────────────────
/** The family of an address string as typed: "gnb" (gnb1…, v2 gnb1z/tgnb1z),
 *  "bloch" (bloch1…) or "obb". The core accepts the GnB and Bloch forms as
 *  the same script (the same key on ObenBlock) and shows its obb1 form; the
 *  page must say so before OBB is sent to a string the user may have copied
 *  from a GnB or Bloch wallet or exchange that never watches ObenBlock. */
export function addressFamily(input) {
  const s = String(input ?? "").trim().toLowerCase();
  if (s.startsWith("bloch1")) return "bloch";
  if (s.startsWith("gnb1") || s.startsWith("tgnb1")) return "gnb";
  return "obb";
}

// ── One chain per wallet session (pre-launch review) ────────────────────────
const CHAIN_HEX = /^0x[0-9a-f]{8}$/, GENESIS_HEX = /^[0-9a-f]{64}$/;
export class ChainMismatchError extends Error {}

/**
 * The chain a wallet session is bound to. The Worker stamps every answer
 * with the chain id, genesis hash and finalized checkpoint of the origin
 * that produced it (X-OBB-Chain-Id, X-OBB-Genesis, X-OBB-Finalized). The
 * first answer binds the session (it must be an ObenBlock chain id); every
 * later answer must name the same chain id and genesis, and must not report
 * a different finalized block at a height already seen. Any violation
 * breaks the session for good: every later check throws, so nothing more
 * is shown or signed until the page is reloaded.
 */
export class ChainSession {
  constructor() { this.identity = null; this.broken = null; this.finalized = new Map(); }

  /** Check the answer whose headers are `headers` (a Headers object). */
  check(headers) {
    if (this.broken) throw new ChainMismatchError(this.broken);
    const get = (n) => String(headers?.get?.(n) ?? "").trim().toLowerCase();
    const chain = get("x-obb-chain-id"), genesis = get("x-obb-genesis");
    if (!CHAIN_HEX.test(chain) || !GENESIS_HEX.test(genesis)) {
      throw new ChainMismatchError("The answer does not say which chain it comes from; it was not used.");
    }
    if (!this.identity) {
      networkOfChainId(chain);
      this.identity = { chain, genesis };
    } else if (chain !== this.identity.chain || genesis !== this.identity.genesis) {
      return this.fail(`An answer came from another chain (chain id ${chain}, genesis ${genesis.slice(0, 16)}…) than the one this session verified (${this.identity.chain}, ${this.identity.genesis.slice(0, 16)}…).`);
    }
    const m = /^(\d{1,15}):([0-9a-f]{64})$/.exec(get("x-obb-finalized"));
    if (m) {
      const height = Number(m[1]), seen = this.finalized.get(height);
      if (seen && seen !== m[2]) return this.fail(`Two answers report different finalized blocks at height ${height}: the site's nodes disagree on the chain.`);
      this.finalized.set(height, m[2]);
      if (this.finalized.size > 256) this.finalized.delete(this.finalized.keys().next().value);
    }
    return this.identity;
  }

  fail(message) {
    this.broken = `${message} Nothing more is shown or signed in this session; reload the page.`;
    throw new ChainMismatchError(this.broken);
  }
}
