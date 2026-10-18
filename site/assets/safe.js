// Safe HTML building for obenblock.xyz (audit finding WAL-3).
//
// Every page that renders API data builds its markup with the `html` tagged
// template: each interpolated value is HTML-escaped unless it is itself the
// result of `html` (or of `raw`, reserved for constant markup written in this
// repository). Arrays are joined, null/undefined/false render as nothing.
// API values are additionally type-checked with the validators below before
// they reach a template, so a forged response cannot smuggle markup, script
// URLs or CSS into attributes either.

export class Safe {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };
export const esc = (s) => String(s ?? "").replace(/[&<>"'`]/g, (c) => ESC[c]);

/** Constant, repository-authored markup only. Never pass API data. */
export const raw = (s) => new Safe(String(s));

function part(v) {
  if (v instanceof Safe) return v.s;
  if (Array.isArray(v)) return v.map(part).join("");
  if (v === null || v === undefined || v === false) return "";
  return esc(v);
}

export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += part(values[i]) + strings[i + 1];
  return new Safe(out);
}

// ── validators ────────────────────────────────────────────────────────────
export const isHex64 = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
// Syntax only: BIP350 alphabet, version/kind lengths, and BIP173 uniform case.
// Checksum/network validity belongs to the node RPC or wallet WASM codec.
// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
// ObenBlock addresses (obb1q/obb1t key hash, obb1m/obb1n policy, v2 obb/tobb)
// and their GnB aliases (gnb1…, v2 gnb/tgnb), which name the same script
// (docs/DESIGN-obenblock.md §2). Bloch's bloch1q/bloch1t strings are accepted
// only where a page converts them first (watchAddress, the explorer search).
export const isLegacyAddress = (v) => typeof v === "string" && v === v.trim()
  && /^((?:obb|gnb)1[qt][0-9a-f]{48}|(?:obb|gnb)1[mn][0-9a-f]{72})$/.test(v);
export const isAddress = (v) => isLegacyAddress(v) || (typeof v === "string" && v === v.trim()
  && (v === v.toLowerCase() || v === v.toUpperCase())
  && /^(t?(?:obb|gnb)1zq[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}|t?(?:obb|gnb)1zp[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58})$/.test(v.toLowerCase()));
/** An ObenBlock (obb1…) legacy address: the form the node and the core show. */
export const isObbAddress = (v) => isLegacyAddress(v) && v.startsWith("obb1");
/** A policy (multisig / timelock) address, legacy form, either family. */
export const isPolicyAddress = (v) => isLegacyAddress(v) && /^(?:obb|gnb)1[mn]/.test(v);

/** Resolve an alias before prefix classification or legacy identity lookups. */
/** An obb1 legacy string is returned as is; every alias (gnb1, v2) is
 *  resolved by the node's validateaddress, which answers the obb1 form. */
export async function canonicalAddress(value, api) {
  if (isObbAddress(value)) return value;
  if (!isAddress(value)) throw new Error("invalid address");
  const result = await api("validateaddress", [value]);
  if (result?.isvalid !== true || !isLegacyAddress(result.canonical_address)) throw new Error("invalid address for this network");
  return result.canonical_address;
}

/** Extract one safe watch-link component; the WASM still verifies its checksum. */
export function watchAddress(hash) {
  if (typeof hash !== "string" || !hash.startsWith("#watch/")) return "";
  const value = hash.slice(7);
  return isAddress(value) || (value === value.trim() && /^bloch1[qt][0-9a-f]{48}$/.test(value)) ? value : "";
}
export const isHex = (v) => typeof v === "string" && /^(0x)?[0-9a-f]*$/i.test(v);

/** A hex hash or "" (never markup). */
export const hex64 = (v) => (isHex64(v) ? v : "");
/** An address or "" (never markup). */
export const address = (v) => (isAddress(v) ? v : "");

/** A finite number, or NaN for anything else (numbers or numeric strings). */
export function num(v) {
  if (typeof v === "number") return Number.isFinite(v) ? v : NaN;
  if (typeof v === "string" && /^-?\d{1,30}(\.\d{1,30})?$/.test(v.trim())) return Number(v);
  return NaN;
}

/** A non-negative integer amount in base units as BigInt, or null. */
export function sats(v) {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === "string" && /^\d{1,30}$/.test(v)) return BigInt(v);
  return null;
}

/** A finite number formatted with `fn`, or an em dash. */
export const numOr = (v, fn = (n) => String(n), dash = "—") => {
  const n = num(v);
  return Number.isFinite(n) ? fn(n) : dash;
};
