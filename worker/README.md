# gnb-smh.com Worker

`worker/index.js` serves the static site (`site/`) and proxies the read-only
explorer API: `/api/<method>?p=<JSON params>` goes to `/v1/<method>` on one of
the explorer origins (`deploy/explorer-api`), `/api/sendrawtransaction`
forwards a broadcast. Deploy from the repository root with `wrangler deploy`
(`wrangler.toml`).

## Configuration

| Name | Kind | Meaning |
| --- | --- | --- |
| `GNB_ORIGINS` | secret or variable | Explorer origins, comma- or space-separated. `https://` only, no credentials, path or query (audit WAL-2); anything else is ignored, and the API answers 503 until one valid origin is set. |
| `GNB_API_KEY` | secret | Shared secret sent to the origin as `X-GnB-Key`; the explorer API refuses requests without it. |

The Worker forwards the visitor's address (`CF-Connecting-IP`) in
`X-GnB-Client-IP`, so the explorer API rate-limits per client (WAL-4). It
ignores the origin's cache headers and caches successful reads at the edge for
a fixed, short TTL per method (at most 300 s); errors are never cached and
redirects are not followed. Every response carries HSTS and a strict
Content-Security-Policy (WAL-3).

`/api/sendrawtransaction` (re-audit B2-R2-2) accepts only `POST` with
`Content-Type: application/json` from the site's own pages (a browser request
must be same-origin: `Sec-Fetch-Site` `same-origin` or `none`, and an `Origin`
header, when present, equal to the host the request was made to) or from a
non-browser client (no `Origin`, no `Sec-Fetch-Site`); anything else is
answered 415 / 403 before the body is read or forwarded. A cross-origin page
can no longer make its visitors' browsers broadcast through the site with a
CORS "simple request" (`fetch` in `no-cors` mode, `navigator.sendBeacon`, an
HTML form), which charged each broadcast to the visitor's rate-limit bucket
instead of the attacker's. Broadcast answers carry no
`access-control-allow-origin`; read answers keep `*` (public explorer data).
The explorer API refuses non-JSON and cross-site broadcasts too
(`broadcast_refusal` in `deploy/explorer-api/gnb_explorer_api.py`).

The read variant of the same trick (a page making its visitors' browsers
send uncached per-address reads such as `getutxos` with a fresh `p` each
time, each charged to that visitor's own read budget) is bounded as well: a
read a browser marks as coming from another site's page (`isCrossSite`: the
same `Sec-Fetch-Site` / `Origin` test as the broadcast route) is forwarded
with `X-GnB-Cross-Site: 1`, and the explorer API charges it to one budget
shared by every cross-site read (`GNB_API_CROSS_SITE_PER_MIN`) as well as to
the visitor's own. Same-origin pages and non-browser clients are unchanged,
and read answers keep `access-control-allow-origin: *`.

## Origin TLS: the zone must use "Full (strict)" (audit WAL-2)

The Worker's `fetch()` to an `https://` origin goes through Cloudflare's edge,
and the edge verifies the origin's certificate **only** when the SSL/TLS
encryption mode that applies to the origin's host name is **"Full (strict)"**
(or "Strict (SSL-Only Origin Pull)"):

| Mode | Origin certificate | Consequence |
| --- | --- | --- |
| Full (strict) | verified (publicly trusted, or a Cloudflare Origin CA certificate for that host name) | required |
| Full | any certificate accepted, self-signed included | an attacker on the path between Cloudflare and a direct-TLS origin can present its own certificate, receive `X-GnB-Key`, and answer with forged balances, UTXO values and explorer data (edge-cached for up to the method's TTL) |
| Flexible / Off | plain HTTP to the origin | the secret and every answer cross the network in clear |

The Worker cannot see the mode or the origin certificate, so check it with
the Cloudflare API before deploying and after any zone change:

    CF_API_TOKEN=... CF_ZONE_ID=... node worker/check-ssl-mode.mjs <origin host name>

The token needs Zone Settings:Read, Config Rules:Read and Page Rules:Read.
The script exits 1, naming the setting, unless the zone mode is strict and no
enabled Configuration Rule and no active Page Rule that can match the host
name lowers it; a setting it cannot read is a failure, never a pass.
`site/tests/worker-ssl-mode.test.mjs` tests it against a fake API.

A Cloudflare Tunnel origin (`deploy/explorer-api/README.md`, layout A, the
recommended one) is authenticated by the tunnel itself, but keep the zone
strict anyway: it costs nothing and covers a later direct-TLS origin.
Authenticated Origin Pulls (mTLS from Cloudflare to the origin) additionally
lets only Cloudflare connect to a direct-TLS origin; it does not authenticate
the origin to Cloudflare and so does not replace "Full (strict)".

## Tests

`node --test site/tests/*.test.mjs` (`worker.test.mjs`: origins, TTLs,
headers; `worker-broadcast-csrf.test.mjs`: the broadcast route's
cross-site refusals; `worker-ssl-mode.test.mjs`: the SSL-mode check).
