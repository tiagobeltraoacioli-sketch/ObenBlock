# obenblock.xyz Worker

`worker/index.js` serves the static site (`site/`) and proxies the read-only
explorer API: `/api/<method>?p=<JSON params>` goes to `/v1/<method>` on one of
the explorer origins (`deploy/explorer-api`), `/api/sendrawtransaction`
forwards a broadcast. Deploy from the repository root with `wrangler deploy`
(`wrangler.toml`: Worker `obenblock`, custom domains `obenblock.xyz` and
`www.obenblock.xyz`).

## Configuration

| Name | Kind | Meaning |
| --- | --- | --- |
| `OBB_API_KEY` | secret | Shared secret (at least 32 characters) of the Worker and every origin. The Worker signs each origin request with it (HMAC-SHA256 over method, target, timestamp, nonce, forwarded headers and body hash; the origin refuses stale timestamps and replayed nonces) and accepts only answers signed back with it. Nothing static is sent. |
| `OBB_ORIGINS` | variable (`wrangler.toml`) | The explorer origins, comma- or space-separated: `https://` host names inside `OBB_ORIGIN_ZONE` only (others are ignored), no credentials, path or query (audit WAL-2). Launch: `https://node1.obenblock.xyz:2087,https://node2.obenblock.xyz:2087,https://node3.obenblock.xyz:2087`. |
| `OBB_ORIGIN_ZONE` | variable | `obenblock.xyz`: the zone the primary origins must be named in. |
| `OBB_FALLBACK_ORIGINS` | variable | Origins used ONLY while no `OBB_ORIGINS` host is usable (the launch sslip.io names). Remove them once node1-3 answer. |
| `OBB_CHAIN_ID` | variable | `0x4f420001` (ObenBlock mainnet): every origin answer must name it. |
| `OBB_GENESIS_HASH` | variable | The genesis block hash, once known (`getblockhash 0` on a node you trust). Every answer must then name it; until it is set the origins must agree on one genesis (a tie is refused). |
| `CANONICAL_HOST` | variable | `obenblock.xyz`: page requests on `www.obenblock.xyz` get a 301 to it. `/api/*` is served on both names. |

The GnB names `GNB_ORIGINS` / `GNB_API_KEY` are no longer read.

The retired GnB pages `/wallet/` and `/explorer/` (its sidechain wallet and
older explorer) answer 301 to `/wallet` and `/explorer`; the fragment of an
old link (`#/tx/<id>`, `#watch/<address>`) is kept by the browser.

## Origins (pre-launch review)

The origins used to be identified only by sslip.io names: whoever controls
that third party's DNS could point a name at its own host, obtain a public
certificate for it, receive the shared header and answer with forged
balances and "finalized" payments. Now:

- the origins are names in the owner's zone, DNS-only (grey cloud) records
  the owner creates:

  | Name | Type | Content | Proxy |
  | --- | --- | --- | --- |
  | `node1.obenblock.xyz` | A | `136.244.93.186` | DNS only |
  | `node2.obenblock.xyz` | A | `209.250.236.240` | DNS only |
  | `node3.obenblock.xyz` | A | `152.236.5.112` | DNS only |
  | `obenblock.xyz` | CAA | `0 issue "letsencrypt.org"` | (restrict further with `accounturi=` of the ACME account the hosts use) |

- every request is HMAC-signed per request and every answer must be signed
  back over the request's nonce together with the node's chain id, genesis
  hash and finalized checkpoint. An origin that cannot sign (an impostor,
  whatever DNS or certificate it holds) or that names another chain is
  never used, and an origin whose identity changes after the health check
  is dropped on the next request;
- the Worker probes every origin (`getdaginfo`, signed both ways, at most
  every 10 s per isolate) and reads from the origins that agree on the
  finalized checkpoint (the largest group, then the highest checkpoint;
  two different checkpoints at one height with equal support are refused),
  freshest tip first. A 404 (a lagging node that does not know a fresh
  transaction yet) is asked of the others of that set before it is
  answered;
- `/api/sendrawtransaction` goes to every healthy origin of the pinned chain
  at once and succeeds when any accepts it; `X-OBB-Broadcast-Accepted: n/m`
  says how many did;
- every API answer carries `X-OBB-Chain-Id`, `X-OBB-Genesis` and
  `X-OBB-Finalized` (exposed to cross-origin readers too), and the web
  wallet binds its session to the first chain it sees
  (`site/wallet/core.js` `ChainSession`);
- `/api/originstatus` shows which origins answer, which serve reads and
  why the others do not (host names only, no secret; uncached). Monitor it:
  it is also where an expired origin certificate shows up.

## Deploying obenblock.xyz

Nothing in the repository deploys; the owner runs it from the repository
root of the release checkout. The origin protocol changed (HMAC instead of
the static `X-GnB-Key`), so roll out in this order:

1. DNS: create the three A records and the CAA record above (DNS only).
2. Each host: issue the certificate for its `nodeN.obenblock.xyz` name
   (keeping its sslip.io name as a second name during the move), install
   the new `gnb_explorer_api.py` and the firewall units, and start the API
   with `OBB_API_AUTH=hmac+static` for the switch
   (`deploy/explorer-api/README.md`, "ObenBlock mainnet"). Make sure the
   host keeps its clock on NTP (`timedatectl`): requests more than 60 s off
   are refused.
3. Worker: the origins are now `[vars]` in `wrangler.toml`, so delete the
   old secret of the same name first (a variable and a secret cannot share
   a name), keep the key, set the genesis hash once known, and deploy:

       wrangler login
       wrangler secret delete OBB_ORIGINS
       wrangler secret put OBB_API_KEY        (only if it is not set yet)
       wrangler deploy

   `OBB_API_KEY` is the content of `/etc/obenblock/explorer-api.key` (the
   same on every origin host). Set `OBB_GENESIS_HASH` in `wrangler.toml`
   (`getblockhash 0`) and redeploy as soon as it is known.
4. Check `https://obenblock.xyz/api/originstatus` (all three hosts `ok`,
   `fallback: false`), `https://obenblock.xyz/api/getnetworkinfo` (`chain_id`
   `0x4f420001`, header `X-OBB-Chain-Id`) and `https://obenblock.xyz/wallet`.
5. Each host: drop `OBB_API_AUTH=hmac+static` (the default is `hmac`),
   restart the API, and rotate `OBB_API_KEY` (new key on every host and
   `wrangler secret put OBB_API_KEY`): the old one travelled to the sslip.io
   names as a static header.
6. Once node1-3 have answered for a while, empty `OBB_FALLBACK_ORIGINS` and
   redeploy.

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
with `X-GnB-Cross-Site: 1` (and the page's `Origin` in `X-OBB-Page-Origin`),
and the explorer API charges it to one budget shared by every cross-site
read of that page origin (`GNB_API_CROSS_SITE_PER_MIN`; reads without an
`Origin` share one pool) as well as to the visitor's own. Keyed by origin, a
client forging cross-site headers drains only the pool of the origin it
names, not the one every third-party explorer depends on. Same-origin pages and non-browser clients are unchanged,
and read answers keep `access-control-allow-origin: *`.

## Origin TLS: the zone must use "Full (strict)" (audit WAL-2)

The Worker's `fetch()` to an `https://` origin goes through Cloudflare's edge,
and the edge verifies the origin's certificate **only** when the SSL/TLS
encryption mode that applies to the origin's host name is **"Full (strict)"**
(or "Strict (SSL-Only Origin Pull)"):

| Mode | Origin certificate | Consequence |
| --- | --- | --- |
| Full (strict) | verified (publicly trusted, or a Cloudflare Origin CA certificate for that host name) | required |
| Full | any certificate accepted, self-signed included | an attacker on the path between Cloudflare and a direct-TLS origin can present its own certificate and read or drop the requests and answers (with the HMAC protocol it can no longer forge an answer the Worker accepts, but it sees addresses, balances and broadcasts) |
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
recommended one for a host name inside the zone) is authenticated by the tunnel itself, but keep the zone
strict anyway: it costs nothing and covers a later direct-TLS origin.
Authenticated Origin Pulls (mTLS from Cloudflare to the origin) additionally
lets only Cloudflare connect to a direct-TLS origin; it does not authenticate
the origin to Cloudflare and so does not replace "Full (strict)".

## Tests

`node --test site/tests/*.test.mjs` (`worker.test.mjs`: origins, TTLs,
headers; `worker-origin-auth.test.mjs`: the signed origin protocol against
the real explorer API, impostors, the chain pin, finality consensus, the
fallback list and broadcast fan-out; `worker-broadcast-csrf.test.mjs`: the
broadcast route's cross-site refusals; `worker-ssl-mode.test.mjs`: the
SSL-mode check).
