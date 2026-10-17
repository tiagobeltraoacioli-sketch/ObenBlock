# Explorer API deployment

`gnb_explorer_api.py` sits between the Cloudflare Worker (`worker/index.js`)
and the node's loopback JSON-RPC. The Worker only talks to `https://` origins
listed in its `GNB_ORIGINS` variable and authenticates with the `X-GnB-Key`
shared secret, so the origin must be reachable over TLS. Two supported
layouts (audit findings WAL-2 and WAL-4):

## Users and sandboxing (audit OPS-3)

The API runs as its own system user, `gnb-api`, never as the node's `gnb`
user: it faces the internet through the Worker, and a compromise of it must
not reach the node's data dir or keys. `cloudflared` runs as `cloudflared`.
Both units carry the node unit's sandbox (no capabilities, read-only system,
private devices, kernel and proc protections, `@system-service` system-call
filter, no writable-executable memory); the API unit also limits its peers to
loopback in the tunnel layout. `systemd-analyze security` rates the units
0.9 (API), 1.1 (tunnel) and 1.5 (node). `python3 deploy/test_deploy_files.py`
(run in CI) keeps the directives, the separate users and those ratings in
place, verifies the units and checks the shell scripts with ShellCheck.

    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gnb-api
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin cloudflared

## A. Cloudflare Tunnel (recommended)

The API listens on `127.0.0.1:2086` only (the service default) and
`cloudflared` publishes it through an outbound, authenticated tunnel.
Nothing listens on a public address and no firewall rule is needed.

1. `install -m 0755 gnb_explorer_api.py /opt/gnb/bin/`
2. Shared secret: `install -m 0640 -o root -g gnb-api /dev/stdin /etc/gnb/explorer-api.key`
   (at least 32 random characters); the API refuses a group-writable or
   world-accessible key file.
3. `install -m 0644 gnb-explorer-api.service /etc/systemd/system/`
4. Create the tunnel and its DNS route (see the header of
   `cloudflared-gnb-explorer.service`), install `cloudflared-config.example.yml`
   as `/etc/cloudflared/gnb-explorer.yml` with your tunnel id and hostname,
   and install the unit.
5. `systemctl enable --now gnb-explorer-api cloudflared-gnb-explorer`
6. Add `https://<tunnel hostname>` to the Worker's `GNB_ORIGINS`
   (`wrangler secret put GNB_ORIGINS`) and the key to `GNB_API_KEY`.

## B. Direct TLS behind a Cloudflare-only firewall

Set `GNB_API_BIND=0.0.0.0`, `GNB_API_PORT=2087` (a port Cloudflare proxies
for HTTPS) and `GNB_API_TLS_CERT` / `GNB_API_TLS_KEY` (for example a
Cloudflare Origin CA certificate; files mode 0640 root:gnb-api) in the
service, remove its `IPAddressDeny=` / `IPAddressAllow=` lines, then restrict
the port to Cloudflare's edge:

    sudo sh firewall-cloudflare.sh 2087 cloudflare-ips-v4.txt

Refresh `cloudflare-ips-v4.txt` from https://www.cloudflare.com/ips-v4 first.
The API refuses to serve plain HTTP on a non-loopback address.

**The zone's SSL/TLS encryption mode must be "Full (strict)"** (audit WAL-2),
for the zone or, through a Configuration Rule, at least for the API host
name. Only in that mode does Cloudflare verify the origin's certificate (a
publicly trusted one, or a Cloudflare Origin CA certificate for that host
name). In "Full" it accepts ANY certificate, self-signed included: an
attacker on the path between Cloudflare and this host could present its own
certificate on port 2087, receive the `X-GnB-Key` secret and answer the
Worker with forged balances and UTXO values (cached at the edge for up to
the Worker's fixed TTL). "Flexible" would send everything in clear. The
Worker cannot verify the origin certificate itself, so check the setting:

    CF_API_TOKEN=... CF_ZONE_ID=... node worker/check-ssl-mode.mjs api.example.org

(`worker/README.md`; the token needs Zone Settings:Read and Config Rules:Read).
It fails unless the zone mode is "strict" and no Configuration Rule lowers
it for the API host name. Authenticated Origin Pulls (mTLS from Cloudflare
to the origin) can be added so that only Cloudflare can connect at all; it
does not replace "Full (strict)", which is what authenticates the origin.
Layout A needs none of this: the tunnel authenticates both ends.

## Limits

Per connection: `GNB_API_TIMEOUT` (per read, default 10 s) and
`GNB_API_DEADLINE` (whole connection, default 30 s). At most
`GNB_API_MAX_CONNECTIONS` (64) connections are served at once; more are
refused immediately. Requests are rate-limited per original client
(`X-GnB-Client-IP`, set by the Worker from `CF-Connecting-IP`), keyed by
address allocation (IPv4 /32, IPv6 /64, audit B2-T4):
`GNB_API_RATE_PER_MIN` reads (240) and `GNB_API_POST_PER_MIN` broadcasts (6).
A full limiter table (`GNB_API_MAX_CLIENTS`, 50,000) evicts its least
recently seen client; it never refuses a new client for being full. Only
well-formed requests are counted and forwarded. Broadcasts also share one
API-wide budget of `GNB_API_POST_BYTES_PER_MIN` transaction bytes
(2,000,000; audit B1-T10): every forwarded transaction costs the node
signature verification, so that work is bounded whatever the number of
client addresses. The node applies its own budget to anonymous
`sendrawtransaction` calls as well (`docs/RUNNING.md`). A broadcast must be
`Content-Type: application/json` and must not carry `Origin` or a cross-site
`Sec-Fetch-Site` (re-audit B2-R2-2): the body used to be parsed as JSON
whatever its type, so a cross-site "simple request" relayed by a front end
was broadcast and charged to the visitor. Such requests are answered 415 /
403 before they are read, counted or forwarded (the Worker refuses them
first, `worker/README.md`). A read the Worker marks as made by a browser page
of another site (`X-GnB-Cross-Site: 1`, trusted only with the shared key) is
charged to the visitor's own read budget and to one budget all cross-site
reads share, `GNB_API_CROSS_SITE_PER_MIN` (240; re-audit B2-R2-2): a page
that makes each of its visitors' browsers send uncached reads gets that one
budget, not one per visitor.

Run `--archive` on the nodes behind the explorer if possible: wallets verify
UTXO values against the creating transaction (`getrawtransaction`), which a
pruning node cannot serve for old outputs.

Tests: `python3 deploy/explorer-api/test_gnb_explorer_api.py` and
`python3 deploy/test_deploy_files.py`.
