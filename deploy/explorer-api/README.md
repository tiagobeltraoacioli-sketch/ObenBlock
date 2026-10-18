# Explorer API deployment

`gnb_explorer_api.py` sits between the Cloudflare Worker (`worker/index.js`)
and the node's loopback JSON-RPC. The Worker only talks to `https://` origins
listed in its `OBB_ORIGINS` (or `GNB_ORIGINS`) variable and authenticates
with the `X-GnB-Key` shared secret, so the origin must be reachable over TLS.
Two supported layouts (audit findings WAL-2 and WAL-4) follow the ObenBlock
section.

## ObenBlock mainnet (obenblock.xyz)

The same program serves ObenBlock (`OBB_CHAIN=obenblock`, the default) and
GnB (`OBB_CHAIN=gnb`). Every `GNB_*` variable below may also be written
`OBB_*`, which wins. On ObenBlock it:

- reads the node's RPC on `127.0.0.1:18210` (DESIGN-obenblock §2);
- accepts `obb1q`/`obb1t`/`obb1m`/`obb1n` and v2 `obb1z`/`tobb1z` addresses,
  and the GnB and Bloch forms of the same script, and shows every legacy
  `gnb1…` string in an answer as its `obb1…` form;
- adds SHA-256d fields: `difficulty` on Bitcoin's scale (1 = bits
  `0x1d00ffff`, the pow limit), `pow: "sha256d"` and `pow_hash` (the block id
  in the byte order Bitcoin tools display; `hash` stays the lookup key);
- adds PoWit finality: `finality` (`finalized` / `pending` / `off-chain`) on
  blocks, chain pages, transactions and address history, from the finalized
  checkpoint of the node's `getpowitinfo`, and `finalized_height`,
  `finalized_hash`, `justified_height` on `getdaginfo`; `getfinalityinfo` is
  served too.

Unit: `obenblock-explorer-api.service` (user `obenblock-api`, after
`obenblock-node.service`). The launch layout is direct TLS behind the
Cloudflare-only firewall (layout B), because Cloudflare Workers cannot fetch a
bare IP address: each host is named by its sslip.io host name, which resolves
to the address written in it, and gets a Let's Encrypt certificate for it.

| Host | Origin for `OBB_ORIGINS` |
| --- | --- |
| 136.244.93.186 | `https://136-244-93-186.sslip.io:2087` |
| 209.250.236.240 | `https://209-250-236-240.sslip.io:2087` |
| 152.236.5.112 | `https://152-236-5-112.sslip.io:2087` |

On each host (as root; the owner or the launch kit runs this, nothing here
is run by the repository):

    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin obenblock-api
    install -d -m 0755 /opt/obenblock/bin /etc/obenblock
    install -m 0755 gnb_explorer_api.py /opt/obenblock/bin/
    gunzip -c ../../genesis/bloch-g3-carryover.tsv.gz > /opt/obenblock/carryover.tsv
    install -m 0640 -o root -g obenblock-api /dev/stdin /etc/obenblock/explorer-api.key   # the shared secret, >= 32 chars
    install -m 0644 obenblock-explorer-api.service /etc/systemd/system/
    install -d /etc/systemd/system/obenblock-explorer-api.service.d
    install -m 0644 obenblock-explorer-api.tls.conf.example /etc/systemd/system/obenblock-explorer-api.service.d/tls.conf

Certificate (HTTP-01 needs port 80 reachable while it is issued; the
firewall script only filters the API port):

    certbot certonly --standalone -d 136-244-93-186.sslip.io \
      --deploy-hook 'install -m 0640 -o root -g obenblock-api $RENEWED_LINEAGE/fullchain.pem /etc/obenblock/explorer-api.crt && install -m 0640 -o root -g obenblock-api $RENEWED_LINEAGE/privkey.pem /etc/obenblock/explorer-api.tls.key && systemctl restart obenblock-explorer-api'

Then `sudo sh firewall-cloudflare.sh 2087 cloudflare-ips-v4.txt` (refresh
the list from https://www.cloudflare.com/ips-v4 first) and
`systemctl enable --now obenblock-explorer-api`. Check from the host:
`curl -s -H "x-gnb-key: $(cat /etc/obenblock/explorer-api.key)" https://136-244-93-186.sslip.io:2087/v1/health`
(answers only from a Cloudflare address once the firewall is on; test
before applying it, or through the Worker). The Worker side is
`worker/README.md`.

## Users and sandboxing (audit OPS-3)

The API runs as its own system user, `gnb-api` (ObenBlock: `obenblock-api`),
never as the node's `gnb` (`obenblock`) user: it faces the internet through the Worker, and a compromise of it must
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

Tests: `python3 deploy/explorer-api/test_gnb_explorer_api.py`,
`python3 deploy/explorer-api/test_obenblock_explorer_api.py`,
`python3 deploy/explorer-api/test_address_v2.py` and
`python3 deploy/test_deploy_files.py`.
