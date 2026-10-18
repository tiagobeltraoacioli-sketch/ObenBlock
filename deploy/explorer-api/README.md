# Explorer API deployment

`gnb_explorer_api.py` sits between the Cloudflare Worker (`worker/index.js`)
and the node's loopback JSON-RPC. The Worker only talks to `https://` origins
listed in its `OBB_ORIGINS` variable (host names inside the owner's zone;
`OBB_FALLBACK_ORIGINS` only while none of them is usable), so the origin must
be reachable over TLS.

Authentication (pre-launch review): every request carries `X-OBB-Ts`,
`X-OBB-Nonce` and `X-OBB-Auth`, an HMAC-SHA256 with the shared secret over
the method, the request target, the timestamp, the nonce, the forwarded
headers (`X-GnB-Client-IP`, `X-GnB-Cross-Site`, `X-OBB-Page-Origin`,
`X-OBB-Probe`) and the body's SHA-256 (`X-OBB-Body-SHA256`). A timestamp more
than `OBB_API_AUTH_SKEW` (60) seconds from the host's clock, a nonce already
seen, or a body that does not match its hash is answered 403. Every answer to
a signed request carries `X-OBB-Chain-Id`, `X-OBB-Genesis` and
`X-OBB-Finalized` (the node's `getnetworkinfo` chain id, `getblockhash 0` and
PoWit finalized checkpoint) and `X-OBB-Resp-Auth`, an HMAC over the request's
nonce, the status, those three values and the body's hash, which the Worker
verifies before it uses the answer. The static `X-GnB-Key` header is accepted
only with `OBB_API_AUTH=hmac+static` (the GnB default; on ObenBlock use it only
during the switch, `worker/README.md` "Deploying obenblock.xyz"). Keep the
host on NTP. Two supported layouts (audit findings WAL-2 and WAL-4) follow the
ObenBlock section.

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
bare IP address: each host is named inside the owner's zone by a DNS-only
(grey cloud) record and gets a Let's Encrypt certificate for that name.

| Host | DNS record (DNS only) | Origin for `OBB_ORIGINS` | Fallback (`OBB_FALLBACK_ORIGINS`) |
| --- | --- | --- | --- |
| 136.244.93.186 | `node1.obenblock.xyz A 136.244.93.186` | `https://node1.obenblock.xyz:2087` | `https://136-244-93-186.sslip.io:2087` |
| 209.250.236.240 | `node2.obenblock.xyz A 209.250.236.240` | `https://node2.obenblock.xyz:2087` | `https://209-250-236-240.sslip.io:2087` |
| 152.236.5.112 | `node3.obenblock.xyz A 152.236.5.112` | `https://node3.obenblock.xyz:2087` | `https://152-236-5-112.sslip.io:2087` |

Also add `obenblock.xyz CAA 0 issue "letsencrypt.org"` (optionally with
`; accounturi=<the hosts' ACME account URI>`), so no other CA issues for the
zone. The sslip.io names sit in a third party's DNS: with the HMAC protocol an
impostor there cannot answer for an origin, but it can deny service, so the
Worker uses them only while no in-zone origin is usable.

On each host (as root; the owner or the launch kit runs this, nothing here
is run by the repository; `nodeN` is the host's name from the table):

    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin obenblock-api
    install -d -m 0755 /opt/obenblock/bin /etc/obenblock
    install -m 0755 gnb_explorer_api.py firewall-cloudflare.sh /opt/obenblock/bin/
    install -m 0644 cloudflare-ips-v4.txt /etc/obenblock/
    gunzip -c ../../genesis/bloch-g3-carryover.tsv.gz > /opt/obenblock/carryover.tsv
    install -m 0640 -o root -g obenblock-api /dev/stdin /etc/obenblock/explorer-api.key   # the shared secret, >= 32 chars
    install -m 0644 obenblock-explorer-api.service obenblock-explorer-firewall.service \
      obenblock-explorer-firewall-reapply.service obenblock-explorer-firewall-reapply.timer /etc/systemd/system/
    install -d /etc/systemd/system/obenblock-explorer-api.service.d
    install -m 0644 obenblock-explorer-api.tls.conf.example /etc/systemd/system/obenblock-explorer-api.service.d/tls.conf

Certificate (HTTP-01: port 80 must stay reachable from the Internet for every
renewal, not only the first issuance; the firewall table only filters the API
port, but check that no other filter or web server takes port 80):

    certbot certonly --standalone -d nodeN.obenblock.xyz -d <ip-with-dashes>.sslip.io \
      --deploy-hook 'install -m 0640 -o root -g obenblock-api $RENEWED_LINEAGE/fullchain.pem /etc/obenblock/explorer-api.crt && install -m 0640 -o root -g obenblock-api $RENEWED_LINEAGE/privkey.pem /etc/obenblock/explorer-api.tls.key && systemctl restart obenblock-explorer-api'

(drop the sslip.io name at the next issuance once the Worker no longer uses
the fallback list). Watch the expiry: `https://obenblock.xyz/api/originstatus`
shows an origin whose certificate expired as not `ok`, and on the host
`openssl x509 -checkend 1209600 -noout -in /etc/obenblock/explorer-api.crt`
fails 14 days before it.

Firewall (pre-launch review: a table loaded once with `nft -f` disappears at
reboot and on every `systemctl restart nftables`, whose stock
`/etc/nftables.conf` starts with `flush ruleset`): refresh
`/etc/obenblock/cloudflare-ips-v4.txt` from https://www.cloudflare.com/ips-v4,
then

    systemctl daemon-reload
    systemctl enable --now obenblock-explorer-firewall obenblock-explorer-firewall-reapply.timer
    nft list table inet gnb_explorer

`obenblock-explorer-firewall.service` applies only the table
`inet gnb_explorer` (atomically, idempotently) at boot before the network,
again after every restart or reload of `nftables.service`, and the timer
re-applies it every 5 minutes. The API's TLS drop-in requires that unit and
runs `nft list table inet gnb_explorer` before it starts, so it never listens
on 0.0.0.0 without the table. If ufw or another filter with a default-drop
input chain is active, it must also allow 2087/tcp from the same ranges
(`ufw allow proto tcp from <range> to any port 2087` per range): an accept in
this table does not override a drop in another one.

Then `systemctl enable --now obenblock-explorer-api`. Check from the host
(the API refuses unsigned requests, so use the Worker, or sign one with the
test helper `signed()` in `test_gnb_explorer_api.py`):
`curl -s https://obenblock.xyz/api/originstatus`. The Worker side is
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
6. Add `https://<tunnel hostname>` (a name inside the zone) to the Worker's
   `OBB_ORIGINS` (`wrangler.toml`) and the key to `OBB_API_KEY`
   (`wrangler secret put OBB_API_KEY`).

## B. Direct TLS behind a Cloudflare-only firewall

Set `GNB_API_BIND=0.0.0.0`, `GNB_API_PORT=2087` (a port Cloudflare proxies
for HTTPS) and `GNB_API_TLS_CERT` / `GNB_API_TLS_KEY` (for example a
Cloudflare Origin CA certificate; files mode 0640 root:gnb-api) in the
service, remove its `IPAddressDeny=` / `IPAddressAllow=` lines, then restrict
the port to Cloudflare's edge persistently (ObenBlock:
`obenblock-explorer-firewall.service`, above; a one-off run of
`sudo sh firewall-cloudflare.sh 2087 cloudflare-ips-v4.txt` does not survive a
reboot or an nftables restart). The firewall only narrows who can connect:
any Cloudflare customer's Worker comes from the same ranges, so what
authenticates the Worker is the per-request HMAC.

Refresh `cloudflare-ips-v4.txt` from https://www.cloudflare.com/ips-v4 first.
The API refuses to serve plain HTTP on a non-loopback address.

**The zone's SSL/TLS encryption mode must be "Full (strict)"** (audit WAL-2),
for the zone or, through a Configuration Rule, at least for the API host
name. Only in that mode does Cloudflare verify the origin's certificate (a
publicly trusted one, or a Cloudflare Origin CA certificate for that host
name). In "Full" it accepts ANY certificate, self-signed included: an
attacker on the path between Cloudflare and this host could present its own
certificate on port 2087 and read or drop every request and answer (it can
no longer forge an answer the Worker accepts without the shared key, which
the HMAC protocol never sends). "Flexible" would send everything in clear. The
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
of another site (`X-GnB-Cross-Site: 1`, trusted only on signed requests) is
charged to the visitor's own read budget and to one budget shared by all
cross-site reads of the same page origin (`X-OBB-Page-Origin`; reads without
an `Origin` share one pool), `GNB_API_CROSS_SITE_PER_MIN` (240; re-audit
B2-R2-2): a page that makes each of its visitors' browsers send uncached
reads gets that one budget, not one per visitor, and a client that forges
the headers only drains the pool of the origin it names. The Worker's own
health probes (`X-OBB-Probe: 1`, signed; `getdaginfo` and `health` only) are
not charged to any client budget.

Run `--archive` on the nodes behind the explorer if possible: wallets verify
UTXO values against the creating transaction (`getrawtransaction`), which a
pruning node cannot serve for old outputs.

Tests: `python3 deploy/explorer-api/test_gnb_explorer_api.py`,
`python3 deploy/explorer-api/test_obenblock_explorer_api.py`,
`python3 deploy/explorer-api/test_address_v2.py` and
`python3 deploy/test_deploy_files.py`.
