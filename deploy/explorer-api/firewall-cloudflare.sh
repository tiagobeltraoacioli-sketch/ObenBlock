#!/bin/sh
# Restrict the explorer API port to Cloudflare's edge (WAL-4), for the
# direct-TLS deployment (not needed with a Cloudflare Tunnel, where the API
# listens on loopback only).
#
#   sudo sh firewall-cloudflare.sh [PORT] [IP-LIST]
#
# Applies an nftables table `gnb_explorer` that accepts PORT/tcp only from the
# IPv4 ranges in IP-LIST (default: cloudflare-ips-v4.txt next to this script)
# and drops it from everywhere else; IPv6 to PORT is dropped. Idempotent:
# the table is replaced as a whole, and no other table is touched. Refresh
# the list from https://www.cloudflare.com/ips-v4 before applying.
#
# Persistence: run it through obenblock-explorer-firewall.service (boot, every
# nftables restart/reload) and obenblock-explorer-firewall-reapply.timer
# (every 5 minutes), never only by hand. Another filter (ufw, iptables-nft, a
# default-drop input chain in another table) must ALSO allow PORT/tcp from
# the same ranges: an accept here does not override a drop elsewhere.
set -eu
PORT=${1:-2087}
LIST=${2:-$(dirname "$0")/cloudflare-ips-v4.txt}

case "$PORT" in *[!0-9]*|'') echo "invalid port: $PORT" >&2; exit 2;; esac
[ -r "$LIST" ] || { echo "cannot read $LIST" >&2; exit 2; }

RANGES=$(grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' "$LIST" | paste -sd, -)
[ -n "$RANGES" ] || { echo "no IPv4 ranges in $LIST" >&2; exit 2; }

nft -f - <<EOF
table inet gnb_explorer
delete table inet gnb_explorer
table inet gnb_explorer {
  set cloudflare_v4 {
    type ipv4_addr
    flags interval
    elements = { $RANGES }
  }
  chain input {
    type filter hook input priority -10; policy accept;
    tcp dport $PORT ip saddr @cloudflare_v4 accept
    tcp dport $PORT drop
  }
}
EOF
echo "port $PORT/tcp: accepted only from $(echo "$RANGES" | tr ',' '\n' | wc -l) Cloudflare ranges"
