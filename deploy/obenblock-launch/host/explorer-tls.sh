#!/bin/bash
# Certificate for the explorer API origin (run with sudo on each host).
#
#   explorer-tls.sh <hostname> [port]
#
# <hostname> is the origin the obenblock.xyz Worker calls, for example
# 136-244-93-186.sslip.io (Workers cannot fetch bare IPs). Gets a Let's
# Encrypt certificate with certbot's standalone HTTP-01 challenge, which
# needs port 80 for a few seconds: the script opens 80/tcp in ufw only for
# the challenge and closes it again, and installs renewal hooks that do the
# same. The certificate is copied to /etc/obenblock/tls (0640
# root:obenblock-api) and the explorer API is enabled and restarted.
# Refuses when another process listens on port 80.
set -euo pipefail
die() { echo "explorer-tls.sh: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "run with sudo"
HOST=${1:-}; PORT=${2:-2087}
case $HOST in ''|*[!a-z0-9.-]*) die "hostname must be [a-z0-9.-]" ;; esac
case $PORT in ''|*[!0-9]*) die "port must be a number" ;; esac
grep -q "^GNB_API_PORT=$PORT$" /etc/obenblock/explorer-api.env 2>/dev/null \
  || die "/etc/obenblock/explorer-api.env is not the letsencrypt layout on port $PORT (run deploy first)"

if ss -ltnH 'sport = :80' | grep -q .; then
  die "port 80 is in use on this host ($(ss -ltnpH 'sport = :80' | head -1)); get the certificate another way"
fi
command -v certbot >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null; }

hooks=/etc/letsencrypt/renewal-hooks
install -d -m 755 "$hooks/pre" "$hooks/post" "$hooks/deploy"
printf '#!/bin/sh\ncommand -v ufw >/dev/null && ufw allow 80/tcp comment "ObenBlock ACME (temporary)" >/dev/null || true\n' > "$hooks/pre/obenblock-acme-open.sh"
printf '#!/bin/sh\ncommand -v ufw >/dev/null && ufw --force delete allow 80/tcp >/dev/null 2>&1 || true\n' > "$hooks/post/obenblock-acme-close.sh"
cat > "$hooks/deploy/obenblock-explorer.sh" <<EOF
#!/bin/sh
# Copy the renewed certificate for the ObenBlock explorer API and restart it.
set -e
case "\$RENEWED_DOMAINS" in *$HOST*) ;; *) exit 0 ;; esac
install -d -m 750 -o root -g obenblock-api /etc/obenblock/tls
install -m 640 -o root -g obenblock-api "\$RENEWED_LINEAGE/fullchain.pem" /etc/obenblock/tls/fullchain.pem
install -m 640 -o root -g obenblock-api "\$RENEWED_LINEAGE/privkey.pem" /etc/obenblock/tls/privkey.pem
systemctl try-restart obenblock-explorer-api.service
EOF
chmod 755 "$hooks/pre/obenblock-acme-open.sh" "$hooks/post/obenblock-acme-close.sh" "$hooks/deploy/obenblock-explorer.sh"

certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email \
  --preferred-challenges http -d "$HOST" \
  --pre-hook "$hooks/pre/obenblock-acme-open.sh" --post-hook "$hooks/post/obenblock-acme-close.sh"

live=/etc/letsencrypt/live/$HOST
[ -s "$live/fullchain.pem" ] || die "certbot left no $live/fullchain.pem"
install -d -m 750 -o root -g obenblock-api /etc/obenblock/tls
install -m 640 -o root -g obenblock-api "$live/fullchain.pem" /etc/obenblock/tls/fullchain.pem
install -m 640 -o root -g obenblock-api "$live/privkey.pem" /etc/obenblock/tls/privkey.pem
systemctl enable obenblock-explorer-api.service >/dev/null 2>&1
systemctl restart obenblock-explorer-api.service
sleep 2
systemctl is-active obenblock-explorer-api.service
echo "origin: https://$HOST:$PORT (open to Cloudflare's IPv4 ranges only)"
