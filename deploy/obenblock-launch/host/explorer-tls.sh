#!/bin/bash
# Certificate for the explorer API origin (run with sudo on each host).
#
#   explorer-tls.sh <hostname> [port] [second name ...]
#
# <hostname> is the origin the obenblock.xyz Worker calls: a DNS-only A
# record in the owner's zone (node1.obenblock.xyz, preferred) or the host's
# sslip.io name (136-244-93-186.sslip.io, fallback). Workers cannot fetch
# bare IPs. Second names (the sslip.io name while the Worker still has it in
# OBB_FALLBACK_ORIGINS) go on the same certificate. Every name must already
# resolve to an address of this host.
#
# Gets a Let's Encrypt certificate with certbot's standalone HTTP-01
# challenge, which needs port 80 for a few seconds. The hooks are passed on
# the command line, so certbot stores them in THIS certificate's renewal
# configuration only (never in the host-wide renewal-hooks directories):
#   pre:    opens 80/tcp in ufw with the comment 'ObenBlock ACME (temporary)'
#           unless 80/tcp is already allowed;
#   post:   deletes only the rules carrying that comment (another service's
#           80/tcp rule is never touched);
#   deploy: copies the renewed files to /etc/obenblock/tls (0640
#           root:obenblock-api) and restarts the explorer API.
# The certificate name is written to /etc/obenblock/tls/cert-name, so
# rollback.sh remove can delete exactly this certificate.
# Refuses when another process listens on port 80.
set -euo pipefail
die() { echo "explorer-tls.sh: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "run with sudo"
HOST=${1:-}; PORT=${2:-2087}
shift 2 2>/dev/null || shift $#
NAMES="$HOST $*"
for n in $NAMES; do
  case $n in ''|*[!a-z0-9.-]*) die "hostname '$n' must be [a-z0-9.-]" ;; esac
done
case $PORT in ''|*[!0-9]*) die "port must be a number" ;; esac
grep -q "^OBB_API_PORT=$PORT$" /etc/obenblock/explorer-api.env 2>/dev/null \
  || die "/etc/obenblock/explorer-api.env is not the letsencrypt layout on port $PORT (run deploy first)"

mine=$(ip -4 -o addr show | awk '{sub(/\/.*/, "", $4); print $4}' | tr '\n' ' ')
domains=()
for n in $NAMES; do
  resolved=$(getent ahostsv4 "$n" | awk '{print $1}' | sort -u | tr '\n' ' ')
  [ -n "$resolved" ] || die "$n does not resolve (create its DNS-only A record first)"
  ok=0
  for a in $resolved; do case " $mine " in *" $a "*) ok=1 ;; esac; done
  [ $ok -eq 1 ] || die "$n resolves to $resolved, not to an address of this host ($mine)"
  domains+=(-d "$n")
done

if ss -ltnH 'sport = :80' | grep -q .; then
  die "port 80 is in use on this host ($(ss -ltnpH 'sport = :80' | head -1)); get the certificate another way"
fi
command -v certbot >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null; }

hooks=/etc/obenblock/acme-hooks
install -d -m 755 "$hooks"
# Remove the host-wide hooks an older kit installed.
rm -f /etc/letsencrypt/renewal-hooks/pre/obenblock-acme-open.sh /etc/letsencrypt/renewal-hooks/post/obenblock-acme-close.sh \
      /etc/letsencrypt/renewal-hooks/deploy/obenblock-explorer.sh
cat > "$hooks/pre.sh" <<'EOF'
#!/bin/sh
# Open 80/tcp for the ObenBlock explorer certificate, unless already allowed.
command -v ufw >/dev/null || exit 0
ufw status | grep -Eq '^80(/tcp)?[[:space:]]+ALLOW' && exit 0
ufw allow 80/tcp comment 'ObenBlock ACME (temporary)' >/dev/null
EOF
cat > "$hooks/post.sh" <<'EOF'
#!/bin/sh
# Delete only the rules the pre hook added (by their comment).
command -v ufw >/dev/null || exit 0
ufw status numbered | grep 'ObenBlock ACME (temporary)' | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' | sort -rn |
  while read -r n; do ufw --force delete "$n" >/dev/null; done
EOF
cat > "$hooks/deploy.sh" <<'EOF'
#!/bin/sh
# Copy the renewed certificate for the ObenBlock explorer API and restart it.
set -e
install -d -m 750 -o root -g obenblock-api /etc/obenblock/tls
install -m 640 -o root -g obenblock-api "$RENEWED_LINEAGE/fullchain.pem" /etc/obenblock/tls/fullchain.pem
install -m 640 -o root -g obenblock-api "$RENEWED_LINEAGE/privkey.pem" /etc/obenblock/tls/privkey.pem
systemctl try-restart obenblock-explorer-api.service
EOF
chmod 755 "$hooks/pre.sh" "$hooks/post.sh" "$hooks/deploy.sh"

certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email \
  --preferred-challenges http --cert-name "$HOST" "${domains[@]}" --expand \
  --pre-hook "$hooks/pre.sh" --post-hook "$hooks/post.sh" --deploy-hook "$hooks/deploy.sh"

live=/etc/letsencrypt/live/$HOST
[ -s "$live/fullchain.pem" ] || die "certbot left no $live/fullchain.pem"
install -d -m 750 -o root -g obenblock-api /etc/obenblock/tls
install -m 640 -o root -g obenblock-api "$live/fullchain.pem" /etc/obenblock/tls/fullchain.pem
install -m 640 -o root -g obenblock-api "$live/privkey.pem" /etc/obenblock/tls/privkey.pem
printf '%s\n' "$HOST" > /etc/obenblock/tls/cert-name
systemctl enable obenblock-explorer-api.service >/dev/null 2>&1
systemctl restart obenblock-explorer-api.service
sleep 2
systemctl is-active obenblock-explorer-api.service
openssl x509 -noout -ext subjectAltName -enddate -in /etc/obenblock/tls/fullchain.pem 2>/dev/null | tr '\n' ' ' || true
echo
echo "origin: https://$HOST:$PORT (open to Cloudflare's IPv4 ranges only; names: $NAMES)"
