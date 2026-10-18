#!/bin/bash
# Install or upgrade ObenBlock mainnet on this host (Ubuntu; run with sudo).
#
#   install.sh --release <dir> --owner <obb1...> --peers "<multiaddr> ..."
#              [--threads auto|N] [--stratum] [--explorer letsencrypt|none]
#              [--explorer-port 2087] [--explorer-key <file>]
#              [--dns-seed none|default] [--network mainnet|regtest]
#              [--root <dir>]
#
# Installs the release into /opt/obenblock/releases/<id> and points
# /opt/obenblock/current at it (the previous target becomes
# /opt/obenblock/previous, for rollback.sh), writes /etc/obenblock/*.env and
# the keys, installs and enables the units, and opens the ports in ufw. It
# does NOT start anything: obb-launch.sh start does, in order.
#
# Only obenblock-* units, the obenblock* users and the paths above are
# touched. GnB (gnb-node, /opt/gnb, /var/lib/gnb) and every bloch-* unit stay
# as they are; the script refuses when a port it needs belongs to another
# process.
#
# --root <dir> stages every file under <dir> instead (no users, no
# ownership, no ufw, no systemctl): the rehearsal and the tests use it.
set -euo pipefail
die() { echo "install.sh: $*" >&2; exit 2; }
say() { echo "install.sh: $*"; }

RELEASE="" OWNER="" PEERS="" THREADS=auto STRATUM=0 EXPLORER=none EXPLORER_PORT=2087
EXPLORER_KEY="" DNS_SEED=none NETWORK=mainnet ROOT=""
while [ $# -gt 0 ]; do
  case $1 in
    --release) RELEASE=$2; shift 2 ;;
    --owner) OWNER=$2; shift 2 ;;
    --peers) PEERS=$2; shift 2 ;;
    --threads) THREADS=$2; shift 2 ;;
    --stratum) STRATUM=1; shift ;;
    --explorer) EXPLORER=$2; shift 2 ;;
    --explorer-port) EXPLORER_PORT=$2; shift 2 ;;
    --explorer-key) EXPLORER_KEY=$2; shift 2 ;;
    --dns-seed) DNS_SEED=$2; shift 2 ;;
    --network) NETWORK=$2; shift 2 ;;
    --root) ROOT=$2; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done

# ── Validation: nothing unchecked reaches a file systemd or a shell reads ──
[ -d "$RELEASE" ] || die "--release $RELEASE is not a directory"
[ -f "$RELEASE/RELEASE" ] || die "$RELEASE/RELEASE missing (not a kit release)"
case $OWNER in
  ''|*[!A-Za-z0-9]*) die "--owner must be an alphanumeric ObenBlock address" ;;
esac
case $NETWORK in
  mainnet) case $OWNER in obb1t*|obb1n*|tobb1*|obb1[!qmz]*) die "--owner is not a mainnet address" ;; obb1*) ;; *) die "--owner must start with obb1" ;; esac ;;
  regtest) case $OWNER in obb1t*|obb1n*|tobb1*) ;; *) die "--owner must be a regtest address (obb1t, obb1n, tobb1)" ;; esac ;;
  *) die "--network must be mainnet or regtest" ;;
esac
case $THREADS in
  auto) ;;
  ''|*[!0-9]*) die "--threads must be auto or a decimal number" ;;
esac
for p in $PEERS; do
  case $p in /*) ;; *) die "peer '$p' is not a multiaddr" ;; esac
  case $p in *[!A-Za-z0-9./:_-]*) die "peer '$p' has characters outside a multiaddr" ;; esac
done
case $EXPLORER in letsencrypt|none) ;; *) die "--explorer must be letsencrypt or none" ;; esac
case $EXPLORER_PORT in ''|*[!0-9]*) die "--explorer-port must be a number" ;; esac
case $DNS_SEED in none|default) ;; *) die "--dns-seed must be none or default" ;; esac
[ -z "$EXPLORER_KEY" ] || [ -f "$EXPLORER_KEY" ] || die "--explorer-key $EXPLORER_KEY not found"

ID=$(sed -n 's/^id=//p' "$RELEASE/RELEASE")
case $ID in ''|*[!A-Za-z0-9._-]*) die "bad release id '$ID'" ;; esac
GENESIS=$(sed -n 's/^genesis=//p' "$RELEASE/RELEASE")
if [ "$NETWORK" = mainnet ]; then
  case $GENESIS in
    [0-9a-f]*) [ ${#GENESIS} -eq 64 ] || die "release genesis '$GENESIS' is not a block id" ;;
    *) die "release $ID has no mainnet genesis (built from the launch placeholder)" ;;
  esac
fi
if [ "$NETWORK" = mainnet ]; then P2P=18110; RPC=18210; else P2P=18111; RPC=18211; fi

STAGE=0
if [ -n "$ROOT" ]; then
  STAGE=1
  mkdir -p "$ROOT"
  ROOT=$(cd "$ROOT" && pwd)
else
  [ "$(id -u)" -eq 0 ] || die "run with sudo (or --root <dir> to stage)"
fi
R=$ROOT

(cd "$RELEASE" && sha256sum --quiet -c SHA256SUMS) || die "release checksums do not match"

# ── Ports: free, or already ours ──
port_owner() {
  ss -ltnpH "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1
}
if [ $STAGE -eq 0 ]; then
  check_ports="$P2P $RPC"
  [ $STRATUM -eq 1 ] && check_ports="$check_ports 3333"
  [ "$EXPLORER" = letsencrypt ] && check_ports="$check_ports $EXPLORER_PORT"
  for port in $check_ports; do
    who=$(port_owner "$port")
    case $who in
      ''|obenblock|python3|obenblock-strat*) ;;
      *) die "port $port is in use by '$who'" ;;
    esac
  done
fi

own() { [ $STAGE -eq 1 ] || chown "$@"; }

# ── Users ──
if [ $STAGE -eq 0 ]; then
  getent group obenblock-rpc >/dev/null || groupadd --system obenblock-rpc
  id -u obenblock >/dev/null 2>&1 || useradd --system --home-dir /var/lib/obenblock --no-create-home \
      --shell /usr/sbin/nologin obenblock
  id -u obenblock-api >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin obenblock-api
  usermod -a -G obenblock-rpc obenblock
  if [ $STRATUM -eq 1 ]; then
    id -u obenblock-pool >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin obenblock-pool
    usermod -a -G obenblock-rpc obenblock-pool
  fi
fi

# ── Files ──
install -d -m 755 "$R/opt/obenblock/releases" "$R/opt/obenblock/share" "$R/etc/systemd/system"
install -d -m 755 "$R/etc/obenblock"
install -d -m 750 "$R/var/lib/obenblock"
own obenblock:obenblock "$R/var/lib/obenblock"

DEST=$R/opt/obenblock/releases/$ID
if [ ! -d "$DEST" ]; then
  tmp=$DEST.partial
  rm -rf "$tmp"
  cp -a "$RELEASE" "$tmp"
  chmod -R go-w "$tmp"
  own -R root:root "$tmp"
  mv "$tmp" "$DEST"
fi
cur=$(readlink "$R/opt/obenblock/current" 2>/dev/null || true)
if [ -n "$cur" ] && [ "$cur" != "releases/$ID" ]; then
  ln -sfn "$cur" "$R/opt/obenblock/previous"
fi
ln -sfn "releases/$ID" "$R/opt/obenblock/current"

SNAP=$R/opt/obenblock/share/bloch-g3-carryover.tsv
if [ ! -s "$SNAP" ]; then
  gzip -dc "$RELEASE/share/bloch-g3-carryover.tsv.gz" > "$SNAP.partial"
  chmod 644 "$SNAP.partial"
  mv "$SNAP.partial" "$SNAP"
fi

# Node API key (getblocktemplate/submitblock for the stratum proxy, operator
# recovery calls). Generated once, never overwritten.
if [ ! -s "$R/etc/obenblock/rpc.key" ]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$R/etc/obenblock/rpc.key.partial"
  mv "$R/etc/obenblock/rpc.key.partial" "$R/etc/obenblock/rpc.key"
fi
chmod 640 "$R/etc/obenblock/rpc.key"
own root:obenblock-rpc "$R/etc/obenblock/rpc.key"

if [ -n "$EXPLORER_KEY" ]; then
  install -m 640 "$EXPLORER_KEY" "$R/etc/obenblock/explorer-api.key"
  own root:obenblock-api "$R/etc/obenblock/explorer-api.key"
fi

# Read by systemd only: root-owned, 0600, written with printf (no heredoc
# expansion), one validated value per line.
{
  printf 'OBB_NETWORK=%s\n' "$NETWORK"
  printf 'OBB_CARRYOVER=/opt/obenblock/share/bloch-g3-carryover.tsv\n'
  printf 'OBB_MINER_ADDRESS=%s\n' "$OWNER"
  printf 'OBB_MINE_THREADS=%s\n' "$THREADS"
  printf 'OBB_PEERS="%s"\n' "$PEERS"
  printf 'OBB_RPC_KEY_FILE=/etc/obenblock/rpc.key\n'
  printf 'OBB_DNS_SEED=%s\n' "$DNS_SEED"
} > "$R/etc/obenblock/obenblock.env.partial"
chmod 600 "$R/etc/obenblock/obenblock.env.partial"
mv "$R/etc/obenblock/obenblock.env.partial" "$R/etc/obenblock/obenblock.env"

if [ "$EXPLORER" = letsencrypt ]; then
  printf 'GNB_API_BIND=0.0.0.0\nGNB_API_PORT=%s\nGNB_API_TLS_CERT=/etc/obenblock/tls/fullchain.pem\nGNB_API_TLS_KEY=/etc/obenblock/tls/privkey.pem\n' \
    "$EXPLORER_PORT" > "$R/etc/obenblock/explorer-api.env"
  rm -f "$R/etc/systemd/system/obenblock-explorer-api.service.d/loopback.conf"
else
  printf 'GNB_API_BIND=127.0.0.1\nGNB_API_PORT=2086\n' > "$R/etc/obenblock/explorer-api.env"
  install -d -m 755 "$R/etc/systemd/system/obenblock-explorer-api.service.d"
  printf '[Service]\nIPAddressDeny=any\nIPAddressAllow=localhost\n' \
    > "$R/etc/systemd/system/obenblock-explorer-api.service.d/loopback.conf"
fi
chmod 644 "$R/etc/obenblock/explorer-api.env"

if [ $STRATUM -eq 1 ] && [ ! -f "$R/etc/obenblock/stratum.env" ]; then
  # Written once (the operator may tune it; a redeploy keeps it). The
  # OBB_STRATUM_* names are those of tools/obenblock-stratum (configured from
  # the environment, solo pool: every block pays OBB_STRATUM_PAYOUT_ADDRESS).
  stratum_exec=$(sed -n 's/^stratum=//p' "$RELEASE/RELEASE")
  {
    printf 'OBB_STRATUM_EXEC=%s\n' "${stratum_exec:-obenblock-stratum}"
    printf 'OBB_STRATUM_ARGS=\n'
    printf 'OBB_STRATUM_NETWORK=%s\n' "$NETWORK"
    printf 'OBB_STRATUM_LISTEN=0.0.0.0:3333\n'
    printf 'OBB_STRATUM_RPC=127.0.0.1:%s\n' "$RPC"
    printf 'OBB_STRATUM_RPC_API_KEY_FILE=/etc/obenblock/rpc.key\n'
    printf 'OBB_STRATUM_PAYOUT_ADDRESS=%s\n' "$OWNER"
    printf 'OBB_STRATUM_METRICS=127.0.0.1:9333\n'
  } > "$R/etc/obenblock/stratum.env"
  chmod 600 "$R/etc/obenblock/stratum.env"
fi

install -m 644 "$RELEASE/units/obenblock-node.service" "$R/etc/systemd/system/obenblock-node.service"
install -m 644 "$RELEASE/units/obenblock-explorer-api.service" "$R/etc/systemd/system/obenblock-explorer-api.service"
[ $STRATUM -eq 1 ] && install -m 644 "$RELEASE/units/obenblock-stratum.service" "$R/etc/systemd/system/obenblock-stratum.service"

if [ $STAGE -eq 1 ]; then
  say "staged release $ID under $ROOT (no users, ufw or systemctl)"
  exit 0
fi

# ── Firewall: P2P public, stratum public on its host, explorer to Cloudflare ──
if command -v ufw >/dev/null; then
  ufw allow "$P2P/tcp" comment 'ObenBlock P2P' >/dev/null
  [ $STRATUM -eq 1 ] && ufw allow 3333/tcp comment 'ObenBlock stratum' >/dev/null
  if [ "$EXPLORER" = letsencrypt ]; then
    while read -r cidr; do
      case $cidr in [0-9]*/[0-9]*) ufw allow proto tcp from "$cidr" to any port "$EXPLORER_PORT" comment 'ObenBlock explorer (Cloudflare)' >/dev/null ;; esac
    done < "$RELEASE/share/cloudflare-ips-v4.txt"
  fi
  ufw status | grep -q '^Status: active' || say "WARNING: ufw is inactive on this host; the rules are recorded but not enforced"
else
  say "WARNING: ufw not installed; open $P2P/tcp (and 3333/tcp on the stratum host) by hand"
fi

systemctl daemon-reload
systemctl enable obenblock-node.service >/dev/null 2>&1
if [ "$EXPLORER" = none ] || [ -s /etc/obenblock/tls/fullchain.pem ]; then
  systemctl enable obenblock-explorer-api.service >/dev/null 2>&1
else
  say "explorer API not enabled yet: run the explorer-tls step for its certificate"
fi
[ $STRATUM -eq 1 ] && systemctl enable obenblock-stratum.service >/dev/null 2>&1
say "installed release $ID (genesis ${GENESIS:-none}); units enabled, not started"
