#!/bin/bash
# Install or upgrade ObenBlock mainnet on this host (Ubuntu; run with sudo).
#
#   install.sh --release <dir> --owner <obb1...> --peers "<multiaddr> ..."
#              [--miner-label <label>] [--miner-threads auto|N]
#              [--stratum-v1-port 3333] [--stratum-v2-port 3334]
#              [--witness on|off] [--share-threads N] [--node-mine on|off]
#              [--stratum-proxy on|off] [--stratum-proxy-port 3335]
#              [--explorer letsencrypt|none] [--explorer-port 2087]
#              [--explorer-key <file>] [--explorer-auth hmac|hmac+static]
#              [--dns-seed none|default]
#              [--network mainnet|regtest] [--root <dir>]
#
# Installs the release into /opt/obenblock/releases/<id> and points
# /opt/obenblock/current at it (the previous target becomes
# /opt/obenblock/previous, for rollback.sh), writes /etc/obenblock/*.env and
# the keys, installs and enables the units, and opens the ports in ufw. It
# does NOT start anything: obb-launch.sh start does, in order.
#
# On every host:
#   obenblock-node          the node, peers = the other hosts, P2P 18110
#                           public, RPC 18210 on 127.0.0.1 with the API key
#                           /etc/obenblock/rpc.key, built-in Stratum V1 3333
#                           and V2 3334 (public; V2 authority key created by
#                           the node on first start in the data dir), payout
#                           = the owner address, PoWit witness duty
#   obenblock-cpu-miner     obenblock-cpu-miner through the local V1 as
#                           <owner>.<label>, logical CPUs - 2 threads
#   obenblock-explorer-api  the read-only API for the obenblock.xyz Worker
#   obenblock-stratum       optional external job server (--stratum-proxy on)
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

RELEASE="" OWNER="" PEERS="" MINER_LABEL="cpu" MINER_THREADS=auto V1_PORT=3333 V2_PORT=3334
WITNESS=on SHARE_THREADS=1 NODE_MINE=off PROXY=off PROXY_PORT=3335
EXPLORER=none EXPLORER_PORT=2087 EXPLORER_KEY="" EXPLORER_AUTH=hmac+static DNS_SEED=none NETWORK=mainnet ROOT=""
while [ $# -gt 0 ]; do
  case $1 in
    --release) RELEASE=$2; shift 2 ;;
    --owner) OWNER=$2; shift 2 ;;
    --peers) PEERS=$2; shift 2 ;;
    --miner-label) MINER_LABEL=$2; shift 2 ;;
    --miner-threads|--threads) MINER_THREADS=$2; shift 2 ;;
    --stratum-v1-port) V1_PORT=$2; shift 2 ;;
    --stratum-v2-port) V2_PORT=$2; shift 2 ;;
    --witness) WITNESS=$2; shift 2 ;;
    --share-threads) SHARE_THREADS=$2; shift 2 ;;
    --node-mine) NODE_MINE=$2; shift 2 ;;
    --stratum-proxy) PROXY=$2; shift 2 ;;
    --stratum-proxy-port) PROXY_PORT=$2; shift 2 ;;
    --explorer) EXPLORER=$2; shift 2 ;;
    --explorer-port) EXPLORER_PORT=$2; shift 2 ;;
    --explorer-key) EXPLORER_KEY=$2; shift 2 ;;
    --explorer-auth) EXPLORER_AUTH=$2; shift 2 ;;
    --dns-seed) DNS_SEED=$2; shift 2 ;;
    --network) NETWORK=$2; shift 2 ;;
    --root) ROOT=$2; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done

# ── Validation: nothing unchecked reaches a file systemd or a shell reads ──
isnum() { case $2 in ''|*[!0-9]*) die "$1 must be a decimal number" ;; esac; }
isonoff() { case $2 in on|off) ;; *) die "$1 must be on or off" ;; esac; }
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
case $MINER_LABEL in
  ''|*[!A-Za-z0-9_-]*) die "--miner-label must be [A-Za-z0-9_-]" ;;
esac
[ ${#MINER_LABEL} -le 24 ] || die "--miner-label is longer than 24 characters"
case $MINER_THREADS in
  auto) ;;
  *) isnum --miner-threads "$MINER_THREADS" ;;
esac
isnum --stratum-v1-port "$V1_PORT"; isnum --stratum-v2-port "$V2_PORT"; isnum --stratum-proxy-port "$PROXY_PORT"
isnum --share-threads "$SHARE_THREADS"
[ "$V1_PORT" != "$V2_PORT" ] || die "Stratum V1 and V2 need different ports"
isonoff --witness "$WITNESS"; isonoff --node-mine "$NODE_MINE"; isonoff --stratum-proxy "$PROXY"
for p in $PEERS; do
  case $p in /*) ;; *) die "peer '$p' is not a multiaddr" ;; esac
  case $p in *[!A-Za-z0-9./:_-]*) die "peer '$p' has characters outside a multiaddr" ;; esac
done
case $EXPLORER in letsencrypt|none) ;; *) die "--explorer must be letsencrypt or none" ;; esac
isnum --explorer-port "$EXPLORER_PORT"
case $EXPLORER_AUTH in hmac|hmac+static) ;; *) die "--explorer-auth must be hmac or hmac+static" ;; esac
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
[ -x "$RELEASE/obenblock-cpu-miner" ] || die "release $ID has no obenblock-cpu-miner (built without tools/obenblock-stratum)"
if [ "$PROXY" = on ]; then
  [ -x "$RELEASE/obenblock-stratum" ] || die "release $ID has no obenblock-stratum for --stratum-proxy on"
  [ "$PROXY_PORT" != "$V1_PORT" ] && [ "$PROXY_PORT" != "$V2_PORT" ] || die "--stratum-proxy-port collides with the built-in servers"
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
  check_ports="$P2P $RPC $V1_PORT $V2_PORT"
  [ "$PROXY" = on ] && check_ports="$check_ports $PROXY_PORT"
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
sysuser() {
  id -u "$1" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "${2:-/nonexistent}" \
      --shell /usr/sbin/nologin "$1"
}

# ── Users ──
if [ $STAGE -eq 0 ]; then
  getent group obenblock-rpc >/dev/null || groupadd --system obenblock-rpc
  sysuser obenblock /var/lib/obenblock
  sysuser obenblock-api
  sysuser obenblock-miner
  usermod -a -G obenblock-rpc obenblock
  if [ "$PROXY" = on ]; then
    sysuser obenblock-pool
    usermod -a -G obenblock-rpc obenblock-pool
  fi
fi

# ── Files ──
install -d -m 755 "$R/opt/obenblock/releases" "$R/opt/obenblock/share" "$R/etc/systemd/system"
install -d -m 755 "$R/etc/obenblock"
install -d -m 750 "$R/var/lib/obenblock"
own obenblock:obenblock "$R/var/lib/obenblock"

DEST=$R/opt/obenblock/releases/$ID
if [ -d "$DEST" ] && ! cmp -s "$DEST/SHA256SUMS" "$RELEASE/SHA256SUMS"; then
  die "release $ID is already installed with other contents (rebuilt under the same id): rebuild (the id carries a content digest) or remove $DEST"
fi
if [ ! -d "$DEST" ]; then
  tmp=$DEST.partial
  rm -rf "$tmp"
  cp -a "$RELEASE" "$tmp"
  chmod -R go-w "$tmp"
  own -R root:root "$tmp"
  mv "$tmp" "$DEST"
fi
(cd "$DEST" && sha256sum --quiet -c SHA256SUMS) || die "installed release $DEST does not match its SHA256SUMS"
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

newsecret() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Node API key (privileged RPC: getblocktemplate/submitblock for the optional
# proxy, operator recovery calls). Generated once, never overwritten.
if [ ! -s "$R/etc/obenblock/rpc.key" ]; then
  newsecret > "$R/etc/obenblock/rpc.key.partial"
  mv "$R/etc/obenblock/rpc.key.partial" "$R/etc/obenblock/rpc.key"
fi
chmod 640 "$R/etc/obenblock/rpc.key"
own root:obenblock-rpc "$R/etc/obenblock/rpc.key"

if [ -n "$EXPLORER_KEY" ]; then
  install -m 640 "$EXPLORER_KEY" "$R/etc/obenblock/explorer-api.key"
  own root:obenblock-api "$R/etc/obenblock/explorer-api.key"
fi

# PoWit witness key (KES, gnb-cli witnesskeygen), generated once on the host
# and never copied anywhere: exactly one signer per key (PoCI §8). Its
# password is a random line in /etc/obenblock/witness.pw. The key directory
# is the node's (the duty writes the high-water file beside the key).
WKEY=/var/lib/obenblock/witness/witness-key.json
WPW=/etc/obenblock/witness.pw
if [ "$WITNESS" = on ]; then
  install -d -m 700 "$R/var/lib/obenblock/witness"
  own obenblock:obenblock "$R/var/lib/obenblock/witness"
  if [ ! -s "$R$WPW" ]; then
    (umask 077; newsecret > "$R$WPW.partial")
    mv "$R$WPW.partial" "$R$WPW"
  fi
  # root only: the node gets it through systemd LoadCredential (drop-in
  # below), in its private /run/credentials directory.
  chmod 600 "$R$WPW"
  own root:root "$R$WPW"
  install -d -m 755 "$R/etc/systemd/system/obenblock-node.service.d"
  printf '[Service]\nLoadCredential=witness.pw:%s\n' "$WPW" > "$R/etc/systemd/system/obenblock-node.service.d/witness.conf"
  if [ ! -s "$R$WKEY" ]; then
    say "generating the PoWit witness key (KES depth 12, a few minutes)"
    # As root (the password reaches the CLI in its environment only), then
    # handed to the node's user.
    GNB_WALLET_PASSWORD=$(cat "$R$WPW") "$RELEASE/obenblock-cli" --chain obenblock witnesskeygen "$R$WKEY.partial" \
      > "$R/var/lib/obenblock/witness/keygen.log" 2>&1 || die "witnesskeygen failed"
    [ -s "$R$WKEY.partial" ] || die "witnesskeygen produced no key"
    chmod 600 "$R$WKEY.partial"
    own obenblock:obenblock "$R$WKEY.partial" "$R/var/lib/obenblock/witness/keygen.log"
    mv "$R$WKEY.partial" "$R$WKEY"
  fi
  wid=$(sed -n 's/^Witness id: *//p' "$R/var/lib/obenblock/witness/keygen.log" 2>/dev/null | head -1)
  say "witness key $WKEY${wid:+ (witness id $wid)}"
else
  rm -f "$R/etc/systemd/system/obenblock-node.service.d/witness.conf"
fi

# Read by systemd only: root-owned, 0600, written with printf (no heredoc
# expansion), one validated value per line.
{
  printf 'OBB_NETWORK=%s\n' "$NETWORK"
  printf 'OBB_CARRYOVER=/opt/obenblock/share/bloch-g3-carryover.tsv\n'
  printf 'OBB_PAYOUT_ADDRESS=%s\n' "$OWNER"
  printf 'OBB_PEERS="%s"\n' "$PEERS"
  printf 'OBB_RPC_KEY_FILE=/etc/obenblock/rpc.key\n'
  printf 'OBB_DNS_SEED=%s\n' "$DNS_SEED"
  printf 'OBB_STRATUM=on\nOBB_STRATUM_V1_PORT=%s\n' "$V1_PORT"
  printf 'OBB_STRATUM_V2=on\nOBB_STRATUM_V2_PORT=%s\n' "$V2_PORT"
  printf 'OBB_STRATUM_V2_KEY=/var/lib/obenblock/stratum-v2-authority.json\n'
  printf 'OBB_STRATUM_MAX_SESSIONS=1024\nOBB_STRATUM_MAX_PER_IP=256\n'
  printf 'OBB_STRATUM_V2_MAX_SESSIONS=1024\nOBB_STRATUM_V2_MAX_PER_IP=64\n'
  printf 'OBB_NODE_MINE=%s\nOBB_MINE_THREADS=auto\n' "$NODE_MINE"
  printf 'OBB_WITNESS=%s\n' "$WITNESS"
  if [ "$WITNESS" = on ]; then
    printf 'OBB_WITNESS_KEY=%s\nOBB_WITNESS_PASSWORD_FILE=credential:witness.pw\nOBB_WITNESS_PAYOUT=%s\nOBB_SHARE_THREADS=%s\n' \
      "$WKEY" "$OWNER" "$SHARE_THREADS"
  fi
  printf 'OBB_METRICS=on\n'
} > "$R/etc/obenblock/obenblock.env.partial"
chmod 600 "$R/etc/obenblock/obenblock.env.partial"
mv "$R/etc/obenblock/obenblock.env.partial" "$R/etc/obenblock/obenblock.env"

{
  printf 'OBB_MINER_URL=stratum+tcp://127.0.0.1:%s\n' "$V1_PORT"
  printf 'OBB_MINER_USER=%s.%s\n' "$OWNER" "$MINER_LABEL"
  printf 'OBB_MINER_THREADS=%s\n' "$MINER_THREADS"
  printf 'OBB_MINER_KERNEL=auto\n'
  printf 'OBB_MINER_START_DIFF=auto\n'
} > "$R/etc/obenblock/miner.env.partial"
chmod 600 "$R/etc/obenblock/miner.env.partial"
mv "$R/etc/obenblock/miner.env.partial" "$R/etc/obenblock/miner.env"

DROPIN=$R/etc/systemd/system/obenblock-explorer-api.service.d
install -d -m 755 "$DROPIN"
if [ "$EXPLORER" = letsencrypt ]; then
  # Direct TLS for the Worker. Every request must carry the Worker's HMAC
  # (OBB_API_AUTH=hmac; hmac+static also takes the old static header, for
  # the switch: deploy/explorer-api/README.md, worker/README.md). The port
  # is filtered to Cloudflare's ranges by the nftables table of
  # obenblock-explorer-firewall.service (persistent; the drop-in requires it
  # and refuses to start the API without it) AND by ufw below.
  printf 'OBB_API_BIND=0.0.0.0\nOBB_API_PORT=%s\nOBB_API_TLS_CERT=/etc/obenblock/tls/fullchain.pem\nOBB_API_TLS_KEY=/etc/obenblock/tls/privkey.pem\nOBB_API_AUTH=%s\n' \
    "$EXPLORER_PORT" "$EXPLORER_AUTH" > "$R/etc/obenblock/explorer-api.env"
  rm -f "$DROPIN/loopback.conf"
  printf '[Unit]\nRequires=obenblock-explorer-firewall.service\nAfter=obenblock-explorer-firewall.service\n\n[Service]\nExecStartPre=+/usr/sbin/nft list table inet gnb_explorer\n' \
    > "$DROPIN/firewall.conf"
  install -d -m 755 "$R/opt/obenblock/bin"
  install -m 755 "$RELEASE/host/firewall-cloudflare.sh" "$R/opt/obenblock/bin/firewall-cloudflare.sh"
  install -m 644 "$RELEASE/share/cloudflare-ips-v4.txt" "$R/etc/obenblock/cloudflare-ips-v4.txt"
  for u in obenblock-explorer-firewall.service obenblock-explorer-firewall-reapply.service obenblock-explorer-firewall-reapply.timer; do
    sed "s|firewall-cloudflare.sh 2087 |firewall-cloudflare.sh $EXPLORER_PORT |" "$RELEASE/units/$u" > "$R/etc/systemd/system/$u"
    chmod 644 "$R/etc/systemd/system/$u"
  done
else
  printf 'OBB_API_BIND=127.0.0.1\nOBB_API_PORT=2086\nOBB_API_AUTH=%s\n' "$EXPLORER_AUTH" > "$R/etc/obenblock/explorer-api.env"
  rm -f "$DROPIN/firewall.conf"
  printf '[Service]\nIPAddressDeny=any\nIPAddressAllow=localhost\n' > "$DROPIN/loopback.conf"
fi
chmod 644 "$R/etc/obenblock/explorer-api.env"

if [ "$PROXY" = on ] && [ ! -f "$R/etc/obenblock/stratum.env" ]; then
  # Written once (the operator may tune it; a redeploy keeps it). The
  # OBB_STRATUM_* names are those of tools/obenblock-stratum (configured from
  # the environment, solo pool: every block pays OBB_STRATUM_PAYOUT_ADDRESS).
  {
    printf 'OBB_STRATUM_EXEC=obenblock-stratum\n'
    printf 'OBB_STRATUM_ARGS=\n'
    printf 'OBB_STRATUM_NETWORK=%s\n' "$NETWORK"
    printf 'OBB_STRATUM_LISTEN=0.0.0.0:%s\n' "$PROXY_PORT"
    printf 'OBB_STRATUM_RPC=127.0.0.1:%s\n' "$RPC"
    printf 'OBB_STRATUM_RPC_API_KEY_FILE=/etc/obenblock/rpc.key\n'
    printf 'OBB_STRATUM_PAYOUT_ADDRESS=%s\n' "$OWNER"
    printf 'OBB_STRATUM_METRICS=127.0.0.1:9333\n'
  } > "$R/etc/obenblock/stratum.env"
  chmod 600 "$R/etc/obenblock/stratum.env"
fi

for u in obenblock-node obenblock-cpu-miner obenblock-explorer-api; do
  install -m 644 "$RELEASE/units/$u.service" "$R/etc/systemd/system/$u.service"
done
[ "$PROXY" = on ] && install -m 644 "$RELEASE/units/obenblock-stratum.service" "$R/etc/systemd/system/obenblock-stratum.service"

if [ $STAGE -eq 1 ]; then
  say "staged release $ID under $ROOT (no users, ufw or systemctl)"
  exit 0
fi

# ── Firewall: P2P and stratum public, explorer to Cloudflare only ──
if command -v ufw >/dev/null; then
  ufw allow "$P2P/tcp" comment 'ObenBlock P2P' >/dev/null
  ufw allow "$V1_PORT/tcp" comment 'ObenBlock stratum V1' >/dev/null
  ufw allow "$V2_PORT/tcp" comment 'ObenBlock stratum V2' >/dev/null
  [ "$PROXY" = on ] && ufw allow "$PROXY_PORT/tcp" comment 'ObenBlock stratum proxy' >/dev/null
  if [ "$EXPLORER" = letsencrypt ]; then
    while read -r cidr; do
      case $cidr in [0-9]*/[0-9]*) ufw allow proto tcp from "$cidr" to any port "$EXPLORER_PORT" comment 'ObenBlock explorer (Cloudflare)' >/dev/null ;; esac
    done < "$RELEASE/share/cloudflare-ips-v4.txt"
  fi
  ufw status | grep -q '^Status: active' || say "WARNING: ufw is inactive on this host; the rules are recorded but not enforced"
else
  say "WARNING: ufw not installed; open $P2P/tcp, $V1_PORT/tcp and $V2_PORT/tcp by hand"
fi

# The explorer API refuses requests more than 60 s off: keep the clock on NTP.
if command -v timedatectl >/dev/null && [ "$(timedatectl show -p NTP --value 2>/dev/null)" = no ]; then
  timedatectl set-ntp true && say "NTP time sync turned on (timedatectl set-ntp true)"
fi

systemctl daemon-reload
systemctl enable obenblock-node.service obenblock-cpu-miner.service >/dev/null 2>&1
if [ "$EXPLORER" = letsencrypt ]; then
  command -v nft >/dev/null || die "nft (nftables) is not installed: apt-get install nftables, then run deploy again"
  systemctl enable --now obenblock-explorer-firewall.service obenblock-explorer-firewall-reapply.timer >/dev/null 2>&1 \
    || die "obenblock-explorer-firewall did not start (journalctl -u obenblock-explorer-firewall)"
  nft list table inet gnb_explorer >/dev/null || die "the nftables table inet gnb_explorer is not loaded"
  say "explorer firewall: nft table inet gnb_explorer loaded (2087 from Cloudflare only), re-applied every 5 min"
fi
if [ "$EXPLORER" = none ] || [ -s /etc/obenblock/tls/fullchain.pem ]; then
  systemctl enable obenblock-explorer-api.service >/dev/null 2>&1
else
  say "explorer API not enabled yet: run the explorer-tls step for its certificate"
fi
[ "$PROXY" = on ] && systemctl enable obenblock-stratum.service >/dev/null 2>&1
say "installed release $ID (genesis ${GENESIS:-none}); units enabled, not started"
