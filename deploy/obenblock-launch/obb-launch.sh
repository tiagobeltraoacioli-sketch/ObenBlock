#!/bin/bash
# ObenBlock mainnet launch kit: run from the Mac, one step at a time.
#
#   obb-launch.sh preflight              tools, config, hosts (read-only)
#   obb-launch.sh genesis [--yes] [--full-tests]
#                                        mine the mainnet genesis at LAUNCH_TS
#                                        (or now) on BUILD_HOST, write it into
#                                        SRC_DIR, run the genesis tests
#   obb-launch.sh genesis --rehearsal    the same on a scratch copy at the
#                                        documented rehearsal time; SRC_DIR is
#                                        not touched
#   obb-launch.sh build [--allow-placeholder]
#                                        release binaries + SHA256SUMS on
#                                        BUILD_HOST, tarball to state/dist
#   obb-launch.sh deploy [host ...]      install the release on the hosts
#                                        (units enabled, nothing started)
#   obb-launch.sh explorer-tls [host ...]
#                                        Let's Encrypt certificate for
#                                        <ip-with-dashes>.sslip.io, API start
#   obb-launch.sh start [host ...]       start the nodes (first host first),
#                                        then the explorer API and stratum
#   obb-launch.sh verify [host ...]      status, peers, tip, miner threads,
#                                        exactly one node process per host
#   obb-launch.sh logs <host> [lines]    the node's journal
#   obb-launch.sh stop [host ...]        stop and disable (data kept)
#   obb-launch.sh rollback [host ...]    back to the previous release
#   obb-launch.sh remove [host ...]      uninstall; files moved aside
#
# Configuration: kit.conf next to this script (kit.conf.example). The steps
# and what to check after each are in LAUNCH-RUNBOOK.md. Nothing here touches
# GnB's gnb-node or any bloch-* unit.
set -euo pipefail
KIT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
. "$KIT_DIR/lib/common.sh"

REHEARSAL_TS=1792281600

usage() { sed -n 2,28p "$0"; exit 64; }

push_kit() {
  local h=$1
  kit_run "$h" "rm -rf ~/$BUILD_DIR/kit && mkdir -p ~/$BUILD_DIR/kit"
  rsync -az --delete -e "ssh ${KIT_SSH_OPTS[*]} -i $SSH_KEY" \
    --exclude /state --exclude /kit.conf "$KIT_DIR/" "$SSH_USER@$h:$BUILD_DIR/kit/"
}

latest_release() {
  local f
  f=$(ls -t "$STATE_DIR"/dist/obenblock-release-*.tar.gz 2>/dev/null | head -1 || true)
  [ -n "$f" ] || kit_die "no release in $STATE_DIR/dist: run the build step"
  printf '%s' "$f"
}

step_preflight() {
  local h
  for t in ssh scp rsync expect python3; do kit_need "$t"; done
  kit_src_check
  kit_log "source: $SRC_DIR ($(git -C "$SRC_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo 'not a git checkout'))"
  kit_log "genesis in source: $(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$SRC_DIR")"
  kit_check_address "$OWNER_ADDRESS" mainnet
  [ -f "$SSH_KEY" ] || kit_die "SSH key $SSH_KEY not found"
  for h in $HOSTS; do
    kit_log "== $h"
    kit_run "$h" 'echo "host=$(hostname) nproc=$(nproc) mem_gb=$(free -g | awk "/^Mem:/{print \$2}") disk_free=$(df -h / | awk "NR==2{print \$4}")"
sudo -n true 2>/dev/null && echo "sudo=passwordless" || { sudo -v && echo "sudo=password-ok"; }
echo "gnb-node=$(systemctl is-active gnb-node 2>/dev/null) enabled=$(systemctl is-enabled gnb-node 2>/dev/null)"
echo "bloch-active-units=$(systemctl list-units --type=service --state=active --no-legend "bloch-*" 2>/dev/null | wc -l)"
echo "obenblock-node=$(systemctl is-active obenblock-node 2>/dev/null)"
echo "gnb-processes=$(pgrep -c -x gnb || true) obenblock-processes=$(pgrep -c -x obenblock || true)"
for p in 80 18110 18210 3333 2087; do o=$(sudo ss -ltnpH "sport = :$p" | head -1); [ -n "$o" ] && echo "port $p in use: $o"; done
echo "ufw: $(sudo ufw status | head -1)"
command -v python3 >/dev/null && echo "python3=$(python3 --version 2>&1)" || echo "python3=MISSING"
ls -d /opt/obenblock /var/lib/obenblock /etc/obenblock 2>/dev/null | sed "s/^/existing: /" || true' | tr -d '\r'
  done
  kit_log "preflight done (read-only)"
}

step_genesis() {
  local yes=0 full="" rehearsal=0 a
  for a in "$@"; do
    case $a in --yes) yes=1 ;; --full-tests) full=--full-tests ;; --rehearsal) rehearsal=1 ;; *) kit_die "genesis: unknown option $a" ;; esac
  done
  kit_src_check
  local src=$SRC_DIR ts bdir=$BUILD_DIR tag=mainnet
  if [ $rehearsal -eq 1 ]; then
    ts=$REHEARSAL_TS; tag=rehearsal
    src=$STATE_DIR/rehearsal-src
    rm -rf "$src"; mkdir -p "$src"
    rsync -a --exclude /target --exclude /.git "$SRC_DIR/" "$src/"
    bdir=$BUILD_DIR-rehearsal
    kit_log "REHEARSAL: scratch copy $src, timestamp $ts (the documented rehearsal; not the mainnet genesis)"
  else
    ts=${LAUNCH_TS:-$(date -u +%s)}
    [ "$(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$src")" = placeholder ] \
      || kit_die "SRC_DIR already has a mainnet genesis: $(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$src")"
    local now; now=$(date -u +%s)
    if [ "$ts" -gt $((now + 600)) ]; then
      kit_log "WARNING: LAUNCH_TS is $(( (ts - now) / 60 )) min in the future: no block can be mined before LAUNCH_TS - 600 s"
    fi
    kit_log "MAINNET genesis at $ts = $(date -u -r "$ts" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -u -d "@$ts")"
    if [ $yes -eq 0 ]; then
      printf 'Type MINE to mine the real mainnet genesis into %s: ' "$src"
      read -r answer
      [ "$answer" = MINE ] || kit_die "not confirmed"
    fi
  fi
  local saved=$SRC_DIR saved_bd=$BUILD_DIR
  SRC_DIR=$src BUILD_DIR=$bdir
  kit_sync_src
  push_kit "$BUILD_HOST"
  local log="$STATE_DIR/logs/genesis-$tag-$ts.log"
  kit_run "$BUILD_HOST" "$(kit_cargo_env); bash ~/$bdir/kit/host/genesis-build.sh ~/$bdir/src $ts $full" 2>&1 | tee "$log"
  local f
  for f in crates/gnb-crypto/src/core/genesis.rs reference/obb_genesis.py reference/obb_genesis_vectors.json docs/OBENBLOCK-GENESIS.md; do
    kit_get "$BUILD_HOST" "$bdir/src/$f" "$src/$f"
  done
  kit_get "$BUILD_HOST" "$bdir/src/genesis-mine.log" "$STATE_DIR/logs/genesis-mine-$tag-$ts.log"
  kit_get "$BUILD_HOST" "$bdir/src/genesis-result.env" "$STATE_DIR/genesis-$tag.env"
  SRC_DIR=$saved BUILD_DIR=$saved_bd
  local st; st=$(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$src")
  case $st in launched*) ;; *) kit_die "the source did not come back launched ($st)" ;; esac
  # shellcheck source=/dev/null
  . "$STATE_DIR/genesis-$tag.env"
  echo
  echo "GENESIS ($tag): timestamp $GENESIS_TIMESTAMP version $GENESIS_VERSION nonce $GENESIS_NONCE"
  echo "GENESIS BLOCK ID (display order): $GENESIS_HASH"
  echo "GENESIS BLOCK ID (raw, getblockhash 0): $GENESIS_HASH_RAW"
  if [ $rehearsal -eq 0 ]; then
    echo
    echo "Written into $src (not committed). Review, then commit:"
    echo "  git -C $src add crates/gnb-crypto/src/core/genesis.rs reference/obb_genesis.py reference/obb_genesis_vectors.json docs/OBENBLOCK-GENESIS.md"
    echo "  git -C $src -c user.name=gnb-smh -c user.email=gnb-smh@proton.me commit -m 'obenblock: mainnet genesis $GENESIS_HASH'"
  fi
}

step_build() {
  local allow="${1:-}"
  kit_src_check
  local label
  label=$(git -C "$SRC_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo nogit)
  if [ -n "$(git -C "$SRC_DIR" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
    label="$label-dirty"
    kit_log "WARNING: $SRC_DIR has uncommitted changes; the release is labelled $label"
  fi
  kit_sync_src
  push_kit "$BUILD_HOST"
  local log="$STATE_DIR/logs/build-$label.log"
  kit_run "$BUILD_HOST" "$(kit_cargo_env); bash ~/$BUILD_DIR/kit/host/release-build.sh ~/$BUILD_DIR/src ~/$BUILD_DIR/dist $label $allow" 2>&1 | tee "$log"
  local tarball
  tarball=$(sed -n 's/^RELEASE_TARBALL=//p' "$log" | tail -1)
  [ -n "$tarball" ] || kit_die "the build printed no tarball (see $log)"
  kit_get "$BUILD_HOST" "$tarball" "$STATE_DIR/dist/"
  kit_get "$BUILD_HOST" "$tarball.sha256" "$STATE_DIR/dist/"
  (cd "$STATE_DIR/dist" && shasum -a 256 -c "$(basename "$tarball").sha256")
  kit_log "release: $STATE_DIR/dist/$(basename "$tarball")"
}

explorer_key() {
  local k="$STATE_DIR/secrets/explorer-api.key"
  if [ ! -s "$k" ]; then
    (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$k")
    kit_log "new explorer API shared secret: $k (set it as the Worker secret GNB_API_KEY)"
  fi
  printf '%s' "$k"
}

step_deploy() {
  kit_check_address "$OWNER_ADDRESS" mainnet
  local tarball name key h stratum
  tarball=$(latest_release) || exit 2
  name=$(basename "$tarball" .tar.gz)
  key=$(explorer_key) || exit 2
  kit_select_hosts "$@"
  for h in $SEL; do
    kit_log "== deploy $name to $h"
    stratum=""
    [ "$h" = "${STRATUM_HOST:-}" ] && stratum=--stratum
    kit_run "$h" "rm -rf /tmp/obenblock-kit && mkdir -m 700 /tmp/obenblock-kit"
    kit_put "$h" "$tarball" "/tmp/obenblock-kit/"
    kit_put "$h" "$key" "/tmp/obenblock-kit/explorer-api.key"
    kit_run "$h" "cd /tmp/obenblock-kit && tar -xzf $name.tar.gz && sudo bash $name/host/install.sh --release /tmp/obenblock-kit/$name --owner $OWNER_ADDRESS --peers '$(kit_peers_for "$h")' --threads $MINE_THREADS $stratum --explorer $EXPLORER_TLS --explorer-port $EXPLORER_PORT --explorer-key /tmp/obenblock-kit/explorer-api.key --dns-seed $DNS_SEED; rc=\$?; rm -f /tmp/obenblock-kit/explorer-api.key; exit \$rc" | tr -d '\r'
  done
}

step_explorer_tls() {
  local h
  [ "$EXPLORER_TLS" = letsencrypt ] || kit_die "EXPLORER_TLS is $EXPLORER_TLS in kit.conf"
  kit_select_hosts "$@"
  for h in $SEL; do
    kit_log "== explorer TLS on $h: https://$(kit_dashed "$h").sslip.io:$EXPLORER_PORT"
    kit_run "$h" "sudo bash /opt/obenblock/current/host/explorer-tls.sh $(kit_dashed "$h").sslip.io $EXPLORER_PORT" | tr -d '\r'
  done
}

step_start() {
  local h first=1
  kit_select_hosts "$@"
  for h in $SEL; do
    kit_log "== start obenblock-node on $h"
    kit_run "$h" 'set -e
n=$(pgrep -c -x obenblock || true)
if [ "$n" -gt 0 ] && ! systemctl is-active --quiet obenblock-node; then echo "refusing: $n obenblock process(es) run outside the unit"; exit 3; fi
sudo systemctl start obenblock-node
for i in $(seq 1 30); do curl -s -m 2 -H content-type:application/json -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}" http://127.0.0.1:18210/ >/dev/null && break; sleep 2; done
systemctl is-active obenblock-node
if systemctl is-enabled --quiet obenblock-explorer-api 2>/dev/null; then sudo systemctl start obenblock-explorer-api; echo "explorer-api $(systemctl is-active obenblock-explorer-api)"; fi
if systemctl is-enabled --quiet obenblock-stratum 2>/dev/null; then sudo systemctl start obenblock-stratum || true; sleep 2; echo "stratum $(systemctl is-active obenblock-stratum)"; fi
echo "obenblock processes: $(pgrep -c -x obenblock)"' | tr -d '\r'
    if [ $first -eq 1 ]; then first=0; sleep 5; fi
  done
}

step_verify() {
  local h out files=() genesis_raw="" st
  st=$(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$SRC_DIR" 2>/dev/null || true)
  case $st in launched*) genesis_raw=$(printf '%s' "$st" | awk '{print $4}') ;; esac
  kit_select_hosts "$@"
  for h in $SEL; do
    out="$STATE_DIR/logs/status-$h.txt"
    kit_log "== status $h"
    kit_run "$h" 'sudo -n true 2>/dev/null || sudo -v; python3 -I /opt/obenblock/current/host/status.py' 2>&1 | tr -d '\r' > "$out" || true
    grep -v '^OBB-STATUS ' "$out" || true
    files+=("$h=$out")
  done
  python3 -I "$KIT_DIR/lib/verify_summary.py" --network mainnet ${genesis_raw:+--genesis "$genesis_raw"} \
    --threads "$MINE_THREADS" --stratum-host "${STRATUM_HOST:-}" "${files[@]}"
}

step_logs() {
  local h=${1:?logs <host> [lines]} n=${2:-100}
  kit_is_known_host "$h" || kit_die "$h is not in HOSTS"
  case $n in *[!0-9]*) kit_die "lines must be a number" ;; esac
  kit_run "$h" "sudo journalctl -u obenblock-node -n $n --no-pager" | tr -d '\r'
}

step_rollback() {
  local mode=$1 h; shift
  kit_select_hosts "$@"
  for h in $SEL; do
    kit_log "== $mode on $h"
    kit_run "$h" "cp /opt/obenblock/current/host/rollback.sh /tmp/obenblock-rollback.sh && sudo bash /tmp/obenblock-rollback.sh $mode; rc=\$?; rm -f /tmp/obenblock-rollback.sh; exit \$rc" | tr -d '\r'
  done
}

[ $# -ge 1 ] || usage
cmd=$1; shift
kit_load_conf
case $cmd in
  preflight) step_preflight ;;
  genesis) step_genesis "$@" ;;
  build) step_build "$@" ;;
  deploy) step_deploy "$@" ;;
  explorer-tls) step_explorer_tls "$@" ;;
  start) step_start "$@" ;;
  verify) step_verify "$@" ;;
  logs) step_logs "$@" ;;
  stop) step_rollback stop "$@" ;;
  rollback) step_rollback previous "$@" ;;
  remove) step_rollback remove "$@" ;;
  *) usage ;;
esac
