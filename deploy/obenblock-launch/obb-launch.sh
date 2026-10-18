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
#   obb-launch.sh build [--allow-placeholder] [--allow-dirty]
#                                        release binaries + SHA256SUMS on
#                                        BUILD_HOST from a clean committed
#                                        tree, tarball to state/dist
#   obb-launch.sh deploy [host ...]      install the release on the hosts
#                                        (units enabled; witness key generated
#                                        per host; running units restarted on
#                                        the new release/config, host by host)
#   obb-launch.sh dns                    the DNS records the explorer names need
#   obb-launch.sh explorer-tls [host ...]
#                                        Let's Encrypt certificate for the
#                                        host's EXPLORER_NAMES entry (or its
#                                        sslip.io name), API start
#   obb-launch.sh start [host ...]       start the nodes (first host first),
#                                        then the CPU miner, the explorer API
#                                        and the optional proxy; print each
#                                        Stratum V2 authority key
#   obb-launch.sh verify [host ...]      status, peers, tip, finality, stratum
#                                        V1/V2, miner threads, exactly one
#                                        node and one miner per host
#   obb-launch.sh site [--rehearsal]     after verify: fill the obenblock.xyz
#                                        launch placeholders in a copy of the
#                                        site (state/site-deploy) and print
#                                        the wrangler commands (never runs them)
#   obb-launch.sh backup-keys [host ...] copy each host's witness key, vote
#                                        record and Stratum V2 authority key
#                                        to state/secrets/keys-<host>.tgz
#   obb-launch.sh explorer-auth hmac|hmac+static [host ...]
#                                        the explorer API's request auth
#                                        (hmac+static at launch, then hmac)
#   obb-launch.sh logs <host> [lines] [unit]
#                                        a unit's journal (default the node)
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
# reference/obb_genesis_vectors.json mainnet.rehearsal (Bitcoin's header
# Merkle root and the ObenBlock body commitment, obenblock/asic-merkle).
REHEARSAL_GENESIS=00000000f9db8f81e92e293fae6032d359f731c1c7afebcaca1b75f47bfc32bc

GENESIS_FILES="crates/gnb-crypto/src/core/genesis.rs reference/obb_genesis.py reference/obb_genesis_vectors.json docs/OBENBLOCK-GENESIS.md"

usage() { sed -n '2,/^# Configuration/p' "$0" | sed '$d'; exit 64; }

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
  command -v node >/dev/null 2>&1 || kit_log "note: node is not installed on this Mac (the site step and wrangler need it)"
  kit_src_check
  kit_log "source: $SRC_DIR ($(git -C "$SRC_DIR" rev-parse --short=12 HEAD 2>/dev/null || echo 'not a git checkout'))"
  kit_log "genesis in source: $(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$SRC_DIR")"
  [ -f "$SRC_DIR/tools/obenblock-stratum/Cargo.toml" ] || kit_die "$SRC_DIR has no tools/obenblock-stratum (the CPU miner)"
  grep -q 'stratum_v2' "$SRC_DIR/node/src/main.rs" || kit_die "$SRC_DIR has no built-in stratum servers (obenblock/stratum-node)"
  kit_check_address "$OWNER_ADDRESS" mainnet
  kit_log "owner: $OWNER_ADDRESS${OWNER_ADDRESS_GNB:+ (GnB form $OWNER_ADDRESS_GNB)}"
  [ -f "$SSH_KEY" ] || kit_die "SSH key $SSH_KEY not found"
  for h in $HOSTS; do
    kit_log "== $h"
    kit_run "$h" 'echo "host=$(hostname) nproc=$(nproc) mem_gb=$(free -g | awk "/^Mem:/{print \$2}") disk_free=$(df -h / | awk "NR==2{print \$4}")"
echo "cpu: $(lscpu | sed -n "s/^Model name: *//p") avx2=$(grep -c -m1 " avx2 " /proc/cpuinfo) avx512f=$(grep -c -m1 " avx512f " /proc/cpuinfo) sha_ni=$(grep -c -m1 " sha_ni " /proc/cpuinfo)"
sudo -n true 2>/dev/null && echo "sudo=passwordless" || { sudo -v && echo "sudo=password-ok"; }
echo "gnb-node=$(systemctl is-active gnb-node 2>/dev/null) enabled=$(systemctl is-enabled gnb-node 2>/dev/null)"
echo "bloch-active-units=$(systemctl list-units --type=service --state=active --no-legend "bloch-*" 2>/dev/null | wc -l)"
echo "obenblock-node=$(systemctl is-active obenblock-node 2>/dev/null)"
echo "gnb-processes=$(pgrep -c -x gnb || true) obenblock-processes=$(pgrep -c -x obenblock || true)"
for p in 80 18110 18210 18310 3333 3334 3335 2087; do o=$(sudo ss -ltnpH "sport = :$p" | head -1); [ -n "$o" ] && echo "port $p in use: $o"; done
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
    rsync -a "${KIT_SRC_EXCLUDES[@]}" "$SRC_DIR/" "$src/"
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
  # The four files come back into a scratch tree first, are checked there
  # (launched, and the reference agrees), and only then replace the
  # placeholder files together: a failed copy leaves SRC_DIR untouched.
  local f back="$STATE_DIR/genesis-back-$tag"
  rm -rf "$back"
  for f in $GENESIS_FILES; do
    mkdir -p "$back/$(dirname "$f")"
    kit_get "$BUILD_HOST" "$bdir/src/$f" "$back/$f"
  done
  case $(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$back") in
    launched*) ;; *) kit_die "the genesis files from the build host are not launched; SRC_DIR untouched" ;;
  esac
  for f in $GENESIS_FILES; do cp "$back/$f" "$src/$f.genesis-new"; done
  for f in $GENESIS_FILES; do mv "$src/$f.genesis-new" "$src/$f"; done
  rm -rf "$back"
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
  if [ $rehearsal -eq 1 ]; then
    [ "$GENESIS_HASH" = "$REHEARSAL_GENESIS" ] || kit_die "the rehearsal genesis differs from the documented $REHEARSAL_GENESIS"
    echo "rehearsal genesis reproduced (reference/obb_genesis_vectors.json mainnet.rehearsal)"
  else
    echo
    echo "Written into $src (not committed). Review, then commit:"
    echo "  git -C $src add $GENESIS_FILES"
    echo "  git -C $src -c user.name=gnb-smh -c user.email=gnb-smh@proton.me commit -m 'obenblock: mainnet genesis $GENESIS_HASH'"
  fi
}

step_build() {
  local allow="" dirty_ok=0 a
  for a in "$@"; do
    case $a in --allow-placeholder) allow=$a ;; --allow-dirty) dirty_ok=1 ;; *) kit_die "build: unknown option $a" ;; esac
  done
  kit_src_check
  local label st head_st tmpd
  label=$(git -C "$SRC_DIR" rev-parse --short=12 HEAD 2>/dev/null) || kit_die "$SRC_DIR is not a git checkout"
  # Everything rsync ships must be the labelled commit: no modified and no
  # untracked file (the kit's state/ and kit.conf are ignored and excluded).
  if [ -n "$(git -C "$SRC_DIR" status --porcelain 2>/dev/null)" ]; then
    [ $dirty_ok -eq 1 ] || kit_die "$SRC_DIR has uncommitted or untracked files (git status): commit them (the mined genesis first) or pass --allow-dirty for a test build"
    label="$label-dirty"
    kit_log "WARNING: building a dirty tree as $label (not for mainnet)"
  fi
  st=$(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$SRC_DIR")
  tmpd=$(mktemp -d)
  mkdir -p "$tmpd/crates/gnb-crypto/src/core"
  git -C "$SRC_DIR" show HEAD:crates/gnb-crypto/src/core/genesis.rs > "$tmpd/crates/gnb-crypto/src/core/genesis.rs"
  head_st=$(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$tmpd"); rm -rf "$tmpd"
  [ "$st" = "$head_st" ] || [ $dirty_ok -eq 1 ] || kit_die "the genesis in the tree ($st) is not the committed one ($head_st)"
  case $st in launched*) ;; *) [ -n "$allow" ] || kit_die "SRC_DIR has the LAUNCH PLACEHOLDER: run the genesis step and commit it (or --allow-placeholder for a test build)" ;; esac
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
    kit_log "new explorer API shared secret: $k (the Worker secret OBB_API_KEY)"
  fi
  printf '%s' "$k"
}

step_deploy() {
  kit_check_address "$OWNER_ADDRESS" mainnet
  local tarball name key h
  tarball=$(latest_release) || exit 2
  name=$(basename "$tarball" .tar.gz)
  key=$(explorer_key) || exit 2
  kit_select_hosts "$@"
  for h in $SEL; do
    kit_log "== deploy $name to $h"
    kit_run "$h" "rm -rf /tmp/obenblock-kit && mkdir -m 700 /tmp/obenblock-kit"
    kit_put "$h" "$tarball" "/tmp/obenblock-kit/"
    kit_put "$h" "$key" "/tmp/obenblock-kit/explorer-api.key"
    kit_run "$h" "cd /tmp/obenblock-kit && tar -xzf $name.tar.gz && sudo bash $name/host/install.sh --release /tmp/obenblock-kit/$name --owner $OWNER_ADDRESS --peers '$(kit_peers_for "$h")' --miner-label $(kit_miner_label "$h") --miner-threads $MINER_THREADS --stratum-v1-port $STRATUM_V1_PORT --stratum-v2-port $STRATUM_V2_PORT --witness $WITNESS --share-threads $WITNESS_SHARE_THREADS --node-mine $NODE_MINE --stratum-proxy $STRATUM_PROXY --stratum-proxy-port $STRATUM_PROXY_PORT --explorer $EXPLORER_TLS --explorer-port $EXPLORER_PORT --explorer-key /tmp/obenblock-kit/explorer-api.key --explorer-auth ${EXPLORER_AUTH:-hmac+static} --dns-seed $DNS_SEED; rc=\$?; rm -f /tmp/obenblock-kit/explorer-api.key; exit \$rc" | tr -d '\r'
    # An upgrade or a new env file takes effect only on a restart: the units
    # that run are restarted on the new release, node first (one host at a
    # time, so the other two keep the network up). Before the launch nothing
    # runs and nothing starts here.
    kit_run "$h" 'set -e
if systemctl is-active --quiet obenblock-node; then
  sudo systemctl restart obenblock-node
  for i in $(seq 1 60); do curl -s -m 2 -H content-type:application/json -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}" http://127.0.0.1:18210/ >/dev/null && break; sleep 2; done
  for u in obenblock-cpu-miner obenblock-explorer-api obenblock-stratum; do
    if systemctl is-active --quiet $u || systemctl is-failed --quiet $u; then sudo systemctl restart $u; fi
  done
  echo "restarted on $(readlink /opt/obenblock/current): node $(systemctl is-active obenblock-node), miner $(systemctl is-active obenblock-cpu-miner)"
else
  echo "obenblock-node not running: nothing restarted (start step)"
fi' | tr -d '\r'
  done
}

print_dns_records() {
  local h n any=0
  for h in $HOSTS; do
    n=$(kit_explorer_name "$h")
    case $n in *.sslip.io) continue ;; esac
    [ $any -eq 0 ] && { echo "DNS records to create in the Cloudflare dashboard (zone of the names; proxy status: DNS only, grey cloud):"; any=1; }
    printf '  A    %-28s %-16s DNS only  TTL auto\n' "$n" "$h"
  done
  if [ $any -eq 1 ]; then
    printf '  CAA  %-28s %s\n' "${EXPLORER_ZONE:-obenblock.xyz}" '0 issue "letsencrypt.org"'
  fi
  [ $any -eq 1 ] || echo "explorer origins: sslip.io names (no DNS record needed; set EXPLORER_NAMES for names in the owner's zone)"
}

step_explorer_tls() {
  local h
  [ "$EXPLORER_TLS" = letsencrypt ] || kit_die "EXPLORER_TLS is $EXPLORER_TLS in kit.conf"
  kit_select_hosts "$@"
  print_dns_records
  for h in $SEL; do
    kit_log "== explorer TLS on $h: https://$(kit_explorer_name "$h"):$EXPLORER_PORT"
    local second=""
    case $(kit_explorer_name "$h") in *.sslip.io) ;; *) [ "${EXPLORER_SSLIP_SAN:-on}" = on ] && second="$(kit_dashed "$h").sslip.io" ;; esac
    kit_run "$h" "sudo bash /opt/obenblock/current/host/explorer-tls.sh $(kit_explorer_name "$h") $EXPLORER_PORT $second" | tr -d '\r'
  done
}

step_start() {
  local h first=1 out k
  kit_select_hosts "$@"
  for h in $SEL; do
    kit_log "== start obenblock-node on $h"
    out="$STATE_DIR/logs/start-$h.txt"
    kit_run "$h" 'set -e
n=$(pgrep -c -x obenblock || true)
if [ "$n" -gt 0 ] && ! systemctl is-active --quiet obenblock-node; then echo "refusing: $n obenblock process(es) run outside the unit"; exit 3; fi
sudo systemctl start obenblock-node
for i in $(seq 1 60); do curl -s -m 2 -H content-type:application/json -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}" http://127.0.0.1:18210/ >/dev/null && break; sleep 2; done
echo "obenblock-node $(systemctl is-active obenblock-node)"
for i in $(seq 1 30); do sudo test -s /var/lib/obenblock/stratum-v2-authority.json && break; sleep 1; done
sudo python3 -I -c "import json; k = json.load(open(\"/var/lib/obenblock/stratum-v2-authority.json\")); print(\"STRATUM_V2_KEY\", k[\"public_b58\"], k[\"fingerprint_hex\"])" || echo "STRATUM_V2_KEY missing"
if systemctl is-enabled --quiet obenblock-cpu-miner 2>/dev/null; then sudo systemctl start obenblock-cpu-miner; sleep 3; echo "obenblock-cpu-miner $(systemctl is-active obenblock-cpu-miner)"; fi
if systemctl is-enabled --quiet obenblock-explorer-api 2>/dev/null; then sudo systemctl start obenblock-explorer-api; echo "explorer-api $(systemctl is-active obenblock-explorer-api)"; fi
if systemctl is-enabled --quiet obenblock-stratum 2>/dev/null; then sudo systemctl start obenblock-stratum || true; sleep 2; echo "stratum-proxy $(systemctl is-active obenblock-stratum)"; fi
echo "obenblock processes: $(pgrep -c -x obenblock)"' | tr -d '\r' | tee "$out"
    k=$(sed -n 's/^STRATUM_V2_KEY \([1-9A-HJ-NP-Za-km-z]*\) .*/\1/p' "$out" | tail -1)
    if [ -n "$k" ]; then
      printf '%s\n' "$k" > "$STATE_DIR/stratum-v2-$h.key"
      echo "STRATUM V2 on $h: stratum2+tcp://$h:$STRATUM_V2_PORT/$k"
    else
      kit_log "WARNING: no Stratum V2 authority key read on $h (verify reports it once the node wrote it)"
    fi
    echo "STRATUM V1 on $h: stratum+tcp://$h:$STRATUM_V1_PORT"
    if [ $first -eq 1 ]; then first=0; sleep 5; fi
  done
}

step_verify() {
  local h out files=() genesis_raw="" st rc=0
  st=$(python3 -I "$KIT_DIR/lib/apply_genesis.py" status "$SRC_DIR" 2>/dev/null || true)
  case $st in launched*) genesis_raw=$(printf '%s' "$st" | awk '{print $4}') ;; esac
  kit_select_hosts "$@"
  for h in $SEL; do
    out="$STATE_DIR/logs/status-$h.txt"
    kit_log "== status $h"
    kit_run "$h" 'sudo -n true 2>/dev/null || sudo -v; sudo python3 -I /opt/obenblock/current/host/status.py' 2>&1 | tr -d '\r' > "$out" || true
    grep -v '^OBB-STATUS ' "$out" || true
    files+=("$h=$out")
  done
  python3 -I "$KIT_DIR/lib/verify_summary.py" --network mainnet ${genesis_raw:+--genesis "$genesis_raw"} \
    --miner-threads "$MINER_THREADS" --node-mine "$NODE_MINE" --witness "$WITNESS" "${files[@]}" \
    > "$STATE_DIR/logs/verify-last.txt" || rc=$?
  cat "$STATE_DIR/logs/verify-last.txt"
  # The V2 authority keys the nodes report, kept for the runbook and the site step.
  sed -n 's/^STRATUM \([0-9.]*\) .* key=\([1-9A-HJ-NP-Za-km-z]\{40,\}\)$/\1 \2/p' "$STATE_DIR/logs/verify-last.txt" |
    while read -r h k; do printf '%s\n' "$k" > "$STATE_DIR/stratum-v2-$h.key"; done
  return $rc
}

step_site() {
  local rehearsal=0 tag=mainnet a h k stratum="" tarball sha rel out origins=""
  for a in "$@"; do
    case $a in --rehearsal) rehearsal=1; tag=rehearsal ;; *) kit_die "site: unknown option $a" ;; esac
  done
  [ -f "$STATE_DIR/genesis-$tag.env" ] || kit_die "no $STATE_DIR/genesis-$tag.env: run the genesis step first"
  # shellcheck source=/dev/null
  . "$STATE_DIR/genesis-$tag.env"
  if [ $rehearsal -eq 0 ]; then
    grep -q '^RESULT OK' "$STATE_DIR/logs/verify-last.txt" 2>/dev/null \
      || kit_die "the last verify was not RESULT OK: run ./obb-launch.sh verify first"
  fi
  for h in $HOSTS; do
    k=$(cat "$STATE_DIR/stratum-v2-$h.key" 2>/dev/null || true)
    if [ -z "$k" ] && [ $rehearsal -eq 1 ]; then
      k=9bRehearsa1KeyNotARea1KeyNotARea1KeyNotARea1Key111
    fi
    [ -n "$k" ] || kit_die "no Stratum V2 key for $h in $STATE_DIR: run start or verify first"
    stratum="${stratum:+$stratum }$h=$k"
  done
  tarball=$(latest_release) || exit 2
  sha=$(awk '{print $1}' "$tarball.sha256")
  rel=$(basename "$tarball" .tar.gz); rel=${rel#obenblock-release-}
  out=$SITE_OUT
  [ $rehearsal -eq 1 ] && out=$STATE_DIR/site-rehearsal
  [ -f "$SRC_DIR/scripts/site-launch-fill.mjs" ] || kit_die "$SRC_DIR has no scripts/site-launch-fill.mjs (merge obenblock/site-deploy)"
  kit_log "site tree: $out (copy of $SRC_DIR site/, worker/, wrangler.toml, scripts/site-launch-fill.mjs)"
  rm -rf "$out"; mkdir -p "$out/scripts"
  rsync -a "$SRC_DIR/site" "$SRC_DIR/worker" "$out/"
  cp "$SRC_DIR/wrangler.toml" "$out/"
  cp "$SRC_DIR/scripts/site-launch-fill.mjs" "$out/scripts/"
  python3 -I "$KIT_DIR/lib/site_launch.py" --site "$out/site" --genesis-hash "$GENESIS_HASH" \
    --launch-ts "$GENESIS_TIMESTAMP" --seeds "$HOSTS" --stratum "$stratum" \
    --v1-port "$STRATUM_V1_PORT" --v2-port "$STRATUM_V2_PORT" --release "$rel" --release-sha256 "$sha" \
    ${RELEASE_URL:+--release-url "$RELEASE_URL"} --dns-seed "$DNS_SEED" --out "$out/launch.json"
  cp "$out/launch.json" "$STATE_DIR/launch-$tag.json"
  # The Worker's variables in the copied wrangler.toml: the origins of this
  # kit, the sslip.io fallbacks, the chain id and the genesis (getblockhash 0,
  # raw order: what the origins sign). Secrets stay out of the file.
  local fallback="" chain_id=0x4f420001
  for h in $HOSTS; do
    origins="${origins:+$origins,}https://$(kit_explorer_name "$h"):$EXPLORER_PORT"
    case $(kit_explorer_name "$h") in *.sslip.io) ;; *) fallback="${fallback:+$fallback,}https://$(kit_dashed "$h").sslip.io:$EXPLORER_PORT" ;; esac
  done
  python3 -I "$KIT_DIR/lib/site_launch.py" --wrangler "$out/wrangler.toml" --origins "$origins" \
    --fallback-origins "$fallback" --chain-id "$chain_id" --genesis-raw "$GENESIS_HASH_RAW" \
    --zone "${EXPLORER_ZONE:-obenblock.xyz}"
  if command -v node >/dev/null 2>&1; then
    (cd "$out" && node scripts/site-launch-fill.mjs launch.json site --strict)
    if grep -q 'class="at-launch" data-launch=' "$out"/site/*.html; then kit_die "a launch marker is still open in $out/site"; fi
    kit_log "filled $out/site (compare: diff -ru $SRC_DIR/site $out/site)"
  else
    kit_log "node is not installed on this Mac: run the fill command below first (wrangler needs node as well)"
  fi
  cat <<EOF

Site launch values: $out/launch.json
Worker variables:   $out/wrangler.toml
  OBB_ORIGIN_ZONE      = ${EXPLORER_ZONE:-obenblock.xyz}
  OBB_ORIGINS          = $origins
  OBB_FALLBACK_ORIGINS = ${fallback:-(none)}
  OBB_CHAIN_ID         = $chain_id
  OBB_GENESIS_HASH     = $GENESIS_HASH_RAW
Worker secret OBB_API_KEY: $STATE_DIR/secrets/explorer-api.key (the same as /etc/obenblock/explorer-api.key on the hosts)

Run these on the Mac, one at a time (this step runs none of them). The
"secret delete" removes an OBB_ORIGINS secret of an older deploy (a variable
and a secret cannot share a name); it fails harmlessly when there is none.

cd $out
node scripts/site-launch-fill.mjs launch.json site --strict
npx wrangler login
npx wrangler secret delete OBB_ORIGINS
npx wrangler secret put OBB_API_KEY < $STATE_DIR/secrets/explorer-api.key
npx wrangler deploy

Then check https://obenblock.xyz/api/originstatus (every host ok, fallback false),
https://obenblock.xyz/api/getnetworkinfo (chain_id $chain_id) and https://obenblock.xyz/#launch.
Once all three answer: ./obb-launch.sh explorer-auth hmac (drops the static header),
then rotate the key (docs: LAUNCH-RUNBOOK.md step 8).
EOF
}

step_explorer_auth() {
  local mode=${1:-} h
  case $mode in hmac|hmac+static) ;; *) kit_die "explorer-auth hmac|hmac+static [host ...]" ;; esac
  shift
  kit_select_hosts "$@"
  for h in $SEL; do
    kit_log "== explorer API auth $mode on $h"
    kit_run "$h" "set -e; f=/etc/obenblock/explorer-api.env; sudo grep -q '^OBB_API_AUTH=' \$f && sudo sed -i 's/^OBB_API_AUTH=.*/OBB_API_AUTH=$mode/' \$f || echo 'OBB_API_AUTH=$mode' | sudo tee -a \$f >/dev/null; sudo systemctl try-restart obenblock-explorer-api; echo \"\$(grep ^OBB_API_AUTH= \$f) explorer-api \$(systemctl is-active obenblock-explorer-api)\"" | tr -d '\r'
  done
}

step_backup_keys() {
  local h dst
  kit_select_hosts "$@"
  for h in $SEL; do
    dst="$STATE_DIR/secrets/keys-$h-$(date -u +%Y%m%dT%H%M%SZ).tgz"
    kit_log "== keys of $h -> $dst"
    kit_run "$h" 'set -e; rm -rf /tmp/obenblock-keys; mkdir -m 700 /tmp/obenblock-keys
cd /var/lib/obenblock && sudo tar -czf /tmp/obenblock-keys/keys.tgz $(sudo sh -c "cd /var/lib/obenblock && ls -d witness stratum-v2-authority.json powit-votes-*.json 2>/dev/null")
sudo chown "$(id -u)" /tmp/obenblock-keys/keys.tgz; ls -l /tmp/obenblock-keys/keys.tgz' | tr -d '\r'
    (umask 077; kit_get "$h" /tmp/obenblock-keys/keys.tgz "$dst")
    kit_run "$h" 'rm -rf /tmp/obenblock-keys' | tr -d '\r'
    chmod 600 "$dst"
    tar -tzf "$dst" | sed 's/^/  /'
  done
  kit_log "keep these OFF the hosts and never restore a witness key on a second running node (PoCI §8: one signer per key)"
}

step_logs() {
  local h=${1:?logs <host> [lines] [unit]} n=${2:-100} u=${3:-obenblock-node}
  kit_is_known_host "$h" || kit_die "$h is not in HOSTS"
  case $n in *[!0-9]*) kit_die "lines must be a number" ;; esac
  case $u in obenblock-node|obenblock-cpu-miner|obenblock-explorer-api|obenblock-stratum) ;; *) kit_die "unit must be one of the kit's obenblock-* units" ;; esac
  kit_run "$h" "sudo journalctl -u $u -n $n --no-pager" | tr -d '\r'
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
  dns) print_dns_records ;;
  deploy) step_deploy "$@" ;;
  explorer-tls) step_explorer_tls "$@" ;;
  start) step_start "$@" ;;
  verify) step_verify "$@" ;;
  site) step_site "$@" ;;
  backup-keys) step_backup_keys "$@" ;;
  explorer-auth) step_explorer_auth "$@" ;;
  logs) step_logs "$@" ;;
  stop) step_rollback stop "$@" ;;
  rollback) step_rollback previous "$@" ;;
  remove) step_rollback remove "$@" ;;
  *) usage ;;
esac
