# Shared helpers of the ObenBlock launch kit (sourced by obb-launch.sh).
# shellcheck shell=bash

kit_log() { printf '%s [obb-launch] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
kit_die() { printf 'obb-launch: error: %s\n' "$*" >&2; exit 2; }
kit_need() { command -v "$1" >/dev/null 2>&1 || kit_die "'$1' is required on this machine"; }

# Load kit.conf (KIT_CONF overrides the path) and fill the defaults.
kit_load_conf() {
  KIT_CONF=${KIT_CONF:-$KIT_DIR/kit.conf}
  [ -f "$KIT_CONF" ] || kit_die "no $KIT_CONF: copy kit.conf.example to kit.conf and fill it"
  # shellcheck source=/dev/null
  . "$KIT_CONF"
  : "${HOSTS:?HOSTS is empty in kit.conf}"
  SSH_USER=${SSH_USER:-ubuntu}
  BUILD_DIR=${BUILD_DIR:-obenblock-launch}
  BUILD_JOBS=${BUILD_JOBS:-28}
  STRATUM_V1_PORT=${STRATUM_V1_PORT:-3333}
  STRATUM_V2_PORT=${STRATUM_V2_PORT:-3334}
  MINER_THREADS=${MINER_THREADS:-${MINE_THREADS:-auto}}
  MINER_LABEL_PREFIX=${MINER_LABEL_PREFIX:-cpu}
  NODE_MINE=${NODE_MINE:-off}
  WITNESS=${WITNESS:-on}
  WITNESS_SHARE_THREADS=${WITNESS_SHARE_THREADS:-1}
  STRATUM_PROXY=${STRATUM_PROXY:-off}
  STRATUM_PROXY_PORT=${STRATUM_PROXY_PORT:-3335}
  EXPLORER_TLS=${EXPLORER_TLS:-letsencrypt}
  EXPLORER_PORT=${EXPLORER_PORT:-2087}
  DNS_SEED=${DNS_SEED:-none}
  if [ -z "${SRC_DIR:-}" ]; then
    SRC_DIR=$(cd "$KIT_DIR/../.." 2>/dev/null && pwd)
  fi
  STATE_DIR=${STATE_DIR:-$KIT_DIR/state}
  # Never ship the kit's state (secrets, tarballs, logs) or kit.conf with a
  # source copy: excluded from every rsync of SRC_DIR (build host and the
  # rehearsal copy). A STATE_DIR elsewhere inside SRC_DIR is refused.
  KIT_SRC_EXCLUDES=(--exclude /target --exclude /.git --exclude /deploy/obenblock-launch/state
                    --exclude /deploy/obenblock-launch/kit.conf)
  local sd src_abs
  mkdir -p "$STATE_DIR"
  sd=$(cd "$STATE_DIR" && pwd -P)
  src_abs=$(cd "${SRC_DIR:-$KIT_DIR/../..}" 2>/dev/null && pwd -P || true)
  if [ -n "$src_abs" ]; then
    case $sd/ in
      "$src_abs"/deploy/obenblock-launch/state/) ;;
      "$src_abs"/*) kit_die "STATE_DIR=$STATE_DIR is inside SRC_DIR: it would be copied to the build host" ;;
    esac
  fi
  SITE_OUT=${SITE_OUT:-$STATE_DIR/site-deploy}
  RELEASE_URL=${RELEASE_URL:-}
  mkdir -p "$STATE_DIR/logs" "$STATE_DIR/secrets" "$STATE_DIR/dist"
  chmod 700 "$STATE_DIR/secrets"
}

kit_src_check() {
  [ -f "$SRC_DIR/crates/gnb-crypto/src/core/genesis.rs" ] || kit_die "SRC_DIR=$SRC_DIR is not an ObenBlock checkout"
}

kit_is_pw_host() {
  case " ${PW_HOSTS:-} " in *" $1 "*) return 0 ;; esac
  return 1
}

kit_is_known_host() {
  case " $HOSTS " in *" $1 "*) return 0 ;; esac
  return 1
}

KIT_SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=30)

# Run a command string on a host (remote shell syntax). Key hosts use the
# key; password hosts go through expect with ssh -tt (stdout then carries
# CR line ends, which the callers strip).
kit_run() {
  local h=$1; shift
  if kit_is_pw_host "$h"; then
    [ -f "$PW_FILE" ] || kit_die "password file $PW_FILE not found"
    expect -f "$KIT_DIR/lib/pw-ssh.exp" run "$SSH_USER@$h" "$PW_FILE" "$*"
  else
    ssh "${KIT_SSH_OPTS[@]}" -i "$SSH_KEY" "$SSH_USER@$h" "$*"
  fi
}

kit_put() {
  local h=$1 src=$2 dst=$3
  if kit_is_pw_host "$h"; then
    expect -f "$KIT_DIR/lib/pw-ssh.exp" put "$SSH_USER@$h" "$PW_FILE" "$src" "$dst" >/dev/null
  else
    scp -q "${KIT_SSH_OPTS[@]}" -i "$SSH_KEY" "$src" "$SSH_USER@$h:$dst"
  fi
}

kit_get() {
  local h=$1 src=$2 dst=$3
  if kit_is_pw_host "$h"; then
    expect -f "$KIT_DIR/lib/pw-ssh.exp" get "$SSH_USER@$h" "$PW_FILE" "$src" "$dst" >/dev/null
  else
    scp -q "${KIT_SSH_OPTS[@]}" -i "$SSH_KEY" "$SSH_USER@$h:$src" "$dst"
  fi
}

# The source tree on the build host (no target/, no .git).
kit_sync_src() {
  kit_is_pw_host "$BUILD_HOST" && kit_die "BUILD_HOST must be a key host"
  kit_run "$BUILD_HOST" "mkdir -p ~/$BUILD_DIR/src"
  rsync -az --delete "${KIT_SRC_EXCLUDES[@]}" \
    -e "ssh ${KIT_SSH_OPTS[*]} -i $SSH_KEY" "$SRC_DIR/" "$SSH_USER@$BUILD_HOST:$BUILD_DIR/src/"
}

# Environment of every cargo command on the build host.
kit_cargo_env() {
  printf 'export PATH=$HOME/.cargo/bin:$PATH CARGO_BUILD_JOBS=%s CARGO_TERM_COLOR=never BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/13/include' "$BUILD_JOBS"
}

# Multiaddrs of the hosts other than $1, space separated.
kit_peers_for() {
  local self=$1 out="" h
  for h in $HOSTS; do
    [ "$h" = "$self" ] && continue
    out="${out:+$out }/ip4/$h/tcp/18110"
  done
  printf '%s' "$out"
}

kit_dashed() { printf '%s' "$1" | tr . -; }

# The explorer API origin name of host $1: its entry in EXPLORER_NAMES
# ("<ip>=<name> ..."; DNS-only A records in the owner's zone, preferred),
# else <ip-with-dashes>.sslip.io (fallback).
kit_explorer_name() {
  local e
  for e in ${EXPLORER_NAMES:-}; do
    [ "${e%%=*}" = "$1" ] && { printf '%s' "${e#*=}"; return; }
  done
  printf '%s.sslip.io' "$(kit_dashed "$1")"
}

# The CPU miner's worker label on host $1 (cpu-136-244-93-186).
kit_miner_label() { printf '%s-%s' "$MINER_LABEL_PREFIX" "$(kit_dashed "$1")"; }

kit_check_address() {
  local addr=$1 network=${2:-mainnet}
  case $addr in
    *LAUNCH-PLACEHOLDER*|'') kit_die "OWNER_ADDRESS is still the placeholder in kit.conf" ;;
  esac
  python3 -I "$KIT_DIR/lib/check_address.py" "$SRC_DIR/reference" "$addr" "$network" \
    || kit_die "OWNER_ADDRESS '$addr' is not a valid ObenBlock $network address"
}

# Selected hosts: the arguments, or every host, into $SEL (a die here stops
# the whole script, unlike inside a command substitution).
kit_select_hosts() {
  local h
  SEL=""
  if [ $# -eq 0 ]; then SEL=$HOSTS; return; fi
  for h in "$@"; do
    kit_is_known_host "$h" || kit_die "$h is not in HOSTS"
    SEL="${SEL:+$SEL }$h"
  done
}
