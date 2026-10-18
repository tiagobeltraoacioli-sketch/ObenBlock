#!/bin/bash
# Build an ObenBlock release bundle on the build host.
#
#   release-build.sh <src-dir> <out-dir> <source-label> [--allow-placeholder]
#
# Builds the node, CLI, wallet and genesis tool (release profile), the
# stratum proxy when tools/obenblock-stratum exists, and assembles
#   <out-dir>/obenblock-release-<id>/   binaries, launchers, units, host
#                                       scripts, explorer API, carryover
#                                       snapshot, RELEASE, SHA256SUMS
#   <out-dir>/obenblock-release-<id>.tar.gz (+ .sha256)
# The CPU miner is the node's built-in SHA-256d miner (--mine). A mainnet
# release needs the mined genesis in the source; --allow-placeholder builds
# one without it (marked genesis=none; install.sh refuses it on mainnet).
set -euo pipefail
die() { echo "release-build.sh: $*" >&2; exit 2; }
[ $# -ge 3 ] || die "usage: release-build.sh <src-dir> <out-dir> <source-label> [--allow-placeholder]"
SRC=$(cd "$1" && pwd); OUT=$2; LABEL=$3; ALLOW=${4:-}
KIT=$(cd "$(dirname "$0")/.." && pwd)
case $LABEL in ''|*[!A-Za-z0-9._-]*) die "source label must be [A-Za-z0-9._-]" ;; esac
export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never
export BINDGEN_EXTRA_CLANG_ARGS=${BINDGEN_EXTRA_CLANG_ARGS:--I/usr/lib/gcc/x86_64-linux-gnu/13/include}
cd "$SRC"

state=$(python3 -I "$KIT/lib/apply_genesis.py" status "$SRC")
case $state in
  launched*) set -- $state; GENESIS_RAW=$4; GENESIS_DISPLAY=$3; GENESIS_TS=$2 ;;
  placeholder)
    [ "$ALLOW" = --allow-placeholder ] || die "the source still has the mainnet LAUNCH PLACEHOLDER: run the genesis step first"
    GENESIS_RAW=none; GENESIS_DISPLAY=none; GENESIS_TS=0 ;;
  *) die "unexpected genesis state: $state" ;;
esac

echo "== build node, cli, mine-genesis"
cargo build -q --release --locked -p gnb --bins
# The node binaries are staged before the wallet build: gnb-wallet needs
# gnb-crypto's wallet-cli feature, which must not leak into the node.
STAGE=$(mktemp -d)
install -m 755 target/release/gnb target/release/gnb-cli target/release/gnb-mine-genesis "$STAGE/"
echo "== build wallet (gnb-crypto/wallet-cli)"
cargo build -q --release --locked -p gnb --bin gnb-wallet --features gnb-crypto/wallet-cli
install -m 755 target/release/gnb-wallet "$STAGE/"

STRATUM_EXEC=""
STRATUM_SRC=tools/obenblock-stratum
if [ -d "$STRATUM_SRC" ]; then
  echo "== build stratum proxy ($STRATUM_SRC)"
  if [ -f "$STRATUM_SRC/Cargo.toml" ]; then
    pkg=$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$STRATUM_SRC/Cargo.toml" | head -1)
    if cargo metadata -q --no-deps --format-version 1 | grep -q "\"name\":\"$pkg\""; then
      cargo build -q --release --locked -p "$pkg"
      STRATUM_DIR=target/release
    else
      cargo build -q --release --manifest-path "$STRATUM_SRC/Cargo.toml"
      STRATUM_DIR=$STRATUM_SRC/target/release
    fi
    STRATUM_EXEC=$(sed -n '/^\[\[bin\]\]/,/^\[/{s/^name *= *"\(.*\)"/\1/p}' "$STRATUM_SRC/Cargo.toml" | head -1)
    STRATUM_EXEC=${STRATUM_EXEC:-$pkg}
    [ -x "$STRATUM_DIR/$STRATUM_EXEC" ] || die "stratum build produced no $STRATUM_DIR/$STRATUM_EXEC"
  else
    echo "   (no Cargo.toml: shipped as files)"
  fi
else
  echo "== no $STRATUM_SRC in this source: the release has no stratum proxy"
fi

ID="$LABEL-$( [ "$GENESIS_DISPLAY" = none ] && echo nogenesis || echo "g${GENESIS_DISPLAY:56:8}")"
REL=$OUT/obenblock-release-$ID
rm -rf "$REL" "$REL.tar.gz"
mkdir -p "$REL/units" "$REL/host" "$REL/lib" "$REL/share" "$REL/explorer-api"
install -m 755 "$STAGE/gnb" "$REL/obenblock"
install -m 755 "$STAGE/gnb-cli" "$REL/obenblock-cli"
install -m 755 "$STAGE/gnb-wallet" "$REL/obenblock-wallet"
install -m 755 "$STAGE/gnb-mine-genesis" "$REL/obenblock-mine-genesis"
rm -rf "$STAGE"
if [ -n "$STRATUM_EXEC" ]; then
  for b in $(sed -n '/^\[\[bin\]\]/,/^\[/{s/^name *= *"\(.*\)"/\1/p}' "$STRATUM_SRC/Cargo.toml") $STRATUM_EXEC; do
    [ -x "$STRATUM_DIR/$b" ] && install -m 755 "$STRATUM_DIR/$b" "$REL/$b"
  done
elif [ -d "$STRATUM_SRC" ]; then
  mkdir -p "$REL/stratum"
  cp -a "$STRATUM_SRC/." "$REL/stratum/"
  STRATUM_EXEC="stratum"
fi
install -m 755 "$KIT/host/obenblock-launch" "$KIT/host/obenblock-stratum-launch" "$REL/"
install -m 644 "$KIT"/host/*.service "$REL/units/"
install -m 755 "$KIT/host/install.sh" "$KIT/host/rollback.sh" "$KIT/host/explorer-tls.sh" "$KIT/host/status.py" "$REL/host/"
install -m 644 "$KIT/lib/apply_genesis.py" "$REL/lib/"
install -m 644 deploy/explorer-api/gnb_explorer_api.py "$REL/explorer-api/"
install -m 644 deploy/explorer-api/cloudflare-ips-v4.txt "$REL/share/"
install -m 644 genesis/bloch-g3-carryover.tsv.gz "$REL/share/"

version=$("$REL/obenblock" --version 2>&1 | head -1)
{
  echo "id=$ID"
  echo "source=$LABEL"
  echo "genesis=$GENESIS_RAW"
  echo "genesis_display=$GENESIS_DISPLAY"
  echo "genesis_timestamp=$GENESIS_TS"
  echo "stratum=$STRATUM_EXEC"
  echo "cpu_miner=built-in (obenblock --mine)"
  echo "node_version=$version"
  echo "rustc=$(rustc --version)"
  echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)"
} > "$REL/RELEASE"
(cd "$REL" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
tar -C "$OUT" -czf "$REL.tar.gz" "obenblock-release-$ID"
(cd "$OUT" && sha256sum "obenblock-release-$ID.tar.gz" > "obenblock-release-$ID.tar.gz.sha256")

echo "== release $ID"
cat "$REL/RELEASE"
echo "-- SHA256SUMS (binaries)"
grep -E ' obenblock[a-z-]*$' "$REL/SHA256SUMS" || true
echo "RELEASE_TARBALL=$REL.tar.gz"
cat "$REL.tar.gz.sha256"
