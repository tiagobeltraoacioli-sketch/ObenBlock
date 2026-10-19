#!/bin/bash
# Build an ObenBlock release bundle on the build host.
#
#   release-build.sh <src-dir> <out-dir> <source-label> [--allow-placeholder]
#
# Builds the node (with the built-in Stratum V1/V2 servers), CLI, wallet and
# genesis tool (release profile), obenblock-cpu-miner and obenblock-stratum
# (tools/obenblock-stratum), and assembles
#   <out-dir>/obenblock-release-<id>/   binaries, launchers, units, host
#                                       scripts, explorer API, carryover
#                                       snapshot, RELEASE, SHA256SUMS
#   <out-dir>/obenblock-release-<id>.tar.gz (+ .sha256)
# The CPU miner is obenblock-cpu-miner, run as its own unit through the
# node's V1 server (the node's --mine stays available, off). A mainnet
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

# tools/obenblock-stratum is its own cargo workspace (with its own
# Cargo.lock): obenblock-cpu-miner (the CPU miner unit on every host) and
# obenblock-stratum (the optional external job server).
STRATUM_SRC=tools/obenblock-stratum
[ -f "$STRATUM_SRC/Cargo.toml" ] || die "no $STRATUM_SRC in this source: the release needs obenblock-cpu-miner (merge obenblock/stratum)"
echo "== build obenblock-cpu-miner and obenblock-stratum ($STRATUM_SRC)"
cargo build -q --release --locked --manifest-path "$STRATUM_SRC/Cargo.toml" --bin obenblock-cpu-miner --bin obenblock-stratum
STRATUM_DIR=$STRATUM_SRC/target/release
for b in obenblock-cpu-miner obenblock-stratum; do
  [ -x "$STRATUM_DIR/$b" ] || die "the stratum build produced no $STRATUM_DIR/$b"
done
"$STRATUM_DIR/obenblock-cpu-miner" --bench 1 -t 1 > "$STAGE/miner-bench.txt" 2>&1 || true

BASE_ID="$LABEL-$( [ "$GENESIS_DISPLAY" = none ] && echo nogenesis || echo "g${GENESIS_DISPLAY:56:8}")"
# Assembled under a temporary name; the id gets a digest of the contents
# (every file but RELEASE), so a rebuild with other binaries, units or
# launchers never reuses an installed id.
REL=$OUT/obenblock-release-$BASE_ID.assembling
rm -rf "$REL"
mkdir -p "$REL/units" "$REL/host" "$REL/lib" "$REL/share" "$REL/explorer-api"
install -m 755 "$STAGE/gnb" "$REL/obenblock"
install -m 755 "$STAGE/gnb-cli" "$REL/obenblock-cli"
install -m 755 "$STAGE/gnb-wallet" "$REL/obenblock-wallet"
install -m 755 "$STAGE/gnb-mine-genesis" "$REL/obenblock-mine-genesis"
install -m 755 "$STRATUM_DIR/obenblock-cpu-miner" "$STRATUM_DIR/obenblock-stratum" "$REL/"
install -m 755 "$KIT/host/obenblock-launch" "$KIT/host/obenblock-miner-launch" "$KIT/host/obenblock-stratum-launch" "$REL/"
install -m 644 "$KIT"/host/*.service "$REL/units/"
install -m 755 "$KIT/host/install.sh" "$KIT/host/rollback.sh" "$KIT/host/explorer-tls.sh" "$KIT/host/status.py" "$REL/host/"
install -m 644 "$KIT/lib/apply_genesis.py" "$REL/lib/"
install -m 644 deploy/explorer-api/gnb_explorer_api.py "$REL/explorer-api/"
install -m 644 deploy/explorer-api/cloudflare-ips-v4.txt "$REL/share/"
# The explorer API's Cloudflare-only nftables table (obenblock/site-deploy):
# the script and its persistent units, used as they are.
install -m 755 deploy/explorer-api/firewall-cloudflare.sh "$REL/host/"
install -m 644 deploy/explorer-api/obenblock-explorer-firewall.service deploy/explorer-api/obenblock-explorer-firewall-reapply.service \
  deploy/explorer-api/obenblock-explorer-firewall-reapply.timer "$REL/units/"
install -m 644 genesis/bloch-g3-carryover.tsv.gz "$REL/share/"

version=$("$REL/obenblock" --version 2>&1 | head -1)
DIGEST=$(cd "$REL" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -c1-8)
ID="$BASE_ID-c$DIGEST"
FINAL=$OUT/obenblock-release-$ID
rm -rf "$FINAL" "$FINAL.tar.gz"
mv "$REL" "$FINAL"
REL=$FINAL
{
  echo "id=$ID"
  echo "content_digest=$DIGEST"
  echo "source=$LABEL"
  echo "genesis=$GENESIS_RAW"
  echo "genesis_display=$GENESIS_DISPLAY"
  echo "genesis_timestamp=$GENESIS_TS"
  echo "stratum=built-in V1 + V2 (obenblock --stratum --stratum-v2); external obenblock-stratum optional"
  echo "cpu_miner=obenblock-cpu-miner (on the build host: $(sed -n 's/^\[miner\] kernels (MH\/s, one thread): //p' "$STAGE/miner-bench.txt" | head -1))"
  echo "node_version=$version"
  echo "rustc=$(rustc --version)"
  echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)"
} > "$REL/RELEASE"
(cd "$REL" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
tar -C "$OUT" -czf "$REL.tar.gz" "obenblock-release-$ID"
(cd "$OUT" && sha256sum "obenblock-release-$ID.tar.gz" > "obenblock-release-$ID.tar.gz.sha256")

rm -rf "$STAGE"
echo "== release $ID"
cat "$REL/RELEASE"
echo "-- SHA256SUMS (binaries)"
grep -E ' obenblock[a-z-]*$' "$REL/SHA256SUMS" || true
echo "RELEASE_TARBALL=$REL.tar.gz"
cat "$REL.tar.gz.sha256"
