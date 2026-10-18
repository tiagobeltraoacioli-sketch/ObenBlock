#!/bin/bash
# Mine the ObenBlock mainnet genesis in a source tree and check it
# (docs/OBENBLOCK-GENESIS.md steps 2 to 5). Runs on the build host, from
# obb-launch.sh genesis (real launch) or rehearse-regtest.sh (dry run in a
# scratch copy).
#
#   genesis-build.sh <src-dir> <launch unix time> [--full-tests]
#
# 1. builds gnb-mine-genesis and mines at the given timestamp (2^32
#    SHA-256d on average, seconds on 32 threads);
# 2. writes the constants into crates/gnb-crypto/src/core/genesis.rs and
#    reference/obb_genesis.py (lib/apply_genesis.py), then rewrites and
#    checks reference/obb_genesis_vectors.json;
# 3. runs the genesis and consensus tests (the whole workspace with
#    --full-tests);
# 4. prints GENESIS_* lines with the block id.
# It never commits anything.
set -euo pipefail
die() { echo "genesis-build.sh: $*" >&2; exit 2; }
[ $# -ge 2 ] || die "usage: genesis-build.sh <src-dir> <launch unix time> [--full-tests]"
SRC=$(cd "$1" && pwd); TS=$2; FULL=${3:-}
KIT=$(cd "$(dirname "$0")/.." && pwd)
case $TS in ''|*[!0-9]*) die "timestamp must be decimal unix seconds" ;; esac
[ "$TS" -gt 0 ] && [ "$TS" -lt 4294967296 ] || die "timestamp must fit a u32"
export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never
export BINDGEN_EXTRA_CLANG_ARGS=${BINDGEN_EXTRA_CLANG_ARGS:--I/usr/lib/gcc/x86_64-linux-gnu/13/include}
cd "$SRC"

state=$(python3 -I "$KIT/lib/apply_genesis.py" status "$SRC")
[ "$state" = placeholder ] || die "the source already has a mainnet genesis ($state)"

echo "== build gnb-mine-genesis"
cargo build -q --release -p gnb --bin gnb-mine-genesis
echo "== mine: --chain obenblock --timestamp $TS ($(date -u -d "@$TS" '+%Y-%m-%d %H:%M:%S UTC'))"
./target/release/gnb-mine-genesis --chain obenblock --timestamp "$TS" | tee genesis-mine.log
python3 -I "$KIT/lib/apply_genesis.py" parse genesis-mine.log > genesis-result.env

echo "== write the constants"
python3 -I "$KIT/lib/apply_genesis.py" apply "$SRC" genesis-mine.log
python3 reference/obb_genesis.py --write
python3 reference/obb_genesis.py --check

echo "== genesis and consensus tests"
cargo test -q --release -p gnb-crypto genesis
cargo test -q --release -p gnb-crypto --test obb_genesis_vectors --test obb_genesis_process_chain --test obb_genesis_regtest
cargo test -q --release -p gnb --test obb_regtest_genesis --test obb_sha256d_mining
if [ "$FULL" = --full-tests ]; then
  echo "== workspace tests"
  cargo test -q --release --workspace
fi

echo "== result"
cat genesis-result.env
python3 -I "$KIT/lib/apply_genesis.py" status "$SRC"
