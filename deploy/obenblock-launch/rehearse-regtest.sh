#!/bin/bash
# End-to-end rehearsal of the launch kit on a build host, without systemd,
# without root and without touching any running service:
#
#   bash deploy/obenblock-launch/rehearse-regtest.sh [work-dir]
#
# Run from the root of a checkout (for example through
# worktrees/obb-remote.sh run <worktree> bash deploy/obenblock-launch/rehearse-regtest.sh).
#  1. kit tests (test_launch_kit.py);
#  2. genesis step on a scratch copy at the documented rehearsal time
#     (host/genesis-build.sh: mine, write, vectors, genesis tests); the
#     checkout itself keeps its LAUNCH PLACEHOLDER;
#  3. release step on that copy (host/release-build.sh: binaries,
#     SHA256SUMS, tarball);
#  4. install step staged into a directory (host/install.sh --root);
#  5. the rehearsal release boots an isolated node on the rehearsal genesis
#     (loopback only, no peers, no mining) to prove the launch refusal is
#     gone and the genesis ledger is written;
#  6. three regtest nodes from the release's launcher, peered on loopback,
#     mining with 2 threads each; status.py + verify_summary.py on them;
#  7. stop: the nodes are terminated and the script checks none is left.
set -euo pipefail
SRC=$(pwd)
KIT=$SRC/deploy/obenblock-launch
W=${1:-$HOME/obb-launch-rehearsal}
REHEARSAL_TS=1792281600
export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never
export BINDGEN_EXTRA_CLANG_ARGS=${BINDGEN_EXTRA_CLANG_ARGS:--I/usr/lib/gcc/x86_64-linux-gnu/13/include}
step() { echo; echo "######## $*"; }
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

[ -f "$KIT/obb-launch.sh" ] || { echo "run from the root of a checkout that has deploy/obenblock-launch" >&2; exit 2; }
if [ "${REUSE_GENESIS:-0}" = 1 ] && [ -f "$W/src/genesis-result.env" ]; then
  echo "(REUSE_GENESIS=1: keeping the genesis copy of the previous run in $W/src)"
  rm -rf "$W/dist" "$W/stage" "$W"/regtest-n* "$W/mainnet-boot" "$W/refuse"
else
  rm -rf "$W"; mkdir -p "$W"
fi

step "1. kit tests"
python3 "$KIT/test_launch_kit.py" 2>&1 | tail -4

step "2. genesis step (dry run on a scratch copy, rehearsal timestamp $REHEARSAL_TS)"
[ "$(python3 -I "$KIT/lib/apply_genesis.py" status "$SRC")" = placeholder ] || { echo "checkout is not the placeholder" >&2; exit 1; }
if [ ! -f "$W/src/genesis-result.env" ]; then
  mkdir -p "$W/src"
  rsync -a --exclude /target --exclude /.git "$SRC/" "$W/src/"
  t0=$(date +%s)
  bash "$KIT/host/genesis-build.sh" "$W/src" "$REHEARSAL_TS" > "$W/genesis.log" 2>&1 || { tail -60 "$W/genesis.log"; exit 1; }
  grep -E '^(==|test result|pub const|genesis block id|Found in|GENESIS_|launched)' "$W/genesis.log"
  echo "genesis step took $(( $(date +%s) - t0 )) s"
else
  grep -E '^(==|test result|GENESIS_|launched)' "$W/genesis.log" | tail -30
fi
# The kit scripts of the copy are those of the checkout (rsync above).
rsync -a "$KIT/" "$W/src/deploy/obenblock-launch/"
. "$W/src/genesis-result.env"
[ "$GENESIS_HASH" = 00000000721a9cb402747bea3f34d0ecc7095952173a5606cd50711230c74d6d ] \
  || { echo "rehearsal genesis differs from the documented one: $GENESIS_HASH" >&2; exit 1; }
echo "rehearsal genesis reproduced: $GENESIS_HASH (nonce $GENESIS_NONCE)"
[ "$(python3 -I "$KIT/lib/apply_genesis.py" status "$SRC")" = placeholder ] && echo "checkout still holds the LAUNCH PLACEHOLDER"
found=$(sed -n 's/^Found in \([0-9.]*\) s.*/\1/p' "$W/src/genesis-mine.log")
threads=$(sed -n 's/^  threads    : \([0-9]*\).*/\1/p' "$W/src/genesis-mine.log")
per=$(( (1 << 32) / threads + ((1 << 32) % threads > 0) ))
done_hashes=$(( GENESIS_NONCE % per ))
python3 - "$found" "$threads" "$done_hashes" <<'EOF' | tee "$W/cpu-rate.txt"
import sys
secs, threads, hashes = float(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
per_thread = hashes / secs
print(f"CPU SHA-256d: {per_thread / 1e6:.1f} MH/s per thread ({threads} threads, {secs} s); "
      f"3 hosts x 31 threads = {per_thread * 93 / 1e9:.2f} GH/s")
print(f"CPU_RATE_HS={per_thread * 93:.0f}")
EOF

step "3. release step (rehearsal genesis)"
bash "$KIT/host/release-build.sh" "$W/src" "$W/dist" rehearsal > "$W/release.log" 2>&1 || { tail -60 "$W/release.log"; exit 1; }
sed -n '/^== release/,$p' "$W/release.log"
REL=$(ls -d "$W"/dist/obenblock-release-rehearsal-*/ | head -1); REL=${REL%/}
(cd "$REL" && sha256sum --quiet -c SHA256SUMS) && echo "SHA256SUMS verified"
grep -q "^genesis=$GENESIS_HASH_RAW$" "$REL/RELEASE" && echo "RELEASE records the genesis"

step "4. install step, staged (no root, no systemd)"
OWNER=$(python3 -I -c "import sys,hashlib; sys.path.insert(0,'$SRC/reference'); import obb_address as a; print(a.key_string('obenblock','mainnet',hashlib.sha3_256(b'obenblock launch rehearsal').digest()[:20]))")
REG_OWNER=$(python3 -I -c "import sys,hashlib; sys.path.insert(0,'$SRC/reference'); import obb_address as a; print(a.key_string('obenblock','testnet',hashlib.sha3_256(b'obenblock launch rehearsal').digest()[:20]))")
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/explorer-api.key"
bash "$REL/host/install.sh" --release "$REL" --owner "$OWNER" \
  --peers "/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110" --threads auto --stratum \
  --explorer letsencrypt --explorer-port 2087 --explorer-key "$W/explorer-api.key" --root "$W/stage"
(cd "$W/stage" && find . -type f -o -type l | LC_ALL=C sort | grep -v '/releases/.*/' ) | sed 's/^/  /'
echo "-- etc/obenblock/obenblock.env"; sed 's/^/  /' "$W/stage/etc/obenblock/obenblock.env"
set -a; . "$W/stage/etc/obenblock/obenblock.env"; set +a
echo "-- the node command line systemd would run on 136:"
OBB_LAUNCH_PRINT=1 OBB_CARRYOVER=$W/stage/opt/obenblock/share/bloch-g3-carryover.tsv sh "$REL/obenblock-launch" | sed 's/^/  /'
if command -v systemd-analyze >/dev/null; then
  for u in "$W"/stage/etc/systemd/system/*.service; do
    printf '  %s: ' "$(basename "$u")"
    systemd-analyze security --offline=true --no-pager "$u" 2>&1 | sed -n 's/.*Overall exposure level for [^:]*: \(.*\)/exposure \1/p'
  done
fi

step "5. isolated boot on the rehearsal mainnet genesis (loopback, no peers, no mining)"
SNAP=$W/stage/opt/obenblock/share/bloch-g3-carryover.tsv
"$REL/obenblock" --chain obenblock --data-dir "$W/mainnet-boot" --carryover-snapshot "$SNAP" \
  --listen /ip4/127.0.0.1/tcp/28110 --rpc-port 28210 --no-default-dns-seed > "$W/mainnet-boot.log" 2>&1 &
PIDS+=($!); boot=$!
rpc() { curl -s -m 5 -H content-type:application/json -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" "http://127.0.0.1:$1/"; }
for _ in $(seq 1 60); do rpc 28210 getblockcount >/dev/null 2>&1 && break; sleep 1; done
rpc 28210 getnetworkinfo | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print('  chain_id', r['chain_id'], r['network'], 'blocks', r['blocks'])"
g=$(rpc 28210 getblockhash '[0]' | python3 -c "import json,sys; print(json.load(sys.stdin)['result'])")
echo "  getblockhash 0 = $g"
[ "$g" = "$GENESIS_HASH_RAW" ] && echo "  matches the mined rehearsal genesis"
grep -m3 -i "genesis\|utxo" "$W/mainnet-boot.log" | sed 's/^/  log: /' || true
kill "$boot"; wait "$boot" 2>/dev/null || true
echo "-- the placeholder build refuses mainnet:"
timeout 60 "$SRC/target/release/gnb" --chain obenblock --data-dir "$W/refuse" --carryover-snapshot "$SNAP" --rpc-port 28212 \
  --listen /ip4/127.0.0.1/tcp/28112 --no-default-dns-seed > "$W/refuse.log" 2>&1 && echo "  UNEXPECTED: started" || echo "  refused: $(grep -m1 -o 'genesis is not mined yet[^.]*' "$W/refuse.log")"

step "6. three regtest nodes from the release launcher (2 mining threads each)"
for i in 1 2 3; do
  peers=""
  for j in 1 2 3; do [ "$j" = "$i" ] || peers="$peers /ip4/127.0.0.1/tcp/2811$j"; done
  env -i PATH="$PATH" HOME="$HOME" OBB_NETWORK=regtest OBB_BIN="$REL/obenblock" OBB_DATA_DIR="$W/regtest-n$i" \
      OBB_CARRYOVER="$SNAP" OBB_MINER_ADDRESS="$REG_OWNER" OBB_MINE_THREADS=2 OBB_PEERS="$peers" \
      OBB_P2P_PORT="2811$i" OBB_RPC_PORT="2821$i" OBB_LISTEN_IP=127.0.0.1 OBB_ALLOW_PRIVATE_PEERS=1 \
      sh "$REL/obenblock-launch" > "$W/regtest-n$i.log" 2>&1 &
  PIDS+=($!)
  sleep 2
done
sleep 75
files=()
for i in 1 2 3; do
  python3 -I "$REL/host/status.py" --no-units --rpc-port "2821$i" --data-dir "$W/regtest-n$i" > "$W/status-n$i.txt"
  grep -v '^OBB-STATUS' "$W/status-n$i.txt" | sed "s/^/  n$i: /"
  files+=("n$i=$W/status-n$i.txt")
done
python3 -I "$KIT/lib/verify_summary.py" --network regtest --threads 2 --no-units "${files[@]}" | sed 's/^/  /'
grep -q '^RESULT OK' < <(python3 -I "$KIT/lib/verify_summary.py" --network regtest --threads 2 --no-units "${files[@]}") \
  && echo "regtest verify: OK" || { echo "regtest verify: FAIL"; exit 1; }

step "7. stop"
cleanup
sleep 3
left=0
for i in 1 2 3; do
  if pgrep -f -- "--data-dir $W/regtest-n$i" >/dev/null; then left=$((left + 1)); fi
done
echo "node processes left: $left"
[ $left -eq 0 ]
PIDS=()

step "timing model (median, from the genesis timestamp)"
cpu=$(sed -n 's/^CPU_RATE_HS=//p' "$W/cpu-rate.txt")
python3 "$KIT/lib/first_blocks.py" --runs 200 "$cpu" 100T 1P 10P 100P 1E
echo
echo "REHEARSAL COMPLETE"
