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
#  3. release step on that copy (host/release-build.sh: node with the
#     built-in Stratum V1/V2, cli, wallet, genesis tool, obenblock-cpu-miner,
#     obenblock-stratum, SHA256SUMS, tarball);
#  4. install step staged into a directory (host/install.sh --root), with
#     the owner's real obb1 address and a real KES witness key;
#  5. the rehearsal release boots an isolated node on the rehearsal mainnet
#     genesis (loopback, no peers) with Stratum V1 + V2 on: the launch
#     refusal is gone, the V2 authority key is created, the owner address
#     validates on mainnet in both forms; the placeholder build refuses;
#  6. three regtest nodes from the release launcher on different ports,
#     peered on loopback, built-in Stratum V1 + V2 on each, a KES witness
#     each, NO --mine: one obenblock-cpu-miner per node mines through its
#     node's V1 (release miner launcher); runs past the PoCI launch height
#     (100 on regtest) and waits for finality; status.py + verify_summary.py;
#  7. explorer API from the release, TLS (self-signed) in front of node 1,
#     asked with the Worker's per-request HMAC (lib/explorer_probe.py);
#  8. the node's V1/V2 end-to-end test (SRI codec) and the external job
#     server's own regtest test;
#  9. site values: lib/site_launch.py on a copy of site/ (and the fill when
#     node is installed);
# 10. stop: every process is terminated and the script checks none is left.
set -euo pipefail
SRC=$(pwd)
KIT=$SRC/deploy/obenblock-launch
W=${1:-$HOME/obb-launch-rehearsal}
REHEARSAL_TS=1792281600
REHEARSAL_GENESIS=00000000780c0cdc6532c5d64b9477fe6fe9738b811e0b8d72ebf7af065ff1bb
OWNER_GNB=gnb1q52273b58c1032291d562f582c413bbf05efabcdd0df82055
OWNER=obb1q52273b58c1032291d562f582c413bbf05efabcdd0df82055
TARGET_HEIGHT=${TARGET_HEIGHT:-160}
# Finality the regtest network must reach on every node (the launch
# checkpoint is slot 80, final at launch_height 100).
FIN_TARGET=${FIN_TARGET:-$((TARGET_HEIGHT - 20))}
WAIT_SECS=${WAIT_SECS:-1500}
MINER_THREADS_REG=${MINER_THREADS_REG:-2}
# MINER_NODES="1": one CPU miner only (no competing forks; the default runs
# one per node, as on mainnet).
MINER_NODES=${MINER_NODES:-1 2 3}
# Regtest mines at the pow limit (about two hashes per block) and its ASERT
# anchor is the fixed regtest genesis time, so unpaced CPU miners find
# blocks as fast as the nodes accept them (tens per second): far beyond the
# block rate the network, the 5-block checkpoint interval and the 20-block
# vote lifetime are made for (mainnet: 30 s blocks, launch target 1 EH/s).
# Each miner pauses this long after a block: about one block a second in all.
BLOCK_PAUSE_MS=${BLOCK_PAUSE_MS:-$(( 1000 * $(echo $MINER_NODES | wc -w) ))}
export PATH=$HOME/.cargo/bin:$PATH CARGO_TERM_COLOR=never
export BINDGEN_EXTRA_CLANG_ARGS=${BINDGEN_EXTRA_CLANG_ARGS:--I/usr/lib/gcc/x86_64-linux-gnu/13/include}
step() { echo; echo "######## $*"; }
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
RESULTS=()
result() { RESULTS+=("$1"); echo ">>> $1"; }

[ -f "$KIT/obb-launch.sh" ] || { echo "run from the root of a checkout that has deploy/obenblock-launch" >&2; exit 2; }
if [ "${REUSE_GENESIS:-0}" = 1 ] && [ -f "$W/src/genesis-result.env" ]; then
  echo "(REUSE_GENESIS=1: keeping the genesis copy of the previous run in $W/src)"
  rm -rf "$W/stage" "$W"/regtest-n* "$W/mainnet-boot" "$W/refuse" "$W/site" "$W/tls"
  [ "${REUSE_RELEASE:-0}" = 1 ] || rm -rf "$W/dist"
else
  rm -rf "$W"; mkdir -p "$W"
fi

rpc() {  # rpc <port> <method> [params json] [key file]
  local auth=()
  [ -n "${4:-}" ] && auth=(-H "x-api-key: $(cat "$4")")
  curl -s -m 10 "${auth[@]}" -H content-type:application/json \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" "http://127.0.0.1:$1/"
}
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); r=d.get('result', d); print(eval(sys.argv[1], {}, {'r': r}))" "$1"; }

step "1. kit tests"
python3 "$KIT/test_launch_kit.py" 2>&1 | tail -4
result "kit tests: $(python3 "$KIT/test_launch_kit.py" 2>&1 | tail -1)"

step "2. genesis step (dry run on a scratch copy, rehearsal timestamp $REHEARSAL_TS)"
[ "$(python3 -I "$KIT/lib/apply_genesis.py" status "$SRC")" = placeholder ] || { echo "checkout is not the placeholder" >&2; exit 1; }
if [ ! -f "$W/src/genesis-result.env" ]; then
  mkdir -p "$W/src"
  rsync -a --exclude /target --exclude /.git --exclude /deploy/obenblock-launch/state --exclude /deploy/obenblock-launch/kit.conf "$SRC/" "$W/src/"
  t0=$(date +%s)
  bash "$KIT/host/genesis-build.sh" "$W/src" "$REHEARSAL_TS" > "$W/genesis.log" 2>&1 || { tail -60 "$W/genesis.log"; exit 1; }
  grep -E '^(==|test result|genesis block id|Found in|GENESIS_|launched)' "$W/genesis.log"
  echo "genesis step took $(( $(date +%s) - t0 )) s"
else
  grep -E '^(==|test result|GENESIS_|launched)' "$W/genesis.log" | tail -30
fi
rsync -a "$KIT/" "$W/src/deploy/obenblock-launch/"
. "$W/src/genesis-result.env"
[ "$GENESIS_HASH" = "$REHEARSAL_GENESIS" ] \
  || { echo "rehearsal genesis differs from the documented one: $GENESIS_HASH" >&2; exit 1; }
result "genesis --rehearsal: $GENESIS_HASH (nonce $GENESIS_NONCE) = reference/obb_genesis_vectors.json mainnet.rehearsal"
[ "$(python3 -I "$KIT/lib/apply_genesis.py" status "$SRC")" = placeholder ] && echo "checkout still holds the LAUNCH PLACEHOLDER"

step "3. release step (rehearsal genesis)"
if [ "${REUSE_RELEASE:-0}" = 1 ] && ls -d "$W"/dist/obenblock-release-rehearsal-*/ >/dev/null 2>&1; then
  echo "(REUSE_RELEASE=1)"
else
  t0=$(date +%s)
  bash "$KIT/host/release-build.sh" "$W/src" "$W/dist" rehearsal > "$W/release.log" 2>&1 || { tail -60 "$W/release.log"; exit 1; }
  echo "release step took $(( $(date +%s) - t0 )) s"
fi
sed -n '/^== release/,$p' "$W/release.log"
REL=$(ls -d "$W"/dist/obenblock-release-rehearsal-*/ | head -1); REL=${REL%/}
(cd "$REL" && sha256sum --quiet -c SHA256SUMS) && echo "SHA256SUMS verified"
grep -q "^genesis=$GENESIS_HASH_RAW$" "$REL/RELEASE" && echo "RELEASE records the genesis"
for b in obenblock obenblock-cli obenblock-wallet obenblock-mine-genesis obenblock-cpu-miner obenblock-stratum \
         obenblock-launch obenblock-miner-launch obenblock-stratum-launch; do
  [ -x "$REL/$b" ] || { echo "release lacks $b" >&2; exit 1; }
done
"$REL/obenblock" --help | grep -q -- '--stratum-v2-key' || { echo "node built without the stratum servers" >&2; exit 1; }
result "build: $(basename "$REL") with node (stratum V1+V2), cli, wallet, mine-genesis, cpu-miner, stratum; SHA256SUMS ok"

step "4. install step, staged (no root, no systemd), owner $OWNER, real witness key"
REG_OWNER=$(python3 -I -c "import sys; sys.path.insert(0,'$SRC/reference'); import obb_address as a; n,k,p,f=a.decode('$OWNER','obenblock'); print(a.key_string('obenblock','testnet',p))")
echo "owner, GnB form    : $OWNER_GNB"
echo "owner, ObenBlock   : $OWNER (reference normalize: $(python3 -I -c "import sys; sys.path.insert(0,'$SRC/reference'); import obb_address as a; print(a.normalize('$OWNER_GNB','obenblock'))"))"
echo "same key, regtest  : $REG_OWNER"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$W/explorer-api.key"
chmod 600 "$W/explorer-api.key"
t0=$(date +%s)
bash "$REL/host/install.sh" --release "$REL" --owner "$OWNER" \
  --peers "/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110" --miner-label cpu-136-244-93-186 \
  --witness on --explorer letsencrypt --explorer-port 2087 --explorer-key "$W/explorer-api.key" --root "$W/stage"
echo "install (with witnesskeygen) took $(( $(date +%s) - t0 )) s"
(cd "$W/stage" && find . -type f -o -type l | LC_ALL=C sort | grep -v '/releases/.*/' ) | sed 's/^/  /'
for f in obenblock.env miner.env explorer-api.env; do echo "-- etc/obenblock/$f"; sed 's/^/  /' "$W/stage/etc/obenblock/$f"; done
set -a; . "$W/stage/etc/obenblock/obenblock.env"; set +a
echo "-- the node command line systemd would run on 136:"
OBB_LAUNCH_PRINT=1 OBB_CARRYOVER=$W/stage/opt/obenblock/share/bloch-g3-carryover.tsv \
  CREDENTIALS_DIRECTORY=/run/credentials/obenblock-node.service \
  OBB_WITNESS_KEY=$W/stage/var/lib/obenblock/witness/witness-key.json sh "$REL/obenblock-launch" | sed 's/^/  /'
echo "-- witness drop-in: $(tr '\n' ' ' < "$W/stage/etc/systemd/system/obenblock-node.service.d/witness.conf")"
echo "-- the CPU miner command line (on a 32-thread host: 30 threads):"
(set -a; . "$W/stage/etc/obenblock/miner.env"; set +a; OBB_LAUNCH_PRINT=1 OBB_RELEASE_DIR=$REL sh "$REL/obenblock-miner-launch") | sed 's/^/  /'
grep -q '^OBB_PAYOUT_ADDRESS='"$OWNER"'$' "$W/stage/etc/obenblock/obenblock.env"
grep -q "^OBB_MINER_USER=$OWNER.cpu-136-244-93-186$" "$W/stage/etc/obenblock/miner.env"
if command -v systemd-analyze >/dev/null; then
  for u in "$W"/stage/etc/systemd/system/*.service; do
    printf '  %s: ' "$(basename "$u")"
    systemd-analyze security --offline=true --no-pager "$u" 2>&1 | sed -n 's/.*Overall exposure level for [^:]*: \(.*\)/exposure \1/p'
  done
fi
result "deploy (staged): env files, units, witness key $(sed -n 's/^Witness id: *//p' "$W/stage/var/lib/obenblock/witness/keygen.log"), node + miner command lines"

step "5. isolated boot on the rehearsal mainnet genesis (loopback, no peers, stratum V1 + V2)"
SNAP=$W/stage/opt/obenblock/share/bloch-g3-carryover.tsv
mkdir -p "$W/mainnet-boot"
"$REL/obenblock" --chain obenblock --data-dir "$W/mainnet-boot" --carryover-snapshot "$SNAP" \
  --listen /ip4/127.0.0.1/tcp/28110 --rpc-port 28210 --no-default-dns-seed \
  --stratum --stratum-addr 127.0.0.1:28333 --stratum-v2 --stratum-v2-addr 127.0.0.1:28334 \
  --stratum-v2-key "$W/mainnet-boot/stratum-v2-authority.json" --stratum-payout "$OWNER" > "$W/mainnet-boot.log" 2>&1 &
PIDS+=($!); boot=$!
for _ in $(seq 1 90); do rpc 28210 getblockcount >/dev/null 2>&1 && break; sleep 1; done
rpc 28210 getnetworkinfo | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print('  chain_id', r['chain_id'], r['network'], 'blocks', r['blocks'])"
g=$(rpc 28210 getblockhash '[0]' | jget r)
echo "  getblockhash 0 = $g"
[ "$g" = "$GENESIS_HASH_RAW" ] && echo "  matches the mined rehearsal genesis"
for a in "$OWNER" "$OWNER_GNB"; do
  echo "  validateaddress $a: $(rpc 28210 validateaddress "[\"$a\"]" | python3 -c "import json,sys; r=json.load(sys.stdin).get('result',{}); print({k: r.get(k) for k in ('isvalid','address','network','script_pubkey') if k in r})")"
done
sleep 2
grep -m4 -E 'stratum(_v2)?:' "$W/mainnet-boot.log" | sed 's/^/  log: /' || true
v2pub=$(python3 -c "import json; print(json.load(open('$W/mainnet-boot/stratum-v2-authority.json'))['public_b58'])")
echo "  V2 authority key file created: public_b58 $v2pub (mode $(stat -c %a "$W/mainnet-boot/stratum-v2-authority.json"))"
ss -ltnH | grep -E ':2833[34] ' | sed 's/^/  listen: /'
kill "$boot"; wait "$boot" 2>/dev/null || true
echo "-- the placeholder build refuses mainnet:"
[ -x "$SRC/target/release/gnb" ] || cargo build -q --release -p gnb --bin gnb
timeout 60 "$SRC/target/release/gnb" --chain obenblock --data-dir "$W/refuse" --carryover-snapshot "$SNAP" --rpc-port 28212 \
  --listen /ip4/127.0.0.1/tcp/28112 --no-default-dns-seed > "$W/refuse.log" 2>&1 && echo "  UNEXPECTED: started" || echo "  refused: $(grep -m1 -o 'genesis is not mined yet[^.]*' "$W/refuse.log")"
result "mainnet boot: genesis $([ "$g" = "$GENESIS_HASH_RAW" ] && echo matches || echo DIFFERS), V1+V2 listening, V2 key $v2pub, placeholder refuses"

step "6. three regtest nodes (release launcher; stratum V1 + V2; witness; CPU miner through V1, no --mine)"
for i in 1 2 3; do
  d=$W/regtest-n$i; mkdir -p "$d/witness"; chmod 700 "$d"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$d/rpc.key"; chmod 600 "$d/rpc.key"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$d/witness.pw"; chmod 600 "$d/witness.pw"
  GNB_WALLET_PASSWORD=$(cat "$d/witness.pw") "$REL/obenblock-cli" --chain obenblock --regtest witnesskeygen \
    "$d/witness/witness-key.json" > "$d/keygen.log" 2>&1 &
done
wait
for i in 1 2 3; do echo "  n$i witness id $(sed -n 's/^Witness id: *//p' "$W/regtest-n$i/keygen.log")"; done
for i in 1 2 3; do
  d=$W/regtest-n$i; peers=""
  for j in 1 2 3; do [ "$j" = "$i" ] || peers="$peers /ip4/127.0.0.1/tcp/2811$j"; done
  env -i PATH="$PATH" HOME="$HOME" RUST_LOG="${REHEARSAL_RUST_LOG:-info}" OBB_NETWORK=regtest OBB_BIN="$REL/obenblock" OBB_DATA_DIR="$d" \
      OBB_CARRYOVER="$SNAP" OBB_PAYOUT_ADDRESS="$REG_OWNER" OBB_PEERS="$peers" OBB_RPC_KEY_FILE="$d/rpc.key" \
      OBB_STRATUM=on OBB_STRATUM_V1_PORT="2833$i" OBB_STRATUM_V2=on OBB_STRATUM_V2_PORT="2834$i" OBB_STRATUM_IP=127.0.0.1 \
      OBB_WITNESS=on OBB_WITNESS_KEY="$d/witness/witness-key.json" OBB_WITNESS_PASSWORD_FILE="$d/witness.pw" OBB_SHARE_THREADS=1 \
      OBB_METRICS=on OBB_METRICS_PORT="2831$i" OBB_NODE_MINE=off OBB_DNS_SEED=none \
      OBB_P2P_PORT="2811$i" OBB_RPC_PORT="2821$i" OBB_LISTEN_IP=127.0.0.1 OBB_ALLOW_PRIVATE_PEERS=1 \
      sh "$REL/obenblock-launch" > "$W/regtest-n$i.log" 2>&1 &
  PIDS+=($!)
  sleep 2
done
for i in 1 2 3; do for _ in $(seq 1 60); do rpc "2821$i" getblockcount >/dev/null 2>&1 && break; sleep 1; done; done
for i in $MINER_NODES; do
  env -i PATH="$PATH" OBB_RELEASE_DIR="$REL" OBB_MINER_URL="stratum+tcp://127.0.0.1:2833$i" \
      OBB_MINER_USER="$REG_OWNER.cpu-n$i" OBB_MINER_THREADS="$MINER_THREADS_REG" OBB_MINER_BLOCK_PAUSE_MS="$BLOCK_PAUSE_MS" \
      sh "$REL/obenblock-miner-launch" > "$W/miner-n$i.log" 2>&1 &
  PIDS+=($!)
done
t0=$(date +%s); last=""
while :; do
  line=""; done_all=1
  for i in 1 2 3; do
    h=$(rpc "2821$i" getdaginfo | jget "r.get('tip_height')" 2>/dev/null || echo "?")
    f=$(rpc "2821$i" getfinalityinfo | jget "(r.get('pin') or {}).get('block_height')" 2>/dev/null || echo "?")
    line="$line n$i h=$h fin=$f"
    case $h in ''|*[!0-9]*) done_all=0 ;; *) [ "$h" -ge "$TARGET_HEIGHT" ] || done_all=0 ;; esac
    case $f in ''|*[!0-9]*) done_all=0 ;; *) [ "$f" -ge "$FIN_TARGET" ] || done_all=0 ;; esac
  done
  el=$(( $(date +%s) - t0 ))
  [ "$line" != "$last" ] && echo "  t+${el}s:$line"; last=$line
  [ $done_all -eq 1 ] && break
  [ $el -ge "$WAIT_SECS" ] && { echo "  (stopped waiting after ${WAIT_SECS}s)"; break; }
  sleep 10
done
echo "-- per-node view"
for i in 1 2 3; do
  echo "  n$i getfinalityinfo.poci: $(rpc "2821$i" getfinalityinfo | python3 -c "import json,sys; r=json.load(sys.stdin).get('result',{}); print(json.dumps({'pin': r.get('pin'), 'finalized_count': r.get('finalized_count'), 'poci': r.get('poci')})[:900])")"
done
for hgt in 1 50 100; do
  hs=$(for i in 1 2 3; do rpc "2821$i" getblockhash "[$hgt]" | jget r; done | sort -u | wc -l)
  echo "  block $hgt: $([ "$hs" = 1 ] && echo 'same on the three nodes' || echo "DIFFERS ($hs ids)")"
done
grep -h -m2 'BLOCK FOUND' "$W"/regtest-n*.log | sed 's/^/  log: /' || true
grep -h -m3 'attested checkpoint' "$W"/regtest-n*.log | sed 's/^/  log: /' || true
grep -h -m2 'pool URL' "$W"/regtest-n*.log | sed 's/^/  log: /' || true
tail -3 "$W/miner-n1.log" | sed 's/^/  miner n1: /'
files=()
for i in 1 2 3; do
  python3 -I "$REL/host/status.py" --no-units --rpc-port "2821$i" --metrics-port "2831$i" --data-dir "$W/regtest-n$i" \
    --v2-key "$W/regtest-n$i/stratum-v2-authority.json" --stratum-ports "2833$i,2834$i" --rpc-key-file "$W/regtest-n$i/rpc.key" \
    --release-dir "$REL" --sample-secs 15 > "$W/status-n$i.txt"
  grep -v '^OBB-STATUS' "$W/status-n$i.txt" | sed "s/^/  n$i: /"
  files+=("n$i=$W/status-n$i.txt")
done
python3 -I "$KIT/lib/verify_summary.py" --network regtest --miner-threads "$MINER_THREADS_REG" --no-units --no-peer-check \
  --paced-miner --miner-hosts "$(for i in $MINER_NODES; do printf 'n%s,' "$i"; done)" --min-finalized "$FIN_TARGET" \
  "${files[@]}" > "$W/verify.txt" || true
sed 's/^/  /' "$W/verify.txt"
fin_all=$(for i in 1 2 3; do rpc "2821$i" getfinalityinfo | jget "(r.get('pin') or {}).get('block_height')"; done | tr '\n' ' ')
tips=$(for i in 1 2 3; do rpc "2821$i" getdaginfo | jget "r.get('tip_height')"; done | tr '\n' ' ')
bans=$(cat "$W"/regtest-n*.log | grep -c 'misbehaved' || true)
echo "-- peers discouraged for misbehaviour: $bans"
grep -h 'misbehaved' "$W"/regtest-n*.log | head -6 | sed 's/^/  log: /' || true
result "regtest network: tip heights $tips, finalized pins $fin_all, peer bans $bans, verify $(sed -n 's/^RESULT //p' "$W/verify.txt")"

step "7. explorer API (release copy, TLS with a self-signed certificate) in front of node 1"
mkdir -p "$W/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 -keyout "$W/tls/key.pem" -out "$W/tls/cert.pem" >/dev/null 2>&1
chmod 600 "$W/tls/key.pem"
env -i PATH="$PATH" OBB_CHAIN=obenblock OBB_RPC_URL=http://127.0.0.1:28211/ OBB_API_BIND=127.0.0.1 OBB_API_PORT=28087 \
    OBB_API_KEY_FILE="$W/explorer-api.key" OBB_API_TLS_CERT="$W/tls/cert.pem" OBB_API_TLS_KEY="$W/tls/key.pem" \
    OBB_API_AUTH=hmac OBB_CARRYOVER="$SNAP" python3 -I "$REL/explorer-api/gnb_explorer_api.py" > "$W/explorer.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 20); do curl -sk -m 2 https://127.0.0.1:28087/ >/dev/null 2>&1 && break; sleep 1; done
echo "  signed (HMAC, as the Worker): $(python3 -I "$KIT/lib/explorer_probe.py" https://127.0.0.1:28087 "$W/explorer-api.key" getdaginfo --insecure --expect-chain 0x4f420002 --expect-genesis "$(rpc 28211 getblockhash '[0]' | jget r)" || true)"
probe=$(python3 -I "$KIT/lib/explorer_probe.py" https://127.0.0.1:28087 "$W/explorer-api.key" health --insecure || true)
echo "  signed /v1/health: $probe"
echo "  static X-GnB-Key under OBB_API_AUTH=hmac -> $(curl -sk -m 10 -o /dev/null -w '%{http_code}' -H "x-gnb-key: $(cat "$W/explorer-api.key")" https://127.0.0.1:28087/v1/health)"
echo "  no auth -> $(curl -sk -m 10 -o /dev/null -w '%{http_code}' https://127.0.0.1:28087/v1/health)"
result "explorer API over TLS (HMAC): $probe"

step "8. stratum end-to-end tests (node V1/V2 with SRI's codec; external job server)"
# The regtest network and the API stop first: the tests time their own nodes.
cleanup; PIDS=(); sleep 3
(cd "$W/src" && cargo test -q --release -p gnb --test stratum_e2e 2>&1 | grep -E '^test result|FAILED|panicked' | head -5 || true) | sed 's/^/  node stratum_e2e: /'
(cd "$W/src" && OBB_NODE_BIN="$REL/obenblock" cargo test -q --release --manifest-path tools/obenblock-stratum/Cargo.toml --test e2e_regtest -- --ignored 2>&1 | grep -E '^test result|FAILED|panicked' | head -5 || true) | sed 's/^/  obenblock-stratum e2e_regtest: /'
result "stratum e2e: see the two lines above"

step "9. site values (lib/site_launch.py on a copy of site/)"
mkdir -p "$W/site"; cp -a "$SRC/site/." "$W/site/"
k1=$(python3 -c "import json; print(json.load(open('$W/regtest-n1/stratum-v2-authority.json'))['public_b58'])")
k2=$(python3 -c "import json; print(json.load(open('$W/regtest-n2/stratum-v2-authority.json'))['public_b58'])")
k3=$(python3 -c "import json; print(json.load(open('$W/regtest-n3/stratum-v2-authority.json'))['public_b58'])")
python3 -I "$KIT/lib/site_launch.py" --site "$W/site" --genesis-hash "$GENESIS_HASH" --launch-ts "$GENESIS_TIMESTAMP" \
  --seeds "136.244.93.186 209.250.236.240 152.236.5.112" \
  --stratum "136.244.93.186=$k1 209.250.236.240=$k2 152.236.5.112=$k3" \
  --release "$(basename "$REL" | sed 's/^obenblock-release-//')" --release-sha256 "$(awk '{print $1}' "$REL.tar.gz.sha256")" \
  --out "$W/site/launch.json"
sed 's/^/  /' "$W/site/launch.json"
if command -v node >/dev/null; then
  node "$SRC/scripts/site-launch-fill.mjs" "$W/site/launch.json" "$W/site" --strict
  ! grep -q 'class="at-launch" data-launch=' "$W"/site/*.html && echo "  no marker left"
  result "site: launch.json + fill --strict OK"
else
  result "site: launch.json built and checked against the pages' keys (node not installed here: fill not run)"
fi

step "10. stop"
cleanup
sleep 3
left=0
for i in 1 2 3; do
  if pgrep -f -- "--data-dir $W/regtest-n$i" >/dev/null; then left=$((left + 1)); fi
done
pgrep -f "$REL/obenblock-cpu-miner" >/dev/null && left=$((left + 1))
pgrep -f "$REL/explorer-api" >/dev/null && left=$((left + 1))
echo "processes left: $left"
[ $left -eq 0 ]
PIDS=()

step "timing model (median, from the genesis timestamp)"
"$REL/obenblock-cpu-miner" --bench 3 -t 4 2>&1 | tail -6 | sed 's/^/  /' | tee "$W/bench.txt"
python3 "$KIT/lib/first_blocks.py" --runs 200 3G 30G 100T 1P 10P 100P 1E

echo
echo "SUMMARY"
for r in "${RESULTS[@]}"; do echo "  - $r"; done
echo "REHEARSAL COMPLETE"
