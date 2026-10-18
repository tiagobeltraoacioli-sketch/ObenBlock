#!/bin/sh
# Build the ObenBlock browser wallet core (crates/gnb-wallet-wasm) for
# wasm32-wasip1, copy it to site/wallet/gnb_wallet.wasm, pin its SHA-256 in
# the wallet page's controller, site/wallet/app.js (checked by loadCore before
# instantiation), and refresh the Subresource Integrity hashes of the site's
# scripts.
#
# Needs: the rustup target wasm32-wasip1 and a wasi-sdk (clang with the wasm32
# backend and the WASI sysroot), e.g. https://github.com/WebAssembly/wasi-sdk
#   WASI_SDK=~/.local/wasi-sdk scripts/build-wallet-wasm.sh
# The committed binary is built with wasi-sdk 34 (WANT_WASI_SDK below; the
# CI job wasm-reproducible must use the same major version): another wasi-sdk
# compiles the C code (PQClean) differently and gives another hash.
#
#   scripts/build-wallet-wasm.sh --pin-only   re-pin the committed binary and
#                                             refresh SRI without rebuilding
#
# The pin and the SRI attributes are verified by `node --test site/tests/`;
# a stale pin fails those tests. Deploy only a binary whose hash is pinned.
set -eu
cd "$(dirname "$0")/.."

if [ "${1:-}" != "--pin-only" ]; then
  W=${WASI_SDK:-$HOME/.local/wasi-sdk}
  WANT_WASI_SDK=34
  if [ -r "$W/VERSION" ] && [ "$(head -n 1 "$W/VERSION" | cut -d. -f1)" != "$WANT_WASI_SDK" ]; then
    echo "warning: $W is wasi-sdk $(head -n 1 "$W/VERSION"), not $WANT_WASI_SDK: the hash will differ from a wasi-sdk $WANT_WASI_SDK build" >&2
  fi
  export WASI_SDK_DIR="$W/share/wasi-sysroot"
  export CC_wasm32_wasip1="$W/bin/clang" AR_wasm32_wasip1="$W/bin/llvm-ar"
  # Reproducibility: keep build-machine paths out of the binary, so the same
  # source, toolchain (rust-toolchain.toml) and wasi-sdk give the same hash.
  ROOT=$(pwd) CARGO_DIR=${CARGO_HOME:-$HOME/.cargo}
  export CFLAGS_wasm32_wasip1="--target=wasm32-wasip1 --sysroot=$W/share/wasi-sysroot -ffile-prefix-map=$ROOT=/gnb-smh -ffile-prefix-map=$CARGO_DIR=/cargo -ffile-prefix-map=$W=/wasi-sdk"
  export CARGO_TARGET_WASM32_WASIP1_RUSTFLAGS="--remap-path-prefix=$ROOT=/gnb-smh --remap-path-prefix=$CARGO_DIR=/cargo"
  cargo build --release --locked -p gnb-wallet-wasm --target wasm32-wasip1
  cp "${CARGO_TARGET_DIR:-target}/wasm32-wasip1/release/gnb_wallet_wasm.wasm" site/wallet/gnb_wallet.wasm
fi

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
sri() { printf 'sha384-%s' "$(openssl dgst -sha384 -binary "$1" | openssl base64 -A)"; }

# 1. Pin the wasm hash in the served wallet entry point.
WASM_HASH=$(sha256 site/wallet/gnb_wallet.wasm)
pin_entry() { # <path> <constant>
  sed "s/^const $2 = \"[0-9a-f]*\";/const $2 = \"$WASM_HASH\";/" "$1" > "$1.tmp"
  mv "$1.tmp" "$1"
  grep -q "^const $2 = \"$WASM_HASH\";" "$1" \
    || { echo "could not pin $2 in $1" >&2; exit 1; }
}
pin_entry site/wallet/app.js WASM_SHA256

# 2. Refresh integrity="..." on every <script src> / <link rel=modulepreload>
#    that names one of these files (after step 1: app.js changed).
set_sri() { # <html file> <url path> <local file>
  H=$(sri "$3")
  sed "s#\\(\"$2\" integrity=\"\\)sha384-[A-Za-z0-9+/=]*\"#\\1$H\"#g" "$1" > "$1.tmp"
  mv "$1.tmp" "$1"
}
for page in site/wallet.html site/explorer.html site/index.html site/brand.html site/downloads.html; do
  set_sri "$page" /wallet/app.js     site/wallet/app.js
  set_sri "$page" /wallet/core.js    site/wallet/core.js
  set_sri "$page" /wallet/qrcode.js  site/wallet/qrcode.js
  set_sri "$page" /assets/safe.js    site/assets/safe.js
  set_sri "$page" /assets/site.js    site/assets/site.js
  set_sri "$page" /explorer.js       site/explorer.js
  set_sri "$page" /assets/explorer-views.js site/assets/explorer-views.js
done

echo "gnb_wallet.wasm sha256 $WASM_HASH (pinned in site/wallet/app.js)"
