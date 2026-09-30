#!/usr/bin/env bash
# Builds the browser page into web/dist: tzun-verify compiled to WebAssembly
# (cmd/tzun-verify-wasm) with the release flags, the wasm_exec.js of the same
# Go toolchain, the pinned publisher manifest, and the page's own files. It
# prints the wasm's size, its gzip -9 size and its SHA-256, which the page
# also shows once it has loaded it.
#
#   web/build.sh           build
#   web/serve.sh [port]    build, then serve web/dist on 127.0.0.1
set -euo pipefail
cd "$(dirname "$0")/.."

out=web/dist
rm -rf "$out"
mkdir -p "$out"

CGO_ENABLED=0 GOOS=js GOARCH=wasm GOFLAGS=-mod=readonly \
  go build -trimpath -buildvcs=false -tags purego -o "$out/tzun-verify.wasm" ./cmd/tzun-verify-wasm
# wasm_exec.js is the glue between the page and Go's runtime. It must come
# from the toolchain that built the wasm, so it is copied, never committed.
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$out/"
cp web/index.html web/app.js web/spec.js web/style.css web/favicon.svg web/_headers "$out/"
cp publishers/publishers.json "$out/publishers.json"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
wasm="$out/tzun-verify.wasm"
echo "$wasm  $(wc -c <"$wasm" | tr -d ' ') bytes, $(gzip -9 -c "$wasm" | wc -c | tr -d ' ') gzipped  sha256 $(sha256 "$wasm")  $(go env GOVERSION)"
