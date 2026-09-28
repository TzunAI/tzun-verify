#!/usr/bin/env bash
# Builds tzun-verify twice and requires byte-identical binaries. The two
# builds differ in everything a second machine would: the path of the tree,
# the build cache, and the module cache (GOMODCACHE), each fresh. They share
# only the toolchain go.mod pins and the release flags:
#
#   CGO_ENABLED=0 GOFLAGS=-mod=readonly \
#     go build -trimpath -buildvcs=false -tags purego -o tzun-verify ./cmd/tzun-verify
#
# -tags purego is what makes the module cache's path drop out. Without it,
# gnark-crypto (linked through go-ethereum) assembles files that #include an
# assembly file from another package, which -trimpath does not rewrite, so
# the absolute module-cache path lands in .gopclntab and .debug_line. The
# purego build uses the same code in Go, and every result is the same.
#
# Anyone can rebuild a release this way, on any machine with the pinned
# toolchain, and compare the SHA-256 this prints with the published one (and
# with CI's, which this script prints in the job log).
set -euo pipefail
cd "$(dirname "$0")/.."

targets=("${@:-linux/amd64}")
work="$(mktemp -d)"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

# Both module caches fill from the host's download cache, so the second
# build needs no network; anything missing comes from the usual proxy.
go mod download
proxy="file://$(go env GOMODCACHE)/cache/download,$(go env GOPROXY)"

build() { # build <tree> <modcache> <out> <goos> <goarch>
  (cd "$1" && CGO_ENABLED=0 GOOS="$4" GOARCH="$5" GOFLAGS=-mod=readonly GOPROXY="$proxy" \
    GOMODCACHE="$2" GOCACHE="$(mktemp -d -p "$work")" \
    go build -trimpath -buildvcs=false -tags purego -o "$3" ./cmd/tzun-verify)
}

mkdir -p "$work/a" "$work/b/nested/path"
git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$work/a"
git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$work/b/nested/path"

status=0
for t in "${targets[@]}"; do
  goos="${t%/*}" goarch="${t#*/}"
  build "$work/a" "$work/mod-one" "$work/one-$goos-$goarch" "$goos" "$goarch"
  build "$work/b/nested/path" "$work/elsewhere/mod-two" "$work/two-$goos-$goarch" "$goos" "$goarch"
  one="$(sha256sum "$work/one-$goos-$goarch" | cut -d' ' -f1)"
  two="$(sha256sum "$work/two-$goos-$goarch" | cut -d' ' -f1)"
  if [[ "$one" == "$two" ]]; then
    echo "OK   $t  $one  ($(go env GOVERSION))"
  else
    echo "FAIL $t  $one != $two"
    status=1
  fi
done
exit "$status"
