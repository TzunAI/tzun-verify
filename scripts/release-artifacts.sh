#!/usr/bin/env bash
# Makes a release's files: every target's binary, built reproducibly by
# scripts/reproducible-build.sh (two builds, which must agree), an archive of
# each, and SHA256SUMS. The release workflow (.github/workflows/release.yml)
# runs it twice, on two machines from two clean checkouts, and requires the
# two SHA256SUMS to be identical. Anyone can run it on a checkout of a
# release tag with the pinned toolchain and compare the SHA256SUMS it writes
# with the release's.
#
#   scripts/release-artifacts.sh <out-dir> [<tag>]
#
# <out-dir> must be empty or not exist. The version is the Version constant
# of internal/cli: a release sets its version in source, so a rebuild of the
# tagged tree reproduces the binary. With <tag>, nothing is built unless the
# tag is v<version>.
#
# The files, for each target <os>/<arch> (RELEASING.md, which the npm, PyPI
# and Homebrew packaging read):
#
#   tzun-verify_<version>_<os>_<arch>          the binary (.exe on windows)
#   tzun-verify_<version>_<os>_<arch>.tar.gz   linux and darwin: tzun-verify and README.md
#   tzun-verify_<version>_<os>_<arch>.zip      windows: tzun-verify.exe and README.md
#   SHA256SUMS                                 the SHA-256 of each file above, sha256sum's format
#
# The archives are reproducible too: fixed order, owner, modes and times (the
# tagged commit's), written by GNU tar, gzip -n and Info-ZIP zip -X.
set -euo pipefail

usage() {
  echo "usage: scripts/release-artifacts.sh <out-dir> [<tag>]" >&2
  exit 2
}
[[ $# -ge 1 && $# -le 2 && -n "$1" ]] || usage
mkdir -p "$1"
out="$(cd "$1" && pwd)"
tag="${2:-}"
cd "$(dirname "$0")/.."

# The targets scripts/release-gate.sh checks, and no others.
TARGETS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)
gate="$(sed -n 's/^TARGETS=(\(.*\))$/\1/p' scripts/release-gate.sh)"
if [[ "$gate" != "${TARGETS[*]}" ]]; then
  echo "release-artifacts: the targets here (${TARGETS[*]}) differ from scripts/release-gate.sh's ($gate)" >&2
  exit 1
fi

if [[ -n "$(ls -A "$out")" ]]; then
  echo "release-artifacts: $out is not empty" >&2
  exit 2
fi

version="$(sed -n 's/^const Version = "\([^"]*\)"$/\1/p' internal/cli/cli.go)"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release-artifacts: internal/cli/cli.go sets no version of the form <major>.<minor>.<patch>[-<pre>] (read: '$version')" >&2
  exit 1
fi
if [[ -n "$tag" && "$tag" != "v$version" ]]; then
  echo "release-artifacts: the tag is $tag, but internal/cli/cli.go sets Version $version (tag v$version)" >&2
  exit 1
fi

if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  echo "release-artifacts: the archives need GNU tar" >&2
  exit 1
fi
for tool in gzip zip sha256sum; do
  command -v "$tool" >/dev/null || { echo "release-artifacts: $tool is needed" >&2; exit 1; }
done

export TZ=UTC LC_ALL=C
epoch="$(git log -1 --format=%ct HEAD)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

scripts/reproducible-build.sh --out "$tmp/bin" "${TARGETS[@]}"

# The binary this machine can run states the version it was built with.
host="$(go env GOHOSTOS)_$(go env GOHOSTARCH)"
if [[ -x "$tmp/bin/$host/tzun-verify" ]]; then
  said="$("$tmp/bin/$host/tzun-verify" --version)"
  if [[ "${said%%$'\n'*}" != "tzun-verify $version" ]]; then
    echo "release-artifacts: the $host binary says '${said%%$'\n'*}', not 'tzun-verify $version'" >&2
    exit 1
  fi
fi

for t in "${TARGETS[@]}"; do
  goos="${t%/*}" goarch="${t#*/}"
  name="tzun-verify_${version}_${goos}_$goarch"
  exe=tzun-verify
  [[ "$goos" == windows ]] && exe=tzun-verify.exe
  stage="$tmp/stage/${goos}_$goarch"
  mkdir -p "$stage"
  cp "$tmp/bin/${goos}_$goarch/$exe" "$stage/$exe"
  cp README.md "$stage/README.md"
  chmod 0755 "$stage/$exe"
  chmod 0644 "$stage/README.md"
  touch -d "@$epoch" "$stage/$exe" "$stage/README.md"
  if [[ "$goos" == windows ]]; then
    cp -p "$stage/$exe" "$out/$name.exe"
    (cd "$stage" && zip -q -X -D -9 "$out/$name.zip" "$exe" README.md)
  else
    cp -p "$stage/$exe" "$out/$name"
    tar --format=ustar --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
      -C "$stage" -cf - "$exe" README.md | gzip -9 -n >"$out/$name.tar.gz"
  fi
done

(cd "$out" && sha256sum tzun-verify_* >SHA256SUMS)
echo "== SHA256SUMS of tzun-verify $version"
cat "$out/SHA256SUMS"
