#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Tzun, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# Makes a release's files: every target's binary, built reproducibly by
# scripts/reproducible-build.sh (two builds, which must agree), an archive of
# each, the third-party licences, and SHA256SUMS. The release workflow (.github/workflows/release.yml)
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
# tag is v<version>, the version is not a -dev one, HEAD is the tag's commit
# (when the tag is here) and no tracked file has uncommitted changes.
#
# The files (RELEASING.md lists them), for each target <os>/<arch>:
#
#   tzun-verify_<version>_<os>_<arch>          the binary (.exe on windows)
#   tzun-verify_<version>_<os>_<arch>.tar.gz   linux and darwin: tzun-verify and the licence files
#   tzun-verify_<version>_<os>_<arch>.zip      windows: tzun-verify.exe and the licence files
#
# and once:
#
#   LICENSE-THIRD-PARTY                        third_party/LICENSE-THIRD-PARTY
#   SHA256SUMS                                 the SHA-256 of each file above, sha256sum's format
#
# An archive's licence files are README.md, LICENSE, NOTICE and
# LICENSE-THIRD-PARTY: the licence of tzun-verify and of every module the
# binary links travel with it.
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
if [[ -n "$tag" ]]; then
  if [[ "$tag" != "v$version" ]]; then
    echo "release-artifacts: the tag is $tag, but internal/cli/cli.go sets Version $version (tag v$version)" >&2
    exit 1
  fi
  # A -dev version is what main carries between two releases (RELEASING.md),
  # never a release.
  if [[ "$version" == *-dev* ]]; then
    echo "release-artifacts: $version is a development version, which is never released; tag a release version" >&2
    exit 1
  fi
  # The files are made from the tree as it is on disk and dated by HEAD's
  # commit, so a rebuild to compare with a release must be of the tag's
  # commit, unchanged; otherwise SHA256SUMS would differ for that alone.
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null &&
    [[ "$(git rev-parse HEAD)" != "$(git rev-parse "refs/tags/$tag^{commit}")" ]]; then
    echo "release-artifacts: HEAD is not the commit of the tag $tag" >&2
    exit 1
  fi
  if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "release-artifacts: the tree has uncommitted changes; a release is built from its tag's commit as committed" >&2
    exit 1
  fi
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
  cp README.md LICENSE NOTICE third_party/LICENSE-THIRD-PARTY "$stage/"
  chmod 0755 "$stage/$exe"
  chmod 0644 "$stage/README.md" "$stage/LICENSE" "$stage/NOTICE" "$stage/LICENSE-THIRD-PARTY"
  touch -d "@$epoch" "$stage/$exe" "$stage/README.md" "$stage/LICENSE" "$stage/NOTICE" "$stage/LICENSE-THIRD-PARTY"
  if [[ "$goos" == windows ]]; then
    cp -p "$stage/$exe" "$out/$name.exe"
    (cd "$stage" && zip -q -X -D -9 "$out/$name.zip" "$exe" README.md LICENSE NOTICE LICENSE-THIRD-PARTY)
  else
    cp -p "$stage/$exe" "$out/$name"
    tar --format=ustar --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
      -C "$stage" -cf - "$exe" README.md LICENSE NOTICE LICENSE-THIRD-PARTY | gzip -9 -n >"$out/$name.tar.gz"
  fi
done
cp third_party/LICENSE-THIRD-PARTY "$out/LICENSE-THIRD-PARTY"

# LC_ALL=C sorts LICENSE-THIRD-PARTY before the tzun-verify_ files, so the
# list is in name order.
(cd "$out" && sha256sum LICENSE-THIRD-PARTY tzun-verify_* >SHA256SUMS)
echo "== SHA256SUMS of tzun-verify $version"
cat "$out/SHA256SUMS"
