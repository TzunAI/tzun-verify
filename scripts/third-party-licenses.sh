#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Tzun, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# The licences of the code a release binary contains besides this
# repository's own: the Go standard library and runtime, and every module the
# release build links for the targets a release publishes. They are written
# to third_party/LICENSE-THIRD-PARTY, which a release publishes beside its
# binaries.
#
#   scripts/third-party-licenses.sh [<goos>/<goarch> ...]          write the file
#   scripts/third-party-licenses.sh --check [<goos>/<goarch> ...]  fail if the file is not current
#
# The targets default to the ones scripts/release-gate.sh publishes. The gate
# passes its own list, so a difference between the two fails the gate. CI runs
# --check, so a change to the modules the build links, or to one of their
# licences, fails until the file is written again.
#
# For each module it copies, as the module ships them, the licence and notice
# files (LICENSE, LICENCE, COPYING, NOTICE and UNLICENSE, in any case and with
# any suffix) at the module's root and in every directory between the root
# and a package the build links, since a directory's own licence covers the
# packages under it. It leaves out AUTHORS files, which list contributors and
# are not licence text, and the grant files of the Go projects, which grant
# rights and ask nothing of a redistributor.
set -euo pipefail
cd "$(dirname "$0")/.."

out=third_party/LICENSE-THIRD-PARTY
check=0
if [[ "${1:-}" == "--check" ]]; then
  check=1
  shift
fi
if [[ $# -gt 0 ]]; then
  targets=("$@")
else
  targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)
fi

toolchain="$(sed -n 's/^toolchain //p' go.mod)"
golicence="$(go env GOROOT)/LICENSE"
if [[ -z "$toolchain" || ! -f "$golicence" ]]; then
  echo "third-party licences: go.mod names no toolchain, or $golicence is missing" >&2
  exit 2
fi

# One line per package the build links from another module: the module path,
# its version (and replacement, if any), its root, and the package directory.
# shellcheck disable=SC2016 # a Go template, not a shell expansion
template='{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{with .Replace}} => {{.Path}} {{.Version}}{{end}}{{"\t"}}{{.Dir}}{{"\t"}}{{$.Dir}}{{end}}{{end}}'
packages="$(for t in "${targets[@]}"; do
  CGO_ENABLED=0 GOOS="${t%/*}" GOARCH="${t#*/}" GOFLAGS=-mod=readonly \
    go list -tags purego -deps -f "$template" ./cmd/tzun-verify
done | LC_ALL=C sort -u)"
[[ -n "$packages" ]] || { echo "third-party licences: go list found no modules" >&2; exit 2; }

# One line per licence file: the module path, its version, its root, and the
# file's path below the root.
shopt -s nullglob nocaseglob
files="$(while IFS=$'\t' read -r path version root dir; do
  d="$dir"
  while :; do
    below="${d#"$root"}"
    below="${below#/}"
    for f in "$d"/licen[cs]e* "$d"/copying* "$d"/notice* "$d"/unlicen[cs]e*; do
      [[ -f "$f" && "$f" != *.go ]] || continue
      printf '%s\t%s\t%s\t%s\n' "$path" "$version" "$root" "${below:+$below/}${f##*/}"
    done
    [[ "$d" == "$root" || "$d" == / ]] && break
    d="$(dirname "$d")"
  done
done <<<"$packages" | LC_ALL=C sort -u)"
shopt -u nullglob nocaseglob

rule="$(printf '=%.0s' {1..78})"

section() { # section <heading> <file name as shown> <file>
  printf '%s\n%s\n%s\n%s\n\n' "$rule" "$1" "$2" "$rule"
  cat "$3"
  if [[ -n "$(tail -c1 "$3")" ]]; then echo; fi
  echo
}

generate() {
  cat <<EOF
Third-party licences of the tzun-verify release binaries

A tzun-verify release binary is built from this repository, which is under
the BSD 3-Clause Clear License (LICENSE), and it also contains code from the
Go standard library and runtime and from the modules below, each under its
own licence. This file holds those licences, and any notice file a module
ships, as each module ships them: the files at the module's root and the
ones in each directory between the root and a package the binary links.

The go-ethereum library, which the binary links, is under the GNU Lesser
General Public License, version 3 or later (COPYING.LESSER below), which
incorporates the terms of the GNU General Public License, version 3
(COPYING below), with the additional permissions it lists. The source of
this repository and of every module below is public, and the build is
reproducible (README, How it is held to account), so anyone can build the
binary again with a changed copy of any of these modules, for example
through a replace directive in go.mod.

The modules are the ones the release build links for these targets:
${targets[*]}

scripts/third-party-licenses.sh writes this file, and CI fails when it is
not current; it is not edited by hand.

EOF
  section "Go standard library and runtime, $toolchain" LICENSE "$golicence"
  while IFS=$'\t' read -r path version root file; do
    section "$path $version" "$file" "$root/$file"
  done <<<"$files"
}

if [[ "$check" -eq 1 ]]; then
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  generate >"$tmp"
  if cmp -s "$tmp" "$out"; then
    echo "third-party licences: $out is current"
  else
    diff -u "$out" "$tmp" | head -40 || true
    echo "third-party licences: $out is not current; run scripts/third-party-licenses.sh" >&2
    exit 1
  fi
else
  mkdir -p "${out%/*}"
  generate >"$out"
  echo "third-party licences: wrote $out"
fi
