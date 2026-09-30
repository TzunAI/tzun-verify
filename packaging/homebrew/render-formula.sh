#!/usr/bin/env bash
# Writes the Homebrew formula of one release of tzun-verify to standard
# output: packaging/homebrew/tzun-verify.rb.in with the release's version,
# the URL and SHA-256 of each archive it installs, and a bundle of the
# conformance corpus for its test block.
#
#   packaging/homebrew/render-formula.sh <version> <SHA256SUMS> [<url-base>]
#
# <SHA256SUMS> is the release's (RELEASING.md, "The files"). The formula
# installs the archives of the four targets Homebrew runs on, macOS and Linux
# on arm64 and x86_64 (Go's darwin and linux, arm64 and amd64), and each must
# be listed there exactly once, as
# tzun-verify_<version>_<os>_<arch>.tar.gz.
#
# <url-base> is where the archives are downloaded from, without a trailing
# slash. It defaults to the release's download URL,
# https://github.com/TzunAI/tzun-verify/releases/download/v<version>; the
# tests pass the file:// URL of a release directory built locally.
#
# The test block writes testdata/vectors/bundle-b1/unanchored-pending-stripped
# (its bundle.json, and the timestamping root its inputs.json trusts) from
# this tree, so a formula rendered from a tagged tree tests that tag's corpus.
set -euo pipefail

usage() {
  echo "usage: packaging/homebrew/render-formula.sh <version> <SHA256SUMS> [<url-base>]" >&2
  exit 2
}
[[ $# -ge 2 && $# -le 3 ]] || usage
version="$1"
sums="$2"
base="${3:-https://github.com/TzunAI/tzun-verify/releases/download/v$version}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

fail() {
  echo "render-formula: $*" >&2
  exit 1
}

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
  fail "'$version' is not a version of the form <major>.<minor>.<patch>[-<pre>]"
[[ -f "$sums" ]] || fail "$sums: no such file"
# Only characters that need no quoting in a Ruby string or an awk argument.
[[ "$base" =~ ^(https|file)://[A-Za-z0-9._~%/:+-]+$ && "$base" != */ ]] ||
  fail "'$base' is not an https:// or file:// URL without a trailing slash"

# The SHA-256 SHA256SUMS gives the archive of one target, which it must list
# exactly once.
sha_of() { # sha_of <os> <arch>
  local name="tzun-verify_${version}_$1_$2.tar.gz" found
  found="$(awk -v n="$name" '$2 == n' "$sums")"
  if [[ -z "$found" ]]; then
    fail "$sums lists no $name"
  fi
  if [[ "$found" == *$'\n'* ]]; then
    fail "$sums lists $name more than once"
  fi
  if ! [[ "$found" =~ ^([0-9a-f]{64})\ \ [^[:space:]]+$ ]]; then
    fail "$sums: not a SHA-256 line: $found"
  fi
  printf '%s\n' "${BASH_REMATCH[1]}"
}
darwin_arm64="$(sha_of darwin arm64)"
darwin_amd64="$(sha_of darwin amd64)"
linux_arm64="$(sha_of linux arm64)"
linux_amd64="$(sha_of linux amd64)"

# The test block's bundle, read through an interpolating Ruby heredoc, so it
# must hold nothing Ruby would read as an escape or an interpolation.
case_dir="$root/testdata/vectors/bundle-b1/unanchored-pending-stripped"
bundle="$case_dir/bundle.json"
[[ -f "$bundle" ]] || fail "$bundle: no such file"
[[ "$(cat "$case_dir/expected-exit")" == 0 ]] ||
  fail "the test block expects $case_dir to exit 0, and its expected-exit says otherwise"
if grep -qF "\\" "$bundle" || grep -q '#[{@$]' "$bundle"; then
  fail "$bundle holds a backslash or a Ruby interpolation, which the test block's heredoc would change"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
python3 - "$case_dir/inputs.json" >"$work/root.pem" <<'PY'
import json
import sys

roots = json.load(open(sys.argv[1], encoding="utf-8"))["trustAnchorsPem"]
if len(roots) != 1:
    sys.exit(f"{sys.argv[1]}: {len(roots)} trust anchors, the test block expects one")
print(roots[0].strip())
PY

awk -v version="$version" -v base="$base" \
  -v darwin_arm64="$darwin_arm64" -v darwin_amd64="$darwin_amd64" \
  -v linux_arm64="$linux_arm64" -v linux_amd64="$linux_amd64" \
  -v bundle="$bundle" -v pem="$work/root.pem" '
  # Replaces every key in s by val, taking both literally.
  function subst(s, key, val,    i, out) {
    out = ""
    while ((i = index(s, key)) > 0) {
      out = out substr(s, 1, i - 1) val
      s = substr(s, i + length(key))
    }
    return out s
  }
  # Prints a file with the indentation of the line it replaces; a blank line
  # stays empty.
  function embed(file, indent,    line, n) {
    n = 0
    while ((getline line < file) > 0) {
      print (line == "" ? "" : indent line)
      n++
    }
    close(file)
    if (n == 0) {
      print "render-formula: " file " is empty" > "/dev/stderr"
      exit 1
    }
  }
  /^[ ]*@TEST_BUNDLE@$/ { embed(bundle, substr($0, 1, index($0, "@") - 1)); next }
  /^[ ]*@TEST_ROOT@$/ { embed(pem, substr($0, 1, index($0, "@") - 1)); next }
  {
    line = subst($0, "@URL_BASE@", base)
    line = subst(line, "@VERSION@", version)
    line = subst(line, "@SHA256_DARWIN_ARM64@", darwin_arm64)
    line = subst(line, "@SHA256_DARWIN_AMD64@", darwin_amd64)
    line = subst(line, "@SHA256_LINUX_ARM64@", linux_arm64)
    line = subst(line, "@SHA256_LINUX_AMD64@", linux_amd64)
    print line
  }
' "$here/tzun-verify.rb.in" >"$work/formula.rb"

if grep -n '@[A-Z][A-Z0-9_]*@' "$work/formula.rb" >&2; then
  fail "a placeholder of tzun-verify.rb.in was left unfilled"
fi
cat "$work/formula.rb"
