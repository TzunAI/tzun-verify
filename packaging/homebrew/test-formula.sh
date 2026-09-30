#!/usr/bin/env bash
# Installs and tests the Homebrew formula in a container of Homebrew's own
# image, pinned below, so a run on a workstation and a run in CI are the same.
#
#   packaging/homebrew/test-formula.sh --local <release-dir>
#   packaging/homebrew/test-formula.sh [--online] <formula.rb>
#
# --local takes a directory scripts/release-artifacts.sh wrote, built locally
# and published nowhere. The formula is rendered for it with file:// URLs
# into a copy of the directory in the container. On top of the checks below,
# the installed binary must be the directory's binary for the container's
# architecture, byte for byte, and a formula naming a wrong SHA-256 must fail
# them, whether the wrong one is for the archive this platform installs or
# for another platform's.
#
# <formula.rb> is a formula already rendered, installed from the URLs it
# names: the publish job's, for the published release. --online adds brew
# audit's online checks (the homepage and every URL answer).
#
# In the container, as Homebrew's own user, the formula goes into a local
# tap, and then:
#   brew style, brew audit --strict   the formula's source
#   every platform's archive          for each platform Homebrew evaluates
#                                     the formula on (brew info --variations),
#                                     the URL is that platform's archive, and
#                                     what it downloads has the formula's SHA-256
#   brew install, brew test           the archive for the container's
#                                     platform, and the formula's test block
#
# The container is made by docker create, filled by docker cp and started by
# docker start, with no bind mount, so this runs wherever the docker client
# reaches a daemon.
set -euo pipefail

IMAGE=ghcr.io/homebrew/brew:7.0.7@sha256:63f9a03880f954b2dc05ee0b8e93903dae2f161883af0072d77f476303fc834a

usage() {
  echo "usage: packaging/homebrew/test-formula.sh --local <release-dir>" >&2
  echo "       packaging/homebrew/test-formula.sh [--online] <formula.rb>" >&2
  exit 2
}
mode=formula
online=""
case "${1:-}" in
  --local) mode=local; shift ;;
  --online) online=1; shift ;;
esac
[[ $# -eq 1 && -n "$1" ]] || usage
here="$(cd "$(dirname "$0")" && pwd)"

work="$(mktemp -d)"
container=""
cleanup() {
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/in"

if [[ "$mode" == local ]]; then
  release="$(cd "$1" && pwd)"
  version="$(sed -n 's/^[0-9a-f]\{64\}  tzun-verify_\(.*\)_linux_amd64\.tar\.gz$/\1/p' "$release/SHA256SUMS")"
  if [[ -z "$version" || "$version" == *$'\n'* ]]; then
    echo "test-formula: $release/SHA256SUMS does not name one linux/amd64 archive" >&2
    exit 1
  fi
  (cd "$release" && sha256sum --check --strict --quiet SHA256SUMS)
  # The four archives, and the Linux binaries the installed one is compared with.
  mkdir "$work/in/release"
  for t in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
    cp "$release/tzun-verify_${version}_$t.tar.gz" "$work/in/release/"
  done
  cp "$release/tzun-verify_${version}_linux_arm64" "$release/tzun-verify_${version}_linux_amd64" "$work/in/release/"
  base=file:///brew-test/release
  "$here/render-formula.sh" "$version" "$release/SHA256SUMS" "$base" >"$work/in/tzun-verify.rb"
  # The same formula with one target's SHA-256 wrong: the SHA-256 of nothing.
  empty=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  for t in linux_amd64 linux_arm64 darwin_arm64; do
    sed "s/^[0-9a-f]\{64\}  \(tzun-verify_${version}_${t}\.tar\.gz\)$/$empty  \1/" \
      "$release/SHA256SUMS" >"$work/SHA256SUMS.$t"
    "$here/render-formula.sh" "$version" "$work/SHA256SUMS.$t" "$base" >"$work/in/wrong-$t.rb"
    if cmp -s "$work/in/tzun-verify.rb" "$work/in/wrong-$t.rb"; then
      echo "test-formula: making a wrong SHA-256 for $t changed nothing" >&2
      exit 1
    fi
  done
  printf '%s\n' "$version" >"$work/in/local-version"
else
  [[ -f "$1" ]] || { echo "test-formula: $1: no such file" >&2; exit 1; }
  cp "$1" "$work/in/tzun-verify.rb"
fi
if [[ -n "$online" ]]; then touch "$work/in/online"; fi

cat >"$work/in/run.sh" <<'EOF'
set -euo pipefail
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1 \
  HOMEBREW_NO_INSTALL_CLEANUP=1
in=/brew-test
formula=local/tzun/tzun-verify
empty=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
step() { printf '\n== %s\n' "$*"; }
fail() { echo "test-formula: $*" >&2; exit 1; }
case "$(uname -m)" in
  x86_64) arch=amd64 host=x86_64_linux ;;
  aarch64 | arm64) arch=arm64 host=arm64_linux ;;
  *) fail "no release target for $(uname -m)" ;;
esac

# For every platform Homebrew evaluates the formula on, the URL is that
# platform's archive and what it downloads has the formula's SHA-256. brew
# info --variations gives this platform's URL in .urls and each other
# platform's in .variations, keyed by Homebrew's tag for it: a macOS release
# name (arm64_<name> on Apple silicon), x86_64_linux or arm64_linux.
check_targets() (
  set -euo pipefail
  declare -A sums=() seen=()
  brew info --json=v2 --variations "$formula" >"$HOME/info.json"
  while read -r tag url sum; do
    case "$tag" in
      *_linux) want=linux ;;
      *) want=darwin ;;
    esac
    case "$tag" in
      arm64_*) want+=_arm64 ;;
      *) want+=_amd64 ;;
    esac
    [[ "$url" == */tzun-verify_*_"$want".tar.gz ]] || fail "on $tag the formula downloads $url, not the $want archive"
    seen[$want]=1
    if [[ -z "${sums[$url]:-}" ]]; then
      curl -fsSL -o "$HOME/archive" "$url"
      got="$(sha256sum "$HOME/archive" | cut -d' ' -f1)"
      [[ "$got" == "$sum" ]] || fail "on $tag the formula's SHA-256 is $sum; ${url##*/} has $got"
      sums[$url]="$sum"
    fi
    [[ "${sums[$url]}" == "$sum" ]] || fail "two SHA-256s for $url"
  done < <(jq -r --arg host "$host" '.formulae[0]
    | [[$host, .urls.stable]] + [.variations // {} | to_entries[] | select(.value.urls.stable) | [.key, .value.urls.stable]]
    | .[] | "\(.[0]) \(.[1].url) \(.[1].checksum)"' "$HOME/info.json")
  for t in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
    [[ -n "${seen[$t]:-}" ]] || fail "no platform downloads the $t archive"
  done
  printf '%s\n' "${!sums[@]}" | sed 's/^/  checked /' | sort
)

brew --version
brew tap-new --no-git local/tzun >/dev/null 2>&1
tap="$(brew --repository local/tzun)"
use() { cp "$in/$1" "$tap/Formula/tzun-verify.rb"; }
use tzun-verify.rb

step "brew style"
brew style "$formula"
step "brew audit --strict"
audit=(--strict)
if [[ -f "$in/online" ]]; then audit+=(--online); fi
brew audit "${audit[@]}" --formula "$formula"
step "every platform's archive against its SHA-256"
check_targets
step "brew install"
brew install --formula "$formula"
step "brew test"
brew test "$formula"
bin="$(brew --prefix)/bin/tzun-verify"
"$bin" --version

if [[ -f "$in/local-version" ]]; then
  version="$(cat "$in/local-version")"
  step "the installed binary is the release's linux/$arch binary"
  cmp "$bin" "$in/release/tzun-verify_${version}_linux_$arch"
  echo "identical: tzun-verify_${version}_linux_$arch"
  brew uninstall --formula "$formula"

  step "a wrong SHA-256 for the archive this platform installs"
  rm -rf "$(brew --cache)/downloads"
  use "wrong-linux_$arch.rb"
  if brew install --formula "$formula" >"$HOME/wrong.log" 2>&1; then
    fail "installed although the formula's SHA-256 for linux/$arch is wrong"
  fi
  if ! grep -A1 "reports different checksum: *$empty" "$HOME/wrong.log"; then
    cat "$HOME/wrong.log"
    fail "the install failed, but not on the SHA-256"
  fi
  [[ ! -e "$bin" ]] || fail "$bin exists after the failed install"

  for t in "linux_$arch" darwin_arm64; do
    step "the check of every platform's archive, with a wrong SHA-256 for $t"
    use "wrong-$t.rb"
    if check_targets 2>"$HOME/wrong.log"; then
      fail "passed although the formula's SHA-256 for $t is wrong"
    fi
    cat "$HOME/wrong.log"
    grep -q "SHA-256 is $empty; tzun-verify_${version}_$t.tar.gz has" "$HOME/wrong.log" ||
      fail "the check failed, but not on the SHA-256 for $t"
  done
else
  brew uninstall --formula "$formula"
fi
echo
echo "test-formula: all checks passed"
EOF

container="tzun-verify-brew-$$-$RANDOM"
docker create --name "$container" "$IMAGE" bash /brew-test/run.sh >/dev/null
docker cp "$work/in" "$container:/brew-test"
docker start --attach "$container"
