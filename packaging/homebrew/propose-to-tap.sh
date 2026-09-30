#!/usr/bin/env bash
# Proposes a rendered formula to the tap: commits it as Formula/tzun-verify.rb
# on the branch tzun-verify-<version> of the tap repository and opens a pull
# request of it against the tap's default branch. The tap's own checks run on
# that pull request, and a person merges it.
#
#   packaging/homebrew/propose-to-tap.sh <owner>/<tap-repository> <version> <formula.rb>
#
# GH_TOKEN is a token that may push to the tap and open pull requests there:
# the publish job's, minted from its OIDC token for this one job. It reaches
# git as an HTTP header for github.com, never in a URL or a file.
# TAP_GIT_URL, for tests only, replaces the tap's clone URL.
set -euo pipefail

usage() {
  echo "usage: packaging/homebrew/propose-to-tap.sh <owner>/<tap-repository> <version> <formula.rb>" >&2
  exit 2
}
[[ $# -eq 3 ]] || usage
tap="$1"
version="$2"
formula="$3"

fail() {
  echo "propose-to-tap: $*" >&2
  exit 1
}

[[ "$tap" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || fail "'$tap' is not <owner>/<repository>"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "'$version' is not a version"
[[ -f "$formula" ]] || fail "$formula: no such file"
grep -q "^  version \"$version\"$" "$formula" || fail "$formula is not the formula of version $version"
if grep -q 'file://' "$formula"; then fail "$formula downloads from file:// URLs, not from the release"; fi
[[ -n "${GH_TOKEN:-}" ]] || fail "GH_TOKEN is not set"

url="${TAP_GIT_URL:-https://github.com/$tap.git}"
auth="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')"
git_tap() { git -c "http.https://github.com/.extraheader=$auth" "$@"; }
branch="tzun-verify-$version"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git_tap clone --quiet --depth 1 "$url" "$work/tap"
cd "$work/tap"
mkdir -p Formula
cp "$formula" Formula/tzun-verify.rb
git add Formula/tzun-verify.rb
if git diff --cached --quiet; then
  echo "propose-to-tap: the tap's default branch already holds this formula"
  exit 0
fi

run="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-TzunAI/tzun-verify}/actions/runs/${GITHUB_RUN_ID:-0}"
release="https://github.com/${GITHUB_REPOSITORY:-TzunAI/tzun-verify}/releases/tag/v$version"
git -c user.name="Tzun" -c user.email="noreply@tzun.ai" commit --quiet \
  -m "tzun-verify $version" \
  -m "Rendered from the release's SHA256SUMS by $run."
# The branch is this job's alone: a re-run replaces what an earlier one pushed.
git_tap push --quiet --force origin "HEAD:refs/heads/$branch"
echo "propose-to-tap: pushed $branch"

if [[ -n "$(gh pr list --repo "$tap" --head "$branch" --state open --json number --jq '.[].number')" ]]; then
  echo "propose-to-tap: the pull request of $branch is open already, and now holds this commit"
  exit 0
fi
gh pr create --repo "$tap" --head "$branch" --title "tzun-verify $version" --body "$(
  cat <<EOF
The formula of [tzun-verify $version]($release), rendered from the release's SHA256SUMS by [the publish job]($run).

Before rendering it, the job downloaded the four archives the formula installs from the published release, checked each against SHA256SUMS and against the build provenance the release workflow attested, installed the formula and ran its test in Homebrew's container.
EOF
)"
