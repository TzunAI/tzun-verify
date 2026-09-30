#!/usr/bin/env bash
# Downloads, from a published release, the SHA256SUMS and the four archives
# the Homebrew formula installs, and checks each archive twice: against
# SHA256SUMS, and against the build provenance the release workflow attested
# for it (RELEASING.md, "The files").
#
#   packaging/homebrew/fetch-release.sh <tag> <out-dir>
#
# The download is anonymous, from the release's public URL, as brew's own
# will be: it fails until a person has published the draft release, and while
# the repository is not public. The attestation check is gh attestation
# verify, which needs gh and a token in GH_TOKEN; it requires the signer to be
# .github/workflows/release.yml at refs/tags/<tag>, on a GitHub-hosted runner.
# The repository is $GITHUB_REPOSITORY, TzunAI/tzun-verify when unset.
set -euo pipefail

usage() {
  echo "usage: packaging/homebrew/fetch-release.sh <tag> <out-dir>" >&2
  exit 2
}
[[ $# -eq 2 && -n "$2" ]] || usage
tag="$1"
repo="${GITHUB_REPOSITORY:-TzunAI/tzun-verify}"

fail() {
  echo "fetch-release: $*" >&2
  exit 1
}

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "'$tag' is not a release tag, v<major>.<minor>.<patch>[-<pre>]"
version="${tag#v}"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
[[ -z "$(ls -A "$out")" ]] || fail "$out is not empty"
base="https://github.com/$repo/releases/download/$tag"

if ! curl -fsSL --retry 3 -o "$out/SHA256SUMS" "$base/SHA256SUMS"; then
  fail "no SHA256SUMS at $base: the release is not published, or the repository is not public"
fi

names=()
for t in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
  names+=("tzun-verify_${version}_$t.tar.gz")
done
for name in "${names[@]}"; do
  lines="$(awk -v n="$name" '$2 == n' "$out/SHA256SUMS")"
  [[ -n "$lines" && "$lines" != *$'\n'* ]] || fail "SHA256SUMS does not list $name exactly once"
  printf '%s\n' "$lines" >>"$out/SHA256SUMS.homebrew"
  curl -fsSL --retry 3 -o "$out/$name" "$base/$name"
done
echo "== the archives match SHA256SUMS"
(cd "$out" && sha256sum --check --strict SHA256SUMS.homebrew)
rm "$out/SHA256SUMS.homebrew"

echo "== each archive's build provenance"
for name in "${names[@]}"; do
  gh attestation verify "$out/$name" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "refs/tags/$tag" --deny-self-hosted-runners
done
