#!/usr/bin/env bash
# Prints a release's notes in Markdown: the specification versions the
# release implements (the table under "Specification" in README.md, as the
# tagged tree states it), how to check its files, and its SHA256SUMS. The
# release workflow writes the draft release's notes with it.
#
#   scripts/release-notes.sh <version> <SHA256SUMS>
set -euo pipefail

if [[ $# -ne 2 || -z "$1" || ! -f "$2" ]]; then
  echo "usage: scripts/release-notes.sh <version> <SHA256SUMS>" >&2
  exit 2
fi
version="$1"
sums="$(cat "$2")"
cd "$(dirname "$0")/.."

# The table starts at its header row and ends at the first line that is not
# a table row.
table="$(awk '/^\| Name \| Document \| Version \|/ { on = 1 } on && /^\|/ { print; next } on { exit }' README.md)"
if [[ "$(grep -c '^|' <<<"$table")" -lt 3 ]]; then
  echo "release-notes: README.md has no specification table (a row starting '| Name | Document | Version |')" >&2
  exit 1
fi
if [[ -z "$sums" ]]; then
  echo "release-notes: $2 is empty" >&2
  exit 1
fi

cat <<EOF
tzun-verify $version implements these versions of the DEO verification specification, published at https://spec.tzun.ai/:

$table

## Files

For linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64: the binary \`tzun-verify_${version}_<os>_<arch>\` (\`.exe\` on Windows) and an archive holding it with README.md (\`.tar.gz\`; \`.zip\` on Windows). \`SHA256SUMS\` gives the SHA-256 of every file, and every file has a build provenance attestation.

Every file was built on two machines from two clean checkouts of this tag, each machine building it twice, and every build agreed byte for byte. Anyone can rebuild them with \`scripts/release-artifacts.sh\` and compare (RELEASING.md).

## Checking a download

\`\`\`
grep " tzun-verify_${version}_linux_amd64.tar.gz\$" SHA256SUMS | sha256sum --check
gh attestation verify tzun-verify_${version}_linux_amd64.tar.gz --repo TzunAI/tzun-verify \\
  --signer-workflow TzunAI/tzun-verify/.github/workflows/release.yml \\
  --source-ref refs/tags/v${version} --deny-self-hosted-runners
\`\`\`

README.md, "Install from a release", says more.

## SHA256SUMS

\`\`\`
$sums
\`\`\`
EOF
