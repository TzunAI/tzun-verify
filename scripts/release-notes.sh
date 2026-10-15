#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Tzun, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# Prints a release's notes in Markdown: the specification versions the
# release implements (the table under "Specification" in README.md, as the
# tagged tree states it), the SHA-256 of the publisher manifest it pins, how
# to check its files against SHA256SUMS and the attestation file, and its
# SHA256SUMS. The release workflow writes the draft release's notes with it.
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
manifest="$(sha256sum publishers/publishers.json | cut -d' ' -f1)"

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

For linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64: the binary \`tzun-verify_${version}_<os>_<arch>\` (\`.exe\` on Windows) and an archive holding it with README.md, LICENSE, NOTICE and LICENSE-THIRD-PARTY (\`.tar.gz\`; \`.zip\` on Windows). \`LICENSE-THIRD-PARTY\` also stands alone: the licence of every module a binary links. \`SHA256SUMS\` gives the SHA-256 of each of those files, and each has a build provenance attestation, which \`tzun-verify_${version}.intoto.jsonl\` holds: a Sigstore bundle, signed in this release's workflow run. \`SHA256SUMS\` does not list that file, which no rebuild reproduces.

Every binary was built twice on each of two machines, from two clean checkouts of this tag, and every file (binaries and archives) was identical byte for byte across the two machines. Anyone can rebuild them with \`scripts/release-artifacts.sh\` and compare (RELEASING.md).

## Publisher manifest

This release pins a byte-for-byte copy of https://tzun.ai/anchors/publishers.json (Anchor §9), SHA-256 \`$manifest\`; \`tzun-verify --version\` prints it. When the file at that address has another digest, pass it with \`--publishers\`.

## Checking a download

\`\`\`
grep " tzun-verify_${version}_linux_amd64.tar.gz\$" SHA256SUMS | sha256sum --check
gh attestation verify tzun-verify_${version}_linux_amd64.tar.gz --repo TzunAI/tzun-verify \\
  --bundle tzun-verify_${version}.intoto.jsonl \\
  --signer-workflow TzunAI/tzun-verify/.github/workflows/release.yml \\
  --source-ref refs/tags/v${version} --deny-self-hosted-runners
\`\`\`

With \`--bundle\`, gh reads the attestation from \`tzun-verify_${version}.intoto.jsonl\` and needs no login; without it, gh fetches the same attestation from GitHub. README.md, "Install", says more.

## SHA256SUMS

\`\`\`
$sums
\`\`\`
EOF
