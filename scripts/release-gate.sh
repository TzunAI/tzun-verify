#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Tzun, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# The release gate: what must hold before a tzun-verify release is tagged,
# beyond the checks every pull request runs. CI runs it on every v* tag, and
# anyone can run it on a clone of this repository with the pinned toolchain:
#
#   scripts/release-gate.sh
#
#   1. Reproducible build, for every target a release publishes
#      (scripts/reproducible-build.sh).
#   2. Mutation testing: every listed mutation is killed
#      (scripts/mutation-test.sh).
#   3. Third-party licences: third_party/LICENSE-THIRD-PARTY holds the
#      licence of every module the build links for these same targets
#      (scripts/third-party-licenses.sh). A release publishes that file
#      beside its binaries.
#
# Each part prints its own verdict, and the gate fails if any does.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)
status=0

echo "== 1. reproducible build"
if scripts/reproducible-build.sh "${TARGETS[@]}"; then :; else status=1; fi

echo "== 2. mutation testing"
if scripts/mutation-test.sh -j "$(nproc 2>/dev/null || echo 4)"; then :; else status=1; fi

echo "== 3. third-party licences"
if scripts/third-party-licenses.sh --check "${TARGETS[@]}"; then :; else status=1; fi

if [[ "$status" -ne 0 ]]; then
  echo "RELEASE GATE: FAIL"
else
  echo "RELEASE GATE: OK"
fi
exit "$status"
