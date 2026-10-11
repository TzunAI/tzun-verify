#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Tzun, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# Every Go file of this repository, the tests included, begins with its SPDX
# licence line, the one `want` holds below, followed by a blank line, so the
# line is never part of a package's doc comment. The files checked are the
# ones git tracks or would add (untracked and not ignored), as in the working
# tree.
set -euo pipefail
cd "$(dirname "$0")/.."

# The REUSE markers keep the line from reading as this script's own licence.
# REUSE-IgnoreStart
want='// SPDX-License-Identifier: BSD-3-Clause-Clear'
# REUSE-IgnoreEnd
bad=0
n=0

while IFS= read -r -d '' f; do
  [[ -f "$f" ]] || continue
  n=$((n + 1))
  first="$(sed -n '1p' "$f")"
  second="$(sed -n '2p' "$f")"
  if [[ "$first" != "$want" ]]; then
    echo "$f:1: the first line is not \"$want\""
    bad=1
  elif [[ -n "$second" ]]; then
    echo "$f:2: the licence line is not followed by a blank line"
    bad=1
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- '*.go')

if [[ "$bad" -ne 0 ]]; then
  echo "FAIL: every Go file begins with \"$want\" and a blank line"
  exit 1
fi
echo "OK: $n Go files begin with \"$want\""
