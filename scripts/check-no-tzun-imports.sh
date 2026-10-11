#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Tzun, Inc.
# SPDX-License-Identifier: BSD-3-Clause-Clear
#
# tzun-verify imports nothing from Tzun. Every package the build and the tests
# link, and every module in the build list, must come from somewhere whose
# path does not name Tzun, this module excepted.
set -euo pipefail
cd "$(dirname "$0")/.."

self="$(go list -m)"
bad=0

names_tzun() { # names_tzun <path>: true when the path names Tzun
  [[ "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" == *tzun* ]]
}

# Packages the command, the libraries and the tests link, with their modules.
# A test variant's import path holds a space ("p [p.test]"), so fields are
# split on "|".
while IFS='|' read -r pkg mod; do
  [[ "$mod" == "$self" ]] && continue
  if names_tzun "$pkg $mod"; then
    echo "Tzun package linked: $pkg (module ${mod:-none})"
    bad=1
  fi
done < <(go list -deps -test -f '{{.ImportPath}}|{{with .Module}}{{.Path}}{{end}}' ./...)

# The whole module graph, including modules no package is linked from.
while read -r mod _; do
  if [[ "$mod" != "$self" ]] && names_tzun "$mod"; then
    echo "Tzun module required: $mod"
    bad=1
  fi
done < <(go list -m all)

if [[ "$bad" -ne 0 ]]; then
  echo "FAIL: tzun-verify must not depend on Tzun code"
  exit 1
fi
echo "OK: no Tzun package or module besides $self"
