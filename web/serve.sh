#!/usr/bin/env bash
# Builds the page (web/build.sh) and serves web/dist on 127.0.0.1, with the
# headers of web/_headers, until interrupted. Needs Go and Node.js.
#
#   web/serve.sh [port]    default 8787
set -euo pipefail
cd "$(dirname "$0")/.."
web/build.sh
exec node web/serve.mjs --port "${1:-8787}"
