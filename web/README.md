# The browser page

A static page that verifies a b1 proof bundle in the browser, with
tzun-verify compiled to WebAssembly. The bundle is read by the page and never
uploaded; nothing needs installing.

## What it does

The auditor chooses, as with the command's flags:

| Input | Flag it becomes |
|---|---|
| The bundle: dropped on the page, or chosen with the file picker | the bundle argument |
| The publisher manifest: the one bundled with the page (the copy pinned in this build, its SHA-256 shown), a file of their own, or none | none, `--publishers`, `--no-publishers` |
| Timestamp authority roots and intermediates, as PEM (optional) | `--tsa-roots`, `--tsa-intermediates` |
| Offline, or an Ethereum JSON-RPC endpoint of their choosing, with the finality and lookup options | `--evm-rpc`, `--confirmations`, `--accept-non-final`, `--no-tx-lookup`, `--timeout` |
| Their regime (optional) | `--require`, `--allow-unchecked` |

The page shows the command line those choices make, then runs the command
itself on them: `cmd/tzun-verify-wasm` hands the flags and the bytes of every
file they name to `internal/cli.RunBytes`, which is `tzun-verify` reading
from memory instead of from disk. The report, the rows and the exit code are
the command's own; `internal/corpus/bytes_test.go` holds the two to the same
bytes on every case of the b1 corpus.

It shows every row with its outcome and reason, its facts, and a link to each
section of the specification it cites (`Anchor §10.5` is
https://spec.tzun.ai/anchor/1/#s10-5; `spec.js` maps the names, and the test
holds it to the README's table), the exit code with its meaning, and offers
the JSON report and the text report for download, byte for byte what
`tzun-verify --json` and `tzun-verify` print.

## What leaves the browser

Nothing but the header-source requests. Offline, the page makes no request at
all once it has loaded, and says so: the on-chain lookup is skipped, so
`anchor.evm.canonical` reads NOT CHECKED, `input_not_supplied:evm_header_source`.
With an endpoint, the page states the URL before any request is made, and the
verifier asks that endpoint, and no other host, through the browser's
`fetch` (Go's HTTP client uses `fetch` in a browser): `eth_chainId`,
`eth_getBlockByNumber` and, unless turned off, `eth_getTransactionByHash`.
The report names the endpoint by its chain and finality only, never by its
URL.

The page has no third-party script, no analytics and no web font. Its
Content-Security-Policy, in `_headers` and in a meta tag, allows scripts and
styles from the page's own origin only, WebAssembly compilation, no inline
script or style, Trusted Types with no policy, and requests to its own origin,
to `https:` and to a node on localhost, which the auditor-chosen endpoint
needs. `Referrer-Policy: no-referrer` keeps the page's address from the
endpoint.

## Build, serve and test

With Go (the toolchain go.mod pins; `GOTOOLCHAIN=auto` fetches it) and
Node.js:

```
web/build.sh          # web/dist: the wasm, Go's wasm_exec.js, the page
web/serve.sh          # build, then serve web/dist on http://127.0.0.1:8787/
```

`web/build.sh` prints the wasm's size, gzipped size and SHA-256; the page
shows the SHA-256 of the wasm it loaded, and the version of the verifier. The
wasm is built with the release flags (`-trimpath -buildvcs=false -tags
purego`). `wasm_exec.js` is copied from the toolchain that built the wasm,
since the two must match, and is not committed.

The Playwright test serves `web/dist` with `serve.mjs`, which sends the
headers of `_headers`, and drives the page in Chromium on corpus cases: a
pass and a failure offline, a verification against a JSON-RPC endpoint the
test answers from a case's header source, and inputs the verifier refuses.
It checks the report against the case's expected report, every row of the
table, that nothing is requested offline and that only the named endpoint is
asked online, that there is no sideways scrolling at 375 px, and that the
console stays clean. It writes screenshots at 1280 px and 375 px to
`SCREENSHOT_DIR` (default `web/test-results/screenshots`).

```
web/build.sh
cd web && npm ci && npx playwright install chromium && npx playwright test
```

## Files

```
index.html            the page
app.js                the flags from the choices, the run, the report
spec.js               specification links: document names to addresses, rows to sections
style.css             the page's styles (system fonts)
favicon.svg           the tab icon
_headers              the response headers for a static host
build.sh, serve.sh    build web/dist; build and serve it locally
serve.mjs             the local server, which sends the headers of _headers
test/page.spec.mjs    the Playwright test
```

Where the page will be hosted is decided with the rest of the public launch.
