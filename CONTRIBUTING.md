# Contributing

tzun-verify is an implementation of the DEO verification specification
published at [spec.tzun.ai](https://spec.tzun.ai/), written without any Tzun
code so that it checks Tzun's records independently. Most of what follows
comes from that.

## Where to go

- A question, or an idea that is not yet a concrete change:
  [Discussions](https://github.com/TzunAI/tzun-verify/discussions).
- tzun-verify crashes, hangs or misbehaves: an issue, with the bug report
  form.
- tzun-verify gives a result the specification or a conformance vector says
  it must not give: an issue, with the conformance form.
- The specification's text looks wrong or unclear: a discussion.
- A security problem: [`SECURITY.md`](SECURITY.md), never a public issue.

Proof bundles can hold personal data. Before you attach one to an issue,
remove it or build a minimal case that shows the same thing.

## The specification governs

Where this repository and the specification differ, the specification
governs and the difference is a defect here. A change in behaviour names the
section that requires it, cited as the README describes (`Record §3.2`), and
comes with a test or a vector case that fails without it.

## Building and testing

Use the toolchain go.mod pins (`toolchain` line); CI refuses any other.
These are the checks CI runs (`.github/workflows/ci.yml`):

```
go mod tidy -diff
gofmt -l .
go vet ./...
go test -count=1 ./...
go test -count=1 -tags purego ./...
scripts/check-no-tzun-imports.sh
scripts/check-spdx-headers.sh
scripts/third-party-licenses.sh --check
scripts/reproducible-build.sh linux/amd64
```

and these are the public hygiene checks
(`.github/workflows/public-hygiene.yml`):

```
scripts/test-public-hygiene.sh
scripts/check-public-hygiene.sh tree
reuse lint
```

## What a change must keep true

- **No Tzun code.** Nothing here imports a Tzun module
  (`scripts/check-no-tzun-imports.sh`), and the code is not copied from one.
- **Stock third-party libraries.** A new dependency says in its pull request
  why the standard library and the existing ones do not do. A release binary
  ships the licence of every module it links, so `scripts/third-party-licenses.sh`
  rewrites `third_party/LICENSE-THIRD-PARTY` when the set changes.
- **Every file has a copyright and a licence.** A Go file begins with its
  SPDX licence line. Any other new file carries both in its own header
  comment or is listed in `REUSE.toml`; `reuse lint` checks it.
- **A reader outside Tzun can follow everything.** Files, commit messages and
  pull request titles and bodies refer only to this repository and to public
  places. `scripts/check-public-hygiene.sh` checks them, and the commit hook
  runs it on each message: `git config core.hooksPath .githooks`.
- **The build is reproducible.** Two clean builds of one target give the
  same bytes.

## Pull requests

Keep one change to a pull request, and say in its title what changes. A
workflow on a pull request from a fork waits for a maintainer to approve the
run. A pull request merges once both required checks pass: the CI check and
public hygiene.

## Licence of contributions

Under GitHub's Terms of Service, a contribution to this repository is made
under the repository's licence: BSD-3-Clause-Clear for the code
([`LICENSE`](LICENSE)), CC0-1.0 for the conformance vectors in
`testdata/vectors`. There is no separate contributor agreement.
