# The Homebrew formula

`brew install` for tzun-verify on macOS and Linux: a formula that installs a
release's binary, never a build of its own, from the release's archives and
with the SHA-256 its `SHA256SUMS` gives. It is made from a template for each
release, tested here, and published to a TzunAI tap, which does not exist
yet ("Publishing to the tap").

## The files

| File | What it is |
|---|---|
| `tzun-verify.rb.in` | The formula, with placeholders for the version, the URLs and SHA-256s, and the test block's bundle. |
| `render-formula.sh` | Fills the template from a release's `SHA256SUMS`, and writes the formula to standard output. |
| `test-formula.sh` | Installs and tests a formula in Homebrew's own container. |
| `fetch-release.sh` | Downloads a published release's archives and checks them against `SHA256SUMS` and their build provenance. |
| `propose-to-tap.sh` | Opens a pull request of a formula in the tap. |
| `tzun-verify-release.sts.yaml` | The tap's trust policy for the publish job's token, to copy into the tap. |

`.github/workflows/homebrew.yml` runs them.

## What the formula installs

The archive of the platform brew runs on, from the release's files
(RELEASING.md, "The files"), for the four platforms Homebrew supports:

| Homebrew | Archive |
|---|---|
| macOS, Apple silicon | `tzun-verify_<version>_darwin_arm64.tar.gz` |
| macOS, Intel | `tzun-verify_<version>_darwin_amd64.tar.gz` |
| Linux, arm64 | `tzun-verify_<version>_linux_arm64.tar.gz` |
| Linux, x86_64 | `tzun-verify_<version>_linux_amd64.tar.gz` |

It installs the archive's `tzun-verify` as `bin/tzun-verify`, byte for byte
the release's binary for that platform. brew refuses an archive whose SHA-256
is not the formula's. Its version is the release's, and its `livecheck`
follows the repository's latest release.

## Its test

`brew test tzun-verify` runs the installed binary on one bundle of the b1
conformance corpus, `testdata/vectors/bundle-b1/unanchored-pending-stripped`,
which the formula carries with the corpus's test timestamping root:

- `--version` names the formula's version;
- with that root, every check the record holds is correct: exit 0, and a
  `tzun-verify-report/1` report with nothing wrong and the record's timestamp
  as its `existedBy`;
- without the root, the timestamp's trust is not checked: exit 4;
- `--require anchor`, which this unanchored record cannot meet: exit 3;
- the record's `humanAction` changed: `digest_mismatch`, exit 1.

`render-formula.sh` embeds the bundle and the root from the tree it runs in,
so a formula rendered from a tagged tree tests that tag's corpus, and it
stops if the case no longer expects exit 0.

## Rendering it

```
packaging/homebrew/render-formula.sh <version> <SHA256SUMS> [<url-base>] >tzun-verify.rb
```

`<url-base>` defaults to the release's download URL,
`https://github.com/TzunAI/tzun-verify/releases/download/v<version>`. The
script stops unless `SHA256SUMS` lists each of the four archives exactly once
for that version.

## Testing it

`test-formula.sh` needs docker, and makes its container with `docker create`,
`docker cp` and `docker start`, never a bind mount. The image is
`ghcr.io/homebrew/brew`, pinned by digest in the script.

```
dir="$(mktemp -d)/release"
scripts/release-artifacts.sh "$dir"      # Go 1.27.1, GNU tar, gzip and zip
packaging/homebrew/test-formula.sh --local "$dir"
```

`--local` renders the formula for a release directory built on this machine,
with `file://` URLs into a copy of it in the container. There, as Homebrew's
own user, the formula goes into a local tap, and:

1. `brew style` and `brew audit --strict` pass;
2. on every platform `brew info --variations` evaluates the formula for
   (each macOS release on Apple silicon and Intel, and Linux on arm64 and
   x86_64), it downloads that platform's archive, whose SHA-256 is the
   formula's;
3. `brew install` installs the container's platform's archive, and its binary
   is byte for byte the release's;
4. `brew test` passes;
5. with a wrong SHA-256 for the archive the container installs, `brew
   install` fails on the checksum and installs nothing; with a wrong SHA-256
   for that archive or for the darwin/arm64 one, step 2 fails, naming it.

Given a formula already rendered instead, `test-formula.sh [--online]
<formula.rb>` runs steps 1 to 4 on the URLs it names; `--online` adds brew
audit's online checks.

## In CI

`.github/workflows/homebrew.yml` has two jobs:

- **formula**, on a pull request (out of draft) that changes this directory,
  the workflow, `scripts/release-artifacts.sh`, `scripts/reproducible-build.sh`
  or the corpus case the test uses, on every `v*` tag, and when run by hand
  (**Run workflow** on the Actions page, for any branch): builds the release
  files with `scripts/release-artifacts.sh`, exactly as the release workflow
  does, and runs `test-formula.sh --local` on them. It publishes nothing.
  While the repository is not public it skips pull requests, to spare the
  plan's GitHub-hosted minutes; run it by hand on the branch instead.
- **publish**, on the push of a final release's `v*` tag (none with a `-`),
  and only once the repository variable `BREW_TAP_REPO` names the tap. It
  waits for approval in the `homebrew-tap` environment, then:
  1. `fetch-release.sh` downloads the four archives and `SHA256SUMS`
     anonymously from the published release, and checks each archive
     against `SHA256SUMS` and with `gh attestation verify` (the release
     workflow, at the tag, on a GitHub-hosted runner);
  2. the published `SHA256SUMS` must be identical to the one the formula job
     built from the tag;
  3. `render-formula.sh` renders the formula, and `test-formula.sh --online`
     installs and tests it from the published release;
  4. octo-sts exchanges the job's OIDC token for a token that may push to the
     tap and open a pull request there, as the tap's trust policy allows, and
     `propose-to-tap.sh` opens the pull request of `Formula/tzun-verify.rb` on
     the branch `tzun-verify-<version>`.

  No secret is stored anywhere: the tap token lives for the job, and only
  this job, in this environment, for a final release's tag, can obtain it.

## Publishing to the tap

Nothing is published yet: there is no tap. Homebrew names a tap `<owner>/tap`
after the repository `<owner>/homebrew-tap`, so the tap is the TzunAI
organisation's `homebrew-tap` repository, and users will run `brew install`
with the organisation, `tap` and `tzun-verify` as the formula's name.

### Once, before the first release the tap carries

1. **This repository is public.** The formula downloads the release's files
   anonymously, and GitHub attests build provenance only for public
   repositories on the organisation's plan, so there are no attestations to
   check before.
2. **Create the tap**: a public repository named `homebrew-tap` in the TzunAI
   organisation, with a `Formula` directory. `brew tap-new` writes a
   starting point whose `tests.yml` runs `brew test-bot` on every pull
   request, on macOS and Linux; keep that. Leave out its `publish.yml`
   (bottles) and `autobump.yml`: this formula installs release binaries, so
   there is nothing to bottle, and `brew bump` cannot update four
   per-platform SHA-256s. Protect its default branch: pull requests only.
3. **Install the octo-sts GitHub App** (octo-sts.dev, or a self-hosted
   instance) on the tap repository only, and add
   `tzun-verify-release.sts.yaml` to the tap at
   `.github/chainguard/tzun-verify-release.sts.yaml`. It grants the publish
   job, and nothing else, `contents: write` and `pull_requests: write` on the
   tap. This is the trust decision to take here: the App holds write access
   to the tap, and mints tokens for any identity a policy in the tap names.
4. **Create the `homebrew-tap` environment** in this repository: required
   reviewers (the people who publish releases), deployments from tags
   matching `v*` only, and no secrets.
5. **Set the repository variable `BREW_TAP_REPO`** to `homebrew-tap`. Until
   it is set, the publish job is skipped.
6. **Let the hygiene check name the tap**: add `homebrew-tap` and `tap` to the
   repositories `scripts/check-public-hygiene.sh` allows, so that README can
   give the exact `brew install` line.
7. **A licence**: this repository has no licence file yet, so the formula
   states no `license`. Add one to the template with the file. A tap does not
   require it; Homebrew's own repository does.

### For each release

1. Publish the draft release as RELEASING.md says.
2. Approve the waiting publish job of the Homebrew workflow's run for the
   tag. Approved before the release is published, it fails at its first
   check and can be re-run. The formula job's `SHA256SUMS` it compares with
   is kept for 30 days after the tag's run; after that, re-run all jobs.
3. Merge the pull request it opens in the tap once the tap's checks pass.
   From then on `brew upgrade` finds the new version.

A pre-release tag (`v0.2.0-rc.1`) runs the formula job only.

## homebrew-core

Homebrew's own repository builds every formula from source, so a formula
there would be another one: the tagged source archive, `depends_on "go" =>
:build`, and `go build` with the flags of `scripts/reproducible-build.sh`,
keeping this test block. It also asks for a licence and for signs of use
(stars, forks, watchers) the repository does not have yet. The tap's formula
installs the release binaries themselves, the same bytes as every other way
of installing a release.
