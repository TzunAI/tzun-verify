# Releasing tzun-verify

A release is a `v<version>` tag on a commit of `main`, where `<version>` is
the `Version` constant in `internal/cli/cli.go`. The version is set in
source, never by a linker flag, so a rebuild of the tagged tree reproduces
the binary. Pushing the tag starts these workflows:

- `.github/workflows/ci.yml`: the checks every pull request runs, and the
  release gate (`scripts/release-gate.sh`: the reproducible build of every
  target, and every mutation killed);
- `.github/workflows/release.yml`: the release files, built on two machines
  and compared, their build provenance attested, and a **draft** release
  holding them;
- the workflow of each package made from the release files: npm, PyPI and
  Homebrew. Each builds the release files again, makes and tests its
  package, and then has a publish job that waits in its environment for a
  reviewer. That job publishes nothing until the release is published and
  each file the package ships is, byte for byte, one the release's
  `SHA256SUMS` lists, with a build provenance attestation that
  `gh attestation verify` accepts.

Nothing is published until a person publishes the draft, and nothing is
published to npm, PyPI or the Homebrew tap until a reviewer approves that
channel's publish job ("Cutting a release").

## Where a release goes

| Version | GitHub release | npm | PyPI | Homebrew tap |
|---|---|---|---|---|
| final: `0.2.0` | a release | dist-tag `latest` | `0.2.0` | the formula, by a pull request in the tap |
| pre-release: `0.2.0-rc.1`, `0.2.0-beta.2`, `0.2.0-alpha` | a pre-release | dist-tag `next` | `0.2.0rc1`, `0.2.0b2`, `0.2.0a0`, which pip installs only when asked for | nothing |
| development: `0.2.0-dev` | refused | nothing | nothing | nothing |

A development version is what `main` carries between releases (step 5
below). `scripts/release-artifacts.sh` refuses its tag, and every workflow
above makes the release files with it, so nothing is built for it. A version
uploaded to PyPI can never be uploaded again, even once deleted, and a
version published on npm cannot be reused either: check the version before
approving either.

## The files

These names are an interface. The npm package, the PyPI package and the
Homebrew formula take their binaries from them, so a change to a name, to an
archive's layout or to the format of `SHA256SUMS` needs the same change in
each of them.

`<version>` is the tag without its `v` (tag `v0.1.0`, version `0.1.0`).
`<os>` and `<arch>` are Go's `GOOS` and `GOARCH`.

| Target | Binary | Archive |
|---|---|---|
| linux/amd64 | `tzun-verify_<version>_linux_amd64` | `tzun-verify_<version>_linux_amd64.tar.gz` |
| linux/arm64 | `tzun-verify_<version>_linux_arm64` | `tzun-verify_<version>_linux_arm64.tar.gz` |
| darwin/amd64 | `tzun-verify_<version>_darwin_amd64` | `tzun-verify_<version>_darwin_amd64.tar.gz` |
| darwin/arm64 | `tzun-verify_<version>_darwin_arm64` | `tzun-verify_<version>_darwin_arm64.tar.gz` |
| windows/amd64 | `tzun-verify_<version>_windows_amd64.exe` | `tzun-verify_<version>_windows_amd64.zip` |

and one `SHA256SUMS`: eleven files in all. For version `0.1.0`, the
linux/amd64 binary is `tzun-verify_0.1.0_linux_amd64` and its archive
`tzun-verify_0.1.0_linux_amd64.tar.gz`.

- **Binary**: the executable, byte for byte the one in the archive. Release
  downloads carry no file mode, so it needs `chmod +x` on Linux and macOS.
- **Archive**: two files at its root, no directory: the executable, named
  `tzun-verify` (`tzun-verify.exe` in the zip), mode 0755, and the tagged
  tree's `README.md`, mode 0644. Owner 0, group 0, every time the tagged
  commit's. A `.tar.gz` is a ustar archive compressed by `gzip -n`; the zip
  is written by Info-ZIP `zip -X`.
- **`SHA256SUMS`**: one line per file above, `<sha256 hex>  <name>` (two
  spaces), sorted by name, as `sha256sum` writes it. It does not list itself.
- **Attestation**: one SLSA build provenance attestation
  (`https://slsa.dev/provenance/v1`) whose subjects are the ten files that
  `SHA256SUMS` lists, signed for `.github/workflows/release.yml` at the tag,
  on a GitHub-hosted runner. `gh attestation verify` checks any of them
  (README, "Install").

The release notes list the specification versions the release implements,
from the table under "Specification" in the tagged tree's README, then
`SHA256SUMS` itself (`scripts/release-notes.sh`).

## How the release workflow checks a release

| Job | Machine | What it does |
|---|---|---|
| build | a fresh GitHub-hosted runner | Checks that the tagged commit is on `main` and that the toolchain is the one `go.mod` pins, then runs `scripts/release-artifacts.sh`, which refuses a tag other than `v<Version>`, builds every target twice through `scripts/reproducible-build.sh` (two copies of the tree at different paths, fresh build and module caches, identical binaries required), checks that the linux/amd64 binary's `--version` names the version, and writes the archives and `SHA256SUMS`. |
| rebuild | a second fresh runner | The same, from its own clean checkout at another path. Only its `SHA256SUMS` leaves the job. |
| attest | a third | Requires the first machine's files to be exactly those its `SHA256SUMS` names, each matching it, and the two machines' `SHA256SUMS` to be identical: any byte difference in any file stops the release here. Then attests the files' build provenance. |
| release | a fourth | Creates the draft release with the files, `SHA256SUMS` and the notes; a version with a pre-release part (`0.2.0-rc.1`) is marked a pre-release. |

Permissions are per job: `contents: read` for the builds, `id-token: write`
and `attestations: write` (with `contents: read`) for the attestation, and
`contents: write` for the draft release, which is made with the job's own
`GITHUB_TOKEN`. No job holds a long-lived secret, and no job reads a cache
another run wrote.

GitHub creates artifact attestations for public repositories on every plan,
and otherwise only on GitHub Enterprise Cloud. Without them the attest job
fails, and no draft release is made.

## Before the first release

- The repository is public: GitHub attests build provenance only for public
  repositories on this plan, and npm, PyPI and Homebrew download the
  release's files anonymously.
- The environments `npm`, `pypi` and `homebrew-tap` exist in the
  repository's settings, **before the first tag is pushed**, each with
  required reviewers (the people who publish releases) and deployments from
  tags matching `v*` only. GitHub creates an environment a job names when it
  does not exist, with no protection rules: a publish job would then run
  without waiting for anyone.
- Releases are immutable (the repository's release settings), and a tag
  ruleset lets only the people who publish releases create `v*` tags.
- Each channel's own set-up: `npm/README.md` ("Once, before the first
  release"), `python/RELEASING.md` ("Setting it up, once") and
  `packaging/homebrew/README.md` ("Once, before the first release the tap
  carries").

## Cutting a release

1. On a branch, set `Version` in `internal/cli/cli.go` to the release's
   version, and the version in README's sample output ("What it prints") to
   match. Merge it to `main`.
2. Tag that commit of `main` and push the tag:

   ```
   git tag -a v0.1.0 -m "tzun-verify 0.1.0" <commit>
   git push origin v0.1.0
   ```

3. Wait for both workflows on the tag. `release.yml` ends with a draft
   release; `ci.yml`'s release gate must be green too.
4. Check the draft: eleven files, `SHA256SUMS` as the notes show it, the
   specification versions the notes list. To check the build yourself, run
   on a clean checkout of the tag, with Go 1.27.1, GNU tar, gzip and zip:

   ```
   scripts/release-artifacts.sh "$(mktemp -d)/dist" v0.1.0
   ```

   and compare the `SHA256SUMS` it prints with the draft's. With a tag, the
   script refuses a checkout whose HEAD is not the tag's commit or whose
   tracked files have changes.
5. Publish the draft. Then set `Version` to the next version with a `-dev`
   suffix on `main`.
6. Approve the publish job waiting in each environment, on the tag's runs of
   the npm, Python package and Homebrew workflows. Each first checks the
   published release; one approved before the release was published stops
   at that check, and is re-run once it is.
7. On npm, approve the six staged packages with two-factor authentication,
   the five platform packages first and `tzun-verify` last
   (`npm/README.md`, "Publishing").
8. In the tap, merge the pull request the Homebrew workflow opened once the
   tap's checks pass. A pre-release has none.
9. Check each channel: `npx tzun-verify@<version> --version`,
   `pip install tzun-verify==<version>` (the PEP 440 spelling) and, for a
   final release, `brew upgrade`, each naming the release.

If a check fails before step 5, nothing has been published: delete the tag
(and the draft, if one was made), fix the cause on `main`, and tag again.
Once the release is published, a wrong release is fixed by the next
version, never by moving its tag.
