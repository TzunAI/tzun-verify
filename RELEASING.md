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
  holding them.

Nothing is published until a person publishes the draft ("Cutting a
release"). Packages for npm, PyPI and Homebrew are planned (#2, #3, #4);
none exists yet.

## Versions

| Version | GitHub release |
|---|---|
| final: `0.2.0` | a release |
| pre-release: `0.2.0-rc.1`, `0.2.0-beta.2`, `0.2.0-alpha` | a pre-release |
| development: `0.2.0-dev` | refused |

A development version is what `main` carries between releases (step 5
below). `scripts/release-artifacts.sh` refuses its tag, and the release
workflow makes the release files with it, so nothing is built for it.

## The files

These names are an interface: the planned packages will take their
binaries from them, and anyone checking a release reads them, so a change
to a name, to an archive's layout or to the format of `SHA256SUMS` is a
change to document here and in the release notes.

`<version>` is the tag without its `v` (tag `v0.1.0`, version `0.1.0`).
`<os>` and `<arch>` are Go's `GOOS` and `GOARCH`.

| Target | Binary | Archive |
|---|---|---|
| linux/amd64 | `tzun-verify_<version>_linux_amd64` | `tzun-verify_<version>_linux_amd64.tar.gz` |
| linux/arm64 | `tzun-verify_<version>_linux_arm64` | `tzun-verify_<version>_linux_arm64.tar.gz` |
| darwin/amd64 | `tzun-verify_<version>_darwin_amd64` | `tzun-verify_<version>_darwin_amd64.tar.gz` |
| darwin/arm64 | `tzun-verify_<version>_darwin_arm64` | `tzun-verify_<version>_darwin_arm64.tar.gz` |
| windows/amd64 | `tzun-verify_<version>_windows_amd64.exe` | `tzun-verify_<version>_windows_amd64.zip` |

and once, `LICENSE-THIRD-PARTY` and `SHA256SUMS`: twelve files in all. For
version `0.1.0`, the linux/amd64 binary is `tzun-verify_0.1.0_linux_amd64`
and its archive `tzun-verify_0.1.0_linux_amd64.tar.gz`.

- **Binary**: the executable, byte for byte the one in the archive. Release
  downloads carry no file mode, so it needs `chmod +x` on Linux and macOS.
- **Archive**: five files at its root, no directory: the executable, named
  `tzun-verify` (`tzun-verify.exe` in the zip), mode 0755, and the tagged
  tree's `README.md`, `LICENSE`, `NOTICE` and
  `third_party/LICENSE-THIRD-PARTY` (as `LICENSE-THIRD-PARTY`), mode 0644.
  Owner 0, group 0, every time the tagged commit's. A `.tar.gz` is a ustar archive compressed by `gzip -n`; the zip
  is written by Info-ZIP `zip -X`.
- **`LICENSE-THIRD-PARTY`**: the tagged tree's
  `third_party/LICENSE-THIRD-PARTY`, the licence of every module a binary
  links, as each module ships it.
- **`SHA256SUMS`**: one line per file above, `<sha256 hex>  <name>` (two
  spaces), sorted by name, as `sha256sum` writes it. It does not list itself.
- **Attestation**: one SLSA build provenance attestation
  (`https://slsa.dev/provenance/v1`) whose subjects are the eleven files
  that `SHA256SUMS` lists, signed for `.github/workflows/release.yml` at the tag,
  on a GitHub-hosted runner. `gh attestation verify` checks any of them
  (README, "Install").

The release notes list the specification versions the release implements,
from the table under "Specification" in the tagged tree's README, the
SHA-256 of the publisher manifest it pins, then `SHA256SUMS` itself
(`scripts/release-notes.sh`).

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

## Repository settings a release relies on

- Releases are immutable (the repository's release settings), so a
  published release's files and tag cannot change.
- A tag ruleset lets only the people who publish releases create, move or
  delete `v*` tags.

## Cutting a release

1. On a branch, set `Version` in `internal/cli/cli.go` to the release's
   version, and the version in README's sample output ("What it prints") to
   match. Copy the bytes served at https://tzun.ai/anchors/publishers.json
   to `publishers/publishers.json`, and update the README's paragraph on the
   pinned manifest to match (Anchor §9: each release pins a copy, byte for
   byte). Merge it to `main`.
2. Tag that commit of `main` and push the tag:

   ```
   git tag -a v0.1.0 -m "tzun-verify 0.1.0" <commit>
   git push origin v0.1.0
   ```

3. Wait for both workflows on the tag. `release.yml` ends with a draft
   release; `ci.yml`'s release gate must be green too.
4. Check the draft: twelve files, `SHA256SUMS` as the notes show it, the
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

If a check fails before step 5, nothing has been published: delete the tag
(and the draft, if one was made), fix the cause on `main`, and tag again.
Once the release is published, a wrong release is fixed by the next
version, never by moving its tag.
