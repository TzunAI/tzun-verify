# Releasing tzun-verify

A release is a `v<version>` tag on a commit of `main`, where `<version>` is
the `Version` constant in `internal/cli/cli.go`. The version is set in
source, never by a linker flag, so a rebuild of the tagged tree reproduces
the binary. Pushing the tag starts two workflows:

- `.github/workflows/ci.yml`: the checks every pull request runs, and the
  release gate (`scripts/release-gate.sh`: the reproducible build of every
  target, and every mutation killed);
- `.github/workflows/release.yml`: the release files, built on two machines
  and compared, their build provenance attested, and a **draft** release
  holding them.

Nothing is published until a person publishes the draft.

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
  (README, "Install from a release").

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

   and compare the `SHA256SUMS` it prints with the draft's.
5. Publish the draft. Then set `Version` to the next version with a `-dev`
   suffix on `main`.

If a check fails, nothing has been published: delete the tag (and the draft,
if one was made), fix the cause on `main`, and tag again.
