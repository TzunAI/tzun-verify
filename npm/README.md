# The npm packages

`npx tzun-verify <bundle.json>` and `npm install -g tzun-verify` run the
release binary without a Go toolchain. Six packages make that up, all at the
release's version:

| Package | Holds |
|---|---|
| `tzun-verify` | `bin/tzun-verify.js`, the launcher; each package below as an optional dependency |
| `tzun-verify-linux-x64` | `bin/tzun-verify`, the release file `tzun-verify_<version>_linux_amd64` |
| `tzun-verify-linux-arm64` | `bin/tzun-verify`, the release file `tzun-verify_<version>_linux_arm64` |
| `tzun-verify-darwin-x64` | `bin/tzun-verify`, the release file `tzun-verify_<version>_darwin_amd64` |
| `tzun-verify-darwin-arm64` | `bin/tzun-verify`, the release file `tzun-verify_<version>_darwin_arm64` |
| `tzun-verify-win32-x64` | `bin/tzun-verify.exe`, the release file `tzun-verify_<version>_windows_amd64.exe` |

Each platform package declares its `os` and `cpu`, so npm installs the one
for the machine and skips the others. The launcher finds it, requires it to
be of its own version, and runs its binary with the same arguments, standard
streams and exit code. When there is none it says why and exits 127. No
package has an install script, and nothing is downloaded at install or at
run time.

## Files

```
npm/tzun-verify/     the tzun-verify package: the launcher, its README (the
                     package's npm page) and package.json, a template that
                     stage.js completes (it is marked private, so it cannot
                     be published as it stands)
npm/stage.js         makes and packs all six packages from a release's files
npm/test.js          installs and runs the packages on this machine
```

`.github/workflows/npm.yml` runs them.

## Making the packages

```
scripts/release-artifacts.sh "$dist"          # the release files (RELEASING.md)
node npm/stage.js "$dist" "$out" [<version>]  # the packages, packed
```

`stage.js` reads the release files through `SHA256SUMS` and the names
RELEASING.md fixes. It refuses a binary whose SHA-256 is not the one
`SHA256SUMS` lists, a binary whose header is for another platform than its
package's, a version other than `<version>` when one is given, and a release
whose targets are not exactly the five platforms the launcher knows (a new
release target needs a package here first). It writes each package's
directory and tarball into `$out`, checks each tarball holds exactly its
files with their modes, and writes `publish-order.txt`: the platform
packages, then `tzun-verify`.

## Testing them

```
node npm/test.js "$out" "$dist"
```

On the machine it runs on, `test.js`:

- installs `tzun-verify` and the machine's platform package from their
  tarballs into an empty project, with `npm --offline` and an empty cache,
  and checks that no other platform package came along, that the installed
  binary is byte for byte the release file, and that no package has scripts;
- runs every case of the conformance corpus (`testdata/vectors/bundle-b1`,
  its `inputs.json` as flags) as `npx tzun-verify` and as the release binary,
  with `--json` and without: standard output, standard error and exit code
  must be the same (the report's `checkedAt` aside), and the JSON report must
  be the case's `expected-report.json`, with its `expected-exit`;
- does the same for `--version`, `--help`, usage errors, and paths with
  spaces, quotes and shell characters, then for a global install;
- checks the launcher's errors: no platform package, one of another version,
  a platform it has no package for;
- serves the tarballs from a registry on 127.0.0.1 that holds nothing else,
  runs a bare `npx tzun-verify` from an empty directory against it (only
  `tzun-verify` and the machine's package may be downloaded), and installs
  `tzun-verify` once as each platform (`npm install --os --cpu`): exactly
  that platform's package must come, and the launcher must pick its binary.

The workflow runs it on each platform (Linux x64 and arm64, macOS x64 and
arm64, Windows x64) once the repository is public, and on one Linux runner
while it is not.

## Publishing

On a `v<version>` tag, `npm.yml` builds the release files again (the build
is reproducible), makes and tests the packages on every platform, and then
its `publish` job, which runs only while the repository is public, waits for
a reviewer in the `npm` environment and:

1. requires the tag's GitHub release to be **published**: it downloads the
   release's `SHA256SUMS` anonymously from the release's public URL, where a
   draft serves nothing whatever token the job holds, so while the release
   is a draft the job stops before staging anything;
2. requires the release's `SHA256SUMS` to be the one built here, line for
   line, and each packaged binary to be listed in it and to pass
   `gh attestation verify` against the release workflow's attestation for
   the tag;
3. stages the six tarballs on npm with `npm stage publish`, platform
   packages first, with provenance, through trusted publishing: the job
   holds no npm token.

A staged package is not public. A maintainer approves each one on npm with
two-factor authentication (`npm stage list`, `npm stage approve <stage-id>`,
or the package's "Staged Packages" tab): the platform packages first,
`tzun-verify` last, so that nobody installs a `tzun-verify` whose platform
package is not there yet.

So a release, after RELEASING.md's steps, is:

1. Publish the GitHub release (RELEASING.md, step 5).
2. On the tag's run of the `npm` workflow, approve the `publish` job waiting
   for the `npm` environment. Approved before the release was published, it
   stops at its first check: re-run it once the release is published. The
   run's tarballs and binaries are kept for 30 days; after that, **Re-run all
   jobs** builds them again.
3. Approve the six staged packages on npm, `tzun-verify` last.

If staging stops part way, reject what was staged (`npm stage reject`)
before running it again.

### Once, before the first release

- **The names.** npm lets a trusted publisher be configured only for a
  package that exists. Staging a package that does not exist yet creates it
  with a placeholder version, `0.0.0-stage`; a maintainer logged in to npm
  does that once for each of the six names.
- **Trusted publishers.** On each of the six packages: GitHub Actions,
  organization `TzunAI`, repository `tzun-verify`, workflow `npm.yml`,
  environment `npm`, and allowed to stage only, not to publish. Then, under
  the package's publishing access, require two-factor authentication and
  disallow tokens.
- **The `npm` environment** in the repository's settings, created **before
  the first tag is pushed**: required reviewers (the people who publish
  releases) and deployments from tags matching `v*` only. GitHub creates an
  environment a job names when it does not exist, with no protection rules,
  and the `publish` job would then stage without waiting for anyone.

npm attaches provenance only for packages published from a public
repository, and GitHub attests the release files only for a public
repository on this plan: both need the repository to be public before the
first release.
