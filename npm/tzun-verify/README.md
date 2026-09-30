# tzun-verify

The standalone verifier for Tzun DEO proof bundles. It checks a record's b1
proof bundle offline, without Tzun code and without asking Tzun, and says
for each check whether it is correct, wrong or not checked.

```
npx tzun-verify record-42.json
```

or, to keep the `tzun-verify` command:

```
npm install -g tzun-verify
tzun-verify record-42.json
```

No Go toolchain is needed. The flags, the report and the exit codes are the
command's own, described in the
[README](https://github.com/TzunAI/tzun-verify#readme) of the repository:
`tzun-verify --help` lists the flags, `--json` prints the
`tzun-verify-report/1` JSON report, and the exit code is the verifier's
(0 nothing wrong and everything present checked, 1 something is wrong, 2 the
bundle could not be read or was abstained on as a whole, 3 a `--require` or
`--require-rung` was not met, 4 something present was not checked, 64 a
usage error).

## What this package runs

This package holds a small launcher. The binary it runs is in a second
package, one per platform, which npm installs with this one as an optional
dependency:

| Platform | Package | Release file |
|---|---|---|
| Linux x64 | `tzun-verify-linux-x64` | `tzun-verify_<version>_linux_amd64` |
| Linux arm64 | `tzun-verify-linux-arm64` | `tzun-verify_<version>_linux_arm64` |
| macOS x64 | `tzun-verify-darwin-x64` | `tzun-verify_<version>_darwin_amd64` |
| macOS arm64 | `tzun-verify-darwin-arm64` | `tzun-verify_<version>_darwin_arm64` |
| Windows x64 | `tzun-verify-win32-x64` | `tzun-verify_<version>_windows_amd64.exe` |

Each package's binary is byte for byte the release file of the same version
on the [GitHub releases](https://github.com/TzunAI/tzun-verify/releases)
page, and the packages are published from the release's own `SHA256SUMS`
and build provenance, which the package's README repeats. No package has an
install script, and nothing is downloaded at install or when the command
runs. The Linux binaries are static, so they run on glibc and musl systems
alike.

To check an installed binary yourself, compare its SHA-256 with the release's
`SHA256SUMS`, or check its attestation with the GitHub CLI:

```
sha256sum node_modules/tzun-verify-linux-x64/bin/tzun-verify
gh attestation verify node_modules/tzun-verify-linux-x64/bin/tzun-verify \
  --repo TzunAI/tzun-verify \
  --signer-workflow TzunAI/tzun-verify/.github/workflows/release.yml
```

`npm audit signatures` checks the packages' own npm provenance.

If the command says the package for your platform is not installed, npm
left the optional dependency out: install without `--omit=optional`, and
without a lockfile made on another platform. Other platforms can build the
verifier from source (the repository's README, "How to run it").
