# Releasing the PyPI package

The PyPI package `tzun-verify` is a set of wheels, one per release target,
each carrying that target's release binary (RELEASING.md at the repository's
root names the files). Nothing in it is built from Go: `build_wheels.py`
writes the wheels from a release's files, and the publish job checks, before
it uploads anything, that each wheel's binary is the published GitHub
release's, byte for byte.

## The files here

| File | What it is |
|---|---|
| `src/tzun_verify/` | the package: `verify()`, `binary()`, `python -m tzun_verify` |
| `build_wheels.py` | writes the wheels from a release's files; `--check` compares wheels with a release's `SHA256SUMS` |
| `test_wheels.py` | installs this platform's wheel under each Python given and runs `tests/test_installed.py` |
| `tests/test_build_wheels.py` | the builder's tests, on made-up binaries |
| `tests/test_installed.py` | the installed package's tests: every corpus case through `verify()`, the `tzun-verify` command and the release binary |
| `README.md` | the package's page on PyPI |

## The wheels

| Target | Wheel platform tags |
|---|---|
| linux/amd64 | `manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64` |
| linux/arm64 | `manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64` |
| darwin/amd64 | `macosx_<major>_<minor>_x86_64` |
| darwin/arm64 | `macosx_<major>_<minor>_arm64` |
| windows/amd64 | `win_amd64` |

Every wheel is `py3-none`: the Python code runs on any Python 3.10 or later.

- The Linux binaries are static, so one wheel serves glibc and musl; the
  builder refuses an ELF file with an interpreter or a dynamic section.
- The macOS tag is the minimum macOS version the binary's own Mach-O load
  commands declare (Go 1.27.1: macOS 13, so `macosx_13_0_*`).
- The builder checks each binary's header: ELF, Mach-O or PE, for the
  target's machine. A target the release adds without a wheel here stops the
  build.
- The binary is the wheel's script (`tzun_verify-<version>.data/scripts/`),
  so an installer puts it on PATH as `tzun-verify`, unchanged.
  `tzun_verify/_release.py`, written into each wheel, records the release
  version, the target and the binary's SHA-256, which `binary()` checks
  before `verify()` runs it.
- The package version is the PEP 440 spelling of the release's: `0.1.0`,
  `0.2.0-rc.1` → `0.2.0rc1`, `0.2.0-beta.2` → `0.2.0b2`, `0.1.0-dev` →
  `0.1.0.dev0`. Any other pre-release part stops the build. A `-dev`
  version is only ever built from `main`, never released:
  `scripts/release-artifacts.sh` refuses its tag (RELEASING.md, "Where a
  release goes").
- The wheels have no sdist: without a binary there is nothing to install.

## How the workflow checks a release

`.github/workflows/python.yml`, on a `v*` tag:

| Job | Machine | What it does |
|---|---|---|
| build | GitHub-hosted, linux/amd64 | Makes the release files with `scripts/release-artifacts.sh` (refusing a tag other than `v<Version>`, a `-dev` version's tag, and a checkout other than the tag's commit as committed), writes the wheels, runs the builder's tests, and installs and tests the linux/amd64 wheel under Python 3.10 to 3.14. |
| test | one per other target and Python version: `ubuntu-24.04-arm`, `macos-15-intel`, `macos-15`, `windows-2025` | Installs the wheel for its platform (pip chooses it by its tags) and runs the installed tests. |
| publish | GitHub-hosted, in the `pypi` environment | Waits for the environment's reviewers. Downloads `SHA256SUMS` anonymously from the tag's GitHub release, at its public URL, where a draft serves nothing whatever token the job holds, so this fails while the release is a draft. Checks each wheel's binary against it (`build_wheels.py --check`) and against its build provenance attestation (`gh attestation verify`). Then uploads the wheels with PyPI trusted publishing. |

The test and publish jobs run only while the repository is public: the
release workflow's attestations need that too. On a pull request, only the
build job runs, with no upload.

## Setting it up, once

1. On PyPI, add a trusted publisher for the project `tzun-verify` (before
   the first upload, a "pending publisher"): owner `TzunAI`, repository
   `tzun-verify`, workflow `python.yml`, environment `pypi`.
2. In the repository's settings, create the environment `pypi`, **before
   the first tag is pushed**: required reviewers, the people who publish
   releases; deployment branches and tags, the tag rule `v*` only. GitHub
   creates an environment a job names when it does not exist, with no
   protection rules, and the publish job would then upload without waiting
   for anyone: its reviewers are the only people between a published
   release and a permanent upload.

No token is stored anywhere: the publish job gets a short-lived OIDC token
from GitHub, which PyPI exchanges for an upload token for this project
alone. The upload also carries PyPI's own attestations of the files.

## Publishing a release

1. Cut the release as RELEASING.md says, up to and including publishing the
   draft GitHub release.
2. In the tag's "Python package" run, check that the build and test jobs
   passed, then approve the `pypi` environment. If the publish job ran and
   failed at "Each wheel carries the published release's binary" because
   the release was still a draft (its `SHA256SUMS` is not downloadable
   until the release is published), re-run that job.
3. Check the result: `pip install tzun-verify==<version>`, then
   `tzun-verify --version` names the release.

A version, once uploaded, cannot be uploaded again, even after it is
deleted. If a published version is wrong, yank it on PyPI and release the
next version.

## Testing it yourself

With a release's files in `dist/` (from `scripts/release-artifacts.sh`, or
downloaded from a release):

```
python3 python/build_wheels.py dist wheels
python3 python/build_wheels.py --check dist/SHA256SUMS wheels/*.whl
python3 -m unittest discover -s python/tests -p test_build_wheels.py
python3 python/test_wheels.py --wheels wheels --dist dist \
  --corpus testdata/vectors/bundle-b1 --python python3.10 --python python3.14
```

`test_wheels.py` makes its own virtual environments and installs only the
wheel; `--system` installs into the interpreter itself, for a throwaway
container such as `python:3.13-slim` or `python:3.13-alpine`.
