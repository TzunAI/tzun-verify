# tzun-verify for Python

`tzun-verify` verifies a Tzun evidence record's b1 proof bundle without Tzun
code and without asking Tzun. This package installs it from PyPI and lets
Python run it:

```
pip install tzun-verify
```

There is one verifier. Each wheel carries the release binary for its
platform, byte for byte the file of the same release on GitHub, and installs
it as the `tzun-verify` command. The Python API runs that binary and returns
the report it prints; nothing is verified in Python.

| Platform | Wheel |
|---|---|
| Linux x86_64 and aarch64, glibc or musl | `manylinux_2_17`, `musllinux_1_1` (the binary is static) |
| macOS 13 or later, Intel and Apple silicon | `macosx_13_0_x86_64`, `macosx_13_0_arm64` |
| Windows x86_64 | `win_amd64` |

Python 3.10 or later. `pipx install tzun-verify` and `uv tool install
tzun-verify` install the command alone.

## The command

```
tzun-verify record-42.json                     # offline
tzun-verify --evm-rpc https://… record-42.json  # with your own Ethereum node
tzun-verify --json record-42.json              # the tzun-verify-report/1 report
tzun-verify --help
```

`python -m tzun_verify` runs the same binary with the same arguments. The
flags, the report and the exit codes are those of the
[tzun-verify README](https://github.com/TzunAI/tzun-verify#readme); the
[specification](https://spec.tzun.ai) defines what each check means.

## The Python API

```python
import tzun_verify

report = tzun_verify.verify(
    "record-42.json",
    evm_rpc="https://ethereum-sepolia-rpc.publicnode.com",
    require=["anchor", "ts.record.trust"],
)
print(report.exit_code)                    # 0, 1, 3 or 4
print(report["summary"]["outcomes"])       # {"checked-correct": 7, ...}
for check in report["checks"]:
    print(check["id"], check["outcome"], check.get("reason", ""))
```

`verify(path, **options)` runs `tzun-verify --json [flags] <path>` and
returns the report as a `dict` (a `tzun_verify.Report`), with the exit code
as its `exit_code`. The report alone does not say whether the exit code is
0, 3 or 4: that depends on the policy the options set.

Each keyword is the flag of the same name, with `_` for `-`:

| Keyword | Flag | Value |
|---|---|---|
| `evm_rpc` | `--evm-rpc` | `"[eip155:<id>=]<url>"`, or a list |
| `evm_header_file` | `--evm-header-file` | `"[eip155:<id>=]<file.json>"`, or a list |
| `confirmations` | `--confirmations` | an integer |
| `accept_non_final` | `--accept-non-final` | `True` or `False` |
| `no_tx_lookup` | `--no-tx-lookup` | `True` or `False` |
| `publishers` | `--publishers` | a path |
| `no_publishers` | `--no-publishers` | `True` or `False` |
| `tsa_roots` | `--tsa-roots` | a path, or a list |
| `tsa_intermediates` | `--tsa-intermediates` | a path, or a list |
| `timeout` | `--timeout` | milliseconds, an integer |
| `allow_unchecked` | `--allow-unchecked` | `True` or `False` |
| `require` | `--require` | a check id, or a list |
| `require_rung` | `--require-rung` | a rung, or a list |

A keyword set to `None`, or a switch set to `False`, passes nothing. A
switch takes only `True` or `False`, so `allow_unchecked="false"` is a
`TypeError`, as is a keyword that is not a flag.

| Exit code | `verify` |
|---|---|
| 0 nothing wrong, everything present checked | returns the report |
| 1 something is wrong | returns the report |
| 2 the bundle could not be read, or was abstained on as a whole | raises `tzun_verify.BundleError`; its `report` is the report when the command printed one |
| 3 a `require` or `require_rung` was not met | returns the report |
| 4 something present was not checked | returns the report |
| 64 the arguments, or an input they name, could not be used | raises `tzun_verify.UsageError` |

Both errors are `tzun_verify.VerifyError`s, with `exit_code`, `stderr` and
`report`. An exit 1 is a finding, not an error: read the report.

`tzun_verify.binary()` is the path of the installed binary. Before it runs
the binary, the module checks that its SHA-256 is the one of the release
binary the wheel was built with, and raises `tzun_verify.BinaryError` if it
is not.

## Checking the binary

The installed binary is the release file, so the release's checks apply to
it as they are:

```
path="$(python -c 'import tzun_verify; print(tzun_verify.binary())')"
sha256sum "$path"          # the line for tzun-verify_<version>_<os>_<arch> in the release's SHA256SUMS
gh attestation verify "$path" --repo TzunAI/tzun-verify \
  --signer-workflow TzunAI/tzun-verify/.github/workflows/release.yml \
  --source-ref "refs/tags/v<version>" --deny-self-hosted-runners
```

A pre-release's package version is the PEP 440 spelling of the release's:
release `0.2.0-rc.1` is package `0.2.0rc1`.
