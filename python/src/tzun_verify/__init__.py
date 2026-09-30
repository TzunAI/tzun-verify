"""Run tzun-verify, the standalone verifier for Tzun b1 proof bundles, from Python.

There is one verifier: the release binary this wheel carries, byte for byte
the one on the GitHub release. This module runs it with ``--json`` and
returns the report it prints.

    >>> import tzun_verify
    >>> report = tzun_verify.verify("record-42.json", evm_rpc="https://...")
    >>> report.exit_code, report["summary"]["outcomes"]

Each keyword of :func:`verify` is a flag of the command, spelled with ``_``
for ``-``: ``allow_unchecked=True`` is ``--allow-unchecked``,
``require=["anchor", "ts.record.trust"]`` is ``--require anchor --require
ts.record.trust``. ``tzun-verify --help`` lists them.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import subprocess
import threading
from collections.abc import Iterable
from typing import Any, Union

# Written into each wheel by python/build_wheels.py: the release, the target
# and the SHA-256 of the binary the wheel carries. A source tree has none,
# and no binary.
_release: Any
try:
    _release = importlib.import_module(f"{__name__}._release")
except ImportError:
    _release = None

__all__ = [
    "BinaryError",
    "BundleError",
    "Report",
    "UsageError",
    "VerifyError",
    "binary",
    "verify",
]

__version__ = _release.VERSION if _release is not None else "0+source"

# The command's exit codes (Verification §6.6, and 64 for a usage error).
EXIT_OK = 0
EXIT_WRONG = 1
EXIT_BUNDLE = 2
EXIT_REQUIRE = 3
EXIT_UNCHECKED = 4
EXIT_USAGE = 64

# The command's flags, by the keyword that stands for each. A switch takes
# True or False; a flag of one value takes a string, a path or an integer;
# a repeatable flag takes one of those or a list of them. --json is always
# passed, and --version and --help print no report, so none of the three is
# a keyword. The installed tests compare this table with `tzun-verify --help`.
_SWITCHES = frozenset(
    {"accept_non_final", "no_tx_lookup", "no_publishers", "allow_unchecked"}
)
_SINGLE = frozenset({"confirmations", "publishers", "timeout"})
_REPEATABLE = frozenset(
    {
        "evm_rpc",
        "evm_header_file",
        "tsa_roots",
        "tsa_intermediates",
        "require",
        "require_rung",
    }
)

PathLike = Union[str, "os.PathLike[str]"]


class VerifyError(Exception):
    """tzun-verify did not produce a report this module can return.

    ``exit_code`` is the command's exit code (None when it did not run),
    ``stderr`` what it wrote to standard error, and ``report`` the report it
    printed, when it printed one.
    """

    def __init__(
        self,
        message: str,
        exit_code: int | None = None,
        stderr: str = "",
        report: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr
        self.report = report


class BundleError(VerifyError):
    """Exit 2: the bundle could not be read, or was abstained on as a whole.

    When the command printed a report, as it does for a bundle it read and
    abstained on, ``report`` holds it.
    """


class UsageError(VerifyError):
    """Exit 64: the command refused its arguments or an input they name."""


class BinaryError(VerifyError):
    """The binary this package installed is missing or has been changed."""


class Report(dict[str, Any]):
    """A tzun-verify-report/1 report, as the command printed it.

    It is the report's JSON object as a ``dict``. ``exit_code`` is the exit
    code it came with: 0, 1, 3 or 4 (Verification §6.6). The report alone
    does not give it, since the policy (``require``, ``require_rung``,
    ``allow_unchecked``) decides between 0, 3 and 4.
    """

    exit_code: int

    def __init__(self, report: dict[str, Any], exit_code: int) -> None:
        super().__init__(report)
        self.exit_code = exit_code


_EXE = "tzun-verify.exe" if os.name == "nt" else "tzun-verify"
_lock = threading.Lock()
_checked: dict[str, tuple[int, int, int]] = {}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _candidates() -> list[str]:
    """Where this package's installation may have put the binary, in order."""
    if _release is None:
        raise BinaryError(
            "this copy of tzun_verify was not installed from a wheel, so it has no binary"
        )
    # The distribution installed next to this package, not whichever one
    # comes first on sys.path: its RECORD says where the installer put the
    # binary, whatever the scheme (a virtual environment, --user or
    # --prefix).
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dists = [
        d
        for d in importlib.metadata.distributions(path=[root])
        if _normalize(d.metadata["Name"] or "") == "tzun-verify"
    ]
    if len(dists) != 1:
        raise BinaryError(
            f"expected one tzun-verify installation in {root}, found {len(dists)}"
        )
    found = [
        os.path.normpath(str(dists[0].locate_file(f)))
        for f in dists[0].files or ()
        if f.name == _EXE
    ]
    # pip install --target puts the binary in <target>/bin (Scripts on
    # Windows), but records its path relative to the temporary prefix it
    # installed into, which is not where it ends up.
    return found + [os.path.join(root, d, _EXE) for d in ("bin", "Scripts")]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def binary() -> str:
    """The path of the tzun-verify binary this package installed.

    It is the first file where the installation may have put it whose
    SHA-256 is the one of the release binary this wheel was built with.
    Raises :class:`BinaryError` when there is none.
    """
    other = None
    for path in _candidates():
        try:
            st = os.stat(path)
        except OSError:
            continue
        key = (st.st_size, st.st_mtime_ns, st.st_ino)
        with _lock:
            if _checked.get(path) == key:
                return path
            digest = _sha256(path)
            if digest == _release.BINARY_SHA256:
                _checked[path] = key
                return path
        other = other or (path, digest)
    if other is not None:
        raise BinaryError(
            f"{other[0]} is not the tzun-verify {_release.RELEASE} binary this package "
            f"installed: its SHA-256 is {other[1]}, not {_release.BINARY_SHA256}"
        )
    raise BinaryError(f"tzun_verify is installed without its {_EXE}")


def _value(key: str, v: Any) -> str:
    if isinstance(v, bool) or not isinstance(v, (str, int, os.PathLike)):
        raise TypeError(
            f"{key}: expected a string, a path or an integer, got {type(v).__name__}"
        )
    if isinstance(v, int):
        return str(v)
    s = os.fspath(v)
    return os.fsdecode(s) if isinstance(s, bytes) else s


def _flags(options: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, v in options.items():
        flag = "--" + key.replace("_", "-")
        if key in _SWITCHES:
            # Only a bool: "false" would otherwise switch it on.
            if not isinstance(v, bool):
                raise TypeError(f"{key} takes True or False, got {v!r}")
            if v:
                out.append(flag)
        elif key in _SINGLE:
            if v is not None:
                out.append(f"{flag}={_value(key, v)}")
        elif key in _REPEATABLE:
            if v is None:
                continue
            values: Iterable[Any] = (
                v if isinstance(v, (list, tuple)) else (v,)
            )
            out.extend(f"{flag}={_value(key, x)}" for x in values)
        else:
            raise TypeError(f"verify() got an unexpected keyword argument {key!r}")
    return out


def _bundle_arg(path: PathLike) -> str:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f"path: expected a string or a path, got {type(path).__name__}")
    p = os.fsdecode(os.fspath(path))
    # The command reads an argument that starts with "-" as a flag.
    return os.path.join(os.curdir, p) if p.startswith("-") else p


def _first_undecided(report: dict[str, Any] | None) -> str:
    """The first row of a report that is not checked-correct, as one line."""
    checks = report.get("checks") if isinstance(report, dict) else None
    for row in checks if isinstance(checks, list) else ():
        if isinstance(row, dict) and row.get("outcome") != "checked-correct":
            return " ".join(
                str(row[k]) for k in ("id", "outcome", "reason") if row.get(k)
            )
    return ""


def verify(path: PathLike, /, **options: Any) -> Report:
    """Verify the b1 proof bundle at ``path`` and return the report.

    Runs ``tzun-verify --json [flags] <path>``, each keyword standing for
    the flag of the same name with ``-`` for ``_``:

    - ``evm_rpc``, ``evm_header_file``, ``tsa_roots``, ``tsa_intermediates``,
      ``require``, ``require_rung``: a value or a list of values, one flag
      each;
    - ``confirmations``, ``timeout`` (milliseconds): an integer;
      ``publishers``: a path;
    - ``accept_non_final``, ``no_tx_lookup``, ``no_publishers``,
      ``allow_unchecked``: True or False.

    A keyword set to None, or a switch set to False, passes nothing.

    Returns the report, a :class:`Report` (a ``dict``) whose ``exit_code`` is
    0, 1, 3 or 4. Raises :class:`BundleError` on exit 2, :class:`UsageError`
    on exit 64, :class:`VerifyError` on anything else the command does, and
    TypeError for a keyword that is not a flag or a value of the wrong type.
    """
    args = [binary(), "--json", *_flags(options), _bundle_arg(path)]
    proc = subprocess.run(
        args, stdin=subprocess.DEVNULL, capture_output=True, check=False
    )
    stderr = proc.stderr.decode("utf-8", errors="replace")
    report: dict[str, Any] | None = None
    if proc.stdout.strip():
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            report = None
    code = proc.returncode
    detail = stderr.strip().splitlines()[0] if stderr.strip() else ""
    if code == EXIT_USAGE:
        raise UsageError(
            detail or "tzun-verify refused its arguments", code, stderr, report
        )
    if code == EXIT_BUNDLE:
        if not detail:
            detail = "the bundle could not be read, or was abstained on as a whole"
            row = _first_undecided(report)
            if row:
                detail += f" ({row})"
        raise BundleError(detail, code, stderr, report)
    if code not in (EXIT_OK, EXIT_WRONG, EXIT_REQUIRE, EXIT_UNCHECKED):
        raise VerifyError(
            f"tzun-verify exited {code}" + (f": {detail}" if detail else ""),
            code,
            stderr,
            report,
        )
    if not isinstance(report, dict):
        raise VerifyError(
            f"tzun-verify exited {code} without a JSON report", code, stderr, None
        )
    return Report(report, code)
