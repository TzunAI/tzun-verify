#!/usr/bin/env python3
"""Installs the tzun-verify wheel for this platform and tests it, under each
Python given.

    python3 python/test_wheels.py --wheels <dir> --dist <release-dir> \\
        --corpus testdata/vectors/bundle-b1 [--python <exe>]... [--system]

For each interpreter (this one when none is given): a fresh virtual
environment, `pip install --no-index --find-links <dir> tzun-verify`, which
must choose this platform's wheel by its tags, then python/tests/
test_installed.py with the environment's scripts directory on PATH, as
activating it would put it. Then the same wheel installed with --target, and
verify() run from there.

With --system the wheel is installed into each interpreter itself, not a
virtual environment: for a throwaway container, where `tzun-verify` must
then be on PATH as the image has it.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TESTS = HERE / "tests"

PIP = ["-m", "pip", "--disable-pip-version-check", "--no-input"]


def call(args: list[Any], **kw: Any) -> None:
    print("+ " + " ".join(str(a) for a in args), flush=True)
    subprocess.run([str(a) for a in args], check=True, **kw)


def scripts_dir(python: str) -> str:
    out = subprocess.run(
        [python, "-c", "import sysconfig; print(sysconfig.get_path('scripts'))"],
        check=True, capture_output=True, text=True,
    )
    return out.stdout.strip()


def test_one(python: str, a: argparse.Namespace, work: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    if a.system:
        py = python
    else:
        venv = work / "venv"
        call([python, "-m", "venv", venv])
        py = str(venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
        env["PATH"] = scripts_dir(py) + os.pathsep + env.get("PATH", "")
        env["VIRTUAL_ENV"] = str(venv)
    call([py, *PIP, "install", "--no-index", "--find-links", a.wheels, "tzun-verify"], env=env)
    call([py, *PIP, "show", "--files", "tzun-verify"], env=env)
    env["TZUN_VERIFY_CORPUS"] = str(a.corpus)
    env["TZUN_VERIFY_DIST"] = str(a.dist)
    # From the tests' directory, so that tzun_verify comes from the
    # installation and not from python/src.
    call([py, "-m", "unittest", "-v", "test_installed"], cwd=TESTS, env=env)

    # --target: pip puts the binary in <target>/bin, not where its RECORD
    # says, and the module must find it there.
    target = work / "target"
    call([py, *PIP, "install", "--no-index", "--find-links", a.wheels, "--target", target, "tzun-verify"], env=env)
    probe = (
        "import os, sys, tzun_verify\n"
        "b = tzun_verify.binary()\n"
        "assert os.path.commonpath([b, sys.argv[1]]) == sys.argv[1], b\n"
        "r = tzun_verify.verify(sys.argv[2], no_publishers=True)\n"
        "assert r.exit_code == 4, r.exit_code\n"
        "print('--target:', b, 'exit', r.exit_code)\n"
    )
    target_env = dict(env, PYTHONPATH=str(target))
    bundle = a.corpus / "anchored-offline" / "bundle.json"
    call([py, "-c", probe, target.resolve(), bundle], cwd=work, env=target_env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--wheels", type=Path, required=True)
    ap.add_argument("--dist", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--python", action="append", default=[])
    ap.add_argument("--system", action="store_true")
    a = ap.parse_args()
    a.wheels, a.dist, a.corpus = a.wheels.resolve(), a.dist.resolve(), a.corpus.resolve()
    failed = []
    for python in a.python or [sys.executable]:
        print(f"== {python}", flush=True)
        with tempfile.TemporaryDirectory(prefix="tzun-verify-wheels-") as work:
            try:
                test_one(python, a, Path(work))
            except subprocess.CalledProcessError as e:
                print(f"FAIL {python}: {e}", flush=True)
                failed.append(python)
    if failed:
        print(f"failed under: {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"passed under: {', '.join(a.python or [sys.executable])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
