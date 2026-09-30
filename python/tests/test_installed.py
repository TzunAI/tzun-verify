"""Tests of an installed tzun-verify wheel.

python/test_wheels.py runs them in an environment where the wheel, and
nothing from the source tree, is installed. They need two directories, named
in the environment:

  TZUN_VERIFY_CORPUS  the b1 conformance corpus (testdata/vectors/bundle-b1)
  TZUN_VERIFY_DIST    the release files the wheel was built from: SHA256SUMS
                      and the raw binaries

Every corpus case runs three ways: through tzun_verify.verify, through the
installed `tzun-verify` command, and through the release binary itself. All
three must agree with each other and with the case's expected report and exit
code.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tzun_verify
from tzun_verify import _release  # only a wheel has it: this is no source tree

WINDOWS = sys.platform == "win32"
EXE = "tzun-verify.exe" if WINDOWS else "tzun-verify"


def env_dir(name: str) -> Path:
    value = os.environ.get(name)
    if not value or not Path(value).is_dir():
        raise unittest.SkipTest(f"{name} must name a directory")
    return Path(value)


def canonical(v: object) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def comparable(report: object) -> str:
    """A report without checkedAt, which comparisons leave out (Verification §6.5)."""
    assert isinstance(report, dict), report
    return canonical({k: v for k, v in report.items() if k != "checkedAt"})


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def host_target() -> str:
    goos = {"linux": "linux", "darwin": "darwin", "win32": "windows"}[sys.platform]
    machine = platform.machine().lower()
    goarch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[machine]
    return f"{goos}_{goarch}"


def run(exe: str, args: list[str]) -> tuple[int, bytes, bytes]:
    p = subprocess.run([exe, *args], stdin=subprocess.DEVNULL, capture_output=True, check=False)
    return p.returncode, p.stdout, p.stderr


def case_inputs(inputs: dict, tmp: Path) -> tuple[dict, list[str]]:
    """A case's inputs.json as verify() keywords and, built separately, as the
    command's flags: the conversion internal/corpus/bundle_test.go makes."""
    unknown = set(inputs) - {"publisherManifest", "headerSources", "trustAnchorsPem", "regime"}
    if unknown:
        raise AssertionError(f"inputs.json: unknown members {sorted(unknown)}")
    options: dict = {}
    flags: list[str] = []
    manifest = inputs["publisherManifest"]
    if manifest is None:
        options["no_publishers"] = True
        flags.append("--no-publishers")
    else:
        p = tmp / "publishers.json"
        p.write_bytes(canonical(manifest).encode("utf-8"))
        options["publishers"] = p
        flags += ["--publishers", str(p)]
    for i, (chain, source) in enumerate(inputs["headerSources"].items()):
        p = tmp / f"headers-{i}.json"
        p.write_bytes(canonical(source).encode("utf-8"))
        options.setdefault("evm_header_file", []).append(f"{chain}={p}")
        flags += ["--evm-header-file", f"{chain}={p}"]
    if inputs["trustAnchorsPem"]:
        p = tmp / "roots.pem"
        p.write_bytes("".join(pem + "\n" for pem in inputs["trustAnchorsPem"]).encode("ascii"))
        options["tsa_roots"] = p
        flags += ["--tsa-roots", str(p)]
    regime = inputs["regime"]
    unknown = set(regime) - {"require", "requireRung", "allowUnchecked"}
    if unknown:
        raise AssertionError(f"inputs.json regime: unknown members {sorted(unknown)}")
    if regime["require"]:
        options["require"] = list(regime["require"])
        for r in regime["require"]:
            flags += ["--require", r]
    if regime["requireRung"]:
        options["require_rung"] = list(regime["requireRung"])
        for r in regime["requireRung"]:
            flags += ["--require-rung", r]
    if regime["allowUnchecked"]:
        options["allow_unchecked"] = True
        flags.append("--allow-unchecked")
    return options, flags


def setUpModule() -> None:
    global CORPUS, DIST, SUMS, RELEASE_NAME, COMMAND, WORK, RELEASE_EXE
    CORPUS = env_dir("TZUN_VERIFY_CORPUS")
    DIST = env_dir("TZUN_VERIFY_DIST")
    SUMS = {}
    for line in (DIST / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        SUMS[name] = digest
    RELEASE_NAME = f"tzun-verify_{_release.RELEASE}_{_release.TARGET}" + (".exe" if WINDOWS else "")
    found = shutil.which("tzun-verify")
    if found is None:
        raise AssertionError("tzun-verify is not on PATH")
    COMMAND = found
    WORK = Path(tempfile.mkdtemp(prefix="tzun-verify-wheel-test-"))
    # The release binary itself, as a download gets it: without an exec bit.
    RELEASE_EXE = str(WORK / ("release" + (".exe" if WINDOWS else "")))
    shutil.copyfile(DIST / RELEASE_NAME, RELEASE_EXE)
    os.chmod(RELEASE_EXE, 0o755)


def tearDownModule() -> None:
    shutil.rmtree(WORK, ignore_errors=True)


class Installed(unittest.TestCase):
    def test_the_wheel_is_for_this_platform(self) -> None:
        self.assertEqual(_release.TARGET, host_target())

    def test_binary_is_the_release_binary(self) -> None:
        path = tzun_verify.binary()
        self.assertEqual(os.path.basename(path), EXE)
        self.assertIn(RELEASE_NAME, SUMS)
        self.assertEqual(sha256_file(path), SUMS[RELEASE_NAME])
        self.assertEqual(_release.BINARY_SHA256, SUMS[RELEASE_NAME])
        self.assertEqual(Path(path).read_bytes(), Path(DIST / RELEASE_NAME).read_bytes())

    def test_the_command_on_path_is_the_binary(self) -> None:
        self.assertTrue(os.path.samefile(COMMAND, tzun_verify.binary()), COMMAND)
        if not WINDOWS:
            self.assertTrue(os.stat(COMMAND).st_mode & stat.S_IXUSR)

    def test_versions(self) -> None:
        self.assertEqual(tzun_verify.__version__, _release.VERSION)
        from importlib.metadata import version

        self.assertEqual(version("tzun-verify"), _release.VERSION)
        code, out, err = run(COMMAND, ["--version"])
        self.assertEqual((code, err), (0, b""))
        self.assertEqual(out.decode().splitlines()[0], f"tzun-verify {_release.RELEASE}")
        self.assertEqual(run(RELEASE_EXE, ["--version"]), (code, out, err))
        module = run(sys.executable, ["-m", "tzun_verify", "--version"])
        self.assertEqual(module, (code, out, err))

    def test_python_m_passes_exit_code_and_arguments(self) -> None:
        bundle = CORPUS / "anchored-offline" / "bundle.json"
        want = run(RELEASE_EXE, ["--no-publishers", str(bundle)])
        self.assertEqual(want[0], 4)
        self.assertEqual(run(sys.executable, ["-m", "tzun_verify", "--no-publishers", str(bundle)]), want)
        self.assertEqual(run(COMMAND, ["--no-publishers", str(bundle)]), want)

    def test_a_changed_binary_is_refused(self) -> None:
        saved = _release.BINARY_SHA256
        tzun_verify._checked.clear()
        _release.BINARY_SHA256 = "0" * 64
        try:
            with self.assertRaises(tzun_verify.BinaryError) as cm:
                tzun_verify.verify(CORPUS / "anchored-offline" / "bundle.json")
            self.assertIn("is not the tzun-verify", str(cm.exception))
        finally:
            _release.BINARY_SHA256 = saved
            tzun_verify._checked.clear()
        tzun_verify.binary()

    def test_keywords_are_the_commands_flags(self) -> None:
        # The flags `tzun-verify --help` lists, each a switch, a flag of one
        # value or a repeatable one, are the keywords verify() takes, less
        # the three that print no report.
        code, out, _ = run(COMMAND, ["--help"])
        self.assertEqual(code, 0)
        # Each flag's line, and the lines of its description below it.
        flags: dict[str, tuple[bool, str]] = {}
        current = None
        for line in out.decode().splitlines():
            m = re.match(r"^  (?:-h, )?(--[a-z][a-z-]*)( [\[<])?", line)
            if m:
                current = m.group(1)
                flags[current] = (m.group(2) is not None, line)
            elif current and line.startswith("   "):
                flags[current] = (flags[current][0], flags[current][1] + " " + line.strip())
            else:
                current = None
        switches, single, repeatable = set(), set(), set()
        for flag, (takes_value, text) in flags.items():
            if flag in ("--json", "--version", "--help"):
                continue
            key = flag[2:].replace("-", "_")
            if not takes_value:
                switches.add(key)
            elif "(repeatable" in text:
                repeatable.add(key)
            else:
                single.add(key)
        self.assertEqual(len(flags), 16, sorted(flags))
        self.assertEqual(switches, set(tzun_verify._SWITCHES))
        self.assertEqual(single, set(tzun_verify._SINGLE))
        self.assertEqual(repeatable, set(tzun_verify._REPEATABLE))


class Corpus(unittest.TestCase):
    def test_every_case_three_ways(self) -> None:
        index = json.loads((CORPUS / "index.json").read_text(encoding="utf-8"))
        listed = {c["name"]: c["exit"] for c in index["cases"]}
        cases = sorted(p.name for p in CORPUS.iterdir() if p.is_dir())
        self.assertEqual(sorted(listed), cases)
        self.assertGreater(len(cases), 0)
        exits = set()
        for name in cases:
            with self.subTest(case=name):
                self.run_case(CORPUS / name, listed[name])
                exits.add(listed[name])
        # Every exit code that verify() returns or raises on, but 64.
        self.assertEqual(exits, {0, 1, 2, 3, 4})

    def run_case(self, case: Path, listed_exit: int) -> None:
        inputs = json.loads((case / "inputs.json").read_text(encoding="utf-8"))
        want_exit = int((case / "expected-exit").read_text().strip())
        self.assertEqual(want_exit, listed_exit)
        want = comparable(json.loads((case / "expected-report.json").read_text(encoding="utf-8")))
        bundle = case / "bundle.json"
        tmp = Path(tempfile.mkdtemp(dir=WORK))
        options, flags = case_inputs(inputs, tmp)

        # The release binary, and the installed command: the same report
        # and exit code, and the same text report.
        code, out, err = run(RELEASE_EXE, [*flags, "--json", str(bundle)])
        self.assertEqual((code, err), (want_exit, b""))
        self.assertEqual(comparable(json.loads(out)), want)
        c_code, c_out, c_err = run(COMMAND, [*flags, "--json", str(bundle)])
        self.assertEqual((c_code, c_err), (code, b""))
        self.assertEqual(comparable(json.loads(c_out)), want)
        self.assertEqual(run(COMMAND, [*flags, str(bundle)]), run(RELEASE_EXE, [*flags, str(bundle)]))

        # The API.
        if want_exit == 2:
            with self.assertRaises(tzun_verify.BundleError) as cm:
                tzun_verify.verify(bundle, **options)
            e = cm.exception
            self.assertEqual(e.exit_code, 2)
            self.assertIsInstance(e, tzun_verify.VerifyError)
            self.assertEqual(comparable(e.report), want)
            self.assertIn("could not be read, or was abstained on as a whole (", str(e))
        else:
            report = tzun_verify.verify(bundle, **options)
            self.assertIsInstance(report, dict)
            self.assertIsInstance(report, tzun_verify.Report)
            self.assertEqual(report.exit_code, want_exit)
            self.assertEqual(comparable(report), want)
            # verify() with the path as a string gives the same.
            again = tzun_verify.verify(str(bundle), **options)
            self.assertEqual((again.exit_code, comparable(again)), (want_exit, want))


class Errors(unittest.TestCase):
    bundle: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = CORPUS / "anchored-offline" / "bundle.json"

    def test_a_missing_bundle_is_exit_2(self) -> None:
        missing = WORK / "no-such-bundle.json"
        with self.assertRaises(tzun_verify.BundleError) as cm:
            tzun_verify.verify(missing)
        self.assertEqual(cm.exception.exit_code, 2)
        self.assertIsNone(cm.exception.report)
        self.assertIn("no-such-bundle.json", str(cm.exception))
        self.assertEqual(run(RELEASE_EXE, ["--json", str(missing)])[0], 2)

    def test_usage_errors_are_exit_64(self) -> None:
        for options in (
            {"timeout": 0},
            {"confirmations": 0},
            {"publishers": WORK / "no-such-manifest.json"},
            {"publishers": self.bundle, "no_publishers": True},
            {"tsa_roots": self.bundle},
        ):
            with self.subTest(options=options):
                with self.assertRaises(tzun_verify.UsageError) as cm:
                    tzun_verify.verify(self.bundle, **options)
                self.assertEqual(cm.exception.exit_code, 64)
                self.assertTrue(str(cm.exception).startswith("tzun-verify: "), str(cm.exception))
                self.assertTrue(cm.exception.stderr.startswith(str(cm.exception)))

    def test_keywords_that_are_not_flags(self) -> None:
        for options in (
            {"json": True},
            {"version": True},
            {"help": True},
            {"no_such_flag": 1},
            {"allow_unchecked": "false"},
            {"allow_unchecked": 1},
            {"timeout": 1.5},
            {"timeout": True},
            {"require": [["anchor"]]},
            {"publishers": b"manifest.json"},
        ):
            with self.subTest(options=options):
                with self.assertRaises(TypeError):
                    tzun_verify.verify(self.bundle, **options)
        with self.assertRaises(TypeError):
            tzun_verify.verify(42)  # type: ignore[arg-type]

    def test_none_and_false_pass_nothing(self) -> None:
        plain = tzun_verify.verify(self.bundle, no_publishers=True)
        same = tzun_verify.verify(
            self.bundle,
            no_publishers=True,
            allow_unchecked=False,
            require=None,
            publishers=None,
            timeout=None,
        )
        self.assertEqual((same.exit_code, comparable(same)), (plain.exit_code, comparable(plain)))
        self.assertEqual(plain.exit_code, 4)

    def test_switches_and_lists(self) -> None:
        r = tzun_verify.verify(self.bundle, no_publishers=True, allow_unchecked=True)
        self.assertEqual(r.exit_code, 0)
        both = tzun_verify.verify(self.bundle, no_publishers=True, require=["bundle", "anchor"])
        joined = tzun_verify.verify(self.bundle, no_publishers=True, require="bundle,anchor")
        code = run(RELEASE_EXE, ["--no-publishers", "--require", "bundle", "--require", "anchor", "--json", str(self.bundle)])[0]
        self.assertEqual(both.exit_code, 3)
        self.assertEqual(joined.exit_code, code)
        self.assertEqual(comparable(both), comparable(joined))

    def test_a_path_that_starts_with_a_dash(self) -> None:
        d = Path(tempfile.mkdtemp(dir=WORK))
        for name in ("--json", "-h"):
            shutil.copyfile(self.bundle, d / name)
        cwd = os.getcwd()
        os.chdir(d)
        try:
            want = comparable(tzun_verify.verify(self.bundle, no_publishers=True))
            for name in ("--json", "-h"):
                with self.subTest(path=name):
                    r = tzun_verify.verify(name, no_publishers=True)
                    self.assertEqual((r.exit_code, comparable(r)), (4, want))
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
