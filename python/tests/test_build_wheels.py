"""Tests of python/build_wheels.py on made-up release files.

    python3 -m unittest discover -s python/tests -p test_build_wheels.py

The binaries here are headers and nothing else: enough for the checks the
build makes of each target's executable format. With TZUN_VERIFY_DIST set to
a real release's files, one more test builds the wheels from those.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import stat
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import build_wheels as bw  # noqa: E402

LINUX_TAGS = "manylinux_2_17_{0}.manylinux2014_{0}.musllinux_1_1_{0}"


def elf(machine: int, ptypes: tuple[int, ...] = (6, 1, 1, 4)) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0, 64, 0, 0, 64, 56, len(ptypes), 64, 0, 0)
    phdrs = b"".join(struct.pack("<IIQQQQQQ", t, 0, 0, 0, 0, 0, 0, 0) for t in ptypes)
    return header + phdrs + b"elf body"


def macho(cputype: int, minos: tuple[int, int] = (13, 0), cmd: int = 0x32) -> bytes:
    version = (minos[0] << 16) | (minos[1] << 8)
    if cmd == 0x32:  # LC_BUILD_VERSION
        lc = struct.pack("<IIIIII", 0x32, 24, 1, version, version, 0)
    elif cmd == 0x24:  # LC_VERSION_MIN_MACOSX
        lc = struct.pack("<IIII", 0x24, 16, version, version)
    else:  # neither: no minimum version at all
        lc = struct.pack("<II", cmd, 8)
    other = struct.pack("<II", 0x19, 8)  # a load command the build skips
    header = b"\xcf\xfa\xed\xfe" + struct.pack("<iiIIIII", cputype, 0, 2, 2, len(lc) + len(other), 0, 0)
    return header + other + lc + b"macho body"


def pe(machine: int) -> bytes:
    head = bytearray(0x40)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = struct.pack("<I", 0x40)
    return bytes(head) + b"PE\0\0" + struct.pack("<H", machine) + b"pe body"


def fake_binaries() -> dict[str, bytes]:
    return {
        "linux_amd64": elf(bw.ELF_X86_64),
        "linux_arm64": elf(bw.ELF_AARCH64),
        "darwin_amd64": macho(bw.MACHO_X86_64),
        "darwin_arm64": macho(bw.MACHO_ARM64),
        "windows_amd64": pe(bw.PE_AMD64),
    }


def write_release(d: Path, version: str = "1.2.3", binaries: dict[str, bytes] | None = None,
                  sums_override: dict[str, str] | None = None) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    lines = []
    for key, data in sorted((binaries or fake_binaries()).items()):
        name = f"tzun-verify_{version}_{key}" + (".exe" if key.startswith("windows") else "")
        (d / name).write_bytes(data)
        lines.append((name, hashlib.sha256(data).hexdigest()))
        archive = name.removesuffix(".exe") + (".zip" if key.startswith("windows") else ".tar.gz")
        (d / archive).write_bytes(b"archive")
        lines.append((archive, hashlib.sha256(b"archive").hexdigest()))
    sums = dict(lines)
    sums.update(sums_override or {})
    (d / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for n, h in sorted(sums.items())))
    return d


def quiet(fn, *args):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return fn(*args)


class Versions(unittest.TestCase):
    def test_pep440(self) -> None:
        for release, want in [
            ("0.1.0", "0.1.0"),
            ("1.20.3", "1.20.3"),
            ("0.2.0-rc.1", "0.2.0rc1"),
            ("0.2.0-rc1", "0.2.0rc1"),
            ("0.2.0-beta.2", "0.2.0b2"),
            ("0.2.0-b.2", "0.2.0b2"),
            ("0.2.0-alpha", "0.2.0a0"),
            ("0.2.0-a.3", "0.2.0a3"),
            ("0.1.0-dev", "0.1.0.dev0"),
            ("0.1.0-dev.4", "0.1.0.dev4"),
        ]:
            self.assertEqual(bw.pypi_version(release), want, release)

    def test_refused(self) -> None:
        for release in ["1.2", "v1.2.3", "1.2.3-foo", "1.2.3-rc.1.2", "1.2.3+build", "1.2.3-"]:
            with self.assertRaises(bw.BuildError, msg=release):
                bw.pypi_version(release)


class Build(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp)

    def build(self, release: Path, tag: str | None = None, out: str = "wheels") -> list[Path]:
        return bw.build(release, self.tmp / out, tag)

    def test_one_wheel_per_target(self) -> None:
        wheels = self.build(write_release(self.tmp / "rel"))
        names = sorted(w.name for w in wheels)
        self.assertEqual(names, sorted([
            "tzun_verify-1.2.3-py3-none-" + LINUX_TAGS.format("x86_64") + ".whl",
            "tzun_verify-1.2.3-py3-none-" + LINUX_TAGS.format("aarch64") + ".whl",
            "tzun_verify-1.2.3-py3-none-macosx_13_0_x86_64.whl",
            "tzun_verify-1.2.3-py3-none-macosx_13_0_arm64.whl",
            "tzun_verify-1.2.3-py3-none-win_amd64.whl",
        ]))

    def test_wheel_contents(self) -> None:
        binaries = fake_binaries()
        for w in self.build(write_release(self.tmp / "rel", "0.3.0-rc.2", binaries)):
            with self.subTest(wheel=w.name), zipfile.ZipFile(w) as z:
                infos = z.infolist()
                names = [i.filename for i in infos]
                release = z.read("tzun_verify/_release.py").decode()
                key = release.split("TARGET = '")[1].split("'")[0]
                exe = "tzun-verify.exe" if key.startswith("windows") else "tzun-verify"
                self.assertEqual(names, [
                    "tzun_verify/__init__.py",
                    "tzun_verify/__main__.py",
                    "tzun_verify/_release.py",
                    "tzun_verify/py.typed",
                    f"tzun_verify-0.3.0rc2.data/scripts/{exe}",
                    "tzun_verify-0.3.0rc2.dist-info/METADATA",
                    "tzun_verify-0.3.0rc2.dist-info/WHEEL",
                    "tzun_verify-0.3.0rc2.dist-info/RECORD",
                ])
                # The binary, byte for byte, executable; everything else 0644.
                script = z.read(names[4])
                self.assertEqual(script, binaries[key])
                for i in infos:
                    mode = i.external_attr >> 16
                    self.assertTrue(stat.S_ISREG(mode))
                    self.assertEqual(stat.S_IMODE(mode), 0o755 if i.filename == names[4] else 0o644, i.filename)
                    self.assertEqual(i.date_time, bw.ZIP_TIME)
                # The package's sources are the tree's.
                src = Path(bw.PACKAGE_DIR)
                for n in ("__init__.py", "__main__.py", "py.typed"):
                    self.assertEqual(z.read(f"tzun_verify/{n}"), (src / n).read_bytes())
                self.assertIn("VERSION = '0.3.0rc2'\n", release)
                self.assertIn("RELEASE = '0.3.0-rc.2'\n", release)
                self.assertIn(f"BINARY_SHA256 = '{hashlib.sha256(script).hexdigest()}'\n", release)
                # RECORD lists every other file with its hash and size.
                record = z.read(names[-1]).decode().splitlines()
                self.assertEqual(record[-1], "tzun_verify-0.3.0rc2.dist-info/RECORD,,")
                self.assertEqual([r.split(",")[0] for r in record], names)
                for line in record[:-1]:
                    path, digest, size = line.split(",")
                    data = z.read(path)
                    want = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                    self.assertEqual((digest, size), (f"sha256={want}", str(len(data))))
                # WHEEL's tags are the file name's.
                wheel = z.read(names[-2]).decode()
                tags = [ln.split(": ")[1] for ln in wheel.splitlines() if ln.startswith("Tag: ")]
                plats = w.name.removesuffix(".whl").split("-")[4].split(".")
                self.assertEqual(tags, [f"py3-none-{p}" for p in plats])
                self.assertIn("Root-Is-Purelib: false\n", wheel)
                meta = z.read(names[-3]).decode()
                head, body = meta.split("\n\n", 1)
                self.assertIn("Name: tzun-verify\n", head + "\n")
                self.assertIn("Version: 0.3.0rc2\n", head + "\n")
                self.assertIn("Requires-Python: >=3.10\n", head + "\n")
                self.assertEqual(body, (bw.HERE / "README.md").read_text())

    def test_the_same_files_make_the_same_wheels(self) -> None:
        rel = write_release(self.tmp / "rel")
        one = {w.name: w.read_bytes() for w in self.build(rel, out="one")}
        two = {w.name: w.read_bytes() for w in self.build(rel, out="two")}
        self.assertEqual(one, two)

    def test_tag(self) -> None:
        rel = write_release(self.tmp / "rel", "0.1.0")
        self.assertEqual(len(self.build(rel, "v0.1.0", "ok")), 5)
        with self.assertRaisesRegex(bw.BuildError, "the tag is v0.1.1"):
            self.build(rel, "v0.1.1", "no")
        self.assertFalse((self.tmp / "no").exists())

    def test_out_dir_must_be_empty(self) -> None:
        rel = write_release(self.tmp / "rel")
        (self.tmp / "wheels").mkdir()
        (self.tmp / "wheels" / "old.whl").write_bytes(b"")
        with self.assertRaisesRegex(bw.BuildError, "not empty"):
            self.build(rel)

    def test_refusals(self) -> None:
        b = fake_binaries()
        cases = {
            "does not match SHA256SUMS": dict(sums_override={"tzun-verify_1.2.3_linux_amd64": "0" * 64}),
            "no binary for darwin_arm64": dict(binaries={k: v for k, v in b.items() if k != "darwin_arm64"}),
            "freebsd_amd64, a target with no wheel": dict(binaries={**b, "freebsd_amd64": elf(bw.ELF_X86_64)}),
            "dynamically linked": dict(binaries={**b, "linux_amd64": elf(bw.ELF_X86_64, (6, 3, 1, 2))}),
            "ELF machine 183, not 62": dict(binaries={**b, "linux_amd64": elf(bw.ELF_AARCH64)}),
            "not a 64-bit little-endian ELF": dict(binaries={**b, "linux_arm64": macho(bw.MACHO_ARM64)}),
            "Mach-O CPU type": dict(binaries={**b, "darwin_amd64": macho(bw.MACHO_ARM64)}),
            "no minimum macOS version": dict(binaries={**b, "darwin_arm64": macho(bw.MACHO_ARM64, cmd=0x19)}),
            "PE machine 0xaa64": dict(binaries={**b, "windows_amd64": pe(0xAA64)}),
            "not a PE file": dict(binaries={**b, "windows_amd64": elf(bw.ELF_X86_64)}),
        }
        for i, (message, kw) in enumerate(cases.items()):
            with self.subTest(message):
                rel = write_release(self.tmp / f"rel{i}", **kw)
                with self.assertRaisesRegex(bw.BuildError, message):
                    self.build(rel, out=f"w{i}")

    def test_two_versions_are_refused(self) -> None:
        rel = write_release(self.tmp / "rel")
        (rel / "SHA256SUMS").write_text(
            (rel / "SHA256SUMS").read_text().replace("tzun-verify_1.2.3_linux_arm64\n", "tzun-verify_1.2.4_linux_arm64\n")
        )
        with self.assertRaisesRegex(bw.BuildError, "2 versions"):
            self.build(rel)

    def test_macos_tags_follow_the_binary(self) -> None:
        t = bw.TARGETS["darwin_arm64"]
        for minos, want in [((13, 0), "macosx_13_0_arm64"), ((13, 1), "macosx_14_0_arm64"),
                            ((11, 0), "macosx_11_0_arm64"), ((10, 15), "macosx_10_15_arm64")]:
            self.assertEqual(bw.macos_platform(t, macho(bw.MACHO_ARM64, minos)), want)
            self.assertEqual(bw.macos_platform(t, macho(bw.MACHO_ARM64, minos, cmd=0x24)), want)


class Check(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp)
        self.rel = write_release(self.tmp / "rel")
        self.wheels = bw.build(self.rel, self.tmp / "wheels", None)

    def test_the_wheels_carry_the_release(self) -> None:
        out = self.tmp / "extracted"
        quiet(bw.check, self.rel / "SHA256SUMS", self.wheels, out)
        for name in os.listdir(out):
            self.assertEqual((out / name).read_bytes(), (self.rel / name).read_bytes())
        self.assertEqual(len(os.listdir(out)), 5)
        self.assertEqual(quiet(bw.main, ["--check", str(self.rel / "SHA256SUMS"), *map(str, self.wheels)]), 0)
        quiet(bw.check, self.rel / "SHA256SUMS", self.wheels, None, "v1.2.3")
        with self.assertRaisesRegex(bw.BuildError, "the tag is v1.2.4"):
            quiet(bw.check, self.rel / "SHA256SUMS", self.wheels, None, "v1.2.4")

    def test_another_release_is_refused(self) -> None:
        other = fake_binaries()
        other["linux_arm64"] = elf(bw.ELF_AARCH64) + b"changed"
        rel2 = write_release(self.tmp / "rel2", binaries=other)
        with self.assertRaisesRegex(bw.BuildError, "carries a binary whose SHA-256"):
            quiet(bw.check, rel2 / "SHA256SUMS", self.wheels, None)
        rel3 = write_release(self.tmp / "rel3", "1.2.4")
        with self.assertRaisesRegex(bw.BuildError, "is not version 1.2.4"):
            quiet(bw.check, rel3 / "SHA256SUMS", self.wheels, None)

    def test_a_missing_or_doubled_wheel_is_refused(self) -> None:
        with self.assertRaisesRegex(bw.BuildError, "no wheel for"):
            quiet(bw.check, self.rel / "SHA256SUMS", self.wheels[1:], None)
        with self.assertRaisesRegex(bw.BuildError, "are both for"):
            quiet(bw.check, self.rel / "SHA256SUMS", [*self.wheels, self.wheels[0]], None)

    def test_a_wheel_that_does_not_match_its_record_is_refused(self) -> None:
        w = self.wheels[0]
        with zipfile.ZipFile(w) as z:
            entries = [(i, z.read(i)) for i in z.infolist()]
        with zipfile.ZipFile(w, "w") as z:
            for info, data in entries:
                if info.filename.endswith("__init__.py"):
                    data += b"\n# changed\n"
                z.writestr(info, data)
        with self.assertRaisesRegex(bw.BuildError, "does not match RECORD"):
            quiet(bw.check, self.rel / "SHA256SUMS", self.wheels, None)


class RealRelease(unittest.TestCase):
    def test_wheels_from_the_release_files(self) -> None:
        dist = os.environ.get("TZUN_VERIFY_DIST")
        if not dist:
            self.skipTest("TZUN_VERIFY_DIST is not set")
        with tempfile.TemporaryDirectory() as tmp:
            wheels = bw.build(Path(dist), Path(tmp) / "wheels", None)
            self.assertEqual(len(wheels), 5)
            quiet(bw.check, Path(dist) / "SHA256SUMS", wheels, None)
            plats = sorted(w.name.split("-")[-1].removesuffix(".whl") for w in wheels)
            self.assertEqual(plats, sorted([
                LINUX_TAGS.format("aarch64"), LINUX_TAGS.format("x86_64"),
                "macosx_13_0_arm64", "macosx_13_0_x86_64", "win_amd64",
            ]))


if __name__ == "__main__":
    unittest.main()
