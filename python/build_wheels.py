#!/usr/bin/env python3
"""Writes the tzun-verify wheels from a release's files, and checks wheels
against a release.

    python3 python/build_wheels.py [--tag v<version>] <release-dir> <out-dir>
    python3 python/build_wheels.py [--tag v<version>] --check <SHA256SUMS> [--extract <dir>] <wheel>...

The first form reads <release-dir>, a release's files as RELEASING.md names
them (SHA256SUMS and the raw binary of each target; the archives are not
read), and writes one wheel per target into <out-dir>, which must be empty
or not exist. Each wheel carries its target's binary as the package's
script, the way ruff and uv ship: an installer puts it on PATH as
`tzun-verify`, byte for byte the release binary, and the tzun_verify module
runs that file. With --tag, nothing is written unless the release's version
is the tag's.

The second form checks that the wheels are one per target and that each
carries, byte for byte, the binary a release's SHA256SUMS names for its
target; with --tag, that the release is the tag's; with --extract, it writes
those binaries there under their release names, for `gh attestation verify`.

It needs nothing but the Python standard library (3.10 or later). The wheels
it writes from the same files are identical byte for byte on one machine;
their deflate streams depend on the zlib that Python links.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import re
import stat
import struct
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE_DIR = HERE / "src" / "tzun_verify"
README = HERE / "README.md"

NAME = "tzun-verify"
DIST = "tzun_verify"
SUMMARY = "Standalone verifier for Tzun DEO proof bundles"
REQUIRES_PYTHON = ">=3.10"
PROJECT_URLS = [
    ("Source", "https://github.com/TzunAI/tzun-verify"),
    ("Specification", "https://spec.tzun.ai"),
]
CLASSIFIERS = [
    "Environment :: Console",
    "Intended Audience :: Developers",
    "Operating System :: MacOS",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3 :: Only",
    "Topic :: Security :: Cryptography",
    "Typing :: Typed",
]

# Every file of the tzun_verify package, and no other. The build refuses a
# package directory that holds anything else, so a new file lands with a
# decision to ship it.
PACKAGE_FILES = ["__init__.py", "__main__.py", "py.typed"]

# Every zip entry's time, so that a rebuild writes the same bytes.
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class Target:
    goos: str
    goarch: str
    # What the binary's header must say: "elf", "macho" or "pe", and the
    # machine it is for.
    fmt: str
    machine: int
    # The wheel's platform tags. None for darwin: the tag comes from the
    # minimum macOS version the binary itself declares.
    platforms: tuple[str, ...] | None
    wheel_arch: str

    @property
    def key(self) -> str:
        return f"{self.goos}_{self.goarch}"

    @property
    def exe(self) -> str:
        return "tzun-verify.exe" if self.goos == "windows" else "tzun-verify"


ELF_X86_64, ELF_AARCH64 = 62, 183
MACHO_X86_64, MACHO_ARM64 = 0x01000007, 0x0100000C
PE_AMD64 = 0x8664

# The release's targets (scripts/release-artifacts.sh) and each one's wheel.
# The Linux binaries are static (CGO_ENABLED=0, which the build checks: no
# interpreter, no dynamic section), so one wheel serves glibc and musl alike,
# tagged for both.
TARGETS = {
    t.key: t
    for t in [
        Target(
            "linux", "amd64", "elf", ELF_X86_64,
            ("manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64"),
            "x86_64",
        ),
        Target(
            "linux", "arm64", "elf", ELF_AARCH64,
            ("manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_1_aarch64"),
            "aarch64",
        ),
        Target("darwin", "amd64", "macho", MACHO_X86_64, None, "x86_64"),
        Target("darwin", "arm64", "macho", MACHO_ARM64, None, "arm64"),
        Target("windows", "amd64", "pe", PE_AMD64, ("win_amd64",), "amd64"),
    ]
}

BINARY_NAME = re.compile(
    r"tzun-verify_(?P<version>[0-9][0-9A-Za-z.-]*)_(?P<goos>[a-z0-9]+)_(?P<goarch>[a-z0-9]+)(?P<exe>\.exe)?"
)
ARCHIVE_NAME = re.compile(r"tzun-verify_[0-9][0-9A-Za-z.-]*_[a-z0-9]+_[a-z0-9]+\.(?:tar\.gz|zip)")
SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?")


class BuildError(Exception):
    pass


def pypi_version(version: str) -> str:
    """The PEP 440 version of a release version (internal/cli's Version).

    0.1.0 -> 0.1.0, 0.2.0-rc.1 -> 0.2.0rc1, 0.2.0-beta.2 -> 0.2.0b2,
    0.2.0-alpha -> 0.2.0a0, 0.1.0-dev -> 0.1.0.dev0. Any other pre-release
    part is refused: PyPI has no spelling for it.
    """
    m = SEMVER.fullmatch(version)
    if not m:
        raise BuildError(f"{version!r} is not <major>.<minor>.<patch>[-<pre>]")
    release = ".".join(str(int(x)) for x in m.group(1, 2, 3))
    pre = m.group(4)
    if pre is None:
        return release
    p = re.fullmatch(r"(alpha|a|beta|b|rc)\.?(\d+)?", pre)
    if p:
        letter = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "rc": "rc"}[p.group(1)]
        return f"{release}{letter}{int(p.group(2) or 0)}"
    d = re.fullmatch(r"dev\.?(\d+)?", pre)
    if d:
        return f"{release}.dev{int(d.group(1) or 0)}"
    raise BuildError(f"the pre-release part of {version!r} has no PEP 440 spelling")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_sums(path: Path) -> dict[str, str]:
    """SHA256SUMS as {name: hex}, in sha256sum's format."""
    sums: dict[str, str] = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        if not m:
            raise BuildError(f"{path}:{n}: not a sha256sum line: {line!r}")
        if m.group(2) in sums:
            raise BuildError(f"{path}:{n}: {m.group(2)} is listed twice")
        sums[m.group(2)] = m.group(1)
    return sums


def release_binaries(sums: dict[str, str]) -> tuple[str, dict[str, str]]:
    """The release's version and {target key: binary name} from SHA256SUMS.

    Every target of TARGETS must be there, and nothing else: a new target
    needs a decision about its wheel.
    """
    versions: set[str] = set()
    names: dict[str, str] = {}
    for name in sums:
        if ARCHIVE_NAME.fullmatch(name):
            continue
        m = BINARY_NAME.fullmatch(name)
        if not m:
            raise BuildError(f"SHA256SUMS lists {name}, which is not a release file name")
        key = f"{m.group('goos')}_{m.group('goarch')}"
        t = TARGETS.get(key)
        if t is None:
            raise BuildError(f"SHA256SUMS lists {name}, a target with no wheel here: add it to TARGETS")
        if bool(m.group("exe")) != (t.goos == "windows"):
            raise BuildError(f"{name}: a {t.goos} binary {'needs' if t.goos == 'windows' else 'has no'} .exe")
        versions.add(m.group("version"))
        names[key] = name
    if len(versions) != 1:
        raise BuildError(f"SHA256SUMS names {len(versions)} versions: {sorted(versions)}")
    missing = sorted(set(TARGETS) - set(names))
    if missing:
        raise BuildError(f"SHA256SUMS lists no binary for {', '.join(missing)}")
    return versions.pop(), names


def check_elf(t: Target, data: bytes) -> None:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise BuildError("not a 64-bit little-endian ELF file")
    (machine,) = struct.unpack_from("<H", data, 18)
    if machine != t.machine:
        raise BuildError(f"ELF machine {machine}, not {t.machine}")
    (phoff,) = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for i in range(phnum):
        (ptype,) = struct.unpack_from("<I", data, phoff + i * phentsize)
        # PT_DYNAMIC, PT_INTERP: the wheel's manylinux and musllinux tags
        # hold because the binary links against no libc at all.
        if ptype in (2, 3):
            raise BuildError("dynamically linked; the Linux wheel tags need a static binary")


def macos_platform(t: Target, data: bytes) -> str:
    """Checks a Mach-O binary and returns its wheel platform tag."""
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise BuildError("not a 64-bit little-endian Mach-O file")
    cputype, _, _, ncmds, _ = struct.unpack_from("<iiIII", data, 4)
    if cputype != t.machine:
        raise BuildError(f"Mach-O CPU type {cputype:#x}, not {t.machine:#x}")
    off, minos = 32, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x32:  # LC_BUILD_VERSION: platform, minos, sdk
            platform, minos = struct.unpack_from("<II", data, off + 8)
            if platform != 1:  # PLATFORM_MACOS
                raise BuildError(f"LC_BUILD_VERSION platform {platform}, not macOS")
        elif cmd == 0x24:  # LC_VERSION_MIN_MACOSX: version, sdk
            (minos,) = struct.unpack_from("<I", data, off + 8)
        off += size
    if minos is None:
        raise BuildError("no minimum macOS version in the Mach-O load commands")
    major, minor = minos >> 16, (minos >> 8) & 0xFF
    if major >= 11 and minor:
        # Installers match macOS 11 and later by major version only, so a
        # binary that needs 13.1 is tagged for 14.
        major, minor = major + 1, 0
    return f"macosx_{major}_{minor}_{t.wheel_arch}"


def check_pe(t: Target, data: bytes) -> None:
    if data[:2] != b"MZ":
        raise BuildError("not a PE file")
    (lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[lfanew : lfanew + 4] != b"PE\0\0":
        raise BuildError("no PE signature")
    (machine,) = struct.unpack_from("<H", data, lfanew + 4)
    if machine != t.machine:
        raise BuildError(f"PE machine {machine:#x}, not {t.machine:#x}")


def platform_tags(t: Target, data: bytes) -> tuple[str, ...]:
    """Checks that the binary is the target's, and returns its wheel's platform tags."""
    if t.fmt == "elf":
        check_elf(t, data)
    elif t.fmt == "macho":
        return (macos_platform(t, data),)
    else:
        check_pe(t, data)
    assert t.platforms is not None
    return t.platforms


def record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def metadata(version: str) -> bytes:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {NAME}",
        f"Version: {version}",
        f"Summary: {SUMMARY}",
        *(f"Project-URL: {label}, {url}" for label, url in PROJECT_URLS),
        *(f"Classifier: {c}" for c in CLASSIFIERS),
        f"Requires-Python: {REQUIRES_PYTHON}",
        "Description-Content-Type: text/markdown",
    ]
    return ("\n".join(lines) + "\n\n" + README.read_text(encoding="utf-8")).encode("utf-8")


def release_module(release: str, version: str, t: Target, digest: str) -> bytes:
    return (
        '"""The release this wheel was built from (written by python/build_wheels.py)."""\n'
        "\n"
        f"# The version of the package, and of the release (internal/cli's Version).\n"
        f"VERSION = {version!r}\n"
        f"RELEASE = {release!r}\n"
        f"# The release target whose binary this wheel carries, and its SHA-256.\n"
        f"TARGET = {t.key!r}\n"
        f"BINARY_SHA256 = {digest!r}\n"
    ).encode("utf-8")


def package_sources() -> dict[str, bytes]:
    present = sorted(
        p.name for p in PACKAGE_DIR.iterdir() if p.name != "__pycache__"
    )
    if present != sorted(PACKAGE_FILES):
        raise BuildError(
            f"{PACKAGE_DIR} holds {present}, not {sorted(PACKAGE_FILES)}: list a new file in PACKAGE_FILES"
        )
    return {name: (PACKAGE_DIR / name).read_bytes() for name in PACKAGE_FILES}


def write_wheel(out: Path, release: str, t: Target, binary: bytes, sources: dict[str, bytes]) -> Path:
    version = pypi_version(release)
    platforms = platform_tags(t, binary)
    tag = f"py3-none-{'.'.join(platforms)}"
    dist_info = f"{DIST}-{version}.dist-info"
    wheel = "\n".join(
        [
            "Wheel-Version: 1.0",
            "Generator: tzun-verify python/build_wheels.py",
            "Root-Is-Purelib: false",
            *(f"Tag: py3-none-{p}" for p in platforms),
        ]
    ) + "\n"

    # (path in the wheel, bytes, executable), in the order they are written,
    # the .dist-info directory last and RECORD last of all.
    files: list[tuple[str, bytes, bool]] = [
        (f"{DIST}/{name}", data, False) for name, data in sources.items()
    ]
    files.append((f"{DIST}/_release.py", release_module(release, version, t, sha256(binary)), False))
    files.sort(key=lambda f: f[0])
    files.append((f"{DIST}-{version}.data/scripts/{t.exe}", binary, True))
    files.append((f"{dist_info}/METADATA", metadata(version), False))
    files.append((f"{dist_info}/WHEEL", wheel.encode("utf-8"), False))
    record = "".join(f"{p},{record_hash(d)},{len(d)}\n" for p, d, _ in files)
    record += f"{dist_info}/RECORD,,\n"
    files.append((f"{dist_info}/RECORD", record.encode("utf-8"), False))

    path = out / f"{DIST}-{version}-{tag}.whl"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data, executable in files:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.create_system = 3  # Unix, so installers read the mode below
            mode = 0o755 if executable else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data, compresslevel=9)
    path.write_bytes(buf.getvalue())
    return path


def build(release_dir: Path, out: Path, tag: str | None) -> list[Path]:
    sums = read_sums(release_dir / "SHA256SUMS")
    release, names = release_binaries(sums)
    check_tag(release, tag)
    pypi_version(release)
    if out.exists() and any(out.iterdir()):
        raise BuildError(f"{out} is not empty")
    sources = package_sources()
    binaries: dict[str, bytes] = {}
    for key, name in sorted(names.items()):
        data = (release_dir / name).read_bytes()
        if sha256(data) != sums[name]:
            raise BuildError(f"{name} does not match SHA256SUMS")
        binaries[key] = data
    out.mkdir(parents=True, exist_ok=True)
    wheels = []
    for key, data in binaries.items():
        try:
            wheels.append(write_wheel(out, release, TARGETS[key], data, sources))
        except BuildError as e:
            raise BuildError(f"{names[key]}: {e}") from None
    return wheels


def wheel_binary(path: Path) -> tuple[str, bytes]:
    """A wheel's target key and binary, after checking the wheel's RECORD."""
    with zipfile.ZipFile(path) as z:
        entries = {i.filename: z.read(i) for i in z.infolist()}
    records = [n for n in entries if n.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise BuildError(f"{path.name}: {len(records)} RECORD files")
    listed = set()
    for line in entries[records[0]].decode("utf-8").splitlines():
        name, digest, size = line.rsplit(",", 2)
        listed.add(name)
        if name == records[0]:
            continue
        data = entries.get(name)
        if data is None or digest != record_hash(data) or size != str(len(data)):
            raise BuildError(f"{path.name}: {name} does not match RECORD")
    if listed != set(entries):
        raise BuildError(f"{path.name}: RECORD and the wheel's files differ")
    release = entries.get(f"{DIST}/_release.py")
    if release is None:
        raise BuildError(f"{path.name}: no {DIST}/_release.py")
    m = re.search(rb"^TARGET = '([a-z0-9_]+)'$", release, re.MULTILINE)
    if not m or m.group(1).decode() not in TARGETS:
        raise BuildError(f"{path.name}: _release.py names no known target")
    t = TARGETS[m.group(1).decode()]
    scripts = [n for n in entries if re.fullmatch(rf"{DIST}-[^/]+\.data/scripts/[^/]+", n)]
    if len(scripts) != 1 or not scripts[0].endswith("/" + t.exe):
        raise BuildError(f"{path.name}: expected one script, {t.exe}; found {scripts}")
    return t.key, entries[scripts[0]]


def check_tag(release: str, tag: str | None) -> None:
    if tag is not None and tag != f"v{release}":
        raise BuildError(f"the tag is {tag}, but the release's files are version {release} (tag v{release})")


def check(sums_path: Path, wheels: list[Path], extract: Path | None, tag: str | None = None) -> None:
    sums = read_sums(sums_path)
    release, names = release_binaries(sums)
    check_tag(release, tag)
    seen: dict[str, Path] = {}
    for w in wheels:
        key, data = wheel_binary(w)
        if key in seen:
            raise BuildError(f"{w.name} and {seen[key].name} are both for {key}")
        seen[key] = w
        if not w.name.startswith(f"{DIST}-{pypi_version(release)}-"):
            raise BuildError(f"{w.name} is not version {pypi_version(release)}")
        if sha256(data) != sums[names[key]]:
            raise BuildError(
                f"{w.name} carries a binary whose SHA-256 is {sha256(data)}; "
                f"the release's {names[key]} is {sums[names[key]]}"
            )
        print(f"OK   {w.name}  {names[key]}  {sums[names[key]]}")
        if extract is not None:
            extract.mkdir(parents=True, exist_ok=True)
            (extract / names[key]).write_bytes(data)
    missing = sorted(set(TARGETS) - set(seen))
    if missing:
        raise BuildError(f"no wheel for {', '.join(missing)}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="build_wheels.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--tag", help="refuse release files whose version is not this tag's (v<version>)")
    ap.add_argument("--check", metavar="SHA256SUMS", type=Path, help="check wheels against a release's SHA256SUMS")
    ap.add_argument("--extract", metavar="DIR", type=Path, help="with --check: write each wheel's binary here")
    ap.add_argument("paths", nargs="+", type=Path)
    a = ap.parse_args(argv)
    try:
        if a.check is not None:
            check(a.check, a.paths, a.extract, a.tag)
            return 0
        if a.extract is not None or len(a.paths) != 2:
            ap.error("usage: build_wheels.py [--tag v<version>] <release-dir> <out-dir>")
        for w in build(a.paths[0], a.paths[1], a.tag):
            print(f"{sha256(w.read_bytes())}  {w.name}")
        return 0
    except BuildError as e:
        print(f"build_wheels: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
