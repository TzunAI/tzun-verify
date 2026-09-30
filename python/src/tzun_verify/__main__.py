"""``python -m tzun_verify [flags] <bundle.json>``: the tzun-verify command.

It runs the binary this package installed, the same one as the
``tzun-verify`` command, with the same arguments, and exits with its exit
code.
"""

from __future__ import annotations

import os
import subprocess
import sys

from . import BinaryError, binary


def main() -> None:
    try:
        path = binary()
    except BinaryError as e:
        print(f"tzun-verify: {e}", file=sys.stderr)
        sys.exit(1)
    args = [path, *sys.argv[1:]]
    if sys.platform == "win32":
        # Windows has no exec: run it and pass its exit code on.
        sys.exit(subprocess.run(args, check=False).returncode)
    os.execv(path, args)


if __name__ == "__main__":
    main()
