#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and run the native unit tests of the pure kernel32 code (NLS core and formatting engine).

These tests need no emulator: they compile kernel32/nls_core.c and nls_fmt.c with the host gcc and check them against the C
library's ctype for ASCII, fixed Unicode facts and documented Windows formatting rules. The same sources are linked into
kernel32.dll; the in-kernel programs tests/t_k32_*.c then check the exported Win32 API on top of them.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parents[3] / "build" / "shizukudos" / "win64" / "host"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    fails = 0
    for name in sorted(p.stem for p in HERE.glob("*_host_test.c")):
        exe = OUT / name
        cmd = ["gcc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-o", str(exe),
               str(HERE / f"{name}.c")]
        subprocess.run(cmd, check=True)
        r = subprocess.run([str(exe)], capture_output=True, text=True)
        print(f"{name}: {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else '(no output)'}")
        if r.returncode:
            fails += 1
            print(r.stdout[-4000:])
            print(r.stderr[-2000:])
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
