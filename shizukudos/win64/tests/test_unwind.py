#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Builds and runs the ntdll x64 unwinder host test (test_unwind.c + the real win64/ntdll/unwind.c, compiled natively
against tests/hostshim/nt.h) under GCC and under Clang ASan/UBSan.

The x64 UNWIND_INFO format packs 32-bit fields at 2-byte alignment (the unwind codes are 16-bit slots), which is
well-defined on x86-64 (unaligned loads are supported by the hardware) but not by the C standard, so the alignment
sanitizer is turned off for this one test; every other UBSan check and the full AddressSanitizer stay on and guard the
200000-iteration unwind-data fuzz and the 100000-iteration __C_specific_handler fuzz.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE.parents[2] / "build" / "shizukudos" / "win64" / "petest"


def run(cmd, **kw):
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True, **kw)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"failed: {' '.join(map(str, cmd))}")
    return r.stdout


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    src = [HERE / "test_unwind.c", ROOT / "ntdll" / "unwind.c"]
    common = ["-std=c11", "-Wall", "-Wextra", "-I", HERE / "hostshim"]
    run(["gcc", "-O2", *common, "-Wno-pragmas", *src, "-o", BUILD / "test_unwind"])
    print(run([BUILD / "test_unwind"]).strip().splitlines()[-1])
    run(["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-sanitize=alignment", "-fno-sanitize-recover=all",
         "-fno-omit-frame-pointer", *common, *src, "-o", BUILD / "test_unwind_asan"])
    print("ASan/UBSan:", run([BUILD / "test_unwind_asan"]).strip().splitlines()[-1])


if __name__ == "__main__":
    main()
