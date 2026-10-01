#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Builds and runs the ntdll x64 unwinder host test (test_unwind.c + the real win64/ntdll/unwind.c, compiled natively
against tests/hostshim/nt.h) under GCC and under Clang ASan/UBSan.

The x64 UNWIND_INFO format packs 32-bit fields at 2-byte alignment (the unwind codes are 16-bit slots), which is
well-defined on x86-64 (unaligned loads are supported by the hardware) but not by the C standard, so the alignment
sanitizer is turned off for this one test; every other UBSan check and the full AddressSanitizer stay on and guard the
200000-iteration unwind-data fuzz and the 100000-iteration __C_specific_handler fuzz.
"""
import argparse
import tempfile
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent



def run(cmd, **kw):
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True, timeout=60, **kw)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"failed: {' '.join(map(str, cmd))}")
    return r.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, help="isolated output directory; default: a fresh temporary directory")
    args = parser.parse_args()
    build = args.build_dir or Path(tempfile.mkdtemp(prefix="shz-unwind-host-"))
    build.mkdir(parents=True, exist_ok=True)
    print("Isolated host outputs:", build)
    common = ["-std=c11", "-Wall", "-Wextra", "-DSHZ_UNWIND_HOST_TEST", "-I", HERE / "hostshim"]
    for name in ("test_unwind", "test_unwind_robustness"):
        src = [HERE / (name + ".c"), ROOT / "ntdll" / "unwind.c"]
        run(["gcc", "-O2", *common, "-Wno-pragmas", *src, "-o", build / name])
        print(run([build / name]).strip().splitlines()[-1])
        run(["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-sanitize=alignment", "-fno-sanitize-recover=all",
             "-fno-omit-frame-pointer", *common, *src, "-o", build / (name + "_asan")])
        print("ASan/UBSan:", run([build / (name + "_asan")]).strip().splitlines()[-1])


if __name__ == "__main__":
    main()
