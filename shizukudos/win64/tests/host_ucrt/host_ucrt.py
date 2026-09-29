#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host (Linux) verification of the portable core of the Shizuku UCRT (shizukudos/win64/dlls/ucrtbase).

The core translation units are compiled for the host with -DSHZ_HOST_TEST, linked into one relocatable object and every
symbol is prefixed "u_" (objcopy --prefix-symbols), so the tests can call the Shizuku functions next to glibc's without
either binding to the other. Tests:
  test_math  accuracy of every math function against glibc's 80-bit long double functions (floats against double),
             bit-exactness of the exact functions (fmod, remainder, remquo, fma, sqrt, rounding, scaling)
  test_fmt   strtod/strtof and printf %e %f %g %a against glibc (both are exact), scanf, strtol family, qsort,
             gmtime/mkgmtime/strftime against glibc, _ecvt/_fcvt, ctype, secure string functions
Usage: host_ucrt.py [--samples N] [--seed S] [--only math|fmt]
"""
import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
UCRT = REPO / "shizukudos/win64/dlls/ucrtbase"
OUT = REPO / "build/shizukudos/win64/host_ucrt"
CORE = ["printf.c", "fltfmt.c", "fltparse.c", "scanf.c", "math.c", "fenv.c", "string.c", "ctype.c", "convert.c", "utility.c",
        "time.c"]
CFLAGS = ["-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-unused-function", "-fno-builtin", "-ffreestanding",
          "-fno-stack-protector", "-fno-pic", "-fno-pie", "-fno-tree-loop-distribute-patterns", "-DSHZ_HOST_TEST", "-I", str(UCRT)]


def run(cmd, **kw):
    r = subprocess.run([str(c) for c in cmd], **kw)
    if r.returncode:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(map(str, cmd))}")
    return r


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    objs = []
    for c in CORE:
        o = OUT / (Path(c).stem + ".o")
        run(["gcc", *CFLAGS, "-c", UCRT / c, "-o", o])
        objs.append(o)
    run(["ld", "-r", "-o", OUT / "core.o", *objs])
    run(["objcopy", "--prefix-symbols=u_", OUT / "core.o", OUT / "core_u.o"])
    run(["gcc", "-O2", "-fno-pic", "-fno-pie", "-c", HERE / "shim.c", "-o", OUT / "shim.o"])
    exes = {}
    for t in ("test_math", "test_fmt"):
        exe = OUT / t
        run(["gcc", "-O2", "-fno-pic", "-no-pie", "-Wall", "-Wno-unused-function", HERE / f"{t}.c", OUT / "core_u.o", OUT / "shim.o",
             "-lm", "-o", exe])
        exes[t] = exe
    return exes


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", type=int, default=200000)
    ap.add_argument("--seed", default="0x9e3779b97f4a7c15")
    ap.add_argument("--only", choices=("math", "fmt"))
    args = ap.parse_args()
    exes = build()
    rc = 0
    for name, exe in exes.items():
        if args.only and not name.endswith(args.only):
            continue
        print(f"== {name}", flush=True)
        r = subprocess.run([str(exe), str(args.samples), args.seed])
        rc |= r.returncode
    print("host_ucrt:", "PASS" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
