#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests of the ShizukuTrident Lite portable core (Linux, gcc, AddressSanitizer + UndefinedBehaviorSanitizer).

Every tests/t_*.c is linked with all of core/*.c (including the weak L1/L2 stubs, which real implementations
override) and tests/platform_host.c into its own program and run; each program prints PASS:/FAIL: lines and exits 0
only when all its checks passed. LeakSanitizer is on, so a leaked node or string fails the run too.

Exit status 0 = every test program passed.

    python3 shizukudos/win64/trident/engine/tests/run_host_tests.py [--out DIR] [-k NAME] [-v]
"""
import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent
CORE = ENGINE / "core"
REPO = ENGINE.parents[3]
DEFAULT_OUT = REPO / "build" / "shizukudos" / "trident-engine" / "host-tests"

CC = os.environ.get("CC", "gcc")
CFLAGS = ["-std=c99", "-g", "-O1", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
          "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined", "-fno-omit-frame-pointer"]
LDFLAGS = ["-fsanitize=address,undefined"]


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def compile_one(src, obj, extra=()):
    r = run([CC, *CFLAGS, *extra, "-I", CORE, "-c", src, "-o", obj])
    if r.returncode:
        raise SystemExit(f"compile failed: {src}\n{r.stdout}{r.stderr}")
    return obj


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("-k", dest="only", help="run only tests whose name contains this")
    ap.add_argument("-v", action="store_true", help="print every PASS line")
    args = ap.parse_args()
    out = Path(args.out)
    (out / "obj").mkdir(parents=True, exist_ok=True)
    started = time.time()

    core_srcs = sorted(CORE.glob("*.c")) + [HERE / "platform_host.c"]
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 2) as pool:
        objs = list(pool.map(lambda s: compile_one(s, out / "obj" / (s.stem + ".o")), core_srcs))

    tests = sorted(HERE.glob("t_*.c"))
    if args.only:
        tests = [t for t in tests if args.only in t.stem]
    if not tests:
        raise SystemExit("no tests")

    def build_and_run(src):
        exe = out / src.stem
        obj = compile_one(src, out / "obj" / (src.stem + ".o"), ["-I", HERE])
        r = run([CC, *LDFLAGS, obj, *objs, "-o", exe])
        if r.returncode:
            return src.stem, 1, f"link failed\n{r.stdout}{r.stderr}", 0.0
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=0",
                   UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1", SHZ_TEST_DATA=str(HERE / "data"),
                   SHZ_TEST_TMP=str(out))
        t0 = time.time()
        r = run([exe], cwd=out, env=env, timeout=300)
        return src.stem, r.returncode, r.stdout + r.stderr, time.time() - t0

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 2) as pool:
        results = list(pool.map(build_and_run, tests))

    failed = 0
    for name, rc, output, secs in results:
        lines = output.splitlines()
        passes = sum(1 for l in lines if l.startswith("PASS:"))
        fails = [l for l in lines if l.startswith("FAIL:") or l.startswith("  ")]
        status = "PASS" if rc == 0 else "FAIL"
        if rc:
            failed += 1
        print(f"{status}: {name} ({passes} checks passed, {secs:.1f}s)")
        if args.v:
            for l in lines:
                print("    " + l)
        elif rc:
            for l in fails[:60]:
                print("    " + l)
            if not fails:
                print("\n".join("    " + l for l in lines[-40:]))
    print(f"host tests: {len(results)} programs, {failed} failed ({time.time() - started:.1f}s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
