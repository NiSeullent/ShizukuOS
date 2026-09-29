#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the kernel32 test programs (tests/t_k32_*.c) on Wine, outside Kernel64.

This is a developer cross-check, not a replacement for the in-kernel run (tests/t_k32_*.exe inside Kernel64 under QEMU):

  reference  the program is linked against the ordinary mingw kernel32 import library, so on Wine it exercises Wine's own
             kernel32. A FAIL here means the test's expectation disagrees with an independent Win32 implementation and must be
             examined (Wine is not Windows, but a disagreement is a reason to re-read the documentation).
  shizuku    the Shizuku kernel32 sources listed in GROUPS for that test are compiled into the program itself (the test is built
             with -D_KERNEL32_ so its calls bind to them), so the real Shizuku code runs natively with 32-bit LONG, the real TEB/PEB
             layout and Wine's ntdll underneath. Only groups whose code needs no Kernel64-specific system call are listed.

Requires wine64 (apt install wine64). Usage: run_wine_tests.py [test-name ...]
"""
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
W64 = HERE.parents[1]
K32 = W64 / "kernel32"
REPO = HERE.parents[3]
OUT = REPO / "build" / "shizukudos" / "win64" / "wine"
CC = "x86_64-w64-mingw32-gcc"
WINE = "/usr/lib/wine/wine64"

COMMON = ["-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-mno-red-zone",
          "-fno-ident", "-fno-tree-loop-distribute-patterns", "-Wno-unused-function", "-Wno-unused-parameter",
          "-Wno-cast-function-type", "-mcx16"]

# test -> Shizuku kernel32 sources that provide the group (everything else comes from Wine's kernel32/ntdll)
GROUPS = {
    "t_k32_nls": ["k32_nls.c", "nls_core.c", "nls_fmt.c", "k32_utf.c"],
    "t_k32_slist": ["k32_slist.c"],
    "t_k32_module": ["k32_module.c", "k32_utf.c", "../ntdll/unwind.c", "../ntdll/ntdll_asm.S"],
}
DEFINES = {                                       # per-test compiler defines (ntdll sources bind the Rtl* calls of the test to them)
    "t_k32_module": ["-DSHZ_NTDLL_BUILD", "-D_NTSYSTEM_="],
}
SHIM = HERE / "wine_shim.c"                       # k32_nt_error over Wine's ntdll
WINDRES = "x86_64-w64-mingw32-windres"


def build(test, shizuku):
    exe = OUT / f"{test}.{'shizuku' if shizuku else 'reference'}.exe"
    cmd = [CC, *COMMON, "-DSHZ_NO_EVIDENCE", "-nostdlib", "-Wl,--entry,ShzStart", "-Wl,--subsystem,console",
           "-Wl,--image-base,0x140000000", "-I", str(W64 / "include"), "-I", str(W64 / "crt")]
    if shizuku:
        cmd += ["-D_KERNEL32_="] + DEFINES.get(test, [])
    cmd += [str(W64 / "tests" / f"{test}.c"), str(W64 / "crt" / "shzcrt.c")]
    rc = W64 / "tests" / f"{test}.rc"
    if rc.exists():
        res = OUT / f"{test}_res.o"
        subprocess.run([WINDRES, "-O", "coff", "-i", str(rc), "-o", str(res)], check=True)
        cmd.append(str(res))
    if shizuku:
        cmd += [str(K32 / s) for s in GROUPS[test]] + [str(SHIM)]
    cmd += ["-lgcc", "-lkernel32", "-lntdll", "-o", str(exe)]
    subprocess.run(cmd, check=True)
    return exe


def run(exe):
    env = dict(os.environ, WINEPREFIX=str(OUT / "prefix"), WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=", DISPLAY="")
    p = subprocess.run([WINE, str(exe)], capture_output=True, text=True, timeout=300, env=env)
    return p.returncode, p.stdout + p.stderr


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    names = sys.argv[1:] or sorted(p.stem for p in (W64 / "tests").glob("t_k32_*.c"))
    bad = 0
    for name in names:
        for shizuku in (False, True):
            label = "shizuku " if shizuku else "reference"
            if shizuku and name not in GROUPS:
                continue
            rc, out = run(build(name, shizuku))
            passed = len(re.findall(r"^PASS:", out, re.M))
            fails = re.findall(r"^FAIL:.*$", out, re.M)
            print(f"{name} [{label}]: exit={rc} pass={passed} fail={len(fails)}")
            for f in fails:
                print("   " + f)
            if rc != 0 and not fails:
                print("   " + out[-800:].replace("\n", "\n   "))
            if shizuku and (rc != 0 or fails):
                bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
