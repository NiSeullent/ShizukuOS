#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Builds real AMD64 PE images with mingw-w64, then runs the PE parser host tests under
GCC and Clang ASan/UBSan. Also cross-checks parser results with an independent tool
(objdump), and rejects the x86 build of the same sources."""
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
    dll, exe = BUILD / "sample_dll.dll", BUILD / "sample_exe.exe"
    run(["x86_64-w64-mingw32-gcc", "-O1", "-shared", "-nostdlib", "-Wl,--entry,DllMain", HERE / "sample_dll.c",
         HERE / "sample_dll.def", "-lkernel32", "-o", dll])
    run(["x86_64-w64-mingw32-gcc", "-O1", "-nostdlib", "-Wl,--entry,mainCRTStartup", "-Wl,--subsystem,console",
         HERE / "sample_exe.c", "-L", BUILD, "-l:sample_dll.dll", "-lkernel32", "-o", exe])
    # x86 build of the same DLL must be rejected as a wrong machine.
    x86 = BUILD / "sample_dll_x86.dll"
    run(["i686-w64-mingw32-gcc", "-O1", "-shared", "-nostdlib", "-Wl,--entry,_DllMain@12", HERE / "sample_dll.c",
         "-o", x86])
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", HERE / "test_pe_parse.c", ROOT / "pe_parse.c"]
    run(["gcc", "-O2", *common, "-o", BUILD / "test_pe"])
    print(run([BUILD / "test_pe", dll, exe]).strip())
    run(["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", *common,
         "-o", BUILD / "test_pe_asan"])
    print("ASan/UBSan:", run([BUILD / "test_pe_asan", dll, exe]).strip().splitlines()[-1])
    magic = run(["objdump", "-p", dll])
    assert "PE32+" in magic or "pei-x86-64" in run(["objdump", "-f", dll]), "independent tool disagrees"
    sect = run(["objdump", "-h", dll])
    assert ".text" in sect and ".pdata" in sect, "AMD64 image must carry an exception table"
    check = subprocess.run([BUILD / "test_pe", x86, exe], capture_output=True, text=True)
    assert check.returncode != 0, "x86 image must not be accepted by the AMD64 loader"
    print("independent objdump agrees (PE32+, .pdata present); x86 build rejected")
    # loader host tests that share this parser: API-set contracts, then real images (pe_parse on chrome.dll etc.)
    sys.path.insert(0, str(HERE))
    import test_apiset
    test_apiset.main()
    import test_pe_real
    test_pe_real.main()
    import test_unwind
    test_unwind.main()


if __name__ == "__main__":
    main()
