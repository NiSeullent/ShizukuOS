#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the production CreateFileW access translation (k32_create_access.h)
against the verbatim Kernel64 sysfile.c delete-on-close/overwrite guard.
Host evidence only; T_K32_SYS remains the guest acceptance test."""
import hashlib, re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
K32 = ROOT / "shizukudos/win64/kernel32"
FIXTURE = Path(__file__).with_suffix(".c")


def main():
    sysfile = (ROOT / "shizukudos/kernel64/sysfile.c").read_text()
    guard = re.search(r"\n(    if \(\(disposition == FILE_OVERWRITE \|\| disposition == FILE_OVERWRITE_IF\) &&.*?"
                      r"DELETE_ACCESS\)\)\) return STATUS_ACCESS_DENIED;)\n", sysfile, re.S)
    if not guard:
        raise SystemExit("production sysfile.c delete-on-close guard not found")
    caller = (K32 / "k32_ipc_io.c").read_text()
    if caller.count("NtCreateFile(&h, k32_create_native_access(access, flags), &oa,") != 1 or \
            "if (flags & FILE_FLAG_DELETE_ON_CLOSE) opts |= NT_OPT_DELETE_ON_CLOSE;" not in caller:
        raise SystemExit("CreateFileW does not use the production translation")
    out = Path("/dev/shm/k32-create-access-host")
    out.mkdir(parents=True, exist_ok=True)
    src = out / "fixture.c"
    src.write_text(FIXTURE.read_text().replace("/* @SYSFILE_GUARD@ */", guard.group(1)))
    status = 0
    for cc in ("gcc", "clang"):
        if not shutil.which(cc):
            continue
        exe = out / cc
        extra = ["-fsanitize=address,undefined"] if cc == "clang" else []
        build = subprocess.run([cc, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", *extra, "-I", str(K32),
                                "-I", str(ROOT / "shizukudos/kcommon"), str(src), "-o", str(exe)],
                               capture_output=True, text=True, timeout=30)
        if build.returncode:
            print(build.stderr); status = 1; continue
        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
        print(f"{cc}: {run.stdout.strip()} {run.stderr.strip()}")
        status |= run.returncode
    print("guard_sha256", hashlib.sha256(guard.group(1).encode()).hexdigest())
    return status


if __name__ == "__main__":
    sys.exit(main())
