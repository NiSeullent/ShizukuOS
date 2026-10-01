#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile and run the CSM INT 13h host test. No VM and no firmware."""
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / "build"
SOURCES = [
    HERE / "test_int13.c",
    HERE / "bios" / "int13.c",
    HERE / "storage" / "geometry.c",
    HERE / "storage" / "ramdisk.c",
    HERE / "storage" / "handoff.c",
    HERE / "storage" / "ahci_hook.c",
    ROOT / "drivers" / "ahci_native" / "ahci.c",
]


def run(cmd):
    result = subprocess.run([str(x) for x in cmd], capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result


def main():
    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        raise SystemExit("clang or gcc is required")
    BUILD.mkdir(exist_ok=True)
    binary = BUILD / "test_int13"
    flags = [
        "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
        "-Wconversion", "-Wshadow", "-O1", "-g",
        "-fno-omit-frame-pointer",
    ]
    if Path(compiler).name.startswith("clang"):
        flags += ["-fsanitize=address,undefined"]
    run([compiler, *flags, "-I", HERE, *SOURCES, "-o", binary])
    linked = run(["nm", binary]).stdout
    if " ahci_read_sector" not in linked and " T ahci_read_sector" not in linked:
        # nm prints the type in the second column: "T ahci_read_sector".
        if "ahci_read_sector" not in linked:
            raise SystemExit("ahci_read_sector was not linked")
    result = run([binary])
    sys.stdout.write(result.stdout)
    if "ALL PASS" not in result.stdout:
        raise SystemExit("host test did not report ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
