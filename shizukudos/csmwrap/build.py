#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the CSMWrap core and its host contract test. Does not boot a guest."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
SOURCES = [
    ROOT / "core" / "mode.c",
    ROOT / "core" / "checksum.c",
    ROOT / "core" / "kernel64.c",
    ROOT / "core" / "registry.c",
    ROOT / "handoff" / "fill.c",
    ROOT / "diagnostics" / "log.c",
    ROOT / "bios" / "dispatch.c",
    ROOT / "test_host.c",
]


def run(command):
    print(" ".join(command), flush=True)
    subprocess.run(command, check=True, timeout=60)


def main():
    BUILD.mkdir(exist_ok=True)
    entry = BUILD / "entry16.bin"
    stage2 = BUILD / "stage2-gate.bin"
    boot = BUILD / "boot-gate.bin"
    switch = BUILD / "switch.obj"
    binary = BUILD / "csmwrap-host-test"
    run(["nasm", "-f", "bin", "-o", str(entry), str(ROOT / "handoff" / "entry16.asm")])
    run(["nasm", "-f", "bin", "-I", str(ROOT.parent) + "/", "-o", str(stage2),
         str(ROOT.parent / "stage2.asm")])
    run(["nasm", "-f", "bin", "-o", str(boot), str(ROOT.parent / "boot.asm")])
    run(["nasm", "-f", "win64", "-o", str(switch), str(ROOT / "loader" / "switch.asm")])
    blob = entry.read_bytes()
    recorded = (ROOT / "loader" / "entry16_bytes.c").read_text()
    if not all(f"0x{byte:02x}" in recorded for byte in blob):
        raise SystemExit("entry16_bytes.c does not contain the assembled stub")
    if b"\xea\x00\x00\x00\x10" not in blob:
        raise SystemExit("16-bit stub does not enter ShizukuDOS at 1000:0000")
    run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fno-strict-aliasing",
         "-o", str(binary), *[str(path) for path in SOURCES]])
    run([str(binary)])
    print(f"stage2 {stage2.stat().st_size} boot {boot.stat().st_size} stub {len(blob)}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode or 1)
