#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run source-layout checks and host ABI/page-table contracts under Clang sanitizers."""
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"


def main():
    BUILD.mkdir(exist_ok=True)
    binary = BUILD / "host-tests"
    subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    str(ROOT / "test.c"), str(ROOT / "contract.c"), str(ROOT / "paging.c"),
                    "-o", str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20)
    (BUILD / "host-tests.log").write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    result.check_returncode()
    transition = (BUILD / "transition.bin").read_bytes()
    assert len(transition) == 0x2800
    for base, stride, selector in ((0x1000, 16, 8), (0x2000, 8, 0x10)):
        for index in range(256):
            offset = base + index * stride
            low, cs, flags, high = struct.unpack_from("<HHHH", transition, offset)
            assert cs == selector and flags == 0x8e00
            assert 0x02000000 <= low | high << 16 < 0x02001000
    receipt = json.loads((BUILD / "build-result.json").read_text())
    assert receipt["payload"]["entry"] == 0x02010000
    print("PASS: 512 original IDT gates and fixed ELF32 payload entry")


if __name__ == "__main__":
    main()
