#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host negative checks for the Win98->Shizuku64 GUI ABI against the real headers and VxD owner stamper."""
import subprocess, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

def main():
    with tempfile.TemporaryDirectory() as d:
        exe = Path(d) / "abi_host"
        subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "ntwrapper/vxd"), "-o", str(exe),
                        str(HERE / "w98w64_abi_host.c"), str(ROOT / "ntwrapper/vxd/w64_owner.c")], check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout
    assert "W98W64 ABI HOST PASS" in out, out
    print(out.strip())

if __name__ == "__main__":
    main()
