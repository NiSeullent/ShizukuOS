#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile and run the static-TLS host contract."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "build/evidence/chromium-156"
sys.path.insert(0, str(ROOT / "ntwin32/loader"))
import evidence


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    exe = OUT / "test-tls"
    cmd = ["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
           str(HERE / "tls.c"), str(HERE / "test_tls.c"), "-I", str(HERE), "-o", str(exe)]
    subprocess.run(cmd, check=True)
    result = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
    payload = json.loads(result.stdout)
    if not payload.get("passed"):
        raise SystemExit(result.stdout)
    evidence.panel(OUT / "03-tls-callback-order.png",
                   "Static TLS callback order from the host contract",
                   [result.stdout.strip(),
                    "registration order: module A callbacks, then module B",
                    "PROCESS_ATTACH reason 1, reserved NULL",
                    "template 11 22 33 44 plus 4 zero-fill bytes",
                    "characteristics must be zero; empty directories are rejected"])
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
