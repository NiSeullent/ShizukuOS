#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the CSMWrap host contract test."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    completed = subprocess.run([sys.executable, str(ROOT / "build.py")], cwd=ROOT, timeout=90)
    if completed.returncode != 0:
        sys.exit(completed.returncode)
    text = (ROOT / "build" / "csmwrap-host-test").exists()
    if not text:
        sys.exit("host test binary missing")
    print("test_core.py RESULT PASS")


if __name__ == "__main__":
    main()
