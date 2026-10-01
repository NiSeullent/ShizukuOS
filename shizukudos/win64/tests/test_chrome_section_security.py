#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run production section security parser/policy contracts under GCC and Clang sanitizers."""
import argparse
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    out = args.build_dir or Path(tempfile.mkdtemp(prefix="shz-chrome-section-"))
    out.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_suffix(".c")
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
    for cc, flags, name in (("gcc", ["-O2"], "contract"),
                            ("clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"], "sanitized")):
        exe = out / name
        subprocess.run([cc, *common, *flags, str(source), "-o", str(exe)], check=True, timeout=60)
        result = subprocess.run([str(exe)], text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise SystemExit(result.stdout + result.stderr)
        print(name + ": " + result.stdout.strip())
    print("Isolated host outputs:", out)


if __name__ == "__main__":
    main()
