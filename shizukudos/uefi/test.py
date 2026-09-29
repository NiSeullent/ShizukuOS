#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile and run bounded host tests, optionally with installed sanitizers."""
import argparse
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    cc = shutil.which(args.cc)
    if not cc:
        raise SystemExit("A native C compiler is required; nothing installed")
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    suffix = "-sanitized" if args.sanitize else ""
    binary = build / ("host-tests" + suffix)
    flags = ["-fno-omit-frame-pointer", "-fsanitize=address,undefined"] if args.sanitize else []
    subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g"] + flags + [
                    "-I", str(ROOT.parent.parent / "ntwddm" / "include"),
                    str(ROOT / "test.c"), str(ROOT / "boot.c"), str(ROOT / "display.c"),
                    str(ROOT.parent.parent / "ntwddm" / "src" / "ntwddm.c"), "-o", str(binary)],
                   check=True, timeout=60)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20)
    (build / ("host-tests" + suffix + ".log")).write_text(result.stdout + result.stderr)
    print(result.stdout + result.stderr, end="")
    result.check_returncode()


if __name__ == "__main__":
    main()
