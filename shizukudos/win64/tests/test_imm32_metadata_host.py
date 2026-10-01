#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the exact production IMM32 metadata source with host adapters."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    test = root / "tests/test_imm32_metadata_host.c"
    source = root / "dlls/imm32/imm32_metadata.c"
    with tempfile.TemporaryDirectory(prefix="win98-imm32-metadata-") as folder:
        exe = Path(folder) / "metadata-test"
        flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation", "-fshort-wchar"]
        if args.sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        subprocess.run([args.cc, *flags, str(test), "-o", str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
        print(json.dumps({"production_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                          "test_sha256": hashlib.sha256(test.read_bytes()).hexdigest(),
                          "compiler": args.cc, "sanitize": args.sanitize}))

if __name__ == "__main__":
    main()
