#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests of the production SMP ACPI parser. No VM is executed."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCES = [REPO / p for p in (
    "shizukudos/kernel64/smp_acpi.c", "shizukudos/kernel64/smp_acpi.h",
    "shizukudos/tests/test_k64_smp_acpi.c", "shizukudos/tests/test_k64_smp_acpi.py")]


def hashes():
    return {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPO / "build/shizukudos/smp-acpi-host")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    before = hashes()
    runs = []
    for name, compiler, flags in (
        ("gcc", "gcc", ["-O2"]),
        ("asan-ubsan", "clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]),
    ):
        binary = out / name
        cmd = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", *flags,
               str(SOURCES[2]), str(SOURCES[0]), "-o", str(binary)]
        subprocess.run(cmd, cwd=REPO, check=True, timeout=60)
        result = subprocess.run([str(binary)], cwd=REPO, check=True, capture_output=True, text=True, timeout=30)
        (out / (name + ".log")).write_text(result.stdout + result.stderr)
        assert "PASS production SMP ACPI parser:" in result.stdout, result.stdout
        runs.append({"name": name, "compile": cmd, "exit_code": result.returncode,
                     "output": result.stdout, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()})
    for bits in (32, 64):
        cmd = ["gcc", f"-m{bits}", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
               "-fno-builtin", "-fno-stack-protector", "-c", str(SOURCES[0]), "-o", str(out / f"parser-{bits}.o")]
        subprocess.run(cmd, cwd=REPO, check=True, timeout=30)
        runs.append({"name": f"freestanding-{bits}", "compile": cmd, "exit_code": 0})
    after = hashes()
    assert before == after, "sources changed during host validation"
    receipt = {"scope": "host production ACPI parser; no VM executed; no SMP scheduling claim",
               "sources_sha256": before, "sources_unchanged": True, "runs": runs}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
