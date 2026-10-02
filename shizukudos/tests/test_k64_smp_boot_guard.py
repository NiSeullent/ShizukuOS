#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host production native Multiboot-page retirement checks; never a VM run."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOURCES = [REPO / p for p in (
    "shizukudos/kernel64/smp_boot_guard.h", "shizukudos/kernel64/smp_acpi.h",
    "shizukudos/kernel64/standalone/memholes.h",
    "shizukudos/tests/test_k64_smp_boot_guard.c", "shizukudos/tests/test_k64_smp_boot_guard.py")]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hashes():
    return {str(p.relative_to(REPO)): digest(p) for p in SOURCES}


def tool_hashes():
    result = {name: digest(Path(shutil.which(name)).resolve(strict=True)) for name in ("gcc", "clang", "as", "nm")}
    result["python"] = digest(Path(sys.executable).resolve(strict=True))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("output must be a new unique directory")
    out.mkdir(parents=True)
    before, tools_before, runs = hashes(), tool_hashes(), []
    for name, compiler, flags in (
        ("gcc", "gcc", ["-O2"]),
        ("asan-ubsan", "clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]),
    ):
        binary = out / name
        cmd = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", *flags, str(SOURCES[3]), "-o", str(binary)]
        subprocess.run(cmd, cwd=REPO, check=True, timeout=60)
        run = subprocess.run([str(binary)], cwd=REPO, check=True, capture_output=True, text=True, timeout=30)
        (out / (name + ".log")).write_text(run.stdout + run.stderr)
        if "PASS production SMP boot retirement guard:" not in run.stdout:
            raise SystemExit("host guard success marker missing")
        runs.append({"name": name, "command": cmd, "returncode": run.returncode, "output": run.stdout,
                     "binary_sha256": digest(binary)})
    probe = out / "freestanding.c"
    probe.write_text('#include "smp_boot_guard.h"\nint guard(shz_smp_phys_read_fn r,void *c,uint64_t i,uint64_t a,uint64_t f,uint64_t m){return shz_smp_boot_pages_safe(r,c,i,a,f,m);}\n')
    for bits in (32, 64):
        obj = out / f"guard-{bits}.o"
        cmd = ["gcc", f"-m{bits}", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
               "-fno-builtin", "-fno-pie", "-fno-stack-protector", "-I", str(REPO / "shizukudos/kernel64"),
               "-c", str(probe), "-o", str(obj)]
        subprocess.run(cmd, cwd=REPO, check=True, timeout=30)
        undefined = subprocess.run(["nm", "-u", str(obj)], check=True, capture_output=True, text=True, timeout=10).stdout
        if undefined.strip():
            raise SystemExit("freestanding guard acquired undefined runtime dependencies")
        runs.append({"name": f"freestanding-{bits}", "command": cmd, "returncode": 0, "object_sha256": digest(obj)})
    after, tools_after = hashes(), tool_hashes()
    valid = before == after and tools_before == tools_after
    receipt = {"scope": "host production native Multiboot retirement guard; no firmware/VM/AP/Windows execution",
               "all_expected": valid, "sources_unchanged": before == after, "tools_unchanged": tools_before == tools_after,
               "sources_sha256": before, "tools_sha256": tools_before, "runs": runs}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({k: v for k, v in receipt.items() if k not in ("sources_sha256", "tools_sha256")}, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
