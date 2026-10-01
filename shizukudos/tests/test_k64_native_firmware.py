#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute adversarial host tests of the actual retained native firmware map."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PATHS = ["shizukudos/kernel64/standalone/native_firmware.h", "shizukudos/kernel64/standalone/boot32.c",
         "shizukudos/kernel64/standalone/memholes.h", "shizukudos/tests/test_k64_native_firmware.c",
         "shizukudos/tests/test_k64_native_firmware.py", "shizukudos/kernel64/standalone/qemu_firmware.h",
         "shizukudos/tests/test_k64_qemu_firmware.c", "shizukudos/kernel64/cpu_boot_contract.h",
         "shizukudos/tests/test_k64_ap_boot_contract.c", "shizukudos/kernel64/cpu_firmware.c",
         "shizukudos/kernel64/cpu_firmware.h"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    return {p: digest(REPO / p) if (REPO / p).exists() else None for p in PATHS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = sources()
    runs = []
    for mode, compiler, flags in (("gcc", "gcc", ["-O2"]), ("asan-ubsan", "clang", ["-O1", "-g",
            "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])):
        for source in (PATHS[3], PATHS[6], PATHS[8]):
            name = Path(source).stem + "-" + mode
            binary = out / name
            command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", *flags,
                       str(REPO / source), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
            record = {"name": name, "compile": command, "compile_exit": compiled.returncode}
            (out / f"{name}.compile.log").write_text(compiled.stdout + compiled.stderr)
            if compiled.returncode == 0:
                binary_before = digest(binary)
                run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                (out / f"{name}.log").write_text(run.stdout + run.stderr)
                record.update(exit_code=run.returncode, output=run.stdout + run.stderr,
                              binary_sha256=binary_before, binary_unchanged=digest(binary) == binary_before)
            runs.append(record)
    unchanged = before == sources()
    ok = unchanged and all(r.get("exit_code") == 0 and r.get("binary_unchanged") for r in runs)
    receipt = {"scope": "host native firmware resource handoff; no AP or scheduler completion claim",
               "status": "PASS" if ok else "FAIL", "sources_sha256": before,
               "sources_unchanged": unchanged, "runs": runs}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
