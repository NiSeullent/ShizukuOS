#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile and run actual native-domain C bodies; VMX/EPT callbacks are modeled."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
SUPERVISOR = NATIVE.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.exists() or not output.parent.is_dir():
        parser.error("a new output directory with an existing parent is required")
    output.mkdir()
    cases = {
        "ata": (HERE / "ata_host.c", NATIVE / "ata_pio.c"),
        "string": (HERE / "string_host.c", NATIVE / "string_pio.c", NATIVE / "ata_pio.c"),
        "pic": (HERE / "pic_host.c", SUPERVISOR / "src/devices.c"),
        "constructor": (HERE / "constructor_host.c", NATIVE / "ata_pio.c"),
        "channels": (HERE / "channels_host.c",),
    }
    results = []
    for compiler in ("gcc", "clang"):
        if not shutil.which(compiler):
            raise SystemExit(f"missing compiler {compiler}; validation is incomplete")
        for name, sources in cases.items():
            binary = output / f"{compiler}-{name}"
            sanitizer = ["-fsanitize=address,undefined"] if compiler == "clang" else []
            command = [compiler, "-std=c11", "-D_GNU_SOURCE", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                       *sanitizer, "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                       "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                       *map(str, sources), "-o", str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            (output / f"{compiler}-{name}-compile.log").write_text(built.stdout + built.stderr)
            if built.returncode:
                raise SystemExit(f"FAIL {compiler}/{name}: {built.stderr[-1500:]}")
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
            (output / f"{compiler}-{name}-run.log").write_text(run.stdout + run.stderr)
            if run.returncode or not run.stdout.startswith("PASS ") or run.stderr:
                raise SystemExit(f"FAIL {compiler}/{name}: {run.stdout[-500:]} {run.stderr[-1500:]}")
            results.append({"compiler": compiler, "case": name, "sanitizers": sanitizer,
                            "stdout": run.stdout.strip(),
                            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()})
    result = {"status": "PASS_ACTUAL_C_BODIES_GCC_STRICT_AND_CLANG_SANITIZERS", "results": results,
              "VMX_executed": False, "Windows98_executed": False}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
