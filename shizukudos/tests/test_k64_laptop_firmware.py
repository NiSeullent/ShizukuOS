#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Production laptop firmware bootstrap/parser checks; no guest or port I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
KERNEL = ROOT / "shizukudos/kernel64"
TEST = Path(__file__).with_suffix(".c")
DRIVERS = ROOT / "drivers/shz_laptop"


def run(argv, log, environment=None):
    result = subprocess.run([str(arg) for arg in argv], cwd=ROOT,
                            env=environment, capture_output=True, text=True,
                            timeout=60)
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"exit {result.returncode}: {log}\n{result.stderr[-4000:]}")
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "build/laptop-firmware-boot")
    args = parser.parse_args()
    out = args.out.resolve()
    # Keep produced files in this worktree's ignored build area.
    out.relative_to((ROOT / "build").resolve())
    out.mkdir(parents=True, exist_ok=True)
    receipt = out / "result.json"
    receipt.unlink(missing_ok=True)
    sources = [KERNEL / "laptop_firmware.c", DRIVERS / "acpi.c", DRIVERS / "firmware.c", TEST]
    tracked = sources + [KERNEL / "laptop_firmware.h", KERNEL / "laptop_protocols.c",
                         KERNEL / "cpu_firmware.h", KERNEL / "cpu_firmware.c",
                         KERNEL / "smp_acpi.h", KERNEL / "smp_acpi.c",
                         KERNEL / "k64.h", KERNEL / "main.c",
                         DRIVERS / "firmware.h", DRIVERS / "laptop.h", DRIVERS / "internal.h",
                         ROOT / "drivers/common/device.h", Path(__file__).resolve()]
    # Include the transitive quoted-header closure. k64.h brings the actual ABI
    # and firmware owner layouts into the adapter compilation.
    pending = list(tracked)
    frozen = set()
    while pending:
        path = pending.pop().resolve()
        if path in frozen:
            continue
        path.relative_to(ROOT)
        frozen.add(path)
        data = path.read_bytes()
        pending.extend(path.parent / name.decode() for name in
                       re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', data, re.M))
    tracked = sorted(frozen)
    before = {str(p.relative_to(ROOT)): digest(p) for p in tracked}
    base = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fno-builtin"]
    evidence = []
    for label, compiler, flags in (
        ("gcc", "gcc", ["-O2"]),
        ("clang-sanitized", "clang", ["-O1", "-g", "-fsanitize=address,undefined",
                                        "-fno-omit-frame-pointer"]),
    ):
        binary = out / label
        command = [compiler, *base, *flags, *sources, "-o", binary]
        run(command, out / (label + "-build.log"))
        environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
                           UBSAN_OPTIONS="halt_on_error=1")
        result = run([binary], out / (label + ".log"), environment)
        if "PASS production laptop firmware boot adapter:" not in result.stdout:
            raise RuntimeError("Missing behavioral assertion result")
        print(result.stdout.strip(), flush=True)
        evidence.append({"name": label, "command": [str(arg) for arg in command],
                         "exit_code": result.returncode, "output": result.stdout,
                         "binary_sha256": digest(binary)})
    for compiler in ("gcc", "clang"):
        flags = [*base, "-m64", "-march=x86-64", "-O2", "-ffreestanding", "-fno-pie",
                 "-fno-pic", "-fno-stack-protector", "-mno-red-zone", "-mcmodel=kernel",
                 "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float", "-fstack-usage"]
        for profile, extra in (("supervisor", []), ("standalone", ["-DSHZ_STANDALONE"])):
            for source in (KERNEL / "laptop_firmware.c", KERNEL / "laptop_protocols.c", KERNEL / "main.c"):
                stem = compiler + "-" + profile + "-" + source.stem
                obj = out / (stem + ".o")
                command = [compiler, *flags, *extra, "-c", source, "-o", obj]
                run(command, out / (stem + "-build.log"))
                stack_path = obj.with_suffix(".su")
                frames = {}
                for line in stack_path.read_text().splitlines():
                    location, amount, kind = line.rsplit("\t", 2)
                    if kind not in ("static", "dynamic,bounded") or int(amount) > 8192:
                        raise RuntimeError("Unbounded or excessive stack frame: " + line)
                    frames[location.rsplit(":", 1)[-1]] = {"bytes": int(amount), "kind": kind}
                evidence.append({"name": stem, "command": [str(arg) for arg in command],
                                 "exit_code": 0, "object_sha256": digest(obj),
                                 "static_stack_frames": frames,
                                 "stack_usage_sha256": digest(stack_path)})
    after = {str(p.relative_to(ROOT)): digest(p) for p in tracked}
    if before != after:
        raise RuntimeError("Sources changed during boot adapter checks")
    receipt.write_text(json.dumps({"sources_sha256": before, "sources_unchanged": True,
                                  "runs": evidence,
                                  "scope": {"actual_boot_adapter_and_parser": True,
                                            "firmware_owner_boundary_modeled": True,
                                            "real_kernel_profiles_compiled": True,
                                            "guest_execution": False,
                                            "physical_hardware": False,
                                            "register_access": False,
                                            "windows98_acceptance": False}}, indent=2) + "\n")
    print("Receipt: " + str(receipt), flush=True)


if __name__ == "__main__":
    main()
