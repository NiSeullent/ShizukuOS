#!/usr/bin/env python3
"""Verify actual driver C and existing native core models; no hardware/VM I/O.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COMMON = ROOT / "drivers/common"
PRODUCTION = [COMMON / "device.c", COMMON / "native_sessions.c"] + [
    HERE / name for name in ("acpi.c", "ec.c", "hid.c", "hidi2c.c", "sensors.c")
] + [ROOT / "drivers/ahci_native/ahci.c", ROOT / "drivers/xhci_native/xhci.c"]
TESTS = [COMMON / name for name in ("test_device.c", "test_ahci_session.c", "test_xhci_session.c")] + [
    HERE / name for name in ("test_acpi.c", "test_ec.c", "test_hid.c", "test_sensors.c")
]
FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         "-Wconversion", "-Wshadow", "-fno-builtin"]
TARGET = ["-ffreestanding", "-fno-builtin", "-fno-pie", "-fno-pic",
          "-fno-stack-protector", "-march=i486", "-mno-sse", "-mno-sse2",
          "-mno-mmx", "-msoft-float", "-fno-asynchronous-unwind-tables", "-fstack-usage"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, environment=None):
    result = subprocess.run([str(value) for value in command], cwd=ROOT,
                            capture_output=True, text=True, timeout=60, env=environment)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}:\n{result.stdout}{result.stderr}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=HERE / "build")
    args = parser.parse_args()
    build = args.build_dir.resolve()
    for name in ("gcc", "clang", "nm", "ld"):
        if not shutil.which(name):
            raise RuntimeError("Existing tool required: " + name)
    build.mkdir(parents=True, exist_ok=True)
    receipt = build / "test-result.json"
    receipt.unlink(missing_ok=True)
    manifest = sorted(set(PRODUCTION + TESTS + list(COMMON.glob("*.h")) + list(HERE.glob("*.h")) + [
        Path(__file__).resolve(), ROOT / "drivers/ahci_native/ahci.h",
        ROOT / "drivers/ahci_native/ahci_clock.h", ROOT / "drivers/ahci_native/test_ahci.c",
        ROOT / "drivers/xhci_native/xhci.h", ROOT / "drivers/xhci_native/xhci_internal.h",
        ROOT / "drivers/xhci_native/test_xhci.c", COMMON / "README.md", HERE / "README.md"
    ]))
    hashes = {str(path.relative_to(ROOT)): digest(path) for path in manifest}
    result = {"schema": 1, "module": "common controller sessions and laptop protocol adapters",
              "sources_sha256": hashes, "host": {}, "i486": {},
              "scope": {"actual_production_c": True, "existing_native_core_models": True,
                        "actual_win98_bound": False, "physical_hardware": False,
                        "aml_evaluator_supplied": False, "i2c_host_bound": False,
                        "system_suspend_implemented": False, "driver_binary_compatibility_claim": False}}
    for compiler, label, extra in (
        ("gcc", "gcc", []), ("clang", "clang", []),
        ("clang", "clang_sanitized", ["-O1", "-g", "-fsanitize=address,undefined",
                                    "-fno-omit-frame-pointer"])
    ):
        suites = []
        for test in TESTS:
            executable = build / (label + "-" + test.stem)
            # GCC diagnoses a baseline test's compact legacy for-loop; the new
            # production objects are independently checked with no suppression.
            legacy = ["-Wno-misleading-indentation"] if "session" in test.stem else []
            run([compiler, *FLAGS, *legacy, *extra, *PRODUCTION, test, "-o", executable])
            environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
                               UBSAN_OPTIONS="halt_on_error=1")
            output = run([executable], environment)
            if "PASS" not in output:
                raise RuntimeError("Missing execution result: " + test.name)
            log = build / (label + "-" + test.stem + ".log")
            log.write_text(output)
            matches = re.findall(r"(\d+) (?:cumulative )?assertions PASS", output)
            suites.append({"test": str(test.relative_to(ROOT)), "passed": True,
                           "assertions": int(matches[-1]) if matches else None,
                           "log_sha256": digest(log), "binary_sha256": digest(executable),
                           "output": output})
            print(f"{label}: {output.splitlines()[-1]}", flush=True)
        result["host"][label] = {"compiler": run([compiler, "--version"]).splitlines()[0],
                                   "suites": suites, "passed": True}
    for compiler, target in (("gcc", ["-m32"]), ("clang", ["--target=i386-unknown-none-elf"])):
        objects, frames = [], []
        for index, source in enumerate(PRODUCTION):
            obj = build / f"{compiler}-i486-{index}.o"
            run([compiler, *FLAGS, *TARGET, *target, "-c", source, "-o", obj])
            objects.append(obj)
            for line in obj.with_suffix(".su").read_text().splitlines():
                name, size, kind = line.rsplit("\t", 2)
                if kind not in ("static", "dynamic,bounded"):
                    raise RuntimeError("Unbounded freestanding frame: " + line)
                frames.append({"function": name.replace(str(ROOT) + "/", ""),
                               "bytes": int(size), "kind": kind})
        linked = build / (compiler + "-i486-linked.o")
        run(["ld", "-m", "elf_i386", "-r", *objects, "-o", linked])
        undefined = run(["nm", "-u", linked]).strip()
        if undefined:
            raise RuntimeError("Unexpected runtime dependency: " + undefined)
        if not frames or max(frame["bytes"] for frame in frames) > 8192:
            raise RuntimeError("Driver frame exceeds 8KiB; worker stack must be reviewed")
        result["i486"][compiler] = {"flags": FLAGS + TARGET + target,
                                     "undefined_symbols": [], "passed": True,
                                     "linked_sha256": digest(linked),
                                     "size_bytes": linked.stat().st_size,
                                     "all_internal_frames_sum_bytes": sum(f["bytes"] for f in frames),
                                     "frames": frames}
        print(f"{compiler}: freestanding i486 linked, no runtime imports", flush=True)
    if hashes != {str(path.relative_to(ROOT)): digest(path) for path in manifest}:
        raise RuntimeError("Driver source changed during verification")
    result["passed"] = True
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print("receipt: " + str(receipt), flush=True)


if __name__ == "__main__":
    main()
