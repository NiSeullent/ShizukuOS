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
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COMMON = ROOT / "drivers/common"
PRODUCTION = [COMMON / "device.c", COMMON / "native_sessions.c"] + [
    HERE / name for name in ("acpi.c", "firmware.c", "ec.c", "hid.c", "hidi2c.c", "sensors.c", "pointer_adapter.c")
] + [ROOT / "drivers/ahci_native/ahci.c", ROOT / "drivers/xhci_native/xhci.c"]
TESTS = [COMMON / name for name in ("test_device.c", "test_ahci_session.c", "test_xhci_session.c")] + [
    HERE / name for name in ("test_acpi.c", "test_firmware.c", "test_ec.c", "test_hid.c", "test_sensors.c", "test_pointer_adapter.c")
]
FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         "-Wconversion", "-Wshadow", "-fno-builtin"]
TARGET = ["-ffreestanding", "-fno-builtin", "-fno-pie", "-fno-pic",
          "-fno-stack-protector", "-march=i486", "-mno-sse", "-mno-sse2",
          "-mno-mmx", "-msoft-float", "-fno-asynchronous-unwind-tables", "-fstack-usage"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, environment=None, timeout=60):
    result = subprocess.run([str(value) for value in command], cwd=ROOT,
                            capture_output=True, text=True, timeout=timeout, env=environment)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}:\n{result.stdout}{result.stderr}")
    return result.stdout


def fresh_object(path):
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        mode = None
    if mode is not None and not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
        raise RuntimeError("Unexpected object path type: " + str(path))
    # Remove only this exact generated output, including a stale symlink itself.
    # The compiler must produce the current source/profile object again.
    path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=HERE / "build")
    parser.add_argument("--timeout", type=int, default=60,
                        help="compile/link deadline seconds (60..180); execution stays bounded to 60s")
    args = parser.parse_args()
    if not 60 <= args.timeout <= 180:
        parser.error("--timeout must be between 60 and 180 seconds")
    build = args.build_dir.resolve()
    for name in ("gcc", "clang", "nm", "ld"):
        if not shutil.which(name):
            raise RuntimeError("Existing tool required: " + name)
    build.mkdir(parents=True, exist_ok=True)
    receipt = build / "test-result.json"
    manifest = sorted(set(PRODUCTION + TESTS + list(COMMON.glob("*.h")) + list(HERE.glob("*.h")) + [
        Path(__file__).resolve(), ROOT / "drivers/ahci_native/ahci.h",
        ROOT / "drivers/ahci_native/ahci_clock.h", ROOT / "drivers/ahci_native/test_ahci.c",
        ROOT / "drivers/xhci_native/xhci.h", ROOT / "drivers/xhci_native/xhci_internal.h",
        ROOT / "drivers/xhci_native/test_xhci.c", COMMON / "README.md", HERE / "README.md"
    ]))
    hashes = {str(path.relative_to(ROOT)): digest(path) for path in manifest}
    result = {"schema": 1, "module": "common controller sessions and laptop protocol adapters",
              "sources_sha256": hashes, "host": {}, "i486": {},
              "compile_timeout_seconds": args.timeout, "runtime_timeout_seconds": 60,
              "scope": {"actual_production_c": True, "existing_native_core_models": True,
                        "actual_win98_bound": False, "physical_hardware": False,
                        "aml_evaluator_supplied": False, "i2c_host_bound": False,
                        "system_suspend_implemented": False, "driver_binary_compatibility_claim": False}}
    for compiler, label, extra in (
        ("gcc", "gcc", []), ("clang", "clang", []),
        ("clang", "clang_sanitized", ["-O1", "-g", "-fsanitize=address,undefined",
                                    "-fno-omit-frame-pointer"])
    ):
        suites, objects, production = [], [], []
        for index, source in enumerate(PRODUCTION):
            obj = build / f"{label}-production-{index}.o"
            relative = str(source.relative_to(ROOT))
            if digest(source) != hashes[relative]:
                raise RuntimeError("Production source changed before compile: " + relative)
            fresh_object(obj)
            command = [compiler, *FLAGS, *extra, "-c", source, "-o", obj]
            run(command, timeout=args.timeout)
            if digest(source) != hashes[relative]:
                raise RuntimeError("Production source changed during compile: " + relative)
            objects.append(obj)
            production.append({"source": relative, "source_sha256": hashes[relative],
                               "object": str(obj), "object_sha256": digest(obj),
                               "command": [str(value) for value in command]})
        def check_objects():
            for obj, row in zip(objects, production):
                if digest(obj) != row["object_sha256"]:
                    raise RuntimeError("Production object changed: " + str(obj))
        for test in TESTS:
            executable = build / (label + "-" + test.stem)
            # GCC diagnoses a baseline test's compact legacy for-loop; the new
            # production objects are independently checked with no suppression.
            legacy = ["-Wno-misleading-indentation"] if "session" in test.stem else []
            check_objects()
            command = [compiler, *FLAGS, *legacy, *extra, *objects, test, "-o", executable]
            run(command, timeout=args.timeout)
            check_objects()
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
                           "compile_command": [str(value) for value in command],
                           "runtime_command": [str(executable)],
                           "output": output})
            print(f"{label}: {output.splitlines()[-1]}", flush=True)
        result["host"][label] = {"compiler": run([compiler, "--version"]).splitlines()[0],
                                   "production_objects": production,
                                   "suites": suites, "passed": True}
    for compiler, target in (("gcc", ["-m32"]), ("clang", ["--target=i386-unknown-none-elf"])):
        objects, frames = [], []
        for index, source in enumerate(PRODUCTION):
            obj = build / f"{compiler}-i486-{index}.o"
            fresh_object(obj)
            run([compiler, *FLAGS, *TARGET, *target, "-c", source, "-o", obj],
                timeout=args.timeout)
            objects.append(obj)
            for line in obj.with_suffix(".su").read_text().splitlines():
                name, size, kind = line.rsplit("\t", 2)
                if kind not in ("static", "dynamic,bounded"):
                    raise RuntimeError("Unbounded freestanding frame: " + line)
                frames.append({"function": name.replace(str(ROOT) + "/", ""),
                               "bytes": int(size), "kind": kind})
        linked = build / (compiler + "-i486-linked.o")
        fresh_object(linked)
        run(["ld", "-m", "elf_i386", "-r", *objects, "-o", linked], timeout=args.timeout)
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
    # Keep the last source-bound result until this complete invocation succeeds.
    # Publish the new receipt atomically; a failed compile never destroys it.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=build,
                                         prefix=".test-result-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(result, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(receipt)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print("receipt: " + str(receipt), flush=True)


if __name__ == "__main__":
    main()
