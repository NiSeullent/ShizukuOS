#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the independent native observer; do not run it or modify a guest."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GATE = ROOT / "ntwddm/win98/theme_selector/build.py"
SPEC = importlib.util.spec_from_file_location("win98_selector_shared_gate", GATE)
checks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checks)
SOURCES = (
    "ntwddm/win98/theme_global_probe/observer.c",
    "ntwddm/win98/theme_global_probe/build.py",
    "ntwddm/win98/theme_selector/build.py",
    "tests/test_win98_theme_selector_build.py",
    "platform/freestanding/memory.c",
    "platform/freestanding/memory.h",
    "benchmarks/win98se-ko-oem-native-exports-v1.json",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    checks.guard(admission=True)
    hashes = {name: digest(ROOT / name) for name in SOURCES}
    parent = ROOT / "build/win98-global-theme-observer"
    checks.require(parent.absolute() == parent.resolve(), "symlinked output parent")
    parent.mkdir(parents=True, exist_ok=True)
    directory = parent / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
                          + uuid.uuid4().hex[:8])
    directory.mkdir(mode=0o700)
    commands = []
    report = {"schema": 1, "status": "FAIL", "source_root": str(ROOT),
              "source_hashes": hashes, "run_directory": str(directory),
              "native_win98_execution": "not_tested", "installation_performed": False,
              "two_cold_boots_verified": False, "automatic_restore_exit": "NOT_OBSERVED"}

    def run(argv):
        checks.guard(directory)
        completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=90)
        commands.append({"argv": argv, "exit_code": completed.returncode,
                         "stdout": completed.stdout[:16384], "stderr": completed.stderr[:16384]})
        (directory / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        checks.guard(directory)
        checks.require(completed.returncode == 0, "command failed; see commands.json")
        checks.require(len(completed.stdout) <= 16384 and len(completed.stderr) <= 16384,
                       "diagnostics exceeded bound")
        return completed.stdout.strip()

    try:
        run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_win98_theme_selector_build.py", "-v"])
        report["compiler_version"] = run(["i686-w64-mingw32-gcc", "--version"]).splitlines()[0]
        executable = directory / "SHZOBS.EXE"
        run(["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
             "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
             "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
             "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,windows:4.10",
             "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
             "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
             "-Wl,--no-insert-timestamp", str(HERE / "observer.c"),
             str(ROOT / "platform/freestanding/memory.c"), "-lkernel32", "-luser32",
             "-lgdi32", "-ladvapi32", "-o", str(executable)])
        gate = checks.native_gate(executable, role="observer")
        checks.require(all(digest(ROOT / name) == value for name, value in hashes.items()),
                       "source changed during observer build")
        report.update(status="PASS", executable={"path": str(executable),
                      "sha256": digest(executable), "bytes": executable.stat().st_size,
                      "native_gate": gate})
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        receipt = checks.finish_report(report, directory)
    print(f"PASS: independent observer OEM PE32/import gates; receipt {receipt}")
    print("Observer runtime, independent observer exit and both cold boots remain unverified.")


if __name__ == "__main__":
    main()
