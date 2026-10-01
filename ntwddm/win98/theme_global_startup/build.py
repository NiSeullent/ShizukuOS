#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the fixed Win98 parent and verify owned-child error paths on the host.

This creates bounded private build outputs. It never installs or runs a guest.
Host/SAN checks and OEM imports do not establish native process completion.
"""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location(
    "win98_global_bootstrap_shared_gate", ROOT / "ntwddm/win98/theme_selector/build.py")
checks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checks)
SOURCES = (
    "ntwddm/win98/theme_global_startup/launcher.c",
    "ntwddm/win98/theme_global_startup/launcher_host_test.c",
    "ntwddm/win98/theme_global_startup/launcher_mock.h",
    "ntwddm/win98/theme_global_startup/build.py",
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
    parent = ROOT / "build/win98-global-theme-bootstrap"
    checks.require(parent.absolute() == parent.resolve(), "symlinked output parent")
    parent.mkdir(parents=True, exist_ok=True)
    directory = parent / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
                          + uuid.uuid4().hex[:8])
    directory.mkdir(mode=0o700)
    commands = []
    report = {"schema": 1, "status": "FAIL", "source_root": str(ROOT),
              "source_hashes": hashes, "run_directory": str(directory), "host_tests": [],
              "native_win98_execution": "not_tested", "installation_performed": False,
              "observer_external_exit": "NOT_OBSERVED", "bootstrap_external_exit": "NOT_OBSERVED",
              "two_cold_boots_verified": False}

    def run(argv, env=None):
        checks.guard(directory)
        completed = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                                   text=True, timeout=90)
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
        report["host_compiler_version"] = run(["clang", "--version"]).splitlines()[0]
        counts = []
        for kind, flags in (("host", []), ("sanitizer", ["-fsanitize=address,undefined",
                                                       "-fno-omit-frame-pointer"])):
            host = directory / kind
            run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
                + flags + [str(HERE / "launcher_host_test.c"), "-o", str(host)])
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
            result = run([str(host)], env=env)
            match = re.fullmatch(r"PASS: ([1-9][0-9]*) global bootstrap checks", result)
            checks.require(match is not None and int(match[1]) >= 30,
                           "actual completed bootstrap host assertions missing")
            counts.append(int(match[1]))
            report["host_tests"].append({"kind": kind, "result": result,
                                         "completed_checks": int(match[1])})
        checks.require(counts[0] == counts[1], "host and sanitizer completed different checks")
        executable = directory / "SHZGBOOT.EXE"
        run(["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
             "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
             "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
             "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,windows:4.10",
             "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
             "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
             "-Wl,--no-insert-timestamp", str(HERE / "launcher.c"),
             str(ROOT / "platform/freestanding/memory.c"), "-lkernel32", "-o", str(executable)])
        gate = checks.native_gate(executable, role="bootstrap")
        checks.require(all(digest(ROOT / name) == value for name, value in hashes.items()),
                       "source changed during bootstrap build")
        report.update(status="PASS", executable={"path": str(executable),
                      "sha256": digest(executable), "bytes": executable.stat().st_size,
                      "native_gate": gate})
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        receipt = checks.finish_report(report, directory)
    print(f"PASS: fixed bootstrap HOST/SAN and OEM PE32/import gates; receipt {receipt}")
    print("Native observer completion, bootstrap own exit and both cold boots remain unverified.")


if __name__ == "__main__":
    main()
