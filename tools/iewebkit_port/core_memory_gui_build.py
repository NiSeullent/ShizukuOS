#!/usr/bin/env python3
"""Build a GUI entry for the pinned memory probe; never execute a guest.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from iewebkit_build_win98 import audit


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(native_receipt: Path, baseline: Path, output: Path) -> dict:
    original = json.loads(native_receipt.read_text())
    if (original.get("schema") != "iewebkit-win9x-core-memory-native-v1"
            or original.get("static_gate_passed") is not True):
        raise ValueError("A successful original memory build receipt is required")
    bound = {"native_receipt": {"path": str(native_receipt.resolve()), "sha256": digest(native_receipt)}}
    for name in ("source", "header", "source_pin", "binary"):
        item = original[name]
        path = Path(item["path"])
        if not path.is_file() or digest(path) != item["sha256"]:
            raise ValueError("Original memory probe input changed: " + name)
        bound["original_" + name] = {"path": str(path.resolve()), "sha256": item["sha256"]}
    if Path(original["source"]["path"]).resolve() != HERE / "core_memory_native.c":
        raise ValueError("The GUI adapter must include the exact original source")
    if digest(baseline) != original["baseline"]["sha256"]:
        raise ValueError("The native export baseline changed")
    compiler = shutil.which("i686-w64-mingw32-gcc")
    if not compiler:
        raise ValueError("The existing x86 MinGW compiler is required")
    if output.exists() or output.is_symlink():
        raise ValueError("Preserve prior outputs; choose a new private directory")
    source = HERE / "core_memory_gui.c"
    bound["adapter"] = {"path": str(source), "sha256": digest(source)}
    output.mkdir(parents=True, mode=0o700)
    binary = output / "MEM9XG.EXE"
    command = [compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-Os", "-g0",
               "-march=pentium3", "-ffunction-sections", "-fdata-sections", "-static", "-static-libgcc",
               "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400",
               "-DNTDDI_VERSION=0x04000000", "-Wl,--gc-sections", "-Wl,--subsystem,windows:4.0",
               "-Wl,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0",
               str(source), "-o", str(binary)]
    result = subprocess.run(command, capture_output=True, timeout=120)
    log = output / "build.log"
    log.write_bytes(result.stdout + result.stderr)
    report = {"schema": "iewebkit-win9x-memory-gui-v1", "inputs": bound,
              "baseline": {"path": str(baseline.resolve()), "sha256": digest(baseline)},
              "compiler_argv": command, "compile_returncode": result.returncode,
              "build_log": {"path": str(log), "sha256": digest(log)},
              "scope": "GUI entry into source-identical shared Win9x memory probe",
              "command": "C:\\GOPLAB\\MEM9XG.EXE <nonce>",
              "outputs": ["C:\\GOPLAB\\MEM9X.LOG"],
              "provenance": [original["source"]["sha256"], original["header"]["sha256"],
                             None, None],
              "guest_execution": "NOT-VERIFIED", "full_engine_or_renderer": False}
    if result.returncode == 0:
        report["binary"] = audit(binary, json.loads(baseline.read_text()))
        report["binary"]["path"] = str(binary.resolve())
        report["provenance"][2] = report["binary"]["sha256"]
    for item in bound.values():
        if digest(Path(item["path"])) != item["sha256"]:
            raise ValueError("A frozen source changed during compilation")
    receipt = output / "MEM9XG.receipt.json"
    # The fourth provenance value is the external hash of this exact receipt.
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    if result.returncode or not report.get("binary", {}).get("static_gate_passed"):
        raise ValueError("GUI build/import gate failed; preserve " + str(receipt))
    return {"receipt": str(receipt.resolve()), "sha256": digest(receipt),
            "binary": str(binary.resolve()), "binary_sha256": digest(binary),
            "static_gate_passed": True, "guest_execution": "NOT-VERIFIED"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-receipt", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.native_receipt, args.baseline, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
