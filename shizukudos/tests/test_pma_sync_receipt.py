#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Behavioral runner guard regressions using isolated copies and compiler boundaries.

These exercise source attribution, not C compilation or guest behavior. The
compiler boundary mutates a copied input while the real receipt runner executes.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
FILES = ("shizukudos/kernel64/ntdrv_ke.c", "shizukudos/kernel64/ntddk.h",
         "shizukudos/kernel64/ntddk_abi.h",
         "shizukudos/kernel64/tests/test_ntdrv_spin_host.c", "shizukudos/kcommon/pma_sync.h",
         "shizukudos/tests/test_pma_sync.py")


def test_case(out, name, edit_during_extraction,
              mutated_header="shizukudos/kcommon/pma_sync.h"):
    case = out / name
    tree = case / "tree"
    for relative in FILES:
        target = tree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    path = tree / "shizukudos/tests/test_pma_sync.py"
    spec = importlib.util.spec_from_file_location("pma_guard_" + name, path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    source = tree / "shizukudos/kernel64/ntdrv_ke.c"
    original_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    header = tree / mutated_header
    compiler_calls = []
    original_body = runner.body
    edited = False

    def extracting(text, function):
        nonlocal edited
        value = original_body(text, function)
        if edit_during_extraction and not edited:
            edited = True
            source.write_bytes(source.read_bytes() + b"\n/* changed during extraction */\n")
        return value

    def compiler_boundary(command, **kwargs):
        nonlocal edited
        del kwargs
        compiler_calls.append(command)
        if not edit_during_extraction and not edited:
            edited = True
            header.write_bytes(header.read_bytes() + b"\n/* changed during compilation */\n")
        return subprocess.CompletedProcess(command, 0, "controlled compiler boundary\n", "")

    run_dir = case / "run"
    with mock.patch.object(runner, "body", extracting), \
         mock.patch.object(runner.subprocess, "run", compiler_boundary), \
         mock.patch.object(sys, "argv", [str(path), "--driver-only", "--out", str(run_dir)]), \
         contextlib.redirect_stdout(io.StringIO()):
        status = runner.main()
    result = json.loads((run_dir / "result.json").read_text())
    checks = {"exit_is_failure": status == 1, "receipt_is_failure": result["status"] == "FAIL",
              "source_mismatch_recorded": result["source_before_after_match"] is False}
    if edit_during_extraction:
        checks["digest_matches_extracted_bytes"] = result["source_sha256"] == original_sha
        checks["no_compiler_started_after_mismatch"] = not compiler_calls
    else:
        checks["mutated_header_pinned_in_driver_mode"] = mutated_header in result["sources_sha256"]
    print(name, checks)
    return {"case": name, "checks": checks, "pass": all(checks.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("choose a fresh directory to preserve prior evidence")
    out.mkdir(parents=True)
    results = [test_case(out, "driver-header-edit", False),
               test_case(out, "driver-abi-header-edit", False,
                         "shizukudos/kernel64/ntddk_abi.h"),
               test_case(out, "extraction-source-edit", True)]
    passed = all(row["pass"] for row in results)
    (out / "result.json").write_text(json.dumps({"status": "PASS" if passed else "FAIL", "results": results,
                                                "compiler_executed": False, "guest_executed": False}, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
