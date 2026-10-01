#!/usr/bin/env python3
"""Stage the exact real WTF/JSC filesystem port without changing engine inputs.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Only two pinned source files and one new helper header are copied. Optional
host algorithm controls and the GUI API probe are small private builds; no
guest, network, global package installation or application renderer starts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FLOOR = 20 * 1024 ** 3
RESERVE = 8 * 1024 ** 2


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def regular(path):
    path = Path(os.path.abspath(path))
    if path.resolve(strict=True) != path or not path.is_file():
        raise ValueError("Require the unchanged private regular source: " + str(path))
    return path


def space(path):
    if shutil.disk_usage(path).free < FLOOR + RESERVE:
        raise ValueError("Preserve 20 GiB free space plus this 8 MiB bounded stage")


def read_pin():
    path = regular(HERE / "core_filesystem_pin.json")
    pin = json.loads(path.read_text())
    if pin["upstream_commit"] != "5220e80b97a253c60ed899361654142ab5021998":
        raise ValueError("Filesystem port belongs to a different genuine source")
    if sha(regular(HERE / pin["patch"])) != pin["patch_sha256"]:
        raise ValueError("Filesystem source patch changed after its pin")
    for row in pin["new_files"]:
        if sha(regular(HERE / row["source"])) != row["sha256"]:
            raise ValueError("Lossless path helper changed after its pin")
    return pin


def apply_to_stage(source, stage):
    pin = read_pin()
    originals = {}
    for row in pin["files"]:
        path = regular(source / row["path"])
        originals[str(path)] = sha(path)
        if originals[str(path)] != row["before_sha256"]:
            raise ValueError("Preserve source outside this port's exact before state: " + str(path))
    space(stage.parent)
    stage.mkdir(mode=0o700)
    for row in pin["files"]:
        path = stage / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / row["path"], path)
    command = ["patch", "--batch", "--fuzz=0", "-p1", "-d", str(stage), "-i", str(HERE / pin["patch"])]
    result = subprocess.run(command, capture_output=True, timeout=15)
    if result.returncode:
        raise ValueError("Exact staged source patch failed: " + result.stderr.decode(errors="replace"))
    for row in pin["files"]:
        if sha(stage / row["path"]) != row["after_sha256"]:
            raise ValueError("Staged genuine source differs from the exact after pin")
    for row in pin["new_files"]:
        path = stage / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(HERE / row["source"], path)
        if sha(path) != row["sha256"]:
            raise ValueError("Staged helper differs from the exact header pin")
    for path, expected in originals.items():
        if sha(path) != expected:
            raise ValueError("Original engine source changed during private staging")
    return pin, originals, command


def small_command(command, directory, log_name):
    space(directory)
    result = subprocess.run(command, capture_output=True, timeout=60)
    if len(result.stdout) + len(result.stderr) > 1024 ** 2:
        raise ValueError("Small compiler exceeded its diagnostic budget")
    log = directory / log_name
    log.write_bytes(result.stdout + result.stderr)
    record = {"argv": command, "returncode": result.returncode, "log": str(log), "log_sha256": sha(log)}
    if result.returncode:
        raise ValueError("Bounded command failed; inspect " + str(log))
    space(directory)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--host-controls", action="store_true")
    parser.add_argument("--native-probe", action="store_true")
    args = parser.parse_args()
    work = args.work.resolve(strict=True)
    if work != Path("/root/Win98-Modern-boot/build/iewebkit-core-83bd"):
        parser.error("Use the owned private engine build")
    stage = Path(os.path.abspath(args.stage))
    if stage.exists() or stage.parent.resolve(strict=True) != work:
        parser.error("Use a new direct child of the private work directory")
    source = work / "webkitgtk-2.54.0"
    pin, originals, command = apply_to_stage(source, stage)
    report = {"schema": "iewebkit-staged-genuine-filesystem-port-v1", "stage": str(stage),
        "pin_sha256": sha(HERE / "core_filesystem_pin.json"), "patch_argv": command,
        "source_sha256": sha(HERE / "core_filesystem_native.c"),
        "header_sha256": sha(HERE / "src/core_FileSystemWin9x.h"),
        "original_source_inputs": originals, "original_engine_source_unchanged": True,
        "engine_source_applied": False, "engine_translation_unit_compiled": False,
        "native_execution_verified": False, "engine_executed": False, "document_rendering_verified": False,
        "limitations": pin["limitations"], "steps": []}
    if args.host_controls:
        executable = stage / "host-path-controls"
        compiler = shutil.which("cc")
        if not compiler:
            raise ValueError("Existing host C compiler is required; no package is installed")
        argv = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-g0", "-O1",
            "-I" + str(HERE / "tests/filesystem_api_model"),
            str(HERE / "tests/core_filesystem_controls.c"), "-o", str(executable)]
        report["steps"].append(small_command(argv, stage, "host-compile.log"))
        report["steps"].append(small_command([str(executable)], stage, "host-controls.log"))
        report["host_controls"] = {"result": "PASS", "cases": 9,
            "model": "Synthetic ASCII/DBCS/best-fit/default-substitution ACP model; exact production header",
            "windows_api_verified": False}
    if args.native_probe:
        binary = stage / "FSPATH.EXE"
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if not compiler:
            raise ValueError("Existing genuine MinGW compiler is required")
        argv = [compiler, "-std=c11", "-Os", "-g0", "-Wall", "-Wextra",
            "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400",
            "-mwindows", "-static", "-static-libgcc", "-Wl,--gc-sections,--no-insert-timestamp",
            "-Wl,--major-os-version,4,--minor-os-version,0,--major-subsystem-version,4,--minor-subsystem-version,0",
            str(HERE / "core_filesystem_native.c"), "-o", str(binary)]
        report["steps"].append(small_command(argv, stage, "native-compile.log"))
        report["native_binary"] = {"path": str(binary), "sha256": sha(binary), "bytes": binary.stat().st_size,
            "compiler": compiler, "compiler_sha256": sha(compiler), "native_execution_verified": False}
    for path, expected in originals.items():
        if sha(path) != expected:
            raise ValueError("Current engine inputs changed during this bounded stage")
    receipt = stage / "stage-receipt.json"
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"receipt": str(receipt), "sha256": sha(receipt), "host_controls": report.get("host_controls"),
        "native_binary": report.get("native_binary"), "original_source_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()
