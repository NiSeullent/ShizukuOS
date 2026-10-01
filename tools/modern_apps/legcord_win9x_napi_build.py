#!/usr/bin/env python3
"""Bounded static build of the actual Win98 Node-API adapter and native probe.

SPDX-License-Identifier: GPL-2.0-only. Never executes a PE or app/runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
from iewebkit_build_win98 import audit

ORIGINALS = {
    "legcord_win9x_entry.cjs": "921ab2a9872d5cf627ab4845089cf49c5411d9abcd805f037f97cab72f9937d8",
    "legcord_win9x_source_lease.c": "e0d78158cb915e8786c70c8d43f330d9e052da7835ae57c47c315b8c0005de04",
    "legcord_win9x_source_lease.h": "cf9fca509a80c2f38aaef5d013308edefbd624e65bca1404406556b43ed3fdb1",
}
FLOOR = 20 * 1024 ** 3
BUDGET = 8 * 1024 ** 2


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(data)
    return value.hexdigest()


def pin(path):
    path = path.resolve()
    before = path.stat()
    result = {"path": str(path), "bytes": before.st_size, "sha256": digest(path)}
    after = path.stat()
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    if identity(before) != identity(after):
        raise ValueError("Actual input changed while being pinned")
    return result


def size(directory):
    return directory.stat().st_blocks * 512 + sum(path.lstat().st_blocks * 512
                                                 for path in directory.rglob("*"))


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 ** 2, 2 * 1024 ** 2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headers", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "build"):
        raise ValueError("Require a new private build output under the owned build tree")
    if shutil.disk_usage(output.parent).free < FLOOR + 256 * 1024 ** 2 + BUDGET:
        raise ValueError("Preserve20GiB floor plus256MiB headroom and8MiB build allowance")
    started = time.monotonic()
    cpu_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    headers = args.headers.resolve()
    extraction = headers / "extraction.json"
    frozen = json.loads(extraction.read_text())
    if frozen["node_archive"]["sha256"] != "694c4868c187d4a435a86d617346e2c81676c30a9bbf6fc65cce8eb50038dcaf" or \
            frozen["electron_archive"]["sha256"] != "bef9da935120ac15bf09277b29ef5f95134552f5b5d3b4c7c733791fb234ecb6":
        raise ValueError("Require the complete officially checksum-bound exact release headers")
    for row in frozen["files"]:
        if digest(Path(row["path"])) != row["sha256"]:
            raise ValueError("Pinned official public header evidence changed")
    for name, expected in ORIGINALS.items():
        if digest(HERE / name) != expected:
            raise ValueError("Preserve the already pinned original source contract")
    source_files = sorted(HERE.glob("legcord_win9x_napi*"))
    if sum(path.stat().st_size for path in source_files) + sum(row["bytes"] for row in frozen["files"]) > 256 * 1024:
        raise ValueError("Adapter sources/docs/header evidence exceed256KiB")
    compiler = Path(shutil.which("i686-w64-mingw32-gcc"))
    flags = [str(compiler), "-std=gnu11", "-Os", "-g0", "-ffunction-sections", "-fdata-sections",
             "-fno-ident", "-Wall", "-Wextra", "-Werror", "-Wno-cast-function-type",
             "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400", "-I" + str(HERE)]
    linker = "-Wl,--gc-sections,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0,--major-subsystem-version,4,--minor-subsystem-version,0"
    addon = HERE / "legcord_win9x_napi.c"
    helper = HERE / "legcord_win9x_source_lease.c"
    native_probe = HERE / "legcord_win9x_napi_native_probe.c"
    probe_defines = [
        '-DLEG_NAPI_PROBE_SHA="' + digest(native_probe) + '"',
        '-DLEG_LEASE_SOURCE_SHA="' + ORIGINALS[helper.name] + '"',
        '-DLEG_LEASE_HEADER_SHA="' + ORIGINALS["legcord_win9x_source_lease.h"] + '"',
    ]
    tool_paths = [compiler]
    for name in ("cc1", "as", "ld"):
        result = subprocess.run([str(compiler), "-print-prog-name=" + name], check=True,
                                capture_output=True, text=True, timeout=5, preexec_fn=limits).stdout.strip()
        selected = Path(result if Path(result).is_absolute() else shutil.which(result))
        tool_paths.append(selected)
    initial = {str(path.resolve()): pin(path) for path in [*source_files, *[HERE / name for name in ORIGINALS],
               extraction, args.baseline, ROOT / "tools/iewebkit_build_win98.py", *tool_paths,
               *[Path(row["path"]) for row in frozen["files"]]]}
    # Get genuine target compiler dependencies; never invent runtime headers.
    for include, source in ((headers / "electron", addon), (headers / "node", addon), (None, helper), (None, native_probe)):
        argv = flags + (["-I" + str(include)] if include else []) + \
            (probe_defines if source == native_probe else []) + ["-M", "-MT", "native-input", str(source)]
        dependency = subprocess.run(argv, check=True, capture_output=True, text=True,
                                    timeout=min(10, max(1, 45 - (time.monotonic() - started))),
                                    preexec_fn=limits).stdout
        for name in shlex.split(dependency.replace("\\\n", " ").split(":", 1)[1]):
            path = Path(name)
            initial[str(path.resolve())] = pin(path)
    output.mkdir(mode=0o700)
    (output / "tmp").mkdir()
    (output / "sources").mkdir()
    for path in [*source_files, *[HERE / name for name in ORIGINALS]]:
        (output / "sources" / path.name).write_bytes(path.read_bytes())
    commands = [
        ("node-signature-control", flags + ["-I" + str(headers / "node"), "-c", str(addon), "-o", str(output / "node-signature-control.o")]),
        ("electron-addon", flags + ["-I" + str(headers / "electron"), "-shared", "-static-libgcc", str(addon), str(helper), linker, "-o", str(output / "LEGLEASE.node")]),
        ("native-lease-probe", flags + probe_defines + [
            "-mwindows", "-static-libgcc", str(native_probe), str(helper), linker, "-o", str(output / "LNLEASE.EXE")]),
    ]
    report = {"schema": "legcord-win9x-real-node-api-adapter-static-build-v1",
              "header_extraction": pin(extraction), "input_pins": list(initial.values()),
              "node_api_version": 8, "symbol_registration_version": 1,
              "dynamic_api_owner": "Actual main executable, every required symbol checked",
              "ordinary_import_baseline": pin(args.baseline), "commands": [], "artifacts": {},
              "output_budget_bytes": BUDGET, "child_file_limit_bytes": 2 * 1024 ** 2,
              "native_electron_executed": False, "native_component_pass": False,
              "whole_legcord_or_discord_pass": False, "static_gate_passed": False}
    receipt = output / "build.json"
    def save():
        receipt.write_text(json.dumps(report, indent=2) + "\n")
    environment = dict(os.environ, TMPDIR=str(output / "tmp"))
    try:
        for label, argv in commands:
            if shutil.disk_usage(output).free < FLOOR or size(output) > BUDGET:
                raise ValueError("Static build resource floor/budget changed")
            log = output / (label + ".log")
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       env=environment, cwd=output, start_new_session=True, preexec_fn=limits)
            try:
                data, _ = process.communicate(timeout=min(15, max(1, 45 - (time.monotonic() - started))))
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL); process.wait(); raise
            log.write_bytes(data)
            report["commands"].append({"phase": label, "argv": argv, "returncode": process.returncode, "log": pin(log)})
            save()
            if process.returncode:
                raise RuntimeError("Actual static compilation failed: " + str(log))
        baseline = json.loads(args.baseline.read_text())
        for name in ("LEGLEASE.node", "LNLEASE.EXE"):
            path = output / name
            gate = audit(path, baseline)
            gate["path"] = str(path)
            report["artifacts"][name] = gate
            if not gate["static_gate_passed"]:
                raise ValueError("Actual PE/import gate failed: " + name)
        exports = subprocess.run(["i686-w64-mingw32-objdump", "-p", str(output / "LEGLEASE.node")],
                                 check=True, capture_output=True, text=True, timeout=5).stdout
        if "napi_register_module_v1" not in exports or "node_api_module_get_api_version_v1" not in exports:
            raise ValueError("Actual native Node-API registration exports missing")
        for row in initial.values():
            if pin(Path(row["path"])) != row:
                raise ValueError("Exact source/header/compiler/baseline changed across compilation")
        cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
        report["children_cpu_seconds"] = cpu.ru_utime + cpu.ru_stime - cpu_start.ru_utime - cpu_start.ru_stime
        if report["children_cpu_seconds"] > 45 or size(output) > BUDGET or shutil.disk_usage(output).free < FLOOR:
            raise ValueError("Static component build exceeded its bounded resources")
        report["registration_export_gate"] = "PASS"
        report["all_inputs_unchanged"] = True
        report["static_gate_passed"] = True
        report["allocated_output_bytes"] = size(output)
        report["final_host_free_bytes"] = shutil.disk_usage(output).free
        save()
    except BaseException as error:
        report["failure"] = str(error) or type(error).__name__
        save(); raise
    print(json.dumps({"receipt": str(receipt), "sha256": digest(receipt),
                      "static_gate_passed": True, "outputs": {name: pin(output / name)
                          for name in ("LEGLEASE.node", "LNLEASE.EXE")},
                      "allocated_bytes": size(output), "children_cpu_seconds": report["children_cpu_seconds"]}))


if __name__ == "__main__":
    main()
