#!/usr/bin/env python3
"""Build only the owned native Winsock child observer; execute no probe."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time

import steam_win9x_socket_probe_build as base

PREFIX = base.ROOT / "tools/modern_apps/steam_win9x_socket_probe_observer"


def build(output: Path) -> tuple[dict, int]:
    output = output.absolute()
    if output.exists() or output.is_symlink() or output.resolve() != output:
        raise ValueError("choose a new private nonsymlink output directory")
    if not output.is_relative_to(base.ROOT / "build"):
        raise ValueError("observer output must remain below the checkout's build directory")
    free = shutil.disk_usage(base.ROOT).free
    if free < base.START_FREE:
        raise ValueError("unchanged tiny PE free-space admission failed")
    compiler_name = shutil.which("i686-w64-mingw32-gcc")
    if not compiler_name:
        raise ValueError("actual i686 MinGW GCC is required")
    compiler = Path(compiler_name).resolve()
    if base.captured([str(compiler), "-dumpmachine"]).strip() != "i686-w64-mingw32":
        raise ValueError("unexpected compiler target")
    baseline_bytes = base.BASELINE.read_bytes()
    if base.digest(baseline_bytes) != base.BASELINE_SHA:
        raise ValueError("preserved native-media exports changed")
    baseline = json.loads(baseline_bytes)
    inputs = [Path(str(PREFIX) + suffix) for suffix in
              (".c", "_build.py", "_README.md", "_fixture.py")]
    inputs.extend([Path(base.__file__), base.BASELINE, base.ROOT / "tools/app_preflight.py"])
    records = [base.file_record(path) for path in inputs]
    source_bytes = inputs[0].read_bytes()
    if base.digest(source_bytes) != records[0]["sha256"]:
        raise ValueError("observer source changed during capture")
    output.mkdir(parents=True, mode=0o700)
    source = output / inputs[0].name
    source.write_bytes(source_bytes)
    compiler_version = base.captured([str(compiler), "--version"]).splitlines()[0]
    dependency_text = base.captured([str(compiler), *base.COMMON, "-M", "-MT", "observer", str(source)])
    tokens = shlex.split(dependency_text.replace("\\\n", " ").split(":", 1)[1])
    headers = sorted({str(Path(token).resolve()) for token in tokens if Path(token) != source})
    if len(headers) > 256:
        raise ValueError("actual observer header inventory exceeds 256")
    header_records = [base.file_record(Path(path)) for path in headers]
    (output / "headers.json").write_text(json.dumps(header_records, indent=2) + "\n")
    command = [str(compiler), *base.COMMON, "-static", "-static-libgcc", str(source),
               "-o", str(output / "SPWAIT.EXE"), "-Wl,--subsystem,windows:4.0,--no-insert-timestamp,"
               "--major-os-version,4,--minor-os-version,0"]
    pre_compile_free = shutil.disk_usage(base.ROOT).free
    if pre_compile_free < base.START_FREE:
        raise ValueError("free-space admission changed before observer compiler launch")
    minimum_free = pre_compile_free
    started = time.monotonic()
    samples = 0
    maximum_output = base.output_size(output)
    aborted = None
    with (output / "build.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, preexec_fn=base.limits)
        while process.poll() is None:
            minimum_free = min(minimum_free, shutil.disk_usage(base.ROOT).free)
            maximum_output = max(maximum_output, base.output_size(output))
            samples += 1
            if minimum_free < base.FLOOR:
                aborted = "unchanged 20 GiB floor crossed"
            elif maximum_output > base.OUTPUT_CAP:
                aborted = "private 8 MiB output cap crossed"
            elif time.monotonic() - started > 45:
                aborted = "45-second observer compiler wall bound reached"
            if aborted:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                break
            time.sleep(0.05)
        code = process.wait()
    minimum_free = min(minimum_free, shutil.disk_usage(base.ROOT).free)
    maximum_output = max(maximum_output, base.output_size(output))
    unchanged = (records == [base.file_record(Path(row["path"])) for row in records] and
                 header_records == [base.file_record(Path(row["path"])) for row in header_records])
    ok = code == 0 and aborted is None and unchanged and minimum_free >= base.FLOOR and maximum_output <= base.OUTPUT_CAP
    receipt = {"schema": "steam.win9x-socket-owned-observer-build.v1", "source_inputs": records,
               "inputs_unchanged_after_build": unchanged,
               "compiler": {**base.file_record(compiler), "version": compiler_version, "target": "i686-w64-mingw32"},
               "actual_header_inventory": base.file_record(output / "headers.json"), "actual_header_count": len(headers),
               "command": command, "compiler_exit": code, "abort_reason": aborted,
               "build_log": base.file_record(output / "build.log"),
               "elapsed_seconds": round(time.monotonic() - started, 4),
               "resource_guard": {"floor_bytes": base.FLOOR, "start_requirement_bytes": base.START_FREE,
                                  "initial_free_bytes": free, "pre_compile_free_bytes": pre_compile_free,
                                  "minimum_free_bytes": minimum_free, "samples": samples,
                                  "maximum_output_bytes_observed": maximum_output, "output_limit_bytes": base.OUTPUT_CAP,
                                  "child_cpu_limit_seconds": 45, "child_file_limit_bytes": 2 * 1024**2, "child_core_limit_bytes": 0},
               "native_observer_executed": False, "native_probe_execution_verified": False,
               "actual_process_exit_after_crt_verified": False, "steam_application_executed": False,
               "steam_application_passed": False}
    if ok:
        sys.path.insert(0, str(base.ROOT / "tools"))
        from app_preflight import analyze
        binary_path = output / "SPWAIT.EXE"
        audit = analyze(binary_path)
        data = binary_path.read_bytes()
        optional = struct.unpack_from("<I", data, 0x3C)[0] + 24
        os_version = list(struct.unpack_from("<HH", data, optional + 40))
        absent = [row for row in audit["imports"] if row["symbol"] not in baseline["dlls"].get(row["dll"], [])]
        imports = {row["symbol"] for row in audit["imports"] if row["dll"] == "KERNEL32.DLL"}
        required = {"CreateProcessA", "WaitForSingleObject", "GetExitCodeProcess", "TerminateProcess", "CloseHandle",
                    "CreateFileA", "WriteFile", "FlushFileBuffers", "GetVersionExA"}
        receipt["pe_audit"] = {"binary": base.file_record(binary_path), "pe": audit["pe"], "os_version": os_version,
                               "imports": audit["imports"], "import_inventory_complete": audit["import_inventory_complete"],
                               "absent_from_native_media_exports": absent, "required_native_observer_imports_present": required <= imports}
        ok = (audit["pe"]["machine"] == 0x14C and audit["pe"]["format"] == "PE32" and audit["pe"]["subsystem"] == 2 and
              audit["pe"]["subsystem_version"] == [4, 0] and os_version == [4, 0] and
              audit["import_inventory_complete"] and required <= imports and not absent)
    receipt["source_and_static_gate_passed"] = ok
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if base.output_size(output) > base.OUTPUT_CAP:
        raise ValueError("receipt-inclusive observer output exceeds its cap")
    return receipt, 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result, code = build(args.output)
        print(json.dumps({"output": str(args.output.absolute()), "source_and_static_gate_passed": result["source_and_static_gate_passed"],
                          "native_observer_executed": False, "steam_application_passed": False}))
        return code
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
