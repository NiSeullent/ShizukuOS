#!/usr/bin/env python3
"""Build a bounded real Winsock prerequisite probe; never execute it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PREFIX = ROOT / "tools/modern_apps/steam_win9x_socket_probe"
BASELINE = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
BASELINE_SHA = "3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d"
FLOOR = 20 * 1024**3
OUTPUT_CAP = 8 * 1024**2
START_FREE = FLOOR + 256 * 1024**2 + OUTPUT_CAP
COMMON = ["-pipe", "-std=c99", "-Wall", "-Wextra", "-Werror", "-Os", "-g0",
          "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path), "size_bytes": len(data), "sha256": digest(data)}


def limits() -> None:
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def captured(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=45,
                            preexec_fn=limits, check=True)
    if len(result.stdout) + len(result.stderr) > 1024**2:
        raise ValueError("compiler metadata exceeds the 1 MiB limit")
    return result.stdout


def output_size(output: Path) -> int:
    return sum(path.stat().st_size for path in output.rglob("*") if path.is_file())


def build(output: Path, syntax_only: bool) -> tuple[dict, int]:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("choose a new private output directory")
    if not output.is_relative_to(ROOT / "build"):
        raise ValueError("output must be below this checkout's build directory")
    if output.resolve() != output:
        raise ValueError("output must not traverse symlinks or dot components")
    initial_free = shutil.disk_usage(ROOT).free
    if not syntax_only and initial_free < START_FREE:
        raise ValueError(f"tiny PE build requires {START_FREE} free bytes; observed {initial_free}")
    compiler_name = shutil.which("i686-w64-mingw32-gcc")
    if not compiler_name:
        raise ValueError("the actual i686 MinGW compiler is required")
    compiler = Path(compiler_name).resolve()
    if captured([str(compiler), "-dumpmachine"]).strip() != "i686-w64-mingw32":
        raise ValueError("unexpected compiler target")
    baseline_bytes = BASELINE.read_bytes()
    if digest(baseline_bytes) != BASELINE_SHA:
        raise ValueError("native-media export baseline changed")
    baseline = json.loads(baseline_bytes)
    if baseline.get("schema") != "w98mod.export-manifest.v1":
        raise ValueError("unexpected media baseline schema")
    inputs = [Path(str(PREFIX) + ".c"), Path(__file__), Path(str(PREFIX) + "_README.md"),
              Path(str(PREFIX) + "_verify.py"), Path(str(PREFIX) + "_test.py"),
              BASELINE, ROOT / "tools/app_preflight.py"]
    records = [file_record(path) for path in inputs]
    source_bytes = inputs[0].read_bytes()
    if digest(source_bytes) != records[0]["sha256"]:
        raise ValueError("source changed during capture")
    output.mkdir(parents=True, mode=0o700)
    source = output / "steam_win9x_socket_probe.c"
    source.write_bytes(source_bytes)
    compiler_version = captured([str(compiler), "--version"]).splitlines()[0]
    dependencies = captured([str(compiler), *COMMON, "-M", "-MT", "probe", str(source)])
    tokens = shlex.split(dependencies.replace("\\\n", " ").split(":", 1)[1])
    headers = sorted({str(Path(token).resolve()) for token in tokens if Path(token) != source})
    if len(headers) > 256:
        raise ValueError("header inventory exceeds its bound")
    header_records = [file_record(Path(path)) for path in headers]
    (output / "headers.json").write_text(json.dumps(header_records, indent=2) + "\n")
    command = [str(compiler), *COMMON]
    if syntax_only:
        command.extend(["-fsyntax-only", str(source)])
    else:
        command.extend(["-static", "-static-libgcc", str(source), "-o", str(output / "SPROB.EXE"),
                        "-lwsock32", "-Wl,--subsystem,windows:4.0,--no-insert-timestamp,"
                        "--major-os-version,4,--minor-os-version,0"])
    pre_compile_free = shutil.disk_usage(ROOT).free
    if not syntax_only and pre_compile_free < START_FREE:
        raise ValueError(f"free-space admission changed before compiler launch: {pre_compile_free}")
    started = time.monotonic()
    minimum_free = shutil.disk_usage(ROOT).free
    abort_reason = None
    max_output = output_size(output)
    samples = 0
    # CPU, file and core limits apply to the actual compiler and every child.
    with (output / "build.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   preexec_fn=limits)
        while process.poll() is None:
            free = shutil.disk_usage(ROOT).free
            minimum_free = min(minimum_free, free)
            max_output = max(max_output, output_size(output))
            samples += 1
            if not syntax_only and free < FLOOR:
                abort_reason = "unchanged 20 GiB free-space floor crossed"
            elif max_output > OUTPUT_CAP:
                abort_reason = "private 8 MiB output cap crossed"
            elif time.monotonic() - started > 45:
                abort_reason = "45-second wall-clock bound reached"
            if abort_reason:
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
    minimum_free = min(minimum_free, shutil.disk_usage(ROOT).free)
    max_output = max(max_output, output_size(output))
    if not syntax_only and minimum_free < FLOOR and abort_reason is None:
        abort_reason = "unchanged 20 GiB floor crossed at final sample"
    if max_output > OUTPUT_CAP and abort_reason is None:
        abort_reason = "private 8 MiB cap crossed at final sample"
    after = [file_record(Path(row["path"])) for row in records]
    headers_after = [file_record(Path(row["path"])) for row in header_records]
    inputs_unchanged = after == records and headers_after == header_records
    receipt = {
        "schema": "steam.win9x-socket-prerequisite-build.v1",
        "mode": "actual-mingw-syntax-only" if syntax_only else "actual-mingw-pe-build",
        "source_inputs": records, "inputs_unchanged_after_build": inputs_unchanged,
        "compiler": {**file_record(compiler), "version": compiler_version,
                     "target": "i686-w64-mingw32"},
        "actual_header_inventory": file_record(output / "headers.json"),
        "actual_header_count": len(header_records), "command": command,
        "compiler_exit": code, "abort_reason": abort_reason,
        "elapsed_seconds": round(time.monotonic() - started, 4),
        "resource_guard": {"floor_bytes": FLOOR, "start_requirement_bytes": START_FREE,
                           "initial_free_bytes": initial_free, "minimum_free_bytes": minimum_free,
                           "pre_compile_free_bytes": pre_compile_free,
                           "maximum_output_bytes_observed": max_output,
                           "output_limit_bytes": OUTPUT_CAP, "samples": samples,
                           "child_cpu_limit_seconds": 45, "child_file_limit_bytes": 2 * 1024**2,
                           "child_core_limit_bytes": 0,
                           "pe_build_floor_gate_applied": not syntax_only},
        "build_log": file_record(output / "build.log"),
        "native_probe_executed": False, "actual_socket_semantics_verified": False,
        "native_dependency_load_verified": False, "steam_application_executed": False,
        "steam_application_passed": False,
    }
    ok = code == 0 and abort_reason is None and inputs_unchanged
    if not syntax_only and ok:
        sys.path.insert(0, str(ROOT / "tools"))
        from app_preflight import analyze
        pe = output / "SPROB.EXE"
        audit = analyze(pe)
        binary = pe.read_bytes()
        optional = struct.unpack_from("<I", binary, 0x3C)[0] + 24
        os_version = list(struct.unpack_from("<HH", binary, optional + 40))
        absent = [row for row in audit["imports"]
                  if row["symbol"] not in baseline["dlls"].get(row["dll"], [])]
        legacy_socket_imports = sorted(row["symbol"] for row in audit["imports"]
                                       if row["dll"] == "WSOCK32.DLL")
        receipt["pe_audit"] = {"binary": file_record(pe), "pe": audit["pe"],
                               "os_version": os_version, "imports": audit["imports"],
                               "import_inventory_complete": audit["import_inventory_complete"],
                               "absent_from_native_media_exports": absent,
                               "actual_wsock32_imports": legacy_socket_imports}
        ok = (audit["pe"]["machine"] == 0x14C and audit["pe"]["format"] == "PE32" and
              audit["pe"]["subsystem"] == 2 and audit["pe"]["subsystem_version"] == [4, 0] and
              os_version == [4, 0] and audit["import_inventory_complete"] and
              bool(legacy_socket_imports) and not absent)
    receipt["source_and_static_gate_passed"] = ok
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if output_size(output) > OUTPUT_CAP:
        raise ValueError("final receipt-inclusive output exceeds its cap")
    return receipt, 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new private directory below build/")
    parser.add_argument("--syntax-only", action="store_true", help="check actual C source without emitting a PE")
    args = parser.parse_args()
    try:
        receipt, code = build(args.output, args.syntax_only)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.output.absolute()), "compiler_exit": receipt["compiler_exit"],
                      "source_and_static_gate_passed": receipt["source_and_static_gate_passed"],
                      "native_probe_executed": False, "steam_application_passed": False}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
