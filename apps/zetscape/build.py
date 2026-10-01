#!/usr/bin/env python3
"""Compile the real x86 host; never execute it or supply a pretend engine."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import time

APP = Path(__file__).resolve().parent
ROOT = APP.parents[1]
FLOOR = 20 * 1024**3
OUTPUT_LIMIT = 8 * 1024**2
MARGIN = 256 * 1024**2
SOURCES = ("zetscape.c", "zetscape_extensions.h", "engine_abi_pin.json",
           "upstream/engine.h", "upstream/engine_contract.c", "upstream/LICENSE")
COMMON = ("-pipe", "-std=c99", "-Wall", "-Wextra", "-Werror", "-Os", "-g0",
          "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400")


def compiler_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def digest(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def snapshot() -> dict[str, bytes]:
    data = {name: (APP / name).read_bytes() for name in SOURCES}
    pin = json.loads(data["engine_abi_pin.json"])
    if (pin.get("schema") != "zetscape.shared-engine-abi-pin.v1" or
            pin.get("origin_commit") != "dd93262508ecec2969d3267b9d6d831d66fcd489" or
            pin.get("ABI") != 1 or pin.get("license") != "BSD-2-Clause"):
        raise ValueError("unexpected shared-engine ABI pin")
    entries = pin.get("inputs", [])
    names = {"upstream/engine.h", "upstream/engine_contract.c", "upstream/LICENSE"}
    if len(entries) != 3 or {"upstream/" + Path(e["local"]).name for e in entries} != names:
        raise ValueError("shared-engine ABI input inventory changed")
    for entry in entries:
        raw = data["upstream/" + Path(entry["local"]).name]
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("shared-engine ABI bytes changed")
    return data


def compiler_inputs(cc: str, source: Path) -> tuple[list[dict], list[list[str]]]:
    files: set[Path] = set()
    commands = []
    for name in ("zetscape.c", "upstream/engine_contract.c"):
        command = [cc, *COMMON, "-I", str(source / "upstream"), "-M", "-MT", "zetscape", str(source / name)]
        commands.append(command)
        result = subprocess.run(command, check=True, capture_output=True, text=True,
                                timeout=30, preexec_fn=compiler_limits)
        dependencies = result.stdout.replace("\\\n", " ").split(":", 1)[1]
        files.update(Path(p).resolve(strict=True) for p in shlex.split(dependencies))
    return [digest(path) for path in sorted(files)], commands


def output_bytes(output: Path) -> int:
    return sum(path.stat().st_size for path in output.rglob("*") if path.is_file())


def run_bounded(command: list[str], output: Path) -> dict:
    environment = dict(os.environ, TMPDIR=str(output / "tmp"))
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=environment, start_new_session=True, preexec_fn=compiler_limits)
    start = time.monotonic()
    minimum_free = shutil.disk_usage(output).free
    try:
        while True:
            free = shutil.disk_usage(output).free
            minimum_free = min(minimum_free, free)
            if free < FLOOR or output_bytes(output) > OUTPUT_LIMIT:
                raise ValueError("owned build stopped at its disk reserve or output bound")
            if time.monotonic() - start > 90:
                raise ValueError("owned host compilation exceeded 90 seconds")
            try:
                log, _ = process.communicate(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        # The separate process group contains only this compiler and children.
        import signal
        os.killpg(process.pid, signal.SIGTERM)
        try:
            log, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            log, _ = process.communicate()
        (output / "build.log").write_bytes(log[-1024**2:])
        raise
    (output / "build.log").write_bytes(log[-1024**2:])
    if process.returncode:
        raise ValueError(f"real compiler returned {process.returncode}; inspect build.log")
    if output_bytes(output) > OUTPUT_LIMIT or shutil.disk_usage(output).free < FLOOR:
        raise ValueError("post-build resource bound failed")
    return {"minimum_free_bytes": minimum_free, "output_bytes": output_bytes(output),
            "reserve_bytes": FLOOR, "output_limit_bytes": OUTPUT_LIMIT,
            "compiler_cpu_limit_seconds": 45, "compiler_file_limit_bytes": 2 * 1024**2,
            "core_dumps_disabled": True}


def audit(executable: Path, baseline: Path) -> dict:
    sys.path.insert(0, str(ROOT / "tools"))
    from app_preflight import analyze
    manifest = json.loads(baseline.read_bytes())
    if manifest.get("schema") != "w98mod.export-manifest.v1":
        raise ValueError("unexpected native export baseline")
    report = analyze(executable)
    raw = executable.read_bytes()
    offset = struct.unpack_from("<I", raw, 0x3c)[0] + 24
    os_version = list(struct.unpack_from("<HH", raw, offset + 40))
    absent = [row for row in report["imports"]
              if row["symbol"] not in manifest["dlls"].get(row["dll"], [])]
    pe = report["pe"]
    passed = (pe["machine"] == 0x14c and pe["format"] == "PE32" and
              pe["subsystem"] == 2 and pe["subsystem_version"] == [4, 0] and
              os_version == [4, 0] and report["import_inventory_complete"] and not absent)
    return {"pe": pe, "os_version": os_version, "imports": report["imports"],
            "absent_from_native_baseline": absent, "static_gate_passed": passed,
            "baseline": digest(baseline), "auditor": digest(ROOT / "tools/app_preflight.py"),
            "installed_dependencies_or_runtime_verified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--syntax-only", action="store_true", help="real compiler checks; no generated files")
    mode.add_argument("--output", type=Path, help="new private PE/source/receipt directory; 20 GiB reserve")
    parser.add_argument("--baseline", type=Path,
                        default=ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json")
    args = parser.parse_args(argv)
    try:
        source_bytes = snapshot()
        cc = shutil.which("i686-w64-mingw32-gcc")
        if not cc:
            raise ValueError("the existing x86 MinGW compiler is required")
        target = subprocess.run([cc, "-dumpmachine"], check=True, capture_output=True,
                                text=True, timeout=10).stdout.strip()
        if target != "i686-w64-mingw32":
            raise ValueError("wrong compiler target")
        source = APP
        receipt = {"schema": "zetscape.native-host-build.v1", "compiler": digest(Path(cc).resolve()),
                   "compiler_target": target, "build_driver": digest(Path(__file__).resolve()),
                   "engine_provider_built": False, "native_execution_verified": False,
                   "full_modern_web_verified": False, "shizuku_gpu_verified": False,
                   "toolchain_archive_closure_complete": False, "commands": []}
        output = args.output.absolute() if args.output else None
        if output:
            if output.exists() or output.is_symlink():
                raise ValueError("use a new private output directory")
            ancestor = output.parent
            while not ancestor.exists():
                ancestor = ancestor.parent
            if shutil.disk_usage(ancestor).free < FLOOR + MARGIN + OUTPUT_LIMIT:
                raise ValueError("insufficient disk reserve; syntax-only checks remain available")
            if output.resolve().is_relative_to(APP):
                raise ValueError("output must be outside the source directory")
            output.mkdir(parents=True, mode=0o700)
            source = output / "source"
            for name, raw in source_bytes.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            (output / "tmp").mkdir()
        dependencies, commands = compiler_inputs(cc, source)
        receipt["compile_dependencies"] = dependencies
        receipt["commands"].extend(commands)
        command = [cc, *COMMON, "-I", str(source / "upstream"),
                   str(source / "zetscape.c"), str(source / "upstream/engine_contract.c")]
        if not output:
            command.append("-fsyntax-only")
            receipt["commands"].append(command)
            subprocess.run(command, check=True, timeout=30, preexec_fn=compiler_limits)
            receipt["syntax_check_passed"] = True
        else:
            executable = output / "ZETSCAPE.EXE"
            command.extend(["-static", "-static-libgcc", "-mwindows",
                            "-Wl,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0,"
                            "--major-subsystem-version,4,--minor-subsystem-version,0",
                            "-o", str(executable), "-luser32", "-lgdi32"])
            receipt["commands"].append(command)
            receipt["resource_guard"] = run_bounded(command, output)
            receipt["executable"] = digest(executable)
            receipt["audit"] = audit(executable, args.baseline.resolve(strict=True))
            if not receipt["audit"]["static_gate_passed"]:
                raise ValueError("native PE/import gate failed")
        for old in dependencies:
            if digest(Path(old["path"])) != old:
                raise ValueError("compiler source/header input changed during verification")
        if snapshot() != source_bytes:
            raise ValueError("live host source changed during verification")
        if output:
            (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            if output_bytes(output) > OUTPUT_LIMIT:
                raise ValueError("receipt exceeds output allowance")
            print(json.dumps({"receipt": str(output / "receipt.json"),
                              "host_bytes": receipt["executable"]["bytes"],
                              "static_gate_passed": True, "native_execution_verified": False}))
        else:
            print(json.dumps(receipt, indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Zetscape build: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
