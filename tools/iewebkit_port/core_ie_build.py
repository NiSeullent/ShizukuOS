#!/usr/bin/env python3
"""Build new GUI diagnostics from pinned local sources; never launch a guest.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Preserves the canonical checkout, existing host snapshots and memory fixtures.
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
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from app_preflight import analyze

TARGET = {"os": "win98se", "os_version": "4.10.2222", "ie": "5.0",
          "ie_version": "5.00.2614.3500", "arch": "x86", "mode": "classic"}
FLOOR = 20 * 1024 ** 3
MAX_FILES = 10 * 1024 ** 2


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path, limit: int = 1024 ** 2) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("input must be a bounded regular file: " + str(path))
    return path.read_bytes()


def binding(path: Path) -> dict:
    data = read(path)
    return {"path": str(path.resolve()), "sha256": sha(data), "bytes": len(data)}


def audit(path: Path, baseline: dict, gui: bool) -> dict:
    report = analyze(path)
    missing = [row for row in report["imports"] if row["symbol"] not in baseline["dlls"].get(row["dll"], [])]
    good = (report["pe"]["machine"] == 0x14c and report["pe"]["format"] == "PE32"
            and report["pe"]["subsystem_version"] <= [4, 10]
            and (not gui or report["pe"]["subsystem"] == 2)
            and report["import_inventory_complete"] and not missing)
    return {"path": str(path.resolve()), "sha256": report["input"]["sha256"],
            "bytes": report["input"]["size_bytes"], "pe": report["pe"],
            "import_inventory": report["imports"], "import_inventory_complete": report["import_inventory_complete"],
            "missing_from_win98_export_baseline": missing, "static_gate_passed": good,
            "installed_dependency_or_behavior_verified": False}


def build(snapshot: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("output exists; choose a new private build directory")
    permitted = ROOT / "build/iewebkit-core-83bd"
    if not output.resolve().is_relative_to(permitted.resolve()):
        raise ValueError("output must be a private child of the core build area")
    if shutil.disk_usage(permitted).free < FLOOR + MAX_FILES:
        raise ValueError("host free space is below the 20 GiB floor plus the build budget")
    host_receipt_path = snapshot / "build.json"
    host_raw = read(host_receipt_path)
    host = json.loads(host_raw)
    if (host.get("schema") != "win98modern.iewebkit-build.v1" or host.get("target") != TARGET
            or not host.get("static_gate_passed") or not host.get("diagnostic_handoff_included")
            or host.get("engine_included")):
        raise ValueError("a successful exact-target diagnostic host snapshot is required")
    for relative, expected in host["source_sha256"].items():
        # Use the selected frozen snapshot, independently of new peer edits.
        if sha(read(snapshot / "source" / relative)) != expected:
            raise ValueError("selected host snapshot source has changed: " + relative)
    dlls = {}
    for name in ("IEWKHOST.DLL", "NAVBHO.DLL"):
        dlls[name] = read(snapshot / "bundle" / name)
        if sha(dlls[name]) != host["artifacts"][name]["sha256"]:
            raise ValueError("host DLL differs from its build receipt: " + name)
    baseline_path = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    baseline_raw = read(baseline_path, 32 * 1024 ** 2)
    baseline = json.loads(baseline_raw)
    if sha(baseline_raw) != host["native_export_baseline_sha256"]:
        raise ValueError("native media export baseline differs from the pinned inputs")
    native_path = HERE / "core_ie_native.cpp"
    native = read(native_path)
    compilers = {key: shutil.which("i686-w64-mingw32-" + suffix) for key, suffix in (("cc", "gcc"), ("cxx", "g++"))}
    if not all(compilers.values()):
        raise ValueError("the existing x86 MinGW compilers are required")
    output.mkdir(parents=True, mode=0o700)
    source = output / "source"
    source.mkdir()
    (source / "core_ie_native.cpp").write_bytes(native)
    artifacts = output / "bundle"
    artifacts.mkdir()
    for name, data in dlls.items():
        (artifacts / name).write_bytes(data)
    common = ["-Os", "-g0", "-Wall", "-Wextra", "-Werror", "-march=pentium3",
              "-ffunction-sections", "-fdata-sections", "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410",
              "-D_WIN32_WINNT=0x0400", "-DNTDDI_VERSION=0x04000000", "-D_WIN32_IE=0x0500"]
    link = ["-static", "-static-libgcc", "-mwindows", "-Wl,--gc-sections,--no-insert-timestamp," 
            "--major-os-version,4,--minor-os-version,0,--major-subsystem-version,4,--minor-subsystem-version,0"]
    commands = [
        [compilers["cxx"], "-std=c++11", "-fno-exceptions", "-fno-rtti", *common, *link,
         "-static-libstdc++", str(source / "core_ie_native.cpp"), "-o", str(artifacts / "IEACT.EXE"),
         "-ladvapi32", "-luser32", "-lole32", "-loleaut32", "-luuid", "-lversion"],
    ]
    (output / "argv.json").write_text(json.dumps(commands, indent=2) + "\n")
    for command in commands:
        with (output / "build.log").open("ab") as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        if completed.returncode:
            raise ValueError("compile failed; inspect " + str(output / "build.log"))
    audits = {name: audit(artifacts / name, baseline, name.endswith(".EXE"))
              for name in ("IEACT.EXE", "IEWKHOST.DLL", "NAVBHO.DLL")}
    report = {"schema": "iewebkit-win98-ie5-activation-build-v1", "target": TARGET,
              "source": {"path": str(native_path.resolve()), "sha256": sha(native), "bytes": len(native)},
              "builder": binding(Path(__file__)), "host_receipt": binding(host_receipt_path),
              "host_source_sha256": host["source_sha256"],
              "artifacts": audits, "compiler_argv": commands, "build_log": binding(output / "build.log") if (output / "build.log").stat().st_size else
              {"path": str((output / "build.log").resolve()), "bytes": 0, "sha256": sha(b"")},
              "native_export_baseline": {"path": str(baseline_path.resolve()), "sha256": sha(baseline_raw)},
              "static_gate_passed": all(value["static_gate_passed"] for value in audits.values()),
              "guest_execution": "NOT-VERIFIED", "provider_status": "UNVERIFIED", "full_engine": False,
              "rendering_verified": False, "tls_verified": False}
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    total = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
    if total > MAX_FILES or shutil.disk_usage(output).free < FLOOR:
        raise ValueError("private build exceeded its artifact/free-space budget")
    return {"receipt": str((output / "build.json").resolve()), "sha256": sha((output / "build.json").read_bytes()),
            "allocated_file_bytes": total, "static_gate_passed": report["static_gate_passed"],
            "gui_probe_sha256": audits["IEACT.EXE"]["sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = build(args.snapshot, args.output)
        print(json.dumps(report, indent=2))
        return 0 if report["static_gate_passed"] else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
