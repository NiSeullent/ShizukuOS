#!/usr/bin/env python3
"""Build a pinned private protocol-telemetry host and GUI probe; no guest.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from core_ie_build import TARGET, FLOOR, MAX_FILES, HERE, ROOT, sha, read, binding, audit


def build(snapshot: Path, output: Path) -> dict:
    permitted = ROOT / "build/iewebkit-core-83bd"
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(permitted.resolve()):
        raise ValueError("choose a new private child of the core build area")
    if shutil.disk_usage(permitted).free < FLOOR + MAX_FILES:
        raise ValueError("host free space is below the 20 GiB floor plus the build budget")
    host_path = snapshot / "build.json"
    host_raw = read(host_path)
    host = json.loads(host_raw)
    if (host.get("schema") != "win98modern.iewebkit-build.v1" or host.get("target") != TARGET
            or not host.get("static_gate_passed") or not host.get("diagnostic_handoff_included")
            or host.get("engine_included")):
        raise ValueError("an exact-target diagnostic host snapshot is required")
    pin_path = HERE / "core_ie_protocol_pin.json"
    pin_raw = read(pin_path)
    pin = json.loads(pin_raw)
    patch_path = Path(pin["patch"]["path"])
    patch = read(patch_path)
    if (pin.get("schema") != "iewebkit-win98-ie5-protocol-source-pin-v1"
            or sha(host_raw) != pin["original_host_receipt"]["sha256"]
            or sha(patch) != pin["patch"]["sha256"]):
        raise ValueError("original host receipt or explicit telemetry patch changed")
    snapshot_bytes = {}
    for relative, expected in host["source_sha256"].items():
        data = read(snapshot / "source" / relative)
        if sha(data) != expected:
            raise ValueError("original snapshot source changed: " + relative)
        snapshot_bytes[relative] = data
    for relative, hashes in pin["source"].items():
        if sha(snapshot_bytes[relative]) != hashes["before_sha256"]:
            raise ValueError("patch before-source pin mismatch")
    host_dll = read(snapshot / "bundle/IEWKHOST.DLL")
    if sha(host_dll) != host["artifacts"]["IEWKHOST.DLL"]["sha256"]:
        raise ValueError("unchanged DocObject DLL differs from its receipt")
    baseline_path = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    baseline_raw = read(baseline_path, 32 * 1024 ** 2)
    if sha(baseline_raw) != host["native_export_baseline_sha256"]:
        raise ValueError("native media export baseline changed")
    baseline = json.loads(baseline_raw)
    native_path = HERE / "core_ie_protocol_native.cpp"
    native = read(native_path)
    executables = {name: shutil.which(exe) for name, exe in
                   (("cc", "i686-w64-mingw32-gcc"), ("cxx", "i686-w64-mingw32-g++"), ("patch", "patch"))}
    if not all(executables.values()):
        raise ValueError("the existing MinGW and patch tools are required")
    output.mkdir(parents=True, mode=0o700)
    source, objects, bundle = (output / name for name in ("source", "objects", "bundle"))
    for directory in (source, objects, bundle):
        directory.mkdir()
    for relative, data in snapshot_bytes.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (source / native_path.name).write_bytes(native)
    (output / patch_path.name).write_bytes(patch)
    (output / pin_path.name).write_bytes(pin_raw)
    (bundle / "IEWKHOST.DLL").write_bytes(host_dll)
    commands = []

    def run(command: list[str], cwd: Path | None = None):
        commands.append({"argv": command, "cwd": str(cwd or output)})
        (output / "argv.json").write_text(json.dumps(commands, indent=2) + "\n")
        with (output / "build.log").open("ab") as log:
            result = subprocess.run(command, cwd=cwd or output, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        if result.returncode:
            raise ValueError("private compile/patch failed; inspect " + str(output / "build.log"))

    run([executables["patch"], "--batch", "--fuzz=0", "-p1", "-i", str(output / patch_path.name)], source)
    patched_hashes = dict(host["source_sha256"])
    for relative, hashes in pin["source"].items():
        actual = sha(read(source / relative))
        if actual != hashes["after_sha256"]:
            raise ValueError("patched private source differs from its after pin")
        patched_hashes[relative] = actual
    defines = ["-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400",
               "-D_WIN32_IE=0x0500", "-DIEWK_TARGET_IE=50", "-DIEWK_TARGET_SECURITY_MODE=0",
               "-DIEWK_HOST_DEVELOPMENT=1"]
    common = ["-Os", "-g0", "-Wall", "-Wextra", "-Werror", "-march=pentium3", *defines,
              "-I", str(source / "include"), "-I", str(source / "host")]
    link = ["-static", "-static-libgcc", "-static-libstdc++",
            "-Wl,--kill-at,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0,"
            "--major-subsystem-version,4,--minor-subsystem-version,0"]
    libraries = ["-ladvapi32", "-luser32", "-lole32", "-loleaut32", "-luuid", "-lurlmon"]
    for filename, tool, standard in (("engine_contract.c", "cc", "c99"), ("engine_loader.cpp", "cxx", "c++11")):
        run([executables[tool], "-std=" + standard, *common, "-c", str(source / "host" / filename),
             "-o", str(objects / (Path(filename).stem + ".o"))])
    run([executables["cxx"], "-std=c++11", *common, "-DIEWK_NAV_DIAGNOSTIC", *link, "-shared",
         str(source / "host/navigation_bho.cpp"), str(source / "host/navigation_handoff.cpp"),
         str(objects / "engine_loader.o"), str(objects / "engine_contract.o"), "-o", str(bundle / "NAVBHO.DLL"), *libraries])
    run([executables["cxx"], "-std=c++11", "-fno-exceptions", "-fno-rtti", *common,
         "-DNTDDI_VERSION=0x04000000", "-ffunction-sections", "-fdata-sections", *link,
         "-mwindows", "-Wl,--gc-sections", str(source / native_path.name), "-o", str(bundle / "IEACT.EXE"),
         "-ladvapi32", "-luser32", "-lole32", "-loleaut32", "-luuid", "-lversion"])
    artifacts = {name: audit(bundle / name, baseline, name.endswith(".EXE"))
                 for name in ("IEACT.EXE", "IEWKHOST.DLL", "NAVBHO.DLL")}
    receipt = {"schema": "iewebkit-win98-ie5-protocol-build-v1", "target": TARGET,
               "source": binding(source / native_path.name), "source_origin": binding(native_path),
               "builder": binding(Path(__file__)), "builder_dependency": binding(HERE / "core_ie_build.py"),
               "host_receipt": binding(host_path), "original_host_source_sha256": host["source_sha256"],
               "private_host_source_sha256": patched_hashes, "private_host_source": str(source.resolve()),
               "patch": binding(output / patch_path.name), "pin": binding(output / pin_path.name),
               "artifacts": artifacts, "compiler_commands": commands,
               "native_export_baseline": {"path": str(baseline_path.resolve()), "sha256": sha(baseline_raw)},
               "build_log": binding(output / "build.log"),
               "unchanged_DocObject_DLL": True, "DocObject_Load_acceptance_preserved": True,
               "static_gate_passed": all(value["static_gate_passed"] for value in artifacts.values()),
               "guest_execution": "NOT-VERIFIED", "provider_status": "UNVERIFIED", "full_engine": False,
               "protocol_ingress_verified": False, "rendering_verified": False, "tls_verified": False}
    (output / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    total = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
    if total > MAX_FILES or shutil.disk_usage(output).free < FLOOR:
        raise ValueError("private build exceeded its artifact/free-space budget")
    return {"receipt": str(output / "build.json"), "sha256": sha((output / "build.json").read_bytes()),
            "allocated_file_bytes": total, "static_gate_passed": receipt["static_gate_passed"],
            "probe_sha256": artifacts["IEACT.EXE"]["sha256"], "bho_sha256": artifacts["NAVBHO.DLL"]["sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = build(args.snapshot.resolve(), args.output.resolve())
        print(json.dumps(report, indent=2))
        return 0 if report["static_gate_passed"] else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
