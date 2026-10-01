#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze bounded exit ownership controls; never launch a VM or an application."""
import argparse
import datetime
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
import pefile

ROOT = Path(__file__).resolve().parents[2]
NAMES = ("M98EXIT.DLL", "PXUNLD.DLL", "PXDEPA.DLL", "PXDEPB.DLL", "PXPROBE.EXE", "PXSUIT.EXE")
FILES = tuple("ntwin32/process_exit/" + n for n in (
    "exit_registry.h", "exit_registry.c", "main_image.h", "main_image.c", "original_kernel.h", "original_kernel.c",
    "native.c", "native.def", "unload.def", "observer.c", "observer.def", "native_probe.c", "native_suite.c",
    "host_test.c", "build.py", "prepare.py", "README.md")) + ("benchmarks/win98se-ko-oem-native-exports-v1.json",)
OFFICIAL = ROOT / "build/latest-app-preflight-20260930/chromium-157.0.8080.0-1707946/chrome.exe"
PIN = "7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823"
KEX_ROOT = ROOT / "build/app-prerequisites-20260930/sources/KernelEx-31cdfc3560fc116637ee8ed7be31b12f3aacf5d1"

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    host, cross = shutil.which("clang"), shutil.which("i686-w64-mingw32-gcc")
    if out.exists() or not out.is_relative_to(ROOT / "build") or not host or not cross:
        parser.error("fresh isolated build output and existing Clang/MinGW compilers required")
    if sha(OFFICIAL) != PIN:
        parser.error("preserved original Chromium root changed")
    with pefile.PE(str(OFFICIAL)) as pe:
        observed = {i.name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT if d.dll.decode().upper() == "KERNEL32.DLL"
                    for i in d.imports if i.name}
    if "ExitProcess" not in observed:
        parser.error("actual original Chromium ExitProcess contract absent")
    sdk = (KEX_ROOT / "common/kexcoresdk.h", KEX_ROOT / "core/kexcoresdk.cpp", KEX_ROOT / "apilibs/kexbases/Kernel32/process.c")
    if "_KEXCOREIMP PROC kexGetProcAddress(HMODULE hModule, PCSTR lpProcName);" not in sdk[0].read_text():
        parser.error("pinned original-export SDK contract differs")
    pins = {n: sha(ROOT / n) for n in FILES}
    out.mkdir(parents=True)
    for name in FILES:
        dest = out / "frozen" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    src = out / "frozen/ntwin32/process_exit"
    sdk_pins = {}
    for path in sdk:
        relative = path.relative_to(KEX_ROOT)
        dest = out / "frozen/kernel-ex-sdk" / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        sdk_pins[str(path)] = {"sha256": sha(path), "frozen": str(dest)}
    flags = [cross, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
             "-Wno-misleading-indentation", "-fno-builtin", "-fno-tree-loop-distribute-patterns",
             "-fno-stack-protector", "-ffunction-sections", "-fdata-sections", "-nostdlib",
             "-Wl,--gc-sections", "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4",
             "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
             "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp"]
    dll_sources = [str(src / n) for n in ("exit_registry.c", "main_image.c", "original_kernel.c", "native.c")]
    commands = [[host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                 "-Wno-misleading-indentation", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                 "-fno-omit-frame-pointer", "-pthread", str(src / "exit_registry.c"), str(src / "main_image.c"),
                 str(src / "host_test.c"), "-o", str(out / "host-controls")],
                flags + ["-shared", "-Wl,--entry,_dll_entry@12", *dll_sources, str(src / "native.def"),
                         "-o", str(out / "M98EXIT.DLL"), "-lkernel32", "-lgcc"],
                flags + ["-shared", "-DPX_TEST_DYNAMIC_UNLOAD=1", "-Wl,--entry,_dll_entry@12", *dll_sources,
                         str(src / "unload.def"), "-o", str(out / "PXUNLD.DLL"), "-lkernel32", "-lgcc"]]
    for id_, name in ((1, "PXDEPA.DLL"), (2, "PXDEPB.DLL")):
        commands.append(flags + ["-shared", f"-DOBSERVER_ID={id_}", "-Wl,--entry,_dll_entry@12", str(src / "observer.c"),
                                 str(src / "observer.def"), "-o", str(out / name), "-lkernel32", "-lgcc"])
    commands.append(flags + ["-Wl,--entry,_entry@0", str(src / "original_kernel.c"), str(src / "native_probe.c"),
                              "-o", str(out / "PXPROBE.EXE"), "-lkernel32", "-lgcc"])
    commands.append(flags + ["-Wl,--entry,_entry@0", str(src / "native_suite.c"), "-o", str(out / "PXSUIT.EXE"), "-lkernel32", "-lgcc"])
    receipt = {"schema": "win98modern.native-process-exit-core.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "sources": pins, "commands": commands,
               "primary_sdk": {"repository": "https://github.com/KernelEx/KernelEx", "commit": "31cdfc3560fc116637ee8ed7be31b12f3aacf5d1", "files": sdk_pins},
               "compilers": {k: {"path": v, "sha256": sha(Path(v))} for k, v in (("host", host), ("native", cross))},
               "original_target": {"path": str(OFFICIAL), "sha256": PIN, "bytes": OFFICIAL.stat().st_size},
               "original_target_contract": "KERNEL32.DLL!ExitProcess", "native_executed": False, "application_executed": False,
               "production_loader_integrated": False,
               "scope": "Immutable ownership/host fault/concurrency controls and OEM-gated native fixtures; application and native execution unproved."}
    try:
        for i, command in enumerate(commands):
            run = subprocess.run(command, capture_output=True, text=True, timeout=90, cwd=ROOT)
            (out / f"compile-{i}.log").write_text(run.stdout + run.stderr)
            if run.returncode:
                raise ValueError(f"compiler {i} failed with {run.returncode}")
        run = subprocess.run([str(out / "host-controls")], capture_output=True, text=True, timeout=30, cwd=ROOT)
        (out / "host-controls.log").write_text(run.stdout + run.stderr)
        match = re.fullmatch(r"PASS (\d+) checks; immutable exit snapshots and real host concurrency; native_executed=false; application_executed=false\n", run.stdout)
        if run.returncode or run.stderr or not match:
            raise ValueError("real ASan/UBSan host ownership/concurrency controls failed")
        receipt["host_checks"] = int(match[1]); receipt["host_sanitizers"] = ["address", "undefined"]
        exported = json.loads((out / "frozen/benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
        artifacts = {}
        for name in NAMES:
            binary = out / name
            with pefile.PE(str(binary)) as pe:
                opt = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem, opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (0x14c, 0x10b, 2, 4, 10):
                    raise ValueError("artifact is not classic i386 Win98 4.10")
                if bool(pe.FILE_HEADER.Characteristics & 0x2000) != name.endswith(".DLL"):
                    raise ValueError("artifact executable/DLL kind differs")
                if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)) or opt.DllCharacteristics & 0x140:
                    raise ValueError("artifact needs unsupported modern runtime state")
                imports = {}
                for desc in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = desc.dll.decode().upper()
                    names = [i.name.decode() if i.name else f"#{i.ordinal}" for i in desc.imports]
                    if dll != "KERNEL32.DLL" or set(names) - set(exported[dll]):
                        raise ValueError("artifact import unavailable in actual OEM profile")
                    imports[dll] = names
                if name.endswith(".DLL"):
                    names = {i.name.decode() for i in pe.DIRECTORY_ENTRY_EXPORT.symbols if i.name}
                    expected = {"PXObserverBind"} if name.startswith("PXDEP") else {"M98ExitInitialize", "M98ExitRegister", "M98ExitUnregister", "M98ExitCount"}
                    if name == "PXUNLD.DLL": expected.add("PXTestObserve")
                    if names != expected:
                        raise ValueError("exact fixture/production stdcall export set differs")
            artifacts[name] = {"path": str(binary), "bytes": binary.stat().st_size, "sha256": sha(binary), "native_imports": imports,
                               "native_import_gate": "PASS", "native_executed": False, "test_only": name != "M98EXIT.DLL"}
        receipt["artifacts"] = artifacts
        if any(sha(ROOT / n) != digest for n, digest in pins.items()) or sha(OFFICIAL) != PIN or any(sha(Path(p)) != i["sha256"] for p, i in sdk_pins.items()):
            raise ValueError("source/original target/primary SDK changed during controls")
        receipt["status"] = "PASS"
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(out / "result.json"), "host_checks": receipt.get("host_checks"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
