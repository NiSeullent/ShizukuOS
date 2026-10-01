#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze/build real event address wait controls; no VM or target app launch."""
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
NAMES = ("M98ADDR.DLL", "CHADDR.EXE", "CHASUIT.EXE")
FILES = tuple("ntwin32/chromium_port/" + n for n in (
    "address_wait.h", "address_wait.c", "address_native.c", "address_native.def",
    "address_native_probe.c", "address_suite.c", "address_host_test.c",
    "api_contract.h", "api_contract.c", "address_cxx_contract.cpp", "build_address.py", "prepare_address.py", "ADDRESS_README.md")) + (
    "ntwin32/native_environment/environment.h", "ntwin32/native_environment/environment.c",
    "benchmarks/win98se-ko-oem-native-exports-v1.json")
OFFICIAL = ROOT / "build/latest-app-preflight-20260930/chromium-157.0.8080.0-1707946/chrome.exe"
PIN = "7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823"
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    host, cxx, cross = shutil.which("clang"), shutil.which("clang++"), shutil.which("i686-w64-mingw32-gcc")
    if out.exists() or not out.is_relative_to(ROOT / "build") or not host or not cxx or not cross:
        parser.error("fresh isolated output and existing Clang/C++/MinGW compilers required")
    if sha(OFFICIAL) != PIN:
        parser.error("preserved original Chromium root changed")
    with pefile.PE(str(OFFICIAL)) as pe:
        actual = {(d.dll.decode().upper(), i.name.decode()) for d in pe.DIRECTORY_ENTRY_DELAY_IMPORT
                  for i in d.imports if i.name and d.dll.decode().upper().startswith("API-MS-")}
    expected = {("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL", n) for n in
                ("WaitOnAddress", "WakeByAddressSingle", "WakeByAddressAll")}
    expected.add(("API-MS-WIN-POWER-BASE-L1-1-0.DLL", "CallNtPowerInformation"))
    if actual != expected:
        parser.error("original API-set contracts differ from this exact candidate map")
    pins = {n: sha(ROOT / n) for n in FILES}
    out.mkdir(parents=True)
    for n in FILES:
        dest = out / "frozen" / n
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / n, dest)
    src = out / "frozen/ntwin32/chromium_port"
    flags = [cross, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
             "-Wno-misleading-indentation", "-fno-builtin", "-fno-tree-loop-distribute-patterns",
             "-fno-stack-protector", "-ffunction-sections", "-fdata-sections", "-nostdlib",
             "-Wl,--gc-sections", "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4",
             "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
             "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp"]
    commands = [[host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                 "-Wno-misleading-indentation", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                 "-fno-omit-frame-pointer", "-pthread", str(src / "address_wait.c"),
                 str(src / "address_host_test.c"), str(src / "api_contract.c"),
                 str(out / "frozen/ntwin32/native_environment/environment.c"),
                 "-o", str(out / "host-controls")],
                flags + ["-shared", "-Wl,--entry,_dll_entry@12", str(src / "address_wait.c"),
                         str(src / "address_native.c"), str(src / "address_native.def"),
                         "-o", str(out / NAMES[0]), "-lkernel32", "-lgcc"],
                flags + ["-Wl,--entry,_entry@0", str(src / "address_native_probe.c"),
                         "-o", str(out / NAMES[1]), "-lkernel32", "-lgcc"],
                flags + ["-Wl,--entry,_entry@0", str(src / "address_suite.c"),
                         "-o", str(out / NAMES[2]), "-lkernel32", "-lgcc"]]
    c_flags = [host, "--no-default-config", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
               "-Wno-misleading-indentation", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    objects = []
    for name, source in (("address", src / "address_wait.c"), ("contract", src / "api_contract.c"),
                         ("environment", out / "frozen/ntwin32/native_environment/environment.c")):
        obj = out / (name + ".o");objects.append(str(obj))
        commands.append(c_flags + ["-c", str(source), "-o", str(obj)])
    commands.append([cxx, "--no-default-config", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
                     "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(src / "address_cxx_contract.cpp"),
                     *objects, "-o", str(out / "cxx-contract")])
    receipt = {"schema": "win98modern.chromium-address-core.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "sources": pins, "commands": commands,
               "compilers": {k: {"path": v, "sha256": sha(Path(v))} for k, v in (("host", host), ("cxx", cxx), ("native", cross))},
               "original_target": {"path": str(OFFICIAL), "sha256": PIN, "bytes": OFFICIAL.stat().st_size},
               "observed_original_contracts": sorted(actual),
               "native_executed": False, "application_executed": False,
               "scope": "Source-linked real host event/fault/concurrency controls and native compilation; no target app execution."}
    try:
        for i, command in enumerate(commands):
            run = subprocess.run(command, capture_output=True, text=True, timeout=90, cwd=ROOT)
            (out / f"compile-{i}.log").write_text(run.stdout + run.stderr)
            if run.returncode:
                raise ValueError(f"compiler {i} failed with {run.returncode}")
        run = subprocess.run([str(out / "host-controls"), str(OFFICIAL)], capture_output=True, text=True, timeout=30, cwd=ROOT)
        (out / "host-controls.log").write_text(run.stdout + run.stderr)
        match = re.fullmatch(r"PASS (\d+) checks; real host event waits; native_executed=false; application_executed=false\n", run.stdout)
        if run.returncode or run.stderr or not match:
            raise ValueError("actual ASan/UBSan host event controls failed")
        receipt["host_checks"] = int(match[1]); receipt["host_sanitizers"] = ["address", "undefined"]
        cxx_run = subprocess.run([str(out / "cxx-contract")], capture_output=True, text=True, timeout=10, cwd=ROOT)
        (out / "cxx-contract.log").write_text(cxx_run.stdout + cxx_run.stderr)
        if cxx_run.returncode or cxx_run.stdout or cxx_run.stderr:
            raise ValueError("actual C++ consumer failed to link or call source-linked C interfaces")
        receipt["cxx_consumer"] = {"status": "PASS", "exit_code": cxx_run.returncode, "sha256": sha(out / "cxx-contract")}
        exported = json.loads((out / "frozen/benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
        if "CallNtPowerInformation" not in exported["POWRPROF.DLL"]:
            raise ValueError("actual OEM power export unavailable")
        artifacts = {}
        for name in NAMES:
            binary = out / name
            with pefile.PE(str(binary)) as pe:
                opt = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem, opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (0x14c, 0x10b, 2, 4, 10):
                    raise ValueError("artifact is not classic i386 Win98 4.10")
                if bool(pe.FILE_HEADER.Characteristics & 0x2000) != (name == "M98ADDR.DLL"):
                    raise ValueError("artifact executable/DLL kind differs")
                if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)) or opt.DllCharacteristics & 0x140:
                    raise ValueError("artifact needs modern runtime state")
                imports = {}
                for desc in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = desc.dll.decode().upper()
                    names = [i.name.decode() if i.name else f"#{i.ordinal}" for i in desc.imports]
                    if dll != "KERNEL32.DLL" or set(names) - set(exported[dll]):
                        raise ValueError("artifact import unavailable in native OEM profile")
                    imports[dll] = names
                if name == "M98ADDR.DLL":
                    names = {i.name.decode() for i in pe.DIRECTORY_ENTRY_EXPORT.symbols if i.name}
                    if names != {"WaitOnAddress", "WakeByAddressSingle", "WakeByAddressAll", "M98AddressPending", "M98AddressCleanup"}:
                        raise ValueError("provider stdcall export set differs")
            artifacts[name] = {"path": str(binary), "bytes": binary.stat().st_size, "sha256": sha(binary),
                               "native_imports": imports, "native_import_gate": "PASS", "native_executed": False}
        receipt["artifacts"] = artifacts
        if any(sha(ROOT / n) != digest for n, digest in pins.items()) or sha(OFFICIAL) != PIN:
            raise ValueError("source/original target changed during controls")
        receipt["status"] = "PASS"
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(out / "result.json"), "host_checks": receipt.get("host_checks"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
