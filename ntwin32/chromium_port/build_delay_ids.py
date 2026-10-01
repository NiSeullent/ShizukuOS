#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile delay core controls and a classic Win98 probe; launch no VM/app."""
import argparse
import datetime
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FILES = tuple(f"ntwin32/chromium_port/{name}" for name in (
    "delay_runtime.h", "delay_runtime.c", "delay_fixture.h", "delay_fixture.c",
    "delay_host_test.c", "delay_native_probe.c", "delay_suite.c", "delay_cxx_contract.cpp", "prepare_delay.py", "build_delay.py", "README.md")) + (
    "ntwin32/native_loader/pe.h", "ntwin32/native_loader/pe.c",
    "benchmarks/win98se-ko-oem-native-exports-v1.json")
FILES += tuple("ntwin32/chromium_port/" + n for n in ("delay_native_probe_ids.c", "build_delay_ids.py"))
OFFICIAL = {
    "chrome.exe": "7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823",
    "chrome_elf.dll": "54ffa9edd24ed9251fefca50abd27d4542fe81b63757d0ed0df2304a36ad1473",
}
OFFICIAL_ROOT = ROOT / "build/latest-app-preflight-20260930/chromium-157.0.8080.0-1707946"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("fresh isolated repository build output required")
    host, cxx, cross = shutil.which("clang"), shutil.which("clang++"), shutil.which("i686-w64-mingw32-gcc")
    if not host or not cxx or not cross:
        parser.error("existing host Clang and MinGW x86 compiler required")
    pins = {name: sha(ROOT / name) for name in FILES}
    if any(not (OFFICIAL_ROOT / name).is_file() or sha(OFFICIAL_ROOT / name) != digest
           for name, digest in OFFICIAL.items()):
        parser.error("preserved official Chromium 157 inputs changed or unavailable")
    out.mkdir(parents=True)
    for name in pins:
        dest = out / "frozen" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    source = out / "frozen/ntwin32/chromium_port"
    pe_source = out / "frozen/ntwin32/native_loader/pe.c"
    commands = [
        [host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
         "-Wno-misleading-indentation", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
         "-fno-omit-frame-pointer", "-pthread", str(source / "delay_runtime.c"),
         str(source / "delay_fixture.c"), str(source / "delay_host_test.c"), str(pe_source),
         "-o", str(out / "host-controls")],
        [cross, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
         "-Wno-misleading-indentation", "-fno-builtin", "-fno-tree-loop-distribute-patterns",
         "-fno-stack-protector", "-ffunction-sections", "-fdata-sections", "-nostdlib",
         "-Wl,--gc-sections", "-Wl,--entry,_entry@0", "-Wl,--subsystem,windows:4.10",
         "-Wl,--major-os-version,4", "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase",
         "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
         str(source / "delay_runtime.c"), str(source / "delay_fixture.c"),
         str(source / "delay_native_probe_ids.c"), str(pe_source), "-o", str(out / "CHDLY.EXE"),
         "-lkernel32", "-lgcc"],
    ]
    commands.append(commands[1][:commands[1].index(str(source / "delay_runtime.c"))] +
                    [str(source / "delay_suite.c"), "-o", str(out / "CHDSUIT.EXE"), "-lkernel32", "-lgcc"])
    c_flags = [host, "--no-default-config", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
               "-Wno-misleading-indentation", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    commands.extend([c_flags + ["-c", str(source / "delay_runtime.c"), "-o", str(out / "delay-runtime.o")],
                     c_flags + ["-c", str(pe_source), "-o", str(out / "pe.o")],
                     [cxx, "--no-default-config", "-std=c++17", "-O1", "-Wall", "-Wextra", "-Werror",
                      "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                      str(source / "delay_cxx_contract.cpp"), str(out / "delay-runtime.o"),
                      str(out / "pe.o"), "-o", str(out / "cxx-contract")]])
    receipt = {"schema": "win98modern.chromium-delay-core.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "sources": pins, "commands": commands, "native_thread_id_outputs": "real DWORD storage for every worker; handle/id/immediate failure error logs; original NULL cause unproved",
               "compilers": {"host": {"path": host, "sha256": sha(Path(host))},
                             "cxx": {"path": cxx, "sha256": sha(Path(cxx))},
                             "native": {"path": cross, "sha256": sha(Path(cross))}},
               "native_executed": False, "application_executed": False,
               "scope": "Host fault/concurrency controls and classic Win98 probe compilation."
                        " Chromium/Electron/Office/Steam execution remains unproved."}
    try:
        for index, command in enumerate(commands):
            result = subprocess.run(command, capture_output=True, text=True, timeout=120, cwd=ROOT)
            (out / f"compile-{index}.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise ValueError(f"compiler {index} failed with {result.returncode}")
        tested = subprocess.run([str(out / "host-controls"), *(str(OFFICIAL_ROOT / name) for name in OFFICIAL)], capture_output=True, text=True,
                                timeout=30, cwd=ROOT)
        (out / "host-controls.log").write_text(tested.stdout + tested.stderr)
        match = re.search(r"^PASS (\d+) checks; host mock resolver only; native_executed=false\n$", tested.stdout, re.MULTILINE)
        if tested.returncode or tested.stderr or not match:
            raise ValueError("actual sanitized host controls failed")
        receipt["host_checks"] = int(match[1])
        cxx_result = subprocess.run([str(out / "cxx-contract")], capture_output=True, text=True, timeout=10, cwd=ROOT)
        (out / "cxx-contract.log").write_text(cxx_result.stdout + cxx_result.stderr)
        if cxx_result.returncode or cxx_result.stdout or cxx_result.stderr:
            raise ValueError("actual C++ consumer failed to link or call the C ABI")
        receipt["cxx_consumer"] = {"status": "PASS", "exit_code": cxx_result.returncode,
                                   "sha256": sha(out / "cxx-contract")}
        receipt["host_sanitizers"] = ["address", "undefined"]
        receipt["official_chromium_delay_metadata"] = {
            "version": "157.0.8080.0", "snapshot": 1707946,
            "inputs": {name: {"sha256": digest, "bytes": (OFFICIAL_ROOT / name).stat().st_size}
                       for name, digest in OFFICIAL.items()},
            "actual_host_output": [line for line in tested.stdout.splitlines() if line.startswith("OFFICIAL ")],
            "application_executed": False,
            "scope": "Only original delay directory validation in private host mappings;"
                     " no target entry point, TLS callback or imported function was called.",
        }
        exported = json.loads((out / "frozen/benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
        artifacts = {}
        for name in ("CHDLY.EXE", "CHDSUIT.EXE"):
            binary = out / name
            with pefile.PE(str(binary)) as pe:
                opt = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem,
                        opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (0x14c, 0x10b, 2, 4, 10):
                    raise ValueError("native probe is not a classic i386 Win98 image")
                if any(opt.DATA_DIRECTORY[index].VirtualAddress for index in (9, 10, 13, 14)) or opt.DllCharacteristics & 0x140:
                    raise ValueError("native probe unexpectedly requires modern runtime state")
                imports = {}
                for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = descriptor.dll.decode().upper()
                    names = [item.name.decode() if item.name else f"#{item.ordinal}" for item in descriptor.imports]
                    if dll != "KERNEL32.DLL":
                        raise ValueError("native probe imports a non-Kernel32 library")
                    native_names = set(exported[dll])
                    if set(names) - native_names:
                        raise ValueError(f"native OEM import unavailable: {set(names) - native_names}")
                    imports[dll] = names
            artifacts[name] = {"path": str(binary), "bytes": binary.stat().st_size,
                               "sha256": sha(binary), "native_imports": imports,
                               "native_import_gate": "PASS", "native_executed": False}
        receipt["artifact"] = artifacts["CHDLY.EXE"]
        receipt["artifacts"] = artifacts
        if any(sha(ROOT / name) != digest for name, digest in pins.items()):
            raise ValueError("source changed during compilation or controls")
        if any(sha(OFFICIAL_ROOT / name) != digest for name, digest in OFFICIAL.items()):
            raise ValueError("official Chromium input changed during controls")
        receipt["status"] = "PASS"
    except (OSError, ValueError, subprocess.TimeoutExpired, KeyError, TypeError) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "host_checks": receipt.get("host_checks"),
                      "receipt": str(out / "result.json"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
