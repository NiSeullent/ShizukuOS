#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a frozen native supervisor; never install or launch a Windows guest."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/theme-engine/guest-runner"
SOURCE_NAMES = ["tests/uxtheme_guest_runner.c", "tests/uxtheme_guest_runner_mock.c",
                "tests/uxtheme_guest_runner_mock.h", "tools/build_theme_guest_runner.py",
                "benchmarks/win98se-ko-oem-native-exports-v1.json"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env=None):
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def native_gate(path):
    native = json.loads((ROOT / SOURCE_NAMES[-1]).read_text())["dlls"]["KERNEL32.DLL"]
    with pefile.PE(str(path)) as pe:
        h = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine != 0x14C or h.Magic != 0x10B or pe.is_dll() or
                pe.FILE_HEADER.TimeDateStamp != 0 or h.Subsystem != 2 or not h.AddressOfEntryPoint or
                (h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion) != (4, 10) or
                (h.MajorSubsystemVersion, h.MinorSubsystemVersion) != (4, 10) or
                h.DllCharacteristics & (0x40 | 0x100 | 0x8000) or pe.FILE_HEADER.Characteristics & 1 or
                not h.DATA_DIRECTORY[5].VirtualAddress):
            raise ValueError("Supervisor violates native Win98 PE32 GUI/4.10 contract")
        for index in (9, 10, 13, 14):
            if h.DATA_DIRECTORY[index].VirtualAddress or h.DATA_DIRECTORY[index].Size:
                raise ValueError(f"Unsupported supervisor PE directory {index}")
        imports = {}
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            name = module.dll.decode().upper()
            if name != "KERNEL32.DLL" or any(not item.name for item in module.imports):
                raise ValueError("Supervisor must import only named native KERNEL32 APIs")
            names = sorted(item.name.decode() for item in module.imports)
            if not set(names) <= set(native):
                raise ValueError(f"Supervisor has absent native imports: {set(names) - set(native)}")
            imports[name] = names
        if not imports or hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            raise ValueError("Supervisor import/export surface is unexpected")
        return {"pe98_gate": "pass", "imports": imports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", default="theme-5abe-" + secrets.token_hex(12))
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.nonce):
        parser.error("nonce must contain 1..64 ASCII letters, digits, underscore or hyphen")
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / "result.json"
    receipt.unlink(missing_ok=True)
    sources = {name: digest(ROOT / name) for name in SOURCE_NAMES}
    host = BUILD / "supervisor-host"
    common = ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
              "tests/uxtheme_guest_runner_mock.c"]
    run(common + ["-o", str(host)])
    host_result = run([str(host)])
    sanitized = BUILD / "supervisor-host-sanitize"
    run(common + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-o", str(sanitized)])
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    sanitizer_result = run([str(sanitized)], env=env)
    artifact = BUILD / "M98THRUN.EXE"
    command = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
               "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
               "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
               "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
               "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
               "-Wl,--no-insert-timestamp", "-Wl,--entry,_mainCRTStartup",
               f'-DM98_RUN_NONCE="{args.nonce}"', "tests/uxtheme_guest_runner.c", "-lkernel32",
               "-o", str(artifact)]
    run(command)
    gates = native_gate(artifact)
    if any(digest(ROOT / name) != value for name, value in sources.items()):
        raise RuntimeError("Supervisor source changed while building")
    result = {"passed": True, "host": host_result, "sanitizer": sanitizer_result,
              "nonce": args.nonce, "source_sha256": sources,
              "artifacts": {artifact.name: gates | {"sha256": digest(artifact), "bytes": artifact.stat().st_size}},
              "guest_paths": {"self": "C:\\GOPLAB\\M98THRUN.EXE", "supervisor_log": "C:\\GOPLAB\\THRUN.LOG",
                              "dynamic_stdout": "C:\\GOPLAB\\THPRO.LOG", "static_stdout": "C:\\GOPLAB\\THSTA.LOG"},
              "child_timeout_ms": 20000, "reap_timeout_ms": 5000,
              "native_win98": "not_tested", "installation": "not_performed",
              "outer_exit_limit": "requested-exit-code precedes final close; actual supervisor exit requires an outer observer"}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(host_result)
    print(sanitizer_result)
    print("PASS: native PE32 GUI 4.10 supervisor gate; Windows guest execution still required")
    print(receipt)


if __name__ == "__main__":
    main()
