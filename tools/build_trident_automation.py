#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/test own bounded bridge; no VM, download, registration or service."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ["src/m98_trident_automation.h", "src/m98_trident_automation.cpp",
           "src/m98_trident_automation_HANDOFF.md", "src/m98_trident_script.h",
           "tests/m98_trident_automation_host.cpp", "tests/m98_trident_automation_mock.h",
           "tests/m98_trident_automation_guest.cpp", "tools/build_trident_automation.py",
           "platform/freestanding/memory.c", "platform/freestanding/memory.h",
           "benchmarks/win98se-ko-oem-native-exports-v1.json"]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build/trident-automation-v4")
    args = parser.parse_args()
    build = args.build_dir.resolve()
    require(build.is_relative_to(ROOT / "build"), "build directory must stay in own worktree build")
    require(not build.exists(), "preserve existing checkpoint; choose a fresh build directory")
    hashes = {name: digest(ROOT / name) for name in SOURCES}
    build.mkdir(parents=True)
    steps = []

    def run(name, command, env=None):
        result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                capture_output=True, timeout=60)
        log = build / f"{name}.txt"
        log.write_text(result.stdout + result.stderr)
        steps.append({"name": name, "command": command, "returncode": result.returncode,
                      "log": str(log), "sha256": digest(log)})
        require(result.returncode == 0, f"{name} failed: {result.stderr}")
        return result.stdout.strip()

    common = ["-std=c++11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
              "-DM98_AUTOMATION_HOST_TEST", "-Isrc", "-Itests"]
    core = ["src/m98_trident_automation.cpp", "tests/m98_trident_automation_host.cpp"]
    host = build / "automation-host"
    sanitized = build / "automation-host-sanitize"
    run("host-build", ["clang++"] + common + core + ["-o", str(host)])
    normal = run("host-test", [str(host)])
    run("sanitize-build", ["clang++"] + common + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        + core + ["-o", str(sanitized)])
    sanitizer = run("sanitize-test", [str(sanitized)], dict(os.environ,
                    ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
    native = ["-std=c++11", "-Os", "-Wall", "-Wextra", "-Werror", "-Isrc", "-march=i486",
              "-mno-sse", "-mno-sse2", "-mno-mmx", "-fno-exceptions", "-fno-rtti",
              "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe"]
    obj = build / "M98AUTO.OBJ"
    archive = build / "libm98automation.a"
    guest = build / "M98AUTPR.EXE"
    run("native-adapter", ["i686-w64-mingw32-g++"] + native
        + ["-c", "src/m98_trident_automation.cpp", "-o", str(obj)])
    memory = build / "memory.o"
    run("native-memory", ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-march=i486",
        "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-c",
        "platform/freestanding/memory.c", "-o", str(memory)])
    run("native-archive", ["i686-w64-mingw32-ar", "rcsD", str(archive), str(obj), str(memory)])
    run("native-fixture", ["i686-w64-mingw32-g++"] + native + ["-nostdlib",
        "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,windows:4.10",
        "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
        "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
        "-Wl,--no-insert-timestamp", "-Xlinker", "--stack", "-Xlinker", "2097152,524288",
        "tests/m98_trident_automation_guest.cpp", str(obj), str(memory),
        "-lkernel32", "-luser32", "-lole32", "-loleaut32", "-o", str(guest)])
    exports = json.loads((ROOT / SOURCES[-1]).read_text())["dlls"]
    with pefile.PE(str(guest)) as pe:
        header = pe.OPTIONAL_HEADER
        require(pe.FILE_HEADER.Machine == 0x14c and header.Magic == 0x10b, "x86 PE32 required")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and not pe.is_dll(), "deterministic EXE required")
        require((header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion) == (4, 10), "OS4.10 required")
        require(header.Subsystem == 2 and (header.MajorSubsystemVersion, header.MinorSubsystemVersion) == (4, 10), "GUI4.10 required")
        require(header.AddressOfEntryPoint != 0, "entrypoint missing")
        require(not header.DllCharacteristics & (0x40 | 0x100 | 0x8000), "modern loader flags present")
        require(header.SizeOfStackReserve == 2097152 and header.SizeOfStackCommit == 524288, "native stack bounds mismatch")
        require(header.DATA_DIRECTORY[5].VirtualAddress != 0 and not pe.FILE_HEADER.Characteristics & 1, "relocations required")
        require(all(not header.DATA_DIRECTORY[index].VirtualAddress for index in (9, 10, 13, 14)), "unsupported PE directory")
        imports = {}
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            name = module.dll.decode().upper()
            require(name in {"KERNEL32.DLL", "USER32.DLL", "OLE32.DLL", "OLEAUT32.DLL"}, f"unexpected import module {name}")
            names = [row.name.decode() if row.name else f"#{row.ordinal}" for row in module.imports]
            require(set(names) <= set(exports[name]), f"non-OEM imports {name}: {set(names) - set(exports[name])}")
            imports[name] = sorted(names)
        require(not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"), "fixture has unexpected exports")
    require(hashes == {name: digest(ROOT / name) for name in SOURCES}, "source drift during build")
    for name in SOURCES:
        destination = build / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
        require(digest(destination) == hashes[name], f"snapshot mismatch {name}")
    artifacts = {path.name: {"sha256": digest(path), "size": path.stat().st_size}
                 for path in (obj, archive, guest)}
    artifacts[guest.name].update(pe98_gate="pass", imports=imports,
        stack_reserve=2097152, stack_commit=524288, adapter="statically embedded")
    receipt = {"schema": 1, "kind": "genuine-mshtml-automation-component-build",
        "passed": True, "source_sha256": hashes, "host": normal, "sanitizer": sanitizer,
        "steps": steps, "artifacts": artifacts, "runtime_dependency": "M98QJS.DLL; frozen staging required separately",
        "native_mshtml_execution": False, "native_visual_input": False,
        "standard_browser_integration": False, "html5_layout_wasm": False,
        "modern_app_operation": False, "vm_operations": False}
    path = build / "result.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(normal)
    print(sanitizer)
    print("PASS: OEM import/GUI PE32 4.10 fixture gate; native MSHTML and runtime trial pending")
    print(path)

if __name__ == "__main__":
    main()
