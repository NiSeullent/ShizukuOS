#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a bounded genuine numeric WAMR child observer; launch nothing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import pefile
from i486_instruction_gate import scan

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ["tests/m98_wasm_guest_runner.c", "tests/m98_wasm_guest_runner_mock.c",
           "tests/m98_tls13_guest_runner_mock.h", "tools/build_wasm_guest_runner.py",
           "tools/i486_instruction_gate.py", "tests/test_i486_instruction_gate.py",
           "docs/TRIDENT_WASM_NATIVE_OBSERVER.md",
           "benchmarks/win98se-ko-oem-native-exports-v1.json"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.nonce), "invalid frozen nonce")
    build = args.build_dir.absolute()
    require(build.resolve() == build and build.parent == ROOT / "build" and not build.exists(),
            "select a fresh directory in the owned build tree")
    hashes = {name: digest(ROOT / name) for name in SOURCES}
    build.mkdir(parents=True)
    steps, artifacts, profiles = [], {}, {}

    def run(name, command, env=None):
        result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                capture_output=True, timeout=60)
        log = build / (name + ".txt")
        log.write_text(result.stdout + result.stderr)
        steps.append(dict(name=name, command=command, returncode=result.returncode,
                          log=str(log), sha256=digest(log)))
        require(result.returncode == 0, name + " failed; see " + str(log))
        return result.stdout.strip()

    native_exports = json.loads((ROOT / SOURCES[-1]).read_text())["dlls"]["KERNEL32.DLL"]
    common = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
    for stem, child, child_log, milliseconds in (("M98WARUN", "WAS13PR", "WA13", 60000),):
        label = "wasm"
        host = build / (label + "-host")
        sanitized = build / (label + "-sanitize")
        sources = ["tests/m98_wasm_guest_runner_mock.c"]
        run(label + "-host-build", ["clang"] + common + sources + ["-o", str(host)])
        normal = run(label + "-host-test", [str(host)])
        run(label + "-sanitize-build", ["clang"] + common + [
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer"] + sources + ["-o", str(sanitized)])
        sanitizer = run(label + "-sanitize-test", [str(sanitized)], dict(os.environ,
            ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
        artifact = build / (stem + ".EXE")
        run(label + "-native-build", ["i686-w64-mingw32-gcc", "-std=c11", "-Os",
            "-Wall", "-Wextra", "-Werror", "-march=i486", "-mno-sse", "-mno-sse2",
            "-mno-mmx", "-msoft-float", "-fno-builtin", "-fno-stack-protector",
            "-mno-stack-arg-probe", "-nostdlib", "-Wl,--entry,_mainCRTStartup",
            "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
            "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
            "-Wl,--no-insert-timestamp", "-Xlinker", "--stack", "-Xlinker", "2097152,65536",
            '-DM98_RUN_NONCE="' + args.nonce + '"',
            "tests/m98_wasm_guest_runner.c", "-lkernel32", "-o", str(artifact)])
        require(0 < artifact.stat().st_size <= 1024 ** 2, "observer exceeds guest input bound")
        gate, disassembly = scan(artifact)
        require(gate["instructions_decoded"] > 100, "empty/truncated disassembly")
        log = build / "wasm-full-disassembly.txt"
        log.write_bytes(disassembly)
        steps.append(dict(name="wasm-full-disassembly", command=gate["command"], returncode=0,
                          log=str(log), sha256=digest(log)))
        imports = {}
        with pefile.PE(str(artifact)) as pe:
            h = pe.OPTIONAL_HEADER
            require(pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b and not pe.is_dll(), "PE32 EXE required")
            require(pe.FILE_HEADER.TimeDateStamp == 0 and h.Subsystem == 2 and h.AddressOfEntryPoint, "deterministic GUI entry required")
            require((h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion) == (4, 10)
                    and (h.MajorSubsystemVersion, h.MinorSubsystemVersion) == (4, 10), "Win98 OS/subsystem required")
            require(not h.DllCharacteristics & (0x40 | 0x100 | 0x8000)
                    and not pe.FILE_HEADER.Characteristics & 1 and h.DATA_DIRECTORY[5].VirtualAddress,
                    "legacy relocation contract required")
            require(h.SizeOfStackReserve == 2097152 and h.SizeOfStackCommit == 65536, "stack bounds differ")
            require(all(not h.DATA_DIRECTORY[i].VirtualAddress and not h.DATA_DIRECTORY[i].Size
                        for i in (9, 10, 13, 14)), "unsupported PE directory")
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                name = module.dll.decode().upper()
                require(name == "KERNEL32.DLL" and all(row.name for row in module.imports), "native named Kernel32 imports required")
                names = sorted(row.name.decode() for row in module.imports)
                require(set(names) <= set(native_exports), "non-OEM native import")
                imports[name] = names
            require(imports and not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"), "unexpected import/export surface")
        artifacts[artifact.name] = dict(sha256=digest(artifact), bytes=artifact.stat().st_size,
            pe98_gate="pass", imports=imports, stack_reserve=2097152, stack_commit=65536,
            i486_instruction_gate="pass",
            i486_instructions=gate)
        prefix = "WA"
        profiles[label] = dict(host=normal, sanitizer=sanitizer,
            self="C:\\GOPLAB\\" + stem + ".EXE", supervisor_log="C:\\GOPLAB\\" + prefix + "RUN.LOG",
            child_stdout="C:\\GOPLAB\\" + prefix + "OUT.LOG",
            child="C:\\GOPLAB\\" + child + ".EXE", child_log="C:\\GOPLAB\\" + child_log + ".LOG",
            child_timeout_ms=milliseconds, reap_timeout_ms=5000)
        print(label + ": " + normal)
    require(hashes == {name: digest(ROOT / name) for name in SOURCES}, "source drift during build")
    for name in SOURCES:
        target = build / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        require(digest(target) == hashes[name], "source snapshot mismatch")
    result = dict(schema=1, kind="win98-wasm-owned-child-observer-build", passed=True,
        nonce=args.nonce, source_sha256=hashes, artifacts=artifacts, profiles=profiles, steps=steps,
        native_execution=False, native_numeric_execution=False, native_paint=False,
        actual_child_exit=False, full_modern_wasm=False, browser_webassembly=False, webgpu=False, webgl=False,
        full_web_standards=False, vm_operations=False,
        outer_exit_limit="requested supervisor result precedes final flush/close; actual supervisor exit needs an outer observer")
    receipt = build / "result.json"
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(receipt)


if __name__ == "__main__":
    main()
