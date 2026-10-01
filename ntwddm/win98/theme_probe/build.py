#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the shared theme engine and interactive probe; no install or VM launch."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = HERE / "build"
SOURCES = [
    "src/uxtheme_engine_core.c", "src/uxtheme_engine_core.h",
    "src/uxtheme_engine_win32.c", "src/uxtheme_engine.def", "src/uxtheme_sysfont.c",
    "ntwddm/src/nttheme.c", "ntwddm/src/ntstyle.c", "ntwddm/include/nttheme.h",
    "ntwddm/include/ntwddm.h", "platform/freestanding/memory.c",
    "platform/freestanding/memory.h", "tests/uxtheme_engine_host.c",
    "benchmarks/win98se-ko-oem-native-exports-v1.json",
    "ntwddm/win98/theme_probe/probe.c", "ntwddm/win98/theme_probe/build.py",
    "ntwddm/win98/theme_probe/verify.py", "ntwddm/win98/theme_probe/test_verify.py",
    "ntwddm/win98/theme_probe/observer.c", "ntwddm/win98/theme_probe/observer_mock.h",
    "ntwddm/win98/theme_probe/observer_mock_test.c",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def gate(path, is_dll):
    native = json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        header = pe.OPTIONAL_HEADER
        require(pe.FILE_HEADER.Machine == 0x14c and header.Magic == 0x10b, "expected i386 PE32")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and pe.is_dll() == is_dll, "wrong PE type/timestamp")
        require((header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion) == (4, 10), "OS version")
        require((header.MajorSubsystemVersion, header.MinorSubsystemVersion) == (4, 10), "subsystem version")
        require(header.Subsystem == 2 and header.AddressOfEntryPoint != 0, "GUI entry required")
        require(not header.DllCharacteristics & (0x40 | 0x100 | 0x8000), "modern PE flags")
        require(header.DATA_DIRECTORY[5].VirtualAddress != 0 and not pe.FILE_HEADER.Characteristics & 1,
                "relocations required")
        for index in (9, 10, 13, 14):
            require(not header.DATA_DIRECTORY[index].VirtualAddress, f"unsupported PE directory {index}")
        imports = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            module = entry.dll.decode("ascii").upper()
            require(module in {"KERNEL32.DLL", "USER32.DLL", "GDI32.DLL"}, f"unexpected import {module}")
            require(all(item.name is not None for item in entry.imports), "ordinal imports forbidden")
            names = sorted(item.name.decode("ascii") for item in entry.imports)
            require(set(names) <= set(native[module]), f"non-native {module} imports {set(names) - set(native[module])}")
            imports[module] = names
        require(bool(imports), "imports missing")
        exports = []
        if is_dll:
            symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
            require(all(item.name is not None for item in symbols), "unnamed export")
            exports = sorted(item.name.decode("ascii") for item in symbols)
            expected = sorted(line.strip().split("=")[0] for line in
                              (ROOT / "src/uxtheme_engine.def").read_text().splitlines()[2:] if line.strip())
            require(exports == expected, "provider exports differ from definition")
        return {"status": "PASS", "imports": imports, "exports": exports,
                "runtime_execution_verified": False}


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    latest = BUILD / "result.json"
    latest.unlink(missing_ok=True)
    run_dir = BUILD / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    run_dir.mkdir()
    hashes = {name: digest(ROOT / name) for name in SOURCES}
    commands = []

    def run(argv, env=None):
        completed = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
        item = {"argv": argv, "returncode": completed.returncode,
                "stdout": completed.stdout, "stderr": completed.stderr}
        commands.append(item)
        (run_dir / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        require(completed.returncode == 0, f"command failed: {argv}\n{completed.stdout}{completed.stderr}")
        return completed.stdout.strip()

    result = {"schema": 1, "status": "FAIL", "native_win98": "not_tested",
              "source_root": str(ROOT), "source_hashes": hashes, "run_dir": str(run_dir),
              "installation": "not_performed", "os_wide_theme_verified": False}
    try:
        versions = {name: run([name, "--version"]).splitlines()[0]
                    for name in ("clang", "i686-w64-mingw32-gcc")}
        core = ["src/uxtheme_engine_core.c", "ntwddm/src/nttheme.c", "ntwddm/src/ntstyle.c"]
        includes = ["-Isrc", "-Intwddm/include"]
        common = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"] + includes
        host_results = {}
        for kind, flags in (("host", []), ("sanitizer", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            executable = run_dir / ("theme-" + kind)
            run(["clang"] + common + flags + core + ["tests/uxtheme_engine_host.c", "-o", str(executable)])
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
            output = run([str(executable)], env)
            match = re.fullmatch(r"PASS: (\d+) theme lifecycle, pixel, state, query and allocation checks", output)
            require(match is not None and int(match[1]) > 0, f"unrecognized {kind} result: {output}")
            host_results[kind] = {"checks": int(match[1]), "output": output}
            observer_host = run_dir / ("observer-" + kind)
            run(["clang"] + common + flags + ["ntwddm/win98/theme_probe/observer_mock_test.c",
                                               "-o", str(observer_host)])
            observer_output = run([str(observer_host)], env)
            observer_match = re.fullmatch(r"PASS: (\d+) observer ownership, lifecycle, exit and log assertions",
                                         observer_output)
            require(observer_match is not None and int(observer_match[1]) > 0,
                    f"unrecognized observer {kind} result: {observer_output}")
            host_results["observer_" + kind] = {"checks": int(observer_match[1]), "output": observer_output}
        native = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
                  "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
                  "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
                  "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
                  "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
                  "-Wl,--no-insert-timestamp"] + includes
        dll, probe = run_dir / "M98THEME.DLL", run_dir / "NTTHGUI.EXE"
        run(native + ["-shared", "-Wl,--entry,_DllMain@12"] + core +
            ["src/uxtheme_engine_win32.c", "src/uxtheme_sysfont.c", "platform/freestanding/memory.c",
             "src/uxtheme_engine.def", "-lkernel32", "-luser32", "-lgdi32", "-o", str(dll)])
        run(native + ["-Wl,--entry,_mainCRTStartup", "ntwddm/win98/theme_probe/probe.c",
                      "platform/freestanding/memory.c", "-lkernel32", "-luser32", "-lgdi32", "-o", str(probe)])
        observer = run_dir / "NTTHRUN.EXE"
        run(native + ["-Wl,--entry,_mainCRTStartup", "ntwddm/win98/theme_probe/observer.c",
                      "platform/freestanding/memory.c", "-lkernel32", "-o", str(observer)])
        artifacts = {path.name: {"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size,
                                 "pe98_gate": gate(path, is_dll)}
                     for path, is_dll in ((dll, True), (probe, False), (observer, False))}
        require(all(digest(ROOT / name) == value for name, value in hashes.items()), "source changed during build")
        result.update(status="PASS", artifacts=artifacts, compiler_versions=versions, host_results=host_results)
    except Exception as error:
        result["error"] = str(error)
        (run_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        raise
    receipt = run_dir / "result.json"
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    latest.write_bytes(receipt.read_bytes())
    print(f"PASS: {host_results['host']['checks']} host checks and sanitizers; native PE32 gates")
    print(f"PASS: {host_results['observer_host']['checks']} observer lifecycle assertions and sanitizers")
    print(f"Windows 98 execution and visual review remain required. Receipt: {receipt}")
    print(f"Receipt SHA256: {digest(receipt)}")


if __name__ == "__main__":
    main()
