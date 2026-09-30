#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/test the opt-in provider; never install it or start a Windows guest."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/theme-engine"
SOURCES = ["src/uxtheme_engine_core.c", "src/uxtheme_engine_core.h",
           "src/uxtheme_engine_win32.c", "src/uxtheme_engine.def", "src/uxtheme_sysfont.c",
           "ntwddm/src/nttheme.c", "ntwddm/src/ntstyle.c", "ntwddm/include/nttheme.h",
           "ntwddm/include/ntwddm.h", "platform/freestanding/memory.c",
           "platform/freestanding/memory.h", "benchmarks/win98se-ko-oem-native-exports-v1.json",
           "tests/uxtheme_engine_host.c", "tests/uxtheme_engine_guest.c",
           "tools/build_theme_engine.py"]
STDCALL_BYTES = {
    "M98SetThemeStyle": 4, "M98GetThemeStyle": 0, "OpenThemeData": 8,
    "CloseThemeData": 4, "IsThemeActive": 0, "IsAppThemed": 0,
    "GetWindowTheme": 4, "SetWindowTheme": 12, "GetThemeAppProperties": 0,
    "SetThemeAppProperties": 4, "IsThemePartDefined": 12,
    "IsThemeBackgroundPartiallyTransparent": 12, "DrawThemeBackground": 24,
    "DrawThemeText": 36, "DrawThemeTextEx": 36, "GetThemeColor": 20,
    "GetThemeInt": 20, "GetThemeEnumValue": 20, "GetThemeMargins": 28,
    "GetThemeBackgroundContentRect": 24, "GetThemeFont": 24, "GetThemeSysFont": 12,
}

def run(command):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()

def pe_gate(path, dll):
    native = json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        header = pe.OPTIONAL_HEADER
        assert pe.FILE_HEADER.Machine == 0x14c and header.Magic == 0x10b
        assert pe.FILE_HEADER.TimeDateStamp == 0
        assert pe.is_dll() == dll
        assert (header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion) == (4, 10)
        assert header.Subsystem == 2 and header.AddressOfEntryPoint
        assert (header.MajorSubsystemVersion, header.MinorSubsystemVersion) == (4, 10)
        assert not header.DllCharacteristics & (0x40 | 0x100 | 0x8000)
        assert header.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics & 1
        for index in (9, 10, 13, 14):
            assert not header.DATA_DIRECTORY[index].VirtualAddress, index
        imports = {}
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            module = entry.dll.decode().upper()
            if module == "M98THEME.DLL" and not dll:
                names = [x.name.decode() for x in entry.imports]
                assert not any(x.ordinal is not None for x in entry.imports)
                with pefile.PE(str(BUILD / "M98THEME.DLL")) as provider:
                    available = {x.name.decode() for x in provider.DIRECTORY_ENTRY_EXPORT.symbols}
                assert set(names) <= available
                imports[module] = sorted(names)
                continue
            assert module in {"KERNEL32.DLL", "USER32.DLL", "GDI32.DLL"}, module
            names = [x.name.decode() if x.name else f"#{x.ordinal}" for x in entry.imports]
            assert set(names) <= set(native[module]), (module, set(names) - set(native[module]))
            imports[module] = sorted(names)
        exports = []
        if dll:
            exports = sorted(x.name.decode() for x in pe.DIRECTORY_ENTRY_EXPORT.symbols)
            expected = sorted(line.strip().split("=")[0] for line in
                              (ROOT / "src/uxtheme_engine.def").read_text().splitlines()[2:])
            assert exports == expected
        return {"imports": imports, "exports": exports, "pe98_gate": "pass"}

def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / "result.json"
    receipt.unlink(missing_ok=True)
    source_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}
    core = ["src/uxtheme_engine_core.c", "ntwddm/src/nttheme.c", "ntwddm/src/ntstyle.c"]
    includes = ["-Isrc", "-Intwddm/include"]
    host = BUILD / "theme-host"
    common = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"] + includes
    run(["clang"] + common + core + ["tests/uxtheme_engine_host.c", "-o", str(host)])
    host_result = run([str(host)])
    sanitized = BUILD / "theme-host-sanitize"
    run(["clang"] + common + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] +
        core + ["tests/uxtheme_engine_host.c", "-o", str(sanitized)])
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    sanitizer_result = subprocess.run([str(sanitized)], cwd=ROOT, env=env, text=True,
                                      capture_output=True, check=True, timeout=30).stdout.strip()
    native = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
              "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
              "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
              "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
              "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
              "-Wl,--no-insert-timestamp"] + includes
    dll = BUILD / "M98THEME.DLL"
    library = BUILD / "libM98THEME.a"
    run(native + ["-shared", "-Wl,--entry,_DllMain@12"] + core +
        ["src/uxtheme_engine_win32.c", "src/uxtheme_sysfont.c", "platform/freestanding/memory.c",
         "src/uxtheme_engine.def", "-lkernel32", "-luser32", "-lgdi32", "-o", str(dll)])
    # Public DLL exports are undecorated; i386 callers require stdcall-sized
    # linker symbols. --kill-at removes @N from the actual import names.
    import_def = BUILD / "uxtheme-engine-import.def"
    import_def.write_text("LIBRARY M98THEME.DLL\nEXPORTS\n" +
                          "\n".join(f" {name}@{size}" for name, size in STDCALL_BYTES.items()) + "\n")
    run(["i686-w64-mingw32-dlltool", "--input-def", str(import_def),
         "--output-lib", str(library), "--kill-at"])
    guest = BUILD / "M98THPRO.EXE"
    run(native + ["-Wl,--entry,_mainCRTStartup", "tests/uxtheme_engine_guest.c",
                  "-lkernel32", "-luser32", "-lgdi32", "-o", str(guest)])
    static_guest = BUILD / "M98THSTA.EXE"
    run(native + ["-DM98_THEME_STATIC", "-Wl,--entry,_mainCRTStartup", "tests/uxtheme_engine_guest.c",
                  str(library), "-lkernel32", "-luser32", "-lgdi32", "-o", str(static_guest)])
    artifacts = {}
    for path, is_dll in ((dll, True), (guest, False), (static_guest, False)):
        artifacts[path.name] = dict(pe_gate(path, is_dll),
                                   sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    assert "M98THEME.DLL" not in artifacts[guest.name]["imports"]
    assert "M98THEME.DLL" in artifacts[static_guest.name]["imports"]
    assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
               for name, digest in source_hashes.items()), "source changed while building"
    result = {"passed": True, "host": host_result, "sanitizer": sanitizer_result,
              "artifacts": artifacts, "source_sha256": source_hashes,
              "native_win98": "not_tested", "installation": "not_performed"}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(host_result)
    print(sanitizer_result)
    print("PASS: native PE32 4.10 import/export gates; Windows guest execution still required")
    print(receipt)

if __name__ == "__main__":
    main()
