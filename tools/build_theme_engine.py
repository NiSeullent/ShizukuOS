#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/test the opt-in provider; never install it or start a Windows guest."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import pefile
from i486_instruction_gate import scan

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/theme-engine"
STEPS = []
SOURCES = ["src/uxtheme_engine_core.c", "src/uxtheme_engine_core.h",
           "src/uxtheme_shizukuos_style.h", "src/uxtheme_shizukuos.ntth",
           "src/uxtheme_user_profile.c", "apps/shizukuos-appearance/main.c",
           "src/uxtheme_engine_win32.c", "src/uxtheme_engine.def", "src/uxtheme_sysfont.c",
           "ntwddm/src/nttheme.c", "ntwddm/src/ntstyle.c", "ntwddm/include/nttheme.h",
           "ntwddm/include/ntwddm.h", "platform/freestanding/memory.c",
           "platform/freestanding/memory.h", "benchmarks/win98se-ko-oem-native-exports-v1.json",
           "tests/uxtheme_engine_host.c", "tests/uxtheme_engine_guest.c",
           "tests/uxtheme_shizukuos_host.c", "tests/uxtheme_user_profile_host.c",
           "tests/uxtheme_profile_win32_mock.h",
           "tools/i486_instruction_gate.py", "tests/test_i486_instruction_gate.py",
           "tools/build_theme_engine.py"]
STDCALL_BYTES = {
    "M98SetThemeStyle": 4, "M98GetThemeStyle": 0, "OpenThemeData": 8,
    "ShizukuOSLoadUserTheme": 0, "ShizukuOSSaveUserTheme": 4,
    "CloseThemeData": 4, "IsThemeActive": 0, "IsAppThemed": 0,
    "GetWindowTheme": 4, "SetWindowTheme": 12, "GetThemeAppProperties": 0,
    "SetThemeAppProperties": 4, "IsThemePartDefined": 12,
    "IsThemeBackgroundPartiallyTransparent": 12, "DrawThemeBackground": 24,
    "DrawThemeText": 36, "DrawThemeTextEx": 36, "GetThemeColor": 20,
    "GetThemeInt": 20, "GetThemeEnumValue": 20, "GetThemeMargins": 28,
    "GetThemeBackgroundContentRect": 24, "GetThemeFont": 24, "GetThemeSysFont": 12,
}

def execute(command, *, env=None, timeout=60):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
    prefix = "step-" + str(len(STEPS) + 1).zfill(2)
    logs = {}
    for stream in ("stdout", "stderr"):
        data = getattr(result, stream).encode()
        name = prefix + "." + stream
        (BUILD / name).write_bytes(data)
        logs[stream] = {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    step = {"command": command, "returncode": result.returncode, "logs": logs}
    if env is not None:
        step["validation_environment"] = {key: env[key] for key in
            ("ASAN_OPTIONS", "UBSAN_OPTIONS", "PYTHONDONTWRITEBYTECODE") if key in env}
    STEPS.append(step)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command}\n{result.stdout}\n{result.stderr}")
    return result

def run(command, *, env=None, timeout=60):
    result = execute(command, env=env, timeout=timeout)
    return result.stdout.strip()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def pe_gate(path, dll):
    native = json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        header = pe.OPTIONAL_HEADER
        require(pe.FILE_HEADER.Machine == 0x14c and header.Magic == 0x10b, "PE32 i386 required")
        require(pe.FILE_HEADER.TimeDateStamp == 0, "non-reproducible PE timestamp")
        require(pe.is_dll() == dll, "unexpected DLL flag")
        require((header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion) == (4, 10),
                "Windows98 OS version required")
        require(header.Subsystem == 2 and header.AddressOfEntryPoint, "GUI entrypoint required")
        require((header.MajorSubsystemVersion, header.MinorSubsystemVersion) == (4, 10),
                "Windows98 subsystem version required")
        require(not header.DllCharacteristics & (0x40 | 0x100 | 0x8000), "unsupported modern flags")
        require(header.DATA_DIRECTORY[5].VirtualAddress and header.DATA_DIRECTORY[5].Size and
                not pe.FILE_HEADER.Characteristics & 1, "relocation directory required")
        for index in (9, 10, 13, 14):
            require(not header.DATA_DIRECTORY[index].VirtualAddress and
                    not header.DATA_DIRECTORY[index].Size, "unsupported directory " + str(index))
        imports = {}
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            module = entry.dll.decode().upper()
            if module == "M98THEME.DLL" and not dll:
                require(all(x.name and x.ordinal is None for x in entry.imports),
                        "theme import must be named")
                names = [x.name.decode() for x in entry.imports]
                with pefile.PE(str(BUILD / "M98THEME.DLL")) as provider:
                    available = {x.name.decode() for x in provider.DIRECTORY_ENTRY_EXPORT.symbols}
                require(set(names) <= available, "unresolved theme imports")
                imports[module] = sorted(names)
                continue
            require(module in {"KERNEL32.DLL", "USER32.DLL", "GDI32.DLL", "ADVAPI32.DLL"},
                    "unexpected import module " + module)
            names = [x.name.decode() if x.name else f"#{x.ordinal}" for x in entry.imports]
            require(set(names) <= set(native[module]),
                    "imports absent from pinned OEM: " + module + " " + str(set(names) - set(native[module])))
            imports[module] = sorted(names)
        exports = []
        if dll:
            exports = sorted(x.name.decode() for x in pe.DIRECTORY_ENTRY_EXPORT.symbols)
            expected = sorted(line.strip().split("=")[0] for line in
                              (ROOT / "src/uxtheme_engine.def").read_text().splitlines()[2:])
            require(exports == expected, "provider export ABI differs from .def")
        return {"imports": imports, "exports": exports, "pe98_gate": "pass"}

def main():
    global BUILD
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        help="Fresh directory under build/; preserves historical acceptance receipts")
    args = parser.parse_args()
    if args.output_dir is not None:
        BUILD = args.output_dir.resolve()
        if not BUILD.is_relative_to((ROOT / "build").resolve()):
            raise ValueError("--output-dir must be under this worktree's build directory")
    if BUILD.exists() and any(BUILD.iterdir()):
        raise ValueError("build output must be absent or empty; preserve previous evidence with --output-dir")
    reserve = 20 * 1024**3
    budget = 32 * 1024**2
    if shutil.disk_usage(ROOT).free < reserve + budget:
        raise RuntimeError("insufficient free space for theme build and shared disk reserve")
    available = next(int(line.split()[1]) * 1024 for line in
                     Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    if available < 6 * 1024**3:
        raise RuntimeError("insufficient available memory for bounded theme build")
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / "result.json"
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
    sanitizer_result = run([str(sanitized)], env=env, timeout=30)
    additional_host = {}
    fixtures = [
        ("shizukuos-style", core + ["tests/uxtheme_shizukuos_host.c"], []),
        ("user-profile", ["src/uxtheme_user_profile.c", "tests/uxtheme_user_profile_host.c"],
         ["-DM98_PROFILE_HOST", "-Itests"]),
    ]
    for name, sources, options in fixtures:
        fixture = BUILD / (name + "-host")
        run(["clang"] + common + options + sources + ["-o", str(fixture)])
        plain = run([str(fixture)])
        sanitizer = BUILD / (name + "-sanitize")
        run(["clang"] + common + options + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] +
            sources + ["-o", str(sanitizer)])
        checked = run([str(sanitizer)], env=env, timeout=30)
        additional_host[name] = {"host": plain, "sanitizer": checked}
    native = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
              "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
              "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
              "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
              "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
              "-Wl,--no-insert-timestamp"] + includes
    dll = BUILD / "M98THEME.DLL"
    library = BUILD / "libM98THEME.a"
    run(native + ["-shared", "-Wl,--entry,_DllMain@12"] + core +
        ["src/uxtheme_engine_win32.c", "src/uxtheme_user_profile.c", "src/uxtheme_sysfont.c",
         "platform/freestanding/memory.c", "src/uxtheme_engine.def", "-lkernel32", "-luser32",
         "-lgdi32", "-ladvapi32", "-o", str(dll)])
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
    appearance = BUILD / "SHZAPPEAR.EXE"
    run(native + ["-Wl,--entry,_mainCRTStartup", "apps/shizukuos-appearance/main.c",
                  "platform/freestanding/memory.c", "-lkernel32", "-luser32", "-lgdi32",
                  "-o", str(appearance)])
    artifacts = {}
    controls_command = ["python3", "tests/test_i486_instruction_gate.py", "-v"]
    controls = execute(controls_command, timeout=30, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    controls_log = controls.stdout + controls.stderr
    (BUILD / "i486-controls.log").write_text(controls_log)
    require(controls.returncode == 0, "i486 parser controls failed: " + controls_log)
    for path, is_dll in ((dll, True), (guest, False), (static_guest, False), (appearance, False)):
        cpu, disassembly = scan(path)
        (BUILD / (path.name + ".i486.log")).write_bytes(disassembly)
        artifacts[path.name] = dict(pe_gate(path, is_dll),
                                   sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                   bytes=path.stat().st_size, i486=cpu)
    require("M98THEME.DLL" not in artifacts[guest.name]["imports"], "direct probe imports provider")
    require("M98THEME.DLL" in artifacts[static_guest.name]["imports"], "static probe lacks provider import")
    require("M98THEME.DLL" not in artifacts[appearance.name]["imports"], "appearance requires dynamic provider")
    require(set(STDCALL_BYTES) == set(artifacts[dll.name]["exports"]), "stdcall import table mismatch")
    require(all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
                for name, digest in source_hashes.items()), "source changed while building")
    actual_bytes = sum(p.stat().st_size for p in BUILD.rglob("*") if p.is_file())
    require(actual_bytes < budget, "theme build exceeded its admitted output budget")
    result = {"passed": True, "host": host_result, "sanitizer": sanitizer_result,
              "steps": STEPS,
              "additional_host": additional_host,
              "cpu_controls": {"command": controls_command, "returncode": controls.returncode,
                               "log": "i486-controls.log",
                               "sha256": hashlib.sha256(controls_log.encode()).hexdigest()},
              "artifacts": artifacts, "source_sha256": source_hashes,
              "theme_profile": {"registry_key": "HKCU\\Software\\ShizukuOS\\Appearance",
                                "value": "ThemeStyle REG_DWORD", "styles": [1, 3], "default": 3},
              "native_win98": "not_tested", "native_gui": "not_tested",
              "registry_validation": "production code with mocked Win32 registry APIs",
              "os_wide_theme": "not_installed", "installation": "not_performed"}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(host_result)
    print(sanitizer_result)
    for result in additional_host.values():
        print(result["host"])
        print(result["sanitizer"])
    print("PASS: PE32 4.10 OEM import/export and full executable-byte i486 gates; Windows guest execution still required")
    print(receipt)

if __name__ == "__main__":
    main()
