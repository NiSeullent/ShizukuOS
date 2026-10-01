#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and check the genuine Win98 palette selector; never install or boot it."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import uuid

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RESERVE = 20 * 1024**3
OUTPUT_LIMIT = 8 * 1024**2
SOURCES = (
    "ntwddm/win98/theme_selector/selector_core.h",
    "ntwddm/win98/theme_selector/selector_core.c",
    "ntwddm/win98/theme_selector/selector_win98.c",
    "ntwddm/win98/theme_selector/selector_core_test.c",
    "ntwddm/win98/theme_selector/build.py",
    "platform/freestanding/memory.c",
    "platform/freestanding/memory.h",
    "tests/test_win98_theme_selector_build.py",
    "benchmarks/win98se-ko-oem-native-exports-v1.json",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_gate(path, role="selector"):
    """Require genuine OEM imports, a legacy GUI entry and usable relocations."""
    require(role in {"selector", "observer"}, "unknown native component role")
    inventory = json.loads((ROOT / SOURCES[-1]).read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        header = pe.OPTIONAL_HEADER
        require(pe.FILE_HEADER.Machine == 0x14c and header.Magic == 0x10b,
                "selector must be i386 PE32")
        require(not pe.is_dll() and pe.FILE_HEADER.TimeDateStamp == 0,
                "selector must be a deterministic executable")
        require((header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion) == (4, 10),
                "incorrect Win98 OS version")
        require((header.MajorSubsystemVersion, header.MinorSubsystemVersion) == (4, 10)
                and header.Subsystem == 2 and header.AddressOfEntryPoint,
                "incorrect Win98 GUI entry")
        require(not header.DllCharacteristics & (0x40 | 0x100 | 0x8000),
                "unsupported modern PE flags")
        require(header.DATA_DIRECTORY[5].VirtualAddress and header.DATA_DIRECTORY[5].Size
                and not pe.FILE_HEADER.Characteristics & 1,
                "relocations required")
        require(any(item.type == 3 for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", [])
                    for item in block.entries), "actual i386 HIGHLOW relocation required")
        for index in (9, 10, 13, 14):
            require(not header.DATA_DIRECTORY[index].VirtualAddress,
                    f"unsupported PE directory {index}")
        imports = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            module = entry.dll.decode("ascii").upper()
            require(module in {"KERNEL32.DLL", "USER32.DLL", "GDI32.DLL", "ADVAPI32.DLL"},
                    f"unexpected dependency {module}")
            require(all(item.name is not None for item in entry.imports),
                    "ordinal imports forbidden")
            names = sorted(item.name.decode("ascii") for item in entry.imports)
            require(set(names) <= set(inventory[module]),
                    f"not present in OEM {module}: {set(names) - set(inventory[module])}")
            imports[module] = names
        require(imports, "native imports missing")
        if role == "selector":
            require("SetSysColors" in imports.get("USER32.DLL", []),
                    "actual system palette setter missing")
            require("RegSetValueExA" in imports.get("ADVAPI32.DLL", [])
                    and "RegQueryValueExA" in imports.get("ADVAPI32.DLL", []),
                    "native persistent profile access missing")
        else:
            all_names = {name for names in imports.values() for name in names}
            require(not all_names & {"SetSysColors", "RegSetValueExA", "RegSetValueExW",
                    "RegSetValueA", "RegSetValueW", "RegCreateKeyA", "RegCreateKeyW",
                    "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteValueA", "RegDeleteValueW",
                    "RegDeleteKeyA", "RegDeleteKeyW", "GetProcAddress", "LoadLibraryA",
                    "LoadLibraryW", "TerminateProcess"}, "observer imports a forbidden mutation/resolver")
            require(set(imports.get("ADVAPI32.DLL", [])) <=
                    {"RegOpenKeyExA", "RegQueryValueExA", "RegCloseKey"},
                    "observer registry imports must be read-only")
            require({"GetSysColor"} <= set(imports.get("USER32.DLL", []))
                    and "GetPixel" in imports.get("GDI32.DLL", [])
                    and "RegQueryValueExA" in imports.get("ADVAPI32.DLL", [])
                    and {"CreateProcessA", "WaitForSingleObject", "GetExitCodeProcess"}
                    <= set(imports.get("KERNEL32.DLL", [])),
                    "independent observer palette/pixel/profile/child APIs missing")
        return {"status": "PASS", "role": role, "imports": imports,
                "native_execution_verified": False}


def guard(directory=None, admission=False):
    free = shutil.disk_usage(ROOT).free
    required = RESERVE + (OUTPUT_LIMIT if admission else 0)
    require(free >= required, f"20 GiB reserve and admitted output required; available {free} bytes")
    used = 0
    if directory is not None:
        for path in directory.rglob("*"):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                    f"unsafe output path: {path}")
            if stat.S_ISREG(info.st_mode):
                used += info.st_size
        require(used <= OUTPUT_LIMIT, f"selector output limit exceeded: {used} bytes")
    return {"available_bytes": free, "reserve_bytes": RESERVE,
            "output_bytes": used, "output_limit_bytes": OUTPUT_LIMIT}


def finish_report(report, directory):
    """Account for the receipt itself, and never leave PASS after guard failure."""
    receipt = directory / "result.json"
    temporary = directory / "result.pending"
    resource = guard(directory)
    base_bytes = resource["output_bytes"]
    report["resource_guard"] = resource
    for _ in range(8):
        payload = (json.dumps(report, indent=2) + "\n").encode("utf-8")
        accounted = base_bytes + len(payload)
        if resource["output_bytes"] == accounted:
            break
        resource["output_bytes"] = accounted
    else:
        raise RuntimeError("receipt accounting did not converge")
    require(accounted <= OUTPUT_LIMIT, "receipt would exceed output limit")
    # Allow filesystem blocks and metadata for the new, small receipt as well.
    require(shutil.disk_usage(ROOT).free >= RESERVE + ((len(payload) + 4095) // 4096 + 4) * 4096,
            "receipt would cross the 20 GiB reserve")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
        os.replace(temporary, receipt)
        final = guard(directory)
        require(final["output_bytes"] == accounted, "final receipt accounting differs")
    except Exception:
        temporary.unlink(missing_ok=True)
        receipt.unlink(missing_ok=True)
        raise
    return receipt


def main():
    guard(admission=True)
    hashes = {name: digest(ROOT / name) for name in SOURCES}
    parent = ROOT / "build" / "win98-global-theme-selector"
    require(parent.absolute() == parent.resolve(), "symlinked output parent forbidden")
    parent.mkdir(parents=True, exist_ok=True)
    directory = parent / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
                          + uuid.uuid4().hex[:8])
    directory.mkdir(mode=0o700)
    commands = []
    report = {"schema": 1, "status": "FAIL", "source_hashes": hashes,
              "source_root": str(ROOT), "run_directory": str(directory),
              "installation_performed": False, "native_win98_execution": "not_tested",
              "os_wide_theme_verified": False, "cold_boot_persistence_verified": False}

    def run(argv, env=None):
        guard(directory)
        completed = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True,
                                   text=True, timeout=90)
        commands.append({"argv": argv, "exit_code": completed.returncode,
                         "stdout": completed.stdout[:16384], "stderr": completed.stderr[:16384]})
        (directory / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        guard(directory)
        require(completed.returncode == 0, f"command failed: {argv}; see commands.json")
        require(len(completed.stdout) <= 16384 and len(completed.stderr) <= 16384,
                "command output exceeded diagnostic bound")
        return completed.stdout.strip()

    try:
        run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_win98_theme_selector_build.py", "-v"])
        versions = {name: run([name, "--version"]).splitlines()[0]
                    for name in ("clang", "i686-w64-mingw32-gcc")}
        report["compiler_versions"] = versions
        core = str(HERE / "selector_core.c")
        tests = str(HERE / "selector_core_test.c")
        host = []
        report["host_tests"] = host
        for kind, flags in (("host", []),
                            ("sanitizer", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            binary = directory / kind
            run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
                + flags + [core, tests, "-o", str(binary)])
            # A failed sanitizer is a failed build; it is never downgraded to a warning.
            environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                               UBSAN_OPTIONS="halt_on_error=1")
            text = run([str(binary)], environment)
            require(text.startswith("PASS:"), "host test did not report its completed assertions")
            host.append({"kind": kind, "result": text})
        executable = directory / "SHZTHEME.EXE"
        run(["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
             "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
             "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
             "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,windows:4.10",
             "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
             "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
             "-Wl,--no-insert-timestamp", core, str(HERE / "selector_win98.c"),
             str(ROOT / "platform/freestanding/memory.c"),
             "-lkernel32", "-luser32", "-lgdi32", "-ladvapi32", "-o", str(executable)])
        gate = native_gate(executable)
        require(all(digest(ROOT / name) == value for name, value in hashes.items()),
                "sources changed during build")
        report.update(status="PASS", compiler_versions=versions, host_tests=host,
                      executable={"path": str(executable), "sha256": digest(executable),
                                  "bytes": executable.stat().st_size, "native_gate": gate})
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        receipt = finish_report(report, directory)
    print(f"PASS: selector host transactions, sanitizers and OEM PE32 imports; receipt {receipt}")
    print("Actual Win98 system repaint, rollback and cold-boot persistence remain required.")


if __name__ == "__main__":
    main()
