#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build isolated native Win98 COM Save dialog and probe; no guest/global changes.

python3 tools/build_file_dialog.py [--out build/native-file-dialog]
Builds do not execute either PE, register COM, install KernelEx or alter a VM.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import pefile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = ["src/m98_file_dialog.c", "src/m98_file_dialog.h", "src/m98_file_dialog.def",
           "tests/file_dialog_probe.c", "tools/build_file_dialog.py",
           "benchmarks/win98se-ko-oem-native-exports-v1.json"]
FLAGS = ["-std=c11", "-Os", "-march=i486", "-Wall", "-Wextra", "-Werror", "-fno-builtin",
         "-ffunction-sections", "-fdata-sections", "-nostdlib", "-Wl,--gc-sections",
         "-Wl,--major-image-version,4", "-Wl,--minor-image-version,10",
         "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
         "-Wl,--no-insert-timestamp"]
EXPORTS = {"DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer", "DllUnregisterServer"}
ALLOWED = {"KERNEL32.DLL", "USER32.DLL", "COMDLG32.DLL", "OLE32.DLL", "ADVAPI32.DLL"}


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def inspect(path, dll):
    """Fail closed on PE/version/directory/import/export issues against OEM bytes."""
    native = json.loads((ROOT / SOURCES[-1]).read_text())["dlls"]
    errors, imports = [], {}
    with pefile.PE(str(path)) as image:
        h = image.OPTIONAL_HEADER
        if image.FILE_HEADER.Machine != 0x14c or h.Magic != 0x10b or image.is_dll() != dll:
            errors.append("expected original x86 PE32 DLL" if dll else "expected original x86 PE32 EXE")
        if h.Subsystem != (2 if dll else 3) or (h.MajorSubsystemVersion, h.MinorSubsystemVersion) != (4, 10):
            errors.append("expected Win98 subsystem/version")
        if h.DllCharacteristics & (0x40 | 0x100 | 0x8000):
            errors.append("unexpected ASLR/NX/terminal-server flags")
        if not h.AddressOfEntryPoint or not image.get_section_by_rva(h.AddressOfEntryPoint):
            errors.append("missing bounded image entrypoint")
        for index, name in [(9, "TLS"), (13, "delay imports"), (14, "CLR")]:
            if h.DATA_DIRECTORY[index].VirtualAddress or h.DATA_DIRECTORY[index].Size:
                errors.append("unexpected " + name)
        if dll and (not h.DATA_DIRECTORY[5].VirtualAddress or image.FILE_HEADER.Characteristics & 1):
            errors.append("DLL requires real base relocations")
        for desc in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
            name = desc.dll.decode("ascii").upper()
            names = imports.setdefault(name, [])
            if name not in ALLOWED:
                errors.append("unexpected import DLL: " + name)
            for item in desc.imports:
                symbol = item.name.decode("ascii") if item.name else "#" + str(item.ordinal)
                names.append(symbol)
                if not item.name or symbol not in native.get(name, []):
                    errors.append("absent OEM-native import: " + name + "!" + symbol)
                if name == "COMDLG32.DLL" and symbol == "GetSaveFileNameW":
                    errors.append("Win98 Save As backend must use the real ANSI implementation")
        if not imports or (dll and "COMDLG32.DLL" not in imports):
            errors.append("missing real native common-dialog backend")
        exports = {s.name.decode("ascii") for s in getattr(getattr(image, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) if s.name}
        if dll and exports != EXPORTS:
            errors.append("unexpected COM server export names")
        if not dll and exports:
            errors.append("unexpected probe exports")
    return errors, imports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "build/native-file-dialog")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "build"):
        parser.error("isolated output must be under this checkout's build directory")
    out.mkdir(parents=True, exist_ok=True)
    cc = shutil.which("i686-w64-mingw32-gcc")
    if not cc:
        raise SystemExit("BLOCKED: i686-w64-mingw32-gcc is absent; no host install attempted")
    before = {p: sha(ROOT / p) for p in SOURCES}
    commands = [
        [cc, *FLAGS, "-shared", "-Wl,--entry,_DllMain@12", "-Wl,--subsystem,windows:4.10",
         "-o", str(out / "M98FDLG.DLL"), str(ROOT / SOURCES[0]), str(ROOT / SOURCES[2]),
         "-lcomdlg32", "-luser32", "-lole32", "-ladvapi32", "-lkernel32", "-luuid"],
        [cc, *FLAGS, "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,console:4.10",
         "-o", str(out / "FDPROBE.EXE"), str(ROOT / SOURCES[3]),
         "-lole32", "-luser32", "-lkernel32", "-luuid"],
    ]
    for command in commands:
        subprocess.run(command, cwd=ROOT, check=True, timeout=120)
    if before != {p: sha(ROOT / p) for p in SOURCES}:
        raise SystemExit("FAIL: source changed during native provider build")
    artifacts = {}
    for filename, dll in [("M98FDLG.DLL", True), ("FDPROBE.EXE", False)]:
        errors, imports = inspect(out / filename, dll)
        if errors:
            raise SystemExit("FAIL: " + filename + ": " + "; ".join(errors))
        artifacts[filename] = {"sha256": sha(out / filename), "bytes": (out / filename).stat().st_size,
                               "oem_import_gate": "PASS", "imports": imports}
    receipt = {"schema": "m98.native-file-dialog.build.v1", "status": "BUILT-STATIC-GATES-PASS",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "sources_sha256": before,
               "compiler": {"path": cc, "sha256": sha(cc), "version": subprocess.check_output([cc, "--version"], text=True).splitlines()[0]},
               "commands": commands, "artifacts": artifacts, "native_execution": "NOT-RUN",
               "latest_npp_execution": "NOT-RUN", "guest_registry_changed": False}
    (out / "build-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "output": str(out), "artifacts": artifacts}, indent=2))


if __name__ == "__main__":
    main()
