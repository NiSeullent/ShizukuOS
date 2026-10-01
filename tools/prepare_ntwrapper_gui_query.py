#!/usr/bin/env python3
"""Rebuild the frozen production query with only the linker subsystem changed.

This additive candidate never changes the original query/driver/preparer, starts
a VM, or interprets a host build as native execution.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import datetime
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

import pefile

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "build/ntwrapper-production-native-inputs-20260930T2315-v3/manifest.json"
ORIGINAL_SHA = "1defebed03f0d2fc06f0721d2efca990df75fda3ecf0a1421c4fc7fd58203be3"
PROFILE = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
PROFILE_SHA = "3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d"
PRODUCER = ROOT / "build/shizukudos/ntwrapper-vxd-shared-nonresident/manifest.json"
PRODUCER_SHA = "d715b09064df8a7f4c0ea66adab89cf2a731d3842a7eb745e06aadf01dbeed22"
CC_SHA = "b1425bcad9b5034ec95b342e47678ea9f1cee882e3376c57e440892b5ef91d46"
QUERY_SHA = "7f8abf3e15d2d7838d921e0aed1e9efb0efd9d7a2d243f968b7b5eca5f71ddb0"
PROJECT_SOURCES = ("ntwrapper/vxd/query_probe.c", "ntwrapper/vxd/bridge.h",
                   "ntwrapper/include/ntwrapper.h", "ntwrapper/vxd/build.py")
EXPECTED_IMPORTS = {"CloseHandle", "CreateFileA", "DeviceIoControl", "ExitProcess",
                    "FlushFileBuffers", "GetLastError", "WriteFile"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def profile(path, subsystem):
    exports = json.loads(PROFILE.read_text())["dlls"]
    with pefile.PE(str(path)) as pe:
        opt = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem, opt.MajorSubsystemVersion,
                opt.MinorSubsystemVersion, opt.MajorOperatingSystemVersion,
                opt.MinorOperatingSystemVersion, opt.AddressOfEntryPoint) != (
                    0x14c, 0x10b, subsystem, 4, 10, 4, 10, 0x118c):
            raise ValueError("Query classic Win98 PE profile/entry changed")
        if pe.FILE_HEADER.Characteristics & 0x2000 or opt.DllCharacteristics:
            raise ValueError("Query executable/modern DLL flags changed")
        if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (0, 2, 9, 10, 13, 14)):
            raise ValueError("Query needs unexpected export/resource/TLS/modern runtime state")
        imports = {}
        for desc in pe.DIRECTORY_ENTRY_IMPORT:
            dll = desc.dll.decode("ascii").upper()
            names = [i.name.decode("ascii") if i.name else "#" + str(i.ordinal) for i in desc.imports]
            if dll != "KERNEL32.DLL" or set(names) != EXPECTED_IMPORTS or set(names) - set(exports[dll]):
                raise ValueError("Exact original query import/OEM availability gate failed")
            imports[dll] = names
        if set(imports) != {"KERNEL32.DLL"} or not pe.verify_checksum():
            raise ValueError("Query import/checksum invalid")
        return {"machine": pe.FILE_HEADER.Machine, "subsystem": opt.Subsystem,
                "os_version": [opt.MajorOperatingSystemVersion, opt.MinorOperatingSystemVersion],
                "subsystem_version": [opt.MajorSubsystemVersion, opt.MinorSubsystemVersion],
                "entry_rva": opt.AddressOfEntryPoint, "image_bytes": opt.SizeOfImage,
                "native_imports": imports, "oem_gate": "PASS", "checksum_valid": True,
                "sections": [{"name": s.Name.rstrip(b"\0").decode("ascii"),
                              "raw_sha256": hashlib.sha256(s.get_data()).hexdigest()}
                             for s in pe.sections]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    cc = shutil.which("i686-w64-mingw32-gcc")
    if out.exists() or out == ROOT / "build" or not out.is_relative_to(ROOT / "build") or not cc:
        parser.error("Fresh isolated project build directory and existing compiler required")
    for path, pin in ((ORIGINAL, ORIGINAL_SHA), (PROFILE, PROFILE_SHA), (PRODUCER, PRODUCER_SHA), (Path(cc), CC_SHA)):
        if sha(path) != pin:
            parser.error("Pinned original input/compiler changed: " + str(path))
    original = json.loads(ORIGINAL.read_text())
    producer = json.loads(PRODUCER.read_text())
    if original["kind"] != "isolated-guest-file-inputs" or len(original["inputs"]) != 5:
        parser.error("Exact original five-input shape changed")
    pins = {str(ORIGINAL): ORIGINAL_SHA, str(PROFILE): PROFILE_SHA, str(PRODUCER): PRODUCER_SHA,
            cc: CC_SHA, str(Path(__file__).resolve()): sha(Path(__file__))}
    for name in PROJECT_SOURCES:
        pins[str(ROOT / name)] = producer["sources"][name]
    for item in original["inputs"]:
        path = Path(item["source"]).resolve(strict=True)
        if not path.is_relative_to(ORIGINAL.parent) or path.stat().st_size != item["bytes"]:
            parser.error("Original input path/size changed")
        pins[str(path)] = item["sha256"]
    for item in original["source_receipts"]:
        pins[item["path"]] = item["sha256"]
    if next(i["sha256"] for i in original["inputs"] if i["guest"] == "C:\\VXDLAB\\NTWQUERY.EXE") != QUERY_SHA:
        parser.error("Original query pin changed")
    holds = []
    for name, pin in pins.items():
        handle = Path(name).open("rb")
        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
        holds.append(handle)
        if sha(name) != pin:
            parser.error("Held source differs: " + name)
    out.mkdir(parents=True)
    for name in PROJECT_SOURCES + ("benchmarks/win98se-ko-oem-native-exports-v1.json", "tools/prepare_ntwrapper_gui_query.py"):
        target = out / "frozen" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    frozen = out / "frozen/ntwrapper/vxd/query_probe.c"
    control = out / "original-cui-control/NTWQUERY.EXE"
    control.parent.mkdir()
    flags = [cc, "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-march=i486",
             "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-nostdlib"]
    tail = ["-Wl,--major-os-version,4", "-Wl,--minor-os-version,10", "-Wl,--disable-dynamicbase",
            "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
            "-Wl,--entry,_mainCRTStartup", str(frozen)]
    commands = [flags + ["-Wl,--subsystem,console:4.10"] + tail + ["-o", str(control), "-lkernel32"],
                flags + ["-Wl,--subsystem,windows:4.10"] + tail + ["-o", str(out / "NTWQUERY.EXE"), "-lkernel32"]]
    result = {"schema": "win98modern.production-vxd-gui-query-preparation.v1", "status": "FAIL",
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "sources": pins,
              "commands": commands, "source_changed": False, "driver_changed": False,
              "query_code_changed": False, "native_executed": False, "application_executed": False,
              "scope": "Exact original production query rebuilt with only linker subsystem console->windows. No native acceptance.",
              "original_manifest": {"path": str(ORIGINAL), "sha256": ORIGINAL_SHA}}
    try:
        for i, command in enumerate(commands):
            build = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
            (out / f"compile-{i}.log").write_text(build.stdout + build.stderr)
            if build.returncode:
                raise ValueError("Compiler failed: " + str(i))
        if sha(control) != QUERY_SHA:
            raise ValueError("Same frozen source/options did not exactly reproduce original console query")
        result["original_cui_control"] = {"path": str(control), "sha256": sha(control), "exact_original_match": True,
                                          "profile": profile(control, 3)}
        gui = out / "NTWQUERY.EXE"
        result["gui_query"] = {"path": str(gui), "sha256": sha(gui), "bytes": gui.stat().st_size,
                               "profile": profile(gui, 2)}
        old, new = control.read_bytes(), gui.read_bytes()
        pe_offset = struct.unpack_from("<I", old, 60)[0]
        optional = pe_offset + 24
        allowed = set(range(optional + 64, optional + 68)) | set(range(optional + 68, optional + 70))
        # GNU ld also emits an absolute COFF __subsystem__ symbol. Validate its
        # exact name/kind/value, rather than accepting arbitrary symbol changes.
        symbol_offset, symbol_count = struct.unpack_from("<II", old, pe_offset + 12)
        strings = symbol_offset + symbol_count * 18
        subsystem_symbols = []
        index = 0
        while index < symbol_count:
            offset = symbol_offset + index * 18
            record = old[offset:offset + 18]
            if record[:4] == bytes(4):
                start = strings + struct.unpack_from("<I", record, 4)[0]
                end = old.index(b"\0", start)
                name = old[start:end]
            else:
                name = record[:8].rstrip(b"\0")
            if name == b"__subsystem__":
                if (struct.unpack_from("<IhHBB", old, offset + 8) != (3, -1, 0, 2, 0) or
                        struct.unpack_from("<IhHBB", new, offset + 8) != (2, -1, 0, 2, 0)):
                    raise ValueError("Linker absolute COFF subsystem symbol changed unexpectedly")
                allowed.update(range(offset + 8, offset + 12))
                subsystem_symbols.append({"index": index, "value_offset": offset + 8,
                                          "name": "__subsystem__", "before": 3, "after": 2,
                                          "kind": "external absolute COFF symbol"})
            index += 1 + record[17]
        if len(subsystem_symbols) != 1:
            raise ValueError("Expected exactly one linker absolute subsystem symbol")
        differences = [i for i, (a, b) in enumerate(zip(old, new)) if a != b]
        if len(old) != len(new) or not differences or set(differences) - allowed:
            raise ValueError("GUI binary changed beyond linker subsystem/checksum/absolute subsystem symbol")
        if result["original_cui_control"]["profile"]["sections"] != result["gui_query"]["profile"]["sections"]:
            raise ValueError("Query executable/data/import/relocation section bytes changed")
        result["binary_comparison"] = {"equal_length": True, "only_subsystem_checksum_and_absolute_coff_subsystem_symbol_changed": True,
                                       "differing_offsets": differences, "binary_header_patch_used": False,
                                       "absolute_subsystem_symbols": subsystem_symbols,
                                       "all_section_raw_bytes_identical": True, "comparison_is_read_only": True}
        for item in original["inputs"]:
            name = Path(item["source"]).name
            if name != "NTWQUERY.EXE":
                shutil.copyfile(item["source"], out / name)
                if sha(out / name) != item["sha256"]:
                    raise ValueError("Unchanged driver/loader/observer copy differs")
        if any(sha(path) != pin for path, pin in pins.items()):
            raise ValueError("Held input changed during build")
        result["original_sources_unchanged"] = True
        result["status"] = "HOST_BUILD_PASS_NATIVE_PENDING"
    except Exception as error:
        result["error"] = str(error)
    finally:
        for handle in holds:
            handle.close()
        write(out / "gui-query-build-result.json", result)
    if result["status"] != "HOST_BUILD_PASS_NATIVE_PENDING":
        print(json.dumps({"status": result["status"], "error": result.get("error")}))
        return 1
    manifest = dict(original)
    manifest["inputs"] = [{"source": str(out / Path(i["source"]).name), "guest": i["guest"],
                           "bytes": (out / Path(i["source"]).name).stat().st_size,
                           "sha256": sha(out / Path(i["source"]).name)} for i in original["inputs"]]
    manifest["source_receipts"] = original["source_receipts"] + [
        {"path": str(ORIGINAL), "sha256": ORIGINAL_SHA},
        {"path": str(out / "gui-query-build-result.json"), "sha256": sha(out / "gui-query-build-result.json")}]
    manifest["commands"] = ["C:\\VXDLAB\\NTWOUT.EXE"]
    manifest["scope"] = "Direct Windows GUI-subsystem query -> original production VxD version/event/errors/two load/unload cycles. Only query linker subsystem changed; no DOS/fullscreen step or modern app/bridge claim. Outer observes inner/query actual OS exits; outer own OS exit remains unproved."
    write(out / "manifest.json", manifest)
    print(json.dumps({"status": result["status"], "manifest": str(out / "manifest.json"),
                      "manifest_sha256": sha(out / "manifest.json"), "input_bytes": sum(i["bytes"] for i in manifest["inputs"]),
                      "query_sha256": result["gui_query"]["sha256"], "native_executed": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
