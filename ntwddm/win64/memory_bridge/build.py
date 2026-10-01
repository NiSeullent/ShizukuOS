#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a private basic-memory KERNELBASE candidate; no VM or installation."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import uuid

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ADAPTERS = {"VirtualAlloc2", "MapViewOfFile3", "UnmapViewOfFile2"}
PEER_SOURCES = (
    "shizukudos/win64/kernel32/k32_mem.c", "shizukudos/win64/kernel32/k32_ipc_section.c",
    "shizukudos/win64/kernel32/k32_ipc_proc.c", "shizukudos/win64/kernel32/k32_misc.c",
    "shizukudos/kernel64/syscall.c", "shizukudos/kernel64/vad.c",
    "shizukudos/kernel64/ipc_section.c", "shizukudos/win64/ntdll/ntdll_main.c",
)
SOURCES = ["LICENSE"] + [str((HERE / n).relative_to(ROOT)) for n in
                           ("build.py", "bridge.h", "bridge.c", "host.c", "test_build.py", "README.md")]
IMPORTS = {"GetCurrentProcess", "GetProcessId", "GetLastError", "SetLastError", "GetSystemInfo",
           "VirtualAllocEx", "MapViewOfFileEx", "UnmapViewOfFile", "VirtualQuery"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    require(path.is_file() and not path.is_symlink(), f"regular input required: {path}")
    return path.read_bytes()


def parse_archive(raw):
    require(16 <= len(raw) <= 128 * 1024 * 1024 and raw[:8] == b"SHZARC01", "invalid/bounded archive")
    count, reserved = struct.unpack_from("<II", raw, 8)
    require(1 <= count <= 4096 and reserved == 0, "invalid archive count/reserved")
    header = 16 + 136 * count
    require(header <= len(raw), "truncated archive table")
    files, seen, spans = {}, {}, []
    for index in range(count):
        field, offset, size = struct.unpack_from("<120sQQ", raw, 16 + index * 136)
        require(b"\0" in field, "unterminated member name")
        name, padding = field.split(b"\0", 1)
        require(not any(padding), "invalid member padding")
        name = name.decode("ascii")
        require(name.startswith("\\") and not name.startswith("\\\\"), "unsafe member root")
        parts = name[1:].split("\\")
        require(all(p not in ("", ".", "..") and not p.endswith((".", " ")) and
                    not any(ord(c) < 32 or c in '/:*?<>|"' for c in p) for p in parts), "unsafe member path")
        for depth in range(1, len(parts) + 1):
            component = "\\" + "\\".join(parts[:depth])
            kind = "file" if depth == len(parts) else "directory"
            previous = seen.get(component.casefold())
            require(previous is None or previous == (component, kind) and kind == "directory", "member alias/collision")
            seen[component.casefold()] = (component, kind)
        require(offset >= header and offset % 16 == 0 and offset <= len(raw) and size <= len(raw) - offset,
                "invalid member extent")
        files[name] = raw[offset:offset + size]
        spans.append((offset, size))
    end = header
    for offset, size in sorted(spans):
        require(offset >= end and not any(raw[end:offset]), "overlap/nonzero alignment padding")
        end = offset + size
    require(end == len(raw), "archive trailing data")
    return files


def pe_exports(raw):
    with pefile.PE(data=raw) as pe:
        require(pe.is_dll() and pe.FILE_HEADER.Machine == 0x8664 and pe.OPTIONAL_HEADER.Magic == 0x20b,
                "AMD64 PE32+ DLL required")
        exports = {}
        for item in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            if item.name is None:
                continue
            name = item.name.decode("ascii")
            require(name not in exports and item.address != 0 and item.address < pe.OPTIONAL_HEADER.SizeOfImage,
                    "duplicate/null/out-of-image export")
            exports[name] = {"ordinal": item.ordinal, "rva": item.address,
                             "forwarder": item.forwarder.decode("ascii") if item.forwarder else None}
        require(exports, "DLL exports absent")
        return exports


def direct_forwarders(exports):
    result = {}
    for name, item in exports.items():
        if item["forwarder"] or name in ADAPTERS:
            continue
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,94}", name) is not None, "unsupported forwarder identifier")
        result[name] = "KERNEL32." + name
    return result


def gate(path, forwarders):
    with pefile.PE(str(path)) as pe:
        opt = pe.OPTIONAL_HEADER
        require(pe.is_dll() and pe.FILE_HEADER.Machine == 0x8664 and opt.Magic == 0x20b, "wrong candidate ABI")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and opt.AddressOfEntryPoint != 0 and opt.Subsystem == 2,
                "wrong timestamp/entry/subsystem")
        require(opt.DATA_DIRECTORY[5].VirtualAddress != 0, "relocations absent")
        require(all(not opt.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)), "unexpected CRT/TLS/delay/managed directory")
        imports = {}
        for module in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = module.dll.decode("ascii").upper()
            require(dll == "KERNEL32.DLL" and dll not in imports, "unexpected import module")
            require(all(entry.name for entry in module.imports), "ordinal import unsupported")
            imports[dll] = sorted(entry.name.decode("ascii") for entry in module.imports)
        require(imports == {"KERNEL32.DLL": sorted(IMPORTS)}, "unexpected adapter imports")
        exports = pe_exports(path.read_bytes())
        require(set(exports) == ADAPTERS | set(forwarders), "candidate export set drift")
        require(all(exports[name]["forwarder"] is None for name in ADAPTERS), "adapter unexpectedly forwarded")
        require(all(exports[name]["forwarder"] == target for name, target in forwarders.items()), "forwarder drift")
        require(pe.DIRECTORY_ENTRY_EXPORT.name.decode("ascii").upper() == "KERNELBASE.DLL", "wrong DLL identity")
        return {"status": "PASS", "machine": "AMD64", "format": "PE32+", "imports": imports,
                "exports": exports, "native_win98_loadable": False, "runtime_execution_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--peer-root", type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256) is not None, "lowercase SHA256 required")
    require(shutil.disk_usage(HERE).free >= 20 * 1024**3 + 256 * 1024**2, "20 GiB reserve plus build headroom required")
    run_dir = HERE / "build" / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    run_dir.mkdir(parents=True)
    hashes = {name: sha(regular(ROOT / name)) for name in SOURCES}
    result = {"schema": 1, "status": "FAIL", "source_root": str(ROOT), "source_hashes": hashes,
              "run_dir": str(run_dir), "installation": "not_performed", "vm_started": False,
              "kernel64_execution_verified": False, "signal_functionality_verified": False,
              "windows98_execution_verified": False, "os_wide_support_verified": False,
              "license": "GPL-2.0-only", "implementation_copied": False,
              "supported_subset": {"VirtualAlloc2": "Current pseudo/NULL process; no extended elements; basic commit/reserve/top-down and six basic private protections",
                                   "MapViewOfFile3": "Current pseudo/NULL process; no extended elements; allocation 0; six exact map protections; page size/alignment/offset validated",
                                   "UnmapViewOfFile2": "Current pseudo process; flags 0; exact allocation base of MEM_MAPPED view; real VirtualQuery and UnmapViewOfFile",
                                   "unsupported": "Real process handles; placeholders; extended parameters; large/physical pages; reset/write-watch; guard/cache/CFG; unmap hints; image/private unmap",
                                   "ownership": "Underlying endpoints own allocation, mapping, coherency, references and write-back; bridge owns no region or handle"},
              "abi_references": ["https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-" + name
                                 for name in ("virtualalloc2", "virtualallocex", "mapviewoffile3", "mapviewoffileex", "unmapviewoffile2", "unmapviewoffile")]}
    commands = []

    def run(argv, env=None):
        child = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        commands.append({"argv": argv, "returncode": child.returncode, "stdout": child.stdout, "stderr": child.stderr})
        (run_dir / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        require(child.returncode == 0, "build/test failed: " + " ".join(argv) + "\n" + child.stdout + child.stderr)
        return child.stdout.strip()

    try:
        archive = regular(args.archive)
        require(sha(archive) == args.archive_sha256, "archive hash mismatch")
        members = parse_archive(archive)
        require(not any(n.casefold().endswith("\\kernelbase.dll") for n in members), "baseline already contains Kernelbase")
        modules = {}
        for name, data in members.items():
            if name.casefold().startswith("\\shz\\sys64\\") and name.casefold().endswith(".dll"):
                key = name.rsplit("\\", 1)[1].upper()
                require(key not in modules, "duplicate runtime module")
                modules[key] = {"member": name, "sha256": sha(data), "bytes": len(data), "exports": pe_exports(data)}
        require("KERNEL32.DLL" in modules, "Kernel32 absent")
        original = modules["KERNEL32.DLL"]["exports"]
        require(all(name in original and original[name]["forwarder"] is None for name in IMPORTS), "real direct backing API absent")
        forwarded = direct_forwarders(original)
        peer_hashes = {name: sha(regular(args.peer_root / name)) for name in PEER_SOURCES}
        sources_dir = run_dir / "sources"
        for name in SOURCES:
            target = sources_dir / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(regular(ROOT / name))
        peer_dir = run_dir / "reviewed-consumer-source"
        for name in PEER_SOURCES:
            target = peer_dir / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(regular(args.peer_root / name))
        (run_dir / "WIN64-input.IMG").write_bytes(archive)
        definition = run_dir / "kernelbase.def"
        definition.write_text("LIBRARY KERNELBASE\nEXPORTS\n" + "".join(
            "    " + name + "=m98mb_" + name + "\n" for name in sorted(ADAPTERS)) + "".join(
            "    " + name + "=" + target + "\n" for name, target in sorted(forwarded.items())))
        versions = {name: run([name, "--version"]).splitlines()[0] for name in ("clang", "x86_64-w64-mingw32-gcc")}
        run(["python3", "-B", str(HERE / "test_build.py")])
        host = {}
        frozen = sources_dir / HERE.relative_to(ROOT)
        for kind, flags in (("host", []), ("sanitizer", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            executable = run_dir / ("memory-bridge-" + kind)
            run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"] + flags +
                [str(frozen / "bridge.c"), str(frozen / "host.c"), "-o", str(executable)])
            output = run([str(executable)], dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
            match = re.fullmatch(r"PASS: (\d+) basic-memory translation, failure, untouched-input and ownership assertions", output)
            require(match is not None, "unrecognized host result")
            host[kind] = {"checks": int(match[1]), "output": output, "guest_memory_semantics_verified": False}
        dll = run_dir / "KERNELBASE.DLL"
        run(["x86_64-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-fno-builtin",
             "-fno-stack-protector", "-mno-stack-arg-probe", "-mno-red-zone", "-nostdlib", "-shared",
             "-Wl,--entry,DllMain", "-Wl,--subsystem,windows:6.0", "-Wl,--major-os-version,6", "-Wl,--minor-os-version,0",
             "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
             str(frozen / "bridge.c"), str(definition), "-lkernel32", "-o", str(dll)])
        require(dll.stat().st_size <= 1024 * 1024, "candidate exceeds 1 MiB")
        pe_gate = gate(dll, forwarded)
        require(all(sha(regular(ROOT / name)) == value for name, value in hashes.items()), "own source changed")
        require(all(sha(regular(args.peer_root / name)) == value for name, value in peer_hashes.items()), "reviewed peer source changed")
        require(sha(regular(args.archive)) == args.archive_sha256, "original archive changed")
        require(shutil.disk_usage(HERE).free >= 20 * 1024**3, "20 GiB reserve lost")
        result.update(status="STATIC_CANDIDATE_READY_FOR_GUEST_TEST", structural_build_status="PASS", host_results=host,
                      compiler_versions=versions,
                      artifact={"path": str(dll), "sha256": sha(dll.read_bytes()), "bytes": dll.stat().st_size, "pe_gate": pe_gate},
                      runtime_archive={"path": str(args.archive.resolve()), "sha256": args.archive_sha256, "member_count": len(members),
                                       "dll_count": len(modules), "modules": modules, "original_unchanged": True},
                      runtime_import_coverage={"status": "STATIC_NAMES_PRESENT", "resolved": [{"dll": "KERNEL32.DLL", "name": name} for name in sorted(IMPORTS)],
                                               "unresolved": [], "abi_semantics_verified": False, "runtime_execution_verified": False},
                      forwarder_coverage={"status": "STATIC_NAMES_PRESENT", "count": len(forwarded), "direct_owner": "KERNEL32.DLL",
                                          "targets": forwarded, "kernelbase_ordinal_compatibility_verified": False, "runtime_execution_verified": False},
                      reviewed_consumer_sources={"root": str(args.peer_root.resolve()), "hashes": peer_hashes, "originals_unchanged": True,
                                                 "binary_source_identity_verified": False},
                      generated_definition={"path": str(definition), "sha256": sha(definition.read_bytes())},
                      compiler_inputs=[{"path": str(path), "sha256": sha(path.read_bytes())}
                                       for path in (frozen / "bridge.c", frozen / "bridge.h", definition)])
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        receipt = run_dir / "result.json"
        receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(result["status"] + ": " + str(receipt))
    print("Receipt SHA256: " + sha(receipt.read_bytes()))
    print("Host checks: " + str(result["host_results"]["host"]["checks"]) + "; direct Kernel32 forwarders: " + str(len(forwarded)))


if __name__ == "__main__":
    main()
