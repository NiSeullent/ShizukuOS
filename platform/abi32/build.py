#!/usr/bin/env python3
"""Run actual NTW32 PE32 code in an original static x86 Linux ABI harness.

No Windows loader or service emulation. All output remains in local build/.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / "build"
IMPORTS = {"Sleep", "GetTickCount", "GetModuleHandleA", "GetProcAddress", "SetLastError",
           "MultiByteToWideChar", "WideCharToMultiByte",
           # routing policy: NTW32.INI beside the DLL, NTW32_ROUTING, diagnostics
           "GetModuleFileNameA", "CreateFileA", "ReadFile", "CloseHandle",
           "GetEnvironmentVariableA", "OutputDebugStringA", "GetLastError"}
EXPORTS = {
    "InitializeSRWLock", "AcquireSRWLockExclusive", "AcquireSRWLockShared",
    "ReleaseSRWLockExclusive", "ReleaseSRWLockShared", "TryAcquireSRWLockExclusive",
    "TryAcquireSRWLockShared", "GetTickCount64", "GetProcAddress",
    "InitOnceInitialize", "InitOnceBeginInitialize", "InitOnceComplete", "InitOnceExecuteOnce",
    "MultiByteToWideChar", "WideCharToMultiByte",
    "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler",
}


def parser_module():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("abi32_prepare", ROOT / "ntwin32/prepare.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load original project PE parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def inspect(data):
    pe = parser_module().PE(data)
    size = pe.u32(pe.opt + 56)
    preferred = pe.u32(pe.opt + 28)
    entry = pe.u32(pe.opt + 16)
    if not 0 < size <= 16 * 1024 * 1024 or preferred != 0x68000000:
        raise ValueError("Unexpected or excessive DLL image size/base")
    if not pe.u16(pe.pe + 22) & 0x2000:
        raise ValueError("Expected IMAGE_FILE_DLL")
    for index in (9, 10, 13, 14):
        if any(pe.directory(index)):
            raise ValueError("TLS, load-config, delay imports, or CLR unsupported")
    image = bytearray(size)
    image[:pe.headers] = data[:pe.headers]
    executable = []
    for index, (va, span, raw, raw_size) in enumerate(pe.sections):
        if va + span > size:
            raise ValueError("Section exceeds mapped image")
        image[va:va + raw_size] = data[raw:raw + raw_size]
        flags = pe.u32(pe.table + index * 40 + 36)
        if flags & 0x20000000:
            executable.append((va, va + raw_size))

    def code_rva(rva):
        if not any(start <= rva < end for start, end in executable):
            raise ValueError("Entrypoint/export is outside executable file data")

    code_rva(entry)
    imports = []
    for descriptor in pe.imports():
        if descriptor["dll"].upper() != "KERNEL32.DLL":
            raise ValueError("Only explicitly mocked KERNEL32 imports are allowed")
        for _, name, iat in descriptor["entries"]:
            if name not in IMPORTS:
                raise ValueError(f"Unsupported import: {name!r}")
            imports.append((name, iat))
    if {name for name, _ in imports} != IMPORTS:
        raise ValueError("DLL import inventory differs from the fourteen mock contracts")
    export_rva, export_size = pe.directory(0)
    at = pe.offset(export_rva, 40)
    function_count, name_count, functions, names, ordinals = struct.unpack_from("<IIIII", data, at + 20)
    if function_count > 256 or name_count > 256:
        raise ValueError("Unexpected export inventory size")
    exports = {}
    for index in range(name_count):
        name = pe.string(pe.u32(pe.offset(names + index * 4, 4)))
        ordinal = pe.u16(pe.offset(ordinals + index * 2, 2))
        if ordinal >= function_count or name in exports:
            raise ValueError("Malformed export table")
        rva = pe.u32(pe.offset(functions + ordinal * 4, 4))
        if export_rva <= rva < export_rva + export_size:
            raise ValueError("Forwarded exports are unsupported")
        code_rva(rva)
        exports[name] = rva
    if set(exports) != EXPORTS:
        raise ValueError(f"Need exact 15-export runtime; got {sorted(exports)}")
    return pe, image, preferred, entry, imports, exports


def relocate(pe, original, preferred, target):
    image = bytearray(original)
    rva, length = pe.directory(5)
    if not rva or length < 8:
        raise ValueError("A relocation directory is required for the alternate-base test")
    if rva + length > len(image):
        raise ValueError("Relocation directory out of bounds")
    cursor, end, seen = rva, rva + length, set()
    delta = target - preferred
    while cursor < end:
        if cursor + 8 > end:
            raise ValueError("Truncated relocation block")
        page, block_size = struct.unpack_from("<II", image, cursor)
        if page & 4095 or block_size < 8 or block_size & 1 or cursor + block_size > end:
            raise ValueError("Malformed relocation block")
        for slot in range(cursor + 8, cursor + block_size, 2):
            entry = struct.unpack_from("<H", image, slot)[0]
            kind, offset = entry >> 12, entry & 4095
            if kind == 0:
                continue
            if kind != 3:
                raise ValueError(f"Unsupported relocation type {kind}")
            address = page + offset
            if address + 4 > len(image) or address in seen:
                raise ValueError("Out-of-range or duplicate relocation")
            seen.add(address)
            struct.pack_into("<I", image, address, (u32(image, address) + delta) & 0xffffffff)
        cursor += block_size
    return image, len(seen)


def run(command, **kwargs):
    return subprocess.run([str(part) for part in command], cwd=HERE, check=True, **kwargs)


def build_variant(pe, image, preferred, entry, imports, exports, target):
    output = BUILD / f"{target:08x}"
    output.mkdir(parents=True, exist_ok=True)
    mapped, relocation_count = relocate(pe, image, preferred, target)
    (output / "pe-image.bin").write_bytes(mapped)
    (output / "pe_config.h").write_text(
        "/* Generated from the actual input DLL. */\n"
        f"#define PE_BASE UINT32_C(0x{target:08x})\n"
        f"#define PE_ENTRY UINT32_C(0x{entry:08x})\n" +
        "".join(f"#define RVA_{name} UINT32_C(0x{rva:08x})\n" for name, rva in sorted(exports.items()))
    )
    (output / "pe_imports.inc").write_text("".join(
        f"*(volatile uint32_t *)(uintptr_t)(PE_BASE + UINT32_C(0x{iat:08x})) = "
        f"(uint32_t)(uintptr_t)&mock_{name};\n" for name, iat in imports))
    (output / "image.S").write_text(
        '.section .peimage,"awx",@progbits\n.balign 4096\n'
        f'.incbin "{output / "pe-image.bin"}"\n'
        '.section .note.GNU-stack,"",@progbits\n')
    (output / "link.ld").write_text(f"""ENTRY(_start)
PHDRS {{ text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); pe PT_LOAD FLAGS(7); }}
SECTIONS {{
 . = 0x08048000;
 .text : {{ *(.text.start) *(.text*) *(.rodata*) }} :text
 . = ALIGN(4096);
 .data : {{ *(.data*) }} :data
 .bss : {{ *(.bss*) *(COMMON) }} :data
 . = 0x{target:08x};
 .peimage : {{ KEEP(*(.peimage)) }} :pe
 /DISCARD/ : {{ *(.comment) *(.note*) *(.eh_frame*) }}
}}
""")
    flags = ["clang", "--target=i486-none-elf", "-std=c11", "-O2", "-g",
             "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic",
             "-mno-sse", "-mno-mmx", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
             "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Wstrict-prototypes"]
    run([*flags, "-I", output, "-c", HERE / "harness.c", "-o", output / "harness.o"])
    run(["clang", "--target=i486-none-elf", "-c", HERE / "entry.S", "-o", output / "entry.o"])
    run(["clang", "--target=i486-none-elf", "-c", output / "image.S", "-o", output / "image.o"])
    binary = output / "abi32-test"
    run(["ld.lld", "-m", "elf_i386", "-static", "-T", output / "link.ld", "-o", binary,
         output / "entry.o", output / "harness.o", output / "image.o"])
    undefined = run(["nm", "-u", binary], capture_output=True, text=True).stdout
    if undefined.strip():
        raise RuntimeError(f"Unexpected unresolved host dependency: {undefined}")
    execution = run([binary], capture_output=True, text=True, timeout=30)
    (output / "result.txt").write_text(execution.stdout)
    if not execution.stdout.startswith("PASS NTW32 actual PE32 ABI:"):
        raise RuntimeError("Missing successful ABI test evidence")
    return {"base": f"0x{target:08x}", "relocation_delta": target - preferred,
            "highlow_relocation_sites": relocation_count,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "stdout": execution.stdout.strip(), "undefined_symbols": []}


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--dll", type=Path, default=ROOT / "build/platform/NTW32.DLL")
    options = args.parse_args()
    options.dll = options.dll.resolve()
    BUILD.mkdir(parents=True, exist_ok=True)
    source_paths = [HERE / name for name in ("build.py", "harness.c", "entry.S", "test_packer.py")]
    source_paths.append(ROOT / "ntwin32/prepare.py")
    source_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in source_paths}
    report_path = BUILD / "results.json"
    report_path.unlink(missing_ok=True)
    data = options.dll.read_bytes()
    pe, image, preferred, entry, imports, exports = inspect(data)
    packer_tests = run([sys.executable, HERE / "test_packer.py", "--dll", options.dll],
                       capture_output=True, text=True, timeout=30)
    count_match = re.search(r"Ran ([0-9]+) tests?", packer_tests.stderr)
    if count_match is None or not packer_tests.stderr.rstrip().endswith("OK"):
        raise RuntimeError("Missing successful packer test evidence")
    variants = [build_variant(pe, image, preferred, entry, imports, exports, target)
                for target in (0x68000000, 0x69000000)]
    if options.dll.read_bytes() != data:
        raise RuntimeError("Input DLL changed during ABI run; rerun against a stable artifact")
    if source_hashes != {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in source_paths}:
        raise RuntimeError("Harness/parser source changed during ABI run")
    report = {"schema": "ntwin32.abi32.v1", "dll_sha256": hashlib.sha256(data).hexdigest(),
              "input_dll": str(options.dll), "windows_guest_verified": False,
              "execution": "native x86 Linux ELF32 executing embedded PE32 code with original mocks",
              "sources_sha256": source_hashes,
              "packer_tests": {"status": "PASS", "count": int(count_match.group(1)),
                               "stdout": packer_tests.stdout, "stderr": packer_tests.stderr},
              "imports_mocked": sorted(IMPORTS), "exports_checked": sorted(EXPORTS),
              "variants": variants}
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"ABI32 validation failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "", file=sys.stderr)
            print(error.stderr or "", file=sys.stderr)
        sys.exit(1)
