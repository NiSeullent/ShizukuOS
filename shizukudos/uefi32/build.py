#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build original x64 EFI loader, low-memory mode transition and i486 payload."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
BUILD = ROOT / "build"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    subprocess.run([str(x) for x in command], check=True, cwd=ROOT, timeout=60)


def elf_contract(path):
    data = path.read_bytes()
    assert data[:7] == b"\x7fELF\x01\x01\x01", "little-endian ELF32"
    kind, machine, _, entry, phoff, shoff = struct.unpack_from("<HHIIII", data, 16)
    assert kind == 2 and machine == 3 and entry == 0x02010000, "fixed i386 entry"
    phsize, phcount, shsize, shcount = struct.unpack_from("<HHHH", data, 42)
    segments = []
    for index in range(phcount):
        fields = struct.unpack_from("<IIIIIIII", data, phoff + index * phsize)
        kind, offset, virtual, physical, file_size, memory_size, flags, alignment = fields
        if kind != 1:
            continue
        assert virtual == physical and 0x02010000 <= virtual < 0x02100000
        assert file_size <= memory_size and virtual + memory_size <= 0x02100000
        assert offset + file_size <= len(data)
        segments.append({"physical": physical, "file_bytes": file_size,
                         "memory_bytes": memory_size, "flags": flags})
    assert segments, "load segments"
    for index in range(shcount):
        section = shoff + index * shsize
        kind = struct.unpack_from("<I", data, section + 4)[0]
        size = struct.unpack_from("<I", data, section + 20)[0]
        assert kind not in (4, 9) or not size, "no unresolved relocations"
    return {"machine": "i386", "entry": entry, "segments": segments}


def pe_contract(path):
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0"
    machine, count, stamp = struct.unpack_from("<HHI", data, pe + 4)
    optional = pe + 24
    assert machine == 0x8664 and stamp == 0
    assert struct.unpack_from("<H", data, optional)[0] == 0x20B
    assert struct.unpack_from("<H", data, optional + 68)[0] == 10
    imports, size = struct.unpack_from("<II", data, optional + 120)
    sections = optional + struct.unpack_from("<H", data, pe + 20)[0]
    if imports:
        found = False
        for index in range(count):
            _, base, raw_bytes, raw = struct.unpack_from("<IIII", data, sections + index * 40 + 8)
            if base <= imports < base + raw_bytes:
                offset = raw + imports - base
                assert size >= 20 and data[offset:offset + 20] == bytes(20)
                found = True
        assert found, "empty import descriptor"
    assert all(struct.unpack_from("<II", data, optional + 112 + 5 * 8)), "PE relocations"
    return {"machine": "AMD64", "subsystem": "EFI_APPLICATION", "imports": [], "relocations": True}


def main():
    tools = {name: shutil.which(name) for name in
             ("nasm", "gcc", "ld", "objcopy", "nm", "x86_64-w64-mingw32-gcc")}
    if not all(tools.values()):
        raise SystemExit(f"Existing build tools required; nothing installed: {tools}")
    BUILD.mkdir(exist_ok=True)
    receipt_path = BUILD / "build-result.json"
    receipt_path.unlink(missing_ok=True)
    sources = list(ROOT.glob("*.c")) + list(ROOT.glob("*.h")) + [ROOT / "transition.asm", ROOT / "payload.ld"]
    sources += [REPO / name for name in ("ntwrapper/core.c", "ntwrapper/include/ntwrapper.h",
                "ntwddm/src/ntwddm.c", "ntwddm/include/ntwddm.h", "shizukudos/uefi/boot.c",
                "shizukudos/uefi/boot.h", "shizukudos/uefi/efi.h")]
    hashes = {str(path.relative_to(REPO)): digest(path) for path in sources}
    constants = re.findall(r"^#define (SD32_\w+) (0x[0-9A-Fa-f]+|\d+)$", (ROOT / "layout.h").read_text(), re.M)
    (BUILD / "layout.inc").write_text("".join(f"%define {name} {value}\n" for name, value in constants))
    run([tools["nasm"], "-f", "bin", "-I", str(BUILD) + "/", "-l", BUILD / "transition.lst",
         ROOT / "transition.asm", "-o", BUILD / "transition.bin"])
    transition = (BUILD / "transition.bin").read_bytes()
    assert len(transition) == 0x2800 and len(transition) < 0x4000
    flags = ["-m32", "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
             "-mpreferred-stack-boundary=2", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
             "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pie", "-fno-pic",
             "-fno-asynchronous-unwind-tables", "-fno-ident", "-I", str(REPO / "ntwddm/include")]
    objects = []
    for index, path in enumerate((ROOT / "payload.c", ROOT / "contract.c", REPO / "ntwrapper/core.c", REPO / "ntwddm/src/ntwddm.c")):
        obj = BUILD / f"payload-{index}.o"
        run([tools["gcc"], *flags, "-c", path, "-o", obj])
        objects.append(obj)
    elf = BUILD / "payload.elf"
    run([tools["ld"], "-m", "elf_i386", "-T", ROOT / "payload.ld", "-o", elf, *objects])
    elf_details = elf_contract(elf)
    assert not subprocess.check_output([tools["nm"], "-u", str(elf)], text=True).strip(), "no runtime dependencies"
    run([tools["objcopy"], "-O", "binary", elf, BUILD / "payload.bin"])
    payload = (BUILD / "payload.bin").read_bytes()
    assert payload and len(payload) < 0xF0000
    images = "/* Generated from original locally built machine code. */\n"
    for name, data in (("transition_image", transition), ("payload_image", payload)):
        images += f"static const unsigned char {name}[] = {{\n"
        images += "\n".join(",".join(f"0x{x:02x}" for x in data[pos:pos + 24]) + ","
                              for pos in range(0, len(data), 24)) + "\n};\n"
    (BUILD / "images.h").write_text(images)
    temporary = BUILD / "BOOTX64.EFI.tmp"
    command = [tools["x86_64-w64-mingw32-gcc"], "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
               "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-mno-red-zone", "-mno-stack-arg-probe",
               "-fno-ident", "-fno-asynchronous-unwind-tables", "-nostdlib", "-Wl,--subsystem,10",
               "-Wl,--entry,efi_main", "-Wl,--image-base,0x10000000", "-Wl,--enable-reloc-section",
               "-Wl,--no-insert-timestamp", "-Wl,--strip-all", "-I", str(BUILD),
               str(ROOT / "loader.c"), str(ROOT / "contract.c"), str(ROOT / "paging.c"),
               str(REPO / "shizukudos/uefi/boot.c"), "-o", str(temporary)]
    run(command)
    details = pe_contract(temporary)
    assert hashes == {str(path.relative_to(REPO)): digest(path) for path in sources}, "sources changed during compilation"
    output = BUILD / "BOOTX64.EFI"
    temporary.replace(output)
    receipt = {"efi": {**details, "bytes": output.stat().st_size, "sha256": digest(output)},
               "payload": {**elf_details, "bytes": len(payload), "sha256": digest(BUILD / "payload.bin")},
               "transition": {"bytes": len(transition), "sha256": digest(BUILD / "transition.bin")},
               "sources_sha256": hashes, "efi_command": command, "payload_flags": flags}
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: value for key, value in receipt.items() if key in ("efi", "payload", "transition")}, indent=2))


if __name__ == "__main__":
    main()
