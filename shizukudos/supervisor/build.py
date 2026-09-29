#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the Shizuku Supervisor: vBIOS ROM, fixed-address x64 payload, UEFI loader
and the ESP image that carries the DOS16 RAM-backed disk.

Toolchains stay separate on purpose:
  * vBIOS       : NASM, 16-bit flat binary (guest code, real mode)
  * payload     : gcc -m64 ELF64 System V, freestanding, general-registers only,
                  linked at a fixed physical address (VMX root mode)
  * loader      : x86_64-w64-mingw32-gcc PE32+ EFI application (MS ABI)
"""
import argparse
import json
import re
import shutil
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

SRC = SHZ / "supervisor"
OUT = BUILD / "supervisor"
PAYLOAD_BASE = 0x04002000
ESP_MIB = 96

PAYLOAD_C = ["main.c", "platform.c", "console.c", "caps.c", "vmx.c", "ept.c", "devices.c", "video.c", "bios.c",
             "domain.c", "dos.c", "kdom.c", "pool.c", "lib.c"]
PAYLOAD_ASM = ["entry.asm", "vmx_asm.asm"]
CFLAGS = ["-m64", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
          "-fno-stack-protector", "-fno-pie", "-fno-pic", "-mno-red-zone", "-mgeneral-regs-only",
          "-mcmodel=small", "-fno-asynchronous-unwind-tables", "-fno-ident", "-fno-common", "-mno-mmx",
          "-mno-sse", "-fno-tree-loop-distribute-patterns", "-fwrapv", "-fno-strict-aliasing"]


def c_array(name, data, const="const unsigned char"):
    lines = [f"/* Generated from locally built machine code. */", f"{const} {name}[{len(data)}] = {{"]
    for pos in range(0, len(data), 24):
        lines.append(",".join(f"0x{x:02x}" for x in data[pos:pos + 24]) + ",")
    lines.append("};")
    return "\n".join(lines) + "\n"


def build_vbios():
    out = OUT / "vbios.bin"
    run(["nasm", "-f", "bin", "-w+all", "-l", OUT / "vbios.lst", "-o", out, SRC / "guest" / "vbios.asm"])
    data = out.read_bytes()
    assert len(data) == 0x10000 and data[0xfff0] == 0xea, "vBIOS must be 64 KiB with a far-jump reset vector"
    (OUT / "vbios_image.h").write_text(c_array("vbios_image", data))
    return data


def build_payload():
    objs = []
    OUT.joinpath("obj").mkdir(exist_ok=True)
    commands = []
    for name in PAYLOAD_C:
        obj = OUT / "obj" / (name[:-2] + ".o")
        cmd = ["gcc", *CFLAGS, "-I", OUT, "-I", SRC / "src", "-I", SHZ / "abi", "-c", SRC / "src" / name, "-o", obj]
        run(cmd)
        commands.append(cmd)
        objs.append(obj)
    for name in PAYLOAD_ASM:
        obj = OUT / "obj" / (name[:-4] + ".o")
        cmd = ["nasm", "-f", "elf64", "-w+all", "-o", obj, SRC / "src" / name]
        run(cmd)
        commands.append(cmd)
        objs.append(obj)
    elf = OUT / "payload.elf"
    link = ["ld", "-m", "elf_x86_64", "-static", "-nostdlib", "-z", "max-page-size=4096", "-z", "noexecstack", "--no-warn-rwx-segments",
            "-T", SRC / "payload.ld", "-o", elf, *objs]
    run(link)
    commands.append(link)
    undefined = run(["nm", "-u", elf], capture=True).stdout.strip()
    assert not undefined, f"payload has unresolved runtime dependencies:\n{undefined}"
    entry = int(re.search(r"Entry point address:\s+(0x[0-9a-f]+)",
                          run(["readelf", "-h", elf], capture=True).stdout).group(1), 16)
    assert entry == PAYLOAD_BASE, f"payload entry {entry:#x} != {PAYLOAD_BASE:#x}"
    binary = OUT / "payload.bin"
    run(["objcopy", "-O", "binary", "--only-section=.text", "--only-section=.rodata", "--only-section=.data",
         elf, binary])
    data = binary.read_bytes()
    assert 0 < len(data) < 0x100000, "payload must stay below 1 MiB of file-backed image"
    return data, commands


def build_loader(payload):
    (OUT / "images.h").write_text(c_array("payload_image", payload, "static const unsigned char"))
    out = OUT / "BOOTX64.EFI"
    cmd = ["x86_64-w64-mingw32-gcc", "-std=gnu11", "-Os", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
           "-fno-builtin", "-fno-stack-protector", "-mno-red-zone", "-mno-stack-arg-probe", "-fno-ident",
           "-fno-asynchronous-unwind-tables", "-fno-tree-loop-distribute-patterns", "-nostdlib",
           "-Wl,--subsystem,10", "-Wl,--entry,efi_main", "-Wl,--image-base,0x10000000",
           "-Wl,--enable-reloc-section", "-Wl,--no-insert-timestamp", "-Wl,--strip-all",
           "-I", OUT, "-I", SRC / "loader", "-I", SRC / "src",
           SRC / "loader" / "loader.c", SRC / "loader" / "bootini.c", SRC / "src" / "caps.c",
           REPO / "shizukudos/uefi/boot.c",
           "-o", out]
    run(cmd)
    data = out.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    subsystem = struct.unpack_from("<H", data, pe + 24 + 68)[0]
    assert data[:2] == b"MZ" and machine == 0x8664 and subsystem == 10, "expected PE32+ EFI application"
    return out, cmd


def guest_kernel_files():
    """Optional guest kernel images built by shizukudos/kbuild.py and the Win64 initrd."""
    found = []
    for rel in ("kernel32/KERNEL32.BIN", "kernel64/KERNEL64.BIN", "win64/WIN64.IMG"):
        path = BUILD / rel
        if path.exists():
            found.append(path)
    return found


def build_esp(loader, disk_image):
    esp = OUT / "esp.img"
    esp.unlink(missing_ok=True)
    with open(esp, "wb") as fh:
        fh.truncate(ESP_MIB * 1024 * 1024)
    run(["mkfs.vfat", "-F", "32", "-n", "SHZESP", "-i", "53485A45", esp], capture=True)
    env = {"MTOOLS_SKIP_CHECK": "1", "PATH": "/usr/bin:/bin"}
    run(["mmd", "-i", esp, "::/EFI", "::/EFI/BOOT", "::/SHZDOS"], env=env)
    run(["mcopy", "-i", esp, loader, "::/EFI/BOOT/BOOTX64.EFI"], env=env)
    run(["mcopy", "-i", esp, disk_image, "::/SHZDOS/DISK.IMG"], env=env, timeout=120)
    for extra in guest_kernel_files():
        run(["mcopy", "-i", esp, extra, f"::/SHZDOS/{extra.name}"], env=env, timeout=120)
    return esp


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for tool in ("nasm", "gcc", "ld", "nm", "readelf", "objcopy", "x86_64-w64-mingw32-gcc", "mkfs.vfat", "mcopy",
                 "mmd"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool} (nothing is installed automatically)")
    disk = BUILD / "dos16" / "shizukudos-dos16-hd32.img"
    if not disk.exists():
        raise SystemExit("Run shizukudos/dos16/build.py first (the DOS16 disk image is an input)")
    OUT.mkdir(parents=True, exist_ok=True)
    vbios = build_vbios()
    payload, payload_cmds = build_payload()
    loader, loader_cmd = build_loader(payload)
    esp = build_esp(loader, disk)
    sources = sorted(p for p in SRC.rglob("*") if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld"))
    receipt = {
        "profile": "uefi-supervisor-vmx",
        "built_utc": shzlib.utc_now(),
        "git": shzlib.git_state(),
        "toolchain": {"gcc": shzlib.tool_version("gcc"), "nasm": shzlib.tool_version("nasm", ("-v",)),
                      "mingw": shzlib.tool_version("x86_64-w64-mingw32-gcc"), "ld": shzlib.tool_version("ld")},
        "payload_base": hex(PAYLOAD_BASE),
        "commands": {"payload": [[str(x) for x in c] for c in payload_cmds], "loader": [str(x) for x in loader_cmd]},
        "artifacts": {
            "BOOTX64.EFI": {"sha256": sha256_file(loader), "bytes": loader.stat().st_size},
            "payload.bin": {"sha256": sha256_file(OUT / "payload.bin"), "bytes": len(payload)},
            "payload.elf": {"sha256": sha256_file(OUT / "payload.elf")},
            "vbios.bin": {"sha256": sha256_file(OUT / "vbios.bin"), "bytes": len(vbios)},
            "esp.img": {"sha256": sha256_file(esp), "bytes": esp.stat().st_size},
            "disk.img (input)": {"sha256": sha256_file(disk), "bytes": disk.stat().st_size},
            **{f"{p.name} (input)": {"sha256": sha256_file(p), "bytes": p.stat().st_size}
               for p in guest_kernel_files()},
        },
        "sources_sha256": {str(p.relative_to(REPO)): sha256_file(p) for p in sources},
        "font": "shizukudos/supervisor/src/font8x8_basic.h (public domain, Daniel Hepper / IBM VGA lineage)",
    }
    shzlib.write_json(OUT / "build-result.json", receipt)
    print(json.dumps({k: v for k, v in receipt["artifacts"].items()}, indent=2))


if __name__ == "__main__":
    main()
