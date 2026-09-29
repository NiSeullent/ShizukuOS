#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the Shizuku guest kernels as separate images with separate toolchains/ABIs.

  Kernel32 : i486, freestanding, elf_i386, flat image linked at 0x00100000
  Kernel64 : x86-64, -mcmodel=kernel, general registers only, elf_x86_64, higher-half

Neither is a recompilation of the other: they share only kcommon/ headers and the ABI
header, and have independent entry code, descriptor tables, memory managers and schedulers.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

K32_FLAGS = ["-m32", "-march=i486", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
             "-fno-builtin", "-fno-pic", "-fno-pie", "-mno-sse", "-mno-mmx", "-msoft-float",
             "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-ident", "-fno-common",
             "-mpreferred-stack-boundary=2", "-fwrapv", "-fno-strict-aliasing", "-fno-tree-loop-distribute-patterns"]
K64_FLAGS = ["-m64", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
             "-fno-pic", "-fno-pie", "-mcmodel=kernel", "-mno-red-zone", "-mgeneral-regs-only",
             "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-ident", "-fno-common",
             "-fwrapv", "-fno-strict-aliasing", "-fno-tree-loop-distribute-patterns"]


STUB_DIR = SHZ / "kernel64" / "standalone"


def build_standalone_stub(k32=False):
    """Multiboot ELF32 boot stub (see kernel64/standalone/boot32.c) for running a guest kernel without the Supervisor."""
    out = BUILD / ("kernel32s" if k32 else "kernel64s")
    out.mkdir(parents=True, exist_ok=True)
    asm_o, c_o, elf = out / "boot.asm.o", out / "boot32.o", out / "boot.elf"
    run(["nasm", "-f", "elf32", "-w+all", "-o", asm_o, STUB_DIR / ("boot_pm.asm" if k32 else "boot.asm")])
    run(["gcc", "-m32", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-pic",
         "-fno-pie", "-fno-stack-protector", "-mno-sse", "-mno-mmx", "-fno-asynchronous-unwind-tables", "-fno-ident",
         "-fno-tree-loop-distribute-patterns", *(["-DSTUB_K32"] if k32 else []), "-c", STUB_DIR / "boot32.c", "-o", c_o])
    run(["ld", "-m", "elf_i386", "-nostdlib", "-z", "noexecstack", "--no-warn-rwx-segments", "-T", STUB_DIR / "boot.ld",
         "-o", elf, asm_o, c_o])
    assert not run(["nm", "-u", elf], capture=True).stdout.strip(), "boot stub has unresolved symbols"
    return {"elf": elf, "sha256": sha256_file(elf), "bytes": elf.stat().st_size}


def sources(directory, suffix):
    return sorted((SHZ / directory).glob(f"*{suffix}"))


def build_kernel(name, directory, cflags, nasm_fmt, ld_emul, out_name, extra_c=()):
    out = BUILD / name
    obj = out / "obj"
    obj.mkdir(parents=True, exist_ok=True)
    objects, commands = [], []
    for src in sources(directory, ".asm"):
        if src.stem.startswith("user_"):            # ring-3 flat binaries, embedded by incbin
            flat = obj / (src.stem + ".bin")
            cmd = ["nasm", "-f", "bin", "-w+all", "-o", flat, src]
            run(cmd)
            commands.append(cmd)
            continue
    for src in sources(directory, ".asm"):
        if src.stem.startswith("user_"):
            continue
        o = obj / (src.stem + ".asm.o")
        cmd = ["nasm", "-f", nasm_fmt, "-w+all", "-I", str(obj) + "/", "-o", o, src]
        run(cmd)
        commands.append(cmd)
        objects.append(o)
    for src in [*sources(directory, ".c"), *extra_c]:
        o = obj / (src.stem + ".o")
        cmd = ["gcc", *cflags, "-I", SHZ, "-I", SHZ / directory, "-c", src, "-o", o]
        run(cmd)
        commands.append(cmd)
        objects.append(o)
    elf = out / f"{name}.elf"
    link = ["ld", "-m", ld_emul, "-static", "-nostdlib", "-z", "max-page-size=4096", "-z", "noexecstack",
            "--no-warn-rwx-segments", "-T", SHZ / directory / "link.ld", "-o", elf, *objects]
    run(link)
    commands.append(link)
    undefined = run(["nm", "-u", elf], capture=True).stdout.strip()
    assert not undefined, f"{name}: unresolved runtime dependencies:\n{undefined}"
    binary = out / out_name
    run(["objcopy", "-O", "binary", elf, binary])
    disasm = run(["objdump", "-d", "-M", "intel", elf], capture=True).stdout
    (out / f"{name}.disasm.txt").write_text(disasm)
    return {"elf": elf, "bin": binary, "commands": commands, "bytes": binary.stat().st_size,
            "sha256": sha256_file(binary), "elf_sha256": sha256_file(elf)}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for tool in ("nasm", "gcc", "ld", "nm", "objcopy", "objdump"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    results = {}
    k32 = build_kernel("kernel32", "kernel32", K32_FLAGS, "elf32", "elf_i386", "KERNEL32.BIN")
    # The PE32+ parser is shared with the host tests; Kernel64 links the same source freestanding.
    k64 = build_kernel("kernel64", "kernel64", K64_FLAGS, "elf64", "elf_x86_64", "KERNEL64.BIN",
                       extra_c=[SHZ / "win64" / "pe_parse.c"])
    # Same sources with SHZ_STANDALONE: hypercalls served in-kernel over COM1/PIT/RTC so it boots under QEMU TCG.
    # The standalone profile is the only one with a disk: the original AHCI core (drivers/ahci_native) is linked
    # behind kernel64/ahci_blk.c; under the Supervisor no device is passed through and the block registry stays empty.
    k64s = build_kernel("kernel64s", "kernel64", K64_FLAGS + ["-DSHZ_STANDALONE"], "elf64", "elf_x86_64",
                        "KERNEL64S.BIN", extra_c=[SHZ / "win64" / "pe_parse.c", STUB_DIR / "standalone64.c",
                                                  REPO / "drivers" / "ahci_native" / "ahci.c"])
    stub = build_standalone_stub()
    k32s = build_kernel("kernel32s", "kernel32", K32_FLAGS + ["-DSHZ_STANDALONE"], "elf32", "elf_i386", "KERNEL32S.BIN",
                        extra_c=[SHZ / "kernel32" / "standalone" / "standalone32.c"])
    stub32 = build_standalone_stub(k32=True)
    for name, r in (("kernel32", k32), ("kernel64", k64)):
        results[name] = {"bytes": r["bytes"], "sha256": r["sha256"], "elf_sha256": r["elf_sha256"],
                         "commands": [[str(x) for x in c] for c in r["commands"]]}
    # Structural proof they are different images for different CPU modes.
    elf32 = k32["elf"].read_bytes()[:20]
    elf64 = k64["elf"].read_bytes()[:20]
    assert elf32[4] == 1 and elf32[18:20] == b"\x03\x00", "Kernel32 must be ELF32/i386"
    assert elf64[4] == 2 and elf64[18:20] == b"\x3e\x00", "Kernel64 must be ELF64/x86-64"
    results["kernel64-standalone"] = {"bytes": k64s["bytes"], "sha256": k64s["sha256"], "elf_sha256": k64s["elf_sha256"],
                                      "stub_sha256": stub["sha256"],
                                      "commands": [[str(x) for x in c] for c in k64s["commands"]]}
    results["kernel32-standalone"] = {"bytes": k32s["bytes"], "sha256": k32s["sha256"], "elf_sha256": k32s["elf_sha256"],
                                      "stub_sha256": stub32["sha256"],
                                      "commands": [[str(x) for x in c] for c in k32s["commands"]]}
    shzlib.write_json(BUILD / "kernels-build-result.json", {
        "built_utc": shzlib.utc_now(), "git": shzlib.git_state(), "kernels": results,
        "kernel32_machine": "EM_386 ELF32", "kernel64_machine": "EM_X86_64 ELF64",
        "sources_sha256": {str(p.relative_to(REPO)): sha256_file(p) for d in ("kernel32", "kernel64", "kcommon")
                           for p in sorted((SHZ / d).glob("*")) if p.is_file()}})
    print(json.dumps({k: {"bytes": v["bytes"], "sha256": v["sha256"]} for k, v in results.items()}, indent=2))


if __name__ == "__main__":
    main()
