#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the Shizuku guest kernels as separate images with separate toolchains/ABIs.

  Kernel32 : i486, freestanding, elf_i386, flat image linked at 0x00100000
  Kernel64 : x86-64, -mcmodel=kernel, general registers only, elf_x86_64, higher-half

Neither is a recompilation of the other: they share only kcommon/ headers and the ABI
header, and have independent entry code, descriptor tables, memory managers and schedulers.
"""
import argparse
from contextlib import ExitStack
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
# Pin the guest ISA: a distribution GCC may default to x86-64-v3 and emit
# BMI2 even for integer-only code, which faults on baseline x86-64 CPUs.
K64_FLAGS = ["-m64", "-march=x86-64", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
             "-fno-pic", "-fno-pie", "-mcmodel=kernel", "-mno-red-zone", "-mgeneral-regs-only",
             "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-ident", "-fno-common",
             "-fwrapv", "-fno-strict-aliasing", "-fno-tree-loop-distribute-patterns"]


STUB_DIR = SHZ / "kernel64" / "standalone"


def dead_screen_sources():
    # Host/ABI test units share this directory and must not enter either kernel.
    return [SHZ / "dead_screen" / name for name in
            ("dead_screen.c", "render.c", "native.c", "control.c")]


def kernel_font_sources():
    # The same licensed glyph data and allocation-free rasterizer as GDI32.
    return [SHZ / "win64/dlls/gdi32" / name for name in ("gdi_font.c", "gdi_font_data.c")]


def build_standalone_stub(k32=False):
    """Multiboot ELF32 boot stub (see kernel64/standalone/boot32.c) for running a guest kernel without the Supervisor."""
    out = BUILD / ("kernel32s" if k32 else "kernel64s")
    out.mkdir(parents=True, exist_ok=True)
    asm_o, c_o, elf = out / "boot.asm.o", out / "boot32.o", out / "boot.elf"
    run(["nasm", "-f", "elf32", "-w+all", "-o", asm_o, STUB_DIR / ("boot_pm.asm" if k32 else "boot.asm")])
    run(["gcc", "-m32", "-march=i486", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-pic",
         "-fno-pie", "-fno-stack-protector", "-mno-sse", "-mno-mmx", "-fno-asynchronous-unwind-tables", "-fno-ident",
         "-fno-tree-loop-distribute-patterns", *(["-DSTUB_K32"] if k32 else []), "-c", STUB_DIR / "boot32.c", "-o", c_o])
    run(["ld", "-m", "elf_i386", "-nostdlib", "-z", "noexecstack", "--no-warn-rwx-segments", "-T", STUB_DIR / "boot.ld",
         "-o", elf, asm_o, c_o])
    assert not run(["nm", "-u", elf], capture=True).stdout.strip(), "boot stub has unresolved symbols"
    return {"elf": elf, "sha256": sha256_file(elf), "bytes": elf.stat().st_size}


def sources(directory, suffix):
    return sorted((SHZ / directory).glob(f"*{suffix}"))


def source_hashes():
    directories = [SHZ / name for name in ("kernel32", "kernel64", "accounts", "kcommon", "abi", "pma_bridge", "win64/include", "dead_screen", "boot_profile", "supervisor/loader", "supervisor/src", "supervisor/guest", "supervisor/native_win98", "uefi", "csmwrap/video")]
    # Kernel64's laptop_protocols.c imports the shared driver C and headers.
    directories += [REPO / "shizukufs/v1/libsfs", REPO / "drivers/ahci_native",
                    REPO / "drivers/common", REPO / "drivers/shz_laptop"]
    # Kernel64 net_sock_extensions.h includes the AcceptEx registry source.
    directories += [REPO / "ntwin32/steam_socket"]
    paths = {p for directory in directories for p in directory.rglob("*")
             if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld")}
    paths.update(SHZ / "install" / name for name in
                 ("native_release_admission.py", "native_release_policy.py", "native_payload_ingest.py", "private_installer_package.py", "native_capacity_profile.py", "private_installer_iso.py", "native_build_tool_custody.py"))
    paths.update([*kernel_font_sources(), SHZ / "win64/dlls/gdi32/gdi_font.h"])
    paths.update([Path(__file__).resolve(), SHZ / "tools/shzlib.py", SHZ / "win64/pe_parse.c",
                  SHZ / "win64/pe_parse.h",
                  SHZ / "supervisor/src/font8x8_basic.h", SHZ / "supervisor/build.py",
                  REPO / "tools/shizuku_se_media.py", REPO / "tools/shizuku_image_io.py",
                  REPO / "tools/shizuku_se_drivers.py", REPO / "tools/build_shizuku_se_iso.py"])
    return {str(p.relative_to(REPO)): sha256_file(p) for p in sorted(paths)}


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


def build_all(args, stack, private_finalize=None):
    if private_finalize is not None and args.native_release_manifest is None:
        raise ValueError("private packaging requires independent release admission")
    global BUILD
    if args.out is not None:
        output = args.out
        if not output.is_absolute() or output.resolve() != output or output.exists() or not output.parent.is_dir():
            raise ValueError("--out requires a new canonical absolute directory with an existing parent")
        if output.is_relative_to(REPO) and not output.is_relative_to(REPO / "build"):
            raise ValueError("--out cannot write generated kernels into visible project sources")
        if shutil.disk_usage(output.parent).free < (17 << 30) + (64 << 20):
            raise ValueError("--out requires the retained 17 GiB reserve plus a 64 MiB component budget")
        BUILD = output
    for tool in ("nasm", "gcc", "ld", "nm", "objcopy", "objdump"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    results = {}
    built_sources = source_hashes()
    tools = {name: {"path": str(Path(shutil.which(name)).resolve()),
                   "sha256": sha256_file(Path(shutil.which(name)).resolve())}
             for name in ("nasm", "gcc", "ld", "nm", "objcopy", "objdump")}
    for program in ("cc1", "as"):
        selected = run(["gcc", "-print-prog-name=" + program], capture=True).stdout.strip()
        actual = Path(selected) if Path(selected).is_absolute() else Path(shutil.which(selected) or "")
        if not actual.is_file():
            raise RuntimeError("cannot pin actual GCC child executable: " + program)
        actual = actual.resolve()
        tools["gcc-" + program] = {"path": str(actual), "sha256": sha256_file(actual)}
    # Only the explicit private packaging lane needs the actual EFI compiler.
    # Its children participate in the same held source/tool union and receipt.
    if args.native_release_manifest is not None:
        for name in ("xorriso", "mkfs.vfat", "mcopy", "mmd", "mdir", "fsck.vfat", "zstd", "git", "readelf"):
            selected = shutil.which(name)
            if selected is None:
                raise RuntimeError("private media tool absent: " + name)
            actual = Path(selected).resolve()
            tools["private-media-" + name] = {"path": str(actual), "sha256": sha256_file(actual)}
        compiler = shutil.which("x86_64-w64-mingw32-gcc")
        if compiler is None:
            raise RuntimeError("private installer requires actual MinGW EFI compiler")
        actual = Path(compiler).resolve()
        tools["private-efi-gcc"] = {"path": str(actual), "sha256": sha256_file(actual)}
        for program in ("cc1", "as", "collect2", "ld"):
            selected = run([compiler, "-print-prog-name=" + program], capture=True).stdout.strip()
            actual = Path(selected) if Path(selected).is_absolute() else Path(shutil.which(selected) or "")
            if not actual.is_file():
                raise RuntimeError("cannot pin actual private EFI compiler child: " + program)
            actual = actual.resolve()
            tools["private-efi-" + program] = {"path": str(actual), "sha256": sha256_file(actual)}
    release = None
    if args.native_release_manifest is not None:
        sys.path.insert(0, str(SHZ / "install"))
        import native_release_admission
        BUILD.mkdir(mode=0o700)
        release = stack.enter_context(native_release_admission.admit_for_build(
            args.native_release_manifest, BUILD / "private-release",
            [{"path": str(REPO / name), "bytes": (REPO / name).stat().st_size, "sha256": sha}
             for name, sha in built_sources.items()],
            build_tool_pins={role: {"path": row["path"], "bytes": Path(row["path"]).stat().st_size,
                                   "sha256": row["sha256"]}
                             for role, row in tools.items()},
            # role-2 SZOU pin only when explicitly requested; v1-only call shape is unchanged
            **({"original_userland_manifest": args.original_userland_manifest}
               if getattr(args, "original_userland_manifest", None) is not None else {})))
    private_flags = [] if release is None or release.get('profile') is None else release['profile'].flags()
    k32 = build_kernel("kernel32", "kernel32", K32_FLAGS, "elf32", "elf_i386", "KERNEL32.BIN")
    # The PE32+ parser is shared with the host tests; Kernel64 links the same source freestanding.
    # ShizukuFS v1 (ext4 format, jbd2): the portable libsfs sources are linked freestanding (kernel64/sfs_mount.c).
    libsfs = sorted((REPO / "shizukufs" / "v1" / "libsfs").glob("*.c"))
    k64 = build_kernel("kernel64", "kernel64", K64_FLAGS, "elf64", "elf_x86_64", "KERNEL64.BIN",
                       extra_c=[SHZ / "win64" / "pe_parse.c", *libsfs, *dead_screen_sources(), *kernel_font_sources()])
    # Same sources with SHZ_STANDALONE: hypercalls served in-kernel over COM1/PIT/RTC so it boots under QEMU TCG.
    # The standalone profile is the only one with a disk: the original AHCI core (drivers/ahci_native) is linked
    # behind kernel64/ahci_blk.c; under the Supervisor no device is passed through and the block registry stays empty.
    k64s = build_kernel("kernel64s", "kernel64", K64_FLAGS + ["-DSHZ_STANDALONE"] + (["-DSHZ_NATIVE_INSTALLER_RELEASE"] if release else []) + private_flags, "elf64", "elf_x86_64",
                        "KERNEL64S.BIN", extra_c=[SHZ / "win64" / "pe_parse.c", STUB_DIR / "standalone64.c",
                                                  REPO / "drivers" / "ahci_native" / "ahci.c",
                                                  REPO / "drivers" / "xhci_native" / "xhci.c", REPO / "drivers" / "xhci_usb" / "xhci_usb.c",
                                                  REPO / "drivers" / "xhci_usb" / "hid_interrupt.c", REPO / "drivers" / "usb_native" / "ntwu_usb.c",
                                                  REPO / "drivers" / "shz_laptop" / "hid.c", REPO / "drivers" / "shz_laptop" / "pointer_adapter.c",
                                                  REPO / "drivers" / "shz_laptop" / "ps2_touchpad.c",
                                                  REPO / "drivers" / "common" / "device.c", *libsfs, *dead_screen_sources(), *kernel_font_sources(),
                                                  *([release["source"]] if release else [])])
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
    packaged = None
    if private_finalize is not None:
        packaged = private_finalize(release, BUILD, results)
    if source_hashes() != built_sources:
        raise RuntimeError("kernel sources changed during build; no verified receipt written")
    if any(sha256_file(Path(row["path"])) != row["sha256"] for row in tools.values()):
        raise RuntimeError("kernel compiler/tool bytes changed; no verified receipt written")
    profile_record = None if release is None or release.get("profile") is None else release["profile"].record()
    # Close the admission custody before writing any successful receipt.
    stack.close()
    shzlib.write_json(BUILD / "kernels-build-result.json", {
        "built_utc": shzlib.utc_now(), "git": shzlib.git_state(), "kernels": results,
        "kernel32_machine": "EM_386 ELF32", "kernel64_machine": "EM_X86_64 ELF64",
        "sources_sha256": built_sources, "tools_sha256": tools,
        "private": release is not None, "public_artifact": release is None,
        "private_installer": packaged,
        "private_load_profile": profile_record,
        "native_release": None if release is None else
            {k: v for k, v in release.items() if k not in ("source", "custody", "profile")}})
    print(json.dumps({k: {"bytes": v["bytes"], "sha256": v["sha256"]} for k, v in results.items()}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="new canonical private output directory")
    parser.add_argument("--original-userland-manifest", type=Path, default=None,
                        help="private original-userland stage manifest; role-2 SZOU pin, needs --native-release-manifest "
                             "and an approved ORIGINAL_USERLAND_STAGE policy anchor")
    parser.add_argument("--native-release-manifest", type=Path,
                        help="private actual saved producer manifest; installer K64S only")
    args = parser.parse_args()
    if args.original_userland_manifest is not None and args.native_release_manifest is None:
        parser.error("--original-userland-manifest is admitted only inside --native-release-manifest custody")
    if args.native_release_manifest is not None:
        if args.out is None or any((p / ".git").exists() for p in args.out.parents):
            parser.error("native release requires explicit fresh private --out outside Git")
    with ExitStack() as stack:
        build_all(args, stack)


if __name__ == "__main__":
    main()
