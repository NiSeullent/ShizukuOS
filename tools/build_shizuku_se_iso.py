#!/usr/bin/env python3
"""Build the Windows 98 Shizuku Second Edition VM install ISO (one hybrid image).

One ISO, bootable as a CD and, written to a USB stick or attached as a disk, as a
hard disk, on legacy BIOS and on UEFI:

- BIOS, El Torito default entry: isolinux.bin (no emulation, boot info table),
  pinned syslinux 6.04 (shizukudos/upstream/manifest.json "syslinux"). menu.c32
  offers, also on COM1:
    Kernel64  mboot.c32 loads the Multiboot stub SHZ/K64/BOOT.ELF with module 0
              KERNEL64S.BIN and module 1 WIN64.IMG (standalone Kernel64 + Win64).
    DOS16     memdisk boots ShizukuDOS10/dos16/shizukudos-dos16-hd32.img, the
              ShizukuDOS 10 DOS16 FreeDOS-profile disk, from RAM.
    0.1       memdisk boots ShizukuDOS/shizukudos.img, the ShizukuDOS 0.1 floppy.
    Install   only when SHZSETUP (agent I1) is present under SHZ/SETUP: Kernel64
              with shz.setup=auto on its Multiboot command line.
- UEFI, El Torito EFI entry (platform 0xEF): ShizukuDOS10/efiboot.img, a FAT
  image with \\EFI\\BOOT\\BOOTX64.EFI (Shizuku loader and boot manager),
  \\EFI\\SHIZUKU\\CSMWRAP.EFI (+ CSMWRAP.INI) and BOOT.INI (mode = auto,
  menu_timeout = 5), and \\SHZDOS\\ (loader inputs incl. KERNEL64S.BIN). The boot
  manager's menu: no key = auto (the Supervisor with Intel VMX, otherwise CSMWrap
  -> SeaBIOS CSM -> the El Torito default entry, i.e. the same menu as legacy
  BIOS); K = Kernel64 direct (no CSM, no VMX).
- isohybrid: isohdpfx.bin MBR code in the system area, MBR partition 1 (0x00,
  active, whole image) for BIOS disk boot, MBR partition 2 (0xEF) and a GPT
  entry for the EFI image so UEFI finds \\EFI\\BOOT\\BOOTX64.EFI on a disk.

The ISO 9660/Joliet/Rock Ridge tree also carries the Win98 SE overlay
(NTWrapper9x, NTWin32Wrapper9x, NTWDDMWrapper9x, SHZSE installer), the
driver store (DRIVERS\\<package>\\ + HWIDS.TXT index; --driver-package DIR copies
a user-supplied package unchanged), VMPROFIL.TXT, and the licences and
corresponding source of every third-party part (FreeDOS, CSMWrap + SeaBIOS,
syslinux). Microsoft files are never packaged by default: --win98-media PATH
overlays the builder's OWN Windows 98 media under WIN98/ in a separate
-private ISO (git-ignored build/ only).

Reproducible: fixed SOURCE_DATE_EPOCH for xorriso and mtools, fixed FAT volume
ids, deterministic tarballs; building twice from the same inputs gives the same
bytes (the receipt records the sha256). Boot evidence comes from
tools/test_shizuku_se_boot_matrix.py, not from this builder.
"""
from __future__ import annotations

import argparse
import filecmp
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import shizuku_se_media as se_media  # noqa: E402
BUILD = ROOT / "build"
STAGE_ROOT = BUILD / "shizuku-second-edition-stage"
ISO_NAME = "windows98-shizuku-second-edition.iso"
# The image that contains the user's own Windows 98 files is a different,
# private artifact. It never reuses the public image's stage or file names.
PRIVATE_SUFFIX = "-private"
SHZ10 = ROOT / "shizukudos"
SHZ10_BUILD = BUILD / "shizukudos"
SHZ10_DIR = "ShizukuDOS10"
SHZSE_TEMPLATES = ROOT / "tools" / "shizuku_se"
SHZSE_FILES = ("NTW32.DLL", "NTWRAP9X.VXD", "NTWQUERY.EXE", "NTWPROBE.EXE", "NTWGPROB.EXE")
EFI_IMAGE = f"{SHZ10_DIR}/efiboot.img"
# Fixed so that the EFI FAT image and the source tarballs are reproducible.
FIXED_EPOCH = 1785283200


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd or ROOT, check=True, env=env)


class Win98MediaError(RuntimeError):
    """The supplied --win98-media is unusable. Reported as a clear error, not a traceback."""


def load_image_builder():
    path = ROOT / "shizukudos" / "build_image.py"
    spec = importlib.util.spec_from_file_location("shizuku_image", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replace_broken_symlink(path: Path) -> None:
    """Official builders mkdir these output dirs. Broken /dev/shm links block them."""
    if path.is_symlink() and not path.exists():
        path.unlink()
    path.mkdir(parents=True, exist_ok=True)


def build_components(work: Path) -> dict[str, Path]:
    work.mkdir(parents=True, exist_ok=True)
    for output in (
        ROOT / "build" / "platform",
        ROOT / "ntwrapper" / "vxd" / "build",
        ROOT / "ntwddm" / "build",
        ROOT / "ntwddm" / "win98" / "build",
    ):
        replace_broken_symlink(output)
    run(["nasm", "-f", "bin", "shizukudos/boot.asm", "-o", str(work / "boot.bin")])
    run([
        "nasm", "-f", "bin", "-I", "shizukudos/",
        "shizukudos/stage2.asm", "-o", str(work / "stage2.bin"),
    ])
    for source, output in (
        ("shizukudos/tests/demo_com.asm", "demo.com"),
        ("shizukudos/tests/ret_com.asm", "ret.com"),
        ("shizukudos/tests/std_com.asm", "std.com"),
    ):
        run(["nasm", "-f", "bin", source, "-o", str(work / output)])
    run(["python3", "-B", "platform/build.py"])
    run(["python3", "-B", "ntwrapper/vxd/build.py"])
    run(["python3", "-B", "ntwddm/win98/build.py"])
    # The combined i386 object currently references __udivdi3, so the phony
    # freestanding32 check fails. The core object is the Makefile product
    # whose undefined-symbol list is empty. Do not rewrite ntwddm sources.
    run(["make", "-C", "ntwddm", "build/ntwddm-i386.o"])
    core = ROOT / "ntwddm" / "build" / "ntwddm-i386.o"
    undefined = subprocess.check_output(["nm", "-u", str(core)], text=True)
    if undefined.strip():
        raise RuntimeError("ntwddm-i386.o has undefined symbols:\n" + undefined)
    artifacts = {
        "NTW32.DLL": ROOT / "build" / "platform" / "NTW32.DLL",
        "NTWPROBE.EXE": ROOT / "build" / "platform" / "NTWPROBE.EXE",
        "NTWRAP9X.VXD": ROOT / "ntwrapper" / "vxd" / "build" / "NTWRAP9X.VXD",
        "NTWQUERY.EXE": ROOT / "ntwrapper" / "vxd" / "build" / "NTWQUERY.EXE",
        "NTWGPROB.EXE": ROOT / "ntwddm" / "win98" / "build" / "NTWGPROB.EXE",
        "ntwddm-i386.o": ROOT / "ntwddm" / "build" / "ntwddm-i386.o",
    }
    missing = [name for name, path in artifacts.items() if not path.is_file()]
    if missing:
        raise RuntimeError("missing built artifacts: " + ", ".join(missing))
    return artifacts


def edition_text() -> bytes:
    """EDITION.TXT inside the ShizukuDOS 0.1 floppy (8.3 FAT12 root, 40-column friendly)."""
    return (
        "Windows 98 Shizuku Second Edition\r\n"
        "This floppy is ShizukuDOS 0.1, the project's own real-mode shell.\r\n"
        "The VM install ISO boots it from its menu (memdisk floppy). The\r\n"
        "same menu offers ShizukuDOS 10 DOS16 (external FreeDOS profile) and\r\n"
        "the standalone Kernel64 + Win64 runtime; on UEFI the Shizuku loader\r\n"
        "(Supervisor with Intel VMX) or CSMWrap leads to the same menu.\r\n"
        "Embedded on this floppy: NTW32.DLL NTWRAP9X.VXD NTWGPROB.EXE\r\n"
        "ShizukuDOS does not replace IO.SYS and does not install or boot the\r\n"
        "Windows 98 GUI. No completed Windows 98 installation is claimed.\r\n"
        "Microsoft setup files are not on this floppy or in the public disc.\r\n"
    ).encode("ascii")


def limits_text() -> bytes:
    return (
        "LIMITS\r\n"
        "ShizukuDOS 0.1 (menu entry 0.1, floppy image in RAM): reads FAT12 root\r\n"
        "files and runs one 8.3 COM program. No MS-DOS 7.1, no CD-ROM driver.\r\n"
        "ShizukuDOS 10 DOS16 (menu entry DOS16): FreeDOS kernel + FreeCOM\r\n"
        "(external, GPL) on a 32 MiB conformance disk held in RAM by memdisk;\r\n"
        "it runs its test programs and stops. Changes are not written back.\r\n"
        "Kernel64 (menu entry Kernel64): the standalone Long Mode kernel and\r\n"
        "Win64 runtime run their self-tests and Win64 test programs and stop.\r\n"
        "It is not the Supervisor; it has no Win98 or DOS domain.\r\n"
        "UEFI: the Supervisor needs Intel VMX with EPT and unrestricted guest.\r\n"
        "AMD SVM is detected but has no backend. Without VMX the legacy menu is\r\n"
        "reached through CSMWrap (needs 2+ logical CPUs, Secure Boot off). Key K\r\n"
        "in the UEFI boot manager menu starts Kernel64 directly (at most 256 MiB).\r\n"
        "Neither profile replaces IO.SYS or installs or boots the Win98 GUI.\r\n"
        "This is not a completed Windows 98 installation.\r\n"
        "NTWRAP9X.VXD: the project docs record a failed VxD load on Windows 98\r\n"
        "(Win32 error 2, VXDLDR error 6). See SHZSE\\README.TXT on the disc.\r\n"
    ).encode("ascii")


def sources_text() -> bytes:
    return (
        "Layout sources checked while building this image\r\n"
        "1. El Torito Bootable CD-ROM Format Specification 1.0, Phoenix/IBM, 1995:\r\n"
        "   boot catalog, validation entry, default entry, section entries.\r\n"
        "   https://pdos.csail.mit.edu/6.828/2018/readings/boot-cdrom.pdf\r\n"
        "2. ECMA-119 (ISO 9660): the 32 KiB system area is free for the MBR/GPT.\r\n"
        "   https://ecma-international.org/publications-and-standards/standards/ecma-119/\r\n"
        "3. xorriso -as mkisofs (1.5.x, on the build host): -b isolinux.bin\r\n"
        "   -no-emul-boot -boot-load-size 4 -boot-info-table, -eltorito-alt-boot -e\r\n"
        "   IMAGE -no-emul-boot (platform 0xEF), -isohybrid-mbr isohdpfx.bin and\r\n"
        "   -isohybrid-gpt-basdat (MBR partition 0xEF + GPT entry for the EFI\r\n"
        "   image). For an EFI image over 65535 sectors xorriso records sector\r\n"
        "   count 0 ('extend to end of medium'); the parser here reads the catalog.\r\n"
        "4. Syslinux 6.04 documentation in the pinned packages (doc/isolinux.txt,\r\n"
        "   doc/menu.txt, doc/mboot.txt, doc/memdisk.txt): SERIAL, MENU LABEL ^key,\r\n"
        "   mboot.c32 KERNEL --- MODULE --- MODULE, memdisk harddisk/floppy.\r\n"
        "   isolinux.bin reads Rock Ridge names (core/fs/iso9660/susp_rr.c).\r\n"
        "5. Multiboot 0.6.96: module list order, memory map (flags bit 6); the\r\n"
        "   Kernel64 stub takes module 0 = kernel, module 1 = initrd.\r\n"
        "6. What the UEFI loader reads from its own volume: in the project tree,\r\n"
        "   shizukudos/supervisor/loader/loader.c load_file() and\r\n"
        "   shizukudos/supervisor/build.py build_esp(): \\SHZDOS\\DISK.IMG,\r\n"
        "   KERNEL32.BIN, KERNEL64.BIN, WIN64.IMG next to EFI\\BOOT\\BOOTX64.EFI.\r\n"
        "7. CSMWrap (build/upstream/csmwrap at the pinned commit): src/bootdev.c\r\n"
        "   boots the PCI device CSMWRAP.EFI was loaded from; SeaBIOS cdrom.c boots\r\n"
        "   the El Torito default entry, boot.c a disk through its MBR.\r\n"
        "8. The boot manager in the project tree: shizukudos/supervisor/loader/\r\n"
        "   bootini.h (BOOT.INI grammar incl. menu_timeout) and loader.c (menu,\r\n"
        "   CSMWrap chain-load, Kernel64 direct boot); kernel64/standalone/\r\n"
        "   memholes.h (firmware holes such as OVMF's S3 ACPI NVS at 8 MiB).\r\n"
        "9. Windows 98 guest procedure for SHZSE: platform/win98lab/README.md,\r\n"
        "   ntwrapper/vxd/README.md, docs/NATIVE_FIRST_TRIAL.md,\r\n"
        "   docs/NATIVE_GDI_TRIAL.md, docs/VXD_V86_LOADER_TRIAL.md.\r\n"
        "10. INF syntax for the driver store index: Microsoft 'General Syntax Rules\r\n"
        "   for INF Files', 'INF Manufacturer Section', 'INF Models Section'.\r\n"
        "\r\n"
        "Referenced but NOT re-read while building (verify before relying on them):\r\n"
        "- UEFI Specification 2.10, chapter 13 (El Torito, platform id 0xEF, the\r\n"
        "  boot image is a FAT file system). https://uefi.org/specs/UEFI/2.10/\r\n"
    ).encode("ascii")


def build_floppy(work: Path, artifacts: dict[str, Path]) -> bytes:
    image_mod = load_image_builder()
    files = {
        "HELLO.TXT": b"Hello from ShizukuDOS.\r\nThis FAT12 file can be read with TYPE.\r\n",
        "README.TXT": (
            b"ShizukuDOS is a from-scratch experimental shell.\r\n"
            b"BOOT chainloads the first hard disk MBR.\r\n"
            b"Windows 98 still uses its own IO.SYS and DOS 7.1.\r\n"
        ),
        "CHAIN.TXT": b"START OF FAT12 CHAIN\r\n" + b"0123456789ABCDEF\r\n" * 60 + b"END OF FAT12 CHAIN\r\n",
        "DEMO.COM": (work / "demo.com").read_bytes(),
        "RET.COM": (work / "ret.com").read_bytes(),
        "STD.COM": (work / "std.com").read_bytes(),
        "EDITION.TXT": edition_text(),
        "LIMITS.TXT": limits_text(),
        "NTW32.DLL": artifacts["NTW32.DLL"].read_bytes(),
        "NTWRAP9X.VXD": artifacts["NTWRAP9X.VXD"].read_bytes(),
        "NTWQUERY.EXE": artifacts["NTWQUERY.EXE"].read_bytes(),
        "NTWPROBE.EXE": artifacts["NTWPROBE.EXE"].read_bytes(),
        "NTWGPROB.EXE": artifacts["NTWGPROB.EXE"].read_bytes(),
        "NTWDDM.O": artifacts["ntwddm-i386.o"].read_bytes(),
    }
    image = image_mod.make_image(
        (work / "boot.bin").read_bytes(),
        (work / "stage2.bin").read_bytes(),
        files,
    )
    if len(image) != 1474560:
        raise RuntimeError(f"boot image is {len(image)} bytes, not 1474560")
    if image[0:3] != b"\xeb\x3c\x90" and image[0] != 0xEB:
        raise RuntimeError("boot image is missing the ShizukuDOS jump")
    if image[3:11] != b"SHIZUKU ":
        raise RuntimeError("boot image OEM name is not SHIZUKU")
    if image[510:512] != b"\x55\xaa":
        raise RuntimeError("boot image signature missing")
    return image


# ---------------------------------------------------------------------------
# ShizukuDOS 10.0-dev: build, stage, EFI image, licences and source
# ---------------------------------------------------------------------------

# Build outputs (relative to build/shizukudos) that are staged under ShizukuDOS10/.
SHZ10_STAGED = (
    "dos16/shizukudos-dos16-hd32.img",
    "kernel32/KERNEL32.BIN",
    "kernel64/KERNEL64.BIN",
    "kernel64s/KERNEL64S.BIN",
    "win64/WIN64.IMG",
    "supervisor/BOOTX64.EFI",
    "csm/CSMWRAP.EFI",
)
# The DOS16 disk image the BIOS menu's DOS16 entry boots with memdisk (ISO 9660 path).
DOS16_ISO_PATH = f"{SHZ10_DIR}/dos16/shizukudos-dos16-hd32.img"
# supervisor/esp.img (96 MiB) is only cross-checked, not shipped: the ISO carries a
# size-fitted EFI image built from the very same bytes plus CSMWrap and BOOT.INI.
SHZ10_ESP = "supervisor/esp.img"
SHZ10_RECEIPTS = {
    "dos16/build-result.json": "dos16-build-result.json",
    "supervisor/build-result.json": "supervisor-build-result.json",
    "kernels-build-result.json": "kernels-build-result.json",
    "win64/build-result.json": "win64-build-result.json",
    "csm/build-result.json": "csm-build-result.json",
}
# Files of supervisor/esp.img that the EFI image of the ISO must carry unchanged.
ESP_CROSSCHECK = {
    "EFI/BOOT/BOOTX64.EFI": "supervisor/BOOTX64.EFI",
    "SHZDOS/DISK.IMG": "dos16/shizukudos-dos16-hd32.img",
    "SHZDOS/KERNEL32.BIN": "kernel32/KERNEL32.BIN",
    "SHZDOS/KERNEL64.BIN": "kernel64/KERNEL64.BIN",
    "SHZDOS/KERNEL64S.BIN": "kernel64s/KERNEL64S.BIN",
    "SHZDOS/WIN64.IMG": "win64/WIN64.IMG",
}
BUILD_STEPS = (
    [sys.executable, "shizukudos/csm/build.py"],
    [sys.executable, "shizukudos/tools/shz.py", "build", "--profile", "uefi-multikernel"],
)
MIB = 1024 * 1024


def build_shizukudos10(reuse: bool) -> dict[str, Path]:
    """Rebuild CSMWrap and ShizukuDOS 10.0-dev (or, with reuse, take existing outputs). Failures are fatal."""
    outputs = {rel: SHZ10_BUILD / rel for rel in (*SHZ10_STAGED, SHZ10_ESP, *SHZ10_RECEIPTS)}
    outputs.update({f"kernel64s/{name}": path for name, path in se_media.K64_FILES.items()})
    if reuse and all(path.is_file() for path in outputs.values()):
        print("== --reuse-builds: packaging the existing build/shizukudos outputs (checked against their receipts)")
    else:
        # SOURCE_DATE_EPOCH: GNU ld then stamps the Win64 PE images (WIN64.IMG) with the fixed date instead of the
        # link time, so a rebuild from the same source gives the same bytes (the other steps fix their dates already).
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(FIXED_EPOCH))
        for command in BUILD_STEPS:
            print("== SOURCE_DATE_EPOCH=%d " % FIXED_EPOCH + " ".join(str(c) for c in command), flush=True)
            try:
                subprocess.run(command, cwd=ROOT, check=True, timeout=2400, env=env)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise RuntimeError(f"build step failed ({exc}); refusing to package stale or partial outputs") from exc
    missing = [rel for rel, path in outputs.items() if not path.is_file()]
    if missing:
        raise RuntimeError("the ShizukuDOS 10.0 build did not produce: " + ", ".join(missing))
    return outputs


def mtools_env() -> dict[str, str]:
    return se_media.mtools_env()


def mcopy_out(image: Path, member: str, destination: Path) -> bytes:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    subprocess.run(["mcopy", "-i", str(image), f"::/{member}", str(destination)],
                   check=True, env=mtools_env(), stdout=subprocess.DEVNULL)
    return destination.read_bytes()


def check_shizukudos10_outputs(outputs: dict[str, Path], work: Path) -> str:
    """The staged files must be the ones the build receipts and the prebuilt esp.img describe."""
    receipt = json.loads(outputs["supervisor/build-result.json"].read_text(encoding="utf-8"))["artifacts"]
    receipt_keys = {
        "supervisor/BOOTX64.EFI": "BOOTX64.EFI",
        SHZ10_ESP: "esp.img",
        "dos16/shizukudos-dos16-hd32.img": "disk.img (input)",
        "kernel32/KERNEL32.BIN": "KERNEL32.BIN (input)",
        "kernel64/KERNEL64.BIN": "KERNEL64.BIN (input)",
        "kernel64s/KERNEL64S.BIN": "KERNEL64S.BIN (input)",
        "win64/WIN64.IMG": "WIN64.IMG (input)",
    }
    lines = []
    for rel, key in receipt_keys.items():
        actual = sha256_path(outputs[rel])
        if key not in receipt or receipt[key]["sha256"] != actual:
            raise RuntimeError(f"{rel} does not match supervisor/build-result.json ({key}); the outputs are inconsistent")
        lines.append(f"{rel} matches supervisor/build-result.json")
    csm = json.loads(outputs["csm/build-result.json"].read_text(encoding="utf-8"))["artifacts"]["CSMWRAP.EFI"]
    if csm["sha256"] != sha256_path(outputs["csm/CSMWRAP.EFI"]):
        raise RuntimeError("csm/CSMWRAP.EFI does not match csm/build-result.json")
    lines.append("csm/CSMWRAP.EFI matches csm/build-result.json")
    archive = json.loads(outputs["win64/build-result.json"].read_text(encoding="utf-8"))["archive"]
    if archive["sha256"] != sha256_path(outputs["win64/WIN64.IMG"]):
        raise RuntimeError("win64/WIN64.IMG does not match win64/build-result.json")
    lines.append(f"win64/WIN64.IMG matches win64/build-result.json ({len(archive['files'])} files)")
    scratch = work / "esp-crosscheck"
    for member, staged in ESP_CROSSCHECK.items():
        if mcopy_out(outputs[SHZ10_ESP], member, scratch / member) != outputs[staged].read_bytes():
            raise RuntimeError(f"supervisor/esp.img ::/{member} differs from {staged}")
    lines.append("supervisor/esp.img holds the same loader and \\SHZDOS files")
    shutil.rmtree(scratch, ignore_errors=True)
    return "\n".join(lines)


def shipped_receipt(path: Path) -> bytes:
    """A build receipt as shipped on the ISO: the build time is the only field that differs between two builds
    of the same source, so it is left out (build/shizukudos keeps the full receipt)."""
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if receipt.pop("built_utc", None) is not None:
        receipt["built_utc_note"] = "removed from the copy on the ISO for a reproducible image"
    if receipt.get("artifacts", {}).pop(SHZ10_ESP.split("/")[1], None) is not None:
        # supervisor/esp.img is a build intermediate that is not on the ISO (its FAT dates follow the build time);
        # the ISO carries the same loader and \SHZDOS bytes in its own EFI image, checked at build time.
        receipt["artifacts_note"] = "esp.img (not on this ISO) omitted from the copy on the ISO"
    return (json.dumps(receipt, indent=2) + "\n").encode("utf-8")


def build_efi_image(work: Path, members: dict[str, bytes]) -> bytes:
    """FAT16 El Torito EFI image sized to its content (reproducible: fixed volume id and dates)."""
    total = sum(len(data) for data in members.values())
    size_mib = -(-(total + 3 * MIB) // MIB)
    image = work / "efiboot.img"
    se_media.make_fat(image, members, size_mib, 16, "SHZESP", "53485A45", work / "efi-fat")
    return image.read_bytes()


def tar_entries(base: Path, prefix: str) -> list[tuple[str, Path]]:
    skip = {".git", "__pycache__"}
    entries: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        here = Path(dirpath)
        relative = here.relative_to(base).as_posix()
        entries.append((prefix if relative == "." else f"{prefix}/{relative}", here))
        for name in sorted(filenames):
            if name in skip or name.endswith(".pyc"):
                continue
            entries.append((f"{prefix}/{name}" if relative == "." else f"{prefix}/{relative}/{name}", here / name))
    return entries


def tracked_entries(tree: Path, prefix: str) -> list[tuple[str, Path]]:
    """Every git-tracked file of the checked-out commit, submodules included (the corresponding source)."""
    listing = subprocess.run(["git", "-C", str(tree), "ls-files", "--recurse-submodules", "-z"],
                             capture_output=True, check=True).stdout.decode("utf-8")
    names = sorted(name for name in listing.split("\0") if name and (tree / name).is_file()
                   and not (tree / name).is_symlink())
    return [(f"{prefix}/{name}", tree / name) for name in names]


def deterministic_tar_gz(entries: list[tuple[str, Path]]) -> bytes:
    return se_media.deterministic_tar_gz(entries)


def git_output(*args: str, cwd: Path = ROOT) -> str:
    result = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def pinned_upstream_tree(name: str, spec: dict) -> Path:
    """The pinned upstream tree the binaries were built from, unmodified (submodules at their pins)."""
    tree = BUILD / "upstream" / name
    if not tree.is_dir():
        raise RuntimeError(f"upstream tree {tree} is missing; its source cannot be shipped")
    head = git_output("rev-parse", "HEAD", cwd=tree)
    if head != spec["commit"]:
        raise RuntimeError(f"{tree} is at {head or 'unknown'}, manifest pins {spec['commit']}")
    if git_output("status", "--porcelain", cwd=tree):
        raise RuntimeError(f"{tree} has local modifications; the shipped source would not match commit {spec['commit']}")
    for sub, info in spec.get("submodules", {}).items():
        got = git_output("rev-parse", "HEAD", cwd=tree / sub)
        if got != info["commit"]:
            raise RuntimeError(f"{tree}/{sub} is at {got or 'unknown'}, manifest pins {info['commit']}")
    return tree


def license_files(tree: Path, spec: dict) -> list[Path]:
    """Licence files of an upstream and of each of its submodules."""
    found: list[Path] = []
    patterns = list(spec.get("license_files", []))
    for info in spec.get("submodules", {}).values():
        patterns += info.get("license_files", [])
    for pattern in patterns:
        matched = [p for p in sorted(tree.glob(pattern)) if p.is_file()]
        if not matched and "/" in pattern:  # "license/*" but the upstream license is a plain file "license"
            plain = tree / pattern.rsplit("/", 1)[0]
            if plain.is_file():
                matched.append(plain)
        found += [p for p in matched if p not in found]
    if not found:
        raise RuntimeError(f"no license file found in {tree} for {spec.get('license_files')}")
    return found


def shz10_readme(outputs: dict[str, Path], efi_size: int) -> bytes:
    digests = {rel: sha256_path(outputs[rel]) for rel in SHZ10_STAGED}
    return (
        "ShizukuDOS 10.0-dev\r\n"
        "===================\r\n"
        "\r\n"
        "This directory is a different product from ShizukuDOS 0.1, which is\r\n"
        "the project's own from-scratch code (..\\ShizukuDOS\\shizukudos.img).\r\n"
        "The two are not mixed under one label (docs/shizukudos10/BASELINE.md\r\n"
        "section 5, in SOURCE\\).\r\n"
        "\r\n"
        "Built by:  python3 shizukudos/csm/build.py and\r\n"
        "           python3 shizukudos/tools/shz.py build --profile uefi-multikernel\r\n"
        "Boot paths on this disc (see VMPROFIL.TXT at the root):\r\n"
        "  UEFI x64  El Torito EFI entry -> efiboot.img: \\EFI\\BOOT\\BOOTX64.EFI\r\n"
        "            (boot manager) -> Supervisor (Intel VMX) -> virtual Real Mode\r\n"
        "            DOS16 / Kernel32 / Kernel64. Without VMX: CSMWrap\r\n"
        "            (\\EFI\\SHIZUKU\\CSMWRAP.EFI) -> the legacy boot menu. Menu key\r\n"
        "            K: \\SHZDOS\\KERNEL64S.BIN directly (Kernel64 direct).\r\n"
        "  BIOS      isolinux menu: DOS16 boots dos16\\shizukudos-dos16-hd32.img\r\n"
        "            with memdisk; Kernel64 boots \\SHZ\\K64 (standalone, no VMX).\r\n"
        "\r\n"
        "Files\r\n"
        "  efiboot.img                        FAT16 image of the El Torito EFI entry\r\n"
        "                                     (see EFIBOOT.TXT for its contents).\r\n"
        "  dos16\\shizukudos-dos16-hd32.img    32 MiB hard-disk image: FreeDOS kernel\r\n"
        "                                     ke2046 + FreeCOM (external, GPL-2.0-or-\r\n"
        "                                     later, built from pinned source with\r\n"
        "                                     patches) and original Shizuku test\r\n"
        "                                     programs. AUTOEXEC.BAT runs T_MODE,\r\n"
        "                                     T_BIOS, T_COM, T_EXE, then SHZEXIT.COM:\r\n"
        "                                     a conformance disk, not a Windows\r\n"
        "                                     installer. No CD-ROM driver.\r\n"
        "  supervisor\\BOOTX64.EFI             Supervisor loader (own code, GPL-2.0-only)\r\n"
        "  kernel32\\KERNEL32.BIN              Kernel32 guest (own code, GPL-2.0-only)\r\n"
        "  kernel64\\KERNEL64.BIN              Kernel64 guest (own code, GPL-2.0-only)\r\n"
        "  kernel64s\\KERNEL64S.BIN            Kernel64 standalone build (Multiboot and\r\n"
        "                                     Kernel64 direct; own code, GPL-2.0-only)\r\n"
        "  win64\\WIN64.IMG                    Win64 runtime + test apps (own code)\r\n"
        "  csm\\CSMWRAP.EFI                    CSMWrap + SeaBIOS CSM (external, LGPL)\r\n"
        "  receipts\\                          build receipts of every build step\r\n"
        "  LICENSES\\, SOURCE\\, GPL-NOTICE.TXT licence texts and corresponding source\r\n"
        "                                     (FreeDOS, CSMWrap + submodules, syslinux)\r\n"
        "\r\n"
        "Requirements and limits\r\n"
        "  - Supervisor: Intel VMX with EPT and unrestricted guest (nested VMX in\r\n"
        "    a VM). AMD SVM is detected but has no backend: the loader refuses.\r\n"
        "  - CSMWrap: Secure Boot off, 2 or more logical CPUs.\r\n"
        "  - This profile does not replace IO.SYS and does not install or boot\r\n"
        "    the Windows 98 GUI. No Windows 98 installation is claimed.\r\n"
        "\r\n"
        "SHA-256 of the staged files (see also the HASHES.TXT at the disc root)\r\n"
        + "".join(f"  {digest}  {rel}\r\n" for rel, digest in digests.items())
        + f"  EFI image size {efi_size} bytes\r\n"
        "  supervisor/esp.img (96 MiB, same loader inputs) was cross-checked at\r\n"
        "  build time and is not shipped.\r\n"
    ).encode("ascii")


def shz10_notice(manifest: dict, tar_names: dict[str, str], patches: list[str], revision: dict) -> bytes:
    lines = [
        "ShizukuDOS 10.0-dev - licence and source notice",
        "===============================================",
        "",
        "External (third-party) programs on this disc:",
    ]
    for name, spec in manifest["upstreams"].items():
        lines += [
            f"  {name}: {spec['ref']}, commit {spec['commit']}",
            f"    licence {spec['license']}, {spec['repository']}",
        ]
        if spec.get("distribution"):
            lines.append(f"    binaries: {spec['distribution']}, unmodified")
        for sub, info in spec.get("submodules", {}).items():
            lines.append(f"    submodule {sub}: commit {info['commit']} ({info['repository']})"
                         + (f", {info['license']}" if info.get("license") else ""))
    lines += [
        "",
        "Where they are: FreeDOS kernel + FreeCOM inside dos16\\shizukudos-dos16-",
        "hd32.img (and its copy SHZDOS\\DISK.IMG in efiboot.img); CSMWrap with",
        "SeaBIOS CSM in csm\\CSMWRAP.EFI (and \\EFI\\SHIZUKU\\CSMWRAP.EFI in",
        "efiboot.img); syslinux in \\isolinux\\ at the disc root.",
        "FreeDOS is built from source with local patches, CSMWrap from the pinned",
        "tree without patches, syslinux is the unmodified Ubuntu build. Licence",
        "texts are in LICENSES\\.",
        "",
        "Corresponding source, on this disc in SOURCE\\:",
    ]
    for name, tar_name in tar_names.items():
        lines.append(f"  {tar_name}   {name}")
    lines.append("  patches\\   FreeDOS patches, applied in this order:")
    lines += [f"    {patch}" for patch in patches]
    lines += [
        "  upstream-manifest.json   pinned commits, licences and build recipes",
        "  shizukudos-source.tar.gz   the Shizuku source that builds everything else",
        "                             here (build scripts, loader, Supervisor, kernels,",
        "                             media builders)",
        "",
        "Build toolchain: Open Watcom v2 snapshot, SHA-256",
        f"  {manifest['tools']['open-watcom-v2']['sha256']}",
        "  (Sybase Open Watcom Public License 1.0), NASM, mtools, gcc. The",
        "  toolchain itself is not redistributed on this disc.",
        "",
        "Project code (Supervisor, UEFI loader, Kernel32, Kernel64, Win64 runtime,",
        "test programs, build scripts) is GPL-2.0-only; the licence text is",
        "LICENSES\\Shizuku-LICENSE-GPL-2.0.txt. The 8x8 font is public domain",
        "(Daniel Hepper / IBM VGA lineage, header kept in the sources).",
        "",
        f"Shizuku source revision: git {revision['revision'] or 'unknown'}, branch {revision['branch'] or 'unknown'}.",
        "Working tree modified when built: " + ("yes" if revision["dirty"] else "no")
        + ". shizukudos-source.tar.gz holds the working-tree files that were built.",
        "",
        "No Microsoft code is in this directory.",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def stage_shizukudos10(work: Path, outputs: dict[str, Path], efi_members: dict[str, bytes]) -> tuple[dict[str, bytes], str]:
    """Everything that goes under ShizukuDOS10/, including the EFI boot image."""
    consistency = check_shizukudos10_outputs(outputs, work)
    manifest = json.loads((SHZ10 / "upstream" / "manifest.json").read_text(encoding="utf-8"))
    payload: dict[str, bytes] = {}
    for rel in SHZ10_STAGED:
        payload[f"{SHZ10_DIR}/{rel}"] = outputs[rel].read_bytes()
    for rel, name in SHZ10_RECEIPTS.items():
        payload[f"{SHZ10_DIR}/receipts/{name}"] = shipped_receipt(outputs[rel])
    for member, staged in ESP_CROSSCHECK.items():  # the EFI image carries exactly the checked bytes
        if efi_members[member] != payload[f"{SHZ10_DIR}/{staged}"]:
            raise RuntimeError(f"EFI image member {member} is not the checked build output {staged}")
    efi = build_efi_image(work, efi_members)
    payload[EFI_IMAGE] = efi
    payload[f"{SHZ10_DIR}/EFIBOOT.TXT"] = (
        "EFI boot image ShizukuDOS10\\efiboot.img (El Torito EFI entry; also GPT/MBR\r\n"
        "partition 2 when this ISO is used as a disk)\r\n"
        f"FAT16, label SHZESP, {len(efi)} bytes, sha256 {sha256(efi)}\r\n"
        "Contents:\r\n"
        + "".join(f"  {member}  {len(data)} bytes  sha256 {sha256(data)}\r\n"
                  for member, data in sorted(efi_members.items()))
    ).encode("ascii")
    # Licence texts, patches, pinned upstream sources and the Shizuku source.
    tar_names: dict[str, str] = {}
    for name, spec in manifest["upstreams"].items():
        if spec.get("kind") == "debian-binary-packages":
            payload.update(se_media.syslinux_payload(SHZ10_DIR) if name == "syslinux" else {})
            if name != "syslinux":
                raise RuntimeError(f"no source staging for the debian-binary-packages upstream {name}")
            tar_names[name] = f"{name}\\ (Debian source package: .dsc, .orig.tar.xz, .debian.tar.xz)"
            continue
        tree = pinned_upstream_tree(name, spec)
        for path in license_files(tree, spec):
            label = path.relative_to(tree).as_posix().replace("/", "-")
            payload[f"{SHZ10_DIR}/LICENSES/{name}-{label}.txt"] = path.read_bytes()
        tar_name = f"{name}-{spec['commit'][:12]}.tar.gz"
        payload[f"{SHZ10_DIR}/SOURCE/{tar_name}"] = deterministic_tar_gz(tracked_entries(tree, f"{name}-{spec['commit'][:12]}"))
        tar_names[name] = tar_name
    payload[f"{SHZ10_DIR}/LICENSES/Shizuku-LICENSE-GPL-2.0.txt"] = (ROOT / "LICENSE").read_bytes()
    patches = sorted((SHZ10 / "dos16" / "patches").glob("*.patch"))
    if not patches:
        raise RuntimeError("shizukudos/dos16/patches has no patches; the FreeDOS build recipe is incomplete")
    for patch in patches:
        payload[f"{SHZ10_DIR}/SOURCE/patches/{patch.name}"] = patch.read_bytes()
    payload[f"{SHZ10_DIR}/SOURCE/upstream-manifest.json"] = (SHZ10 / "upstream" / "manifest.json").read_bytes()
    top = "win98-modern-shizukudos10-source"
    source_entries: list[tuple[str, Path]] = [
        (top, ROOT), (f"{top}/docs", ROOT / "docs"), (f"{top}/tools", ROOT / "tools")]
    for relative in ("shizukudos", "docs/shizukudos10", "licenses", "tools/shizuku_se"):
        source_entries += tar_entries(ROOT / relative, f"{top}/{relative}")
    for relative in ("LICENSE", "tools/build_shizuku_se_iso.py", "tools/build_shizuku_se_disk.py",
                     "tools/shizuku_se_media.py", "tools/shizuku_se_drivers.py",
                     "tools/test_shizuku_se_boot_matrix.py"):
        if (ROOT / relative).is_file():
            source_entries.append((f"{top}/{relative}", ROOT / relative))
    payload[f"{SHZ10_DIR}/SOURCE/shizukudos-source.tar.gz"] = deterministic_tar_gz(source_entries)
    revision = {"revision": git_output("rev-parse", "HEAD"), "branch": git_output("rev-parse", "--abbrev-ref", "HEAD"),
                "dirty": bool(git_output("status", "--porcelain"))}
    payload[f"{SHZ10_DIR}/GPL-NOTICE.TXT"] = shz10_notice(manifest, tar_names, [p.name for p in patches], revision)
    payload[f"{SHZ10_DIR}/README.TXT"] = shz10_readme(outputs, len(efi))
    return payload, consistency


# ---------------------------------------------------------------------------
# SHZSE overlay installer for an already installed Windows 98
# ---------------------------------------------------------------------------

def dos_text(path: Path) -> bytes:
    text = path.read_text(encoding="ascii")  # the DOS shell needs plain ASCII
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")


def shzse_payload(artifacts: dict[str, Path]) -> dict[str, bytes]:
    files = {
        "SHZSE/INSTALL.BAT": dos_text(SHZSE_TEMPLATES / "INSTALL.BAT"),
        "SHZSE/README.TXT": dos_text(SHZSE_TEMPLATES / "README.TXT"),
    }
    for name in SHZSE_FILES:
        files[f"SHZSE/{name}"] = artifacts[name].read_bytes()
    return files


# ---------------------------------------------------------------------------
# --win98-media: the builder's OWN Windows 98 media, private ISO only
# ---------------------------------------------------------------------------

REQUIRED_MS_FILES = ("IO.SYS", "MSDOS.SYS", "COMMAND.COM")


def rmtree_force(path: Path) -> None:
    def fix(function, target, _info):
        os.chmod(target, 0o700)
        function(target)
    if path.exists():
        shutil.rmtree(path, onerror=fix)


def require_git_ignored(path: Path) -> None:
    """Microsoft files may only be written where git ignores them (build/)."""
    path = path.resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        return  # outside the repository
    result = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", str(path)])
    if result.returncode != 0:
        raise Win98MediaError(f"refusing to write Windows 98 files to {path}: it is not git-ignored")


def cab_member_names(path: Path) -> set[str]:
    """Upper-case member base names of a cabinet; empty if it is not a readable CAB."""
    try:
        data = path.read_bytes()
        if len(data) < 36 or data[:4] != b"MSCF":
            return set()
        count = struct.unpack_from("<H", data, 28)[0]
        cursor = struct.unpack_from("<I", data, 16)[0]
        names = set()
        for _ in range(count):
            end = data.find(b"\0", cursor + 16)
            if cursor + 16 > len(data) or end < 0:
                break
            name = data[cursor + 16:end].decode("cp437")
            names.add(name.replace("\\", "/").rsplit("/", 1)[-1].upper())
            cursor = end + 1
        return names
    except (OSError, struct.error):
        return set()


def walk_media(tree: Path) -> list[tuple[str, Path]]:
    files = []
    for dirpath, dirnames, filenames in os.walk(tree):
        dirnames.sort()
        for name in [*dirnames, *filenames]:
            if os.path.islink(os.path.join(dirpath, name)):
                raise Win98MediaError(f"the Windows 98 media contains a symbolic link ({name}); refusing to follow it")
        for name in sorted(filenames):
            path = Path(dirpath) / name
            files.append((path.relative_to(tree).as_posix(), path))
    return files


def find_win98_layout(tree: Path) -> dict:
    files = walk_media(tree)
    loose = {}
    for relative, _path in files:
        base = relative.rsplit("/", 1)[-1].upper()
        if base in REQUIRED_MS_FILES:
            loose.setdefault(base, relative)
    win98_dirs = set()
    for relative, _path in files:
        if relative.upper().endswith(".CAB") and "/" in relative:
            parent = relative.rsplit("/", 1)[0]
            if parent.rsplit("/", 1)[-1].upper() == "WIN98":
                win98_dirs.add(parent)
    cabs = sorted(path for relative, path in files
                  if relative.upper().endswith(".CAB") and "/" in relative and relative.rsplit("/", 1)[0] in win98_dirs)
    if not win98_dirs:
        raise Win98MediaError("no directory named WIN98 that contains .CAB files was found")
    found = {name: "loose file" for name in loose}
    missing = [name for name in REQUIRED_MS_FILES if name not in loose]
    if missing:
        members: set[str] = set()
        for cab in cabs:
            members |= cab_member_names(cab)
        for name in list(missing):
            if name in members:
                found[name] = "inside a WIN98 cabinet"
                missing.remove(name)
    if missing:
        raise Win98MediaError("not found as files or inside the WIN98 cabinets: " + ", ".join(missing))
    return {"required": {name: found[name] for name in REQUIRED_MS_FILES}, "cabinets": len(cabs),
            "files": len(files), "bytes": sum(path.stat().st_size for _, path in files)}


def tree_sha256(tree: Path) -> str:
    """Digest over sorted (path, size, sha256) records; identifies a directory as a whole."""
    digest = hashlib.sha256()
    for relative, path in walk_media(tree):
        digest.update(f"{relative}\0{path.stat().st_size}\0{sha256_path(path)}\n".encode("utf-8"))
    return digest.hexdigest()


def inspect_win98_media(media: Path, work: Path) -> dict:
    """Validate the user's Windows 98 ISO or directory. Only sha256/size/counts are recorded."""
    media = media.expanduser()
    if not media.exists():
        raise Win98MediaError(f"--win98-media path does not exist: {media}")
    info: dict = {"extracted": False}
    if media.is_dir():
        tree = media.resolve()
        info["kind"] = "directory"
    else:
        tree = work / "win98-media-tree"
        rmtree_force(tree)
        require_git_ignored(tree / "IO.SYS")
        result = subprocess.run(
            ["xorriso", "-osirrox", "on:auto_chmod_on", "-joliet", "on", "-indev", str(media),
             "-extract", "/", str(tree)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0 or not tree.is_dir() or not any(tree.iterdir()):
            rmtree_force(tree)
            raise Win98MediaError(f"{media} is not readable as an ISO 9660 image or a directory (xorriso failed)")
        info.update(kind="ISO image", extracted=True)
    try:
        layout = find_win98_layout(tree)
    except Win98MediaError as exc:
        if info["extracted"]:
            rmtree_force(tree)
        raise Win98MediaError(
            f"{media} is not usable Windows 98 media: {exc}. Supply your own Windows 98 ISO or the "
            "extracted media root that contains the WIN98 folder (IO.SYS, MSDOS.SYS and COMMAND.COM "
            "as files or inside the WIN98 cabinets). Nothing was built.") from exc
    info.update(tree=tree, files=layout["files"], total_bytes=layout["bytes"], required=layout["required"],
                cabinets=layout["cabinets"])
    if media.is_file():
        info.update(sha256=sha256_path(media), bytes=media.stat().st_size, identity="SHA-256 of the ISO file")
    else:
        info.update(sha256=tree_sha256(tree), bytes=layout["bytes"],
                    identity="SHA-256 over sorted path/size/sha256 records of the directory")
    return info


def place_win98_media(info: dict, stage: Path) -> None:
    destination = stage / "WIN98"
    require_git_ignored(destination / "IO.SYS")
    if info["extracted"]:
        shutil.move(str(info["tree"]), str(destination))
    else:
        shutil.copytree(info["tree"], destination, symlinks=False)


def media_summary(info: dict) -> str:
    required = ", ".join(f"{name} ({how})" for name, how in info["required"].items())
    return (
        f"kind {info['kind']}\n"
        f"{info['identity']}: {info['sha256']}\n"
        f"bytes {info['bytes']}\n"
        f"files {info['files']}, total file bytes {info['total_bytes']}, WIN98 cabinets {info['cabinets']}\n"
        f"required files present: {required}\n"
    )


def readme_text(media: dict | None, setup: bool) -> bytes:
    text = (
        "Windows 98 Shizuku Second Edition - VM install ISO\r\n"
        "\r\n"
        "One hybrid image: boot it as a CD, or write it raw to a USB stick / attach\r\n"
        "it as a hard disk. Legacy BIOS and UEFI (see VMPROFIL.TXT).\r\n"
        "\r\n"
        "Legacy BIOS -> boot menu (isolinux; also on COM1 115200 8N1):\r\n"
        "  K  Kernel64 + Win64 runtime: the standalone Long Mode kernel runs its\r\n"
        "     self-tests and every Win64 test program in WIN64.IMG (SHZ\\K64).\r\n"
        + ("  I  Install ShizukuDOS 10 (SHZ\\SETUP): unattended, ERASES the first disk\r\n"
           "     without a partition table, then powers off. See SHZ\\SETUP\\README.TXT.\r\n" if setup else "")
        + "  D  DOS16: ShizukuDOS 10 FreeDOS profile, the conformance disk image\r\n"
        "     (ShizukuDOS10\\dos16) in RAM through memdisk.\r\n"
        "  1  ShizukuDOS 0.1: the project's own shell, 1.44 MB floppy image\r\n"
        "     (ShizukuDOS\\shizukudos.img) in RAM through memdisk.\r\n"
        "UEFI x64 -> \\EFI\\BOOT\\BOOTX64.EFI, the Shizuku boot manager. Its menu waits\r\n"
        "  5 s: no key = the Supervisor with Intel VMX, otherwise CSMWrap and the\r\n"
        "  same legacy boot menu; K = Kernel64 direct (no CSM, no VMX, GOP).\r\n"
        "\r\n"
        "Other contents\r\n"
        "  Windows 98 Shizuku Second Edition\\  NTWrapper9x, NTWin32Wrapper9x and\r\n"
        "     NTWDDMWrapper9x binaries (also inside the 0.1 floppy).\r\n"
        "  SHZSE\\   overlay installer for an ALREADY INSTALLED Windows 98 (copies\r\n"
        "     the probe binaries to C:\\NTWLAB). Read SHZSE\\README.TXT first: the\r\n"
        "     VxD load is a recorded, unfixed failure.\r\n"
        "  DRIVERS\\ driver store: DRIVERS\\<package>\\ as shipped, HWIDS.TXT index.\r\n"
        "  ShizukuDOS10\\  ShizukuDOS 10 build outputs, receipts, licences, source.\r\n"
        "  VMPROFIL.TXT, HASHES.TXT, SOURCES.TXT, LIMITS.TXT\r\n"
        "\r\n"
        "What this disc does not do\r\n"
        "  ShizukuDOS (either profile) cannot replace IO.SYS and cannot install or\r\n"
        "  boot the Windows 98 GUI. This disc is not a Windows 98 installation and\r\n"
        "  no completed Windows 98 installation is claimed.\r\n"
    )
    if media is None:
        text += (
            "\r\nMicrosoft Windows files and product keys are not included\r\n"
            "(NOMSBASE.TXT). Rebuild with --win98-media to add your own copy.\r\n"
        )
    else:
        text += (
            "\r\nPRIVATE BUILD. WIN98\\ holds an unmodified copy of Windows 98 media\r\n"
            "supplied by whoever ran the builder (MSBASE.TXT). It is not for\r\n"
            "redistribution. This disc does not boot Windows 98 Setup.\r\n"
        )
    return text.encode("ascii")


def msbase_text(media: dict) -> bytes:
    return (
        "Windows 98 media overlay - PRIVATE\r\n"
        "This image contains files copied from Windows 98 media that the person\r\n"
        "running the builder supplied (--win98-media). They are under WIN98\\ and\r\n"
        "were not modified. Do not redistribute this image. Only sizes and\r\n"
        "hashes of the source are recorded here:\r\n"
        + "".join(line + "\r\n" for line in media_summary(media).splitlines())
        + "The boot menu still offers the ShizukuDOS entries, not Windows 98 Setup.\r\n"
        "The builder did not run Setup and installed nothing.\r\n"
    ).encode("ascii")


ISOLINUX_DIR = "isolinux"
K64_DIR = "SHZ/K64"


def boot_payload(syslinux: dict[str, Path], k64: dict[str, "se_media.Input"], setup: bool) -> dict[str, bytes]:
    """isolinux + modules + menu, and the Kernel64 Multiboot files the menu loads."""
    payload = {f"{ISOLINUX_DIR}/isolinux.bin": syslinux["isolinux.bin"].read_bytes(),
               f"{ISOLINUX_DIR}/memdisk": syslinux["memdisk"].read_bytes()}
    for name in se_media.SYSLINUX_MODULES:
        payload[f"{ISOLINUX_DIR}/{name}"] = syslinux[name].read_bytes()
    payload[f"{ISOLINUX_DIR}/isolinux.cfg"] = se_media.boot_menu(
        dos16_image=f"/{DOS16_ISO_PATH}", shzdos01_image="/ShizukuDOS/shizukudos.img", k64_dir=f"/{K64_DIR}",
        setup=setup)
    for name, item in k64.items():
        payload[f"{K64_DIR}/{name}"] = item.data
    payload[f"{K64_DIR}/README.TXT"] = (
        "SHZ\\K64 - standalone Kernel64 + Win64 runtime (boot menu entry K)\r\n"
        "BOOT.ELF       Multiboot (ELF32) stub; loaded by mboot.c32 or by QEMU:\r\n"
        "               qemu-system-x86_64 -kernel BOOT.ELF -initrd KERNEL64S.BIN,WIN64.IMG\r\n"
        "KERNEL64S.BIN  Kernel64 built with SHZ_STANDALONE (module 0)\r\n"
        "WIN64.IMG      ntdll, kernel32 and the other Win64 DLLs + T_*.EXE (module 1)\r\n"
        "No Supervisor and no VMX: this is Kernel64 on its own. The stub takes RAM\r\n"
        "and firmware holes from the Multiboot memory map; results go to COM1\r\n"
        "(SHZ-EXIT:0 = every self-test and every Win64 test program passed).\r\n"
        + "".join(f"{name:14} sha256 {sha256(item.data)}\r\n" for name, item in k64.items())
    ).encode("ascii")
    return payload


def stage_tree(stage: Path, floppy: bytes, artifacts: dict[str, Path], extra: dict[str, bytes],
               media: dict | None, setup: bool) -> dict[str, bytes]:
    if stage.exists():
        rmtree_force(stage)
    stage.mkdir(parents=True)
    payload: dict[str, bytes] = {
        "README.TXT": readme_text(media, setup),
        "VMPROFIL.TXT": se_media.vm_profiles_text().encode("ascii"),
        "SOURCES.TXT": sources_text(),
        "LIMITS.TXT": limits_text(),
    }
    if media is None:
        payload["NOMSBASE.TXT"] = (
            "Microsoft base omitted\r\n"
            "This image does not redistribute the Windows 98 file tree.\r\n"
            "Missing for a Microsoft setup: IO.SYS, MSDOS.SYS, COMMAND.COM,\r\n"
            "WIN98 cabinet files, and the OEM boot floppy drivers.\r\n"
            "To add your own copy, rebuild with --win98-media PATH (private image).\r\n"
        ).encode("ascii")
    else:
        payload["MSBASE.TXT"] = msbase_text(media)
    edition = "Windows 98 Shizuku Second Edition"
    payload.update({
        "ShizukuDOS/shizukudos.img": floppy,
        f"{edition}/EDITION.TXT": edition_text(),
        f"{edition}/LIMITS.TXT": limits_text(),
        f"{edition}/NTWrapper9x/NTWRAP9X.VXD": artifacts["NTWRAP9X.VXD"].read_bytes(),
        f"{edition}/NTWrapper9x/NTWQUERY.EXE": artifacts["NTWQUERY.EXE"].read_bytes(),
        f"{edition}/NTWin32Wrapper9x/NTW32.DLL": artifacts["NTW32.DLL"].read_bytes(),
        f"{edition}/NTWin32Wrapper9x/NTWPROBE.EXE": artifacts["NTWPROBE.EXE"].read_bytes(),
        f"{edition}/NTWDDMWrapper9x/NTWGPROB.EXE": artifacts["NTWGPROB.EXE"].read_bytes(),
        f"{edition}/NTWDDMWrapper9x/ntwddm-i386.o": artifacts["ntwddm-i386.o"].read_bytes(),
    })
    clash = set(payload) & set(extra)
    if clash:
        raise RuntimeError(f"two parts of the ISO want the same paths: {sorted(clash)[:5]}")
    payload.update(extra)
    lines = ["sha256  bytes  path\r\n"]
    for name in sorted(payload):
        data = payload[name]
        lines.append(f"{sha256(data)}  {len(data)}  {name}\r\n")
    payload["HASHES.TXT"] = "".join(lines).encode("ascii")
    for relative, data in payload.items():
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if media is not None:
        # Not in `payload` / HASHES.TXT: only the source's aggregate sha256 and size are recorded.
        place_win98_media(media, stage)
    return payload


VOLUME_ID = "W98SHIZUKU2"


def pin_stage_times(stage: Path) -> None:
    """Every file and directory of the stage gets the fixed epoch as mtime/atime: ISO 9660, Joliet and Rock
    Ridge directory records carry them, and SOURCE_DATE_EPOCH alone only fixes the volume dates."""
    for dirpath, dirnames, filenames in os.walk(stage, topdown=False):
        for name in filenames + dirnames:
            os.utime(os.path.join(dirpath, name), (FIXED_EPOCH, FIXED_EPOCH), follow_symlinks=False)
    os.utime(stage, (FIXED_EPOCH, FIXED_EPOCH))


def write_iso(stage: Path, iso_path: Path, isohdpfx: Path) -> None:
    iso_path.parent.mkdir(parents=True, exist_ok=True)
    pin_stage_times(stage)
    temporary = iso_path.with_suffix(".iso.partial")
    temporary.unlink(missing_ok=True)
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)  # fixed ISO timestamps and GPT GUIDs (build receipts carry build times)
    run([
        "xorriso", "-as", "mkisofs",
        "-iso-level", "3", "-J", "-joliet-long", "-R",
        "-V", VOLUME_ID,
        "-publisher", "Win98-Modern project",
        # Legacy BIOS: isolinux, no emulation, 4 x 512 bytes loaded, boot info table patched in.
        "-c", f"{ISOLINUX_DIR}/boot.cat",
        "-b", f"{ISOLINUX_DIR}/isolinux.bin",
        "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
        # Written to a disk: isohdpfx.bin MBR code, MBR partition 1 = the whole image.
        "-isohybrid-mbr", str(isohdpfx),
        # UEFI: the FAT image as El Torito platform 0xEF, and as MBR (0xEF) + GPT partition on a disk.
        "-eltorito-alt-boot",
        "-e", EFI_IMAGE, "-no-emul-boot",
        "-isohybrid-gpt-basdat",
        "-o", str(temporary),
        str(stage),
    ], env=env)
    temporary.replace(iso_path)


MEDIA_NAMES = {0: "no emulation", 1: "1.2MB floppy", 2: "1.44MB floppy", 3: "2.88MB floppy", 4: "hard disk"}


def el_torito_entries(iso: bytes) -> tuple[int, list[dict]]:
    """Boot catalog LBA and every boot entry (default entry first, then the sections)."""
    boot_record = iso[17 * 2048:18 * 2048]
    if boot_record[0] != 0:
        raise RuntimeError("volume descriptor at sector 17 is not a boot record")
    if boot_record[1:6] != b"CD001":
        raise RuntimeError("missing CD001 in the boot record")
    if not boot_record[7:39].startswith(b"EL TORITO SPECIFICATION"):
        raise RuntimeError("boot record is not El Torito")
    catalog_lba = struct.unpack_from("<I", boot_record, 0x47)[0]
    catalog = iso[catalog_lba * 2048:catalog_lba * 2048 + 2048]
    if catalog[0] != 1 or catalog[30:32] != b"\x55\xaa":
        raise RuntimeError("El Torito validation entry is invalid")
    if sum(struct.unpack_from("<16H", catalog, 0)) & 0xFFFF:
        raise RuntimeError("El Torito validation entry checksum is wrong")

    def entry(raw: bytes, platform: int, section: str) -> dict:
        return {
            "section": section, "platform": platform, "bootable": raw[0] == 0x88,
            "indicator": raw[0], "media": raw[1],
            "load_segment": struct.unpack_from("<H", raw, 2)[0],
            "sector_count": struct.unpack_from("<H", raw, 6)[0],
            "lba": struct.unpack_from("<I", raw, 8)[0],
        }

    entries = [entry(catalog[32:64], catalog[1], "default")]
    position = 64
    while position + 32 <= len(catalog) and catalog[position] in (0x90, 0x91):
        header = catalog[position:position + 32]
        count = struct.unpack_from("<H", header, 2)[0]
        for index in range(count):
            raw = catalog[position + 32 + 32 * index:position + 64 + 32 * index]
            entries.append(entry(raw, header[1], f"section platform 0x{header[1]:02x}"))
        position += 32 + 32 * count
        if header[0] == 0x91:
            break
    return catalog_lba, entries


def check_boot_info_table(iso: bytes, lba: int, isolinux: bytes) -> str:
    """isolinux.bin at the default entry's LBA, byte-identical except the 56-byte boot info table at 8,
    whose fields (El Torito / mkisofs convention) must describe this very file."""
    found = iso[lba * 2048:lba * 2048 + len(isolinux)]
    if found[:8] != isolinux[:8] or found[64:] != isolinux[64:]:
        raise RuntimeError("the BIOS boot image is not the pinned isolinux.bin")
    pvd, file_lba, length, checksum = struct.unpack_from("<IIII", found, 8)
    words = found[64:] + b"\0" * (-(len(found) - 64) % 4)
    expect = sum(struct.unpack(f"<{len(words) // 4}I", words)) & 0xFFFFFFFF
    if (pvd, file_lba, length, checksum) != (16, lba, len(isolinux), expect):
        raise RuntimeError(f"boot info table wrong: pvd {pvd} lba {file_lba} length {length} checksum {checksum:#x} "
                           f"(expected 16, {lba}, {len(isolinux)}, {expect:#x})")
    return (f"isolinux.bin at LBA {lba}: pinned bytes (sha256 {sha256(isolinux)}), boot info table "
            f"PVD 16, file LBA {lba}, length {length}, checksum {checksum:#010x} (recomputed)\n")


def parse_el_torito(iso: bytes, isolinux: bytes) -> tuple[str, dict]:
    catalog_lba, entries = el_torito_entries(iso)
    default = entries[0]
    if not default["bootable"] or default["platform"] != 0 or default["media"] != 0:
        raise RuntimeError(f"default El Torito entry must be a bootable BIOS no-emulation image: {default}")
    if default["sector_count"] != 4:
        raise RuntimeError(f"isolinux entry should load 4 sectors, catalog says {default['sector_count']}")
    report = (f"El Torito catalog LBA {catalog_lba}\n"
              f"default entry: boot indicator 0x88, platform 0x00 (BIOS), media type 0 (no emulation), "
              f"load segment 0x{default['load_segment']:04x} (0 = 0x07C0), 4 sectors, LBA {default['lba']}\n")
    report += check_boot_info_table(iso, default["lba"], isolinux)
    efi = [e for e in entries[1:] if e["platform"] == 0xEF]
    if len(efi) != 1:
        raise RuntimeError(f"expected exactly one EFI (platform 0xEF) El Torito entry, found {len(efi)}")
    efi = efi[0]
    if not efi["bootable"] or efi["media"] != 0:
        raise RuntimeError("the EFI El Torito entry is not a bootable no-emulation image")
    boot_sector = iso[efi["lba"] * 2048:efi["lba"] * 2048 + 512]
    if len(boot_sector) != 512 or boot_sector[510:512] != b"\x55\xaa" or boot_sector[0] not in (0xEB, 0xE9):
        raise RuntimeError("the EFI El Torito image is not a FAT volume (no jump/0x55AA boot sector)")
    report += (f"section entry: boot indicator 0x88, platform 0xEF (EFI), media type 0 (no emulation), sector count "
               f"{efi['sector_count']} (0 = to end of medium), image LBA {efi['lba']}, FAT OEM {boot_sector[3:11]!r}\n")
    return report, efi


def mbr_entries(sector0: bytes) -> list[dict]:
    out = []
    for index in range(4):
        raw = sector0[446 + 16 * index:462 + 16 * index]
        start, count = struct.unpack_from("<II", raw, 8)
        if count:
            out.append({"n": index + 1, "status": raw[0], "type": raw[4], "start": start, "sectors": count})
    return out


def check_hybrid(iso: bytes, isohdpfx: bytes, efi_lba: int, efi_len: int) -> str:
    """isohybrid: MBR boot code, MBR partitions 1 (whole image, active) and 2 (0xEF = the EFI image), GPT."""
    import zlib
    sector0 = iso[:512]
    if sector0[:432] != isohdpfx[:432] or sector0[510:512] != b"\x55\xaa":
        raise RuntimeError("sector 0 does not carry the pinned isohdpfx.bin MBR code")
    parts = mbr_entries(sector0)
    total = len(iso) // 512
    efi_start, efi_sectors = efi_lba * 4, efi_len // 512
    p1 = next((p for p in parts if p["n"] == 1), None)
    p2 = next((p for p in parts if p["n"] == 2), None)
    if not p1 or p1["status"] != 0x80 or p1["start"] != 0 or p1["sectors"] != total:
        raise RuntimeError(f"MBR partition 1 must be the active whole image (0..{total}): {parts}")
    if not p2 or p2["type"] != 0xEF or p2["start"] != efi_start or p2["sectors"] != efi_sectors:
        raise RuntimeError(f"MBR partition 2 must be type 0xEF at {efi_start}+{efi_sectors} (the EFI image): {parts}")
    header = iso[512:1024]
    if header[:8] != b"EFI PART":
        raise RuntimeError("no GPT header in sector 1")
    hsize, hcrc = struct.unpack_from("<II", header, 12)
    check = bytearray(header[:hsize])
    check[16:20] = b"\0\0\0\0"
    if zlib.crc32(bytes(check)) != hcrc:
        raise RuntimeError("GPT header CRC32 mismatch")
    array_lba, count, entry_size, array_crc = struct.unpack_from("<QIII", header, 72)
    array = iso[array_lba * 512:array_lba * 512 + count * entry_size]
    if zlib.crc32(array) != array_crc:
        raise RuntimeError("GPT partition array CRC32 mismatch")
    backup_lba = struct.unpack_from("<Q", header, 32)[0]
    if iso[backup_lba * 512:backup_lba * 512 + 8] != b"EFI PART":
        raise RuntimeError(f"no backup GPT header at LBA {backup_lba}")
    gpt = []
    for index in range(count):
        raw = array[index * entry_size:(index + 1) * entry_size]
        if raw[:16] == b"\0" * 16:
            continue
        first, last = struct.unpack_from("<QQ", raw, 32)
        gpt.append({"n": index + 1, "first": first, "last": last,
                    "name": raw[56:128].decode("utf-16-le").rstrip("\0")})
    if not any(p["first"] == efi_start and p["last"] == efi_start + efi_sectors - 1 for p in gpt):
        raise RuntimeError(f"no GPT partition covers the EFI image {efi_start}..{efi_start + efi_sectors - 1}: {gpt}")
    return (f"isohybrid MBR: isohdpfx.bin code (sha256 {sha256(isohdpfx)}), partitions "
            + "; ".join(f"{p['n']}: status 0x{p['status']:02x} type 0x{p['type']:02x} LBA {p['start']}+{p['sectors']}"
                        for p in parts)
            + f"\nGPT: header and array CRC32 valid, backup header at LBA {backup_lba}, entries "
            + "; ".join(f"{p['n']} {p['name']} {p['first']}..{p['last']}" for p in gpt) + "\n")


def verify_efi_image(iso: bytes, iso_efi: dict, payload: dict[str, bytes], members: dict[str, bytes],
                     evidence: Path) -> str:
    """The EFI image found through the boot catalog must equal the staged one, file by file."""
    expected = payload[EFI_IMAGE]
    from_catalog = iso[iso_efi["lba"] * 2048:iso_efi["lba"] * 2048 + len(expected)]
    if from_catalog != expected:
        raise RuntimeError("EFI image read via the El Torito catalog LBA differs from the staged image")
    image = evidence / "efiboot-from-catalog.img"
    image.write_bytes(from_catalog)
    count = se_media.verify_fat_members(str(image), members, evidence / "efi-readback")
    check = subprocess.run(["fsck.vfat", "-n", str(image)], capture_output=True, text=True)
    if check.returncode != 0:
        raise RuntimeError("fsck.vfat rejects the EFI image found through the catalog:\n" + check.stdout)
    image.unlink()
    return (f"EFI image via catalog LBA {iso_efi['lba']}: {len(expected)} bytes, byte-identical to the staged image "
            f"(sha256 {sha256(expected)}); {count} members read back identical: "
            + ", ".join(sorted(members)) + "\n  fsck.vfat -n: " + check.stdout.strip().splitlines()[-1] + "\n")


def trees_identical(expected: Path, actual: Path) -> int:
    """Same set of files with the same bytes; returns the file count."""
    left = dict(walk_media(expected))
    right = dict(walk_media(actual))
    if set(left) != set(right):
        raise RuntimeError(f"the WIN98/ overlay on the ISO has a different file set: "
                           f"{len(set(left) - set(right))} missing, {len(set(right) - set(left))} unexpected")
    for relative in sorted(left):
        if not filecmp.cmp(left[relative], right[relative], shallow=False):
            raise RuntimeError(f"the WIN98/ overlay on the ISO differs in content: {relative}")
    return len(left)


def verify_iso(iso_path: Path, payload: dict[str, bytes], efi_members: dict[str, bytes], syslinux: dict[str, Path],
               evidence: Path, media_stage: Path | None = None) -> str:
    iso = iso_path.read_bytes()
    report, efi_entry = parse_el_torito(iso, syslinux["isolinux.bin"].read_bytes())
    report += check_hybrid(iso, syslinux["isohdpfx.bin"].read_bytes(), efi_entry["lba"], len(payload[EFI_IMAGE]))
    listing = subprocess.check_output(["xorriso", "-indev", str(iso_path), "-find", "/", "-type", "f"], text=True,
                                      stderr=subprocess.DEVNULL)
    system = subprocess.check_output(["xorriso", "-indev", str(iso_path), "-report_el_torito", "plain",
                                      "-report_system_area", "plain"], text=True, stderr=subprocess.STDOUT)
    if not (re.search(r"El Torito boot img\s*:\s*1\s+BIOS\s+y\s+none", system)
            and re.search(r"El Torito boot img\s*:\s*2\s+UEFI\s+y\s+none", system)
            and "isohybrid" in system and "GPT" in system):
        raise RuntimeError("xorriso does not report BIOS entry 1, UEFI entry 2, isohybrid MBR and GPT:\n" + system)
    on_iso = {line[2:-1] for line in listing.splitlines() if line.startswith("'/") and line.endswith("'")}
    overlay = {name for name in on_iso if name.startswith("WIN98/")}
    if media_stage is None and overlay:
        raise RuntimeError("the public image unexpectedly contains WIN98/ files")
    unexpected = sorted(on_iso - overlay - set(payload) - {f"{ISOLINUX_DIR}/boot.cat"})
    absent = sorted(set(payload) - on_iso)
    if unexpected or absent:
        raise RuntimeError(f"ISO file list differs from the payload: unexpected {unexpected}, missing {absent}")
    extracted = evidence / "extracted"
    rmtree_force(extracted)
    extracted.mkdir(parents=True)
    command = ["xorriso", "-osirrox", "on", "-indev", str(iso_path)]
    for top in sorted({name.split("/", 1)[0] for name in payload}):
        command += ["-extract", f"/{top}", str(extracted / top)]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for relative, data in payload.items():
        found = extracted / relative
        if not found.is_file():
            raise RuntimeError(f"ISO is missing {relative}")
        got = found.read_bytes()
        if relative == f"{ISOLINUX_DIR}/isolinux.bin":
            got = got[:8] + data[8:64] + got[64:]  # the boot info table is patched in by design (checked above)
        if got != data:
            raise RuntimeError(f"ISO payload mismatch for {relative}")
    rmtree_force(extracted)
    report += verify_efi_image(iso, efi_entry, payload, efi_members, evidence)
    report += f"all {len(payload)} payload files extracted from the ISO are byte-identical to the staged files\n"
    if media_stage is not None:
        check = evidence / "win98-overlay-check"
        rmtree_force(check)
        try:
            subprocess.run(["xorriso", "-osirrox", "on:auto_chmod_on", "-indev", str(iso_path),
                            "-extract", "/WIN98", str(check)], check=True, stdout=subprocess.DEVNULL)
            compared = trees_identical(media_stage / "WIN98", check)
        finally:
            rmtree_force(check)
        report += f"WIN98/ overlay: {compared} files extracted from the ISO are byte-identical to the staged media copy\n"
    report += "xorriso -report_el_torito / -report_system_area plain:\n" + system
    if media_stage is None:
        report += "\nfiles:\n" + listing
    else:
        shown = "".join(line + "\n" for line in listing.splitlines() if not line.startswith("'/WIN98/"))
        report += f"\nfiles ({len(overlay)} files under /WIN98 are not listed):\n" + shown
    (evidence / "layout.txt").write_text(report, encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--win98-media", type=Path, metavar="PATH",
        help="your OWN Windows 98 ISO or extracted directory; overlaid under WIN98/ in a separate PRIVATE "
             "image (never the public one). IO.SYS, MSDOS.SYS, COMMAND.COM and a WIN98 cabinet folder "
             "are required. Nothing Microsoft is copied into the repository.")
    parser.add_argument("--driver-package", action="append", default=[], metavar="DIR|PACKAGE=DIR",
                        help="copy this driver package unchanged to DRIVERS\\<package>\\ and index its INF "
                             "hardware IDs (repeatable). Use only packages you may redistribute.")
    parser.add_argument("--setup", type=Path, metavar="DIR",
                        help="install/mkpayload.py output directory to ship under \\SHZ\\SETUP (default: built into "
                             f"{se_media.rel(se_media.DEFAULT_SETUP_DIR)} with the shipped answer file); adds the "
                             "unattended Install menu entry")
    parser.add_argument("--no-setup", action="store_true", help="leave the installer and its menu entry off the medium")
    parser.add_argument("--loader", type=Path, help="UEFI loader to ship (default: the shizukudos build)")
    parser.add_argument("--csmwrap", type=Path, help="CSMWRAP.EFI to ship (default: shizukudos/csm/build.py output)")
    parser.add_argument("--boot-mode", choices=se_media.BOOT_MODES, default="auto",
                        help="mode written to \\EFI\\SHIZUKU\\BOOT.INI (read by the loader's boot manager)")
    parser.add_argument("--reuse-builds", action="store_true",
                        help="package the existing build/shizukudos outputs instead of rebuilding them "
                             "(they are still checked against their build receipts)")
    parser.add_argument("--output", type=Path, metavar="ISO", help="output ISO path (default under build/)")
    parser.add_argument("--skip-qemu", action="store_true",
                        help="accepted for compatibility; the builder runs no QEMU. Boot evidence: "
                             "tools/test_shizuku_se_boot_matrix.py")
    args = parser.parse_args()
    private = args.win98_media is not None
    tag = PRIVATE_SUFFIX if private else ""
    stage_root = BUILD / f"shizuku-second-edition{tag}-stage" if private else STAGE_ROOT
    media_work = BUILD / "shizuku-second-edition-media-work"
    work = BUILD / f"shizuku-second-edition{tag}-work"
    evidence = BUILD / f"shizuku-second-edition-evidence{tag}"
    iso_path = (args.output or BUILD / (ISO_NAME.replace(".iso", f"{tag}.iso") if private else ISO_NAME)).resolve()
    summary_path = iso_path.with_suffix(".txt")   # receipt and summary sit next to the ISO they describe
    receipt_path = iso_path.with_suffix(".json")
    media = None
    try:
        if private:
            # Validate first: nothing is built for unusable media.
            require_git_ignored(iso_path)
            require_git_ignored(stage_root / "WIN98" / "IO.SYS")
            media = inspect_win98_media(args.win98_media, media_work)
        evidence.mkdir(parents=True, exist_ok=True)
        outputs = build_shizukudos10(args.reuse_builds)
        loader = se_media.loader_input(args.loader)
        csm = se_media.csmwrap_input(args.csmwrap)
        k64 = se_media.k64_inputs()
        shzdos = se_media.shzdos_inputs()
        syslinux = se_media.syslinux()
        if args.no_setup:
            setup_files, setup_info = {}, {"present": False, "note": "--no-setup"}
        else:
            if args.setup is None and not (args.reuse_builds and
                                           (se_media.DEFAULT_SETUP_DIR / se_media.SETUP_MAIN).is_file()):
                print("== install/mkpayload.py --out " + se_media.rel(se_media.DEFAULT_SETUP_DIR), flush=True)
                se_media.build_install_payload()
            setup_files, setup_info = se_media.setup_payload(args.setup)
        store, store_manifest = se_media.driver_store(args.driver_package)
        artifacts = build_components(work)
        floppy = build_floppy(work, artifacts)
        (work / "shizukudos.img").write_bytes(floppy)
        efi_members = se_media.efi_members(loader, csm, shzdos, args.boot_mode)
        shz10_payload, consistency = stage_shizukudos10(work, outputs, efi_members)
        extra = {**shz10_payload, **shzse_payload(artifacts), **store, **setup_files,
                 **boot_payload(syslinux, k64, bool(setup_files))}
        payload = stage_tree(stage_root, floppy, artifacts, extra, media, bool(setup_files))
        write_iso(stage_root, iso_path, syslinux["isohdpfx.bin"])
        report = verify_iso(iso_path, payload, efi_members, syslinux, evidence, stage_root if media else None)
        digest = sha256_path(iso_path)
        size = iso_path.stat().st_size
    except (Win98MediaError, se_media.drivers.DriverPackageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        # The ISO holds everything the stage held, and the work files are rebuilt every time: keep build/ small.
        # A private build also never leaves a second copy of the user's files lying around.
        rmtree_force(stage_root)
        rmtree_force(work)
        if private:
            rmtree_force(media_work)
    inputs = [loader, csm, *k64.values(), *shzdos.values()]
    receipt = {
        "iso": str(iso_path), "bytes": size, "sha256": digest, "private": private,
        "volume_id": VOLUME_ID, "source_date_epoch": FIXED_EPOCH, "boot_mode": args.boot_mode,
        "git": {"revision": git_output("rev-parse", "HEAD"), "dirty": bool(git_output("status", "--porcelain"))},
        "inputs": [item.record() for item in inputs],
        "syslinux": se_media.syslinux_spec()["distribution"],
        "setup": setup_info,
        "drivers": [{"package": p["package"], "files": len(p["files"]), "hardware_ids": len(p["hardware_ids"])}
                    for p in store_manifest["packages"]],
        "menu": {"dos16": f"/{DOS16_ISO_PATH}", "shzdos01": "/ShizukuDOS/shizukudos.img", "k64_dir": f"/{K64_DIR}",
                 "keys": se_media.MENU_KEYS, "setup_entry": bool(setup_files),
                 "uefi": {"boot_ini": {"mode": args.boot_mode, "menu_timeout": se_media.MENU_TIMEOUT},
                          "keys": {"auto": "a", "k64direct": "k", "csm": "c", "supervisor": "s"}}},
        "efi_members": {name: {"bytes": len(data), "sha256": sha256(data)} for name, data in sorted(efi_members.items())},
        "payload_files": len(payload),
    }
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    private_note = (
        "PRIVATE image: it contains the builder's own Windows 98 files. Do not distribute it.\n"
        "Windows 98 media (only hashes and sizes are recorded):\n" + media_summary(media)
        if media else ""
    )
    summary = (
        f"{iso_path}\n"
        f"bytes {size}\n"
        f"sha256 {digest}\n"
        f"{private_note}"
        + f"SHZSETUP: {'present, ' + str(len(setup_info['files'])) + ' files' if setup_info['present'] else setup_info['note']}\n"
        f"driver packages: {len(store_manifest['packages'])}\n"
        f"{consistency}\n"
        f"{report}\n"
        f"receipt {receipt_path}\n"
        "Boot evidence: python3 tools/test_shizuku_se_boot_matrix.py\n"
    )
    summary_path.write_text(summary, encoding="utf-8")
    print(summary[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
