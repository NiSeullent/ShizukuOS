#!/usr/bin/env python3
"""Build a bootable Windows 98 Shizuku Second Edition project ISO.

One ISO carries two separate boot profiles. They are never mixed under one
label (docs/shizukudos10/BASELINE.md section 5):

- BIOS, El Torito default entry: ShizukuDOS 0.1, the project's own FAT12 1.44
  MiB floppy image (media type 2, floppy emulation).
- UEFI x64, El Torito EFI entry (platform 0xEF, no emulation): ShizukuDOS
  10.0-dev, the external FreeDOS profile. The EFI image is a FAT image holding
  EFI/BOOT/BOOTX64.EFI (the Shizuku Supervisor loader) plus the \\SHZDOS files
  the loader reads from its own volume (DISK.IMG, KERNEL32.BIN, KERNEL64.BIN,
  WIN64.IMG). The multikernel domains need Intel VMX; the loader refuses
  otherwise. ShizukuDOS 10.0 is rebuilt with
  `shizukudos/tools/shz.py build --profile uefi-multikernel` on every run.

The ISO9660/Joliet tree also carries the Second Edition payload (built
NTWrapper9x, NTWin32Wrapper9x and NTWDDMWrapper9x artifacts), the SHZSE
overlay installer for an already installed Windows 98, and the GPL license
and corresponding-source files for the FreeDOS parts. Neither profile
replaces IO.SYS or installs the Windows 98 GUI.

Microsoft installation files are never packaged by default. `--win98-media
PATH` overlays the builder's OWN Windows 98 ISO or extracted directory under
WIN98/ in a separate, private ISO (git-ignored build/ only; do not share it).

Layout sources recorded in SOURCES.TXT on the image:
- "El Torito" Bootable CD-ROM Format Specification 1.0 (Phoenix/IBM, 1995),
  media type 2 = 1.44 MB floppy emulation.
  https://pdos.csail.mit.edu/6.828/2018/readings/boot-cdrom.pdf
- Microsoft KB Q167685 (media byte 0x02 is a 1.44 MB floppy).
  https://helparchive.huntertur.net/document/106908
- ECMA-119 / ISO 9660.
  https://ecma-international.org/publications-and-standards/standards/ecma-119/
- xorriso mkisofs emulation: a 1440 KiB -b image selects floppy emulation.
  Do not pass -no-emul-boot or -boot-info-table; the info table would
  overwrite FAT BPB bytes at offset 8.
  https://wiki.osdev.org/Mkisofs
  https://wiki.osdev.org/El-Torito
- Windows 98 installation CDs boot that embedded floppy as drive A. Reading
  the rest of the CD still needs a CD-ROM driver, which ShizukuDOS does not
  implement. https://www.vogons.org/viewtopic.php?t=102014
- FAT12 geometry matches shizukudos/boot.asm: 512-byte sectors, 2880 sectors,
  18 sectors/track, 2 heads (1.44 MiB). Microsoft FAT specification:
  https://www.win.tue.nl/~aeb/linux/fs/fat/fatgen103.pdf
"""
from __future__ import annotations

import argparse
import filecmp
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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


def load_qemu_tools():
    """Portable QEMU/OVMF discovery shared with ShizukuDOS 10.0 (shizukudos/tools/qemu.py)."""
    path = SHZ10 / "tools" / "qemu.py"
    spec = importlib.util.spec_from_file_location("shizuku_qemu_tools", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


qemu_tools = load_qemu_tools()


def find_qemu() -> Path:
    """shizukudos/tools/qemu.py DEFAULT_QEMU, else any qemu-system-x86_64 on PATH."""
    candidate = Path(qemu_tools.DEFAULT_QEMU)
    if candidate.is_file():
        return candidate
    found = shutil.which("qemu-system-x86_64")
    return Path(found) if found else candidate


QEMU = find_qemu()


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
    return (
        "Windows 98 Shizuku Second Edition\r\n"
        "Two SEPARATE boot profiles are on this disc. Different code.\r\n"
        "1. BIOS boot: ShizukuDOS 0.1 (own code) = this FAT12 floppy image.\r\n"
        "2. UEFI x64 boot: ShizukuDOS 10.0-dev (external FreeDOS profile).\r\n"
        "   Not on this floppy. It needs Intel VMX to run its multikernel\r\n"
        "   domains; without VMX the UEFI loader refuses and returns.\r\n"
        "Embedded on this floppy: NTW32.DLL NTWRAP9X.VXD NTWGPROB.EXE\r\n"
        "ShizukuDOS does not replace IO.SYS and does not install or boot the\r\n"
        "Windows 98 GUI. No completed Windows 98 installation is claimed.\r\n"
        "Microsoft setup files are not on this floppy or in the public disc.\r\n"
    ).encode("ascii")


def limits_text() -> bytes:
    return (
        "LIMITS\r\n"
        "ShizukuDOS 0.1 (BIOS, this floppy): reads FAT12 root files and runs\r\n"
        "one 8.3 COM program. No MS-DOS 7.1, MSCDEX or CD-ROM driver.\r\n"
        "BOOT and BOOTC only chainload an existing hard-disk boot sector.\r\n"
        "ShizukuDOS 10.0-dev (UEFI x64, FreeDOS profile, see the disc):\r\n"
        "the loader needs Intel VMX with EPT and unrestricted guest. AMD SVM\r\n"
        "is detected but has no backend. A VM without nested VMX is refused.\r\n"
        "Its DOS16 disk is a conformance test disk, not a Windows installer.\r\n"
        "Neither profile replaces IO.SYS or installs or boots the Win98 GUI.\r\n"
        "This is not a completed Windows 98 installation.\r\n"
        "NTWRAP9X.VXD: the project docs record a failed VxD load on Windows 98\r\n"
        "(Win32 error 2, VXDLDR error 6). See SHZSE\\README.TXT on the disc.\r\n"
    ).encode("ascii")


def sources_text() -> bytes:
    return (
        "Layout sources checked while building this image\r\n"
        "1. El Torito Bootable CD-ROM Format Specification 1.0, Phoenix/IBM, 1995.\r\n"
        "   Media type 2 is 1.44 MB floppy emulation. Boot indicator 0x88.\r\n"
        "   https://pdos.csail.mit.edu/6.828/2018/readings/boot-cdrom.pdf\r\n"
        "2. Microsoft KB Q167685. Media byte 0x02 is a 1.44 MB floppy.\r\n"
        "   https://helparchive.huntertur.net/document/106908\r\n"
        "3. ECMA-119, volume and file structure of CD-ROM (ISO 9660).\r\n"
        "   https://ecma-international.org/publications-and-standards/standards/ecma-119/\r\n"
        "4. xorriso -as mkisofs. A 1440 KiB -b image uses floppy emulation.\r\n"
        "   -boot-info-table is not used because it overwrites BPB offset 8.\r\n"
        "   https://wiki.osdev.org/Mkisofs\r\n"
        "   https://wiki.osdev.org/El-Torito\r\n"
        "5. Windows 98 bootable CDs expose the embedded floppy as drive A.\r\n"
        "   CD directory access still requires a CD-ROM driver.\r\n"
        "   https://www.vogons.org/viewtopic.php?t=102014\r\n"
        "6. FAT12 BPB geometry is the ShizukuDOS boot sector: 512x2880, 18x2.\r\n"
        "   https://www.win.tue.nl/~aeb/linux/fs/fat/fatgen103.pdf\r\n"
        "7. UEFI boot entry, checked on the build host with the local tools:\r\n"
        "   xorriso 1.5.x -eltorito-alt-boot -e IMAGE -no-emul-boot writes an\r\n"
        "   El Torito section with platform id 0xEF. For an image over 65535\r\n"
        "   512-byte sectors xorriso records sector count 0 (\"extend the ESP to\r\n"
        "   end-of-medium\"), as its own warning states. The ISO parser in\r\n"
        "   tools/build_shizuku_se_iso.py reads the catalog bytes directly.\r\n"
        "8. What the UEFI loader reads from its own volume: in the project tree,\r\n"
        "   shizukudos/supervisor/loader/loader.c load_file() and\r\n"
        "   shizukudos/supervisor/build.py build_esp(): \\SHZDOS\\DISK.IMG,\r\n"
        "   KERNEL32.BIN, KERNEL64.BIN, WIN64.IMG next to EFI\\BOOT\\BOOTX64.EFI.\r\n"
        "9. Windows 98 guest procedure for SHZSE: platform/win98lab/README.md,\r\n"
        "   ntwrapper/vxd/README.md, docs/NATIVE_FIRST_TRIAL.md,\r\n"
        "   docs/NATIVE_GDI_TRIAL.md, docs/VXD_V86_LOADER_TRIAL.md.\r\n"
        "\r\n"
        "Referenced but NOT re-read while building (uefi.org and other hosts are\r\n"
        "unreachable from the build container; verify before relying on them):\r\n"
        "- UEFI Specification 2.10, chapter 13 (El Torito, platform id 0xEF, the\r\n"
        "  boot image is a FAT file system). https://uefi.org/specs/UEFI/2.10/\r\n"
        "- GNU GPL version 2. The texts shipped on this disc are the copies from\r\n"
        "  the pinned FreeDOS trees (ShizukuDOS10\\LICENSES).\r\n"
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
# ShizukuDOS 10.0-dev (external FreeDOS profile): build, stage, EFI image
# ---------------------------------------------------------------------------

# Build outputs (relative to build/shizukudos) that are staged under ShizukuDOS10/.
SHZ10_STAGED = (
    "dos16/shizukudos-dos16-hd32.img",
    "kernel32/KERNEL32.BIN",
    "kernel64/KERNEL64.BIN",
    "win64/WIN64.IMG",
    "supervisor/BOOTX64.EFI",
)
# supervisor/esp.img (96 MiB, same five files) is only cross-checked, not shipped:
# the ISO carries a size-fitted EFI image built from the very same bytes.
SHZ10_ESP = "supervisor/esp.img"
SHZ10_RECEIPTS = {
    "dos16/build-result.json": "dos16-build-result.json",
    "supervisor/build-result.json": "supervisor-build-result.json",
    "kernels-build-result.json": "kernels-build-result.json",
}
# Path inside the EFI FAT volume -> path of the same bytes in the ISO tree.
# The loader reads \SHZDOS\DISK.IMG, KERNEL32.BIN, KERNEL64.BIN, WIN64.IMG from
# the volume it was loaded from (shizukudos/supervisor/loader/loader.c) and
# shizukudos/supervisor/build.py build_esp() lays them out the same way.
EFI_MEMBERS = {
    "EFI/BOOT/BOOTX64.EFI": f"{SHZ10_DIR}/supervisor/BOOTX64.EFI",
    "SHZDOS/DISK.IMG": f"{SHZ10_DIR}/dos16/shizukudos-dos16-hd32.img",
    "SHZDOS/KERNEL32.BIN": f"{SHZ10_DIR}/kernel32/KERNEL32.BIN",
    "SHZDOS/KERNEL64.BIN": f"{SHZ10_DIR}/kernel64/KERNEL64.BIN",
    "SHZDOS/WIN64.IMG": f"{SHZ10_DIR}/win64/WIN64.IMG",
}
MIB = 1024 * 1024


def build_shizukudos10() -> dict[str, Path]:
    """Rebuild ShizukuDOS 10.0-dev and return its outputs. Any failure is fatal."""
    command = [sys.executable, "shizukudos/tools/shz.py", "build", "--profile", "uefi-multikernel"]
    print("== " + " ".join(command), flush=True)
    try:
        subprocess.run(command, cwd=ROOT, check=True, timeout=1800)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"ShizukuDOS 10.0 build failed ({exc}); refusing to package stale or partial outputs"
        ) from exc
    outputs = {rel: SHZ10_BUILD / rel for rel in (*SHZ10_STAGED, SHZ10_ESP, *SHZ10_RECEIPTS)}
    missing = [rel for rel, path in outputs.items() if not path.is_file()]
    if missing:
        raise RuntimeError("ShizukuDOS 10.0 build did not produce: " + ", ".join(missing))
    return outputs


def mtools_env() -> dict[str, str]:
    env = dict(os.environ)
    env["MTOOLS_SKIP_CHECK"] = "1"
    env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)
    return env


def mcopy_out(image: Path, member: str, destination: Path) -> bytes:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    subprocess.run(["mcopy", "-i", str(image), f"::/{member}", str(destination)],
                   check=True, env=mtools_env(), stdout=subprocess.DEVNULL)
    return destination.read_bytes()


def check_shizukudos10_outputs(outputs: dict[str, Path], work: Path) -> str:
    """The staged files must be the ones the build receipt and the prebuilt esp.img describe."""
    receipt = json.loads(outputs["supervisor/build-result.json"].read_text(encoding="utf-8"))["artifacts"]
    receipt_keys = {
        "supervisor/BOOTX64.EFI": "BOOTX64.EFI",
        SHZ10_ESP: "esp.img",
        "dos16/shizukudos-dos16-hd32.img": "disk.img (input)",
        "kernel32/KERNEL32.BIN": "KERNEL32.BIN (input)",
        "kernel64/KERNEL64.BIN": "KERNEL64.BIN (input)",
        "win64/WIN64.IMG": "WIN64.IMG (input)",
    }
    lines = []
    for rel, key in receipt_keys.items():
        actual = sha256_path(outputs[rel])
        if key not in receipt or receipt[key]["sha256"] != actual:
            raise RuntimeError(f"{rel} does not match supervisor/build-result.json ({key}); the outputs are inconsistent")
        lines.append(f"{rel} matches supervisor/build-result.json")
    # The prebuilt ESP must hold exactly the bytes that are about to be staged.
    scratch = work / "esp-crosscheck"
    for member, staged in EFI_MEMBERS.items():
        rel = staged[len(SHZ10_DIR) + 1:]
        if mcopy_out(outputs[SHZ10_ESP], member, scratch / member) != outputs[rel].read_bytes():
            raise RuntimeError(f"supervisor/esp.img ::/{member} differs from {rel}")
    lines.append("supervisor/esp.img holds the same five files")
    shutil.rmtree(scratch, ignore_errors=True)
    return "\n".join(lines)


def build_efi_image(work: Path, members: dict[str, bytes]) -> bytes:
    """FAT16 image (1 KiB clusters) sized to its content. members: FAT path -> bytes."""
    total = sum(len(data) for data in members.values())
    size_mib = -(-(total + 3 * MIB) // MIB)
    source = work / "efi-src"
    if source.exists():
        shutil.rmtree(source)
    image = work / "efiboot.img"
    image.unlink(missing_ok=True)
    with open(image, "wb") as handle:
        handle.truncate(size_mib * MIB)
    mkfs = ["mkfs.vfat", "-F", "16", "-s", "2", "-n", "SHZESP", "-i", "53485A45"]
    help_text = subprocess.run(["mkfs.vfat", "--help"], capture_output=True, text=True)
    if "--invariant" in (help_text.stdout + help_text.stderr):
        mkfs.insert(1, "--invariant")  # constant timestamps: reproducible image
    subprocess.run([*mkfs, str(image)], check=True, stdout=subprocess.DEVNULL, env=mtools_env())
    env = mtools_env()
    directories = sorted({str(Path(name).parent.as_posix()) for name in members} | {"EFI", "SHZDOS"},
                         key=lambda d: (d.count("/"), d))
    subprocess.run(["mmd", "-i", str(image), *[f"::/{d}" for d in directories if d != "."]], check=True, env=env)
    for name, data in members.items():
        local = source / name
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(data)
        subprocess.run(["mcopy", "-i", str(image), str(local), f"::/{name}"], check=True, env=env)
    shutil.rmtree(source)
    if shutil.which("fsck.vfat"):
        check = subprocess.run(["fsck.vfat", "-n", str(image)], capture_output=True, text=True)
        if check.returncode != 0:
            raise RuntimeError("fsck.vfat rejects the EFI image:\n" + check.stdout + check.stderr)
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


def deterministic_tar_gz(entries: list[tuple[str, Path]]) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for arcname, path in entries:
                info = tar.gettarinfo(str(path), arcname)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = FIXED_EPOCH
                info.mode = 0o755 if (info.isdir() or info.mode & 0o111) else 0o644
                if info.isreg():
                    with open(path, "rb") as handle:
                        tar.addfile(info, handle)
                else:
                    tar.addfile(info)
    return buffer.getvalue()


def git_output(*args: str, cwd: Path = ROOT) -> str:
    result = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def pinned_upstream_tree(name: str, spec: dict) -> Path:
    """The pinned upstream tree the FreeDOS binaries were built from, unmodified."""
    tree = BUILD / "upstream" / name
    if not tree.is_dir():
        raise RuntimeError(f"upstream tree {tree} is missing; the GPL source cannot be shipped")
    head = git_output("rev-parse", "HEAD", cwd=tree)
    if head != spec["commit"]:
        raise RuntimeError(f"{tree} is at {head or 'unknown'}, manifest pins {spec['commit']}")
    if git_output("status", "--porcelain", cwd=tree):
        raise RuntimeError(f"{tree} has local modifications; the shipped source would not match commit {spec['commit']}")
    return tree


def license_files(tree: Path, spec: dict) -> list[Path]:
    found: list[Path] = []
    for pattern in spec.get("license_files", []):
        found += [p for p in sorted(tree.glob(pattern)) if p.is_file()]
        if not found and "/" in pattern:  # "license/*" but the upstream license is a plain file "license"
            plain = tree / pattern.rsplit("/", 1)[0]
            if plain.is_file():
                found.append(plain)
    if not found:
        raise RuntimeError(f"no license file found in {tree} for {spec.get('license_files')}")
    return found


def shz10_readme(outputs: dict[str, Path], efi_size: int) -> bytes:
    digests = {rel: sha256_path(outputs[rel]) for rel in SHZ10_STAGED}
    return (
        "ShizukuDOS 10.0-dev - EXTERNAL-CODE profile (FreeDOS based)\r\n"
        "==========================================================\r\n"
        "\r\n"
        "This directory is a different product from ShizukuDOS 0.1, which is\r\n"
        "the project's own from-scratch code (..\\ShizukuDOS\\shizukudos.img,\r\n"
        "the BIOS El Torito entry). The two are not mixed under one label\r\n"
        "(docs/shizukudos10/BASELINE.md section 5, in SOURCE\\).\r\n"
        "\r\n"
        "Built by:  python3 shizukudos/tools/shz.py build --profile uefi-multikernel\r\n"
        "Boot path: UEFI x64 (El Torito EFI entry, platform 0xEF, no emulation)\r\n"
        "           -> EFI\\BOOT\\BOOTX64.EFI (Supervisor loader) -> Supervisor\r\n"
        "           (Intel VMX) -> virtual Real Mode DOS16 / Kernel32 / Kernel64.\r\n"
        "\r\n"
        "Files\r\n"
        "  efiboot.img                        FAT16 image used by the El Torito EFI\r\n"
        "                                     entry. It holds EFI\\BOOT\\BOOTX64.EFI and\r\n"
        "                                     SHZDOS\\DISK.IMG, KERNEL32.BIN,\r\n"
        "                                     KERNEL64.BIN, WIN64.IMG, which the loader\r\n"
        "                                     reads from its own volume. See EFIBOOT.TXT.\r\n"
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
        "  win64\\WIN64.IMG                    Win64 runtime + test apps (own code)\r\n"
        "  receipts\\                          build receipts of the three build steps\r\n"
        "  LICENSES\\, SOURCE\\, GPL-NOTICE.TXT license texts and corresponding source\r\n"
        "\r\n"
        "Requirements and limits\r\n"
        "  - UEFI x64 firmware with a GOP framebuffer.\r\n"
        "  - Intel VMX with EPT and unrestricted guest, enabled in firmware\r\n"
        "    setup. In a VM that means nested Intel VMX. Otherwise the loader\r\n"
        "    prints REFUSED and returns to the firmware.\r\n"
        "  - AMD SVM is detected, but no SVM backend exists: the loader refuses.\r\n"
        "  - A software CPU (QEMU TCG) has no VMX, so it only reaches that\r\n"
        "    refusal. Running the domains was not exercised when this disc was\r\n"
        "    built unless the build report says so.\r\n"
        "  - This profile does not replace IO.SYS and does not install or boot\r\n"
        "    the Windows 98 GUI. No Windows 98 installation is claimed.\r\n"
        "\r\n"
        "SHA-256 of the staged files (see also the HASHES.TXT at the disc root)\r\n"
        + "".join(f"  {digest}  {rel}\r\n" for rel, digest in digests.items())
        + f"  EFI image size {efi_size} bytes\r\n"
        "  supervisor/esp.img (96 MiB, same files) was cross-checked at build\r\n"
        "  time and is not shipped.\r\n"
    ).encode("ascii")


def shz10_notice(manifest: dict, tar_names: dict[str, str], patches: list[str], revision: dict) -> bytes:
    lines = [
        "ShizukuDOS 10.0-dev - license and source notice",
        "===============================================",
        "",
        "External (third-party) programs on this disc, inside",
        "dos16/shizukudos-dos16-hd32.img and its copy SHZDOS\\DISK.IMG in",
        "efiboot.img:",
    ]
    for name, spec in manifest["upstreams"].items():
        lines += [
            f"  {name}: {spec['ref']}, commit {spec['commit']}",
            f"    license {spec['license']}, {spec['repository']}",
        ]
        for sub, info in spec.get("submodules", {}).items():
            lines.append(f"    submodule {sub}: commit {info['commit']} ({info['repository']})")
    lines += [
        "",
        "These binaries were built from source with local patches. FreeDOS is",
        "licensed under GPL-2.0-or-later. The license texts are in LICENSES\\.",
        "",
        "Corresponding source (GPL-2.0 section 3a), on this disc in SOURCE\\:",
    ]
    for name, tar_name in tar_names.items():
        lines.append(f"  {tar_name}   pinned upstream tree of {name}, without .git")
    lines.append("  patches\\   applied in this order:")
    lines += [f"    {patch}" for patch in patches]
    lines += [
        "  upstream-manifest.json   pinned commits, licenses and build recipes",
        "  shizukudos-source.tar.gz   the Shizuku source that builds everything else",
        "                             here (build scripts, loader, Supervisor, kernels)",
        "",
        "Build toolchain: Open Watcom v2 snapshot, SHA-256",
        f"  {manifest['tools']['open-watcom-v2']['sha256']}",
        "  (Sybase Open Watcom Public License 1.0), NASM and mtools. The toolchain",
        "  itself is not redistributed on this disc.",
        "",
        "Project code (Supervisor, UEFI loader, Kernel32, Kernel64, Win64 runtime,",
        "test programs, build scripts) is GPL-2.0-only; the license text is",
        "LICENSES\\Shizuku-LICENSE-GPL-2.0.txt. The 8x8 font is public domain",
        "(Daniel Hepper / IBM VGA lineage, header kept in the sources).",
        "",
        f"Shizuku source revision: git {revision['revision'] or 'unknown'}, branch {revision['branch'] or 'unknown'}.",
        "Working tree modified when built: " + ("yes" if revision["dirty"] else "no")
        + ". shizukudos-source.tar.gz holds the working-tree files that were built.",
        "",
        "This notice covers ShizukuDOS10\\ only. No Microsoft code is in this",
        "directory.",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def stage_shizukudos10(work: Path, outputs: dict[str, Path]) -> tuple[dict[str, bytes], str]:
    """Everything that goes under ShizukuDOS10/, including the EFI boot image."""
    consistency = check_shizukudos10_outputs(outputs, work)
    manifest = json.loads((SHZ10 / "upstream" / "manifest.json").read_text(encoding="utf-8"))
    payload: dict[str, bytes] = {}
    for rel in SHZ10_STAGED:
        payload[f"{SHZ10_DIR}/{rel}"] = outputs[rel].read_bytes()
    for rel, name in SHZ10_RECEIPTS.items():
        payload[f"{SHZ10_DIR}/receipts/{name}"] = outputs[rel].read_bytes()
    # The EFI FAT image is made from exactly the bytes staged above.
    members = {member: payload[staged] for member, staged in EFI_MEMBERS.items()}
    efi = build_efi_image(work, members)
    payload[EFI_IMAGE] = efi
    payload[f"{SHZ10_DIR}/EFIBOOT.TXT"] = (
        "EFI boot image ShizukuDOS10\\efiboot.img (El Torito EFI entry)\r\n"
        f"FAT16, label SHZESP, {len(efi)} bytes, sha256 {sha256(efi)}\r\n"
        "Contents (the loader reads the SHZDOS files from its own volume):\r\n"
        + "".join(f"  {member}  {len(data)} bytes  sha256 {sha256(data)}\r\n" for member, data in members.items())
        + "Not a USB hybrid image: write it to CD/DVD or attach it as a CD.\r\n"
    ).encode("ascii")
    # GPL: license texts, patches, pinned upstream trees and the Shizuku source.
    tar_names: dict[str, str] = {}
    for name, spec in manifest["upstreams"].items():
        tree = pinned_upstream_tree(name, spec)
        for path in license_files(tree, spec):
            payload[f"{SHZ10_DIR}/LICENSES/{name}-{path.name}.txt"] = path.read_bytes()
        tar_name = f"{name}-{spec['commit'][:12]}.tar.gz"
        payload[f"{SHZ10_DIR}/SOURCE/{tar_name}"] = deterministic_tar_gz(tar_entries(tree, name))
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
    for relative in ("LICENSE", "tools/build_shizuku_se_iso.py"):
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


def readme_text(media: dict | None) -> bytes:
    text = (
        "Windows 98 Shizuku Second Edition project disc\r\n"
        "\r\n"
        "El Torito boot entries, in this order:\r\n"
        "  1. BIOS (default): ShizukuDOS 0.1, the project's own code, as a 1.44\r\n"
        "     MiB FAT12 floppy image (ShizukuDOS\\shizukudos.img).\r\n"
        "  2. UEFI x64: ShizukuDOS 10.0-dev, the external FreeDOS profile\r\n"
        "     (ShizukuDOS10\\efiboot.img: EFI\\BOOT\\BOOTX64.EFI Supervisor loader\r\n"
        "     and the \\SHZDOS files it reads). It needs Intel VMX to run its\r\n"
        "     multikernel domains and otherwise refuses and returns to firmware.\r\n"
        "The two profiles are separate products. They are not mixed under one\r\n"
        "label. See ShizukuDOS10\\README.TXT.\r\n"
        "\r\n"
        "Other contents\r\n"
        "  Windows 98 Shizuku Second Edition\\  NTWrapper9x, NTWin32Wrapper9x and\r\n"
        "     NTWDDMWrapper9x binaries. The same binaries are in the 0.1 floppy.\r\n"
        "  SHZSE\\   overlay installer for an ALREADY INSTALLED Windows 98 (copies\r\n"
        "     the probe binaries to C:\\NTWLAB). Read SHZSE\\README.TXT first: the\r\n"
        "     VxD load is a recorded, unfixed failure.\r\n"
        "  HASHES.TXT, SOURCES.TXT, LIMITS.TXT\r\n"
        "\r\n"
        "What this disc does not do\r\n"
        "  ShizukuDOS (either profile) cannot replace IO.SYS and cannot install or\r\n"
        "  boot the Windows 98 GUI. This disc is not a Windows 98 installation and\r\n"
        "  no completed Windows 98 installation is claimed. It is not a USB hybrid\r\n"
        "  image.\r\n"
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
        + "The BIOS entry still boots ShizukuDOS 0.1, not Windows 98 Setup.\r\n"
        "The builder did not run Setup and installed nothing.\r\n"
    ).encode("ascii")


def stage_tree(stage: Path, floppy: bytes, artifacts: dict[str, Path],
               extra: dict[str, bytes] | None = None, media: dict | None = None) -> dict[str, bytes]:
    if stage.exists():
        rmtree_force(stage)
    edition = stage / "Windows 98 Shizuku Second Edition"
    dos = stage / "ShizukuDOS"
    (edition / "NTWrapper9x").mkdir(parents=True)
    (edition / "NTWin32Wrapper9x").mkdir(parents=True)
    (edition / "NTWDDMWrapper9x").mkdir(parents=True)
    dos.mkdir(parents=True)
    payload: dict[str, bytes] = {
        "README.TXT": readme_text(media),
        "SOURCES.TXT": sources_text(),
        "LIMITS.TXT": limits_text(),
    }
    if media is None:
        payload["NOMSBASE.TXT"] = (
            "Microsoft base omitted\r\n"
            "vm/Win98-SE-ko-OEM.iso is not in this tree.\r\n"
            "build/win98-lab/win98se-ko-oem.iso does not resolve to a readable ISO.\r\n"
            "This image does not redistribute the Windows 98 file tree.\r\n"
            "Missing for a Microsoft setup: IO.SYS, MSDOS.SYS, COMMAND.COM,\r\n"
            "WIN98 cabinet files, and the OEM boot floppy drivers.\r\n"
            "To add your own copy, rebuild with --win98-media PATH (private image).\r\n"
        ).encode("ascii")
    else:
        payload["MSBASE.TXT"] = msbase_text(media)
    copies = {
        "ShizukuDOS/shizukudos.img": floppy,
        "Windows 98 Shizuku Second Edition/EDITION.TXT": edition_text(),
        "Windows 98 Shizuku Second Edition/LIMITS.TXT": limits_text(),
        "Windows 98 Shizuku Second Edition/NTWrapper9x/NTWRAP9X.VXD": artifacts["NTWRAP9X.VXD"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWrapper9x/NTWQUERY.EXE": artifacts["NTWQUERY.EXE"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWin32Wrapper9x/NTW32.DLL": artifacts["NTW32.DLL"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWin32Wrapper9x/NTWPROBE.EXE": artifacts["NTWPROBE.EXE"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWDDMWrapper9x/NTWGPROB.EXE": artifacts["NTWGPROB.EXE"].read_bytes(),
        "Windows 98 Shizuku Second Edition/NTWDDMWrapper9x/ntwddm-i386.o": artifacts["ntwddm-i386.o"].read_bytes(),
    }
    payload.update(copies)
    payload.update(extra or {})
    lines = ["sha256  bytes  path\r\n"]
    for name in sorted(payload):
        if name.endswith("HASHES.TXT"):
            continue
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


def write_iso(stage: Path, iso_path: Path) -> None:
    iso_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = iso_path.with_suffix(".iso.partial")
    if temporary.exists():
        temporary.unlink()
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)  # fixed ISO timestamps (the build receipts still carry build times)
    run([
        "xorriso", "-as", "mkisofs",
        "-iso-level", "3",
        "-J", "-R",
        "-V", "W98SHIZUKU2",
        "-publisher", "Win98-Modern project",
        # Entry 1 (default, BIOS): 1.44 MiB floppy emulation. Neither -no-emul-boot
        # nor -boot-info-table here: the info table would overwrite FAT BPB bytes.
        "-b", "ShizukuDOS/shizukudos.img",
        "-c", "ShizukuDOS/boot.cat",
        # Entry 2 (EFI, platform 0xEF): a FAT image, no emulation.
        "-eltorito-alt-boot",
        "-e", EFI_IMAGE,
        "-no-emul-boot",
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


def parse_el_torito(iso: bytes) -> str:
    catalog_lba, entries = el_torito_entries(iso)
    default = entries[0]
    if not default["bootable"]:
        raise RuntimeError("default El Torito entry is not bootable")
    if default["media"] != 2:
        raise RuntimeError(f"expected 1.44MB floppy emulation, media type is {default['media']}")
    if default["platform"] != 0:
        raise RuntimeError(f"default entry is not the BIOS (80x86) platform: 0x{default['platform']:02x}")
    report = (
        f"El Torito catalog LBA {catalog_lba}\n"
        f"boot indicator 0x88, platform 0x{default['platform']:02x}, media type {default['media']} "
        f"({MEDIA_NAMES[default['media']]})\n"
        f"load segment 0x{default['load_segment']:04x} (0 means 0x07C0), boot image LBA {default['lba']}\n"
        f"boot image OEM {iso[default['lba'] * 2048 + 3:default['lba'] * 2048 + 11]!r}\n"
    )
    efi = [e for e in entries[1:] if e["platform"] == 0xEF]
    if len(efi) != 1:
        raise RuntimeError(f"expected exactly one EFI (platform 0xEF) El Torito entry, found {len(efi)}")
    efi = efi[0]
    if not efi["bootable"] or efi["media"] != 0:
        raise RuntimeError("the EFI El Torito entry is not a bootable no-emulation image")
    boot_sector = iso[efi["lba"] * 2048:efi["lba"] * 2048 + 512]
    if len(boot_sector) != 512 or boot_sector[510:512] != b"\x55\xaa" or boot_sector[0] not in (0xEB, 0xE9):
        raise RuntimeError("the EFI El Torito image is not a FAT volume (no jump/0x55AA boot sector)")
    report += (
        f"boot indicator 0x88, platform 0x{efi['platform']:02x} (EFI), media type {efi['media']} "
        f"({MEDIA_NAMES[efi['media']]}), sector count {efi['sector_count']} "
        f"(0 = extend to end of medium), image LBA {efi['lba']}\n"
        f"EFI image FAT OEM {boot_sector[3:11]!r}\n"
    )
    return report


def verify_efi_image(iso: bytes, iso_efi: dict, payload: dict[str, bytes], evidence: Path) -> str:
    """The EFI image found through the boot catalog must equal the staged one, file by file."""
    expected = payload[EFI_IMAGE]
    from_catalog = iso[iso_efi["lba"] * 2048:iso_efi["lba"] * 2048 + len(expected)]
    if from_catalog != expected:
        raise RuntimeError("EFI image read via the El Torito catalog LBA differs from the staged image")
    image = evidence / "efiboot-from-catalog.img"
    image.write_bytes(from_catalog)
    lines = [f"EFI image via catalog LBA {iso_efi['lba']}: {len(expected)} bytes, byte-identical to the staged image "
             f"(sha256 {sha256(expected)})"]
    for member, staged in EFI_MEMBERS.items():
        data = mcopy_out(image, member, evidence / "efi-members" / member)
        if data != payload[staged]:
            raise RuntimeError(f"::/{member} inside the EFI image differs from {staged}")
        lines.append(f"  ::/{member} == {staged} ({len(data)} bytes)")
    if shutil.which("fsck.vfat"):
        check = subprocess.run(["fsck.vfat", "-n", str(image)], capture_output=True, text=True)
        if check.returncode != 0:
            raise RuntimeError("fsck.vfat rejects the EFI image found through the catalog:\n" + check.stdout)
        lines.append("  fsck.vfat -n: " + check.stdout.strip().splitlines()[-1])
    return "\n".join(lines) + "\n"


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


def verify_iso(iso_path: Path, payload: dict[str, bytes], evidence: Path, media_stage: Path | None = None) -> str:
    iso = iso_path.read_bytes()
    report = parse_el_torito(iso)
    _lba, entries = el_torito_entries(iso)
    listing = subprocess.check_output(
        ["xorriso", "-indev", str(iso_path), "-find", "/", "-type", "f"],
        text=True,
    )
    eltorito = subprocess.check_output(
        ["xorriso", "-indev", str(iso_path), "-report_el_torito", "plain"],
        text=True,
        stderr=subprocess.STDOUT,
    )
    if not (re.search(r"boot img\s*:\s*1\s+BIOS\s+y\s+fd1\.4", eltorito)
            and re.search(r"boot img\s*:\s*2\s+UEFI\s+y\s+none", eltorito)):
        raise RuntimeError("xorriso -report_el_torito does not show the BIOS floppy entry 1 and the UEFI entry 2:\n"
                           + eltorito)
    # Every file on the ISO must be a known payload file, and the reverse.
    on_iso = {line[2:-1] for line in listing.splitlines() if line.startswith("'/") and line.endswith("'")}
    overlay = {name for name in on_iso if name.startswith("WIN98/")}
    if media_stage is None and overlay:
        raise RuntimeError("the public image unexpectedly contains WIN98/ files")
    unexpected = sorted(on_iso - overlay - set(payload) - {"ShizukuDOS/boot.cat"})
    absent = sorted(set(payload) - on_iso)
    if unexpected or absent:
        raise RuntimeError(f"ISO file list differs from the payload: unexpected {unexpected}, missing {absent}")
    extracted = evidence / "extracted"
    if extracted.exists():
        rmtree_force(extracted)
    extracted.mkdir(parents=True)
    tops = sorted({name.split("/", 1)[0] for name in payload})
    command = ["xorriso", "-osirrox", "on", "-indev", str(iso_path)]
    for top in tops:
        command += ["-extract", f"/{top}", str(extracted / top)]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    for relative, data in payload.items():
        found = extracted / relative
        if not found.is_file():
            raise RuntimeError(f"ISO is missing {relative}")
        if found.read_bytes() != data:
            raise RuntimeError(f"ISO payload mismatch for {relative}")
    efi_entry = next(e for e in entries[1:] if e["platform"] == 0xEF)
    efi_report = verify_efi_image(iso, efi_entry, payload, evidence)
    boot = (extracted / "ShizukuDOS/shizukudos.img").read_bytes()
    report += f"embedded floppy sha256 {sha256(boot)}\n"
    report += f"all {len(payload)} payload files extracted from the ISO are byte-identical to the staged files\n"
    report += efi_report
    if media_stage is not None:
        # xorriso -compare_r also compares timestamps, which the fixed-date ISO does not keep,
        # so extract the overlay again and compare the bytes of every file.
        check = evidence / "win98-overlay-check"
        rmtree_force(check)
        try:
            subprocess.run(["xorriso", "-osirrox", "on:auto_chmod_on", "-indev", str(iso_path),
                            "-extract", "/WIN98", str(check)], check=True, stdout=subprocess.DEVNULL)
            compared = trees_identical(media_stage / "WIN98", check)
        finally:
            rmtree_force(check)
        report += f"WIN98/ overlay: {compared} files extracted from the ISO are byte-identical to the staged media copy\n"
    report += "xorriso -report_el_torito plain:\n" + eltorito
    if media_stage is None:
        report += "\nfiles:\n" + listing
    else:
        shown = "".join(line + "\n" for line in listing.splitlines() if not line.startswith("'/WIN98/"))
        report += f"\nfiles ({len(overlay)} files under /WIN98 are not listed):\n" + shown
    (evidence / "layout.txt").write_text(report, encoding="utf-8")
    return report


def strip_ansi(data: bytes) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", data.decode("latin-1")).replace("\r", "")


def qemu_uefi(iso_path: Path, evidence: Path, tag: str = "") -> str:
    """Boot the ISO through OVMF and read the loader's console output from the serial port.

    This QEMU run is TCG (no /dev/kvm here): it has no Intel VMX, so the expected result
    is the loader's own refusal. It does not run the DOS16/Kernel32/Kernel64 domains.
    """
    code = Path(qemu_tools.DEFAULT_OVMF_CODE)
    vars_source = Path(qemu_tools.DEFAULT_OVMF_VARS)
    if not QEMU.is_file():
        return f"QEMU binary {QEMU} is not present; UEFI boot was not exercised."
    if not code.is_file() or not vars_source.is_file():
        return f"OVMF firmware ({code}, {vars_source}) not found; UEFI boot was not exercised."
    vars_copy = evidence / "OVMF_VARS.fd"
    shutil.copyfile(vars_source, vars_copy)
    serial_log = evidence / "uefi-serial.txt"
    monitor_path = evidence / "uefi-monitor.sock"
    for path in (serial_log, monitor_path):
        path.unlink(missing_ok=True)
    process = subprocess.Popen(
        [
            str(QEMU),
            "-machine", "q35",
            "-accel", "tcg",
            "-cpu", "Nehalem",  # an Intel model: TCG has no VMX, the loader must refuse on the Intel path
            "-m", "512",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_copy}",
            "-cdrom", str(iso_path),
            "-vga", "std",
            "-display", "none",
            "-nic", "none",
            "-serial", f"file:{serial_log}",
            "-monitor", f"unix:{monitor_path},server=on,wait=off",
            "-no-reboot",
        ],
        stdout=subprocess.DEVNULL,
        stderr=open(evidence / "uefi-qemu.stderr", "wb"),
    )
    banner = "Supervisor loader (UEFI x64)"
    deadline = time.time() + 240
    text = ""
    try:
        while time.time() < deadline:
            if process.poll() is not None:
                break
            if serial_log.is_file():
                text = strip_ansi(serial_log.read_bytes())
                if banner in text and ("REFUSED" in text or "Handing over to the Supervisor" in text):
                    break
            time.sleep(0.5)
        if banner not in text:
            return ("UEFI boot did NOT reach the Shizuku Supervisor loader within 240 s "
                    f"(serial log {serial_log}, {len(text)} characters).\n")
        try:
            monitor = connect_unix(monitor_path, 5)
            save_png(monitor, evidence / "uefi.ppm", BUILD / f"windows98-shizuku-second-edition{tag}-uefi.png")
            png = f"PNG {BUILD / f'windows98-shizuku-second-edition{tag}-uefi.png'}\n"
        except Exception as exc:  # the screenshot is a convenience, the serial text is the evidence
            png = f"no UEFI screenshot ({exc})\n"
        seen = [line.strip() for line in text.splitlines()
                if any(key in line for key in ("Shizuku", "Virtualization", "REFUSED", "Handing over", "Enable Intel"))]
        outcome = ("the loader refused, as designed, for the reason quoted above (a software CPU has no "
                   "Intel VMX); the DOS16/Kernel32/Kernel64 domains were NOT run"
                   if "REFUSED" in text else
                   "the loader handed over to the Supervisor (VMX was available)")
        return (
            "QEMU TCG + OVMF booted the ISO through its El Torito EFI entry and ran BOOTX64.EFI from it:\n"
            + "".join(f"  serial: {line}\n" for line in seen)
            + f"Result: {outcome}.\n" + png
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def qemu_frames(iso_path: Path, evidence: Path, tag: str = "") -> str:
    if not QEMU.is_file():
        return f"QEMU binary {QEMU} is not present; no PNG captured."
    serial_path = evidence / "serial.sock"
    monitor_path = evidence / "monitor.sock"
    for path in (serial_path, monitor_path):
        if path.exists():
            path.unlink()
    serial_log = evidence / "serial.txt"
    boot_png = BUILD / f"windows98-shizuku-second-edition{tag}-boot.png"
    dir_png = BUILD / f"windows98-shizuku-second-edition{tag}-dir.png"
    process = subprocess.Popen(
        [
            str(QEMU),
            "-machine", "pc",
            "-accel", "tcg",
            "-m", "64",
            "-boot", "order=d,menu=off",
            "-cdrom", str(iso_path),
            "-vga", "std",
            "-display", "none",
            "-serial", f"unix:{serial_path},server=on,wait=off",
            "-monitor", f"unix:{monitor_path},server=on,wait=off",
            "-no-reboot",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        serial = connect_unix(serial_path, 10)
        monitor = connect_unix(monitor_path, 10)
        prompt = read_until(serial, b"A:\\> ", 30)
        save_png(monitor, evidence / "boot.ppm", boot_png)
        serial.sendall(b"DIR\r")
        # The shell prints 8.3 names with space padding: "NTW32   .DLL".
        prompt += read_until(serial, b"NTW32   .DLL", 10)
        prompt += read_until(serial, b"NTWRAP9X.VXD", 10)
        prompt += read_until(serial, b"NTWGPROB.EXE", 10)
        prompt += read_until(serial, b"A:\\> ", 10)
        save_png(monitor, evidence / "dir.ppm", dir_png)
        serial_log.write_bytes(prompt)
        return (
            "QEMU TCG (BIOS, El Torito default entry) reached the ShizukuDOS 0.1 prompt and DIR listed the embedded files.\n"
            f"PNG {boot_png}\n"
            f"PNG {dir_png}\n"
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def connect_unix(path: Path, timeout: float) -> socket.socket:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(str(path))
                sock.settimeout(2)
                return sock
            except OSError:
                sock.close()
        time.sleep(0.1)
    raise TimeoutError(f"socket not ready: {path}")


def read_until(sock: socket.socket, marker: bytes, timeout: float) -> bytes:
    deadline = time.time() + timeout
    data = bytearray()
    while time.time() < deadline:
        if marker in data:
            return bytes(data)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        data.extend(chunk)
    raise TimeoutError(f"did not see {marker!r}; got {bytes(data[-400:])!r}")


def save_png(monitor: socket.socket, ppm: Path, png: Path) -> None:
    command = f"screendump {ppm}\n".encode()
    try:
        monitor.recv(4096)
    except socket.timeout:
        pass
    monitor.sendall(command)
    deadline = time.time() + 10
    reply = bytearray()
    while time.time() < deadline:
        if b"(qemu)" in reply and ppm.is_file() and ppm.stat().st_size > 0:
            break
        try:
            chunk = monitor.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        reply.extend(chunk)
    from PIL import Image
    Image.open(ppm).save(png)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-qemu", action="store_true")
    parser.add_argument(
        "--win98-media", type=Path, metavar="PATH",
        help="your OWN Windows 98 ISO or extracted directory; overlaid under WIN98/ in a separate PRIVATE "
             "image (never the public one). IO.SYS, MSDOS.SYS, COMMAND.COM and a WIN98 cabinet folder "
             "are required. Nothing Microsoft is copied into the repository.")
    parser.add_argument("--output", type=Path, metavar="ISO", help="output ISO path (default under build/)")
    args = parser.parse_args()
    private = args.win98_media is not None
    tag = PRIVATE_SUFFIX if private else ""
    stage_root = BUILD / f"shizuku-second-edition{tag}-stage" if private else STAGE_ROOT
    media_work = BUILD / "shizuku-second-edition-media-work"
    work = BUILD / "shizuku-second-edition-work"
    evidence = BUILD / f"shizuku-second-edition-evidence{tag}"
    iso_path = args.output or BUILD / (ISO_NAME.replace(".iso", f"{tag}.iso") if private else ISO_NAME)
    summary_path = BUILD / f"windows98-shizuku-second-edition{tag}.txt"
    media = None
    try:
        if private:
            # Validate first: nothing is built for unusable media.
            require_git_ignored(iso_path)
            require_git_ignored(stage_root / "WIN98" / "IO.SYS")
            media = inspect_win98_media(args.win98_media, media_work)
        evidence.mkdir(parents=True, exist_ok=True)
        outputs = build_shizukudos10()
        artifacts = build_components(work)
        floppy = build_floppy(work, artifacts)
        (work / "shizukudos.img").write_bytes(floppy)
        shz10_payload, consistency = stage_shizukudos10(work, outputs)
        extra = {**shz10_payload, **shzse_payload(artifacts)}
        payload = stage_tree(stage_root, floppy, artifacts, extra, media)
        write_iso(stage_root, iso_path)
        report = verify_iso(iso_path, payload, evidence, stage_root if media else None)
        digest = sha256_path(iso_path)
        size = iso_path.stat().st_size
        qemu_report = "QEMU boot was skipped.\n"
        if not args.skip_qemu:
            try:
                qemu_report = qemu_frames(iso_path, evidence, tag)
            except Exception:
                qemu_report = "QEMU BIOS boot did not produce the expected frames:\n" + traceback.format_exc()
            try:
                qemu_report += qemu_uefi(iso_path, evidence, tag)
            except Exception:
                qemu_report += "QEMU UEFI boot did not produce the expected output:\n" + traceback.format_exc()
    except Win98MediaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if private:  # no second copy of the user's files is left lying around
            rmtree_force(stage_root)
            rmtree_force(media_work)
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
        "ShizukuDOS 10.0-dev rebuilt with: python3 shizukudos/tools/shz.py build --profile uefi-multikernel\n"
        f"{consistency}\n"
        f"{report}\n"
        f"{qemu_report}\n"
    )
    summary_path.write_text(summary, encoding="utf-8")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
