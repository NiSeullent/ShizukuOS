#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the ShizukuOS raw disk image (secondary artifact).

The product is the hybrid VM install ISO (tools/build_shizuku_se_iso.py), which
already boots when written to a USB stick. This raw image is for VMs and tools
that want a plain MBR hard disk with a writable FAT32 file system:

  sector 0      syslinux mbr.bin (pinned syslinux 6.04), disk signature,
                one active partition, type 0x0C (FAT32 LBA), LBA 2048 to the end
  partition     FAT32 "SHIZUKUSE" (BPB hidden sectors = 2048)
                  \\syslinux\\  ldlinux.sys + ldlinux.c32 (syslinux FAT installer),
                               menu.c32, libcom32.c32, libutil.c32, mboot.c32,
                               memdisk, syslinux.cfg (the same menu as the ISO)
                  \\EFI\\BOOT\\BOOTX64.EFI, \\EFI\\SHIZUKU\\CSMWRAP.EFI (+ .INI,
                  BOOT.INI), \\SHZDOS\\ (loader inputs; DISK.IMG
                  is also what the DOS16 entry boots with memdisk)
                  \\SHZ\\K64\\ (Kernel64 Multiboot files), \\SHZ\\SHZDOS01.IMG
                  (ShizukuDOS 0.1 floppy), \\SHZ\\SETUP\\ (when SHZSETUP exists),
                  \\DRIVERS\\, \\SHZSE\\, the Win98 SE overlay, README/VMPROFIL

Legacy BIOS: MBR -> syslinux VBR -> ldlinux.sys -> menu. UEFI: the firmware
finds \\EFI\\BOOT\\BOOTX64.EFI on the FAT32 partition; without VMX the loader's
boot manager (menu: no key = auto, K = Kernel64 direct) starts CSMWrap,
which legacy-boots this disk's MBR -> the same menu.

Inputs are the existing build outputs (run tools/build_shizuku_se_iso.py or
shizukudos/tools/shz.py build first); nothing is rebuilt except the small Win98
SE overlay binaries. The retired 0.1 floppy is not shipped. Reproducible (fixed ids and dates).
Licences and sources of the third-party parts are on the ISO (ShizukuDOS10\\).
"""
from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_shizuku_se_iso as iso_builder  # noqa: E402
import shizuku_se_media as se_media  # noqa: E402
import shizuku_image_io as image_io  # noqa: E402

BUILD = ROOT / "build"
DISK_NAME = "shizukuos-development-disk.img"
DISK_MIB = 128
PART_START = 2048
PART_TYPE = 0x0C          # FAT32 with LBA
DISK_SIGNATURE = 0x53485A31  # "1ZHS", fixed for reproducibility
# FAT32 volume serial ("SE98"). Not 0x53485A31: that is the volume serial Kernel64 reports for C: (sysk32.c
# K64_VOLUME_SERIAL); Kernel64 mounts this partition as D:, and Win64 programs expect the two to differ
# (win64/tests/t_k32_file.c: "D: has a volume serial number of its own").
VOLUME_ID = "53453938"
SECTOR = 512


def mbr_entry(active: bool, ptype: int, start: int, count: int) -> bytes:
    # CHS fields: the "beyond CHS" placeholder (1023/254/63); syslinux mbr.bin and SeaBIOS use the LBA fields.
    chs = bytes([0xFE, 0xFF, 0xFF])
    return bytes([0x80 if active else 0]) + chs + bytes([ptype]) + chs + struct.pack("<II", start, count)


def write_mbr(disk: Path, code: bytes, total_sectors: int) -> bytes:
    if len(code) != 440:
        raise RuntimeError("syslinux mbr.bin must be 440 bytes")
    sector = bytearray(SECTOR)
    sector[:440] = code
    sector[440:444] = struct.pack("<I", DISK_SIGNATURE)
    sector[446:462] = mbr_entry(True, PART_TYPE, PART_START, total_sectors - PART_START)
    sector[510:512] = b"\x55\xaa"
    with open(disk, "r+b") as handle:
        handle.write(sector)
    return bytes(sector)


def install_syslinux(disk: Path, installer: Path, work: Path) -> None:
    """The pinned mtools-based syslinux installer: boot sector + ldlinux.sys/ldlinux.c32 into \\syslinux."""
    env = se_media.mtools_env()
    tmp = work / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    subprocess.run([str(installer), "--install", "--directory", "/syslinux", "--offset", str(PART_START * SECTOR),
                    str(disk)], check=True, env=env)


def disk_members(loader, csm, shzdos, k64, mode: str, artifacts: dict, setup_files: dict,
                 store: dict, syslinux: dict, desktop: bool = True) -> dict[str, bytes]:
    members = dict(se_media.efi_members(loader, csm, shzdos, mode, setup_files))
    if desktop:
        members["SHZDOS/KERNEL64.INI"] = b"cmdline = shz.desktop\r\n"
    for name in se_media.SYSLINUX_MODULES:
        if name != "ldlinux.c32":  # written by the installer, matched to its ldlinux.sys
            members[f"syslinux/{name}"] = syslinux[name].read_bytes()
    members["syslinux/memdisk"] = syslinux["memdisk"].read_bytes()
    members["syslinux/syslinux.cfg"] = se_media.boot_menu(
        dos16_image="/SHZDOS/DISK.IMG", k64_dir="/SHZ/K64", setup=bool(setup_files), desktop=desktop)
    for name, item in k64.items():
        members[f"SHZ/K64/{name}"] = item.data
    members.update(setup_files)
    members.update(store)
    members.update(iso_builder.shzse_payload(artifacts))
    edition = "ShizukuOS"
    members.update({
        f"{edition}/EDITION.TXT": iso_builder.edition_text(),
        f"{edition}/NTWrapper9x/NTWRAP9X.VXD": artifacts["NTWRAP9X.VXD"].read_bytes(),
        f"{edition}/NTWrapper9x/NTWQUERY.EXE": artifacts["NTWQUERY.EXE"].read_bytes(),
        f"{edition}/NTWin32Wrapper9x/NTW32.DLL": artifacts["NTW32.DLL"].read_bytes(),
        f"{edition}/NTWin32Wrapper9x/NTWPROBE.EXE": artifacts["NTWPROBE.EXE"].read_bytes(),
        f"{edition}/NTWDDMWrapper9x/NTWGPROB.EXE": artifacts["NTWGPROB.EXE"].read_bytes(),
    })
    members["VMPROFIL.TXT"] = se_media.vm_profiles_text().encode("ascii")
    members["LIMITS.TXT"] = iso_builder.limits_text()
    members["README.TXT"] = (
        "ShizukuOS - raw disk image (secondary artifact)\r\n"
        "The same boot menu as the VM install ISO: Kernel64 (K), DOS16 (D, boots\r\n"
        "\\SHZDOS\\DISK.IMG with memdisk), DOS10 recovery shell"
        + (", Install (I)" if setup_files else "") + ".\r\n"
        "Legacy BIOS: MBR -> syslinux. UEFI: \\EFI\\BOOT\\BOOTX64.EFI, the boot manager:\r\n"
        "no key = auto (without VMX CSMWrap legacy-boots this disk), K = Kernel64\r\n"
        "direct. See VMPROFIL.TXT. Licences and source of\r\n"
        "the third-party parts (FreeDOS, CSMWrap + SeaBIOS, syslinux) are on the\r\n"
        "ISO under ShizukuDOS10\\. Not a Windows 98 installation.\r\n"
    ).encode("ascii")
    return members


def verify_disk(disk: Path, members: dict[str, bytes], syslinux: dict, sector0: bytes, work: Path) -> str:
    with disk.open("rb") as src:
        data_mbr = src.read(SECTOR)
    if data_mbr != sector0:
        raise RuntimeError("sector 0 changed after it was written")
    part = work / "partition-check.img"
    image_io.copy_new_sparse(disk, part, source_offset=PART_START * SECTOR)
    try:
        with part.open("rb") as src:
            vbr = src.read(SECTOR)
        hidden = struct.unpack_from("<I", vbr, 28)[0]
        if vbr[3:11] != b"SYSLINUX" or vbr[0x52:0x5A] != b"FAT32   " or hidden != PART_START or vbr[510:] != b"\x55\xaa":
            raise RuntimeError(f"partition boot sector is not a syslinux FAT32 VBR at hidden={PART_START}: "
                               f"{vbr[3:11]!r} {vbr[0x52:0x5A]!r} hidden={hidden}")
        count = se_media.verify_fat_members(str(part), members, work / "readback")
        # ldlinux.sys and ldlinux.c32 are a matched pair embedded in the pinned installer (its build differs from
        # syslinux-common's ldlinux.c32 only in the version date string); both must come from that binary.
        ldlinux_c32 = se_media.read_fat_file(str(part), "syslinux/ldlinux.c32") or b""
        if len(ldlinux_c32) < 4096 or ldlinux_c32 not in syslinux["installer"].read_bytes():
            raise RuntimeError("the installed ldlinux.c32 is not the copy embedded in the pinned syslinux installer")
        listing = subprocess.run(["mdir", "-a", "-i", str(part), "::/syslinux"], capture_output=True, text=True,
                                 env=se_media.mtools_env()).stdout
        if "ldlinux  sys" not in listing:
            raise RuntimeError("ldlinux.sys is missing from \\syslinux")
        check = subprocess.run(["fsck.vfat", "-n", str(part)], capture_output=True, text=True)
        if check.returncode != 0:
            raise RuntimeError("fsck.vfat rejects the partition:\n" + check.stdout)
    finally:
        part.unlink(missing_ok=True)
    return (f"MBR: syslinux mbr.bin code, signature {DISK_SIGNATURE:#010x}, partition 1 active type 0x{PART_TYPE:02x} "
            f"LBA {PART_START}..end\n"
            f"VBR: SYSLINUX FAT32, hidden sectors {PART_START}; ldlinux.sys installed, ldlinux.c32 = the pinned "
            f"installer's embedded copy ({len(ldlinux_c32)} bytes, sha256 {se_media.sha256(ldlinux_c32)})\n"
            f"{count} files read back identical; fsck.vfat -n: {check.stdout.strip().splitlines()[-1]}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, help=f"default build/{DISK_NAME}")
    parser.add_argument("--driver-package", action="append", default=[], metavar="DIR|PACKAGE=DIR")
    parser.add_argument("--setup", type=Path, metavar="DIR")
    parser.add_argument("--loader", type=Path)
    parser.add_argument("--csmwrap", type=Path)
    parser.add_argument("--boot-mode", choices=se_media.BOOT_MODES, default=None)
    parser.add_argument("--desktop", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--size-mib", type=int, default=0,
                        help=f"disk size (default: fitted to the content in 32 MiB steps, at least {DISK_MIB} MiB)")
    args = parser.parse_args()
    if args.boot_mode is None:
        args.boot_mode = "kernel64" if args.desktop else "auto"
    disk = (args.output or BUILD / DISK_NAME).resolve()
    work = BUILD / "shizuku-second-edition-disk-work"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    try:
        loader = se_media.loader_input(args.loader)
        csm = se_media.csmwrap_input(args.csmwrap)
        k64 = se_media.k64_inputs()
        shzdos = se_media.shzdos_inputs()
        syslinux = se_media.syslinux()
        setup_files, setup_info = se_media.setup_payload(args.setup)
        if args.boot_mode == "install" and not setup_files:
            raise RuntimeError("UEFI mode=install requires the actual installer payload")
        if args.desktop and setup_files and setup_info.get("boot_profile") != "desktop":
            raise RuntimeError("production disk requires a desktop installer payload")
        store, store_manifest = se_media.driver_store(args.driver_package)
    except se_media.drivers.DriverPackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    artifacts = iso_builder.build_components(work / "components")
    members = disk_members(loader, csm, shzdos, k64, args.boot_mode, artifacts, setup_files, store, syslinux, args.desktop)
    need = sum(len(d) for d in members.values()) * 11 // 10 + 8 * se_media.MIB   # + FAT32 overhead and slack
    if not args.size_mib:
        args.size_mib = max(DISK_MIB, -(-(need + se_media.MIB) // (32 * se_media.MIB)) * 32)
    if need > (args.size_mib - 1) * se_media.MIB:
        raise RuntimeError(f"content needs about {need >> 20} MiB; use --size-mib larger than {args.size_mib}")
    partial = disk.with_suffix(".img.partial")
    partial.unlink(missing_ok=True)
    disk.parent.mkdir(parents=True, exist_ok=True)
    total = args.size_mib * se_media.MIB // SECTOR
    with open(partial, "wb") as handle:
        handle.truncate(total * SECTOR)
    se_media.make_fat(partial, members, args.size_mib - 1, 32, "SHIZUKUSE", VOLUME_ID, work / "fat",
                      offset=PART_START * SECTOR, hidden=PART_START)
    install_syslinux(partial, syslinux["installer"], work)
    sector0 = write_mbr(partial, syslinux["mbr.bin"].read_bytes(), total)
    report = verify_disk(partial, members, syslinux, sector0, work)
    partial.replace(disk)
    digest = se_media.shzlib.sha256_file(disk)
    inputs = [loader, csm, *k64.values(), *shzdos.values()]
    receipt = {"disk": str(disk), "bytes": disk.stat().st_size, "sha256": digest,
               "product": "ShizukuOS", "release_target": "1.0.0", "release_channel": "development",
               "boot_profile": "desktop" if args.desktop else "self-test", "boot_mode": args.boot_mode,
               "distribution_origin": "https://m98.nyase.kr", "retired_dos01_shipped": False,
               "layout": {"part_start": PART_START, "part_type": PART_TYPE, "fs": "FAT32", "disk_signature": DISK_SIGNATURE},
               "inputs": [item.record() for item in inputs],
               "syslinux": se_media.syslinux_spec()["distribution"], "setup": setup_info,
               "drivers": [p["package"] for p in store_manifest["packages"]],
               "menu": {"dos16": "/SHZDOS/DISK.IMG", "k64_dir": "/SHZ/K64",
                        "keys": se_media.MENU_KEYS, "setup_entry": bool(setup_files),
                        "uefi": {"boot_ini": {"mode": args.boot_mode, "menu_timeout": se_media.MENU_TIMEOUT}}},
               "members": len(members)}
    receipt_path = disk.with_suffix(".json")
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    print(f"{disk}\nbytes {disk.stat().st_size}\nsha256 {digest}\n{report}"
          + f"receipt {receipt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
