# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic FAT12/16 boot-image builder using host mtools.

The FreeDOS boot sector is installed the way the FreeDOS SYS utility does it
(kernel/sys/sys.c, FAT12/16 branch): take the boot code template, keep the BPB
that the formatter wrote (bytes 11..61) and write the result to sector 0.
"""
import os
import shutil
import struct
from pathlib import Path

from shzlib import run

FIXED_EPOCH = 1785283200  # 2026-07-29 00:00:00 UTC; keeps file times reproducible


def _mtools_env():
    env = dict(os.environ)
    env["MTOOLS_SKIP_CHECK"] = "1"
    env["TZ"] = "UTC"
    env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)   # mformat stamps the volume-label entry with "now" otherwise
    return env


HDD_HEADS = 16
HDD_SPT = 63
PART_START = 63


def _chs(lba):
    cyl, rem = divmod(lba, HDD_HEADS * HDD_SPT)
    head, sec = divmod(rem, HDD_SPT)
    cyl = min(cyl, 1023)
    return bytes([head, (sec + 1) | ((cyl >> 2) & 0xc0), cyl & 0xff])


def make_hdd(image, mbr_code, size_mib=32, label="SHZDOS", serial=0x5348_5A44):
    """Create an MBR-partitioned disk image with one active FAT16 partition.

    Returns the mtools image spec (path@@byte-offset) addressing the partition.
    """
    image = Path(image)
    image.unlink(missing_ok=True)
    cylinders = (size_mib * 1024 * 1024) // (HDD_HEADS * HDD_SPT * 512)
    total = cylinders * HDD_HEADS * HDD_SPT
    part_sectors = total - PART_START
    with open(image, "wb") as fh:
        fh.truncate(total * 512)
    mbr = bytearray(Path(mbr_code).read_bytes())
    if len(mbr) != 512 or mbr[510:512] != b"\x55\xaa":
        raise ValueError("MBR image must be 512 bytes with a boot signature")
    entry = bytes([0x80]) + _chs(PART_START) + bytes([0x06]) + _chs(total - 1) + \
        struct.pack("<II", PART_START, part_sectors)
    mbr[446:462] = entry
    with open(image, "r+b") as fh:
        fh.write(mbr)
    spec = f"{image}@@{PART_START * 512}"
    run(["mformat", "-i", spec, "-h", str(HDD_HEADS), "-s", str(HDD_SPT),
         "-T", str(part_sectors), "-H", str(PART_START), "-v", label, "-N", f"{serial:08x}",
         "::"], env=_mtools_env())
    return spec


def install_freedos_boot(spec, template, kernel_name=b"KERNEL  SYS"):
    """spec is an mtools image spec (path or path@@offset); patches its boot sector."""
    path, _, offset = str(spec).partition("@@")
    offset = int(offset) if offset else 0
    template = Path(template).read_bytes()
    if len(template) != 512 or template[510:512] != b"\x55\xaa":
        raise ValueError("boot sector template must be 512 bytes with a boot signature")
    with open(path, "r+b") as fh:
        fh.seek(offset)
        old = bytearray(fh.read(512))
        if old[510:512] != b"\x55\xaa":
            raise ValueError("formatted image has no boot signature")
        new = bytearray(template)
        # struct bootsectortype: 62 bytes for FAT12/16; SBOFFSET=11, SBSIZE=51
        new[11:62] = old[11:62]
        # Kernel filename slot in the FreeDOS FAT12/16 boot code (0x1f1..0x1fb).
        new[0x1f1:0x1f1 + 11] = kernel_name
        fh.seek(offset)
        fh.write(new)


def partition_spec(image):
    return f"{image}@@{PART_START * 512}"


def copy_in(image, files):
    """files: list of (host_path, dos_name). Order matters: KERNEL.SYS first."""
    env = _mtools_env()
    for host, name in files:
        os.utime(host, (FIXED_EPOCH, FIXED_EPOCH))
        run(["mcopy", "-m", "-i", image, host, f"::{name}"], env=env)


def read_file(image, name):
    r = run(["mtype", "-i", image, f"::{name}"], env=_mtools_env(), capture=True, check=False)
    return r.stdout if r.returncode == 0 else None


def read_bytes(image, name):
    import subprocess
    r = subprocess.run(["mcopy", "-n", "-i", str(image), f"::{name}", "-"],
                       capture_output=True, env=_mtools_env())
    return r.stdout if r.returncode == 0 else None


def listing(image):
    r = run(["mdir", "-i", image, "::"], env=_mtools_env(), capture=True, check=False)
    return r.stdout
