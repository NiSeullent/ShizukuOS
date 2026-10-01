# SPDX-License-Identifier: GPL-2.0-only
"""Bounded, read-only OEM El Torito/FAT12 input validation.

The three DOS files are licensed media/reference inputs, never a ShizukuDOS
replacement claim or a request to boot them. No image is launched or changed.
Optional extraction writes only to an existing, private, git-ignored directory.
"""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECTOR = 2048
FLOPPY_BYTES = 1474560
REQUIRED_FILES = ("IO.SYS", "MSDOS.SYS", "COMMAND.COM")


class BootMediaError(ValueError):
    """Input cannot establish the supported BIOS 1.44 MiB FAT12 contract."""


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise BootMediaError(message)


def _identity(info) -> tuple:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read_at(handle, offset: int, size: int, limit: int) -> bytes:
    _require(0 <= offset <= limit and 0 <= size <= limit - offset, "ISO extent outside source bounds")
    handle.seek(offset)
    data = handle.read(size)
    _require(len(data) == size, "truncated ISO extent")
    return data


def _fat_files(image: bytes) -> dict[str, bytes]:
    _require(image[510:512] == b"\x55\xaa", "unsigned FAT12 boot sector")
    bps, spc, reserved, fats, roots, total, media, fatsize = struct.unpack_from("<HBHBHHBH", image, 11)
    total32 = struct.unpack_from("<I", image, 32)[0]
    _require(bps == 512 and total == 2880 and total32 in (0, total), "not a 1.44 MiB FAT12 volume")
    _require(spc and not spc & (spc - 1) and spc <= 128 and reserved and fats == 2 and roots and fatsize,
             "invalid FAT12 BPB geometry")
    root_bytes = roots * 32
    root_start = (reserved + fats * fatsize) * bps
    data_start = root_start + (root_bytes + bps - 1) // bps * bps
    _require(data_start < len(image) and root_start + root_bytes <= data_start, "FAT12 root outside volume")
    cluster_bytes = spc * bps
    clusters = (len(image) - data_start) // cluster_bytes
    _require(0 < clusters < 4085, "not a bounded FAT12 cluster count")
    fat_start, fat_bytes = reserved * bps, fatsize * bps
    _require(fat_start + 2 * fat_bytes <= root_start and (clusters + 2) * 3 // 2 + 1 <= fat_bytes,
             "FAT12 table cannot address volume")
    fat = image[fat_start:fat_start + fat_bytes]
    _require(fat == image[fat_start + fat_bytes:fat_start + 2 * fat_bytes], "FAT12 copies disagree")
    _require(media == 0xf0 and fat[:3] == b"\xf0\xff\xff", "invalid FAT12 reserved entries")

    def next_cluster(cluster: int) -> int:
        offset = cluster * 3 // 2
        value = struct.unpack_from("<H", fat, offset)[0]
        return (value >> 4 if cluster & 1 else value) & 0xfff

    entries = {}
    for offset in range(root_start, root_start + root_bytes, 32):
        entry = image[offset:offset + 32]
        if not entry[0]:
            break
        if entry[0] == 0xe5 or entry[11] == 0x0f or entry[11] & 8:
            continue
        stem, extension = entry[:8].rstrip(b" "), entry[8:11].rstrip(b" ")
        if entry[11] & 0x10 and stem in (b".", b".."):
            continue
        _require(stem and not any(c < 32 or c in b'./\\:*?"<>|' for c in stem + extension),
                 "unsafe FAT12 root filename")
        name = (stem + (b"." + extension if extension else b"")).decode("cp437").upper()
        if name not in REQUIRED_FILES:
            continue
        _require(not entry[11] & 0xd8 and name not in entries, "duplicate or non-file required root entry")
        _require(struct.unpack_from("<H", entry, 20)[0] == 0, "invalid FAT12 high cluster")
        cluster = struct.unpack_from("<H", entry, 26)[0]
        size = struct.unpack_from("<I", entry, 28)[0]
        _require(0 < size <= len(image), "invalid required file size")
        entries[name] = (cluster, size)
    _require(set(entries) == set(REQUIRED_FILES), "required DOS files missing from FAT12 root")

    files, owned = {}, set()
    for name in REQUIRED_FILES:
        cluster, size = entries[name]
        count = (size + cluster_bytes - 1) // cluster_bytes
        chunks = []
        for index in range(count):
            _require(2 <= cluster <= clusters + 1 and cluster not in owned, "corrupt, looping or overlapping FAT12 chain")
            owned.add(cluster)
            offset = data_start + (cluster - 2) * cluster_bytes
            chunks.append(image[offset:offset + cluster_bytes])
            cluster = next_cluster(cluster)
            if index + 1 == count:
                _require(0xff8 <= cluster <= 0xfff, "overlong or invalid FAT12 file tail")
            else:
                _require(2 <= cluster <= clusters + 1, "premature or invalid FAT12 file chain")
        files[name] = b"".join(chunks)[:size]
    return files


def _inspect(iso: Path) -> tuple[dict, dict[str, bytes]]:
    iso = Path(iso)
    try:
        fd = os.open(iso, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            _require(stat.S_ISREG(before.st_mode), "ISO source must be a regular file")
            limit, volume, catalog_lba, terminated = before.st_size, None, None, False
            for sector in range(16, 80):
                descriptor = _read_at(handle, sector * SECTOR, SECTOR, limit)
                _require(descriptor[1:7] == b"CD001\x01", "invalid ISO volume descriptor")
                if descriptor[0] == 1:
                    blocks = struct.unpack_from("<I", descriptor, 80)[0]
                    _require(blocks == struct.unpack_from(">I", descriptor, 84)[0] and blocks >= 19,
                             "invalid ISO volume bounds")
                    _require(struct.unpack_from("<H", descriptor, 128)[0] == SECTOR ==
                             struct.unpack_from(">H", descriptor, 130)[0], "unsupported ISO logical sector")
                    _require(volume is None, "ambiguous primary ISO descriptor")
                    volume = blocks * SECTOR
                    _require(volume <= limit, "truncated declared ISO volume")
                elif descriptor[0] == 0 and descriptor[7:39].rstrip(b"\0 ") == b"EL TORITO SPECIFICATION":
                    _require(catalog_lba is None, "ambiguous El Torito boot record")
                    catalog_lba = struct.unpack_from("<I", descriptor, 71)[0]
                elif descriptor[0] == 255:
                    terminated = True
                    break
            _require(terminated and volume is not None and catalog_lba is not None,
                     "missing bounded ISO/El Torito descriptor sequence")
            _require(catalog_lba > sector, "boot catalog overlaps volume descriptors")
            catalog = _read_at(handle, catalog_lba * SECTOR, SECTOR, volume)
            _require(catalog[:4] == b"\x01\0\0\0" and catalog[30:32] == b"\x55\xaa" and
                     sum(struct.unpack("<16H", catalog[:32])) & 0xffff == 0,
                     "invalid BIOS El Torito validation entry/checksum")
            entry = catalog[32:64]
            _require(entry[0] == 0x88 and entry[1] == 2 and entry[4:6] == b"\0\0",
                     "no supported bootable BIOS 1.44 MiB floppy entry")
            load_sectors = struct.unpack_from("<H", entry, 6)[0]
            _require(0 < load_sectors <= 2880, "invalid El Torito load count")
            boot_lba = struct.unpack_from("<I", entry, 8)[0]
            offset = boot_lba * SECTOR
            _require(boot_lba > sector and not offset <= catalog_lba * SECTOR < offset + FLOPPY_BYTES,
                     "boot image overlaps descriptors/catalog")
            image = _read_at(handle, offset, FLOPPY_BYTES, volume)
            files = _fat_files(image)
            _require(_identity(before) == _identity(os.fstat(handle.fileno())) == _identity(iso.stat()),
                     "ISO source changed during validation")
        report = {"schema": 1, "scope": "OEM boot-media validation/reference only", "iso_bytes": limit,
                  "catalog_lba": catalog_lba, "boot_lba": boot_lba, "boot_offset": offset,
                  "boot_bytes": FLOPPY_BYTES, "boot_sha256": hashlib.sha256(image).hexdigest(),
                  "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                            for name, data in files.items()}, "DOS_replacement_verified": False,
                  "Windows98_setup_executed": False}
        return report, files
    except OSError as error:
        raise BootMediaError(f"cannot read OEM boot media: {error}") from error


def inspect_boot_media(iso: Path) -> dict:
    """Read at most 64 descriptors, one catalog and one 1.44 MiB floppy."""
    return _inspect(iso)[0]


def extract_boot_files(iso: Path, destination: Path) -> dict:
    """Copy fixed filenames into an existing private ignored stage, without overwrite.

    Git is queried read-only for the existing ignore boundary. No directory is
    created and nothing is written to the source ISO or public repository files.
    """
    destination = Path(destination)
    try:
        destination.absolute().relative_to(ROOT)
        cursor = destination.absolute()
        while cursor != ROOT:
            _require(not cursor.is_symlink(), "symlink in extraction destination")
            cursor = cursor.parent
        destination = destination.resolve(strict=True)
        destination.relative_to(ROOT)
        info = destination.stat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o077 == 0,
                 "extraction requires an existing private directory")
        for name in REQUIRED_FILES:
            result = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--",
                                     str(destination / name)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _require(result.returncode == 0, "extraction destination is not git-ignored")
        report, files = _inspect(iso)
        directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        created = {}
        try:
            for name in REQUIRED_FILES:
                try:
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise BootMediaError("refusing to overwrite an existing extracted file")
            for name, data in files.items():
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                created[name] = os.fstat(fd).st_ino
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                with os.fdopen(fd, "rb") as handle:
                    _require(handle.read() == data, "extracted boot file readback mismatch")
            _require(info.st_ino == os.fstat(directory).st_ino == destination.stat().st_ino,
                     "extraction directory changed")
        except BaseException:
            for name, inode in created.items():
                if os.stat(name, dir_fd=directory, follow_symlinks=False).st_ino == inode:
                    os.unlink(name, dir_fd=directory)
            raise
        finally:
            os.close(directory)
        return report
    except (OSError, ValueError) as error:
        if isinstance(error, BootMediaError):
            raise
        raise BootMediaError(f"cannot extract into private stage: {error}") from error
