#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare a private, identity-pinned original Windows 98 IO.SYS capsule.

This module only reads an MBR/FAT32 image. It does not patch or execute IO.SYS,
change a disk, start a guest, or make network requests. Imports have no effects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys


MAGIC = b"SHZIO98\0"
VERSION = 1
HEADER_BYTES = 128
BPB_BYTES = 512
PREFIX_BYTES = 2048
CAPSULE_BYTES = HEADER_BYTES + BPB_BYTES + PREFIX_BYTES
FLAGS = 3
ENTRY_SIGNATURE = bytes.fromhex("42 4a 8b 46 fc 8b 56 fe")
SCHEMA = "win98modern.iosys-uefi-capsule.v1"
EOC = 0x0FFFFFF8
RESERVED_CLUSTER = 0x0FFFFFF0


class CapsuleError(ValueError):
    """An input cannot establish the supported original IO.SYS boot contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CapsuleError(message)


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expected_hash(value: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value)
             is not None, "expected IO.SYS SHA-256 must contain exactly 64 hex digits")
    return value.lower()


def _prefix_contract(prefix: bytes) -> None:
    _require(len(prefix) == PREFIX_BYTES, "IO.SYS prefix must contain exactly 2048 bytes")
    _require(prefix[:2] == b"MZ", "unsupported IO.SYS: missing MZ signature")
    _require(prefix[0x200:0x208] == ENTRY_SIGNATURE,
             "unsupported IO.SYS entry: original MSLOAD signature does not match")
    _require(prefix[0x7FE:0x800] == b"MS",
             "unsupported IO.SYS: missing first-stage MS signature")


def _geometry(vbr: bytes, start_lba: int,
              partition_sectors: int | None = None) -> dict:
    _require(len(vbr) == BPB_BYTES and vbr[510:512] == b"\x55\xaa",
             "FAT32 VBR must be a signed 512-byte sector")
    _require(vbr[0] == 0xEB and vbr[2] == 0x90,
             "unsupported original VBR: expected EB jump and unmodified 90 marker")
    _require(_u16(vbr, 0x0B) == 512, "only 512-byte FAT32 sectors are supported")
    _require(vbr[0x40] >= 0x80, "original FAT32 BPB must identify a BIOS hard disk")
    spc = vbr[0x0D]
    _require(4 <= spc <= 128 and spc & (spc - 1) == 0,
             "FAT32 sectors per cluster must be a power of two from 4 through 128")
    reserved = _u16(vbr, 0x0E)
    fats = vbr[0x10]
    fat_sectors = _u32(vbr, 0x24)
    total_sectors = _u32(vbr, 0x20)
    _require(reserved > 0 and fats in (1, 2) and fat_sectors > 0,
             "invalid FAT32 reserved-sector or FAT geometry")
    _require(_u16(vbr, 0x11) == 0 and _u16(vbr, 0x13) == 0
             and _u16(vbr, 0x16) == 0, "BPB is not a FAT32 layout")
    _require(_u16(vbr, 0x2A) == 0, "unsupported FAT32 filesystem version")
    _require(_u32(vbr, 0x1C) == start_lba,
             "FAT32 hidden sectors do not match the active partition start")
    _require(total_sectors > 0, "FAT32 volume size is zero")
    if partition_sectors is not None:
        _require(total_sectors <= partition_sectors,
                 "FAT32 volume extends beyond its partition")
    first_data_relative = reserved + fats * fat_sectors
    _require(first_data_relative < total_sectors, "FAT32 data area is absent")
    clusters = (total_sectors - first_data_relative) // spc
    _require(65525 <= clusters and clusters + 1 < RESERVED_CLUSTER,
             "cluster count is outside the FAT32 data-cluster range")
    _require((clusters + 2) * 4 <= fat_sectors * 512,
             "FAT32 table cannot address the declared data area")
    _require(start_lba + total_sectors <= 0x100000000,
             "FAT32 volume exceeds the 32-bit LBA boot contract")
    root_cluster = _u32(vbr, 0x2C)
    _require(2 <= root_cluster <= clusters + 1, "FAT32 root cluster is out of range")
    extflags = _u16(vbr, 0x28)
    _require(extflags & ~0x008F == 0, "unsupported FAT32 extended flags")
    mirrored = not bool(extflags & 0x0080)
    active_fat = 0 if mirrored else extflags & 0x000F
    _require(active_fat < fats, "FAT32 active FAT index is out of range")
    _require(active_fat == 0,
             "original MSLOAD contract requires the first FAT to be active")
    for offset, label in ((0x30, "FSInfo"), (0x32, "backup boot")):
        value = _u16(vbr, offset)
        _require(value in (0, 0xFFFF) or value < reserved,
                 f"FAT32 {label} sector is outside the reserved area")
    return {
        "bytes_per_sector": 512,
        "sectors_per_cluster": spc,
        "reserved_sectors": reserved,
        "fat_count": fats,
        "fat_sectors": fat_sectors,
        "total_sectors": total_sectors,
        "cluster_count": clusters,
        "root_cluster": root_cluster,
        "first_data_absolute_lba": start_lba + first_data_relative,
        "active_fat": active_fat,
        "fat_mirroring": mirrored,
    }


def _partition(disk: bytes) -> dict:
    _require(len(disk) >= 512 and len(disk) % 512 == 0,
             "raw disk image must contain whole 512-byte sectors")
    _require(disk[510:512] == b"\x55\xaa", "MBR signature is missing")
    sectors = len(disk) // 512
    entries = []
    for index in range(4):
        offset = 446 + index * 16
        entry = disk[offset:offset + 16]
        status, kind = entry[0], entry[4]
        start, count = _u32(entry, 8), _u32(entry, 12)
        _require(status in (0, 0x80), "MBR partition has an invalid active flag")
        if kind == 0:
            _require(entry == bytes(16), "empty MBR partition contains metadata")
            continue
        _require(kind != 0xEE, "protective or hybrid GPT is not supported")
        _require(start > 0 and count > 0 and start + count <= sectors
                 and start + count <= 0x100000000,
                 "MBR partition extends beyond the raw image or LBA range")
        entries.append({"index": index, "type": kind, "start_lba": start,
                        "sectors": count, "active": status == 0x80})
    for left_index, left in enumerate(entries):
        for right in entries[left_index + 1:]:
            _require(left["start_lba"] + left["sectors"] <= right["start_lba"]
                     or right["start_lba"] + right["sectors"] <= left["start_lba"],
                     "MBR partitions overlap")
    active = [entry for entry in entries if entry["active"]]
    _require(len(active) == 1, "exactly one active primary partition is required")
    _require(active[0]["type"] in (0x0B, 0x0C),
             "active partition must be FAT32 type 0x0b or 0x0c")
    return active[0]


class _Volume:
    def __init__(self, disk: bytes, partition: dict, geometry: dict) -> None:
        self.disk = disk
        self.partition = partition
        self.geometry = geometry
        self.cluster_bytes = geometry["sectors_per_cluster"] * 512

    def cluster_lba(self, cluster: int) -> int:
        _require(2 <= cluster <= self.geometry["cluster_count"] + 1,
                 "FAT32 cluster is outside the data area")
        return (self.geometry["first_data_absolute_lba"]
                + (cluster - 2) * self.geometry["sectors_per_cluster"])

    def cluster_bytes_at(self, cluster: int) -> bytes:
        offset = self.cluster_lba(cluster) * 512
        end = offset + self.cluster_bytes
        volume_end = ((self.partition["start_lba"]
                       + self.geometry["total_sectors"]) * 512)
        _require(end <= volume_end and end <= len(self.disk),
                 "FAT32 cluster extends beyond the volume or image")
        return self.disk[offset:end]

    def next_cluster(self, cluster: int) -> int:
        self.cluster_lba(cluster)
        geometry = self.geometry
        fat_start = self.partition["start_lba"] + geometry["reserved_sectors"]
        indexes = (range(geometry["fat_count"]) if geometry["fat_mirroring"]
                   else (geometry["active_fat"],))
        values = []
        for index in indexes:
            offset = (fat_start + index * geometry["fat_sectors"]) * 512 + cluster * 4
            fat_end = (fat_start + (index + 1) * geometry["fat_sectors"]) * 512
            _require(offset + 4 <= fat_end and offset + 4 <= len(self.disk),
                     "FAT32 entry extends beyond its table or image")
            values.append(_u32(self.disk, offset) & 0x0FFFFFFF)
        _require(all(value == values[0] for value in values),
                 "mirrored FAT32 entries disagree")
        value = values[0]
        _require(value >= EOC or 2 <= value <= geometry["cluster_count"] + 1,
                 "FAT32 chain contains a free, bad, reserved, or out-of-range cluster")
        return value

    def io_entry(self) -> tuple[int, int, set[int]]:
        cluster = self.geometry["root_cluster"]
        visited: set[int] = set()
        matches: list[tuple[int, int]] = []
        directory_end = False
        while True:
            _require(cluster not in visited, "FAT32 root directory chain loops")
            visited.add(cluster)
            data = self.cluster_bytes_at(cluster)
            if not directory_end:
                for offset in range(0, len(data), 32):
                    entry = data[offset:offset + 32]
                    if entry[0] == 0:
                        directory_end = True
                        break
                    if entry[0] == 0xE5 or entry[11] == 0x0F:
                        continue
                    if entry[:11] != b"IO      SYS":
                        continue
                    _require(entry[11] & 0xD8 == 0,
                             "IO.SYS root entry is a directory, label, or has reserved attributes")
                    first = (_u16(entry, 20) << 16) | _u16(entry, 26)
                    self.cluster_lba(first)
                    size = _u32(entry, 28)
                    _require(size >= PREFIX_BYTES, "IO.SYS is shorter than its 2048-byte first stage")
                    matches.append((first, size))
            following = self.next_cluster(cluster)
            if following >= EOC:
                break
            cluster = following
        _require(len(matches) == 1, "root directory must contain exactly one short-name IO.SYS")
        return matches[0][0], matches[0][1], visited

    def read_io(self, first_cluster: int, size: int,
                root_clusters: set[int]) -> tuple[bytes, int]:
        required = (size + self.cluster_bytes - 1) // self.cluster_bytes
        _require(required <= self.geometry["cluster_count"],
                 "IO.SYS file size exceeds the FAT32 data area")
        cluster = first_cluster
        visited: set[int] = set()
        chunks = []
        remaining = size
        for index in range(required):
            _require(cluster not in visited, "IO.SYS FAT32 chain loops")
            _require(cluster not in root_clusters, "IO.SYS chain overlaps the root directory")
            visited.add(cluster)
            count = min(remaining, self.cluster_bytes)
            chunks.append(self.cluster_bytes_at(cluster)[:count])
            remaining -= count
            following = self.next_cluster(cluster)
            if index + 1 == required:
                _require(following >= EOC, "IO.SYS FAT32 chain is longer than its declared file size")
            else:
                _require(following < EOC, "IO.SYS FAT32 chain ends before its declared file size")
                cluster = following
        return b"".join(chunks), len(visited)


def parse_capsule(capsule_bytes: bytes) -> dict:
    """Validate the serialized bootstrap contract, without executing any bytes.

    The full IO.SYS digest is an identity pin; the capsule contains only its
    first 2048 bytes and cannot independently recompute that full-file digest.
    """
    _require(isinstance(capsule_bytes, bytes), "capsule input must be immutable bytes")
    _require(len(capsule_bytes) == CAPSULE_BYTES, "capsule size must be exactly 2688 bytes")
    data = capsule_bytes
    _require(data[:8] == MAGIC, "capsule magic does not match")
    _require(_u16(data, 8) == VERSION and _u16(data, 10) == HEADER_BYTES,
             "unsupported capsule version or header size")
    _require(_u32(data, 12) == CAPSULE_BYTES, "capsule total size does not match")
    _require(sum(struct.unpack("<672I", data)) & 0xFFFFFFFF == 0,
             "capsule additive checksum does not match")
    _require(_u32(data, 20) == FLAGS, "unsupported capsule flags")
    _require(_u32(data, 44) == PREFIX_BYTES and _u32(data, 48) == BPB_BYTES,
             "unsupported capsule prefix or BPB size")
    _require(_u32(data, 52) == 0 and data[123] == 0 and _u32(data, 124) == 0,
             "capsule reserved fields must be zero")
    vbr = data[HEADER_BYTES:HEADER_BYTES + BPB_BYTES]
    prefix = data[HEADER_BYTES + BPB_BYTES:]
    _require(hashlib.sha256(vbr).digest() == data[88:120], "capsule VBR SHA-256 does not match")
    _prefix_contract(prefix)
    start = _u32(data, 24)
    _require(start > 0, "capsule partition start is zero")
    geometry = _geometry(vbr, start)
    kind = data[122]
    _require(kind in (0x0B, 0x0C), "capsule partition type is not supported FAT32")
    _require(data[121] == (kind | 2), "capsule memory-only BPB marker does not match")
    _require(data[120] == vbr[0x40], "capsule drive does not match the original BPB")
    first = _u32(data, 32)
    _require(2 <= first <= geometry["cluster_count"] + 1,
             "capsule IO.SYS first cluster is out of range")
    first_data = geometry["first_data_absolute_lba"]
    first_io = first_data + (first - 2) * geometry["sectors_per_cluster"]
    _require(_u32(data, 28) == first_data and _u32(data, 40) == first_io,
             "capsule LBA metadata does not match its BPB and first cluster")
    io_size = _u32(data, 36)
    _require(PREFIX_BYTES <= io_size <= geometry["cluster_count"]
             * geometry["sectors_per_cluster"] * 512,
             "capsule IO.SYS file size is outside the volume bounds")
    return {
        "schema": SCHEMA, "version": VERSION, "header_bytes": HEADER_BYTES,
        "size_bytes": CAPSULE_BYTES, "flags": FLAGS, "checksum": _u32(data, 16),
        "partition_start_lba": start, "first_data_absolute_lba": first_data,
        "io_first_cluster": first, "io_size_bytes": io_size,
        "io_first_absolute_lba": first_io, "prefix_bytes": PREFIX_BYTES,
        "bpb_bytes": BPB_BYTES, "io_sha256": data[56:88].hex(),
        "vbr_sha256": data[88:120].hex(), "drive": data[120],
        "marker": data[121], "partition_type": kind,
        "prefix_sha256": _sha256(prefix),
    }


def create_capsule(disk_bytes: bytes, expected_io_sha256: str) -> tuple[bytes, dict]:
    """Derive one capsule from a single immutable MBR/FAT32 disk snapshot."""
    _require(isinstance(disk_bytes, bytes), "disk input must be immutable bytes")
    expected = _expected_hash(expected_io_sha256)
    partition = _partition(disk_bytes)
    start = partition["start_lba"]
    vbr = disk_bytes[start * 512:(start + 1) * 512]
    geometry = _geometry(vbr, start, partition["sectors"])
    volume = _Volume(disk_bytes, partition, geometry)
    first, io_size, root_clusters = volume.io_entry()
    io_bytes, file_clusters = volume.read_io(first, io_size, root_clusters)
    io_hash = _sha256(io_bytes)
    _require(io_hash == expected, "full IO.SYS SHA-256 does not match the required identity pin")
    prefix = io_bytes[:PREFIX_BYTES]
    _prefix_contract(prefix)
    first_io = volume.cluster_lba(first)
    header = bytearray(HEADER_BYTES)
    header[:8] = MAGIC
    struct.pack_into("<HH", header, 8, VERSION, HEADER_BYTES)
    struct.pack_into("<11I", header, 12, CAPSULE_BYTES, 0, FLAGS, start,
                     geometry["first_data_absolute_lba"], first, io_size,
                     first_io, PREFIX_BYTES, BPB_BYTES, 0)
    header[56:88] = bytes.fromhex(io_hash)
    header[88:120] = hashlib.sha256(vbr).digest()
    header[120:124] = bytes((vbr[0x40], partition["type"] | 2, partition["type"], 0))
    capsule = bytes(header) + vbr + prefix
    checksum = (-sum(struct.unpack("<672I", capsule))) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, checksum)
    capsule = bytes(header) + vbr + prefix
    parsed = parse_capsule(capsule)
    report = {
        "schema": SCHEMA,
        "input": {"sha256": _sha256(disk_bytes), "size_bytes": len(disk_bytes)},
        "partition": {key: partition[key] for key in ("index", "type", "start_lba", "sectors")},
        "fat32": geometry,
        "io_sys": {"sha256": io_hash, "size_bytes": io_size,
                   "first_cluster": first, "first_absolute_lba": first_io,
                   "prefix_sha256": parsed["prefix_sha256"],
                   "file_clusters": file_clusters, "root_clusters": len(root_clusters)},
        "capsule": {"sha256": _sha256(capsule), "size_bytes": len(capsule),
                    "checksum": checksum, "vbr_sha256": parsed["vbr_sha256"]},
        "entry": {"cs": 0x0070, "ip": 0x0200, "ss": 0, "sp": 0x7BF0,
                  "ds": 0, "es": 0, "bp": 0x7C00, "bx": 0x0700, "cx": 0,
                  "si": first >> 16, "di": first & 0xFFFF,
                  "drive_from_bpb": parsed["drive"], "memory_bpb_marker": parsed["marker"],
                  "original_int1e_vector_required": True},
        "source_unchanged": True,
        "guest_executed": False,
        "runtime_compatibility": "unverified",
    }
    return capsule, report


def _file_digest(path: Path) -> tuple[str, os.stat_result]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        _require(stat.S_ISREG(before.st_mode), "input must be a regular raw disk image")
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    _require(_file_identity(before) == _file_identity(after),
             "source disk changed while its unchanged check was running")
    return digest.hexdigest(), after


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=Path, help="existing private raw MBR/FAT32 disk image")
    parser.add_argument("--io-sha256", required=True, help="required full original IO.SYS SHA-256")
    parser.add_argument("--output", required=True, type=Path, help="new private capsule file (never overwritten)")
    args = parser.parse_args(argv)
    created_identity = None
    try:
        expected = _expected_hash(args.io_sha256)
        _require(args.disk.resolve() != args.output.resolve(), "capsule output must differ from the source disk")
        with args.disk.open("rb") as stream:
            before = os.fstat(stream.fileno())
            _require(stat.S_ISREG(before.st_mode), "input must be a regular raw disk image")
            snapshot = stream.read()
            after = os.fstat(stream.fileno())
        _require(_file_identity(before) == _file_identity(after)
                 and len(snapshot) == before.st_size, "source disk changed while it was read")
        capsule, report = create_capsule(snapshot, expected)
        snapshot_hash = report["input"]["sha256"]

        def confirm_source() -> None:
            digest, current = _file_digest(args.disk)
            _require(digest == snapshot_hash and _file_identity(current) == _file_identity(before),
                     "source disk changed; capsule preparation is rejected")

        confirm_source()
        with args.output.open("xb") as output:
            created_identity = os.fstat(output.fileno())
            output.write(capsule)
            output.flush()
            os.fsync(output.fileno())
            confirm_source()
        report["input"]["path"] = str(args.disk.resolve())
        report["capsule"]["path"] = str(args.output.resolve())
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (CapsuleError, OSError) as error:
        if created_identity is not None:
            try:
                current = args.output.stat()
                if (current.st_dev, current.st_ino) == (created_identity.st_dev, created_identity.st_ino):
                    args.output.unlink()
            except OSError:
                pass
        print(f"IO.SYS capsule preparation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
