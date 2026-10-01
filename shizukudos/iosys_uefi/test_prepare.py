# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic FAT32 and IO.SYS capsule contracts; no Windows media or VM.

The smallest accepted FAT32 geometry with four sectors per cluster occupies
about 128.5 MiB. One immutable disk is shared by these tests. CLI fixtures are
sparse temporary files and are removed; every byte is authored here.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("iosys_capsule_prepare", HERE / "prepare.py")
prepare = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(prepare)

SECTOR = 512
PART_START = 63
RESERVED = 32
FAT_COUNT = 2
FAT_SECTORS = 512
SPC = 4
CLUSTER_BYTES = SECTOR * SPC
CLUSTER_COUNT = 65525
PART_SECTORS = RESERVED + FAT_COUNT * FAT_SECTORS + CLUSTER_COUNT * SPC
DISK_BYTES = (PART_START + PART_SECTORS) * SECTOR
FIRST_DATA = PART_START + RESERVED + FAT_COUNT * FAT_SECTORS
ROOT_CHAIN = (5, 80)
IO_CHAIN = (20, 45, 53)
IO_SIZE = 4099
EOC = 0x0FFFFFFF
CAPSULE_BYTES = 128 + 512 + 2048


def source_io() -> bytes:
    """Synthetic signature-bearing data, never a runnable Microsoft image."""
    data = bytearray((index * 29 + index // 251 + 17) & 255 for index in range(IO_SIZE))
    data[:2] = b"MZ"
    data[0x200:0x208] = bytes.fromhex("424a8b46fc8b56fe")
    data[0x7FE:0x800] = b"MS"
    return bytes(data)


def cluster_offset(cluster: int) -> int:
    return (FIRST_DATA + (cluster - 2) * SPC) * SECTOR


def directory_entry(name: bytes, cluster: int, size: int, attrs: int = 0x26) -> bytes:
    data = bytearray(32)
    data[:11] = name
    data[11] = attrs
    struct.pack_into("<H", data, 20, cluster >> 16)
    struct.pack_into("<H", data, 26, cluster & 0xFFFF)
    struct.pack_into("<I", data, 28, size)
    return bytes(data)


def fixture_blocks() -> dict[int, bytes]:
    """Nonzero byte ranges of a fully bounded, mirrored FAT32 disk."""
    blocks: dict[int, bytes] = {}
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"\xfe\xff\xff", 0x0C,
                               b"\xfe\xff\xff", PART_START, PART_SECTORS)
    mbr[510:] = b"\x55\xaa"
    blocks[0] = bytes(mbr)
    bpb = bytearray(SECTOR)
    bpb[:11] = b"\xeb\x58\x90SYNTH98 "
    struct.pack_into("<HBHBHHBHHHII", bpb, 11, SECTOR, SPC, RESERVED, FAT_COUNT,
                     0, 0, 0xF8, 0, 63, 255, PART_START, PART_SECTORS)
    struct.pack_into("<IHHIHH", bpb, 36, FAT_SECTORS, 0, 0, ROOT_CHAIN[0], 1, 6)
    bpb[0x40], bpb[0x42] = 0x80, 0x29
    struct.pack_into("<I", bpb, 67, 0x53594E54)
    bpb[71:82], bpb[82:90] = b"IOSYS TEST ", b"FAT32   "
    bpb[510:] = b"\x55\xaa"
    blocks[PART_START * SECTOR] = bytes(bpb)
    fat = bytearray(SECTOR)
    entries = {0: 0x0FFFFFF8, 1: EOC}
    for chain in (ROOT_CHAIN, IO_CHAIN):
        for index, cluster in enumerate(chain):
            entries[cluster] = chain[index + 1] if index + 1 < len(chain) else EOC
    for cluster, value in entries.items():
        struct.pack_into("<I", fat, cluster * 4, value)
    for copy in range(FAT_COUNT):
        blocks[(PART_START + RESERVED + copy * FAT_SECTORS) * SECTOR] = bytes(fat)
    first_root = bytearray(CLUSTER_BYTES)
    first_root[::32] = b"\xe5" * (CLUSTER_BYTES // 32)
    blocks[cluster_offset(ROOT_CHAIN[0])] = bytes(first_root)
    second_root = bytearray(CLUSTER_BYTES)
    second_root[:32] = directory_entry(b"IOSYS TEST ", 0, 0, 0x08)
    second_root[32:64] = directory_entry(b"IGNORED LFN", 0, 0, 0x0F)
    second_root[64:96] = directory_entry(b"IO      SYS", IO_CHAIN[0], IO_SIZE)
    # An invalid matching record after the directory end is ignored.
    second_root[128:160] = directory_entry(b"IO      SYS", 0, IO_SIZE)
    blocks[cluster_offset(ROOT_CHAIN[1])] = bytes(second_root)
    data = source_io()
    for index, cluster in enumerate(IO_CHAIN):
        chunk = data[index * CLUSTER_BYTES:(index + 1) * CLUSTER_BYTES]
        blocks[cluster_offset(cluster)] = chunk + bytes([0xCC]) * (CLUSTER_BYTES - len(chunk))
    return blocks


def synthetic_disk() -> bytes:
    disk = bytearray(DISK_BYTES)
    for offset, data in fixture_blocks().items():
        disk[offset:offset + len(data)] = data
    return bytes(disk)


def put_fat(disk: bytearray, cluster: int, value: int, copies=(0, 1)) -> None:
    for copy in copies:
        offset = (PART_START + RESERVED + copy * FAT_SECTORS) * SECTOR + cluster * 4
        struct.pack_into("<I", disk, offset, value)


def fix_capsule_checksum(capsule: bytearray) -> bytes:
    struct.pack_into("<I", capsule, 16, 0)
    total = sum(struct.unpack("<" + "I" * (len(capsule) // 4), capsule)) & 0xFFFFFFFF
    struct.pack_into("<I", capsule, 16, (-total) & 0xFFFFFFFF)
    return bytes(capsule)


class IOSysCapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.disk = synthetic_disk()
        cls.io_bytes = source_io()
        cls.io_sha256 = hashlib.sha256(cls.io_bytes).hexdigest()
        cls.disk_sha256 = hashlib.sha256(cls.disk).hexdigest()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def capsule(self) -> tuple[bytes, dict]:
        return prepare.create_capsule(self.disk, self.io_sha256)

    def assert_rejected(self, disk: bytes | bytearray, expected: str | None = None) -> None:
        with self.assertRaises(prepare.CapsuleError):
            prepare.create_capsule(bytes(disk), self.io_sha256 if expected is None else expected)

    def sparse_source(self) -> Path:
        path = self.folder / "synthetic-fat32.raw"
        with path.open("xb") as stream:
            stream.truncate(DISK_BYTES)
            for offset, data in fixture_blocks().items():
                stream.seek(offset)
                stream.write(data)
        return path

    def test_exact_wire_layout_checksum_and_source_receipt(self) -> None:
        capsule, report = self.capsule()
        self.assertEqual(len(capsule), CAPSULE_BYTES)
        self.assertEqual(capsule[:8], b"SHZIO98\0")
        self.assertEqual(struct.unpack_from("<HHI", capsule, 8), (1, 128, CAPSULE_BYTES))
        self.assertEqual(sum(struct.unpack("<672I", capsule)) & 0xFFFFFFFF, 0)
        self.assertEqual(struct.unpack_from("<9I", capsule, 20), (
            3, PART_START, FIRST_DATA, IO_CHAIN[0], IO_SIZE,
            FIRST_DATA + (IO_CHAIN[0] - 2) * SPC, 2048, 512, 0,
        ))
        self.assertEqual(capsule[56:88], hashlib.sha256(self.io_bytes).digest())
        bpb = self.disk[PART_START * SECTOR:(PART_START + 1) * SECTOR]
        self.assertEqual(capsule[88:120], hashlib.sha256(bpb).digest())
        self.assertEqual(capsule[120:128], b"\x80\x0e\x0c\0\0\0\0\0")
        self.assertEqual(capsule[128:640], bpb)
        self.assertEqual(capsule[640:], self.io_bytes[:2048])
        self.assertEqual(report["input"]["sha256"], self.disk_sha256)
        self.assertEqual(report["input"]["size_bytes"], DISK_BYTES)
        self.assertEqual(report["partition"]["start_lba"], PART_START)
        self.assertEqual(report["fat32"]["cluster_count"], CLUSTER_COUNT)
        self.assertEqual(report["fat32"]["root_cluster"], ROOT_CHAIN[0])
        self.assertEqual(report["io_sys"]["first_cluster"], IO_CHAIN[0])
        self.assertEqual(report["io_sys"]["sha256"], self.io_sha256)
        self.assertEqual(report["io_sys"]["size_bytes"], IO_SIZE)
        self.assertEqual(report["capsule"]["sha256"], hashlib.sha256(capsule).hexdigest())
        self.assertIs(report["guest_executed"], False)
        self.assertEqual(report["runtime_compatibility"], "unverified")

    def test_parse_round_trip_has_derived_locations_and_serializable_fields(self) -> None:
        capsule, _ = self.capsule()
        decoded = prepare.parse_capsule(capsule)
        self.assertIsInstance(decoded, dict)
        self.assertEqual(decoded["version"], 1)
        self.assertEqual(decoded["header_bytes"], 128)
        self.assertEqual(decoded["size_bytes"], CAPSULE_BYTES)
        self.assertEqual(decoded["flags"], 3)
        self.assertEqual(decoded["partition_start_lba"], PART_START)
        self.assertEqual(decoded["first_data_absolute_lba"], FIRST_DATA)
        self.assertEqual(decoded["io_first_cluster"], IO_CHAIN[0])
        self.assertEqual(decoded["io_first_absolute_lba"], FIRST_DATA + (IO_CHAIN[0] - 2) * SPC)
        self.assertEqual(decoded["io_size_bytes"], IO_SIZE)
        self.assertEqual(decoded["io_sha256"], self.io_sha256)
        self.assertEqual(decoded["prefix_sha256"], hashlib.sha256(self.io_bytes[:2048]).hexdigest())
        self.assertEqual(decoded["drive"], 0x80)
        self.assertEqual(decoded["marker"], 0x0E)
        self.assertEqual(decoded["partition_type"], 0x0C)
        json.dumps(decoded)

    def test_source_bytes_remain_immutable(self) -> None:
        capsule, _ = self.capsule()
        self.assertEqual(hashlib.sha256(self.disk).hexdigest(), self.disk_sha256)
        self.assertNotEqual(len(capsule), len(self.disk))
        self.assertEqual(self.disk[cluster_offset(IO_CHAIN[0]):cluster_offset(IO_CHAIN[0]) + 2048],
                         self.io_bytes[:2048])

    def test_file_location_is_derived_from_directory_not_a_fixed_cluster(self) -> None:
        disk = bytearray(self.disk)
        moved = 21
        target = cluster_offset(moved)
        disk[target:target + CLUSTER_BYTES] = self.io_bytes[:CLUSTER_BYTES]
        entry = cluster_offset(ROOT_CHAIN[1]) + 64
        struct.pack_into("<H", disk, entry + 26, moved)
        put_fat(disk, moved, IO_CHAIN[1])
        put_fat(disk, IO_CHAIN[0], 0)
        capsule, report = prepare.create_capsule(bytes(disk), self.io_sha256)
        decoded = prepare.parse_capsule(capsule)
        self.assertEqual(report["io_sys"]["first_cluster"], moved)
        self.assertEqual(decoded["io_first_cluster"], moved)
        self.assertEqual(decoded["io_first_absolute_lba"], FIRST_DATA + (moved - 2) * SPC)
        self.assertEqual(report["entry"]["di"], moved)
        self.assertEqual(capsule[640:], self.io_bytes[:2048])

    def test_fat32_chs_partition_uses_its_original_type_marker(self) -> None:
        disk = bytearray(self.disk)
        disk[450] = 0x0B
        capsule, _ = prepare.create_capsule(bytes(disk), self.io_sha256)
        decoded = prepare.parse_capsule(capsule)
        self.assertEqual(decoded["partition_type"], 0x0B)
        self.assertEqual(decoded["marker"], 0x0B)
        self.assertEqual(capsule[128:640], self.disk[PART_START * SECTOR:(PART_START + 1) * SECTOR])

    def test_complete_file_hash_is_required_including_fragmented_tail(self) -> None:
        self.assert_rejected(self.disk, "0" * 64)
        disk = bytearray(self.disk)
        disk[cluster_offset(IO_CHAIN[-1]) + 1] ^= 1
        self.assertEqual(disk[cluster_offset(IO_CHAIN[0]):cluster_offset(IO_CHAIN[0]) + 2048],
                         self.io_bytes[:2048])
        self.assert_rejected(disk)

    def test_malformed_expected_hash_is_rejected(self) -> None:
        for digest in ("", "0" * 63, "g" * 64, "0" * 65):
            with self.subTest(digest=digest):
                self.assert_rejected(self.disk, digest)

    def test_mbr_and_partition_bounds_fail_closed(self) -> None:
        for offset, replacement in ((510, b"\0\0"), (446, b"\0"),
                                    (450, b"\x07"), (454, struct.pack("<I", 0)),
                                    (458, struct.pack("<I", PART_SECTORS + 1))):
            with self.subTest(offset=offset):
                disk = bytearray(self.disk)
                disk[offset:offset + len(replacement)] = replacement
                self.assert_rejected(disk)

    def test_two_active_fat32_partitions_are_ambiguous(self) -> None:
        disk = bytearray(self.disk)
        disk[462:478] = disk[446:462]
        self.assert_rejected(disk)

    def test_truncated_disk_and_tiny_fat32_geometry_are_rejected(self) -> None:
        self.assert_rejected(self.disk[:-1])
        disk = bytearray(self.disk)
        struct.pack_into("<I", disk, PART_START * SECTOR + 32,
                         RESERVED + FAT_COUNT * FAT_SECTORS + 100 * SPC)
        self.assert_rejected(disk)

    def test_bpb_hidden_sectors_and_fat_capacity_are_validated(self) -> None:
        for field, value in ((28, PART_START + 1), (36, 1), (44, CLUSTER_COUNT + 2)):
            with self.subTest(field=field):
                disk = bytearray(self.disk)
                struct.pack_into("<I", disk, PART_START * SECTOR + field, value)
                self.assert_rejected(disk)

    def test_prefix_requires_four_contiguous_sectors_in_the_first_cluster(self) -> None:
        for spc in (0, 1, 2, 3):
            with self.subTest(spc=spc):
                disk = bytearray(self.disk)
                disk[PART_START * SECTOR + 13] = spc
                self.assert_rejected(disk)

    def test_root_search_follows_chain_and_ignores_lfn_volume_and_post_end_records(self) -> None:
        capsule, report = self.capsule()
        self.assertEqual(report["io_sys"]["first_cluster"], IO_CHAIN[0])
        self.assertEqual(capsule[640:], self.io_bytes[:2048])
        disk = bytearray(self.disk)
        disk[cluster_offset(ROOT_CHAIN[0])] = 0
        self.assert_rejected(disk)

    def test_missing_source_name_or_directory_entry_is_rejected(self) -> None:
        for field, value in ((0, ord("X")), (11, 0x10)):
            with self.subTest(field=field):
                disk = bytearray(self.disk)
                disk[cluster_offset(ROOT_CHAIN[1]) + 64 + field] = value
                self.assert_rejected(disk)

    def test_root_directory_cycle_does_not_loop(self) -> None:
        disk = bytearray(self.disk)
        put_fat(disk, ROOT_CHAIN[0], ROOT_CHAIN[0])
        self.assert_rejected(disk)

    def test_invalid_first_file_clusters_are_rejected(self) -> None:
        for cluster in (0, 1, CLUSTER_COUNT + 2, 0x0FFFFFF5):
            with self.subTest(cluster=cluster):
                disk = bytearray(self.disk)
                entry = cluster_offset(ROOT_CHAIN[1]) + 64
                struct.pack_into("<H", disk, entry + 20, cluster >> 16)
                struct.pack_into("<H", disk, entry + 26, cluster & 0xFFFF)
                self.assert_rejected(disk)

    def test_fat_file_chain_cycles_free_reserved_bad_and_early_eoc_fail_closed(self) -> None:
        for value in (IO_CHAIN[0], 0, 1, 0x0FFFFFF0, 0x0FFFFFF7, EOC):
            with self.subTest(value=value):
                disk = bytearray(self.disk)
                put_fat(disk, IO_CHAIN[0], value)
                self.assert_rejected(disk)

    def test_file_chain_must_end_at_declared_file_length(self) -> None:
        disk = bytearray(self.disk)
        put_fat(disk, IO_CHAIN[-1], 54)
        put_fat(disk, 54, EOC)
        self.assert_rejected(disk)

    def test_mirrored_fat_disagreement_on_used_entry_is_rejected(self) -> None:
        disk = bytearray(self.disk)
        put_fat(disk, IO_CHAIN[0], 46, copies=(1,))
        self.assert_rejected(disk)

    def test_unmirrored_first_fat_does_not_consult_inactive_second_copy(self) -> None:
        disk = bytearray(self.disk)
        struct.pack_into("<H", disk, PART_START * SECTOR + 40, 0x80)
        put_fat(disk, IO_CHAIN[0], 0, copies=(1,))
        capsule, report = prepare.create_capsule(bytes(disk), self.io_sha256)
        self.assertEqual(capsule[640:], self.io_bytes[:2048])
        self.assertEqual(report["io_sys"]["sha256"], self.io_sha256)

    def test_second_active_fat_requires_a_separate_msload_contract(self) -> None:
        disk = bytearray(self.disk)
        struct.pack_into("<H", disk, PART_START * SECTOR + 40, 0x81)
        self.assert_rejected(disk)

    def test_source_is_large_enough_for_prefix_and_signatures_are_checked(self) -> None:
        disk = bytearray(self.disk)
        struct.pack_into("<I", disk, cluster_offset(ROOT_CHAIN[1]) + 64 + 28, 2047)
        self.assert_rejected(disk)
        for file_offset in (0, 0x200, 0x7FE):
            with self.subTest(file_offset=file_offset):
                changed_io = bytearray(self.io_bytes)
                changed_io[file_offset] ^= 1
                disk = bytearray(self.disk)
                disk[cluster_offset(IO_CHAIN[0]) + file_offset] ^= 1
                self.assert_rejected(disk, hashlib.sha256(changed_io).hexdigest())

    def test_capsule_checksum_rejects_header_and_payload_tampering(self) -> None:
        capsule, _ = self.capsule()
        for offset in (0, 20, 56, 128 + 3, 640 + 29, CAPSULE_BYTES - 1):
            with self.subTest(offset=offset):
                changed = bytearray(capsule)
                changed[offset] ^= 1
                with self.assertRaises(prepare.CapsuleError):
                    prepare.parse_capsule(bytes(changed))

    def test_capsule_length_is_exact(self) -> None:
        capsule, _ = self.capsule()
        for changed in (b"", capsule[:127], capsule[:-1], capsule + b"\0"):
            with self.subTest(length=len(changed)):
                with self.assertRaises(prepare.CapsuleError):
                    prepare.parse_capsule(changed)

    def test_recomputed_checksum_cannot_bypass_fixed_header_contract(self) -> None:
        capsule, _ = self.capsule()
        changes = ((8, "<H", 2), (10, "<H", 124), (12, "<I", CAPSULE_BYTES - 4),
                   (20, "<I", 1), (44, "<I", 2044), (48, "<I", 508),
                   (52, "<I", 1), (123, "<B", 1), (124, "<I", 1))
        for offset, fmt, value in changes:
            with self.subTest(offset=offset):
                changed = bytearray(capsule)
                struct.pack_into(fmt, changed, offset, value)
                with self.assertRaises(prepare.CapsuleError):
                    prepare.parse_capsule(fix_capsule_checksum(changed))

    def test_recomputed_checksum_cannot_forge_lba_geometry_or_marker(self) -> None:
        capsule, _ = self.capsule()
        changes = ((24, "<I", PART_START + 1), (28, "<I", FIRST_DATA + 1),
                   (32, "<I", 0), (40, "<I", FIRST_DATA),
                   (120, "<B", 0), (121, "<B", 0), (122, "<B", 7))
        for offset, fmt, value in changes:
            with self.subTest(offset=offset):
                changed = bytearray(capsule)
                struct.pack_into(fmt, changed, offset, value)
                with self.assertRaises(prepare.CapsuleError):
                    prepare.parse_capsule(fix_capsule_checksum(changed))

    def test_recomputed_checksum_does_not_bypass_vbr_hash_or_io_signatures(self) -> None:
        capsule, _ = self.capsule()
        for offset in (128 + 3, 640, 640 + 0x200, 640 + 0x7FE):
            with self.subTest(offset=offset):
                changed = bytearray(capsule)
                changed[offset] ^= 1
                with self.assertRaises(prepare.CapsuleError):
                    prepare.parse_capsule(fix_capsule_checksum(changed))

    def test_cli_emits_new_capsule_and_json_without_changing_sparse_source(self) -> None:
        source = self.sparse_source()
        output = self.folder / "IOSYS.BIN"
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = prepare.main([str(source), "--io-sha256", self.io_sha256,
                                   "--output", str(output)])
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["input"]["sha256"], self.disk_sha256)
        capsule = output.read_bytes()
        self.assertEqual(prepare.parse_capsule(capsule)["io_sha256"], self.io_sha256)
        self.assertEqual(report["capsule"]["sha256"], hashlib.sha256(capsule).hexdigest())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), self.disk_sha256)
        self.assertEqual({path.name for path in self.folder.iterdir()}, {source.name, output.name})

    def test_cli_refuses_existing_output_without_overwriting_it(self) -> None:
        source = self.sparse_source()
        output = self.folder / "IOSYS.BIN"
        output.write_bytes(b"retained artifact")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = prepare.main([str(source), "--io-sha256", self.io_sha256,
                                   "--output", str(output)])
        self.assertEqual(result, 2)
        self.assertEqual(output.read_bytes(), b"retained artifact")
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(stderr.getvalue())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), self.disk_sha256)

    def test_cli_failed_hash_gate_does_not_create_output(self) -> None:
        source = self.sparse_source()
        output = self.folder / "IOSYS.BIN"
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = prepare.main([str(source), "--io-sha256", "0" * 64,
                                   "--output", str(output)])
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
