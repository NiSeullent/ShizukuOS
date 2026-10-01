"""Pure host safety tests; no guest, disk write, or assembler invocation."""
import importlib.util
from pathlib import Path
import struct
import unittest


SPEC = importlib.util.spec_from_file_location("ios_gop_boot_probe_build", Path(__file__).with_name("build.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def disk(entries=((0, 0x80, 0x0C, 63, 131072),)):
    mbr = bytearray(512)
    mbr[:446] = bytes((index * 37 + 11) & 255 for index in range(446))
    mbr[510:] = b"\x55\xaa"
    for index, status, kind, start, count in entries:
        offset = 446 + 16 * index
        mbr[offset], mbr[offset + 4] = status, kind
        struct.pack_into("<II", mbr, offset + 8, start, count)
    return bytes(mbr)


class MbrGuardTests(unittest.TestCase):
    def test_each_supported_fat_type_and_table_position(self):
        for kind in MODULE.FAT_TYPES:
            for index in range(4):
                with self.subTest(kind=kind, index=index):
                    result = MODULE.validate_mbr(disk(((index, 0x80, kind, 63, 131072),)), 200000)
                    self.assertEqual(result["index"], index)
                    self.assertEqual(result["start_lba"], 63)

    def test_only_boot_code_changes(self):
        original = disk()
        probe = b"P" * 440 + bytes(70) + b"\x55\xaa"
        changed = MODULE.apply_to_mbr(original, probe)
        self.assertEqual(changed[:440], probe[:440])
        self.assertEqual(changed[440:], original[440:])
        self.assertEqual(original, disk())

    def test_no_active_partition(self):
        with self.assertRaises(ValueError):
            MODULE.validate_mbr(disk(((0, 0, 0x0C, 63, 131072),)), 200000)

    def test_ambiguous_active_partition(self):
        with self.assertRaises(ValueError):
            MODULE.validate_mbr(disk(((0, 0x80, 0x0C, 63, 10000), (1, 0x80, 0x06, 20000, 10000))), 200000)

    def test_no_nonfat_active_partition(self):
        with self.assertRaises(ValueError):
            MODULE.validate_mbr(disk(((0, 0x80, 0x07, 63, 131072),)), 200000)

    def test_no_gpt_or_hybrid(self):
        with self.assertRaises(ValueError):
            MODULE.validate_mbr(disk(((0, 0x80, 0x0C, 63, 10000), (1, 0, 0xEE, 20000, 10000))), 200000)

    def test_no_overlap(self):
        with self.assertRaises(ValueError):
            MODULE.validate_mbr(disk(((0, 0x80, 0x0C, 63, 10000), (1, 0, 0x06, 100, 1000))), 200000)

    def test_zero_or_outside_disk_geometry(self):
        for start, count, limit in ((0, 100, 200000), (63, 0, 200000), (63, 200000, 200000), (0xFFFFFFF0, 32, 1 << 33)):
            with self.subTest(start=start, count=count), self.assertRaises(ValueError):
                MODULE.validate_mbr(disk(((0, 0x80, 0x0C, start, count),)), limit)

    def test_partition_may_end_exactly_at_disk_end(self):
        self.assertEqual(MODULE.validate_mbr(disk(), 131135)["end_lba"], 131135)

    def test_invalid_boot_indicator_and_unused_entry(self):
        for entries in (((0, 0x7F, 0x0C, 63, 10000),), ((0, 0x80, 0x0C, 63, 10000), (1, 0, 0, 20000, 100))):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                MODULE.validate_mbr(disk(entries), 200000)

    def test_bad_signature_length_and_code_length(self):
        for mbr in (disk()[:-1], disk()[:-2] + b"XX", b""):
            with self.assertRaises(ValueError):
                MODULE.validate_mbr(mbr, 200000)
        for code in (b"", b"P" * 446, b"P" * 512, b"P" * 446 + b"X" * 64 + b"\x55\xaa"):
            with self.assertRaises(ValueError):
                MODULE.apply_to_mbr(disk(), code)

    def test_explicit_real_disk_size_required(self):
        for limit in (0, -1, True, None, "200000"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                MODULE.validate_mbr(disk(), limit)


if __name__ == "__main__":
    unittest.main()
