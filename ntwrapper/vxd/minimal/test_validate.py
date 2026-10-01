#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-only format rejection and relocated DDB tests; no Windows loader claim."""
import importlib.util
import random
import struct
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("minimal_le_reader", HERE / "validate.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = ("original-flags", "shared-data", "shared-both",
                 "shared-nonresident", "all-executable", "ddb-first")
        cls.files = [HERE / "build" / name / "NTWMIN9X.VXD" for name in names]
        if not all(path.is_file() for path in cls.files):
            raise RuntimeError("build all six fixture variants before testing")
        cls.image = cls.files[0].read_bytes()

    def test_all_variants_have_a_relocatable_exported_ddb(self):
        for path in self.files:
            with self.subTest(variant=path.parent.name):
                decoded = reader.decode(path.read_bytes())
                self.assertEqual(decoded["module_name"], "NTWMIN9X")
                self.assertEqual(len(decoded["fixups"]), 1)
                first = path.parent.name == "ddb-first"
                self.assertEqual(decoded["ddb"]["object"], 1 if first else 2)
                for bases in ((0x100000, 0x300000), (0xc1000000, 0xc3000000)):
                    loaded = reader.relocate(decoded, bases)
                    obj = 0 if first else 1
                    self.assertEqual(struct.unpack_from("<I", loaded[obj], 24)[0], bases[0] + (80 if first else 0))
                    self.assertEqual(loaded[1 - obj], decoded["buffers"][1 - obj])
                    self.assertEqual(loaded[obj][:24], decoded["buffers"][obj][:24])
                    self.assertEqual(loaded[obj][28:], decoded["buffers"][obj][28:])

    def test_truncation_and_trailing_bytes_are_rejected(self):
        for size in (0, 63, 127, 128, 323, 4095, len(self.image) - 1):
            with self.subTest(size=size), self.assertRaises(reader.InvalidLE):
                reader.decode(self.image[:size])
        with self.assertRaises(reader.InvalidLE):
            reader.decode(self.image + b"\x00")

    def test_corrupted_offsets_and_counts_are_bounded(self):
        for offset in (0x3c, 0x80 + 0x14, 0x80 + 0x44, 0x80 + 0x40,
                       0x80 + 0x48, 0x80 + 0x58, 0x80 + 0x5c,
                       0x80 + 0x68, 0x80 + 0x6c, 0x80 + 0x80):
            damaged = bytearray(self.image)
            struct.pack_into("<I", damaged, offset, 0xffffffff)
            with self.subTest(offset=offset), self.assertRaises(reader.InvalidLE):
                reader.decode(damaged)

    def test_ddb_and_fixup_damage_are_rejected(self):
        le = struct.unpack_from("<I", self.image, 0x3c)[0]
        fixup = le + struct.unpack_from("<I", self.image, le + 0x6c)[0]
        decoded = reader.decode(self.image)
        ddb = (struct.unpack_from("<I", self.image, le + 0x80)[0]
               + (decoded["objects"][decoded["ddb"]["object"] - 1]["page_start"] - 1) * 4096)
        for offset, value in ((fixup, 3), (fixup + 1, 0), (fixup + 4, 0),
                              (fixup + 8, 255), (ddb + 4, 0),
                              (ddb + 12, ord("X")), (ddb + 64, 0)):
            damaged = bytearray(self.image)
            damaged[offset] = value
            with self.subTest(offset=offset), self.assertRaises(reader.InvalidLE):
                reader.decode(damaged)

    def test_relocated_objects_cannot_alias_or_wrap(self):
        decoded = reader.decode(self.image)
        for bases in ((0x100000,), (0x100000, 0x100010),
                      (0xffffff00, 0x300000), (-1, 0x300000)):
            with self.subTest(bases=bases), self.assertRaises(reader.InvalidLE):
                reader.relocate(decoded, bases)

    def test_bounded_mutations_raise_only_format_errors(self):
        rng = random.Random(98)
        for _ in range(300):
            damaged = bytearray(self.image)
            offset = rng.randrange(len(damaged))
            damaged[offset] ^= rng.randrange(1, 256)
            try:
                reader.decode(damaged)
            except reader.InvalidLE:
                pass


if __name__ == "__main__":
    unittest.main()
