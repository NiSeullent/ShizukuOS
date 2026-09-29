#!/usr/bin/env python3
"""Original malformed-image and relocation checks for the local ABI harness.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True
import build
INPUT_DLL = build.ROOT / "build/platform/NTW32.DLL"


class PackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = INPUT_DLL.read_bytes()
        cls.pe, cls.image, cls.base, _, _, _ = build.inspect(cls.data)

    def test_actual_inventory(self):
        _, image, base, entry, imports, exports = build.inspect(self.data)
        self.assertEqual(base, 0x68000000)
        self.assertLess(entry, len(image))
        self.assertEqual({name for name, _ in imports}, build.IMPORTS)
        self.assertEqual(set(exports), build.EXPORTS)

    def test_image_size_limit(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, self.pe.opt + 56, 32 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, "size/base"):
            build.inspect(data)

    def test_wrong_preferred_base(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, self.pe.opt + 28, 0x67000000)
        with self.assertRaisesRegex(ValueError, "size/base"):
            build.inspect(data)

    def test_non_dll_rejected(self):
        data = bytearray(self.data)
        flags = self.pe.u16(self.pe.pe + 22)
        struct.pack_into("<H", data, self.pe.pe + 22, flags & ~0x2000)
        with self.assertRaisesRegex(ValueError, "IMAGE_FILE_DLL"):
            build.inspect(data)

    def test_tls_rejected(self):
        data = bytearray(self.data)
        struct.pack_into("<II", data, self.pe.opt + 96 + 9 * 8, 0x1000, 24)
        with self.assertRaisesRegex(ValueError, "TLS"):
            build.inspect(data)

    def test_non_code_entry_rejected(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, self.pe.opt + 16, 0x40)
        with self.assertRaisesRegex(ValueError, "executable"):
            build.inspect(data)

    def test_unsupported_import_rejected(self):
        data = self.data.replace(b"GetTickCount\0", b"GetTockCount\0", 1)
        self.assertNotEqual(data, self.data)
        with self.assertRaisesRegex(ValueError, "Unsupported import"):
            build.inspect(data)

    def test_relocation_baseline_unchanged(self):
        mapped, count = build.relocate(self.pe, self.image, self.base, self.base)
        self.assertEqual(mapped, self.image)
        self.assertGreater(count, 0)

    def test_relocation_roundtrip(self):
        moved, count = build.relocate(self.pe, self.image, self.base, self.base + 0x1000000)
        restored, restored_count = build.relocate(self.pe, moved, self.base + 0x1000000, self.base)
        self.assertNotEqual(moved, self.image)
        self.assertEqual(restored, self.image)
        self.assertEqual(count, restored_count)

    def test_unknown_relocation_rejected(self):
        image = bytearray(self.image)
        rva, _ = self.pe.directory(5)
        struct.pack_into("<H", image, rva + 8, 0xa000)
        with self.assertRaisesRegex(ValueError, "Unsupported relocation"):
            build.relocate(self.pe, image, self.base, self.base + 0x1000000)

    def test_bad_relocation_size_rejected(self):
        image = bytearray(self.image)
        rva, _ = self.pe.directory(5)
        struct.pack_into("<I", image, rva + 4, 7)
        with self.assertRaisesRegex(ValueError, "Malformed relocation block"):
            build.relocate(self.pe, image, self.base, self.base + 0x1000000)

    def test_bad_relocation_target_rejected(self):
        image = bytearray(self.image)
        rva, _ = self.pe.directory(5)
        struct.pack_into("<I", image, rva, 0xfffff000)
        struct.pack_into("<H", image, rva + 8, 0x3000)
        with self.assertRaisesRegex(ValueError, "Out-of-range"):
            build.relocate(self.pe, image, self.base, self.base + 0x1000000)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--dll", type=Path, default=INPUT_DLL)
    arguments, remaining = parser.parse_known_args()
    INPUT_DLL = arguments.dll
    unittest.main(argv=[sys.argv[0], *remaining])
