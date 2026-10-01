#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounds, path aliases and exact owner-forwarder selection tests; no guest."""
import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location("private_memory_bridge_build", Path(__file__).with_name("build.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def archive(files):
    header = 16 + 136 * len(files)
    rows, payload = bytearray(), bytearray()
    for name, content in files:
        offset = (header + len(payload) + 15) & ~15
        payload.extend(b"\0" * (offset - header - len(payload)))
        rows.extend(struct.pack("<120sQQ", name.encode(), offset, len(content)))
        payload.extend(content)
    return bytearray(b"SHZARC01" + struct.pack("<II", len(files), 0) + rows + payload)


class ArchiveTests(unittest.TestCase):
    def test_valid_bytes_and_order(self):
        files = [("\\SHZ\\SYS64\\kernel32.dll", b"abcdef"), ("\\SHZ\\SYS64\\UXTHEME.DLL", b"123")]
        self.assertEqual(list(builder.parse_archive(archive(files)).items()), files)

    def test_zero_length(self):
        self.assertEqual(builder.parse_archive(archive([("\\SHZ\\EMPTY", b"")])), {"\\SHZ\\EMPTY": b""})

    def test_header(self):
        for raw in (b"", b"SHZARC01", b"BADARC01" + struct.pack("<II", 1, 0), b"SHZARC01" + struct.pack("<II", 0, 0),
                    b"SHZARC01" + struct.pack("<II", 4097, 0), b"SHZARC01" + struct.pack("<II", 1, 1)):
            with self.subTest(raw=raw), self.assertRaises(ValueError): builder.parse_archive(raw)

    def test_paths(self):
        for name in ("relative", "\\\\SHZ\\A", "\\SHZ\\..\\X", "\\SHZ\\.\\X", "\\SHZ\\\\X", "\\SHZ\\X.",
                     "\\SHZ\\X ", "\\SHZ\\X:Y", "\\SHZ\\X/Y", "\\SHZ\\X*Y", "\\SHZ\\X\x01Y"):
            with self.subTest(name=name), self.assertRaises(ValueError): builder.parse_archive(archive([(name, b"a")]))

    def test_duplicate(self):
        with self.assertRaises(ValueError): builder.parse_archive(archive([("\\SHZ\\X", b"a"), ("\\SHZ\\X", b"b")]))

    def test_case_alias(self):
        for files in ([ ("\\SHZ\\X", b"a"), ("\\shz\\Y", b"b") ], [ ("\\SHZ\\X", b"a"), ("\\SHZ\\x", b"b") ]):
            with self.assertRaises(ValueError): builder.parse_archive(archive(files))

    def test_file_directory_collision(self):
        with self.assertRaises(ValueError): builder.parse_archive(archive([("\\SHZ\\X", b"a"), ("\\SHZ\\X\\Y", b"b")]))

    def test_non_ascii(self):
        raw = archive([("\\SHZ\\X", b"a")]); raw[16 + 5] = 0xff
        with self.assertRaises(ValueError): builder.parse_archive(raw)

    def test_name_padding(self):
        raw = archive([("\\SHZ\\X", b"a")]); raw[16 + 90] = 1
        with self.assertRaises(ValueError): builder.parse_archive(raw)

    def test_name_terminator(self):
        raw = archive([("\\SHZ\\X", b"a")]); raw[16:136] = b"A" * 120
        with self.assertRaises(ValueError): builder.parse_archive(raw)

    def test_extent(self):
        for offset, size in ((0, 1), (153, 1), (160, 999), ((1 << 64) - 16, 32)):
            raw = archive([("\\SHZ\\X", b"a")]); struct.pack_into("<QQ", raw, 16 + 120, offset, size)
            with self.subTest(offset=offset), self.assertRaises(ValueError): builder.parse_archive(raw)

    def test_overlap(self):
        raw = archive([("\\SHZ\\X", b"a" * 32), ("\\SHZ\\Y", b"b")])
        offset = struct.unpack_from("<Q", raw, 16 + 120)[0]
        struct.pack_into("<Q", raw, 16 + 136 + 120, offset + 16)
        with self.assertRaises(ValueError): builder.parse_archive(raw)

    def test_alignment_padding(self):
        raw = archive([("\\SHZ\\X", b"a")]); raw[152] = 1
        with self.assertRaises(ValueError): builder.parse_archive(raw)

    def test_trailing_data(self):
        with self.assertRaises(ValueError): builder.parse_archive(archive([("\\SHZ\\X", b"a")]) + b"\0")


class ForwarderTests(unittest.TestCase):
    def test_exact_direct_only(self):
        exports = {"RealOwner": {"forwarder": None}, "ExistingForwarder": {"forwarder": "NTDLL.Real"},
                   "VirtualAlloc2": {"forwarder": None}}
        self.assertEqual(builder.direct_forwarders(exports), {"RealOwner": "KERNEL32.RealOwner"})

    def test_no_case_rewrite(self):
        self.assertEqual(builder.direct_forwarders({"MixedCase": {"forwarder": None}}), {"MixedCase": "KERNEL32.MixedCase"})

    def test_dll_and_ordinal_not_synthesized(self):
        for name in ("A.B", "#10", "export-name", "A" * 96, "A\nB"):
            with self.subTest(name=name), self.assertRaises(ValueError): builder.direct_forwarders({name: {"forwarder": None}})

    def test_no_reinterpret_existing_forwarder(self):
        self.assertEqual(builder.direct_forwarders({"Real": {"forwarder": "KERNELBASE.Missing"}}), {})


if __name__ == "__main__":
    unittest.main()
