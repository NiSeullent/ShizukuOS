"""PE32 loader-output storage versus raw metadata, using inert synthetic images.

Fixtures and preparation stay in memory. No application, build, image writer,
network operation or guest is started by these tests.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ntw_prepare_zero_fill', ROOT / 'ntwin32/prepare.py')
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)

BASE = 0x400000
OPTIONAL = 0x98
SECTIONS = OPTIONAL + 224
RAW_START = 0x400
TLS_RVA = 0x3100
CONFIG_RVA = 0x3180


def synthetic_pe() -> bytes:
    """TLS index in .data's virtual tail; initialized CFG slots in .rdata."""
    image = bytearray(0xC00)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 0x3C, 0x80)
    struct.pack_into('<I', image, 0x80, 0x4550)
    struct.pack_into('<HHIIIHH', image, 0x84, 0x14C, 3, 0, 0, 0, 224, 0x0102)
    struct.pack_into('<H', image, OPTIONAL, 0x10B)
    struct.pack_into('<I', image, OPTIONAL + 4, 0x200)
    struct.pack_into('<I', image, OPTIONAL + 8, 0x600)
    struct.pack_into('<I', image, OPTIONAL + 16, 0x1000)
    struct.pack_into('<I', image, OPTIONAL + 28, BASE)
    struct.pack_into('<II', image, OPTIONAL + 32, 0x1000, 0x200)
    struct.pack_into('<HH', image, OPTIONAL + 40, 10, 0)
    struct.pack_into('<HH', image, OPTIONAL + 48, 10, 0)
    struct.pack_into('<II', image, OPTIONAL + 56, 0x4000, RAW_START)
    struct.pack_into('<HH', image, OPTIONAL + 68, 3, 0xC140)
    struct.pack_into('<I', image, OPTIONAL + 92, 16)
    for index, name, span, rva, raw_size, raw, flags in (
        (0, b'.text', 0x200, 0x1000, 0x200, 0x400, 0x60000020),
        (1, b'.data', 0x300, 0x2000, 0x200, 0x600, 0xC0000040),
        (2, b'.rdata', 0x400, 0x3000, 0x400, 0x800, 0x40000040),
    ):
        struct.pack_into('<8sIIIIIIHHI', image, SECTIONS + index * 40,
                         name, span, rva, raw_size, raw, 0, 0, 0, 0, flags)

    def put(rva: int, fmt: str, *values: int) -> None:
        raw = (0x600 + rva - 0x2000) if 0x2000 <= rva < 0x2200 else (0x800 + rva - 0x3000)
        struct.pack_into(fmt, image, raw, *values)

    def directory(index: int, rva: int, size: int) -> None:
        struct.pack_into('<II', image, OPTIONAL + 96 + index * 8, rva, size)

    directory(1, 0x3000, 40)
    directory(9, TLS_RVA, 24)
    directory(10, CONFIG_RVA, 192)
    directory(12, 0x2010, 8)
    put(0x3000, '<IIIII', 0x3028, 0, 0, 0x3260, 0x2010)
    put(0x3028, '<II', 0x3270, 0)
    put(0x2010, '<II', 0x3270, 0)
    image[0xA60:0xA6D] = b'KERNEL32.dll\0'
    image[0xA70:0xA81] = b'\0\0GetProcAddress\0'
    put(0x2000, '<I', 0x44332211)
    put(0x2004, '<I', 0xBB40E64E)
    put(0x3040, '<II', BASE + 0x1000, 0)
    put(0x3050, '<II', BASE + 0x1000, BASE + 0x1000)
    put(0x3070, '<I', 0x1000)
    put(0x3080, '<I', 0x1000)
    put(TLS_RVA, '<6I', BASE + 0x2000, BASE + 0x2004, BASE + 0x22F0,
        BASE + 0x3040, 4, 0)
    put(CONFIG_RVA, '<I', 192)
    for offset, value in ((60, BASE + 0x2004), (64, BASE + 0x3070), (68, 1),
                          (72, BASE + 0x3050), (76, BASE + 0x3054),
                          (80, BASE + 0x3080), (84, 1), (88, 0x500)):
        put(CONFIG_RVA + offset, '<I', value)
    return bytes(image)


class RuntimeDataTargets(unittest.TestCase):
    def setUp(self):
        self.original = synthetic_pe()
        self.pe = prepare.PE(self.original)

    def changed_word(self, rva: int, value: int) -> bytes:
        data = bytearray(self.original)
        struct.pack_into('<I', data, self.pe.offset(rva, 4), value)
        return bytes(data)

    def test_preserves_zero_fill_tls_index_and_read_only_cfg_slots(self):
        prepared, report = prepare.prepare(self.original)
        rewritten = prepare.PE(prepared)
        self.assertEqual(self.original, synthetic_pe())
        self.assertEqual(prepared[RAW_START:len(self.original)], self.original[RAW_START:])
        for index in (9, 10):
            rva, size = self.pe.directory(index)
            self.assertEqual(rewritten.directory(index), (rva, size))
            self.assertEqual(prepared[rewritten.offset(rva, size):rewritten.offset(rva, size) + size],
                             self.original[self.pe.offset(rva, size):self.pe.offset(rva, size) + size])
        self.assertEqual(report['tls']['callbacks'], 1)
        self.assertEqual(report['load_config']['cfg_functions'], 1)
        self.assertEqual(report['subsystem_version'], [10, 0])
        self.assertEqual(report['dll_characteristics'], '0xc140')
        for key in ('guest_verified', 'browser_functionality_verified', 'subsystem_version_downgraded',
                    'stock_win98_loader_accepts_subsystem', 'aslr_implemented', 'nx_enforced'):
            self.assertFalse(report[key], key)

    def test_runtime_storage_does_not_manufacture_a_file_offset(self):
        self.assertEqual(self.pe.runtime_data_rva(BASE + 0x22F0, 4, writable=True), 0x22F0)
        with self.assertRaisesRegex(prepare.PEError, 'file-backed'):
            self.pe.map_va(BASE + 0x22F0, 4)
        with self.assertRaisesRegex(prepare.PEError, 'file-backed'):
            self.pe.offset(0x22F0, 4)

    def test_initialized_tls_index_remains_accepted(self):
        data = self.changed_word(TLS_RVA + 8, BASE + 0x2008)
        self.assertEqual(prepare.validate_tls(prepare.PE(data))['callbacks'], 1)

    def test_uninitialized_data_section_is_a_valid_index_output(self):
        data = bytearray(self.original)
        struct.pack_into('<I', data, SECTIONS + 40 + 36, 0xC0000080)
        self.assertEqual(prepare.validate_tls(prepare.PE(bytes(data)))['callbacks'], 1)

    def test_tls_index_rejects_unaligned_outside_and_wrong_protection_targets(self):
        for rva, reason in ((0x22F1, 'DWORD-aligned'), (0x2300, 'mapped data section'),
                            (0x22FE, 'DWORD-aligned'), (0x4000, 'SizeOfImage'),
                            (0x1000, 'non-executable data'), (0x3050, 'not writable'),
                            (0x100, 'mapped data section')):
            with self.subTest(rva=hex(rva)), self.assertRaisesRegex(prepare.PEError, reason):
                prepare.validate_tls(prepare.PE(self.changed_word(TLS_RVA + 8, BASE + rva)))

    def test_runtime_range_cannot_wrap_or_cross_section(self):
        for va, size, reason in ((0xFFFFFFFC, 8, 'PE32 address range'),
                                (BASE + 0x22FC, 8, 'mapped data section'),
                                (BASE + 0x2000, 0, 'PE32 address range')):
            with self.subTest(va=hex(va), size=size), self.assertRaisesRegex(prepare.PEError, reason):
                self.pe.runtime_data_rva(va, size, writable=True)

    def test_tls_metadata_and_templates_remain_file_backed(self):
        mutations = (
            (TLS_RVA, BASE + 0x22F0),
            (TLS_RVA + 4, BASE + 0x22F4),
            (TLS_RVA + 12, BASE + 0x22F0),
        )
        # Move the template as a pair, or only its callback array, into zero-fill.
        template = bytearray(self.changed_word(*mutations[0]))
        struct.pack_into('<I', template, self.pe.offset(TLS_RVA + 4, 4), mutations[1][1])
        for data in (bytes(template), self.changed_word(*mutations[2])):
            with self.assertRaisesRegex(prepare.PEError, 'file-backed'):
                prepare.validate_tls(prepare.PE(data))
        data = bytearray(self.original)
        struct.pack_into('<II', data, OPTIONAL + 96 + 9 * 8, 0x22D0, 24)
        with self.assertRaisesRegex(prepare.PEError, 'file-backed'):
            prepare.validate_tls(prepare.PE(bytes(data)))

    def test_guard_check_and_dispatch_slots_require_readable_non_executable_raw_data(self):
        for field in (72, 76):
            for rva, reason in ((0x1000, 'non-executable data'), (0x22F0, 'file-backed'),
                                (0x3051, 'DWORD-aligned'), (0x4000, 'SizeOfImage')):
                with self.subTest(field=field, rva=hex(rva)), self.assertRaisesRegex(prepare.PEError, reason):
                    prepare.validate_load_config(prepare.PE(self.changed_word(CONFIG_RVA + field, BASE + rva)))
        data = bytearray(self.original)
        struct.pack_into('<I', data, SECTIONS + 2 * 40 + 36, 0x40)
        with self.assertRaisesRegex(prepare.PEError, 'readable'):
            prepare.validate_load_config(prepare.PE(bytes(data)))

    def test_guard_and_seh_tables_still_require_raw_bytes(self):
        for field in (64, 80):
            with self.subTest(field=field), self.assertRaisesRegex(prepare.PEError, 'file-backed'):
                prepare.validate_load_config(prepare.PE(self.changed_word(CONFIG_RVA + field, BASE + 0x22F0)))

    def test_malformed_tls_and_cfg_are_still_refused(self):
        cases = ((TLS_RVA + 20, 1, 'static TLS characteristics'),
                 (CONFIG_RVA + 80, 0, 'CFG function table is malformed'),
                 (0x3080, 0x2000, 'CFG function is outside executable'),
                 (CONFIG_RVA + 88, 0xD0000100, 'unsupported CFG function-table stride'))
        for rva, value, reason in cases:
            with self.subTest(rva=hex(rva)), self.assertRaisesRegex(prepare.PEError, reason):
                prepare.prepare(self.changed_word(rva, value))
        data = self.changed_word(CONFIG_RVA + 88, 0)
        with self.assertRaisesRegex(prepare.PEError, 'CFG flag requires'):
            prepare.prepare(data)


if __name__ == '__main__':
    unittest.main()
