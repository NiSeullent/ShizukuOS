#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for immutable PE32 Load Config and bounded cookie initialization.

Compiles only the portable parser into a fresh output directory. No target app,
VM, network, installation, services or client configuration are invoked.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = 0x400000
DEFAULT_COOKIE = 0xBB40E64E


class Section(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ('va', 'span', 'raw', 'bytes', 'flags')]


class Image(C.Structure):
    _fields_ = [('file', C.c_void_p)] + [(n, C.c_uint32) for n in
        ('bytes', 'base', 'size', 'headers', 'entry', 'section_align')] + [
        (n, C.c_uint16) for n in
        ('sections', 'characteristics', 'subsystem', 'subsystem_major', 'subsystem_minor')] + [
        ('directory', (C.c_uint32 * 2) * 16), ('section', Section * 96)]


class Table(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ('rva', 'count', 'stride')]


class ParseLimits(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ('file_bytes', 'image_bytes', 'total_bytes')]


class Limits(C.Structure):
    _fields_ = [('image', ParseLimits)] + [(n, C.c_uint32) for n in
                                          ('table_entries', 'total_table_entries')]


def limits(table=262144, total=6 * 262144, file=32 * 1024**2,
           image=64 * 1024**2, combined=96 * 1024**2):
    return Limits(ParseLimits(file, image, combined), table, total)


class Info(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in
        ('present', 'directory_rva', 'directory_bytes', 'declared_size', 'timestamp')] + [
        ('major_version', C.c_uint16), ('minor_version', C.c_uint16)] + [
        (n, C.c_uint32) for n in
        ('global_flags_clear', 'global_flags_set', 'critical_section_timeout',
         'decommit_free', 'decommit_total', 'maximum_allocation',
         'virtual_memory_threshold', 'process_heap_flags', 'affinity_mask')] + [
        ('csd_version', C.c_uint16), ('dependent_load_flags', C.c_uint16)] + [
        (n, C.c_uint32) for n in
        ('lock_prefix_rva', 'lock_prefix_count', 'cookie_rva', 'cookie_raw_backed',
         'cookie_initial', 'cf_check_rva', 'cf_dispatch_rva', 'guard_flags',
         'rf_failure_rva', 'rf_failure_slot_rva', 'rf_verify_slot_rva',
         'xfg_check_rva', 'xfg_dispatch_rva', 'xfg_table_rva',
         'castguard_rva', 'memcpy_rva')] + [
        (n, Table) for n in ('seh', 'cfg', 'address_taken_iat', 'long_jump', 'eh_continuation')] + [
        ('protection_needed', C.c_uint32), ('prerequisites', C.c_uint32)]


class CookieResult(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in
        ('present', 'rva', 'previous', 'value', 'initialized', 'needs_crt_reinit',
         'remaining_prerequisites')]


def put(data, at, value):
    struct.pack_into('<I', data, at, value)


def fixture(size=192):
    """Three real PE sections, including a writable virtual zero-fill tail."""
    b = bytearray(0xE00)
    b[:2] = b'MZ'
    put(b, 60, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', b, 0x84, 0x14C, 3, 0, 0, 0, 224, 0x102)
    o = 0x98
    struct.pack_into('<H', b, o, 0x10B)
    for offset, value in ((16, 0x1000), (28, BASE), (32, 0x1000), (36, 0x200),
                          (56, 0x4000), (60, 0x200), (92, 16)):
        put(b, o + offset, value)
    struct.pack_into('<HH', b, o + 48, 10, 0)
    struct.pack_into('<H', b, o + 68, 2)
    table = o + 224
    for n, (name, vs, va, rs, rp, flags) in enumerate((
        (b'.text', 0x200, 0x1000, 0x200, 0x200, 0x60000020),
        (b'.rdata', 0x800, 0x2000, 0x800, 0x400, 0x40000040),
        (b'.data', 0x1000, 0x3000, 0x200, 0xC00, 0xC0000040))):
        at = table + 40 * n
        b[at:at + len(name)] = name
        struct.pack_into('<IIII', b, at + 8, vs, va, rs, rp)
        put(b, at + 36, flags)
    struct.pack_into('<II', b, o + 96 + 10 * 8, 0x2000, size)
    put(b, 0x400, size)
    put(b, 0x400 + 60, BASE + 0x3000)
    put(b, 0xC00, DEFAULT_COOKIE)
    return b


def cfg_fixture():
    b = fixture()
    for offset, value in ((64, BASE + 0x2200), (68, 2),
                          (72, BASE + 0x2100), (76, BASE + 0x2104),
                          (80, BASE + 0x2210), (84, 2), (88, 0x500)):
        put(b, 0x400 + offset, value)
    for offset, value in ((0x500, BASE + 0x1000), (0x504, BASE + 0x1004),
                          (0x600, 0x1008), (0x604, 0x1010),
                          (0x610, 0x1000), (0x614, 0x1004)):
        put(b, offset, value)
    return b


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Tests(unittest.TestCase):
    lib = None
    official = []
    large_official = []

    def parse(self, data, accepted=True):
        self.assertIsNotNone(self.lib)
        source = bytes(data)
        buf = C.create_string_buffer(source)
        image = Image()
        error = C.c_char_p()
        self.assertTrue(self.lib.np_parse(C.byref(image), buf, len(data), C.byref(error)),
                        error.value)
        self.assertEqual(bytes(buf)[:len(source)], source)
        info = Info()
        C.memset(C.byref(info), 0xA5, C.sizeof(info))
        valid = bool(self.lib.np_load_config(C.byref(image), C.byref(info), C.byref(error)))
        self.assertEqual(bytes(buf)[:len(source)], source)
        self.assertEqual(valid, accepted, error.value)
        if not valid:
            self.assertTrue(error.value)
            self.assertEqual(bytes(info), bytes(C.sizeof(info)))
        return buf, image, info

    def profile(self, buf, image):
        before = bytes(buf)
        error = C.c_char_p()
        valid = bool(self.lib.np_load_config_execution_profile(C.byref(image), C.byref(error)))
        self.assertEqual(bytes(buf), before)
        return valid, error.value

    def test_absent_and_size_versioned_directory(self):
        for size in (64, 72, 92, 192, 256):
            with self.subTest(size=size):
                _, _, i = self.parse(fixture(size))
                self.assertEqual((i.present, i.declared_size, i.cookie_rva), (1, size, 0x3000))
        b = fixture()
        struct.pack_into('<II', b, 0x98 + 96 + 10 * 8, 0, 0)
        buf, image, i = self.parse(b)
        self.assertEqual(i.present, 0)
        valid, error = self.profile(buf, image)
        self.assertTrue(valid, error)

    def test_directory_version_and_future_fields(self):
        for size in (0, 63, 193, 257, 0xFFFFFFFF):
            with self.subTest(size=size):
                b = fixture()
                put(b, 0x400, size)
                self.parse(b, False)
        b = fixture(256)
        put(b, 0x400 + 252, 1)
        self.parse(b, False)

    def test_versioned_fields_are_bounded_by_declared_size(self):
        for size in (4, 8, 12, 60, 64, 68, 72, 76, 80, 84, 88, 92,
                     104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
                     144, 148, 152, 156, 160, 164, 168, 172, 176, 180,
                     184, 188, 192, 196, 256):
            with self.subTest(size=size):
                b = fixture(256)
                put(b, 0x400, size)
                b[0x400 + size:0x500] = bytes(256 - size)
                _, _, info = self.parse(b)
                self.assertEqual(info.declared_size, size)
                self.assertEqual(info.cookie_rva, 0x3000 if size >= 64 else 0)
                self.assertEqual(info.cfg.count, 0)
        # CodeIntegrity is a complete twelve-byte field at offset 92; sizes
        # 96/100 cannot describe a complete version of that aggregate.
        for size in (63, 65, 67, 69, 71, 73, 75, 89, 91, 93, 96, 100, 191, 193, 255):
            with self.subTest(partial=size):
                b = fixture(256)
                put(b, 0x400, size)
                b[0x400 + size:0x500] = bytes(256 - size)
                self.parse(b, False)
        # A table VA present at size 68 cannot borrow a count from bytes beyond
        # that declared version; nonzero extension bytes are also refused.
        b = fixture(256)
        put(b, 0x400, 68)
        put(b, 0x400 + 64, BASE + 0x2200)
        self.parse(b, False)
        put(b, 0x400 + 68, 1)
        self.parse(b, False)

    def test_zero_fill_cookie_is_runtime_memory(self):
        b = fixture()
        put(b, 0x400 + 60, BASE + 0x3200)
        _, _, i = self.parse(b)
        self.assertEqual((i.cookie_rva, i.cookie_raw_backed, i.cookie_initial), (0x3200, 0, 0))
        for va in (BASE - 4, BASE + 0x1000, BASE + 0x2000, BASE + 0x3001,
                   BASE + 0x3FFF, BASE + 0x4000, 0xFFFFFFFC):
            with self.subTest(va=va):
                b = fixture()
                put(b, 0x400 + 60, va)
                self.parse(b, False)

    def test_readonly_cfg_slots_report_protection(self):
        original = cfg_fixture()
        buf, image, i = self.parse(original)
        self.assertEqual((i.cf_check_rva, i.cf_dispatch_rva), (0x2100, 0x2104))
        self.assertEqual(i.protection_needed & 3, 3)
        self.assertEqual((i.seh.count, i.cfg.count, i.cfg.stride), (2, 2, 4))
        self.assertEqual(i.prerequisites & 3, 3)
        valid, error = self.profile(buf, image)
        self.assertFalse(valid)
        self.assertTrue(error)
        self.assertEqual(original, cfg_fixture())

    def test_writable_cfg_slots_need_no_temporary_protection(self):
        b = cfg_fixture()
        put(b, 0x400 + 72, BASE + 0x3010)
        put(b, 0x400 + 76, BASE + 0x3014)
        put(b, 0xC10, BASE + 0x1000)
        put(b, 0xC14, BASE + 0x1004)
        _, _, info = self.parse(b)
        self.assertEqual(info.protection_needed & 3, 0)
        self.assertEqual(info.prerequisites & 2, 2)

    def test_unaligned_packed_tables_and_cfg_metadata_strides(self):
        for stride in (4, 5, 19):
            with self.subTest(stride=stride):
                b = cfg_fixture()
                put(b, 0x400 + 64, BASE + 0x2201)
                struct.pack_into('<II', b, 0x601, 0x1008, 0x1010)
                put(b, 0x400 + 80, BASE + 0x2211)
                put(b, 0x400 + 88, 0x500 | ((stride - 4) << 28))
                b[0x611:0x611 + 2 * stride] = bytes(2 * stride)
                put(b, 0x611, 0x1000)
                put(b, 0x611 + stride, 0x1004)
                if stride > 4:
                    b[0x615] = 1
                    b[0x615 + stride] = 2
                _, _, info = self.parse(b)
                self.assertEqual((info.seh.rva, info.cfg.rva), (0x2201, 0x2211))
                self.assertEqual((info.cfg.count, info.cfg.stride), (2, stride))
                if stride > 4:
                    b[0x615] = 4
                    self.parse(b, False)
                if stride == 19:
                    b[0x615] = 1
                    b[0x616] = 1
                    self.parse(b, False)
        b = cfg_fixture()
        put(b, 0x400 + 80, BASE + 0x27F8)
        put(b, 0x400 + 88, 0x10000500)
        self.parse(b, False)

    def test_mitigation_tables_require_ordered_executable_targets(self):
        for at, value in ((0x600, 0x2000), (0x604, 0x1008), (0x604, 0x1004),
                          (0x610, 0x3000), (0x614, 0x1000), (0x614, 0x0FFF),
                          (0x400 + 68, 262145), (0x400 + 84, 0xFFFFFFFF),
                          (0x400 + 64, BASE + 0x3200),
                          (0x400 + 80, BASE + 0x27FC),
                          (0x400 + 72, BASE + 0x1000),
                          (0x400 + 76, BASE + 0x4000)):
            with self.subTest(at=at, value=value):
                b = cfg_fixture()
                put(b, at, value)
                self.parse(b, False)

    def test_declared_flags_are_not_silently_ignored(self):
        b = cfg_fixture()
        put(b, 0x400 + 88, 0x8000000)
        self.parse(b, False)
        for flags, prerequisite in ((0x2000000, 0x8000), (0x800000, 0x10)):
            with self.subTest(flags=flags):
                b = fixture()
                put(b, 0x400 + 60, 0)
                put(b, 0x400 + 88, flags)
                buf, image, info = self.parse(b)
                self.assertEqual(info.guard_flags, flags)
                self.assertEqual(info.prerequisites & prerequisite, prerequisite)
                valid, error = self.profile(buf, image)
                self.assertFalse(valid)
                self.assertTrue(error)

    def mapping(self, buf, image):
        # Extra canaries also detect writes just outside the declared mapping.
        mapped = C.create_string_buffer(image.size + 8)
        C.memmove(C.addressof(mapped) + image.size, b'\xDD' * 8, 8)
        C.memmove(mapped, buf, image.headers)
        for s in image.section[:image.sections]:
            if s.bytes:
                C.memmove(C.addressof(mapped) + s.va, C.addressof(buf) + s.raw, s.bytes)
        return mapped

    def cookie(self, data, initial, entropy, available=None):
        buf, image, info = self.parse(data)
        mapped = self.mapping(buf, image)
        put_value = struct.pack('<I', initial)
        C.memmove(C.addressof(mapped) + info.cookie_rva, put_value, 4)
        before = bytes(mapped)
        result = CookieResult()
        error = C.c_char_p()
        valid = bool(self.lib.np_load_config_cookie(C.byref(image), mapped,
                     image.size if available is None else available, entropy,
                     C.byref(result), C.byref(error)))
        self.assertEqual(bytes(buf)[:len(data)], bytes(data))
        after = bytes(mapped)
        if not valid:
            self.assertEqual(bytes(result), bytes(C.sizeof(result)))
            self.assertEqual(after, before)
        rva = info.cookie_rva
        self.assertEqual(after[:rva], before[:rva])
        self.assertEqual(after[rva + 4:], before[rva + 4:])
        return valid, result, struct.unpack_from('<I', after, rva)[0], error.value

    def test_cookie_entropy_normalization_and_existing_state(self):
        for initial in (0, DEFAULT_COOKIE):
            for entropy in (0, 1, 0xFFFF, DEFAULT_COOKIE, 0x11223344, 0xFFFFFFFF):
                with self.subTest(initial=initial, entropy=entropy):
                    valid, r, value, error = self.cookie(fixture(), initial, entropy)
                    self.assertTrue(valid, error)
                    self.assertEqual((r.previous, r.value, r.initialized), (initial, value, 1))
                    self.assertNotEqual(value, DEFAULT_COOKIE)
                    self.assertNotEqual(value >> 16, 0)
                    normalized = entropy
                    if normalized == DEFAULT_COOKIE:
                        normalized += 1
                    elif normalized >> 16 == 0:
                        normalized |= ((normalized | 0x4711) << 16) & 0xFFFFFFFF
                    self.assertEqual(value, normalized)
                    self.assertEqual(r.remaining_prerequisites & 0x20000, 0)
        for initial in (0x11223344, 0xFFFFFFFF, 0xFFFF, 1):
            with self.subTest(initial=initial):
                valid, r, value, error = self.cookie(fixture(), initial, 0x12345678)
                self.assertTrue(valid, error)
                self.assertEqual((value, r.initialized), (initial, 0))
                self.assertEqual(r.needs_crt_reinit, int(initial >> 16 == 0))

    def test_short_mapping_and_cfg_gate_survive_cookie_preparation(self):
        valid, _, value, error = self.cookie(fixture(), DEFAULT_COOKIE, 0x11223344, 0x3002)
        self.assertFalse(valid)
        self.assertTrue(error)
        self.assertEqual(value, DEFAULT_COOKIE)
        valid, result, _, error = self.cookie(cfg_fixture(), DEFAULT_COOKIE, 0x11223344)
        self.assertTrue(valid, error)
        self.assertEqual(result.remaining_prerequisites & 3, 3)

    def test_parser_output_cannot_alias_immutable_input(self):
        for offset in (0, 0x400, 0xE00 - 4):
            with self.subTest(offset=offset):
                buf, image, _ = self.parse(fixture())
                before = bytes(buf)
                output = C.cast(C.addressof(buf) + offset, C.POINTER(Info))
                error = C.c_char_p()
                self.assertFalse(self.lib.np_load_config(C.byref(image), output, C.byref(error)))
                self.assertEqual(error.value, b'LC_OUTPUT_ALIASES_INPUT')
                self.assertEqual(bytes(buf), before)

    def test_cookie_mapping_cannot_alias_original_file(self):
        for offset in (0, 4, 0xE00 - 4):
            with self.subTest(offset=offset):
                buf, image, _ = self.parse(fixture())
                before = bytes(buf)
                result = CookieResult()
                C.memset(C.byref(result), 0xA5, C.sizeof(result))
                error = C.c_char_p()
                self.assertFalse(self.lib.np_load_config_cookie(C.byref(image),
                    C.addressof(buf) + offset, image.size, 0x11223344,
                    C.byref(result), C.byref(error)))
                self.assertEqual(error.value, b'LC_COOKIE_MAPPING_ALIASES_FILE')
                self.assertEqual(bytes(result), bytes(C.sizeof(result)))
                self.assertEqual(bytes(buf), before)

    def test_cookie_output_cannot_alias_source_or_mapping(self):
        buf, image, _ = self.parse(fixture())
        mapped = self.mapping(buf, image)
        for owner, offset, expected in ((buf, 0x400, b'LC_COOKIE_OUTPUT_ALIASES_INPUT'),
                                       (mapped, 0x1000, b'LC_COOKIE_OUTPUT_ALIASES_MAPPING'),
                                       (mapped, image.size - 4, b'LC_COOKIE_OUTPUT_ALIASES_MAPPING')):
            with self.subTest(error=expected, offset=offset):
                source_before, map_before = bytes(buf), bytes(mapped)
                output = C.cast(C.addressof(owner) + offset, C.POINTER(CookieResult))
                error = C.c_char_p()
                self.assertFalse(self.lib.np_load_config_cookie(C.byref(image), mapped,
                    image.size, 0x11223344, output, C.byref(error)))
                self.assertEqual(error.value, expected)
                self.assertEqual(bytes(buf), source_before)
                self.assertEqual(bytes(mapped), map_before)

    def test_pinned_real_chromium_metadata_is_immutable(self):
        folder = ROOT / 'build/latest-app-preflight-20260930/chromium-157.0.8080.0-1707946'
        pinned = {
            'chrome.exe': ('7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823', 131, 1847),
            'chrome_elf.dll': ('54ffa9edd24ed9251fefca50abd27d4542fe81b63757d0ed0df2304a36ad1473', 127, 944),
        }
        if not folder.exists():
            self.skipTest('exact locally retained Chromium corpus unavailable')
        for name, (digest, seh, cfg) in pinned.items():
            with self.subTest(name=name):
                path = folder / name
                data = path.read_bytes()
                self.assertEqual(sha(data), digest)
                buf, image, i = self.parse(data)
                self.assertEqual((i.declared_size, i.seh.count, i.cfg.count), (192, seh, cfg))
                self.assertEqual(i.guard_flags, 0x10500)
                self.assertTrue(i.protection_needed & 1)
                valid, error = self.profile(buf, image)
                self.assertFalse(valid, error)
                self.assertEqual(sha(path.read_bytes()), digest)
                self.official.append({'file': str(path), 'sha256': digest,
                    'seh': seh, 'cfg': cfg, 'prerequisites': i.prerequisites,
                    'executed': False})

    def test_explicit_table_and_aggregate_budgets(self):
        buf, image, _ = self.parse(cfg_fixture())
        for per_table, total, expected in ((2, 4, None), (1, 4, b'LC_TABLE_LIMIT'),
                                          (2, 3, b'LC_TOTAL_TABLE_LIMIT')):
            with self.subTest(per_table=per_table, total=total):
                budget, info, error = limits(per_table, total), Info(), C.c_char_p()
                C.memset(C.byref(info), 0xA5, C.sizeof(info))
                before = bytes(buf)
                accepted = bool(self.lib.np_load_config_limited(C.byref(image),
                    C.byref(info), C.byref(budget), C.byref(error)))
                self.assertEqual(accepted, expected is None, error.value)
                self.assertEqual(bytes(buf), before)
                if expected:
                    self.assertEqual(error.value, expected)
                    self.assertEqual(bytes(info), bytes(C.sizeof(info)))
                else:
                    self.assertEqual((info.seh.count, info.cfg.count), (2, 2))
        # The terminating lock-prefix entry is read only to detect its zero;
        # two actual lock records participate in the same aggregate budget.
        b = cfg_fixture()
        put(b, 0x400 + 32, BASE + 0x2240)
        put(b, 0x640, BASE + 0x1000)
        put(b, 0x644, BASE + 0x1001)
        b[0x200:0x202] = b'\xf0\xf0'
        buf, image, _ = self.parse(b)
        for total, accepted in ((6, True), (5, False)):
            budget, info, error = limits(2, total), Info(), C.c_char_p()
            self.assertEqual(bool(self.lib.np_load_config_limited(C.byref(image),
                C.byref(info), C.byref(budget), C.byref(error))), accepted)
            if accepted:
                self.assertEqual(info.lock_prefix_count, 2)
            else:
                self.assertEqual(error.value, b'LC_TOTAL_TABLE_LIMIT')

    def test_invalid_and_undersized_limits(self):
        buf, image, _ = self.parse(fixture())
        cases = []
        for field, values in (('table_entries', (0, 8388609, 0xFFFFFFFF)),
                              ('total_table_entries', (0, 8388609, 0xFFFFFFFF)),
                              ('file_bytes', (0, 512 * 1024**2 + 1)),
                              ('image_bytes', (0, 512 * 1024**2 + 1)),
                              ('total_bytes', (0, 1024 * 1024**2 + 1))):
            for value in values:
                budget = limits()
                setattr(budget if 'entries' in field else budget.image, field, value)
                cases.append((budget, b'LC_LIMITS_INVALID'))
        cases += [(None, b'LC_LIMITS_INVALID'),
                  (limits(file=len(fixture()) - 1), b'LC_IMAGE_INVALID'),
                  (limits(image=image.size - 1), b'LC_IMAGE_INVALID'),
                  (limits(combined=image.bytes + image.size - 1), b'LC_IMAGE_INVALID')]
        for budget, expected in cases:
            with self.subTest(budget=None if budget is None else bytes(budget)):
                info, error = Info(), C.c_char_p()
                C.memset(C.byref(info), 0xA5, C.sizeof(info))
                before = bytes(buf)
                self.assertFalse(self.lib.np_load_config_limited(C.byref(image),
                    C.byref(info), None if budget is None else C.byref(budget), C.byref(error)))
                self.assertEqual(error.value, expected)
                self.assertEqual(bytes(info), bytes(C.sizeof(info)))
                self.assertEqual(bytes(buf), before)

    def test_budget_output_and_mapping_aliases_preserve_limits(self):
        buf, image, _ = self.parse(fixture())
        storage = C.create_string_buffer(C.sizeof(Info) + 64)
        budget = C.cast(storage, C.POINTER(Limits))
        C.memmove(storage, C.byref(limits()), C.sizeof(Limits))
        before = bytes(storage)
        error = C.c_char_p()
        self.assertFalse(self.lib.np_load_config_limited(C.byref(image),
            C.cast(storage, C.POINTER(Info)), budget, C.byref(error)))
        self.assertEqual(error.value, b'LC_OUTPUT_ALIASES_LIMITS')
        self.assertEqual(bytes(storage), before)
        info = Info()
        self.assertFalse(self.lib.np_load_config_limited(C.byref(image),
            C.byref(info), budget, C.cast(storage, C.POINTER(C.c_char_p))))
        self.assertEqual(bytes(storage), before)
        mapped = self.mapping(buf, image)
        self.assertFalse(self.lib.np_load_config_cookie_limited(C.byref(image),
            mapped, image.size, 0x11223344,
            C.cast(storage, C.POINTER(CookieResult)), budget, C.byref(error)))
        self.assertEqual(error.value, b'LC_COOKIE_OUTPUT_ALIASES_LIMITS')
        self.assertEqual(bytes(storage), before)
        # Supply valid limits in an otherwise inert mapped data region.
        C.memmove(C.addressof(mapped) + 0x1100, C.byref(limits()), C.sizeof(Limits))
        mapped_budget = C.cast(C.addressof(mapped) + 0x1100, C.POINTER(Limits))
        mapped_before = bytes(mapped)
        result = CookieResult()
        self.assertFalse(self.lib.np_load_config_cookie_limited(C.byref(image),
            mapped, image.size, 0x11223344, C.byref(result), mapped_budget, C.byref(error)))
        self.assertEqual(error.value, b'LC_COOKIE_MAPPING_ALIASES_LIMITS')
        self.assertEqual(bytes(mapped), mapped_before)

    def test_explicit_limits_cookie_and_runtime_gate(self):
        buf, image, _ = self.parse(cfg_fixture())
        mapped = self.mapping(buf, image)
        before = bytes(mapped)
        budget, result, error = limits(2, 3), CookieResult(), C.c_char_p()
        self.assertFalse(self.lib.np_load_config_cookie_limited(C.byref(image),
            mapped, image.size, 0x11223344, C.byref(result), C.byref(budget), C.byref(error)))
        self.assertEqual(error.value, b'LC_TOTAL_TABLE_LIMIT')
        self.assertEqual(bytes(mapped), before)
        budget = limits(2, 4)
        self.assertTrue(self.lib.np_load_config_cookie_limited(C.byref(image),
            mapped, image.size, 0x11223344, C.byref(result), C.byref(budget), C.byref(error)))
        self.assertEqual(result.value, 0x11223344)
        self.assertEqual(result.remaining_prerequisites & 3, 3)
        self.assertFalse(self.lib.np_load_config_execution_profile_limited(C.byref(image),
            C.byref(budget), C.byref(error)))
        self.assertEqual(error.value, b'LC_SAFESEH_RUNTIME_REQUIRED')

    def test_pinned_large_chromium_requires_explicit_budget(self):
        path = ROOT / 'build/chromium-large-image-20260930T2336/chrome.dll'
        if not path.exists():
            self.skipTest('exact locally retained large Chromium core unavailable')
        digest = 'f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158'
        data = path.read_bytes()
        self.assertEqual(sha(data), digest)
        self.assertEqual(len(data), 283207168)
        buf, image, info, error = C.create_string_buffer(data), Image(), Info(), C.c_char_p()
        budget = limits(267868, 268177, 512 * 1024**2, 512 * 1024**2, 1024 * 1024**2)
        self.assertFalse(self.lib.np_parse(C.byref(image), buf, len(data), C.byref(error)))
        self.assertTrue(self.lib.np_parse_limited(C.byref(image), buf, len(data),
            C.byref(budget.image), C.byref(error)), error.value)
        self.assertEqual(image.size, 284966912)
        self.assertFalse(self.lib.np_load_config(C.byref(image), C.byref(info), C.byref(error)))
        self.assertEqual(error.value, b'LC_IMAGE_INVALID')
        for per_table, total, expected in ((267867, 268177, b'LC_TABLE_LIMIT'),
                                          (267868, 268176, b'LC_TOTAL_TABLE_LIMIT'),
                                          (267868, 268177, None)):
            budget.table_entries, budget.total_table_entries = per_table, total
            self.assertEqual(bool(self.lib.np_load_config_limited(C.byref(image),
                C.byref(info), C.byref(budget), C.byref(error))), expected is None, error.value)
            if expected:
                self.assertEqual(error.value, expected)
                self.assertEqual(bytes(info), bytes(C.sizeof(info)))
        self.assertEqual((info.declared_size, info.seh.count, info.cfg.count,
                          info.address_taken_iat.count, info.long_jump.count),
                         (192, 202, 267868, 15, 92))
        self.assertFalse(self.lib.np_load_config_execution_profile_limited(C.byref(image),
            C.byref(budget), C.byref(error)))
        self.assertEqual(error.value, b'LC_SAFESEH_RUNTIME_REQUIRED')
        self.assertEqual(sha(C.string_at(buf, len(data))), digest)
        self.assertEqual(sha(path.read_bytes()), digest)
        self.large_official.append({'file': str(path), 'sha256': digest,
            'bytes': len(data), 'image_bytes': image.size, 'cfg': info.cfg.count,
            'all_table_entries': 268177, 'limits': {'table_entries': 267868,
                'total_table_entries': 268177}, 'prerequisites': info.prerequisites,
            'default_rejected': True, 'executed': False})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    out = args.out.resolve()
    if out.exists():
        ap.error('use a fresh output directory')
    out.mkdir(parents=True)
    sources = (HERE / 'load_config.c', HERE / 'load_config.h', HERE / 'test.py',
               HERE.parent / 'native_loader/pe.c', HERE.parent / 'native_loader/pe.h')
    source_before = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sources}
    command = ['gcc', '-std=c11', '-shared', '-fPIC', '-O1', '-g', '-Wall', '-Wextra',
               '-Werror', '-Wno-misleading-indentation', '-fsanitize=undefined',
               '-fsanitize-undefined-trap-on-error', '-o', str(out / 'load_config.so'),
               str(HERE / 'load_config.c'), str(HERE.parent / 'native_loader/pe.c')]
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=120)
    (out / 'build.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    lib = C.CDLL(str(out / 'load_config.so'))
    lib.np_parse.argtypes = [C.POINTER(Image), C.c_void_p, C.c_uint32, C.POINTER(C.c_char_p)]
    lib.np_parse_limited.argtypes = [C.POINTER(Image), C.c_void_p, C.c_uint32,
                                   C.POINTER(ParseLimits), C.POINTER(C.c_char_p)]
    lib.np_load_config.argtypes = [C.POINTER(Image), C.POINTER(Info), C.POINTER(C.c_char_p)]
    lib.np_load_config_cookie.argtypes = [C.POINTER(Image), C.c_void_p, C.c_uint32,
                                        C.c_uint32, C.POINTER(CookieResult), C.POINTER(C.c_char_p)]
    lib.np_load_config_execution_profile.argtypes = [C.POINTER(Image), C.POINTER(C.c_char_p)]
    lib.np_load_config_limited.argtypes = [C.POINTER(Image), C.POINTER(Info),
                                         C.POINTER(Limits), C.POINTER(C.c_char_p)]
    lib.np_load_config_cookie_limited.argtypes = [C.POINTER(Image), C.c_void_p,
        C.c_uint32, C.c_uint32, C.POINTER(CookieResult), C.POINTER(Limits), C.POINTER(C.c_char_p)]
    lib.np_load_config_execution_profile_limited.argtypes = [C.POINTER(Image),
        C.POINTER(Limits), C.POINTER(C.c_char_p)]
    for name in ('np_parse', 'np_load_config', 'np_load_config_cookie',
                 'np_load_config_execution_profile', 'np_parse_limited',
                 'np_load_config_limited', 'np_load_config_cookie_limited',
                 'np_load_config_execution_profile_limited'):
        getattr(lib, name).restype = C.c_int
    Tests.lib = lib
    with (out / 'tests.log').open('w') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    source_after = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sources}
    source_stable = source_before == source_after
    passed = result.wasSuccessful() and source_stable
    receipt = {'status': 'PASS' if passed else 'FAIL',
        'host_only': True, 'native_executed': False, 'tests': result.testsRun,
        'failures': len(result.failures), 'errors': len(result.errors),
        'skipped': len(result.skipped), 'command': command,
        'sources': source_before, 'sources_unchanged_during_validation': source_stable,
        'sources_after': source_after,
        'official_input_status': ('PASS' if len(Tests.official) == 2 else
                                 'SKIPPED_NO_LOCAL_CORPUS' if result.skipped else 'INCOMPLETE'),
        'official_inputs': Tests.official,
        'large_official_inputs': Tests.large_official,
        'parser_sha256': sha((out / 'load_config.so').read_bytes())}
    (out / 'host-result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'tests': result.testsRun,
                      'receipt': str(out / 'host-result.json')}))
    if not passed:
        print((out / 'tests.log').read_text())
        if not source_stable:
            print('FAIL: module sources changed during compilation or validation')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
