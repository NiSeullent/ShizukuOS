#!/usr/bin/env python3
"""Finite modeled PCI-role controls; no process, QMP, FD or device authority.

Use the unchanged original configs() fixture. The default path is portable to
native_win98/tests; --native-root selects an isolated baseline or candidate.
"""
import argparse
from collections import UserDict
from enum import IntEnum
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--native-root', type=Path, default=Path(__file__).resolve().parents[1])
options, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location('role_key_original_fixtures', options.native_root / 'tests' / 'test_native_epoch_host.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
host = fixtures.host

class Role(IntEnum):
    VGA = 1
    STORAGE = 2

class StrictRoles(unittest.TestCase):
    def setUp(self):
        self.vga, self.rom, self.storage, self.bars = fixtures.configs()

    def expect(self, bars):
        return host.Expectations(self.vga, self.rom, self.storage, bars)

    def test_role_alias_bool_refused(self):
        with self.assertRaisesRegex(ValueError, 'exact selected roles required'):
            self.expect({True: self.bars[1], 2: self.bars[2]})

    def test_role_alias_float_refused(self):
        with self.assertRaisesRegex(ValueError, 'exact selected roles required'):
            self.expect({1.0: self.bars[1], 2: self.bars[2]})

    def test_role_alias_intenum_refused(self):
        with self.assertRaisesRegex(ValueError, 'exact selected roles required'):
            self.expect({Role.VGA: self.bars[1], 2: self.bars[2]})

    def policy(self, roles, label):
        vga = self.vga if 1 in roles else None
        rom = self.rom if 1 in roles else None
        storage = self.storage if 2 in roles else None
        bars = {role: self.bars[role] for role in roles}
        expected = host.Expectations(vga, rom, storage, bars)
        nonce = bytes(range(32)); deadline = 123456789000
        actual = expected.policy(nonce, deadline)
        # Independent fixed wire vector, including every reserved byte.
        wire = bytearray(256)
        struct.pack_into('<IHHI', wire, 0, 0x50454457, 1, 256, sum(roles))
        wire[16:48] = nonce
        if 1 in roles:
            wire[48:80] = hashlib.sha256(self.vga).digest()
            wire[112:144] = hashlib.sha256(self.rom).digest()
            struct.pack_into('<H6x6I', wire, 160, 16, *self.bars[1])
        if 2 in roles:
            wire[80:112] = hashlib.sha256(self.storage).digest()
            struct.pack_into('<H', wire, 162, 24)
            struct.pack_into('<6I', wire, 192, *self.bars[2])
        struct.pack_into('<QI H', wire, 144, deadline, 10000, 0x2f8)
        self.assertEqual(actual, bytes(wire))
        self.assertEqual(len(actual), 256)
        print('POLICY256 %s %s' % (label, actual.hex()), flush=True)

    def test_exact_int_vga_policy256(self):
        self.policy((1,), 'VGA')

    def test_exact_int_storage_policy256(self):
        self.policy((2,), 'STORAGE')

    def test_exact_int_both_policy256(self):
        self.policy((1, 2), 'BOTH')

    def test_missing_roles_refused(self):
        for bars in ({}, {1: self.bars[1]}, {2: self.bars[2]}):
            with self.subTest(keys=tuple(bars)), self.assertRaisesRegex(ValueError, 'exact selected roles required'):
                self.expect(bars)

    def test_extra_integer_roles_refused(self):
        for role in (-1, 0, 3):
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'exact selected roles required'):
                self.expect({**self.bars, role: self.bars[1]})

    def test_mapping_subclass_refused(self):
        class DictChild(dict):
            pass
        for bars in (UserDict(self.bars), DictChild(self.bars), tuple(self.bars.items()), None):
            with self.subTest(kind=type(bars).__name__), self.assertRaisesRegex(ValueError, 'exact selected roles required'):
                self.expect(bars)

    def test_malformed_bar_tuple_refused(self):
        for bars in (list(self.bars[1]), self.bars[1][:-1], self.bars[1] + (0,)):
            with self.subTest(kind=type(bars).__name__, size=len(bars)), self.assertRaisesRegex(ValueError, 'six immutable BAR DWORDs required'):
                self.expect({**self.bars, 1: bars})

    def test_malformed_dword_types_refused(self):
        class Zero(IntEnum):
            VALUE = 0
        for raw in (False, 0.0, Zero.VALUE, '0', None):
            words = list(self.bars[1]); words[1] = raw
            with self.subTest(kind=type(raw).__name__), self.assertRaisesRegex(ValueError, 'bounded exact integer required'):
                self.expect({**self.bars, 1: tuple(words)})

    def test_malformed_dword_range_refused(self):
        for raw in (-1, 1 << 32):
            words = list(self.bars[1]); words[1] = raw
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'bounded exact integer required'):
                self.expect({**self.bars, 1: tuple(words)})

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]] + remaining, verbosity=2)
