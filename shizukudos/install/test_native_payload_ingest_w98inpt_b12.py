#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""W98INPT.BIN is a private native member: public installer payload admission refuses it.

Host-only; calls the real require_public_payload/private_member with synthetic archives."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

SOURCE = Path(__file__).resolve().with_name('native_payload_ingest.py')
spec = importlib.util.spec_from_file_location('ingest_w98inpt_b12', SOURCE)
ingest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingest)

MANIFEST = {'schema': 'shizukudos-install-manifest/1', 'boot_profile': 'desktop'}


def archive(items):
    offset = 16 + len(items) * 136
    entries, body = bytearray(), bytearray()
    for name, data in items:
        entries.extend(name.encode('ascii').ljust(120, b'\0') + struct.pack('<QQ', offset, len(data)))
        body.extend(data); offset += len(data)
    return b'SHZARC01' + struct.pack('<II', len(items), 0) + entries + body


def admit(extra):
    items = [('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', json.dumps(MANIFEST).encode())] + extra
    return ingest.require_public_payload(MANIFEST, {}, archive(items))


class W98InptRefused(unittest.TestCase):
    def test_variants_refused(self):
        for name in ('SHZDOS/W98INPT.BIN', 'shzdos/w98inpt.bin', 'ShzDos/W98Inpt.Bin', '\\SHZDOS\\W98INPT.BIN',
                     'W98INPT.BIN', 'SHZDOS/W98INPT.BIN.', 'SHZDOS/W98INPT.BIN ', 'SHZDOS\\w98inpt.bin'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                admit([(name, b'x' * 96)])

    def test_existing_private_names_still_refused_in_all_forms(self):
        for name in ('shzdos/vgacfg.bin', 'SHZDOS\\W98PERS.BIN.', 'x/VGAROM.BIN', 'a/win98/b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                admit([(name, b'x')])

    def test_unrelated_names_pass(self):
        for name in ('SHZDOS/W98INPT.TXT', 'SHZDOS/W98INPUT.BIN', 'SHZDOS/XW98INPT.BIN', 'SHZDOS/W98INPT.BIN.D/readme'):
            with self.subTest(name=name):
                admit([(name, b'public')])

    def test_predicate(self):
        self.assertTrue(ingest.private_member('a\\b\\w98inpt.bin'))
        self.assertFalse(ingest.private_member('a/W98INPT.BIN2'))


if __name__ == '__main__':
    unittest.main()
