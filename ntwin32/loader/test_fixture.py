# SPDX-License-Identifier: GPL-2.0-only
"""Preparer acceptance of a Chromium-shaped TLS/load-config/delay fixture."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import fixture
import evidence

spec = importlib.util.spec_from_file_location('ntw_prepare', ROOT / 'ntwin32/prepare.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
OUT = ROOT / 'build/evidence/chromium-156'


class ChromiumFixture(unittest.TestCase):
    def test_preserves_tls_load_config_and_delay_without_downgrade(self):
        original = fixture.build_chromium_shaped_pe()
        pe = mod.PE(original)
        prepared, report = mod.prepare(original)
        new = mod.PE(prepared)
        self.assertEqual(report['tls']['bytes'], 24)
        self.assertEqual(report['tls']['callbacks'], 1)
        self.assertEqual(report['tls']['zero_fill'], 4)
        self.assertTrue(report['tls']['preserved'])
        self.assertEqual(report['load_config']['bytes'], 192)
        self.assertTrue(report['load_config']['cfg_instrumented'])
        self.assertEqual(report['load_config']['cfg_functions'], 1)
        self.assertEqual(report['delay_imports'], [{'dll': 'KERNEL32.dll', 'symbols': 1, 'preserved': True}])
        self.assertEqual(report['subsystem_version'], [10, 0])
        self.assertFalse(report['subsystem_version_downgraded'])
        self.assertFalse(report['stock_win98_loader_accepts_subsystem'])
        self.assertFalse(report['nx_enforced'])
        self.assertFalse(report['aslr_implemented'])
        self.assertFalse(report['browser_functionality_verified'])
        self.assertFalse(report['guest_verified'])
        self.assertIn('GetProcAddress', report['redirected'])
        for index in (9, 10, 13):
            rva, size = pe.directory(index)
            old = pe.offset(rva, size)
            new_off = new.offset(rva, size)
            self.assertEqual(prepared[new_off:new_off + size], original[old:old + size])
        self.assertEqual((new.u16(new.opt + 48), new.u16(new.opt + 50)), (10, 0))
        self.assertEqual(new.u16(new.opt + 70), 0xC140)
        # A one-field directory still fails. Acceptance is not "any TLS bit".
        broken = bytearray(original)
        struct.pack_into('<I', broken, pe.opt + 96 + 9 * 8 + 4, 8)
        with self.assertRaisesRegex(mod.PEError, 'static TLS'):
            mod.prepare(bytes(broken))
        tls_at = pe.offset(pe.directory(9)[0], 24)
        evidence.byte_rows(OUT / '01-tls-directory.png',
                           'Synthetic TLS directory (24 bytes, preserved)',
                           [('IMAGE_TLS_DIRECTORY32', original[tls_at:tls_at + 24]),
                            ('template + index', original[pe.offset(0x2070, 8):pe.offset(0x2070, 8) + 8])])
        evidence.panel(OUT / '02-preparer-fixture.png',
                       'Preparer result for Chromium-shaped fixture (not chrome.exe)',
                       [f"schema {report['schema']}",
                        f"TLS bytes {report['tls']['bytes']} callbacks {report['tls']['callbacks']} zero-fill {report['tls']['zero_fill']}",
                        f"load config {report['load_config']['bytes']} CFG functions {report['load_config']['cfg_functions']} fail-closed",
                        f"delay imports {report['delay_imports'][0]['dll']} symbols {report['delay_imports'][0]['symbols']}",
                        'subsystem 10.0 retained; stock Win98 loader still rejects it',
                        'DLL characteristics 0xc140 retained; NX not enforced; ASLR not implemented',
                        'browser_functionality_verified false'])


if __name__ == '__main__':
    unittest.main()
