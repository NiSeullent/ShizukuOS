#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""DOS 8.3 alias / NTFS stream refusal for private native members (host-only, real predicate and admission)."""
import unittest
from shizukudos.install import test_native_payload_ingest_w98inpt_b12 as b12

ingest, admit = b12.ingest, b12.admit
REFUSED = ('W98INP~1.BIN', 'shzdos/w98inp~1.bin', 'SHZDOS\\W98INP~2.BIN', 'SHZDOS/W98INP~10.BIN.', 'W98I~1.BIN',
           'VGACFG~1.BIN', 'VGARO~1.BIN', 'W98PER~1.BIN ', 'WIN98C~1.BIN', 'WINDOW~1', 'a/WINDOW~1/x', 'WIN98~1',
           'SHZDOS/W98INPT.BIN:stream', 'SHZDOS/W98INPT.BIN::$DATA', 'SHZDOS/vgacfg.bin:x:y', 'W98INPT.BIN.', 'W98INPT.BIN. .')
PASSED = ('W98INPT.TXT', 'W98INPUT.BIN', 'W98INPX.BIN', 'README~1.TXT', 'KERNEL~1.BIN', 'W98INP~1.TXT', 'W98INPT~1.BIN2',
          'W98INP~A.BIN', 'W98INPT.BIN2', 'W98INPT.BIN.d/readme', 'XW98INP~1.BIN')


class Aliases(unittest.TestCase):
    def test_predicate(self):
        for n in REFUSED:
            with self.subTest(n=n): self.assertTrue(ingest.private_member(n))
        for n in PASSED:
            with self.subTest(n=n): self.assertFalse(ingest.private_member(n))

    def test_archive_member_site(self):
        for n in REFUSED:
            with self.subTest(n=n), self.assertRaises(ValueError): admit([('SHZDOS/' + n if '/' not in n and '\\' not in n else n, b'x' * 96)])
        for n in PASSED:
            with self.subTest(n=n): admit([('SHZDOS/' + n, b'public')])


if __name__ == '__main__':
    unittest.main()
