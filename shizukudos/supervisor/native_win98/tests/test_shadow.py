#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Whole-ROM, absent-LAPIC/debugcon and actual EPT boundary controls.

The modeled VMX/EPT callbacks do not execute a VM or validate Windows98.
"""
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent

class WholeRomShadowTests(unittest.TestCase):
    def compile_run(self, fixture, extras=()):
        for compiler in ('gcc', 'clang'):
            with self.subTest(compiler=compiler), tempfile.TemporaryDirectory() as out:
                target = pathlib.Path(out) / 'constructor'
                command = [compiler, '-std=c11', '-D_GNU_SOURCE', '-O1', '-g',
                           '-Wall', '-Wextra', '-Werror', '-fno-pie', '-no-pie',
                           '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections']
                if compiler == 'clang':
                    command += ['-fsanitize=address,undefined']
                built = subprocess.run([*command, str(HERE/fixture),
                                        *map(str, extras), '-o', str(target)],
                                       capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stderr)
                result = subprocess.run([str(target)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith('PASS '), result.stdout)
                self.assertEqual(result.stderr, '')

    def test_real_constructor_gcc_and_clang_sanitizers(self):
        self.compile_run('constructor_host.c', (HERE.parent/'ata_pio.c',))

    def test_real_ept_gcc_and_clang_sanitizers(self):
        self.compile_run('absent_ept_host.c')

if __name__ == '__main__':
    unittest.main()
