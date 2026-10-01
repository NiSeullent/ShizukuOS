#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native MTRR honesty in the production CPUID handler; host controls only."""
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent

class NativeCpuidTests(unittest.TestCase):
    def test_actual_handler_gcc_and_clang_sanitizers(self):
        for compiler in ('gcc', 'clang'):
            with self.subTest(compiler=compiler), tempfile.TemporaryDirectory() as out:
                target = pathlib.Path(out) / 'cpuid'
                command = [compiler, '-std=c11', '-D_GNU_SOURCE', '-O1', '-g',
                           '-Wall', '-Wextra', '-Werror', '-fno-pie', '-no-pie',
                           '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections']
                if compiler == 'clang':
                    command += ['-fsanitize=address,undefined']
                built = subprocess.run([*command, str(HERE/'cpuid_host.c'), '-o', str(target)],
                                       capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stderr)
                result = subprocess.run([str(target)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith('PASS '), result.stdout)
                self.assertEqual(result.stderr, '')

if __name__ == '__main__':
    unittest.main()
