#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent

class ObserverTests(unittest.TestCase):
    def test_actual_observer_body_strict_gcc_and_clang_sanitizers(self):
        for compiler in ('gcc', 'clang'):
            with self.subTest(compiler=compiler), tempfile.TemporaryDirectory() as out:
                target = pathlib.Path(out) / 'observer'
                command = [compiler, '-std=c11', '-D_GNU_SOURCE', '-O1', '-g',
                           '-Wall', '-Wextra', '-Werror', '-fno-pie', '-no-pie',
                           '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections']
                if compiler == 'clang':
                    command += ['-fsanitize=address,undefined']
                subprocess.run([*command, str(HERE/'observer_host.c'), '-o', str(target)],
                               check=True, capture_output=True, text=True, timeout=60)
                result = subprocess.run([str(target)], check=True, capture_output=True,
                                        text=True, timeout=60)
                self.assertTrue(result.stdout.startswith('PASS '), result.stdout)
                self.assertEqual(result.stderr, '')

if __name__ == '__main__':
    unittest.main()
