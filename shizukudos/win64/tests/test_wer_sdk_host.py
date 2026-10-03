# SPDX-License-Identifier: GPL-2.0-only
"""Compile the real WER fixture and exclusion ABI; no Windows/registry execution."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
WIN64 = HERE.parent
CC = shutil.which('x86_64-w64-mingw32-gcc')
FLAGS = ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
         '-mno-red-zone', '-Wno-unused-function', '-Wno-unused-parameter']


class WerSDKTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(CC, 'actual x64 MinGW compiler is required')
        self.temp = tempfile.TemporaryDirectory(prefix='shz-wer-sdk-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def compile(self, path, *extra):
        return subprocess.run([CC, *FLAGS, *extra, '-I', str(WIN64 / 'include'),
                               '-I', str(WIN64 / 'crt'), '-fsyntax-only', str(path)],
                              capture_output=True, text=True, timeout=60)

    def source(self, text):
        path = self.root / 'abi.c'
        path.write_text('#define WIN32_LEAN_AND_MEAN\n#include "wer_exclusions.h"\n' + text)
        return path

    def test_exact_wide_string_boolean_hresult_and_win64_abi(self):
        source = self.source('''
typedef HRESULT (WINAPI *exclusion_api)(PCWSTR, BOOL);
_Static_assert(sizeof(HRESULT) == 4 && sizeof(BOOL) == 4, "32-bit result/boolean");
_Static_assert(sizeof(WCHAR) == 2 && sizeof(void *) == 8, "UTF-16 and x64");
_Static_assert(__builtin_types_compatible_p(__typeof__(&WerAddExcludedApplication), exclusion_api), "add ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&WerRemoveExcludedApplication), exclusion_api), "remove ABI");
''')
        for version in ('0x0501', '0x0600', '0x0a00'):
            with self.subTest(version=version):
                result = self.compile(source, '-D_WIN32_WINNT=' + version)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_exclusion_fixture_needs_no_report_sdk_header(self):
        # An actual unwanted include is rejected by the compiler, including
        # transitive includes; this is not a source-string assertion.
        (self.root / 'werapi.h').write_text('#error unrelated WER report SDK header included\n')
        result = self.compile(HERE / 't_wer_exclusions.c', '-I', str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_argument_result_width_or_calling_convention_is_refused(self):
        bad = ['HRESULT WINAPI WerAddExcludedApplication(PCSTR, BOOL);\n',
               'void WINAPI WerRemoveExcludedApplication(PCWSTR, BOOL);\n',
               'HRESULT WINAPI WerRemoveExcludedApplication(PCWSTR, ULONGLONG);\n',
               'HRESULT __attribute__((sysv_abi)) WerAddExcludedApplication(PCWSTR, BOOL);\n']
        for declaration in bad:
            with self.subTest(declaration=declaration):
                result = self.compile(self.source(declaration))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('conflicting types', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
