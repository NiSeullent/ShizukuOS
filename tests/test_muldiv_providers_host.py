#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute both actual MulDiv providers against independent endpoint arithmetic."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def body(path, name):
    source = path.read_text()
    match = re.search(r"\b" + name + r"\s*\([^;{}]*\)\s*\{", source)
    if not match:
        raise ValueError("actual provider function missing")
    start, end, depth = match.start(), match.end(), 1
    while depth:
        if end == len(source):
            raise ValueError("unterminated actual provider")
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


class Providers(unittest.TestCase):
    def test_actual_canonical_and_browser_providers_signed_endpoints(self):
        header = ROOT / "shizukudos/win64/kernel32/k32_muldiv.h"
        canonical = body(ROOT / "shizukudos/win64/kernel32/k32_steam_compat.c", "MulDiv")
        browser = body(ROOT / "shizukudos/win64/trident/comrt/kernel32.c", "MulDiv")
        source = '#include <stdint.h>\n#include <limits.h>\n#include <stdio.h>\n'
        source += '#include "' + str(header) + '"\n'
        source += "static int " + canonical.replace("MulDiv(", "canonical(", 1) + "\n"
        source += "static int " + browser.replace("MulDiv(", "browser(", 1).replace("INT ", "int ") + "\n"
        source += r'''
static int oracle(int a, int b, int c)
{
    int64_t p = (int64_t)a * b, d = c, q, r;
    if (!d) return -1;
    q = p / d; r = p % d;
    if (r < 0) r = -r;
    if (d < 0) d = -d;
    if (r * 2 >= d) q += ((p < 0) != (c < 0)) ? -1 : 1;
    return q < INT_MIN || q > INT_MAX ? -1 : (int)q;
}
static int check(int a, int b, int c)
{
    int expected = oracle(a, b, c), x = canonical(a,b,c), y = browser(a,b,c);
    if (x == expected && y == expected) return 0;
    fprintf(stderr, "%d * %d / %d: canonical=%d browser=%d expected=%d\n",a,b,c,x,y,expected);
    return 1;
}
int main(void)
{
    const int ends[] = {INT_MIN, INT_MIN+1, -65536, -7, -3, -2, -1, 0, 1, 2, 3, 7, 65536, INT_MAX-1, INT_MAX};
    unsigned count = 0, failures = 0, state = 0x9e3779b9;
    for (unsigned a=0;a<sizeof ends/sizeof *ends;a++)
        for (unsigned b=0;b<sizeof ends/sizeof *ends;b++)
            for (unsigned c=0;c<sizeof ends/sizeof *ends;c++) {
                failures += check(ends[a], ends[b], ends[c]); count++;
            }
    for (unsigned n=0;n<10000;n++) {
        int values[3];
        for (unsigned i=0;i<3;i++) {
            state = state*1664525u+1013904223u;
            values[i] = (int)(state & INT_MAX);
            if (state & 0x80000000u) values[i] = -values[i];
        }
        failures += check(values[0],values[1],values[2]); count++;
    }
    printf("actual MulDiv providers: %u cases, %u failures\n",count,failures);
    return failures ? 1 : 0;
}
'''
        for compiler, extra in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            with self.subTest(compiler=compiler), tempfile.TemporaryDirectory() as directory:
                self.assertIsNotNone(shutil.which(compiler))
                path = Path(directory); (path / "provider.c").write_text(source)
                run = subprocess.run([compiler, "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", *extra,
                                      str(path / "provider.c"), "-o", str(path / "provider")], capture_output=True, text=True, timeout=60)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
                run = subprocess.run([str(path / "provider")], capture_output=True, text=True, timeout=30, env=env)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn("13375 cases, 0 failures", run.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
