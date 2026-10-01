#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pending doorbells survive WAIT until ACK; execute actual domain.c on the host."""
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class DoorbellHostTests(unittest.TestCase):
    def test_actual_wait_dispatch_and_delivery_gcc_and_clang_sanitizers(self):
        for compiler in ("gcc", "clang"):
            with self.subTest(compiler=compiler), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary) / "doorbell"
                command = [compiler, "-std=c11", "-D_GNU_SOURCE", "-O1", "-g",
                           "-Wall", "-Wextra", "-Werror", "-fno-pie", "-no-pie",
                           "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"]
                if compiler == "clang":
                    command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
                built = subprocess.run([*command, str(HERE / "doorbell_host.c"), "-o", str(target)],
                                       capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                result = subprocess.run([str(target)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(result.stdout.startswith("PASS "), result.stdout)
                self.assertEqual(result.stderr, "")
                print(f"{compiler}: {result.stdout.strip()}")


if __name__ == "__main__":
    unittest.main()
