#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute production NTW64 handle lifecycle; Win32 device callbacks are modeled."""
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = ROOT / "build/fd5c-handles"


class HandleLifetimeTests(unittest.TestCase):
    def test_actual_client_lifetime_gcc_and_clang_sanitizers(self):
        OUT.mkdir(parents=True, exist_ok=True)
        for compiler in ("gcc", "clang"):
            with self.subTest(compiler=compiler):
                target = OUT / f"handles-{compiler}"
                flags = ["-std=c11", "-D_WIN32=1", "-O1", "-g", "-Wall", "-Wextra",
                         "-Werror", "-pedantic", "-I", str(HERE / "mock")]
                if compiler == "clang":
                    flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
                built = subprocess.run([compiler, *flags, str(HERE / "handle_lifetime_host.c"),
                                        "-o", str(target)], capture_output=True, text=True, timeout=60)
                (OUT / f"{compiler}-compile.log").write_text(built.stdout + built.stderr)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                for scenario in ("exhaustion", "failure-paths", "deferred-close"):
                    with self.subTest(scenario=scenario):
                        result = subprocess.run([str(target), scenario], capture_output=True,
                                                text=True, timeout=120)
                        (OUT / f"{compiler}-{scenario}.log").write_text(result.stdout + result.stderr)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertTrue(result.stdout.startswith(f"PASS {scenario}:"), result.stdout)
                        self.assertEqual(result.stderr, "")
                        print(f"{compiler}: {result.stdout.strip()}")


if __name__ == "__main__":
    unittest.main()
