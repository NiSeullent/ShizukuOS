#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the actual Supervisor text renderer, without starting a VM."""
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
CP437 = REPO / "shizukudos/csmwrap/video/cp437.c"


class LegacyVideoHostTests(unittest.TestCase):
    def compile_run(self, compiler, sanitize):
        build = REPO / "build/pma-fd5c-video"
        build.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="host-", dir=build) as output:
            target = pathlib.Path(output) / "video-host"
            flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                     "-fno-pie", "-no-pie", "-fno-omit-frame-pointer"]
            if sanitize:
                flags += ["-fsanitize=address,undefined"]
            command = [compiler, *flags, "-I", str(CP437.parent.parent),
                       str(HERE / "video_host.c"), str(CP437), "-o", str(target)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            # This host ships GCC linker scripts without their shared runtimes.
            # Preserve a visible environment skip, never a sanitized PASS.
            if (compiler == "gcc" and sanitize and built.returncode != 0
                    and "cannot find /usr/lib64/libasan.so." in built.stderr
                    and "cannot find /usr/lib64/libubsan.so." in built.stderr):
                self.skipTest("GCC ASan/UBSan shared runtimes unavailable: " + built.stderr.strip())
            self.assertEqual(built.returncode, 0, built.stderr)
            for group in range(10):
                with self.subTest(group=group):
                    result = subprocess.run([str(target), str(group)], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(result.stdout.startswith("PASS "), result.stdout)
                    self.assertEqual(result.stderr, "")
                    print(f"{compiler} {'ASan/UBSan' if sanitize else 'native'} group {group}: {result.stdout}", end="")

    def test_gcc_native(self):
        self.compile_run("gcc", False)

    def test_gcc_sanitized(self):
        self.compile_run("gcc", True)

    def test_clang_native(self):
        self.compile_run("clang", False)

    def test_clang_sanitized(self):
        self.compile_run("clang", True)


if __name__ == "__main__":
    unittest.main()
