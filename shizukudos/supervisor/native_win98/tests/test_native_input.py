# SPDX-License-Identifier: GPL-2.0-only
"""Host control: actual devices.c + native_input.c (owned outer i8042 -> inner KBC). No VM/QMP."""
import pathlib, subprocess, tempfile, unittest

HERE = pathlib.Path(__file__).resolve().parent


class NativeInputHost(unittest.TestCase):
    def test_outer_i8042_to_inner_kbc_gcc_and_clang_sanitizers(self):
        for compiler in ("gcc", "clang"):
            with tempfile.TemporaryDirectory() as tmp:
                target = pathlib.Path(tmp) / "native_input_host"
                flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
                if compiler == "clang":
                    flags += ["-fsanitize=address,undefined"]
                built = subprocess.run([compiler, *flags, str(HERE / "native_input_host.c"), "-o", str(target)],
                                       capture_output=True, text=True, timeout=60)
                self.assertEqual(built.returncode, 0, built.stderr)
                ran = subprocess.run([str(target)], capture_output=True, text=True, timeout=60)
                self.assertEqual(ran.returncode, 0, ran.stderr)
                self.assertIn("PASS", ran.stdout)


if __name__ == "__main__":
    unittest.main()
