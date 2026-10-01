#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for process output collection; these do not boot a guest."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import qemu


class BoundedProcessTests(unittest.TestCase):
    def test_output_larger_than_pipe_completes(self):
        rc, output, timed_out = qemu.run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 262144)"], 5)
        self.assertEqual(rc, 0)
        self.assertEqual(output, "x" * 262144)
        self.assertFalse(timed_out)

    def test_timeout_retains_partial_stdout_and_stderr(self):
        rc, output, timed_out = qemu.run_bounded([sys.executable, "-c",
            "import sys,time; print('before timeout',flush=True); "
            "print('diagnostic',file=sys.stderr,flush=True); time.sleep(30)"], 0.5)
        self.assertNotEqual(rc, 0)
        self.assertTrue(timed_out)
        self.assertIn("before timeout", output)
        self.assertIn("diagnostic", output)

    def test_nonzero_exit_is_retained(self):
        rc, output, timed_out = qemu.run_bounded(
            [sys.executable, "-c", "print('launch failed'); raise SystemExit(7)"], 5)
        self.assertEqual(rc, 7)
        self.assertEqual(output.strip(), "launch failed")
        self.assertFalse(timed_out)

    def test_launch_error_propagates(self):
        with self.assertRaises(OSError):
            qemu.run_bounded(["/shizuku-test-tool-that-does-not-exist"], 1)

    def test_invalid_output_bytes_do_not_hide_result(self):
        rc, output, timed_out = qemu.run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes([255]))"], 5)
        self.assertEqual(rc, 0)
        self.assertEqual(output, "\ufffd")
        self.assertFalse(timed_out)


if __name__ == "__main__":
    unittest.main()
