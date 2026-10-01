#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""HOST ONLY: Chromium runner decisions and persistence with simulated logs/processes.

These tests never boot QEMU, run Chromium, or supply guest compatibility evidence.
All build inputs, Chromium trees, images, and outputs are in temporary directories.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_k64_chromium as runner

START = r"K64 autorun: starting D:\chrome-win\chrome.exe (cwd D:\chrome-win, timeout 1200 s)"
RESULT = "K64 autorun: result exited exit=0 faulted=0 reaped=1 after 42 ms"
MARKER = runner.M2_EXPECT
OUTPUT = f"[win64 chrome.exe pid 2] {MARKER}"
SUCCESS = "\n".join((START, OUTPUT, RESULT))


class HostEvidenceTests(unittest.TestCase):
    def evaluate(self, serial=SUCCESS, expected=MARKER, rc=1, timed_out=False):
        return runner.evaluate(serial, expected, rc, timed_out)

    def test_success_requires_clean_autorun_and_accepts_both_qemu_exit_conventions(self):
        for rc in (0, 1):
            with self.subTest(rc=rc):
                res = self.evaluate(rc=rc)
                self.assertEqual(res["status"], "PASS")
                self.assertEqual(res["ended_by"], "exited")
                self.assertEqual(res["exit_code"], 0)
                self.assertIs(res["faulted"], False)
                self.assertTrue(res["expected_line_seen"])
                self.assertEqual(res["qemu_returncode"], rc)
                self.assertEqual(res["failure_reasons"], [])

    def test_actual_autorun_optional_suffix_formats_remain_accepted(self):
        for result in ("K64 autorun: result exited exit=0 faulted=0",
                       "K64 autorun: result exited exit=0 faulted=0 reaped=-1 after 42 ms",
                       "K64 autorun: result exited exit=0 faulted=0 reaped=0 (1 thread(s) still alive) after 42 ms"):
            with self.subTest(result=result):
                self.assertEqual(self.evaluate("\n".join((START, OUTPUT, result)))["status"], "PASS")

    def test_marker_before_autorun_cannot_pass(self):
        res = self.evaluate("\n".join((OUTPUT, START, RESULT)))
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["expected_line_seen"])

    def test_pre_autorun_self_test_failures_do_not_contaminate_clean_run(self):
        preamble = "\n".join(("FATAL: pre-autorun self-test", "K64 EXCEPTION self-test",
                              "K64 ldr: SELFTEST.DLL not loaded: missing import", "K32 unsupported: self-test",
                              "K64 autorun: timeout after 1 s", "K64 autorun: result timeout exit=102 faulted=1"))
        res = self.evaluate(preamble + "\n" + SUCCESS)
        self.assertEqual(res["status"], "PASS")
        for key in ("loader_failures", "exceptions", "chromium_fatal", "unsupported_calls"):
            self.assertEqual(res[key], [])
        self.assertFalse(res["guest_timed_out"])

    def test_missing_start_excludes_marker_and_all_completion_evidence(self):
        res = self.evaluate("\n".join((OUTPUT, RESULT, "FATAL: no start")))
        self.assertEqual(res["status"], "FAIL")
        self.assertFalse(res["expected_line_seen"])
        self.assertIsNone(res["autorun_result"])
        self.assertIsNone(res["faulted"])
        self.assertEqual(res["chromium_fatal"], [])

    def test_empty_and_whitespace_markers_cannot_pass(self):
        for expected in ("", " ", "\n", "\t"):
            with self.subTest(expected=repr(expected)):
                res = self.evaluate(expected=expected)
                self.assertEqual(res["status"], "FAIL")
                self.assertFalse(res["expected_line_seen"])
                self.assertIn("expected marker is empty", res["failure_reasons"])

    def test_marker_with_any_chromium_fatal_is_failure(self):
        for fatal in ("FATAL: unexpected", "Check failed: handle", "CHECK failed: thread", "NOTREACHED hit"):
            with self.subTest(fatal=fatal):
                res = self.evaluate(SUCCESS + "\n" + fatal)
                self.assertEqual(res["status"], "FAIL")
                self.assertTrue(res["expected_line_seen"])
                self.assertEqual(res["chromium_fatal"], [fatal])
                self.assertTrue(res["furthest"].startswith("chromium fatal:"))

    def test_marker_with_loader_failure_is_failure(self):
        for failure in ("not loaded: chrome.exe needs DLL!fn", "imports unresolved", "rejected image",
                        "failed relocation", "cannot resolve import", "lacks export"):
            line = "K64 ldr: chrome.dll " + failure
            with self.subTest(failure=failure):
                res = self.evaluate(SUCCESS + "\n" + line)
                self.assertEqual(res["status"], "FAIL")
                self.assertEqual(res["loader_failures"], [line])
                self.assertTrue(res["furthest"].startswith("loader:"))

    def test_optional_loadlibrary_misses_and_unsupported_calls_are_nonfatal(self):
        line = "K64 ldr: OPTIONAL.DLL not loaded: LoadLibrary needs OPTIONAL.DLL!probe"
        res = self.evaluate(SUCCESS + "\n" + line + "\n" + line + "\nK32 unsupported: optional probe")
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["runtime_loadlibrary_misses"], [line])
        self.assertEqual(res["loader_failures"], [])
        self.assertEqual(res["unsupported_calls"], ["K32 unsupported: optional probe"])

    def test_optional_miss_does_not_hide_required_loader_failure(self):
        optional = "K64 ldr: OPT.DLL not loaded: LoadLibrary needs OPT.DLL!probe"
        required = "K64 ldr: chrome.dll not loaded: chrome.exe needs REQUIRED.DLL!fn"
        res = self.evaluate(SUCCESS + "\n" + optional + "\n" + required)
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["runtime_loadlibrary_misses"], [optional])
        self.assertEqual(res["loader_failures"], [required])

    def test_marker_with_exception_is_failure(self):
        for line in ("K64: process 2 killed", "K64 EXCEPTION page fault", "unhandled exception in chrome.exe"):
            with self.subTest(line=line):
                res = self.evaluate(SUCCESS + "\n" + line)
                self.assertEqual(res["status"], "FAIL")
                self.assertEqual(res["exceptions"], [line])

    def test_malformed_or_missing_autorun_result_cannot_pass(self):
        for result in ("", "K64 autorun: result start-failed status=c0000001",
                       "K64 autorun: result exited exit=0", "K64 autorun: result exited exit=0 faulted=",
                       "K64 autorun: result exited exit=0 faulted=10",
                       "K64 autorun: result exited exit=0 faulted=0junk",
                       "K64 autorun: result exited exit=0 faulted=00",
                       "K64 autorun: result exited exit=0 faulted=0 garbage",
                       "K64 autorun: result exited exit=garbage faulted=0",
                       "prefix K64 autorun: result exited exit=0 faulted=0"):
            with self.subTest(result=result):
                res = self.evaluate("\n".join((START, OUTPUT, result)))
                self.assertEqual(res["status"], "FAIL")
                self.assertIsNone(res["faulted"])
                self.assertIsNone(res["exit_code"])

    def test_fault_nonzero_exit_and_non_exit_endings_cannot_pass(self):
        for result in ("K64 autorun: result exited exit=0 faulted=1",
                       "K64 autorun: result exited exit=C0000005 faulted=0",
                       "K64 autorun: result killed exit=0 faulted=0",
                       "K64 autorun: result timeout exit=0 faulted=0"):
            with self.subTest(result=result):
                res = self.evaluate("\n".join((START, OUTPUT, result)))
                self.assertEqual(res["status"], "FAIL")

    def test_latest_result_must_be_valid_and_successful(self):
        for result in ("K64 autorun: result exited exit=1 faulted=0", "K64 autorun: result malformed"):
            with self.subTest(result=result):
                self.assertEqual(self.evaluate(SUCCESS + "\n" + result)["status"], "FAIL")

    def test_explicit_guest_timeout_diagnostic_cannot_pass_with_exited_result(self):
        res = self.evaluate("\n".join((START, OUTPUT, "K64 autorun: timeout after 1200 s", RESULT)))
        self.assertEqual(res["status"], "FAIL")
        self.assertTrue(res["guest_timed_out"])

    def test_marker_with_host_timeout_or_bad_host_exit_cannot_pass(self):
        for rc, timed_out in ((0, True), (1, True), (-9, False), (2, False), (3, False), (7, False), (None, False)):
            with self.subTest(rc=rc, timed_out=timed_out):
                res = self.evaluate(rc=rc, timed_out=timed_out)
                self.assertEqual(res["status"], "FAIL")
                self.assertTrue(res["expected_line_seen"])


class HostPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="host-only-k64-chromium-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.k64s = self.root / "build" / "kernel64s"
        self.win64 = self.root / "build" / "win64"
        self.tree = self.root / "chromium" / "chrome-win"
        self.image = self.root / "images" / "chromium.img"
        self.out = self.root / "output" / "nested"
        self.inputs = (self.k64s / "boot.elf", self.k64s / "KERNEL64S.BIN", self.win64 / "WIN64.IMG",
                       self.tree / "chrome.exe")
        self.argv = ["run_k64_chromium.py", "--qemu", "host-only-qemu", "--accel", "tcg", "--timeout", "9",
                     "--chromium", str(self.tree), "--chromium-image", str(self.image), "--out", str(self.out)]
        self.patch(runner, "K64S", self.k64s)
        self.patch(runner, "WIN64", self.win64)
        self.which = self.patch(runner.shutil, "which", side_effect=lambda name: f"/host-only/bin/{name}")
        self.build_image = self.patch(runner.disk, "build_chromium_image", return_value=[("chrome.exe", 1)])
        self.put_file = self.patch(runner, "put_file")
        self.bounded = self.patch(runner.qemu, "run_bounded", autospec=True)
        self.patch(runner.shzlib, "git_state", return_value={"revision": "host-only-simulated"})

    def patch(self, obj, name, *args, **kwargs):
        patcher = mock.patch.object(obj, name, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def ready_inputs(self):
        for path in self.inputs:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"host-only-placeholder")

    def run_main(self, extra=()):
        with mock.patch.object(sys, "argv", self.argv + list(extra)), contextlib.redirect_stdout(io.StringIO()) as output:
            rc = runner.main()
        record = json.loads((self.out / "result.json").read_text())
        return rc, record, output.getvalue()

    def simulate_qemu(self, serial=SUCCESS, rc=1, timed_out=False, output="host-only QEMU output"):
        def collect(command, timeout):
            serial_arg = command[command.index("-serial") + 1]
            Path(serial_arg.removeprefix("file:")).write_text(serial)
            return rc, output, timed_out
        self.bounded.side_effect = collect

    def test_all_missing_inputs_tools_and_qemu_persist_blocked_before_preparation(self):
        self.which.side_effect = None
        self.which.return_value = None
        rc, record, output = self.run_main()
        self.assertEqual(rc, 2)
        self.assertEqual(record["status"], "BLOCKED")
        self.assertEqual(len(record["missing_prerequisites"]), 8)
        for path in self.inputs:
            self.assertIn(str(path), record["blocked_reason"])
        for tool in ("mkfs.vfat", "mcopy", "mmd", "host-only-qemu"):
            self.assertIn(tool, record["blocked_reason"])
        self.assertIn(str(self.out / "result.json"), output)
        self.build_image.assert_not_called()
        self.put_file.assert_not_called()
        self.bounded.assert_not_called()
        old_fields = {"profile", "accel", "status", "expected_line", "expected_line_seen", "qemu_timed_out",
                      "seconds", "image_prepare_s", "image", "tree_files", "command", "chrome_args",
                      "runtime_loadlibrary_misses", "loader_failures", "exceptions", "chromium_fatal",
                      "unsupported_calls", "autorun_result", "exit_code", "faulted", "ended_by", "furthest",
                      "chrome_output_lines", "chrome_output_line_count", "serial_tail", "qemu_output", "utc", "git"}
        self.assertTrue(old_fields.issubset(record))
        self.assertIsNone(record["faulted"])
        self.assertIsNone(record["qemu_returncode"])

    def test_blocked_preflight_overwrites_old_pass_without_reusing_serial(self):
        self.out.mkdir(parents=True)
        (self.out / "result.json").write_text(json.dumps({"status": "PASS", "expected_line_seen": True}))
        (self.out / "serial.log").write_text(SUCCESS)
        rc, record, _ = self.run_main()
        self.assertEqual(rc, 2)
        self.assertEqual(record["status"], "BLOCKED")
        self.assertFalse(record["expected_line_seen"])
        self.assertIsNone(record["autorun_result"])
        self.assertEqual(record["serial_tail"], "")
        self.bounded.assert_not_called()

    def test_metadata_oserror_persists_blocked_and_retains_missing_input_list(self):
        with mock.patch.object(runner.shzlib, "git_state", side_effect=OSError("host-only git unavailable")):
            rc, record, _ = self.run_main()
        self.assertEqual(rc, 2)
        self.assertEqual(record["status"], "BLOCKED")
        self.assertIn("OSError: host-only git unavailable", record["blocked_reason"])
        self.assertEqual(len(record["missing_prerequisites"]), 4)
        self.assertEqual(record["git"], {})
        self.bounded.assert_not_called()

    def test_each_missing_prerequisite_blocks_independently(self):
        for target in ("boot.elf", "KERNEL64S.BIN", "WIN64.IMG", "chrome.exe", "mkfs.vfat", "mcopy", "mmd", "host-only-qemu"):
            with self.subTest(target=target):
                self.ready_inputs()
                self.which.side_effect = lambda name: None if name == target else f"/host-only/bin/{name}"
                for path in self.inputs:
                    if path.name == target:
                        path.unlink()
                rc, record, _ = self.run_main()
                self.assertEqual(rc, 2)
                self.assertEqual(record["status"], "BLOCKED")
                self.assertEqual(len(record["missing_prerequisites"]), 1)
                self.assertIn(target, record["missing_prerequisites"][0])
        self.bounded.assert_not_called()
        self.build_image.assert_not_called()

    def test_relative_out_is_resolved_before_missing_input_preflight(self):
        self.out = self.root / "relative-output"
        rc, record, output = self.run_main(["--out", os.path.relpath(self.out, Path.cwd())])
        self.assertEqual(rc, 2)
        self.assertEqual(record["status"], "BLOCKED")
        serial = record["command"][record["command"].index("-serial") + 1]
        self.assertEqual(serial, f"file:{self.out / 'serial.log'}")
        self.assertIn(str(self.out / "result.json"), output)

    def test_empty_expect_is_blocked_without_launch(self):
        self.ready_inputs()
        rc, record, _ = self.run_main(["--expect", ""])
        self.assertEqual(rc, 2)
        self.assertEqual(record["status"], "BLOCKED")
        self.assertIn("expected marker is empty", record["blocked_reason"])
        self.bounded.assert_not_called()

    def test_invalid_host_timeouts_persist_blocked_without_preparation_or_launch(self):
        self.ready_inputs()
        for value in ("-1", "-1800", "0", "not-a-number", "1.5", "nan", "inf", ""):
            with self.subTest(value=value):
                rc, record, _ = self.run_main(["--timeout", value])
                self.assertEqual(rc, 2)
                self.assertEqual(record["status"], "BLOCKED")
                self.assertIn("invalid host timeout", record["blocked_reason"])
                self.assertFalse(record["expected_line_seen"])
        self.build_image.assert_not_called()
        self.bounded.assert_not_called()

    def test_overlong_command_is_blocked_by_encoded_byte_length(self):
        self.ready_inputs()
        # Both values occupy exactly 512 UTF-8 bytes including the 'chrome.exe ' prefix.
        for value in ("x" * 501, "x" + "é" * 250):
            with self.subTest(value=value):
                self.assertEqual(len(("chrome.exe " + value).encode()), 512)
                rc, record, _ = self.run_main(["--args", value])
                self.assertEqual(rc, 2)
                self.assertEqual(record["status"], "BLOCKED")
                self.assertIn("512 encoded bytes", record["blocked_reason"])
                self.assertIn("autorun limit is 511", record["blocked_reason"])
        self.build_image.assert_not_called()
        self.bounded.assert_not_called()

    def test_command_at_511_byte_boundary_is_not_truncated(self):
        self.ready_inputs()
        for value in ("x" * 500, "é" * 250):
            with self.subTest(value=value):
                command = "chrome.exe " + value
                self.assertEqual(len(command.encode()), 511)
                self.simulate_qemu()
                rc, record, _ = self.run_main(["--args", value])
                self.assertEqual(rc, 0)
                self.assertEqual(record["status"], "PASS")
                control = self.put_file.call_args_list[-2].args[1]
                self.assertIn(("cmdline=" + command + "\r\n").encode(), control)

    def test_qemu_launch_oserror_persists_blocked_evidence(self):
        self.ready_inputs()
        self.bounded.side_effect = OSError("host-only launch failure")
        rc, record, _ = self.run_main()
        self.assertEqual(rc, 2)
        self.assertEqual(record["status"], "BLOCKED")
        self.assertIn("QEMU launch/collection: OSError: host-only launch failure", record["blocked_reason"])
        self.assertIsNone(record["qemu_returncode"])
        self.assertEqual(record["tree_files"], 1)

    def test_image_preparation_errors_persist_blocked_without_launch(self):
        self.ready_inputs()
        for error in (OSError("host-only image inaccessible"), RuntimeError("host-only mcopy failed")):
            with self.subTest(error=error):
                self.build_image.side_effect = error
                rc, record, _ = self.run_main()
                self.assertEqual(rc, 2)
                self.assertEqual(record["status"], "BLOCKED")
                self.assertIn("image preparation", record["blocked_reason"])
                self.assertIn(str(error), record["blocked_reason"])
        self.bounded.assert_not_called()

    def test_simulated_success_uses_bounded_helper_and_replaces_stale_serial(self):
        self.ready_inputs()
        self.out.mkdir(parents=True)
        (self.out / "serial.log").write_text("FATAL: stale host-only fixture")
        self.simulate_qemu()
        rc, record, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertEqual(record["status"], "PASS")
        self.assertEqual(record["qemu_returncode"], 1)
        self.assertEqual(record["qemu_output"], "host-only QEMU output")
        self.assertEqual(record["chrome_output_line_count"], 1)
        self.assertEqual(record["chrome_output_lines"], [OUTPUT])
        self.assertNotIn("stale", record["serial_tail"])
        self.bounded.assert_called_once_with(record["command"], 9)

    def test_simulated_host_failure_timeout_and_fatal_persist_fail(self):
        self.ready_inputs()
        for serial, rc, timeout in ((SUCCESS, 7, False), (SUCCESS, -9, True),
                                    (SUCCESS + "\nFATAL: host-only fatal fixture", 1, False),
                                    (SUCCESS + "\nK64 ldr: chrome.dll rejected image", 1, False),
                                    (SUCCESS + "\nK64 autorun: result malformed", 1, False)):
            with self.subTest(rc=rc, timeout=timeout, serial=serial):
                self.simulate_qemu(serial=serial, rc=rc, timed_out=timeout)
                code, record, _ = self.run_main()
                self.assertEqual(code, 1)
                self.assertEqual(record["status"], "FAIL")
                self.assertEqual(record["qemu_returncode"], rc)
                self.assertEqual(record["qemu_timed_out"], timeout)
                self.assertTrue(record["failure_reasons"])


if __name__ == "__main__":
    print("HOST ONLY: simulated Chromium runner tests; no guest or application execution.", flush=True)
    unittest.main()
