#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host regressions for Electron verdicts and persistent BLOCKED evidence.

Only fixture files in a TemporaryDirectory are created or removed. Build roots,
probe inputs, tools, image preparation and QEMU observations are isolated from
the real build and guest; these tests do not assert application compatibility.
"""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_k64_electron as runner

START = r"K64 autorun: starting D:\e1min\electron.exe (cwd D:\e1min, timeout 1500 s)"
RESULT = "K64 autorun: result exited exit=0 faulted=0 reaped=1 after 120 ms"
MARKER_LINE = f"[win64 electron.exe pid 7] {runner.MARKER}"


class ElectronRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="shz-electron-runner-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.k64 = self.root / "kernel-fixture"
        self.win64 = self.root / "win64-fixture"
        self.probe = self.root / "probe-fixture"
        self.tree = self.root / "app-fixture"
        self.out = self.root / "results"
        for directory in (self.k64, self.win64, self.probe, self.tree):
            directory.mkdir()
        self.build_inputs = [self.k64 / "boot.elf", self.k64 / "KERNEL64S.BIN", self.win64 / "WIN64.IMG"]
        for path in self.build_inputs:
            path.write_bytes(b"host fixture; never booted")
        for name in ("package.json", "main.js", "index.html", "nodeprobe.js"):
            (self.probe / name).write_text("fixture")
        for name in ("electron.exe", "Code.exe"):
            (self.tree / name).write_bytes(b"fixture; never executed")
        self.qemu_path = str(self.root / "qemu-fixture")
        for name, value in (("K64S", self.k64), ("WIN64", self.win64),
                            ("MINAPP", self.probe), ("IMAGES", self.root / "image-fixture")):
            self.patch("runner." + name, value)
        self.which = self.patch("runner.shutil.which", side_effect=lambda name: self.qemu_path)
        self.image_builder = self.patch("runner.build_image", return_value=[("electron.exe", 1)])
        self.put_file = self.patch("runner.put_file")
        self.patch("runner.shzlib.git_state", return_value={"revision": "host-fixture"})
        self.serial = "\n".join((START, MARKER_LINE, RESULT)) + "\n"
        self.process_result = (1, "QEMU fixture diagnostic\n", False)
        self.qemu_run = self.patch("runner.qemu.run_bounded", side_effect=self.emulate_qemu)

    def patch(self, target, *args, **kwargs):
        # Patching module attributes never rewrites the parent's build paths.
        if target.startswith("runner."):
            patcher = mock.patch.object(
                self.resolve_parent(target.removeprefix("runner."))[0],
                self.resolve_parent(target.removeprefix("runner."))[1], *args, **kwargs)
        else:
            patcher = mock.patch(target, *args, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    @staticmethod
    def resolve_parent(name):
        parts = name.split(".")
        parent = runner
        for part in parts[:-1]:
            parent = getattr(parent, part)
        return parent, parts[-1]

    def emulate_qemu(self, command, timeout):
        serial_path = Path(command[command.index("-serial") + 1].removeprefix("file:"))
        self.assertTrue(serial_path.is_relative_to(self.root))
        serial_path.write_text(self.serial)
        return self.process_result

    def invoke(self, *extra, app="minimal", with_tree=True, explicit_out=True):
        argv = ["--app", app, "--qemu", self.qemu_path, "--accel", "tcg"]
        if with_tree:
            argv.extend(("--tree", str(self.tree)))
        if explicit_out:
            argv.extend(("--out", str(self.out)))
        argv.extend(extra)
        with contextlib.redirect_stdout(io.StringIO()):
            code = runner.main(argv)
        out = self.out if explicit_out else self.k64 / f"run_electron_{app}"
        self.assertTrue(out.is_relative_to(self.root))
        return code, json.loads((out / "result.json").read_text())

    def assert_failed(self, *extra, **kwargs):
        code, record = self.invoke(*extra, **kwargs)
        self.assertEqual((code, record["status"]), (1, "FAIL"))
        return record

    def assert_blocked(self, *extra, **kwargs):
        code, record = self.invoke(*extra, **kwargs)
        self.assertEqual((code, record["status"]), (2, "BLOCKED"))
        self.assertTrue(record["blockers"])
        self.image_builder.assert_not_called()
        self.qemu_run.assert_not_called()
        return record

    def test_success_requires_clean_autorun_and_accepts_both_qemu_statuses(self):
        for rc in (0, 1):
            with self.subTest(qemu_rc=rc):
                self.process_result = (rc, "recorded QEMU output", False)
                code, record = self.invoke()
                self.assertEqual((code, record["status"]), (0, "PASS"))
                self.assertTrue(record["expected_line_seen"])
                self.assertEqual(record["ended_by"], "exited")
                self.assertEqual(record["exit_code"], 0)
                self.assertIs(record["faulted"], False)
                self.assertEqual(record["qemu_returncode"], rc)
                self.assertEqual(record["qemu_output"], "recorded QEMU output")
                self.assertEqual(record["app_output_line_count"], 1)
                self.assertEqual(self.qemu_run.call_args.args[1], 2400)

    def test_marker_before_autorun_does_not_pass_or_report_marker_seen(self):
        self.serial = "\n".join((MARKER_LINE, START, "app did not print the marker", RESULT))
        record = self.assert_failed()
        self.assertFalse(record["expected_line_seen"])
        self.assertNotIn("marker seen", record["furthest"])
        self.assertEqual(record["app_output_line_count"], 0)

    def test_marker_and_result_without_autorun_start_fail(self):
        self.serial = "\n".join((MARKER_LINE, RESULT))
        record = self.assert_failed()
        self.assertFalse(record["expected_line_seen"])
        self.assertIsNone(record["ended_by"])
        self.assertEqual(record["autorun_log"], [])

    def test_empty_expected_marker_cannot_pass(self):
        record = self.assert_failed("--expect=")
        self.assertEqual(record["expected_line"], "")
        self.assertFalse(record["expected_line_seen"])

    def test_whitespace_expected_marker_cannot_pass_an_ordinary_serial_log(self):
        for expected in (" ", "\\t", " \\r\\n "):
            with self.subTest(expected=repr(expected)):
                record = self.assert_failed("--expect", expected)
                self.assertEqual(record["expected_line"], expected)
                self.assertFalse(record["expected_line_seen"])

    def test_explicit_expected_marker_is_checked_in_autorun_region(self):
        self.serial = "\n".join(("custom marker", START, RESULT))
        self.assertFalse(self.assert_failed("--expect", "custom marker")["expected_line_seen"])
        self.serial = "\n".join((START, "[user app pid 7] custom marker", RESULT))
        code, record = self.invoke("--expect", "custom marker")
        self.assertEqual((code, record["status"]), (0, "PASS"))

    def test_fatal_loader_and_exception_lines_veto_a_marker_and_clean_exit(self):
        cases = (
            ("loader_failures", r"K64 ldr: D:\e1min\electron.exe imports missing.dll not loaded"),
            ("exceptions", "K64: process 8 renderer killed by page fault"),
            ("exceptions", "K64 EXCEPTION: child process fault"),
            ("exceptions", "unhandled exception in renderer"),
            ("node_fatal", "FATAL ERROR: Reached heap limit"),
            ("node_fatal", "Uncaught TypeError: broken app"),
            ("node_fatal", "SHZ-E1 main: renderer gone"),
            ("chromium_fatal", "[renderer] FATAL: failed initialization"),
            ("chromium_fatal", "Check failed: valid_context"),
        )
        for field, line in cases:
            with self.subTest(diagnostic=line):
                # Also catch a fatal message emitted after the autorun result.
                self.serial = "\n".join((START, MARKER_LINE, RESULT, line))
                record = self.assert_failed()
                self.assertTrue(record["expected_line_seen"])
                self.assertIn(line, record[field])

    def test_optional_runtime_loadlibrary_misses_remain_diagnostic(self):
        line = r"K64 ldr: app: LoadLibrary needs optional.dll not loaded"
        self.serial = "\n".join((START, line, "K32 unsupported: optional probe", MARKER_LINE, RESULT))
        code, record = self.invoke()
        self.assertEqual((code, record["status"]), (0, "PASS"))
        self.assertEqual(record["runtime_loadlibrary_misses"], [line])
        self.assertEqual(record["loader_failures"], [])

    def test_boot_selftest_diagnostics_do_not_count_as_app_failures(self):
        self.serial = "\n".join(("K64 EXCEPTION: selftest", "FATAL ERROR: selftest",
                                 "K64 ldr: selftest imports not loaded", self.serial))
        code, record = self.invoke()
        self.assertEqual((code, record["status"]), (0, "PASS"))
        for field in ("exceptions", "node_fatal", "loader_failures"):
            self.assertEqual(record[field], [])

    def test_guest_timeout_or_other_end_reason_cannot_pass(self):
        for reason in ("timeout", "start-failed", "interrupted"):
            with self.subTest(reason=reason):
                self.serial = "\n".join((START, MARKER_LINE,
                    f"K64 autorun: result {reason} exit=0 faulted=0"))
                record = self.assert_failed()
                self.assertEqual(record["ended_by"], reason)

    def test_nonzero_exit_or_fault_vetoes_success(self):
        for ending in ("exited exit=1 faulted=0", "exited exit=c0000005 faulted=0",
                       "exited exit=0 faulted=1"):
            with self.subTest(ending=ending):
                self.serial = "\n".join((START, MARKER_LINE, "K64 autorun: result " + ending))
                self.assert_failed()

    def test_missing_or_malformed_autorun_result_cannot_pass(self):
        endings = (
            "", "K64 autorun: result exited exit=0",
            "K64 autorun: result exited exit=0 faulted=2",
            "K64 autorun: result exited exit=0 faulted=00",
            "K64 autorun: result exited exit=0 faulted=10",
            "K64 autorun: result exited exit=0z faulted=0",
            "K64 autorun: result exited exit=0 faulted=0 garbage",
            "K64 autorun: result exited exit=0 faulted=0 reaped=1 after",
            "K64 autorun: result start-failed status=c0000135",
        )
        for ending in endings:
            with self.subTest(ending=ending):
                self.serial = "\n".join((START, MARKER_LINE, ending))
                record = self.assert_failed()
                self.assertIsNone(record["faulted"])
                self.assertIsNone(record["exit_code"])
                self.assertIsNone(record["ended_by"])

    def test_latest_malformed_result_does_not_reuse_earlier_clean_result(self):
        self.serial += "K64 autorun: result exited exit=0\n"
        self.assertIsNone(self.assert_failed()["faulted"])

    def test_host_timeout_vetoes_even_complete_guest_evidence(self):
        self.process_result = (1, "partial output from timed-out QEMU", True)
        record = self.assert_failed("--timeout", "7")
        self.assertTrue(record["qemu_timed_out"])
        self.assertEqual(record["qemu_output"], "partial output from timed-out QEMU")
        self.assertEqual(self.qemu_run.call_args.args[1], 7)

    def test_unacceptable_qemu_returncode_vetoes_clean_guest_evidence(self):
        for rc in (-9, 2, 17, None):
            with self.subTest(qemu_rc=rc):
                self.process_result = (rc, "QEMU failed", False)
                self.assertEqual(self.assert_failed()["qemu_returncode"], rc)

    def test_stale_serial_log_is_removed_before_a_new_run(self):
        self.out.mkdir()
        (self.out / "serial.log").write_text(self.serial)
        self.qemu_run.side_effect = lambda command, timeout: (1, "", False)
        record = self.assert_failed()
        self.assertEqual(record["serial_tail"], "")
        self.assertFalse(record["expected_line_seen"])

    def test_node_mode_keeps_probe_steps_environment_and_shared_image(self):
        self.serial = "\n".join((START, "[win64 electron.exe pid 7] SHZ-E1-NODE step 1 ok: fs",
                                "[win64 electron.exe pid 7] SHZ-E1-NODE-DONE 1 steps", RESULT))
        code, record = self.invoke("--env", "EXTRA=value", app="node")
        self.assertEqual((code, record["status"]), (0, "PASS"))
        self.assertEqual(record["env"], ["ELECTRON_RUN_AS_NODE=1", "EXTRA=value"])
        self.assertEqual(record["command_line"], r"electron.exe D:\e1min\resources\app\nodeprobe.js")
        self.assertEqual(Path(record["image"]).name, "minimal.img")
        self.assertEqual(record["node_steps"][0]["result"], "ok")
        control = self.put_file.call_args.args[1]
        self.assertIn(b"env=ELECTRON_RUN_AS_NODE=1\r\nenv=EXTRA=value\r\n", control)
        self.assertEqual(self.image_builder.call_args.args[3],
                         {str(self.probe): "e1min/resources/app"})

    def test_default_and_vscode_keep_modes_and_require_explicit_marker(self):
        for app, executable in (("default", "electron.exe"), ("vscode", "Code.exe")):
            with self.subTest(app=app):
                record = self.assert_failed("--env", "EXTRA=value", app=app)
                self.assertEqual(record["exe"], executable)
                self.assertIsNone(record["expected_line"])
                self.assertEqual(record["env"], ["EXTRA=value"])
                self.assertEqual(self.image_builder.call_args.args[3], None)
                self.assertNotIn("--single-process", record["command_line"])

    def test_missing_prerequisites_are_collected_without_touching_real_build(self):
        for path in self.build_inputs:
            self.assertTrue(path.is_relative_to(self.root))
            path.unlink()
        (self.tree / "electron.exe").unlink()
        self.which.side_effect = lambda name: None
        record = self.assert_blocked()
        missing = "\n".join(record["missing_prerequisites"])
        for path in self.build_inputs:
            self.assertIn(str(path), missing)
        for name in ("electron.exe", "mkfs.vfat", "mcopy", "mmd", self.qemu_path):
            self.assertIn(name, missing)
        self.assertEqual(len(record["missing_prerequisites"]), 8)

    def test_missing_tree_persists_evidence_in_explicit_output(self):
        record = self.assert_blocked(with_tree=False)
        self.assertIn("--tree is required", record["reason"])

    def test_missing_tree_uses_resolved_default_output_before_preflight(self):
        record = self.assert_blocked(with_tree=False, explicit_out=False)
        self.assertEqual(record["app"], "minimal")
        self.assertTrue((self.k64 / "run_electron_minimal" / "result.json").is_file())

    def test_tree_and_executable_must_be_real_files_and_directories(self):
        record = self.assert_blocked("--tree", str(self.root / "absent-tree"))
        self.assertIn("not a directory", record["reason"])
        (self.tree / "electron.exe").unlink()
        (self.tree / "electron.exe").mkdir()
        record = self.assert_blocked()
        self.assertIn("no electron.exe", record["reason"])

    def test_missing_qemu_is_blocked_before_image_preparation(self):
        self.which.side_effect = lambda name: None if name == self.qemu_path else "/fixture/tool"
        record = self.assert_blocked()
        self.assertIn("required QEMU", record["reason"])
        self.assertIsNone(record["qemu_returncode"])

    def test_missing_overlay_input_is_blocked(self):
        (self.probe / "nodeprobe.js").unlink()
        record = self.assert_blocked(app="node")
        self.assertIn(str(self.probe / "nodeprobe.js"), record["reason"])

    def test_command_length_uses_encoded_bytes_and_accepts_exact_buffer_limit(self):
        for text in ("a" * 498, "é" * 249):
            with self.subTest(boundary=text[:1]):
                code, record = self.invoke("--args=" + text)
                self.assertEqual((code, record["status"]), (0, "PASS"))
                self.assertEqual(len(record["command_line"].encode("utf-8")), 511)
        # Reset only fixture mocks so the BLOCKED assertion verifies no new work.
        self.image_builder.reset_mock()
        self.qemu_run.reset_mock()
        record = self.assert_blocked("--args=" + "é" * 250)
        self.assertIn("513 bytes", record["reason"])
        self.assertLess(len(record["command_line"]), 511)

    def test_oversized_ascii_command_is_blocked(self):
        record = self.assert_blocked("--args=" + "a" * 499)
        self.assertIn("512 bytes", record["reason"])

    def test_command_control_characters_are_blocked(self):
        for char in ("\r", "\n", "\0"):
            with self.subTest(character=repr(char)):
                record = self.assert_blocked("--args=probe" + char + "injection")
                self.assertIn("CR, LF or NUL", record["reason"])

    def test_nonpositive_host_and_guest_timeouts_are_blocked(self):
        for option in ("--timeout", "--guest-timeout"):
            for value in ("0", "-1"):
                with self.subTest(option=option, value=value):
                    record = self.assert_blocked(option, value)
                    self.assertIn("must be positive", record["reason"])

    def test_invalid_env_or_oversized_control_file_is_blocked(self):
        for env in ("MISSING_EQUALS", "=value", "NAME=value\ncmdline=other", "NAME=\0",
                    "NAME=" + "a" * 4096):
            with self.subTest(env=env[:40]):
                self.assert_blocked("--env", env)

    def test_control_file_accepts_4096_bytes_and_rejects_4097(self):
        # Size the padding from the control bytes actually emitted by the runner.
        code, _ = self.invoke()
        self.assertEqual(code, 0)
        base_size = len(self.put_file.call_args.args[1])
        padding = "PAD=" + "x" * (4096 - base_size - len(b"env=PAD=\r\n"))
        code, record = self.invoke("--env", padding)
        self.assertEqual((code, record["status"]), (0, "PASS"))
        self.assertEqual(len(self.put_file.call_args.args[1]), 4096)
        self.image_builder.reset_mock()
        self.qemu_run.reset_mock()
        record = self.assert_blocked("--env", padding + "x")
        self.assertIn("4097 bytes", record["reason"])

    def test_invalid_cli_persists_blocked_in_requested_output(self):
        for extra in (("--timeout", "not-an-int"), ("--display", "invalid"), ("--unknown-option",)):
            with self.subTest(extra=extra):
                record = self.assert_blocked(*extra)
                self.assertEqual(record["error_stage"], "command line")
                self.assertEqual(record["error_type"], "ValueError")

    def test_qemu_launch_oserror_has_blocked_evidence_and_command(self):
        self.qemu_run.side_effect = PermissionError("fixture QEMU is not executable")
        code, record = self.invoke()
        self.assertEqual((code, record["status"]), (2, "BLOCKED"))
        self.assertEqual(record["error_stage"], "QEMU execution")
        self.assertEqual(record["error_type"], "PermissionError")
        self.assertEqual(record["command"][0], self.qemu_path)
        self.assertIn("not executable", record["reason"])
        self.assertIsNone(record["qemu_returncode"])

    def test_image_preparation_oserror_persists_blocked(self):
        self.image_builder.side_effect = FileNotFoundError("fixture tool disappeared")
        code, record = self.invoke()
        self.assertEqual((code, record["status"]), (2, "BLOCKED"))
        self.assertEqual(record["error_stage"], "image preparation")
        self.assertEqual(record["error_type"], "FileNotFoundError")
        self.qemu_run.assert_not_called()

    def test_control_write_oserror_persists_blocked(self):
        self.put_file.side_effect = PermissionError("fixture image is not writable")
        code, record = self.invoke()
        self.assertEqual((code, record["status"]), (2, "BLOCKED"))
        self.assertEqual(record["error_type"], "PermissionError")
        self.qemu_run.assert_not_called()

    def test_image_tool_failure_or_timeout_persists_blocked(self):
        for error in (RuntimeError("mcopy fixture failed"),
                      subprocess.TimeoutExpired(["mcopy"], 1, output="partial fixture output")):
            with self.subTest(error=type(error).__name__):
                self.image_builder.side_effect = error
                code, record = self.invoke()
                self.assertEqual((code, record["status"]), (2, "BLOCKED"))
                self.assertEqual(record["error_type"], type(error).__name__)
                self.qemu_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
