# SPDX-License-Identifier: GPL-2.0-only
"""Offline contract fixtures; execution belongs to the admitted parent phase.

Each case targets a wrong mutation: stale kind/roots, ANSI re-encoding, a reset
COW baseline, or incomplete/forged observer evidence. No VM/media is accessed.
"""
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zlib

SOURCE = Path(__file__).resolve().parents[1] / "tools/global_theme_trial.py"
SPEC = importlib.util.spec_from_file_location("global_theme_trial", SOURCE)
trial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trial)

NONCE = "0123456789abcdef0123456789abcdef"
BASELINE = tuple(i * 0x010101 for i in range(25))
MODERN = (0xcfcfcf, 0x452e13, 0xd77800, 0x888078, 0xf0f0f0,
          0xffffff, 0x605040, 0, 0, 0xffffff, 0xa0a0a0, 0xc0c0c0,
          0xa0a0a0, 0xd77800, 0xffffff, 0xf0f0f0, 0xa0a0a0,
          0x808080, 0, 0xf0f0f0, 0xffffff, 0x606060, 0xe0e0e0, 0, 0xe1ffff)
RUN = b'"C:\\VXDLAB\\SHZTHEME.EXE" /restore\0'


def profile(style):
    # Independently specified on-wire record, not the production encoder.
    return (b"SHZCLR1\0" + struct.pack("<4I", 1, 224, style, 25)
            + struct.pack("<25I", *BASELINE)
            + struct.pack("<25I", *(MODERN if style else BASELINE)))


def snapshot(style=None):
    if style is None:
        return ["PROFILE_TYPE=0", "PROFILE_BYTES=0", "PROFILE_RAW=",
                "RUN_TYPE=0", "RUN_BYTES=0", "RUN_RAW="]
    return ["PROFILE_TYPE=3", "PROFILE_BYTES=224", "PROFILE_RAW=" + profile(style).hex(),
            "RUN_TYPE=1", "RUN_BYTES=34", "RUN_RAW=" + RUN.hex()]


def stage(name, colors, notifications, paints):
    return ["STAGE=" + name, "WITNESS_COLORCHANGE_COUNT=" + str(notifications),
            "WITNESS_PAINT_COUNT=" + str(paints),
            "WITNESS_NATIVE_PIXEL=" + str(colors[15]),
            "ACTUAL_COLORS=" + struct.pack("<25I", *colors).hex()]


def log(phase):
    lines = ["HEADER=SHZGLOB%d_V1" % phase, "NONCE=" + NONCE, "PHASE=" + str(phase), "OBSERVER_PID=234",
             "OBSERVER_ROLE=INDEPENDENT_NATIVE_READ_ONLY_THEME_OBSERVER",
             "PROCESS_SELF_LOG_IS_NOT=EXTERNAL_EXIT_OR_BOOT_OR_SOURCE_PROOF",
             "OS_PLATFORM=1", "OS_MAJOR=4", "OS_MINOR=10",
             "OS_BUILD_RAW=67766446", "OS_BUILD_LOW_WORD=2222"]
    child = ['CHILD_COMMAND="C:\\VXDLAB\\SHZTHEME.EXE"', "CHILD_PID=123",
             "CHILD_NATIVE_GUI_CONTROLS=CLASS_PID_101_102_ENABLED"]
    if phase == 1:
        lines += ["INITIAL_PROFILE_PRESENT=0", "INITIAL_RUN_PRESENT=0",
                  "BASELINE=" + struct.pack("<25I", *BASELINE).hex()]
        lines += snapshot() + stage("INITIAL_BASELINE", BASELINE, 0, 1) + child
        for name, style, n in (("SHIZOS_FIRST", 1, 1),
                               ("CLASSIC_ORIGINAL_BASELINE", 0, 2), ("SHIZOS_SAVED", 1, 3)):
            lines += ["AWAITING_TRANSITION=" + name]
            lines += stage(name, MODERN if style else BASELINE, n, n + 1) + snapshot(style)
        lines += ["SEQUENCE=BASELINE_SHIZOS_CLASSIC_SHIZOS"]
    else:
        lines += ["RESTORE_PROCESS_EXTERNAL_EXIT=NOT_OBSERVED_NO_PROCESS_HANDLE",
                  "COLD_BOOT_IDENTITY=REQUIRES_EXTERNAL_SAME_COW_SECOND_EPOCH_RECEIPT",
                  "BASELINE=" + struct.pack("<25I", *BASELINE).hex()]
        lines += stage("COLD_BOOT_AUTOMATIC_SHIZOS_BEFORE_CHILD", MODERN, 0, 1) + snapshot(1) + child
        lines += ["AWAITING_TRANSITION=COLD_BOOT_CLASSIC_RETURN"]
        lines += stage("COLD_BOOT_CLASSIC_RETURN", BASELINE, 1, 2) + snapshot(0)
        lines += ["SEQUENCE=AUTOMATIC_SHIZOS_BEFORE_CHILD_CLASSIC_RETURN"]
    final_style = 1 if phase == 1 else 0
    lines += ["AWAITING=ACTUAL_CHILD_GUI_CLOSE", "CHILD_EXIT_OBSERVED=1", "CHILD_EXIT_CODE=0",
              "FINAL_READBACK=AFTER_NORMAL_CHILD_EXIT", "FINAL_STYLE=" + str(final_style),
              "FINAL_COLORS=" + struct.pack("<25I", *(MODERN if final_style else BASELINE)).hex(),
              "FINAL_PROFILE_TYPE=3", "FINAL_PROFILE_BYTES=224", "FINAL_PROFILE=" + profile(final_style).hex(),
              "FINAL_RUN_TYPE=1", "FINAL_RUN_BYTES=34", "FINAL_RUN_RAW=" + RUN.hex(),
              "EVIDENCE_COMPLETE_REQUIRES_EXTERNAL_EXIT=1", "OBSERVER_REQUESTED_EXIT=0"]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def bootstrap_log(phase):
    # Independent accepted wire grammar; this is not a native execution claim.
    lines = ["HEADER=SHZGB%d_V1" % phase, "NONCE=" + NONCE, "PHASE=" + str(phase),
             "BOOTSTRAP_PID=345", "BOOTSTRAP_PATH=C:\\VXDLAB\\SHZGBOOT.EXE",
             "BOOTSTRAP_COMMAND_MODE=FIXED_PATH_NO_ARGUMENTS", "OS_PLATFORM=1", "OS_MAJOR=4", "OS_MINOR=10",
             "OS_BUILD_RAW=67766446", "OS_BUILD_LOW_WORD=2222",
             'OBSERVER_COMMAND="C:\\VXDLAB\\SHZOBS.EXE"', "OBSERVER_WORKING_DIRECTORY=C:\\VXDLAB",
             "OBSERVER_INHERIT_HANDLES=0", "OBSERVER_PID=234", "OBSERVER_THREAD_HANDLE_CLOSED=1",
             "OBSERVER_WAIT_RESULT=0", "OBSERVER_EXIT_QUERY_SUCCEEDED=1", "OBSERVER_EXIT_CODE=0",
             "OBSERVER_PROCESS_HANDLE_CLOSED=1", "LOG_FLUSH_OBSERVED=1",
             "LOG_FINAL_FLUSH=REQUESTED_NOT_EXTERNALLY_OBSERVED", "LOG_FINAL_CLOSE=REQUESTED_NOT_EXTERNALLY_OBSERVED",
             "BOOTSTRAP_EXTERNAL_EXIT=NOT_OBSERVED", "BOOTSTRAP_REQUESTED_EXIT=0",
             "RESULT=NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT"]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


class BytePreservingStartup(unittest.TestCase):
    def test_only_one_empty_windows_run_changes_and_ansi_bytes_survive(self):
        data = b";\xb0\xa1\xb3\xaa\r\n[Windows]\r\n run = \t\r\nload=\r\n[fonts]\r\nx=\xc7\xd1\r\n"
        changed, detail = trial.patch_empty_run(data)
        self.assertEqual(changed, b";\xb0\xa1\xb3\xaa\r\n[Windows]\r\n run =C:\\VXDLAB\\SHZGBOOT.EXE \t\r\nload=\r\n[fonts]\r\nx=\xc7\xd1\r\n")
        self.assertTrue(detail["other_bytes_preserved"])

    def test_stale_duplicate_and_ambiguous_inputs_are_refused(self):
        for data in (b"[windows]\r\nrun=old.exe\r\n", b"[windows]\r\nrun=\r\nrun=\r\n",
                     b"[windows]\r\nrun=\r\n[windows]\r\n", b"[windows]\rrun=\r",
                     b"\xff\xfe[windows]\r\nrun=\r\n", b"[windows]\r\nrun=\0\r\n"):
            with self.subTest(data=data), self.assertRaises(trial.TrialError):
                trial.patch_empty_run(data)

    def test_case_two_changes_only_phase_and_keeps_nonce(self):
        first = trial.case_bytes(NONCE, 1)
        self.assertEqual(first, b"SHZGCASE1\r\nnonce=0123456789abcdef0123456789abcdef\r\nphase=1\r\n")
        self.assertEqual(len(first), 60)
        self.assertEqual(trial.case_bytes(NONCE, 2), first.replace(b"phase=1", b"phase=2"))
        for nonce, phase in ((NONCE.upper(), 1), (NONCE, 3), (NONCE + "0", 1)):
            with self.assertRaises(trial.TrialError): trial.case_bytes(nonce, phase)


class NativeObserverEvidence(unittest.TestCase):
    def test_complete_two_logs_bind_real_profile_palette_and_child_exit(self):
        first = trial.parse_observer_log(log(1), NONCE, 1)
        second = trial.parse_observer_log(log(2), NONCE, 2, first)
        self.assertEqual(first["stages"], ["INITIAL_BASELINE", "SHIZOS_FIRST", "CLASSIC_ORIGINAL_BASELINE", "SHIZOS_SAVED"])
        self.assertEqual(second["stages"][0], "COLD_BOOT_AUTOMATIC_SHIZOS_BEFORE_CHILD")
        self.assertEqual(second["baseline"], BASELINE)
        self.assertEqual(second["restore_process_exit"], "NOT_OBSERVED_NO_PROCESS_HANDLE")
        self.assertEqual(second["observer_exit"], "NOT_OBSERVED_SELF_LOG_ONLY")
        self.assertEqual(second["observer_pid"], 234)
        self.assertEqual(second["final_profile"], profile(0).hex())
        self.assertEqual(second["cold_boot_saved_profile"], profile(1).hex())

    def test_missing_duplicate_wrong_nonce_and_failure_records_never_pass(self):
        valid = log(1)
        damaged = (valid[:-2], valid.replace(b"CHILD_EXIT_CODE=0\r\n", b""),
                   valid.replace(b"CHILD_EXIT_CODE=0", b"CHILD_EXIT_CODE=1"),
                   valid + b"RESULT=FAIL\r\n", valid.replace(b"PHASE=1\r\n", b"PHASE=1\r\nPHASE=1\r\n"),
                   valid.replace(NONCE.encode(), b"f" * 32), valid.replace(b"\r\n", b"\n"))
        for data in damaged:
            with self.subTest(data=data[-60:]), self.assertRaises(trial.TrialError):
                trial.parse_observer_log(data, NONCE, 1)

    def test_repaint_palette_pixel_and_stage_order_are_real_gates(self):
        valid = log(1)
        damaged = (valid.replace(b"WITNESS_COLORCHANGE_COUNT=2", b"WITNESS_COLORCHANGE_COUNT=1"),
                   valid.replace(b"WITNESS_PAINT_COUNT=3", b"WITNESS_PAINT_COUNT=2"),
                   valid.replace(b"WITNESS_NATIVE_PIXEL=15790320", b"WITNESS_NATIVE_PIXEL=0", 1),
                   valid.replace(b"STAGE=SHIZOS_FIRST", b"STAGE=SHIZOS_SAVED", 1),
                   valid.replace(profile(1).hex().encode(), profile(0).hex().encode(), 1))
        for data in damaged:
            with self.subTest(data=data[-60:]), self.assertRaises(trial.TrialError):
                trial.parse_observer_log(data, NONCE, 1)

    def test_second_boot_cannot_adopt_a_different_baseline(self):
        first = trial.parse_observer_log(log(1), NONCE, 1)
        altered = log(2).replace(struct.pack("<25I", *BASELINE).hex().encode(), b"00" * 100, 1)
        with self.assertRaises(trial.TrialError): trial.parse_observer_log(altered, NONCE, 2, first)

    def test_zero_child_exit_does_not_override_wrong_final_state(self):
        data = log(1).replace(b"FINAL_STYLE=1\r\n", b"FINAL_STYLE=0\r\n")
        with self.assertRaises(trial.TrialError): trial.parse_observer_log(data, NONCE, 1)
        data = log(1).replace(b"FINAL_READBACK=AFTER_NORMAL_CHILD_EXIT\r\n", b"")
        with self.assertRaises(trial.TrialError): trial.parse_observer_log(data, NONCE, 1)


class ParentBootstrapEvidence(unittest.TestCase):
    def test_parent_both_epochs_prove_observer_zero_exit_but_not_self_exit(self):
        first = trial.parse_observer_log(log(1), NONCE, 1)
        second = trial.parse_observer_log(log(2), NONCE, 2, first)
        for phase, observer in ((1, first), (2, second)):
            parsed = trial.parse_bootstrap_log(bootstrap_log(phase), NONCE, phase, observer)
            self.assertEqual(parsed["observer_pid"], observer["observer_pid"])
            self.assertEqual(parsed["observer_exit"], "OBSERVED_NORMAL_ZERO")
            self.assertEqual(parsed["bootstrap_exit"], "NOT_OBSERVED")
            self.assertEqual(parsed["final_io"], "REQUESTED_NOT_EXTERNALLY_OBSERVED")

    def test_missing_truncated_duplicate_wrong_phase_or_nonce_are_rejected(self):
        observer = trial.parse_observer_log(log(1), NONCE, 1)
        valid = bootstrap_log(1)
        damaged = (b"", valid[:-2], valid[:-12], valid.replace(b"OBSERVER_EXIT_QUERY_SUCCEEDED=1\r\n", b""),
                   valid.replace(b"PHASE=1\r\n", b"PHASE=1\r\nPHASE=1\r\n"),
                   valid.replace(b"PHASE=1\r\n", b"PHASE=2\r\n"), valid.replace(NONCE.encode(), b"f" * 32),
                   valid + b"FAIL_STAGE=final_close\r\n", valid.replace(b"\r\n", b"\n"))
        for data in damaged:
            with self.subTest(length=len(data)), self.assertRaises(trial.TrialError):
                trial.parse_bootstrap_log(data, NONCE, 1, observer)

    def test_high_dword_exit_timeout_wrong_command_and_pid_cannot_pass(self):
        observer = trial.parse_observer_log(log(1), NONCE, 1)
        valid = bootstrap_log(1)
        damaged = (valid.replace(b"OBSERVER_EXIT_CODE=0\r\n", b"OBSERVER_EXIT_CODE=256\r\n"),
                   valid.replace(b"OBSERVER_EXIT_CODE=0\r\n", b"OBSERVER_EXIT_CODE=4294967295\r\n"),
                   valid.replace(b"OBSERVER_WAIT_RESULT=0\r\n", b"OBSERVER_WAIT_RESULT=258\r\n"),
                   valid.replace(b"SHZOBS.EXE\"", b"SHZTHEME.EXE\""),
                   valid.replace(b"OBSERVER_PID=234\r\n", b"OBSERVER_PID=123\r\n"),
                   valid.replace(b"OBSERVER_PID=234\r\n", b"OBSERVER_PID=0\r\n"))
        for data in damaged:
            with self.subTest(data=data[-80:]), self.assertRaises(trial.TrialError):
                trial.parse_bootstrap_log(data, NONCE, 1, observer)

    def test_handle_and_final_io_failures_or_self_final_claims_are_rejected(self):
        observer = trial.parse_observer_log(log(1), NONCE, 1)
        valid = bootstrap_log(1)
        damaged = (valid.replace(b"OBSERVER_THREAD_HANDLE_CLOSED=1", b"OBSERVER_THREAD_HANDLE_CLOSED=0"),
                   valid.replace(b"OBSERVER_PROCESS_HANDLE_CLOSED=1", b"OBSERVER_PROCESS_HANDLE_CLOSED=0"),
                   valid.replace(b"LOG_FLUSH_OBSERVED=1", b"LOG_FLUSH_OBSERVED=0"),
                   valid.replace(b"LOG_FINAL_CLOSE=REQUESTED_NOT_EXTERNALLY_OBSERVED", b"LOG_FINAL_CLOSE=PASS"),
                   valid.replace(b"BOOTSTRAP_EXTERNAL_EXIT=NOT_OBSERVED", b"BOOTSTRAP_EXTERNAL_EXIT=PASS"),
                   valid + b"FAIL_ERROR=5\r\nBOOTSTRAP_REQUESTED_EXIT=5\r\n",
                   valid + b"OBSERVER_TERMINATED=1\r\n")
        for data in damaged:
            with self.subTest(data=data[-80:]), self.assertRaises(trial.TrialError):
                trial.parse_bootstrap_log(data, NONCE, 1, observer)


class CumulativePrivateBudget(unittest.TestCase):
    def observation(self, exclusive, inode=22):
        return {"device": 11, "inode": inode, "file_bytes": 2147483648,
                "exclusive_bytes": exclusive, "shared_bytes": 1000000}

    def test_two_epochs_use_the_original_pre_injection_baseline(self):
        baseline = self.observation(1048576)
        self.assertEqual(trial.cumulative_growth(baseline, self.observation(134217728)), 133169152)
        with self.assertRaises(trial.TrialError):
            trial.cumulative_growth(baseline, self.observation(269484033))

    def test_inode_replacement_cannot_reset_budget(self):
        with self.assertRaises(trial.TrialError):
            trial.cumulative_growth(self.observation(0), self.observation(1, 23))


class NativeInputBoundaries(unittest.TestCase):
    def test_manual_input_cannot_inject_hmp_or_foreign_file_commands(self):
        for action in ({"kind": "hmp", "command": "quit"},
                       {"kind": "key", "keys": ["ret;quit"]},
                       {"kind": "click", "x": -1, "y": 0},
                       {"kind": "capture", "filename": "/tmp/foreign"}):
            with self.assertRaises(trial.TrialError): trial.input_action(action)
        self.assertEqual(trial.input_action({"kind": "key", "keys": ["alt", "f4"]}),
                         {"kind": "key", "keys": ["alt", "f4"]})

    def test_absolute_click_requires_a_current_absolute_device(self):
        absolute = [{"name": "fixture absolute device", "index": 0, "current": True, "absolute": True}]
        self.assertEqual(trial.absolute_pointer_device(absolute), absolute[0])
        for devices in ([], [{**absolute[0], "absolute": False}],
                        [{**absolute[0], "current": False}], absolute * 2,
                        [{**absolute[0], "absolute": "true"}]):
            with self.assertRaises(trial.TrialError): trial.absolute_pointer_device(devices)

    def test_native_ppm_requires_complete_bounded_raster(self):
        valid = b"P6\n1 1\n255\n\x10\x20\x30"
        self.assertEqual(trial.native_image_kind(valid), "native-QMP-PPM")
        for data in (valid[:-1], valid + b"x", b"P6\n9999 9999\n255\n"):
            with self.assertRaises(trial.TrialError): trial.native_image_kind(data)

    def test_native_png_requires_complete_chunks_crc_and_raster(self):
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
        header = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        raster = chunk(b"IDAT", zlib.compress(b"\x00\x10\x20\x30"))
        footer = chunk(b"IEND", b"")
        valid = b"\x89PNG\r\n\x1a\n" + header + raster + footer
        self.assertEqual(trial.native_image_kind(valid), "native-QMP-PNG")
        damaged = (valid[:33], valid[:-1], valid[:-12], valid + b"garbage",
                   valid[:-16] + bytes([valid[-16] ^ 1]) + valid[-15:],
                   valid[:8] + header + chunk(b"IDAT", zlib.compress(b"\x00\x10\x20")) + footer,
                   valid[:8] + header + chunk(b"IDAT", zlib.compress(b"\x05\x10\x20\x30")) + footer,
                   valid[:8] + header + raster + header + footer)
        for data in damaged:
            with self.subTest(length=len(data)), self.assertRaises(trial.TrialError):
                trial.native_image_kind(data)


class StoppedGuestInputIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        stage = self.root / "stage"; stage.mkdir()
        bootstrap = self.root / "bootstrap"; bootstrap.mkdir()
        sources = self.root / "sources"; sources.mkdir()
        inputs = {"SHZTHEME.EXE": b"independent selector fixture", "SHZOBS.EXE": b"independent observer fixture",
                  "SHZGBOOT.EXE": b"independent parent fixture",
                  "SHZCASE.TXT": b"SHZGCASE1\r\nnonce=0123456789abcdef0123456789abcdef\r\nphase=1\r\n"}
        for name, data in inputs.items(): (stage / name).write_bytes(data)
        second = inputs["SHZCASE.TXT"].replace(b"phase=1", b"phase=2")
        (bootstrap / "SHZCASE2.TXT").write_bytes(second)
        ini = b";\xb0\xa1\r\n[windows]\r\nrun=C:\\VXDLAB\\SHZGBOOT.EXE\r\nload=\r\n"
        (bootstrap / "WININI-AFTER").write_bytes(ini)
        bindings = []
        for role, name in (("selector", "SHZTHEME.EXE"), ("observer", "SHZOBS.EXE"), ("bootstrap", "SHZGBOOT.EXE")):
            artifact = sources / name; artifact.write_bytes(inputs[name])
            receipt = sources / (role + "-receipt.json"); receipt.write_bytes(b'{"fixture":"not a native build"}\n')
            source = sources / (role + ".c"); source.write_bytes(("/* " + role + " */\n").encode())
            bindings += [trial.binding(role, artifact), trial.binding(role + "_receipt", receipt),
                         trial.binding("pe_source:" + name + ":" + role + ".c", source)]
        tool = sources / "mattrib-fixture"; tool.write_bytes(b"not executed\n")
        bindings.append(trial.binding("mattrib", tool))
        self.plan = {"nonce": NONCE, "roots": {"stage": str(stage), "bootstrap": str(bootstrap)},
                     "bindings": bindings, "stage_hashes": {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
                     "bootstrap_hashes": {name: hashlib.sha256((bootstrap / name).read_bytes()).hexdigest()
                                           for name in ("SHZCASE2.TXT", "WININI-AFTER")},
                     "private_cow_identity": {"device": 1, "inode": 2, "bytes": 2147483648},
                     "preparation": {"winini_after_sha256": hashlib.sha256(ini).hexdigest(),
                                     "winini_attributes_hex": b"  A      ::/WINDOWS/WIN.INI\n".hex()}}
        self.guest = {"::/VXDLAB/" + name: data for name, data in inputs.items()}
        self.guest["::/WINDOWS/WIN.INI"] = ini
        self.phase2 = second

    def collect(self, phase):
        with mock.patch.object(trial, "mtype", side_effect=lambda plan, guard, path, limit: self.guest[path]), \
             mock.patch.object(trial, "guest_spec", return_value="fixture-not-opened"), \
             mock.patch.object(trial, "guarded_mtool", return_value=bytes.fromhex(self.plan["preparation"]["winini_attributes_hex"])):
            # This fixture exercises stopped byte comparison, not guest execution.
            return trial.stopped_guest_readback(self.plan, object(), phase)

    def test_each_epoch_binds_guest_bytes_to_stage_and_actual_source_receipts(self):
        first = self.collect(1)
        self.assertEqual(first["status"], "PASS")
        self.assertEqual(first["epoch"], 1)
        self.assertEqual(first["files"]["SHZOBS.EXE"]["source_hashes"],
                         {"observer.c": trial.by_role(self.plan, "pe_source:SHZOBS.EXE:observer.c")["sha256"]})
        self.guest["::/VXDLAB/SHZCASE.TXT"] = self.phase2
        second = self.collect(2)
        self.assertEqual(second["files"]["SHZCASE.TXT"]["sha256"], hashlib.sha256(self.phase2).hexdigest())
        self.assertEqual(second["files"]["WIN.INI"], first["files"]["WIN.INI"])

    def test_changed_binary_case_or_winini_is_not_accepted_after_guest_exit(self):
        for path in ("::/VXDLAB/SHZTHEME.EXE", "::/VXDLAB/SHZOBS.EXE", "::/VXDLAB/SHZGBOOT.EXE", "::/VXDLAB/SHZCASE.TXT", "::/WINDOWS/WIN.INI"):
            original = self.guest[path]
            try:
                self.guest[path] = original + b"tampered"
                with self.subTest(path=path), self.assertRaises(trial.TrialError): self.collect(1)
            finally: self.guest[path] = original
        with self.assertRaises(trial.TrialError): self.collect(2)

    def test_changed_stage_cannot_rebind_unchanged_source_artifact(self):
        (Path(self.plan["roots"]["stage"]) / "SHZOBS.EXE").write_bytes(b"changed staged program")
        with self.assertRaises(trial.TrialError): self.collect(1)

    def test_third_bootstrap_artifact_and_build_source_binding_are_mandatory(self):
        for missing_role in ("bootstrap", "bootstrap_receipt", "pe_source:SHZGBOOT.EXE:bootstrap.c"):
            original = self.plan["bindings"]
            try:
                self.plan["bindings"] = [row for row in original if row["role"] != missing_role]
                with self.subTest(missing_role=missing_role), self.assertRaises(trial.TrialError): self.collect(1)
            finally: self.plan["bindings"] = original


class CompiledReceiptBoundary(unittest.TestCase):
    def native_envelope(self, root, name):
        # Receipt-shape fixture only: no compiler or native executable is run.
        inputs = {"SHZTHEME.EXE": ("ntwddm/win98/theme_selector/selector_core.c", "ntwddm/win98/theme_selector/selector_win98.c"),
                  "SHZOBS.EXE": ("ntwddm/win98/theme_global_probe/observer.c",),
                  "SHZGBOOT.EXE": ("ntwddm/win98/theme_global_startup/launcher.c",)}[name] + ("platform/freestanding/memory.c",)
        hashes = {}
        for relative in inputs:
            source = root / relative; source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(("/* independent fixture " + relative + " */\n").encode())
            hashes[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
        artifact = root / name; artifact.write_bytes(b"receipt-envelope-fixture")
        receipt = root / "result.json"
        payload = {"schema": 1, "status": "PASS", "source_root": str(root),
                   "source_hashes": hashes,
                   "compiler_version": "i686-w64-mingw32-gcc (GCC) fixture-version",
                   "executable": {"path": str(artifact), "bytes": artifact.stat().st_size,
                                  "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                  "native_gate": {"status": "PASS", "role": {"SHZTHEME.EXE": "selector", "SHZOBS.EXE": "observer", "SHZGBOOT.EXE": "bootstrap"}[name],
                                                  "native_execution_verified": False}}}
        libraries = ["-lkernel32"] if name == "SHZGBOOT.EXE" else ["-lkernel32", "-luser32", "-lgdi32", "-ladvapi32"]
        if name == "SHZTHEME.EXE":
            payload["compiler_versions"] = {"clang": "clang fixture-version", "i686-w64-mingw32-gcc": payload.pop("compiler_version")}
            payload["host_tests"] = [{"kind": kind, "result": "PASS: 139 selector checks"} for kind in ("host", "sanitizer")]
        commands = [{"argv": ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
            "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
            "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
            "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,windows:4.10",
            "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
            "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
            "-Wl,--no-insert-timestamp", *[str(root / relative) for relative in inputs], *libraries,
            "-o", str(artifact)], "exit_code": 0, "stdout": "", "stderr": ""}]
        return receipt, payload, commands

    def observer_envelope(self, root):
        return self.native_envelope(root, "SHZOBS.EXE")

    def write_envelope(self, receipt, payload, commands):
        receipt.write_text(json.dumps(payload))
        (receipt.parent / "commands.json").write_text(json.dumps(commands))
        return hashlib.sha256(receipt.read_bytes()).hexdigest()

    def bootstrap_envelope(self, root):
        receipt, payload, commands = self.native_envelope(root, "SHZGBOOT.EXE")
        for relative in ("ntwddm/win98/theme_global_startup/launcher_host_test.c", "ntwddm/win98/theme_global_startup/launcher_mock.h"):
            source = root / relative; source.write_bytes(("/* fixture " + relative + " */\n").encode())
            payload["source_hashes"][relative] = hashlib.sha256(source.read_bytes()).hexdigest()
        text = "PASS: 32 global bootstrap checks"
        payload["host_compiler_version"] = "clang fixture-version"
        payload["host_tests"] = [{"kind": kind, "result": text, "completed_checks": 32} for kind in ("host", "sanitizer")]
        for kind in ("host", "sanitizer"):
            flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if kind == "sanitizer" else []
            binary = root / kind
            commands.append({"argv": ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", *flags,
                str(root / "ntwddm/win98/theme_global_startup/launcher_host_test.c"), "-o", str(binary)], "exit_code": 0, "stdout": "", "stderr": ""})
            commands.append({"argv": [str(binary)], "exit_code": 0, "stdout": text + "\n", "stderr": ""})
        return receipt, payload, commands

    def test_bootstrap_requires_matching_actual_host_sanitizer_and_native_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, payload, commands = self.bootstrap_envelope(root)
            selected = self.write_envelope(receipt, payload, commands)
            artifact, _ = trial.build_input(receipt, selected, "SHZGBOOT.EXE")
            self.assertEqual(artifact, root / "SHZGBOOT.EXE")

    def test_bootstrap_declared_checks_missing_runs_or_wrong_native_artifact_reject(self):
        for defect in ("too_few", "different_counts", "duplicate_kind", "missing_runtime", "runtime_failed",
                       "wrong_stdout", "no_sanitizer", "wrong_role", "wrong_artifact", "no_commands"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); receipt, payload, commands = self.bootstrap_envelope(root)
                if defect == "too_few":
                    for row in payload["host_tests"]: row["result"] = "PASS: 29 global bootstrap checks"
                elif defect == "different_counts": payload["host_tests"][1]["result"] = "PASS: 33 global bootstrap checks"
                elif defect == "duplicate_kind": payload["host_tests"][1]["kind"] = "host"
                elif defect == "missing_runtime": commands.pop()
                elif defect == "runtime_failed": commands[-1]["exit_code"] = 1
                elif defect == "wrong_stdout": commands[-1]["stdout"] = "PASS: 999 global bootstrap checks\n"
                elif defect == "no_sanitizer": commands[-2]["argv"].remove("-fsanitize=address,undefined")
                elif defect == "wrong_role": payload["executable"]["native_gate"]["role"] = "observer"
                elif defect == "wrong_artifact": payload["executable"]["sha256"] = "0" * 64
                else: commands = []
                selected = self.write_envelope(receipt, payload, commands)
                with self.assertRaises(trial.TrialError): trial.build_input(receipt, selected, "SHZGBOOT.EXE")

    def test_actual_observer_singular_compiler_envelope_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, payload, commands = self.observer_envelope(root)
            selected = self.write_envelope(receipt, payload, commands)
            executable, records = trial.build_input(receipt, selected, "SHZOBS.EXE")
            self.assertEqual(executable, root / "SHZOBS.EXE")
            self.assertEqual({row["role"] for row in records},
                             {"pe_commands:SHZOBS.EXE", "pe_source:SHZOBS.EXE:ntwddm/win98/theme_global_probe/observer.c",
                              "pe_source:SHZOBS.EXE:platform/freestanding/memory.c"})

    def test_all_three_genuine_compiler_recipe_envelopes_remain_accepted(self):
        for name in ("SHZTHEME.EXE", "SHZOBS.EXE", "SHZGBOOT.EXE"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt, payload, commands = self.bootstrap_envelope(root) if name == "SHZGBOOT.EXE" else self.native_envelope(root, name)
                selected = self.write_envelope(receipt, payload, commands)
                self.assertEqual(trial.build_input(receipt, selected, name)[0], root / name)

    def test_swapped_unhashed_extra_response_or_plugin_native_inputs_reject(self):
        defects = ("swapped", "extra_unhashed", "extra_hashed", "response", "include", "imacros", "plugin",
                   "object", "library_path", "noncanonical", "missing_hash")
        for defect in defects:
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); receipt, payload, commands = self.observer_envelope(root)
                source = str(root / "ntwddm/win98/theme_global_probe/observer.c")
                extra = root / "unrelated.c"; extra.write_bytes(b"/* unapproved source */\n")
                argv = commands[0]["argv"]
                if defect == "swapped":
                    payload["source_hashes"]["unrelated.c"] = hashlib.sha256(extra.read_bytes()).hexdigest()
                    argv[argv.index(source)] = str(extra)
                elif defect.startswith("extra_"):
                    argv.insert(argv.index("-o"), str(extra))
                    if defect == "extra_hashed": payload["source_hashes"]["unrelated.c"] = hashlib.sha256(extra.read_bytes()).hexdigest()
                elif defect == "response": argv.insert(1, "@" + str(root / "inputs.rsp"))
                elif defect in ("include", "imacros"): argv[1:1] = ["-" + defect, str(root / "unhashed.h")]
                elif defect == "plugin": argv.insert(1, "-fplugin=" + str(root / "unhashed.so"))
                elif defect == "object": argv.insert(1, str(root / "unhashed.o"))
                elif defect == "library_path": argv.insert(1, str(root / "unhashed.a"))
                elif defect == "noncanonical": argv[argv.index(source)] = str(root) + "/ntwddm/win98/theme_global_probe/../theme_global_probe/observer.c"
                else: payload["source_hashes"].pop("ntwddm/win98/theme_global_probe/observer.c")
                selected = self.write_envelope(receipt, payload, commands)
                with self.assertRaises(trial.TrialError): trial.build_input(receipt, selected, "SHZOBS.EXE")

    def test_host_source_mock_header_and_implicit_inputs_are_source_bound(self):
        for defect in ("swapped", "extra", "response", "include", "plugin", "missing_mock", "missing_host_hash"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); receipt, payload, commands = self.bootstrap_envelope(root)
                argv = commands[-2]["argv"]
                source = str(root / "ntwddm/win98/theme_global_startup/launcher_host_test.c")
                extra = root / "foreign_test.c"; extra.write_bytes(b"/* not the shared host test */\n")
                if defect == "swapped":
                    payload["source_hashes"]["foreign_test.c"] = hashlib.sha256(extra.read_bytes()).hexdigest()
                    argv[argv.index(source)] = str(extra)
                elif defect == "extra": argv.insert(1, str(extra))
                elif defect == "response": argv.insert(1, "@" + str(root / "host-inputs.rsp"))
                elif defect == "include": argv[1:1] = ["-include", str(root / "unhashed.h")]
                elif defect == "plugin": argv.insert(1, "-fplugin=" + str(root / "unhashed.so"))
                elif defect == "missing_mock": payload["source_hashes"].pop("ntwddm/win98/theme_global_startup/launcher_mock.h")
                else: payload["source_hashes"].pop("ntwddm/win98/theme_global_startup/launcher_host_test.c")
                selected = self.write_envelope(receipt, payload, commands)
                with self.assertRaises(trial.TrialError): trial.build_input(receipt, selected, "SHZGBOOT.EXE")

    def test_observer_version_does_not_replace_actual_command_and_role_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for defect in ("empty_version", "plural_only", "wrong_role", "compiler_failed", "missing_legacy_flag"):
                with self.subTest(defect=defect):
                    receipt, payload, commands = self.observer_envelope(root)
                    if defect == "empty_version": payload["compiler_version"] = " \t"
                    elif defect == "plural_only":
                        payload["compiler_versions"] = {"i686-w64-mingw32-gcc": payload.pop("compiler_version")}
                    elif defect == "wrong_role": payload["executable"]["native_gate"]["role"] = "selector"
                    elif defect == "compiler_failed": commands[0]["exit_code"] = 1
                    else: commands[0]["argv"].remove("-march=i486")
                    selected = self.write_envelope(receipt, payload, commands)
                    with self.assertRaises(trial.TrialError):
                        trial.build_input(receipt, selected, "SHZOBS.EXE")

    def test_hashes_and_declared_pass_without_actual_compile_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "SHZOBS.EXE"; artifact.write_bytes(b"fixture-not-an-executed-build")
            receipt = root / "result.json"
            payload = {"status": "PASS", "source_root": str(root), "source_hashes": {"observer.c": "0" * 64},
                       "compiler_version": "hashed metadata only",
                       "executable": {"path": str(artifact), "bytes": artifact.stat().st_size,
                                      "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                      "native_gate": {"status": "PASS", "role": "observer", "native_execution_verified": False}}}
            receipt.write_text(json.dumps(payload))
            selected_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()
            with self.assertRaisesRegex(trial.TrialError, "Executed compiler"):
                trial.build_input(receipt, selected_sha, "SHZOBS.EXE")


class PinnedMtoolsDispatch(unittest.TestCase):
    def child_and_selector(self, exit_code=0):
        child = mock.Mock()
        child.wait.return_value = exit_code
        child.poll.return_value = exit_code
        selector = mock.MagicMock()
        selector.__enter__.return_value.get_map.return_value = {}
        return child, selector

    def test_resolved_alias_keeps_each_whitelisted_role_as_actual_argv_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); executable = root / "mtools"; executable.write_bytes(b"fixture never executed\n")
            bindings = []
            for role in ("mtype", "mcopy", "mdir", "mattrib"):
                alias = root / role; alias.symlink_to(executable)
                bindings.append(trial.binding(role, alias.resolve(strict=True)))
            plan = {"bindings": bindings}
            for role in ("mtype", "mcopy", "mdir", "mattrib"):
                with self.subTest(role=role):
                    child, selector = self.child_and_selector()
                    guard = mock.Mock()
                    with mock.patch.object(trial.subprocess, "Popen", return_value=child) as spawn, \
                         mock.patch.object(trial.selectors, "DefaultSelector", return_value=selector):
                        self.assertEqual(trial.guarded_mtool(plan, guard, role, ["-V"]), b"")
                    argv = spawn.call_args.args[0]
                    self.assertEqual(argv, [role, "-V"])
                    self.assertEqual(spawn.call_args.kwargs["executable"], str(executable))
                    self.assertNotIn("shell", spawn.call_args.kwargs)
                    self.assertEqual(guard.check.call_count, 2)

    def test_arbitrary_or_path_based_dispatch_is_rejected_before_process_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "mtools"; executable.write_bytes(b"not executed\n")
            for role in ("mtools", "sh", "/usr/bin/mtype", "mtype;sh"):
                with self.subTest(role=role), mock.patch.object(trial.subprocess, "Popen") as spawn:
                    with self.assertRaises(trial.TrialError):
                        trial.command([role, "-V"], mtool_executable=executable)
                    spawn.assert_not_called()

    def test_failed_dispatch_reports_actual_role_argv_and_exit_boundedly(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "mtools"; executable.write_bytes(b"not executed\n")
            child, selector = self.child_and_selector(exit_code=1)
            with mock.patch.object(trial.subprocess, "Popen", return_value=child), \
                 mock.patch.object(trial.selectors, "DefaultSelector", return_value=selector):
                with self.assertRaises(trial.TrialError) as raised:
                    trial.command(["mtype", "-i", "fixture", "::/VXDLAB/SHZCASE.TXT"], mtool_executable=executable)
            message = str(raised.exception)
            self.assertIn('"role": "mtype"', message)
            self.assertIn('"exit_code": 1', message)
            self.assertIn("::/VXDLAB/SHZCASE.TXT", message)
            self.assertLess(len(message), 8192)


class OwnedPlanScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def plan(self):
        roots = [self.root / "build" / ("global-theme-6970-" + role + "-abc")
                 for role in ("stage", "consumer", "run", "bootstrap")]
        return {"schema": 2, "kind": "native-win98-global-selector-two-cold-boots-v2",
                "owner_root": str(self.root), "nonce": NONCE,
                "roots": {role: str(path) for role, path in zip(("stage", "consumer", "run", "bootstrap"), roots)},
                "host_output_budget": {"schema": 1, "roots": [str(p) for p in roots],
                    "excluded_private_cow": str(roots[2] / "windows-uefi.raw"),
                    "limit_bytes": 16777216, "reserve_bytes": 21474836480},
                "cow_quota_bytes": 268435456, "runtime_bound_seconds": 900,
                "startup_executable": "C:\\VXDLAB\\SHZGBOOT.EXE", "two_cold_epochs": 2,
                "machine_profile": "q35-kvm-qemu64-2cpu-128m-gop-offline",
                "scope": "OEM_WIN98_CONTROL_NOT_SHIZUKUDOS_REPLACEMENT"}

    def test_old_plan_kind_and_unsafe_path_fail_before_mutations(self):
        for field, value in (("kind", "native-theme-empty-winini-run-on-owned-cow-v1"),
                             ("kind", "native-win98-global-selector-two-cold-boots-v1"), ("schema", 1),
                             ("startup_executable", "C:\\VXDLAB\\SHZOBS.EXE /restore"),
                             ("two_cold_epochs", 1), ("cow_quota_bytes", 536870912)):
            plan = self.plan(); plan[field] = value
            with self.assertRaises(trial.TrialError): trial.validate_plan_shape(plan, self.root)
        plan = self.plan();plan["roots"]["run"] = str(self.root / "build/../foreign")
        with self.assertRaises(trial.TrialError): trial.validate_plan_shape(plan, self.root)

    def test_exact_four_roots_and_exact_cow_exclusion_are_required(self):
        trial.validate_plan_shape(self.plan(), self.root)
        for role in ("stage", "consumer", "bootstrap"):
            plan = self.plan();plan["host_output_budget"]["excluded_private_cow"] = plan["roots"][role] + "/windows-uefi.raw"
            with self.assertRaises(trial.TrialError): trial.validate_plan_shape(plan, self.root)

    def test_symlink_owner_and_stale_run_are_refused(self):
        plan = self.plan(); (self.root / "build").mkdir()
        Path(plan["roots"]["run"]).mkdir()
        with self.assertRaises(trial.TrialError): trial.require_fresh_roots(plan, self.root)
        alias = self.root / "alias";alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(trial.TrialError): trial.safe_path(alias)

    def test_frozen_kvm_and_guard_cannot_rebind_different_source_hashes(self):
        roles = {"canonical": "1", "adapter": "2", "cow": "3", "qemu_helper": "4", "shzlib": "5",
                 "own:tools/theme_native_runner.py": "6", "own:tools/global_theme_kvm_gate.py": "7"}
        bindings = [{"role": name, "sha256": digit * 64} for name, digit in roles.items()]
        frozen = {name + ".py": roles[name] * 64 for name in ("canonical", "adapter", "cow", "qemu_helper", "shzlib")}
        frozen.update({"guard.py": "6" * 64, "kvm_gate.py": "7" * 64})
        plan = {"bindings": bindings, "frozen_helpers": frozen}
        trial.validate_frozen_helpers(plan)
        for name in ("kvm_gate.py", "guard.py", "adapter.py"):
            original = frozen[name]
            try:
                frozen[name] = "f" * 64
                with self.subTest(name=name), self.assertRaises(trial.TrialError): trial.validate_frozen_helpers(plan)
            finally: frozen[name] = original


if __name__ == "__main__":
    unittest.main()
