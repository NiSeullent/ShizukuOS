# SPDX-License-Identifier: GPL-2.0-only
"""Negative acceptance cases for independent native theme evidence."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("theme_evidence_verifier", Path(__file__).with_name("verify.py"))
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.nonce = "a10b20c30d40e50f60a70b80c90d00e1"
        self.provider = r"C:\VXDLAB\M98THEME.DLL"
        build_dir, readback_dir = self.root / "build", self.root / "stopped-readback"
        build_dir.mkdir()
        readback_dir.mkdir()
        self.artifacts = {}
        for name, payload in (("M98THEME.DLL", b"test-only provider build bytes"),
                              ("NTTHGUI.EXE", b"test-only native probe build bytes")):
            built, readback = build_dir / name, readback_dir / name
            built.write_bytes(payload)
            readback.write_bytes(payload)
            self.artifacts[name] = {"path": str(built), "sha256": hashlib.sha256(payload).hexdigest(),
                                    "bytes": len(payload), "pe98_gate": {"status": "PASS"}}
        self.source = self.root / "source.c"
        self.source.write_bytes(b"test-only frozen source")
        self.receipt = self.root / "build-result.json"
        self.receipt_value = {"schema": 1, "status": "PASS", "native_win98": "not_tested",
                              "artifacts": self.artifacts, "source_root": str(self.root),
                              "source_hashes": {"source.c": hashlib.sha256(self.source.read_bytes()).hexdigest()}}
        self.freeze_receipt()
        self.log = readback_dir / "THEME.LOG"
        self.valid_log = "\r\n".join([
            "NTTHGUI_LOG_VERSION=1", f"BEGIN_NONCE={self.nonce}", "OS_PLATFORM=1", "OS_MAJOR=4", "OS_MINOR=10",
            "PAINT_EVENT=CLASSIC", "EVENT_SWITCH=1", "PAINT_EVENT=MODERN", "EVENT_SWITCH=2",
            "PAINT_EVENT=CLASSIC", f"RUN_NONCE={self.nonce}", "WIN98_IDENTIFIED=1",
            "CLASSIC_PAINTS=2", "MODERN_PAINTS=1", "SWITCHES=2", "DLL_LOCAL=1",
            f"PROVIDER_PATH={self.provider}", "CLEANUP=PASS", "RESULT=PASS", "",
        ])
        self.log.write_text(self.valid_log, encoding="ascii", newline="")
        self.args = {"build_receipt": self.receipt, "build_receipt_sha256": self.receipt_hash,
                     "log": self.log, "nonce": self.nonce, "exit_code": 0, "provider_path": self.provider,
                     "guest_dll": readback_dir / "M98THEME.DLL", "guest_probe": readback_dir / "NTTHGUI.EXE"}

    def freeze_receipt(self):
        self.receipt.write_text(json.dumps(self.receipt_value), encoding="utf-8")
        self.receipt_hash = hashlib.sha256(self.receipt.read_bytes()).hexdigest()

    def reject_log(self, text):
        self.log.write_text(text, encoding="ascii", newline="")
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.verify_native_evidence(**self.args)

    def test_matching_evidence_requires_a_separate_visual_review(self):
        result = VERIFY.verify_native_evidence(**self.args)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["gdi_contracts_verified"])
        self.assertTrue(result["visual_review_required"])
        self.assertFalse(result["native_visibility_verified"])
        self.assertFalse(result["os_wide_automatic_theme_verified"])
        self.assertFalse(result["persistence_verified"])
        self.assertEqual(result["source_freshness"]["matches"], True)

    def test_successful_old_run_cannot_be_replayed_under_a_new_nonce(self):
        self.args["nonce"] = "f" * 32
        with self.assertRaisesRegex(VERIFY.VerificationError, "nonce"):
            VERIFY.verify_native_evidence(**self.args)

    def test_partial_log_cannot_be_promoted_by_pass_substring(self):
        for text in (self.valid_log.replace("RESULT=PASS\r\n", ""),
                     self.valid_log.replace("CLEANUP=PASS\r\n", ""),
                     self.valid_log.replace("NTTHGUI_LOG_VERSION=1\r\n", ""),
                     self.valid_log.replace(f"BEGIN_NONCE={self.nonce}\r\n", ""),
                     "RESULT=PASS\r\n", self.valid_log + "LOG_CLOSE_PENDING\r\n"):
            with self.subTest(text=text):
                self.reject_log(text)

    def test_claimed_win98_flag_cannot_mask_wrong_platform_or_version(self):
        for field, wrong in (("OS_PLATFORM=1", "OS_PLATFORM=2"), ("OS_MAJOR=4", "OS_MAJOR=10"),
                             ("OS_MINOR=10", "OS_MINOR=90"), ("WIN98_IDENTIFIED=1", "WIN98_IDENTIFIED=0")):
            with self.subTest(field=field):
                self.reject_log(self.valid_log.replace(field, wrong))

    def test_final_nonce_cannot_mask_a_different_screenshot_time_nonce(self):
        self.reject_log(self.valid_log.replace("BEGIN_NONCE=" + self.nonce, "BEGIN_NONCE=" + "0" * 32))

    def test_duplicate_final_fields_reject_both_matching_and_conflicting_values(self):
        for extra in ("RESULT=PASS", "RUN_NONCE=" + self.nonce, "SWITCHES=99", " OS_MAJOR = 4 ", "os_major=4"):
            with self.subTest(extra=extra):
                self.reject_log(self.valid_log.replace("RESULT=PASS", extra + "\r\nRESULT=PASS"))

    def test_final_pass_does_not_override_failed_stage_or_log_error(self):
        for error in ("FAIL_STAGE=DrawThemeBackground", "LOG_ERROR=WriteFile", "ERROR=close log",
                      "LOG_CLOSE_FAILED=1", "WRITEFILE_ERROR=5"):
            with self.subTest(error=error):
                self.reject_log(error + "\r\n" + self.valid_log)

    def test_log_pass_cannot_override_nonzero_external_exit(self):
        for code in (1, 29, -1, True):
            with self.subTest(code=code):
                self.args["exit_code"] = code
                with self.assertRaisesRegex(VERIFY.VerificationError, "exit code"):
                    VERIFY.verify_native_evidence(**self.args)

    def test_each_changed_guest_binary_rejects_otherwise_valid_evidence(self):
        for key in ("guest_dll", "guest_probe"):
            with self.subTest(key=key):
                path = self.args[key]
                original = path.read_bytes()
                path.write_bytes(original + b"changed after execution")
                with self.assertRaisesRegex(VERIFY.VerificationError, "guest readback artifact changed"):
                    VERIFY.verify_native_evidence(**self.args)
                path.write_bytes(original)

    def test_replaced_original_build_artifact_rejects_matching_guest_copy(self):
        for name in VERIFY.ARTIFACTS:
            with self.subTest(name=name):
                path = Path(self.artifacts[name]["path"])
                original = path.read_bytes()
                path.write_bytes(original + b"different build")
                with self.assertRaisesRegex(VERIFY.VerificationError, "original build artifact changed"):
                    VERIFY.verify_native_evidence(**self.args)
                path.write_bytes(original)

    def test_rewritten_receipt_cannot_legitimize_changed_binaries(self):
        payload = b"replacement provider"
        built = Path(self.artifacts["M98THEME.DLL"]["path"])
        built.write_bytes(payload)
        self.args["guest_dll"].write_bytes(payload)
        self.artifacts["M98THEME.DLL"].update(sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload))
        self.freeze_receipt()
        with self.assertRaisesRegex(VERIFY.VerificationError, "frozen digest"):
            VERIFY.verify_native_evidence(**self.args)

    def test_frozen_receipt_with_missing_or_failed_native_gate_is_rejected(self):
        for name in VERIFY.ARTIFACTS:
            for gate in (None, "PASS", {}, {"status": "FAIL"}):
                with self.subTest(name=name, gate=gate):
                    self.artifacts[name]["pe98_gate"] = gate
                    self.freeze_receipt()
                    self.args["build_receipt_sha256"] = self.receipt_hash
                    with self.assertRaisesRegex(VERIFY.VerificationError, "native PE gate"):
                        VERIFY.verify_native_evidence(**self.args)
            self.artifacts[name]["pe98_gate"] = {"status": "PASS"}

    def test_duplicate_receipt_keys_are_not_silently_overwritten(self):
        data = self.receipt.read_text(encoding="utf-8")
        self.receipt.write_text(data[:-1] + ', "status": "PASS"}', encoding="utf-8")
        self.args["build_receipt_sha256"] = hashlib.sha256(self.receipt.read_bytes()).hexdigest()
        with self.assertRaisesRegex(VERIFY.VerificationError, "duplicate build receipt key"):
            VERIFY.verify_native_evidence(**self.args)

    def test_original_build_file_cannot_masquerade_as_guest_readback(self):
        self.args["guest_dll"] = Path(self.artifacts["M98THEME.DLL"]["path"])
        with self.assertRaisesRegex(VERIFY.VerificationError, "original build file"):
            VERIFY.verify_native_evidence(**self.args)

    def test_malformed_or_insufficient_counts_do_not_pass(self):
        for old, new in (("CLASSIC_PAINTS=2", "CLASSIC_PAINTS=0"),
                         ("MODERN_PAINTS=1", "MODERN_PAINTS=-1"),
                         ("SWITCHES=2", "SWITCHES=1"), ("SWITCHES=2", "SWITCHES=2.0"),
                         ("SWITCHES=2", "SWITCHES=+2"), ("SWITCHES=2", "SWITCHES=4294967296")):
            with self.subTest(new=new):
                self.reject_log(self.valid_log.replace(old, new))

    def test_local_flag_cannot_mask_another_loaded_provider_path(self):
        self.reject_log(self.valid_log.replace(self.provider, r"C:\WINDOWS\SYSTEM\M98THEME.DLL"))

    def test_windows_provider_path_is_case_insensitive(self):
        self.log.write_text(self.valid_log.replace(self.provider, self.provider.lower()), encoding="ascii", newline="")
        self.assertEqual(VERIFY.verify_native_evidence(**self.args)["status"], "PASS")

    def test_changed_current_source_is_reported_without_rewriting_execution_identity(self):
        self.source.write_bytes(b"newer source not used for these executed binaries")
        result = VERIFY.verify_native_evidence(**self.args)
        self.assertTrue(result["gdi_contracts_verified"])
        self.assertFalse(result["source_freshness"]["matches"])
        self.assertEqual(result["source_freshness"]["mismatches"][0]["path"], "source.c")


if __name__ == "__main__":
    unittest.main()
