#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Receipt-only status regressions; fixtures never start a VM or a subprocess."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import export_preview_status as exporter


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PreviewStatusTests(unittest.TestCase):
    """Exercise receipt selection and the boundary of each claimed capability."""

    OLD = "20260930T110000"
    NEW = "20260930T120000"
    IDENTITY = {
        "revision": "a" * 40,
        "branch": "codex/fixture",
        "dirty": True,
        "worktree_fingerprint": "b" * 64,
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write_bytes(self, relative, payload):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def write_json(self, relative, value):
        return self.write_bytes(relative, (json.dumps(value, indent=2) + "\n").encode())

    def source_receipts(self):
        receipts = {}
        for role in ("loader", "kernel", "runtime"):
            path = self.write_bytes(f"fixture-sources/{role}.c", f"/* {role} source */\n".encode())
            receipts[role] = {"sources_sha256": {str(path.relative_to(self.root)): digest(path.read_bytes())}}
        return receipts

    @staticmethod
    def checks(status="PASS"):
        return [{"check": "host acceptance gate", "status": status, "detail": "synthetic receipt"}]

    def gop(self, stamp=OLD, status="PASS"):
        directory = Path("build/gop-provenance") / stamp
        guest = self.write_json(directory / "guest-result.json", {
            "test": "shizukudos/tests/run_k64_gop.py",
            "status": "PASS",
            "checks": self.checks(),
            "runs": [{"display": "std", "status": "PASS", "checks": self.checks()}],
            "git": copy.deepcopy(self.IDENTITY),
        })
        serial = self.write_bytes(directory / "serial.log", b"SHZ-EXIT:0\n")
        shots = {}
        for name in ("shot-fb.png", "shot-status.png"):
            path = self.write_bytes(directory / name, b"synthetic artifact: " + name.encode())
            shots[name] = {"path": str(path), "sha256": digest(path.read_bytes())}
        self.write_json(directory / "inputs.json", {"source_receipts": self.source_receipts()})
        receipt = {
            "status": status,
            "utc": f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z",
            "checks": self.checks(status),
            "apps_run": 85,
            "apps_pass": 85 if status == "PASS" else 84,
            "apps_failed": [] if status == "PASS" else ["T_DELAY.EXE"],
            "guest_check_count": 1,
            "guest_check_results": {"PASS": 1, "FAIL": 0},
            "guest_result": str(guest),
            "guest_result_sha256": digest(guest.read_bytes()),
            "serial": str(serial),
            "serial_sha256": digest(serial.read_bytes()),
            "screenshots": shots,
        }
        path = self.write_json(directory / "result.json", receipt)
        return path, receipt

    def rewrite(self, path, receipt):
        path.write_text(json.dumps(receipt, indent=2) + "\n")

    def desktop(self, stamp=OLD):
        directory = Path("build/desktop-harness-iso") / (stamp + "-fixture")
        receipts = self.source_receipts()
        receipt_paths = {
            "loader": "build/shizukudos/supervisor/build-result.json",
            "kernel": "build/shizukudos/kernels-build-result.json",
            "runtime": "build/shizukudos/win64/build-result.json",
        }
        bound_receipts = {}
        for role, relative in receipt_paths.items():
            path = self.write_json(relative, receipts[role])
            bound_receipts[role] = digest(path.read_bytes())
        frozen_iso = self.write_bytes(directory / "iso-inputs/boot.iso", b"synthetic frozen ISO")
        iso_receipt = self.write_json(directory / "iso-inputs/builder.json", {"sha256": digest(frozen_iso.read_bytes())})
        expected = b"uefi desktop persistence\n"
        common_checks = self.checks()
        boots = []
        for number in (1, 2):
            shot = self.write_bytes(directory / f"boot-{number}/desktop.png", f"synthetic boot {number}".encode())
            self.write_bytes(directory / f"boot-{number}-DESKTOP.TXT", expected)
            common_checks += [
                {"check": f"boot-{number}: disk bytes equal exact host-selected text", "status": "PASS"},
                {"check": f"boot-{number}: FAT32 volume consistent after guest writes", "status": "PASS"},
            ]
            boots.append({
                "boot": number, "status": "PASS", "boot_medium": "shipped-iso-cd", "qemu_exit_code": 1,
                "checks": self.checks(),
                "screenshots": [{"path": str(shot), "sha256": digest(shot.read_bytes()), "label": "desktop-ready"}],
            })
        receipt = {
            "test": "shizukudos/tests/run_k64_desktop.py",
            "utc": f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z",
            "status": "PASS", "checks": common_checks, "boots": boots, "git": copy.deepcopy(self.IDENTITY),
            "inputs": {"receipts": bound_receipts},
            "expected_file": {"path": "D:\\DESKTOP.TXT", "bytes": len(expected), "sha256": digest(expected)},
            "iso": {
                "frozen": str(frozen_iso), "sha256": digest(frozen_iso.read_bytes()),
                "receipt": {"path": str(iso_receipt), "sha256": digest(iso_receipt.read_bytes())},
            },
        }
        return self.write_json(directory / "result.json", receipt), receipt

    def report(self):
        return exporter.build_status(self.root)

    def test_missing_evidence_never_creates_a_capability(self):
        report = self.report()
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(set(report["evidence"]), {
            "gop_qa", "shipped_desktop_iso", "native_win98_gui", "native_win98_driver"})
        self.assertTrue(all(item["state"] == "unverified" for item in report["evidence"].values()))
        self.assertTrue(all(value is False for value in report["capabilities"].values()))

    def test_newer_failure_dominates_an_older_complete_pass(self):
        self.gop()
        latest, _ = self.gop(self.NEW, status="FAIL")
        report = self.report()
        evidence = report["evidence"]["gop_qa"]
        self.assertEqual(evidence["state"], "verified_fail")
        self.assertEqual(Path(evidence["receipt"]["path"]), latest)
        self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_malformed_newest_receipt_does_not_revive_the_older_pass(self):
        self.gop()
        for invalid in (b'{"status":', b"null", b"[]", b'"PASS"', b"85",
                        b'{"status":"FAIL","status":"PASS"}', b'{"utc":NaN}'):
            with self.subTest(receipt=invalid):
                latest = self.write_bytes(Path("build/gop-provenance") / self.NEW / "result.json", invalid)
                report = self.report()
                self.assertEqual(report["evidence"]["gop_qa"]["state"], "error")
                self.assertEqual(Path(report["evidence"]["gop_qa"]["receipt"]["path"]), latest)
                self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_latest_run_without_a_receipt_is_not_skipped(self):
        self.gop()
        directory = self.root / "build/gop-provenance" / self.NEW
        directory.mkdir(parents=True)
        self.write_bytes(directory / "serial.log", b"work in progress\n")
        report = self.report()
        self.assertEqual(report["evidence"]["gop_qa"]["state"], "unverified")
        self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_85_internal_qa_programs_do_not_establish_modern_apps_or_gpu_acceleration(self):
        self.gop()
        report = self.report()
        evidence = report["evidence"]["gop_qa"]
        self.assertEqual(evidence["state"], "verified_pass")
        self.assertEqual(evidence["counts"]["apps_run"], 85)
        self.assertEqual(evidence["counts"]["apps_pass"], 85)
        self.assertTrue(report["capabilities"]["gop_qa_85_apps"])
        self.assertFalse(report["capabilities"]["modern_app_compatibility"])
        self.assertFalse(report["capabilities"]["gpu_acceleration"])
        self.assertFalse(report["capabilities"]["native_windows98_gui"])
        self.assertFalse(report["capabilities"]["native_windows98_driver"])

    def test_receipt_identity_records_exact_bytes_and_guest_source_identity(self):
        path, receipt = self.gop()
        evidence = self.report()["evidence"]["gop_qa"]
        self.assertEqual(Path(evidence["receipt"]["path"]), path)
        self.assertEqual(evidence["receipt"]["sha256"], digest(path.read_bytes()))
        self.assertEqual(evidence["receipt"]["timestamp"], receipt["utc"])
        self.assertEqual(evidence["source_identity"], self.IDENTITY)
        self.assertEqual(evidence["source_freshness"]["state"], "matched")

    def test_changed_current_source_cannot_inherit_a_historical_pass(self):
        self.gop()
        self.write_bytes("fixture-sources/runtime.c", b"/* modified after the accepted run */\n")
        report = self.report()
        evidence = report["evidence"]["gop_qa"]
        self.assertEqual(evidence["source_identity"], self.IDENTITY)
        self.assertEqual(evidence["source_freshness"]["state"], "mismatch")
        self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_missing_source_receipts_are_not_current_source_verification(self):
        path, _ = self.gop()
        (path.parent / "inputs.json").unlink()
        report = self.report()
        self.assertEqual(report["evidence"]["gop_qa"]["source_freshness"]["state"], "unavailable")
        self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_tampered_bound_artifact_invalidates_the_latest_pass(self):
        _, receipt = self.gop()
        Path(receipt["screenshots"]["shot-status.png"]["path"]).write_bytes(b"replaced screenshot")
        report = self.report()
        self.assertNotEqual(report["evidence"]["gop_qa"]["state"], "verified_pass")
        self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_missing_bound_guest_receipt_cannot_be_satisfied_by_an_older_run(self):
        self.gop()
        latest, receipt = self.gop(self.NEW)
        Path(receipt["guest_result"]).unlink()
        report = self.report()
        self.assertEqual(Path(report["evidence"]["gop_qa"]["receipt"]["path"]), latest)
        self.assertNotEqual(report["evidence"]["gop_qa"]["state"], "verified_pass")
        self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_pass_wrapper_cannot_hide_failed_checks_guest_or_disagreeing_counters(self):
        for failure in ("check", "guest", "app", "guest_count", "guest_results", "runner_kind"):
            with self.subTest(failure=failure):
                path, receipt = self.gop()
                if failure == "check":
                    receipt["checks"].append({"check": "unresolved regression", "status": "FAIL"})
                elif failure in ("guest", "runner_kind"):
                    guest_path = Path(receipt["guest_result"])
                    guest = json.loads(guest_path.read_text())
                    if failure == "guest":
                        guest["status"] = "FAIL"
                    else:
                        guest["test"] = "shizukudos/csm/test_win98_uefi.py"
                    self.rewrite(guest_path, guest)
                    receipt["guest_result_sha256"] = digest(guest_path.read_bytes())
                elif failure == "app":
                    receipt["apps_failed"] = ["T_DELAY.EXE"]
                elif failure == "guest_count":
                    receipt["guest_check_count"] = 2
                else:
                    receipt["guest_check_results"] = {"PASS": 2, "FAIL": 0}
                self.rewrite(path, receipt)
                report = self.report()
                self.assertNotEqual(report["evidence"]["gop_qa"]["state"], "verified_pass")
                self.assertFalse(report["capabilities"]["gop_qa_85_apps"])

    def test_two_shipped_desktop_boots_do_not_establish_native_windows98(self):
        self.desktop()
        report = self.report()
        self.assertEqual(report["evidence"]["shipped_desktop_iso"]["state"], "verified_pass")
        self.assertTrue(report["capabilities"]["shipped_desktop_persistence"])
        self.assertFalse(report["capabilities"]["native_windows98_gui"])
        self.assertFalse(report["capabilities"]["native_windows98_driver"])
        self.assertFalse(report["capabilities"]["modern_app_compatibility"])
        self.assertFalse(report["capabilities"]["gpu_acceleration"])

    def test_persistence_requires_two_distinct_cold_boots_of_the_shipped_medium(self):
        for failure in ("one_boot", "repeated_id", "private_medium", "runner_kind"):
            with self.subTest(failure=failure):
                path, receipt = self.desktop()
                if failure == "one_boot":
                    receipt["boots"] = receipt["boots"][:1]
                elif failure == "repeated_id":
                    receipt["boots"][1]["boot"] = 1
                elif failure == "private_medium":
                    for boot in receipt["boots"]:
                        boot["boot_medium"] = "private-fixture-esp"
                else:
                    receipt["test"] = "shizukudos/csm/test_win98_uefi.py"
                self.rewrite(path, receipt)
                report = self.report()
                self.assertNotEqual(report["evidence"]["shipped_desktop_iso"]["state"], "verified_pass")
                self.assertFalse(report["capabilities"]["shipped_desktop_persistence"])

    def test_new_desktop_failure_is_not_hidden_by_old_persistence_success(self):
        self.desktop()
        path, receipt = self.desktop(self.NEW)
        receipt["status"] = "FAIL"
        receipt["boots"][1]["status"] = "FAIL"
        self.rewrite(path, receipt)
        report = self.report()
        self.assertEqual(report["evidence"]["shipped_desktop_iso"]["state"], "verified_fail")
        self.assertEqual(Path(report["evidence"]["shipped_desktop_iso"]["receipt"]["path"]), path)
        self.assertFalse(report["capabilities"]["shipped_desktop_persistence"])

    def test_incomplete_new_desktop_run_does_not_fall_back_to_old_success(self):
        self.desktop()
        (self.root / "build/desktop-harness-iso" / (self.NEW + "-unfinished")).mkdir()
        report = self.report()
        self.assertEqual(report["evidence"]["shipped_desktop_iso"]["state"], "unverified")
        self.assertFalse(report["capabilities"]["shipped_desktop_persistence"])

    def test_desktop_without_exact_host_readback_checks_does_not_prove_persistence(self):
        path, receipt = self.desktop()
        receipt["checks"] = self.checks()
        self.rewrite(path, receipt)
        report = self.report()
        self.assertNotEqual(report["evidence"]["shipped_desktop_iso"]["state"], "verified_pass")
        self.assertFalse(report["capabilities"]["shipped_desktop_persistence"])

    def test_changed_source_receipt_does_not_bind_the_accepted_desktop_to_current_source(self):
        for live_receipt in ("changed", "missing"):
            with self.subTest(live_receipt=live_receipt):
                self.desktop()
                relative = "build/shizukudos/win64/build-result.json"
                if live_receipt == "changed":
                    self.write_json(relative, {"sources_sha256": {"other.c": "0" * 64}})
                else:
                    (self.root / relative).unlink()
                report = self.report()
                evidence = report["evidence"]["shipped_desktop_iso"]
                self.assertEqual(evidence["state"], "verified_pass")
                self.assertEqual(evidence["source_freshness"]["state"],
                                 "mismatch" if live_receipt == "changed" else "unavailable")
                self.assertFalse(report["capabilities"]["shipped_desktop_persistence"])

    def test_a_native_gui_pass_label_requires_independent_review_and_readback(self):
        path = self.write_json("build/shizukudos/csm/run-win98-uefi-q35-kvm-desktop/result.json", {
            "profile": "actual-win98-uefi-csmwrap",
            "status": "PASS", "utc": "2026-09-30T12:00:00Z", "checks": self.checks(),
            "gui_verdict": "PASS", "qemu_exit_code": 0,
        })
        report = self.report()
        self.assertEqual(Path(report["evidence"]["native_win98_gui"]["receipt"]["path"]), path)
        self.assertNotEqual(report["evidence"]["native_win98_gui"]["state"], "verified_pass")
        self.assertFalse(report["capabilities"]["native_windows98_gui"])

    def test_native_driver_failure_remains_separate_from_a_native_gui_run(self):
        gui_path = self.write_json("build/shizukudos/csm/run-win98-uefi-q35-kvm-desktop/result.json", {
            "profile": "actual-win98-uefi-csmwrap",
            "status": "NEEDS-VISUAL-REVIEW", "utc": "2026-09-30T11:00:00Z",
        })
        log = self.write_bytes("build/shizukudos/csm/run-win98-uefi-q35-kvm-native-vxd-fixture/raw.log", b"loader rejected fixture\n")
        driver_path = self.write_json("build/shizukudos/csm/run-win98-uefi-q35-kvm-native-vxd-fixture/result.json", {
            "profile": "actual-win98-uefi-csmwrap",
            "status": "FAIL", "utc": "2026-09-30T12:00:00Z", "checks": self.checks("FAIL"),
            "native_trial": {"validation_status": "FAIL", "readback": [
                {"freshness": "new-in-owned-run", "path": str(log), "sha256": digest(log.read_bytes())}]},
        })
        report = self.report()
        self.assertEqual(Path(report["evidence"]["native_win98_gui"]["receipt"]["path"]), gui_path)
        self.assertEqual(Path(report["evidence"]["native_win98_driver"]["receipt"]["path"]), driver_path)
        self.assertEqual(report["evidence"]["native_win98_driver"]["state"], "verified_fail")
        self.assertFalse(report["capabilities"]["native_windows98_driver"])

    def test_outer_native_failure_cannot_be_promoted_by_a_passing_diagnostic_trial(self):
        directory = "build/shizukudos/csm/run-win98-uefi-q35-kvm-native-vxd-fixture"
        log = self.write_bytes(directory + "/raw.log", b"diagnostic fixture returned zero\n")
        receipt = {
            "profile": "actual-win98-uefi-csmwrap",
            "status": "FAIL", "utc": "2026-09-30T12:00:00Z", "checks": self.checks("FAIL"),
            "native_trial": {
                "validation_status": "PASS", "windows98_version_confirmed": True,
                "candidate_identity_matches": True, "dos_exit": 0, "result_code": 0,
                "readback": [{"freshness": "new-in-owned-run", "path": str(log), "sha256": digest(log.read_bytes())}],
            },
        }
        for profile in ("actual-win98-uefi-csmwrap", "independent-shizukudos-runtime"):
            with self.subTest(profile=profile):
                receipt["profile"] = profile
                self.write_json(directory + "/result.json", receipt)
                report = self.report()
                self.assertEqual(report["evidence"]["native_win98_driver"]["state"],
                                 "verified_fail" if profile == "actual-win98-uefi-csmwrap" else "error")
                self.assertFalse(report["capabilities"]["native_windows98_driver"])


if __name__ == "__main__":
    unittest.main()
