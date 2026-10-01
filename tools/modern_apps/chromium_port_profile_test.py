"""No guest, downloads, compilation or file mutation. SPDX-License-Identifier: GPL-2.0-only"""
import json
from pathlib import Path
import unittest
from chromium_port_profile import assess

HERE = Path(__file__).resolve().parent


class SourceProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((HERE / "chromium_port_profile.json").read_text())
        self.preflight = {
            "schema": "win98modern.app-preflight.v1",
            "input": {"path": "owned.exe", "sha256": "0" * 64, "size_bytes": 1024},
            "pe": {"machine": 0x14C, "format": "PE32", "subsystem": 2,
                   "subsystem_version": [4, 10], "clr_present": False},
            "import_inventory_complete": True, "api_set_dlls": [],
            "unresolved_by_ntw32": [],
        }

    def test_static_eligibility_never_becomes_runtime_pass(self):
        report = assess(self.profile, self.preflight)
        self.assertFalse(report["browser_pass"])
        self.assertFalse(report["guest_executed"])
        self.assertEqual(report["runtime_compatibility"], "unverified")
        self.assertEqual(report["status"], "SOURCE_PORT_REQUIRED")

    def test_active_publisher_snapshot_is_not_replaced_by_stable_reference(self):
        self.assertEqual(self.profile["version"], "157.0.8080.0")
        self.assertEqual(self.profile["publisher_input"]["snapshot"], 1707946)
        self.assertEqual(self.profile["source_commit"], "73c8f84d67bfbad65ad4817d9839ffecb78b06ee")
        self.assertEqual(self.profile["alternate_upstream_reference"]["version"], "155.0.8059.26")

    def test_active_binary_binding_does_not_accept_another_input(self):
        self.assertFalse(assess(self.profile, self.preflight)["active_input_matches_profile"])
        self.preflight["input"]["sha256"] = self.profile["existing_preflights"][0]["input_sha256"]
        report = assess(self.profile, self.preflight)
        self.assertTrue(report["active_input_matches_profile"])
        self.assertFalse(report["browser_pass"])

    def test_x64_uefi_does_not_accept_a_pe32plus_guest(self):
        self.preflight["pe"].update(machine=0x8664, format="PE32+")
        self.assertTrue(any("32-bit Win98" in text for text in assess(self.profile, self.preflight)["blockers"]))

    def test_api_set_unresolved_is_not_proof_of_native_absence(self):
        self.preflight["api_set_dlls"] = ["api-ms-win-core-synch-l1-2-0.dll"]
        self.preflight["unresolved_by_ntw32"] = [{"dll": "kernel32.dll", "symbol": "WaitOnAddress", "kind": "load"}]
        report = assess(self.profile, self.preflight)
        self.assertEqual(report["ntw32_unresolved_count"], 1)
        self.assertFalse(report["ntw32_unresolved_is_native_missing_proof"])

    def test_wrong_schema_cannot_supply_proof(self):
        self.preflight["schema"] = "arbitrary"
        with self.assertRaises(ValueError):
            assess(self.profile, self.preflight)

    def test_malformed_subsystem_is_rejected(self):
        self.preflight["pe"]["subsystem_version"] = [True, 10]
        with self.assertRaises(ValueError):
            assess(self.profile, self.preflight)

    def test_legcord_release_x86_candidate_is_preserved(self):
        profile = json.loads((HERE / "legcord_port_profile.json").read_text())
        report = assess(profile, self.preflight)
        self.assertEqual(profile["electron"]["version"], "43.2.0")
        self.assertIn("ia32", profile["ia32_candidate"]["name"])
        self.assertFalse(report["browser_pass"])


if __name__ == "__main__":
    unittest.main()
