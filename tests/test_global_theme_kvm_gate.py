# SPDX-License-Identifier: GPL-2.0-only
"""Configuration or host capability must not replace current-VM KVM evidence."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tools/global_theme_kvm_gate.py"


class CurrentKVMTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SOURCE.is_file(), "current owned-VM KVM gate is not implemented")
        spec = importlib.util.spec_from_file_location("global_theme_kvm_gate_tests", SOURCE)
        self.gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.gate)

    def test_enabled_present_booleans_bind_actual_owned_pid(self):
        result = self.gate.validate_kvm_reply({"enabled": True, "present": True}, 1234)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["owned_qemu_pid"], 1234)
        self.assertEqual(result["query_kvm_reply"], {"enabled": True, "present": True})

    def test_host_support_without_active_guest_acceleration_fails(self):
        for reply in ({"enabled": False, "present": True},
                      {"enabled": True, "present": False},
                      {"enabled": False, "present": False}):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                self.gate.validate_kvm_reply(reply, 1234)

    def test_truthy_values_and_incomplete_or_extended_objects_fail(self):
        for reply in (None, [], True, {}, {"present": True}, {"enabled": True},
                      {"enabled": 1, "present": True}, {"enabled": True, "present": "true"},
                      {"enabled": True, "present": True, "configured_accel": "kvm"}):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                self.gate.validate_kvm_reply(reply, 1234)

    def test_invalid_process_identity_fails(self):
        for pid in (None, True, False, 0, -1, "1234", 1.0):
            with self.subTest(pid=pid), self.assertRaises(ValueError):
                self.gate.validate_kvm_reply({"enabled": True, "present": True}, pid)


if __name__ == "__main__":
    unittest.main()
