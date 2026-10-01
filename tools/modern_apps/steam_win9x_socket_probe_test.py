#!/usr/bin/env python3
"""Host rejection controls; synthetic checkpoint text is not native proof."""
import unittest
from steam_win9x_socket_probe_verify import CHECKS, review

NONCE = "synthetic-control-not-native-001"


def authored_control():
    fields = {"scope": "steam-native-win98-loopback-prerequisite", "nonce": NONCE,
              "source.version": "1", "steam.application-executed": "0", "os.platform": "1",
              "os.major": "4", "os.minor": "10", "os.build-low": "2222", "winsock.version": "257",
              "winsock.high-version": "514", "loopback.server-port": "34567", "connect.result": "-1",
              "connect.error": "10035", "roundtrip.bytes-each-direction": str(len(NONCE) + 11)}
    errors = {"accept-empty-wouldblock": 10035, "recv-empty-wouldblock": 10035,
              "connect-started": 10035, "send-after-shutdown-error": 10058,
              "closed-socket-error": 10038, "unmatched-cleanup-error": 10093}
    for name in CHECKS:
        fields[f"check.{name}"] = "1"
        fields[f"error.{name}"] = str(errors.get(name, 0))
    fields.update({"resources.cleaned": "1", "prerequisite.checks-completed": "1",
                   "steam.application-passed": "0", "exit": "0"})
    return fields


def encode(fields):
    return "".join(f"{key}={value}\r\n" for key, value in fields.items()).encode("ascii")


class RejectionControls(unittest.TestCase):
    def test_consistent_text_never_proves_native_execution_or_steam(self):
        result = review(encode(authored_control()), NONCE)
        self.assertTrue(result["complete_consistent_prerequisite_log"])
        self.assertFalse(result["native_probe_execution_verified"])
        self.assertFalse(result["actual_process_exit_after_crt_verified"])
        self.assertFalse(result["steam_application_passed"])

    def test_stale_nonce_is_rejected(self):
        with self.assertRaises(ValueError):
            review(encode(authored_control()), "different-trial-nonce-001")

    def test_missing_and_duplicate_checkpoints_are_rejected(self):
        fields = authored_control()
        del fields["check.recv-server"]
        with self.assertRaises(ValueError):
            review(encode(fields), NONCE)
        with self.assertRaises(ValueError):
            review(encode(authored_control()) + b"check.recv-server=1\r\n", NONCE)

    def test_failed_cleanup_or_wrong_target_cannot_pass(self):
        for key, value in (("resources.cleaned", "0"), ("os.platform", "2"), ("os.build-low", "2223"),
                           ("check.client-eof-zero", "0"), ("steam.application-passed", "1")):
            with self.subTest(key=key):
                fields = authored_control()
                fields[key] = value
                with self.assertRaises(ValueError):
                    review(encode(fields), NONCE)

    def test_wrong_error_transition_and_payload_length_are_rejected(self):
        for key, value in (("error.recv-empty-wouldblock", "0"), ("error.send-after-shutdown-error", "10035"),
                           ("connect.error", "10061"), ("roundtrip.bytes-each-direction", "1")):
            with self.subTest(key=key):
                fields = authored_control()
                fields[key] = value
                with self.assertRaises(ValueError):
                    review(encode(fields), NONCE)

    def test_incomplete_or_oversized_log_is_rejected(self):
        with self.assertRaises(ValueError):
            review(encode(authored_control())[:-2], NONCE)
        with self.assertRaises(ValueError):
            review(b"x" * (65536 + 1), NONCE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
