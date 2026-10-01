#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Negative acceptance tests using explicitly synthetic guest-shaped logs.

The TLS baseline is the frozen real Linux host-v3 log, whose digest is checked
before replacing its platform/nonce and inserting an authored Windows identity.
None of these fixtures or tests establishes native Windows execution.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "verify_observed_guest.py"
SPEC = importlib.util.spec_from_file_location("verify_observed_guest", MODULE_PATH)
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

NONCE = "tls7707-synthetic-acceptance-a8c03941"
BUILD = 0x040A08AE
HOST_LOG = HERE.parents[1] / "build/secure-transport/host-v3/probe.log"
HOST_LOG_SHA256 = "b7e7c87196f314880798fa03e72fa48c0cd26a8cc6268925cff60b28cae392c0"
HOST_MODEL = HERE.parents[1] / "build/secure-transport/verify-observed-host-model"
CHILD_COMMAND = (
    "C:\\GOPLAB\\TLS13PRB.EXE --server-cert SRV.PEM --server-key SRV.KEY "
    "--ca CA.PEM --untrusted-ca BADCA.PEM --expired-cert EXP.PEM "
    "--expired-key EXP.KEY --output TLS13.LOG --nonce " + NONCE
)


def encode_rows(rows):
    return ("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n").encode("ascii")


def synthetic_tls_rows():
    raw = HOST_LOG.read_bytes()
    if hashlib.sha256(raw).hexdigest() != HOST_LOG_SHA256:
        raise AssertionError("Frozen actual host-v3 baseline changed")
    rows = [json.loads(line) for line in raw.splitlines()]
    for row in rows:
        row["nonce"] = NONCE
    rows[0]["platform"] = "windows-native-build"
    rows.insert(1, {"case": "windows_identity", "version_query_ok": True,
                    "platform_id": 1, "major": 4, "minor": 10, "build": BUILD,
                    "win98_identified": True, "nonce": NONCE})
    return rows


def synthetic_observer_fields():
    # These 36 fields represent an authored successful observer trace. They are
    # an input-parser fixture, never claimed as a returned guest log.
    return {
        "schema": "win98modern.tls-owned-child-observer.v1",
        "scope": "fixed-native-TLS-fixture-actual-post-CRT-child-exit",
        "nonce": NONCE,
        "observer.application": r"C:\GOPLAB\TLSWATCH.EXE",
        "observer.pid": "1234",
        "observer.tid": "1235",
        "os.query-ok": "1",
        "os.query-error": "0",
        "os.platform": "1",
        "os.major": "4",
        "os.minor": "10",
        "os.build": str(BUILD),
        "os.build-low": "2222",
        "os.exact-win98se": "1",
        "child.application": r"C:\GOPLAB\TLS13PRB.EXE",
        "child.command": CHILD_COMMAND,
        "child.directory": r"C:\GOPLAB",
        "child.timeout-ms": "90000",
        "child.output-absent-before-create": "1",
        "child.created": "1",
        "child.create-error": "0",
        "child.pid": "2234",
        "child.tid": "2235",
        "child.thread-handle-closed": "1",
        "child.thread-handle-close-error": "0",
        "child.wait": "0",
        "child.wait-error": "0",
        "child.exit-query": "1",
        "child.exit-query-error": "0",
        "child.exit-code": "0",
        "child.process-handle-closed": "1",
        "child.process-handle-close-error": "0",
        "child.terminated": "1",
        "child.post-crt-zero-exit-observed": "1",
        "observer.exit-candidate": "0",
        "observer.success-requires-report-close": "1",
    }


def encode_observer(fields):
    return ("\r\n".join(name + "=" + value for name, value in fields.items()) + "\r\n").encode("ascii")


class TLSLogAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.rows = synthetic_tls_rows()

    def reject(self, rows):
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_tls_log(encode_rows(rows), NONCE)

    def test_synthetic_native_shaped_baseline(self):
        result = VERIFIER.validate_tls_log(encode_rows(self.rows), NONCE)
        self.assertIsInstance(result, dict)

    def test_one_stale_nonce_cannot_join_other_fresh_rows(self):
        self.rows[5]["nonce"] = "tls7707-stale-acceptance-a8c03941"
        self.reject(self.rows)

    def test_actual_linux_host_log_is_not_guest_evidence(self):
        raw = HOST_LOG.read_bytes()
        nonce = json.loads(raw.splitlines()[0])["nonce"]
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_tls_log(raw, nonce)

    def test_linux_platform_rejected_even_with_authored_windows_identity(self):
        self.rows[0]["platform"] = "linux-host-build"
        self.reject(self.rows)

    def test_missing_duplicate_reordered_or_unknown_case(self):
        variants = []
        missing = copy.deepcopy(self.rows); del missing[4]; variants.append(missing)
        duplicate = copy.deepcopy(self.rows); duplicate.insert(4, copy.deepcopy(duplicate[4])); variants.append(duplicate)
        reordered = copy.deepcopy(self.rows); reordered[4], reordered[5] = reordered[5], reordered[4]; variants.append(reordered)
        unknown = copy.deepcopy(self.rows); unknown[4]["case"] = "unknown_future_case"; variants.append(unknown)
        for index, rows in enumerate(variants):
            with self.subTest(index=index):
                self.reject(rows)

    def test_duplicate_json_key_rejected_even_when_values_agree(self):
        raw = encode_rows(self.rows).replace(b'"passed":true', b'"passed":true,"passed":true', 1)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_tls_log(raw, NONCE)

    def test_case_pass_requires_literal_boolean_true(self):
        for value in (False, 0, 1, "true", None):
            with self.subTest(value=value):
                rows = copy.deepcopy(self.rows)
                rows[4]["passed"] = value
                self.reject(rows)

    def test_summary_failure_or_integer_true_rejected(self):
        for key in ("passed", "tls13_handshake", "authenticated_payload", "wrong_host_rejected",
                    "untrusted_ca_rejected", "expired_rejected", "partial_io_and_truncation",
                    "random_failure_rejected", "tls12_downgrade_rejected", "late_random_failure_rejected",
                    "modified_ciphertext_rejected", "record_boundary_eof_rejected",
                    "zero_size_random_has_no_os_call"):
            for value in (False, 1):
                with self.subTest(key=key, value=value):
                    rows = copy.deepcopy(self.rows)
                    rows[-1][key] = value
                    self.reject(rows)

    def test_random_calls_requires_positive_integer(self):
        for value in (-1, 0, False, True, 1.5, "77", None):
            with self.subTest(value=value):
                rows = copy.deepcopy(self.rows)
                rows[-1]["random_calls"] = value
                self.reject(rows)

    def test_summary_cannot_hide_contradictory_certificate_or_protocol_results(self):
        for case, field, value in (
            ("valid_bidirectional_payload_and_close", "version", "TLSv1.2"),
            ("valid_bidirectional_payload_and_close", "verify_flags", 8),
            ("wrong_host_rejected", "verify_flags", 0),
            ("untrusted_ca_rejected", "client_status", 0),
            ("expired_certificate_rejected", "verify_flags", 0),
            ("tls12_only_peer_rejected", "client_status", 0),
            ("modified_ciphertext_rejected", "server_status", 0),
            ("record_boundary_eof_rejected", "server_status", 3),
        ):
            with self.subTest(case=case, field=field):
                rows = copy.deepcopy(self.rows)
                next(row for row in rows if row.get("case") == case)[field] = value
                self.reject(rows)

    def test_false_or_non_win98_identity_rejected(self):
        for field, value in (("version_query_ok", False), ("version_query_ok", 1),
                             ("platform_id", 2), ("major", 5), ("minor", 90),
                             ("build", 1998), ("win98_identified", False)):
            with self.subTest(field=field, value=value):
                rows = copy.deepcopy(self.rows)
                rows[1][field] = value
                self.reject(rows)


class ObserverLogAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.fields = synthetic_observer_fields()

    def reject(self, fields):
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_observer_log(encode_observer(fields), NONCE, BUILD)

    def test_synthetic_success_trace(self):
        self.assertEqual(len(self.fields), 36)
        result = VERIFIER.validate_observer_log(encode_observer(self.fields), NONCE, BUILD)
        self.assertIsInstance(result, dict)

    def test_duplicate_field_rejected(self):
        raw = encode_observer(self.fields) + b"child.exit-code=0\r\n"
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_observer_log(raw, NONCE, BUILD)

    def test_guarded_timeout_is_never_success(self):
        self.fields["child.guard-terminate"] = "1"
        self.reject(self.fields)

    def test_full_dword_child_crash_cannot_be_truncated_to_zero(self):
        for value in ("3221225472", "3221225477", "1996947457", "4294967296", "-1"):
            with self.subTest(value=value):
                fields = self.fields.copy()
                fields["child.exit-code"] = value
                self.reject(fields)

    def test_wait_query_cleanup_and_final_exit_failures(self):
        for field, value in (
            ("child.wait", "258"), ("child.wait", "4294967295"),
            ("child.exit-query", "0"), ("child.exit-query-error", "6"),
            ("child.created", "0"), ("child.create-error", "2"),
            ("child.thread-handle-closed", "0"), ("child.thread-handle-close-error", "6"),
            ("child.process-handle-closed", "0"), ("child.process-handle-close-error", "6"),
            ("child.terminated", "0"), ("child.post-crt-zero-exit-observed", "0"),
            ("observer.exit-candidate", "29"), ("observer.success-requires-report-close", "0"),
            ("child.output-absent-before-create", "0"), ("child.wait-error", "6"),
        ):
            with self.subTest(field=field, value=value):
                fields = self.fields.copy()
                fields[field] = value
                self.reject(fields)

    def test_os_and_executable_binding_failures(self):
        for field, value in (
            ("os.query-ok", "0"), ("os.query-error", "120"),
            ("os.platform", "2"), ("os.major", "5"), ("os.minor", "90"),
            ("os.build-low", "1998"), ("os.build", str(BUILD + 1)),
            ("os.exact-win98se", "0"), ("nonce", "tls7707-stale-acceptance-a8c03941"),
            ("child.application", r"C:\GOPLAB\OTHER.EXE"),
            ("observer.application", r"C:\GOPLAB\OTHER.EXE"),
            ("child.directory", r"C:\OTHER"), ("child.command", CHILD_COMMAND + " --extra"),
        ):
            with self.subTest(field=field, value=value):
                fields = self.fields.copy()
                fields[field] = value
                self.reject(fields)

    def test_missing_or_unknown_field_rejected(self):
        missing = self.fields.copy(); del missing["child.process-handle-closed"]
        unknown = self.fields.copy(); unknown["child.extra-success"] = "1"
        self.reject(missing)
        self.reject(unknown)


class CheckedFilesAcceptanceTests(unittest.TestCase):
    def setUp(self):
        HOST_MODEL.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="checked-files-", dir=HOST_MODEL)
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "evidence.bin"
        self.path.write_bytes(b"frozen private evidence\n")

    def test_explicit_null_sha_is_not_an_unpinned_read(self):
        reader = VERIFIER.CheckedFiles()
        with self.assertRaises(VERIFIER.VerificationError):
            reader.read(self.path, None)
        self.assertEqual(reader.records, {})

    def test_content_mutation_after_correct_hash_read_rejected_at_finish(self):
        raw = self.path.read_bytes()
        reader = VERIFIER.CheckedFiles()
        self.assertEqual(reader.read(self.path, hashlib.sha256(raw).hexdigest()), raw)
        self.path.write_bytes(b"changed evidence with a different size\n")
        with self.assertRaises(VERIFIER.VerificationError):
            reader.finish()

    def test_json_exact_default_and_explicit_receipt_limits(self):
        for maximum in (1024 ** 2, 4 * 1024 ** 2):
            with self.subTest(maximum=maximum):
                self.path.write_bytes(b"{}" + b" " * (maximum - 2))
                reader = VERIFIER.CheckedFiles()
                options = {} if maximum == 1024 ** 2 else {"maximum": maximum}
                self.assertEqual(reader.json(self.path, **options), {})
                self.assertEqual(reader.finish()[0]["bytes"], maximum)

    def test_json_limit_plus_one_rejected_with_no_record(self):
        for maximum in (1024 ** 2, 4 * 1024 ** 2):
            with self.subTest(maximum=maximum):
                self.path.write_bytes(b"{}" + b" " * (maximum - 1))
                reader = VERIFIER.CheckedFiles()
                options = {} if maximum == 1024 ** 2 else {"maximum": maximum}
                with self.assertRaisesRegex(VERIFIER.VerificationError, "Evidence size outside bounds"):
                    reader.json(self.path, **options)
                self.assertEqual(reader.records, {})

    def test_json_receipt_allowance_does_not_raise_default_limit(self):
        self.path.write_bytes(b"{}" + b" " * (1024 ** 2 - 1))
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Evidence size outside bounds"):
            VERIFIER.CheckedFiles().json(self.path)
        self.assertEqual(VERIFIER.CheckedFiles().json(self.path, maximum=4 * 1024 ** 2), {})

    def test_json_explicit_null_sha_with_receipt_allowance_stays_pinned(self):
        self.path.write_bytes(b"{}" + b" " * (1024 ** 2 - 1))
        reader = VERIFIER.CheckedFiles()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Malformed pinned SHA"):
            reader.json(self.path, None, maximum=4 * 1024 ** 2)
        self.assertEqual(reader.records, {})

    def test_large_json_mutation_rejected_at_finish(self):
        raw = b"{}" + b" " * (1024 ** 2 - 1)
        self.path.write_bytes(raw)
        reader = VERIFIER.CheckedFiles()
        self.assertEqual(reader.json(self.path, hashlib.sha256(raw).hexdigest(), maximum=4 * 1024 ** 2), {})
        self.path.write_bytes(raw + b" ")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Evidence mutated during verification"):
            reader.finish()

    def test_large_json_mutation_rejected_against_retained_sha(self):
        raw = b"{}" + b" " * (1024 ** 2 - 1)
        self.path.write_bytes(raw + b" ")
        reader = VERIFIER.CheckedFiles()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Evidence SHA differs"):
            reader.json(self.path, hashlib.sha256(raw).hexdigest(), maximum=4 * 1024 ** 2)
        self.assertEqual(reader.records, {})


if __name__ == "__main__":
    unittest.main()
