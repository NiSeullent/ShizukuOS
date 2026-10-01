#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reject incomplete/stale/contradictory native receipts using synthetic files.

These are evidence-parser tests. Their tiny fixture DLLs, simulated VM JSON and
transcripts never demonstrate TLS cryptography or Windows process execution.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("guest_evidence", ROOT / "tools/verify_tls13_guest_evidence.py")
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / "stage"
        self.run_dir = self.root / "run"
        self.sources = self.root / "sources"
        for path in (self.stage, self.run_dir, self.sources):
            path.mkdir()
        self.nonce = "synthetic-parser-fixture-only"
        self.inputs = []
        for name in sorted(E.INPUT_NAMES):
            data = ("SYNTHETIC-PARSER-FIXTURE:" + name).encode()
            path = self.stage / name
            path.write_bytes(data)
            self.inputs.append({"source": str(path), "guest": E.PREFIX + name,
                                "sha256": self.sha(data), "bytes": len(data)})
        self.by_name = {item["guest"].rsplit("\\", 1)[1]: item for item in self.inputs}
        source_hashes = {}
        for name in E.SOURCE_NAMES:
            path = self.sources / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"SYNTHETIC-SOURCE-FIXTURE")
            source_hashes[name] = self.sha(path.read_bytes())
        client = {"profile": "pe32", "dependency": {"version": "4.2.0", "tf_psa_crypto_version": "1.2.0"},
                  "artifacts": [{"path": "fixture/M98TLS13.dll", "sha256": self.by_name["M98TLS13.DLL"]["sha256"]}]}
        server = {"status": "PASS", "target": "win98-x86", "upstream": {"version": "3.6.7"},
                  "source_sha256": {"transport.h": "7f3f364ab97fd58d94c03f80432a94b99c0ad28b71b48bc4d0ee4920e3191cda"},
                  "native_library": {key: self.by_name["M98TLS.DLL"][key] for key in ("sha256", "bytes")}}
        self.build = {"schema": "win98modern.latest-tls-dll-interop.v1", "status": "PASS", "nonce": self.nonce,
                      "artifacts": {name: {key: item[key] for key in ("sha256", "bytes")}
                                    for name, item in self.by_name.items()}, "source_sha256": source_hashes,
                      "client_receipt_sha256": self.write_json(self.stage / "client-build.json", client),
                      "server_receipt_sha256": self.write_json(self.stage / "server-build.json", server)}
        for key, name, exports in (("client_gate", "M98TLS13.DLL", E.CLIENT_EXPORTS),
                                    ("server_gate", "M98TLS.DLL", E.SERVER_EXPORTS)):
            self.build[key] = {"pe32_oem_gate": "PASS", "sha256": self.by_name[name]["sha256"],
                               "exports": sorted(exports)}
        for key, name in (("probe_gate", "TLSDLL.EXE"), ("runner_gate", "T13RUN.EXE")):
            self.build[key] = dict({field: self.by_name[name][field] for field in ("sha256", "bytes")},
                                  pe32_oem_gate="PASS", stack_reserve=2097152, stack_commit=65536)
        self.build_path = self.stage / "build-result.json"
        build_sha = self.write_json(self.build_path, self.build)
        self.manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "nonce": self.nonce,
                         "command": E.PREFIX + "T13RUN.EXE", "network_required": False, "inputs": self.inputs,
                         "outputs": [E.PREFIX + name for name in ("TLSDLL.LOG", "T13RUN.LOG", "TLSOUT.LOG")],
                         "source_receipts": [{"path": str(self.build_path), "sha256": build_sha}]}
        self.manifest_path = self.stage / "guest-files.json"
        self.manifest_sha = self.write_json(self.manifest_path, self.manifest)
        native = ["NONCE=" + self.nonce,
                  "CLIENT_SHA256=" + self.by_name["M98TLS13.DLL"]["sha256"],
                  "SERVER_SHA256=" + self.by_name["M98TLS.DLL"]["sha256"],
                  "SCOPE=Native DLL interoperability; offline queues; no OS networking",
                  "WIN98_IDENTIFIED=PASS", "CLIENT_PATH=C:\\GOPLAB\\M98TLS13.DLL",
                  "SERVER_PATH=C:\\GOPLAB\\M98TLS.DLL", "LOAD_BOTH_DLLS_AND_9_13_EXPORTS=PASS",
                  "FIXTURES_LOADED=PASS", "NATIVE_CRYPTOAPI_CSPRNG=PASS", "UNIX_TIME=1790856000",
                  "NATIVE_UTC_VALID=PASS", "INDEPENDENT_SERVER_PSA_NATIVE_INIT=PASS",
                  "ENTROPY_ZERO_REJECTED=PASS", "ENTROPY_MINUS1_REJECTED=PASS", "ENTROPY_TWO_REJECTED=PASS",
                  "LATE_ENTROPY_FAILURE_DENIED=PASS", "PAIR_CREATE=PASS", "TLS13_HANDSHAKE_BOTH_DLLS=PASS",
                  "AUTHENTICATED_BIDIRECTIONAL_PAYLOAD=PASS", "BOUNDED_PARTIAL_IO_WANT_RETRIES=PASS",
                  "AUTHENTICATED_CLOSE_NOTIFY=PASS", "WRITE_AFTER_CLOSE_DENIED=PASS",
                  "WRONG_HOST_REJECTED_WITHOUT_PLAINTEXT=PASS", "UNTRUSTED_CA_REJECTED_WITHOUT_PLAINTEXT=PASS",
                  "LATEST_CLIENT_TAMPERED_CIPHERTEXT_NO_PLAINTEXT=PASS", "SERVER_RUNTIME_SHUTDOWN=PASS",
                  "CRYPTOAPI_PROVIDER_RELEASED=PASS", "SERVER_DLL_UNLOADED=PASS", "CLIENT_DLL_UNLOADED=PASS",
                  "CRYPTOAPI_DLL_UNLOADED=PASS", "CHECKS=24", "FAILURES=0", "FINAL=PASS", "REQUESTED_EXIT=0",
                  "POSITIVE_CLIENT_STATUS=0", "POSITIVE_SERVER_STATUS=0", "POSITIVE_CLIENT_ESTABLISHED=1",
                  "POSITIVE_CLIENT_BACKEND_ERROR=0", "POSITIVE_SERVER_BACKEND_ERROR=0",
                  "POSITIVE_CLIENT_VERIFY_FLAGS=0", "POSITIVE_SERVER_VERIFY_FLAGS=4294967295",
                  "POSITIVE_SERVER_VERSION=TLSv1.3", "CLIENT_CERTIFICATE_AUTHENTICATION=not-requested"]
        supervisor = ["scope=actual-win98-tls-owned-child-supervisor", "nonce=" + self.nonce,
                      "WIN98_IDENTIFIED=1", "os.major=4", "os.minor=10", "os.build-low=2222", "os.platform=1",
                      "child.path=C:\\GOPLAB\\TLSDLL.EXE", "child.stdout=C:\\GOPLAB\\TLSOUT.LOG",
                      "child.created=1", "child.create-error=0", "child.pid=73", "child.wait=0",
                      "child.exit-query=1", "child.exit-query-error=0", "child.exit-code=0",
                      "child.stdout-flushed=1", "child.handles-closed=1", "child.success=1",
                      "supervisor.requested-exit-code=0"]
        self.run = {"profile": "actual-win98-uefi-csmwrap", "status": "NEEDS-VISUAL-REVIEW",
                    "originals_unchanged": True, "qemu_exit_code": 0, "guest_status": {"running": True},
                    "hardware": {"network": "none"}, "guest_files": {
                        "manifest": str(self.manifest_path), "manifest_sha256": self.manifest_sha,
                        "immutable_sources_unchanged": True, "output_baseline": "all absent before private injection",
                        "immutable_sources": dict({str(self.manifest_path): self.manifest_sha,
                                                    str(self.build_path): build_sha},
                                                  **{item["source"]: item["sha256"] for item in self.inputs}),
                        "inputs": [dict(item, private_copy_sha256=item["sha256"]) for item in self.inputs],
                        "outputs": self.manifest["outputs"], "readback": []}}
        harness_source = self.run_dir / "runner-source.py"
        harness_source.write_bytes(b"SYNTHETIC-PARSER-HARNESS-FIXTURE")
        self.run.update(source_snapshot=str(harness_source), source_sha256=self.sha(harness_source.read_bytes()))
        for name, lines in (("TLSDLL.LOG", native), ("T13RUN.LOG", supervisor), ("TLSOUT.LOG", [])):
            raw = (("\r\n".join(lines) + "\r\n").encode() if lines else b"")
            path = self.run_dir / ("guest-output-" + name)
            path.write_bytes(raw)
            self.run["guest_files"]["readback"].append({"guest": E.PREFIX + name, "status": "captured",
                "freshness": "new-in-owned-run", "path": str(path), "bytes": len(raw), "sha256": self.sha(raw)})
        self.run_path = self.run_dir / "result.json"

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    def write_json(self, path, data):
        raw = (json.dumps(data, indent=2) + "\n").encode()
        path.write_bytes(raw)
        return self.sha(raw)

    def invoke(self):
        run_sha = self.write_json(self.run_path, self.run)
        return E.verify(self.run_path, run_sha, self.manifest_path, self.manifest_sha, self.sources)

    def rewrite_log(self, name, change):
        entry = next(item for item in self.run["guest_files"]["readback"] if item["guest"] == E.PREFIX + name)
        path = Path(entry["path"])
        raw = change(path.read_bytes())
        path.write_bytes(raw)
        entry.update(bytes=len(raw), sha256=self.sha(raw))

    def assert_rejected(self):
        with self.assertRaises((E.EvidenceError, OSError)):
            self.invoke()

    def rebind_fixture_build(self):
        # Only used to test contradictory, caller-frozen build metadata. Real
        # runs must keep their independently approved staging hashes frozen.
        build_sha = self.write_json(self.build_path, self.build)
        self.manifest["source_receipts"][0]["sha256"] = build_sha
        self.manifest_sha = self.write_json(self.manifest_path, self.manifest)
        self.run["guest_files"]["manifest_sha256"] = self.manifest_sha
        self.run["guest_files"]["immutable_sources"].update({str(self.manifest_path): self.manifest_sha,
                                                          str(self.build_path): build_sha})

    def test_complete_fixture_keeps_os_and_app_claims_false(self):
        verdict = self.invoke()
        self.assertEqual(verdict["native_checks"], 24)
        self.assertEqual(verdict["actual_owned_child_exit_code"], 0)
        for key in ("system_tls_verified", "network_transport_verified", "application_functionality_verified",
                    "actual_supervisor_exit_verified"):
            self.assertIs(verdict[key], False)

    def test_requested_success_does_not_override_actual_child_failure(self):
        self.rewrite_log("T13RUN.LOG", lambda raw: raw.replace(b"child.exit-code=0", b"child.exit-code=4294967295"))
        self.assert_rejected()

    def test_wait_timeout(self):
        self.rewrite_log("T13RUN.LOG", lambda raw: raw.replace(b"child.wait=0", b"child.wait=258"))
        self.assert_rejected()

    def test_missing_exit_query(self):
        self.rewrite_log("T13RUN.LOG", lambda raw: raw.replace(b"child.exit-query=1\r\n", b""))
        self.assert_rejected()

    def test_child_log_pass_cannot_hide_parent_cleanup_failure(self):
        self.rewrite_log("T13RUN.LOG", lambda raw: raw.replace(b"child.handles-closed=1", b"child.handles-closed=0"))
        self.assert_rejected()

    def test_wrong_win98_build(self):
        self.rewrite_log("T13RUN.LOG", lambda raw: raw.replace(b"os.build-low=2222", b"os.build-low=1998"))
        self.assert_rejected()

    def test_wrong_nonce(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(self.nonce.encode(), b"prior-owned-run"))
        self.assert_rejected()

    def test_wrong_client_digest(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(self.by_name["M98TLS13.DLL"]["sha256"].encode(), b"0" * 64))
        self.assert_rejected()

    def test_duplicate_pass_cannot_override_fail(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw + b"TLS13_HANDSHAKE_BOTH_DLLS=FAIL\r\n")
        self.assert_rejected()

    def test_missing_native_crypto_check(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(b"NATIVE_CRYPTOAPI_CSPRNG=PASS\r\n", b""))
        self.assert_rejected()

    def test_missing_teardown_check(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(b"SERVER_DLL_UNLOADED=PASS\r\n", b""))
        self.assert_rejected()

    def test_failed_tamper_rejection(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(b"LATEST_CLIENT_TAMPERED_CIPHERTEXT_NO_PLAINTEXT=PASS",
                                                              b"LATEST_CLIENT_TAMPERED_CIPHERTEXT_NO_PLAINTEXT=FAIL"))
        self.assert_rejected()

    def test_incomplete_last_log_line(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw[:-1])
        self.assert_rejected()

    def test_failed_utc(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(b"UNIX_TIME=1790856000", b"UNIX_TIME=-1"))
        self.assert_rejected()

    def test_inherited_guest_output(self):
        self.run["guest_files"]["readback"][0]["freshness"] = "inherited-unchanged"
        self.assert_rejected()

    def test_missing_guest_output(self):
        self.run["guest_files"]["readback"].pop()
        self.assert_rejected()

    def test_diagnostic_vm_failure(self):
        self.run["status"] = "FAIL"
        self.assert_rejected()

    def test_changed_original_disk(self):
        self.run["originals_unchanged"] = False
        self.assert_rejected()

    def test_changed_prepared_source(self):
        self.run.update(prepared_reuse={"source_run": "fixture"}, prepared_source_unchanged=False)
        self.assert_rejected()

    def test_changed_frozen_sources(self):
        (self.sources / "tests/m98_tls13_guest_interop.c").write_bytes(b"CHANGED")
        self.assert_rejected()

    def test_changed_captured_harness(self):
        (self.run_dir / "runner-source.py").write_bytes(b"CHANGED")
        self.assert_rejected()

    def test_changed_staged_dll(self):
        (self.stage / "M98TLS13.DLL").write_bytes(b"CHANGED")
        self.assert_rejected()

    def test_changed_guest_copy(self):
        self.run["guest_files"]["inputs"][0]["private_copy_sha256"] = "0" * 64
        self.assert_rejected()

    def test_harness_source_scope_omits_an_input(self):
        self.run["guest_files"]["immutable_sources"].pop(self.inputs[0]["source"])
        self.assert_rejected()

    def test_changed_client_build_receipt(self):
        path = self.stage / "client-build.json"
        path.write_bytes(path.read_bytes().replace(b"4.2.0", b"3.6.7"))
        self.assert_rejected()

    def test_equal_export_count_with_wrong_names(self):
        self.build["client_gate"]["exports"][0] = "unrelated_api"
        self.rebind_fixture_build()
        self.assert_rejected()

    def test_duplicate_export_name(self):
        self.build["server_gate"]["exports"][0] = self.build["server_gate"]["exports"][1]
        self.rebind_fixture_build()
        self.assert_rejected()

    def test_probe_commit_below_unprobed_frame_bound(self):
        self.build["probe_gate"]["stack_commit"] = 4096
        self.rebind_fixture_build()
        self.assert_rejected()

    def test_runner_reserve_smaller_than_commit(self):
        self.build["runner_gate"]["stack_reserve"] = 32768
        self.rebind_fixture_build()
        self.assert_rejected()

    def test_output_hash_mismatch(self):
        (self.run_dir / "guest-output-TLSDLL.LOG").write_bytes(b"CHANGED")
        self.assert_rejected()

    def test_output_symlink(self):
        path = self.run_dir / "guest-output-TLSDLL.LOG"
        other = self.root / "outside-log"
        path.rename(other)
        path.symlink_to(other)
        self.assert_rejected()

    def test_output_escape(self):
        entry = self.run["guest_files"]["readback"][0]
        path = Path(entry["path"])
        other = self.root / path.name
        path.rename(other)
        entry["path"] = str(other)
        self.assert_rejected()

    def test_unexpected_child_stdout(self):
        self.rewrite_log("TLSOUT.LOG", lambda raw: b"unexpected failure\r\n")
        self.assert_rejected()

    def test_no_client_certificate_server_zero_flags(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(
            b"POSITIVE_SERVER_VERIFY_FLAGS=4294967295", b"POSITIVE_SERVER_VERIFY_FLAGS=0"))
        self.invoke()

    def test_no_client_certificate_server_skip_verify_flags(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(
            b"POSITIVE_SERVER_VERIFY_FLAGS=4294967295", b"POSITIVE_SERVER_VERIFY_FLAGS=128"))
        result = self.invoke()
        self.assertEqual(result["server_reported_peer_verify_flags"], 128)
        self.assertFalse(result["client_certificate_authentication_verified"])

    def test_server_verification_flags_must_be_uint32(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(
            b"POSITIVE_SERVER_VERIFY_FLAGS=4294967295", b"POSITIVE_SERVER_VERIFY_FLAGS=4294967296"))
        self.assert_rejected()

    def test_positive_diagnostics_cannot_hide_failed_authentication(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(
            b"POSITIVE_CLIENT_VERIFY_FLAGS=0", b"POSITIVE_CLIENT_VERIFY_FLAGS=4"))
        self.assert_rejected()

    def test_positive_diagnostics_cannot_hide_failed_server(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(
            b"POSITIVE_SERVER_STATUS=0", b"POSITIVE_SERVER_STATUS=-3"))
        self.assert_rejected()

    def test_positive_diagnostics_cannot_hide_wrong_protocol(self):
        self.rewrite_log("TLSDLL.LOG", lambda raw: raw.replace(
            b"POSITIVE_SERVER_VERSION=TLSv1.3", b"POSITIVE_SERVER_VERSION=TLSv1.2"))
        self.assert_rejected()

    def test_duplicate_json_key(self):
        data = self.manifest_path.read_bytes().replace(b'"schema": 1,', b'"schema": 1, "schema": 1,')
        self.manifest_path.write_bytes(data)
        self.manifest_sha = self.sha(data)
        self.assert_rejected()

    def test_rejects_enabled_guest_network(self):
        self.run["hardware"]["network"] = "user-mode"
        self.assert_rejected()

    def test_stale_caller_result_digest(self):
        run_sha = self.write_json(self.run_path, self.run)
        self.run["status"] = "FAIL"
        self.write_json(self.run_path, self.run)
        with self.assertRaises(E.EvidenceError):
            E.verify(self.run_path, run_sha, self.manifest_path, self.manifest_sha, self.sources)


if __name__ == "__main__":
    unittest.main()
