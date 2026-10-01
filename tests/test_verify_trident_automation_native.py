# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic fault controls, never native/DOM/input/paint acceptance evidence."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("automation_evidence", ROOT / "tools/verify_trident_automation_native.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def log(fields, events=0):
    return ("".join(f"{k}={v}\r\n" for k, v in fields.items()) +
            "EVENT_EXECUTED_OUTSIDE_COM=PASS\r\n" * events).encode("ascii")


class AutomationEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="automation-evidence-SYNTHETIC-")
        self.root = Path(self.temp.name)
        self.stage = self.root / "stage"
        self.run = self.root / "synthetic-owned-run"
        self.stage.mkdir(); self.run.mkdir()
        self.run_path = self.run / "result.json"
        self.manifest_path = self.stage / "manifest.json"
        self.review_path = self.root / "synthetic-trusted-review.json"
        runner = self.run / "runner-source.py"
        runner.write_bytes(b"Synthetic unit fixture; not executable or native evidence.\n")
        self.harness_sha = digest(runner)
        all_sources = M.AUTOMATION_SOURCES | M.OBSERVER_SOURCES | M.RUNTIME_SOURCES
        source_hashes = {}
        for name in sorted(all_sources):
            path = self.stage / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("SYNTHETIC frozen project source: " + name).encode())
            source_hashes[name] = digest(path)
        prepared = {}
        for name in ("quickjs/quickjs.c", "math/src/math/log2.c"):
            path = self.stage / "runtime-prepared" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("SYNTHETIC interpreter dependency: " + name).encode())
            prepared["/not-read/original-build/prepared/" + name] = digest(path)
        inputs = []
        gates = {}
        for name in sorted(M.INPUTS):
            path = self.stage / name
            path.write_bytes(("SYNTHETIC input, NOT A PE: " + name).encode())
            (self.run / ("prepared-guest-" + name)).write_bytes(path.read_bytes())
            row = {"source": str(path), "guest": M.PREFIX + name, "bytes": path.stat().st_size, "sha256": digest(path)}
            inputs.append(row)
            gates[name] = {"sha256": row["sha256"], "size": row["bytes"], "pe98_gate": "pass",
                           "stack_reserve": 2097152, "stack_commit": 524288}
        gates["M98AUTPR.EXE"]["adapter"] = "statically embedded"
        gates["M98AURUN.EXE"]["i486_instruction_gate"] = "pass"
        gates["M98QJS.DLL"]["exports"] = sorted(M.RUNTIME_EXPORTS)
        gates["M98QJS.DLL"]["i486_instructions"] = {"instructions_decoded": 100, "post_i486_families": "absent"}
        self.builds = {
            "automation-build.json": {"schema": 1, "kind": "genuine-mshtml-automation-component-build", "passed": True,
                "source_sha256": {n: source_hashes[n] for n in sorted(M.AUTOMATION_SOURCES)},
                "artifacts": {"M98AUTPR.EXE": gates["M98AUTPR.EXE"]}},
            "runtime-build.json": {"profile": "bounded-local-trident-quickjs-v1", "passed": True,
                "source_sha256": {n: source_hashes[n] for n in sorted(M.RUNTIME_SOURCES)},
                "prepared_sha256": prepared, "artifacts": {"M98QJS.DLL": gates["M98QJS.DLL"]}},
            "observer-build.json": {"schema": 1, "kind": "win98-trident-owned-child-observer-build", "passed": True,
                "nonce": "synthetic-trial-v1", "source_sha256": {n: source_hashes[n] for n in sorted(M.OBSERVER_SOURCES)},
                "artifacts": {"M98AURUN.EXE": gates["M98AURUN.EXE"]},
                "profiles": {"automation": {"self": M.PREFIX + "M98AURUN.EXE", "supervisor_log": M.PREFIX + "AURUN.LOG",
                    "child_stdout": M.PREFIX + "AUOUT.LOG", "child": M.PREFIX + "M98AUTPR.EXE",
                    "child_log": M.PREFIX + "AUT13.LOG", "child_timeout_ms": 240000, "reap_timeout_ms": 5000}}}}
        selected = self.stage / "runtime-selected.h"
        selected.write_bytes(b"SYNTHETIC selected fixture header, not executable\n")
        self.builds["runtime-build.json"]["embedded_fixture_header_sha256"] = digest(selected)
        for name, build in self.builds.items():
            role = name.removesuffix("-build.json")
            basename = {"automation": "host-build.txt", "observer": "automation-host-test.txt",
                        "runtime": "host-run.log"}[role]
            path = self.stage / "build-logs" / role / basename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"SYNTHETIC test-build output, not native evidence\n")
            build["steps"] = [{"returncode": 0, "log": "/original-build/" + basename, "sha256": digest(path)}]
        self.manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "nonce": "synthetic-trial-v1",
            "command": M.PREFIX + "M98AURUN.EXE", "network_required": False, "inputs": inputs,
            "outputs": [M.PREFIX + n for n in sorted(M.OUTPUTS)], "source_receipts": []}
        self.component = dict(M.FIXED) | {k: "PASS" for k in sorted(M.CHECKS)} | {k: "00000000" for k in sorted(M.HRESULTS)} | {
            "MSHTML_MODULE": "C:\\WINDOWS\\SYSTEM\\MSHTML.DLL", "OBSERVED_UI_KEYUPS": "2", "EXECUTED_QUEUED_CALLBACKS": "2"}
        self.observer = {"scope": "actual-win98-trident-owned-child-observer", "nonce": "synthetic-trial-v1",
            "profile": "genuine-mshtml-direct-host", "WIN98_IDENTIFIED": "1", "os.major": "4", "os.minor": "10",
            "os.build-low": "2222", "os.platform": "1", "child.path": M.PREFIX + "M98AUTPR.EXE",
            "child.stdout": M.PREFIX + "AUOUT.LOG", "child.created": "1", "child.create-error": "0", "child.pid": "101",
            "child.wait": "0", "child.exit-query": "1", "child.exit-query-error": "0", "child.exit-code": "0",
            "child.stdout-flushed": "1", "child.handles-closed": "1", "child.success": "1", "supervisor.requested-exit-code": "0"}
        self.payloads = {"AUT13.LOG": log(self.component, 2), "AURUN.LOG": log(self.observer), "AUOUT.LOG": b""}
        self.result = {"profile": "actual-win98-uefi-csmwrap", "status": "NEEDS-VISUAL-REVIEW",
            "originals_unchanged": True, "prepared_source_unchanged": True, "qemu_exit_code": 0, "manual_finish_requested": True,
            "source_snapshot": str(runner), "source_sha256": self.harness_sha,
            "hardware": {"run_name": self.run.name, "network": "none", "reserve_gib": 20, "accel": "kvm",
                         "memory": 128, "smp": 2, "manual_gui": True, "firmware_gop": True},
            "firmware_gop_opt_in": True,
            "prepared_reuse": {"method": "verified private sparse post-run disk copy; cold hardware; synthetic unit fixture"},
            "guest_files": {"manifest": str(self.manifest_path), "immutable_sources_unchanged": True,
                "output_baseline": "all absent before private injection",
                "inputs": [r | {"private_copy_sha256": r["sha256"]} for r in inputs], "readback": []},
            "gui_interaction": {"actions": [{"sequence": 1, "name": "synthetic-type-input", "seconds": 20.0,
                "typed": "Ab12", "keys": [], "status": "sent; application effect requires screenshot/readback verification"}]},
            "captures": []}
        for name, data in self.payloads.items():
            path = self.run / ("guest-output-" + name)
            path.write_bytes(data)
            self.result["guest_files"]["readback"].append({"guest": M.PREFIX + name, "path": str(path), "status": "captured",
                "freshness": "new-in-owned-run", "bytes": len(data), "sha256": digest(path)})
        self.review = {"schema": "win98modern.trident-automation-input-visual-review.v1", "input_action_sequence": 1,
            "reviewed_typed_input": "Ab12", "genuine_mshtml_paint_verified": True, "qemu_gui_input_verified": True,
            "standard_browser_integration_verified": False, "full_web_standards_verified": False, "modern_apps_verified": False,
            "manual_review": "SYNTHETIC trusted-review unit fixture; no actual input or pixels reviewed.", "frames": {}}
        for role, seconds in (("focused_input", 10.0), ("korean_after_input", 30.0)):
            path = self.run / (role + ".png")
            path.write_bytes(("SYNTHETIC capture NOT AN IMAGE: " + role).encode())
            row = {"screenshot": str(path), "sha256": digest(path), "screenshot_status": "captured", "seconds": seconds}
            self.result["captures"].append(row)
            self.review["frames"][role] = {"path": str(path), "sha256": row["sha256"], "seconds": seconds,
                "visual_review": "SYNTHETIC manually trusted review control; not native evidence."}
        self.sync_builds()

    def tearDown(self):
        self.temp.cleanup()

    def sync_builds(self):
        self.build_pins = {}
        self.manifest["source_receipts"] = []
        for name, build in self.builds.items():
            path = self.stage / name
            write(path, build)
            self.build_pins[name] = digest(path)
            self.manifest["source_receipts"].append({"path": str(path), "sha256": digest(path)})
        self.sync()

    def sync(self):
        write(self.manifest_path, self.manifest)
        self.manifest_sha = digest(self.manifest_path)
        files = self.result["guest_files"]
        files["manifest_sha256"] = self.manifest_sha
        files["outputs"] = self.manifest["outputs"].copy()
        files["immutable_sources"] = {str(self.manifest_path): self.manifest_sha} | {
            r["source"]: r["sha256"] for r in self.manifest["inputs"]} | {
            r["path"]: r["sha256"] for r in self.manifest["source_receipts"]}
        self.write_run()

    def write_run(self):
        write(self.run_path, self.result)
        self.run_sha = digest(self.run_path)
        self.review["harness_result_sha256"] = self.run_sha
        self.review["manifest_sha256"] = self.manifest_sha
        self.review["input_sha256"] = {Path(r["source"]).name: r["sha256"] for r in self.manifest["inputs"]}
        actions = self.result.get("gui_interaction", {}).get("actions")
        self.review["gui_actions_sha256"] = M.sha(json.dumps(actions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        self.write_review()

    def write_review(self):
        write(self.review_path, self.review)
        self.review_sha = digest(self.review_path)

    def verify(self, review=False):
        return M.verify(self.run_path, self.run_sha, self.manifest_path, self.manifest_sha, self.harness_sha,
                        self.build_pins, self.review_path if review else None, self.review_sha if review else None)

    def change_log(self, name, data):
        row = next(r for r in self.result["guest_files"]["readback"] if r["guest"] == M.PREFIX + name)
        path = Path(row["path"])
        path.write_bytes(data)
        row["bytes"] = len(data); row["sha256"] = digest(path)
        self.write_run()

    def reject(self, review=False, message=None):
        context = self.assertRaisesRegex(M.EvidenceError, message) if message else self.assertRaises((M.EvidenceError, OSError))
        with context:
            self.verify(review)

    def test_nominal_component_keeps_input_paint_and_web_pending(self):
        report = self.verify()
        self.assertTrue(report["passed"])
        self.assertEqual(report["actual_owned_child"], {"pid": 101, "exit_code": 0, "stdout_flushed": True, "handles_closed": True})
        for key in ("actual_supervisor_exit_verified", "real_gui_input_verified", "genuine_mshtml_paint_verified",
                    "visual_content_automatically_asserted", "standard_browser_navigation_verified", "full_html5_verified",
                    "webassembly_verified", "es2026_conformance_verified", "modern_css_verified", "webgpu_verified",
                    "webgl_verified", "modern_apps_verified"):
            self.assertFalse(report[key], key)
        self.assertEqual(report["native_observations"]["queued_callbacks"], 2)
        self.assertEqual(report["log_sha256"]["AUOUT.LOG"], M.sha(b""))

    def test_trusted_manual_control_sets_only_input_and_paint(self):
        report = self.verify(True)
        self.assertTrue(report["real_gui_input_verified"])
        self.assertTrue(report["genuine_mshtml_paint_verified"])
        self.assertFalse(report["visual_content_automatically_asserted"])
        self.assertFalse(report["standard_browser_navigation_verified"])

    def test_every_hresult_failure_and_missing_field_rejected(self):
        for key in sorted(M.HRESULTS):
            with self.subTest(key=key):
                fields = self.component | {key: "80004005"}
                self.change_log("AUT13.LOG", log(fields, 2)); self.reject(message="HRESULT failure")
                del fields[key]
                self.change_log("AUT13.LOG", log(fields, 2)); self.reject(message="stale/partial")

    def test_every_component_check_is_required(self):
        for key in sorted(M.CHECKS):
            with self.subTest(key=key):
                self.change_log("AUT13.LOG", log(self.component | {key: "FAIL"}, 2)); self.reject()

    def test_failed_status_count_os_module_or_extra_diagnostics(self):
        for key, value in (("STATUS", "PASS"), ("FAILURES", "1"), ("ACP", "1252"), ("OS_BUILD_LOW", "1998"),
                           ("MSHTML_MODULE", "C:\\GOPLAB\\MSHTML.DLL"), ("SCRIPT_STATUS", "00000000"),
                           ("OBSERVED_UI_KEYUPS", "0"), ("EXECUTED_QUEUED_CALLBACKS", "4294967296")):
            with self.subTest(key=key):
                self.change_log("AUT13.LOG", log(self.component | {key: value}, 2)); self.reject()

    def test_event_count_must_match_all_callbacks(self):
        for events in (0, 1, 3):
            self.change_log("AUT13.LOG", log(self.component, events)); self.reject(message="callback evidence")

    def test_partial_empty_crlf_duplicate_and_nonascii_component_logs(self):
        data = self.payloads["AUT13.LOG"]
        for invalid in (b"", data[:-2], data.replace(b"\r\n", b"\n"), data + b"FAILURES=0\r\n", data + b"X=\xff\r\n"):
            self.change_log("AUT13.LOG", invalid); self.reject()

    def test_all_owned_child_completion_conditions_required(self):
        for key, value in (("child.created", "0"), ("child.create-error", "5"), ("child.wait", "258"),
                           ("child.exit-query", "0"), ("child.exit-query-error", "5"), ("child.exit-code", "259"),
                           ("child.stdout-flushed", "0"), ("child.handles-closed", "0"), ("child.success", "0"),
                           ("supervisor.requested-exit-code", "5"), ("child.pid", "0"), ("child.pid", "true"),
                           ("child.pid", "4294967296"), ("nonce", "previous-trial"), ("child.path", M.PREFIX + "OTHER.EXE")):
            with self.subTest(key=key, value=value):
                self.change_log("AURUN.LOG", log(self.observer | {key: value})); self.reject()

    def test_partial_and_duplicate_observer_log(self):
        fields = self.observer.copy(); del fields["child.handles-closed"]
        self.change_log("AURUN.LOG", log(fields)); self.reject()
        self.change_log("AURUN.LOG", self.payloads["AURUN.LOG"] + b"child.exit-code=0\r\n"); self.reject()

    def test_gui_stdout_diagnostics_rejected(self):
        self.change_log("AUOUT.LOG", b"unexpected failure message\r\n"); self.reject(message="stdout diagnostics")

    def test_stale_missing_and_changed_readback(self):
        rows = self.result["guest_files"]["readback"]
        rows[0]["freshness"] = "inherited"; self.write_run(); self.reject()
        rows[0]["freshness"] = "new-in-owned-run"; rows[0]["sha256"] = "0" * 64; self.write_run(); self.reject()
        rows.pop(); self.write_run(); self.reject()

    def test_readback_bool_size_and_wrong_owned_path(self):
        row = self.result["guest_files"]["readback"][0]
        row["bytes"] = True; self.write_run(); self.reject()
        row["bytes"] = len(self.payloads["AUT13.LOG"]); row["path"] = str(self.root / "guest-output-AUT13.LOG")
        self.write_run(); self.reject(message="escapes")

    def test_changed_frozen_input_private_copy_or_harness(self):
        for path in (self.stage / "M98AUTPR.EXE", self.run / "prepared-guest-M98QJS.DLL", self.run / "runner-source.py"):
            original = path.read_bytes(); path.write_bytes(original + b"changed")
            self.reject(); path.write_bytes(original)

    def test_changed_project_and_prepared_sources(self):
        for path in (self.stage / "source/src/m98_trident_automation.cpp", self.stage / "runtime-prepared/quickjs/quickjs.c"):
            original = path.read_bytes(); path.write_bytes(original + b"changed")
            self.reject(message="source.*changed"); path.write_bytes(original)

    def test_successful_build_log_hashes_are_required(self):
        path = self.stage / "build-logs/observer/automation-host-test.txt"
        original = path.read_bytes(); path.write_bytes(original + b"changed")
        self.reject(message="build-step log changed"); path.write_bytes(original)
        self.builds["observer-build.json"]["steps"][0]["returncode"] = False
        self.sync_builds(); self.reject(message="unchecked step")

    def test_real_disassembly_size_regression_and_explicit_log_bound(self):
        # Actual provisional runtime v7 log was 7,485,493 bytes: a default
        # 4 MiB reader incorrectly rejects its frozen build provenance.
        path = self.stage / "build-logs/runtime/native-disassembly.log"
        with path.open("wb") as stream:
            stream.write(b"SYNTHETIC sparse log, never an actual disassembly verdict\n")
            stream.truncate(7485493)
        step = {"returncode": 0, "log": "/original-build/native-disassembly.log", "sha256": digest(path)}
        self.builds["runtime-build.json"]["steps"].append(step)
        self.sync_builds()
        self.assertTrue(self.verify()["passed"])
        with path.open("ab") as stream:
            stream.truncate((8 << 20) + 1)
        step["sha256"] = digest(path)
        self.sync_builds(); self.reject(message="unbounded")

    def test_generated_runtime_fixture_header_is_frozen(self):
        path = self.stage / "runtime-selected.h"
        path.write_bytes(b"changed"); self.reject(message="selected fixture header changed")

    def test_ambiguous_missing_build_logs_are_rejected(self):
        steps = self.builds["runtime-build.json"]["steps"]
        steps.append(steps[0].copy()); self.sync_builds(); self.reject(message="ambiguous")
        self.builds["runtime-build.json"]["steps"] = []; self.sync_builds(); self.reject(message="missing/unbounded")

    def test_build_failed_wrong_profile_or_source_set(self):
        original = copy.deepcopy(self.builds)
        for role, key, value in (("automation-build.json", "passed", False), ("observer-build.json", "schema", True),
                                 ("runtime-build.json", "profile", "another-engine"), ("observer-build.json", "nonce", "old-trial")):
            self.builds = copy.deepcopy(original); self.builds[role][key] = value; self.sync_builds(); self.reject()
        self.builds = copy.deepcopy(original)
        del self.builds["runtime-build.json"]["source_sha256"]["src/m98_trident_script.c"]
        self.sync_builds(); self.reject(message="source profile")

    def test_conflicting_header_generations(self):
        self.builds["runtime-build.json"]["source_sha256"]["src/m98_trident_script.h"] = "0" * 64
        self.sync_builds(); self.reject(message="conflicting source")

    def test_prepared_paths_never_read_original_or_escape_stage(self):
        original = self.builds["runtime-build.json"]["prepared_sha256"]
        digest_value = next(iter(original.values()))
        for key in ("/outside/no-prepared.c", "/outside/prepared/../secret", "/outside/prepared/quickjs//quickjs.c"):
            self.builds["runtime-build.json"]["prepared_sha256"] = {key: digest_value}
            self.sync_builds(); self.reject()
        self.builds["runtime-build.json"]["prepared_sha256"] = {k.replace("/not-read", "/different" if "math" in k else "/not-read"): v for k, v in original.items()}
        self.sync_builds(); self.reject(message="coherent")

    def test_abi_exports_and_native_gates(self):
        original = copy.deepcopy(self.builds)
        for role, name, key, value in (("runtime-build.json", "M98QJS.DLL", "exports", sorted(M.RUNTIME_EXPORTS - {"m98_script_invoke_this"})),
                                     ("runtime-build.json", "M98QJS.DLL", "stack_commit", 4096),
                                     ("runtime-build.json", "M98QJS.DLL", "i486_instructions", False),
                                     ("runtime-build.json", "M98QJS.DLL", "i486_instructions", {"instructions_decoded": 1048577, "post_i486_families": "absent"}),
                                     ("runtime-build.json", "M98QJS.DLL", "i486_instructions", {"instructions_decoded": True, "post_i486_families": "absent"}),
                                     ("runtime-build.json", "M98QJS.DLL", "i486_instructions", {"instructions_decoded": 100, "post_i486_families": "present"}),
                                     ("automation-build.json", "M98AUTPR.EXE", "pe98_gate", "unchecked"),
                                     ("automation-build.json", "M98AUTPR.EXE", "adapter", "DOM double"),
                                     ("observer-build.json", "M98AURUN.EXE", "i486_instruction_gate", "unchecked"),
                                     ("observer-build.json", "M98AURUN.EXE", "size", True)):
            self.builds = copy.deepcopy(original); self.builds[role]["artifacts"][name][key] = value
            self.sync_builds(); self.reject()

    def test_runtime_instruction_dictionary_requires_complete_exact_real_shape(self):
        valid = {"instructions_decoded": 225883, "post_i486_families": "absent"}
        self.assertEqual(M.runtime_instructions({"i486_instructions": valid}), 225883)
        for gate in ({"instructions_decoded": 225883}, {"post_i486_families": "absent"},
                     valid | {"unchecked": True}, valid | {"instructions_decoded": True},
                     valid | {"post_i486_families": False}, valid | {"post_i486_families": "present"}):
            with self.subTest(gate=gate), self.assertRaisesRegex(M.EvidenceError, "instruction gate"):
                M.runtime_instructions({"i486_instructions": gate})

    def test_observer_paths_and_timeout_profile(self):
        profile = self.builds["observer-build.json"]["profiles"]["automation"]
        profile["child_timeout_ms"] = 180000; self.sync_builds(); self.reject(message="deadline")
        profile["child_timeout_ms"] = 240000; profile["child_log"] = M.PREFIX + "OLD.LOG"
        self.sync_builds(); self.reject(message="deadline")

    def test_unapproved_build_receipt_and_mutated_manifest(self):
        path = self.stage / "automation-build.json"
        path.write_bytes(path.read_bytes() + b" "); self.reject(message="receipt changed")
        self.sync_builds()
        self.manifest_path.write_bytes(self.manifest_path.read_bytes() + b" "); self.reject(message="receipt changed")

    def test_harness_error_even_with_success_status(self):
        for field in ("error", "runtime_failure"):
            self.result[field] = "collector failed"; self.write_run(); self.reject(message="harness failed")
            del self.result[field]

    def test_hardware_requires_exact_integer_offline_profile(self):
        original = self.result["hardware"].copy()
        for key, value in (("memory", 128.0), ("smp", 2.0), ("network", "user"), ("reserve_gib", 20.0), ("firmware_gop", False)):
            self.result["hardware"] = original | {key: value}; self.write_run(); self.reject(message="hardware profile")

    def test_unstopped_bool_exit_and_original_mutation(self):
        for key, value in (("qemu_exit_code", False), ("qemu_exit_code", 1), ("manual_finish_requested", False),
                           ("originals_unchanged", False), ("prepared_source_unchanged", False)):
            original = self.result[key]; self.result[key] = value; self.write_run(); self.reject(); self.result[key] = original

    def test_immutable_full_set_and_output_plan(self):
        files = self.result["guest_files"]
        files["immutable_sources"].pop(str(self.stage / "runtime-build.json")); self.write_run(); self.reject(message="immutable")
        self.sync()
        files["outputs"].append(M.PREFIX + "OTHER.LOG"); self.write_run(); self.reject(message="immutable")

    def test_manifest_schema_nonce_command_and_network(self):
        original = copy.deepcopy(self.manifest)
        for key, value in (("schema", True), ("kind", "another-kind"), ("nonce", ""), ("nonce", "x" * 97),
                           ("command", M.PREFIX + "M98AUTPR.EXE"), ("network_required", True)):
            self.manifest = original | {key: value}; self.sync(); self.reject()

    def test_symlink_evidence_rejected(self):
        path = self.run / "guest-output-AUT13.LOG"
        original = path.read_bytes(); path.unlink()
        target = self.root / "actual-copy.log"; target.write_bytes(original)
        path.symlink_to(target); self.reject(message="symlink")

    def test_source_escape_extra_or_duplicate_receipt_rejected(self):
        self.manifest["source_receipts"].append(self.manifest["source_receipts"][0].copy()); self.sync(); self.reject()
        self.sync_builds()
        self.builds["runtime-build.json"]["source_sha256"]["../outside"] = "0" * 64
        self.sync_builds(); self.reject()

    def test_json_duplicate_key_rejected_even_when_caller_pins_bytes(self):
        raw = self.run_path.read_text().replace('"profile":', '"profile": "other", "profile":', 1)
        self.run_path.write_text(raw); self.run_sha = digest(self.run_path)
        self.reject(message="duplicate JSON")

    def test_no_review_is_required_for_component_but_half_review_fails(self):
        with self.assertRaisesRegex(M.EvidenceError, "supplied together"):
            M.verify(self.run_path, self.run_sha, self.manifest_path, self.manifest_sha, self.harness_sha,
                     self.build_pins, self.review_path)

    def test_hashes_or_sent_input_alone_do_not_prove_visual_effect(self):
        for key in ("genuine_mshtml_paint_verified", "qemu_gui_input_verified"):
            self.review[key] = False; self.write_review(); self.reject(True, "trusted observed")
            self.review[key] = True
        self.review["manual_review"] = ""; self.write_review(); self.reject(True, "description")

    def test_review_wrong_run_manifest_binary_or_action_hash(self):
        original = copy.deepcopy(self.review)
        for key in ("harness_result_sha256", "manifest_sha256", "input_sha256", "gui_actions_sha256"):
            self.review = original | {key: "0" * 64}; self.write_review(); self.reject(True)

    def test_review_cannot_claim_web_or_apps(self):
        for key in ("standard_browser_integration_verified", "full_web_standards_verified", "modern_apps_verified",
                    "modern_css_verified", "webgpu_verified", "webgl_verified"):
            self.review[key] = True; self.write_review(); self.reject(True, "exceeds")
            self.review[key] = False

    def test_missing_typed_input_unsupported_action_status_and_wrong_input(self):
        action = self.result["gui_interaction"]["actions"][0]
        original = action.copy()
        for key, value in (("typed", ""), ("typed", "한글"), ("status", "applied"), ("sequence", True)):
            self.result["gui_interaction"]["actions"] = [original | {key: value}]; self.write_run(); self.reject(True)
        self.result["gui_interaction"]["actions"] = [original]; self.write_run()
        self.review["reviewed_typed_input"] = "Different"; self.write_review(); self.reject(True, "different sent input")

    def test_duplicate_out_of_order_missing_or_unbounded_actions(self):
        action = self.result["gui_interaction"]["actions"][0].copy()
        for actions in ([], [action, action], [action | {"sequence": 2}, action], [action | {"sequence": 129}],
                        [action, action | {"sequence": 3}]):
            self.result["gui_interaction"]["actions"] = actions; self.write_run(); self.reject(True)

    def test_reviewed_captures_must_be_actual_distinct_intact_and_bracket_input(self):
        path = self.run / "korean_after_input.png"; original = path.read_bytes()
        path.write_bytes(original + b"changed"); self.reject(True, "frame changed"); path.write_bytes(original)
        frames = copy.deepcopy(self.review["frames"])
        self.review["frames"]["korean_after_input"] = self.review["frames"]["focused_input"].copy()
        self.write_review(); self.reject(True, "identical")
        self.review["frames"] = frames
        self.result["gui_interaction"]["actions"][0]["seconds"] = 31.0; self.write_run(); self.reject(True, "bracket")

    def test_unconfirmed_capture_and_missing_review_description(self):
        self.result["captures"][0]["screenshot_status"] = "unknown"; self.write_run(); self.reject(True, "actual harness capture")
        self.result["captures"][0]["screenshot_status"] = "captured"; self.write_run()
        self.review["frames"]["focused_input"]["visual_review"] = " "; self.write_review(); self.reject(True, "painted-content")

    def test_review_hash_itself_required(self):
        self.review_path.write_bytes(self.review_path.read_bytes() + b" "); self.reject(True, "receipt changed")

    def test_cli_missing_actual_run_returns_failure_without_false_claims(self):
        argv = [sys.executable, str(ROOT / "tools/verify_trident_automation_native.py"),
            "--run-result", str(self.root / "missing-native-run.json"), "--run-result-sha256", "0" * 64,
            "--manifest", str(self.manifest_path), "--manifest-sha256", self.manifest_sha,
            "--harness-sha256", self.harness_sha]
        for role in ("automation", "runtime", "observer"):
            argv += [f"--{role}-build-sha256", self.build_pins[f"{role}-build.json"]]
        result = subprocess.run(argv, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["native_component_execution_verified"])


if __name__ == "__main__":
    unittest.main()
