# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic evidence fault controls; no VM or guest acceptance is performed."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("theme_native", ROOT / "tools/verify_theme_native.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")

class ThemeEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="theme-evidence-synthetic-")
        self.root = Path(self.temp.name)
        self.run = self.root / "owned-synthetic-run"
        self.stage = self.root / "frozen-stage"
        self.run.mkdir(); self.stage.mkdir()
        self.manifest_path = self.stage / "manifest.json"
        self.review_path = self.root / "trusted-synthetic-review.json"
        inputs = []
        for name in sorted(module.INPUTS):
            source = self.stage / name
            source.write_bytes(("synthetic frozen input " + name).encode())
            (self.run / ("prepared-guest-" + name)).write_bytes(source.read_bytes())
            inputs.append({"source": str(source), "guest": "C:\\GOPLAB\\" + name,
                           "bytes": source.stat().st_size, "sha256": digest(source)})
        source_receipts = []
        for name in sorted(module.SOURCE_RECEIPTS):
            path = self.stage / name
            write(path, {"synthetic_source_receipt": name})
            source_receipts.append({"path": str(path), "sha256": digest(path)})
        self.manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                         "outputs": ["C:\\GOPLAB\\" + n for n in sorted(module.OUTPUTS)],
                         "source_receipts": source_receipts, "nonce": "synthetic-test-only"}
        runner = self.run / "runner-source.py"
        runner.write_bytes(b"synthetic frozen runner fixture; not executable\n")
        self.runner_sha = digest(runner)
        run_log = "scope=actual-win98-theme-owned-child-supervisor\nnonce=synthetic-test-only\nWIN98_IDENTIFIED=1\nos.major=4\nos.minor=10\nos.build-low=2222\nos.platform=1\n"
        for name, log, pid in (("M98THPRO.EXE", "THPRO.LOG", 101), ("M98THSTA.EXE", "THSTA.LOG", 102)):
            fields = {"child.path": "C:\\GOPLAB\\" + name, "child.stdout": "C:\\GOPLAB\\" + log,
                      "child.created": 1, "child.create-error": 0, "child.pid": pid, "child.wait": 0,
                      "child.exit-query": 1, "child.exit-query-error": 0, "child.exit-code": 0,
                      "child.stdout-flushed": 1, "child.handles-closed": 1, "child.success": 1}
            run_log += "".join(f"{k}={v}\n" for k, v in fields.items())
        run_log += "supervisor.requested-exit-code=0\n"
        payloads = {"THRUN.LOG": run_log,
                    "THPRO.LOG": "WIN98_IDENTIFIED=1\nPROBE_MODE=direct-dll\nACP=949\n" + module.PASS_LINE + "\n",
                    "THSTA.LOG": "WIN98_IDENTIFIED=1\nPROBE_MODE=static-import\nACP=949\n" + module.PASS_LINE + "\n"}
        self.result = {"profile": "actual-win98-uefi-csmwrap", "status": "NEEDS-VISUAL-REVIEW",
                       "originals_unchanged": True, "prepared_source_unchanged": True,
                       "qemu_exit_code": 0, "manual_finish_requested": True,
                       "source_snapshot": str(runner), "source_sha256": self.runner_sha,
                       "hardware": {"run_name": self.run.name, "network": "none", "reserve_gib": 20,
                                    "accel": "kvm", "memory": 128, "smp": 2, "manual_gui": True, "firmware_gop": True},
                       "firmware_gop_opt_in": True,
                       "prepared_reuse": {"method": "verified private sparse post-run disk copy; cold hardware, synthetic fixture"},
                       "guest_files": {"manifest": str(self.manifest_path), "immutable_sources_unchanged": True,
                                       "output_baseline": "all absent before private injection",
                                       "inputs": [row | {"private_copy_sha256": row["sha256"]} for row in inputs],
                                       "readback": []}, "captures": []}
        for name, text in payloads.items():
            path = self.run / ("guest-output-" + name)
            path.write_text(text)
            self.result["guest_files"]["readback"].append({"guest": "C:\\GOPLAB\\" + name, "path": str(path),
                  "status": "captured", "freshness": "new-in-owned-run", "bytes": path.stat().st_size, "sha256": digest(path)})
        self.review = {"schema": "win98modern.theme-native-visual-review.v1", "native_component_visual_verified": True,
                       "originals_unchanged": True, "system_theme_verified": False,
                       "application_functionality_verified": False, "frames": {}}
        for mode, seconds in (("direct-dll", 10.0), ("static-import", 30.0)):
            path = self.run / (mode + ".png")
            # Bytes are synthetic, deliberately no visual-content acceptance.
            path.write_bytes(("synthetic reviewed frame " + mode).encode())
            self.result["captures"].append({"screenshot": str(path), "sha256": digest(path),
                                            "screenshot_status": "captured", "seconds": seconds})
            self.review["frames"][mode] = {"path": str(path), "sha256": digest(path), "seconds": seconds,
                                           "visual_review": "synthetic trusted review fixture; not a real screen"}
        self.sync()

    def tearDown(self):
        self.temp.cleanup()

    def sync(self):
        write(self.manifest_path, self.manifest)
        self.manifest_sha = digest(self.manifest_path)
        self.result["guest_files"]["manifest_sha256"] = self.manifest_sha
        self.result["guest_files"]["outputs"] = self.manifest["outputs"].copy()
        self.result["guest_files"]["immutable_sources"] = {str(self.manifest_path): self.manifest_sha} | {
            row["source"]: row["sha256"] for row in self.manifest["inputs"]} | {
            row["path"]: row["sha256"] for row in self.manifest["source_receipts"]}
        write(self.run / "result.json", self.result)
        self.review["harness_result_sha256"] = digest(self.run / "result.json")
        self.review["frozen_manifest_sha256"] = self.manifest_sha
        write(self.review_path, self.review)
        self.review_sha = digest(self.review_path)

    def verify(self):
        return module.verify(self.run, self.manifest_path, self.manifest_sha, self.runner_sha,
                             self.review_path, self.review_sha)

    def log_change(self, name, text):
        row = next(r for r in self.result["guest_files"]["readback"] if r["guest"].endswith(name))
        path = Path(row["path"])
        path.write_text(text)
        row["bytes"] = path.stat().st_size
        row["sha256"] = digest(path)
        self.sync()

    def test_nominal_distinguishes_supervisor_request(self):
        report = self.verify()
        self.assertTrue(report["passed"])
        self.assertEqual([c["actual_exit"] for c in report["actual_children"]], [0, 0])
        self.assertEqual(report["supervisor_actual_exit"], "not_observed")
        self.assertFalse(report["visual_content_automatically_asserted"])
        self.assertFalse(report["system_theme_verified"])

    def test_empty_static_stdout(self):
        self.log_change("THSTA.LOG", "")
        with self.assertRaisesRegex(module.EvidenceError, "empty/stale/incomplete"):
            self.verify()

    def test_partial_supervisor_like_real_v3(self):
        path = self.run / "guest-output-THRUN.LOG"
        text = path.read_text(); text = text[:text.index("child.path=C:\\GOPLAB\\M98THSTA.EXE")]
        self.log_change("THRUN.LOG", text)
        with self.assertRaisesRegex(module.EvidenceError, "both complete child"):
            self.verify()

    def test_failed_child_controls(self):
        original = (self.run / "guest-output-THRUN.LOG").read_text()
        for key, value in (("child.created", "0"), ("child.wait", "258"), ("child.exit-query", "0"),
                           ("child.exit-code", "259"), ("child.stdout-flushed", "0"),
                           ("child.handles-closed", "0"), ("child.success", "0")):
            with self.subTest(key=key):
                self.log_change("THRUN.LOG", original.replace(key + "=1" if key != "child.wait" and key != "child.exit-code" else key + "=0", key + "=" + value, 1))
                with self.assertRaises(module.EvidenceError):
                    self.verify()

    def test_supervisor_requested_failure(self):
        text = (self.run / "guest-output-THRUN.LOG").read_text().replace("supervisor.requested-exit-code=0", "supervisor.requested-exit-code=15")
        self.log_change("THRUN.LOG", text)
        with self.assertRaisesRegex(module.EvidenceError, "requested completion"):
            self.verify()

    def test_nonce_and_duplicate_keys(self):
        original = (self.run / "guest-output-THRUN.LOG").read_text()
        for text in (original.replace("synthetic-test-only", "old-trial"), original.replace("child.wait=0", "child.wait=0\nchild.wait=0", 1)):
            self.log_change("THRUN.LOG", text)
            with self.assertRaises(module.EvidenceError):
                self.verify()

    def test_old_probe_markers_do_not_establish_current_probe(self):
        self.log_change("THSTA.LOG", "WIN98_IDENTIFIED=1\n" + module.PASS_LINE + "\n")
        with self.assertRaisesRegex(module.EvidenceError, "current native probe"):
            self.verify()

    def test_wrong_codepage(self):
        text = (self.run / "guest-output-THPRO.LOG").read_text().replace("ACP=949", "ACP=1252")
        self.log_change("THPRO.LOG", text)
        with self.assertRaises(module.EvidenceError):
            self.verify()

    def test_stale_readback(self):
        self.result["guest_files"]["readback"][0]["freshness"] = "inherited-unchanged"
        self.sync()
        with self.assertRaises(module.EvidenceError):
            self.verify()

    def test_wrong_guest_destination_rejected(self):
        self.result["guest_files"]["readback"][0]["guest"] = "C:\\OLD\\THRUN.LOG"; self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "different guest path"):
            self.verify()

    def test_firmware_gop_profile_required(self):
        self.result["firmware_gop_opt_in"] = False; self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "GOP trial profile"):
            self.verify()

    def test_input_and_private_copy_mutation(self):
        (self.run / "prepared-guest-M98THEME.DLL").write_bytes(b"changed")
        with self.assertRaisesRegex(module.EvidenceError, "private prepared input"):
            self.verify()

    def test_missing_actual_immutable_flags(self):
        self.result["originals_unchanged"] = False; self.sync()
        with self.assertRaises(module.EvidenceError):
            self.verify()

    def test_unstopped_and_bool_exit_are_rejected(self):
        self.result["manual_finish_requested"] = False; self.sync()
        with self.assertRaises(module.EvidenceError):
            self.verify()
        self.result["manual_finish_requested"] = True; self.result["qemu_exit_code"] = False; self.sync()
        with self.assertRaises(module.EvidenceError):
            self.verify()

    def test_png_integrity_is_not_a_manual_review(self):
        self.review["native_component_visual_verified"] = False; self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "trusted manual"):
            self.verify()

    def test_manual_review_wrong_result(self):
        self.review["harness_result_sha256"] = "a" * 64
        write(self.review_path, self.review); self.review_sha = digest(self.review_path)
        with self.assertRaisesRegex(module.EvidenceError, "different run result"):
            self.verify()

    def test_reviewed_frame_mutation(self):
        Path(self.review["frames"]["direct-dll"]["path"]).write_bytes(b"changed pixels")
        with self.assertRaisesRegex(module.EvidenceError, "PNG changed"):
            self.verify()

    def test_one_frame_cannot_prove_two_modes(self):
        self.review["frames"]["static-import"] = self.review["frames"]["direct-dll"].copy(); self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "same frame"):
            self.verify()

    def test_identical_bytes_under_two_names_rejected(self):
        first = self.review["frames"]["direct-dll"]
        second = self.review["frames"]["static-import"]
        Path(second["path"]).write_bytes(Path(first["path"]).read_bytes())
        second["sha256"] = first["sha256"]
        self.result["captures"][1]["sha256"] = first["sha256"]
        self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "identical frame bytes"):
            self.verify()

    def test_snapshot_source_pin(self):
        (self.run / "runner-source.py").write_bytes(b"modified source")
        with self.assertRaisesRegex(module.EvidenceError, "runner source"):
            self.verify()

    def test_symlinked_input_rejected_even_with_same_bytes(self):
        path = self.stage / "M98THEME.DLL"; saved = self.stage / "saved.dll"
        path.rename(saved); path.symlink_to(saved)
        with self.assertRaisesRegex(module.EvidenceError, "symlink"):
            self.verify()

    def test_output_plan_duplicates_rejected(self):
        self.manifest["outputs"].append(self.manifest["outputs"][0]); self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "output plan"):
            self.verify()

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(module.EvidenceError, "duplicate JSON"):
            module.object_from(b'{"passed":false,"passed":true}')

    def test_manifest_schema_kind_and_nonce(self):
        original = self.manifest.copy()
        for key, value in (("schema", True), ("schema", 2), ("kind", "unapproved"),
                           ("nonce", ""), ("nonce", "x"*65), ("nonce", "x\nforged")):
            with self.subTest(key=key, value=value):
                self.manifest = original.copy(); self.manifest[key] = value; self.sync()
                with self.assertRaises(module.EvidenceError):
                    self.verify()

    def test_nonempty_harness_error(self):
        self.result["error"] = "disk budget abort after capture"; self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "native harness failed"):
            self.verify()

    def test_source_receipt_mutation(self):
        Path(self.manifest["source_receipts"][0]["path"]).write_text('{"changed": true}')
        with self.assertRaisesRegex(module.EvidenceError, "source receipt changed"):
            self.verify()

    def test_missing_approved_source_receipt(self):
        self.manifest["source_receipts"].pop(); self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "both current approved"):
            self.verify()

    def test_duplicate_approved_source_receipt(self):
        self.manifest["source_receipts"].append(self.manifest["source_receipts"][0].copy()); self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "duplicate approved source receipt"):
            self.verify()

    def test_source_receipt_outside_stage(self):
        row = self.manifest["source_receipts"][0]; path = self.root / Path(row["path"]).name
        path.write_bytes(Path(row["path"]).read_bytes()); row["path"] = str(path); self.sync()
        with self.assertRaisesRegex(module.EvidenceError, "outside its owned directory"):
            self.verify()

    def test_exact_native_immutable_source_set(self):
        for alteration in ("missing", "wrong", "extra"):
            with self.subTest(alteration=alteration):
                self.sync(); sources = self.result["guest_files"]["immutable_sources"]
                key = next(k for k in sources if k.endswith("M98THEME.DLL"))
                if alteration == "missing": del sources[key]
                elif alteration == "wrong": sources[key] = "a"*64
                else: sources[str(self.stage/"unapproved.txt")] = "a"*64
                write(self.run/"result.json", self.result)
                self.review["harness_result_sha256"] = digest(self.run/"result.json")
                write(self.review_path, self.review); self.review_sha = digest(self.review_path)
                with self.assertRaisesRegex(module.EvidenceError, "immutable source set/hash"):
                    self.verify()

    def test_exact_guest_output_plan(self):
        self.result["guest_files"]["outputs"][0] = "C:\\OLD\\THRUN.LOG"
        write(self.run/"result.json", self.result)
        self.review["harness_result_sha256"] = digest(self.run/"result.json")
        write(self.review_path, self.review); self.review_sha = digest(self.review_path)
        with self.assertRaisesRegex(module.EvidenceError, "guest output plan"):
            self.verify()

if __name__ == "__main__":
    unittest.main()
