"""Actual CLI receipt decisions over copied inputs and filesystem race controls.

Only private copies under build/ are changed; no compiler or guest runs.
SPDX-License-Identifier: GPL-2.0-only
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        owner = ROOT / "build/pma-c957-cap-receipt-controls"
        owner.mkdir(parents=True, exist_ok=True)
        self.folder = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=owner))
        self.root = self.folder / "project"
        manifest = json.loads((HERE / "manifest.json").read_bytes())
        paths = set(manifest["source_contracts"].values())
        paths.update(e["path"] for e in manifest["evidence"])
        for binding in manifest["bindings"]:
            paths.update((binding["declaration"], binding["implementation"]))
        for entry in manifest["catalog"]:
            paths.update(ref["path"] for ref in entry["backend_refs"])
        for api in manifest["backend_apis"]:
            paths.update((api["source"], api["declaration_source"], api["resolver_source"]))
            paths.update(ref["path"] for ref in api.get("source_dependencies", []))
        paths.update(("ntwrapper/capabilities/manifest.json", "ntwrapper/capabilities/validate.py"))
        for name in paths:
            copied = self.root / name
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, copied)
        self.manifest = self.root / "ntwrapper/capabilities/manifest.json"
        self.program = self.root / "ntwrapper/capabilities/validate.py"
        self.source = self.root / "ntwrapper/include/ntwrapper.h"
        self.out = self.root / "build/result/capabilities.json"
        self.original_manifest = self.manifest.read_bytes()
        self.original_program = self.program.read_bytes()
        spec = importlib.util.spec_from_file_location("capability_receipt_fixture", self.program)
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)

    def invoke(self, drift=None, boundary="read", stdout_only=False, prior=False):
        original_bytes, original_text = Path.read_bytes, Path.read_text
        original_write, original_replace = Path.write_text, Path.replace
        mutated = False
        target = {"manifest": self.manifest, "source": self.source, "validator": self.program}.get(drift)
        prior_bytes = b'{"historical_receipt": true}\n' if prior else None
        if prior:
            self.out.parent.mkdir(parents=True)
            self.out.write_bytes(prior_bytes)

        def mutate():
            nonlocal mutated
            if not target or mutated:
                return
            mutated = True
            if drift == "manifest":
                changed = json.loads(self.original_manifest)
                changed["architecture"]["win98_win64_positive"] = True
                target.write_bytes(json.dumps(changed).encode())
            else:
                target.write_bytes(original_bytes(target) + b"\n/* persistent private fixture replacement */\n")

        def after_read(path, data):
            # Validator replacement is injected while reading the first source;
            # the validator snapshot must already have been taken by then.
            trigger = self.source if drift == "validator" else target
            if boundary == "read" and path == trigger:
                mutate()
            return data

        def read_bytes(path):
            return after_read(path, original_bytes(path))

        def read_text(path, *args, **kwargs):
            return after_read(path, original_text(path, *args, **kwargs))

        def write_text(path, data, *args, **kwargs):
            if boundary == "stage" and path.parent == self.out.parent:
                mutate()
            return original_write(path, data, *args, **kwargs)

        def replace(path, destination):
            if boundary == "publish" and Path(destination) == self.out:
                mutate()
            return original_replace(path, destination)

        output, errors = io.StringIO(), io.StringIO()
        argv = [] if stdout_only else ["--out", str(self.out)]
        with mock.patch.object(Path, "read_bytes", read_bytes), mock.patch.object(Path, "read_text", read_text), \
                mock.patch.object(Path, "write_text", write_text), mock.patch.object(Path, "replace", replace), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            rc = self.runner.main(argv)
        report = json.loads(self.out.read_bytes()) if self.out.is_file() else None
        record = {"exit": rc, "mutated": mutated, "boundary": boundary, "drift": drift,
                  "stdout": output.getvalue(), "stderr": errors.getvalue(), "prior_output": prior,
                  "output_exists": self.out.exists(), "output_preserved": prior and self.out.read_bytes() == prior_bytes}
        (self.folder / "control.json").write_text(json.dumps(record, indent=2) + "\n")
        return rc, report, record

    def assert_rejected(self, drift, boundary="read", prior=False):
        rc, _, record = self.invoke(drift, boundary, prior=prior)
        self.assertTrue(record["mutated"])
        self.assertEqual(rc, 1, record)
        self.assertNotIn("PASS:", record["stdout"])
        if prior:
            self.assertTrue(record["output_preserved"], record)
        else:
            self.assertFalse(self.out.exists(), record)
        if self.out.parent.is_dir():
            self.assertEqual(set(p.name for p in self.out.parent.iterdir()), {self.out.name} if prior else set())

    def test_unchanged_cli_receipt_matches_captured_inputs(self):
        rc, report, _ = self.invoke()
        self.assertEqual(rc, 0)
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(self.original_manifest).hexdigest())
        self.assertEqual(report["validator_sha256"], hashlib.sha256(self.original_program).hexdigest())
        self.assertFalse(report["behavior_tests_run"])
        self.assertFalse(report["win98_win64_positive"])
        self.assertFalse(report["win98_pma_positive"])
        self.assertFalse(report["windows98_dos_replacement_verified"])
        for name, expected in report["source_sha256"].items():
            self.assertEqual(expected, hashlib.sha256((self.root / name).read_bytes()).hexdigest())

    def test_read_only_cli_keeps_exact_manifest_identity(self):
        rc, _, record = self.invoke(stdout_only=True)
        self.assertEqual(rc, 0)
        report = json.loads(record["stdout"])
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(self.original_manifest).hexdigest())
        self.assertFalse(self.out.exists())

    def test_manifest_replacement_after_parse_is_rejected(self):
        self.assert_rejected("manifest")

    def test_source_replacement_after_capture_is_rejected(self):
        self.assert_rejected("source")

    def test_validator_replacement_during_validation_is_rejected(self):
        self.assert_rejected("validator")

    def test_manifest_drift_while_staging_preserves_prior_receipt(self):
        self.assert_rejected("manifest", "stage", prior=True)

    def test_source_drift_while_staging_preserves_prior_receipt(self):
        self.assert_rejected("source", "stage", prior=True)

    def test_validator_drift_while_staging_preserves_prior_receipt(self):
        self.assert_rejected("validator", "stage", prior=True)

    def test_manifest_drift_at_publication_removes_new_receipt(self):
        self.assert_rejected("manifest", "publish")

    def test_source_drift_at_publication_preserves_prior_receipt(self):
        self.assert_rejected("source", "publish", prior=True)

    def test_validator_drift_at_publication_preserves_prior_receipt(self):
        self.assert_rejected("validator", "publish", prior=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
