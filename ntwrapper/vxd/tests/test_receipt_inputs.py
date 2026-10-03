"""Exercise the actual receipt runner with private inputs and a modeled child.

The compiler dependency and child test-process boundaries are substituted
separately; real dependency discovery is covered by SourceStabilityTests.
A separate regression injects
a private manifest rewrite immediately after the runner reads its old bytes.
Parsing, hashing, validation and receipt decisions execute the production runner.
No compiler, VxD, Windows guest or real project header is modified or executed.
SPDX-License-Identifier: GPL-2.0-only
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EXTERNAL_INPUTS = ("shizukudos/abi/shz_abi.h", "shizukudos/abi/shz_ipc.h",
                   "shizukudos/abi/future_dependency.h",
                   "shizukudos/boot_profile/storage/provenance.h",
                   "platform/freestanding/memory.c", "platform/freestanding/memory.h")


class ReceiptInputTests(unittest.TestCase):
    def run_fixture(self, changed=None, remove=False, child_status=0, stale=False,
                    manifest_drift=False):
        output_root = ROOT / "build/fd5c-vxd-receipt"
        output_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="inputs-", dir=output_root) as temporary:
            root = Path(temporary) / "project"
            here = root / "ntwrapper/vxd"
            build = root / "build/receipt"
            here.mkdir(parents=True)
            build.mkdir(parents=True)
            runner_path = here / "test.py"
            shutil.copyfile(HERE.parent / "test.py", runner_path)
            sources = ("ntwrapper/vxd/bridge.c", "ntwrapper/core.c",
                       "ntwrapper/include/ntwrapper.h", *EXTERNAL_INPUTS)
            hashes = {}
            for name in sources:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                data = ("/* private receipt fixture: " + name + " */\n").encode()
                path.write_bytes(data)
                hashes[name] = hashlib.sha256(data).hexdigest()
            for name in ("NTWRAP9X.VXD", "NTWRAP9X.elf", "NTWQUERY.EXE"):
                (build / name).write_bytes(("private fixture " + name).encode())
            manifest = {"sources": hashes,
                        "compiler_flags": ["--target=i386-unknown-none-elf", "-march=i486", "-std=c11",
                                           "-ffreestanding", "-mno-sse", "-mno-mmx", "-msoft-float"],
                        "sha256": hashlib.sha256((build / "NTWRAP9X.VXD").read_bytes()).hexdigest(),
                        "probe": {"sha256": hashlib.sha256((build / "NTWQUERY.EXE").read_bytes()).hexdigest()}}
            (build / "manifest.json").write_text(json.dumps(manifest))
            spec = importlib.util.spec_from_file_location("vxd_receipt_fixture", runner_path)
            runner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runner)
            if stale:
                (root / changed).write_bytes(b"changed before test admission\n")
            self.child_calls = 0
            self.discovery_calls = 0
            self.manifest_changed = False
            manifest_path = build / "manifest.json"
            original_read_text, original_read_bytes = Path.read_text, Path.read_bytes

            def after_manifest_read(path, data):
                if manifest_drift and path == manifest_path and not self.manifest_changed:
                    name = "shizukudos/abi/changed_manifest_dependency.h"
                    replacement = b"/* dependency declared only by the new manifest */\n"
                    (root / name).write_bytes(replacement)
                    manifest["sources"][name] = hashlib.sha256(replacement).hexdigest()
                    manifest_path.write_text(json.dumps(manifest))
                    self.manifest_changed = True
                return data

            def read_text(path, *args, **kwargs):
                return after_manifest_read(path, original_read_text(path, *args, **kwargs))

            def read_bytes(path, *args, **kwargs):
                return after_manifest_read(path, original_read_bytes(path, *args, **kwargs))

            def discovery_boundary(actual_manifest):
                self.discovery_calls += 1
                self.assertEqual(actual_manifest["sources"], hashes)
                self.assertEqual(actual_manifest["compiler_flags"], manifest["compiler_flags"])
                return {"modeled_fixture_inputs": {root / name for name in sources}}, []

            def child_boundary(command, **kwargs):
                del kwargs
                self.assertEqual(command, [sys.executable, "-B", "-m", "unittest", "discover",
                                           "-s", str(here / "tests"), "-v"])
                self.child_calls += 1
                if changed and not stale:
                    path = root / changed
                    if remove:
                        path.unlink()
                    else:
                        path.write_bytes(path.read_bytes() + b"/* changed during child execution */\n")
                return subprocess.CompletedProcess(command, child_status,
                    "MODELED child boundary; no compiler or guest executed\n", "")

            with mock.patch.object(runner, "dependency_closure", discovery_boundary), \
                 mock.patch.object(runner.subprocess, "run", child_boundary), \
                 mock.patch.object(Path, "read_text", read_text), \
                 mock.patch.object(Path, "read_bytes", read_bytes), \
                 mock.patch.object(sys, "argv", [str(runner_path), "--out", str(build)]), \
                 contextlib.redirect_stdout(io.StringIO()):
                try:
                    status = runner.main()
                except SystemExit as error:
                    if manifest_drift:
                        self.assertFalse((build / "host-tests.json").exists())
                    return error.code, None, hashes
            report = json.loads((build / "host-tests.json").read_text())
            return status, report, hashes

    def test_unchanged_inputs_preserve_success(self):
        status, report, _ = self.run_fixture()
        self.assertEqual(status, 0)
        self.assertEqual(self.discovery_calls, 1)
        self.assertEqual(self.child_calls, 1)
        self.assertTrue(report["passed"])
        self.assertTrue(report["inputs_unchanged_during_test"])
        self.assertFalse(report["guest_loaded"])
        self.assertFalse(report["native_vmm_calls_verified"])

    def test_receipt_records_every_manifest_source(self):
        status, report, hashes = self.run_fixture()
        self.assertEqual(status, 0)
        for name, expected in hashes.items():
            with self.subTest(source=name):
                self.assertIn(name, report["hashes"])
                self.assertEqual(report["hashes"][name], expected)

    def test_persistent_external_source_mutation_fails_receipt(self):
        for name in EXTERNAL_INPUTS:
            with self.subTest(source=name):
                status, report, hashes = self.run_fixture(changed=name)
                self.assertEqual(status, 1)
                self.assertFalse(report["passed"])
                self.assertFalse(report["inputs_unchanged_during_test"])
                self.assertEqual(report["hashes"][name], hashes[name])
                self.assertTrue(all(value == "failed-or-unverified" for value in report["statuses"].values()))

    def test_removed_external_source_fails_receipt(self):
        status, report, _ = self.run_fixture(changed=EXTERNAL_INPUTS[1], remove=True)
        self.assertEqual(status, 1)
        self.assertFalse(report["passed"])
        self.assertFalse(report["inputs_unchanged_during_test"])

    def test_stale_build_source_is_refused(self):
        status, report, _ = self.run_fixture(changed=EXTERNAL_INPUTS[1], stale=True)
        self.assertIsInstance(status, str)
        self.assertIn("Build inputs changed", status)
        self.assertIsNone(report)
        self.assertEqual(self.discovery_calls, 0)
        self.assertEqual(self.child_calls, 0)

    def test_child_failure_stays_failed_with_unchanged_inputs(self):
        status, report, _ = self.run_fixture(child_status=1)
        self.assertEqual(status, 1)
        self.assertFalse(report["passed"])
        self.assertTrue(report["inputs_unchanged_during_test"])
        self.assertEqual(self.discovery_calls, 1)
        self.assertEqual(self.child_calls, 1)

    def test_manifest_parse_capture_drift_is_refused_before_child(self):
        status, report, _ = self.run_fixture(manifest_drift=True)
        self.assertTrue(self.manifest_changed)
        self.assertIsInstance(status, str)
        self.assertIn("Build manifest changed", status)
        self.assertIsNone(report)
        self.assertEqual(self.discovery_calls, 0)
        self.assertEqual(self.child_calls, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
