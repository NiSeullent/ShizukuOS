#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic stopped-run rejection controls, with stage boundary tested separately."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import verify_wasm_native as verifier
from test_wasm_native_log import NONCE, HOST, fixture, observer_fixture, encode


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class StoppedRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-wasm-acceptance-", dir=ROOT / "build")
        self.base = Path(self.tmp.name)
        self.stage = self.base / "stage"; self.stage.mkdir()
        self.run_dir = self.base / "shizukudos/csm/run-win98-gop-wasm-numeric-5abe-native-synthetic"
        self.run_dir.mkdir(parents=True)
        self.inputs = {}
        for name in ("M98WASM.DLL", "WAS13PR.EXE", "M98WARUN.EXE"):
            data = ("SYNTHETIC-NOT-A-PE:" + name).encode()
            (self.stage / name).write_bytes(data)
            (self.run_dir / ("prepared-guest-" + name)).write_bytes(data)
            self.inputs[name] = dict(source=str(self.stage / name), guest=verifier.PREFIX + name,
                                     bytes=len(data), sha256=digest(data))
        receipts = []
        self.pins = {}
        for name in ("runtime-build.json", "probe-build.json", "observer-build.json"):
            (self.stage / name).write_bytes(b"{}\n"); self.pins[name] = digest(b"{}\n")
            receipts.append(dict(path=str(self.stage / name), sha256=self.pins[name]))
        self.manifest = dict(nonce=NONCE, source_receipts=receipts,
            outputs=[verifier.PREFIX + n for n in ("WA13.LOG", "WARUN.LOG", "WAOUT.LOG")])
        self.manifest_path = self.stage / "guest-files.json"
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.manifest_sha = digest(self.manifest_path.read_bytes())
        snapshot = self.run_dir / "runner-source.py"; snapshot.write_bytes(b"# synthetic harness\n")
        self.harness_sha = digest(snapshot.read_bytes())
        raw_logs = {"WA13.LOG": encode(fixture()), "WARUN.LOG": encode([k + "=" + v for k, v in observer_fixture().items()]), "WAOUT.LOG": b""}
        readback = []
        for name, raw in raw_logs.items():
            path = self.run_dir / ("guest-output-" + name); path.write_bytes(raw)
            readback.append(dict(guest=verifier.PREFIX + name, path=str(path), status="captured",
                freshness="new-in-owned-run", bytes=len(raw), sha256=digest(raw)))
        immutable = {str(self.manifest_path): self.manifest_sha} | {
            r["source"]: r["sha256"] for r in self.inputs.values()} | {r["path"]: r["sha256"] for r in receipts}
        self.run = dict(profile="actual-win98-uefi-csmwrap", status="NEEDS-VISUAL-REVIEW",
            originals_unchanged=True, prepared_source_unchanged=True, qemu_exit_code=0,
            manual_finish_requested=True, source_snapshot=str(snapshot), source_sha256=self.harness_sha,
            hardware=dict(run_name=self.run_dir.name, network="none", accel="kvm", memory=128,
                smp=2, reserve_gib=20, manual_gui=True, firmware_gop=True), firmware_gop_opt_in=True,
            prepared_reuse=dict(method="verified private sparse post-run disk copy; cold hardware synthetic"),
            guest_files=dict(manifest=str(self.manifest_path), manifest_sha256=self.manifest_sha,
                immutable_sources_unchanged=True, immutable_sources=immutable,
                output_baseline="all absent before private injection", outputs=self.manifest["outputs"],
                inputs=[r | dict(private_copy_sha256=r["sha256"]) for r in self.inputs.values()], readback=readback))
        self.checked = {str(self.manifest_path): self.manifest_sha}
        self.boundary = ({}, self.inputs, HOST.read_bytes(), {}, self.checked)

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, run=None, boundaries=None):
        path = self.run_dir / "result.json"; path.write_text(json.dumps(self.run if run is None else run))
        with patch.object(verifier, "BOOT_BUILD", self.base), patch.object(verifier, "check_stage",
                side_effect=boundaries if boundaries is not None else None,
                return_value=self.boundary):
            return verifier.verify(path, digest(path.read_bytes()), self.manifest_path,
                self.manifest_sha, self.harness_sha, self.pins, "1" * 64)

    def test_synthetic_component_scope_and_outer_exit_limit(self):
        result = self.verify()
        self.assertTrue(result["native_numeric_component_execution_verified"])
        self.assertFalse(result["actual_supervisor_exit_verified"])
        for name in ("browser_webassembly_verified", "full_modern_wasm_verified", "webgpu_verified",
                     "webgl_verified", "modern_apps_verified", "user_objective_complete"):
            self.assertFalse(result[name])

    def test_wrong_stop_hardware_and_preservation_rejected(self):
        changes = [("qemu_exit_code", 1), ("qemu_exit_code", False), ("manual_finish_requested", False),
            ("originals_unchanged", False), ("prepared_source_unchanged", False), ("error", "failed"),
            ("profile", "other"), ("firmware_gop_opt_in", False), ("status", "FAIL")]
        for key, value in changes:
            bad = copy.deepcopy(self.run); bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.verify(bad)
        for key, value in (("network", "user"), ("memory", 129), ("memory", True), ("smp", 1),
                           ("reserve_gib", 0), ("manual_gui", False), ("firmware_gop", False), ("accel", "tcg")):
            bad = copy.deepcopy(self.run); bad["hardware"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(bad)

    def test_freshness_and_immutable_input_closure_required(self):
        for key, value in (("output_baseline", "present"), ("immutable_sources_unchanged", False),
                           ("immutable_sources", {}), ("manifest_sha256", "0" * 64)):
            bad = copy.deepcopy(self.run); bad["guest_files"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(bad)
        for key, value in (("freshness", "old"), ("status", "missing"), ("bytes", False), ("sha256", "0" * 64)):
            bad = copy.deepcopy(self.run); bad["guest_files"]["readback"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(bad)
        bad = copy.deepcopy(self.run); bad["guest_files"]["readback"].pop()
        with self.assertRaises(ValueError): self.verify(bad)

    def test_actual_pe_copy_harness_and_log_byte_drift_rejected(self):
        for name in ("prepared-guest-WAS13PR.EXE", "runner-source.py", "guest-output-WARUN.LOG"):
            path = self.run_dir / name; old = path.read_bytes(); path.write_bytes(old + b"changed")
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify()
            path.write_bytes(old)

    def test_stage_late_generation_drift_rejected(self):
        changed = self.boundary[:-1] + ({str(self.manifest_path): "0" * 64},)
        with self.assertRaises(ValueError): self.verify(boundaries=[self.boundary, changed])

    def test_native_files_changed_during_final_stage_replay_rejected(self):
        # Reproduce the independent-review gap: receipt and frozen stage stay
        # unchanged while an already-consumed native file changes on replay.
        names = ("runner-source.py", "prepared-guest-M98WASM.DLL",
            "prepared-guest-WAS13PR.EXE", "prepared-guest-M98WARUN.EXE",
            "guest-output-WA13.LOG", "guest-output-WARUN.LOG", "guest-output-WAOUT.LOG")
        for name in names:
            path = self.run_dir / name
            old, calls = path.read_bytes(), []
            def replay(*args):
                calls.append(1)
                if len(calls) == 2:
                    path.write_bytes(old + b"late-native-drift")
                return self.boundary
            try:
                with self.subTest(name=name), self.assertRaisesRegex(
                        ValueError, "native file drift during final stage replay"):
                    self.verify(boundaries=replay)
                self.assertEqual(len(calls), 2)
            finally:
                path.write_bytes(old)

    def test_collector_rehash_cannot_hide_failed_child(self):
        path = self.run_dir / "guest-output-WARUN.LOG"
        raw = path.read_bytes().replace(b"child.exit-code=0\r\n", b"child.exit-code=3221225477\r\n")
        path.write_bytes(raw); bad = copy.deepcopy(self.run)
        row = next(r for r in bad["guest_files"]["readback"] if r["guest"].endswith("WARUN.LOG"))
        row.update(bytes=len(raw), sha256=digest(raw))
        with self.assertRaises(ValueError): self.verify(bad)


if __name__ == "__main__":
    unittest.main()
