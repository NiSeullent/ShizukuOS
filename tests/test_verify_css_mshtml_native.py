#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic stopped-run protocol controls with real frozen build bytes.

No VM, real native log, screenshot or native acceptance receipt is produced.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import verify_css_mshtml_native as verifier
from test_css_mshtml_native_log import fixture, raw

STAGE = Path("/root/Win98-Modern-boot/build/css-mshtml-native-5abe-20261001-v2")
STAGE_SHA = "cef8c34813161bb544dbdcf3f8ba2ab83310d738d4d75642c17231b4e520320e"
HARNESS = Path("/root/Win98-Modern-boot/shizukudos/csm/test_win98_uefi.py")
HARNESS_SHA = "5e11254a6c0ca512a51d3fe5c4d33b110e067cf265344b663a12958b84062857"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    path.write_bytes(data)
    return sha(data)


class FrozenProtocol(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="m98-css-protocol-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stage = self.base / "stage"
        self.run_dir = self.base / "synthetic-run"
        self.run_dir.mkdir()
        self.assertEqual(sha((STAGE / "guest-files.json").read_bytes()), STAGE_SHA)
        self.assertEqual(sha(HARNESS.read_bytes()), HARNESS_SHA)
        shutil.copytree(STAGE, self.stage)
        self.manifest = json.loads((self.stage / "guest-files.json").read_text())
        for row in self.manifest["inputs"]:
            row["source"] = str(self.stage / Path(row["source"]).name)
        for row in self.manifest["source_receipts"]:
            row["path"] = str(self.stage / Path(row["path"]).name)
        self.manifest_path = self.stage / "guest-files.json"
        self.manifest_sha = save(self.manifest_path, self.manifest)
        self.build_pins = {Path(row["path"]).name: row["sha256"]
                           for row in self.manifest["source_receipts"]}
        (self.run_dir / "runner-source.py").write_bytes(HARNESS.read_bytes())
        inputs = []
        for row in self.manifest["inputs"]:
            name = Path(row["source"]).name
            (self.run_dir / ("prepared-guest-" + name)).write_bytes((self.stage / name).read_bytes())
            inputs.append(dict(row, private_copy_sha256=row["sha256"]))
        observer = {
            "scope": "actual-win98-css-owned-child-observer", "nonce": self.manifest["nonce"],
            "profile": "genuine-mshtml-css-variable-consumer", "WIN98_IDENTIFIED": "1",
            "os.major": "4", "os.minor": "10", "os.build-low": "2222", "os.platform": "1",
            "child.path": "C:\\GOPLAB\\CSS13PR.EXE", "child.stdout": "C:\\GOPLAB\\CSOUT.LOG",
            "child.created": "1", "child.create-error": "0", "child.pid": "123",
            "child.wait": "0", "child.exit-query": "1", "child.exit-query-error": "0",
            "child.exit-code": "0", "child.stdout-flushed": "1", "child.handles-closed": "1",
            "child.success": "1", "supervisor.requested-exit-code": "0"}
        payloads = {"CSS13.LOG": raw(fixture()), "CSRUN.LOG": raw(observer), "CSOUT.LOG": b""}
        readback = []
        for guest in self.manifest["outputs"]:
            name = guest.split("\\")[-1]
            path = self.run_dir / ("guest-output-" + name)
            path.write_bytes(payloads[name])
            readback.append(dict(guest=guest, path=str(path), bytes=len(payloads[name]),
                                 sha256=sha(payloads[name]), status="captured", freshness="new-in-owned-run"))
        immutable = {str(self.manifest_path): self.manifest_sha} | {
            row["source"]: row["sha256"] for row in self.manifest["inputs"]} | {
            row["path"]: row["sha256"] for row in self.manifest["source_receipts"]}
        self.run = dict(profile="actual-win98-uefi-csmwrap", status="NEEDS-VISUAL-REVIEW",
            originals_unchanged=True, prepared_source_unchanged=True, qemu_exit_code=0,
            manual_finish_requested=True, source_snapshot=str(self.run_dir / "runner-source.py"),
            source_sha256=HARNESS_SHA, firmware_gop_opt_in=True,
            hardware=dict(run_name=self.run_dir.name, network="none", accel="kvm", memory=128,
                          smp=2, reserve_gib=20, manual_gui=True, firmware_gop=True),
            prepared_reuse=dict(method="verified private sparse post-run disk copy; cold hardware synthetic protocol control"),
            guest_files=dict(manifest=str(self.manifest_path), manifest_sha256=self.manifest_sha,
                immutable_sources_unchanged=True, immutable_sources=immutable,
                output_baseline="all absent before private injection", outputs=self.manifest["outputs"],
                inputs=inputs, readback=readback))
        self.run_path = self.run_dir / "result.json"

    def verify(self, run=None):
        run_sha = save(self.run_path, self.run if run is None else run)
        # Only this synthetic host test replaces canonical directory policy;
        # production source still pins the real boot build constant.
        with patch.object(verifier, "BOOT_BUILD", self.base):
            return verifier.verify(self.run_path, run_sha, self.manifest_path, self.manifest_sha,
                                   HARNESS_SHA, self.build_pins)

    def test_synthetic_protocol_baseline_only(self):
        result = self.verify()
        self.assertFalse(result["native_paint_verified"])
        self.assertFalse(result["actual_supervisor_exit_verified"])
        self.assertFalse(result["full_modern_css_verified"])

    def test_native_hardware_and_preservation_rejections(self):
        mutations = [lambda r: r.update(status="FAIL"), lambda r: r.update(qemu_exit_code=True),
            lambda r: r.update(qemu_exit_code=1), lambda r: r.update(manual_finish_requested=False),
            lambda r: r.update(originals_unchanged=False), lambda r: r.update(prepared_source_unchanged=False),
            lambda r: r["hardware"].update(network="user"), lambda r: r["hardware"].update(memory=True),
            lambda r: r["hardware"].update(reserve_gib=0), lambda r: r["hardware"].update(manual_gui=False),
            lambda r: r["prepared_reuse"].update(method="warm CPU/RAM resume")]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, verifier.EvidenceError)):
                run = copy.deepcopy(self.run); mutate(run); self.verify(run)

    def test_stale_partial_and_ambiguous_collector(self):
        for mutate in (lambda r: r["guest_files"].update(output_baseline="existing outputs"),
            lambda r: r["guest_files"].update(immutable_sources_unchanged=False),
            lambda r: r["guest_files"]["readback"][0].update(freshness="preexisting"),
            lambda r: r["guest_files"]["readback"][0].update(status="missing"),
            lambda r: r["guest_files"]["readback"].append(r["guest_files"]["readback"][0]),
            lambda r: r["guest_files"]["inputs"][0].update(private_copy_sha256="0" * 64)):
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, verifier.EvidenceError)):
                run = copy.deepcopy(self.run); mutate(run); self.verify(run)

    def test_changed_source_harness_artifact_and_log(self):
        candidates = [self.run_dir / "runner-source.py", self.stage / "M98CSS.DLL",
                      self.stage / "source/src/m98_css_syntax.c",
                      self.run_dir / "guest-output-CSS13.LOG"]
        for path in candidates:
            with self.subTest(path=path), self.assertRaises((ValueError, verifier.EvidenceError)):
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"changed")
                    self.verify()
                finally:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
