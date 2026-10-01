#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual CLI rejection tests for Kernel32 build provenance (no guest execution).

A controlled executable records attempted QEMU launches and emits fixed valid
serial evidence. It tests the runner's admission/rejection behavior only.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RUNNER = HERE / "run_k32_publication_guest.py"
spec = importlib.util.spec_from_file_location("k32_publication_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
ROOT = None
RECORDS = []

FAKE_QEMU = r'''#!/usr/bin/env python3
import json
import sys
from pathlib import Path
root = Path(__file__).resolve().parent
(root / "launched").write_text("runner control fixture, not a guest\n")
serial = Path(sys.argv[sys.argv.index("-serial") + 1].removeprefix("file:"))
serial.write_text("""SHZ-EV 0 80010011
SHZ-EV 1 400000
SHZ-EV 2 2c
SHZ-EV 3 4e20
SHZ-EV 4 2710
SHZ-EV 5 10
SHZ-EV 6 2a
SHZ-EV 7 8000000d
SHZ-EV 8 8000000e
SHZ-EV c 0
SHZ-EV d 7530
SHZ-EV e c350
SHZ-EV 10 1
SHZ-EV 11 7a314
SHZ-EV 1c 0
SHZ-EV 1d 4b333221
SHZ-EXIT:0
""")
mutation = root / "mutation.json"
if mutation.exists():
    path = Path(json.loads(mutation.read_text())["path"])
    path.write_bytes(path.read_bytes() + b"changed during fixture execution\n")
raise SystemExit(1)
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="k32-provenance-tests-") if ROOT is None else None
        cls.evidence_root = Path(cls.temporary.name) if cls.temporary else ROOT

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def setUp(self):
        self.root = self.evidence_root / self._testMethodName
        self.root.mkdir(parents=True, exist_ok=False)
        self.kernel = self.root / "kernel32s"
        self.kernel.mkdir()
        for name in ("boot.elf", "KERNEL32S.BIN", "kernel32s.elf"):
            (self.kernel / name).write_bytes(("runner fixture " + name).encode())
        self.qemu = self.root / "controlled-qemu"
        self.qemu.write_text(FAKE_QEMU)
        self.qemu.chmod(0o700)
        sources = runner.source_hashes()
        # Required inputs are independently named; an omitted header/evaluator
        # in source_hashes must not make these rejection cases disappear.
        for name in ("shizukudos/kernel64/standalone/memholes.h", "shizukudos/tests/run_k32_standalone.py",
                     "shizukudos/tests/run_k64_standalone.py", "shizukudos/tools/qemu.py"):
            sources[name] = digest(REPO / name)
        self.receipt = self.root / "kernel32s-build-result.json"
        self.record = {"receipt_version": 2, "profile": "kernel32-standalone-publication",
                       "sources_sha256": sources.copy(), "sources_sha256_before": sources.copy(),
                       "sources_sha256_after": sources.copy(),
                       "kernel_sha256": digest(self.kernel / "KERNEL32S.BIN"),
                       "stub_sha256": digest(self.kernel / "boot.elf"),
                       "elf_sha256": digest(self.kernel / "kernel32s.elf")}
        self.write_receipt()

    def write_receipt(self):
        self.receipt.write_text(json.dumps(self.record, indent=2) + "\n")

    def invoke(self, extra=()):
        command = [sys.executable, "-B", str(RUNNER), "--kernel-dir", str(self.kernel), "--qemu", str(self.qemu),
                   "--accel", "tcg", "--timeout", "5", "--out", str(self.root / "run"), *extra]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (self.root / "console.log").write_text(result.stdout + result.stderr)
        RECORDS.append({"test": self._testMethodName, "command": command, "returncode": result.returncode,
                        "launched": (self.root / "launched").exists(), "output": result.stdout + result.stderr})
        return result

    def rejected_before_launch(self, message):
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn(message, result.stderr)
        self.assertFalse((self.root / "launched").exists())

    def test_missing_receipt_rejected_before_launch(self):
        self.receipt.unlink()
        self.rejected_before_launch("source-bound build receipt missing")

    def test_kernel_hash_mismatch_rejected_before_launch(self):
        (self.kernel / "KERNEL32S.BIN").write_bytes(b"changed before execution")
        self.rejected_before_launch("artifact hash mismatch")

    def test_stub_hash_mismatch_rejected_before_launch(self):
        (self.kernel / "boot.elf").write_bytes(b"changed before execution")
        self.rejected_before_launch("artifact hash mismatch")

    def test_stale_core_hash_rejected_before_launch(self):
        for key in ("sources_sha256", "sources_sha256_before", "sources_sha256_after"):
            self.record[key]["shizukudos/kernel32/user.c"] = "0" * 64
        self.write_receipt()
        self.rejected_before_launch("build source changed or unavailable")

    def test_missing_boot_header_rejected_before_launch(self):
        for key in ("sources_sha256", "sources_sha256_before", "sources_sha256_after"):
            self.record[key].pop("shizukudos/kernel64/standalone/memholes.h")
        self.write_receipt()
        self.rejected_before_launch("source closure mismatch")

    def test_missing_evaluator_rejected_before_launch(self):
        for key in ("sources_sha256", "sources_sha256_before", "sources_sha256_after"):
            self.record[key].pop("shizukudos/tests/run_k32_standalone.py")
        self.write_receipt()
        self.rejected_before_launch("source closure mismatch")

    def test_build_snapshot_drift_rejected_before_launch(self):
        self.record["sources_sha256_after"]["shizukudos/kernel32/k32.h"] = "0" * 64
        self.write_receipt()
        self.rejected_before_launch("build source snapshots differ")

    def test_build_preserves_existing_receipt_and_artifacts(self):
        before = {str(p): digest(p) for p in (self.receipt, *self.kernel.iterdir())}
        result = self.invoke(("--build",))
        self.assertEqual(result.returncode, 2)
        self.assertIn("choose a fresh --kernel-dir", result.stderr)
        self.assertEqual(before, {str(p): digest(p) for p in (self.receipt, *self.kernel.iterdir())})
        self.assertFalse((self.root / "launched").exists())

    def test_run_preserves_existing_evidence(self):
        out = self.root / "run"
        out.mkdir()
        (out / "result.json").write_text("historical evidence\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertEqual((out / "result.json").read_text(), "historical evidence\n")
        self.assertFalse((self.root / "launched").exists())

    def test_kernel_mutation_during_run_rejects_computed_pass(self):
        (self.root / "mutation.json").write_text(json.dumps({"path": str(self.kernel / "KERNEL32S.BIN")}))
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        receipt = json.loads((self.root / "run/result.json").read_text())
        self.assertEqual(receipt["status"], "FAIL")
        self.assertFalse(receipt["artifacts_stable"])
        self.assertIn("artifacts_sha256_before", receipt)
        self.assertIn("artifacts_sha256_after", receipt)
        self.assertNotEqual(receipt["artifacts_sha256_before"], receipt["artifacts_sha256_after"])

    def test_build_receipt_mutation_during_run_rejects_computed_pass(self):
        (self.root / "mutation.json").write_text(json.dumps({"path": str(self.receipt)}))
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        receipt = json.loads((self.root / "run/result.json").read_text())
        self.assertEqual(receipt["status"], "FAIL")
        self.assertFalse(receipt["build_receipt_stable"])

    def test_valid_receipt_binds_runner_evaluator_and_artifacts(self):
        before = digest(self.receipt)
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        receipt = json.loads((self.root / "run/result.json").read_text())
        self.assertEqual(receipt["status"], "PASS")
        self.assertIn("build_receipt_sha256_before", receipt)
        self.assertIn("build_receipt_sha256_after", receipt)
        self.assertEqual(receipt["build_receipt_sha256_before"], before)
        self.assertEqual(receipt["build_receipt_sha256_after"], before)
        self.assertTrue(receipt["sources_stable"])
        self.assertEqual(receipt["runner_sources_sha256"]["shizukudos/tests/run_k32_standalone.py"],
                         digest(HERE / "run_k32_standalone.py"))
        self.assertEqual(receipt["artifacts_sha256_before"], receipt["artifacts_sha256_after"])


def main():
    global ROOT
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    ROOT = args.out.resolve()
    ROOT.mkdir(parents=True, exist_ok=False)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProvenanceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    (ROOT / "result.json").write_text(json.dumps({"test": "k32-runner-provenance-control-fixtures-no-guest",
        "status": "PASS" if result.wasSuccessful() else "FAIL", "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), "checks": RECORDS}, indent=2) + "\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
