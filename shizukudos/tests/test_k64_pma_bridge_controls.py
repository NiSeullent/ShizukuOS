#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the actual PMA bridge runner's output and process-exit controls.

QEMU is replaced at the launch boundary. Parsers, source inventory, input
hashes and receipt checks remain real. Private copied artifacts and a synthetic
build receipt are control fixtures, never compiled-source or guest evidence.
No VM, compiler, build, download or existing run output is touched.
"""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
STAGE = None
INPUTS = None
RUNNER = ROOT / "shizukudos/tests/run_k64_pma_bridge.py"
spec = importlib.util.spec_from_file_location("pma_bridge_runner_controls", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

# A hand-constructed successful serial fixture consumed by both actual parsers.
# The large memory evidence encodes a 256 MiB guest and a successful top-page
# probe. This is test data; no guest emitted these records in this suite.
EVENTS = {0: 0x80010001, 1: 0x1000, 2: 10, 3: 20000, 4: 10000, 5: 16,
          6: 0x2a002a, 7: 0xc0000096, 8: 0xc0000005, 9: 0xc0000005,
          10: (65536 << 33) | (1 << 32) | 256, 12: 0, 16: 0x200000000,
          17: 0x1122334455667788, 19: 0x140000000, 20: 1, 21: 2, 22: 0,
          23: 3, 28: 0, 29: 0x4b363421, 30: (1 << 33) | (1 << 34) | 7,
          31: (0x5734 << 16) | (48 << 8)}
PMA_NAMES = ("query negotiation", "auto-reset deferred wait", "manual-reset broadcast",
             "timeout", "cancellation", "stale generation", "duplicate request",
             "thread cleanup", "process cleanup", "full-ring completion retention", "domain restart",
             "corrupt-ring quarantine", "process cleanup after thread exit", "invalid-ring metadata quarantine",
             "mixed W64 backpressure deadline", "shutdown cancels waits and stops admission")
SERIAL = "\n".join([*(f"SHZ-EV {slot:x} {value:x}" for slot, value in EVENTS.items()),
                      "hello from Win64 PE32+", "K64 subsys64: T_W64CON relay: fixture",
                      "K64 subsys64: service stopped: fixture",
                      *("K64 PMA bridge PASS: " + name for name in PMA_NAMES),
                      "K64 PMA bridge: 16 passed, 0 failed", "SHZ-EXIT:0", ""])


class RunnerControls(unittest.TestCase):
    def setUp(self):
        self.case = STAGE / self._testMethodName
        self.case.mkdir()
        self.output = self.case / "run"
        evidence, code = runner.baseline.parse(SERIAL)
        self.assertTrue(all(c["status"] == "PASS" for c in
                            runner.baseline.evaluate(SERIAL, evidence, code, 1, memory="256") +
                            runner.pma_checks(SERIAL)))

    def invoke(self, rc=1, timed_out=False, error=None, output=None):
        destination = output or self.output

        def launch(command, timeout):
            self.assertEqual(timeout, 1)
            self.assertIn("isa-debug-exit,iobase=0xf4,iosize=0x04", command)
            if error:
                raise error
            serial_path = Path(command[command.index("-serial") + 1].removeprefix("file:"))
            serial_path.write_text(SERIAL)
            return rc, "simulated process result; no VM was launched", timed_out

        captured = io.StringIO()
        result, failure = None, None
        with patch.object(runner, "BUILD", INPUTS), patch.object(runner.qemu, "run_bounded", side_effect=launch) as mocked, \
             patch.object(sys, "argv", [str(RUNNER), "--accel", "tcg", "--timeout", "1", "--out", str(destination)]), \
             redirect_stdout(captured), redirect_stderr(captured):
            try:
                result = runner.main()
            except (SystemExit, OSError) as exc:
                failure = exc
        (self.case / (destination.name + ".log")).write_text(captured.getvalue())
        return result, failure, mocked.call_count

    def test_existing_output_is_rejected_without_launch_or_receipt_changes(self):
        self.output.mkdir()
        previous = b'{"status":"PASS","identity":"prior receipt must survive"}\n'
        prior_serial = b"prior serial output must survive\n"
        (self.output / "result.json").write_bytes(previous)
        (self.output / "serial.log").write_bytes(prior_serial)
        result, failure, launches = self.invoke(error=FileNotFoundError("unavailable QEMU"))
        self.assertIsNone(result)
        self.assertIsInstance(failure, SystemExit)
        self.assertEqual(failure.code, 2)
        self.assertEqual(launches, 0)
        self.assertEqual((self.output / "result.json").read_bytes(), previous)
        self.assertEqual((self.output / "serial.log").read_bytes(), prior_serial)

    def test_complete_success_serial_cannot_mask_abnormal_process_exit(self):
        for rc in (-9, 0, 2, 3):
            with self.subTest(rc=rc):
                destination = self.case / ("rc-" + str(rc))
                result, failure, launches = self.invoke(rc=rc, output=destination)
                self.assertIsNone(failure)
                self.assertEqual(launches, 1)
                self.assertEqual(result, 1)
                receipt = json.loads((destination / "result.json").read_text())
                self.assertEqual(receipt["status"], "FAIL")
                self.assertEqual(receipt["qemu_rc"], rc)

    def test_timeout_cannot_pass_even_with_success_exit_and_complete_serial(self):
        result, failure, launches = self.invoke(rc=1, timed_out=True)
        self.assertIsNone(failure)
        self.assertEqual(launches, 1)
        self.assertEqual(result, 1)
        self.assertEqual(json.loads((self.output / "result.json").read_text())["status"], "FAIL")

    def test_expected_process_exit_and_complete_checks_pass_in_fresh_output(self):
        result, failure, launches = self.invoke()
        self.assertIsNone(failure)
        self.assertEqual(launches, 1)
        self.assertEqual(result, 0)
        receipt = json.loads((self.output / "result.json").read_text())
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["qemu_rc"], 1)
        self.assertTrue(all(c["status"] == "PASS" for c in receipt["checks"]))

    def test_failed_fresh_launch_cannot_leave_a_pass_receipt(self):
        result, failure, launches = self.invoke(error=FileNotFoundError("unavailable QEMU"))
        self.assertIsNone(result)
        self.assertIsInstance(failure, FileNotFoundError)
        self.assertEqual(launches, 1)
        self.assertFalse((self.output / "result.json").exists())


def main():
    global STAGE, INPUTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    STAGE = args.out.resolve()
    if STAGE.exists():
        parser.error("choose fresh output to preserve earlier control evidence")
    STAGE.mkdir(parents=True)
    INPUTS = STAGE / "fixture-inputs"
    artifacts = ("kernel64s/boot.elf", "kernel64s/KERNEL64S.BIN", "win64/WIN64.IMG")
    # Snapshot each live artifact once; every test subsequently reads only the
    # private copy. Root's active build outputs may change independently.
    artifact_sources = {}
    for name in artifacts:
        original = runner.BUILD / name
        data = original.read_bytes() if original.is_file() else b"synthetic control artifact; no guest execution\n"
        destination = INPUTS / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        artifact_sources[name] = {"original": str(original), "sha256": hashlib.sha256(data).hexdigest(),
                                  "kind": "copied bytes" if original.is_file() else "synthetic bytes"}
    current = runner.kbuild.source_hashes()
    receipt = {"sources_sha256": current, "kernels": {"kernel64-standalone": {
        "sha256": runner.digest(INPUTS / "kernel64s/KERNEL64S.BIN"),
        "stub_sha256": runner.digest(INPUTS / "kernel64s/boot.elf")}}}
    (INPUTS / "kernels-build-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    paths = (RUNNER, Path(__file__).resolve(), Path(runner.baseline.__file__).resolve(),
             Path(runner.qemu.__file__).resolve(), Path(runner.shzlib.__file__).resolve(),
             Path(runner.kbuild.__file__).resolve())
    before = {str(p.relative_to(ROOT)): runner.digest(p) for p in paths}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RunnerControls))
    stable = before == {str(p.relative_to(ROOT)): runner.digest(p) for p in paths} and current == runner.kbuild.source_hashes()
    status = "PASS_RUNNER_CONTROLS_ONLY" if result.wasSuccessful() and stable else "FAIL"
    (STAGE / "controls-result.json").write_text(json.dumps({"status": status, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), "sources_sha256": before,
        "sources_before_after_match": stable, "artifact_snapshots": artifact_sources,
        "scope": "Mocked runner control tests; synthetic build receipt, no VM/build/compiler execution",
        "guest_executed": False}, indent=2) + "\n")
    return 0 if status == "PASS_RUNNER_CONTROLS_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
