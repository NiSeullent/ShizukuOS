#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Negative tests for the focused guest runner's evidence gate, with mocked QEMU.

These test receipt rejection, not CPU execution. Supply one actual successful
guest log to keep the semantic evaluator unchanged while replacing artifacts.
"""
import argparse
import contextlib
import io
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import run_k64_pma as runner


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build-dir", type=Path, required=True)
    ap.add_argument("--serial", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    actual_serial = args.serial.read_text()
    assert all(item["status"] == "PASS" for item in runner.evaluate(actual_serial, 1)[0])
    base_receipt_path = args.build_dir.parent / "kernels-build-result.json"
    base_receipt = json.loads(base_receipt_path.read_text())
    original_popen = subprocess.Popen
    original_read_text, original_read_bytes = Path.read_text, Path.read_bytes
    original_helpers = getattr(runner, "HELPER_PATHS", ())
    original_helper_hashes = getattr(runner, "HELPER_IMPORT_HASHES", {})
    results = []
    for name in ("unchanged", "missing-receipt", "mismatched-artifact", "stale-source", "replaced-artifact", "removed-artifact", "replaced-receipt", "receipt-read-replacement", "zero-first-low-phase-progress", "zero-second-low-phase-progress", "omit-scheduler", "omit-all-core", "omit-main", "unexpected-source-key", "persistent-copied-helper-drift", "reused-output"):
        folder = args.out.resolve() / name
        kernel_dir = folder / "kernel64s"
        kernel_dir.mkdir(parents=True, exist_ok=True)
        for artifact in ("boot.elf", "KERNEL64S.BIN"):
            shutil.copy2(args.build_dir / artifact, kernel_dir / artifact)
        receipt_path = folder / "kernels-build-result.json"
        receipt = json.loads(json.dumps(base_receipt))
        if name == "stale-source":
            receipt["sources_sha256"]["shizukudos/kernel64/sched.c"] = "0" * 64
        omissions = {"omit-scheduler": ("sched.c",), "omit-all-core": ("sched.c", "k64.h", "pma_tests.c", "tests.c"),
                     "omit-main": ("main.c",)}
        for omitted in omissions.get(name, ()):
            receipt["sources_sha256"].pop("shizukudos/kernel64/" + omitted)
        if name == "unexpected-source-key":
            receipt["sources_sha256"]["shizukudos/tests/run_k64_pma.py"] = runner.shzlib.sha256_file(Path(runner.__file__))
        receipt_path.write_text(json.dumps(receipt) + "\n")
        prior_result = b'{"status":"PASS","scope":"historical control receipt"}\n'
        prior_serial = b"historical serial bytes must survive\n"
        if name == "reused-output":
            (folder / "run").mkdir()
            (folder / "run/result.json").write_bytes(prior_result)
            (folder / "run/serial.log").write_bytes(prior_serial)
        helper_paths, helper_hashes = original_helpers, original_helper_hashes
        copied_helper = folder / "copied-evaluator.py"
        if name == "persistent-copied-helper-drift":
            shutil.copy2(Path(runner.__file__).with_name("run_k64_standalone.py"), copied_helper)
            helper_paths = (copied_helper,)
            helper_hashes = {str(copied_helper.resolve()): runner.shzlib.sha256_file(copied_helper)}
        if name == "missing-receipt":
            receipt_path.unlink()
        if name == "mismatched-artifact":
            with (kernel_dir / "KERNEL64S.BIN").open("ab") as stream:
                stream.write(b"changed before launch")
        launches = []
        receipt_read = []
        original_receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest() if receipt_path.is_file() else None

        def replace_after_read(path, data):
            if name == "receipt-read-replacement" and path.resolve() == receipt_path and not receipt_read:
                receipt_read.append(True)
                changed = dict(receipt, replacement_between_read_and_digest=True)
                receipt_path.write_text(json.dumps(changed) + "\n")
            return data

        def read_text(path, *positional, **keywords):
            return replace_after_read(path, original_read_text(path, *positional, **keywords))

        def read_bytes(path, *positional, **keywords):
            return replace_after_read(path, original_read_bytes(path, *positional, **keywords))

        class FakeGuest:
            returncode = 1

            def communicate(self, timeout):
                command = launches[-1]
                serial = actual_serial
                if name in ("zero-first-low-phase-progress", "zero-second-low-phase-progress"):
                    progress = re.findall(r"^K64 PMA progress: low_loops=(\d+)/(\d+)$", serial, re.M)[0]
                    first, second = progress
                    if name == "zero-first-low-phase-progress":
                        first = "0"
                    else:
                        second = "0"
                    serial = re.sub(r"^K64 PMA progress: low_loops=\d+/\d+\n", "", serial, flags=re.M)
                    serial += f"K64 PMA progress: low_loops={first}/{second}\n"
                Path(command[command.index("-serial") + 1][5:]).write_text(serial)
                if name == "replaced-artifact":
                    with (kernel_dir / "KERNEL64S.BIN").open("ab") as stream:
                        stream.write(b"changed after QEMU loaded the input")
                if name == "removed-artifact":
                    (kernel_dir / "boot.elf").unlink()
                if name == "replaced-receipt":
                    receipt_path.write_text("{}\n")
                if name == "persistent-copied-helper-drift":
                    with copied_helper.open("ab") as stream:
                        stream.write(b"\n# controlled copied helper drift\n")
                return b"", None

        def launch(command, *positional, **keywords):
            if command[0] != "PMA-QEMU-MOCK":
                return original_popen(command, *positional, **keywords)
            launches.append(command)
            return FakeGuest()

        log = io.StringIO()
        argv = [str(Path(runner.__file__)), "--qemu", "PMA-QEMU-MOCK", "--build-dir", str(kernel_dir),
                "--out", str(folder / "run")]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(subprocess, "Popen", launch), \
                mock.patch.object(Path, "read_text", read_text), mock.patch.object(Path, "read_bytes", read_bytes), \
                mock.patch.object(runner, "HELPER_PATHS", helper_paths, create=True), \
                mock.patch.object(runner, "HELPER_IMPORT_HASHES", helper_hashes, create=True), \
                contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                status = runner.main()
            except SystemExit as error:
                status = error.code
        (folder / "gate.log").write_text(log.getvalue())
        if name == "unchanged":
            passed = status == 0 and len(launches) == 1
        elif name == "reused-output":
            passed = status == 2 and not launches and (folder / "run/result.json").read_bytes() == prior_result and (folder / "run/serial.log").read_bytes() == prior_serial
        elif name in ("missing-receipt", "mismatched-artifact", "stale-source", "omit-scheduler", "omit-all-core", "omit-main", "unexpected-source-key"):
            passed = status == 2 and not launches
        elif name in ("zero-first-low-phase-progress", "zero-second-low-phase-progress"):
            result = json.loads((folder / "run/result.json").read_text())
            passed = status == 1 and len(launches) == 1 and result["inputs_stable"] and result["status"] == "FAIL"
        else:
            result = json.loads((folder / "run/result.json").read_text())
            passed = status == 1 and len(launches) == 1 and not result["inputs_stable"] and result["status"] == "FAIL"
            if name == "receipt-read-replacement":
                passed = passed and receipt_read == [True] and result["build_receipt_sha256"] == original_receipt_sha
            if name == "persistent-copied-helper-drift":
                passed = passed and result.get("runtime_helpers_sha256") == helper_hashes and result.get("runtime_helpers_stable") is False
        results.append({"case": name, "status": "PASS" if passed else "FAIL", "runner_exit": status,
                        "mock_guest_launches": len(launches)})
        print(f"[{results[-1]['status']}] {name}: runner_exit={status} guest_launches={len(launches)}")
    report = {"profile": "host receipt-gate negative tests; mocked QEMU, no native execution claim",
              "status": "PASS" if all(item["status"] == "PASS" for item in results) else "FAIL", "checks": results,
              "runner_sha256": runner.shzlib.sha256_file(Path(runner.__file__)),
              "test_sha256": runner.shzlib.sha256_file(Path(__file__)),
              "base_receipt_sha256": runner.shzlib.sha256_file(base_receipt_path),
              "actual_guest_serial_sha256": runner.shzlib.sha256_file(args.serial)}
    runner.shzlib.write_json(args.out / "result.json", report)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
