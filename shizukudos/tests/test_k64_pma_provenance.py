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
    results = []
    for name in ("unchanged", "missing-receipt", "mismatched-artifact", "stale-source", "replaced-artifact", "removed-artifact", "replaced-receipt", "receipt-read-replacement", "zero-first-low-phase-progress", "zero-second-low-phase-progress"):
        folder = args.out.resolve() / name
        kernel_dir = folder / "kernel64s"
        kernel_dir.mkdir(parents=True, exist_ok=True)
        for artifact in ("boot.elf", "KERNEL64S.BIN"):
            shutil.copy2(args.build_dir / artifact, kernel_dir / artifact)
        receipt_path = folder / "kernels-build-result.json"
        receipt = json.loads(json.dumps(base_receipt))
        if name == "stale-source":
            receipt["sources_sha256"]["shizukudos/kernel64/sched.c"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt) + "\n")
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
                contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                status = runner.main()
            except SystemExit as error:
                status = error.code
        (folder / "gate.log").write_text(log.getvalue())
        if name == "unchanged":
            passed = status == 0 and len(launches) == 1
        elif name in ("missing-receipt", "mismatched-artifact", "stale-source"):
            passed = status == 2 and not launches
        elif name in ("zero-first-low-phase-progress", "zero-second-low-phase-progress"):
            result = json.loads((folder / "run/result.json").read_text())
            passed = status == 1 and len(launches) == 1 and result["inputs_stable"] and result["status"] == "FAIL"
        else:
            result = json.loads((folder / "run/result.json").read_text())
            passed = status == 1 and len(launches) == 1 and not result["inputs_stable"] and result["status"] == "FAIL"
            if name == "receipt-read-replacement":
                passed = passed and receipt_read == [True] and result["build_receipt_sha256"] == original_receipt_sha
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
