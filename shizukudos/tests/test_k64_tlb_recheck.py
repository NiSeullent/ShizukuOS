#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual saved-run evaluator RED/GREEN and private read-only admission controls.

No compiler or guest is launched. Tool/artifact replacements are confined to
the byte-reader boundary; source/receipt/log replacements use private files.
"""
import argparse
import copy
import hashlib
import io
import json
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / "shizukudos/tests/run_k64_tlb_ap.py"
NEW = ROOT / "shizukudos/tests/recheck_k64_tlb_no_invalidate.py"

def load(path):
    raw = path.read_bytes()
    module = types.ModuleType("tlb_recheck_test_module")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module, hashlib.sha256(raw).hexdigest()

def gate_cases(serial):
    cpu1 = "cpu=1 actual=1 warm=1 reads=3 ack=0 inv=0 bad=0 value=544c420000000001"
    cases = [("actual-new-payload-with-no-ack", serial, True, True),
             ("possible-stale-final-payload", serial.replace(cpu1, cpu1.replace("bad=0 value=544c420000000001", "bad=2 value=544c420000000000")).replace("pages=60880/60880 bad=1", "pages=60880/60880 bad=3"), True, True),
             ("possible-partial-eviction", serial.replace(cpu1, cpu1.replace("bad=0", "bad=1")).replace("pages=60880/60880 bad=1", "pages=60880/60880 bad=2"), True, True)]
    mutations = [
        ("forged-completion", "completed=0 retirements=0", "completed=1 retirements=0"),
        ("premature-retirement", "retirements=0 poisoned=1", "retirements=1 poisoned=1"),
        ("not-poisoned", "poisoned=1 retained=1", "poisoned=0 retained=1"),
        ("lost-resource", "retained=1 pages=", "retained=0 pages="),
        ("page-conservation", "pages=60880/60880", "pages=60880/60879"),
        ("wrong-request", "request=1 completed=0", "request=2 completed=0"),
        ("victim-acknowledged", cpu1, cpu1.replace("ack=0", "ack=1")),
        ("victim-invalidated", cpu1, cpu1.replace("inv=0", "inv=1")),
        ("victim-not-warmed", cpu1, cpu1.replace("warm=1", "warm=0")),
        ("victim-no-read", cpu1, cpu1.replace("reads=3", "reads=2")),
        ("wrong-physical-identity", cpu1, cpu1.replace("actual=1", "actual=0")),
        ("corrupt-payload", cpu1, cpu1.replace("value=544c420000000001", "value=dead000000000001")),
        ("inconsistent-payload-count", cpu1, cpu1.replace("bad=0", "bad=2")),
        ("bsp-no-instruction", "cpu=0 actual=0 warm=1 reads=3 ack=1 inv=1", "cpu=0 actual=0 warm=1 reads=3 ack=1 inv=0"),
        ("extra-stress-error", "pages=60880/60880 bad=1", "pages=60880/60880 bad=2"),
        ("missing-participant", "ready=2 request=1", "ready=1 request=1"),
        ("wrong-ap-result", "arch_online=2 completed=1 bad=2", "arch_online=2 completed=1 bad=3")]
    cases += [(name, serial.replace(before, after), False, True) for name, before, after in mutations]
    cases += [("duplicate-cpu", serial + "SMP-TLB CPU: " + cpu1 + "\n", False, True),
              ("duplicate-summary", serial + next(line for line in serial.splitlines() if line.startswith("SMP-TLB summary:")) + "\n", False, True),
              ("whole-pma-failure", serial + "K64 PMA FAIL: preserved negative\n", True, False),
              ("exception", serial + "K64 EXCEPTION: negative\n", True, False),
              ("missing-exit", serial.replace("SHZ-EXIT:0\n", ""), True, False),
              ("duplicate-exit", serial + "SHZ-EXIT:0\n", True, False)]
    return cases

def admission_cases(successor, native_path, built_path):
    cases = []
    def rejected(name, action):
        try:
            action()
            cases.append({"case": name, "rejected": False, "expected_behavior": False})
        except (ValueError, SystemExit) as exc:
            cases.append({"case": name, "rejected": True, "reason": str(exc), "expected_behavior": True})
    with tempfile.TemporaryDirectory(prefix="tlb-recheck-control-") as temporary:
        private = Path(temporary)
        with patch.object(sys, "argv", [str(NEW), "--native", str(native_path), "--build", str(built_path), "--out", str(private / "admitted")]), redirect_stdout(io.StringIO()):
            try:
                admitted = successor.main(NEW.read_bytes()) == 0
                cases.append({"case": "actual-full-read-only-replay", "admitted": admitted, "expected_behavior": admitted})
            except (ValueError, SystemExit) as exc:
                cases.append({"case": "actual-full-read-only-replay", "admitted": False, "reason": str(exc), "expected_behavior": False})
        for name, path, pin in (("native-receipt", native_path, successor.NATIVE_SHA),
                                ("build-receipt", built_path, successor.BUILD_SHA),
                                ("original-evaluator", OLD, successor.ORIGINAL_SHA)):
            target = private / name
            target.write_bytes(path.read_bytes() + b"\n")
            rejected(name, lambda target=target, pin=pin: successor.read_pinned(target, pin))
        native = json.loads(native_path.read_bytes())
        built = json.loads(built_path.read_bytes())
        target = private / "serial.log"
        target.write_bytes((native_path.parent / "serial.log").read_bytes() + b"changed\n")
        rejected("raw-serial", lambda: successor.read_pinned(target, native["serial_sha256"]))
        def reader_change(path):
            def reader(actual):
                raw = Path(actual).read_bytes()
                return raw + b"persistent private replacement" if Path(actual) == Path(path) else raw
            return reader
        for name, path in (("compiled-input", next(iter(built["compiled_inputs_sha256"]))),
                           ("tool-byte", built["tools"]["qemu"]["path"]),
                           ("captured-header", ROOT / "shizukudos/win64/pe_parse.h"),
                           ("captured-fixture", ROOT / "shizukudos/kernel64/pma_tests.c")):
            rejected(name, lambda path=path: successor.verify_files(built, ROOT, reader_change(path)))
        for name, mutation in (("broadened-profile", {"cpus": 4}),
                               ("timeout", {"timed_out": True}),
                               ("source-unstable", {"inputs_sources_tools_unchanged": False}),
                               ("lost-build-origin", {"producer_receipt_sha256": "0" * 64}),
                               ("changed-source-map", {"sources_sha256": {}}),
                               ("whole-gate-failed", {"whole_native_gate_pass": False})):
            altered = copy.deepcopy(native)
            altered.update(mutation)
            rejected(name, lambda altered=altered: successor.verify_records(altered, built))
        # Copy the actual captured source closure and add a genuine unlisted C
        # file: no current project file or shared index is ever changed.
        source_root = private / "project"
        for name in built["sources_sha256"]:
            path = source_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        old_path = source_root / OLD.relative_to(ROOT)
        old_path.parent.mkdir(parents=True, exist_ok=True)
        old_path.write_bytes(OLD.read_bytes())
        private_old, _ = load(old_path)
        (source_root / "shizukudos/kernel64/private_unlisted.c").write_text("int actual_unlisted_source;\n")
        rejected("extra-source-namespace", lambda: successor.verify_inventory(private_old, built))
        copied = private / "rechecker.py"
        captured = NEW.read_bytes()
        copied.write_bytes(captured)
        private_successor, _ = load(copied)
        copied.write_bytes(captured + b"\n# persistent replacement after load\n")
        with patch.object(sys, "argv", [str(copied), "--native", str(native_path), "--build", str(built_path), "--out", str(private / "unexpected")]):
            rejected("loaded-evaluator-byte-replacement", lambda: private_successor.main(captured))
    return cases

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--implementation", choices=("legacy", "successor"), required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    old, old_sha = load(OLD)
    serial = (args.native.parent / "serial.log").read_text()
    native_sha = hashlib.sha256(args.native.read_bytes()).hexdigest()
    successor, successor_sha = (load(NEW) if args.implementation == "successor" else (None, None))
    results = []
    for name, text, component, whole in gate_cases(serial):
        actual = (successor.evaluate_safety(old, text, 1) if successor else old.evaluate(text, 1, 2, "no-invalidate"))[:2]
        results.append({"case": name, "actual": actual, "expected": (component, whole), "expected_behavior": actual == (component, whole)})
    admissions = admission_cases(successor, args.native, args.build) if successor else []
    original_component, original_whole, _ = old.evaluate(serial, 1, 2, "no-invalidate")
    okay = all(row["expected_behavior"] for row in results + admissions)
    result = {"status": "PASS" if okay else "FAIL", "scope": __doc__, "implementation": args.implementation,
              "original_strict_component_pass": original_component, "original_whole_gate_pass": original_whole,
              "native_receipt_sha256": native_sha, "original_evaluator_sha256": old_sha,
              "successor_evaluator_sha256": successor_sha, "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "gates": results, "admission_controls": admissions, "guest_executed": False}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("gates", "admission_controls")}, indent=2))
    return 0 if okay else 1

if __name__ == "__main__":
    raise SystemExit(main())
