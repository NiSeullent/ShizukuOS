#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the real evaluator's narrow admission in disposable captured copies.

The VM call is stopped. These are admission controls, not native AP evidence.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = ROOT / "shizukudos/tests/run_k64_ap_bringup.py"
ORIGIN = ROOT / "build/smp-memory-native-source-2/result.json"


class Boundary(Exception):
    pass


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    original = json.loads(ORIGIN.read_bytes())
    identity = {str(ORIGIN): sha(ORIGIN), str(EVALUATOR): sha(EVALUATOR),
                str(Path(__file__)): sha(Path(__file__))}
    identity.update({str(ROOT / p): h for p, h in original["sources_sha256"].items()})
    identity.update(original["compiled_inputs_sha256"])
    identity.update({r["path"]: r["sha256"] for r in original["tools"].values()})
    identity[str(ORIGIN.parent / "build.log")] = sha(ORIGIN.parent / "build.log")
    for row in original["runs"]:
        log = Path(row["command"][row["command"].index("-serial") + 1][5:])
        identity[str(log)] = row["serial_sha256"]
        error = log.with_name(log.name.replace(".serial.log", ".qemu.log"))
        identity[str(error)] = sha(error)
    cases = []
    with tempfile.TemporaryDirectory(prefix="smp-memory-admission-") as directory:
        private = Path(directory)
        for p, h in original["sources_sha256"].items():
            assert sha(ROOT / p) == h
            dst = private / p
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / p, dst)
        evaluator = private / EVALUATOR.relative_to(ROOT)
        evaluator.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(EVALUATOR, evaluator)
        baseline = copy.deepcopy(original)
        baseline["compiled_inputs_sha256"] = {}
        relocated = {}
        for path, h in original["compiled_inputs_sha256"].items():
            dst = private / "origin" / Path(path).name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dst)
            baseline["compiled_inputs_sha256"][str(dst)] = h
            relocated[path] = str(dst)
        shutil.copyfile(ORIGIN.parent / "build.log", private / "origin/build.log")
        # A private Python executable identity permits post-launch tool drift
        # without touching installed tools. No executable is run in this test.
        tool = private / "origin/python-tool"
        shutil.copyfile(original["tools"]["python"]["path"], tool)
        baseline["tools"]["python"]["path"] = str(tool)
        for run in baseline["runs"]:
            run["command"] = [relocated.get(item, item) for item in run["command"]]
            index = run["command"].index("-serial") + 1
            old = Path(run["command"][index][5:])
            dst = private / "origin" / old.name
            shutil.copyfile(old, dst)
            shutil.copyfile(old.with_name(old.name.replace(".serial.log", ".qemu.log")),
                            dst.with_name(dst.name.replace(".serial.log", ".qemu.log")))
            run["command"][index] = "file:" + str(dst)
        frozen = {p: p.read_bytes() for p in private.rglob("*") if p.is_file()}
        receipt = private / "origin/result.json"
        test_names = ("valid2", "valid4", "default-refusal", "extra-failure", "wrong-failure",
                      "summary-two", "extra-exit", "exit-drift", "timeout", "qemu-drift",
                      "second-firmware-fail", "serial-drift", "compiler-error", "absent-artifact",
                      "bad-elf", "fixture", "source", "tool", "helper", "source-stability",
                      "input-set", "incomplete-runs", "no-memory", "cpu1", "off", "tcg",
                      "expect-red", "post-source", "post-tool", "post-origin-log")
        for number, name in enumerate(test_names):
            for p, data in frozen.items():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            built = copy.deepcopy(baseline)
            argv = [str(evaluator), "--receipt", str(receipt), "--out", str(private / f"case{number}"),
                    "--cpus", "4" if name == "valid4" else "2", "--memory-test", "--known-core-failure-component"]
            log = Path(built["runs"][2]["command"][built["runs"][2]["command"].index("-serial") + 1][5:])
            if name == "default-refusal": argv.remove("--known-core-failure-component")
            if name == "no-memory": argv.remove("--memory-test")
            if name == "cpu1": argv[argv.index("--cpus") + 1] = "1"
            if name == "off": argv += ["--mode", "off"]
            if name == "tcg": argv += ["--accel", "tcg"]
            if name == "expect-red": argv += ["--expect-red"]
            if name in ("extra-failure", "wrong-failure", "summary-two", "extra-exit", "exit-drift"):
                text = log.read_text()
                if name == "extra-failure": text += "K64 PMA FAIL: another assertion\n"
                if name == "wrong-failure": text = text.replace("each low-priority policy phase executes useful CPU work", "another assertion")
                if name == "summary-two": text = text.replace("summary: failures=1", "summary: failures=2")
                if name == "extra-exit": text += "SHZ-EXIT:0\n"
                if name == "exit-drift": text = text.replace("SHZ-EXIT:1", "SHZ-EXIT:2")
                log.write_text(text); built["runs"][2]["serial_sha256"] = sha(log)
            if name == "timeout": built["runs"][2]["timed_out"] = True
            if name == "qemu-drift": built["runs"][2]["qemu_returncode"] = 1
            if name == "second-firmware-fail": built["runs"][1]["expected_behavior"] = False
            if name == "serial-drift": log.write_bytes(log.read_bytes() + b"changed\n")
            if name == "compiler-error": (private / "origin/build.log").write_text("fatal error: compile failed\n")
            if name == "absent-artifact": (private / "origin/kernel64s.elf").unlink()
            if name == "bad-elf":
                p = private / "origin/boot.elf"; p.write_bytes(b"bad ELF"); built["compiled_inputs_sha256"][str(p)] = sha(p)
            if name == "fixture":
                p = private / "shizukudos/kernel64/pma_tests.c"; p.write_bytes(p.read_bytes() + b"\n/* changed */\n")
                built["sources_sha256"][str(p.relative_to(private))] = sha(p)
            if name == "source":
                p = private / "shizukudos/kernel64/mem.c"; p.write_bytes(p.read_bytes() + b"\n/* changed */\n")
            if name == "tool": built["tools"]["python"]["sha256"] = "0" * 64
            if name == "helper": built["executed_helpers_sha256"]["shizukudos/kbuild.py"] = "0" * 64
            if name == "source-stability": built["sources_unchanged"] = False
            if name == "input-set": built["compiled_inputs_sha256"].pop(str(private / "origin/kernel64s.elf"))
            if name == "incomplete-runs": built["runs"].pop()
            receipt.write_text(json.dumps(built))
            spec = importlib.util.spec_from_file_location("private_memory_admission", evaluator)
            runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
            calls = []
            def stop_vm(*unused, **ignored):
                calls.append(True)
                if name.startswith("post-"):
                    target = {"post-source": private / "shizukudos/kernel64/mem.c", "post-tool": tool,
                              "post-origin-log": log}[name]
                    target.write_bytes(target.read_bytes() + b"drift\n")
                    return type("Run", (), {"returncode": 1, "stderr": ""})()
                raise Boundary()
            saved_path = list(sys.path)
            try:
                with patch.object(sys, "argv", argv), patch.object(runner.subprocess, "run", side_effect=stop_vm):
                    try: runner.main(); outcome = "returned"
                    except Boundary: outcome = "VM boundary reached"
                    except (SystemExit, OSError) as error: outcome = str(error)
            finally: sys.path[:] = saved_path
            if name.startswith("post-"):
                result_path = private / f"case{number}/result.json"
                result = json.loads(result_path.read_text()) if result_path.exists() else {}
                okay = bool(calls) and result.get("status") == "FAIL" and result.get("inputs_sources_tools_unchanged") is False and \
                    result.get("whole_acceptance") is False and result.get("known_failure_preserved") is True
            else:
                okay = outcome == "VM boundary reached" if name.startswith("valid") else not calls and outcome != "returned"
            cases.append({"name": name, "actual": outcome, "vm_calls": len(calls), "expected_behavior": bool(okay)})
    stable = all(Path(p).is_file() and sha(Path(p)) == h for p, h in identity.items())
    result = {"status": "PASS" if stable and all(c["expected_behavior"] for c in cases) else "FAIL",
              "scope": "actual evaluator/private captured sources and receipt, stopped VM boundary; no guest",
              "cases": cases, "dependencies_sha256": identity, "originals_unchanged": stable}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "dependencies_sha256"}, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__": raise SystemExit(main())
