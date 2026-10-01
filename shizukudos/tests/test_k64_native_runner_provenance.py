#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the real producer with private actual-helper replacement before capture.

The compiler boundary is stopped deliberately. No compiler or VM is started,
and every mutation is restricted to a disposable copy of the producer closure.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / "shizukudos/tests/run_k64_native_firmware.py"


class CompilerBoundaryReached(Exception):
    pass


def trial(target):
    with tempfile.TemporaryDirectory(prefix="smp-runner-identity-") as temporary:
        root = Path(temporary)
        # Copy real helper bytes and their real required source files. The
        # producer discovers its own dependency list; the test does not supply it.
        paths = [ROOT / "shizukudos/kbuild.py", ROOT / "shizukudos/tools/shzlib.py",
                 ROOT / "shizukudos/win64/pe_parse.c",
                 ROOT / "shizukudos/supervisor/src/font8x8_basic.h", PRODUCER]
        for original in paths:
            copied = root / original.relative_to(ROOT)
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(original.read_bytes())
        producer = root / PRODUCER.relative_to(ROOT)
        spec = importlib.util.spec_from_file_location("smp_private_producer", producer)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        mutation = root / target if target else None
        original_sha = hashlib.sha256(mutation.read_bytes()).hexdigest() if mutation else None
        replaced = False

        def stop_compiler(*args, **kwargs):
            raise CompilerBoundaryReached("actual builder reached its compiler boundary")

        def after_load(frame, event, arg):
            nonlocal replaced
            if event != "return" or frame.f_code.co_name != "<module>":
                return
            loaded = Path(frame.f_code.co_filename)
            if loaded == root / "shizukudos/kbuild.py":
                frame.f_globals["build_kernel"] = stop_compiler
            if mutation and loaded == mutation and not replaced:
                # Persistent replacement immediately after actual helper execution,
                # before the producer can obtain its later source snapshot.
                mutation.write_bytes(mutation.read_bytes() + b"\n# private replacement after execution\n")
                replaced = True

        saved_profile, saved_path = sys.getprofile(), list(sys.path)
        saved_shzlib = sys.modules.pop("shzlib", None)
        try:
            sys.setprofile(after_load)
            with patch.object(runner, "identities", return_value={}), \
                 patch.object(sys, "argv", [str(producer), "--out", str(root / "proof")]):
                try:
                    runner.main()
                    outcome = "unexpected return"
                except CompilerBoundaryReached:
                    outcome = "compiler boundary reached"
                except SystemExit as exc:
                    outcome = str(exc)
        finally:
            sys.setprofile(saved_profile)
            sys.path[:] = saved_path
            sys.modules.pop("shzlib", None)
            if saved_shzlib is not None:
                sys.modules["shzlib"] = saved_shzlib
        after_sha = hashlib.sha256(mutation.read_bytes()).hexdigest() if mutation else None
        expected = outcome == "compiler boundary reached" if not mutation else \
            replaced and after_sha != original_sha and "closure changed" in outcome
        return {"target": target, "actual": outcome, "replacement_performed": replaced,
                "before_sha256": original_sha, "after_sha256": after_sha,
                "expected_behavior": bool(expected)}


def reuse_trial(target):
    """Use real prior machine inputs; alter only copied C/artifact controls."""
    prior_path = ROOT / "build/smp-normal-firmware-reviewed-core-2/result.json"
    prior = json.loads(prior_path.read_bytes())
    with tempfile.TemporaryDirectory(prefix="smp-compiled-reuse-") as temporary:
        root = Path(temporary)
        for name in prior["sources_sha256"]:
            copied = root / name
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes((ROOT / name).read_bytes())
        copied_inputs = {}
        for name, sha in prior["compiled_inputs_sha256"].items():
            copied = root / "original-inputs" / Path(name).name
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(Path(name).read_bytes())
            copied_inputs[str(copied)] = sha
        prior["compiled_inputs_sha256"] = copied_inputs
        receipt = root / "prior.json"
        receipt.write_text(json.dumps(prior))
        producer = root / PRODUCER.relative_to(ROOT)
        spec = importlib.util.spec_from_file_location("smp_private_reuse", producer)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        if target == "source":
            copied = root / "shizukudos/kernel64/main.c"
            copied.write_bytes(copied.read_bytes() + b"\n/* private changed C input */\n")
        elif target == "artifact":
            copied = next(Path(name) for name in copied_inputs if name.endswith("KERNEL64S.BIN"))
            copied.write_bytes(copied.read_bytes() + b"private changed artifact")
        captured = runner.capture_sources()
        before = {name: hashlib.sha256(data).hexdigest() for name, data in captured.items()}
        try:
            kernel, stub, provenance = runner.reuse_compiled(receipt, before, prior["tools"], root / "successor")
            outcome = "source/tool-bound real compiled inputs copied"
            valid = target is None and all(Path(name).read_bytes() == (root / "original-inputs" / Path(name).name).read_bytes()
                                         for name in (kernel["bin"], kernel["elf"], stub["elf"]))
        except SystemExit as exc:
            outcome = str(exc)
            valid = target is not None and "reuse rejected" in outcome
        except AttributeError:
            outcome, valid = "compiled input reuse guard missing", False
        return {"target": target, "actual": outcome, "expected_behavior": bool(valid)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    results = [trial(None), trial("shizukudos/kbuild.py"), trial("shizukudos/tools/shzlib.py")]
    reuse = [reuse_trial(None), reuse_trial("source"), reuse_trial("artifact")]
    passed = all(row["expected_behavior"] for row in results + reuse)
    receipt = {"status": "PASS" if passed else "FAIL", "scope": "real producer private-copy helper bytes; persistent replacement after execution, before snapshot; compiler boundary mocked; no VM",
               "producer_sha256": hashlib.sha256(PRODUCER.read_bytes()).hexdigest(),
               "test_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": results, "reuse_cases": reuse}
    (args.out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
