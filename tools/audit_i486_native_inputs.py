#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Supplement frozen native inputs with pinned full executable-byte decoding."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from i486_instruction_gate import scan

ROOT = Path(__file__).resolve().parents[1]
BOOT_BUILD = Path("/root/Win98-Modern-boot/build")
SOURCES = ["tools/i486_instruction_gate.py", "tests/test_i486_instruction_gate.py",
           "tools/audit_i486_native_inputs.py"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True,
                        help="Exact canonical owned EXE/DLL path=approved SHA256")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.absolute()
    require(out.resolve() == out and out.parent == ROOT / "build" and not out.exists(),
            "fresh direct owned build output required")
    require(1 <= len(args.input) <= 32, "bounded exact input set required")
    inputs = {}
    for argument in args.input:
        path_text, expected = argument.rsplit("=", 1)
        path = Path(path_text)
        require(path.is_absolute() and path.resolve() == path and path.is_file() and
                path.suffix.upper() in {".DLL", ".EXE"} and
                (path.is_relative_to(ROOT / "build") or path.is_relative_to(BOOT_BUILD)),
                "canonical owned native input required")
        require(str(path) not in inputs and re.fullmatch(r"[0-9a-f]{64}", expected),
                "duplicate input or invalid caller hash")
        require(0 < path.stat().st_size <= 1024 * 1024 and sha(path.read_bytes()) == expected,
                "native input differs from caller approval")
        inputs[str(path)] = expected
    sources = {name: (ROOT / name).read_bytes() for name in SOURCES}
    out.mkdir()
    for name, data in sources.items():
        destination = out / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    receipt = dict(schema=1, kind="pinned-i486-native-input-supplement", passed=False,
        source_sha256={n: sha(d) for n, d in sources.items()}, input_sha256=inputs,
        artifacts={}, native_execution=False, modern_web_standards=False,
        native_styles=False, native_paint=False, modern_apps=False, vm_operations=False)
    try:
        command = ["python3", "tests/test_i486_instruction_gate.py", "-v"]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=30,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        data = result.stdout + result.stderr
        require(len(data) <= 1024 * 1024, "bounded control log")
        log = out / "parser-controls.log"
        log.write_bytes(data)
        receipt["controls"] = dict(command=command, returncode=result.returncode,
                                   log=str(log), sha256=sha(data),
                                   actual_modern_after_no_operand_cases=27)
        require(result.returncode == 0, "actual parser controls failed")
        for i, (path, expected) in enumerate(inputs.items()):
            gate, data = scan(Path(path))
            require(gate["artifact_sha256"] == expected, "scanned different input")
            log = out / (str(i) + "-" + Path(path).name + "-disassembly.log")
            log.write_bytes(data)
            gate["log"] = str(log)
            receipt["artifacts"][path] = gate
        require(all(sha((ROOT / n).read_bytes()) == sha(d) for n, d in sources.items()) and
                all(sha(Path(p).read_bytes()) == d for p, d in inputs.items()), "source/input drift")
        receipt["passed"] = True
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(dict(result=str(out / "result.json"),
                          sha256=sha((out / "result.json").read_bytes()),
                          passed=True, native_execution=False)))


if __name__ == "__main__":
    main()
