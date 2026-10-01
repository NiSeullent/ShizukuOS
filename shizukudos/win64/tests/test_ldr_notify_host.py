#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual LdrLoadDll/notification bodies, including optional old-source counterfactual."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def extract(source, name):
    match = re.search(r"^(?:SHZ_EXPORT NTSTATUS NTAPI|void) " + re.escape(name) + r"\([^;]*?\)\n\{", source, re.M)
    if not match:
        raise ValueError("missing exact production function " + name)
    start = source.index("{", match.start())
    depth = 0
    for offset in range(start, len(source)):
        depth += (source[offset] == "{") - (source[offset] == "}")
        if not depth:
            return source[match.start():offset + 1] + "\n"
    raise ValueError("unterminated production body")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--before-dir", type=Path)
    args = parser.parse_args()
    win64 = Path(__file__).resolve().parents[1]
    inputs = {"LdrLoadDll": win64 / "ntdll/ntdll_main.c", "ShzNotifyLoaded": win64 / "ntdll/ldr_search.c"}
    source_sha = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs.values()}
    args.out.mkdir(parents=True, exist_ok=True)
    cases = [("current", inputs)]
    if args.before_dir:
        cases.append(("old-counterfactual", {name: args.before_dir / (p.name + ".before") for name, p in inputs.items()}))
    rows, body_hashes = [], {}
    for label, paths in cases:
        directory = args.out / label
        directory.mkdir(exist_ok=True)
        bodies = {name: extract(p.read_text(), name) for name, p in paths.items()}
        body_hashes[label] = {name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()}
        # Notification is defined first so both old and new real signatures
        # are compiled consistently with each corresponding LdrLoadDll body.
        (directory / "ldr_notify_production.inc").write_text(bodies["ShzNotifyLoaded"] + bodies["LdrLoadDll"])
        for compiler, flags in [("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
            binary = directory / ("test-" + compiler)
            build = [compiler, *flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-I", str(directory),
                     str(win64 / "tests/test_ldr_notify_production.c"), "-o", str(binary)]
            for command in [build, [str(binary)]]:
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                rows.append({"case": label, "command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
                expected = 2 if label == "old-counterfactual" and command == [str(binary)] else 0
                if result.returncode != expected:
                    (args.out / "host-result.json").write_text(json.dumps({"status": "FAIL", "records": rows}, indent=2) + "\n")
                    print(result.stdout + result.stderr)
                    return 1
            print(rows[-1]["stdout"] + rows[-1]["stderr"], end="")
    assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == sha for p, sha in source_sha.items())
    (args.out / "host-result.json").write_text(json.dumps({"status": "PASS", "production_source_sha256": source_sha,
        "body_sha256": body_hashes, "records": rows, "old_counterfactual_reproduced": bool(args.before_dir), "guest_executed": False}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
