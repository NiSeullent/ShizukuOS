#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the complete object manager and exact mutant syscall cases on the host."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def function(text, name):
    match = re.search(r"^static int32_t " + name + r"\([^;]*?\)\n\{", text, re.M)
    if not match:
        raise ValueError(name)
    start = text.index("{", match.start())
    depth = 0
    for pos in range(start, len(text)):
        depth += (text[pos] == "{") - (text[pos] == "}")
        if not depth:
            return text[match.start():pos + 1] + "\n"
    raise ValueError("unterminated " + name)


def structure(text, prefix, suffix):
    start = text.index(prefix)
    return text[start:text.index(suffix, start) + len(suffix)] + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--before-dir", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    kernel = root / "shizukudos/kernel64"
    inputs = [kernel / name for name in ("objects.c", "sysx.c", "proc_internal.h")]
    pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    args.out.mkdir(parents=True, exist_ok=True)
    cases = [("current", kernel)]
    if args.before_dir:
        cases.append(("old-counterfactual", args.before_dir))
    rows = []
    for label, directory in cases:
        out = args.out / label
        out.mkdir(exist_ok=True)
        header = (directory / "proc_internal.h").read_text()
        objects = (directory / "objects.c").read_text()
        sysx = (directory / "sysx.c").read_text()
        structs = (structure(header, "enum { OB_NONE", "};") +
                   structure(header, "struct kobject {", "\n};") +
                   structure(header, "typedef struct waitblock {", "} waitblock_t;"))
        attrs = structure(sysx, "struct objattr {", "};") + structure(sysx, "struct ustr {", "};")
        statuses = "\n".join(line for line in (kernel / "ntsys.h").read_text().splitlines()
                             if line.startswith("#define STATUS_"))
        (out / "mutant_structures.inc").write_text(statuses + "\n" + structs + attrs)
        body = objects.replace('#include "proc_internal.h"', "")
        start = sysx.index("    case SYS_NtCreateMutant:")
        end = sysx.index("    case SYS_NtCreateSemaphore:", start)
        wrapper = (function(sysx, "object_name") + function(sysx, "give_handle") +
                   "static int32_t mutant_syscall(process_t *p, unsigned num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)\n"
                   "{ int32_t st; switch (num) {\n" + sysx[start:end] +
                   "default: return STATUS_INVALID_PARAMETER; } }\n")
        (out / "mutant_production.inc").write_text(body + "\n" + wrapper)
        for compiler, flags in [("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
            binary = out / ("test-" + compiler)
            command = [compiler, *flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(out),
                       str(Path(__file__).with_suffix(".c")), "-o", str(binary)]
            for cmd in [command, [str(binary)] + (["old-counterfactual"] if label != "current" else [])]:
                run = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                row = {"case": label, "command": cmd, "exit": run.returncode, "stdout": run.stdout, "stderr": run.stderr}
                rows.append(row)
                expected = 2 if label != "current" and cmd[0] == str(binary) else 0
                if run.returncode != expected:
                    (args.out / "host-result.json").write_text(json.dumps({"status": "FAIL", "records": rows}, indent=2) + "\n")
                    print(run.stdout + run.stderr)
                    return 1
            print(rows[-1]["stdout"], end="")
    assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == pin for path, pin in pins.items())
    (args.out / "host-result.json").write_text(json.dumps({"status": "PASS", "production_source_sha256": pins,
        "records": rows, "old_counterfactual_reproduced": bool(args.before_dir), "guest_executed": False}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
