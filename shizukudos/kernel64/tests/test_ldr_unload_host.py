#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile exact loader production bodies against controlled host boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

FUNCTIONS = ["image_metadata_free", "image_owner_retire", "module_edges_free", "module_life_links", "module_edge",
             "module_incoming_remove", "module_loadcount", "module_lists_valid", "module_lists_unlink",
             "ldr_lifetime_control", "ldr_lifetime_commit"]


def extract(source, name):
    match = re.search(r"^(?:static )?(?:void|int|int32_t) " + re.escape(name) + r"\([^;]*?\)\n\{", source, re.M)
    if not match:
        raise ValueError("missing exact production function " + name)
    start = source.index("{", match.start())
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if not depth:
                return source[match.start():i + 1] + "\n"
    raise ValueError("unterminated production body " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    kernel = root / "kernel64"
    args.out.mkdir(parents=True, exist_ok=True)
    source = (kernel / "ldr.c").read_text()
    digest = hashlib.sha256(source.encode()).hexdigest()
    bodies = {name: extract(source, name) for name in FUNCTIONS}
    (args.out / "ldr_unload_production.inc").write_text("\n".join(bodies.values()))
    image_bodies = {name: extract(source, name) for name in ["image_metadata_free", "image_owner_retire", "ldr_image_fault"]}
    (args.out / "ldr_image_production.inc").write_text("\n".join(image_bodies.values()))
    rows = []
    for compiler, flags in [("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        for test in ["test_ldr_lifetime", "test_ldr_unload_backend", "test_ldr_image_retire"]:
            binary = args.out / (test + "-" + compiler)
            commands = [[compiler, *flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", str(args.out),
                         str(kernel / "tests" / (test + ".c")), "-o", str(binary)], [str(binary)]]
            for command in commands:
                p = subprocess.run(command, capture_output=True, text=True, timeout=90)
                rows.append({"command": command, "exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr})
                if p.returncode:
                    print(p.stdout + p.stderr)
                    (args.out / "host-result.json").write_text(json.dumps({"status": "FAIL", "records": rows}, indent=2) + "\n")
                    return 1
            print(rows[-1]["stdout"], end="")
    assert hashlib.sha256((kernel / "ldr.c").read_bytes()).hexdigest() == digest
    (args.out / "host-result.json").write_text(json.dumps({"status": "PASS", "production_ldr_sha256": digest,
        "body_sha256": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in (bodies | image_bodies).items()},
        "scope": "exact production bodies at controlled boundaries; actual callbacks/unmapping require separate guest",
        "records": rows, "qemu_used": False}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
