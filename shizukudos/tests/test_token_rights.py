#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise complete production token/security dispatch with real handle lifetimes.

Only hardware IRQ, scheduler-current-thread, authorization policy and user-memory/
heap boundaries are host adapters. Object create/ref/deref and handle
insert/lookup/ref/close are extracted
unchanged from objects.c. The complete sysk32_sec.c is compiled, with its fs.h
include replaced by those adapters. This is a Kernel64 host regression, not a
Windows 98/VMM or multi-user access-control acceptance test.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL = ROOT / "shizukudos/kernel64"
FIXTURE = Path(__file__).with_suffix(".c")


def definition(source, name):
    match = re.search(r"(?:^|\n)([^\n;{}]*\b" + name + r"\([^;{}]*\))\s*\{", source)
    if not match:
        raise ValueError(f"missing production function {name}")
    start = match.start(1)
    opening = match.end() - 1
    depth = 1
    for end in range(opening + 1, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if not depth:
            return source[start:end + 1]
    raise ValueError(f"unterminated production function {name}")


def source_for_host(objects=None):
    if objects is None:
        objects = (KERNEL / "objects.c").read_text()
    internal = (KERNEL / "proc_internal.h").read_text()
    object_layout = internal.split("struct kobject {", 1)[1].split("\n};", 1)[0]
    handles = re.search(r"typedef struct \{\s*kobject_t \*obj;\s*uint32_t access;\s*uint32_t inherit;\s*\} handle_entry_t;", internal).group(0)
    production_objects = "\n".join(definition(objects, name) for name in
                                    ("ob_create", "ob_ref", "ob_deref", "handle_insert", "handle_lookup", "handle_ref", "handle_close"))
    security = (KERNEL / "sysk32_sec.c").read_text()
    if security.count('#include "fs.h"') != 1:
        raise ValueError("production fs boundary include must occur exactly once")
    security = security.replace('#include "fs.h"', "/* Host boundary declarations precede this unmodified translation unit. */")
    security = security.replace('#include "auth_policy.h"', '/* Auth policy is an explicitly controlled host boundary below. */')
    frontend = (ROOT / "shizukudos/win64/ntdll/ntobj.c").read_text().replace('#include "ntdll_int.h"', '/* Host Windows type boundaries. */')
    fixture = FIXTURE.read_text()
    return (fixture.replace("/* @PRODUCTION_OBJECT_LAYOUT@ */", "struct kobject {" + object_layout + "\n};\n" + handles)
                   .replace("/* @PRODUCTION_OBJECT_FUNCTIONS@ */", production_objects)
                   .replace("/* @PRODUCTION_SECURITY_TRANSLATION_UNIT@ */", security)
                   .replace("/* @PRODUCTION_TOKEN_FRONTEND@ */", frontend))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/fd5c2-token")
    parser.add_argument("--compiler", choices=("all", "gcc", "clang"), default="all")
    parser.add_argument("--label", default="current")
    parser.add_argument("--baseline-objects", help="local immutable Git revision for extracted object/handle functions only")
    args = parser.parse_args()
    directory = args.output / args.label
    directory.mkdir(parents=True, exist_ok=True)
    paths = [FIXTURE, Path(__file__).resolve(), KERNEL / "sysk32_sec.c", KERNEL / "objects.c", KERNEL / "proc_internal.h"]
    paths += [ROOT / "shizukudos/abi/shz_token_ops.h", ROOT / "shizukudos/win64/ntdll/ntobj.c",
              KERNEL / "auth_policy.h"]
    before = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    baseline = None
    object_source = None
    if args.baseline_objects:
        baseline = subprocess.run(["git", "rev-parse", args.baseline_objects + "^{commit}"], cwd=ROOT,
                                  check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        object_source = subprocess.run(["git", "show", baseline + ":shizukudos/kernel64/objects.c"], cwd=ROOT,
                                       check=True, capture_output=True, text=True, timeout=10).stdout
    source = directory / "token_rights_host.c"
    source.write_text(source_for_host(object_source))
    compilers = [args.compiler] if args.compiler != "all" else ["gcc", "clang"]
    results = []
    for compiler in compilers:
        if not shutil.which(compiler):
            if args.compiler != "all":
                raise SystemExit(f"required compiler missing: {compiler}")
            continue
        binary = directory / (compiler + "-token-rights")
        extras = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if compiler == "clang" else []
        command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", *extras,
                   "-I", str(KERNEL), "-I", str(ROOT / "shizukudos/win64/ntdll"), str(source), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (directory / (compiler + "-compile.log")).write_text(compiled.stdout + compiled.stderr)
        if compiled.returncode:
            print(compiled.stderr)
            results.append({"compiler": compiler, "compile_exit": compiled.returncode})
            continue
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1")
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30, env=env)
        (directory / (compiler + "-run.log")).write_text(run.stdout + run.stderr)
        print(f"{compiler}:\n{run.stdout}{run.stderr}", end="")
        results.append({"compiler": compiler, "compile_exit": 0, "run_exit": run.returncode,
                        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()})
    after = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    receipt = {"source_sha256": before, "source_stable": before == after, "results": results,
               "generated_fixture_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "scope": "production Kernel64 host token/descriptor rights; no native Windows 98 acceptance"}
    if baseline:
        actual_objects_sha256 = hashlib.sha256(object_source.encode()).hexdigest()
        receipt.update(baseline_objects_commit=baseline,
                       live_objects_sha256=before["shizukudos/kernel64/objects.c"],
                       extracted_objects_sha256=actual_objects_sha256)
        receipt["source_sha256"]["shizukudos/kernel64/objects.c"] = actual_objects_sha256
    (directory / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if results and before == after and all(r.get("run_exit", 1) == 0 for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
