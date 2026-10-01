#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile production Kernel32 process/scheduler C with deterministic IRQ injection.

This host test observes actual runnable selection, syscall ownership and fault
completion. It substitutes privileged operations and allocators; guest execution
and the Windows 98 integration remain separate checks.
"""
import argparse
import hashlib
import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project_inputs(cc, flags, source, out, phase):
    # Ask the compiler which project files this exact host translation unit
    # reads. -MM excludes platform system headers; -no-pie is link-only.
    command = [cc, *(flag for flag in flags if flag != "-no-pie"), "-MM", "-MT", "publication", str(source)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (out / f"dependencies-{phase}.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"project dependency discovery failed ({result.returncode}); see dependencies-{phase}.log")
    body = result.stdout.replace("\\\n", "").split(":", 1)[1]
    paths = {Path(token).resolve() for token in shlex.split(body)}
    paths = {path for path in paths if path.is_relative_to(REPO.resolve())}
    paths.add(Path(__file__).resolve())
    return sorted(paths), command


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cc", default="gcc")
    ap.add_argument("--sanitize", action="store_true")
    ap.add_argument("--out", type=Path, default=REPO / "build/pma-k32-publication/host")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    source = HERE / "test_k32_publication.c"
    exe = args.out / "test_k32_publication"
    flags = ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fno-pie", "-no-pie", "-fno-builtin",
             "-Wno-pointer-to-int-cast", "-Wno-int-to-pointer-cast"]
    if args.sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    inputs, dependencies_before = project_inputs(args.cc, flags, source, args.out, "before")
    before = {str(p.relative_to(REPO)): digest(p) for p in inputs}
    cmd = [args.cc, *flags, str(source), "-o", str(exe)]
    compiled = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    (args.out / "compile.log").write_text(compiled.stdout + compiled.stderr)
    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=15) if compiled.returncode == 0 else None
    if run:
        (args.out / "run.log").write_text(run.stdout + run.stderr)
        print(run.stdout, end="")
        print(run.stderr, end="")
    else:
        print(compiled.stdout + compiled.stderr, end="")
    checks = [{"check": line.split(": ", 1)[1], "status": line.split(":", 1)[0]}
              for line in run.stdout.splitlines() if line.startswith(("PASS: ", "FAIL: "))] if run else []
    after_inputs, dependencies_after = project_inputs(args.cc, flags, source, args.out, "after")
    after = {str(p.relative_to(REPO)): digest(p) for p in after_inputs}
    stable = before == after
    okay = compiled.returncode == 0 and run is not None and run.returncode == 0 and bool(checks) and stable and all(
        check["status"] == "PASS" for check in checks)
    receipt = {"test": "k32-publication-production-c", "status": "PASS" if okay else "FAIL", "command": cmd,
               "compile_exit": compiled.returncode, "run_exit": run.returncode if run else None, "checks": checks,
               "sources_sha256": before, "sources_sha256_after": after, "inputs_stable": stable,
               "dependency_commands": [dependencies_before, dependencies_after],
               "executable_sha256": digest(exe) if compiled.returncode == 0 else None,
               "utc": datetime.now(timezone.utc).isoformat()}
    (args.out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(receipt["status"])
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
