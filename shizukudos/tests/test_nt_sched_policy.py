#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the actual priority projection, with fresh bounded host evidence.

No runtime wiring, download, VM, private media, NAS or client configuration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("choose a fresh output directory; prior evidence is retained")
    out.mkdir(parents=True)
    header = ROOT / "shizukudos/kcommon/nt_sched_policy.h"
    fixture = Path(__file__).with_suffix(".c")
    paths = [header, fixture, Path(__file__).resolve()]
    snapshots = {path: path.read_bytes() for path in paths}
    for path, data in snapshots.items():
        frozen = out / "frozen" / path.relative_to(ROOT)
        frozen.parent.mkdir(parents=True, exist_ok=True)
        frozen.write_bytes(data)
    compilers = {name: Path(shutil.which(name)).resolve() for name in ("gcc", "clang")}
    compiler_bytes = {name: path.read_bytes() for name, path in compilers.items()}
    artifacts = {}
    result = {"status": "FAIL", "scope": "Production helper host projection only; no runtime or native Windows acceptance",
              "source_sha256": {str(path.relative_to(ROOT)): digest(data) for path, data in snapshots.items()},
              "compilers": {name: {"path": str(path), "sha256": digest(compiler_bytes[name])}
                            for name, path in compilers.items()},
              "records": [], "artifacts_sha256": {}, "guest_executed": False, "runtime_wired": False}

    def stable():
        return all(path.exists() and path.read_bytes() == data for path, data in snapshots.items()) and all(
            compilers[name].read_bytes() == data for name, data in compiler_bytes.items()) and all(
            path.exists() and path.read_bytes() == data for path, data in artifacts.items())

    def run(command, name):
        argv = list(map(str, command))
        if not stable():
            process = subprocess.CompletedProcess(argv, 125, "", "source/compiler/artifact changed; refused\n")
        else:
            try:
                process = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired as error:
                def decoded(value):
                    return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
                process = subprocess.CompletedProcess(argv, 124, decoded(error.stdout),
                    decoded(error.stderr) + "bounded process timeout after 30 seconds\n")
        output = process.stdout + process.stderr
        (out / (name + ".log")).write_text(output)
        result["records"].append({"name": name, "command": argv, "returncode": process.returncode,
                                  "stdout": process.stdout, "stderr": process.stderr})
        print(name, process.returncode, output.strip()[-1000:], flush=True)
        return process

    def pin(path):
        artifacts[path] = path.read_bytes()
        result["artifacts_sha256"][path.name] = digest(artifacts[path])

    passed = True
    for name, flags in (("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined",
                                                   "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])):
        binary = out / ("nt-sched-policy-" + name)
        process = run([compilers[name], "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", *flags,
                       fixture, "-o", binary], "compile-" + name)
        passed = process.returncode == 0 and passed
        if process.returncode == 0:
            pin(binary)
            process = run([binary], "run-" + name)
            count = re.search(r"NT_SCHED_POLICY_HOST: (\d+) checks, (\d+) failures", process.stdout)
            result["records"][-1]["checks"] = int(count[1]) if count else None
            result["records"][-1]["failures"] = int(count[2]) if count else None
            passed = process.returncode == 0 and count is not None and int(count[2]) == 0 and passed

    # Compile a small real consumer for both kernel ABIs. It invokes both
    # production entry points without libc or a test-only replacement mapper.
    consumer = out / "freestanding-consumer.c"
    consumer.write_text('#include "nt_sched_policy.h"\n'
        'shz_nt_sched_result_t project_win(uint32_t c,int32_t p,shz_nt_sched_projection_t *o)\n'
        '{return shz_nt_sched_from_win32(c,p,o);}\n'
        'shz_nt_sched_result_t project_nt(uint32_t c,int32_t p,shz_nt_sched_projection_t *o)\n'
        '{return shz_nt_sched_from_base_increment(c,p,o);}\n')
    pin(consumer)
    for name, abi in (("i486", ["-m32", "-march=i486", "-mno-sse", "-mno-mmx", "-msoft-float"]),
                      ("x64", ["-m64", "-march=x86-64", "-mcmodel=kernel", "-mno-red-zone", "-mgeneral-regs-only"])):
        obj = out / ("nt-sched-policy-" + name + ".o")
        process = run([compilers["gcc"], "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
                       "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                       *abi, "-I", header.parent, "-c", consumer, "-o", obj], "compile-" + name)
        passed = process.returncode == 0 and passed
        if process.returncode == 0:
            pin(obj)
            process = run(["nm", "-u", obj], "unresolved-" + name)
            passed = process.returncode == 0 and not process.stdout.strip() and passed

    result["source_compiler_artifact_stable"] = stable()
    passed = result["source_compiler_artifact_stable"] and passed
    result["status"] = "PASS_HOST_NT_PRIORITY_PROJECTION_NOT_WIRED" if passed else "FAIL"
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
