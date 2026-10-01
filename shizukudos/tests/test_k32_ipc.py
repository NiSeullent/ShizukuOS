#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile and exercise the production Kernel32 IPC endpoint on the host.

Only fresh local artifacts and bounded compiler/test processes are created.
No download, package install, VM, service or client configuration changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CASES = ("head", "magic", "slots", "size", "malformed", "refill", "normal")
K32_FLAGS = ["-m32", "-march=i486", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
             "-fno-builtin", "-fno-pic", "-fno-pie", "-mno-sse", "-mno-mmx", "-msoft-float",
             "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-ident", "-fno-common",
             "-mpreferred-stack-boundary=2", "-fwrapv", "-fno-strict-aliasing", "-fno-tree-loop-distribute-patterns"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("choose a fresh output directory to preserve earlier evidence")
    out.mkdir(parents=True)
    source = ROOT / "shizukudos/kernel32/ipc.c"
    fixture = ROOT / "shizukudos/kernel32/tests/test_ipc_host.c"
    # This fixture includes the complete original translation unit, not copied
    # endpoint bodies. Preserve that input and its complete current project closure.
    paths = [source, fixture, Path(__file__).resolve(), ROOT / "shizukudos/kernel32/k32.h",
             ROOT / "shizukudos/kcommon/khc.h", ROOT / "shizukudos/abi/shz_abi.h", ROOT / "shizukudos/abi/shz_ipc.h"]
    snapshots = {p: p.read_bytes() for p in paths}
    before = {str(p.relative_to(ROOT)): digest(b) for p, b in snapshots.items()}
    compilers = {cc: Path(shutil.which(cc)).resolve() for cc in ("gcc", "clang")}
    compiler_bytes = {cc: p.read_bytes() for cc, p in compilers.items()}
    receipt = {"status": "FAIL", "sources_sha256": before, "runs": [], "binaries_sha256": {},
               "compilers": {cc: {"path": str(compilers[cc]), "sha256": digest(b)}
                             for cc, b in compiler_bytes.items()},
               "guest_executed": False, "production_translation_unit": str(source.relative_to(ROOT))}
    binaries = {}

    def stable():
        return all(p.exists() and p.read_bytes() == b for p, b in snapshots.items()) and all(
            compilers[cc].read_bytes() == b for cc, b in compiler_bytes.items()) and all(
            p.exists() and p.read_bytes() == b for p, b in binaries.items())

    def run(command, name):
        if not stable():
            result = subprocess.CompletedProcess(command, 125, "", "input changed; refused\n")
        else:
            try:
                result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired as error:
                def decoded(value):
                    return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
                result = subprocess.CompletedProcess(command, 124, decoded(error.stdout),
                                                     decoded(error.stderr) + "runner timeout after 30 seconds\n")
        output = result.stdout + result.stderr
        (out / (name + ".log")).write_text(output)
        receipt["runs"].append({"name": name, "command": list(map(str, command)),
                                "returncode": result.returncode, "output": output})
        print(name, result.returncode, output.strip()[-800:], flush=True)
        return result.returncode == 0

    passed = True
    for cc, extra in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        exe = out / ("ipc-" + cc)
        command = [compilers[cc], "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", *extra, fixture, "-o", exe]
        built = run(command, "build-" + cc)
        passed = built and passed
        if built:
            binaries[exe] = exe.read_bytes()
            receipt["binaries_sha256"][exe.name] = digest(binaries[exe])
            for case in CASES:
                passed = run([exe, case], cc + "-" + case) and passed
    obj = out / "ipc-i486.o"
    passed = run([compilers["gcc"], *K32_FLAGS, "-c", source, "-o", obj], "build-i486") and passed
    if obj.exists():
        binaries[obj] = obj.read_bytes()
        receipt["binaries_sha256"][obj.name] = digest(binaries[obj])
    receipt["source_compiler_binary_before_after_match"] = stable()
    passed = receipt["source_compiler_binary_before_after_match"] and passed
    receipt["status"] = "PASS_HOST_KERNEL32_IPC_RECEIVE_CONTRACT" if passed else "FAIL"
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
