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
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CASES = ("head", "magic", "slots", "size", "malformed", "refill", "normal")
PERSISTENT_CASES = ("persistent-head", "persistent-refill", "persistent-live")
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
    main_source = ROOT / "shizukudos/kernel32/main.c"
    fixture = ROOT / "shizukudos/kernel32/tests/test_ipc_host.c"
    # Snapshot project headers before asking the compiler for its exact closure.
    # A nested include changed during discovery must not acquire a later hash.
    paths = [source, main_source, fixture, Path(__file__).resolve()]
    snapshots = {p: p.read_bytes() for p in paths}
    initial_headers = {p.resolve(): p.read_bytes() for p in ROOT.rglob("*.h")
                       if ".git" not in p.parts and "build" not in p.parts and
                       p.resolve().is_relative_to(ROOT)}
    before = {str(p.relative_to(ROOT)): digest(b) for p, b in snapshots.items()}
    compilers = {cc: Path(shutil.which(cc)).resolve() for cc in ("gcc", "clang")}
    compiler_bytes = {cc: p.read_bytes() for cc, p in compilers.items()}
    receipt = {"status": "FAIL", "sources_sha256": before, "runs": [], "binaries_sha256": {},
               "compilers": {cc: {"path": str(compilers[cc]), "sha256": digest(b)}
                             for cc, b in compiler_bytes.items()},
               "guest_executed": False, "production_translation_unit": str(source.relative_to(ROOT))}
    binaries = {}
    helper_snapshots = {}
    receipt["project_dependencies"] = {}
    receipt["unbound_project_dependencies"] = []
    receipt["dependency_scope"] = "Compiler -MM project closure for host GCC, host Clang sanitizers and freestanding i486; system headers excluded."
    receipt["compiler_helpers_sha256"] = {}

    def stable():
        return all(p.exists() and p.read_bytes() == b for p, b in snapshots.items()) and all(
            compilers[cc].read_bytes() == b for cc, b in compiler_bytes.items()) and all(
            p.exists() and p.read_bytes() == b for p, b in binaries.items()) and all(
            p.exists() and p.read_bytes() == b for p, b in helper_snapshots.items())

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
    for cc, names in (("gcc", ("cc1", "collect2", "as", "ld")), ("clang", ("ld",))):
        for name in names:
            command = [compilers[cc], "-print-prog-name=" + name]
            if not run(command, "helper-" + cc + "-" + name):
                passed = False
                continue
            printed = receipt["runs"][-1]["output"].strip()
            helper = Path(shutil.which(printed) or printed).resolve()
            if not helper.is_file():
                passed = False
                continue
            helper_snapshots[helper] = helper.read_bytes()
            receipt["compiler_helpers_sha256"][str(helper)] = digest(helper_snapshots[helper])
    variants = (("host_gcc", "gcc", ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"], fixture),
                ("host_clang_asan_ubsan", "clang", ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                                                  "-fsanitize=address,undefined", "-fno-omit-frame-pointer"], fixture),
                ("i486", "gcc", K32_FLAGS, source),
                ("i486_main", "gcc", K32_FLAGS, main_source))
    for label, cc, flags, translation_unit in variants:
        command = [compilers[cc], *flags, "-MM", "-MT", "k32-inputs", translation_unit]
        if not run(command, "dependencies-" + label):
            passed = False
            continue
        dependencies = set()
        for line in receipt["runs"][-1]["output"].replace("\\\n", " ").splitlines():
            _, separator, names = line.partition(":")
            if not separator:
                passed = False
                continue
            for name in shlex.split(names):
                path = (ROOT / name).resolve()
                if not path.is_relative_to(ROOT):
                    continue
                original = snapshots.get(path, initial_headers.get(path))
                if original is None:
                    receipt["unbound_project_dependencies"].append(str(path.relative_to(ROOT)))
                    passed = False
                    continue
                snapshots[path] = original
                before[str(path.relative_to(ROOT))] = digest(original)
                dependencies.add(str(path.relative_to(ROOT)))
        receipt["project_dependencies"][label] = sorted(dependencies)
        passed = stable() and passed
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
            # The fixed ABI GPA lies in ASAN's shadow gap; use the unsanitized
            # GCC artifact for these real policy/channel/lifetime cases.
            if cc == "gcc":
                for case in PERSISTENT_CASES:
                    passed = run([exe, case], cc + "-" + case) and passed
    for name, translation_unit in (("ipc", source), ("main", main_source)):
        obj = out / (name + "-i486.o")
        passed = run([compilers["gcc"], *K32_FLAGS, "-c", translation_unit, "-o", obj],
                     "build-i486-" + name) and passed
        if obj.exists():
            binaries[obj] = obj.read_bytes()
            receipt["binaries_sha256"][obj.name] = digest(binaries[obj])
    receipt["persistent_service_scope"] = "Real service policy and IPC receive C; fixed ABI GPA; SESSION_END refusal followed by ECHO. Main lifetime polling compiled only."
    receipt["source_compiler_binary_before_after_match"] = stable()
    receipt["changed_project_inputs"] = [str(p.relative_to(ROOT)) for p, b in snapshots.items()
                                          if not p.exists() or p.read_bytes() != b]
    passed = receipt["source_compiler_binary_before_after_match"] and passed
    receipt["status"] = "PASS_HOST_KERNEL32_IPC_RECEIVE_CONTRACT" if passed else "FAIL"
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
