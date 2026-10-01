#!/usr/bin/env python3
"""Bind actual CMake-produced engine objects to source and configuration hashes.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
This records compilation and import symbols, never native engine execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    source = work / "webkitgtk-2.54.0"
    build = work / "build-jsc-win9x"
    compile_path = build / "compile_commands.json"
    commands = json.loads(compile_path.read_text())
    pins = json.loads((HERE / "core_memory_pin.json").read_text())
    loop = json.loads((HERE / "source-pin.json").read_text())
    expected = {item["path"]: item["after_sha256"] for item in pins["files"]}
    expected[loop["upstream_file"]] = loop["modified_sha256"]
    unsupported = (
        "GlobalMemoryStatusEx", "CreateMemoryResourceNotification",
        "QueryMemoryResourceNotification", "RegisterWaitForSingleObject",
        "UnregisterWaitEx", "GetProcessMemoryInfo", "QueryWorkingSet",
        "RegisterClassW", "CreateWindowExW",
    )
    objects = []
    for relative, source_hash in expected.items():
        path = source / relative
        if digest(path) != source_hash:
            raise ValueError("Actual object source differs from its frozen source pin: " + relative)
        matches = [item for item in commands if Path(item["file"]).resolve() == path.resolve()]
        if len(matches) != 1:
            raise ValueError("Source lacks exactly one real generated compile command: " + relative)
        entry = matches[0]
        output = entry.get("output")
        if not output:
            import shlex
            argv = shlex.split(entry["command"])
            output = argv[argv.index("-o") + 1]
        artifact = Path(entry["directory"]) / output
        symbols = subprocess.run(["i686-w64-mingw32-nm", "-u", str(artifact)],
                                 check=True, capture_output=True, text=True).stdout.splitlines()
        violations = [line for line in symbols if any(api in line for api in unsupported)]
        objects.append({"source": relative, "source_sha256": source_hash,
                        "compile_command": entry, "object": str(artifact),
                        "object_sha256": digest(artifact), "bytes": artifact.stat().st_size,
                        "undefined_symbols": symbols, "unsupported_symbols": violations})
    inputs = [HERE / "core_memory_pin.json", HERE / "source-pin.json",
              HERE / "core_profile.json", build / "cmakeconfig.h", compile_path,
              work / "actual-memory-objects.log", work / "actual-runloop-build.log",
              source / "Source/WTF/wtf/win/core_MemoryWin9x.h",
              source / "Source/WTF/wtf/win/RunLoopWin9x.h"]
    receipt = {"schema": "iewebkit-real-cmake-object-compile-v2",
               "source_commit": pins["upstream_commit"],
               "inputs": [{"path": str(path), "sha256": digest(path)} for path in inputs],
               "objects": objects,
               "legacy_api_symbol_gate": "PASS" if not any(item["unsupported_symbols"] for item in objects) else "FAIL",
               "native_engine_execution": "NOT-VERIFIED", "full_renderer": "NOT-BUILT"}
    output = work / "actual-cmake-objects-v2.json"
    if output.exists():
        raise FileExistsError("Preserve the existing immutable object receipt")
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"receipt": str(output), "sha256": digest(output),
                      "legacy_api_symbol_gate": receipt["legacy_api_symbol_gate"]}))
    if receipt["legacy_api_symbol_gate"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
