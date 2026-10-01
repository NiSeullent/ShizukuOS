#!/usr/bin/env python3
"""Build the actual Win9x RunLoop backend fixture; never certify WebKit.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_imports(dump):
    modules = {}
    current = None
    for line in dump.splitlines():
        match = re.match(r"\s*DLL Name: (.+)", line)
        if match:
            current = match.group(1).upper()
            modules[current] = []
            continue
        # Binutils prints either vma/hint/name or vma/ordinal/hint/name.
        match = re.match(
            r"\s*[0-9a-fA-F]+\s+(?:<none>\s+)?[0-9a-fA-F]+\s+"
            r"([A-Za-z_?@$][A-Za-z0-9_?@$]*)\s*$", line)
        if current and match:
            modules[current].append(match.group(1))
    if not modules or not all(modules.values()):
        raise ValueError("No complete named import table was decoded")
    return modules


def main():
    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exports", type=Path, required=True,
                        help="Exact Windows 98 native-export manifest")
    parser.add_argument("--cc", default="i686-w64-mingw32-gcc")
    parser.add_argument("--objdump", default="i686-w64-mingw32-objdump")
    args = parser.parse_args()
    output = args.output.resolve()
    if output == directory or directory in output.parents:
        parser.error("Build output must be outside the port source directory")
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = args.exports.resolve()
    manifest = json.loads(manifest_path.read_text())
    exports = manifest["dlls"]
    pins = json.loads((directory / "source-pin.json").read_text())
    patch = directory / pins["patch"]
    if digest(patch) != pins["patch_sha256"]:
        raise ValueError("Pinned port patch has changed; review its pin metadata")
    executable = output / "RUNLOOP.EXE"
    flags = ["-std=gnu11", "-Os", "-Wall", "-Wextra", "-Werror",
             "-march=pentium3", "-static", "-static-libgcc",
             "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400"]
    command = [args.cc, *flags, str(directory / pins["native_fixture"]),
               "-o", str(executable), "-luser32"]
    compile_run = subprocess.run(command, text=True, capture_output=True)
    (output / "build.log").write_text(compile_run.stdout + compile_run.stderr)
    compile_run.check_returncode()
    dump = subprocess.run([args.objdump, "-p", str(executable)],
                          text=True, capture_output=True, check=True).stdout
    (output / "RUNLOOP.imports.txt").write_text(dump)
    imports = read_imports(dump)
    missing = {}
    for module, names in imports.items():
        available = exports.get(module, [])
        if isinstance(available, dict):
            available = available.get("exports", [])
        absent = sorted(set(names) - set(available))
        if absent:
            missing[module] = absent
    source_hashes = {name: digest(directory / name) for name in
                     [pins["new_header"], pins["native_fixture"], pins["patch"]]}
    receipt = {
        "schema": "iewebkit-win98-runloop-build-v1",
        "target": "Windows 98 Win32 x86 (actual guest version gate: 4.10)",
        "binary_sha256": digest(executable),
        "bytes": executable.stat().st_size,
        "upstream_commit": pins["upstream_commit"],
        "upstream_sha256": pins["upstream_sha256"],
        "source_sha256": source_hashes,
        "exports_manifest_sha256": digest(manifest_path),
        "compile_argv": command,
        "imports": imports,
        "import_count": sum(map(len, imports.values())),
        "missing_exports": missing,
        "import_gate": "FAIL" if missing else "PASS",
        "guest_behavior": "NOT-RUN",
        "full_engine": False,
        "linked_WTF_archive": False,
        "engine_provider_built": False,
        "guest_log_default": "C:\\GOPLAB\\RL9X.LOG",
    }
    (output / "RUNLOOP.receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt[key] for key in
                      ["binary_sha256", "bytes", "import_count", "import_gate",
                       "guest_behavior", "full_engine"]}))
    if receipt["bytes"] > 1024 * 1024:
        raise ValueError("Fixture exceeds the bounded guest input limit")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
