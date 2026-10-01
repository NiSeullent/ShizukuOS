#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build genuine TaskDialog against frozen runtime import libraries; check PE ABI.

This is a host compile/export/dependency check. The actual modal/control behavior
is exercised separately by T_TASKDIALOG.EXE inside the guest.
"""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

import pefile
from test_wsock32_host import pe_exports


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-libs", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    out = args.build_dir or Path(tempfile.mkdtemp(prefix="shz-taskdialog-"))
    out.mkdir(parents=True, exist_ok=True)
    w64 = Path(__file__).resolve().parent.parent
    module = w64 / "dlls" / "comctl32"
    sources = sorted(module.glob("*.c"))
    cfg = json.loads((module / "module.json").read_text())
    inputs = [*sources, module / "module.json", *w64.joinpath("include").glob("*.h")]
    for name in ("user32", "kernel32", "ntdll"):
        inputs += [args.runtime_libs / f"lib{name}.a", args.runtime_libs / f"{name}.dll"]
    before = {str(p): digest(p) for p in inputs}
    names = sorted({m.group(1) for source in sources
                    for m in re.finditer(r"^DLLAPI\s[^;{()]*?\b(\w+)\s*\(", source.read_text(), re.M)})
    definition = out / "comctl32.def"
    definition.write_text("LIBRARY comctl32.dll\nEXPORTS\n" + "\n".join(
        f"  {name} @{cfg['ordinals'][name]}" if name in cfg["ordinals"] else "  " + name for name in names) + "\n")
    dll = out / "comctl32.dll"
    command = ["x86_64-w64-mingw32-gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
               "-fno-stack-protector", "-mno-red-zone", "-shared", "-nostdlib", "-Wl,--entry,DllMain",
               "-I", str(w64 / "include"), *map(str, sources), str(definition), "-L", str(args.runtime_libs),
               "-luser32", "-lkernel32", "-lntdll", "-lgcc", "-o", str(dll)]
    subprocess.run(command, check=True, timeout=60)
    exports = pe_exports(dll)
    assert exports["TaskDialog"]["ordinal"] == 344 and exports["TaskDialogIndirect"]["ordinal"] == 345
    assert not exports["TaskDialog"]["forwarder"] and not exports["TaskDialogIndirect"]["forwarder"]
    pe = pefile.PE(str(dll))
    imports = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        name = entry.dll.decode("ascii").lower()
        provider = pefile.PE(str(args.runtime_libs / name))
        available = {symbol.name for symbol in provider.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name}
        actual = [symbol.name for symbol in entry.imports]
        assert all(symbol in available for symbol in actual), f"unresolved actual runtime imports: {name}"
        imports[name] = [symbol.decode("ascii") for symbol in actual]
        provider.close()
    pe.close()
    assert all(digest(Path(path)) == sha for path, sha in before.items()), "input changed during build"
    receipt = {"mode": "host-PE-export-and-real-runtime-import-check", "sources_and_dependencies": before,
               "dll_sha256": digest(dll), "exports": exports, "imports": imports, "command": command,
               "guest_modal_behavior": "not executed by this host check"}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("TaskDialog actual PE exports 344/345 and all runtime imports verified")
    print("Receipt:", out / "receipt.json")


if __name__ == "__main__":
    main()
