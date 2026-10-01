#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Static PE32 gate against the project's actual Win98 OEM export inventory.

An import being present does not prove its runtime behavior. Passing this
gate is not a guest handshake, LoadLibrary pass, or OS integration claim.
"""
import hashlib
import json
from pathlib import Path
import sys

import pefile

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
EXPECTED = {"m98_tls_create", "m98_tls_handshake", "m98_tls_write", "m98_tls_read",
            "m98_tls_shutdown", "m98_tls_backend_error", "m98_tls_verify_flags",
            "m98_tls_is_established", "m98_tls_free"}


def inspect(path):
    out = path.parent / "native-import-gate.json"
    out.unlink(missing_ok=True)
    baseline = json.loads(BASELINE.read_text())
    issues, imports = [], {}
    with pefile.PE(str(path)) as pe:
        opt = pe.OPTIONAL_HEADER
        if pe.FILE_HEADER.Machine != 0x14C or opt.Magic != 0x10B or not pe.is_dll():
            issues.append("not an x86 PE32 DLL")
        if opt.Subsystem != 2 or (opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (4,10):
            issues.append("not Windows GUI subsystem 4.10")
        if pe.FILE_HEADER.TimeDateStamp != 0:
            issues.append("nonzero PE build timestamp")
        if opt.DllCharacteristics & (0x40|0x100):
            issues.append("ASLR/NX flags set")
        for index, name in ((9,"static TLS"),(13,"delay imports"),(14,"CLR")):
            if opt.DATA_DIRECTORY[index].VirtualAddress:
                issues.append(f"unexpected {name} directory")
        if not opt.DATA_DIRECTORY[5].VirtualAddress:
            issues.append("no base relocation directory")
        if not opt.AddressOfEntryPoint:
            issues.append("missing DLL entry point")
        exports = {s.name.decode("ascii") for s in getattr(pe,"DIRECTORY_ENTRY_EXPORT").symbols if s.name}
        if exports != EXPECTED:
            issues.append(f"unexpected exports: {sorted(exports)}")
        for desc in getattr(pe,"DIRECTORY_ENTRY_IMPORT",()):
            name = desc.dll.decode("ascii").upper()
            imports[name] = []
            if name not in ("KERNEL32.DLL", "MSVCRT.DLL"):
                issues.append(f"non-native dependency: {name}")
            native = set(baseline["dlls"].get(name,[]))
            for symbol in desc.imports:
                label = symbol.name.decode("ascii") if symbol.name else f"#{symbol.ordinal}"
                imports[name].append(label)
                if label not in native:
                    issues.append(f"not present in pinned Win98 OEM: {name}!{label}")
        result = {"passed": not issues, "issues": issues, "imports": imports,
                  "exports": sorted(exports), "dll_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "native_baseline_sha256": hashlib.sha256(BASELINE.read_bytes()).hexdigest(),
                  "iso_sha256": baseline["iso_sha256"], "guest_validated": False,
                  "os_schannel_integrated": False}
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build/tls13/pe32/M98TLS13.dll"
    result = inspect(path)
    print(json.dumps(result))
    raise SystemExit(0 if result["passed"] else 1)
