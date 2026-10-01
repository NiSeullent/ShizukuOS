"""Require the native Windows 98 loader ABI for the bounded NPP mode guard."""
from __future__ import annotations
import json
import sys
from pathlib import Path
import pefile

ROOT = Path(__file__).resolve().parents[1]

def check(path: Path) -> list[str]:
    errors: list[str] = []
    with pefile.PE(str(path)) as pe:
        opt = pe.OPTIONAL_HEADER
        if pe.FILE_HEADER.Machine != 0x14C or opt.Magic != 0x10B or pe.is_dll():
            errors.append("expected PE32 i386 executable")
        if opt.Subsystem != 3 or (opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (4, 10):
            errors.append("expected native console subsystem 4.10")
        if opt.DllCharacteristics & (0x40 | 0x100):
            errors.append("unsupported ASLR/NX flags")
        for n, label in ((9, "TLS"), (13, "delay imports"), (14, "CLR")):
            if opt.DATA_DIRECTORY[n].VirtualAddress:
                errors.append("unexpected " + label)
        native = json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"]
        modules = set()
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            name = descriptor.dll.decode("ascii").upper()
            modules.add(name)
            if name not in {"KERNEL32.DLL", "ADVAPI32.DLL"}:
                errors.append("unexpected native module: " + name)
                continue
            symbols = {item.name.decode("ascii") if item.name else f"#{item.ordinal}" for item in descriptor.imports}
            missing = symbols - set(native[name])
            if missing:
                errors.append(f"{name} absent OEM imports: {sorted(missing)}")
        if modules != {"KERNEL32.DLL", "ADVAPI32.DLL"}:
            errors.append("expected KERNEL32/ADVAPI32 native imports")
    return errors

if __name__ == "__main__":
    failures = check(Path(sys.argv[1]))
    for item in failures:
        print("FAIL: " + item)
    if not failures:
        print("PASS: NPP exact-app mode guard uses only native Win98 OEM registry/file APIs")
    raise SystemExit(bool(failures))
