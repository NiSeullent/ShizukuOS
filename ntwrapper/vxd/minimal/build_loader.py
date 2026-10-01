#!/usr/bin/env python3
"""Build an explicitly selected fixture's byte-verifying V86 loader COM.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from validate import decode

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TEMPLATE = HERE.parent / "dos_loader_diag.asm"
VARIANTS = ("original-flags", "shared-data", "shared-both", "shared-nonresident",
            "all-executable", "ddb-first", "watcom-le")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(variant: str) -> dict:
    if variant not in VARIANTS:
        raise ValueError("an explicit fixture variant is required")
    candidate_path = HERE / "build" / variant / "NTWMIN9X.VXD"
    receipt_path = (HERE / "build/watcom-le/build-result.json" if variant == "watcom-le"
                    else HERE / "build/build-result.json")
    receipt_bytes = receipt_path.read_bytes()
    original = json.loads(receipt_bytes)
    candidate = candidate_path.read_bytes()
    recorded = original["files"][variant]
    if len(candidate) != recorded["bytes"] or digest(candidate) != recorded["sha256"]:
        raise ValueError("fixture bytes do not match the fixture build receipt")
    if variant == "watcom-le":
        from validate_watcom import decode as toolchain_decode
        decoded = toolchain_decode(candidate)
    else:
        decoded = decode(candidate)
    if decoded["module_name"] != "NTWMIN9X":
        raise ValueError("unexpected fixture device name")
    template = TEMPLATE.read_bytes()
    text = template.decode("ascii")
    substitutions = {
        "C:\\NTWLAB\\NTWLDR.LOG": "C:\\VXDLAB\\MINLDR.LOG",
        "C:\\NTWLAB\\NTWRAP9X.VXD": "C:\\VXDLAB\\NTWMIN9X.VXD",
        "driver_name: db 'NTWRAP9X',0": "driver_name: db 'NTWMIN9X',0",
        "heading: db 'NTWLDR FORMAT=1'": "heading: db 'MINLDR FORMAT=1'",
        "PREFLIGHT=EXACT_9390_BYTES_AND_EOF": f"PREFLIGHT=EXACT_{len(candidate)}_BYTES_AND_EOF",
    }
    for before, after in substitutions.items():
        if text.count(before) != 1:
            raise ValueError(f"unexpected diagnostic template occurrence: {before}")
        text = text.replace(before, after)
    out = candidate_path.parent / "guest"
    out.mkdir(exist_ok=True)
    (out / "expected.vxd").write_bytes(candidate)
    (out / "NTWMIN9X.VXD").write_bytes(candidate)
    (out / "expected.inc").write_text(
        f"%define EXPECTED_SIZE {len(candidate)}\n"
        f'%define EXPECTED_SHA256 "{digest(candidate)}"\n', encoding="ascii")
    assembly = out / "MINLDR.asm"
    assembly.write_text(text, encoding="ascii")
    command = ["nasm", "-f", "bin", "-Wall", "-Werror", "-I", str(out) + "/",
               "-l", str(out / "MINLDR.lst"), "-o", str(out / "MINLDR.COM"), str(assembly)]
    subprocess.run(command, check=True, capture_output=True, text=True)
    code = (out / "MINLDR.COM").read_bytes()
    if not len(candidate) < len(code) < 0xfe00 or code.count(candidate) != 1:
        raise ValueError("unexpected COM size or embedded fixture multiplicity")
    disassembly = subprocess.check_output(["ndisasm", "-b", "16", "-o", "0x100", str(out / "MINLDR.COM")])
    (out / "MINLDR.disasm").write_bytes(disassembly)
    if (candidate_path.read_bytes() != candidate or receipt_path.read_bytes() != receipt_bytes
            or TEMPLATE.read_bytes() != template):
        raise ValueError("diagnostic input changed during build")
    sources = {str(p.relative_to(ROOT)): digest(p.read_bytes())
               for p in (Path(__file__), HERE / "validate.py", TEMPLATE)}
    if variant == "watcom-le":
        sources[str((HERE / "validate_watcom.py").relative_to(ROOT))] = digest((HERE / "validate_watcom.py").read_bytes())
    result = {
        "schema": 1, "kind": "isolated-fixture-v86-loader-build", "variant": variant,
        "native_execution_verified": False, "production_driver_modified": False,
        "sources": sources, "template_substitutions": substitutions,
        "fixture_build_receipt_sha256": digest(receipt_bytes),
        "candidate": {"bytes": len(candidate), "sha256": digest(candidate), "name": "NTWMIN9X"},
        "command": command, "nasm": subprocess.check_output(["nasm", "-v"], text=True).strip(),
        "outputs": {name: {"bytes": (out / name).stat().st_size,
                           "sha256": digest((out / name).read_bytes())}
                    for name in ("MINLDR.asm", "MINLDR.COM", "MINLDR.lst", "MINLDR.disasm",
                                 "expected.vxd", "expected.inc", "NTWMIN9X.VXD")},
        "guest": {"directory": "C:\\VXDLAB", "program": "MINLDR.COM", "log": "MINLDR.LOG",
                  "requires": "installed Windows 98 DOS session with VXDLDR; new private disk per variant",
                  "ownership": "unload only after raw CF=0 and AX=0 from this load",
                  "watchdog_required": True},
    }
    (out / "build-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=VARIANTS, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.variant), indent=2, sort_keys=True))
