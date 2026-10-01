#!/usr/bin/env python3
"""Build isolated original LE fixtures; writes only minimal/build, starts no guest.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

HERE = Path(__file__).resolve().parent
OUT = HERE / "build"


def emit(payload, code_flags, data_flags, ddb_first=False):
    if len(payload) != 4176 or payload[4108:4116] != b"NTWMIN9X":
        raise ValueError("unexpected assembled payload")
    if ddb_first:
        # Keep the historical control instructions intact; change only layout.
        control = payload[:4096].rstrip(b"\0")
        payload = payload[4096:] + control
        payload += bytes(4176 - len(payload))
    dos = bytearray(128)
    struct.pack_into("<14H", dos, 0, 0x5a4d, 128, 1, 0, 4, 0, 0xffff,
                     0, 0x100, 0, 0, 0, 0x40, 0)
    struct.pack_into("<I", dos, 0x3c, 128)
    dos[64:69] = bytes.fromhex("b8014ccd21")
    header = bytearray(196)
    header[:2] = b"LE"

    def u16(at, value):
        struct.pack_into("<H", header, at, value)

    def u32(at, value):
        struct.pack_into("<I", header, at, value)

    u16(8, 3); u16(10, 4)
    u32(0x10, 0x38000); u32(0x14, 2)
    u32(0x28, 4096); u32(0x2c, 80)
    u32(0x40, 196); u32(0x44, 2)
    tables = bytearray(struct.pack("<12I", 4096, 0, code_flags, 1, 1, 0,
                                   80, 0, data_flags, 2, 1, 0))
    u32(0x48, 196 + len(tables))
    tables.extend(bytes.fromhex("0000010000000200"))
    u32(0x58, 196 + len(tables))
    tables.extend(b"\x08NTWMIN9X\x00\x00\x00")
    u32(0x5c, 196 + len(tables))
    tables.extend(struct.pack("<BBHBI", 1, 3, 1 if ddb_first else 2, 3, 0) + b"\x00")
    u32(0x38, len(tables))
    u32(0x68, 196 + len(tables))
    tables.extend(struct.pack("<3I", 0, 9 if ddb_first else 0, 9))
    u32(0x6c, 196 + len(tables))
    tables.extend(struct.pack("<BBhBI", 7, 0x10, 24, 1, 80 if ddb_first else 0))
    u32(0x70, 196 + len(tables)); u32(0x78, 196 + len(tables))
    tables.append(0)
    u32(0x30, 22); u32(0x80, 4096); u32(0x84, 2)
    u16(0xc0, 0); u16(0xc2, 0x040a)
    image = dos + header + tables
    image.extend(bytes(4096 - len(image)))
    image.extend(payload)
    return bytes(image)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    command = ["nasm", "-f", "bin", str(HERE / "control.asm"), "-o", str(OUT / "payload.bin")]
    subprocess.run(command, check=True)
    payload = (OUT / "payload.bin").read_bytes()
    variants = (
        ("original-flags", 0x2245, 0x2243, False),
        ("shared-data", 0x2245, 0x2263, False),
        ("shared-both", 0x2265, 0x2263, False),
        ("shared-nonresident", 0x2065, 0x2063, False),
        ("all-executable", 0x2265, 0x2267, False),
        ("ddb-first", 0x2267, 0x2267, True),
    )
    files = {}
    for name, code_flags, data_flags, ddb_first in variants:
        target = OUT / name / "NTWMIN9X.VXD"
        target.parent.mkdir(exist_ok=True)
        image = emit(payload, code_flags, data_flags, ddb_first)
        target.write_bytes(image)
        files[name] = {"path": str(target.relative_to(HERE)), "bytes": len(image),
                       "sha256": hashlib.sha256(image).hexdigest(),
                       "object_flags": [code_flags, data_flags], "ddb_first": ddb_first,
                       "guest_loaded": False}
    sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir()
               if p.is_file() and p.suffix in (".py", ".asm", ".md")}
    receipt = {"schema": 1, "scope": "isolated control-only LE/DDB fixture",
               "command": command, "nasm": subprocess.check_output(["nasm", "-v"], text=True).strip(),
               "sources_sha256": sources, "files": files, "native_loader_test": "not_run",
               "production_driver_modified": False}
    (OUT / "build-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
