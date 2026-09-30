#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Builds the large test DLLs of known content for Kernel64's lazily mapped images (tests/run_k64_disk.py).

BIGLAZY.DLL: 320 MiB blob, preferred base 0x7fe000000000, linked WITHOUT DYNAMIC_BASE: the Kernel64 loader's ASLR
leaves such an image at its preferred base (free in every Win64 process), so this one is mapped lazily unrelocated.
BIGRELOC.DLL: 16 MiB blob, DYNAMIC_BASE, preferred base 0x140000000 = the base of the fixed-base test executable
T_LAZY.EXE, so the loader must relocate it (per page, lazily) whether or not ASLR picks another base first. Sources: shizukudos/win64/tests/lazy/biglazy.c; blob page i = SHA-256(b"shz-lazy-%d" % i) * 128.
Deterministic (no PE timestamp); outputs are cached by a key over the sources, sizes and the compiler version.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
from shzlib import BUILD, SHZ, run  # noqa: E402

SRC = SHZ / "win64" / "tests" / "lazy" / "biglazy.c"
CC = "x86_64-w64-mingw32-gcc"
DLLS = {"BIGLAZY.DLL": (320 << 20, 0x7fe000000000), "BIGRELOC.DLL": (16 << 20, 0x140000000)}
FIXED_BASE = {"BIGLAZY.DLL"}                            # no DYNAMIC_BASE: not moved by ASLR


def blob_page(i):
    return hashlib.sha256(b"shz-lazy-%d" % i).digest() * 128


def page_hash(page):
    """Host mirror of page_hash() in biglazy.c."""
    data = blob_page(page)
    h = 0x5348495a554b4136 ^ page
    for (w,) in struct.iter_unpack("<Q", data):
        h = (((h << 7) | (h >> 57)) & 0xffffffffffffffff) ^ w
    return h


def build(out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cc_version = subprocess.run([CC, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    key = hashlib.sha256(SRC.read_bytes() + Path(__file__).read_bytes() + cc_version.encode() +
                         json.dumps(DLLS).encode()).hexdigest()
    stamp = out_dir / "lazy-dlls.json"
    result = {name: out_dir / name for name in DLLS}
    if stamp.exists() and json.loads(stamp.read_text()).get("key") == key and all(p.exists() for p in result.values()):
        return result
    for name, (size, base) in DLLS.items():
        blob = out_dir / f"{name}.blob"
        with open(blob, "wb") as fh:
            for i in range(size // 4096):
                fh.write(blob_page(i))
        asm = out_dir / f"{name}.S"
        asm.write_text('    .section .lazyblob,"dr"\n    .p2align 12\n    .globl big_blob\n    .globl big_blob_end\n'
                       f'big_blob:\n    .incbin "{blob}"\nbig_blob_end:\n')
        run([CC, "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-shared",
             "-nostdlib", "-Wl,--entry,0", f"-Wl,--image-base,{base:#x}", "-Wl,--disable-dynamicbase" if name in FIXED_BASE else "-Wl,--dynamicbase",
             "-Wl,--no-insert-timestamp",
             "-Wl,--subsystem,console", str(SRC), str(asm), "-o", str(result[name])])
        blob.unlink()
    stamp.write_text(json.dumps({"key": key, "dlls": {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in result.items()}}))
    return result


if __name__ == "__main__":
    for n, p in build(BUILD / "lazy-dll").items():
        print(n, p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
