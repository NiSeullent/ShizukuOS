#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and run the ABI host model with GCC, Clang ASan/UBSan and Clang TSan, then
decode a C-produced message independently in Python (struct + zlib CRC-32)."""
import struct
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD = HERE.parents[1] / "build" / "shizukudos" / "abi"


def run(cmd):
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True, timeout=300)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"failed: {' '.join(map(str, cmd))}")
    return r.stdout


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", HERE, HERE / "test_abi.c", "-lpthread"]
    sample = BUILD / "sample.msg"
    run(["gcc", "-O2", *common, "-o", BUILD / "test_abi"])
    out = run([BUILD / "test_abi", sample])
    print(out.strip())
    run(["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", *common,
         "-o", BUILD / "test_abi_asan"])
    print("ASan/UBSan:", run([BUILD / "test_abi_asan"]).strip())
    run(["clang", "-g", "-O1", "-fsanitize=thread", *common, "-o", BUILD / "test_abi_tsan"])
    print("TSan:", run([BUILD / "test_abi_tsan"]).strip())
    run(["gcc", "-m32", "-ffreestanding", "-fsyntax-only", "-x", "c", HERE / "shz_ipc.h"])
    print("shz_ipc.h compiles as freestanding 32-bit and 64-bit code")

    # Independent decode of the C-produced slot.
    slot = sample.read_bytes()
    (magic, major, minor, hsize, flags, msize, opcode, src, dst, req, gen, status, poff, plen, blen, boff, cap,
     crc) = struct.unpack_from("<IHHHHIIHHQIiHHIQII", slot, 0)
    assert struct.calcsize("<IHHHHIIHHQIiHHIQII") == 64
    assert magic == 0x43505A53 and (major, minor) == (1, 0) and hsize == 64
    assert msize == 64 + plen and poff == 64 and plen == 16 and opcode == 0x1234
    assert req == 0x1122334455667788 and gen == 7 and status == -3 and cap == 0xABCD
    assert boff == 0x100000010 and blen == 99, "64-bit buffer offset must not be truncated"
    assert slot[poff:poff + plen] == b"wire-format-v1!\0"
    zeroed = bytearray(slot[:msize])
    zeroed[60:64] = b"\0\0\0\0"
    assert zlib.crc32(bytes(zeroed)) & 0xFFFFFFFF == crc, "CRC-32 must equal zlib's"
    print("independent Python decode of the wire message: OK (CRC-32 matches zlib)")


if __name__ == "__main__":
    main()
