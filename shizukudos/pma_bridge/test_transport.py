#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the production PMA service over real ABI 1.1 SPSC rings.

Outputs are local host binaries and wire samples under build/shizukudos/pma-bridge.
No downloads, driver installation, VM operation or client configuration changes.
Host evidence does not establish an actual Windows 98 VMM connection.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import zlib

HERE = Path(__file__).resolve().parent
BUILD = HERE.parents[1] / "build" / "shizukudos" / "pma-bridge"


def run(command):
    result = subprocess.run([str(x) for x in command], capture_output=True,
                            text=True, timeout=120)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f"failed ({result.returncode}): {' '.join(map(str, command))}")
    return result.stdout.strip()


def check_wire(path):
    """Decode C-emitted slots with Python struct/zlib, independently of the C ABI."""
    raw = path.read_bytes()
    assert raw and len(raw) % 256 == 0
    request_ids = set()
    for at in range(0, len(raw), 256):
        slot = raw[at:at + 256]
        fields = struct.unpack_from("<IHHHHIIHHQIiHHIQII", slot)
        magic, major, minor, header, flags, size, opcode, src, dst, rid, epoch, status, offset, length, blen, boff, cap, crc = fields
        assert (magic, major, minor, header) == (0x43505A53, 1, 1, 64)
        assert flags == 1 and 64 <= size <= 256 and size == 64 + length
        assert src == 4 and dst == 5 and epoch == 7
        assert opcode in range(0x300, 0x309)
        assert offset == (64 if length else 0) and (blen, boff, cap) == (0, 0, 0)
        body = bytearray(slot[:size])
        body[60:64] = b"\0" * 4
        assert zlib.crc32(body) & 0xFFFFFFFF == crc
        assert rid not in request_ids
        request_ids.add(rid)
        assert status == 0
        assert length == 64
        prefix = struct.unpack_from("<IHHIIQ", slot, 64)
        assert prefix[:4] == (0x31414D50, 1, 0, 64) and prefix[5] == 31
        if opcode == 0x300:
            info = struct.unpack_from("<4IQ4I", slot, 64 + 24)
            assert info == (8, 32, 32, 64, 0x123456789ABCDEF, 7, 4, 5, 128)
        else:
            completion = struct.unpack_from("<IIIIIIQiI", slot, 64 + 24)
            domain, pid, tid, owner_gen, thread_gen, obj, seq, cstatus, reserved = completion
            assert domain == 5 and pid == 41
            assert tid == (2 if opcode == 0x302 else 1) and owner_gen == thread_gen == 1
            assert obj != 0 and seq == rid and cstatus == status and reserved == 0
    print(f"independent Python wire validation: {len(request_ids)} unique CRC-valid PMA replies")


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / "transport-result.json"
    receipt.unlink(missing_ok=True)
    inputs = [HERE / "test_transport.c", HERE / "test_transport.py", HERE / "service.h",
              HERE.parent / "abi" / "shz_vmm_pma.h", HERE.parent / "abi" / "shz_ipc.h",
              HERE.parent / "abi" / "shz_abi.h"]
    hashes = {str(path.relative_to(HERE.parents[1])): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in inputs}
    results = {}
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
              "-pthread", HERE / "test_transport.c"]
    sample = BUILD / "transport_samples.msg"
    plain = BUILD / "test_transport"
    run(["gcc", "-O2", *common, "-o", plain])
    results["gcc"] = run([plain, sample])
    print(results["gcc"])
    for sanitizer, name in (("address,undefined", "asan"), ("thread", "tsan")):
        binary = BUILD / f"test_transport_{name}"
        run(["clang", "-O1", "-g", f"-fsanitize={sanitizer}",
             "-fno-omit-frame-pointer", *common, "-o", binary])
        results[sanitizer] = run([binary])
        print(f"{sanitizer}: {results[sanitizer]}")
    check_wire(sample)
    for compiler, target in (("gcc", ["-m32"]), ("gcc", ["-m64"]),
                             ("i686-w64-mingw32-gcc", [])):
        run([compiler, *target, "-std=c11", "-ffreestanding", "-fsyntax-only",
             "-x", "c", HERE / "service.h"])
    print("production service header: freestanding i386, x86-64 and i686-mingw syntax OK")
    assert hashes == {str(path.relative_to(HERE.parents[1])): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in inputs}, "test sources changed during execution; rerun"
    receipt.write_text(json.dumps({"status": "PASS", "results": results,
        "sources_sha256": hashes, "wire_sample_sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
        "scope": "Host production service with ABI rings and freestanding syntax checks.",
        "windows98_executed": False, "vmm_executed": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()
