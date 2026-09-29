#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and run the ABI host model with GCC, Clang ASan/UBSan and Clang TSan, then decode
C-produced messages independently in Python (struct + zlib CRC-32) and cross-check the WIN64
subsystem frame rules (ABI 1.1) between this Python model and the C library on generated frames.

The encoder/decoder here (`encode_slot`, `decode_slot`, the `w64_*` helpers) is also imported by
platform/abi32/k64model.py, the Kernel64 stand-in that drives NTW32.DLL's bridge client.
"""
import random
import struct
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD = HERE.parents[1] / "build" / "shizukudos" / "abi"

ABI_MAJOR, ABI_MINOR = 1, 1
MSG_MAGIC = 0x43505A53
SLOT_SIZE, HEADER_SIZE, MAX_INLINE = 256, 64, 192
HDR_FMT = "<IHHHHIIHHQIiHHIQII"
HDR_FIELDS = ("magic", "abi_major", "abi_minor", "header_size", "flags", "message_size", "opcode", "src_domain",
              "dst_domain", "request_id", "generation", "status", "payload_offset", "payload_length", "buffer_length",
              "buffer_offset", "capability_id", "checksum")
assert struct.calcsize(HDR_FMT) == HEADER_SIZE
MSGF_REPLY, MSGF_ONEWAY, MSGF_CANCEL, MSGF_BUFFER = 1, 2, 4, 8
DOM_KERNEL32, DOM_KERNEL64, DOM_WIN98 = 3, 4, 5
OK, E_INVALID, E_RANGE, E_NOENT, E_BUSY, E_QUEUE_FULL, E_STALE, E_TIMEOUT, E_CANCELLED, E_PROTO, E_NOMEM, E_UNSUPPORTED, E_DENIED = \
    0, -1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12
PR_NONE, PR_MAGIC, PR_VERSION, PR_HEADER_SIZE, PR_MESSAGE_SIZE, PR_PAYLOAD_RANGE, PR_CHECKSUM = 0, 1, 2, 3, 4, 5, 6

# WIN64 subsystem family (shz_ipc.h, ABI 1.1)
OP_W64_QUERY, OP_W64_CREATE_PROCESS, OP_W64_PROCESS_EXITED, OP_W64_CONSOLE_OUTPUT = 0x200, 0x201, 0x202, 0x203
OP_W64_CONSOLE_ACK, OP_W64_CONSOLE_INPUT, OP_W64_KILL_PROCESS, OP_W64_RELEASE, OP_W64_SHUTDOWN = 0x204, 0x205, 0x206, 0x207, 0x208
W64_SUBSYS_VERSION = 0x00010000
W64_CAP_CREATE, W64_CAP_CONSOLE_OUTPUT, W64_CAP_CONSOLE_INPUT, W64_CAP_KILL, W64_CAP_POOL_ARGS = 1, 2, 4, 8, 16
W64_MAX_ARGS_BYTES, W64_CONSOLE_WINDOW, W64_CONSOLE_CHUNK, W64_MAX_PATH_CHARS = 4096, 8, 176, 260
W64_PS_STARTED, W64_PS_EXITED, W64_PS_FAILED, W64_PS_KILLED = 1, 2, 3, 4
W64_CONF_EOF = 1
INFO_FMT, CREATE_FMT, EVENT_FMT, CONSOLE_FMT, KILL_FMT = "<HHIIIIIIIQ", "<IHHHHI", "<IIiIqII", "<IIHBBI", "<Ii"
assert (struct.calcsize(INFO_FMT), struct.calcsize(CREATE_FMT), struct.calcsize(EVENT_FMT),
        struct.calcsize(CONSOLE_FMT), struct.calcsize(KILL_FMT)) == (40, 16, 32, 16, 8)


def run(cmd, **kw):
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True, timeout=600, **kw)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"failed: {' '.join(map(str, cmd))}")
    return r.stdout


# ---------------------------------------------------------------- wire encode / decode (independent of shz_ipc.h)
def crc32(data):
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def encode_slot(opcode, payload=b"", *, flags=0, src=DOM_WIN98, dst=DOM_KERNEL64, request_id=0, generation=1,
                status=0, buffer_offset=0, buffer_length=0, capability_id=0, abi=(ABI_MAJOR, ABI_MINOR)):
    """One 256-byte ring slot exactly as shz_ring_push() lays it out (CRC over header + inline payload)."""
    payload = bytes(payload)
    if len(payload) > MAX_INLINE:
        raise ValueError("inline payload too large")
    hdr = struct.pack(HDR_FMT, MSG_MAGIC, abi[0], abi[1], HEADER_SIZE, flags, HEADER_SIZE + len(payload), opcode, src,
                      dst, request_id, generation, status, HEADER_SIZE if payload else 0, len(payload), buffer_length,
                      buffer_offset, capability_id, 0)
    body = hdr + payload
    return (body[:60] + struct.pack("<I", crc32(body)) + body[64:]).ljust(SLOT_SIZE, b"\0")


def decode_slot(slot):
    """Validates a slot like shz_ring_pop(): returns (rc, reason, header dict, payload bytes)."""
    if len(slot) < HEADER_SIZE:
        return E_PROTO, PR_MESSAGE_SIZE, None, b""
    h = dict(zip(HDR_FIELDS, struct.unpack_from(HDR_FMT, slot, 0)))
    if h["magic"] != MSG_MAGIC:
        return E_PROTO, PR_MAGIC, h, b""
    if h["abi_major"] != ABI_MAJOR:
        return E_PROTO, PR_VERSION, h, b""
    if h["header_size"] != HEADER_SIZE:
        return E_PROTO, PR_HEADER_SIZE, h, b""
    if (h["message_size"] < HEADER_SIZE or h["message_size"] > SLOT_SIZE or
            h["message_size"] != HEADER_SIZE + h["payload_length"]):
        return E_PROTO, PR_MESSAGE_SIZE, h, b""
    if (h["payload_length"] > MAX_INLINE or (h["payload_length"] and h["payload_offset"] != HEADER_SIZE) or
            h["payload_offset"] > h["message_size"] or h["payload_length"] > h["message_size"] - h["payload_offset"]):
        return E_PROTO, PR_PAYLOAD_RANGE, h, b""
    body = bytearray(slot[:h["message_size"]])
    body[60:64] = b"\0\0\0\0"
    if crc32(body) != h["checksum"]:
        return E_PROTO, PR_CHECKSUM, h, b""
    return OK, PR_NONE, h, bytes(slot[HEADER_SIZE:HEADER_SIZE + h["payload_length"]])


# ---------------------------------------------------------------- WIN64 payloads
def w64_pack_create(path, cmdline, cwd):
    """(header bytes, utf16 block, needs_pool) mirroring shz_w64_create_pack(); raises on unusable strings."""
    for s in (path, cmdline, cwd):
        if "\0" in s:
            raise ValueError("embedded NUL")
    if not path or len(path) > W64_MAX_PATH_CHARS or len(cwd) > W64_MAX_PATH_CHARS:
        raise ValueError("path/cwd length")
    block = (path + cmdline + cwd).encode("utf-16-le")
    if len(block) > W64_MAX_ARGS_BYTES:
        raise ValueError("arguments too long")
    hdr = struct.pack(CREATE_FMT, 0, len(path), len(cmdline), len(cwd), 0, len(block))
    return hdr, block, len(block) > MAX_INLINE - 16


def w64_check_create(h, payload, pool):
    """Receiver rule set of shz_w64_create_check(). `pool` = (pool_offset, pool_size, {block_offset: owner}) or None.
    Returns (rc, header tuple, block bytes)."""
    if len(payload) < 16:
        return E_PROTO, None, b""
    flags, path_chars, cmd_chars, cwd_chars, reserved, block_bytes = struct.unpack_from(CREATE_FMT, payload, 0)
    total = path_chars + cmd_chars + cwd_chars
    if (flags != 0 or reserved or path_chars == 0 or path_chars > W64_MAX_PATH_CHARS or cwd_chars > W64_MAX_PATH_CHARS or
            block_bytes != total * 2):
        return E_INVALID, None, b""
    if block_bytes > W64_MAX_ARGS_BYTES:
        return E_RANGE, None, b""
    if h["flags"] & MSGF_BUFFER:
        if pool is None or h["buffer_length"] != block_bytes or h["payload_length"] != 16:
            return E_INVALID, None, b""
        pool_offset, pool_size, owners, memory = pool
        off = h["buffer_offset"]
        if off < pool_offset or off - pool_offset > pool_size or block_bytes > pool_size - (off - pool_offset):
            return E_DENIED, None, b""          # shz_pool_check: E_RANGE, surfaced as DENIED by create_check
        first = (off - pool_offset) // 4096
        need = ((off - pool_offset) % 4096 + block_bytes + 4095) // 4096
        if any(owners.get(first + i, 0) != h["src_domain"] for i in range(need)):
            return E_DENIED, None, b""
        block = memory[off - pool_offset:off - pool_offset + block_bytes]
    else:
        if h["buffer_length"] or h["payload_length"] != 16 + block_bytes:
            return E_INVALID, None, b""
        block = payload[16:16 + block_bytes]
    units = struct.unpack_from(f"<{total}H", block, 0)
    if any(u == 0 for u in units):
        return E_INVALID, None, b""
    return OK, (path_chars, cmd_chars, cwd_chars), block


def w64_check_console(h, payload):
    if len(payload) < 16:
        return E_PROTO, None
    pid, seq, length, stream, flags, reserved = struct.unpack_from(CONSOLE_FMT, payload, 0)
    if (reserved or stream > 2 or flags & ~W64_CONF_EOF or length > W64_CONSOLE_CHUNK or
            h["payload_length"] != 16 + length or h["buffer_length"]):
        return E_INVALID, None
    return OK, (pid, seq, length, stream, flags)


def w64_console(pid, seq, data=b"", stream=1, flags=0):
    return struct.pack(CONSOLE_FMT, pid, seq, len(data), stream, flags, 0) + bytes(data)


def w64_event(pid, state, status=0, fault_status=0, exit_code=0, console_seq=0, dropped=0):
    return struct.pack(EVENT_FMT, pid, state, status, fault_status, exit_code, console_seq, dropped)


def w64_info(max_processes=4, active=0, uptime_ns=0, caps=None):
    caps = (W64_CAP_CREATE | W64_CAP_CONSOLE_OUTPUT | W64_CAP_CONSOLE_INPUT | W64_CAP_KILL | W64_CAP_POOL_ARGS
            if caps is None else caps)
    return struct.pack(INFO_FMT, ABI_MAJOR, ABI_MINOR, W64_SUBSYS_VERSION, caps, max_processes, W64_MAX_ARGS_BYTES,
                       W64_CONSOLE_WINDOW, W64_CONSOLE_CHUNK, active, uptime_ns)


# ---------------------------------------------------------------- checks against the C build
def check_legacy_sample(sample):
    slot = sample.read_bytes()
    rc, reason, h, payload = decode_slot(slot)
    assert rc == OK and reason == PR_NONE
    assert (h["abi_major"], h["abi_minor"]) == (1, 1) and h["header_size"] == 64
    assert h["message_size"] == 64 + h["payload_length"] and h["payload_offset"] == 64 and h["payload_length"] == 16
    assert h["opcode"] == 0x1234 and h["request_id"] == 0x1122334455667788 and h["generation"] == 7
    assert h["status"] == -3 and h["capability_id"] == 0xABCD
    assert h["buffer_offset"] == 0x100000010 and h["buffer_length"] == 99, "64-bit buffer offset must not be truncated"
    assert payload == b"wire-format-v1!\0"
    assert encode_slot(0x1234, payload, src=DOM_KERNEL32, dst=DOM_KERNEL64, request_id=h["request_id"], generation=7,
                       status=-3, buffer_offset=0x100000010, buffer_length=99, capability_id=0xABCD) == slot, \
        "Python encoder must reproduce the C slot byte for byte"
    print("independent Python decode of the wire message: OK (CRC-32 matches zlib, encoder round trip identical)")


def check_w64_samples(sample):
    data = sample.read_bytes()
    assert len(data) == 4 * SLOT_SIZE
    frames = [decode_slot(data[i * SLOT_SIZE:(i + 1) * SLOT_SIZE]) for i in range(4)]
    assert all(f[0] == OK for f in frames)
    rc, hdr, block = w64_check_create(frames[0][2], frames[0][3], None)
    assert rc == OK and hdr == (24, 17, 12)
    text = block.decode("utf-16-le")
    assert text == "C:\\SHZ\\TESTS\\T_HELLO.EXET_HELLO.EXE firstC:\\SHZ\\TESTS"
    assert frames[0][2]["opcode"] == OP_W64_CREATE_PROCESS and frames[0][2]["src_domain"] == DOM_WIN98
    h, payload = frames[1][2], frames[1][3]
    assert h["opcode"] == OP_W64_QUERY and h["flags"] == MSGF_REPLY and h["src_domain"] == DOM_KERNEL64
    info = struct.unpack(INFO_FMT, payload)
    assert info == (1, 1, W64_SUBSYS_VERSION, 31, 4, W64_MAX_ARGS_BYTES, W64_CONSOLE_WINDOW, W64_CONSOLE_CHUNK, 1, 0x123456789)
    assert payload == w64_info(max_processes=4, active=1, uptime_ns=0x123456789)
    h, payload = frames[2][2], frames[2][3]
    rc, con = w64_check_console(h, payload)
    assert rc == OK and con == (20, 3, 24, 1, 0) and payload[16:] == b"hello from Win64 PE32+!\n"
    assert payload == w64_console(20, 3, b"hello from Win64 PE32+!\n")
    h, payload = frames[3][2], frames[3][3]
    assert h["opcode"] == OP_W64_PROCESS_EXITED and h["flags"] == MSGF_ONEWAY
    assert struct.unpack(EVENT_FMT, payload) == (20, W64_PS_EXITED, 0, 0, 7, 3, 0)
    assert payload == w64_event(20, W64_PS_EXITED, exit_code=7, console_seq=3)
    print("independent Python decode of the four WIN64 subsystem frames: OK")


def cross_verify(binary):
    """Generate valid and hostile WIN64 frames here, let the C library judge them, compare with this model."""
    rng = random.Random(20260929)
    frames, expected = [], []
    verdict_in, verdict_out = BUILD / "w64_frames.bin", BUILD / "w64_verdicts.txt"
    # geometry as verify_frames() sets it up: channel of 1 MiB, 32 slots; first line of the output confirms it
    probe = run([binary, "--verify", "/dev/null", verdict_out])
    first = verdict_out.read_text().splitlines()[0].split()
    assert first[0] == "pool" and first[3] == "owned"
    pool_offset, pool_size, owned, owned_len = int(first[1]), int(first[2]), int(first[4]), int(first[5])
    owners = {((owned - pool_offset) // 4096) + i: DOM_WIN98 for i in range(owned_len // 4096)}
    memory = bytearray(pool_size)
    memory[owned - pool_offset:owned - pool_offset + owned_len] = b"x" * owned_len
    pool = (pool_offset, pool_size, owners, memory)

    def add(slot):
        rc, reason, h, payload = decode_slot(slot)
        crc = coc = 99
        if rc == OK:
            crc = w64_check_create(h, payload, pool)[0]
            coc = w64_check_console(h, payload)[0]
        frames.append(slot)
        expected.append((rc, reason, crc, coc))

    def rand_text(n):
        return "".join(chr(rng.choice([0x41, 0x7A, 0xD55C, 0x5C, 0x20])) for _ in range(n))

    for i in range(6000):
        kind = rng.randrange(8)
        if kind == 0:                                           # valid inline CREATE
            hdr, block, _ = w64_pack_create(rand_text(rng.randrange(1, 40)), rand_text(rng.randrange(0, 40)), rand_text(rng.randrange(0, 8)))
            add(encode_slot(OP_W64_CREATE_PROCESS, hdr + block, request_id=i))
        elif kind == 1:                                         # CREATE through the pool: owned, unowned or out of range
            block_len = rng.randrange(2, 3000, 2)
            hdr = struct.pack(CREATE_FMT, 0, block_len // 2 - 0 if block_len // 2 <= W64_MAX_PATH_CHARS else W64_MAX_PATH_CHARS,
                              max(0, block_len // 2 - W64_MAX_PATH_CHARS), 0, 0, block_len)
            off = rng.choice([owned, owned + 4096, owned + owned_len - 8, pool_offset, pool_offset + pool_size - 4,
                              0x100000000 + owned, owned + rng.randrange(0, 4000)])
            src = rng.choice([DOM_WIN98, DOM_WIN98, DOM_KERNEL32])
            add(encode_slot(OP_W64_CREATE_PROCESS, hdr, flags=MSGF_BUFFER, buffer_offset=off, buffer_length=block_len, src=src))
        elif kind == 2:                                         # header field damage on an otherwise valid CREATE
            hdr, block, _ = w64_pack_create(rand_text(rng.randrange(1, 30)), rand_text(rng.randrange(0, 30)), "")
            fields = list(struct.unpack(CREATE_FMT, hdr))
            fields[rng.randrange(6)] = rng.choice([0, 1, 261, 0xFFFF, 4097, 0x80000000])
            fields = [f & (0xFFFF if k in (1, 2, 3, 4) else 0xFFFFFFFF) for k, f in enumerate(fields)]
            add(encode_slot(OP_W64_CREATE_PROCESS, struct.pack(CREATE_FMT, *fields) + block))
        elif kind == 3:                                         # NUL inside the block, or wrong payload length
            hdr, block, _ = w64_pack_create(rand_text(rng.randrange(1, 30)), rand_text(rng.randrange(1, 30)), "")
            b = bytearray(block)
            if rng.random() < 0.5:
                pos = rng.randrange(0, len(b) - 1, 2)
                b[pos:pos + 2] = b"\0\0"
                add(encode_slot(OP_W64_CREATE_PROCESS, hdr + bytes(b)))
            else:
                add(encode_slot(OP_W64_CREATE_PROCESS, (hdr + bytes(b) + b"\x41\x00")[:rng.randrange(1, MAX_INLINE)]))
        elif kind == 4:                                         # console frames, valid and damaged
            n = rng.randrange(0, W64_CONSOLE_CHUNK + 1)
            p = bytearray(w64_console(rng.randrange(1, 100), rng.randrange(0, 5), bytes(rng.randrange(1, 256) for _ in range(n)),
                                      stream=rng.randrange(0, 3), flags=rng.randrange(0, 2)))
            if rng.random() < 0.4:
                p[rng.randrange(0, 16)] ^= rng.randrange(1, 256)
            add(encode_slot(OP_W64_CONSOLE_OUTPUT, bytes(p)[:rng.choice([len(p), len(p), len(p) - 1 if len(p) > 16 else len(p)])],
                            flags=MSGF_ONEWAY, buffer_length=rng.choice([0, 0, 0, 5])))
        elif kind == 5:                                         # transport-level damage: CRC, magic, sizes
            hdr, block, _ = w64_pack_create(rand_text(5), rand_text(5), "")
            s = bytearray(encode_slot(OP_W64_CREATE_PROCESS, hdr + block))
            where = rng.randrange(0, 64 + len(hdr) + len(block))
            s[where] ^= 1 << rng.randrange(8)
            add(bytes(s))
        elif kind == 6:                                         # random bytes
            add(bytes(rng.randrange(256) for _ in range(SLOT_SIZE)))
        else:                                                   # foreign major / flags soup on a valid frame
            hdr, block, _ = w64_pack_create(rand_text(3), "", "")
            add(encode_slot(OP_W64_CREATE_PROCESS, hdr + block, abi=(rng.choice([1, 2, 0]), rng.randrange(0, 5)),
                            flags=rng.randrange(0, 16), buffer_length=rng.choice([0, 0, 6])))
    verdict_in.write_bytes(b"".join(frames))
    run([binary, "--verify", verdict_in, verdict_out])
    lines = verdict_out.read_text().splitlines()[1:]
    assert len(lines) == len(frames)
    got = [tuple(int(x) for x in line.split()) for line in lines]
    mismatches = [(k, e, g) for k, (e, g) in enumerate(zip(expected, got)) if e != g]
    assert not mismatches, f"Python model and C library disagree on {len(mismatches)} frames, first: {mismatches[:3]}"
    accepted = sum(1 for e in expected if e[2] == OK)
    consoles = sum(1 for e in expected if e[3] == OK)
    rejected = len(expected) - accepted - consoles
    assert accepted > 500 and consoles > 200 and rejected > 2000
    print(f"cross-verified {len(frames)} generated WIN64 frames: C library and Python model agree "
          f"({accepted} CREATE accepted, {consoles} console accepted, {rejected} rejected)")
    del probe


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", HERE, HERE / "test_abi.c", "-lpthread"]
    sample, w64_sample = BUILD / "sample.msg", BUILD / "w64_samples.msg"
    run(["gcc", "-O2", *common, "-o", BUILD / "test_abi"])
    out = run([BUILD / "test_abi", sample, w64_sample])
    print(out.strip())
    run(["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", *common,
         "-o", BUILD / "test_abi_asan"])
    print("ASan/UBSan:", run([BUILD / "test_abi_asan"]).strip())
    run(["clang", "-g", "-O1", "-fsanitize=thread", *common, "-o", BUILD / "test_abi_tsan"])
    print("TSan:", run([BUILD / "test_abi_tsan"]).strip())
    run(["gcc", "-m32", "-ffreestanding", "-fsyntax-only", "-x", "c", HERE / "shz_ipc.h"])
    run(["i686-w64-mingw32-gcc", "-std=c11", "-ffreestanding", "-fsyntax-only", "-x", "c", HERE / "shz_ipc.h"])
    print("shz_ipc.h compiles as freestanding 32-bit, 64-bit and i686-mingw (NTW32.DLL / VxD) code")
    check_legacy_sample(sample)
    check_w64_samples(w64_sample)
    cross_verify(BUILD / "test_abi_asan")


if __name__ == "__main__":
    main()
