# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic disk images and partition tables for the Kernel64 storage tests.

Independent of the kernel code: a second implementation of MBR/EBR/GPT writing (with zlib's CRC-32) so the guest-side
scanner (kernel64/blk_part.c) is checked against tables it did not produce. Also the byte patterns the guest writes
(mirrored in kernel64/blk_test.c and win64/tests/t_blk_raw.c) so the host can verify written sectors after a run.
"""
import random
import struct
import uuid
import zlib

GPT_SIG = b"EFI PART"


def content(size, seed):
    """Image body: seeded pseudo-random bytes (C-implemented Mersenne Twister, ~1 s per 256 MiB), generated in 16 MiB
    steps (randbytes() of more than 2^31 bits at once overflows)."""
    rnd = random.Random(seed)
    out = bytearray()
    step = 16 << 20
    while len(out) < size:
        out += rnd.randbytes(min(step, size - len(out)))
    return out


def write_mbr(img, primaries, extended=None, sector=512):
    """primaries: [(start, sectors, type, bootable)], extended: (start, sectors, [(rel_start, sectors, type), ...])."""
    mbr = bytearray(img[:sector])
    mbr[446:510] = bytes(64)
    slot = 0
    for start, n, ptype, boot in primaries:
        mbr[446 + 16 * slot:446 + 16 * slot + 16] = struct.pack("<B3sB3sII", 0x80 if boot else 0, b"\xff\xff\xff", ptype, b"\xff\xff\xff", start, n)
        slot += 1
    if extended:
        ext_start, ext_n, logicals = extended
        mbr[446 + 16 * slot:446 + 16 * slot + 16] = struct.pack("<B3sB3sII", 0, b"\xff\xff\xff", 0x05, b"\xff\xff\xff", ext_start, ext_n)
        ebr_lba = ext_start
        for i, (rel, n, ptype) in enumerate(logicals):
            ebr = bytearray(sector)
            ebr[446:462] = struct.pack("<B3sB3sII", 0, b"\xff\xff\xff", ptype, b"\xff\xff\xff", rel, n)
            if i + 1 < len(logicals):
                next_rel = (ebr_lba - ext_start) + rel + n
                ebr[462:478] = struct.pack("<B3sB3sII", 0, b"\xff\xff\xff", 0x05, b"\xff\xff\xff", next_rel, logicals[i + 1][0] + logicals[i + 1][1])
            ebr[510:512] = b"\x55\xaa"
            img[ebr_lba * sector:(ebr_lba + 1) * sector] = ebr
            if i + 1 < len(logicals):
                ebr_lba = ext_start + next_rel
    mbr[510:512] = b"\x55\xaa"
    img[:sector] = mbr


def gpt_layout(size, sector, entries=128, entry_size=128):
    sectors = size // sector
    ent_sectors = (entries * entry_size + sector - 1) // sector
    return sectors, ent_sectors


def _gpt_header(sector, my_lba, alt_lba, first, last, disk_guid, ent_lba, entries, entry_size, ecrc):
    h = bytearray(92)
    h[0:8] = GPT_SIG
    struct.pack_into("<IIII", h, 8, 0x00010000, 92, 0, 0)
    struct.pack_into("<QQQQ", h, 24, my_lba, alt_lba, first, last)
    h[56:72] = disk_guid
    struct.pack_into("<QIII", h, 72, ent_lba, entries, entry_size, ecrc)
    struct.pack_into("<I", h, 16, zlib.crc32(bytes(h)))
    return bytes(h).ljust(sector, b"\0")


def write_gpt(img, sector, parts, entries=128, entry_size=128, seed=7):
    """parts: [(start, sectors, name)] -> protective MBR, primary header/array at LBA 1/2, backup at the end."""
    size = len(img)
    sectors, ent_sectors = gpt_layout(size, sector, entries, entry_size)
    rnd = random.Random(seed)
    disk_guid = uuid.UUID(int=rnd.getrandbits(128)).bytes_le
    arr = bytearray(entries * entry_size)
    for i, (start, n, name) in enumerate(parts):
        type_guid = uuid.UUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4").bytes_le if i else uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").bytes_le
        e = struct.pack("<16s16sQQQ", type_guid, uuid.UUID(int=rnd.getrandbits(128)).bytes_le, start, start + n - 1, 0)
        e += name.encode("utf-16-le").ljust(72, b"\0")
        arr[i * entry_size:i * entry_size + entry_size] = e.ljust(entry_size, b"\0")
    ecrc = zlib.crc32(bytes(arr))
    first, last = 2 + ent_sectors, sectors - 2 - ent_sectors
    # protective MBR
    mbr = bytearray(img[:sector])
    mbr[446:510] = bytes(64)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1, min(sectors - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    img[:sector] = mbr
    img[sector:2 * sector] = _gpt_header(sector, 1, sectors - 1, first, last, disk_guid, 2, entries, entry_size, ecrc)
    img[2 * sector:2 * sector + len(arr)] = arr
    back_ent = sectors - 1 - ent_sectors
    img[back_ent * sector:back_ent * sector + len(arr)] = arr
    img[(sectors - 1) * sector:sectors * sector] = _gpt_header(sector, sectors - 1, 1, first, last, disk_guid, back_ent, entries, entry_size, ecrc)


def corrupt_gpt_primary(img, sector):
    """Flip a byte of the primary header so its CRC fails (the backup at the last LBA stays intact)."""
    img[sector + 40] ^= 0x5A


# --- patterns the guest writes (kernel64/blk_test.c: bench_fill; win64/tests/t_blk_raw.c: app_fill) ---
def bench_pattern(lba, nbytes, tag):
    """Kernel bench write pattern: byte i of sector `lba` = (lba*7 + i*13 + tag) & 0xff, sector by sector."""
    out = bytearray(nbytes)
    per = 512
    for s in range(nbytes // per):
        base = ((lba + s) * 7 + tag) & 0xff
        row = bytes((base + i * 13) & 0xff for i in range(per))
        out[s * per:(s + 1) * per] = row
    return bytes(out)


def app_pattern(lba, nbytes, tag):
    """T_BLK_RAW write pattern: byte i of sector `lba` = ((lba ^ tag) * 31 + i * 17 + (i >> 5)) & 0xff."""
    out = bytearray(nbytes)
    per = 512
    for s in range(nbytes // per):
        l = lba + s
        out[s * per:(s + 1) * per] = bytes((((l ^ tag) * 31) + i * 17 + (i >> 5)) & 0xff for i in range(per))
    return bytes(out)


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF
