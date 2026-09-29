# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic disk images and partition tables for the Kernel64 storage tests.

Independent of the kernel code: a second implementation of MBR/EBR/GPT writing (with zlib's CRC-32) so the guest-side
scanner (kernel64/blk_part.c) is checked against tables it did not produce. Also the byte pattern the guest writes
(win64/tests/blktest.h app_fill) so the host can verify written sectors after a run. Tables can be produced as
(byte offset, bytes) pieces for sparse multi-GiB images that never exist in memory as a whole.
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


def mbr_blobs(primaries, extended=None, sector=512, mbr_head=b""):
    """primaries: [(start, sectors, type, bootable)], extended: (start, sectors, [(rel_start, sectors, type), ...]).
    Returns [(byte offset, bytes)]: the MBR sector (boot code area from mbr_head) and one EBR per logical partition."""
    blobs = []
    mbr = bytearray(mbr_head[:sector].ljust(sector, b"\0"))
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
            blobs.append((ebr_lba * sector, bytes(ebr)))
            if i + 1 < len(logicals):
                ebr_lba = ext_start + next_rel
    mbr[510:512] = b"\x55\xaa"
    blobs.insert(0, (0, bytes(mbr)))
    return blobs


def mbr_partitions(primaries, extended=None):
    """The partitions blk_part.c reports for mbr_blobs() input, in its order: [(start, sectors, type)]."""
    out = [(s, n, t) for s, n, t, _ in primaries]
    if extended:
        ext_start, _, logicals = extended
        ebr = ext_start
        for i, (rel, n, ptype) in enumerate(logicals):
            out.append((ebr + rel, n, ptype))
            ebr = ebr + rel + n
    return out


def write_mbr(img, primaries, extended=None, sector=512):
    """In-memory variant of mbr_blobs() (keeps the boot code area of img)."""
    for off, blob in mbr_blobs(primaries, extended, sector, bytes(img[:sector])):
        img[off:off + len(blob)] = blob


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


GUID_ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
GUID_LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"


def gpt_blobs(size, sector, parts, entries=128, entry_size=128, seed=7):
    """parts: [(start, sectors, name)] -> [(byte offset, bytes)]: protective MBR, primary header/array at LBA 1/2, backup
    array and header at the end. The first partition gets the ESP type GUID, the others Linux data."""
    sectors, ent_sectors = gpt_layout(size, sector, entries, entry_size)
    rnd = random.Random(seed)
    disk_guid = uuid.UUID(int=rnd.getrandbits(128)).bytes_le
    arr = bytearray(entries * entry_size)
    for i, (start, n, name) in enumerate(parts):
        type_guid = uuid.UUID(GUID_LINUX if i else GUID_ESP).bytes_le
        e = struct.pack("<16s16sQQQ", type_guid, uuid.UUID(int=rnd.getrandbits(128)).bytes_le, start, start + n - 1, 0)
        e += name.encode("utf-16-le").ljust(72, b"\0")
        arr[i * entry_size:i * entry_size + entry_size] = e.ljust(entry_size, b"\0")
    ecrc = zlib.crc32(bytes(arr))
    first, last = 2 + ent_sectors, sectors - 2 - ent_sectors
    mbr = bytearray(sector)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1, min(sectors - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    back_ent = sectors - 1 - ent_sectors
    return [(0, bytes(mbr)),
            (sector, _gpt_header(sector, 1, sectors - 1, first, last, disk_guid, 2, entries, entry_size, ecrc)),
            (2 * sector, bytes(arr)),
            (back_ent * sector, bytes(arr)),
            ((sectors - 1) * sector, _gpt_header(sector, sectors - 1, 1, first, last, disk_guid, back_ent, entries, entry_size, ecrc))]


def write_gpt(img, sector, parts, entries=128, entry_size=128, seed=7):
    """In-memory variant of gpt_blobs(); the boot code area of the MBR sector is kept."""
    for off, blob in gpt_blobs(len(img), sector, parts, entries, entry_size, seed):
        if off == 0:
            blob = bytes(img[:446]) + blob[446:]
        img[off:off + len(blob)] = blob


def corrupt_gpt_primary(img, sector):
    """Flip a byte of the primary header so its CRC fails (the backup at the last LBA stays intact)."""
    img[sector + 40] ^= 0x5A


# --- the pattern the guest writes (win64/tests/blktest.h: app_fill) ---
_ROW_OFFS = bytes((i * 17 + (i >> 5)) & 0xff for i in range(512))
_ROWS = [_ROW_OFFS.translate(bytes((j + b) & 0xff for j in range(256))) for b in range(256)]


def app_pattern(unit, nbytes, tag):
    """Byte i of 512-byte unit u (unit = device byte offset / 512): ((u ^ tag) * 31 + i * 17 + (i >> 5)) & 0xff.
    Every unit is one of 256 precomputed rows, so 64 MiB take well under a second."""
    return b"".join(_ROWS[(((unit + s) ^ tag) * 31) & 0xff] for s in range(nbytes // 512))


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF
