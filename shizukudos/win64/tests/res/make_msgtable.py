#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Writes shzmsg.bin, the RT_MESSAGETABLE resource used by tests/t_k32_fmt.rc (layout of MESSAGE_RESOURCE_DATA in winnt.h).

Blocks: 0x1000..0x1002 (ANSI, Unicode, ANSI) and 0x2000..0x2000 (ANSI). Each entry is {u16 Length, u16 Flags, text}, Length
counting the 4 header bytes and padded to a multiple of 4. Regenerate with:  python3 make_msgtable.py
"""
import struct
from pathlib import Path

BLOCKS = [
    (0x1000, [("Hello %1, you have %2!d! messages.\r\n", False),
              ("Unicode entry é\r\n", True),
              ("Line one%nLine two%0", False)]),
    (0x2000, [("Second block entry\r\n", False)]),
]


def entry(text, unicode_):
    raw = (text.encode("utf-16-le") + b"\0\0") if unicode_ else (text.encode("utf-8") + b"\0")
    pad = (-(len(raw) + 4)) % 4
    raw += b"\0" * pad
    return struct.pack("<HH", len(raw) + 4, 1 if unicode_ else 0) + raw


def main():
    header = 4 + 12 * len(BLOCKS)
    entries, blocks, offset = b"", b"", header
    for low, items in BLOCKS:
        data = b"".join(entry(t, u) for t, u in items)
        blocks += struct.pack("<III", low, low + len(items) - 1, offset)
        entries += data
        offset += len(data)
    out = struct.pack("<I", len(BLOCKS)) + blocks + entries
    path = Path(__file__).resolve().parent / "shzmsg.bin"
    path.write_bytes(out)
    print(f"{path}: {len(out)} bytes")


if __name__ == "__main__":
    main()
