#!/usr/bin/env python3
"""Convert evidence PPM files written by the theme tests into PNG."""
import pathlib
import struct
import sys
import zlib


def ppm_to_png(path: pathlib.Path) -> None:
    data = path.read_bytes()
    if not data.startswith(b"P6\n"):
        raise SystemExit(f"{path} is not a binary PPM")
    header, raw = data.split(b"\n", 1)
    del header
    size, raw = raw.split(b"\n", 1)
    depth, raw = raw.split(b"\n", 1)
    width, height = (int(part) for part in size.split())
    if depth != b"255":
        raise SystemExit(f"{path} depth is {depth!r}")
    if len(raw) != width * height * 3:
        raise SystemExit(f"{path} pixel length {len(raw)} != {width * height * 3}")

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    rows = b"".join(
        b"\x00" + raw[y * width * 3 : (y + 1) * width * 3] for y in range(height)
    )
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )
    dest = path.with_suffix(".png")
    dest.write_bytes(png)
    print(dest)


def main() -> None:
    directory = pathlib.Path(sys.argv[1])
    ppm = sorted(directory.glob("*.ppm"))
    if not ppm:
        raise SystemExit(f"no PPM files in {directory}")
    for path in ppm:
        ppm_to_png(path)


if __name__ == "__main__":
    main()
