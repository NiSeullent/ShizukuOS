#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build WIN64_KMDF.IMG: the NT-driver-host initrd (WIN64_NTDRV.IMG, the test drivers) plus the KMDF pieces of the
driver corpus, unmodified, under \\SHZ\\DRIVERS:

    WDFLDR.SYS    the KMDF loader (export driver: WdfVersionBind, WdfRegisterLibrary, ...)
    WDF01000.SYS  the KMDF 1.x framework library, loaded by WdfLdr through ZwLoadDriver
    CDROM.SYS     a KMDF client driver (its FxDriverEntry binds to the framework)
    HDAUDBUS.SYS  a second KMDF client

The corpus is built by shizukudos/ntdrv/corpus/fetch.py + build.py (build/shizukudos/ntdrv/corpus/<name>/gcc/<name>.sys).
tests/run_k64_ntdrv.py --kmdf mounts the result.
"""
import argparse
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / "build" / "shizukudos"
KMDF_MODULES = ("wdfldr", "wdf01000", "cdrom", "hdaudbus")


def read_archive(path):
    data = Path(path).read_bytes()
    if data[:8] != b"SHZARC01":
        raise SystemExit(f"{path}: not a SHZARC01 archive")
    count = struct.unpack_from("<I", data, 8)[0]
    files = []
    for i in range(count):
        raw, off, size = struct.unpack_from("<120sQQ", data, 16 + 136 * i)
        files.append((raw.split(b"\0", 1)[0].decode("ascii"), data[off:off + size]))
    return files


def pack_archive(files):
    """SHZARC01: header, entries {char path[120]; u64 offset; u64 size}, then file data (16-byte aligned)."""
    entries, blob = [], bytearray()
    header_size = 16 + 136 * len(files)
    for path, data in files:
        while (header_size + len(blob)) % 16:
            blob.append(0)
        entries.append((path, header_size + len(blob), len(data)))
        blob += data
    out = bytearray(b"SHZARC01" + struct.pack("<II", len(files), 0))
    for path, off, size in entries:
        raw = path.encode("ascii")
        assert len(raw) < 120
        out += raw.ljust(120, b"\0") + struct.pack("<QQ", off, size)
    return bytes(out + blob)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=str(BUILD / "win64" / "WIN64_NTDRV.IMG"))
    ap.add_argument("--corpus", default=str(BUILD / "ntdrv" / "corpus"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--all", action="store_true",
                    help="add EVERY built corpus driver (build/.../corpus/*/gcc/*.sys) and write WIN64_CORPUS.IMG instead")
    args = ap.parse_args()
    if args.out is None:
        args.out = str(BUILD / "win64" / ("WIN64_CORPUS.IMG" if args.all else "WIN64_KMDF.IMG"))
    files = [f for f in read_archive(args.base) if not any(f[0].upper() == f"\\SHZ\\DRIVERS\\{m.upper()}.SYS" for m in KMDF_MODULES)]
    missing = []
    if args.all:
        have = {f[0].upper() for f in files}
        for sys_file in sorted(Path(args.corpus).glob("*/gcc/*.sys")):
            store = f"\\SHZ\\DRIVERS\\{sys_file.stem.upper()}.SYS"
            if store not in have:
                files.append((store, sys_file.read_bytes()))
                have.add(store)
        Path(args.out).write_bytes(pack_archive(files))
        print(f"wrote {args.out}: {len(files)} files")
        return 0
    for name in KMDF_MODULES:
        sys_file = Path(args.corpus) / name / "gcc" / f"{name}.sys"
        if not sys_file.exists():
            missing.append(str(sys_file))
            continue
        files.append((f"\\SHZ\\DRIVERS\\{name.upper()}.SYS", sys_file.read_bytes()))
    if missing:
        print("missing corpus binaries (run shizukudos/ntdrv/corpus/fetch.py and build.py --packages):\n  " + "\n  ".join(missing), file=sys.stderr)
        return 1
    Path(args.out).write_bytes(pack_archive(files))
    print(f"wrote {args.out}: {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
