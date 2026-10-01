"""Current default: build DOS10. Explicit --historical-fixture retains the retired FAT12 test builder."""

from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from pathlib import Path

BYTES_PER_SECTOR = 512
SECTORS = 2880
RESERVED_SECTORS = 32
FAT_SECTORS = 9
ROOT_ENTRIES = 224
ROOT_LBA = RESERVED_SECTORS + 2 * FAT_SECTORS
ROOT_SECTORS = ROOT_ENTRIES * 32 // BYTES_PER_SECTOR
DATA_LBA = ROOT_LBA + ROOT_SECTORS
MAX_STAGE2_BYTES = (RESERVED_SECTORS - 1) * BYTES_PER_SECTOR


def set_fat12(fat: bytearray, cluster: int, value: int) -> None:
    offset = cluster * 3 // 2
    value &= 0xFFF
    if cluster & 1:
        fat[offset] = (fat[offset] & 0x0F) | ((value << 4) & 0xF0)
        fat[offset + 1] = value >> 4
    else:
        fat[offset] = value & 0xFF
        fat[offset + 1] = (fat[offset + 1] & 0xF0) | (value >> 8)


def fat_name(name: str) -> bytes:
    base, dot, extension = name.upper().partition(".")
    if not base or len(base) > 8 or len(extension) > 3:
        raise ValueError(f"not an 8.3 FAT name: {name}")
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$~!#%&-{}()@'`" for ch in base + extension):
        raise ValueError(f"unsupported FAT name: {name}")
    return base.ljust(8).encode("ascii") + extension.ljust(3).encode("ascii")


def make_image(boot: bytes, stage2: bytes, files: dict[str, bytes]) -> bytes:
    if len(boot) != BYTES_PER_SECTOR or boot[-2:] != b"\x55\xaa":
        raise ValueError("stage1 must be a signed, 512-byte boot sector")
    if not stage2 or len(stage2) > MAX_STAGE2_BYTES:
        raise ValueError(f"stage2 must be 1..{MAX_STAGE2_BYTES} bytes")
    if len(files) > ROOT_ENTRIES:
        raise ValueError("too many root directory files")

    image = bytearray(BYTES_PER_SECTOR * SECTORS)
    image[:BYTES_PER_SECTOR] = boot
    image[BYTES_PER_SECTOR : BYTES_PER_SECTOR + len(stage2)] = stage2
    fat = bytearray(BYTES_PER_SECTOR * FAT_SECTORS)
    fat[:3] = b"\xf0\xff\xff"
    root_offset = ROOT_LBA * BYTES_PER_SECTOR
    next_cluster = 2
    last_cluster = SECTORS - DATA_LBA + 1

    for index, (name, content) in enumerate(files.items()):
        clusters = (len(content) + BYTES_PER_SECTOR - 1) // BYTES_PER_SECTOR
        if next_cluster + clusters - 1 > last_cluster:
            raise ValueError("image has insufficient data clusters")
        first_cluster = next_cluster if clusters else 0
        for part in range(clusters):
            cluster = next_cluster + part
            following = cluster + 1 if part + 1 < clusters else 0xFFF
            set_fat12(fat, cluster, following)
            offset = (DATA_LBA + cluster - 2) * BYTES_PER_SECTOR
            image[offset : offset + len(content[part * 512 : (part + 1) * 512])] = content[
                part * 512 : (part + 1) * 512
            ]
        next_cluster += clusters
        entry = bytearray(32)
        entry[:11] = fat_name(name)
        entry[11] = 0x20
        struct.pack_into("<H", entry, 26, first_cluster)
        struct.pack_into("<I", entry, 28, len(content))
        image[root_offset + index * 32 : root_offset + (index + 1) * 32] = entry

    for copy in range(2):
        offset = (RESERVED_SECTORS + copy * FAT_SECTORS) * BYTES_PER_SECTOR
        image[offset : offset + len(fat)] = fat
    return bytes(image)


def main() -> None:
    if "--historical-fixture" not in sys.argv[1:]:
        if sys.argv[1:] in (["--help"], ["-h"]):
            print(__doc__)
            print("Run without arguments for DOS10. Current CLI: python3 shizukudos/tools/shz.py build.")
            print("Retired fixture: --historical-fixture boot stage2 output --demo COM --ret-demo COM --std-demo COM.")
            return
        if len(sys.argv) != 1:
            raise SystemExit("ShizukuDOS 0.1 is retired. Run this entry without arguments for DOS10, "
                             "or use --historical-fixture only for the old developer test inputs.")
        subprocess.run([sys.executable, str(Path(__file__).resolve().parent / "dos16/build.py")], check=True)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--historical-fixture", action="store_true", required=True,
                        help="explicit retired DOS 0.1 developer fixture; never the current product image")
    parser.add_argument("boot", type=Path)
    parser.add_argument("stage2", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--demo", required=True, type=Path, help="assembled demo COM program")
    parser.add_argument("--ret-demo", required=True, type=Path, help="assembled near-RET COM program")
    parser.add_argument("--std-demo", required=True, type=Path, help="assembled DF=1 COM program")
    args = parser.parse_args()
    files = {
        "HELLO.TXT": b"Hello from ShizukuDOS.\r\nThis FAT12 file can be read with TYPE.\r\n",
        "README.TXT": (
            b"ShizukuDOS is a from-scratch experimental shell.\r\n"
            b"BOOT chainloads the first hard disk MBR.\r\n"
            b"Windows 98 still uses its own IO.SYS and DOS 7.1.\r\n"
        ),
        "CHAIN.TXT": b"START OF FAT12 CHAIN\r\n" + b"0123456789ABCDEF\r\n" * 60 + b"END OF FAT12 CHAIN\r\n",
        "DEMO.COM": args.demo.read_bytes(),
        "RET.COM": args.ret_demo.read_bytes(),
        "STD.COM": args.std_demo.read_bytes(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(make_image(args.boot.read_bytes(), args.stage2.read_bytes(), files))
    print(f"Wrote {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
