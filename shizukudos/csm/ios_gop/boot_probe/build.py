#!/usr/bin/env python3
"""Build an original diagnostic MBR sector; never modify a guest disk."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


FAT_TYPES = frozenset((0x06, 0x0B, 0x0C, 0x0E))
CODE_BYTES = 440


def validate_mbr(mbr: bytes, sector_count: int) -> dict:
    """Validate an immutable caller-selected disk's exact active FAT partition."""
    if len(mbr) != 512 or mbr[510:] != b"\x55\xaa":
        raise ValueError("A signed 512-byte MBR is required")
    if not isinstance(sector_count, int) or isinstance(sector_count, bool) or sector_count <= 1:
        raise ValueError("The whole physical disk sector count is required")
    entries = []
    active = []
    for index in range(4):
        entry = mbr[446 + 16 * index:462 + 16 * index]
        status, kind = entry[0], entry[4]
        start, count = struct.unpack_from("<II", entry, 8)
        if status not in (0, 0x80):
            raise ValueError("Invalid partition boot indicator")
        if kind == 0xEE:
            raise ValueError("Protective/hybrid GPT disks are outside this MBR profile")
        if not kind:
            if status or start or count:
                raise ValueError("An unused partition entry contains live geometry")
            continue
        if not start or not count or start + count > sector_count or start + count > 0xFFFFFFFF:
            raise ValueError("Partition geometry exceeds the supported disk range")
        if any(start < other["end_lba"] and other["start_lba"] < start + count for other in entries):
            raise ValueError("Overlapping primary partitions are not accepted")
        parsed = {"index": index, "type": kind, "start_lba": start,
                  "sectors": count, "end_lba": start + count}
        entries.append(parsed)
        if status == 0x80:
            active.append(parsed)
    if len(active) != 1 or active[0]["type"] not in FAT_TYPES:
        raise ValueError("Exactly one active FAT16/FAT32 primary partition is required")
    return dict(active[0])


def apply_to_mbr(mbr: bytes, probe: bytes) -> bytes:
    """Return a sector preserving disk identity, partition table and signature."""
    # Structural guard here; owner must first validate against the real disk size.
    validate_mbr(mbr, 0xFFFFFFFF)
    if len(probe) != 512 or probe[440:510] != bytes(70) or probe[510:] != b"\x55\xaa":
        raise ValueError("The probe must be a signed sector with empty disk identity and partition table")
    return probe[:CODE_BYTES] + mbr[CODE_BYTES:]


def build(output: Path, *, debug_exit: bool = False, nasm: str = "nasm") -> dict:
    source = Path(__file__).with_name("boot_probe.asm")
    output = output.resolve()
    if output == source.resolve():
        raise ValueError("Output must not overwrite the assembly source")
    output.parent.mkdir(parents=True, exist_ok=True)
    args = [nasm, "-f", "bin", "-o", str(output)]
    if debug_exit:
        args.append("-DTEST_DEBUG_EXIT=1")
    subprocess.run(args + [str(source)], check=True)
    data = output.read_bytes()
    if len(data) != 512 or data[440:510] != bytes(70) or data[510:] != b"\x55\xaa":
        raise RuntimeError("Assembler produced an invalid MBR code fragment")
    return {"schema_version": 1, "profile": "actual-win98-mbr-gop-boot-probe",
            "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "artifact": str(output), "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "code_area_bytes": CODE_BYTES, "test_debug_exit": debug_exit,
            "modifies_guest_disk": False, "io_sys_bytes_included": False}


def build_probe(out_dir: Path, test_exit: bool = False) -> Path:
    """Assemble a signed, empty-table probe plus its source/artifact receipt."""
    output = Path(out_dir) / ("boot-probe-test.bin" if test_exit else "boot-probe.bin")
    receipt = build(output, debug_exit=test_exit)
    output.with_suffix(".json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return output.resolve()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--debug-exit", action="store_true")
    parser.add_argument("--nasm", default="nasm")
    args = parser.parse_args()
    receipt = build(args.output, debug_exit=args.debug_exit, nasm=args.nasm)
    args.output.with_suffix(".json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
