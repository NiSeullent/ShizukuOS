#!/usr/bin/env python3
"""Check actual COM bytes and retained memory bounds; no DOS execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

TAG = b"CBMEM-LAYOUT-V1\0"


def verify(data):
    def require(condition, label):
        if not condition:
            raise ValueError(label)
        checks.append(label)

    checks = []
    require(data.count(TAG) == 1, "unique native layout record")
    pos = data.index(TAG) + len(TAG)
    values = struct.unpack_from("<12H", data, pos)
    names = ("entry", "shrink", "query", "release", "report_start", "report_end",
             "stack_bottom", "stack_top", "image_end", "keep_paras", "keep_immediate",
             "stack_immediate")
    layout = dict(zip(names, values))
    at = lambda address, count: data[address - 0x100:address - 0x100 + count]
    require(layout["image_end"] == len(data) + 0x100, "actual image end")
    require(0x100 <= layout["entry"] < layout["shrink"] < layout["query"] < layout["release"] < layout["report_start"], "actual code order")
    require(layout["keep_paras"] == (layout["image_end"] + 15) // 16, "PSP included in exact retained paragraphs")
    require(layout["keep_paras"] < 0x1000, "retained block below 64 KiB")
    require(layout["report_end"] - layout["report_start"] == 2048, "whole 2048-byte report buffer retained")
    require(layout["stack_bottom"] >= layout["report_end"], "stack does not overlap report")
    require(layout["stack_top"] - layout["stack_bottom"] == 1024, "whole 1024-byte own stack retained")
    require(layout["stack_top"] == layout["image_end"], "own stack top at retained image end")
    require(layout["image_end"] <= layout["keep_paras"] * 16 <= layout["image_end"] + 15, "no released code data or stack")
    require(at(layout["keep_immediate"], 2) == struct.pack("<H", layout["keep_paras"]), "actual shrink size immediate")
    require(at(layout["stack_immediate"], 2) == struct.pack("<H", layout["stack_top"]), "actual SP immediate")
    require(at(layout["shrink"], 8) == b"\xbb" + struct.pack("<H", layout["keep_paras"]) + b"\xb4\x4a\xf9\xcd\x21", "actual AH4A shrink vector")
    require(at(layout["query"], 8) == b"\xbb\xff\xff\xb4\x48\xf9\xcd\x21", "actual FFFF paragraph AH48 query vector")
    require(at(layout["release"], 5) == b"\xb4\x49\xf9\xcd\x21", "actual exceptional own allocation release vector")
    require(b"\xb8\x06\x33\xcd\x21" in data[:layout["report_start"] - 0x100], "actual AX3306 query")
    require(b"\xb4\x62\xcd\x21" in data[:layout["report_start"] - 0x100], "actual own PSP query")
    require(b"\xcd\x12" in data[:layout["report_start"] - 0x100], "actual BIOS INT12 query")
    require(b"\xb8\x00\x58\xcd\x21" in data[:layout["report_start"] - 0x100], "actual allocator strategy query")
    require(b"\xb8\x02\x58\xcd\x21" in data[:layout["report_start"] - 0x100], "actual UMB link query")
    return {"schema": "cb43-conventional-memory-native-layout-v1", "static_checks": len(checks),
            "checks": checks, "layout": layout, "COM_bytes": len(data),
            "COM_sha256": hashlib.sha256(data).hexdigest(), "DOS_executed": False,
            "free_conventional_memory_measured": False, "Windows98_verified": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    result = verify(data)
    rejected = []
    for field in ("keep_immediate", "stack_immediate", "query"):
        changed = bytearray(data)
        changed[result["layout"][field] - 0x100] ^= 1
        try:
            verify(bytes(changed))
        except ValueError:
            rejected.append(field)
        else:
            raise ValueError("unsafe binary mutation accepted: " + field)
    result["unsafe_binary_mutations_rejected"] = rejected
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
