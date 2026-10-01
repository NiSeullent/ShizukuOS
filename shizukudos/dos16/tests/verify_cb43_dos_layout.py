#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check actual linked MZ bytes, relocations and flattened DOS kernel bytes."""
import argparse
import hashlib
import json
import pathlib
import re
import struct


def verify(tree):
    kernel = tree / "kernel"
    exe = (kernel / "kernel.exe").read_bytes()
    flat = (kernel / "kernel.sys").read_bytes()
    symbols = {}
    for line in (kernel / "kernel.map").read_text().splitlines():
        match = re.match(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\*?\s+(\S+)", line)
        if match:
            symbols[match[3]] = (int(match[1], 16), int(match[2], 16))
    checks = []

    def check(condition, name):
        if not condition:
            raise ValueError(name)
        checks.append(name)

    check(exe[:2] == b"MZ", "actual DOS linked executable has MZ header")
    header = struct.unpack_from("<14H", exe)
    image = exe[header[4] * 16:]
    reloc = {struct.unpack_from("<HH", exe, header[12] + i * 4) for i in range(header[3])}
    ds, base = symbols["_DATASTART"]
    winseg, winbase = symbols["_winStartupInfo"]
    check(base == 0 and ds == winseg, "startup info belongs to DOS data group")
    check(symbols["_firstsftt"] == (ds, 0xcc), "first SFT fixed address DS:00CC preserved")
    ptr = struct.unpack_from("<HH", image, ds * 16 + winbase + 14)
    item, itemseg = ptr
    check(itemseg == ds, "startup instance table points to DOS data segment")
    check(struct.unpack_from("<I", image, ds * 16 + winbase + 18)[0] == 0,
          "4.0 optional instance pointer is an actual linked zero DWORD")
    low, high, size = struct.unpack_from("<HHH", image, itemseg * 16 + item)
    check((low, high) == (0, ds), "IIS_Ptr bytes encode offset-low then segment-high")
    check((item + 2, itemseg) in reloc, "MZ relocation targets IIS_Ptr segment word")
    check((item, itemseg) not in reloc, "MZ relocation never targets IIS_Ptr offset word")
    check(symbols["_markEndInstanceData"] == (ds, size),
          "actual instance item length covers complete DOS data group")
    check(image[itemseg * 16 + item + 6:itemseg * 16 + item + 12] == b"\0" * 6,
          "instance list has actual zero pointer and zero length terminator")
    check(item + 12 <= symbols["_winPatchTable"][1] and symbols["_winReportHidden"][1] < 0xcc,
          "instance table and presence flag do not overlap fixed SFT")
    # The uncompressed DOS16 build invokes exeflat with load segment 0x60.
    check(struct.unpack_from("<HH", flat, ds * 16 + winbase + 14) == (item, ds + 0x60),
          "flattened kernel startup pointer has actual load-segment relocation")
    check(struct.unpack_from("<HH", flat, ds * 16 + item) == (0, ds + 0x60),
          "flattened kernel IIS_Ptr resolves actual DOS DS:0000")
    check(struct.unpack_from("<I", flat, ds * 16 + winbase + 18)[0] == 0,
          "flattened kernel preserves optional NULL pointer")
    return {
        "schema": "shizukudos-cb43-linked-dos-layout-v1",
        "passed": len(checks), "failed": 0, "checks": checks,
        "kernel_exe_sha256": hashlib.sha256(exe).hexdigest(),
        "kernel_sys_sha256": hashlib.sha256(flat).hexdigest(),
        "dos_group_link_segment": ds, "startup_offset": winbase,
        "instance_table_offset": item, "instance_bytes": size,
        "limits": ["Source-link byte/relocation checks, no Windows boot", "Uncompressed exeflat load segment 0x60 profile"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-tree", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = verify(args.kernel_tree.resolve())
    with args.output.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({"passed": result["passed"], "failed": 0}))


if __name__ == "__main__":
    main()
