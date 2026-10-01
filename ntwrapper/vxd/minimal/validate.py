#!/usr/bin/env python3
"""Independent bounded decoder of the fixture/production LE subset. No emitter import.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path


class InvalidLE(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise InvalidLE(message)


def decode(image):
    require(128 <= len(image) <= 16 * 1024 * 1024, "bounded image length")

    def read(at, size):
        require(0 <= at <= len(image) and 0 <= size <= len(image) - at, "file range")
        return image[at:at + size]

    def number(at, kind="I"):
        return struct.unpack("<" + kind, read(at, struct.calcsize("<" + kind)))[0]

    require(read(0, 2) == b"MZ", "DOS signature")
    le = number(0x3c)
    require(le >= 64 and read(le, 2) == b"LE", "LE signature/offset")
    read(le, 196)
    require(read(le + 2, 6) == bytes(6), "little-endian level-zero LE")
    require(number(le + 8, "H") in (2, 3) and number(le + 10, "H") == 4, "386/486 Win386 LE")
    header = {name: number(le + offset) for name, offset in (
        ("module_flags", 0x10), ("pages", 0x14), ("start_object", 0x18), ("entry_point", 0x1c),
        ("stack_object", 0x20), ("stack_pointer", 0x24), ("page_size", 0x28), ("last_page_bytes", 0x2c),
        ("fixup_size", 0x30), ("loader_size", 0x38), ("object_table", 0x40), ("objects", 0x44),
        ("page_map", 0x48), ("resident_names", 0x58), ("entry_table", 0x5c),
        ("fixup_pages", 0x68), ("fixup_records", 0x6c), ("import_modules", 0x70),
        ("import_module_count", 0x74), ("import_procedures", 0x78), ("data_pages", 0x80),
        ("preload_pages", 0x84))}
    h = header
    require(h["module_flags"] == 0x38000, "dynamic VxD module flags")
    require(h["page_size"] == 4096 and 0 < h["pages"] <= 4096, "bounded 4-KiB pages")
    require(0 < h["last_page_bytes"] <= 4096 and 0 < h["objects"] <= 32, "last page/object count")
    require(h["preload_pages"] == h["pages"], "all fixture pages preloaded")
    require(not any(h[k] for k in ("start_object", "entry_point", "stack_object", "stack_pointer")), "no process entry/stack")
    require(h["import_module_count"] == 0, "no imported LE modules")
    require(not any(number(le + off) for off in (0x4c, 0x50, 0x54, 0x60, 0x64, 0x7c, 0x88, 0x8c, 0x90, 0x94, 0x98, 0x9c, 0xa0, 0xa4, 0xa8, 0xac, 0xb8, 0xbc)),
            "unsupported auxiliary table")
    require(number(le + 0xc0, "H") == 0 and number(le + 0xc2, "H") == 0x040a, "unassigned device/Win98 DDK version")
    require(h["object_table"] >= 196, "object table starts after header")
    require(h["page_map"] >= h["object_table"] + 24 * h["objects"], "nonoverlapping object/page tables")
    require(h["resident_names"] >= h["page_map"] + 4 * h["pages"], "nonoverlapping page/name tables")
    require(h["entry_table"] > h["resident_names"] and h["fixup_pages"] > h["entry_table"], "ordered name/entry/fixup tables")
    require(h["loader_size"] == h["fixup_pages"] - h["object_table"], "loader section size")
    require(h["fixup_records"] == h["fixup_pages"] + 4 * (h["pages"] + 1), "fixup page table including sentinel")
    require(h["import_modules"] >= h["fixup_records"] and h["import_procedures"] == h["import_modules"], "empty import module table")
    require(read(le + h["import_procedures"], 1) == b"\0", "empty import procedure table")
    require(h["fixup_size"] == h["import_procedures"] + 1 - h["fixup_pages"], "fixup section size")
    require(h["data_pages"] >= le + h["import_procedures"] + 1 and h["data_pages"] % 4096 == 0, "absolute aligned data page offset")
    require(len(image) == h["data_pages"] + (h["pages"] - 1) * 4096 + h["last_page_bytes"], "exact physical page extent/EOF")

    objects, buffers, owners = [], [], []
    next_page = 1
    for i in range(h["objects"]):
        size, base, flags, start, count, reserved = struct.unpack("<6I", read(le + h["object_table"] + 24 * i, 24))
        require(size and count == (size + 4095) // 4096 and start == next_page and not reserved, "object size/page range")
        require((flags & 0x2041) == 0x2041 and flags & ~0x2267 == 0, "supported readable/preloaded/big object flags")
        require(count <= h["pages"] - len(owners), "object pages within module")
        data = bytearray()
        for page in range(count):
            map_at = le + h["page_map"] + 4 * (start + page - 1)
            mapping = read(map_at, 4)
            physical = int.from_bytes(mapping[:3], "big")
            require(physical == start + page and mapping[3] == 0, "one-to-one valid enumerated page map")
            extent = h["last_page_bytes"] if physical == h["pages"] else 4096
            data.extend(read(h["data_pages"] + (physical - 1) * 4096, extent))
            owners.append((i + 1, page))
        require(size <= len(data), "object backed by physical pages")
        buffers.append(bytes(data[:size]))
        objects.append({"size": size, "base": base, "flags": flags, "page_start": start, "page_count": count})
        next_page += count
    require(len(owners) == h["pages"], "all pages owned")
    last = objects[-1]
    require((last["size"] - 1) % 4096 + 1 == h["last_page_bytes"], "last object/physical page agreement")

    names, at = [], le + h["resident_names"]
    while True:
        require(at < le + h["entry_table"], "resident name terminator")
        n = read(at, 1)[0]; at += 1
        if not n:
            break
        require(n <= 127 and at + n + 2 <= le + h["entry_table"], "resident name bound")
        name = read(at, n)
        require(all(32 <= c < 127 for c in name), "ASCII resident name")
        names.append((name.decode("ascii"), number(at + n, "H")))
        require(len(names) <= 32, "resident name count")
        at += n + 2
    require(names and names[0][1] == 0, "module name ordinal zero")
    entry = read(le + h["entry_table"], 10)
    n, kind, objno, flags, offset, end = struct.unpack("<BBHBIB", entry)
    require(n == 1 and kind == 3 and flags & 1 and end == 0 and 1 <= objno <= len(objects), "one exported ordinal-1 32-bit DDB entry")
    require(le + h["entry_table"] + 10 <= le + h["fixup_pages"], "bounded entry bundle")
    ddb = buffers[objno - 1]
    require(offset + 80 <= len(ddb) and objects[objno - 1]["flags"] & 2, "writable complete DDB")
    ddb = ddb[offset:offset + 80]
    require(number(le + 0xc2, "H") == struct.unpack_from("<H", ddb, 4)[0], "DDB/header SDK agreement")
    require(ddb[:4] == bytes(4) and ddb[6:8] == bytes(2) and ddb[10:12] == bytes(2), "initial DDB ownership fields")
    require(ddb[12:20].decode("ascii", errors="replace").rstrip() == names[0][0], "DDB/module name agreement")
    require(struct.unpack_from("<I", ddb, 20)[0] == 0x80000000 and ddb[28:60] == bytes(32), "DDB init order/no service APIs")
    require(struct.unpack_from("<5I", ddb, 60) == (0x50726576, 80, 0x52737631, 0x52737632, 0x52737633), "DDB size/sentinels")

    page_offsets = [number(le + h["fixup_pages"] + i * 4) for i in range(h["pages"] + 1)]
    require(page_offsets[0] == 0 and all(a <= b for a, b in zip(page_offsets, page_offsets[1:])), "monotonic fixup page offsets")
    require(page_offsets[-1] == h["import_modules"] - h["fixup_records"], "fixup terminal offset")
    fixups, seen = [], {}
    for page, (begin, finish) in enumerate(zip(page_offsets, page_offsets[1:])):
        require((finish - begin) % 9 == 0, "whole narrow internal fixup records")
        source_obj, local_page = owners[page]
        for pos in range(begin, finish, 9):
            source_type, target_flags, source, target_obj, target = struct.unpack("<BBhBI", read(le + h["fixup_records"] + pos, 9))
            require(source_type in (7, 8) and target_flags == 0x10, "32-bit internal absolute/relative fixup")
            where = local_page * 4096 + source
            require(-3 <= source < 4096 and 0 <= where <= len(buffers[source_obj - 1]) - 4, "fixup source bounds")
            require(1 <= target_obj <= len(objects) and target < objects[target_obj - 1]["size"], "fixup target bounds")
            value = (target_obj, target, source_type)
            key = (source_obj, where)
            if key in seen:
                require(seen[key] == value and source < 0, "only matching straddling fixup duplicate")
                continue
            require(all(key[0] != old[0] or abs(key[1] - old[1]) >= 4 for old in seen), "nonoverlapping fixup writes")
            seen[key] = value
            fixups.append({"source_object": source_obj, "source_offset": where,
                           "target_object": target_obj, "target_offset": target, "relative": source_type == 8})
    control = [r for r in fixups if r["source_object"] == objno and r["source_offset"] == offset + 24]
    require(len(control) == 1 and not control[0]["relative"] and objects[control[0]["target_object"] - 1]["flags"] & 4,
            "DDB control pointer relocates into executable object")
    return {"header": h, "objects": objects, "module_name": names[0][0],
            "ddb": {"object": objno, "offset": offset, "bytes": 80, "control": control[0]},
            "fixups": fixups, "buffers": buffers}


def relocate(decoded, bases):
    require(len(bases) == len(decoded["objects"]), "one load base per object")
    for i, (base, obj) in enumerate(zip(bases, decoded["objects"])):
        require(0 <= base <= 0xffffffff - obj["size"], "32-bit relocated object range")
        require(all(base + obj["size"] <= b or b + other["size"] <= base
                    for b, other in zip(bases[:i], decoded["objects"][:i])), "disjoint load bases")
    output = [bytearray(b) for b in decoded["buffers"]]
    for r in decoded["fixups"]:
        value = bases[r["target_object"] - 1] + r["target_offset"]
        if r["relative"]:
            value -= bases[r["source_object"] - 1] + r["source_offset"] + 4
        struct.pack_into("<I", output[r["source_object"] - 1], r["source_offset"], value & 0xffffffff)
    return output


def description(image):
    result = decode(image)
    result.pop("buffers")
    result["sha256"] = hashlib.sha256(image).hexdigest()
    result["bytes"] = len(image)
    result["native_loader_acceptance"] = "not_measured"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    try:
        report = {"image": description(args.image.read_bytes())}
        if args.compare:
            report["comparison"] = description(args.compare.read_bytes())
            report["different_header_fields"] = {k: [report["image"]["header"][k], report["comparison"]["header"][k]]
                for k in report["image"]["header"] if report["image"]["header"][k] != report["comparison"]["header"][k]}
        print(json.dumps(report, indent=2))
    except (OSError, InvalidLE) as exc:
        parser.exit(1, f"LE validation failed: {exc}\n")


if __name__ == "__main__":
    main()
