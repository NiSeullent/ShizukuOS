#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Which LOAD-TIME imports still block a given startup chain from loading on the Shizuku Win64 runtime?

import_coverage.py counts every import of every image in a tree (delay-loads included). A process start only needs
the load-time (non-delay) imports of the images the loader maps eagerly: the executable, then transitively every DLL
named in a load-time import table. This tool walks exactly that closure starting from one executable, resolving DLL
names the way the Kernel64 loader does (application directory first, then the built Shizuku system DLLs; api-ms-*/
ext-ms-* through the contract table in kernel64/ldr.c), and reports, per image, the imports that would fail:
  - DLL not found (neither in the app dir nor built by Shizuku)
  - API set contract not mapped
  - function (or ordinal) not exported by the resolved DLL, following export forwarders
It predicts the loader's first failures; the kernel's own diagnostics are the ground truth once the image can be read
from a disk inside the guest.
"""
import argparse
import json
import re
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    raise SystemExit("pip install pefile")

REPO = Path(__file__).resolve().parents[3]


def apiset_schema():
    text = (REPO / "shizukudos/kernel64/ldr.c").read_text()
    block = text[text.index("apiset_schema[]"):]
    block = block[:block.index("{0, 0}")]
    return [(m.group(1), m.group(2)) for m in re.finditer(r'\{"([^"]+)", "([^"]+)"\}', block)]


class Image:
    def __init__(self, path):
        self.path = path
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[d] for d in (
            "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT")])
        self.imports = []                                           # (dll, name-or-#ordinal)
        for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for i in e.imports:
                self.imports.append((e.dll.decode(errors="replace"), i.name.decode() if i.name else f"#{i.ordinal}"))
        self.delay = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))
        self.exports, self.forwards, self.ordinals = set(), {}, set()
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exp:
            for s in exp.symbols:
                if s.ordinal is not None:
                    self.ordinals.add(s.ordinal)
                if s.name:
                    n = s.name.decode(errors="replace")
                    self.exports.add(n)
                    if s.forwarder:
                        self.forwards[n] = s.forwarder.decode(errors="replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", type=Path)
    ap.add_argument("--build", type=Path, default=REPO / "build/shizukudos/win64")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()
    appdir = args.exe.parent
    schema = apiset_schema()
    system = {p.name.lower(): p for p in args.build.glob("*.dll")}
    cache = {}

    def image(path):
        if path not in cache:
            cache[path] = Image(path)
        return cache[path]

    def locate(dll):
        n = dll.lower()
        if n.startswith(("api-ms-", "ext-ms-")):
            for prefix, host in schema:
                if n.startswith(prefix.lower() + "-"):
                    return locate(host)
            return None, "api set contract not mapped"
        local = appdir / dll
        for cand in appdir.iterdir():
            if cand.name.lower() == n:
                return cand, "app"
        if n in system:
            return system[n], "system"
        return None, "DLL not found"

    def exported(img, fn, depth=0):
        if fn.startswith("#"):
            return int(fn[1:]) in img.ordinals
        if fn not in img.exports:
            return False
        fwd = img.forwards.get(fn)
        if not fwd or depth > 8:
            return True
        tdll, _, tfn = fwd.partition(".")
        path, _ = locate(tdll if tdll.lower().endswith(".dll") else tdll + ".dll")
        return bool(path) and exported(image(path), tfn, depth + 1)

    order, seen, report = [], set(), {}
    queue = [args.exe]
    while queue:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        order.append(path)
        img = image(path)
        missing, by_dll = [], {}
        for dll, fn in img.imports:
            target, where = locate(dll)
            if not target:
                missing.append((dll, fn, where))
                continue
            if target not in seen:
                queue.append(target)
            if not exported(image(target), fn):
                missing.append((dll, fn, "not exported by " + target.name + (" (Shizuku)" if where == "system" else "")))
        for dll, fn, why in missing:
            by_dll.setdefault((dll.lower(), why.split(" (")[0] if why.startswith("not exported") else why), []).append(fn)
        report[path.name] = {"load_time_imports": len(img.imports), "delay_imports": img.delay, "missing": len(missing),
                             "by_dll": {f"{d} [{w}]": sorted(set(v)) for (d, w), v in sorted(by_dll.items())}}
    total = sum(r["load_time_imports"] for r in report.values())
    miss = sum(r["missing"] for r in report.values())
    print(f"startup chain of {args.exe.name}: {len(order)} image(s) loaded eagerly: {', '.join(p.name for p in order)}")
    print(f"load-time imports: {total}, would fail: {miss} ({100.0 * miss / max(total, 1):.1f}%)\n")
    for name, r in report.items():
        print(f"{name}: {r['load_time_imports']} load-time imports ({r['delay_imports']} delay-load not needed at start), "
              f"{r['missing']} missing")
        for key, fns in sorted(r["by_dll"].items(), key=lambda kv: -len(kv[1])):
            print(f"   {len(fns):4}  {key}: {', '.join(fns[:args.top])}{' ...' if len(fns) > args.top else ''}")
    if args.json:
        args.json.write_text(json.dumps({"exe": str(args.exe), "chain": [p.name for p in order], "images": report}, indent=1))
    return 0 if miss == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
