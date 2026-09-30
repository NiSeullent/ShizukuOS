#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Which LOAD-TIME imports still block a given startup chain from loading on the Shizuku Win64 runtime?

A load simulator for the Kernel64 PE32+ loader. import_coverage.py counts every import of every image in a tree
(delay-loads included); a process start instead only needs the load-time (non-delay) imports of the images the loader
maps eagerly: the executable, then transitively every DLL named in a load-time import table. This tool walks exactly
that closure from one executable and resolves each DLL name the way kernel64/ldr.c does:
  - api-ms-*/ext-ms-* through the data-driven contract table (kernel64/apiset_contracts.txt, read by
    win64/tools/gen_apiset_table.lookup, kept identical to the C resolver kernel64/apiset.c by the host tests): the
    contract resolves only when its host DLL exists and (for a load-time import) exports the name;
  - KnownDLLs (the Windows 11 KnownDLLs list, mirrored from ldr.c) and api-set hosts come from the system directory;
  - every other name: the application directory first, then the built Shizuku system directory (\\SHZ\\SYS64).
For each eagerly loaded image it reports the load-time imports that would fail:
  - DLL not found (neither next to the application nor built by Shizuku)
  - API-set contract not in the table, or its host DLL not built
  - function (or ordinal) not exported by the resolved DLL, following export forwarders (API-set forwarders included)
The FIRST such failure per image is the loader diagnostic the guest would print; the kernel's own one-line message is
the ground truth once the image is on a disk inside the guest.
"""
import argparse
import json
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    raise SystemExit("pip install pefile")

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_apiset_table as apiset  # noqa: E402

# Windows 11 KnownDLLs (mirror of the list in kernel64/ldr.c): resolved from the system directory only.
KNOWN_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll",
    "coml2.dll", "difxapi.dll", "gdi32.dll", "gdiplus.dll", "imagehlp.dll", "imm32.dll", "msctf.dll", "msvcrt.dll",
    "normaliz.dll", "nsi.dll", "ole32.dll", "oleaut32.dll", "psapi.dll", "rpcrt4.dll", "sechost.dll", "setupapi.dll",
    "shcore.dll", "shell32.dll", "shlwapi.dll", "user32.dll", "wldap32.dll", "ws2_32.dll",
}


class Image:
    def __init__(self, path):
        self.path = path
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[d] for d in (
            "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT", "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT")])
        self.imports = []                                           # (dll, name-or-#ordinal)
        self.expect = {}                                            # (dll, "#N") -> the name pefile knows for that ordinal
        for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for i in e.imports:
                dll = e.dll.decode(errors="replace")
                if i.import_by_ordinal:                             # pefile names ws2_32/oleaut32 ordinals: keep the number
                    fn = f"#{i.ordinal}"
                    if i.name:
                        self.expect[(dll.lower(), fn)] = i.name.decode()
                else:
                    fn = i.name.decode()
                self.imports.append((dll, fn))
        self.delay = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))
        self.delay_imports = []
        for e in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            dll = e.dll.decode(errors="replace")
            for i in e.imports:
                if i.import_by_ordinal:                             # as above: by number, pefile's name is the expectation
                    fn = f"#{i.ordinal}"
                    if i.name:
                        self.expect[(dll.lower(), fn)] = i.name.decode()
                else:
                    fn = i.name.decode()
                self.delay_imports.append((dll, fn))
        self.exports, self.forwards, self.ordinals, self.ordinal_names = set(), {}, set(), {}
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exp:
            for s in exp.symbols:
                if s.ordinal is not None:
                    self.ordinals.add(s.ordinal)
                    if s.name:
                        self.ordinal_names[s.ordinal] = s.name.decode(errors="replace")
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
    ap.add_argument("--delay", action="store_true",
                    help="also list the delay-load imports of the loaded images that would fail when first called "
                         "(the program starts without them; a call raises the MSVC delay-load exception)")
    args = ap.parse_args()
    appdir = args.exe.parent
    rows = apiset.parse()
    system = {p.name.lower(): p for p in args.build.glob("*.dll")}
    appfiles = {c.name.lower(): c for c in appdir.iterdir() if c.is_file()}
    cache = {}

    def image(path):
        if path not in cache:
            cache[path] = Image(path)
        return cache[path]

    def base_name(dll):
        n = dll.lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        return n if n.endswith(".dll") or "." in n else n + ".dll"

    def locate(dll):
        n = base_name(dll)
        if dll.lower().startswith(("api-ms-", "ext-ms-")):
            result, row = apiset.lookup(rows, dll[:-4] if dll.lower().endswith(".dll") else dll)
            if result == apiset.VERSION:
                return None, "API-set contract version newer than the table"
            if result != apiset.OK:
                return None, "API-set contract not in the table"
            host = row.host.lower()                          # api-set hosts come from the system directory only
            return (system.get(host), "system") if host in system else (None, f"API-set host {row.host} not built")
        if n in KNOWN_DLLS:                                  # KnownDLLs: system directory only, never the app dir
            return (system.get(n), "system") if n in system else (None, "DLL not found")
        if n in appfiles:                                    # application directory first
            return appfiles[n], "app"
        if n in system:
            return system[n], "system"
        return None, "DLL not found"

    pinned = {}                                              # Shizuku DLL -> ordinals its module.json fixes ("ordinals")
    for mj in (REPO / "shizukudos/win64/dlls").glob("*/module.json"):
        pinned[mj.parent.name.lower() + ".dll"] = set(json.loads(mj.read_text()).get("ordinals", {}).values())

    def exported(img, fn, depth=0, expect=None):
        if fn.startswith("#"):                               # by ordinal: the export at that number must be the expected one
            n = int(fn[1:])
            if img.path.parent == args.build and n not in pinned.get(img.path.name.lower(), set()):
                return False                                 # a Shizuku DLL's unpinned ordinals are whatever the linker chose
            return n in img.ordinals and (expect is None or img.ordinal_names.get(n) == expect)
        if fn not in img.exports:
            return False
        fwd = img.forwards.get(fn)
        if not fwd or depth > 8:
            return True
        tdll, _, tfn = fwd.partition(".")
        path, _ = locate(tdll if tdll.lower().endswith(".dll") else tdll + ".dll")
        return bool(path) and exported(image(path), tfn, depth + 1)

    order, seen, report = [], set(), {}
    first_fail = None
    queue = [args.exe]
    while queue:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        order.append(path)
        img = image(path)
        missing, by_dll, first = [], {}, None
        for dll, fn in img.imports:
            target, where = locate(dll)
            if not target:
                why = where
            elif not exported(image(target), fn, expect=img.expect.get((dll.lower(), fn))):
                if target not in seen:
                    queue.append(target)
                why = "not exported by " + target.name + (" (Shizuku)" if where == "system" else "")
            else:
                if target not in seen:
                    queue.append(target)
                continue
            missing.append((dll, fn, why))
            if first is None:
                first = f"{dll}!{fn}: {why}"
        for dll, fn, why in missing:
            by_dll.setdefault((dll.lower(), why.split(" (")[0] if why.startswith("not exported") else why), []).append(fn)
        report[path.name] = {"load_time_imports": len(img.imports), "delay_imports": img.delay, "missing": len(missing),
                             "first_failure": first,
                             "by_dll": {f"{d} [{w}]": sorted(set(v)) for (d, w), v in sorted(by_dll.items())}}
        if first and first_fail is None:
            first_fail = (path.name, first)
    total = sum(r["load_time_imports"] for r in report.values())
    miss = sum(r["missing"] for r in report.values())
    print(f"startup chain of {args.exe.name}: {len(order)} image(s) loaded eagerly: {', '.join(p.name for p in order)}")
    print(f"load-time imports: {total}, would fail: {miss} ({100.0 * miss / max(total, 1):.1f}%)")
    if first_fail:
        print(f"predicted first loader failure: {args.exe.name} needs {first_fail[1]}  (in {first_fail[0]})\n")
    else:
        print("predicted result: the eager load-time closure resolves completely\n")
    for name, r in report.items():
        print(f"{name}: {r['load_time_imports']} load-time imports ({r['delay_imports']} delay-load not needed at start), "
              f"{r['missing']} missing")
        if r["first_failure"]:
            print(f"   first: {r['first_failure']}")
        for key, fns in sorted(r["by_dll"].items(), key=lambda kv: -len(kv[1])):
            print(f"   {len(fns):4}  {key}: {', '.join(fns[:args.top])}{' ...' if len(fns) > args.top else ''}")
    if args.delay:
        dmiss_total = 0
        for path in order:
            img = image(path)
            by = {}
            for dll, fn in img.delay_imports:
                target, where = locate(dll)
                if not target:
                    by.setdefault((dll, where), []).append(fn)
                elif not exported(image(target), fn, expect=img.expect.get((dll.lower(), fn))):
                    by.setdefault((dll, "not exported by " + target.name), []).append(fn)
            n = sum(len(v) for v in by.values())
            dmiss_total += n
            report[path.name]["delay_missing"] = n
            report[path.name]["delay_by_dll"] = {f"{d} [{w}]": sorted(set(v)) for (d, w), v in sorted(by.items())}
            if n:
                print(f"{path.name}: {len(img.delay_imports)} delay-load imports, {n} would fail when called")
                for (d, w), fns in sorted(by.items(), key=lambda kv: -len(kv[1])):
                    print(f"   {len(fns):4}  {d} [{w}]: {', '.join(fns[:args.top])}{' ...' if len(fns) > args.top else ''}")
        print(f"delay-load imports that would fail when called: {dmiss_total}")
    if args.json:
        args.json.write_text(json.dumps({"exe": str(args.exe), "chain": [p.name for p in order],
                                         "first_failure": first_fail, "images": report}, indent=1))
    return 0 if miss == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
