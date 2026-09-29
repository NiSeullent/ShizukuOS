#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""How much of a real Win64 application can the Shizuku Win64 runtime load today?

Static import audit: every PE32+ under the given paths is parsed for its import and delay-import tables; each imported
(DLL, function) is checked against the export tables of the ntdll.dll / kernel32.dll this repository builds
(shizukudos/win64/build.py) and of every extra module built from win64/dlls/, using the same api-ms-* schema the Kernel64 loader uses (kernel64/ldr.c apiset_schema).
Imports of DLLs shipped with the application itself are internal and skipped. Everything else is a system DLL
that must exist for the image to load at all: those without a Shizuku implementation are listed as load blockers.

With --providers the scan covers kernel-mode images instead (.sys/.dll with the native subsystem) and groups their
imports by provider module (ntoskrnl, hal, ndis, storport, wdfldr/Wdf01000, dxgkrnl, ...); --exports <json> checks them
against the NT driver host's export list.

This measures loader-level coverage only. It says nothing about whether the functions behave correctly, and it is
not a claim that any of these applications runs.
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    raise SystemExit("pip install pefile")

REPO = Path(__file__).resolve().parents[3]


def schema():
    text = (REPO / "shizukudos/kernel64/ldr.c").read_text()
    block = text[text.index("apiset_schema[]"):]
    block = block[:block.index("{0, 0}")]
    return {m.group(1): m.group(2) for m in re.finditer(r'\{"([^"]+)", "([^"]+)"\}', block)}


def exports(dll):
    pe = pefile.PE(str(dll), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    return {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}


def resolve(name, api_schema):
    """-> (provider dll or None, kind). kind: ours | apiset-unmapped | system"""
    n = name.lower()
    if n.startswith(("api-", "ext-")):
        for prefix, host in api_schema.items():
            if n.startswith(prefix + "-"):
                return host, "apiset"
        return None, "apiset-unmapped"
    return n, "direct"


def scan(path, api_schema):
    pe = pefile.PE(str(path), fast_load=True)
    if pe.FILE_HEADER.Machine != 0x8664:
        return None
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                           pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"]])
    found = []
    for attr, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
        for entry in getattr(pe, attr, []):
            dll = entry.dll.decode(errors="replace")
            for imp in entry.imports:
                fn = imp.name.decode(errors="replace") if imp.name else f"#{imp.ordinal}"
                found.append((dll, fn, delayed))
    return found


# ------------------------------------------------------------------------------------------ kernel-mode providers
# --providers: the same static import audit for kernel-mode images (.sys), grouped by the module that must provide
# each import (ntoskrnl, hal, the framework libraries). With --exports, each provider's imported functions are checked
# against an export list (the NT driver host's machine-readable export JSON); without it the lists are raw.
PROVIDERS = {"ntoskrnl.exe": "ntoskrnl", "ntkrnlpa.exe": "ntoskrnl", "ntkrnlmp.exe": "ntoskrnl", "hal.dll": "hal",
             "ndis.sys": "ndis", "storport.sys": "storport", "scsiport.sys": "scsiport", "classpnp.sys": "classpnp",
             "wdfldr.sys": "wdf01000 (via wdfldr.sys)", "wdf01000.sys": "wdf01000", "dxgkrnl.sys": "dxgkrnl",
             "portcls.sys": "portcls", "ks.sys": "ks", "hidclass.sys": "hidclass", "hidparse.sys": "hidparse",
             "usbd.sys": "usbd", "wmilib.sys": "wmilib", "videoprt.sys": "videoprt", "ataport.sys": "ataport",
             "netio.sys": "netio", "fltmgr.sys": "fltmgr", "cng.sys": "cng", "msrpc.sys": "msrpc", "wdfldr": "wdf01000"}


def load_exports(path):
    """Export JSON of the driver host -> {dll lower: set(names)}. Accepted shapes: {"ntoskrnl.exe": [...], ...},
    {"exports"|"providers"|"modules": {dll: [...] | {"exports": [...]}}}, or [{"dll"|"module": x, "exports"|"names": [...]}]."""
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        for key in ("exports", "providers", "modules"):
            if isinstance(data.get(key), (dict, list)):
                data = data[key]
                break
    out = {}
    items = data.items() if isinstance(data, dict) else [((d.get("dll") or d.get("module") or d.get("name")), d) for d in data]
    for dll, v in items:
        if not isinstance(dll, str):
            continue
        names = v if isinstance(v, list) else (v.get("exports") or v.get("names") or v.get("functions") or []) if isinstance(v, dict) else []
        names = {n if isinstance(n, str) else (n.get("name") if isinstance(n, dict) else None) for n in names}
        dll = dll.lower()
        if "." not in dll:
            dll = {"ntoskrnl": "ntoskrnl.exe", "hal": "hal.dll"}.get(dll, dll + ".sys")
        out.setdefault(dll, set()).update(n for n in names if n)
    return out


def providers_main(args):
    exports = load_exports(args.exports) if args.exports else None
    files = sorted(p for p in ([args.app] if args.app.is_file() else args.app.rglob("*")) if p.suffix.lower() in (".sys", ".dll"))
    per = collections.defaultdict(lambda: collections.defaultdict(set))                    # provider dll -> fn -> images
    images = {}
    for p in files:
        try:
            imps = scan(p, {})
        except pefile.PEFormatError:
            continue
        if imps is None:
            continue
        pe = pefile.PE(str(p), fast_load=True)
        if pe.OPTIONAL_HEADER.Subsystem != 1:                                               # IMAGE_SUBSYSTEM_NATIVE only
            continue
        rel = str(p.relative_to(args.app)) if args.app.is_dir() else p.name
        images[rel] = collections.defaultdict(list)
        for dll, fn, _ in imps:
            per[dll.lower()][fn].add(rel)
            images[rel][dll.lower()].append(fn)
    local = {Path(r).name.lower() for r in images}
    print(f"{len(images)} kernel-mode images (subsystem native) under {args.app}")
    print(f"export list: {args.exports if exports else 'none (raw import lists; pass --exports <driver-host export JSON>)'}\n")
    print(f"{'provider':30} {'module':16} {'imported':>8} {'provided':>9} {'images':>7}")
    rows = {}
    for dll, fns in sorted(per.items(), key=lambda kv: -len(kv[1])):
        have = exports.get(dll) if exports else None
        ok = sum(1 for f in fns if have and f in have) if have is not None else None
        users = {u for us in fns.values() for u in us}
        name = PROVIDERS.get(dll, dll.rsplit(".", 1)[0] + (" (in the image set)" if dll in local else ""))
        rows[dll] = {"provider": name, "imported": sorted(fns), "provided": sorted(f for f in fns if have and f in have) if have is not None else None,
                     "images": sorted(users)}
        print(f"{name:30} {dll:16} {len(fns):8} {('-' if ok is None else ok):>9} {len(users):7}")
    print("\nper image (imports per provider" + (", provided/imported" if exports else "") + "):")
    table = {}
    for rel, by in sorted(images.items()):
        cells = []
        for dll, fns in sorted(by.items()):
            have = exports.get(dll) if exports else None
            prov = PROVIDERS.get(dll, dll)
            if have is not None:
                cells.append(f"{prov}={sum(1 for f in set(fns) if f in have)}/{len(set(fns))}")
            else:
                cells.append(f"{prov}={len(set(fns))}")
        missing = sorted({(dll, f) for dll, fns in by.items() for f in fns if exports is not None and not (exports.get(dll) and f in exports[dll])})
        table[rel] = {"imports": {d: sorted(set(f)) for d, f in by.items()}, "missing": [f"{d}!{f}" for d, f in missing] if exports else None}
        print(f"  {rel:48} {'  '.join(cells)}" + (f"   loadable={'yes' if not missing else 'no (' + str(len(missing)) + ' missing)'}" if exports else ""))
    if exports:
        for dll, fns in sorted(per.items(), key=lambda kv: -len(kv[1])):
            have = exports.get(dll, set())
            miss = sorted(((len(u), f) for f, u in fns.items() if f not in have), reverse=True)
            if miss:
                print(f"\nmissing from {dll} ({len(miss)} of {len(fns)}), most widely imported first:")
                print("  " + ", ".join(f for _, f in miss[:args.top]))
    if args.json:
        args.json.write_text(json.dumps({"images": table, "providers": rows, "exports": args.exports and str(args.exports)}, indent=1))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("app", type=Path, help="directory (or file) of the application, scanned recursively for .exe/.dll")
    ap.add_argument("--providers", action="store_true", help="kernel-mode images (.sys): imports grouped by provider module")
    ap.add_argument("--exports", type=Path, help="with --providers: export JSON of the NT driver host")
    ap.add_argument("--build", type=Path, default=REPO / "build/shizukudos/win64")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()
    if args.providers:
        return providers_main(args)

    api_schema = schema()
    ours = {p.name.lower(): exports(p) for p in sorted(args.build.glob("*.dll"))}     # ntdll, kernel32 and every extra module
    OURS = set(ours)
    files = sorted(p for p in ([args.app] if args.app.is_file() else args.app.rglob("*")) if p.suffix.lower() in (".exe", ".dll"))
    local = {p.name.lower() for p in files}
    per_dll = collections.defaultdict(lambda: collections.defaultdict(set))       # dll -> fn -> importing files
    blockers = collections.defaultdict(set)                                         # missing DLL -> importing files
    scanned = 0
    for p in files:
        try:
            imps = scan(p, api_schema)
        except pefile.PEFormatError:
            continue
        if imps is None:
            continue
        scanned += 1
        for dll, fn, delayed in imps:
            provider, kind = resolve(dll, api_schema)
            key = provider or dll.lower()
            if key in local:
                continue                                                            # shipped with the app
            if key not in OURS:
                if not delayed:
                    blockers[key].add(p.name)
            per_dll[key][fn].add(p.name)
    rows, total, hit = [], 0, 0
    for dll, fns in sorted(per_dll.items(), key=lambda kv: -len(kv[1])):
        have = ours.get(dll)
        ok = sum(1 for f in fns if have and f in have)
        rows.append((dll, len(fns), ok))
        total += len(fns)
        hit += ok
    print(f"{scanned} PE32+ images scanned under {args.app}")
    print(f"{total} distinct imported functions from {len(per_dll)} system DLLs; {hit} resolve against "
          f"the built Shizuku DLLs ({100.0 * hit / max(total, 1):.1f}%)\n")
    print(f"{'system DLL':40} {'imported':>8} {'provided':>9}")
    for dll, n, ok in rows[:args.top]:
        mark = "" if dll in OURS else "  <- no implementation"
        print(f"{dll:40} {n:8} {ok:9}{mark}")
    print(f"\nload blockers (DLLs imported at load time with no Shizuku implementation): {len(blockers)}")
    for dll, users in sorted(blockers.items(), key=lambda kv: -len(per_dll[kv[0]]))[:args.top]:
        print(f"  {dll:38} {len(per_dll[dll]):5} functions, needed by {len(users)} image(s)")
    for dll in sorted(d for d in OURS if d in per_dll):
        missing = sorted(((len(users), fn) for fn, users in per_dll.get(dll, {}).items() if fn not in ours[dll]), reverse=True)
        print(f"\nmissing from Shizuku {dll}: {len(missing)} of {len(per_dll.get(dll, {}))} imported; most widely imported:")
        print("  " + ", ".join(fn for _, fn in missing[:args.top]))
    if args.json:
        args.json.write_text(json.dumps({
            "images": scanned, "distinct_imports": total, "resolved": hit,
            "system_dlls": {d: {"imported": n, "provided": ok} for d, n, ok in rows},
            "load_blockers": {d: sorted(u) for d, u in blockers.items()},
            "missing": {dll: sorted(fn for fn in per_dll.get(dll, {}) if fn not in ours[dll]) for dll in sorted(OURS) if dll in per_dll}}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
