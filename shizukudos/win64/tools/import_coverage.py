#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""How much of a real Win64 application can the Shizuku Win64 runtime load today?

Static import audit: every PE32+ under the given paths is parsed for its import and delay-import tables; each imported
(DLL, function) is checked against the export tables of the ntdll.dll / kernel32.dll this repository builds
(shizukudos/win64/build.py), using the same api-ms-* schema the Kernel64 loader uses (kernel64/ldr.c apiset_schema).
Imports of DLLs shipped with the application itself are internal and skipped. Everything else is a system DLL
that must exist for the image to load at all: those without a Shizuku implementation are listed as load blockers.

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
OURS = {"ntdll.dll", "kernel32.dll"}


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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("app", type=Path, help="directory (or file) of the application, scanned recursively for .exe/.dll")
    ap.add_argument("--build", type=Path, default=REPO / "build/shizukudos/win64")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()

    api_schema = schema()
    ours = {d: exports(args.build / d) for d in OURS}
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
    print(f"{total} distinct imported functions from {len(per_dll)} system DLLs; {hit} resolve against Shizuku "
          f"ntdll/kernel32 ({100.0 * hit / max(total, 1):.1f}%)\n")
    print(f"{'system DLL':40} {'imported':>8} {'provided':>9}")
    for dll, n, ok in rows[:args.top]:
        mark = "" if dll in OURS else "  <- no implementation"
        print(f"{dll:40} {n:8} {ok:9}{mark}")
    print(f"\nload blockers (DLLs imported at load time with no Shizuku implementation): {len(blockers)}")
    for dll, users in sorted(blockers.items(), key=lambda kv: -len(per_dll[kv[0]]))[:args.top]:
        print(f"  {dll:38} {len(per_dll[dll]):5} functions, needed by {len(users)} image(s)")
    for dll in sorted(OURS):
        missing = sorted(((len(users), fn) for fn, users in per_dll.get(dll, {}).items() if fn not in ours[dll]), reverse=True)
        print(f"\nmissing from Shizuku {dll}: {len(missing)} of {len(per_dll.get(dll, {}))} imported; most widely imported:")
        print("  " + ", ".join(fn for _, fn in missing[:args.top]))
    if args.json:
        args.json.write_text(json.dumps({
            "images": scanned, "distinct_imports": total, "resolved": hit,
            "system_dlls": {d: {"imported": n, "provided": ok} for d, n, ok in rows},
            "load_blockers": {d: sorted(u) for d, u in blockers.items()},
            "missing": {dll: sorted(fn for fn in per_dll.get(dll, {}) if fn not in ours[dll]) for dll in OURS}}, indent=1))


if __name__ == "__main__":
    sys.exit(main())
