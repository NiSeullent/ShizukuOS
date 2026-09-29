#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""How much of the user32/gdi32 surface a real application imports does the Shizuku GUI stack export?

Thin wrapper around win64/tools/import_coverage.py (unchanged): that tool only counts ntdll/kernel32, so this script adds
user32.dll and gdi32.dll to the set of system DLLs this repository provides, then prints the per-DLL numbers and the most
widely imported functions that are still missing. Like the tool, it measures loader-level coverage only (the import resolves),
not behaviour: behaviour is what the t_gui_*.exe programs and tests/run_k64_gui.py check.

  python3 shizukudos/tests/gui_import_coverage.py <application dir> [--top 40]
"""
import argparse
import collections
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "win64" / "tools"))
import import_coverage as ic  # noqa: E402

GUI = ("user32.dll", "gdi32.dll")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("app", type=Path)
    ap.add_argument("--build", type=Path, default=ic.REPO / "build/shizukudos/win64")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()
    provided = {d: ic.exports(args.build / d) for d in (*ic.OURS, *GUI) if (args.build / d).exists()}
    schema = ic.schema()
    files = sorted(p for p in ([args.app] if args.app.is_file() else args.app.rglob("*")) if p.suffix.lower() in (".exe", ".dll"))
    per = collections.defaultdict(lambda: collections.defaultdict(set))
    for p in files:
        try:
            imps = ic.scan(p, schema)
        except Exception:
            continue
        if imps is None:
            continue
        for dll, fn, _ in imps:
            prov, _kind = ic.resolve(dll, schema)
            per[prov or dll.lower()][fn].add(p.name)
    print(f"{'DLL':14} {'imported':>9} {'exported here':>14}")
    for dll in ("kernel32.dll", *GUI):
        fns = per.get(dll, {})
        have = provided.get(dll, set())
        print(f"{dll:14} {len(fns):9} {sum(1 for f in fns if f in have):14}")
    for dll in GUI:
        fns = per.get(dll, {})
        have = provided.get(dll, set())
        missing = sorted(((len(u), f) for f, u in fns.items() if f not in have), reverse=True)
        print(f"\n{dll}: {len(missing)} of {len(fns)} imported functions are not exported yet; most widely imported first:")
        print("  " + ", ".join(f for _, f in missing[:args.top]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
