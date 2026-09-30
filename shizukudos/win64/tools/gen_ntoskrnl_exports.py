#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Emit the driver-host export surface from its single source of truth.

Parses shizukudos/kernel64/ntdrv_prov.c -- the same tables the running kernel links -- and
writes, into <out>/:
  ntoskrnl-exports.json   {"ntoskrnl.exe":[...], "hal.dll":[...]}  (fed to import_coverage.py --ntoskrnl)
  ntoskrnl.def / hal.def  dlltool inputs whose LIBRARY names are ntoskrnl.exe / hal.dll,
                          so an unmodified .sys links its imports against exactly what the kernel provides.

The measured/linkable surface is therefore identical to what DriverEntry actually finds at load time.
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PROV = REPO / "shizukudos/kernel64/ntdrv_prov.c"


def table_names(text, table):
    """Names inside `const ntdrv_export_t <table>[] = { ... };` -- from E(Name) and { "Name", ... }."""
    m = re.search(r"ntdrv_export_t\s+" + re.escape(table) + r"\[\]\s*=\s*\{(.*?)\n\};", text, re.S)
    if not m:
        raise SystemExit(f"table {table} not found in {PROV}")
    body = m.group(1)
    # E(Name): function; C("cname", impl): function under its C name; V(Name): data export; { "Name", ... }: literal entry.
    # The table is read in source order so the emitted list keeps it.
    names = [(mm.group(2) or mm.group(3) or mm.group(4) or mm.group(5), mm.group(1) == "V")
             for mm in re.finditer(r'\b(E|C|V)\(\s*(?:(\w+)|"([^"]+)"\s*,\s*\w+)\s*\)|\{\s*"([^"]+)"\s*,|\bV\((\w+)\)', body)
             if mm.group(2) or mm.group(3) or mm.group(4) or mm.group(5)]
    # de-dup, keep order
    seen, out = set(), []
    for n, is_data in names:
        if n not in seen:
            seen.add(n)
            out.append((n, is_data))
    return out


def write_def(path, library, names):
    """dlltool input: data exports are marked DATA so no call thunk is generated for them (a driver reaches them
    through __imp_Name, as it does on Windows)."""
    path.write_text("LIBRARY " + library + "\nEXPORTS\n" + "".join(f"  {n}{' DATA' if d else ''}\n" for n, d in names))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    text = PROV.read_text()
    nt = table_names(text, "ntdrv_ntoskrnl_exports")
    hal = table_names(text, "ntdrv_hal_exports")
    (args.out / "ntoskrnl-exports.json").write_text(json.dumps({"ntoskrnl.exe": nt, "hal.dll": hal}, indent=1))
    write_def(args.out / "ntoskrnl.def", "ntoskrnl.exe", nt)
    write_def(args.out / "hal.def", "hal.dll", hal)
    print(json.dumps({"ntoskrnl.exe": len(nt), "hal.dll": len(hal)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
