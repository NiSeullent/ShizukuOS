#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check that every import of the given PE32+ images is exported by the Shizuku Win64 runtime as built in
build/shizukudos/win64 (the DLLs WIN64.IMG carries, including the Wine ports), after the Kernel64 loader's API-set
mapping (kernel64/apiset_contracts.txt) and forwarders. DLLs shipped next to the images (the images themselves) count
too. Prints JSON {image: {"imports": n, "missing": ["dll!name", ...]}}; exit status 1 when anything is missing."""
import json
import sys
from pathlib import Path

import pefile

REPO = Path(__file__).resolve().parents[3]
W64OUT = REPO / "build" / "shizukudos" / "win64"
CONTRACTS = REPO / "shizukudos" / "kernel64" / "apiset_contracts.txt"


def apiset_table():
    table = {}
    for line in CONTRACTS.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and not line.startswith("#"):
            table[parts[0].lower()] = parts[1].lower()
    return table


def contract_host(name, table):
    """api-ms-win-core-x-l1-2-0 -> host DLL. As in apiset.c: the contract name without its version must match an entry
    of the table, and the entry with the highest version is taken."""
    stem = name.rpartition("-l")[0]
    hits = sorted(k for k in table if k.rpartition("-l")[0] == stem)
    return table[hits[-1]] if hits else None


def exports_of(path, cache):
    key = path.name.lower()
    if key not in cache:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        names = {}
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if e.name:
                    names[e.name.decode()] = e.forwarder.decode() if e.forwarder else None
        cache[key] = names
    return cache[key]


def check(images, search=(W64OUT, W64OUT / "wineport")):
    table = apiset_table()
    cache = {}
    local = {Path(i).name.lower(): Path(i) for i in images}

    def find(dll):
        dll = dll.lower()
        if dll.startswith(("api-ms-", "ext-ms-")):
            host = contract_host(dll[:-4] if dll.endswith(".dll") else dll, table)
            if not host:
                return None
            dll = host
        if dll in local:
            return local[dll]
        for d in search:
            for p in d.glob("*.dll"):
                if p.name.lower() == dll:
                    return p
        return None

    report, bad = {}, False
    for img in images:
        pe = pefile.PE(str(img))
        missing, n = [], 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) + getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            dll = entry.dll.decode()
            host = find(dll)
            for imp in entry.imports:
                n += 1
                name = imp.name.decode() if imp.name else f"#{imp.ordinal}"
                if host is None:
                    missing.append(f"{dll}!{name} (no such DLL)")
                    continue
                ex = exports_of(host, cache)
                if imp.name and name not in ex:
                    missing.append(f"{dll}!{name}")
        report[Path(img).name] = {"imports": n, "missing": sorted(set(missing))}
        bad |= bool(missing)
    return report, bad


if __name__ == "__main__":
    rep, bad = check(sys.argv[1:])
    print(json.dumps(rep, indent=1))
    sys.exit(1 if bad else 0)
