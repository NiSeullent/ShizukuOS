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
    """{(contract name without version, level): [(major, minor, shizuku host)]} from kernel64/apiset_contracts.txt:
    rows `contract windows-host [shizuku-host]`, the shizuku host defaulting to the windows host after the
    `@provider <windows-host> <shizuku-host>` substitutions (the Shizuku runtime has no kernelbase.dll, for example)."""
    providers, rows = {}, []
    for line in CONTRACTS.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] == "@provider" and len(parts) >= 3:
            providers[parts[1].lower()] = parts[2].lower()
        elif len(parts) >= 2:
            rows.append((parts[0].lower(), parts[1].lower(), parts[2].lower() if len(parts) > 2 else None))
    table = {}
    for contract, win, shz in rows:
        key = split_contract(contract)
        if key:
            table.setdefault(key[:2], []).append((key[2], key[3], shz or providers.get(win, win)))
    return table


def split_contract(name):
    """api-ms-win-core-synch-l1-2-0 -> ("api-ms-win-core-synch", 1, 2, 0)."""
    stem, sep, ver = name.rpartition("-l")
    nums = ver.split("-")
    if not sep or len(nums) != 3 or not all(n.isdigit() for n in nums):
        return None
    return stem, int(nums[0]), int(nums[1]), int(nums[2])


def contract_host(name, table):
    """The rule of kernel64/apiset.c apiset_lookup(): the highest row of the same contract and level, which must be at
    least the requested (major, minor) version (an l1-2-1 row satisfies l1-1-0 and l1-2-0, not l1-3-0)."""
    key = split_contract(name)
    if not key or key[:2] not in table:
        return None
    major, minor, host = max(table[key[:2]])
    return host if (major, minor) >= (key[2], key[3]) else None


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
