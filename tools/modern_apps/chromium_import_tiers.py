#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Rank Chromium 157 x86 import blockers against the Win98 SE OEM export inventory.

Fetches ONLY the named members of the pinned public snapshot zip with HTTP Range
reads (central directory + local members) into a scratch dir under /dev/shm,
verifies CRC32, prints sha256 + missing imports, and accounts chrome_elf.dll
against ntwin32/chromium_port/api_contract.c. Binaries are never executed and
the scratch copy is deleted unless --keep is given."""
import argparse, hashlib, json, re, shutil, struct, sys, tempfile, urllib.request, zlib
from pathlib import Path
import pefile

ROOT = Path(__file__).resolve().parents[2]
URL = "https://storage.googleapis.com/chromium-browser-snapshots/Win/1707946/chrome-win.zip"
ZIP_BYTES = 323332967
PINS = {"chrome-win/chrome.exe": "7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823",
        "chrome-win/chrome_elf.dll": "54ffa9edd24ed9251fefca50abd27d4542fe81b63757d0ed0df2304a36ad1473"}
LIMIT = 8 << 20  # refuse members whose compressed size exceeds 8 MiB

def get(start, length):
    req = urllib.request.Request(URL, headers={"Range": f"bytes={start}-{start + length - 1}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    if len(data) != length:
        raise ValueError("short range read")
    return data

def central():
    tail = get(ZIP_BYTES - 65536, 65536)
    i = tail.rfind(b"PK\x06\x06")  # zip64 end record
    if i >= 0:
        size, off = struct.unpack_from("<QQ", tail, i + 40)
    else:
        i = tail.rfind(b"PK\x05\x06"); size, off = struct.unpack_from("<II", tail, i + 12)
    cd = get(off, size); p = 0; out = {}
    while p + 46 <= len(cd) and cd[p:p + 4] == b"PK\x01\x02":
        method, _, _, crc, csize, usize, nl, xl, cl = struct.unpack_from("<HHHIIIHHH", cd, p + 10)
        local = struct.unpack_from("<I", cd, p + 42)[0]; name = cd[p + 46:p + 46 + nl].decode()
        extra = cd[p + 46 + nl:p + 46 + nl + xl]; q = 0
        while q + 4 <= len(extra):
            tag, ln = struct.unpack_from("<HH", extra, q); body = extra[q + 4:q + 4 + ln]; k = 0
            if tag == 1:
                if usize == 0xFFFFFFFF: usize = struct.unpack_from("<Q", body, k)[0]; k += 8
                if csize == 0xFFFFFFFF: csize = struct.unpack_from("<Q", body, k)[0]; k += 8
                if local == 0xFFFFFFFF: local = struct.unpack_from("<Q", body, k)[0]
            q += 4 + ln
        out[name] = (method, crc, csize, usize, local); p += 46 + nl + xl + cl
    return out

def member(entry):
    method, crc, csize, usize, local = entry
    if csize > LIMIT: raise ValueError("member too large for a small selective fetch")
    head = get(local, 30); nl, xl = struct.unpack_from("<HH", head, 26)
    data = get(local + 30 + nl + xl, csize)
    data = zlib.decompress(data, -15) if method == 8 else data
    if len(data) != usize or zlib.crc32(data) != crc: raise ValueError("CRC/size mismatch")
    return data

def contract_names():
    src = (ROOT / "ntwin32/chromium_port/api_contract.c").read_text()
    def arr(name):
        m = re.search(r"\b" + name + r"\[\]=\{(.*?)\};", src, re.S)
        return set(re.findall(r'"([^"]+)"', re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)))
    return arr("elf_ntdll"), arr("elf_kernel32"), arr("elf_kernel32_unsupported")

def audit(data, inv):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[1, 13])
    res = {"regular": {}, "delay": {}}
    for kind, attr in (("regular", "DIRECTORY_ENTRY_IMPORT"), ("delay", "DIRECTORY_ENTRY_DELAY_IMPORT")):
        for d in getattr(pe, attr, []):
            dll = d.dll.decode(); have = inv.get(dll.upper())
            names = [i.name.decode() if i.name else f"#{i.ordinal}" for i in d.imports]
            miss = sorted(n for n in names if have is None or n not in have)
            res[kind][dll] = {"count": len(names), "missing": miss, "dll_in_inventory": have is not None}
    return res

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--members", nargs="+", default=list(PINS))
    ap.add_argument("--keep", type=Path, help="copy verified members here (must be under /dev/shm)")
    a = ap.parse_args()
    inv = {k.upper(): set(v) for k, v in json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())["dlls"].items()}
    cd = central(); report = {"url": URL, "zip_bytes": ZIP_BYTES, "executed": False, "members": {}}
    scratch = Path(tempfile.mkdtemp(dir="/dev/shm", prefix="chromium-tiers-"))
    try:
        for name in a.members:
            data = member(cd[name]); digest = hashlib.sha256(data).hexdigest()
            if name in PINS and digest != PINS[name]: raise ValueError(f"{name} sha256 {digest} != pin")
            (scratch / Path(name).name).write_bytes(data)
            report["members"][name] = {"bytes": len(data), "sha256": digest, "compressed": cd[name][2], **audit(data, inv)}
        elf = report["members"].get("chrome-win/chrome_elf.dll")
        if elf:
            nt, k32, k32u = contract_names()
            mk = set(elf["regular"]["KERNEL32.dll"]["missing"]); mn = set(elf["regular"]["ntdll.dll"]["missing"])
            report["chrome_elf_accounting"] = {
                "kernel32_missing": len(mk), "routed": sorted(mk & k32), "explicit_unsupported": sorted(mk & k32u),
                "unaccounted": sorted(mk - k32 - k32u), "contract_not_imported": sorted((k32 | k32u) - mk),
                "ntdll_missing": len(mn), "ntdll_unaccounted": sorted(mn - nt)}
        if a.keep:
            if not str(a.keep.resolve()).startswith("/dev/shm/"): raise ValueError("--keep must be under /dev/shm")
            a.keep.mkdir(parents=True, exist_ok=True)
            for f in scratch.iterdir(): shutil.copyfile(f, a.keep / f.name)
    finally:
        shutil.rmtree(scratch)
    json.dump(report, sys.stdout, indent=1, sort_keys=True); print()
    acc = report.get("chrome_elf_accounting")
    return 1 if acc and (acc["unaccounted"] or acc["ntdll_unaccounted"]) else 0

if __name__ == "__main__":
    sys.exit(main())
