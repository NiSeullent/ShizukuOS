#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Add a hashed, separately built Wine port to a copied experimental runtime.

The upstream port receipt stays separate from the native build receipt. This
does not change the ordinary Wine cache or claim full application support.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import pefile

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--base', type=Path, required=True)
    ap.add_argument('--port-receipt', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT/'build'):
        raise SystemExit('output must belong to this worktree build directory')
    base = args.base.resolve(strict=True)
    receipt_path = args.port_receipt.resolve(strict=True)
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    dll = Path(receipt['build']['dll']).resolve(strict=True)
    if not dll.is_relative_to(ROOT/'build') or not re.fullmatch(r'[a-zA-Z0-9_]+\.dll', dll.name):
        raise SystemExit('port DLL must belong to this worktree build directory')
    target = out/'WIN64.IMG'
    if target in (base, dll, receipt_path) or target.exists():
        raise SystemExit('output must be new and distinct from all inputs')
    raw, payload = base.read_bytes(), dll.read_bytes()
    if sha(payload) != receipt['sha256']:
        raise SystemExit('port DLL no longer matches its build receipt')
    if raw[:8] != b'SHZARC01' or len(raw) < 16:
        raise SystemExit('invalid base archive')
    count = struct.unpack_from('<I', raw, 8)[0]
    header = 16 + count*136
    if header > len(raw):
        raise SystemExit('truncated archive header')
    entries = {}
    spans = []
    for i in range(count):
        name, offset, size = struct.unpack_from('<120sQQ', raw, 16+i*136)
        name = name.split(b'\0', 1)[0].decode('ascii')
        key = name.casefold()
        if key in entries or offset < header or offset+size > len(raw):
            raise SystemExit('invalid archive entry')
        entries[key] = (name, raw[offset:offset+size])
        spans.append((offset, offset+size))
    spans.sort()
    if any(a[1] > b[0] for a,b in zip(spans, spans[1:])):
        raise SystemExit('overlapping archive payloads')
    image = pefile.PE(data=payload, fast_load=True)
    if image.FILE_HEADER.Machine != 0x8664 or not image.FILE_HEADER.Characteristics & 0x2000:
        raise SystemExit('port must be an AMD64 DLL')
    preferred = image.OPTIONAL_HEADER.ImageBase
    end = preferred + image.OPTIONAL_HEADER.SizeOfImage
    image.parse_data_directories(directories=[0,1])
    exports = sorted(e.name.decode('ascii') for e in image.DIRECTORY_ENTRY_EXPORT.symbols if e.name)
    imports = {d.dll.decode('ascii'): [i.name.decode('ascii') if i.name else '#'+str(i.ordinal)
               for i in d.imports] for d in getattr(image, 'DIRECTORY_ENTRY_IMPORT', [])}
    image.close()
    guest = '\\SHZ\\SYS64\\'+dll.name.lower()
    for name,data in entries.values():
        if name.casefold().endswith('.dll') and name.casefold() != guest.casefold():
            other = pefile.PE(data=data, fast_load=True)
            lo = other.OPTIONAL_HEADER.ImageBase
            hi = lo + other.OPTIONAL_HEADER.SizeOfImage
            other.close()
            if preferred < hi and lo < end:
                raise SystemExit('preferred base collides with '+name)
    old = entries.get(guest.casefold())
    entries[guest.casefold()] = (guest, payload)
    items = sorted(entries.values())
    header_size = 16 + len(items)*136
    blob = bytearray()
    packed = bytearray(b'SHZARC01'+struct.pack('<II',len(items),0))
    for name,data in items:
        encoded = name.encode('ascii')
        if len(encoded) >= 120:
            raise SystemExit('archive path too long')
        while (header_size + len(blob)) % 16:
            blob.append(0)
        packed.extend(struct.pack('<120sQQ',encoded,header_size + len(blob),len(data)))
        blob.extend(data)
    packed.extend(blob)
    if base.read_bytes() != raw or dll.read_bytes() != payload or receipt_path.read_bytes() != receipt_bytes:
        raise SystemExit('input changed during merge')
    out.mkdir(parents=True, exist_ok=True)
    target.write_bytes(packed)
    proof = {'mode':'isolated-wine-port-merge', 'base_archive':str(base), 'base_sha256':sha(raw),
             'port_receipt':str(receipt_path), 'port_receipt_sha256':sha(receipt_bytes),
             'upstream_commit':receipt['upstream_commit'], 'port_dll':str(dll), 'port_sha256':sha(payload),
             'guest_path':guest, 'previous_payload_sha256':sha(old[1]) if old else None,
             'unchanged_payload_count':len(items)-1, 'archive_sha256':sha(packed),
             'preferred_base':hex(preferred), 'exports':exports, 'imports':imports,
             'merge_tool_sha256':sha(Path(__file__).read_bytes()), 'app_functionality_verified':False}
    (out/'port-merge-receipt.json').write_text(json.dumps(proof, indent=2)+'\n')
    print('Copied runtime with isolated port:', target)


if __name__ == '__main__':
    main()
