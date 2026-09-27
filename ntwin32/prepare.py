#!/usr/bin/env python3
"""Original, non-destructive PE32 import routing for NTWin32Wrapper9x.

The stock loader still owns mapping, relocation, TLS and process creation.
Only a deliberately bounded, unsigned x86 PE subset is accepted here.
Specification: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

class PEError(ValueError):
    pass

def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment

class PE:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 64 or data[:2] != b'MZ':
            raise PEError('missing DOS header')
        self.pe = self.u32(60)
        if self.take(self.pe, 4) != b'PE\0\0':
            raise PEError('missing PE signature')
        if self.u16(self.pe + 4) != 0x14c:
            raise PEError('only 32-bit x86 images are supported')
        self.count = self.u16(self.pe + 6)
        self.opt = self.pe + 24
        self.opt_size = self.u16(self.pe + 20)
        self.take(self.opt, self.opt_size)
        if self.opt_size < 224 or self.u16(self.opt) != 0x10b:
            raise PEError('expected complete PE32 optional header')
        if self.u32(self.opt + 92) != 16:
            raise PEError('expected 16 data directories')
        self.section_alignment = self.u32(self.opt + 32)
        self.file_alignment = self.u32(self.opt + 36)
        if not (512 <= self.file_alignment <= 65536 and
                self.section_alignment >= max(4096, self.file_alignment)):
            raise PEError('unsupported section/file alignment')
        if any(n & (n - 1) for n in (self.section_alignment, self.file_alignment)):
            raise PEError('non-power-of-two alignment')
        self.headers = self.u32(self.opt + 60)
        self.take(0, self.headers)
        self.table = self.opt + self.opt_size
        if not 1 <= self.count < 96 or self.table + self.count * 40 > self.headers:
            raise PEError('invalid section table')
        self.sections = []
        self.section_flags = []
        for i in range(self.count):
            at = self.table + 40 * i
            vs, va, rs, rp = struct.unpack_from('<IIII', self.take(at + 8, 16))
            span = max(vs, rs)
            if va < self.headers or va % self.section_alignment or va + span > 0xffffffff:
                raise PEError('invalid virtual section range')
            if rs:
                if rp < self.headers or rp % self.file_alignment or rs % self.file_alignment:
                    raise PEError('invalid raw section alignment')
                self.take(rp, rs)
            for old_va, old_span, old_rp, old_rs in self.sections:
                if span and old_span and va < old_va + old_span and old_va < va + span:
                    raise PEError('overlapping virtual sections')
                if rs and old_rs and rp < old_rp + old_rs and old_rp < rp + rs:
                    raise PEError('overlapping raw sections')
            self.sections.append((va, span, rp, rs))
            self.section_flags.append(self.u32(at + 36))
        needed = align(max(v + n for v, n, _, _ in self.sections), self.section_alignment)
        if self.u32(self.opt + 56) < needed:
            raise PEError('SizeOfImage does not cover sections')

    def take(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > len(self.data):
            raise PEError('truncated PE range')
        return self.data[offset:offset + length]

    def u16(self, offset: int) -> int:
        return struct.unpack('<H', self.take(offset, 2))[0]

    def u32(self, offset: int) -> int:
        return struct.unpack('<I', self.take(offset, 4))[0]

    def directory(self, index: int) -> tuple[int, int]:
        return struct.unpack('<II', self.take(self.opt + 96 + index * 8, 8))

    def offset(self, rva: int, length: int = 1) -> int:
        if rva < self.headers and rva + length <= self.headers:
            return rva
        for va, _, rp, rs in self.sections:
            if va <= rva and rva + length <= va + rs:
                return rp + rva - va
        raise PEError('RVA outside file-backed image')

    def string(self, rva: int) -> str:
        result = bytearray()
        for i in range(4096):
            ch = self.data[self.offset(rva + i)]
            if not ch:
                try:
                    return result.decode('ascii')
                except UnicodeDecodeError as exc:
                    raise PEError('non-ASCII import string') from exc
            result.append(ch)
        raise PEError('unterminated import string')

    def iat_offset(self, rva: int, length: int) -> int:
        # Imports cause loader writes. Never let those writes target headers,
        # executable bytes, even if the RVA maps to disk. Linkers may emit a
        # read-only .idata; the native loader owns temporary import protection.
        for (va, _, rp, rs), flags in zip(self.sections, self.section_flags):
            if va <= rva and rva + length <= va + rs:
                if flags & 0x20000020 or not flags & 0x40000000 or not flags & 0x40:
                    raise PEError('IAT must be non-executable initialized data')
                declared_rva, declared_size = self.directory(12)
                if declared_rva and not (declared_rva <= rva and
                                         rva + length <= declared_rva + declared_size):
                    raise PEError('IAT outside declared address table')
                return rp + rva - va
        raise PEError('IAT outside file-backed data section')

    def imports(self) -> list[dict]:
        rva, size = self.directory(1)
        if not rva or size < 20:
            raise PEError('missing import directory')
        at = self.offset(rva, size)
        result = []
        claimed = set()
        for index in range(min(size // 20, 4096)):
            oft, stamp, chain, name, ft = struct.unpack('<IIIII', self.take(at + index * 20, 20))
            if not any((oft, stamp, chain, name, ft)):
                return result
            if not name or not ft or ft & 3 or (oft and oft & 3):
                raise PEError('invalid import descriptor')
            if not oft and stamp:
                raise PEError('bound imports without original lookup table')
            library = self.string(name)
            if not library or any(c in library for c in '/\\:'):
                raise PEError('invalid import DLL name')
            entries = []
            for k in range(65536):
                val = self.u32(self.offset((oft or ft) + k * 4, 4))
                self.iat_offset(ft + k * 4, 4)
                if not val:
                    break
                if ft + k * 4 in claimed:
                    raise PEError('overlapping import address tables')
                claimed.add(ft + k * 4)
                if len(claimed) > 65536:
                    raise PEError('too many imports')
                if val & 0x80000000:
                    if val & 0x7fff0000:
                        raise PEError('invalid ordinal import')
                    symbol = None
                else:
                    self.offset(val, 2)
                    symbol = self.string(val + 2)
                    if not symbol:
                        raise PEError('empty import name')
                entries.append((val, symbol, ft + k * 4))
            else:
                raise PEError('unterminated import lookup table')
            if not entries:
                raise PEError('empty import descriptor')
            # The ILT terminates each descriptor. Split descriptors can point
            # to adjacent runs within a single original IAT; the next IAT cell
            # can therefore be the first live cell of the next descriptor.
            result.append({'dll': library, 'entries': entries})
        raise PEError('unterminated import descriptors')

def routes() -> dict:
    return json.loads(Path(__file__).with_name('routes.json').read_text())

def prepare(data: bytes) -> tuple[bytes, dict]:
    pe = PE(data)
    for index, label in ((4, 'signed image'), (9, 'static TLS'),
                         (10, 'load configuration'), (13, 'delay imports'), (14, 'CLR')):
        if any(pe.directory(index)):
            raise PEError(f'{label} requires a separate compatibility path')
    if pe.u16(pe.opt + 68) not in (2, 3):
        raise PEError('only GUI/console applications and their DLLs are supported')
    if (pe.u16(pe.opt + 48), pe.u16(pe.opt + 50)) > (4, 10):
        raise PEError('subsystem version exceeds Win98; no silent version downgrade')
    if pe.u16(pe.opt + 70) & (0x40 | 0x100 | 0x4000):
        raise PEError('ASLR, NX or CFG flags need a separate execution path')
    new_header = pe.table + pe.count * 40
    if new_header + 40 > min([pe.headers] + [p for _, _, p, n in pe.sections if n]):
        raise PEError('no section-header slack')
    if any(pe.take(new_header, 40)):
        raise PEError('section-header slack is in use')
    plan = routes()
    supported = set(plan['exports'])
    groups, redirected = [], []
    for descriptor in pe.imports():
        for val, symbol, iat in descriptor['entries']:
            migrate = descriptor['dll'].upper() == plan['source_dll'] and symbol in supported
            library = plan['provider'] if migrate else descriptor['dll']
            if migrate:
                redirected.append(symbol)
            if groups and groups[-1]['dll'] == library and groups[-1]['end'] == iat:
                groups[-1]['values'].append(val)
                groups[-1]['end'] += 4
            else:
                groups.append({'dll': library, 'iat': iat, 'end': iat + 4, 'values': [val]})
    if not redirected:
        raise PEError('no supported imports to route')
    section_rva = align(max(v + n for v, n, _, _ in pe.sections), pe.section_alignment)
    payload = bytearray(20 * (len(groups) + 1))
    strings = {}
    for group in groups:
        library = group['dll']
        if library not in strings:
            strings[library] = section_rva + len(payload)
            payload.extend(library.encode('ascii') + b'\0')
    while len(payload) % 4:
        payload.append(0)
    for i, group in enumerate(groups):
        lookup = section_rva + len(payload)
        for value in group['values'] + [0]:
            payload.extend(struct.pack('<I', value))
        struct.pack_into('<IIIII', payload, i * 20, lookup, 0, 0,
                         strings[group['dll']], group['iat'])
    raw = align(len(data), pe.file_alignment)
    raw_size = align(len(payload), pe.file_alignment)
    image_size = align(section_rva + len(payload), pe.section_alignment)
    if max(raw + raw_size, image_size) > 0xffffffff:
        raise PEError('image size overflow')
    out = bytearray(data)
    out.extend(bytes(raw + raw_size - len(out)))
    out[raw:raw + len(payload)] = payload
    # Restore the prebinding IAT contents at their original addresses.
    for group in groups:
        for i, value in enumerate(group['values']):
            struct.pack_into('<I', out, pe.offset(group['iat'] + i * 4, 4), value)
    struct.pack_into('<8sIIIIIIHHI', out, new_header, b'.ntwimp\0', len(payload),
                     section_rva, raw_size, raw, 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<H', out, pe.pe + 6, pe.count + 1)
    initialized_size = pe.u32(pe.opt + 8) + raw_size
    if initialized_size > 0xffffffff:
        raise PEError('initialized-data size overflow')
    struct.pack_into('<I', out, pe.opt + 8, initialized_size)
    struct.pack_into('<I', out, pe.opt + 56, image_size)
    struct.pack_into('<I', out, pe.opt + 64, 0)  # invalidated PE checksum
    struct.pack_into('<II', out, pe.opt + 104, section_rva, 20 * (len(groups) + 1))
    struct.pack_into('<II', out, pe.opt + 96 + 11 * 8, 0, 0)  # unbind
    # Validate all output structures independently before returning anything.
    PE(bytes(out)).imports()
    return bytes(out), {'schema': 'ntwin32wrapper9x.prepared.v1',
                       'input_sha256': hashlib.sha256(data).hexdigest(),
                       'output_sha256': hashlib.sha256(out).hexdigest(),
                       'provider': plan['provider'], 'redirected': redirected,
                       'guest_verified': False}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        if args.input.resolve() == args.output.resolve() or args.output.exists():
            raise PEError('output must be a new path; original files are never overwritten')
        data, report = prepare(args.input.read_bytes())
        with args.output.open('xb') as stream:
            stream.write(data)
        print(json.dumps(report, indent=2))
    except (PEError, OSError) as exc:
        parser.exit(1, f'NTWin32Wrapper9x: {exc}\n')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
