#!/usr/bin/env python3
"""Original, non-destructive PE32 import routing for NTWin32Wrapper9x.

The stock loader still owns mapping, relocation and process creation.
A validated static TLS directory, load configuration and RVA-based delay
import directory are retained. Subsystem versions above 4.10 are not rewritten.
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

    def image_base(self) -> int:
        return self.u32(self.opt + 28)

    def map_va(self, va: int, length: int, *, writable: bool = False,
               executable: bool = False) -> int:
        base = self.image_base()
        if length < 0 or va < base or (va - base) + length < (va - base):
            raise PEError('virtual address is outside the image')
        rva = va - base
        for (section_va, _span, raw, raw_size), flags in zip(self.sections, self.section_flags):
            if section_va <= rva and rva + length <= section_va + raw_size and raw_size:
                if executable and not flags & 0x20000000:
                    raise PEError('address is not in an executable section')
                if writable and (flags & 0x20000020 or not flags & 0x80000000 or not flags & 0x40):
                    raise PEError('address is not writable initialized data')
                return raw + rva - section_va
        raise PEError('virtual address is outside a file-backed section')

    def executable_rva(self, rva: int) -> bool:
        for (va, span, _raw, _raw_size), flags in zip(self.sections, self.section_flags):
            if flags & 0x20000000 and va <= rva < va + span:
                return True
        return False

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

ROUTES_SCHEMA = 'ntwin32wrapper9x.routes.v2'
PROVIDERS = ('native', 'own', 'kernelex')
PROVIDER_MACRO = {'native': 'NTW_PROVIDER_NATIVE', 'own': 'NTW_PROVIDER_OWN',
                  'kernelex': 'NTW_PROVIDER_KERNELEX'}
MODES = ('auto', 'own', 'kernelex', 'native')

def _identifier(value) -> bool:
    return isinstance(value, str) and value.isascii() and value.isidentifier() and len(value) < 64

def validate_routes(plan) -> dict:
    """Reject any routing table the C consumers could misread. Returns the plan."""
    if not isinstance(plan, dict) or plan.get('schema') != ROUTES_SCHEMA:
        raise PEError('routes.json must declare schema ' + ROUTES_SCHEMA)
    for key in ('provider', 'source_dll'):
        value = plan.get(key)
        if not isinstance(value, str) or not value or value != value.upper() or not value.isascii():
            raise PEError(f'routes.json {key} must be an upper-case ASCII module name')
    if plan.get('providers') != list(PROVIDERS):
        raise PEError('routes.json providers must list native, own and kernelex')
    order = plan.get('default_order')
    if not isinstance(order, list) or sorted(order) != sorted(PROVIDERS):
        raise PEError('routes.json default_order must be a permutation of the providers')
    modes = plan.get('modes')
    if not isinstance(modes, dict) or set(modes) != set(MODES):
        raise PEError('routes.json modes must describe auto, own, kernelex and native')
    if modes['own'] != ['own', 'native'] or modes['kernelex'] != ['kernelex', 'native', 'own']:
        raise PEError('routes.json fixed mode orders do not match the resolver')
    exports = plan.get('exports')
    if not isinstance(exports, list) or not exports:
        raise PEError('routes.json exports must be a non-empty list')
    names = []
    for entry in exports:
        if not isinstance(entry, dict) or not _identifier(entry.get('name')):
            raise PEError('routes.json export entries need an ASCII identifier name')
        name = entry['name']
        if name in names:
            raise PEError(f'routes.json duplicate export {name}')
        names.append(name)
        entry_order = entry.get('order')
        if not isinstance(entry_order, list) or len(entry_order) != len(set(entry_order)) or \
                not entry_order or any(p not in PROVIDERS for p in entry_order) or 'own' not in entry_order:
            raise PEError(f'routes.json export {name} needs a unique provider order that includes own')
        if not isinstance(entry.get('native_win98se'), bool):
            raise PEError(f'routes.json export {name} must state native_win98se')
        if entry['native_win98se'] and (entry_order[0] != 'own' or not isinstance(entry.get('reason'), str)
                                        or not entry['reason']):
            raise PEError(f'routes.json export {name} exists natively; own-first order needs a reason')
    stubs = plan.get('stubs')
    if not isinstance(stubs, list):
        raise PEError('routes.json stubs must be a list')
    seen = set()
    for stub in stubs:
        if not isinstance(stub, dict):
            raise PEError('routes.json stub entries must be objects')
        module, name, provider = stub.get('module'), stub.get('name'), stub.get('provider')
        if not isinstance(module, str) or module != module.upper() or not module.isascii() or \
                not 0 < len(module) < 32 or any(c in module for c in '/\\: '):
            raise PEError('routes.json stub module must be an upper-case ASCII file name')
        if not _identifier(name):
            raise PEError('routes.json stub name must be an ASCII identifier')
        if provider not in ('native', 'kernelex'):
            raise PEError(f'routes.json stub {name} provider must be native or kernelex')
        if provider == 'native' and name in names:
            raise PEError(f'routes.json stub {name}: an own export cannot be its own native stub entry')
        if not isinstance(stub.get('evidence'), str) or not stub['evidence']:
            raise PEError(f'routes.json stub {name} needs evidence')
        key = (module, name, provider)
        if key in seen:
            raise PEError(f'routes.json duplicate stub {name}')
        seen.add(key)
    return plan

def routes() -> dict:
    return validate_routes(json.loads(Path(__file__).with_name('routes.json').read_text()))

def route_names(plan: dict) -> list[str]:
    return [entry['name'] for entry in plan['exports']]

def order_macro(order: list[str]) -> str:
    return f'NTW_ORDER{len(order)}(' + ', '.join(PROVIDER_MACRO[p] for p in order) + ')'

def render_routes_inc(plan: dict) -> str:
    """The generated C include consumed by ntwin32/runtime.c."""
    lines = ['/* Generated from ntwin32/routes.json by ntwin32/prepare.py; do not edit. */\n']
    for entry in sorted(plan['exports'], key=lambda e: e['name']):
        lines.append(f'NTW_ROUTE("{entry["name"]}", Ntw{entry["name"]}, {order_macro(entry["order"])})\n')
    for stub in sorted(plan['stubs'], key=lambda s: (s['module'], s['name'], s['provider'])):
        lines.append(f'NTW_STUB("{stub["module"]}", "{stub["name"]}", {PROVIDER_MACRO[stub["provider"]]})\n')
    lines.append(f'#define NTW_DEFAULT_ORDER {order_macro(plan["default_order"])}\n')
    return ''.join(lines)

def validate_tls(pe: PE) -> dict | None:
    """Accept a 24-byte IMAGE_TLS_DIRECTORY32. The directory bytes stay in place."""
    rva, size = pe.directory(9)
    if rva == 0 and size == 0:
        return None
    if rva == 0 or size < 24:
        raise PEError('static TLS directory is incomplete')
    at = pe.offset(rva, 24)
    start, end, index, callbacks, zero_fill, characteristics = struct.unpack_from('<IIIIII', pe.data, at)
    align_nibble = (characteristics >> 20) & 0xF
    if characteristics & ~0x00F00000:
        raise PEError('static TLS characteristics contain unsupported bits')
    if align_nibble > 13:
        raise PEError('static TLS alignment is unsupported')
    if end < start:
        raise PEError('static TLS template range is inverted')
    raw = end - start
    if raw > 16 * 1024 * 1024 or zero_fill > 16 * 1024 * 1024 or raw + zero_fill > 16 * 1024 * 1024:
        raise PEError('static TLS block exceeds the compatibility limit')
    if raw == 0 and zero_fill == 0 and callbacks == 0:
        raise PEError('static TLS directory has no template or callbacks')
    if raw:
        pe.map_va(start, raw)
    pe.map_va(index, 4, writable=True)
    callback_count = 0
    if callbacks:
        slot = callbacks
        while callback_count <= 32:
            target = pe.u32(pe.map_va(slot, 4))
            if target == 0:
                break
            pe.map_va(target, 1, executable=True)
            callback_count += 1
            slot += 4
        else:
            raise PEError('static TLS callback list is unterminated')
    return {'bytes': 24, 'directory_bytes': size, 'raw_bytes': raw, 'zero_fill': zero_fill,
            'callbacks': callback_count, 'alignment': (1 << (align_nibble - 1)) if align_nibble else 1,
            'preserved': True}

def validate_load_config(pe: PE) -> dict | None:
    """Validate IMAGE_LOAD_CONFIG_DIRECTORY32 without rewriting it."""
    rva, size = pe.directory(10)
    if rva == 0 and size == 0:
        return None
    if rva == 0 or size < 64:
        raise PEError('load configuration directory is incomplete')
    at = pe.offset(rva, min(size, 64))
    declared = pe.u32(at)
    if declared < 64 or declared > size or declared > 256:
        raise PEError('load configuration size is inconsistent')
    at = pe.offset(rva, declared)
    cookie = pe.u32(at + 60) if declared >= 64 else 0
    seh_table = pe.u32(at + 64) if declared >= 72 else 0
    seh_count = pe.u32(at + 68) if declared >= 72 else 0
    guard_check = guard_table = guard_count = guard_flags = 0
    if declared >= 92:
        guard_check = pe.u32(at + 72)
        guard_table = pe.u32(at + 80)
        guard_count = pe.u32(at + 84)
        guard_flags = pe.u32(at + 88)
    if cookie:
        pe.map_va(cookie, 4, writable=True)
    if seh_count:
        if seh_count > 4096 or not seh_table:
            raise PEError('malformed safe exception handler table')
        table_at = pe.map_va(seh_table, seh_count * 4)
        for index in range(seh_count):
            if not pe.executable_rva(pe.u32(table_at + index * 4)):
                raise PEError('safe exception handler is outside executable image')
    instrumented = bool(guard_flags & 0x100)
    stride_extra = (guard_flags >> 28) & 0xF
    if stride_extra > 12:
        raise PEError('unsupported CFG function-table stride')
    if instrumented or guard_count or guard_table:
        if declared < 92:
            raise PEError('CFG metadata exceeds the load configuration')
        if guard_count > 1000000 or (guard_count and not guard_table):
            raise PEError('CFG function table is malformed')
        stride = 4 + stride_extra
        if guard_count * stride > 16 * 1024 * 1024:
            raise PEError('CFG function table is too large')
        if guard_count:
            table_at = pe.map_va(guard_table, guard_count * stride)
            for index in range(guard_count):
                if not pe.executable_rva(pe.u32(table_at + index * stride)):
                    raise PEError('CFG function is outside executable image')
        if guard_check:
            pe.map_va(guard_check, 4, writable=True)
    return {'bytes': declared, 'cfg_instrumented': instrumented, 'cfg_functions': guard_count,
            'cfg_stride': 4 + stride_extra if declared >= 92 else 0,
            'has_security_cookie': bool(cookie), 'preserved': True,
            'fail_closed': True}

def validate_delay(pe: PE) -> list | None:
    """Validate RVA-based delay-import descriptors. Bytes are not rewritten."""
    rva, size = pe.directory(13)
    if rva == 0 and size == 0:
        return None
    if rva == 0 or size < 32 or size % 32 or size > 32 * 64:
        raise PEError('delay-import directory is malformed')
    at = pe.offset(rva, size)
    descriptors = []
    for index in range(size // 32):
        fields = struct.unpack_from('<8I', pe.data, at + index * 32)
        if not any(fields):
            if index == 0:
                raise PEError('delay-import directory is empty')
            return descriptors
        attrs, dll, module, iat, name_table, _bound, _unload, _stamp = fields
        if attrs != 1:
            raise PEError('delay import must be RVA-based with no extra attributes')
        if not dll or not module or not iat or not name_table:
            raise PEError('delay import descriptor is incomplete')
        pe.offset(dll, 1)
        library = pe.string(dll)
        if not library:
            raise PEError('empty delay-import DLL name')
        pe.map_va(pe.image_base() + module, 4, writable=True)
        names = 0
        for slot in range(4096):
            value = pe.u32(pe.offset(name_table + slot * 4, 4))
            pe.offset(iat + slot * 4, 4)
            if value == 0:
                if slot == 0:
                    raise PEError('delay import has no names')
                break
            if value & 0x80000000:
                if value & 0x7fff0000:
                    raise PEError('invalid delay-import ordinal')
            else:
                pe.offset(value, 2)
                if not pe.string(value + 2):
                    raise PEError('empty delay-import name')
            names += 1
        else:
            raise PEError('unterminated delay-import table')
        descriptors.append({'dll': library, 'symbols': names, 'preserved': True})
    raise PEError('delay-import descriptors are unterminated')

def prepare(data: bytes) -> tuple[bytes, dict]:
    pe = PE(data)
    plan = routes()
    export_rva, export_size = pe.directory(0)
    if export_rva:
        if export_size < 40:
            raise PEError('invalid export directory')
        export_at = pe.offset(export_rva, 40)
        library_name = pe.string(pe.u32(export_at + 12))
        if library_name.upper() == plan['provider']:
            raise PEError('provider must retain native imports; self-routing is forbidden')
    for index, label in ((4, 'signed image'), (14, 'CLR')):
        if any(pe.directory(index)):
            raise PEError(f'{label} requires a separate compatibility path')
    tls_plan = validate_tls(pe)
    load_plan = validate_load_config(pe)
    delay_plan = validate_delay(pe)
    if pe.u16(pe.opt + 68) not in (2, 3):
        raise PEError('only GUI/console applications and their DLLs are supported')
    subsystem_version = (pe.u16(pe.opt + 48), pe.u16(pe.opt + 50))
    dll_flags = pe.u16(pe.opt + 70)
    # DYNAMIC_BASE and NX_COMPAT are retained. NX_COMPAT means the image can
    # run with DEP; it is not a demand, and this path does not enforce NX.
    # GUARD_CF stays rejected unless the load config named a real CFG table.
    if dll_flags & ~0xC140:
        raise PEError('unsupported DLL characteristics need a separate execution path')
    if dll_flags & 0x4000 and not (load_plan and load_plan['cfg_instrumented']):
        raise PEError('CFG flag requires a validated guard function table')
    new_header = pe.table + pe.count * 40
    if new_header + 40 > min([pe.headers] + [p for _, _, p, n in pe.sections if n]):
        raise PEError('no section-header slack')
    if any(pe.take(new_header, 40)):
        raise PEError('section-header slack is in use')
    supported = set(route_names(plan))
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
    return bytes(out), {'schema': 'ntwin32wrapper9x.prepared.v2',
                       'input_sha256': hashlib.sha256(data).hexdigest(),
                       'output_sha256': hashlib.sha256(out).hexdigest(),
                       'provider': plan['provider'], 'redirected': redirected,
                       'guest_verified': False,
                       'browser_functionality_verified': False,
                       'subsystem_version': list(subsystem_version),
                       'subsystem_version_downgraded': False,
                       'stock_win98_loader_accepts_subsystem': subsystem_version <= (4, 10),
                       'dll_characteristics': f'0x{dll_flags:04x}',
                       'dynamic_base_requested': bool(dll_flags & 0x40),
                       'aslr_implemented': False,
                       'nx_compat_requested': bool(dll_flags & 0x100),
                       'nx_enforced': False,
                       'tls': tls_plan, 'load_config': load_plan, 'delay_imports': delay_plan}

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
