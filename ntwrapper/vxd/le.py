#!/usr/bin/env python3
"""Original, intentionally narrow i386 ELF -> Windows VxD LE packager.

Input: own fully linked ELF32, exactly .text/.data, retained REL relocations.
Output: two shared/preloaded 32-bit objects, ordinal-1 DDB and internal fixups only.
No SDK libraries, imported LE writer, external services table or NT PE loader.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations
import struct

PAGE = 4096
MAX_BYTES = 16 * 1024 * 1024

class FormatError(ValueError):
    pass

def take(data, at, size):
    if at < 0 or size < 0 or at + size > len(data):
        raise FormatError('truncated range')
    return data[at:at + size]

def unpack(fmt, data, at):
    return struct.unpack(fmt, take(data, at, struct.calcsize(fmt)))

def align(n, to):
    return (n + to - 1) & -to

def cstring(data, at):
    if not 0 <= at < len(data):
        raise FormatError('invalid string offset')
    end = data.find(b'\0', at)
    if end < 0:
        raise FormatError('unterminated string')
    try:
        return data[at:end].decode('ascii')
    except UnicodeDecodeError as exc:
        raise FormatError('non-ASCII symbol') from exc

def read_elf(data: bytes) -> dict:
    if len(data) > MAX_BYTES or take(data, 0, 7) != b'\x7fELF\x01\x01\x01':
        raise FormatError('expected bounded little-endian ELF32')
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shnames = unpack('<HHIIIIIHHHHHH', data, 16)
    if kind != 2 or machine != 3 or version != 1 or ehsize != 52 or shsize != 40:
        raise FormatError('expected linked i386 ELF')
    if not 1 <= shnum <= 128 or not 0 < shnames < shnum:
        raise FormatError('invalid section count/name table')
    take(data, shoff, shsize * shnum)
    sections = []
    for i in range(shnum):
        vals = unpack('<IIIIIIIIII', data, shoff + i * 40)
        s = dict(zip(('name_at','type','flags','va','offset','size','link','info','align','entsize'), vals))
        s['index'] = i
        s['data'] = b'' if s['type'] == 8 else take(data, s['offset'], s['size'])
        sections.append(s)
    names = sections[shnames]['data']
    for s in sections:
        s['name'] = cstring(names, s['name_at'])
    objects = [s for s in sections if s['flags'] & 2]
    if [s['name'] for s in objects] != ['.text', '.data']:
        raise FormatError('only ordered .text/.data allocated sections are supported')
    previous_end = 0
    for s in objects:
        if s['type'] != 1 or not s['size'] or s['size'] > MAX_BYTES or s['va'] % PAGE or s['va'] < previous_end:
            raise FormatError('invalid object layout')
        if s['va'] + s['size'] > 0xffffffff:
            raise FormatError('object overflow')
        previous_end = s['va'] + s['size']
    if objects[0]['flags'] & 5 != 4 or objects[1]['flags'] & 5 != 1:
        raise FormatError('unexpected executable/writable section flags')
    def target(address):
        for number, obj in enumerate(objects, 1):
            if obj['va'] <= address < obj['va'] + obj['size']:
                return number, address - obj['va']
        raise FormatError('relocation target outside allocated objects')
    symbols = {}
    for s in sections:
        if s['type'] != 2:
            continue
        if s['entsize'] != 16 or s['size'] % 16 or s['link'] >= shnum:
            raise FormatError('invalid symbol table')
        strings = sections[s['link']]['data']
        for at in range(0, s['size'], 16):
            name, value, size, info, other, index = unpack('<IIIBBH', s['data'], at)
            name = cstring(strings, name)
            if name and index == 0:
                raise FormatError('undefined symbol: ' + name)
            if name:
                symbols[name] = value
    if 'ntwv_ddb' not in symbols or 'ntwv_control' not in symbols:
        raise FormatError('missing native DDB/control symbols')
    ddb_object, ddb_offset = target(symbols['ntwv_ddb'])
    if ddb_object != 2 or ddb_offset + 80 > objects[1]['size'] or entry != symbols['ntwv_control']:
        raise FormatError('invalid DDB or control entry')
    relocs, claimed = [], set()
    for section in sections:
        if section['type'] != 9:
            continue
        if section['entsize'] != 8 or section['size'] % 8 or section['info'] >= shnum:
            raise FormatError('invalid relocation section')
        owner = sections[section['info']]
        if owner not in objects:
            raise FormatError('relocation outside allocated section')
        objno = objects.index(owner) + 1
        for at in range(0, section['size'], 8):
            where, info = unpack('<II', section['data'], at)
            reltype = info & 255
            if reltype not in (1, 2):
                raise FormatError('unsupported i386 relocation type')
            offset = where - owner['va']
            value, = unpack('<I', owner['data'], offset)
            if any(where + k in claimed for k in range(4)):
                raise FormatError('overlapping relocations')
            claimed.update(range(where, where + 4))
            # GNU --emit-relocs retains records after applying ELF addends.
            address = value if reltype == 1 else (value + where + 4) & 0xffffffff
            dest, delta = target(address)
            if reltype == 2 and dest == objno:
                continue  # Same-object PC-relative code is position independent.
            relocs.append({'object':objno, 'offset':offset, 'target':dest,
                           'target_offset':delta, 'relative':reltype == 2})
    if not any(r['object'] == ddb_object and r['offset'] == ddb_offset + 24 for r in relocs):
        raise FormatError('DDB control pointer has no relocation')
    return {'objects':objects, 'relocations':relocs, 'symbols':symbols,
            'ddb_object':ddb_object, 'ddb_offset':ddb_offset}

def fixup_pages(objects, relocs):
    starts, total = [], 0
    for obj in objects:
        starts.append(total)
        total += (obj['size'] + PAGE - 1) // PAGE
    pages = [[] for _ in range(total)]
    for rel in relocs:
        obj = objects[rel['object'] - 1]
        if not 0 <= rel['offset'] <= obj['size'] - 4:
            raise FormatError('relocation source outside object')
        source_page, offset = divmod(rel['offset'], PAGE)
        encoded = lambda source: struct.pack('<BBhBI', 8 if rel['relative'] else 7,
                                            0x10, source, rel['target'], rel['target_offset'])
        pages[starts[rel['object'] - 1] + source_page].append(encoded(offset))
        if offset > PAGE - 4:
            # LE loaders process either page independently: duplicate straddling
            # fixups with a negative source offset on the following page.
            pages[starts[rel['object'] - 1] + source_page + 1].append(encoded(offset - PAGE))
    table, records = bytearray(), bytearray()
    for page in pages:
        table.extend(struct.pack('<I', len(records)))
        for record in page:
            records.extend(record)
    table.extend(struct.pack('<I', len(records)))
    return bytes(table), bytes(records), total

def package(elf: bytes) -> tuple[bytes, dict]:
    image = read_elf(elf)
    objects = image['objects']
    fixpages, fixrecords, pages = fixup_pages(objects, image['relocations'])
    le_at = 0x80
    header = bytearray(0xc4)
    header[:2] = b'LE'
    def h16(at, value): struct.pack_into('<H', header, at, value)
    def h32(at, value): struct.pack_into('<I', header, at, value)
    h16(8, 3)  # i486 instructions in the original core
    h16(10, 4) # Windows386/VxD
    h32(0x10, 0x00038000) # dynamically loadable virtual device
    h32(0x14, pages)
    h32(0x28, PAGE)
    last_bytes = objects[-1]['size'] % PAGE or PAGE
    h32(0x2c, last_bytes)
    h32(0x40, len(header)); h32(0x44, len(objects))
    tables = bytearray()
    first_page = 1
    for number, obj in enumerate(objects):
        count = (obj['size'] + PAGE - 1) // PAGE
        # Shared + preload + 32-bit RX/RW; permanent-resident bit 0x200 is clear.
        # These flags passed a separate native control-only loader fixture;
        # acceptance of the complete production driver still needs a guest run.
        flags = 0x2065 if number == 0 else 0x2063
        tables.extend(struct.pack('<IIIIII', obj['size'], 0, flags, first_page, count, 0))
        first_page += count
    h32(0x48, len(header) + len(tables))
    for page in range(1, pages + 1):
        tables.extend(page.to_bytes(3, 'big') + b'\0')
    h32(0x58, len(header) + len(tables))
    tables.extend(b'\x08NTWRAP9X\x00\x00\0') # module name, ordinal0, terminator
    h32(0x5c, len(header) + len(tables))
    tables.extend(struct.pack('<BBHBI', 1, 3, image['ddb_object'], 3, image['ddb_offset']) + b'\0')
    h32(0x38, len(tables)) # loader section: object table through entry table
    h32(0x68, len(header) + len(tables))
    tables.extend(fixpages)
    h32(0x6c, len(header) + len(tables))
    tables.extend(fixrecords)
    h32(0x70, len(header) + len(tables))
    h32(0x78, len(header) + len(tables))
    tables.append(0) # empty imported-procedure table
    h32(0x30, len(fixpages) + len(fixrecords) + 1)
    data_at = align(le_at + len(header) + len(tables), PAGE)
    h32(0x80, data_at) # file-relative (unlike table offsets)
    h32(0x84, pages)
    h16(0xc0, 0); h16(0xc2, 0x040a)
    # Original DOS stub: terminate with error1, never fall into LE payload.
    dos = bytearray(le_at)
    struct.pack_into('<14H', dos, 0, 0x5a4d, le_at, 1, 0, 4, 0, 0xffff, 0, 0x100, 0, 0, 0, 0x40, 0)
    struct.pack_into('<I', dos, 0x3c, le_at)
    dos[0x40:0x45] = b'\xb8\x01\x4c\xcd\x21'
    result = dos + header + tables
    result.extend(bytes(data_at - len(result)))
    for i, obj in enumerate(objects):
        result.extend(obj['data'])
        if i + 1 != len(objects):
            result.extend(bytes(align(obj['size'], PAGE) - obj['size']))
    if len(result) > MAX_BYTES:
        raise FormatError('LE image exceeds limit')
    return bytes(result), {'format':'LE', 'objects':len(objects), 'pages':pages,
        'object_flags':[0x2065,0x2063],
        'object_policy':'shared/preloaded/big32 RX and RW; permanent-resident bit 0x200 clear',
        'internal_fixups':len(image['relocations']), 'ddb_export_ordinal':1,
        'ddb_object':image['ddb_object'], 'ddb_offset':image['ddb_offset'],
        'guest_loaded':False, 'native_vmm_calls_verified':False}
