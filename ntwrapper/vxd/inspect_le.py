#!/usr/bin/env python3
"""Independent narrow LE reader and synthetic relocation checker.
SPDX-License-Identifier: GPL-2.0-only
"""
import json
from pathlib import Path
import struct
import sys

class LEError(ValueError):
    pass

def inspect(data):
    def get(at, length):
        if at < 0 or length < 0 or at + length > len(data):
            raise LEError('range outside file')
        return data[at:at+length]
    def u32(at): return struct.unpack('<I', get(at,4))[0]
    if get(0,2) != b'MZ':
        raise LEError('MZ missing')
    base = u32(60)
    header = get(base,196)
    def h(at): return u32(base+at)
    if header[:8] != b'LE\0\0\0\0\0\0' or header[8:12] != b'\x03\0\x04\0':
        raise LEError('unexpected LE CPU/OS/encoding')
    if h(16) != 0x38000 or h(40) != 4096 or header[192:196] != b'\0\0\x0a\x04':
        raise LEError('unexpected dynamic-VxD metadata')
    pages, count = h(20), h(68)
    if not 1 <= pages <= 4096 or count != 2 or h(132) != pages or not 1 <= h(44) <= 4096:
        raise LEError('invalid page/object counts')
    table, page_map, names, entries, fix_pages, fix_records = [h(n) for n in (64,72,88,92,104,108)]
    if not (196 <= table < page_map < names < entries < fix_pages < fix_records <= h(112) == h(120)):
        raise LEError('unordered loader tables')
    if page_map != table + count*24 or names != page_map + pages*4 or fix_records != fix_pages+(pages+1)*4:
        raise LEError('loader table lengths disagree')
    if h(56) != fix_pages-table or h(48) != h(120)+1-fix_pages or h(116) != 0:
        raise LEError('loader/fixup sizes disagree')
    if base + h(120)+1 > h(128) or h(128) % 4096 or get(base+h(120),1) != b'\0':
        raise LEError('invalid data offset/import terminator')
    if get(base+names, entries-names) != b'\x08NTWRAP9X\0\0\0':
        raise LEError('module resident name mismatch')
    entry = get(base+entries,fix_pages-entries)
    if len(entry) != 10 or entry[:4] != b'\x01\x03\x02\0' or entry[4] != 3 or entry[9] != 0:
        raise LEError('DDB ordinal-1 entry mismatch')
    ddb = struct.unpack_from('<I',entry,5)[0]
    objects, next_page = [], 1
    for i in range(count):
        size, address, flags, first, npages, reserved = struct.unpack('<6I',get(base+table+i*24,24))
        if not size or size > 16*1024*1024 or address or reserved or first != next_page or npages != (size+4095)//4096:
            raise LEError('invalid object record')
        if flags != (0x2065 if i == 0 else 0x2063):
            raise LEError('object permissions/shared/preload policy mismatch')
        memory = bytearray(npages*4096)
        for j in range(npages):
            index = first+j
            mapped = get(base+page_map+(index-1)*4,4)
            if int.from_bytes(mapped[:3],'big') != index or mapped[3] != 0:
                raise LEError('unsupported/nonlinear page map')
            length = h(44) if index == pages else 4096
            memory[j*4096:j*4096+length] = get(h(128)+(index-1)*4096,length)
        objects.append({'size':size,'first':first,'pages':npages,'memory':memory})
        next_page += npages
    if next_page != pages+1 or len(data) != h(128)+(pages-1)*4096+h(44):
        raise LEError('file/page coverage mismatch')
    ddb_bytes = bytes(objects[1]['memory'][ddb:ddb+80])
    if len(ddb_bytes) != 80 or ddb_bytes[4:8] != b'\x0a\x04\0\0' or ddb_bytes[12:20] != b'NTWRAP9X':
        raise LEError('invalid DDB identity')
    if struct.unpack_from('<I',ddb_bytes,64)[0] != 80 or struct.unpack_from('<I',ddb_bytes,20)[0] != 0x80000000:
        raise LEError('invalid DDB size/order')
    if any(ddb_bytes[28:60]) or struct.unpack_from('<4I',ddb_bytes,60) != (0x50726576,80,0x52737631,0x52737632) or struct.unpack_from('<I',ddb_bytes,76)[0] != 0x52737633:
        raise LEError('invalid DDB services/sentinels')
    offsets = [u32(base+fix_pages+i*4) for i in range(pages+1)]
    if offsets[0] or offsets[-1] != h(112)-fix_records or any(a>b for a,b in zip(offsets,offsets[1:])):
        raise LEError('invalid fixup page offsets')
    relocations = []
    for page in range(pages):
        chunk = get(base+fix_records+offsets[page],offsets[page+1]-offsets[page])
        if len(chunk)%9:
            raise LEError('malformed internal fixup')
        owner = next(i for i,o in enumerate(objects) if o['first']-1 <= page < o['first']-1+o['pages'])
        for at in range(0,len(chunk),9):
            source_type, target_flags, offset, destination, target = struct.unpack_from('<BBhBI',chunk,at)
            actual = (page-objects[owner]['first']+1)*4096+offset
            if source_type not in (7,8) or target_flags != 0x10 or destination not in (1,2):
                raise LEError('unsupported fixup flags/target')
            if not -3 <= offset <= 4095 or not 0 <= actual <= objects[owner]['size']-4 or target >= objects[destination-1]['size']:
                raise LEError('fixup range invalid')
            relocations.append((owner,actual,destination-1,target,source_type))
    if not any(a==1 and b==ddb+24 and c==0 and e==7 for a,b,c,d,e in relocations):
        raise LEError('unrelocated DDB control pointer')
    return {'objects':objects, 'fixups':relocations, 'ddb':ddb, 'pages':pages}

def relocate(data, bases):
    image = inspect(data)
    if len(bases) != 2:
        raise LEError('two load bases required')
    for base,obj in zip(bases,image['objects']):
        if base < 0 or base%4096 or base+obj['size'] > 0x100000000:
            raise LEError('invalid synthetic load base')
    if bases[0] < bases[1]+image['objects'][1]['size'] and bases[1] < bases[0]+image['objects'][0]['size']:
        raise LEError('overlapping synthetic objects')
    for owner,offset,target,delta,kind in image['fixups']:
        value = bases[target]+delta
        if kind == 8:
            value = (value-bases[owner]-offset-4)&0xffffffff
        struct.pack_into('<I', image['objects'][owner]['memory'],offset,value)
    return image

if __name__ == '__main__':
    result = inspect(Path(sys.argv[1]).read_bytes())
    print(json.dumps({'objects':len(result['objects']), 'pages':result['pages'],
                      'fixup_records':len(result['fixups']), 'ddb_offset':result['ddb'],
                      'native_loader_verified':False},indent=2))
