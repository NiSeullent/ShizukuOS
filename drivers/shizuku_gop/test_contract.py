#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the actual C consumer against valid and hostile firmware records."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import re
import struct
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
OUT=ROOT/'build/shizuku-gop-locator-contract-test'

def stamp(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def ip(data):
    total=sum(int.from_bytes(data[i:i+2],'little') for i in range(0,len(data),2))
    while total>>16: total=(total&65535)+(total>>16)
    return (~total)&65535
def descriptor(**changes):
    p=bytearray(96);p[:8]=b'SHZGOP1\0'
    fields={'version':(8,0x00000001),'size':(12,96),'flags':(20,7),
        'base':(24,0xe0000000),'base_hi':(28,0),'aperture':(32,16*1024*1024),
        'aperture_hi':(36,0),'visible':(40,5120*800),'visible_hi':(44,0),
        'width':(48,1280),'height':(52,800),'pitch':(56,5120),'bpp':(60,32),
        'red':(64,0x00ff0000),'green':(68,0x0000ff00),'blue':(72,0xff),
        'mask':(76,0xff000000),'location':(80,0x00100000),'identity':(84,0x11111234),
        'mode':(88,3),'reserved':(92,0)}
    for name,(at,value) in fields.items():struct.pack_into('<I',p,at,changes.get(name,value))
    struct.pack_into('<I',p,16,(-sum(struct.unpack('<24I',p)))&0xffffffff)
    return bytes(p)
def table(record=None,count=1):
    if record is None:record=struct.pack('<IIQII',0x53485a47,24,0x800000,96,0)
    h=bytearray(struct.pack('<6I',0x4f49424c,24,0,len(record),ip(record),count))
    struct.pack_into('<I',h,8,ip(h))
    return bytes(h)+record

def anchor(p=None,address=0xf1000,target=0x800000,**changes):
    if p is None:p=descriptor()
    a=bytearray(48);a[:8]=b'SHZLOC1\0'
    fields={'version':(8,1),'size':(12,48),'self':(20,address),
        'target':(24,target&0xffffffff),'target_hi':(28,target>>32),
        'descriptor_size':(32,96),'descriptor_checksum':(36,struct.unpack_from('<I',p,16)[0]),
        'flags':(40,1),'reserved':(44,0)}
    for name,(at,value) in fields.items():struct.pack_into('<I',a,at,changes.get(name,value))
    struct.pack_into('<I',a,16,(-sum(struct.unpack('<12I',a)))&0xffffffff)
    return bytes(a)

def rom(*anchors):
    data=bytearray(b'\xff'*0x10000)
    for offset,value in anchors:data[offset:offset+len(value)]=value
    return bytes(data)

class Locator(ctypes.Structure):
    _fields_=[('address',ctypes.c_uint32),('descriptor_address',ctypes.c_uint32),
        ('descriptor_checksum',ctypes.c_uint32)]

def main():
    global OUT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=OUT)
    parser.add_argument('--capture-descriptor-page',type=Path)
    parser.add_argument('--capture-fseg',type=Path)
    parser.add_argument('--capture-serial',type=Path)
    args=parser.parse_args()
    OUT=args.out.resolve()
    if not OUT.is_relative_to((ROOT/'build').resolve()) or OUT==(ROOT/'build').resolve():
        parser.error('--out must be a component directory under build/')
    if args.capture_fseg and not(args.capture_descriptor_page and args.capture_serial):
        parser.error('--capture-fseg requires descriptor page and serial capture')
    OUT.mkdir(parents=True,exist_ok=True)
    sources={str(p.relative_to(ROOT)):stamp(p) for p in (Path(__file__),HERE/'gop_contract.h')}
    wrapper=OUT/'test-wrapper.c';wrapper.write_text('#include "gop_contract.h"\n'
        'int parse(const unsigned char*p,size_t n){shzgop_mode m;return shzgop_parse(p,n,&m);}\n'
        'uint32_t address(const unsigned char*p,size_t n){return shzgop_descriptor_address(p,n);}\n'
        'int locate(const unsigned char*p,size_t n,shzgop_locator*l){return shzgop_locator_scan(p,n,l);}\n'
        'int binding(const unsigned char*r,size_t rn,const unsigned char*p,size_t n){'
        'shzgop_locator l;shzgop_mode m;return shzgop_locator_scan(r,rn,&l)&&shzgop_locator_bind(&l,p,n,&m);}\n')
    library=OUT/'test-contract.so'
    command=['gcc','-std=c99','-Wall','-Wextra','-Werror','-shared','-fPIC','-O2',
        '-I'+str(HERE),str(wrapper),'-o',str(library)]
    subprocess.run(command,check=True)
    lib=ctypes.CDLL(str(library));lib.parse.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    lib.address.argtypes=[ctypes.c_void_p,ctypes.c_size_t];lib.address.restype=ctypes.c_uint32
    lib.locate.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(Locator)]
    lib.binding.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t]
    checks=[]
    def check(name,actual,expected):
        if actual!=expected:raise AssertionError(f'{name}: {actual} != {expected}')
        checks.append({'name':name,'status':'PASS'})
    def parse(p):return lib.parse(ctypes.create_string_buffer(p),len(p))
    def address(p):return lib.address(ctypes.create_string_buffer(p),len(p))
    def locate(p):
        found=Locator()
        return lib.locate(ctypes.create_string_buffer(p),len(p),ctypes.byref(found)),found
    def located(p):return locate(p)[0]
    def binding(r,p):return lib.binding(ctypes.create_string_buffer(r),len(r),ctypes.create_string_buffer(p),len(p))
    check('native BGRX',parse(descriptor()),1)
    check('pitch padding preserved',parse(descriptor(pitch=5376,visible=5376*800)),1)
    check('CB locator and checksums',address(table()),0x800000)
    for changes in ({'version':2},{'size':92},{'flags':2},{'flags':15},{'base_hi':1},
        {'base':0},{'base':0xfffff000},{'aperture':0},{'aperture_hi':1},{'visible_hi':1},
        {'width':0},{'height':4097},{'pitch':5116},{'pitch':65536},{'pitch':5121},
        {'visible':1},{'aperture':4096},{'bpp':24},{'red':0xff,'blue':0xff0000},
        {'mask':0},{'location':1},{'flags':3},{'identity':0xffffffff},{'reserved':1}):
        check('descriptor rejects '+str(changes),parse(descriptor(**changes)),0)
    p=descriptor()
    for n in (0,7,95,97):check(f'descriptor length {n}',parse((p+b'\0')[:n]),0)
    for i in range(96):
        bad=bytearray(p);bad[i]^=1;check(f'descriptor corruption byte {i}',parse(bytes(bad)),0)
    for address_value in (0,0x500,0x800001,0x100000000):
        r=struct.pack('<IIQII',0x53485a47,24,address_value,96,0)
        check(f'locator range {address_value:x}',address(table(r)),0)
    record=struct.pack('<IIQII',0x53485a47,24,0x800000,96,0)
    check('duplicate locator',address(table(record+record,2)),0)
    check('missing record count',address(table(record,0)),0)
    check('oversized record count',address(table(record,129)),0)
    for r in (struct.pack('<II',0x53485a47,0),struct.pack('<II',0x53485a47,4096),
        struct.pack('<IIQII',0x53485a47,24,0x800000,92,0),
        struct.pack('<IIQII',0x53485a47,24,0x800000,96,1)):
        check('malformed record '+r.hex(),address(table(r)),0)
    cb=table()
    for n in range(len(cb)):check(f'table truncation {n}',address(cb[:n]),0)
    for i in range(len(cb)):
        bad=bytearray(cb);bad[i]^=1;check(f'table corruption byte {i}',address(bytes(bad)),0)
    valid=rom((0x1000,anchor()))
    check('F-segment unique allocator anchor',located(valid),1)
    found=locate(valid)[1]
    check('anchor physical slot binding',found.address,0xf1000)
    check('anchor reserved descriptor pointer',found.descriptor_address,0x800000)
    check('anchor final descriptor checksum binding',binding(valid,descriptor()),1)
    for offset in (0,16,0x8000,0xffd0):
        check(f'complete aligned locator boundary {offset:x}',
            located(rom((offset,anchor(address=0xf0000+offset)))),1)
    for offset in (0xffe0,0xfff0):
        tail=bytearray(valid);tail[offset:offset+8]=b'SHZLOC1\0'
        check(f'partial tail anchor fails entire scan {offset:x}',located(bytes(tail)),0)
    for n in (0,7,48,65535,65537):
        check(f'F-segment capture exact bound {n}',located((valid+b'\0')[:n]),0)
    check('null F-segment pointer',lib.locate(None,65536,ctypes.byref(Locator())),0)
    check('null locator output',lib.locate(ctypes.create_string_buffer(valid),65536,None),0)
    check('no locator in bounded ROM',located(rom()),0)
    check('descriptor magic is not locator magic',located(rom((0,descriptor()))),0)
    check('unaligned signature cannot become locator',located(rom((1,anchor(address=0xf0001)))),0)
    check('unaligned noise does not invalidate unique anchor',located(rom((1,anchor(address=0xf0001)),(0x1000,anchor()))),1)
    check('duplicate identical descriptor anchors rejected',located(rom((0x1000,anchor()),
        (0x2000,anchor(address=0xf2000)))),0)
    check('different descriptor anchors rejected',located(rom((0x1000,anchor()),
        (0x2000,anchor(address=0xf2000,target=0x900000)))),0)
    check('moved anchor self-address rejected',located(rom((0x2000,anchor()))),0)
    for changes in ({'version':2},{'version':0x10001},{'size':44},{'self':0xf1001},
        {'self':0xe1000},{'target':0},{'target':0x100000},{'target':0x800001},
        {'target':0xfffff001},{'target_hi':1},{'descriptor_size':92},{'flags':0},
        {'flags':3},{'reserved':1}):
        invalid=anchor(**changes)
        check('anchor rejects '+str(changes),located(rom((0x1000,invalid))),0)
        check('matching-magic malformed second anchor fails '+str(changes),
            located(rom((0x1000,anchor()),(0x2000,invalid))),0)
    a=anchor()
    for i in range(48):
        bad=bytearray(a);bad[i]^=1
        check(f'anchor corruption byte {i}',located(rom((0x1000,bytes(bad)))),0)
    check('checksum-bound wrong valid descriptor rejected',binding(valid,descriptor(pitch=5376,visible=5376*800)),0)
    check('anchor copied checksum mismatch rejected',binding(rom((0x1000,anchor(descriptor_checksum=0))),descriptor()),0)
    bad=bytearray(descriptor());bad[95]^=1
    check('bound descriptor own checksum rejected',binding(valid,bytes(bad)),0)
    captures={}
    if args.capture_descriptor_page:
        page=args.capture_descriptor_page.resolve();data=page.read_bytes()
        if len(data)!=4096:raise ValueError('Descriptor capture must be exactly one physical page')
        check('captured descriptor actual C parser',parse(data[:96]),1)
        captures[str(page)]={'sha256':stamp(page),'bytes':len(data)}
        if args.capture_fseg:
            fseg=args.capture_fseg.resolve();serial=args.capture_serial.resolve()
            fr=fseg.read_bytes();st=serial.read_text(errors='replace')
            check('captured F-segment actual C parser',located(fr),1)
            check('captured anchor to descriptor actual C binding',binding(fr,data[:96]),1)
            found=locate(fr)[1]
            markers=set(tuple(int(value,16) for value in values) for values in re.findall(
                r'SHZLOC1 anchor=0x([0-9a-fA-F]+) descriptor=0x([0-9a-fA-F]+) checksum=0x([0-9a-fA-F]+)',st))
            check('captured physical addresses/checksum match serial marker',markers,
                {(found.address,found.descriptor_address,found.descriptor_checksum)})
            captures[str(fseg)]={'sha256':stamp(fseg),'bytes':len(fr)}
            captures[str(serial)]={'sha256':stamp(serial),'bytes':serial.stat().st_size}
        else:
            check('captured descriptor binds only synthetic host-test anchor',
                binding(rom((0x1000,anchor(data[:96]))),data[:96]),1)
    for name,value in captures.items():
        if stamp(Path(name))!=value['sha256']:raise ValueError('Capture changed during audit: '+name)
    if sources!={str(p.relative_to(ROOT)):stamp(p) for p in (Path(__file__),HERE/'gop_contract.h')}:
        raise ValueError('consumer source changed during testing')
    report={'status':'PASS','scope':'actual C parser host execution; no driver load, VMM-lifetime or native-rendering claim',
        'sources':sources,'command':command,'checks':checks,'checks_passed':len(checks),
        'captures':captures,'captured_anchor':bool(args.capture_fseg),
        'artifacts':{p.name:stamp(p) for p in (wrapper,library)}}
    (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS {len(checks)} actual C handoff-parser checks')

if __name__=='__main__':main()
