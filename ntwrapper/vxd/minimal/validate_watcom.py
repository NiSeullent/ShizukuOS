#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded reader of the isolated one-object Open Watcom LE fixture.

This admits the linker's 16-bit target-offset fixup and nonresident name
table. It does not loosen the independently written historical LE reader.
"""
import struct
from validate import InvalidLE, require


def decode(image):
    require(8192<=len(image)<=16384,"bounded toolchain fixture size")
    def take(at,n):
        require(0<=at<=len(image) and 0<=n<=len(image)-at,"file range")
        return image[at:at+n]
    def u32(at): return struct.unpack('<I',take(at,4))[0]
    def u16(at): return struct.unpack('<H',take(at,2))[0]
    require(take(0,2)==b'MZ',"DOS signature")
    le=u32(60); require(le>=64 and take(le,8)==b'LE'+bytes(6),"LE header")
    require(u16(le+8)==2 and u16(le+10)==4,"386 Win386 target")
    require(u32(le+16)==0x38000 and u32(le+20)==2,"dynamic VxD/two pages")
    require(take(le+24,16)==bytes(16),"no process entry/stack")
    require(u32(le+40)==4096 and u32(le+44)==4096,"full final page")
    obj=u32(le+64); require(obj>=196 and u32(le+68)==1,"one object")
    size,base,flags,start,count,reserved=struct.unpack('<6I',take(le+obj,24))
    require((size,base,start,count,reserved)==(8192,0,1,2,0),"fixed object range")
    require(flags==0x2047,"read/write/executable/preloaded 32-bit object")
    maps=u32(le+72); names=u32(le+88); entry=u32(le+92)
    pages=u32(le+104); records=u32(le+108); imports=u32(le+112); procs=u32(le+120)
    data=u32(le+128); nonres=u32(le+136); nonlen=u32(le+140)
    require(maps==obj+24 and take(le+maps,8)==bytes.fromhex('0000010000000200'),"page map")
    require(names==maps+8 and take(le+names,12)==b'\x08NTWMIN9X\0\0\0',"module name")
    require(entry==names+12 and take(le+entry,10)==bytes.fromhex('01030100010000000000'),"ordinal1 DDB export")
    require(pages==entry+10 and u32(le+56)==pages-obj,"loader section extent")
    require(records==pages+12 and take(le+pages,12)==struct.pack('<3I',0,7,7),"fixup page bounds")
    require(take(le+records,7)==struct.pack('<BBhBH',7,0,24,1,80),"DDB control internal fixup")
    require(imports==records+7 and procs==imports and u32(le+116)==0 and take(le+procs,1)==b'\0',"no imports")
    require(u32(le+48)==procs+1-pages,"fixup section extent")
    require(data>=le+procs+1 and data%16==0,"absolute bounded page offset")
    require(nonres==data+8192 and nonlen==11 and len(image)==nonres+nonlen,"exact page/name extent and EOF")
    require(take(nonres,nonlen)==b'\x07VXD_DDB\x01\0\0',"nonresident ordinal1 name")
    require(u32(le+80)==names and u32(le+84)==0,"empty resource table")
    require(u32(le+132)==0 and u16(le+192)==0 and u16(le+194)==0x030a,"Watcom header SDK/device")
    for offset in (12,52,60,76,96,100,124,144,148,152,156,160,164,168,172,176,180,184,188):
        require(u32(le+offset)==0,"unsupported auxiliary table")
    payload=take(data,8192); ddb=payload[:80]
    require(ddb[:4]==bytes(4) and ddb[4:12]==bytes.fromhex('0a03000001000000') and ddb[12:20]==b'NTWMIN9X',"DDB identity")
    require(struct.unpack_from('<II',ddb,20)==(0x80000000,80) and ddb[28:60]==bytes(32),"DDB ownership/API fields")
    require(struct.unpack_from('<5I',ddb,60)==(0x50726576,80,0x52737631,0x52737632,0x52737633),"DDB sentinels")
    control=bytes.fromhex('9c83f8237407b801000000eb05b832000000832424fe9dc3')
    # Source assembler records are separately hash-bound by the build receipt.
    require(payload[80:80+len(control)]==control and not any(payload[80+len(control):]),"bounded control-only instructions")
    return {'module_name':'NTWMIN9X','ddb':{'object':1,'offset':0,'bytes':80},
            'objects':[{'size':8192,'base':0,'flags':flags}], 'data_pages':data}
