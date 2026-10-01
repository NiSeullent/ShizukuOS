#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the actual C parser against linked binaries and immutable official roots."""
import argparse
import ctypes as C
import hashlib
import json
import struct
import subprocess
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
class Section(C.Structure):
    _fields_=[(name,C.c_uint32) for name in ('va','span','raw','bytes','flags')]
class Image(C.Structure):
    _fields_=[('file',C.c_void_p)]+[(name,C.c_uint32) for name in ('bytes','base','size','headers','entry','section_align')]+[(name,C.c_uint16) for name in ('sections','characteristics','subsystem','subsystem_major','subsystem_minor')]+[('directory',(C.c_uint32*2)*16),('section',Section*96)]
class Tls(C.Structure):
    _fields_=[(name,C.c_uint32) for name in ('present','template_rva','template_bytes','zero_bytes','index_rva','callbacks_rva','alignment','count')]+[('callback',C.c_uint32*64)]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--artifact-dir',type=Path,required=True)
    args=ap.parse_args();out=args.out.resolve()
    if out.exists():ap.error('use a new output directory')
    out.mkdir(parents=True)
    command=['gcc','-std=c11','-shared','-fPIC','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=undefined','-fsanitize-undefined-trap-on-error','-o',str(out/'parser.so'),str(HERE/'pe.c')]
    subprocess.run(command,check=True,cwd=ROOT)
    lib=C.CDLL(str(out/'parser.so'));records=[]
    lib.np_parse.argtypes=[C.POINTER(Image),C.c_void_p,C.c_uint32,C.POINTER(C.c_char_p)]
    lib.np_imports.argtypes=[C.POINTER(Image),C.c_int,C.c_void_p,C.c_void_p,C.POINTER(C.c_uint32),C.POINTER(C.c_char_p)]
    lib.np_relocations.argtypes=[C.POINTER(Image),C.c_void_p,C.c_void_p,C.POINTER(C.c_char_p)]
    lib.np_execution_profile.argtypes=[C.POINTER(Image),C.POINTER(C.c_char_p)]
    lib.np_export.argtypes=[C.POINTER(Image),C.c_char_p,C.c_uint16,C.POINTER(C.c_uint32),C.POINTER(C.c_char_p),C.POINTER(C.c_char_p)]
    lib.np_tls.argtypes=[C.POINTER(Image),C.POINTER(Tls),C.POINTER(C.c_char_p)]
    lib.np_runtime_profile.argtypes=[C.POINTER(Image),C.POINTER(C.c_char_p)]
    def check(name,data,expected=True,profile=None):
        buf=C.create_string_buffer(bytes(data));image=Image();error=C.c_char_p();count=C.c_uint32();forward=C.c_char_p();rva=C.c_uint32()
        valid=bool(lib.np_parse(C.byref(image),buf,len(data),C.byref(error)))
        if valid:valid=bool(lib.np_imports(C.byref(image),1,None,None,C.byref(count),C.byref(error)))
        if valid:valid=bool(lib.np_relocations(C.byref(image),None,None,C.byref(error)))
        if valid:valid=bool(lib.np_export(C.byref(image),b'__VALIDATE_ONLY__',0,C.byref(rva),C.byref(forward),C.byref(error)))
        if valid:valid=bool(lib.np_tls(C.byref(image),C.byref(Tls()),C.byref(error)))
        assert valid==expected,(name,valid,error.value)
        error_text=error.value.decode() if error.value else None
        executable=bool(lib.np_execution_profile(C.byref(image),C.byref(error))) if valid else False
        if profile is not None:assert executable==profile,(name,error.value)
        records.append({'case':name,'valid':valid,'imports':count.value,'error':error_text,'classic_profile':executable})
        return image
    artifacts=args.artifact_dir.resolve();build=json.loads((artifacts/'build-result.json').read_text())
    assert build['status']=='PASS','only a completed compile/import receipt may supply fixtures'
    for artifact in build['artifacts']:assert sha(Path(artifact['path']))==artifact['sha256']
    fixture=(artifacts/'PE32FIX.DLL').read_bytes()
    check('actual linked native loader',(artifacts/'NTWPE32.EXE').read_bytes(),profile=True)
    image=check('actual linked fixture',fixture,profile=True)
    if (artifacts/'PE32FAIL.DLL').exists():check('actual linked failing-attach fixture',(artifacts/'PE32FAIL.DLL').read_bytes(),profile=True)
    for name in ('PEORDA.DLL','PEORDB.DLL','PEBFAIL.DLL','PEORDER.DLL'):
        if (artifacts/name).exists():check('actual linked '+name,(artifacts/name).read_bytes(),profile=True)
    official=ROOT/'build/latest-app-preflight-20260930/chromium-157.0.8080.0-1707946'
    pinned={'chrome.exe':'7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823',
            'chrome_elf.dll':'54ffa9edd24ed9251fefca50abd27d4542fe81b63757d0ed0df2304a36ad1473'}
    official_images={}
    for name,digest in pinned.items():
        path=official/name;assert sha(path)==digest;check('official '+name,path.read_bytes(),profile=False)
        official_images[name]=path.read_bytes()
    pe=struct.unpack_from('<I',fixture,60)[0];opt=pe+24;table=opt+struct.unpack_from('<H',fixture,pe+20)[0]
    def change(name,offset,value,format='<I'):
        data=bytearray(fixture);struct.pack_into(format,data,offset,value);check(name,data,False)
    for size in (0,1,63,pe+3,opt+95,table+39):check('truncated '+str(size),fixture[:size],False)
    change('overflow PE header',60,0xfffffff0)
    change('wrong machine',pe+4,0x8664,'<H')
    change('missing optional header',pe+20,95,'<H')
    change('directory exceeds optional header',opt+92,17)
    change('section count overflow',pe+6,97,'<H')
    change('nonpower file alignment',opt+36,513)
    change('image size overflow',opt+56,0xfffff000)
    change('raw section beyond file',table+20,0xfffffe00)
    change('virtual section wraps',table+12,0xfffff000)
    change('virtual sections overlap',table+40+12,struct.unpack_from('<I',fixture,table+12)[0])
    change('raw sections overlap',table+40+20,struct.unpack_from('<I',fixture,table+20)[0])
    change('directory partial declaration',opt+96+9*8+4,24)
    change('directory overflowing RVA',opt+96+5*8,0xfffffff0)
    change('entry in headers',opt+16,32)
    def raw(rva):
        for s in image.section[:image.sections]:
            if s.va<=rva<s.va+s.bytes:return s.raw+rva-s.va
        raise AssertionError(rva)
    irva=image.directory[1][0];ipat=raw(irva);lookup=struct.unpack_from('<I',fixture,ipat)[0];iat=struct.unpack_from('<I',fixture,ipat+16)[0]
    change('import DLL path injection',raw(struct.unpack_from('<I',fixture,ipat+12)[0]),ord('/'),'<B')
    change('lookup thunk overflows',ipat,0xfffffffc)
    change('IAT writes headers',ipat+16,32)
    change('invalid ordinal high bits',raw(lookup),0x80010001)
    change('unterminated imported name RVA',raw(lookup),0xfffffff0)
    rrva=image.directory[5][0];rat=raw(rrva);change('relocation block overflows',rat+4,0xfffffffc)
    change('relocation page unaligned',rat,1)
    change('unsupported relocation type',rat+8,0x5000,'<H')
    change('relocation writes headers',rat,0)
    change('overlapping relocation targets',rat+10,struct.unpack_from('<H',fixture,rat+8)[0],'<H')
    er=image.directory[0][0];ea=raw(er);functions=raw(struct.unpack_from('<I',fixture,ea+28)[0]);change('export targets beyond image',functions,0xfffffff0)
    for directory in (3,7,9,10,11,13,14):
        data=bytearray(fixture);struct.pack_into('<II',data,opt+96+directory*8,irva,4)
        if directory==13:check('truncated delay directory',data,False)
        elif directory==9:check('truncated TLS directory',data,False)
        else:check('declared blocked runtime '+str(directory),data,profile=False)
    chrome=official_images['chrome.exe'];ci=check('official Chrome repeat parser',chrome,profile=False)
    cp=struct.unpack_from('<I',chrome,60)[0];co=cp+24
    def chrome_raw(rva):
        for s in ci.section[:ci.sections]:
            if s.va<=rva<s.va+s.bytes:return s.raw+rva-s.va
        raise AssertionError(rva)
    data=bytearray(chrome);rel=chrome_raw(ci.directory[5][0]);struct.pack_into('<II',data,co+96+5*8,ci.directory[5][0],24)
    struct.pack_into('<IIHHIIHH',data,rel,0x1000,12,0x3fff,0,0x2000,12,0x3000,0)
    check('cross-page overlapping relocations',data,False)
    data=bytearray(chrome);delay=chrome_raw(ci.directory[13][0]);ordinary=chrome_raw(ci.directory[1][0]);struct.pack_into('<I',data,delay+12,struct.unpack_from('<I',chrome,ordinary+16)[0])
    check('ordinary-delay IAT overlap',data,False)
    if (artifacts/'PE32TLS.DLL').exists():
        tls_bytes=(artifacts/'PE32TLS.DLL').read_bytes();ti=check('actual MS-ABI TLS DLL',tls_bytes,profile=False)
        buf=C.create_string_buffer(tls_bytes);pi=Image();err=C.c_char_p();td=Tls()
        assert lib.np_parse(C.byref(pi),buf,len(tls_bytes),C.byref(err))
        assert lib.np_tls(C.byref(pi),C.byref(td),C.byref(err))
        assert (td.present,td.template_bytes,td.zero_bytes,td.alignment,td.count)==(1,4,28,64,1)
        assert lib.np_runtime_profile(C.byref(pi),C.byref(err))
        tp=struct.unpack_from('<I',tls_bytes,60)[0];to=tp+24
        def tls_raw(rva):
            if rva<pi.headers:return rva
            for section in pi.section[:pi.sections]:
                if section.va<=rva<section.va+section.bytes:return section.raw+rva-section.va
            raise AssertionError(rva)
        descriptor=tls_raw(pi.directory[9][0]);callbacks=tls_raw(td.callbacks_rva)
        def tls_change(name,at,value):
            data=bytearray(tls_bytes);struct.pack_into('<I',data,at,value);check(name,data,False)
        tls_change('TLS directory too short',to+96+9*8+4,20)
        tls_change('TLS template VA underflows',descriptor,pi.base-1)
        tls_change('TLS template end precedes start',descriptor+4,pi.base+td.template_rva-1)
        tls_change('TLS template zero exceeds cap',descriptor+16,1048576)
        tls_change('TLS index null',descriptor+8,0)
        tls_change('TLS index unaligned',descriptor+8,pi.base+td.index_rva+1)
        tls_change('TLS index targets executable section',descriptor+8,pi.base+pi.entry)
        tls_change('TLS index overlaps template',descriptor+8,pi.base+td.template_rva)
        tls_change('TLS callback array invalid',descriptor+12,pi.base+pi.size-1)
        tls_change('TLS callback VA outside image',callbacks,0xffffffff)
        tls_change('TLS callback target nonexecutable',callbacks,pi.base+td.index_rva)
        tls_change('TLS reserved characteristics',descriptor+20,0x00700001)
        tls_change('TLS reserved alignment15',descriptor+20,0x00f00000)
        data=bytearray(tls_bytes)
        # Place an unterminated executable callback array in readable raw padding.
        room=next(s for s in pi.section[:pi.sections] if s.va<=td.template_rva<s.va+s.bytes)
        assert room.bytes>=65*4
        struct.pack_into('<I',data,descriptor+12,pi.base+room.va+16)
        for n in range(65):struct.pack_into('<I',data,room.raw+16+n*4,pi.base+pi.entry)
        check('TLS callback array lacks bounded terminator',data,False)
    for key,digest in pinned.items():assert sha(official/key)==digest
    receipt={'status':'PASS','native_executed':False,'cases':records,'command':command,'sources':{name:sha(HERE/name) for name in ('pe.c','pe.h','test.py')},'official_unchanged':pinned,'parser_sha256':sha(out/'parser.so')}
    (out/'host-result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'status':'PASS','cases':len(records),'receipt':str(out/'host-result.json')}))

if __name__=='__main__':main()
