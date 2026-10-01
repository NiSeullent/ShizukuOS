#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the actual C validator against five linked provider PE images.

No Windows code executes here. The observed six-byte getter is decoded only to
locate the real immutable table; native getter/load behavior needs a guest test.
"""
import argparse
import ctypes
import hashlib
import json
import struct
import subprocess
from pathlib import Path
import pefile

HERE = Path(__file__).resolve().parent
CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
                           ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--providers',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    library=args.out/'libtable.so'
    subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',
                    str(HERE/'table.c'),'-o',str(library)],check=True)
    lib=ctypes.CDLL(str(library));find=lib.ntwp_find_table
    find.argtypes=[CALLBACK,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_char_p,ctypes.c_char_p,
                   ctypes.c_uint16,ctypes.POINTER(ctypes.c_uint32)];find.restype=ctypes.c_int
    checks=[]
    for filename,dll in [('M98WRAP.DLL','KERNEL32.DLL'),('M98SHELL.DLL','SHELL32.DLL'),
                         ('M98AD2.DLL','ADVAPI32.DLL'),('M98USR1.DLL','USER32.DLL'),('M98CTL3.DLL','COMCTL32.DLL')]:
        path=args.providers/filename
        original_bytes=path.read_bytes()
        before_hash=hashlib.sha256(original_bytes).hexdigest()
        with pefile.PE(data=original_bytes) as pe:
            base=pe.OPTIONAL_HEADER.ImageBase
            image=bytearray(pe.get_memory_mapped_image())
            export=next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name==b'get_api_table')
            code=pe.get_data(export.address,6)
            assert code[0]==0xb8 and code[5]==0xc3,'getter shape requires explicit review'
            table=struct.unpack_from('<I',code,1)[0]
            regions=[(0,pe.OPTIONAL_HEADER.SizeOfHeaders,False)]
            for section in pe.sections:
                if section.Characteristics & 0x40000000:
                    regions.append((section.VirtualAddress,max(section.Misc_VirtualSize,section.SizeOfRawData),bool(section.Characteristics&0x20000000)))
        immutable=bytes(image)
        @CALLBACK
        def read(_ctx,address,out,count,executable):
            rva=address-base
            if rva<0 or rva+count>len(image):return 0
            if not any(start<=rva and rva+count<=start+size and (not executable or execute) for start,size,execute in regions):return 0
            ctypes.memmove(out,bytes(image[rva:rva+count]),count);return 1
        def query(name=None,ordinal=0,expected=1,label=''):
            result=ctypes.c_uint32(0xdeadbeef)
            status=find(read,None,table,dll.encode(),name.encode() if name else None,ordinal,ctypes.byref(result))
            assert status==expected,(filename,label,status,expected)
            assert bool(result.value)==(expected==1),(filename,label,'partial address escaped validation')
            checks.append({'artifact':filename,'case':label,'status':'PASS'})
        module,names,count,ords,ocount=struct.unpack_from('<IIIII',image,table-base)
        def cstr(at):
            rva=at-base;return bytes(image[rva:image.index(0,rva)]).decode('ascii')
        named=[cstr(struct.unpack_from('<I',image,names-base+n*8)[0]) for n in range(count)]
        for name in named:query(name,label='actual named export '+name)
        for n in range(ocount):query(ordinal=struct.unpack_from('<I',image,ords-base+n*8)[0],label='actual ordinal')
        query('__UNKNOWN_EXPORT__',expected=0,label='missing export stays absent')
        query(named[0].swapcase(),expected=0,label='symbol names remain case sensitive')
        # A later malformed entry must reject an earlier otherwise-valid match.
        for label,offset,value in [('negative-count',table-base+8,0xffffffff),
                                  ('oversized-count',table-base+8,129),
                                  ('foreign-name-array',table-base+4,0x1000),
                                  ('foreign-function',names-base+(count-1)*8+4,0x1000),
                                  ('nonexecutable-function',names-base+(count-1)*8+4,module),
                                  ('bad-terminator',table-base+20+8,1)]:
            image[:]=immutable;struct.pack_into('<I',image,offset,value)
            query(named[0],expected=-1,label=label)
        image[:]=immutable
        if count>1:
            image[names-base+8:names-base+16]=image[names-base:names-base+8]
            query(named[0],expected=-1,label='duplicate unsorted name')
        image[:]=immutable
        for prefix in range(1,20):
            struct.pack_into('<I',image,table-base+4,0xffffffff-prefix)
            query(named[0],expected=-1,label='overflowing array '+str(prefix));image[:]=immutable
        assert hashlib.sha256(path.read_bytes()).hexdigest()==before_hash
    result={'status':'PASS','checks':checks,'count':len(checks),'native_executed':False,
            'validator_sha256':hashlib.sha256((HERE/'table.c').read_bytes()).hexdigest(),
            'scope':'actual linked table validation; no Windows getter or function execution'}
    (args.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('status','count','native_executed')},indent=2))


if __name__=='__main__':main()
