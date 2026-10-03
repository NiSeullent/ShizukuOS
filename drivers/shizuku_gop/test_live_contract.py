#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the actual live-query C consumer with hostile snapshot bytes.

These are host admission checks, never evidence of a guest/current-boot query.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from test_contract import descriptor,anchor

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def snapshot():
    p=bytearray(288);p[:8]=b'SHZGPB1\0';struct.pack_into('<HHI',p,8,1,0,288)
    p[16:48]=bytes(range(32));d=descriptor();a=anchor(d)
    struct.pack_into('<III',p,48,0xf1000,0x800000,struct.unpack_from('<I',d,16)[0])
    p[64:112]=a;p[112:208]=d
    h=bytearray(80)
    for at,v in {0:280,4:8192|256,8:20260213,12:1280,16:800,20:32,24:5120,
                 32:5120*800,40:0xc0200000,48:0xd0000000,52:5120*800,
                 56:16*1024*1024,60:5120*800}.items():struct.pack_into('<I',h,at,v)
    h[64:80]=b'SHZGOP.VXD\0\0\0\0\0\0';p[208:288]=h;return bytes(p)
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,default=ROOT/'build/gop-live-contract-test')
    args=parser.parse_args();out=args.out.resolve()
    if out==ROOT/'build' or not out.is_relative_to((ROOT/'build').resolve()):parser.error('owned component output under build required')
    out.mkdir(parents=True,exist_ok=True)
    source=out/'wrapper.c';source.write_text('#include "gop_live_contract.h"\n'
        'int admit(const unsigned char*p,size_t n,const unsigned char*i){shzgop_mode m;return shzgop_probe_admit(p,n,i,&m);}\n')
    cmd=['gcc','-std=c99','-Wall','-Wextra','-Werror','-Wno-unused-function','-shared','-fPIC','-O2',
         '-I'+str(HERE),str(source),'-o',str(out/'contract.so')]
    subprocess.run(cmd,check=True);lib=ctypes.CDLL(str(out/'contract.so'))
    lib.admit.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
    provider=bytes(range(32));checks=[]
    def check(name,p,expected=0,identity=provider):
        actual=lib.admit(ctypes.create_string_buffer(p),len(p),ctypes.create_string_buffer(identity))
        if actual!=expected:raise AssertionError(f'{name}: {actual} != {expected}')
        checks.append({'name':name,'status':'PASS'})
    p=snapshot();check('source-bound actual descriptor and HDA snapshot',p,1)
    for n in (0,15,47,111,207,287,289):check('extent '+str(n),(p+b'\0')[:n])
    check('different source implementation provider',p,identity=b'!'+provider[1:])
    check('all-zero provider cannot replace expected implementation',p,identity=bytes(32))
    zero=bytearray(p);zero[16:48]=bytes(32);check('matching all-zero implementation is not source admission',bytes(zero),identity=bytes(32))
    # Every meaningful validated byte is corrupted individually. Dynamic HDA
    # surface/onflip/PM16 alias fields are deliberately not acceptance fields.
    required=list(range(208))+list(range(208,236))+list(range(240,244))+list(range(260,288))
    for i in required:
        bad=bytearray(p);bad[i]^=1;check('corruption '+str(i),bytes(bad))
    for at,val in ((208,79),(208,4097),(212,0),(216,20260212),(228,24),
                   (256,0),(260,0),(264,0),(268,0),(48,0xf0001),(52,0x800001),(60,1)):
        bad=bytearray(p);struct.pack_into('<I',bad,at,val);check(f'field {at}:{val}',bytes(bad))
    # Valid replacement records must still match observed live HDA dimensions.
    bad=bytearray(p);d=descriptor(width=1024,pitch=4096,visible=4096*800)
    a=anchor(d);bad[64:112]=a;bad[112:208]=d;struct.pack_into('<I',bad,56,struct.unpack_from('<I',d,16)[0])
    check('valid different native mode with old HDA rejected',bytes(bad))
    result={'schema':'shizukuos.host-gop-live-contract-test.v1','status':'HOST_ADMISSION_PASS_NOT_NATIVE_PROOF',
        'checks':checks,'command':cmd,'sources':{str(q.relative_to(ROOT)):hashlib.sha256(q.read_bytes()).hexdigest()
          for q in (Path(__file__),HERE/'gop_live_contract.h',HERE/'gop_contract.h',HERE/'test_contract.py')},
        'VM_executed':False,'default_GOP_registered':False,'GPU_active':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'checks':len(checks)}))
if __name__=='__main__':main()
