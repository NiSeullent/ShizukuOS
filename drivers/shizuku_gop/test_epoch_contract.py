#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual160B epoch consumer controls; HC14/Win16 runtime not executed."""
import ctypes,json,struct,subprocess,tempfile
from pathlib import Path
from test_contract import descriptor,anchor
from test_live_contract import snapshot
HERE=Path(__file__).resolve().parent

def main():
    with tempfile.TemporaryDirectory(prefix='gop-epoch-contract-') as tmp:
        w=Path(tmp);c=w/'wrapper.c'
        c.write_text('#include "gop_live_contract.h"\nint admit(const unsigned char*e,size_t n,const unsigned char*nonce,const unsigned char*p,const unsigned char*provider){shzgop_mode m;return shzgop_probe_admit(p,288,provider,&m)&&shzgop_epoch_admit(e,n,nonce,p);}\n')
        subprocess.run(['gcc','-std=c99','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-shared','-fPIC','-I'+str(HERE),str(c),'-o',str(w/'epoch.so')],check=True)
        lib=ctypes.CDLL(str(w/'epoch.so'));lib.admit.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
        probe=bytearray(snapshot());d=descriptor(location=0x10000000,base=0xd0000000);a=anchor(d)
        probe[64:112]=a;probe[112:208]=d;struct.pack_into('<I',probe,56,struct.unpack_from('<I',d,16)[0])
        words=[0x31455047,1,40,5,1,0,3,16,0x11111234,0x030000]+[0xd0000008,0,0,0,0,0]+[0x7d7d7d7d]*24
        epoch=struct.pack('<40I',*words);nonce=epoch[64:96];provider=bytes(range(32));checks=0
        def check(e=epoch,n=None,nn=nonce,p=probe,pr=provider,expected=0):
            nonlocal checks
            got=lib.admit(ctypes.create_string_buffer(bytes(e)),len(e) if n is None else n,ctypes.create_string_buffer(nn),ctypes.create_string_buffer(bytes(p)),ctypes.create_string_buffer(pr))
            if got!=expected:raise AssertionError((checks,got,expected))
            checks+=1
        check(expected=1)
        for n in (0,4,64,96,159,161):check(n=n)
        check(nn=b'x'+nonce[1:]);check(nn=bytes(32));check(pr=b'x'+provider[1:])
        for index,value in ((0,0),(1,0),(1,2),(2,39),(3,3),(4,0),(5,256),(6,1),(7,17),(8,0x11114321),(9,0),(10,0xd0000018),(10,0xd0000000)):
            e=bytearray(epoch);struct.pack_into('<I',e,index*4,value);check(e=e)
        for start,end in ((64,96),(96,128),(128,160)):
            e=bytearray(epoch);e[start:end]=bytes(end-start);check(e=e)
        for index,value in ((80,0x11000000),(84,0x11114321),(24,0xe0000000)):
            p=bytearray(probe);d=bytearray(p[112:208]);struct.pack_into('<I',d,index,value);struct.pack_into('<I',d,16,0);struct.pack_into('<I',d,16,(-sum(struct.unpack('<24I',d)))&0xffffffff)
            p[64:112]=anchor(d);p[112:208]=d;struct.pack_into('<I',p,56,struct.unpack_from('<I',d,16)[0]);check(p=p)
        print(json.dumps(dict(status='PASS_ACTUAL_C_GUARDIAN_CONSUMER',checks=checks,VM_executed=False,default_GOP_registered=False)))
if __name__=='__main__':main()
