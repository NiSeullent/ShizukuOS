#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare actual C PBKDF2 with the independent Python/OpenSSL implementation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,default=ROOT/'build/fd5c2-kdf-reference')
    out=parser.parse_args().out.resolve();out.mkdir(parents=True,exist_ok=True)
    sources=[ROOT/'shizukudos/accounts'/name for name in ('kdf.c','sha256.c')]
    files=sources+[ROOT/'shizukudos/accounts'/name for name in ('kdf.h','sha256.h')]
    files+=[ROOT/'shizukudos/tests/test_kdf_reference.c',Path(__file__).resolve()]
    def capture():
        return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    before=capture();results=[]
    vectors=[]
    for pn in (0,1,8,32,64,65,128):
        for sn in (0,1,32,64):
            for rounds in (1,7):
                vectors.append((bytes((i*13+pn)%256 for i in range(pn)),
                                bytes((i*17+sn)%256 for i in range(sn)),rounds))
    vectors.append((b'password',b'salt',600000))
    for cc in ('gcc','clang'):
        exe=out/cc
        cmd=[cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror']
        if cc=='clang':cmd+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
        cmd+=list(map(str,sources+[ROOT/'shizukudos/tests/test_kdf_reference.c']))+['-o',str(exe)]
        compiled=subprocess.run(cmd,text=True,capture_output=True,timeout=30)
        (out/(cc+'-compile.log')).write_text(compiled.stdout+compiled.stderr)
        compiled.check_returncode()
        for pw,salt,rounds in vectors:
            expected=hashlib.pbkdf2_hmac('sha256',pw,salt,rounds,32).hex()
            run=subprocess.run([str(exe),pw.hex(),salt.hex(),str(rounds)],text=True,
                capture_output=True,timeout=60,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
            if run.returncode or run.stdout.strip()!=expected:
                raise RuntimeError(f'{cc}: independent KDF mismatch {len(pw)=} {len(salt)=} {rounds=}: {run.stderr}')
        results.append({'compiler':cc,'vectors':len(vectors),'status':'PASS',
                        'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest()})
        print(cc,'independent PBKDF2',len(vectors),'PASS',flush=True)
    receipt={'source_sha256':before,'source_stable':before==capture(),'results':results,
             'reference':'Python hashlib.pbkdf2_hmac (OpenSSL)',
             'scope':'portable KDF only; synthetic test vectors, no guest or account persistence'}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    raise SystemExit(0 if receipt['source_stable'] else 1)

if __name__=='__main__':main()
