#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute exact frontend token/SID/ACL/AccessCheck bodies with native API adapters."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).with_suffix('.c')
ADV=Path('shizukudos/win64/dlls/advapi32')


def definition(source,name):
    m=re.search(r'^[^\n;{}]*\b'+name+r'\([^;{}]*\)\s*\{',source,re.M)
    if not m:raise ValueError('missing production definition '+name)
    depth=1
    for i in range(m.end(),len(source)):
        depth+=(source[i]=='{')-(source[i]=='}')
        if not depth:return source[m.start():i+1]
    raise ValueError('unterminated production definition '+name)


def capture():
    pending=[FIXTURE,Path(__file__).resolve(),ROOT/ADV/'token.c',ROOT/ADV/'sid.c',ROOT/ADV/'security.c']
    data={}
    while pending:
        p=pending.pop().resolve();rel=p.relative_to(ROOT)
        if rel in data:continue
        contents=p.read_bytes();data[rel]=contents
        for inc in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"',contents,re.M):
            name=inc.decode();choices=[p.parent/name,ROOT/'shizukudos/win64/include'/name]
            found=next((c for c in choices if c.is_file()),None)
            if found is None:raise ValueError('unresolved production local include '+name)
            pending.append(found)
    # Old token.c does not yet include the new query ABI consumed by the fixture.
    for rel in (Path('shizukudos/abi/shz_auth.h'),Path('shizukudos/accounts/account.h')):
        data.setdefault(rel,(ROOT/rel).read_bytes())
    return data


def execute(command,timeout,env=None):
    start=time.monotonic()
    try:
        result=subprocess.run(command,capture_output=True,text=True,timeout=timeout,env=env)
        return result.returncode,result.stdout+result.stderr,time.monotonic()-start,False
    except subprocess.TimeoutExpired as error:
        def decoded(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
        return 124,decoded(error.stdout)+decoded(error.stderr)+'\nTIMEOUT\n',time.monotonic()-start,True


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',default='current');p.add_argument('--compiler',choices=('gcc','clang','all'),default='all')
    p.add_argument('--mingw',action='store_true',help='also compile the entire captured production token.c to a PE/COFF object')
    p.add_argument('--timeout',type=float,default=120,help='bounded timeout per compiler/executable, seconds');a=p.parse_args()
    if a.timeout<=0:raise SystemExit('timeout must be positive')
    out=ROOT/'build/fd5c2-token-identity'/a.label
    if out.exists():raise SystemExit('fresh output label required')
    data=capture();token=data[ADV/'token.c'].decode();sid=data[ADV/'sid.c'].decode();security=data[ADV/'security.c'].decode()
    record=re.search(r'typedef struct shz_token_info \{.*?\} shz_token_info;',data[Path('shizukudos/win64/include/nt.h')].decode(),re.S).group(0)
    identity=token.split('/* ---------------------------------------------------------------- the identity */',1)[1].split('/* ---------------------------------------------------------------- opening and duplicating */',1)[0]
    identity=identity.split('static int wieq(',1)[0] # only unrelated account-name comparison is omitted
    rendering=identity+'\n'+definition(token,'nt_ok')+'\n'+definition(token,'token_info')
    rendering+='\ntypedef struct { BYTE *b; DWORD cap, need; } obuf;\n'
    rendering+='\n'.join(definition(token,n) for n in ('oreserve','oput_sid','GetTokenInformation','token_has_sid','AccessCheck','CreateProcessAsUserW'))
    sid_functions='\n'.join(definition(sid,n) for n in ('sid_valid','sid_len','IsValidSid','GetLengthSid','EqualSid','GetSidSubAuthorityCount','GetSidSubAuthority','MapGenericMask'))
    acl_functions='\n'.join(definition(security,n) for n in ('InitializeAcl','sec_acl_used','IsValidAcl','ace_at','insert_aces','sec_add_simple_ace','sec_parts','IsValidSecurityDescriptor'))
    fixture=data[FIXTURE.relative_to(ROOT)].decode()
    user_sid_macro=re.search(r'^#define SHZ_USER_SID_W .+$',data[Path('shizukudos/win64/include/ntreg.h')].decode(),re.M).group(0)
    fixture=fixture.replace('/* @PRODUCTION_TOKEN_RECORD@ */',record+'\n'+user_sid_macro+'\n#include "../abi/shz_auth.h"')
    fixture=fixture.replace('/* @PRODUCTION_SID_FUNCTIONS@ */',sid_functions).replace('/* @PRODUCTION_ACL_FUNCTIONS@ */',acl_functions).replace('/* @PRODUCTION_TOKEN_RENDERING@ */',rendering)
    snap=out/'source'
    for rel,contents in data.items():
        dst=snap/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(contents)
    unit=snap/FIXTURE.relative_to(ROOT);unit.write_text(fixture);results=[]
    for compiler in (['gcc','clang'] if a.compiler=='all' else [a.compiler]):
        cc=shutil.which(compiler)
        if not cc:raise SystemExit('compiler missing '+compiler)
        flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-const-variable','-fshort-wchar']
        if compiler=='clang':flags+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
        binary=out/(compiler+'-token-identity');command=[cc,*flags,str(unit),'-o',str(binary)]
        code,log,elapsed,expired=execute(command,a.timeout);(out/(compiler+'-compile.log')).write_text(log)
        r={'compiler':compiler,'command':command,'compile_exit':code,'compile_seconds':elapsed,'compile_timeout':expired}
        if not code:
            code,log,elapsed,expired=execute([str(binary)],a.timeout,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
            (out/(compiler+'-run.log')).write_text(log);r.update(run_exit=code,run_seconds=elapsed,run_timeout=expired,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest());print(compiler,log,end='')
        else:print(log)
        results.append(r)
    if a.mingw:
        cc=shutil.which('x86_64-w64-mingw32-gcc')
        if not cc:raise SystemExit('installed MinGW compiler missing')
        binary=out/'token-mingw.obj'
        command=[cc,'-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fno-ident',
                 '-Wno-unused-function','-Wno-unused-parameter','-Wno-cast-function-type','-I',str(snap/'shizukudos/win64/include'),
                 '-c',str(snap/ADV/'token.c'),'-o',str(binary)]
        code,log,elapsed,expired=execute(command,a.timeout);(out/'mingw-compile.log').write_text(log)
        r={'compiler':'mingw64','command':command,'object_only':True,'compile_exit':code,'compile_seconds':elapsed,'compile_timeout':expired}
        if not code:r['object_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
        print('mingw64 full production object', 'PASS' if not code else 'FAIL',log);results.append(r)
    stable=all((ROOT/f).read_bytes()==contents for f,contents in data.items())
    receipt={'source_sha256':{str(f):hashlib.sha256(contents).hexdigest() for f,contents in data.items()},'source_stable':stable,'generated_fixture_sha256':hashlib.sha256(unit.read_bytes()).hexdigest(),'timeout_seconds':a.timeout,'results':results,'scope':'unchanged actual token/SID/ACL/AccessCheck/caller-launch production bodies; Windows type and native transport host adapters; optional complete production MinGW object; no native Windows98/NT DACL enforcement proof'}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return 0 if stable and results and all(r['compile_exit']==0 and (r.get('object_only') or r.get('run_exit',1)==0) for r in results) else 1


if __name__=='__main__':raise SystemExit(main())
