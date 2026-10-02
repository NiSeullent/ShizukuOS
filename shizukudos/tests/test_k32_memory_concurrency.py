#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded actual Kernel32 allocator host tests; never launches a guest."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / 'shizukudos/tests/test_k32_memory_concurrency.c'
FLAGS = ['-std=gnu11', '-O2', '-fPIE', '-Wall', '-Wextra', '-Werror',
         '-Wno-int-to-pointer-cast', '-Wno-pointer-to-int-cast', '-pthread']

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--guards-only',action='store_true')
    args=p.parse_args()
    out=args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'build'):
        p.error('output must be a fresh directory under this worktree build/')
    out.mkdir(parents=True)
    sources={Path(__file__).resolve(),UNIT}
    compilers={name:Path(shutil.which(name)).resolve() for name in ('gcc','clang')}
    tools={str(path):digest(path) for path in compilers.values()}
    commands=[]
    def call(argv,label,timeout=60):
        started=time.monotonic()
        try:
            r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=timeout)
            item={'argv':list(map(str,argv)),'exit_code':r.returncode,
                  'stdout':r.stdout,'stderr':r.stderr,'timed_out':False}
        except subprocess.TimeoutExpired as e:
            item={'argv':list(map(str,argv)),'exit_code':None,'timed_out':True,
                  'stdout':(e.stdout or b'').decode(errors='replace'),
                  'stderr':(e.stderr or b'').decode(errors='replace')}
        item['seconds']=round(time.monotonic()-started,3)
        (out/(label+'.log')).write_text(item['stdout']+item['stderr'])
        commands.append(item)
        return item
    for name,compiler in compilers.items():
        r=call([compiler,*FLAGS,'-MM',UNIT],name+'-dependencies')
        if r['exit_code']!=0: raise RuntimeError('dependency discovery failed')
        for token in shlex.split(r['stdout'].replace('\\\n',' ').split(':',1)[1]):
            path=Path(token).resolve()
            if not path.is_relative_to(ROOT): raise RuntimeError('unexpected project dependency')
            sources.add(path)
    before={str(path.relative_to(ROOT)):digest(path) for path in sorted(sources)}
    frozen=out/'source'
    for path in sources:
        target=frozen/path.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True)
        b=path.read_bytes()
        if hashlib.sha256(b).hexdigest()!=before[str(path.relative_to(ROOT))]:
            raise RuntimeError('source changed during capture')
        target.write_bytes(b)
    (out/'before.json').write_text(json.dumps({'sources':before,'compiler_drivers':tools},indent=2)+'\n')
    all_passed=True
    for name,compiler in compilers.items():
        binary=out/(name+'-allocator')
        extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if name=='clang' else []
        r=call([compiler,*FLAGS,*extra,frozen/UNIT.relative_to(ROOT),'-pie','-o',binary],name+'-compile')
        if r['exit_code']!=0: all_passed=False;continue
        for mode in (('guards',) if args.guards_only else ('pmm','heap','guards')):
            r=call([binary,mode],name+'-'+mode)
            all_passed&=r['exit_code']==0 and not r['timed_out']
    after={rel:digest(ROOT/rel) for rel in before}
    stable=before==after and all(digest(path)==h for path,h in tools.items())
    result={'status':'PASS' if all_passed and stable else 'FAIL',
            'scope':'Actual C allocators with contiguous low host mappings; local IRQ adapters; host-only.',
            'sources_before':before,'sources_after':after,'compiler_drivers_before':tools,
            'compiler_drivers_after':{path:digest(path) for path in tools},
            'inputs_unchanged':stable,'commands':commands,
            'external_environment_sealed':False,'guest_executed':False,
            'physical_ap_executed':False,'generic_page_table_smp_verified':False,
            'artifact_sha256':{str(p.relative_to(out)):digest(p) for p in out.rglob('*') if p.is_file()},
            'owned_output_bytes':sum(p.stat().st_size for p in out.rglob('*') if p.is_file())}
    if result['owned_output_bytes']>64<<20: raise RuntimeError('output cap exceeded')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'inputs_unchanged':stable,
                      'outputs':result['owned_output_bytes'],'result':str(out/'result.json')}))

if __name__=='__main__': main()
