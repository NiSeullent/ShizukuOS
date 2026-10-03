#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile combined account/GUI/token routing units, without images or a VM."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
UNITS=('auth_core','sysk32_auth','sysk32_sec','proc','ldr','objects','ipc_core',
       'ipc_proc','ipc_io','ipc_section','sysx','syscall','sysfile','npfs','autorun',
       'gfx_wm','gfx_msg','gfx_input','registry','sysreg')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve()
    if out.exists():parser.error('fresh output directory required')
    out.mkdir(parents=True)
    pending=[Path(__file__).resolve(),ROOT/'shizukudos/kbuild.py']
    pending += [ROOT/'shizukudos/kernel64'/(name+'.c') for name in UNITS]
    sources={}
    while pending:
        path=pending.pop().resolve();rel=path.relative_to(ROOT)
        if rel in sources:continue
        data=path.read_bytes();sources[rel]=data
        pending.extend(path.parent/name.decode() for name in
                       re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"',data,re.M))
    snap=out/'source'
    for rel,data in sources.items():
        target=snap/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    flags=None
    for node in ast.parse(sources[Path('shizukudos/kbuild.py')]).body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='K64_FLAGS' for t in node.targets):
            flags=ast.literal_eval(node.value)
    if not flags:raise RuntimeError('literal production Kernel64 flags missing')
    results=[]
    for cc in ('gcc','clang'):
        directory=out/cc;directory.mkdir();objects=[]
        effective=[f for f in flags if not(cc=='clang' and f=='-fno-tree-loop-distribute-patterns')]
        for name in UNITS:
            obj=directory/(name+'.o');source=snap/'shizukudos/kernel64'/(name+'.c')
            cmd=[cc,*effective,'-I',str(snap/'shizukudos'),'-I',str(snap/'shizukudos/kernel64'),
                 '-c',str(source),'-o',str(obj)]
            started=time.monotonic();run=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
            (directory/(name+'.log')).write_text(run.stdout+run.stderr)
            results.append({'compiler':cc,'unit':name,'command':cmd,'exit':run.returncode,
                            'elapsed_seconds':time.monotonic()-started})
            if run.returncode:print(run.stderr,flush=True);break
            results[-1]['object_sha256']=hashlib.sha256(obj.read_bytes()).hexdigest();objects.append(obj)
        if len(objects)==len(UNITS):
            combined=directory/'account-routing.o'
            cmd=['ld','-r',*map(str,objects),'-o',str(combined)]
            run=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
            (directory/'link.log').write_text(run.stdout+run.stderr)
            results.append({'compiler':cc,'unit':'partial-relocatable-link','command':cmd,'exit':run.returncode})
            if not run.returncode:
                results[-1]['object_sha256']=hashlib.sha256(combined.read_bytes()).hexdigest()
                undefined=subprocess.run(['nm','-u',str(combined)],capture_output=True,text=True,check=True,timeout=30)
                (directory/'undefined-runtime-symbols.txt').write_text(undefined.stdout)
        print(cc,'combined units',len(objects),'of',len(UNITS),flush=True)
    stable=all((ROOT/rel).read_bytes()==data for rel,data in sources.items())
    passed=stable and len(results)==2*(len(UNITS)+1) and all(row['exit']==0 for row in results)
    receipt={'passed':passed,'source_stable':stable,
             'source_sha256':{str(rel):hashlib.sha256(data).hexdigest() for rel,data in sources.items()},
             'results':results,'external_toolchain_closure_complete':False,
             'scope':'combined freestanding units and partial relocatable link; undefined external runtime symbols retained; no full kernel/image/guest/native Windows98 execution'}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    raise SystemExit(0 if passed else 1)

if __name__=='__main__':main()
