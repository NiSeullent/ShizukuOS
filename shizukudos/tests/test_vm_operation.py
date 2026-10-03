#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""VM permission/lifetime contracts; per-invocation 8MiB output ceiling; no images."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from test_nt_settings import block_end,function,case

ROOT=Path(__file__).resolve().parents[2]
KERNEL=ROOT/'shizukudos/kernel64'
LIMIT=8*1024*1024

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--red',action='store_true',help='GCC behavior only before source correction')
    args=parser.parse_args();out=args.out.resolve()
    if out.exists():parser.error('fresh output required')
    out.mkdir(parents=True)
    files=[Path(__file__).resolve(),Path(__file__).with_suffix('.c'),Path(__file__).with_name('test_nt_settings.py'),
           ROOT/'shizukudos/kbuild.py',*[KERNEL/n for n in ('syscall.c','objects.c','ipc_core.c','vad.c','ipc.h')]]
    sources={}
    while files:
        p=files.pop().resolve()
        if p in sources:continue
        data=p.read_bytes();sources[p]=data
        if p.parent==KERNEL or p.suffix=='.h':
            files.extend(p.parent/n.decode() for n in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"',data,re.M))
    def src(n):return sources[KERNEL/n].decode()
    snap=out/'source'
    for p,data in sources.items():
        target=snap/p.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    k64,internal=src('k64.h'),src('proc_internal.h')
    thread=k64[k64.index('typedef struct thread thread_t;'):block_end(k64,k64.index('{',k64.index('struct thread {')))]+ ';\n'
    process=internal[internal.index('/* ---- virtual address descriptors ---- */'):block_end(internal,internal.index('{',internal.index('struct process {')))]+ ';\n'
    (out/'layouts.inc').write_text(thread+process)
    obj='\n'.join(function(src('objects.c'),n) for n in ('ob_create','ob_ref','ob_deref','handle_insert','handle_lookup','handle_ref','handle_close'))
    free='void ipc_object_free(kobject_t *o) { switch(o->type) {\n'+case(src('ipc_core.c'),'OB_PROCESS')+'default:break; } }\n'+function(src('vad.c'),'vad_destroy')
    ipc='\n'.join(function(src('ipc_core.c'),n) for n in ('ipc_ref_handle','ipc_ref_process'))
    defs='\n'.join(re.findall(r'^#define PROCESS_VM_OPERATION[^\n]+',src('ipc.h'),re.M))
    vm='\n'.join(function(src('syscall.c'),n,optional=True) for n in ('proc_from_handle','vm_target_status','vm_ref_target','sys_allocate_vm','sys_free_vm','sys_protect_vm'))
    vad='\n'.join(function(src('vad.c'),n) for n in ('vad_alloc','vad_free','vad_protect'))
    fixture=sources[Path(__file__).with_suffix('.c')].decode()
    for tag,data in (('OBJECT_FREE',free),('OBJECT_BODIES',obj),('IPC_BODIES',defs+'\n'+ipc),('VAD_BODIES',vad),('VM_BODIES',vm)):
        fixture=fixture.replace('/* @'+tag+'@ */',data)
    # The private lifetime record, when present, is taken verbatim from syscall.c.
    schema=re.search(r'^typedef struct \{[^{}]*\} vm_target_ref;',src('syscall.c'),re.M)
    if schema:fixture=fixture.replace('/* @VM_BODIES@ */',schema[0]+'\n'+vm) if '/* @VM_BODIES@ */' in fixture else fixture.replace(vm,schema[0]+'\n'+vm,1)
    generated=out/'vm_host.c';generated.write_text(fixture)
    records=[]
    def run(cmd,name):
        try:
            r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=60,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
            rc,log=r.returncode,r.stdout+r.stderr
        except subprocess.TimeoutExpired as e:rc,log=124,str(e)
        (out/(name+'.log')).write_text(log);records.append({'name':name,'command':list(map(str,cmd)),'exit':rc})
        print(name,rc,log[-3000:],flush=True);return rc
    for cc in (('gcc',) if args.red else ('gcc','clang')):
        exe=out/('vm-'+cc)
        flags=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'] if cc=='clang' else []
        cmd=[cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',*flags,'-I',out,'-I',snap/'shizukudos/kernel64',generated,'-o',exe]
        if not run(cmd,'compile-'+cc):run([exe],'run-'+cc)
    if not args.red:
        flags=None
        for node in ast.parse(sources[ROOT/'shizukudos/kbuild.py']).body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='K64_FLAGS' for t in node.targets):flags=ast.literal_eval(node.value)
        if not flags:raise RuntimeError('production K64 flags missing')
        for cc in ('gcc','clang'):
            effective=[x for x in flags if not(cc=='clang' and x=='-fno-tree-loop-distribute-patterns')]
            for profile in ('supervisor','standalone'):
                run([cc,*effective,*(['-DSHZ_STANDALONE'] if profile=='standalone' else []),'-I',snap/'shizukudos','-I',snap/'shizukudos/kernel64','-c',snap/'shizukudos/kernel64/syscall.c','-o',out/(cc+'-'+profile+'.o')],cc+'-'+profile)
    stable=all(p.read_bytes()==data for p,data in sources.items())
    allocated=sum(p.stat().st_blocks*512 for p in out.rglob('*') if p.is_file())
    passed=stable and allocated<=LIMIT and len(records)==(2 if args.red else 8) and all(r['exit']==0 for r in records)
    receipt={'passed':passed,'source_stable':stable,'output_allocated_bytes':allocated,'output_limit_bytes':LIMIT,'records':records,
             'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(d).hexdigest() for p,d in sources.items()},
             'generated_sha256':hashlib.sha256(fixture.encode()).hexdigest(),
             'scope':'UP Kernel64 permission/admission/lifetime with controlled VAD results; no allocator/guest/native Windows98 acceptance'}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
