#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Frozen production GetContextThread rights/lifetime contracts; no VM/images.

Object/handle/ref/close/detach bodies and complete TCB/process/object/frame
schemas are unmodified production extracts. Account decisions, IRQ/current
thread and user-copy preemption are controlled platform boundaries. Native
host heap frees are used by both compiler sanitizers. Full sysk32_proc.c is
also compiled with the production normal and standalone Kernel64 flags.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from test_nt_settings import block_end, function

ROOT=Path(__file__).resolve().parents[2]
KERNEL=ROOT/'shizukudos/kernel64'
CASES=('zero','query','sync','typed','invalid','foreign','input-fault','output-fault','flags',
       'close','detach','zombie','free','reuse','owner','owner-exit',
       'pseudo-owner','pseudo-type','pseudo-null','valid','initial','masked')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--host-only',action='store_true')
    args=parser.parse_args();out=args.out.resolve()
    if out.exists():parser.error('fresh output directory required')
    out.mkdir(parents=True)
    pending=[Path(__file__).resolve(),Path(__file__).with_suffix('.c'),
             Path(__file__).with_name('test_nt_settings.py'),ROOT/'shizukudos/kbuild.py',
             KERNEL/'sysk32_proc.c',KERNEL/'objects.c',KERNEL/'ipc_core.c',KERNEL/'auth_policy.h',KERNEL/'proc.c']
    sources={}
    while pending:
        path=pending.pop().resolve()
        if path in sources:continue
        data=path.read_bytes();sources[path]=data
        if path.parent==KERNEL or path.suffix=='.h':
            pending.extend(path.parent/name.decode() for name in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"',data,re.M))
    snap=out/'frozen'
    for path,data in sources.items():
        target=snap/path.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    def source(name):return sources[KERNEL/name].decode()
    k64,internal,ipc=source('k64.h'),source('proc_internal.h'),source('ipc.h')
    thread=k64[k64.index('typedef struct thread thread_t;'):block_end(k64,k64.index('{',k64.index('struct thread {')))]+ ';\n'
    process=internal[internal.index('/* ---- virtual address descriptors ---- */'):block_end(internal,internal.index('{',internal.index('struct process {')))]+ ';\n'
    frame=k64[k64.index('struct regs {'):block_end(k64,k64.index('{',k64.index('struct regs {')))]+ ';\n'
    layout=thread+process+frame+re.search(r'^#define KSTACK_BYTES[^\n]+',k64,re.M)[0]+'\n'
    (out/'layouts.inc').write_text(layout)
    body=source('sysk32_proc.c')
    context='\n'.join(re.findall(r'^#define CTX_(?:SIZE|AMD64)[^\n]+',body,re.M))+'\n'+function(body,'put64')+'\n'+function(body,'k32_get_context_thread')
    # Candidate may reuse its existing validated pseudo-current reference helper.
    context=function(source('proc.c'),'thread_must_die')+'\n'+function(body,'ref_settings_object')+'\n'+context
    objects=source('objects.c')
    names=('ob_create','ob_ref','ob_deref','handle_insert','handle_lookup','handle_ref','handle_close','thread_object_detach')
    prod_objects='\n'.join(function(objects,n) for n in names)
    fixture=sources[Path(__file__).with_suffix('.c')].decode()
    fixture=fixture.replace('/* @OBJECT_BODIES@ */',prod_objects).replace('/* @IPC_REF_BODY@ */',function(source('ipc_core.c'),'ipc_ref_handle')).replace('/* @CONTEXT_BODY@ */',context)
    generated=out/'get_context_host.c';generated.write_text(fixture)
    results=[]
    blocked=[]
    def run(command,label,env=None):
        try:
            r=subprocess.run(list(map(str,command)),capture_output=True,text=True,timeout=60,env=env)
            rc,log=r.returncode,r.stdout+r.stderr
        except subprocess.TimeoutExpired as e:
            rc,log=124,str(e)
        (out/(label+'.log')).write_text(log)
        row={'name':label,'command':list(map(str,command)),'exit':rc};results.append(row)
        print(label,rc,log[-2400:],flush=True);return rc
    for variant,compiler,sanitized in (('gcc','gcc',False),('gcc-sanitized','gcc',True),('clang','clang',True)):
        if not shutil.which(compiler):raise RuntimeError('required compiler missing: '+compiler)
        exe=out/('get-context-'+variant)
        command=[compiler,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                 '-Wno-unused-function',*(['-fsanitize=address,undefined','-fno-sanitize-recover=all'] if sanitized else []),
                 '-fno-omit-frame-pointer','-I',out,'-I',snap/'shizukudos/kernel64',generated,'-o',exe]
        rc=run(command,'compile-'+variant)
        if rc==0:
            for case in CASES:
                run([exe,case],variant+'-'+case,dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
        elif variant=='gcc-sanitized':
            log=(out/('compile-'+variant+'.log')).read_text()
            if 'cannot find' in log and 'libasan' in log and 'libubsan' in log:
                results[-1]['blocked']='GCC sanitizer runtime linker-script targets absent'
                blocked.append(variant)
    if not args.host_only:
        flags=None
        for node in ast.parse(sources[ROOT/'shizukudos/kbuild.py']).body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='K64_FLAGS' for t in node.targets):flags=ast.literal_eval(node.value)
        if not flags:raise RuntimeError('literal production Kernel64 flags missing')
        for compiler in ('gcc','clang'):
            effective=[f for f in flags if not(compiler=='clang' and f=='-fno-tree-loop-distribute-patterns')]
            for profile in ('supervisor','standalone'):
                command=[compiler,*effective,*(['-DSHZ_STANDALONE'] if profile=='standalone' else []),
                         '-I',snap/'shizukudos','-I',snap/'shizukudos/kernel64',
                         '-c',snap/'shizukudos/kernel64/sysk32_proc.c','-o',out/(compiler+'-'+profile+'.o')]
                run(command,'freestanding-'+compiler+'-'+profile)
    stable=all(path.read_bytes()==data for path,data in sources.items())
    expected=3*(len(CASES)+1)-len(blocked)*len(CASES)+(0 if args.host_only else 4)
    passed=stable and len(results)==expected and all(r['exit']==0 or r.get('blocked') for r in results)
    receipt={'passed':passed,'source_stable':stable,'results':results,
             'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(d).hexdigest() for p,d in sources.items()},
             'selected_function_sha256':hashlib.sha256(function(body,'k32_get_context_thread').encode()).hexdigest(),
             'generated_fixture_sha256':hashlib.sha256(fixture.encode()).hexdigest(),
             'sanitizer_blocked':blocked,'complete_requested_sanitizer_coverage':not blocked,
             'scope':'UP Kernel64 rights/lifetime and full source object compilation; no guest/native Windows98/SMP acceptance'}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
