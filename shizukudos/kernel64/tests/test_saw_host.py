#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual SAW/teardown bodies and inject lifecycle faults safely on host."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import subprocess

ROOT=Path(__file__).resolve().parents[3]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--no-sanitize',action='store_true',help='explicit fallback when host sanitizer runtime is absent')
    args=parser.parse_args();out=args.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    tools=runpy.run_path(str(ROOT/'shizukudos/tests/test_native_create_admission.py'))
    proc=(ROOT/'shizukudos/kernel64/proc.c').read_text()
    auth=(ROOT/'shizukudos/kernel64/sysk32_auth.c').read_text()
    bodies='\n'.join(tools['definition'](proc,name) for name in ('process_terminate','process_teardown'))
    bodies+='\n'+tools['definition'](auth,'shz_auth_saw_process_access')
    (out/'saw_process_bodies.h').write_text(bodies+'\n')
    sources=['shizukudos/kernel64/saw.c','shizukudos/kernel64/saw.h','shizukudos/kernel64/proc.c',
             'shizukudos/kernel64/proc_internal.h','shizukudos/kernel64/ldr.c','shizukudos/kernel64/autorun.c',
             'shizukudos/abi/shz_saw.h','shizukudos/kernel64/tests/test_saw_host.c']
    sources+=['shizukudos/kernel64/sysk32_auth.c','shizukudos/kernel64/auth_policy.h']
    before={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources}
    commands=[]
    def run(name,command):
        result=subprocess.run(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
        (out/(name+'.log')).write_text(result.stdout)
        commands.append({'name':name,'command':[str(c) for c in command],'exit_code':result.returncode})
        if result.returncode:raise RuntimeError(name+': '+result.stdout[-4000:])
        return result.stdout
    receipt={'status':'FAIL','source_before':before,'commands':commands,'actual_shizukuos_execution':False,
             'scope':'actual production SAW and named teardown bodies; host scheduler/VM adapters; fault injection only'}
    receipt['sanitizers_requested']=not args.no_sanitize
    try:
        compiler='gcc'
        host=out/'test_saw_host'
        run('host_compile',[compiler,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-pthread',
            *([] if args.no_sanitize else ['-fsanitize=address,undefined','-fno-omit-frame-pointer']),'-I'+str(out),
            str(ROOT/'shizukudos/kernel64/tests/test_saw_host.c'),'-o',str(host)])
        print(run('host_execute',[str(host)]),end='')
        flags=runpy.run_path(str(ROOT/'shizukudos/kbuild.py'))['K64_FLAGS']
        for unit in ('saw','proc','ldr','autorun'):
            run('native_'+unit,[compiler,*flags,'-DSHZ_STANDALONE','-c',
                str(ROOT/'shizukudos/kernel64'/f'{unit}.c'),'-o',str(out/f'{unit}.o')])
        after={s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources}
        receipt['source_after']=after
        if before!=after:raise RuntimeError('production sources changed during test epoch')
        receipt['status']='PASS';receipt['exact_extracted_bodies_sha256']=hashlib.sha256(bodies.encode()).hexdigest()
    except Exception as exc:
        receipt['error']=str(exc);raise
    finally:
        (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')

if __name__=='__main__':main()
