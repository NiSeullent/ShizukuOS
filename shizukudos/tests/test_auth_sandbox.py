#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual authority admission for a fresh anonymous sandbox before enrollment."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
CONTROLS=r'''
int main(void){
    process_t caller={.used=1,.pid=4},low={.used=1,.pid=8};
    shz_auth_reply reply;shz_subject sandbox={.integrity=0x1000,.flags=SHZ_SUBJECT_SANDBOX,.auth_id=0x4e7};
    unsigned checks=0,failures=0;
    #define CHECK(expr) do{checks++;if(!(expr)){failures++;fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#expr);}}while(0)
    CHECK(!call(&caller,SHZ_AUTH_QUERY,0,&reply)&&!reply.accounts);
    CHECK(!bind(&low,&sandbox));
    CHECK(shz_auth_path_access(&caller,"C:\\SHZ\\SYS64\\public.dll",1));
    CHECK(shz_auth_path_access(&low,"C:\\SHZ\\SYS64\\public.dll",0));
    CHECK(!shz_auth_path_access(&low,"C:\\SHZ\\SYS64\\public.dll",1));
    CHECK(!shz_auth_special_allowed(&low,0x50u));
    CHECK(!shz_auth_special_allowed(&low,OB_NPIPE));
    CHECK(!shz_auth_syscall_allowed(&low,SYS_NtShzBlkRead));
    CHECK(!shz_auth_syscall_allowed(&low,SYS_NtLoadDriver));
    CHECK(!shz_auth_syscall_allowed(&low,SYS_NtSetValueKey));
    CHECK(!shz_auth_syscall_allowed(&low,SYS_NtUserClipboard));
    for(unsigned n=0x80;n<=0x8f;n++){CHECK(!shz_auth_syscall_allowed(&low,n));CHECK(shz_auth_syscall_allowed(&caller,n));}
    CHECK(shz_auth_syscall_allowed(&low,SYS_NtShzRandom));
    char regular[80]="event",private_name[80]="event";
    CHECK(!shz_auth_object_name(&caller,regular,sizeof regular));
    CHECK(!shz_auth_object_name(&low,private_name,sizeof private_name));
    CHECK(strcmp(regular,private_name)&&private_name[0]=='@');
    CHECK(!shz_auth_process_access(&low,&caller));
    CHECK(!shz_auth_gui_take_entry(&low));
    CHECK(!authority.count);shz_auth_process_gone(&low);
    printf("pre-enrollment sandbox: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--label',default='current')
    args=parser.parse_args();out=ROOT/'build/fd5c2-sandbox'/args.label
    if out.exists():parser.error('fresh output label required')
    path=ROOT/'shizukudos/tests/test_auth_admission.py'
    spec=importlib.util.spec_from_file_location('auth_admission_source_capture',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    sources=module.capture();sources[Path(__file__).resolve().relative_to(ROOT)]=Path(__file__).read_bytes()
    fixture=ROOT/'shizukudos/tests/test_auth_kernel.c'
    unit_data=sources[fixture.relative_to(ROOT)].decode().split('int main(void){',1)[0]+CONTROLS
    snap=out/'source'
    for rel,data in sources.items():
        target=snap/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    unit=snap/fixture.relative_to(ROOT);unit.write_text(unit_data);results=[]
    for cc in ('gcc','clang'):
        exe=out/cc;flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror']
        if cc=='clang':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
        command=[cc,*flags,str(unit),str(snap/'shizukudos/kernel64/auth_core.c'),'-o',str(exe)]
        compiled=subprocess.run(command,text=True,capture_output=True,timeout=60)
        (out/(cc+'-compile.log')).write_text(compiled.stdout+compiled.stderr);compiled.check_returncode()
        run=subprocess.run([str(exe)],text=True,capture_output=True,timeout=30,
            env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
        (out/(cc+'-run.log')).write_text(run.stdout+run.stderr);print(cc,run.stdout+run.stderr,end='',flush=True)
        results.append({'compiler':cc,'run_exit':run.returncode,'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest()})
    stable=all((ROOT/rel).read_bytes()==data for rel,data in sources.items())
    receipt={'source_sha256':{str(rel):hashlib.sha256(data).hexdigest() for rel,data in sources.items()},
        'source_stable':stable,'results':results,'scope':'actual pre-enrollment sandbox admission, controlled IRQ/token/filesystem/loader boundaries; no native runtime'}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    raise SystemExit(0 if stable and all(r['run_exit']==0 for r in results) else 1)

if __name__=='__main__':main()
