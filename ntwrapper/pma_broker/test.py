#!/usr/bin/env python3
"""Fresh portable PMA broker evidence. No native guest/load/installation.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,subprocess,sys,os
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
OUT=ROOT/'build/pma-broker'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def hashes():
    paths=list(HERE.rglob('*'))+list((ROOT/'shizukudos/abi').glob('*.h'))+[ROOT/'shizukudos/pma_bridge/service.h']
    return {str(p.relative_to(ROOT)):digest(p) for p in paths if p.is_file() and '__pycache__' not in p.parts}
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    receipt=OUT/'result.json'
    if receipt.exists():receipt.rename(OUT/('result-'+stamp+'.json'))
    log=OUT/'test.log'
    if log.exists():log.rename(OUT/('test-'+stamp+'.log'))
    before=hashes();results=[];passed=True
    flags=['-std=c11','-Wall','-Wextra','-Werror','-Wpedantic','-Wconversion','-Wshadow']
    c=[str(HERE/'broker.c'),str(HERE/'tests/test_broker.c')]
    commands=[['gcc',*flags,*c,'-o',str(OUT/'gcc')],[str(OUT/'gcc')],
              ['clang',*flags,'-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',*c,'-o',str(OUT/'asan')],
              [str(OUT/'asan')]]
    for target,march in [('i386-unknown-none-elf','i486'),('x86_64-unknown-none-elf','x86-64')]:
        native=['clang','--target='+target,'-march='+march,*flags,'-Oz','-ffreestanding','-fno-builtin','-fno-pic','-fno-pie','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-sse','-mno-mmx','-msoft-float']
        if target.startswith('i386'):native+=['-mstack-alignment=4']
        for source in ['broker.c','tests/layout.c']:
            commands.append([*native,'-c',str(HERE/source),'-o',str(OUT/(march+'-'+Path(source).stem+'.o'))])
    for command in commands:
        env=os.environ.copy();env['ASAN_OPTIONS']='detect_leaks=1:abort_on_error=1';env['UBSAN_OPTIONS']='halt_on_error=1'
        result=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True)
        results.append({'command':command,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        with log.open('a') as f:f.write(json.dumps(results[-1])+'\n')
        print(result.stdout,end='');print(result.stderr,end='',file=sys.stderr)
        if result.returncode:passed=False;break
    after=hashes();unchanged=before==after;passed=passed and unchanged
    report={'utc_start':stamp,'utc_end':datetime.now(timezone.utc).isoformat(),'passed':passed,'source_sha256':before,'inputs_unchanged':unchanged,'commands':results,'scope':'portable production broker + production PMA service/ring + freestanding layouts','actual_windows_vmm':False,'native_event_delivery':False,'linked_vxd':False}
    receipt.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS' if passed else 'FAIL',receipt)
    return 0 if passed else 1
if __name__=='__main__':sys.exit(main())
