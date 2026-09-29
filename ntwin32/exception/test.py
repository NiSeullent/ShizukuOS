#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-only ReactOS-reference exception-core tests; outputs default to RAM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
NAMES=('veh.c','veh.h','test_veh.c','test.py','README.md','PROVENANCE.md',
       'NATIVE_BINDING.md','provenance.json','COPYING.ReactOS')


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sources():return {name:sha(HERE/name) for name in NAMES}


def run(command,log,environment=None):
    result=subprocess.run(command,capture_output=True,text=True,timeout=90,env=environment)
    with log.open('a') as f:f.write(' '.join(command)+'\n'+result.stdout+result.stderr)
    result.check_returncode()
    if result.stderr:raise ValueError('unexpected compiler/sanitizer/runtime diagnostic')
    return result.stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    out=args.output or Path(tempfile.mkdtemp(prefix='ntw-exception-',dir='/dev/shm'))
    out.mkdir(parents=True,exist_ok=True)
    before=sources();(out/'test-result.json').unlink(missing_ok=True)
    if sha(HERE/'COPYING.ReactOS')!='5dd08524bb37f07b4a6f548439ffcd8ec0444bc0ae92e0fe929ea70185cdbc62':
        raise ValueError('upstream license text changed')
    variants=[]
    for name,compiler,extra in (('gcc','gcc',[]),('clang','clang',[]),
        ('asan_ubsan','clang',['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])):
        exe=out/('test-'+name);log=out/(name+'.log');log.write_text('')
        command=[compiler,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wpedantic',
                 '-pthread',*extra,str(HERE/'veh.c'),str(HERE/'test_veh.c'),'-o',str(exe)]
        run(command,log)
        environment=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
        counts=json.loads(run([str(exe)],log,environment))
        if (counts.get('passed') is not True or counts['allocations']!=counts['releases']
                or counts['stress_threads']!=4 or counts['stress_iterations_each']!=500
                or counts['checks']<10000 or counts['callbacks']<2000):
            raise ValueError('host lifetime model did not complete')
        variants.append({'name':name,'counts':counts,'log_sha256':sha(log),'binary_sha256':sha(exe)})
    objects=[]
    for compiler in ('gcc','clang'):
        obj=out/(compiler+'-i486.o');log=out/(compiler+'-i486.log');log.write_text('')
        command=[compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror','-m32','-march=i486',
                 '-mno-sse','-mno-sse2','-mno-mmx','-msoft-float','-ffreestanding',
                 '-fno-builtin','-fno-stack-protector','-fno-pie','-fno-pic',
                 '-Wframe-larger-than=2048','-fstack-usage','-c',str(HERE/'veh.c'),'-o',str(obj)]
        run(command,log)
        undefined=run(['nm','-u',str(obj)],log)
        if undefined.strip():raise ValueError('freestanding core has unresolved helpers')
        objects.append({'compiler':compiler,'sha256':sha(obj),'bytes':obj.stat().st_size,
                        'undefined_symbols':[],'log_sha256':sha(log)})
    if sources()!=before:raise ValueError('sources changed during test')
    receipt={'schema':'ntw.exception.reference-port.host.v1','passed':True,
             'native_execution_verified':False,'win98_veh_compatible':False,
             'sources_sha256':before,'variants':variants,'freestanding_i486':objects,
             'reactos_commit':'cae3c053d47024545c773148185319075eae0202',
             'wine_comparison_commit':'4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf',
             'toolchains':{tool:subprocess.check_output([tool,'--version'],text=True,timeout=10).splitlines()[0]
                           for tool in ('gcc','clang','nm')},
             'output':str(out)}
    (out/'test-result.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    print(json.dumps(receipt,indent=2,sort_keys=True))


if __name__=='__main__':main()
