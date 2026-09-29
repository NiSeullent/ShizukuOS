#!/usr/bin/env python3
"""Host-only synthetic WinAPI tests and static import audit for NTWAPP."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import build


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--cd-source',action='store_true')
    args=parser.parse_args()
    out=args.output if args.output is not None else build.BUILD/('cd' if args.cd_source else 'disk')
    out.mkdir(parents=True,exist_ok=True)
    (out/'host-tests.json').unlink(missing_ok=True)
    sources=build.source_map();variants=[]
    for name,compiler,extra in (('gcc','gcc',[]),('clang','clang',[]),
       ('asan_ubsan','clang',['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])):
        exe=out/('test-'+name)
        command=[compiler,'-std=c11','-O1','-Wall','-Wextra','-Werror','-Wpedantic',
                 '-DNTWAPP_TEST',*(['-DNTWAPP_CD_SOURCE'] if args.cd_source else []),
                 '-I',str(build.HERE),*extra,str(build.HERE/'probe.c'),
                 str(build.HERE/'test.c'),'-o',str(exe)]
        compiled=subprocess.run(command,capture_output=True,text=True,timeout=60)
        log=out/(name+'.log')
        log.write_text(' '.join(command)+'\n'+compiled.stdout+compiled.stderr)
        compiled.check_returncode()
        environment=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
        tested=subprocess.run([str(exe)],capture_output=True,text=True,timeout=90,env=environment)
        with log.open('a') as f:f.write(tested.stdout+tested.stderr)
        tested.check_returncode()
        if tested.stderr:raise ValueError('unexpected host/sanitizer diagnostics')
        counts=json.loads(tested.stdout)
        if counts.get('passed') is not True or any(type(counts.get(k)) is not int or counts[k]<=0 for k in ('checks','scenarios','injected_faults')):
            raise ValueError('invalid model result')
        variants.append({'name':name,'counts':counts,'log_sha256':build.sha(log),
                         'binary_sha256':build.sha(exe),'compiler':subprocess.check_output([compiler,'--version'],text=True).splitlines()[0]})
    if any(v['counts']!=variants[0]['counts'] for v in variants):raise ValueError('variant disagreement')
    receipt=build.build(out,args.cd_source);binary=(out/'NTWAPP.EXE').read_bytes();receipt_bytes=(out/'build-result.json').read_bytes()
    if (build.source_map()!=sources or receipt['sources_sha256']!=sources or
        build.sha(out/'NTWAPP.EXE')!=receipt['sha256'] or len(binary)!=receipt['bytes']):
        raise ValueError('source/artifact changed across host tests/build')
    record={'schema':'ntw.app_probe.host.v1','passed':True,'guest_executed':False,
            'native_execution_verified':False,'app_executed':False,'fixture':'synthetic WinAPI callbacks',
            'sources_sha256':sources,'artifact_sha256':receipt['sha256'],
            'application_source':receipt['application_source'],
            'application_path':receipt['application_path'],
            'application_directory':receipt['application_directory'],
            'build_receipt_sha256':build.hashlib.sha256(receipt_bytes).hexdigest(),'variants':variants}
    (out/'host-tests.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps(record,indent=2,sort_keys=True))


if __name__=='__main__':main()
