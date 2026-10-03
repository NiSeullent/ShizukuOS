#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build an owner-nonce-bound readonly Win98 PE32 observer from captured headers/sources.

No guest runs. Original source/header/tool/import-library read leases remain
held through compilation and receipt readback. Microsoft guest files are absent.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('enum_observer_constructor',ROOT/'shizukudos/win98_boot/prepare_replacement.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
FLAGS=['-std=c11','-Os','-Wall','-Wextra','-Werror','-march=i486','-mno-sse','-mno-mmx','-msoft-float',
       '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-use-linker-plugin','-nostdlib']
LINK=['-Wl,--entry,_mainCRTStartup','-Wl,--subsystem,console:4.10',
      '-Wl,--major-os-version,4,--minor-os-version,10,--disable-dynamicbase,--disable-nxcompat,--no-insert-timestamp']

def capture(held,pin,target):
    import os
    row=held[pin['path']];row['checkpoint']();raw=os.pread(row['fd'],pin['bytes'],0)
    r.need(len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],'held capture bytes differ')
    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);row['checkpoint']()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--private-out',type=Path,required=True);a=p.parse_args()
    out=r.safe_path(a.private_out);r.private_output(out)
    r.need(not out.exists() and out.parent.is_dir(),'fresh existing-parent private output required')
    gcc=Path(shutil.which('i686-w64-mingw32-gcc')).resolve()
    def query(option):return Path(subprocess.check_output([str(gcc),option],text=True).strip()).resolve()
    tools={'gcc':gcc,**{name:query('-print-prog-name='+name) for name in ('cc1','as','ld','collect2')}}
    imports={name:query('-print-file-name='+name) for name in ('libadvapi32.a','libkernel32.a')}
    internal=query('-print-file-name=include');mingw=imports['libkernel32.a'].parent.parent/'include'
    r.need(internal.is_dir() and mingw.is_dir(),'actual selected compiler/header roots required')
    source=HERE/'observer.c';producer_sources=(Path(__file__).resolve(),source,Path(r.__file__).resolve())
    originals=[r.local_pin(path) for path in (*producer_sources,*tools.values(),*imports.values())]
    commands=[]
    with r.leased_inputs(originals) as held:
        def check():
            for row in held.values():row['checkpoint']()
        def run(argv,read=False):
            commands.append([str(x) for x in argv]);check()
            result=subprocess.check_output(commands[-1],text=True) if read else subprocess.run(commands[-1],check=True)
            check();return result
        deps=run([gcc,*FLAGS,'-M','-MT','observer',source],True).replace('\\\n',' ')
        headers={Path(name).resolve() for name in shlex.split(deps.split(':',1)[1])}-{source.resolve()}
        header_pins=[r.local_pin(path) for path in sorted(headers)]
        held.add_inputs(header_pins);r.capacity(out.parent,sum(row['bytes'] for row in header_pins)+(4<<20),1<<20)
        out.mkdir(mode=0o700);mapping={}
        for row in header_pins:
            path=Path(row['path'])
            if path.is_relative_to(internal):relative=Path('gcc')/path.relative_to(internal)
            elif path.is_relative_to(mingw):relative=Path('mingw')/path.relative_to(mingw)
            else:raise ValueError('unexpected external compiler header: '+str(path))
            target=out/'headers'/relative;capture(held,row,target);mapping[str(relative)]=row
        sources={}
        for path in producer_sources:
            row=r.local_pin(path);relative=path.relative_to(ROOT);capture(held,row,out/'source'/relative);sources[str(relative)]=row
        for name,path in imports.items():capture(held,r.local_pin(path),out/'imports'/name)
        includes=['-nostdinc','-isystem',str(out/'headers/gcc'),'-isystem',str(out/'headers/mingw')]
        captures=[r.local_pin(path) for path in out.rglob('*') if path.is_file()]
        held.add_inputs(captures)
        target=out/'BASEOBS.EXE'
        run([gcc,*FLAGS,*includes,*LINK,out/'source'/source.relative_to(ROOT),'-o',target,
             out/'imports/libadvapi32.a',out/'imports/libkernel32.a'])
        raw=target.read_bytes();r.need(raw[:2]==b'MZ' and b'PE\0\0' in raw,'actual PE32 observer required')
        result={'schema':'shizukuos.private-win98-baseline-observer-build.v1','status':'HOST_COMPILE_LINK_PASS_NOT_EXECUTED',
                'source_pins':sources,'compiler_header_pins':mapping,'tool_pins':{name:r.local_pin(path) for name,path in tools.items()},
                'import_library_pins':{name:r.local_pin(path) for name,path in imports.items()},'commands':commands,
                'artifact':r.local_pin(target),'scope':'Held C:\\BASENONC.BIN32B nonce; actual Win9x4.10 and readonly HKLM Enum Class/Driver; fresh C:\\BASEOBS.JSON.',
                'VM_executed':False,'registry_mutated':False,'default_GOP_registered':False,'Windows98_on_ShizukuDOS':False,
                'source_approval':False,'nonce_owner_verified':False,'complete_SDK_shared_library_closure':False}
        for row in captures:
            entry=held[row['path']];r.need(r.hash_fd(entry['fd'],row['bytes'],entry['checkpoint'])==row['sha256'],'captured compile input full readback differs')
        path=out/'build-result.json';path.write_text(json.dumps(result,indent=2)+'\n');check()
        r.need(json.loads(path.read_bytes())==result,'actual build receipt readback differs')
    print(json.dumps({'status':result['status'],'artifact':result['artifact'],'captured_headers':len(mapping)}))

if __name__=='__main__':main()
