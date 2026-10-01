#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a closed same-C WASM design/game preview and its corresponding source ZIP."""
import argparse
import datetime
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
OWN=ROOT/'shizukudos/dead_screen/wasm'
EXPORTS=['ds_preview_init','ds_preview_input','ds_preview_tick','ds_preview_render','ds_preview_pixels',
         'ds_preview_width','ds_preview_height','ds_preview_trace','ds_preview_trace_len','ds_preview_mode',
         'ds_preview_score','ds_preview_fallback','ds_preview_set_size']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def pin(p):
    p=Path(p);return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',required=True,type=Path);a=ap.parse_args()
    out=a.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'build'):raise SystemExit('require NEW output beneath build/')
    out.mkdir(parents=True)
    logs=[];tools={};sources={};runtime={};artifacts={};result={'status':'FAIL','native_execution':False,'app_success':False}
    def run(cmd,label):
        cmd=[str(x) for x in cmd];p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,cwd=ROOT)
        f=out/(str(len(logs)).zfill(2)+'-'+label+'.log');f.write_bytes(p.stdout)
        logs.append({**pin(f),'exit_code':p.returncode,'command':cmd})
        if p.returncode:raise RuntimeError(label+' failed '+str(p.returncode)+': '+p.stdout.decode(errors='replace')[-4000:])
        return p.stdout.decode(errors='replace')
    try:
        for name in ('clang','wasm-ld','node','python3'):
            p=Path(shutil.which(name) or '')
            if not p.is_file():raise RuntimeError('missing installed tool '+name+'; no installation attempted')
            tools[name]=pin(p.resolve());run([p,'--version'],name+'-version')
            try:
                libs=run(['ldd',p.resolve()],name+'-runtime')
                for path in re.findall(r'(/[^\s()]+)',libs):
                    q=Path(path)
                    if q.is_file():runtime[str(q.resolve())]=pin(q.resolve())
            except RuntimeError:
                if name!='wasm-ld':raise
        relatives=['LICENSE','shizukudos/dead_screen/dead_screen.c','shizukudos/dead_screen/dead_screen.h',
                   'shizukudos/dead_screen/render.c','shizukudos/supervisor/src/font8x8_basic.h']
        relatives += [str(p.relative_to(ROOT)) for p in sorted(OWN.iterdir()) if p.is_file()]
        frozen=out/'source'
        for rel in relatives:
            p=ROOT/rel;sources[rel]=pin(p);d=frozen/rel;d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,d)
        core=frozen/'shizukudos/dead_screen';adapter=core/'wasm/wasm.c'
        module=out/'dead-screen-demo.wasm'
        cmd=['clang','--target=wasm32','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin',
             '-fno-stack-protector','-fno-ident','-nostdlib','-Wl,--no-entry','-Wl,--export-memory','-Wl,--stack-first',
             '-Wl,-z,stack-size=65536','-Wl,--initial-memory=4194304','-Wl,--max-memory=4194304','-Wl,--strip-all',
             '-MD','-MF',out/'wasm.d',*[f'-Wl,--export={e}' for e in EXPORTS],
             core/'dead_screen.c',core/'render.c',adapter,'-o',module]
        run(cmd,'wasm-compile')
        if module.read_bytes()[:8]!=b'\0asm\x01\0\0\0':raise RuntimeError('not a version-1 WASM module')
        test=json.loads(run(['node',frozen/'shizukudos/dead_screen/wasm/wasm_test.js',module],'actual-wasm-controls'))
        # Wasm compilers use installed freestanding headers; freeze actual last
        # translation-unit dependencies plus the complete closed source subset.
        headers={}
        for token in (out/'wasm.d').read_text().replace('\\\n',' ').split(':',1)[1].split():
            p=Path(token)
            if p.is_file():headers[str(p)]=pin(p)
        (out/'compiler-inputs.json').write_text(json.dumps(headers,indent=2)+'\n')
        members={rel:(frozen/rel).read_bytes() for rel in relatives}
        members['artifact/dead-screen-demo.wasm']=module.read_bytes()
        package_manifest={'scope':'Design/game preview; synthetic example trace; no native OS execution',
            'module':{'bytes':module.stat().st_size,'sha256':sha(module)},'exports':['memory',*EXPORTS],
            'format':'RGBA8 alpha255; 640x480 or optional 800x600; fixed4MiB memory; no imports/heap',
            'members':{name:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in sorted(members.items())},
            'compiler':tools,'compiler_runtime':runtime,'compile_command':[str(x) for x in cmd]}
        members['MANIFEST.json']=(json.dumps(package_manifest,ensure_ascii=False,indent=2)+'\n').encode()
        archive=out/'dead-screen-demo-source-2026.10.01.zip'
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for name,data in sorted(members.items()):
                info=zipfile.ZipInfo(name,(2026,10,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
                z.writestr(info,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
        with zipfile.ZipFile(archive) as z:
            if z.namelist()!=sorted(members) or z.testzip():raise RuntimeError('source ZIP structure/CRC failure')
            for name,data in members.items():
                if z.read(name)!=data:raise RuntimeError('source ZIP member differs '+name)
        checksum=out/(archive.name+'.sha256');checksum.write_text(sha(archive)+'  '+archive.name+'\n')
        for rel,p in sources.items():
            if sha(ROOT/rel)!=p['sha256'] or sha(frozen/rel)!=p['sha256']:raise RuntimeError('source changed '+rel)
        for p in [*tools.values(),*runtime.values()]:
            if sha(p['path'])!=p['sha256']:raise RuntimeError('compiler/runtime changed '+p['path'])
        for p in (module,archive,checksum,out/'compiler-inputs.json'):artifacts[p.name]=pin(p)
        result.update(status='PASS',actual_wasm_controls=test,wasm=pin(module),source_zip=pin(archive),checksum=pin(checksum),
                      source_zip_members={name:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in sorted(members.items())},
                      byte_format='RGBA8 alpha255',memory_bytes=4194304,abi=['memory',*EXPORTS],
                      scope='explicit synthetic design/game preview; native Kernel64 acceptance remains pending')
    except Exception as exc:result['failure']=str(exc)
    manifest={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sources':sources,'tools':tools,
              'tool_runtime':runtime,'logs':logs,'artifacts':artifacts,'side_effects':'only new private build files; no site/VM/global/package changes'}
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');result['manifest']=pin(out/'manifest.json')
    (out/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'result':pin(out/'result.json'),'failure':result.get('failure')}))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
