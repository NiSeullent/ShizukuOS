#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze one classic observer; leaves exact CHRLAB plan/default caps unchanged."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import pefile

ROOT=Path(__file__).resolve().parents[2]
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    out=args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'build'):parser.error('Absent private build directory required')
    if shutil.disk_usage(ROOT).free<17*1024**3+512*1024**2:parser.error('Unchanged17GiB+512MiB floor required')
    compiler=shutil.which('i686-w64-mingw32-gcc')
    if not compiler:parser.error('Existing native compiler required')
    helper=ROOT/'build/chromium-large-native-probe-20261001T0036-v2/CHLWAIT.EXE'
    if helper.stat().st_size!=8951 or sha(helper)!='034fdb8f3a1a0e1f83471d6606f092892db622ae862553a3a9bbfd7b50dcad2c':parser.error('Exact unchanged inner helper required')
    names=['ntwin32/native_loader/chromium_outer_wait.c','ntwin32/native_loader/build_chromium_outer_wait.py',
        'ntwin32/process_exit/original_kernel.h','ntwin32/process_exit/original_kernel_win98_v3.c',
        'ntwin32/process_exit/main_image.h','ntwin32/process_exit/main_image.c',
        'ntwin32/process_exit/win98_guard.h','ntwin32/process_exit/win98_guard.c',
        'ntwin32/process_exit/win98_export.h','ntwin32/process_exit/win98_export.c',
        'shizukufs/v1/tools/sha256.c','shizukufs/v1/tools/sha256.h',
        'platform/freestanding/memory.c','platform/freestanding/memory.h',
        'benchmarks/win98se-ko-oem-native-exports-v1.json']
    pins={n:sha(ROOT/n) for n in names};out.mkdir(parents=True)
    for name in names:
        dest=out/'frozen'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
        if sha(dest)!=pins[name]:raise ValueError('Source changed while freezing')
    frozen=out/'frozen';artifact=out/'CHLRUN.EXE'
    command=[compiler,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
        '-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-stack-protector','-nostdlib',
        '-Wl,--no-insert-timestamp','-Wl,--entry,_entry@0','-Wl,--subsystem,windows:4.10',
        '-Wl,--major-os-version,4','-Wl,--minor-os-version,0','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat',
        '-Xlinker','--stack','-Xlinker','2097152,4096','-I',str(frozen/'shizukufs/v1/tools'),
        *[str(frozen/n) for n in names if n.endswith('.c')],'-o',str(artifact),'-lkernel32','-lgcc']
    receipt={'status':'FAIL','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sources':pins,
        'compiler':{'path':compiler,'sha256':sha(compiler)},'command':command,'native_executed':False,
        'application_success':False,'inner_helper':{'path':str(helper),'bytes':8951,'sha256':sha(helper)},
        'scope':'Fresh outer entry/CreateProcess/native wait/actual inner observer OSexit diagnosis only. No Chromium entry/TLS/import calls; exact3CHRLABstager/defaultcaps unchanged; ownouterOSexit notproven.'}
    try:
        with (out/'build.log').open('wb') as log:
            result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=log,timeout=120)
        receipt['compile_exit']=result.returncode
        if result.returncode:raise ValueError('Native compile failed')
        oem=json.loads((frozen/names[-1]).read_text())['dlls'];imports={}
        with pefile.PE(str(artifact)) as image:
            o=image.OPTIONAL_HEADER
            if (image.FILE_HEADER.Machine,o.Magic,o.Subsystem,o.MajorSubsystemVersion,o.MinorSubsystemVersion)!=(0x14c,0x10b,2,4,10):raise ValueError('Classic GUI4.10 required')
            if image.is_dll() or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)):raise ValueError('Unexpected runtime directories')
            for descriptor in image.DIRECTORY_ENTRY_IMPORT:
                dll=descriptor.dll.decode().upper();symbols=[]
                for item in descriptor.imports:
                    if not item.name or item.name.decode() not in oem.get(dll,[]):raise ValueError('Outside actual OEM exports')
                    symbols.append(item.name.decode())
                imports[dll]=symbols
            if set(imports)!={'KERNEL32.DLL'}:raise ValueError('Only actual native Kernel32 imports required')
        if any(sha(ROOT/n)!=pin or sha(frozen/n)!=pin for n,pin in pins.items()):raise ValueError('Source changed during build')
        receipt.update(status='HOST_BUILD_PASS_NATIVE_PENDING',artifact={'path':str(artifact),'bytes':artifact.stat().st_size,'sha256':sha(artifact),'imports':imports,'native_import_gate':'PASS'})
    except (OSError,ValueError,subprocess.TimeoutExpired,pefile.PEFormatError) as error:receipt['error']=str(error)
    p=out/'result.json';p.write_text(json.dumps(receipt,indent=2)+'\n')
    if receipt['status']=='HOST_BUILD_PASS_NATIVE_PENDING':
        item=receipt['artifact'];manifest={'schema':1,'kind':'isolated-guest-file-inputs',
            'inputs':[{'source':item['path'],'guest':r'C:\VXDLAB\CHLRUN.EXE','bytes':item['bytes'],'sha256':item['sha256']}],
            'outputs':[r'C:\VXDLAB\CHLRUN.LOG'],'backups':[],
            'source_receipts':[{'path':str(p),'sha256':sha(p)}],'command':r'C:\VXDLAB\CHLRUN.EXE',
            'scope':receipt['scope'],'next_stage':'Apply exact unchanged3CHRLABplan sequentially on this same ownquiescent clone before boot; jointallocation reserve/provenance required.'}
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'result':str(p),'sha256':sha(p),'error':receipt.get('error')}))
    return 0 if receipt['status']=='HOST_BUILD_PASS_NATIVE_PENDING' else 1
if __name__=='__main__':raise SystemExit(main())
