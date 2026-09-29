#!/usr/bin/env python3
"""Build/audit original NTWAPP.EXE. No VM, app execution or downloads."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BUILD=HERE.parent/'build/native_runner/app_probe'
SOURCES=('platform/win98lab/app_probe/probe.c','platform/win98lab/app_probe/mock.h',
         'platform/win98lab/app_probe/build.py','platform/win98lab/app_probe/test.py',
         'platform/win98lab/app_probe/test.c','platform/win98lab/app_probe/README.md',
         'ntwin32/prepare.py')
IMPORTS={
 'KERNEL32.DLL':set('CloseHandle CreateFileA CreateProcessA ExitProcess FlushFileBuffers GetExitCodeProcess GetLastError GetModuleFileNameA GetTickCount GetVersionExA SetErrorMode SetLastError TerminateProcess WaitForSingleObject WriteFile'.split()),
 'USER32.DLL':set('EnumWindows GetClassNameA GetWindowTextA GetWindowThreadProcessId IsWindowVisible PostMessageA'.split())}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_map():
    return {name:sha(ROOT/name) for name in SOURCES}


def build(output=None,cd_source=False):
    output=Path(output) if output is not None else BUILD/('cd' if cd_source else 'disk')
    output.mkdir(parents=True,exist_ok=True)
    before=source_map()
    receipt_path=output/'build-result.json'
    receipt_path.unlink(missing_ok=True)
    artifact=output/'NTWAPP.EXE';temporary=output/'NTWAPP.EXE.tmp'
    command=['i686-w64-mingw32-gcc','-std=c11','-Os','-Wall','-Wextra','-Werror',
             '-march=i486','-mno-sse','-mno-sse2','-mno-mmx','-msoft-float',
             '-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-stack-arg-probe',
             '-fno-ident','-fno-asynchronous-unwind-tables','-nostdlib',
             '-Wl,--subsystem,console:4.10','-Wl,--major-os-version,4',
             '-Wl,--minor-os-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat',
             '-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-Wl,--entry,_mainCRTStartup',
             '-Wl,--strip-all',*(['-DNTWAPP_CD_SOURCE'] if cd_source else []),
             str(HERE/'probe.c'),'-lkernel32','-luser32','-o',str(temporary)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
    (output/'build.log').write_text(' '.join(command)+'\n'+result.stdout+result.stderr)
    result.check_returncode()
    spec=importlib.util.spec_from_file_location('ntwapp_pe',ROOT/'ntwin32/prepare.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    pe=module.PE(temporary.read_bytes())
    if (pe.u16(pe.opt+68)!=3 or (pe.u16(pe.opt+48),pe.u16(pe.opt+50))!=(4,10)
        or (pe.u16(pe.opt+40),pe.u16(pe.opt+42))!=(4,10)
        or pe.u16(pe.pe+22)&0x2000 or pe.u16(pe.opt+70)&0xc140 or not pe.u32(pe.opt+16)):
        raise ValueError('expected PE32 console4.10 without modern DLL characteristics')
    pe.offset(pe.u32(pe.opt+16))
    for index in (0,4,9,10,13,14):
        if any(pe.directory(index)):raise ValueError('unexpected exports/security/TLS/load-config/delay/CLR directory')
    imports={}
    for descriptor in pe.imports():
        dll=descriptor['dll'].upper();names=[item[1] for item in descriptor['entries']]
        if dll in imports or dll not in IMPORTS or set(names)!=IMPORTS[dll] or len(names)!=len(set(names)):
            raise ValueError('imports differ from the exact classic API allowlist')
        imports[dll]=sorted(names)
    if set(imports)!=set(IMPORTS):raise ValueError('missing import descriptor')
    if source_map()!=before:raise ValueError('sources changed during build')
    temporary.replace(artifact)
    receipt={'schema':'ntw.app_probe.build.v1','passed':True,'artifact':artifact.name,
             'sha256':sha(artifact),'bytes':artifact.stat().st_size,'sources_sha256':before,
             'build_log_sha256':sha(output/'build.log'),'imports':imports,
             'machine':'i386','cpu':'i486, no SSE/MMX, soft-float','subsystem':'console4.10',
             'crt_linked':False,'kernelex_linked':False,'guest_executed':False,
             'native_execution_verified':False,'app_executed':False,
             'application_source':'readonly-cd' if cd_source else 'guest-disk',
             'application_path':r'D:\CHROME\CHROME.EXE' if cd_source else r'C:\CHROMIUM\CHROME.EXE',
             'application_directory':r'D:\CHROME' if cd_source else r'C:\CHROMIUM',
             'compiler':subprocess.check_output([command[0],'--version'],text=True).splitlines()[0]}
    receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--cd-source',action='store_true',help='Build for fixed D:\\CHROME; copy only this observer to C:\\NTWLAB')
    args=parser.parse_args();print(json.dumps(build(args.output,args.cd_source),indent=2,sort_keys=True))
