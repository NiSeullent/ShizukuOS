#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build isolated classic Win98 debugger and owned DR proof; never launch them."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
import pefile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
NPP=ROOT/'build/app-prerequisites-20260930/latest-npp-inputs/app/NPP.EXE'
NPP_SHA='986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5'
CHAINS=(bytes.fromhex('64a1180000008b40308b4068c1e8082401c3'),bytes.fromhex('64a1180000008b40308b40108b4008c1e81fc3'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def profile(path,rvas):
    with pefile.PE(str(path)) as pe:
        for rva,chain in zip(rvas,CHAINS):
            section=pe.get_section_by_rva(rva)
            if not section or section.Characteristics&0x60000000!=0x60000000 or pe.get_data(rva,len(chain))!=chain:
                raise ValueError('exact executable UCRT chain absent')
        relocs={entry.rva for block in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',()) for entry in block.entries if entry.type}
        if any(rva+2 in relocs for rva in rvas):raise ValueError('FS18 operand must not be relocated')
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':sha(path),'rvas':list(rvas)}
def declaration(name,item):
    return 'static const env_profile '+name+'={{'+','.join('0x'+item['sha256'][i:i+2] for i in range(0,64,2))+'},'+str(item['bytes'])+','+','.join(hex(rva) for rva in item['rvas'])+'};\n'
def compile_command(command,log,out,sources,commands):
    result=subprocess.run(command,stdout=log,stderr=log,cwd=ROOT,timeout=120)
    if result.returncode:
        (out/'build-result.json').write_text(json.dumps({'status':'FAIL','native_executed':False,'sources':sources,'commands':commands,'exit_code':result.returncode,'scope':'compiler failure; native acceptance unavailable'},indent=2)+'\n')
        raise subprocess.CalledProcessError(result.returncode,command)
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);args=ap.parse_args();out=args.out.resolve()
    if out.exists():ap.error('use a fresh output directory')
    cc=shutil.which('i686-w64-mingw32-gcc')
    if not cc:ap.error('existing private/session compiler required')
    if not NPP.is_file() or sha(NPP)!=NPP_SHA:ap.error('immutable official latest NPP input mismatch')
    names=('environment.h','environment.c','native.c','fixture.c','fixture.def','build.py','README.md','test.py','host_test.c')
    sources={str((HERE/name).relative_to(ROOT)):sha(HERE/name) for name in names}
    npp=profile(NPP,(0x38a901,0x38a913))
    kernel=ROOT/'build/iewebkit-win98-installed-audit-83bd/KERNEL32.DLL'
    if sha(kernel)!='6771ab74633e9de1359864bd4306a2ed669bec50de7ac9bb9978c05bf04563ca':raise ValueError('pinned licensed OEM Kernel32 mismatch')
    with pefile.PE(str(kernel)) as pe:
        debugbreak=[s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name==b'DebugBreak']
        if len(debugbreak)!=1 or pe.get_data(debugbreak[0],2)!=b'\xcc\xc3':raise ValueError('native DebugBreak export mismatch')
    out.mkdir(parents=True)
    flags=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-stack-protector',
           '-ffunction-sections','-fdata-sections','-nostdlib','-Wl,--gc-sections','-Wl,--entry,_entry@0','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,0',
           '-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp']
    fixture=out/'ENVFIX.EXE';debugger=out/'NTWPENV.EXE';commands=[flags+['-o',str(fixture),str(HERE/'fixture.c'),str(HERE/'fixture.def'),'-lkernel32','-lgcc']]
    with (out/'build.log').open('w') as log:
        compile_command(commands[0],log,out,sources,commands)
        with pefile.PE(str(fixture)) as pe:
            exports={s.name.decode():s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
        if set(exports)!={'env_verifier','env_secure'}:raise ValueError('owned fixture exports changed')
        own=profile(fixture,(exports['env_verifier'],exports['env_secure']))
        header=out/'profiles.h';header.write_text('/* Build-only full-file identities; generated from untouched inputs. */\n'+declaration('fixture_profile',own)+declaration('npp_profile',npp)+'static const uint32_t kernel_debugbreak_rva='+hex(debugbreak[0])+';\n')
        commands.append(flags+['-I',str(out),'-o',str(debugger),str(HERE/'native.c'),str(HERE/'environment.c'),'-lkernel32','-lgcc'])
        compile_command(commands[-1],log,out,sources,commands)
    oem=json.loads((ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())['dlls'];artifacts=[]
    for path in (debugger,fixture):
        with pefile.PE(str(path)) as pe:
            opt=pe.OPTIONAL_HEADER
            if pe.is_dll() or (pe.FILE_HEADER.Machine,opt.Magic,opt.Subsystem,opt.MajorSubsystemVersion,opt.MinorSubsystemVersion)!=(0x14c,0x10b,2,4,10):raise ValueError('classic image profile mismatch')
            if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)) or opt.DllCharacteristics&0x140:raise ValueError('unexpected modern runtime requirement')
            imports={}
            for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
                dll=descriptor.dll.decode().upper();symbols=[]
                for item in descriptor.imports:
                    if not item.name or dll!='KERNEL32.DLL' or item.name.decode() not in oem[dll]:raise ValueError('outside exact classic OEM imports')
                    symbols.append(item.name.decode())
                imports[dll]=sorted(symbols)
            artifacts.append({'path':str(path),'bytes':path.stat().st_size,'sha256':sha(path),'imports':imports,'oem_import_gate':'PASS','native_executed':False})
    if any(sha(ROOT/path)!=digest for path,digest in sources.items()) or sha(NPP)!=NPP_SHA:raise ValueError('source changed during build')
    frozen=out/'source';frozen.mkdir()
    for name in names:shutil.copyfile(HERE/name,frozen/name)
    shutil.copyfile(header,frozen/header.name)
    receipt={'status':'PASS','native_executed':False,'sources':sources,'frozen_sources':{name:sha(frozen/name) for name in (*names,header.name)},
             'compiler':{'path':cc,'sha256':sha(Path(cc))},'commands':commands,'profiles':{'fixture':own,'official_npp':npp,'native_debugbreak':{'source':str(kernel),'sha256':sha(kernel),'rva':debugbreak[0],'bytes':'ccc3'}},'artifacts':artifacts,
             'scope':'compiled native imports/profile gates only; actual hardware DR event proof must precede NPP compatibility trial',
             'fixture_command':'C:\\VXDLAB\\NTWPENV.EXE --fixture --log C:\\VXDLAB\\ENVDBG.LOG C:\\VXDLAB\\ENVFIX.EXE',
             'npp_command':'C:\\VXDLAB\\NTWPENV.EXE --npp --log C:\\VXDLAB\\ENVNPP.LOG C:\\NPPLAB\\APP\\NPP.EXE'}
    (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'status':'PASS','receipt':str(out/'build-result.json'),'native_executed':False}))
if __name__=='__main__':main()
