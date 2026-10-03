#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build isolated native Win98 PE loader and its own execution fixture."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
import pefile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve()
    if out.exists():parser.error('use a new output directory')
    cc=shutil.which('i686-w64-mingw32-gcc')
    if not cc:parser.error('existing MinGW compiler required')
    clang=shutil.which('clang')
    if not clang:parser.error('existing Clang MS-ABI compiler required')
    names=('native.c','pe.c','pe.h','fixture.c','fixture.def','tls_fixture.c','tls_compiler_fixture.c','tls_runtime.c','tls_runtime.h','order_fixture.c','order_a.def','order_b.def','build.py')
    frozen={str((HERE/name).relative_to(ROOT)):sha(HERE/name) for name in names}
    out.mkdir(parents=True)
    flags=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror',
           '-Wno-misleading-indentation','-fno-builtin','-fno-tree-loop-distribute-patterns',
           '-fno-stack-protector','-ffunction-sections','-fdata-sections','-nostdlib',
           '-Wl,--gc-sections','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4',
           '-Wl,--minor-os-version,0','-Wl,--major-image-version,4','-Wl,--minor-image-version,10',
           '-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware',
           '-Wl,--no-insert-timestamp','-Xlinker','--stack','-Xlinker','4194304,65536']
    commands=[[clang,'--no-default-config','--target=i686-pc-windows-msvc','-march=i486','-O2','-fno-stack-protector','-c',str(HERE/'tls_compiler_fixture.c'),'-o',str(out/'compiler.obj')],
              flags+['-Wl,--entry,_entry@0','-o',str(out/'NTWPE32.EXE'),str(HERE/'native.c'),str(HERE/'pe.c'),str(HERE/'tls_runtime.c'),str(ROOT/'ntwin32/chromium_port/api_contract.c'),str(ROOT/'ntwin32/native_environment/environment.c'),'-lkernel32','-lgcc'],
              flags+['-shared','-Wl,--entry,_DllMain@12','-o',str(out/'PE32FIX.DLL'),str(HERE/'fixture.c'),str(HERE/'fixture.def'),'-lkernel32'],
              flags+['-DNP_FAIL_ATTACH','-shared','-Wl,--entry,_DllMain@12','-o',str(out/'PE32FAIL.DLL'),str(HERE/'fixture.c'),str(HERE/'fixture.def'),'-lkernel32'],
              flags+['-shared','-Wl,--entry,_DllMain@12','-Wl,--undefined,__tls_used','-Wl,--defsym,__tls_array=0x2c','-o',str(out/'PE32TLS.DLL'),str(HERE/'tls_fixture.c'),str(out/'compiler.obj'),str(HERE/'fixture.def'),'-lkernel32'],
              flags+['-DNP_ORDER_A','-shared','-Wl,--entry,_DllMain@12','-Wl,--out-implib,'+str(out/'order-a.a'),'-o',str(out/'PEORDA.DLL'),str(HERE/'order_fixture.c'),str(HERE/'order_a.def'),'-lkernel32'],
              flags+['-DNP_ORDER_B','-shared','-Wl,--entry,_DllMain@12','-Wl,--out-implib,'+str(out/'order-b.a'),'-o',str(out/'PEORDB.DLL'),str(HERE/'order_fixture.c'),str(HERE/'order_b.def'),'-lkernel32'],
              flags+['-DNP_ORDER_B','-DNP_ORDER_FAIL_B','-shared','-Wl,--entry,_DllMain@12','-o',str(out/'PEBFAIL.DLL'),str(HERE/'order_fixture.c'),str(HERE/'order_b.def'),'-lkernel32'],
              flags+['-shared','-Wl,--entry,_DllMain@12','-o',str(out/'PEORDER.DLL'),str(HERE/'order_fixture.c'),str(HERE/'fixture.def'),str(out/'order-a.a'),str(out/'order-b.a'),'-lkernel32']]
    receipt={'status':'FAIL','native_executed':False,'target_headers_modified':False,'sources':frozen,
             'compiler':{'path':cc,'sha256':sha(Path(cc))},'ms_abi_compiler':{'path':clang,'sha256':sha(Path(clang))},'commands':commands,'artifacts':[]}
    with (out/'build.log').open('w') as log:
        for command in commands:
            result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=log,timeout=120)
            if result.returncode:
                receipt['exit_code']=result.returncode
                (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
                print(json.dumps({'status':'FAIL','receipt':str(out/'build-result.json')}))
                return result.returncode
    doc=json.loads((ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())
    available={name.upper():set(exports) for name,exports in doc['dlls'].items()}
    for name in ('NTWPE32.EXE','PE32FIX.DLL','PE32FAIL.DLL','PE32TLS.DLL','PEORDA.DLL','PEORDB.DLL','PEBFAIL.DLL','PEORDER.DLL'):
        path=out/name
        with pefile.PE(str(path)) as pe:
            opt=pe.OPTIONAL_HEADER
            if (pe.FILE_HEADER.Machine,opt.Magic,opt.Subsystem,opt.MajorSubsystemVersion,opt.MinorSubsystemVersion)!=(0x14c,0x10b,2,4,10):raise ValueError('native PE profile mismatch')
            if opt.DllCharacteristics&0x140 or bool(pe.is_dll())!=name.endswith('.DLL'):raise ValueError('native PE image flags mismatch')
            if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (10,13,14)) or bool(opt.DATA_DIRECTORY[9].VirtualAddress)!=(name=='PE32TLS.DLL'):raise ValueError('unexpected runtime directory')
            imports={}
            for descriptor in getattr(pe,'DIRECTORY_ENTRY_IMPORT',()):
                dll=descriptor.dll.decode('ascii').upper();symbols=[]
                for entry in descriptor.imports:
                    if not entry.name:raise ValueError('unexpected native ordinal import')
                    symbol=entry.name.decode('ascii')
                    private={'PEORDA.DLL':{'AReady@0'},'PEORDB.DLL':{'BReady@0'}} if name=='PEORDER.DLL' else {}
                    if symbol not in available.get(dll,set()) and symbol not in private.get(dll,set()):raise ValueError('outside exact OEM/private exports: '+dll+'!'+symbol)
                    symbols.append(symbol)
                imports[dll]=sorted(symbols)
            exports=sorted(symbol.name.decode('ascii') for symbol in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',()) if symbol.name)
            artifact={'path':str(path),'bytes':path.stat().st_size,'sha256':sha(path),'imports':imports,'exports':exports,'oem_import_gate':'PASS','native_load':False}
            if name=='PE32TLS.DLL':
                operands=[]
                for section in pe.sections:
                    if not section.Characteristics&0x20000000:continue
                    code=section.get_data()
                    for offset in range(len(code)-5):
                        if code[offset:offset+2]==b'\x64\xa1' and int.from_bytes(code[offset+2:offset+6],'little')==0x2c:operands.append(section.VirtualAddress+offset+2)
                        if offset+7<=len(code) and code[offset:offset+2]==b'\x64\x8b' and code[offset+2]&0xc7==5 and int.from_bytes(code[offset+3:offset+7],'little')==0x2c:operands.append(section.VirtualAddress+offset+3)
                relocations={entry.rva for block in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',()) for entry in block.entries if entry.type}
                if len(operands)!=2 or any(rva in relocations for rva in operands):raise ValueError('actual MS compiler FS ABI proof mismatch')
                if opt.DATA_DIRECTORY[9].Size!=24 or not pe.get_data(opt.DATA_DIRECTORY[9].VirtualAddress,24):raise ValueError('TLS descriptor linker retention failed')
                artifact['ms_abi_fs_2c_operands']=operands
        allowed={'KERNEL32.DLL','PEORDA.DLL','PEORDB.DLL'} if name=='PEORDER.DLL' else {'KERNEL32.DLL'}
        if set(artifact['imports'])!=allowed:raise ValueError('only classic Kernel32 and exact own fixtures allowed')
        expected={'AReady@0'} if name=='PEORDA.DLL' else {'BReady@0'} if name in ('PEORDB.DLL','PEBFAIL.DLL') else {'NtwPeFixture'}
        if name.endswith('.DLL') and set(artifact['exports'])!=expected:raise ValueError('fixture ABI mismatch')
        if name=='PEORDER.DLL' and list(artifact['imports']).index('PEORDA.DLL')>list(artifact['imports']).index('PEORDB.DLL'):raise ValueError('later-B fixture ordering lost')
        receipt['artifacts'].append(artifact)
    if any(sha(ROOT/name)!=value for name,value in frozen.items()):raise ValueError('source changed during build')
    receipt.update(status='PASS',exit_code=0,scope='compiled native imports and host format only; parent owns native execution')
    (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':'PASS','receipt':str(out/'build-result.json'),'native_executed':False}))
    return 0

if __name__=='__main__':raise SystemExit(main())
