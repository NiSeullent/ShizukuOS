#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build, but never execute, native Win98 TLS ABI/compiler proof."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
import pefile
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);args=ap.parse_args();out=args.out.resolve()
    if out.exists():ap.error('use a fresh output')
    cc=shutil.which('i686-w64-mingw32-gcc');clang=shutil.which('clang')
    if not cc or not clang:ap.error('existing compilers required')
    sources={str((HERE/name).relative_to(ROOT)):sha(HERE/name) for name in ('tls_probe.c','tls_runtime.c','tls_runtime.h','tls_compiler_fixture.c','tls_probe_build.py')}
    out.mkdir(parents=True);obj=out/'compiler.obj';exe=out/'NTWTLS.EXE'
    commands=[[clang,'--no-default-config','--target=i686-pc-windows-msvc','-march=i486','-O2','-fno-stack-protector','-c',str(HERE/'tls_compiler_fixture.c'),'-o',str(obj)],
              [cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fno-builtin','-fno-tree-loop-distribute-patterns','-nostdlib',
               '-Wl,--entry,_entry@0','-Wl,--subsystem,windows:4.10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp',
               '-Wl,--defsym,__tls_array=0x2c','-o',str(exe),str(HERE/'tls_probe.c'),str(HERE/'tls_runtime.c'),str(obj),'-lkernel32','-lgcc']]
    with (out/'build.log').open('w') as log:
        for command in commands:subprocess.run(command,check=True,stdout=log,stderr=log,cwd=ROOT,timeout=120)
    native=json.loads((ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())['dlls'];imports={}
    with pefile.PE(str(exe)) as pe:
        opt=pe.OPTIONAL_HEADER
        assert (pe.FILE_HEADER.Machine,opt.Magic,opt.MajorSubsystemVersion,opt.MinorSubsystemVersion)==(0x14c,0x10b,4,10)
        assert not pe.is_dll() and all(not opt.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14))
        relocations={e.rva for b in pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type}
        fs_operands=[]
        for section in pe.sections:
            if not section.Characteristics&0x20000000:continue
            raw=section.get_data()
            for opcode in (b'\x64\x8b\x0d\x2c\0\0\0',b'\x64\x8b\x15\x2c\0\0\0'):
                start=0
                while (at:=raw.find(opcode,start))>=0:
                    operand=section.VirtualAddress+at+3;assert operand not in relocations;fs_operands.append(operand);start=at+1
        assert len(fs_operands)==2,fs_operands
        for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
            dll=descriptor.dll.decode().upper();assert dll=='KERNEL32.DLL';names=[]
            for entry in descriptor.imports:
                assert entry.name and entry.name.decode() in native[dll];names.append(entry.name.decode())
            imports[dll]=sorted(names)
    assert all(sha(ROOT/name)==digest for name,digest in sources.items())
    receipt={'status':'PASS','native_executed':False,'sources':sources,'commands':commands,'compilers':{cc:sha(Path(cc)),clang:sha(Path(clang))},
             'artifact':{'path':str(exe),'bytes':exe.stat().st_size,'sha256':sha(exe),'imports':imports,'automatic_tls_directory':False,
                         'real_ms_abi_compiler_fs_2c_operands':fs_operands,'oem_import_gate':'PASS'},
             'scope':'compiled ABI proof only; real Windows98 FS/native slots/thread behavior pending parent trial'}
    (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'status':'PASS','receipt':str(out/'build-result.json'),'native_executed':False}))
if __name__=='__main__':main()
