#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the native provider bridge without executing or installing it."""
import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

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
    sources=[HERE/name for name in ('native.c','table.c','table.h','NTWPROV.def','probe.c','build.py')]
    frozen={str(p.relative_to(ROOT)):sha(p) for p in sources}
    out.mkdir(parents=True);dll=out/'NTWPROV.DLL'
    command=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-fno-builtin',
             '-ffunction-sections','-fdata-sections','-nostdlib','-shared','-Wl,--gc-sections',
             '-Wl,--entry,_DllMain@12','-Wl,--subsystem,windows:4.10','-Wl,--major-image-version,4',
             '-Wl,--minor-image-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat',
             '-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-o',str(dll),
             str(HERE/'native.c'),str(HERE/'table.c'),str(HERE/'NTWPROV.def'),'-lkernel32']
    with (out/'build.log').open('w') as log:result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=log,timeout=120)
    receipt={'status':'FAIL','native_executed':False,'command':command,'exit_code':result.returncode,
             'sources':frozen,'compiler_sha256':sha(Path(cc))}
    if not result.returncode:
        spec=importlib.util.spec_from_file_location('prerequisite_gate',ROOT/'tools/build_npp_prerequisites.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        document=json.loads((ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())
        artifact=gate.gate(dll,{name.upper():set(exports) for name,exports in document['dlls'].items()})
        expected={'NtwOpenProviderDirectoryA','NtwFindProviderExportA','NtwCloseProviderDirectory'}
        if set(artifact['exports'])!=expected:raise ValueError('native bridge export ABI mismatch')
        probe=out/'NTWPRB.EXE'
        probe_command=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-fno-builtin',
                       '-nostdlib','-Wl,--entry,_mainCRTStartup','-Wl,--subsystem,windows:4.10',
                       '-Wl,--major-image-version,4','-Wl,--minor-image-version,10',
                       '-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware',
                       '-Wl,--no-insert-timestamp','-o',str(probe),str(HERE/'probe.c'),'-lkernel32']
        with (out/'probe-build.log').open('w') as log:
            subprocess.run(probe_command,cwd=ROOT,stdout=log,stderr=log,timeout=120,check=True)
        import pefile
        with pefile.PE(str(probe)) as pe:
            header=pe.OPTIONAL_HEADER
            if (pe.FILE_HEADER.Machine,header.Magic,header.Subsystem,header.MajorSubsystemVersion,header.MinorSubsystemVersion)!=(0x14c,0x10b,2,4,10):raise ValueError('probe PE ABI')
            if pe.is_dll() or header.DllCharacteristics&0x140 or any(header.DATA_DIRECTORY[n].VirtualAddress for n in (9,13,14)):raise ValueError('probe unsupported runtime flags')
            imports={}
            for desc in pe.DIRECTORY_ENTRY_IMPORT:
                name=desc.dll.decode('ascii').upper();imports[name]=[]
                for entry in desc.imports:
                    if not entry.name or entry.name.decode('ascii') not in document['dlls'].get(name,[]):raise ValueError('probe outside native OEM imports')
                    imports[name].append(entry.name.decode('ascii'))
        if any(sha(ROOT/name)!=value for name,value in frozen.items()):raise ValueError('source changed during build')
        receipt.update(status='PASS',artifact=artifact,probe_command=probe_command,
                       probe_artifact={'bytes':probe.stat().st_size,'sha256':sha(probe),'imports':imports,'native_load':False})
    (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'receipt':str(out/'build-result.json'),'native_executed':False}))
    return result.returncode


if __name__=='__main__':raise SystemExit(main())
