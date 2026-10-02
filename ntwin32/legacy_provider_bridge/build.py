#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build-only native bridge with retained symbols proving empty lifecycle lists."""
import argparse
import hashlib
import importlib.util
import json
import os
import selectors
import shutil
import signal
import subprocess
import time
import types
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def capture_query(argv, out, label):
    """Bound only direct query captures; this legacy builder is not a quota guard."""
    if not all(hasattr(os, key) for key in ('waitid','P_PID','WEXITED','WNOHANG','WNOWAIT')):
        raise RuntimeError('bounded GNU queries require POSIX nonreaping process observation')
    child=subprocess.Popen(argv,cwd=ROOT,stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    watch=selectors.DefaultSelector();chunks={'stdout':bytearray(),'stderr':bytearray()}
    started=time.monotonic()
    try:
        watch.register(child.stdout,selectors.EVENT_READ,'stdout')
        watch.register(child.stderr,selectors.EVENT_READ,'stderr')
        while True:
            if time.monotonic()-started>120:raise RuntimeError('GNU query timeout')
            observed=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            if observed and observed.si_pid==child.pid and not watch.get_map():break
            for key,_ in watch.select(0.05):
                block=os.read(key.fileobj.fileno(),16384)
                if not block:watch.unregister(key.fileobj)
                else:
                    if sum(map(len,chunks.values()))+len(block)>256*1024:
                        raise RuntimeError('GNU query capture exceeds 256 KiB')
                    chunks[key.data].extend(block)
        child.wait(timeout=5)
    except BaseException:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        child.wait(timeout=5)
        raise
    finally:
        watch.close();child.stdout.close();child.stderr.close()
        for name,data in chunks.items():(out/(label+'.'+name)).write_bytes(data)
    if child.returncode or chunks['stderr']:raise RuntimeError('selected GNU query failed or diagnosed')
    return bytes(chunks['stdout'])


def linker_profiles(cc, out, helper):
    raw=capture_query([cc,'-print-prog-name=ld'],out,'selected-ld-query')
    if not raw.endswith(b'\n') or raw.count(b'\n')!=1 or b'\r' in raw:
        raise RuntimeError('selected GCC linker query must return one path')
    name=raw[:-1].decode('utf-8',errors='strict')
    candidate=Path(name)
    if not candidate.is_absolute():
        found=shutil.which(name) if candidate.name==name else str(ROOT/candidate)
        if not found:raise RuntimeError('selected GCC linker is unavailable')
        candidate=Path(found)
    selected=candidate.resolve(strict=True);digest=sha(selected)
    profiles={}
    for profile,dll_mode in (('dll',True),('probe',False)):
        argv=[str(selected),'-m','i386pe','--verbose']+(['--dll'] if dll_mode else [])
        verbose=capture_query(argv,out,profile+'-default-script')
        default=helper.extract_default_script(verbose)
        generated,transform=helper.relocate_lifecycle_lists(default)
        original_path=out/(profile+'-default.ld');script=out/(profile+'-lifecycle.ld')
        original_path.write_bytes(default);script.write_bytes(generated)
        profiles[profile]={'argv':argv,'default_path':str(original_path),'default_sha256':sha(original_path),
                           'script_path':str(script),'script_sha256':sha(script),'transform':transform,
                           'verbose_path':str(out/(profile+'-default-script.stdout')),
                           'verbose_sha256':hashlib.sha256(verbose).hexdigest()}
    if sha(selected)!=digest:raise RuntimeError('selected GNU linker changed during script queries')
    return {'path':str(selected),'sha256':digest,'profiles':profiles,
            'full_toolchain_attestation_verified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve()
    if out.exists():parser.error('use a new output directory')
    cc=shutil.which('i686-w64-mingw32-gcc')
    if not cc:parser.error('existing MinGW compiler required')
    sources=[HERE/name for name in ('native.c','table.c','table.h','NTWPROV.def','probe.c','build.py',
                                    'pe_link_script_6970.py')]
    frozen={str(p.relative_to(ROOT)):sha(p) for p in sources}
    out.mkdir(parents=True);dll=out/'NTWPROV.DLL'
    helper_path=HERE/'pe_link_script_6970.py';helper_bytes=helper_path.read_bytes()
    if hashlib.sha256(helper_bytes).hexdigest()!=frozen[str(helper_path.relative_to(ROOT))]:
        raise RuntimeError('link-script helper changed before source loading')
    helper=types.ModuleType('pe_link_script_6970');helper.__file__=str(helper_path)
    exec(compile(helper_bytes,str(helper_path),'exec'),helper.__dict__)
    linker=linker_profiles(cc,out,helper)
    command=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-fno-builtin',
             '-ffunction-sections','-fdata-sections','-nostdlib','-shared','-Wl,--gc-sections',
             '-Wl,--entry,_DllMain@12','-Wl,--subsystem,windows:4.10','-Wl,--major-image-version,4',
             '-Wl,--minor-image-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat',
             '-Wl,--disable-tsaware','-Wl,--no-insert-timestamp',
             '-Xlinker','-T','-Xlinker',linker['profiles']['dll']['script_path'],'-o',str(dll),
             str(HERE/'native.c'),str(HERE/'table.c'),str(HERE/'NTWPROV.def'),'-lkernel32']
    with (out/'build.log').open('w') as log:result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=log,timeout=120)
    receipt={'status':'FAIL','native_executed':False,'command':command,'exit_code':result.returncode,
             'sources':frozen,'compiler_sha256':sha(Path(cc)),'selected_linker':linker,
             'filesystem_quota_enforced':False,'full_toolchain_attestation_verified':False}
    if not result.returncode:
        spec=importlib.util.spec_from_file_location('prerequisite_gate',ROOT/'tools/build_npp_prerequisites.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        document=json.loads((ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())
        artifact=gate.gate(dll,{name.upper():set(exports) for name,exports in document['dlls'].items()})
        expected={'NtwOpenProviderDirectoryA','NtwFindProviderExportA','NtwCloseProviderDirectory'}
        if set(artifact['exports'])!=expected:raise ValueError('native bridge export ABI mismatch')
        import pefile
        dll_layout=helper.validate_empty_lifecycle_layout(dll.read_bytes(),pefile)
        probe=out/'NTWPRB.EXE'
        probe_command=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-fno-builtin',
                       '-nostdlib','-Wl,--entry,_mainCRTStartup','-Wl,--subsystem,windows:4.10',
                       '-Wl,--major-image-version,4','-Wl,--minor-image-version,10',
                       '-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware',
                       '-Wl,--no-insert-timestamp','-Xlinker','-T','-Xlinker',
                       linker['profiles']['probe']['script_path'],
                       '-o',str(probe),str(HERE/'probe.c'),'-lkernel32']
        with (out/'probe-build.log').open('w') as log:
            subprocess.run(probe_command,cwd=ROOT,stdout=log,stderr=log,timeout=120,check=True)
        import pefile
        probe_layout=helper.validate_empty_lifecycle_layout(probe.read_bytes(),pefile)
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
        if sha(Path(linker['path']))!=linker['sha256']:raise ValueError('selected GNU linker changed during build')
        for profile in linker['profiles'].values():
            if (sha(Path(profile['default_path']))!=profile['default_sha256']
                    or sha(Path(profile['script_path']))!=profile['script_sha256']
                    or sha(Path(profile['verbose_path']))!=profile['verbose_sha256']):
                raise ValueError('actual/default/generated linker script changed during build')
        receipt.update(status='PASS',artifact=artifact,probe_command=probe_command,
                       lifecycle_layout={'dll':dll_layout,'probe':probe_layout},
                       lifecycle_list_spans_verified_by_retained_end_symbols=True,
                       lifecycle_end_markers_exported=False,
                       probe_artifact={'bytes':probe.stat().st_size,'sha256':sha(probe),'imports':imports,'native_load':False})
    (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'receipt':str(out/'build-result.json'),'native_executed':False}))
    return result.returncode


if __name__=='__main__':raise SystemExit(main())
