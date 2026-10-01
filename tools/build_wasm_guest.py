#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build actual numeric engine oracles and a Win98 DLL probe; launch no VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pefile
from i486_instruction_gate import scan

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'build/wasm-runtime-v24'
RUNTIME_SHA = '26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91'
OWN = ['tests/m98_wasm_guest.c', 'tests/m98_wasm_guest_HANDOFF.md',
       'tools/build_wasm_guest.py', 'src/m98_wasm.h',
       'tools/i486_instruction_gate.py', 'tests/test_i486_instruction_gate.py',
       'benchmarks/win98se-ko-oem-native-exports-v1.json']
FIXTURES = ('arithmetic', 'memory', 'float', 'imports', 'infinite',
            'start_infinite', 'missing_import', 'bad_magic')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def read(path, limit=16 << 20):
    path = Path(path)
    need(path.resolve(strict=True) == path and path.is_file() and
         not path.is_symlink(), 'Canonical regular input required')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(0 <= before.st_size <= limit, 'Input bound')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        need(len(data) == before.st_size and all(getattr(before,k)==getattr(after,k)
             for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')), 'Input drift')
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',required=True,type=Path)
    parser.add_argument('--nonce',required=True)
    args=parser.parse_args()
    build=args.build_dir.absolute()
    need(build.parent==ROOT/'build' and build.resolve()==build and not build.exists(),
         'Fresh owned direct build directory required')
    need(re.fullmatch(r'[A-Za-z0-9_-]{1,64}',args.nonce),'Bounded nonce required')
    observed={}
    def checked(path, expected=None, limit=16<<20):
        data=read(path,limit);actual=digest(data)
        need(expected is None or actual==expected,'Changed input: '+str(path))
        need(str(path) not in observed or observed[str(path)]==actual,'Conflicting generation')
        observed[str(path)]=actual
        return data
    runtime=json.loads(checked(RUNTIME/'result.json',RUNTIME_SHA))
    need(runtime['passed'] is True and runtime['native_execution'] is False and
         runtime['browser_wasm'] is False,'Frozen numeric runtime scope required')
    for name,h in runtime['source_sha256'].items():
        checked(ROOT/name,h);checked(RUNTIME/'source'/name,h)
    for name,row in runtime['prepared_files'].items():checked(RUNTIME/'prepared'/name,row['sha256'])
    for step in runtime['steps']:checked(Path(step['log']),step['sha256'])
    for item in runtime['object_cache']:
        cache=ROOT/'build/wasm-runtime-object-cache'
        checked(cache/(item['key']+'.json'),item['provenance_sha256'])
        checked(cache/(item['key']+'.o'),item['object_sha256'])
    own={name:checked(ROOT/name) for name in OWN}
    fixture={name:checked(RUNTIME/'original-fixtures'/(name+'.wasm'),
             runtime['original_fixtures'][name]['sha256']) for name in FIXTURES}
    checked(RUNTIME/'M98WASM.DLL',runtime['artifacts']['M98WASM.DLL']['sha256'])
    objects={}
    for label in ('host','sanitizer'):
        rows=[s for s in runtime['steps'] if s['name']==label+'-build']
        need(len(rows)==1,'Unique frozen engine link command required')
        old=[Path(s) for s in rows[0]['command'] if str(s).endswith('.o')]
        need(len(old)==31 and old[-1]==RUNTIME/(label+'-30.o'),'Frozen engine/test split')
        objects[label]=old[:-1]
        cache_hashes={row['object_sha256'] for row in runtime['object_cache']}
        for path in objects[label]:need(digest(checked(path)) in cache_hashes,'Actual reused object pin')
    build.mkdir()
    for name,data in own.items():
        target=build/'source'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        need(read(target)==data,'Initial own source snapshot readback')
    steps=[]
    result=dict(schema=1,kind='actual-numeric-wamr-win98-probe-build',passed=False,
        nonce=args.nonce,runtime_receipt_sha256=RUNTIME_SHA,source_sha256={n:digest(b) for n,b in own.items()},
        original_fixture_sha256={n:digest(b) for n,b in fixture.items()},steps=steps,
        native_execution=False,browser_webassembly=False,full_modern_wasm=False,
        webgl=False,webgpu=False,modern_apps=False,vm_operations=False,
        source_archives_and_original_runtime_unchanged=True,
        toolchain_limit='Frozen runtime cache pins compiler version/local headers, not complete external toolchain bytes')
    def run(label,command,env=None):
        r=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,timeout=90)
        data=r.stdout+r.stderr;need(len(data)<=8<<20,'Build/test log bound')
        log=build/(label+'.log');log.write_bytes(data)
        steps.append(dict(name=label,command=command,returncode=r.returncode,log=str(log),sha256=digest(data)))
        need(r.returncode==0,label+' failed; original log retained')
        return data
    try:
        header='/* Pinned project-owned binary fixtures, not official spec modules. */\n'
        for name,data in fixture.items():
            header+='static const unsigned char wasm_'+name+'[]={'+','.join(str(v) for v in data)+'};\n'
        (build/'wasm_original_fixtures.h').write_text(header)
        result['generated_sha256']={'wasm_original_fixtures.h':digest(header.encode())}
        models={}
        for label in ('host','sanitizer'):
            extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if label=='sanitizer' else []
            obj=build/(label+'-probe.o');binary=build/(label+'-probe')
            run(label+'-compile',['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                '-mfpmath=387','-ffp-contract=off','-fno-strict-aliasing','-DM98_WASM_GUEST_HOST=1',
                '-Isrc','-I'+str(build)]+extra+['-c','tests/m98_wasm_guest.c','-o',str(obj)])
            run(label+'-link',['clang' if extra else 'gcc']+extra+[str(p) for p in objects[label]]+
                [str(obj),'-Wl,--gc-sections','-pthread','-lm','-o',str(binary)])
            log=run(label+'-test',[str(binary)],dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
            match=re.search(rb'CHECKS=([0-9]+)\r\nFAILURES=0\r\nSTATUS=PASS\r\n$',log)
            need(match is not None,'Actual engine terminal totals missing');models[label]=int(match[1])
        need(models['host']==models['sanitizer'],'Host/sanitizer case drift')
        binary=build/'WAS13PR.EXE'
        run('native-build',['i686-w64-mingw32-gcc','-std=gnu11','-Os','-g','-Wall','-Wextra','-Werror',
            '-march=i486','-mfpmath=387','-mno-sse','-mno-sse2','-mno-mmx','-fno-builtin',
            '-fno-stack-protector','-mno-stack-arg-probe','-nostdlib','-Isrc','-I'+str(build),
            '-DM98_WASM_GUEST_NONCE="'+args.nonce+'"','tests/m98_wasm_guest.c',
            '-Wl,--entry,_m98_wasm_probe@0','-Wl,--subsystem,windows:4.10',
            '-Wl,--major-os-version,4','-Wl,--minor-os-version,10','-Wl,--disable-dynamicbase',
            '-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp',
            '-Xlinker','--stack','-Xlinker','2097152,65536','-lmsvcrt','-lkernel32','-o',str(binary)])
        gates={}
        for path in (binary,RUNTIME/'M98WASM.DLL'):
            gate,raw=scan(path);log=build/(path.name+'-disassembly.log');log.write_bytes(raw)
            steps.append(dict(name=path.name+'-disassembly',command=gate['command'],returncode=0,log=str(log),sha256=digest(raw)))
            gates[path.name]=gate
        installed=json.loads(own['benchmarks/win98se-ko-oem-native-exports-v1.json'])['dlls']
        imports={}
        need(0<binary.stat().st_size<=1<<20,'Bounded native guest input')
        with pefile.PE(str(binary)) as pe:
            h=pe.OPTIONAL_HEADER
            need(pe.FILE_HEADER.Machine==0x14c and h.Magic==0x10b and not pe.is_dll(),'PE32 EXE')
            need(h.Subsystem==2 and h.AddressOfEntryPoint and pe.FILE_HEADER.TimeDateStamp==0,'Deterministic GUI entry')
            need((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion)==(4,10) and
                 (h.MajorSubsystemVersion,h.MinorSubsystemVersion)==(4,10),'Actual Win98 PE version')
            need(not h.DllCharacteristics&(0x40|0x100|0x8000) and not pe.FILE_HEADER.Characteristics&1
                 and h.DATA_DIRECTORY[5].VirtualAddress,'Legacy relocation contract')
            need((h.SizeOfStackReserve,h.SizeOfStackCommit)==(2097152,65536),'Bounded stack')
            need(all(not h.DATA_DIRECTORY[i].VirtualAddress and not h.DATA_DIRECTORY[i].Size for i in (9,10,13,14)),'No modern PE directory')
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                name=module.dll.decode().upper();need(name in {'KERNEL32.DLL','MSVCRT.DLL'} and all(r.name for r in module.imports),'Named original imports')
                symbols=sorted(r.name.decode() for r in module.imports);need(set(symbols)<=set(installed[name]),'Actual OEM exports');imports[name]=symbols
            need(not hasattr(pe,'DIRECTORY_ENTRY_EXPORT') and imports,'Exact probe surface')
        for name,data in own.items():
            target=build/'source'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            need(read(target)==data,'Own source snapshot readback')
        for path,h in observed.items():need(digest(read(Path(path)))==h,'Final actual input drift')
        result.update(passed=True,models=models,checked_evidence_sha256=observed,
            artifacts={binary.name:dict(bytes=binary.stat().st_size,sha256=digest(read(binary)),
            imports=imports,pe98_gate='pass',i486_instructions=gates[binary.name])},
            runtime_i486_recheck=gates['M98WASM.DLL'],actual_guest_output='C:\\GOPLAB\\WA13.LOG',
            independently_observed_actual_child_exit_required=True)
    except Exception as error:
        result['error']=str(error);raise
    finally:
        (build/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=True,models=models,result=str(build/'result.json'),native_execution=False)))


if __name__=='__main__':
    main()
