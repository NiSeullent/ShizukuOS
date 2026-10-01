#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded host WinAPI controls and PE32 build only; never Windows/boot evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUTPUT_LIMIT = 64 << 20
IMPORTS = {'CloseHandle','CreateFileA','ExitProcess','FlushFileBuffers','GetCommandLineA',
           'GetFileSize','GetStdHandle','GetVersion','ReadFile','WriteFile'}


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1 << 20),b''): h.update(block)
    return h.hexdigest()


def source_pins():
    return {str(p):digest(p) for p in sorted(HERE.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}


def execute_owned(argv,cwd,env,log,*,timeout=120,output_limit=1 << 20,file_limit=8 << 20):
    """Bounded streaming and an owned unreaped session, including descendants."""
    assert 0<timeout<=120 and 0<output_limit<=1 << 20 and 0<file_limit<=8 << 20
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(file_limit,file_limit))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resources(log.parent)
    raw=bytearray(); deadline=time.monotonic()+timeout; proc=None
    with log.open('xb') as saved, selectors.DefaultSelector() as ready:
        try:
            proc=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=limits)
            os.set_blocking(proc.stdout.fileno(),False); ready.register(proc.stdout,selectors.EVENT_READ)
            eof=False
            while True:
                if time.monotonic()>=deadline: raise subprocess.TimeoutExpired(argv,timeout)
                for key,_ in ready.select(min(0.04,max(0,deadline-time.monotonic()))):
                    block=os.read(key.fileobj.fileno(),65536)
                    if not block:
                        ready.unregister(key.fileobj); eof=True; continue
                    room=output_limit-len(raw); part=block[:room]; raw.extend(part); saved.write(part)
                    if len(block)>room: raise RuntimeError('bounded raw output exceeded')
                resources(log.parent)
                # WNOWAIT keeps the owned leader/PID until group cleanup. No
                # reused process-group identifier can be targeted after reaping.
                ended=os.waitid(os.P_PID,proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if eof and ended is not None: break
        finally:
            if proc is not None:
                primary=sys.exception(); cleanup=[]
                try:
                    try: os.killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    except OSError as error:
                        cleanup.append('owned group kill failed: '+str(error))
                        # The unreaped direct child is still ours. Reject the
                        # group-cleanup failure even if this fallback succeeds.
                        try: proc.kill()
                        except OSError as error: cleanup.append('owned leader kill failed: '+str(error))
                finally:
                    try: proc.wait(timeout=5)
                    except (OSError,subprocess.SubprocessError) as error: cleanup.append('owned leader reap failed: '+str(error))
                    finally:
                        try: proc.stdout.close()
                        except OSError as error: cleanup.append('owned pipe close failed: '+str(error))
                if cleanup:
                    if primary is not None:
                        for note in cleanup: primary.add_note(note)
                    else: raise RuntimeError('; '.join(cleanup))
    return subprocess.CompletedProcess(argv,proc.returncode,bytes(raw).decode('utf-8','replace'),'')


def resources(out):
    info={line.split(':',1)[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')}
    free=shutil.disk_usage(out).free
    usage=sum(p.stat().st_size for p in out.rglob('*') if p.is_file())
    assert free >= 128 << 20 and usage < OUTPUT_LIMIT,'tiny local output capacity unavailable'
    assert info['MemAvailable'] >= 512 << 20,'host memory reserve unavailable'
    row=next((s for s in Path('/proc/self/cgroup').read_text().splitlines() if s.startswith('0::')),None)
    assert row is not None,'actual cgroup2 identity required'
    group=Path('/sys/fs/cgroup')/row.split('::',1)[1].lstrip('/')
    samples=[]; memory_seen=False
    for at in (group,*group.parents):
        if not at.is_relative_to('/sys/fs/cgroup'): break
        sample={'path':str(at)}
        for prefix,reserve in (('memory',512 << 20),('pids',16)):
            maximum,current=at/(prefix+'.max'),at/(prefix+'.current')
            if not maximum.is_file() or not current.is_file(): continue
            limit=maximum.read_text().strip(); used=int(current.read_text())
            sample[prefix]={'max':limit,'current':used}
            if prefix=='memory': memory_seen=True
            if limit!='max': assert int(limit)-used >= reserve,f'cgroup {prefix} reserve unavailable'
        if len(sample)>1: samples.append(sample)
    assert memory_seen,'actual cgroup memory controls not exposed'
    return {'MemAvailable':info['MemAvailable'],'free_bytes':free,'output_bytes':usage,'output_limit':OUTPUT_LIMIT,'cgroups':samples}


def pe_contract(path):
    data=path.read_bytes(); assert len(data)<1 << 20 and data[:2]==b'MZ'
    pe=struct.unpack_from('<I',data,0x3c)[0]; assert data[pe:pe+4]==b'PE\0\0'
    machine,sections,_,_,_,optbytes,_=struct.unpack_from('<HHIIIHH',data,pe+4)
    opt=pe+24; assert machine==0x14c and struct.unpack_from('<H',data,opt)[0]==0x10b
    assert struct.unpack_from('<HH',data,opt+40)==(4,0)
    assert struct.unpack_from('<HH',data,opt+48)==(4,0)
    assert struct.unpack_from('<HH',data,opt+68)==(3,0)
    table=opt+optbytes
    def offset(rva):
        for i in range(sections):
            _,va,size,raw=struct.unpack_from('<IIII',data,table+40*i+8)
            if va<=rva<va+size:
                at=raw+rva-va; assert at<len(data); return at
        raise AssertionError('unmapped PE RVA')
    def string(rva):
        at=offset(rva); return data[at:data.index(0,at)].decode('ascii')
    p=offset(struct.unpack_from('<I',data,opt+104)[0]); imports={}
    while data[p:p+20]!=bytes(20):
        lookup,_,_,name,thunk=struct.unpack_from('<IIIII',data,p)
        dll=string(name); assert dll not in imports
        q=offset(lookup or thunk); names=[]
        while (entry:=struct.unpack_from('<I',data,q)[0]):
            assert not entry & 0x80000000,'ordinal import refused'
            names.append(string(entry+2)); q+=4
        imports[dll]=names; p+=20
    assert len(imports)==1 and next(iter(imports)).lower()=='kernel32.dll'
    assert set(next(iter(imports.values())))==IMPORTS
    return {'machine':'PE32 i386','instruction_target':'i486, no SSE/MMX/float','OS_version':'4.0',
            'subsystem':'console 4.0','DLL_characteristics':0,'imports':imports,'CRT_imports':False,
            'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args(); out=args.out.absolute()
    assert out.resolve()==out and not any(p.is_symlink() for p in (out,*out.parents)),'canonical output required'
    assert out.is_relative_to(REPO/'build'),'tiny artifacts belong under ignored local build/'
    assert not out.exists(),'fresh output required; prior evidence retained'
    subprocess.run(['git','-C',str(REPO),'check-ignore','--no-index','--quiet','--',str(out)],check=True)
    out.mkdir(parents=True,mode=0o700)
    before=source_pins(); tools={}; sdk={}; runs=[]; resource_samples=[]; pe=None; passed=False
    env=os.environ.copy(); env.update(ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
    temporary=out/'tmp'; temporary.mkdir(mode=0o700); env['TMPDIR']=str(temporary)
    def pin_tool(name):
        found=shutil.which(name) if not Path(name).is_absolute() else name
        assert found,'required real tool missing: '+name
        path=Path(found).resolve(); tools[str(path)]=digest(path); return path
    def run(command,name,check=True):
        resource_samples.append(resources(out)); argv=[str(x) for x in command]
        log=out/(name+'.log')
        try: result=execute_owned(argv,REPO,env,log)
        except (AssertionError,OSError,subprocess.SubprocessError,RuntimeError) as error:
            runs.append({'name':name,'command':argv,'returncode':None,'error':str(error),
                         'log':str(log),'log_sha256':digest(log) if log.is_file() else None})
            raise
        runs.append({'name':name,'command':argv,'returncode':result.returncode,'log':str(log),'log_sha256':digest(log)})
        resources(out)
        if check: result.check_returncode()
        return result
    try:
        python=pin_tool(sys.executable); run([python,'--version'],'python-version')
        gcc=pin_tool('gcc'); clang=pin_tool('clang'); cross=pin_tool('i686-w64-mingw32-gcc'); inspector=pin_tool('llvm-readobj')
        for name,tool in (('gcc',gcc),('clang',clang),('cross',cross),('llvm-readobj',inspector)): run([tool,'--version'],name+'-version')
        for compiler,name in ((gcc,'gcc'),(cross,'cross')):
            run([compiler,'-dumpspecs'],name+'-specs')
            for component in ('cc1','collect2','as','ld'):
                result=run([compiler,'-print-prog-name='+component],name+'-'+component)
                pin_tool(result.stdout.strip())
        library=Path(run([cross,'-print-file-name=libkernel32.a'],'kernel32-library').stdout.strip()).resolve()
        assert library.is_file(); tools[str(library)]=digest(library)
        common=['-std=c11','-Wall','-Wextra','-Werror','-Wpedantic']
        for name,compiler,sources,includes in (
            ('gcc',gcc,[HERE/'probe.c',HERE/'tests/test_probe.c'],['-I',HERE/'tests/mock']),
            ('clang',clang,[HERE/'probe.c',HERE/'tests/test_probe.c'],['-I',HERE/'tests/mock']),
            ('native',cross,[HERE/'probe.c'],[])):
            for number,source in enumerate(sources):
                dep=out/(name+'-'+str(number)+'.d')
                run([compiler,*common,*includes,'-M','-MT','probe','-MF',dep,source],name+'-'+str(number)+'-dependencies')
                for word in shlex.split(dep.read_text().replace('\\\n',' ').split(':',1)[1]):
                    path=Path(word).resolve(); sdk[str(path)]=digest(path)
        host_pass=True
        for name,compiler,flags in (('gcc-host',gcc,['-O2']),('clang-asan',clang,['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
            binary=out/name
            run([compiler,*common,*flags,'-I',HERE/'tests/mock',HERE/'probe.c',HERE/'tests/test_probe.c','-o',binary],name+'-build')
            result=run([binary],name,check=False)
            host_pass=host_pass and result.returncode==0 and 'WinAPI modeled; no real cold boot' in result.stdout
        assert host_pass,'production probe host boundary controls failed'
        run([sys.executable,'-B','-m','unittest',HERE/'tests/test_runner.py','-v'],'owned-runner-controls')
        binary=out/'PERSCHK.EXE'
        run([cross,*common,'-Os','-march=i486','-mno-sse','-mno-mmx','-msoft-float','-ffreestanding','-fno-builtin',
             '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-tree-loop-distribute-patterns',
             HERE/'probe.c','-nostdlib','-Wl,--entry,_mainCRTStartup','-Wl,--subsystem,console:4.0',
             '-Wl,--major-os-version,4,--minor-os-version,0,--disable-dynamicbase,--disable-nxcompat,--no-insert-timestamp',
             '-lkernel32','-o',binary],'pe32-build')
        pe=pe_contract(binary); run([inspector,'--file-headers','--coff-imports',binary],'pe32-inspection')
        assert binary.stat().st_size==pe['bytes'] and digest(binary)==pe['sha256'],'PE artifact changed after parsing'
        resources(out); passed=True
    except (AssertionError,OSError,subprocess.SubprocessError,ValueError,RuntimeError,struct.error) as error:
        (out/'failure.txt').write_text(str(error)+'\n'); print(str(error),file=sys.stderr)
    after=source_pins(); tools_ok=all(Path(p).is_file() and digest(Path(p))==h for p,h in tools.items())
    sdk_ok=all(Path(p).is_file() and digest(Path(p))==h for p,h in sdk.items())
    artifact=out/'PERSCHK.EXE'
    pe_ok=pe is not None and artifact.is_file() and artifact.stat().st_size==pe['bytes'] and digest(artifact)==pe['sha256']
    passed=passed and before==after and tools_ok and sdk_ok and pe_ok
    report={'passed':passed,'scope':'production ANSI probe; host WinAPI modeled; actual PE32 compilation only',
            'actual_Windows_execution':False,'actual_cold_boot':False,'persistence_acceptance':False,'GUI_acceptance':False,
            'source_before':before,'source_after':after,'source_before_after_equal':before==after,'tools_sha256':tools,
            'SDK_dependencies_sha256':sdk,'tools_before_after_equal':tools_ok,'SDK_before_after_equal':sdk_ok,
            'PE_before_publication_equal':pe_ok,
            'tool_closure_scope':'compiler/assembler/linker executables, import library, observed SDK includes; host shared libraries not fully pinned',
            'resources':resource_samples,'runs':runs,'PE32':pe}
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS' if passed else 'FAIL',out/'result.json'); return 0 if passed else 1


if __name__=='__main__': sys.exit(main())
