#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Owned bounded host proofs and real i486/native import audit. No VM or install.

python3 -B ntwddm/win98/personalization/verify.py --out build/personalization-fd5c/final
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import sys
import subprocess
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
LIMIT=16*1024*1024
SOURCES=('native.c','core.c','core.h','store.c','store.h','profile.c','profile.h','mock/windows.h','mock/shlobj.h','test_core.c','test_store.c','test_profile.c','test_html.js','verify.py','verify_agent.py','desktop_agent.c','desktop_agent.h','desktop_agent_core.c','test_desktop_agent.c',
         'agent_ctl.c','agent_ctl.h','chrome_core.c','chrome_core.h','chrome_native.c','chrome_native.h','test_chrome.c','retro_core.c','retro_core.h','test_retro.c')
SHARED=('ntwddm/win98/adapter.c','ntwddm/win98/adapter.h','ntwddm/src/ntwddm.c',
        'ntwddm/include/ntwddm.h','platform/freestanding/memory.c','platform/freestanding/memory.h',
        'ntwin32/prepare.py','ntwddm/win98/theme_selector/selector_core.c','ntwddm/win98/theme_selector/selector_core.h',
        'ntwddm/win98/theme_selector/native_backend.c','ntwddm/win98/theme_selector/native_backend.h',
        'ntwddm/win98/theme_selector/native_backend_test.c','ntwddm/win98/theme_selector/mock/windows.h',
        'benchmarks/win98se-ko-oem-native-exports-v1.json')

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def relative(path):return str(path.relative_to(ROOT))
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    output=parser.parse_args().out
    if not output.is_absolute():output=ROOT/output
    output=output.absolute()
    if output.exists() or not output.parent.is_dir() or not output.resolve().is_relative_to(ROOT/'build'):
        raise SystemExit('one new owned directory under build/ with an existing parent is required')
    if shutil.disk_usage(ROOT).free<64*1024*1024:raise SystemExit('64 MiB bounded build admission refused')
    initial={relative(HERE/name):digest(HERE/name) for name in SOURCES}
    initial.update({name:digest(ROOT/name) for name in SHARED})
    output.mkdir()
    commands=[];tools={};dependencies=set();result={'passed':False,'scope':'host/pure-source and PE32 compile only',
       'native_Windows98_executed':False,'wallpaper_applied':False,'Explorer_verified':False,
       'native_theme_applied':False,'cold_start_theme_restored':False}

    def bounded():
        total=sum(p.stat().st_size for p in output.iterdir() if p.is_file())
        if total>LIMIT:raise RuntimeError('16 MiB owned output bound exceeded')

    def run(argv,label):
        bounded()
        environment=dict(os.environ,TMPDIR=str(output),PYTHONDONTWRITEBYTECODE='1',
                         ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
        for name in ('CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','LIBRARY_PATH','COMPILER_PATH','GCC_EXEC_PREFIX'):
            environment.pop(name,None)
        begin=time.monotonic();child=subprocess.Popen(argv,cwd=ROOT,env=environment,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        streams=selectors.DefaultSelector();streams.register(child.stdout,selectors.EVENT_READ,0);streams.register(child.stderr,selectors.EVENT_READ,1)
        captured=[bytearray(),bytearray()];error=None
        try:
            while True:
                exited=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if exited and not streams.get_map():break
                if time.monotonic()-begin>60:raise RuntimeError('60-second owned command deadline')
                bounded()
                for key,_ in streams.select(.05):
                    block=os.read(key.fileobj.fileno(),8192)
                    if not block:streams.unregister(key.fileobj)
                    else:
                        captured[key.data].extend(block)
                        if sum(map(len,captured))>512*1024:raise RuntimeError('bounded command output exceeded')
            child.wait(timeout=5)
        except BaseException as failure:
            error=str(failure)
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=5)
            raise
        finally:
            streams.close();child.stdout.close();child.stderr.close()
            commands.append({'argv':list(map(str,argv)),'label':label,'returncode':child.returncode,
                             'leader_reaped':child.returncode is not None,'error':error,'seconds':time.monotonic()-begin})
            for index,suffix in enumerate(('stdout','stderr')):(output/(label+'.'+suffix)).write_bytes(captured[index])
        if child.returncode or captured[1]:raise RuntimeError(label+' did not finish cleanly')
        return bytes(captured[0])

    try:
        for name in ('gcc','clang','i686-w64-mingw32-gcc','node'):
            path=Path(shutil.which(name) or '').resolve(strict=True)
            if not path.is_file():raise RuntimeError('missing '+name)
            tools[name]={'path':str(path),'sha256':digest(path),'version':run([str(path),'--version'],name+'-version').decode().splitlines()[0]}
        for label,compiler,flags in (('gcc','gcc',['-O2']),('clang','clang',['-O1','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])):
            executable=output/('core-'+label)
            run([tools[compiler]['path'],'-std=c11','-Wall','-Wextra','-Werror',*flags,str(HERE/'core.c'),str(HERE/'test_core.c'),'-o',str(executable)],label+'-compile')
            before=digest(executable)
            data=run([str(executable)],label+'-test').decode()
            if not data.startswith('PASS:') or before!=digest(executable):raise RuntimeError('core verdict/binary changed')
            executable=output/('store-'+label)
            run([tools[compiler]['path'],'-std=c11','-Wall','-Wextra','-Werror',*flags,'-I'+str(HERE/'mock'),
                 str(HERE/'core.c'),str(HERE/'store.c'),str(HERE/'test_store.c'),'-o',str(executable)],label+'-store-compile')
            before=digest(executable)
            data=run([str(executable)],label+'-store-test').decode()
            if not data.startswith('PASS:') or before!=digest(executable):raise RuntimeError('store verdict/binary changed')
            executable=output/('profile-'+label)
            run([tools[compiler]['path'],'-std=c11','-Wall','-Wextra','-Werror',*flags,'-I'+str(HERE/'mock'),
                 str(HERE/'profile.c'),str(HERE/'test_profile.c'),'-o',str(executable)],label+'-profile-compile')
            before=digest(executable)
            data=run([str(executable)],label+'-profile-test').decode()
            if not data.startswith('PASS:') or before!=digest(executable):raise RuntimeError('profile verdict/binary changed')
            executable=output/('chrome-'+label)
            run([tools[compiler]['path'],'-std=c11','-Wall','-Wextra','-Werror',*flags,
                 str(HERE/'chrome_core.c'),str(HERE/'test_chrome.c'),'-o',str(executable)],label+'-chrome-compile')
            if not run([str(executable)],label+'-chrome-test').decode().startswith('chrome core ok'):raise RuntimeError('chrome verdict')
            executable=output/('retro-'+label)
            run([tools[compiler]['path'],'-std=c11','-Wall','-Wextra','-Werror',*flags,
                 str(HERE/'retro_core.c'),str(HERE/'test_retro.c'),'-o',str(executable)],label+'-retro-compile')
            if not run([str(executable)],label+'-retro-test').decode().startswith('retro core ok'):raise RuntimeError('retro verdict')
            theme=HERE.parent/'theme_selector'
            executable=output/('theme-backend-'+label)
            run([tools[compiler]['path'],'-std=c11','-Wall','-Wextra','-Werror',*flags,'-I'+str(theme/'mock'),
                 str(theme/'selector_core.c'),str(theme/'native_backend.c'),str(theme/'native_backend_test.c'),
                 '-o',str(executable)],label+'-theme-backend-compile')
            before=digest(executable)
            data=run([str(executable)],label+'-theme-backend-test').decode()
            if not data.startswith('PASS:') or before!=digest(executable):raise RuntimeError('theme backend verdict/binary changed')
        agent_out=output/'agent'
        agent_text=run([sys.executable,'-B',str(HERE/'verify_agent.py'),str(agent_out)],'wallpaper-agent').decode()
        if 'SHZWALL.EXE sha256=' not in agent_text:raise RuntimeError('wallpaper agent verdict missing')
        html=run([str(output/'core-gcc'),'--html'],'html-generate');(output/'wallpaper.htm').write_bytes(html)
        run([tools['node']['path'],str(HERE/'test_html.js'),str(output/'wallpaper.htm')],'html-behavior')
        compiler=tools['i686-w64-mingw32-gcc']['path']
        flags=['-std=c11','-Os','-Wall','-Wextra','-Werror','-march=i486','-mno-sse','-mno-mmx','-msoft-float',
               '-fno-stack-protector','-fno-builtin','-ffreestanding','-nostdlib','-Intwddm/include']
        native_sources=[HERE/'native.c',HERE/'core.c',HERE/'store.c',HERE/'profile.c',HERE/'agent_ctl.c',HERE/'desktop_agent_core.c',HERE/'chrome_core.c',HERE/'chrome_native.c',HERE/'retro_core.c',
                        theme/'selector_core.c',theme/'native_backend.c',
                        ROOT/'ntwddm/win98/adapter.c',ROOT/'ntwddm/src/ntwddm.c',ROOT/'platform/freestanding/memory.c']
        for index,source in enumerate(native_sources):
            raw=run([compiler,*flags,'-MM',str(source)],'native-deps-'+str(index)).decode()
            words=raw.replace('\\\n',' ').split(':',1)[1].split()
            for word in words:
                path=Path(word);path=path if path.is_absolute() else ROOT/path
                dependencies.add(relative(path.resolve(strict=True)))
        if not dependencies<=set(initial):raise RuntimeError('compiled project dependency omitted from frozen input set: '+str(dependencies-set(initial)))
        library=Path(run([compiler,'-print-libgcc-file-name'],'libgcc-path').decode().strip()).resolve(strict=True)
        library_hash=digest(library)
        executable=output/'SHZPERS.EXE'
        run([compiler,*flags,'-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,10',
             '-Wl,--entry,_WinMainCRTStartup@0','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--no-insert-timestamp',
             *map(str,native_sources),'-lkernel32','-luser32','-lgdi32','-lole32','-lshell32','-ladvapi32','-lgcc','-o',str(executable)],'native-link')
        spec=importlib.util.spec_from_file_location('pz98_pe',ROOT/'ntwin32/prepare.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);pe=module.PE(executable.read_bytes())
        exports=json.loads((ROOT/SHARED[-1]).read_bytes())['dlls'];imports={}
        for entry in pe.imports():
            dll=entry['dll'].upper();names=[item[1] for item in entry['entries']]
            if dll not in ('KERNEL32.DLL','USER32.DLL','GDI32.DLL','OLE32.DLL','SHELL32.DLL','ADVAPI32.DLL') or any(n not in exports[dll] for n in names):
                raise RuntimeError('import absent from actual Win98 native export inventory: '+str(entry))
            imports[dll]=names
        if set(imports)!=set(('KERNEL32.DLL','USER32.DLL','GDI32.DLL','OLE32.DLL','SHELL32.DLL','ADVAPI32.DLL')):raise RuntimeError('unexpected native import boundary')
        if 'SetSysColors' not in imports['USER32.DLL'] or not {'RegSetValueExA','RegQueryValueExA','RegFlushKey'}<=set(imports['ADVAPI32.DLL']):
            raise RuntimeError('actual native theme mutation/readback imports missing')
        if pe.u16(pe.opt+68)!=2 or (pe.u16(pe.opt+48),pe.u16(pe.opt+50))!=(4,10) or pe.u16(pe.pe+4)!=0x14c:
            raise RuntimeError('not native GUI PE32 4.10')
        pe.offset(pe.u32(pe.opt+16))
        for directory in (4,9,10,13,14):
            if any(pe.directory(directory)):raise RuntimeError('unexpected PE security/TLS/load-config/delay/CLR directory')
        if any(digest(ROOT/name)!=value for name,value in initial.items()):raise RuntimeError('frozen source drift')
        if digest(library)!=library_hash or any(digest(Path(v['path']))!=v['sha256'] for v in tools.values()):raise RuntimeError('observed tool/library drift')
        result.update(passed=True,sources_sha256=initial,compiler_project_dependencies=sorted(dependencies),imports=imports,
                      tools=tools,libgcc={'path':str(library),'sha256':library_hash},
                      executable={'file':str(executable),'sha256':digest(executable),'bytes':executable.stat().st_size},
                      source_before_after_match=True,external_toolchain_closure_complete=False)
    finally:
        result['commands']=commands
        result['artifact_sha256']={p.name:digest(p) for p in output.iterdir() if p.is_file()}
        (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        bounded()
    print('PASS: personalization core/store/profile/theme, offline script and native i486 PE32/import compile; Windows not executed')
if __name__=='__main__':main()
