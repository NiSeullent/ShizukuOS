#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded actual GUI route checks and separate freestanding source compiles.

No guest, GUI execution, media, install or network. One new build directory only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import time
ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'shizukudos'
LIMIT=16*1024*1024
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',required=True,type=Path)
    parser.add_argument('--host-only',action='store_true',help='run actual source routes; combined unit compilation is verified separately')
    args=parser.parse_args();out=args.out;out=(out if out.is_absolute() else ROOT/out).absolute()
    if out.exists() or not out.parent.is_dir() or not any(out.resolve().is_relative_to(base) for base in (ROOT/'build',Path('/dev/shm'))):
        raise SystemExit('one new output directory under build/ or /dev/shm, existing parent required')
    if shutil.disk_usage(out.parent).free<64*1024*1024:raise SystemExit('64 MiB bounded build admission refused')
    out.mkdir();commands=[];paths={Path(__file__).resolve()};frozen={};tools={}
    result={'passed':False,'scope':'actual GUI source routes with kernel boundaries mocked'+(' only; freestanding compilation verified separately' if args.host_only else '; freestanding objects only'),
            'guest_executed':False,'Windows98_executed':False,'secure_desktop_verified':False,'external_toolchain_closure_complete':False}
    result['host_only']=args.host_only
    def bound():
        if sum(p.stat().st_size for p in out.iterdir() if p.is_file())>LIMIT:raise RuntimeError('16 MiB output bound exceeded')
    def run(argv,label):
        bound();env=dict(os.environ,TMPDIR=str(out),PYTHONDONTWRITEBYTECODE='1',ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
        for key in ('CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','LIBRARY_PATH','COMPILER_PATH','GCC_EXEC_PREFIX'):env.pop(key,None)
        began=time.monotonic();p=subprocess.Popen(list(map(str,argv)),cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        selector=selectors.DefaultSelector();selector.register(p.stdout,selectors.EVENT_READ,0);selector.register(p.stderr,selectors.EVENT_READ,1)
        data=[bytearray(),bytearray()];error=None
        try:
            while True:
                exited=os.waitid(os.P_PID,p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                if exited and not selector.get_map():break
                if time.monotonic()-began>120:raise RuntimeError('120-second owned command deadline')
                bound()
                for key,_ in selector.select(.05):
                    block=os.read(key.fileobj.fileno(),8192)
                    if not block:selector.unregister(key.fileobj)
                    else:
                        data[key.data].extend(block)
                        if sum(map(len,data))>512*1024:raise RuntimeError('bounded command log exceeded')
            p.wait(timeout=5)
        except BaseException as problem:
            error=str(problem)
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=5);raise
        finally:
            selector.close();p.stdout.close();p.stderr.close()
            commands.append({'argv':list(map(str,argv)),'label':label,'returncode':p.returncode,'reaped':p.returncode is not None,'seconds':time.monotonic()-began,'error':error})
            for i,suffix in enumerate(('stdout','stderr')):(out/(label+'.'+suffix)).write_bytes(data[i])
        if p.returncode or data[1]:raise RuntimeError(label+' failed or wrote diagnostics')
        return bytes(data[0])
    host=['-std=c11','-Wall','-Wextra','-Werror','-ffunction-sections','-fdata-sections','-Wl,--gc-sections']
    native=['-m64','-march=x86-64','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin',
            '-fno-pic','-fno-pie','-mcmodel=kernel','-mno-red-zone','-mgeneral-regs-only','-fno-stack-protector',
            '-fno-asynchronous-unwind-tables','-fno-ident','-fno-common','-fwrapv','-fno-strict-aliasing']
    gui=[HERE/'kernel64'/name for name in ('gfx_wm.c','gfx_msg.c','gfx_input.c')]
    sources=[HERE/'tests/test_gfx_auth.c',HERE/'accounts/account.c']
    def closure(phase):
        found=set(paths)
        for cc in tools.values():
            units=[(s,host) for s in sources]
            if not args.host_only:units += [(s,native+extra) for extra in ([],['-DSHZ_STANDALONE']) for s in gui]
            for i,(src,flags) in enumerate(units):
                flags=[v for v in flags if not v.startswith('-Wl,')]
                dep=run([cc['path'],*flags,'-MM','-MT','fixture',src],'deps-'+phase+'-'+cc['name']+'-'+str(i)).decode()
                for word in shlex.split(dep.replace('\\\n',' ').split(':',1)[1]):
                    path=Path(word);path=(path if path.is_absolute() else ROOT/path).resolve(strict=True);path.relative_to(ROOT);found.add(path)
        return found
    def hashes(selected):return {str(p.relative_to(ROOT)):digest(p) for p in sorted(selected)}
    try:
        for name in ('gcc','clang'):
            p=Path(shutil.which(name) or '').resolve(strict=True)
            if not p.is_file():raise RuntimeError('missing '+name)
            tools[name]={'name':name,'path':str(p),'sha256':digest(p),'version':run([p,'--version'],name+'-version').decode().splitlines()[0]}
        paths=closure('before');frozen=hashes(paths)
        result['host_tests']={}
        for name,compiler,flags in [('gcc-strict','gcc',['-O2']),('gcc-san','gcc',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie']),
                                    ('clang-san','clang',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])]:
            if hashes(paths)!=frozen:raise RuntimeError('input drift before '+name)
            exe=out/name
            if name=='gcc-san':
                # Compiler health only; never counted as a production test.
                probe=out/'gcc-sanitizer-probe.c';probe.write_text('int main(void){return 0;}\n')
                try:run([tools[compiler]['path'],*host,*flags,probe,'-o',out/'gcc-sanitizer-probe'],name+'-runtime-probe')
                except RuntimeError:
                    diagnostics=(out/(name+'-runtime-probe.stderr')).read_text()
                    missing=re.findall(r'cannot find (\S+): No such file or directory',diagnostics)
                    if not missing or any(Path(p).exists() or not Path(p).name.startswith(('libasan.so','libubsan.so')) for p in missing):raise
                    result['host_tests'][name]={'status':'BLOCKED_NOT_RUN','missing_runtime_paths':missing,'diagnostics':diagnostics,'runtime_probe_only':True}
                    continue
            run([tools[compiler]['path'],*host,*flags,*sources,'-o',exe],name+'-compile')
            before=digest(exe)
            text=run([exe],name+'-test').decode()
            if not text.startswith('PASS:') or digest(exe)!=before:raise RuntimeError('invalid verdict or binary drift')
            result['host_tests'][name]={'status':'PASS','verdict':text,'binary_sha256':before}
        for name,tool in ([] if args.host_only else tools.items()):
            for profile,extra in [('bridge',[]),('standalone',['-DSHZ_STANDALONE'])]:
                for src in gui:
                    if hashes(paths)!=frozen:raise RuntimeError('input drift before native source')
                    run([tool['path'],*native,*extra,'-I',HERE,'-I',HERE/'kernel64','-c',src,'-o',out/(name+'-'+profile+'-'+src.stem+'.o')],name+'-'+profile+'-'+src.stem)
        after=closure('after')
        if after!=paths or hashes(after)!=frozen or any(digest(Path(v['path']))!=v['sha256'] for v in tools.values()):raise RuntimeError('source/tool closure drift')
        result.update(passed=True,sources_sha256=frozen,project_include_closure_complete=True,tools=tools,source_before_after_match=True)
    except BaseException as failure:
        result['failure']=str(failure);raise
    finally:
        result['commands']=commands;result['sources_sha256_initial']=frozen
        result['artifacts_sha256']={p.name:digest(p) for p in out.iterdir() if p.is_file()}
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');bound()
    print('PASS: actual GUI source authorization routes'+('' if args.host_only else ' and GCC/Clang freestanding objects')+'; guest not run')
if __name__=='__main__':main()
