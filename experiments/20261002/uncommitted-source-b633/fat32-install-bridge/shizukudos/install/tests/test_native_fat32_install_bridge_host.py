#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Selected typed bridge controls; no media, whole installer or VM execution.

The synthetic --legacy-control adapter omits relocation, with real stage
validation. Both modes use the same literal fixture. Compile-only COFF objects
do not establish linked setup closure. Per-file RLIMIT_FSIZE plus observed
aggregate checks are not a hard aggregate quota or a subprocess PIPE RAM cap.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import time

ROOT=Path(__file__).resolve().parents[3]
LEAF=ROOT/'build/native-fat32-install-bridge-v1'
SETUP=Path('shizukudos/win64/setup')
FADA=Path('/root/Win98-Modern-native-integrated-fada-20261002')
MIB=1024*1024
EXPECTED={
 FADA/SETUP/'native_install.h':'4db7a21fa40cc54b37b18e4029cbb5f7a72e6e30c3d9b5428ee341303e9996c9',
 FADA/SETUP/'plat.h':'4eda76b2df7a64aa6715f249e23e4c7c3793819c41449cab1423ac4b8baefdf4',
 ROOT/SETUP/'native_fat32_relocate.h':'51c0512711b1424ee560a984b96e609153c715883dc618eed62ee62ee9f78092',
 ROOT/SETUP/'native_fat32_relocate.c':'d24d566c122a4a51b8c8916eb362d056e8e3b56c21238c2858c2d8c2b4dd142a'}

def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def hashes(paths): return {str(p):digest(p) for p in paths}
def usage(): return sum(p.stat().st_size for p in LEAF.rglob('*') if p.is_file())
def group_live(pgid):
    live=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            f=(p/'stat').read_text().rsplit(')',1)[1].split()
            if int(f[2])==pgid and f[0] not in ('Z','X'): live.append(int(p.name))
        except FileNotFoundError: pass
    return live
def limits():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(4*MIB,4*MIB))

def owned(argv,seconds):
    r={'argv':list(map(str,argv)),'seconds':seconds,'returncode':None,'leader_reaped':False,
       'timed_out':False,'interrupted':False,'cleanup_failed':False,'error':None,
       'term_attempted':False,'kill_attempted':False,'live_group':[]}
    p=None; stdout=stderr=''; start=time.monotonic()
    def send(sig):
        r['term_attempted' if sig==signal.SIGTERM else 'kill_attempted']=True
        try: os.killpg(p.pid,sig)
        except ProcessLookupError: pass
        except OSError as e: r['cleanup_failed']=True; r['error']=str(e)
    try:
        env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',
                 TMPDIR=str(LEAF/'tmp'),TEMP=str(LEAF/'tmp'),TMP=str(LEAF/'tmp'))
        p=subprocess.Popen(r['argv'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors='replace',
                           start_new_session=True,preexec_fn=limits,env=env)
        r['pgid']=p.pid; stdout,stderr=p.communicate(timeout=seconds)
        r['live_group']=group_live(p.pid)
        if r['live_group']: r['cleanup_failed']=True
    except subprocess.TimeoutExpired: r['timed_out']=True
    except KeyboardInterrupt: r['interrupted']=True
    except Exception as e: r['error']=type(e).__name__+': '+str(e)
    finally:
        if p is not None and any((r['timed_out'],r['interrupted'],r['cleanup_failed'],r['error'],p.returncode not in (0,None))):
            send(signal.SIGTERM)
            try: stdout,stderr=p.communicate(timeout=.5)
            except subprocess.TimeoutExpired: pass
            except KeyboardInterrupt: r['interrupted']=True
            except Exception as e: r['cleanup_failed']=True; r['error']=str(e)
            finally: send(signal.SIGKILL)
            try: stdout,stderr=p.communicate(timeout=1.5)
            except (subprocess.TimeoutExpired,KeyboardInterrupt): r['cleanup_failed']=True
            except Exception as e: r['cleanup_failed']=True; r['error']=str(e)
        if p is not None:
            p.poll(); r['returncode']=p.returncode; r['leader_reaped']=p.returncode is not None
            try: r['live_group']=group_live(p.pid)
            except Exception as e: r['cleanup_failed']=True; r['error']=str(e)
            if r['live_group']: r['cleanup_failed']=True
        r['elapsed_seconds']=time.monotonic()-start
    r['normal']=r['leader_reaped'] and not any((r['timed_out'],r['interrupted'],r['cleanup_failed'],r['error']))
    return r,stdout,stderr

def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('--legacy-control',action='store_true')
    args=ap.parse_args(); out=LEAF/('red' if args.legacy_control else 'green')
    if out.exists(): raise SystemExit('fresh phase leaf required')
    out.mkdir(parents=True); (LEAF/'tmp').mkdir(exist_ok=True)
    r={'schema':'native-fat32-install-bridge-host/v1','status':'FAIL','mode':'synthetic-unrelocated' if args.legacy_control else 'actual-bridge',
       'records':[],'hosts':[],'objects':[],'errors':[],'scope':{'typed_callback':True,'whole_core_executed':False,
       'provider_wired':False,'media_or_disk_job':False,'native_Windows98':False,'VM':False,'ISO':False,
       'linked_consumer':False,'external_compiler_sysroot_closure':False},
       'caps':{'compile_seconds':60,'other_seconds':25,'term_seconds':.5,'kill_seconds':1.5,
               'core_bytes':0,'child_per_file_bytes':4*MIB,'observed_unit_bytes':16*MIB,'hard_aggregate_quota':False,'PIPE_RAM_bound':False}}
    sources={}; tools={}; frozen={}
    def execute(argv,name,seconds=25,accepted=(0,)):
        if usage()>16*MIB: raise ValueError('observed aggregate limit before command')
        if hashes(sources)!=r['source_before'] or hashes(frozen)!=r['frozen_before'] or hashes(tools)!=r['tool_before']:
            raise ValueError('input changed before command')
        rec,stdout,stderr=owned(argv,seconds); rec['name']=name
        r['records'].append(rec); (out/(name+'.stdout')).write_text(stdout); (out/(name+'.stderr')).write_text(stderr)
        if usage()>16*MIB: raise ValueError('observed aggregate limit after command')
        if not rec['normal'] or rec['returncode'] not in accepted: raise ValueError(name+' refused')
        return stdout
    try:
        own=[SETUP/'native_fat32_install_bridge.h',Path('shizukudos/install/tests/native_fat32_install_bridge_host.c'),
             Path('shizukudos/install/tests/test_native_fat32_install_bridge_host.py'),Path('shizukudos/win64/build.py')]
        if not args.legacy_control: own.append(SETUP/'native_fat32_install_bridge.c')
        sources={p:p.relative_to(ROOT if p.is_relative_to(ROOT) else FADA) for p in EXPECTED}
        sources.update({ROOT/p:p for p in own}); r['source_before']=hashes(sources)
        if any(r['source_before'][str(p)]!=want for p,want in EXPECTED.items()): raise ValueError('held dependency pin mismatch')
        for p,rel in sources.items():
            q=out/'frozen'/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_bytes(p.read_bytes()); frozen[q]=None
        r['frozen_before']=hashes(frozen)
        names=['gcc','clang','x86_64-w64-mingw32-gcc','i686-w64-mingw32-gcc',
               'x86_64-w64-mingw32-nm','i686-w64-mingw32-nm']
        for n in names:
            p=shutil.which(n)
            if p: tools[Path(p).resolve()]=None
            elif n in ('gcc','clang'): raise ValueError('required host compiler absent: '+n)
        r['tool_before']=hashes(tools); r['tool_names']={n:str(Path(shutil.which(n)).resolve()) for n in names if shutil.which(n)}
        setup=out/'frozen'/SETUP; fixture=out/'frozen/shizukudos/install/tests/native_fat32_install_bridge_host.c'
        units=[str(setup/'native_fat32_relocate.c')]
        if not args.legacy_control: units.append(str(setup/'native_fat32_install_bridge.c'))
        flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-I'+str(setup)]
        for name in ('gcc','clang'):
            exe=out/(name+'-host'); extra=['-DSHZ_BRIDGE_LEGACY'] if args.legacy_control else []
            if name=='clang': extra+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
            execute([r['tool_names'][name],*flags,*extra,'-MMD','-MF',str(out/(name+'.d')),str(fixture),*units,'-o',str(exe)],name+'-compile',60)
            text=execute([str(exe)],name+'-run',accepted=(1,) if args.legacy_control else (0,))
            m=re.fullmatch(r'BRIDGE checks=(\d+) failures=(\d+)\n',text)
            if not m: raise ValueError('host metrics absent')
            checks,failures=map(int,m.groups()); r['hosts'].append({'compiler':name,'checks':checks,'failures':failures})
            if (args.legacy_control and failures==0) or (not args.legacy_control and failures): raise ValueError('behavior control not observed')
        if not args.legacy_control:
            tree=ast.parse((out/'frozen/shizukudos/win64/build.py').read_text())
            common=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='COMMON' for t in n.targets))
            consumer=out/'typed-consumer.c'; consumer.write_text('#include "native_fat32_install_bridge.h"\nvoid bind_bridge(native_setup_ops_v1_t *o) { o->prepare_relocation=shz_native_fat32_install_prepare_relocation; }\n')
            r['generated_consumer_sha256']=digest(consumer)
            for arch,prefix,code in [('x64','x86_64',0x8664),('i386','i686',0x14c)]:
                cc=prefix+'-w64-mingw32-gcc'; nm=prefix+'-w64-mingw32-nm'
                if cc not in r['tool_names'] or nm not in r['tool_names']:
                    r.setdefault('unavailable_optional',[]).append(arch); continue
                for label,src in [('bridge',setup/'native_fat32_install_bridge.c'),('stage',setup/'native_fat32_relocate.c'),('consumer',consumer)]:
                    obj=out/(arch+'-'+label+'.o')
                    execute([r['tool_names'][cc],*common,'-I'+str(setup),'-MMD','-MF',str(obj)+'.d','-c',str(src),'-o',str(obj)],arch+'-'+label+'-compile',60)
                    text=execute([r['tool_names'][nm],'-u',str(obj)],arch+'-'+label+'-nm')
                    symbols=sorted(line.split()[-1].lstrip('_') for line in text.splitlines() if line.split())
                    allowed={'bridge':{'shz_native_fat32_relocate_stage'},'consumer':{'shz_native_fat32_install_prepare_relocation'},'stage':{'udivdi3'} if arch=='i386' else set()}[label]
                    if not set(symbols)<=allowed or int.from_bytes(obj.read_bytes()[:2],'little')!=code: raise ValueError('unexpected selected object contract')
                    r['objects'].append({'path':str(obj),'machine':arch,'undefined':symbols,'compile_only':True})
        r['status']='PASS'; r['red_control_observed']=args.legacy_control
    except BaseException as e:
        r['errors'].append(type(e).__name__+': '+str(e))
    finally:
        for key,paths in [('source',sources),('tool',tools),('frozen',frozen)]:
            try:
                r[key+'_after']=hashes(paths)
                if r[key+'_after']!=r.get(key+'_before',{}): r['status']='FAIL'; r['errors'].append(key+' changed')
            except Exception as e: r['status']='FAIL'; r['errors'].append(key+': '+str(e))
        r['artifacts']={str(p.relative_to(out)):{'bytes':p.stat().st_size,'sha256':digest(p)} for p in out.rglob('*') if p.is_file() and p.name!='result.json'}
        r['artifact_map_excludes']='result.json; final receipt self-hashed by caller'
        r['observed_unit_bytes']=usage()
        while True:
            raw=(json.dumps(r,sort_keys=True,indent=2)+'\n').encode(); total=usage()+len(raw)
            if total==r['observed_unit_bytes']: break
            r['observed_unit_bytes']=total
        if total>16*MIB:
            r['status']='FAIL'; r['errors'].append('observed aggregate limit including receipt exceeded')
            raw=(json.dumps(r,sort_keys=True,indent=2)+'\n').encode()
        (out/'result.json').write_bytes(raw)
    print(json.dumps({'status':r['status'],'mode':r['mode'],'hosts':r['hosts'],'objects':r['objects'],'errors':r['errors'],'receipt':str(out/'result.json')}))
    return 0 if r['status']=='PASS' and not args.legacy_control else 1

if __name__=='__main__': raise SystemExit(main())
