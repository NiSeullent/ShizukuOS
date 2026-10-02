#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Source-bound native AP dispatcher host controls; no guest or AP execution."""
import argparse
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import time
import shutil
import subprocess
import sys
# Owned session/group cleanup reused verbatim from approved adcf9a707675... helper.
CLEANUP_SECONDS = 2.0

def group_members(pgid):
    """Only the new session/group created for this invocation is owned."""
    members = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
            if int(fields[2]) == pgid and int(fields[3]) == pgid:
                members[int(entry.name)] = {'state': fields[0], 'start': fields[19]}
        except (OSError, IndexError, ValueError):
            continue
    return members

def run_owned(argv, timeout=60):
    """Bound work separately from a <=2s owned-group cleanup/drain/reap.

    Linux subreaping applies only to this host runner process. No shared group
    or unrelated child is signaled/reaped. A terminal parent is insufficient:
    even successful parents may leave children or inherited output pipes.
    """
    proc = None
    output, errors = b'', b''
    timed_out = False
    infrastructure_error = None
    cleanup = {'passed': False, 'limit_seconds': CLEANUP_SECONDS, 'signals': [],
               'reaped_descendants': [], 'owned_pgid': None, 'group_empty': False,
               'drain_complete': False, 'direct_reaped': False}
    leader_start = None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), 'cannot enable local child subreaper')
        proc = subprocess.Popen(list(map(str, argv)), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        cleanup['owned_pgid'] = proc.pid
        leader_start = group_members(proc.pid).get(proc.pid, {}).get('start')
        output, errors = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        output, errors = error.output or b'', error.stderr or b''
    except BaseException as error:
        infrastructure_error = repr(error)
    finally:
        if proc is not None:
            started = time.monotonic()
            deadline = started + CLEANUP_SECONDS
            pgid = proc.pid
            def members():
                found = group_members(pgid)
                # Never signal a reused session leader with a different start.
                if pgid in found and leader_start is not None and found[pgid]['start'] != leader_start:
                    raise RuntimeError('owned group identity changed; refused group signal')
                return found
            def live():
                return {pid: state for pid, state in members().items() if state['state'] != 'Z'}
            try:
                cleanup['descendants_observed'] = sorted(pid for pid in members() if pid != pgid)
                if live():
                    try:
                        os.killpg(pgid, signal.SIGTERM)
                        cleanup['signals'].append('TERM')
                    except ProcessLookupError:
                        pass
                    grace = min(deadline, time.monotonic() + 0.15)
                    while live() and time.monotonic() < grace:
                        time.sleep(0.01)
                if live():
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                        cleanup['signals'].append('KILL')
                    except ProcessLookupError:
                        pass
                try:
                    output, errors = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
                    cleanup['drain_complete'] = True
                except subprocess.TimeoutExpired as error:
                    output, errors = error.output or output, error.stderr or errors
                    for stream in (proc.stdout, proc.stderr):
                        if stream is not None:
                            stream.close()
                    proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                cleanup['direct_reaped'] = proc.returncode is not None
                while time.monotonic() < deadline:
                    # Negative PID waits only for children in OUR group. The
                    # direct child was reaped by communicate/wait above.
                    while True:
                        try:
                            pid, status = os.waitpid(-pgid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if not pid:
                            break
                        cleanup['reaped_descendants'].append({'pid': pid, 'status': status})
                    if not members():
                        break
                    time.sleep(0.01)
                cleanup['remaining_group_pids'] = sorted(members())
                cleanup['group_empty'] = not cleanup['remaining_group_pids']
                cleanup['passed'] = (cleanup['group_empty'] and cleanup['drain_complete'] and
                                     cleanup['direct_reaped'])
            except BaseException as error:
                cleanup['error'] = repr(error)
                # Best-effort bounded recovery still uses only the owned identity.
                # A cleanup error remains a rejected invocation even if recovery succeeds.
                try:
                    if live():
                        os.killpg(pgid, signal.SIGKILL)
                        cleanup['signals'].append('KILL-recovery')
                except (OSError, RuntimeError):
                    pass
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
                try:
                    proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                    cleanup['direct_reaped'] = True
                    while time.monotonic() < deadline:
                        try:
                            pid, status = os.waitpid(-pgid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if pid:
                            cleanup['reaped_descendants'].append({'pid': pid, 'status': status})
                        elif not members():
                            break
                        else:
                            time.sleep(0.01)
                    cleanup['remaining_group_pids'] = sorted(members())
                    cleanup['group_empty'] = not cleanup['remaining_group_pids']
                except BaseException as recovery_error:
                    cleanup['recovery_error'] = repr(recovery_error)
            cleanup['seconds'] = round(time.monotonic() - started, 3)
        else:
            cleanup.update(passed=True, group_empty=True, drain_complete=True,
                           direct_reaped=True, seconds=0, remaining_group_pids=[])
    decode = lambda value: value.decode(errors='replace') if isinstance(value, bytes) else value or ''
    return {'argv': list(map(str, argv)), 'exit_code': None if timed_out else
            125 if infrastructure_error or not cleanup['passed'] else proc.returncode,
            'parent_exit_code': proc.returncode if proc is not None else None,
            'stdout': decode(output), 'stderr': decode(errors), 'timed_out': timed_out,
            'infrastructure_error': infrastructure_error, 'cleanup': cleanup}

ROOT=Path(__file__).resolve().parents[2]
def sha(data): return hashlib.sha256(data).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--cc',choices=['gcc','clang'],required=True)
    parser.add_argument('--sanitize',action='store_true')
    parser.add_argument('--compile-units',action='store_true')
    args=parser.parse_args();out=args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'build'): parser.error('fresh local build output required')
    out.mkdir(parents=True);snapshot=out/'source'
    units=[ROOT/'shizukudos/tests/test_k64_ap_dispatch_arch.c']
    for name in ('context','entry'):
        p=ROOT/('shizukudos/tests/test_k64_ap_dispatch_'+name+'.c')
        if p.is_file(): units.append(p)
    production=[ROOT/('shizukudos/kernel64/'+name+'.c') for name in ('sched','arch','cpu_arch_bringup','cpu_bringup')] if args.compile_units else []
    sources={};pending=[*units,*production,*([ROOT/'shizukudos/kbuild.py'] if production else []),Path(__file__).resolve(),ROOT/'shizukudos/kernel64/start.asm',*(ROOT/'shizukudos/kernel64').glob('user_*.asm')]
    while pending:
        p=pending.pop().resolve()
        if not p.is_relative_to(ROOT): raise RuntimeError('project include escape')
        rel=str(p.relative_to(ROOT))
        if rel in sources:continue
        data=p.read_bytes();sources[rel]=data
        pending.extend(p.parent/name.decode() for name in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"',data,re.M))
    before={p:sha(data) for p,data in sorted(sources.items())}
    for rel,data in sources.items():
        p=snapshot/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    cc=Path(shutil.which(args.cc)).resolve();tools={str(cc):sha(cc.read_bytes())}
    assembly_tools={name:Path(shutil.which(name)).resolve() for name in ('nasm','objcopy','objdump')}
    tools.update({str(p):sha(p.read_bytes()) for p in assembly_tools.values()})
    commands=[];artifacts={}
    def stable():
        return all((ROOT/p).read_bytes()==data and (snapshot/p).read_bytes()==data for p,data in sources.items()) and all(sha(Path(p).read_bytes())==h for p,h in tools.items()) and all(sha((out/p).read_bytes())==h for p,h in artifacts.items())
    def run(argv,label,timeout=60):
        if not stable():raise RuntimeError('captured input drift before command')
        owned=run_owned(argv,timeout)
        rc=124 if owned['timed_out'] else owned['exit_code']
        proc=subprocess.CompletedProcess(list(map(str,argv)),rc,owned['stdout'],owned['stderr'])
        (out/(label+'.log')).write_text(proc.stdout+proc.stderr)
        commands.append({'argv':list(map(str,argv)),'label':label,'exit':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr,'timeout':timeout,'owned_cleanup':owned['cleanup'],'timed_out':owned['timed_out']})
        return proc
    for name in ('cc1','collect2','as','ld'):
        r=run([cc,'-print-prog-name='+name],'tool-'+name,10);r.check_returncode();s=r.stdout.strip()
        p=Path(s).resolve() if '/' in s else Path(shutil.which(s)).resolve() if shutil.which(s) else None
        if p and p.is_file():tools[str(p)]=sha(p.read_bytes())
        elif args.cc!='clang' or name not in ('cc1','collect2'):raise RuntimeError('missing compiler subtool')
    (out/'before.json').write_text(json.dumps({'sources':before,'tools':tools,'capture_before_dependency_or_compile':True},indent=2)+'\n')
    flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fno-pie','-no-pie','-fno-builtin','-ffunction-sections','-fdata-sections','-pthread','-Wl,--gc-sections']
    if args.sanitize:flags+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    dependencies={};results=[]
    if any(p.stem.endswith('_entry') for p in units):
        for rel in sorted(before):
            if rel.endswith('.asm') and Path(rel).name.startswith('user_'):
                dest=out/(Path(rel).stem+'.bin');run([assembly_tools['nasm'],'-f','bin',snapshot/rel,'-o',dest],Path(rel).stem).check_returncode();artifacts[dest.name]=sha(dest.read_bytes())
        start=out/'start.o';run([assembly_tools['nasm'],'-f','elf64','-I',str(out)+'/',snapshot/'shizukudos/kernel64/start.asm','-o',start],'start-assemble').check_returncode();artifacts[start.name]=sha(start.read_bytes())
        linked=out/'start-host.o';run([assembly_tools['objcopy'],'--redefine-sym','_start=kernel_test_start',start,linked],'start-rename').check_returncode();artifacts[linked.name]=sha(linked.read_bytes())
        run([assembly_tools['objdump'],'-dr','-M','intel',start],'start-disassembly').check_returncode()
    for unit in units:
        rel=str(unit.relative_to(ROOT));name=unit.stem
        extra=['-mgeneral-regs-only'] if name.endswith('_arch') else []
        r=run([cc,'-std=gnu11',*extra,'-MM',snapshot/rel],name+'-MM');r.check_returncode()
        deps=[]
        for token in shlex.split(r.stdout.replace('\\\n',' ').split(':',1)[1]):
            p=Path(token).resolve()
            if not p.is_relative_to(snapshot):raise RuntimeError('uncaptured compiler project input')
            item=str(p.relative_to(snapshot))
            if item not in before or sha(p.read_bytes())!=before[item]:raise RuntimeError('compiler input mismatch')
            deps.append(item)
        dependencies[name]=sorted(set(deps))
        exe=out/name
        linked_input=[out/'start-host.o','-Wl,-z,noexecstack'] if name.endswith('_entry') else []
        unit_flags=[f for f in flags if not f.startswith('-fsanitize') and f!='-fno-sanitize-recover=all'] if name.endswith('_entry') else flags
        r=run([cc,*unit_flags,*extra,snapshot/rel,*linked_input,'-o',exe],name+'-compile')
        if r.returncode:results.append({'unit':name,'exit':r.returncode,'stage':'compile'});continue
        artifacts[name]=sha(exe.read_bytes());r=run([exe],name+'-run')
        expected={'test_k64_ap_dispatch_arch':17,'test_k64_ap_dispatch_context':10,'test_k64_ap_dispatch_entry':7}[name]
        summary=re.findall(r'^checks=(\d+) failures=(\d+) scope=([^\n]+)$',r.stdout,re.M)
        complete=len(summary)==1 and int(summary[0][0])==expected and int(summary[0][1])==0 and not r.stderr
        results.append({'unit':name,'exit':r.returncode if r.returncode else 0 if complete else 125,'actual_exit':r.returncode,'summary_complete':complete,'expected_checks':expected,'stage':'actual-host','scope':'CPU instructions/table facts/stack boundaries adapted; no AP'})
        print(r.stdout,end='')
    unit_results=[];unit_dependencies={};external_headers={}
    if production:
        tree=ast.parse(sources['shizukudos/kbuild.py'].decode())
        kernel_flags=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='K64_FLAGS' for t in node.targets))
        if args.cc=='clang':kernel_flags=[f for f in kernel_flags if f!='-fno-tree-loop-distribute-patterns']
        for profile,defines in [('supervisor',[]),('standalone',['-DSHZ_STANDALONE'])]:
            for unit in production:
                label=profile+'-'+unit.stem;rel=str(unit.relative_to(ROOT))
                options=[*kernel_flags,*defines,'-I',snapshot/'shizukudos','-I',snapshot/'shizukudos/kernel64']
                r=run([cc,*options,'-M',snapshot/rel],label+'-dependencies');r.check_returncode()
                deps={}
                for token in shlex.split(r.stdout.replace('\\\n',' ').split(':',1)[1]):
                    p=Path(token).resolve()
                    if p.is_relative_to(snapshot):
                        item=str(p.relative_to(snapshot))
                        if item not in before or sha(p.read_bytes())!=before[item]:raise RuntimeError('changed-unit uncaptured project dependency')
                        deps[item]=before[item]
                    else:external_headers[str(p)]=sha(p.read_bytes())
                unit_dependencies[label]=deps
                if not all(sha(Path(p).read_bytes())==h for p,h in external_headers.items()):raise RuntimeError('changed-unit external header drift')
                obj=out/(label+'.o');r=run([cc,*options,'-c',snapshot/rel,'-o',obj],label+'-compile')
                unit_results.append({'unit':label,'exit':r.returncode,'warnings':r.stderr,'actual_flags':options[:-4]})
                if not r.returncode:artifacts[obj.name]=sha(obj.read_bytes())
        results.extend({'unit':u['unit'],'exit':u['exit'] if not u['warnings'] else 125,'stage':'freestanding-compile-only'} for u in unit_results)
    unchanged=stable() and all(sha((out/p).read_bytes())==h for p,h in artifacts.items()) and all(sha(Path(p).read_bytes())==h for p,h in external_headers.items())
    result={'status':'PASS' if unchanged and len(results)==len(units)+len(unit_results) and all(r['exit']==0 for r in results) else 'FAIL','results':results,'sources_before':before,'sources_after':{p:sha((ROOT/p).read_bytes()) for p in before},'tools_before':tools,'tools_after':{p:sha(Path(p).read_bytes()) for p in tools},'compiler_project_dependencies':dependencies,'freestanding_dependencies':unit_dependencies,'freestanding_units':unit_results,'external_header_hashes':external_headers,'commands':commands,'artifacts':artifacts,'inputs_stable':unchanged,'external_environment_sealed':False,'guest_executed':False,'physical_ap_executed':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    total=sum(p.stat().st_size for d in (ROOT/'build').glob('k64-ap-dispatch*') for p in ([d] if d.is_file() else d.rglob('*')) if p.is_file())
    if total>96<<20:raise RuntimeError('96MiB lane cap')
    print('STATUS',result['status'],'bytes',total)
    return result['status']!='PASS'
if __name__=='__main__':raise SystemExit(main())
