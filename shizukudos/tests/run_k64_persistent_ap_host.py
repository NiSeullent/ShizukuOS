#!/usr/bin/env python3
"""Bounded source-bound actual-C controls; no guest or physical AP execution."""
import sys
sys.dont_write_bytecode=True
import argparse,ast,ctypes,hashlib,json,os,re,shlex,shutil,signal,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OWNER_SHA='adcf9a70767541d6fdeb47146bce72f3e3e349a05595d539091d2a7627e2fe4f'
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def function(data,name):
    match=re.search(r'^[A-Za-z_][^\n;{}]*\b'+re.escape(name)+r'\([^;]*?\)\s*\{',data,re.M)
    if not match:raise RuntimeError('missing actual function '+name)
    start=match.start();i=match.end();depth=1
    while depth:
        depth+=(data[i]=='{')-(data[i]=='}');i+=1
    return data[start:i]+'\n'
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--cc',choices=['gcc','clang'],required=True);p.add_argument('--baseline-red',action='store_true');p.add_argument('--migration-red',action='store_true');p.add_argument('--sanitize',action='store_true');p.add_argument('--compile-units',action='store_true');p.add_argument('--only-pool',action='store_true');a=p.parse_args()
    out=a.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'build'):raise RuntimeError('fresh own output required')
    out.mkdir(parents=True);snap=out/'source';owner=ROOT/'shizukudos/tests/test_k32_memory_concurrency.py';owner_bytes=owner.read_bytes()
    if hashlib.sha256(owner_bytes).hexdigest()!=OWNER_SHA:raise RuntimeError('owner changed')
    units=['shizukudos/tests/test_k64_persistent_ap.c','shizukudos/tests/test_k64_persistent_ap_service.c','shizukudos/tests/test_k64_persistent_ap_trace.c','shizukudos/tests/test_k64_persistent_ap_migration.c','shizukudos/tests/test_k64_ap_dispatch_context.c','shizukudos/tests/test_k64_ap_dispatch_arch.c','shizukudos/tests/test_k64_cpu_api.c','shizukudos/tests/test_k64_runqueue.c']
    if a.only_pool:units=units[:1]
    if a.migration_red:units=['shizukudos/tests/test_k64_persistent_ap_migration.c']
    production=['shizukudos/kernel64/'+n+'.c' for n in ['sched','kernel_ap_work','cpu_arch_bringup','cpu_bringup']]
    pending=[Path(__file__),owner,ROOT/'docs/agents/plans/core-k64-persistent-ap.md',ROOT/'shizukudos/kernel64/sched.c',ROOT/'shizukudos/tests/test_k64_persistent_ap_red.c']
    if not a.baseline_red:pending+=[ROOT/f for f in units+production+['shizukudos/kbuild.py','shizukudos/kernel64/start.asm']]
    sources={}
    while pending:
        f=pending.pop().resolve();rel=str(f.relative_to(ROOT))
        if rel in sources:continue
        data=f.read_bytes();sources[rel]=data
        pending += [f.parent/x.decode() for x in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"',data,re.M) if x not in [b'persistent-pristine-bodies.inc',b'persistent-service-bodies.inc']]
    for rel,data in sources.items():
        dest=snap/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    tools={};cc=Path(shutil.which(a.cc)).resolve();tools[str(cc)]=digest(cc);tools[str(Path(sys.executable).resolve())]=digest(Path(sys.executable).resolve())
    # Conservative system-header superset exists BEFORE the first compiler
    # consumer. The later -M output must be a subset of these captured bytes.
    system_headers={}
    for base in [Path('/usr/include'),Path('/usr/lib/gcc'),Path('/usr/lib/clang'),Path('/usr/local/swift/usr/lib/clang'),Path('/opt/rh')]:
        if base.exists():
            for f in base.rglob('*'):
                if f.is_file() and f.suffix in ['.h','.inc','.def']:
                    system_headers[str(f.resolve())]=digest(f)
    generated={}
    runtime_pins={}
    # Compiler runtime and CRT files are input bytes, not global environment
    # repairs. The conservative local inventory precedes every consumer.
    for base in [Path('/usr/lib64'),Path('/usr/lib/clang'),Path('/usr/lib/gcc'),Path('/opt/rh')]:
        if base.exists():
            for f in base.rglob('*'):
                if f.is_file() and (f.suffix in ['.o','.a','.so','.syms','.txt'] or '.so.' in f.name):
                    runtime_pins[str(f.resolve())]=digest(f)
    ns={'Path':Path,'ctypes':ctypes,'os':os,'signal':signal,'subprocess':subprocess,'time':time,'CLEANUP_SECONDS':2.0};tree=ast.parse(owner_bytes);nodes=[x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name in ['group_members','run_owned']]
    if len(nodes)!=2:raise RuntimeError('owner functions incomplete')
    (out/'loaded-owner.py').write_bytes(owner_bytes)
    before={rel:hashlib.sha256(data).hexdigest() for rel,data in sources.items()};(out/'before-helper.json').write_text(json.dumps({'sources':before,'tools':tools,'system_headers':system_headers,'runtime_pins':runtime_pins,'owner_sha256':OWNER_SHA,'capture_before_owner_execution':True},indent=2)+'\n')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(owner),'exec'),ns)
    commands=[]
    def stable():return all((ROOT/rel).read_bytes()==data and (snap/rel).read_bytes()==data for rel,data in sources.items()) and all(digest(f)==h for f,h in tools.items()) and all(digest(f)==h for f,h in generated.items())
    def run(argv,label):
        if not stable():raise RuntimeError('precommand drift')
        result=ns['run_owned'](list(map(str,argv)),timeout=30);commands.append(result);(out/(label+'.log')).write_text(result['stdout']+result['stderr'])
        (out/(label+'-owned.json')).write_text(json.dumps(result,indent=2)+'\n')
        if not result['cleanup']['passed'] or result['timed_out'] or result['infrastructure_error']:raise RuntimeError('owned command failed lifecycle')
        return result
    for name in ['cc1','collect2','as','ld']:
        result=run([cc,'-print-prog-name='+name],'tool-'+name);s=result['stdout'].strip();f=Path(s).resolve() if '/' in s else Path(shutil.which(s)).resolve() if shutil.which(s) else None
        if f and f.is_file():tools[str(f)]=digest(f)
        elif a.cc!='clang' or name not in ['cc1','collect2']:raise RuntimeError('compiler subtool missing')
    if a.baseline_red:
        body='\n'.join(function(sources['shizukudos/kernel64/sched.c'].decode(),n) for n in ['thread_join','thread_discard','sched_ap_cohort_finish']);body_path=snap/'shizukudos/tests/persistent-pristine-bodies.inc';body_path.write_text(body);generated[str(body_path)]=digest(body_path)
    else:
        names=['thread_pointer_valid','thread_set_sched_policy','thread_find_tid','sched_for_each_thread','thread_slot','thread_creator_release','thread_join','thread_discard','sched_ap_cohort_resources','sched_ap_work_overlaps','sched_ap_work_quiescent','ap_work_complete_locked','ap_work_failed','ap_work_coverage_locked','ap_work_signal','ap_work_wait','sched_ap_work_start','sched_ap_work_submit','sched_ap_work_poll','sched_ap_work_release','sched_ap_work_migrate','sched_ap_work_stop']
        body='\n'.join(function(sources['shizukudos/kernel64/sched.c'].decode(),n) for n in names)
        body_path=snap/'shizukudos/tests/persistent-service-bodies.inc';body_path.write_text(body);generated[str(body_path)]=digest(body_path)
    (out/'before-dependencies.json').write_text(json.dumps({'sources':before,'tools':tools,'system_headers':system_headers,'generated':generated},indent=2)+'\n')
    dependencies={};artifacts={};results=[]
    project_pins={str((snap/rel).resolve()):h for rel,h in before.items()}
    def closure(unit,flags,label):
        # Linker-only arguments do not alter preprocessing. Clang rejects them
        # at -M under -Werror; retain all actual preprocessing/ISA definitions.
        dep_flags=[f for f in flags if not str(f).startswith('-Wl,') and f!='-no-pie']
        dep=run([cc,*dep_flags,'-M',unit],label+'-dependencies')
        if dep['exit_code']!=0:raise RuntimeError('dependency command failed '+label)
        current={}
        for token in shlex.split(dep['stdout'].replace('\\\n',' ').split(':',1)[1]):
            f=str(Path(token).resolve());h=digest(f)
            if h!=({**system_headers,**runtime_pins,**project_pins,**generated}).get(f):raise RuntimeError('uncaptured dependency '+f)
            current[f]=h;dependencies[f]=h
        (out/(label+'-before-compile.json')).write_text(json.dumps({'sources':before,'tools':tools,'compiler_dependencies':current,'generated':generated},indent=2)+'\n')
    flags=['-std=gnu11','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fno-pie','-no-pie','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-pthread']
    if a.baseline_red:
        unit=snap/'shizukudos/tests/test_k64_persistent_ap_red.c';exe=out/'pristine-finish';flags+=['-DSHZ_STANDALONE'];closure(unit,flags,'actual')
        compiled=run([cc,*flags,unit,'-o',exe],'compile');actual=run([exe],'actual-pristine-finish') if compiled['exit_code']==0 else compiled
        red=compiled['exit_code']==0 and actual['exit_code']==1 and 'PRISTINE_FINISH: rc=0 mask=1 retained_count=0 freed=3' in actual['stdout'] and 'PERSISTENT_SECOND_GENERATION_EMPTY_INTERVAL: FAIL' in actual['stdout']
        if exe.exists():artifacts[str(exe)]=digest(exe)
        status='EXPECTED_REAL_BEHAVIOR_RED' if red else 'FAIL';results=[{'raw_test_exit':actual['exit_code'],'expected_semantic_red':red}];print(actual['stdout'])
    else:
        if a.sanitize:flags+=['-fsanitize=address,undefined','-fno-sanitize-recover=all']
        for rel in units:
            label=Path(rel).stem;unit=snap/rel;exe=out/label;extra=['-mgeneral-regs-only'] if label.endswith(('_arch','_trace')) else ['-DSHZ_STANDALONE'] if label.endswith(('_service','_migration')) else []
            if a.migration_red:extra+=['-DPERSISTENT_MIGRATION_BASELINE']
            linked=[snap/'shizukudos/kernel64/kernel_ap_work.c'] if label in ['test_k64_persistent_ap','test_k64_persistent_ap_service','test_k64_persistent_ap_migration'] else []
            closure(unit,flags+extra,label)
            if linked:closure(linked[0],flags+extra,label+'-linked')
            compiled=run([cc,*flags,*extra,unit,*linked,'-o',exe],label+'-compile')
            actual=run([exe],label+'-run') if compiled['exit_code']==0 else compiled
            summary=re.findall(r'^checks=(\d+) failures=(\d+)(?: scope=([^\n]+))?$',actual['stdout'],re.M)
            expected={'test_k64_persistent_ap_migration':1 if a.migration_red else 34,'test_k64_persistent_ap':45,'test_k64_persistent_ap_service':28,'test_k64_persistent_ap_trace':17,'test_k64_ap_dispatch_context':10,'test_k64_ap_dispatch_arch':17,'test_k64_cpu_api':27,'test_k64_runqueue':13}[label]
            complete=(len(summary)==1 and int(summary[0][1])==0 and int(summary[0][0])==expected) if label!='test_k64_runqueue' else len(re.findall('^PASS:',actual['stdout'],re.M))==13 and 'FAIL:' not in actual['stdout'] and 'HOST_CONCURRENCY_END: all owners joined' in actual['stdout']
            valid=compiled['exit_code']==0 and actual['exit_code']==0 and not actual['stderr'] and complete
            if a.migration_red:valid=compiled['exit_code']==0 and actual['exit_code']==1 and not actual['stderr'] and 'PRISTINE_PARKED_POLICY: rc=-1 source_mask=2' in actual['stdout'] and 'checks=1 failures=1 scope=actual_C_parked_migration_no_AP' in actual['stdout']
            results.append({'unit':label,'passed':valid,'exit':actual['exit_code'],'summary':summary});print(actual['stdout'])
            if exe.exists():artifacts[str(exe)]=digest(exe)
        if a.compile_units:
            tree=ast.parse(sources['shizukudos/kbuild.py']);kernel_flags=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='K64_FLAGS' for t in n.targets))
            if a.cc=='clang':kernel_flags=[f for f in kernel_flags if f!='-fno-tree-loop-distribute-patterns']
            for profile,defines in [('standalone',['-DSHZ_STANDALONE']),('supervisor',[])]:
                for rel in production:
                    label=profile+'-'+Path(rel).stem;unit=snap/rel;options=[*kernel_flags,*defines,'-I',snap/'shizukudos','-I',snap/'shizukudos/kernel64'];closure(unit,options,label)
                    obj=out/(label+'.o');r=run([cc,*options,'-c',unit,'-o',obj],label+'-compile');results.append({'unit':label,'passed':r['exit_code']==0 and not r['stderr'],'exit':r['exit_code'],'scope':'actual freestanding unit, no kernel link'})
                    if obj.exists():artifacts[str(obj)]=digest(obj)
        status=('EXPECTED_REAL_MIGRATION_RED' if a.migration_red else 'PASS') if all(x['passed'] for x in results) else 'FAIL'
    inputs_stable=stable() and all(digest(f)==h for f,h in {**dependencies,**artifacts,**runtime_pins}.items())
    result={'status':status if inputs_stable else 'FAIL','scope':'actual source C/host queue and ownership adapters; no physical AP, VM, preemption or hardware NMI','sources_before':before,'sources_after':{rel:digest(ROOT/rel) for rel in before},'tools':tools,'dependencies':dependencies,'runtime_pins':runtime_pins,'commands':commands,'results':results,'artifacts':artifacts,'inputs_stable':inputs_stable,'generated':generated,'guest_executed':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    total=sum(p.stat().st_size for d in (ROOT/'build').glob('k64-persistent-ap-*') for p in d.rglob('*') if p.is_file())
    if total>96<<20:raise RuntimeError('96MiB aggregate lane cap')
    print(result['status'],'bytes',total);return result['status'] not in ['PASS','EXPECTED_REAL_BEHAVIOR_RED','EXPECTED_REAL_MIGRATION_RED']
if __name__=='__main__':raise SystemExit(main())
