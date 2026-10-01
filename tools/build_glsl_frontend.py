#!/usr/bin/env python3
"""Build a bounded genuine Mesa preprocessing/typed-HIR host proof, offline.

No GL context/device, native acceptance, global install or generator substitute.
Every failed command and partial output remains in the fresh owned build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
AUDIT=ROOT/'build/mesa-softpipe-audit-v1'
ARCHIVE_SHA='1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f'
PINS_SHA='71b5e6199051ac9baa9b1bfb21816324cf57325039cf4dcbd9f9c110ebcf4efa'
FLOOR=22058516480
BUDGET=512*1024**2
MEMORY_LIMIT=6*1024**3
RECEIPT_RESERVE=16*1024**2
POLL_SECONDS=0.05
POLL_GAP_REJECT_SECONDS=1.0
GENERATOR_ROOT=ROOT/'build/glsl-generator-dependencies-v3'
GENERATOR_SHA='19a1d52bae7228dadb8b0fca20a86fd8d3dc3d563ca9bb0ed9e49c1919917f08'
OWN=('src/m98_glsl_frontend.h','src/m98_glsl_frontend.cpp',
 'src/m98_glsl_frontend_port.h','src/m98_glsl_frontend_port.c',
 'tests/m98_glsl_frontend_host.cpp','tools/build_glsl_frontend.py',
 'profiles/mesa-glsl-es300-frontend-v1.json',
 'patches/mesa-26.2.3-glsl-es300-frontend-v1.patch','docs/TRIDENT_GLSL_FRONTEND.md')
PP_UNITS=('src/compiler/glsl/glcpp/glcpp-parse.c',
 'src/compiler/glsl/glcpp/glcpp-lex.c','src/compiler/glsl/glcpp/pp.c',
 'src/util/ralloc.c','src/util/hash_table.c','src/util/set.c',
 'src/util/string_buffer.c','src/util/u_printf.c','src/util/u_math.c')
CORE_CPP=('ast_array_index','ast_expr','ast_function','ast_to_hir','ast_type',
 'builtin_functions','builtin_types','builtin_variables','glsl_symbol_table',
 'glsl_parser_extras','hir_field_selection','ir','ir_builder','ir_clone',
 'ir_constant_expression','ir_function','ir_function_detect_recursion',
 'ir_hierarchical_visitor','ir_hv_accept','ir_print_visitor','ir_rvalue_visitor',
 'ir_validate','ir_variable_refcount','glsl_parser','glsl_lexer')
CORE_C=('src/compiler/glsl_types.c','src/compiler/shader_enums.c',
 'src/compiler/builtin_types.c','src/util/half_float.c','src/util/strtod.c',
 'src/mesa/program/symbol_table.c','src/mesa/main/extensions_table.c')

class BuildError(Exception): pass
def need(ok,message):
 if not ok: raise BuildError(message)
def read(p,cap=64*1024**2):
 p=Path(p);need(p.is_absolute() and p.resolve()==p,'canonical input: '+str(p))
 need(all(not q.is_symlink() for q in [p,*p.parents]),'symlink input')
 st=p.stat();need(p.is_file() and st.st_size<=cap,'bounded regular input')
 with p.open('rb') as f:
  a=os.fstat(f.fileno());b=f.read(cap+1);z=os.fstat(f.fileno())
 need((a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) and len(b)==a.st_size,'input drift')
 return b
def sha(p,cap=64*1024**2): return hashlib.sha256(read(p,cap)).hexdigest()
def pairs(rows):
 d={}
 for k,v in rows:need(k not in d,'duplicate JSON key');d[k]=v
 return d
def receipt(p):return json.loads(read(p),object_pairs_hook=pairs)
def memory_available():
 for line in Path('/proc/meminfo').read_text().splitlines():
  if line.startswith('MemAvailable:'):return int(line.split()[1])*1024
 raise BuildError('MemAvailable unavailable')

class ResourceGuard:
 """Measured own-tree footprint guard; sampling cannot promise zero overshoot."""
 def __init__(self,out,budget=BUDGET,reserve=RECEIPT_RESERVE,test_probe=None):
  self.out=out;self.budget=budget;self.reserve=reserve;self.test_probe=test_probe
  self.last={};self.samples=0;self.poll_samples=0;self.last_poll=None
  self.peaks={'logical_bytes':0,'allocated_bytes':0,'owned_rss_bytes':0,
   'scan_seconds':0.0,'poll_gap_seconds':0.0}
  self.minimum_free=None;self.minimum_available=None
 def sample(self,group=None,monitor=False):
  start=time.monotonic();logical=allocated=count=0;seen=set()
  if self.out.exists():
   base=self.out.lstat();need(stat.S_ISDIR(base.st_mode),'owned root directory')
   allocated=base.st_blocks*512;seen.add((base.st_dev,base.st_ino))
  pending=[self.out] if self.out.exists() else []
  while pending:
   folder=pending.pop()
   with os.scandir(folder) as entries:
    for entry in entries:
     try:s=entry.stat(follow_symlinks=False)
     except FileNotFoundError:continue # A compiler-owned temporary disappeared.
     need(not stat.S_ISLNK(s.st_mode),'own-tree symlink rejected')
     need(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode),'own-tree nonregular rejected')
     inode=(s.st_dev,s.st_ino)
     if inode not in seen:allocated+=s.st_blocks*512;seen.add(inode)
     if stat.S_ISDIR(s.st_mode):pending.append(entry.path)
     else:logical+=s.st_size;count+=1
     need(count<=20000,'own-tree file-count bound')
  rss=0
  for q in Path('/proc').iterdir():
   if not q.name.isdigit():continue
   try:
    fields=(q/'stat').read_text().rsplit(')',1)[1].split()
    if int(q.name)==os.getpid() or (group is not None and int(fields[2])==group):
     rss+=int(fields[21])*os.sysconf('SC_PAGE_SIZE')
   except (OSError,ValueError,IndexError):continue
  snapshot={'logical_bytes':logical,'allocated_bytes':allocated,'files':count,
   'owned_rss_bytes':rss,'disk_free_bytes':shutil.disk_usage(ROOT).free,
   'mem_available_bytes':memory_available(),'scan_seconds':time.monotonic()-start,
   'poll_gap_seconds':0.0}
  if monitor:
   snapshot['poll_gap_seconds']=0.0 if self.last_poll is None else start-self.last_poll
   self.last_poll=start;self.poll_samples+=1
  if self.test_probe is not None:snapshot=self.test_probe(dict(snapshot),group)
  for name in self.peaks:self.peaks[name]=max(self.peaks[name],snapshot[name])
  self.minimum_free=snapshot['disk_free_bytes'] if self.minimum_free is None else min(self.minimum_free,snapshot['disk_free_bytes'])
  self.minimum_available=snapshot['mem_available_bytes'] if self.minimum_available is None else min(self.minimum_available,snapshot['mem_available_bytes'])
  self.samples+=1;self.last=snapshot;return snapshot
 def violations(self,snapshot,additional=0,final=False):
  reasons=[];used=max(snapshot['logical_bytes'],snapshot['allocated_bytes'])
  limit=self.budget if final else self.budget-self.reserve
  if used+additional>limit:reasons.append('aggregate-own-output-limit')
  if snapshot['disk_free_bytes']<FLOOR+additional:reasons.append('shared-disk-floor')
  if snapshot['owned_rss_bytes']>MEMORY_LIMIT:reasons.append('owned-rss-limit')
  if snapshot['mem_available_bytes']<MEMORY_LIMIT:reasons.append('shared-MemAvailable-floor')
  if snapshot['poll_gap_seconds']>POLL_GAP_REJECT_SECONDS:reasons.append('measurement-poll-gap')
  return reasons
 def check(self,additional=0,admission=False,final=False):
  s=self.sample();reasons=self.violations(s,additional,final)
  if admission and s['disk_free_bytes']<FLOOR+self.budget:reasons.append('fresh-recipe-headroom')
  need(not reasons,'resource guard: '+','.join(reasons));return s
 def write(self,path,data,final=False):
  need(path.is_relative_to(self.out) and path.resolve()==path,'owned write topology')
  old=path.stat().st_size if path.exists() else 0
  extra=max(0,len(data)-old)+4096
  self.check(additional=extra,final=final)
  path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
  self.check(final=final)
 def describe(self):
  return {'budget_bytes':self.budget,'reserved_failure_receipt_bytes':self.reserve,
   'data_limit_bytes':self.budget-self.reserve,'disk_floor_bytes':FLOOR,
   'minimum_fresh_free_bytes':FLOOR+self.budget,'rss_limit_bytes':MEMORY_LIMIT,
   'MemAvailable_floor_bytes':MEMORY_LIMIT,'poll_target_seconds':POLL_SECONDS,
   'poll_gap_rejection_seconds':POLL_GAP_REJECT_SECONDS,'samples':self.samples,
   'command_poll_samples':self.poll_samples,'observed_high_water':dict(self.peaks),
   'observed_minimum_disk_free_bytes':self.minimum_free,
   'observed_minimum_MemAvailable_bytes':self.minimum_available,'last':dict(self.last),
   'synthetic_test_probe':self.test_probe is not None,'sampling_zero_overshoot_proved':False,
   'limitations':'Own logical/st_blocks footprint and RSS are sampled, not atomic. Scheduler and tree-scan delay, transient/deleted compiler temporaries, directory/filesystem metadata and unrelated writers can cause unobserved peaks or overshoot. A late sample rejects and stops only the new owned process group; it cannot control peers.'}

def owned_run(argv,log,err,timeout,guard,stdin=None,combined=False,san=False,pythonpath=None):
 before=guard.check();guard.last_poll=None
 def limits():
  resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2))
  resource.setrlimit(resource.RLIMIT_CPU,(timeout+10,timeout+10))
  if not san:resource.setrlimit(resource.RLIMIT_AS,(MEMORY_LIMIT,MEMORY_LIMIT))
 env=dict(os.environ,LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(guard.out/'tmp'),
  ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
 env.pop('PYTHONPATH',None)
 if pythonpath is not None:env['PYTHONPATH']=str(pythonpath)
 start=time.monotonic();hits=[];stop=threading.Event()
 with log.open('wb') as f,err.open('wb') as e:
  p=subprocess.Popen([str(x) for x in argv],cwd=ROOT,env=env,
   stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
   stdout=f,stderr=subprocess.STDOUT if combined else e,
   start_new_session=True,preexec_fn=limits)
  # This PID is obtained only from the Popen created above; no caller/peer PID.
  def kill_owned():
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  def monitor():
   while not stop.wait(POLL_SECONDS):
    try:
     snapshot=guard.sample(p.pid,monitor=True);reasons=guard.violations(snapshot)
    except (BuildError,OSError,ValueError) as exc:reasons=['resource-measurement-error:'+str(exc)]
    if reasons:hits.extend(reasons);kill_owned();return
  watcher=threading.Thread(target=monitor,daemon=True);watcher.start();timed_out=False
  try:p.communicate(stdin,timeout=timeout)
  except subprocess.TimeoutExpired:
   timed_out=True;kill_owned();p.communicate(timeout=5)
  finally:stop.set();watcher.join(timeout=2)
  if watcher.is_alive():
   hits.append('resource-monitor-did-not-finish');kill_owned();p.wait(timeout=5)
  code=p.returncode
 after=guard.sample();hits.extend(guard.violations(after))
 return {'returncode':code,'timed_out':timed_out,'owned_process_group':p.pid,
  'owned_child_reaped':p.returncode is not None,'seconds':round(time.monotonic()-start,3),
  'resource_violations':list(dict.fromkeys(hits)),'resources_before':before,
  'resources_after':after,'resource_guard':guard.describe()}
def resource_controls(out):
 """Small synthetic thresholds, real fresh processes/kill/reap/partial files."""
 parent=ResourceGuard(out);parent.check(admission=True)
 out.mkdir();(out/'tmp').mkdir();rows=[]
 python=Path(sys.executable).resolve();source={n:sha(ROOT/n) for n in OWN}
 child="import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_bytes(b'x'*65536); print('OWNED_CHILD_STARTED',flush=True); time.sleep(3)"
 sibling_log=out/'sibling.log'
 with sibling_log.open('wb') as f:
  sibling=subprocess.Popen([str(python),'-B','-c','import time; time.sleep(10)'],
   stdout=f,stderr=f,start_new_session=True)
  try:
   for label,field,value,reason in (
    ('disk','disk_free_bytes',FLOOR-1,'shared-disk-floor'),
    ('rss','owned_rss_bytes',MEMORY_LIMIT+1,'owned-rss-limit'),
    ('available','mem_available_bytes',MEMORY_LIMIT-1,'shared-MemAvailable-floor'),
    ('poll','poll_gap_seconds',POLL_GAP_REJECT_SECONDS+0.001,'measurement-poll-gap'),
    ('aggregate',None,None,'aggregate-own-output-limit')):
    parent.check();folder=out/label;folder.mkdir();(folder/'tmp').mkdir()
    def inject(snapshot,group,field=field,value=value):
     if group is not None and field is not None:snapshot[field]=value
     return snapshot
    g=ResourceGuard(folder,budget=48*1024 if field is None else BUDGET,
     reserve=8*1024 if field is None else RECEIPT_RESERVE,
     test_probe=inject if field is not None else None)
    actual=owned_run([python,'-B','-c',child,folder/'partial.bin'],
     folder/'child.log',folder/'child.stderr',5,g)
    need(actual['returncode']==-signal.SIGKILL and actual['owned_child_reaped'],
     'real controlled child must be killed/reaped '+label)
    need(reason in actual['resource_violations'],'independent limit reason '+label)
    need((folder/'partial.bin').stat().st_size==65536
     and b'OWNED_CHILD_STARTED' in read(folder/'child.log'),'actual partial output retained '+label)
    need(sibling.poll() is None,'separate newly-owned sibling must remain alive')
    rows.append(dict(actual,control=label,synthetic_threshold_or_probe=True,
     actual_partial_sha256=sha(folder/'partial.bin'),actual_sibling_alive=True))
    parent.check()
  finally:
   if sibling.poll() is None:os.killpg(sibling.pid,signal.SIGKILL)
   sibling.wait(timeout=5)
 empty=out/'copy-check';empty.mkdir();g=ResourceGuard(empty,budget=48*1024,reserve=8*1024)
 rejected=False
 try:g.write(empty/'must-not-publish.bin',b'z'*65536)
 except BuildError:rejected=True
 need(rejected and not (empty/'must-not-publish.bin').exists(),'copy size rejected before write')
 rows.append({'control':'pre-copy-size','rejected_before_write':True})
 low=ResourceGuard(out,test_probe=lambda s,group:dict(s,disk_free_bytes=FLOOR+BUDGET-1))
 rejected=False
 try:low.check(admission=True)
 except BuildError:rejected=True
 need(rejected,'fresh admission rejects exactly one byte below floor plus budget')
 rows.append({'control':'fresh-headroom','synthetic_probe':True,'rejected':True})
 positive=out/'positive';positive.mkdir();(positive/'tmp').mkdir()
 actual=owned_run([python,'-B','-c',"print('ACTUAL_POSITIVE_OWNED_PROCESS')"],
  positive/'child.log',positive/'child.stderr',5,ResourceGuard(positive))
 need(actual['returncode']==0 and not actual['resource_violations']
  and actual['owned_child_reaped'],'ordinary owned process remains successful')
 need(read(positive/'child.log')==b'ACTUAL_POSITIVE_OWNED_PROCESS\n','literal positive output')
 rows.append(dict(actual,control='positive'))
 for n,h in source.items():need(sha(ROOT/n)==h,'source held during resource controls')
 parent.check(final=True)
 result={'schema':1,'kind':'synthetic-threshold-real-owned-resource-process-controls',
  'passed':True,'controls':rows,'source_sha256':source,'resource_guard':parent.describe(),
  'python_executable':str(python),'python_sha256':sha(python),'native_execution':False,
  'typed_hir':False,'webgl':False,'webgpu':False,'vm_operations':False,
  'limitations':'Reduced/injected resource thresholds exercise actual own-group kill/reap and preserved output. They are not a 512MiB production-growth or real 6GiB memory-exhaustion proof.'}
 parent.write(out/'result.json',(json.dumps(result,indent=2)+'\n').encode(),final=True)
 print(json.dumps({'passed':True,'actual_controls':len(rows),'receipt':str(out/'result.json'),
  'receipt_sha256':sha(out/'result.json'),'resources':parent.describe()}));return 0

def main():
 need(not sys.flags.optimize,'optimized builder rejected')
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--build-dir',type=Path,required=True)
 ap.add_argument('--preprocess-only',action='store_true')
 ap.add_argument('--typed-first',action='store_true')
 ap.add_argument('--generator-python',type=Path,default=Path(sys.executable))
 ap.add_argument('--resource-self-test',action='store_true')
 args=ap.parse_args();out=args.build_dir
 if not out.is_absolute():out=ROOT/out
 need(out.parent==ROOT/'build' and out.resolve()==out and not out.exists(),'fresh direct owned build')
 need(not out.is_symlink(),'fresh own directory has no symlink')
 guard=ResourceGuard(out);guard.check(admission=True)
 if args.resource_self_test:return resource_controls(out)
 own={n:sha(ROOT/n) for n in OWN}
 need(sha(AUDIT/'input/mesa-26.2.3.tar.xz',96*1024**2)==ARCHIVE_SHA and sha(AUDIT/'source-pins.json')==PINS_SHA,'approved Mesa authority')
 pins=receipt(AUDIT/'source-pins.json')['files'];profile=receipt(ROOT/OWN[6])
 need(profile['archive_sha256']==ARCHIVE_SHA and profile['source_pin_sha256']==PINS_SHA,'profile authority')
 original=AUDIT/'source';observed={}
 for n,row in pins.items():
  p=original/n;need(p.is_relative_to(original),'source topology')
  need(sha(p)==row['sha256'] and p.stat().st_size==row['size'],'original source mismatch '+n)
  observed[str(p)]=row['sha256']
 if not args.preprocess_only:
  need(sha(GENERATOR_ROOT/'result.json')==GENERATOR_SHA,'approved isolated generator authority')
  generator_authority=receipt(GENERATOR_ROOT/'result.json')
  need(generator_authority['status']=='PASS_ISOLATED_GENERATOR_DEPENDENCY_ONLY'
   and generator_authority['global_installation'] is False
   and generator_authority['native_execution'] is False
   and len(generator_authority['closure_sha256'])==53,'isolated dependency boundary')
  need(args.generator_python.resolve()==Path(generator_authority['python_executable'])
   and sha(args.generator_python.resolve())==generator_authority['python_executable_sha256'],'approved generator interpreter')
 guard.check(admission=True)
 out.mkdir();prepared=out/'prepared';prepared.mkdir();(out/'tmp').mkdir();guard.check()
 result={'schema':1,'kind':'genuine-mesa-glsl-compiler-only-host-build',
  'passed':False,'preprocessing':False,'typed_hir':False,'native_built':False,
  'native_execution':False,'backend_lowering':False,'gles':False,'webgl':False,
  'webgpu':False,'browser':False,'modern_apps':False,'vm_operations':False,
  'downloads':False,'global_install':False,'source_sha256':own,
  'archive_sha256':ARCHIVE_SHA,'source_pin_sha256':PINS_SHA,
  'steps':[],'models':{},'original_source_sha256':observed,
  'external_entire_toolchain_closure_proved':False}
 tools={}
 def external(p):
  p=Path(p).resolve();h=sha(p);observed[str(p)]=h;return h
 def command(name,argv,timeout=180,stdin=None,combined=False,output=None,expect=(0,),san=False,pythonpath=None):
  guard.check(additional=8192)
  executable=Path(shutil.which(str(argv[0])) or str(argv[0])).resolve()
  need(executable.is_file(),'actual command executable');tools[str(executable)]=external(executable)
  log=out/(name+'.log');err=out/(name+'.stderr')
  actual=owned_run(argv,log,err,timeout,guard,stdin,combined,san,pythonpath)
  row=dict(actual,name=name,argv=[str(x) for x in argv],cwd=str(ROOT),
   timeout_seconds=timeout,
   stdout=log.name,stdout_sha256=sha(log),stderr=err.name,stderr_sha256=sha(err),locale='C',
   address_limit_bytes=None if san else MEMORY_LIMIT,
   scoped_pythonpath=str(pythonpath) if pythonpath is not None else None)
  result['steps'].append(row)
  observed[str(log)]=row['stdout_sha256'];observed[str(err)]=row['stderr_sha256']
  need(not actual['timed_out'] and not actual['resource_violations'] and actual['owned_child_reaped']
   and actual['returncode'] in expect,'command failed '+name+' (see retained stdout/stderr/resource measurements)')
  b=read(log)
  if output is not None:
   guard.write(output,b)
   observed[str(output)]=sha(output)
   expected_prepared[str(output.relative_to(prepared))]=sha(output)
  guard.check();return b,actual['returncode']
 try:
  expected_prepared={n:row['sha256'] for n,row in pins.items()}
  for n in pins:
   dest=prepared/n;guard.write(dest,read(original/n))
   need(sha(dest)==pins[n]['sha256'],'prepared copy mismatch')
  frozen={}
  for n in OWN:
   dest=out/'inputs'/n;guard.write(dest,read(ROOT/n))
   need(sha(dest)==own[n],'own frozen source');frozen[n]=str(dest.relative_to(out))
  result['frozen_source_paths']=frozen
  warnings=prepared/'src/compiler/glsl/tests/warnings'
  warning_rows=[]
  for p in sorted(warnings.glob('*.vert')):
   expected=Path(str(p)+'.expected');need(expected.is_file(),'original linked warning expectation')
   warning_rows.append({'source':str(p.relative_to(prepared)),'source_sha256':sha(p),'expected':str(expected.relative_to(prepared)),'expected_sha256':sha(expected),'prescribed_language_version':150,'requires_program_link':True,'counted_as_es300':False})
  need(len(warning_rows)==33,'unchanged 33 GLSL150 linkage fixtures')
  result['preserved_distinct_glsl150_linkage_pairs']=warning_rows
  command('apply-reviewed-exact-patch',['patch','--batch','--fuzz=0','-d',prepared,'-p1','-i',ROOT/OWN[7]])
  for n,row in profile['patched_sources'].items():
   need(row['before_sha256']==pins[n]['sha256'] and sha(prepared/n)==row['after_sha256'],'exact prepared patch '+n)
   expected_prepared[n]=row['after_sha256']
  pp=prepared/'src/compiler/glsl/glcpp'
  command('glcpp-bison',['bison','-o',pp/'glcpp-parse.c','-p','glcpp_parser_','--defines='+str(pp/'glcpp-parse.h'),pp/'glcpp-parse.y'])
  command('glcpp-flex',['flex','-o',pp/'glcpp-lex.c',pp/'glcpp-lex.l'])
  for n in ('glcpp-parse.c','glcpp-parse.h','glcpp-lex.c'):
   expected_prepared[str((pp/n).relative_to(prepared))]=sha(pp/n)
  include=['-I'+str(ROOT/'src'),'-I'+str(prepared/'include'),'-I'+str(prepared/'src'),
   '-I'+str(prepared/'src/mesa'),'-I'+str(prepared/'src/compiler'),
   '-I'+str(prepared/'src/compiler/glsl'),'-I'+str(pp),
   '-I'+str(prepared/'src/gallium/include'),'-I'+str(prepared/'src/gallium/auxiliary')]
  common=['-O1','-g','-Wall','-Wextra','-fno-builtin','-ffunction-sections','-fdata-sections',
   '-D_GNU_SOURCE','-DHAVE_PTHREAD=1','-DHAVE_STRUCT_TIMESPEC=1',
   '-DHAVE_LINUX_FUTEX_H=1','-DUTIL_ARCH_LITTLE_ENDIAN=1','-DUTIL_ARCH_BIG_ENDIAN=0',
   '-DMESA_DEBUG=1','-include',str(ROOT/'src/m98_glsl_frontend_port.h')]+include
  dependencies={};objects=[]
  def build(label,typed):
   extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if 'sanitize' in label else []
   if typed:extra+=['-DM98_GLSL_TYPED_ENABLED=1','-DHAVE_STRTOD_L=1','-DHAVE_STRTOF=1']
   c_sources=[prepared/n for n in PP_UNITS]+[ROOT/'src/m98_glsl_frontend_port.c']
   cpp_sources=[ROOT/'src/m98_glsl_frontend.cpp',ROOT/'tests/m98_glsl_frontend_host.cpp']
   if typed:
    c_sources+=[prepared/n for n in CORE_C]
    cpp_sources+=[prepared/('src/compiler/glsl/'+n+'.cpp') for n in CORE_CPP]
   objs=[]
   for i,p in enumerate(c_sources+cpp_sources):
    cpp=p.suffix=='.cpp';obj=out/(label+'-'+str(i)+'.o');dep=out/(label+'-'+str(i)+'.d')
    flags=common+extra+(['-DM98_GLSL_TRACK_ALLOC=1'] if p.name!='m98_glsl_frontend_port.c' else [])
    args=['clang++' if cpp else 'clang','-std=c++17' if cpp else '-std=c11']+flags
    if cpp:args+=['-fno-exceptions','-fno-rtti']
    command(label+'-unit-'+str(i),args+['-MD','-MF',dep,'-c',p,'-o',obj],timeout=300)
    names=shlex.split(read(dep).decode().replace('\\\n',' ').split(':',1)[1])
    for x in names:
     f=Path(x);f=f if f.is_absolute() else ROOT/f;f=f.resolve()
     h=external(f);dependencies[str(f)]={'sha256':h,'size':f.stat().st_size}
    objects.append({'source':str(p),'source_sha256':sha(p),'object':obj.name,'object_sha256':sha(obj),'dependency_file':dep.name,'dependency_sha256':sha(dep),'compiler_flags':args})
    observed[str(obj)]=sha(obj);observed[str(dep)]=sha(dep)
    objs.append(obj)
   binary=out/label
   command(label+'-link',['clang++']+extra+['-Wl,--gc-sections']+objs+['-lm','-pthread','-o',binary])
   raw,_=command(label+'-semantic',[binary],san='sanitize' in label)
   need(raw.startswith(b'M98_GLSL_HOST_CHECKS='),'literal host receipt')
   control,_=command(label+'-allocation-control',[binary,'--allocation-limit'],expect=(86,),combined=True,san='sanitize' in label)
   need(b'M98_GLSL_OWNED_PROCESS_ALLOCATION_LIMIT' in control,'real allocation failure control')
   if 'sanitize' in label:
    for suffix,needle in [('asan',b'AddressSanitizer'),('ubsan',b'signed integer overflow')]:
     command(label+'-'+suffix+'-actual-control',[binary,'--'+suffix+'-control'],expect=(1,),san=True)
     need(needle in read(out/(label+'-'+suffix+'-actual-control.stderr')),'actual sanitizer failed control')
   fixture_rows=[];tests=prepared/'src/compiler/glsl/glcpp/tests'
   for newline_name,newline in [('unix',b'\n'),('windows',b'\r\n'),('oldmac',b'\r'),('bizarro',b'\n\r')]:
    for case in sorted(tests.glob('*.c')):
     contents=read(case).replace(b'\n',newline);args=[]
     for line in contents.split(newline):
      if b'glcpp-args:' in line:args=line.split(b'glcpp-args:',1)[1].strip().decode().split();break
     need(args in ([],['--disable-line-continuations']),'original prescribed fixture args')
     raw_case,code=command(label+'-'+newline_name+'-'+case.stem,[binary,'--preprocess']+args,stdin=contents,combined=True,expect=(0,1),san='sanitize' in label)
     expected=read(Path(str(case)+'.expected'))
     # Only the upstream runner's documented Bison 3.6 message normalization.
     need(raw_case.replace(b'$end',b'end of file')==expected,'unchanged original glcpp expected '+case.name+' '+newline_name)
     fixture_rows.append({'input':case.name,'input_sha256':sha(case),'expected_sha256':sha(Path(str(case)+'.expected')),'newline':newline_name,'prescribed_args':args,'actual_sha256':hashlib.sha256(raw_case).hexdigest(),'returncode':code})
   need(len(fixture_rows)==608,'all 152 original pairs in four newline modes')
   result['models'][label]={'host_receipt':raw.decode().strip(),'original_glcpp_cases':fixture_rows,'binary_sha256':sha(binary),'allocation_control':True}
  if not args.typed_first:
   build('preprocess-host',False);build('preprocess-sanitize',False)
   result['preprocessing']=True
  if not args.preprocess_only:
   python=args.generator_python.resolve();external(python)
   dependency_copy=out/'generator-dependencies';dependency_copy.mkdir()
   observed[str(GENERATOR_ROOT/'result.json')]=GENERATOR_SHA
   for n,h in generator_authority['closure_sha256'].items():
    src=GENERATOR_ROOT/n;need(src.is_relative_to(GENERATOR_ROOT) and sha(src)==h,'actual isolated module closure')
    dst=dependency_copy/n;guard.write(dst,read(src))
    need(sha(dst)==h,'frozen isolated module closure');observed[str(src)]=h
   for p,h in generator_authority['local_origin_sha256'].items():
    need(sha(Path(p))==h,'original local MarkupSafe package metadata');observed[p]=h
   guard.write(dependency_copy/'result.json',read(GENERATOR_ROOT/'result.json'))
   result['generator_dependency_authority_sha256']=GENERATOR_SHA
   result['generator_dependency_closure_sha256']=generator_authority['closure_sha256']
   module_origins={}
   def generate(name,script,arguments,output=None):
    trace=out/(name+'-modules.json')
    wrapper="import sys,runpy,json,pathlib; script=sys.argv[1]; trace=sys.argv[2]; sys.argv=[script]+sys.argv[3:]; sys.path.insert(0,str(pathlib.Path(script).parent)); runpy.run_path(script,run_name='__main__'); pathlib.Path(trace).write_text(json.dumps({n:getattr(m,'__file__',None) for n,m in sorted(sys.modules.items())},sort_keys=True)+'\\n')"
    command(name,[python,'-B','-c',wrapper,script,trace]+arguments,output=output,pythonpath=dependency_copy/'lib')
    observed[str(trace)]=sha(trace)
    if script.name in ('builtin_types_h.py','builtin_types_c.py'):
     generated=Path(arguments[0]);expected_prepared[str(generated.relative_to(prepared))]=sha(generated)
     observed[str(generated)]=sha(generated)
    mods=receipt(trace)
    for module,path in mods.items():
     if path is None:module_origins[module]={'origin':None,'kind':'built-in-or-frozen'};continue
     p=Path(path)
     if not p.is_file():
      need(str(path).startswith('memory:'),'unexpected virtual Python module')
      module_origins[module]={'origin':path,'kind':'generated-memory-template'};continue
     canonical=p.resolve();need(canonical.is_relative_to(out) or canonical.is_relative_to(Path('/usr')),'actual allowed generator module origin')
     h=external(canonical);module_origins[module]={'origin':str(canonical),'sha256':h}
    result['actual_generator_modules']=module_origins
   generator=prepared/'src/compiler/glsl/ir_expression_operation.py'
   for mode in ('enum','strings','constant'):
    dest=prepared/('src/compiler/'+('ir_expression_operation.h' if mode=='enum' else 'glsl/ir_expression_operation_'+mode+'.h'))
    generate('original-ir-generator-'+mode,generator,[mode],output=dest)
   for suffix in ('h','c'):
    generate('original-types-generator-'+suffix,prepared/('src/compiler/builtin_types_'+suffix+'.py'),[prepared/('src/compiler/builtin_types.'+suffix)])
   command('glsl-bison',['bison','-o',prepared/'src/compiler/glsl/glsl_parser.cpp','-p','_mesa_glsl_','--defines='+str(prepared/'src/compiler/glsl/glsl_parser.h'),prepared/'src/compiler/glsl/glsl_parser.yy'])
   command('glsl-flex',['flex','-o',prepared/'src/compiler/glsl/glsl_lexer.cpp',prepared/'src/compiler/glsl/glsl_lexer.ll'])
   for n in ('glsl_parser.cpp','glsl_parser.h','glsl_lexer.cpp'):
    p=prepared/'src/compiler/glsl'/n;expected_prepared[str(p.relative_to(prepared))]=sha(p)
   fmt=prepared/'src/util/format';generate('original-format-enums',fmt/'u_format_table.py',[fmt/'u_format.yaml','--enums'],output=fmt/'u_format_gen.h')
   build('typed-host',True);build('typed-sanitize',True);result['typed_hir']=True
  if args.typed_first:
   need(not args.preprocess_only,'typed-first requires actual typed build')
   build('preprocess-host',False);build('preprocess-sanitize',False);result['preprocessing']=True
  result['passed']=True
 except (BuildError,OSError,ValueError) as e:
  result['error']=str(e)
 finally:
  try:guard.check()
  except (BuildError,OSError,ValueError) as e:
   result['passed']=False;result['resource_error']=str(e)
  result['actual_objects']=objects if 'objects' in locals() else []
  result['actual_header_dependencies']=dependencies if 'dependencies' in locals() else {}
  result['tool_executables_sha256']=tools
  result['prepared_sha256']={str(p.relative_to(prepared)):sha(p) for p in prepared.rglob('*') if p.is_file()}
  result['output_sha256']={str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file()}
  try:
   actual_prepared={str(p.relative_to(prepared)):sha(p) for p in prepared.rglob('*') if p.is_file()}
   need(actual_prepared==expected_prepared,'late exact original/patch/generated prepared closure drift')
   for n,h in own.items():need(sha(ROOT/n)==h,'late own source drift '+n)
   for p,h in observed.items():need(sha(Path(p))==h,'late input/header/tool drift '+p)
   need(sha(AUDIT/'input/mesa-26.2.3.tar.xz',96*1024**2)==ARCHIVE_SHA and sha(AUDIT/'source-pins.json')==PINS_SHA,'late caller authority drift')
   result['late_readback']=True
  except (BuildError,OSError) as e:result['passed']=False;result['late_readback']=False;result['error']=str(e)
  try:guard.check(final=True)
  except (BuildError,OSError,ValueError) as e:
   result['passed']=False;result['resource_error']=str(e)
  if not result['passed']:result['preprocessing']=False;result['typed_hir']=False
  result['resource_guard']=guard.describe()
  result['receipt_written']=True
  result['acceptance_requires_exit_zero_and_final_console_guard']=True
  encoded=(json.dumps(result,indent=2)+'\n').encode()
  try:
   need(len(encoded)<=RECEIPT_RESERVE,'bounded reserved final receipt')
   guard.write(out/'result.json',encoded,final=True);result['receipt_written']=True
  except (BuildError,OSError,ValueError) as e:
   result['receipt_written']=False
   result['passed']=False;result['preprocessing']=False;result['typed_hir']=False
   result['resource_error']=str(e)
   # No further file write while a final resource check refuses it. Existing
   # command logs/partial outputs remain; this bounded console result survives.
 print(json.dumps({'passed':result['passed'],'preprocessing':result['preprocessing'],'typed_hir':result['typed_hir'],'error':result.get('error'),'resource_error':result.get('resource_error'),'receipt_written':result['receipt_written'],'receipt':str(out/'result.json'),'resources':guard.describe()}))
 return 0 if result['passed'] else 1
if __name__=='__main__':
 try:sys.exit(main())
 except (BuildError,OSError,ValueError) as e:print(str(e),file=sys.stderr);sys.exit(1)
