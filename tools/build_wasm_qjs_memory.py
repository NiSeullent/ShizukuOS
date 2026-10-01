#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Relink the frozen private genuine QuickJS seam with corrected WAMR memory."""
import argparse,difflib,hashlib,json,os,re,shutil,signal,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OWN=['tools/build_wasm_qjs_memory.py','tests/m98_wasm_qjs_memory_host.c','docs/TRIDENT_WASM_QJS_MEMORY_PROFILE.md']
BRIDGE=ROOT/'build/wasm-qjs-v11';BRIDGE_SHA='b3e0e6ef6b966b9c9cb0beaaaf41d8227e048fbe6245232b73d825d0584705ac'
MEMORY=ROOT/'build/wasm-memory-profile-v8';MEMORY_SHA='657308666b48175c0369cdac0d3c35f9888d053f7c3038c5625c1ee5209dc5dc'
QJS=ROOT/'build/trident-script-v10';QJS_SHA='7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716'
BASE=ROOT/'build/wasm-runtime-v24';BASE_SHA='26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91'
FIXTURE_SHA='bdbaa12932eddc4a940077e982ea6284c4ae965c42a2e4a0fc33b76ce906bdd2'
DELTAS=[
("seam.memorySize(ii,0)===1&&seam.memoryGrow(ii,0,1)===-1&&seam.memorySize(ii,0)===1,'measured no-grow backend gap 1/-1/1'","seam.memorySize(ii,0)===1&&seam.memoryGrow(ii,0,1)===1&&seam.memorySize(ii,0)===2,'corrected no-grow declared pages 1/1/2'"),
("seam.memorySize(ii,0)===1&&seam.memoryGrow(ii,0,1)===-1&&seam.memoryRead(ii,0,131071,1).byteLength===1,'measured coalesced backend page-count gap'","seam.memorySize(ii,0)===2&&seam.memoryGrow(ii,0,1)===2&&seam.memorySize(ii,0)===3&&seam.memoryRead(ii,0,131071,1).byteLength===1,'corrected two-page declared pages 2/2/3'")
]
FINAL_INSERT=' printf("BRIDGE_BASELINE_RESULT %u %u %u\\n",total,passed,failed);check(total==140&&passed==140&&failed==0,"all 140 historical bridge predicates retained");\n memory_integration();\n'
FALSE_FLAGS=dict(native_execution=False,browser_js_api=False,browser_wasm=False,full_modern_wasm=False,mshtml_integration=False,full_browser=False,webgpu=False,webgl=False,modern_apps=False,vm_operations=False,network_operations=False)
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 global attempt
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--build-dir',type=Path,required=True);args=parser.parse_args();build=args.build_dir.absolute()
 require(build.parent==ROOT/'build' and build.parent.resolve()==build.parent and not build.exists(),'fresh canonical owned direct build child');attempt=build
 observed={}
 def checked(path,digest,force=False):
  path=Path(path);require(path.is_absolute() and path.resolve()==path and not path.is_symlink() and path.is_file() and path.stat().st_size<=33554432,'bounded canonical regular evidence')
  require(re.fullmatch('[0-9a-f]{64}',digest),'literal SHA256');prior=observed.get(str(path));require(prior is None or prior==digest,'consistent evidence SHA')
  if prior is None or force:require(sha(path)==digest,'actual evidence SHA '+str(path))
  observed[str(path)]=digest;return path
 own_bytes={n:(ROOT/n).read_bytes() for n in OWN};pins={n:hashlib.sha256(v).hexdigest() for n,v in own_bytes.items()}
 for n,s in pins.items():checked(ROOT/n,s)
 old=json.loads(checked(BRIDGE/'result.json',BRIDGE_SHA).read_text());memory=json.loads(checked(MEMORY/'result.json',MEMORY_SHA).read_text());q=json.loads(checked(QJS/'result.json',QJS_SHA).read_text())
 require(old['passed'] is True and memory['passed'] is True and q['passed'] is True,'accepted actual engine foundations')
 require(all(old.get(k) is v and memory.get(k) is v for k,v in FALSE_FLAGS.items()) and q['native_guest_execution_verified'] is False,'component-only frozen scope')
 require(old['quickjs_receipt_sha256']==QJS_SHA and memory['base_bridge_receipt_sha256']==BRIDGE_SHA and memory['new_proof_closure_rechecked'] is True,'exact approved foundation chain')
 require(memory['base_runtime_receipt_sha256']==BASE_SHA,'exact original C ABI foundation');original_runtime=json.loads(checked(BASE/'result.json',BASE_SHA).read_text())
 require(memory['config']['M98_WASM_BROWSER_MEMORY']==1 and memory['config']['WASM_ENABLE_SHRUNK_MEMORY']==0,'real corrected memory profile')
 for base,data in ((BRIDGE,old),(MEMORY,memory)):
  for n,s in data['source_sha256'].items():checked(ROOT/n,s);checked(base/'source'/n,s)
  for n,s in data['checked_evidence_sha256'].items():checked(Path(n),s)
  for n,row in data['retained_files'].items():
   p=checked(base/n,row['sha256']);require(p.stat().st_size==row['bytes'],'retained byte count')
 for n,s in q['source_sha256'].items():checked(ROOT/n,s);checked(QJS/'source'/n,s)
 for n,s in q['prepared_sha256'].items():checked(Path(n),s)
 for step in q['steps']:checked(Path(step['log']),step['sha256'])
 for n,row in memory['prepared_files'].items():checked(MEMORY/'prepared'/n,row['sha256'])
 original=checked(ROOT/'tests/m98_wasm_qjs_host.c',old['source_sha256']['tests/m98_wasm_qjs_host.c']).read_bytes();prepared=own_bytes[OWN[1]]
 text=prepared.decode();blocks=re.findall(r'/\* M98_MEMORY_ADDITIONS_BEGIN\n[\s\S]+?/\* M98_MEMORY_ADDITIONS_END \*/\n',text);require(len(blocks)==1,'one bounded additive test block')
 restored=text.replace(blocks[0],'');require(restored.count(FINAL_INSERT)==1,'one additive main test entry');restored=restored.replace(FINAL_INSERT,'')
 for before,after in DELTAS:
  require(restored.count(after)==1 and before not in restored,'exact two source-grounded predicate changes');restored=restored.replace(after,before)
 require(restored.encode()==original,'all other original test bytes and predicates retained')
 fixture=checked(BRIDGE/'wasm_qjs_fixtures.h',FIXTURE_SHA);require(fixture.stat().st_size==1727,'exact unchanged original fixture header')
 compilers={}
 for name in ('gcc','clang'):
  row=memory['compilers'][name];require(Path(shutil.which(name)).resolve()==Path(row['path']) and q['tool_identities'][name]['sha256']==row['sha256'],'same actual frozen compiler driver')
  checked(Path(row['path']),row['sha256']);compilers[name]=row
 build.mkdir()
 for n,b in own_bytes.items():
  p=build/'source'/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);checked(p,pins[n])
 steps=[];selected=[];new_objects=[];models={};completed=False
 receipt=dict(schema=1,kind='private-genuine-QuickJS-corrected-WAMR-memory-integration',passed=False,source_sha256=pins,original_bridge_receipt_sha256=BRIDGE_SHA,corrected_memory_receipt_sha256=MEMORY_SHA,quickjs_receipt_sha256=QJS_SHA,fixture_header_sha256=FIXTURE_SHA,compilers=compilers,steps=steps,selected_objects=selected,new_objects=new_objects,models=models,new_proof_closure_rechecked=False,external_toolchain_complete_closure=False,**FALSE_FLAGS)
 def run(label,command,success=True):
  deadline=300 if '-c' in command else 180;timed_out=False
  child=subprocess.Popen(command,cwd=ROOT,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  try:stdout,stderr=child.communicate(timeout=deadline)
  except subprocess.TimeoutExpired:
   timed_out=True
   try:os.killpg(child.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   stdout,stderr=child.communicate()
  result=subprocess.CompletedProcess(command,None if timed_out else child.returncode,stdout,stderr)
  log=build/(label+'.log');log.write_text(stdout+stderr);require(log.stat().st_size<=8388608,'bounded actual log');digest=sha(log);checked(log,digest)
  steps.append(dict(name=label,command=command,returncode=result.returncode,timed_out=timed_out,deadline_seconds=deadline,subprocess_pid=child.pid,owned_process_group=child.pid,cleanup_returncode=child.returncode if timed_out else None,log=str(log),sha256=digest))
  require(not timed_out,label+': owned subprocess deadline; partial output retained')
  if success:require(result.returncode==0,label+': '+(stdout+stderr)[-6000:])
  return result
 def copy_object(src,digest,profile,engine,index):
  checked(src,digest);dst=build/(profile+'-'+engine+'-%02d.o'%index);shutil.copyfile(src,dst);checked(dst,digest);return dst
 def qjs_objects(profile):
  prior=[r for r in old['selected_objects'] if r['engine']=='QuickJS' and r['profile']==profile];require(len(prior)==28,'actual original complete QuickJS28')
  result=[]
  for index,held in enumerate(prior):
   row=held['receipt_row'];matches=[r for r in q['object_cache'] if r['object']==row['object']]
   require(matches and all({k:v for k,v in r.items() if k!='reused'}=={k:v for k,v in row.items() if k!='reused'} for r in matches),'frozen actual QJS recipe identity')
   src=Path(row['recipe']['source']);checked(src,row['recipe']['source_sha256']);checked(Path(row['object']),row['sha256'])
   meta=checked(Path(row['object']).with_suffix('.json'),held['metadata_sha256']);data=json.loads(meta.read_text());command=data['command']
   normalized=json.dumps(row['recipe'],sort_keys=True).replace(str(QJS),'<CHECKPOINT>')
   require(data['object_sha256']==row['sha256'] and command==row['executed_command'] and data['recipe_normalized']==normalized and hashlib.sha256(normalized.encode()).hexdigest()==row['key'],'actual original QJS cache metadata and key')
   original_source=Path(command[command.index('-c')+1]);checked(original_source,row['recipe']['source_sha256'])
   origin=Path(next(f[2:] for f in command if f.startswith('-I') and f.endswith('/prepared/quickjs'))).parent.parent
   require(origin.parent==ROOT/'build' and origin.name.startswith('trident-script-v'),'original QJS compile checkpoint')
   for n,s in row['recipe']['header_context'].items():checked(origin/n if n.startswith('prepared/') else ROOT/n,s)
   checked(Path(held['compile_log']),held['compile_log_sha256'])
   flags=row['recipe']['flags'];require(('-fsanitize=address,undefined' in flags)==(profile=='sanitizer') and '-mfpmath=387' in flags,'real complete QJS instrumentation/x87 flags')
   dst=copy_object(Path(row['object']),row['sha256'],profile,'qjs',index);result.append(dst)
   selected.append(dict(engine='QuickJS',profile=profile,destination=str(dst),sha256=row['sha256'],frozen_row=held,flags=flags,original_command=command,compile_log=str(held['compile_log']),compile_log_sha256=held['compile_log_sha256'],compile_log_pin_origin=held['compile_log_pin_origin']))
  return result
 def wasm_objects(profile):
  rows=sorted((r for r in memory['objects'] if r['profile']==profile),key=lambda r:Path(r['object']).name);require(len(rows)==30 and len({r['source'] for r in rows})==30,'actual corrected WAMR30 runtime objects')
  require({Path(r['source']) for r in rows}=={MEMORY/'prepared'/n for n in original_runtime['linked_units']}|{ROOT/'src/m98_wasm.c',ROOT/'src/m98_wasm_platform.c',ROOT/'src/m98_wasm_math.c'},'exact approved engine and unchanged C ABI sources')
  result=[]
  for index,row in enumerate(rows):
   source=checked(Path(row['source']),row['source_sha256']);obj=checked(Path(row['object']),row['sha256']);flags=row['flags']
   require(('-fsanitize=address,undefined' in flags)==(profile=='sanitizer') and '-mfpmath=387' in flags and '-DM98_WASM_BROWSER_MEMORY=1' in flags and '-DWASM_ENABLE_SHRUNK_MEMORY=0' in flags and '-DM98_WASM_TESTING=1' in flags,'actual corrected engine instrumentation/profile/fault-hook flags')
   compiler=row['compiler'];require(compiler==compilers['gcc'],'original actual memory compiler identity')
   command=['gcc']+flags+['-c',str(source),'-o',str(obj)]
   compile_steps=[s for s in memory['steps'] if s['command']==command];require(len(compile_steps)==1 and compile_steps[0]['returncode']==0 and compile_steps[0]['timed_out'] is False,'one successful actual corrected compile')
   config_steps=[s for s in memory['steps'] if s['command']==['gcc']+flags+['-dM','-E',str(source)]];require(len(config_steps)==1 and config_steps[0]['returncode']==0,'one actual corresponding configuration')
   cfg_path=checked(Path(config_steps[0]['log']),config_steps[0]['sha256']);actual={m[1]:m[2] for m in re.finditer(r'^#define ((?:WASM_|M98_WASM_BROWSER_MEMORY)[A-Z0-9_]*)[ \t]+([^\r\n]+)$',cfg_path.read_text(),re.M)}
   require(actual==memory['effective_config'][profile][str(source)] and all(actual.get(k)==str(v) for k,v in memory['config'].items() if k.startswith(('WASM_','M98_'))),'actual compiled per-TU memory macros')
   checked(Path(compile_steps[0]['log']),compile_steps[0]['sha256']);dst=copy_object(obj,row['sha256'],profile,'wasm',index);result.append(dst)
   selected.append(dict(engine='WAMR',profile=profile,destination=str(dst),sha256=row['sha256'],frozen_row=row,original_command=command,compile_log=compile_steps[0]['log'],compile_log_sha256=compile_steps[0]['sha256'],config_log=config_steps[0]['log'],config_log_sha256=config_steps[0]['sha256'],effective_config=actual))
  return result
 try:
  shutil.copyfile(fixture,build/'wasm_qjs_fixtures.h');checked(build/'wasm_qjs_fixtures.h',FIXTURE_SHA)
  original_copy=build/'original-m98_wasm_qjs_host.c';original_copy.write_bytes(original);checked(original_copy,hashlib.sha256(original).hexdigest())
  prepared_copy=build/'prepared-m98_wasm_qjs_memory_host.c';prepared_copy.write_bytes(prepared);checked(prepared_copy,pins[OWN[1]])
  delta=build/'test-delta.patch';delta.write_text(''.join(difflib.unified_diff(original.decode().splitlines(True),prepared.decode().splitlines(True),fromfile='frozen-v11/tests/m98_wasm_qjs_host.c',tofile='additive/tests/m98_wasm_qjs_memory_host.c')));checked(delta,sha(delta))
  receipt['test_delta']=dict(original_sha256=sha(original_copy),prepared_sha256=sha(prepared_copy),patch_sha256=sha(delta),literal_predicate_deltas=[dict(before=a,after=b) for a,b in DELTAS],all_other_original_bytes_unchanged=True,original_predicates=140,additive_block_sha256=hashlib.sha256(blocks[0].encode()).hexdigest())
  headers=[ROOT/'src/m98_wasm_qjs.h',ROOT/'src/m98_wasm.h',ROOT/'src/m98_trident_script_port.h']+sorted((QJS/'prepared/quickjs').glob('*.h'))+[build/'wasm_qjs_fixtures.h']
  receipt['new_compilation_headers_sha256']={str(p):sha(p) for p in headers}
  for p,s in receipt['new_compilation_headers_sha256'].items():checked(Path(p),s)
  flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Wno-unused-parameter','-Wno-misleading-indentation','-ffunction-sections','-fdata-sections','-fno-strict-aliasing','-ffp-contract=off','-fexcess-precision=standard','-mfpmath=387','-mpc64','-ffloat-store','-Isrc','-I'+str(QJS/'prepared/quickjs'),'-I'+str(build)]
  for profile in ('host','sanitizer'):
   extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if profile=='sanitizer' else []
   objects=qjs_objects(profile)+wasm_objects(profile)
   for src in (ROOT/'src/m98_wasm_qjs.c',ROOT/OWN[1]):
    digest=sha(src);checked(src,digest);obj=build/(profile+'-'+src.stem+'.o');dep=obj.with_suffix('.d');command=[compilers['gcc']['path']]+flags+extra+['-MMD','-MF',str(dep),'-c',str(src),'-o',str(obj)]
    run(profile+'-compile-'+src.stem,command);checked(obj,sha(obj));require(dep.stat().st_size<=131072,'bounded actual non-system dependency output');checked(dep,sha(dep))
    dependency=dep.read_text().replace('\\\n','');require(dependency.startswith(str(obj)+':'),'actual corresponding dependency target');names=dependency[len(str(obj))+1:].split();actual_headers={}
    require(names and all(not any(c in n for c in '\\:#') for n in names),'unescaped trusted canonical dependency paths')
    for n in names:
     p=Path(n);p=p if p.is_absolute() else ROOT/p;require(str(p) in observed,'actual non-system include already pinned by foundation/context');actual_headers[str(p)]=observed[str(p)];checked(p,observed[str(p)],True)
    require(str(src) in actual_headers,'actual source dependency present');objects.append(obj);new_objects.append(dict(profile=profile,source=str(src),source_sha256=digest,object=str(obj),sha256=sha(obj),command=command,headers_sha256=receipt['new_compilation_headers_sha256'],dependency_file=str(dep),dependency_sha256=sha(dep),actual_non_system_dependencies_sha256=actual_headers))
   binary=build/(profile+'-bridge');command=[compilers['clang' if extra else 'gcc']['path']]+extra+[str(p) for p in objects]+['-Wl,--gc-sections','-pthread','-lm','-o',str(binary)]
   run(profile+'-link',command);checked(binary,sha(binary));out=run(profile+'-tests',[str(binary)],False)
   baseline=re.findall(r'^BRIDGE_BASELINE_RESULT (\d+) (\d+) (\d+)$',out.stdout,re.M);summary=re.findall(r'^BRIDGE_RESULT (\d+) (\d+) (\d+)$',out.stdout,re.M);recoveries=re.findall(r'^REAL_JS_REALLOC_RECOVERY initial=(\d+) allocation_point=(\d+)$',out.stdout,re.M)
   require(baseline==[('140','140','0')] and len(summary)==1 and out.returncode==0,'all original140 and actual new test summaries passed')
   total,passed,failed=map(int,summary[0]);require(total>140 and total==passed and failed==0,'honest new assertion result')
   require(len(recoveries)==2 and {int(i) for i,p in recoveries}=={1,2} and all(1<=int(p)<=192 for i,p in recoveries),'actual bounded allocator failures recovered for both initial pages')
   models[profile]=dict(total=total,passed=passed,failed=failed,returncode=out.returncode,original_predicates=140,allocator_recovery=[dict(initial=int(i),allocation_point=int(p)) for i,p in recoveries])
  require(models['host']==models['sanitizer'],'ordinary/full instrumentation result agreement')
  for name,needle in (('asan','heap-buffer-overflow'),('ubsan','signed integer overflow')):
   out=run(name+'-instrumentation-control',[str(build/'sanitizer-bridge'),name],False);require(out.returncode!=0 and needle in out.stderr,'real active deliberate instrument fault')
  completed=True
 except Exception as error:receipt['error']=str(error);raise
 finally:
  late_error=None
  try:
   for p,s in list(observed.items()):checked(Path(p),s,True)
   require({n:sha(ROOT/n) for n in OWN}==pins,'own source late drift')
   receipt['new_proof_closure_rechecked']=True
  except Exception as error:late_error=error;receipt['error']='late evidence drift: '+str(error)
  receipt['passed']=completed and late_error is None;receipt['checked_evidence_sha256']=observed
  receipt['retained_files']={str(p.relative_to(build)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(build.rglob('*')) if p.is_file() and not p.is_symlink()}
  (build/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
  if late_error:raise late_error
 print(json.dumps(dict(result=str(build/'result.json'),sha256=sha(build/'result.json'),models=models),indent=2))
if __name__=='__main__':
 attempt=None
 try:main()
 except Exception as error:
  if attempt is not None and not (attempt/'result.json').exists():
   attempt.mkdir(exist_ok=True)
   pins={n:sha(ROOT/n) for n in OWN}
   for n,s in pins.items():
    p=attempt/'source'/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/n,p)
   (attempt/'result.json').write_text(json.dumps(dict(schema=1,kind='private-genuine-QuickJS-memory-integration-preflight',passed=False,error=str(error),source_sha256=pins,**FALSE_FLAGS),indent=2)+'\n')
  raise
