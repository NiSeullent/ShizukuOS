#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise a private actual QuickJS/WAMR numeric seam; no native/browser claim."""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OWN=['src/m98_wasm_qjs.h','src/m98_wasm_qjs.c','tests/m98_wasm_qjs_host.c','tools/build_wasm_qjs.py','docs/TRIDENT_WASM_QJS_BRIDGE.md']
QJS=ROOT/'build/trident-script-v10'; QJS_SHA='7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716'
WASM=ROOT/'build/wasm-runtime-v24'; WASM_SHA='26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91'
TOOLS=ROOT/'build/wasm-fixture-tools-v1'; TOOL_SHA='ca8af3c91976d1b7676fbfe0951db4f603922338ba294daa893909a5085b7c05'
# Original private-seam fixtures, not an official standards suite.
WAT={
'numeric':'''(module (memory (export "memory") 1 3)
 (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
 (func (export "wide") (param i64) (result i64) local.get 0 i64.const 1 i64.add)
 (func (export "f32") (param f32) (result f32) local.get 0)
 (func (export "f64") (param f64) (result f64) local.get 0)
 (func (export "mixed") (param i64 f32 f64) (result i64 f32 f64) local.get 0 local.get 1 local.get 2)
 (func (export "store") (param i32) (result i32) i32.const 0 local.get 0 i32.store i32.const 91)
 (func (export "grow") (param i32) (result i32) local.get 0 memory.grow)
 (func (export "size") (result i32) memory.size)
 (func (export "trap") unreachable)
 (func (export "loop") (loop br 0)))''',
'callback':'''(module (import "env" "visit" (func $visit (param i32) (result i32)))
 (func (export "invoke") (param i32) (result i32) local.get 0 call $visit))''',
'missing':'''(module (import "missing" "function" (func $f)) (func (export "go") call $f))''',
'start_loop':'''(module (func $start (loop br 0)) (start $start))'''
}
WAT['no_grow']='(module (memory (export "memory") 1 3))'
WAT['coalesced']='(module (memory (export "memory") 2 4))'
WAT['start_callback']='(module (import "env" "visit" (func $visit (param i32) (result i32))) (func $start i32.const 7 call $visit drop) (start $start))'
def require(ok,message):
 if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 global attempt_dir
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--build-dir',type=Path,required=True);args=parser.parse_args()
 build=args.build_dir.absolute();require(build.parent==ROOT/'build' and not build.exists(),'fresh owned direct build child')
 attempt_dir=build
 observed={}
 def checked(path,digest,limit=33554432):
  path=Path(path);require(path.is_absolute() and path.resolve()==path and not path.is_symlink() and path.is_file(),'regular canonical evidence file')
  require(path.stat().st_size<=limit and re.fullmatch('[0-9a-f]{64}',digest) and sha(path)==digest,'evidence pin '+str(path))
  prior=observed.setdefault(str(path),digest);require(prior==digest,'inconsistent evidence pin');return path
 def read_receipt(base,digest):return json.loads(checked(base/'result.json',digest).read_text())
 q=read_receipt(QJS,QJS_SHA);w=read_receipt(WASM,WASM_SHA)
 require(q['passed'] is True and q['native_guest_execution_verified'] is False and w['passed'] is True and w['native_execution'] is False,'frozen actual host foundations')
 for name in ('gcc','clang'):
  identity=q['tool_identities'][name];require(Path(shutil.which(name)).resolve()==Path(identity['path']),'actual pinned compiler selection');checked(Path(identity['path']),identity['sha256'])
 for base,data in ((QJS,q),(WASM,w)):
  for name,digest in data['source_sha256'].items():checked(ROOT/name,digest);checked(base/'source'/name,digest)
  for step in data['steps']:checked(Path(step['log']),step['sha256'])
 for path,digest in q['prepared_sha256'].items():checked(Path(path),digest)
 for name,row in w['prepared_files'].items():checked(WASM/'prepared'/name,row['sha256'])
 for name,row in w['original_source_files'].items():checked(ROOT/'build/wasm-runtime-sources-v3/source'/name,row['sha256'])
 checked(ROOT/'build/wasm-runtime-sources-v3/wamr.tar.gz',w['upstream_archive_sha256'])
 for row in q['dependency']['archives'].values():checked(Path(row['path']),row['sha256'])
 for directory,key in (('quickjs','quickjs_original_sha256'),('math','musl_original_sha256')):
  for name,digest in q['dependency'][key].items():checked(QJS/'original'/directory/name,digest)
 tool=json.loads(checked(TOOLS/'tool-pin.json',TOOL_SHA).read_text())
 require(tool['version']=='1.0.42' and tool['host_fixture_compiler_only'] is True,'pinned official assembler')
 for name,row in tool['files'].items():checked(TOOLS/name,row['sha256'])
 checked(TOOLS/'wabt-1.0.42-linux-x64.tar.gz',tool['archive_sha256'])
 pins={n:sha(ROOT/n) for n in OWN};build.mkdir();steps=[];selected=[]
 receipt=dict(schema=1,kind='private-actual-QuickJS-WAMR-numeric-seam',passed=False,source_sha256=pins,quickjs_receipt_sha256=QJS_SHA,wasm_receipt_sha256=WASM_SHA,wabt_tool_pin_sha256=TOOL_SHA,steps=steps,selected_objects=selected,models={},mandatory_backend_gaps={'no_memory_grow_or_size_module':{'declared_initial_pages':1,'reported_pages':1,'grow_one_return':-1,'after_pages':1},'coalesced_no_grow_module':{'declared_initial_pages':2,'reported_pages':1,'accessible_last_byte':131071,'grow_one_return':-1}},native_execution=False,browser_js_api=False,browser_wasm=False,full_modern_wasm=False,mshtml_integration=False,full_browser=False,webgpu=False,webgl=False,modern_apps=False,vm_operations=False,network_operations=False)
 def run(label,cmd,success=True):
  env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
  result=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True,timeout=120)
  log=build/(label+'.log');log.write_text(result.stdout+result.stderr);require(log.stat().st_size<=8388608,'bounded log')
  steps.append(dict(name=label,command=cmd,returncode=result.returncode,log=str(log),sha256=sha(log)))
  if success:require(result.returncode==0,label+': '+(result.stdout+result.stderr)[-6000:])
  return result
 def qjs_objects(profile):
  original='host' if profile=='host' else 'sanitize'
  links=[s['argv'] for s in q['steps'] if s['argv'][-1]==str(QJS/original) and '-o' in s['argv']]
  require(len(links)==1,'one frozen QuickJS host link');result=[]
  for obj in links[0]:
   if not obj.endswith('.o'):continue
   rows=[e for e in q['object_cache'] if e['object']==obj];require(rows and len({json.dumps({k:v for k,v in e.items() if k!='reused'},sort_keys=True) for e in rows})==1,'one consistent actual QJS object recipe');row=rows[0];src=Path(row['recipe']['source'])
   if src in [ROOT/'src/m98_trident_script.c',ROOT/'src/m98_trident_script_fp.c',ROOT/'tests/m98_trident_script_host.c']:continue
   checked(src,row['recipe']['source_sha256']);checked(Path(obj),row['sha256'])
   meta=Path(obj).with_suffix('.json');checked(meta,sha(meta));data=json.loads(meta.read_text())
   require(data['object_sha256']==row['sha256'] and data['command']==row['executed_command'],'QJS retained cache metadata')
   normalized=json.dumps(row['recipe'],sort_keys=True).replace(str(QJS),'<CHECKPOINT>')
   require(data['recipe_normalized']==normalized and hashlib.sha256(normalized.encode()).hexdigest()==row['key'],'QJS cache recipe key')
   command=data['command'];original_source=Path(command[command.index('-c')+1]);checked(original_source,row['recipe']['source_sha256'])
   origin=Path(next(f[2:] for f in command if f.startswith('-I') and f.endswith('/prepared/quickjs'))).parent.parent
   require(origin.parent==ROOT/'build' and origin.name.startswith('trident-script-v'),'retained original QJS compile checkpoint')
   for name,digest in row['recipe']['header_context'].items():checked(origin/name if name.startswith('prepared/') else ROOT/name,digest)
   original_steps=[s for s in q['steps'] if s['argv']==command]
   if original_steps:
    require(len(original_steps)==1,'one actual frozen QJS compile log');compile_log=Path(original_steps[0]['log']);checked(compile_log,original_steps[0]['sha256']);log_origin='frozen receipt'
   else:
    compile_log=origin/(original+'-'+original_source.stem+'-compile.log');checked(compile_log,sha(compile_log));log_origin='retained historical log pinned by this closure; old cache metadata has no log hash'
   flags=row['recipe']['flags'];require(('-fsanitize=address,undefined' in flags)==(profile!='host') and '-mfpmath=387' in flags,'full QJS sanitizer/x87 profile')
   dst=build/(profile+'-qjs-'+str(len(result))+'.o');shutil.copyfile(obj,dst);require(sha(dst)==row['sha256'],'copied QJS object pin');result.append(dst)
   selected.append(dict(engine='QuickJS',profile=profile,destination=str(dst),receipt_row=row,metadata_sha256=sha(meta),compile_log=str(compile_log),compile_log_sha256=sha(compile_log),compile_log_pin_origin=log_origin))
  require(len(result)==28,'complete private QJS engine/math/port/platform objects');return result
 def wasm_objects(profile):
  links=[s['command'] for s in w['steps'] if s['name']==profile+'-build'];require(len(links)==1,'one frozen WAMR host link')
  original=[Path(p) for p in links[0] if p.endswith('.o')];require(len(original)==31,'complete WAMR link')
  result=[]
  for obj in original[:-1]:
   rows=[e for e in w['object_cache'] if e['object_sha256']==sha(obj)];require(len(rows)==1,'one frozen WAMR object recipe');row=rows[0]
   checked(obj,row['object_sha256']);cache=ROOT/'build/wasm-runtime-object-cache'/(row['key']+'.o');checked(cache,row['object_sha256'])
   meta=cache.with_suffix('.json');checked(meta,row['provenance_sha256']);data=json.loads(meta.read_text());context=data['context']
   require(data['object_sha256']==row['object_sha256'] and hashlib.sha256(json.dumps(context,sort_keys=True).encode()).hexdigest()==row['key'],'actual WAMR object cache key')
   checked(Path(row['source']),context['source_sha256'])
   command=data['original_command'];original_source=Path(command[command.index('-c')+1]);checked(original_source,context['source_sha256'])
   original_object=Path(command[-1]);origin=original_object.parent;require(origin.parent==ROOT/'build' and origin.name.startswith('wasm-runtime-v'),'retained original WAMR compile checkpoint')
   for name,digest in context['headers'].items():checked(ROOT/name if name.startswith('src/') else origin/'prepared'/name,digest)
   compile_log=origin/(original_object.stem.replace('-','-compile-',1)+'.log');checked(compile_log,data['compile_log_sha256'])
   require(('-fsanitize=address,undefined' in context['flags'])==(profile!='host') and '-mfpmath=387' in context['flags'],'full WAMR sanitizer/x87 profile')
   dst=build/(profile+'-wasm-'+str(len(result))+'.o');shutil.copyfile(obj,dst);require(sha(dst)==row['object_sha256'],'copied WAMR object pin');result.append(dst)
   selected.append(dict(engine='WAMR',profile=profile,destination=str(dst),receipt_row=row,metadata_sha256=sha(meta),flags=context['flags'],original_command=data['original_command'],compile_log=str(compile_log),compile_log_sha256=data['compile_log_sha256']))
  return result
 try:
  header=['/* Original private numeric-seam fixtures, compiled by pinned official WABT. */']
  for name,wat in WAT.items():
   source=build/(name+'.wat');source.write_text(wat+'\n');binary=build/(name+'.wasm')
   run(name+'-assemble',[str(TOOLS/'wabt-1.0.42/bin/wat2wasm'),'--enable-all',str(source),'-o',str(binary)])
   data=binary.read_bytes();require(8<=len(data)<=4096,'bounded actual fixture');header.append('static const unsigned char fixture_'+name+'[]={'+','.join(str(b) for b in data)+'};')
  (build/'wasm_qjs_fixtures.h').write_text('\n'.join(header)+'\n')
  flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Wno-unused-parameter','-Wno-misleading-indentation','-ffunction-sections','-fdata-sections','-fno-strict-aliasing','-ffp-contract=off','-fexcess-precision=standard','-mfpmath=387','-mpc64','-ffloat-store','-Isrc','-I'+str(QJS/'prepared/quickjs'),'-I'+str(build)]
  for profile in ('host','sanitizer'):
   extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if profile=='sanitizer' else []
   objects=qjs_objects(profile)+wasm_objects(profile)
   for source in ('src/m98_wasm_qjs.c','tests/m98_wasm_qjs_host.c'):
    obj=build/(profile+'-'+Path(source).stem+'.o');run(profile+'-compile-'+Path(source).stem,['gcc']+flags+extra+['-c',str(ROOT/source),'-o',str(obj)]);objects.append(obj)
   binary=build/(profile+'-bridge');run(profile+'-link',['clang' if extra else 'gcc']+extra+[str(p) for p in objects]+['-Wl,--gc-sections','-pthread','-lm','-o',str(binary)])
   outcome=run(profile+'-tests',[str(binary)],False);match=re.search(r'^BRIDGE_RESULT (\d+) (\d+) (\d+)$',outcome.stdout,re.M)
   receipt['models'][profile]=dict(total=int(match[1]) if match else None,passed=int(match[2]) if match else None,failed=int(match[3]) if match else None,returncode=outcome.returncode,complete_summary=bool(match))
  require(all(m['complete_summary'] and m['returncode']==0 and m['failed']==0 and m['total']==m['passed'] for m in receipt['models'].values()),'actual test assertion summary, both engine profiles')
  require(receipt['models']['host']==receipt['models']['sanitizer'],'normal/full sanitizer result agreement')
  control=build/'sanitizer-bridge'
  for name,needle in [('asan','heap-buffer-overflow'),('ubsan','signed integer overflow')]:
   result=run(name+'-instrumentation-control',[str(control),name],False);require(result.returncode!=0 and needle in result.stderr,'real instrumented deliberate fault')
  receipt['passed']=True
 except Exception as error:receipt['error']=str(error);raise
 finally:
  for path,digest in list(observed.items()):checked(Path(path),digest)
  require(pins=={n:sha(ROOT/n) for n in OWN},'own source closure drift')
  for name in OWN:
   target=build/'source'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
  receipt['checked_evidence_sha256']=observed
  receipt['retained_files']={str(p.relative_to(build)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(build.rglob('*')) if p.is_file() and not p.is_symlink()}
  (build/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps(dict(result=str(build/'result.json'),sha256=sha(build/'result.json'),models=receipt['models']),indent=2))
if __name__=='__main__':
 attempt_dir=None
 try:main()
 except Exception as error:
  if attempt_dir is not None and not (attempt_dir/'result.json').exists():
   attempt_dir.mkdir(exist_ok=True)
   data=dict(schema=1,kind='private-actual-QuickJS-WAMR-numeric-seam-preflight',passed=False,error=str(error),source_sha256={n:sha(ROOT/n) for n in OWN},native_execution=False,browser_wasm=False,browser_js_api=False,full_browser=False,modern_apps=False,vm_operations=False,network_operations=False)
   for name in OWN:
    target=attempt_dir/'source'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
   (attempt_dir/'result.json').write_text(json.dumps(data,indent=2)+'\n')
  raise
