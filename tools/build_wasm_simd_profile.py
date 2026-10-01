#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded additive classic scalar SIMD recipe; no downloads, namespace or VM."""
import argparse,difflib,hashlib,importlib.util,json,os,re,resource,shutil,signal,subprocess,sys,threading,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
OWN=['profiles/wasm-i486-simd-v1.json','patches/wamr-f5f57c09-i486-simd-v1.patch','tools/build_wasm_simd_profile.py','tests/m98_wasm_simd_host.c','tests/m98_wasm_simd_spec_host.c','docs/TRIDENT_WASM_SIMD_PROFILE.md']
BASE=ROOT/'build/wasm-runtime-v24';BASE_SHA='26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91'
MEMORY=ROOT/'build/wasm-memory-profile-v8';MEMORY_SHA='657308666b48175c0369cdac0d3c35f9888d053f7c3038c5625c1ee5209dc5dc'
JS=ROOT/'build/wasm-qjs-memory-v4';JS_SHA='01ffc91cb052b9c6c7e4c217267b6f8ffc6f447333da46446c3ebb3b2c447307'
BRIDGE=ROOT/'build/wasm-qjs-v11';BRIDGE_SHA='b3e0e6ef6b966b9c9cb0beaaaf41d8227e048fbe6245232b73d825d0584705ac'
QJS=ROOT/'build/trident-script-v10';QJS_SHA='7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716'
SOURCE=ROOT/'build/wasm-runtime-sources-v3';TOOLS=ROOT/'build/wasm-fixture-tools-v1'
SOURCE_FLOOR=20*1024**3;RUNTIME_FLOOR=22058516480;OWN_LIMIT=512*1024**2;ADMISSION_FLOOR=RUNTIME_FLOOR+OWN_LIMIT;RAM_FLOOR=6*1024**3;RSS_LIMIT=2*1024**3;FILE_LIMIT=64*1024**2
FALSE=dict(native_execution=False,browser_js_api=False,browser_wasm=False,full_fixed_simd=False,relaxed_simd=False,current_exception_handling=False,full_modern_wasm=False,mshtml_integration=False,full_browser=False,webgpu=False,webgl=False,modern_apps=False,vm_operations=False,network_operations=False,external_toolchain_complete_closure=False)
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def u(n):
 b=[]
 while n>=128:b.append((n&127)|128);n>>=7
 return bytes(b+[n])
def section(n,b):return bytes([n])+u(len(b))+b
def binary(body,result=b'',global_bytes=b'',end=True,memory_bytes=b''):
 out=b'\0asm\1\0\0\0'+section(1,b'\1\x60\0'+u(len(result))+result)+section(3,b'\1\0')
 if memory_bytes:out+=section(5,memory_bytes)
 if global_bytes:out+=section(6,global_bytes)
 out+=section(7,b'\1\4read\0\0');code=b'\0'+body+(b'\x0b' if end else b'');return out+section(10,b'\1'+u(len(code))+code)
def modules():
 ops={'and':'v128.and','andnot':'v128.andnot','or':'v128.or','xor':'v128.xor','add':'i32x4.add','shuffle':'i8x16.shuffle '+' '.join(str((j*7+3)%32) for j in range(16)),'swizzle':'i8x16.swizzle'}
 functions=['(func (export "'+name+'") (param i32 i32 i32) local.get 0 local.get 1 v128.load align=1 local.get 2 v128.load align=1 '+op+' v128.store align=1)' for name,op in ops.items()]
 for j in range(4):
  functions+=['(func (export "extract'+str(j)+'") (param i32) (result i32) local.get 0 v128.load i32x4.extract_lane '+str(j)+')','(func (export "replace'+str(j)+'") (param i32 i32 i32) local.get 0 local.get 1 v128.load local.get 2 i32x4.replace_lane '+str(j)+' v128.store)']
 functions+=['''(func (export "not") (param i32 i32) local.get 0 local.get 1 v128.load v128.not v128.store)
 (func (export "bitselect") (param i32 i32 i32 i32) local.get 0 local.get 1 v128.load local.get 2 v128.load local.get 3 v128.load v128.bitselect v128.store)
 (func (export "splat") (param i32 i32) local.get 0 local.get 1 i32x4.splat v128.store)
 (func (export "local") (param i32 i32) (local $v v128) local.get 1 v128.load local.tee $v drop local.get 0 local.get $v local.set $v local.get $v v128.store)
 (func (export "select") (param i32 i32 i32 i32) local.get 0 local.get 1 v128.load local.get 2 v128.load local.get 3 select v128.store)
 (func (export "typedselect") (param i32 i32 i32 i32) local.get 0 local.get 1 v128.load local.get 2 v128.load local.get 3 select (result v128) v128.store)
 (func (export "control") (param i32 i32 i32) local.get 0 block (result v128) local.get 2 if local.get 1 v128.load br 1 end local.get 1 v128.load end v128.store)
 (func $vector (param v128) (result v128) local.get 0 v128.const i32x4 1 2 3 4 i32x4.add)
 (func (export "calls") (param i32 i32) local.get 0 local.get 1 v128.load call $vector v128.store)
 (func $tail (param i32 i32) local.get 0 local.get 1 v128.load v128.store)
 (func (export "tail") (param i32 i32) local.get 0 local.get 1 return_call $tail)
 (func (export "gwrite") (param i32) local.get 0 v128.load global.set $g)
 (func (export "gread") (param i32) local.get 0 global.get $g v128.store)
 (func (export "callback") (param i32 i32 i32) (result i32) (local $v v128) local.get 1 v128.load local.set $v local.get 2 call $visit local.get 0 local.get $v v128.store)
 (func (export "gc") (param i32 i32 i32) (result i32) (local $r (ref null $S)) (local $v v128)
 i32.const 61 struct.new $S local.set $r local.get 1 v128.load local.set $v
 loop local.get 2 struct.new $S drop local.get 2 i32.const 1 i32.sub local.tee 2 br_if 0 end
 local.get 0 local.get $v v128.store local.get $r struct.get $S 0)''']
 return {'main':'(module (import "env" "visit" (func $visit (param i32) (result i32))) (type $S (struct (field i32))) (memory (export "memory") 1 3) (global $g (mut v128) (v128.const i32x4 7 8 9 10)) '+' '.join(functions)+')',
 'start':'(module (memory (export "memory") 1 3) (func $s i32.const 0 v128.const i32x4 7 8 9 10 v128.store) (start $s))',
 'multi':'(module (memory 1 3) (memory 2 4) (func (export "move") (param i32 i32) local.get 0 local.get 1 v128.load 1 align=1 v128.store 0 align=1))',
 'loop':'(module (func (export "loop") (local v128) (loop v128.const i32x4 1 2 3 4 local.set 0 br 0)))',
 'boundary':'(module (memory (export "memory") 1 3) (func (export "vector") (result v128) i32.const 0 i32.const 1 i32.store8 v128.const i32x4 1 2 3 4))',
 'importvector':'(module (import "env" "vector" (func (param v128) (result v128))))',
 'gcstruct':'(module (type (struct (field v128))))','gcarray':'(module (type (array (mut v128))))'}
def import_frozen(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--build-dir',type=Path,required=True);parser.add_argument('--native',action='store_true');args=parser.parse_args();build=args.build_dir.absolute()
 require(build.parent==ROOT/'build' and build.parent.resolve()==build.parent and not build.exists(),'fresh canonical owned direct build child')
 observed={};lock=threading.Lock();steps=[];objects=[];models={};high={'own_bytes':0,'rss_bytes':0,'minimum_free_bytes':None,'minimum_available_memory_bytes':None};active=set()
 def checked(path,digest):
  path=Path(path);require(path.is_absolute() and path.resolve()==path and path.is_file() and not path.is_symlink() and path.stat().st_size<=FILE_LIMIT,'bounded canonical regular evidence '+str(path));require(re.fullmatch('[0-9a-f]{64}',digest),'literal SHA')
  with lock:
   old=observed.get(str(path));require(old is None or old==digest,'conflicting pin');
   if old is None:require(sha(path)==digest,'exact evidence '+str(path));observed[str(path)]=digest
  return path
 def memory_available():return int(re.search(r'^MemAvailable:[ \t]+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])*1024
 def measure():
  fs=os.statvfs(ROOT);free=fs.f_bavail*fs.f_frsize;ram=memory_available();used=sum(p.stat().st_size for p in build.rglob('*') if p.is_file()) if build.exists() else 0;rss=0
  with lock:groups=set(active)
  if groups:
   for p in Path('/proc').iterdir():
    if not p.name.isdigit():continue
    try:
     fields=(p/'stat').read_text().rsplit(')',1)[1].split()
     if int(fields[2]) in groups:rss+=int(fields[21])*os.sysconf('SC_PAGE_SIZE')
    except (FileNotFoundError,ProcessLookupError,PermissionError,ValueError,IndexError):pass
  with lock:
   high['own_bytes']=max(high['own_bytes'],used);high['rss_bytes']=max(high['rss_bytes'],rss)
   for key,value in [('minimum_free_bytes',free),('minimum_available_memory_bytes',ram)]:high[key]=value if high[key] is None else min(high[key],value)
  return free,ram,used,rss
 def guard(admission=False):
  free,ram,used,rss=measure();require(free>=(ADMISSION_FLOOR if admission else RUNTIME_FLOOR),'disk admission/runtime floor');require(ram>=RAM_FLOOR,'available-memory floor');require(used<=OWN_LIMIT,'whole owned logical-byte budget');require(rss<=RSS_LIMIT,'aggregate own process-group RSS limit')
 guard(True)
 pins={n:sha(ROOT/n) for n in OWN}
 for n,d in pins.items():checked(ROOT/n,d)
 profile=json.loads((ROOT/OWN[0]).read_text());require(profile['memory_profile_receipt_sha256']==MEMORY_SHA and profile['supported_secondary_opcodes']==[0,11,12,13,14,17,27,28,77,78,79,80,81,82,174],'exact additive profile')
 parents={}
 for parent,digest in [(BASE,BASE_SHA),(MEMORY,MEMORY_SHA),(JS,JS_SHA),(BRIDGE,BRIDGE_SHA),(QJS,QJS_SHA)]:
  receipt=json.loads(checked(parent/'result.json',digest).read_text());require(receipt['passed'] is True,'accepted frozen foundation');parents[str(parent)]=receipt
  for n,d in receipt.get('source_sha256',{}).items():checked(ROOT/n,d);checked(parent/'source'/n,d)
  for n,d in receipt.get('checked_evidence_sha256',{}).items():checked(Path(n),d)
  for step in receipt['steps']:checked(Path(step['log']),step['sha256'])
  for n,row in receipt.get('retained_files',{}).items():checked(parent/n,row['sha256'])
 memory=parents[str(MEMORY)];original=parents[str(BASE)];js=parents[str(JS)];qjs=parents[str(QJS)]
 for key in ('native_execution','browser_js_api','full_modern_wasm'):require(memory[key] is False and js[key] is False,'component-only frozen evidence')
 helper_path=checked(ROOT/'tools/build_wasm_runtime.py','9e10828c4f1c88fa162bde9a76c014c709a604876dc710fba424fe6c3443e506');helper=import_frozen(helper_path,'m98_simd_frozen_runtime')
 memory_helper=import_frozen(checked(ROOT/'tools/build_wasm_memory_profile.py','44049c5ed1aeedd3b79c57e9c2be68fefb9bb25022aaf09554fc0fabdf93c07e'),'m98_simd_frozen_patch_parser')
 members=helper.safe_source(SOURCE);checked(SOURCE/'wamr.tar.gz',helper.ARCHIVE_SHA)
 for n,row in members.items():checked(SOURCE/'source'/n,row['sha256'])
 toolpin=json.loads(checked(TOOLS/'tool-pin.json','ca8af3c91976d1b7676fbfe0951db4f603922338ba294daa893909a5085b7c05').read_text())
 for n,row in toolpin['files'].items():checked(TOOLS/n,row['sha256'])
 checked(TOOLS/'wabt-1.0.42-linux-x64.tar.gz',toolpin['archive_sha256']);assembler=TOOLS/'wabt-1.0.42/bin/wat2wasm'
 guard(True);build.mkdir();receipt=dict(schema=1,kind='additive-classic-i486-scalar-integer-data-SIMD',passed=False,source_sha256=pins,profile=profile,parent_receipt_sha256={str(BASE):BASE_SHA,str(MEMORY):MEMORY_SHA,str(JS):JS_SHA,str(BRIDGE):BRIDGE_SHA,str(QJS):QJS_SHA},steps=steps,objects=objects,models=models,resource_highwaters=high,resource_limits=dict(admission_free_bytes=ADMISSION_FLOOR,runtime_free_bytes=RUNTIME_FLOOR,available_memory_bytes=RAM_FLOOR,whole_own_logical_bytes=OWN_LIMIT,aggregate_owned_group_rss_bytes=RSS_LIMIT,child_fsize_bytes=FILE_LIMIT,poll_seconds=0.25,overshoot_between_samples_possible=True),effective_config={},non_system_headers_sha256={},**FALSE)
 limiter=Path(shutil.which('prlimit')).resolve();checked(limiter,sha(limiter));receipt['child_limit_tool']=dict(path=str(limiter),sha256=sha(limiter))
 def run(label,command,success=True):
  guard();stdout_path=build/(label+'.stdout');stderr_path=build/(label+'.stderr');deadline=300 if '-c' in command else 180;reason=None;t0=time.monotonic()
  with stdout_path.open('wb') as out,stderr_path.open('wb') as err:
   actual_command=[str(limiter),'--fsize='+str(FILE_LIMIT)+':'+str(FILE_LIMIT),'--']+[str(x) for x in command]
   child=subprocess.Popen(actual_command,cwd=ROOT,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'),stdout=out,stderr=err,start_new_session=True)
   with lock:active.add(child.pid)
   try:
    while child.poll() is None:
     try:guard();require(time.monotonic()-t0<=deadline,'owned subprocess deadline')
     except Exception as e:
      reason=str(e)
      try:os.killpg(child.pid,signal.SIGKILL)
      except ProcessLookupError:pass
      break
     time.sleep(0.25)
    child.wait()
   finally:
    with lock:active.remove(child.pid)
  for p in (stdout_path,stderr_path):checked(p,sha(p))
  stdout=stdout_path.read_text(errors='replace');stderr=stderr_path.read_text(errors='replace');row=dict(name=label,command=[str(x) for x in command],executed_command=actual_command,returncode=None if reason else child.returncode,cleanup_returncode=child.returncode if reason else None,resource_failure=reason,deadline_seconds=deadline,subprocess_pid=child.pid,owned_process_group=child.pid,stdout=str(stdout_path),stdout_sha256=sha(stdout_path),stderr=str(stderr_path),stderr_sha256=sha(stderr_path),elapsed_seconds=time.monotonic()-t0)
  with lock:steps.append(row)
  require(reason is None,label+': '+str(reason)+'; partial output retained')
  if success:require(child.returncode==0,label+': '+(stdout+stderr)[-6000:])
  return subprocess.CompletedProcess(command,child.returncode,stdout,stderr)
 def generated(path,data):
  require(path.is_relative_to(build) and path.resolve()==path,'owned canonical output');guard();require(measure()[2]+len(data)<=OWN_LIMIT-8*1024**2,'reserve final bounded receipt space');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);checked(path,sha(path));return path
 try:
  for n in OWN:generated(build/'source'/n,(ROOT/n).read_bytes())
  prepared=build/'prepared';prepared.mkdir()
  for n,row in memory['prepared_files'].items():
   src=checked(MEMORY/'prepared'/n,row['sha256']);dst=prepared/n;dst.parent.mkdir(parents=True,exist_ok=True);generated(dst,src.read_bytes())
  patch=checked(ROOT/profile['patch'],profile['patch_sha256']).read_bytes();sections=[p.encode() for p in re.split(r'(?m)(?=^--- a/)',patch.decode()) if p];require(len(sections)==len(profile['sources'])==4,'exact four SIMD source sections')
  for row,part in zip(profile['sources'],sections):
   path=prepared/row['path'];require(sha(path)==row['basis_sha256'],'exact accepted memory basis');data=memory_helper.apply_patch_bytes(path.read_bytes(),part,row['path']);require(hashlib.sha256(data).hexdigest()==row['patched_sha256'],'exact additive prepared source');
   # Replacing a prepared source is the only intentional change to a new-build pin.
   observed.pop(str(path));generated(path,data)
  receipt['prepared_files']={str(p.relative_to(prepared)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(prepared.rglob('*')) if p.is_file()}
  fixtures={}
  for name,wat in modules().items():
   src=generated(build/(name+'.wat'),(wat+'\n').encode());out=build/(name+'.wasm');run(name+'-assembler',[str(assembler),'--enable-all',str(src),'-o',str(out)]);checked(out,sha(out));fixtures[name]=out.read_bytes()
  def array(name,b):return 'static const unsigned char '+name+'[]={'+','.join(str(v) for v in b)+'};'
  generated(build/'wasm_simd_fixtures.h',('\n'.join(array('fixture_'+n,b) for n,b in fixtures.items())+'\n').encode())
  fault_rows=[];fault_arrays=[]
  def fault(name,b,unsupported=0):fault_arrays.append(array(name,b));fault_rows.append('{'+name+',sizeof('+name+'),'+str(unsupported)+'}')
  enum=(prepared/'core/iwasm/interpreter/wasm_opcode.h').read_text();opcodes=[int(m[1],16) for m in re.finditer(r'^\s*SIMD_\w+\s*=\s*0x([0-9a-f]+)',enum,re.M)];require(len(opcodes)==236 and len(set(opcodes))==236,'actual original fixed SIMD opcode authority')
  for op in opcodes+list(range(256,276)):
   if op not in profile['supported_secondary_opcodes']:fault('unsupported_'+str(op),binary(b'\xfd'+u(op)),1)
  for name,body in {'leb_overflow':b'\xfd\x80\x80\x80\x80\x10','lane':b'\xfd\x0c'+bytes(16)+b'\xfd\x1b\x04\x1a','shuffle':b'\xfd\x0c'+bytes(16)+b'\xfd\x0c'+bytes(16)+b'\xfd\x0d'+bytes([32]*16),'types':b'\x41\0\xfd\x11\xfd\xae\x01\x1a','wire_internal':b'\xe3','alignment':b'\x41\0\xfd\0\5\0\x1a','memoryindex':b'\x41\0\xfd\0\x44\x02\0\x1a'}.items():fault(name,binary(body,memory_bytes=b'\1\1\1\3' if name in ('alignment','memoryindex') else b''))
  fault('leb_truncated',binary(b'\xfd\x80',end=False))
  for name,secondary in [('init_wrong',b'\x0d'),('init_overflow',b'\x80\x80\x80\x80\x10')]:fault(name,binary(b'',global_bytes=b'\1\x7b\0\xfd'+secondary+bytes(16)+b'\x0b'))
  fault('init_truncated',binary(b'',global_bytes=b'\1\x7b\0\xfd\x80'))
  fault('gcstruct',fixtures['gcstruct']);fault('gcarray',fixtures['gcarray'])
  # Proper overlong encodings for both const initializer and ordinary secondary.
  literal=(7).to_bytes(4,'little')+(8).to_bytes(4,'little')+(0xdeadbeef).to_bytes(4,'little')+(10).to_bytes(4,'little')
  overlong=binary(b'\x23\0\xfd\x9b\0\2',b'\x7f',b'\1\x7b\0\xfd\x8c\0'+literal+b'\x0b')
  fault_arrays+=[array('fixture_overlong',overlong),array('fixture_boundary',fixtures['boundary']),array('fixture_importvector',fixtures['importvector'])]
  generated(build/'wasm_simd_faults.h',('/* Original project binary controls, not official SIMD WAST. */\n'+'\n'.join(fault_arrays)+'\ntypedef struct {const unsigned char *bytes;unsigned length,unsupported;} simd_fault;\nstatic const simd_fault faults[]={'+','.join(fault_rows)+'};\n').encode());receipt['literal_simd_faults']=len(fault_rows);receipt['official_simd_suite']=False
  for parent,name in [(BASE,'wasm_original_fixtures.h'),(MEMORY,'wasm_memory_fixtures.h'),(MEMORY,'wasm_memory_spec_vectors.h'),(BRIDGE,'wasm_qjs_fixtures.h')]:generated(build/name,checked(parent/name,sha(parent/name)).read_bytes())
  # Only observation ownership changes: both original foreign-thread predicates
  # move after join, retaining the original 1237 assertions and their meanings.
  numeric=(ROOT/'tests/m98_wasm_host.c').read_bytes();text=numeric.decode();old='static void *foreign(void *p){m98_wasm_info info;(void)p;CHECK(m98_wasm_inspect(store,&info)==M98_WASM_THREAD);CHECK(m98_wasm_close(store)==M98_WASM_THREAD);return NULL;}'
  new='static int foreign_inspect_status,foreign_close_status;\nstatic void *foreign(void *p){m98_wasm_info info;(void)p;foreign_inspect_status=m98_wasm_inspect(store,&info);foreign_close_status=m98_wasm_close(store);return NULL;}'
  join='CHECK(pthread_join(thread,NULL)==0);';require(text.count(old)==1 and text.count(join)==1,'exact original observation race');text=text.replace(old,new).replace(join,join+'CHECK(foreign_inspect_status==M98_WASM_THREAD);CHECK(foreign_close_status==M98_WASM_THREAD);');restored=text.replace(new,old).replace(join+'CHECK(foreign_inspect_status==M98_WASM_THREAD);CHECK(foreign_close_status==M98_WASM_THREAD);',join);require(restored.encode()==numeric,'all original numeric predicates retained')
  generated(build/'numeric-original.c',numeric);numeric_test=generated(build/'numeric-observed.c',text.encode());delta=generated(build/'numeric-observation.patch',''.join(difflib.unified_diff(numeric.decode().splitlines(True),text.splitlines(True))).encode());receipt['numeric_observation_only_delta']=dict(original_sha256=hashlib.sha256(numeric).hexdigest(),prepared_sha256=sha(numeric_test),patch_sha256=sha(delta),expected_assertions=1237)
  config=dict(memory['config'],**profile['config_delta']);receipt['config']=config
  includes=['src',str(build)]+[str(prepared/n) for n in ('core','core/iwasm/include','core/iwasm/common','core/iwasm/common/gc','core/iwasm/interpreter','core/shared/utils','core/shared/mem-alloc','core/shared/platform/include')]
  common=['-std=gnu99','-O1','-g','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-ffunction-sections','-fdata-sections','-fno-strict-aliasing','-mfpmath=387','-mpc64','-ffloat-store']+['-I'+n for n in includes]+['-D'+k+'='+str(v) for k,v in config.items()]+['-DBH_MALLOC=wasm_runtime_malloc','-DBH_FREE=wasm_runtime_free']
  compilers={}
  for name in ['gcc','clang']+(['i686-w64-mingw32-gcc'] if args.native else []):
   path=Path(shutil.which(name)).resolve();checked(path,sha(path));compilers[name]=dict(path=str(path),sha256=sha(path),version=run(name+'-identity',[str(path),'--version']).stdout.splitlines()[0])
  receipt['compilers']=compilers
  def compile_one(model,flags,item):
   index,src=item;digest=sha(src);checked(src,digest);label=model+'-%02d'%index;obj=build/(label+'.o');dep=build/(label+'.d');compiler='i686-w64-mingw32-gcc' if model.startswith('native') else 'gcc'
   output=run(label+'-config',[compiler]+flags+['-dM','-E',str(src)]).stdout;actual={m[1]:m[2] for m in re.finditer(r'^#define ((?:WASM_|M98_WASM_)[A-Z0-9_]*)[ \t]+([^\r\n]+)$',output,re.M)}
   require(all(actual.get(k)==str(v) for k,v in config.items() if k.startswith(('WASM_','M98_'))),'actual TU config '+str(src))
   run(label+'-compile',[compiler]+flags+['-MMD','-MF',str(dep),'-c',str(src),'-o',str(obj)]);checked(dep,sha(dep));require(sha(src)==digest,'source drift during compile')
   deps=dep.read_text().replace('\\\n',' ').split(':',1)[1].split();require(deps and all('\\' not in n for n in deps),'bounded unambiguous actual MMD paths')
   for n in deps:
    p=Path(n);p=p if p.is_absolute() else ROOT/p;checked(p,sha(p));receipt['non_system_headers_sha256'][str(p)]=sha(p)
   checked(obj,sha(obj));receipt['effective_config'].setdefault(model,{})[str(src)]=actual;objects.append(dict(profile=model,source=str(src),source_sha256=digest,object=str(obj),sha256=sha(obj),flags=flags,compiler=compilers[compiler],dependency=str(dep),dependency_sha256=sha(dep)));return obj
  def compile_many(model,flags,selected):
   with ThreadPoolExecutor(max_workers=2) as pool:return list(pool.map(lambda item:compile_one(model,flags,item),enumerate(selected)))
  units=[prepared/n for n in original['linked_units']]+[ROOT/n for n in ('src/m98_wasm.c','src/m98_wasm_platform.c','src/m98_wasm_math.c')];require(len(units)==30,'exact fresh real WAMR30')
  receipt['selected_quickjs_objects']=[]
  def qjs_objects(model):
   rows=[r for r in js['selected_objects'] if r['engine']=='QuickJS' and r['profile']==model];require(len(rows)==28,'actual frozen QuickJS28');result=[]
   for index,row in enumerate(rows):
    held=row['frozen_row'];cached=held['receipt_row'];require(any({k:v for k,v in r.items() if k!='reused'}=={k:v for k,v in cached.items() if k!='reused'} for r in qjs['object_cache']),'actual QJS cache binding');normalized=json.dumps(cached['recipe'],sort_keys=True).replace(str(QJS),'<CHECKPOINT>');require(hashlib.sha256(normalized.encode()).hexdigest()==cached['key'],'actual normalized cache key')
    metadata=checked(Path(cached['object']).with_suffix('.json'),held['metadata_sha256']);data=json.loads(metadata.read_text());require(data['object_sha256']==cached['sha256'] and data['command']==cached['executed_command'] and data['recipe_normalized']==normalized,'actual cache compile metadata');checked(Path(held['compile_log']),held['compile_log_sha256']);command=data['command'];checked(Path(command[command.index('-c')+1]),cached['recipe']['source_sha256']);origin=Path(next(f[2:] for f in command if f.startswith('-I') and f.endswith('/prepared/quickjs'))).parent.parent
    for n,d in cached['recipe']['header_context'].items():checked(origin/n if n.startswith('prepared/') else ROOT/n,d)
    flags=cached['recipe']['flags'];require(('-fsanitize=address,undefined' in flags)==(model=='sanitizer') and '-mfpmath=387' in flags,'true QJS instrumentation/x87 profile');src=checked(Path(cached['object']),cached['sha256']);dst=generated(build/(model+'-qjs-%02d.o'%index),src.read_bytes());result.append(dst);receipt['selected_quickjs_objects'].append(dict(profile=model,destination=str(dst),sha256=sha(dst),original_row=row,cache_key=cached['key'],original_command=command))
   return result
  for model,san in [('host',False),('sanitizer',True)]:
   extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if san else [];flags=common+extra+['-DM98_WASM_TESTING=1'];engine=compile_many(model,flags,units);models[model]={}
   tests=[('simd',ROOT/OWN[3],'SIMD_RESULT',None),('faults',ROOT/OWN[4],'SIMD_FAULT_RESULT',None),('numeric',numeric_test,None,1237),('memory',ROOT/'tests/m98_wasm_memory_host.c','MEMORY_RESULT',386),('memoryspec',ROOT/'tests/m98_wasm_memory_spec_host.c','MEMORY_SPEC_RESULT',4641)]
   for label,source,marker,expected in tests:
    obj=compile_one(model+'-'+label,flags,(0,source));exe=build/(model+'-'+label);run(model+'-'+label+'-link',['clang' if san else 'gcc']+extra+[str(p) for p in engine]+[str(obj),'-Wl,--gc-sections','-pthread','-lm','-o',str(exe)]);checked(exe,sha(exe));r=run(model+'-'+label+'-tests',[str(exe)],False)
    match=re.search(r'^'+marker+r' (\d+) (\d+) (\d+)$',r.stdout,re.M) if marker else re.search(r'^WAMR actual standalone tests: (\d+) assertions;',r.stdout,re.M);require(match,'actual test result marker '+label);n=int(match[1]);passed=int(match[2]) if marker else n;failed=int(match[3]) if marker else 0;models[model][label]=dict(total=n,passed=passed,failed=failed,returncode=r.returncode);require(r.returncode==0 and n==passed and failed==0 and (expected is None or n==expected),'actual new backend '+label+' regression')
   quick=qjs_objects(model);qjs_include=QJS/'prepared/quickjs';qflags=flags+['-std=gnu11','-O0','-g0','-fwrapv','-ffp-contract=off','-fexcess-precision=standard','-I'+str(qjs_include)];bridge=compile_many(model+'-bridge',qflags,[ROOT/'src/m98_wasm_qjs.c',ROOT/'tests/m98_wasm_qjs_memory_host.c']);exe=build/(model+'-jsmemory');run(model+'-jsmemory-link',['clang' if san else 'gcc']+extra+[str(p) for p in engine+quick+bridge]+['-Wl,--gc-sections','-pthread','-lm','-o',str(exe)]);checked(exe,sha(exe));r=run(model+'-jsmemory-tests',[str(exe)],False);match=re.search(r'^BRIDGE_RESULT (\d+) (\d+) (\d+)$',r.stdout,re.M);require(match and tuple(map(int,match.groups()))==(622,622,0) and r.returncode==0,'retained true 622 JS memory predicates on new engine');models[model]['jsmemory']=dict(total=622,passed=622,failed=0,returncode=r.returncode)
  require(models['host']==models['sanitizer'],'identical complete instrumented/ordinary outcomes')
  for name,source,needle in [('asan','#include <stdlib.h>\nint main(void){volatile char *p=malloc(1);p[2]=1;free((void*)p);return 0;}\n','heap-buffer-overflow'),('ubsan','#include <stdint.h>\nint main(void){volatile int32_t x=2147483647;return x+1;}\n','signed integer overflow')]:
   src=generated(build/(name+'-control.c'),source.encode());obj=build/(name+'-control.o');exe=build/(name+'-control');flag='-fsanitize='+('address' if name=='asan' else 'undefined');run(name+'-control-compile',['gcc','-O1','-g',flag,'-c',str(src),'-o',str(obj)]);checked(obj,sha(obj));run(name+'-control-link',['clang',flag,str(obj),'-o',str(exe)]);checked(exe,sha(exe));r=run(name+'-control-tests',[str(exe)],False);require(r.returncode!=0 and needle in r.stderr,'actual full instrumentation detector control')
  if args.native:
   receipt['native_profile']=native(build,common,units,compile_many,run,checked,generated,helper)
  receipt['passed']=True
 except Exception as error:
  receipt['error']=str(error)
 finally:
  try:
   for p,d in list(observed.items()):require(sha(Path(p))==d,'late byte drift '+p)
   for n,d in pins.items():require(sha(ROOT/n)==d,'own late source drift')
   receipt['new_proof_closure_rechecked']=True
  except Exception as error:receipt['passed']=False;receipt['closure_error']=str(error)
  receipt['checked_evidence_sha256']=observed;receipt['retained_files']={str(p.relative_to(build)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(build.rglob('*')) if p.is_file()}
  try:guard()
  except Exception as error:receipt['passed']=False;receipt['final_resource_error']=str(error)
  # Retaining a bounded failure receipt is required even when a runtime floor
  # stops compilation. The reservation above leaves room for this final record.
  encoded=(json.dumps(receipt,indent=2)+'\n').encode();require(len(encoded)<=8*1024**2 and measure()[2]+len(encoded)<=OWN_LIMIT,'bounded reserved final receipt');(build/'result.json').write_bytes(encoded);measure()
 print(json.dumps(dict(passed=receipt['passed'],result=str(build/'result.json'),sha256=sha(build/'result.json'),models=models,error=receipt.get('error'),resource_highwaters=high),indent=2));return 0 if receipt['passed'] else 1
def native(build,common,units,compile_many,run,checked,generated,helper):
 # Native admission is separate from host execution; this path never launches PE.
 import pefile
 flags=common+['-Os','-D__USE_MINGW_ANSI_STDIO=0','-march=i486','-mno-sse','-mno-sse2','-mno-mmx','-fno-builtin','-fno-stack-protector','-fno-delete-null-pointer-checks','-mno-stack-arg-probe','-DBUILD_TARGET_X86_32'];objs=compile_many('native',flags,units+[ROOT/'tests/m98_wasm_native_gate.c']);definition=generated(build/'M98WASM.def',('LIBRARY M98WASM\nEXPORTS\n'+'\n'.join(' '+n for n in helper.EXPORTS)+'\n').encode());dll=build/'M98WASM.DLL'
 run('native-link',['i686-w64-mingw32-gcc']+flags+['-shared','-nostdlib','-Wl,--exclude-all-symbols','-Wl,--strip-debug','-Wl,--gc-sections','-Wl,--entry,_m98_wasm_dll_entry@12','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-Xlinker','--stack','-Xlinker','2097152,524288']+[str(p) for p in objs]+[str(definition),'-lmsvcrt','-lkernel32','-lgcc','-o',str(dll)]);checked(dll,sha(dll));catalog_path=ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json';checked(catalog_path,sha(catalog_path));catalog=json.loads(catalog_path.read_text())['dlls'];imports={};sections={}
 with pefile.PE(str(dll)) as pe:
  h=pe.OPTIONAL_HEADER;require(pe.FILE_HEADER.Machine==0x14c and h.Magic==0x10b and pe.is_dll() and pe.FILE_HEADER.Characteristics==0x2306 and h.DllCharacteristics==0,'exact original PE32 x86 flags');require((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion,h.Subsystem,h.MajorSubsystemVersion,h.MinorSubsystemVersion)==(4,10,2,4,10),'Win98 loader versions');require(pe.FILE_HEADER.TimeDateStamp==0 and h.SizeOfStackReserve==2097152 and h.SizeOfStackCommit==524288 and h.AddressOfEntryPoint,'native stack/entry/timestamp');require(h.DATA_DIRECTORY[5].VirtualAddress and h.DATA_DIRECTORY[5].Size and all(h.DATA_DIRECTORY[i].VirtualAddress==0 and h.DATA_DIRECTORY[i].Size==0 for i in (9,10,13,14)),'old loader directories')
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
   name=entry.dll.decode().upper();require(name in ('KERNEL32.DLL','MSVCRT.DLL') and name not in imports,'exact unique OEM descriptor');names=[v.name.decode() if v.name is not None else None for v in entry.imports];require(names and len(set(names))==len(names) and all(n is not None and n in catalog[name] for n in names),'actual named unique OEM imports');imports[name]=sorted(names)
  require(set(imports)=={'KERNEL32.DLL','MSVCRT.DLL'},'exact OEM import set');exports=pe.DIRECTORY_ENTRY_EXPORT.symbols;require(len(exports)==12 and all(e.name and not e.forwarder for e in exports) and sorted(e.name.decode() for e in exports)==helper.EXPORTS,'exact scalar ABI12, no ordinals/forwarders')
  headers=dict(machine=pe.FILE_HEADER.Machine,characteristics=pe.FILE_HEADER.Characteristics,dll_characteristics=h.DllCharacteristics,os=[h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion],subsystem=h.Subsystem,subsystem_version=[h.MajorSubsystemVersion,h.MinorSubsystemVersion],entry_rva=h.AddressOfEntryPoint,stack_reserve=h.SizeOfStackReserve,stack_commit=h.SizeOfStackCommit,directories={str(i):dict(rva=h.DATA_DIRECTORY[i].VirtualAddress,bytes=h.DATA_DIRECTORY[i].Size) for i in (0,1,5,9,10,13,14)})
  for s in pe.sections:
   if not s.Characteristics&0x20000000:continue
   name=s.Name.rstrip(b'\0').decode('ascii');size=s.Misc_VirtualSize;require(name not in sections and 0<size<=s.SizeOfRawData<=4*1024**2,'actual executable section extent');data=s.get_data()[:size];require(len(data)==size,'actual executable bytes');sections[name]=dict(data=data,address=h.ImageBase+s.VirtualAddress)
  require(sections and sum(len(s['data']) for s in sections.values())<=4*1024**2,'total executable byte bound')
 path=checked(ROOT/'tools/i486_instruction_gate.py',helper.COMMON_PINS['tools/i486_instruction_gate.py']);gate=import_frozen(path,'m98_simd_pinned_cpu_decoder');decoder=Path(shutil.which('i686-w64-mingw32-objdump')).resolve();checked(decoder,sha(decoder));command=[str(decoder),'-d','-z','--show-raw-insn','--insn-width=16',str(dll)];r=run('native-disassembly-complete',command);require(not r.stderr,'actual objdump diagnostics');cpu=gate.decode(r.stdout,sections);cpu.update(artifact_sha256=sha(dll),artifact_bytes=dll.stat().st_size,command=command,disassembly_sha256=hashlib.sha256(r.stdout.encode()).hexdigest());checked(ROOT/'tests/test_i486_instruction_gate.py',helper.COMMON_PINS['tests/test_i486_instruction_gate.py']);run('native-instruction-controls',['python3',str(ROOT/'tests/test_i486_instruction_gate.py')]);return dict(sha256=sha(dll),bytes=dll.stat().st_size,headers=headers,imports=imports,exports=helper.EXPORTS,complete_i486=cpu,native_execution=False)
if __name__=='__main__':sys.exit(main())
