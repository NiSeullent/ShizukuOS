#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build an additive fixed-64KiB WAMR memory profile; no downloads or VM."""
import argparse,hashlib,importlib.util,json,os,re,shutil,signal,subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pefile
ROOT=Path(__file__).resolve().parents[1]
OWN=['tools/build_wasm_memory_profile.py','profiles/wasm-browser-memory-v1.json','patches/wamr-f5f57c09-browser-memory-v1.patch','tests/m98_wasm_memory_host.c','tests/m98_wasm_memory_spec_host.c','docs/TRIDENT_WASM_MEMORY_PROFILE.md']
BASE=ROOT/'build/wasm-runtime-v24'; BASE_SHA='26b28af54df7566a9653633078c1948ff5211714f95a836f4a3b2bb0ea773d91'
SOURCE=ROOT/'build/wasm-runtime-sources-v3'; SPEC=ROOT/'build/wasm-spec-selected-sources-v2'; SPEC_SHA='a9beffe4d27b6e52c6fb5b925cd6f881d9a64fbaabd921099f294b6cc42a8724'
TOOLS=ROOT/'build/wasm-fixture-tools-v1'; TOOL_SHA='ca8af3c91976d1b7676fbfe0951db4f603922338ba294daa893909a5085b7c05'
BRIDGE=ROOT/'build/wasm-qjs-v11'; BRIDGE_SHA='b3e0e6ef6b966b9c9cb0beaaaf41d8227e048fbe6245232b73d825d0584705ac'
WAT={
 'one':'(module (memory (export "memory") 1 3))',
 'two':'(module (memory (export "memory") 2 4))',
 'zero':'(module (memory (export "memory") 0 2))',
 'multi':'(module (memory (export "first") 1 3) (memory (export "second") 2 4))',
 'aux':'(module (memory (export "memory") 2 4) (global (export "__data_end") i32 (i32.const 16384)) (global (export "__heap_base") i32 (i32.const 32768)) (global (export "__stack_pointer") (mut i32) (i32.const 49152)))',
 'callback':'(module (import "env" "visit" (func $visit (param i32) (result i32))) (memory (export "memory") 1 3) (func (export "invoke") (param i32) (result i32) local.get 0 call $visit))',
 'loop':'(module (memory (export "memory") 1 3) (func (export "loop") (loop br 0)))',
 'bulk':'(module (memory (export "memory") 1 2) (data (i32.const 0) "\\ab") (func (export "copy") i32.const 65536 i32.const 0 i32.const 1 memory.copy) (func (export "oob") i32.const 131072 i32.load8_u drop))',
 'largegrow':'(module (memory (export "memory") 1) (func (export "grow") (param i32) (result i32) local.get 0 memory.grow))',
 'largeinitial':'(module (memory (export "memory") 65536))',
 'tables':'(module (type $t (func (result i32))) (memory 1 3) (global (mut i32) (i32.const 1)) (table $a 1 funcref) (table $b 1 funcref) (func $f (type $t) i32.const 19) (func $g (type $t) i32.const 23) (elem (table $a) (i32.const 0) func $f) (elem (table $b) (i32.const 0) func $g) (func (export "invoke") (result i32) i32.const 0 call_indirect $a (type $t) i32.const 0 call_indirect $b (type $t) i32.add))',
 'tableszero':'(module (type $t (func (result i32))) (memory 1 3) (global (mut i32) (i32.const 1)) (table $a 0 funcref) (table $b 1 funcref) (func $f (type $t) i32.const 42) (elem (table $b) (i32.const 0) func $f) (func (export "invoke") (result i32) i32.const 0 call_indirect $b (type $t)))'
}
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def apply_patch_bytes(original,patch,source='core/iwasm/interpreter/wasm_loader.c'):
 lines=original.decode().splitlines(True);changes=patch.decode().splitlines(True);out=[];cursor=0;pos=2
 require(changes[:2]==['--- a/'+source+'\n','+++ b/'+source+'\n'],'exact pinned patch source')
 while pos<len(changes):
  match=re.fullmatch(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n',changes[pos]);require(match,'strict patch hunk');pos+=1
  start=int(match[1])-1;require(cursor<=start<=len(lines),'ordered patch offsets');out+=lines[cursor:start];cursor=start;before=after=0
  while pos<len(changes) and not changes[pos].startswith('@@ '):
   line=changes[pos];pos+=1;require(line[:1] in (' ','+','-'),'strict patch operation')
   if line[0] in (' ','-'):require(cursor<len(lines) and lines[cursor]==line[1:],'exact patch context');cursor+=1;before+=1
   if line[0] in (' ','+'):out.append(line[1:]);after+=1
  require(before==int(match[2]) and after==int(match[4]),'patch hunk counts')
 out+=lines[cursor:];return ''.join(out).encode()
def main():
 global attempt
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--build-dir',type=Path,required=True);args=parser.parse_args();build=args.build_dir.absolute()
 require(build.parent==ROOT/'build' and not build.exists() and build.parent.resolve()==build.parent,'fresh canonical owned build child');attempt=build
 pins={name:sha(ROOT/name) for name in OWN};observed={}
 def checked(path,digest,force=False):
  path=Path(path);require(path.is_absolute() and path.resolve()==path and not path.is_symlink() and path.is_file() and path.stat().st_size<=33554432,'bounded regular evidence')
  old=observed.get(str(path));require(old is None or old==digest,'consistent evidence pin')
  if old is None or force:require(sha(path)==digest,'evidence SHA '+str(path))
  observed[str(path)]=digest;return path
 for name,digest in pins.items():checked(ROOT/name,digest)
 baseline=json.loads(checked(BASE/'result.json',BASE_SHA).read_text());bridge=json.loads(checked(BRIDGE/'result.json',BRIDGE_SHA).read_text());profile=json.loads((ROOT/OWN[1]).read_text())
 require(baseline['passed'] is True and baseline['native_execution'] is False and bridge['passed'] is True and bridge['native_execution'] is False,'frozen host foundations')
 for base,receipt in ((BASE,baseline),(BRIDGE,bridge)):
  for name,digest in receipt['source_sha256'].items():checked(ROOT/name,digest);checked(base/'source'/name,digest)
  for step in receipt['steps']:checked(Path(step['log']),step['sha256'])
  if base==BRIDGE:
   for name,digest in receipt['checked_evidence_sha256'].items():checked(Path(name),digest)
 for name,row in baseline['prepared_files'].items():checked(BASE/'prepared'/name,row['sha256'])
 require(profile['frozen_runtime_receipt_sha256']==BASE_SHA and profile['config_delta']=={'M98_WASM_BROWSER_MEMORY':1,'WASM_ENABLE_SHRUNK_MEMORY':0},'exact new memory profile')
 helper_path=checked(ROOT/'tools/build_wasm_runtime.py',profile['frozen_builder_sha256']);spec=importlib.util.spec_from_file_location('m98_frozen_memory_helpers',helper_path);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
 require(profile['upstream_revision']==helper.REV and profile['page_bytes']==65536,'official version/page discipline')
 members=helper.safe_source(SOURCE)
 for name,row in members.items():checked(SOURCE/'source'/name,row['sha256'])
 checked(SOURCE/'wamr.tar.gz',helper.ARCHIVE_SHA)
 official=json.loads(checked(SPEC/'source-pin.json',SPEC_SHA).read_text());tools=json.loads(checked(TOOLS/'tool-pin.json',TOOL_SHA).read_text())
 for base,rows in ((SPEC/'raw',official['files']),(TOOLS,tools['files'])):
  for name,row in rows.items():checked(base/name,row['sha256'])
 checked(TOOLS/'wabt-1.0.42-linux-x64.tar.gz',tools['archive_sha256'])
 build.mkdir();steps=[];models={};objects=[];config=dict(helper.CONFIG,**profile['config_delta'])
 receipt=dict(schema=1,kind='additive-fixed-64KiB-WAMR-memory-profile',passed=False,source_sha256=pins,base_runtime_receipt_sha256=BASE_SHA,base_bridge_receipt_sha256=BRIDGE_SHA,profile=profile,config=config,steps=steps,models=models,objects=objects,effective_config={},spec_exclusions=[],native_execution=False,browser_js_api=False,browser_wasm=False,full_modern_wasm=False,mshtml_integration=False,full_browser=False,webgpu=False,webgl=False,modern_apps=False,vm_operations=False,network_operations=False)
 def run(label,command,success=True):
  deadline=300 if '-c' in command else 180;timed_out=False
  child=subprocess.Popen(command,cwd=ROOT,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  try:stdout,stderr=child.communicate(timeout=deadline)
  except subprocess.TimeoutExpired:
   timed_out=True
   # This group was created by this exact Popen; never find/stop old or peer jobs.
   try:os.killpg(child.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   stdout,stderr=child.communicate()
  r=subprocess.CompletedProcess(command,None if timed_out else child.returncode,stdout,stderr)
  log=build/(label+'.log');log.write_text(r.stdout+r.stderr);require(log.stat().st_size<=8388608,'bounded log');digest=sha(log);checked(log,digest);steps.append(dict(name=label,command=command,returncode=r.returncode,timed_out=timed_out,deadline_seconds=deadline,subprocess_pid=child.pid,owned_process_group=child.pid,cleanup_returncode=child.returncode if timed_out else None,log=str(log),sha256=digest))
  require(not timed_out,label+': owned subprocess exceeded '+str(deadline)+' seconds; partial output retained')
  if success:require(r.returncode==0,label+': '+(r.stdout+r.stderr)[-5000:])
  return r
 def pin_input(p):
  digest=sha(p);checked(p,digest);receipt.setdefault('generated_input_sha256',{})[str(p)]=digest
 try:
  prepared,patches,prepared_files=helper.prepare(SOURCE,build,members);loader=prepared/'core/iwasm/interpreter/wasm_loader.c';require(sha(loader)==profile['frozen_prepared_loader_sha256'],'exact prior prepared loader')
  patch=checked(ROOT/profile['patch'],profile['patch_sha256']).read_bytes();parts=[p.encode() for p in re.split(r'(?m)(?=^--- a/)',patch.decode()) if p];require(len(parts)==3,'exact three corrective patch sections')
  prefix=b'#include "m98_wasm_platform_internal.h"\n#define M98_WASM_MATH_MAP\n#include "m98_wasm_math.h"\n';body=loader.read_bytes();require(body.startswith(prefix),'unchanged frozen prelude');body=body[len(prefix):];require(hashlib.sha256(body).hexdigest()==profile['original_loader_sha256'],'exact official loader body')
  body=apply_patch_bytes(body,parts[0]);require(hashlib.sha256(body).hexdigest()==profile['patched_original_loader_sha256'],'exact patched original loader');loader.write_bytes(prefix+body)
  patches['core/iwasm/interpreter/wasm_loader.c']=dict(original_sha256=profile['original_loader_sha256'],prior_prepared_sha256=profile['frozen_prepared_loader_sha256'],prepared_sha256=sha(loader),additive_patch_sha256=profile['patch_sha256'])
  rows=profile['additional_prepared_patches'];require([r['source'] for r in rows]==['core/iwasm/common/wasm_memory.c','core/iwasm/interpreter/wasm_runtime.c'],'exact additional source scope')
  for row,section in zip(rows,parts[1:]):
   name=row['source'];p=prepared/name;require(row['basis']=='frozen-v24-prepared' and members[name]['sha256']==row['original_sha256'] and sha(p)==row['prior_prepared_sha256'],'exact original and prepared correction bases')
   corrected=apply_patch_bytes(p.read_bytes(),section,name);require(hashlib.sha256(corrected).hexdigest()==row['patched_prepared_sha256'],'exact prepared correction');p.write_bytes(corrected)
   patches[name]=dict(original_sha256=row['original_sha256'],prior_prepared_sha256=row['prior_prepared_sha256'],prepared_sha256=sha(p),additive_patch_sha256=profile['patch_sha256'],basis=row['basis'])
  receipt['patches']=patches;receipt['prepared_files']={str(p.relative_to(prepared)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(prepared.rglob('*')) if p.is_file()}
  header=[]
  for name,wat in WAT.items():
   p=build/(name+'.wat');p.write_text(wat+'\n');binary=build/(name+'.wasm');run(name+'-assembler',[str(TOOLS/'wabt-1.0.42/bin/wat2wasm'),'--enable-all',str(p),'-o',str(binary)])
   b=binary.read_bytes();header.append('static const unsigned char fixture_'+name+'[]={'+','.join(str(n) for n in b)+'};')
  (build/'wasm_memory_fixtures.h').write_text('/* Original project memory fixtures. */\n'+'\n'.join(header)+'\n')
  generate_spec(build,run,receipt)
  for p in sorted(build.rglob('*')):
   if p.is_file() and p.relative_to(build).parts[0]!='prepared' and p.suffix in ('.wat','.wasm','.json','.h'):pin_input(p)
  units=[prepared/name for name in baseline['linked_units']]+[ROOT/name for name in ('src/m98_wasm.c','src/m98_wasm_platform.c','src/m98_wasm_math.c')]
  includes=['src','tests',str(build)]+[str(prepared/name) for name in ('core','core/iwasm/include','core/iwasm/common','core/iwasm/common/gc','core/iwasm/interpreter','core/shared/utils','core/shared/mem-alloc','core/shared/platform/include')]
  common=['-std=gnu99','-O1','-g','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-ffunction-sections','-fdata-sections','-fno-strict-aliasing','-mfpmath=387','-mpc64','-ffloat-store']+['-I'+n for n in includes]+['-D'+k+'='+str(v) for k,v in config.items()]+['-DBH_MALLOC=wasm_runtime_malloc','-DBH_FREE=wasm_runtime_free']
  nativeflags=common+['-Os','-D__USE_MINGW_ANSI_STDIO=0','-march=i486','-mno-sse','-mno-sse2','-mno-mmx','-fno-builtin','-fno-stack-protector','-fno-delete-null-pointer-checks','-mno-stack-arg-probe','-DBUILD_TARGET_X86_32']
  compiler_pins={}
  for name in ('gcc','clang','i686-w64-mingw32-gcc'):
   path=Path(shutil.which(name)).resolve();checked(path,sha(path));compiler_pins[name]=dict(path=str(path),sha256=sha(path),version=run(name+'-identity',[str(path),'--version']).stdout.splitlines()[0])
  receipt['compilers']=compiler_pins
  nm_path=Path(shutil.which('nm')).resolve();checked(nm_path,sha(nm_path));receipt['layout_decoder']=dict(path=str(nm_path),sha256=sha(nm_path));receipt['table_layout']={}
  layout=build/'table_layout.c';layout.write_text('#include "wasm_runtime.h"\nvoid m98_emit_table_layout(void){__asm__ volatile(".globl m98_layout_table_align\\n.set m98_layout_table_align,%c0\\n.globl m98_layout_table_size\\n.set m98_layout_table_size,%c1\\n.globl m98_layout_table_elements\\n.set m98_layout_table_elements,%c2"::"i"(__alignof__(WASMTableInstance)),"i"(sizeof(WASMTableInstance)),"i"(sizeof(table_elem_type_t)));}\n')
  def compile_one(profile_name,compiler,flags,item):
   index,source=item;digest=sha(source);checked(source,digest);obj=build/(profile_name+'-%02d.o'%index);label=profile_name+'-%02d'%index
   output=run(label+'-config',[compiler]+flags+['-dM','-E',str(source)]).stdout
   actual={m[1]:m[2] for m in re.finditer(r'^#define ((?:WASM_|M98_WASM_BROWSER_MEMORY)[A-Z0-9_]*)[ \t]+([^\r\n]+)$',output,re.M)}
   require(all(actual.get(k)==str(v) for k,v in config.items() if k.startswith(('WASM_','M98_'))),'actual per-TU profile config '+str(source))
   receipt['effective_config'].setdefault(profile_name,{})[str(source)]=actual
   run(label+'-compile',[compiler]+flags+['-c',str(source),'-o',str(obj)]);require(sha(source)==digest,'compile source drift')
   digest_object=sha(obj);checked(obj,digest_object);objects.append(dict(profile=profile_name,source=str(source),source_sha256=digest,object=str(obj),sha256=digest_object,flags=flags,compiler=compiler_pins[compiler]));return obj
  def compile_many(profile_name,compiler,flags,selected):
   with ThreadPoolExecutor(max_workers=2) as pool:return list(pool.map(lambda item:compile_one(profile_name,compiler,flags,item),enumerate(selected)))
  def measure_layout(name,compiler,flags):
   obj=compile_one(name+'-layout',compiler,flags,(0,layout));output=run(name+'-layout-symbols',[str(nm_path),'-P',str(obj)]).stdout
   values={m[1]:int(m[2],16) for m in re.finditer(r'^m98_layout_table_(align|size|elements)[ \t]+A[ \t]+([0-9a-fA-F]+)(?:[ \t].*)?$',output,re.M)}
   require(set(values)=={'align','size','elements'} and values['align'] in (4,8,16) and values['elements'] in (4,8),'actual compiler table layout');receipt['table_layout'][name]=values
  for name,sanitizer in (('host',False),('sanitizer',True)):
   extra=['-fsanitize=address,undefined','-fno-omit-frame-pointer'] if sanitizer else [];flags=common+extra+['-DM98_WASM_TESTING=1'];measure_layout(name,'gcc',flags);engine=compile_many(name,'gcc',flags,units)
   models[name]={}
   for label,source,marker in (('memory','tests/m98_wasm_memory_host.c','MEMORY_RESULT'),('spec','tests/m98_wasm_memory_spec_host.c','MEMORY_SPEC_RESULT')):
    obj=compile_one(name+'-'+label,'gcc',flags,(0,ROOT/source));binary=build/(name+'-'+label);run(name+'-'+label+'-link',['clang' if sanitizer else 'gcc']+extra+[str(p) for p in engine]+[str(obj),'-Wl,--gc-sections','-pthread','-lm','-o',str(binary)])
    checked(binary,sha(binary));result=run(name+'-'+label+'-tests',[str(binary)],False);match=re.search(r'^'+marker+r' (\d+) (\d+) (\d+)$',result.stdout,re.M);models[name][label]=dict(returncode=result.returncode,total=int(match[1]) if match else None,passed=int(match[2]) if match else None,failed=int(match[3]) if match else None)
  require(models['host']==models['sanitizer'] and all(m['returncode']==0 and m['total']==m['passed'] and m['failed']==0 for m in models['host'].values()),'honest normal/full-sanitizer regression results')
  for label,text,needle in [('asan','#include <stdlib.h>\nint main(void){volatile char *p=malloc(1);p[2]=1;free((void*)p);return 0;}\n','heap-buffer-overflow'),('ubsan','#include <stdint.h>\nint main(void){volatile int32_t x=2147483647;return x+1;}\n','signed integer overflow')]:
   p=build/(label+'-control.c');p.write_text(text);pin_input(p);obj=build/(label+'-control.o');binary=build/(label+'-control');flag='-fsanitize='+('address' if label=='asan' else 'undefined');run(label+'-control-compile',['gcc','-O1','-g',flag,'-c',str(p),'-o',str(obj)]);checked(obj,sha(obj));run(label+'-control-link',['clang',flag,str(obj),'-o',str(binary)]);checked(binary,sha(binary));r=run(label+'-control-test',[str(binary)],False);require(r.returncode!=0 and needle in r.stderr,'deliberate instrumentation control')
  measure_layout('native','i686-w64-mingw32-gcc',nativeflags);native=compile_many('native','i686-w64-mingw32-gcc',nativeflags,units+[ROOT/'tests/m98_wasm_native_gate.c'])
  definition=build/'M98WASM.def';definition.write_text('LIBRARY M98WASM\nEXPORTS\n'+'\n'.join(' '+n for n in helper.EXPORTS)+'\n');pin_input(definition);dll=build/'M98WASM.DLL'
  run('native-link',['i686-w64-mingw32-gcc']+nativeflags+['-shared','-nostdlib','-Wl,--exclude-all-symbols','-Wl,--strip-debug','-Wl,--gc-sections','-Wl,--entry,_m98_wasm_dll_entry@12','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-Xlinker','--stack','-Xlinker','2097152,524288']+[str(p) for p in native]+[str(definition),'-lmsvcrt','-lkernel32','-lgcc','-o',str(dll)])
  checked(dll,sha(dll));receipt['native_profile']=native_gate(dll,build,helper,run,steps);receipt['passed']=True
 except Exception as error:receipt['error']=str(error);raise
 finally:
  for step in steps:checked(Path(step['log']),step['sha256'],True)
  for path,digest in observed.items():checked(Path(path),digest,True)
  for name,row in receipt.get('prepared_files',{}).items():require(sha(build/'prepared'/name)==row['sha256'],'prepared source closure drift')
  require(pins=={name:sha(ROOT/name) for name in OWN},'own source drift')
  for name in OWN:
   p=build/'source'/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p);require(sha(p)==pins[name],'own snapshot pin')
  receipt['new_proof_closure_rechecked']=True;receipt['checked_evidence_sha256']=observed;receipt['retained_files']={str(p.relative_to(build)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(build.rglob('*')) if p.is_file() and not p.is_symlink()};(build/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps(dict(result=str(build/'result.json'),sha256=sha(build/'result.json'),models=models),indent=2))
def generate_spec(build,run,receipt):
 lines=['typedef struct {unsigned kind;const char *suite;unsigned line;const unsigned char *bytes;unsigned length;const char *name;m98_wasm_value args[8];unsigned count,results;m98_wasm_value expected[8];const char *trap;} spec_command;'];commands=[];total=0
 def value(row):
  require(row['type']=='i32' and row['value'].isdigit(),'original selected i32 bits');return '{0,UINT64_C('+row['value']+')}'
 for suite in ('memory_grow','bulk-memory/memory_copy','bulk-memory/memory_fill'):
  out=build/('official-'+suite.replace('/','-'));out.mkdir();source=SPEC/'raw/test/core'/(suite+'.wast');json_path=out/'commands.json';run(out.name+'-assembler',[str(TOOLS/'wabt-1.0.42/bin/wast2json'),'--enable-all',str(source),'-o',str(json_path)])
  data=json.loads(json_path.read_text());excluded=False;current_name=None
  for ordinal,c in enumerate(data['commands']):
   total+=1;kind=c['type'];reason=None
   if kind=='module':
    excluded=suite=='memory_grow' and c['line'] in (1,324,331);current_name=c.get('name');reason='whole unchanged >800-page group exceeds 256-page/32MiB host budget' if c['line']==1 else 'whole cross-module imported-memory group requires unsupported registry/linking'
   if excluded and kind in ('module','assert_return','assert_trap','action','register'):
    receipt['spec_exclusions'].append(dict(suite=suite,command=ordinal,line=c['line'],reason=reason or 'dependent command in excluded original module group'));continue
   if kind in ('register','assert_malformed'):
    receipt['spec_exclusions'].append(dict(suite=suite,command=ordinal,line=c['line'],reason='registry has no standalone C ABI effect' if kind=='register' else 'text-only malformed syntax protocol produces no runtime binary'));continue
   ref='NULL';length=0;name='';args=[];expected=[];trap='';results=0
   if kind in ('module','assert_invalid'):
    filename=c['filename'];require(Path(filename).name==filename and filename.endswith('.wasm'),'actual official binary fixture');b=(out/filename).read_bytes();require(8<=len(b)<=1048576,'bounded original fixture');tag='fixture_'+suite.replace('/','_').replace('-','_')+'_'+str(ordinal);lines.append('static const unsigned char '+tag+'[]={'+','.join(str(n) for n in b)+'};');ref=tag;length=len(b);k=0 if kind=='module' else 3
   elif kind in ('assert_return','assert_trap','action'):
    action=c['action'];require(action['type']=='invoke' and ('module' not in action or action['module']==current_name),'current actual numeric instance invoke');name=action['field'];args=[value(r) for r in action['args']]
    if kind in ('assert_return','action'):
     require(kind!='action' or c.get('expected',[])==[],'original standalone void invoke');expected=[value(r) for r in c.get('expected',[])];results=len(expected);k=1
    else:trap=c['text'];results=len(c.get('expected',[]));require(all(r['type']=='i32' for r in c.get('expected',[])),'original trap arity');k=2
   else:raise RuntimeError('unsupported ORIGINAL official protocol '+kind)
   require(len(args)<=8 and results<=8 and len(name)<128,'bounded oracle shape');commands.append('{'+f'{k},{json.dumps(suite)},{c["line"]},{ref},{length},{json.dumps(name)},'+'{'+(','.join(args) or '{0,0}')+'},'+str(len(args))+','+str(results)+',{'+(','.join(expected) or '{0,0}')+'},'+json.dumps(trap)+'}')
 lines.append('static const spec_command spec_commands[]={'+',\n'.join(commands)+'};');(build/'wasm_memory_spec_vectors.h').write_text('\n'.join(lines)+'\n');receipt['official_commands']=dict(original=total,selected=len(commands),excluded=len(receipt['spec_exclusions']));require(total==len(commands)+len(receipt['spec_exclusions']),'complete original command accounting')
def native_gate(dll,build,helper,run,steps):
 catalog=json.loads((ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())['dlls'];imports={}
 with pefile.PE(str(dll)) as pe:
  h=pe.OPTIONAL_HEADER;require(pe.FILE_HEADER.Machine==0x14c and h.Magic==0x10b and pe.is_dll(),'native PE32 x86 DLL');require((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion,h.Subsystem,h.MajorSubsystemVersion,h.MinorSubsystemVersion)==(4,10,2,4,10),'Win98 PE headers');require(pe.FILE_HEADER.TimeDateStamp==0 and h.SizeOfStackReserve==2097152 and h.SizeOfStackCommit==524288 and h.AddressOfEntryPoint,'native stack/timestamp/entry');require(h.DllCharacteristics==0 and pe.FILE_HEADER.Characteristics==0x2306 and h.DATA_DIRECTORY[5].VirtualAddress and h.DATA_DIRECTORY[5].Size,'exact original v24/v5 native relocations/flags');require(all(h.DATA_DIRECTORY[i].VirtualAddress==0 and h.DATA_DIRECTORY[i].Size==0 for i in (9,10,13,14)),'no modern image directory RVAs or sizes')
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
   name=entry.dll.decode().upper();require(name in ('KERNEL32.DLL','MSVCRT.DLL') and name in catalog and name not in imports,'exact unique original OEM DLL descriptors');names=[]
   for imp in entry.imports:require(imp.name is not None and imp.name.decode() in catalog[name],'actual original OEM import');names.append(imp.name.decode())
   require(names and len(names)==len(set(names)),'unique named OEM imports');imports[name]=sorted(names)
  require(set(imports)=={'KERNEL32.DLL','MSVCRT.DLL'},'exact original OEM import DLL set');exports=pe.DIRECTORY_ENTRY_EXPORT.symbols
  require(len(exports)==len(helper.EXPORTS) and all(e.name and not e.forwarder for e in exports) and sorted(e.name.decode() for e in exports)==helper.EXPORTS,'exact twelve named numeric exports without ordinal-only entries or forwarders');require(dll.stat().st_size<=1048576,'bounded native image')
  headers=dict(machine=pe.FILE_HEADER.Machine,characteristics=pe.FILE_HEADER.Characteristics,timestamp=pe.FILE_HEADER.TimeDateStamp,magic=h.Magic,os_version=[h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion],subsystem=h.Subsystem,subsystem_version=[h.MajorSubsystemVersion,h.MinorSubsystemVersion],dll_characteristics=h.DllCharacteristics,stack_reserve=h.SizeOfStackReserve,stack_commit=h.SizeOfStackCommit,entry_rva=h.AddressOfEntryPoint,image_base=h.ImageBase,image_bytes=h.SizeOfImage,section_alignment=h.SectionAlignment,file_alignment=h.FileAlignment,directories={str(i):dict(rva=h.DATA_DIRECTORY[i].VirtualAddress,bytes=h.DATA_DIRECTORY[i].Size) for i in (0,1,5,9,10,13,14)})
 path=ROOT/'tools/i486_instruction_gate.py';require(sha(path)==helper.COMMON_PINS['tools/i486_instruction_gate.py'],'immutable reviewed complete CPU gate');spec=importlib.util.spec_from_file_location('m98_memory_i486_gate',path);gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate);machine,raw=gate.scan(dll);log=build/'native-disassembly-complete.log';log.write_bytes(raw);require(machine['artifact_sha256']==sha(dll) and machine['disassembly_sha256']==sha(log),'exact complete PE decode');steps.append(dict(name='native-disassembly-complete',command=machine['command'],returncode=0,log=str(log),sha256=sha(log)))
 run('native-instruction-controls',['python3',str(ROOT/'tests/test_i486_instruction_gate.py')]);macros=run('native-original-crt-macros',['i686-w64-mingw32-gcc','-std=gnu99','-D__USE_MINGW_ANSI_STDIO=0','-dM','-E','-x','c',str(ROOT/'src/m98_wasm_platform_internal.h')]).stdout
 required={'__USE_MINGW_ANSI_STDIO':'0','PRId64':'"I64d"','PRIi64':'"I64i"','PRIu64':'"I64u"','PRIx64':'"I64x"','PRIX64':'"I64X"'};actual={n:re.search(r'^#define '+n+r'[ \t]+([^\r\n]+)$',macros,re.M)[1] for n in required};require(actual==required and '_vsnprintf' in catalog['MSVCRT.DLL'],'compiler actual original CRT numeric profile')
 return dict(bytes=dll.stat().st_size,sha256=sha(dll),pe_headers=headers,imports=imports,exports=helper.EXPORTS,complete_i486=machine,crt_macros=actual,native_execution=False)
if __name__=='__main__':
 attempt=None
 try:main()
 except Exception as error:
  if attempt is not None and not (attempt/'result.json').exists():
   attempt.mkdir(exist_ok=True);(attempt/'result.json').write_text(json.dumps(dict(passed=False,error=str(error),native_execution=False,browser_wasm=False,browser_js_api=False,full_modern_wasm=False,vm_operations=False,network_operations=False),indent=2)+'\n')
  raise
