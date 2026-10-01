#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build selected genuine Mesa TGSI foundation; no VM/global install/network."""
import argparse, hashlib, importlib.util, json, os, re, shutil, subprocess, sys
from pathlib import Path
import pefile
ROOT=Path(__file__).resolve().parents[1]
ARCHIVE_SHA="1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f"
PIN_SHA="71b5e6199051ac9baa9b1bfb21816324cf57325039cf4dcbd9f9c110ebcf4efa"
AUDIT=ROOT/"build/mesa-softpipe-audit-v1"
UNITS=["src/gallium/auxiliary/tgsi/"+n+".c" for n in ("tgsi_exec","tgsi_parse","tgsi_build","tgsi_util","tgsi_info")]+["src/util/half_float.c","src/util/softfloat.c"]
OWN=["src/m98_softpipe_shader.h","src/m98_softpipe_shader.c","src/m98_softpipe_port.h",
 "tests/m98_softpipe_shader_host.c","tests/m98_softpipe_native_gate.c",
 "tests/m98_softpipe_shader_guest.c","tests/test_build_softpipe_shader.py",
 "tools/build_softpipe_shader.py","docs/MESA_SOFTPIPE_PORT_FEASIBILITY.md",
 "src/m98_softpipe_HANDOFF.md","platform/freestanding/memory.c",
 "platform/freestanding/memory.h","benchmarks/win98se-ko-oem-native-exports-v1.json","LICENSE",
 "tools/i486_instruction_gate.py","tests/test_i486_instruction_gate.py"]
EXPORTS=sorted(["m98_sp_abi","m98_sp_open","m98_sp_run","m98_sp_close"])
def require(ok,why):
 if not ok:raise RuntimeError(why)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def replace(text,old,new,count=1):
 require(text.count(old)==count,"prepared patch anchor count: "+old[:90]);return text.replace(old,new)

GATE_SHA="6ba89c7a521e6a7b17e18519f27ed3d1f860d3f8e7ed7d9c89302ea960088973"
GATE_TEST_SHA="6a0ff7367a2c32d09bebda68283b4be710cf27ddae67b21a571424655edabe51"
def instruction_gate():
 path=ROOT/"tools/i486_instruction_gate.py"
 require(digest(path)==GATE_SHA and digest(ROOT/"tests/test_i486_instruction_gate.py")==GATE_TEST_SHA,"reviewed complete-section gate source drift")
 spec=importlib.util.spec_from_file_location("m98_softpipe_frozen_gate",path)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def prepare(build,original,pins):
 prepared=build/"prepared";used={}
 def read(name):
  p=original/name;row=pins[name];require(p.is_file() and not p.is_symlink() and p.stat().st_size==row["size"] and digest(p)==row["sha256"],"original source drift: "+name);used[name]=row;return p.read_text()
 def write(name,text):
  p=prepared/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
 name="src/gallium/auxiliary/tgsi/tgsi_exec.c";text=read(name)
 start=text.index("void \ntgsi_exec_machine_bind_shader(");end=text.index("\n\nstruct tgsi_exec_machine *",start)
 bind=text[start:end].rstrip()
 bind=replace(bind,"void \ntgsi_exec_machine_bind_shader(","bool\nm98_tgsi_bind_checked(")
 bind=replace(bind,"struct tgsi_parse_context parse;","struct tgsi_parse_context parse = {0};")
 bind=replace(bind,"struct tgsi_full_instruction *instructions;","struct tgsi_full_instruction *instructions = NULL;")
 bind=replace(bind,"struct tgsi_full_declaration *declarations;","struct tgsi_full_declaration *declarations = NULL;")
 require(bind.count("return;")==6,"exact bind early-return profile")
 bind=bind.replace("return;","goto bind_fail;")
 bind=replace(bind,"mach->NumInstructions = 0;\n\n      goto bind_fail;","mach->NumInstructions = 0;\n\n      return true;")
 bind=replace(bind,"if (!instructions) {\n      FREE( declarations );\n      goto bind_fail;\n   }","if (!instructions) {\n      goto bind_fail;\n   }")
 for variable,typ,maximum in (("declarations","tgsi_full_declaration","maxDeclarations"),("instructions","tgsi_full_instruction","maxInstructions")):
  pattern=rf"{variable} = REALLOC\({variable},(.*?)\);\n            {maximum} \+= 10;"
  m=re.search(pattern,bind,re.S);require(m is not None,"exact realloc patch")
  replacement=f"struct {typ} *grown = REALLOC({variable},"+m.group(1)+f");\n            if (!grown) goto bind_fail;\n            {variable} = grown;\n            {maximum} += 10;"
  bind=bind[:m.start()]+replacement+bind[m.end():]
 bind=replace(bind,'debug_printf("Unable to (re)allocate space for immidiate constants\\n");\n                  break;','debug_printf("Unable to (re)allocate space for immidiate constants\\n");\n                  goto bind_fail;')
 require(bind.endswith("numInstructions;\n}"),"bind final anchor")
 bind=bind[:-2]+"\n   return true;\nbind_fail:\n   FREE(declarations);\n   FREE(instructions);\n   tgsi_parse_free(&parse);\n   return false;\n}"
 write(name,text[:start]+bind+text[end:])
 name="src/gallium/auxiliary/tgsi/tgsi_exec.h";text=read(name)
 write(name,replace(text,"void \ntgsi_exec_machine_bind_shader(","bool\nm98_tgsi_bind_checked("))
 name="src/util/half_float.h";text=read(name)
 text=replace(text,'#include "util/u_cpu_detect.h"\n','/* Scalar-only profile needs no CPU dispatch/thread dependency. */\n')
 write(name,replace(text,"#if DETECT_ARCH_X86_64 && DETECT_CC_GCC","#if 0 /* Selected scalar profile: no runtime F16C dispatch. */",3))
 # Relative includes from half_float.c must resolve the prepared scalar header.
 name="src/util/half_float.c";write(name,read(name))
 name="src/util/os_memory.h";write(name,read(name))
 name="src/util/os_memory_stdc.h";text=read(name)
 # Original notices retained; actual allocations are checked by the adapter.
 a=text.index("#include <stdlib.h>")
 write(name,text[:a]+'''#include "m98_softpipe_port.h"
#define os_malloc(n) m98_sp_heap_alloc(n)
#define os_calloc(n,s) m98_sp_heap_calloc(n,s)
#define os_free(p) m98_sp_heap_free(p)
#define os_realloc(p,old,n) m98_sp_heap_realloc(p,n)
#define os_malloc_aligned(n,a) m98_sp_heap_aligned(n,a)
#define os_free_aligned(p) m98_sp_heap_free(p)
#define os_realloc_aligned(p,old,n,a) m98_sp_heap_realloc(p,n)
''')
 for name in UNITS:read(name)
 for name in ("licenses/MIT","licenses/BSL-1.0","src/util/format/u_format_table.py","src/util/format/u_format_pack.py","src/util/format/u_format_parse.py","src/util/format/u_format.yaml"):read(name)
 return prepared,used

def pe_gate(p,exports,baseline):
 with pefile.PE(str(p)) as pe:
  h=pe.OPTIONAL_HEADER
  require(pe.FILE_HEADER.Machine==0x14c and h.Magic==0x10b,"native x86 PE32 required")
  require(pe.FILE_HEADER.TimeDateStamp==0,"zero timestamp required")
  require((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion)==(4,10) and h.Subsystem==2 and (h.MajorSubsystemVersion,h.MinorSubsystemVersion)==(4,10),"Win98 GUI4.10 PE")
  require(h.SizeOfStackReserve==2097152 and h.SizeOfStackCommit==524288 and h.AddressOfEntryPoint,"real native stack/entry")
  require(not h.DllCharacteristics&(0x40|0x100|0x8000),"modern loader flags")
  require(h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics&1,"relocations required")
  require(all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)),"no TLS/loadconfig/delay/CLR")
  imports={}
  for module in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
   name=module.dll.decode('ascii').upper();names=[]
   for item in module.imports:
    require(item.name is not None,"named OEM imports required");symbol=item.name.decode('ascii');require(symbol in baseline['dlls'].get(name,[]),"not in original OEM module: "+name+"!"+symbol);names.append(symbol)
   imports[name]=names
  actual=[]
  for item in getattr(getattr(pe,"DIRECTORY_ENTRY_EXPORT",None),"symbols",[]):
   require(item.name is not None and not item.forwarder,"named direct exports required");actual.append(item.name.decode('ascii'))
  require(sorted(actual)==exports,"exact exports")
  if exports:
   require(pe.is_dll() and not imports,"pure native DLL import closure")
   d=h.DATA_DIRECTORY[1]
   if d.VirtualAddress:require(d.Size==20 and pe.get_data(d.VirtualAddress,20)==bytes(20),"exact null import terminator")
  else:require(not pe.is_dll() and set(imports)=={'KERNEL32.DLL'},"probe only original kernel imports")
 return {'sha256':digest(p),'size':p.stat().st_size,'imports':imports,'exports':exports,'stack_reserve':2097152,'stack_commit':524288,'pe98_gate':'pass'}

def main():
 require(not sys.flags.optimize,"Python optimization rejected before output mutation")
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--build-dir',type=Path,default=ROOT/'build/softpipe-shader-v1');ap.add_argument('--nonce',default='softpipe-5abe-20261001-v1');a=ap.parse_args();out=a.build_dir.resolve()
 require(out.is_relative_to(ROOT/'build') and not out.exists(),"fresh own build directory")
 require(re.fullmatch('[A-Za-z0-9-]{8,96}',a.nonce),"bounded nonce")
 require(digest(AUDIT/'input/mesa-26.2.3.tar.xz')==ARCHIVE_SHA and digest(AUDIT/'source-pins.json')==PIN_SHA,"exact original archive/source pin")
 gate=instruction_gate()
 original=AUDIT/'source';pins=json.loads((AUDIT/'source-pins.json').read_text())['files'];source={n:digest(ROOT/n) for n in OWN};out.mkdir()
 steps=[];receipt={'schema':1,'kind':'selected-genuine-mesa-tgsi-build','passed':False,'nonce':a.nonce,'source_sha256':source,'steps':steps,
  'upstream_version':'26.2.3','archive_sha256':ARCHIVE_SHA,'original_source_pin_sha256':PIN_SHA,
  'native_execution':False,'glsl_es_compiler':False,'text_or_raw_tgsi_api':False,'gallium_rasterization':False,'gles':False,'webgl':False,'webgpu':False,'gpu_compute':False,'textures':False,'loops':False,'mshtml_integration':False,'full_browser':False,'modern_apps':False,'vm_operations':False,'global_install':False}
 def run(label,cmd,env=None,timeout=60):
  p=out/(label+'.log')
  try:r=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,env=env,timeout=timeout)
  except subprocess.TimeoutExpired as e:
   pieces=[e.stdout or b'',e.stderr or b''];p.write_text(''.join(x.decode('utf-8','replace') if isinstance(x,bytes) else x for x in pieces))
   steps.append({'name':label,'command':cmd,'returncode':-124,'timeout_seconds':timeout,'timed_out':True,'log':str(p),'sha256':digest(p)})
   raise RuntimeError(label+' exceeded bounded '+str(timeout)+' second deadline') from e
  p.write_text(r.stdout+r.stderr);steps.append({'name':label,'command':cmd,'returncode':r.returncode,'timeout_seconds':timeout,'log':str(p),'sha256':digest(p)});require(r.returncode==0,label+' failed; inspect '+str(p));return r.stdout
 try:
  toolchain={}
  for executable in ('clang','i686-w64-mingw32-gcc','i686-w64-mingw32-objdump','i686-w64-mingw32-as','python3'):
   file=Path(shutil.which(executable)).resolve();toolchain[executable]={'path':str(file),'sha256':digest(file),'size':file.stat().st_size,'version':run('version-'+executable,[executable,'--version']).splitlines()[0]}
  libraries={}
  for name,query in (('libgcc.a','-print-libgcc-file-name'),('libkernel32.a','-print-file-name=libkernel32.a')):
   file=Path(run('resolve-'+name,['i686-w64-mingw32-gcc',query]).strip()).resolve();require(file.is_file() and file.stat().st_size<=32*1024*1024,'bounded actual selected linker input')
   libraries[name]={'path':str(file),'size':file.stat().st_size,'sha256':digest(file)}
  prepared,upstream=prepare(out,original,pins)
  enum=prepared/'src/util/format/u_format_gen.h';enum.parent.mkdir(parents=True,exist_ok=True)
  generated=run('reviewed-format-enums',['python3','-B',str(original/'src/util/format/u_format_table.py'),str(original/'src/util/format/u_format.yaml'),'--enums'])
  require(0<len(generated.encode())<262144 and 'enum pipe_format' in generated and 'Copyright 2010 VMware' in generated,"real bounded original enum generator")
  enum.write_text(generated)
  sources=[prepared/n if (prepared/n).exists() else original/n for n in UNITS]+[ROOT/'src/m98_softpipe_shader.c']
  inc=['-Isrc','-I'+str(prepared/'src'),'-I'+str(prepared/'src/gallium/auxiliary'),'-I'+str(original/'src'),'-I'+str(original/'include'),'-I'+str(original/'src/gallium/include'),'-I'+str(original/'src/gallium/auxiliary'),'-I'+str(original/'src/util')]
  config=['-DUTIL_ARCH_LITTLE_ENDIAN=1','-DUTIL_ARCH_BIG_ENDIAN=0']
  common=['-std=c11','-O1','-g','-Wall','-Wextra','-DMESA_DEBUG=0','-DNDEBUG','-D_POSIX_C_SOURCE=200809L','-DHAVE_PTHREAD=1','-DHAVE_STRUCT_TIMESPEC=1','-fno-builtin','-fexcess-precision=standard','-include','src/m98_softpipe_port.h']+config+inc
  models={}
  for label,extra in (('host',[]),('sanitize',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
   binary=out/(label+'-test');run(label+'-build',['clang']+common+extra+[str(p) for p in sources]+['tests/m98_softpipe_shader_host.c','-lm','-o',str(binary)],timeout=180)
   text=run(label+'-test',[str(binary)],dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
   models[label]=text.strip()
  require(models['host']==models['sanitize'],"host/sanitizer output mismatch")
  run('instruction-gate-fault-controls',['python3','-B','-m','unittest','discover','-s','tests','-p','test_build_softpipe_shader.py'])
  run('assembled-instruction-gate-controls',['python3','-B','-m','unittest','discover','-s','tests','-p','test_i486_instruction_gate.py'])
  native=['-std=c11','-Os','-Wall','-Wextra','-DMESA_DEBUG=0','-DNDEBUG','-D_WIN32_WINNT=0x0400','-DWINVER=0x0400','-fno-builtin','-fexcess-precision=standard','-march=i486','-mno-sse','-mno-sse2','-mno-mmx','-fno-stack-protector','-mno-stack-arg-probe','-include','src/m98_softpipe_port.h']+config+inc
  objects=[]
  for i,p in enumerate(sources+[ROOT/'platform/freestanding/memory.c',ROOT/'tests/m98_softpipe_native_gate.c']):
   obj=out/('native-'+str(i)+'.o');run('native-unit-'+str(i),['i686-w64-mingw32-gcc']+native+['-MD','-MF',str(out/('native-'+str(i)+'.d')),'-c',str(p),'-o',str(obj)]);objects.append(obj)
  defs=out/'M98SHP.def';defs.write_text('LIBRARY M98SHP\nEXPORTS\n'+'\n'.join(' '+n for n in EXPORTS)+'\n')
  linker=['-nostdlib','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-Xlinker','--stack','-Xlinker','2097152,524288']
  dll=out/'M98SHP.DLL';run('native-dll',['i686-w64-mingw32-gcc']+native+linker+['-shared','-Wl,--image-base,0x65800000','-Wl,--entry,_m98_sp_dll_entry@12','-Wl,-Map,'+str(out/'M98SHP.map')]+[str(p) for p in objects]+[str(defs),'-lgcc','-o',str(dll)])
  selected=out/'selected.h';selected.write_text('#define M98_SP_NONCE '+json.dumps(a.nonce)+'\n')
  guest_object=out/'native-probe-guest.o';run('native-probe-unit',['i686-w64-mingw32-gcc']+native+['-I'+str(out),'-MD','-MF',str(out/'native-probe-guest.d'),'-c','tests/m98_softpipe_shader_guest.c','-o',str(guest_object)])
  probe=out/'SHP13PR.EXE';run('native-probe',['i686-w64-mingw32-gcc']+native+['-Wl,--entry,_m98_sp_probe@0']+linker+[str(guest_object),str(objects[-2]),'-Wl,-Map,'+str(out/'SHP13PR.map'),'-lkernel32','-lgcc','-o',str(probe)])
  baseline=json.loads((ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text());artifacts={}
  for p,exports in ((dll,EXPORTS),(probe,[])):
   row=pe_gate(p,exports,baseline)
   try:decoded,raw=gate.scan(p)
   except Exception as error:
    # Failed gates never fall back to a relaxed decode. Retain an independent
    # raw diagnostic listing and the original PE for the rejected checkpoint.
    cmd=['i686-w64-mingw32-objdump','-d','-z','--show-raw-insn','--insn-width=16',str(p)]
    diagnostic=subprocess.run(cmd,capture_output=True,timeout=60);log=out/(p.stem+'-failed-disassembly.log');log.write_bytes(diagnostic.stdout)
    steps.append({'name':p.stem+'-failed-disassembly','command':cmd,'returncode':1,'command_returncode':diagnostic.returncode,'gate_error':str(error),'log':str(log),'sha256':digest(log)})
    raise
   log=out/(p.stem+'-disassembly.log');log.write_bytes(raw)
   steps.append({'name':p.stem+'-disassembly','command':decoded['command'],'returncode':0,'log':str(log),'sha256':digest(log)})
   row['i486_instructions']=decoded;artifacts[p.name]=row
  # Actual compiler dependency closure includes original and SDK math headers.
  compiler_headers={}
  for p in out.glob('native-*.d'):
   words=p.read_text().replace('\\\n',' ').split(':',1)[1].split()
   for word in words:
    f=Path(word).resolve()
    if f.is_relative_to(original):
     name=str(f.relative_to(original));require(digest(f)==pins[name]['sha256'],"original header drift");upstream[name]=pins[name]
    elif f.is_relative_to(prepared) or f.is_relative_to(ROOT/'src') or f.is_relative_to(ROOT/'tests') or f.is_relative_to(ROOT/'platform') or f==selected:pass
    else:
     require(f.is_relative_to(Path('/usr')) and f.is_file(),'unexpected compiler header location')
     compiler_headers[str(f)]={'sha256':digest(f),'size':f.stat().st_size}
  require(len(compiler_headers)<=512 and sum(r['size'] for r in compiler_headers.values())<=32*1024*1024,'bounded complete native compiler header closure')
  for name,row in compiler_headers.items():
   copy=out/'compiler-headers'/Path(name).relative_to('/');copy.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(name,copy);require(digest(copy)==row['sha256'] and digest(Path(name))==row['sha256'],'native compiler header drift');row['frozen_copy']=str(copy.relative_to(out))
  require(source=={n:digest(ROOT/n) for n in OWN},"own source drift")
  frozen=out/'source'
  for n,h in source.items():
   f=frozen/n;f.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/n,f);require(digest(f)==h,"frozen own source")
  originals=out/'original'
  for n,row in upstream.items():
   f=originals/n;f.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original/n,f);require(digest(f)==row['sha256'],"frozen original source")
  receipt.update(passed=True,models=models,artifacts=artifacts,upstream_original=upstream,prepared_sha256={str(p.relative_to(prepared)):digest(p) for p in prepared.rglob('*') if p.is_file()},generated_sha256={p.name:digest(p) for p in (defs,selected,out/'M98SHP.map',out/'SHP13PR.map')},toolchain=toolchain,linker_libraries=libraries,compiler_headers=compiler_headers,reviewed_generator_script_execution=True,
   profile='bounded-typed-ir-to-real-tgsi-fragment-quads-v1',math_profile='checked actual provider double math with float conversion; portable exact nearest-even/trunc/min/max; no GLSL correctly-rounded claim',linked_native_helpers='full linked instruction/import gate; no cached peer objects')
 except Exception as e:receipt['error']=str(e);raise
 finally:(out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'receipt':str(out/'result.json'),'sha256':digest(out/'result.json'),'models':models,'native_execution':False},indent=2))
if __name__=='__main__':main()
