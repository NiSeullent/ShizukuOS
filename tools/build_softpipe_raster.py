#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build an actual TGSI triangle raster slice; no network, VM or global install."""
import argparse, hashlib, importlib.util, json, os, re, shutil, subprocess, sys
from pathlib import Path
import pefile
ROOT=Path(__file__).resolve().parents[1]
FOUNDATION=ROOT/'build/softpipe-shader-v2'
FOUNDATION_SHA='b2c21ccdbf876d310affac58202d4b3139c30f1d71db7b696d12980dfb81cac2'
GATE_SHA='6ba89c7a521e6a7b17e18519f27ed3d1f860d3f8e7ed7d9c89302ea960088973'
GATE_TEST_SHA='6a0ff7367a2c32d09bebda68283b4be710cf27ddae67b21a571424655edabe51'
NEW=['src/m98_softpipe_raster.h','src/m98_softpipe_raster.c','tests/m98_softpipe_raster_host.c','tools/build_softpipe_raster.py','docs/TRIDENT_SOFTWARE_RASTER.md']
CONSUMED=['src/m98_softpipe_shader.h','src/m98_softpipe_shader.c','src/m98_softpipe_port.h','platform/freestanding/memory.c','platform/freestanding/memory.h','LICENSE','benchmarks/win98se-ko-oem-native-exports-v1.json','tools/i486_instruction_gate.py','tests/test_i486_instruction_gate.py']
EXPORTS=['m98_raster_abi','m98_raster_draw']
UNITS=['src/gallium/auxiliary/tgsi/'+n+'.c' for n in ('tgsi_exec','tgsi_parse','tgsi_build','tgsi_util','tgsi_info')]+['src/util/half_float.c','src/util/softfloat.c']
def require(ok,why):
 if not ok:raise RuntimeError(why)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def check(p,h,size=None):
 require(p.is_file() and not p.is_symlink() and (size is None or p.stat().st_size==size) and digest(p)==h,'pinned input drift: '+str(p))
def dependency():
 check(FOUNDATION/'result.json',FOUNDATION_SHA)
 j=json.loads((FOUNDATION/'result.json').read_text())
 require(j.get('schema')==1 and j.get('kind')=='selected-genuine-mesa-tgsi-build' and j.get('passed') is True and not j.get('native_execution'),'exact genuine foundation build profile')
 require(len(j['source_sha256'])==16 and len(j['upstream_original'])==49 and len(j['prepared_sha256'])==7 and len(j['compiler_headers'])==180 and len(j['steps'])==29,'complete frozen dependency profile')
 for n,h in j['source_sha256'].items():check(ROOT/n,h);check(FOUNDATION/'source'/n,h)
 for n,row in j['upstream_original'].items():check(FOUNDATION/'original'/n,row['sha256'],row['size'])
 for n,h in j['prepared_sha256'].items():check(FOUNDATION/'prepared'/n,h)
 for n,h in j['generated_sha256'].items():check(FOUNDATION/n,h)
 for step in j['steps']:
  p=Path(step['log']);require(step['returncode']==0 and p.resolve().parent==FOUNDATION and p.stat().st_size<=16*1024*1024,'frozen successful dependency log');check(p,step['sha256'])
 for n,row in j['artifacts'].items():check(FOUNDATION/n,row['sha256'],row['size'])
 for n,row in j['compiler_headers'].items():check(Path(n),row['sha256'],row['size']);check(FOUNDATION/row['frozen_copy'],row['sha256'],row['size'])
 for row in list(j['toolchain'].values())+list(j['linker_libraries'].values()):check(Path(row['path']),row['sha256'],row['size'])
 check(ROOT/'tools/i486_instruction_gate.py',GATE_SHA);check(ROOT/'tests/test_i486_instruction_gate.py',GATE_TEST_SHA)
 return j
def pe_gate(p):
 with pefile.PE(str(p)) as pe:
  h=pe.OPTIONAL_HEADER
  require(pe.FILE_HEADER.Machine==0x14c and h.Magic==0x10b and pe.is_dll(),'real x86 PE32 DLL')
  require(pe.FILE_HEADER.TimeDateStamp==0 and h.AddressOfEntryPoint,'deterministic timestamp and real entry')
  require((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion,h.MajorSubsystemVersion,h.MinorSubsystemVersion,h.Subsystem)==(4,10,4,10,2),'Win98 GUI 4.10 profile')
  require((h.SizeOfStackReserve,h.SizeOfStackCommit)==(2097152,524288),'bounded native stack')
  require(not h.DllCharacteristics&(0x40|0x100|0x8000) and not pe.FILE_HEADER.Characteristics&1 and h.DATA_DIRECTORY[5].VirtualAddress,'original loader flags/relocations')
  require(all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)),'no TLS/loadconfig/delay/CLR')
  require(not getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]),'no system/CRT imports')
  if h.DATA_DIRECTORY[1].VirtualAddress:require(h.DATA_DIRECTORY[1].Size==20 and pe.get_data(h.DATA_DIRECTORY[1].VirtualAddress,20)==bytes(20),'only null import terminator')
  actual=[]
  for symbol in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[]):
   require(symbol.name is not None and not symbol.forwarder,'named direct exports');actual.append(symbol.name.decode('ascii'))
  require(sorted(actual)==EXPORTS,'exact private raster exports')
 return {'sha256':digest(p),'size':p.stat().st_size,'imports':{},'exports':EXPORTS,'stack_reserve':2097152,'stack_commit':524288,'pe98_gate':'pass'}
def main():
 require(not sys.flags.optimize,'Python optimization rejected before output mutation')
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--build-dir',type=Path,default=ROOT/'build/softpipe-raster-v1');a=ap.parse_args();out=a.build_dir.resolve()
 require(out.is_relative_to(ROOT/'build') and not out.exists(),'fresh own ignored build directory')
 foundation=dependency();source={n:digest(ROOT/n) for n in NEW+CONSUMED}
 spec=importlib.util.spec_from_file_location('raster_frozen_i486_gate',ROOT/'tools/i486_instruction_gate.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
 out.mkdir();steps=[];receipt={'schema':1,'kind':'genuine-tgsi-triangle-raster-build','passed':False,'source_sha256':source,'steps':steps,
  'foundation':{'receipt':str(FOUNDATION/'result.json'),'sha256':FOUNDATION_SHA,'implementation_commit':'e40cd6b','upstream_version':'26.2.3','archive_sha256':foundation['archive_sha256'],'original_sources':49,'prepared_sources':7,'native_sdk_headers':180},
  'profile':'bounded-fixed16-affine-single-triangle-rgba8-depth-tgsi-v1','maximum_compile_jobs':1,
  'native_execution':False,'native_render_readback':False,'glsl_es_compiler':False,'full_gallium':False,'gles':False,'webgl':False,'webgl2':False,'webgpu':False,'gpu_compute':False,'textures':False,'loops':False,'mshtml_integration':False,'full_browser':False,'modern_apps':False,'vm_operations':False,'network_operations':False,'global_install':False}
 def run(label,cmd,env=None,timeout=60):
  p=out/(label+'.log')
  try:r=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,env=env,timeout=timeout)
  except subprocess.TimeoutExpired as e:
   p.write_text(''.join(x.decode('utf-8','replace') if isinstance(x,bytes) else x for x in (e.stdout or b'',e.stderr or b'')))
   steps.append({'name':label,'command':cmd,'returncode':-124,'timeout_seconds':timeout,'timed_out':True,'log':str(p),'sha256':digest(p)});raise RuntimeError(label+' timed out')
  p.write_text(r.stdout+r.stderr);steps.append({'name':label,'command':cmd,'returncode':r.returncode,'timeout_seconds':timeout,'log':str(p),'sha256':digest(p)})
  require(r.returncode==0,label+' failed; preserved log '+str(p));return r.stdout
 try:
  original=FOUNDATION/'original';prepared=FOUNDATION/'prepared'
  inc=['-Isrc','-I'+str(prepared/'src'),'-I'+str(prepared/'src/gallium/auxiliary'),'-I'+str(original/'src'),'-I'+str(original/'include'),'-I'+str(original/'src/gallium/include'),'-I'+str(original/'src/gallium/auxiliary'),'-I'+str(original/'src/util')]
  units=[prepared/n if (prepared/n).is_file() else original/n for n in UNITS]
  host=['-std=c11','-O1','-g','-Wall','-Wextra','-DMESA_DEBUG=0','-DNDEBUG','-D_POSIX_C_SOURCE=200809L','-DHAVE_PTHREAD=1','-DHAVE_STRUCT_TIMESPEC=1','-fno-builtin','-fexcess-precision=standard','-frounding-math','-ffp-contract=off','-include','src/m98_softpipe_port.h','-DUTIL_ARCH_LITTLE_ENDIAN=1','-DUTIL_ARCH_BIG_ENDIAN=0']+inc
  models={}
  for label,extra in (('host',[]),('sanitize',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
   binary=out/(label+'-test');run(label+'-build',['clang']+host+extra+[str(p) for p in units]+['src/m98_softpipe_shader.c','src/m98_softpipe_raster.c','tests/m98_softpipe_raster_host.c','-lm','-o',str(binary)],timeout=180)
   text=run(label+'-test',[str(binary)],dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
   require(re.fullmatch(r'PASS genuine TGSI triangle raster: [1-9][0-9]* assertions; native/WebGL/WebGPU/browser unverified\n',text),'actual full host assertion receipt');models[label]=text.strip()
  require(models['host']==models['sanitize'],'normal/sanitizer result mismatch')
  run('assembled-instruction-gate-controls',['python3','-B','-m','unittest','discover','-s','tests','-p','test_i486_instruction_gate.py'])
  native=['-std=c11','-Os','-Wall','-Wextra','-DNDEBUG','-D_WIN32_WINNT=0x0400','-DWINVER=0x0400','-fno-builtin','-fexcess-precision=standard','-frounding-math','-ffp-contract=off','-march=i486','-mno-sse','-mno-sse2','-mno-mmx','-fno-stack-protector','-mno-stack-arg-probe','-Isrc']
  objects=[]
  for i,p in enumerate(('src/m98_softpipe_raster.c','platform/freestanding/memory.c')):
   obj=out/('native-'+str(i)+'.o');run('native-unit-'+str(i),['i686-w64-mingw32-gcc']+native+['-MD','-MF',str(out/('native-'+str(i)+'.d')),'-c',p,'-o',str(obj)]);objects.append(obj)
  defs=out/'M98RAST.def';defs.write_text('LIBRARY M98RAST\nEXPORTS\n'+'\n'.join(' '+n for n in EXPORTS)+'\n')
  dll=out/'M98RAST.DLL';linker=['-nostdlib','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-Xlinker','--stack','-Xlinker','2097152,524288']
  run('native-dll',['i686-w64-mingw32-gcc']+native+linker+['-shared','-Wl,--image-base,0x65900000','-Wl,--entry,_m98_raster_dll_entry@12','-Wl,-Map,'+str(out/'M98RAST.map')]+[str(p) for p in objects]+[str(defs),'-lgcc','-o',str(dll)])
  row=pe_gate(dll)
  try:decoded,raw=gate.scan(dll)
  except Exception as e:
   cmd=['i686-w64-mingw32-objdump','-d','-z','--show-raw-insn','--insn-width=16',str(dll)];r=subprocess.run(cmd,capture_output=True,timeout=60);log=out/'failed-disassembly.log';log.write_bytes(r.stdout);steps.append({'name':'failed-disassembly','command':cmd,'returncode':1,'command_returncode':r.returncode,'gate_error':str(e),'log':str(log),'sha256':digest(log)});raise
  log=out/'native-disassembly.log';log.write_bytes(raw);steps.append({'name':'native-disassembly','command':decoded['command'],'returncode':0,'log':str(log),'sha256':digest(log)});row['i486_instructions']=decoded
  headers={}
  for dep in out.glob('native-*.d'):
   for word in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
    p=Path(word).resolve()
    if p.is_relative_to(ROOT):require(str(p.relative_to(ROOT)) in source,'untracked repository compile dependency')
    else:
     require(p.is_relative_to(Path('/usr')) and p.is_file(),'unexpected native compiler header');headers[str(p)]={'sha256':digest(p),'size':p.stat().st_size}
  require(0<len(headers)<=128 and sum(r['size'] for r in headers.values())<=8*1024*1024,'bounded complete native header closure')
  for name,h in headers.items():
   p=out/'compiler-headers'/Path(name).relative_to('/');p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(name,p);check(p,h['sha256'],h['size']);h['frozen_copy']=str(p.relative_to(out))
  dependency();require(source=={n:digest(ROOT/n) for n in NEW+CONSUMED},'own source drift after execution')
  for n,h in source.items():p=out/'source'/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/n,p);check(p,h)
  receipt.update(passed=True,models=models,artifacts={'M98RAST.DLL':row},generated_sha256={p.name:digest(p) for p in (defs,out/'M98RAST.map')},compiler_headers=headers,toolchain=foundation['toolchain'],linker_libraries={'libgcc.a':foundation['linker_libraries']['libgcc.a']},host_genuine_mesa_execution=True,transactional_single_triangle_readback=True)
 except Exception as e:receipt['error']=str(e);raise
 finally:(out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'receipt':str(out/'result.json'),'sha256':digest(out/'result.json'),'models':models,'native_execution':False},indent=2))
if __name__=='__main__':main()
