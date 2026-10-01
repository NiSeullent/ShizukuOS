#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze real Mesa inputs; host pixel/lifetime tests and freestanding AMD64 PE.

No repository/upstream scripts are executed, downloaded, installed or booted.
Compiler and host test processes write only to a fresh private ignored directory.
"""
import argparse, datetime, hashlib, json, os, re, shutil, signal, subprocess, sys, uuid
from pathlib import Path
import pefile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
PEER=Path('/root/Win98-Modern-theme-tls-5abe')
SHADER=PEER/'build/softpipe-shader-v2'
RASTER=PEER/'build/softpipe-raster-v3'
SHADER_SHA='b2c21ccdbf876d310affac58202d4b3139c30f1d71db7b696d12980dfb81cac2'
RASTER_SHA='26d7055953bb6e0915df675ea0c0797c07e0c5704b00ef16f077e1867da3164f'
UNITS=['src/gallium/auxiliary/tgsi/'+n+'.c' for n in ('tgsi_exec','tgsi_parse','tgsi_build','tgsi_util','tgsi_info')]+['src/util/half_float.c','src/util/softfloat.c']
SOURCES=['backend.c','backend.h','fp64.h','host.c','probe.c','build.py']
EXPORTS=sorted(['ntg_abi','ntg_create','ntg_destroy','ntg_texture_create','ntg_shader_create','ntg_retain','ntg_release','ntg_map','ntg_unmap','ntg_clear_color','ntg_clear_depth','ntg_copy','ntg_bind','ntg_draw'])
RESERVE=20*1024**3
WRITE_LIMIT=256*1024**2
OUTPUT_LIMIT=16*1024**2
def require(value,why):
 if not value:raise RuntimeError(why)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def check(p,h,size=None):
 require(p.is_file() and not p.is_symlink() and (size is None or p.stat().st_size==size) and digest(p)==h,'input drift: '+str(p))
def foundation():
 check(SHADER/'result.json',SHADER_SHA);check(RASTER/'result.json',RASTER_SHA)
 s=json.loads((SHADER/'result.json').read_text());r=json.loads((RASTER/'result.json').read_text())
 require(s['kind']=='selected-genuine-mesa-tgsi-build' and s['passed'] is True and r['kind']=='genuine-tgsi-triangle-raster-build' and r['passed'] is True,'real successful upstream foundations')
 require(s['archive_sha256']=='1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f' and len(s['upstream_original'])==49 and len(s['prepared_sha256'])==7,'complete reviewed selected source profile')
 rows={}
 for name,row in s['upstream_original'].items():rows[SHADER/'original'/name]={'sha256':row['sha256'],'size':row['size']}
 for name,h in s['prepared_sha256'].items():p=SHADER/'prepared'/name;rows[p]={'sha256':h,'size':p.stat().st_size}
 for name in ('m98_softpipe_shader.c','m98_softpipe_shader.h','m98_softpipe_raster.c','m98_softpipe_raster.h','m98_softpipe_port.h'):
  n='src/'+name;p=RASTER/'source'/n;rows[p]={'sha256':r['source_sha256'][n],'size':p.stat().st_size}
 for p,row in rows.items():check(p,row['sha256'],row['size'])
 return s,r,rows
def replace(text,old,new):
 require(text.count(old)==1,'exact AMD64 preparation anchor: '+old[:80]);return text.replace(old,new)
def fp_prepare(text):
 pattern=r'typedef struct \{\n#ifdef _WIN32\n unsigned char state\[108\];.*?static void fp_leave\(fp_scope \*s\)\{.*?\n\}'
 matches=list(re.finditer(pattern,text,re.S));require(len(matches)==1,'exact original FP scope')
 m=matches[0];return text[:m.start()]+'#include "fp64.h"\ntypedef ntg_fp_scope fp_scope;\n#define fp_enter ntg_fp_enter\n#define fp_leave ntg_fp_leave'+text[m.end():]
def pe_gate(p):
 with pefile.PE(str(p)) as pe:
  h=pe.OPTIONAL_HEADER
  require(pe.is_dll() and pe.FILE_HEADER.Machine==0x8664 and h.Magic==0x20b,'actual AMD64 PE32+ DLL')
  require(pe.FILE_HEADER.TimeDateStamp==0 and h.AddressOfEntryPoint and h.Subsystem==2,'deterministic timestamp, actual entry, GUI profile')
  require(h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics&1,'real relocations required')
  require(all(not h.DATA_DIRECTORY[i].VirtualAddress and not h.DATA_DIRECTORY[i].Size for i in (9,10,13,14)),'no TLS/loadconfig/delay/CLR')
  relocations=[e for block in getattr(pe,'DIRECTORY_ENTRY_BASERELOC',[]) for e in block.entries if e.type]
  require(relocations and all(e.type==10 and pe.get_section_by_rva(e.rva) is not None for e in relocations),'actual AMD64 DIR64 relocation records required')
  require(not getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]),'no OS/CRT dependency may enter the backend')
  require(pe.get_section_by_rva(h.AddressOfEntryPoint).Characteristics&0x20000000,'entry must be executable')
  actual=[]
  for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
   require(s.name and not s.forwarder and s.address,'direct named implemented exports');actual.append(s.name.decode('ascii'))
   require(pe.get_section_by_rva(s.address).Characteristics&0x20000000,'export must be actual executable code')
  require(sorted(actual)==EXPORTS,'exact private resource exports, no D3D/DXGI impersonation')
 return {'sha256':digest(p),'size':p.stat().st_size,'imports':{},'exports':EXPORTS,'machine':'AMD64','PE32+':True}
def main():
 require(not sys.flags.optimize,'Python optimization rejected')
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path);ap.add_argument('--nonce',default=uuid.uuid4().hex);a=ap.parse_args()
 require(re.fullmatch('[0-9a-f]{32}',a.nonce),'exact32 lowercase hex trial nonce')
 out=(a.out or HERE/'build'/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])).resolve()
 require(out.is_relative_to(HERE/'build') and not out.exists(),'fresh owned ignored build path required')
 require(shutil.disk_usage(ROOT).free>=RESERVE+WRITE_LIMIT,'20 GiB floor plus bounded writes required')
 s,r,rows=foundation();own={HERE/n:digest(HERE/n) for n in SOURCES}
 for n in ('platform/freestanding/memory.c','platform/freestanding/memory.h','LICENSE'):own[ROOT/n]=digest(ROOT/n)
 out.mkdir(parents=True);steps=[];receipt={'schema':1,'kind':'private-amd64-genuine-mesa-resource-backend','passed':False,'nonce':a.nonce,'steps':steps,'source_sha256':{str(p):h for p,h in own.items()},'peer_foundations':{'shader_receipt':str(SHADER/'result.json'),'shader_sha256':SHADER_SHA,'raster_receipt':str(RASTER/'result.json'),'raster_sha256':RASTER_SHA,'mesa_version':'26.2.3','archive_sha256':s['archive_sha256']},'upstream_inputs':{str(p):row for p,row in rows.items()},'resource_reserve_bytes':RESERVE,'write_limit_bytes':WRITE_LIMIT,'output_limit_bytes':OUTPUT_LIMIT,'native_windows98_execution_verified':False,'actual_guest_rendering_verified':False,'direct3d_device_creation_verified':False,'dxgi_presentation_verified':False,'direct2d_support_verified':False,'directwrite_full_support_verified':False,'modern_app_functionality_verified':False,'global_install':False,'network_operations':False,'vm_operations':False}
 def budget():
  total=sum(p.stat().st_size for p in out.rglob('*') if p.is_file());require(total<=WRITE_LIMIT and shutil.disk_usage(ROOT).free>=RESERVE,'bounded outputs and unchanged reserve');return total
 def run(label,cmd,timeout=180,env=None):
  budget();log=out/(label+'.log')
  with log.open('wb') as f:
   try:
    proc=subprocess.Popen(list(map(str,cmd)),cwd=ROOT,stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True)
    import time
    begin=time.monotonic()
    while proc.poll() is None:
     if time.monotonic()-begin>timeout or log.stat().st_size>OUTPUT_LIMIT or sum(p.stat().st_size for p in out.rglob('*') if p.is_file())>WRITE_LIMIT or shutil.disk_usage(ROOT).free<RESERVE:
      os.killpg(proc.pid,signal.SIGKILL);proc.wait();raise RuntimeError(label+' stopped by owned resource/timeout guard')
     time.sleep(.1)
    code=proc.returncode
   finally:
    if 'proc' in locals() and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
  steps.append({'name':label,'command':list(map(str,cmd)),'returncode':code,'log':str(log),'sha256':digest(log)})
  require(log.stat().st_size<=OUTPUT_LIMIT,'final log exceeds output gate');require(code==0,label+' failed; log '+str(log));budget();return log.read_text(errors='replace')
 try:
  for p,h in own.items():dst=out/'source'/p.relative_to(ROOT);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dst);check(dst,h)
  for p,row in rows.items():
   if p.is_relative_to(SHADER):dst=out/'mesa'/p.relative_to(SHADER)
   else:dst=out/'glue'/p.relative_to(RASTER/'source/src')
   dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dst);check(dst,row['sha256'],row['size'])
  glue=out/'glue';prepared=out/'mesa/prepared';original=out/'mesa/original';frozen=out/'source/ntwddm/graphics_backend'
  for name in ('m98_softpipe_shader.c','m98_softpipe_raster.c'):
   p=glue/name;text=fp_prepare(p.read_text())
   if name.endswith('raster.c'):
    text=replace(text,'sizeof(m98_r_surface)==32&&sizeof(m98_r_ops)==24&&sizeof(m98_r_draw)==420,"native x86 raster ABI"','sizeof(m98_r_surface)==40&&sizeof(m98_r_ops)==40&&sizeof(m98_r_draw)==432,"native AMD64 raster ABI"')
   p.write_text(text)
  inc=['-I'+str(frozen),'-I'+str(glue),'-I'+str(prepared/'src'),'-I'+str(prepared/'src/gallium/auxiliary'),'-I'+str(original/'src'),'-I'+str(original/'include'),'-I'+str(original/'src/gallium/include'),'-I'+str(original/'src/gallium/auxiliary'),'-I'+str(original/'src/util')]
  units=[prepared/n if (prepared/n).is_file() else original/n for n in UNITS]+[glue/'m98_softpipe_shader.c',glue/'m98_softpipe_raster.c',frozen/'backend.c']
  common=['-std=c11','-O1','-g','-Wall','-Wextra','-DMESA_DEBUG=0','-DNDEBUG','-fno-builtin','-frounding-math','-ffp-contract=off','-include',str(glue/'m98_softpipe_port.h'),'-DUTIL_ARCH_LITTLE_ENDIAN=1','-DUTIL_ARCH_BIG_ENDIAN=0']+inc
  models={}
  for label,flags in (('host',[]),('sanitize',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
   binary=out/(label+'-test');run(label+'-build',['clang']+common+['-D_POSIX_C_SOURCE=200809L','-DHAVE_PTHREAD=1','-DHAVE_STRUCT_TIMESPEC=1']+flags+units+[frozen/'host.c','-lm','-o',binary])
   text=run(label+'-test',[binary],env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
   require(re.fullmatch(r'PASS genuine Mesa resource backend: [1-9][0-9]* assertions; DirectX and guest rendering remain unverified\n',text),'actual complete genuine Mesa test verdict');models[label]=text.strip()
  require(models['host']==models['sanitize'],'normal/sanitizer assertion agreement')
  native=[x for x in common if x!='-g']+['-D_WIN32_WINNT=0x0601','-DWINVER=0x0601','-ffreestanding','-fno-stack-protector','-mno-stack-arg-probe']
  objects=[];headers={}
  def dependencies(dep):
   for n in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
    h=Path(n).resolve()
    require(h.is_relative_to(out) or h.is_relative_to(Path('/usr')),'compile dependency outside frozen sources/toolchain')
    if not h.is_relative_to(out):headers[str(h)]={'sha256':digest(h),'size':h.stat().st_size}
  for i,p in enumerate(units+[out/'source/platform/freestanding/memory.c']):
   obj=out/('native-'+str(i)+'.o');dep=out/('native-'+str(i)+'.d');run('native-unit-'+str(i),['x86_64-w64-mingw32-gcc']+native+['-MD','-MF',dep,'-c',p,'-o',obj]);objects.append(obj)
   dependencies(dep)
  defs=out/'NTGSW.def';defs.write_text('LIBRARY NTGSW\nEXPORTS\n'+'\n'.join(' '+n for n in EXPORTS)+'\n')
  dll=out/'NTGSW.DLL';run('native-dll',['x86_64-w64-mingw32-gcc','-nostdlib','-shared','-Wl,--entry,ntg_dll_entry','-Wl,--subsystem,windows','-Wl,--no-insert-timestamp','-Wl,--image-base,0x7fff39000000','-Wl,-Map,'+str(out/'NTGSW.map')]+objects+[defs,'-o',dll])
  row=pe_gate(dll)
  nonce_header=out/'trial_nonce.h';nonce_header.write_text('#define NTG_TRIAL_NONCE "'+a.nonce+'"\n')
  probe_obj=out/'probe.o';probe_dep=out/'probe.d';run('guest-probe-unit',['x86_64-w64-mingw32-gcc']+native+['-I'+str(out),'-MD','-MF',probe_dep,'-c',frozen/'probe.c','-o',probe_obj]);dependencies(probe_dep)
  probe=out/'NTG64PR.EXE';run('guest-probe-link',['x86_64-w64-mingw32-gcc','-nostdlib','-Wl,--entry,ntg_probe_entry','-Wl,--subsystem,windows','-Wl,--no-insert-timestamp','-Wl,--stack,2097152',probe_obj,'-lkernel32','-luser32','-lgdi32','-o',probe])
  with pefile.PE(str(probe)) as pe:
   require(pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Magic==0x20b and not pe.is_dll() and pe.OPTIONAL_HEADER.AddressOfEntryPoint,'real AMD64 guest executable')
   require(pe.FILE_HEADER.TimeDateStamp==0 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress,'fresh deterministic relocated probe')
   imports={m.dll.decode('ascii').lower():[x.name.decode('ascii') for x in m.imports] for m in pe.DIRECTORY_ENTRY_IMPORT}
   require(set(imports)=={'kernel32.dll','user32.dll','gdi32.dll'},'exact genuine guest transport imports')
  runtime=ROOT/'build/modern-required-apps-6970/runtime-archive-static-v1';runtime_hashes={}
  for module,names in imports.items():
   p=runtime/module;h=digest(p)
   with pefile.PE(str(p)) as pe:names_in_owner={e.name.decode('ascii') for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name and e.address and not e.forwarder}
   require(set(names)<=names_in_owner,'probe actual archive import gap: '+module);check(p,h);runtime_hashes[str(p)]=h
  receipt['probe']={'sha256':digest(probe),'size':probe.stat().st_size,'imports':imports,'runtime_owner_sha256':runtime_hashes,'nonce':a.nonce,'actual_guest_execution_verified':False}
  require(len(headers)<=260 and sum(x['size'] for x in headers.values())<=16*1024**2,'bounded compiler header closure')
  for name,h in headers.items():dst=out/'compiler-headers'/Path(name).relative_to('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(name,dst);check(dst,h['sha256'],h['size']);h['frozen_copy']=str(dst.relative_to(out))
  tools={}
  for name in ('clang','x86_64-w64-mingw32-gcc','x86_64-w64-mingw32-ld'):
   p=Path(shutil.which(name)).resolve();tools[name]={'path':str(p),'sha256':digest(p),'size':p.stat().st_size}
  for p,h in own.items():check(p,h)
  foundation();receipt.update(passed=True,models=models,artifact=row,compiler_headers=headers,toolchain=tools,generated_sha256={str(p.relative_to(out)):digest(p) for p in list(glue.glob('*.c'))+[defs,out/'NTGSW.map',nonce_header]},host_genuine_mesa_pixels_verified=True,host_resource_lifecycle_verified=True,peak_accounted_output_bytes=budget())
 except Exception as e:receipt['error']=str(e);raise
 finally:(out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'receipt':str(out/'result.json'),'sha256':digest(out/'result.json'),'models':models,'artifact':row,'guest_verified':False},indent=2))
if __name__=='__main__':main()
