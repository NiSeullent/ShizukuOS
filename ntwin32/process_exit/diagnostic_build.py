#!/usr/bin/env python3
"""Freeze and OEM-gate additive native observations; never change v3 or run a VM."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import pefile

ROOT=Path(__file__).resolve().parents[2]
V3=ROOT/'build/process-exit-candidate-20260930-v3/result.json'
V3_SHA='accbffd7df03bab11efaef0baa3cf9810eaea6f66f513fb78a5e3eae840a4f0a'
PROFILE=ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json'
PROFILE_SHA='3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d'
FILES=('native_diagnostic.c','diagnostic_wait.c','diagnostic_build.py','original_kernel.c','original_kernel.h')

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,value):p.write_text(json.dumps(value,indent=2)+'\n')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args();out=a.out.resolve();cc=shutil.which('i686-w64-mingw32-gcc')
 if out.exists() or out==ROOT/'build' or not out.is_relative_to(ROOT/'build') or not cc:p.error('Fresh isolated project build output/compiler required')
 if sha(V3)!=V3_SHA or sha(PROFILE)!=PROFILE_SHA:p.error('Frozen v3/OEM profile receipt changed')
 v3=json.loads(V3.read_text());pins={str(V3):V3_SHA,str(PROFILE):PROFILE_SHA}
 for name in FILES:pins[str(ROOT/'ntwin32/process_exit'/name)]=sha(ROOT/'ntwin32/process_exit'/name)
 # Every production v3 source remains untouched; this diagnostic only links
 # original_kernel.c verbatim and loads the exact original manager DLL.
 for name,pin in v3['sources'].items():
  if sha(ROOT/name)!=pin:p.error('Production v3 source changed: '+name)
  pins[str(ROOT/name)]=pin
 if sha(cc)!=v3['compilers']['native']['sha256']:p.error('Original compiler changed')
 manager=v3['artifacts']['M98EXIT.DLL'];pins[manager['path']]=manager['sha256']
 if sha(manager['path'])!=manager['sha256']:p.error('Original v3 manager artifact changed')
 out.mkdir(parents=True)
 for name in FILES:
  target=out/'frozen/ntwin32/process_exit'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/'ntwin32/process_exit'/name,target)
 target=out/'frozen/benchmarks'/PROFILE.name;target.parent.mkdir(parents=True);shutil.copyfile(PROFILE,target)
 src=out/'frozen/ntwin32/process_exit';flags=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
 '-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-stack-protector','-nostdlib','-Wl,--subsystem,windows:4.10',
 '-Wl,--major-os-version,4','-Wl,--minor-os-version,0','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-Wl,--entry,_entry@0']
 commands=[flags+[str(src/'native_diagnostic.c'),str(src/'original_kernel.c'),'-o',str(out/'PXDIAG.EXE'),'-lkernel32','-lgcc'],
           flags+[str(src/'diagnostic_wait.c'),'-o',str(out/'PXDWAIT.EXE'),'-lkernel32','-lgcc']]
 result={'schema':'win98modern.native-exit-guard-diagnostic-build.v1','status':'FAIL','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'sources':pins,'commands':commands,'native_executed':False,'application_executed':False,'v3_guard_changed':False,
 'compilers':{'native':{'path':cc,'sha256':sha(cc)}},'production_loader_integrated':False,
 'scope':'Observe actual native Kernel32 export/module/VQ/PE/static-context fields and unchanged manager initialize guard; no callback registration/guard relaxation/process-exit semantics acceptance.',
 'primary_api_reference':['https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery','https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information'],
 'reference_limit':'Current Microsoft minimum XP docs define field labels, not exact Windows98 protection/allocation behavior. Native observations required.'}
 try:
  for i,command in enumerate(commands):
   run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=90);(out/f'compile-{i}.log').write_text(run.stdout+run.stderr)
   if run.returncode:raise ValueError('Compiler failed '+str(i))
  shutil.copyfile(manager['path'],out/'M98EXIT.DLL');exports=json.loads(PROFILE.read_text())['dlls'];result['artifacts']={}
  for name in ('PXDIAG.EXE','PXDWAIT.EXE','M98EXIT.DLL'):
   artifact=out/name
   with pefile.PE(str(artifact)) as pe:
    opt=pe.OPTIONAL_HEADER
    if (pe.FILE_HEADER.Machine,opt.Magic,opt.Subsystem,opt.MajorSubsystemVersion,opt.MinorSubsystemVersion,opt.MajorOperatingSystemVersion,opt.MinorOperatingSystemVersion)!=(0x14c,0x10b,2,4,10,4,0):raise ValueError('Native classic GUI PE profile mismatch')
    if bool(pe.FILE_HEADER.Characteristics&0x2000)!=name.endswith('.DLL') or opt.DllCharacteristics:raise ValueError('Artifact DLL/modern flags mismatch')
    if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)):raise ValueError('Unsupported runtime state')
    imports={}
    for desc in pe.DIRECTORY_ENTRY_IMPORT:
     dll=desc.dll.decode('ascii').upper();names=[i.name.decode('ascii') if i.name else '#'+str(i.ordinal) for i in desc.imports]
     if dll!='KERNEL32.DLL' or set(names)-set(exports[dll]):raise ValueError('Actual native OEM import gate failed')
     imports[dll]=names
   result['artifacts'][name]={'path':str(artifact),'sha256':sha(artifact),'bytes':artifact.stat().st_size,'native_imports':imports,'oem_gate':'PASS'}
  if sha(out/'M98EXIT.DLL')!=manager['sha256'] or any(sha(path)!=pin for path,pin in pins.items()):raise ValueError('Original production v3/source/profile input changed')
  result['all_v3_sources_and_manager_unchanged']=True;result['status']='HOST_BUILD_PASS_NATIVE_PENDING'
 except Exception as error:result['error']=str(error)
 write(out/'result.json',result)
 if result['status']=='FAIL':print(json.dumps({'status':'FAIL','error':result.get('error')}));return 1
 manifest={'schema':1,'kind':'isolated-guest-file-inputs','inputs':[dict(source=i['path'],guest='C:\\VXDLAB\\'+n,bytes=i['bytes'],sha256=i['sha256']) for n,i in result['artifacts'].items()],
 'outputs':['C:\\VXDLAB\\PXDIAG.LOG','C:\\VXDLAB\\PXDW.LOG'],'backups':[],
 'source_receipts':[{'path':str(V3),'sha256':V3_SHA},{'path':str(out/'result.json'),'sha256':sha(out/'result.json')}],
 'commands':['C:\\VXDLAB\\PXDWAIT.EXE'],'scope':result['scope']+' Parent observes helper actual OS exit, parent own OS exit unproved.'}
 write(out/'manifest.json',manifest);print(json.dumps({'status':result['status'],'manifest':str(out/'manifest.json'),'manifest_sha256':sha(out/'manifest.json'),'native_executed':False}));return 0

if __name__=='__main__':sys.exit(main())
