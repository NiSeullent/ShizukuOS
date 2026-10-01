#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build bounded independent native waiter and frozen fixture inputs, no VM."""
import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
from pathlib import Path
import pefile
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
BUILD=ROOT/'build/rpc-lifecycle-observer-20261001T1240-v4'
HOST=ROOT/'build/rpc-lifecycle-observer-host-20261001T1241-v4/host-result.json'
RELEASE=ROOT/'build/rpc-lifecycle-observer-release-20261001T1243-v4/release.json'
PINS=('fe7cfc57f5e11f5e08964380dad7664ccdc3578a86e321c5a5c3c65649c35cf5','7030940b7660d4f03a4de45bff2088e66b8cb4ff97bc09fdc75f4f3b43d33f45','86bb13cda13c9ebfe47d3152d4cd09176e0128c8a1fde5f022d65ce745cb661c')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def pin(p):p=Path(p).resolve();return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args();out=a.out.resolve()
 if out.exists() or not out.is_relative_to(ROOT/'build'):ap.error('fresh private build directory required')
 parents=[BUILD/'build-result.json',HOST,RELEASE]
 if any(sha(p)!=s for p,s in zip(parents,PINS)):ap.error('frozen V4 parent pin mismatch')
 original=json.loads(parents[0].read_text());oem=ROOT/'benchmarks/win98se-ko-oem-native-exports-v1.json'
 cc=shutil.which('i686-w64-mingw32-gcc');hostcc=shutil.which('clang')
 if not cc or not hostcc:ap.error('installed native/host compilers required')
 inputs={str(p):pin(p) for p in [HERE/n for n in ('wait.c','mock_windows.h','host_test.c','build.py')]+parents+[oem]}
 for item in original['artifacts']:
  p=Path(item['path'])
  if pin(p)['sha256']!=item['sha256']:ap.error('V4 owned binary changed')
  inputs[str(p)]=pin(p)
 tools={str(Path(cc).resolve()):pin(cc),str(Path(hostcc).resolve()):pin(hostcc)}
 for arg in ('-print-prog-name=cc1','-print-prog-name=as','-print-prog-name=ld','-print-libgcc-file-name'):
  raw=subprocess.check_output([cc,arg],text=True).strip();p=Path(raw).resolve() if '/' in raw else Path(shutil.which(raw)).resolve();tools[str(p)]=pin(p)
 out.mkdir(parents=True);frozen=out/'source';frozen.mkdir();commands=[];runs=[]
 for n in ('wait.c','mock_windows.h','host_test.c','build.py'):shutil.copyfile(HERE/n,frozen/n)
 def run(cmd,label):
  commands.append(cmd);r=subprocess.run(cmd,cwd=ROOT,capture_output=True,timeout=120);(out/(label+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode();return r
 try:
  headers={};dep=run([cc,'-std=c11','-march=i486','-M',str(frozen/'wait.c')],'headers').stdout.decode()
  for text in shlex.split(dep.split(':',1)[1].replace('\\\n',' ')):
   p=Path(text).resolve()
   if p.is_file() and not p.is_relative_to(out):headers[str(p)]=pin(p)
  flags=[cc,'-std=c11','-march=i486','-Os','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-stack-protector','-ffunction-sections','-fdata-sections','-nostdlib','-Wl,--gc-sections','-Wl,--entry,_entry@0','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,0','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp']
  exe=out/'RPCWAIT.EXE';run(flags+['-o',str(exe),str(frozen/'wait.c'),'-lkernel32','-lgcc'],'native-compile')
  exports=json.loads(oem.read_text())['dlls'];imports={}
  with pefile.PE(str(exe)) as pe:
   p=pe.OPTIONAL_HEADER
   if pe.is_dll() or (pe.FILE_HEADER.Machine,p.Magic,p.Subsystem,p.MajorSubsystemVersion,p.MinorSubsystemVersion)!=(0x14c,0x10b,2,4,10) or p.DllCharacteristics&0x140 or any(p.DATA_DIRECTORY[i].VirtualAddress or p.DATA_DIRECTORY[i].Size for i in (9,10,13,14)):raise ValueError('classic native PE profile mismatch')
   for d in pe.DIRECTORY_ENTRY_IMPORT:
    dll=d.dll.decode().upper();names=[]
    for i in d.imports:
     if not i.name or dll!='KERNEL32.DLL' or i.name.decode() not in exports[dll]:raise ValueError('not original OEM native import')
     names.append(i.name.decode())
    imports[dll]=sorted(names)
  for mode in ('normal','sanitized'):
   cmd=[hostcc,'--no-default-config','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-DRPC_WAIT_HOST']
   if mode=='sanitized':cmd+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
   host=out/('host-'+mode);run(cmd+[str(frozen/'wait.c'),str(frozen/'host_test.c'),'-o',str(host)],mode+'-compile');r=run([str(host)],mode+'-run');runs.append({'mode':mode,'exit_code':r.returncode,'stdout':r.stdout.decode(),'binary_sha256':sha(host)})
  for group in (inputs,tools,headers):
   if any(pin(Path(p))!=v for p,v in group.items()):raise ValueError('input/header/tool changed')
  result={'schema':1,'status':'PASS','native_executed':False,'application_success':False,'immutable_inputs':inputs,'tools':tools,'selected_headers':headers,'commands':commands,'host_runs':runs,'artifact':{**pin(exe),'imports':imports,'oem_import_gate':'PASS'},'frozen_sources':{p.name:pin(p) for p in frozen.iterdir()},'scope':'Compiled actual native i486 waiter plus actual C mocked API result/error/lifetime controls; no native target executed. Reports nonempty only; full inner protocol and parent/fixture OS exits remain separate. Timeout never terminates child.'}
  receipt=out/'build-result.json';receipt.write_text(json.dumps(result,indent=2)+'\n')
  staged=out/'inputs';staged.mkdir();items=[]
  for item in original['artifacts']+[result['artifact']]:
   source=Path(item['path']);target=staged/source.name;shutil.copyfile(source,target)
   if sha(target)!=item['sha256']:raise ValueError('copied input changed')
   items.append({'source':str(target),'guest':'C:\\VXDLAB\\'+target.name,'bytes':target.stat().st_size,'sha256':sha(target)})
  manifest={'schema':1,'kind':'isolated-guest-file-inputs','inputs':items,'outputs':['C:\\VXDLAB\\RPCDBG.LOG','C:\\VXDLAB\\RPCFIX.LOG','C:\\VXDLAB\\RPCWAIT.LOG'],'backups':[],'source_receipts':[{'path':str(p),'sha256':sha(p)} for p in parents+[receipt]],'command':'C:\\VXDLAB\\RPCWAIT.EXE','scope':'OWNED DLL/RF fixture only; require two admitted load/unload generations, six real worker exits0, fixture actual OSexit0, observer actual wait/query/OSexit0, original code/FS and transparent exceptions. No VLC/app acceptance. Own outer OSexit not observed.'}
  (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
  plan={'schema':1,'native_executed':False,'manifest':pin(out/'manifest.json'),'command':manifest['command'],'input_count':4,'output_count':3,'input_bytes':sum(i['bytes'] for i in items),'preflight_required_absent_guest_names':[i['guest'] for i in items]+manifest['outputs'],'no_raw_read_or_clone_performed':True,'cold_source':{'run':str(ROOT/'build/shizukudos/csm/run-win98-gop-vlc-no-qtload-storage-20261001T1050'),'result_sha256':'e49f0294fd76b7ad632b2a0e27536565fff05c894dd9bd283a67f206d238c31f','expected_full_post_raw_sha256':'88abd75c0ddd661977fe828f4723ea2cf282c2a58156508bf61f44e17713f174','stream_proof_sha256':'71abca2268bb37f169cc22c0dc83f4daf4327d550ee4e33d396f86a6419cb032','scope':'Pins retained host receipts only; launch owner must independently verify whole source/raw/VARS quiescence/content and clone provenance before writes.'},'unchanged_profile':{'firmware_sha256':'031f481d4256e8a6d6f4c63e75e8f9f533e97806c5320fdf219ed61e262c8701','runner_sha256':'c629d0da00839d3567076f8edb821894d570635b4e8aace8d60e7a4ac4f953ee','cpu':2,'ram_mib':128,'timeout_cap_seconds':1800,'actual_free_floor_gib':17,'no_network':True},'required_native_review':{'two_load_unload_generations':True,'six_actual_worker_exit_queries_zero':True,'fixture_actual_process_exit_zero':True,'observer_actual_os_wait_query_exit_zero':True,'native_RF_same_instruction_code_FS_unchanged':True,'all_admitted_threads_armed_no_identity_context_gaps':True,'all_first_second_chance_other_exceptions_OS_owned':True,'no_forced_termination':True,'outer_own_os_exit':'unobserved unless an additional real parent observes it'},'expected_minimal_fixture_counts':{'generations':2,'entry_hits':16,'store_hits':2,'known_worker_exit_zero_checks':6,'known_thread_records':7,'arms':8,'unload_restores':2,'scope':'Expected for exactly the fixture-created main+six workers. Any additional native threads/events must be reported and reviewed, not silently dropped.'},'root_integration_release_required':True}
  (out/'guest-input-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
  for p in out.rglob('*'):
   if p.is_file():p.chmod(0o400)
  print(json.dumps({'status':'PASS','build_result':pin(receipt),'manifest':pin(out/'manifest.json'),'guest_input_plan':pin(out/'guest-input-plan.json'),'waiter':result['artifact'],'host_runs':runs}))
 except Exception as e:
  (out/'failure.json').write_text(json.dumps({'status':'FAIL','error':str(e),'native_executed':False,'commands':commands,'inputs':inputs,'host_runs':runs},indent=2)+'\n');raise
if __name__=='__main__':main()
