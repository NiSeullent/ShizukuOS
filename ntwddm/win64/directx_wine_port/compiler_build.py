#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build real pinned vkd3d-shader compiler from an owned frozen Wine closure.

Generators/compiler processes are bounded and serial. No VM, SDK installation,
upstream scripts, downloads or peer mutations. SPIR-V is compiled, not executed.
"""
import argparse,hashlib,json,os,re,shutil,signal,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
RESERVE=20*1024**3;WRITE=256*1024**2;OUTPUT=16*1024**2
PIN='db11d0fe6a169c457e23d007e20404643d067aa8'
def require(x,s):
 if not x:raise RuntimeError(s)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--base',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
 base=Path(a.base).resolve(strict=True);out=Path(a.out).resolve()
 require(base.is_relative_to(HERE/'build') and out.is_relative_to(HERE/'build') and not out.exists(),'owned immutable base and fresh output')
 j=json.loads((base/'result.json').read_text());require(j['wine_commit']==PIN and len(j['original'])>1000 and len(j['generated_headers'])>300 and 'prepared_headers' in j,'complete actual materialized source receipt')
 w=base/'wine'
 def verify_base():
  require(digest(base/'result.json')==base_hash,'base receipt changed')
  for name,row in j['original'].items():require(digest(w/name)==row['sha256'],'pinned original changed '+name)
  for name,row in j['generated_headers'].items():require(digest(w/name)==row['sha256'],'frozen generated header changed '+name)
  for name,row in j['prepared_headers'].items():require(digest(w/name)==row['sha256'],'frozen IDL header changed '+name)
 base_hash=digest(base/'result.json');verify_base();require(shutil.disk_usage(HERE).free-64*1024**2>=RESERVE,'20 GiB floor and compiler-output margin')
 out.mkdir();(out/'tmp').mkdir();(out/'own').mkdir();steps=[]
 receipt={'schema':1,'stage':'genuine-pinned-vkd3d-shader-compiler-prerequisite','status':'INCOMPLETE','wine_commit':PIN,'vkd3d_version':'1.18','base_receipt':{'path':str(base/'result.json'),'sha256':base_hash},'source_and_license_closure':'Immutable base receipt original/generated/prepared header records; no upstream source modified.','own_sources':{},'steps':steps,'objects':{},'guards':{'reserve_bytes':RESERVE,'write_budget_bytes':WRITE,'output_budget_bytes':OUTPUT,'jobs':1},'network_operations':False,'vm_operations':False,'global_install':False,'peer_sources_modified':False,'shader_bytecode_execution_verified':False,'spirv_device_execution_verified':False,'spirv_full_validation_verified':False,'linked_directx_runtime_verified':False,'direct3d_device_creation_verified':False,'dxgi_presentation_verified':False,'direct2d_support_verified':False,'directwrite_full_support_verified':False,'full_directx_support_verified':False,'windows98_execution_verified':False,'app_functionality_verified':False}
 def guard():
  used=logs=0
  for p in (HERE/'build').rglob('*'):
   try:
    if p.is_file() and not p.is_symlink():
     n=p.stat().st_size;used+=n
     if p.suffix=='.log':logs+=n
   except FileNotFoundError:pass
  free=shutil.disk_usage(out).free;require(used<=WRITE,'aggregate 256 MiB new graphics allocation budget');require(logs<=OUTPUT,'aggregate 16 MiB logs');require(free>=RESERVE,'20 GiB reserve');receipt['guards']['peak_owned_bytes']=max(used,receipt['guards'].get('peak_owned_bytes',0));receipt['guards']['minimum_free_bytes']=min(free,receipt['guards'].get('minimum_free_bytes',2**63))
 def run(label,cmd,timeout=90):
  guard();log=out/(label+'.log');env=os.environ.copy();env['TMPDIR']=str(out/'tmp');env['VKD3D_DEBUG']='none';start=time.monotonic()
  with log.open('wb') as f:
   p=subprocess.Popen([str(x) for x in cmd],cwd=out,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   try:
    while p.poll() is None:guard();require(time.monotonic()-start<timeout,'bounded compiler/generator timeout');time.sleep(.1)
    guard()
   except BaseException:
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    p.wait();raise
  r={'label':label,'command':[str(x) for x in cmd],'returncode':p.returncode,'log':str(log.relative_to(out)),'sha256':digest(log),'duration_seconds':round(time.monotonic()-start,3)};steps.append(r);return r
 try:
  for name in ('compiler_build.py','compiler_host.c'):
   p=HERE/name;q=out/'own'/name;shutil.copyfile(p,q);q.chmod(0o400);receipt['own_sources'][name]=digest(p)
  require(digest(base/'own/fixture.h')==j['fixture']['header_sha256'],'actual pinned fixture closure');shutil.copyfile(base/'own/fixture.h',out/'own/fixture.h');receipt['fixture']=j['fixture']
  paths={name:shutil.which(name) for name in ('gcc','clang','x86_64-w64-mingw32-gcc','x86_64-w64-mingw32-ar','x86_64-w64-mingw32-nm','bison','flex','m4','nm','readelf')};require(all(paths.values()),'installed genuine compiler/generator/symbol tools');receipt['tools']={name:{'path':str(Path(p).resolve()),'sha256':digest(Path(p).resolve())} for name,p in paths.items()}
  gen=out/'generated';gen.mkdir();shader=w/'libs/vkd3d/libs/vkd3d-shader';receipt['generated']={}
  for name in ('hlsl','preproc'):
   r=run('bison-'+name,[paths['bison'],'-d','-o',gen/(name+'.tab.c'),shader/(name+'.y')]);require(r['returncode']==0,'actual shader grammar generation')
   r=run('flex-'+name,[paths['flex'],'-o',gen/(name+'.yy.c'),shader/(name+'.l')]);require(r['returncode']==0,'actual shader lexer generation')
  for p in gen.iterdir():receipt['generated'][p.name]=digest(p)
  # Preserve installed Bison skeleton/m4 input closure; generated notices remain.
  receipt['generator_data']={}
  for p in sorted(Path('/usr/share/bison').rglob('*')):
   if not p.is_file() or p.is_symlink():continue
   q=out/'generator-data'/p.relative_to('/');q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q);require(digest(p)==digest(q),'generator data drift');receipt['generator_data'][str(p)]={'sha256':digest(p),'frozen_copy':str(q.relative_to(out))}
  common=[w/'libs/vkd3d/libs/vkd3d-common'/f'{n}.c' for n in ('debug','error','memory','utf8')]
  units=common+sorted(shader.glob('*.c'))+sorted(gen.glob('*.c'))
  receipt['genuine_units']=[str(p.relative_to(base)) if p.is_relative_to(base) else str(p.relative_to(out)) for p in units]
  inc=['-I'+str(gen),'-I'+str(out/'own'),'-I'+str(w/'libs/vkd3d'),'-I'+str(w/'libs/vkd3d/include'),'-I'+str(w/'libs/vkd3d/include/private'),'-I'+str(shader),'-I'+str(w/'include')]
  probe=out/'own/builtin_probe.c';probe.write_text('#include <stdint.h>\n#include <stddef.h>\nint main(void){volatile uint64_t x=1;volatile uint32_t y=2;size_t z;void *volatile p=0;if(__sync_add_and_fetch(&x,3)!=4)return 1;if(!__sync_bool_compare_and_swap(&y,2,5))return 2;if(__atomic_exchange_n(&y,7,__ATOMIC_SEQ_CST)!=5)return 3;if(!__sync_bool_compare_and_swap(&p,(void*)0,(void*)1))return 4;if(!__builtin_add_overflow((size_t)-1,(size_t)1,&z))return 5;return 0;}\n');receipt['builtin_probe_sha256']=digest(probe)
  r=run('actual-gcc-builtin-build',[paths['gcc'],probe,'-o',out/'builtin-probe']);require(r['returncode']==0,'actual installed GCC builtin capability');r=run('actual-gcc-builtin-test',[out/'builtin-probe']);require(r['returncode']==0,'actual atomic/overflow semantics');r=run('actual-mingw-builtin-build',[paths['x86_64-w64-mingw32-gcc'],'-c',probe,'-o',out/'builtin-pe.o']);require(r['returncode']==0,'actual AMD64 builtin compile')
  flags=['-O1','-g0','-D__WINESRC__','-DLIBVKD3D_SHADER_SOURCE','-DLIBVKD3D_SOURCE','-DLIBVKD3D_UTILS_SOURCE','-D_POSIX_C_SOURCE=200809L','-D_GNU_SOURCE=1','-DHAVE_PTHREAD_H=1','-DHAVE_DLFCN_H=1','-DHAVE_SYNC_ADD_AND_FETCH=1','-DHAVE_SYNC_BOOL_COMPARE_AND_SWAP=1','-DHAVE_ATOMIC_EXCHANGE_N=1','-DHAVE_BUILTIN_ADD_OVERFLOW=1','-ffunction-sections','-fdata-sections','-fno-strict-aliasing',*inc]
  obj=out/'objects';obj.mkdir();receipt['outputs']={}
  for mode,extra in (('normal',[]),('sanitize',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
   objects=[];hc=paths['clang'] if mode=='sanitize' else paths['gcc']
   for i,p in enumerate(units+[out/'own/compiler_host.c']):
    o=obj/(mode+'-'+str(i)+'.o');dep=o.with_suffix('.d');r=run(mode+'-compile-'+str(i),[hc,*flags,*extra,'-MD','-MF',dep,'-c',p,'-o',o]);require(r['returncode']==0,'genuine shader unit compile failed: '+str(p));objects.append(o);receipt['objects'][str(o.relative_to(out))]={'source':str(p),'sha256':digest(o),'bytes':o.stat().st_size}
   binary=out/(mode+'-shader-test');r=run(mode+'-link',[hc,*extra,*objects,'-Wl,--gc-sections','-pthread','-lm','-o',binary]);require(r['returncode']==0,'genuine shader compiler link failed');destination=out/(mode+'-output');destination.mkdir();r=run(mode+'-test',[binary,destination]);require(r['returncode']==0,'genuine compiler positive/error/lifetime test failed');receipt[mode+'_host_result']={'log':r['log'],'sha256':r['sha256'],'binary_sha256':digest(binary),'compiler':hc}
   receipt['outputs'][mode]={p.name:{'sha256':digest(p),'bytes':p.stat().st_size} for p in destination.iterdir()};r=run(mode+'-elf-imports',[paths['readelf'],'-d',binary]);require(r['returncode']==0,'actual host import contract')
   container_objects=[]
   for name in ('container.c','host.c'):
    p=base/'own'/name;require(digest(p)==j['own_sources'][name],'frozen container consumer drift');o=obj/(mode+'-container-'+name+'.o');dep=o.with_suffix('.d');r=run(mode+'-container-'+name,[hc,*flags,*extra,'-I'+str(base/'own'),'-MD','-MF',dep,'-c',p,'-o',o]);require(r['returncode']==0,'actual owned container consumer compile');container_objects.append(o);receipt['objects'][str(o.relative_to(out))]={'source':str(p),'sha256':digest(o),'bytes':o.stat().st_size}
   cb=out/(mode+'-container-test');r=run(mode+'-container-link',[hc,*extra,*objects[:-1],*container_objects,'-Wl,--gc-sections','-pthread','-lm','-o',cb]);require(r['returncode']==0,'actual container link against genuine compiler');r=run(mode+'-container-test',[cb]);require(r['returncode']==0,'genuine container bounds/signature/copy/lifetime tests');receipt[mode+'_container_result']={'log':r['log'],'sha256':r['sha256'],'binary_sha256':digest(cb),'compiler':hc}
  require(receipt['outputs']['normal']==receipt['outputs']['sanitize'],'independent host/sanitizer compiler byte outputs differ')
  # Genuine AMD64 COFF shader library. This has actual unresolved OS/CRT
  # imports, recorded as prerequisites; it is not a loadable device DLL.
  peflags=[x for x in flags if x not in ('-DHAVE_PTHREAD_H=1','-DHAVE_DLFCN_H=1','-D_POSIX_C_SOURCE=200809L','-D_GNU_SOURCE=1')]+['-D__WINE_PE_BUILD','-D_UCRT','-D_WIN32','-D_ACRTIMP=','-fshort-wchar','-mabi=ms','-mcx16','-I'+str(w/'include/msvcrt')]
  pe=[]
  for i,p in enumerate(units):
   o=obj/('pe-'+str(i)+'.o');dep=o.with_suffix('.d');r=run('pe-compile-'+str(i),[paths['x86_64-w64-mingw32-gcc'],*peflags,'-MD','-MF',dep,'-c',p,'-o',o]);require(r['returncode']==0,'genuine AMD64 shader unit compile failed: '+str(p));pe.append(o);receipt['objects'][str(o.relative_to(out))]={'source':str(p),'sha256':digest(o),'bytes':o.stat().st_size}
  library=out/'libgenuine-vkd3d-shader-amd64.a';r=run('pe-archive',[paths['x86_64-w64-mingw32-ar'],'rcs',library,*pe]);require(r['returncode']==0,'actual COFF archive build');receipt['amd64_library']={'path':str(library),'sha256':digest(library),'bytes':library.stat().st_size}
  for name,tool in (('host-symbols','nm'),('pe-symbols','x86_64-w64-mingw32-nm')):
   r=run(name,[paths[tool],'-g',library if name=='pe-symbols' else out/'normal-shader-test']);require(r['returncode']==0,'actual shader symbol contract')
  receipt['compiler_headers']={}
  for dep in obj.glob('*.d'):
   for name in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
    p=Path(name).resolve(strict=True)
    if p.is_relative_to(base) or p.is_relative_to(out):continue
    require(p.is_relative_to('/usr'),'external compile dependency outside installed toolchain')
    if str(p) in receipt['compiler_headers']:continue
    q=out/'compiler-headers'/p.relative_to('/');q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q);q.chmod(0o400);require(digest(p)==digest(q),'compiler system header drift');receipt['compiler_headers'][str(p)]={'sha256':digest(p),'frozen_copy':str(q.relative_to(out)),'bytes':q.stat().st_size};guard()
  verify_base()
  for name,h in receipt['own_sources'].items():require(digest(HERE/name)==h and digest(out/'own'/name)==h,'original/frozen compiler consumer drift')
  for name,h in receipt['generated'].items():require(digest(gen/name)==h,'generated shader parser drift')
  receipt['actual_host_dxbc_container_verified']=True;receipt['actual_host_hlsl_dxbc_compile_verified']=True;receipt['actual_host_dxbc_spirv_compile_verified']=True;receipt['actual_host_pinned_dxbc_disassembly_verified']=True;receipt['status']='HOST_SHADER_COMPILER_PASS_AND_AMD64_LIBRARY_BUILT';guard()
 except BaseException as e:receipt['error']=str(e)
 finally:(out/'result.json').write_text(json.dumps(receipt,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'out':str(out),'status':receipt['status'],'error':receipt.get('error'),'objects':len(receipt['objects']),'guards':receipt['guards']}));return 0 if receipt['status']=='HOST_SHADER_COMPILER_PASS_AND_AMD64_LIBRARY_BUILT' else 1
if __name__=='__main__':raise SystemExit(main())
