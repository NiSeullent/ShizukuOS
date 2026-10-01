#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze pinned local Wine objects; compile genuine graphics units, no guest.

Only fresh owned outputs are written. No upstream scripts, sparse-checkout
changes, downloads, global settings, shared libraries or runtime installation.
"""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PEER=Path('/root/Win98-Modern-apps-cb43')
WINE=PEER/'build/upstream/wine'
PIN='db11d0fe6a169c457e23d007e20404643d067aa8'
RESERVE=20*1024**3; WRITE=256*1024**2; OUTPUT=16*1024**2
MODULES=['d3d11','dxgi','wined3d','d2d1','d3d9','d3d10','d3d10_1','d3d10core','ddraw','d3d12','d3dcompiler_43']
OWN=['container.h','container.c','host.c','build.py']
WFLAGS=['-O2','-g0','-D__WINESRC__','-D__WINE_PE_BUILD','-D_UCRT','-D_WIN32','-D_ACRTIMP=','-fshort-wchar','-mabi=ms','-fno-strict-aliasing','-mcx16','-ffunction-sections','-fdata-sections','-fno-stack-protector','-fno-ident','-Wno-format','-Wno-attributes','-Wno-unused','-Wno-int-to-pointer-cast','-Wno-pointer-to-int-cast','-Wno-incompatible-pointer-types']
CONTAINER_UNITS=['libs/vkd3d/libs/vkd3d-common/'+n+'.c' for n in ('debug','memory','error')]+['libs/vkd3d/libs/vkd3d-shader/'+n+'.c' for n in ('checksum','dxbc','vkd3d_shader_main')]
def require(x,s):
 if not x:raise RuntimeError(s)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write_json(p,j):p.write_text(json.dumps(j,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
def git(*args):
 r=subprocess.run(['git',*args],cwd=WINE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True);return r.stdout
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);a=ap.parse_args()
 out=Path(a.out).resolve();require(out.is_relative_to(HERE/'build') and not out.exists(),'fresh own build only')
 require(git('rev-parse','HEAD').decode().strip()==PIN,'exact local Wine pin')
 require(shutil.disk_usage(HERE).free-128*1024**2>=RESERVE,'20 GiB floor + frozen source margin')
 out.mkdir(parents=True);(out/'tmp').mkdir();steps=[]
 receipt={'schema':1,'stage':'pinned-wine-graphics-source-and-dxbc-container-build','status':'INCOMPLETE','wine_commit':PIN,'source_repository':'https://github.com/wine-mirror/wine','peer_worktree':str(PEER),'original':{},'generated_headers':{},'own_sources':{},'steps':steps,'guards':{'reserve_bytes':RESERVE,'write_budget_bytes':WRITE,'output_budget_bytes':OUTPUT,'jobs':1},'network_operations':False,'vm_operations':False,'global_install':False,'peer_sources_modified':False,'direct3d_device_creation_verified':False,'dxgi_presentation_verified':False,'direct2d_support_verified':False,'directwrite_full_support_verified':False,'full_directx_support_verified':False,'windows98_execution_verified':False,'app_functionality_verified':False}
 def guard():
  used=logs=0
  for p in (HERE/'build').rglob('*'):
   try:
    if p.is_file() and not p.is_symlink():
     n=p.stat().st_size;used+=n
     if p.suffix=='.log':logs+=n
   except FileNotFoundError:pass # compiler-owned temporary files may expire
  require(used<=WRITE,'256 MiB own allocation budget');require(logs<=OUTPUT,'16 MiB aggregate logs');require(shutil.disk_usage(out).free>=RESERVE,'20 GiB disk floor');receipt['guards']['peak_owned_bytes']=max(used,receipt['guards'].get('peak_owned_bytes',0));receipt['guards']['minimum_free_bytes']=min(shutil.disk_usage(out).free,receipt['guards'].get('minimum_free_bytes',2**63))
 def run(label,cmd,timeout=45):
  guard();log=out/(label+'.log');start=time.monotonic();env=os.environ.copy();env['TMPDIR']=str(out/'tmp');env['VKD3D_DEBUG']='none'
  with log.open('wb') as f:
   p=subprocess.Popen([str(x) for x in cmd],cwd=out,stdout=f,stderr=subprocess.STDOUT,start_new_session=True,env=env)
   try:
    while p.poll() is None:
     guard();require(time.monotonic()-start<timeout,'bounded child timeout');time.sleep(.1)
    guard()
   except BaseException:
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    p.wait();raise
  row={'label':label,'command':[str(x) for x in cmd],'returncode':p.returncode,'log':str(log.relative_to(out)),'sha256':digest(log),'duration_seconds':round(time.monotonic()-start,3)};steps.append(row);return row
 try:
  originals=git('ls-tree','-r','-l',PIN,'include','libs/vkd3d','tools/widl','tools/wpp',*[f'dlls/{m}' for m in MODULES],'COPYING.LIB','LICENSE','AUTHORS','VERSION').decode().splitlines()
  tree={}
  for line in originals:
   mode,kind,oid,size,name=line.split(None,4);require(kind=='blob' and mode in ('100644','100755'),'only regular upstream files');tree[name]=(oid,int(size))
  require(sum(n for _,n in tree.values())<64*1024**2,'bounded selected upstream closure')
  for i,(name,(oid,size)) in enumerate(sorted(tree.items())):
   data=git('cat-file','blob',oid);require(len(data)==size and hashlib.sha1(b'blob '+str(size).encode()+b'\0'+data).hexdigest()==oid,'actual pinned Git blob')
   p=out/'wine'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o400);receipt['original'][name]={'git_blob':oid,'sha256':digest(p),'bytes':size}
   if i%25==0:guard()
  for p in sorted((WINE/'include').rglob('*.h')):
   name=str(p.relative_to(WINE))
   if name in tree:continue
   require(p.is_file() and not p.is_symlink(),'regular existing generated header');q=out/'wine'/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q);q.chmod(0o400);require(digest(p)==digest(q),'generated header drift');receipt['generated_headers'][name]={'source':str(p),'sha256':digest(q),'bytes':q.stat().st_size}
  for name in OWN:
   p=HERE/name;q=out/'own'/name;q.parent.mkdir(exist_ok=True);shutil.copyfile(p,q);q.chmod(0o400);receipt['own_sources'][name]=digest(p)
  # Exact upstream VS4.1 fixture, without copying surrounding Windows test harness.
  fixture=(out/'wine/dlls/d3d11/tests/d3d11.c').read_text();match=re.search(r'static const DWORD vs_4_1\[\]\s*=\s*\{(.*?)\n\s*\};',fixture,re.S);require(match is not None,'unique named upstream bytecode fixture');words=re.findall(r'0x[0-9a-fA-F]+',match[1]);require(len(words)==113 and words[0]=='0x43425844','real known 452-byte DXBC fixture');fp=out/'own/fixture.h';fp.write_text('/* Exact Wine LGPL-2.1-or-later test bytecode; original source/notice retained. */\nstatic const uint32_t fixture_vs_4_1[] = {\n'+','.join(words)+'\n};\n');receipt['fixture']={'original_file':'dlls/d3d11/tests/d3d11.c','original_sha256':receipt['original']['dlls/d3d11/tests/d3d11.c']['sha256'],'array':'vs_4_1','bytes':452,'header_sha256':digest(fp)}
  cc=shutil.which('x86_64-w64-mingw32-gcc');hc=shutil.which('gcc');nm=shutil.which('x86_64-w64-mingw32-nm');require(cc and hc and nm,'installed AMD64 tools');receipt['tools']={name:{'path':str(Path(p).resolve()),'sha256':digest(Path(p).resolve())} for name,p in (('mingw_gcc',cc),('host_gcc',hc),('mingw_nm',nm))}
  widl=WINE/'tools/widl/widl';require(widl.is_file() and not widl.is_symlink(),'existing genuine WIDL generator');wt=out/'tools/widl';wt.parent.mkdir();shutil.copyfile(widl,wt);wt.chmod(0o500);require(digest(widl)==digest(wt),'WIDL drift');receipt['tools']['widl']={'path':str(widl),'sha256':digest(widl),'frozen_copy':'tools/widl','corresponding_source':'wine/tools/widl and wine/tools/wpp at pinned commit; cached tool exact build receipt not assumed'}
  header=out/'wine/include/wine/winedxgi.h';r=run('generate-winedxgi',[wt,'--nostdinc','-I'+str(out/'wine/include'),'-h','-o',header,out/'wine/include/wine/winedxgi.idl']);require(r['returncode']==0 and header.is_file(),'real missing Wine DXGI IDL header generation');receipt['prepared_headers']={'include/wine/winedxgi.h':{'sha256':digest(header),'source':'include/wine/winedxgi.idl','generator':'widl'}}
  w=out/'wine';inc=['-I'+str(w/'include'),'-I'+str(w/'include/msvcrt'),'-I'+str(w/'libs/vkd3d/include'),'-I'+str(w/'libs/vkd3d/include/private')];obj=out/'objects';obj.mkdir();receipt['units']={};receipt['module_contracts']={}
  for module in MODULES:
   directory=w/'dlls'/module;mk=(directory/'Makefile.in').read_text();normalized=mk.replace('\\\n',' ')
   variables={k:v.split() for k,v in re.findall(r'^(\w+)\s*=\s*(.*)$',normalized,re.M)};receipt['module_contracts'][module]=variables
   parent=variables.get('PARENTSRC',[]);flags=WFLAGS+inc+['-I'+str(directory)]+['-I'+str((directory/x).resolve()) for x in parent]+[x for x in variables.get('EXTRADEFS',[]) if x.startswith('-D')]
   for source in variables.get('SOURCES',[]):
    if not source.endswith('.c'):continue
    p=directory/source
    if not p.exists() and parent:p=(directory/parent[0]/source).resolve()
    if not p.exists():receipt['units'][module+'/'+source]={'status':'MISSING_SOURCE'};continue
    o=obj/(module+'-'+Path(source).stem+'.o');dep=o.with_suffix('.d');label='pe-'+module+'-'+Path(source).stem
    r=run(label,[cc,*flags,'-MD','-MF',dep,'-c',p,'-o',o]);receipt['units'][module+'/'+source]={'status':'COMPILED' if r['returncode']==0 else 'COMPILE_FAILED','source':str(p.relative_to(out)),'sha256':digest(o) if o.exists() else None,'bytes':o.stat().st_size if o.exists() else 0,'object':str(o.relative_to(out)),'dependency_file':str(dep.relative_to(out)) if dep.exists() else None,'step':label}
  # Genuine subset objects + section GC create a container/signature-only host
  # executable; no compiler/device entry point is substituted or claimed.
  host_inc=['-I'+str(out/'own'),'-I'+str(w/'include'),'-I'+str(w/'libs/vkd3d'),'-I'+str(w/'libs/vkd3d/include'),'-I'+str(w/'libs/vkd3d/include/private'),'-I'+str(w/'libs/vkd3d/libs/vkd3d-shader')]
  hflags=['-O1','-g0','-D__WINESRC__','-DLIBVKD3D_SHADER_SOURCE','-DLIBVKD3D_SOURCE','-DLIBVKD3D_UTILS_SOURCE','-DHAVE_PTHREAD_H=1','-DHAVE_DLFCN_H=1','-ffunction-sections','-fdata-sections','-fno-strict-aliasing',*host_inc]
  receipt['container_units']={}
  for mode,extra in (('normal',[]),('sanitize',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
   objects=[]
   for i,source in enumerate(CONTAINER_UNITS+['own/container.c','own/host.c']):
    p=out/source if source.startswith('own/') else w/source;o=obj/(mode+'-dxbc-'+str(i)+'.o');dep=o.with_suffix('.d');label=mode+'-dxbc-'+str(i)
    r=run(label,[hc,*hflags,*extra,'-MD','-MF',dep,'-c',p,'-o',o]);require(r['returncode']==0,'genuine container unit did not compile: '+source);objects.append(o);receipt['container_units'][mode+'/'+source]={'object':str(o.relative_to(out)),'sha256':digest(o),'bytes':o.stat().st_size}
   binary=out/(mode+'-dxbc-test');r=run(mode+'-link',[hc,*extra,*objects,'-Wl,--gc-sections','-pthread','-lm','-o',binary]);require(r['returncode']==0,'actual container host link failed');r=run(mode+'-test',[binary]);require(r['returncode']==0,'actual container test failed');receipt[mode+'_host_result']={'log':r['log'],'sha256':r['sha256'],'binary_sha256':digest(binary)}
  # Record real AMD64 undefined symbol contracts rather than shipping DLL names.
  peobjects=[out/row['object'] for row in receipt['units'].values() if row['status']=='COMPILED'];r=run('pe-undefined-symbols',[nm,'-u',*peobjects]);require(r['returncode']==0,'real object symbol inspection');receipt['object_symbol_contract_log']=r['log']
  receipt['compiler_headers']={}
  for dep in obj.glob('*.d'):
   dependencies=dep.read_text().replace('\\\n',' ').split(':',1)[1].split()
   for name in dependencies:
    p=Path(name).resolve(strict=True)
    if p.is_relative_to(out):continue
    require(p.is_relative_to('/usr'),'compiler dependency outside owned source and installed toolchain')
    if str(p) in receipt['compiler_headers']:continue
    q=out/'compiler-headers'/p.relative_to('/');q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q);q.chmod(0o400);require(digest(p)==digest(q),'compiler header drift');receipt['compiler_headers'][str(p)]={'sha256':digest(p),'frozen_copy':str(q.relative_to(out)),'bytes':q.stat().st_size};guard()
  for name,row in receipt['original'].items():require(digest(w/name)==row['sha256'],'frozen original drift')
  for name,row in receipt['generated_headers'].items():require(digest(Path(row['source']))==row['sha256'] and digest(w/name)==row['sha256'],'generated compiler header drift')
  for name,h in receipt['own_sources'].items():require(digest(HERE/name)==h and digest(out/'own'/name)==h,'owned source drift')
  receipt['actual_host_dxbc_container_verified']=True;receipt['shader_bytecode_execution_verified']=False;receipt['complete_shader_compiler_verified']=False;receipt['linked_directx_runtime_verified']=False;receipt['status']='HOST_CONTAINER_PASS_WITH_GRAPHICS_OBJECT_PROGRESS';guard()
 except BaseException as e:
  receipt['error']=str(e)
 finally:write_json(out/'result.json',receipt)
 print(json.dumps({'out':str(out),'status':receipt['status'],'error':receipt.get('error'),'compiled_units':sum(x['status']=='COMPILED' for x in receipt.get('units',{}).values()),'failed_units':sum(x['status']=='COMPILE_FAILED' for x in receipt.get('units',{}).values()),'guards':receipt['guards']}))
 return 0 if receipt['status']=='HOST_CONTAINER_PASS_WITH_GRAPHICS_OBJECT_PROGRESS' else 1
if __name__=='__main__':raise SystemExit(main())
