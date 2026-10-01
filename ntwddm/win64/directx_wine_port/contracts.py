#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Record real COFF dependency contracts against sealed runtime export inventory.

Inventory is never a behavior verdict. Only fresh owned metadata/header copies
are written; no DLL linking, installation, shared build or VM operation occurs.
"""
import argparse,hashlib,json,os,shutil,signal,struct,subprocess,time
from pathlib import Path
import pefile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
LIMIT=256*1024**2;OUTPUT=16*1024**2;RESERVE=20*1024**3
def require(x,s):
 if not x:raise RuntimeError(s)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def coff(p):
 raw=p.read_bytes();require(len(raw)>=20,'actual COFF header')
 machine,sections,timestamp,table,symbols,optional,flags=struct.unpack_from('<HHIIIHH',raw)
 require(machine==0x8664 and optional==0 and 0<sections<10000 and 20+40*sections<=len(raw),'actual regular AMD64 COFF object')
 require(table==0 and symbols==0 or table>=20+40*sections and table+18*symbols<=len(raw),'actual COFF symbol bounds')
 relocations=0
 for i in range(sections):
  name,physical,virtual,size,data,reloc,lineno,count,lines,characteristics=struct.unpack_from('<8sIIIIIIHHI',raw,20+40*i)
  require(size==0 or data==0 and characteristics&0x80 or data>=20+40*sections and data+size<=len(raw),'actual COFF raw section or declared uninitialized-storage bounds')
  require(count==0 or reloc>=20+40*sections and reloc+10*count<=len(raw),'actual COFF relocation bounds');relocations+=count
 return {'machine':'AMD64','sections':sections,'symbols':symbols,'relocations':relocations,'sha256':digest(p),'bytes':len(raw),'timestamp':timestamp}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--base',required=True);ap.add_argument('--compiler',required=True);ap.add_argument('--runtime',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
 base=Path(a.base).resolve(strict=True);compiler=Path(a.compiler).resolve(strict=True);runtime=Path(a.runtime).resolve(strict=True);out=Path(a.out).resolve()
 require(base.is_relative_to(HERE/'build') and compiler.is_relative_to(HERE/'build') and out.is_relative_to(HERE/'build') and not out.exists(),'fresh owned contracts output')
 b=json.loads((base/'result.json').read_text());c=json.loads((compiler/'result.json').read_text());r=json.loads(runtime.read_text());require(c['status']=='HOST_SHADER_COMPILER_PASS_AND_AMD64_LIBRARY_BUILT','actual coherent shader compiler gates required');require(c['base_receipt']['sha256']==digest(base/'result.json'),'actual exact upstream base receipt');archive=Path(r['archive']['path']);require(archive.is_relative_to(ROOT/'build') and archive.stat().st_size==r['archive']['bytes'] and digest(archive)==r['archive']['sha256'],'exact sealed actual runtime archive')
 prior=None
 if 'prior_receipt' in c:
  prior_file=Path(c['prior_receipt']['path']).resolve(strict=True);prior=prior_file.parent;require(prior.is_relative_to(HERE/'build') and digest(prior_file)==c['prior_receipt']['sha256'],'exact immutable reused compiler receipt')
  for name,row in c['reused_objects'].items():require(Path(name).is_relative_to(prior) and digest(Path(name))==row['sha256'],'completed reused compiler object drift')
 require(shutil.disk_usage(HERE).free>=RESERVE,'20 GiB reserve before contracts allocation');out.mkdir();steps=[];nm=shutil.which('x86_64-w64-mingw32-nm');require(nm,'installed COFF symbol tool')
 def guard():
  used=logs=0
  for p in (HERE/'build').rglob('*'):
   try:
    if p.is_file() and not p.is_symlink():
     n=p.stat().st_size;used+=n
     if p.suffix=='.log':logs+=n
   except FileNotFoundError:pass
  require(used<=LIMIT and logs<=OUTPUT and shutil.disk_usage(out).free>=RESERVE,'exact aggregate source/output/reserve guards')
 def symbols(label,objects):
  guard();cmd=[nm,'-g',*[str(x) for x in objects]];log=out/(label+'.log');start=time.monotonic()
  with log.open('wb') as f:
   child=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   try:
    while child.poll() is None:guard();require(log.stat().st_size<=2*1024**2 and time.monotonic()-start<30,'bounded genuine COFF inspection');time.sleep(.1)
    guard();require(child.returncode==0 and log.stat().st_size<=2*1024**2,'bounded genuine COFF symbol inspection')
   except BaseException:
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    child.wait();raise
  steps.append({'command':cmd,'returncode':child.returncode,'log':str(log.relative_to(out)),'sha256':digest(log)})
  defined=set();undefined=set()
  for line in log.read_text().splitlines():
   parts=line.split()
   if len(parts)==2 and parts[0]=='U':undefined.add(parts[1])
   elif len(parts)==3 and len(parts[1])==1 and parts[1]!='U':defined.add(parts[2])
  guard();return defined,undefined
 groups={};object_gates={}
 for name,row in b['units'].items():
  require(row['status']=='COMPILED','partial objects cannot become a complete compiled-unit inventory');p=base/row['object'];require(digest(p)==row['sha256'],'actual graphics object drift');groups.setdefault(name.split('/')[0],[]).append(p);object_gates[str(p)]=coff(p)
 for name,row in c['objects'].items():
  if not name.startswith('objects/pe-'):continue
  p=compiler/name;require(digest(p)==row['sha256'],'actual shader COFF object drift');object_gates[str(p)]=coff(p)
 library=Path(c['amd64_library']['path']);require(library.is_relative_to(compiler) and digest(library)==c['amd64_library']['sha256'],'actual AMD64 shader archive drift');groups['vkd3d-shader']=[library]
 sets={m:symbols(m,objects) for m,objects in groups.items()};all_def=set().union(*(x[0] for x in sets.values()))
 # Read exact SHZARC01 extents; do not extract or write baseline modules.
 raw=archive.read_bytes();require(len(raw)<128*1024**2 and raw[:8]==b'SHZARC01','bounded actual runtime archive');count,reserved=struct.unpack_from('<II',raw,8);require(reserved==0 and 1<=count<=512 and 16+count*136<=len(raw),'real runtime archive directory');exports={};members=[]
 for i in range(count):
  name,offset,size=struct.unpack_from('<120sQQ',raw,16+i*136);name=name.split(b'\0',1)[0].decode('ascii');require(offset>=16+count*136 and offset%16==0 and size<=len(raw)-offset,'actual sealed archive extent');data=raw[offset:offset+size];members.append({'name':name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':size})
  if not name.upper().startswith('\\SHZ\\SYS64\\') or not name.upper().endswith('.DLL'):continue
  pe=pefile.PE(data=data,fast_load=False)
  if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
   for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name:exports.setdefault(e.name.decode('ascii'),[]).append({'module':name,'forwarder':e.forwarder.decode('ascii') if e.forwarder else None,'rva':e.address})
  pe.close()
 contracts={}
 for module,(defined,undefined) in sets.items():
  external=undefined-defined;unresolved=external-all_def
  contracts[module]={'compiled_objects':len(groups[module]),'declared_makefile_contract':b['module_contracts'].get(module),'defined_external_symbols':sorted(defined),'undefined_outside_module':sorted(external),'resolved_by_other_genuine_objects':sorted(external&all_def),'remaining_link_prerequisites':{name:{'runtime_export_inventory':exports.get(name.removeprefix('__imp_'),[]),'behavior_verified':False} for name in sorted(unresolved)}}
 headers={}
 for directory in (base/'objects',compiler/'objects',*((prior/'objects',) if prior else ())):
  for dep in directory.glob('*.d'):
   for name in dep.read_text().replace('\\\n',' ').split(':',1)[1].split():
    p=Path(name).resolve(strict=True)
    if p.is_relative_to(base) or p.is_relative_to(compiler) or prior and p.is_relative_to(prior):continue
    require(p.is_relative_to('/usr'),'compiler dependency outside owned sources and installed toolchain')
    if str(p) in headers:continue
    q=out/'compiler-headers'/p.relative_to('/');q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q);q.chmod(0o400);require(digest(p)==digest(q),'actual compiler header drift');headers[str(p)]={'sha256':digest(p),'bytes':q.stat().st_size,'frozen_copy':str(q.relative_to(out))};guard()
 result={'schema':1,'status':'RECORDED','stage':'actual-graphics-coff-source-import-prerequisites','inventory_only_not_runtime_behavior':True,'base_receipt':{'path':str(base/'result.json'),'sha256':digest(base/'result.json')},'compiler_receipt':{'path':str(compiler/'result.json'),'sha256':digest(compiler/'result.json')},'runtime_preparation':{'path':str(runtime),'sha256':digest(runtime)},'runtime_archive':{'path':str(archive),'sha256':digest(archive),'members':members},'source_sha256':digest(Path(__file__).resolve()),'nm':{'path':str(Path(nm).resolve()),'sha256':digest(Path(nm).resolve())},'steps':steps,'modules':contracts,'coff_object_gates':object_gates,'compiler_headers':headers,'dynamic_backend_requirements':{'opengl':'Real opengl32 WGL context/pixel format, GL entry points and surface/swap presentation. Compiled adapter_gl is not a working GL device.','vulkan':'Real Vulkan loader/vkCreateInstance/physical-device enumeration/vkCreateDevice/queues/resources/presentation. Compiled adapter_vk and SPIR-V are not device execution.','mesa':'Prior private TGSI renderer supplies no GL/Vulkan winsys or SPIR-V interpreter and is not automatically compatible with these Wine adapters.'},'host_shader_negative_scope':'Valid-checksum oversized SHDR declared DWORD length is rejected during actual tpf parser initialization; not an unknown-opcode test.','spirv_validation_scope':'Independent structural instruction/header/Vertex/FAdd checks; spirv-val not installed; no SPIR-V execution.','linked_directx_runtime_verified':False,'direct3d_device_creation_verified':False,'dxgi_presentation_verified':False,'direct2d_support_verified':False,'directwrite_full_support_verified':False,'full_directx_support_verified':False,'windows98_execution_verified':False,'app_functionality_verified':False,'peer_sources_modified':False,'global_install':False,'vm_operations':False,'network_operations':False,'full_requirement_manifest':'benchmarks/modern-graphics-requirements-6970.json'}
 data=(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode();require(len(data)<OUTPUT,'bounded contracts receipt');(out/'result.json').write_bytes(data);guard();print(json.dumps({'status':result['status'],'modules':len(contracts),'graphics_objects':sum(len(x) for m,x in groups.items() if m!='vkd3d-shader'),'compiler_headers':len(headers),'result_sha256':digest(out/'result.json')}))
if __name__=='__main__':main()
