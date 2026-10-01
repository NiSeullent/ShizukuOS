#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Seal and test private real Mesa resources in the existing standalone guest.

Original native Win98 disks, other VM controls, peer sources and global settings
are never modified. Actual DirectX COM support remains a separate verdict.
"""
import argparse, importlib.util, json, re, shutil, socket, sys, threading
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
theme=load('ntg_private_theme_tools',ROOT/'tools/required_theme_runtime.py')
common=load('ntg_private_trial_common',ROOT/'tools/win64_theme_probe_trial.py')
builder=load('ntg_private_builder',HERE/'build.py')
handoff=theme.handoff
require=common.require
digest=common.digest
EXE='NTG64PR.EXE'
VOLUME='graphicsprobe'
APP='private_graphics_probe'
RUNTIME_EVIDENCE_SOURCES=common.WAIT_SOURCES+('shizukudos/kernel64/standalone/standalone64.c','shizukudos/kcommon/standalone_dev.h')
FALSE_FLAGS={'windows98_execution_verified':False,'direct3d_device_creation_verified':False,'dxgi_presentation_verified':False,'direct2d_support_verified':False,'directwrite_full_support_verified':False,'app_functionality_verified':False,'full_directx_support_verified':False}
MANDATORY=('create_real_resource_device','create_rgba8_target','create_d32_attachment','create_readback_resource','real_color_and_depth_clear','create_actual_mesa_tgsi_shader','bind_actual_owned_targets','bound_target_map_rejected','actual_guest_mesa_triangle_dispatch','independent_496_sample_coverage','actual_guest_resource_copy','all_4096_independent_rgba_bytes_and_padding','independent_depth_and_padding','stale_shader_cookie_rejected','destroy_device_and_owned_resources','all_allocator_blocks_released','actual_visible_framebuffer_write','all_16384_visible_framebuffer_pixels','destroy_visible_window','unregister_window_class','unload_math_owner','unload_private_backend')
def sources():
 paths=[HERE/'trial.py',HERE/'build.py',ROOT/'tools/required_theme_runtime.py',ROOT/'tools/required_app_runtime_handoff.py',ROOT/'tools/win64_theme_probe_trial.py',ROOT/'tools/signal_desktop_corpus.py',ROOT/'tools/modern_app_inventory.py',ROOT/'LICENSE']
 return {str(p.relative_to(ROOT)):digest(p) for p in paths}
def candidate(path):
 directory=path.parent.resolve(strict=True);require(directory.is_relative_to(HERE/'build'),'candidate outside own build')
 j=handoff.read_json(path);require(j.get('schema')==1 and j.get('kind')=='private-amd64-genuine-mesa-resource-backend' and j.get('passed') is True,'actual successful genuine Mesa build required')
 require(common.nonce_ok(j.get('nonce','')),'candidate needs exact fresh nonce')
 require(j['source_sha256'] and all(digest(Path(p))==h and digest(directory/'source'/Path(p).relative_to(ROOT))==h for p,h in j['source_sha256'].items()),'original/frozen compile input changed')
 for p,row in j['upstream_inputs'].items():
  original=Path(p);require(digest(original)==row['sha256'] and original.stat().st_size==row['size'],'upstream frozen input changed')
  frozen=directory/'mesa'/original.relative_to(builder.SHADER) if original.is_relative_to(builder.SHADER) else directory/'glue'/original.relative_to(builder.RASTER/'source/src')
  if frozen.suffix=='.c' and frozen.parent==directory/'glue':require(digest(frozen)==j['generated_sha256'][str(frozen.relative_to(directory))],'AMD64 prepared source changed')
  else:require(digest(frozen)==row['sha256'],'upstream/private frozen source changed')
 for name,h in j['generated_sha256'].items():require(digest(directory/name)==h,'generated compile input changed')
 for p,row in j['compiler_headers'].items():require(digest(Path(p))==row['sha256'] and digest(directory/row['frozen_copy'])==row['sha256'],'compiler header changed')
 for row in j['toolchain'].values():require(digest(Path(row['path']))==row['sha256'],'compiler tool changed')
 require(j['models'].get('host')==j['models'].get('sanitize') and j.get('host_genuine_mesa_pixels_verified') is True and j.get('host_resource_lifecycle_verified') is True,'real normal/sanitizer pixel/lifetime result required')
 for step in j['steps']:
  p=Path(step['log']);require(p.parent.resolve()==directory and step['returncode']==0 and digest(p)==step['sha256'],'frozen successful build/test step changed')
 require(builder.pe_gate(directory/'NTGSW.DLL')==j['artifact'],'actual private PE gate differs from receipt')
 require(digest(directory/EXE)==j['probe']['sha256'] and (directory/EXE).stat().st_size==j['probe']['size'],'guest executable changed')
 require(j['probe']['nonce']==j['nonce'],'guest/build nonce mismatch')
 return j
def prepare(build,base,out):
 build=build.resolve(strict=True);base=base.resolve(strict=True);out=theme.owned_new_directory(out)
 j=candidate(build);b=theme.verified_overlay(base);source_hashes=sources();build_sha=digest(build);base_sha=digest(base)
 archive=theme.inventory.read_regular(Path(b['archive']['path']));files=theme.parse_archive(archive)
 require(not any(n.casefold()=='\\shz\\sys64\\ntgsw.dll' for n,_ in files),'append-only fresh private module required')
 dll=theme.inventory.read_regular(build.parent/'NTGSW.DLL');derived=theme.pack_archive(files+[('\\SHZ\\SYS64\\NTGSW.DLL',dll)])
 require(theme.parse_archive(derived)[:-1]==files,'baseline member order/bytes must remain intact')
 modules=theme.archive_modules(theme.parse_archive(derived))
 for module,names in j['probe']['imports'].items():
  for name in names:theme.resolve_export(modules,module,name)
 for name in ('cos','sin','log','pow','sqrt','floor','ceil','ldexp'):theme.resolve_export(modules,'ucrtbase.dll',name)
 productivity,hashes=handoff.load_peer(Path(b['runtime_worktree']));require(hashes==b['runtime_source_hashes'],'current peer helper changed')
 wait={p:digest(Path(b['runtime_worktree'])/p) for p in RUNTIME_EVIDENCE_SOURCES}
 handoff.check_space(out.parent,300*1024**2+len(derived)+handoff.METADATA_MARGIN);out.mkdir()
 frozen=out/'sources';frozen.mkdir()
 for p,h in source_hashes.items():q=frozen/p;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/p,q);require(digest(q)==h,'trial source changed while freezing');q.chmod(0o400)
 for p,h in wait.items():q=frozen/'runtime-wait'/p;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(Path(b['runtime_worktree'])/p,q);require(digest(q)==h,'wait source changed while freezing');q.chmod(0o400)
 runtime_archive=out/'WIN64.IMG';runtime_archive.write_bytes(derived);runtime_archive.chmod(0o400)
 tree=out/'tree';tree.mkdir();exe=tree/EXE;shutil.copyfile(build.parent/EXE,exe);exe.chmod(0o400)
 image=out/'graphics-probe.img';productivity.runner.build_image(image,tree,VOLUME)
 control=f'image=D:\\{VOLUME}\\{EXE}\r\ncmdline={EXE} \r\ncwd=D:\\{VOLUME}\r\ntimeout=30\r\n'.encode('ascii');productivity.runner.put_file(image,control,'K64RUN.TXT',out);image.chmod(0o400)
 require(candidate(build)==j and theme.verified_overlay(base)==b and sources()==source_hashes,'preparation inputs changed')
 result={'schema':1,'stage':'private-amd64-mesa-resource-probe','status':'PREPARED','nonce':j['nonce'],'candidate_receipt':{'path':str(build),'sha256':build_sha},'theme_overlay_receipt':{'path':str(base),'sha256':base_sha},'source_hashes':source_hashes,'runtime_worktree':b['runtime_worktree'],'runtime_source_hashes':hashes,'runtime_wait_source_hashes':wait,'archive':{'path':str(runtime_archive),'sha256':digest(runtime_archive),'bytes':len(derived),'members':theme.member_manifest(theme.parse_archive(derived))},'executable':{'path':str(exe),'sha256':digest(exe),'bytes':exe.stat().st_size},'image':{'path':str(image),'sha256':digest(image),'bytes':image.stat().st_size},'tree':str(tree),'control':control.decode('ascii'),'original_member_bytes_and_order_preserved':True,'network_attached':False,'vm_started':False,**FALSE_FLAGS}
 handoff.write_json(out/'prepared.json',result);return result
def verified(path):
 r=handoff.read_json(path);directory=path.parent.resolve(strict=True)
 require(directory.is_relative_to(ROOT/'build') and r.get('stage')=='private-amd64-mesa-resource-probe' and r.get('status')=='PREPARED' and common.nonce_ok(r.get('nonce','')),'invalid owned preparation')
 require(r['source_hashes']==sources(),'trial source changed')
 for p,h in r['source_hashes'].items():require(digest(directory/'sources'/p)==h,'frozen trial source changed')
 require(set(r['runtime_wait_source_hashes'])==set(RUNTIME_EVIDENCE_SOURCES),'missing wait/ISA-debug-exit semantics lineage')
 for p,h in r['runtime_wait_source_hashes'].items():require(digest(directory/'sources/runtime-wait'/p)==h and digest(Path(r['runtime_worktree'])/p)==h,'wait semantics source changed')
 for field in ('candidate_receipt','theme_overlay_receipt'):require(digest(Path(r[field]['path']))==r[field]['sha256'],'candidate/baseline receipt changed')
 j=candidate(Path(r['candidate_receipt']['path']));b=theme.verified_overlay(Path(r['theme_overlay_receipt']['path']))
 require(j['nonce']==r['nonce'] and b['runtime_worktree']==r['runtime_worktree'] and b['runtime_source_hashes']==r['runtime_source_hashes'],'runtime/nonce lineage mismatch')
 for field in ('archive','image','executable'):
  row=r[field];p=Path(row['path']);require(p.resolve(strict=True).is_relative_to(directory) and p.stat().st_size==row['bytes'] and digest(p)==row['sha256'],'owned '+field+' changed')
 actual=theme.parse_archive(theme.inventory.read_regular(Path(r['archive']['path'])));base=theme.parse_archive(theme.inventory.read_regular(Path(b['archive']['path'])))
 require(actual[:-1]==base and actual[-1]==('\\SHZ\\SYS64\\NTGSW.DLL',theme.inventory.read_regular(Path(r['candidate_receipt']['path']).parent/'NTGSW.DLL')),'actual derived archive lineage changed')
 require(r['archive']['members']==theme.member_manifest(actual),'member hashes mismatch')
 return r
def parse(serial,nonce):
 require(common.nonce_ok(nonce),'nonce invalid');starts=list(re.finditer(r'^K64 autorun: starting ([^\r\n]+)',serial,re.M));require(len(starts)==1 and f'D:\\{VOLUME}\\{EXE}' in starts[0][1],'exact unique private autorun required')
 tail=serial[starts[0].start():];pids=re.findall(r'^K64 autorun: started pid (\d+)\r?$',tail,re.M);require(len(pids)==1,'unique child PID required');pid=pids[0]
 app=re.findall(r'^\[(?:win64|user) '+re.escape(EXE)+r' pid '+pid+r'\] (NTG64[^\r\n]*)\r?$',tail,re.M)
 require(app.count('NTG64 BEGIN nonce='+nonce)==1 and app.count('NTG64 RESULT PASS nonce='+nonce)==1,'fresh unique complete nonce verdict required')
 require(not any(x.startswith(('NTG64 FAIL ','NTG64 RESULT FAIL ')) for x in app),'child assertion failure')
 totals=[re.fullmatch(r'NTG64 COUNTS checks=(\d+) failures=(\d+) paints=(\d+) pixels=(\d+)',x) for x in app if x.startswith('NTG64 COUNTS')];require(len(totals)==1 and totals[0],'exact unique totals')
 checks,failures,paints,pixels=map(int,totals[0].groups());require(checks>=50 and failures==0 and paints>=1 and pixels==16384,'meaningful actual guest/pixel checks required');require(sum(x.startswith('NTG64 PASS ') for x in app)==checks,'assertion count mismatch')
 require(all('NTG64 PASS '+x in app for x in MANDATORY),'required resource/pixel/lifetime assertions absent')
 require(not re.search(r'K64 EXCEPTION|K64: process .* killed|unhandled exception|K64 ldr: .* (?:failed|rejected|not loaded)',tail),'guest fault or loader rejection')
 all_results=re.findall(r'^K64 autorun: result [^\r\n]*',tail,re.M);results=re.findall(r'^K64 autorun: result (\S+) exit=([0-9a-f]+) faulted=(\d) reaped=(-?\d+) after \d+ ms\r?$',tail,re.M)
 require(len(all_results)==1 and results==[('exited','0','0','0')],'external normal child exit0/proc_wait0 required')
 return {'status':'PASS','nonce':nonce,'pid':int(pid),'assertions':checks,'paint_events':paints,'visible_pixels':pixels,'normal_exit_code':0,'proc_wait_return_code':0,'kernel_child_reaped':True,'private_guest_mesa_resource_rendering_verified':True}
def screenshot(path):
 from PIL import Image
 require(path.stat().st_size<=4*1024**2,'capture bounded')
 with Image.open(path) as img:
  require(img.format=='PPM' and img.size==(1024,768) and img.mode=='RGB','actual expected guest framebuffer mode')
  # Kernel64 USER32 places client x+4,y+23, already independently accepted by
  # theme proof. The private resource window is at90,70; paint starts20,40.
  left,top=114,133;count=0
  for y in range(128):
   for x in range(128):
    sx,sy=x//4,y//4;expected=((255*(2*sx+1)+32)//64,(255*(2*sy+1)+32)//64,64) if sx+sy<31 else (3,7,11)
    require(img.getpixel((left+x,top+y))==expected,f'independent Mesa framebuffer pixel mismatch ({left+x},{top+y})');count+=1
  png=path.with_suffix('.png');img.save(png)
 return {'status':'PASS','source':str(path),'sha256':digest(path),'preview':str(png),'rectangle':[left,top,left+128,top+128],'checked_pixels':count,'actual_qemu_framebuffer_mesa_pixels_verified':True}
class Guard(common.CaptureGuard):
 def Popen(self,command,**kwargs):
  require('-nodefaults' in command and not any(x in command for x in ('-net','-netdev','-nic')),'strict no-NIC guest command required')
  for i,x in enumerate(command):
   if x=='-device':require(i+1<len(command) and command[i+1].split(',',1)[0] in ('isa-debug-exit','ahci','ide-hd'),'unreviewed guest device requested')
  return super().Popen(command,**kwargs)
 def written_bytes(self,pid):
  written,output=super().written_bytes(pid);observed=self.record.setdefault('kvm_fd_evidence',[])
  try:
   for fd in (Path('/proc')/str(pid)/'fd').iterdir():
    try:target=str(fd.readlink())
    except OSError:continue
    if target=='/dev/kvm' or 'kvm-vm' in target or 'kvm-vcpu' in target:
     row={'pid':pid,'fd':fd.name,'target':target}
     if row not in observed:observed.append(row)
  except OSError:pass
  return written,output
 def observe(self):
  connection=None
  try:
   while not self.stop.wait(.05):
    if self.child.poll() is not None:return
    serial=self.out/'serial.log';s=serial.read_text(errors='replace') if serial.exists() else ''
    if 'NTG64 BEGIN nonce='+self.nonce not in s or 'NTG64 PASS all_16384_visible_framebuffer_pixels' not in s:continue
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(2);connection.connect(str(self.qmp));stream=connection.makefile('rwb');require('QMP' in json.loads(stream.readline()),'owned QMP greeting absent')
    def command(name,args=None):
     payload={'execute':name,'id':name}
     if args is not None:payload['arguments']=args
     stream.write(json.dumps(payload).encode()+b'\n');stream.flush()
     while True:
      response=json.loads(stream.readline())
      if response.get('id')==name:require('return' in response,'owned QMP request failed');return response['return']
    command('qmp_capabilities');path=self.out/'theme-screen.ppm';command('screendump',{'filename':str(path)});self.capture=screenshot(path);stream.close();return
  except Exception as e:self.capture={'status':'FAIL','error':str(e)}
  finally:
   if connection:connection.close()
def run(prepared,out,qemu,firmware_dirs,timeout=60):
 require(qemu.is_absolute() and 10<=timeout<=180,'absolute QEMU/bounded timeout');r=verified(prepared);prep_sha=digest(prepared);out=theme.owned_new_directory(out);productivity,hashes=handoff.load_peer(Path(r['runtime_worktree']));require(hashes==r['runtime_source_hashes'],'peer helper changed');runner=productivity.runner
 inputs={'boot_stub':runner.K64S/'boot.elf','kernel':runner.K64S/'KERNEL64S.BIN','win64_initrd':Path(r['archive']['path']),'qemu':qemu};before={key:digest(p) for key,p in inputs.items()};firmware=handoff.firmware_manifest(firmware_dirs);handoff.check_space(out.parent,sum(p.stat().st_size for p in inputs.values())+firmware['bytes']+handoff.RUN_WRITE_BUDGET);out.mkdir();sealed=handoff.seal_runtime_inputs(inputs,out/'runtime-inputs');require(all(sealed[k]['sha256']==h for k,h in before.items()),'runtime changed while sealing');sealed_fw=handoff.seal_firmware(firmware,out/'runtime-firmware')
 handoff.write_json(out/'runtime-seal.json',{'schema':1,'stage':'sealed-private-mesa-resource-runtime','probe_preparation_sha256':prep_sha,'runtime_source_hashes':hashes,'sealed_runtime_input_hashes':sealed,'sealed_firmware':sealed_fw})
 guard=Guard(Path(sealed['qemu']['path']),out,sealed_fw,r['nonce']);app={'dir':VOLUME,'exe':EXE,'args':'','expect':'NTG64 RESULT PASS nonce='+r['nonce']};require(APP not in runner.APPS,'probe key already owned');saved=runner.K64S,runner.WIN64,runner.subprocess,runner.build_image,runner.put_file,sys.argv;image=Path(r['image']['path'])
 def image_builder(selected,tree,volume,over=None):require(Path(selected).resolve()==image.resolve() and Path(tree).resolve()==Path(r['tree']).resolve() and volume==VOLUME and not over,'unowned image requested');return [(EXE,r['executable']['bytes'])]
 def control_writer(selected,data,name,folder):require(Path(selected).resolve()==image.resolve() and name=='K64RUN.TXT' and data.decode('ascii')==r['control'],'unowned autorun requested')
 runner.K64S=runner.WIN64=out/'runtime-inputs';runner.subprocess=guard;runner.build_image=image_builder;runner.put_file=control_writer;runner.APPS[APP]=app;sys.argv=[str(Path(runner.__file__)),'--app',APP,'--tree',r['tree'],'--image',str(image),'--out',str(out),'--qemu',sealed['qemu']['path'],'--accel','kvm','--memory','1024','--timeout',str(timeout),'--guest-timeout','30'];code,error=2,None
 try:code=runner.main()
 except Exception as e:error=str(e)
 finally:runner.K64S,runner.WIN64,runner.subprocess,runner.build_image,runner.put_file,sys.argv=saved;runner.APPS.pop(APP,None);guard.close()
 acceptance={'status':'FAIL'}
 try:require(error is None and code==0,error or 'original runner failed');acceptance=parse((out/'serial.log').read_text(errors='replace'),r['nonce'])
 except Exception as e:acceptance['error']=str(e)
 preserved=False
 try:
  require(digest(prepared)==prep_sha and verified(prepared)==r,'preparation changed');require(all(digest(Path(row['path']))==row['sha256'] and digest(Path(row['source_path']))==row['sha256'] for row in sealed.values()),'original or sealed runtime changed');require(handoff.sealed_firmware_preserved(sealed_fw) and handoff.firmware_sources_preserved(firmware),'original/sealed firmware changed');preserved=True
 except Exception as e:error=(error+'; ' if error else '')+str(e)
 fd_targets=[x['target'] for x in guard.record.get('kvm_fd_evidence',[])];kvm='/dev/kvm' in fd_targets and any('kvm-vm' in x for x in fd_targets) and any('kvm-vcpu' in x for x in fd_targets);safe=preserved and kvm and not guard.record['termination_reason']
 # The exact command contains isa-debug-exit; sa_exit(0) writes0, which QEMU
 # encodes as host status1. This is separate from the actual child exit0.
 serial=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
 host_exit_ok=guard.child is not None and guard.child.returncode==1 and re.findall(r'^SHZ-EXIT:(\d+)\r?$',serial,re.M)==['0']
 ok=safe and acceptance['status']=='PASS' and guard.capture['status']=='PASS' and host_exit_ok
 result={'schema':1,'stage':'standalone-kernel64-private-mesa-resource-and-framebuffer-acceptance','status':'PASS' if ok else 'FAIL','probe_nonce':r['nonce'],'probe_preparation':{'path':str(prepared),'sha256':prep_sha},'guest_os':'ShizukuDOS Kernel64 standalone','original_runner_return_code':code,'host_qemu_return_code':guard.child.returncode if guard.child else None,'qemu_isa_debug_exit_guest_zero_encoding_verified':host_exit_ok,'acceptance':acceptance,'capture':guard.capture,'resource_guard':guard.record,'hardware_virtualization_fd_verified':kvm,'original_and_sealed_inputs_preserved':preserved,'error':error,'network_attached':False,'peer_sources_modified':False,'installation':'not_performed','private_guest_mesa_resource_rendering_verified':safe and acceptance['status']=='PASS','actual_qemu_framebuffer_mesa_pixels_verified':safe and guard.capture['status']=='PASS',**FALSE_FLAGS}
 handoff.write_json(out/'graphics-acceptance.json',result);return result
def main():
 ap=argparse.ArgumentParser(description=__doc__);stages=ap.add_subparsers(dest='stage',required=True);p=stages.add_parser('prepare')
 for n in ('build','theme-overlay','out'):p.add_argument('--'+n,type=Path,required=True)
 p=stages.add_parser('run')
 for n in ('prepared','out','qemu'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--firmware-dir',type=Path,action='append',required=True);p.add_argument('--timeout',type=int,default=60);a=ap.parse_args()
 try:r=prepare(a.build,a.theme_overlay,a.out) if a.stage=='prepare' else run(a.prepared,a.out,a.qemu,a.firmware_dir,a.timeout)
 except Exception as e:print(json.dumps({'status':'FAIL','error':str(e)}));return 2
 print(json.dumps({'status':r['status'],'stage':r['stage']}));return 0 if r['status'] in ('PREPARED','PASS') else 1
if __name__=='__main__':raise SystemExit(main())
