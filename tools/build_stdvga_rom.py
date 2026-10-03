#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build pinned SeaBIOS standard VGA ROM in one private independent unit.

Retains original/archive/copied source, configuration and primary-tool Linux
read leases until build children are gone and final SHA readback completes.
No VM, device epoch, VGACFG or PCI address is created here.
"""
import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import tarfile
import time

COMMIT='578d260b94f62150bf6ab9149784287bd1154f06'
CONFIG=b'CONFIG_QEMU=y\nCONFIG_VGA_BOCHS=y\nCONFIG_VGA_BOCHS_STDVGA=y\nCONFIG_VGA_VID=0x1234\nCONFIG_VGA_DID=0x1111\nCONFIG_VGA_VBE=y\n'

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def canonical(path):
    p=Path(path);need(p.is_absolute() and p.resolve()==p and not any(q.is_symlink() for q in (p,*p.parents)),'canonical nonsymlink path required');return p
def pin(p):
    p=canonical(p);raw=p.read_bytes();return {'path':str(p),'bytes':len(raw),'sha256':sha(raw)}

class Leases:
    def __init__(self):
        self.rows={};self.broken=False;self.cancelled=False;self.previous={}
        for number in (signal.SIGIO,signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
            self.previous[number]=signal.getsignal(number);signal.signal(number,self.interrupt)
    def interrupt(self,number,*_):
        if number==signal.SIGIO:self.broken=True
        else:self.cancelled=True
    def check(self):
        need(not self.broken and not self.cancelled,'source lease break/cancellation requested')
        for name,row in self.rows.items():
            p=canonical(name);fd=row['fd'];info=os.fstat(fd)
            need(fcntl.fcntl(fd,fcntl.F_GETOWN)==os.getpid() and fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK and
                 identity(info)==row['identity']==identity(p.stat()),'original held path/lease identity differs')
    def add(self,row):
        p=canonical(row['path']);name=str(p)
        if name in self.rows:need(self.rows[name]['pin']==row,'conflicting source pin');return
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_size==row['bytes'],'exact regular source extent')
            fcntl.fcntl(fd,fcntl.F_SETOWN,os.getpid());fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK)
            self.rows[name]={'fd':fd,'identity':identity(info),'pin':dict(row)}
            self.check();need(self.full(fd,info.st_size)==row['sha256'],'original leased SHA differs')
        except BaseException:
            self.rows.pop(name,None);os.close(fd);raise
    def full(self,fd,size):
        at=0;digest=hashlib.sha256()
        while at<size:
            self.check();block=os.pread(fd,min(1<<20,size-at),at);need(block,'short leased source read');digest.update(block);at+=len(block)
        need(not os.pread(fd,1,size),'source extent grew');self.check();return digest.hexdigest()
    def verify_all(self):
        for row in self.rows.values():need(self.full(row['fd'],row['pin']['bytes'])==row['pin']['sha256'],'final full SHA changed')
    def close(self):
        for row in reversed(list(self.rows.values())):
            try:fcntl.fcntl(row['fd'],fcntl.F_SETLEASE,fcntl.F_UNLCK)
            finally:os.close(row['fd'])
        self.rows.clear()
        for number,handler in self.previous.items():signal.signal(number,handler)

def archive_files(raw,tree):
    """Exact tracked regular files only; no symlink/path traversal/extra entry."""
    result={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for item in archive.getmembers():
            if item.isdir():continue
            name=item.name;p=PurePosixPath(name)
            need(item.isfile() and not p.is_absolute() and '..' not in p.parts and str(p)==name and name in tree and name not in result,'unsafe/extra archive entry')
            mode,blob=tree[name];need(item.size<=16<<20 and item.mode&0o777==int(mode,8)&0o777,'archive mode/extent differs')
            data=archive.extractfile(item).read();need(len(data)==item.size and hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'archive Git blob differs')
            result[name]=(data,item.mode&0o777)
    need(set(result)==set(tree),'missing tracked archive file');return result

def rom_metadata(raw):
    need(512<=len(raw)<=65536 and raw[:2]==b'\x55\xaa' and raw[2]*512==len(raw),'actual raw x86 ROM extent/signature')
    at=struct.unpack_from('<H',raw,0x18)[0];need(0x1a<=at<=len(raw)-24,'bounded PCIR')
    need(raw[at:at+4]==b'PCIR' and struct.unpack_from('<HH',raw,at+4)==(0x1234,0x1111) and
         24<=struct.unpack_from('<H',raw,at+10)[0]<=len(raw)-at and raw[at+13:at+16]==b'\0\0\3' and
         struct.unpack_from('<H',raw,at+16)[0]*512==len(raw) and raw[at+20:at+22]==b'\0\x80' and sum(raw)%256==0,
         'stdVGA PCIR/class/code/lastimage/checksum differs')
    return {'vendor_id':0x1234,'device_id':0x1111,'image_bytes':len(raw),'code_type':0,'last_image':128}

def census(group):
    pids=set()
    for file in (group/'cgroup.procs',*group.rglob('cgroup.procs')):
        need(not file.is_symlink(),'owned unit membership symlink');raw=file.read_text().split()
        need(all(v.isdigit() and int(v)>0 for v in raw),'invalid owned unit census');pids.update(map(int,raw))
    need(os.getpid() in pids,'actual producer left owned unit');return sorted(pids-{os.getpid()})
def cleanup(group):
    """Pidfd signals only members of this actual independent build unit."""
    for number,budget in ((signal.SIGTERM,3),(signal.SIGKILL,6)):
        for pid in census(group):
            try:fd=os.pidfd_open(pid,0)
            except ProcessLookupError:continue
            try:
                proc=Path('/proc')/str(pid);path=Path('/sys/fs/cgroup')/proc.joinpath('cgroup').read_text().strip().split('::',1)[1].lstrip('/')
                need(path==group or group in path.parents,'cleanup target outside owned unit')
                signal.pidfd_send_signal(fd,number)
            except ProcessLookupError:pass
            finally:os.close(fd)
        stop=time.monotonic()+budget
        while census(group) and time.monotonic()<stop:time.sleep(.05)
        if not census(group):return
    # Retain leases while an unkillable descendant remains; no PASS receipt.
    while census(group):time.sleep(.2)

def retained_cleanup(group):
    warned=False
    while True:
        try:cleanup(group);need(not census(group),'owned unit quiescence not observed');return
        except Exception:
            if not warned:print('Build cleanup observation failed; retain source leases until owned descendants are gone.',flush=True);warned=True
            time.sleep(.2)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--private-out',type=Path,required=True);p.add_argument('--unit',required=True);a=p.parse_args()
    source=canonical(a.source);out=canonical(a.private_out)
    need(not out.exists() and out.parent.is_dir() and stat.S_IMODE(out.parent.stat().st_mode)==0o700 and out.parent.stat().st_uid==os.getuid(),'fresh owned private mode0700 output parent required')
    need(re.fullmatch(r'shz-stdvga-[a-z0-9-]{1,64}\.service',a.unit),'independent build unit name required')
    unit=subprocess.check_output(['systemctl','show',a.unit,'--property=MainPID,ActiveState,Delegate,RuntimeMaxUSec','--no-pager'],text=True,timeout=5)
    observation=dict(line.split('=',1) for line in unit.splitlines())
    need(observation.get('MainPID')==str(os.getpid()) and observation.get('ActiveState')=='active' and observation.get('Delegate')=='yes' and observation.get('RuntimeMaxUSec')=='infinity','actual independent surviving delegated producer required')
    group=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
    need(not census(group),'fresh build unit contains no other process')
    os.umask(0o077);leases=Leases();commands=[];out_created=False;stop=time.monotonic()+150
    tools={name:Path(shutil.which(name)).resolve() for name in ('gcc','make','git','sh','python3','ld','as','objcopy','objdump','strip')}
    for name in ('cc1','collect2'):
        tools[name]=Path(subprocess.check_output([tools['gcc'],'-print-prog-name='+name],text=True).strip()).resolve()
    try:
        originals=[pin(Path(__file__).resolve()),*[pin(t) for t in tools.values()]]
        for row in originals:leases.add(row)
        def run(argv,cwd=None):
            leases.check();remaining=stop-time.monotonic();need(remaining>0,'original bounded build budget consumed')
            command=list(map(str,argv));commands.append(command)
            try:value=subprocess.check_output(command,cwd=cwd,stderr=subprocess.STDOUT,timeout=remaining)
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
                if out_created:(out/'failed-command-output.log').write_bytes((error.output or b'')[:1<<20])
                raise
            leases.check();return value
        need(run([tools['git'],'-C',source,'rev-parse','HEAD']).decode().strip()==COMMIT,'actual pinned SeaBIOS commit differs')
        tree={}
        for row in run([tools['git'],'-C',source,'ls-tree','-rz',COMMIT]).split(b'\0'):
            if not row:continue
            meta,name=row.split(b'\t');mode,kind,blob=meta.decode().split();need(kind=='blob' and mode in ('100644','100755'),'tracked regular source only')
            name=name.decode();tree[name]=(mode,blob);leases.add(pin(source/name))
        for file in (source/'.git').rglob('*'):
            if file.is_file():leases.add(pin(file))
        archive=run([tools['git'],'-c','tar.umask=0022','-C',source,'archive','--format=tar',COMMIT]);files=archive_files(archive,tree)
        out.mkdir(mode=0o700);out_created=True;(out/'source').mkdir(mode=0o700)
        (out/'source.tar').write_bytes(archive);leases.add(pin(out/'source.tar'));rows=[]
        (out/'tool-snapshot').mkdir(mode=0o700)
        tool_snapshots={}
        for name,tool in tools.items():
            target=out/'tool-snapshot'/name;target.write_bytes(tool.read_bytes());target.chmod(0o700)
            need(pin(target)['sha256']==leases.rows[str(tool)]['pin']['sha256'],'tool snapshot differs from held original')
            tool_snapshots[name]=pin(target);leases.add(tool_snapshots[name])
        for name,(raw,mode) in sorted(files.items()):
            path=out/'source'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
            row={'path':name,'bytes':len(raw),'mode':mode,'sha256':sha(raw)};rows.append(row)
            original=leases.rows[str(source/name)]['pin'];need(original['bytes']==len(raw) and original['sha256']==row['sha256'],'cached original differs from pinned Git archive');leases.add(pin(path))
        manifest=(json.dumps(rows,indent=2)+'\n').encode();(out/'source-manifest.json').write_bytes(manifest);leases.add(pin(out/'source-manifest.json'))
        (out/'config-fragment').write_bytes(CONFIG);leases.add(pin(out/'config-fragment'))
        config=out/'generated.config';config.write_bytes(CONFIG)
        args=[tools['make'],'-j2','KCONFIG_CONFIG='+str(config),'CC='+str(tools['gcc']),'HOSTCC='+str(tools['gcc']),
              'CONFIG_SHELL='+str(tools['sh']),'LD='+str(tools['ld']),'AS='+str(tools['as']),'OBJCOPY='+str(tools['objcopy']),
              'OBJDUMP='+str(tools['objdump']),'STRIP='+str(tools['strip']),'PYTHON='+str(tools['python3'])]
        (out/'configure.log').write_bytes(run([*args,'olddefconfig'],out/'source'))
        (out/'configure-header.log').write_bytes(run([*args,'out/autoconf.h'],out/'source'))
        generated=config.read_bytes()
        for line in CONFIG.decode().splitlines():need(line.encode() in generated.splitlines(),'actual generated VGA config omitted requested option')
        leases.add(pin(config));(out/'make.log').write_bytes(run([*args,'out/vgabios.bin'],out/'source'))
        raw=(out/'source/out/vgabios.bin').read_bytes();pcir=rom_metadata(raw)
        (out/'vgabios-stdvga.bin').write_bytes(raw);(out/'VGAROM.BIN').write_bytes(raw+bytes(65536-len(raw)))
        artifacts={name:pin(out/name) for name in ('source-manifest.json','generated.config','vgabios-stdvga.bin','VGAROM.BIN')}
        for row in artifacts.values():leases.add(row)
        retained_cleanup(group);need(not census(group),'actual final owned unit descendants remain');leases.verify_all()
        receipt={'schema':'shizukuos.actual-source-built-stdvga-rom.v1','status':'ACTUAL_SOURCE_BOUND_STDVGA_ROM_BUILT_NOT_RUN',
                 'source_commit':COMMIT,'source_archive':pin(out/'source.tar'),'source_files':rows,'source_tree_digest_sha256':sha(manifest),
                 'generated_configuration_sha256':sha(generated),'raw_ROM':{'bytes':len(raw),'sha256':sha(raw)},
                 'padded_ROM':{'bytes':65536,'sha256':artifacts['VGAROM.BIN']['sha256']},'PCIR':pcir,'RAM_artifact_pins':artifacts,
                 'original_primary_tool_pins':{name:pin(t) for name,t in tools.items()},'primary_tool_snapshot_pins':tool_snapshots,'producer_source':pin(Path(__file__).resolve()),
                 'commands':commands,'actual_unit_observation':observation,'actual_unit_cgroup':str(group),
                 'all_original_copied_source_tools_config_RDLKs_held_through_build_final_SHA':True,
                 'exact_source_and_primary_tools_final_SHA_unchanged':True,'actual_final_unit_descendant_census_empty':True,
                 'VM_executed':False,'public_artifact':False,'complete_SDK_shared_library_closure':False,
                 'VGACFG_created':False,'device_epoch_authority':False}
        (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n');leases.verify_all();need(not census(group),'late build descendant appeared')
        print(json.dumps({'status':receipt['status'],'raw_ROM':receipt['raw_ROM'],'padded_ROM':receipt['padded_ROM']}))
    except BaseException:
        if out_created:(out/'build-result.json').unlink(missing_ok=True)
        raise
    finally:
        retained_cleanup(group)
        try:leases.verify_all()
        except BaseException:
            if out_created:(out/'build-result.json').unlink(missing_ok=True)
            raise
        finally:
            try:leases.close()
            except BaseException:
                if out_created:(out/'build-result.json').unlink(missing_ok=True)
                raise

if __name__=='__main__':main()
