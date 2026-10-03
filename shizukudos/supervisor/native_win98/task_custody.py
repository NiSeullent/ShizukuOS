#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Single private native task guardian; host proof never proves a guest boot.

Optional manifest pci_preparation selects an original observation pin and ten
independent producer_pins; sources must also pin tools/native_pci_preparation.py.
Held descriptor admission checks the actual private target recipe before spawn.
This optional comparison confers no device authority and does not alter argv.
"""
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import threading
import types

HERE=Path(__file__).resolve().parent
rpc=sys.modules.get('native_custody_rpc')
if rpc is None:
    # Host imports only. Production main requires bootstrap's admitted byte pins.
    spec=importlib.util.spec_from_file_location('native_custody_rpc',HERE/'custody_rpc.py')
    rpc=importlib.util.module_from_spec(spec);spec.loader.exec_module(rpc)
need=rpc.need
FLAGS={'VM_executed':False,'Windows98_boot_verified':False,'Windows98_GUI_verified':False,
       'native_Windows98_complete':False,'MSDOS_replacement_under_Windows98':False,
       'SMP_verified':False,'all_modern_apps_validated':False,'ISO_verified':False}
HELPERS=('shizukudos/supervisor/native_win98/build.py','shizukudos/supervisor/native_win98/prepare_vm.py',
         'shizukudos/tools/qemu.py','shizukudos/tools/shzinfo.py')
SOURCES=(*HELPERS,'shizukudos/supervisor/native_win98/run_vm.py',
         'shizukudos/supervisor/native_win98/owned_capture.py',
         'shizukudos/supervisor/native_win98/custody_rpc.py',
         'shizukudos/supervisor/native_win98/task_custody.py',
         'shizukudos/supervisor/native_win98/disk_lineage.py')
NATIVE_EPOCH_SOURCE='shizukudos/supervisor/native_win98/native_epoch_host.py'
PCI_PREPARATION_SOURCE='tools/native_pci_preparation.py'
GOP_NONCE_SOURCE='shizukudos/supervisor/native_win98/gop_nonce_staging.py'
GOP_CONSTRUCTOR_SOURCE='shizukudos/win98_boot/prepare_replacement.py'
ORIGINAL_MANIFEST_SCHEMA='shizukuos.native-original-userland-custody-manifest.v1'
ORIGINAL_EPOCH_INTENT_SCHEMA='shizukuos.native-original-userland-epoch-intent.v1'
# Optional original-phase scripted input recipe {path,bytes,sha256}; == owned_capture.INPUT_RECIPE_MAX_BYTES.
INPUT_RECIPE_MAX=16<<10
OWNED_INPUT_SCHEMA='shizukuos.w98-owned-input-option.v1'
def owned_input_flags(option):
    """Explicit versioned owned-machine input choice -> W98INPT flags (unknown fields refused).

    The choice selects only; authority is the live Attempt's sealed policy SHA."""
    need(type(option) is dict and set(option)=={'schema','machine','keyboard','mouse'} and option['schema']==OWNED_INPUT_SCHEMA and
         option['machine']=='q35-i8042' and type(option['keyboard']) is bool and type(option['mouse']) is bool and
         (option['keyboard'] or option['mouse']),'exact versioned owned Q35 i8042 keyboard/mouse input option required')
    return (1 if option['keyboard'] else 0)|(2 if option['mouse'] else 0)
# An original-observation device epoch never confers these; they stay literal False.
ORIGINAL_EPOCH_FALSE=('DOS3_replacement_profile','MSDOS_replacement_under_Windows98','default_GOP_registered',
                      'GPU_active','Windows98_release_approved','genuine_Windows_verified','HostGrant_transmitted',
                      'VM_executed','ISO_verified','apps_verified','public_artifact')

def identity(s):return s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns

def pin(row,maximum=8<<30):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact immutable file pin')
    p=Path(row['path']);need(p.is_absolute() and str(p)==row['path'] and p.resolve()==p and not any(q.is_symlink() for q in (p,*p.parents)),'canonical nonsymlink path')
    need(not any(p==base or base in p.parents for base in map(Path,('/dev','/proc','/sys'))),'nonvirtual source path')
    need(type(row['bytes']) is int and 0<row['bytes']<=maximum,'bounded literal extent')
    need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) and row['sha256']!='0'*64,'explicit nonzero SHA')
    return p

# Streaming reads use bounded large blocks. A full SHA pass is still complete;
# only the syscall/block granularity changes (perf-b9: 1 MiB -> 4 MiB).
HASH_BLOCK=4<<20
# Namespace sweep cadence for long streaming reads (full hashes, FAT
# observation). Every block still checks the global SIGIO latch plus the
# exact streamed FD/path/lease; a complete sweep of all held rows and their
# ancestors runs at stream start/end and at least every SWEEP_SECONDS or
# SWEEP_TICKS blocks, and every explicit union.check() decision point stays a
# complete sweep. Nothing observed is cached across sweeps.
SWEEP_SECONDS=.25
SWEEP_TICKS=1024
PROGRESS_BYTES=512<<20

def progress(phase,done,total,started):
    """Bounded guardian stderr marker for long held-source phases (no paths)."""
    print('task_custody progress phase=%s bytes=%d/%d elapsed=%.1fs'%(phase,done,total,time.monotonic()-started),
          file=sys.stderr,flush=True)

def full_hash(fd,size,check=lambda:None,phase=None):
    digest=hashlib.sha256();at=0;started=time.monotonic();marker=PROGRESS_BYTES
    while at<size:
        check();block=os.pread(fd,min(HASH_BLOCK,size-at),at);need(block,'short immutable input read');digest.update(block);at+=len(block)
        if phase is not None and size>=PROGRESS_BYTES and (at>=marker or at==size):
            progress(phase,at,size,started);marker+=PROGRESS_BYTES
    check();need(not os.pread(fd,1,size),'unexpected extent');return digest.hexdigest()

class LeaseUnion:
    """One guardian-only SIGIO latch, including subsequently frozen sources."""
    def __init__(self):
        self.rows={};self.broken=False;self.previous=signal.getsignal(signal.SIGIO);self.closed=False
        # Lexical names only (fixed at admission); every sweep re-observes them.
        self._ancestors=set();self._ticks=0;self._swept=time.monotonic()
        signal.signal(signal.SIGIO,self._break)
    def _break(self,*_):self.broken=True
    def add(self,row):
        p=pin(row);name=str(p)
        if name in self.rows:
            need(self.rows[name]['pin']==row,'conflicting shared input pins');return self.rows[name]
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_size==row['bytes'],'regular exact input')
            fcntl.fcntl(fd,fcntl.F_SETOWN,os.getpid());fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK)
            entry={'fd':fd,'pin':dict(row),'identity':identity(before),'full_SHA_admitted':False,
                   'lexical':(name,tuple(str(q) for q in (p,*p.parents)))};self.rows[name]=entry
            # Entry-local per block (scheduled complete sweeps); a complete
            # sweep per tiny admitted source made admission O(rows^2).
            self._entry(entry)
            need(full_hash(fd,row['bytes'],lambda:self.tick(entry),'admit-full-sha')==row['sha256'],'full leased SHA mismatch')
            # Close the stream: exact entry path/lease and its own ancestors now;
            # all other rows at the next scheduled or explicit complete sweep.
            self._entry(entry,ancestors=True);self._ancestors.update(entry['lexical'][1])
            entry['full_SHA_admitted']=True;self.tick(entry);return entry
        except BaseException:
            self.rows.pop(name,None);os.close(fd);raise
    def _entry(self,entry,ancestors=False):
        """One held FD: latch, owner, read-only lease, inode and path identity."""
        need(not self.broken and not self.closed,'guardian lease break requested')
        fd=entry['fd'];info=os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY and
             fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK and fcntl.fcntl(fd,fcntl.F_GETOWN)==os.getpid() and
             identity(info)==entry['identity'] and identity(os.stat(entry['lexical'][0]))==entry['identity'],
             'guardian lease/path identity changed')
        if ancestors:need(not any(stat.S_ISLNK(os.lstat(q).st_mode) for q in entry['lexical'][1]),'guardian original ancestor became a symlink')
    def tick(self,entry):
        """Per-block streaming guard; escalates to a complete sweep on schedule."""
        self._entry(entry);self._ticks+=1
        if self._ticks>=SWEEP_TICKS or time.monotonic()-self._swept>=SWEEP_SECONDS:self.check()
    def stream_guard(self,entry):
        need(self.rows.get(entry['lexical'][0]) is entry,'stream guard requires a currently held row')
        self.check()
        return lambda:self.tick(entry)
    def check(self):
        need(not self.broken,'guardian lease break requested')
        pid=os.getpid();ancestors=self._ancestors
        for name,row in self.rows.items():
            if 'lexical' not in row:ancestors=ancestors|{str(q) for q in (Path(name),*Path(name).parents)}
            fd=row['fd'];info=os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY and
                 fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK and fcntl.fcntl(fd,fcntl.F_GETOWN)==pid and
                 identity(info)==row['identity'] and identity(os.stat(name))==row['identity'],'guardian lease/path identity changed')
        # Lexical ancestor names are fixed; their lstat is re-observed every sweep.
        need(not any(stat.S_ISLNK(os.lstat(q).st_mode) for q in ancestors),'guardian original ancestor became a symlink')
        self._ticks=0;self._swept=time.monotonic()
    def raw(self,row,maximum):
        entry=self.add(row);need(row['bytes']<=maximum,'bounded metadata/source');raw=os.pread(entry['fd'],row['bytes']+1,0)
        need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'held raw snapshot differs');self.check();return raw
    def json(self,row,maximum=16<<20):
        value=json.loads(self.raw(row,maximum),object_pairs_hook=rpc.pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite metadata')))
        need(type(value) is dict,'receipt object required');return value
    def close(self,owner=None):
        need(owner is None or owner.safe_to_release(),'cannot unlock a live/unreaped owned child')
        error=None
        try:
            self.check()
            for row in self.rows.values():
                guard=(lambda row=row:self.tick(row)) if 'lexical' in row else self.check
                need(full_hash(row['fd'],row['pin']['bytes'],guard,'late-full-sha')==row['pin']['sha256'],'late leased full SHA differs')
            self.check()
        except BaseException as caught:error=caught
        for row in reversed(list(self.rows.values())):
            try:fcntl.fcntl(row['fd'],fcntl.F_SETLEASE,fcntl.F_UNLCK)
            except BaseException as caught:error=error or caught
            try:os.close(row['fd'])
            except BaseException as caught:error=error or caught
        self.rows.clear();self.closed=True;signal.signal(signal.SIGIO,self.previous)
        if error:raise error

class TaskGroup:
    """Fresh delegated sibling leaves; only owned children enter the kill leaf."""
    def __init__(self,parent,name,limits):
        parent=Path(parent)
        need(parent.is_relative_to('/sys/fs/cgroup') and parent.resolve()==parent and re.fullmatch('custody-[a-z0-9-]{1,48}',name),'task delegated cgroup required')
        need(set(limits)=={'memory.high','memory.max','pids.max','cpu.max'} and all(type(limits[k]) is int and limits[k]>0 for k in ('memory.high','memory.max','pids.max')),'explicit task caps required')
        need(limits['memory.high']<=limits['memory.max'] and re.fullmatch('[0-9]+ [0-9]+',limits['cpu.max']),'bounded task cap order')
        current=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
        need(current==parent or current.parent==parent,'guardian must own delegated parent')
        self.parent,self.path,self.limits=parent,parent/name,dict(limits)
        self.guardian=current
        if current==parent:
            need((parent/'cgroup.procs').read_text().split()==[str(os.getpid())],'no unrelated process in delegated parent')
            self.guardian=parent/(name+'-owner');self.guardian.mkdir()
            (self.guardian/'cgroup.procs').write_text(str(os.getpid()))
            need(str(os.getpid()) in (self.guardian/'cgroup.procs').read_text().split(),'guardian placement not observed')
        available=(parent/'cgroup.controllers').read_text().split();need({'memory','pids','cpu'}<=set(available),'delegated controllers unavailable')
        (parent/'cgroup.subtree_control').write_text('+memory +pids +cpu')
        self.path.mkdir();self.closed=False;self.directory_fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        info=os.fstat(self.directory_fd);self.directory_identity=(info.st_dev,info.st_ino)
        for key,value in limits.items():(self.path/key).write_text(str(value))
        self.check()
    def check(self):
        info=os.fstat(self.directory_fd);need((info.st_dev,info.st_ino)==self.directory_identity,'held child cgroup inode replaced')
        need((self.path.stat().st_dev,self.path.stat().st_ino)==self.directory_identity,'owned child cgroup inode replaced')
        for key,value in self.limits.items():need((self.path/key).read_text().strip()==str(value),'actual task cgroup cap differs')
        current=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
        need(current!=self.path and current==self.guardian,'guardian entered child kill scope')
    def place_before_exec(self):
        # Called only in this single-threaded guardian's fork child. Failures go
        # through Popen's exec-error pipe; no target executable has run yet.
        (self.path/'cgroup.procs').write_text(str(os.getpid()))
        expected='0::/'+str(self.path.relative_to('/sys/fs/cgroup'))
        need(Path('/proc/self/cgroup').read_text().strip()==expected,'child cgroup placement failed before exec')
        libc=ctypes.CDLL(None,use_errno=True)
        need(libc.prctl(1,signal.SIGKILL,0,0,0)==0,'child parent-death signal failed')
        need(os.getppid()==self.owner_pid,'guardian died before exec')
    def members(self):
        self.check();fd=os.open('cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.directory_fd)
        try:
            raw=os.read(fd,65537);need(len(raw)<=65536 and not os.read(fd,1),'bounded actual task membership')
            members=raw.decode('ascii').split();need(all(v.isdigit() and int(v)>0 for v in members),'malformed task membership')
            self.check();return members
        finally:os.close(fd)
    def kill_members(self):
        self.check();fd=os.open('cgroup.kill',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.directory_fd)
        try:need(os.write(fd,b'1')==1,'owned task kill short write')
        finally:os.close(fd)
    def populated(self):
        self.check();fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.directory_fd)
        try:
            raw=os.read(fd,4097);need(len(raw)<=4096 and not os.read(fd,1),'bounded recursive task events')
            events={}
            for line in raw.decode('ascii').splitlines():
                pair=line.split();need(len(pair)==2 and pair[0] not in events and pair[1].isdigit(),'exact recursive task events');events[pair[0]]=int(pair[1])
            need(events.get('populated') in (0,1),'actual recursive populated observation required')
            self.check();return bool(events['populated'])
        finally:os.close(fd)
    def close(self):
        need(not self.members() and not self.populated(),'live child remains in cgroup subtree')
        try:self.path.rmdir()
        finally:os.close(self.directory_fd);self.closed=True

GATE_CODE="""import json,os,sys
readfd,execfd=int(sys.argv[1]),int(sys.argv[2]);args=json.loads(sys.argv[3])
try:
 if os.read(readfd,1)!=b'X':os._exit(125)
finally:os.close(readfd)
os.set_inheritable(execfd,False)
os.execve(execfd,args,os.environ)
"""

class Owner:
    def __init__(self,union,group,argv,executable_pin,timeout=300):
        self.union,self.group,self.expected,self.executable_pin=union,group,tuple(argv),executable_pin
        self.timeout=timeout;self.process=None;self.pidfd=None;self.qmp=None;self.attempted=False;self.start=None;self.reaped=False;self.target_released=False
        self._native_reaper=None;self._legacy_wait_started=False
        self.record={'schema':'shizukuos.native-custody.v1',**FLAGS,'custody_admitted':False,'owned_child_reaped':False,'leases_released':False,'launch_attempted':False}
    def spawn(self,request,rights):
        need(not self.attempted and self.process is None,'exactly one launch attempt')
        self.attempted=True;self.record['launch_attempted']=True
        declared=self.record.get('runtime_source_pins',{});configured=getattr(self,'_configured_native_reaper',None)
        need(type(declared) is dict and ((NATIVE_EPOCH_SOURCE in declared)==(configured is not None)),'declared native source requires actual native reaper configuration')
        if configured is not None:
            need(type(configured) is tuple and len(configured)==2 and configured[1]==declared[NATIVE_EPOCH_SOURCE],'native reaper configuration pin differs')
            module,row=configured;entry=self.union.rows.get(str(pin(row,1<<20)))
            need(type(module) is type(sys) and module.__file__==row['path'] and getattr(module,'__executed_sha256__',None)==row['sha256'] and
                 entry is not None and entry['pin']==row and entry.get('full_SHA_admitted') is True,'actual admitted native reaper configuration required')
            self.union.check()
        need(set(request)=={'argv','pipes'} and type(request['argv']) is list,'exact launch request')
        normalized=list(request['argv'])
        for option,placeholder in (('-serial','file:/proc/self/fd/0'),('-debugcon','file:/proc/self/fd/1')):
            index=list(self.expected).index(option)+1
            need(len(normalized)==len(self.expected) and type(normalized[index]) is str and re.fullmatch('file:/proc/self/fd/[0-9]{1,9}',normalized[index]),'exact sender log FD option')
            normalized[index]=placeholder
        need(normalized==list(self.expected),'only approved reconstructed argv')
        need(len(rights)==3 and len(request['pipes'])==3,'three role-ordered log writers required')
        observed=[]
        for fd in rights:
            info=os.fstat(fd);need(stat.S_ISFIFO(info.st_mode) and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_WRONLY,'anonymous writable log pipe required')
            need(os.readlink('/proc/self/fd/%d'%fd).startswith('pipe:['),'named FIFO refused')
            observed.append([info.st_dev,info.st_ino])
        need(observed==request['pipes'] and len({tuple(v) for v in observed})==3,'distinct sender-bound log pipes required')
        self.union.check();self.group.check();self.group.owner_pid=os.getpid()
        args=list(self.expected);serial=args.index('-serial')+1;debug=args.index('-debugcon')+1
        args[serial]='file:/proc/self/fd/%d'%rights[0];args[debug]='file:/proc/self/fd/%d'%rights[1]
        need(threading.active_count()==1,'guardian fork/exec requires its single thread')
        attempt=self.epoch_context['attempt'] if hasattr(self,'epoch_context') else None
        # The sealed policy is inherited by the TARGET (QEMU), never the
        # controller: prove the guardian FD number is the sealed memfd now.
        if attempt is not None:attempt.check();policy_fds=(attempt.policy_fd,)
        else:policy_fds=()
        source=self.union.add(self.executable_pin);gate_read,gate_write=os.pipe()
        try:
            launch=[str(Path(sys.executable).resolve()),'-B','-c',GATE_CODE,str(gate_read),str(source['fd']),json.dumps(args)]
            self.process=subprocess.Popen(launch,cwd=self.output,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=rights[2],pass_fds=(rights[0],rights[1],gate_read,source['fd'],*policy_fds),preexec_fn=self.group.place_before_exec)
            self.actual_args=args;self.record['owned_pid']=self.process.pid
            # Target exec remains gated even if pidfd allocation/ACK fails.
            self.pidfd=os.pidfd_open(self.process.pid,0)
            self.union.check();self.group.check()
            need(not self.exited(),'gated launcher exited before pidfd admission')
            if attempt is not None:self.assert_child_policy_fd(attempt)
            self.start=time.monotonic()
            need(os.write(gate_write,b'X')==1,'target gate release failed')
            self.target_released=True;self.record['VM_launch_may_have_occurred']=True
        finally:
            os.close(gate_read);os.close(gate_write)
        stop=time.monotonic()+5
        while True:
            try:self.assert_owned();break
            except (ValueError,FileNotFoundError):
                if self.exited() or time.monotonic()>=stop:raise
                time.sleep(.005)
        self.record['VM_executed']=True;self.record['custody_admitted']=True
        if configured is not None:
            module,row=configured
            executable=module.PinnedFD(source['fd'],self.executable_pin)
            binding=module.ProcessBinding(self.process,self.pidfd,executable,tuple(args),'/'+str(self.group.path.relative_to('/sys/fs/cgroup')))
            self.admit_native_reaper(binding,module,row)
            if hasattr(self,'epoch_context'):
                self.epoch_context['attempt'].bind_child(binding,self.epoch_context['listener'])
        return {'pid':self.process.pid,'argv':args}
    def assert_child_policy_fd(self,attempt):
        """Before the exec gate opens: the gated child's own FD N is the sealed policy memfd."""
        attempt.check();fd=attempt.policy_fd
        need(type(fd) is int and fd>2,'sealed policy FD number required')
        child=os.stat('/proc/%d/fd/%d'%(self.process.pid,fd))
        need((child.st_dev,child.st_ino,child.st_size)==tuple(attempt.policy_identity[:3]),'actual gated child inherited policy FD differs')
        need(not self.exited(),'gated launcher exited during policy FD admission')
        self.record['target_policy_fd_identity_verified_before_exec']=True
    def assert_owned(self):
        need(self.process is not None and self.pidfd is not None and not self.exited(),'owned live pidfd required')
        need(os.readlink('/proc/self/fd/%d'%self.pidfd)=='anon_inode:[pidfd]','actual pidfd required')
        fdinfo=Path('/proc/self/fdinfo/%d'%self.pidfd).read_text();need(re.findall(r'^Pid:\s*(\d+)$',fdinfo,re.M)==[str(self.process.pid)],'pidfd PID differs')
        proc=Path('/proc/%d'%self.process.pid);raw=(proc/'stat').read_bytes();need(len(raw)<=8192,'bounded proc stat')
        fields=raw[raw.rfind(b')')+2:].split();need(len(fields)>=20 and fields[0] not in (b'Z',b'X') and int(fields[1])==os.getpid() and proc.stat().st_uid==os.getuid(),'actual parent/live UID differs')
        start=int(fields[19])
        if hasattr(self,'starttime'):need(start==self.starttime,'process start identity drift')
        else:self.starttime=start
        args=(proc/'cmdline').read_bytes();need(len(args)<=65536 and args==b''.join(os.fsencode(a)+b'\0' for a in self.actual_args),'actual argv differs')
        source=self.union.add(self.executable_pin);executed=(proc/'exe').stat();need((executed.st_dev,executed.st_ino)==source['identity'][:2],'actual executable differs from leased source')
        expected='0::/'+str(self.group.path.relative_to('/sys/fs/cgroup'))
        need((proc/'cgroup').read_text().strip()==expected,'actual executable outside child task cgroup')
        self.union.check();self.group.check()
    def exited(self):
        if self.pidfd is None:return False
        poll=select.poll();poll.register(self.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR);return bool(poll.poll(0))
    def admit_native_reaper(self,binding,native_module,source_pin):
        """Delegate this guardian's one waiter to an admitted concrete binding.

        In-process only: no RPC request can provide a module, class or callback.
        This entry does not start an optional exchange or confer device access.
        """
        need(self._native_reaper is None and not self._legacy_wait_started and not self.reaped,'native reaper requires fresh exclusive waiter')
        name='shizukudos/supervisor/native_win98/native_epoch_host.py'
        declared=self.record.get('runtime_source_pins',{})
        need(type(declared) is dict and declared.get(name)==source_pin,'native reaper source must be declared by guardian manifest')
        path=pin(source_pin,1<<20);entry=self.union.rows.get(str(path))
        need(entry is not None and entry.get('full_SHA_admitted') is True and entry['pin']==source_pin,'already full-SHA-leased native source required')
        need(type(native_module) is type(sys) and native_module.__file__==str(path) and getattr(native_module,'__executed_sha256__',None)==source_pin['sha256'],'actual admitted native module origin required')
        cls=getattr(native_module,'ProcessBinding',None)
        need(type(cls) is type and cls.__name__=='ProcessBinding' and cls.__module__==native_module.__name__ and type(binding) is cls,'exact admitted concrete ProcessBinding required')
        raw=self.union.raw(source_pin,1<<20);compiled=compile(raw,str(path),'exec',dont_inherit=True)
        codes=[x for x in compiled.co_consts if type(x) is type(compiled) and x.co_name=='ProcessBinding']
        need(len(codes)==1,'unique admitted ProcessBinding class required')
        expected={x.co_name:x for x in codes[0].co_consts if type(x) is type(compiled)}
        methods={}
        for method in ('__init__','_pidfd','check','reap_owned','assert_reaped'):
            actual=cls.__dict__.get(method);frozen=expected.get(method)
            need(type(actual) is type(lambda:None) and frozen is not None and actual.__globals__ is native_module.__dict__ and actual.__code__==frozen and
                 all(getattr(actual.__code__,field)==getattr(frozen,field) for field in ('co_filename','co_firstlineno','co_qualname','co_linetable','co_exceptiontable')) and method not in binding.__dict__,'native reaper methods must match whole held source')
            methods[method]=(actual,actual.__code__)
        need(type(self.process) is subprocess.Popen and binding.process is self.process and self.pidfd is not None and binding.pidfd==binding.original_pidfd==self.pidfd and binding.original_pid==self.process.pid,'same guardian Popen and original pidfd required')
        need(binding.reap_record is None and not hasattr(binding,'_guardian_reaper_owner'),'native binding already consumed or claimed')
        self.assert_owned();binding.check()
        source=self.union.rows[str(pin(self.executable_pin))]
        need(type(binding.executable) is native_module.PinnedFD and binding.executable.fd==source['fd'] and binding.executable.pin==self.executable_pin and
             binding.starttime==self.starttime and binding.argv==tuple(self.actual_args) and binding.command==b''.join(os.fsencode(a)+b'\0' for a in self.actual_args) and
             binding.cgroup=='/'+str(self.group.path.relative_to('/sys/fs/cgroup')),'same original start/argv/cgroup/executable descriptor required')
        self.assert_owned();self.union.check();self.group.check()
        context={'binding':binding,'class':cls,'module':native_module,'methods':methods,'source_pin':dict(source_pin),'guardian_pid':os.getpid(),
                 'process':self.process,'pid':self.process.pid,'pidfd':self.pidfd,'pidfd_identity':identity(os.fstat(self.pidfd)),
                 'binding_pidfd_identity':binding.pidfd_identity,'starttime':self.starttime,'argv':tuple(self.actual_args),'command':binding.command,'cgroup':binding.cgroup,
                 'executable':binding.executable,'executable_fd':binding.executable.fd,'executable_pin':dict(binding.executable.pin),'executable_identity':binding.executable.binding,
                 'record_seen':False,'raw_record':None,'status_unavailable':False}
        binding._guardian_reaper_owner=self;self._native_reaper=context
        self.record.update(native_reaper_admitted=True,native_reaper_source_pin=dict(source_pin),native_reap_postcheck_verified=False)
        return {'pid':self.process.pid,'starttime':self.starttime,'source_pin':dict(source_pin)}
    def _native_record(self,raw):
        need(type(raw) is dict and set(raw)=={'pid','code','status'} and all(type(raw[k]) is int for k in raw),'strict numeric native CLD record required')
        need(raw['pid']==self._native_reaper['pid'] and raw['code'] in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED),'exact native parent waitid PID/code required')
        need(0<=raw['status']<=255 if raw['code']==os.CLD_EXITED else 0<raw['status']<signal.NSIG,'actual native waitid status bound required')
        return dict(raw)
    def _native_identity(self):
        context=self._native_reaper;binding=context['binding'];module=context['module']
        need(os.getpid()==context['guardian_pid'] and self.process is context['process'] and self.process.pid==context['pid'] and
             self.pidfd==context['pidfd'] and identity(os.fstat(self.pidfd))==context['pidfd_identity'],'original guardian/Popen/pidfd identity changed')
        need(type(binding) is context['class'] and module.ProcessBinding is context['class'] and getattr(module,'__executed_sha256__',None)==context['source_pin']['sha256'] and
             binding._guardian_reaper_owner is self and binding.process is self.process and binding.pidfd==binding.original_pidfd==self.pidfd and binding.original_pid==context['pid'] and
             binding.pidfd_identity==context['binding_pidfd_identity'],'admitted native reaper context changed')
        for name,(function,code) in context['methods'].items():
            actual=getattr(binding,name)
            need(name not in binding.__dict__ and getattr(actual,'__self__',None) is binding and getattr(actual,'__func__',None) is function and function.__code__ is code and function.__globals__ is module.__dict__,'admitted native reaper method changed')
        need(binding.starttime==self.starttime==context['starttime'] and binding.argv==tuple(self.actual_args)==context['argv'] and binding.command==context['command'] and binding.cgroup==context['cgroup'] and
             binding.executable is context['executable'] and binding.executable.fd==context['executable_fd'] and binding.executable.pin==context['executable_pin'] and binding.executable.binding==context['executable_identity'],'original native birth/argv/cgroup/executable changed')
        if context['record_seen']:
            need(self._native_record(binding.reap_record)==context['raw_record']==self._native_record(self.record.get('native_reap_record')),'retained native waitid record changed')
        else:need(binding.reap_record is None,'native wait performed outside delegated guardian observation')
        binding._pidfd(reaped=context['record_seen'] or context['status_unavailable'])
        return binding
    def _retain_native_record(self,raw):
        # Latch before validation: an unusable result still cannot cause a
        # second destructive wait. Ordinary native records contain three ints.
        context=self._native_reaper;context['record_seen']=True
        if type(raw) is dict and set(raw)=={'pid','code','status'} and all(type(v) in (int,bool,type(None)) and (type(v) is not int or -(1<<63)<=v<(1<<63)) for v in raw.values()):
            self.record['native_reap_record']=dict(raw)
        else:self.record['native_reap_record']=None
        self.record.update(native_reap_postcheck_verified=False,exit_status_verified=False)
        context['raw_record']=self._native_record(raw)
    def _observe_native(self):
        context=self._native_reaper;binding=self._native_identity()
        if context['status_unavailable']:raise ChildProcessError('original delegated parent wait status remains unavailable')
        if not context['record_seen']:
            if not self.exited():return None
            try:raw=binding.reap_owned()
            except BaseException as error:
                if binding.reap_record is not None:
                    try:self._retain_native_record(binding.reap_record)
                    except BaseException as retained_error:
                        self.record['native_reap_postcheck_error']=type(error).__name__
                        raise error from retained_error
                    self.record['native_reap_postcheck_error']=type(error).__name__
                elif isinstance(error,ChildProcessError):
                    context['status_unavailable']=True;self.physically_dead=self.exited()
                    self.record.update(exit_status_verified=False,parent_wait_status_unavailable=True)
                raise
            self._retain_native_record(raw)
        binding=self._native_identity();binding.assert_reaped()
        raw=context['raw_record'];code=raw['status'] if raw['code']==os.CLD_EXITED else -raw['status']
        self.process.returncode=code;self.reaped=True
        self.record.update(native_reap_postcheck_verified=True,owned_child_reaped=True,exit_status_verified=True,observed_exit_code=code)
        return code
    def observe(self):
        if self.process is None:return None
        if self._native_reaper is not None:return self._observe_native()
        if self.reaped:return self.process.returncode
        self._legacy_wait_started=True
        try:
            if self.pidfd is not None:
                status=os.waitid(os.P_PIDFD,self.pidfd,os.WEXITED|os.WNOHANG)
                if status is None:return None
                need(status.si_pid==self.process.pid and status.si_code in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED),'exact actual parent waitid status required')
                code=status.si_status if status.si_code==os.CLD_EXITED else -status.si_status
                need(self.exited(),'actual status without pidfd exit refused')
            else:
                need(not self.target_released,'missing pidfd after target gate release')
                pid,status=os.waitpid(self.process.pid,os.WNOHANG)
                if pid==0:return None
                need(pid==self.process.pid,'actual unreleased launcher wait required');code=os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            self.record['exit_status_verified']=False;self.record['parent_wait_status_unavailable']=True
            self.physically_dead=bool(self.pidfd is not None and self.exited())
            # Never return CPython's synthesized zero. A dead original pidfd
            # permits failed physical cleanup, not observed-status acceptance.
            raise
        self.process.returncode=code;self.reaped=True
        self.record.update(owned_child_reaped=True,exit_status_verified=True,observed_exit_code=code)
        return code
    def poll(self):return self.observe()
    def wait(self,seconds):
        need(type(seconds) in (int,float) and 0<seconds<=5,'bounded cleanup wait')
        stop=time.monotonic()+seconds
        while True:
            code=self.observe()
            if code is not None:return code
            remaining=stop-time.monotonic()
            if remaining<=0:return None
            time.sleep(min(.01,remaining))
    def confirm_reaped(self):
        if self._native_reaper is not None:
            if not self.reaped or self.record.get('native_reap_postcheck_verified') is not True:return False
            binding=self._native_identity();binding.assert_reaped()
            return self.process.returncode is not None and self.exited()
        return self.process is None or (self.reaped and self.process.returncode is not None and (self.exited() or not self.target_released))
    def safe_to_release(self):
        if self._native_reaper is not None:
            if self.confirm_reaped():return True
            if not self._native_reaper['status_unavailable']:return False
            self._native_identity();return bool(getattr(self,'physically_dead',False) and self.exited())
        return self.confirm_reaped() or (getattr(self,'physically_dead',False) and self.exited())
    def signal(self,number):
        need(number in (signal.SIGTERM,signal.SIGKILL),'only bounded owned cleanup signals')
        if self._native_reaper is not None:self._native_identity()
        if self.pidfd is None:
            need(self.process is None or not self.target_released,'released target missing pidfd; custody must remain held');return
        if not self.exited():signal.pidfd_send_signal(self.pidfd,number)
    def configure_epoch_context(self,attempt,listener,capture,guard):
        """Attach internal pre-artifact live objects; no RPC or receipt can do it."""
        configured = getattr(self,'_configured_native_reaper',None)
        need(configured is not None and self.process is None and not self.attempted and
             not hasattr(self,'epoch_context') and callable(guard),'fresh source-admitted guardian epoch context')
        module,row = configured
        need(type(attempt) is module.Attempt and type(listener) is module.PrivateListener and
             attempt.owner is None and listener.owner is None and attempt.staging_claim is not None,
             'original staged same-process Attempt/channel required')
        attempt.check();listener.check();guard()
        source = self.record['runtime_source_pins']['shizukudos/supervisor/native_win98/owned_capture.py']
        need(capture.__file__ == source['path'] and getattr(capture,'__executed_sha256__',None) == source['sha256'],
             'held original capture source module required')
        self.epoch_context = {'module':module,'attempt':attempt,'listener':listener,'capture':capture,
                              'guard':guard,'monitor':None,'grant':None,'resumed':False,'esp_fd':None}

    def epoch_guard(self):
        context = self.epoch_context;context['guard']();self.union.check();self.group.check()
        attempt = context['attempt']
        if context['resumed']:attempt.check_after_handoff()
        else:attempt.check()
        if self.process is not None:self.assert_owned()

    def open_epoch_monitor(self):
        context = self.epoch_context;module = context['module'];attempt = context['attempt']
        need(context['monitor'] is None and self.qmp is None and self.process is not None,
             'first and sole guardian QMP reader required')
        self.epoch_guard();binding = self._native_identity()
        need(attempt.owner is binding and context['listener'].owner is binding,'exact original child/policy/channel binding')
        monitor = context['capture'].OwnedQMP(self.output/'qmp.sock',self.process.pid,
                  attempt.original_deadline_ns/1e9,pump=self.epoch_guard)
        context['monitor'] = monitor;self.qmp = monitor.socket
        self.record['QMP_peer_admitted'] = True
        self.epoch_guard();initial = monitor.call('query-status')
        need(type(initial) is dict and initial.get('running') is False and
             initial.get('status') in ('prelaunch','paused'), 'fresh -S child must be observed stopped before guest execution')
        fd = os.open(self.output/'esp.img',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        context['esp_fd'] = fd
        esp = module.OwnedESP(fd,self.output/'esp.img')
        source = self.record['runtime_source_pins']['shizukudos/supervisor/native_win98/owned_capture.py']
        held = self.union.add(source);monitor_source = module.PinnedFD(held['fd'],source)
        grant = module.HostGrant(attempt,binding,monitor,context['listener'],esp,monitor_source,guard=self.epoch_guard)
        context['grant'] = grant
        self.epoch_guard();monitor.call('cont');self.epoch_guard()
        receipt = grant.exchange()
        need(grant.handoff_monitor() is monitor,'same actual monitor/parser must be handed back')
        # Complete exchange leaves QEMU paused. Resume within BOTH immutable
        # bounds before any controller can request its first capture operation.
        attempt.check();monitor.call('cont');attempt.check()
        context['resumed'] = True;self.epoch_guard()
        context['receipt'] = receipt;context['requests'] = 0
        receipt.update(constructor_host_runtime_wiring_implemented=True,QEMU_remains_paused=False,
                       actual_owner_resumed_within_exchange_deadline=True,
                       same_guardian_Attempt_and_sole_monitor_retained=True)
        persist(self.output/'native-host-grant.json',receipt)
        self.record['actual_host_grant_transmitted'] = True
        return {'host_grant_transmitted':True,'original_deadline_ns':attempt.original_deadline_ns,
                'receipt_sha256':hashlib.sha256((json.dumps(receipt,indent=2,allow_nan=False)+'\n').encode()).hexdigest()},[]

    def epoch_peer_facts(self):
        self.epoch_guard()
        context = self.epoch_context
        need(context['resumed'] is True and context['monitor'] is not None,
             'completed original HostGrant and sole monitor required')
        peer = struct.unpack('3i',context['monitor'].socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        need(peer[:2] == (self.process.pid,os.getuid()),'current sole monitor peer differs from original child')
        self.epoch_guard()
        return list(peer),[]

    def epoch_monitor_call(self,request):
        need(type(request) is dict and set(request) == {'command','arguments','deadline'}, 'exact bounded epoch monitor request')
        context = self.epoch_context;need(context['resumed'] is True and context['monitor'] is not None,
                                         'actual completed HostGrant/owner resume required before controller observation')
        command,arguments,deadline = (request[k] for k in ('command','arguments','deadline'))
        need(type(deadline) in (int,float) and math.isfinite(deadline), 'finite controller operation deadline')
        allowed = {'query-blockstats','query-status','query-block','query-named-block-nodes','query-pci','stop','quit','screendump','pmemsave','human-monitor-command','input-send-event','send-key'}
        need(type(command) is str and command in allowed and (arguments is None or type(arguments) is dict),
             'scoped post-grant capture or cleanup command required')
        if command in {'query-blockstats','query-status','query-block','query-named-block-nodes','query-pci','stop','quit'}:
            need(arguments is None,'no arguments for scoped query/pause/quit')
        elif command in ('input-send-event','send-key'):
            need(context['capture'].input_arguments_valid(command,arguments),'bounded scoped input command')
            context['input_events'] = context.get('input_events',0)+context['capture'].input_events_count(command,arguments)
            need(context['input_events'] <= context['capture'].INPUT_MAX_EVENTS,'finite scripted input event budget')
        elif command == 'human-monitor-command':
            need(type(arguments) is dict and set(arguments) == {'command-line'},'exact readonly HMP command')
            line = arguments['command-line'];allowed_addresses = {
                context['receipt']['observations']['FlatView']['ecam'][0]+device.bdf*4096
                for device in context['attempt'].expected.devices}
            match = re.fullmatch(r'xp /10wx 0x([0-9a-f]{1,16})',line) if type(line) is str else None
            need(line in ('info registers','info mtree -f') or (match is not None and int(match[1],16) in allowed_addresses),
                 'only current admitted ECAM or CPU/RAM description reads')
        else:
            need(type(arguments) is dict and type(arguments.get('filename')) is str,'exact private capture destination')
            target = Path(arguments['filename'])
            need(target.parent == self.output and target.resolve() == target and not target.exists() and
                 re.fullmatch(r'native-[0-9]{3}(?:\.png|-info\.bin)',target.name) is not None,
                 'fresh exact private capture filename required')
            if command == 'screendump':need(set(arguments) == {'filename','format'} and arguments['format'] == 'png' and target.suffix == '.png','exact PNG capture')
            else:need(set(arguments) == {'filename','val','size'} and type(arguments['val']) is int and arguments['val'] == 0x04000000 and
                      type(arguments['size']) is int and arguments['size'] == 8192 and target.name.endswith('-info.bin'),'bounded actual native info memory capture')
        self.epoch_guard();monitor = context['monitor']
        monitor.deadline = min(deadline,context['attempt'].original_deadline_ns/1e9)
        result = monitor.call(command,arguments)
        if command == 'quit' and self.exited():
            context['guard']();self.union.check();self.group.check();context['attempt']._check_sources_policy()
        else:self.epoch_guard()
        # Large readonly observations do not fit16KiB RPC. Pass one newly
        # persisted/read-leased result FD, never a second monitor reader.
        context['requests'] += 1
        need(context['requests'] <= 4096,'finite postepoch QMP capture operation budget')
        raw = (json.dumps({'command':command,'result':result},separators=(',',':'),allow_nan=False)+'\n').encode()
        need(len(raw) <= 1<<20,'bounded full QMP result')
        path = self.output/('qmp-return-%04d.json'%context['requests'])
        persist(path,{'command':command,'result':result})
        actual = path.read_bytes()
        row = {'path':str(path),'bytes':len(actual),'sha256':hashlib.sha256(actual).hexdigest()}
        entry = self.union.add(row)
        return {'pin':row,'command':command},[entry['fd']]

    def close_epoch_after_reap(self):
        context = getattr(self,'epoch_context',None)
        if context is None:return
        need(self.confirm_reaped(),'original child must be exactly reaped before policy/channel release')
        if context['grant'] is not None:context['grant'].close_after_reap()
        else:
            try:context['listener'].close()
            finally:context['attempt'].close()
        if context['monitor'] is not None:context['monitor'].close();self.qmp = None
        if context['esp_fd'] is not None:os.close(context['esp_fd']);context['esp_fd'] = None

    def admit_qmp(self,fd):
        sock=None
        try:
            need(not hasattr(self,'epoch_context'),'guardian-owned epoch monitor cannot adopt a controller reader')
            self.assert_owned();sock=socket.socket(fileno=fd)
            need(sock.family==socket.AF_UNIX and sock.type&15==socket.SOCK_STREAM,'actual Unix QMP stream')
            pid,uid,_=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            need(pid==self.process.pid and uid==os.getuid(),'actual QMP peer differs from held owned child')
            if self.qmp is not None:raise ValueError('QMP already admitted')
            self.qmp=sock;self.record['QMP_peer_admitted']=True;return True
        except BaseException:
            if sock is not None:sock.close()
            else:os.close(fd)
            raise
    def recover(self,budget=16):
        # No QMP takeover: duplicated streams can have controller-buffered data.
        stop=time.monotonic()+budget
        for number,seconds in ((signal.SIGTERM,3),(signal.SIGKILL,3)):
            if self.safe_to_release():return self.confirm_reaped()
            try:self.signal(number)
            except BaseException as error:self.record.setdefault('recovery_errors',[]).append(type(error).__name__)
            try:
                if self.wait(min(seconds,max(.001,stop-time.monotonic()))) is not None:return True
            except BaseException as error:self.record.setdefault('recovery_errors',[]).append(type(error).__name__)
        self.record['unresolved_owned_child']=not self.safe_to_release();return self.confirm_reaped()
    def release(self):
        need(self.safe_to_release(),'unreaped child forbids custody release')
        self.close_epoch_after_reap()
        if self.qmp:self.qmp.close();self.qmp=None
        self.union.close(self)
        if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
        self.record['leases_released']=True

class ParentWait:
    """Strict controller parent status; never Popen's ECHILD fallback zero."""
    def __init__(self,process):self.process=process;self.pidfd=None;self.reaped=False;self.physically_dead=False
    def exited(self):
        if self.pidfd is None:return False
        poll=select.poll();poll.register(self.pidfd,select.POLLIN|select.POLLHUP|select.POLLERR);return bool(poll.poll(0))
    def observe(self):
        if self.reaped:return self.process.returncode
        try:
            if self.pidfd is None:
                pid,status=os.waitpid(self.process.pid,os.WNOHANG)
                if pid==0:return None
                need(pid==self.process.pid,'exact controller parent wait required');code=os.waitstatus_to_exitcode(status)
            else:
                status=os.waitid(os.P_PIDFD,self.pidfd,os.WEXITED|os.WNOHANG)
                if status is None:return None
                need(status.si_pid==self.process.pid and status.si_code in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED) and self.exited(),'exact controller parent waitid/pidfd exit required')
                code=status.si_status if status.si_code==os.CLD_EXITED else -status.si_status
        except ChildProcessError:
            self.physically_dead=self.exited();raise
        self.process.returncode=code;self.reaped=True;return code
    def safe_to_release(self):
        if self.reaped:return self.pidfd is None or self.exited()
        if self.physically_dead:return self.exited()
        self.observe();return self.reaped and (self.pidfd is None or self.exited())
    def kill(self):
        if self.safe_to_release():return
        if self.pidfd is None:self.pidfd=os.pidfd_open(self.process.pid,0)
        if not self.exited():signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)

def task_stop(owner,preparation_stop,finalization_stop,timeout):
    return finalization_stop if finalization_stop is not None else owner.start+timeout+16 if owner.start else preparation_stop

def task_deadline(owner,preparation_stop,finalization_stop,timeout,now):
    if owner.start is not None and owner.confirm_reaped() and finalization_stop is None:finalization_stop=now+timeout
    stop=task_stop(owner,preparation_stop,finalization_stop,timeout)
    if now>stop:raise TimeoutError('original task observation/cleanup/finalization deadline consumed')
    return finalization_stop

def recovery_tick(owner,controller,group,recovery_stop):
    """One resident recovery iteration: every failed observation retains custody."""
    safe=False;control_safe=controller is None;members=None;populated=True
    try:
        safe=owner.safe_to_release()
        if controller is not None:control_safe=controller.safe_to_release()
        members=group.members();populated=group.populated()
        if safe and control_safe and not members and not populated:return True
    except BaseException as error:owner.record['custody_observation_failed']=type(error).__name__
    owner.record.update(unresolved_owned_child=not safe,unresolved_controller=not control_safe,unresolved_task_members=members is None or bool(members) or populated)
    try:
        if not control_safe:controller.kill()
    except BaseException as error:owner.record['controller_recovery_failed']=type(error).__name__
    try:
        if not safe:owner.signal(signal.SIGKILL);owner.wait(1)
        if (members or populated) and time.monotonic()>=recovery_stop:group.kill_members()
    except BaseException as error:owner.record['task_recovery_failed']=type(error).__name__
    return False

class Server:
    def __init__(self,channel,owner,sources,output):
        self.channel,self.owner,self.sources,self.output=channel,owner,sources,Path(output);self.sequence=0;self.frozen=set()
        self.originals={name:dict(entry) for name,entry in owner.union.rows.items() if entry.get('full_SHA_admitted') is True}
        self.borrowed=set()
    def original(self,row):
        name=str(pin(row));entry=self.originals.get(name);current=self.owner.union.rows.get(name)
        need(entry is not None and current is not None and entry['pin']==row==current['pin'] and
             current.get('full_SHA_admitted') is True and entry['fd']==current['fd'] and entry['identity']==current['identity'],'only initially full-SHA-admitted original pins')
        need(fcntl.fcntl(entry['fd'],fcntl.F_GETOWN)==os.getpid(),'guardian retains original lease signal ownership')
        return name,entry
    def dispatch(self,row,rights):
        need(set(row)=={'id','op','params'} and type(row['id']) is int and row['id']==self.sequence+1 and type(row['params']) is dict,'strict ordered request')
        self.sequence=row['id'];op,p=row['op'],row['params']
        self.in_flight=op if type(op) is str and re.fullmatch('[a-z-]{1,32}',op) else '<invalid-op>'
        if op=='original':
            need(not rights and set(p)=={'pin'},'one exact original pin and no request rights')
            self.owner.union.check();name,entry=self.original(p['pin'])
            need(name not in self.borrowed,'original descriptor already borrowed')
            self.borrowed.add(name);self.owner.union.check()
            return {'pin':dict(entry['pin']),'identity':list(entry['identity']),'guardian_pid':os.getpid(),
                    'guardian_full_SHA_admitted':True},[entry['fd']]
        if op=='original-check':
            need(not rights and set(p)=={'pins'} and type(p['pins']) is list and 0<len(p['pins'])<=128,'bounded exact borrowed-original checkpoint')
            self.owner.union.check();seen=set()
            for item in p['pins']:
                name,_=self.original(item);need(name in self.borrowed and name not in seen,'only unique previously borrowed originals');seen.add(name)
            self.owner.union.check();return True,[]
        if op=='frozen':
            need(not rights and set(p)=={'path','relative'} and p['relative'] in self.sources,'only approved frozen source')
            source=self.sources[p['relative']];target=self.output/'runtime-source'/p['relative']
            need(str(target)==p['path'] and p['relative'] not in self.frozen,'fresh exact frozen path')
            item={**source,'path':str(target)};entry=self.owner.union.add(item);os.fsync(entry['fd']);self.frozen.add(p['relative'])
            return {'bytes':item['bytes'],'sha256':item['sha256']},[entry['fd']]
        if op=='spawn':
            need(set(self.sources)-{'shizukudos/supervisor/native_win98/task_custody.py','shizukudos/supervisor/native_win98/custody_rpc.py','shizukudos/supervisor/native_win98/disk_lineage.py',NATIVE_EPOCH_SOURCE,GOP_NONCE_SOURCE,GOP_CONSTRUCTOR_SOURCE}<=self.frozen,'all executed snapshots must be admitted before launch')
            return self.owner.spawn(p,rights),[]
        if op=='epoch-monitor':
            need(not p and not rights and hasattr(self.owner,'epoch_context'),'internal current epoch context required')
            return self.owner.open_epoch_monitor()
        if op=='epoch-peer-facts':
            need(not p and not rights and hasattr(self.owner,'epoch_context'),'original guardian epoch peer query required')
            return self.owner.epoch_peer_facts()
        if op=='epoch-monitor-call':
            need(not rights and hasattr(self.owner,'epoch_context'),'original guardian epoch monitor required')
            return self.owner.epoch_monitor_call(p)
        if op=='qmp':
            need(not p and len(rights)==1,'one exact QMP descriptor');fd=rights.pop();return self.owner.admit_qmp(fd),[]
        need(not rights,'unexpected descriptor rights')
        if op=='live-check':
            need(not p,'empty live owner check')
            self.owner.assert_owned();need(self.owner.qmp is not None,'guardian-admitted QMP required')
            peer=struct.unpack('3i',self.owner.qmp.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            need(peer[:2]==(self.owner.process.pid,os.getuid()),'current held QMP peer differs')
            self.owner.assert_owned();return True,[]
        if op=='poll':need(not p,'empty poll request');return self.owner.poll(),[]
        if op=='wait':need(set(p)=={'seconds'},'exact wait request');return self.owner.wait(p['seconds']),[]
        if op=='signal':need(set(p)=={'signal'},'exact signal request');self.owner.signal(p['signal']);return True,[]
        if op=='status':need(not p,'empty status request');return dict(self.owner.record),[]
        raise ValueError('unknown task-only custody operation')
    def once(self,timeout=.1):
        row,rights=self.channel.receive(timeout)
        try:
            result,returned=self.dispatch(row,rights)
            self.channel.send({'id':row['id'],'ok':True,'result':result},returned)
            self.in_flight=None
        finally:
            for fd in rights:os.close(fd)

def admitted_module(name,row,union):
    # prepare_vm imports build.py: its nested loader is also descriptor-backed.
    loader=object.__new__(rpc.Client)
    loader.frozen_fds={path:(entry['fd'],os.pread(entry['fd'],entry['pin']['bytes'],0))
                       for path,entry in union.rows.items() if path.endswith('.py') and entry['pin']['bytes']<=1<<20}
    path=pin(row,1<<20);entry=union.rows.get(str(path))
    need(entry is not None and entry['pin']==row,'module source must already be admitted under its exact pin')
    union.check();held=loader.frozen_fds.get(str(path))
    need(held is not None,'held Python source required')
    raw=held[1];sha=hashlib.sha256(raw).hexdigest()
    need(len(raw)==row['bytes'] and sha==row['sha256'],'actual executed module source bytes differ')
    module=loader.load(name,path);union.check()
    module.__executed_sha256__=sha
    return module

def configure_native_reaper(owner,sources,union,*,epoch_context=None):
    """Load the declared guardian-only source before its one gated launch."""
    need(type(owner) is Owner and owner.union is union and not owner.attempted and owner.process is None and
         getattr(owner,'_configured_native_reaper',None) is None,'fresh guardian native reaper configuration required')
    need(type(sources) is dict and sources==owner.record.get('runtime_source_pins'),'native configuration must use declared runtime sources')
    if NATIVE_EPOCH_SOURCE not in sources:return None
    row=sources[NATIVE_EPOCH_SOURCE]
    if epoch_context is None:module=admitted_module('admitted_native_epoch',row,union)
    else:
        module=epoch_context['module']
        need(getattr(module,'__executed_sha256__',None)==row['sha256'] and module.__file__==row['path'] and
             type(epoch_context['attempt']) is module.Attempt,'original retained epoch source/Attempt required')
        epoch_context['attempt'].check()
    owner._configured_native_reaper=(module,dict(row))
    return None

def admit_optional_native_inputs(manifest,built,union,builder):
    """Hold only explicitly declared optional originals, never infer PCI authority."""
    sizes={'VGACFG.BIN':136,'VGAROM.BIN':65536,'W98PERS.BIN':192,'W98INPT.BIN':96}
    maps={}
    for field in ('optional_native_inputs','optional_native_provenance'):
        declared=manifest.get(field,{});actual=built.get(field,{})
        need(type(declared) is dict and type(actual) is dict and declared==actual,'optional manifest/builder original pin map differs')
        need((field not in manifest or bool(declared)) and (field not in built or bool(actual)),'present optional map must be nonempty')
        maps[field]=declared
    blobs=maps['optional_native_inputs'];provenance=maps['optional_native_provenance']
    builder.optional_native_names(blobs,provenance)
    members=built.get('members',{})
    need(type(members) is dict,'exact optional member map')
    descriptors={};provenance_descriptors={}
    for name,row in blobs.items():
        pin(row,sizes[name]);need(row['bytes']==sizes[name],'exact separate optional ABI extent')
        member=members.get('SHZDOS/'+name)
        need(type(member) is dict and set(member)=={'bytes','sha256'} and
             type(member['bytes']) is int and member['bytes']==row['bytes'] and member['sha256']==row['sha256'],'optional original/ESP member crosslink differs')
        descriptors[name]=union.add(row)['fd']
    need({name for name in sizes if 'SHZDOS/'+name in members}==set(blobs),'undeclared optional ESP member')
    for name,row in provenance.items():
        pin(row,builder.VGA_RECEIPT_MAX)
        need('SHZDOS/'+name not in members,'provenance receipt must not be an ESP member')
        provenance_descriptors[name]=union.add(row)['fd']
    union.check();builder.validate_optional_native(descriptors,provenance_descriptors);union.check()

def admit_runtime_sources(repo,sources,union):
    # Retain the complete original closure and its positional bootstrap roles.
    # Declaring the native module admits bytes only, never a device grant.
    need(isinstance(repo,Path) and repo.is_absolute() and repo.resolve()==repo,'canonical source root')
    legacy=set(SOURCES)
    need(type(sources) is dict and legacy<=set(sources)<=legacy|{NATIVE_EPOCH_SOURCE,PCI_PREPARATION_SOURCE,GOP_NONCE_SOURCE,GOP_CONSTRUCTOR_SOURCE},'exact legacy or native runtime source closure')
    need((GOP_NONCE_SOURCE in sources)==(GOP_CONSTRUCTOR_SOURCE in sources),'paired original GOP staging/constructor sources required')
    if GOP_NONCE_SOURCE in sources:need(NATIVE_EPOCH_SOURCE in sources,'GOP staging requires original epoch source')
    for relative,row in sources.items():need(pin(row,1<<20)==repo/relative,'approved source path differs');union.add(row)
    need(globals().get('__executed_sha256__')==sources[SOURCES[-2]]['sha256'] and getattr(rpc,'__executed_sha256__',None)==sources[SOURCES[-3]]['sha256'],'guardian and RPC must execute independently pinned held bytes')
    return sources


def admit_pci_preparation(manifest,plan,sources,union):
    """Optional original selection stays prospective and under guardian custody."""
    need(('pci_preparation' in manifest)==(PCI_PREPARATION_SOURCE in sources),
         'PCI selection and retained adapter source must be declared together')
    if 'pci_preparation' not in manifest:return None
    adapter=admitted_module('admitted_pci_preparation',sources[PCI_PREPARATION_SOURCE],union)
    result=adapter.admit_selection(manifest['pci_preparation'],plan,union.raw)
    union.check();return result


def check_original_observation(profile,proof,producers,union,epoch_context=None):
    """Re-derive the phase observations from the guardian's held disk FD.

    Both the observer and FAT reader execute their independently pinned held
    source bytes. These observations authenticate the metadata-to-disk link,
    not Windows licensing, product version, boot or a Shizuku service result.
    """
    observer=admitted_module('admitted_original_observer',producers[0],union)
    constructor=admitted_module('admitted_original_fat',producers[1],union)
    need(callable(getattr(observer,'observe',None)),'source-admitted original observer required')
    entry=union.add(proof['source_disk']);union.check()
    # Per-read guard: latch + exact disk FD/path/lease every FAT read, complete
    # namespace sweep on schedule (perf-b9: was a full O(rows) sweep twice per
    # cluster, the measured admission stall). Complete sweeps bracket the call.
    started=time.monotonic();progress('original-observation',0,proof['source_disk']['bytes'],started)
    stream_check=union.stream_guard(entry)
    if epoch_context is not None:
        attempt=epoch_context['attempt'];outer_guard=epoch_context['guard']
        immutable_deadline=attempt.original_deadline_ns;next_outer=[0.0]
        def observation_check():
            stream_check()
            need(attempt.original_deadline_ns==immutable_deadline,'original observation deadline changed')
            attempt.check()
            now=time.monotonic()
            if now>=next_outer[0]:
                outer_guard();next_outer[0]=now+SWEEP_SECONDS
        observation_check()
    else:
        observation_check=stream_check
    observed=observer.observe(entry['fd'],proof['source_disk']['bytes'],
                              proof['observed_windows_path'][3:],constructor,observation_check)
    observation_check()
    union.check();progress('original-observation-done',proof['source_disk']['bytes'],proof['source_disk']['bytes'],started)
    fields={'observed_windows_path','observed_members','boot_sectors'}
    need(type(observed) is dict and set(observed)==fields and
         observed=={name:profile[name] for name in fields},
         'original phase observations differ from actual held disk bytes')


def _local_pin(path):
    """Hash one fresh local producer output; union.add re-admits it under lease."""
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and 0<st.st_size<=16<<30,'regular bounded producer output')
        return {'path':str(Path(path)),'bytes':st.st_size,'sha256':full_hash(fd,st.st_size)}
    finally:os.close(fd)


def prepare_original_intent(intent,union,sources,guard):
    """Original-observation device epoch: real retained Attempt, no DOS3 cohort.

    The selected original disk is only read; the native builder copies it into
    the fresh ESP, which becomes the trial's mutable target. The live Attempt
    carries the source-built StdVGA config/ROM and optional persistence config
    through the existing COM2/fw_cfg HostGrant. Nothing here stages a guest
    nonce, registers a GOP driver, or grants DOS replacement/release status.
    Returns internal live objects only, never a resumable receipt.
    """
    expected={'schema','repo','sources','limits','timeout','lineage','producers','native_inputs',
              'optional_native_inputs','optional_native_provenance','raw_bars','firmware','private_root','assembly_scratch'}
    need(type(intent) is dict and expected<=set(intent)<=expected|{'input_recipe','owned_input'} and intent['schema']==ORIGINAL_EPOCH_INTENT_SCHEMA,
         'exact private original-observation device epoch intent required')
    need(type(intent['timeout']) is int and 20<=intent['timeout']<=900,'original bounded observation/preparation budget')
    need(NATIVE_EPOCH_SOURCE in sources and GOP_NONCE_SOURCE not in sources and GOP_CONSTRUCTOR_SOURCE not in sources,
         'original phase holds the epoch source and no DOS3 GOP staging producers')
    need(type(intent['lineage']) is list and len(intent['lineage'])==1 and type(intent['producers']) is list and len(intent['producers'])==2,
         'exact one original observation profile and two producer pins')
    need(type(intent['native_inputs']) is dict and set(intent['native_inputs'])=={'DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG'},
         'six original native builder inputs')
    optional=intent['optional_native_inputs']
    need(type(optional) is dict and {'VGACFG.BIN','VGAROM.BIN'}<=set(optional)<={'VGACFG.BIN','VGAROM.BIN','W98PERS.BIN'},
         'source-built StdVGA pair required; persistence optional')
    need(type(intent['optional_native_provenance']) is dict and set(intent['optional_native_provenance'])=={'vga-build-receipt'},
         'exact separately pinned source-bound VGA producer required')
    need(type(intent['firmware']) is dict and set(intent['firmware'])=={'firmware_code','firmware_vars','qemu'},'exact firmware/executable input pins')
    input_flags=owned_input_flags(intent['owned_input']) if 'owned_input' in intent else 0
    roles={'1'}|({'2'} if 'W98PERS.BIN' in optional else set())
    need(type(intent['raw_bars']) is dict and set(intent['raw_bars'])==roles and
         all(type(words) is list and len(words)==6 and all(type(word) is int and 0<=word<1<<32 for word in words)
             for words in intent['raw_bars'].values()),'literal six raw BAR words for exactly the selected roles')
    need(intent['assembly_scratch'] is None or type(intent['assembly_scratch']) is str,'optional explicit private assembly path required')
    root=Path(intent['private_root']);st=os.lstat(root)
    need(root.is_absolute() and root.resolve()==root and stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and st.st_mode&0o777==0o700,
         'existing owned mode0700 private preparation root required')
    names={'native':root/'native','vm':root/'vm','input':root/'input'}
    need(not any(os.path.lexists(p) for p in (*names.values(),root/'generated-custody-manifest.json')),'fresh one-shot preparation outputs required')
    originals=[*intent['lineage'],*intent['producers'],*intent['native_inputs'].values(),*optional.values(),
               *intent['optional_native_provenance'].values(),*intent['firmware'].values()]
    for row in originals:pin(row,16<<30);union.add(row)
    if 'input_recipe' in intent:pin(intent['input_recipe'],INPUT_RECIPE_MAX);union.add(intent['input_recipe'])
    guard()
    # Same selected bytes as the held observation profile; the full observer
    # re-derivation runs again inside admit_manifest on the generated plan.
    profile=union.json(intent['lineage'][0],4<<20)
    need(type(profile) is dict and profile.get('source_disk')==intent['native_inputs']['DISK.IMG'],
         'builder disk must be the exact observed original source disk')
    epoch=admitted_module('original_epoch_live_policy',sources[NATIVE_EPOCH_SOURCE],union)
    native_builder=admitted_module('original_epoch_native_builder',sources[HELPERS[0]],union)
    preparer=admitted_module('original_epoch_vm_preparer',sources[HELPERS[1]],union)
    for path in native_builder.source_files():union.add(_local_pin(path))
    deadline_ns=int((time.monotonic()+2*intent['timeout']+16)*1e9)
    for _ in range(16):
        if int((deadline_ns/1e9)*1e9)==deadline_ns:break
        deadline_ns-=1
    need(int((deadline_ns/1e9)*1e9)==deadline_ns,'exact original QMP deadline representation required')
    bars={int(role):tuple(words) for role,words in intent['raw_bars'].items()}
    def borrowed(name):
        if name not in optional:return None
        row=optional[name];return epoch.PinnedFD(union.rows[row['path']]['fd'],row)
    attempt=epoch.Attempt(borrowed('VGACFG.BIN'),borrowed('VGAROM.BIN'),borrowed('W98PERS.BIN'),bars,deadline_ns,input_flags=input_flags)
    listener=None;built_optional=dict(optional)
    try:
        preparation_stop=time.monotonic()+intent['timeout']
        # The one pre-exec clone is the builder's ESP copy of the original disk.
        claim=attempt.reserve_staging()
        def check():
            guard();union.check();attempt.check()
            need(attempt.staging_claim is claim and attempt.owner is None and not attempt.consumed,'same prospective pre-exec Attempt must remain held')
            need(time.monotonic()<preparation_stop,'original preparation phase budget consumed')
        flags={'DISK.IMG':'disk','SEABIOS.BIN':'rom','WIN98CFG.BIN':'config','KERNEL32.BIN':'kernel32',
               'KERNEL64.BIN':'kernel64','WIN64.IMG':'win64-img','VGACFG.BIN':'vga-config','VGAROM.BIN':'vga-rom',
               'W98PERS.BIN':'persistence-config','W98INPT.BIN':'input-policy','vga-build-receipt':'vga-build-receipt'}
        if input_flags:
            # W98INPT.BIN comes only from THIS live reserved Attempt (nonce +
            # VGA config SHA sealed in its policy memfd), written once into a
            # fresh owned file and then held under the same full-SHA read lease.
            raw=attempt.input_policy();check()
            os.mkdir(names['input'],0o700);target=names['input']/'W98INPT.BIN'
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
            try:
                need(os.write(fd,raw)==len(raw)==96,'complete owned input policy write');os.fsync(fd)
            finally:os.close(fd)
            row=_local_pin(target);need(row['bytes']==96 and row['sha256']==hashlib.sha256(raw).hexdigest(),'generated input policy readback differs')
            union.add(row);need(union.raw(row,96)==raw,'held input policy bytes differ');built_optional['W98INPT.BIN']=row
        args=['--out',str(names['native'])]
        for name,row in {**intent['native_inputs'],**built_optional,**intent['optional_native_provenance']}.items():
            args+=['--'+flags[name],row['path'],'--'+flags[name]+'-sha256',row['sha256']]
        if intent['assembly_scratch'] is not None:args+=['--assembly-scratch',intent['assembly_scratch']]
        returned=[];check();native_builder.main(args,receipt_sink=returned.append);check()
        result_pin=_local_pin(names['native']/'result.json');union.add(result_pin);built=union.json(result_pin)
        need(returned==[union.raw(result_pin,16<<20)] and built.get('VM_executed') is False and
             built.get('input_pins',{}).get('DISK.IMG')==intent['native_inputs']['DISK.IMG'],
             'actual native builder return must equal leased output over the observed original disk')
        need(not input_flags or (built.get('optional_native_inputs')==built_optional and
                                 union.raw(built_optional['W98INPT.BIN'],96)==attempt.input_policy()),
             'builder optional map/held input policy must equal the live Attempt selection')
        esp={'path':str(names['native']/built['artifact']['path']),'bytes':built['artifact']['bytes'],'sha256':built['artifact']['sha256']}
        union.add(esp)
        binding={'policy_fd':attempt.policy_fd,'listener_path':str(names['vm']/'epoch.sock')}
        if 'W98PERS.BIN' in optional:binding['modern_persistence_low32']=True
        args=['--out',str(names['vm'])]
        for name,row in {'esp':esp,'build-receipt':result_pin,**{k.replace('_','-'):v for k,v in intent['firmware'].items()}}.items():
            args+=['--'+name,row['path'],'--'+name+'-sha256',row['sha256']]
        returned=[];check();preparer.main(args,receipt_sink=returned.append,epoch_binding=binding);check()
        plan_pin=_local_pin(names['vm']/'vm-plan.json');union.add(plan_pin);plan=union.json(plan_pin)
        need(returned==[union.raw(plan_pin,16<<20)] and plan.get('prospective_native_epoch_recipe')==binding,
             'actual fresh VM preparation return differs from same live policy recipe')
        listener=epoch.PrivateListener(names['vm']/'epoch.sock')
        policy={'policy_sha256':hashlib.sha256(attempt.policy).hexdigest(),'nonce_sha256':hashlib.sha256(attempt.nonce).hexdigest(),
                'original_host_deadline_ns':attempt.original_deadline_ns}
        manifest={'schema':ORIGINAL_MANIFEST_SCHEMA,'repo':intent['repo'],'sources':sources,'limits':intent['limits'],
                  'timeout':intent['timeout'],'plan':plan_pin,'lineage':intent['lineage'],'producers':intent['producers'],
                  'optional_native_inputs':built_optional,'optional_native_provenance':intent['optional_native_provenance'],
                  # Intent raw_bars keep JSON string keys; the declared roles are
                  # the same integer roles the live Attempt/admission compare.
                  'original_device_epoch':{'live_policy':policy,'selected_roles':sorted(int(role) for role in roles),
                                           **{name:False for name in ORIGINAL_EPOCH_FALSE}}}
        if 'input_recipe' in intent:manifest['input_recipe']=intent['input_recipe']
        if input_flags:manifest['owned_input']=dict(intent['owned_input'])
        check();persist(root/'generated-custody-manifest.json',manifest)
        return manifest,{'module':epoch,'attempt':attempt,'listener':listener,'recipe_binding':binding,
                         'live_policy':policy,'guard':guard,'phase':ORIGINAL_MANIFEST_SCHEMA}
    except BaseException:
        try:
            if listener is not None:listener.close()
        finally:attempt.close()
        raise


def admit_original_epoch(manifest,sources,epoch_context):
    """Bind the original manifest to the same in-process live Attempt."""
    declared=manifest['original_device_epoch']
    need(type(epoch_context) is dict and epoch_context.get('phase')==ORIGINAL_MANIFEST_SCHEMA,
         'original-observation live Attempt required; DOS3 GOP contexts are refused')
    need(NATIVE_EPOCH_SOURCE in sources and GOP_NONCE_SOURCE not in sources and GOP_CONSTRUCTOR_SOURCE not in sources,
         'held epoch source without DOS3 GOP staging producers required')
    epoch_context['guard']();attempt=epoch_context['attempt']
    need(type(attempt) is getattr(epoch_context['module'],'Attempt',None) and attempt.staging_claim is not None and
         attempt.owner is None and not attempt.consumed,'retained unbound pre-exec original Attempt required')
    attempt.check()
    actual={'policy_sha256':hashlib.sha256(attempt.policy).hexdigest(),'nonce_sha256':hashlib.sha256(attempt.nonce).hexdigest(),
            'original_host_deadline_ns':attempt.original_deadline_ns}
    optional=manifest.get('optional_native_inputs',{})
    roles=sorted({1}|({2} if 'W98PERS.BIN' in optional else set()))
    need(type(declared) is dict and set(declared)=={'live_policy','selected_roles',*ORIGINAL_EPOCH_FALSE} and
         declared['live_policy']==actual==epoch_context['live_policy'] and declared['selected_roles']==roles and
         all(declared[name] is False for name in ORIGINAL_EPOCH_FALSE),'same original owner live policy and false grants required')
    need({'VGACFG.BIN','VGAROM.BIN'}<=set(optional) and
         [source.pin for source in attempt.sources]==[optional[name] for name in ('VGACFG.BIN','VGAROM.BIN','W98PERS.BIN') if name in optional] and
         sorted(d.role for d in attempt.expected.devices)==roles,'live Attempt must hold exactly the declared VGA/persistence pins')
    flags=owned_input_flags(manifest['owned_input']) if 'owned_input' in manifest else 0
    need(attempt.expected.input_flags==flags and ('W98INPT.BIN' in optional)==bool(flags),
         'declared owned input option must equal the live Attempt policy option')
    if flags:
        raw=attempt.expected.input_policy(attempt.nonce);row=optional['W98INPT.BIN']
        need(attempt.policy[216:248]==hashlib.sha256(raw).digest() and row['bytes']==96 and
             row['sha256']==hashlib.sha256(raw).hexdigest(),'W98INPT.BIN must be the current Attempt nonce/VGA/policy-sealed bytes')


def admit_manifest(manifest,union,*,epoch_context=None):
    fields={'schema','plan','repo','sources','lineage','producers','limits','timeout'}
    need(type(manifest) is dict and fields<=set(manifest) and
         set(manifest)<=fields|{'preparation_receipt','optional_native_inputs','optional_native_provenance','pci_preparation','gop_cohort','original_device_epoch','input_recipe','owned_input'} and
         manifest['schema'] in ('shizukuos.native-custody-manifest.v1',ORIGINAL_MANIFEST_SCHEMA),'exact task manifest')
    original_phase=manifest['schema']==ORIGINAL_MANIFEST_SCHEMA
    if original_phase:
        # A distinct original-observation device epoch, never the DOS3 cohort.
        need('gop_cohort' not in manifest and ('original_device_epoch' in manifest)==(epoch_context is not None),
             'original observation phase has no DOS-replacement GOP cohort; live epoch only via its own Attempt')
    else:
        need('original_device_epoch' not in manifest and (epoch_context is None or 'phase' not in epoch_context),
             'DOS3 replacement manifests cannot carry an original-observation epoch')
    need(type(manifest['timeout']) is int and 20<=manifest['timeout']<=900,'existing observation timeout')
    repo=Path(manifest['repo']);need(repo.is_absolute() and repo.resolve()==repo,'canonical source root')
    sources=admit_runtime_sources(repo,manifest['sources'],union)
    need(('owned_input' in manifest)==('W98INPT.BIN' in manifest.get('optional_native_inputs',{})) and
         ('owned_input' not in manifest or (original_phase and epoch_context is not None)),
         'owned input option only with its W98INPT.BIN and the live original-phase Attempt')
    if 'input_recipe' in manifest:
        need(original_phase,'scripted input recipe only in the original-userland phase')
        pin(manifest['input_recipe'],INPUT_RECIPE_MAX);need(union.add(manifest['input_recipe'])['full_SHA_admitted'] is True,'held full-SHA input recipe lease')
    plan=union.json(manifest['plan']);out=Path(manifest['plan']['path']).parent
    need(plan.get('status')=='PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN' and plan.get('private') is True and plan.get('VM_executed') is False and plan.get('source_bound_ESP') is True and plan.get('originals_before_after_match') is True,'fresh private unexecuted plan')
    need(set(plan['input_pins'])=={'esp','build_receipt','firmware_code','firmware_vars','qemu'},'five original preparation inputs')
    for item in plan['input_pins'].values():union.add(item)
    built=union.json(plan['input_pins']['build_receipt']);need(built.get('status')=='PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN' and built.get('VM_executed') is False and built.get('source_before_after_match') is True and built.get('originals_before_after_match') is True,'source-bound private builder receipt')
    need(set(built['input_pins'])=={'DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG'},'six original builder inputs')
    for item in built['input_pins'].values():union.add(item)
    if (any(field in manifest or field in built for field in ('optional_native_inputs','optional_native_provenance')) or
        any('SHZDOS/'+name in built.get('members',{}) for name in ('VGACFG.BIN','VGAROM.BIN','W98PERS.BIN','W98INPT.BIN'))):
        builder=admitted_module('admitted_optional_builder',sources[HELPERS[0]],union)
        admit_optional_native_inputs(manifest,built,union,builder)
    need(built['artifact']['bytes']==plan['input_pins']['esp']['bytes'] and built['artifact']['sha256']==plan['input_pins']['esp']['sha256'],'prepared ESP/builder crosslink')
    need(type(built.get('sources_sha256')) is dict and 0<len(built['sources_sha256'])<=30000,'actual native builder source closure required')
    for relative,sha in built['sources_sha256'].items():
        need(type(relative) is str and not relative.startswith('/') and '..' not in Path(relative).parts,'bounded native source relative path')
        source=Path(plan['input_pins']['build_receipt']['path']).parent/'source'/relative
        union.add({'path':str(source),'bytes':source.stat().st_size,'sha256':sha})
    header='shizukudos/supervisor/include/shz_info.h';headerpath=Path(plan['input_pins']['build_receipt']['path']).parent/'source'/header
    headerrow={'path':str(headerpath),'bytes':headerpath.stat().st_size,'sha256':built['sources_sha256'][header]};union.add(headerrow);sources=dict(sources);sources[header]=headerrow
    lineage=manifest['lineage']
    need(type(lineage) is list and len(lineage)==(1 if original_phase else 3),
         'explicit original observation pin required' if original_phase else 'explicit ordered DOS3 lineage pins')
    producers=manifest['producers'];need(type(producers) is list and len(producers)==2,'explicit two producer pins')
    for row in producers:union.add(row)
    parser=admitted_module('admitted_disk_lineage',manifest['sources'][SOURCES[-1]],union)
    raw=[union.raw(row,maximum) for row,maximum in zip(lineage,((4<<20,) if original_phase else (1<<20,4<<20,16<<20)))]
    cohort=None
    if original_phase and epoch_context is not None:admit_original_epoch(manifest,sources,epoch_context)
    need(original_phase or ('gop_cohort' in manifest)==(epoch_context is not None),'GOP cohort requires internal retained live Attempt')
    if epoch_context is not None and not original_phase:
        need(GOP_NONCE_SOURCE in sources and GOP_CONSTRUCTOR_SOURCE in sources,'held GOP production source closure required')
        epoch_context['guard']();attempt=epoch_context['attempt'];attempt.check()
        actual={'policy_sha256':hashlib.sha256(attempt.policy).hexdigest(),
                'nonce_sha256':hashlib.sha256(attempt.nonce).hexdigest(),
                'original_host_deadline_ns':attempt.original_deadline_ns}
        declared=manifest['gop_cohort']
        need(type(declared) is dict and set(declared)=={'record_pins','producer_pins','live_policy'} and
             declared['live_policy']==actual==epoch_context['live_policy'],'same original owner live policy required')
        need(type(declared['record_pins']) is dict and set(declared['record_pins'])==parser.COHORT_RECORDS,'exact7 original cohort records required')
        need(type(declared['producer_pins']) is dict and set(declared['producer_pins'])=={'gop_stage','caller_stage','nonce_stage'},'exact3 producer closures required')
        for closure in declared['producer_pins'].values():
            need(type(closure) is list,'explicit original producer closure required')
            for row in closure:union.add(row)
        need(declared['producer_pins']['nonce_stage']==[sources[GOP_NONCE_SOURCE],sources[NATIVE_EPOCH_SOURCE],sources[GOP_CONSTRUCTOR_SOURCE]],'current retained nonce staging producer differs')
        cohort={'records':{name:{'raw':union.raw(row,4<<20),'pin':row} for name,row in declared['record_pins'].items()},
                'producer_pins':declared['producer_pins'],'live_policy':actual}
    if original_phase:
        profile=union.json(lineage[0],4<<20)
        need(type(profile.get('request')) is dict,'explicit held original-phase request required')
        request_raw=union.raw(profile['request'],1<<20)
        proof=parser.admit_original(raw,lineage,built['input_pins']['DISK.IMG'],producers,request_raw=request_raw)
        check_original_observation(profile,proof,producers,union,epoch_context)
    else:
        proof=(parser.admit(raw,lineage,built['input_pins']['DISK.IMG'],producers) if cohort is None else
               parser.admit(raw,lineage,built['input_pins']['DISK.IMG'],producers,gop_cohort=cohort))
        profile=union.json(lineage[0],1<<20);prepared=union.json(lineage[2])
        union.add(profile['disk']);union.add(profile['boot_template']['file']);union.add(profile['build_receipt'])
        for item in profile['payloads']:union.add(item['file'])
        need(type(prepared.get('build_source_pins')) is list and 0<len(prepared['build_source_pins'])<=30000,'actual retained DOS source closure required')
        for row in prepared['build_source_pins']:union.add(row)
    helpers={name:sources[name]['sha256'] for name in HELPERS}
    if 'preparation_runtime_helpers_sha256' in plan:need(plan['preparation_runtime_helpers_sha256']==helpers,'preparation helper epoch differs')
    if 'preparation_receipt' in manifest:
        outer=union.json(manifest['preparation_receipt'])
        need(outer.get('schema')=='shizukuos.actual-native-vm-preparation.v1' and outer.get('status')=='ACTUAL_FRESH_PRIVATE_VM_INPUTS_PREPARED_FROM_SELECTED_ESP_NOT_RUN','actual selected-ESP preparation outer receipt required')
        need(outer.get('vm_plan_derived_from_actual_return')==manifest['plan'] and outer.get('actual_prepare_return_snapshot')==plan and outer.get('preparation_runtime_helpers_sha256')==helpers,'actual return/plan/helper crosslinks differ')
        need(outer.get('source_execution_sha256')=={'prepare_vm.py':helpers[HELPERS[1]],'build.py':helpers[HELPERS[0]]},'actual executed preparer/build source identities differ')
        need(outer.get('selected_native_esp_builder_receipt_pin')==plan['input_pins']['build_receipt'] and outer.get('six_original_builder_input_pins')==built['input_pins'],'actual ESP/builder/six-original crosslinks differ')
        need(all(outer.get(name) is True for name in ('source_original_metadata_read_leases_held_through_actual_return','canonical_vm_plan_exact_return_bytes_readback_verified')),'actual preparation lease/readback facts required')
        need(all(outer.get(name) is False for name in ('VM_executed','Windows98_boot_verified','MSDOS_replacement_under_Windows98','native_apps_verified','persistence_verified','SMP_acceptance','ISO_built','public_artifact')),'preparation never proves runtime/publication')
        for name in ('selected_native_esp_result_pin','selected_native_esp_terminal_pin','frozen_header_pin'):union.add(outer[name])
        need(outer['frozen_header_pin']['bytes']==headerrow['bytes'] and outer['frozen_header_pin']['sha256']==headerrow['sha256'],'actual frozen layout header differs')
    helper_identity=hashlib.sha256(json.dumps(helpers,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    prep=admitted_module('admitted_preparation',sources[HELPERS[1]],union)
    binding=None if epoch_context is None else epoch_context['recipe_binding']
    need(plan.get('prospective_native_epoch_recipe')==binding,'same internal original policy/COM2 recipe required')
    argv=(prep.recipe(Path(plan['input_pins']['qemu']['path']),out) if binding is None else
          prep.recipe(Path(plan['input_pins']['qemu']['path']),out,epoch_binding=binding))
    need(argv==plan['qemu_argv'],'actual independently reconstructed recipe differs')
    admit_pci_preparation(manifest,plan,sources,union)
    # Sender descriptor numbers are symbolic placeholders until SCM transport.
    argv=list(argv);argv[argv.index('-serial')+1]='file:/proc/self/fd/0';argv+=['-debugcon','file:/proc/self/fd/1','-global','isa-debugcon.iobase=0xe9']
    return plan,built,sources,proof,argv,helper_identity

CONTROLLER_BOOTSTRAP="""import hashlib,os,sys,types
rpcfd,runfd=int(sys.argv[1]),int(sys.argv[2]);rpcpath,runpath=sys.argv[3],sys.argv[4];pins=sys.argv[5:7]
m=types.ModuleType('native_custody_rpc');m.__file__=rpcpath;raw=os.pread(rpcfd,1048577,0);assert hashlib.sha256(raw).hexdigest()==pins[0];m.__executed_sha256__=pins[0];exec(compile(raw,rpcpath,'exec'),m.__dict__);sys.modules[m.__name__]=m
raw=os.pread(runfd,1048577,0);assert hashlib.sha256(raw).hexdigest()==pins[1];os.close(rpcfd);os.close(runfd);sys.argv=[runpath,*sys.argv[7:]];exec(compile(raw,runpath,'exec'),{'__file__':runpath,'__name__':'__main__'})
"""

def persist(path,row):
    raw=(json.dumps(row,indent=2,allow_nan=False)+'\n').encode();need(len(raw)<=1<<20,'bounded custody receipt')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        at=0
        while at<len(raw):n=os.write(fd,raw[at:]);need(n>0,'short custody receipt write');at+=n
        os.fsync(fd)
    finally:os.close(fd)

    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)

FAILURE_DETAIL_BYTES=8192;FAILURE_TRACEBACK_BYTES=16384
GRANT_FAILURE_INTS=('failure_after_grant_bytes','grant_bytes_written','transport_calls')

def bounded_text(text,limit,tail=False):
    raw=str(text).encode('utf-8','backslashreplace');raw=raw[-limit:] if tail else raw[:limit]
    return raw.decode('utf-8','ignore')

def transport_failure_facts(diagnostics):
    """Bounded copy of native_epoch_host HostGrant.transport_failure.

    Nonce secrecy: READY/REPORT carry the attempt nonce at frame offset 16, so
    only the 16-byte frame header hex is kept and chunk-head hex is dropped.
    """
    if type(diagnostics) is not dict:return None
    out={}
    for key in ('schema','phase','direction','kind','error_class','message'):
        if type(diagnostics.get(key)) is str:out[key]=bounded_text(diagnostics[key],512)
    for key in ('frame_bytes_declared','frame_bytes_transferred','surplus_bytes','phase_stream_bytes','phase_io_calls','elapsed_ms','shared_transport_calls'):
        if type(diagnostics.get(key)) is int:out[key]=diagnostics[key]
    if type(diagnostics.get('segments_truncated')) is bool:out['segments_truncated']=diagnostics['segments_truncated']
    for key,limit in (('frame_head_hex',32),('surplus_head_hex',64)):
        if type(diagnostics.get(key)) is str and re.fullmatch('[0-9a-f]*',diagnostics[key]):out[key]=diagnostics[key][:limit]
    segments=diagnostics.get('segment_lengths')
    if type(segments) is list:out['segment_lengths']=[n for n in segments[:64] if type(n) is int]
    console=diagnostics.get('pre_ready_console')
    if type(console) is dict:
        out['pre_ready_console']={k:(console[k] if type(console[k]) is int else bounded_text(console[k],64)) for k in ('bytes','sha256','head_hex','tail_hex')
                                  if type(console.get(k)) is int or (type(console.get(k)) is str and re.fullmatch('[0-9a-f]*',console[k]))}
    return out

def grant_failure_facts(owner,error=None):
    """Scalar post-grant exchange facts only: no nonce, policy, report or frame body bytes."""
    context=getattr(owner,'epoch_context',None);grant=context.get('grant') if type(context) is dict else None
    facts={}
    if grant is not None:
        facts.update({name:getattr(grant,name) for name in GRANT_FAILURE_INTS if type(getattr(grant,name,None)) is int})
        if getattr(grant,'transport_failure',None) is not None:facts['transport_failure']=transport_failure_facts(grant.transport_failure)
    if 'transport_failure' not in facts and getattr(error,'transport_diagnostics',None) is not None:
        facts['transport_failure']=transport_failure_facts(error.transport_diagnostics)
    return facts or None

def record_actual_failure(owner,error,stage,server):
    """First actual failure, captured BEFORE recovery/kill/cleanup; never overwritten."""
    import traceback
    record=owner.record
    if 'error' in record:return
    record['error']=type(error).__name__
    record['error_detail']=bounded_text(error,FAILURE_DETAIL_BYTES)
    # Frames are kept even for a huge message: the full bounded message is error_detail.
    last='%s: %s\n'%(type(error).__name__,bounded_text(error,1024))
    frames=bounded_text(''.join(traceback.format_tb(error.__traceback__)),FAILURE_TRACEBACK_BYTES-len(last.encode())-64,tail=True)
    record['error_traceback']='Traceback (most recent call last):\n'+frames+last
    record['error_stage']={'stage':stage,'rpc_op_in_flight':getattr(server,'in_flight',None),'rpc_sequence':getattr(server,'sequence',None),
                           'target_launch_attempted':owner.attempted,'target_released':owner.target_released,'VM_executed':record.get('VM_executed') is True}
    try:
        facts=grant_failure_facts(owner,error)
        if facts is not None:record['epoch_exchange_failure']=facts
    except BaseException as nested:record['epoch_exchange_failure_unavailable']=type(nested).__name__
    try:print(json.dumps({'native_custody_actual_failure':record['error'],'detail':record['error_detail'],'stage':record['error_stage'],
                          'traceback':record['error_traceback']},ensure_ascii=True),file=sys.stderr,flush=True)
    except BaseException:pass

def finish_task(owner,controller,group,channel,out,failure):
    """After proven task quiescence, cleanup errors cannot skip failure receipt."""
    actual_reaped=owner.confirm_reaped();errors={}
    try:owner.release();owner.record['lease_integrity_verified']=True
    except BaseException as error:failure=failure or error;errors['leases']=type(error).__name__;owner.record['lease_integrity_verified']=False
    actions=[('cgroup',group.close),('channel',channel.close)]
    if controller is not None and controller.pidfd is not None:actions.insert(0,('controller_pidfd',lambda:os.close(controller.pidfd)))
    for name,action in actions:
        try:action()
        except BaseException as error:failure=failure or error;errors[name]=type(error).__name__
    owner.record['terminal_cleanup_errors']=errors
    if failure is not None and 'error' not in owner.record:owner.record['cleanup_only_failure']=type(failure).__name__
    owner.record['controller_exit_code']=controller.process.returncode if controller is not None and controller.reaped else None
    owner.record['controller_exit_status_verified']=bool(controller is not None and controller.reaped)
    # Reached only after recovery_tick proved owner, controller and cgroup quiescent.
    owner.record['controller_reaped']=bool(controller is not None and controller.reaped)
    owner.record['target_process_existed']=owner.process is not None
    owner.record['status']=('CUSTODY_RELEASED_AFTER_ACTUAL_REAP' if failure is None else 'FAILED_CUSTODY_RELEASED_AFTER_ACTUAL_REAP' if actual_reaped else 'FAILED_CUSTODY_RELEASED_AFTER_PROVEN_EXIT_UNKNOWN_STATUS')
    persist(out/'custody-result.json',owner.record);return failure

def resource_guard(parent,limits,group,capture,out,admission):
    """Actual remaining ancestor headroom, host/FS floors; no parent mutation."""
    import shutil
    current_mem=int((group.path/'memory.current').read_text()) if group else 0
    current_pids=int((group.path/'pids.current').read_text()) if group else 0
    pending_mem=max(0,limits['memory.max']-current_mem)+(64<<20)
    pending_pids=max(0,limits['pids.max']-current_pids)+2
    rows=[]
    for ancestor in (parent,*parent.parents):
        if not ancestor.is_relative_to('/sys/fs/cgroup'):break
        row={'path':str(ancestor)}
        for high in ('memory.high','memory.max','pids.max'):
            file=ancestor/high
            if not file.exists():row[high]=None;continue
            value=file.read_text().strip();usedfile=ancestor/('pids.current' if high=='pids.max' else 'memory.current')
            used=int(usedfile.read_text());row[high]={'limit':value,'current':used}
            needed=pending_pids if high=='pids.max' else pending_mem
            need(value=='max' or int(value)-used>=needed,'actual finite ancestor remaining headroom consumed')
        rows.append(row)
    need(capture.available_memory_bytes()>=(6<<30 if admission else 2<<30),'unchanged host memory admission/floor consumed')
    need(shutil.disk_usage(out).free>=(17<<30)+(capture.PREFLIGHT_BUDGET if admission else 0),'unchanged storage/capture reserve consumed')
    capture.capture_bytes(out);return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--manifest',type=Path,required=True);ap.add_argument('--manifest-sha256',required=True);ap.add_argument('--guardian-unit',required=True);args=ap.parse_args()
    stopped=[False]
    for number in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(number,lambda *_:stopped.__setitem__(0,True))
    os.umask(0o077);union=LeaseUnion();owner=None;controller=None;group=None;server=None;failure=None
    size=args.manifest.stat().st_size;manifest_pin={'path':str(args.manifest),'bytes':size,'sha256':args.manifest_sha256}
    check_bootstrap=globals().get('__bootstrap_check__');need(callable(check_bootstrap),'independent held-byte bootstrap required');check_bootstrap()
    manifest=union.json(manifest_pin,4<<20);epoch_context=None
    unit=subprocess.check_output(['systemctl','show',args.guardian_unit,'--property=MainPID,RuntimeMaxUSec,ActiveState,Delegate','--no-pager'],text=True,timeout=5)
    values=dict(line.split('=',1) for line in unit.splitlines());need(values.get('MainPID')==str(os.getpid()) and values.get('ActiveState')=='active' and values.get('RuntimeMaxUSec')=='infinity' and values.get('Delegate')=='yes','guardian must survive child timeout in actual delegated independent unit')
    limits=manifest.get('limits')
    need(type(limits) is dict and set(limits)=={'memory.high','memory.max','pids.max','cpu.max'} and
         all(type(limits[k]) is int and limits[k]>0 for k in ('memory.high','memory.max','pids.max')) and
         limits['memory.high']>=4<<30 and limits['memory.max']>=limits['memory.high'] and limits['pids.max']<=64 and
         type(limits['cpu.max']) is str and re.fullmatch('[0-9]+ [0-9]+',limits['cpu.max']) is not None,'explicit original native child caps required')
    parent=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
    try:
        sources=admit_runtime_sources(Path(manifest['repo']),manifest['sources'],union)
        capture=admitted_module('admitted_capture',sources['shizukudos/supervisor/native_win98/owned_capture.py'],union)
        if manifest.get('schema')=='shizukuos.native-custody-gop-intent.v1':
            need(GOP_NONCE_SOURCE in sources and GOP_CONSTRUCTOR_SOURCE in sources and NATIVE_EPOCH_SOURCE in sources,
                 'original source-admitted GOP preparation closure required')
            preparation_root=Path(manifest['private_root'])
            def preparation_guard():
                need(not stopped[0],'guardian cancellation requested')
                check_bootstrap();union.check();resource_guard(parent,limits,group,capture,preparation_root,
                    owner is None or owner.start is None)
            preparation_guard()
            producer=admitted_module('admitted_gop_nonce_production',sources[GOP_NONCE_SOURCE],union)
            manifest,epoch_context=producer.prepare_intent(types.SimpleNamespace(**{name:globals()[name] for name in
                ('admitted_module','persist','GOP_NONCE_SOURCE','GOP_CONSTRUCTOR_SOURCE','NATIVE_EPOCH_SOURCE','HELPERS')}),
                manifest,union,sources,preparation_guard)
        elif manifest.get('schema')==ORIGINAL_EPOCH_INTENT_SCHEMA:
            preparation_root=Path(manifest['private_root'])
            def preparation_guard():
                need(not stopped[0],'guardian cancellation requested')
                check_bootstrap();union.check();resource_guard(parent,limits,group,capture,preparation_root,
                    owner is None or owner.start is None)
            preparation_guard()
            manifest,epoch_context=prepare_original_intent(manifest,union,sources,preparation_guard)
        plan,built,sources,proof,argv,helper_identity=admit_manifest(manifest,union,epoch_context=epoch_context)
        out=Path(manifest['plan']['path']).parent
        need(not (out/'custody-result.json').exists() and not (out/'native-result.json').exists(),'fresh one-shot native task')
        resource_guard(parent,manifest['limits'],None,capture,out,True)
    except BaseException:
        try:
            if epoch_context is not None:
                try:epoch_context['listener'].close()
                finally:epoch_context['attempt'].close()
        finally:union.close()
        raise
    try:
        group=TaskGroup(parent,'custody-native',manifest['limits'])
        owner=Owner(union,group,argv,plan['input_pins']['qemu'],manifest['timeout']);owner.output=out;owner.record['disk_lineage']=proof
        if 'original_device_epoch' in manifest:owner.record['original_device_epoch_at_preparation']=manifest['original_device_epoch']
    except BaseException:
        try:
            if epoch_context is not None:
                try:epoch_context['listener'].close()
                finally:epoch_context['attempt'].close()
        finally:
            try:
                if group is not None:group.close()
            finally:union.close()
        raise
    owner.record.update(manifest_pin=manifest_pin,plan_pin=manifest['plan'],builder_receipt_pin=plan['input_pins']['build_receipt'],runtime_source_pins=manifest['sources'],task_caps=manifest['limits'],observation_seconds=manifest['timeout'],cleanup_budget_seconds=16,guardian_unit_observation=values,preparation_helper_binding_verified=('preparation_receipt' in manifest or 'preparation_runtime_helpers_sha256' in plan))
    group.owner_pid=os.getpid()
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);left.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);right.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
    rpcrow=sources['shizukudos/supervisor/native_win98/custody_rpc.py'];runrow=sources['shizukudos/supervisor/native_win98/run_vm.py'];rpcfd=union.rows[rpcrow['path']]['fd'];runfd=union.rows[runrow['path']]['fd']
    runtime_names=(*HELPERS,'shizukudos/supervisor/native_win98/run_vm.py','shizukudos/supervisor/native_win98/owned_capture.py','shizukudos/supervisor/include/shz_info.h')
    if 'pci_preparation' in manifest:runtime_names+= (PCI_PREPARATION_SOURCE,)
    runtime_pins=json.dumps({name:sources[name] for name in runtime_names},separators=(',',':'),allow_nan=False)
    need(len(runtime_pins.encode())<=rpc.MAX_PACKET,'bounded exact runtime original pin map')
    command=[sys.executable,'-B','-c',CONTROLLER_BOOTSTRAP,str(rpcfd),str(runfd),rpcrow['path'],runrow['path'],rpcrow['sha256'],runrow['sha256'],'--custody-fd',str(right.fileno()),'--repo',manifest['repo'],'--plan',manifest['plan']['path'],'--plan-sha256',manifest['plan']['sha256'],'--plan-bytes',str(manifest['plan']['bytes']),'--runtime-source-pins-json',runtime_pins,'--runtime-sources-sha256',helper_identity,'--timeout',str(manifest['timeout'])]
    if epoch_context is not None:command+=['--guardian-epoch']
    if 'pci_preparation' in manifest:
        selected=json.dumps(manifest['pci_preparation'],separators=(',',':'),allow_nan=False)
        need(len(selected.encode())<=rpc.MAX_PACKET,'bounded explicit PCI preparation selection')
        command+=['--pci-preparation-json',selected]
    controller_status=None;stage='controller-preparation'
    try:
        if 'input_recipe' in manifest:
            # Compile the held bytes with the admitted capture before spawn; the
            # controller re-reads them only through the borrowed guardian FD.
            recipe=manifest['input_recipe'];capture.InputScript(union.raw(recipe,INPUT_RECIPE_MAX),recipe['sha256']);union.check()
            command+=['--input-recipe',recipe['path'],'--input-recipe-sha256',recipe['sha256']];owner.record['input_recipe_pin']=dict(recipe)
        if 'owned_input' in manifest:
            # Selection evidence only: nothing here observed a guest key/mouse delivery.
            owner.record['owned_input']={'option':dict(manifest['owned_input']),'w98inpt':dict(manifest['optional_native_inputs']['W98INPT.BIN']),
                                         'status':'NOT_BOOTED_INPUT_OPTION_SELECTED','keyboard_delivery_verified':False,
                                         'mouse_delivery_verified':False,'win98_input_verified':False}
        configure_native_reaper(owner,manifest['sources'],union,epoch_context=epoch_context)
        if epoch_context is not None:
            owner.configure_epoch_context(epoch_context['attempt'],epoch_context['listener'],capture,epoch_context['guard'])
        need(not stopped[0],'guardian cancellation requested')
        stage='controller-spawn'
        controller=subprocess.Popen(command,stdin=subprocess.DEVNULL,pass_fds=(rpcfd,runfd,right.fileno()),preexec_fn=group.place_before_exec)
        controller_status=ParentWait(controller);controller_status.pidfd=os.pidfd_open(controller.pid,0);right.close()
        server=Server(rpc.Channel(left,controller.pid),owner,sources,out)
        preparation_stop=time.monotonic()+manifest["timeout"];finalization_stop=None
        owner.record['finalization_budget_seconds']=manifest['timeout']
        rpc_closed=False;stage='controller-observation'
        while controller_status.observe() is None:
            need(not stopped[0],'guardian cancellation requested')
            check_bootstrap();union.check();group.check();resource_guard(parent,manifest['limits'],group,capture,out,owner.start is None)
            finalization_stop=task_deadline(owner,preparation_stop,finalization_stop,manifest['timeout'],time.monotonic())
            if rpc_closed:
                time.sleep(.1)
                continue
            try:server.once(.1)
            except socket.timeout:continue
            except EOFError:
                # Interpreter teardown can close RPC before the parent wait
                # reports exit. EOF proves neither exit nor successful status;
                # retain every guard and the original deadline until that wait.
                rpc_closed=True
                owner.record['controller_rpc_EOF_observed']=True
        stage='controller-exit-admission'
        check_bootstrap();union.check();group.check();resource_guard(parent,manifest['limits'],group,capture,out,owner.start is None)
        need(not stopped[0],'guardian cancellation requested')
        # Check the already established phase stop; completion cannot start a
        # new finalization budget or bypass a guard while the last wait reaps.
        if time.monotonic()>task_stop(owner,preparation_stop,finalization_stop,manifest['timeout']):
            raise TimeoutError('original task observation/cleanup/finalization deadline consumed')
        need(controller_status.reaped and controller.returncode==0 and owner.confirm_reaped() and owner.record.get('QMP_peer_admitted') is True,'controller exit is not owned-child reap/QMP admission')
    except BaseException as error:
        failure=error;record_actual_failure(owner,error,stage,server)
    finally:
        try:right.close()
        except BaseException as error:failure=failure or error
        unresolved=False;recovery_stop=time.monotonic()+16
        if owner is not None:
            try:
                if not owner.safe_to_release():owner.recover()
            except BaseException as error:failure=failure or error;owner.record['recovery_observation_failed']=type(error).__name__
        while owner is not None:
            if recovery_tick(owner,controller_status,group,recovery_stop):break
            if not unresolved:
                try:persist(out/'custody-unresolved.json',{**owner.record,'status':'FAILED_CUSTODY_RETAINED_NOT_REAPED'})
                except BaseException:pass
                unresolved=True;failure=failure or RuntimeError('unresolved owned task retained')
            time.sleep(.1)
        if owner is not None:
            failure=finish_task(owner,controller_status,group,left,out,failure)
    return 0 if failure is None else 1

if __name__=='__main__':raise SystemExit(main())
