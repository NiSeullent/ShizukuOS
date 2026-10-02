#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Single private native task guardian; host proof never proves a guest boot."""
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
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

def identity(s):return s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns

def pin(row,maximum=8<<30):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact immutable file pin')
    p=Path(row['path']);need(p.is_absolute() and str(p)==row['path'] and p.resolve()==p and not any(q.is_symlink() for q in (p,*p.parents)),'canonical nonsymlink path')
    need(not any(p==base or base in p.parents for base in map(Path,('/dev','/proc','/sys'))),'nonvirtual source path')
    need(type(row['bytes']) is int and 0<row['bytes']<=maximum,'bounded literal extent')
    need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) and row['sha256']!='0'*64,'explicit nonzero SHA')
    return p

def full_hash(fd,size,check=lambda:None):
    digest=hashlib.sha256();at=0
    while at<size:
        check();block=os.pread(fd,min(1<<20,size-at),at);need(block,'short immutable input read');digest.update(block);at+=len(block)
    check();need(not os.pread(fd,1,size),'unexpected extent');return digest.hexdigest()

class LeaseUnion:
    """One guardian-only SIGIO latch, including subsequently frozen sources."""
    def __init__(self):
        self.rows={};self.broken=False;self.previous=signal.getsignal(signal.SIGIO);self.closed=False
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
            entry={'fd':fd,'pin':dict(row),'identity':identity(before),'full_SHA_admitted':False};self.rows[name]=entry
            need(full_hash(fd,row['bytes'],self.check)==row['sha256'],'full leased SHA mismatch')
            entry['full_SHA_admitted']=True;self.check();return entry
        except BaseException:
            self.rows.pop(name,None);os.close(fd);raise
    def check(self):
        need(not self.broken,'guardian lease break requested')
        ancestors=set()
        for path,row in self.rows.items():
            p=Path(path);ancestors.update((p,*p.parents))
            info=os.fstat(row['fd'])
            need(stat.S_ISREG(info.st_mode) and fcntl.fcntl(row['fd'],fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY and
                 fcntl.fcntl(row['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK and fcntl.fcntl(row['fd'],fcntl.F_GETOWN)==os.getpid() and
                 identity(info)==row['identity'] and identity(p.stat())==row['identity'],'guardian lease/path identity changed')
        # Deduplicate only within this checkpoint; never cache namespace checks.
        need(not any(p.is_symlink() for p in ancestors),'guardian original ancestor became a symlink')
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
            for row in self.rows.values():need(full_hash(row['fd'],row['pin']['bytes'],self.check)==row['pin']['sha256'],'late leased full SHA differs')
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
        self.record={'schema':'shizukuos.native-custody.v1',**FLAGS,'custody_admitted':False,'owned_child_reaped':False,'leases_released':False,'launch_attempted':False}
    def spawn(self,request,rights):
        need(not self.attempted and self.process is None,'exactly one launch attempt')
        self.attempted=True;self.record['launch_attempted']=True
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
        source=self.union.add(self.executable_pin);gate_read,gate_write=os.pipe()
        try:
            launch=[str(Path(sys.executable).resolve()),'-B','-c',GATE_CODE,str(gate_read),str(source['fd']),json.dumps(args)]
            self.process=subprocess.Popen(launch,cwd=self.output,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=rights[2],pass_fds=(rights[0],rights[1],gate_read,source['fd']),preexec_fn=self.group.place_before_exec)
            self.actual_args=args;self.record['owned_pid']=self.process.pid
            # Target exec remains gated even if pidfd allocation/ACK fails.
            self.pidfd=os.pidfd_open(self.process.pid,0)
            self.union.check();self.group.check()
            need(not self.exited(),'gated launcher exited before pidfd admission')
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
        return {'pid':self.process.pid,'argv':args}
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
    def observe(self):
        if self.process is None:return None
        if self.reaped:return self.process.returncode
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
    def confirm_reaped(self):return self.process is None or (self.reaped and self.process.returncode is not None and (self.exited() or not self.target_released))
    def safe_to_release(self):return self.confirm_reaped() or (getattr(self,'physically_dead',False) and self.exited())
    def signal(self,number):
        need(number in (signal.SIGTERM,signal.SIGKILL),'only bounded owned cleanup signals')
        if self.pidfd is None:
            need(self.process is None or not self.target_released,'released target missing pidfd; custody must remain held');return
        if not self.exited():signal.pidfd_send_signal(self.pidfd,number)
    def admit_qmp(self,fd):
        sock=None
        try:
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
            need(set(self.sources)-{'shizukudos/supervisor/native_win98/task_custody.py','shizukudos/supervisor/native_win98/custody_rpc.py','shizukudos/supervisor/native_win98/disk_lineage.py'}<=self.frozen,'all executed snapshots must be admitted before launch')
            return self.owner.spawn(p,rights),[]
        if op=='qmp':
            need(not p and len(rights)==1,'one exact QMP descriptor');fd=rights.pop();return self.owner.admit_qmp(fd),[]
        need(not rights,'unexpected descriptor rights')
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
        finally:
            for fd in rights:os.close(fd)

def admitted_module(name,row,union):
    # prepare_vm imports build.py: its nested loader is also descriptor-backed.
    loader=object.__new__(rpc.Client)
    loader.frozen_fds={path:(entry['fd'],os.pread(entry['fd'],entry['pin']['bytes'],0))
                       for path,entry in union.rows.items() if path.endswith('.py') and entry['pin']['bytes']<=1<<20}
    union.check();return loader.load(name,Path(row['path']))

def admit_optional_native_inputs(manifest,built,union,builder):
    """Hold only explicitly declared optional originals, never infer PCI authority."""
    sizes={'VGACFG.BIN':136,'VGAROM.BIN':65536,'W98PERS.BIN':192}
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

def admit_manifest(manifest,union):
    fields={'schema','plan','repo','sources','lineage','producers','limits','timeout'}
    need(type(manifest) is dict and fields<=set(manifest) and
         set(manifest)<=fields|{'preparation_receipt','optional_native_inputs','optional_native_provenance'} and
         manifest['schema']=='shizukuos.native-custody-manifest.v1','exact task manifest')
    need(type(manifest['timeout']) is int and 20<=manifest['timeout']<=900,'existing observation timeout')
    repo=Path(manifest['repo']);need(repo.is_absolute() and repo.resolve()==repo,'canonical source root')
    sources=manifest['sources'];need(type(sources) is dict and set(sources)==set(SOURCES),'exact runtime/guardian/lineage source closure')
    for relative,row in sources.items():need(pin(row,1<<20)==repo/relative,'approved source path differs');union.add(row)
    need(globals().get('__executed_sha256__')==sources[SOURCES[-2]]['sha256'] and getattr(rpc,'__executed_sha256__',None)==sources[SOURCES[-3]]['sha256'],'guardian and RPC must execute independently pinned held bytes')
    plan=union.json(manifest['plan']);out=Path(manifest['plan']['path']).parent
    need(plan.get('status')=='PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN' and plan.get('private') is True and plan.get('VM_executed') is False and plan.get('source_bound_ESP') is True and plan.get('originals_before_after_match') is True,'fresh private unexecuted plan')
    need(set(plan['input_pins'])=={'esp','build_receipt','firmware_code','firmware_vars','qemu'},'five original preparation inputs')
    for item in plan['input_pins'].values():union.add(item)
    built=union.json(plan['input_pins']['build_receipt']);need(built.get('status')=='PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN' and built.get('VM_executed') is False and built.get('source_before_after_match') is True and built.get('originals_before_after_match') is True,'source-bound private builder receipt')
    need(set(built['input_pins'])=={'DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG'},'six original builder inputs')
    for item in built['input_pins'].values():union.add(item)
    if (any(field in manifest or field in built for field in ('optional_native_inputs','optional_native_provenance')) or
        any('SHZDOS/'+name in built.get('members',{}) for name in ('VGACFG.BIN','VGAROM.BIN','W98PERS.BIN'))):
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
    lineage=manifest['lineage'];need(type(lineage) is list and len(lineage)==3,'explicit ordered DOS3 lineage pins')
    producers=manifest['producers'];need(type(producers) is list and len(producers)==2,'explicit two producer pins')
    for row in producers:union.add(row)
    parser=admitted_module('admitted_disk_lineage',manifest['sources'][SOURCES[-1]],union)
    raw=[union.raw(row,maximum) for row,maximum in zip(lineage,(1<<20,4<<20,16<<20))]
    proof=parser.admit(raw,lineage,built['input_pins']['DISK.IMG'],producers)
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
    argv=prep.recipe(Path(plan['input_pins']['qemu']['path']),out);need(argv==plan['qemu_argv'],'actual independently reconstructed recipe differs')
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
    owner.record['controller_exit_code']=controller.process.returncode if controller is not None and controller.reaped else None
    owner.record['controller_exit_status_verified']=bool(controller is not None and controller.reaped)
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
    manifest=union.json(manifest_pin,4<<20);plan,built,sources,proof,argv,helper_identity=admit_manifest(manifest,union);out=args.manifest.parent
    out=Path(manifest['plan']['path']).parent
    need(not (out/'custody-result.json').exists() and not (out/'native-result.json').exists(),'fresh one-shot native task')
    unit=subprocess.check_output(['systemctl','show',args.guardian_unit,'--property=MainPID,RuntimeMaxUSec,ActiveState,Delegate','--no-pager'],text=True,timeout=5)
    values=dict(line.split('=',1) for line in unit.splitlines());need(values.get('MainPID')==str(os.getpid()) and values.get('ActiveState')=='active' and values.get('RuntimeMaxUSec')=='infinity' and values.get('Delegate')=='yes','guardian must survive child timeout in actual delegated independent unit')
    need(manifest['limits']['memory.high']>=4<<30 and manifest['limits']['memory.max']>=manifest['limits']['memory.high'] and manifest['limits']['pids.max']<=64,'explicit native child caps required')
    parent=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
    capture=admitted_module('admitted_capture',sources['shizukudos/supervisor/native_win98/owned_capture.py'],union)
    need(capture.available_memory_bytes()>=6<<30,'existing6GiB host admission required')
    import shutil
    need(shutil.disk_usage(out).free>=(17<<30)+capture.PREFLIGHT_BUDGET,'existing17GiB plus capture budget required')
    resource_guard(parent,manifest['limits'],None,capture,out,True)
    group=TaskGroup(parent,'custody-native',manifest['limits']);owner=Owner(union,group,argv,plan['input_pins']['qemu'],manifest['timeout']);owner.output=out;owner.record['disk_lineage']=proof
    owner.record.update(manifest_pin=manifest_pin,plan_pin=manifest['plan'],builder_receipt_pin=plan['input_pins']['build_receipt'],runtime_source_pins=manifest['sources'],task_caps=manifest['limits'],observation_seconds=manifest['timeout'],cleanup_budget_seconds=16,guardian_unit_observation=values,preparation_helper_binding_verified=('preparation_receipt' in manifest or 'preparation_runtime_helpers_sha256' in plan))
    group.owner_pid=os.getpid()
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);left.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);right.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
    rpcrow=sources['shizukudos/supervisor/native_win98/custody_rpc.py'];runrow=sources['shizukudos/supervisor/native_win98/run_vm.py'];rpcfd=union.rows[rpcrow['path']]['fd'];runfd=union.rows[runrow['path']]['fd']
    runtime_names=(*HELPERS,'shizukudos/supervisor/native_win98/run_vm.py','shizukudos/supervisor/native_win98/owned_capture.py','shizukudos/supervisor/include/shz_info.h')
    runtime_pins=json.dumps({name:sources[name] for name in runtime_names},separators=(',',':'),allow_nan=False)
    need(len(runtime_pins.encode())<=rpc.MAX_PACKET,'bounded seven-source original pin map')
    command=[sys.executable,'-B','-c',CONTROLLER_BOOTSTRAP,str(rpcfd),str(runfd),rpcrow['path'],runrow['path'],rpcrow['sha256'],runrow['sha256'],'--custody-fd',str(right.fileno()),'--repo',manifest['repo'],'--plan',manifest['plan']['path'],'--plan-sha256',manifest['plan']['sha256'],'--plan-bytes',str(manifest['plan']['bytes']),'--runtime-source-pins-json',runtime_pins,'--runtime-sources-sha256',helper_identity,'--timeout',str(manifest['timeout'])]
    controller_status=None
    try:
        need(not stopped[0],'guardian cancellation requested')
        controller=subprocess.Popen(command,stdin=subprocess.DEVNULL,pass_fds=(rpcfd,runfd,right.fileno()),preexec_fn=group.place_before_exec)
        controller_status=ParentWait(controller);controller_status.pidfd=os.pidfd_open(controller.pid,0);right.close()
        server=Server(rpc.Channel(left,controller.pid),owner,sources,out)
        preparation_stop=time.monotonic()+manifest["timeout"];finalization_stop=None
        owner.record['finalization_budget_seconds']=manifest['timeout']
        rpc_closed=False
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
        check_bootstrap();union.check();group.check();resource_guard(parent,manifest['limits'],group,capture,out,owner.start is None)
        need(not stopped[0],'guardian cancellation requested')
        # Check the already established phase stop; completion cannot start a
        # new finalization budget or bypass a guard while the last wait reaps.
        if time.monotonic()>task_stop(owner,preparation_stop,finalization_stop,manifest['timeout']):
            raise TimeoutError('original task observation/cleanup/finalization deadline consumed')
        need(controller_status.reaped and controller.returncode==0 and owner.confirm_reaped() and owner.record.get('QMP_peer_admitted') is True,'controller exit is not owned-child reap/QMP admission')
    except BaseException as error:failure=error;owner.record['error']=type(error).__name__
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
