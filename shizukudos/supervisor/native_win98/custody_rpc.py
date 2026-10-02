# SPDX-License-Identifier: GPL-2.0-only
"""Inherited, credential-checked, bounded single-task custody RPC; no listener."""
import array
import hashlib
import ctypes
import fcntl
import shutil
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import stat
import re
import time

MAX_PACKET=16384
MAX_FDS=3

def need(value,message):
    if not value:raise ValueError(message)

def pairs(rows):
    result={}
    for key,value in rows:
        need(key not in result,'duplicate RPC JSON field');result[key]=value
    return result

class Channel:
    def __init__(self,sock,peer_pid):
        need(sock.family==socket.AF_UNIX and sock.type & 15==socket.SOCK_SEQPACKET,'inherited Unix seqpacket required')
        need(type(peer_pid) is int and peer_pid>0,'actual owned peer PID required')
        self.socket,self.peer_pid=sock,peer_pid
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
    def send(self,row,fds=(),timeout=5):
        need(len(fds)<=MAX_FDS,'bounded rights count')
        raw=json.dumps(row,separators=(',',':'),allow_nan=False).encode()
        need(0<len(raw)<=MAX_PACKET,'bounded RPC packet')
        self.socket.settimeout(timeout)
        anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
        need(self.socket.sendmsg([raw],anc)==len(raw),'short RPC packet write')
    def receive(self,timeout=5):
        self.socket.settimeout(timeout);fds=[]
        try:
            raw,anc,flags,_=self.socket.recvmsg(MAX_PACKET+1,socket.CMSG_SPACE(MAX_FDS*4)+socket.CMSG_SPACE(12),socket.MSG_CMSG_CLOEXEC)
            credentials=[]
            for level,kind,data in anc:
                need(level==socket.SOL_SOCKET,'foreign RPC control level')
                if kind==socket.SCM_RIGHTS:
                    rights=array.array('i');rights.frombytes(data[:len(data)//rights.itemsize*rights.itemsize]);fds.extend(rights)
                elif kind==socket.SCM_CREDENTIALS:
                    need(len(data)==12,'exact kernel credentials');credentials.append(struct.unpack('3i',data))
                else:raise ValueError('unknown RPC control type')
            if not raw:raise EOFError('controller/guardian channel closed')
            need(not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC) and len(raw)<=MAX_PACKET and len(fds)<=MAX_FDS,'truncated/surplus RPC data')
            need(len(credentials)==1 and credentials[0][0]==self.peer_pid and credentials[0][1]==os.getuid(),'actual sender PID/UID differs')
            value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite RPC JSON')))
            need(type(value) is dict,'RPC object required')
            return value,fds
        except BaseException:
            for fd in fds:os.close(fd)
            raise

class Client:
    def __init__(self,fd,guardian_pid):
        self.channel=Channel(socket.socket(fileno=fd),guardian_pid);self.sequence=0;self.frozen_fds={};self.launch_requested=False
    def call(self,operation,parameters=None,fds=(),timeout=5):
        self.sequence+=1
        self.channel.send({'id':self.sequence,'op':operation,'params':parameters or {}},fds,timeout)
        row,rights=self.channel.receive(timeout)
        try:
            need(set(row)=={'id','ok','result'} and row['id']==self.sequence and type(row['ok']) is bool,'exact ordered RPC response')
            if not row['ok']:raise RuntimeError('custody refused: '+str(row['result'])[:512])
            return row['result'],rights
        except BaseException:
            for fd in rights:os.close(fd)
            raise
    def ordinary(self,operation,parameters=None,timeout=5):
        value,rights=self.call(operation,parameters,timeout=timeout)
        if rights:
            for fd in rights:os.close(fd)
            raise ValueError('unexpected response rights')
        return value
    def admit_frozen(self,path,relative):
        row,rights=self.call('frozen',{'path':str(path),'relative':relative})
        try:
            need(len(rights)==1 and set(row)=={'bytes','sha256'},'exact frozen admission')
            fd=rights[0];size=row['bytes']
            need(type(size) is int and 0<size<=1<<20 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded typed frozen response before read')
            info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_size==size,'actual frozen regular extent')
            raw=os.pread(fd,size+1,0)
            need(type(size) is int and 0<size<=1<<20 and len(raw)==size and hashlib.sha256(raw).hexdigest()==row['sha256'],'held frozen bytes differ')
            self.frozen_fds[str(Path(path))]=(fd,raw);return raw
        except BaseException:
            for fd in rights:os.close(fd)
            raise
    def load(self,name,path):
        """Includes prepare_vm's nested build import; no admitted path is reopened."""
        original=importlib.util.spec_from_file_location
        held=self.frozen_fds
        class Loader:
            def create_module(self,spec):return None
            def exec_module(self,module):
                raw=held[module.__spec__.origin][1]
                module.__file__=module.__spec__.origin
                exec(compile(raw,module.__file__,'exec'),module.__dict__)
        def spec(name,location,*args,**kwargs):
            location=str(location)
            if location in held:return importlib.machinery.ModuleSpec(name,Loader(),origin=location)
            # Project imports must use already admitted descriptors. Stdlib uses
            # the ordinary import system, not this project-file helper API.
            raise ValueError('project source was not admitted before import')
        importlib.util.spec_from_file_location=spec
        try:
            definition=spec(name,str(path));module=importlib.util.module_from_spec(definition);definition.loader.exec_module(module);return module
        finally:importlib.util.spec_from_file_location=original
    def layout(self,info,header):
        """Compile admitted header bytes from stdin, execute a sealed probe FD."""
        fd,raw=self.frozen_fds[str(header)]
        names=[name for name,_ in info.Info._fields_]
        need(all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',n) for n in names),'literal layout field identifiers')
        program=b'#include <stddef.h>\n#include <stdio.h>\n'+raw+b'\nint main(void){\nprintf("%zu\\n",sizeof(shz_info_t));\n'
        program+=''.join('printf("%s %%zu\\n",offsetof(shz_info_t,%s));\n'%(n,n) for n in names).encode()+b'return 0;}\n'
        probe=os.memfd_create('native-layout-probe',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            compiler=shutil.which('gcc');need(compiler,'existing gcc layout compiler required')
            result=subprocess.run([compiler,'-x','c','-','-o','/proc/self/fd/%d'%probe],input=program,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(probe,),timeout=10)
            need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=65536,'bounded successful layout compile')
            need(0<os.fstat(probe).st_size<=16<<20,'bounded produced layout probe')
            os.fchmod(probe,0o700)
            fcntl.fcntl(probe,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
            executed=subprocess.run(['/proc/self/fd/%d'%probe],pass_fds=(probe,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            need(executed.returncode==0 and len(executed.stdout)+len(executed.stderr)<=16384,'bounded successful sealed layout probe')
            lines=executed.stdout.decode('ascii').splitlines();size=int(lines[0]);offsets={name:int(value) for name,value in (line.split() for line in lines[1:])}
            need(size==ctypes.sizeof(info.Info) and size<=info.INFO_BYTES and set(offsets)==set(names),'actual C/Python layout size/field mismatch')
            need(all(offsets[n]==getattr(info.Info,n).offset for n in names),'actual C/Python layout offset mismatch');return size
        finally:os.close(probe)
    def spawn(self,args,writers):
        self.launch_requested=True
        names=('serial.log','e9.log','native-qemu.stderr')
        descriptors=[writers[name] for name in names]
        identities=[list((os.fstat(fd).st_dev,os.fstat(fd).st_ino)) for fd in descriptors]
        row,rights=self.call('spawn',{'argv':args,'pipes':identities},descriptors,timeout=25)
        try:
            need(not rights and set(row)=={'pid','argv'} and type(row['pid']) is int and row['pid']>0 and isinstance(row['argv'],list),'exact successful spawn ACK')
            return Process(self,row['pid'],row['argv'])
        finally:
            for fd in rights:os.close(fd)
    def admit_qmp(self,monitor):
        row,rights=self.call('qmp',{},[monitor.socket.fileno()])
        try:need(not rights and row is True,'actual QMP socket admission required')
        finally:
            for fd in rights:os.close(fd)
    def close(self):
        for fd,_ in self.frozen_fds.values():os.close(fd)
        self.frozen_fds.clear();self.channel.socket.close()

class Process:
    """Only observations/signals of the guardian's one real Popen child."""
    def __init__(self,client,pid,args):self.client,self.pid,self.args=client,pid,args;self._returncode=None
    @property
    def returncode(self):return self._returncode
    def poll(self):
        row=self.client.ordinary('poll');self._returncode=row;return row
    def wait(self,timeout=None):
        need(type(timeout) in (int,float) and 0<timeout<=5,'bounded existing cleanup wait required')
        row=self.client.ordinary('wait',{'seconds':timeout},timeout=timeout+1)
        if row is None:raise subprocess.TimeoutExpired(self.args,timeout)
        self._returncode=row;return row
    def terminate(self):self.client.ordinary('signal',{'signal':15})
    def kill(self):self.client.ordinary('signal',{'signal':9})
