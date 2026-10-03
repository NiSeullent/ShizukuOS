#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent launch-owned baseline custody transport; no lineage approval.

The source-only route is a real Linux control. The Windows route invokes only
fixed source-built control/observer and retains its live original/clone leases.
Neither route can issue Windows grade without independent private lineage auth.
"""
import fcntl, hashlib, importlib.util, json, os, select, signal, socket, stat, struct, subprocess, sys, threading, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
MAX_PACKET=65536

def need(ok,message):
    if not ok:raise ValueError(message)

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__);return module

control=load(ROOT/'shizukudos/install/live_baseline/control.py','provider_fixed_control')
replacement=control.replacement

def encode(row):
    data=json.dumps(row,sort_keys=True,separators=(',',':')).encode()
    need(len(data)<=MAX_PACKET,'bounded custody packet required');return data

def send(peer,row):
    data=encode(row);need(peer.send(data)==len(data),'complete custody packet required')

def receive(peer,deadline,guard=lambda:None):
    while True:
        guard();need(time.monotonic()<deadline,'custody transport deadline expired')
        if select.select([peer],[],[],min(.1,deadline-time.monotonic()))[0]:
            data,_,flags,_=peer.recvmsg(MAX_PACKET)
            need(data and not flags&socket.MSG_TRUNC,'complete bounded custody packet required')
            return json.loads(data,object_pairs_hook=control.unique)

def peer_pid(peer):
    pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    need(uid==os.getuid() and gid==os.getgid(),'owned custody peer credentials differ');return pid

class SourceHold:
    """Real original FD lease custody only; an arbitrary fixture is not Windows."""
    def __init__(self,held,source,deadline,cancel):
        self.held=held;self.source=source;self.deadline=deadline;self.cancel=cancel
        self.pid=os.getpid();self.thread=threading.get_ident()
    def __reduce__(self):raise TypeError('live source hold cannot be serialized')
    def check(self):
        need(os.getpid()==self.pid and threading.get_ident()==self.thread and not self.cancel[0] and time.monotonic()<self.deadline,'source owner cancelled/dead/stale')
        for entry in self.held.values():entry['checkpoint']()
    def summary(self):
        self.check();return {'grade':'SOURCE_CUSTODY_ONLY','source':self.source,'source_identity':list(self.held[self.source['path']]['identity']),'source_approval':False,'Windows98_on_ShizukuDOS':False}
    def finish(self):
        self.check()
        for entry in self.held.values():need(replacement.hash_fd(entry['fd'],entry['pin']['bytes'],self.check)==entry['pin']['sha256'],'source owner final input SHA differs')
        self.check()

def serve_hold(peer,hold,token,deadline,cancel):
    need(type(hold) in (SourceHold,control.OwnedObservation),'fixed actual source/control hold issuer required')
    summary=hold.summary()
    if 'observation' in summary:
        observation=summary.pop('observation')
        summary['observation_sha256']=hashlib.sha256(json.dumps(observation,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        summary['observed_version']={k:observation[k] for k in ('platform_id','major','minor','build_raw','display_count')}
    send(peer,{'state':'READY','token':token,'summary':summary})
    sequence=0;used=set()
    while True:
        hold.check();need(not cancel[0],'custody service cancelled')
        request=receive(peer,deadline,hold.check)
        need(type(request) is dict and set(request)=={'operation','token','sequence','challenge'} and request['token']==token,'current owned service token required')
        need(type(request['sequence']) is int and request['sequence']==sequence+1,'fresh exact custody sequence required')
        challenge=request['challenge'];need(type(challenge) is str and len(challenge)==64,'fresh challenge32 required')
        raw=bytes.fromhex(challenge);need(len(raw)==32 and any(raw) and challenge not in used and len(used)<4096,'fresh unused custody challenge required')
        used.add(challenge);sequence+=1
        need(request['operation'] in ('CHECK','FINISH','WINDOWS_GRADE'),'fixed custody operation required')
        hold.check()
        if request['operation']=='WINDOWS_GRADE':
            # A live observer and a source SHA do not establish approved lineage.
            send(peer,{'state':'REFUSED','reason':'independent private live media/install-lineage authority absent','token':token,'sequence':sequence,'challenge':challenge,'source_approval':False});continue
        if request['operation']=='FINISH':hold.finish()
        send(peer,{'state':request['operation'],'token':token,'sequence':sequence,'challenge':challenge,'summary':summary})
        if request['operation']=='FINISH':return

def serve(config):
    need(type(config) is dict and set(config)=={'mode','source','control_request','socket','token','parent_pid','input_pins'},'exact service configuration required')
    need(config['mode'] in ('SOURCE_CUSTODY_ONLY','FIXED_WINDOWS_OBSERVATION'),'fixed service mode required')
    source=config['source'];replacement.pin_fields(source);st=Path(source['path']).lstat()
    need(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o400 and st.st_uid==os.getuid() and st.st_nlink==1,'owned0400 original source required')
    deadline=time.monotonic()+900;cancel=[False]
    for number in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(number,lambda *_:cancel.__setitem__(0,True))
    peer=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);peer.settimeout(5)
    try:
        peer.connect(config['socket']);need(peer_pid(peer)==config['parent_pid'] and os.getppid()==config['parent_pid'],'actual owned launch parent required')
        send(peer,{'state':'CONNECTED','token':config['token'],'pid':os.getpid()})
        if config['mode']=='SOURCE_CUSTODY_ONLY':
            with replacement.leased_inputs([source,*config['input_pins']]) as held:
                hold=SourceHold(held,source,deadline,cancel);serve_hold(peer,hold,config['token'],deadline,cancel)
        else:
            need(config['control_request']['source']==source,'fixed Windows source binding differs')
            # The actual control owns QEMU/observer and the one original union.
            # Parent independently keeps provider/interpreter inputs leased.
            control.run(config['control_request'],retain=lambda observation:serve_hold(peer,observation,config['token'],deadline,cancel))
    finally:peer.close()

class Client:
    """Only a newly owned exec child may provide this nonserialized context."""
    def __init__(self,source,output,*,control_request=None,borrowed_launcher=None):
        self.source=source;self.output=Path(output);self.control_request=control_request;self.borrowed=borrowed_launcher
        self.active=False;self.child=self.pidfd=self.peer=self.listener=self.inputs=None
        self.owner_pid=os.getpid();self.owner_thread=threading.get_ident();self.sequence=0
    def __reduce__(self):raise TypeError('live baseline service cannot be serialized')
    def owner_check(self):
        need(self.active and os.getpid()==self.owner_pid and threading.get_ident()==self.owner_thread,'current provider client owner/lifetime required')
        if self.child is not None:need(self.child.poll() is None and not select.select([self.pidfd],[],[],0)[0],'actual owned service exited')
        for entry in self.held.values():entry['checkpoint']()
    def __enter__(self):
        replacement.safe_path(self.output);need(not self.output.exists() and self.output.parent.is_dir() and stat.S_IMODE(self.output.parent.stat().st_mode)==0o700 and self.output.parent.stat().st_uid==os.getuid(),'fresh owned0700 provider directory required')
        self.output.mkdir(mode=0o700);self.deadline=time.monotonic()+900;self.token=os.urandom(32).hex()
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);self.listener.bind(str(self.output/'owner.sock'));self.listener.listen(1);self.listener.settimeout(5)
        self.pins=[replacement.local_pin(p) for p in (Path(__file__),Path(control.__file__),Path(replacement.__file__),Path(control.capture.__file__),Path(sys.executable).resolve())]
        config={'mode':'FIXED_WINDOWS_OBSERVATION' if self.control_request is not None else 'SOURCE_CUSTODY_ONLY','source':self.source,'control_request':self.control_request,'socket':str(self.output/'owner.sock'),'token':self.token,'parent_pid':os.getpid(),'input_pins':self.pins}
        raw=encode(config);path=self.output/'configuration.json'
        with path.open('xb') as stream:need(stream.write(raw)==len(raw),'complete private service configuration required')
        os.chmod(path,0o400);self.pins.append(replacement.local_pin(path))
        try:
            if self.borrowed is None:
                self.inputs=replacement.leased_inputs(self.pins);self.held=self.inputs.__enter__()
            else:
                need(type(self.borrowed).__name__=='Union' and hasattr(self.borrowed,'broken') and
                     self.borrowed.add.__code__.co_filename==str(ROOT/'shizukudos/install/native_payload_ingest.py'),
                     'actual caller-admitted ingester union required')
                self.borrowed.check();self.held={}
                for pin in self.pins:
                    entry=self.borrowed.add(pin)
                    def checkpoint(entry=entry,pin=pin):
                        # Do not call Union.check/io_check recursively when its guards
                        # invoke this live provider. Caller retains the one SIGIO owner.
                        need(not self.borrowed.broken and entry['pin']==pin and
                             replacement.identity(os.fstat(entry['fd']))==entry['identity']==replacement.identity(Path(pin['path']).stat()) and
                             fcntl.fcntl(entry['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK,'borrowed launcher identity/lease changed')
                    self.held[pin['path']]={**entry,'checkpoint':checkpoint}
                self.borrowed.check()
            self.active=True
            executable=str(Path(sys.executable).resolve());argv=[executable,'-I',str(Path(__file__)),'--serve',str(path)]
            self.log=(self.output/'service.stderr').open('xb')
            self.child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=self.log,cwd=self.output)
            self.pidfd=os.pidfd_open(self.child.pid)
            self.peer,_=self.listener.accept();need(peer_pid(self.peer)==self.child.pid,'actual postexec owned service PID differs')
            exe=Path('/proc/%d/exe'%self.child.pid).stat();original=os.fstat(self.held[executable]['fd']);need((exe.st_dev,exe.st_ino)==(original.st_dev,original.st_ino),'actual service interpreter inode differs')
            actual=Path('/proc/%d/cmdline'%self.child.pid).read_bytes();need(actual.rstrip(b'\0').split(b'\0')==[p.encode() for p in argv],'actual owned service argv differs')
            response=receive(self.peer,self.deadline,self.owner_check)
            need(response=={'state':'CONNECTED','token':self.token,'pid':self.child.pid},'fresh owned postexec handshake required')
            return self
        except BaseException:self.close();raise
    def wait_ready(self):
        self.owner_check();row=receive(self.peer,self.deadline,self.owner_check)
        need(type(row) is dict and set(row)=={'state','token','summary'} and row['state']=='READY' and row['token']==self.token,'actual held ready observation required')
        summary=row['summary'];need(summary['source']==self.source and summary['source_approval'] is False and summary['Windows98_on_ShizukuDOS'] is False,'actual held source/scope differs')
        self.summary=summary;return summary
    def query(self,operation='CHECK'):
        self.owner_check();need(hasattr(self,'summary'),'live ready source required')
        challenge=os.urandom(32).hex();self.sequence+=1
        send(self.peer,{'operation':operation,'token':self.token,'sequence':self.sequence,'challenge':challenge})
        row=receive(self.peer,self.deadline,self.owner_check)
        need(row['token']==self.token and row['sequence']==self.sequence and row['challenge']==challenge,'live challenge response differs')
        if operation=='WINDOWS_GRADE':raise ValueError(row['reason'])
        need(row['state']==operation and row['summary']==self.summary,'actual source hold changed')
        return row
    def match_held_source(self,entry):
        self.query();need(entry['pin']==self.source and replacement.identity(os.fstat(entry['fd']))==tuple(self.summary['source_identity']),'held compiler source FD differs')
        need(fcntl.fcntl(entry['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK,'actual compiler source read lease required')
        need(replacement.hash_fd(entry['fd'],self.source['bytes'],self.owner_check)==self.source['sha256'],'actual compiler source fullSHA differs')
        self.query();return True
    def finish(self):
        self.query('FINISH');self.child.wait(timeout=30)
        need(self.child.returncode==0 and select.select([self.pidfd],[],[],0)[0],'actual service final cleanup/reap failed')
        for entry in self.held.values():need(replacement.hash_fd(entry['fd'],entry['pin']['bytes'],entry['checkpoint'])==entry['pin']['sha256'],'launcher retained input final SHA differs')
        self.active=False
    def close(self):
        # No saved response remains active after owned service death/reap.
        if self.peer is not None:self.peer.close();self.peer=None
        if self.child is not None and self.child.poll() is None:
            try:
                if self.pidfd is not None:signal.pidfd_send_signal(self.pidfd,signal.SIGTERM)
                else:self.child.send_signal(signal.SIGTERM)
            except ProcessLookupError:pass
            try:self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                if self.pidfd is not None:signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
                else:self.child.kill()
                self.child.wait()
        self.active=False
        if self.listener is not None:self.listener.close();self.listener=None
        if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
        if hasattr(self,'log'):self.log.close()
        if self.inputs is not None:self.inputs.__exit__(*sys.exc_info());self.inputs=None
    def __exit__(self,*_):self.close()

if __name__=='__main__':
    need(len(sys.argv)==3 and sys.argv[1]=='--serve','owned service entry only')
    raw=Path(sys.argv[2]).read_bytes();need(len(raw)<=MAX_PACKET,'bounded private owned configuration required')
    serve(json.loads(raw,object_pairs_hook=control.unique))
