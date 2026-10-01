#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""HELD private standalone Kernel64 controls. No launch without exact external release.

This runner never builds or changes a kernel. It clones prepared inputs into an
absent output directory, drives ONLY three deliberate own-kernel fault tokens,
and cleans up ONLY the child it created. Win98/VMM interception is out of scope.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path('/root/Win98-Modern-boot')
FLOOR = 17 * 1024**3 + 512 * 1024**2
RUN_HEADROOM = 1024**3
CASES = ('panic', 'ud', 'text')
SCOPE = 'standalone-kernel64-own-panic-ud-text-controls-only'
KEYS = {'1','2','a','d','w','s','spc','esc','r','l','t'}
LOCKS = (ROOT/'build/dead-screen-native-control-plan-20261001-v5/dead-screen-lane.lock',)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''): h.update(block)
    return h.hexdigest()


def verify(item):
    p = Path(item['path'])
    if p.is_symlink() or p.resolve(strict=True) != p or not p.is_file():
        raise ValueError('canonical nonsymlink file required: '+str(p))
    if p.stat().st_size != item['bytes'] or digest(p) != item['sha256']:
        raise ValueError('held file differs: '+str(p))
    return p


def read_json(path, limit=8*1024*1024):
    return json.loads(bounded_read(path,limit))


def bounded_read(path,limit):
    with Path(path).open('rb') as stream:raw=stream.read(limit+1)
    if len(raw)>limit: raise ValueError('bounded read exceeded: '+str(path))
    return raw


def fresh(path):
    p = Path(path)
    if not p.is_absolute() or p.is_symlink() or p.exists(): raise ValueError('absent absolute output required')
    if p.parent.resolve(strict=True) != p.parent or not p.is_relative_to(ROOT/'build'):
        raise ValueError('output must have a canonical existing parent below build')
    return p


def acquire_native_lane(stack,plan):
    """Only this standalone task lane; never open external Win98 locks."""
    if plan['own_native_locks']!=[str(p) for p in LOCKS]:
        raise ValueError('exact task-private lane required')
    expected=plan['native_lane_identity']
    if len(LOCKS)!=1 or expected['path']!=str(LOCKS[0]):
        raise ValueError('single exact task-private lane identity required')
    path=LOCKS[0]
    if path.parent.resolve(strict=True)!=path.parent:
        raise ValueError('canonical task-private lane parent required')
    fd=os.open(path,os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
    stream=stack.enter_context(os.fdopen(fd,'r+b'));metadata=os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid() or metadata.st_nlink!=1:
        raise ValueError('task-private lane regular owned unique inode required')
    if (metadata.st_dev,metadata.st_ino)!=(expected['device'],expected['inode']):
        raise ValueError('task-private lane inode replaced')
    raw=stream.read(4097)
    if len(raw)>4096 or len(raw)!=expected['bytes'] or hashlib.sha256(raw).hexdigest()!=expected['sha256']:
        raise ValueError('task-private lane content differs')
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    current=os.stat(path,follow_symlinks=False)
    if (current.st_dev,current.st_ino)!=(metadata.st_dev,metadata.st_ino):
        raise ValueError('task-private lane path replaced while acquiring')
    return {'path':str(path),'device':metadata.st_dev,'inode':metadata.st_ino,'owner_uid':metadata.st_uid,
            'exclusive':True,'scope':'standalone-dead-screen-only; external Win98 locks untouched'}


def host_status(proc_root=Path('/proc'), free_path=ROOT/'build'):
    conflicts = []
    for p in proc_root.iterdir():
        if not p.name.isdecimal(): continue
        try:
            raw = (p/'cmdline').read_bytes()
            exe = raw.split(b'\0',1)[0].decode(errors='replace')
            base = Path(exe).name
            if re.fullmatch(r'qemu-(?:system-[\w-]+|kvm)|emulator(?:-headless)?',base):
                status=(p/'status').read_text()
                rss=re.search(r'^VmRSS:\s+(\d+) kB$',status,re.M)
                fields=(p/'stat').read_text().rpartition(') ')[2].split()
                conflicts.append({'pid':int(p.name),'executable':exe,'rss_bytes':int(rss[1])*1024 if rss else None,
                    'cpu_time_ticks':int(fields[11])+int(fields[12]) if len(fields)>19 else None,
                    'start_ticks':int(fields[19]) if len(fields)>19 else None})
        except (FileNotFoundError,ProcessLookupError): continue
        except PermissionError as e: raise ValueError('cannot prove process exclusivity') from e
    meminfo=(proc_root/'meminfo').read_text()
    available=re.search(r'^MemAvailable:\s+(\d+) kB$',meminfo,re.M)
    if not available: raise ValueError('host memory availability unavailable')
    return {'filesystem_free':shutil.disk_usage(free_path).free,'floor':FLOOR,'memory_available':int(available[1])*1024,
            'required_memory':7*1024**3,
            'required_run_headroom':RUN_HEADROOM,'active_qemu_or_emulator':conflicts}


def enforce_host(status):
    if status['filesystem_free'] < FLOOR + RUN_HEADROOM: raise ValueError('strict disk floor plus run headroom unavailable')
    if status['memory_available'] < status['required_memory']: raise ValueError('6 GiB host reserve plus 1 GiB bounded child/observer memory unavailable')


def own_process(proc,argv,token):
    if proc.poll() is not None: return False
    p=Path('/proc')/str(proc.pid)
    fields=(p/'stat').read_text().rpartition(') ')[2].split()
    if len(fields)<20 or int(fields[19])!=token or (p/'cmdline').read_bytes().split(b'\0')[:-1]!=[v.encode() for v in argv]:
        raise ValueError('owned child PID/start/complete command identity differs')
    if (p/'exe').resolve()!=Path(argv[0]).resolve(): raise ValueError('owned child executable differs')
    return True


def cleanup_owned(owned,report,publish):
    """Runs before source/lock handles close, including failed token acquisition.

    Popen owns this unreaped child independently of optional /proc metadata.
    A stable pidfd strengthens signal identity when available. No foreign PID
    scan ever authorizes cleanup. A still-live child keeps this coordinator and
    its actual held descriptors alive; it cannot be converted into success.
    """
    proc=owned.get('proc');pidfd=owned.get('pidfd')
    if proc is None:return
    # Popen ownership is the source of launch truth even if interruption occurs
    # before caller bookkeeping or /proc metadata acquisition.
    report['native_started']=True;report['owned_pid']=proc.pid
    def send(sig):
        if proc.poll() is not None:return
        if pidfd is not None:signal.pidfd_send_signal(pidfd,sig)
        elif sig==signal.SIGTERM:proc.terminate()
        else:proc.kill()
    try:
        if proc.poll() is None:
            report['forced_termination']=True;report['status']='FAIL'
            for sig in (signal.SIGTERM,signal.SIGKILL):
                try:send(sig);proc.wait(timeout=5)
                except (OSError,subprocess.TimeoutExpired,KeyboardInterrupt) as exc:
                    report.setdefault('cleanup_errors',[]).append(repr(exc))
                if proc.poll() is not None:break
    finally:
        try:
            if proc.poll() is None:
                report['cleanup_pending']=True
                report['cleanup_scope']='observation failed; coordinator retains actual input/lock handles until its child exits'
                try:publish()
                except BaseException as exc:report['pending_receipt_io_failure']=repr(exc)
                # Observations have ended. OS-level inability to stop a child
                # cannot satisfy both process-exit and a bounded parent exit.
                # Preserve ownership instead of falsely releasing its handles.
                while proc.poll() is None:
                    try:proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:continue
                    except OSError as exc:
                        report.setdefault('cleanup_errors',[]).append(repr(exc));time.sleep(1)
                    except KeyboardInterrupt:
                        try:send(signal.SIGKILL)
                        except OSError:pass
                report['cleanup_pending']=False;report['cleanup_eventually_stopped']=True
            report['source_handles_retained_until_owned_child_exit']=proc.poll() is not None
        finally:
            if pidfd is not None and proc.poll() is not None:os.close(pidfd);owned['pidfd']=None


def validate_release(release,plan,plan_sha,runner_sha):
    if release.get('status') != 'ROOT_RELEASED_PRIVATE_NATIVE_CONTROL' or release.get('owner') not in ('root','win98_variant'):
        raise ValueError('root/variant release required; preparation is not launch permission')
    if release.get('scope') != SCOPE or release.get('plan_sha256') != plan_sha or release.get('runner_sha256') != runner_sha:
        raise ValueError('release must identify exact plan, runner and closed scope')
    if release.get('candidate_sha256') != plan['candidate_sha256'] or release.get('no_win98_vmm_acceptance') is not True:
        raise ValueError('release candidate/scope differs')


class QMP:
    """Bounded lines, events, operation deadlines and matching response IDs."""
    def __init__(self,path,deadline,expected_pid):
        self.deadline=deadline;self.sock=socket.socket(socket.AF_UNIX);self.buffer=b'';self.ident=0
        try:
            connect_end=min(deadline,time.monotonic()+30)
            while True:
                left=connect_end-time.monotonic()
                if left<=0: raise TimeoutError('QMP connection deadline')
                self.sock.settimeout(min(1,left))
                try: self.sock.connect(str(path));break
                except (FileNotFoundError,ConnectionRefusedError): time.sleep(.05)
            pid,uid,_=struct.unpack('3i',self.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if pid!=expected_pid or uid!=os.getuid(): raise ValueError('QMP peer is not the owned child')
            if 'QMP' not in self.line(min(deadline,time.monotonic()+3)): raise ValueError('missing QMP greeting')
            self.call('qmp_capabilities')
        except BaseException:
            self.sock.close();raise
    def line(self,deadline):
        while b'\n' not in self.buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError('QMP reply deadline')
            self.sock.settimeout(remaining)
            block=self.sock.recv(4096)
            if not block: raise EOFError('QMP closed')
            self.buffer+=block
            if len(self.buffer)>65536: raise ValueError('QMP line bound exceeded')
        line,self.buffer=self.buffer.split(b'\n',1)
        item=json.loads(line)
        if not isinstance(item,dict): raise ValueError('QMP object required')
        return item
    def call(self,command,arguments=None):
        self.ident+=1;msg={'execute':command,'id':self.ident}
        if arguments is not None: msg['arguments']=arguments
        deadline=min(self.deadline,time.monotonic()+3)
        if deadline<=time.monotonic(): raise TimeoutError('overall native control deadline')
        self.sock.settimeout(deadline-time.monotonic())
        self.sock.sendall((json.dumps(msg)+'\n').encode())
        for _ in range(64):
            reply=self.line(deadline)
            if 'event' in reply: continue
            if reply.get('id') != self.ident: raise ValueError('QMP response ID differs')
            if 'error' in reply: raise ValueError('QMP error: '+str(reply['error']))
            if 'return' not in reply: raise ValueError('QMP result absent')
            return reply['return']
        raise ValueError('QMP event bound exceeded')
    def close(self): self.sock.close()


def u32(raw,off): return struct.unpack_from('<I',raw,off)[0]
def i32(raw,off): return struct.unpack_from('<i',raw,off)[0]
def u64(raw,off): return struct.unpack_from('<Q',raw,off)[0]


def state_fields(raw,abi):
    if len(raw)!=abi['state_size']: raise ValueError('short/extra native state dump')
    a=abi['state'];f=abi['fault'];t=abi['tetris'];su=abi['suika'];b=abi['ball']
    s={k:u32(raw,a[k]) for k in ('ticks','latched','korean','mode','show_trace','graphics_failed')}
    if s['latched'] not in (0,1): raise ValueError('invalid latch')
    if not s['latched']: return s
    if s['mode']>2 or s['korean']>1 or s['show_trace']>1 or s['graphics_failed']>1:
        raise ValueError('invalid native state metadata')
    reason=raw[f['reason']:f['reason']+160]
    if b'\0' not in reason: raise ValueError('unterminated first record')
    s['fault']={k:u64(raw,f[k]) for k in ('ip','sp','bp','flags','vector','error','cr2','cr3')}
    s['fault']['reason']=reason.split(b'\0')[0].decode('ascii')
    s['fault']['frame_count']=u32(raw,f['frame_count']);s['fault']['registers_valid']=u32(raw,f['registers_valid'])
    s['fault']['frame0']=u64(raw,f['frames']);s['fault']['cs']=u64(raw,f['reg']+15*8)
    if s['fault']['frame_count']!=1 or s['fault']['registers_valid'] not in (0,1): raise ValueError('unexpected actual-frame metadata')
    if s['fault']['frame0']!=s['fault']['ip']: raise ValueError('frame0 is not captured IP')
    to=a['tetris'];so=a['suika']
    s['tetris']={k:(i32 if k in ('x','y') else u32)(raw,to+t[k]) for k in ('x','y','piece','rotation','lines','score','over')}
    s['tetris']['occupied']=sum(v!=0 for v in raw[to+t['board']:to+t['board']+200])
    s['suika']={k:(i32 if k=='aim' else u32)(raw,so+su[k]) for k in ('aim','next','cooldown','score','over')}
    s['suika']['balls']=[]
    for i in range(32):
        off=so+su['ball']+i*b['end']
        if raw[off+b['used']]:
            level=raw[off+b['level']]
            if level>5: raise ValueError('invalid bounded ball rank')
            s['suika']['balls'].append({'x':i32(raw,off+b['x']),'y':i32(raw,off+b['y']),'level':level})
    return s


def ppm(raw):
    m=re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s',raw)
    if not m: raise ValueError('unsupported screenshot PPM')
    w,h=map(int,m.groups())
    if not 640<=w<=4096 or not 480<=h<=4096 or len(raw)-m.end()!=w*h*3:
        raise ValueError('screenshot size/bounds differ')
    return w,h,raw[m.end():]


def command(plan,work,sock):
    q=plan['tools']['qemu']['path'];fw=plan['firmware_code']['path']
    return [q,'-name','shz-dead-screen-own-control','-machine','q35','-accel','tcg',
        '-cpu','qemu64,vendor=GenuineIntel','-smp','1','-m','256',
        '-global','ICH9-LPC.disable_s3=1','-display','none','-vga','std',
        '-L',plan['rom_directory'],'-net','none','-no-reboot',
        '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+fw,
        '-drive','if=pflash,format=raw,unit=1,file='+str(work/'OVMF_VARS.fd'),
        '-drive','file='+str(work/'disk.img')+',format=raw,if=none,id=hd0,cache=writethrough',
        '-device','ide-hd,drive=hd0,bus=ide.0,bootindex=1',
        '-device','isa-debug-exit,iobase=0xf4,iosize=0x04',
        '-serial','file:'+str(work/'serial.log'),'-qmp','unix:'+str(sock)+',server=on,wait=off']


class Control:
    def __init__(self,q,proc,plan,work,case):
        self.q=q;self.proc=proc;self.plan=plan;self.work=work;self.case=case;self.seq=0;self.first=None;self.observations=[]
    def memory(self,name,address,size):
        if not 0<size<=4096 or not 0x100000<=address or address+size>0x300000:
            raise ValueError('only bounded own-kernel image/BSS physical reads allowed')
        p=self.work/name
        if p.exists(): raise ValueError('fresh memory dump required')
        self.q.call('pmemsave',{'val':address,'size':size,'filename':str(p)})
        raw=bounded_read(p,size)
        if len(raw)!=size: raise ValueError('memory dump length differs')
        return raw
    def sample(self,tag,screen=False):
        if self.proc.poll() is not None: raise ValueError('guest exited before observation')
        if shutil.disk_usage(self.work).free<FLOOR: raise ValueError('strict floor exhausted during bounded observation')
        self.seq+=1;stem=f'{self.seq:03d}-{tag}'
        self.q.call('stop')
        try:
            sym=self.plan['symbols'];abi=self.plan['abi']
            raw=self.memory(stem+'-state.bin',sym['state']['physical'],abi['state_size'])
            s=state_fields(raw,abi)
            if s['latched']:
                fault=raw[:abi['fault_size']]
                if self.first is None: self.first=fault
                if fault!=self.first: raise ValueError('first latched record changed')
            regs=self.q.call('human-monitor-command',{'command-line':'info registers'})
            (self.work/(stem+'-cpu.txt')).write_text(regs)
            if screen:
                shot=self.work/(stem+'.ppm');self.q.call('screendump',{'filename':str(shot)})
                data=bounded_read(shot,4096*4096*3+256);w,h,actual=ppm(data)
                surface=self.memory(stem+'-surface.bin',sym['framebuffer']['physical'],abi['surface_size'])
                sa=abi['surface']
                pitch=u32(surface,sa['pitch_words']);span=u64(surface,sa['span_words']);pointer=u64(surface,sa['pixels']);rgbx=u32(surface,sa['rgbx'])
                if (u32(surface,sa['width']),u32(surface,sa['height']))!=(w,h): raise ValueError('retained framebuffer/screenshot geometry differs')
                if pitch<w or pitch>16384 or span<(h-1)*pitch+w or span>64*1024**2 or pointer<0xffff800000000000 or pointer&3 or rgbx>1:
                    raise ValueError('retained actual framebuffer binding invalid')
                mode='text' if self.case=='text' else 'graphics'
                ref=subprocess.run([self.plan['reference']['path'],str(self.work/(stem+'-state.bin')),str(w),str(h),mode],capture_output=True,timeout=3)
                if ref.returncode: raise ValueError('captured-state host transport reference failed')
                rw,rh,want=ppm(ref.stdout)
                s['screenshot']={'path':str(shot),'sha256':hashlib.sha256(data).hexdigest(),'width':w,'height':h,
                    'actual_guest_pixels':True,'same_source_transport_reference':True,'complete_frame_matches':(rw,rh)==(w,h) and actual==want}
            s['tag']=tag;s['state_file']=str(self.work/(stem+'-state.bin'));s['cpu_file']=str(self.work/(stem+'-cpu.txt'))
            self.observations.append(s)
            return s
        finally:
            self.q.call('cont')
    def until(self,tag,predicate,seconds=15,screen=False):
        end=min(self.q.deadline,time.monotonic()+seconds)
        for _ in range(120):
            if time.monotonic()>=end: break
            s=self.sample(tag,screen)
            if predicate(s): return s
            time.sleep(.1)
        raise TimeoutError('native observation not reached: '+tag)
    def keys(self,*keys):
        for key in keys:
            if key not in KEYS: raise ValueError('closed keyboard key required')
            self.q.call('send-key',{'keys':[{'type':'qcode','data':key}],'hold-time':80})
            time.sleep(.2)
    def frame(self,tag,predicate=lambda s:True):
        return self.until(tag,lambda s:predicate(s) and s.get('screenshot',{}).get('complete_frame_matches'),seconds=8,screen=True)


def validate_fault(s,case,plan):
    if not s['latched'] or s['graphics_failed']: raise ValueError('requested fault not latched cleanly')
    f=s['fault'];ip=f['ip']
    if not plan['kernel_virtual_start']<=ip<plan['kernel_virtual_end'] or not f['sp'] or not f['cr3']:
        raise ValueError('actual captured own-kernel register prerequisites absent')
    if case=='ud':
        if f['vector']!=6 or f['error'] or f['registers_valid']!=1 or f['cs']&3 or ip!=plan['control_ud_ip']:
            raise ValueError('not the deliberate own-kernel ring0 #UD')
    # BP is the actual raw register value, including zero: no frame-pointer unwind.
    elif ip!=plan['control_panic_return_ip'] or f['vector']!=2**64-1 or f['registers_valid'] or 'requested own-kernel panic' not in f['reason']:
        raise ValueError('not the deliberate own-kernel panic')


def games(c):
    c.frame('menu-ko',lambda s:s['mode']==0 and s['korean']==1)
    c.keys('l');c.frame('menu-en',lambda s:s['mode']==0 and s['korean']==0)
    c.keys('1');t0=c.frame('tetris-start',lambda s:s['mode']==1 and s['tetris']['occupied']==0)
    c.keys('a');t1=c.until('tetris-left',lambda s:s['mode']==1 and s['tetris']['x']==t0['tetris']['x']-1)
    c.keys('d','w');rotated=c.until('tetris-rotate',lambda s:s['tetris']['x']==t0['tetris']['x'] and s['tetris']['rotation']==(t1['tetris']['rotation']+1)%4)
    c.until('tetris-real-gravity',lambda s:s['ticks']>rotated['ticks'] and s['tetris']['y']>rotated['tetris']['y'],seconds=20)
    c.keys('spc');c.frame('tetris-locked',lambda s:s['mode']==1 and s['tetris']['occupied']>=4)
    c.keys('r');c.frame('tetris-restarted',lambda s:s['mode']==1 and s['tetris']['occupied']==0 and s['tetris']['over']==0)
    c.keys('esc','2');su=c.frame('suika-start',lambda s:s['mode']==2 and not s['suika']['balls'])
    c.keys('a');c.until('suika-left',lambda s:s['suika']['aim']==su['suika']['aim']-8)
    c.keys('d','spc');b=c.frame('suika-dropped',lambda s:s['mode']==2 and len(s['suika']['balls'])==1)
    c.until('suika-real-gravity',lambda s:s['ticks']>b['ticks'] and s['suika']['balls'] and s['suika']['balls'][0]['y']>b['suika']['balls'][0]['y'],seconds=20)
    # Real deterministic drops from actual keys; never write guest state to force a merge.
    for i in range(8):
        c.until('suika-cooldown',lambda s:s['suika']['cooldown']==0,seconds=20)
        c.keys('spc')
        s=c.until('suika-drop-'+str(i),lambda s:s['suika']['cooldown']>0 or s['suika']['over'])
        if s['suika']['score']>0: break
        if s['suika']['over']: raise ValueError('Suika ended before an observed actual merge')
    c.frame('suika-merged',lambda s:s['suika']['score']>0 and any(v['level']>0 for v in s['suika']['balls']))
    c.keys('r');c.frame('suika-restarted',lambda s:s['mode']==2 and not s['suika']['balls'] and not s['suika']['score'])
    c.keys('esc','t');c.frame('trace-toggled',lambda s:s['mode']==0 and s['show_trace']==0)
    c.keys('t','l');c.frame('menu-restored',lambda s:s['mode']==0 and s['show_trace']==1 and s['korean']==1)


def serial_read(path):
    if not path.exists(): return b''
    return bounded_read(path,4*1024*1024)


def run_case(plan,out,case):
    work=out/case;work.mkdir()
    prepared=plan['cases'][case]
    for name in ('disk.img','OVMF_VARS.fd'):
        src=verify(prepared[name]);shutil.copyfile(src,work/name)
        if digest(work/name)!=prepared[name]['sha256']: raise ValueError('own clone differs')
    report={'case':case,'status':'FAIL','native_started':False,'win98_vmm_acceptance':False,'app_success':False}
    proc=q=None;stderr=None;token=None;argv=None;owned={'proc':None,'pidfd':None}
    started=time.monotonic();sockdir=Path(tempfile.mkdtemp(prefix='ds-control-'))
    try:
        with contextlib.ExitStack() as holds:
            limit=resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            if limit!=resource.RLIM_INFINITY and limit<len(plan['hold_files'])+64:
                raise ValueError('existing file descriptor limit cannot hold the exact input closure; no override attempted')
            report['source_handle_budget']=len(plan['hold_files']);report['actual_descriptor_soft_limit']=limit
            held=[]
            for item in plan['hold_files']:
                path=verify(item);fd=holds.enter_context(path.open('rb'));fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB);held.append(str(path))
            for name in ('disk.img','OVMF_VARS.fd'):
                fd=holds.enter_context((work/name).open('r+b'));fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            status=host_status();report['launch_host_status']=status;enforce_host(status)
            # No child can exist before this exact point; there is no preparatory QEMU boot.
            argv=command(plan,work,sockdir/'qmp.sock');report['command']=argv;report['held_input_handles']=held
            stderr=holds.enter_context((work/'qemu.stderr').open('xb'))
            def publish_pending():
                report['native_started']=owned['proc'] is not None
                report['owned_pid']=owned['proc'].pid if owned['proc'] is not None else None
                report['os_exit_success']=False
                report['retained_socket_directory']=str(sockdir)
                (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
            # Register before spawn, so every post-Popen exception reaches
            # cleanup while actual source/lock descriptors are still held.
            holds.callback(cleanup_owned,owned,report,publish_pending)
            owned['proc']=subprocess.Popen(argv,cwd=work,stdout=subprocess.DEVNULL,stderr=stderr)
            proc=owned['proc']
            report['native_started']=True;report['owned_pid']=proc.pid
            if hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'):
                try:owned['pidfd']=os.pidfd_open(proc.pid,0)
                except OSError as exc:
                    report['pidfd_acquisition_error']=repr(exc)
                    raise
            fields=(Path('/proc')/str(proc.pid)/'stat').read_text().rpartition(') ')[2].split()
            if len(fields)<20: raise ValueError('owned process start token absent')
            token=int(fields[19]);report['owned_start_ticks']=token
            parent_fields=(Path('/proc')/str(os.getpid())/'stat').read_text().rpartition(') ')[2].split()
            if len(parent_fields)<20:raise ValueError('parent process start token absent')
            report['parent_pid']=os.getpid();report['parent_start_ticks']=int(parent_fields[19])
            print(json.dumps({'event':'owned_native_child_started','case':case,'parent_pid':report['parent_pid'],
                'parent_start_ticks':report['parent_start_ticks'],'qemu_pid':proc.pid,'qemu_start_ticks':token}),flush=True)
            q=QMP(sockdir/'qmp.sock',started+180,proc.pid)
            own_process(proc,argv,token)
            c=Control(q,proc,plan,work,case)
            try:
                s=c.until('first-latch',lambda s:s['latched']==1,seconds=60)
                validate_fault(s,case,plan)
                if case=='text':
                    text=c.frame('ascii-fallback')
                    expected=subprocess.run([plan['reference']['path'],text['state_file'],'640','480','serial'],capture_output=True,timeout=3)
                    if expected.returncode or not expected.stdout.startswith(b'You session got wasted\nEnglish traceback:'):
                        raise ValueError('counted first-record serial reference failed')
                    end=min(q.deadline,time.monotonic()+10)
                    while time.monotonic()<end:
                        log=serial_read(work/'serial.log')
                        if expected.stdout in log: break
                        time.sleep(.1)
                    else: raise ValueError('exact complete English serial fallback absent')
                    c.keys('1','2','l');after=c.sample('text-remains-halted',screen=True)
                    if after['mode']!=0 or after['korean']!=1 or not after['screenshot']['complete_frame_matches']:
                        raise ValueError('text fallback resumed or changed first state')
                else: games(c)
                log=serial_read(work/'serial.log').decode(errors='strict')
                if 'DEAD SCREEN CONTROL: normal GUI preparation status=0;' not in log:
                    raise ValueError('actual GUI/input setup did not succeed')
                if 'display backend UEFI GOP' not in log or 'started directly by the UEFI boot manager (no Supervisor)' not in log:
                    raise ValueError('actual direct UEFI/GOP provenance absent')
                if 'SHZ-EXIT:' in log: raise ValueError('damaged kernel resumed an exit path')
                report['status']='OWN_STANDALONE_NATIVE_CONTROL_OBSERVED'
                report['first_record_sha256']=hashlib.sha256(c.first).hexdigest()
                report['actual_native_fault']=s['fault'];report['observations']=c.observations
            finally:
                if report.get('observations') is None: report['observations']=c.observations
                if proc.poll() is None:
                    own_process(proc,argv,token)
                    try: q.call('quit');report['termination']='owner-QMP-quit-after-observations-or-failure'
                    except Exception as e: report['qmp_quit_error']=repr(e);raise
            proc.wait(timeout=5);report['qemu_returncode']=proc.returncode
            if proc.returncode!=0: raise ValueError('owned QEMU did not exit normally on QMP quit')
            for item in plan['hold_files']: verify(item)
            report['held_input_handles_released_after_child_exit']=True
    except BaseException as e:
        report['status']='FAIL';report['error']=repr(e)
    finally:
        if q: q.close()
        if proc and proc.poll() is None:
            report['status']='FAIL';report['cleanup_failure']='owned child still live; no foreign PID action permitted'
        report['elapsed_seconds']=time.monotonic()-started
        report['qemu_returncode']=proc.returncode if proc else None
        report['os_exit_success']=False
        report['termination_scope']='intentional fatal loop; owner shutdown is not kernel or Win98 OS exit acceptance'
        report['files']=[{'path':str(p),'bytes':p.stat().st_size,'sha256':digest(p)} for p in sorted(work.iterdir()) if p.is_file()]
        if proc is None or proc.poll() is not None:shutil.rmtree(sockdir)
        else:report['retained_socket_directory']=str(sockdir)
        (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--plan',type=Path,required=True);ap.add_argument('--plan-sha256',required=True)
    ap.add_argument('--release',type=Path);ap.add_argument('--out',type=Path)
    ap.add_argument('--guard-only',action='store_true');args=ap.parse_args()
    if digest(args.plan)!=args.plan_sha256: raise ValueError('exact plan hash required')
    plan=read_json(args.plan)
    if plan['status']!='PREPARED_HELD_NO_NATIVE_EXECUTION' or plan['scope']!=SCOPE: raise ValueError('held closed plan required')
    if plan['runner']['path']!=str(Path(__file__).resolve()) or verify(plan['runner'])!=Path(__file__).resolve(): raise ValueError('held runner identity differs')
    for item in plan['hold_files']: verify(item)
    status=host_status()
    if args.guard_only:
        print(json.dumps({'native_started':False,'status':status},indent=2));return 0
    if args.release is None or args.out is None: raise ValueError('reviewed external release and fresh output required')
    validate_release(read_json(args.release,65536),plan,args.plan_sha256,digest(__file__))
    enforce_host(status);out=fresh(args.out);out.mkdir()
    record={'scope':SCOPE,'plan_sha256':args.plan_sha256,'runner_sha256':digest(__file__),
            'release_path':str(args.release),'release_sha256':digest(args.release),
            'native_started':False,'win98_vmm_acceptance':False,'app_success':False,'cases':[],'status':'FAIL'}
    try:
        with contextlib.ExitStack() as locks:
            record['task_private_native_lane']=acquire_native_lane(locks,plan)
            for case in CASES:
                r=run_case(plan,out,case);record['cases'].append(r);record['native_started']|=r['native_started']
                if r['status']!='OWN_STANDALONE_NATIVE_CONTROL_OBSERVED': break
            if len(record['cases'])==3 and all(r['status']=='OWN_STANDALONE_NATIVE_CONTROL_OBSERVED' for r in record['cases']):
                record['status']='OWN_STANDALONE_CONTROLS_OBSERVED_REVIEW_REQUIRED'
    finally:
        (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    return 0 if record['status']=='OWN_STANDALONE_CONTROLS_OBSERVED_REVIEW_REQUIRED' else 1


if __name__=='__main__':
    try: sys.exit(main())
    except Exception as exc: print(str(exc),file=sys.stderr);sys.exit(1)
