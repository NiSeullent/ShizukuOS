# SPDX-License-Identifier: GPL-2.0-only
"""Owned cold original-Windows observation, never production source approval.

No VM launch occurs on import. A private request pins the actual source, tools
and observer. Only this process owns its newly launched child and QMP reader.
"""
import fcntl, hashlib, importlib.util, io, json, os, select, signal, stat, struct, subprocess, sys, time
from pathlib import Path

REPO=Path(__file__).resolve().parents[3]
FLOOR=20535312384
GROWTH_FLOOR=17<<30
NAMES={'BASEOBS.EXE','BASENONC.BIN','BASEOBS.JSON'}

def need(ok,message):
    if not ok:raise ValueError(message)

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

replacement=load(REPO/'shizukudos/win98_boot/prepare_replacement.py','baseline_replacement')
capture=load(REPO/'shizukudos/supervisor/native_win98/owned_capture.py','baseline_capture')

def sha(data):return hashlib.sha256(data).hexdigest()

def unique(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,'duplicate JSON key');result[k]=v
    return result

def report(raw,nonce):
    need(type(nonce) is bytes and len(nonce)==32 and any(nonce),'fresh owner nonce32 required')
    need(0<len(raw)<=4<<20,'bounded fresh observer report required')
    row=json.loads(raw,object_pairs_hook=unique)
    fields={'schema','nonce_hex','platform_id','major','minor','build_raw','scope','devices','display_count',
            'observation_only','source_approval','Windows98_on_ShizukuDOS'}
    need(type(row) is dict and set(row)==fields,'exact observer schema required')
    need(row['schema']=='shizukuos.win98-baseline-observation.v1' and row['nonce_hex']==nonce.hex(),'current owner nonce differs')
    need(all(type(row[k]) is int for k in ('platform_id','major','minor','build_raw','display_count')) and
         (row['platform_id'],row['major'],row['minor'])==(1,4,10) and 0<=row['build_raw']<1<<32,'actual Win9x4.10 observation required')
    need(row['observation_only'] is True and row['source_approval'] is False and row['Windows98_on_ShizukuDOS'] is False,'observation-only scope required')
    need(row['scope']=='Win9x4.10 and HKLM Enum Display Class/Driver only','observer scope differs')
    need(type(row['devices']) is list and 1<=len(row['devices'])<=16384 and row['display_count']==len(row['devices']),'bounded Display inventory required')
    seen=set()
    for device in row['devices']:
        need(type(device) is dict and set(device)=={'enum_key','driver'},'readonly Display device fields required')
        need(all(type(device[k]) is str and len(device[k])<=256 and '\x00' not in device[k] for k in device),'bounded actual Enum fields required')
        need(device['enum_key'].startswith('Enum\\') and device['enum_key'] not in seen,'unique actual Enum device required');seen.add(device['enum_key'])
    return row

def root_entries(fd,g,check):
    """Read actual FAT root entries including validated VFAT long file names."""
    volume=replacement.Volume(fd,g,check);out={};pending=[]
    if g['root_cluster']:
        chunks=(volume.cluster(c) for c in volume.chain(g['root_cluster']))
    else:
        chunks=[volume.read((g['start_lba']+g['reserved']+g['fats']*g['fat_sectors'])*512,g['root_sectors']*512)]
    for block in chunks:
        for at in range(0,len(block),32):
            check();row=block[at:at+32]
            if row[0]==0:return out
            if row[0]==0xe5:pending=[];continue
            if row[11]==15:
                need(len(pending)<20,'bounded LFN sequence required');pending.append(row);continue
            short=row[:8].rstrip(b' ').decode('cp437');ext=row[8:11].rstrip(b' ').decode('cp437')
            name=short+('.'+ext if ext else '')
            if pending:
                count=pending[0][0]&31;checksum=0
                for value in row[:11]:checksum=(((checksum&1)<<7)+(checksum>>1)+value)&255
                need(1<=count<=20 and len(pending)==count and pending[0][0]==count|64,'complete LFN sequence required')
                words=[]
                for n,item in enumerate(pending):
                    need(item[0]==(count-n|(64 if n==0 else 0)) and item[12]==0 and item[13]==checksum and item[26:28]==b'\0\0','valid LFN checksum/order required')
                for item in reversed(pending):
                    words.extend(struct.unpack('<13H',item[1:11]+item[14:26]+item[28:32]))
                if 0 in words:
                    end=words.index(0);need(all(v==65535 for v in words[end+1:]),'valid LFN terminator required');words=words[:end]
                need(0<len(words)<=255 and 65535 not in words,'valid LFN characters required')
                name=struct.pack('<%dH'%len(words),*words).decode('utf-16le');pending=[]
            if row[11]&8 or name in ('.','..'):continue
            key=name.upper();need(key not in out,'duplicate FAT root name')
            out[key]={'directory':bool(row[11]&16),'cluster':replacement.u16(row,26)|((replacement.u16(row,20)<<16) if g['fat_bits']==32 else 0),'bytes':replacement.u32(row,28)}
    return out

def geometry(fd,size):
    mbr=os.pread(fd,512,0);active=[replacement.u32(mbr,454+n*16) for n in range(4) if mbr[446+n*16]==128]
    need(len(active)==1,'one active FAT partition required')
    return replacement.inspect_geometry(mbr,os.pread(fd,512,active[0]*512),size)

def reap(child,pidfd,monitor=None):
    """Never release original leases before the newly owned child is reaped."""
    if child is None:return
    if child.poll() is None and monitor is not None:
        monitor.pump=lambda:None;monitor.deadline=time.monotonic()+5
        try:monitor.call('quit')
        except BaseException:pass
    try:child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        for number,timeout in ((signal.SIGTERM,3),(signal.SIGKILL,None)):
            if child.poll() is None:
                try:
                    if pidfd is not None:signal.pidfd_send_signal(pidfd,number)
                    else:child.send_signal(number) # Only same newly owned Popen, never attached PID.
                except ProcessLookupError:pass
            try:child.wait(timeout=timeout);break
            except subprocess.TimeoutExpired:continue

class InputGuard:
    """Immediate shared SIGIO refusal, fixed one-second namespace sweeps.

    leased_inputs checkpoints share one break latch. Checking the original
    source entry therefore catches SIGIO on ANY union member on every FAT IO.
    No caller controls the sweep interval. A full sweep is also forced at each
    tool/launch/observation/readback boundary; FD leases remain held throughout.
    """
    def __init__(self,held,source,deadline,cancel,resource):
        self.held=held;self.source=source;self.deadline=deadline
        self.cancel=cancel;self.resource=resource;self.last=None;self.previous=None
        self.clone_check=lambda:None
    def __call__(self,force=False):
        now=time.monotonic()
        need(not self.cancel[0] and now<self.deadline and
             (self.previous is None or now>=self.previous),'bounded phase cancelled or clock moved backwards')
        self.previous=now
        self.held[self.source]['checkpoint']() # Actual same-union ANY-input SIGIO latch.
        self.clone_check();self.resource()
        if force or self.last is None or now-self.last>=1:
            for entry in self.held.values():entry['checkpoint']()
            end=time.monotonic()
            need(end>=now and end<self.deadline and end-now<=1,'bounded phase or one-second namespace sweep expired')
            self.held[self.source]['checkpoint']()
            self.last=now # measured from start, not end; no added caller-chosen grace.
            self.previous=end

_OBSERVATION_KEY=object()
class OwnedObservation:
    """Only the fixed successful control issues this live observation hold."""
    def __init__(self,key,check,held,source,clone_fd,clone_pin,pidfd,child,observed):
        need(key is _OBSERVATION_KEY,'fixed-control observation issuer required')
        import threading
        self._pid=os.getpid();self._thread=threading.get_ident();self._active=True
        self._guard=check;self._held=held;self._source=source;self._clone_fd=clone_fd
        self._clone_pin=clone_pin;self._pidfd=pidfd;self._child=child;self._observed=json.loads(json.dumps(observed))
    def __reduce__(self):raise TypeError('live observation cannot be serialized')
    def check(self):
        import threading
        need(self._active and self._pid==os.getpid() and self._thread==threading.get_ident(),'observation owner lifetime differs')
        self._guard(True)
        need(self._child.poll() is not None and select.select([self._pidfd],[],[],0)[0],'actual owned child must remain reaped')
    def summary(self):
        self.check();source=self._held[self._source['path']]
        return {'grade':'SOURCE_AND_OBSERVATION_CUSTODY_ONLY','source':dict(self._source),
                'source_identity':list(source['identity']),'clone':dict(self._clone_pin),
                'observation':json.loads(json.dumps(self._observed)),
                'source_approval':False,'Windows98_on_ShizukuDOS':False}
    def finish(self):
        self.check()
        for entry in self._held.values():need(replacement.hash_fd(entry['fd'],entry['pin']['bytes'],self._guard)==entry['pin']['sha256'],'held producer input final SHA differs')
        need(replacement.hash_fd(self._clone_fd,self._clone_pin['bytes'],self._guard)==self._clone_pin['sha256'],'held observed clone final SHA differs')
        self.check()

def run(request, retain=None):
    need(type(request) is dict and set(request)=={'schema','source','observer','observer_receipt','qemu','mcopy','lock','output','guest_seconds'},'exact private control request required')
    need(request['schema']=='shizukuos.private-baseline-control.v1' and type(request['guest_seconds']) is int and 1<=request['guest_seconds']<=600,'bounded600s guest request required')
    out=replacement.safe_path(request['output']);need(not out.exists() and out.parent.is_dir(),'fresh private output required')
    need(out.parent.stat().st_uid==os.getuid() and stat.S_IMODE(out.parent.stat().st_mode)==0o700,'owned0700 output parent required')
    import shutil
    need(shutil.disk_usage(out.parent).free>=FLOOR,'fresh launch resource reserve required')
    source=request['source'];replacement.pin_fields(source)
    original=Path(source['path']).lstat()
    need(stat.S_ISREG(original.st_mode) and original.st_uid==os.getuid() and original.st_nlink==1 and stat.S_IMODE(original.st_mode)==0o400 and source['bytes']==2<<30,'owned0400 exact2GiB original required')
    rows=[source,request['observer'],request['observer_receipt'],request['qemu'],request['mcopy']]
    for path in (Path(__file__),Path(replacement.__file__),Path(capture.__file__)):
        rows.append(replacement.local_pin(path))
    phase_deadline=time.monotonic()+900;cancel=[False]
    previous={s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    for s in previous:signal.signal(s,lambda *_:cancel.__setitem__(0,True))
    lock=os.open(replacement.safe_path(request['lock']),os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    clone_fd=pidfd=child=monitor=logs=held_context=None;frozen_clone=None;held=None
    result={'schema':'shizukuos.private-baseline-control-result.v1','observation_only':True,'source_approval':False,'Windows98_on_ShizukuDOS':False,'VM_started':False,'observer_invoked':False}
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        out.mkdir(mode=0o700)
        held_context=replacement.leased_inputs(rows);held=held_context.__enter__()
        def resource():need(shutil.disk_usage(out).free>=GROWTH_FLOOR,'17GiB reserve breached')
        check=InputGuard(held,source['path'],phase_deadline,cancel,resource)
        def clone_check():
            if frozen_clone is not None:
                need(fcntl.fcntl(clone_fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK and replacement.identity(os.fstat(clone_fd))==frozen_clone and replacement.identity(clone.stat())==frozen_clone,'completed clone read lease/identity differs')
        check.clone_check=clone_check;check(True)
        receipt_entry=held[request['observer_receipt']['path']]
        need(receipt_entry['pin']['bytes']<=2<<20,'bounded actual observer producer receipt required')
        receipt=json.loads(os.pread(receipt_entry['fd'],receipt_entry['pin']['bytes'],0),object_pairs_hook=unique)
        need(receipt.get('artifact')==request['observer'] and receipt.get('VM_executed') is False and receipt.get('source_approval') is False,'actual nonexecuted observer producer binding required')
        producer_rows=[p for key in ('source_pins','compiler_header_pins','tool_pins','import_library_pins') for p in receipt[key].values()]
        held.add_inputs(producer_rows);check(True)
        need(set(receipt['source_pins'])=={'shizukudos/install/live_baseline/build.py','shizukudos/install/live_baseline/observer.c','shizukudos/win98_boot/prepare_replacement.py'},'exact actual observer source closure required')
        for name,p in receipt['source_pins'].items():need(p['sha256']==replacement.local_pin(REPO/name)['sha256'],'actual observer source binding differs')
        entry=held[source['path']];clone=out/'control.raw'
        clone_fd=os.open(clone,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        fcntl.ioctl(clone_fd,0x40049409,entry['fd']);os.fsync(clone_fd)
        need(replacement.hash_fd(clone_fd,source['bytes'],check)==source['sha256'],'FICLONE original readback differs')
        g=geometry(clone_fd,source['bytes']);before=replacement.inventory(clone_fd,g,check)
        need(not (NAMES&root_entries(clone_fd,g,check).keys()),'no previous observer/nonce/report allowed')
        boot=(os.pread(clone_fd,512,0),os.pread(clone_fd,512,g['start_lba']*512))
        nonce=os.urandom(32);need(any(nonce),'nonzero fresh owner nonce required')
        observer=held[request['observer']['path']];pe=os.pread(observer['fd'],observer['pin']['bytes']+1,0)
        need(len(pe)==observer['pin']['bytes'] and pe[:2]==b'MZ' and sha(pe)==observer['pin']['sha256'],'exact actual observer executable required')
        stage=out/'stage';stage.mkdir(mode=0o700)
        for name,data in (('BASEOBS.EXE',pe),('BASENONC.BIN',nonce)):
            with (stage/name).open('xb') as f:need(f.write(data)==len(data),'complete staged input required')
            env={**os.environ,'MTOOLSRC':'/dev/null'}
            check(True)
            subprocess.run(['mcopy','-i','/proc/self/fd/%d@@%d'%(clone_fd,g['start_lba']*512),str(stage/name),'::'+name],executable=request['mcopy']['path'],pass_fds=(clone_fd,),env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=30)
            check(True)
        after=replacement.inventory(clone_fd,g,check)
        need(set(after)==set(before)|{'BASEOBS.EXE','BASENONC.BIN'} and all(after[k]==v for k,v in before.items()),'only appended payloads may change FAT inventory')
        need(after['BASEOBS.EXE']['sha256']==sha(pe) and after['BASENONC.BIN']['sha256']==sha(nonce),'actual payload FAT readback differs')
        need(boot==(os.pread(clone_fd,512,0),os.pread(clone_fd,512,g['start_lba']*512)),'original boot sectors changed')
        os.fsync(clone_fd);check(True);need(shutil.disk_usage(out).free>=FLOOR,'fresh launch resource reserve required')
        logs=capture.BoundedLogs(out)
        argv=[request['qemu']['path'],'-name','win98-nonce-observation','-machine','pc-i440fx-rhel10.0.0','-accel','tcg','-cpu','qemu64','-m','128M','-smp','1','-nic','none','-display','none','-vga','std','-drive','if=ide,index=0,format=raw,file=/proc/self/fd/%d'%clone_fd,'-boot','order=c','-qmp','unix:%s/qmp.sock,server=on,wait=off'%out,'-serial','none','-monitor','none']
        child=subprocess.Popen(argv,cwd=out,stdout=subprocess.DEVNULL,stderr=logs.writers['native-qemu.stderr'],pass_fds=(clone_fd,));pidfd=os.pidfd_open(child.pid);logs.close_writers()
        check(True)
        admission=time.monotonic()+.25
        actual=Path('/proc/%d/cmdline'%child.pid).read_bytes()
        while not actual and child.poll() is None and time.monotonic()<admission:
            time.sleep(.005);actual=Path('/proc/%d/cmdline'%child.pid).read_bytes()
        need(actual.rstrip(b'\0').split(b'\0')==[v.encode() for v in argv],'actual owned argv differs')
        actual_exe=Path('/proc/%d/exe'%child.pid).stat();pinned_exe=os.fstat(held[request['qemu']['path']]['fd'])
        need((actual_exe.st_dev,actual_exe.st_ino)==(pinned_exe.st_dev,pinned_exe.st_ino),'actual owned executable differs')
        deadline=min(time.monotonic()+request['guest_seconds'],phase_deadline);result.update(VM_started=True,owned_pid=child.pid,guest_seconds=request['guest_seconds'])
        def pump():
            check();logs.pump();need(time.monotonic()<deadline,'guest deadline reached')
        monitor=capture.OwnedQMP(out/'qmp.sock',child.pid,deadline,pump=pump)
        next_screen=0;index=0
        try:
            while child.poll() is None and time.monotonic()<deadline:
                pump()
                if (out/'STOP').exists():break
                if (out/'OBSERVE').exists() and not result['observer_invoked']:
                    # Explicit owner action after inspecting actual current desktop; no timer promotion.
                    check(True)
                    need((out/'OBSERVE').read_bytes()==b'EXECUTE_AFTER_OBSERVED_WIN98_DESKTOP\n','exact explicit desktop-reviewed action required')
                    monitor.call('send-key',{'keys':[{'type':'qcode','data':'meta_l'},{'type':'qcode','data':'r'}],'hold-time':100})
                    time.sleep(.5);pump()
                    for key in ['c',('shift','semicolon'),'backslash',*list('baseobs'),'dot',*list('exe'),'ret']:
                        codes=key if isinstance(key,tuple) else (key,)
                        monitor.call('send-key',{'keys':[{'type':'qcode','data':k} for k in codes],'hold-time':60});time.sleep(.08);pump()
                    check(True);result['observer_invoked']=True
                if time.monotonic()>=next_screen:
                    check(True)
                    image=out/('screen-%03d.png'%index);monitor.call('screendump',{'filename':str(image),'format':'png'})
                    need(image.stat().st_size<=16<<20 and index<91 and sum(p.stat().st_size for p in out.glob('screen-*.png'))<=64<<20,'bounded private capture required')
                    check(True);index+=1;next_screen=time.monotonic()+10
                capture.atomic_json(out/'status.json',result);logs.pump(timeout=.1)
        finally:
            # Cleanup continues independently of guest deadline/cancellation.
            reap(child,pidfd,monitor)
            monitor.close();monitor=None;logs.pump(check=False);logs.close();logs=None
        need(child.poll() is not None and select.select([pidfd],[],[],0)[0],'actual child reap required')
        check(True);os.fsync(clone_fd);os.close(clone_fd);clone_fd=os.open(clone,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fcntl.fcntl(clone_fd,fcntl.F_SETOWN,os.getpid());fcntl.fcntl(clone_fd,fcntl.F_SETLEASE,fcntl.F_RDLCK);frozen_clone=replacement.identity(os.fstat(clone_fd))
        check(True)
        entries=root_entries(clone_fd,g,check);need(result['observer_invoked'] and 'BASEOBS.JSON' in entries,'actual fresh guest output required')
        member=entries['BASEOBS.JSON'];need(not member['directory'] and 0<member['bytes']<=4<<20,'bounded actual guest report required')
        output=io.BytesIO();replacement.Volume(clone_fd,g,check).file(member['cluster'],member['bytes'],output)
        observed=report(output.getvalue(),nonce);check(True)
        need(replacement.hash_fd(entry['fd'],source['bytes'],check)==source['sha256'],'original final SHA differs')
        for held_entry in held.values():need(replacement.hash_fd(held_entry['fd'],held_entry['pin']['bytes'],check)==held_entry['pin']['sha256'],'retained producer input differs')
        check(True)
        result.update(status='FRESH_GUEST_OBSERVATION_ONLY',report_sha256=sha(output.getvalue()),observed=observed,source_unchanged=True,actual_child_reaped=True,clone_sha256=replacement.hash_fd(clone_fd,source['bytes'],check))
        check(True)
        if retain is not None:
            need(callable(retain),'live hold hook required')
            observation=OwnedObservation(_OBSERVATION_KEY,check,held,source,clone_fd,{'path':str(clone),'bytes':source['bytes'],'sha256':result['clone_sha256']},pidfd,child,observed)
            try:
                retain(observation) # Lifetime/challenge serving only; return value never affects grade.
                observation.finish()
            finally:observation._active=False
        check(True)
        capture.atomic_json(out/'result.json',result)
        return result
    finally:
        reap(child,pidfd,monitor)
        if monitor is not None:monitor.close()
        if logs is not None:logs.pump(check=False);logs.close()
        for fd in (clone_fd,pidfd,lock):
            if fd is not None:os.close(fd)
        try:
            if held_context is not None:
                try:
                    # Cleanup already reaped the owned child. Always sweep before release,
                    # even on cancellation; a phase exception cannot waive FD validation.
                    if held is not None:
                        for entry in held.values():entry['checkpoint']()
                finally:held_context.__exit__(*sys.exc_info())
        finally:
            for s,handler in previous.items():signal.signal(s,handler)

if __name__=='__main__':
    need(len(sys.argv)==2,'one private pinned control request path required')
    raw=Path(sys.argv[1]).read_bytes();need(len(raw)<=16384,'bounded request required');run(json.loads(raw,object_pairs_hook=unique))
