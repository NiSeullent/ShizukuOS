#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-only refusal and protocol controls. Never launch QEMU or read a guest."""
import json
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock
sys.dont_write_bytecode=True
import runner
checks=0


def check(ok,message):
    global checks
    checks+=1
    if not ok: raise AssertionError(message)


def rejected(fn,message):
    try:fn()
    except (ValueError,TimeoutError,EOFError,OSError,UnicodeError):check(True,message);return
    raise AssertionError('refusal missing: '+message)


def exchange(response,expect_error=False):
    left,right=socket.socketpair();q=runner.QMP.__new__(runner.QMP)
    q.sock=left;q.buffer=b'';q.ident=0;q.deadline=time.monotonic()+1
    result=[]
    def server():
        try:
            request=b''
            while b'\n' not in request:request+=right.recv(4096)
            result.append(json.loads(request))
            right.sendall(response)
        except (BrokenPipeError,ConnectionResetError):pass
        finally:right.close()
    t=threading.Thread(target=server);t.start()
    try:
        if expect_error:rejected(lambda:q.call('query-status'),'actual bounded protocol refusal')
        else:check(q.call('query-status')=={'running':False},'actual matching response with interleaved event')
    finally:left.close();t.join(timeout=2)
    check(not t.is_alive() and result[0]['id']==1,'bounded host socket/control cleanup')


def main():
    abi=json.loads(Path(sys.argv[1]).read_text());check(abi['state_size']==1352 and abi['fault_size']==424,'actual held-header ABI')
    raw=bytearray(abi['state_size']);check(runner.state_fields(raw,abi)=={'ticks':0,'latched':0,'korean':0,'mode':0,'show_trace':0,'graphics_failed':0},'unlatched boot observation')
    rejected(lambda:runner.state_fields(raw[:-1],abi),'truncated physical read')
    rejected(lambda:runner.state_fields(raw+b'\0',abi),'overlong physical read')
    struct.pack_into('<I',raw,abi['state']['latched'],1)
    struct.pack_into('<I',raw,abi['fault']['frame_count'],1)
    struct.pack_into('<Q',raw,abi['fault']['ip'],0xffffffff8018e31f)
    struct.pack_into('<Q',raw,abi['fault']['frames'],0xffffffff8018e31f)
    raw[abi['fault']['reason']:abi['fault']['reason']+2]=b'x\0'
    s=runner.state_fields(raw,abi);check(s['fault']['frame0']==s['fault']['ip'],'actual frame metadata decode')
    bad=bytearray(raw);struct.pack_into('<I',bad,abi['fault']['frame_count'],9)
    rejected(lambda:runner.state_fields(bad,abi),'excess frame count never rendered')
    bad=bytearray(raw);bad[abi['fault']['reason']:abi['fault']['reason']+160]=b'x'*160
    rejected(lambda:runner.state_fields(bad,abi),'unterminated first record')
    bad=bytearray(raw);struct.pack_into('<I',bad,abi['state']['mode'],3)
    rejected(lambda:runner.state_fields(bad,abi),'foreign mode metadata')
    bad=bytearray(raw);bo=abi['state']['suika']+abi['suika']['ball'];bad[bo+abi['ball']['used']]=1;bad[bo+abi['ball']['level']]=6
    rejected(lambda:runner.state_fields(bad,abi),'invalid rank before host reference')
    # These bytes are the real frozen V4 guest observation, not invented registers.
    captured=Path(sys.argv[3]).read_bytes()
    check(hashlib.sha256(captured).hexdigest()=='b3057c89fdf5556b29ee9785656ce46b85e8796af7026b563cf6c40cc1a709a6','actual raw104 full immutable input')
    fault_plan={'kernel_virtual_start':0xffffffff80100000,'kernel_virtual_end':0xffffffff802656c8,
                'control_ud_ip':0xffffffff8018e31f,'control_panic_return_ip':0xffffffff8018e33e}
    actual=runner.state_fields(captured,abi)
    check(actual['fault']['bp']==0 and actual['fault']['registers_valid']==0,'actual panic zeroBP/caller-only semantics')
    for case in ('panic','text'):
        runner.validate_fault(actual,case,fault_plan);check(True,'actual captured zeroBP valid '+case)
    def validate_bytes(data,case='panic'):
        runner.validate_fault(runner.state_fields(data,abi),case,fault_plan)
    for field,value in [('sp',0),('cr3',0),('ip',0),('ip',0xffffffff8018e33f),('vector',6),('frames',0),('frame_count',0),('frame_count',2),('registers_valid',1)]:
        bad=bytearray(captured)
        struct.pack_into('<I' if field in ('frame_count','registers_valid') else '<Q',bad,abi['fault'][field],value)
        rejected(lambda bad=bad:validate_bytes(bad),'actual capture damaged '+field+'='+str(value))
    for field,value in [('latched',0),('graphics_failed',1)]:
        bad=bytearray(captured);struct.pack_into('<I',bad,abi['state'][field],value)
        rejected(lambda bad=bad:validate_bytes(bad),'actual capture not ready '+field)
    bad=bytearray(captured);bad[abi['fault']['reason']:abi['fault']['reason']+160]=bytes(160)
    rejected(lambda:validate_bytes(bad),'foreign panic reason refused')
    # A clearly labelled synthetic full interrupt-frame host control verifies
    # unchanged #UD gates. No native #UD execution is claimed by these bytes.
    ud=bytearray(captured)
    for field,value in [('ip',fault_plan['control_ud_ip']),('frames',fault_plan['control_ud_ip']),('vector',6)]:
        struct.pack_into('<Q',ud,abi['fault'][field],value)
    struct.pack_into('<I',ud,abi['fault']['registers_valid'],1)
    struct.pack_into('<Q',ud,abi['fault']['reg']+15*8,8)
    validate_bytes(ud,'ud');check(True,'synthetic #UD full frame with rawBP0 accepted')
    for field,value in [('ip',0xffffffff8018e33e),('vector',7),('error',1),('registers_valid',0),('registers_valid',2),('frames',0),('frame_count',0)]:
        bad=bytearray(ud)
        struct.pack_into('<I' if field in ('frame_count','registers_valid') else '<Q',bad,abi['fault'][field],value)
        rejected(lambda bad=bad:validate_bytes(bad,'ud'),'damaged full #UD '+field)
    bad=bytearray(ud);struct.pack_into('<Q',bad,abi['fault']['reg']+15*8,3)
    rejected(lambda:validate_bytes(bad,'ud'),'#UD user CS refused')
    good={'filesystem_free':runner.FLOOR+runner.RUN_HEADROOM,'memory_available':7*1024**3,'required_memory':6*1024**3+512*1024**2,
          'active_qemu_or_emulator':[{'pid':123,'executable':'/foreign/Android/emulator'}]}
    runner.enforce_host(good);check(True,'unrelated emulator allowed within resource capacity')
    rejected(lambda:runner.enforce_host({**good,'filesystem_free':good['filesystem_free']-1}),'strict disk floor/headroom refusal')
    rejected(lambda:runner.enforce_host({**good,'memory_available':0}),'real capacity conflict refusal')
    plan={'candidate_sha256':'c'*64};release={'status':'ROOT_RELEASED_PRIVATE_NATIVE_CONTROL','owner':'root','scope':runner.SCOPE,
        'plan_sha256':'p'*64,'runner_sha256':'r'*64,'candidate_sha256':'c'*64,'no_win98_vmm_acceptance':True}
    runner.validate_release(release,plan,'p'*64,'r'*64);check(True,'exact explicit scope release')
    for key,value in [('status','PREPARED'),('owner','foreign'),('plan_sha256','changed'),('runner_sha256','changed'),('candidate_sha256','changed'),('no_win98_vmm_acceptance',False)]:
        rejected(lambda key=key,value=value:runner.validate_release({**release,key:value},plan,'p'*64,'r'*64),'bad release '+key)
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent,prefix='host-control-') as name:
        d=Path(name);p=d/'input';p.write_bytes(b'owned')
        item={'path':str(p),'bytes':5,'sha256':runner.digest(p)}
        check(runner.verify(item)==p,'actual exact file pin')
        p.write_bytes(b'other');rejected(lambda:runner.verify(item),'same-size changed file')
        p.write_bytes(b'owned');link=d/'link';link.symlink_to(p)
        rejected(lambda:runner.verify({**item,'path':str(link)}),'symlink alias input')
        rejected(lambda:runner.fresh(p),'pre-existing output never overwritten')
        rejected(lambda:runner.fresh(d/'link'/'outside'),'symlink parent escape')
        # Real task-private flock interprocess controls. External lane is only
        # a new host fixture; actual Win98 lock files are never opened here.
        lane=d/'private-lane';lane.write_bytes(b'private lane fixture\n')
        meta=lane.stat()
        lane_plan={'own_native_locks':[str(lane)],'native_lane_identity':{
            'path':str(lane),'device':meta.st_dev,'inode':meta.st_ino,'bytes':lane.stat().st_size,'sha256':runner.digest(lane)}}
        child_lock_code='''import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW)
try:
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
 sys.exit(3)
finally:
 os.close(fd)
'''
        def child_lock():
            return subprocess.run([sys.executable,'-B','-c',child_lock_code,str(lane)],capture_output=True,timeout=3)
        def acquire_test(plan=lane_plan):
            with mock.patch.object(runner,'LOCKS',(lane,)),contextlib.ExitStack() as stack:
                return runner.acquire_native_lane(stack,plan)
        lane_bytes=lane.read_bytes()
        with mock.patch.object(runner,'LOCKS',(lane,)),contextlib.ExitStack() as stack:
            binding=runner.acquire_native_lane(stack,lane_plan)
            check(binding['exclusive'] and binding['inode']==meta.st_ino,'actual task-private lane exclusive acquisition')
            check(child_lock().returncode==3,'second real process refused while private lane held')
            rejected(acquire_test,'second independent file description refused')
            external=d/'external-lane-fixture';external.write_bytes(b'foreign host fixture')
            with external.open('r+b') as ext:
                fcntl.flock(ext,fcntl.LOCK_EX|fcntl.LOCK_NB)
                check(binding['exclusive'] and external.read_bytes()==b'foreign host fixture','independent external fixture lock preserved')
        check(child_lock().returncode==0 and lane.read_bytes()==lane_bytes,'private lane released without content change')
        # An already held external fixture does not prevent the private lane.
        with external.open('r+b') as ext:
            fcntl.flock(ext,fcntl.LOCK_EX|fcntl.LOCK_NB)
            check(acquire_test()['exclusive'],'private lane acquired independently of external host fixture')
        rejected(lambda:acquire_test({**lane_plan,'own_native_locks':['/foreign/lane']}),'foreign lane plan refused')
        wrong={**lane_plan,'native_lane_identity':{**lane_plan['native_lane_identity'],'inode':meta.st_ino+1}}
        rejected(lambda:acquire_test(wrong),'replaced lane inode refused')
        lane.write_bytes(b'private lane changed\n');rejected(acquire_test,'changed lock content refused');lane.write_bytes(lane_bytes)
        lane.write_bytes(b'x'*4097);rejected(acquire_test,'oversized lock content refused');lane.write_bytes(lane_bytes)
        hard=d/'lane-hardlink';os.link(lane,hard);rejected(acquire_test,'ambiguous lock hardlink refused');hard.unlink()
        saved=d/'lane-original';lane.rename(saved);lane.symlink_to(saved)
        rejected(acquire_test,'symlink lane refused');lane.unlink();saved.rename(lane)
        saved=d/'lane-original';lane.rename(saved);rejected(acquire_test,'missing private lane refused');saved.rename(lane)
        listener=socket.socket(socket.AF_UNIX);sock=d/'peer.sock';listener.bind(str(sock));listener.listen(1)
        def foreign_peer():
            c,_=listener.accept()
            with c:
                try:c.sendall(b'{"QMP":{}}\n')
                except (BrokenPipeError,ConnectionResetError):pass # refused client deliberately closes before greeting
        t=threading.Thread(target=foreign_peer);t.start()
        try:rejected(lambda:runner.QMP(sock,time.monotonic()+1,os.getpid()+999999),'foreign real Unix peer PID')
        finally:listener.close();t.join(timeout=2)
        check(not t.is_alive(),'foreign-peer host fixture cleanup')
        # Actual compiled C input/IO controls, explicitly synthetic host state.
        state=d/'synthetic-host-state.bin';state.write_bytes(raw);reference=sys.argv[2]
        out=subprocess.run([reference,state,'640','480','serial'],capture_output=True,timeout=3)
        check(out.returncode==0 and out.stdout.startswith(b'You session got wasted\nEnglish traceback:') and b'IP=0xffffffff8018e31f' in out.stdout,'compiled counted English formatter uses supplied fixture bytes')
        check(state.read_bytes()==raw,'host formatter never changes its borrowed input')
        for data in (raw[:-1],raw+b'\0'):
            state.write_bytes(data);r=subprocess.run([reference,state,'640','480','graphics'],capture_output=True,timeout=3)
            check(r.returncode!=0 and not r.stdout,'compiled reference refuses truncated/extra owner bytes')
        state.write_bytes(raw);r=subprocess.run([reference,state,'640','480','graphics'],capture_output=True,timeout=3)
        check(r.returncode==0 and runner.ppm(r.stdout)[:2]==(640,480),'compiled held C renderer real pixels from host fixture')
        r=subprocess.run([reference,state,'640','480','unsupported'],capture_output=True,timeout=3)
        check(r.returncode!=0 and not r.stdout,'compiled reference refuses arbitrary mode')
        # Exercise lifetime ordering with actual open input handles; simulate
        # host signal failure, not native kernel execution or QEMU behavior.
        for behavior in ('term','kill','stuck','receipt-fails'):
            report={'status':'FAIL'};events=[]
            class SimulatedChild:
                def __init__(self):self.code=None;self.waits=0;self.pid=123456 # host model only; never an OS signal target
                def poll(self):return self.code
                def terminate(self):
                    events.append('term');check(not held.closed,'source handle live during terminate')
                    if behavior=='term':self.code=-15
                    elif behavior in ('stuck','receipt-fails'):raise OSError('injected host terminate failure')
                def kill(self):
                    events.append('kill');check(not held.closed,'source handle live during kill')
                    if behavior=='kill':self.code=-9
                    else:raise OSError('injected host kill failure')
                def wait(self,timeout):
                    check(not held.closed,'source handle live through child wait');self.waits+=1
                    if self.code is not None:return self.code
                    if timeout==1 and self.waits>=3:self.code=-9;return -9
                    raise subprocess.TimeoutExpired('simulated-owned-child',timeout)
            def pending():
                events.append('pending');check(not held.closed,'source handle retained while cleanup pending')
                if behavior=='receipt-fails':raise OSError('injected receipt IO failure')
            with contextlib.ExitStack() as stack:
                held=stack.enter_context(p.open('rb'));child=SimulatedChild()
                stack.callback(runner.cleanup_owned,{'proc':child,'pidfd':None},report,pending)
            check(held.closed and child.poll() is not None and report['status']=='FAIL','source handles close only after stopped simulated child')
            check(report['forced_termination'] and report['source_handles_retained_until_owned_child_exit'],'every forced cleanup failed without false lifetime proof')
            check(report['native_started'] and report['owned_pid']==child.pid,'interrupted caller bookkeeping retains actual owned launch truth')
            if behavior in ('stuck','receipt-fails'):check('pending' in events and report['cleanup_eventually_stopped'],'failed bounded cleanup retains ownership until eventual exit')
            if behavior=='receipt-fails':check('pending_receipt_io_failure' in report,'failed receipt does not release live-child handles')
        # Execute actual run_case's error seam with a real closed Python child.
        # QEMU argv is intercepted and NEVER executed. An injected pidfd/token
        # acquisition failure must stop/reap that exact child before unwind.
        disk=d/'disk.input';var=d/'vars.input';disk.write_bytes(b'private disk fixture');var.write_bytes(b'private vars fixture')
        def pin(path):return {'path':str(path),'bytes':path.stat().st_size,'sha256':runner.digest(path)}
        closed_plan={'cases':{'panic':{'disk.img':pin(disk),'OVMF_VARS.fd':pin(var)}},'hold_files':[pin(p)],
            'tools':{'qemu':{'path':'/MUST-NOT-LAUNCH/QEMU'}},'firmware_code':{'path':'/private/fixture/code.fd'},'rom_directory':'/private/fixture/roms'}
        real_popen=subprocess.Popen;created=[]
        def safe_spawn(argv,**kwargs):
            check(argv[0]=='/MUST-NOT-LAUNCH/QEMU','actual run_case remains closed to QEMU')
            child=real_popen([sys.executable,'-c','import time; time.sleep(60)'],stdout=kwargs['stdout'],stderr=kwargs['stderr']);created.append(child);return child
        with mock.patch.object(runner.subprocess,'Popen',side_effect=safe_spawn),mock.patch.object(runner,'host_status',return_value=good),mock.patch.object(runner.os,'pidfd_open',side_effect=OSError('injected token acquisition failure')):
            result=runner.run_case(closed_plan,d,'panic')
        check(len(created)==1 and created[0].poll() is not None and result['status']=='FAIL','actual spawn/token failure reaps only own closed host child')
        check(result['forced_termination'] and result['source_handles_retained_until_owned_child_exit'],'actual failure path cleanup runs before handles release')
        check(not result['os_exit_success'],'host cleanup is never OS success')
    exchange(b'{"event":"STOP"}\n{"id":1,"return":{"running":false}}\n')
    exchange(b'{"id":2,"return":{}}\n',True)
    exchange(b'{"id":1,"error":{"class":"GenericError"}}\n',True)
    exchange(b'not-json\n',True)
    exchange(b'{"event":"STOP"}\n'*65,True)
    exchange(b'x'*65537,True)
    exchange(b'',True)
    rejected(lambda:runner.ppm(b'P6\n4097 480\n255\n'),'oversized screenshot')
    rejected(lambda:runner.ppm(b'P6\n640 480\n255\n'+b'\0'*(640*480*3-1)),'truncated actual pixels')
    w,h,data=runner.ppm(b'P6\n640 480\n255\n'+b'\0'*(640*480*3));check((w,h,len(data))==(640,480,921600),'bounded PPM decode')
    argv=runner.command({'tools':{'qemu':{'path':'/owned/qemu'}},'firmware_code':{'path':'/owned/code.fd'},'rom_directory':'/owned/roms'},Path('/owned/output'),Path('/owned/qmp.sock'))
    check(argv[argv.index('-smp')+1]=='1' and argv[argv.index('-net')+1]=='none' and '-enable-kvm' not in argv,'single CPU TCG/no network explicit device plan')
    print(json.dumps({'status':'PASS','checks':checks,'qemu_or_guest_started':False,'scope':'host malformed/ownership/resource/release/actual Unix protocol controls'}))

if __name__=='__main__':main()
