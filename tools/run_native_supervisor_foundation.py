#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Root-owned opt-in actual VMX foundation gate; default only validates frozen inputs.

New profile: DOS16 plus native K64/tiny real T_HELLO, with no K32 or Win98 peer.
The original three-domain/DOS/IPC test runner is left unchanged. Nothing here
claims a Windows 98 boot, positive W64 channel or target application execution.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import time

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'shizukudos/kbuild.py').is_file())
BUILD = ROOT/'build/modern-apps/native-foundation-current-build-v2'
RECEIPT_SHA = 'b65ce5dda18fae3d08f934f1ffdac14bbfb64b07e086296a55e9dd838491aad3'
HELPERS = ROOT/'build/modern-apps/native-foundation-runner-source-v1/helpers'
HELPER_PINS = {
    'shizukudos/tools/qemu.py':'aac9c9aed1e975eac1e1a7f7952818ba3804149c55675e2748e27120d72a2bb4',
    'shizukudos/tools/shzinfo.py':'5488e19dba21e57680810cfb5aad35d458e651137171788d3c845bb5fa21291b',
    'shizukudos/tools/shzlib.py':'bcbe177f38f327989b7815d55eaa3046bd8b5e8255753edf072bdf4f0bdb2329',
    'shizukudos/tools/fatimg.py':'c6dcd8c09130002ca9423aaf70ac61f6b34293cb793ad0b5345f4f62ea6f327c',
    'shizukudos/dos16/verify.py':'ad3e85a0cd2fbbc4dc79e87c1fa181f4dc0cb9cdc59adf31f2f6d761f57d8cda',
    'shizukudos/dos16/ints.py':'efc1dd5e0e071ad31fcd74c12c81c15634668c55ca0f3b652e33fb58faf12694',
}
QEMU = Path('/usr/libexec/qemu-kvm')
QEMU_SHA = 'ea9073d267ec64048e8078c5fc0cb0d091bacf11587bdd6b05cf3d46181ffe09'
CODE = Path('/usr/share/edk2/ovmf/OVMF_CODE.fd')
CODE_SHA = '090b9b1872b725cd698d41d9d8987ad3d08ffbe6ea5dab28b973ad7f7b846498'


def sha(path):
    if path.resolve() != path: raise ValueError('canonical regular pinned file required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): raise ValueError('pinned input must be regular')
        h=hashlib.sha256()
        while chunk:=os.read(fd,1<<20): h.update(chunk)
        after=os.fstat(fd);current=os.stat(path,follow_symlinks=False)
        stable=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if stable(before)!=stable(after) or stable(after)!=stable(current): raise ValueError('pinned input changed during read')
    finally: os.close(fd)
    return h.hexdigest()


def inputs():
    receipt=BUILD/'foundation-build-receipt.json'
    if sha(receipt)!=RECEIPT_SHA: raise ValueError('foundation receipt mismatch')
    build=json.loads(receipt.read_text())
    if build['status']!='PASS_NATIVE_FOUNDATION_BUILD_NOT_RUN' or build['standalone_compiled'] or build['VM_executed']:
        raise ValueError('ordinary unexecuted native foundation required')
    pins={receipt:RECEIPT_SHA,QEMU:QEMU_SHA,CODE:CODE_SHA}
    for name,pin in build['sources_sha256'].items(): pins[BUILD/'source'/name]=pin
    for name,pin in build['artifacts'].items(): pins[BUILD/name]=pin
    for name,pin in HELPER_PINS.items(): pins[HELPERS/name]=pin
    if len(build['sources_sha256'])!=221 or len(build['artifacts'])!=6: raise ValueError('foundation source/artifact set mismatch')
    if any(sha(p)!=pin for p,pin in pins.items()): raise ValueError('frozen input drift')
    if CODE.stat().st_size+(BUILD/'OVMF_VARS.fd').stat().st_size != 4<<20: raise ValueError('firmware flash geometry mismatch')
    return pins


def resources(out):
    free=shutil.disk_usage(out.parent).free
    available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M).group(1))*1024
    if free < (17<<30)+(256<<20) or available < (4<<30)+(512<<20):
        raise RuntimeError('required 17 GiB disk plus clone margin / 4 GiB RAM plus guest margin unavailable')
    return {'disk_free_bytes':free,'MemAvailable_bytes':available}


def identity(pid):
    raw=Path(f'/proc/{pid}/stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19])
    argv=Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    return start,argv


def verify_owned(proc,owner,command):
    if proc.poll() is not None: raise RuntimeError('owned QEMU already exited')
    expected=[os.fsencode(x) for x in command]
    first=identity(proc.pid);second=identity(proc.pid)
    if first!=second or first!=(owner,expected): raise RuntimeError('QEMU PID/start/actual argv ownership mismatch')


def native_checks(info,serial,check):
    c=[]
    add=lambda n,v,detail='':c.append(check(n,bool(v),detail))
    # Size is checked independently against ctypes/C by selfcheck and the concrete object.
    import ctypes
    add('actual handoff magic/version/size',info.magic==0x3031505553485a53 and info.version==3 and info.size==ctypes.sizeof(type(info)))
    add('Supervisor guest-exit stage',info.stage==6,info.stage_name())
    add('real L1 VMX/EPT/unrestricted backend',{'LONG_MODE','VMX','VMX_ENABLED','EPT','UNRESTRICTED','BACKEND_VMX'}<=set(info.caps()))
    add('actual CPU vendor/native backend error-free',info.vendor()=='GenuineIntel' and not info.last_error and not info.status)
    add('Supervisor root64 paging/VMXE',info.host_cr0&0x80000001==0x80000001 and info.host_cr4&0x2000 and info.host_efer&0x400)
    add('DOS genuine first/last real-mode VMCS',info.first_exit.valid==1 and not(info.first_exit.cr0&1) and info.last_exit.valid==1 and not(info.last_exit.cr0&1) and info.last_exit.efer==0)
    add('DOS actual normal exit request0',info.guest_exit_requested==1 and info.guest_exit_code==0 and 'SHZ-EXIT:0' in serial)
    add('virtual timer/real I/O/hypercalls',info.injected_irqs>0 and info.io_exits>100 and info.hypercalls>50)
    domains=info.to_dict()['domains'];add('configured DOS16/nativeK64 only',set(domains)=={'DOS16','KERNEL64'},str(sorted(domains)))
    dos=domains.get('DOS16');add('DOS actual domain exit0/no error',dos is not None and dos['state']==3 and dos['exit_code']==0 and not dos['error'])
    d=domains.get('KERNEL64')
    if d is None: return c
    ev=lambda n:d['evidence'][n]
    add('native K64 actual exit0/no domain error',d['state']==3 and d['exit_code']==0 and not d['error'])
    add('K64 real Long Mode VMCS/higher-half RIP',d['last_efer']&0xd01==0xd01 and d['last_cr4']&0x20 and d['last_cs']==8 and d['last_rip']>=0xffffffff80000000)
    add('K64 guest CR0/CR3 matches VMCS',ev(0)&0x80010001==0x80010001 and ev(1)!=0 and ev(1)==d['last_cr3'] and not(ev(1)&0xfff))
    add('native timer/thread/mutex/heap/demand-page tests',ev(2)>=10 and ev(3)==20000 and ev(4)==10000 and ev(5)==16)
    add('native genuine SSE ring3 exits42/42',ev(6)==0x2a002a)
    add('native actual faults contained',ev(7)&0xffffffff==0xc0000096 and ev(8)&0xffffffff==0xc0000005 and ev(9)&0xffffffff==0xc0000005)
    add('native ring3 real8GiB address/pattern',ev(16)==0x200000000 and ev(17)==0x1122334455667788)
    add('native user exception counts',ev(24)&0xffff>=1 and ev(24)>>16>=2)
    add('native physical pages returned',ev(12)==0)
    add('K64 completion marker/zero self-test failures',ev(29)==0x4b363421 and ev(28)==0)
    result=ev(30)
    add('real T_HELLO twice exit7/reaped/no fault',result&0xffffffff==7 and not(result>>32&1) and result>>33&1 and result>>34&1,hex(result))
    add('app-written actual above4GiB/AMD64/argc2',ev(19)==0x140000000 and ev(20)==1 and ev(21)==2)
    add('second real app no page leak and3 initrd files',ev(22)==0 and ev(23)==3)
    add('both actual app console markers',serial.count('hello from Win64 PE32+: argc=2 argv1=first')==2)
    return c


def cpu_views(info,samples):
    views=[]
    for raw in samples:
        register=lambda name:re.search(r'\b'+name+r'=([0-9a-fA-F]{8,16})\b',raw)
        cr0=register('CR0');cr3=register('CR3');efer=register('EFER')
        cs=re.search(r'CS =([0-9a-fA-F]{4}) ([0-9a-fA-F]{8,16})\b',raw)
        real=bool(cr0 and cs and not int(cr0[1],16)&1 and int(cs[2],16)==int(cs[1],16)<<4)
        long_mode=bool(cr0 and cs and efer and int(cr0[1],16)&0x80000001==0x80000001 and int(cs[1],16)==8 and int(efer[1],16)&0x400)
        root=bool(long_mode and cr3 and int(cr3[1],16)==info.host_cr3)
        native=bool(long_mode and cr3 and info.domains[4].last_cr3 and int(cr3[1],16)==info.domains[4].last_cr3)
        views.append({'DOS_real_mode':real,'Supervisor_VMX_root':root,'native_K64_long_mode':native})
    return views


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--timeout',type=int,default=600);ap.add_argument('--execute',action='store_true')
    a=ap.parse_args();out=a.out
    if not 60<=a.timeout<=900 or not out.is_absolute() or out.resolve()!=out or not out.is_relative_to(ROOT/'build/modern-apps') or out.exists():
        ap.error('fresh canonical owned output / bounded60..900 timeout required')
    if not a.execute:
        pins=inputs()
        print(json.dumps({'status':'VALIDATED_NO_VM','input_pins':len(pins),'frozen_build_sha256':RECEIPT_SHA}));return
    out.mkdir();record={'status':'FAIL','VM_executed':False,'Windows98_positive_verified':False,'K32_IPC_configured_or_verified':False,'source_current_private_main_not_consumed':True,'checks':[]}
    proc=pidfd=qmp=None;owner=None;command=[];pins={}
    try:
        pins=inputs()
        record['resources_before']=resources(out)
        sys.path.insert(0,str(HELPERS/'shizukudos/tools'));sys.path.insert(0,str(HELPERS/'shizukudos/dos16'))
        import qemu,shzinfo,verify
        shzinfo.selfcheck(BUILD/'source')
        esp=out/'esp-owned.img';variables=out/'OVMF_VARS-owned.fd'
        shutil.copyfile(BUILD/'source/build/shizukudos/supervisor/esp.img',esp);shutil.copyfile(BUILD/'OVMF_VARS.fd',variables)
        serial=out/'serial.log';sock=out/'qmp.sock'
        command=[str(QEMU),'-name','shz-native-foundation-k64','-machine','q35','-accel','kvm','-cpu','host,+vmx','-m','512M','-smp','1','-nodefaults','-nic','none','-display','none','-device','VGA','-no-reboot',
                 '-drive',f'if=pflash,format=raw,unit=0,readonly=on,file={CODE}',
                 '-drive',f'if=pflash,format=raw,unit=1,file={variables}',
                 '-drive',f'if=none,id=esp,format=raw,file={esp}','-device','virtio-blk-pci,drive=esp,bootindex=1',
                 '-serial',f'file:{serial}','-qmp',f'unix:{sock},server=on,wait=off']
        record['command']=command;record['owned_images']=[str(esp),str(variables)]
        if inputs()!=pins: raise RuntimeError('prelaunch input drift')
        with (out/'qemu.stderr').open('wb') as err:
            proc=subprocess.Popen(command,cwd=out,stdout=subprocess.DEVNULL,stderr=err)
        record['VM_executed']=True;pidfd=os.pidfd_open(proc.pid);owner=identity(proc.pid)[0]
        verify_owned(proc,owner,command);record['owner']={'pid':proc.pid,'starttime':owner,'pidfd_opened':True}
        qmp=qemu.QMP(sock,timeout=20);deadline=time.monotonic()+a.timeout;info=None;samples=[];next_sample=0
        while time.monotonic()<deadline:
            verify_owned(proc,owner,command);resources(out)
            raw=qemu.read_guest_memory(qmp,shzinfo.REGION_BASE,shzinfo.INFO_BYTES,out/'info-current.bin')
            candidate=shzinfo.Info.parse(raw)
            if candidate.magic==shzinfo.MAGIC:
                info=candidate
                if info.stage>=4 and len(samples)<4 and time.monotonic()>=next_sample:
                    samples.append(qemu.cpu_state(qmp));next_sample=time.monotonic()+2
                if info.stage in (6,0xdead): break
            time.sleep(.5)
        if info is None or info.stage!=6: raise RuntimeError('actual native foundation did not finish before bounded deadline')
        if not (info.guest_ram_base and info.guest_ram_size==64<<20 and info.guest_ram_base+info.guest_ram_size<=512<<20
                and info.disk_base and info.disk_base+info.disk_size<=512<<20):
            raise RuntimeError('actual guest RAM/disk addresses leave owned512MiB L1 RAM')
        text=qemu.read_guest_memory(qmp,info.guest_ram_base+0xb8000,4000,out/'b8000.bin')
        disk_size=33546240
        if info.disk_size!=disk_size: raise RuntimeError('actual disk geometry differs from pinned DOS input')
        qemu.read_guest_memory(qmp,info.disk_base,info.disk_size,out/'disk-after.img')
        qmp.call('screendump',{'filename':str(out/'screen.ppm')});qmp.call('quit');proc.wait(timeout=15)
        checks=native_checks(info,serial.read_text(errors='replace'),verify._check)
        dos,result_text=verify.verify_disk(out/'disk-after.img');checks+=dos+verify.verify_screen(qemu.decode_text_page(text))
        views=cpu_views(info,samples)
        checks.append(verify._check('independent L0/KVM registers match actual DOS/root/native VMCS',bool(views) and all(any(v.values()) for v in views),str(views)))
        checks.append(verify._check('owned QEMU normal exit0',proc.returncode==0,str(proc.returncode)))
        unchanged=inputs()==pins;checks.append(verify._check('frozen221-source/six-artifact/reader/firmware inputs unchanged',unchanged))
        record.update(status=verify.overall(checks),checks=checks,info=info.to_dict(),independent_CPU_samples=samples,independent_CPU_views=views,DOS_result_text=result_text)
    except BaseException as exc:
        record['error']=f'{type(exc).__name__}: {exc}'
    finally:
        if qmp: qmp.close()
        if proc and proc.poll() is None:
            try:
                # pidfd binds the unreaped child we created, even if argv checking failed.
                if pidfd is None:
                    pidfd=os.pidfd_open(proc.pid)
                signal.pidfd_send_signal(pidfd,signal.SIGTERM);proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signal.pidfd_send_signal(pidfd,signal.SIGKILL);proc.wait(timeout=5)
            except BaseException as exc: record['owned_stop_error']=f'{type(exc).__name__}: {exc}'
        if pidfd is not None: os.close(pidfd)
        record['qemu_exit_code']=proc.returncode if proc else None
        record['owned_QEMU_stopped']=proc is None or proc.poll() is not None
        if not record['owned_QEMU_stopped']: record['status']='FAIL'
        try:
            record['frozen_inputs_unchanged']=bool(pins) and inputs()==pins
        except BaseException as exc:
            record['frozen_inputs_unchanged']=False;record['final_input_error']=f'{type(exc).__name__}: {exc}'
        if not record['frozen_inputs_unchanged']: record['status']='FAIL'
        record['input_pins']={str(p):v for p,v in pins.items()}
        record['preserved_files']={str(p.relative_to(out)):sha(p) for p in out.iterdir() if p.is_file()}
        (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'status':record['status'],'receipt':str(out/'result.json'),'owned_QEMU_stopped':record['owned_QEMU_stopped']}))
    raise SystemExit(0 if record['status']=='PASS' else 1)


if __name__=='__main__':main()
