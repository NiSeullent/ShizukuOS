#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded opt-in original-MS-DOS Windows98 control on a new owned raw clone.

Existing source disk/OEM/media/running VMs are never writable. This measures an
original Windows control, not ShizukuDOS replacement/native-product acceptance.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import stat
import tempfile
import time

MAX_TRACE=1024*1024
DIRTY_BUDGET=256*1024*1024
RESERVE=20*1024**3
BOOT_FILES=('IO.SYS','MSDOS.SYS','WINDOWS/WIN.COM','COMMAND.COM','WINDOWS/SYSTEM/VMM32.VXD')


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()



def copy_new_reflink(source,destination,expected_sha256):
    """Explicit Linux COW clone: pinned source, independent inode, exact readback.

    Unsupported filesystems fail without a dense fallback. Shared disk extents
    are never interpreted as new physical allocation or general speed evidence.
    """
    destination=Path(destination)
    if os.path.lexists(destination):
        raise FileExistsError(str(destination))
    if not isinstance(expected_sha256,str) or len(expected_sha256)!=64 or any(c not in '0123456789abcdef' for c in expected_sha256):
        raise ValueError('a lowercase SHA-256 source pin is required')
    src=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    target=None
    temporary=None
    previous=signal.getsignal(signal.SIGIO)
    broken=[False]
    leased=False
    try:
        original=os.fstat(src)
        if not stat.S_ISREG(original.st_mode):
            raise ValueError('reflink source must be a regular file')
        signal.signal(signal.SIGIO,lambda *_:broken.__setitem__(0,True))
        fcntl.fcntl(src,fcntl.F_SETOWN,os.getpid())
        fcntl.fcntl(src,fcntl.F_SETLEASE,fcntl.F_RDLCK)
        leased=True
        identity=(original.st_dev,original.st_ino,original.st_size,original.st_mtime_ns,original.st_ctime_ns)
        def checkpoint():
            now=os.fstat(src)
            path_now=os.stat(source,follow_symlinks=False)
            if broken[0] or fcntl.fcntl(src,fcntl.F_GETLEASE)!=fcntl.F_RDLCK or (now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_ctime_ns)!=identity or (path_now.st_dev,path_now.st_ino,path_now.st_size,path_now.st_mtime_ns,path_now.st_ctime_ns)!=identity:
                raise RuntimeError('source read lease or identity changed')
        checkpoint()
        def digest(fd):
            h=hashlib.sha256(); offset=0
            while offset<original.st_size:
                chunk=os.pread(fd,min(1024*1024,original.st_size-offset),offset)
                checkpoint()
                if not chunk: raise OSError('unexpected reflink image EOF')
                h.update(chunk); offset+=len(chunk)
            return h.hexdigest()
        if digest(src)!=expected_sha256:
            raise ValueError('reflink source does not match its pinned SHA-256')
        target,name=tempfile.mkstemp(prefix='.'+destination.name+'.',suffix='.reflink.tmp',dir=destination.parent)
        temporary=Path(name)
        # Linux FICLONE; destination writes break COW and cannot write source.
        fcntl.ioctl(target,0x40049409,src)
        checkpoint()
        os.fsync(target)
        clone=os.fstat(target)
        if clone.st_size!=original.st_size or (clone.st_dev,clone.st_ino)==identity[:2] or digest(target)!=expected_sha256:
            raise RuntimeError('reflink target failed independent exact readback')
        final=os.fstat(src)
        if (final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)!=identity:
            raise RuntimeError('reflink source changed during preparation')
        os.link(temporary,destination,follow_symlinks=False)
        temporary.unlink(); temporary=None
        return {'method':'explicit-linux-FICLONE-COW','bytes':clone.st_size,'sha256':expected_sha256,'source_stable':True,'source_read_lease_verified':True,'target_readback_verified':True,'independent_inode':True,'allocated_bytes':clone.st_blocks*512,'allocation_includes_shared_extents':True}
    finally:
        try:
            if target is not None: os.close(target)
            if temporary is not None: temporary.unlink(missing_ok=True)
            if leased: fcntl.fcntl(src,fcntl.F_SETLEASE,fcntl.F_UNLCK)
        finally:
            os.close(src)
            signal.signal(signal.SIGIO,previous)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(argv,timeout=30):
    result=subprocess.run([str(x) for x in argv],capture_output=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError('bounded command failed: '+str(argv[0]))
    return result.stdout


def get_guest(spec,name):
    return run(['mtype','-i',spec,'::'+name])


def boot_hashes(spec):
    return {name:hashlib.sha256(get_guest(spec,name)).hexdigest() for name in BOOT_FILES}



def check_write_budget(stats,last_value,budget=DIRTY_BUDGET):
    """Fail closed on sampled fresh-QEMU owned-device total write accounting.

    FICLONE st_blocks includes shared extents and is allocation growth only.
    The fresh process counter starts at zero, so early startup writes are also
    counted; never subtract the first sampled counter and lose early writes.
    """
    if not isinstance(stats,list): raise ValueError('blockstats must be a list')
    matches=[s for s in stats if isinstance(s,dict) and s.get('device')=='win98']
    if len(matches)!=1: raise ValueError('exactly one owned win98 block backend is required')
    block=matches[0].get('stats')
    value=block.get('wr_bytes') if isinstance(block,dict) else None
    if type(value) is not int or value<0: raise ValueError('owned wr_bytes must be a nonnegative integer')
    if value<last_value: raise RuntimeError('owned write counter reset or decreased')
    if value>budget: raise RuntimeError('owned guest write counter exceeded its sampled budget')
    return value


def process_input(request,last_sequence,monitor,record,elapsed):
    keys={'sequence','key','purpose','basis_screenshot_sha256'}
    if not isinstance(request,dict) or set(request)!=keys:
        raise ValueError('operator input must contain exactly the qualified Enter fields')
    sequence=request['sequence']
    if type(sequence) is not int or not 1<=sequence<=8:
        raise ValueError('operator sequence must be 1..8')
    if request['key']!='ret' or request['purpose']!='continue-known-optional-device-warning':
        raise ValueError('only explicit Enter for the observed existing warning is allowed')
    basis=request['basis_screenshot_sha256']
    if not isinstance(basis,str) or len(basis)!=64 or basis not in {c.get('screenshot_sha256') for c in record['captures']}:
        raise ValueError('input must name a screenshot captured by this owned run')
    if sequence==last_sequence:
        return sequence
    if sequence!=last_sequence+1:
        raise ValueError('operator input sequence must be contiguous')
    monitor.call('send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':100})
    record['operator_inputs'].append({'sequence':sequence,'key':'ret','purpose':request['purpose'],'basis_screenshot_sha256':basis,'seconds':round(elapsed,3)})
    return sequence


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-run',type=Path,required=True)
    parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--image-io-helper',type=Path,required=True)
    parser.add_argument('--qmp-helper',type=Path,required=True)
    parser.add_argument('--trace-parser',type=Path,required=True)
    parser.add_argument('--harness-source',type=Path,required=True)
    parser.add_argument('--harness-com',type=Path,required=True)
    parser.add_argument('--harness-com-sha256',required=True)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--firmware-code',type=Path,required=True)
    parser.add_argument('--firmware-vars',type=Path,required=True)
    parser.add_argument('--timeout',type=int,default=300)
    parser.add_argument('--reflink',action='store_true',help='require Linux COW clone; fail if unsupported, no dense fallback')
    args=parser.parse_args()
    if not 10<=args.timeout<=300:
        parser.error('timeout must be 10..300 seconds')
    source=(args.source_run/'windows-uefi.raw').resolve(strict=True)
    source_receipt=args.source_run/'result.json'
    prior=json.loads(source_receipt.read_text())
    if prior.get('owned_disk_sha256_after_run')!=args.expected_sha256 or source.stat().st_size!=2*1024**3:
        parser.error('selected source must be the receipt-pinned owned 2 GiB control disk')
    source_identity=(source.stat().st_dev,source.stat().st_ino,source.stat().st_size,source.stat().st_mtime_ns,source.stat().st_ctime_ns)
    args.output.mkdir(mode=0o700)
    output=args.output.resolve()
    if shutil.disk_usage(output).free<RESERVE+2*DIRTY_BUDGET:
        raise RuntimeError('insufficient disk reserve')
    # All dynamically read public helpers are source-snapshotted before import.
    frozen=output/'source'
    frozen.mkdir(mode=0o700)
    sources={}
    for name,path in (('image_io.py',args.image_io_helper),('qmp.py',args.qmp_helper),('parse_trace.py',args.trace_parser),('dosvmm_trace.asm',args.harness_source),('run_original_dos_control.py',Path(__file__))):
        data=path.read_bytes()
        target=frozen/name
        target.write_bytes(data)
        sources[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    image_io=load('control_image_io',frozen/'image_io.py')
    qmp_helper=load('control_qmp',frozen/'qmp.py')
    trace_parser=load('control_trace_parser',frozen/'parse_trace.py')
    record={'status':'CONTROL_PREPARING','scope':'original-MS-DOS/IO.SYS Windows98 measurement; not ShizukuDOS replacement','native_Windows98_complete':False,'ShizukuDOS_replaces_MS_DOS_validated':False,'source_disk_sha256':args.expected_sha256,'source_receipt_sha256':sha(source_receipt),'source_files':sources,'capture_seconds':args.timeout,'trace_budget_bytes':MAX_TRACE,'sampled_write_budget_bytes':DIRTY_BUDGET,'write_counter_sample_seconds':1,'write_budget_verified':False,'captures':[],'operator_inputs':[],'original_boot_path':prior.get('boot_path'),'firmware':{},'guest_execution':False}
    disk=output/'control.raw'
    copied=copy_new_reflink(source,disk,args.expected_sha256) if args.reflink else image_io.copy_new_sparse(source,disk,expected_sha256=args.expected_sha256)
    record['clone']=copied
    record['source_disk_sha256_before']=args.expected_sha256
    partition=prior['partition']
    if partition.get('start_lba')!=63 or partition.get('type')!=12 or not partition.get('active'):
        raise RuntimeError('only the verified active FAT32 LBA63 control is allowed')
    spec=str(disk)+'@@32256'
    originals=boot_hashes(spec)
    record['original_boot_file_sha256']=originals
    with disk.open('rb') as stream:
        mbr=stream.read(512)
        stream.seek(32256)
        vbr=stream.read(512)
    if hashlib.sha256(mbr).hexdigest()!=partition['mbr_sha256'] or hashlib.sha256(vbr).hexdigest()!=partition['boot_sector_sha256']:
        raise RuntimeError('control boot sectors do not match the original receipt')
    original_autoexec=get_guest(spec,'AUTOEXEC.BAT')
    (output/'AUTOEXEC.original').write_bytes(original_autoexec)
    autoexec=b'C:\\DOSVMM.COM /I\r\n'+original_autoexec
    autoexec_path=output/'AUTOEXEC.BAT'
    autoexec_path.write_bytes(autoexec)
    harness=output/'DOSVMM.COM'
    harness.write_bytes(args.harness_com.read_bytes())
    if sha(harness)!=args.harness_com_sha256 or harness.stat().st_size>=4096:
        raise RuntimeError('trace COM does not match the exact compiled host-validated candidate')
    run(['mcopy','-o','-i',spec,harness,'::DOSVMM.COM'])
    run(['mcopy','-o','-i',spec,autoexec_path,'::AUTOEXEC.BAT'])
    if get_guest(spec,'DOSVMM.COM')!=harness.read_bytes() or get_guest(spec,'AUTOEXEC.BAT')!=autoexec:
        raise RuntimeError('own trace files failed exact guest readback')
    if boot_hashes(spec)!=originals:
        raise RuntimeError('injection changed an original boot file')
    with disk.open('rb') as stream:
        if stream.read(512)!=mbr:
            raise RuntimeError('injection changed original MBR')
        stream.seek(32256)
        if stream.read(512)!=vbr:
            raise RuntimeError('injection changed original VBR')
    record['harness_com_sha256']=sha(harness)
    record['harness_com_bytes']=harness.stat().st_size
    record['autoexec_original_sha256']=hashlib.sha256(original_autoexec).hexdigest()
    record['autoexec_instrumented_sha256']=hashlib.sha256(autoexec).hexdigest()
    record['source_boot_sectors_preserved']=True
    record['original_boot_files_preserved_before_vm']=True
    vars_path=output/'OVMF_VARS.fd'
    shutil.copyfile(args.firmware_vars,vars_path)
    record['firmware']={'code_sha256':sha(args.firmware_code),'vars_template_sha256':sha(args.firmware_vars),'fresh_vars_sha256':sha(vars_path),'qemu_sha256':sha(args.qemu)}
    sock=output/'qmp.sock'
    if len(str(sock).encode())>=100:
        raise RuntimeError('owned QMP socket path exceeds safe Unix bound')
    trace=output/'e9.log'
    serial=output/'serial.log'
    argv=[str(args.qemu),'-name','shz-owned-original-dos-vmm-control','-machine','q35,hpet=off','-accel','kvm','-cpu','qemu64','-smp','2','-m','128','-nodefaults','-nic','none','-display','none','-device','VGA','-drive',f'if=pflash,unit=0,format=raw,readonly=on,file={args.firmware_code}','-drive',f'if=pflash,unit=1,format=raw,file={vars_path}','-drive',f'file={disk},format=raw,if=none,id=win98','-device','ide-hd,drive=win98,bus=ide.0,bootindex=1','-serial',f'file:{serial}','-debugcon',f'file:{trace}','-global','isa-debugcon.iobase=0xe9','-qmp',f'unix:{sock},server=on,wait=off','-no-reboot']
    (output/'command.json').write_text(json.dumps(argv,indent=2)+'\n')
    record['command_sha256']=sha(output/'command.json')
    (output/'prepared.json').write_text(json.dumps(record,indent=2)+'\n')
    initial_allocation=disk.stat().st_blocks*512
    child=monitor=None
    start=time.monotonic()
    try:
        with (output/'qemu.stderr').open('wb') as err:
            child=subprocess.Popen(argv,cwd=output,stdout=subprocess.DEVNULL,stderr=err)
            record['owned_pid']=child.pid
            record['guest_execution']=True
            print(json.dumps({'stage':'owned-vm-started','pid':child.pid,'scope':'original MSDOS control','output':str(output)}),flush=True)
            monitor=qmp_helper.QMP(sock,timeout=15)
            next_capture=20
            last_sequence=0
            last_write_bytes=0
            while time.monotonic()-start<args.timeout and child.poll() is None:
                elapsed=time.monotonic()-start
                if trace.exists() and trace.stat().st_size>MAX_TRACE:
                    raise RuntimeError('owned E9 trace exceeded its 1 MiB budget')
                last_write_bytes=check_write_budget(monitor.call('query-blockstats'),last_write_bytes)
                record['sampled_guest_write_bytes']=last_write_bytes
                if disk.stat().st_blocks*512-initial_allocation>DIRTY_BUDGET:
                    raise RuntimeError('owned allocation growth exceeded 256 MiB')
                if shutil.disk_usage(output).free<RESERVE:
                    raise RuntimeError('disk reserve consumed')
                request_path=output/'operator-input.json'
                if request_path.exists():
                    request_bytes=trace_parser.read_bounded(request_path)
                    if len(request_bytes)>4096:
                        raise ValueError('operator request exceeds 4 KiB')
                    request=json.loads(request_bytes)
                    last_sequence=process_input(request,last_sequence,monitor,record,elapsed)
                if elapsed>=next_capture:
                    number=len(record['captures'])
                    stem='screen-%03d'%number
                    capture={'seconds':round(elapsed,2)}
                    try:
                        (output/(stem+'-cpu.txt')).write_text(monitor.hmp('info registers'))
                        capture['cpu_sha256']=sha(output/(stem+'-cpu.txt'))
                        screenshot=output/(stem+'.png')
                        monitor.call('screendump',{'filename':str(screenshot),'format':'png'})
                        capture['screenshot_sha256']=sha(screenshot)
                    except Exception as exc:
                        capture['capture_error']=type(exc).__name__
                    record['captures'].append(capture)
                    (output/'progress.json').write_text(json.dumps(record,indent=2)+'\n')
                    print(json.dumps({'stage':'capture','seconds':capture['seconds'],'trace_bytes':trace.stat().st_size if trace.exists() else 0,'screenshot':bool(capture.get('screenshot_sha256'))}),flush=True)
                    next_capture=elapsed+30
                time.sleep(1)
            last_write_bytes=check_write_budget(monitor.call('query-blockstats'),last_write_bytes)
            record['sampled_guest_write_bytes']=last_write_bytes
            record['write_budget_verified']=True
            record['status']='CONTROL_CAPTURE_COMPLETE_REQUIRES_GUI_REVIEW'
    except (Exception,KeyboardInterrupt) as exc:
        record['status']='CONTROL_CAPTURE_INTERRUPTED' if isinstance(exc,KeyboardInterrupt) else 'CONTROL_CAPTURE_FAILED'
        record['error_type']=type(exc).__name__
        record['error']=str(exc)
    finally:
        if child is not None and child.poll() is None:
            try:
                if monitor is not None:
                    monitor.call('quit')
            except Exception:
                pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        if monitor is not None:
            monitor.close()
        record['qemu_exitcode']=child.returncode if child is not None else None
        record['qemu0_is_not_Windows_success']=True
        record['elapsed_seconds']=round(time.monotonic()-start,3)
        record['original_boot_files_preserved_after_vm']=boot_hashes(spec)==originals
        record['owned_disk_sha256_after_vm']=sha(disk)
        record['source_disk_sha256_after']=sha(source)
        now=source.stat()
        record['source_disk_unchanged']=(now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_ctime_ns)==source_identity and record['source_disk_sha256_after']==args.expected_sha256
        record['source_receipt_unchanged']=sha(source_receipt)==record['source_receipt_sha256']
        record['allocation_growth_bytes']=disk.stat().st_blocks*512-initial_allocation
        record['allocation_growth_is_not_guest_write_count']=True
        if trace.exists():
            record['trace_bytes']=trace.stat().st_size
            record['trace_sha256']=sha(trace)
            try:
                record['measurement']=trace_parser.parse(trace_parser.read_bounded(trace),'windows98-original-control')
            except ValueError as exc:
                record['measurement']={'status':'REJECTED','reason':str(exc)}
        (output/'result.json').write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps({'stage':'complete','status':record['status'],'source_unchanged':record['source_disk_unchanged'],'measurement':record.get('measurement',{}).get('status')}),flush=True)
    return 0 if record['status']=='CONTROL_CAPTURE_COMPLETE_REQUIRES_GUI_REVIEW' and record['source_disk_unchanged'] else 1

if __name__=='__main__':
    raise SystemExit(main())
