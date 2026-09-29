#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot own AHCI code against one disposable patterned disk, never host disks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import threading
import time

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
BUILD=HERE/'build'
spec=importlib.util.spec_from_file_location('sd32_guest_contracts',HERE.parent/'uefi32/test_qemu.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def pattern(lba):
    return bytes((i*37+0x5a+lba*13)&255 for i in range(512))

def headroom():
    for proc in Path('/proc').glob('[0-9]*/cmdline'):
        try: command=proc.read_bytes()
        except (FileNotFoundError,PermissionError,ProcessLookupError): continue
        if b'qemu' in command and any(name in command for name in
                (b'win98-modern-private-install',b'zuku-compat-',b'ntw-ahci-fixture')):
            raise RuntimeError('Another compatibility guest is active; coordinate before booting')
    values=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(values['MemAvailable'].split()[0])*1024 < (6*1024+512)*1024**2:
        raise RuntimeError('Insufficient RAM headroom')
    if shutil.disk_usage(BUILD).free < 20*1024**3+32*1024**2:
        raise RuntimeError('Insufficient disk headroom')

def read_proof(qmp,directory):
    path=directory/'ahci-proof.bin'
    qmp.call('pmemsave',{'val':0x0200f100,'size':80,'filename':str(path)})
    names=('magic size calibrated ticks_per_us start_tsc stage pci_bdf abar open_result '
           'read_result close_result sectors_low sectors_high bytes_verified mismatch '
           'last_is last_tfd last_serr quarantine').split()
    proof=dict(zip(names,struct.unpack('<4IQ14I',path.read_bytes())))
    return proof

def main():
    (BUILD/'qemu-result.json').unlink(missing_ok=True)
    headroom()
    build_receipt=BUILD/'build-result.json'
    build_bytes=build_receipt.read_bytes()
    build_hash=hashlib.sha256(build_bytes).hexdigest()
    built=json.loads(build_bytes)
    artifact=BUILD/'BOOTX64.EFI'
    artifact_bytes=artifact.read_bytes()
    artifact_hash=hashlib.sha256(artifact_bytes).hexdigest()
    if artifact_hash!=built['efi']['sha256']: raise RuntimeError('EFI artifact hash mismatch')
    for name,expected in built['sources_sha256'].items():
        if digest(REPO/name)!=expected: raise RuntimeError('Source changed since build: '+name)
    directory=Path(tempfile.mkdtemp(prefix='qemu-',dir=BUILD));directory.chmod(0o700)
    # Copy the same bytes that were validated, even if another build replaces
    # the public artifact path while the guest is being prepared.
    staged=directory/'tested-BOOTX64.EFI';staged.write_bytes(artifact_bytes)
    esp=directory/'esp.img';disk=directory/'pattern.img'
    with esp.open('wb') as f:f.truncate(16*1024**2)
    for command in (['mkfs.vfat','-F','16',esp],['mmd','-i',esp,'::/EFI','::/EFI/BOOT'],
                    ['mcopy','-i',esp,staged,'::/EFI/BOOT/BOOTX64.EFI']):
        subprocess.run([str(x) for x in command],check=True,capture_output=True,timeout=10)
    with disk.open('wb') as f:
        f.truncate(8*1024**2)
        for lba in (7,11):f.seek(lba*512);f.write(pattern(lba))
    before=digest(disk)
    firmware=Path('/usr/share/edk2/ovmf/OVMF_CODE.fd')
    variables=directory/'OVMF_VARS.fd';shutil.copyfile('/usr/share/edk2/ovmf/OVMF_VARS.fd',variables)
    monitor=directory/'qmp.sock'
    command=['/usr/libexec/qemu-kvm','-name','ntw-ahci-fixture','-machine','q35',
             '-accel','kvm','-cpu','host','-m','256M','-smp','1','-nodefaults','-nic','none',
             '-display','none','-device','VGA','-no-reboot',
             '-drive',f'if=pflash,format=raw,unit=0,readonly=on,file={firmware}',
             '-drive',f'if=pflash,format=raw,unit=1,file={variables}',
             '-drive',f'if=none,id=esp,format=raw,readonly=on,file={esp}',
             '-device','virtio-blk-pci,drive=esp,bootindex=1',
             '-drive',f'if=none,id=sata,format=raw,file={disk}',
             '-device','ide-hd,drive=sata,bus=ide.0',
             '-qmp',f'unix:{monitor},server=on,wait=off']
    result={'pass':False,'artifact_sha256':artifact_hash,'build_receipt_sha256':build_hash,'command':command,
            'firmware_code_sha256':digest(firmware),'pattern_before_sha256':before,
            'network':'none','guest_memory_mib':256,'evidence_directory':str(directory),
            'windows_98_driver':'not_tested','physical_hardware':'not_tested'}
    result['harness_sources_sha256']={str(path.relative_to(REPO)):digest(path)
        for path in (HERE/'test_qemu.py',HERE.parent/'uefi32/test_qemu.py')}
    process=None;qmp=None;timer=None;started=time.monotonic()
    try:
        with (directory/'qemu.log').open('wb') as log:
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            result['pid']=process.pid
            timer=threading.Timer(45,process.kill);timer.daemon=True;timer.start()
            deadline=started+45
            while not monitor.exists():
                if process.poll() is not None:raise RuntimeError((directory/'qemu.log').read_text())
                if time.monotonic()>deadline:raise RuntimeError('QMP startup timeout')
                time.sleep(.05)
            qmp=base.QMP(monitor);result['kvm']=qmp.call('query-kvm')
            if not result['kvm']['enabled']:raise RuntimeError('KVM unavailable')
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('Guest exited before proof')
                proof=read_proof(qmp,directory);result['ahci']=proof
                ready,handoff=base.inspect_handoff(qmp,directory);result['handoff']=handoff
                if proof['magic']==0x49434841 and proof['stage'] in (3,4):
                    if proof['stage']==4:raise RuntimeError('AHCI integration reported failure')
                    # The driver result is published before the caller finishes
                    # rendering and publishes its final mode/core handoff.
                    if not ready:
                        time.sleep(.05);continue
                    if (proof['open_result'] or proof['read_result'] or proof['close_result'] or
                        proof['bytes_verified']!=1024 or proof['mismatch'] or proof['quarantine'] or
                        proof['sectors_low']!=16384 or proof['sectors_high']):
                        raise RuntimeError('Invalid AHCI success record')
                    registers=qmp.call('human-monitor-command',{'command-line':'info registers'})
                    if 'HLT=1' not in registers:
                        time.sleep(.05);continue
                    result['registers']=base.inspect_registers(registers,handoff)
                    (directory/'registers.txt').write_text(registers)
                    dma=directory/'dma.bin'
                    qmp.call('pmemsave',{'val':built['payload']['dma_address'],'size':4096,'filename':str(dma)})
                    data=dma.read_bytes()
                    if data[2048:2560]!=pattern(11) or struct.unpack_from('<I',data,4)[0]!=512:
                        raise RuntimeError('Independent physical DMA dump does not match final disk sector')
                    result['dma_sha256']=digest(dma)
                    result['pci']=qmp.call('query-pci')
                    qmp.call('screendump',{'filename':str(directory/'handoff.ppm')})
                    visible,_,_=base.inspect_screen(directory/'handoff.ppm')
                    if not visible:raise RuntimeError('Missing mode/core/graphics screen evidence')
                    qmp.call('screendump',{'filename':str(directory/'handoff.png'),'format':'png'})
                    result['screenshot_sha256']=digest(directory/'handoff.ppm')
                    result['pass']=True;break
                time.sleep(.1)
            if not result['pass']:raise RuntimeError('No AHCI read proof before bounded timeout')
    except Exception as error:
        result['error']=str(error)
        if qmp:
            try:
                qmp.call('screendump',{'filename':str(directory/'failure.png'),'format':'png'})
                result['registers_text']=qmp.call('human-monitor-command',{'command-line':'info registers'})
                qmp.call('pmemsave',{'val':built['payload']['dma_address'],'size':4096,
                                     'filename':str(directory/'failure-dma.bin')})
                result['pci']=qmp.call('query-pci')
                abar=result.get('ahci',{}).get('abar',0)
                if 0x80000000<=abar<=0xfffff000:
                    qmp.call('pmemsave',{'val':abar,'size':4096,
                                         'filename':str(directory/'failure-hba.bin')})
            except Exception:pass
    finally:
        if qmp:qmp.close()
        if process:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
            result['process_stopped']=process.poll() is not None
            result['qemu_returncode']=process.returncode
        if timer:timer.cancel()
        result['pattern_after_sha256']=digest(disk)
        if result['pattern_after_sha256']!=before:
            result['pass']=False;result['error']='Read-only test changed its disk'
        if digest(artifact)!=artifact_hash or digest(build_receipt)!=build_hash:
            result['pass']=False;result['error']='Build artifact or receipt changed during guest test'
        for name,expected in {**built['sources_sha256'],**result['harness_sources_sha256']}.items():
            if digest(REPO/name)!=expected:
                result['pass']=False;result['error']='Source changed during guest test: '+name
        if result['pass']:
            result['evidence_sha256']={name:digest(directory/name) for name in
                ('ahci-proof.bin','dma.bin','handoff.bin','registers.txt','handoff.ppm','handoff.png')}
        result['elapsed_seconds']=round(time.monotonic()-started,3)
        (directory/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        (BUILD/'qemu-result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
    if not result['pass']:raise SystemExit(1)

if __name__=='__main__':main()
