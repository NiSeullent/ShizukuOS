#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot one original USB2 EP0 descriptor transaction with disposable emulated USB."""
import hashlib
import importlib.util
import json
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
spec=importlib.util.spec_from_file_location('sdxhci_inventory_contracts',HERE.parent/'uefi_xhci/test_qemu.py')
inventory=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventory)
from verify import verify_evidence

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def headroom():
    for proc in Path('/proc').glob('[0-9]*/cmdline'):
        try: command=proc.read_bytes()
        except (FileNotFoundError,PermissionError,ProcessLookupError): continue
        if b'qemu' in command and any(name in command for name in
                (b'win98-modern-private-install',b'zuku-compat-',b'ntw-ahci-fixture',b'ntw-xhci-fixture')):
            raise RuntimeError('Another compatibility guest is active; coordinate before booting')
    values=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(values['MemAvailable'].split()[0])*1024 < (6*1024+512)*1024**2:
        raise RuntimeError('Insufficient RAM headroom')
    if shutil.disk_usage(BUILD).free < 20*1024**3+32*1024**2:
        raise RuntimeError('Insufficient disk headroom')

PROOF_NAMES = ('stage pci_bdf mmio bridges open_result probe_status transport_error '
    'parser_status failed_stage parser_offset close_result controller_dma_owned '
    'device_dma_owned allocations releases commands_completed port_events last_status '
    'last_completion_code completion_low completion_high dma_in_use_mask '
    'original_pci_command restored_pci_command command_index command_cycle event_index '
    'event_cycle dma_address device_dma_address descriptor_bytes reserved1').split()

def read_proof(qmp,directory):
    path=directory/'usb-proof.bin'
    qmp.call('pmemsave',{'val':0x0200f100,'size':256,'filename':str(path)})
    data=path.read_bytes()
    if len(data)!=256:raise RuntimeError('Truncated physical USB proof')
    names=('magic size version calibrated ticks_per_us reserved0 start_tsc').split()
    proof=dict(zip(names,struct.unpack_from('<6IQ',data)))
    proof.update(zip(PROOF_NAMES,struct.unpack_from('<32I',data,32)))
    proof['descriptor_hex']=data[160:244].hex()
    proof['configuration_address'],proof['configuration_bytes'],proof['configuration_index']=struct.unpack_from('<3I',data,244)
    return proof

def dump_region(qmp,directory,name,address,size):
    path=directory/name
    qmp.call('pmemsave',{'val':address,'size':size,'filename':str(path)})
    data=path.read_bytes()
    if len(data)!=size:raise RuntimeError('Truncated physical dump: '+name)
    return data

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
    esp=directory/'esp.img'
    with esp.open('wb') as f:f.truncate(16*1024**2)
    for command in (['mkfs.vfat','-F','16',esp],['mmd','-i',esp,'::/EFI','::/EFI/BOOT'],
                    ['mcopy','-i',esp,staged,'::/EFI/BOOT/BOOTX64.EFI']):
        subprocess.run([str(x) for x in command],check=True,capture_output=True,timeout=10)
    firmware=Path('/usr/share/edk2/ovmf/OVMF_CODE.fd')
    variables=directory/'OVMF_VARS.fd';shutil.copyfile('/usr/share/edk2/ovmf/OVMF_VARS.fd',variables)
    monitor=directory/'qmp.sock'
    command=['/usr/libexec/qemu-kvm','-name','ntw-xhci-fixture-usbconfig','-machine','q35',
             '-accel','kvm','-cpu','host','-m','256M','-smp','1','-nodefaults','-nic','none',
             '-display','none','-device','VGA','-no-reboot',
             '-drive',f'if=pflash,format=raw,unit=0,readonly=on,file={firmware}',
             '-drive',f'if=pflash,format=raw,unit=1,file={variables}',
             '-drive',f'if=none,id=esp,format=raw,readonly=on,file={esp}',
             '-device','virtio-blk-pci,drive=esp,bootindex=1',
             '-device','pcie-root-port,id=rp1,chassis=1,slot=1,bus=pcie.0',
             '-device','qemu-xhci,id=xhci,bus=rp1',
             '-device','usb-tablet,bus=xhci.0,port=1,usb_version=2',
             '-qmp',f'unix:{monitor},server=on,wait=off']
    result={'pass':False,'artifact_sha256':artifact_hash,'build_receipt_sha256':build_hash,'command':command,
            'firmware_code_sha256':digest(firmware),'usb_devices':['emulated usb-tablet; no host passthrough'],
            'network':'none','guest_memory_mib':256,'evidence_directory':str(directory),
            'windows_98_driver':'not_tested','physical_hardware':'not_tested'}
    result['harness_sources_sha256']={str(path.relative_to(REPO)):digest(path)
        for path in (HERE/'test_qemu.py', HERE/'verify.py', HERE.parent/'uefi_usb/verify.py',
                     HERE.parent/'uefi32/test_qemu.py', HERE.parent/'uefi_xhci/test_qemu.py')}
    process=None;qmp=None;timer=None;started=time.monotonic()
    watchdog_fired=threading.Event()
    def watchdog():
        watchdog_fired.set()
        if process is not None and process.poll() is None:
            process.kill()
    try:
        with (directory/'qemu.log').open('wb') as log:
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            result['pid']=process.pid
            timer=threading.Timer(45,watchdog);timer.daemon=True;timer.start()
            deadline=started+45
            while not monitor.exists():
                if process.poll() is not None:raise RuntimeError((directory/'qemu.log').read_text())
                if time.monotonic()>deadline:raise RuntimeError('QMP startup timeout')
                time.sleep(.05)
            qmp=base.QMP(monitor);result['kvm']=qmp.call('query-kvm')
            if not result['kvm']['enabled']:raise RuntimeError('KVM unavailable')
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('Guest exited before proof')
                proof=read_proof(qmp,directory);result['usb']=proof
                ready,handoff=base.inspect_handoff(qmp,directory);result['handoff']=handoff
                if proof['magic']==0x43425355 and proof['stage'] in (3,4):
                    if proof['stage']==4:raise RuntimeError('USB configuration integration reported failure')
                    # The driver result is published before the caller finishes
                    # rendering and publishes its final mode/core handoff.
                    if not ready:
                        time.sleep(.05);continue
                    registers=qmp.call('human-monitor-command',{'command-line':'info registers'})
                    if 'HLT=1' not in registers:
                        time.sleep(.05);continue
                    result['registers']=base.inspect_registers(registers,handoff)
                    (directory/'registers.txt').write_text(registers)
                    qmp.call('stop')
                    if qmp.call('query-status').get('running') is not False:
                        raise RuntimeError('Guest did not pause for evidence collection')
                    proof=read_proof(qmp,directory);result['usb']=proof
                    controller_dma=dump_region(qmp,directory,'controller-dma.bin',
                        built['payload']['dma_address'],4096)
                    device_dma=dump_region(qmp,directory,'device-dma.bin',
                        built['payload']['device_dma_address'],12288)
                    result['pci']=qmp.call('query-pci')
                    inventory.verify_pci(result['pci'],proof)
                    if not 0x80000000<=proof['mmio']<=0xffffc000:
                        raise RuntimeError('USB proof MMIO address outside fixture aperture')
                    mmio=dump_region(qmp,directory,'mmio.bin',proof['mmio'],0x4000)
                    result['usb_inventory']=qmp.call('human-monitor-command',
                        {'command-line':'info usb'})
                    (directory/'usb-inventory.txt').write_text(result['usb_inventory'])
                    configuration_page=dump_region(qmp,directory,'configuration-result.bin',
                        built['configuration_result_address'],built['configuration_page_bytes'])
                    result['independent']=verify_evidence((directory/'usb-proof.bin').read_bytes(),
                        controller_dma,device_dma,built['payload']['dma_address'],
                        built['payload']['device_dma_address'],mmio_bytes=mmio,
                        configuration_page=configuration_page,
                        expected_configuration_address=built['configuration_result_address'])
                    qmp.call('screendump',{'filename':str(directory/'handoff.ppm')})
                    visible,_,_=base.inspect_screen(directory/'handoff.ppm')
                    if not visible:raise RuntimeError('Missing mode/core/graphics screen evidence')
                    qmp.call('screendump',{'filename':str(directory/'handoff.png'),'format':'png'})
                    result['screenshot_sha256']=digest(directory/'handoff.ppm')
                    result['pass']=True;break
                time.sleep(.1)
            if not result['pass']:raise RuntimeError('No USB configuration proof before bounded timeout')
    except Exception as error:
        result['error']=str(error)
        if qmp:
            try:
                qmp.call('screendump',{'filename':str(directory/'failure.png'),'format':'png'})
                result['registers_text']=qmp.call('human-monitor-command',{'command-line':'info registers'})
                dump_region(qmp,directory,'failure-controller-dma.bin',
                    built['payload']['dma_address'],4096)
                dump_region(qmp,directory,'failure-device-dma.bin',
                    built['payload']['device_dma_address'],12288)
                result['pci']=qmp.call('query-pci')
                abar=result.get('usb',{}).get('mmio',0)
                if 0x80000000<=abar<=0xffffc000:
                    dump_region(qmp,directory,'failure-mmio.bin',abar,0x4000)
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
        if timer:
            timer.cancel();timer.join(timeout=1)
        result['watchdog_fired']=watchdog_fired.is_set()
        if digest(artifact)!=artifact_hash or digest(build_receipt)!=build_hash:
            result['pass']=False;result['error']='Build artifact or receipt changed during guest test'
        for name,expected in {**built['sources_sha256'],**result['harness_sources_sha256']}.items():
            if digest(REPO/name)!=expected:
                result['pass']=False;result['error']='Source changed during guest test: '+name
        if result.get('process_stopped') is not True:
            result['pass']=False;result['error']='Guest shutdown was not confirmed'
        elif result.get('qemu_returncode')!=0 or result['watchdog_fired']:
            result['pass']=False;result['error']='Guest did not complete a clean bounded shutdown'
        if result['pass']:
            result['evidence_sha256']={name:digest(directory/name) for name in
                ('usb-proof.bin','configuration-result.bin','controller-dma.bin','device-dma.bin','mmio.bin',
                 'usb-inventory.txt','handoff.bin','registers.txt','handoff.ppm','handoff.png')}
        result['elapsed_seconds']=round(time.monotonic()-started,3)
        (directory/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        (BUILD/'qemu-result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
    if not result['pass']:raise SystemExit(1)

if __name__=='__main__':main()
