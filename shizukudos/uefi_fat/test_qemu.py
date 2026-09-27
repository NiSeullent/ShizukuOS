#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded isolated FAT32/AHCI guest fixture. Explicit operator lane required.

Never accepts an external disk or installer. Requires existing tools/firmware,
current successful build+host receipts and the fixed synthetic original disk.
Running this module starts a guest; importing it or --verify-only never does.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time

import fixture
import verify as v

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE/'build'
BUILD_SOURCES = set('shizukudos/uefi_fat/'+name for name in (
    'loader.c','payload.c','budget.c','budget.h','bridge.c','bridge.h','layout.h',
    'payload.ld','transition.asm','build.py')) | set('shizukudos/uefi32/'+name for name in (
    'build.py','contract.c','paging.c','paging.h','layout.h','transition.asm')) | {
    'shizukudos/uefi_ahci/clock.c','shizukudos/uefi_ahci/layout.h',
    'drivers/ahci_native/ahci.c','drivers/ahci_native/ahci.h',
    'drivers/fat_native/fat.c','drivers/fat_native/fat.h',
    'ntwrapper/core.c','ntwrapper/include/ntwrapper.h','ntwddm/src/ntwddm.c','ntwddm/include/ntwddm.h',
    'shizukudos/uefi/boot.c','shizukudos/uefi/boot.h','shizukudos/uefi/efi.h'}
HOST_SOURCES = set('shizukudos/uefi_fat/'+name for name in (
    'fixture.py','verify.py','test.py','test_qemu.py','layout.h','budget.c','budget.h','bridge.c','bridge.h')) | {
    'shizukudos/uefi_ahci/clock.c','shizukudos/uefi_ahci/layout.h','shizukudos/uefi32/layout.h',
    'drivers/ahci_native/ahci.h','drivers/fat_native/fat.c','drivers/fat_native/fat.h'}
HARNESS_SOURCES = {'shizukudos/uefi_fat/'+name for name in ('fixture.py','verify.py','test_qemu.py')} | {
    'shizukudos/uefi32/test_qemu.py'}
RECEIPT_PATHS = {'build-result.json':'shizukudos/uefi_fat/build/build-result.json',
    'host-tests.json':'shizukudos/uefi_fat/build/host-tests.json',
    'fat-host-tests.json':'drivers/fat_native/build/test-result.json',
    'ahci-host-tests.json':'drivers/ahci_native/build/host-tests.json'}
EVIDENCE_NAMES = ('fat-proof.bin','dma.bin','file-output.bin','guard-before.bin','guard-after.bin',
    'mmio.bin','handoff.bin','memory-map.bin','registers.txt','handoff.ppm','handoff.png',
    'pci.json','block.json','fixture.json','process-command.json',*RECEIPT_PATHS)
LIMITS = {'fat-proof.bin':256,'dma.bin':4096,'file-output.bin':524288,
    'guard-before.bin':4096,'guard-after.bin':4096,'mmio.bin':4096,'handoff.bin':112,
    'memory-map.bin':32768,'registers.txt':65536,'handoff.ppm':32*1024**2,'handoff.png':32*1024**2}


def hashes(source_map, expected_names, prefix=''):
    v.require(isinstance(source_map,dict) and set(source_map) == set(expected_names),
              'Missing or unexpected source binding')
    result = {}
    for name, expected in source_map.items():
        v.require(isinstance(expected,str) and re.fullmatch('[0-9a-f]{64}',expected), 'Invalid source digest')
        result[prefix+name] = expected
    return result


def capture_inputs(root=ROOT):
    """Validate all current inputs and return the exact bytes to pin to this run."""
    captured = {}
    def read(name,limit=8*1024**2):
        data = v.read_regular(root/name,limit)
        if name in captured:
            v.require(captured[name] == data,'Input changed during capture: '+name)
        captured[name] = data
        return data
    receipts = {key:v.parse_json(read(path)) for key,path in RECEIPT_PATHS.items()}
    built,host,fat,ahci = (receipts[key] for key in RECEIPT_PATHS)
    sources = hashes(built.get('sources_sha256'),BUILD_SOURCES)
    def merge(values):
        for name,value in values.items():
            v.require(name not in sources or sources[name] == value,'Conflicting receipt source binding: '+name)
            sources[name] = value
    merge(hashes(host.get('sources_sha256'),HOST_SOURCES))
    merge(hashes(fat.get('sources_sha256'),('fat.c','fat.h','test_fat.c','test.py','README.md','REFERENCES.md'),
                 'drivers/fat_native/'))
    merge(hashes(ahci.get('sources_sha256'),('ahci.c','ahci.h','test_ahci.c','test.py','README.md','REFERENCES.md'),
                 'drivers/ahci_native/'))
    for name in HARNESS_SOURCES:
        digest = v.digest(read(name))
        v.require(name not in sources or sources[name] == digest,'Harness changed since host test')
        sources[name] = digest
    for name,expected in sources.items():
        v.require(v.digest(read(name)) == expected,'Stale source receipt: '+name)
    for key,filename in (('efi','BOOTX64.EFI'),('payload','payload.bin'),('transition','transition.bin')):
        item = built.get(key,{})
        data = read('shizukudos/uefi_fat/build/'+filename)
        v.require(item.get('sha256') == v.digest(data) and item.get('bytes') == len(data),
                  'Build artifact mismatch: '+filename)
    p = built['payload']
    v.require(built.get('guest_test') == 'not_run' and built.get('physical_hardware') == 'not_tested' and
              built['transition']['bytes'] == 0x2800 and p.get('stack_frame_sum',65536)+4096 <= 65536,
              'Invalid build scope/transition/stack contract')
    spans = [(p.get('dma_address'),p.get('dma_bytes'),4096),
             (p.get('workspace_address'),p.get('workspace_bytes'),530176),
             (p.get('graphics_address'),p.get('graphics_bytes'),65536)]
    for address,size,expected in spans:
        v.require(type(address) is int and type(size) is int and size == expected and
                  address % (4096 if expected == 4096 else 16) == 0 and
                  0x02010000 <= address <= p['payload_end']-size <= v.GUARD_BEFORE-size,
                  'Invalid linked owned storage span')
    ordered = sorted((address,address+size) for address,size,_ in spans)
    v.require(all(left[1] <= right[0] for left,right in zip(ordered,ordered[1:])), 'Linked owned regions overlap')
    v.require((p.get('destination'),p.get('capacity'),p.get('guard_before'),p.get('guard_after'),p.get('guard_bytes')) ==
              (v.OUTPUT_ADDRESS,v.OUTPUT_BYTES,v.GUARD_BEFORE,v.GUARD_AFTER,4096), 'Build output coordinates changed')
    v.require(host.get('schema') == 'shizukudos.uefi_fat.host.v1' and host.get('passed') is True and
              host.get('guest_executed') is False and host.get('native_windows') is False and
              type(host.get('evidence_tests')) is int and host['evidence_tests'] >= 14,
              'Missing successful original host evidence tests')
    v.require(v.digest(read('shizukudos/uefi_fat/build/host-tests.log')) == host.get('log_sha256'),
              'Host evidence test log changed')
    for receipt,prefix,required in ((host,'shizukudos/uefi_fat/build/',{'checks':1000000}),
                                    (fat,'drivers/fat_native/build/',{'checks':18649,'scenarios':244,
                                      'injected_callbacks':75,'mutation_cases':28})):
        variants = receipt.get('variants')
        v.require(isinstance(variants,dict) and set(variants) == {'gcc','clang','asan_ubsan'},'Missing host compiler variants')
        for name,result in variants.items():
            v.require(result.get('passed') is True and result.get('status') == 'PASS' and
                      all(type(result.get(key)) is int and result[key] >= limit for key,limit in required.items()),
                      'Incomplete host variant')
            v.require(v.digest(read(prefix+name+'.log')) == result.get('log_sha256'),'Host compiler log changed')
    v.require(fat.get('schema') == 'ntw.fat_native.host.v1' and fat.get('passed') is True and
              fat.get('guest_executed') is False and fat.get('private_windows_accessed') is False and
              fat.get('writes_supported') is False and fat.get('boot_file_execution') is False,
              'FAT host scope is not the approved synthetic read-only implementation')
    v.require(set(fat.get('i486_objects',{})) == {'gcc','clang'},'Missing i486 FAT proof')
    for name,item in fat['i486_objects'].items():
        v.require(item.get('passed') is True and item.get('undefined_symbols') == [] and
                  v.digest(read('drivers/fat_native/build/'+name+'-i486.o')) == item.get('sha256') and
                  v.digest(read('drivers/fat_native/build/'+name+'-i486.log')) == item.get('log_sha256'),
                  'FAT i486 object/log mismatch')
    v.require(ahci.get('schema') == 1 and ahci.get('passed') is True and ahci.get('asan_ubsan') is True and
              ahci.get('freestanding_i486_no_runtime_imports') is True and
              ahci.get('guest_dma_executed') is False and ahci.get('win98_driver_bound') is False and
              ahci.get('physical_hardware_tested') is False, 'AHCI host scope mismatch')
    for field,filename in (('host_log_sha256','host-tests.log'),('host_binary_sha256','test_ahci'),
                           ('i486_object_sha256','ahci-i486.o')):
        v.require(v.digest(read('drivers/ahci_native/build/'+filename)) == ahci.get(field),'AHCI host artifact mismatch')
    return built,receipts,sources,captured


def clean_path(path):
    text = str(Path(path).absolute())
    v.require(not any(char in text for char in ',\x00\r\n'),'Unsafe QEMU option filename')
    return text


def command_for(directory,firmware='/usr/share/edk2/ovmf/OVMF_CODE.fd'):
    directory = Path(directory)
    return ['/usr/libexec/qemu-kvm','-name','ntw-fat-fixture','-machine','q35',
            '-accel','kvm','-cpu','host','-m','256M','-smp','1','-nodefaults','-nic','none',
            '-display','none','-device','VGA','-no-reboot',
            '-drive','if=pflash,format=raw,unit=0,readonly=on,file='+clean_path(firmware),
            '-drive','if=pflash,format=raw,unit=1,file='+clean_path(directory/'OVMF_VARS.fd'),
            '-drive','if=none,id=esp,format=raw,readonly=on,file='+clean_path(directory/'esp.img'),
            '-device','virtio-blk-pci,drive=esp,bootindex=1',
            '-drive','if=none,id=sata,format=raw,readonly=on,file='+clean_path(directory/'synthetic-fat.img'),
            '-device','ide-hd,drive=sata,bus=ide.0',
            '-qmp','unix:'+clean_path(directory/'qmp.sock')+',server=on,wait=off']


def verify_command(command,directory):
    v.require(isinstance(command,list) and len(command) == 35,'Unexpected guest command length')
    firmware = command[22]
    match = re.fullmatch(r'if=pflash,format=raw,unit=0,readonly=on,file=(/[^,\x00\r\n]+)',firmware)
    v.require(match is not None,'Firmware command is not strictly read-only')
    v.require(command == command_for(directory,match.group(1)),'Guest command differs from fixed isolated fixture')
    return match.group(1)


def compatibility_guest(command, repository_root=ROOT):
    """Classify actual QEMU argv, never text quoted inside a shell command.

    Production guests outside this lab keep running. The owned compatibility
    namespace and any argument referencing this checkout's ShizukuDOS fixtures
    identify the single QA lane, including older unnamed disk/ESP fixtures.
    """
    if not command:
        return False  # Kernel threads and exited/zombie processes have no argv.
    argv = command.rstrip(b'\0').split(b'\0')
    executable = argv[0].rsplit(b'/',1)[-1]
    if executable not in (b'qemu-kvm',b'kvm') and not re.fullmatch(rb'qemu-system-[A-Za-z0-9_-]+',executable):
        return False
    prefixes = (b'win98-modern-private-',b'zuku-compat-',b'ntw-')
    owned = os.fsencode(Path(repository_root).absolute()/'shizukudos')+b'/'
    for index,argument in enumerate(argv[1:],1):
        if owned in argument:
            return True
        name = None
        if argument == b'-name' and index+1 < len(argv):
            name = argv[index+1]
        elif argument.startswith(b'-name='):
            name = argument[len(b'-name='):]
        if name is not None:
            fields = name.split(b',')
            names = [field[len(b'guest='):] for field in fields if field.startswith(b'guest=')]
            if fields and b'=' not in fields[0]:
                names.append(fields[0])
            if any(value.startswith(prefixes) for value in names):
                return True
    return False


def check_compatibility_lane(proc_root=Path('/proc'), *, repository_root=ROOT, read_cmdline=None):
    """Fail closed if a process cannot be inspected; disappearing PIDs are OK."""
    if read_cmdline is None:
        read_cmdline = lambda path: path.read_bytes()
    try:
        entries = list(Path(proc_root).iterdir())
    except OSError as error:
        raise RuntimeError('Cannot inspect process directory; refusing guest start') from error
    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        try:
            command = read_cmdline(entry/'cmdline')
        except (FileNotFoundError,ProcessLookupError):
            continue
        except OSError as error:
            raise RuntimeError('Cannot inspect process '+entry.name+'; refusing guest start') from error
        if not isinstance(command,bytes) or len(command) > 1024**2:
            raise RuntimeError('Invalid process command line; refusing guest start')
        if compatibility_guest(command,repository_root):
            raise RuntimeError('A compatibility QA guest already owns the lane (PID '+entry.name+')')


def headroom():
    check_compatibility_lane()
    values = dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(values['MemAvailable'].split()[0])*1024 < (6*1024+512)*1024**2:
        raise RuntimeError('Insufficient 6GiB plus guest/codec RAM headroom')
    if shutil.disk_usage(BUILD).free < 20*1024**3+32*1024**2:
        raise RuntimeError('Insufficient 20GiB plus32MiB disk headroom')


def verify_blocks(blocks,directory,firmware):
    expected = {clean_path(firmware):True,clean_path(directory/'OVMF_VARS.fd'):False,
                clean_path(directory/'esp.img'):True,clean_path(directory/'synthetic-fat.img'):True}
    v.require(isinstance(blocks,list) and len(blocks) == 4,'Unexpected extra/missing QMP block device')
    observed = {}
    for item in blocks:
        inserted = item.get('inserted',{})
        filename = inserted.get('file')
        v.require(filename in expected and filename not in observed and inserted.get('drv') == 'raw' and
                  inserted.get('ro') is expected[filename], 'QMP disk differs from owned raw/read-only fixture')
        observed[filename] = inserted['ro']
    v.require(observed == expected,'Missing QMP owned disk')


def check_screen(data):
    try:
        magic,dimensions,maximum,pixels = data.split(b'\n',3)
        width,height = map(int,dimensions.split())
    except (ValueError,TypeError) as error:
        raise v.EvidenceError('Invalid PPM evidence') from error
    v.require(magic == b'P6' and maximum == b'255' and 640 <= width <= 4096 and 400 <= height <= 4096 and
              len(pixels) == width*height*3,'Invalid PPM extent')
    for (x,y),color in { (10,10):'101c30',(50,50):'20d080',(130,50):'ffb020',(210,50):'30d0e0' }.items():
        v.require(pixels[(y*width+x)*3:(y*width+x)*3+3] == bytes.fromhex(color),
                  'Missing original protected-mode/core/graphics display markers')
    return [width,height]


def decode_run_evidence(directory,built,disk):
    raw = {name:v.read_regular(directory/name,LIMITS.get(name,2*1024**2)) for name in EVIDENCE_NAMES}
    p = built['payload']
    result = v.verify_evidence(raw['fat-proof.bin'],raw['dma.bin'],raw['file-output.bin'],
        raw['guard-before.bin'],raw['guard-after.bin'],raw['mmio.bin'],
        expected_dma_address=p['dma_address'],disk_bytes=disk,handoff_bytes=raw['handoff.bin'],
        memory_map_bytes=raw['memory-map.bin'],registers_text=raw['registers.txt'].decode('ascii'),
        payload_bytes=p['bytes'],payload_end=p['payload_end'])
    pci = json.loads(raw['pci.json'])
    result['pci'] = v.verify_pci(pci,result['proof'])
    result['resolution'] = check_screen(raw['handoff.ppm'])
    metadata = v.parse_json(raw['fixture.json'])
    v.require(metadata == fixture.metadata(v.digest(disk)),'Synthetic fixture receipt changed')
    return result,raw


def verify_saved_run(path,root=ROOT):
    """Pure revalidation; a saved PASS must match its fixed evidence directory."""
    path = Path(path).absolute()
    result_bytes = v.read_regular(path,2*1024**2)
    result = v.parse_json(result_bytes)
    directory = Path(result.get('evidence_directory',''))
    expected_build = root/'shizukudos/uefi_fat/build'
    v.require(directory.is_absolute() and directory.parent == expected_build and
              directory.name.startswith('qemu-') and not directory.is_symlink(), 'Foreign/floating evidence directory')
    v.require(v.read_regular(directory/'result.json',2*1024**2) == result_bytes,'Floating guest result receipt')
    built,receipts,sources,captured = capture_inputs(root)
    v.require(result.get('pass') is True and result.get('process_stopped') is True and
              type(result.get('qemu_returncode')) is int and result['qemu_returncode'] == 0 and
              result.get('watchdog_fired') is False and result.get('clean_quit') is True and
              result.get('kvm') == {'enabled':True,'present':True} and
              result.get('windows_98_driver') == result.get('physical_hardware') == 'not_tested' and
              result.get('file_execution') is False and result.get('network') == 'none' and
              result.get('guest_memory_mib') == 256 and result.get('vcpus') == 1 and
              type(result.get('elapsed_seconds')) in (int,float) and 0 < result['elapsed_seconds'] <= 45,
              'Guest did not finish cleanly inside the isolated test bounds')
    firmware = verify_command(result.get('command'),directory)
    v.require(result.get('sources_sha256') == sources and
              result.get('input_sha256') == {name:v.digest(data) for name,data in captured.items()},
              'Saved guest is stale or missing complete input bindings')
    for name,current in RECEIPT_PATHS.items():
        v.require(v.read_regular(directory/name,2*1024**2) == captured[current],'Captured build/host receipt differs')
    disk = v.read_regular(directory/'synthetic-fat.img',fixture.DISK_BYTES)
    v.require(result.get('disk_before_sha256') == result.get('disk_after_sha256') == v.digest(disk),
              'Synthetic disk changed or disappeared')
    esp = v.read_regular(directory/'esp.img',16*1024**2)
    v.require(result.get('esp_before_sha256') == result.get('esp_after_sha256') == v.digest(esp),
              'Read-only boot medium changed')
    v.require(v.digest(v.read_regular(directory/'tested-BOOTX64.EFI',8*1024**2)) == built['efi']['sha256'] and
              result.get('artifact_sha256') == built['efi']['sha256'] and
              result.get('firmware_code_sha256') == v.digest(v.read_regular(firmware,16*1024**2)),
              'Staged EFI/firmware identity changed')
    independent,raw = decode_run_evidence(directory,built,disk)
    v.require(result.get('independent') == independent and
              result.get('evidence_sha256') == {name:v.digest(data) for name,data in raw.items()},
              'Raw independent evidence or its exact hash set changed')
    v.require(json.loads(raw['process-command.json']) == result['command'],'Observed process command differs')
    verify_blocks(json.loads(raw['block.json']),directory,firmware)
    return independent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only',type=Path)
    parser.add_argument('--guest-lane',choices=('authorized',),help='Explicit operator handoff; no automatic guest execution')
    args = parser.parse_args()
    if args.verify_only:
        print(json.dumps(verify_saved_run(args.verify_only),indent=2));return
    if args.guest_lane != 'authorized':
        parser.error('Guest execution requires explicit --guest-lane authorized')
    BUILD.mkdir(exist_ok=True)
    headroom()
    built,receipts,sources,captured = capture_inputs()
    # Use the original in-repository QMP framing only. Input bytes are bound
    # before/after execution, and all evidence validation above is separate.
    spec = importlib.util.spec_from_file_location('sdfat_qmp',HERE.parent/'uefi32/test_qemu.py')
    base = importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    directory = Path(tempfile.mkdtemp(prefix='qemu-',dir=BUILD));directory.chmod(0o700)
    (BUILD/'qemu-result.json').unlink(missing_ok=True)
    for name,current in RECEIPT_PATHS.items():(directory/name).write_bytes(captured[current])
    staged = directory/'tested-BOOTX64.EFI'
    staged.write_bytes(captured['shizukudos/uefi_fat/build/BOOTX64.EFI'])
    disk = directory/'synthetic-fat.img';metadata = fixture.create(disk)
    (directory/'fixture.json').write_text(json.dumps(metadata,indent=2)+'\n')
    disk_before = v.read_regular(disk,fixture.DISK_BYTES)
    v.decode_disk(disk_before)
    esp = directory/'esp.img'
    with esp.open('xb') as stream:stream.truncate(16*1024**2)
    for command in (['mkfs.vfat','-F','16',esp],['mmd','-i',esp,'::/EFI','::/EFI/BOOT'],
                    ['mcopy','-i',esp,staged,'::/EFI/BOOT/BOOTX64.EFI']):
        subprocess.run([str(item) for item in command],check=True,capture_output=True,timeout=10)
    esp_hash = v.digest(v.read_regular(esp,16*1024**2))
    firmware = Path('/usr/share/edk2/ovmf/OVMF_CODE.fd')
    firmware_data = v.read_regular(firmware,16*1024**2)
    (directory/'OVMF_VARS.fd').write_bytes(v.read_regular('/usr/share/edk2/ovmf/OVMF_VARS.fd',16*1024**2))
    command = command_for(directory,firmware);verify_command(command,directory)
    result = {'schema':'shizukudos.uefi_fat.guest.v1','pass':False,'command':command,
        'artifact_sha256':built['efi']['sha256'],'sources_sha256':sources,
        'input_sha256':{name:v.digest(data) for name,data in captured.items()},
        'firmware_code_sha256':v.digest(firmware_data),'disk_before_sha256':metadata['disk_sha256'],
        'esp_before_sha256':esp_hash,'evidence_directory':str(directory),'network':'none',
        'guest_memory_mib':256,'vcpus':1,'windows_98_driver':'not_tested',
        'physical_hardware':'not_tested','file_execution':False,'clean_quit':False}
    process = qmp = timer = None
    watchdog_fired = threading.Event();started = time.monotonic()
    def watchdog():
        watchdog_fired.set()
        if process is not None and process.poll() is None:process.kill()
    def dump(name,address,size):
        qmp.call('pmemsave',{'val':address,'size':size,'filename':str(directory/name)})
        return v.snapshot(v.read_regular(directory/name,size),size,name)
    try:
        with (directory/'qemu.log').open('xb') as log:
            headroom()
            process = subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            result['pid'] = process.pid
            timer = threading.Timer(45,watchdog);timer.daemon=True;timer.start()
            monitor = directory/'qmp.sock';deadline = started+45
            observed = Path('/proc')/str(process.pid)/'cmdline'
            process_command = observed.read_bytes().rstrip(b'\0').decode().split('\0')
            v.require(process_command == command,'Actual guest process command differs')
            (directory/'process-command.json').write_text(json.dumps(process_command)+'\n')
            while not monitor.exists():
                if process.poll() is not None:raise RuntimeError('Guest exited before QMP')
                if time.monotonic() >= deadline:raise RuntimeError('QMP startup timeout')
                time.sleep(.05)
            qmp = base.QMP(monitor);result['kvm'] = qmp.call('query-kvm')
            v.require(result['kvm'] == {'enabled':True,'present':True},'KVM is required for this fixture')
            while time.monotonic() < deadline:
                if process.poll() is not None:raise RuntimeError('Guest exited before FAT proof')
                proof = v.decode_proof(dump('fat-proof.bin',v.PROOF_ADDRESS,256));result['fat'] = proof
                if proof['magic'] == 0x54414653 and proof['stage'] == 4:
                    raise RuntimeError('FAT integration reported failure')
                handoff = dump('handoff.bin',0x0200f000,112)
                if proof['magic'] == 0x54414653 and proof['stage'] == 3 and v.u32(handoff,12) == 5:
                    registers = qmp.call('human-monitor-command',{'command-line':'info registers'})
                    if 'HLT=1' not in registers:time.sleep(.05);continue
                    qmp.call('stop')
                    v.require(qmp.call('query-status').get('running') is False,'Guest did not stop for capture')
                    proof = v.decode_proof(dump('fat-proof.bin',v.PROOF_ADDRESS,256))
                    handoff = dump('handoff.bin',0x0200f000,112)
                    v.require(v.u32(handoff,40) == 0x02004000 and 0 < v.u32(handoff,44) <= 32768,
                              'Retained memory-map pointer/bounds invalid')
                    registers = qmp.call('human-monitor-command',{'command-line':'info registers'})
                    (directory/'registers.txt').write_text(registers)
                    dump('memory-map.bin',0x02004000,v.u32(handoff,44))
                    for name,address,size in (('dma.bin',built['payload']['dma_address'],4096),
                            ('file-output.bin',v.OUTPUT_ADDRESS,524288),('guard-before.bin',v.GUARD_BEFORE,4096),
                            ('guard-after.bin',v.GUARD_AFTER,4096)):
                        dump(name,address,size)
                    pci = qmp.call('query-pci');v.verify_pci(pci,proof)
                    blocks = qmp.call('query-block');verify_blocks(blocks,directory,firmware)
                    (directory/'pci.json').write_text(json.dumps(pci,indent=2)+'\n')
                    (directory/'block.json').write_text(json.dumps(blocks,indent=2)+'\n')
                    v.require(0x80000000 <= proof['abar'] <= 0xfffff000 and proof['abar']%4096 == 0,'Invalid fixture BAR')
                    dump('mmio.bin',proof['abar'],4096)
                    qmp.call('screendump',{'filename':str(directory/'handoff.ppm')})
                    qmp.call('screendump',{'filename':str(directory/'handoff.png'),'format':'png'})
                    result['independent'],raw = decode_run_evidence(directory,built,disk_before)
                    result['evidence_sha256'] = {name:v.digest(data) for name,data in raw.items()}
                    result['pass'] = True
                    qmp.call('quit');result['clean_quit'] = True
                    process.wait(timeout=min(3,max(.1,deadline-time.monotonic())))
                    break
                time.sleep(.05)
            if not result['pass']:raise RuntimeError('No completed FAT evidence before45s watchdog')
    except Exception as error:
        result['pass'] = False;result['error'] = str(error)
        if qmp and process is not None and process.poll() is None:
            try:
                qmp.call('screendump',{'filename':str(directory/'failure.png'),'format':'png'})
                result['failure_registers'] = qmp.call('human-monitor-command',{'command-line':'info registers'})
                dump('failure-dma.bin',built['payload']['dma_address'],4096)
            except Exception:pass
    finally:
        if qmp:
            try:qmp.close()
            except OSError:pass
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
            result['process_stopped'] = process.poll() is not None
            result['qemu_returncode'] = process.returncode
        if timer:timer.cancel();timer.join(timeout=1)
        result['watchdog_fired'] = watchdog_fired.is_set()
        result['elapsed_seconds'] = round(time.monotonic()-started,3)
        try:
            result['disk_after_sha256'] = v.digest(v.read_regular(disk,fixture.DISK_BYTES))
            result['esp_after_sha256'] = v.digest(v.read_regular(esp,16*1024**2))
            v.require(result['disk_after_sha256'] == result['disk_before_sha256'] and
                      result['esp_after_sha256'] == esp_hash,'Read-only synthetic media changed')
            for name,data in captured.items():
                v.require(v.read_regular(ROOT/name,8*1024**2) == data,'Input changed during guest: '+name)
            v.require(result.get('process_stopped') is True and result.get('qemu_returncode') == 0 and
                      not result['watchdog_fired'] and result['clean_quit'] and result['elapsed_seconds'] <= 45,
                      'Guest shutdown was not clean and bounded')
        except Exception as error:
            result['pass'] = False;result['error'] = str(error)
        encoded = json.dumps(result,indent=2)+'\n'
        (directory/'result.json').write_text(encoded)
        (BUILD/'qemu-result.json').write_text(encoded)
        if result['pass']:
            try:verify_saved_run(BUILD/'qemu-result.json')
            except Exception as error:
                result['pass'] = False;result['error'] = str(error)
                encoded = json.dumps(result,indent=2)+'\n'
                (directory/'result.json').write_text(encoded);(BUILD/'qemu-result.json').write_text(encoded)
        print(json.dumps(result,indent=2))
    if not result['pass']:raise SystemExit(1)


if __name__ == '__main__':
    main()
