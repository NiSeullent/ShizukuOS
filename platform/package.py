#!/usr/bin/env python3
"""Package only independent project code/artifacts; no OS media or firmware.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_NAME = 'windows98-shizuku-second-edition-usb-ep0-checkpoint.zip'
UTF_SOURCES = tuple('ntwin32/unicode/'+name for name in
                    ('utf.h','utf.c','test_utf.c','test.py','oracle.py'))
STORAGE_EVIDENCE = ('ahci-proof.bin','dma.bin','handoff.bin','registers.txt','handoff.ppm','handoff.png')
STORAGE_BUILD_SOURCES = (
    'shizukudos/uefi_ahci/loader.c','shizukudos/uefi_ahci/payload.c',
    'shizukudos/uefi_ahci/clock.c','shizukudos/uefi_ahci/layout.h','shizukudos/uefi_ahci/build.py',
    'shizukudos/uefi32/build.py','shizukudos/uefi32/contract.c',
    'shizukudos/uefi32/paging.c','shizukudos/uefi32/paging.h','shizukudos/uefi32/layout.h',
    'shizukudos/uefi32/transition.asm','shizukudos/uefi32/payload.ld',
    'drivers/ahci_native/ahci.c','drivers/ahci_native/ahci.h',
    'ntwrapper/core.c','ntwrapper/include/ntwrapper.h',
    'ntwddm/src/ntwddm.c','ntwddm/include/ntwddm.h',
    'shizukudos/uefi/boot.c','shizukudos/uefi/boot.h','shizukudos/uefi/efi.h')
AHCI_PROOF_FIELDS = ('magic size calibrated ticks_per_us start_tsc stage pci_bdf abar open_result '
    'read_result close_result sectors_low sectors_high bytes_verified mismatch '
    'last_is last_tfd last_serr quarantine').split()
HANDOFF_FIELDS = ('magic version size stage framebuffer framebuffer_bytes width height pitch_pixels pixel_format '
    'memory_map map_bytes descriptor_bytes descriptor_version region_base region_bytes payload_bytes stack_top '
    'cr0 cr4 efer cs ss esp core_pass graphics_pass mode_pass exit_attempted').split()
USB_EVIDENCE = ('xhci-proof.bin','dma.bin','handoff.bin','registers.txt','handoff.ppm','handoff.png')
USB_BUILD_SOURCES = tuple(name.replace('uefi_ahci','uefi_xhci').replace('ahci_native/ahci','xhci_native/xhci')
                          for name in STORAGE_BUILD_SOURCES) + (
    'drivers/pcie/src/ntw_pcie.c','drivers/pcie/include/ntw_pcie.h',
    'drivers/xhci_native/xhci_internal.h')
USB_HOST_SOURCES = tuple('shizukudos/uefi_xhci/'+name for name in
    ('clock.c','layout.h','test_clock.c','test.py','test_qemu.py','test_inventory.py')) + (
    'shizukudos/uefi32/layout.h','shizukudos/uefi32/test_qemu.py')
XHCI_PROOF_FIELDS = ('magic size calibrated ticks_per_us start_tsc stage pci_bdf mmio open_result '
    'command_result close_result commands_completed bridges port_events completion_low '
    'completion_high last_status last_completion_code quarantine').split()
MEMORY_SOURCES = tuple('platform/freestanding/'+name for name in
    ('memory.c','memory.h','test_memory.c','test.py'))
DESCRIPTOR_SOURCES = tuple('drivers/usb_native/'+name for name in
    ('ntwu_usb.c','ntwu_usb.h','test_usb.c','test.py'))
GDI_HOST_SOURCES = tuple('ntwddm/win98/'+name for name in
    ('adapter.h','adapter.c','selftest.c','test_adapter.c','test.py')) + (
    'ntwddm/include/ntwddm.h','ntwddm/src/ntwddm.c')
GDI_BUILD_SOURCES = tuple('ntwddm/win98/'+name for name in
    ('probe.c','adapter.c','adapter.h','selftest.c','build.py')) + (
    'ntwddm/src/ntwddm.c','ntwddm/include/ntwddm.h',
    'platform/freestanding/memory.c','platform/freestanding/memory.h','ntwin32/prepare.py')
GDI_IMPORTS = {
    'KERNEL32.DLL':sorted('CloseHandle CreateFileA ExitProcess GetLastError GetModuleHandleA '
        'GetProcessHeap GetTickCount GetVersionExA HeapAlloc HeapFree Sleep WriteFile'.split()),
    'USER32.DLL':sorted('AdjustWindowRect BeginPaint CreateWindowExA DefWindowProcA DestroyWindow '
        'DispatchMessageA EndPaint GetDC InvalidateRect LoadCursorA PeekMessageA RegisterClassA '
        'ReleaseDC ShowWindow TranslateMessage UnregisterClassA UpdateWindow'.split()),
    'GDI32.DLL':sorted('BitBlt CreateCompatibleDC CreateDIBSection DeleteDC DeleteObject '
        'GdiFlush GetDeviceCaps SelectObject'.split()),
}
ABI_SOURCES = ('platform/abi32/build.py','platform/abi32/harness.c','platform/abi32/entry.S',
               'platform/abi32/test_packer.py','ntwin32/prepare.py')
ABI_PASS = ('PASS NTW32 actual PE32 ABI: 406 checks; 147 PE calls with verified ESP; '
            'Windows services mocked.')
MEMORY_COUNTS = {'checks':1024736, 'memmove_cases':162380, 'memcpy_cases':162040,
                 'memset_cases':17490, 'memcmp_cases':179216}
DESCRIPTOR_COUNTS = {'status':'PASS', 'assertions':576668, 'parse_calls':42179,
    'device_successes':2523, 'configuration_successes':3420, 'rejections':36236,
    'mutation_cases':11008, 'random_cases':31000, 'truncation_cases':43}
EP0_COUNTS = {'status':'PASS', 'checks':6597254, 'scenarios':1095, 'injected_callbacks':984}
EP0_DRIVER_SOURCES = tuple('drivers/xhci_usb/'+name for name in
    ('xhci_usb.c','xhci_usb.h','test_usb_xhci.c','test.py','README.md')) + (
    'drivers/xhci_native/xhci.c','drivers/xhci_native/xhci.h','drivers/xhci_native/xhci_internal.h',
    'drivers/usb_native/ntwu_usb.c','drivers/usb_native/ntwu_usb.h')
EP0_BUILD_SOURCES = tuple(name.replace('uefi_xhci','uefi_usb')
    if name in ('shizukudos/uefi_xhci/loader.c','shizukudos/uefi_xhci/payload.c',
                'shizukudos/uefi_xhci/layout.h','shizukudos/uefi_xhci/build.py') else name
    for name in USB_BUILD_SOURCES) + (
    'shizukudos/uefi_xhci/layout.h','drivers/xhci_usb/xhci_usb.c','drivers/xhci_usb/xhci_usb.h',
    'drivers/usb_native/ntwu_usb.c','drivers/usb_native/ntwu_usb.h',
    'platform/freestanding/memory.c','platform/freestanding/memory.h')
EP0_HOST_SOURCES = tuple('shizukudos/uefi_usb/'+name for name in
    ('layout.h','test.py','test_qemu.py','verify.py','test_verify.py')) + tuple(
    name for name in USB_HOST_SOURCES if name != 'shizukudos/uefi_xhci/test.py')
EP0_HARNESS_SOURCES = ('shizukudos/uefi_usb/test_qemu.py','shizukudos/uefi_usb/verify.py',
    'shizukudos/uefi32/test_qemu.py','shizukudos/uefi_xhci/test_qemu.py')
EP0_EVIDENCE = ('usb-proof.bin','controller-dma.bin','device-dma.bin','mmio.bin',
    'usb-inventory.txt','handoff.bin','registers.txt','handoff.ppm','handoff.png')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class Inputs:
    """Bind validation and archive bytes to the same observed input versions."""
    def __init__(self):
        self.observed = {}

    def read(self, path):
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if self.observed.setdefault(path, actual) != actual:
            raise RuntimeError(f'Input changed during packaging: {path}')
        return data

    def digest(self, path):
        return hashlib.sha256(self.read(path)).hexdigest()

    def json(self, path):
        return json.loads(self.read(path))

    def verify_unchanged(self):
        for path, expected in self.observed.items():
            if digest(path) != expected:
                raise RuntimeError(f'Input changed before package publication: {path}')

def validate_sources(inputs, hashes, required, label):
    if not set(required).issubset(hashes):
        raise RuntimeError(f'{label} source receipt is incomplete')
    for name, expected in hashes.items():
        path = ROOT/name
        if (Path(name).is_absolute() or not path.resolve().is_relative_to(ROOT.resolve()) or
            inputs.digest(path) != expected):
            raise RuntimeError(f'{label} source changed since validation: {name}')

def validate_local_sources(inputs, hashes, folder, required, label):
    if any(Path(name).name != name for name in hashes):
        raise RuntimeError(f'{label} source receipt contains nonlocal paths')
    validate_sources(inputs, {folder+'/'+name:value for name,value in hashes.items()}, required, label)

def validate_host_variants(receipt, counts, label):
    host = receipt.get('host', {})
    if (receipt.get('pass') is not True or receipt.get('guest') != 'not_run' or
        set(host) != {'gcc','clang','clang_sanitized'} or
        set(receipt.get('i486', {})) != {'gcc','clang'} or
        any(variant.get('passed') is not True or
            any(variant.get(key) != value for key,value in counts.items()) for variant in host.values())):
        raise RuntimeError(f'{label} lacks complete strict/sanitized host evidence')
    for variant in receipt['i486'].values():
        if (variant.get('passed') is not True or variant.get('undefined_symbols') != [] or
            not {'-march=i486','-ffreestanding','-fno-builtin'}.issubset(variant.get('flags', []))):
            raise RuntimeError(f'{label} lacks standalone i486 evidence')

def add_memory_support(inputs, files):
    prefix = 'platform/freestanding'
    folder = ROOT/prefix/'build'
    receipt = inputs.json(folder/'test-result.json')
    validate_host_variants(receipt, MEMORY_COUNTS, 'Memory support')
    validate_local_sources(inputs, receipt['sources_sha256'], prefix, MEMORY_SOURCES, 'Memory support')
    names = ['test-result.json']
    for compiler, variant in receipt['i486'].items():
        for kind in ('memory','linked'):
            name = compiler+'-i486-'+kind+'.o'
            if inputs.digest(folder/name) != variant[kind+'_object_sha256']:
                raise RuntimeError('Memory support object changed since validation: '+name)
            names.append(name)
    for name in names:
        files[prefix+'/build/'+name] = folder/name

def add_usb_descriptors(inputs, files):
    prefix = 'drivers/usb_native'
    folder = ROOT/prefix/'build'
    receipt = inputs.json(folder/'test-result.json')
    validate_host_variants(receipt, DESCRIPTOR_COUNTS, 'USB descriptors')
    if receipt.get('hardware_io') != 'none':
        raise RuntimeError('USB descriptor evidence must remain a host parser claim')
    validate_local_sources(inputs, receipt['sources_sha256'], prefix, DESCRIPTOR_SOURCES, 'USB descriptors')
    names = ['test-result.json']
    for compiler, variant in receipt['i486'].items():
        name = compiler+'-i486-usb.o'
        data = inputs.read(folder/name)
        if hashlib.sha256(data).hexdigest() != variant['object_sha256'] or len(data) != variant['size_bytes']:
            raise RuntimeError('USB descriptor object changed since validation: '+name)
        names.append(name)
    for name in names:
        files[prefix+'/build/'+name] = folder/name

def add_native_gdi(inputs, files):
    prefix = 'ntwddm/win98'
    folder = ROOT/prefix/'build'
    host = inputs.json(folder/'host-tests.json')
    log = inputs.read(folder/'host-tests.log')
    expected_log = ('strict\nPASS: 398287 adapter/pixel/lifetime checks; host only\n\n'
                    'asan_ubsan\nPASS: 398287 adapter/pixel/lifetime checks; host only\n').encode()
    if (host.get('passed') is not True or host.get('variants') != ['strict','asan_ubsan'] or
        host.get('native_gdi') != 'not_executed' or host.get('guest') != 'not_run' or
        hashlib.sha256(log).hexdigest() != host.get('log_sha256') or log != expected_log):
        raise RuntimeError('GDI adapter lacks matching strict/sanitized host evidence')
    validate_sources(inputs, host['sources_sha256'], GDI_HOST_SOURCES, 'GDI adapter')
    built = inputs.json(folder/'build-result.json')
    if (built.get('passed') is not True or built.get('artifact') != 'NTWGPROB.EXE' or
        built.get('machine') != 'i386' or built.get('subsystem') != 'GUI 4.10' or
        built.get('cpu_flags') != 'i486, no SSE/MMX, soft-float' or
        built.get('crt_linked') is not False or built.get('kernelex_linked') is not False or
        built.get('native_win98') != 'not_tested' or built.get('imports') != GDI_IMPORTS or
        inputs.digest(folder/'build.log') != built.get('build_log_sha256')):
        raise RuntimeError('Native GDI probe lacks matching PE32/classic-import build evidence')
    validate_sources(inputs, built['sources_sha256'], GDI_BUILD_SOURCES, 'Native GDI probe')
    data = inputs.read(folder/'NTWGPROB.EXE')
    if (not data or hashlib.sha256(data).hexdigest() != built.get('sha256') or
        len(data) != built.get('bytes')):
        raise RuntimeError('Native GDI probe artifact changed since build')
    for name in ('NTWGPROB.EXE','build-result.json','build.log','host-tests.json','host-tests.log'):
        files[prefix+'/build/'+name] = folder/name

def add_unicode(inputs, files, platform_tests):
    folder = ROOT/'ntwin32/unicode/build'
    receipt_path = folder/'host-tests.json'
    receipt = inputs.json(receipt_path)
    if (platform_tests.get('unicode_receipt_sha256') != inputs.digest(receipt_path) or
        receipt.get('passed') is not True or receipt.get('unicode_scalars') != 1112064 or
        receipt.get('strict_host') != 'pass' or receipt.get('asan_ubsan') != 'pass' or
        receipt.get('i486_undefined_symbols') != [] or
        receipt.get('independent_host_oracle', {}).get('status') != 'PASS'):
        raise RuntimeError('UTF core lacks matching exhaustive/sanitized host evidence')
    validate_sources(inputs, receipt['sources_sha256'], UTF_SOURCES, 'UTF core')
    if inputs.digest(folder/'utf-i486.o') != receipt['artifacts_sha256']['utf-i486.o']:
        raise RuntimeError('UTF freestanding object changed since validation')
    for name in ('host-tests.json','utf-i486.o'):
        files['ntwin32/unicode/build/'+name] = folder/name

def add_storage(inputs, files):
    driver = ROOT/'drivers/ahci_native'
    host = inputs.json(driver/'build/host-tests.json')
    if (host.get('passed') is not True or host.get('asan_ubsan') is not True or
        host.get('freestanding_i486_no_runtime_imports') is not True or
        inputs.digest(driver/'build/ahci-i486.o') != host['i486_object_sha256'] or
        inputs.digest(driver/'build/host-tests.log') != host['host_log_sha256']):
        raise RuntimeError('AHCI core lacks matching sanitized/freestanding host evidence')
    hashes = host['sources_sha256']
    if any(Path(name).name != name for name in hashes):
        raise RuntimeError('AHCI core source receipt contains nonlocal paths')
    validate_sources(inputs, {'drivers/ahci_native/'+name:expected for name,expected in hashes.items()},
        ('drivers/ahci_native/'+name for name in ('ahci.c','ahci.h','test_ahci.c','test.py')), 'AHCI core')
    for name in ('host-tests.json','host-tests.log','ahci-i486.o'):
        files['drivers/ahci_native/build/'+name] = driver/'build'/name

    folder = ROOT/'shizukudos/uefi_ahci/build'
    clock = inputs.json(folder/'host-tests.json')
    if (clock.get('pass') is not True or clock.get('cases_per_variant') != 100031 or
        clock.get('variants') != ['strict','asan_ubsan'] or
        inputs.digest(folder/'host-tests.log') != clock['log_sha256']):
        raise RuntimeError('AHCI clock lacks matching strict/sanitized host evidence')
    validate_sources(inputs, clock['sources_sha256'],
        ('shizukudos/uefi_ahci/clock.c','shizukudos/uefi_ahci/layout.h',
         'shizukudos/uefi_ahci/test_clock.c','shizukudos/uefi_ahci/test.py','shizukudos/uefi32/layout.h'),
        'AHCI clock')
    built = inputs.json(folder/'build-result.json')
    validate_sources(inputs, built['sources_sha256'], STORAGE_BUILD_SOURCES, 'AHCI integration')
    for filename, key in (('BOOTX64.EFI','efi'),('payload.bin','payload'),('transition.bin','transition')):
        data = inputs.read(folder/filename)
        if (hashlib.sha256(data).hexdigest() != built[key]['sha256'] or
            len(data) != built[key]['bytes']):
            raise RuntimeError(f'AHCI integration artifact changed since build: {filename}')
    if built['transition']['bytes'] != 0x2800 or not 0 < built['payload']['bytes'] <= 0xf0000:
        raise RuntimeError('AHCI integration image exceeds fixed transition/payload bounds')
    guest = inputs.json(folder/'qemu-result.json')
    if (guest.get('pass') is not True or guest.get('process_stopped') is not True or
        guest.get('kvm', {}).get('enabled') is not True or
        guest.get('artifact_sha256') != built['efi']['sha256'] or
        guest.get('build_receipt_sha256') != inputs.digest(folder/'build-result.json')):
        raise RuntimeError('AHCI integration lacks matching stopped KVM guest proof')
    validate_sources(inputs, guest['harness_sources_sha256'],
        ('shizukudos/uefi_ahci/test_qemu.py','shizukudos/uefi32/test_qemu.py'), 'AHCI guest harness')
    proof = guest['ahci']
    if (proof.get('magic') != 0x49434841 or proof.get('size') != 80 or
        proof.get('calibrated') != 1 or not 10 <= proof.get('ticks_per_us', 0) <= 100000 or
        proof.get('stage') != 3 or proof.get('bytes_verified') != 1024 or
        proof.get('sectors_low') != 16384 or proof.get('sectors_high') != 0 or
        any(proof.get(name) != 0 for name in
            ('open_result','read_result','close_result','mismatch','quarantine'))):
        raise RuntimeError('AHCI guest did not prove completed 1024-byte reads and released DMA')
    evidence = Path(guest['evidence_directory'])
    if not evidence.resolve().is_relative_to(folder.resolve()):
        raise RuntimeError('AHCI evidence must belong to its isolated build directory')
    hashes = guest['evidence_sha256']
    if set(hashes) != set(STORAGE_EVIDENCE):
        raise RuntimeError('AHCI guest evidence hash inventory is incomplete or unexpected')
    snapshots = {}
    for name in STORAGE_EVIDENCE:
        data = inputs.read(evidence/name)
        if hashlib.sha256(data).hexdigest() != hashes[name]:
            raise RuntimeError(f'AHCI guest evidence changed: {name}')
        snapshots[name] = data
        files['evidence/uefi-ahci-'+name] = evidence/name
    if (guest.get('dma_sha256') != hashes['dma.bin'] or
        guest.get('screenshot_sha256') != hashes['handoff.ppm']):
        raise RuntimeError('AHCI guest evidence hash fields disagree')
    if len(snapshots['ahci-proof.bin']) != 80 or dict(zip(AHCI_PROOF_FIELDS,
        struct.unpack('<4IQ14I', snapshots['ahci-proof.bin']))) != proof:
        raise RuntimeError('AHCI physical proof snapshot disagrees with guest receipt')
    handoff = guest['handoff']
    if len(snapshots['handoff.bin']) != 112 or dict(zip(HANDOFF_FIELDS,
        struct.unpack('<28I', snapshots['handoff.bin']))) != handoff:
        raise RuntimeError('AHCI physical handoff snapshot disagrees with guest receipt')
    if (handoff.get('magic') != 0x32334453 or handoff.get('version') != 1 or
        handoff.get('size') != 112 or handoff.get('stage') != 5 or
        any(handoff.get(name) != 1 for name in ('core_pass','graphics_pass','mode_pass','exit_attempted')) or
        not handoff['cr0'] & 1 or handoff['cr0'] & 0x80000000 or handoff['cr4'] & 0x21020 or
        handoff['efer'] & 0x500 or handoff['cs'] != 0x10 or handoff['ss'] != 0x18 or
        not 0x021f0000 <= handoff['esp'] < 0x02200000):
        raise RuntimeError('AHCI guest lacks completed protected-mode/core/graphics handoff')
    registers = snapshots['registers.txt'].decode('ascii')
    observed = {}
    for name in ('EIP','ESP','CR0','CR4','EFER'):
        match = re.search(r'\b'+name+r'=([0-9a-fA-F]+)', registers)
        if not match:
            raise RuntimeError('AHCI register snapshot is incomplete')
        observed[name] = int(match.group(1), 16)
    if (observed != guest['registers'] or not all(token in registers for token in ('CS32','CPL=0','HLT=1')) or
        not 0x02010000 <= observed['EIP'] < 0x02100000 or
        not 0x021f0000 <= observed['ESP'] < 0x02200000 or
        any(observed[name.upper()] != handoff[name] for name in ('cr0','cr4','efer'))):
        raise RuntimeError('AHCI independent CPU registers disagree with handoff')
    dma = snapshots['dma.bin']
    if (len(dma) != 4096 or dma[2048:2560] != bytes((i*37+0x5a+11*13)&255 for i in range(512)) or
        struct.unpack_from('<I', dma, 4)[0] != 512):
        raise RuntimeError('AHCI physical DMA snapshot lacks the final sector and transfer count')
    before = guest.get('pattern_before_sha256')
    if (not isinstance(before, str) or len(before) != 64 or
        before != guest.get('pattern_after_sha256') or inputs.digest(evidence/'pattern.img') != before):
        raise RuntimeError('AHCI disposable read-only test disk changed')
    for name in ('BOOTX64.EFI','payload.bin','transition.bin','build-result.json',
                 'qemu-result.json','host-tests.json','host-tests.log'):
        files['shizukudos/uefi_ahci/build/'+name] = folder/name

def validate_usb_inventory(buses, proof):
    """Check the recorded QMP topology independently of the guest's PCI scan."""
    matches, seen_buses, seen_devices = [], set(), set()
    pending = [(bus['bus'], bus['devices'], None) for bus in buses]
    bridges = 0
    while pending:
        bus, devices, parent_limit = pending.pop()
        if (type(bus) is not int or not 0 <= bus <= 255 or bus in seen_buses or
            (parent_limit is not None and bus > parent_limit)):
            raise RuntimeError('xHCI PCI inventory has invalid or duplicate buses')
        seen_buses.add(bus)
        for device in devices:
            slot, function = device.get('slot'), device.get('function')
            if (device.get('bus') != bus or type(slot) is not int or not 0 <= slot <= 31 or
                type(function) is not int or not 0 <= function <= 7):
                raise RuntimeError('xHCI PCI inventory has inconsistent device coordinates')
            bdf = (bus << 8) | (slot << 3) | function
            if bdf in seen_devices:
                raise RuntimeError('xHCI PCI inventory repeats a device')
            seen_devices.add(bdf)
            identity = device.get('id', {})
            if identity.get('vendor') == 0x1b36 and identity.get('device') == 0x000d:
                matches.append((bus, bdf, device, parent_limit))
            bridge = device.get('pci_bridge')
            if bridge:
                primary = bridge['bus']['number']
                secondary, subordinate = bridge['bus']['secondary'], bridge['bus']['subordinate']
                if (primary != bus or type(secondary) is not int or type(subordinate) is not int or
                    not bus < secondary <= subordinate <= 255 or
                    (parent_limit is not None and subordinate > parent_limit)):
                    raise RuntimeError('xHCI PCI inventory has inconsistent bridge routing')
                bridges += 1
                pending.append((secondary, bridge.get('devices', []), subordinate))
    if len(matches) != 1 or bridges != proof['bridges']:
        raise RuntimeError('xHCI PCI inventory does not match the controller/bridge count')
    bus, bdf, device, parent_limit = matches[0]
    regions = [region for region in device.get('regions', []) if region.get('bar') == 0]
    if (bus == 0 or parent_limit is None or bdf != proof['pci_bdf'] or len(regions) != 1 or
        regions[0].get('type') != 'memory' or regions[0].get('mem_type_64') is not True or
        regions[0].get('size') != 0x4000 or regions[0].get('address') != proof['mmio'] or
        not 0x80000000 <= proof['mmio'] <= 0xffffc000 or proof['mmio'] & 0x3fff):
        raise RuntimeError('xHCI PCI inventory does not match the bridged controller BAR')

def validate_usb_mode(snapshots, guest, built):
    handoff = guest['handoff']
    if len(snapshots['handoff.bin']) != 112 or dict(zip(HANDOFF_FIELDS,
        struct.unpack('<28I', snapshots['handoff.bin']))) != handoff:
        raise RuntimeError('xHCI physical handoff snapshot disagrees with guest receipt')
    if (handoff.get('magic') != 0x32334453 or handoff.get('version') != 1 or
        handoff.get('size') != 112 or handoff.get('stage') != 5 or
        any(handoff.get(name) != 1 for name in ('core_pass','graphics_pass','mode_pass','exit_attempted')) or
        not handoff['cr0'] & 1 or handoff['cr0'] & 0x80000000 or handoff['cr4'] & 0x21020 or
        handoff['efer'] & 0x500 or handoff['cs'] != 0x10 or handoff['ss'] != 0x18 or
        not 0x021f0000 <= handoff['esp'] < 0x02200000 or
        handoff['region_base'] != 0x02000000 or handoff['region_bytes'] != 0x00200000 or
        handoff['stack_top'] != 0x02200000 or handoff['payload_bytes'] != built['payload']['bytes']):
        raise RuntimeError('xHCI guest lacks completed protected-mode/core/graphics handoff')
    registers = snapshots['registers.txt'].decode('ascii')
    observed = {}
    for name in ('EIP','ESP','CR0','CR4','EFER'):
        match = re.search(r'\b'+name+r'=([0-9a-fA-F]+)', registers)
        if not match:
            raise RuntimeError('xHCI register snapshot is incomplete')
        observed[name] = int(match.group(1), 16)
    if (observed != guest['registers'] or not all(token in registers for token in ('CS32','CPL=0','HLT=1')) or
        not 0x02010000 <= observed['EIP'] < 0x02100000 or
        not 0x021f0000 <= observed['ESP'] < 0x02200000 or
        any(observed[name.upper()] != handoff[name] for name in ('cr0','cr4','efer'))):
        raise RuntimeError('xHCI independent CPU registers disagree with handoff')

def add_usb(inputs, files):
    driver = ROOT/'drivers/xhci_native'
    host = inputs.json(driver/'build/host-tests.json')
    if (host.get('passed') is not True or host.get('asan_ubsan') is not True or
        host.get('freestanding_i486_no_runtime_imports') is not True or
        inputs.digest(driver/'build/xhci-i486.o') != host['i486_object_sha256'] or
        inputs.digest(driver/'build/host-tests.log') != host['host_log_sha256']):
        raise RuntimeError('xHCI core lacks matching sanitized/freestanding host evidence')
    hashes = host['sources_sha256']
    if any(Path(name).name != name for name in hashes):
        raise RuntimeError('xHCI core source receipt contains nonlocal paths')
    validate_sources(inputs, {'drivers/xhci_native/'+name:expected for name,expected in hashes.items()},
        ('drivers/xhci_native/'+name for name in ('xhci.c','xhci.h','xhci_internal.h','test_xhci.c','test.py')), 'xHCI core')
    for name in ('host-tests.json','host-tests.log','xhci-i486.o'):
        files['drivers/xhci_native/build/'+name] = driver/'build'/name
    folder = ROOT/'shizukudos/uefi_xhci/build'
    host = inputs.json(folder/'host-tests.json')
    if (host.get('pass') is not True or host.get('cases_per_variant') != 100031 or
        host.get('variants') != ['strict','asan_ubsan'] or host.get('inventory_tests') != 6 or
        inputs.digest(folder/'host-tests.log') != host['log_sha256']):
        raise RuntimeError('xHCI integration lacks matching strict/sanitized/inventory host evidence')
    validate_sources(inputs, host['sources_sha256'], USB_HOST_SOURCES, 'xHCI integration host')
    built = inputs.json(folder/'build-result.json')
    validate_sources(inputs, built['sources_sha256'], USB_BUILD_SOURCES, 'xHCI integration')
    for filename, key in (('BOOTX64.EFI','efi'),('payload.bin','payload'),('transition.bin','transition')):
        data = inputs.read(folder/filename)
        if (hashlib.sha256(data).hexdigest() != built[key]['sha256'] or len(data) != built[key]['bytes']):
            raise RuntimeError(f'xHCI integration artifact changed since build: {filename}')
    dma_address = built['payload']['dma_address']
    if (built['transition']['bytes'] != 0x2800 or not 0 < built['payload']['bytes'] <= 0xf0000 or
        type(dma_address) is not int or dma_address & 4095 or not 0x02010000 <= dma_address <= 0x020ff000):
        raise RuntimeError('xHCI integration image/DMA exceeds fixed protected-mode bounds')
    guest = inputs.json(folder/'qemu-result.json')
    if (guest.get('pass') is not True or guest.get('process_stopped') is not True or
        guest.get('kvm', {}).get('enabled') is not True or guest.get('qemu_returncode') != 0 or
        guest.get('artifact_sha256') != built['efi']['sha256'] or
        guest.get('build_receipt_sha256') != inputs.digest(folder/'build-result.json')):
        raise RuntimeError('xHCI integration lacks matching stopped KVM guest proof')
    validate_sources(inputs, guest['harness_sources_sha256'],
        ('shizukudos/uefi_xhci/test_qemu.py','shizukudos/uefi32/test_qemu.py'), 'xHCI guest harness')
    proof = guest['xhci']
    if (proof.get('magic') != 0x49434858 or proof.get('size') != 80 or
        proof.get('calibrated') != 1 or not 10 <= proof.get('ticks_per_us', 0) <= 100000 or
        proof.get('stage') != 3 or proof.get('commands_completed') != 130 or
        proof.get('bridges', 0) < 1 or proof.get('last_completion_code') != 1 or
        proof.get('last_status', 0) & 0x1004 or any(proof.get(name) != 0 for name in
            ('open_result','command_result','close_result','port_events','completion_high','quarantine'))):
        raise RuntimeError('xHCI guest did not prove 130 completed commands and released DMA')
    evidence = Path(guest['evidence_directory'])
    if not evidence.resolve().is_relative_to(folder.resolve()):
        raise RuntimeError('xHCI evidence must belong to its isolated build directory')
    hashes = guest['evidence_sha256']
    if set(hashes) != set(USB_EVIDENCE):
        raise RuntimeError('xHCI guest evidence hash inventory is incomplete or unexpected')
    snapshots = {}
    for name in USB_EVIDENCE:
        path = evidence/name
        if not path.resolve().is_relative_to(folder.resolve()):
            raise RuntimeError('xHCI evidence file escapes its isolated build directory')
        data = inputs.read(path)
        if hashlib.sha256(data).hexdigest() != hashes[name]:
            raise RuntimeError(f'xHCI guest evidence changed: {name}')
        snapshots[name] = data
        files['evidence/uefi-xhci-'+name] = path
    if (guest.get('dma_sha256') != hashes['dma.bin'] or
        guest.get('screenshot_sha256') != hashes['handoff.ppm']):
        raise RuntimeError('xHCI guest evidence hash fields disagree')
    if len(snapshots['xhci-proof.bin']) != 80 or dict(zip(XHCI_PROOF_FIELDS,
        struct.unpack('<4IQ14I', snapshots['xhci-proof.bin']))) != proof:
        raise RuntimeError('xHCI physical proof snapshot disagrees with guest receipt')
    validate_usb_mode(snapshots, guest, built)
    dma = snapshots['dma.bin']
    expected_pointer = dma_address + 2048 + 9 * 16
    if (len(dma) != 4096 or struct.unpack_from('<4I', dma, 2304 + 16) !=
        (expected_pointer, 0, 1 << 24, (33 << 10) | 1) or proof['completion_low'] != expected_pointer):
        raise RuntimeError('xHCI physical DMA snapshot lacks the 130th command completion')
    validate_usb_inventory(guest['pci'], proof)
    for name in ('BOOTX64.EFI','payload.bin','transition.bin','build-result.json',
                 'qemu-result.json','host-tests.json','host-tests.log'):
        files['shizukudos/uefi_xhci/build/'+name] = folder/name

def validate_ep0_command(guest, evidence):
    """Match this bounded emulated fixture; never execute the recorded command."""
    command = guest.get('command', [])
    if not command or Path(command[0]).name not in ('qemu-kvm','qemu-system-x86_64'):
        raise RuntimeError('USB EP0 guest command is not the recorded QEMU fixture')
    options = {}
    index = 1
    while index < len(command):
        name = command[index]
        if name in ('-nodefaults','-no-reboot'):
            value = True
            index += 1
        elif name in ('-name','-machine','-accel','-cpu','-m','-smp','-nic','-display',
                      '-device','-drive','-qmp') and index+1 < len(command):
            value = command[index+1]
            index += 2
        else:
            raise RuntimeError('USB EP0 guest command contains unexpected options')
        options.setdefault(name, []).append(value)
    expected = {'-name':['ntw-xhci-fixture-usbep0'], '-machine':['q35'], '-accel':['kvm'],
        '-cpu':['host'], '-m':['256M'], '-smp':['1'], '-nic':['none'], '-display':['none'],
        '-nodefaults':[True], '-no-reboot':[True], '-device':['VGA',
            'virtio-blk-pci,drive=esp,bootindex=1',
            'pcie-root-port,id=rp1,chassis=1,slot=1,bus=pcie.0',
            'qemu-xhci,id=xhci,bus=rp1', 'usb-tablet,bus=xhci.0,port=1,usb_version=2'],
        '-qmp':['unix:'+str(evidence/'qmp.sock')+',server=on,wait=off']}
    if any(options.get(name) != values for name,values in expected.items()):
        raise RuntimeError('USB EP0 guest command differs from the isolated tablet fixture')
    drives = options.get('-drive', [])
    if (len(drives) != 3 or not re.fullmatch(
            r'if=pflash,format=raw,unit=0,readonly=on,file=/[^,\x00\r\n]+', drives[0]) or
        drives[1] != 'if=pflash,format=raw,unit=1,file='+str(evidence/'OVMF_VARS.fd') or
        drives[2] != 'if=none,id=esp,format=raw,readonly=on,file='+str(evidence/'esp.img')):
        raise RuntimeError('USB EP0 guest command lacks isolated firmware/ESP drives')

def add_usb_ep0(inputs, files):
    driver_prefix = 'drivers/xhci_usb/build/'
    driver = ROOT/driver_prefix
    host = inputs.json(driver/'test-result.json')
    validate_host_variants(host, {}, 'USB EP0 transport')
    if host.get('hardware_io') != 'none':
        raise RuntimeError('USB EP0 transport host evidence must not claim hardware execution')
    validate_sources(inputs, host['sources_sha256'], EP0_DRIVER_SOURCES, 'USB EP0 transport')
    driver_names = ['test-result.json']
    for name, variant in host['host'].items():
        log = inputs.read(driver/(name+'.log'))
        if (hashlib.sha256(log).hexdigest() != variant.get('log_sha256') or
            log.decode('utf-8') != variant.get('output') or json.loads(log) != EP0_COUNTS):
            raise RuntimeError('USB EP0 transport host log/counts differ from the frozen suite')
        driver_names.append(name+'.log')
    for compiler, variant in host['i486'].items():
        name = compiler+'-i486-linked.o'
        data = inputs.read(driver/name)
        if (hashlib.sha256(data).hexdigest() != variant.get('linked_object_sha256') or
            len(data) != variant.get('size_bytes')):
            raise RuntimeError('USB EP0 transport linked object changed since validation')
        driver_names.append(name)
    for name in driver_names:
        files[driver_prefix+name] = driver/name

    prefix = 'shizukudos/uefi_usb/build/'
    folder = ROOT/prefix
    host = inputs.json(folder/'host-tests.json')
    if (host.get('pass') is not True or host.get('cases_per_variant') != 100031 or
        host.get('variants') != ['strict','asan_ubsan'] or host.get('inventory_tests') != 6 or
        host.get('usb_evidence_tests') != 18 or
        inputs.digest(folder/'host-tests.log') != host.get('log_sha256')):
        raise RuntimeError('USB EP0 integration lacks matching clock/inventory/evidence host tests')
    validate_sources(inputs, host['sources_sha256'], EP0_HOST_SOURCES, 'USB EP0 integration host')
    built = inputs.json(folder/'build-result.json')
    validate_sources(inputs, built['sources_sha256'], EP0_BUILD_SOURCES, 'USB EP0 integration')
    for name,key in (('BOOTX64.EFI','efi'),('payload.bin','payload'),('transition.bin','transition')):
        data = inputs.read(folder/name)
        if (not data or hashlib.sha256(data).hexdigest() != built[key].get('sha256') or
            len(data) != built[key].get('bytes')):
            raise RuntimeError('USB EP0 integration artifact changed since build: '+name)
    if built['transition']['bytes'] != 0x2800 or not 0 < built['payload']['bytes'] <= 0xf0000:
        raise RuntimeError('USB EP0 integration image exceeds protected-mode bounds')
    guest = inputs.json(folder/'qemu-result.json')
    if (guest.get('pass') is not True or guest.get('process_stopped') is not True or
        guest.get('qemu_returncode') != 0 or guest.get('watchdog_fired') is not False or
        guest.get('kvm', {}).get('enabled') is not True or
        guest.get('artifact_sha256') != built['efi']['sha256'] or
        guest.get('build_receipt_sha256') != inputs.digest(folder/'build-result.json')):
        raise RuntimeError('USB EP0 integration lacks matching cleanly stopped KVM guest proof')
    if (guest.get('windows_98_driver') != 'not_tested' or guest.get('physical_hardware') != 'not_tested' or
        guest.get('network') != 'none' or guest.get('guest_memory_mib') != 256 or
        guest.get('usb_devices') != ['emulated usb-tablet; no host passthrough']):
        raise RuntimeError('USB EP0 guest scope differs from the emulated descriptor fixture')
    validate_sources(inputs, guest['harness_sources_sha256'], EP0_HARNESS_SOURCES, 'USB EP0 guest harness')
    evidence = Path(guest['evidence_directory'])
    if not evidence.resolve().is_relative_to(folder.resolve()):
        raise RuntimeError('USB EP0 evidence must belong to its isolated build directory')
    validate_ep0_command(guest, evidence)
    hashes = guest['evidence_sha256']
    if set(hashes) != set(EP0_EVIDENCE):
        raise RuntimeError('USB EP0 evidence hash inventory is incomplete or unexpected')
    snapshots = {}
    for name in EP0_EVIDENCE:
        path = evidence/name
        if not path.resolve().is_relative_to(folder.resolve()):
            raise RuntimeError('USB EP0 evidence file escapes its isolated build directory')
        data = inputs.read(path)
        if hashlib.sha256(data).hexdigest() != hashes[name]:
            raise RuntimeError('USB EP0 guest evidence changed: '+name)
        snapshots[name] = data
        files['evidence/uefi-usb-'+name] = path
    if (guest.get('screenshot_sha256') != hashes['handoff.ppm'] or
        guest.get('usb_inventory') != snapshots['usb-inventory.txt'].decode('utf-8')):
        raise RuntimeError('USB EP0 screenshot/inventory evidence disagrees with receipt')

    # Execute our pure verifier from the same captured source bytes validated above.
    # No source is re-imported from disk, and no guest/rebuild command is executed.
    verifier_path = ROOT/'shizukudos/uefi_usb/verify.py'
    namespace = {'__name__':'packaged_usb_evidence', '__file__':str(verifier_path)}
    exec(compile(inputs.read(verifier_path), str(verifier_path), 'exec'), namespace)
    try:
        independent = namespace['verify_evidence'](snapshots['usb-proof.bin'],
            snapshots['controller-dma.bin'], snapshots['device-dma.bin'],
            built['payload']['dma_address'], built['payload']['device_dma_address'],
            mmio_bytes=snapshots['mmio.bin'])
    except ValueError as error:
        raise RuntimeError('USB EP0 independent physical evidence rejected: '+str(error)) from error
    proof = {name:value for name,value in independent['proof'].items()
             if name not in ('descriptor','reserved')}
    proof['descriptor_hex'] = snapshots['usb-proof.bin'][160:244].hex()
    if proof != guest['usb'] or independent != guest['independent']:
        raise RuntimeError('USB EP0 receipt disagrees with independently decoded physical evidence')
    # QMP logical port 1 is not the physical USB2 companion root-port number.
    inventory = snapshots['usb-inventory.txt'].decode('utf-8')
    descriptor = independent['descriptor']
    if (inventory != '  Device 0.1, Port 1, Speed 480 Mb/s, Product QEMU USB Tablet\r\n' or
        independent['topology']['port_speed_id'] != 3 or independent['usb_address'] != 1 or
        descriptor['vendor_id'] != 0x0627 or descriptor['product_id'] != 1 or
        descriptor['packet_bytes'] != 64 or descriptor['evaluate_context'] is not False):
        raise RuntimeError('USB EP0 evidence does not match the observed high-speed QEMU tablet fixture')
    validate_usb_mode(snapshots, guest, built)
    validate_usb_inventory(guest['pci'], proof)
    for name in ('BOOTX64.EFI','payload.bin','transition.bin','build-result.json',
                 'qemu-result.json','host-tests.json','host-tests.log'):
        files[prefix+name] = folder/name

def main():
    inputs = Inputs()
    digest = inputs.digest
    read_json = inputs.json
    build = ROOT/'build/platform'
    manifest_path = build/'manifest.json'
    manifest = read_json(manifest_path)
    tests = read_json(build/'host-tests.json')
    if tests['build_manifest_sha256'] != digest(manifest_path):
        raise RuntimeError('Host test receipt belongs to a different build')
    for name, expected in {**manifest['sources_sha256'], **tests['test_sources_sha256']}.items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'Source changed since validation: {name}')
    for name, info in manifest['artifacts'].items():
        if digest(build/name) != info['sha256']:
            raise RuntimeError(f'Artifact changed since validation: {name}')
    files = {}
    for folder in ('ntwrapper','ntwin32','ntwddm','drivers/pcie','drivers/ahci_native','drivers/xhci_native',
                   'drivers/usb_native','drivers/xhci_usb',
                   'shizukudos/uefi','shizukudos/uefi32','shizukudos/uefi_ahci','shizukudos/uefi_xhci',
                   'shizukudos/uefi_usb','platform'):
        for path in (ROOT/folder).rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(ROOT)
            if any(part in ('build','__pycache__') for part in relative.parts):
                continue
            files[str(relative)] = path
    for name in ('LICENSE','THIRD_PARTY.md','drivers/README.md','docs/INDEPENDENT_PLATFORM_CHECKPOINT.md',
                 'docs/NATIVE_PLATFORM_CHECKPOINT.md','docs/STORAGE_UTF_CHECKPOINT.md','docs/XHCI_CHECKPOINT.md',
                 'docs/DEVICE_FOUNDATION_CHECKPOINT.md','docs/NATIVE_DRIVER_INTEGRATION.md',
                 'docs/USB_EP0_CHECKPOINT.md'):
        files[name] = ROOT/name
    for name in ('NTW32.DLL','NTWPROBE.EXE','ntwrapper9x.a','ntwrapper9x.o',
                 'manifest.json','host-tests.json','prepare-report.json'):
        files['build/platform/'+name] = build/name
    uefi = ROOT/'shizukudos/uefi/build'
    receipt_path = uefi/'qemu-result.json'
    receipt = read_json(receipt_path)
    if not receipt['pass'] or not receipt['process_stopped'] or receipt['artifact_sha256'] != digest(uefi/'BOOTX64.EFI'):
        raise RuntimeError('Current EFI image lacks matching stopped-guest proof')
    uefi_build = read_json(uefi/'build-result.json')
    if uefi_build['sha256'] != receipt['artifact_sha256']:
        raise RuntimeError('EFI build receipt and tested artifact differ')
    for name, expected in uefi_build['sources_sha256'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'EFI source changed since build: {name}')
    for name in ('BOOTX64.EFI','build-result.json','qemu-result.json'):
        files['shizukudos/uefi/build/'+name] = uefi/name
    screenshot = Path(receipt['evidence_directory'])/'handoff.ppm'
    if digest(screenshot) != receipt['screenshot_sha256']:
        raise RuntimeError('Screenshot changed since guest validation')
    files['evidence/uefi-handoff.ppm'] = screenshot
    files['evidence/uefi-handoff.png'] = Path(receipt['evidence_directory'])/'handoff.png'
    # Earlier checkpoints remain untouched; each generation uses its own name.
    abi = ROOT/'platform/abi32/build/results.json'
    abi_receipt = read_json(abi)
    if abi_receipt['dll_sha256'] != digest(build/'NTW32.DLL') or len(abi_receipt['variants']) != 2:
        raise RuntimeError('Actual PE32 execution receipt does not match this DLL')
    if (abi_receipt['packer_tests']['status'] != 'PASS' or abi_receipt['packer_tests'].get('count') != 12 or
        abi_receipt.get('windows_guest_verified') is not False):
        raise RuntimeError('ABI packer validation did not pass')
    validate_sources(inputs, abi_receipt['sources_sha256'], ABI_SOURCES, 'ABI harness')
    files['platform/abi32/build/results.json'] = abi
    if {variant.get('base') for variant in abi_receipt['variants']} != {'0x68000000','0x69000000'}:
        raise RuntimeError('PE32 variants do not cover both image bases')
    for variant in abi_receipt['variants']:
        if variant.get('stdout') != ABI_PASS or variant.get('undefined_symbols') != []:
            raise RuntimeError('PE32 variant lacks current contention/backoff regression evidence')
    vxd = ROOT/'ntwrapper/vxd/build'
    vxd_manifest = read_json(vxd/'manifest.json')
    if digest(vxd/'NTWRAP9X.VXD') != vxd_manifest['sha256']:
        raise RuntimeError('VxD artifact changed since build')
    for name, expected in vxd_manifest['sources'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'VxD source changed since build: {name}')
    vxd_tests = read_json(vxd/'host-tests.json')
    if (not vxd_tests['passed'] or not vxd_tests['inputs_unchanged_during_test'] or
        vxd_tests['artifact_sha256'] != vxd_manifest['sha256'] or
        vxd_tests['probe_sha256'] != vxd_manifest['probe']['sha256'] or
        digest(vxd/'NTWQUERY.EXE') != vxd_manifest['probe']['sha256'] or
        digest(vxd/'host-tests.log') != vxd_tests['log_sha256']):
        raise RuntimeError('VxD/probe artifacts lack matching successful host validation')
    for name, expected in vxd_tests['hashes'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'VxD input changed since host validation: {name}')
    for name in ('NTWRAP9X.VXD','NTWRAP9X.elf','manifest.json','host-tests.json',
                 'host-tests.log','NTWQUERY.EXE'):
        files['ntwrapper/vxd/build/'+name] = vxd/name
    pm = ROOT/'shizukudos/uefi32/build'
    pm_build = read_json(pm/'build-result.json')
    pm_guest = read_json(pm/'qemu-result.json')
    if (not pm_guest['pass'] or not pm_guest['process_stopped'] or
        pm_guest['artifact_sha256'] != digest(pm/'BOOTX64.EFI') or
        pm_build['efi']['sha256'] != pm_guest['artifact_sha256']):
        raise RuntimeError('32-bit handoff lacks matching stopped-guest proof')
    for name, expected in pm_build['sources_sha256'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'32-bit handoff source changed since build: {name}')
    for name, key in (('payload.bin','payload'),('transition.bin','transition')):
        if digest(pm/name) != pm_build[key]['sha256']:
            raise RuntimeError(f'32-bit handoff payload changed: {name}')
    for name in ('BOOTX64.EFI','payload.bin','transition.bin','build-result.json',
                 'qemu-result.json','host-tests.log'):
        files['shizukudos/uefi32/build/'+name] = pm/name
    pm_evidence = Path(pm_guest['evidence_directory'])
    if digest(pm_evidence/'handoff.ppm') != pm_guest['screenshot_sha256']:
        raise RuntimeError('32-bit handoff screenshot changed since validation')
    for name in ('handoff.ppm','handoff.png','registers.txt','handoff.bin'):
        files['evidence/uefi32-'+name] = pm_evidence/name
    add_unicode(inputs, files, tests)
    add_storage(inputs, files)
    add_usb(inputs, files)
    add_memory_support(inputs, files)
    add_usb_descriptors(inputs, files)
    add_native_gdi(inputs, files)
    add_usb_ep0(inputs, files)
    output = ROOT/'build'/OUTPUT_NAME
    temporary = output.with_suffix('.zip.tmp')
    members = {name:inputs.read(path) for name,path in sorted(files.items())}
    index = {name:hashlib.sha256(data).hexdigest() for name,data in members.items()}
    with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED) as archive:
        def add(name, data):
            entry=zipfile.ZipInfo(name, (2026,9,27,0,0,0))
            entry.compress_type=zipfile.ZIP_DEFLATED
            entry.external_attr=0o100644 << 16
            archive.writestr(entry,data)
        for name,data in members.items():
            add(name,data)
        add('FILES-SHA256.json',json.dumps(index,indent=2)+'\n')
        add('README.txt',"Windows 98 Shizuku's Second Edition — USB EP0 checkpoint\n"
            "Read platform/README.md and docs/USB_EP0_CHECKPOINT.md.\n"
            "Not a complete operating system or installation package.\n"
            "Includes original USB2 EP0 GET8/GET18 transport and independent QEMU DMA evidence.\n"
            "USB configuration, HID input and native Windows 98 USB integration remain unfinished.\n"
            "See checkpoint for precise Windows 98 VxD/app validation status.\n"
            "Modern vendor drivers, complete DOS and UEFI-to-Win98 boot remain unfinished.\n"
            "Contains only independently authored source/binaries and development evidence.\n"
            "No Windows media, keys, firmware binaries or third-party implementations.\n")
    with zipfile.ZipFile(temporary) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Package CRC verification failed')
        for name, expected in index.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise RuntimeError(f'Package member failed manifest validation: {name}')
    inputs.verify_unchanged()
    temporary.replace(output)
    output.with_suffix('.zip.sha256').write_text(digest(output)+'  '+output.name+'\n')
    print(json.dumps({'path':str(output),'sha256':digest(output),'files':len(files)+2,
                      'bytes':output.stat().st_size},indent=2))

if __name__ == '__main__':
    main()
