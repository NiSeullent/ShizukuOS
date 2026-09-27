"""Original regression tests for package/receipt snapshot integrity.

All files are synthetic fixtures beneath TemporaryDirectory. Rebuild commands
are mocked; these tests never rebuild or alter real platform artifacts.
SPDX-License-Identifier: GPL-2.0-only
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


package = load_module('package_evidence_packager', ROOT / 'platform/package.py')
verify = load_module('package_evidence_verifier', ROOT / 'platform/verify_package.py')


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Fixture:
    """Small self-consistent receipt tree; no PE, firmware, or OS data."""
    def __init__(self, root):
        self.root = root
        self.output = root / 'build'/package.OUTPUT_NAME
        self.source = self.write('ntwin32/runtime.c', b'original synthetic runtime source\n')
        test_source = self.write('platform/test.py', b'# synthetic test source\n')
        abi_source = self.write('platform/abi32/harness.c', b'/* synthetic ABI source */\n')
        core_source = self.write('ntwrapper/core.c', b'/* synthetic kernel source */\n')
        uefi_source = self.write('shizukudos/uefi/main.c', b'/* synthetic UEFI source */\n')
        pm_source = self.write('shizukudos/uefi32/payload.c', b'/* synthetic PM source */\n')
        for name in ('LICENSE', 'THIRD_PARTY.md', 'drivers/README.md','docs/INDEPENDENT_PLATFORM_CHECKPOINT.md',
                     'docs/NATIVE_PLATFORM_CHECKPOINT.md','docs/STORAGE_UTF_CHECKPOINT.md','docs/XHCI_CHECKPOINT.md',
                     'docs/DEVICE_FOUNDATION_CHECKPOINT.md','docs/NATIVE_DRIVER_INTEGRATION.md'):
            self.write(name, ('fixture ' + name).encode())
        artifacts = {}
        for name in ('NTW32.DLL', 'NTWPROBE.EXE', 'ntwrapper9x.a', 'ntwrapper9x.o'):
            path = self.write('build/platform/' + name, ('synthetic ' + name).encode())
            artifacts[name] = {'sha256': sha(path.read_bytes())}
        manifest = self.json('build/platform/manifest.json', {
            'sources_sha256': {'ntwin32/runtime.c': sha(self.source.read_bytes())},
            'artifacts': artifacts,
        })
        self.json('build/platform/host-tests.json', {
            'build_manifest_sha256': sha(manifest.read_bytes()),
            'test_sources_sha256': {'platform/test.py': sha(test_source.read_bytes())},
        })
        self.json('build/platform/prepare-report.json', {'fixture': True})
        self.json('platform/abi32/build/results.json', {
            'dll_sha256': artifacts['NTW32.DLL']['sha256'],
            'variants': [{'stdout': package.ABI_PASS, 'undefined_symbols':[], 'base':base}
                         for base in ('0x68000000','0x69000000')],
            'packer_tests': {'status': 'PASS', 'count':12}, 'windows_guest_verified':False,
            'sources_sha256': self.sources(package.ABI_SOURCES),
        })
        efi = self.write('shizukudos/uefi/build/BOOTX64.EFI', b'synthetic x64 EFI')
        efi_evidence = root / 'fixture-evidence/uefi'
        screenshot = self.write('fixture-evidence/uefi/handoff.ppm', b'synthetic ppm 64')
        self.write('fixture-evidence/uefi/handoff.png', b'synthetic png 64')
        self.json('shizukudos/uefi/build/qemu-result.json', {
            'pass': True, 'process_stopped': True, 'artifact_sha256': sha(efi.read_bytes()),
            'evidence_directory': str(efi_evidence), 'screenshot_sha256': sha(screenshot.read_bytes()),
        })
        self.json('shizukudos/uefi/build/build-result.json', {
            'sha256': sha(efi.read_bytes()),
            'sources_sha256': {'shizukudos/uefi/main.c': sha(uefi_source.read_bytes())},
        })
        vxd = self.write('ntwrapper/vxd/build/NTWRAP9X.VXD', b'synthetic VxD')
        self.write('ntwrapper/vxd/build/NTWRAP9X.elf', b'synthetic ELF')
        probe = self.write('ntwrapper/vxd/build/NTWQUERY.EXE', b'synthetic probe')
        log = self.write('ntwrapper/vxd/build/host-tests.log', b'synthetic test log')
        self.json('ntwrapper/vxd/build/manifest.json', {
            'sha256': sha(vxd.read_bytes()), 'probe': {'sha256': sha(probe.read_bytes())},
            'sources': {'ntwrapper/core.c': sha(core_source.read_bytes())},
        })
        self.json('ntwrapper/vxd/build/host-tests.json', {
            'passed': True, 'inputs_unchanged_during_test': True,
            'artifact_sha256': sha(vxd.read_bytes()), 'probe_sha256': sha(probe.read_bytes()),
            'log_sha256': sha(log.read_bytes()),
            'hashes': {'ntwrapper/core.c': sha(core_source.read_bytes())},
        })
        pm_hashes = {}
        for filename, key in (('BOOTX64.EFI', 'efi'), ('payload.bin', 'payload'),
                              ('transition.bin', 'transition')):
            path = self.write('shizukudos/uefi32/build/' + filename,
                              ('synthetic PM ' + filename).encode())
            pm_hashes[key] = {'sha256': sha(path.read_bytes())}
        self.json('shizukudos/uefi32/build/build-result.json', {
            **pm_hashes,
            'sources_sha256': {'shizukudos/uefi32/payload.c': sha(pm_source.read_bytes())},
        })
        self.write('shizukudos/uefi32/build/host-tests.log', b'synthetic PM tests')
        for filename in ('handoff.ppm', 'handoff.png', 'registers.txt', 'handoff.bin'):
            self.write('fixture-evidence/uefi32/' + filename,
                       ('synthetic PM evidence ' + filename).encode())
        self.json('shizukudos/uefi32/build/qemu-result.json', {
            'pass': True, 'process_stopped': True,
            'artifact_sha256': pm_hashes['efi']['sha256'],
            'evidence_directory': str(root / 'fixture-evidence/uefi32'),
            'screenshot_sha256': sha((root / 'fixture-evidence/uefi32/handoff.ppm').read_bytes()),
        })
        self.write('build/windows98-shizuku-second-edition-native-checkpoint.zip', b'previous native checkpoint')
        self.write('build/windows98-shizuku-second-edition-storage-utf-checkpoint.zip', b'previous storage UTF checkpoint')
        self.write('build/windows98-shizuku-second-edition-xhci-checkpoint.zip', b'previous xHCI checkpoint')
        self.unicode()
        self.storage()
        self.usb()
        self.device_foundations()

    def sources(self, names):
        hashes = {}
        for name in names:
            path = self.root/name
            if not path.exists():
                self.write(name, ('synthetic source '+name+'\n').encode())
            hashes[name] = sha(path.read_bytes())
        return hashes

    def device_foundations(self):
        for prefix, sources, counts, kinds in (
            ('platform/freestanding', package.MEMORY_SOURCES, package.MEMORY_COUNTS, ('memory','linked')),
            ('drivers/usb_native', package.DESCRIPTOR_SOURCES, package.DESCRIPTOR_COUNTS, ('usb',))):
            receipt = {'pass':True, 'guest':'not_run', 'hardware_io':'none',
                'sources_sha256':{Path(name).name:value for name,value in self.sources(sources).items()},
                'host':{variant:{'passed':True, **counts} for variant in ('gcc','clang','clang_sanitized')},
                'i486':{}}
            for compiler in ('gcc','clang'):
                variant = {'passed':True, 'undefined_symbols':[],
                           'flags':['-march=i486','-ffreestanding','-fno-builtin']}
                for kind in kinds:
                    name = compiler+'-i486-'+kind+'.o'
                    data = ('synthetic original '+prefix+'/'+name).encode()
                    self.write(prefix+'/build/'+name, data)
                    if kind == 'usb':
                        variant.update(object_sha256=sha(data), size_bytes=len(data))
                    else:
                        variant[kind+'_object_sha256'] = sha(data)
                receipt['i486'][compiler] = variant
            self.json(prefix+'/build/test-result.json', receipt)
        host_log = self.write('ntwddm/win98/build/host-tests.log',
            b'strict\nPASS: 398287 adapter/pixel/lifetime checks; host only\n\n'
            b'asan_ubsan\nPASS: 398287 adapter/pixel/lifetime checks; host only\n')
        self.json('ntwddm/win98/build/host-tests.json', {
            'passed':True, 'variants':['strict','asan_ubsan'], 'native_gdi':'not_executed', 'guest':'not_run',
            'log_sha256':sha(host_log.read_bytes()), 'sources_sha256':self.sources(package.GDI_HOST_SOURCES)})
        probe = self.write('ntwddm/win98/build/NTWGPROB.EXE', b'synthetic native GDI probe')
        build_log = self.write('ntwddm/win98/build/build.log', b'synthetic native GDI build log')
        self.json('ntwddm/win98/build/build-result.json', {
            'passed':True, 'artifact':'NTWGPROB.EXE', 'sha256':sha(probe.read_bytes()),
            'bytes':probe.stat().st_size, 'machine':'i386', 'subsystem':'GUI 4.10',
            'cpu_flags':'i486, no SSE/MMX, soft-float', 'crt_linked':False, 'kernelex_linked':False,
            'native_win98':'not_tested', 'imports':package.GDI_IMPORTS,
            'sources_sha256':self.sources(package.GDI_BUILD_SOURCES),
            'build_log_sha256':sha(build_log.read_bytes())})

    def unicode(self):
        obj = self.write('ntwin32/unicode/build/utf-i486.o', b'synthetic UTF object')
        receipt = self.json('ntwin32/unicode/build/host-tests.json', {
            'passed': True, 'unicode_scalars': 1112064, 'strict_host': 'pass', 'asan_ubsan': 'pass',
            'i486_undefined_symbols': [], 'independent_host_oracle': {'status': 'PASS'},
            'sources_sha256': self.sources(package.UTF_SOURCES),
            'artifacts_sha256': {'utf-i486.o': sha(obj.read_bytes())},
        })
        path = self.root/'build/platform/host-tests.json'
        tests = json.loads(path.read_text())
        tests['unicode_receipt_sha256'] = sha(receipt.read_bytes())
        self.json('build/platform/host-tests.json', tests)

    def storage(self):
        sources = self.sources(package.STORAGE_BUILD_SOURCES)
        driver_sources = self.sources('drivers/ahci_native/'+name for name in
                                     ('ahci.c','ahci.h','test_ahci.c','test.py'))
        obj = self.write('drivers/ahci_native/build/ahci-i486.o', b'synthetic AHCI object')
        log = self.write('drivers/ahci_native/build/host-tests.log', b'synthetic AHCI tests')
        self.json('drivers/ahci_native/build/host-tests.json', {
            'passed': True, 'asan_ubsan': True, 'freestanding_i486_no_runtime_imports': True,
            'sources_sha256': {Path(name).name:digest for name,digest in driver_sources.items()},
            'i486_object_sha256': sha(obj.read_bytes()), 'host_log_sha256': sha(log.read_bytes()),
        })
        clock_sources = self.sources(('shizukudos/uefi_ahci/clock.c','shizukudos/uefi_ahci/layout.h',
            'shizukudos/uefi_ahci/test_clock.c','shizukudos/uefi_ahci/test.py','shizukudos/uefi32/layout.h'))
        log = self.write('shizukudos/uefi_ahci/build/host-tests.log', b'synthetic clock tests')
        self.json('shizukudos/uefi_ahci/build/host-tests.json', {
            'pass': True, 'cases_per_variant': 100031, 'variants': ['strict','asan_ubsan'],
            'sources_sha256': clock_sources, 'log_sha256': sha(log.read_bytes()),
        })
        artifacts = {}
        for filename, key in (('BOOTX64.EFI','efi'),('payload.bin','payload'),('transition.bin','transition')):
            data = bytes(0x2800) if key == 'transition' else ('synthetic AHCI '+filename).encode()
            self.write('shizukudos/uefi_ahci/build/'+filename, data)
            artifacts[key] = {'sha256': sha(data), 'bytes': len(data)}
        built = self.json('shizukudos/uefi_ahci/build/build-result.json', {
            **artifacts, 'sources_sha256': sources,
        })
        self.ahci_evidence = 'shizukudos/uefi_ahci/build/qemu-fixture/'
        proof = dict.fromkeys(package.AHCI_PROOF_FIELDS, 0)
        proof.update(magic=0x49434841, size=80, calibrated=1, ticks_per_us=3000,
                     start_tsc=1000, stage=3, pci_bdf=250, abar=0xfedc0000,
                     sectors_low=16384, bytes_verified=1024)
        self.write(self.ahci_evidence+'ahci-proof.bin',
                   struct.pack('<4IQ14I', *(proof[name] for name in package.AHCI_PROOF_FIELDS)))
        handoff = dict.fromkeys(package.HANDOFF_FIELDS, 0)
        handoff.update(magic=0x32334453, version=1, size=112, stage=5,
                       framebuffer=0x80000000, framebuffer_bytes=640*400*4,
                       width=640, height=400, pitch_pixels=640, pixel_format=1,
                       cr0=1, cs=0x10, ss=0x18, esp=0x021fff00,
                       core_pass=1, graphics_pass=1, mode_pass=1, exit_attempted=1)
        self.write(self.ahci_evidence+'handoff.bin',
                   struct.pack('<28I', *(handoff[name] for name in package.HANDOFF_FIELDS)))
        registers = {'EIP':0x02010010,'ESP':0x021fff00,'CR0':1,'CR4':0,'EFER':0}
        self.write(self.ahci_evidence+'registers.txt', ('CS32 CPL=0 HLT=1\n' + ' '.join(
            f'{name}={value:08x}' for name,value in registers.items())+'\n').encode())
        dma = bytearray(4096)
        struct.pack_into('<I', dma, 4, 512)
        dma[2048:2560] = bytes((i*37+0x5a+11*13)&255 for i in range(512))
        self.write(self.ahci_evidence+'dma.bin', dma)
        self.write(self.ahci_evidence+'handoff.ppm', b'synthetic AHCI ppm')
        self.write(self.ahci_evidence+'handoff.png', b'synthetic AHCI png')
        disk = self.write(self.ahci_evidence+'pattern.img', b'synthetic disposable disk')
        hashes = {name:sha((self.root/self.ahci_evidence/name).read_bytes())
                  for name in package.STORAGE_EVIDENCE}
        self.json('shizukudos/uefi_ahci/build/qemu-result.json', {
            'pass':True, 'process_stopped':True, 'kvm':{'enabled':True},
            'artifact_sha256':artifacts['efi']['sha256'], 'build_receipt_sha256':sha(built.read_bytes()),
            'harness_sources_sha256': self.sources(('shizukudos/uefi_ahci/test_qemu.py',
                                                   'shizukudos/uefi32/test_qemu.py')),
            'ahci':proof, 'handoff':handoff, 'registers':registers,
            'evidence_directory':str(self.root/self.ahci_evidence), 'evidence_sha256':hashes,
            'dma_sha256':hashes['dma.bin'], 'screenshot_sha256':hashes['handoff.ppm'],
            'pattern_before_sha256':sha(disk.read_bytes()), 'pattern_after_sha256':sha(disk.read_bytes()),
        })

    def usb(self):
        sources = self.sources(package.USB_BUILD_SOURCES)
        driver_sources = self.sources('drivers/xhci_native/'+name for name in
                                     ('xhci.c','xhci.h','test_xhci.c','test.py'))
        obj = self.write('drivers/xhci_native/build/xhci-i486.o', b'synthetic xHCI object')
        log = self.write('drivers/xhci_native/build/host-tests.log', b'synthetic xHCI tests')
        self.json('drivers/xhci_native/build/host-tests.json', {
            'passed':True, 'asan_ubsan':True, 'freestanding_i486_no_runtime_imports':True,
            'sources_sha256':{Path(name).name:digest for name,digest in driver_sources.items()},
            'i486_object_sha256':sha(obj.read_bytes()), 'host_log_sha256':sha(log.read_bytes()),
        })
        log = self.write('shizukudos/uefi_xhci/build/host-tests.log', b'synthetic clock/inventory tests')
        self.json('shizukudos/uefi_xhci/build/host-tests.json', {
            'pass':True, 'cases_per_variant':100031, 'variants':['strict','asan_ubsan'],
            'inventory_tests':6, 'sources_sha256':self.sources(package.USB_HOST_SOURCES),
            'log_sha256':sha(log.read_bytes()),
        })
        artifacts = {}
        for filename, key in (('BOOTX64.EFI','efi'),('payload.bin','payload'),('transition.bin','transition')):
            data = bytes(0x2800) if key == 'transition' else ('synthetic xHCI '+filename).encode()
            self.write('shizukudos/uefi_xhci/build/'+filename, data)
            artifacts[key] = {'sha256':sha(data), 'bytes':len(data)}
        artifacts['payload']['dma_address'] = 0x02026000
        built = self.json('shizukudos/uefi_xhci/build/build-result.json', {
            **artifacts, 'sources_sha256':sources,
        })
        self.xhci_evidence = 'shizukudos/uefi_xhci/build/qemu-fixture/'
        proof = dict.fromkeys(package.XHCI_PROOF_FIELDS, 0)
        proof.update(magic=0x49434858, size=80, calibrated=1, ticks_per_us=3000,
                     start_tsc=1000, stage=3, pci_bdf=0x100, mmio=0x81000000,
                     commands_completed=130, bridges=1, last_completion_code=1, last_status=8,
                     completion_low=artifacts['payload']['dma_address']+2048+9*16)
        self.write(self.xhci_evidence+'xhci-proof.bin',
                   struct.pack('<4IQ14I', *(proof[name] for name in package.XHCI_PROOF_FIELDS)))
        old_guest = json.loads((self.root/'shizukudos/uefi_ahci/build/qemu-result.json').read_text())
        handoff = old_guest['handoff']
        handoff.update(region_base=0x02000000, region_bytes=0x00200000,
                       stack_top=0x02200000, payload_bytes=artifacts['payload']['bytes'])
        self.write(self.xhci_evidence+'handoff.bin',
                   struct.pack('<28I', *(handoff[name] for name in package.HANDOFF_FIELDS)))
        for name in ('registers.txt','handoff.ppm','handoff.png'):
            self.write(self.xhci_evidence+name, (self.root/self.ahci_evidence/name).read_bytes())
        dma = bytearray(4096)
        struct.pack_into('<4I', dma, 2304+16, proof['completion_low'], 0, 1<<24, (33<<10)|1)
        self.write(self.xhci_evidence+'dma.bin', dma)
        hashes = {name:sha((self.root/self.xhci_evidence/name).read_bytes()) for name in package.USB_EVIDENCE}
        endpoint = {'bus':1,'slot':0,'function':0,'id':{'vendor':0x1b36,'device':0x000d},
                    'regions':[{'bar':0,'type':'memory','mem_type_64':True,'size':0x4000,'address':proof['mmio']}]}
        pci = [{'bus':0,'devices':[{'bus':0,'slot':3,'function':0,
                'pci_bridge':{'bus':{'number':0,'secondary':1,'subordinate':1},'devices':[endpoint]}}]}]
        self.json('shizukudos/uefi_xhci/build/qemu-result.json', {
            'pass':True, 'process_stopped':True, 'kvm':{'enabled':True}, 'qemu_returncode':0,
            'artifact_sha256':artifacts['efi']['sha256'], 'build_receipt_sha256':sha(built.read_bytes()),
            'harness_sources_sha256':self.sources(('shizukudos/uefi_xhci/test_qemu.py',
                                                  'shizukudos/uefi32/test_qemu.py')),
            'xhci':proof, 'handoff':handoff, 'registers':old_guest['registers'], 'pci':pci,
            'evidence_directory':str(self.root/self.xhci_evidence), 'evidence_sha256':hashes,
            'dma_sha256':hashes['dma.bin'], 'screenshot_sha256':hashes['handoff.ppm'],
        })

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def json(self, name, value):
        return self.write(name, (json.dumps(value, sort_keys=True) + '\n').encode())


class PackageEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ntw-package-evidence-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = Fixture(self.root)
        root_patch = patch.object(package, 'ROOT', self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def run_packager(self):
        with contextlib.redirect_stdout(io.StringIO()):
            package.main()

    def previous_package(self):
        previous = b'preserved previous package'
        self.fixture.output.write_bytes(previous)
        return previous

    def test_successful_snapshot_has_exact_member_hashes(self):
        self.run_packager()
        with zipfile.ZipFile(self.fixture.output) as archive:
            index = json.loads(archive.read('FILES-SHA256.json'))
            self.assertEqual(set(archive.namelist()), set(index) | {'FILES-SHA256.json', 'README.txt'})
            for name, expected in index.items():
                with self.subTest(member=name):
                    self.assertEqual(sha(archive.read(name)), expected)
            self.assertEqual(archive.read('ntwin32/runtime.c'), self.fixture.source.read_bytes())
            for name in package.STORAGE_EVIDENCE:
                self.assertIn('evidence/uefi-ahci-'+name, index)
            for name in package.USB_EVIDENCE:
                self.assertIn('evidence/uefi-xhci-'+name, index)
            for name in ('drivers/ahci_native/build/ahci-i486.o',
                         'shizukudos/uefi_ahci/build/BOOTX64.EFI',
                         'shizukudos/uefi_ahci/build/payload.bin',
                         'shizukudos/uefi_ahci/build/transition.bin',
                         'ntwin32/unicode/build/host-tests.json','ntwin32/unicode/build/utf-i486.o',
                         'drivers/xhci_native/build/xhci-i486.o','drivers/xhci_native/build/host-tests.log',
                         'shizukudos/uefi_xhci/build/BOOTX64.EFI','shizukudos/uefi_xhci/build/payload.bin',
                         'shizukudos/uefi_xhci/build/transition.bin','shizukudos/uefi_xhci/build/host-tests.log',
                         'ntwddm/win98/build/NTWGPROB.EXE','ntwddm/win98/build/build-result.json',
                         'ntwddm/win98/build/build.log','ntwddm/win98/build/host-tests.json',
                         'ntwddm/win98/build/host-tests.log','drivers/usb_native/ntwu_usb.c',
                         'drivers/usb_native/build/test-result.json','drivers/usb_native/build/gcc-i486-usb.o',
                         'drivers/usb_native/build/clang-i486-usb.o','platform/freestanding/build/test-result.json',
                         'platform/freestanding/build/gcc-i486-memory.o','platform/freestanding/build/gcc-i486-linked.o',
                         'platform/freestanding/build/clang-i486-memory.o','platform/freestanding/build/clang-i486-linked.o',
                         'docs/XHCI_CHECKPOINT.md','docs/STORAGE_UTF_CHECKPOINT.md',
                         'docs/DEVICE_FOUNDATION_CHECKPOINT.md','docs/NATIVE_DRIVER_INTEGRATION.md'):
                self.assertIn(name, index)
            self.assertFalse(any(name.endswith(('pattern.img','esp.img','.fd')) for name in index))
        checksum = self.fixture.output.with_suffix('.zip.sha256').read_text().split()[0]
        self.assertEqual(checksum, sha(self.fixture.output.read_bytes()))
        self.assertEqual((self.root/'build/windows98-shizuku-second-edition-native-checkpoint.zip').read_bytes(),
                         b'previous native checkpoint')
        self.assertEqual((self.root/'build/windows98-shizuku-second-edition-storage-utf-checkpoint.zip').read_bytes(),
                         b'previous storage UTF checkpoint')
        self.assertEqual((self.root/'build/windows98-shizuku-second-edition-xhci-checkpoint.zip').read_bytes(),
                         b'previous xHCI checkpoint')

    def test_source_mutation_between_validation_and_snapshot_is_rejected(self):
        previous = self.previous_package()
        original_read = package.Inputs.read
        observations = 0

        def mutate_before_second_read(inputs, path):
            nonlocal observations
            if path == self.fixture.source:
                observations += 1
                if observations == 2:
                    path.write_bytes(b'changed after validation, before archive snapshot')
            return original_read(inputs, path)

        with patch.object(package.Inputs, 'read', mutate_before_second_read):
            with self.assertRaisesRegex(RuntimeError, 'Input changed during packaging'):
                self.run_packager()
        self.assertEqual(observations, 2)
        self.assertEqual(self.fixture.output.read_bytes(), previous)
        self.assertFalse(self.fixture.output.with_suffix('.zip.sha256').exists())

    def test_source_mutation_after_snapshot_prevents_publication(self):
        previous = self.previous_package()
        original_testzip = zipfile.ZipFile.testzip

        def mutate_during_final_validation(archive):
            result = original_testzip(archive)
            self.fixture.source.write_bytes(b'changed after archive creation')
            return result

        with patch.object(zipfile.ZipFile, 'testzip', mutate_during_final_validation):
            with self.assertRaisesRegex(RuntimeError, 'before package publication'):
                self.run_packager()
        self.assertEqual(self.fixture.output.read_bytes(), previous)
        self.assertFalse(self.fixture.output.with_suffix('.zip.sha256').exists())

    def test_uefi_build_receipt_must_identify_tested_artifact(self):
        previous = self.previous_package()
        path = self.root / 'shizukudos/uefi/build/build-result.json'
        receipt = json.loads(path.read_text())
        receipt['sha256'] = sha(b'another EFI build with the same source hashes')
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(RuntimeError, 'EFI build receipt and tested artifact differ'):
            self.run_packager()
        self.assertEqual(self.fixture.output.read_bytes(), previous)

    def reject_changed_json(self, name, mutate, message):
        path = self.root/name
        original = path.read_bytes()
        previous = self.previous_package()
        value = json.loads(original)
        mutate(value)
        path.write_text(json.dumps(value))
        try:
            with self.assertRaisesRegex(RuntimeError, message):
                self.run_packager()
            self.assertEqual(self.fixture.output.read_bytes(), previous)
        finally:
            path.write_bytes(original)

    def test_current_abi_receipt_requires_backoff_cases_and_both_bases(self):
        path = 'platform/abi32/build/results.json'
        self.reject_changed_json(path,
            lambda data:data['variants'][0].update(stdout=
                'PASS NTW32 actual PE32 ABI: 382 checks; 139 PE calls with verified ESP; Windows services mocked.'),
            'current contention/backoff regression evidence')
        self.reject_changed_json(path,
            lambda data:data['variants'][1].update(base='0x68000000'), 'both image bases')
        self.reject_changed_json(path,
            lambda data:data['sources_sha256'].pop('platform/abi32/harness.c'), 'source receipt is incomplete')
        self.reject_changed_json(path,
            lambda data:data['variants'][0].update(undefined_symbols=['Sleep']), 'current contention/backoff')

    def test_foundations_require_all_host_variants_and_complete_case_counts(self):
        for prefix in ('platform/freestanding','drivers/usb_native'):
            path = prefix+'/build/test-result.json'
            for key,value in (('pass',False),('guest','passed')):
                with self.subTest(prefix=prefix,key=key):
                    self.reject_changed_json(path, lambda data:data.update({key:value}), 'strict/sanitized host evidence')
            for variant in ('gcc','clang','clang_sanitized'):
                with self.subTest(prefix=prefix,variant=variant):
                    self.reject_changed_json(path, lambda data:data['host'].pop(variant), 'strict/sanitized host evidence')
                    self.reject_changed_json(path,
                        lambda data:data['host'][variant].update(passed=False), 'strict/sanitized host evidence')
            counts = package.MEMORY_COUNTS if prefix == 'platform/freestanding' else package.DESCRIPTOR_COUNTS
            for key in counts:
                with self.subTest(prefix=prefix,count=key):
                    self.reject_changed_json(path,
                        lambda data:data['host']['clang_sanitized'].update({key:0}), 'strict/sanitized host evidence')
        self.reject_changed_json('drivers/usb_native/build/test-result.json',
            lambda data:data.update(hardware_io='claimed native USB enumeration'), 'host parser claim')

    def test_foundations_require_both_standalone_i486_variants(self):
        for prefix in ('platform/freestanding','drivers/usb_native'):
            path = prefix+'/build/test-result.json'
            for compiler in ('gcc','clang'):
                with self.subTest(prefix=prefix,compiler=compiler):
                    self.reject_changed_json(path, lambda data:data['i486'].pop(compiler), 'host evidence')
                    for key,value in (('passed',False),('undefined_symbols',['memcpy']),('flags',['-march=i686'])):
                        self.reject_changed_json(path,
                            lambda data:data['i486'][compiler].update({key:value}), 'standalone i486 evidence')
        self.reject_changed_json('drivers/usb_native/build/test-result.json',
            lambda data:data['i486']['gcc'].update(size_bytes=1), 'object changed since validation')

    def test_foundation_source_receipts_cannot_omit_dependencies_or_escape(self):
        for path,source in (
            ('platform/freestanding/build/test-result.json','memory.c'),
            ('drivers/usb_native/build/test-result.json','ntwu_usb.c'),
            ('ntwddm/win98/build/host-tests.json','ntwddm/src/ntwddm.c'),
            ('ntwddm/win98/build/build-result.json','platform/freestanding/memory.c')):
            with self.subTest(path=path):
                self.reject_changed_json(path, lambda data:data['sources_sha256'].pop(source),
                                         'source receipt is incomplete')
        for prefix in ('platform/freestanding','drivers/usb_native'):
            self.reject_changed_json(prefix+'/build/test-result.json',
                lambda data:data['sources_sha256'].update({'../outside.c':'0'*64}), 'nonlocal paths')

    def test_foundation_artifacts_sources_and_logs_are_hash_bound(self):
        for name in ('platform/freestanding/memory.c','platform/freestanding/test_memory.c',
                     'platform/freestanding/build/gcc-i486-memory.o','platform/freestanding/build/gcc-i486-linked.o',
                     'platform/freestanding/build/clang-i486-memory.o','platform/freestanding/build/clang-i486-linked.o',
                     'drivers/usb_native/ntwu_usb.c','drivers/usb_native/test_usb.c',
                     'drivers/usb_native/build/gcc-i486-usb.o','drivers/usb_native/build/clang-i486-usb.o',
                     'ntwddm/win98/adapter.c','ntwddm/win98/probe.c',
                     'ntwddm/win98/build/NTWGPROB.EXE','ntwddm/win98/build/host-tests.log',
                     'ntwddm/win98/build/build.log'):
            path = self.root/name
            original = path.read_bytes()
            previous = self.previous_package()
            path.write_bytes(original+b'changed')
            try:
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError,
                        'source changed|object changed|artifact changed|host evidence|build evidence'):
                    self.run_packager()
                self.assertEqual(self.fixture.output.read_bytes(), previous)
            finally:
                path.write_bytes(original)

    def test_gdi_requires_host_only_sanitized_evidence(self):
        for key,value in (('passed',False),('variants',['strict']),('guest','passed'),('native_gdi','passed')):
            with self.subTest(key=key):
                self.reject_changed_json('ntwddm/win98/build/host-tests.json',
                    lambda data:data.update({key:value}), 'GDI adapter lacks matching.*host evidence')

    def test_gdi_log_requires_actual_completed_counts_even_if_rehashed(self):
        log = self.root/'ntwddm/win98/build/host-tests.log'
        log.write_bytes(b'strict\nPASS: 0 adapter/pixel/lifetime checks; host only\n')
        self.reject_changed_json('ntwddm/win98/build/host-tests.json',
            lambda data:data.update(log_sha256=sha(log.read_bytes())), 'GDI adapter lacks matching.*host evidence')

    def test_gdi_build_requires_classic_pe32_and_unverified_guest_status(self):
        for key,value in (('passed',False),('artifact','wrong.exe'),('machine','x64'),('subsystem','GUI 6.0'),
                          ('cpu_flags','i686'),('crt_linked',True),('kernelex_linked',True),
                          ('native_win98','passed'),('imports',{'KERNEL32.DLL':['LoadLibraryExW']})):
            with self.subTest(key=key):
                self.reject_changed_json('ntwddm/win98/build/build-result.json',
                    lambda data:data.update({key:value}), 'PE32/classic-import build evidence')
        self.reject_changed_json('ntwddm/win98/build/build-result.json',
            lambda data:data.update(bytes=1), 'Native GDI probe artifact changed')

    def test_previous_xhci_archive_survives_device_validation_failure(self):
        self.reject_changed_json('drivers/usb_native/build/test-result.json',
            lambda data:data['host']['clang_sanitized'].update(passed=False), 'strict/sanitized host evidence')
        self.assertEqual((self.root/'build/windows98-shizuku-second-edition-xhci-checkpoint.zip').read_bytes(),
                         b'previous xHCI checkpoint')

    def test_ahci_guest_must_match_exact_build_receipt(self):
        self.reject_changed_json('shizukudos/uefi_ahci/build/build-result.json',
            lambda receipt: receipt.update(extra_metadata='different build receipt'),
            'matching stopped KVM guest proof')

    def test_ahci_guest_requires_success_stop_kvm_and_complete_reads(self):
        path = 'shizukudos/uefi_ahci/build/qemu-result.json'
        for key in ('pass','process_stopped'):
            with self.subTest(key=key):
                self.reject_changed_json(path, lambda data: data.update({key:False}), 'stopped KVM guest proof')
        self.reject_changed_json(path, lambda data: data['kvm'].update(enabled=False), 'stopped KVM guest proof')
        for key,value in (('magic',0),('size',79),('calibrated',0),('ticks_per_us',0),
                          ('stage',2),('stage',4),('bytes_verified',512),('sectors_low',1),
                          ('sectors_high',1),('open_result',1),('read_result',1),('close_result',1),
                          ('mismatch',1),('quarantine',1)):
            with self.subTest(key=key,value=value):
                self.reject_changed_json(path, lambda data: data['ahci'].update({key:value}),
                                         'completed 1024-byte reads and released DMA')

    def test_ahci_all_three_artifacts_are_bound(self):
        for name in ('BOOTX64.EFI','payload.bin','transition.bin'):
            path = self.root/'shizukudos/uefi_ahci/build'/name
            original = path.read_bytes()
            previous = self.previous_package()
            path.write_bytes(original+b'changed')
            try:
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'artifact changed since build'):
                    self.run_packager()
                self.assertEqual(self.fixture.output.read_bytes(), previous)
            finally:
                path.write_bytes(original)

    def test_ahci_host_and_clock_passes_are_required(self):
        for key in ('passed','asan_ubsan','freestanding_i486_no_runtime_imports'):
            with self.subTest(key=key):
                self.reject_changed_json('drivers/ahci_native/build/host-tests.json',
                    lambda data: data.update({key:False}), 'sanitized/freestanding host evidence')
        for key,value in (('pass',False),('cases_per_variant',0),('variants',['strict'])):
            with self.subTest(key=key):
                self.reject_changed_json('shizukudos/uefi_ahci/build/host-tests.json',
                    lambda data: data.update({key:value}), 'strict/sanitized host evidence')
        self.reject_changed_json('drivers/ahci_native/build/host-tests.json',
            lambda data: data['sources_sha256'].pop('ahci.c'), 'source receipt is incomplete')

    def test_ahci_sources_logs_and_host_object_are_bound(self):
        for name in ('drivers/ahci_native/ahci.c','drivers/ahci_native/build/host-tests.log',
                     'drivers/ahci_native/build/ahci-i486.o','shizukudos/uefi_ahci/clock.c',
                     'shizukudos/uefi_ahci/build/host-tests.log','shizukudos/uefi_ahci/test_qemu.py',
                     'shizukudos/uefi32/test_qemu.py'):
            path = self.root/name
            original = path.read_bytes()
            previous = self.previous_package()
            path.write_bytes(original+b'changed')
            try:
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'source changed|host evidence'):
                    self.run_packager()
                self.assertEqual(self.fixture.output.read_bytes(), previous)
            finally:
                path.write_bytes(original)

    def test_ahci_six_evidence_files_are_individually_bound(self):
        for name in package.STORAGE_EVIDENCE:
            path = self.root/self.fixture.ahci_evidence/name
            original = path.read_bytes()
            previous = self.previous_package()
            path.write_bytes(original+b'changed')
            try:
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'AHCI guest evidence changed'):
                    self.run_packager()
                self.assertEqual(self.fixture.output.read_bytes(), previous)
            finally:
                path.write_bytes(original)
        self.reject_changed_json('shizukudos/uefi_ahci/build/qemu-result.json',
            lambda data: data['evidence_sha256'].pop('dma.bin'), 'evidence hash inventory')
        self.reject_changed_json('shizukudos/uefi_ahci/build/qemu-result.json',
            lambda data: data['evidence_sha256'].update({'unexpected.bin':sha(b'new')}), 'evidence hash inventory')

    def test_ahci_physical_proof_must_agree_with_receipt(self):
        self.reject_changed_json('shizukudos/uefi_ahci/build/qemu-result.json',
            lambda data: data['ahci'].update(pci_bdf=249), 'physical proof snapshot disagrees')
        self.reject_changed_json('shizukudos/uefi_ahci/build/qemu-result.json',
            lambda data: data['handoff'].update(stage=4), 'physical handoff snapshot disagrees')
        self.reject_changed_json('shizukudos/uefi_ahci/build/qemu-result.json',
            lambda data: data['registers'].update(EIP=0x02020000), 'CPU registers disagree')

    def test_ahci_dma_content_is_checked_even_with_matching_new_hash(self):
        dma_path = self.root/self.fixture.ahci_evidence/'dma.bin'
        data = bytearray(dma_path.read_bytes())
        data[2048] ^= 1
        dma_path.write_bytes(data)
        def update_hash(receipt):
            receipt['dma_sha256'] = sha(data)
            receipt['evidence_sha256']['dma.bin'] = sha(data)
        self.reject_changed_json('shizukudos/uefi_ahci/build/qemu-result.json', update_hash,
                                 'physical DMA snapshot lacks')

    def test_ahci_test_disk_must_still_match_before_and_after_hash(self):
        self.reject_changed_json('shizukudos/uefi_ahci/build/qemu-result.json',
            lambda data: data.update(pattern_after_sha256=sha(b'changed')), 'read-only test disk changed')
        path = self.root/self.fixture.ahci_evidence/'pattern.img'
        path.write_bytes(path.read_bytes()+b'changed after guest receipt')
        with self.assertRaisesRegex(RuntimeError, 'read-only test disk changed'):
            self.run_packager()

    def test_utf_evidence_is_bound_to_platform_validation(self):
        self.reject_changed_json('build/platform/host-tests.json',
            lambda data: data.update(unicode_receipt_sha256=sha(b'another UTF run')),
            'UTF core lacks matching exhaustive/sanitized host evidence')
        self.reject_changed_json('ntwin32/unicode/build/host-tests.json',
            lambda data: data.update(passed=False), 'UTF core lacks matching exhaustive/sanitized host evidence')

    def test_xhci_guest_requires_exact_current_build_and_stopped_success(self):
        self.reject_changed_json('shizukudos/uefi_xhci/build/build-result.json',
            lambda data: data.update(metadata='another build receipt'), 'matching stopped KVM guest proof')
        path = 'shizukudos/uefi_xhci/build/qemu-result.json'
        for key,value in (('pass',False),('process_stopped',False),('qemu_returncode',-15),
                          ('artifact_sha256',sha(b'different EFI'))):
            with self.subTest(key=key):
                self.reject_changed_json(path, lambda data:data.update({key:value}), 'stopped KVM guest proof')
        self.reject_changed_json(path, lambda data:data['kvm'].update(enabled=False), 'stopped KVM guest proof')

    def test_xhci_requires_130_completed_commands_and_released_dma(self):
        path = 'shizukudos/uefi_xhci/build/qemu-result.json'
        for key,value in (('magic',0),('size',79),('calibrated',0),('ticks_per_us',0),
                          ('stage',2),('commands_completed',129),('commands_completed',131),
                          ('bridges',0),('last_completion_code',2),('last_status',0x1004),
                          ('open_result',1),('command_result',1),('close_result',1),
                          ('port_events',1),('completion_high',1),('quarantine',1)):
            with self.subTest(key=key,value=value):
                self.reject_changed_json(path, lambda data:data['xhci'].update({key:value}),
                                         '130 completed commands and released DMA')

    def test_xhci_build_bounds_and_required_sources(self):
        path = 'shizukudos/uefi_xhci/build/build-result.json'
        for value in (0x02026001, 0x02000000, 0x02100000):
            with self.subTest(dma_address=value):
                self.reject_changed_json(path, lambda data:data['payload'].update(dma_address=value),
                                         'image/DMA exceeds fixed protected-mode bounds')
        for name in ('drivers/xhci_native/xhci.c','drivers/pcie/src/ntw_pcie.c'):
            with self.subTest(source=name):
                self.reject_changed_json(path, lambda data:data['sources_sha256'].pop(name),
                                         'source receipt is incomplete')

    def test_xhci_host_sanitizers_and_inventory_tests_are_required(self):
        path = 'drivers/xhci_native/build/host-tests.json'
        for key in ('passed','asan_ubsan','freestanding_i486_no_runtime_imports'):
            with self.subTest(key=key):
                self.reject_changed_json(path, lambda data:data.update({key:False}),
                                         'sanitized/freestanding host evidence')
        self.reject_changed_json(path, lambda data:data['sources_sha256'].pop('xhci.c'),
                                 'source receipt is incomplete')
        self.reject_changed_json(path, lambda data:data['sources_sha256'].update({'../xhci.c':sha(b'x')}),
                                 'nonlocal paths')
        path = 'shizukudos/uefi_xhci/build/host-tests.json'
        for key,value in (('pass',False),('cases_per_variant',0),('variants',['strict']),('inventory_tests',0)):
            with self.subTest(key=key):
                self.reject_changed_json(path, lambda data:data.update({key:value}),
                                         'strict/sanitized/inventory host evidence')
        self.reject_changed_json(path,
            lambda data:data['sources_sha256'].pop('shizukudos/uefi_xhci/test_inventory.py'),
            'source receipt is incomplete')

    def test_xhci_artifacts_sources_logs_and_object_are_bound(self):
        names = ('drivers/xhci_native/xhci.c','drivers/xhci_native/build/host-tests.log',
                 'drivers/xhci_native/build/xhci-i486.o','shizukudos/uefi_xhci/clock.c',
                 'shizukudos/uefi_xhci/test_qemu.py','shizukudos/uefi_xhci/test_inventory.py',
                 'shizukudos/uefi_xhci/build/host-tests.log','drivers/pcie/src/ntw_pcie.c') + tuple(
                 'shizukudos/uefi_xhci/build/'+name for name in ('BOOTX64.EFI','payload.bin','transition.bin'))
        for name in names:
            path = self.root/name
            original = path.read_bytes()
            previous = self.previous_package()
            path.write_bytes(original+b'changed')
            try:
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError,
                        'source changed|host evidence|artifact changed since build'):
                    self.run_packager()
                self.assertEqual(self.fixture.output.read_bytes(), previous)
            finally:
                path.write_bytes(original)

    def test_xhci_evidence_inventory_hashes_and_directory_are_bound(self):
        for name in package.USB_EVIDENCE:
            path = self.root/self.fixture.xhci_evidence/name
            original = path.read_bytes()
            previous = self.previous_package()
            path.write_bytes(original+b'changed')
            try:
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError,'xHCI guest evidence changed'):
                    self.run_packager()
                self.assertEqual(self.fixture.output.read_bytes(), previous)
            finally:
                path.write_bytes(original)
        receipt = 'shizukudos/uefi_xhci/build/qemu-result.json'
        self.reject_changed_json(receipt, lambda data:data['evidence_sha256'].pop('dma.bin'),
                                 'evidence hash inventory')
        self.reject_changed_json(receipt,
            lambda data:data['evidence_sha256'].update({'unexpected.bin':sha(b'x')}),'evidence hash inventory')
        self.reject_changed_json(receipt, lambda data:data.update(evidence_directory=str(self.root)),
                                 'isolated build directory')
        self.reject_changed_json(receipt, lambda data:data.update(dma_sha256=sha(b'other DMA')),
                                 'evidence hash fields disagree')

    def test_xhci_receipt_matches_physical_snapshots(self):
        path = 'shizukudos/uefi_xhci/build/qemu-result.json'
        self.reject_changed_json(path, lambda data:data['xhci'].update(pci_bdf=0x108),
                                 'physical proof snapshot disagrees')
        self.reject_changed_json(path, lambda data:data['handoff'].update(stage=4),
                                 'physical handoff snapshot disagrees')
        self.reject_changed_json(path, lambda data:data['registers'].update(EIP=0x02020000),
                                 'CPU registers disagree')

    def reject_changed_usb_evidence(self, name, mutate, message, update_receipt=lambda receipt,data:None):
        path = self.root/self.fixture.xhci_evidence/name
        original = path.read_bytes()
        data = bytearray(original)
        mutate(data)
        path.write_bytes(data)
        def update(receipt):
            receipt['evidence_sha256'][name] = sha(data)
            if name == 'dma.bin':receipt['dma_sha256'] = sha(data)
            update_receipt(receipt, data)
        try:
            self.reject_changed_json('shizukudos/uefi_xhci/build/qemu-result.json', update, message)
        finally:
            path.write_bytes(original)

    def test_xhci_dma_event_is_checked_even_after_hash_rebinding(self):
        for offset in (2320,2324,2328,2332):
            with self.subTest(offset=offset):
                self.reject_changed_usb_evidence('dma.bin', lambda data:data.__setitem__(offset,data[offset]^1),
                    'physical DMA snapshot lacks the 130th command completion')
        self.reject_changed_usb_evidence('xhci-proof.bin', lambda data:struct.pack_into('<I',data,60,1),
            'physical DMA snapshot lacks the 130th command completion',
            lambda receipt,data:receipt.update(xhci=dict(zip(package.XHCI_PROOF_FIELDS,struct.unpack('<4IQ14I',data)))))

    def test_xhci_mode_is_checked_even_after_snapshot_rebinding(self):
        for key,value in (('stage',4),('cr0',0x80000001),('cr4',0x20),('efer',0x400),
                          ('cs',8),('graphics_pass',0),('payload_bytes',1),('region_bytes',0)):
            with self.subTest(key=key):
                self.reject_changed_usb_evidence('handoff.bin',
                    lambda data:struct.pack_into('<I',data,package.HANDOFF_FIELDS.index(key)*4,value),
                    'completed protected-mode/core/graphics handoff',
                    lambda receipt,data:receipt.update(handoff=dict(zip(package.HANDOFF_FIELDS,struct.unpack('<28I',data)))))

    def test_xhci_pci_inventory_must_prove_bridge_and_bar(self):
        path = 'shizukudos/uefi_xhci/build/qemu-result.json'
        def endpoint(data):return data['pci'][0]['devices'][0]['pci_bridge']['devices'][0]
        for key,value in (('size',0x1000),('address',0x82000000),('type','io'),('mem_type_64',False),('bar',1)):
            with self.subTest(key=key):
                self.reject_changed_json(path, lambda data:endpoint(data)['regions'][0].update({key:value}),
                                         'PCI inventory does not match.*BAR')
        for key,value in (('bus',0),('slot',1),('function',8)):
            with self.subTest(key=key):
                self.reject_changed_json(path, lambda data:endpoint(data).update({key:value}), 'PCI inventory')
        for key,value in (('number',1),('secondary',0),('subordinate',0)):
            with self.subTest(key=key):
                self.reject_changed_json(path,
                    lambda data:data['pci'][0]['devices'][0]['pci_bridge']['bus'].update({key:value}), 'PCI inventory')
        self.reject_changed_json(path,
            lambda data:data['pci'][0]['devices'][0]['pci_bridge']['devices'].append(copy.deepcopy(endpoint(data))),
            'PCI inventory repeats a device')
        self.reject_changed_json(path,
            lambda data:data['pci'][0]['devices'][0]['pci_bridge']['devices'].clear(), 'controller/bridge count')

    def test_previous_checkpoint_archives_survive_xhci_validation_failure(self):
        self.reject_changed_json('shizukudos/uefi_xhci/build/qemu-result.json',
            lambda data:data.update(process_stopped=False), 'stopped KVM guest proof')
        self.assertEqual((self.root/'build/windows98-shizuku-second-edition-native-checkpoint.zip').read_bytes(),
                         b'previous native checkpoint')
        self.assertEqual((self.root/'build/windows98-shizuku-second-edition-storage-utf-checkpoint.zip').read_bytes(),
                         b'previous storage UTF checkpoint')


class RebuildReceiptTests(unittest.TestCase):
    ARTIFACTS = (
        'build/platform/NTW32.DLL', 'build/platform/NTWPROBE.EXE',
        'build/platform/ntwrapper9x.a', 'shizukudos/uefi/build/BOOTX64.EFI',
        'shizukudos/uefi32/build/BOOTX64.EFI', 'shizukudos/uefi32/build/payload.bin',
        'shizukudos/uefi32/build/transition.bin', 'ntwrapper/vxd/build/NTWRAP9X.VXD',
        'ntwrapper/vxd/build/NTWQUERY.EXE',
        'shizukudos/uefi_ahci/build/BOOTX64.EFI', 'shizukudos/uefi_ahci/build/payload.bin',
        'shizukudos/uefi_ahci/build/transition.bin',
        'shizukudos/uefi_xhci/build/BOOTX64.EFI', 'shizukudos/uefi_xhci/build/payload.bin',
        'shizukudos/uefi_xhci/build/transition.bin',
        'ntwddm/win98/build/NTWGPROB.EXE',
    )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ntw-rebuild-evidence-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'build/platform').mkdir(parents=True)
        self.package_path = self.root / 'build'/verify.PACKAGE_NAME
        self.receipt_path = self.root / 'build/platform/package-rebuild.json'
        self.original = self.archive_bytes(b'snapshot A')
        self.package_path.write_bytes(self.original)
        self.receipt_path.write_text('{"stale_receipt": true}')
        root_patch = patch.object(verify, 'ROOT', self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    @classmethod
    def archive_bytes(cls, marker):
        members = {name: ('synthetic rebuilt ' + name).encode() for name in cls.ARTIFACTS}
        members['snapshot-marker.txt'] = marker
        index = {name: sha(data) for name, data in members.items()}
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
            archive.writestr('FILES-SHA256.json', json.dumps(index))
        return stream.getvalue()

    def run_verifier(self):
        with contextlib.redirect_stdout(io.StringIO()):
            verify.main()

    def successful_mock_rebuild(self, command, **arguments):
        folder = Path(arguments['cwd'])
        self.assertTrue(folder.is_relative_to(self.root / 'build'))
        self.assertEqual((folder / 'snapshot-marker.txt').read_bytes(), b'snapshot A')
        return subprocess.CompletedProcess(command, 0, 'mocked rebuild passed\n', '')

    def test_unchanged_snapshot_receives_its_own_hash(self):
        with patch.object(verify.subprocess, 'run', side_effect=self.successful_mock_rebuild) as runner:
            self.run_verifier()
        self.assertEqual(runner.call_count, 16)
        receipt = json.loads(self.receipt_path.read_text())
        self.assertEqual(receipt['source_package_sha256'], sha(self.original))
        self.assertEqual(set(receipt['rebuild_identical']), set(self.ARTIFACTS))
        self.assertEqual(len(receipt['rebuild_identical']), 16)
        self.assertFalse(receipt['guest_reexecuted'])
        self.assertEqual(receipt['rebuild_commands'], [list(command) for command in verify.REBUILD_COMMANDS])
        self.assertFalse(any('test_qemu.py' in part for command in verify.REBUILD_COMMANDS for part in command))

    def test_replaced_package_after_rebuild_never_receives_receipt(self):
        replacement = self.archive_bytes(b'different snapshot B')
        self.assertNotEqual(sha(replacement), sha(self.original))
        calls = 0

        def replace_on_last_rebuild(command, **arguments):
            nonlocal calls
            result = self.successful_mock_rebuild(command, **arguments)
            calls += 1
            if calls == 16:
                self.package_path.write_bytes(replacement)
            return result

        with patch.object(verify.subprocess, 'run', side_effect=replace_on_last_rebuild):
            with self.assertRaisesRegex(RuntimeError, 'Source package changed during rebuild'):
                self.run_verifier()
        self.assertEqual(calls, 16)
        self.assertEqual(self.package_path.read_bytes(), replacement)
        self.assertFalse(self.receipt_path.exists())

    def test_failed_rebuild_removes_stale_receipt(self):
        result = subprocess.CompletedProcess(['synthetic rebuild'], 1, '', 'intentional failure')
        with patch.object(verify.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'Package rebuild failed'):
                self.run_verifier()
        self.assertFalse(self.receipt_path.exists())


if __name__ == '__main__':
    unittest.main()
