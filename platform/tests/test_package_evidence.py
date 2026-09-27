"""Original regression tests for package/receipt snapshot integrity.

All files are synthetic fixtures beneath TemporaryDirectory. Rebuild commands
are mocked; these tests never rebuild or alter real platform artifacts.
SPDX-License-Identifier: GPL-2.0-only
"""
import contextlib
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
                     'docs/NATIVE_PLATFORM_CHECKPOINT.md','docs/STORAGE_UTF_CHECKPOINT.md'):
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
            'variants': [{'stdout': 'PASS NTW32 actual PE32 ABI: fixture'} for _ in range(2)],
            'packer_tests': {'status': 'PASS'},
            'sources_sha256': {'platform/abi32/harness.c': sha(abi_source.read_bytes())},
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
        self.unicode()
        self.storage()

    def sources(self, names):
        hashes = {}
        for name in names:
            path = self.root/name
            if not path.exists():
                self.write(name, ('synthetic source '+name+'\n').encode())
            hashes[name] = sha(path.read_bytes())
        return hashes

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
            for name in ('drivers/ahci_native/build/ahci-i486.o',
                         'shizukudos/uefi_ahci/build/BOOTX64.EFI',
                         'shizukudos/uefi_ahci/build/payload.bin',
                         'shizukudos/uefi_ahci/build/transition.bin',
                         'ntwin32/unicode/build/host-tests.json','ntwin32/unicode/build/utf-i486.o'):
                self.assertIn(name, index)
            self.assertFalse(any(name.endswith(('pattern.img','esp.img','.fd')) for name in index))
        checksum = self.fixture.output.with_suffix('.zip.sha256').read_text().split()[0]
        self.assertEqual(checksum, sha(self.fixture.output.read_bytes()))
        self.assertEqual((self.root/'build/windows98-shizuku-second-edition-native-checkpoint.zip').read_bytes(),
                         b'previous native checkpoint')

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


class RebuildReceiptTests(unittest.TestCase):
    ARTIFACTS = (
        'build/platform/NTW32.DLL', 'build/platform/NTWPROBE.EXE',
        'build/platform/ntwrapper9x.a', 'shizukudos/uefi/build/BOOTX64.EFI',
        'shizukudos/uefi32/build/BOOTX64.EFI', 'shizukudos/uefi32/build/payload.bin',
        'shizukudos/uefi32/build/transition.bin', 'ntwrapper/vxd/build/NTWRAP9X.VXD',
        'ntwrapper/vxd/build/NTWQUERY.EXE',
        'shizukudos/uefi_ahci/build/BOOTX64.EFI', 'shizukudos/uefi_ahci/build/payload.bin',
        'shizukudos/uefi_ahci/build/transition.bin',
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
        self.assertEqual(runner.call_count, 9)
        receipt = json.loads(self.receipt_path.read_text())
        self.assertEqual(receipt['source_package_sha256'], sha(self.original))
        self.assertEqual(set(receipt['rebuild_identical']), set(self.ARTIFACTS))
        self.assertEqual(len(receipt['rebuild_identical']), 12)
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
            if calls == 9:
                self.package_path.write_bytes(replacement)
            return result

        with patch.object(verify.subprocess, 'run', side_effect=replace_on_last_rebuild):
            with self.assertRaisesRegex(RuntimeError, 'Source package changed during rebuild'):
                self.run_verifier()
        self.assertEqual(calls, 9)
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
