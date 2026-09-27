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
        self.output = root / 'build/windows98-shizuku-second-edition-native-checkpoint.zip'
        self.source = self.write('ntwin32/runtime.c', b'original synthetic runtime source\n')
        test_source = self.write('platform/test.py', b'# synthetic test source\n')
        abi_source = self.write('platform/abi32/harness.c', b'/* synthetic ABI source */\n')
        core_source = self.write('ntwrapper/core.c', b'/* synthetic kernel source */\n')
        uefi_source = self.write('shizukudos/uefi/main.c', b'/* synthetic UEFI source */\n')
        pm_source = self.write('shizukudos/uefi32/payload.c', b'/* synthetic PM source */\n')
        for name in ('LICENSE', 'THIRD_PARTY.md', 'docs/INDEPENDENT_PLATFORM_CHECKPOINT.md',
                     'docs/NATIVE_PLATFORM_CHECKPOINT.md'):
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
        checksum = self.fixture.output.with_suffix('.zip.sha256').read_text().split()[0]
        self.assertEqual(checksum, sha(self.fixture.output.read_bytes()))

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


class RebuildReceiptTests(unittest.TestCase):
    ARTIFACTS = (
        'build/platform/NTW32.DLL', 'build/platform/NTWPROBE.EXE',
        'build/platform/ntwrapper9x.a', 'shizukudos/uefi/build/BOOTX64.EFI',
        'shizukudos/uefi32/build/BOOTX64.EFI', 'shizukudos/uefi32/build/payload.bin',
        'shizukudos/uefi32/build/transition.bin', 'ntwrapper/vxd/build/NTWRAP9X.VXD',
        'ntwrapper/vxd/build/NTWQUERY.EXE',
    )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ntw-rebuild-evidence-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'build/platform').mkdir(parents=True)
        self.package_path = self.root / 'build/windows98-shizuku-second-edition-native-checkpoint.zip'
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
        self.assertEqual(runner.call_count, 6)
        receipt = json.loads(self.receipt_path.read_text())
        self.assertEqual(receipt['source_package_sha256'], sha(self.original))
        self.assertEqual(set(receipt['rebuild_identical']), set(self.ARTIFACTS))

    def test_replaced_package_after_rebuild_never_receives_receipt(self):
        replacement = self.archive_bytes(b'different snapshot B')
        self.assertNotEqual(sha(replacement), sha(self.original))
        calls = 0

        def replace_on_last_rebuild(command, **arguments):
            nonlocal calls
            result = self.successful_mock_rebuild(command, **arguments)
            calls += 1
            if calls == 6:
                self.package_path.write_bytes(replacement)
            return result

        with patch.object(verify.subprocess, 'run', side_effect=replace_on_last_rebuild):
            with self.assertRaisesRegex(RuntimeError, 'Source package changed during rebuild'):
                self.run_verifier()
        self.assertEqual(calls, 6)
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
