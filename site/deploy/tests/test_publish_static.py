"""Host controls for reviewed public ISO publication; never publish or boot.

These controls catch private-input publication, stale identities, unbounded
large reads, unintended changes to existing downloads and wrong origin ranges.
"""
import hashlib
import errno
from contextlib import redirect_stdout
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
import shutil
from unittest.mock import patch
from html.parser import HTMLParser

PUBLISHER = Path(__file__).resolve().parents[1] / 'publish_static.py'
spec = importlib.util.spec_from_file_location('m98_publish_static', PUBLISHER)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
COMMIT = '1234567890abcdef1234567890abcdef12345678'


PROOF = Path(__file__).resolve().parents[2] / 'evidence/component-installer'


class ComponentInstallerProof(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='m98-component-proof-controls-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proof = self.root / 'proof'
        shutil.copytree(PROOF, self.proof)
        self.manifest = json.loads((self.proof / 'manifest.json').read_bytes())

    def prepare(self, **kwargs):
        return publisher.prepare_assets(component_installer_proof=self.proof, **kwargs)

    def write_manifest(self):
        (self.proof / 'manifest.json').write_text(json.dumps(self.manifest))

    def test_optional_original_component_frames_are_localized_and_scope_stays_incomplete(self):
        prepared = self.prepare()
        self.assertIsNone(prepared['iso'])
        self.assertEqual(len(prepared['assets']), 88)
        self.assertEqual(prepared['component_installer_proof'], self.manifest)
        for flag in ('microsoft_media_included', 'windows98_boot_verified', 'ms_dos_replaced', 'latest_apps_complete', 'pixel_transform'):
            self.assertIs(self.manifest[flag], False)
        for frame in self.manifest['frames']:
            name = 'evidence/component-installer/' + frame['file']
            self.assertEqual(hashlib.sha256(prepared['assets'][name]).hexdigest(), frame['sha256'])
        for name, scope, pending, prefix in (
                ('index.html', 'Shizuku 구성요소 설치 검증', 'Windows 98의 MS-DOS 대체와 최신 앱 전체 지원은 개발 중입니다.', './'),
                ('en/index.html', 'Shizuku component installer verification', 'Replacing MS-DOS for Windows 98 and complete latest-app support remain in development.', '../')):
            page = prepared['assets'][name].decode()
            self.assertIn(scope, page)
            self.assertIn(pending, page)
            self.assertIn('2026-10-01', page)
            self.assertIn(prefix + 'evidence/component-installer/manifest.json', page)
            for frame in self.manifest['frames']:
                self.assertIn(prefix + 'evidence/component-installer/' + frame['file'], page)
        self.assertNotIn(b'/root/', prepared['assets']['evidence/component-installer/manifest.json'])

    def test_unpinned_bytes_and_dimensions_are_rejected(self):
        path = self.proof / self.manifest['frames'][0]['file']
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(ValueError): self.prepare()
        path.write_bytes(original)
        self.manifest['frames'][0]['width'] = 1024; self.write_manifest()
        with self.assertRaises(ValueError): self.prepare()

    def test_changed_provenance_scope_and_private_fields_are_rejected(self):
        original = json.loads(json.dumps(self.manifest))
        for field, value in [('windows98_boot_verified', True), ('ms_dos_replaced', True),
                             ('latest_apps_complete', True), ('microsoft_media_included', True),
                             ('pixel_transform', True), ('public', False),
                             ('actual_vm_count', 3), ('result_sha256', '0' * 64),
                             ('input_capture_sha256', '0' * 64), ('scope', 'Windows 98 installed'),
                             ('date', '2026-10-02'), ('status', 'PASS_WINDOWS98_COMPLETE'),
                             ('private_input_path', '/private/owned-media.iso')]:
            with self.subTest(field=field):
                self.manifest = json.loads(json.dumps(original)); self.manifest[field] = value
                self.write_manifest()
                with self.assertRaises(ValueError): self.prepare()

    def test_missing_extra_or_symlink_inputs_are_rejected(self):
        frame = self.proof / self.manifest['frames'][0]['file']
        original = frame.read_bytes(); frame.unlink()
        with self.assertRaises(ValueError): self.prepare()
        frame.write_bytes(original)
        extra = self.proof / 'private.iso'; extra.write_bytes(b'not accepted')
        with self.assertRaises(ValueError): self.prepare()
        extra.unlink(); frame.unlink(); frame.symlink_to(PROOF / frame.name)
        with self.assertRaises(ValueError): self.prepare()
        linked = self.root / 'linked-proof'; linked.symlink_to(PROOF, target_is_directory=True)
        with self.assertRaises(ValueError): publisher.prepare_assets(component_installer_proof=linked)
        frame.unlink(); frame.write_bytes(original)
        manifest = self.proof / 'manifest.json'; manifest.unlink(); manifest.symlink_to(PROOF / 'manifest.json')
        with self.assertRaises(ValueError): self.prepare()

    def test_default_pages_do_not_gain_or_claim_component_proof(self):
        prepared = publisher.prepare_assets()
        self.assertIsNone(prepared.get('component_installer_proof'))
        self.assertEqual(len(prepared['assets']), 83)
        self.assertNotIn('evidence/component-installer/manifest.json', prepared['assets'])
        for name in ('index.html', 'en/index.html'):
            self.assertEqual(prepared['assets'][name], (publisher.SITE / name).read_bytes())


class Anchors(HTMLParser):
    def __init__(self):
        super().__init__(); self.downloads = []
    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'a' and 'download' in attrs:
            self.downloads.append(attrs.get('href'))


class IsoPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='m98-iso-controls-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.iso = self.root / 'public-development.iso'
        payload = bytearray(b'x' * (2 * 1024 * 1024 + 37))
        payload[32768:32775] = b'\x01CD001\x01'
        self.iso.write_bytes(payload)
        self.digest = hashlib.sha256(payload).hexdigest()
        self.size = len(payload)
        self.receipt = self.iso.with_suffix('.json')
        self.receipt_data = {'iso': str(self.iso), 'bytes': self.size,
                             'sha256': self.digest, 'private': False,
                             'git': {'revision': COMMIT, 'dirty': False}}
        self.write_receipt()

    def write_receipt(self):
        self.receipt.write_text(json.dumps(self.receipt_data))

    def open_iso(self, path=None, commit=COMMIT):
        self.assertTrue(hasattr(publisher, 'open_iso'), 'reviewed ISO input support is absent')
        candidate = publisher.open_iso(path or self.iso, commit)
        self.addCleanup(candidate.close)
        return candidate

    def test_regular_public_iso_streams_exact_bytes_and_truthful_metadata(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('whole-file reads forbidden')):
            candidate = self.open_iso()
            destination = self.root / 'copied.iso'
            candidate.copy_to(destination)
        self.assertEqual(destination.stat().st_size, self.size)
        self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(), self.digest)
        metadata = candidate.metadata
        self.assertEqual(metadata['artifact']['sha256'], self.digest)
        self.assertEqual(metadata['artifact']['bytes'], self.size)
        self.assertEqual(metadata['source_commit'], COMMIT)
        self.assertFalse(metadata['private'])
        self.assertFalse(metadata['windows98_media_included'])
        self.assertFalse(metadata['validation']['windows98_installer_complete'])
        self.assertFalse(metadata['validation']['latest_apps_complete'])
        self.assertEqual(metadata['validation']['boot_status'], 'not-verified-for-this-download')
        self.assertEqual(metadata['product'], 'ShizukuOS')
        self.assertEqual(metadata['release_target'], '1.0.0')
        self.assertEqual(metadata['release_channel'], 'development')
        self.assertEqual(metadata['distribution_origin'], 'https://m98.nyase.kr')
        self.assertEqual(candidate.name, 'downloads/shizukuos-development-1234567890ab-' + self.digest[:12] + '.iso')

    def desktop_evidence(self):
        # Contract from run_k64_desktop.py; this is a disposable host fixture,
        # never evidence of an actual boot or acceptance of the release ISO.
        members = ('EFI/BOOT/BOOTX64.EFI', 'SHZDOS/KERNEL64S.BIN', 'SHZDOS/WIN64.IMG',
                   'EFI/SHIZUKU/BOOT.INI', 'SHZDOS/KERNEL64.INI')
        artifacts = {'BOOTX64.EFI': '1' * 64, 'KERNEL64S.BIN': '2' * 64, 'WIN64.IMG': '3' * 64}
        global_names = [
            'WIN64.IMG contains the production desktop',
            'ISO frozen as an identical read-only private copy',
            'extracted EFI payload is the actual firmware-selected El Torito image',
            'shipped ISO selects Kernel64 without harness injection',
            'shipped ISO selects the production desktop command',
            'ISO matches its builder receipt',
            'ISO builder receipt describes production desktop media',
            'source ISO unchanged while freezing and inspecting it',
            'boot template remained unchanged',
            'source shipped ISO unchanged after both cold boots',
            'ISO builder receipt unchanged after both cold boots',
            'all inputs still match their current sources at completion',
        ]
        for name in artifacts:
            global_names += [name + ' matches its build receipt',
                             'shipped ISO ' + name + ' matches source-bound current build',
                             'original ' + name + ' unchanged']
        for kind in ('loader', 'kernel', 'runtime'):
            global_names += [kind + ' build records source hashes', kind + ' build matches current source',
                             kind + ' receipt unchanged']
        global_names += ['ISO receipt binds shipped ' + member for member in members]
        for number in (1, 2):
            global_names += ['boot-' + str(number) + ': ' + suffix for suffix in (
                'host independently extracted guest-written file', 'disk bytes equal exact host-selected text',
                'FAT32 volume consistent after guest writes', 'prepared seed file unchanged')]
        boot_names = [
            'UEFI boot manager selected Kernel64 and exited firmware boot services',
            'real UEFI GOP driver initialized before desktop',
            'AHCI driver mounted writable FAT32 D: volume',
            'production boot did not execute all-T application suite',
            'desktop registered its actual GUI window as the system shell',
            'production shell reached its own GUI readiness marker',
            'desktop persists while idle instead of a timed test screen',
            'Explorer enumerated the independently prepared writable D: volume',
            'editor reopened the saved file with expected length',
            'editor read exact host-selected text back',
            'desktop launched/reaped real Win64 child with documented exit code',
            'production shell exited cleanly only after F10',
            'Kernel64 flushed writable volume and intentionally stopped QEMU successfully',
            'production boot never ran the all-T suite',
        ]
        def checks(names): return [{'check': name, 'status': 'PASS', 'detail': ''} for name in names]
        private = '/PRIVATE-ONLY/desktop'
        frozen = private + '/boot.iso'
        data = private + '/data-working.img'
        boots = [{'boot': number, 'status': 'PASS', 'boot_medium': 'shipped-iso-cd',
                  'data_disk': data, 'qemu_exit_code': 1,
                  'checks': checks(boot_names + (['editor saved new nonempty text through real disk driver'] if number == 1 else [])),
                  'command': ['/usr/libexec/qemu-kvm', '-machine', 'q35',
                              '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/PRIVATE-ONLY/OVMF_CODE.fd',
                              '-drive', 'if=pflash,format=raw,unit=1,file=' + private + '/boot-' + str(number) + '/OVMF_VARS.fd',
                              '-drive', 'file=' + frozen + ',format=raw,if=none,id=boot,readonly=on,media=cdrom',
                              '-device', 'ide-cd,drive=boot,bus=ide.1,bootindex=1'],
                  'serial_tail': 'PRIVATE-ONLY', 'screenshots': []} for number in (1, 2)]
        return {'test': 'shizukudos/tests/run_k64_desktop.py', 'status': 'PASS',
                'checks': checks(global_names), 'boots': boots, 'data_disk': data,
                'boot_disk_sha256': self.digest, 'work': private,
                'iso': {'source': str(self.iso), 'frozen': frozen, 'sha256': self.digest,
                        'bytes': self.size, 'efi_lba': 42,
                        'efi_members_sha256': dict(zip(members, [*artifacts.values(), '4' * 64, '5' * 64])),
                        'receipt': {'path': str(self.receipt), 'sha256': hashlib.sha256(self.receipt.read_bytes()).hexdigest(),
                                    'recorded_iso': str(self.iso)}},
                'inputs': {'artifacts': artifacts}}

    def write_desktop_evidence(self, evidence=None):
        path = self.root / 'desktop-result.json'
        path.write_text(json.dumps(self.desktop_evidence() if evidence is None else evidence))
        return path

    def require_boot_evidence(self):
        self.assertTrue(hasattr(publisher, 'load_iso_boot_evidence'), 'production ISO boot-evidence validation is absent')

    def test_matching_desktop_evidence_is_sanitized_and_updates_both_languages(self):
        self.require_boot_evidence()
        path = self.write_desktop_evidence()
        prepared = publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=path)
        self.addCleanup(prepared['iso'].close)
        metadata = json.loads(prepared['assets']['downloads/release.json'])
        self.assertEqual(metadata['validation']['boot_status'], 'verified-uefi-development-desktop-two-cold-boots')
        self.assertEqual(metadata['validation']['boot_evidence'], {
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'cold_boots': 2,
            'firmware': 'UEFI', 'platform': 'QEMU q35 / Shizuku Kernel64'})
        self.assertFalse(metadata['validation']['windows98_installer_complete'])
        self.assertFalse(metadata['validation']['latest_apps_complete'])
        for name, sentence in [('index.html', 'UEFI 개발 데스크톱 두 번 콜드 부팅과 실제 저장·다시 열기 시험을 통과했습니다.'),
                               ('en/index.html', 'The UEFI development desktop passed two cold boots and real save/reopen tests.')]:
            text = prepared['assets'][name].decode()
            self.assertIn(sentence, text)
            self.assertNotIn('PRIVATE-ONLY', text)
        self.assertNotIn('PRIVATE-ONLY', json.dumps(metadata))

    def test_desktop_evidence_rejects_bad_status_identity_boot_count_and_media(self):
        self.require_boot_evidence()
        for label in ('status', 'test', 'iso hash', 'iso size', 'boot disk', 'one boot', 'repeated boot',
                      'boot status', 'boot medium', 'exit code', 'different disk', 'builder receipt'):
            with self.subTest(field=label):
                evidence = self.desktop_evidence()
                if label == 'status': evidence['status'] = 'FAIL'
                elif label == 'test': evidence['test'] = 'shizukudos/tests/run_k64_gop.py'
                elif label == 'iso hash': evidence['iso']['sha256'] = '0' * 64
                elif label == 'iso size': evidence['iso']['bytes'] = self.size + 1
                elif label == 'boot disk': evidence['boot_disk_sha256'] = '0' * 64
                elif label == 'one boot': evidence['boots'].pop()
                elif label == 'repeated boot': evidence['boots'][1]['boot'] = 1
                elif label == 'boot status': evidence['boots'][1]['status'] = 'FAIL'
                elif label == 'boot medium': evidence['boots'][1]['boot_medium'] = 'private-fixture-esp'
                elif label == 'exit code': evidence['boots'][1]['qemu_exit_code'] = 0
                elif label == 'different disk': evidence['boots'][1]['data_disk'] += '-other'
                elif label == 'builder receipt': evidence['iso']['receipt']['sha256'] = '0' * 64
                with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=self.write_desktop_evidence(evidence))

    def test_desktop_evidence_requires_each_semantic_gate_and_every_check_pass(self):
        self.require_boot_evidence()
        original = self.desktop_evidence()
        for location in ('global', 'boot1', 'boot2'):
            original_checks = original['checks'] if location == 'global' else original['boots'][int(location[-1]) - 1]['checks']
            for index, check in enumerate(original_checks):
                with self.subTest(location=location, missing=check['check']):
                    evidence = json.loads(json.dumps(original))
                    target = evidence['checks'] if location == 'global' else evidence['boots'][int(location[-1]) - 1]['checks']
                    del target[index]
                    with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=self.write_desktop_evidence(evidence))
            evidence = json.loads(json.dumps(original))
            target = evidence['checks'] if location == 'global' else evidence['boots'][int(location[-1]) - 1]['checks']
            target.append({'check': 'extra real check', 'status': 'FAIL', 'detail': ''})
            with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=self.write_desktop_evidence(evidence))

    def test_desktop_evidence_rejects_firmware_or_boot_command_injection(self):
        self.require_boot_evidence()
        for label in ('BIOS', 'machine', 'writable boot', 'other ISO', 'injected kernel'):
            with self.subTest(field=label):
                evidence = self.desktop_evidence()
                command = evidence['boots'][1]['command']
                if label == 'BIOS': command[command.index('-drive') + 1] = 'if=none,format=raw,file=/PRIVATE-ONLY/BIOS.bin'
                elif label == 'machine': command[command.index('-machine') + 1] = 'pc'
                elif label == 'writable boot': command[-3] = command[-3].replace('readonly=on', 'readonly=off')
                elif label == 'other ISO': command[-3] = command[-3].replace('/boot.iso', '/fixture.iso')
                elif label == 'injected kernel': command += ['-kernel', '/PRIVATE-ONLY/injected.bin']
                with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=self.write_desktop_evidence(evidence))

    def test_boot_evidence_without_iso_and_malformed_evidence_fail_closed(self):
        self.require_boot_evidence()
        path = self.write_desktop_evidence()
        with self.assertRaises(ValueError): publisher.prepare_assets(iso_boot_evidence=path)
        for invalid in ([], None, 'not evidence', {'status': 'PASS'}):
            path.write_text(json.dumps(invalid))
            with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=path)
        path.write_text('{invalid')
        with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=path)
        path.unlink(); path.symlink_to(self.receipt)
        with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, COMMIT, iso_boot_evidence=path)

    def test_private_media_receipt_is_rejected(self):
        self.receipt_data['private'] = True; self.write_receipt()
        self.assertTrue(hasattr(publisher, 'open_iso'), 'reviewed ISO input support is absent')
        with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)

    def test_identity_corruption_is_rejected(self):
        self.assertTrue(hasattr(publisher, 'open_iso'), 'reviewed ISO input support is absent')
        for field, value in [('sha256', '0' * 64), ('bytes', self.size + 1),
                             ('iso', str(self.root / 'other.iso'))]:
            with self.subTest(field=field):
                self.receipt_data[field] = value; self.write_receipt()
                with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)
                self.receipt_data[field] = {'sha256': self.digest, 'bytes': self.size, 'iso': str(self.iso)}[field]

    def test_malformed_commit_or_receipt_is_rejected(self):
        self.assertTrue(hasattr(publisher, 'open_iso'), 'reviewed ISO input support is absent')
        for commit in ['main', '../downloads/escape', COMMIT + '\n', 'g' * 40]:
            with self.subTest(commit=commit):
                with self.assertRaises(ValueError): publisher.open_iso(self.iso, commit)
        self.receipt_data['git']['revision'] = '0' * 40; self.write_receipt()
        with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)
        self.receipt.write_text('{malformed')
        with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)
        for invalid_shape in [[], None, 'not a receipt']:
            with self.subTest(receipt_shape=invalid_shape):
                self.receipt.write_text(json.dumps(invalid_shape))
                with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)

    def test_symlink_and_non_regular_paths_are_rejected(self):
        self.assertTrue(hasattr(publisher, 'open_iso'), 'reviewed ISO input support is absent')
        link = self.root / 'linked.iso'; link.symlink_to(self.iso)
        with self.assertRaises(ValueError): publisher.open_iso(link, COMMIT)
        directory = self.root / 'directory.iso'; directory.mkdir()
        with self.assertRaises(ValueError): publisher.open_iso(directory, COMMIT)
        self.receipt.unlink(); self.receipt.symlink_to(self.root / 'other.json')
        with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)

    def test_zero_oversized_or_non_iso_inputs_are_rejected(self):
        self.assertTrue(hasattr(publisher, 'open_iso'), 'reviewed ISO input support is absent')
        for size in [0, 512 * 1024 * 1024 + 1]:
            with self.subTest(size=size):
                with self.iso.open('wb') as stream: stream.truncate(size)
                with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)
        self.iso.write_bytes(b'x' * self.size)
        self.receipt_data['sha256'] = hashlib.sha256(self.iso.read_bytes()).hexdigest(); self.write_receipt()
        with self.assertRaises(ValueError): publisher.open_iso(self.iso, COMMIT)

    def test_281_mib_sparse_iso_streams_without_claiming_a_boot(self):
        # Sparse host contract input; this is not a release or a boot record.
        with self.iso.open('wb') as stream:
            stream.truncate(281 * 1024 * 1024)
            stream.seek(32768); stream.write(b'\x01CD001\x01')
        digest = hashlib.sha256()
        with self.iso.open('rb') as stream:
            while chunk := stream.read(1024 * 1024): digest.update(chunk)
        self.receipt_data.update(bytes=self.iso.stat().st_size, sha256=digest.hexdigest())
        self.write_receipt()
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('whole ISO reads forbidden')):
            candidate = self.open_iso()
        self.assertEqual(publisher.ISO_LIMIT, 512 * 1024 * 1024)
        self.assertEqual(candidate.metadata['artifact']['bytes'], 281 * 1024 * 1024)
        self.assertEqual(candidate.metadata['validation']['boot_status'], 'not-verified-for-this-download')
        self.assertFalse(candidate.metadata['validation']['windows98_installer_complete'])
        self.assertFalse(candidate.metadata['validation']['latest_apps_complete'])
        with self.assertRaises(ValueError): publisher.read_small(self.iso)

    def test_iso_512_mib_exact_bound_and_larger_rejected_before_read(self):
        large = self.root / 'bounded.iso'
        with large.open('wb') as stream: stream.truncate(512 * 1024 * 1024)
        with publisher.open_regular(large, publisher.ISO_LIMIT) as stream:
            self.assertEqual(os.fstat(stream.fileno()).st_size, 512 * 1024 * 1024)
        with large.open('wb') as stream: stream.truncate(512 * 1024 * 1024 + 1)
        with patch.object(publisher, 'stream_digest', side_effect=AssertionError('oversized ISO must not be read')):
            with self.assertRaises(ValueError): publisher.open_iso(large, COMMIT)
        self.assertEqual(publisher.SMALL_LIMIT, 8 * 1024 * 1024)

    def test_changed_open_source_cannot_be_copied_as_reviewed(self):
        candidate = self.open_iso()
        with self.iso.open('r+b') as stream: stream.write(b'changed')
        with self.assertRaises(ValueError): candidate.copy_to(self.root / 'stale.iso')

    def test_rendered_languages_share_four_iso_ctas_and_keep_zip_download(self):
        candidate = self.open_iso()
        self.assertTrue(hasattr(publisher, 'render_iso_homepage'), 'ISO home page rendering is absent')
        for language, name, prefix in [('ko', 'index.html', './'), ('en', 'en/index.html', '../')]:
            with self.subTest(language=language):
                original = (publisher.SITE / name).read_bytes()
                rendered = publisher.render_iso_homepage(original, candidate.metadata, language)
                parser = Anchors(); parser.feed(rendered.decode())
                self.assertEqual(parser.downloads.count(prefix + candidate.name), 4)
                self.assertIn(prefix + 'downloads/shizuku-modern-preview-2026.10.01.zip', parser.downloads)
                self.assertIn(self.digest[:12], rendered.decode())
                self.assertIn(prefix + 'downloads/release.json', rendered.decode())

    def test_no_iso_assets_remain_exact_source_bytes(self):
        self.assertTrue(hasattr(publisher, 'prepare_assets'), 'testable static preparation is absent')
        prepared = publisher.prepare_assets()
        self.assertIsNone(prepared['iso'])
        self.assertEqual(len(prepared['assets']), 83)
        for name, data in prepared['assets'].items():
            self.assertEqual(data, (publisher.SITE / name).read_bytes(), name)
        self.assertNotIn('downloads/release.json', prepared['assets'])

    def test_iso_adds_three_assets_and_source_pages_stay_unmodified(self):
        self.assertTrue(hasattr(publisher, 'prepare_assets'), 'testable static preparation is absent')
        before = {name: (publisher.SITE / name).read_bytes() for name in ['index.html', 'en/index.html']}
        prepared = publisher.prepare_assets(self.iso, COMMIT)
        self.addCleanup(prepared['iso'].close)
        self.assertEqual(len(prepared['assets']) + 1, 86)
        checksum = prepared['assets'][prepared['iso'].name + '.sha256'].decode('ascii')
        self.assertEqual(checksum, self.digest + '  ' + Path(prepared['iso'].name).name + '\n')
        metadata = json.loads(prepared['assets']['downloads/release.json'])
        self.assertEqual(metadata, prepared['iso'].metadata)
        for name, data in before.items(): self.assertEqual(data, (publisher.SITE / name).read_bytes())

    def test_component_proof_cannot_replace_exact_shipped_iso_boot_evidence(self):
        prepared = publisher.prepare_assets(self.iso, COMMIT, component_installer_proof=PROOF)
        self.addCleanup(prepared['iso'].close)
        self.assertEqual(len(prepared['assets']) + 1, 91)
        metadata = json.loads(prepared['assets']['downloads/release.json'])
        self.assertEqual(metadata['validation']['boot_status'], 'not-verified-for-this-download')
        self.assertFalse(metadata['validation']['windows98_installer_complete'])
        self.assertFalse(metadata['validation']['latest_apps_complete'])
        self.assertNotIn('iso_boot_evidence', metadata)
        self.assertEqual(prepared['component_installer_proof']['actual_vm_count'], 4)
        for name, warning in [('index.html', '별도로 확인하세요.'),
                              ('en/index.html', 'Check release information separately')]:
            self.assertIn(warning, prepared['assets'][name].decode())
        path = self.root / 'rejected-shipped-iso.json'
        evidence = self.desktop_evidence(); evidence['status'] = 'FAIL'
        path.write_text(json.dumps(evidence))
        with self.assertRaises(ValueError):
            publisher.prepare_assets(self.iso, COMMIT, path, component_installer_proof=PROOF)

    def test_origin_headers_reject_full_body_for_range_and_wrong_lengths(self):
        candidate = self.open_iso()
        self.assertTrue(hasattr(publisher, 'validate_iso_headers'), 'ISO origin range validation is absent')
        head = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(self.size).encode() + b'\r\nContent-Type: application/octet-stream\r\n\r\n'
        ranged = b'HTTP/1.1 206 Partial Content\r\nContent-Length: 2048\r\nContent-Range: bytes 0-2047/' + str(self.size).encode() + b'\r\n\r\n'
        with self.iso.open('rb') as stream:
            prefix = stream.read(2048)
        publisher.validate_iso_headers(head, ranged, prefix, candidate.metadata, prefix)
        for broken_head, broken_range, body in [(head.replace(str(self.size).encode(), b'1'), ranged, prefix), (head, ranged.replace(b'206 Partial Content', b'200 OK'), prefix), (head, ranged.replace(b'0-2047', b'1-2048'), prefix), (head, ranged, prefix[:-1]), (head, ranged, b'y' * 2048)]:
            with self.subTest(body_length=len(body)):
                with self.assertRaises(ValueError): publisher.validate_iso_headers(broken_head, broken_range, body, candidate.metadata, prefix)

    def test_truncated_or_changed_origin_file_fails_complete_digest(self):
        self.assertTrue(hasattr(publisher, 'verify_download'), 'bounded ISO verification is absent')
        publisher.verify_download(self.iso, self.size, self.digest)
        with self.iso.open('r+b') as stream:
            stream.truncate(self.size - 1)
        with self.assertRaises(ValueError): publisher.verify_download(self.iso, self.size, self.digest)

    def test_small_asset_bound_and_complete_iso_option_pair_are_required(self):
        self.assertTrue(hasattr(publisher, 'read_small'), 'small static file admission is absent')
        large = self.root / 'large.json'
        with large.open('wb') as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError): publisher.read_small(large)
        with self.assertRaises(ValueError): publisher.prepare_assets(self.iso, None)
        with self.assertRaises(ValueError): publisher.prepare_assets(None, COMMIT)

    def publication_environment(self):
        base = self.root / 'origin'
        previous = base / 'releases' / 'previous'
        previous.mkdir(parents=True)
        (base / 'current').symlink_to(previous)
        return base, previous

    def exact_local_curl(self, base, command, **kwargs):
        # Replace only the external curl transport. Publish/copy/symlink/receipt
        # operations remain real in this isolated directory.
        name = command[-1].removeprefix('https://m98.nyase.kr/')
        destination = Path(command[command.index('--output') + 1])
        destination.write_bytes((base / 'current' / 'site' / name).read_bytes())
        return subprocess.CompletedProcess(command, 0, '', '')

    def test_component_proof_origin_hashes_and_publication_receipt_remain_separate(self):
        prepared = publisher.prepare_assets(component_installer_proof=PROOF)
        base, previous = self.publication_environment()
        with patch.object(publisher, 'BASE', base), patch.object(publisher, 'ROOT', self.root), \
             patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kwargs: self.exact_local_curl(base, cmd, **kwargs)), \
             redirect_stdout(io.StringIO()):
            publisher.publish(prepared)
        records = list((self.root / 'build/m98-self-host').glob('release-*.json'))
        self.assertEqual(len(records), 1)
        receipt = json.loads(records[0].read_bytes())
        self.assertEqual(receipt['component_installer_proof'], json.loads((PROOF / 'manifest.json').read_bytes()))
        self.assertEqual(receipt['origin_check_count'], 88)
        self.assertFalse(receipt['public_edge_verified'])
        self.assertNotIn('iso_release', receipt)
        checks = {row['path']: row for row in receipt['origin_checks']}
        for frame in receipt['component_installer_proof']['frames']:
            name = '/evidence/component-installer/' + frame['file']
            self.assertEqual(checks[name]['sha256'], frame['sha256'])
            self.assertEqual(checks[name]['bytes'], frame['bytes'])

    def test_receipt_persistence_failure_restores_previous_publication(self):
        prepared = publisher.prepare_assets()
        base, previous = self.publication_environment()
        original_fdopen = os.fdopen
        class FailedReceiptWrite:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def write(self, payload):
                raise OSError(errno.ENOSPC, 'modeled final receipt persistence failure')
            def __exit__(self, *args): self.stream.close()
        def fail_receipt_write(fd, mode='r', *args, **kwargs):
            stream = original_fdopen(fd, mode, *args, **kwargs)
            return FailedReceiptWrite(stream) if mode == 'wb' else stream
        with patch.object(publisher, 'BASE', base), patch.object(publisher, 'ROOT', self.root), \
             patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kwargs: self.exact_local_curl(base, cmd, **kwargs)), \
             patch.object(publisher.os, 'fdopen', new=fail_receipt_write):
            with self.assertRaises(OSError): publisher.publish(prepared)
        self.assertEqual((base / 'current').resolve(), previous)
        output = self.root / 'build/m98-self-host'
        self.assertFalse(list(output.glob('release-*.json')))
        self.assertFalse(list(output.glob('*.tmp')))

    def test_failed_publication_does_not_replace_a_newer_foreign_release(self):
        prepared = publisher.prepare_assets()
        base, previous = self.publication_environment()
        other = base / 'releases' / 'other-publisher'; other.mkdir()
        def other_publication_then_failure(command, **kwargs):
            staged = base / 'foreign-current'; staged.symlink_to(other)
            os.replace(staged, base / 'current')
            return subprocess.CompletedProcess(command, 22, '', 'modeled origin failure')
        with patch.object(publisher, 'BASE', base), patch.object(publisher, 'ROOT', self.root), \
             patch.object(publisher.subprocess, 'run', side_effect=other_publication_then_failure):
            with self.assertRaises(RuntimeError): publisher.publish(prepared)
        self.assertEqual((base / 'current').resolve(), other)

    def test_partial_parseable_pass_receipt_is_never_left_at_canonical_path(self):
        prepared = publisher.prepare_assets()
        base, previous = self.publication_environment()
        original_write = Path.write_bytes
        original_fdopen = os.fdopen
        class FailedReceiptClose:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def write(self, payload):
                self.stream.write(payload[:-1])
                return len(payload)
            def __exit__(self, *args):
                self.stream.close()
                raise OSError(errno.ENOSPC, 'modeled partial buffered receipt close failure')
        def fail_buffered_close(fd, mode='r', *args, **kwargs):
            stream = original_fdopen(fd, mode, *args, **kwargs)
            return FailedReceiptClose(stream) if mode == 'wb' else stream
        def fail_old_canonical_write(path, payload):
            if path.name.startswith('release-') and path.parent.name == 'm98-self-host':
                original_write(path, payload[:-1])
                raise OSError(errno.ENOSPC, 'modeled partial canonical receipt failure')
            return original_write(path, payload)
        with patch.object(publisher, 'BASE', base), patch.object(publisher, 'ROOT', self.root), \
             patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kwargs: self.exact_local_curl(base, cmd, **kwargs)), \
             patch.object(Path, 'write_bytes', new=fail_old_canonical_write), \
             patch.object(publisher.os, 'fdopen', new=fail_buffered_close):
            with self.assertRaises(OSError): publisher.publish(prepared)
        self.assertEqual((base / 'current').resolve(), previous)
        output = self.root / 'build/m98-self-host'
        self.assertFalse(list(output.glob('release-*.json')))
        self.assertFalse(list(output.glob('*.tmp')))

    def test_receipt_short_write_cannot_become_canonical_even_if_count_is_misreported(self):
        payload = b'{"status": "PASS"}\n'
        original_fdopen = os.fdopen
        for reported_complete in (False, True):
            with self.subTest(reported_complete=reported_complete):
                path = self.root / ('release-' + str(reported_complete) + '.json')
                class ShortReceiptWrite:
                    def __init__(self, stream): self.stream = stream
                    def __enter__(self): return self
                    def write(self, data):
                        self.stream.write(data[:-1])
                        return len(data) if reported_complete else len(data) - 1
                    def __exit__(self, *args): self.stream.close()
                def short_write(fd, mode='r', *args, **kwargs):
                    stream = original_fdopen(fd, mode, *args, **kwargs)
                    return ShortReceiptWrite(stream) if mode == 'wb' else stream
                with patch.object(publisher.os, 'fdopen', new=short_write):
                    with self.assertRaises(OSError): publisher.write_receipt(path, payload)
                self.assertFalse(path.exists())
                self.assertFalse(list(self.root.glob('*.tmp')))

    def test_receipt_atomic_replace_failure_cleans_complete_temporary_record(self):
        path = self.root / 'release-atomic.json'
        payload = b'{"status": "PASS"}\n'
        def fail_replace(source, destination):
            self.assertEqual(Path(source).parent, path.parent)
            self.assertEqual(Path(destination), path)
            self.assertEqual(Path(source).read_bytes(), payload)
            self.assertFalse(path.exists())
            raise OSError(errno.ENOSPC, 'modeled receipt rename failure')
        with patch.object(publisher.os, 'replace', new=fail_replace):
            with self.assertRaises(OSError): publisher.write_receipt(path, payload)
        self.assertFalse(path.exists())
        self.assertFalse(list(self.root.glob('*.tmp')))

    def test_cooperating_publications_cannot_hold_the_same_lock(self):
        self.assertTrue(hasattr(publisher, 'publication_lock'), 'publication coordination is absent')
        path = self.root / 'publish.lock'
        with publisher.publication_lock(path):
            with self.assertRaises(ValueError):
                with publisher.publication_lock(path):
                    self.fail('a second publisher entered the transaction')
        with publisher.publication_lock(path):
            pass

    def local_iso_curl(self, base, command, bad_head=False, **kwargs):
        name = command[-1].removeprefix('https://m98.nyase.kr/')
        source = base / 'current' / 'site' / name
        destination = Path(command[command.index('--output') + 1])
        if '--head' in command:
            size = source.stat().st_size + int(bad_head)
            destination.write_bytes(('HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ' + str(size) + '\r\n\r\n').encode())
        elif '--dump-header' in command:
            with source.open('rb') as stream:
                destination.write_bytes(stream.read(2048))
            header = Path(command[command.index('--dump-header') + 1])
            header.write_bytes(('HTTP/1.1 206 Partial Content\r\nContent-Length: 2048\r\nContent-Range: bytes 0-2047/' + str(source.stat().st_size) + '\r\n\r\n').encode())
        else:
            shutil.copyfile(source, destination)
        return subprocess.CompletedProcess(command, 0, '', '')

    def test_complete_iso_publication_copies_records_and_validates_three_transport_forms(self):
        prepared = publisher.prepare_assets(self.iso, COMMIT)
        self.addCleanup(prepared['iso'].close)
        base, previous = self.publication_environment()
        with patch.object(publisher, 'BASE', base), patch.object(publisher, 'ROOT', self.root), \
             patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kwargs: self.local_iso_curl(base, cmd, **kwargs)), \
             redirect_stdout(io.StringIO()):
            publisher.publish(prepared)
        receipt_path, = (self.root / 'build/m98-self-host').glob('release-*.json')
        receipt = json.loads(receipt_path.read_text())
        self.assertNotEqual((base / 'current').resolve(), previous)
        self.assertEqual(receipt['origin_check_count'], 86)
        self.assertTrue(receipt['iso_head_and_range_verified'])
        self.assertEqual(receipt['iso_release'], prepared['iso'].metadata)
        self.assertFalse(receipt['public_edge_verified'])
        self.assertEqual(hashlib.sha256((base / 'current/site' / prepared['iso'].name).read_bytes()).hexdigest(), self.digest)

    def test_invalid_iso_head_restores_previous_after_full_digest_success(self):
        prepared = publisher.prepare_assets(self.iso, COMMIT)
        self.addCleanup(prepared['iso'].close)
        base, previous = self.publication_environment()
        with patch.object(publisher, 'BASE', base), patch.object(publisher, 'ROOT', self.root), \
             patch.object(publisher.subprocess, 'run', side_effect=lambda cmd, **kwargs: self.local_iso_curl(base, cmd, bad_head=True, **kwargs)):
            with self.assertRaises(ValueError): publisher.publish(prepared)
        self.assertEqual((base / 'current').resolve(), previous)
        self.assertFalse(list((self.root / 'build/m98-self-host').glob('release-*.json')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
