"""Source/fixture preservation boundaries; these tests start no guest."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from iewebkit_audit_guest import partition_start
from iewebkit_guest_fixture import create
from iewebkit_build_win98 import build
from iewebkit_verify_guest import verify
from iewebkit_unicode_fixture import create as create_unicode
from iewebkit_verify_unicode import verify as verify_unicode


class IntegrationBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bundle(self):
        folder = self.root / 'build' / 'bundle'
        folder.mkdir(parents=True)
        artifacts = {}
        for name in ('IETARGET.EXE', 'HOSTTEST.EXE', 'NAVTEST.EXE', 'NAVVALUE.EXE'):
            content = ('synthetic nonexecutable ' + name).encode()
            (folder / name).write_bytes(content)
            artifacts[name] = {'sha256': hashlib.sha256(content).hexdigest()}
        report = {'schema': 'win98modern.iewebkit-build.v1', 'static_gate_passed': True,
                  'target': {'ie_version': '5.00.2614.3500'}, 'artifacts': artifacts}
        (folder.parent / 'build.json').write_text(json.dumps(report))
        return folder

    def test_fixture_preserves_inputs_and_binds_fresh_nonce(self):
        bundle = self.bundle()
        before = {path.name: path.read_bytes() for path in bundle.iterdir()}
        report = create(bundle, self.root / 'fixture')
        manifest = Path(report['manifest']).read_bytes()
        self.assertEqual(hashlib.sha256(manifest).hexdigest(), report['sha256'])
        data = json.loads(manifest)
        self.assertEqual(data['nonce'], report['nonce'])
        self.assertFalse({item['guest'] for item in data['inputs']} & set(data['outputs']))
        self.assertEqual(before, {path.name: path.read_bytes() for path in bundle.iterdir()})
        batch = (self.root / 'fixture/RUNIE.BAT').read_bytes()
        self.assertIn(report['nonce'].encode(), batch)
        self.assertNotIn(b'regsvr32', batch)

    def test_modified_binary_is_rejected_before_output_creation(self):
        bundle = self.bundle()
        (bundle / 'HOSTTEST.EXE').write_bytes(b'changed')
        output = self.root / 'fixture'
        with self.assertRaisesRegex(ValueError, 'differs'):
            create(bundle, output)
        self.assertFalse(output.exists())

    def test_winme_target_is_not_accepted(self):
        bundle = self.bundle()
        path = bundle.parent / 'build.json'
        report = json.loads(path.read_text())
        report['target']['ie_version'] = '5.50.4134.0100'
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'installed Win98'):
            create(bundle, self.root / 'fixture')

    def test_existing_fixture_output_is_untouched(self):
        bundle = self.bundle()
        output = self.root / 'fixture'
        output.mkdir()
        (output / 'keep').write_bytes(b'owned')
        with self.assertRaisesRegex(ValueError, 'exists'):
            create(bundle, output)
        self.assertEqual((output / 'keep').read_bytes(), b'owned')

    def test_oversized_native_addition_is_rejected_without_output(self):
        bundle = self.bundle()
        extra = self.root / 'RUNLOOP.EXE'
        extra.write_bytes(bytes(1024 ** 2 + 1))
        output = self.root / 'fixture'
        with self.assertRaisesRegex(ValueError, 'size limit'):
            create(bundle, output, extra)
        self.assertFalse(output.exists())

    def test_builder_does_not_overwrite_existing_output(self):
        output = self.root / 'existing'
        output.mkdir()
        (output / 'keep').write_bytes(b'owned')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            build(self.root / 'no-checkout', output, self.root / 'no-baseline')
        self.assertEqual((output / 'keep').read_bytes(), b'owned')

    def test_partition_selector_rejects_multiple_active_and_bad_signature(self):
        mbr = bytearray(512)
        mbr[510:] = b'\x55\xaa'
        mbr[446], mbr[450] = 0x80, 0x0c
        struct.pack_into('<II', mbr, 454, 63, 100000)
        self.assertEqual(partition_start(bytes(mbr)), 63)
        mbr[462], mbr[466] = 0x80, 0x0b
        struct.pack_into('<II', mbr, 470, 200000, 100000)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            partition_start(bytes(mbr))
        mbr[510:] = b'\x00\x00'
        with self.assertRaisesRegex(ValueError, 'signed MBR'):
            partition_start(bytes(mbr))

    def run_evidence(self):
        run = self.root / 'owned-run'
        run.mkdir()
        nonce = '83bd-synthetic'
        inputs = [{'guest': 'C:\\GOPLAB\\' + name,
                   'sha256': hashlib.sha256(name.encode()).hexdigest()}
                  for name in ('IETARGET.EXE', 'HOSTTEST.EXE', 'NAVTEST.EXE', 'NAVVALUE.EXE')]
        manifest = {'schema': 1, 'kind': 'isolated-guest-file-inputs', 'nonce': nonce, 'inputs': inputs}
        manifest_path = self.root / 'manifest.json'
        manifest_raw = json.dumps(manifest).encode()
        manifest_path.write_bytes(manifest_raw)
        logs = {
            'IETARGET.LOG': ('schema=win98modern.iewebkit-target.v1\nnonce=' + nonce +
                '\nos=4.10.2222\nplatform=1\nshdocvw_version=5.0.2614.3500\n'
                'iexplore_version=5.0.2614.3500\ntarget_matched=1\nprovider_status=-2\n').encode(),
            'HOSTTEST.LOG': b'PASS DocObject site replacement; reentrant deactivation ownership\n',
            'NAVTEST.LOG': (b'remote_moniker_equal=0x00000001\n' * 2 +
                            b'all_moniker_checks=0x00000001\n'),
            'NAVVALUE.LOG': b'PASS nested IE variants, cyclic rejection, nonempty headers and POST rejection\n',
            'IEDONE.TXT': nonce.encode() + b'\r\n'}
        captures = []
        for name, content in logs.items():
            path = run / name
            path.write_bytes(content)
            captures.append({'guest': 'C:\\GOPLAB\\' + name, 'status': 'captured',
                'freshness': 'new-in-owned-run', 'path': str(path),
                'sha256': hashlib.sha256(content).hexdigest()})
        report = {'profile': 'actual-win98-uefi-csmwrap', 'qemu_exit_code': 0,
                  'originals_unchanged': True, 'prepared_source_unchanged': True,
                  'command': ['qemu', '-nic', 'none'],
                  'guest_files': {'immutable_sources_unchanged': True,
                      'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
                      'inputs': [item | {'private_copy_sha256': item['sha256']} for item in inputs],
                      'readback': captures}}
        (run / 'result.json').write_text(json.dumps(report))
        return run, manifest_path

    def test_returned_log_tamper_is_rejected(self):
        run, manifest = self.run_evidence()
        self.assertTrue(verify(run, manifest)['native_diagnostics_passed'])
        (run / 'HOSTTEST.LOG').write_bytes(b'changed result')
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            verify(run, manifest)

    def test_runtime_me_version_cannot_certify_win98(self):
        run, manifest = self.run_evidence()
        path = run / 'IETARGET.LOG'
        path.write_bytes(path.read_bytes().replace(b'os=4.10.2222', b'os=4.90.3000'))
        report = json.loads((run / 'result.json').read_text())
        report['guest_files']['readback'][0]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        (run / 'result.json').write_text(json.dumps(report))
        checked = verify(run, manifest)
        self.assertFalse(checked['native_diagnostics_passed'])
        self.assertFalse(checked['engine_rendering_verified'])

    def test_failed_owned_shutdown_is_rejected(self):
        run, manifest = self.run_evidence()
        report = json.loads((run / 'result.json').read_text())
        report['qemu_exit_code'] = 1
        (run / 'result.json').write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'shutdown'):
            verify(run, manifest)

    def unicode_evidence(self):
        run, manifest_path = self.run_evidence()
        manifest = json.loads(manifest_path.read_text())
        inputs = [{'guest': 'C:\\GOPLAB\\' + name,
                   'sha256': hashlib.sha256(name.encode()).hexdigest()}
                  for name in ('IETARGET.EXE', 'RLCMP.EXE', 'RUNUNI.BAT')]
        manifest['inputs'] = inputs
        manifest['probe_sha256'] = inputs[1]['sha256']
        manifest_raw = json.dumps(manifest).encode()
        manifest_path.write_bytes(manifest_raw)
        report = json.loads((run / 'result.json').read_text())
        files = report['guest_files']
        files['manifest_sha256'] = hashlib.sha256(manifest_raw).hexdigest()
        files['inputs'] = [item | {'private_copy_sha256': item['sha256']} for item in inputs]
        files['readback'] = [files['readback'][0]]
        logs = {'RLCMP.LOG': (
            'scope=Actual-WTF-RunLoop-Windows-API-comparison\n'
            'os.major=4\nos.minor=10\nos.win9x=1\n'
            'original.RegisterClassW.atom=0\noriginal.RegisterClassW.error=120\n'
            'original.CreateWindowExW.skipped=class-registration-failed\n'
            'ported.RegisterClassA.error=0\nported.CreateWindowExA.created=1\n'
            'ported.CreateWindowExA.error=0\nported.GetWindowLongA.context=1\n'
            'ported.WM_CREATE=1\nexit=0\n').encode(),
            'RLDONE.TXT': manifest['nonce'].encode() + b'\r\n'}
        for name, raw in logs.items():
            path = run / name
            path.write_bytes(raw)
            files['readback'].append({'guest': 'C:\\GOPLAB\\' + name, 'path': str(path),
                'status': 'captured', 'freshness': 'new-in-owned-run',
                'sha256': hashlib.sha256(raw).hexdigest()})
        (run / 'result.json').write_text(json.dumps(report))
        source = self.root / 'probe.c'
        source.write_bytes(b'synthetic diagnostic source')
        receipt = self.root / 'probe-receipt.json'
        receipt.write_text(json.dumps({'schema': 'iewebkit-native-runloop-api-comparison-v1',
            'binary_sha256': manifest['probe_sha256'],
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'backend_sha256': hashlib.sha256(b'synthetic helper').hexdigest(),
            'import_gate': 'PASS', 'missing_exports': {}}))
        return run, manifest_path, receipt, source

    def test_unicode_source_receipt_and_skipped_create_are_precise(self):
        report = verify_unicode(*self.unicode_evidence())
        self.assertTrue(report['native_diagnostics_passed'])
        self.assertEqual(report['original_RegisterClassW']['error'], 120)
        self.assertFalse(report['original_CreateWindowExW']['attempted'])
        self.assertIsNone(report['original_CreateWindowExW']['created'])
        self.assertFalse(report['engine_rendering_verified'])
        self.assertFalse(report['browser_trial_performed'])

    def test_unicode_receipt_rejects_probe_source_change(self):
        run, manifest, receipt, source = self.unicode_evidence()
        source.write_bytes(b'changed after compilation')
        with self.assertRaisesRegex(ValueError, 'source/import receipt'):
            verify_unicode(run, manifest, receipt, source)

    def test_unicode_fixture_requires_selected_probe_before_writing(self):
        bundle = self.bundle()
        probe = self.root / 'RLCMP.EXE'
        probe.write_bytes(b'selected nonexecutable fixture')
        expected = hashlib.sha256(probe.read_bytes()).hexdigest()
        before = {p.name: p.read_bytes() for p in bundle.iterdir()}
        probe.write_bytes(b'changed')
        output = self.root / 'unicode-fixture'
        with self.assertRaisesRegex(ValueError, 'selected digest'):
            create_unicode(probe, expected, bundle, output)
        self.assertFalse(output.exists())
        self.assertEqual(before, {p.name: p.read_bytes() for p in bundle.iterdir()})


if __name__ == '__main__':
    unittest.main()
