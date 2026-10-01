# SPDX-License-Identifier: GPL-2.0-or-later
"""Host rejection controls; no process is started and no guest is operated."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    'wtf_control', Path(__file__).resolve().parents[1] / 'iewebkit_wtf_control.py')
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class ControlTests(unittest.TestCase):
    def manifest(self):
        nonce = '83bd-wtf-' + 'a' * 32
        return dict(nonce=nonce, command=control.OBSERVER + ' ' + nonce,
                    inputs=[dict(guest=name) for name in sorted(control.INPUTS)],
                    outputs=[r'C:\GOPLAB\WTFNAT.LOG', r'C:\GOPLAB\WTFEXIT.LOG'],
                    backups=[], post_crt_exit_required=True,
                    requires_nic_absent=True, requires_absent_guest_paths=True)

    def validate(self, obj, *, wrong_hash=False, escape_input=False, wrong_input_hash=False):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / 'package'
            package.mkdir()
            for index, row in enumerate(obj['inputs']):
                payload = row['guest'].encode()
                source = (Path(temp) if escape_input and index == 0 else package) / f'input-{index}.exe'
                source.write_bytes(payload)
                row.update(source=str(source), bytes=len(payload),
                           sha256='0' * 64 if wrong_input_hash else hashlib.sha256(payload).hexdigest())
            path = package / 'manifest.json'
            raw = json.dumps(obj).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest() if not wrong_hash else '0' * 64
            return control.validate_manifest(path, digest)

    def test_exact_observer_manifest(self):
        manifest = self.manifest()
        self.assertEqual(self.validate(manifest)[1], manifest['command'])

    def test_same_bytes_outside_manifest_package_are_rejected_before_boot(self):
        with self.assertRaises(ValueError):
            self.validate(self.manifest(), escape_input=True)
        with self.assertRaises(ValueError):
            self.validate(self.manifest(), wrong_input_hash=True)

    def test_diagnostic_output_requires_exact_closed_checkpoint_scope(self):
        manifest = self.manifest()
        manifest['outputs'].insert(1, r'C:\GOPLAB\WTFABRT.LOG')
        with self.assertRaises(ValueError):
            self.validate(manifest)
        manifest['diagnostic_scope'] = {'closed_checkpoint_handles': True}
        self.assertEqual(self.validate(manifest)[1], manifest['command'])
        manifest['diagnostic_scope']['closed_checkpoint_handles'] = False
        with self.assertRaises(ValueError):
            self.validate(manifest)

    def test_hash_command_nonce_and_target_changes_are_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(self.manifest(), wrong_hash=True)
        for key, value in [('nonce', 'reused'), ('command', 'C:\\OTHER.EXE'),
                           ('inputs', [{'guest': 'C:\\OTHER.EXE'}]),
                           ('outputs', [r'C:\GOPLAB\WTFNAT.LOG']),
                           ('backups', [{'guest': 'C:\\SYSTEM.INI'}]),
                           ('post_crt_exit_required', False),
                           ('requires_nic_absent', False),
                           ('requires_absent_guest_paths', False)]:
            with self.subTest(key=key):
                obj = self.manifest()
                obj[key] = value
                with self.assertRaises(ValueError):
                    self.validate(obj)

    def test_only_exact_owned_disk_without_nic(self):
        run = Path('/tmp/owned-trial')
        args = ['qemu-kvm', '-nic', 'none', '-device', 'VGA', '-device',
                'ide-hd,drive=win98,bus=ide.0,bootindex=1',
                '-drive', 'if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
                '-drive', 'if=pflash,unit=1,format=raw,file=/tmp/owned-trial/OVMF_VARS.fd',
                '-drive', 'file=/tmp/owned-trial/windows-uefi.raw,format=raw,if=none,id=win98']
        self.assertTrue(control.owned_qemu_args(args, run))
        for changed in [args[:1], ['other-process', *args[1:]],
                        ['qemu-kvm', '-nic', 'user', *args[3:]],
                        [*args, '-nic', 'user'],
                        [*args, '-netdev', 'user,id=n0'],
                        [*args, '-device', 'e1000'],
                        [*args, '-drive', 'file=/another-session/windows.raw,if=none,id=other',
                         '-device', 'ide-hd,drive=other,bootindex=0'],
                        [*args, '-blockdev', 'driver=file,filename=/another-session/windows.raw'],
                        ['qemu-kvm', '-nic', 'none', '-drive',
                         'file=/tmp/owned-trial/windows-uefi.raw.old,format=raw']]:
            self.assertFalse(control.owned_qemu_args(changed, run))

    def test_acknowledgement_binds_exact_request_and_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp).resolve()
            image = run / 'screen-003.png'
            image.write_bytes(b'\x89PNG\r\n\x1a\nfixture')
            request = dict(sequence=3, name='launch-exact-frozen-wtf-observer',
                           keys=[['ctrl', 'a']], text=control.OBSERVER, enter=True)
            receipt = dict(sequence=3, name=request['name'], keys=request['keys'],
                           typed=request['text'], screenshot=str(image), status=
                           'sent; application effect requires screenshot/readback verification')
            control.atomic_json(run / 'gui-control.json', request)
            control.atomic_json(run / 'gui-control-receipt.json', receipt)
            self.assertEqual(control.acknowledged_request(run, request)['typed'], request['text'])
            for key, value in [('name', 'competing-action'), ('keys', [['alt', 'f4']]),
                               ('typed', 'C:\\OTHER.EXE')]:
                changed = dict(receipt, **{key: value})
                control.atomic_json(run / 'gui-control-receipt.json', changed)
                with self.assertRaises(ValueError):
                    control.acknowledged_request(run, request)
            control.atomic_json(run / 'gui-control-receipt.json', receipt)
            control.atomic_json(run / 'gui-control.json', dict(request, enter=False))
            with self.assertRaises(ValueError):
                control.acknowledged_request(run, request)
            control.atomic_json(run / 'gui-control.json', request)
            request['framebuffer_capture'] = True
            control.atomic_json(run / 'gui-control.json', request)
            with self.assertRaises(FileNotFoundError):
                control.acknowledged_request(run, request)
            physical = image.with_name(image.stem + '-physical-framebuffer.bin')
            physical.write_bytes(b'retained-physical-data')
            self.assertIn('review_driver_physical_capture_sha256', control.acknowledged_request(run, request))

    def test_unacknowledged_controls_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            self.assertEqual(control.queue_sequence(run), 0)
            control.atomic_json(run / 'gui-control.json', {'sequence': 1})
            with self.assertRaises(ValueError):
                control.queue_sequence(run)
            receipt = {'sequence': 1, 'status':
                       'sent; application effect requires screenshot/readback verification'}
            control.atomic_json(run / 'gui-control-receipt.json', receipt)
            self.assertEqual(control.queue_sequence(run), 1)
            for bad in [{'sequence': 2}, {'sequence': True}]:
                control.atomic_json(run / 'gui-control.json', bad)
                with self.assertRaises(ValueError):
                    control.queue_sequence(run)
            control.atomic_json(run / 'gui-control.json', {'sequence': 1})
            receipt['status'] = 'FAIL'
            control.atomic_json(run / 'gui-control-receipt.json', receipt)
            with self.assertRaises(ValueError):
                control.queue_sequence(run)

    def test_pending_atomic_temp_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'gui-control.json'
            pending = path.with_name(path.name + '.wtf-control.tmp')
            pending.write_text('preserve')
            with self.assertRaises(FileExistsError):
                control.atomic_json(path, {'sequence': 1})
            self.assertEqual(pending.read_text(), 'preserve')
            self.assertFalse(path.exists())

    def test_warning_and_welcome_require_a_separate_desktop_review(self):
        # This is a control-boundary regression, not a guest/application test.
        # A slow boot must never receive Run, Alt-F4, or finish from a timer.
        for stage, expected in [('boot-warning', 'ack-reviewed-boot-warning'),
                                ('welcome', 'close-reviewed-baseline-welcome'),
                                ('desktop', 'open-run-for-wtf-observer')]:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temp:
                run = Path(temp)
                record = {'actions': []}
                args = SimpleNamespace(stage=stage, action=None, qemu_pid=123,
                                       launch_only=False)
                with mock.patch.object(control, 'process_token', return_value='owned'), \
                     mock.patch.object(control, 'queue_sequence', return_value=0), \
                     mock.patch.object(control, 'acknowledged_request',
                                       side_effect=lambda _, req: dict(req)), \
                     mock.patch.object(control.time, 'sleep',
                                       side_effect=AssertionError('Timed stage transition')):
                    self.assertEqual(control.drive(args, run, control.OBSERVER,
                                     record, run / 'control.json', 'owned', 0), 0)
                self.assertEqual(len(record['actions']), 1)
                self.assertEqual(record['actions'][0]['name'], expected)
                self.assertNotIn('text', record['actions'][0])
                self.assertNotIn('finish', record['actions'][0])


if __name__ == '__main__':
    unittest.main()
