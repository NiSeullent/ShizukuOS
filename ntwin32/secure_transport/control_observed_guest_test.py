#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-only admission/ownership tests. No VM or live disk access."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tls_control', HERE / 'control_observed_guest.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aKWQAAAAASUVORK5CYII=')


def write(path, value):
    path.write_text(json.dumps(value))


def canonical_argv(run):
    return [str(C.QEMU), '-name', 'shz-disposable-win98-uefi',
            '-machine', 'q35,hpet=off', '-accel', 'kvm', '-cpu', 'qemu64',
            '-smp', '2', '-m', '128', '-nodefaults', '-nic', 'none',
            '-display', 'none', '-device', 'VGA',
            '-drive', 'if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
            '-drive', f'if=pflash,unit=1,format=raw,file={run}/OVMF_VARS.fd',
            '-drive', f'file={run}/windows-uefi.raw,format=raw,if=none,id=win98',
            '-device', 'ide-hd,drive=win98,bus=ide.0,bootindex=1',
            '-serial', f'file:{run}/serial.log', '-qmp',
            'unix:/tmp/shz-win98-uefi-test123/qmp.sock,server=on,wait=off', '-no-reboot']


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='tls-control-host-test-')
        self.addCleanup(self.tmp.cleanup)
        self.run = Path(self.tmp.name)
        self.request = dict(sequence=1, name='tls7707-reviewed-boot-warning-enter', keys=[['ret']])
        self.image = self.run / 'screen-001.png'
        self.image.write_bytes(PNG)
        self.ack = dict(sequence=1, name=self.request['name'], keys=[['ret']],
                        status=C.ACK_STATUS, screenshot=str(self.image))
        self.record = dict(reviewed_stage='desktop', manifest=str(C.MANIFEST),
                           manifest_sha256=C.MANIFEST_SHA, nonce=C.NONCE,
                           guest_plan_sha256='pinned-plan', control_source_sha256='pinned-source',
                           qemu_pid=123, qemu_start_ticks='456')

    def queue(self, request=None, ack=None):
        write(self.run / 'gui-control.json', request or self.request)
        write(self.run / 'gui-control-receipt.json', ack or self.ack)

    def test_pinned_fixture_can_be_admitted(self):
        manifest = C.validate_manifest(C.MANIFEST, C.MANIFEST_SHA)
        self.assertEqual(len(manifest['inputs']), 8)
        self.assertEqual(manifest['nonce'], C.NONCE)

    def test_old_manifest_or_hash_rejected(self):
        for path, sha in [(C.MANIFEST, '0' * 64),
                          (C.MANIFEST.parent.parent / 'tls-observed-v2/guest-files.json', C.MANIFEST_SHA)]:
            with self.subTest(path=path, sha=sha), self.assertRaises(ValueError):
                C.validate_manifest(path, sha)

    def test_exact_canonical_argv_is_admitted(self):
        self.assertTrue(C.owned_qemu_args(canonical_argv(self.run), self.run))

    def test_foreign_disk_nic_firmware_and_extra_options_rejected(self):
        base = canonical_argv(self.run)
        mutations = []
        for index, value in [(0, '/tmp/qemu-kvm'), (4, 'pc,hpet=off'),
                             (6, 'tcg'), (10, '4'), (12, '256'),
                             (15, 'user'), (21, 'if=pflash,file=/tmp/firmware'),
                             (23, 'if=pflash,unit=1,format=raw,file=/tmp/foreign-vars'),
                             (25, 'file=/tmp/foreign.raw,format=raw,if=none,id=win98'),
                             (27, 'e1000'), (29, 'file:/tmp/other.log'),
                             (31, 'unix:/tmp/other/qmp.sock,server=on,wait=off')]:
            mutated = list(base)
            mutated[index] = value
            mutations.append(mutated)
        mutations.extend([base + ['-nic', 'none'], base + ['-netdev', 'user,id=n'],
                          base + ['-drive', 'file=/tmp/other.raw'],
                          base + ['-readconfig', '/tmp/config'], base[:-1]])
        for argv in mutations:
            with self.subTest(argv=argv):
                self.assertFalse(C.owned_qemu_args(argv, self.run))

    def test_arbitrary_host_process_rejected(self):
        with self.assertRaises(ValueError):
            C.process_token(os.getpid(), self.run)

    def test_foreign_trial_directory_rejected(self):
        with self.assertRaises(ValueError):
            C.validate_run(self.run)

    def test_fresh_queue_accepted(self):
        self.assertEqual(C.existing_queue(self.run, self.record), (0, None))

    def test_pending_queue_rejected(self):
        write(self.run / 'gui-control.json', self.request)
        with self.assertRaises(ValueError):
            C.existing_queue(self.run, self.record)

    def test_foreign_completed_queue_rejected(self):
        self.queue()
        with self.assertRaises(ValueError):
            C.existing_queue(self.run, self.record)

    def test_exact_ack_and_image_accepted(self):
        self.queue()
        got = C.acknowledged_request(self.run, self.request)
        self.assertEqual(got['review_driver_screenshot_sha256'], C.digest(PNG))

    def test_unacknowledged_request_returns_pending(self):
        write(self.run / 'gui-control.json', self.request)
        self.assertIsNone(C.acknowledged_request(self.run, self.request))

    def test_ack_name_keys_typed_status_or_sequence_tamper_rejected(self):
        for key, value in [('name', 'foreign-request'), ('keys', [['alt', 'f4']]),
                           ('typed', 'calc.exe'), ('status', 'PASS'),
                           ('sequence', True), ('sequence', 2), ('error', 'capture failed')]:
            with self.subTest(key=key, value=value):
                ack = dict(self.ack, **{key: value})
                self.queue(ack=ack)
                with self.assertRaises(ValueError):
                    C.acknowledged_request(self.run, self.request)

    def test_foreign_pending_request_detected(self):
        self.queue(request=dict(self.request, name='foreign'))
        with self.assertRaises(ValueError):
            C.acknowledged_request(self.run, self.request)

    def test_cross_run_screenshot_and_symlink_rejected(self):
        foreign = self.run / 'nested'
        foreign.mkdir()
        image = foreign / 'screen-001.png'
        image.write_bytes(PNG)
        self.queue(ack=dict(self.ack, screenshot=str(image)))
        with self.assertRaises(ValueError):
            C.acknowledged_request(self.run, self.request)
        link = self.run / 'screen-002.png'
        link.symlink_to(image)
        with self.assertRaises(ValueError):
            C.screenshot(link, self.run)

    def test_required_physical_capture_is_not_faked(self):
        request = dict(self.request, framebuffer_capture=True)
        self.queue(request=request)
        with self.assertRaises(FileNotFoundError):
            C.acknowledged_request(self.run, request)
        physical = self.image.with_name(self.image.stem + '-physical-framebuffer.bin')
        physical.write_bytes(b'bounded physical capture')
        self.assertIn('review_driver_physical_capture_sha256', C.acknowledged_request(self.run, request))

    def test_only_exact_prior_boot_stage_can_resume(self):
        request = dict(sequence=2, name='tls7707-boot-warning-result-capture', framebuffer_capture=True)
        ack = dict(sequence=2, name=request['name'], keys=[], status=C.ACK_STATUS,
                   screenshot=str(self.image))
        self.image.with_name(self.image.stem + '-physical-framebuffer.bin').write_bytes(b'framebuffer')
        self.queue(request, ack)
        decorated = C.acknowledged_request(self.run, request)
        prior = dict(self.record, status=C.BOOT_STATUS, reviewed_stage='boot-warning',
                     actions=[dict(request=self.request, ack=self.ack), dict(request=request, ack=decorated)])
        write(self.run / 'tls-control-boot-warning.json', prior)
        self.assertEqual(C.existing_queue(self.run, self.record), (2, request))
        for key, value in [('qemu_start_ticks', 'reused-pid'), ('nonce', 'old'),
                           ('manifest_sha256', 'old'), ('control_source_sha256', 'changed'),
                           ('status', 'CONTROL_INTERRUPTED')]:
            with self.subTest(key=key):
                write(self.run / 'tls-control-boot-warning.json', dict(prior, **{key: value}))
                with self.assertRaises(ValueError):
                    C.existing_queue(self.run, self.record)

    def test_prelaunch_plan_and_copies_must_match(self):
        manifest = C.validate_manifest(C.MANIFEST, C.MANIFEST_SHA)
        rows = [dict(row, private_copy_sha256=row['sha256']) for row in manifest['inputs']]
        plan = dict(manifest=str(C.MANIFEST), manifest_sha256=C.MANIFEST_SHA,
                    inputs=rows, outputs=C.OUTPUTS, backups=[], installed_gop_replacement=[],
                    output_baseline='all absent before private injection')
        for row in rows:
            (self.run / ('prepared-guest-' + row['guest'].rsplit('\\', 1)[1])).write_bytes(Path(row['source']).read_bytes())
        path = self.run / 'guest-files-plan.json'
        write(path, plan)
        C.validate_plan(self.run, manifest, C.MANIFEST, C.MANIFEST_SHA)
        mutations = [dict(plan, outputs=[r'C:\GOPLAB\OLD.LOG']),
                     dict(plan, output_baseline='unknown'), dict(plan, inputs=rows[:-1]),
                     dict(plan, backups=['C:\\WINDOWS\\SYSTEM.DAT']),
                     dict(plan, inputs=rows[:-1] + [rows[0]])]
        for changed in mutations:
            with self.subTest(plan=changed), self.assertRaises(ValueError):
                write(path, changed)
                C.validate_plan(self.run, manifest, C.MANIFEST, C.MANIFEST_SHA)
        write(path, plan)
        (self.run / 'prepared-guest-TLSWATCH.EXE').write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            C.validate_plan(self.run, manifest, C.MANIFEST, C.MANIFEST_SHA)

    def test_fifo_and_hardlinked_evidence_rejected_without_blocking(self):
        fifo = self.run / 'fifo-evidence'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            C.bounded_bytes(fifo, 100)
        linked = self.run / 'image-copy'
        os.link(self.image, linked)
        with self.assertRaises(ValueError):
            C.bounded_bytes(self.image, C.MAX_IMAGE)

    def simulate_stage(self, stage):
        clock = [0.0]
        submitted = []
        args = SimpleNamespace(stage=stage, qemu_pid=123)
        record = dict(self.record, reviewed_stage=stage, status='RUNNING', actions=[],
                      tls_pass=False, application_pass=False, process_exit_verified=False)
        original_atomic = C.atomic_json

        def fake_sleep(seconds):
            clock[0] += seconds

        def emulate_runner_ack(path, obj):
            original_atomic(path, obj)
            if path.name != 'gui-control.json':
                return
            submitted.append((clock[0], copy.deepcopy(obj)))
            image = self.run / ('screen-%03d.png' % obj['sequence'])
            image.write_bytes(PNG)
            if obj.get('framebuffer_capture'):
                image.with_name(image.stem + '-physical-framebuffer.bin').write_bytes(b'framebuffer')
            ack = dict(sequence=obj['sequence'], name=obj['name'], keys=obj.get('keys', []),
                       status=C.ACK_STATUS, screenshot=str(image))
            if obj.get('text'):
                ack['typed'] = obj['text']
            write(self.run / 'gui-control-receipt.json', ack)

        out = self.run / ('tls-control-' + stage + '.json')
        with patch.object(C, 'process_token', return_value='456'), \
                patch.object(C.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(C.time, 'sleep', side_effect=fake_sleep), \
                patch.object(C, 'atomic_json', side_effect=emulate_runner_ack):
            rc = C.drive(args, self.run, record, out, '456', 0, None)
        return rc, submitted, C.read_json(out)

    def test_boot_warning_stops_after_enter_and_capture(self):
        rc, actions, record = self.simulate_stage('boot-warning')
        self.assertEqual(rc, 0)
        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0][1]['keys'], [['ret']])
        self.assertTrue(actions[1][1]['framebuffer_capture'])
        self.assertGreaterEqual(actions[1][0] - actions[0][0], 45)
        self.assertTrue(all('text' not in a and not a.get('finish') for _, a in actions))
        self.assertEqual(record['status'], C.BOOT_STATUS)
        self.assertFalse(record['tls_pass'])

    def test_desktop_uses_fixed_command_waits105s_then_finishes(self):
        rc, actions, record = self.simulate_stage('desktop')
        self.assertEqual(rc, 0)
        self.assertEqual(len(actions), 3)
        self.assertEqual(actions[1][1]['text'], C.COMMAND)
        self.assertTrue(actions[1][1]['enter'])
        self.assertGreaterEqual(actions[2][0] - actions[1][0], 105)
        self.assertTrue(actions[2][1]['finish'])
        self.assertTrue(actions[2][1]['framebuffer_capture'])
        self.assertEqual(record['status'], C.DESKTOP_STATUS)
        self.assertFalse(record['tls_pass'])
        self.assertFalse(record['process_exit_verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
