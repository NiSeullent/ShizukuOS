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
        self.record = dict(reviewed_stage='run-dialog', manifest=str(C.MANIFEST),
                           manifest_sha256=C.MANIFEST_SHA, nonce=C.NONCE,
                           guest_plan_sha256='pinned-plan', control_source_sha256='pinned-source',
                           qemu_pid=123, qemu_start_ticks='456',
                           reviewed_image=str(self.image), reviewed_image_sha256=C.digest(PNG))

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
        self.assertEqual(C.existing_queue(self.run, dict(self.record, reviewed_stage='boot-warning')), (0, None))

    def test_fresh_dialog_cannot_lose_the_required_boot_sequence(self):
        with self.assertRaises(ValueError):
            C.existing_queue(self.run, self.record)

    def test_launch_without_reviewed_dialog_rejected(self):
        with self.assertRaises(ValueError):
            C.existing_queue(self.run, dict(self.record, reviewed_stage='launch-observer'))

    def test_launch_accepts_only_exact_completed_dialog(self):
        reqs = [dict(sequence=3, name='tls7707-close-reviewed-welcome', keys=[['esc']]),
                dict(sequence=4, name='tls7707-open-reviewed-run-dialog', keys=[['meta_l', 'r']]),
                dict(sequence=5, name='tls7707-run-dialog-review-capture', framebuffer_capture=True)]
        ack = dict(sequence=5, name=reqs[-1]['name'], keys=[], status=C.ACK_STATUS,
                   screenshot=str(self.image))
        self.image.with_name(self.image.stem + '-physical-framebuffer.bin').write_bytes(b'framebuffer')
        self.queue(reqs[-1], ack)
        got = C.acknowledged_request(self.run, reqs[-1])
        prior = dict(self.record, reviewed_stage='run-dialog', status=C.RUN_DIALOG_STATUS,
                     close_welcome=False,
                     actions=[dict(request=q, ack=got if i == 2 else {}) for i, q in enumerate(reqs)])
        path = self.run / 'tls-control-run-dialog.json'
        write(path, prior)
        record = dict(self.record, reviewed_stage='launch-observer')
        self.assertEqual(C.existing_queue(self.run, record), (5, reqs[-1]))
        for key, value in [('reviewed_image', str(self.run / 'screen-old.png')),
                           ('reviewed_image_sha256', '0' * 64)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                C.existing_queue(self.run, dict(record, **{key: value}))
        for key, value in [('qemu_start_ticks', 'foreign'), ('control_source_sha256', 'foreign'),
                           ('close_welcome', True), ('status', 'RUNNING'), ('actions', prior['actions'][:2])]:
            write(path, dict(prior, **{key: value}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                C.existing_queue(self.run, dict(self.record, reviewed_stage='launch-observer'))
        write(path, prior)
        self.image.with_name(self.image.stem + '-physical-framebuffer.bin').write_bytes(b'changed physical capture')
        with self.assertRaises(ValueError):
            C.existing_queue(self.run, record)

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

    def test_empty_partial_or_changing_producer_ack_is_pending(self):
        self.queue()
        for raw in [b'', b'{', b'{"sequence":']:
            (self.run / 'gui-control-receipt.json').write_bytes(raw)
            self.assertIsNone(C.acknowledged_request(self.run, self.request))
        self.queue()
        with patch.object(C, 'bounded_bytes', side_effect=[json.dumps(self.request).encode(),
                          C.EvidenceWriteInProgress('changed')]):
            self.assertIsNone(C.acknowledged_request(self.run, self.request))
        self.queue()
        self.assertIsNotNone(C.acknowledged_request(self.run, self.request))

    def test_completed_non_object_ack_and_hardlinked_empty_ack_rejected(self):
        self.queue()
        (self.run / 'gui-control-receipt.json').write_text('[]')
        with self.assertRaises(ValueError):
            C.acknowledged_request(self.run, self.request)
        (self.run / 'gui-control-receipt.json').write_bytes(b'')
        os.link(self.run / 'gui-control-receipt.json', self.run / 'linked-ack')
        with self.assertRaises(ValueError):
            C.acknowledged_request(self.run, self.request)

    def test_only_exact_interrupted_legacy_capture_recovers_without_enter_replay(self):
        request = dict(sequence=2, name='tls7707-boot-warning-result-capture', framebuffer_capture=True)
        ack = dict(sequence=2, name=request['name'], keys=[], status=C.ACK_STATUS,
                   screenshot=str(self.image))
        self.image.with_name(self.image.stem + '-physical-framebuffer.bin').write_bytes(b'framebuffer')
        self.queue(request, ack)
        frozen = b'known immutable legacy controller'
        (self.run / 'tls-control-source.py').write_bytes(frozen)
        legacy_sha = C.digest(frozen)
        prior = dict(self.record, control_source_sha256=legacy_sha,
                     status='CONTROL_INTERRUPTED', reviewed_stage='boot-warning',
                     error='Expected a bounded privately owned regular file: ' + str(self.run / 'gui-control-receipt.json'),
                     pending_request=request, actions=[dict(request=self.request, ack=self.ack)])
        path = self.run / 'tls-control-boot-warning.json'
        write(path, prior)
        before = path.read_bytes()
        with patch.object(C, 'LEGACY_BOOT_CONTROLLER_SHA', legacy_sha):
            record = dict(self.record)
            self.assertEqual(C.existing_queue(self.run, record), (2, request))
            self.assertFalse(record['boot_ack_recovery']['keys_replayed'])
            self.assertFalse(record['boot_ack_recovery']['tls_pass'])
            self.assertEqual(path.read_bytes(), before)
            for key, value in [('qemu_start_ticks', 'foreign'), ('error', 'other failure'),
                               ('pending_request', self.request), ('control_source_sha256', 'foreign'),
                               ('status', C.BOOT_STATUS), ('reviewed_stage', 'desktop')]:
                write(path, dict(prior, **{key: value}))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    C.existing_queue(self.run, dict(self.record))
            write(path, prior)
            (self.run / 'tls-control-source.py').write_bytes(b'different source')
            with self.assertRaises(ValueError):
                C.existing_queue(self.run, dict(self.record))

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

    def simulate_stage(self, stage, close_welcome=False, sequence=0, previous=None, ack_mode='complete'):
        clock = [0.0]
        submitted = []
        deferred = []
        args = SimpleNamespace(stage=stage, qemu_pid=123, close_welcome=close_welcome)
        record = dict(self.record, reviewed_stage=stage, status='RUNNING', actions=[],
                      tls_pass=False, application_pass=False, process_exit_verified=False)
        original_atomic = C.atomic_json

        def fake_sleep(seconds):
            clock[0] += seconds
            if ack_mode == 'partial-then-complete' and clock[0] >= 1 and deferred:
                write(self.run / 'gui-control-receipt.json', deferred.pop())

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
            if ack_mode == 'empty':
                (self.run / 'gui-control-receipt.json').write_bytes(b'')
            elif ack_mode == 'partial-then-complete' and obj['sequence'] == 1:
                (self.run / 'gui-control-receipt.json').write_bytes(b'{')
                deferred.append(ack)
            elif ack_mode == 'pid-change':
                (self.run / 'gui-control-receipt.json').write_bytes(b'{')
            else:
                write(self.run / 'gui-control-receipt.json', ack)

        out = self.run / ('tls-control-' + stage + '.json')
        with patch.object(C, 'process_token', side_effect=lambda *_: 'foreign' if ack_mode == 'pid-change' and clock[0] >= 1 else '456'), \
                patch.object(C.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(C.time, 'sleep', side_effect=fake_sleep), \
                patch.object(C, 'atomic_json', side_effect=emulate_runner_ack):
            rc = C.drive(args, self.run, record, out, '456', sequence, previous)
        return rc, submitted, C.read_json(out)

    def test_permanently_empty_ack_times_out_without_replaying_keys(self):
        rc, actions, record = self.simulate_stage('boot-warning', ack_mode='empty')
        self.assertEqual(rc, 1)
        self.assertEqual(len(actions), 1)
        self.assertEqual(record['status'], 'CONTROL_INTERRUPTED')
        self.assertEqual(record['error'], 'Canonical runner did not acknowledge this exact request')
        self.assertEqual(record['actions'], [])

    def test_partial_ack_completed_by_producer_advances_once(self):
        rc, actions, record = self.simulate_stage('boot-warning', ack_mode='partial-then-complete')
        self.assertEqual(rc, 0)
        self.assertEqual([a['sequence'] for _, a in actions], [1, 2])
        self.assertEqual(record['status'], C.BOOT_STATUS)
        self.assertEqual(len(record['actions']), 2)

    def test_pid_start_identity_change_while_ack_pending_aborts(self):
        rc, actions, record = self.simulate_stage('boot-warning', ack_mode='pid-change')
        self.assertEqual(rc, 1)
        self.assertEqual(len(actions), 1)
        self.assertIn('PID was reused', record['error'])
        self.assertFalse(record['tls_pass'])

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

    def test_legacy_desktop_cannot_skip_separate_run_dialog_review(self):
        rc, actions, record = self.simulate_stage('desktop')
        self.assertEqual(rc, 1)
        self.assertEqual(actions, [])
        self.assertEqual(record['status'], 'CONTROL_INTERRUPTED')
        self.assertFalse(record['tls_pass'])
        self.assertFalse(record['process_exit_verified'])

    def test_run_dialog_is_capture_only_and_does_not_launch_or_finish(self):
        rc, actions, record = self.simulate_stage('run-dialog')
        self.assertEqual(rc, 0)
        self.assertEqual([a['keys'] for _, a in actions[:2]],
                         [[['esc']], [['meta_l', 'r']]])
        self.assertGreaterEqual(actions[2][0] - actions[1][0], 8)
        self.assertTrue(actions[2][1]['framebuffer_capture'])
        self.assertTrue(all('text' not in a and not a.get('finish') for _, a in actions))
        self.assertEqual(record['status'], C.RUN_DIALOG_STATUS)
        self.assertFalse(record['tls_pass'])

    def test_reviewed_welcome_close_is_explicit(self):
        rc, actions, record = self.simulate_stage('run-dialog', close_welcome=True)
        self.assertEqual(rc, 0)
        self.assertEqual(actions[0][1]['keys'], [['alt', 'f4'], ['esc']])
        self.assertTrue(all('text' not in a for _, a in actions))

    def test_launch_after_dialog_does_not_reopen_it_and_waits_before_finish(self):
        previous = dict(sequence=5, name='tls7707-run-dialog-review-capture', framebuffer_capture=True)
        ack = dict(sequence=5, name=previous['name'], keys=[], status=C.ACK_STATUS,
                   screenshot=str(self.image))
        self.image.with_name(self.image.stem + '-physical-framebuffer.bin').write_bytes(b'framebuffer')
        self.queue(previous, ack)
        rc, actions, record = self.simulate_stage('launch-observer', sequence=5, previous=previous)
        self.assertEqual(rc, 0)
        self.assertEqual([a['sequence'] for _, a in actions], [6, 7])
        self.assertEqual(actions[0][1]['keys'], [['ctrl', 'a']])
        self.assertEqual(actions[0][1]['text'], C.COMMAND)
        self.assertTrue(actions[0][1]['enter'])
        self.assertGreaterEqual(actions[1][0] - actions[0][0], 105)
        self.assertTrue(actions[1][1]['framebuffer_capture'])
        self.assertTrue(actions[1][1]['finish'])
        self.assertFalse(record['tls_pass'])
        self.assertFalse(record['process_exit_verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
