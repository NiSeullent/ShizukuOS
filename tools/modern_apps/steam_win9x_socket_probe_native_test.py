#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Authored host refusal controls; no VM, process control or native execution."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import steam_win9x_socket_probe_native_control as control
import steam_win9x_socket_probe_native_verify as verify


def authored_observer():
    nonce = '83bd-steam-socket-' + 'a' * 32
    fields = {'scope': 'steam-native-win98-loopback-owned-child-exit', 'nonce': nonce, 'source.version': '1',
              'steam.application-executed': '0', 'os.platform': '1', 'os.major': '4', 'os.minor': '10',
              'os.build-low': '2222', 'os.exact-target': '1', 'child.created': '1', 'child.create-error': '0',
              'child.pid': '42', 'child.thread-handle-closed': '1', 'child.deadline-ms': '90000',
              'child.wait': '0', 'child.wait-error': '0', 'child.exit-query': '1', 'child.exit-code': '0',
              'child.process-handle-closed': '1', 'child.post-CRT-exit-verified': '1',
              'steam.application-passed': '0', 'exit': '0'}
    return nonce, fields


def encode(fields):
    return ''.join(f'{key}={value}\r\n' for key, value in fields.items()).encode('ascii')


class NativeControls(unittest.TestCase):
    def test_actual_pinned_fixture_and_header_source_bindings(self):
        manifest, command = control.validate_manifest(control.FIXTURE, control.FIXTURE_SHA)
        self.assertEqual(command, control.OBSERVER + ' ' + manifest['nonce'])
        rows, headers = verify.receipt_bindings(manifest)
        self.assertEqual(len(rows), 17)
        self.assertEqual([row['actual_header_count'] for row in headers], [166, 166])
        self.assertFalse(manifest['steam_application_passed'])

    def test_changed_hash_or_manifest_cannot_expand_scope(self):
        with self.assertRaises(ValueError):
            control.validate_manifest(control.FIXTURE, '0' * 64)
        manifest = json.loads(control.FIXTURE.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'changed.json'
            for key, value in (('command', r'C:\OTHER.EXE'), ('requires_nic_absent', False),
                               ('outputs', [r'C:\GOPLAB\SPROB.LOG']), ('steam_application_passed', True)):
                changed = dict(manifest, **{key: value})
                data = json.dumps(changed).encode()
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    control.validate_manifest(path, hashlib.sha256(data).hexdigest())

    def test_each_transition_requires_its_own_reviewed_stage(self):
        mapping = {'ack-warning': 'boot-warning', 'close-welcome': 'welcome', 'open-run': 'desktop', 'launch': 'run-dialog'}
        for action, expected in mapping.items():
            control.validate_action_stage(action, expected)
            for wrong in set(mapping.values()) - {expected}:
                with self.subTest(action=action, wrong=wrong), self.assertRaises(ValueError):
                    control.validate_action_stage(action, wrong)
        for stage in mapping.values():
            control.validate_action_stage('capture', stage)
            control.validate_action_stage('finish', stage)

    def test_warning_acknowledgement_never_queues_welcome_or_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary)
            args = SimpleNamespace(action='ack-warning', stage='boot-warning', qemu_pid=999999)
            record = {'actions': [], 'application_pass': False, 'steam_application_passed': False,
                      'native_probe_execution_verified': False, 'launch_command_acknowledged': False}
            sent = []

            def synthetic_ack(_run, request):
                sent.append(dict(request))
                return dict(request, status='authored control acknowledgement; not native')

            with mock.patch.object(control, 'process_token', return_value='synthetic-token'), \
                 mock.patch.object(control, 'acknowledged_request', side_effect=synthetic_ack):
                self.assertEqual(control.drive(args, run, 'must-not-be-launched', record,
                                               run / 'driver.json', 'synthetic-token', 0), 0)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0]['keys'], [['ret']])
            self.assertNotIn('text', sent[0])
            self.assertFalse(record['launch_command_acknowledged'])
            self.assertFalse(record['native_probe_execution_verified'])

    def test_owned_qemu_scope_rejects_peer_disk_or_network(self):
        run = Path('/tmp/owned-steam-control')
        args = ['qemu-kvm', '-nic', 'none', '-device', 'VGA', '-device', 'ide-hd,drive=win98,bus=ide.0,bootindex=1',
                '-drive', 'if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
                '-drive', f'if=pflash,unit=1,format=raw,file={run}/OVMF_VARS.fd',
                '-drive', f'file={run}/windows-uefi.raw,format=raw,if=none,id=win98']
        self.assertTrue(control.owned_qemu_args(args, run))
        for changed in ([*args, '-nic', 'user'], [*args, '-netdev', 'user,id=external'],
                        [*args, '-drive', 'file=/another-session/windows.raw,if=none,id=other'],
                        [*args, '-device', 'e1000'], [*args, '-blockdev', 'driver=file,filename=/peer/raw']):
            self.assertFalse(control.owned_qemu_args(changed, run))

    def test_pending_queue_and_duplicate_temp_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary)
            control.atomic_json(run / 'gui-control.json', {'sequence': 1})
            before = (run / 'gui-control.json').read_bytes()
            with self.assertRaises(ValueError):
                control.queue_sequence(run)
            self.assertEqual((run / 'gui-control.json').read_bytes(), before)
            path = run / 'other.json'
            pending = path.with_name(path.name + '.steam-socket-control.tmp')
            pending.write_text('preserve pending writer')
            with self.assertRaises(FileExistsError):
                control.atomic_json(path, {'sequence': 1})
            self.assertEqual(pending.read_text(), 'preserve pending writer')

    def test_acknowledgement_binds_command_and_screenshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary).resolve()
            image = run / 'screen-003.png'
            image.write_bytes(b'\x89PNG\r\n\x1a\nauthored-host-control')
            request = {'sequence': 3, 'name': 'launch-exact-frozen-steam-socket-observer',
                       'keys': [['ctrl', 'a']], 'text': control.OBSERVER, 'enter': True}
            receipt = {'sequence': 3, 'name': request['name'], 'keys': request['keys'], 'typed': request['text'],
                       'screenshot': str(image), 'status': 'sent; application effect requires screenshot/readback verification'}
            control.atomic_json(run / 'gui-control.json', request)
            control.atomic_json(run / 'gui-control-receipt.json', receipt)
            self.assertEqual(control.acknowledged_request(run, request)['typed'], request['text'])
            for key, value in (('typed', r'C:\OTHER.EXE'), ('keys', [['alt', 'f4']]), ('name', 'other-controller')):
                control.atomic_json(run / 'gui-control-receipt.json', dict(receipt, **{key: value}))
                with self.assertRaises(ValueError):
                    control.acknowledged_request(run, request)

    def test_consistent_synthetic_observer_log_never_proves_native_or_steam(self):
        nonce, fields = authored_observer()
        result = verify.review_observer_log(encode(fields), nonce)
        self.assertTrue(result['post_crt_zero_exit_claim_consistent'])
        self.assertFalse(result['native_execution_verified'])
        self.assertFalse(result['steam_application_passed'])

    def test_wrong_nonce_os_wait_exit_or_cleanup_cannot_pass(self):
        nonce, original = authored_observer()
        for key, value in (('nonce', 'wrong-trial'), ('os.platform', '2'), ('os.build-low', '2223'),
                           ('child.wait', '258'), ('child.exit-code', '5'), ('child.exit-query', '0'),
                           ('child.process-handle-closed', '0'), ('child.pid', '0'), ('steam.application-passed', '1')):
            fields = dict(original, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify.review_observer_log(encode(fields), nonce)

    def test_duplicate_missing_or_truncated_observer_fields_are_rejected(self):
        nonce, fields = authored_observer()
        data = encode(fields)
        for changed in (data + b'child.exit-code=0\r\n', data[:-2], b'x' * 65537):
            with self.assertRaises(ValueError):
                verify.review_observer_log(changed, nonce)
        del fields['child.exit-query']
        with self.assertRaises(ValueError):
            verify.review_observer_log(encode(fields), nonce)

    def test_synthetic_run_cannot_be_native_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                verify.verify(Path(temporary), control.FIXTURE)

    def test_allocation_gate_keeps_the_20_gib_floor(self):
        observation = {'schema': 'xfs-fiemap-exclusive-data-v1', 'filesystem': 'xfs', 'stable_scans': 2,
                       'helper_sha256': 'a' * 64, 'device': 1, 'inode': 2, 'file_bytes': 2147483648,
                       'block_bytes': 4096, 'exclusive_bytes': 4096}
        floor = 20 * 1024**3
        result = {'minimum_free_bytes': floor, 'free_after_run': floor,
                  'sparse_budget': {'reserve_bytes': floor, 'dirty_budget_bytes': 128 * 1024**2,
                                   'free_before_vm': floor, 'cow_baseline': copy.deepcopy(observation),
                                   'cow_latest': copy.deepcopy(observation), 'cow_net_exclusive_growth_bytes': 0,
                                   'cow_peak_net_exclusive_growth_bytes': 0, 'cow_quiescent_samples': 1}}
        entry = {'cow_accounting_helper_sha256': 'a' * 64, 'private_dirty_allocation_quota_mib': 128,
                 'cow_allocation_review': {'observation': copy.deepcopy(observation), 'net_exclusive_growth_bytes': 0}}
        self.assertTrue(verify.allocation_gate(result, entry))
        result['minimum_free_bytes'] = floor - 1
        self.assertFalse(verify.allocation_gate(result, entry))


if __name__ == '__main__':
    unittest.main(verbosity=2)
