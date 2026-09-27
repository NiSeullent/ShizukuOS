#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Persistence routing and rollback guards; never launches an actual guest."""
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import lab


class Integration(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='win98-lab-routing-'))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(shutil.rmtree, self.root)
        for name, value in (('BUILD', self.root), ('DISK', self.root / 'install-disk.qcow2'),
                            ('STATE', self.root / 'state.json'), ('QMP_PATH', self.root / 'qmp.sock')):
            self.stack.enter_context(patch.object(lab, name, value))
        lab.DISK.write_bytes(b'preserved original')
        self.original = lab.DISK.read_bytes()
        self.record = {'mode': 'packed', 'status': 'working_copy_active',
                       'working_disk': '/dev/shm/test-owned/install-disk.qcow2',
                       'original_disk': str(lab.DISK)}
        self.preflight = self.stack.enter_context(patch.object(lab, 'preflight', return_value={}))
        self.output = self.stack.enter_context(patch('builtins.print'))

    def test_unknown_backend_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unknown RAM persistence mode'):
            lab.storage_backend({'mode': 'unexpected'})
        self.assertIs(lab.storage_backend({}), lab.storage)
        self.assertIs(lab.storage_backend({'mode': 'packed'}), lab.packed)

    def test_packed_requires_existing_resume(self):
        with patch.object(lab.packed, 'prepare') as prepare:
            with self.assertRaisesRegex(RuntimeError, '--resume'):
                lab.supervise(60, False, packed_checkpoint=True)
        prepare.assert_not_called()
        self.preflight.assert_not_called()

    def test_raw_boot_refuses_even_malformed_packed_pointer(self):
        # A broken pointer cannot silently fall back to the older raw disk.
        lab.packed.pointer_path(lab.DISK).write_bytes(b'broken pointer')
        for ram_copy in (False, True):
            with self.subTest(ram_copy=ram_copy), patch.object(lab.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(RuntimeError, 'avoid rollback'):
                    lab.supervise(60, True, ram_copy=ram_copy)
                launch.assert_not_called()
        self.preflight.assert_not_called()
        self.assertEqual(lab.DISK.read_bytes(), self.original)

    def test_raw_boot_refuses_dangling_pointer_symlink(self):
        lab.packed.pointer_path(lab.DISK).symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(RuntimeError, 'avoid rollback'):
            lab.supervise(60, True)

    def test_pending_journal_from_either_backend_blocks_boot(self):
        for backend in (lab.storage, lab.packed):
            with self.subTest(backend=backend.__name__), \
                    patch.object(backend, 'pending_journals', return_value=[self.root / 'pending']):
                with self.assertRaisesRegex(RuntimeError, 'requires recovery'):
                    lab.supervise(60, True, packed_checkpoint=True)
        self.preflight.assert_not_called()

    def test_launch_failure_still_persists_with_selected_backend(self):
        for is_packed in (False, True):
            with self.subTest(packed=is_packed):
                lab.STATE.unlink(missing_ok=True)
                record = dict(self.record)
                if not is_packed:
                    record.pop('mode')
                backend = lab.packed if is_packed else lab.storage
                other = lab.storage if is_packed else lab.packed
                def finish(value):
                    self.assertIs(value, record)
                    value['status'] = 'persisted'
                    return value
                with patch.object(backend, 'prepare', return_value=record) as prepare, \
                        patch.object(backend, 'persist', side_effect=finish) as persist, \
                        patch.object(other, 'prepare') as unused_prepare, \
                        patch.object(other, 'persist') as unused_persist, \
                        patch.object(lab.subprocess, 'Popen', side_effect=OSError('synthetic launch failure')):
                    with self.assertRaisesRegex(OSError, 'synthetic launch failure'):
                        lab.supervise(60, True, ram_copy=not is_packed, packed_checkpoint=is_packed)
                prepare.assert_called_once_with(lab.DISK)
                persist.assert_called_once_with(record)
                unused_prepare.assert_not_called()
                unused_persist.assert_not_called()
                self.preflight.assert_called_with(True, is_packed)
                state = json.loads(lab.STATE.read_text())
                self.assertEqual(state['ram_working_copy']['status'], 'persisted')
                self.assertEqual(set(state['harness_sources_sha256']), {'lab.py', 'storage.py', 'packed.py'})
                self.assertEqual(lab.DISK.read_bytes(), self.original)

    def recover(self, record, pending=True):
        journal = self.root / 'packed-copy-test.json'
        journal.write_text(json.dumps(record))
        events = []
        def finish(value):
            events.append('persist')
            value['status'] = 'persisted'
            return value
        with patch.object(lab.packed, 'pending_journals', return_value=[journal] if pending else []), \
                patch.object(lab.packed, 'locations', side_effect=lambda rec: events.append('locations')), \
                patch.object(lab, 'assert_no_owned_processes', side_effect=lambda rec: events.append('stopped')), \
                patch.object(lab.packed, 'persist', side_effect=finish) as persist, \
                patch.object(lab.storage, 'persist') as raw_persist:
            lab.retry_persistence()
        raw_persist.assert_not_called()
        persist.assert_called_once()
        self.assertEqual(events, ['locations', 'stopped', 'persist'])
        self.assertEqual(json.loads(lab.STATE.read_text())['ram_working_copy']['mode'], 'packed')
        self.assertEqual(lab.DISK.read_bytes(), self.original)

    def test_recovery_discovers_packed_journal_before_global_state_exists(self):
        self.recover(dict(self.record))

    def test_recovery_discovers_completed_packed_journal_after_ram_cleanup(self):
        record = dict(self.record, status='persisted')
        self.recover(record, pending=False)

    def test_ambiguous_pending_backends_refuse_recovery(self):
        with patch.object(lab.storage, 'pending_journals', return_value=[self.root / 'raw']), \
                patch.object(lab.packed, 'pending_journals', return_value=[self.root / 'packed']), \
                patch.object(lab.packed, 'persist') as persist:
            with self.assertRaisesRegex(RuntimeError, 'Multiple persistence journals'):
                lab.retry_persistence()
        persist.assert_not_called()

    def test_raw_recovery_cannot_replace_current_packed_history(self):
        record = dict(self.record)
        record.pop('mode')
        lab.STATE.write_text(json.dumps({'owner': 'win98-modern-isolated-install-v1',
                                        'ram_working_copy': record}))
        lab.packed.pointer_path(lab.DISK).write_bytes(b'pointer exists')
        with patch.object(lab.storage, 'persist') as persist:
            with self.assertRaisesRegex(RuntimeError, 'raw persistence would roll back'):
                lab.retry_persistence()
        persist.assert_not_called()
        self.assertEqual(lab.DISK.read_bytes(), self.original)

    def test_live_process_scan_precedes_packed_publication(self):
        lab.STATE.write_text(json.dumps({'owner': 'win98-modern-isolated-install-v1',
                                        'ram_working_copy': self.record}))
        with patch.object(lab.packed, 'locations'), \
                patch.object(lab, 'assert_no_owned_processes', side_effect=RuntimeError('guest remains')), \
                patch.object(lab.packed, 'persist') as persist:
            with self.assertRaisesRegex(RuntimeError, 'guest remains'):
                lab.retry_persistence()
        persist.assert_not_called()


if __name__ == '__main__':
    unittest.main()
