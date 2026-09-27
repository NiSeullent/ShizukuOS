#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic archive-aware lab integration. Never launches a VM or opens OS media."""
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import base_archive as b
import lab
import packed as p
import test_base_archive as fixtures


class Integration(unittest.TestCase):
    make_history = fixtures.BaseArchive.make_history

    def setUp(self):
        fixtures.BaseArchive.setUp(self)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(self.clean_ram)
        for name, value in (('BUILD', self.root), ('DISK', self.original),
                            ('STATE', self.root/'state.json'), ('QMP_PATH', self.root/'qmp.sock')):
            self.stack.enter_context(patch.object(lab, name, value))
        self.stack.enter_context(patch('builtins.print'))
        self.preflight = self.stack.enter_context(patch.object(lab, 'preflight', return_value={}))
        self.launch = self.stack.enter_context(patch.object(lab.subprocess, 'Popen',
                                              side_effect=AssertionError('VM launch forbidden')))
        self.expected = p._load_pointer(self.original)[1]
        self.latest = self.data+b'newer packed generation first'

    def clean_ram(self):
        for path in self.root.rglob('packed-copy-*.json'):
            record = json.loads(path.read_text())
            directory = Path(record['directory'])
            if (directory.parent == Path('/dev/shm') and
                    directory.name.startswith(p.RAM_PREFIX) and not directory.is_symlink()):
                shutil.rmtree(directory, ignore_errors=True)

    def archive(self):
        value = b.create(self.original)
        b.retire_raw(self.original)
        self.assertFalse(self.original.exists())
        return value

    def stopped_state(self, record=None, **changes):
        state = {'owner': 'win98-modern-isolated-install-v1', 'pid': None,
                 'process_stopped': True, **changes}
        if record:
            state['ram_working_copy'] = record
        lab.STATE.write_text(json.dumps(state))

    def test_archived_prepare_reads_latest_generation_and_persists_exact_new_bytes(self):
        archive = self.archive()
        base_bytes = Path(archive['archive']).read_bytes()
        self.assertEqual(p.current(self.original)['raw_sha256'], fixtures.sha(self.latest))
        record = p.prepare(self.original)
        working = Path(record['working_disk'])
        self.assertEqual(working.read_bytes(), self.latest)
        changed = self.latest+b'new stopped checkpoint'
        working.write_bytes(changed)
        p.persist(record)
        current = p.current(self.original)
        restored = self.root/'independent.restore'
        p.decode(current['archive'], restored, expected=current)
        self.assertEqual(restored.read_bytes(), changed)
        self.assertEqual(Path(archive['archive']).read_bytes(), base_bytes)
        self.assertFalse(self.original.exists())
        self.assertEqual(record['status'], 'persisted')

    def test_archived_persistence_retries_every_publication_and_cleanup_boundary(self):
        self.archive()
        for stage in ('persistence_started', 'archive_verified', 'archive_published',
                      'pointer_published', 'persisted_journal', 'ram_unlinked', 'ram_removed'):
            with self.subTest(stage=stage):
                record = p.prepare(self.original)
                data = Path(record['working_disk']).read_bytes()+stage.encode()
                Path(record['working_disk']).write_bytes(data)
                with self.assertRaises(fixtures.Interrupted):
                    p.persist(copy.deepcopy(record), fixtures.fail_at(stage))
                p.persist(record)
                self.assertEqual(p.current(self.original)['raw_sha256'], fixtures.sha(data))
                self.assertFalse(self.original.exists())

    def test_archived_prepare_recovers_both_durable_startup_boundaries(self):
        self.archive()
        for stage in ('prepared_journal', 'working_copy_active'):
            with self.subTest(stage=stage):
                before = {path for path in self.root.glob('packed-copy-*.json')}
                with self.assertRaises(fixtures.Interrupted):
                    p.prepare(self.original, fixtures.fail_at(stage))
                new = set(self.root.glob('packed-copy-*.json'))-before
                self.assertEqual(len(new), 1)
                record = json.loads(new.pop().read_text())
                p.persist(record)
                self.assertEqual(p.current(self.original)['raw_sha256'], fixtures.sha(self.latest))
                self.assertFalse(self.original.exists())

    def test_corrupt_base_pointer_never_falls_back_to_present_raw(self):
        b.create(self.original)
        b.pointer_path(self.original).write_bytes(b'corrupt')
        for operation in (lambda: p.current(self.original), lambda: p.prepare(self.original)):
            with self.assertRaises((RuntimeError, ValueError)):
                operation()
        self.assertEqual(self.original.read_bytes(), self.data)
        self.assertEqual(list(self.root.glob('packed-copy-*.json')), [])

    def test_dangling_base_pointer_refuses_all_raw_boot_modes_and_raw_recovery(self):
        b.pointer_path(self.original).symlink_to(self.root/'absent')
        for resume, ram in ((False, False), (True, False), (True, True)):
            with self.subTest(resume=resume, ram=ram), self.assertRaisesRegex(RuntimeError, 'raw access is refused'):
                lab.supervise(60, resume, ram_copy=ram)
        self.stopped_state({'original_disk': str(self.original), 'status': 'working_copy_active'})
        with patch.object(lab.storage, 'persist') as persist:
            with self.assertRaisesRegex(RuntimeError, 'raw persistence is refused'):
                lab.retry_persistence()
            persist.assert_not_called()
        self.launch.assert_not_called()
        self.preflight.assert_not_called()
        self.assertEqual(self.original.read_bytes(), self.data)

    def test_missing_raw_and_corrupt_base_cannot_create_a_fresh_disk(self):
        self.original.unlink()
        b.pointer_path(self.original).write_bytes(b'broken')
        with patch.object(lab.subprocess, 'run') as create:
            with self.assertRaises((RuntimeError, ValueError)):
                lab.supervise(60, True, packed_checkpoint=True)
            create.assert_not_called()
        self.preflight.assert_not_called()
        self.launch.assert_not_called()
        self.assertFalse(self.original.exists())

    def test_archived_base_without_packed_history_is_never_a_boot_fallback(self):
        self.archive()
        p.pointer_path(self.original).unlink()
        for operation in (lambda: p.current(self.original), lambda: p.prepare(self.original),
                          lambda: lab.supervise(60, True, packed_checkpoint=True)):
            with self.assertRaisesRegex(RuntimeError, 'existing packed checkpoint'):
                operation()
        self.assertFalse(self.original.exists())
        self.launch.assert_not_called()
        self.assertEqual(list(self.root.glob('packed-copy-*.json')), [])

    def test_archived_launch_failure_persists_and_never_invokes_create_disk(self):
        self.archive()
        with patch.object(lab.subprocess, 'run') as create, \
                patch.object(lab.subprocess, 'Popen', side_effect=OSError('synthetic launch failure')):
            with self.assertRaisesRegex(OSError, 'synthetic launch failure'):
                lab.supervise(60, True, packed_checkpoint=True)
        create.assert_not_called()
        self.assertFalse(self.original.exists())
        state = json.loads(lab.STATE.read_text())
        self.assertEqual(state['ram_working_copy']['status'], 'persisted')
        self.assertEqual(set(state['harness_sources_sha256']),
                         {'lab.py', 'packed.py', 'storage.py', 'base_archive.py'})
        self.assertIn('private installation evidence', state['product_key'])
        self.assertEqual(p.current(self.original)['raw_sha256'], fixtures.sha(self.latest))

    def test_present_raw_mismatch_cannot_be_hidden_by_a_valid_archive(self):
        b.create(self.original)
        self.original.write_bytes(b'changed original')
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            p.prepare(self.original)
        self.assertEqual(self.original.read_bytes(), b'changed original')

    def test_archive_command_verifies_candidate_and_writes_bound_private_receipt(self):
        history = p.pointer_path(self.original).read_bytes()
        with patch.object(lab, 'assert_no_owned_processes') as stopped:
            receipt = lab.archive_base(self.expected)
        self.assertGreater(stopped.call_count, 2)
        self.assertEqual(receipt['status'], 'raw_retired')
        self.assertEqual(receipt['packed_pointer_sha256'], self.expected)
        self.assertEqual(receipt['harness_sources_sha256'], lab.harness_sources())
        self.assertEqual(json.loads((self.root/'archive-base-result.json').read_text()), receipt)
        self.assertEqual(p.pointer_path(self.original).read_bytes(), history)
        self.assertFalse(self.original.exists())
        self.assertEqual(p.current(self.original)['raw_sha256'], fixtures.sha(self.latest))

    def test_archive_command_allows_stopped_pending_packed_copy_then_recovery(self):
        record = p.prepare(self.original)
        changed = self.latest+b'awaiting copyback'
        Path(record['working_disk']).write_bytes(changed)
        # Match a stopped real run: the candidate is durable, but the first
        # archive write is refused by the unchanged disk-space reserve.
        with patch.object(p, '_disk_headroom', side_effect=RuntimeError('copyback headroom')):
            with self.assertRaisesRegex(RuntimeError, 'copyback headroom'):
                p.persist(record)
        self.assertEqual(record['status'], 'persistence_started')
        self.assertEqual(record['candidate']['raw_sha256'], fixtures.sha(changed))
        self.stopped_state(dict(record, status='persistence_required'))
        with patch.object(lab, 'assert_no_owned_processes'):
            lab.archive_base(self.expected)
            lab.retry_persistence()
        self.assertFalse(self.original.exists())
        self.assertEqual(p.current(self.original)['raw_sha256'], fixtures.sha(changed))
        self.assertEqual(json.loads(lab.STATE.read_text())['ram_working_copy']['status'], 'persisted')

    def test_archive_command_refuses_pending_raw_journals(self):
        with patch.object(lab.storage, 'pending_journals', return_value=[self.root/'ram-copy-pending.json']), \
                patch.object(b, 'create') as create:
            with self.assertRaisesRegex(RuntimeError, 'raw RAM journals'):
                lab.archive_base(self.expected)
            create.assert_not_called()
        self.assertEqual(self.original.read_bytes(), self.data)

    def test_archive_command_refuses_stale_candidate_before_any_archival(self):
        with patch.object(lab, 'assert_no_owned_processes'), patch.object(b, 'create') as create:
            with self.assertRaisesRegex(RuntimeError, 'reviewed candidate'):
                lab.archive_base('0'*64)
            create.assert_not_called()
        self.assertFalse(b.has_archive(self.original))
        self.assertEqual(self.original.read_bytes(), self.data)

    def test_archive_command_refuses_malformed_hash_without_lock_or_writes(self):
        for invalid in (None, '', 'A'*64, '0'*63, 'x'*64):
            with self.subTest(invalid=invalid), patch.object(lab, 'exclusive_lab_lock') as lock:
                with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
                    lab.archive_base(invalid)
                lock.assert_not_called()

    def test_archive_command_requires_exclusive_real_flock(self):
        with lab.exclusive_lab_lock(), patch.object(b, 'create') as create:
            with self.assertRaisesRegex(RuntimeError, 'holds the lab lock'):
                lab.archive_base(self.expected)
            create.assert_not_called()

    def test_archive_command_refuses_actual_present_recorded_pid(self):
        self.stopped_state(pid=os.getpid())
        with patch.object(b, 'create') as create:
            with self.assertRaisesRegex(RuntimeError, 'Recorded guest PID'):
                lab.archive_base(self.expected)
            create.assert_not_called()
        self.assertEqual(self.original.read_bytes(), self.data)

    def test_archive_command_scans_processes_when_state_is_missing(self):
        proc = self.root/'proc'; (proc/'42').mkdir(parents=True)
        (proc/'42/cmdline').write_bytes(b'qemu-kvm\0-name\0win98-modern-private-install\0')
        scan = lab.assert_no_owned_processes
        with patch.object(lab, 'assert_no_owned_processes', side_effect=lambda record: scan(record, proc)), \
                patch.object(b, 'create') as create:
            with self.assertRaisesRegex(RuntimeError, 'process is still present'):
                lab.archive_base(self.expected)
            create.assert_not_called()
        self.assertEqual(self.original.read_bytes(), self.data)

    def test_archive_command_refuses_unknown_owner(self):
        self.stopped_state(owner='another installation')
        with patch.object(b, 'create') as create:
            with self.assertRaisesRegex(RuntimeError, 'known installation ownership'):
                lab.archive_base(self.expected)
            create.assert_not_called()

    def test_archive_command_rechecks_process_absence_before_retirement(self):
        def create(*args, **kwargs):
            value = real_create(*args, **kwargs)
            scan.side_effect = RuntimeError('new owned process')
            return value
        real_create = b.create
        with patch.object(lab, 'assert_no_owned_processes') as scan, \
                patch.object(b, 'create', side_effect=create), patch.object(b, 'retire_raw') as retire:
            with self.assertRaisesRegex(RuntimeError, 'new owned process'):
                lab.archive_base(self.expected)
            retire.assert_not_called()
        self.assertEqual(self.original.read_bytes(), self.data)
        self.assertTrue(b.has_archive(self.original))

    def test_archive_command_rechecks_candidate_before_retirement(self):
        real_create = b.create
        def create(*args, **kwargs):
            value = real_create(*args, **kwargs)
            self.make_history('second')
            return value
        with patch.object(lab, 'assert_no_owned_processes'), \
                patch.object(b, 'create', side_effect=create), patch.object(b, 'retire_raw') as retire:
            with self.assertRaisesRegex(RuntimeError, 'reviewed candidate'):
                lab.archive_base(self.expected)
            retire.assert_not_called()
        self.assertEqual(self.original.read_bytes(), self.data)

    def test_harness_sources_include_actual_base_module_bytes(self):
        bundle = self.root/'source-bundle'; bundle.mkdir()
        for name in ('lab.py', 'packed.py', 'storage.py', 'base_archive.py'):
            (bundle/name).write_bytes(('synthetic '+name).encode())
        with patch.object(lab, '__file__', str(bundle/'lab.py')):
            captured = lab.harness_sources()
            self.assertEqual(captured['base_archive.py'], fixtures.sha((bundle/'base_archive.py').read_bytes()))
            (bundle/'base_archive.py').write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'sources changed'):
                lab.assert_harness_sources(captured)

    def test_harness_change_during_prepare_blocks_launch_and_persists_owned_ram(self):
        captured = lab.harness_sources()
        changed = dict(captured, **{'base_archive.py': '0'*64})
        with patch.object(lab, 'harness_sources', side_effect=[captured, changed]):
            with self.assertRaisesRegex(RuntimeError, 'sources changed'):
                lab.supervise(60, True, packed_checkpoint=True)
        self.launch.assert_not_called()
        state = json.loads(lab.STATE.read_text())
        self.assertEqual(state['ram_working_copy']['status'], 'persisted')
        self.assertEqual(state['harness_sources_sha256'], captured)

    def test_harness_change_before_retirement_keeps_raw(self):
        sources = lab.harness_sources()
        real_create = b.create
        def create(*args, **kwargs):
            value = real_create(*args, **kwargs)
            source_capture.return_value = dict(sources, **{'base_archive.py': '0'*64})
            return value
        with patch.object(lab, 'harness_sources', return_value=sources) as source_capture, \
                patch.object(lab, 'assert_no_owned_processes'), \
                patch.object(b, 'create', side_effect=create), patch.object(b, 'retire_raw') as retire:
            with self.assertRaisesRegex(RuntimeError, 'sources changed'):
                lab.archive_base(self.expected)
            retire.assert_not_called()
        self.assertEqual(self.original.read_bytes(), self.data)

    def test_cli_requires_explicit_candidate_and_routes_to_locked_operation(self):
        with patch.object(sys, 'argv', ['lab.py', 'archive-base', '--expected-packed-sha256', self.expected]), \
                patch.object(lab, 'archive_base') as operation:
            lab.main()
        operation.assert_called_once_with(self.expected)


if __name__ == '__main__':
    unittest.main()
