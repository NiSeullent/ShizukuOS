#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""QA routing tests with synthetic processes; never launches a VM."""
from contextlib import ExitStack
from pathlib import Path
import argparse
import json
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import lab


class TrialRouting(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='ntw-qa-routing-'))
        self.stack = ExitStack()
        self.addCleanup(shutil.rmtree, self.root)
        self.addCleanup(self.stack.close)
        for name, value in (('BUILD', self.root), ('DISK', self.root/'install-disk.qcow2'),
                            ('STATE', self.root/'state.json'), ('QMP_PATH', self.root/'qmp.sock')):
            self.stack.enter_context(patch.object(lab, name, value))
        lab.DISK.write_bytes(b'unchanged baseline')
        self.record = dict(mode='qa-trial', status='ready', token='synthetic',
                           original_disk=str(lab.DISK),
                           working_disk='/dev/shm/win98-modern-private-qa-synthetic/install-disk.qcow2')
        self.preflight = self.stack.enter_context(patch.object(lab, 'preflight', return_value={}))
        self.prepare = self.stack.enter_context(patch.object(lab.trial, 'prepare', return_value=self.record))
        self.scan = self.stack.enter_context(patch.object(lab, 'assert_no_owned_processes'))
        self.packed_persist = self.stack.enter_context(patch.object(lab.packed, 'persist'))
        self.raw_persist = self.stack.enter_context(patch.object(lab.storage, 'persist'))
        self.stack.enter_context(patch('builtins.print'))

    def run_qa(self, **kwargs):
        return lab.supervise(60, True, ephemeral_qa=True, baseline_pointer_sha256='a'*64, **kwargs)

    def stop_record(self, record, *, guard):
        guard(record)
        record['status'] = 'stopped_awaiting_evidence'
        return record

    def check_no_writeback(self):
        self.raw_persist.assert_not_called()
        self.packed_persist.assert_not_called()
        self.assertEqual(lab.DISK.read_bytes(), b'unchanged baseline')

    def test_backend_and_source_contract(self):
        self.assertIs(lab.storage_backend(self.record), lab.trial)
        self.assertIn('trial.py', lab.harness_sources())

    def test_explicit_mode_and_hash_are_required(self):
        cases = [dict(ephemeral_qa=True), dict(ephemeral_qa=True, baseline_pointer_sha256='bad'),
                 dict(baseline_pointer_sha256='a'*64),
                 dict(ephemeral_qa=True, baseline_pointer_sha256='a'*64, ram_copy=True),
                 dict(ephemeral_qa=True, baseline_pointer_sha256='a'*64, packed_checkpoint=True)]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(RuntimeError):
                lab.supervise(60, True, **options)
        self.preflight.assert_not_called(); self.prepare.assert_not_called()

    def test_resume_is_required(self):
        with self.assertRaisesRegex(RuntimeError, '--resume'):
            lab.supervise(60, False, ephemeral_qa=True, baseline_pointer_sha256='a'*64)
        self.prepare.assert_not_called()

    def test_pending_trial_blocks_all_launch_modes(self):
        with patch.object(lab.trial, 'pending_journals', return_value=[self.root/'pending']):
            for options in ({}, {'ram_copy': True}, {'packed_checkpoint': True},
                            {'ephemeral_qa': True, 'baseline_pointer_sha256': 'a'*64}):
                with self.subTest(options=options), self.assertRaisesRegex(RuntimeError, 'requires recovery'):
                    lab.supervise(60, True, **options)
        self.prepare.assert_not_called(); self.preflight.assert_not_called()

    def test_trial_blocks_persistence_and_base_archival(self):
        with patch.object(lab.trial, 'pending_journals', return_value=[self.root/'pending']):
            with self.assertRaisesRegex(RuntimeError, 'cannot be persisted'):
                lab.retry_persistence()
            with self.assertRaisesRegex(RuntimeError, 'blocks base archival'):
                lab.archive_base('a'*64)
        self.check_no_writeback()

    def test_discarded_state_never_routes_to_persist(self):
        lab.STATE.write_text(json.dumps({'owner':'win98-modern-isolated-install-v1',
                                        'ram_working_copy':dict(self.record,status='discarded')}))
        with self.assertRaisesRegex(RuntimeError, 'never write back'):
            lab.retry_persistence()
        self.check_no_writeback()

    def test_failed_launch_retains_stopped_ram(self):
        with patch.object(lab.subprocess, 'Popen', side_effect=OSError('launch failed')), \
                patch.object(lab.trial, 'record_stopped', side_effect=self.stop_record) as stopped:
            with self.assertRaisesRegex(OSError, 'launch failed'):
                self.run_qa()
        self.prepare.assert_called_once_with(lab.DISK, 'a'*64)
        self.preflight.assert_called_once_with(True, True)
        stopped.assert_called_once(); self.scan.assert_called()
        state=json.loads(lab.STATE.read_text())
        self.assertEqual(state['ram_working_copy']['status'],'stopped_awaiting_evidence')
        self.assertFalse(state['persisted']); self.assertTrue(state['baseline_unchanged'])
        self.check_no_writeback()

    def test_normal_stop_retains_ram_and_baseline(self):
        process=MagicMock(pid=999999991,returncode=0)
        process.poll.side_effect=[None,0,0,0,0]
        qmp=MagicMock()
        qmp.call.side_effect=lambda command: {'enabled':True} if command=='query-kvm' else {'running':True}
        lab.QMP_PATH.touch()
        # supervise removes the old socket before launch; synthetic Popen creates
        # the owned endpoint marker so startup need not sleep.
        def launch(*args,**kwargs):lab.QMP_PATH.touch();return process
        with patch.object(lab.subprocess,'Popen',side_effect=launch), \
                patch.object(lab,'QMP',return_value=qmp), \
                patch.object(lab.threading,'Timer'), \
                patch.object(lab.trial,'record_stopped',side_effect=self.stop_record):
            self.run_qa()
        state=json.loads(lab.STATE.read_text())
        self.assertTrue(state['process_stopped']);self.assertEqual(state['returncode'],0)
        self.assertEqual(state['ram_working_copy']['status'],'stopped_awaiting_evidence')
        self.check_no_writeback()

    def test_failed_stop_guard_preserves_error_and_ready_record(self):
        with patch.object(lab.subprocess,'Popen',side_effect=OSError('launch failed')), \
                patch.object(lab.trial,'record_stopped',side_effect=RuntimeError('ownership uncertain')):
            with self.assertRaisesRegex(RuntimeError,'retained'):
                self.run_qa()
        state=json.loads(lab.STATE.read_text())
        self.assertEqual(state['qa_stop_error'],'ownership uncertain')
        self.assertEqual(state['ram_working_copy']['status'],'ready')
        self.assertNotIn('baseline_unchanged',state)
        self.check_no_writeback()

    def test_prior_qa_requires_discard_before_next_boot(self):
        lab.STATE.write_text(json.dumps({'owner':'win98-modern-isolated-install-v1',
                                        'ram_working_copy':dict(self.record,status='evidence_saved')}))
        with self.assertRaisesRegex(RuntimeError,'prior RAM working copy'):
            self.run_qa()
        self.prepare.assert_not_called()

    def test_discarded_qa_permits_next_baseline_trial(self):
        lab.STATE.write_text(json.dumps({'owner':'win98-modern-isolated-install-v1',
                                        'ram_working_copy':dict(self.record,status='discarded')}))
        with patch.object(lab.subprocess,'Popen',side_effect=OSError('launch failed')), \
                patch.object(lab.trial,'record_stopped',side_effect=self.stop_record):
            with self.assertRaisesRegex(OSError,'launch failed'):self.run_qa()
        self.prepare.assert_called_once()

    def test_explicit_recovery_refuses_foreign_journal(self):
        args=argparse.Namespace(command='qa-record-stopped',journal=self.root/'foreign'/'qa-trial-x.json')
        with self.assertRaisesRegex(RuntimeError,'belong'):
            lab.qa_operation(args)

    def test_recovery_works_without_state_and_runs_stopped_guard(self):
        args=argparse.Namespace(command='qa-record-stopped',journal=self.root/'qa-trial-synthetic.json')
        with patch.object(lab.trial,'load_record',return_value=self.record), \
                patch.object(lab.trial,'record_stopped',side_effect=self.stop_record):
            lab.qa_operation(args)
        self.scan.assert_called()
        self.check_no_writeback()

    def test_recovery_refuses_live_pid_or_other_trial(self):
        args=argparse.Namespace(command='qa-record-stopped',journal=self.root/'qa-trial-synthetic.json')
        import os
        lab.STATE.write_text(json.dumps({'owner':'win98-modern-isolated-install-v1','pid':os.getpid()}))
        with patch.object(lab.trial,'load_record',return_value=self.record), \
                patch.object(lab.trial,'record_stopped') as stopped:
            with self.assertRaisesRegex(RuntimeError,'PID is still present'):lab.qa_operation(args)
            stopped.assert_not_called()
        lab.STATE.unlink()
        with patch.object(lab.trial,'load_record',return_value=self.record), \
                patch.object(lab.trial,'pending_journals',return_value=[self.root/'qa-trial-other.json']):
            with self.assertRaisesRegex(RuntimeError,'Another QA journal'):lab.qa_operation(args)


if __name__=='__main__':unittest.main()
