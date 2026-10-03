# SPDX-License-Identifier: GPL-2.0-only
"""Actual small Git epochs and Linux leases; no private medium or VM."""
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import native_payload_ingest as ingest
import native_release_admission as admission
import private_installer_iso as iso


class SourceGuardCheckpoints(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/tmp',prefix='source-guard-checkpoint-')
        self.addCleanup(self.temp.cleanup)
        self.tree=Path(self.temp.name)/'tree';self.tree.mkdir()
        self.git('init','-q')
        self.git('config','remote.origin.url','https://example.invalid/source-fixture.git')
        self.source=self.tree/'source';self.source.write_bytes(b'actual host fixture')
        self.other=self.tree/'other';self.other.write_bytes(b'another host fixture')
        self.git('add','source','other')
        self.git('-c','user.name=Host fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
        self.revision=self.git('rev-parse','HEAD').decode().strip()

    def git(self,*args):
        return subprocess.check_output(['git','--no-optional-locks','-C',str(self.tree),*args],stderr=subprocess.PIPE)

    def guard(self):
        return iso._GitEpochGuard(self.tree,self.revision,clean=True,
                                  repository='https://example.invalid/source-fixture.git')

    def held(self):
        held=ingest.Union();held.__enter__()
        def close():
            fds=[entry['fd'] for entry in held.entries.values()]
            try:held.__exit__(None,None,None)
            except ValueError:pass # Expected failed epoch/SIGIO still closes every FD.
            for fd in fds:
                with self.assertRaises(OSError):os.fstat(fd)
        self.addCleanup(close)
        return held

    def entry(self,held,path=None):
        path=self.source if path is None else path
        raw=path.read_bytes()
        return held.add({'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})

    def test_legacy_callable_runs_at_every_actual_read_checkpoint(self):
        held=self.held();entry=self.entry(held);calls=[]
        held.guards.append(lambda:calls.append(True))
        ingest.read_exact(entry['fd'],entry['pin']['bytes'],0,lambda:held.io_check(entry))
        self.assertEqual(len(calls),2)
        held.check();self.assertEqual(len(calls),3)

    def test_actual_hash_has_bounded_git_checks_and_forced_full_phase_scan(self):
        held=self.held();entry=self.entry(held);guard=self.guard();held.guards.append(guard)
        # A fixed clock represents repeated real FD reads inside one second.
        with patch.object(iso.time,'monotonic',return_value=guard.previous),patch.object(iso,'_git',wraps=iso._git) as git:
            for _ in range(100):
                self.assertEqual(ingest.hash_fd(entry['fd'],entry['pin']['bytes'],lambda:held.io_check(entry)),entry['pin']['sha256'])
            self.assertEqual(git.call_count,0)
            held.check();self.assertGreaterEqual(git.call_count,6)
            self.assertEqual(fcntl.fcntl(entry['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)

    def test_old_per_checkpoint_callable_is_measurably_repeated(self):
        held=self.held();entry=self.entry(held);guard=self.guard()
        held.guards.append(lambda:guard()) # Original callback path, no IO protocol.
        with patch.object(iso,'_git',wraps=iso._git) as git:
            ingest.hash_fd(entry['fd'],entry['pin']['bytes'],lambda:held.io_check(entry))
        self.assertEqual(git.call_count,18) # Three actual hash checkpoints x six Git queries.

    def test_dirty_git_refused_at_final_full_scan_inside_checkpoint_interval(self):
        held=self.held();entry=self.entry(held);guard=self.guard();held.guards.append(guard)
        (self.tree/'untracked').write_bytes(b'host mutation')
        with patch.object(iso.time,'monotonic',return_value=guard.previous):
            held.io_check(entry)
            with self.assertRaisesRegex(ValueError,'Git source changed'):held.finish()
        self.assertTrue(guard.failed)

    def test_git_drift_refused_at_forced_compiler_boundary_inside_interval(self):
        held=self.held();entry=self.entry(held);guard=self.guard();held.guards.append(guard)
        self.git('config','remote.origin.url','https://example.invalid/changed.git')
        with patch.object(iso.time,'monotonic',return_value=guard.previous):
            held.io_check(entry)
            with self.assertRaisesRegex(ValueError,'repository URL changed'):held.check()

    def test_child_HEAD_change_refused(self):
        guard=self.guard()
        self.git('-c','user.name=Host fixture','-c','user.email=fixture@example.invalid','commit','--allow-empty','-qm','changed')
        with self.assertRaisesRegex(ValueError,'HEAD/reference'):guard()
        self.assertTrue(guard.failed)

    def test_child_same_commit_reference_change_refused(self):
        self.git('branch','same-commit')
        guard=self.guard();self.git('symbolic-ref','HEAD','refs/heads/same-commit')
        self.assertEqual(self.git('rev-parse','HEAD').decode().strip(),self.revision)
        with self.assertRaisesRegex(ValueError,'HEAD/reference'):guard()

    def test_original_repository_namespace_replacement_refused(self):
        guard=self.guard();self.tree.rename(self.tree.with_name('old-tree'));self.tree.mkdir()
        with self.assertRaisesRegex(ValueError,'namespace changed'):guard()

    def test_git_sweep_occurs_at_one_second_from_scan_start(self):
        guard=self.guard();start=guard.last
        with patch.object(iso.time,'monotonic',return_value=guard.previous+.01),patch.object(iso,'_git',wraps=iso._git) as git:
            guard.io_check();self.assertEqual(git.call_count,0)
        with patch.object(iso.time,'monotonic',return_value=start+1),patch.object(iso,'_git',wraps=iso._git) as git:
            guard.io_check();self.assertEqual(git.call_count,6)
        self.assertEqual(guard.last,start+1)

    def test_dirty_tree_refused_when_bounded_sweep_becomes_due(self):
        guard=self.guard();(self.tree/'untracked').write_bytes(b'host mutation')
        with patch.object(iso.time,'monotonic',return_value=guard.last+1):
            with self.assertRaisesRegex(ValueError,'Git source changed'):guard.io_check()

    def test_clock_regression_latches_and_refuses_later_full_scan(self):
        guard=self.guard()
        with patch.object(iso.time,'monotonic',return_value=guard.previous-1):
            with self.assertRaisesRegex(ValueError,'clock moved backwards'):guard.io_check()
        with self.assertRaisesRegex(ValueError,'previously failed'):guard()

    def test_slow_scan_refuses_without_grace_or_later_success(self):
        guard=self.guard();clock=[guard.previous+.01];original=iso._git
        def delayed(*args,**kwargs):
            self.assertTrue(0<kwargs['timeout']<=1)
            result=original(*args,**kwargs);clock[0]+=1.001;return result
        with patch.object(iso.time,'monotonic',side_effect=lambda:clock[0]),patch.object(iso,'_git',side_effect=delayed):
            with self.assertRaisesRegex(ValueError,'one-second Git epoch'):guard()
        self.assertTrue(guard.failed)
        with self.assertRaisesRegex(ValueError,'previously failed'):guard.io_check()

    def test_subprocess_timeout_latches_failure(self):
        guard=self.guard()
        with patch.object(iso,'_git',side_effect=subprocess.TimeoutExpired('host Git fixture',1)):
            with self.assertRaises(subprocess.TimeoutExpired):guard()
        self.assertTrue(guard.failed)

    def test_actual_active_inode_substitution_refused_without_waiting_for_git_scan(self):
        held=self.held();entry=self.entry(held);guard=self.guard();held.guards.append(guard)
        self.source.rename(self.source.with_name('old-source'));self.source.write_bytes(b'actual host fixture')
        with patch.object(iso.time,'monotonic',return_value=guard.previous),patch.object(iso,'_git',wraps=iso._git) as git:
            with self.assertRaisesRegex(ValueError,'active input identity'):held.io_check(entry)
            self.assertEqual(git.call_count,0)

    def test_external_writer_on_other_input_refused_by_shared_SIGIO_immediately(self):
        held=self.held();entry=self.entry(held);self.entry(held,self.other)
        guard=self.guard();held.guards.append(guard)
        result=subprocess.run([sys.executable,'-B','-c','import os,sys;os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)',str(self.other)],capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(held.broken)
        with patch.object(iso.time,'monotonic',return_value=guard.previous),patch.object(iso,'_git',wraps=iso._git) as git:
            with self.assertRaisesRegex(ValueError,'read lease broken'):held.io_check(entry)
            self.assertEqual(git.call_count,0)

    def test_SIGIO_during_git_guard_stops_before_actual_read(self):
        held=self.held();entry=self.entry(held)
        class BreakGuard:
            def __call__(self):pass
            def io_check(self):held.broken=True
        held.guards.append(BreakGuard())
        with patch.object(ingest.os,'pread',wraps=ingest.os.pread) as read:
            with self.assertRaisesRegex(ValueError,'read lease broken'):
                ingest.read_exact(entry['fd'],entry['pin']['bytes'],0,lambda:held.io_check(entry))
            read.assert_not_called()

    def test_exact_reviewed_ingestion_epoch_and_absent_native_authority(self):
        self.assertEqual(admission.policy.INGEST_SHA,hashlib.sha256(Path(ingest.__file__).read_bytes()).hexdigest())
        admission.load_ingester()
        self.assertIsNone(admission.policy.NATIVE_SOURCE_MAP_SHA)
        self.assertIsNone(admission.policy.NATIVE_ARTIFACTS)


if __name__=='__main__':unittest.main(verbosity=2)
