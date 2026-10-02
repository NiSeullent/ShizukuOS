# SPDX-License-Identifier: GPL-2.0-only
"""Actual Linux child/pidfd/waitid/source-lease tests; no guest is started.

Owner.spawn, dedicated cgroup placement and future manifest/caller integration
are modeled. Parentage, argv, starttime, executable identity, source bytes,
read leases, pidfd readiness and exit records are actual Linux observations.
Run from the normal native_win98/tests layout with its adjacent source files.
"""
import hashlib
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock


NATIVE = Path(__file__).resolve().parent.parent
NATIVE_NAME = 'shizukudos/supervisor/native_win98/native_epoch_host.py'
OBSERVATIONS = []


def load_held(name, path):
    # Fixture admission uses the whole actual source buffer and hash, not a
    # claimed marker copied from a different file or extracted class.
    raw = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__executed_sha256__ = hashlib.sha256(raw).hexdigest()
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


rpc = load_held('native_custody_rpc', NATIVE / 'custody_rpc.py')
guardian = load_held('guardian_lifecycle_under_test', NATIVE / 'task_custody.py')
native = load_held('native_lifecycle_binding', NATIVE / 'native_epoch_host.py')


def pin(path):
    path = path.resolve()
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


class InheritedGroup:
    """Explicit cgroup model: validate actual inherited path, never place/kill."""
    def __init__(self):
        self.text = Path('/proc/self/cgroup').read_text().strip()
        assert self.text.startswith('0::/')
        self.path = Path('/sys/fs/cgroup') / self.text[3:].lstrip('/')

    def check(self):
        if Path('/proc/self/cgroup').read_text().strip() != self.text:
            raise ValueError('fixture inherited cgroup changed')


class GuardianLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.children = []
        self.union = guardian.LeaseUnion()
        self.addCleanup(self.cleanup_owned)
        self.native_pin = pin(NATIVE / 'native_epoch_host.py')
        self.union.add(self.native_pin)
        self.exe_pin = pin(Path(sys.executable))
        self.exe_entry = self.union.add(self.exe_pin)
        self.executable = native.PinnedFD(self.exe_entry['fd'], self.exe_pin)
        self.group = InheritedGroup()
        self.process, self.pidfd, self.writer, self.args = self.child()
        self.owner = guardian.Owner(self.union, self.group, self.args, self.exe_pin, 5)
        self.owner.process, self.owner.pidfd = self.process, self.pidfd
        self.owner.actual_args = list(self.args)
        self.owner.start = time.monotonic()
        self.owner.target_released = True
        self.owner.record['runtime_source_pins'] = {NATIVE_NAME: dict(self.native_pin)}
        self.owner.assert_owned()
        self.binding = native.ProcessBinding(self.process, self.pidfd, self.executable, tuple(self.args), self.group.text[3:])

    def child(self):
        readfd, writer = os.pipe()
        code = 'import os,sys; b=os.read(int(sys.argv[1]),1); os._exit(17 if b==b"E" else 0)'
        args = [self.exe_pin['path'], '-B', '-c', code, str(readfd)]
        try:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, pass_fds=(readfd,))
        finally:
            os.close(readfd)
        fd = os.pidfd_open(process.pid, 0)
        self.children.append((process, fd, writer))
        return process, fd, writer, args

    def ready(self, fd):
        poll = select.poll()
        poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        self.assertTrue(poll.poll(1500), 'owned fixture did not exit within 1.5 seconds')

    def cleanup_owned(self):
        for process, fd, writer in reversed(self.children):
            try:
                poll = select.poll(); poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
                if not poll.poll(0):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                if not poll.poll(1500):
                    raise AssertionError('owned fixture cleanup deadline expired')
                try:
                    row = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    if row is not None:
                        process.returncode = row.si_status if row.si_code == os.CLD_EXITED else -row.si_status
                        OBSERVATIONS.append({'kind': 'fixture_cleanup_actual_waitid', 'pid': row.si_pid,
                                             'code': row.si_code, 'status': row.si_status})
                except ChildProcessError:
                    # An actual delegated wait already set the Popen field.
                    # Never synthesize a status merely to satisfy __del__.
                    self.assertIsNotNone(process.returncode)
            finally:
                os.close(writer); os.close(fd)
        try:
            self.union.close()
        except ValueError:
            if not self.union.broken:
                raise
            self.assertTrue(self.union.closed, 'lease-break cleanup must still close held descriptors')

    def admit(self):
        entry = getattr(self.owner, 'admit_native_reaper', None)
        self.assertTrue(callable(entry), 'guardian has no explicit concrete native reaper admission')
        return entry(self.binding, native, self.native_pin)

    def trace_waitid(self):
        original = os.waitid
        rows = []
        def tracked(*args):
            row = original(*args)
            rows.append({'args': list(args), 'pid': None if row is None else row.si_pid,
                         'code': None if row is None else row.si_code,
                         'status': None if row is None else row.si_status})
            return row
        return rows, tracked

    def test_live_admitted_child_never_enters_destructive_wait(self):
        admitted = self.admit()
        rows, tracked = self.trace_waitid()
        with mock.patch.object(os, 'waitid', side_effect=tracked):
            self.assertIsNone(self.owner.observe())
        self.assertEqual(rows, [])
        self.assertEqual(admitted['pid'], self.process.pid)
        self.assertFalse(self.owner.reaped)
        self.assertFalse(self.owner.safe_to_release())

    def test_normal_exit_keeps_actual_CLD_and_waits_exactly_once(self):
        self.admit()
        os.write(self.writer, b'E'); self.ready(self.pidfd)
        rows, tracked = self.trace_waitid()
        with mock.patch.object(os, 'waitid', side_effect=tracked):
            self.assertEqual(self.owner.observe(), 17)
            self.assertEqual(self.owner.observe(), 17)
            self.assertTrue(self.owner.confirm_reaped())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['code'], os.CLD_EXITED)
        self.assertEqual(rows[0]['status'], 17)
        self.assertEqual(self.owner.record['native_reap_record'], {'pid': self.process.pid, 'code': os.CLD_EXITED, 'status': 17})
        self.assertTrue(self.owner.record['native_reap_postcheck_verified'])
        OBSERVATIONS.extend(rows)

    def test_actual_zero_exit_is_distinct_from_live_no_status(self):
        self.admit()
        self.assertIsNone(self.owner.observe())
        os.write(self.writer, b'Z'); self.ready(self.pidfd)
        rows, tracked = self.trace_waitid()
        with mock.patch.object(os, 'waitid', side_effect=tracked):
            self.assertEqual(self.owner.observe(), 0)
            self.assertTrue(self.owner.confirm_reaped())
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['code'], rows[0]['status']), (os.CLD_EXITED, 0))
        self.assertEqual(self.owner.record['native_reap_record']['status'], 0)
        OBSERVATIONS.extend(rows)

    def test_signal_exit_keeps_actual_CLD_status_without_returncode_guess(self):
        self.admit()
        signal.pidfd_send_signal(self.pidfd, signal.SIGTERM); self.ready(self.pidfd)
        rows, tracked = self.trace_waitid()
        with mock.patch.object(os, 'waitid', side_effect=tracked):
            self.assertEqual(self.owner.observe(), -signal.SIGTERM)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['code'], rows[0]['status']), (os.CLD_KILLED, signal.SIGTERM))
        self.assertEqual(self.owner.record['native_reap_record']['status'], signal.SIGTERM)
        OBSERVATIONS.extend(rows)

    def test_postreap_assertion_failure_retains_actual_record_then_recovers_without_wait(self):
        self.admit()
        os.write(self.writer, b'E'); self.ready(self.pidfd)
        rows, tracked = self.trace_waitid()
        actual_readlink = os.readlink
        fault = [False]
        def waited(*args):
            row = tracked(*args)
            fault[0] = row is not None
            return row
        def readlink(path, *args, **kwargs):
            if fault[0] and str(path) == '/proc/self/fd/%d' % self.pidfd:
                fault[0] = False
                return 'anon_inode:[injected-postreap-fault]'
            return actual_readlink(path, *args, **kwargs)
        with mock.patch.object(os, 'waitid', side_effect=waited), mock.patch.object(os, 'readlink', side_effect=readlink):
            with self.assertRaises(ValueError):
                self.owner.observe()
            self.assertEqual(len(rows), 1)
            self.assertEqual(self.owner.record['native_reap_record'], {'pid': self.process.pid, 'code': os.CLD_EXITED, 'status': 17})
            self.assertFalse(self.owner.record['native_reap_postcheck_verified'])
            self.assertFalse(self.owner.reaped)
            self.assertFalse(self.owner.safe_to_release())
            self.assertEqual(os.fstat(self.pidfd).st_ino, os.fstat(self.binding.pidfd).st_ino)
            self.assertTrue(self.union.rows, 'postcheck failure must retain custody')
            OBSERVATIONS.append({'kind': 'postreap_failure_retained', 'record': dict(self.owner.record['native_reap_record']),
                                 'release_permitted': self.owner.safe_to_release(), 'held_lease_count': len(self.union.rows)})
            self.assertEqual(self.owner.observe(), 17)
            self.assertTrue(self.owner.confirm_reaped())
            self.assertEqual(len(rows), 1, 'retained record recovery must not re-wait')
        OBSERVATIONS.extend(rows)

    def test_Popen_returncode_alone_is_not_native_exit_evidence(self):
        self.admit()
        self.process.returncode = 0  # Explicitly injected guessed field, no wait.
        rows, tracked = self.trace_waitid()
        try:
            with mock.patch.object(os, 'waitid', side_effect=tracked):
                self.assertIsNone(self.owner.observe())
            self.assertFalse(self.owner.confirm_reaped())
            self.assertFalse(self.owner.safe_to_release())
            self.assertEqual(rows, [])
            self.assertNotIn('observed_exit_code', self.owner.record)
        finally:
            self.process.returncode = None

    def test_actual_ECHILD_retains_unknown_status_and_does_not_repeat_wait(self):
        self.admit()
        os.write(self.writer, b'E'); self.ready(self.pidfd)
        actual_waitid = os.waitid
        outside = []
        calls = []
        def stolen(*args):
            calls.append(list(args))
            row = actual_waitid(*args)
            outside.append({'pid': row.si_pid, 'code': row.si_code, 'status': row.si_status})
            return actual_waitid(*args)  # Actual ECHILD after a fixture reaper.
        try:
            with mock.patch.object(os, 'waitid', side_effect=stolen):
                with self.assertRaises(ChildProcessError):
                    self.owner.observe()
                self.assertIsNone(self.process.returncode)
                self.assertFalse(self.owner.reaped)
                self.assertFalse(self.owner.confirm_reaped())
                self.assertTrue(self.owner.safe_to_release(), 'original dead pidfd permits failed physical cleanup only')
                self.assertFalse(self.owner.record['exit_status_verified'])
                self.assertTrue(self.owner.record['parent_wait_status_unavailable'])
                self.assertNotIn('observed_exit_code', self.owner.record)
                with self.assertRaises(ChildProcessError):
                    self.owner.observe()
                self.assertEqual(len(calls), 1)
            OBSERVATIONS.append({'kind': 'external_fixture_wait_only_owner_status_unknown', 'record': outside[0],
                                 'owner_reaped': self.owner.reaped, 'owner_observed_exit_code': self.owner.record.get('observed_exit_code'),
                                 'delegated_wait_attempts': len(calls)})
        finally:
            if outside:
                # Fixture-only cleanup uses its own actual raw record, never
                # presents that record as the delegated owner's observation.
                row = outside[0]
                self.process.returncode = row['status'] if row['code'] == os.CLD_EXITED else -row['status']

    def test_missing_declared_source_or_wrong_module_hash_refuses_admission(self):
        self.owner.record['runtime_source_pins'] = {}
        with self.assertRaises(ValueError):
            self.admit()
        self.owner.record['runtime_source_pins'] = {NATIVE_NAME: dict(self.native_pin)}
        saved = native.__executed_sha256__
        native.__executed_sha256__ = '0' * 64
        try:
            with self.assertRaises(ValueError):
                self.admit()
        finally:
            native.__executed_sha256__ = saved
        self.assertFalse(self.owner.reaped)
        self.assertIsNone(self.binding.reap_record)

    def test_generic_callback_and_subclass_are_not_reaper_authority(self):
        entry = getattr(self.owner, 'admit_native_reaper', None)
        self.assertTrue(callable(entry), 'guardian has no explicit concrete native reaper admission')
        with self.assertRaises(ValueError):
            entry(lambda: {'status': 0}, native, self.native_pin)
        class OtherBinding(native.ProcessBinding):
            pass
        other = OtherBinding(self.process, self.pidfd, self.executable, tuple(self.args), self.group.text[3:])
        with self.assertRaises(ValueError):
            entry(other, native, self.native_pin)
        self.assertIsNone(self.binding.reap_record)

    def test_foreign_pidfd_and_overridden_method_refuse_before_waitid(self):
        self.admit()
        other, otherfd, _, _ = self.child()
        os.write(self.writer, b'E'); self.ready(self.pidfd)
        rows, tracked = self.trace_waitid()
        self.binding.pidfd = otherfd
        try:
            with mock.patch.object(os, 'waitid', side_effect=tracked):
                with self.assertRaises(ValueError):
                    self.owner.observe()
        finally:
            self.binding.pidfd = self.pidfd
        self.binding.reap_owned = lambda: {'pid': self.process.pid, 'code': os.CLD_EXITED, 'status': 0}
        try:
            with mock.patch.object(os, 'waitid', side_effect=tracked):
                with self.assertRaises(ValueError):
                    self.owner.observe()
        finally:
            del self.binding.reap_owned
        self.assertEqual(rows, [])
        self.assertIsNone(self.binding.reap_record)
        self.assertIsNone(other.returncode)

    def test_legacy_observation_and_readmission_are_refused_handoffs(self):
        self.assertIsNone(self.owner.observe())
        with self.assertRaises(ValueError):
            self.admit()
        fresh = guardian.Owner(self.union, self.group, self.args, self.exe_pin, 5)
        fresh.process, fresh.pidfd = self.process, self.pidfd
        fresh.actual_args = list(self.args); fresh.target_released = True
        fresh.record['runtime_source_pins'] = {NATIVE_NAME: dict(self.native_pin)}
        fresh.assert_owned()
        fresh.admit_native_reaper(self.binding, native, self.native_pin)
        with self.assertRaises(ValueError):
            fresh.admit_native_reaper(self.binding, native, self.native_pin)
        self.assertFalse(fresh.reaped)

    def test_mutated_retained_CLD_record_cannot_gain_release_or_rewait(self):
        self.admit()
        os.write(self.writer, b'E'); self.ready(self.pidfd)
        self.assertEqual(self.owner.observe(), 17)
        saved = dict(self.binding.reap_record)
        self.binding.reap_record['status'] = True
        rows, tracked = self.trace_waitid()
        try:
            with mock.patch.object(os, 'waitid', side_effect=tracked):
                with self.assertRaises(ValueError):
                    self.owner.observe()
                with self.assertRaises(ValueError):
                    self.owner.safe_to_release()
            self.assertEqual(rows, [])
        finally:
            self.binding.reap_record = saved

    def test_actual_lease_break_still_permits_owned_physical_reap(self):
        self.admit()
        os.kill(os.getpid(), signal.SIGIO)
        self.assertTrue(self.union.broken)
        with self.assertRaises(ValueError):
            self.union.check()
        signal.pidfd_send_signal(self.pidfd, signal.SIGTERM); self.ready(self.pidfd)
        self.assertEqual(self.owner.observe(), -signal.SIGTERM)
        self.assertTrue(self.owner.confirm_reaped())
        self.assertTrue(self.union.rows, 'observation itself must not release held inputs')
        self.assertFalse(self.owner.record['leases_released'])
        OBSERVATIONS.append({'kind': 'actual_SIGIO_lease_break_cleanup', 'record': dict(self.owner.record['native_reap_record']),
                             'lease_break_observed': self.union.broken, 'leases_released': self.owner.record['leases_released']})


if __name__ == '__main__':
    unittest.main()
