# SPDX-License-Identifier: GPL-2.0-only
"""Real gated guardian spawn/typed wait; Python target, never QEMU or a guest.

Source loading, leases, pipes, gated exec, parentage/argv/executable, pidfd and
waitid records are actual. Dedicated cgroup placement and private manifest
admission are modeled: this fixture validates its unchanged inherited cgroup.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import sys
import tempfile
import unittest
from unittest import mock


NATIVE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('activation_guardian', NATIVE / 'task_custody.py')
guardian = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guardian)
NATIVE_NAME = 'shizukudos/supervisor/native_win98/native_epoch_host.py'
OBSERVATIONS = []


def pin(path):
    path = path.resolve()
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


class InheritedGroup:
    def __init__(self):
        self.text = Path('/proc/self/cgroup').read_text().strip()
        assert self.text.startswith('0::/')
        self.path = Path('/sys/fs/cgroup') / self.text[3:].lstrip('/')

    def check(self):
        guardian.need(Path('/proc/self/cgroup').read_text().strip() == self.text,
                      'fixture inherited cgroup changed')

    def place_before_exec(self):
        # Explicit model: no shared cgroup membership or controller mutation.
        self.check()


class NativeActivation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-activation-')
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.union = guardian.LeaseUnion()
        self.previous_sigio = self.union.previous
        self.addCleanup(self.cleanup_owned)
        self.fds = []
        self.owner = None
        self.native_pin = pin(NATIVE / 'native_epoch_host.py')
        self.union.add(self.native_pin)
        self.exe_pin = pin(Path(sys.executable))
        self.exe_entry = self.union.add(self.exe_pin)
        # This target keeps all extra QEMU-style options as unused Python argv.
        self.argv = [self.exe_pin['path'], '-B', '-c', 'import time; time.sleep(20)',
                     '-serial', 'file:/proc/self/fd/0', '-debugcon', 'file:/proc/self/fd/1']
        self.owner = guardian.Owner(self.union, InheritedGroup(), self.argv, self.exe_pin, 5)
        self.owner.output = self.output
        self.sources = {role: {'fixture_role': role} for role in guardian.SOURCES}
        self.sources[NATIVE_NAME] = dict(self.native_pin)
        self.owner.record['runtime_source_pins'] = self.sources
        self.writers = []
        identities = []
        for _ in range(3):
            readfd, writer = os.pipe()
            self.fds.extend((readfd, writer))
            self.writers.append(writer)
            info = os.fstat(writer)
            identities.append([info.st_dev, info.st_ino])
        self.request = {'argv': list(self.argv), 'pipes': identities}

    def configure(self):
        configure = getattr(guardian, 'configure_native_reaper', None)
        self.assertTrue(callable(configure), 'production native reaper configuration missing')
        return configure(self.owner, self.sources, self.union)

    def ready(self):
        poll = select.poll()
        poll.register(self.owner.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        self.assertTrue(poll.poll(1500), 'owned Python target did not exit within 1.5 seconds')

    def cleanup_owned(self):
        if self.owner is not None and self.owner.process is not None:
            if not self.owner.exited():
                signal.pidfd_send_signal(self.owner.pidfd, signal.SIGKILL)
            self.ready()
            if not self.owner.reaped:
                self.owner.observe()
            self.assertTrue(self.owner.confirm_reaped())
            OBSERVATIONS.append({'cleanup': True, 'pid': self.owner.process.pid,
                                 'returncode': self.owner.process.returncode,
                                 'native_record': self.owner.record.get('native_reap_record')})
            self.owner.release()
            self.assertIsNone(self.owner.pidfd)
        elif not self.union.closed:
            self.union.close()
        self.assertTrue(self.union.closed)
        self.assertEqual(signal.getsignal(signal.SIGIO), self.previous_sigio)
        for fd in self.fds:
            os.close(fd)

    def actual_waits(self):
        original = os.waitid
        rows = []
        def track(*args):
            result = original(*args)
            rows.append({'args': list(args), 'pid': None if result is None else result.si_pid,
                         'code': None if result is None else result.si_code,
                         'status': None if result is None else result.si_status})
            return result
        return rows, track

    def test_declared_native_dispatch_admits_actual_waiter_before_ack(self):
        self.configure()
        server = guardian.Server(None, self.owner, self.sources, self.output)
        # Only the six original controller snapshots, not guardian-only native.
        server.frozen = set(guardian.SOURCES) - set(guardian.SOURCES[-3:])
        ack, rights = server.dispatch({'id': 1, 'op': 'spawn', 'params': self.request}, self.writers)
        self.assertEqual(rights, [])
        self.assertEqual(ack['pid'], self.owner.process.pid)
        self.assertTrue(self.owner.record['native_reaper_admitted'])
        binding = self.owner._native_reaper['binding']
        self.assertIs(binding.process, self.owner.process)
        self.assertEqual(binding.original_pidfd, self.owner.pidfd)
        self.assertEqual(binding.executable.fd, self.exe_entry['fd'])
        self.assertEqual(binding.executable.pin, self.exe_pin)
        self.assertEqual(self.owner._native_reaper['module'].__executed_sha256__, self.native_pin['sha256'])
        self.assertTrue(self.owner.record['VM_executed'])  # Host executable fact only.
        self.assertFalse(self.owner.record['Windows98_boot_verified'])
        self.owner.signal(signal.SIGTERM)
        self.ready()
        rows, track = self.actual_waits()
        with mock.patch.object(os, 'waitid', side_effect=track):
            self.assertEqual(self.owner.observe(), -signal.SIGTERM)
            self.assertEqual(self.owner.observe(), -signal.SIGTERM)
            self.assertTrue(self.owner.confirm_reaped())
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['pid'], rows[0]['code'], rows[0]['status']),
                         (ack['pid'], os.CLD_KILLED, signal.SIGTERM))
        self.assertEqual(self.owner.record['native_reap_record'],
                         {'pid': ack['pid'], 'code': os.CLD_KILLED, 'status': signal.SIGTERM})
        OBSERVATIONS.extend(rows)

    def test_legacy_nine_sources_keep_actual_original_waiter(self):
        del self.sources[NATIVE_NAME]
        self.assertIsNone(self.configure())
        ack = self.owner.spawn(self.request, self.writers)
        self.assertIsNone(self.owner._native_reaper)
        self.assertNotIn('native_reaper_admitted', self.owner.record)
        self.owner.signal(signal.SIGTERM)
        self.ready()
        rows, track = self.actual_waits()
        with mock.patch.object(os, 'waitid', side_effect=track):
            self.assertEqual(self.owner.observe(), -signal.SIGTERM)
            self.assertEqual(self.owner.observe(), -signal.SIGTERM)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['pid'], ack['pid'])
        self.assertNotIn('native_reap_record', self.owner.record)
        OBSERVATIONS.extend(rows)

    def test_native_manifest_without_configuration_refuses_before_fork(self):
        with self.assertRaisesRegex(ValueError, 'native.*configur'):
            self.owner.spawn(self.request, self.writers)
        self.assertIsNone(self.owner.process)
        self.assertFalse(self.owner.record['VM_executed'])

    def test_original_controller_snapshot_is_still_required(self):
        self.configure()
        server = guardian.Server(None, self.owner, self.sources, self.output)
        server.frozen = set(guardian.SOURCES[1:]) - set(guardian.SOURCES[-3:])
        with self.assertRaisesRegex(ValueError, 'snapshots'):
            server.dispatch({'id': 1, 'op': 'spawn', 'params': self.request}, self.writers)
        self.assertIsNone(self.owner.process)
        self.assertFalse(self.owner.attempted)

    def test_unleased_native_configuration_refuses_before_fork(self):
        row = self.union.rows.pop(self.native_pin['path'])
        try:
            with self.assertRaises(ValueError):
                self.configure()
        finally:
            self.union.rows[self.native_pin['path']] = row
        self.assertIsNone(self.owner.process)

    def test_activation_fault_after_exec_keeps_truthful_child_for_cleanup(self):
        self.configure()
        module, _ = self.owner._configured_native_reaper
        with mock.patch.object(module, 'ProcessBinding', side_effect=ValueError('injected activation fault')):
            with self.assertRaisesRegex(ValueError, 'injected activation fault'):
                self.owner.spawn(self.request, self.writers)
        self.assertIsNotNone(self.owner.process)
        self.assertTrue(self.owner.target_released)
        self.assertTrue(self.owner.record['VM_executed'])
        self.assertTrue(self.owner.record['custody_admitted'])
        self.assertIsNone(self.owner._native_reaper)
        self.assertIsNone(self.owner.process.returncode)
        self.owner.signal(signal.SIGTERM)
        self.ready()
        self.assertEqual(self.owner.observe(), -signal.SIGTERM)
        self.assertTrue(self.owner.confirm_reaped())


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeActivation)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print('ACTUAL_PYTHON_OBSERVATIONS=' + json.dumps(OBSERVATIONS, sort_keys=True))
    sys.exit(not result.wasSuccessful())
