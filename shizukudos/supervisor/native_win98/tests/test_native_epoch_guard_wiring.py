# SPDX-License-Identifier: GPL-2.0-only
"""Real Linux transport tests; process/QMP/hardware contexts are modeled.

All 21 controls are standalone in the normal native_win98/tests layout.
Process/QMP/hardware remain modeled; these tests do not prove Windows 98 boot.
"""
import importlib.util
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import types
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parent.parent / 'native_epoch_host.py'
spec = importlib.util.spec_from_file_location('epoch_guard_wiring_6970', SOURCE)
host = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = host
spec.loader.exec_module(host)


class GuardWiringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='epoch-wire-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)

    def listener(self):
        listener = host.PrivateListener(self.directory / 'com2.sock')
        self.addCleanup(listener.close)
        return listener

    def pair(self):
        left, right = socket.socketpair()
        left.setblocking(False)
        right.setblocking(False)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def gate(self, peer, guard, deadline=None):
        gate = object.__new__(host.HostGrant)
        gate.peer = peer
        gate.attempt = types.SimpleNamespace(original_deadline_ns=deadline or time.monotonic_ns() + 500_000_000,
                                             nonce=bytes(range(32)))  # transfer() redacts diagnostics with the live nonce
        gate.exchange_stop_ns = gate.original_exchange_stop_ns = None
        gate.transport_calls = gate.grant_bytes_written = 0
        gate.guard = guard
        gate.check = lambda: None  # Explicitly modeled process/QMP admission.
        return gate

    def idle_accept(self, message):
        listener = self.listener()
        ticks = []
        refusal = RuntimeError(message)
        def guard():
            ticks.append(1)
            if len(ticks) >= 3:
                raise refusal
        started = time.monotonic()
        try:
            with self.assertRaises(RuntimeError) as caught:
                listener.accept(os.getpid(), os.getuid(), time.monotonic_ns() + 500_000_000, guard=guard)
        except TypeError:
            self.fail('READY listener has no outer cancellation/resource guard')
        self.assertIs(caught.exception, refusal)
        self.assertLess(time.monotonic() - started, .2)
        self.assertGreaterEqual(len(ticks), 3)
        self.assertTrue(listener.path.exists(), 'refusal must retain listener custody')
        listener.check()

    def test_idle_ready_wait_honors_cancellation(self):
        self.idle_accept('guardian cancellation requested')

    def test_idle_ready_wait_honors_resource_failure(self):
        self.idle_accept('host resource floor consumed')

    def test_report_transfer_honors_guard_before_device_grant(self):
        left, right = self.pair()
        ticks = []
        refusal = RuntimeError('cancel transfer')
        def guard():
            ticks.append(1)
            if len(ticks) >= 3:
                raise refusal
        gate = self.gate(left, guard)
        try:
            with self.assertRaises(RuntimeError) as caught:
                gate.transfer(None, 256)
        except ValueError:
            self.fail('transfer consumed its finite budget without checking the outer guard')
        self.assertIs(caught.exception, refusal)
        self.assertEqual(gate.grant_bytes_written, 0)
        self.assertLess(gate.transport_calls, 4096)
        self.assertIs(gate.peer, left)

    def test_listener_requires_explicit_guard_without_consuming_connection(self):
        listener = self.listener()
        connector = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connector.close)
        connector.connect(str(listener.path))
        with self.assertRaises(ValueError):
            listener.accept(os.getpid(), os.getuid(), time.monotonic_ns() + 500_000_000)
        self.assertTrue(listener.path.exists())
        peer, _ = listener.sock.accept()
        self.addCleanup(peer.close)
        self.assertEqual(peer.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE), socket.SOCK_STREAM)

    def test_listener_postwait_refusal_leaves_queued_peer_unaccepted(self):
        listener = self.listener()
        connector = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connector.close)
        connector.connect(str(listener.path))
        ticks = []
        refusal = RuntimeError('cancel ready peer')
        def guard():
            ticks.append(1)
            if len(ticks) == 2:
                raise refusal
        with self.assertRaises(RuntimeError) as caught:
            listener.accept(os.getpid(), os.getuid(), time.monotonic_ns() + 500_000_000, guard=guard)
        self.assertIs(caught.exception, refusal)
        queued, _ = listener.sock.accept()
        self.addCleanup(queued.close)
        self.assertTrue(listener.path.exists())

    def test_listener_accepts_actual_current_peer_with_guard(self):
        listener = self.listener()
        connector = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connector.close)
        connector.connect(str(listener.path))
        checks = []
        peer = listener.accept(os.getpid(), os.getuid(), time.monotonic_ns() + 500_000_000, guard=lambda: checks.append(1))
        self.addCleanup(peer.close)
        self.assertFalse(peer.getblocking())
        self.assertGreaterEqual(len(checks), 3)
        connector.sendall(b'R')
        self.assertEqual(peer.recv(1), b'R')

    def test_listener_final_guard_deadline_refusal_closes_peer_and_keeps_listener(self):
        listener = self.listener()
        connector = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connector.close)
        connector.connect(str(listener.path))
        connector.settimeout(.1)
        ticks = []
        now = [50]
        deadline_ns = 100
        def guard():
            ticks.append(1)
            if len(ticks) == 3:
                now[0] = deadline_ns
        with mock.patch.object(host.time, 'monotonic_ns', side_effect=lambda: now[0]):
            with self.assertRaises(TimeoutError):
                peer = listener.accept(os.getpid(), os.getuid(), deadline_ns, guard=guard)
                self.addCleanup(peer.close)
        self.assertEqual(len(ticks), 3)
        self.assertEqual(connector.recv(1), b'', 'late accepted peer must be closed')
        self.assertTrue(listener.path.exists())
        listener.check()

    def test_ready_report_is_unread_after_postguard_refusal(self):
        left, right = self.pair()
        right.send(b'report')
        ticks = []
        refusal = RuntimeError('resource consumed after select')
        def guard():
            ticks.append(1)
            if len(ticks) == 3:
                raise refusal
        gate = self.gate(left, guard)
        with self.assertRaises(RuntimeError) as caught:
            gate.transfer(None, 6)
        self.assertIs(caught.exception, refusal)
        self.assertEqual(left.recv(6), b'report')
        self.assertEqual(gate.grant_bytes_written, 0)

    def test_ready_writer_sends_nothing_after_postguard_refusal(self):
        left, right = self.pair()
        ticks = []
        refusal = RuntimeError('cancel grant')
        def guard():
            ticks.append(1)
            if len(ticks) == 3:
                raise refusal
        gate = self.gate(left, guard)
        with self.assertRaises(RuntimeError) as caught:
            gate.transfer(b'G' * 272, 272, True)
        self.assertIs(caught.exception, refusal)
        with self.assertRaises(BlockingIOError):
            right.recv(1)
        self.assertEqual(gate.grant_bytes_written, 0)

    def test_actual_read_and_write_keep_shared_budget_and_grant_byte_count(self):
        left, right = self.pair()
        checks = []
        gate = self.gate(left, lambda: checks.append(1))
        right.send(b'abc')
        self.assertEqual(gate.transfer(None, 3), b'abc')
        calls = gate.transport_calls
        self.assertEqual(gate.transfer(b'G' * 272, 272, True), bytes(272))
        self.assertEqual(right.recv(273), b'G' * 272)
        self.assertEqual(gate.transport_calls, calls + 1)
        self.assertEqual(gate.grant_bytes_written, 272)
        self.assertGreaterEqual(len(checks), 6)

    def test_budget_refusal_does_not_wait_or_write(self):
        left, right = self.pair()
        gate = self.gate(left, lambda: None)
        gate.transport_calls = 4096
        with self.assertRaises(ValueError):
            gate.transfer(b'G' * 272, 272, True)
        self.assertEqual(gate.transport_calls, 4096)
        self.assertEqual(gate.grant_bytes_written, 0)
        with self.assertRaises(BlockingIOError):
            right.recv(1)

    def test_original_deadline_refuses_ready_report_without_read(self):
        left, right = self.pair()
        right.send(b'abc')
        gate = self.gate(left, lambda: None, deadline=time.monotonic_ns() - 1)
        original = gate.attempt.original_deadline_ns
        with self.assertRaises(TimeoutError):
            gate.transfer(None, 3)
        self.assertEqual(gate.attempt.original_deadline_ns, original)
        self.assertEqual(left.recv(3), b'abc')

    def test_additional_exchange_deadline_refuses_ready_grant_without_write(self):
        left, right = self.pair()
        gate = self.gate(left, lambda: None)
        original = gate.attempt.original_deadline_ns
        gate.exchange_stop_ns = gate.original_exchange_stop_ns = time.monotonic_ns() - 1
        stop = gate.exchange_stop_ns
        with self.assertRaises(TimeoutError):
            gate.transfer(b'G' * 272, 272, True)
        self.assertEqual(gate.attempt.original_deadline_ns, original)
        self.assertEqual((gate.exchange_stop_ns, gate.original_exchange_stop_ns), (stop, stop))
        self.assertEqual(gate.grant_bytes_written, 0)
        with self.assertRaises(BlockingIOError):
            right.recv(1)

    def test_select_error_remains_primary_with_postguard_cause(self):
        left, right = self.pair()
        ticks = []
        first = OSError(9, 'select rejected descriptor')
        refusal = RuntimeError('post-select resource refusal')
        def guard():
            ticks.append(1)
            if len(ticks) == 3:
                raise refusal
        gate = self.gate(left, guard)
        with mock.patch.object(host, '_poll_select', side_effect=first):
            with self.assertRaises(OSError) as caught:
                gate.transfer(None, 3)
        self.assertIs(caught.exception, first)
        self.assertIs(first.__cause__, refusal)
        self.assertTrue(first.__suppress_context__)
        self.assertEqual(gate.transport_calls, 1)
        self.assertIs(gate.peer, left)

    def constructor_context(self):
        attempt = object.__new__(host.Attempt)
        attempt.owner = None
        attempt.policy_fd = os.memfd_create('modeled-epoch-policy', os.MFD_CLOEXEC)
        self.addCleanup(os.close, attempt.policy_fd)
        listener = self.listener()
        binding = object.__new__(host.ProcessBinding)
        binding.check = lambda: self.fail('refused constructor inspected the process')
        return attempt, binding, listener

    def assert_constructor_custody(self, attempt, binding, listener):
        self.assertIs(attempt.owner, binding)
        self.assertIs(listener.owner, binding)
        self.assertGreaterEqual(os.fstat(attempt.policy_fd).st_ino, 1)
        self.assertTrue(listener.path.exists())
        listener.owner = None  # Modeled owner: no real child or reap authority.

    def test_missing_constructor_guard_preserves_policy_and_listener_custody(self):
        attempt, binding, listener = self.constructor_context()
        try:
            with self.assertRaises(ValueError):
                host.HostGrant(attempt, binding, None, listener, None, None)
            self.assert_constructor_custody(attempt, binding, listener)
        finally:
            listener.owner = None

    def test_constructor_guard_refusal_preserves_policy_and_listener_custody(self):
        attempt, binding, listener = self.constructor_context()
        refusal = RuntimeError('constructor owner cancelled')
        def guard():
            raise refusal
        try:
            with self.assertRaises(RuntimeError) as caught:
                host.HostGrant(attempt, binding, None, listener, None, None, guard=guard)
            self.assertIs(caught.exception, refusal)
            self.assert_constructor_custody(attempt, binding, listener)
        finally:
            listener.owner = None

    def test_exchange_initial_guard_refusal_latches_bytes_and_keeps_peer(self):
        left, right = self.pair()
        refusal = RuntimeError('cancel exchange')
        def guard():
            raise refusal
        gate = self.gate(left, guard)
        gate.attempt.consumed = False
        with self.assertRaises(RuntimeError) as caught:
            gate.exchange()
        self.assertIs(caught.exception, refusal)
        self.assertTrue(gate.attempt.consumed)
        self.assertEqual(gate.failure_after_grant_bytes, 0)
        self.assertIs(gate.peer, left)

    def test_exchange_passes_actual_guard_into_listener_wait(self):
        listener = self.listener()
        ticks = []
        refusal = RuntimeError('cancel exchange READY')
        def guard():
            ticks.append(1)
            if len(ticks) == 3:
                raise refusal
        gate = self.gate(None, guard)
        gate.listener = listener
        gate.binding = types.SimpleNamespace(process=types.SimpleNamespace(pid=os.getpid()))
        gate.attempt.consumed = False
        with self.assertRaises(RuntimeError) as caught:
            gate.exchange()
        self.assertIs(caught.exception, refusal)
        self.assertTrue(gate.attempt.consumed)
        self.assertIsNone(gate.peer)
        self.assertEqual(gate.failure_after_grant_bytes, 0)
        self.assertTrue(listener.path.exists())


class FADAGuardCompatibilityTests(unittest.TestCase):
    # The four control methods below are exact FADA draft source, made local.
    # Original draft SHA256: 64b97cfab7126ba50053aba608750cee37a701317e65d721ed4827994025c728
    def setUp(self):
        GuardWiringTests.setUp(self)
        self.epoch = host

    def guarded_accept(self, message):
        listener = self.epoch.PrivateListener(self.directory / 'com2.sock')
        ticks = []
        started = time.monotonic()
        def guard():
            ticks.append(time.monotonic())
            if len(ticks) >= 3:
                raise RuntimeError(message)
        try:
            # Removing the guard from the wait would consume the full deadline.
            try:
                with self.assertRaisesRegex(RuntimeError, message):
                    listener.accept(os.getpid(), os.getuid(), time.monotonic_ns() + 500_000_000, guard=guard)
            except TypeError:
                self.fail('READY listener has no outer cancellation/resource guard')
            self.assertGreaterEqual(len(ticks), 3)
            self.assertLess(time.monotonic() - started, .2)
            self.assertTrue(listener.path.exists(), 'failure must retain channel custody')
        finally:
            listener.close()

    def test_idle_ready_wait_honors_cancellation(self):
        self.guarded_accept('guardian cancellation requested')

    def test_idle_ready_wait_honors_resource_failure(self):
        self.guarded_accept('host resource floor consumed')

    def test_report_transfer_honors_guard_before_device_grant(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        left.setblocking(False)
        gate = object.__new__(self.epoch.HostGrant)
        gate.peer = left
        gate.transport_calls = gate.grant_bytes_written = 0
        gate.attempt = type('Deadline', (), {'original_deadline_ns': time.monotonic_ns() + 500_000_000,
                                              'nonce': bytes(range(32))})()  # transfer() redacts diagnostics with the live nonce
        ticks = []
        gate.check = lambda: None
        def guard():
            ticks.append(1)
            if len(ticks) >= 3: raise RuntimeError('cancel transfer')
        gate.guard = guard
        try:
            try:
                with self.assertRaisesRegex(RuntimeError, 'cancel transfer'):
                    gate.transfer(None, 256)
            except ValueError:
                self.fail('transfer consumed its finite budget instead of checking the outer guard')
            self.assertEqual(gate.grant_bytes_written, 0)
        finally:
            left.close(); right.close()



if __name__ == '__main__':
    unittest.main()
