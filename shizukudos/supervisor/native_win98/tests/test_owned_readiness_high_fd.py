# SPDX-License-Identifier: GPL-2.0-only
"""Actual Linux descriptors above 2048; host transport controls, never a VM."""
import ast
from contextlib import contextmanager
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import resource
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('SHIZUKU_READINESS_SOURCE_ROOT', str(HERE)))

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

capture = load('high_fd_capture', SOURCE / 'owned_capture.py')
rpc = load('high_fd_rpc', SOURCE / 'custody_rpc.py')
epoch = load('high_fd_epoch', SOURCE / 'native_epoch_guard_pump.py')
host = load('high_fd_epoch_host', SOURCE / 'native_epoch_host.py')
qmp_fixture = load('high_fd_qmp_fixture', HERE / 'tests/test_owned_capture.py')
rpc_fixture = load('high_fd_rpc_fixture', HERE / 'tests/test_custody_rpc_pump.py')
rpc_fixture.rpc = rpc

@contextmanager
def high_descriptors():
    retained = []
    original_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if original_limit[0] < 4096:
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, original_limit[1]))
    try:
        while not retained or retained[-1] <= 2200:
            retained.append(os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC))
        yield
    finally:
        for fd in reversed(retained):
            os.close(fd)
        resource.setrlimit(resource.RLIMIT_NOFILE, original_limit)


class HighFDReadinessControls(unittest.TestCase):
    def setUp(self):
        self.before = len(os.listdir('/proc/self/fd'))
        self.retained = high_descriptors()
        self.retained.__enter__()

    def tearDown(self):
        self.retained.__exit__(None, None, None)
        self.assertEqual(len(os.listdir('/proc/self/fd')), self.before)

    def test_real_owned_qmp_greeting_capabilities_and_response_above_2048(self):
        with qmp_fixture.server('valid') as (path, pid, _):
            peer = capture.OwnedQMP(path, pid, time.monotonic() + 2)
            try:
                self.assertGreater(peer.socket.fileno(), 2048)
                self.assertEqual(peer.call('query-status'), {'running': True})
            finally:
                peer.close()

    def test_real_owned_qmp_wrong_id_and_eof_remain_refused_above_2048(self):
        for mode in ('wrong_id', 'eof'):
            with self.subTest(mode=mode), qmp_fixture.server(mode) as (path, pid, _):
                peer = capture.OwnedQMP(path, pid, time.monotonic() + 2)
                try:
                    self.assertGreater(peer.socket.fileno(), 2048)
                    with self.assertRaises(RuntimeError):
                        peer.call('query-status')
                finally:
                    peer.close()

    def test_real_owned_qmp_event_stream_retains_original_deadline_above_2048(self):
        with qmp_fixture.server('deadline') as (path, pid, _):
            peer = capture.OwnedQMP(path, pid, time.monotonic() + 2)
            start = time.monotonic()
            peer.deadline = start + .08
            try:
                self.assertGreater(peer.socket.fileno(), 2048)
                with self.assertRaises(TimeoutError):
                    peer.call('query-status')
                self.assertLess(time.monotonic() - start, .7)
            finally:
                peer.close()

    def test_real_logs_drain_and_hangup_close_all_three_high_pipes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            logs = capture.BoundedLogs(base)
            try:
                self.assertTrue(all(fd > 2048 for fd in (*logs.readers, *logs.writers.values())))
                for name, fd in logs.writers.items():
                    os.write(fd, name.encode())
                logs.close_writers()
                logs.pump(.1)
                self.assertEqual(logs.readers, {})
                for name in logs.counts:
                    self.assertEqual((base / name).read_bytes(), name.encode())
                    self.assertEqual(logs.counts[name], len(name))
                    self.assertEqual(logs.dropped[name], 0)
            finally:
                logs.close()

    def test_real_log_overflow_bound_and_unchecked_cleanup_above_2048(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(capture, 'LOG_LIMIT', 3):
            base = Path(temporary)
            logs = capture.BoundedLogs(base)
            try:
                os.write(logs.writers['e9.log'], b'12345678')
                with self.assertRaisesRegex(RuntimeError, 'byte bound'):
                    logs.pump(.1)
                self.assertEqual((base / 'e9.log').read_bytes(), b'123')
                self.assertEqual(logs.dropped['e9.log'], 5)
                logs.close_writers()
                logs.pump(.1, check=False)
                self.assertEqual(logs.readers, {})
            finally:
                logs.close()

    def test_real_closed_high_log_reader_refuses_instead_of_becoming_eof(self):
        with tempfile.TemporaryDirectory() as temporary:
            logs = capture.BoundedLogs(Path(temporary))
            reader = next(iter(logs.readers))
            os.close(reader)
            try:
                with self.assertRaises(OSError) as caught:
                    logs.pump()
                self.assertEqual(caught.exception.errno, errno.EBADF)
            finally:
                logs.readers.pop(reader)
                logs.close()

    def test_real_credential_checked_rpc_reply_and_pumping_above_2048(self):
        fixture = rpc_fixture.PumpTests()
        def handler(channel):
            request = fixture.request(channel)
            time.sleep(.06)
            channel.send({'id': request['id'], 'ok': True, 'result': 'actual-peer'})
        with fixture.peer(handler) as client:
            self.assertGreater(client.channel.socket.fileno(), 2048)
            pumps = []
            self.assertEqual(client.ordinary('modeled', timeout=.8, pump=lambda: pumps.append(1)), 'actual-peer')
            self.assertGreaterEqual(len(pumps), 4)
            self.assertEqual(client.sequence, 1)

    def test_real_qmp_postwait_cancel_leaves_socket_bytes_and_unsent_request(self):
        # Only the I/O boundary is modeled here; peer admission has separate real tests.
        for writing in (False, True):
            left, right = socket.socketpair()
            left.setblocking(False);right.setblocking(False)
            peer = object.__new__(capture.OwnedQMP)
            peer.socket, peer.buffer, peer.request = left, bytearray(), 0
            peer.deadline = time.monotonic() + 1
            calls = []
            refusal = RuntimeError('actual cancellation after poll')
            def pump():
                calls.append(1)
                if len(calls) == 2:
                    raise refusal
            peer.pump = pump
            try:
                self.assertGreater(min(left.fileno(), right.fileno()), 2048)
                if not writing:right.send(b'{"return":{}}\n')
                with self.assertRaises(RuntimeError) as caught:
                    if writing:peer.call('must-not-send')
                    else:peer._read(peer.deadline)
                self.assertIs(caught.exception, refusal)
                self.assertEqual(calls, [1, 1])
                if writing:
                    with self.assertRaises(BlockingIOError):right.recv(1)
                else:self.assertEqual(left.recv(100), b'{"return":{}}\n')
            finally:
                peer.close();right.close()

    def test_real_socket_both_read_and_write_requested_preserves_objects(self):
        left, right = socket.socketpair()
        try:
            right.send(b'z')
            for module in (capture, epoch, host):
                result = module._poll_select([left], [left], [], .1)
                self.assertEqual(result, ([left], [left], []))
                self.assertIs(result[0][0], left)
            self.assertEqual(left.recv(1), b'z')
        finally:
            left.close();right.close()

    def test_real_rpc_postread_rights_refusal_closes_rights_above_2048(self):
        rpc_fixture.PumpTests().test_rights_close_when_postreceive_pump_refuses()

    def test_real_rpc_eof_and_original_deadline_above_2048(self):
        fixture = rpc_fixture.PumpTests()
        fixture.test_eof_is_preserved_and_forbids_another_request()
        fixture.test_one_original_deadline_covers_waiting_for_response()

    def test_real_epoch_read_and_write_readiness_leaves_high_pipe_with_caller(self):
        for module in (epoch, host):
            with self.subTest(module=module.__name__):
                reader, writer = os.pipe()
                try:
                    self.assertGreater(min(reader, writer), 2048)
                    os.write(writer, b'x')
                    guards = []
                    result = module.checked_select([reader], [writer], time.monotonic_ns() + 1_000_000_000, lambda: guards.append(1))
                    self.assertEqual(result, ([reader], [writer], []))
                    self.assertEqual(guards, [1, 1])
                    self.assertEqual(os.read(reader, 1), b'x')
                finally:
                    os.close(reader)
                    os.close(writer)

    def test_real_epoch_postguard_cancel_keeps_high_pipe_byte(self):
        for module in (epoch, host):
            reader, writer = os.pipe()
            calls = []
            refusal = RuntimeError('actual owner cancellation')
            def guard():
                calls.append(1)
                if len(calls) == 2:
                    raise refusal
            try:
                os.write(writer, b'y')
                with self.assertRaises(RuntimeError) as caught:
                    module.checked_select([reader], [], time.monotonic_ns() + 1_000_000_000, guard)
                self.assertIs(caught.exception, refusal)
                self.assertEqual(os.read(reader, 1), b'y')
                self.assertEqual(calls, [1, 1])
            finally:
                os.close(reader)
                os.close(writer)

    def test_real_epoch_closed_high_fd_keeps_postguard_error_as_cause(self):
        for module in (epoch, host):
            reader, writer = os.pipe()
            os.close(reader)
            calls = []
            refusal = RuntimeError('lease broke')
            def guard():
                calls.append(1)
                if len(calls) == 2:
                    raise refusal
            try:
                with self.assertRaises(OSError) as caught:
                    module.checked_select([reader], [], time.monotonic_ns() + 1_000_000_000, guard)
                self.assertEqual(caught.exception.errno, errno.EBADF)
                self.assertIs(caught.exception.__cause__, refusal)
                self.assertEqual(calls, [1, 1])
            finally:
                os.close(writer)

    def test_epoch_local_copy_and_literal_source_sha_match_exact_source(self):
        helper_raw = (SOURCE / 'native_epoch_guard_pump.py').read_bytes()
        host_raw = (SOURCE / 'native_epoch_host.py').read_bytes()
        def functions(raw):
            return [ast.dump(node) for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name in ('_poll_select', 'checked_select')]
        self.assertEqual(functions(helper_raw), functions(host_raw))
        self.assertIn(hashlib.sha256(helper_raw).hexdigest().encode(), host_raw)


if __name__ == '__main__':
    unittest.main()
