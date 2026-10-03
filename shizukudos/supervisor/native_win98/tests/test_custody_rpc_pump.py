# SPDX-License-Identifier: GPL-2.0-only
"""Actual credential-checked RPC waits; no QEMU or device grant is modeled."""
import argparse
from contextlib import contextmanager
import errno
import importlib.util
import os
from pathlib import Path
import signal
import socket
import sys
import time
import unittest
from unittest import mock


arguments = argparse.ArgumentParser()
arguments.add_argument('--source', type=Path,
                       default=Path(__file__).resolve().parent.parent / 'custody_rpc.py')
args, remaining_arguments = arguments.parse_known_args()
spec = importlib.util.spec_from_file_location('rpc_pump_under_test', args.source)
rpc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rpc)


class PumpTests(unittest.TestCase):
    @contextmanager
    def peer(self, handler):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:
            left.close()
            code = 0
            try:
                handler(rpc.Channel(right, os.getppid()))
            except BaseException:
                code = 7
            finally:
                right.close()
            os._exit(code)
        right.close()
        client = rpc.Client(left.detach(), pid)
        failure = None
        try:
            yield client
        except BaseException as first:
            failure = first
            raise
        finally:
            client.close()
            stop = time.monotonic() + 2
            while True:
                observed, status = os.waitpid(pid, os.WNOHANG)
                if observed == pid:
                    code = os.waitstatus_to_exitcode(status)
                    if failure is None:
                        self.assertEqual(code, 0)
                    elif code != 0:
                        print('fixture peer exit %d after %s; primary error preserved' %
                              (code, type(failure).__name__), file=sys.stderr)
                    break
                if time.monotonic() >= stop:
                    os.kill(pid, signal.SIGKILL)
                    observed, status = os.waitpid(pid, 0)
                    self.assertEqual(observed, pid)
                    if failure is None:
                        self.fail('owned fixture peer exceeded its bound')
                    print('owned fixture peer exceeded bound after primary error',
                          file=sys.stderr)
                    break
                time.sleep(.005)

    @staticmethod
    def request(channel):
        row, rights = channel.receive(.8)
        for fd in rights:
            os.close(fd)
        return row

    def test_delayed_reply_pumps_without_nested_sequence_or_send(self):
        def handler(channel):
            row = self.request(channel)
            assert row['id'] == 1 and row['op'] == 'modeled'
            time.sleep(.09)
            channel.send({'id': 1, 'ok': True, 'result': True})
            try:
                self.request(channel)
            except EOFError:
                return
            raise AssertionError('an extra request escaped the pump')

        ticks = []
        with self.peer(handler) as client:
            def pump():
                ticks.append(1)
                with self.assertRaises(ValueError):
                    client.ordinary('forbidden-reentry')
            self.assertEqual(client.call('modeled', timeout=.8, pump=pump), (True, []))
            self.assertGreaterEqual(len(ticks), 4)
            self.assertEqual(client.sequence, 1)

    def test_prewrite_refusal_does_not_consume_a_sequence(self):
        def handler(channel):
            try:
                self.request(channel)
            except EOFError:
                return
            raise AssertionError('cancelled request was written')

        with self.peer(handler) as client:
            refusal = RuntimeError('local cancellation before write')
            def pump():
                raise refusal
            with self.assertRaises(RuntimeError) as caught:
                client.call('cancelled', pump=pump)
            self.assertIs(caught.exception, refusal)
            self.assertEqual(client.sequence, 0)

    def test_cancel_after_write_seals_the_unresolved_response(self):
        def handler(channel):
            row = self.request(channel)
            assert row['id'] == 1
            time.sleep(.06)
            try:
                channel.send({'id': 1, 'ok': True, 'result': True})
            except (BrokenPipeError, ConnectionResetError):
                pass

        with self.peer(handler) as client:
            ticks = []
            def pump():
                ticks.append(1)
                if len(ticks) == 3:
                    raise RuntimeError('cancelled after request')
            with self.assertRaisesRegex(RuntimeError, 'cancelled after request'):
                client.call('one-request', timeout=.5, pump=pump)
            self.assertEqual(client.sequence, 1)
            with self.assertRaisesRegex(ValueError, 'unresolved response'):
                client.call('must-not-send')
            self.assertEqual(client.sequence, 1)

    def test_one_original_deadline_covers_waiting_for_response(self):
        def handler(channel):
            self.request(channel)
            time.sleep(.16)
            try:
                channel.send({'id': 1, 'ok': True, 'result': True})
            except (BrokenPipeError, ConnectionResetError):
                pass

        with self.peer(handler) as client:
            ticks = []
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                client.call('slow', timeout=.055, pump=lambda: ticks.append(1))
            self.assertLess(time.monotonic() - started, .14)
            self.assertGreaterEqual(len(ticks), 4)
            self.assertEqual(client.sequence, 1)
            with self.assertRaises(ValueError):
                client.call('no-new-budget')

    def test_eof_is_preserved_and_forbids_another_request(self):
        def handler(channel):
            self.request(channel)

        with self.peer(handler) as client:
            ticks = []
            with self.assertRaises(EOFError):
                client.call('closed-peer', pump=lambda: ticks.append(1))
            self.assertGreaterEqual(len(ticks), 4)
            with self.assertRaises(ValueError):
                client.call('after-eof')

    def test_rights_close_when_postreceive_pump_refuses(self):
        def handler(channel):
            row = self.request(channel)
            reader, writer = os.pipe()
            try:
                channel.send({'id': row['id'], 'ok': True, 'result': True}, [reader])
            finally:
                os.close(reader)
                os.close(writer)
            row = self.request(channel)
            assert row['id'] == 2 and row['op'] == 'cleanup-check'
            channel.send({'id': 2, 'ok': True, 'result': True})

        with self.peer(handler) as client:
            received = []
            original_receive = client.channel.receive
            def receive(timeout):
                row, rights = original_receive(timeout)
                received.extend(rights)
                return row, rights
            client.channel.receive = receive
            def pump():
                if received:
                    raise RuntimeError('postreceive resource refusal')
            with self.assertRaisesRegex(RuntimeError, 'postreceive resource refusal'):
                client.call('rights', pump=pump)
            self.assertEqual(len(received), 1)
            with self.assertRaises(OSError) as caught:
                os.fstat(received[0])
            self.assertEqual(caught.exception.errno, errno.EBADF)
            # Its exact reply was consumed; ordered cleanup remains possible.
            self.assertTrue(client.ordinary('cleanup-check'))
            self.assertEqual(client.sequence, 2)

    def test_valid_refusal_reply_keeps_cleanup_sequence_aligned(self):
        def handler(channel):
            row = self.request(channel)
            channel.send({'id': row['id'], 'ok': False, 'result': 'modeled refusal'})
            row = self.request(channel)
            assert row['id'] == 2
            channel.send({'id': 2, 'ok': True, 'result': 'cleanup'})

        with self.peer(handler) as client:
            with self.assertRaisesRegex(RuntimeError, 'modeled refusal'):
                client.call('refused', pump=lambda: None)
            self.assertEqual(client.ordinary('cleanup'), 'cleanup')

    def test_bad_response_closes_rights_and_seals_ordering(self):
        def handler(channel):
            self.request(channel)
            reader, writer = os.pipe()
            try:
                channel.send({'id': True, 'ok': True, 'result': True}, [reader])
            finally:
                os.close(reader)
                os.close(writer)

        with self.peer(handler) as client:
            received = []
            original_receive = client.channel.receive
            def receive(timeout):
                row, rights = original_receive(timeout)
                received.extend(rights)
                return row, rights
            client.channel.receive = receive
            with self.assertRaisesRegex(ValueError, 'exact ordered'):
                client.call('bad-id', pump=lambda: None)
            self.assertEqual(len(received), 1)
            with self.assertRaises(OSError):
                os.fstat(received[0])
            with self.assertRaisesRegex(ValueError, 'unresolved response'):
                client.call('must-not-send')

    def test_select_error_retains_identity_and_chains_postpump_error(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client = rpc.Client(left.detach(), os.getpid())
        first = OSError(errno.EBADF, 'first select failure')
        later = RuntimeError('postpump refusal')
        calls = []
        def pump():
            calls.append(1)
            if len(calls) == 2:
                raise later
        try:
            with mock.patch.object(rpc.selectors, 'PollSelector', side_effect=first):
                with self.assertRaises(OSError) as caught:
                    client.call('no-write', pump=pump)
            self.assertIs(caught.exception, first)
            self.assertIs(caught.exception.__cause__, later)
            self.assertEqual(client.sequence, 0)
        finally:
            client.close()
            right.close()

    def test_invalid_timeout_or_pump_refuses_before_send(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client = rpc.Client(left.detach(), os.getpid())
        try:
            for timeout in (True, 0, -1, float('nan'), float('inf')):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    client.call('invalid', timeout=timeout)
            with self.assertRaises(ValueError):
                client.call('invalid', pump=42)
            self.assertEqual(client.sequence, 0)
        finally:
            client.close()
            right.close()


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remaining_arguments])
