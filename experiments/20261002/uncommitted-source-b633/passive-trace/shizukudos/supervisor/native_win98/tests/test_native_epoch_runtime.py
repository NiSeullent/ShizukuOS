# SPDX-License-Identifier: GPL-2.0-only
"""Owned Linux boundary controls; PCI, QMP hardware and Windows are modeled.

The held-source cohort supplies modules. Every helper wait uses real Linux
Unix sockets; fixture children are bounded and actually reaped by their parent.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile
import time
import unittest


class NativeEpochRuntime(unittest.TestCase):
    def setUp(self):
        self.epoch = __held_modules__['epoch']
        self.rpc = __held_modules__['rpc']
        self.guardian = __held_modules__['guardian']
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def required(self, module, name):
        value = getattr(module, name, None)
        self.assertTrue(callable(value), 'missing production optional runtime entry ' + name)
        return value

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
        gate.attempt = type('Deadline', (), {'original_deadline_ns': time.monotonic_ns() + 500_000_000})()
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

    def selection(self):
        helper = Path(__held_modules__['epoch'].__file__)
        raw = __held_source_bytes__[str(helper)]
        hpin = {'path': str(helper), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        rom = {'path': str(self.directory / 'rom.bin'), 'bytes': 65536,
               'sha256': 'eff7bff66e0175b6836f10c0590cacc82336e3271f98c6b684f8581b5c1e2854'}
        vga = {'path': str(self.directory / 'vga.bin'), 'bytes': 136, 'sha256': '1' * 64}
        manifest = {'native_epoch': {'roles': 1, 'helper_source': hpin,
                                    'raw_bars': [0xe0000008, 0, 0, 0, 0, 0]},
                    'optional_native_inputs': {'VGACFG.BIN': vga, 'VGAROM.BIN': rom},
                    'optional_native_provenance': {'VGA_BUILD_RECEIPT.JSON': {'path': str(self.directory / 'receipt.json'), 'bytes': 1, 'sha256': '2' * 64}}}
        built = {'optional_native_inputs': manifest['optional_native_inputs'],
                 'optional_native_provenance': manifest['optional_native_provenance']}
        return manifest, built, helper

    def test_absent_optional_selection_preserves_default(self):
        select = self.required(self.guardian, 'native_epoch_selection')
        self.assertIsNone(select({}, {}, Path('/unused')))

    def test_vga_pair_alone_selects_role_one(self):
        select = self.required(self.guardian, 'native_epoch_selection')
        manifest, built, helper = self.selection()
        selected = select(manifest, built, helper.parents[3])
        self.assertEqual(selected['roles'], 1)
        self.assertEqual(selected['raw_bars'], (0xe0000008, 0, 0, 0, 0, 0))

    def test_unselected_optional_blobs_refuse_before_spawn(self):
        select = self.required(self.guardian, 'native_epoch_selection')
        manifest, built, helper = self.selection(); del manifest['native_epoch']
        with self.assertRaises(ValueError): select(manifest, built, helper.parents[3])

    def test_persistence_role_is_not_silently_added(self):
        select = self.required(self.guardian, 'native_epoch_selection')
        manifest, built, helper = self.selection()
        manifest['optional_native_inputs']['W98PERS.BIN'] = {'path': str(self.directory / 'pers.bin'), 'bytes': 192, 'sha256': '3' * 64}
        with self.assertRaises(ValueError): select(manifest, built, helper.parents[3])

    def test_synthetic_rom_refuses_before_spawn(self):
        select = self.required(self.guardian, 'native_epoch_selection')
        manifest, built, helper = self.selection()
        manifest['optional_native_inputs']['VGAROM.BIN']['sha256'] = '1663' + '0' * 60
        with self.assertRaises(ValueError): select(manifest, built, helper.parents[3])

    def test_proxy_never_exposes_a_qmp_descriptor(self):
        proxy_type = self.required(self.rpc, 'QMPProxy')
        class NoSocketClient:
            def ordinary(self, op, params=None, **kwargs):
                self.last = (op, params)
                return {'running': True, 'status': 'running'}
        client = NoSocketClient(); proxy = proxy_type(client, time.monotonic() + 1)
        self.assertFalse(hasattr(proxy, 'socket'))
        self.assertEqual(proxy.call('query-status'), {'running': True, 'status': 'running'})
        self.assertEqual(client.last[0], 'epoch-qmp')

    def test_proxy_deadline_cannot_be_refreshed(self):
        proxy_type = self.required(self.rpc, 'QMPProxy')
        proxy = proxy_type(object(), time.monotonic() + 1)
        with self.assertRaises((AttributeError, ValueError)): proxy.deadline = time.monotonic() + 50

    def test_ordered_client_wait_pumps_locally_without_nested_requests(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        child = os.fork()
        if child == 0:
            left.close()
            try:
                channel = self.rpc.Channel(right, os.getppid())
                request, rights = channel.receive(1)
                for fd in rights: os.close(fd)
                time.sleep(.09)
                channel.send({'id': request['id'], 'ok': True, 'result': True})
            finally: os._exit(0)
        right.close(); client = self.rpc.Client(left.detach(), child); ticks = []
        def pump():
            ticks.append(1)
            try: client.ordinary('forbidden-reentry')
            except ValueError: pass
            else: self.fail('nested RPC advanced the current request sequence')
        try:
            try: answer, rights = client.call('modeled-gate', timeout=1, pump=pump)
            except TypeError: self.fail('ordered RPC wait cannot drain local logs')
            self.assertTrue(answer); self.assertEqual(rights, [])
            self.assertGreaterEqual(len(ticks), 2); self.assertEqual(client.sequence, 1)
        finally:
            client.close(); pid, status = os.waitpid(child, 0)
            self.assertEqual(pid, child); self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_proxy_capture_uses_actual_held_empty_private_fd(self):
        validate = self.required(self.guardian, 'capture_destination')
        path = self.directory / 'native-000-info.bin'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            result = validate(self.directory, 'pmemsave', {'val': 0x04000000, 'size': 8192, 'filename': str(path)}, fd)
            self.assertEqual(result['filename'], '/proc/%d/fd/%d' % (os.getpid(), fd))
            self.assertNotEqual(result['filename'], str(path))
        finally: os.close(fd)

    def test_capture_unapproved_extent_refuses(self):
        validate = self.required(self.guardian, 'capture_destination')
        path = self.directory / 'native-000-info.bin'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            with self.assertRaises(ValueError): validate(self.directory, 'pmemsave', {'val': 0x04000000, 'size': 8193, 'filename': str(path)}, fd)
        finally: os.close(fd)

    def test_capture_foreign_fd_and_alias_name_refuse(self):
        validate = self.required(self.guardian, 'capture_destination')
        path = self.directory / 'native-000-info.bin'; other = self.directory / 'foreign.bin'
        fd = os.open(other, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        path.write_bytes(b''); path.chmod(0o600)
        try:
            with self.assertRaises(ValueError): validate(self.directory, 'pmemsave', {'val': 0x04000000, 'size': 8192, 'filename': str(path)}, fd)
            path.unlink(); path.symlink_to(other)
            with self.assertRaises(ValueError): validate(self.directory, 'pmemsave', {'val': 0x04000000, 'size': 8192, 'filename': str(path)}, fd)
        finally: os.close(fd)
