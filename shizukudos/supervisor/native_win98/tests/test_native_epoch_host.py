"""Literal device/QMP fields are models; Linux FD/process/peer checks are real."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

NATIVE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_epoch_host', NATIVE / 'native_epoch_host.py')
host = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = host
spec.loader.exec_module(host)


def configs():
    rom = b'Z' * 65536
    vga = struct.pack('<6I2Q', 0x41475657, 1, 136, 1, 16, 0, 0xe0000000, 16 << 20)
    vga += hashlib.sha256(rom).digest() + b's' * 32 + b'c' * 32
    disk = bytearray(192)
    struct.pack_into('<II4H2Q2I', disk, 0, 0x52503957, 1, 24, 0x1af4, 0x1042, 0,
                     2304 << 20, 2 << 30, 0x53485739, 0)
    struct.pack_into('<QQII', disk, 40 + 4 * 24, 0xfe000000, 4096, 2, 0)
    bars = {1: (0xe0000008, 0, 0, 0, 0, 0), 2: (0, 0, 0, 0, 0xfe000004, 0)}
    return vga, rom, bytes(disk), bars


class Frames(unittest.TestCase):
    def setUp(self):
        self.vga, self.rom, self.disk, self.bars = configs()
        self.expected = host.Expectations(self.vga, self.rom, self.disk, self.bars)
        self.nonce = bytes(range(32))

    def report(self):
        raw = bytearray(256)
        struct.pack_into('<IHHII', raw, 0, 0x31454457, 1, 2, 256, 2)
        raw[16:48] = self.nonce
        raw[48:80] = hashlib.sha256(self.vga).digest()
        raw[80:112] = hashlib.sha256(self.disk).digest()
        raw[112:144] = hashlib.sha256(self.rom).digest()
        struct.pack_into('<Q', raw, 144, 100000100)
        for i, (role, bdf, vendor, device, klass, command) in enumerate([
                (1, 16, 0x1234, 0x1111, 0x030000, 3), (2, 24, 0x1af4, 0x1042, 0x010000, 6)]):
            struct.pack_into('<HHI10I', raw, 152 + i * 48, bdf, role, 0,
                             vendor | device << 16, command, klass << 8 | 1, 0,
                             *self.bars[role])
        return bytes(raw)

    def test_exact_policy_and_echo(self):
        policy = self.expected.policy(self.nonce, 123456789000)
        self.assertEqual(len(policy), 256)
        self.assertEqual(struct.unpack_from('<Q', policy, 144)[0], 123456789000)
        self.assertEqual(policy[216:], b'\0' * 40)
        ready = host.frame(4, 48, 0) + self.nonce
        host.validate_ready(ready, self.nonce)
        report = self.report()
        observations = host.validate_report(report, self.expected, self.nonce)
        self.assertEqual([x['bdf'] for x in observations], [16, 24])
        self.assertEqual(host.grant(report), host.frame(3, 272, 2) + report)

    def test_report_refusals(self):
        for offset in (0, 6, 8, 12, 16, 48, 80, 112, 156, 160, 200, 208, 248):
            with self.subTest(offset=offset):
                raw = bytearray(self.report()); raw[offset] ^= 1
                with self.assertRaises(ValueError):
                    host.validate_report(bytes(raw), self.expected, self.nonce)

    def test_bad_ready_replay_and_extents(self):
        for data in (host.frame(1, 48, 0) + self.nonce, host.frame(4, 48, 0) + b'x' * 32,
                     host.frame(4, 48, 0) + self.nonce + b'X'):
            with self.assertRaises(ValueError): host.validate_ready(data, self.nonce)
        with self.assertRaises(ValueError): host.grant(self.report()[:-1])

    def test_bad_shapes_full_hash_and_raw_bar(self):
        for off in (0, 4, 8, 12, 20, 24, 32, 40):
            broken = bytearray(self.vga); broken[off] ^= 1
            with self.subTest(offset=off), self.assertRaises(ValueError):
                host.Expectations(bytes(broken), self.rom, self.disk, self.bars)
        with self.assertRaises(ValueError): host.Expectations(self.vga, self.rom[:-1], self.disk, self.bars)
        with self.assertRaises(ValueError): host.Expectations(self.vga, self.rom, self.disk, {**self.bars, 2: (0, 0, 0, 0, 0xfe001004, 0)})
        with self.assertRaises(ValueError): self.expected.policy(b'\0' * 32, 1)
        with self.assertRaises(ValueError): self.expected.policy(self.nonce, True)

    def test_overlapping_selected_bars_refused(self):
        # Accepting two device decoders for the same bytes loses ownership.
        disk = bytearray(self.disk)
        struct.pack_into('<QQII', disk, 40 + 4 * 24, 0xe0000000, 4096, 2, 0)
        bars = {**self.bars, 2: (0, 0, 0, 0, 0xe0000004, 0)}
        with self.assertRaises(ValueError): host.Expectations(self.vga, self.rom, bytes(disk), bars)

    def pci(self):
        return [{'bus': 0, 'devices': [
            {'bus': 0, 'slot': 2, 'function': 0, 'id': {'vendor': 0x1234, 'device': 0x1111},
             'class_info': {'class': 0x0300, 'desc': 'VGA'}, 'qdev_id': '',
             'regions': [{'bar': 0, 'type': 'memory', 'address': 0xe0000000, 'size': 16 << 20,
                          'prefetch': True, 'mem_type_64': False}]},
            {'bus': 0, 'slot': 3, 'function': 0, 'id': {'vendor': 0x1af4, 'device': 0x1042},
             'class_info': {'class': 0x0100, 'desc': 'SCSI'}, 'qdev_id': '',
             'regions': [{'bar': 4, 'type': 'memory', 'address': 0xfe000000, 'size': 4096,
                          'prefetch': False, 'mem_type_64': True}]}]}]

    def test_complete_current_pci_and_ram_exclusion(self):
        flat = {'ram': ((0, 0x80000000), (1 << 32, 0x180000000)), 'ecam': (0xb0000000, 0xc0000000)}
        good = self.pci()
        self.assertEqual(set(host.validate_pci(good, self.expected, flat)), {16, 24})
        for change in ('duplicate', 'size', 'class', 'flags', 'missing', 'region-duplicate', 'bar-kind'):
            rows = json.loads(json.dumps(good))
            first = rows[0]['devices'][0]
            if change == 'duplicate': rows[0]['devices'].append(first.copy())
            elif change == 'size': first['regions'][0]['size'] = 8 << 20
            elif change == 'class': first['class_info']['class'] = 0x030000
            elif change == 'flags': first['regions'][0]['prefetch'] = False
            elif change == 'missing': rows[0]['devices'].pop()
            elif change == 'region-duplicate': first['regions'].append(first['regions'][0].copy())
            else: first['regions'][0]['type'] = 'io'
            with self.subTest(change=change), self.assertRaises(ValueError):
                host.validate_pci(rows, self.expected, flat)
        with self.assertRaises(ValueError): host.validate_pci(good, self.expected, {**flat, 'ram': ((0, 1 << 32),)})

    def test_foreign_and_ecam_collisions_refused(self):
        flat = {'ram': ((0, 0x80000000),), 'ecam': (0xb0000000, 0xc0000000)}
        foreign = self.pci()
        foreign[0]['devices'].append({'bus': 0, 'slot': 4, 'function': 0,
            'id': {'vendor': 0x8086, 'device': 0x100e}, 'class_info': {'class': 0x0200}, 'qdev_id': '',
            'regions': [{'bar': 0, 'type': 'memory', 'address': 0xe0000000, 'size': 4096,
                         'prefetch': False, 'mem_type_64': False}]})
        with self.assertRaises(ValueError): host.validate_pci(foreign, self.expected, flat)
        with self.assertRaises(ValueError): host.validate_pci(self.pci(), self.expected, {**flat, 'ecam': (0xe0000000, 0xf0000000)})

    def test_actual_block_field_models_reject_flush_and_identity_drift(self):
        # No 2.25GiB image is created: only QMP field interpretation is modeled.
        class ESPModel:
            path = Path('/private/model/esp.img')
            binding = (77, 88)
            def check(self): pass
        esp = ESPModel()
        row = {'node-name': 'owned', 'drv': 'raw', 'ro': False, 'encrypted': False,
               'file': str(esp.path), 'cache': {'writeback': True, 'direct': False, 'no-flush': False},
               'image': {'filename': str(esp.path), 'format': 'raw', 'virtual-size': 2304 << 20}}
        blocks = [{'device': 'esp', 'locked': False, 'inserted': row}]
        record = host.validate_blocks(blocks, [row], esp)
        self.assertEqual(record['caller_inode'], (77, 88))
        self.assertFalse(record['QMP_filename_establishes_open_inode'])
        for field in ('no-flush', 'direct', 'writeback', 'file', 'ro', 'extent', 'duplicate'):
            block = json.loads(json.dumps(blocks)); node = json.loads(json.dumps([row]))
            if field in ('no-flush', 'direct', 'writeback'):
                block[0]['inserted']['cache'][field] = not block[0]['inserted']['cache'][field]
            elif field == 'file': node[0]['file'] = '/foreign/esp.img'
            elif field == 'ro': node[0]['ro'] = True
            elif field == 'extent': node[0]['image']['virtual-size'] -= 1
            else: node.append(node[0].copy())
            with self.subTest(field=field), self.assertRaises(ValueError): host.validate_blocks(block, node, esp)

    def test_flatview_observed_ecam_and_split_ram(self):
        text = ('FlatView #2\n AS "memory", root: system\n Root memory region: system\n'
                '  0000000000000000-000000000009ffff (prio 0, ram): pc.ram\n'
                '  00000000b0000000-00000000bfffffff (prio 1, i/o): pcie-mmcfg\n'
                '  0000000100000000-000000013fffffff (prio 0, ram): pc.ram @00000000c0000000\n\n')
        result = host.parse_flatview(text)
        self.assertEqual(result['ecam'], (0xb0000000, 0xc0000000))
        self.assertEqual(result['ram'], ((0, 0xa0000), (1 << 32, 0x140000000)))
        for bad in (text.rstrip(), text.replace('i/o', 'unknown'), text.replace('pcie-mmcfg', 'guessed'),
                    text.replace('0000000100000000', '00000000b0000000')):
            with self.assertRaises(ValueError): host.parse_flatview(bad)

    def test_xp_addresses_extent_and_truncation(self):
        values = tuple(range(10))
        text = '\n'.join('00000000b0010000: ' + ' '.join('0x%08x' % x for x in values[:4])
                         if i == 0 else '%016x: ' % (0xb0010000 + i * 4) + ' '.join('0x%08x' % x for x in values[i:i + 4])
                         for i in (0, 4, 8)) + '\n'
        self.assertEqual(host.parse_xp(text, 0xb0010000), values)
        for bad in (text[:-12], text.replace('b0010010', 'b0010014'), text + 'garbage\n'):
            with self.assertRaises(ValueError): host.parse_xp(bad, 0xb0010000)


class LinuxOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.path = Path(self.tmp.name)
        os.chmod(self.path, 0o700)
        self.fds = []

    def tearDown(self):
        for fd in self.fds:
            try:
                if fcntl.fcntl(fd, fcntl.F_GETLEASE) != fcntl.F_UNLCK:
                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            finally: os.close(fd)
        self.tmp.cleanup()

    def source(self, name, data):
        p = self.path / name; p.write_bytes(data); p.chmod(0o600)
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW); self.fds.append(fd)
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid()); fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        return host.PinnedFD(fd, {'path': str(p), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})

    def existing_source(self, path):
        path = Path(path).resolve()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW); self.fds.append(fd)
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid()); fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        raw = os.pread(fd, os.fstat(fd).st_size + 1, 0)
        return host.PinnedFD(fd, {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})

    def binding(self, child, argv):
        executable = self.existing_source(sys.executable)
        pidfd = os.pidfd_open(child.pid)
        cgroup = Path('/proc/self/cgroup').read_text().strip().split('0::', 1)[1]
        try: return host.ProcessBinding(child, pidfd, executable, tuple(argv), cgroup)
        except BaseException: os.close(pidfd); raise

    def finish_child(self, child, binding=None):
        try: os.kill(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        if binding is None: child.wait(timeout=2); return
        try:
            poll = select.poll(); poll.register(binding.pidfd, select.POLLIN)
            self.assertTrue(poll.poll(2000), 'owned test child did not exit')
            record = binding.reap_owned(); self.assertEqual(record['pid'], child.pid)
            binding.assert_reaped()
        finally: os.close(binding.pidfd)

    def test_sealed_actual_policy_fresh_nonce_and_close(self):
        vga, rom, disk, bars = configs()
        inputs = [self.source('vga', vga), self.source('rom', rom), self.source('disk', disk)]
        a = host.Attempt(*inputs, bars, time.monotonic_ns() + 10_000_000_000)
        b = host.Attempt(*inputs, bars, time.monotonic_ns() + 10_000_000_000)
        try:
            self.assertNotEqual(a.nonce, b.nonce)
            self.assertEqual(os.fstat(a.policy_fd).st_size, 256)
            a.check()
            with self.assertRaises(OSError): os.pwrite(a.policy_fd, b'X', 0)
            # This kernel updates memfd mtime/ctime even for denied writes.
            # Bytes/seals remain immutable; the producer may refuse metadata
            # drift. Never rebind the producer identity to hide this event.
            self.assertEqual(os.pread(a.policy_fd, 257, 0), a.policy)
            self.assertEqual(fcntl.fcntl(a.policy_fd, fcntl.F_GET_SEALS), host.SEALS)
            b.original_deadline_ns += 1
            with self.assertRaises(ValueError): b.check()
        finally: a.close(); b.close()

    def test_pinned_extent_hash_and_source_lease(self):
        pinned = self.source('x', b'abc'); pinned.check()
        with self.assertRaises(ValueError): host.PinnedFD(pinned.fd, {**pinned.pin, 'sha256': '1' * 64})
        fcntl.fcntl(pinned.fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        with self.assertRaises(ValueError): pinned.check()

    def test_actual_connecting_peer_not_socketpair_creator(self):
        listener = host.PrivateListener(self.path / 'com2.sock')
        child = subprocess.Popen([sys.executable, '-B', '-c',
                                  'import socket,sys,time;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(b"READY");time.sleep(3)', str(listener.path)])
        try:
            connection = listener.accept(child.pid, os.getuid(), time.monotonic_ns() + 1_000_000_000, guard=lambda: None)
            try:
                self.assertEqual(struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0], child.pid)
                self.assertTrue(select.select([connection], [], [], 1)[0])
                self.assertEqual(connection.recv(5), b'READY')
            finally: connection.close()
            with self.assertRaises(ValueError): listener.accept(child.pid, os.getuid(), time.monotonic_ns() + 1_000_000_000, guard=lambda: None)
        finally: child.kill(); child.wait(timeout=2); listener.close()

    def test_listener_foreign_parent_and_replacement(self):
        listener = host.PrivateListener(self.path / 'com2.sock')
        foreign = socket.socket(socket.AF_UNIX); foreign.connect(str(listener.path))
        try:
            with self.assertRaises(ValueError): listener.accept(os.getpid() + 1, os.getuid(), time.monotonic_ns() + 1_000_000_000, guard=lambda: None)
        finally: foreign.close(); listener.close()
        listener = host.PrivateListener(self.path / 'second.sock')
        old = self.path / 'old.sock'; listener.path.rename(old); listener.path.write_bytes(b'foreign')
        with self.assertRaises(ValueError): listener.close()
        self.assertEqual(listener.path.read_bytes(), b'foreign')

    def test_final_socket_symlink_refused(self):
        listener = host.PrivateListener(self.path / 'alias.sock')
        old = self.path / 'original.sock'; listener.path.rename(old); listener.path.symlink_to(old)
        try:
            with self.assertRaises(ValueError): listener.check()
        finally:
            listener.path.unlink(); old.rename(listener.path); listener.close()

    def test_constructor_failure_retains_actual_child_resources(self):
        vga, rom, disk, bars = configs()
        attempt = host.Attempt(self.source('vga', vga), self.source('rom', rom), self.source('disk', disk), bars, time.monotonic_ns() + 10_000_000_000)
        listener = host.PrivateListener(self.path / 'ctor.sock')
        argv = [sys.executable, '-B', '-c', 'import time;time.sleep(20)']
        child = subprocess.Popen(argv); binding = None
        try:
            binding = self.binding(child, argv)
            # Empty ESP object is only an early-refusal fixture: no large file.
            with self.assertRaises(ValueError): host.HostGrant(attempt, binding, None, listener, host.OwnedESP.__new__(host.OwnedESP), None, guard=lambda: None)
            with self.assertRaises(ValueError): attempt.close()
            with self.assertRaises(ValueError): listener.close()
            self.assertEqual(os.fstat(attempt.policy_fd).st_size, 256)
            self.assertTrue(listener.path.exists())
        finally:
            try: os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            if binding is not None:
                poll = select.poll(); poll.register(binding.pidfd, select.POLLIN); self.assertTrue(poll.poll(2000))
                binding.reap_owned(); listener.close(); attempt.close(); os.close(binding.pidfd)
            else: child.wait(timeout=2); listener.close(); attempt.close()

    def test_substituted_pidfd_does_not_reap_foreign_child(self):
        argv = [sys.executable, '-B', '-c', 'import time;time.sleep(20)']
        children = [subprocess.Popen(argv), subprocess.Popen(argv)]; bindings = []
        try:
            bindings = [self.binding(child, argv) for child in children]
            a, b = bindings; original = a.pidfd
            os.kill(children[1].pid, signal.SIGKILL)
            poll = select.poll(); poll.register(b.pidfd, select.POLLIN); self.assertTrue(poll.poll(2000))
            a.pidfd = b.pidfd
            try:
                with self.assertRaises(ValueError): a.reap_owned()
            finally: a.pidfd = original
            try: observed = os.waitid(os.P_PIDFD, b.pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError: self.fail('foreign child was destructively reaped')
            self.assertEqual(observed.si_pid, children[1].pid)
        finally:
            for i, child in enumerate(children):
                try: os.kill(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                if i >= len(bindings): child.wait(timeout=2); continue
                binding = bindings[i]
                poll = select.poll(); poll.register(binding.pidfd, select.POLLIN); self.assertTrue(poll.poll(2000))
                if 'Pid:\t-1' in Path('/proc/self/fdinfo/%d' % binding.pidfd).read_text(): child.returncode = -signal.SIGKILL
                else: binding.reap_owned(); binding.assert_reaped()
                os.close(binding.pidfd)

    def test_actual_popen_pidfd_start_exe_argv_cgroup_and_strict_reap(self):
        argv = [sys.executable, '-B', '-c', 'import time;time.sleep(20)']
        child = subprocess.Popen(argv); binding = None
        try:
            binding = self.binding(child, argv)
            proof = binding.check(); self.assertEqual(proof['pid'], child.pid)
            self.assertGreater(proof['starttime'], 0)
            with self.assertRaises(ValueError): binding.assert_reaped()
            with self.assertRaises(ValueError): binding.reap_owned()
            for attr, changed in (('starttime', binding.starttime + 1), ('command', b'wrong\0'), ('cgroup', '/foreign')):
                original = getattr(binding, attr); setattr(binding, attr, changed)
                try:
                    with self.subTest(attr=attr), self.assertRaises(ValueError): binding.check()
                finally: setattr(binding, attr, original)
            foreign = os.pidfd_open(os.getpid()); original = binding.pidfd; binding.pidfd = foreign
            try:
                with self.assertRaises(ValueError): binding.check()
            finally: binding.pidfd = original; os.close(foreign)
        finally: self.finish_child(child, binding)
        with self.assertRaises(ChildProcessError): os.waitpid(child.pid, os.WNOHANG)

    def test_owned_esp_rejects_small_real_fd_without_large_image(self):
        pinned = self.source('small-esp', b'not-an-image')
        with self.assertRaises(ValueError): host.OwnedESP(pinned.fd, pinned.path)

    def run_backend_fd(self, case):
        # Six actual private bytes exercise Linux open-inode facts. They are
        # not an ESP, a block graph, a QEMU process or hardware authority.
        path = self.path / 'backend'; path.write_bytes(b'abcdef'); path.chmod(0o600)
        other = self.path / 'foreign'; other.write_bytes(b'foreign'); other.chmod(0o600)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW); self.fds.append(fd)
        opened = other if case == 'foreign' else path
        mode = os.O_RDONLY if case == 'readonly' else os.O_RDWR
        script = ('import os,sys,time;fd=os.open(sys.argv[1],int(sys.argv[2]));'
                  'extra=os.dup(fd) if sys.argv[3]=="duplicate" else -1;'
                  'many=[os.dup(fd) for _ in range(257)] if sys.argv[3]=="overflow" else [];'
                  'sys.stdout.write("R");sys.stdout.flush();\n'
                  'if sys.argv[3]=="flags-change":\n'
                  ' sys.stdin.buffer.read(1);os.close(fd);fd=os.open(sys.argv[1],os.O_RDONLY);'
                  'sys.stdout.write("C");sys.stdout.flush()\n'
                  'time.sleep(20)')
        argv = [sys.executable, '-B', '-c', script, str(opened), str(mode), case]
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE); binding = None
        try:
            binding = self.binding(child, argv)
            self.assertTrue(select.select([child.stdout], [], [], 2)[0]); self.assertEqual(child.stdout.read(1), b'R')
            if case == 'unlinked':
                path.unlink(); path.write_bytes(b'abcdef'); path.chmod(0o600)
                replacement = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
                self.fds[self.fds.index(fd)] = replacement; os.close(fd); fd = replacement
            if case == 'alias':
                old = self.path / 'renamed'; path.rename(old); path.symlink_to(old)
            if case == 'changed':
                old = self.path / 'renamed'; path.rename(old); path.write_bytes(b'abcdef'); path.chmod(0o600)
                replacement = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
                self.fds[self.fds.index(fd)] = replacement; os.close(fd); fd = replacement
            if case == 'flags-change':
                original = binding.check; calls = [0]
                def changed_after_first_inventory():
                    calls[0] += 1
                    if calls[0] == 2:
                        child.stdin.write(b'C'); child.stdin.flush()
                        self.assertTrue(select.select([child.stdout], [], [], 2)[0]); self.assertEqual(child.stdout.read(1), b'C')
                    return original()
                # The trigger is modeled; both before/after FD flags are
                # actual observations from this actual owned Linux child.
                with patch.object(binding, 'check', changed_after_first_inventory), self.assertRaises(ValueError):
                    host.observe_open_backend(binding, fd, path)
            elif case == 'positive':
                record = host.observe_open_backend(binding, fd, path)
                self.assertEqual(record['opened_identity'][:3], list(host.identity(os.fstat(fd))[:3]))
                self.assertEqual(record['access'], 'read-write')
                self.assertTrue(record['observed_owned_process_open_inode'])
                self.assertFalse(record['content_immutability_verified'])
            else:
                with self.assertRaises((ValueError, FileNotFoundError)): host.observe_open_backend(binding, fd, path)
        finally:
            self.finish_child(child, binding)
            if child.stdin is not None: child.stdin.close()
            if child.stdout is not None: child.stdout.close()

    def test_actual_backend_open_inode_positive(self): self.run_backend_fd('positive')
    def test_actual_backend_foreign_open_refused(self): self.run_backend_fd('foreign')
    def test_actual_backend_deleted_name_refused(self): self.run_backend_fd('unlinked')
    def test_actual_backend_alias_refused(self): self.run_backend_fd('alias')
    def test_actual_backend_replaced_inode_refused(self): self.run_backend_fd('changed')
    def test_actual_backend_readonly_open_refused(self): self.run_backend_fd('readonly')
    def test_actual_backend_duplicate_open_refused(self): self.run_backend_fd('duplicate')
    def test_actual_backend_inventory_overflow_refused(self): self.run_backend_fd('overflow')
    def test_actual_backend_flags_change_between_inventories_refused(self): self.run_backend_fd('flags-change')

    def test_actual_sole_qmp_peer_and_current_source_methods(self):
        # Python is a protocol fixture process, never claimed to be QEMU.
        source = self.existing_source(NATIVE / 'owned_capture.py')
        namespace = {'__file__': str(source.path), '__name__': '_host_owned_fixture'}
        exec(compile(source.check(), str(source.path), 'exec'), namespace)
        qmp_path = self.path / 'qmp.sock'
        flat = ('FlatView #0\n AS "memory", root: system\n Root memory region: system\n'
                '  0000000000000000-000000007fffffff (prio 0, ram): pc.ram\n'
                '  00000000b0000000-00000000bfffffff (prio 1, i/o): pcie-mmcfg\n\n')
        xp = '00000000b0010000: 0x00000000 0x00000001 0x00000002 0x00000003\n00000000b0010010: 0x00000004 0x00000005 0x00000006 0x00000007\n00000000b0010020: 0x00000008 0x00000009\n'
        script = ('import socket,json,sys;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);'
                  'c,_=s.accept();f=c.makefile("rwb",buffering=0);'
                  'f.write(b\'{"QMP":{"version":{}}}\\n\');\n'
                  'for line in f:\n'
                  ' r=json.loads(line);v={"running":False,"status":"paused"} if r["execute"]=="query-status" else {};'
                  'v=sys.argv[2] if r.get("arguments",{}).get("command-line")=="info mtree -f" else sys.argv[3] if r["execute"]=="human-monitor-command" else v;'
                  'f.write((json.dumps({"id":r["id"],"return":v})+"\\n").encode())\n')
        argv = [sys.executable, '-B', '-c', script, str(qmp_path), flat, xp]
        child = subprocess.Popen(argv); binding = monitor = attempt = None
        try:
            binding = self.binding(child, argv)
            deadline = time.monotonic() + 20
            vga, rom, disk, bars = configs()
            attempt = host.Attempt(self.source('vga', vga), self.source('rom', rom), self.source('disk', disk), bars, int(deadline * 1e9))
            monitor = namespace['OwnedQMP'](qmp_path, child.pid, deadline)
            sole = host.SoleQMP(binding, monitor, attempt, source)
            with self.assertRaises(ValueError): sole.call('human-monitor-command', {'command-line': 'xp /10wx 0x0'})
            sole.paused()
            self.assertEqual(sole.transcripts[0]['command'], 'query-status')
            with self.assertRaises(ValueError): host.SoleQMP(binding, monitor, attempt, source)
            sole.call('human-monitor-command', {'command-line': 'info mtree -f'})
            self.assertEqual(sole.call('human-monitor-command', {'command-line': 'xp /10wx 0xb0010000'}), xp)
            with self.assertRaises(ValueError): sole.call('human-monitor-command', {'command-line': 'xp /10wx 0x0'})
            for command in ('cont', 'quit', 'pmemsave', 'human-monitor-command'):
                with self.subTest(command=command), self.assertRaises(ValueError): sole.call(command)
            monitor.deadline += 1
            with self.assertRaises(ValueError): sole.check()
            monitor.deadline = deadline
            original = monitor.call; monitor.call = lambda *args: {}
            with self.assertRaises(ValueError): sole.check()
            monitor.call = original
            for code in (original.__code__.replace(co_filename='/foreign/owned_capture.py'),
                         original.__code__.replace(co_consts=tuple(6 if type(x) is int and x == 5 else x for x in original.__code__.co_consts))):
                monitor.call = types.MethodType(types.FunctionType(code, original.__globals__), monitor)
                try:
                    with self.assertRaises(ValueError): sole.check()
                finally: monitor.call = original
            pair = socket.socketpair(); original_socket = monitor.socket; monitor.socket = pair[0]
            try:
                with self.assertRaises(ValueError): sole.check()
            finally: monitor.socket = original_socket; pair[0].close(); pair[1].close()
            # B13: a request must fit the immutable exchange stop minus the
            # pre-GRANT reserve; below the minimum useful bound it is refused.
            attempt.exchange_stop_ns = attempt.original_exchange_stop_ns = time.monotonic_ns() + host.QMP_GRANT_RESERVE_NS + 100_000_000
            with self.assertRaises(ValueError): sole.paused()
            # Under 5 s left (root R5) now fits with a narrowed request bound.
            attempt.exchange_stop_ns = attempt.original_exchange_stop_ns = time.monotonic_ns() + 3_000_000_000
            sole.paused(); self.assertIs(monitor.deadline, deadline); self.assertLessEqual(sole.transcripts[-1]['request_bound_ms'], 2500)
        finally:
            self.finish_child(child, binding)
            if monitor is not None: monitor.close()
            if attempt is not None: attempt.close()

    def test_stale_policy_and_backward_clock_refusal(self):
        vga, rom, disk, bars = configs()
        attempt = host.Attempt(self.source('vga', vga), self.source('rom', rom), self.source('disk', disk), bars, time.monotonic_ns() + 5_000_000_000)
        try:
            for now in (attempt.last_now - 1, attempt.original_deadline_ns):
                with patch.object(host.time, 'monotonic_ns', return_value=now), self.assertRaises(ValueError): attempt.check()
        finally: attempt.close()


class ModeledHardwareExchange(unittest.TestCase):
    """Production exchange/transport with real Python peers; QMP hardware modeled.

    Deliberately bypasses HostGrant's QEMU constructor. This fixture cannot
    supply a real host grant, recipe admission, or a physical device epoch.
    """
    setUp = LinuxOwnership.setUp
    tearDown = LinuxOwnership.tearDown
    source = LinuxOwnership.source
    existing_source = LinuxOwnership.existing_source
    binding = LinuxOwnership.binding

    def run_exchange(self, case):
        frames = Frames(); frames.setUp()
        vga, rom, disk, bars = configs()
        attempt = host.Attempt(self.source('vga', vga), self.source('rom', rom), self.source('disk', disk), bars, time.monotonic_ns() + 20_000_000_000)
        listener = host.PrivateListener(self.path / 'epoch.sock')
        report = frames.report()
        # Frame extents and bytes are literals; peer echoes the actual nonce.
        script = ('import socket,sys,time,hashlib;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);'
                  'nonce=bytes.fromhex(sys.argv[2]);report=bytearray.fromhex(sys.argv[3]);case=sys.argv[4];'
                  's.sendall(bytes.fromhex("57444531010004003000000000000000")+(b"x"*32 if case=="wrong-ready" else nonce));\n'
                  'def read(n):\n'
                  ' b=b""\n'
                  ' while len(b)<n:\n'
                  '  x=s.recv(n-len(b))\n'
                  '  if not x: raise RuntimeError("closed")\n'
                  '  b+=x\n'
                  ' return b\n'
                  'challenge=read(48);report[16:48]=challenge[16:48];'
                  'report[16]=report[16]^1 if case=="wrong-report" else report[16];'
                  's.sendall(report);grant=read(272);'
                  'sys.stdout.write(hashlib.sha256(grant).hexdigest());sys.stdout.flush();time.sleep(20)\n')
        argv = [sys.executable, '-B', '-c', script, str(listener.path), attempt.nonce.hex(), report.hex(), case]
        child = subprocess.Popen(argv, pass_fds=(attempt.policy_fd,), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        binding = None; exchange = None
        try:
            binding = self.binding(child, argv)
            class ESPModel:
                path = Path('/private/modeled/esp.img')
                binding = (77, 88)
                def check(self): pass
                def observe_backend(self, owner):
                    # Explicit modeled kernel/backend boundary. This cannot
                    # satisfy concrete HostGrant/OwnedESP construction.
                    if case == 'missing-backend': raise ValueError('modeled absent open inode')
                    return {'modeled_backend_open_inode': [77, 88], 'not_runtime_authority': True}
            esp = ESPModel()
            class QMPHardwareModel:
                def __init__(self): self.calls = []; self.transcripts = []; self.views = 0
                def check(self): attempt.check(); binding.check()
                def paused(self): self.call('query-status')
                def call(self, command, arguments=None):
                    self.calls.append((command, arguments))
                    if case == 'late-grant' and exchange.grant_bytes_written:
                        binding.starttime += 1
                    if command == 'human-monitor-command':
                        if arguments['command-line'] == 'info mtree -f':
                            self.views += 1
                            base = 0xa0000000 if case == 'changed-epoch' and self.views > 1 else 0xb0000000
                            return ('FlatView #0\n AS "memory", root: system\n Root memory region: system\n'
                                    '  0000000000000000-000000007fffffff (prio 0, ram): pc.ram\n'
                                    '  %016x-%016x (prio 1, i/o): pcie-mmcfg\n\n' % (base, base + (256 << 20) - 1))
                        address = int(arguments['command-line'].split()[-1], 16)
                        bdf = (address - (0xa0000000 if case == 'changed-epoch' and self.views > 1 else 0xb0000000)) // 4096
                        words = struct.unpack_from('<10I', report, 160 if bdf == 16 else 208)
                        return '\n'.join('%016x: ' % (address + i * 4) + ' '.join('0x%08x' % x for x in words[i:i + 4]) for i in (0, 4, 8)) + '\n'
                    if command == 'query-pci': return frames.pci()
                    row = {'node-name': 'owned', 'drv': 'raw', 'ro': False, 'encrypted': False,
                           'file': str(esp.path), 'cache': {'writeback': True, 'direct': False, 'no-flush': False},
                           'image': {'filename': str(esp.path), 'format': 'raw', 'virtual-size': 2304 << 20}}
                    if command == 'query-block': return [{'device': 'esp', 'locked': False, 'inserted': row}]
                    if command == 'query-named-block-nodes': return [row]
                    return {'running': False, 'status': 'paused'} if command == 'query-status' else {}
            exchange = host.HostGrant.__new__(host.HostGrant)
            exchange.guard = lambda: None
            exchange.attempt, exchange.binding, exchange.listener, exchange.esp = attempt, binding, listener, esp
            exchange.qmp = QMPHardwareModel(); exchange.peer = None
            exchange.exchange_stop_ns = exchange.original_exchange_stop_ns = None
            exchange.transport_calls = exchange.grant_bytes_written = 0
            attempt.owner = listener.owner = binding
            if case == 'success':
                record = exchange.exchange()
                self.assertTrue(record['host_grant_transmitted'])
                self.assertFalse(record['constructor_host_runtime_wiring_implemented'])
                self.assertFalse(record['native_gate_admission_observed'])
                self.assertTrue(select.select([child.stdout], [], [], 1)[0])
                self.assertEqual(child.stdout.read(64).decode(), record['grant_sha256'])
                self.assertEqual(exchange.grant_bytes_written, 272)
                with self.assertRaises(ValueError): exchange.exchange()
            else:
                with self.assertRaises(ValueError): exchange.exchange()
                self.assertEqual(exchange.failure_after_grant_bytes, 272 if case == 'late-grant' else 0)
                self.assertTrue(attempt.consumed)
                with self.assertRaises(ValueError): exchange.exchange()
            with self.assertRaises(ValueError): exchange.close_after_reap()
            self.assertTrue(listener.path.exists()); self.assertEqual(os.fstat(attempt.policy_fd).st_size, 256)
            self.assertTrue(all(command in {'stop', 'query-status', 'query-pci', 'query-block', 'query-named-block-nodes', 'human-monitor-command'} for command, _ in exchange.qmp.calls))
        finally:
            try: os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            if binding is not None:
                poll = select.poll(); poll.register(binding.pidfd, select.POLLIN); self.assertTrue(poll.poll(2000))
                binding.reap_owned()
                if exchange is not None: exchange.close_after_reap()
                else: listener.close(); attempt.close()
                os.close(binding.pidfd)
            else: child.wait(timeout=2); listener.close(); attempt.close()
            if child.stdout is not None: child.stdout.close()

    def test_actual_transport_modeled_grant_and_single_use(self): self.run_exchange('success')
    def test_wrong_ready_nonce_has_no_grant(self): self.run_exchange('wrong-ready')
    def test_wrong_report_nonce_has_no_grant(self): self.run_exchange('wrong-report')
    def test_changed_paused_epoch_has_no_grant(self): self.run_exchange('changed-epoch')
    def test_missing_backend_observation_has_no_grant(self): self.run_exchange('missing-backend')
    def test_late_failure_records_transmitted_grant_and_retains_resources(self): self.run_exchange('late-grant')


if __name__ == '__main__':
    unittest.main()
