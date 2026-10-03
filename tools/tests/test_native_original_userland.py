# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic sparse FAT disks and real FD/lease controls; no Windows or VM."""
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load('original_userland_producer', ROOT / 'tools/native_original_userland.py')
reader = load('original_userland_test_reader', tool.READER)


def file_pin(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest}


def paths(directory):
    return (f'[Paths]\r\nWinDir=C:\\{directory}\r\nWinBootDir=C:\\{directory}\r\n'
            'HostWinBootDrv=C\r\n').encode()


def name83(name):
    base, _, extension = name.partition('.')
    return base.encode().ljust(8, b' ') + extension.encode().ljust(3, b' ')


def row(name, cluster, size, directory=False):
    raw = bytearray(32)
    raw[:11] = name83(name)
    raw[11] = 0x10 if directory else 0x20
    struct.pack_into('<HI', raw, 26, cluster, size)
    return bytes(raw)


def make_disk(path, directory='WINDOWS', msdos=None, omitted=None, alias=False):
    """Real 2 GiB sparse whole disk, small FAT16 partition, fake file contents."""
    start, reserved, fat_sectors, roots, clusters = 32, 1, 20, 512, 5000
    total = reserved + 2 * fat_sectors + roots * 32 // 512 + clusters
    mbr, vbr = bytearray(512), bytearray(512)
    mbr[510:] = vbr[510:] = b'\x55\xaa'
    mbr[446] = 0x80
    mbr[450] = 6
    struct.pack_into('<II', mbr, 454, start, total)
    vbr[:11] = b'\xeb\x3c\x90SYNTHFAT'
    struct.pack_into('<HBHBHHBHHHII', vbr, 11, 512, 1, reserved, 2, roots,
                     total, 0xf8, fat_sectors, 63, 255, start, 0)
    vbr[36] = 0x80
    first_data = start + reserved + 2 * fat_sectors + roots * 32 // 512
    contents = {'IO.SYS': b'SYNTHETIC IO NOT EXECUTABLE WINDOWS',
                'MSDOS.SYS': paths(directory) if msdos is None else msdos,
                'COMMAND.COM': b'SYNTHETIC SHELL NOT EXECUTABLE',
                'WIN.COM': b'SYNTHETIC WIN NOT EXECUTABLE',
                'SYSTEM.INI': b'SYNTHETIC INI NOT WINDOWS',
                'VMM32.VXD': b'SYNTHETIC VMM NOT EXECUTABLE',
                'IFSHLP.SYS': b'SYNTHETIC IFS NOT EXECUTABLE'}
    numbers = dict(zip(contents, range(4, 11)))
    fat = bytearray(fat_sectors * 512)
    struct.pack_into('<HH', fat, 0, 0xfff8, 0xffff)
    for cluster in range(2, 12):
        struct.pack_into('<H', fat, cluster * 2, 0xffff)
    root = b''.join(row(n, numbers[n], len(contents[n])) for n in
                    ('IO.SYS', 'MSDOS.SYS', 'COMMAND.COM') if n != omitted)
    root += row(directory, 2, 0, True)
    if alias:
        root += row('io.sys', 11, 6)
    win = b''.join(row(n, numbers[n], len(contents[n])) for n in
                   ('WIN.COM', 'SYSTEM.INI', 'IFSHLP.SYS') if n != omitted)
    win += row('SYSTEM', 3, 0, True)
    system = b'' if omitted == 'VMM32.VXD' else row('VMM32.VXD', numbers['VMM32.VXD'], len(contents['VMM32.VXD']))
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(fd, tool.DISK_BYTES)
        os.pwrite(fd, mbr, 0)
        os.pwrite(fd, vbr, start * 512)
        for index in range(2):
            os.pwrite(fd, fat, (start + reserved + index * fat_sectors) * 512)
        os.pwrite(fd, root, (start + reserved + 2 * fat_sectors) * 512)
        os.pwrite(fd, win.ljust(512, b'\0'), first_data * 512)
        os.pwrite(fd, system.ljust(512, b'\0'), (first_data + 1) * 512)
        for name, raw in contents.items():
            os.pwrite(fd, raw, (first_data + numbers[name] - 2) * 512)
        if alias:
            os.pwrite(fd, b'alias!', (first_data + 9) * 512)
        os.fsync(fd)
    finally:
        os.close(fd)
    return bytes(mbr), bytes(vbr), contents


class ActualObservation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-original-observe-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def observe(self, disk, directory='WINDOWS'):
        fd = os.open(disk, os.O_RDONLY | os.O_CLOEXEC)
        before = tool.identity(os.fstat(fd))
        checks = []
        def check():
            self.assertEqual(tool.identity(os.fstat(fd)), before)
            self.assertEqual(tool.identity(disk.stat()), before)
            checks.append(True)
        try:
            result = tool.observe(fd, tool.DISK_BYTES, directory, reader, check)
            self.assertTrue(checks)
            return result
        finally:
            os.close(fd)

    def test_actual_fat_fd_fields_and_alternate_directory(self):
        disk = self.root / 'synthetic.raw'
        mbr, vbr, contents = make_disk(disk, directory='WIN98')
        result = self.observe(disk, 'WIN98')
        self.assertEqual(set(result), {'observed_windows_path', 'observed_members', 'boot_sectors'})
        self.assertEqual(result['observed_windows_path'], r'C:\WIN98')
        self.assertEqual(len(result['observed_members']), 7)
        for name, member in result['observed_members'].items():
            self.assertEqual(member['sha256'], tool.sha(contents[name.rsplit('/', 1)[-1]]))
            self.assertEqual(set(member), {'bytes', 'sha256', 'metadata_sha256', 'cluster'})
        self.assertEqual(result['boot_sectors'], {'mbr': {'bytes': 512, 'sha256': tool.sha(mbr)},
                                                'vbr': {'bytes': 512, 'sha256': tool.sha(vbr)}})
        self.assertEqual(disk.stat().st_size, 2 << 30)
        self.assertLess(disk.stat().st_blocks * 512, 1 << 20)

    def test_actual_missing_empty_directory_and_case_alias_refused(self):
        for name in ('IO.SYS', 'MSDOS.SYS', 'COMMAND.COM', 'WIN.COM', 'SYSTEM.INI', 'IFSHLP.SYS', 'VMM32.VXD'):
            with self.subTest(member=name):
                disk = self.root / (name + '.raw')
                make_disk(disk, omitted=name)
                with self.assertRaisesRegex(ValueError, 'required regular'):
                    self.observe(disk)
        disk = self.root / 'empty.raw'
        make_disk(disk, msdos=b'')
        with self.assertRaisesRegex(ValueError, 'required regular'):
            self.observe(disk)
        disk = self.root / 'alias.raw'
        make_disk(disk, alias=True)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.observe(disk)

    def test_actual_wrong_and_duplicate_msdos_paths_refused(self):
        for index, raw in enumerate((paths('OTHER'), paths('WINDOWS') + b'[Paths]\r\n',
                                     paths('WINDOWS') + b'WinDir=C:\\WINDOWS\r\n',
                                     paths('WINDOWS').replace(b'HostWinBootDrv=C', b'HostWinBootDrv=D'))):
            disk = self.root / ('paths-' + str(index))
            make_disk(disk, msdos=raw)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.observe(disk)

    def test_actual_invalid_active_partition_or_geometry_refused(self):
        for index, (offset, raw) in enumerate(((446, b'\0'), (510, b'\0\0'),
                                               (32 * 512 + 13, b'\x03'),
                                               (32 * 512 + 28, struct.pack('<I', 99)))):
            disk = self.root / ('geometry-' + str(index))
            make_disk(disk)
            with disk.open('r+b') as stream:
                stream.seek(offset)
                stream.write(raw)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.observe(disk)

    def test_mutable_wrong_size_or_cancelled_fd_refused(self):
        disk = self.root / 'synthetic.raw'
        make_disk(disk)
        fd = os.open(disk, os.O_RDWR)
        try:
            with self.assertRaisesRegex(ValueError, 'read-only'):
                tool.observe(fd, tool.DISK_BYTES, 'WINDOWS', reader, lambda: None)
        finally:
            os.close(fd)
        fd = os.open(disk, os.O_RDONLY)
        try:
            for size in (True, 1 << 30):
                with self.assertRaises(ValueError):
                    tool.observe(fd, size, 'WINDOWS', reader, lambda: None)
            def cancelled():
                raise RuntimeError('cancelled observation')
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                tool.observe(fd, tool.DISK_BYTES, 'WINDOWS', reader, cancelled)
        finally:
            os.close(fd)


class ActualProducer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-original-producer-')
        cls.base = Path(cls.temp.name)
        cls.disk = cls.base / 'synthetic.raw'
        make_disk(cls.disk)
        cls.disk_pin = file_pin(cls.disk)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.temp_case = tempfile.TemporaryDirectory(dir=self.base, prefix='case-')
        self.addCleanup(self.temp_case.cleanup)
        self.root = Path(self.temp_case.name)
        self.request = {'schema': 'shizukuos.original-userland-profile-request.v1',
                        'source_disk': dict(self.disk_pin), 'windows_directory': 'WINDOWS',
                        'boot_policy': 'shz.foundation=win98',
                        'producer_inputs': [file_pin(tool.TOOL), file_pin(tool.READER)]}
        self.request_path = self.root / 'request.json'

    def run_producer(self, raw=None):
        raw = (json.dumps(self.request, indent=2) + '\n').encode() if raw is None else raw
        self.request_path.write_bytes(raw)
        return tool.generate(self.request_path, tool.sha(raw), self.root / 'output')

    def test_full_source_readback_private_profile_and_false_scope(self):
        before = tool.identity(self.disk.stat())
        profile = self.run_producer()
        saved = self.root / 'output/original-userland-profile.json'
        self.assertEqual(json.loads(saved.read_bytes()), profile)
        self.assertEqual(set(profile), {'schema', 'status', 'phase', 'source_disk', 'request',
                                       'producer_inputs', 'boot_policy', 'observed_windows_path',
                                       'observed_members', 'boot_sectors', 'source_before_after_match',
                                       *tool.FLAGS})
        self.assertTrue(profile['source_before_after_match'])
        self.assertEqual(profile['source_disk'], self.disk_pin)
        self.assertEqual(profile['phase'], 'original-userland-legacy-adapter')
        self.assertTrue(all(profile[name] is False for name in tool.FLAGS))
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(saved.parent.stat().st_mode), 0o700)
        self.assertEqual(tool.identity(self.disk.stat()), before)
        self.assertEqual(set(p.name for p in saved.parent.iterdir()), {'original-userland-profile.json'})
        with saved.open('rb') as stream:
            self.assertEqual(json.loads(stream.read())['status'], 'ORIGINAL_USERLAND_SOURCE_OBSERVED_NOT_BOOTED')

    def test_exact_schema_pin_paths_and_no_caller_authority(self):
        original = copy.deepcopy(self.request)
        changes = ({'approval': True}, {'schema': 'shizukuos.private-replacement-profile.v1'},
                   {'windows_directory': 'CON'}, {'windows_directory': 'windows'},
                   {'windows_directory': 'WINDOWS/OTHER'}, {'boot_policy': 'shz.desktop=win98'},
                   {'source_disk': {**self.disk_pin, 'bytes': 1 << 30}},
                   {'source_disk': {**self.disk_pin, 'bytes': True}},
                   {'producer_inputs': list(reversed(original['producer_inputs']))},
                   {'producer_inputs': [{**original['producer_inputs'][0], 'path': str(self.root / 'other.py')},
                                        original['producer_inputs'][1]]})
        for change in changes:
            self.request = {**original, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_producer()
            self.assertFalse((self.root / 'output').exists())
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            self.run_producer(b'{"schema":"a","schema":"b"}')
        self.assertFalse((self.root / 'output').exists())

    def test_source_digest_failure_never_publishes(self):
        self.request['source_disk']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'full SHA'):
            self.run_producer()
        self.assertFalse((self.root / 'output').exists())

    def test_partial_writes_and_final_readback(self):
        write = os.write
        with patch.object(os, 'write', side_effect=lambda fd, raw: write(fd, raw[:37])):
            profile = self.run_producer()
        self.assertEqual(json.loads((self.root / 'output/original-userland-profile.json').read_bytes()), profile)

    def test_actual_conflicting_writer_breaks_read_lease(self):
        pread = os.pread
        attempted = []
        def read(fd, count, offset):
            if not attempted and count == 512 and offset == 0 and os.fstat(fd).st_ino == self.disk.stat().st_ino:
                result = subprocess.run([sys.executable, '-I', '-c',
                    'import os,sys;os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)', str(self.disk)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                attempted.append(result.returncode)
            return pread(fd, count, offset)
        with patch.object(os, 'pread', side_effect=read), self.assertRaises((ValueError, RuntimeError)):
            self.run_producer()
        self.assertTrue(attempted)
        self.assertNotEqual(attempted[0], 0)
        self.assertFalse((self.root / 'output/original-userland-profile.json').exists())

    def test_failed_mandatory_unlock_attempts_all_closes_no_profile(self):
        call = tool.fcntl.fcntl
        unlocks, closed = [], []
        real_close = os.close
        def fcntl(fd, op, *args):
            if op == tool.fcntl.F_SETLEASE and args == (tool.fcntl.F_UNLCK,):
                unlocks.append(fd)
                if len(unlocks) == 1:
                    raise OSError(errno.EIO, 'controlled unlock failure')
            return call(fd, op, *args)
        def close(fd):
            closed.append(fd)
            return real_close(fd)
        previous = signal.getsignal(signal.SIGIO)
        with patch.object(tool.fcntl, 'fcntl', side_effect=fcntl), patch.object(os, 'close', side_effect=close):
            with self.assertRaisesRegex(RuntimeError, 'mandatory.*cleanup'):
                self.run_producer()
        self.assertEqual(len(unlocks), 4)
        self.assertTrue(set(unlocks) <= set(closed))
        self.assertIs(signal.getsignal(signal.SIGIO), previous)
        self.assertFalse((self.root / 'output/original-userland-profile.json').exists())
        for fd in unlocks:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_output_public_existing_visible_git_and_mode_refused(self):
        self.request_path.write_text(json.dumps(self.request))
        digest = tool.sha(self.request_path.read_bytes())
        (self.root / 'output').mkdir()
        with self.assertRaisesRegex(ValueError, 'fresh'):
            tool.generate(self.request_path, digest, self.root / 'output')
        (self.root / 'output').rmdir()
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, '0700'):
            tool.generate(self.request_path, digest, self.root / 'output')
        self.root.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'public'):
            tool.generate(self.request_path, digest, Path('/srv/m98/original-fixture-refused'))
        (self.root / '.git').mkdir()
        with self.assertRaisesRegex(ValueError, 'visible Git'):
            tool.generate(self.request_path, digest, self.root / 'output')

    def test_actual_same_size_postrename_corruption_invalidates_profile(self):
        rename = os.rename
        def corrupt(source, destination, **kwargs):
            rename(source, destination, **kwargs)
            if destination == 'original-userland-profile.json':
                fd = os.open(self.root / 'output' / destination, os.O_RDWR)
                try:
                    os.pwrite(fd, b'!', 0)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        with patch.object(os, 'rename', side_effect=corrupt), self.assertRaisesRegex(ValueError, 'published.*readback'):
            self.run_producer()
        self.assertFalse((self.root / 'output/original-userland-profile.json').exists())

    def test_output_mandatory_directory_close_failure_invalidates_profile(self):
        close = os.close
        failed = []
        def close_then_error(fd):
            info = os.fstat(fd)
            is_output = stat.S_ISDIR(info.st_mode) and (self.root / 'output').exists() and \
                info.st_ino == (self.root / 'output').stat().st_ino
            close(fd)
            if is_output:
                failed.append(fd)
                raise OSError(errno.EIO, 'controlled directory close failure')
        with patch.object(os, 'close', side_effect=close_then_error), self.assertRaisesRegex(OSError, 'directory close'):
            self.run_producer()
        self.assertEqual(len(failed), 1)
        self.assertFalse((self.root / 'output/original-userland-profile.json').exists())

    def test_actual_hardlink_input_or_namespace_alias_refused(self):
        small = self.root / 'small'
        small.write_bytes(b'not Windows')
        row = file_pin(small)
        alias = self.root / 'alias'
        os.link(small, alias)
        with tool.HeldInputs() as held:
            with self.assertRaisesRegex(ValueError, 'one-link'):
                held.add(row)
        alias.unlink()
        with self.assertRaises((RuntimeError, ValueError)):
            with tool.HeldInputs() as held:
                held.add(row)
                small.rename(self.root / 'moved')
                try:
                    held.check()
                finally:
                    (self.root / 'moved').rename(small)

    def test_actual_same_inode_ancestor_symlink_refused_at_live_checkpoint(self):
        original = self.root / 'namespace'
        original.mkdir()
        source = original / 'source'
        source.write_bytes(b'actual unchanged inode behind replaced ancestor')
        row = file_pin(source)
        moved = self.root / 'namespace-moved'
        with tool.HeldInputs() as held:
            entry = held.add(row)
            before = tool.identity(os.fstat(entry['fd']))
            original.rename(moved)
            original.symlink_to(moved, target_is_directory=True)
            try:
                self.assertEqual(tool.identity(source.stat()), before)
                with self.assertRaisesRegex(ValueError, 'ancestor.*symlink'):
                    held.check()
            finally:
                original.unlink()
                moved.rename(original)
            held.finish()


if __name__ == '__main__':
    unittest.main(verbosity=2)
