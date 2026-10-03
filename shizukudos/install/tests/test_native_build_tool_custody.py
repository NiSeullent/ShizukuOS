#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real Linux FD/link/lease controls; policy and Windows authority are modeled."""
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'shizukudos/install'))
import native_release_admission as admission
import native_build_tool_custody as tools


class CompilerToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-compiler-leases-host-')
        self.base = Path(self.temp.name)
        self.ingest = admission.load_ingester()
        self.rows = {}
        self.aliases = {}
        for role, count in tools.ROLES.items():
            path = self.base / role
            path.write_bytes((role + ': actual host hardlink fixture').encode())
            self.aliases[role] = []
            for number in range(1, count):
                alias = self.base / (role + '-alias-' + str(number))
                os.link(path, alias)
                self.aliases[role].append(alias)
            self.rows[role] = self.pin(path)
        self.anchors = {role: {**row, 'nlink': tools.ROLES[role]}
                        for role, row in self.rows.items()}
        self.policy = patch.object(tools.policy, 'NATIVE_COMPILER_TOOLS', self.anchors, create=True)
        self.policy.start()

    @staticmethod
    def pin(path):
        data = path.read_bytes()
        return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def tearDown(self):
        self.policy.stop()
        self.temp.cleanup()

    def test_exact_three_two_two_four_link_roles_close_all_fds(self):
        fds = []
        with self.ingest.Union() as held:
            with tools.BuildToolLeases(self.ingest, held) as owner:
                for role, row in self.rows.items():
                    entry = owner.add_build_tool(role, row)
                    fds.append(entry['fd'])
                    self.assertEqual(fcntl.fcntl(entry['fd'], fcntl.F_GETLEASE), fcntl.F_RDLCK)
                self.assertEqual(owner.pins(), [self.rows[role] for role in sorted(self.rows)])
                held.finish()
            self.assertEqual(held.guards, [])
            held.check()
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_private_payload_and_source_still_refuse_hardlinks(self):
        with self.ingest.Union() as held:
            for row in self.rows.values():
                with self.assertRaisesRegex(ValueError, 'independent regular'):
                    held.add(row)
            with tools.BuildToolLeases(self.ingest, held) as owner:
                with self.assertRaisesRegex(ValueError, 'anchors absent'):
                    owner.add_build_tool('Windows-original-source', self.rows['gcc'])

    def test_unanchored_role_path_size_sha_and_count_refuse(self):
        for field, replacement in [('path', str(self.aliases['gcc'][0])),
                                   ('bytes', self.rows['gcc']['bytes'] + 1),
                                   ('sha256', 'a' * 64)]:
            row = {**self.rows['gcc'], field: replacement}
            with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
                with self.assertRaisesRegex(ValueError, 'anchor differs'):
                    owner.add_build_tool('gcc', row)
        os.link(self.base / 'gcc', self.base / 'extra-gcc-link')
        with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
            with self.assertRaisesRegex(ValueError, 'extent/link count'):
                owner.add_build_tool('gcc', self.rows['gcc'])

    def test_absent_and_extra_policy_fields_refuse(self):
        for anchors in (None, {'gcc': self.anchors['gcc']},
                        {**self.anchors, 'gcc': {**self.anchors['gcc'], 'approval': True}}):
            with patch.object(tools.policy, 'NATIVE_COMPILER_TOOLS', anchors):
                with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
                    with self.assertRaises(ValueError):
                        owner.add_build_tool('gcc', self.rows['gcc'])

    def test_nlink_drift_refuses_and_releases_on_error(self):
        fd = None
        with self.assertRaisesRegex(ValueError, 'identity or lease changed'):
            with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
                fd = owner.add_build_tool('gcc', self.rows['gcc'])['fd']
                os.link(self.base / 'gcc', self.base / 'changed-link-count')
                held.check()
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_path_inode_substitution_refuses_and_releases_on_error(self):
        fd = None
        with self.assertRaisesRegex(ValueError, 'identity or lease changed'):
            with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
                fd = owner.add_build_tool('gcc', self.rows['gcc'])['fd']
                replacement = self.base / 'replacement'
                replacement.write_bytes((self.base / 'gcc').read_bytes())
                os.replace(replacement, self.base / 'gcc')
                held.check()
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_actual_alias_writer_sigio_refuses_even_without_write(self):
        previous = signal.getsignal(signal.SIGIO)
        chained = []
        signal.signal(signal.SIGIO, lambda *_: chained.append(True))
        try:
            for role in tools.ROLES:
                with self.assertRaisesRegex(ValueError, 'read lease broken'):
                    with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
                        owner.add_build_tool(role, self.rows[role])
                        # A separate real process opens an alternate inode name;
                        # O_NONBLOCK prevents a lease-break timeout or any write.
                        script = 'import os,sys;\ntry: os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)\nexcept BlockingIOError: sys.exit(0)\nsys.exit(9)'
                        result = subprocess.run([sys.executable, '-c', script, str(self.aliases[role][0])], timeout=5)
                        self.assertEqual(result.returncode, 0)
                        self.assertTrue(held.broken)
                        held.check()
            self.assertTrue(chained)
            self.assertTrue(callable(signal.getsignal(signal.SIGIO)))
        finally:
            signal.signal(signal.SIGIO, previous)

    def test_actual_hash_failure_retains_fd_until_all_cleanup(self):
        row = {**self.rows['gcc'], 'sha256': 'a' * 64}
        self.anchors['gcc'] = {**row, 'nlink': 3}
        fds = []
        with self.assertRaisesRegex(ValueError, 'full SHA differs'):
            with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
                try:
                    owner.add_build_tool('gcc', row)
                finally:
                    fds.extend(entry['fd'] for entry in owner.entries.values())
        self.assertEqual(len(fds), 1)
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_source_owner_cleanup_has_compiler_and_source_leases_on_success_and_failure(self):
        source = self.base / 'private-source-fixture'
        source.write_bytes(b'host model; no Windows bytes')
        for fail in (False, True):
            closed = []
            with self.ingest.Union() as held:
                source_entry = held.add(self.pin(source))
                try:
                    with ExitStack() as stack:
                        owner = stack.enter_context(tools.BuildToolLeases(self.ingest, held))
                        tool_entry = owner.add_build_tool('gcc', self.rows['gcc'])
                        @contextmanager
                        def modeled_private_owner():
                            try:
                                yield
                            finally:
                                self.assertEqual(fcntl.fcntl(source_entry['fd'], fcntl.F_GETLEASE), fcntl.F_RDLCK)
                                self.assertEqual(fcntl.fcntl(tool_entry['fd'], fcntl.F_GETLEASE), fcntl.F_RDLCK)
                                closed.append(True)
                        stack.enter_context(modeled_private_owner())
                        if fail:
                            raise RuntimeError('actual cleanup on modeled compiler failure')
                except RuntimeError:
                    self.assertTrue(fail)
                self.assertEqual(closed, [True])
                self.assertEqual(held.guards, [])
                self.assertEqual(fcntl.fcntl(source_entry['fd'], fcntl.F_GETLEASE), fcntl.F_RDLCK)
                held.finish()

    def test_actual_gcc_and_mingw_compiles_under_retained_driver_leases(self):
        for role, program in [('gcc', 'gcc'), ('private-efi-gcc', 'x86_64-w64-mingw32-gcc')]:
            original = Path(shutil.which(program)).resolve()
            path = self.base / ('actual-' + role)
            shutil.copyfile(original, path)
            path.chmod(0o700)
            for number in range(1, tools.ROLES[role]):
                os.link(path, self.base / ('actual-' + role + '-alias-' + str(number)))
            row = self.pin(path)
            anchors = {**self.anchors, role: {**row, 'nlink': tools.ROLES[role]}}
            source = self.base / ('fixture-' + role + '.c')
            source.write_text('int fixture_add(int x) { return x + 17; }\n')
            output = self.base / ('fixture-' + role + '.o')
            children = {}
            for child in (('cc1', 'as') if role == 'gcc' else ('cc1', 'as', 'collect2', 'ld')):
                selected = subprocess.run([str(original), '-print-prog-name=' + child],
                                          check=True, capture_output=True, text=True, timeout=5).stdout.strip()
                child_path = (Path(selected) if Path(selected).is_absolute()
                              else Path(shutil.which(selected))).resolve()
                children[child] = child_path
                if role == 'private-efi-gcc' and child in ('as', 'ld'):
                    anchors['private-efi-' + child] = {**self.pin(child_path), 'nlink': tools.ROLES['private-efi-' + child]}
            with patch.object(tools.policy, 'NATIVE_COMPILER_TOOLS', anchors):
                with self.ingest.Union() as held, tools.BuildToolLeases(self.ingest, held) as owner:
                    held.add(self.pin(source))
                    for name, child in children.items():
                        owner.add_build_tool('private-efi-' + name if role == 'private-efi-gcc' else 'gcc-' + name,
                                             self.pin(child))
                    fd = owner.add_build_tool(role, row)['fd']
                    result = subprocess.run([str(path), *['-B' + str(child.parent) + '/' for child in children.values()],
                                             '-c', str(source), '-o', str(output)],
                                            capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                    self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETLEASE), fcntl.F_RDLCK)
                    raw = output.read_bytes()
                    self.assertEqual(raw[:4] if role == 'gcc' else raw[:2],
                                     b'\x7fELF' if role == 'gcc' else b'\x64\x86')
                    if role == 'private-efi-gcc':
                        image = self.base / 'actual-host-EFI-fixture.exe'
                        linked = subprocess.run([str(path), *['-B' + str(child.parent) + '/' for child in children.values()],
                                                 '-nostdlib', '-Wl,--subsystem,10', '-Wl,--entry,fixture_add',
                                                 '-Wl,--no-insert-timestamp', str(output), '-o', str(image)],
                                                capture_output=True, timeout=15)
                        self.assertEqual(linked.returncode, 0, linked.stderr.decode(errors='replace'))
                        self.assertEqual(image.read_bytes()[:2], b'MZ')
                    held.finish()


if __name__ == '__main__':
    unittest.main()
