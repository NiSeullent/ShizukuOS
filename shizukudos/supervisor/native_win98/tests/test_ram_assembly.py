#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real tmpfs/FAT/NAS controls with tiny fixture data; no guest execution."""
import hashlib
import builtins
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ram_fixture_builder', HERE.parent / 'build.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class RAMAssemblyControls(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir=os.environ['SHZ_RAM_ASSEMBLY_TEST_ROOT'])
        self.ram = Path(self.folder.name)
        self.sink = Path(os.environ['SHZ_RAM_ASSEMBLY_NAS_TEST_ROOT']) / self.ram.name
        self.sink.mkdir(mode=0o700)
        self.source = self.ram / 'fixture-disk.img'
        with self.source.open('xb') as stream:
            stream.truncate(3 << 20)
            stream.seek(4095); stream.write(b'A')
            stream.seek((3 << 20) - 1); stream.write(b'B')
        self.loader = self.ram / 'fixture-loader'
        self.loader.write_bytes(b'NONEXECUTABLE EFI HOST FIXTURE')

    def tearDown(self):
        self.assertLess(sum(p.stat().st_blocks * 512 for p in self.ram.rglob('*') if p.is_file()), 64 << 20)
        self.assertLess(sum(p.stat().st_blocks * 512 for p in self.sink.rglob('*') if p.is_file()), 64 << 20)
        self.folder.cleanup()
        shutil.rmtree(self.sink)

    def test_actual_ram_member_copied_to_independent_durable_NAS_inode(self):
        receipt = {'commands': []}
        # Model only the logical fixture size. Both actual write filesystems,
        # 6GiB+160MiB RAM/host and 17GiB+2304MiB NAS guards remain unmocked.
        with mock.patch.object(B, 'ESP_MIB', 40):
            esp, members = B.assemble(self.sink, {'DISK.IMG': self.source}, self.loader,
                                      receipt, scratch=self.ram / 'assembly')
        temporary = self.ram / 'assembly' / 'esp-win98.img'
        self.assertEqual(esp, self.sink / 'esp-win98.img')
        self.assertNotEqual((esp.stat().st_dev, esp.stat().st_ino),
                            (temporary.stat().st_dev, temporary.stat().st_ino))
        self.assertEqual(B.file_sha(esp), B.file_sha(temporary))
        self.assertEqual(members['SHZDOS/DISK.IMG']['sha256'], B.file_sha(self.source))
        self.assertTrue(receipt['ram_assembly']['independent_NAS_copy_full_SHA_verified'])
        self.assertEqual(receipt['ram_assembly']['worker_deadline_seconds'], 120)
        self.assertEqual(receipt['ram_assembly']['NAS_reserve_bytes'], 17 << 30)
        self.assertEqual(subprocess.check_output(['mtype', '-i', str(esp),
                         '::/SHZDOS/DISK.IMG'], timeout=30), self.source.read_bytes())

    def test_non_tmpfs_scratch_refuses_before_creating_ESP(self):
        scratch = self.sink / 'invalid-RAM-scratch'
        with self.assertRaisesRegex(ValueError, 'tmpfs'):
            B.assemble(self.sink, {'DISK.IMG': self.source}, self.loader,
                       {'commands': []}, scratch=scratch)
        self.assertFalse(scratch.exists())
        self.assertFalse((self.sink / 'esp-win98.img').exists())

    def guard_module(self):
        spec = importlib.util.spec_from_file_location('actual_RAM_guard', HERE.parent / 'ram_assembly.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_held_actual_tmpfs_query_does_not_require_mount_table_text(self):
        guard = self.guard_module()
        real = Path.read_text
        def no_mount_table(path, *args, **kwargs):
            if str(path) == '/proc/self/mountinfo':
                raise OSError('mount table text deliberately unavailable')
            return real(path, *args, **kwargs)
        with mock.patch.object(Path, 'read_text', no_mount_table):
            with guard.Placement.create(self.ram / 'assembly', self.sink) as placement:
                started = time.monotonic()
                for unused in range(1000):
                    placement.check()
                print(json.dumps({'actual_unmocked_RAM_NAS_guard_calls': 1000,
                                  'elapsed_seconds': time.monotonic() - started}), flush=True)

    def test_symlink_ancestor_alias_to_same_held_directory_is_refused(self):
        guard = self.guard_module()
        parent = self.ram / 'private-parent'; parent.mkdir(mode=0o700)
        saved = self.ram / 'saved-private-parent'
        with guard.Placement.create(parent / 'assembly', self.sink) as placement:
            parent.rename(saved); parent.symlink_to(saved, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError, 'canonical'):
                    placement.check()
            finally:
                parent.unlink(); saved.rename(parent)

    def replacement(self, destination):
        replacement = destination.parent / '.replacement-control.img'
        with replacement.open('xb') as stream:
            stream.truncate(destination.stat().st_size)
            stream.write(b'CHANGED AFTER PRODUCER')
        os.replace(replacement, destination)

    def test_RAM_ESP_replacement_after_producer_is_refused(self):
        real = B._assemble
        def replaced(*args, **kwargs):
            result = real(*args, **kwargs)
            self.replacement(result[0])
            return result
        with mock.patch.object(B, 'ESP_MIB', 40), mock.patch.object(B, '_assemble', replaced):
            with self.assertRaises((ValueError, RuntimeError)):
                B.assemble(self.sink, {'DISK.IMG': self.source}, self.loader,
                           {'commands': []}, scratch=self.ram / 'assembly')

    def test_final_NAS_replacement_during_placement_exit_is_refused(self):
        def intercept(code, namespace):
            builtins.exec(code, namespace)
            placement = namespace['Placement']
            real_exit = placement.__exit__
            def replaced(instance, *args):
                self.replacement(self.sink / 'esp-win98.img')
                return real_exit(instance, *args)
            placement.__exit__ = replaced
        with mock.patch.object(B, 'ESP_MIB', 40), mock.patch.object(B, 'exec', intercept, create=True):
            with self.assertRaises((ValueError, RuntimeError)):
                B.assemble(self.sink, {'DISK.IMG': self.source}, self.loader,
                           {'commands': []}, scratch=self.ram / 'assembly')

    def test_final_NAS_directory_fsync_failure_refuses_return(self):
        real = os.fsync
        def fail(fd):
            info = os.fstat(fd)
            if stat.S_ISDIR(info.st_mode) and info.st_dev == self.sink.stat().st_dev:
                raise OSError('controlled final NAS directory fsync failure')
            return real(fd)
        with mock.patch.object(B, 'ESP_MIB', 40), mock.patch.object(B.os, 'fsync', fail):
            with self.assertRaisesRegex(OSError, 'directory fsync failure'):
                B.assemble(self.sink, {'DISK.IMG': self.source}, self.loader,
                           {'commands': []}, scratch=self.ram / 'assembly')

    def modeled_main(self, *, replace_after_return=True, replace_during_original_close=False):
        # Actual tiny original leases/NAS copies; only compile/ESP are modeled.
        rom = bytearray(B.ROM_BYTES); rom[:7] = b'SeaBIOS'; rom[-16] = 0xea
        data = {'disk': bytes(510) + b'\x55\xaa' + bytes((512 << 10)-512),
                'rom': rom, 'config': B.config_bytes(), 'kernel32': b'HOST K32', 'kernel64': b'HOST K64'}
        args = []
        for name, body in data.items():
            path = self.ram / name; path.write_bytes(body)
            args += ['--'+name, str(path), '--'+name+'-sha256', hashlib.sha256(body).hexdigest()]
        source = self.ram / 'shizukudos/supervisor/native_win98/compile.py'
        source.parent.mkdir(parents=True); source.write_bytes(b'# MODELED HOST COMPILE ONLY\n')
        output = self.sink / 'main'; returned = []
        args += ['--out', str(output), '--assembly-scratch', str(self.ram / 'assembly')]
        def compile_model(argv, receipt, **kwargs):
            components = Path(argv[-1]); components.mkdir()
            loader = components / 'BOOTX64.EFI'; loader.write_bytes(b'HOST EFI ONLY')
            (components / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN',
                'artifacts': {'BOOTX64.EFI': {'sha256': B.file_sha(loader)}}}))
        def assembly_model(out, copies, loader, receipt, **kwargs):
            esp = out / 'esp-win98.img'; esp.write_bytes(b'ORIGINAL MODELED ESP')
            receipt['ram_assembly'] = {'final_copy': {'bytes': esp.stat().st_size, 'sha256': B.file_sha(esp)},
                                      'final_identity': list(B.stable(esp.stat()))}
            if replace_after_return:
                self.replacement(esp)
            return esp, {}
        real_close = os.close
        def close(fd):
            try:
                original_disk = os.readlink('/proc/self/fd/' + str(fd)) == str(self.ram / 'disk')
            except OSError:
                original_disk = False
            real_close(fd)
            if replace_during_original_close and original_disk:
                self.replacement(output / 'esp-win98.img')
        with mock.patch.object(B, 'ROOT', self.ram), mock.patch.object(B, 'DISK_BYTES', 512 << 10), \
             mock.patch.object(B, 'source_files', return_value=[source]), \
             mock.patch.object(B, 'command', compile_model), mock.patch.object(B, 'assemble', assembly_model), \
             mock.patch.object(B.os, 'close', close):
            with self.assertRaises((ValueError, RuntimeError)):
                B.main(args, receipt_sink=returned.append)
        self.assertFalse(returned)
        self.assertEqual(json.loads((output / 'result.json').read_text())['status'], 'FAIL_BUILD_PRESERVED')

    def test_main_does_not_accept_new_self_pin_after_assembly_return(self):
        self.modeled_main()

    def test_final_ESP_replacement_during_last_original_close_vetoes_sink(self):
        self.modeled_main(replace_after_return=False, replace_during_original_close=True)


if __name__ == '__main__':
    unittest.main()
