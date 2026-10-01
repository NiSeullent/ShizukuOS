# SPDX-License-Identifier: GPL-2.0-only
"""Boundary tests for immutable source and private candidate preparation."""
import importlib.util
import contextlib
import json
import os
import pathlib
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'tools/build_win98_supervisor_candidate.py'
SPEC = importlib.util.spec_from_file_location('win98_candidate', PATH)
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


@contextlib.contextmanager
def runtime_fixture():
    """Real immutable Git sources and independently written archive/receipts."""
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d).resolve()
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        names = ('shizukudos/win64/build.py', 'shizukudos/win64/ntdll/provider.c',
                 'shizukudos/win64/kernel32/provider.c', 'shizukudos/abi/shz_abi.h',
                 'shizukudos/kcommon/common.h', 'shizukudos/kernel64/ntsys.h',
                 'shizukudos/kernel64/ntdrv_prov.c', 'shizukudos/tools/shzlib.py',
                 'shizukudos/upstream/manifest.json')
        pins = {}
        for name in names:
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(('/* committed fixture source ' + name + ' */\n').encode())
            pins[name] = C.digest(p.read_bytes())
        subprocess.run(['git', '-C', str(root), 'add', 'shizukudos'], check=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'source binding fixture'], check=True)
        commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        archive_names = ['\\SHZ\\SYS64\\ntdll.dll', '\\SHZ\\SYS64\\kernel32.dll', '\\SHZ\\TESTS\\T_HELLO.EXE']
        data, entries = bytearray(), []
        header = 16 + 136 * len(archive_names)
        for index, name in enumerate(archive_names):
            while (header + len(data)) % 16:
                data.append(0)
            content = b'fixture payload ' + str(index).encode()
            entries.append((name, header + len(data), len(content)))
            data += content
        raw = b'SHZARC01' + struct.pack('<II', len(entries), 0)
        raw += b''.join(struct.pack('<120sQQ', name.encode(), offset, size) for name, offset, size in entries)
        runtime = root / 'WIN64.IMG'
        runtime.write_bytes(raw + data)
        args = SimpleNamespace(runtime=runtime, runtime_sha256=C.digest(runtime.read_bytes()),
                               runtime_receipt=root / 'builder.json', runtime_source_manifest=root / 'source.json')
        receipt = {'schema': 1, 'source_commit': commit, 'git': {'revision': commit, 'dirty': False},
                   'archive': {'sha256': args.runtime_sha256, 'files': archive_names},
                   'consumed_sources_sha256': pins.copy()}
        manifest = {'schema': 1, 'source_commit': commit, 'archive_sha256': args.runtime_sha256,
                    'consumed_sources_sha256': pins.copy()}
        def write():
            args.runtime_receipt.write_text(json.dumps(receipt, sort_keys=True))
            args.runtime_receipt_sha256 = C.digest(args.runtime_receipt.read_bytes())
            manifest['builder_receipt_sha256'] = args.runtime_receipt_sha256
            args.runtime_source_manifest.write_text(json.dumps(manifest, sort_keys=True))
            args.runtime_source_manifest_sha256 = C.digest(args.runtime_source_manifest.read_bytes())
        write()
        yield root, commit, args, receipt, manifest, write


class CandidateBoundaries(unittest.TestCase):
    def test_exact_hunks_and_new_files(self):
        patch = b'--- a/a.c\n+++ b/a.c\n@@ -1,2 +1,2 @@\n first\n-old\n+new\n--- /dev/null\n+++ b/new.h\n@@ -0,0 +1 @@\n+header\n'
        result, changed = C.strict_patch({'a.c': b'first\nold\n'}, patch, {'a.c', 'new.h'})
        self.assertEqual(result, {'a.c': b'first\nnew\n', 'new.h': b'header\n'})
        self.assertEqual(changed, ['a.c', 'new.h'])

    def test_context_offsets_outside_paths_and_extents_rejected(self):
        base = b'--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n+new\n'
        cases = [({'a.c': b'changed\n'}, base, {'a.c'}),
                 ({'a.c': b'prefix\nold\n'}, base, {'a.c'}),
                 ({'a.c': b'old\n'}, base.replace(b'b/a.c', b'b/../a.c'), {'a.c'}),
                 ({'a.c': b'old\n'}, base, {'unrelated.c'}),
                 ({'a.c': b'old\n'}, base.replace(b'@@ -1 +1', b'@@ -1,2 +1'), {'a.c'}),
                 ({'a.c': b'old\n'}, base + base, {'a.c'}),
                 ({'a.c': b'old\n'}, base, {'a.c', 'missing.c'})]
        for source, patch, allowed in cases:
            with self.subTest(patch=patch, allowed=allowed):
                with self.assertRaises(ValueError):
                    C.strict_patch(source, patch, allowed)

    def test_unique_rebase_preserves_new_work(self):
        source = b'observe();\nif (old) {\nnew_work();\n}\n'
        actual = C.replace_once(source, b'if (old)', b'if (peer)')
        self.assertEqual(actual, b'observe();\nif (peer) {\nnew_work();\n}\n')
        for wrong in (b'unchanged', b'old old'):
            with self.assertRaises(ValueError):
                C.replace_once(wrong, b'old', b'new')

    def test_source_selection_excludes_generated_and_private_assets(self):
        for name in ('shizukudos/kernel64/main.c', 'shizukudos/abi/shz_abi.h', 'shizukudos/win64/pe_parse.c'):
            self.assertTrue(C.native_sources_only(name))
        for name in ('build/kernel64/main.c', 'shizukudos/kernel64/private.raw', 'shizukudos/kernel64/runtime.exe', 'site/secret.json'):
            self.assertFalse(C.native_sources_only(name))
        for name in ('../source.c', '/source.c', 'source//a.c', 'a/./b.c', 'a\\b.c', 'a\0b.c'):
            with self.assertRaises(ValueError):
                C.safe_name(name)

    def test_hash_geometry_symlink_and_directory_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d).resolve()
            p = root / 'original'
            p.write_bytes(b'actual bytes')
            h, size = C.pinned_file(p)
            self.assertEqual(h, C.digest(b'actual bytes'))
            self.assertEqual(size, 12)
            for args in ((p, '0' * 64), (p, h, 13), (root,)):
                with self.assertRaises(ValueError):
                    C.pinned_file(*args)
            link = root / 'alias'
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                C.pinned_file(link)

    def test_disk_floor_includes_preparation_budget(self):
        usage = type('Usage', (), {'free': C.FLOOR + 100})()
        with mock.patch.object(C.shutil, 'disk_usage', return_value=usage):
            C.require_floor(pathlib.Path('/tmp'), 100)
            with self.assertRaises(RuntimeError):
                C.require_floor(pathlib.Path('/tmp'), 101)

    def test_git_blobs_ignore_dirty_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d).resolve()
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            p = root / 'shizukudos/kernel64/main.c'
            p.parent.mkdir(parents=True)
            p.write_bytes(b'committed actual source\n')
            subprocess.run(['git', '-C', str(root), 'add', str(p)], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'fixture'], check=True)
            commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            p.write_bytes(b'dirty owner work\n')
            (p.parent / 'ignored.c').write_bytes(b'not committed\n')
            snapshot = C.git_snapshot(root, commit)
            self.assertEqual(snapshot, {'shizukudos/kernel64/main.c': b'committed actual source\n'})
            self.assertEqual(p.read_bytes(), b'dirty owner work\n')
            with self.assertRaises(ValueError):
                C.git_snapshot(root, 'HEAD')

    def test_changed_abi_or_reviewed_preimage_refused(self):
        # Validation checks the full reviewed file before reading candidate hunks.
        source = {name: b'changed source' for name in C.PREIMAGES}
        with self.assertRaisesRegex(ValueError, 'changed ABI/builder/patch preimage'):
            C.prepared_sources(source)

    def test_runtime_positive_full_bidirectional_binding(self):
        with runtime_fixture() as (root, commit, args, _, _, _):
            self.assertEqual(C.validate_runtime(args, root, commit), args.runtime_sha256)

    def test_runtime_old_receipt_cannot_bind_to_new_manifest(self):
        with runtime_fixture() as (root, commit, args, receipt, manifest, write):
            receipt['source_commit'] = '0' * 40
            receipt['git']['revision'] = '0' * 40
            manifest['sources_sha256'] = manifest['consumed_sources_sha256'].copy()  # old validator's bypass
            write()
            with self.assertRaises(ValueError):
                C.validate_runtime(args, root, commit)

    def test_runtime_wrong_receipt_or_archive_crosslink_refused(self):
        for field in ('builder_receipt_sha256', 'archive_sha256'):
            with self.subTest(field=field), runtime_fixture() as (root, commit, args, _, manifest, _):
                manifest['sources_sha256'] = manifest['consumed_sources_sha256'].copy()
                manifest[field] = '0' * 64
                args.runtime_source_manifest.write_text(json.dumps(manifest))
                args.runtime_source_manifest_sha256 = C.digest(args.runtime_source_manifest.read_bytes())
                with self.assertRaises(ValueError):
                    C.validate_runtime(args, root, commit)

    def test_runtime_stale_missing_or_different_consumed_pins_refused(self):
        for how in ('stale_both', 'missing_both', 'missing_receipt', 'different_maps'):
            with self.subTest(how=how), runtime_fixture() as (root, commit, args, receipt, manifest, write):
                manifest['sources_sha256'] = manifest['consumed_sources_sha256'].copy()
                name = 'shizukudos/win64/build.py'
                if how == 'stale_both':
                    receipt['consumed_sources_sha256'][name] = '0' * 64
                    manifest['consumed_sources_sha256'][name] = '0' * 64
                elif how == 'missing_both':
                    receipt['consumed_sources_sha256'].pop(name)
                    manifest['consumed_sources_sha256'].pop(name)
                elif how == 'missing_receipt':
                    receipt.pop('consumed_sources_sha256')
                else:
                    receipt['consumed_sources_sha256'][name] = '0' * 64
                manifest['sources_sha256'] = manifest['consumed_sources_sha256'].copy()
                write()
                with self.assertRaises(ValueError):
                    C.validate_runtime(args, root, commit)

    def test_runtime_mismatched_manifest_commit_refused(self):
        with runtime_fixture() as (root, commit, args, _, manifest, write):
            manifest['source_commit'] = '0' * 40
            write()
            with self.assertRaises(ValueError):
                C.validate_runtime(args, root, commit)

    def test_runtime_json_is_parsed_from_verified_descriptor_bytes(self):
        with runtime_fixture() as (root, commit, args, _, _, _):
            with mock.patch.object(pathlib.Path, 'read_text', side_effect=AssertionError('unverified JSON reopen')):
                self.assertEqual(C.validate_runtime(args, root, commit), args.runtime_sha256)

    def test_runtime_archive_entries_and_loader_limit_refused(self):
        for how in ('wrong_files', 'overlap', 'table_truncated', 'above_loader_limit'):
            with self.subTest(how=how), runtime_fixture() as (root, commit, args, receipt, manifest, write):
                manifest['sources_sha256'] = manifest['consumed_sources_sha256'].copy()
                if how == 'wrong_files':
                    receipt['archive']['files'].pop()
                elif how == 'above_loader_limit':
                    with args.runtime.open('ab') as stream:
                        stream.truncate((64 << 20) + 1)
                else:
                    raw = bytearray(args.runtime.read_bytes())
                    if how == 'overlap':
                        struct.pack_into('<Q', raw, 16 + 120, 0)
                    else:
                        struct.pack_into('<I', raw, 8, 4096)
                    args.runtime.write_bytes(raw)
                args.runtime_sha256 = C.digest(args.runtime.read_bytes())
                receipt['archive']['sha256'] = args.runtime_sha256
                manifest['archive_sha256'] = args.runtime_sha256
                write()
                with self.assertRaises(ValueError):
                    C.validate_runtime(args, root, commit)

    def test_private_output_and_media_are_restricted_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d).resolve()
            previous = os.umask(0o022)
            try:
                out = root / 'private'
                with C.owned_output(out, private=True):
                    self.assertEqual(out.stat().st_mode & 0o777, 0o700)
                    directory = out / 'nested'
                    directory.mkdir()
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                    with (directory / 'disk.img').open('xb') as stream:
                        self.assertEqual(os.fstat(stream.fileno()).st_mode & 0o777, 0o600)
                        stream.write(b'private fixture bytes')
                # The tool's process-local permissions must be restored.
                public = root / 'after.txt'
                public.write_bytes(b'after')
                self.assertEqual(public.stat().st_mode & 0o777, 0o644)
                source = root / 'source.bin'
                source.write_bytes(b'actual private payload')
                with mock.patch.object(C, 'require_floor'):
                    C.private_copy(source, out / 'copy.bin', C.digest(source.read_bytes()))
                self.assertEqual((out / 'copy.bin').stat().st_mode & 0o777, 0o600)
                self.assertEqual((out / 'copy.bin').read_bytes(), source.read_bytes())
            finally:
                os.umask(previous)

    def test_runtime_receipt_wrapper_preserves_original_commit_and_pins(self):
        with runtime_fixture() as (root, commit, args, receipt, _, write):
            receipt['source_binding'] = {'schema': 1, 'source_commit': commit,
                                         'consumed_sources_sha256': receipt.pop('consumed_sources_sha256')}
            write()
            self.assertEqual(C.validate_runtime(args, root, commit), args.runtime_sha256)
            receipt['git']['revision'] = '0' * 40  # new wrapper cannot relabel an old owner's receipt
            write()
            with self.assertRaises(ValueError):
                C.validate_runtime(args, root, commit)

    def test_oversized_runtime_is_rejected_before_any_byte_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d).resolve() / 'oversized.img'
            with p.open('wb') as stream:
                stream.truncate((64 << 20) + 1)
            with mock.patch.object(C.os, 'read', side_effect=AssertionError('oversized file was read')):
                with self.assertRaises(ValueError):
                    C.pinned_bytes(p, '0' * 64, 64 << 20)

    @staticmethod
    def tool_fixture(alias):
        target = alias.resolve()
        return {'alias': str(alias), 'target': str(target),
                'alias_identity': C.identity(alias.lstat()),
                'target_identity': C.identity(target.stat())}

    def test_mtools_alias_argv0_and_actual_target_are_separate(self):
        for name in ('mcopy', 'mmd'):
            alias = pathlib.Path('/usr/bin') / name
            if not alias.is_file():
                self.skipTest('host mtools alias is not installed')
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                out = pathlib.Path(d).resolve()
                binding = self.tool_fixture(alias)
                proof = {'commands': [], 'tool_bindings': {name: binding}}
                run = C.compiler_run({name: alias.resolve()}, out, proof)
                result = subprocess.CompletedProcess([], 0, 'fixture utility output\n')
                with mock.patch.object(C, 'require_floor'), mock.patch.object(C.subprocess, 'run', return_value=result) as invoked:
                    run([name, '-V'])
                actual, kwargs = invoked.call_args
                self.assertEqual(actual[0][0], str(alias))
                self.assertEqual(kwargs.get('executable'), str(alias.resolve()))
                self.assertEqual(proof['commands'][0][0], str(alias))

    def test_mtools_actual_version_dispatch_matches_alias(self):
        for name in ('mcopy', 'mmd'):
            alias = pathlib.Path('/usr/bin') / name
            if not alias.is_file():
                self.skipTest('host mtools alias is not installed')
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                out = pathlib.Path(d).resolve()
                proof = {'commands': [], 'tool_bindings': {name: self.tool_fixture(alias)}}
                with mock.patch.object(C, 'require_floor'):
                    # -V is read-only: no private image, FAT volume or VM.
                    actual = C.compiler_run({name: alias.resolve()}, out, proof)([name, '-V'])
                self.assertEqual(actual.returncode, 0)
                self.assertTrue(actual.stdout.startswith(name + ' (GNU mtools)'), actual.stdout)

    def test_changed_alias_or_target_is_refused_before_exec(self):
        for how in ('retarget', 'replace_alias_same_target', 'change_target'):
            with self.subTest(how=how), tempfile.TemporaryDirectory() as d:
                out = pathlib.Path(d).resolve()
                target = out / 'actual'
                target.write_bytes(b'fixture executable bytes')
                target.chmod(0o700)
                other = out / 'other'
                other.write_bytes(b'other executable bytes')
                other.chmod(0o700)
                alias = out / 'mcopy'
                alias.symlink_to(target)
                binding = self.tool_fixture(alias)
                proof = {'commands': [], 'tool_bindings': {'mcopy': binding}}
                if how == 'change_target':
                    target.write_bytes(b'changed target bytes')
                else:
                    replacement = out / 'replacement'
                    replacement.symlink_to(other if how == 'retarget' else target)
                    replacement.replace(alias)
                result = subprocess.CompletedProcess([], 0, 'must never execute')
                with mock.patch.object(C, 'require_floor'), mock.patch.object(C.subprocess, 'run', return_value=result) as invoked:
                    with self.assertRaises(ValueError):
                        C.compiler_run({'mcopy': target}, out, proof)(['mcopy', '-V'])
                    invoked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
