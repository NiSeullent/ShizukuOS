#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual production archive/cache gate, using private tiny tar fixtures."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[1] / 'shzlib.py'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OpenWatcomPinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ow-pin-control-')
        self.addCleanup(self.tmp.cleanup)
        self.tools = Path(self.tmp.name)/'tools'
        self.tools.mkdir()
        spec = importlib.util.spec_from_file_location('actual_shzlib_pin_fixture', HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.helper.TOOLS_DIR = self.tools
        self.archive = self.tools/'ow-snapshot.tar.xz'
        self.root = self.tools/'ow'
        self.make_archive(b'owned valid fixture')
        self.expected = digest(self.archive)
        self.helper.load_manifest = lambda: {'tools': {'open-watcom-v2': {
            'sha256': self.expected,
            'url': 'https://github.com/open-watcom/open-watcom-v2/releases/download/Last-CI-build/ow-snapshot.tar.xz'}}}

    def make_archive(self, data):
        with tarfile.open(self.archive, 'w:xz') as tar:
            info = tarfile.TarInfo('binl64/wcc')
            info.mode, info.size = 0o755, len(data)
            tar.addfile(info, io.BytesIO(data))

    def cached(self, stamp=None, compiler=True):
        self.root.mkdir()
        if compiler:
            (self.root/'binl64').mkdir()
            (self.root/'binl64/wcc').write_bytes(b'preexisting cache identity')
        (self.root/'sentinel').write_bytes(b'preserve all existing files')
        if stamp is not None:
            (self.root/'.snapshot-sha256').write_text(stamp+'\n')

    def snapshot(self):
        return {str(p.relative_to(self.tools)): p.read_bytes() for p in self.tools.rglob('*') if p.is_file()}

    def refuses_unchanged(self):
        before = self.snapshot()
        with patch.object(self.helper.urllib.request, 'urlretrieve', side_effect=AssertionError('unexpected network')) as fetch:
            with self.assertRaises(RuntimeError):
                self.helper.ensure_open_watcom()
            fetch.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_wrong_archive_refuses_despite_matching_cached_stamp(self):
        self.cached(self.expected)
        self.make_archive(b'different valid archive')
        self.refuses_unchanged()

    def test_wrong_cached_stamp_refuses_without_touching_existing_tree(self):
        self.cached('0'*64)
        self.refuses_unchanged()

    def test_unrecorded_existing_tree_is_preserved(self):
        self.cached()
        self.refuses_unchanged()

    def test_missing_archive_refuses_without_download(self):
        self.archive.unlink()
        self.refuses_unchanged()

    def test_matching_existing_cache_is_reused_without_writes(self):
        self.cached(self.expected)
        before = self.snapshot()
        with patch.object(self.helper.urllib.request, 'urlretrieve', side_effect=AssertionError('unexpected network')):
            self.assertEqual(self.helper.ensure_open_watcom(), self.root)
        self.assertEqual(self.snapshot(), before)

    def test_matching_archive_extracts_only_to_new_cache(self):
        with patch.object(self.helper.urllib.request, 'urlretrieve', side_effect=AssertionError('unexpected network')):
            self.assertEqual(self.helper.ensure_open_watcom(), self.root)
        self.assertEqual((self.root/'binl64/wcc').read_bytes(), b'owned valid fixture')
        self.assertEqual((self.root/'.snapshot-sha256').read_text().strip(), self.expected)
        self.assertEqual(digest(self.archive), self.expected)

    def test_persistent_path_replacement_extracts_only_the_hashed_capture(self):
        accepted = self.archive.read_bytes()
        self.make_archive(b'persistent replacement compiler fixture')
        replacement_bytes = self.archive.read_bytes()
        self.archive.write_bytes(accepted)
        replacement = self.tools/'replacement.tar.xz'
        replacement.write_bytes(replacement_bytes)
        original_open = tarfile.open
        calls = []

        def replace_before_extract(*args, **kwargs):
            replacement.replace(self.archive)
            captured = kwargs.get('fileobj')
            calls.append(isinstance(captured, io.BytesIO) and captured.getvalue() == accepted)
            return original_open(*args, **kwargs)

        with patch.object(self.helper.tarfile, 'open', side_effect=replace_before_extract), \
             patch.object(self.helper.urllib.request, 'urlretrieve', side_effect=AssertionError('unexpected network')):
            returned = self.helper.ensure_open_watcom()
        self.assertEqual(returned, self.root)
        self.assertEqual(self.archive.read_bytes(), replacement_bytes)
        self.assertEqual((returned/'binl64/wcc').read_bytes(), b'owned valid fixture')
        self.assertEqual((returned/'.snapshot-sha256').read_text().strip(), self.expected)
        self.assertEqual(calls, [True])
        # The replacement persists, so a later call must reject it before the
        # already valid cache shortcut can hide the current archive mismatch.
        self.refuses_unchanged()


if __name__ == '__main__':
    unittest.main()
